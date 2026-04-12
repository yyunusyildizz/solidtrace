from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from app.api.websockets import broadcast
from app.database.db_manager import SessionLocal
from app.detection.correlation_engine import get_engine
from app.detection.detection_policy import (
    BENIGN_PROCESS_MARKERS,
    has_strong_attack_context,
    is_real_mimikatz,
    is_real_powershell_attack,
    is_sigma_generated_event,
    should_block_sigma_promotion,
)
from app.services.alert_service import create_alert
from app.services.dedup_service import is_duplicate_event
from app.services.incident_service import upsert_incident_for_new_alert
from app.services.rule_engine import evaluate_rules
from app.services.soc_intelligence import (
    auto_response,
    propagate_risk,
)

logger = logging.getLogger("SolidTrace.EventProcessor")

EXECUTION_INDICATORS = ["powershell", "cmd.exe", "wmic", "rundll32", "psexec", "paexec"]
EXTRA_BENIGN_MARKERS = ["rust-analyzer", "systemsettings.exe", "nvtmmon.exe", "installassistservice.exe"]


def _norm(*parts: object) -> str:
    return " ".join(str(p or "") for p in parts if p).strip().lower()


def ensure_case_for_alert(*args, **kwargs):
    return None


class EventProcessor:
    def __init__(self, min_alert_score: int, correlator=None, sigma_engine=None):
        self.min_alert_score = min_alert_score
        self._correlation = correlator or get_engine()
        self._sigma_engine = sigma_engine

    def set_engines(self, correlator=None, sigma_engine=None) -> None:
        if correlator is not None:
            self._correlation = correlator
        if sigma_engine is not None:
            self._sigma_engine = sigma_engine

    def normalize_event(self, e):
        return {
            "type": str(getattr(e, "type", "") or ""),
            "hostname": str(getattr(e, "hostname", "") or ""),
            "user": str(getattr(e, "user", "") or ""),
            "details": str(getattr(e, "details", "") or ""),
            "command_line": str(getattr(e, "command_line", "") or ""),
            "pid": getattr(e, "pid", 0),
            "serial": getattr(e, "serial", None),
            "severity": (getattr(e, "severity", "INFO") or "INFO").upper(),
            "timestamp": getattr(e, "timestamp", None),
        }

    def _sanitize_text(self, value: str) -> str:
        text = str(value or "")
        wrappers = [
            "severity: info | info:",
            "severity: medium | info:",
            "severity: low | info:",
            "severity: high | info:",
            "severity: critical | info:",
        ]
        lowered = text.lower()
        for prefix in wrappers:
            if lowered.startswith(prefix):
                return text[len(prefix):].strip()
        return text.strip()

    def _extract_command_line(self, event_data: Dict[str, Any]) -> str:
        cmd = str(event_data.get("command_line") or "").strip()
        if cmd:
            return cmd

        details = str(event_data.get("details") or "")
        details_lower = details.lower()

        if "eventid:4688" in details_lower or "yeni process" in details_lower:
            return details
        if "powershell" in details_lower or "wmic" in details_lower or "psexec" in details_lower:
            return details

        return ""

    def _build_text(self, event_data: Dict[str, Any]) -> str:
        cmd = self._extract_command_line(event_data)
        parts = [
            str(event_data.get("type") or ""),
            self._sanitize_text(str(event_data.get("details") or "")),
            self._sanitize_text(cmd),
        ]
        return " ".join([p for p in parts if p]).strip().lower()

    def _is_benign_process_event(self, event_type: str, built_text: str) -> bool:
        if event_type not in {"PROCESS_START", "PROCESS_CREATED", "PROCESS_CREATE_EVT"}:
            return False
        lowered = _norm(built_text)
        return any(marker in lowered for marker in BENIGN_PROCESS_MARKERS + EXTRA_BENIGN_MARKERS)

    def _is_plain_path_or_process_notice(self, built_text: str) -> bool:
        lowered = _norm(built_text)
        return lowered.startswith("yol: ") or lowered.startswith("yeni süreç:") or lowered.startswith("yeni surec:")

    async def process_single_event(self, event_data: Dict[str, Any], tenant_id: Optional[str]):
        db = SessionLocal()
        try:
            event_type = str(event_data.get("type") or "").upper()

            if is_sigma_generated_event(event_data) or event_type == "SIGMA_ALERT":
                logger.warning(
                    "sigma_generated_event_dropped tenant=%s host=%s type=%s rule=%s",
                    tenant_id,
                    event_data.get("hostname"),
                    event_type,
                    event_data.get("rule"),
                )
                return

            if is_duplicate_event(event_data, tenant_id):
                logger.info(
                    "event_duplicate_suppressed tenant=%s host=%s type=%s",
                    tenant_id,
                    event_data.get("hostname"),
                    event_type,
                )
                return

            text = self._build_text(event_data)
            if not text or len(text) < 10:
                logger.info(
                    "event_skipped_empty_payload tenant=%s host=%s type=%s",
                    tenant_id,
                    event_data.get("hostname"),
                    event_type,
                )
                return

            base_sev = (event_data.get("severity") or "INFO").upper()
            command_line = self._extract_command_line(event_data)

            if self._is_benign_process_event(event_type, text):
                logger.info(
                    "benign_process_suppressed tenant=%s host=%s type=%s",
                    tenant_id,
                    event_data.get("hostname"),
                    event_type,
                )
                return

            if self._is_plain_path_or_process_notice(text) and not any(x in text for x in EXECUTION_INDICATORS):
                logger.info(
                    "plain_process_notice_blocked tenant=%s host=%s type=%s",
                    tenant_id,
                    event_data.get("hostname"),
                    event_type,
                )
                return

            if event_type == "SPECIAL_LOGON" and "eventid:4672" in text and "nt authority" in text and "system" in text:
                logger.info(
                    "special_logon_system_noise_blocked tenant=%s host=%s",
                    tenant_id,
                    event_data.get("hostname"),
                )
                return

            score, rule, sev, matched = evaluate_rules(text, default_sev=base_sev)

            if self._sigma_engine:
                try:
                    sigma_matches = await self._sigma_engine.process_event(
                        {
                            **event_data,
                            "command_line": command_line,
                            "details": event_data.get("details") or "",
                            "type": event_type,
                        }
                    )
                    if sigma_matches:
                        top_sigma = max(
                            sigma_matches,
                            key=lambda m: int(m.get("risk", {}).get("score", 0) or 0),
                        )
                        sigma_score = int(top_sigma.get("risk", {}).get("score", 75) or 75)
                        sigma_sev = str(top_sigma.get("severity", "HIGH")).upper()
                        sigma_rule = str(top_sigma.get("rule", "Sigma Detection Match")).strip()
                        sigma_text = _norm(top_sigma.get("details"), top_sigma.get("command_line"))

                        if not should_block_sigma_promotion(
                            event_type=event_type,
                            rule_name=sigma_rule,
                            text=sigma_text or text,
                            command_line=command_line,
                        ):
                            score = max(score, sigma_score)
                            if sigma_sev in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                                sev = sigma_sev
                            if rule in {None, "", "Normal Activity"}:
                                rule = sigma_rule
                            matched = True
                except Exception as exc:
                    logger.warning("sigma_processing_failed tenant=%s error=%s", tenant_id, exc)

            if event_type in {"PROCESS_START", "PROCESS_CREATED", "PROCESS_CREATE_EVT"} and not command_line.strip():
                logger.info(
                    "no_command_line_process_blocked tenant=%s host=%s type=%s",
                    tenant_id,
                    event_data.get("hostname"),
                    event_type,
                )
                return

            if rule and str(rule).startswith("SIGMA:"):
                logger.warning("sigma_rule_name_blocked tenant=%s rule=%s", tenant_id, rule)
                return

            if rule and "mimikatz" in str(rule).lower() and not is_real_mimikatz(text):
                logger.warning(
                    "fake_mimikatz_blocked tenant=%s host=%s type=%s",
                    tenant_id,
                    event_data.get("hostname"),
                    event_type,
                )
                return

            if matched and "powershell" in text and not is_real_powershell_attack(text):
                logger.info(
                    "benign_powershell_blocked tenant=%s host=%s type=%s",
                    tenant_id,
                    event_data.get("hostname"),
                    event_type,
                )
                score, rule, sev, matched = 10, "Low Confidence PowerShell", "INFO", False

            if (
                event_type in {"PROCESS_START", "PROCESS_CREATED", "PROCESS_CREATE_EVT"}
                and not any(x in text for x in EXECUTION_INDICATORS)
                and not has_strong_attack_context(text)
            ):
                logger.info(
                    "process_event_without_exec_indicator_blocked tenant=%s host=%s type=%s",
                    tenant_id,
                    event_data.get("hostname"),
                    event_type,
                )
                return

            if score >= self.min_alert_score and not has_strong_attack_context(text):
                logger.warning(
                    "no_context_drop tenant=%s host=%s type=%s rule=%s score=%s",
                    tenant_id,
                    event_data.get("hostname"),
                    event_type,
                    rule,
                    score,
                )
                return

            try:
                if self._correlation:
                    await self._correlation.process_event(
                        {
                            **event_data,
                            "command_line": command_line,
                            "rule": rule,
                            "risk_score": score,
                            "tenant_id": tenant_id,
                        }
                    )
            except Exception as e:
                logger.warning("correlation_failed tenant=%s error=%s", tenant_id, e)

            if score < self.min_alert_score:
                logger.info(
                    "event_below_alert_threshold tenant=%s host=%s type=%s risk_score=%s sigma_promoted=%s",
                    tenant_id,
                    event_data.get("hostname"),
                    event_type,
                    score,
                    bool(matched),
                )
                return

            final_rule = rule or "Behavioral Detection"
            final_sev = (sev or base_sev or "INFO").upper()
            alert = create_alert(
                db,
                {**event_data, "command_line": command_line},
                score,
                final_rule,
                final_sev,
                tenant_id,
            )
            if alert is None:
                logger.warning(
                    "alert_service_blocked tenant=%s host=%s type=%s rule=%s",
                    tenant_id,
                    event_data.get("hostname"),
                    event_type,
                    final_rule,
                )
                return

            ensure_case_for_alert(db, alert=alert)

            try:
                status, incident = upsert_incident_for_new_alert(
                    db,
                    alert=alert,
                    tenant_id=tenant_id,
                )
                logger.info(
                    "incident_%s tenant=%s host=%s user=%s incident_id=%s campaign=%s severity=%s priority=%s",
                    status,
                    tenant_id,
                    getattr(alert, "hostname", None),
                    getattr(alert, "username", None),
                    incident.get("id") if isinstance(incident, dict) else None,
                    incident.get("campaign_family") if isinstance(incident, dict) else None,
                    incident.get("severity") if isinstance(incident, dict) else None,
                    incident.get("priority") if isinstance(incident, dict) else None,
                )

                try:
                    propagate_result = propagate_risk(
                        db,
                        alert=alert,
                        incident=incident if isinstance(incident, dict) else None,
                    )
                    logger.info(
                        "risk_propagated tenant=%s alert_id=%s updates=%s global_threat_level=%s",
                        tenant_id,
                        getattr(alert, "id", None),
                        len(propagate_result.get("updates", [])),
                        propagate_result.get("global_threat_level"),
                    )
                except Exception as exc:
                    logger.warning(
                        "risk_propagation_hook_failed tenant=%s alert_id=%s error=%s",
                        tenant_id,
                        getattr(alert, "id", None),
                        exc,
                    )

                try:
                    if isinstance(incident, dict):
                        response_result = auto_response(
                            incident,
                            tenant_id=tenant_id,
                        )
                        logger.info(
                            "auto_response_result tenant=%s incident_id=%s executed=%s skipped=%s errors=%s",
                            tenant_id,
                            incident.get("id"),
                            response_result.get("executed"),
                            response_result.get("skipped"),
                            response_result.get("errors"),
                        )
                except Exception as exc:
                    logger.warning(
                        "auto_response_hook_failed tenant=%s alert_id=%s error=%s",
                        tenant_id,
                        getattr(alert, "id", None),
                        exc,
                    )

            except Exception as exc:
                logger.exception(
                    "incident_upsert_failed tenant=%s alert_id=%s error=%s",
                    tenant_id,
                    getattr(alert, "id", None),
                    exc,
                )

            logger.info(
                "alert_created tenant=%s host=%s type=%s risk_score=%s rule=%s sigma_promoted=%s",
                tenant_id,
                event_data.get("hostname"),
                event_type,
                score,
                final_rule,
                bool(matched),
            )
            await broadcast(
                {
                    "type": "alert",
                    "data": alert.to_dict() if hasattr(alert, "to_dict") else {},
                }
            )

        except Exception:
            logger.exception(
                "event_processing_failed tenant=%s host=%s type=%s",
                tenant_id,
                event_data.get("hostname"),
                event_data.get("type"),
            )
            raise
        finally:
            db.close()
