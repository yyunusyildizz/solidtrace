from __future__ import annotations

from collections import Counter
from typing import Optional, Dict, List, Set, Tuple

from app.database.db_manager import AlertModel, CaseAlertLinkModel, CaseModel


def _safe_node_id(prefix: str, value: str) -> str:
    return f"{prefix}:{value.strip()}"


MITRE_MAP = [
    {
        "match": ["mimikatz", "credential dumping", "lsass", "sekurlsa", "procdump lsass", "lsass dump"],
        "technique_id": "T1003",
        "technique_name": "Credential Dumping",
        "tactic": "Credential Access",
    },
    {
        "match": ["powershell", "invoke-webrequest", "downloadstring", "frombase64string"],
        "technique_id": "T1059.001",
        "technique_name": "PowerShell",
        "tactic": "Execution",
    },
    {
        "match": ["wmic", "process call create", "/node:"],
        "technique_id": "T1047",
        "technique_name": "Windows Management Instrumentation",
        "tactic": "Execution",
    },
    {
        "match": ["psexec", "paexec", "wmiexec", "admin$"],
        "technique_id": "T1021",
        "technique_name": "Remote Services",
        "tactic": "Lateral Movement",
    },
    {
        "match": ["net user", "new user created via net.exe", "create account"],
        "technique_id": "T1136",
        "technique_name": "Create Account",
        "tactic": "Persistence",
    },
    {
        "match": ["vssadmin delete shadows", "wbadmin delete catalog", "ransomware", "encrypt"],
        "technique_id": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "tactic": "Impact",
    },
]


NOISE_PROCESS_MARKERS = [
    "audiodg.exe",
    "trustedinstaller.exe",
    "tiworker.exe",
    "explorer.exe",
    "updater.exe",
    "officesvcmgr.exe",
    "systemsettings.exe",
    "rtkbtmanserv.exe",
    "pet.exe",
    "python.exe",
    "uvicorn.exe",
    "cargo.exe",
    "rustup.exe",
    "installassistservice.exe",
    "sppsvc.exe",
    "clipesuconsumer.exe",
    "language_server_windows_x64.exe",
    "mscopilot_proxy.exe",
    "microsoftedgeupdate.exe",
    "notepad.exe",
    "git-remote-https.exe",
    "7zfm.exe",
    "smartscreen.exe",
    "easyduplicatefinder.exe",
]

LOW_VALUE_RULE_MARKERS = [
    "process_anomaly_storm",
    "new user created via net.exe",
]


def _infer_mitre(text: str) -> Optional[dict]:
    hay = (text or "").lower()
    for item in MITRE_MAP:
        if any(keyword in hay for keyword in item["match"]):
            return item
    return None


def _derive_node_role(
    node_type: str,
    *,
    risk: int = 0,
    meta: Optional[str] = None,
    tactic: Optional[str] = None,
) -> str:
    meta_l = (meta or "").lower()
    tactic_l = (tactic or "").lower()

    if "pivot" in meta_l:
        return "pivot"
    if tactic_l == "impact" or risk >= 95:
        return "impact"
    if tactic_l in {"execution", "credential access", "lateral movement"}:
        return "entry"
    return "context"


def _node_score(
    node_type: str,
    *,
    risk: int = 0,
    meta: Optional[str] = None,
    tactic: Optional[str] = None,
) -> float:
    score = float(risk or 0)

    if node_type == "alert":
        score += 20
    elif node_type == "process":
        score += 12
    elif node_type in {"host", "user"}:
        score += 8
    elif node_type == "rule":
        score += 5

    meta_l = (meta or "").lower()
    if "pivot" in meta_l:
        score += 15

    tactic_bonus = {
        "credential access": 18,
        "lateral movement": 18,
        "execution": 12,
        "persistence": 12,
        "defense evasion": 14,
        "impact": 20,
        "discovery": 8,
    }
    score += tactic_bonus.get((tactic or "").lower(), 0)

    return round(score, 1)


def build_case_graph(db, case_id: str, tenant_id: Optional[str]) -> Optional[Dict]:
    case_query = db.query(CaseModel).filter(CaseModel.id == case_id)
    if tenant_id and hasattr(CaseModel, "tenant_id"):
        case_query = case_query.filter(CaseModel.tenant_id == tenant_id)

    case_row = case_query.first()
    if not case_row:
        return None

    links = db.query(CaseAlertLinkModel).filter(CaseAlertLinkModel.case_id == case_id).all()
    alert_ids = [link.alert_id for link in links]
    alerts: List[AlertModel] = []

    if alert_ids:
        alert_query = db.query(AlertModel).filter(AlertModel.id.in_(alert_ids))
        if tenant_id and hasattr(AlertModel, "tenant_id"):
            alert_query = alert_query.filter(AlertModel.tenant_id == tenant_id)
        alerts = alert_query.all()

    nodes: list[dict] = []
    edges: list[dict] = []

    seen_nodes: Set[str] = set()
    seen_edges: Set[Tuple[str, str, str]] = set()

    def add_node(
        node_id: str,
        label: str,
        node_type: str,
        risk: Optional[int] = None,
        meta: Optional[str] = None,
        tactic: Optional[str] = None,
        technique_id: Optional[str] = None,
        technique_name: Optional[str] = None,
    ):
        if node_id in seen_nodes:
            return
        seen_nodes.add(node_id)

        role = _derive_node_role(node_type, risk=int(risk or 0), meta=meta, tactic=tactic)
        score = _node_score(node_type, risk=int(risk or 0), meta=meta, tactic=tactic)

        nodes.append(
            {
                "id": node_id,
                "label": label,
                "type": node_type,
                "risk": risk,
                "meta": meta,
                "tactic": tactic,
                "technique_id": technique_id,
                "technique_name": technique_name,
                "role": role,
                "score": score,
                "highlighted": False,
            }
        )

    def add_edge(from_id: str, to_id: str, label: Optional[str] = None, weight: float = 1.0):
        key = (from_id, to_id, label or "")
        if key in seen_edges:
            return
        seen_edges.add(key)
        edges.append(
            {
                "from": from_id,
                "to": to_id,
                "label": label,
                "weight": round(weight, 2),
                "highlighted": False,
            }
        )

    host_counter = Counter()
    user_counter = Counter()
    for alert in alerts:
        if getattr(alert, "hostname", None):
            host_counter[alert.hostname] += 1
        if getattr(alert, "username", None):
            user_counter[alert.username] += 1

    case_node_id = _safe_node_id("case", case_row.id)
    add_node(case_node_id, case_row.title or "Case", "rule", meta=f"status={case_row.status}")

    alerts_sorted = sorted(alerts, key=lambda a: (getattr(a, "created_at", "") or ""))
    previous_alert_node_id: Optional[str] = None

    for alert in alerts_sorted:
        alert_label = alert.rule or alert.type or "Alert"
        full_text = " ".join(
            [
                str(alert.rule or ""),
                str(alert.type or ""),
                str(alert.details or ""),
                str(alert.command_line or ""),
            ]
        )
        mitre = _infer_mitre(full_text)
        tactic = mitre.get("tactic") if mitre else None
        technique_id = mitre.get("technique_id") if mitre else None
        technique_name = mitre.get("technique_name") if mitre else None
        risk = int(alert.risk_score or 0)

        if any(marker in alert_label.lower() for marker in LOW_VALUE_RULE_MARKERS):
            continue

        alert_node_id = _safe_node_id("alert", alert.id)
        add_node(
            alert_node_id,
            alert_label,
            "alert",
            risk=risk,
            meta=alert.severity,
            tactic=tactic,
            technique_id=technique_id,
            technique_name=technique_name,
        )
        add_edge(case_node_id, alert_node_id, "contains", weight=1.0 + (risk / 100.0))

        if previous_alert_node_id and previous_alert_node_id != alert_node_id:
            add_edge(previous_alert_node_id, alert_node_id, "sequence", weight=1.2 + (risk / 120.0))
        previous_alert_node_id = alert_node_id

        if getattr(alert, "hostname", None):
            host_meta = "pivot" if host_counter[alert.hostname] >= 2 else "affected host"
            host_id = _safe_node_id("host", alert.hostname)
            add_node(host_id, alert.hostname, "host", risk=risk, meta=host_meta)
            add_edge(alert_node_id, host_id, "on_host", weight=1.1)

        if getattr(alert, "username", None):
            user_meta = "pivot" if user_counter[alert.username] >= 2 else "affected user"
            user_id = _safe_node_id("user", alert.username)
            add_node(user_id, alert.username, "user", risk=risk, meta=user_meta)
            add_edge(alert_node_id, user_id, "by_user", weight=1.05)

        if getattr(alert, "rule", None):
            rule_id = _safe_node_id("rule", alert.rule)
            add_node(
                rule_id,
                alert.rule,
                "rule",
                risk=risk,
                meta="detection rule",
                tactic=tactic,
                technique_id=technique_id,
                technique_name=technique_name,
            )
            add_edge(alert_node_id, rule_id, "matched_rule", weight=0.95)

        cmd = (getattr(alert, "command_line", None) or "").strip()
        if cmd and not any(marker in cmd.lower() for marker in NOISE_PROCESS_MARKERS):
            process_label = cmd[:100]
            process_id = _safe_node_id("process", process_label)
            add_node(
                process_id,
                process_label,
                "process",
                risk=risk,
                meta=f"pid={alert.pid}" if getattr(alert, "pid", None) else None,
                tactic=tactic,
                technique_id=technique_id,
                technique_name=technique_name,
            )
            add_edge(alert_node_id, process_id, "spawned_process", weight=1.15)

    if nodes:
        top_node_ids = {
            node["id"] for node in sorted(nodes, key=lambda x: x.get("score", 0), reverse=True)[:5]
        }
        for node in nodes:
            if node["id"] in top_node_ids:
                node["highlighted"] = True
        for edge in edges:
            if edge["from"] in top_node_ids or edge["to"] in top_node_ids:
                edge["highlighted"] = True

    tactic_counts = Counter(node["tactic"] for node in nodes if node.get("tactic"))
    technique_counts = Counter(node["technique_id"] for node in nodes if node.get("technique_id"))
    summary_parts = []

    if case_row.description:
        summary_parts.append(case_row.description)

    if tactic_counts:
        summary_parts.append("Tactics: " + ", ".join(f"{k}({v})" for k, v in tactic_counts.most_common(3)))
    if technique_counts:
        summary_parts.append("MITRE: " + ", ".join(f"{k}({v})" for k, v in technique_counts.most_common(3)))

    if nodes:
        top_path = sorted(nodes, key=lambda x: x.get("score", 0), reverse=True)[:3]
        if top_path:
            summary_parts.append("Primary path: " + " -> ".join(node["label"] for node in top_path))

    return {
        "alert_id": case_row.id,
        "title": case_row.title,
        "nodes": nodes,
        "edges": edges,
        "meta": {
            "summary": " | ".join(summary_parts) if summary_parts else case_row.analyst_note,
            "related_alerts": len(alerts),
            "tactics": [k for k, _ in tactic_counts.most_common(5)],
            "techniques": [k for k, _ in technique_counts.most_common(5)],
        },
    }
