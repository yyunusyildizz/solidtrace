"""
app.schemas.models
==================
Pydantic şemaları
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, EmailStr, Field, field_validator


# ---------------------------------------------------------------------------
# AUTH
# ---------------------------------------------------------------------------

class LoginResponse(BaseModel):
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    role: Optional[str] = None
    username: Optional[str] = None
    password_change_required: Optional[bool] = False
    two_fa_required: bool = False
    pending_2fa_token: Optional[str] = None


Token = LoginResponse


class LoginRequest(BaseModel):
    username: str
    password: str

    @field_validator("username", "password")
    @classmethod
    def strip_required_fields(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Alan boş olamaz")
        return value


class TwoFALoginRequest(BaseModel):
    pending_2fa_token: str
    totp_code: str

    @field_validator("pending_2fa_token", "totp_code")
    @classmethod
    def strip_required_fields(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Alan boş olamaz")
        return value


class RefreshTokenRequest(BaseModel):
    refresh_token: str

    @field_validator("refresh_token")
    @classmethod
    def validate_refresh_token(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("refresh_token boş olamaz")
        return value


class TwoFAVerifyRequest(BaseModel):
    code: str

    @field_validator("code")
    @classmethod
    def validate_code(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("code boş olamaz")
        return value


class TwoFADisableRequest(BaseModel):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("password boş olamaz")
        return value


class UserCreateRequest(BaseModel):
    username: str
    password: Optional[str] = None
    role: str = "analyst"
    email: Optional[EmailStr] = None
    tenant_id: Optional[str] = None

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("username boş olamaz")
        return value

    @field_validator("role")
    @classmethod
    def validate_role(cls, value: str) -> str:
        value = value.strip().lower()
        if value not in {"viewer", "analyst", "admin"}:
            raise ValueError("role viewer, analyst veya admin olmalı")
        return value


class UserInviteRequest(BaseModel):
    username: str
    role: str = "analyst"
    email: EmailStr
    tenant_id: Optional[str] = None

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("username boş olamaz")
        return value

    @field_validator("role")
    @classmethod
    def validate_role(cls, value: str) -> str:
        value = value.strip().lower()
        if value not in {"viewer", "analyst", "admin"}:
            raise ValueError("role viewer, analyst veya admin olmalı")
        return value


class InviteSetupRequest(BaseModel):
    token: str
    new_password: str

    @field_validator("token", "new_password")
    @classmethod
    def strip_required_fields(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Alan boş olamaz")
        return value


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str

    @field_validator("current_password", "new_password")
    @classmethod
    def strip_required_fields(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Alan boş olamaz")
        return value


class AdminPasswordResetRequest(BaseModel):
    username: str
    new_password: str

    @field_validator("username", "new_password")
    @classmethod
    def strip_required_fields(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Alan boş olamaz")
        return value


# ---------------------------------------------------------------------------
# TENANT
# ---------------------------------------------------------------------------

class TenantCreateRequest(BaseModel):
    name: str
    contact_email: Optional[str] = None
    max_agents: int = 10
    plan: str = "starter"

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("name boş olamaz")
        return value[:100]

    @field_validator("max_agents")
    @classmethod
    def validate_max_agents(cls, value: int) -> int:
        if value < 1:
            raise ValueError("max_agents en az 1 olmalı")
        return value


# ---------------------------------------------------------------------------
# AGENT ENROLLMENT / REGISTER / HEARTBEAT
# ---------------------------------------------------------------------------

class AgentEnrollmentTokenCreateRequest(BaseModel):
    tenant_id: str
    expires_in_minutes: int = 30

    @field_validator("tenant_id")
    @classmethod
    def validate_tenant_id(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("tenant_id boş olamaz")
        return value

    @field_validator("expires_in_minutes")
    @classmethod
    def validate_expiry(cls, value: int) -> int:
        if value < 5 or value > 1440:
            raise ValueError("expires_in_minutes 5 ile 1440 arasında olmalı")
        return value


class AgentEnrollmentTokenCreateResponse(BaseModel):
    enrollment_token: str
    expires_at: str
    tenant_id: str


class AgentRegisterRequest(BaseModel):
    enrollment_token: str
    hostname: str
    device_fingerprint: str
    os_name: Optional[str] = None
    agent_version: Optional[str] = None

    @field_validator("enrollment_token")
    @classmethod
    def validate_enrollment_token(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("enrollment_token boş olamaz")
        return value

    @field_validator("hostname")
    @classmethod
    def validate_hostname(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("hostname boş olamaz")
        return value.strip()

    @field_validator("device_fingerprint")
    @classmethod
    def validate_fingerprint(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("device_fingerprint boş olamaz")
        cleaned = value.strip()
        if len(cleaned) < 8:
            raise ValueError("device_fingerprint çok kısa")
        return cleaned

    @field_validator("os_name", "agent_version")
    @classmethod
    def strip_optional_agent_fields(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        value = value.strip()
        return value or None


class AgentRegisterResponse(BaseModel):
    agent_id: str
    agent_secret: str
    tenant_id: str


class AgentListResponse(BaseModel):
    id: str
    tenant_id: str
    hostname: str
    device_fingerprint: str
    os_name: Optional[str] = None
    agent_version: Optional[str] = None
    enrolled_at: str
    last_seen: Optional[str] = None
    is_active: bool
    revoked_at: Optional[str] = None
    last_ip: Optional[str] = None
    last_user: Optional[str] = None


class AgentHeartbeatRequest(BaseModel):
    hostname: str
    agent_version: Optional[str] = None
    os_name: Optional[str] = None
    user: Optional[str] = None
    ip: Optional[str] = None
    uptime_seconds: Optional[int] = None
    cpu_percent: Optional[float] = None
    memory_percent: Optional[float] = None

    @field_validator("hostname")
    @classmethod
    def hostname_not_empty(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("hostname boş olamaz")
        return value.strip()

    @field_validator("agent_version", "os_name", "user", "ip")
    @classmethod
    def strip_optional_heartbeat_fields(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        value = value.strip()
        return value or None

    @field_validator("uptime_seconds")
    @classmethod
    def validate_uptime(cls, value: Optional[int]) -> Optional[int]:
        if value is not None and value < 0:
            raise ValueError("uptime_seconds negatif olamaz")
        return value

    @field_validator("cpu_percent", "memory_percent")
    @classmethod
    def validate_percentages(cls, value: Optional[float]) -> Optional[float]:
        if value is not None and (value < 0 or value > 100):
            raise ValueError("yüzde alanları 0 ile 100 arasında olmalı")
        return value


class AgentHeartbeatResponse(BaseModel):
    status: str = "ok"
    server_time: str


# ---------------------------------------------------------------------------
# DETECTION RULES / EVENTS
# ---------------------------------------------------------------------------

class DetectionRuleSchema(BaseModel):
    name: str = Field(..., min_length=3, max_length=100)
    keyword: str = Field(..., min_length=1, max_length=200)
    risk_score: int = Field(..., ge=0, le=100)
    severity: str = Field(..., pattern="^(INFO|WARNING|HIGH|CRITICAL)$")


class EventBase(BaseModel):
    type: str
    hostname: str
    user: Optional[str] = "SYSTEM"
    pid: Optional[int] = 0
    details: Optional[str] = ""
    command_line: Optional[str] = ""
    serial: Optional[str] = None
    severity: Optional[str] = "INFO"
    timestamp: Optional[str] = None

    @field_validator("type")
    @classmethod
    def validate_type(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("type boş olamaz")
        return value[:128]

    @field_validator("hostname")
    @classmethod
    def hostname_not_empty(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("hostname boş olamaz")
        cleaned = value.strip()
        fake = {"localhost", "unknown", "unknown-host", "sys_internal", "none", "null", "(none)", "computer"}
        if cleaned.lower() in fake:
            raise ValueError(f"Geçersiz hostname: '{cleaned}'.")
        return cleaned

    @field_validator("user", "details", "command_line", "serial", "severity", "timestamp")
    @classmethod
    def truncate_optional_fields(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        if len(value) > 10_000:
            return value[:10_000] + "...[truncated]"
        return value

    @field_validator("pid")
    @classmethod
    def validate_pid(cls, value: Optional[int]) -> Optional[int]:
        if value is not None and value < 0:
            raise ValueError("pid negatif olamaz")
        return value


class ActionRequest(BaseModel):
    hostname: str
    pid: Optional[int] = 0
    rule: Optional[str] = None
    severity: Optional[str] = None
    details: Optional[str] = None
    serial: Optional[str] = None
    risk_score: Optional[int] = 0
    command_line: Optional[str] = None
    description: Optional[str] = None

    @field_validator("hostname")
    @classmethod
    def validate_hostname(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("hostname boş olamaz")
        return value[:255]

    @field_validator("pid")
    @classmethod
    def validate_pid(cls, value: Optional[int]) -> Optional[int]:
        if value is not None and value < 0:
            raise ValueError("pid negatif olamaz")
        return value

    @field_validator("rule", "severity", "details", "serial", "command_line", "description")
    @classmethod
    def strip_optional_action_fields(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        value = value.strip()
        return value or None

    @field_validator("risk_score")
    @classmethod
    def validate_risk_score(cls, value: Optional[int]) -> Optional[int]:
        if value is not None and (value < 0 or value > 100):
            raise ValueError("risk_score 0 ile 100 arasında olmalı")
        return value


class HashReport(BaseModel):
    hostname: str
    file_path: str
    file_hash: str
    pid: int

    @field_validator("hostname", "file_path")
    @classmethod
    def strip_required_fields(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Alan boş olamaz")
        return value

    @field_validator("file_hash")
    @classmethod
    def validate_hash(cls, value: str) -> str:
        value = value.strip().lower()
        if len(value) not in (32, 64) or not all(c in "0123456789abcdef" for c in value):
            raise ValueError("Geçersiz hash formatı (MD5 veya SHA256 bekleniyor)")
        return value

    @field_validator("pid")
    @classmethod
    def validate_pid(cls, value: int) -> int:
        if value < 0:
            raise ValueError("pid negatif olamaz")
        return value


# ---------------------------------------------------------------------------
# ALERT LIFECYCLE / ASSIGNMENT
# ---------------------------------------------------------------------------

class AlertStatusUpdateRequest(BaseModel):
    status: Literal["open", "acknowledged", "resolved"]


class AlertResolveRequest(BaseModel):
    note: Optional[str] = None

    @field_validator("note")
    @classmethod
    def validate_note(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        value = value.strip()
        if len(value) > 4000:
            value = value[:4000]
        return value or None


class AlertNoteUpdateRequest(BaseModel):
    note: str

    @field_validator("note")
    @classmethod
    def validate_note(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("note boş olamaz")
        return value[:4000]


class AlertAssignRequest(BaseModel):
    assigned_to: str

    @field_validator("assigned_to")
    @classmethod
    def validate_assigned_to(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("assigned_to boş olamaz")
        return value[:150]


class AlertResponse(BaseModel):
    id: str
    created_at: str
    hostname: Optional[str] = None
    username: Optional[str] = None
    type: Optional[str] = None
    risk_score: int = 0
    rule: Optional[str] = None
    severity: Optional[str] = None
    details: Optional[str] = None
    command_line: Optional[str] = None
    pid: Optional[int] = None
    serial: Optional[str] = None
    tenant_id: Optional[str] = None
    status: Optional[str] = "open"
    analyst_note: Optional[str] = None
    resolved_at: Optional[str] = None
    resolved_by: Optional[str] = None
    assigned_to: Optional[str] = None
    assigned_at: Optional[str] = None


class AlertActionResponse(BaseModel):
    status: str
    alert_id: str
    analyst_note: Optional[str] = None
    assigned_to: Optional[str] = None
    assigned_at: Optional[str] = None



class InvestigationQueueItem(BaseModel):
    id: str
    alert_id: str
    title: str
    severity: Optional[str] = None
    status: Optional[str] = "open"
    owner: str = "Unassigned"
    created_at: str
    updated_at: str
    related_alerts: int = 0
    affected_host: Optional[str] = None
    username: Optional[str] = None
    rule: Optional[str] = None
    risk_score: Optional[int] = 0
    summary: Optional[str] = None
    tags: list[str] = []


class InvestigationGraphNode(BaseModel):
    id: str
    label: str
    type: Literal["alert", "host", "user", "process", "rule"]
    risk: Optional[int] = None
    meta: Optional[str] = None


class InvestigationGraphEdge(BaseModel):
    from_: str = Field(alias="from")
    to: str
    label: Optional[str] = None

    model_config = {
        "populate_by_name": True,
    }


class InvestigationGraphMeta(BaseModel):
    summary: Optional[str] = None
    related_alerts: int = 0


class InvestigationGraphResponse(BaseModel):
    alert_id: str
    title: str
    nodes: list[InvestigationGraphNode]
    edges: list[InvestigationGraphEdge]
    meta: Optional[InvestigationGraphMeta] = None


# ---------------------------------------------------------------------------
# ASSET INVENTORY
# ---------------------------------------------------------------------------

class AssetListItemResponse(BaseModel):
    id: str
    tenant_id: str
    hostname: str
    os_name: Optional[str] = None
    agent_version: Optional[str] = None
    enrolled_at: str
    last_seen: Optional[str] = None
    online_status: Literal["online", "offline", "unknown"]
    is_active: bool
    revoked_at: Optional[str] = None
    last_ip: Optional[str] = None
    last_user: Optional[str] = None
    total_alerts: int = 0
    critical_count: int = 0
    high_count: int = 0
    max_risk_score: int = 0


class AssetDetailResponse(BaseModel):
    id: str
    tenant_id: str
    hostname: str
    device_fingerprint: str
    os_name: Optional[str] = None
    agent_version: Optional[str] = None
    enrolled_at: str
    last_seen: Optional[str] = None
    online_status: Literal["online", "offline", "unknown"]
    is_active: bool
    revoked_at: Optional[str] = None
    last_ip: Optional[str] = None
    last_user: Optional[str] = None
    total_alerts: int = 0
    critical_count: int = 0
    high_count: int = 0
    max_risk_score: int = 0
    latest_alert_at: Optional[str] = None
    recent_alerts: list[dict] = []

# ---------------------------------------------------------------------------
# DASHBOARD / SIGMA / UEBA
# ---------------------------------------------------------------------------

class DashboardNameCountItem(BaseModel):
    name: str
    count: int


class DashboardLatestAlertItem(BaseModel):
    id: str
    created_at: Optional[str] = None
    hostname: Optional[str] = None
    severity: Optional[str] = None
    rule: Optional[str] = None
    status: Optional[str] = None
    risk_score: int = 0


class DashboardSummaryResponse(BaseModel):
    generated_at: str
    total_alerts: int = 0
    critical_alerts: int = 0
    high_alerts: int = 0
    alerts_last_24h: int = 0
    open_alerts: int = 0
    acknowledged_alerts: int = 0
    resolved_alerts: int = 0
    total_assets: int = 0
    online_assets: int = 0
    offline_assets: int = 0
    revoked_assets: int = 0
    top_hosts: list[DashboardNameCountItem] = []
    top_rules: list[DashboardNameCountItem] = []
    latest_alerts: list[DashboardLatestAlertItem] = []


class DashboardRecentActivityItem(BaseModel):
    timestamp: Optional[str] = None
    activity_type: Literal["alert", "audit"]
    title: str
    description: Optional[str] = None
    severity: Optional[str] = None
    hostname: Optional[str] = None
    username: Optional[str] = None
    status: Optional[str] = None
    source_id: Optional[str] = None


class SigmaTopRuleItem(BaseModel):
    name: str
    count: int


class SigmaStatsResponse(BaseModel):
    total_matches: int = 0
    matches_last_24h: int = 0
    severity_distribution: dict = {}
    top_rules: list[SigmaTopRuleItem] = []
    engine_status: str = "idle"
    note: Optional[str] = None


class UEBAProfileItem(BaseModel):
    entity_name: str
    entity_type: Literal["user", "host"]
    risk_score: int = 0
    alert_count: int = 0
    last_seen: Optional[str] = None


class UEBAProfilesResponse(BaseModel):
    profile_count: int = 0
    risky_profile_count: int = 0
    baseline_ready: bool = False
    last_profile_update_at: Optional[str] = None
    profiles: list[UEBAProfileItem] = []
    note: Optional[str] = None

# ---------------------------------------------------------------------------
# CASE / INCIDENT / CAMPAIGN OVERRIDES (canonical final definitions)
# ---------------------------------------------------------------------------

class CaseCreateRequest(BaseModel):
    title: str
    description: Optional[str] = None
    severity: Optional[str] = "INFO"
    owner: Optional[str] = None

    @field_validator("title")
    @classmethod
    def validate_title(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("title boş olamaz")
        return value[:255]


class CaseAssignRequest(BaseModel):
    owner: str

    @field_validator("owner")
    @classmethod
    def validate_owner(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("owner boş olamaz")
        return value[:150]


class CaseStatusUpdateRequest(BaseModel):
    status: Literal["open", "acknowledged", "resolved", "closed"]


class CaseNoteUpdateRequest(BaseModel):
    note: str

    @field_validator("note")
    @classmethod
    def validate_note(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("note boş olamaz")
        return value[:4000]


class CaseResponse(BaseModel):
    id: str
    tenant_id: Optional[str] = None
    title: str
    description: Optional[str] = None
    status: str = "open"
    severity: str = "INFO"
    owner: Optional[str] = None
    analyst_note: Optional[str] = None
    created_at: str
    updated_at: str
    closed_at: Optional[str] = None
    related_alert_count: int = 0
    related_alerts: list[AlertResponse] = []


class CaseDetailResponse(CaseResponse):
    timeline: list[dict] = []
    linked_hosts: list[str] = []
    linked_users: list[str] = []
    max_risk_score: int = 0
    avg_risk_score: float = 0.0
    critical_alert_count: int = 0
    high_alert_count: int = 0


class InvestigationCampaignItem(BaseModel):
    campaign_key: str
    campaign_score: float = 0.0
    campaign_confidence: Optional[str] = None
    investigation_count: int = 0
    top_severity: Optional[str] = None
    normalized_family: Optional[str] = None
    family_confidence: Optional[str] = None
    hosts: list[str] = []
    users: list[str] = []
    rules: list[str] = []
    sample_investigation_ids: list[str] = []
    latest_seen: Optional[str] = None


class InvestigationCampaignListResponse(BaseModel):
    total_campaigns: int = 0
    items: list[InvestigationCampaignItem] = []


class GlobalCampaignItem(BaseModel):
    campaign_family: str
    user: str
    campaign_score: float = 0.0
    campaign_confidence: Optional[str] = None
    total_events: int = 0
    affected_hosts: list[str] = []
    top_severity: Optional[str] = None
    sample_investigation_ids: list[str] = []
    latest_seen: Optional[str] = None


class GlobalCampaignListResponse(BaseModel):
    total_campaigns: int = 0
    items: list[GlobalCampaignItem] = []


class GlobalCampaignEscalationResponse(BaseModel):
    campaign_family: str
    user: str
    recommended_severity: str
    incident_priority: int = 0
    spread_depth: int = 0
    affected_hosts: list[str] = []
    total_events: int = 0
    escalation_reasons: list[str] = []


class GlobalCampaignResponsePlan(BaseModel):
    campaign_family: str
    user: str
    auto_incident: bool = False
    incident_title: Optional[str] = None
    playbook: Optional[str] = None
    recommended_actions: list[str] = []
    priority: int = 0


class InvestigationGraphNode(BaseModel):
    id: str
    label: str
    type: str
    risk: Optional[int] = None
    meta: Optional[str] = None
    tactic: Optional[str] = None
    role: Optional[str] = None
    score: Optional[float] = 0.0
    highlighted: bool = False


class InvestigationGraphEdge(BaseModel):
    from_: str = Field(alias="from")
    to: str
    label: str
    weight: Optional[float] = 1.0
    highlighted: bool = False

    model_config = {"populate_by_name": True}


class InvestigationGraphMeta(BaseModel):
    summary: Optional[str] = None
    related_alerts: int = 0
    severity: Optional[str] = None
    status: Optional[str] = None
    entry_nodes: list[str] = []
    pivot_nodes: list[str] = []
    impact_nodes: list[str] = []
    primary_attack_path: list[str] = []
    kill_chain_phases: list[str] = []
    campaign_confidence: Optional[str] = None
    related_investigation_ids: list[str] = []


class InvestigationGraphResponse(BaseModel):
    alert_id: str
    title: str
    nodes: list[InvestigationGraphNode] = []
    edges: list[InvestigationGraphEdge] = []
    meta: Optional[InvestigationGraphMeta] = None


class IncidentResponse(BaseModel):
    id: str
    campaign_family: str
    user: str
    title: str
    severity: str
    priority: int = 0
    status: str = "open"
    owner: Optional[str] = None
    analyst_note: Optional[str] = None
    playbook: Optional[str] = None
    recommended_actions: list[str] = []
    affected_hosts: list[str] = []
    total_events: int = 0
    spread_depth: int = 0
    source_type: str = "global_campaign"
    source_key: Optional[str] = None
    confidence: str = "medium"               # EKLENDİ
    attack_story: list[str] = []             # EKLENDİ
    created_at: str
    updated_at: str


class IncidentCreateFromCampaignResponse(BaseModel):
    status: str
    incident: IncidentResponse


class IncidentListResponse(BaseModel):
    total: int = 0
    items: list[IncidentResponse] = []


class IncidentStatusUpdateRequest(BaseModel):
    status: Literal["open", "acknowledged", "resolved"]


class IncidentAssignRequest(BaseModel):
    owner: str

    @field_validator("owner")
    @classmethod
    def validate_owner_incident(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("owner boş olamaz")
        return value[:150]


class IncidentNoteUpdateRequest(BaseModel):
    note: str

    @field_validator("note")
    @classmethod
    def validate_note_incident(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("note boş olamaz")
        return value[:4000]


class IncidentTimelineItem(BaseModel):
    id: str
    incident_id: str
    event_type: str
    actor: Optional[str] = None
    title: str
    details: Optional[str] = None
    created_at: str


class IncidentTimelineResponse(BaseModel):
    incident_id: str
    items: list[IncidentTimelineItem] = []

class IncidentAlertListResponse(BaseModel):
    incident_id: str
    total: int = 0
    items: list[AlertResponse] = []

class IncidentAlertListResponse(BaseModel):
    incident_id: str
    total: int = 0
    items: list[AlertResponse] = []

class IncidentGraphResponse(BaseModel):
    incident_id: str
    title: str
    nodes: list[InvestigationGraphNode] = []
    edges: list[InvestigationGraphEdge] = []
    meta: InvestigationGraphMeta    

class AttackChainStep(BaseModel):
    step: int
    stage: str
    node_id: str
    label: str
    node_type: str
    evidence: Optional[str] = None
    risk: int = 0
    technique_id: Optional[str] = None
    technique_name: Optional[str] = None
    tactic: Optional[str] = None


class IncidentAttackChainResponse(BaseModel):
    incident_id: str
    title: str
    confidence: str
    primary_user: Optional[str] = None
    primary_process: Optional[str] = None
    primary_rule: Optional[str] = None
    affected_hosts: list[str] = []
    kill_chain_phases: list[str] = []
    steps: list[AttackChainStep] = []

class IncidentResponseAction(BaseModel):
    action: str
    automated: bool = False
    reason: Optional[str] = None
    priority: int = 0


class IncidentResponsePlanResponse(BaseModel):
    incident_id: str
    title: str
    confidence: str
    auto_execute: bool = False
    recommended_actions: list[IncidentResponseAction] = []
    escalation_reasons: list[str] = []

class IncidentExecutionResult(BaseModel):
    incident_id: str
    executed: list[str] = []
    skipped: list[str] = []
    errors: list[str] = []