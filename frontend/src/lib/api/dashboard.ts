import { apiGet } from "@/lib/api/client";

export interface DashboardNameCountItem {
  name: string;
  count: number;
}

export interface DashboardLatestAlertItem {
  id: string;
  created_at?: string | null;
  hostname?: string | null;
  severity?: string | null;
  rule?: string | null;
  status?: string | null;
  risk_score?: number | null;
}

export interface DashboardSummaryResponse {
  generated_at: string;
  total_alerts: number;
  critical_alerts: number;
  high_alerts: number;
  alerts_last_24h: number;
  open_alerts: number;
  acknowledged_alerts: number;
  resolved_alerts: number;
  total_assets: number;
  online_assets: number;
  offline_assets: number;
  revoked_assets: number;
  top_hosts: DashboardNameCountItem[];
  top_rules: DashboardNameCountItem[];
  latest_alerts: DashboardLatestAlertItem[];
}

export interface DashboardRecentActivityItem {
  timestamp?: string | null;
  activity_type: "alert" | "audit";
  title: string;
  description?: string | null;
  severity?: string | null;
  hostname?: string | null;
  username?: string | null;
  status?: string | null;
  source_id?: string | null;
}

export interface AssetListItemResponse {
  id: string;
  tenant_id: string;
  hostname: string;
  os_name?: string | null;
  agent_version?: string | null;
  enrolled_at: string;
  last_seen?: string | null;
  online_status: "online" | "offline" | "unknown";
  is_active: boolean;
  revoked_at?: string | null;
  last_ip?: string | null;
  last_user?: string | null;
  total_alerts: number;
  critical_count: number;
  high_count: number;
  max_risk_score: number;
}

export interface SigmaStatsResponse {
  total_matches: number;
  matches_last_24h: number;
  severity_distribution: Record<string, number>;
  top_rules: { name: string; count: number }[];
  engine_status: string;
  note?: string | null;
}

export interface UEBAProfileItem {
  entity_name: string;
  entity_type: "user" | "host";
  risk_score: number;
  alert_count: number;
  last_seen?: string | null;
}

export interface UEBAProfilesResponse {
  profile_count: number;
  risky_profile_count: number;
  baseline_ready: boolean;
  last_profile_update_at?: string | null;
  profiles: UEBAProfileItem[];
  note?: string | null;
}

export async function getDashboardSummary(token?: string) {
  return apiGet<DashboardSummaryResponse>("/api/dashboard/summary", token);
}

export async function getRecentActivity(token?: string) {
  return apiGet<DashboardRecentActivityItem[]>(
    "/api/dashboard/recent-activity?limit=20",
    token,
  );
}

export async function getAssets(token?: string) {
  return apiGet<AssetListItemResponse[]>("/api/v1/assets?limit=10", token);
}

export async function getSigmaStats(token?: string) {
  return apiGet<SigmaStatsResponse>("/api/v1/sigma/stats", token);
}

export async function getUEBAProfiles(token?: string) {
  return apiGet<UEBAProfilesResponse>("/api/v1/ueba/profiles", token);
}
