import { apiGet, apiPost } from "@/lib/api/client";

export interface AlertItem {
  id: string;
  created_at?: string | null;
  hostname?: string | null;
  username?: string | null;
  type?: string | null;
  rule?: string | null;
  severity?: "CRITICAL" | "HIGH" | "WARNING" | "INFO" | string | null;
  details?: string | null;
  command_line?: string | null;
  pid?: number | null;
  serial?: string | null;
  risk_score?: number | null;
  status?: "open" | "acknowledged" | "resolved" | string | null;
  analyst_note?: string | null;
  assigned_to?: string | null;
  assigned_at?: string | null;
  resolved_at?: string | null;
  resolved_by?: string | null;
}

export interface AlertActionResponse {
  status: string;
  alert_id: string;
  analyst_note?: string | null;
  assigned_to?: string | null;
  assigned_at?: string | null;
}

export async function getAlerts(token?: string, limit = 100) {
  return apiGet<AlertItem[]>(`/api/alerts?limit=${limit}`, token);
}

export async function getAlertDetail(alertId: string, token?: string) {
  return apiGet<AlertItem>(`/api/alerts/${alertId}`, token);
}

export async function acknowledgeAlert(alertId: string, token?: string) {
  return apiPost<AlertActionResponse>(`/api/alerts/${alertId}/ack`, {}, token);
}

export async function assignAlert(alertId: string, assignedTo: string, token?: string) {
  return apiPost<AlertActionResponse>(
    `/api/alerts/${alertId}/assign`,
    { assigned_to: assignedTo },
    token,
  );
}

export async function unassignAlert(alertId: string, token?: string) {
  return apiPost<AlertActionResponse>(`/api/alerts/${alertId}/unassign`, {}, token);
}

export async function resolveAlert(alertId: string, note: string, token?: string) {
  return apiPost<AlertActionResponse>(
    `/api/alerts/${alertId}/resolve`,
    { note },
    token,
  );
}

export async function reopenAlert(alertId: string, token?: string) {
  return apiPost<AlertActionResponse>(`/api/alerts/${alertId}/reopen`, {}, token);
}

export async function updateAlertNote(alertId: string, note: string, token?: string) {
  return apiPost<AlertActionResponse>(
    `/api/alerts/${alertId}/note`,
    { note },
    token,
  );
}