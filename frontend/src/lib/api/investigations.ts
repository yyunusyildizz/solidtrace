import { apiGet } from "@/lib/api/client";
import type { InvestigationGraphData } from "@/components/soc/investigation-graph";

export type InvestigationStatus = "open" | "in_progress" | "contained" | "closed";
export type InvestigationSeverity = "CRITICAL" | "HIGH" | "WARNING" | "INFO";

export interface InvestigationQueueItem {
  id: string;
  alert_id: string;
  title: string;
  status: InvestigationStatus;
  severity: InvestigationSeverity;
  owner: string;
  created_at: string;
  updated_at: string;
  related_alerts: number;
  affected_host: string;
  summary: string;
  tags: string[];
}

export interface InvestigationGraphResponse extends InvestigationGraphData {
  alert_id: string;
  title: string;
  meta?: {
    summary?: string;
    related_alerts?: number;
  };
}

export async function getInvestigations(token?: string) {
  return apiGet<InvestigationQueueItem[]>("/api/investigations", token);
}

export async function getInvestigationGraph(alertId: string, token?: string) {
  return apiGet<InvestigationGraphResponse>(
    `/api/investigations/graph/${alertId}`,
    token,
  );
}