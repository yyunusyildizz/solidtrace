import { apiGet, apiPatch } from "@/lib/api/client";
import type { InvestigationGraphData } from "@/components/soc/investigation-graph";

export type InvestigationStatus =
  | "open"
  | "in_progress"
  | "contained"
  | "closed"
  | "acknowledged"
  | "suppressed";

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

export interface IncidentItem {
  id: string;
  campaign_family: string;
  user: string;
  title: string;
  severity: InvestigationSeverity;
  priority: number;
  status: InvestigationStatus;
  owner?: string | null;
  analyst_note?: string | null;
  playbook?: string | null;
  recommended_actions: string[];
  affected_hosts: string[];
  total_events: number;
  spread_depth: number;
  source_type: string;
  source_key?: string | null;
  confidence?: "high" | "medium" | "low" | string;
  attack_story: string[];
  created_at: string;
  updated_at: string;
}

export interface IncidentTimelineItem {
  id: string;
  incident_id: string;
  event_type: string;
  actor?: string | null;
  title: string;
  details?: string | null;
  created_at: string;
}

export interface IncidentTimelineResponse {
  incident_id: string;
  items: IncidentTimelineItem[];
}

export interface IncidentListResponse {
  total: number;
  items: IncidentItem[];
}

export interface IncidentQueueItem extends InvestigationQueueItem {
  incident_id: string;
  campaign_family: string;
  priority: number;
  confidence: string;
  attack_story: string[];
  recommended_actions: string[];
  affected_hosts: string[];
  total_events: number;
  spread_depth: number;
  source_type: string;
  source_key?: string | null;
  analyst_note?: string | null;
  playbook?: string | null;
}

export interface InvestigationGraphNode {
  id: string;
  label?: string;
  type: string;
  risk?: number;
  meta?: string;
  tactic?: string | null;
  technique_id?: string | null;
  technique_name?: string | null;
  role?: string | null;
  score?: number;
  highlighted?: boolean;
}

export interface InvestigationGraphEdge {
  from: string;
  to: string;
  label?: string;
  weight?: number;
  highlighted?: boolean;
}

export interface IncidentGraphResponse extends InvestigationGraphData {
  incident_id: string;
  title: string;
  meta?: {
    summary?: string;
    related_alerts?: number;
    severity?: string;
    status?: string;
    entry_nodes?: string[];
    pivot_nodes?: string[];
    impact_nodes?: string[];
    primary_attack_path?: string[];
    kill_chain_phases?: string[];
    campaign_confidence?: string;
    related_investigation_ids?: string[];
  };
}

export interface IncidentAttackChainStep {
  step: number;
  stage: string;
  node_id: string;
  label: string;
  node_type: string;
  evidence?: string | null;
  risk: number;
  technique_id?: string | null;
  technique_name?: string | null;
  tactic?: string | null;
}

export interface IncidentAttackChainResponse {
  incident_id: string;
  title: string;
  confidence: string;
  primary_user?: string | null;
  primary_process?: string | null;
  primary_rule?: string | null;
  affected_hosts: string[];
  kill_chain_phases: string[];
  steps: IncidentAttackChainStep[];
}

function summarizeIncident(item: IncidentItem): string {
  const story = item.attack_story?.slice(0, 2).join(" · ");
  if (story) return story;
  return `${item.campaign_family} · ${item.total_events} events · spread depth ${item.spread_depth}`;
}

function incidentTags(item: IncidentItem): string[] {
  const tags = [
    item.campaign_family,
    item.confidence || "medium",
    item.playbook || "",
    ...item.affected_hosts.slice(0, 3),
  ].filter(Boolean);
  return Array.from(new Set(tags));
}

export function mapIncidentToQueueItem(item: IncidentItem): IncidentQueueItem {
  return {
    incident_id: item.id,
    id: item.id,
    alert_id: item.id,
    title: item.title,
    status: item.status,
    severity: item.severity,
    owner: item.owner || "Unassigned",
    created_at: item.created_at,
    updated_at: item.updated_at,
    related_alerts: item.total_events,
    affected_host: item.affected_hosts?.[0] || "—",
    summary: summarizeIncident(item),
    tags: incidentTags(item),
    campaign_family: item.campaign_family,
    priority: item.priority,
    confidence: item.confidence || "medium",
    attack_story: item.attack_story || [],
    recommended_actions: item.recommended_actions || [],
    affected_hosts: item.affected_hosts || [],
    total_events: item.total_events,
    spread_depth: item.spread_depth,
    source_type: item.source_type,
    source_key: item.source_key,
    analyst_note: item.analyst_note || null,
    playbook: item.playbook || null,
  };
}

export async function getIncidents(token?: string, limit = 100) {
  const data = await apiGet<IncidentListResponse>(`/api/incidents?limit=${limit}`, token);
  return data.items.map(mapIncidentToQueueItem);
}

export async function getIncidentDetail(incidentId: string, token?: string) {
  return apiGet<IncidentItem>(`/api/incidents/${incidentId}`, token);
}

export async function getIncidentGraph(incidentId: string, token?: string) {
  return apiGet<IncidentGraphResponse>(`/api/incidents/${incidentId}/graph`, token);
}

export async function getIncidentAttackChain(incidentId: string, token?: string) {
  return apiGet<IncidentAttackChainResponse>(
    `/api/incidents/${incidentId}/attack-chain`,
    token,
  );
}

export async function getIncidentTimeline(incidentId: string, token?: string) {
  return apiGet<IncidentTimelineResponse>(
    `/api/incidents/${incidentId}/timeline`,
    token,
  );
}

export async function assignIncident(
  incidentId: string,
  owner: string,
  token?: string,
) {
  return apiPatch<IncidentItem>(
    `/api/incidents/${incidentId}/assign`,
    { owner },
    token,
  );
}

export async function updateIncidentNote(
  incidentId: string,
  note: string,
  token?: string,
) {
  return apiPatch<IncidentItem>(
    `/api/incidents/${incidentId}/note`,
    { note },
    token,
  );
}

export async function updateIncidentStatus(
  incidentId: string,
  status: InvestigationStatus,
  token?: string,
) {
  return apiPatch<IncidentItem>(
    `/api/incidents/${incidentId}/status`,
    { status },
    token,
  );
}

export async function getInvestigations(token?: string) {
  return getIncidents(token);
}

export async function getInvestigationGraph(alertId: string, token?: string) {
  return getIncidentGraph(alertId, token);
}
