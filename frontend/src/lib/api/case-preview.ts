import { apiPost } from "@/lib/api/client";

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

export interface CasePreviewRequest {
  source_type: string;
  items: Record<string, unknown>[];
  include_graph?: boolean;
  consolidate?: boolean;
}

// ---------------------------------------------------------------------------
// CaseDraft sub-models
// ---------------------------------------------------------------------------

export interface CaseEvidenceItem {
  evidence_type: string;
  source_id: string;
  description: string;
  data: Record<string, unknown>;
}

export interface CaseTimelineItem {
  order: number;
  timestamp: string;
  event_id: string;
  description: string;
  source_story_id: string;
}

export interface CaseRecommendedAction {
  action_type: string;
  title: string;
  description: string;
  priority: string;
  target?: string | null;
}

// ---------------------------------------------------------------------------
// CaseDraft
// ---------------------------------------------------------------------------

export interface CaseDraftItem {
  id: string;
  tenant_id?: string | null;
  title: string;
  severity: string;
  risk_score: number;
  status: string;
  priority: string;
  confidence: string;
  summary: string;
  affected_hosts: string[];
  affected_users: string[];
  tactics: string[];
  techniques: string[];
  related_alert_ids: string[];
  related_story_ids: string[];
  graph_ids: string[];
  evidence_items: CaseEvidenceItem[];
  timeline_items: CaseTimelineItem[];
  recommended_actions: CaseRecommendedAction[];
  analyst_questions: string[];
  tags: string[];
  attributes: Record<string, unknown>;
  created_at: string;
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

export interface CasePreviewSummary {
  total_items: number;
  total_stories: number;
  total_graphs: number;
  total_case_drafts: number;
  highest_severity: string;
  max_risk_score: number;
  affected_hosts: string[];
  affected_users: string[];
}

// ---------------------------------------------------------------------------
// Response
// ---------------------------------------------------------------------------

export interface CasePreviewResponse {
  case_drafts: CaseDraftItem[];
  attack_stories: Record<string, unknown>[];
  story_graphs: Record<string, unknown>[];
  summary: CasePreviewSummary;
  warnings: string[];
}

// ---------------------------------------------------------------------------
// API call — Preview
// ---------------------------------------------------------------------------

export async function previewCaseDraft(
  request: CasePreviewRequest,
  token?: string,
): Promise<CasePreviewResponse> {
  return apiPost<CasePreviewResponse>("/api/cases/preview", request, token);
}

// ---------------------------------------------------------------------------
// POST /api/cases/from-preview — Create Case from Preview
// ---------------------------------------------------------------------------

export interface CreatedCaseItem {
  id: string;
  tenant_id?: string | null;
  title: string;
  description?: string | null;
  status: string;
  severity: string;
  owner?: string | null;
  created_at: string;
  updated_at: string;
  related_alert_count?: number;
}

export interface CaseFromPreviewSummary {
  total_items: number;
  total_case_drafts: number;
  total_created_cases: number;
  total_linked_alerts: number;
  highest_severity: string;
  max_risk_score: number;
}

export interface CaseFromPreviewResponse {
  created_cases: CreatedCaseItem[];
  case_drafts: CaseDraftItem[];
  linked_alert_count: number;
  summary: CaseFromPreviewSummary;
  warnings: string[];
}

export async function createCaseFromPreview(
  request: CasePreviewRequest,
  token?: string,
): Promise<CaseFromPreviewResponse> {
  return apiPost<CaseFromPreviewResponse>("/api/cases/from-preview", request, token);
}
