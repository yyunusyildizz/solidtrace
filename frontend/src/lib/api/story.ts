import { apiPost } from "@/lib/api/client";

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

export interface StoryPreviewRequest {
  source_type: string;
  items: Record<string, unknown>[];
}

// ---------------------------------------------------------------------------
// Response — AttackStory sub-models
// ---------------------------------------------------------------------------

export interface RecommendedActionItem {
  action_type: string;
  title: string;
  description: string;
  priority: string;
  target?: string | null;
}

export interface AttackStoryItem {
  id: string;
  tenant_id?: string | null;
  correlation_group_id: string;
  title: string;
  executive_summary: string;
  technical_summary: string;
  severity: string;
  confidence: string;
  risk_score: number;
  affected_hosts: string[];
  affected_users: string[];
  source_ips: string[];
  destination_ips: string[];
  tactics: string[];
  techniques: string[];
  timeline: Record<string, unknown>[];
  key_findings: string[];
  recommended_actions: RecommendedActionItem[];
  analyst_questions: string[];
  created_at: string;
  attributes: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Response — Summary
// ---------------------------------------------------------------------------

export interface StoryPreviewSummary {
  total_events: number;
  total_groups: number;
  total_stories: number;
  max_risk_score: number;
  highest_severity: string;
  affected_hosts: string[];
  affected_users: string[];
  tactics: string[];
  techniques: string[];
}

// ---------------------------------------------------------------------------
// Response — Top-level
// ---------------------------------------------------------------------------

export interface StoryPreviewResponse {
  normalized_events: Record<string, unknown>[];
  correlation_groups: Record<string, unknown>[];
  attack_stories: AttackStoryItem[];
  summary: StoryPreviewSummary;
  warnings: string[];
  attributes: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// API call
// ---------------------------------------------------------------------------

export async function previewStory(
  request: StoryPreviewRequest,
  token?: string,
): Promise<StoryPreviewResponse> {
  return apiPost<StoryPreviewResponse>("/api/story/preview", request, token);
}

// ---------------------------------------------------------------------------
// Graph Preview — Node & Edge
// ---------------------------------------------------------------------------

export interface StoryGraphNode {
  id: string;
  node_type: string;
  label: string;
  severity: string;
  risk_score: number;
  attributes: Record<string, unknown>;
}

export interface StoryGraphEdge {
  id: string;
  source: string;
  target: string;
  edge_type: string;
  label: string;
  attributes: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Graph Preview — Single Graph
// ---------------------------------------------------------------------------

export interface StoryGraphItem {
  id: string;
  story_id: string;
  tenant_id?: string | null;
  title: string;
  severity: string;
  risk_score: number;
  nodes: StoryGraphNode[];
  edges: StoryGraphEdge[];
  summary: {
    node_count: number;
    edge_count: number;
    host_count: number;
    user_count: number;
    action_count: number;
  };
  created_at: string;
  attributes: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Graph Preview — Summary
// ---------------------------------------------------------------------------

export interface StoryGraphPreviewSummary {
  total_events: number;
  total_groups: number;
  total_stories: number;
  graph_count: number;
  total_nodes: number;
  total_edges: number;
  max_risk_score: number;
  highest_severity: string;
  affected_hosts: string[];
  affected_users: string[];
  tactics: string[];
  techniques: string[];
}

// ---------------------------------------------------------------------------
// Graph Preview — Response
// ---------------------------------------------------------------------------

export interface StoryGraphPreviewResponse {
  normalized_events: Record<string, unknown>[];
  correlation_groups: Record<string, unknown>[];
  attack_stories: AttackStoryItem[];
  story_graphs: StoryGraphItem[];
  summary: StoryGraphPreviewSummary;
  warnings: string[];
}

// ---------------------------------------------------------------------------
// Graph Preview — API call
// ---------------------------------------------------------------------------

export async function previewStoryGraph(
  request: StoryPreviewRequest,
  token?: string,
): Promise<StoryGraphPreviewResponse> {
  return apiPost<StoryGraphPreviewResponse>("/api/story/graph-preview", request, token);
}
