import { apiGet } from "@/lib/api/client";

export interface CommandExecutionItem {
  id: string;
  command_id: string;
  action: string;
  target_hostname: string;
  requested_by?: string | null;
  tenant_id?: string | null;
  status?: "queued" | "received" | "completed" | "failed" | "expired" | string | null;
  success?: boolean | null;
  message?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
  acknowledged_at?: string | null;
  finished_at?: string | null;
  agent_hostname?: string | null;
  result_payload?: string | null;
}

export async function getCommandExecutions(limit = 20, hostname?: string, token?: string) {
  const query = new URLSearchParams();
  query.set("limit", String(limit));
  if (hostname) query.set("hostname", hostname);

  return apiGet<CommandExecutionItem[]>(`/api/commands?${query.toString()}`, token);
}