import { apiPost } from "@/lib/api/client";

export interface HostActionResponse {
  status: string;
  action: string;
  command_id: string;
  message?: string;
}

export interface HostActionPayload {
  hostname: string;
  rule?: string;
  pid?: number;
}

export async function isolateHost(payload: HostActionPayload, token?: string) {
  return apiPost<HostActionResponse>("/api/actions/isolate", payload, token);
}

export async function unisolateHost(payload: HostActionPayload, token?: string) {
  return apiPost<HostActionResponse>("/api/actions/unisolate", payload, token);
}

export async function disableUsb(payload: HostActionPayload, token?: string) {
  return apiPost<HostActionResponse>("/api/actions/usb_disable", payload, token);
}

export async function enableUsb(payload: HostActionPayload, token?: string) {
  return apiPost<HostActionResponse>("/api/actions/usb_enable", payload, token);
}

export async function killProcess(payload: Required<Pick<HostActionPayload, "hostname" | "pid">> & { rule?: string }, token?: string) {
  return apiPost<HostActionResponse>("/api/actions/kill", payload, token);
}