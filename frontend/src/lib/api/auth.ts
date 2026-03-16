import { apiFormPost } from "@/lib/api/client";

export interface LoginResponse {
  access_token: string;
  refresh_token?: string;
  token_type: string;
  two_factor_required?: boolean;
  pending_token?: string;
}

export async function login(username: string, password: string) {
  const form = new URLSearchParams();
  form.set("username", username);
  form.set("password", password);

  return apiFormPost<LoginResponse>("/api/login", form);
}