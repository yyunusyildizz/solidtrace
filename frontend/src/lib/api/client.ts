import { getToken, clearAuthSession } from "@/lib/auth";

export const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL || "http://127.0.0.1:8000";

function buildHeaders(token?: string, isForm = false): HeadersInit {
  const authToken = token ?? getToken() ?? undefined;

  const headers: HeadersInit = {};

  if (!isForm) {
    headers["Content-Type"] = "application/json";
  } else {
    headers["Content-Type"] = "application/x-www-form-urlencoded";
  }

  if (authToken) {
    headers.Authorization = `Bearer ${authToken}`;
  }

  return headers;
}

async function readResponseBody(response: Response) {
  const contentType = response.headers.get("content-type") || "";

  if (response.status === 204) {
    return null;
  }

  if (contentType.includes("application/json")) {
    try {
      return await response.json();
    } catch {
      return null;
    }
  }

  try {
    const text = await response.text();
    return text || null;
  } catch {
    return null;
  }
}

async function handleResponse<T>(response: Response): Promise<T> {
  if (response.status === 401) {
    clearAuthSession();
    throw new Error("Not authenticated");
  }

  const body = await readResponseBody(response);

  if (!response.ok) {
    if (body && typeof body === "object" && "detail" in body) {
      throw new Error(String((body as { detail?: unknown }).detail || "Request failed"));
    }

    if (typeof body === "string" && body.trim()) {
      throw new Error(body);
    }

    throw new Error(`Request failed with ${response.status}`);
  }

  return body as T;
}

async function request<T>(
  path: string,
  init: RequestInit = {},
  token?: string,
  isForm = false,
): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      ...buildHeaders(token, isForm),
      ...(init.headers || {}),
    },
    cache: "no-store",
  });

  return handleResponse<T>(response);
}

export async function apiGet<T>(path: string, token?: string): Promise<T> {
  return request<T>(path, { method: "GET" }, token);
}

export async function apiPost<T>(path: string, body?: unknown, token?: string): Promise<T> {
  return request<T>(
    path,
    {
      method: "POST",
      body: body ? JSON.stringify(body) : undefined,
    },
    token,
  );
}

export async function apiPut<T>(path: string, body?: unknown, token?: string): Promise<T> {
  return request<T>(
    path,
    {
      method: "PUT",
      body: body ? JSON.stringify(body) : undefined,
    },
    token,
  );
}

export async function apiPatch<T>(path: string, body?: unknown, token?: string): Promise<T> {
  return request<T>(
    path,
    {
      method: "PATCH",
      body: body ? JSON.stringify(body) : undefined,
    },
    token,
  );
}

export async function apiDelete<T>(path: string, token?: string): Promise<T> {
  return request<T>(
    path,
    {
      method: "DELETE",
    },
    token,
  );
}

export async function apiFormPost<T>(
  path: string,
  form: URLSearchParams,
  token?: string,
): Promise<T> {
  return request<T>(
    path,
    {
      method: "POST",
      body: form.toString(),
    },
    token,
    true,
  );
}
