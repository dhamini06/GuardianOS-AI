/**
 * Typed client for the GuardianOS-AI HTTP API.
 *
 * Auth: optional `X-GUARDIAN-TOKEN` header read from localStorage
 * (`guardian_token`, same key as the legacy dashboard used). When auth is
 * disabled on the backend the header is simply ignored.
 */

const TOKEN_KEY = "guardian_token";

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string): void {
  if (token) {
    localStorage.setItem(TOKEN_KEY, token);
  } else {
    localStorage.removeItem(TOKEN_KEY);
  }
}

export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {};
  const token = getToken();
  if (token) {
    headers["X-GUARDIAN-TOKEN"] = token;
  }
  const hasBody = init.body != null;
  if (hasBody) {
    headers["Content-Type"] = "application/json";
  }

  let response: Response;
  try {
    response = await fetch(path, { ...init, headers: { ...headers, ...init.headers } });
  } catch {
    throw new ApiError(0, `Cannot reach the GuardianOS-AI server at ${window.location.origin}`);
  }

  if (!response.ok) {
    let detail = `HTTP ${response.status}`;
    try {
      const body = (await response.json()) as { detail?: unknown };
      if (typeof body.detail === "string") {
        detail = body.detail;
      }
    } catch {
      // non-JSON error body
    }
    throw new ApiError(response.status, detail);
  }
  return (await response.json()) as T;
}

const json = (method: string) => <T>(path: string, body?: unknown): Promise<T> =>
  request<T>(path, {
    method,
    body: body === undefined ? undefined : JSON.stringify(body),
  });

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: json("POST"),
};
