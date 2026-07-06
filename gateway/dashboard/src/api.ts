// Thin client for the MCP Gateway REST surface. Handles the real two-factor login
// (username + password + TOTP), token/binding storage, and authenticated fetches.
// The gateway binds the session token to a per-session secret returned as
// `thumbprint`, which the client must replay in X-Client-Cert-Thumbprint.

export type User = {
  sub: string; name: string; role: string; clearance: string;
  amr?: string[]; password_change_required?: boolean;
};

const TOKEN_KEY = "mcp_token";
const THUMB_KEY = "mcp_thumb";
const USER_KEY = "mcp_user";

export function getToken(): string | null { return sessionStorage.getItem(TOKEN_KEY); }
export function getThumb(): string | null { return sessionStorage.getItem(THUMB_KEY); }
export function getUser(): User | null {
  const raw = sessionStorage.getItem(USER_KEY);
  return raw ? JSON.parse(raw) : null;
}

function store(token: string, thumb: string, user: User) {
  sessionStorage.setItem(TOKEN_KEY, token);
  sessionStorage.setItem(THUMB_KEY, thumb);
  sessionStorage.setItem(USER_KEY, JSON.stringify(user));
}

export function clearSession() {
  sessionStorage.removeItem(TOKEN_KEY);
  sessionStorage.removeItem(THUMB_KEY);
  sessionStorage.removeItem(USER_KEY);
}

function authHeaders(): Record<string, string> {
  const h: Record<string, string> = {};
  const t = getToken(), th = getThumb();
  if (t) h["Authorization"] = "Bearer " + t;
  if (th) h["X-Client-Cert-Thumbprint"] = th;
  return h;
}

export type AuthInfo = {
  org?: string; mode?: string; password_login?: boolean;
  mfa_required?: boolean; dev_login?: boolean; dev_quick_login?: boolean; assurance?: string;
};

export async function authInfo(): Promise<AuthInfo> {
  try {
    const r = await fetch("/api/auth/info");
    return r.ok ? await r.json() : {};
  } catch { return {}; }
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) { super(message); this.status = status; }
}

// DEV ONLY: skip password + MFA and open as admin (gated server-side by
// auth.dev_quick_login; 404s in production).
export async function quickLogin(): Promise<User> {
  const r = await fetch("/api/dev/quicklogin", { method: "POST" });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new ApiError(r.status, data.detail || "Quick login unavailable");
  store(data.token, data.thumbprint, data.user);
  return data.user as User;
}

// Layer 1: username + password. A wrong password throws here (never advances to
// MFA). Returns either a completed User (when MFA is off) or an mfa_ticket to
// carry into layer 2.
export type LoginResult =
  | { user: User }
  | { mfaTicket: string; username: string };

export async function login(username: string, password: string): Promise<LoginResult> {
  const r = await fetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new ApiError(r.status, data.detail || "Sign in failed");
  if (data.mfa_required) return { mfaTicket: data.mfa_ticket, username: data.username };
  store(data.token, data.thumbprint, data.user);
  return { user: data.user as User };
}

// Layer 2: TOTP code + the ticket from layer 1. Completes the session.
export async function verifyMfa(mfaTicket: string, otp: string): Promise<User> {
  const r = await fetch("/api/auth/mfa", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ mfa_ticket: mfaTicket, otp }),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new ApiError(r.status, data.detail || "Verification failed");
  store(data.token, data.thumbprint, data.user);
  return data.user as User;
}

export async function logout() {
  try {
    await fetch("/mcp", { method: "DELETE", headers: authHeaders() });
  } catch { /* best effort */ }
  clearSession();
}

// GET a JSON endpoint with auth. Returns null on 401/403 (caller renders a
// placeholder) so a non-admin session degrades gracefully instead of throwing.
export async function apiGet<T = any>(path: string): Promise<T | null> {
  try {
    const r = await fetch(path, { headers: authHeaders() });
    if (r.status === 401) { clearSession(); throw new ApiError(401, "session expired"); }
    if (!r.ok) return null;
    return (await r.json()) as T;
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) throw e;
    return null;
  }
}

// POST a JSON action with auth. Throws ApiError on failure (caller shows a toast).
export async function apiPost<T = any>(path: string, body?: any): Promise<T> {
  const r = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeaders() },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await r.json().catch(() => ({}));
  if (r.status === 401) { clearSession(); throw new ApiError(401, "session expired"); }
  if (!r.ok) throw new ApiError(r.status, (data && (data.detail || data.error)) || `HTTP ${r.status}`);
  return data as T;
}

export async function changePassword(oldPassword: string, newPassword: string) {
  const r = await fetch("/api/auth/password", {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeaders() },
    body: JSON.stringify({ old_password: oldPassword, new_password: newPassword }),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new ApiError(r.status, data.detail || "Change failed");
  return data;
}
