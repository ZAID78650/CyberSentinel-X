import axios, { AxiosError, type InternalAxiosRequestConfig } from "axios";
import { API_BASE } from "../config";
import type { AuthResponse, SessionItem, Tokens, User } from "../types";

const TOKEN_KEY = "csx_access";
const REFRESH_KEY = "csx_refresh";
const USER_KEY = "csx_user";

export const tokenStore = {
  getAccess: () => localStorage.getItem(TOKEN_KEY),
  getRefresh: () => localStorage.getItem(REFRESH_KEY),
  set(tokens: Tokens) {
    localStorage.setItem(TOKEN_KEY, tokens.access_token);
    localStorage.setItem(REFRESH_KEY, tokens.refresh_token);
  },
  clear() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(REFRESH_KEY);
    localStorage.removeItem(USER_KEY);
  },
  getUser: (): User | null => {
    const raw = localStorage.getItem(USER_KEY);
    return raw ? (JSON.parse(raw) as User) : null;
  },
  setUser(user: User) {
    localStorage.setItem(USER_KEY, JSON.stringify(user));
  },
};

export const api = axios.create({
  baseURL: API_BASE,
  // Generous timeout: on the Render free tier the backend cold-starts after
  // ~15 min of inactivity and the first request can be held for 30-60s while
  // the instance boots.
  timeout: 60000,
});

api.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const token = tokenStore.getAccess();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

let refreshing: Promise<string | null> | null = null;

const MAX_GATEWAY_RETRIES = 4;
const GATEWAY_STATUSES = [502, 503, 504];

function isTransientGatewayError(error: AxiosError): boolean {
  // Render's edge returns 502/503/504 while a free-tier instance is still
  // cold-starting; a missing response means the connection dropped mid-boot.
  if (error.response && GATEWAY_STATUSES.includes(error.response.status)) return true;
  return !error.response;
}

api.interceptors.response.use(
  (res) => res,
  async (error: AxiosError) => {
    const original = error.config as (InternalAxiosRequestConfig & { _retry?: boolean; _retryCount?: number }) | undefined;
    // Retry transient gateway/network failures with backoff so the app recovers
    // by itself when the backend is waking up (free-tier cold start). This is
    // safe for non-GET requests too: a 502/503/504 (or a dropped connection)
    // means the proxy never reached a healthy app, so the request was never
    // processed and has no side effects to duplicate.
    const method = (original?.method ?? "").toUpperCase();
    const retryableMethod = method === "GET" || method === "POST" || method === "PUT" || method === "PATCH";
    if (original && retryableMethod && isTransientGatewayError(error) && (original._retryCount ?? 0) < MAX_GATEWAY_RETRIES) {
      original._retryCount = (original._retryCount ?? 0) + 1;
      const delay = Math.min(1000 * 2 ** original._retryCount, 8000); // 2s, 4s, 8s, 8s
      await new Promise((resolve) => setTimeout(resolve, delay));
      return api(original);
    }
    if (error.response?.status === 401 && original && !original._retry && !original.url?.includes("/auth/login")) {
      original._retry = true;
      refreshing = refreshing ?? refreshAccessToken().finally(() => {
        refreshing = null;
      });
      const token = await refreshing;
      if (token) {
        original.headers.Authorization = `Bearer ${token}`;
        return api(original);
      }
      tokenStore.clear();
      window.dispatchEvent(new CustomEvent("auth:expired"));
    }
    return Promise.reject(error);
  },
);

async function refreshAccessToken(): Promise<string | null> {
  const refresh = tokenStore.getRefresh();
  if (!refresh) return null;
  try {
    const res = await axios.post<Tokens>(`${API_BASE}/auth/refresh`, { refresh_token: refresh });
    tokenStore.set(res.data);
    return res.data.access_token;
  } catch {
    return null;
  }
}

export async function login(email: string, password: string, rememberMe: boolean): Promise<AuthResponse> {
  const res = await api.post<AuthResponse>("/auth/login", { email, password, remember_me: rememberMe });
  tokenStore.set(res.data.tokens);
  tokenStore.setUser(res.data.user);
  return res.data;
}

export async function register(payload: {
  full_name: string;
  email: string;
  organization?: string;
  password: string;
  confirm_password: string;
  accept_terms: boolean;
}): Promise<AuthResponse> {
  const res = await api.post<AuthResponse>("/auth/register", payload);
  tokenStore.set(res.data.tokens);
  tokenStore.setUser(res.data.user);
  return res.data;
}

export function logout(): void {
  tokenStore.clear();
  window.dispatchEvent(new CustomEvent("auth:logout"));
}

export async function oauthProviders(): Promise<Array<{ provider: string; name: string; configured: boolean }>> {
  const res = await api.get("/auth/oauth/providers");
  return res.data.providers;
}

export async function oauthAuthorize(provider: string): Promise<{ configured: boolean; authorize_url?: string; message?: string }> {
  const res = await api.get(`/auth/oauth/${provider}/authorize`);
  return res.data;
}

export async function oauthLink(provider: string): Promise<{ configured: boolean; authorize_url?: string; message?: string }> {
  const res = await api.get(`/auth/oauth/${provider}/link`);
  return res.data;
}

export async function oauthUnlink(provider: string): Promise<User> {
  const res = await api.post<User>(`/auth/oauth/${provider}/unlink`);
  return res.data;
}

export async function setPassword(payload: {
  current_password?: string;
  new_password: string;
  confirm_password: string;
}): Promise<User> {
  const res = await api.post<User>("/auth/me/password", payload);
  return res.data;
}

export async function listUsers(): Promise<User[]> {
  const res = await api.get<User[]>("/auth/users");
  return res.data;
}

export async function setUserStatus(userId: string, isActive: boolean): Promise<User> {
  const res = await api.post<User>(`/auth/users/${userId}/status`, { is_active: isActive });
  return res.data;
}

export async function adminResetPassword(userId: string, newPassword: string): Promise<User> {
  const res = await api.post<User>(`/auth/users/${userId}/password`, { new_password: newPassword });
  return res.data;
}

export async function updateUserRoles(userId: string, roles: string[]): Promise<User> {
  const res = await api.put<User>(`/auth/users/${userId}/roles`, { roles });
  return res.data;
}

export async function deprovisionUser(userId: string): Promise<User> {
  const res = await api.post<User>(`/auth/users/${userId}/deprovision`);
  return res.data;
}

export async function restoreUser(userId: string): Promise<User> {
  const res = await api.post<User>(`/auth/users/${userId}/restore`);
  return res.data;
}

export async function setUserSsoBlock(userId: string, blocked: boolean): Promise<User> {
  const res = await api.post<User>(`/auth/users/${userId}/sso-block`, { blocked });
  return res.data;
}

export async function mySessions(): Promise<SessionItem[]> {
  const res = await api.get<SessionItem[]>("/auth/sessions");
  return res.data;
}

export async function revokeMySession(deviceId: string): Promise<SessionItem> {
  const res = await api.post<SessionItem>(`/auth/sessions/${deviceId}/revoke`);
  return res.data;
}

export async function userSessions(userId: string): Promise<SessionItem[]> {
  const res = await api.get<SessionItem[]>(`/auth/users/${userId}/sessions`);
  return res.data;
}

export async function adminRevokeSession(userId: string, deviceId: string): Promise<SessionItem> {
  const res = await api.post<SessionItem>(`/auth/users/${userId}/sessions/${deviceId}/revoke`);
  return res.data;
}

async function downloadBlob(url: string, fallbackName: string): Promise<void> {
  const res = await api.get(url, { responseType: "blob" });
  const disposition = String(res.headers["content-disposition"] ?? "");
  const match = disposition.match(/filename="?([^";]+)"?/);
  const filename = match?.[1] ?? fallbackName;
  const blobUrl = URL.createObjectURL(res.data as Blob);
  const a = document.createElement("a");
  a.href = blobUrl;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(blobUrl);
}

export async function downloadEvidenceAttachment(evidenceId: string): Promise<void> {
  await downloadBlob(`/evidence/${evidenceId}/attachment`, "attachment.bin");
}

export async function uploadEvidenceAttachment(evidenceId: string, file: File): Promise<unknown> {
  const form = new FormData();
  form.append("file", file);
  const res = await api.post(`/evidence/${evidenceId}/attachment`, form);
  return res.data;
}

export async function exportMyData(format: "json" | "csv" | "zip"): Promise<void> {
  const res = await api.get(`/auth/me/export?fmt=${format}`, { responseType: "blob" });
  const disposition = String(res.headers["content-disposition"] ?? "");
  const match = disposition.match(/filename="?([^";]+)"?/);
  const filename = match?.[1] ?? `cybersentinel-export.${format === "csv" ? "csv" : "json"}`;
  const url = URL.createObjectURL(res.data as Blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export function completeOAuth(access: string, refresh: string): void {
  tokenStore.set({ access_token: access, refresh_token: refresh, token_type: "bearer", expires_in: 7 * 24 * 60 * 60 });
  window.dispatchEvent(new CustomEvent("auth:oauth"));
}

export function getErrorMessage(err: unknown): string {
  if (axios.isAxiosError(err)) {
    const detail = err.response?.data as { detail?: unknown } | undefined;
    if (typeof detail?.detail === "string") return detail.detail;
    if (Array.isArray(detail?.detail)) {
      return (detail.detail as Array<{ msg?: string }>)
        .map((d) => d.msg ?? "Invalid input")
        .join("; ");
    }
    return err.message;
  }
  return err instanceof Error ? err.message : "Unexpected error";
}
