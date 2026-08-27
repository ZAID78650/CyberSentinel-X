import { getDemoData, getDemoPostData } from "./demoData";
import axios, { AxiosError, type InternalAxiosRequestConfig } from "axios";
import { API_BASE } from "../config";
import type { AuthResponse, SessionItem, Tokens, User } from "../types";

const TOKEN_KEY = "csx_access";
const REFRESH_KEY = "csx_refresh";
const USER_KEY = "csx_user";
const DEMO_MODE_KEY = "csx_demo_mode";

/* ── Demo Mode Detection ────────────────────────────────────────────── */
let _demoMode: boolean | null = null;
let _backendDown = false;  // Set true after first network failure — skips all retries

export function isDemoMode(): boolean {
  if (_demoMode !== null) return _demoMode;
  const stored = localStorage.getItem(DEMO_MODE_KEY);
  _demoMode = stored === "true";
  return _demoMode;
}

export function setDemoMode(enabled: boolean): void {
  _demoMode = enabled;
  localStorage.setItem(DEMO_MODE_KEY, String(enabled));
}

/* ── Demo Users ─────────────────────────────────────────────────────── */
interface DemoUser {
  id: string; email: string; full_name: string; organization: string;
  is_active: boolean; is_verified: boolean; roles: string[];
  oauth_provider: string | null; has_password: boolean; created_at: string;
}

const DEMO_USERS: Record<string, { user: DemoUser; password: string }> = {
  "admin@cybersentinel.io": {
    user: { id: "demo-admin-001", email: "admin@cybersentinel.io", full_name: "Admin User", organization: "CyberSentinel-X", is_active: true, is_verified: true, roles: ["ADMIN", "SECURITY_ANALYST"], oauth_provider: null, has_password: true, created_at: new Date().toISOString() },
    password: "Admin@2026",
  },
  "analyst@cybersentinel.io": {
    user: { id: "demo-analyst-001", email: "analyst@cybersentinel.io", full_name: "Security Analyst", organization: "CyberSentinel-X", is_active: true, is_verified: true, roles: ["SECURITY_ANALYST"], oauth_provider: null, has_password: true, created_at: new Date().toISOString() },
    password: "Analyst@2026",
  },
  "viewer@cybersentinel.io": {
    user: { id: "demo-viewer-001", email: "viewer@cybersentinel.io", full_name: "Viewer User", organization: "CyberSentinel-X", is_active: true, is_verified: true, roles: ["VIEWER"], oauth_provider: null, has_password: true, created_at: new Date().toISOString() },
    password: "Viewer@2026",
  },
};

function generateDemoToken(): string {
  return "demo-token-" + Date.now().toString(36) + "-" + Math.random().toString(36).slice(2, 10);
}

function createDemoTokens(): Tokens {
  return { access_token: generateDemoToken(), refresh_token: generateDemoToken(), token_type: "bearer", expires_in: 7 * 24 * 60 * 60 };
}

/* ── Token Store ────────────────────────────────────────────────────── */
export const tokenStore = {
  getAccess: () => localStorage.getItem(TOKEN_KEY),
  getRefresh: () => localStorage.getItem(REFRESH_KEY),
  set(tokens: Tokens) { localStorage.setItem(TOKEN_KEY, tokens.access_token); localStorage.setItem(REFRESH_KEY, tokens.refresh_token); },
  clear() { localStorage.removeItem(TOKEN_KEY); localStorage.removeItem(REFRESH_KEY); localStorage.removeItem(USER_KEY); },
  getUser: (): User | null => { const raw = localStorage.getItem(USER_KEY); return raw ? (JSON.parse(raw) as User) : null; },
  setUser(user: User) { localStorage.setItem(USER_KEY, JSON.stringify(user)); },
};

/* ── Axios Instance ─────────────────────────────────────────────────── */
export const api = axios.create({ baseURL: API_BASE, timeout: 60000 });

api.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const token = tokenStore.getAccess();
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

let refreshing: Promise<string | null> | null = null;
const MAX_GATEWAY_RETRIES = 4;
const GATEWAY_STATUSES = [502, 503, 504];

function isTransientGatewayError(error: AxiosError): boolean {
  if (error.response && GATEWAY_STATUSES.includes(error.response.status)) return true;
  return !error.response;
}

api.interceptors.response.use(
  (res) => res,
  async (error: AxiosError) => {
    const original = error.config as (InternalAxiosRequestConfig & { _retry?: boolean; _retryCount?: number }) | undefined;

    // ── Demo mode: return mock data immediately, skip all retries ──
    if (isDemoMode() && original?.url) {
      const isPost = (original.method ?? "").toUpperCase() === "POST";
      const demoData = isPost ? getDemoPostData(original.url, original.data) : getDemoData(original.url);
      if (demoData !== null) {
        return { data: demoData, status: 200, statusText: "OK (demo)", headers: {}, config: original } as any;
      }
    }
    // ── Backend down: return demo data for any failed request, skip retries ──
    if (_backendDown && original?.url) {
      const isPost = (original.method ?? "").toUpperCase() === "POST";
      const demoData = isPost ? getDemoPostData(original.url, original.data) : getDemoData(original.url);
      if (demoData !== null) {
        return { data: demoData, status: 200, statusText: "OK (demo)", headers: {}, config: original } as any;
      }
    }
    // Mark backend as down on first network/proxy error (no retries needed)
    if (!error.response || [502, 503, 504].includes(error.response?.status ?? 0)) {
      _backendDown = true;
    }

    const method = (original?.method ?? "").toUpperCase();
    const retryableMethod = method === "GET" || method === "POST" || method === "PUT" || method === "PATCH";
    if (original && retryableMethod && isTransientGatewayError(error) && !_backendDown && (original._retryCount ?? 0) < MAX_GATEWAY_RETRIES) {
      original._retryCount = (original._retryCount ?? 0) + 1;
      const delay = Math.min(1000 * 2 ** original._retryCount, 8000);
      await new Promise((resolve) => setTimeout(resolve, delay));
      return api(original);
    }
    if (error.response?.status === 401 && original && !original._retry && !original.url?.includes("/auth/login")) {
      original._retry = true;
      refreshing = refreshing ?? refreshAccessToken().finally(() => { refreshing = null; });
      const token = await refreshing;
      if (token) { original.headers.Authorization = `Bearer ${token}`; return api(original); }
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
  } catch { return null; }
}

/* ── Auth Functions (with Demo Mode) ────────────────────────────────── */
export async function login(email: string, password: string, rememberMe: boolean): Promise<AuthResponse> {
  try {
    const res = await api.post<AuthResponse>("/auth/login", { email, password, remember_me: rememberMe });
    tokenStore.set(res.data.tokens); tokenStore.setUser(res.data.user); setDemoMode(false);
    return res.data;
  } catch (err) {
    const axErr = axios.isAxiosError(err) ? err : null;
    const isBackendDown = !axErr?.response || [404, 502, 503, 504].includes(axErr?.response?.status ?? 0) || axErr?.code === "ECONNABORTED" || axErr?.code === "ERR_NETWORK";
    if (isBackendDown) return demoLogin(email, password);
    throw err;
  }
}

function demoLogin(email: string, password: string): AuthResponse {
  setDemoMode(true);
  const demoUser = DEMO_USERS[email.toLowerCase()];
  if (demoUser) {
    if (demoUser.password !== password) throw new Error("Invalid email or password");
    const tokens = createDemoTokens(); tokenStore.set(tokens); tokenStore.setUser(demoUser.user as User);
    return { user: demoUser.user as User, tokens };
  }
  const user: DemoUser = { id: "demo-" + Date.now().toString(36), email, full_name: email.split("@")[0].replace(/[._]/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()), organization: "Demo Organization", is_active: true, is_verified: true, roles: ["SECURITY_ANALYST"], oauth_provider: null, has_password: true, created_at: new Date().toISOString() };
  const tokens = createDemoTokens(); tokenStore.set(tokens); tokenStore.setUser(user as User);
  return { user: user as User, tokens };
}

export async function register(payload: { full_name: string; email: string; organization?: string; password: string; confirm_password: string; accept_terms: boolean; }): Promise<AuthResponse> {
  try {
    const res = await api.post<AuthResponse>("/auth/register", payload);
    tokenStore.set(res.data.tokens); tokenStore.setUser(res.data.user); setDemoMode(false);
    return res.data;
  } catch (err) {
    const axErr = axios.isAxiosError(err) ? err : null;
    const isBackendDown = !axErr?.response || [404, 502, 503, 504].includes(axErr?.response?.status ?? 0) || axErr?.code === "ECONNABORTED" || axErr?.code === "ERR_NETWORK";
    if (isBackendDown) return demoRegister(payload);
    throw err;
  }
}

function demoRegister(payload: { full_name: string; email: string; organization?: string; password: string; confirm_password: string; accept_terms: boolean; }): AuthResponse {
  if (payload.password !== payload.confirm_password) throw new Error("Passwords do not match");
  if (!payload.accept_terms) throw new Error("You must accept the terms and conditions");
  setDemoMode(true);
  const user: DemoUser = { id: "demo-" + Date.now().toString(36), email: payload.email, full_name: payload.full_name, organization: payload.organization || "Demo Organization", is_active: true, is_verified: true, roles: ["SECURITY_ANALYST"], oauth_provider: null, has_password: true, created_at: new Date().toISOString() };
  DEMO_USERS[payload.email.toLowerCase()] = { user, password: payload.password };
  const tokens = createDemoTokens(); tokenStore.set(tokens); tokenStore.setUser(user as User);
  return { user: user as User, tokens };
}

export function logout(): void { tokenStore.clear(); setDemoMode(false); window.dispatchEvent(new CustomEvent("auth:logout")); }

/* ── OAuth Functions (Demo Mode) ────────────────────────────────────── */
export async function oauthProviders(): Promise<Array<{ provider: string; name: string; configured: boolean }>> {
  try { const res = await api.get("/auth/oauth/providers"); return res.data.providers; }
  catch { return [{ provider: "google", name: "Google", configured: false }, { provider: "github", name: "GitHub", configured: false }]; }
}

export async function oauthAuthorize(provider: string): Promise<{ configured: boolean; authorize_url?: string; message?: string }> {
  try {
    const res = await api.get(`/auth/oauth/${provider}/authorize`);
    const data = res.data;
    // If backend is reachable but SSO is not configured, fall back to demo mode
    if (!data.configured) {
      setDemoMode(true);
      const providerName = provider === "google" ? "Google" : "GitHub";
      const user: DemoUser = { id: "demo-oauth-" + Date.now().toString(36), email: `demo.${provider}@cybersentinel.io`, full_name: `${providerName} Demo User`, organization: "CyberSentinel-X", is_active: true, is_verified: true, roles: ["SECURITY_ANALYST"], oauth_provider: provider, has_password: false, created_at: new Date().toISOString() };
      const tokens = createDemoTokens(); tokenStore.set(tokens); tokenStore.setUser(user as User);
      return { configured: false, message: `Demo mode: Signed in with ${providerName}. In production, this would redirect to ${providerName} OAuth.` };
    }
    return data;
  }
  catch {
    setDemoMode(true);
    const providerName = provider === "google" ? "Google" : "GitHub";
    const user: DemoUser = { id: "demo-oauth-" + Date.now().toString(36), email: `demo.${provider}@cybersentinel.io`, full_name: `${providerName} Demo User`, organization: "CyberSentinel-X", is_active: true, is_verified: true, roles: ["SECURITY_ANALYST"], oauth_provider: provider, has_password: false, created_at: new Date().toISOString() };
    const tokens = createDemoTokens(); tokenStore.set(tokens); tokenStore.setUser(user as User);
    return { configured: false, message: `Demo mode: Signed in with ${providerName}. In production, this would redirect to ${providerName} OAuth.` };
  }
}

export async function oauthLink(provider: string): Promise<{ configured: boolean; authorize_url?: string; message?: string }> {
  try { const res = await api.get(`/auth/oauth/${provider}/link`); return res.data; }
  catch { return { configured: false, message: "Demo mode: OAuth linking simulated" }; }
}

export async function oauthUnlink(provider: string): Promise<User> {
  try { const res = await api.post<User>(`/auth/oauth/${provider}/unlink`); return res.data; }
  catch { const user = tokenStore.getUser(); if (user) { user.oauth_provider = null; tokenStore.setUser(user); return user; } throw new Error("No user logged in"); }
}

/* ── Other API Functions ────────────────────────────────────────────── */
export async function setPassword(payload: { current_password?: string; new_password: string; confirm_password: string; }): Promise<User> { const res = await api.post<User>("/auth/me/password", payload); return res.data; }
export async function listUsers(): Promise<User[]> { const res = await api.get<User[]>("/auth/users"); return res.data; }
export async function setUserStatus(userId: string, isActive: boolean): Promise<User> { const res = await api.post<User>(`/auth/users/${userId}/status`, { is_active: isActive }); return res.data; }
export async function adminResetPassword(userId: string, newPassword: string): Promise<User> { const res = await api.post<User>(`/auth/users/${userId}/password`, { new_password: newPassword }); return res.data; }
export async function updateUserRoles(userId: string, roles: string[]): Promise<User> { const res = await api.put<User>(`/auth/users/${userId}/roles`, { roles }); return res.data; }
export async function deprovisionUser(userId: string): Promise<User> { const res = await api.post<User>(`/auth/users/${userId}/deprovision`); return res.data; }
export async function restoreUser(userId: string): Promise<User> { const res = await api.post<User>(`/auth/users/${userId}/restore`); return res.data; }
export async function setUserSsoBlock(userId: string, blocked: boolean): Promise<User> { const res = await api.post<User>(`/auth/users/${userId}/sso-block`, { blocked }); return res.data; }
export async function mySessions(): Promise<SessionItem[]> { const res = await api.get<SessionItem[]>("/auth/sessions"); return res.data; }
export async function revokeMySession(deviceId: string): Promise<SessionItem> { const res = await api.post<SessionItem>(`/auth/sessions/${deviceId}/revoke`); return res.data; }
export async function userSessions(userId: string): Promise<SessionItem[]> { const res = await api.get<SessionItem[]>(`/auth/users/${userId}/sessions`); return res.data; }
export async function adminRevokeSession(userId: string, deviceId: string): Promise<SessionItem> { const res = await api.post<SessionItem>(`/auth/users/${userId}/sessions/${deviceId}/revoke`); return res.data; }

async function downloadBlob(url: string, fallbackName: string): Promise<void> {
  const res = await api.get(url, { responseType: "blob" });
  const disposition = String(res.headers["content-disposition"] ?? "");
  const match = disposition.match(/filename="?([^";]+)"?/);
  const filename = match?.[1] ?? fallbackName;
  const blobUrl = URL.createObjectURL(res.data as Blob);
  const a = document.createElement("a"); a.href = blobUrl; a.download = filename;
  document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(blobUrl);
}

export async function downloadEvidenceAttachment(evidenceId: string): Promise<void> { await downloadBlob(`/evidence/${evidenceId}/attachment`, "attachment.bin"); }
export async function uploadEvidenceAttachment(evidenceId: string, file: File): Promise<unknown> { const form = new FormData(); form.append("file", file); const res = await api.post(`/evidence/${evidenceId}/attachment`, form); return res.data; }
export async function exportMyData(format: "json" | "csv" | "zip"): Promise<void> {
  const res = await api.get(`/auth/me/export?fmt=${format}`, { responseType: "blob" });
  const disposition = String(res.headers["content-disposition"] ?? "");
  const match = disposition.match(/filename="?([^";]+)"?/);
  const filename = match?.[1] ?? `cybersentinel-export.${format === "csv" ? "csv" : "json"}`;
  const url = URL.createObjectURL(res.data as Blob);
  const a = document.createElement("a"); a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
}

export function completeOAuth(access: string, refresh: string): void {
  tokenStore.set({ access_token: access, refresh_token: refresh, token_type: "bearer", expires_in: 7 * 24 * 60 * 60 });
  window.dispatchEvent(new CustomEvent("auth:oauth"));
}

export function getErrorMessage(err: unknown): string {
  if (axios.isAxiosError(err)) {
    const detail = err.response?.data as { detail?: unknown } | undefined;
    if (typeof detail?.detail === "string") return detail.detail;
    if (Array.isArray(detail?.detail)) return (detail.detail as Array<{ msg?: string }>).map((d) => d.msg ?? "Invalid input").join("; ");
    return err.message;
  }
  return err instanceof Error ? err.message : "Unexpected error";
}
