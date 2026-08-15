import axios, { AxiosError, type InternalAxiosRequestConfig } from "axios";
import { API_BASE } from "../config";
import type { AuthResponse, Tokens, User } from "../types";

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
  timeout: 30000,
});

api.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const token = tokenStore.getAccess();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

let refreshing: Promise<string | null> | null = null;

api.interceptors.response.use(
  (res) => res,
  async (error: AxiosError) => {
    const original = error.config as (InternalAxiosRequestConfig & { _retry?: boolean }) | undefined;
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
