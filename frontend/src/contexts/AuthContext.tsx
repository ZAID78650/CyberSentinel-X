import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api, login, logout as doLogout, register, tokenStore } from "../services/api";
import type { AuthResponse, User } from "../types";

interface AuthContextValue {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string, rememberMe: boolean) => Promise<AuthResponse>;
  register: (payload: {
    full_name: string;
    email: string;
    organization?: string;
    password: string;
    confirm_password: string;
    accept_terms: boolean;
  }) => Promise<AuthResponse>;
  logout: () => void;
  refreshUser: () => Promise<void>;
  hasRole: (...roles: string[]) => boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(() => tokenStore.getUser());
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    const onExpired = () => setUser(null);
    const onLogout = () => setUser(null);
    const onOAuth = () => {
      // Tokens are already stored; fetch the user profile to complete sign-in
      api.get<User>("/auth/me").then((res) => {
        setUser(res.data);
        tokenStore.setUser(res.data);
      }).catch(() => setUser(null));
    };
    window.addEventListener("auth:expired", onExpired);
    window.addEventListener("auth:logout", onLogout);
    window.addEventListener("auth:oauth", onOAuth);
    return () => {
      window.removeEventListener("auth:expired", onExpired);
      window.removeEventListener("auth:logout", onLogout);
      window.removeEventListener("auth:oauth", onOAuth);
    };
  }, []);

  const handleLogin = useCallback(async (email: string, password: string, rememberMe: boolean) => {
    setIsLoading(true);
    try {
      const res = await login(email, password, rememberMe);
      setUser(res.user);
      return res;
    } finally {
      setIsLoading(false);
    }
  }, []);

  const handleRegister = useCallback(async (payload: {
    full_name: string;
    email: string;
    organization?: string;
    password: string;
    confirm_password: string;
    accept_terms: boolean;
  }) => {
    setIsLoading(true);
    try {
      const res = await register(payload);
      setUser(res.user);
      return res;
    } finally {
      setIsLoading(false);
    }
  }, []);

  const handleLogout = useCallback(() => {
    doLogout();
    setUser(null);
  }, []);

  const handleRefreshUser = useCallback(async () => {
    try {
      const res = await api.get<User>("/auth/me");
      setUser(res.data);
      tokenStore.setUser(res.data);
    } catch {
      setUser(null);
    }
  }, []);

  const hasRole = useCallback(
    (...roles: string[]) => {
      if (!user) return false;
      return roles.some((r) => user.roles.includes(r));
    },
    [user],
  );

  const value = useMemo(
    () => ({
      user,
      isAuthenticated: !!user,
      isLoading,
      login: handleLogin,
      register: handleRegister,
      logout: handleLogout,
      refreshUser: handleRefreshUser,
      hasRole,
    }),
    [user, isLoading, handleLogin, handleRegister, handleLogout, handleRefreshUser, hasRole],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
