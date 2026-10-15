import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { api, refreshAccessToken, setAccessToken, setSessionExpiredHandler } from "../api/http";

const AuthContext = createContext(null);
export const useAuth = () => useContext(AuthContext);

// Tells OTHER tabs to log out when this tab logs out (access tokens are per-tab memory).
const channel = typeof BroadcastChannel !== "undefined" ? new BroadcastChannel("auth") : null;

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true); // true until the first silent-refresh finishes

  const clearLocal = useCallback(() => { setAccessToken(null); setUser(null); }, []);

  // 1) On every page load / reload: try to restore the session from the refresh cookie.
  //    (React StrictMode runs this twice in dev; single-flight refresh makes that harmless.)
  useEffect(() => {
    setSessionExpiredHandler(clearLocal);
    refreshAccessToken()
      .then((data) => setUser(data.user))
      .catch(() => setUser(null))
      .finally(() => setLoading(false));

    if (channel) channel.onmessage = (e) => { if (e.data === "logout") clearLocal(); };
  }, [clearLocal]);

  // 2) Auth actions -----------------------------------------------------------------------
  const register = (name, email, password) => api.post("/auth/register", { name, email, password });
  const verifyEmail = (email, otp) => api.post("/auth/verify-email", { email, otp });
  const resendOtp = (email) => api.post("/auth/resend-otp", { email });

  const login = async (email, password) => {
    const { data } = await api.post("/auth/login", { email, password });
    setAccessToken(data.accessToken);
    setUser(data.user);
    return data.user;
  };

  const logout = async () => {
    try { await api.post("/auth/logout"); } finally {
      clearLocal();
      channel?.postMessage("logout");
    }
  };

  const logoutAll = async () => {
    try { await api.post("/auth/logout-all"); } finally {
      clearLocal();
      channel?.postMessage("logout");
    }
  };

  const value = useMemo(
    () => ({ user, loading, register, verifyEmail, resendOtp, login, logout, logoutAll }),
    [user, loading] // eslint-disable-line react-hooks/exhaustive-deps
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
