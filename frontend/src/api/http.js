import axios from "axios";

const API = import.meta.env.VITE_API_URL;

// ---------------------------------------------------------------------------------------
// The ACCESS TOKEN lives ONLY in this module-level variable (JS memory).
// Never in localStorage / sessionStorage / a normal cookie. A page reload wipes it on purpose;
// bootstrapAuth() in AuthContext gets a new one from the HttpOnly refresh cookie.
// ---------------------------------------------------------------------------------------
let accessToken = null;
export const setAccessToken = (t) => { accessToken = t; };

// Register a callback that AuthContext uses to clear the UI when the session is really dead.
let onSessionExpired = () => {};
export const setSessionExpiredHandler = (fn) => { onSessionExpired = fn; };

export const api = axios.create({
  baseURL: API,
  withCredentials: true, // REQUIRED so the browser sends/accepts the refresh cookie
});

api.interceptors.request.use((config) => {
  if (accessToken) config.headers.Authorization = `Bearer ${accessToken}`;
  return config;
});

// ---- Single-flight refresh --------------------------------------------------------------
// If 5 requests fail with TOKEN_EXPIRED at the same moment, they all await ONE refresh call.
// Without this, the 2nd..5th calls would present an already-rotated token and look like theft.
let refreshPromise = null;

export function refreshAccessToken() {
  if (!refreshPromise) {
    refreshPromise = (async () => {
      for (let attempt = 0; attempt < 3; attempt++) {
        try {
          // Plain axios (not `api`) so this call never triggers the interceptor below.
          const { data } = await axios.post(`${API}/auth/refresh`, null, { withCredentials: true });
          setAccessToken(data.accessToken);
          return data; // { accessToken, expiresIn, user }
        } catch (err) {
          const code = err.response?.data?.error?.code;
          // Another tab is rotating right now: wait a moment, then try with the NEW cookie.
          if (code === "REFRESH_IN_PROGRESS" && attempt < 2) {
            await new Promise((r) => setTimeout(r, 400));
            continue;
          }
          throw err;
        }
      }
    })().finally(() => { refreshPromise = null; });
  }
  return refreshPromise;
}

// ---- Auto-retry once after a silent refresh ---------------------------------------------
api.interceptors.response.use(
  (res) => res,
  async (error) => {
    const original = error.config;
    const status = error.response?.status;
    const code = error.response?.data?.error?.code;

    if (status === 401 && !original._retried && (code === "TOKEN_EXPIRED" || code === "NO_TOKEN")) {
      original._retried = true; // never loop
      try {
        await refreshAccessToken();
        return api(original); // replay the original request with the new token
      } catch {
        setAccessToken(null);
        onSessionExpired();
      }
    }
    // Session was revoked elsewhere (logout-all, reuse detected, password reset...).
    if (status === 401 && (code === "SESSION_REVOKED" || code === "INVALID_TOKEN")) {
      setAccessToken(null);
      onSessionExpired();
    }
    return Promise.reject(error);
  }
);
