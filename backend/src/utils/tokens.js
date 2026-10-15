import jwt from "jsonwebtoken";
import { randomUUID } from "node:crypto";
import { env, isProd } from "../config/env.js";

// ---------- Access token (JWT, short-lived, lives in browser MEMORY only) ----------
export function signAccessToken({ userId, role, sessionId }) {
  return jwt.sign({ role, sid: sessionId }, env.JWT_ACCESS_SECRET, {
    algorithm: "HS256",
    subject: String(userId),
    issuer: env.JWT_ISSUER,
    audience: env.JWT_AUDIENCE,
    expiresIn: env.ACCESS_TOKEN_TTL_SEC,
    jwtid: randomUUID(),
  });
}

export function verifyAccessToken(token) {
  // ALWAYS pin the algorithm. Never let the token header choose it ("alg: none" attacks).
  return jwt.verify(token, env.JWT_ACCESS_SECRET, {
    algorithms: ["HS256"],
    issuer: env.JWT_ISSUER,
    audience: env.JWT_AUDIENCE,
  });
}

// ---------- Refresh cookie (opaque token, HttpOnly) ----------
// "__Secure-" prefix: browser rejects the cookie unless it is set with Secure over HTTPS.
// (We cannot use "__Host-" because it forces Path=/, and we want the narrow /api/auth path.)
export const REFRESH_COOKIE = isProd ? "__Secure-rt" : "rt";

const baseCookie = {
  httpOnly: true,          // JavaScript cannot read it (blocks XSS theft)
  secure: isProd,          // HTTPS only
  sameSite: "strict",      // never sent on cross-site requests (blocks CSRF)
  path: "/api/auth",       // only sent to auth routes, not to /products, /orders...
};

export const setRefreshCookie = (res, token, maxAgeMs) =>
  res.cookie(REFRESH_COOKIE, token, { ...baseCookie, maxAge: maxAgeMs });

export const clearRefreshCookie = (res) => res.clearCookie(REFRESH_COOKIE, baseCookie);
