import { verifyAccessToken } from "../utils/tokens.js";
import { AppError } from "../utils/AppError.js";
import { Session } from "../models/Session.js";

// Step 1 (stateless, no DB): verify the JWT signature, expiry, issuer and audience.
export function authenticate(req, _res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith("Bearer ")) {
    return next(new AppError(401, "NO_TOKEN", "Authentication required"));
  }
  try {
    const p = verifyAccessToken(header.slice(7));
    req.auth = { userId: p.sub, role: p.role, sessionId: p.sid };
    next();
  } catch (err) {
    // The client uses TOKEN_EXPIRED as the signal to silently call /auth/refresh.
    const code = err.name === "TokenExpiredError" ? "TOKEN_EXPIRED" : "INVALID_TOKEN";
    next(new AppError(401, code, "Invalid or expired token"));
  }
}

// Step 2 (stateful, 1 indexed DB lookup): is the session still alive?
// This makes logout / logout-all / revocation take effect IMMEDIATELY instead of waiting up
// to 15 minutes for the access token to expire. Use it on every sensitive route
// (orders, payments, profile, admin). Cache the lookup in Redis if traffic gets high.
export async function requireActiveSession(req, _res, next) {
  const alive = await Session.exists({
    _id: req.auth.sessionId,
    revokedAt: null,
    absoluteExpiresAt: { $gt: new Date() },
  });
  if (!alive) return next(new AppError(401, "SESSION_REVOKED", "Session ended. Please log in again."));
  next();
}

// Role-based access control. Always check the role on the SERVER, never trust the UI.
export const requireRole = (...roles) => (req, _res, next) =>
  roles.includes(req.auth.role) ? next() : next(new AppError(403, "FORBIDDEN", "Not allowed"));
