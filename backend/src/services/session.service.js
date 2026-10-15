import { Session } from "../models/Session.js";
import { RefreshToken } from "../models/RefreshToken.js";
import { User } from "../models/User.js";
import { env } from "../config/env.js";
import { randomToken, sha256 } from "../utils/crypto.js";
import { signAccessToken, setRefreshCookie } from "../utils/tokens.js";
import { AppError } from "../utils/AppError.js";
import { audit } from "../utils/audit.js";

const DAY = 24 * 60 * 60 * 1000;
const userAgentOf = (req) => (req.get("user-agent") || "unknown").slice(0, 300);

// Mint a refresh token (stored hashed) + an access token for an existing session.
async function issueTokens({ user, session, res }) {
  const refreshToken = randomToken();
  // A refresh token can never outlive the session's absolute limit.
  const expiresAt = new Date(
    Math.min(Date.now() + env.REFRESH_TOKEN_TTL_DAYS * DAY, session.absoluteExpiresAt.getTime())
  );
  await RefreshToken.create({
    sessionId: session._id,
    userId: user._id,
    tokenHash: sha256(refreshToken),
    expiresAt,
  });
  setRefreshCookie(res, refreshToken, expiresAt.getTime() - Date.now());

  return {
    accessToken: signAccessToken({ userId: user._id, role: user.role, sessionId: session._id }),
    expiresIn: env.ACCESS_TOKEN_TTL_SEC,
    user: user.toPublic(),
  };
}

// LOGIN: new session (new token family).
export async function createSession({ user, req, res }) {
  const session = await Session.create({
    userId: user._id,
    userAgent: userAgentOf(req),
    ip: req.ip,
    lastUsedAt: new Date(),
    absoluteExpiresAt: new Date(Date.now() + env.SESSION_ABSOLUTE_TTL_DAYS * DAY),
  });
  return issueTokens({ user, session, res });
}

// REFRESH: single-use rotation with reuse detection.
export async function rotateRefreshToken({ rawToken, req, res }) {
  const tokenHash = sha256(rawToken);
  const now = new Date();

  // 1) Atomically "claim" the token: active -> used. Only ONE concurrent request can win.
  const claimed = await RefreshToken.findOneAndUpdate(
    { tokenHash, status: "active", expiresAt: { $gt: now } },
    { $set: { status: "used", usedAt: now } }
  );

  if (!claimed) {
    const old = await RefreshToken.findOne({ tokenHash });
    if (old?.status === "used") {
      // Used a moment ago => almost certainly our own second tab / a retry. Do not punish.
      if (now - old.usedAt < env.REFRESH_GRACE_SEC * 1000) {
        throw new AppError(409, "REFRESH_IN_PROGRESS", "Refresh in progress, retry shortly.");
      }
      // Used long ago and presented AGAIN => someone holds a copy. Kill the whole session.
      await revokeSession(old.sessionId, "REUSE_DETECTED");
      audit("refresh_reuse_detected", req, { userId: old.userId, meta: { sessionId: old.sessionId } });
    }
    throw new AppError(401, "INVALID_REFRESH", "Session expired. Please log in again.");
  }

  // 2) The session must still be alive (not revoked, inside its absolute lifetime).
  const session = await Session.findOne({
    _id: claimed.sessionId,
    revokedAt: null,
    absoluteExpiresAt: { $gt: now },
  });
  const user = session && (await User.findById(claimed.userId));
  if (!session || !user || !user.isActive) {
    if (session) await revokeSession(session._id, "ACCOUNT_UNAVAILABLE");
    throw new AppError(401, "INVALID_REFRESH", "Session expired. Please log in again.");
  }

  // 3) Soft device-drift signal. For stricter shops: revoke here instead of only logging.
  if (session.userAgent !== userAgentOf(req)) {
    audit("refresh_user_agent_changed", req, { userId: user._id, meta: { sessionId: session._id } });
  }

  session.lastUsedAt = now;
  session.ip = req.ip;
  await session.save();

  // 4) Issue the NEXT refresh token in the same family.
  return issueTokens({ user, session, res });
}

// Kill one session + every refresh token in its chain.
export async function revokeSession(sessionId, reason) {
  await Session.updateOne({ _id: sessionId, revokedAt: null }, { revokedAt: new Date(), revokedReason: reason });
  await RefreshToken.updateMany({ sessionId, status: { $ne: "revoked" } }, { status: "revoked" });
}

// Kill every session of a user (optionally keeping the current one).
export async function revokeAllUserSessions(userId, reason, exceptSessionId) {
  const filter = { userId, revokedAt: null };
  if (exceptSessionId) filter._id = { $ne: exceptSessionId };
  const ids = (await Session.find(filter).select("_id").lean()).map((s) => s._id);
  if (!ids.length) return;
  await Session.updateMany({ _id: { $in: ids } }, { revokedAt: new Date(), revokedReason: reason });
  await RefreshToken.updateMany({ sessionId: { $in: ids }, status: { $ne: "revoked" } }, { status: "revoked" });
}
