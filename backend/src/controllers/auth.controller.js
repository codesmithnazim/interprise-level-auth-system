import mongoose from "mongoose";
import { User } from "../models/User.js";
import { Session } from "../models/Session.js";
import { RefreshToken } from "../models/RefreshToken.js";
import { env } from "../config/env.js";
import { AppError } from "../utils/AppError.js";
import { audit, background } from "../utils/audit.js";
import { hashPassword, verifyPassword, DUMMY_HASH, isPwnedPassword, sha256 } from "../utils/crypto.js";
import { REFRESH_COOKIE, clearRefreshCookie } from "../utils/tokens.js";
import { sendOtpEmail, sendMail, sendSecurityAlert } from "../utils/email.js";
import { issueOtp, verifyOtp } from "../services/otp.service.js";
import {
  createSession, rotateRefreshToken, revokeSession, revokeAllUserSessions,
} from "../services/session.service.js";

// Same wording whether or not the account exists => attackers cannot discover who is registered.
const GENERIC_OTP_MSG = "If the email is eligible, a verification code has been sent.";
const MINUTE = 60 * 1000;

// ------------------------------------------------------------------ REGISTER
export async function register(req, res) {
  const { name, email, password } = req.body;

  // if (await isPwnedPassword(password)) {
  //   throw new AppError(400, "WEAK_PASSWORD", "This password appears in known data breaches. Choose another.");
  // } 
  // Here we do not want to check it 

  // Hash FIRST in every branch so response time does not reveal whether the email exists.
  const passwordHash = await hashPassword(password);
  const existing = await User.findOne({ email });

  if (existing?.emailVerified) {
    // Do not reveal it on screen. Tell the real owner by email instead.
    background(sendMail({
      to: email,
      subject: "Sign-up attempt on your account",
      text: "Someone tried to register with this email, but an account already exists. " +
            "If it was you, just log in or use 'Forgot password'.",
    }));
  } else {
    try {
      await User.findOneAndUpdate(
        { email, emailVerified: false },
        {
          $set: { name, passwordHash, purgeAt: new Date(Date.now() + 24 * 60 * MINUTE) },
        },
        { upsert: true } // re-registering an unverified email just overwrites the old attempt
      );
      const otp = await issueOtp({ email, purpose: "verify_email" });
      if (otp.sent) background(sendOtpEmail(email, otp.code, "verify_email"));
    } catch (err) {
      if (err.code !== 11000) throw err; // 11000 = duplicate key race: treat as success
    }
  }
  res.status(202).json({ message: GENERIC_OTP_MSG });
}

// ------------------------------------------------------------- VERIFY EMAIL
export async function verifyEmail(req, res) {
  const { email, otp } = req.body;
  await verifyOtp({ email, purpose: "verify_email", code: otp });

  const user = await User.findOneAndUpdate(
    { email, emailVerified: false },
    { $set: { emailVerified: true }, $unset: { purgeAt: 1 } },
    {runValidators: true},
    { new: true }
  );
  if (user) audit("email_verified", req, { userId: user._id });
  res.json({ message: "Email verified. You can now log in." });
}

// --------------------------------------------------------------- RESEND OTP
export async function resendOtp(req, res) {
  const { email } = req.body;
  const user = await User.findOne({ email, emailVerified: false }).select("_id");
  if (user) {
    const otp = await issueOtp({ email, purpose: "verify_email" });
    if (otp.sent) background(sendOtpEmail(email, otp.code, "verify_email"));
  }
  res.status(202).json({ message: GENERIC_OTP_MSG });
}

// -------------------------------------------------------------------- LOGIN
async function recordFailedLogin(user) {
  const updated = await User.findByIdAndUpdate(user._id, { $inc: { failedLoginCount: 1 } }, { new: true });
  if (updated.failedLoginCount >= env.LOGIN_MAX_FAILED) {
    await User.updateOne(
      { _id: user._id }, 
      { $set: { lockUntil: new Date(Date.now() + env.LOGIN_LOCK_MIN * MINUTE), failedLoginCount: 0 } }
    );
    background(sendSecurityAlert(user.email, "Your account was temporarily locked",
      `There were ${env.LOGIN_MAX_FAILED} failed login attempts. Login is paused for ${env.LOGIN_LOCK_MIN} minutes.`));
  }
}

export async function login(req, res) {
  const { email, password } = req.body;
  const user = await User.findOne({ email }).select("+passwordHash");

  // Locked: same message/status as the rate limiter, so it reveals nothing about the account.
  if (user?.lockUntil && user.lockUntil > new Date()) {
    throw new AppError(429, "RATE_LIMITED", "Too many requests. Please try again later.");
  }

  // ALWAYS run a hash comparison (dummy if no user) => constant response time.
  const passwordOk = await verifyPassword(user?.passwordHash ?? DUMMY_HASH, password);
  if (!user || !passwordOk) {
    if (user) await recordFailedLogin(user);
    audit("login_failed", req, { userId: user?._id });
    throw new AppError(401, "INVALID_CREDENTIALS", "Invalid email or password.");
  }

  // These checks come AFTER the password is proven, so they cannot be used to probe accounts.
  if (!user.isActive) throw new AppError(403, "ACCOUNT_DISABLED", "This account is disabled.");
  if (!user.emailVerified) {
    const otp = await issueOtp({ email, purpose: "verify_email" });
    if (otp.sent) background(sendOtpEmail(email, otp.code, "verify_email"));
    throw new AppError(403, "EMAIL_NOT_VERIFIED", "Please verify your email. A new code was sent.");
  }

  await User.updateOne({ _id: user._id }, { $set: { failedLoginCount: 0 }, $unset: { lockUntil: 1 } });

  // New-device alert: the user has had sessions before, but never from this browser.
  const [total, sameDevice] = await Promise.all([
    Session.countDocuments({ userId: user._id }),
    Session.exists({ userId: user._id, userAgent: (req.get("user-agent") || "unknown").slice(0, 300) }),
  ]);
  
  if (total > 0 && !sameDevice) {
    background(sendSecurityAlert(user.email, "New device login",
      `A new login to your account was detected from IP ${req.ip}.`));
  }

  const result = await createSession({ user, req, res });
  audit("login_success", req, { userId: user._id });
  res.json(result);
}

// ------------------------------------------------------------------ REFRESH
export async function refresh(req, res) {
  const raw = req.cookies?.[REFRESH_COOKIE];
  if (!raw) throw new AppError(401, "NO_REFRESH", "Not logged in.");
  try {
    res.json(await rotateRefreshToken({ rawToken: raw, req, res }));
  } catch (err) {
    if (err.status === 401) clearRefreshCookie(res); // dead cookie: remove it from the browser
    throw err;
  }
}

// ------------------------------------------------------------------- LOGOUT
// Works with only the cookie, so a user whose access token already expired can still log out.
// Idempotent: always 204.
export async function logout(req, res) {
  const raw = req.cookies?.[REFRESH_COOKIE];
  if (raw) {
    const token = await RefreshToken.findOne({ tokenHash: sha256(raw) }).select("sessionId userId");
    if (token) {
      await revokeSession(token.sessionId, "LOGOUT");
      audit("logout", req, { userId: token.userId });
    }
  }
  clearRefreshCookie(res);
  res.status(204).end();
}

// --------------------------------------------------------- LOGOUT ALL DEVICES
export async function logoutAll(req, res) {
  await revokeAllUserSessions(req.auth.userId, "LOGOUT_ALL");
  audit("logout_all", req, { userId: req.auth.userId });
  clearRefreshCookie(res);
  res.status(204).end();
}

// ----------------------------------------------------------- SESSIONS (LIST)
export async function listSessions(req, res) {
  const sessions = await Session.find({
    userId: req.auth.userId,
    revokedAt: null,
    absoluteExpiresAt: { $gt: new Date() },
  }).sort({ lastUsedAt: -1 }).lean();

  res.json(sessions.map((s) => ({
    id: s._id,
    userAgent: s.userAgent,
    ip: s.ip,
    createdAt: s.createdAt,
    lastUsedAt: s.lastUsedAt,
    current: String(s._id) === req.auth.sessionId,
  })));
}

// ---------------------------------------------------------- SESSION (REVOKE)
export async function revokeOneSession(req, res) {
  const { id } = req.params;
  if (!mongoose.isValidObjectId(id)) throw new AppError(400, "BAD_ID", "Invalid session id");

  // Ownership check in the query itself (prevents IDOR: revoking someone else's session).
  const session = await Session.findOne({ _id: id, userId: req.auth.userId, revokedAt: null });
  if (!session) throw new AppError(404, "NOT_FOUND", "Session not found");

  await revokeSession(session._id, "REVOKED_BY_USER");
  audit("session_revoked", req, { userId: req.auth.userId, meta: { sessionId: id } });
  if (String(session._id) === req.auth.sessionId) clearRefreshCookie(res);
  res.status(204).end();
}

// ----------------------------------------------------------------------- ME
export async function me(req, res) {
  const user = await User.findById(req.auth.userId);
  if (!user || !user.isActive) throw new AppError(401, "SESSION_REVOKED", "Session ended.");
  res.json({ user: user.toPublic() });
}

// ---------------------------------------------------------- FORGOT PASSWORD
export async function forgotPassword(req, res) {
  const { email } = req.body;
  const user = await User.findOne({ email, emailVerified: true, isActive: true }).select("_id");
  if (user) {
    const otp = await issueOtp({ email, purpose: "reset_password" });
    if (otp.sent) background(sendOtpEmail(email, otp.code, "reset_password"));
  }
  res.status(202).json({ message: GENERIC_OTP_MSG });
}

// ----------------------------------------------------------- RESET PASSWORD
export async function resetPassword(req, res) {
  const { email, otp, newPassword } = req.body;
  if (await isPwnedPassword(newPassword)) {
    throw new AppError(400, "WEAK_PASSWORD", "This password appears in known data breaches. Choose another.");
  }
  await verifyOtp({ email, purpose: "reset_password", code: otp });

  const user = await User.findOneAndUpdate(
    { email, emailVerified: true },
    {
      $set: { passwordHash: await hashPassword(newPassword), passwordChangedAt: new Date(), failedLoginCount: 0 },
      $unset: { lockUntil: 1 },
    },
    { new: true }
  );
  if (!user) throw new AppError(400, "INVALID_OTP", "Invalid or expired code.");

  // A reset means "I may be compromised": kick out EVERY device, including an attacker's.
  await revokeAllUserSessions(user._id, "PASSWORD_RESET");
  audit("password_reset", req, { userId: user._id });
  background(sendSecurityAlert(user.email, "Your password was changed", "Your password was just reset."));
  res.json({ message: "Password updated. Please log in." });
}

// ---------------------------------------------------------- CHANGE PASSWORD
export async function changePassword(req, res) {
  const { currentPassword, newPassword } = req.body;
  const user = await User.findById(req.auth.userId).select("+passwordHash");

  // 403 (not 401): a 401 would make the frontend think the session died and log the user out.
  if (!user || !(await verifyPassword(user.passwordHash, currentPassword))) {
    throw new AppError(403, "WRONG_PASSWORD", "Current password is incorrect.");
  }
  if (currentPassword === newPassword) throw new AppError(400, "SAME_PASSWORD", "Choose a different password.");
  if (await isPwnedPassword(newPassword)) {
    throw new AppError(400, "WEAK_PASSWORD", "This password appears in known data breaches. Choose another.");
  }

  user.passwordHash = await hashPassword(newPassword);
  user.passwordChangedAt = new Date();
  await user.save();

  await revokeAllUserSessions(user._id, "PASSWORD_CHANGED", req.auth.sessionId); // keep this device
  audit("password_changed", req, { userId: user._id });
  background(sendSecurityAlert(user.email, "Your password was changed", "Your password was just changed."));
  res.json({ message: "Password changed. Other devices were logged out." });
}

