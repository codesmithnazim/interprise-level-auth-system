import { Router } from "express";
import * as c from "../controllers/auth.controller.js";
import { validate } from "../middleware/validate.js";
import { schemas } from "../validators/auth.schemas.js";
import { authenticate, requireActiveSession } from "../middleware/authenticate.js";
import { verifyOrigin } from "../middleware/verifyOrigin.js";
import {
  authIpLimiter, loginEmailLimiter, otpEmailLimiter, refreshLimiter,
} from "../middleware/rateLimit.js";

const router = Router();

// Responses contain tokens/personal data: forbid any browser or proxy caching.
router.use((_req, res, next) => { res.set("Cache-Control", "no-store"); next(); });

const guard = [authenticate, requireActiveSession]; // JWT valid AND session not revoked

// ---- Public
router.post("/register",        authIpLimiter, validate(schemas.register),    otpEmailLimiter, c.register);
router.post("/verify-email",    authIpLimiter, validate(schemas.verifyEmail),                  c.verifyEmail);
router.post("/resend-otp",      authIpLimiter, validate(schemas.emailOnly),   otpEmailLimiter, c.resendOtp);
router.post("/login",           authIpLimiter, validate(schemas.login),       loginEmailLimiter, c.login);
router.post("/forgot-password", authIpLimiter, validate(schemas.emailOnly),   otpEmailLimiter, c.forgotPassword);
router.post("/reset-password",  authIpLimiter, validate(schemas.resetPassword),                c.resetPassword);

// ---- Cookie-based (CSRF-sensitive => Origin check)
router.post("/refresh", verifyOrigin, refreshLimiter, c.refresh);
router.post("/logout",  verifyOrigin, c.logout);

// ---- Bearer-token based (immune to CSRF)
router.get("/me",                guard, c.me);
router.get("/sessions",          guard, c.listSessions);
router.delete("/sessions/:id",   guard, c.revokeOneSession);
router.post("/logout-all",       guard, c.logoutAll);
router.post("/change-password",  guard, validate(schemas.changePassword), c.changePassword);

export default router;
