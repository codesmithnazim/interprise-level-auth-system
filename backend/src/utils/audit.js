import { AuditLog } from "../models/AuditLog.js";
import { logger } from "./logger.js";

// Security event trail (login success/failure, reuse detected, logout-all, password change...).
// Fire-and-forget: auditing must never break or slow down the request.
export function audit(event, req, { userId, meta } = {}) {
  AuditLog.create({
    event,
    userId,
    ip: req?.ip,
    userAgent: req?.get?.("user-agent")?.slice(0, 300),
    meta,
  }).catch((err) => logger.error({ err }, "audit write failed"));
}

// Run a promise in the background; log (never throw) on failure.
export const background = (promise) =>
  promise.catch((err) => logger.error({ err }, "background task failed"));
