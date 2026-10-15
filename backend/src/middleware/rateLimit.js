import rateLimit from "express-rate-limit";

// NOTE: the default store is in-memory (per process). With 2+ servers use rate-limit-redis,
// otherwise each server keeps its own counter and an attacker gets N times the budget.
const base = {
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: { code: "RATE_LIMITED", message: "Too many requests. Please try again later." } },
};
const byEmail = (req) => String(req.body?.email ?? "none").toLowerCase();
const MIN = 60 * 1000;

export const globalLimiter = rateLimit({ ...base, windowMs: 15 * MIN, limit: 300 });
export const authIpLimiter = rateLimit({ ...base, windowMs: 15 * MIN, limit: 30 });
export const refreshLimiter = rateLimit({ ...base, windowMs: MIN, limit: 30 });

// Per-EMAIL limits stop distributed attacks (many IPs, one victim). Trade-off: an attacker can
// make a victim wait; that is why only FAILED logins are counted below.
export const loginEmailLimiter = rateLimit({
  ...base, windowMs: 15 * MIN, limit: 10, keyGenerator: byEmail, skipSuccessfulRequests: true,
});
export const otpEmailLimiter = rateLimit({
  ...base, windowMs: 60 * MIN, limit: 5, keyGenerator: byEmail,
});
