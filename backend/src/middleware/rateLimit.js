import rateLimit from "express-rate-limit";

// NOTE: the default store is in-memory (per process). With 2+ servers use rate-limit-redis,
// otherwise each server keeps its own counter and an attacker gets N times the budget.
const base = {
  standardHeaders: "draft-7", // adds RateLimit headers so clients can see how many requests they have left.
  legacyHeaders: false,//turns off the old X-RateLimit-* headers.
  message: { error: {status:429, code: "RATE_LIMITED", message: "Too many requests. Please try again later." } },
};
const byEmail = (req) => String(req.body?.email ?? "none").toLowerCase();
const MIN = 60 * 1000;

export const globalLimiter = rateLimit({ ...base, windowMs: 15 * MIN, limit: 200 }); // generally in this category we set 4.5-5k requests per minute.
export const authIpLimiter = rateLimit({ ...base, windowMs: 15 * MIN, limit: 30 });
export const refreshLimiter = rateLimit({ ...base, windowMs: MIN, limit: 30 });

// Per-EMAIL limits stop distributed attacks (many IPs, one victim). Trade-off: an attacker can
// make a victim wait; that is why only FAILED logins are counted below.
export const loginEmailLimiter = rateLimit({
  ...base, windowMs: 15 * MIN, limit: 10, keyGenerator: byEmail, skipSuccessfulRequests: true,
});
// Successful logins are not limited.The limit of 10 applies to failed attempts.
export const otpEmailLimiter = rateLimit({
  ...base, windowMs: 60 * MIN, limit: 5, keyGenerator: byEmail,
});



// If In case in future you want to use the redis stores for managing the counters use the below code:
//   new RedisStore({ sendCommand: (...args) => client.sendCommand(args), prefix: `rl:${prefix}:` });

// export const globalLimiter = rateLimit({ ...base, windowMs: 15 * MIN, limit: 300, store: makeStore("global") });
// export const authIpLimiter = rateLimit({ ...base, windowMs: 15 * MIN, limit: 30, store: makeStore("authip") });
// export const loginEmailLimiter = rateLimit({
//   ...base, windowMs: 15 * MIN, limit: 10, keyGenerator: byEmail,
//   skipSuccessfulRequests: true, store: makeStore("loginemail"),
// });