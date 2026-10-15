import { clientOrigins } from "../config/env.js";
import { AppError } from "../utils/AppError.js";

// CSRF defense in depth for the two routes that rely on the refresh COOKIE (/refresh, /logout).
// SameSite=Strict is the first wall; this is the second: browsers always attach an Origin
// header to cross-origin POSTs and JavaScript cannot forge it.
// Routes that use the Authorization header need no CSRF protection (browsers never add it).
export function verifyOrigin(req, _res, next) {
  const origin = req.get("origin");
  if (!origin || !clientOrigins.includes(origin)) {
    return next(new AppError(403, "BAD_ORIGIN", "Origin not allowed"));
  }
  next();
}
