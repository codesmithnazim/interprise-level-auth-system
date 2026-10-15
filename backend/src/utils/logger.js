import pino from "pino";
import { isProd } from "../config/env.js";

// Redact anything secret that could ever end up in a log line.
export const logger = pino({
  level: isProd ? "info" : "debug",
  redact: ["req.headers.authorization", "req.headers.cookie", "*.password", "*.otp", "*.token"],
});
