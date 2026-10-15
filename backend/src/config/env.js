// Loads and VALIDATES environment variables once at startup.
// If a secret is missing or too weak the server refuses to start (fail fast),
// instead of silently running in an insecure state.
import "dotenv/config";
import { z } from "zod";

const num = (def) => z.coerce.number().default(def);

const schema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: num(5000),
  MONGO_URI: z.string().min(1),
  CLIENT_ORIGINS: z.string().min(1),

  // Secrets: minimum 32 chars. NEVER commit them. Rotate on suspected leak.
  JWT_ACCESS_SECRET: z.string().min(32),
  OTP_PEPPER: z.string().min(32),
  JWT_ISSUER: z.string().default("shop-api"),
  JWT_AUDIENCE: z.string().default("shop-web"),

  // Token / session lifetimes
  ACCESS_TOKEN_TTL_SEC: num(15 * 60),        // short: a stolen access token dies fast
  REFRESH_TOKEN_TTL_DAYS: num(7),            // sliding window, renewed on every rotation
  SESSION_ABSOLUTE_TTL_DAYS: num(30),        // hard cap: forced re-login after this
  REFRESH_GRACE_SEC: num(10),                // tolerance for two tabs refreshing together

  // OTP rules
  OTP_TTL_MIN: num(10),
  OTP_MAX_ATTEMPTS: num(5),
  OTP_RESEND_COOLDOWN_SEC: num(60),

  // Brute-force protection
  LOGIN_MAX_FAILED: num(5),
  LOGIN_LOCK_MIN: num(15),

  TRUST_PROXY: num(0),

  SMTP_HOST: z.string().optional(),
  SMTP_PORT: num(587),
  SMTP_USER: z.string().optional(),
  SMTP_PASS: z.string().optional(),
  MAIL_FROM: z.string().default("Shop <no-reply@localhost>"),
});

const parsed = schema.safeParse(process.env);
if (!parsed.success) {
  console.error("Invalid environment:", parsed.error.flatten().fieldErrors);
  process.exit(1);
}

export const env = parsed.data;
export const isProd = env.NODE_ENV === "production";
export const clientOrigins = env.CLIENT_ORIGINS.split(",").map((s) => s.trim());
