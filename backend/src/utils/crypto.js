import crypto, { timingSafeEqual } from "node:crypto";
import argon2 from "argon2";
import { env } from "../config/env.js";

// SHA-256 is fine for refresh tokens: they are 384 random bits, so they cannot be guessed
// or brute-forced even if the DB leaks. (Passwords need argon2 because humans pick them.)
export const sha256 = (v) =>
  crypto.createHash("sha256").update(v).digest("hex");

// Opaque random refresh token. Not a JWT: nothing inside to decode, revocable via DB.
export const randomToken = (bytes = 48) =>
  crypto.randomBytes(bytes).toString("base64url");

// CSPRNG 6-digit code. Never use Math.random() for security codes.
export const generateOtp = () =>
  crypto.randomInt(0, 1_000_000).toString().padStart(6, "0");

// A 6-digit OTP has only 1,000,000 values, so a plain hash could be reversed instantly
// if the DB leaks. HMAC with a server-side secret (pepper) makes the stolen hash useless.
export const hashOtp = (email, purpose, code) =>
  crypto
    .createHmac("sha256", env.OTP_PEPPER)
    .update(`${email}:${purpose}:${code}`)
    .digest("hex"); //h.digest() with no arguments give us buffer

// Constant-time comparison (prevents timing attacks).
export function safeEqual(a, b) {
  const A = Buffer.from(a);
  const B = Buffer.from(b);
  return A.length === B.length && crypto.timingSafeEqual(A, B); // timingSafeEqual only accepts binary types (Buffer, TypedArray, DataView), if we store hashes in the buffer format then we don't need to use buffer.from()
  // length check is mandatory because the timingSafeEqual() throws if length are not equal
}

// Argon2id with OWASP-recommended minimum parameters (19 MiB, 2 iterations).
// Raise memoryCost/timeCost as far as your server latency budget allows.
const ARGON_OPTS = {
  type: argon2.argon2id,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
};
export const hashPassword = (plain) => argon2.hash(plain, ARGON_OPTS);
export const verifyPassword = (hash, plain) =>
  argon2.verify(hash, plain).catch(() => false);

// Used when the email does not exist, so "unknown email" takes as long as "wrong password".
export const DUMMY_HASH = await argon2.hash(
  "dummy-password-for-timing",
  ARGON_OPTS,
);

// Have I Been Pwned check using k-anonymity: only the first 5 chars of the SHA-1 hash
// leave our server, never the password. Fails OPEN (a HIBP outage must not block signups).
export async function isPwnedPassword(password) {
  try {
    const sha1 = crypto
      .createHash("sha1")
      .update(password)
      .digest("hex")
      .toUpperCase();
    const res = await fetch(
      `https://api.pwnedpasswords.com/range/${sha1.slice(0, 5)}`,
      {
        headers: { "Add-Padding": "true" },
        signal: AbortSignal.timeout(2000),
      },
    );
    if (!res.ok) return false;
    const suffix = sha1.slice(5);
    return (await res.text()).split("\n").some((line) => {
      const [s, count] = line.trim().split(":");
      return s === suffix && Number(count) > 0;
    });
  } catch {
    return false;
  }
}
