import { Otp } from "../models/Otp.js";
import { env } from "../config/env.js";
import { generateOtp, hashOtp, safeEqual } from "../utils/crypto.js";
import { AppError } from "../utils/AppError.js";

const INVALID = () => new AppError(400, "INVALID_OTP", "Invalid or expired code.");

// Creates (or replaces) the code for this email+purpose.
// Returns { sent:false } during the resend cooldown. It does NOT throw, so callers can answer
// with the same generic response every time (no account enumeration).
export async function issueOtp({ email, purpose }) {
  const existing = await Otp.findOne({ email, purpose }).select("lastSentAt").lean();
  if (existing && Date.now() - existing.lastSentAt.getTime() < env.OTP_RESEND_COOLDOWN_SEC * 1000) {
    return { sent: false };
  }
  const code = generateOtp();
  await Otp.findOneAndUpdate(
    { email, purpose },
    {
      $set: {
        codeHash: hashOtp(email, purpose, code),
        attempts: 0,                       // new code => fresh attempt budget
        lastSentAt: new Date(),
        expiresAt: new Date(Date.now() + env.OTP_TTL_MIN * 60 * 1000),
      },
    },
    { upsert: true }
  );
  return { sent: true, code };
}

// Verifies and CONSUMES the code (single use). Throws one generic error for every failure.
export async function verifyOtp({ email, purpose, code }) {
  const otp = await Otp.findOne({ email, purpose });
  if (!otp || otp.expiresAt < new Date()) throw INVALID();

  // Count the attempt BEFORE comparing, atomically. Parallel guesses cannot sneak past the limit.
  const counted = await Otp.findOneAndUpdate(
    { _id: otp._id, attempts: { $lt: env.OTP_MAX_ATTEMPTS } },
    { $inc: { attempts: 1 } },
    { new: true }
  );
  if (!counted) {
    await Otp.deleteOne({ _id: otp._id }); // too many wrong guesses: burn the code
    throw INVALID();
  }
  if (!safeEqual(counted.codeHash, hashOtp(email, purpose, code))) throw INVALID();

  await Otp.deleteOne({ _id: otp._id }); // single use
}
