import mongoose from "mongoose";
const { Schema } = mongoose;

// At most ONE live code per (email, purpose). Requesting a new code replaces the old one.
const otpSchema = new Schema({
  email: { type: String, required: true },
  purpose: { type: String, enum: ["verify_email", "reset_password"], required: true },
  codeHash: { type: String, required: true }, // HMAC, never the raw code
  attempts: { type: Number, default: 0 },
  lastSentAt: { type: Date, required: true },
  expiresAt: { type: Date, required: true, index: { expires: 0 } },
});
otpSchema.index({ email: 1, purpose: 1 }, { unique: true });

export const Otp = mongoose.model("Otp", otpSchema);
