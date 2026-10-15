import mongoose from "mongoose";
const { Schema } = mongoose;

// One Session = one login on one device. It is also the "family" of refresh tokens.
// Revoking a Session kills every refresh token in that chain at once.
const sessionSchema = new Schema(
  {
    userId: { type: Schema.Types.ObjectId, ref: "User", required: true, index: true },
    userAgent: { type: String, maxlength: 300 },
    ip: String,
    lastUsedAt: Date,
    absoluteExpiresAt: { type: Date, required: true }, // hard cap, never extended
    revokedAt: Date,
    revokedReason: String, // LOGOUT | LOGOUT_ALL | REUSE_DETECTED | PASSWORD_CHANGED | ...
  },
  { timestamps: true }
);

// Keep finished sessions 30 days for forensics, then MongoDB deletes them automatically.
sessionSchema.index({ absoluteExpiresAt: 1 }, { expireAfterSeconds: 30 * 24 * 3600 });

export const Session = mongoose.model("Session", sessionSchema);
