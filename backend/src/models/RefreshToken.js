import mongoose from "mongoose";
const { Schema } = mongoose;

// Every refresh token ever issued is a row. On rotation the old row is marked "used"
// (NOT deleted). A "used" token showing up again is the theft signal.
const refreshTokenSchema = new Schema({
  sessionId: { type: Schema.Types.ObjectId, ref: "Session", required: true, index: true },
  userId: { type: Schema.Types.ObjectId, ref: "User", required: true },
  tokenHash: { type: String, required: true, unique: true }, // SHA-256, never the raw token
  status: { type: String, enum: ["active", "used", "revoked"], default: "active" },
  usedAt: Date,
  expiresAt: { type: Date, required: true, index: { expires: 0 } }, // TTL auto-cleanup
});

export const RefreshToken = mongoose.model("RefreshToken", refreshTokenSchema);
