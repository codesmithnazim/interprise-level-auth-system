import mongoose from "mongoose";
const { Schema } = mongoose;

const auditSchema = new Schema({
  event: { type: String, required: true, index: true },
  userId: { type: Schema.Types.ObjectId, index: true },
  ip: String,
  userAgent: String,
  meta: Schema.Types.Mixed,
  createdAt: { type: Date, default: Date.now, index: { expires: 365 * 24 * 3600 } },
});

export const AuditLog = mongoose.model("AuditLog", auditSchema);
