import mongoose from "mongoose";
const { Schema } = mongoose;

const userSchema = new Schema(
  {
    name: { type: String, required: true, trim: true, maxlength: 100 },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    // select:false => never returned by queries unless you explicitly .select("+passwordHash")
    passwordHash: { type: String, required: true, select: false },
    role: { type: String, enum: ["customer", "admin"], default: "customer" },
    emailVerified: { type: Boolean, default: false },
    isActive: { type: Boolean, default: true }, // admin can disable an account instantly
    failedLoginCount: { type: Number, default: 0 },
    lockUntil: Date,
    passwordChangedAt: Date,
    // Unverified accounts are auto-deleted by MongoDB after this date (TTL index).
    purgeAt: { type: Date, index: { expires: 0 } },
  },
  { timestamps: true }
);

// Whitelist of fields that may leave the server. Never res.json(user) directly.
userSchema.methods.toPublic = function () {
  return { id: this._id, name: this.name, email: this.email, role: this.role };
};

export const User = mongoose.model("User", userSchema);
