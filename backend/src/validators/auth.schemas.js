import { z } from "zod";

// zod also guarantees each field is a STRING, which blocks NoSQL injection payloads
// like { "email": { "$ne": null } }.
const email = z.string().trim().toLowerCase().email().max(254);
// NIST-style: length matters, composition rules do not. Max 128 stops huge-password DoS on argon2.
const newPassword = z.string().min(10, "At least 10 characters").max(128);
const otp = z.string().regex(/^\d{6}$/, "Code must be 6 digits");

export const schemas = {
  register: z.object({ name: z.string().trim().min(2).max(100), email, password: newPassword }),
  verifyEmail: z.object({ email, otp }),
  emailOnly: z.object({ email }),
  login: z.object({ email, password: z.string().min(1).max(128) }),
  resetPassword: z.object({ email, otp, newPassword }),
  changePassword: z.object({ currentPassword: z.string().min(1).max(128), newPassword }),
};
