import nodemailer from "nodemailer";
import { env, isProd } from "../config/env.js";
import { logger } from "./logger.js";

const transporter = env.SMTP_HOST
  ? nodemailer.createTransport({
      host: env.SMTP_HOST,
      port: env.SMTP_PORT,
      secure: env.SMTP_PORT === 465,
      auth: { user: env.SMTP_USER, pass: env.SMTP_PASS },
    })
  : null;

if (!transporter && isProd) throw new Error("SMTP_HOST is required in production");

export async function sendMail({ to, subject, text }) {
  if (!transporter) {
    // DEV ONLY: print the email so you can copy the OTP. Never reached in production.
    logger.warn({ to, subject, text }, "DEV MAIL (no SMTP configured)");
    return;
  }
  await transporter.sendMail({ from: env.MAIL_FROM, to, subject, text });
}

const PURPOSE_TEXT = {
  verify_email: "verify your email address",
  reset_password: "reset your password",
};

export const sendOtpEmail = (to, code, purpose) =>
  sendMail({
    to,
    subject: "Your verification code",
    text:
      `Use this code to ${PURPOSE_TEXT[purpose]}:\n\n    ${code}\n\n` +
      `It expires in ${env.OTP_TTL_MIN} minutes and works once.\n` +
      `Never share it with anyone. Our staff will never ask for it.\n` +
      `If you did not request this, you can ignore this email.`,
  });

export const sendSecurityAlert = (to, subject, body) =>
  sendMail({ to, subject, text: `${body}\n\nIf this was not you, reset your password immediately.` });
