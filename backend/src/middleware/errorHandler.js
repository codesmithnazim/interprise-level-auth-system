import { AppError } from "../utils/AppError.js";
import { logger } from "../utils/logger.js";

export const notFound = (_req, _res, next) => next(new AppError(404, "NOT_FOUND", "Route not found"));

// eslint-disable-next-line no-unused-vars
export function errorHandler(err, req, res, _next) {
  if (err instanceof AppError) {
    return res.status(err.status).json({
      error: { code: err.code, message: err.message, details: err.details },
    });
  }
  if (err?.type === "entity.parse.failed" || err?.type === "entity.too.large") {
    return res.status(400).json({ error: { code: "BAD_REQUEST", message: "Invalid request body" } });
  }
  // Unknown error: log everything server-side, tell the client nothing (no stack traces!).
  logger.error({ err, path: req.path }, "unhandled error");
  res.status(500).json({ error: { code: "INTERNAL", message: "Something went wrong" } });
}
