import { AppError } from "../utils/AppError.js";

export const validate = (schema) => (req, _res, next) => {
  const result = schema.safeParse(req.body);
  if (!result.success) {
    return next(new AppError(400, "VALIDATION_ERROR", "Invalid input", result.error.flatten().fieldErrors));
  }
  req.body = result.data; // sanitized + normalized (trimmed, lower-cased email)
  next();
};
