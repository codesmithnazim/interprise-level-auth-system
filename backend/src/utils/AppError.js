// One error type for every "expected" failure. The error handler turns it into
// { error: { code, message, details } } so the frontend can branch on `code`.
export class AppError extends Error {
  constructor(status, code, message, details) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}
