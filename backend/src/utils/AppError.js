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


// The error object we get from there will be an error Object and will be behaved more diferent then the objects we get from the ordinary classes.
// One more thing is that always the object we get through "new" keyword starts from the base class and the child class(s) just add or modify the properties or Methods
// of the object made by the base(parent) class.
