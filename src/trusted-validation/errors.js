export class TrustedValidationError extends Error {
  constructor(
    message,
    { cause, changes = [], code = "ERR_TRUSTED_VALIDATION" } = {},
  ) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "TrustedValidationError";
    this.code = code;
    this.changes = Object.freeze([...changes]);
  }
}
