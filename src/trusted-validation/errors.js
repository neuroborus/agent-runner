import { ownershipDiagnosticFrom } from "../platform/index.js";

export function trustedValidationFailureEvidence(cause) {
  const diagnostic = ownershipDiagnosticFrom(cause);
  return diagnostic === null
    ? []
    : [`Ownership diagnostic: ${JSON.stringify(diagnostic)}`];
}

export class TrustedValidationError extends Error {
  constructor(
    message,
    {
      cause,
      changes = [],
      code = "ERR_TRUSTED_VALIDATION",
      ownershipDiagnostic,
    } = {},
  ) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "TrustedValidationError";
    this.code = code;
    this.ownershipDiagnostic = ownershipDiagnosticFrom(
      ownershipDiagnostic === undefined ? cause : { ownershipDiagnostic },
    );
    this.changes = Object.freeze([...changes]);
  }
}
