import { InitProposalError } from "./proposal.js";

// Trusted validators select these constraints. Never inspect rejected text,
// exception messages or causes to manufacture a diagnosis.
const CONSTRAINTS = Object.freeze({
  result_shape:
    "Return the complete phase schema with valid status, bounded fields and exact proposal confirmation bindings.",
  resource_destination:
    "Use only the exact inspected destinations, resource kinds and protected-input restrictions for the frozen placement.",
  resource_prior_hash:
    "Match each resource action and prior hash to inspection; reused content must remain unchanged.",
  guidance_size:
    "Keep the complete rendered guidance, including managed setup metadata, within 65,536 UTF-8 bytes.",
  guidance_encoding:
    "Use valid UTF-8 Markdown without unsafe control characters.",
  guidance_content:
    "Exclude credentials, provider output, transcripts and chain-of-thought from guidance.",
  finalization_procedure:
    "Use the supplied placement-specific finalization path and procedure with the actual ordered checks; preserve existing skills.",
  configuration_shape:
    "Return valid project-configuration JSON with only supported fields and values.",
  configuration_version:
    "Use the supported project configuration schemaVersion: 1.",
  configuration_policy:
    "Preserve unrelated settings and the frozen infrastructure binding; select the exact finalization procedure in execution and polishing.",
  ignore_policy:
    "Preserve existing ignore bytes and append only necessary nonduplicate infrastructure exclusions.",
});
const codesFor = (constraint) =>
  constraint === "configuration_version"
    ? ["ERR_UNSUPPORTED_CONFIGURATION_VERSION"]
    : constraint === "configuration_shape"
      ? ["ERR_INVALID_CONFIGURATION"]
      : constraint.startsWith("guidance_")
        ? [
            "ERR_INVALID_GUIDANCE",
            ...(constraint === "guidance_size" ? ["ERR_INIT_PROPOSAL"] : []),
          ]
        : ["ERR_INIT_PROPOSAL"];

export function isInitRejection(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    typeof value.constraint === "string" &&
    Object.hasOwn(CONSTRAINTS, value.constraint) &&
    codesFor(value.constraint).includes(value.code)
  );
}

export function initResultRejection(cause, setup) {
  const rejection =
    cause instanceof InitProposalError
      ? { code: cause.code, constraint: cause.constraint }
      : (setup.resultRejection?.(cause) ?? null);
  return isInitRejection(rejection) ? rejection : null;
}

export function initCorrectiveFeedback(state) {
  const feedback = state.correctiveFeedback;
  if (feedback === null) return null;
  const { code, constraint } = feedback;
  if (!isInitRejection(feedback))
    throw new Error("Invalid init rejection diagnosis.");
  return {
    code,
    constraint,
    explanation: `Init result rejected (${constraint}; ${code}). ${CONSTRAINTS[constraint]} Correct the result at the same checkpoint without changing frozen inputs or permissions.`,
  };
}
