/** Persisted states owned by the plan-execution pipeline. */
export const MAX_CLARIFICATION_ROUNDS = 3;

export const WORKFLOW_STATES = Object.freeze([
  "CLARIFY",
  "BOOTSTRAP",
  "IMPLEMENT",
  "FINALIZE",
  "REVIEW",
  "RESOLVE_FINDINGS",
  "COMMIT",
  "WAITING_FOR_USER",
  "DONE",
  "FAILED",
]);
