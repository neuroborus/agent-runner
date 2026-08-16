/** Persisted states owned by the plan-authoring pipeline. */
export const MAX_CLARIFICATION_ROUNDS = 3;

export const WORKFLOW_STATES = Object.freeze([
  "CLARIFY",
  "ANALYZE",
  "DRAFT",
  "REVIEW",
  "REVISE",
  "VALIDATE",
  "WRITE_PLAN",
  "WAITING_FOR_USER",
  "DONE",
  "FAILED",
]);
