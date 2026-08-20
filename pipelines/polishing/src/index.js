import {
  createPolishingState,
  MAX_CLARIFICATION_ROUNDS,
  PolishingWorkflowError,
  runPolishing,
  WORKFLOW_STATES,
} from "./workflow.js";
import {
  assertRun as validateRun,
  MAX_DISPUTES_PER_FINDING,
} from "./workflow-contract.js";

export {
  BOOTSTRAP_ARBITRATION_INSTRUCTIONS,
  BOOTSTRAP_INSTRUCTIONS,
  BOOTSTRAP_RECONCILIATION_INSTRUCTIONS,
  CLARIFICATION_INSTRUCTIONS,
  DISPUTE_RECONSIDERATION_INSTRUCTIONS,
  FINALIZATION_INSTRUCTIONS,
  FINDING_ARBITRATION_INSTRUCTIONS,
  FINDING_RESOLUTION_INSTRUCTIONS,
  POLISH_INSTRUCTIONS,
  PRODUCT_DECISION_INSTRUCTIONS,
  REVIEW_INSTRUCTIONS,
  STAGNATION_INSTRUCTIONS,
} from "./prompts.js";
export {
  createPolishingState,
  MAX_CLARIFICATION_ROUNDS,
  PolishingWorkflowError,
  runPolishing,
  WORKFLOW_STATES,
};

export const POLISHING_PIPELINE_ID = "polishing";

function positiveIntegerSetting(defaultValue, maximum = null) {
  return Object.freeze({
    defaultValue,
    errorMessage:
      maximum === null
        ? "must be a positive integer"
        : `must be a positive integer no greater than ${maximum}`,
    validate: (value) =>
      Number.isSafeInteger(value) &&
      value > 0 &&
      (maximum === null || value <= maximum),
  });
}

const ROLES = Object.freeze(["worker", "reviewer", "arbiter"]);
const SETTINGS = Object.freeze({
  maxFixRounds: positiveIntegerSetting(5),
  maxDisputesPerFinding: positiveIntegerSetting(
    2,
    MAX_DISPUTES_PER_FINDING,
  ),
  maxSameFindingRounds: positiveIntegerSetting(3),
  stagnationWindowRounds: positiveIntegerSetting(3),
});

export const polishingPipeline = Object.freeze({
  id: POLISHING_PIPELINE_ID,
  stateVersion: 1,
  roles: ROLES,
  settings: SETTINGS,
  runOptions: Object.freeze(["project", "task", ...ROLES]),
  requiredRunOptions: Object.freeze(["project", "task"]),
  description: "Polish and review an existing dirty worktree without committing it.",
  workflow: Object.freeze({
    createState: createPolishingState,
    run: runPolishing,
    validateRun,
  }),
});
