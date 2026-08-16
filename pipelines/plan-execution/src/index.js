export {
  CLARIFICATION_INSTRUCTIONS,
  FINDING_RESOLUTION_INSTRUCTIONS,
  IMPLEMENTATION_INSTRUCTIONS,
  PLAN_COMPATIBILITY_INSTRUCTIONS,
  PRODUCT_DECISION_INSTRUCTIONS,
  REVIEW_INSTRUCTIONS,
} from "./prompts.js";
export { MAX_CLARIFICATION_ROUNDS, WORKFLOW_STATES } from "./workflow.js";

export const PLAN_EXECUTION_PIPELINE_ID = "plan-execution";

function positiveIntegerSetting(defaultValue) {
  return Object.freeze({
    defaultValue,
    errorMessage: "must be a positive integer",
    validate: (value) => Number.isSafeInteger(value) && value > 0,
  });
}

const ROLES = Object.freeze(["worker", "reviewer", "arbiter"]);
const SETTINGS = Object.freeze({
  maxFixRoundsPerStep: positiveIntegerSetting(5),
  maxDisputesPerFinding: positiveIntegerSetting(2),
  maxSameFindingRounds: positiveIntegerSetting(3),
  stagnationWindowRounds: positiveIntegerSetting(3),
});

export const planExecutionPipeline = Object.freeze({
  id: PLAN_EXECUTION_PIPELINE_ID,
  stateVersion: 1,
  roles: ROLES,
  settings: SETTINGS,
  runOptions: Object.freeze(["project", "task", ...ROLES]),
  requiredRunOptions: Object.freeze(["project", "task"]),
  description: "Execute, finalize, review, and commit each step of a commit plan.",
});
