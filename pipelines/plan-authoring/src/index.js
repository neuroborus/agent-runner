import {
  createPlanAuthoringState,
  MAX_CLARIFICATION_ROUNDS,
  PlanAuthoringWorkflowError,
  runPlanAuthoring,
  WORKFLOW_STATES,
} from "./workflow.js";
import { assertRun as validateRun } from "./workflow-contract.js";

export {
  CLARIFICATION_INSTRUCTIONS,
  DRAFT_INSTRUCTIONS,
  FINDING_RESOLUTION_INSTRUCTIONS,
  PRODUCT_DECISION_INSTRUCTIONS,
  REVIEW_INSTRUCTIONS,
  STAGNATION_INSTRUCTIONS,
} from "./prompts.js";
export {
  createPlanAuthoringState,
  MAX_CLARIFICATION_ROUNDS,
  PlanAuthoringWorkflowError,
  runPlanAuthoring,
  WORKFLOW_STATES,
};

export const PLAN_AUTHORING_PIPELINE_ID = "plan-authoring";

function positiveIntegerSetting(defaultValue) {
  return Object.freeze({
    defaultValue,
    errorMessage: "must be a positive integer",
    validate: (value) => Number.isSafeInteger(value) && value > 0,
  });
}

const ROLES = Object.freeze(["planner", "reviewer", "arbiter"]);
const SETTINGS = Object.freeze({
  maxRevisionRounds: positiveIntegerSetting(15),
  stagnationWindowRounds: positiveIntegerSetting(3),
});

export const planAuthoringPipeline = Object.freeze({
  id: PLAN_AUTHORING_PIPELINE_ID,
  stateVersion: 1,
  roles: ROLES,
  settings: SETTINGS,
  runOptions: Object.freeze(["project", "task", ...ROLES]),
  requiredRunOptions: Object.freeze(["project", "task"]),
  description: "Analyze a task, draft a commit plan, review it, and write plan.md.",
  workflow: Object.freeze({
    createState: createPlanAuthoringState,
    run: runPlanAuthoring,
    validateRun,
  }),
});
