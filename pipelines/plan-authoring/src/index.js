import { join } from "node:path";

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
const TASK_INPUTS = Object.freeze({
  task: Object.freeze({ filename: "task.md", optional: false }),
  context: Object.freeze({ filename: "context.md", optional: true }),
});

function projectClarification(run) {
  return Object.freeze({
    path: join(run.taskPath, "clarifications.md"),
    hash: run.hashes?.clarifications ?? null,
  });
}

function projectStatus(run) {
  const state = run.pipelineState;
  return Object.freeze({
    currentStep: null,
    planPath: state.planPath ?? join(run.taskPath, "plan.md"),
    findings: Object.freeze(
      Array.isArray(state.findings)
        ? state.findings.map(({ id, description }) =>
            Object.freeze({ id, summary: description }),
          )
        : [],
    ),
    completedCommits: Object.freeze([]),
    stagnationDirection: state.arbiterDirection?.direction ?? null,
    finalizedFingerprint: null,
    reviewedFingerprint: null,
  });
}

function validateResumeAction(run, action) {
  if (
    run.pipelineState.workflowState !== "WAITING_FOR_USER" ||
    action !== null ||
    run.pipelineState.pendingEdit === null
  ) {
    throw new Error("Resume action is not valid for this paused run.");
  }
}

export const planAuthoringPipeline = Object.freeze({
  id: PLAN_AUTHORING_PIPELINE_ID,
  stateVersion: 1,
  roles: ROLES,
  settings: SETTINGS,
  taskInputs: TASK_INPUTS,
  runOptions: Object.freeze(["project", "task", ...ROLES]),
  requiredRunOptions: Object.freeze(["project", "task"]),
  description: "Analyze a task, draft a commit plan, review it, and write plan.md.",
  projections: Object.freeze({
    clarification: projectClarification,
    status: projectStatus,
  }),
  validateResumeAction,
  workflow: Object.freeze({
    createState: createPlanAuthoringState,
    run: runPlanAuthoring,
    validateRun,
  }),
});
