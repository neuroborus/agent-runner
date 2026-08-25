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
const PUBLIC_PAUSE_EXPLANATIONS = Object.freeze({
  backend_unavailable: "The selected backend is temporarily unavailable.",
  clarification_answers_required:
    "Material clarification answers are required before planning can continue.",
  clarification_limit_reached:
    "Clarification reached its configured question-round limit.",
  clarifications_changed:
    "The clarification artifact changed outside an authorized editor window.",
  input_changed: "A task input changed after the run began.",
  internal_failure: "Plan authoring failed.",
  plan_revision_limit_reached:
    "Plan revision reached its configured correction limit.",
  plan_revision_not_converging:
    "Plan revision did not converge within the bounded correction window.",
  proactive_clarification:
    "Optional proactive clarification input is pending.",
  product_decision_required:
    "A material product decision is required before planning can continue.",
  read_only_mutation:
    "The repository changed during a read-only turn; inspect the workspace and start a fresh run.",
});

function publicCode(value) {
  return typeof value === "string" && /^[A-Z0-9_]{1,64}$/u.test(value)
    ? value
    : null;
}

function publicResumeState(run) {
  return run.pipelineState.workflowState === "WAITING_FOR_USER" &&
    run.pause.reason === "backend_unavailable" &&
    WORKFLOW_STATES.includes(run.pause.resumeState)
    ? run.pause.resumeState
    : null;
}

function projectPause(run) {
  if (run.pause === null) {
    return null;
  }
  const knownReason = Object.hasOwn(
    PUBLIC_PAUSE_EXPLANATIONS,
    run.pause.reason,
  );
  const reason = knownReason ? run.pause.reason : "unknown_pause";
  const explanation = knownReason
    ? PUBLIC_PAUSE_EXPLANATIONS[reason]
    : "No public diagnostic is available for this pause.";
  const pendingRequest =
    run.pipelineState.workflowState === "WAITING_FOR_USER" &&
    run.pause.inputRequest !== undefined &&
    run.pause.inputResponse === undefined;
  const responseSubmitted = run.pause.inputResponse !== undefined;
  const nextActions = pendingRequest
    ? [
        Object.freeze({
          type: "respond",
          requestId: run.pause.inputRequest.id,
        }),
      ]
    : [];
  if (
    !pendingRequest &&
    !responseSubmitted &&
    run.pipelineState.workflowState === "WAITING_FOR_USER"
  ) {
    try {
      validateResumeAction(run, null);
      nextActions.push(Object.freeze({ type: "resume", action: null }));
    } catch {}
  }
  return Object.freeze({
    reason,
    code: knownReason ? publicCode(run.pause.code) : null,
    explanation,
    evidence: Object.freeze([]),
    resumeState: publicResumeState(run),
    nextActions: Object.freeze(nextActions),
  });
}

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
    (run.pipelineState.pendingEdit === null &&
      run.pause?.reason !== "backend_unavailable")
  ) {
    throw new Error("Resume action is not valid for this paused run.");
  }
}

export const planAuthoringPipeline = Object.freeze({
  id: PLAN_AUTHORING_PIPELINE_ID,
  stateVersion: 1,
  migrations: Object.freeze({}),
  roles: ROLES,
  settings: SETTINGS,
  taskInputs: TASK_INPUTS,
  runOptions: Object.freeze(["project", "task", ...ROLES]),
  requiredRunOptions: Object.freeze(["project", "task"]),
  description: "Analyze a task, draft a commit plan, review it, and write plan.md.",
  projections: Object.freeze({
    clarification: projectClarification,
    pause: projectPause,
    status: projectStatus,
  }),
  validateResumeAction,
  workflow: Object.freeze({
    createState: createPlanAuthoringState,
    run: runPlanAuthoring,
    validateRun,
  }),
});
