import { join } from "node:path";

import {
  createPlanExecutionState,
  MAX_CLARIFICATION_ROUNDS,
  PlanExecutionWorkflowError,
  runPlanExecution,
  WORKFLOW_STATES,
} from "./workflow.js";
import { assertRun as validateRun } from "./workflow-contract.js";

export {
  BOOTSTRAP_ARBITRATION_INSTRUCTIONS,
  BOOTSTRAP_INSTRUCTIONS,
  BOOTSTRAP_RECONCILIATION_INSTRUCTIONS,
  CLARIFICATION_INSTRUCTIONS,
  COMMIT_INSTRUCTIONS,
  DISPUTE_RECONSIDERATION_INSTRUCTIONS,
  FINALIZATION_INSTRUCTIONS,
  FINDING_ARBITRATION_INSTRUCTIONS,
  FINDING_RESOLUTION_INSTRUCTIONS,
  IMPLEMENTATION_INSTRUCTIONS,
  PLAN_COMPATIBILITY_INSTRUCTIONS,
  PRODUCT_DECISION_INSTRUCTIONS,
  REVIEW_INSTRUCTIONS,
  STAGNATION_INSTRUCTIONS,
} from "./prompts.js";
export {
  createPlanExecutionState,
  MAX_CLARIFICATION_ROUNDS,
  PlanExecutionWorkflowError,
  runPlanExecution,
  WORKFLOW_STATES,
};

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
const TASK_INPUTS = Object.freeze({
  task: Object.freeze({ filename: "task.md", optional: false }),
  plan: Object.freeze({ filename: "plan.md", optional: false }),
  taskClarifications: Object.freeze({
    filename: "clarifications.md",
    optional: true,
  }),
  context: Object.freeze({ filename: "context.md", optional: true }),
});
const RETRYABLE_PAUSE_REASONS = new Set([
  "backend_unavailable",
  "environment_blocked",
  "finalization_cannot_pass",
  "local_artifacts_not_ignored",
  "unsafe_git_state",
]);
const RESUMABLE_WORKFLOW_STATES = new Set([
  "CLARIFY",
  "BOOTSTRAP",
  "IMPLEMENT",
  "FINALIZE",
  "REVIEW",
  "RESOLVE_FINDINGS",
  "COMMIT",
]);

function projectClarification(run) {
  return Object.freeze({
    path: run.pipelineState.clarificationPath ?? null,
    hash: run.hashes?.executionClarifications ?? null,
  });
}

function projectStatus(run) {
  const state = run.pipelineState;
  return Object.freeze({
    currentStep: state.currentStep,
    planPath: state.planPath ?? join(run.taskPath, "plan.md"),
    findings: Object.freeze(
      Array.isArray(state.findings)
        ? state.findings.map(({ id, problem }) =>
            Object.freeze({ id, summary: problem }),
          )
        : [],
    ),
    completedCommits: Object.freeze(
      Array.isArray(state.completedCommits) ? [...state.completedCommits] : [],
    ),
    stagnationDirection: state.stagnationDirection?.direction ?? null,
    finalizedFingerprint: state.finalizedFingerprint,
    reviewedFingerprint: state.reviewedFingerprint,
  });
}

function validateResumeAction(run, action) {
  const state = run.pipelineState;
  if (state.workflowState !== "WAITING_FOR_USER") {
    throw new Error("Only a persisted paused run can be resumed.");
  }
  if (state.pendingEdit !== null) {
    if (action !== null) {
      throw new Error("A pending input edit does not accept a resume action.");
    }
    return;
  }
  if (action?.type === "extra-fix-rounds") {
    const additionalFixRounds = state.additionalFixRounds + action.amount;
    if (
      run.pause?.reason !== "fix_limit_reached" ||
      !["IMPLEMENT", "RESOLVE_FINDINGS"].includes(run.pause.resumeState) ||
      !Number.isSafeInteger(additionalFixRounds) ||
      !Number.isSafeInteger(
        state.settings.maxFixRoundsPerStep + additionalFixRounds,
      )
    ) {
      throw new Error("Additional fix rounds are not applicable.");
    }
    return;
  }
  if (action?.type === "override-finding") {
    if (
      !["fix_limit_reached", "no_progress", "dispute_limit_reached"].includes(
        run.pause?.reason,
      ) ||
      state.finalizationResult?.status !== "PASS" ||
      state.reviewedFingerprint === null ||
      !state.findings?.some(({ id }) => id === action.findingId)
    ) {
      throw new Error("Finding override is not applicable.");
    }
    return;
  }
  if (
    action === null &&
    ((run.pause?.reason === "commit_failed" &&
      state.pendingCommit?.status === "consumed") ||
      (RETRYABLE_PAUSE_REASONS.has(run.pause?.reason) &&
        (!state.preflightComplete ||
          ([
            "backend_unavailable",
            "environment_blocked",
            "finalization_cannot_pass",
          ].includes(run.pause?.reason) &&
            RESUMABLE_WORKFLOW_STATES.has(run.pause?.resumeState)))))
  ) {
    return;
  }
  throw new Error("Resume action is not valid for this paused run.");
}

export const planExecutionPipeline = Object.freeze({
  id: PLAN_EXECUTION_PIPELINE_ID,
  stateVersion: 1,
  roles: ROLES,
  settings: SETTINGS,
  taskInputs: TASK_INPUTS,
  runOptions: Object.freeze(["project", "task", ...ROLES]),
  requiredRunOptions: Object.freeze(["project", "task"]),
  description: "Execute, finalize, review, and commit each step of a commit plan.",
  projections: Object.freeze({
    clarification: projectClarification,
    status: projectStatus,
  }),
  validateResumeAction,
  workflow: Object.freeze({
    createState: createPlanExecutionState,
    run: runPlanExecution,
    validateRun,
  }),
});
