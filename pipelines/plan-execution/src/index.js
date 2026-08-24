import { join } from "node:path";

import {
  createPlanExecutionState,
  MAX_CLARIFICATION_ROUNDS,
  PlanExecutionWorkflowError,
  runPlanExecution,
  WORKFLOW_STATES,
} from "./workflow.js";
import {
  assertRun as validateRun,
  DEFAULT_FINALIZATION_POLICY,
  isFinalizationPolicy,
  sha256,
} from "./workflow-contract.js";

export {
  BOOTSTRAP_ARBITRATION_INSTRUCTIONS,
  BOOTSTRAP_INSTRUCTIONS,
  BOOTSTRAP_RECONCILIATION_INSTRUCTIONS,
  CLARIFICATION_INSTRUCTIONS,
  COMMIT_INSTRUCTIONS,
  DISPUTE_RECONSIDERATION_INSTRUCTIONS,
  FINALIZATION_INSTRUCTIONS,
  finalizationBootstrapInstructions,
  finalizationGuidanceInstructions,
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
  finalization: Object.freeze({
    defaultValue: DEFAULT_FINALIZATION_POLICY,
    errorMessage:
      "must be auto, none, or a normalized repository-relative SKILL.md path",
    validate: isFinalizationPolicy,
  }),
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
  "finalization_skill_invalid",
  "finalization_skill_missing",
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
      (state.pendingCommit?.status === "consumed" ||
        (state.pendingCommit === null &&
          run.pause.resumeState === "COMMIT"))) ||
      (RETRYABLE_PAUSE_REASONS.has(run.pause?.reason) &&
        (!state.preflightComplete ||
          ([
            "backend_unavailable",
            "environment_blocked",
            "finalization_cannot_pass",
            "finalization_skill_invalid",
            "finalization_skill_missing",
          ].includes(run.pause?.reason) &&
            RESUMABLE_WORKFLOW_STATES.has(run.pause?.resumeState)))))
  ) {
    return;
  }
  throw new Error("Resume action is not valid for this paused run.");
}

const LEGACY_REQUIRED_CHECKS = Object.freeze([
  Object.freeze({
    id: "C1",
    command: "Rediscover and run the complete project validation procedure",
  }),
]);
const EMPTY_INFRASTRUCTURE_FINGERPRINT = sha256("");

function validationEvidence() {
  return Object.freeze({
    requiredChecks: LEGACY_REQUIRED_CHECKS,
    validationInfrastructure: Object.freeze([]),
  });
}

function upgradedLegacyFinalization(result) {
  if (result === null) {
    return null;
  }
  return Object.freeze({
    ...result,
    requiredChecks: LEGACY_REQUIRED_CHECKS,
    validationInfrastructure: Object.freeze([]),
    validationInfrastructureFingerprint: EMPTY_INFRASTRUCTURE_FINGERPRINT,
    checks: Object.freeze([
      Object.freeze({
        checkId: "C1",
        command: LEGACY_REQUIRED_CHECKS[0].command,
        status: result.status === "PASS" ? "PASS" : "FAIL",
        evidence: Object.freeze([
          "Migrated legacy aggregate evidence; active runs must re-finalize.",
        ]),
      }),
    ]),
    validationChanged: false,
  });
}

export function migratePlanExecutionStateV1(run) {
  const current = run.pipelineState;
  const prepared = current.resolvedSummary !== null;
  const immutableTerminal = ["DONE", "FAILED"].includes(current.workflowState);
  const validationMigrationPending = prepared && !immutableTerminal;
  const paused = current.workflowState === "WAITING_FOR_USER";
  const commitVerificationPending =
    validationMigrationPending &&
    current.workflowState === "COMMIT" &&
    current.pendingCommit?.status === "consumed";
  const rerunFinalization =
    validationMigrationPending &&
    !paused &&
    !commitVerificationPending &&
    ["FINALIZE", "REVIEW", "RESOLVE_FINDINGS", "COMMIT"].includes(
      current.workflowState,
    );
  const keepLegacyGate =
    immutableTerminal || paused || commitVerificationPending;
  const finalizationResult = keepLegacyGate
    ? upgradedLegacyFinalization(current.finalizationResult)
    : null;
  const reviewedFingerprint = keepLegacyGate
    ? current.reviewedFingerprint
    : null;
  return Object.freeze({
    ...current,
    workflowState: rerunFinalization ? "FINALIZE" : current.workflowState,
    workerValidation: validationMigrationPending
      ? null
      : current.workerSummary === null
        ? null
        : validationEvidence(),
    reviewerValidation: validationMigrationPending
      ? null
      : current.reviewerSummary === null
        ? null
        : validationEvidence(),
    requiredChecks: prepared ? LEGACY_REQUIRED_CHECKS : null,
    validationInfrastructure: prepared ? Object.freeze([]) : null,
    validationInfrastructureFingerprint: prepared
      ? EMPTY_INFRASTRUCTURE_FINGERPRINT
      : null,
    validationMigrationPending,
    finalizationResult,
    finalizedFingerprint: keepLegacyGate
      ? current.finalizedFingerprint
      : null,
    reviewResult:
      reviewedFingerprint === null
        ? null
        : Object.freeze({
            status: current.findings.length === 0 ? "APPROVED" : "FINDINGS",
            validationChange: "UNCHANGED",
            validationEvidence: Object.freeze([]),
            fingerprint: reviewedFingerprint,
          }),
    reviewedFingerprint,
    findings: keepLegacyGate ? current.findings : Object.freeze([]),
    pendingDisputes: keepLegacyGate
      ? current.pendingDisputes
      : Object.freeze([]),
    reviewReconsideration: keepLegacyGate
      ? current.reviewReconsideration
      : Object.freeze([]),
    pendingCommit:
      immutableTerminal || paused || commitVerificationPending
        ? current.pendingCommit
        : null,
  });
}

export function migratePlanExecutionStateV2(run) {
  const current = run.pipelineState;
  return Object.freeze({
    ...current,
    pendingCommit:
      current.pendingCommit === null
        ? null
        : Object.freeze({
            ...current.pendingCommit,
            preEffectRejection: null,
          }),
  });
}

export const planExecutionPipeline = Object.freeze({
  id: PLAN_EXECUTION_PIPELINE_ID,
  stateVersion: 3,
  migrations: Object.freeze({
    1: migratePlanExecutionStateV1,
    2: migratePlanExecutionStateV2,
  }),
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
