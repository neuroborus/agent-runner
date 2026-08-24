import {
  createPolishingState,
  MAX_CLARIFICATION_ROUNDS,
  PolishingWorkflowError,
  runPolishing,
  WORKFLOW_STATES,
} from "./workflow.js";
import {
  assertRun as validateRun,
  DEFAULT_FINALIZATION_POLICY,
  isFinalizationPolicy,
  MAX_DISPUTES_PER_FINDING,
  sha256,
} from "./workflow-contract.js";

export {
  BOOTSTRAP_ARBITRATION_INSTRUCTIONS,
  BOOTSTRAP_INSTRUCTIONS,
  BOOTSTRAP_RECONCILIATION_INSTRUCTIONS,
  CLARIFICATION_INSTRUCTIONS,
  DISPUTE_RECONSIDERATION_INSTRUCTIONS,
  FINALIZATION_INSTRUCTIONS,
  finalizationBootstrapInstructions,
  finalizationGuidanceInstructions,
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
  finalization: Object.freeze({
    defaultValue: DEFAULT_FINALIZATION_POLICY,
    errorMessage:
      "must be auto, none, or a normalized repository-relative SKILL.md path",
    validate: isFinalizationPolicy,
  }),
  maxFixRounds: positiveIntegerSetting(5),
  maxDisputesPerFinding: positiveIntegerSetting(
    2,
    MAX_DISPUTES_PER_FINDING,
  ),
  maxSameFindingRounds: positiveIntegerSetting(3),
  stagnationWindowRounds: positiveIntegerSetting(3),
});
const TASK_INPUTS = Object.freeze({
  task: Object.freeze({ filename: "task.md", optional: false }),
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
]);
const RETRYABLE_PREFLIGHT_PAUSE_REASONS = new Set([
  "local_artifacts_not_ignored",
  "unsafe_git_state",
]);
const RESUMABLE_WORKFLOW_STATES = new Set([
  "CLARIFY",
  "BOOTSTRAP",
  "POLISH",
  "FINALIZE",
  "REVIEW",
  "RESOLVE_FINDINGS",
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
    currentStep: null,
    planPath: null,
    findings: Object.freeze(
      Array.isArray(state.findings)
        ? state.findings.map(({ id, problem }) =>
            Object.freeze({ id, summary: problem }),
          )
        : [],
    ),
    completedCommits: Object.freeze([]),
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
      !["POLISH", "RESOLVE_FINDINGS"].includes(run.pause.resumeState) ||
      !Number.isSafeInteger(additionalFixRounds) ||
      !Number.isSafeInteger(state.settings.maxFixRounds + additionalFixRounds)
    ) {
      throw new Error("Additional fix rounds are not applicable.");
    }
    return;
  }
  if (action?.type === "override-finding") {
    if (
      !["fix_limit_reached", "no_progress"].includes(run.pause?.reason) ||
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
    ((RETRYABLE_PREFLIGHT_PAUSE_REASONS.has(run.pause?.reason) &&
      !state.preflightComplete) ||
      (RETRYABLE_PAUSE_REASONS.has(run.pause?.reason) &&
        (!state.preflightComplete ||
          RESUMABLE_WORKFLOW_STATES.has(run.pause?.resumeState))))
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

export function migratePolishingStateV1(run) {
  const current = run.pipelineState;
  const prepared = current.resolvedSummary !== null;
  const immutableTerminal = current.workflowState === "FAILED";
  const validationMigrationPending = prepared && !immutableTerminal;
  const paused = current.workflowState === "WAITING_FOR_USER";
  const rerunFinalization =
    validationMigrationPending &&
    !paused &&
    current.polishSummary !== null &&
    ["FINALIZE", "REVIEW", "RESOLVE_FINDINGS", "DONE"].includes(
      current.workflowState,
    );
  const keepLegacyGate = immutableTerminal || paused;
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
  });
}

export const polishingPipeline = Object.freeze({
  id: POLISHING_PIPELINE_ID,
  stateVersion: 2,
  migrations: Object.freeze({ 1: migratePolishingStateV1 }),
  roles: ROLES,
  settings: SETTINGS,
  taskInputs: TASK_INPUTS,
  runOptions: Object.freeze(["project", "task", ...ROLES]),
  requiredRunOptions: Object.freeze(["project", "task"]),
  description: "Polish and review an existing dirty worktree without committing it.",
  projections: Object.freeze({
    clarification: projectClarification,
    status: projectStatus,
  }),
  validateResumeAction,
  workflow: Object.freeze({
    createState: createPolishingState,
    run: runPolishing,
    validateRun,
  }),
});
