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
  EMPTY_TRUSTED_VALIDATION,
  isFinalizationPolicy,
  sha256,
} from "./workflow-contract.js";

export {
  BOOTSTRAP_ARBITRATION_INSTRUCTIONS,
  BOOTSTRAP_CORRECTION_INSTRUCTIONS,
  BOOTSTRAP_INSTRUCTIONS,
  BOOTSTRAP_RECONCILIATION_INSTRUCTIONS,
  CLARIFICATION_INSTRUCTIONS,
  COMMIT_INSTRUCTIONS,
  DISPUTE_RECONSIDERATION_INSTRUCTIONS,
  FINALIZATION_CORRECTION_INSTRUCTIONS,
  FINALIZATION_INSTRUCTIONS,
  finalizationBootstrapInstructions,
  finalizationGuidanceInstructions,
  FINDING_ARBITRATION_INSTRUCTIONS,
  FINDING_RESOLUTION_INSTRUCTIONS,
  IMPLEMENTATION_INSTRUCTIONS,
  NO_DELEGATION_INSTRUCTIONS,
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

function trustedCheckSelection(value) {
  return (
    Array.isArray(value) &&
    value.length <= 32 &&
    new Set(value).size === value.length &&
    value.every(
      (alias) =>
        typeof alias === "string" && /^[a-z][a-z0-9-]{0,63}$/u.test(alias),
    )
  );
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
  trustedChecks: Object.freeze({
    defaultValue: Object.freeze([]),
    errorMessage:
      "must be an array of unique trusted command aliases",
    validate: trustedCheckSelection,
  }),
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
const PUBLIC_PAUSE_EXPLANATIONS = Object.freeze({
  arbiter_cannot_resolve:
    "The Arbiter could not resolve the current blocking dispute.",
  backend_unavailable: "The selected backend is temporarily unavailable.",
  bootstrap_inventory_capacity_exhausted:
    "A complete bootstrap validation inventory exceeds the supported bounded capacity.",
  clarification_answers_required:
    "Material clarification answers are required before execution can continue.",
  clarification_limit_reached:
    "Clarification reached its configured question-round limit.",
  clarifications_changed:
    "The execution clarification artifact changed outside an authorized editor window.",
  commit_contract_violated:
    "The attempted commit did not satisfy its one-shot authorization contract.",
  commit_failed: "The authorized commit could not be verified as complete.",
  dispute_limit_reached:
    "A finding reached its configured dispute limit.",
  environment_blocked:
    "Required validation is blocked by the execution environment.",
  finalization_cannot_pass:
    "The current finalization procedure cannot establish a passing gate.",
  finalization_skill_invalid:
    "The explicitly configured finalization skill is invalid.",
  finalization_skill_missing:
    "The explicitly configured finalization skill is missing.",
  fix_limit_reached: "The current step reached its configured fix limit.",
  internal_failure: "Plan execution failed.",
  local_artifacts_not_ignored:
    "The configured repository-local artifact path is not ignored.",
  no_progress: "The correction loop reached a bounded no-progress condition.",
  plan_revision_required:
    "The validated plan must be revised and execution must restart in a fresh run.",
  proactive_clarification:
    "Optional proactive execution clarification input is pending.",
  product_decision_required:
    "A material product decision is required before execution can continue.",
  read_only_agent_mutated_repository:
    "A read-only turn contaminated the repository; abandon this run and restart from an uncontaminated worktree.",
  task_input_changed: "A task or plan input changed after the run began.",
  unexpected_git_identity_change:
    "The effective Git identity changed during execution.",
  unexpected_git_ref_change:
    "Git history or refs changed outside the authorized commit turn.",
  unexpected_remote_configuration_change:
    "Git remote configuration changed during execution.",
  unsafe_git_state:
    "The repository is not at a state that can be reconciled safely.",
});
const PUBLIC_DETAIL_REASONS = new Set([
  "environment_blocked",
  "bootstrap_inventory_capacity_exhausted",
  "finalization_cannot_pass",
  "finalization_skill_invalid",
  "finalization_skill_missing",
  "plan_revision_required",
]);

function publicCode(value) {
  return typeof value === "string" && /^[A-Z0-9_]{1,64}$/u.test(value)
    ? value
    : null;
}

function publicResumeState(run) {
  return run.pipelineState.workflowState === "WAITING_FOR_USER" &&
    WORKFLOW_STATES.includes(run.pause.resumeState)
    ? run.pause.resumeState
    : null;
}

function publicExplanation(pause, fallback) {
  if (
    pause.reason === "internal_failure" &&
    typeof pause.diagnosticClass === "string" &&
    /^[a-z][a-z0-9_]{0,63}$/u.test(pause.diagnosticClass)
  ) {
    return `${fallback} Adapter diagnostic: ${pause.diagnosticClass}.`;
  }
  return PUBLIC_DETAIL_REASONS.has(pause.reason) &&
    typeof pause.explanation === "string" &&
    pause.explanation.length > 0 &&
    [...pause.explanation].length <= 4_000
    ? pause.explanation
    : fallback;
}

function publicEvidence(pause) {
  return Object.freeze(
    PUBLIC_DETAIL_REASONS.has(pause.reason) && Array.isArray(pause.evidence)
      ? pause.evidence
          .filter(
            (entry) =>
              typeof entry === "string" &&
              entry.length > 0 &&
              [...entry].length <= 4_000,
          )
          .slice(0, 32)
      : [],
  );
}

function resumeActionApplies(run, action) {
  try {
    validateResumeAction(run, action);
    return true;
  } catch {
    return false;
  }
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
  const nextActions = [];
  if (
    run.pipelineState.workflowState === "WAITING_FOR_USER" &&
    run.pause.inputRequest !== undefined &&
    run.pause.inputResponse === undefined
  ) {
    nextActions.push(
      Object.freeze({
        type: "respond",
        requestId: run.pause.inputRequest.id,
      }),
    );
  } else if (
    run.pipelineState.workflowState === "WAITING_FOR_USER" &&
    run.pause.inputResponse === undefined
  ) {
    if (run.pause.reason === "plan_revision_required") {
      nextActions.push(
        Object.freeze({ type: "start-new-run", requirement: "revised-plan" }),
      );
    } else if (run.pause.reason === "read_only_agent_mutated_repository") {
      nextActions.push(
        Object.freeze({
          type: "start-new-run",
          requirement: "uncontaminated-worktree",
        }),
      );
    } else {
      if (resumeActionApplies(run, null)) {
        nextActions.push(Object.freeze({ type: "resume", action: null }));
      }
      const extraFixRounds = Object.freeze({
        type: "extra-fix-rounds",
        amount: 1,
      });
      if (resumeActionApplies(run, extraFixRounds)) {
        nextActions.push(
          Object.freeze({ type: "resume", action: extraFixRounds }),
        );
      }
      for (const finding of Array.isArray(run.pipelineState.findings)
        ? run.pipelineState.findings
        : []) {
        const override = Object.freeze({
          type: "override-finding",
          findingId: finding.id,
        });
        if (resumeActionApplies(run, override)) {
          nextActions.push(
            Object.freeze({ type: "resume", action: override }),
          );
        }
      }
    }
  }
  return Object.freeze({
    reason,
    code: knownReason ? publicCode(run.pause.code) : null,
    explanation: publicExplanation(run.pause, explanation),
    evidence: publicEvidence(run.pause),
    resumeState: publicResumeState(run),
    nextActions: Object.freeze(nextActions),
  });
}

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
  if (
    action === null &&
    state.validationMigrationPending &&
    state.preflightComplete &&
    ["fix_limit_reached", "no_progress", "dispute_limit_reached"].includes(
      run.pause?.reason,
    )
  ) {
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
      !state.findings?.some(({ id }) => id === action.findingId) ||
      state.findingOverrides.some(
        ({ findingId, fingerprint }) =>
          findingId === action.findingId &&
          fingerprint === state.reviewedFingerprint,
      )
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

export function migratePlanExecutionStateV3(run) {
  return Object.freeze({
    ...run.pipelineState,
    bootstrapCorrections: Object.freeze([]),
    pendingBootstrapCorrection: null,
  });
}

function upgradedTrustedFinalization(result) {
  if (result === null) {
    return null;
  }
  return Object.freeze({
    ...result,
    checks: Object.freeze(
      result.checks.map((check) =>
        Object.freeze({
          ...check,
          executor: "agent",
          commandIdentity: null,
          exitCode: null,
          signal: null,
          timedOut: false,
        }),
      ),
    ),
    trustedCommandFingerprint:
      EMPTY_TRUSTED_VALIDATION.commandFingerprint,
    trustedConfigurationFingerprint:
      EMPTY_TRUSTED_VALIDATION.configurationFingerprint,
  });
}

export function migratePlanExecutionStateV4(run) {
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
  const reviewedFingerprint = keepLegacyGate
    ? current.reviewedFingerprint
    : null;
  return Object.freeze({
    ...current,
    settings:
      current.settings === null
        ? null
        : Object.freeze({
            ...current.settings,
            trustedChecks: Object.freeze([]),
          }),
    trustedValidation: EMPTY_TRUSTED_VALIDATION,
    workflowState: rerunFinalization ? "FINALIZE" : current.workflowState,
    workerValidation: validationMigrationPending
      ? null
      : current.workerValidation,
    reviewerValidation: validationMigrationPending
      ? null
      : current.reviewerValidation,
    validationMigrationPending,
    finalizationResult: keepLegacyGate
      ? upgradedTrustedFinalization(current.finalizationResult)
      : null,
    finalizedFingerprint: keepLegacyGate
      ? current.finalizedFingerprint
      : null,
    reviewResult: keepLegacyGate ? current.reviewResult : null,
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

export function migratePlanExecutionStateV5(run) {
  const current = run.pipelineState;
  const immutableTerminal = ["DONE", "FAILED"].includes(
    current.workflowState,
  );
  const resumeState = run.pause?.resumeState;
  const checkpoint =
    current.workflowState === "WAITING_FOR_USER" &&
    WORKFLOW_STATES.includes(resumeState)
      ? resumeState
      : current.workflowState;
  if (immutableTerminal || !current.preflightComplete) {
    return Object.freeze({ ...current });
  }
  const unfinishedBootstrap =
    checkpoint === "BOOTSTRAP" ||
    (current.workflowState === "WAITING_FOR_USER" &&
      current.currentStep === null &&
      (current.workerSummary !== null ||
        current.reviewerSummary !== null ||
        current.pendingEdit?.suspendedState === "BOOTSTRAP" ||
        run.pause?.reason === "bootstrap_inventory_capacity_exhausted"));
  if (unfinishedBootstrap) {
    return Object.freeze({
      ...current,
      workerSummary: null,
      reviewerSummary: null,
      workerValidation: null,
      reviewerValidation: null,
      resolvedSummary: null,
      bootstrapDisagreement: null,
      bootstrapArbitrationUsed: false,
      requiredChecks: null,
      validationInfrastructure: null,
      validationInfrastructureFingerprint: null,
      validationMigrationPending: false,
      finalizationResult: null,
      finalizedFingerprint: null,
      reviewResult: null,
      reviewedFingerprint: null,
      findings: Object.freeze([]),
      previousFindings: Object.freeze([]),
      pendingDisputes: Object.freeze([]),
      reviewReconsideration: Object.freeze([]),
      pendingCommit: null,
    });
  }
  const prepared = current.resolvedSummary !== null;
  if (!prepared || checkpoint === "CLARIFY") {
    return Object.freeze({ ...current });
  }
  const commitVerificationPending =
    current.pendingCommit?.status === "consumed";
  if (commitVerificationPending) {
    return Object.freeze({
      ...current,
      validationMigrationPending: true,
    });
  }
  const paused = current.workflowState === "WAITING_FOR_USER";
  const rerunFinalization =
    !paused &&
    ["FINALIZE", "REVIEW", "RESOLVE_FINDINGS", "COMMIT"].includes(
      current.workflowState,
    );
  const keepProvisionalGate = paused;
  return Object.freeze({
    ...current,
    workflowState: rerunFinalization ? "FINALIZE" : current.workflowState,
    workerValidation: null,
    reviewerValidation: null,
    validationMigrationPending: true,
    finalizationResult: keepProvisionalGate
      ? current.finalizationResult
      : null,
    finalizedFingerprint: keepProvisionalGate
      ? current.finalizedFingerprint
      : null,
    reviewResult: keepProvisionalGate ? current.reviewResult : null,
    reviewedFingerprint: keepProvisionalGate
      ? current.reviewedFingerprint
      : null,
    previousFindings: keepProvisionalGate
      ? current.previousFindings
      : current.findings.length === 0
        ? current.previousFindings
        : current.findings,
    findings: keepProvisionalGate
      ? current.findings
      : Object.freeze([]),
    pendingDisputes: keepProvisionalGate
      ? current.pendingDisputes
      : Object.freeze([]),
    reviewReconsideration: keepProvisionalGate
      ? current.reviewReconsideration
      : Object.freeze([]),
    pendingCommit: null,
  });
}

export function migratePlanExecutionStateV6(run) {
  return Object.freeze({
    ...run.pipelineState,
    finalizationCorrection: null,
    pendingFinalizationCorrection: null,
  });
}

function upgradeFinalizationCorrection(correction) {
  if (correction === null) {
    return null;
  }
  const { role, phase, contract, field, constraint, ...scope } = correction;
  return Object.freeze({
    ...scope,
    diagnostics: Object.freeze([
      Object.freeze({ role, phase, contract, field, constraint }),
    ]),
  });
}

export function migratePlanExecutionStateV7(run) {
  const {
    finalizationCorrection,
    pendingFinalizationCorrection,
    ...current
  } = run.pipelineState;
  const correction = upgradeFinalizationCorrection(finalizationCorrection);
  return Object.freeze({
    ...current,
    finalizationCorrections: Object.freeze(
      correction === null ? [] : [correction],
    ),
    pendingFinalizationCorrection: upgradeFinalizationCorrection(
      pendingFinalizationCorrection,
    ),
  });
}

function uniqueFindingOverrides(overrides) {
  const identities = new Set();
  return Object.freeze(
    overrides.filter(({ findingId, fingerprint }) => {
      const identity = `${findingId}\0${fingerprint}`;
      if (identities.has(identity)) {
        return false;
      }
      identities.add(identity);
      return true;
    }),
  );
}

export function migratePlanExecutionStateV8(run) {
  const current = run.pipelineState;
  const findingOverrides = uniqueFindingOverrides(current.findingOverrides);
  const immutableTerminal = ["DONE", "FAILED"].includes(
    current.workflowState,
  );
  if (
    immutableTerminal ||
    !current.preflightComplete ||
    current.resolvedSummary === null
  ) {
    return Object.freeze({ ...current, findingOverrides });
  }
  const commitVerificationPending =
    current.pendingCommit?.status === "consumed";
  if (commitVerificationPending) {
    return Object.freeze({
      ...current,
      findingOverrides,
      validationMigrationPending: true,
    });
  }
  const paused = current.workflowState === "WAITING_FOR_USER";
  const rerunFinalization =
    !paused &&
    ["FINALIZE", "REVIEW", "RESOLVE_FINDINGS", "COMMIT"].includes(
      current.workflowState,
    );
  return Object.freeze({
    ...current,
    workflowState: rerunFinalization ? "FINALIZE" : current.workflowState,
    workerValidation: null,
    reviewerValidation: null,
    validationMigrationPending: true,
    finalizationResult: paused ? current.finalizationResult : null,
    finalizedFingerprint: paused ? current.finalizedFingerprint : null,
    reviewResult: paused ? current.reviewResult : null,
    reviewedFingerprint: paused ? current.reviewedFingerprint : null,
    previousFindings: paused
      ? current.previousFindings
      : current.findings.length === 0
        ? current.previousFindings
        : current.findings,
    findings: paused ? current.findings : Object.freeze([]),
    pendingDisputes: paused
      ? current.pendingDisputes
      : Object.freeze([]),
    reviewReconsideration: paused
      ? current.reviewReconsideration
      : Object.freeze([]),
    findingOverrides,
    pendingCommit: null,
  });
}

function upgradeBootstrapCorrection(correction) {
  if (correction === null) {
    return null;
  }
  const { attempt, ...diagnostic } = correction;
  return Object.freeze({
    attempt,
    diagnostics: Object.freeze([Object.freeze(diagnostic)]),
  });
}

export function migratePlanExecutionStateV9(run) {
  const current = run.pipelineState;
  return Object.freeze({
    ...current,
    bootstrapCorrections: Object.freeze(
      current.bootstrapCorrections.map(upgradeBootstrapCorrection),
    ),
    pendingBootstrapCorrection: upgradeBootstrapCorrection(
      current.pendingBootstrapCorrection,
    ),
  });
}

export const planExecutionPipeline = Object.freeze({
  id: PLAN_EXECUTION_PIPELINE_ID,
  stateVersion: 10,
  migrations: Object.freeze({
    1: migratePlanExecutionStateV1,
    2: migratePlanExecutionStateV2,
    3: migratePlanExecutionStateV3,
    4: migratePlanExecutionStateV4,
    5: migratePlanExecutionStateV5,
    6: migratePlanExecutionStateV6,
    7: migratePlanExecutionStateV7,
    8: migratePlanExecutionStateV8,
    9: migratePlanExecutionStateV9,
  }),
  roles: ROLES,
  settings: SETTINGS,
  taskInputs: TASK_INPUTS,
  runOptions: Object.freeze(["project", "task", ...ROLES]),
  requiredRunOptions: Object.freeze(["project", "task"]),
  description: "Execute, finalize, review, and commit each step of a commit plan.",
  projections: Object.freeze({
    clarification: projectClarification,
    pause: projectPause,
    status: projectStatus,
  }),
  validateResumeAction,
  workflow: Object.freeze({
    createState: createPlanExecutionState,
    run: runPlanExecution,
    validateRun,
  }),
});
