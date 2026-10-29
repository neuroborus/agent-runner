import { isDeepStrictEqual } from "node:util";

import { effectivePlanAuthority } from "./plan-position.js";
import { clearedCandidateAndTerminalGate } from "./gate-evidence.js";
import { createFinalizationRecovery } from "./workflow-contract.js";
import { scheduledChecks } from "./validation-schedule.js";
import { retainReplacementFindingAccounting } from "./replacement-findings.js";

// The journal checkpoint, not only the current workflow label, proves that
// this stop preceded repository, artifact, and execution ownership.
export function classifyStopCheckpoint(run, checkpoint) {
  const stop = run.stopRequest;
  if (
    stop == null ||
    stop.reconciledRevision !== null ||
    stop.effectiveTiming !== "immediate" ||
    checkpoint == null ||
    checkpoint.runId !== run.runId ||
    checkpoint.revision !== stop.checkpoint.revision ||
    checkpoint.stopRequest !== null ||
    !isDeepStrictEqual(run.pipelineState, checkpoint.pipelineState)
  )
    return null;

  for (const inspected of [checkpoint, run]) {
    const state = inspected.pipelineState;
    if (
      inspected.pipelineId !== "plan-execution" ||
      inspected.pause !== null ||
      inspected.activeTurn !== null ||
      inspected.preparation != null ||
      inspected.executionProcess !== null ||
      inspected.executionResource !== null ||
      Object.keys(inspected.hashes).length !== 0 ||
      state.workflowState !== "CLARIFY" ||
      state.preflightComplete !== false ||
      state.repositoryBaseline !== null ||
      state.backendVersions !== null ||
      state.clarificationPath !== null ||
      state.clarificationFrozen !== false ||
      state.pendingEdit !== null ||
      state.canonicalPlan !== null ||
      state.currentStep !== null ||
      state.pendingCommit !== null ||
      state.completedCommits.length !== 0
    )
      return null;
  }
  return "pre-work";
}

// Selected steps remain targets while suspended; terminal acceptance is state-owned.
export function resolveStopBoundary(run) {
  const current = run.pipelineState;
  if (current.planKind === "custom") return null;
  if (
    !Number.isSafeInteger(current.currentStep) ||
    current.currentStep < 1 ||
    current.resolvedSummary === null ||
    ["CLARIFY", "BOOTSTRAP"].includes(current.workflowState) ||
    current.repositoryBaseline === null ||
    current.currentStep > effectivePlanAuthority(current).steps.length
  )
    return null;
  const mapping = effectivePlanAuthority(current).mapping;
  const originalStep = mapping[current.currentStep - 1].originalStep;
  const start = mapping.findIndex(
    (entry) => entry.originalStep === originalStep,
  );
  const firstRevision = current.effectivePlanRevisions?.revisions.find(
    (entry) => entry.accepted && entry.originalStep === originalStep,
  );
  return {
    capability: "verified-commit-v1",
    step: originalStep,
    completedCommits: start,
    baselineHead:
      start > 0
        ? current.completedCommits[start - 1]
        : firstRevision
          ? firstRevision.binding.assessment.baseHead
          : current.repositoryBaseline.head,
  };
}

// Construct progress only after the consumed effect and its clean baseline verify.
export function verifiedCommitCheckpoint({
  current,
  counters,
  hashes,
  pause,
  verified,
  nextRepositoryBaseline,
  configurationChanged,
}) {
  const completedCommits = [...current.completedCommits, verified.head];
  const stepCount = effectivePlanAuthority(current).steps.length;
  const done = current.currentStep === stepCount;
  const mapping = effectivePlanAuthority(current).mapping;
  const sameLineage =
    !done &&
    mapping[current.currentStep].originalStep ===
      mapping[current.currentStep - 1].originalStep;
  const nextStepState = done
    ? {}
    : {
        ...(current.validationScopeLegacy
          ? {}
          : {
              requiredChecks: scheduledChecks(current, current.currentStep + 1),
              validationAmendment: null,
            }),
        implementationDirection: null,
        ...clearedCandidateAndTerminalGate(),
        findings: [],
        previousFindings: [],
        pendingDisputes: [],
        disputeCounts: {},
        disputeHistory: [],
        findingArbitrations: [],
        correctionHistory: [],
        sameFindingRounds: {},
        pendingCorrection: false,
        blockedSinceStagnation: 0,
        stagnationArbitrationUsed: false,
        stagnationDirection: null,
        reviewReconsideration: [],
        additionalFixRounds: 0,
        findingOverrides: [],
      };
  const pipelineState = {
    ...current,
    ...nextStepState,
    ...(sameLineage
      ? Object.fromEntries(
          [
            "correctionHistory",
            "blockedSinceStagnation",
            "stagnationArbitrationUsed",
            "stagnationDirection",
            "additionalFixRounds",
          ].map((field) => [field, current[field]]),
        )
      : {}),
    workflowState: configurationChanged
      ? "WAITING_FOR_USER"
      : done
        ? "DONE"
        : "IMPLEMENT",
    validationMigrationPending: done
      ? false
      : current.validationMigrationPending,
    repositoryBaseline: nextRepositoryBaseline,
    currentStep: done ? null : current.currentStep + 1,
    reviewerStep: null,
    finalizationCorrections: [],
    pendingFinalizationCorrection: null,
    reviewCorrection: null,
    pendingReviewCorrection: null,
    confirmationCorrection: null,
    pendingConfirmationCorrection: null,
    lazyCorrections: [],
    pendingLazyCorrection: null,
    pendingCommit: null,
    completedCommits,
    stepImplementation: null,
    implementationEvidenceLegacy: false,
  };
  return {
    patch: {
      pipelineState: {
        ...retainReplacementFindingAccounting(current, pipelineState),
        finalizationRecovery: sameLineage
          ? { ...current.finalizationRecovery, pending: false, feedback: null }
          : createFinalizationRecovery(),
      },
      activeTurn: null,
      hashes,
      // Successful verification resolves a prior failure to observe this effect.
      pause: ["commit_failed", "commit_contract_violated"].includes(
        pause?.reason,
      )
        ? null
        : pause,
      ...(configurationChanged
        ? {
            pause: {
              reason: "project_configuration_changed",
              code: "ERR_PROJECT_CONFIGURATION_CHANGED",
            },
          }
        : {}),
      counters:
        done || sameLineage
          ? counters
          : {
              ...counters,
              fixRounds: 0,
              correctionRounds: 0,
            },
    },
    activity: activity(
      configurationChanged ? "runner" : "worker",
      "commit",
      configurationChanged ? "configuration-changed" : "created",
      configurationChanged
        ? `Commit ${current.currentStep} was verified before project configuration drift stopped the run.`
        : `Commit ${current.currentStep} created: ${verified.head}.`,
    ),
  };
}

function activity(actor, phase, kind, message) {
  return { actor, phase, kind, message };
}
