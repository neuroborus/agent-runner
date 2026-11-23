import { isDeepStrictEqual } from "node:util";

import { effectivePlanAuthority } from "./plan-position.js";
import { clearedCandidateAndTerminalGate } from "./gate-evidence.js";
import {
  commitModelSelectionConstraint,
  commitReadinessConstraint,
  createFinalizationRecovery,
  isCommitCatalogRejectionProof,
} from "./workflow-contract.js";
import { scheduledChecks } from "./validation-schedule.js";
import { retainReplacementFindingAccounting } from "./replacement-findings.js";

// Legacy pauses can carry the native code instead of the normalized class.
export function isCatalogCommitRejection(value) {
  return (
    value?.code === "ERR_CODEX_MODEL_UNAVAILABLE" ||
    value?.adapterCode === "ERR_CODEX_MODEL_UNAVAILABLE" ||
    value?.diagnosticClass === "model_unavailable"
  );
}

export function isNonRetryableCommitRejection(value) {
  return (
    isNonRetryableCommitModelRejection(value) ||
    commitReadinessConstraint(value?.diagnosticClass) !== null
  );
}

export function isNonRetryableCommitModelRejection(value) {
  return (
    isCatalogCommitRejection(value) ||
    commitModelSelectionConstraint(value?.diagnosticClass) !== null
  );
}

function sameCommitCatalogScope(before, after) {
  return (
    before.currentStep === after.currentStep &&
    before.reviewedFingerprint === after.reviewedFingerprint &&
    [
      "canonicalPlan",
      "effectivePlanRevisions",
      "completedCommits",
      "repositoryBaseline",
    ].every((field) => isDeepStrictEqual(before[field], after[field]))
  );
}

export function matchesCommitCatalogReservation(previous, next, binding) {
  if (!binding.checkpoint.startsWith("commit:")) return undefined;

  const before = previous.pipelineState;
  const after = next.pipelineState;
  if (
    binding.role !== "worker" ||
    binding.resumeState !== "COMMIT" ||
    !Number.isSafeInteger(before.currentStep) ||
    before.currentStep < 1 ||
    binding.checkpoint !== `commit:${before.currentStep}` ||
    !sameCommitCatalogScope(before, after)
  )
    return false;

  const pending = before.pendingCommit;
  const nextPending = after.pendingCommit;
  // Bind dispatch to the authorization that preparation and consumption recorded.
  if (next.activeTurn !== null)
    return (
      pending?.status === "consumed" &&
      pending.preEffectRejection === null &&
      isDeepStrictEqual(before, after)
    );
  return (
    isDeepStrictEqual(pending, nextPending) ||
    (pending === null &&
      nextPending?.status === "prepared" &&
      nextPending.preEffectRejection === null) ||
    (pending?.status === "prepared" &&
      isDeepStrictEqual(nextPending, { ...pending, status: "consumed" }))
  );
}

// Only the latest provider attempt of the turn started for this consumed
// authorization can carry its rejection; earlier receipts prove nothing. The
// journaled proof must repeat the normalized pre-executor failure that the
// Runner recorded on that attempt when it failed.
function hasFailedCommitAttempt(previous, before, turnStart, proof) {
  const attempt = previous.observations?.attempts.at(-1);
  return (
    turnStart != null &&
    isDeepStrictEqual(
      turnStart.pipelineState?.pendingCommit,
      before.pendingCommit,
    ) &&
    previous.preparation === null &&
    previous.executionProcess === null &&
    previous.executionResource === null &&
    attempt?.status === "failed" &&
    attempt.role === "worker" &&
    attempt.checkpoint === `commit:${before.currentStep}` &&
    attempt.id > turnStart.previousRevision + 1 &&
    isDeepStrictEqual(attempt.commitRejection, {
      failureClass: "model_unavailable",
      checkpoint: "commit",
      outcome: "rejected",
      effect: "none",
      retry: "terminal",
      commitExecutor: "not_started",
    }) &&
    isDeepStrictEqual(proof, {
      attemptId: attempt.id,
      failure: attempt.commitRejection,
    })
  );
}

export function assertCatalogCommitTransition(
  previous,
  next,
  activity,
  retryCode,
  turnStart,
  commitRejection,
) {
  const before = previous.pipelineState;
  const after = next.pipelineState;
  const pending = before.pendingCommit;
  const nextPending = after.pendingCommit;
  const recorded = Object.hasOwn(previous.modelCompletionReceipts, "worker");
  const commitTurn = { role: "worker", phase: "commit" };
  const commitActivity =
    activity?.actor === "runner" && activity.phase === "commit";

  if (
    commitRejection !== undefined &&
    nextPending?.preEffectRejection?.catalog === undefined
  )
    throw new Error("Catalog COMMIT proof has no recorded rejection.");
  if (nextPending?.preEffectRejection?.catalog !== undefined) {
    const retainedProof =
      commitRejection === undefined &&
      isDeepStrictEqual(pending, nextPending) &&
      sameCommitCatalogScope(before, after);
    // Publish the rejection against the active turn before retiring it.
    const recordedProof =
      before.workflowState === "COMMIT" &&
      pending?.status === "consumed" &&
      pending.preEffectRejection === null &&
      isCommitCatalogRejectionProof(nextPending.preEffectRejection) &&
      isDeepStrictEqual(after, {
        ...before,
        pendingCommit: {
          ...pending,
          preEffectRejection: nextPending.preEffectRejection,
        },
      }) &&
      isDeepStrictEqual(previous.activeTurn, commitTurn) &&
      isDeepStrictEqual(next.activeTurn, commitTurn) &&
      hasFailedCommitAttempt(previous, before, turnStart, commitRejection) &&
      commitActivity &&
      activity.kind === "pre-effect-rejection-recorded";
    if (!recorded || !(retainedProof || recordedProof))
      throw new Error(
        "Catalog rejection proof is not bound to a consumed COMMIT turn.",
      );
  }

  const pause = next.pause?.operatorResume?.pause ?? next.pause;
  if (
    pause?.code !== retryCode ||
    (pause.resumeState !== "COMMIT" && !pause.checkpoint?.startsWith("commit:"))
  )
    return;

  const priorPause = previous.pause?.operatorResume?.pause ?? previous.pause;
  const retained = pending === null && isDeepStrictEqual(pause, priorPause);
  // Both activities follow unchanged Git verification. Stop settlement can
  // retire the active turn and publish the verified pause in one event.
  const ordinaryRetirement =
    before.workflowState === "COMMIT" &&
    previous.activeTurn === null &&
    next.pause === pause &&
    commitActivity &&
    activity.kind === "authorization-retired";
  const stopRetirement =
    (before.workflowState === "COMMIT" ||
      (before.workflowState === "WAITING_FOR_USER" &&
        priorPause?.reason === "commit_failed")) &&
    (previous.activeTurn === null ||
      isDeepStrictEqual(previous.activeTurn, commitTurn)) &&
    previous.stopRequest != null &&
    previous.stopRequest.reconciledRevision === null &&
    next.stopRequest?.reconciledRevision === next.revision &&
    next.pause?.operatorResume?.pause === pause &&
    activity?.actor === "runner" &&
    activity.phase === "stop" &&
    activity.kind === "reconciled";
  const retired =
    pending?.status === "consumed" &&
    isCommitCatalogRejectionProof(pending.preEffectRejection) &&
    (ordinaryRetirement || stopRetirement);
  if (
    !recorded ||
    pause.reason !== "backend_unavailable" ||
    pause.role !== "worker" ||
    pause.resumeState !== "COMMIT" ||
    (next.pause.operatorResume?.workflowState ?? after.workflowState) !==
      "WAITING_FOR_USER" ||
    !Number.isSafeInteger(before.currentStep) ||
    before.currentStep < 1 ||
    pause.checkpoint !== `commit:${before.currentStep}` ||
    next.activeTurn !== null ||
    nextPending !== null ||
    !isDeepStrictEqual(after, {
      ...before,
      workflowState: after.workflowState,
      pendingCommit: null,
    }) ||
    !(retained || retired)
  )
    throw new Error(
      "Catalog COMMIT pause has no verified authorization retirement.",
    );
  return true;
}

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
