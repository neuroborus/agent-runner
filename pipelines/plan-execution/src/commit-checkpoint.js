import { parseCommitPlan } from "@agent-runner/commit-plan";
import { clearedCandidateAndTerminalGate } from "./gate-evidence.js";
import { createFinalizationRecovery } from "./workflow-contract.js";

// Selected steps remain targets while suspended; terminal acceptance is state-owned.
export function resolveStopBoundary(run) {
  const current = run.pipelineState;
  if (
    !Number.isSafeInteger(current.currentStep) ||
    current.currentStep < 1 ||
    current.resolvedSummary === null ||
    ["CLARIFY", "BOOTSTRAP"].includes(current.workflowState) ||
    current.repositoryBaseline === null ||
    current.currentStep > parseCommitPlan(current.canonicalPlan).steps.length
  )
    return null;
  return {
    capability: "verified-commit-v1",
    step: current.currentStep,
    completedCommits: current.completedCommits.length,
    baselineHead: current.repositoryBaseline.head,
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
  const stepCount = parseCommitPlan(current.canonicalPlan).steps.length;
  const done = current.currentStep === stepCount;
  const nextStepState = done
    ? {}
    : {
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
        ...pipelineState,
        finalizationRecovery: createFinalizationRecovery(),
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
      counters: done
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
