import { executionPolicy } from "./mode-policy.js";

// These predicates consume normalized state, not provider output. Candidate
// evidence names the inspected content; finalization may format that content
// before the separate terminal confirmation approves the resulting fingerprint.
function hasFingerprint(value) {
  return typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
}

function overridden(overrides, id, fingerprint) {
  return overrides.some(
    (entry) => entry.findingId === id && entry.fingerprint === fingerprint,
  );
}

function candidateEvidenceBound(
  state,
  fingerprint = state.candidateReviewedFingerprint,
) {
  return (
    hasFingerprint(fingerprint) &&
    state.candidateReviewedFingerprint === fingerprint &&
    state.candidateReviewResult?.fingerprint === fingerprint
  );
}

function primaryCleanGatePassed(
  state,
  fingerprint = state.candidateReviewedFingerprint,
) {
  return (
    candidateEvidenceBound(state, fingerprint) &&
    state.candidateReviewResult.status === "APPROVED" &&
    state.candidateConfirmationFingerprint === fingerprint
  );
}

function independentCandidateGatePassed(
  state,
  fingerprint = state.candidateReviewedFingerprint,
) {
  if (!candidateEvidenceBound(state, fingerprint)) return false;
  const result = state.candidateReviewResult;
  return (
    result.status === "APPROVED" ||
    (result.status === "FINDINGS" &&
      result.findingIds.length > 0 &&
      result.findingIds.every((id) =>
        overridden(state.findingOverrides, id, fingerprint),
      ))
  );
}

export function candidateGatePassed(
  state,
  fingerprint = state.candidateReviewedFingerprint,
) {
  const policy = executionPolicy(state.settings);
  return (
    candidateEvidenceBound(state, fingerprint) &&
    (!policy.primaryConvergence ||
      primaryCleanGatePassed(state, fingerprint)) &&
    (!policy.independentReview ||
      independentCandidateGatePassed(state, fingerprint))
  );
}

export function finalizationGatePassed(
  state,
  fingerprint = state.finalizedFingerprint,
) {
  return (
    hasFingerprint(fingerprint) &&
    state.finalizationResult?.status === "PASS" &&
    state.finalizedFingerprint === fingerprint &&
    state.finalizationResult.fingerprint === fingerprint
  );
}

function terminalConfirmationGatePassed(
  state,
  fingerprint = state.finalizedFingerprint,
) {
  if (
    !finalizationGatePassed(state, fingerprint) ||
    state.reviewedFingerprint !== fingerprint ||
    state.reviewResult?.fingerprint !== fingerprint ||
    state.findings.length !== 0
  )
    return false;
  if (
    executionPolicy(state.settings).terminalConfirmer === "worker" &&
    (state.cleanConfirmationFingerprint !== fingerprint ||
      state.reviewResult.status !== "APPROVED")
  )
    return false;
  if (["UNCHANGED", "ACCEPTED"].includes(state.reviewResult.validationChange))
    return true;
  return (
    state.reviewResult.validationChange === "REJECTED" &&
    state.previousFindings.length > 0 &&
    state.previousFindings.every(({ id }) =>
      overridden(state.findingOverrides, id, fingerprint),
    )
  );
}

export function commitGatePassed(
  state,
  fingerprint = state.finalizedFingerprint,
) {
  return (
    candidateGatePassed(state) &&
    terminalConfirmationGatePassed(state, fingerprint) &&
    state.pendingDisputes.length === 0 &&
    state.reviewReconsideration.length === 0
  );
}

export function clearedConfirmationGate() {
  return {
    confirmationCorrection: null,
    pendingConfirmationCorrection: null,
    cleanConfirmationFingerprint: null,
    reviewResult: null,
    reviewedFingerprint: null,
  };
}

export function clearedTerminalGate() {
  return {
    ...clearedConfirmationGate(),
    finalizationResult: null,
    finalizedFingerprint: null,
  };
}

function clearedCandidateGate() {
  return {
    reviewCorrection: null,
    pendingReviewCorrection: null,
    candidateReviewResult: null,
    candidateReviewedFingerprint: null,
    candidateConfirmationFingerprint: null,
    candidateMigrationPending: false,
  };
}

export function clearedCandidateAndTerminalGate() {
  return {
    ...clearedCandidateGate(),
    ...clearedTerminalGate(),
    lazyCorrections: [],
    pendingLazyCorrection: null,
  };
}

export function clearedCandidateAndConfirmationGate(current) {
  const retainFinalization = finalizationGatePassed(current);
  // Unchanged resolutions must reconverge, but may reuse passing finalization
  // after the live content and infrastructure fingerprints are checked again.
  // Keep the lazy correction ledger: no new mutation resets its bounded scope.
  return {
    ...clearedCandidateGate(),
    ...clearedConfirmationGate(),
    finalizationResult: retainFinalization ? current.finalizationResult : null,
    finalizedFingerprint: retainFinalization
      ? current.finalizedFingerprint
      : null,
  };
}

export function clearedGateAfterResolvedFindings(current) {
  return finalizationGatePassed(current)
    ? clearedCandidateAndConfirmationGate(current)
    : clearedCandidateAndTerminalGate();
}
