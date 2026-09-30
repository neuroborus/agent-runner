// Internal decisions derived from the descriptor's supported modes.
const INDEPENDENT = Object.freeze({
  primaryConvergence: false,
  independentReview: true,
  primarySessionScope: "checkpoint",
  arbitration: true,
});
const LAZY = Object.freeze({
  primaryConvergence: true,
  independentReview: false,
  primarySessionScope: "run",
  arbitration: false,
});
const COMBINED = Object.freeze({
  primaryConvergence: true,
  independentReview: true,
  primarySessionScope: "checkpoint",
  arbitration: true,
});

export function authoringPolicy(settings) {
  if (settings?.mode === "combined") return COMBINED;
  return settings?.mode === "lazy" ? LAZY : INDEPENDENT;
}

export function draftCheckpoint(settings) {
  return authoringPolicy(settings).primaryConvergence
    ? "CHECK_AND_FIX"
    : "REVIEW";
}

export function revisionCheckpoint(settings, checkpoint) {
  const policy = authoringPolicy(settings);
  if (policy.independentReview && checkpoint === "REVIEW") return "REVISE";
  return policy.primaryConvergence ? "CHECK_AND_FIX" : "REVISE";
}

export function checkpointAllowed(settings, checkpoint) {
  const policy = authoringPolicy(settings);
  if (["REVIEW", "REVISE"].includes(checkpoint))
    return policy.independentReview;
  if (["CHECK_AND_FIX", "CLEAN_CONFIRM"].includes(checkpoint))
    return policy.primaryConvergence;
  return true;
}

export function invalidateDraftReview() {
  return {
    findings: [],
    validationIssues: [],
    blockerKind: null,
    reviewApproved: false,
    cleanConfirmationFingerprint: null,
    pendingLazyCorrection: null,
    arbiterDirection: null,
    canonicalPlan: null,
  };
}

export function selectRoleSession({
  settings,
  role,
  latestSession,
  contextKey,
  sourceSession,
  sourceForkConsumed,
  recovering,
  freshSession,
}) {
  const runScopedPrimary =
    role === "planner" &&
    authoringPolicy(settings).primarySessionScope === "run";
  const previousSession =
    !recovering &&
    role !== "arbiter" &&
    latestSession !== undefined &&
    (runScopedPrimary || latestSession.contextKey === contextKey)
      ? latestSession.sessionId
      : undefined;
  let session;
  if (!freshSession && !recovering && role !== "arbiter") {
    if (previousSession !== undefined) {
      session = { id: previousSession, mode: "continue" };
    } else if (
      sourceSession !== null &&
      (!runScopedPrimary || !sourceForkConsumed)
    ) {
      session = { id: sourceSession, mode: "fork" };
    }
  }
  return {
    session,
    previousSession,
    consumeSourceFork: runScopedPrimary && session?.mode === "fork",
  };
}

export function correctionScope(phase, state) {
  return Object.freeze({
    attempt: 1,
    phase,
    draftFingerprint: state.draftFingerprint,
  });
}

export function sameCorrectionScope(left, right) {
  return (
    left !== null &&
    left.attempt === right.attempt &&
    left.phase === right.phase &&
    left.draftFingerprint === right.draftFingerprint
  );
}

export function blockedCorrection(
  state,
  counters,
  blockerKind,
  values,
  historyLimit,
) {
  const counted = counters.revisionRounds > state.lastCountedRevision;
  const correctionRounds = counters.correctionRounds + (counted ? 1 : 0);
  return {
    correctionRounds,
    lastCountedRevision: counted
      ? counters.revisionRounds
      : state.lastCountedRevision,
    blockedSinceArbitration: state.blockedSinceArbitration + (counted ? 1 : 0),
    correctionHistory: counted
      ? [
          ...state.correctionHistory,
          {
            round: correctionRounds,
            draftFingerprint: state.draftFingerprint,
            findingIds:
              blockerKind === "findings"
                ? values.findings.map(({ id }) => id)
                : [],
            validationIssues:
              blockerKind === "validation" ? values.validationIssues : [],
          },
        ].slice(-historyLimit)
      : state.correctionHistory,
  };
}

export function correctionDecision(state, counters) {
  // Replacing invalid output is the same attempt, not a new revision.
  if (state.pendingLazyCorrection !== null) return "continue";
  if (counters.revisionRounds >= state.settings.maxRevisionRounds)
    return "limit";
  if (state.blockedSinceArbitration < state.settings.stagnationWindowRounds)
    return "continue";
  const policy = authoringPolicy(state.settings);
  const independentResolution =
    state.workflowState === "REVISE" && state.blockerKind === "findings";
  return policy.arbitration && independentResolution && !state.arbitrationUsed
    ? "arbitrate"
    : "stagnation";
}
