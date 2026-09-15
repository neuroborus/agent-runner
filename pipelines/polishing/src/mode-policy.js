// Private polishing decisions; supported modes remain descriptor-owned.
const INDEPENDENT = Object.freeze({
  activeRoles: Object.freeze(["worker", "reviewer", "arbiter"]),
  independentBootstrap: true,
  independentReview: true,
  primaryConvergence: false,
  terminalConfirmer: "reviewer",
  arbitration: true,
  bootstrapArbitration: true,
  primarySessionScope: "checkpoint",
});
const LAZY = Object.freeze({
  activeRoles: Object.freeze(["worker"]),
  independentBootstrap: false,
  independentReview: false,
  primaryConvergence: true,
  terminalConfirmer: "worker",
  arbitration: false,
  bootstrapArbitration: false,
  primarySessionScope: "run",
});

const COMBINED = Object.freeze({
  ...INDEPENDENT,
  primaryConvergence: true,
  bootstrapArbitration: false,
});

export function combinedReview(settings) {
  const policy = polishingPolicy(settings);
  return policy.primaryConvergence && policy.independentReview;
}

export function primaryFindings(state) {
  return combinedReview(state.settings)
    ? state.primaryFindings
    : state.findings;
}

export function polishingPolicy(settings) {
  if (settings?.mode === "combined") return COMBINED;
  return settings?.mode === "lazy" ? LAZY : INDEPENDENT;
}

export function candidateCheckpoint(settings) {
  return polishingPolicy(settings).primaryConvergence
    ? "CHECK_AND_FIX"
    : "REVIEW";
}

export function findingResolutionCheckpoint(settings) {
  return polishingPolicy(settings).independentReview
    ? "RESOLVE_FINDINGS"
    : "CHECK_AND_FIX";
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
    role === "worker" &&
    polishingPolicy(settings).primarySessionScope === "run";
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
