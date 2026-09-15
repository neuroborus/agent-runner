// Private execution decisions; the descriptor still validates supported modes.
const INDEPENDENT = Object.freeze({
  activeRoles: Object.freeze(["worker", "reviewer", "arbiter"]),
  independentBootstrap: true,
  independentReview: true,
  primaryConvergence: false,
  terminalConfirmer: "reviewer",
  arbitration: true,
  primarySessionScope: "checkpoint",
});
const LAZY = Object.freeze({
  activeRoles: Object.freeze(["worker"]),
  independentBootstrap: false,
  independentReview: false,
  primaryConvergence: true,
  terminalConfirmer: "worker",
  arbitration: false,
  primarySessionScope: "run",
});

export function executionPolicy(settings) {
  return settings?.mode === "lazy" ? LAZY : INDEPENDENT;
}

export function candidateCheckpoint(settings) {
  return executionPolicy(settings).primaryConvergence
    ? "CHECK_AND_FIX"
    : "REVIEW";
}

export function findingResolutionCheckpoint(settings) {
  return executionPolicy(settings).independentReview
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
    executionPolicy(settings).primarySessionScope === "run";
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
