import { isDeepStrictEqual } from "node:util";

// Private execution decisions; the descriptor still validates supported modes.
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
  const policy = executionPolicy(settings);
  return policy.primaryConvergence && policy.independentReview;
}

export function primaryFindings(state) {
  return combinedReview(state.settings)
    ? state.primaryFindings
    : state.findings;
}

export function executionPolicy(settings) {
  if (settings?.mode === "combined") return COMBINED;
  return settings?.mode === "lazy" ? LAZY : INDEPENDENT;
}

export function roleProducingPhase(state, checkpoint) {
  if (checkpoint.startsWith("commit-size:")) return "commit-size";
  if (checkpoint.startsWith("effective-plan:")) return "effective-plan";
  if (
    ["bootstrap", "validation-migration"].includes(checkpoint) &&
    state.effectivePlanRevisions?.revisions.some(
      (revision) => revision.accepted,
    )
  )
    return "revision-validation";
  return checkpoint === "validation-migration"
    ? checkpoint
    : state.workflowState.toLowerCase().replaceAll("_", "-");
}

export function candidateCheckpoint(settings) {
  return executionPolicy(settings).primaryConvergence
    ? "CHECK_AND_FIX"
    : "REVIEW";
}

export function candidateReviewCheckpoint(state) {
  return state.pendingReviewCorrection === null
    ? `commit:${state.currentStep}`
    : `candidate-review-correction:${state.currentStep}`;
}

export function candidateCleanCheckpoint(state) {
  return state.pendingLazyCorrection === null
    ? `candidate:${state.currentStep}`
    : `lazy-correction:${state.currentStep}:clean-confirm`;
}

export function candidateCheckCheckpoint(state) {
  if (state.pendingLazyCorrection !== null)
    return `lazy-correction:${state.currentStep}:check-and-fix`;
  const phase = combinedReview(state.settings) ? "primary" : "lazy-commit";
  return `${phase}:${state.currentStep}`;
}

export function matchesGateCatalogReservation(previous, next, binding) {
  const before = previous.pipelineState;
  const after = next.pipelineState;
  // Writable finalization keeps its candidate, inventory, correction scope and
  // fix accounting from pause acceptance through dispatch.
  if (binding.checkpoint.startsWith("finalize:workspace-write:")) {
    return (
      binding.role === "worker" &&
      binding.resumeState === "FINALIZE" &&
      Number.isSafeInteger(before.currentStep) &&
      before.currentStep > 0 &&
      binding.checkpoint ===
        `finalize:workspace-write:commit:${before.currentStep}` &&
      (next.activeTurn === null || after.workflowState === "FINALIZE") &&
      isDeepStrictEqual(after, {
        ...before,
        workflowState: after.workflowState,
      }) &&
      isDeepStrictEqual(previous.counters, next.counters)
    );
  }
  if (binding.checkpoint.startsWith("check-and-fix:")) {
    return (
      binding.role === "worker" &&
      binding.resumeState === "CHECK_AND_FIX" &&
      executionPolicy(before.settings).primaryConvergence &&
      Number.isSafeInteger(before.currentStep) &&
      before.currentStep > 0 &&
      binding.checkpoint ===
        `check-and-fix:workspace-write:${candidateCheckCheckpoint(before)}` &&
      (next.activeTurn === null || after.workflowState === "CHECK_AND_FIX") &&
      isDeepStrictEqual(after, {
        ...before,
        workflowState: after.workflowState,
      }) &&
      isDeepStrictEqual(previous.counters, next.counters)
    );
  }
  if (binding.checkpoint.startsWith("confirm:read-only:")) {
    const confirmer = executionPolicy(before.settings).terminalConfirmer;
    const purpose =
      before.pendingConfirmationCorrection != null
        ? "confirmation-correction"
        : confirmer === "worker"
          ? "confirmation"
          : "commit";
    return (
      binding.role === confirmer &&
      binding.resumeState === "CONFIRM" &&
      binding.checkpoint ===
        `confirm:read-only:${purpose}:${before.currentStep}` &&
      (next.activeTurn === null || after.workflowState === "CONFIRM") &&
      isDeepStrictEqual(after, {
        ...before,
        workflowState: after.workflowState,
      }) &&
      isDeepStrictEqual(previous.counters, next.counters)
    );
  }
  if (
    /^clean-confirm:read-only:(?:candidate|lazy-correction):/u.test(
      binding.checkpoint,
    )
  ) {
    return (
      binding.role === "worker" &&
      binding.resumeState === "CLEAN_CONFIRM" &&
      executionPolicy(before.settings).primaryConvergence &&
      Number.isSafeInteger(before.currentStep) &&
      before.currentStep > 0 &&
      binding.checkpoint ===
        `clean-confirm:read-only:${candidateCleanCheckpoint(before)}` &&
      (next.activeTurn === null || after.workflowState === "CLEAN_CONFIRM") &&
      isDeepStrictEqual(after, {
        ...before,
        workflowState: after.workflowState,
      }) &&
      isDeepStrictEqual(previous.counters, next.counters)
    );
  }
  if (
    !/^review:read-only:(?:commit|candidate-review-correction):/u.test(
      binding.checkpoint,
    )
  )
    return undefined;

  return (
    binding.role === "reviewer" &&
    binding.resumeState === "REVIEW" &&
    executionPolicy(before.settings).independentReview &&
    Number.isSafeInteger(before.currentStep) &&
    before.currentStep > 0 &&
    binding.checkpoint ===
      `review:read-only:${candidateReviewCheckpoint(before)}` &&
    before.currentStep === after.currentStep &&
    (next.activeTurn === null || after.workflowState === "REVIEW") &&
    isDeepStrictEqual(previous.counters, next.counters) &&
    isDeepStrictEqual(after, { ...before, workflowState: after.workflowState })
  );
}

// The first pause must keep the reservation and input hashes that acceptance
// and dispatch preserve.
export function assertWritableGateCatalogPause(previous, next, retryCode) {
  const pause = next.pause?.operatorResume?.pause ?? next.pause;
  const prior = previous.pause?.operatorResume?.pause ?? previous.pause;
  if (
    pause?.code !== retryCode ||
    !/^(?:check-and-fix|finalize):workspace-write:/u.test(pause.checkpoint) ||
    previous.modelCatalogResume != null ||
    prior?.code === retryCode
  )
    return;
  const { role, checkpoint, resumeState } = pause;
  if (
    !isDeepStrictEqual(previous.hashes, next.hashes) ||
    !matchesGateCatalogReservation(previous, next, {
      role,
      checkpoint,
      resumeState,
    })
  )
    throw new Error("Writable gate catalog pause changed its reservation.");
  return true;
}

// A first read-only gate pause must retire the gate turn whose own failed
// attempt recorded the no-effect catalog rejection, keeping its reservation.
export function assertReadOnlyGateCatalogPause(
  previous,
  next,
  retryCode,
  turnStart,
  attempt,
) {
  const pause = next.pause?.operatorResume?.pause ?? next.pause;
  const prior = previous.pause?.operatorResume?.pause ?? previous.pause;
  if (
    pause?.code !== retryCode ||
    !/^(?:review|clean-confirm|confirm):read-only:/u.test(pause.checkpoint) ||
    previous.modelCatalogResume != null ||
    prior?.code === retryCode
  )
    return;
  const { role, checkpoint, resumeState } = pause;
  const turn = previous.activeTurn;
  // Review and clean confirmation may capture the inspected infrastructure
  // once; a saved fingerprint stays unchanged through later misses.
  const field = "catalogReviewInfrastructureFingerprint";
  let pipelineState = next.pipelineState;
  if (
    !checkpoint.startsWith("confirm:") &&
    !Object.hasOwn(previous.pipelineState, field)
  ) {
    const { [field]: _, ...reserved } = pipelineState;
    pipelineState = reserved;
  }
  if (
    turn?.role !== role ||
    turn.phase !== checkpoint.split(":")[0] ||
    previous.pipelineState.workflowState !== resumeState ||
    attempt?.role !== role ||
    attempt.checkpoint !== checkpoint ||
    (turnStart?.catalogCheckpoint !== undefined &&
      turnStart.catalogCheckpoint !== checkpoint) ||
    !isDeepStrictEqual(previous.hashes, next.hashes) ||
    !matchesGateCatalogReservation(
      previous,
      { ...next, pipelineState },
      { role, checkpoint, resumeState },
    )
  )
    throw new Error("Read-only gate catalog pause changed its reservation.");
  return true;
}

const VALIDATION_MIGRATION_CHECKPOINT =
  /^(validation-migration|revision-validation):read-only:(plan-context:)?validation-migration$/u;

export function isValidationMigrationArbiterCheckpoint(binding) {
  return (
    binding?.role === "arbiter" &&
    VALIDATION_MIGRATION_CHECKPOINT.test(binding.checkpoint)
  );
}

function retainsProviderCheckpoint(run, role, checkpoint) {
  return [run.availabilityRetry, run.inactivityRecovery].some(
    (recovery) => recovery?.role === role && recovery.checkpoint === checkpoint,
  );
}

export function matchesNarrativeCatalogAttempt(
  run,
  pause,
  turnStart,
  attempt,
  phase,
  observed,
) {
  return (
    attempt?.role === pause.role &&
    attempt.checkpoint === observed &&
    (turnStart?.catalogCheckpoint === undefined ||
      turnStart.catalogCheckpoint === pause.checkpoint) &&
    (run.activeTurn?.phase === "plan-context" ||
      (run.activeTurn?.phase === phase &&
        (turnStart?.catalogCheckpoint === pause.checkpoint ||
          retainsProviderCheckpoint(run, pause.role, observed))))
  );
}

// A first migration pause must retire the invocation whose own failed attempt
// recorded the no-effect read-only rejection at its observed checkpoint. A
// narrative review observes `plan-context`; a version 27 recovery keeps the
// suspended phase.
export function assertValidationMigrationCatalogPause(
  previous,
  next,
  retryCode,
  turnStart,
  attempt,
) {
  const pause = next.pause?.operatorResume?.pause ?? next.pause;
  const prior = previous.pause?.operatorResume?.pause ?? previous.pause;
  const match = VALIDATION_MIGRATION_CHECKPOINT.exec(pause?.checkpoint ?? "");
  if (
    pause?.code !== retryCode ||
    match === null ||
    previous.modelCatalogResume != null ||
    prior?.code === retryCode
  )
    return;
  const { role, checkpoint, resumeState } = pause;
  const [, phase, narrative] = match;
  const suspended = resumeState.toLowerCase().replaceAll("_", "-");
  const legacyCheckpoint = `${suspended}:read-only:validation-migration`;
  const matchesAttempt = narrative
    ? matchesNarrativeCatalogAttempt(
        previous,
        pause,
        turnStart,
        attempt,
        phase,
        "plan-context:read-only:validation-migration",
      )
    : previous.activeTurn?.phase === phase &&
      (attempt?.checkpoint === checkpoint ||
        (attempt?.checkpoint === legacyCheckpoint &&
          retainsProviderCheckpoint(previous, role, legacyCheckpoint)));
  if (
    phase !==
      roleProducingPhase(previous.pipelineState, "validation-migration") ||
    previous.activeTurn?.role !== role ||
    attempt?.role !== role ||
    !matchesAttempt ||
    (turnStart?.catalogCheckpoint !== undefined &&
      turnStart.catalogCheckpoint !== checkpoint) ||
    !isDeepStrictEqual(previous.availabilityRetry, next.availabilityRetry) ||
    !isDeepStrictEqual(previous.inactivityRecovery, next.inactivityRecovery) ||
    !matchesValidationMigrationCatalogReservation(previous, next, pause)
  )
    throw new Error(
      "Validation migration catalog pause changed its reservation or has no failed-attempt proof.",
    );
  return true;
}

export function matchesValidationMigrationCatalogReservation(
  previous,
  next,
  binding,
) {
  const before = previous.pipelineState;
  const after = next.pipelineState;
  if (
    !VALIDATION_MIGRATION_CHECKPOINT.test(binding.checkpoint) ||
    (binding.role === "arbiter" && previous.pipelineStateVersion < 46)
  )
    return undefined;

  const policy = executionPolicy(before.settings);
  return (
    before.validationMigrationPending === true &&
    (binding.role === "arbiter"
      ? policy.bootstrapArbitration &&
        before.validationMigrationDisagreement != null
      : before.validationMigrationDisagreement == null &&
        (binding.role === "worker" ||
          (binding.role === "reviewer" && policy.independentBootstrap))) &&
    (next.activeTurn === null || after.workflowState === binding.resumeState) &&
    isDeepStrictEqual(after, {
      ...before,
      workflowState: after.workflowState,
    }) &&
    isDeepStrictEqual(previous.counters, next.counters)
  );
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
