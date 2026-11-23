import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";

import { executionContentFingerprint } from "./custom-results.js";
import { PlanExecutionWorkflowError } from "./errors.js";

const hash = (value) =>
  createHash("sha256").update(JSON.stringify(value)).digest("hex");
const fingerprint = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
const exact = (value, fields) =>
  value !== null &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.keys(value).length === fields.length &&
  fields.every((field) => Object.hasOwn(value, field));
const count = (value) => Number.isSafeInteger(value) && value >= 0;
const IMPLEMENTATION_CATALOG_CHECKPOINT = "implement:workspace-write:commit:";
const RESTATEMENT_BOUNDARY_SCHEMA_VERSION = 28;
const legacyRestatementExpiries = new WeakMap();
export const CATALOG_IMPLEMENTATION_VERIFIED = "catalog-no-effect-verified";
const FIELDS = [
  "schemaVersion",
  "phase",
  "step",
  "stage",
  "beforeFingerprint",
  "originalContentFingerprint",
  "factsFingerprint",
  "blockers",
  "restrictedIds",
  "budgetExhausted",
  "rework",
  "fixRoundsBefore",
  "fixCharged",
  "pendingCorrectionBefore",
  "candidateFingerprint",
  "attempts",
  "additionalAttempts",
  "diagnostic",
  "productDecision",
  "repair",
];
const CONSTRAINTS = new Set([
  "object",
  "single-object-wrapper",
  "semantic-contract",
  "provider-structured-output",
  "exact-field-set",
  "maximum-2-mebibytes",
  "serializable-json",
  "empty-string",
  "empty-array",
  "implementation-status",
  "exactly-three-policy-evidence-items",
  "resolution-status",
  "nonempty-plain-text-up-to-4000-characters",
  "concise-markdown-up-to-20000-characters",
  "array-up-to-32-items",
  "array-up-to-16-items",
  "nonempty-array-up-to-32-items",
  "current-blocker-id",
  "fix-or-dispute",
  "disputable-blocker-only",
  "every-current-blocker-exactly-once",
  "bounded-current-criterion-evidence-and-authorized-outputs",
  "null-for-inactive-status",
]);

function phaseContract(phase) {
  return phase === "IMPLEMENT" ? "implementation" : "finding-resolution";
}

// New durable diagnostics admit identities only. Historical diagnostics keep
// their existing validator; rejected values and arbitrary exception text never
// enter this checkpoint, even when an adapter supplies diagnostic-like fields.
export function writableResultDiagnostic(cause, phase) {
  const contract = phaseContract(phase);
  const candidate = cause?.diagnostic;
  const field = candidate?.field;
  const decisionField =
    /^decisions\[(?:[0-9]|[12][0-9]|3[01])\](?:\.(?:id|decision|reason|evidence(?:\[(?:[0-9]|[12][0-9]|3[01])\])?))?$/u;
  const listField =
    /^(?:evidence\[(?:[0-9]|[12][0-9]|3[01])\]|options\[(?:[0-9]|1[0-5])\])$/u;
  const allowedField =
    [
      "result",
      "status",
      "reason",
      "question",
      "options",
      "whyBlocked",
      "evidence",
      "customResult",
    ].includes(field) ||
    (phase === "IMPLEMENT" && field === "summary") ||
    (phase === "RESOLVE_FINDINGS" &&
      (field === "decisions" ||
        (typeof field === "string" && decisionField.test(field)))) ||
    (typeof field === "string" && listField.test(field));
  return {
    role: "worker",
    phase: contract,
    contract,
    field:
      allowedField && CONSTRAINTS.has(candidate?.constraint) ? field : "result",
    constraint:
      allowedField && CONSTRAINTS.has(candidate?.constraint)
        ? candidate.constraint
        : "semantic-contract",
  };
}

// Blockers are validated owning-pipeline data, not a rejected response. Keep
// their ownership when content changes invalidate the gates that produced them.
function writableResultFacts(state, checkpoint) {
  return hash({
    phase: checkpoint.phase,
    step: state.currentStep,
    settings: state.settings,
    plan: state.canonicalPlan,
    revisions: state.effectivePlanRevisions,
    implementation: state.stepImplementation,
    direction: state.implementationDirection,
    findings: state.findings,
    previousFindings: state.previousFindings,
    pendingDisputes: state.pendingDisputes,
    disputeCounts: state.disputeCounts,
    arbitrations: state.findingArbitrations,
    stagnation: state.stagnationDirection,
    correctionHistory: state.correctionHistory,
    sameFindingRounds: state.sameFindingRounds,
    disputeHistory: state.disputeHistory,
    blockedSinceStagnation: state.blockedSinceStagnation,
    additionalFixRounds: state.additionalFixRounds,
    pendingCorrectionBefore: checkpoint.pendingCorrectionBefore,
    fixRoundsBefore: checkpoint.fixRoundsBefore,
    completedCommits: state.completedCommits,
    customResults: state.customResults,
    validationSchedule: state.validationSchedule,
    requiredChecks: state.requiredChecks,
    overrides: state.findingOverrides,
    blockers: checkpoint.blockers,
    restrictedIds: checkpoint.restrictedIds,
    budgetExhausted: checkpoint.budgetExhausted,
    rework: checkpoint.rework,
    customCandidate: state.customCandidate,
    customWritePolicy: state.customWritePolicy,
  });
}

export function createWritableResult(
  state,
  counters,
  {
    beforeFingerprint,
    blockers = [],
    restrictedIds = [],
    budgetExhausted = false,
  },
) {
  const checkpoint = {
    schemaVersion: 2,
    phase: state.workflowState,
    step: state.currentStep,
    stage: "prepared",
    beforeFingerprint,
    originalContentFingerprint: state.repositoryBaseline.contentFingerprint,
    factsFingerprint: null,
    blockers: structuredClone(blockers),
    restrictedIds,
    budgetExhausted,
    rework: state.implementationDirection !== null,
    fixRoundsBefore: counters.fixRounds,
    fixCharged: false,
    pendingCorrectionBefore: state.pendingCorrection,
    candidateFingerprint: null,
    attempts: 0,
    additionalAttempts: 0,
    diagnostic: null,
    productDecision: null,
    repair: null,
  };
  checkpoint.factsFingerprint = writableResultFacts(state, checkpoint);
  return checkpoint;
}

export function beginWritableRestatement(
  reservation,
  revision,
  validationFingerprint,
) {
  const { restatementValidationFingerprint, ...fields } = reservation;
  const starting = reservation.stage === "ready";
  // A new attempt captures its own scope. Recovery continues the consumed one.
  const scope = starting
    ? validationFingerprint
    : (restatementValidationFingerprint ?? validationFingerprint);
  return {
    ...fields,
    stage: "correcting",
    attempts: reservation.attempts + (starting ? 1 : 0),
    restatementStartedAfter: revision,
    ...(scope === undefined ? {} : { restatementValidationFingerprint: scope }),
  };
}

export function assertRestatementScopeContinuity(previous, next) {
  const before = previous.pipelineState.writableResult;
  const after = next.pipelineState.writableResult;
  if (
    before?.restatementValidationFingerprint !== undefined &&
    ["correcting", "retry-ready", "inactivity-ready"].includes(after?.stage) &&
    after.attempts <= before.attempts &&
    after.restatementValidationFingerprint !==
      before.restatementValidationFingerprint
  )
    throw new Error(
      "Read-only restatement changed its reserved validation scope.",
    );
}

export function originalWritableCheckpoint(reservation) {
  const phase = reservation.phase.toLowerCase().replaceAll("_", "-");
  const access = reservation.budgetExhausted ? "read-only" : "workspace-write";
  return `${phase}:${access}:commit:${reservation.step}`;
}

function observedRestatementCheckpoint(run, reservation) {
  const original = originalWritableCheckpoint(reservation);
  return [run.availabilityRetry, run.inactivityRecovery].some(
    (recovery) =>
      recovery?.role === "worker" && recovery.checkpoint === original,
  )
    ? original
    : `writable-result:read-only:commit:${reservation.step}`;
}

export function upgradeLegacyWritableResult(reservation) {
  if (reservation === null) return null;
  if (reservation.schemaVersion !== 1 || Object.hasOwn(reservation, "repair"))
    throw new PlanExecutionWorkflowError(
      "Legacy state cannot own finding repair authority.",
    );
  return { ...reservation, schemaVersion: 2, repair: null };
}

export async function prepareWritableResultRecovery(run, history) {
  legacyRestatementExpiries.delete(run);
  const { writableResult, repositoryBaseline } = run.pipelineState;
  const recovery = run.inactivityRecovery;
  if (
    writableResult?.stage !== "correcting" ||
    writableResult.productDecision !== null ||
    writableResult.restatementStartedAfter !== undefined ||
    recovery?.status !== "expired" ||
    recovery.role !== "worker" ||
    recovery.expiryRevision === null ||
    recovery.contentFingerprint !== repositoryBaseline.contentFingerprint ||
    writableResult.candidateFingerprint !==
      executionContentFingerprint(run.pipelineState) ||
    run.activeTurn?.role !== "worker" ||
    run.activeTurn.phase !== "writable-result"
  )
    return;

  let previous = null;
  let previousMatches = false;
  let startedAfter;
  let proof;
  const original = originalWritableCheckpoint(writableResult);
  const restatement = `writable-result:read-only:commit:${writableResult.step}`;
  for await (const { state, activity } of history.events) {
    const historical = state.pipelineState;
    const checkpoint = historical.writableResult;
    const legacyShape =
      state.pipelineStateVersion < 45 &&
      checkpoint?.schemaVersion === 1 &&
      !Object.hasOwn(checkpoint, "repair");
    const matches =
      historical.workflowState === writableResult.phase &&
      state.pause === null &&
      historical.currentStep === writableResult.step &&
      isDeepStrictEqual(historical.repositoryBaseline, repositoryBaseline) &&
      isDeepStrictEqual(
        legacyShape ? upgradeLegacyWritableResult(checkpoint) : checkpoint,
        writableResult,
      ) &&
      executionContentFingerprint(historical) ===
        writableResult.candidateFingerprint;
    if (
      !matches ||
      activity?.kind === "turn-started" ||
      !isDeepStrictEqual(state.activeTurn, previous?.activeTurn)
    ) {
      startedAfter = undefined;
      proof = undefined;
    }
    if (
      state.schemaVersion < RESTATEMENT_BOUNDARY_SCHEMA_VERSION &&
      matches &&
      previousMatches &&
      previous.activeTurn === null &&
      state.revision === previous.revision + 1 &&
      isDeepStrictEqual(state.activeTurn, run.activeTurn) &&
      activity?.actor === "worker" &&
      activity.phase === "writable-result" &&
      activity.kind === "turn-started"
    ) {
      const retained = [
        previous.availabilityRetry,
        previous.inactivityRecovery,
      ].some(
        (episode) =>
          episode?.role === "worker" && episode.checkpoint === original,
      );
      if (recovery.checkpoint === (retained ? original : restatement))
        startedAfter = previous.revision;
    }
    if (
      state.revision === recovery.expiryRevision &&
      startedAfter !== undefined
    ) {
      const attempt = previous.observations?.attempts.at(-1);
      if (
        activity?.actor === "worker" &&
        activity.phase === "inactivity" &&
        activity.kind === "expired" &&
        isDeepStrictEqual(state.inactivityRecovery, recovery) &&
        isDeepStrictEqual(previous.observations, state.observations) &&
        attempt?.status === "active" &&
        attempt.id > startedAfter + 1 &&
        attempt.id < state.revision &&
        attempt.role === recovery.role &&
        attempt.checkpoint === recovery.checkpoint
      )
        proof = { startedAfter, attemptId: attempt.id };
    }
    previous = state;
    previousMatches = matches;
  }
  if (proof !== undefined) legacyRestatementExpiries.set(run, proof);
}

export function legacyWritableExpiryStart(run, currentRun) {
  const proof = legacyRestatementExpiries.get(run);
  if (
    proof !== undefined &&
    isDeepStrictEqual(currentRun.activeTurn, run.activeTurn) &&
    isDeepStrictEqual(currentRun.inactivityRecovery, run.inactivityRecovery) &&
    currentRun.observations?.attempts.at(-1)?.id === proof.attemptId &&
    isDeepStrictEqual(
      currentRun.pipelineState.writableResult,
      run.pipelineState.writableResult,
    ) &&
    isDeepStrictEqual(
      currentRun.pipelineState.repositoryBaseline,
      run.pipelineState.repositoryBaseline,
    )
  )
    return proof.startedAfter;
}

export function matchesWritableAvailabilityRetirement(
  previous,
  next,
  activeTurnStart,
) {
  const state = previous.pipelineState;
  const reservation = state.writableResult;
  const episode = next.availabilityRetry;
  if (
    previous.activeTurn?.role !== "worker" ||
    previous.activeTurn.phase !== "writable-result" ||
    episode.role !== "worker" ||
    reservation?.stage !== "correcting" ||
    !["IMPLEMENT", "RESOLVE_FINDINGS"].includes(reservation.phase) ||
    state.workflowState !== reservation.phase ||
    !Number.isSafeInteger(reservation.step) ||
    reservation.step < 1 ||
    state.currentStep !== reservation.step ||
    state.pendingCommit !== null ||
    reservation.productDecision !== null ||
    !Number.isSafeInteger(reservation.attempts) ||
    reservation.attempts < 1 ||
    reservation.attempts !== reservation.additionalAttempts + 1 ||
    activeTurnStart?.pipelineState == null ||
    reservation.restatementStartedAfter !== activeTurnStart.previousRevision ||
    activeTurnStart.pipelineState.workflowState !== state.workflowState ||
    !isDeepStrictEqual(
      reservation,
      activeTurnStart.pipelineState.writableResult,
    ) ||
    !isDeepStrictEqual(
      state.repositoryBaseline,
      activeTurnStart.pipelineState.repositoryBaseline,
    ) ||
    reservation.candidateFingerprint !== executionContentFingerprint(state) ||
    episode.contentFingerprint !== state.repositoryBaseline?.contentFingerprint
  )
    return false;

  return (
    episode.checkpoint ===
      observedRestatementCheckpoint(previous, reservation) &&
    isDeepStrictEqual(next.pipelineState, {
      ...state,
      writableResult: { ...reservation, stage: "retry-ready" },
    })
  );
}

export function assertCatalogImplementationTransition(
  previous,
  next,
  activity,
  retryCode,
) {
  const pause = next.pause?.operatorResume?.pause ?? next.pause;
  if (
    pause?.code !== retryCode ||
    !pause.checkpoint.startsWith(IMPLEMENTATION_CATALOG_CHECKPOINT)
  )
    return;

  const priorPause = previous.pause?.operatorResume?.pause ?? previous.pause;
  if (isDeepStrictEqual(priorPause, pause)) return;

  const before = previous.pipelineState;
  const reservation = before.writableResult;
  // The workflow emits this event after it verifies the no-effect result
  // and both snapshots. Bind the verification to the turn it retires.
  if (
    next.pause !== pause ||
    pause.reason !== "backend_unavailable" ||
    pause.role !== "worker" ||
    pause.resumeState !== "IMPLEMENT" ||
    previous.pause !== null ||
    !Object.hasOwn(previous.modelCompletionReceipts, "worker") ||
    previous.availabilityRetry !== null ||
    previous.inactivityRecovery !== null ||
    previous.activeTurn?.role !== "worker" ||
    previous.activeTurn.phase !== "implement" ||
    previous.preparation !== null ||
    previous.executionProcess !== null ||
    previous.executionResource !== null ||
    next.activeTurn !== null ||
    activity?.actor !== "runner" ||
    activity.phase !== "implement" ||
    activity.kind !== CATALOG_IMPLEMENTATION_VERIFIED ||
    before.workflowState !== "IMPLEMENT" ||
    reservation?.phase !== "IMPLEMENT" ||
    reservation.stage !== "invoking" ||
    reservation.rework ||
    reservation.budgetExhausted ||
    !Number.isSafeInteger(reservation.step) ||
    reservation.step < 1 ||
    reservation.step !== before.currentStep ||
    !fingerprint(reservation.originalContentFingerprint) ||
    reservation.originalContentFingerprint !==
      before.repositoryBaseline?.contentFingerprint ||
    reservation.beforeFingerprint !== executionContentFingerprint(before) ||
    pause.checkpoint !==
      `${IMPLEMENTATION_CATALOG_CHECKPOINT}${reservation.step}` ||
    !isDeepStrictEqual(previous.counters, next.counters) ||
    !isDeepStrictEqual(previous.hashes, next.hashes) ||
    !isDeepStrictEqual(next.pipelineState, {
      ...before,
      workflowState: "WAITING_FOR_USER",
      writableResult: { ...reservation, stage: "prepared" },
    })
  )
    throw new Error(
      "Catalog IMPLEMENT pause has no verified invocation retirement.",
    );
  return true;
}

export function matchesWritableRestatementCatalogAttempt(
  run,
  binding,
  turnStart,
  attempt,
) {
  const { pipelineState: state } = run;
  const reservation = state.writableResult;
  return (
    run.activeTurn?.role === "worker" &&
    run.activeTurn.phase === "writable-result" &&
    binding.role === "worker" &&
    state.workflowState === binding.resumeState &&
    reservation?.stage === "correcting" &&
    reservation.productDecision === null &&
    binding.checkpoint ===
      `writable-result:read-only:commit:${reservation.step}` &&
    attempt?.role === binding.role &&
    attempt.checkpoint === observedRestatementCheckpoint(run, reservation) &&
    turnStart?.pipelineState != null &&
    (turnStart.catalogCheckpoint === undefined ||
      turnStart.catalogCheckpoint === binding.checkpoint) &&
    reservation.restatementStartedAfter === turnStart.previousRevision &&
    isDeepStrictEqual(state, turnStart.pipelineState)
  );
}

export function assertRestatementCatalogPause(
  previous,
  next,
  retryCode,
  turnStart,
  attempt,
  writableAttempt,
) {
  const pause = next.pause?.operatorResume?.pause ?? next.pause;
  const prior = previous.pause?.operatorResume?.pause ?? previous.pause;
  if (
    pause?.code !== retryCode ||
    !pause.checkpoint.startsWith("writable-result:") ||
    previous.modelCatalogResume != null ||
    prior?.code === retryCode
  )
    return;

  const state = previous.pipelineState;
  const reservation = state.writableResult;
  const after = next.pipelineState.writableResult;
  const original =
    reservation?.stage === "ready"
      ? originalWritableCheckpoint(reservation)
      : null;
  const originalAttempt = reservation?.budgetExhausted
    ? attempt
    : writableAttempt;
  // The original invocation can publish a reconciled report awaiting its
  // first restatement. A consumed restatement must prove its own rejection.
  if (
    original !== null &&
    previous.activeTurn?.phase === original.split(":")[0] &&
    originalAttempt?.role === pause.role &&
    originalAttempt.checkpoint === original &&
    (turnStart?.catalogCheckpoint === undefined ||
      turnStart.catalogCheckpoint === original) &&
    after?.stage === "ready" &&
    matchesWritableCatalogReservation(previous, next, pause)
  )
    return true;

  if (
    pause.reason !== "backend_unavailable" ||
    previous.pause !== null ||
    next.activeTurn !== null ||
    next.pipelineState.workflowState !== "WAITING_FOR_USER" ||
    (next.pause !== pause &&
      !fingerprint(reservation?.restatementValidationFingerprint)) ||
    after?.stage !== "retry-ready" ||
    !matchesWritableRestatementCatalogAttempt(
      previous,
      pause,
      turnStart,
      attempt,
    ) ||
    !matchesWritableCatalogReservation(previous, next, pause, {
      retiringRestatement: true,
    })
  )
    throw new Error(
      "Catalog pause has no verified read-only restatement retirement.",
    );
  return true;
}

export function matchesWritableCatalogReservation(
  previous,
  next,
  binding,
  { retiringRestatement = false } = {},
) {
  const { role, checkpoint, resumeState } = binding;
  const restatement = checkpoint.startsWith("writable-result:");
  const implementation = checkpoint.startsWith(
    IMPLEMENTATION_CATALOG_CHECKPOINT,
  );
  if (!restatement && !implementation) return undefined;

  const before = previous.pipelineState.writableResult;
  const after = next.pipelineState.writableResult;
  if (
    role !== "worker" ||
    before?.phase !== resumeState ||
    before.step !== previous.pipelineState.currentStep ||
    before.step !== next.pipelineState.currentStep ||
    before.productDecision !== null
  )
    return false;

  if (implementation) {
    return (
      before.phase === "IMPLEMENT" &&
      !before.rework &&
      !before.budgetExhausted &&
      before.stage === "prepared" &&
      checkpoint === `${IMPLEMENTATION_CATALOG_CHECKPOINT}${before.step}` &&
      (next.activeTurn === null ||
        (previous.pipelineState.workflowState === "IMPLEMENT" &&
          next.pipelineState.workflowState === "IMPLEMENT")) &&
      isDeepStrictEqual(previous.counters, next.counters) &&
      isDeepStrictEqual(previous.hashes, next.hashes) &&
      isDeepStrictEqual(next.pipelineState, {
        ...previous.pipelineState,
        workflowState: next.pipelineState.workflowState,
        writableResult:
          next.activeTurn === null ? before : { ...before, stage: "invoking" },
      })
    );
  }

  if (
    checkpoint !== `writable-result:read-only:commit:${before.step}` ||
    !["ready", "retry-ready", "correcting"].includes(before.stage) ||
    before.attempts !==
      before.additionalAttempts + (before.stage === "ready" ? 0 : 1) ||
    !isDeepStrictEqual(previous.hashes, next.hashes) ||
    !isDeepStrictEqual(previous.counters, next.counters) ||
    !isDeepStrictEqual(previous.availabilityRetry, next.availabilityRetry) ||
    !isDeepStrictEqual(previous.inactivityRecovery, next.inactivityRecovery)
  )
    return false;

  const invocation = beginWritableRestatement(before, previous.revision);
  if (next.activeTurn !== null) {
    const scope = after?.restatementValidationFingerprint;
    return (
      next.pipelineState.workflowState === resumeState &&
      (scope === undefined || fingerprint(scope)) &&
      isDeepStrictEqual(next.pipelineState, {
        ...previous.pipelineState,
        writableResult: beginWritableRestatement(
          before,
          previous.revision,
          scope,
        ),
      })
    );
  }
  const retained = retiringRestatement
    ? { ...before, stage: "retry-ready" }
    : before;
  return (
    isDeepStrictEqual(next.pipelineState, {
      ...previous.pipelineState,
      workflowState: next.pipelineState.workflowState,
      writableResult: after,
    }) &&
    (isDeepStrictEqual(retained, after) ||
      (before.stage === "ready" && isDeepStrictEqual(after, invocation)))
  );
}

// The journal retains the complete retired checkpoint; this bounded lineage is
// also available to reconstructed prompts after the active checkpoint retires.
export function createRepairReport(checkpoint, result) {
  return {
    step: checkpoint.step,
    phase: "RESOLVE_FINDINGS",
    ...result,
    recovery: {
      checkpointFingerprint: hash(checkpoint),
      candidateFingerprint: checkpoint.candidateFingerprint,
      factsFingerprint: checkpoint.factsFingerprint,
      blockersFingerprint: hash([
        checkpoint.blockers,
        checkpoint.restrictedIds,
      ]),
      attempts: checkpoint.attempts,
      additionalAttempts: checkpoint.additionalAttempts,
      fixRounds: checkpoint.fixRoundsBefore + (checkpoint.fixCharged ? 1 : 0),
      pendingCorrection:
        checkpoint.pendingCorrectionBefore || checkpoint.fixCharged,
      budgetExhausted: checkpoint.budgetExhausted,
      diagnostic: checkpoint.diagnostic,
      previous: checkpoint.repair,
    },
  };
}

export function assertRepairReport(report, reports) {
  const value = report.recovery;
  if (
    !exact(value, [
      "checkpointFingerprint",
      "candidateFingerprint",
      "factsFingerprint",
      "blockersFingerprint",
      "attempts",
      "additionalAttempts",
      "fixRounds",
      "pendingCorrection",
      "budgetExhausted",
      "diagnostic",
      "previous",
    ]) ||
    ![
      value.checkpointFingerprint,
      value.candidateFingerprint,
      value.factsFingerprint,
      value.blockersFingerprint,
    ].every(fingerprint) ||
    ![value.attempts, value.additionalAttempts, value.fixRounds].every(count) ||
    !Number.isSafeInteger(value.additionalAttempts + 1) ||
    value.attempts < value.additionalAttempts ||
    value.attempts > value.additionalAttempts + 1 ||
    typeof value.pendingCorrection !== "boolean" ||
    typeof value.budgetExhausted !== "boolean" ||
    (value.diagnostic !== null &&
      !isDeepStrictEqual(
        value.diagnostic,
        writableResultDiagnostic(
          { diagnostic: value.diagnostic },
          "RESOLVE_FINDINGS",
        ),
      )) ||
    (value.previous !== null &&
      (!count(value.previous) ||
        reports[value.previous]?.status !== "UNFINISHED" ||
        reports[value.previous].step !== report.step))
  )
    throw new PlanExecutionWorkflowError("Invalid unfinished repair history.", {
      code: "ERR_INVALID_PLAN_EXECUTION_STATE",
    });
  if (value.previous !== null) {
    const previous = reports[value.previous].recovery;
    if (
      value.attempts < previous.attempts ||
      value.additionalAttempts < previous.additionalAttempts ||
      value.fixRounds < previous.fixRounds ||
      value.blockersFingerprint !== previous.blockersFingerprint ||
      (previous.pendingCorrection && !value.pendingCorrection)
    )
      throw new PlanExecutionWorkflowError(
        "Unfinished repair history renewed consumed authority.",
        { code: "ERR_INVALID_PLAN_EXECUTION_STATE" },
      );
  }
}

export function rebindWritableRepair(state) {
  return {
    ...state,
    writableResult: {
      ...state.writableResult,
      factsFingerprint: writableResultFacts(state, state.writableResult),
    },
  };
}

export function assertWritableResult(
  state,
  { validateBlockers, validateProductDecision } = {},
) {
  const value = state.writableResult;
  if (value === null) return;
  const invalid = () => {
    throw new PlanExecutionWorkflowError(
      "Invalid writable result checkpoint.",
      {
        code: "ERR_INVALID_PLAN_EXECUTION_STATE",
      },
    );
  };
  // Saved checkpoints may predate invocation-specific expiry evidence.
  const hasRestatementStart = Object.hasOwn(
    value ?? {},
    "restatementStartedAfter",
  );
  const hasRestatementScope = Object.hasOwn(
    value ?? {},
    "restatementValidationFingerprint",
  );
  const fields = [
    ...FIELDS,
    ...(hasRestatementStart ? ["restatementStartedAfter"] : []),
    ...(hasRestatementScope ? ["restatementValidationFingerprint"] : []),
  ];
  if (
    !exact(value, fields) ||
    (hasRestatementScope &&
      (!hasRestatementStart ||
        !fingerprint(value.restatementValidationFingerprint))) ||
    (hasRestatementStart &&
      (!count(value.restatementStartedAfter) ||
        value.restatementStartedAfter === 0 ||
        value.attempts === 0)) ||
    value.schemaVersion !== 2 ||
    !["IMPLEMENT", "RESOLVE_FINDINGS"].includes(value.phase) ||
    ![value.phase, "WAITING_FOR_USER", "FAILED", "CANCELED"].includes(
      state.workflowState,
    ) ||
    value.step !== state.currentStep ||
    !Number.isSafeInteger(value.step) ||
    value.step < 1 ||
    ![
      "prepared",
      "invoking",
      "ready",
      "correcting",
      "retry-ready",
      "inactivity-ready",
      "exhausted",
      "blocked",
      "repair-required",
      "repair-authorized",
    ].includes(value.stage) ||
    ![
      value.beforeFingerprint,
      value.originalContentFingerprint,
      value.factsFingerprint,
    ].every(fingerprint) ||
    !Array.isArray(value.blockers) ||
    value.blockers.length > 32 ||
    value.blockers.some(
      (blocker) =>
        blocker === null ||
        typeof blocker !== "object" ||
        typeof blocker.id !== "string" ||
        !/^[RF][1-9][0-9]{0,8}$/u.test(blocker.id),
    ) ||
    !Array.isArray(value.restrictedIds) ||
    value.restrictedIds.length > 32 ||
    new Set(value.restrictedIds).size !== value.restrictedIds.length ||
    value.restrictedIds.some(
      (id) => !value.blockers.some((blocker) => blocker.id === id),
    ) ||
    typeof value.budgetExhausted !== "boolean" ||
    typeof value.rework !== "boolean" ||
    value.rework !== (state.implementationDirection !== null) ||
    !count(value.fixRoundsBefore) ||
    typeof value.fixCharged !== "boolean" ||
    typeof value.pendingCorrectionBefore !== "boolean" ||
    (["prepared", "invoking"].includes(value.stage) &&
      (value.pendingCorrectionBefore !== state.pendingCorrection ||
        value.beforeFingerprint !== executionContentFingerprint(state))) ||
    (!["prepared", "invoking"].includes(value.stage) &&
      (value.fixCharged !==
        (value.originalContentFingerprint !==
          state.repositoryBaseline?.contentFingerprint &&
          (value.rework ||
            (value.phase === "RESOLVE_FINDINGS" &&
              !value.pendingCorrectionBefore))) ||
        state.pendingCorrection !==
          (value.pendingCorrectionBefore ||
            (value.fixCharged && value.phase === "RESOLVE_FINDINGS")))) ||
    !count(value.attempts) ||
    !count(value.additionalAttempts) ||
    !Number.isSafeInteger(value.additionalAttempts + 1) ||
    value.attempts > value.additionalAttempts + 1 ||
    (value.stage === "invoking" && value.diagnostic !== null) ||
    (!["prepared", "invoking"].includes(value.stage) &&
      value.candidateFingerprint !== executionContentFingerprint(state)) ||
    (["prepared", "invoking"].includes(value.stage) &&
      value.originalContentFingerprint !==
        state.repositoryBaseline?.contentFingerprint) ||
    value.attempts < value.additionalAttempts ||
    (["correcting", "retry-ready", "inactivity-ready"].includes(value.stage) &&
      value.attempts !== value.additionalAttempts + 1) ||
    (value.stage === "inactivity-ready" && !hasRestatementStart) ||
    (value.stage === "exhausted" &&
      value.attempts !== value.additionalAttempts + 1) ||
    (value.stage === "ready" &&
      value.repair === null &&
      value.attempts !== value.additionalAttempts) ||
    (["prepared", "invoking"].includes(value.stage) &&
      (value.candidateFingerprint !== null ||
        value.attempts !==
          (value.repair === null
            ? 0
            : state.workReports[value.repair]?.recovery?.attempts) ||
        value.fixCharged)) ||
    (!["prepared", "invoking"].includes(value.stage) &&
      !fingerprint(value.candidateFingerprint)) ||
    (value.phase === "IMPLEMENT" &&
      (value.blockers.length ||
        value.restrictedIds.length ||
        value.budgetExhausted)) ||
    (value.phase === "RESOLVE_FINDINGS" && !value.blockers.length) ||
    (value.fixCharged && value.phase === "IMPLEMENT" && !value.rework) ||
    (value.diagnostic !== null &&
      !isDeepStrictEqual(
        value.diagnostic,
        writableResultDiagnostic({ diagnostic: value.diagnostic }, value.phase),
      )) ||
    (value.diagnostic !== null &&
      !exact(value.diagnostic, [
        "role",
        "phase",
        "contract",
        "field",
        "constraint",
      ])) ||
    (value.productDecision !== null &&
      (!exact(value.productDecision, [
        "decision",
        "number",
        "expectedHash",
        "resultHash",
      ]) ||
        !["ready", "correcting"].includes(value.stage) ||
        !exact(value.productDecision.decision, [
          "question",
          "options",
          "whyBlocked",
          "evidence",
        ]) ||
        !Number.isSafeInteger(value.productDecision.number) ||
        value.productDecision.number < 1 ||
        !fingerprint(value.productDecision.expectedHash) ||
        (value.productDecision.resultHash !== null &&
          (!fingerprint(value.productDecision.resultHash) ||
            value.productDecision.resultHash ===
              value.productDecision.expectedHash)))) ||
    value.factsFingerprint !== writableResultFacts(state, value) ||
    state.pendingCommit !== null
  )
    invalid();
  if (value.repair !== null) {
    const report = state.workReports[value.repair];
    const previous = report?.recovery;
    if (
      !count(value.repair) ||
      report?.status !== "UNFINISHED" ||
      report.step !== value.step ||
      value.phase !== "RESOLVE_FINDINGS" ||
      previous.blockersFingerprint !==
        hash([value.blockers, value.restrictedIds]) ||
      value.attempts < previous.attempts ||
      value.additionalAttempts < previous.additionalAttempts ||
      value.fixRoundsBefore + (value.fixCharged ? 1 : 0) < previous.fixRounds ||
      (previous.pendingCorrection && !state.pendingCorrection) ||
      (["prepared", "invoking"].includes(value.stage) &&
        (value.budgetExhausted ||
          value.additionalAttempts !== previous.additionalAttempts)) ||
      (!["repair-required", "repair-authorized"].includes(value.stage) &&
        (value.fixRoundsBefore !== previous.fixRounds ||
          value.pendingCorrectionBefore !== previous.pendingCorrection)) ||
      (["repair-required", "repair-authorized"].includes(value.stage) &&
        (value.candidateFingerprint !== previous.candidateFingerprint ||
          value.fixRoundsBefore + (value.fixCharged ? 1 : 0) !==
            previous.fixRounds ||
          value.attempts !== previous.attempts ||
          value.additionalAttempts !== previous.additionalAttempts))
    )
      invalid();
  } else if (["repair-required", "repair-authorized"].includes(value.stage))
    invalid();
  const blockers =
    value.phase === "IMPLEMENT"
      ? []
      : state.finalizationResult?.status === "FAIL"
        ? state.finalizationResult.issues.map((issue) => ({
            ...issue,
            source: "finalization",
          }))
        : state.findings.map((finding) => ({ ...finding, source: "review" }));
  const restrictedIds = blockers
    .filter(
      ({ id }) =>
        state.findingArbitrations.some(
          (entry) =>
            entry.findingId === id && entry.direction === "REVIEWER_CORRECT",
        ) ||
        (state.disputeCounts[id] ?? 0) >= state.settings.maxDisputesPerFinding,
    )
    .map(({ id }) => id);
  if (
    !isDeepStrictEqual(value.blockers, blockers) ||
    !isDeepStrictEqual(value.restrictedIds, restrictedIds)
  )
    invalid();
  validateBlockers?.(value.blockers);
  if (value.productDecision !== null)
    validateProductDecision?.(value.productDecision.decision);
}
