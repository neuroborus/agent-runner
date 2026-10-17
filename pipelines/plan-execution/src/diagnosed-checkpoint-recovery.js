import { isDeepStrictEqual } from "node:util";

import { clearedCandidateAndTerminalGate } from "./gate-evidence.js";

// Status holds no durable authority. Every resumed run must prove its chain
// again from the state-owned journal under the normal execution leases.
const provenRuns = new WeakMap();
const TURN = Object.freeze({ role: "worker", phase: "check-and-fix" });
const FAILURE_FIELDS = Object.freeze([
  "failureClass",
  "checkpoint",
  "outcome",
  "effect",
  "retry",
  "reconstruction",
]);

function exact(value, fields) {
  return (
    value !== null &&
    typeof value === "object" &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value)) &&
    Reflect.ownKeys(value).length === fields.length &&
    fields.every((field) => Object.hasOwn(value, field))
  );
}

export function validDiagnosedCheckpoint(value) {
  const failure = value?.failure;
  return (
    exact(value, [
      "schemaVersion",
      "turnRevision",
      "fixRoundCharged",
      "failure",
    ]) &&
    value.schemaVersion === 1 &&
    Number.isSafeInteger(value.turnRevision) &&
    value.turnRevision > 0 &&
    typeof value.fixRoundCharged === "boolean" &&
    exact(failure, FAILURE_FIELDS) &&
    typeof failure.failureClass === "string" &&
    /^[a-z][a-z0-9_]{0,63}$/u.test(failure.failureClass) &&
    failure.checkpoint === "turn" &&
    failure.outcome === "rejected" &&
    failure.effect === "possible" &&
    failure.retry === "terminal" &&
    exact(failure.reconstruction, ["schemaVersion", "kind"]) &&
    failure.reconstruction.schemaVersion === 1 &&
    failure.reconstruction.kind === "completed_turn_acquisition"
  );
}

function eligibleState(run) {
  const state = run.pipelineState;
  return (
    state.settings?.mode === "lazy" &&
    state.preflightComplete &&
    state.clarificationFrozen &&
    state.stepImplementation?.accepted === true &&
    !state.compatibilityCheckRequired &&
    !state.validationMigrationPending &&
    !state.candidateMigrationPending &&
    run.activeTurn === null &&
    run.executionProcess === null &&
    run.executionResource === null &&
    run.availabilityRetry == null &&
    run.inactivityRecovery == null &&
    (run.stopRequest == null || run.stopRequest.reconciledRevision !== null) &&
    [
      "pendingCommit",
      "pendingEdit",
      "pendingBootstrapCorrection",
      "pendingFinalizationCorrection",
      "pendingReviewCorrection",
      "pendingConfirmationCorrection",
      "implementationDirection",
      "stagnationDirection",
      "authenticationSourceForkRecovery",
    ].every((field) => state[field] === null) &&
    state.pendingDisputes.length === 0 &&
    !state.finalizationRecovery.required &&
    !state.finalizationRecovery.pending &&
    state.finalizationRecovery.feedback === null
  );
}

export function diagnosedCheckpointFor(
  run,
  cause,
  turnRevision,
  fixRoundCharged,
) {
  const value = {
    schemaVersion: 1,
    turnRevision,
    fixRoundCharged,
    failure: cause?.failure,
  };
  return run.pipelineState.workflowState === "CHECK_AND_FIX" &&
    eligibleState(run) &&
    validDiagnosedCheckpoint(value) &&
    cause?.diagnosticClass === value.failure.failureClass &&
    cause?.ambiguous === false &&
    cause?.recoverable === false
    ? structuredClone(value)
    : null;
}

function without(value, fields) {
  return Object.fromEntries(
    Object.entries(value).filter(([field]) => !fields.includes(field)),
  );
}

function bindings(run) {
  return {
    root: without(run, [
      "revision",
      "updatedAt",
      "activeTurn",
      "executionProcess",
      "executionResource",
      "pipelineState",
      "counters",
      "pause",
    ]),
    state: without(run.pipelineState, [
      "workflowState",
      "diagnosedCheckpoint",
      "repositoryBaseline",
      ...Object.keys(clearedCandidateAndTerminalGate()),
      "previousFindings",
      "findings",
      "reviewReconsideration",
      "pendingCorrection",
      "availabilityCorrectionCharged",
      "finalizationRecovery",
    ]),
    git: without(run.pipelineState.repositoryBaseline, [
      "fingerprint",
      "clean",
      "contentFingerprint",
      "trackedContentFingerprint",
      "untrackedContentFingerprint",
    ]),
    counters: without(run.counters, ["fixRounds"]),
  };
}

export function prepareDiagnosedCheckpointRecovery(run, history, migrate) {
  provenRuns.delete(run);
  const checkpoint = run.pipelineState.diagnosedCheckpoint;
  if (
    !validDiagnosedCheckpoint(checkpoint) ||
    !eligibleState(run) ||
    run.pipelineState.workflowState !== "FAILED" ||
    run.pause?.reason !== "internal_failure" ||
    !exact(run.pause, ["reason", "code", "diagnosticClass"]) ||
    run.pause.diagnosticClass !== checkpoint.failure.failureClass
  )
    return;
  try {
    if (
      !Array.isArray(history.events) ||
      history.events.length < 3 ||
      !isDeepStrictEqual(history.events.at(-1).state, history.run) ||
      !isDeepStrictEqual(migrate(history.run), run)
    )
      return;
    const events = history.events.map((event, index) => {
      if (
        event.revision !== index + 1 ||
        event.state.revision !== event.revision ||
        event.runId !== run.runId
      )
        throw new Error("Discontinuous journal.");
      return { ...event, state: migrate(event.state) };
    });
    // Detached admission records correlation before checkpoint continuation.
    // These events may follow the failure but cannot change any saved binding.
    while (events.length > 1) {
      const event = events.at(-1);
      const previous = events.at(-2).state;
      if (
        event.activity?.actor !== "runner" ||
        event.activity.phase !== "recovery" ||
        !["dispatch-started", "dispatch-ready"].includes(event.activity.kind) ||
        !isDeepStrictEqual(
          without(event.state, ["revision", "updatedAt"]),
          without(previous, ["revision", "updatedAt"]),
        )
      )
        break;
      events.pop();
    }
    if (
      events[0].state.pipelineState.workflowState !== "CLARIFY" ||
      events[0].state.pipelineState.preflightComplete ||
      events[0].state.activeTurn !== null
    )
      return;
    const start = events[checkpoint.turnRevision - 1];
    const before = events[checkpoint.turnRevision - 2]?.state;
    if (
      !start ||
      !before ||
      before.activeTurn !== null ||
      start.activity?.kind !== "turn-started" ||
      start.activity.actor !== "worker" ||
      start.activity.phase !== "check-and-fix" ||
      start.state.pipelineState.workflowState !== "CHECK_AND_FIX" ||
      !isDeepStrictEqual(start.state.activeTurn, TURN) ||
      start.state.pipelineState.diagnosedCheckpoint !== null
    )
      return;
    const initial = start.state;
    if (!eligibleState({ ...initial, activeTurn: null })) return;
    const binding = bindings(initial);
    if (
      before.pipelineState.workflowState !== "CHECK_AND_FIX" ||
      !eligibleState(before) ||
      !isDeepStrictEqual(bindings(before), binding) ||
      !isDeepStrictEqual(before.counters, initial.counters) ||
      initial.pause !== null
    )
      return;
    const chargedBefore =
      initial.pipelineState.availabilityCorrectionCharged ||
      initial.pipelineState.pendingLazyCorrection?.fixRoundCharged === true;
    let finished = false;
    let changed = false;
    let previous = initial;
    for (const event of events.slice(checkpoint.turnRevision)) {
      const current = event.state;
      const final = event === events.at(-1);
      if (
        !isDeepStrictEqual(bindings(current), binding) ||
        (current.pause !== null && !final) ||
        current.pipelineState.workflowState !==
          (final ? "FAILED" : "CHECK_AND_FIX") ||
        (final
          ? !isDeepStrictEqual(
              current.pipelineState.diagnosedCheckpoint,
              checkpoint,
            )
          : current.pipelineState.diagnosedCheckpoint !== null)
      )
        return;
      if (finished && current.activeTurn !== null) return;
      if (
        finished &&
        (current.executionProcess !== null ||
          current.executionResource !== null)
      )
        return;
      if (
        finished &&
        !final &&
        (!isDeepStrictEqual(current.pipelineState, previous.pipelineState) ||
          !isDeepStrictEqual(current.counters, previous.counters))
      )
        return;
      if (
        final &&
        !isDeepStrictEqual(current.pipelineState, {
          ...previous.pipelineState,
          workflowState: "FAILED",
          diagnosedCheckpoint: checkpoint,
        })
      )
        return;
      if (!finished && current.activeTurn === null) {
        if (
          !isDeepStrictEqual(previous.activeTurn, TURN) ||
          current.executionProcess !== null ||
          current.executionResource !== null ||
          !isDeepStrictEqual(current.pipelineState, previous.pipelineState) ||
          !isDeepStrictEqual(current.counters, previous.counters)
        )
          return;
        finished = true;
      } else if (!finished && !isDeepStrictEqual(current.activeTurn, TURN))
        return;
      if (
        current.pipelineState.repositoryBaseline.contentFingerprint !==
        previous.pipelineState.repositoryBaseline.contentFingerprint
      ) {
        if (finished || changed) return;
        changed = true;
      }
      if (
        current.counters.fixRounds !==
        initial.counters.fixRounds + (changed && !chargedBefore ? 1 : 0)
      )
        return;
      previous = current;
    }
    const charge = changed && !chargedBefore ? 1 : 0;
    const pending = initial.pipelineState.pendingLazyCorrection;
    if (
      pending !== null &&
      (!isDeepStrictEqual(
        without(pending, ["fixRoundCharged"]),
        without(run.pipelineState.pendingLazyCorrection ?? {}, [
          "fixRoundCharged",
        ]),
      ) ||
        !isDeepStrictEqual(
          initial.pipelineState.lazyCorrections.map((entry) =>
            without(entry, ["fixRoundCharged"]),
          ),
          run.pipelineState.lazyCorrections.map((entry) =>
            without(entry, ["fixRoundCharged"]),
          ),
        ) ||
        run.pipelineState.pendingLazyCorrection.fixRoundCharged !==
          (pending.fixRoundCharged || changed))
    )
      return;
    if (
      !finished ||
      run.counters.fixRounds !== initial.counters.fixRounds + charge ||
      checkpoint.fixRoundCharged !== (chargedBefore || changed) ||
      (checkpoint.fixRoundCharged && !run.pipelineState.pendingCorrection) ||
      (!checkpoint.fixRoundCharged &&
        run.counters.fixRounds >=
          run.pipelineState.settings.maxFixRoundsPerStep +
            run.pipelineState.additionalFixRounds) ||
      events.at(-1).activity?.kind !== "failed" ||
      events.at(-1).activity?.actor !== "runner" ||
      events.at(-1).activity?.phase !== "plan-execution" ||
      events.at(-1).activity?.message !==
        `Plan execution failed: ${run.pause.code} (${checkpoint.failure.failureClass}).`
    )
      return;
    provenRuns.set(run, structuredClone(run));
  } catch {
    // Snapshot metadata and migrations cannot invent missing journal authority.
  }
}

export function canRecoverDiagnosedCheckpoint(run) {
  return provenRuns.has(run) && isDeepStrictEqual(provenRuns.get(run), run);
}
