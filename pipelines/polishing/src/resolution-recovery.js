import { isDeepStrictEqual } from "node:util";

import {
  originalResolutionCheckpoint,
  RESOLUTION_CORRECTION_CHECKPOINT,
  upgradeLegacyResolutionCorrection,
} from "./workflow-contract.js";

const provenBackoffs = new WeakSet();
const provenExpiries = new WeakMap();
const RESTATEMENT_BOUNDARY_SCHEMA_VERSION = 28;

export async function prepareResolutionRecovery(run, history) {
  provenBackoffs.delete(run);
  provenExpiries.delete(run);
  const { resolutionCorrection: correction, repositoryBaseline } =
    run.pipelineState;
  if (
    correction?.stage !== "correcting" ||
    correction.productDecision !== null ||
    correction.restatementStartedAfter !== undefined
  )
    return;

  const originalCheckpoint = originalResolutionCheckpoint(correction);
  const matchesRecovery = (recovery) =>
    recovery?.role === "worker" &&
    recovery.contentFingerprint === repositoryBaseline.contentFingerprint &&
    [RESOLUTION_CORRECTION_CHECKPOINT, originalCheckpoint].includes(
      recovery.checkpoint,
    );
  const episode =
    run.activeTurn === null && matchesRecovery(run.availabilityRetry)
      ? run.availabilityRetry
      : null;
  const recovery = run.inactivityRecovery;
  const expiryRevision = matchesRecovery(recovery)
    ? recovery.expiryRevision
    : null;
  if (episode === null && expiryRevision === null) return;

  // Use the latest certified legacy start for both expiry and the separate
  // backoff schedule that could follow retirement.
  let previous = null;
  let previousMatchesCheckpoint = false;
  let invocation = null;
  let retired = false;
  let scheduled = false;
  let expiry = null;
  for await (const { state, activity } of history.events) {
    // Compare in the current shape, using the facts at each historical event.
    const historicalCorrection =
      state.pipelineStateVersion < 25
        ? upgradeLegacyResolutionCorrection(state.pipelineState)
        : state.pipelineState.resolutionCorrection;
    const sameCheckpoint =
      isDeepStrictEqual(historicalCorrection, correction) &&
      isDeepStrictEqual(
        state.pipelineState.repositoryBaseline,
        repositoryBaseline,
      );
    if (!sameCheckpoint || state.activeTurn !== null) scheduled = false;
    if (
      !sameCheckpoint ||
      (state.activeTurn !== null &&
        (activity?.kind === "turn-started" ||
          !isDeepStrictEqual(state.activeTurn, previous?.activeTurn)))
    )
      expiry = null;

    if (
      state.schemaVersion >= RESTATEMENT_BOUNDARY_SCHEMA_VERSION ||
      !sameCheckpoint ||
      state.pipelineState.workflowState !== "RESOLVE_FINDINGS" ||
      state.pause !== null
    ) {
      invocation = null;
      retired = false;
    } else if (activity?.kind === "turn-started") {
      const isRestatement =
        previous?.activeTurn === null &&
        previous.pipelineState.workflowState === "RESOLVE_FINDINGS" &&
        previousMatchesCheckpoint &&
        state.activeTurn?.role === "worker" &&
        state.activeTurn.phase === "resolve-findings" &&
        activity.actor === "worker" &&
        activity.phase === "resolve-findings";
      invocation = isRestatement ? state.revision : null;
      retired = false;
    } else if (previous?.activeTurn != null && state.activeTurn === null) {
      retired = invocation !== null && activity === null;
      invocation = null;
    } else if (
      state.activeTurn !== null &&
      !isDeepStrictEqual(state.activeTurn, previous?.activeTurn)
    ) {
      invocation = null;
      retired = false;
    }

    if (state.revision === expiryRevision && invocation !== null) {
      const attempt = previous.observations?.attempts.at(-1);
      const expired = state.inactivityRecovery;
      if (
        activity?.actor === "worker" &&
        activity.phase === "inactivity" &&
        activity.kind === "expired" &&
        matchesRecovery(expired) &&
        expired.checkpoint === recovery.checkpoint &&
        (expired.checkpoint !== originalCheckpoint ||
          [previous.availabilityRetry, previous.inactivityRecovery].some(
            (retained) =>
              retained?.role === "worker" &&
              retained.checkpoint === originalCheckpoint,
          )) &&
        attempt?.status === "active" &&
        attempt.id > invocation &&
        attempt.role === expired.role &&
        attempt.checkpoint === expired.checkpoint &&
        isDeepStrictEqual(previous.observations, state.observations)
      )
        expiry = { startedAfter: invocation - 1, attemptId: attempt.id };
    }
    if (episode !== null && state.revision === episode.reconciledRevision + 1) {
      scheduled =
        retired &&
        state.activeTurn === null &&
        activity?.kind === "retry-scheduled" &&
        activity.phase === "availability" &&
        activity.actor === episode.role &&
        isDeepStrictEqual(state.availabilityRetry, episode);
    }
    previous = state;
    previousMatchesCheckpoint = sameCheckpoint;
  }
  if (scheduled) provenBackoffs.add(run);
  if (expiry !== null) provenExpiries.set(run, expiry);
}

export function hasLegacyResolutionBackoff(run) {
  return provenBackoffs.has(run);
}

export function legacyResolutionExpiryStart(run, currentRun) {
  const expiry = provenExpiries.get(run);
  if (
    expiry !== undefined &&
    currentRun.inactivityRecovery?.expiryRevision ===
      run.inactivityRecovery.expiryRevision &&
    currentRun.observations?.attempts.at(-1).id === expiry.attemptId &&
    isDeepStrictEqual(
      currentRun.pipelineState.resolutionCorrection,
      run.pipelineState.resolutionCorrection,
    ) &&
    isDeepStrictEqual(
      currentRun.pipelineState.repositoryBaseline,
      run.pipelineState.repositoryBaseline,
    )
  )
    return expiry.startedAfter;
}
