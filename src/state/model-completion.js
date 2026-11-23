import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";

export const MODEL_CATALOG_RETRY_CODE = "ERR_MODEL_CATALOG_RETRY";
const MODEL_COMPLETION_SCHEMA_VERSION = 28;

export function modelCompletionFingerprint(role, configuration) {
  if (
    configuration === undefined ||
    typeof configuration.model !== "string" ||
    !configuration.model ||
    configuration.model === "current"
  )
    return null;
  return createHash("sha256")
    .update(
      JSON.stringify([
        role,
        configuration.backend,
        configuration.profile,
        configuration.model,
        configuration.effort,
      ]),
    )
    .digest("hex");
}

export function normalizeModelCompletions(value, roles, version) {
  if (version < MODEL_COMPLETION_SCHEMA_VERSION && value === undefined)
    return {};
  if (
    value === null ||
    typeof value !== "object" ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  )
    throw new TypeError("Model completion receipts must be a role map.");
  const entries = Object.entries(value);
  if (
    (version < MODEL_COMPLETION_SCHEMA_VERSION && entries.length !== 0) ||
    entries.some(
      ([role, receipt]) =>
        !Object.hasOwn(roles, role) ||
        typeof receipt !== "string" ||
        receipt !== modelCompletionFingerprint(role, roles[role]),
    )
  )
    throw new TypeError(
      "Model completion receipt has an invalid role binding.",
    );
  return Object.fromEntries(entries);
}

export function hasCompletedModelAttempt(run, role, turnStart) {
  const attempt = run.observations?.attempts.at(-1);
  return (
    run.activeTurn?.role === role &&
    run.preparation === null &&
    run.executionProcess === null &&
    run.executionResource === null &&
    turnStart != null &&
    attempt?.status === "completed" &&
    attempt.role === role &&
    attempt.id > turnStart.previousRevision + 1
  );
}

function catalogResumeBinding(pause) {
  if (pause?.reason === "operator_paused") pause = pause.operatorResume?.pause;
  if (pause?.code !== MODEL_CATALOG_RETRY_CODE) return null;
  const { role, checkpoint, resumeState } = pause;
  return { role, checkpoint, resumeState };
}

function catalogResumeState(run) {
  const checkpoint =
    run.pause?.reason === "operator_paused"
      ? run.pause.operatorResume
      : { pause: run.pause, workflowState: run.pipelineState.workflowState };
  if (checkpoint.pause === null) return checkpoint.workflowState;
  const { pause } = checkpoint;
  const inspectionUnavailable =
    run.pipelineId === "init" &&
    pause.reason === "init_inspection_failed" &&
    pause.inspectionFailure?.constraint === "inspection_unavailable";
  return pause.reason === "environment_blocked" || inspectionUnavailable
    ? (pause.resumeState ?? null)
    : null;
}

export function nextCatalogResume(previous, next) {
  if (next.activeTurn !== null) return null;
  const binding =
    previous.modelCatalogResume ?? catalogResumeBinding(previous.pause);
  return binding !== null && catalogResumeState(next) === binding.resumeState
    ? binding
    : null;
}

export function normalizeCatalogResume(run, value) {
  if (value === null || value === undefined) return null;
  if (
    typeof value !== "object" ||
    Object.keys(value).sort().join(",") !== "checkpoint,resumeState,role" ||
    run.schemaVersion < MODEL_COMPLETION_SCHEMA_VERSION ||
    typeof value.role !== "string" ||
    !Object.hasOwn(run.modelCompletionReceipts, value.role) ||
    typeof value.checkpoint !== "string" ||
    !/^[A-Za-z][A-Za-z0-9:._-]{0,127}$/u.test(value.checkpoint) ||
    typeof value.resumeState !== "string" ||
    catalogResumeState(run) !== value.resumeState ||
    run.activeTurn !== null ||
    run.preparation !== null ||
    run.executionProcess !== null ||
    run.executionResource !== null
  )
    throw new TypeError("Model catalog resume has an invalid checkpoint.");
  return {
    role: value.role,
    checkpoint: value.checkpoint,
    resumeState: value.resumeState,
  };
}

function matchesCatalogTurn(
  binding,
  previous,
  next,
  { activity, catalogCheckpoint },
  matchesCatalogReservation,
) {
  const turn = next.activeTurn;
  return (
    catalogCheckpoint === binding.checkpoint &&
    binding.checkpoint.startsWith(`${turn.phase}:`) &&
    (matchesCatalogReservation(previous, next, binding) ??
      (!binding.checkpoint.startsWith(`${turn.phase}:read-only:`) ||
        isDeepStrictEqual(previous.pipelineState, next.pipelineState))) &&
    turn.role === binding.role &&
    activity?.actor === turn.role &&
    activity.phase === turn.phase &&
    activity.kind === "turn-started"
  );
}

export function matchesCatalogResumeTransition(
  previous,
  next,
  retainedBinding,
  evidence,
  matchesCatalogReservation,
) {
  const binding = previous.modelCatalogResume;
  const pausedBinding = catalogResumeBinding(previous.pause);
  const frozenBinding = binding ?? pausedBinding;
  if (
    frozenBinding !== null &&
    !isDeepStrictEqual(previous.hashes, next.hashes)
  )
    return false;
  if (next.activeTurn !== null) {
    if (binding !== null)
      return (
        matchesCatalogReservation !== null &&
        matchesCatalogTurn(
          binding,
          previous,
          next,
          evidence,
          matchesCatalogReservation,
        )
      );
    // Accept the pause in a separate transition before admitting any turn.
    if (pausedBinding !== null) return false;
  }
  if (frozenBinding !== null && retainedBinding === null) {
    const resumeState = catalogResumeState(next);
    if (resumeState !== null && resumeState !== "CANCELED") return false;
  }
  const nextPausedBinding = catalogResumeBinding(next.pause);
  // Returning to a pause before dispatch cannot replace the pending retry.
  const continuingPause = frozenBinding !== null && nextPausedBinding !== null;
  if (continuingPause && !isDeepStrictEqual(frozenBinding, nextPausedBinding))
    return false;
  const reservation = continuingPause ? frozenBinding : retainedBinding;
  return (
    evidence.catalogCheckpoint === undefined &&
    (reservation === null ||
      (matchesCatalogReservation !== null &&
        matchesCatalogReservation(previous, next, reservation) !== false))
  );
}

function failedCatalogAttempt(run, turnStart) {
  const attempts = run.observations?.attempts ?? [];
  const attempt = attempts.at(-1);
  const turn = run.activeTurn;
  if (
    turnStart == null ||
    turn === null ||
    run.preparation !== null ||
    run.executionProcess !== null ||
    run.executionResource !== null ||
    attempt?.status !== "failed" ||
    attempt.role !== turn.role
  )
    return null;
  const turnStartedAt = turnStart.previousRevision + 1;
  return attempt.id > turnStartedAt &&
    (attempts.at(-2)?.id ?? 0) <= turnStartedAt
    ? attempt
    : null;
}

// Initial turns record the logical checkpoint on the attempt. A catalog retry
// also records its expected checkpoint at turn start.
export function writableCatalogAttempt(run, turnStart, checkpoint) {
  const attempt = failedCatalogAttempt(run, turnStart);
  return attempt?.writableRejection !== undefined &&
    attempt.checkpoint.startsWith(`${run.activeTurn.phase}:workspace-write:`) &&
    (checkpoint === undefined || attempt.checkpoint === checkpoint) &&
    (turnStart.catalogCheckpoint === undefined ||
      attempt.checkpoint === turnStart.catalogCheckpoint)
    ? attempt
    : null;
}

export function readOnlyCatalogAttempt(run, turnStart) {
  const attempt = failedCatalogAttempt(run, turnStart);
  return attempt?.readOnlyRejection === undefined ? null : attempt;
}

export function assertCatalogPauseRetirement(
  previous,
  current,
  pipelineVerified,
) {
  const pause = current.pause?.operatorResume?.pause ?? current.pause;
  const binding = catalogResumeBinding(pause);
  const prior =
    previous.modelCatalogResume ??
    catalogResumeBinding(
      previous.pause?.operatorResume?.pause ?? previous.pause,
    );
  if (binding === null || isDeepStrictEqual(prior, binding)) return;

  // COMMIT validates its consumed authorization and Git reconciliation in
  // the owning descriptor. The active turn may already have retired.
  if (binding.checkpoint.startsWith("commit:")) {
    if (pipelineVerified === true) return;
    throw new TypeError("Model catalog pause has no consumed commit proof.");
  }

  const { role, resumeState } = binding;
  if (
    previous.activeTurn?.role !== role ||
    current.activeTurn !== null ||
    current.pause.operatorResume?.activeTurn != null ||
    previous.pipelineState.workflowState !== resumeState ||
    (current.pause.operatorResume?.workflowState ??
      current.pipelineState.workflowState) !== "WAITING_FOR_USER" ||
    !Object.hasOwn(previous.modelCompletionReceipts, role) ||
    !isDeepStrictEqual(previous.hashes, current.hashes) ||
    pipelineVerified !== true
  )
    throw new TypeError(
      "Model catalog pause has no matching invocation retirement.",
    );
}

function matchesWritableCatalogRejection(previous, current, proof, turnStart) {
  const next = catalogResumeBinding(
    current.pause?.operatorResume?.pause ?? current.pause,
  );
  const prior =
    previous.modelCatalogResume ??
    catalogResumeBinding(
      previous.pause?.operatorResume?.pause ?? previous.pause,
    );
  const access = next?.checkpoint.split(":")[1];
  // An accepted retry can return to its pause before another invocation starts.
  if (access !== "workspace-write" || isDeepStrictEqual(prior, next))
    return proof === undefined;
  const attempt = writableCatalogAttempt(previous, turnStart, next.checkpoint);
  return (
    attempt?.role === next.role &&
    attempt.writableRetryEligible === true &&
    isDeepStrictEqual(proof, {
      attemptId: attempt.id,
      failure: attempt.writableRejection,
    })
  );
}

export function assertModelCompletionContinuity(
  previous,
  current,
  evidence,
  matchesCatalogReservation,
  activeTurnStart,
) {
  if (
    !isDeepStrictEqual(
      nextCatalogResume(previous, current),
      current.modelCatalogResume,
    ) ||
    !matchesCatalogResumeTransition(
      previous,
      current,
      current.modelCatalogResume,
      evidence,
      matchesCatalogReservation,
    ) ||
    !matchesWritableCatalogRejection(
      previous,
      current,
      evidence.writableCatalogRejection,
      activeTurnStart,
    )
  )
    throw new TypeError("Model catalog resume history is inconsistent.");
  const { activity } = evidence;
  const before = previous.modelCompletionReceipts;
  const after = current.modelCompletionReceipts;
  if (isDeepStrictEqual(before, after)) return;
  const role = previous.activeTurn?.role;
  if (
    role === undefined ||
    !hasCompletedModelAttempt(previous, role, activeTurnStart) ||
    Object.hasOwn(before, role) ||
    after[role] === undefined ||
    !isDeepStrictEqual({ ...before, [role]: after[role] }, after) ||
    !isDeepStrictEqual(current, {
      ...previous,
      modelCompletionReceipts: after,
      revision: current.revision,
      updatedAt: current.updatedAt,
    }) ||
    activity?.actor !== "runner" ||
    activity.phase !== "runtime" ||
    activity.kind !== "model-completion-recorded"
  )
    throw new TypeError("Model completion receipt history is inconsistent.");
}
