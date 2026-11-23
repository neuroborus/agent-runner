import {
  CATALOG_VALIDATED_MODEL,
  CodexAdapterError,
  normalizeAdapterFailure,
} from "../../src/agents/index.js";

export function modelCatalogMiss({
  access = "read-only",
  recovery = false,
} = {}) {
  return new CodexAdapterError("Catalog lookup failed.", {
    code: "ERR_CODEX_MODEL_UNAVAILABLE",
    diagnosticClass: "model_unavailable",
    noTurnEffect: !recovery,
    ...(access === "local-commit" ? { effectStarted: false } : {}),
  });
}

export function withModelCompletion(response, request) {
  return { ...response, [CATALOG_VALIDATED_MODEL]: request.model };
}

export async function recordCompletedModelTurn(
  store,
  lease,
  turn,
  preferences,
) {
  const started = await store.startObservationAttempt(lease, {
    role: turn.role,
    checkpoint: `${turn.phase}:model-completion`,
  });
  const { id, role, checkpoint } = started.observations.attempts.at(-1);
  await store.recordObservationBatch(lease, { id, role, checkpoint }, [], {
    status: "completed",
  });
  return store.recordModelCompletion(lease, role, preferences);
}

// A read-only gate pause retires the sole failed attempt of a later invocation.
export async function recordReadOnlyCatalogMiss(
  store,
  lease,
  turn,
  { activity, checkpoint, nextTurn = turn },
) {
  await store.finishAgentTurn(lease, turn);
  await store.startAgentTurn(lease, nextTurn, {
    activity: { ...activity, phase: nextTurn.phase },
  });
  const started = await store.startObservationAttempt(lease, {
    role: turn.role,
    checkpoint,
  });
  const { id } = started.observations.attempts.at(-1);
  return store.recordObservationBatch(
    lease,
    { id, role: turn.role, checkpoint },
    [],
    {
      status: "failed",
      readOnlyRejection: normalizeAdapterFailure("codex", modelCatalogMiss())
        .failure,
    },
  );
}
