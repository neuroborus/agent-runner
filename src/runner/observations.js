import { normalizeProviderObservation } from "../agents/index.js";
import { RunnerError } from "./input.js";

// Adapters publish sealed native turns synchronously. Batch their bounded facts
// at fallback and terminal boundaries rather than writing per notification.
export async function runObservedAttempt({
  runStore,
  lease,
  role,
  checkpoint,
  request,
  operation,
  persist = (write) => write(),
}) {
  const started = await persist(() =>
    runStore.startObservationAttempt(lease, { role, checkpoint }),
  );
  const { id } = started.observations.attempts.at(-1);
  const identity = { id, role, checkpoint };
  const records = new Map();
  let incomplete = false;
  let closed = false;
  let failure;
  let response;
  function onObservation(value) {
    if (closed) return;
    try {
      const normalized = normalizeProviderObservation(value);
      const key = `${normalized.attempt}:${normalized.turn}`;
      if (!records.has(key)) records.set(key, normalized);
    } catch {
      incomplete = true;
    }
  }
  async function flush(status) {
    await persist(() =>
      runStore.recordObservationBatch(lease, identity, [...records.values()], {
        status,
        incomplete,
      }),
    );
  }
  try {
    response = await operation({
      ...request,
      onObservation,
      onFreshSession: async () => {
        try {
          await flush("active");
        } catch {
          // Retry/effect authority stays with the existing recovery policy.
          // The terminal flush retries all available bounded evidence.
        }
        return request.onFreshSession?.();
      },
    });
  } catch (cause) {
    failure = cause;
  } finally {
    closed = true;
    try {
      await flush(
        request.signal?.aborted
          ? "interrupted"
          : failure === undefined
            ? "completed"
            : "failed",
      );
    } catch {
      // An established provider, effect, ownership, or safety failure wins.
      failure ??= new RunnerError(
        "Attempt observations could not be persisted.",
        { code: "ERR_OBSERVATION_PERSISTENCE" },
      );
    }
  }
  if (failure !== undefined) throw failure;
  return response;
}
