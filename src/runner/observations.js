import { isDeepStrictEqual } from "node:util";

import { normalizeProviderObservation } from "../agents/index.js";
import { observationActivity } from "../state/index.js";
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
  publish = async () => {},
}) {
  const bytes = (value) =>
    typeof value === "string" ? Buffer.byteLength(value, "utf8") : null;
  const jsonBytes = (value) => {
    try {
      return value == null ? null : bytes(JSON.stringify(value));
    } catch {
      return null;
    }
  };
  const started = await persist(
    () =>
      runStore.startObservationAttempt(
        lease,
        { role, checkpoint },
        {
          promptBytes: bytes(request.prompt),
          recoveryPromptBytes: bytes(request.recoveryPrompt ?? request.prompt),
          schemaBytes: jsonBytes(request.schema),
          resultBytes: null,
          structuredResultBytes: null,
          referencedFileCount: null,
          referencedFileBytes: null,
        },
      ),
    "start",
  );
  await publish(
    observationActivity(started.observations.attempts.at(-1)),
    started,
  );
  let publishedAttempt = started.observations.attempts.at(-1);
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
    const next = await persist(() =>
      runStore.recordObservationBatch(lease, identity, [...records.values()], {
        status,
        incomplete,
        ...(status === "completed"
          ? {
              resultBytes: bytes(response?.output),
              structuredResultBytes: jsonBytes(response?.structured),
            }
          : {}),
      }),
    );
    const latest = next?.observations.attempts.at(-1);
    if (
      latest?.id === id &&
      latest.status === status &&
      !isDeepStrictEqual(latest, publishedAttempt)
    ) {
      publishedAttempt = latest;
      await publish(observationActivity(latest), next);
    }
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
      failure ??= request.signal?.aborted
        ? request.signal.reason
        : new RunnerError("Attempt observations could not be persisted.", {
            code: "ERR_OBSERVATION_PERSISTENCE",
          });
    }
  }
  if (failure !== undefined) throw failure;
  return response;
}
