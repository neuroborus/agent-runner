import { isDeepStrictEqual } from "node:util";

import { ownershipDiagnosticFrom } from "../platform/index.js";
import {
  AgentBoundaryError,
  MODEL_UNAVAILABLE_DIAGNOSTIC,
  normalizeFailureRecord,
  normalizeProviderObservation,
} from "../agents/index.js";
import { observationActivity } from "../state/index.js";
import { RunnerError } from "./input.js";

// The attempt keeps the normalized rejection for its actual access, even
// when a read-only restatement uses its original writable recovery checkpoint.
function catalogRejectionFrom(cause, { access, session }) {
  if (
    !["local-commit", "workspace-write", "read-only"].includes(access) ||
    (access === "read-only" && session?.mode === "fork") ||
    !(cause instanceof AgentBoundaryError) ||
    cause.failure?.failureClass !== MODEL_UNAVAILABLE_DIAGNOSTIC
  )
    return undefined;
  let failure;
  try {
    failure = normalizeFailureRecord(cause.failure, [
      MODEL_UNAVAILABLE_DIAGNOSTIC,
    ]);
  } catch {
    return undefined;
  }
  if (
    failure.outcome !== "rejected" ||
    failure.effect !== "none" ||
    failure.retry !== "terminal"
  )
    return undefined;
  if (access === "local-commit") {
    return failure.checkpoint === "commit" &&
      failure.commitExecutor === "not_started" &&
      Object.keys(failure).length === 6
      ? { commitRejection: failure }
      : undefined;
  }
  if (failure.checkpoint !== "turn" || Object.keys(failure).length !== 5)
    return undefined;
  return access === "workspace-write"
    ? {
        writableRejection: failure,
        ...(session?.mode === "fork" ? {} : { writableRetryEligible: true }),
      }
    : { readOnlyRejection: failure };
}

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
  isInterrupted = () => request.signal?.aborted === true,
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
    const ownershipDiagnostic = ["failed", "interrupted"].includes(status)
      ? ownershipDiagnosticFrom(failure)
      : null;
    const catalogRejection =
      status === "failed" ? catalogRejectionFrom(failure, request) : undefined;
    const next = await persist(() =>
      runStore.recordObservationBatch(lease, identity, [...records.values()], {
        status,
        incomplete,
        ...(ownershipDiagnostic === null ? {} : { ownershipDiagnostic }),
        ...catalogRejection,
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
        isInterrupted(failure)
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
