import { isDeepStrictEqual } from "node:util";

import { assertRunCanAdvance, stopIsPending } from "./stop-policy.js";
import {
  assertRunId,
  deepFreeze,
  normalizeRunState,
  normalizePublicActivity,
  normalizeTransitionPatch,
  RUNTIME_COMPATIBILITY,
  RUN_STATE_SCHEMA_VERSION,
  RunStoreError,
} from "./validation.js";

const KINDS = new Map([
  ["pause_requested", "run_pause"],
  ["cancel_requested", "run_cancel"],
]);
const TERMINAL_STATES = new Set(["DONE", "FAILED", "CANCELED"]);

function reject(message, code) {
  throw new RunStoreError(message, { code });
}

function receipt(runId, request) {
  return {
    runId,
    requestId: request.requestId,
    kind: request.kind,
    expectedRevision: request.expectedRevision,
    revision: request.acceptedRevision,
  };
}

export function createStopService({
  actions,
  getRunDirectory,
  loadSnapshot,
  journal,
  mutate,
  runLeases,
  timestamp,
}) {
  async function request(input) {
    if (
      input === null ||
      typeof input !== "object" ||
      Array.isArray(input) ||
      Object.keys(input).length !== 4 ||
      Object.keys(input).some(
        (field) =>
          !["runId", "kind", "expectedRevision", "idempotencyKey"].includes(
            field,
          ),
      ) ||
      !KINDS.has(input.kind) ||
      !Number.isSafeInteger(input.expectedRevision) ||
      input.expectedRevision < 1
    ) {
      reject("Operator stop request is invalid.", "ERR_INVALID_STOP_REQUEST");
    }
    const { runId, kind, expectedRevision, idempotencyKey } = input;
    assertRunId(runId);
    const directory = await getRunDirectory(runId);
    await loadSnapshot(directory, runId);
    const action = await actions.begin({
      key: idempotencyKey,
      tool: KINDS.get(kind),
      arguments: { runId, expectedRevision },
      context: { runId },
    });
    try {
      if (action.record.status === "completed")
        return deepFreeze(structuredClone(action.record.result));
      const result = await mutate(directory, async () => {
        const snapshot = await loadSnapshot(directory, runId);
        const requestId = action.record.keyHash;
        // The journal proves acceptance even if receipt publication was interrupted,
        // a competing cancellation won, or the pipeline has since terminated.
        const accepted = snapshot.events.find(
          (event) =>
            event.state.stopRequest?.requestId === requestId &&
            event.state.stopRequest.acceptedRevision === event.revision,
        );
        if (accepted !== undefined)
          return receipt(runId, accepted.state.stopRequest);
        const current = snapshot.state;
        if (
          TERMINAL_STATES.has(current.pipelineState.workflowState) ||
          (current.stopRequest?.kind === "cancel_requested" &&
            !stopIsPending(current))
        ) {
          reject(
            "Terminal runs do not accept new stop requests.",
            "ERR_RUN_TERMINAL",
          );
        }
        if (current.pause?.reason === "operator_paused") {
          reject(
            "An operator pause is already effective; retry its original request.",
            "ERR_STOP_PENDING",
          );
        }
        const supersedes =
          stopIsPending(current) &&
          kind === "cancel_requested" &&
          current.stopRequest.kind === "pause_requested" &&
          [current.revision, current.stopRequest.expectedRevision].includes(
            expectedRevision,
          );
        if (current.revision !== expectedRevision && !supersedes) {
          reject("Operator stop revision is stale.", "ERR_STALE_RUN_REVISION");
        }
        if (stopIsPending(current) && !supersedes) {
          reject(
            "An operator stop is already pending; retry its original request.",
            "ERR_STOP_PENDING",
          );
        }
        const stopRequest = {
          requestId,
          kind,
          expectedRevision,
          acceptedRevision: current.revision + 1,
          requestedAt: timestamp(current.updatedAt),
          checkpoint: supersedes
            ? current.stopRequest.checkpoint
            : {
                revision: current.revision,
                workflowState: current.pipelineState.workflowState,
                activeTurn: current.activeTurn,
                resumeAction: null,
              },
          reconciledRevision: null,
        };
        const next = normalizeRunState(
          {
            ...current,
            schemaVersion: RUN_STATE_SCHEMA_VERSION,
            runtimeCompatibility: RUNTIME_COMPATIBILITY,
            revision: stopRequest.acceptedRevision,
            updatedAt: stopRequest.requestedAt,
            stopRequest,
          },
          runId,
        );
        const migrating = current.schemaVersion !== RUN_STATE_SCHEMA_VERSION;
        await journal.appendTransition(directory, next, snapshot, {
          actor: "runner",
          phase: migrating ? "runtime" : "stop",
          kind: migrating
            ? "migrated"
            : kind === "pause_requested"
              ? "pause-requested"
              : "cancel-requested",
          message:
            kind === "pause_requested"
              ? "Operator pause requested; reconciliation is required."
              : "Operator cancellation requested; reconciliation is required.",
        });
        return receipt(runId, stopRequest);
      });
      await action.complete(result);
      return deepFreeze(result);
    } finally {
      await action.release();
    }
  }

  // Only the execution owner calls this after runner/Git reconciliation. The
  // state boundary neither signals a process nor performs a repository effect.
  async function complete(lease, { requestId, patch, outcomeMessage }) {
    const normalizedPatch = normalizeTransitionPatch(patch);
    return runLeases.runExclusive(lease, async ({ record, runDirectory }) => {
      const snapshot = await loadSnapshot(runDirectory, record.runId);
      const current = snapshot.state;
      if (current.executionProcess !== null) {
        reject(
          "Owned execution must stop before reconciliation completes.",
          "ERR_EXECUTION_PROCESS_ACTIVE",
        );
      }
      if (
        current.stopRequest?.requestId === requestId &&
        !stopIsPending(current) &&
        Object.entries(normalizedPatch).every(([field, value]) =>
          isDeepStrictEqual(current[field], value),
        )
      ) {
        return deepFreeze(current);
      }
      if (
        !stopIsPending(current) ||
        current.stopRequest.requestId !== requestId
      ) {
        reject(
          "Stop reconciliation no longer matches the pending request.",
          "ERR_STOP_REQUEST_CHANGED",
        );
      }
      return persistCheckpoint(runDirectory, snapshot, normalizedPatch, {
        actor: "runner",
        phase: "stop",
        kind: "reconciled",
        message:
          outcomeMessage ??
          (current.stopRequest.kind === "cancel_requested"
            ? "Operator cancellation reconciled."
            : "Operator pause reconciled."),
      });
    });
  }

  // The caller supplies workflow meaning synchronously from the latest snapshot.
  // No provider or repository effects may run inside this serialized boundary.
  async function settleCheckpoint(
    lease,
    resolve,
    { validate = () => {} } = {},
  ) {
    if (typeof resolve !== "function" || typeof validate !== "function") {
      reject("Checkpoint resolver is invalid.", "ERR_INVALID_RUN_TRANSITION");
    }
    return runLeases.runExclusive(lease, async ({ record, runDirectory }) => {
      const snapshot = await loadSnapshot(runDirectory, record.runId);
      if (snapshot.state.executionProcess !== null) {
        reject(
          "Owned execution must stop before checkpoint settlement.",
          "ERR_EXECUTION_PROCESS_ACTIVE",
        );
      }
      if (!stopIsPending(snapshot.state)) assertRunCanAdvance(snapshot.state);
      const { patch, activity } = resolve(
        deepFreeze(structuredClone(snapshot.state)),
      );
      return persistCheckpoint(
        runDirectory,
        snapshot,
        normalizeTransitionPatch(patch),
        activity,
        validate,
      );
    });
  }

  async function persistCheckpoint(
    runDirectory,
    snapshot,
    patch,
    activity,
    validate = () => {},
  ) {
    const current = snapshot.state;
    const pending = stopIsPending(current);
    const canceled = current.stopRequest?.kind === "cancel_requested";
    if (
      pending &&
      (patch.pipelineState?.workflowState !==
        (canceled ? "CANCELED" : "WAITING_FOR_USER") ||
        patch.pause?.reason !==
          (canceled ? "operator_canceled" : "operator_paused"))
    ) {
      reject(
        "Stop reconciliation must record the requested outcome.",
        "ERR_INVALID_STOP_RECONCILIATION",
      );
    }
    const next = normalizeRunState(
      {
        ...current,
        ...patch,
        activeTurn: null,
        stopRequest: pending
          ? { ...current.stopRequest, reconciledRevision: current.revision + 1 }
          : current.stopRequest,
        revision: current.revision + 1,
        updatedAt: timestamp(current.updatedAt),
      },
      current.runId,
    );
    validate(deepFreeze(next));
    await journal.appendTransition(
      runDirectory,
      next,
      snapshot,
      normalizePublicActivity(activity),
    );
    return deepFreeze(next);
  }

  async function checkpoint(runId) {
    const snapshot = await loadSnapshot(await getRunDirectory(runId), runId);
    const revision = snapshot.state.stopRequest?.checkpoint.revision;
    return revision === undefined
      ? null
      : deepFreeze(snapshot.events[revision - 1].state);
  }

  async function activity(lease, value) {
    const normalized = normalizePublicActivity(value);
    if (normalized?.actor !== "runner" || normalized.phase !== "stop") {
      reject(
        "Operator stop activity is invalid.",
        "ERR_INVALID_PUBLIC_ACTIVITY",
      );
    }
    return runLeases.runExclusive(lease, async ({ record, runDirectory }) => {
      const snapshot = await loadSnapshot(runDirectory, record.runId);
      if (!stopIsPending(snapshot.state)) return snapshot.state;
      const next = normalizeRunState(
        {
          ...snapshot.state,
          revision: snapshot.state.revision + 1,
          updatedAt: timestamp(snapshot.state.updatedAt),
        },
        record.runId,
      );
      await journal.appendTransition(runDirectory, next, snapshot, normalized);
      return deepFreeze(next);
    });
  }

  return Object.freeze({
    request,
    complete,
    checkpoint,
    activity,
    settleCheckpoint,
  });
}
