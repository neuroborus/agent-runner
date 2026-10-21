import { join } from "node:path";
import { readdir } from "node:fs/promises";
import { isDeepStrictEqual } from "node:util";

import { assertInactivityContinuity } from "./inactivity.js";
import { assertObservationContinuity } from "./observations.js";
import { assertAvailabilityContinuity } from "./availability.js";
import {
  observeJournalDirectory,
  journalFileUnchanged,
  readJournalSegment,
  sameJournalIdentity,
} from "./journal-files.js";
import { publicDispatchActivity } from "./dispatch.js";
import {
  appendDurableLine,
  atomicWriteFile,
  readOptionalText,
  truncateDurableFile,
} from "./files.js";
import { resolveCommitBoundary, assertStopProgress } from "./stop-policy.js";
import {
  normalizePublicActivity,
  normalizeRunState,
  deepFreeze,
  RUNTIME_COMPATIBILITY,
  RUN_STATE_SCHEMA_VERSION,
  RunStoreError,
} from "./validation.js";

const STATE_FILENAME = "state.json";
const EVENTS_FILENAME = "events.jsonl";
const PROGRESS_FILENAME = "progress.md";
const EVENT_FIELDS = new Set([
  "schemaVersion",
  "revision",
  "runId",
  "recordedAt",
  "state",
  "activity",
]);
const IMMUTABLE_STATE_FIELDS = [
  "runId",
  "pipelineId",
  "projectPath",
  "taskPath",
  "projectConfigurationProtection",
  "clientAttribution",
  "clientAttributionFingerprint",
  "roles",
  "availabilityPolicy",
  "providerInactivityTimeoutMs",
  "providerInactivityFingerprint",
  "createdAt",
];
const VERSION_STATE_FIELDS = [
  "schemaVersion",
  "pipelineStateVersion",
  "runtimeCompatibility",
];
const TRANSITION_STATE_FIELDS = [
  "observations",
  "availabilityRetry",
  "inactivityRecovery",
  "counters",
  "hashes",
  "pause",
  "providerPolicies",
  "activeTurn",
  "executionProcess",
  "executionResource",
  "stopRequest",
  "pipelineState",
];
const MAX_EVENT_LOG_BYTES = 64 * 1024 * 1024;
const MAX_EVENT_SEGMENTS = 1024;
const MAX_CHECKPOINT_ENTRIES = 8;
const MAX_CHECKPOINT_BYTES = 16 * 1024 * 1024;

class CheckpointInvalid extends Error {}

function eventFilename(index) {
  return index === 0
    ? EVENTS_FILENAME
    : `events-${String(index).padStart(6, "0")}.jsonl`;
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function parseJson(source, description, code) {
  try {
    return JSON.parse(source);
  } catch (cause) {
    throw new RunStoreError(`${description} contains invalid JSON.`, {
      cause,
      code,
    });
  }
}

function normalizeEvent(value, runId, lineNumber) {
  try {
    if (!isRecord(value)) {
      throw new RunStoreError("Event must be an object.");
    }
    const unknownField = Object.keys(value).find(
      (field) => !EVENT_FIELDS.has(field),
    );
    if (unknownField !== undefined) {
      throw new RunStoreError(`event.${unknownField} is not supported.`);
    }
    if (
      Number.isSafeInteger(value.schemaVersion) &&
      value.schemaVersion > 0 &&
      ![
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        10,
        11,
        12,
        13,
        14,
        15,
        16,
        17,
        18,
        19,
        20,
        RUN_STATE_SCHEMA_VERSION,
      ].includes(value.schemaVersion)
    ) {
      throw new RunStoreError(
        `Unsupported event.schemaVersion: ${String(value.schemaVersion)}; ` +
          "use the Agent Runner version that created the run or a version " +
          "with an explicit migration.",
        { code: "ERR_RUNTIME_VERSION_SKEW" },
      );
    }
    if (
      !Number.isSafeInteger(value.revision) ||
      value.revision < 1 ||
      value.runId !== runId ||
      typeof value.recordedAt !== "string"
    ) {
      throw new RunStoreError("Event identity is invalid.");
    }

    const state = normalizeRunState(value.state, runId);
    if (value.schemaVersion !== state.schemaVersion) {
      throw new RunStoreError(
        "Event and run state schema versions are inconsistent.",
        { code: "ERR_RUNTIME_VERSION_SKEW" },
      );
    }
    const recordedAt = new Date(value.recordedAt);
    if (
      Number.isNaN(recordedAt.valueOf()) ||
      recordedAt.toISOString() !== value.recordedAt ||
      state.revision !== value.revision ||
      state.updatedAt !== value.recordedAt
    ) {
      throw new RunStoreError("Event state or timestamp is inconsistent.");
    }

    return {
      schemaVersion: value.schemaVersion,
      revision: value.revision,
      runId,
      recordedAt: value.recordedAt,
      state,
      activity: normalizePublicActivity(value.activity),
    };
  } catch (cause) {
    if (cause?.code === "ERR_RUNTIME_VERSION_SKEW") {
      throw cause;
    }
    throw new RunStoreError(`Invalid event at line ${lineNumber}.`, {
      cause,
      code: "ERR_INVALID_EVENT_LOG",
    });
  }
}

function assertInitialEvent(event) {
  if (event.state.createdAt !== event.state.updatedAt) {
    throw new RunStoreError("Initial event timestamps are inconsistent.", {
      code: "ERR_INVALID_EVENT_LOG",
    });
  }
  if (
    event.state.inactivityRecovery !== null ||
    event.state.availabilityRetry !== null ||
    event.state.observations !== null
  ) {
    throw new RunStoreError(
      "Initial run cannot contain provider recovery or observations.",
      {
        code: "ERR_INVALID_EVENT_LOG",
      },
    );
  }
}

function assertEventContinuity(
  previous,
  event,
  stopProof,
  resolveStopBoundary,
) {
  const previousState = previous.state;
  const state = event.state;
  try {
    assertAvailabilityContinuity(previousState, state);
    assertInactivityContinuity(previousState, state, event.activity);
    assertObservationContinuity(previousState, state);
  } catch {
    throw new RunStoreError("Provider recovery history is inconsistent.", {
      code: "ERR_INVALID_EVENT_LOG",
    });
  }
  const previousChildren = previousState.sessionLineage.children;
  const children = state.sessionLineage.children;
  const immutableFieldChanged = IMMUTABLE_STATE_FIELDS.some(
    (field) => !isDeepStrictEqual(state[field], previousState[field]),
  );
  const versionChanged = VERSION_STATE_FIELDS.some(
    (field) => !isDeepStrictEqual(state[field], previousState[field]),
  );
  const migrationIsValid =
    versionChanged &&
    event.activity?.actor === "runner" &&
    event.activity.phase === "runtime" &&
    event.activity.kind === "migrated" &&
    state.schemaVersion <= RUN_STATE_SCHEMA_VERSION &&
    state.schemaVersion >= previousState.schemaVersion &&
    state.pipelineStateVersion >= previousState.pipelineStateVersion &&
    state.runtimeCompatibility?.runnerVersion ===
      RUNTIME_COMPATIBILITY.runnerVersion &&
    state.runtimeCompatibility?.runStateVersion === state.schemaVersion;
  const nextStopProof = assertStopContinuity(
    previousState,
    state,
    migrationIsValid,
    resolveStopBoundary,
    stopProof,
  );
  const lineageChanged =
    state.sessionLineage.source !== previousState.sessionLineage.source ||
    state.sessionLineage.sourceProfile !==
      previousState.sessionLineage.sourceProfile ||
    children.length < previousChildren.length ||
    children.length > previousChildren.length + 1 ||
    previousChildren.some(
      (child, childIndex) => !isDeepStrictEqual(child, children[childIndex]),
    );
  const hasContentChange =
    children.length > previousChildren.length ||
    versionChanged ||
    TRANSITION_STATE_FIELDS.some(
      (field) => !isDeepStrictEqual(state[field], previousState[field]),
    );

  if (
    (previousState.pipelineState.workflowState === "CANCELED" &&
      state.pipelineState.workflowState !== "CANCELED") ||
    immutableFieldChanged ||
    (versionChanged && !migrationIsValid) ||
    lineageChanged ||
    state.updatedAt < previousState.updatedAt ||
    (!hasContentChange && event.activity === null)
  ) {
    throw new RunStoreError(
      `Event state continuity is invalid at line ${event.revision}.`,
      { code: "ERR_INVALID_EVENT_LOG" },
    );
  }
  return nextStopProof;
}

function assertStopContinuity(
  previous,
  current,
  migrating,
  resolveStopBoundary,
  proof,
) {
  const stop = current.stopRequest;
  const prior = previous.stopRequest;
  const invalid = () => {
    throw new RunStoreError("Operator stop history is inconsistent.", {
      code: "ERR_INVALID_EVENT_LOG",
    });
  };
  if (stop === null) {
    if (prior !== null) invalid();
    return null;
  }
  // A new request names the immediately preceding checkpoint. Supersession
  // retains that checkpoint; later transitions retain the accepted request.
  const checkpoint =
    stop.checkpoint.revision === previous.revision
      ? {
          revision: previous.revision,
          workflowState: previous.pipelineState.workflowState,
          activeTurn: previous.activeTurn,
        }
      : proof?.checkpoint;
  const accepted =
    prior?.requestId !== stop.requestId &&
    stop.acceptedRevision === current.revision
      ? stop
      : proof?.accepted;
  if (
    checkpoint?.revision !== stop.checkpoint.revision ||
    checkpoint.workflowState !== stop.checkpoint.workflowState ||
    !isDeepStrictEqual(checkpoint.activeTurn, stop.checkpoint.activeTurn) ||
    accepted?.requestId !== stop.requestId ||
    !isDeepStrictEqual(
      { ...stop, reconciledRevision: null, settlement: null },
      { ...accepted, reconciledRevision: null, settlement: null },
    )
  )
    invalid();
  if (
    stop.targetBoundary !== null &&
    typeof resolveStopBoundary !== "function"
  ) {
    resolveCommitBoundary(current, resolveStopBoundary);
  }
  if (prior?.requestId === stop.requestId) {
    if (prior.reconciledRevision !== null) {
      if (!isDeepStrictEqual(prior, stop)) invalid();
    } else if (stop.reconciledRevision !== null) {
      if (
        stop.reconciledRevision !== current.revision ||
        current.activeTurn !== null ||
        (stop.kind === "cancel_requested"
          ? current.pipelineState.workflowState !== "CANCELED"
          : current.pipelineState.workflowState !== "WAITING_FOR_USER" ||
            current.pause?.reason !== "operator_paused")
      )
        invalid();
    } else if (stop.effectiveTiming === "after-current-commit") {
      assertStopProgress(previous, current, resolveStopBoundary);
    } else if (
      !migrating &&
      !isDeepStrictEqual(previous.pipelineState, current.pipelineState)
    )
      invalid();
    return { checkpoint, accepted };
  }
  if (
    prior?.kind === "cancel_requested" ||
    stop.acceptedRevision !== current.revision ||
    stop.reconciledRevision !== null
  )
    invalid();
  if (stop.timing === "after-current-commit") {
    resolveCommitBoundary(previous, resolveStopBoundary);
  }
  const expectedTiming =
    prior?.reconciledRevision === null && prior.effectiveTiming === "immediate"
      ? "immediate"
      : stop.timing;
  if (stop.effectiveTiming !== expectedTiming) invalid();
  if (
    stop.effectiveTiming === "after-current-commit" &&
    !isDeepStrictEqual(
      resolveCommitBoundary(previous, resolveStopBoundary),
      stop.targetBoundary,
    )
  )
    invalid();
  if (prior !== null && prior.reconciledRevision === null) {
    if (
      stop.kind !== "cancel_requested" ||
      (prior.effectiveTiming === "immediate" &&
        stop.effectiveTiming !== "immediate") ||
      (stop.effectiveTiming === "after-current-commit" &&
        !isDeepStrictEqual(stop.targetBoundary, prior.targetBoundary)) ||
      !isDeepStrictEqual(stop.checkpoint, prior.checkpoint) ||
      ![prior.expectedRevision, previous.revision].includes(
        stop.expectedRevision,
      )
    )
      invalid();
  } else if (
    stop.expectedRevision !== previous.revision ||
    stop.checkpoint.revision !== previous.revision
  )
    invalid();
  if (
    [
      "availabilityRetry",
      "inactivityRecovery",
      "pipelineState",
      "pause",
      "activeTurn",
      "executionProcess",
      "executionResource",
      "counters",
      "hashes",
      "sessionLineage",
    ].some((field) => !isDeepStrictEqual(previous[field], current[field]))
  )
    invalid();
  return { checkpoint, accepted };
}

async function* readEvents(
  runDirectory,
  runId,
  resolveStopBoundary,
  metadata = {},
  checkpoint = null,
) {
  const directory = await observeJournalDirectory(runDirectory);
  const filenames = (await readdir(runDirectory)).filter(
    (name) => name === EVENTS_FILENAME || /^events-[0-9]+\.jsonl$/iu.test(name),
  );
  // The original journal stays at its historical path; later segments are
  // append-only and contiguous. No authoritative history is compacted away.
  filenames.sort((a, b) =>
    a === EVENTS_FILENAME ? -1 : b === EVENTS_FILENAME ? 1 : a < b ? -1 : 1,
  );
  if (
    filenames.length === 0 ||
    filenames.length > MAX_EVENT_SEGMENTS ||
    filenames.some((name, index) => name !== eventFilename(index))
  ) {
    throw new RunStoreError("Run event segments are inconsistent.", {
      code: "ERR_INVALID_EVENT_LOG",
    });
  }
  if (
    checkpoint &&
    (!sameJournalIdentity(directory, checkpoint.directory) ||
      checkpoint.bindings.length > filenames.length ||
      checkpoint.bindings.some(
        (binding, index) => binding.filename !== filenames[index],
      ))
  )
    throw new CheckpointInvalid();
  let previous = checkpoint?.lastEvent ?? null;
  let stopProof = checkpoint?.stopProof ?? null;
  let versionBarrier = checkpoint?.versionBarrier ?? false;
  metadata.previousEvent = checkpoint?.previousEvent ?? null;
  const bindings = [];
  const observations = [];
  for (const [index, filename] of filenames.entries()) {
    const prefix = checkpoint?.bindings[index] ?? null;
    let result;
    try {
      result = await readJournalSegment(
        join(runDirectory, filename),
        MAX_EVENT_LOG_BYTES,
        prefix,
      );
    } catch (cause) {
      if (cause?.code !== "ENOENT") throw cause;
      if (checkpoint) throw new CheckpointInvalid();
      throw new RunStoreError("Run event log is missing.", {
        code: "ERR_INVALID_EVENT_LOG",
      });
    }
    if (
      result === null ||
      (prefix &&
        index < checkpoint.bindings.length - 1 &&
        result.binding.length !== prefix.length)
    )
      throw new CheckpointInvalid();
    const { source, binding } = result;
    bindings.push(binding === null ? null : { ...binding, filename });
    observations.push(result.observation);
    const completeEnd = source.lastIndexOf("\n") + 1;
    const hasPartialTail = completeEnd !== source.length;
    if (index < filenames.length - 1 && hasPartialTail) {
      throw new RunStoreError("A sealed event segment is incomplete.", {
        code: "ERR_INVALID_EVENT_LOG",
      });
    }
    if (completeEnd === 0 && prefix === null) {
      throw new RunStoreError("Run event log has no complete records.", {
        code: "ERR_INVALID_EVENT_LOG",
      });
    }
    // Parse and validate one snapshot at a time. Only this finite segment's
    // source, the adjacent states, and the active stop proof survive a yield.
    for (let start = 0; start < completeEnd;) {
      const end = source.indexOf("\n", start);
      const revision = (previous?.revision ?? 0) + 1;
      const line = source.slice(start, end);
      if (line.length === 0) {
        throw new RunStoreError(`Event line ${revision} is empty.`, {
          code: "ERR_INVALID_EVENT_LOG",
        });
      }
      const event = normalizeEvent(
        parseJson(line, `Event line ${revision}`, "ERR_INVALID_EVENT_LOG"),
        runId,
        revision,
      );
      if (event.revision !== revision) {
        throw new RunStoreError(
          `Event revision must be ${revision}; received ${event.revision}.`,
          { code: "ERR_INVALID_EVENT_LOG" },
        );
      }
      if (previous === null) assertInitialEvent(event);
      else
        stopProof = assertEventContinuity(
          previous,
          event,
          stopProof,
          resolveStopBoundary,
        );
      if (index === 0 && event.schemaVersion >= 21) versionBarrier = true;
      metadata.previousEvent = previous;
      previous = event;
      start = end + 1;
      yield event;
    }
    if (index === 0 && filenames.length > 1 && !versionBarrier) {
      throw new RunStoreError("Segmented history lacks its version barrier.", {
        code: "ERR_INVALID_EVENT_LOG",
      });
    }
    Object.assign(metadata, {
      hasPartialTail,
      validByteLength:
        (prefix?.length ?? 0) + Buffer.byteLength(source.slice(0, completeEnd)),
      eventFilename: filename,
      segmentCount: filenames.length,
      versionBarrier,
      stopProof,
    });
  }
  let stable = true;
  for (const [index, filename] of filenames.entries()) {
    if (
      !(await journalFileUnchanged(
        join(runDirectory, filename),
        observations[index],
      ))
    )
      stable = false;
  }
  const directoryAfter = await observeJournalDirectory(runDirectory);
  stable = stable && isDeepStrictEqual(directory, directoryAfter);
  if (checkpoint && !stable) throw new CheckpointInvalid();
  Object.assign(metadata, {
    directory,
    bindings:
      stable && bindings.every(Boolean) && !metadata.hasPartialTail
        ? bindings
        : null,
  });
}

// Replays a validated snapshot's exact prefix. Later append-only publications
// cannot change its meaning; inconsistent or replaced history grants no proof.
async function* replaySnapshot(runDirectory, snapshot, resolveStopBoundary) {
  for await (const event of readEvents(
    runDirectory,
    snapshot.state.runId,
    resolveStopBoundary,
  )) {
    if (event.revision === snapshot.state.revision) {
      if (!isDeepStrictEqual(event.state, snapshot.state)) {
        throw new RunStoreError("Run changed during history replay.", {
          code: "ERR_INVALID_EVENT_LOG",
        });
      }
      yield event;
      return;
    }
    yield event;
  }
  throw new RunStoreError("Run history ended before its snapshot.", {
    code: "ERR_INVALID_EVENT_LOG",
  });
}

async function readStoredState(runDirectory, runId) {
  const source = await readOptionalText(join(runDirectory, STATE_FILENAME));
  if (source === null) {
    return null;
  }

  try {
    return normalizeRunState(
      parseJson(source, "Run state", "ERR_INVALID_RUN_STATE"),
      runId,
    );
  } catch (cause) {
    if (cause?.code === "ERR_RUNTIME_VERSION_SKEW") {
      throw cause;
    }
    throw new RunStoreError("Run state is invalid.", {
      cause,
      code: "ERR_INVALID_RUN_STATE",
    });
  }
}

async function loadSnapshot(
  runDirectory,
  runId,
  resolveStopBoundary,
  checkpoint = null,
) {
  const storedState = await readStoredState(runDirectory, runId);
  // A lagging snapshot outside the adjacent retained pair needs canonical
  // replay to prove its exact event, even when the newer prefix is unchanged.
  if (
    storedState &&
    checkpoint &&
    storedState.revision <
      (checkpoint.previousEvent?.revision ?? checkpoint.lastEvent.revision)
  )
    checkpoint = null;
  const eventLog = {};
  let lastEvent = checkpoint?.lastEvent;
  let storedStateMatched =
    storedState === null ||
    [checkpoint?.previousEvent, lastEvent].some(
      (event) =>
        event?.revision === storedState?.revision &&
        isDeepStrictEqual(storedState, event.state),
    );
  for await (const event of readEvents(
    runDirectory,
    runId,
    resolveStopBoundary,
    eventLog,
    checkpoint,
  )) {
    if (event.revision === storedState?.revision) {
      storedStateMatched = isDeepStrictEqual(storedState, event.state);
    }
    lastEvent = event;
  }
  if (storedState !== null && storedState.revision > lastEvent.revision) {
    throw new RunStoreError("Run state is ahead of its write-ahead log.", {
      code: "ERR_INVALID_RUN_STATE",
    });
  }
  if (!storedStateMatched) {
    throw new RunStoreError("Run state does not match its write-ahead event.", {
      code: "ERR_INVALID_RUN_STATE",
    });
  }
  return {
    ...eventLog,
    lastEvent,
    state: lastEvent.state,
    stateLagged:
      storedState === null || storedState.revision < lastEvent.revision,
  };
}

async function* renderProgress(state, events) {
  yield [
    "# Agent Runner Progress",
    "",
    `Run: \`${state.runId}\``,
    `Pipeline: \`${state.pipelineId}\``,
    `Revision: ${state.revision}`,
    "",
    "## Activity",
    "",
    "",
  ].join("\n");
  let hasActivity = false;
  for await (const event of events) {
    if (event.activity === null) continue;
    hasActivity = true;
    const { actor, kind, message, phase } = publicDispatchActivity(
      event.activity,
    );
    yield `- ${event.recordedAt} — ${actor}/${phase}/${kind}: ${message}\n`;
  }
  if (!hasActivity) yield "No public activity yet.\n";
}

async function writeState(runDirectory, state) {
  await atomicWriteFile(
    join(runDirectory, STATE_FILENAME),
    `${JSON.stringify(state, null, 2)}\n`,
  );
}

async function removePartialEventTail(runDirectory, snapshot) {
  if (snapshot.hasPartialTail) {
    await truncateDurableFile(
      join(runDirectory, snapshot.eventFilename ?? EVENTS_FILENAME),
      snapshot.validByteLength,
    );
  }
}

export function createStateJournal({
  onTransitionBoundary,
  resolveStopBoundary,
}) {
  // Owned by this store instance, never a cache of historical state sequences.
  const checkpoints = new Map();
  let checkpointBytes = 0;
  function forget(directory) {
    checkpointBytes -= checkpoints.get(directory)?.bytes ?? 0;
    checkpoints.delete(directory);
  }
  function remember(directory, snapshot) {
    forget(directory);
    if (snapshot.bindings === null) return;
    // Measure bounded components separately and stop on overflow rather than
    // materializing a string containing several copies of a large state.
    let bytes = 0;
    for (const value of [
      snapshot.lastEvent,
      snapshot.previousEvent,
      snapshot.state,
      { ...snapshot, lastEvent: null, previousEvent: null, state: null },
    ]) {
      bytes += Buffer.byteLength(JSON.stringify(value));
      if (bytes > MAX_CHECKPOINT_BYTES) return;
    }
    while (
      checkpoints.size >= MAX_CHECKPOINT_ENTRIES ||
      checkpointBytes + bytes > MAX_CHECKPOINT_BYTES
    )
      forget(checkpoints.keys().next().value);
    checkpoints.set(directory, { snapshot: deepFreeze(snapshot), bytes });
    checkpointBytes += bytes;
  }
  async function loadCheckpoint(directory, runId) {
    const checkpoint = checkpoints.get(directory)?.snapshot ?? null;
    try {
      let snapshot;
      try {
        snapshot = await loadSnapshot(
          directory,
          runId,
          resolveStopBoundary,
          checkpoint,
        );
      } catch (cause) {
        if (!(cause instanceof CheckpointInvalid)) throw cause;
        forget(directory);
        snapshot = await loadSnapshot(directory, runId, resolveStopBoundary);
      }
      remember(directory, snapshot);
      return snapshot;
    } catch (cause) {
      forget(directory);
      throw cause;
    }
  }
  async function appendTransition(runDirectory, state, snapshot, activity) {
    await removePartialEventTail(runDirectory, snapshot);

    const event = {
      schemaVersion: state.schemaVersion,
      revision: state.revision,
      runId: state.runId,
      recordedAt: state.updatedAt,
      state,
      activity,
    };
    if (snapshot.lastEvent != null)
      assertEventContinuity(
        snapshot.lastEvent,
        event,
        snapshot.stopProof,
        resolveStopBoundary,
      );
    const serializedEvent = JSON.stringify(event);
    const eventBytes = Buffer.byteLength(serializedEvent) + 1;
    const rotate = snapshot.validByteLength + eventBytes > MAX_EVENT_LOG_BYTES;
    const segmentCount = snapshot.segmentCount ?? 1;
    // A legacy reader must reject the original journal before any event can
    // be published in a path it cannot discover, even if state.json lags.
    if (
      eventBytes > MAX_EVENT_LOG_BYTES ||
      (rotate &&
        (segmentCount >= MAX_EVENT_SEGMENTS || !snapshot.versionBarrier))
    ) {
      throw new RunStoreError("Run event log exceeds its size limit.", {
        code: "ERR_EVENT_LOG_LIMIT",
      });
    }

    if (rotate) {
      // Publish a complete first record atomically before state replacement.
      // Readers can observe either prefix without a missing or partial segment.
      await atomicWriteFile(
        join(runDirectory, eventFilename(segmentCount)),
        `${serializedEvent}\n`,
      );
    } else {
      await appendDurableLine(
        join(runDirectory, snapshot.eventFilename ?? EVENTS_FILENAME),
        serializedEvent,
      );
    }
    await onTransitionBoundary("event-appended");
    await writeState(runDirectory, state);
    await onTransitionBoundary("state-replaced");
    await atomicWriteFile(
      join(runDirectory, PROGRESS_FILENAME),
      renderProgress(
        state,
        replaySnapshot(runDirectory, { state }, resolveStopBoundary),
      ),
    );
    await onTransitionBoundary("progress-replaced");
  }

  async function recover(runDirectory, snapshot) {
    await removePartialEventTail(runDirectory, snapshot);
    if (snapshot.stateLagged) {
      await writeState(runDirectory, snapshot.state);
    }

    await atomicWriteFile(
      join(runDirectory, PROGRESS_FILENAME),
      renderProgress(
        snapshot.state,
        replaySnapshot(runDirectory, snapshot, resolveStopBoundary),
      ),
    );
  }

  return Object.freeze({
    appendTransition: async (directory, ...args) => {
      try {
        await appendTransition(directory, ...args);
      } catch (cause) {
        // Only prepublication checkpoints can survive successful publication;
        // failed callbacks must not leave evidence populated by nested reads.
        forget(directory);
        throw cause;
      }
    },
    loadSnapshot: loadCheckpoint,
    replaySnapshot: (directory, snapshot) =>
      replaySnapshot(directory, snapshot, resolveStopBoundary),
    recover,
  });
}
