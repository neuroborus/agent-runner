import { join } from "node:path";
import { isDeepStrictEqual } from "node:util";

import {
  appendDurableLine,
  atomicWriteFile,
  readOptionalText,
  truncateDurableFile,
} from "./state-files.js";
import {
  normalizePublicActivity,
  normalizeRunState,
  RUN_STATE_SCHEMA_VERSION,
  RunStoreError,
} from "./state-validation.js";

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
  "schemaVersion",
  "runId",
  "pipelineId",
  "pipelineStateVersion",
  "projectPath",
  "taskPath",
  "roles",
  "createdAt",
];
const TRANSITION_STATE_FIELDS = [
  "counters",
  "hashes",
  "pause",
  "pipelineState",
];
const MAX_EVENT_LOG_BYTES = 64 * 1024 * 1024;

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
    if (value.schemaVersion !== RUN_STATE_SCHEMA_VERSION) {
      throw new RunStoreError("Event schema version is unsupported.");
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
      schemaVersion: RUN_STATE_SCHEMA_VERSION,
      revision: value.revision,
      runId,
      recordedAt: value.recordedAt,
      state,
      activity: normalizePublicActivity(value.activity),
    };
  } catch (cause) {
    throw new RunStoreError(`Invalid event at line ${lineNumber}.`, {
      cause,
      code: "ERR_INVALID_EVENT_LOG",
    });
  }
}

function assertEventContinuity(events) {
  if (events[0].state.createdAt !== events[0].state.updatedAt) {
    throw new RunStoreError("Initial event timestamps are inconsistent.", {
      code: "ERR_INVALID_EVENT_LOG",
    });
  }

  for (let index = 1; index < events.length; index += 1) {
    const previousState = events[index - 1].state;
    const state = events[index].state;
    const previousChildren = previousState.sessionLineage.children;
    const children = state.sessionLineage.children;
    const immutableFieldChanged = IMMUTABLE_STATE_FIELDS.some(
      (field) => !isDeepStrictEqual(state[field], previousState[field]),
    );
    const lineageChanged =
      state.sessionLineage.source !== previousState.sessionLineage.source ||
      state.sessionLineage.sourceProfile !==
        previousState.sessionLineage.sourceProfile ||
      children.length < previousChildren.length ||
      children.length > previousChildren.length + 1 ||
      previousChildren.some(
        (child, childIndex) =>
          !isDeepStrictEqual(child, children[childIndex]),
      );
    const hasContentChange =
      children.length > previousChildren.length ||
      TRANSITION_STATE_FIELDS.some(
        (field) => !isDeepStrictEqual(state[field], previousState[field]),
      );

    if (
      immutableFieldChanged ||
      lineageChanged ||
      state.updatedAt < previousState.updatedAt ||
      (!hasContentChange && events[index].activity === null)
    ) {
      throw new RunStoreError(
        `Event state continuity is invalid at line ${index + 1}.`,
        { code: "ERR_INVALID_EVENT_LOG" },
      );
    }
  }
}

async function readEvents(runDirectory, runId) {
  const source = await readOptionalText(join(runDirectory, EVENTS_FILENAME));
  if (source === null) {
    throw new RunStoreError("Run event log is missing.", {
      code: "ERR_INVALID_EVENT_LOG",
    });
  }
  if (Buffer.byteLength(source) > MAX_EVENT_LOG_BYTES) {
    throw new RunStoreError("Run event log exceeds its size limit.", {
      code: "ERR_INVALID_EVENT_LOG",
    });
  }

  const hasPartialTail = !source.endsWith("\n");
  const completeSource = hasPartialTail
    ? source.slice(0, source.lastIndexOf("\n") + 1)
    : source;
  const lines = source.split("\n");
  lines.pop();
  if (lines.length === 0) {
    throw new RunStoreError("Run event log has no complete records.", {
      code: "ERR_INVALID_EVENT_LOG",
    });
  }

  const events = lines.map((line, index) => {
    if (line.length === 0) {
      throw new RunStoreError(`Event line ${index + 1} is empty.`, {
        code: "ERR_INVALID_EVENT_LOG",
      });
    }
    return normalizeEvent(
      parseJson(line, `Event line ${index + 1}`, "ERR_INVALID_EVENT_LOG"),
      runId,
      index + 1,
    );
  });

  for (const [index, event] of events.entries()) {
    const expectedRevision = index + 1;
    if (event.revision !== expectedRevision) {
      throw new RunStoreError(
        `Event revision must be ${expectedRevision}; received ${event.revision}.`,
        { code: "ERR_INVALID_EVENT_LOG" },
      );
    }
  }
  assertEventContinuity(events);

  return {
    events,
    hasPartialTail,
    validByteLength: Buffer.byteLength(completeSource),
  };
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
    throw new RunStoreError("Run state is invalid.", {
      cause,
      code: "ERR_INVALID_RUN_STATE",
    });
  }
}

async function loadSnapshot(runDirectory, runId) {
  const storedState = await readStoredState(runDirectory, runId);
  const eventLog = await readEvents(runDirectory, runId);
  const { events, hasPartialTail, validByteLength } = eventLog;
  const lastEvent = events.at(-1);

  if (storedState === null) {
    return {
      events,
      hasPartialTail,
      validByteLength,
      state: lastEvent.state,
      stateLagged: true,
    };
  }
  if (storedState.revision > lastEvent.revision) {
    throw new RunStoreError("Run state is ahead of its write-ahead log.", {
      code: "ERR_INVALID_RUN_STATE",
    });
  }

  const matchingEvent = events[storedState.revision - 1];
  if (!isDeepStrictEqual(storedState, matchingEvent?.state)) {
    throw new RunStoreError(
      "Run state does not match its write-ahead event.",
      { code: "ERR_INVALID_RUN_STATE" },
    );
  }

  return {
    events,
    hasPartialTail,
    validByteLength,
    state: lastEvent.state,
    stateLagged: storedState.revision < lastEvent.revision,
  };
}

function renderProgress(state, events) {
  const activityLines = events
    .filter((event) => event.activity !== null)
    .map((event) => {
      const { actor, kind, message, phase } = event.activity;
      return `- ${event.recordedAt} — ${actor}/${phase}/${kind}: ${message}`;
    });

  return [
    "# Agent Runner Progress",
    "",
    `Run: \`${state.runId}\``,
    `Pipeline: \`${state.pipelineId}\``,
    `Revision: ${state.revision}`,
    "",
    "## Activity",
    "",
    ...(activityLines.length === 0
      ? ["No public activity yet."]
      : activityLines),
    "",
  ].join("\n");
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
      join(runDirectory, EVENTS_FILENAME),
      snapshot.validByteLength,
    );
  }
}

export function createStateJournal({ onTransitionBoundary }) {
  async function appendTransition(runDirectory, state, snapshot, activity) {
    await removePartialEventTail(runDirectory, snapshot);

    const event = {
      schemaVersion: RUN_STATE_SCHEMA_VERSION,
      revision: state.revision,
      runId: state.runId,
      recordedAt: state.updatedAt,
      state,
      activity,
    };
    const nextEvents = [...snapshot.events, event];
    const serializedEvent = JSON.stringify(event);
    if (
      snapshot.validByteLength + Buffer.byteLength(serializedEvent) + 1 >
      MAX_EVENT_LOG_BYTES
    ) {
      throw new RunStoreError("Run event log exceeds its size limit.", {
        code: "ERR_EVENT_LOG_LIMIT",
      });
    }

    await appendDurableLine(
      join(runDirectory, EVENTS_FILENAME),
      serializedEvent,
    );
    await onTransitionBoundary("event-appended");
    await writeState(runDirectory, state);
    await onTransitionBoundary("state-replaced");
    await atomicWriteFile(
      join(runDirectory, PROGRESS_FILENAME),
      renderProgress(state, nextEvents),
    );
    await onTransitionBoundary("progress-replaced");
  }

  async function recover(runDirectory, snapshot) {
    await removePartialEventTail(runDirectory, snapshot);
    if (snapshot.stateLagged) {
      await writeState(runDirectory, snapshot.state);
    }

    const expectedProgress = renderProgress(snapshot.state, snapshot.events);
    const progressPath = join(runDirectory, PROGRESS_FILENAME);
    if ((await readOptionalText(progressPath)) !== expectedProgress) {
      await atomicWriteFile(progressPath, expectedProgress);
    }
  }

  return Object.freeze({ appendTransition, loadSnapshot, recover });
}
