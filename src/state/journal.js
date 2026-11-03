import { join } from "node:path";
import { readdir } from "node:fs/promises";
import { isDeepStrictEqual } from "node:util";

import { assertInactivityContinuity } from "./inactivity.js";
import { assertObservationContinuity } from "./observations.js";
import { assertPreservationContinuity } from "./preservation-contract.js";
import { assertAvailabilityContinuity } from "./availability.js";
import {
  observeJournalDirectory,
  journalFileUnchanged,
  readJournalSegment,
  sameJournalIdentity,
  streamJournalPrefix,
  truncateJournalTail,
} from "./journal-files.js";
import {
  collectProjection,
  createProjection,
  projectCertifiedActivity,
} from "./projections.js";
import {
  appendDurableLine,
  atomicWriteFile,
  readOptionalText,
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
  "workspace",
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
  "preparation",
  "preservationRecords",
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
        21,
        22,
        23,
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
    event.state.observations !== null ||
    event.state.preparation != null ||
    event.state.preservationRecords?.length > 0
  ) {
    throw new RunStoreError(
      "Initial run cannot contain recovery, observations, preparation, or preservation.",
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
    assertPreservationContinuity(previousState, state, event.activity);
  } catch {
    throw new RunStoreError("Run recovery history is inconsistent.", {
      code: "ERR_INVALID_EVENT_LOG",
    });
  }
  assertPreparationContinuity(previousState, state, event.activity);
  const previousChildren = previousState.sessionLineage.children;
  const children = state.sessionLineage.children;
  const readRebinding = isWorkspaceReadRebinding(
    previousState,
    state,
    event.activity,
  );
  const immutableFieldChanged = IMMUTABLE_STATE_FIELDS.some(
    (field) =>
      !(field === "workspace" && readRebinding) &&
      !isDeepStrictEqual(state[field], previousState[field]),
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

function isWorkspaceReadRebinding(previous, current, activity) {
  if (
    activity?.actor !== "runner" ||
    activity.phase !== "clarify" ||
    activity.kind !== "read-scopes-bound" ||
    previous.workspace.kind !== "directory" ||
    current.workspace.kind !== "directory" ||
    previous.activeTurn !== null ||
    current.activeTurn !== null ||
    previous.preparation != null ||
    current.preparation != null ||
    previous.executionProcess !== null ||
    current.executionProcess !== null ||
    previous.executionResource !== null ||
    current.executionResource !== null ||
    !isDeepStrictEqual(previous.pipelineState, current.pipelineState)
  )
    return false;
  const before = previous.workspace;
  const after = current.workspace;
  const { infrastructurePaths: oldReads, ...oldPolicy } = before.policy;
  const { infrastructurePaths: newReads, ...newPolicy } = after.policy;
  return (
    before.leasePath === after.leasePath &&
    before.lease === after.lease &&
    isDeepStrictEqual(oldPolicy, newPolicy) &&
    oldReads.every((path) => newReads.includes(path)) &&
    before.ancestorBindings.every((entry) =>
      after.ancestorBindings.some((next) => isDeepStrictEqual(entry, next)),
    ) &&
    isDeepStrictEqual(before.absentInputPaths, after.absentInputPaths) &&
    isDeepStrictEqual(before.retrievalPermissions, after.retrievalPermissions)
  );
}

function assertPreparationContinuity(previous, current, activity) {
  const before = previous.preparation;
  const after = current.preparation;
  if (isDeepStrictEqual(before, after)) return;
  const invalid = () => {
    throw new RunStoreError("Preparation history is inconsistent.", {
      code: "ERR_INVALID_EVENT_LOG",
    });
  };
  if (activity?.actor !== "runner" || activity.phase !== "preparation")
    invalid();
  const stationary = ({ preparation, revision, updatedAt, ...state }) => state;
  if (!isDeepStrictEqual(stationary(previous), stationary(current))) invalid();
  if (before == null) {
    const trusted = previous.pipelineState.trustedValidation;
    if (
      activity.kind !== "reserved" ||
      after.revision !== current.revision ||
      after.settlement !== null ||
      previous.executionProcess !== null ||
      !isDeepStrictEqual(after.resource, previous.executionResource) ||
      !isDeepStrictEqual(after.stopRequest, previous.stopRequest) ||
      after.bindings.commandFingerprint !== trusted?.commandFingerprint ||
      after.bindings.configurationFingerprint !==
        trusted?.configurationFingerprint ||
      !trusted.commands.some(
        ({ identity }) => identity === after.bindings.commandIdentity,
      )
    )
      invalid();
  } else if (after == null) {
    if (activity.kind !== "cleared" || before.settlement === null) invalid();
  } else {
    const { settlement: priorSettlement, ...issued } = before;
    const { settlement, ...retained } = after;
    if (
      activity.kind !== "settled" ||
      priorSettlement !== null ||
      settlement === null ||
      !isDeepStrictEqual(issued, retained)
    )
      invalid();
  }
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
      "preparation",
      "counters",
      "hashes",
      "sessionLineage",
    ].some((field) => !isDeepStrictEqual(previous[field], current[field]))
  )
    invalid();
  return { checkpoint, accepted };
}

async function readJournalFilenames(runDirectory) {
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
  return filenames;
}

async function* readEvents(
  runDirectory,
  runId,
  resolveStopBoundary,
  metadata = {},
  checkpoint = null,
  proof = checkpoint,
) {
  const directory = await observeJournalDirectory(runDirectory);
  const filenames = await readJournalFilenames(runDirectory);
  const certificate = proof?.certificate;
  if (
    proof &&
    (!certificate ||
      certificate.runId !== runId ||
      certificate.firstRevision !== 1 ||
      certificate.lastRevision !== proof.lastEvent.revision ||
      !sameJournalIdentity(directory, certificate.directory) ||
      certificate.bindings.length > filenames.length ||
      certificate.bindings.some(
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
    const prefix = certificate?.bindings[index] ?? null;
    const firstRevision =
      prefix?.firstRevision ?? (previous?.revision ?? 0) + 1;
    let lastRevision = prefix?.lastRevision;
    let result;
    try {
      result = await readJournalSegment(
        join(runDirectory, filename),
        MAX_EVENT_LOG_BYTES,
        prefix,
        checkpoint === null,
      );
    } catch (cause) {
      // A bound segment no longer safely openable, such as one gaining a hard
      // link, is a changed binding, as a later link-count change already is.
      if (
        proof &&
        prefix !== null &&
        cause instanceof RunStoreError &&
        cause.code === "ERR_UNSAFE_STATE_FILE"
      )
        throw new CheckpointInvalid();
      if (cause?.code !== "ENOENT") throw cause;
      if (proof) throw new CheckpointInvalid();
      throw new RunStoreError("Run event log is missing.", {
        code: "ERR_INVALID_EVENT_LOG",
      });
    }
    if (
      result === null ||
      (prefix &&
        index < certificate.bindings.length - 1 &&
        result.binding.length !== prefix.length)
    )
      throw new CheckpointInvalid();
    const { source, binding } = result;
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
      lastRevision = event.revision;
      if (metadata.projection) collectProjection(metadata.projection, event);
      start = end + 1;
      yield event;
    }
    bindings.push(
      binding === null
        ? null
        : { ...binding, filename, firstRevision, lastRevision },
    );
    if (index === 0 && filenames.length > 1 && !versionBarrier) {
      throw new RunStoreError("Segmented history lacks its version barrier.", {
        code: "ERR_INVALID_EVENT_LOG",
      });
    }
    Object.assign(metadata, {
      hasPartialTail,
      validByteLength:
        (checkpoint ? (prefix?.length ?? 0) : 0) +
        Buffer.byteLength(source.slice(0, completeEnd)),
      eventFilename: filename,
      segmentCount: filenames.length,
      versionBarrier,
      stopProof,
    });
  }
  // Directory timestamps include choosing/ready claims and derived files.
  // Prove the relevant namespace explicitly instead of treating that metadata
  // churn as a change to journal history. File observations still cover every
  // consumed range across semantic validation, including restored-mtime edits.
  const filenamesAfter = await readJournalFilenames(runDirectory);
  let stable = isDeepStrictEqual(filenames, filenamesAfter);
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
  stable = stable && sameJournalIdentity(directory, directoryAfter);
  if (proof && !stable) throw new CheckpointInvalid();
  Object.assign(metadata, {
    fileObservations: stable ? deepFreeze(observations) : null,
    // Certification belongs to this validated operation even when its snapshot
    // is too large for optional checkpoint retention.
    certificate:
      stable && bindings.every(Boolean)
        ? deepFreeze({
            runId,
            firstRevision: 1,
            lastRevision: previous.revision,
            directory,
            bindings,
          })
        : null,
  });
}

// The snapshot supplies certificates from complete semantic validation. Fresh
// projection digests alone never certify new history. Consumers must drain this
// iterator before returning a page or committing an atomic progress replacement.
async function* streamSnapshotProjection(
  runDirectory,
  snapshot,
  project = true,
) {
  const invalid = () => {
    throw new RunStoreError("Run changed during projection streaming.", {
      code: "ERR_INVALID_EVENT_LOG",
    });
  };
  const directory = await observeJournalDirectory(runDirectory);
  const filenames = await readJournalFilenames(runDirectory);
  const certificate = snapshot.certificate;
  const bindings = certificate?.bindings;
  if (
    !certificate ||
    certificate.runId !== snapshot.state.runId ||
    certificate.firstRevision !== 1 ||
    certificate.lastRevision !== snapshot.state.revision ||
    !sameJournalIdentity(directory, certificate.directory) ||
    bindings.length > filenames.length ||
    bindings.some((binding, index) => binding.filename !== filenames[index])
  )
    invalid();
  const observations = [];
  let revision = 0;
  for (const binding of bindings) {
    if (binding.firstRevision !== revision + 1) invalid();
    const metadata = {};
    for await (const line of streamJournalPrefix(
      join(runDirectory, binding.filename),
      MAX_EVENT_LOG_BYTES,
      binding,
      metadata,
      binding === bindings.at(-1),
      project,
    )) {
      if (!project) continue;
      const event = parseJson(
        line,
        "Projection event",
        "ERR_INVALID_EVENT_LOG",
      );
      revision += 1;
      if (event?.runId !== snapshot.state.runId || event.revision !== revision)
        invalid();
      let activity;
      try {
        activity = projectCertifiedActivity(event);
      } catch (cause) {
        throw new RunStoreError("Invalid event during projection streaming.", {
          cause,
          code: "ERR_INVALID_EVENT_LOG",
        });
      }
      if (activity !== null) yield activity;
    }
    if (!project) revision = binding.lastRevision;
    if (binding.lastRevision !== revision) invalid();
    observations.push(metadata.observation);
  }
  if (project && revision !== snapshot.state.revision) invalid();
  for (const [index, binding] of bindings.entries())
    if (
      !(await journalFileUnchanged(
        join(runDirectory, binding.filename),
        observations[index],
      ))
    )
      invalid();
  if (
    !isDeepStrictEqual(filenames, await readJournalFilenames(runDirectory)) ||
    !sameJournalIdentity(directory, await observeJournalDirectory(runDirectory))
  )
    invalid();
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
  const proof = checkpoint;
  // A lagging snapshot outside the adjacent retained pair needs canonical
  // replay to prove its exact event. Retain its byte proof through that scan;
  // different valid history cannot replace an operation's original prefix.
  if (
    storedState &&
    checkpoint &&
    storedState.revision <
      (checkpoint.previousEvent?.revision ?? checkpoint.lastEvent.revision)
  )
    checkpoint = null;
  const eventLog = { projection: createProjection(checkpoint?.projection) };
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
    proof,
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

async function* renderProgress(state, activities) {
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
  for await (const activity of activities) {
    hasActivity = true;
    const { actor, kind, message, phase } = activity;
    yield `- ${activity.recordedAt} — ${actor}/${phase}/${kind}: ${message}\n`;
  }
  if (!hasActivity) yield "No public activity yet.\n";
}

async function writeState(runDirectory, state) {
  await atomicWriteFile(
    join(runDirectory, STATE_FILENAME),
    `${JSON.stringify(state, null, 2)}\n`,
  );
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
    if (snapshot.certificate === null || snapshot.hasPartialTail) return;
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
  function changedProjection() {
    return new RunStoreError("Run changed during projection publication.", {
      code: "ERR_INVALID_EVENT_LOG",
    });
  }

  async function certifiedSnapshot(directory, snapshot) {
    if (snapshot.certificate !== null) return snapshot;
    // One canonical scan may establish missing evidence. It must certify the
    // same snapshot before streaming; cache retention is never a prerequisite.
    const certified = await loadSnapshot(
      directory,
      snapshot.state.runId,
      resolveStopBoundary,
    );
    if (
      certified.certificate === null ||
      !isDeepStrictEqual(certified.state, snapshot.state)
    )
      throw changedProjection();
    return certified;
  }

  async function verifyPrefix(directory, snapshot) {
    for await (const unused of streamSnapshotProjection(
      directory,
      snapshot,
      false,
    )) {
      void unused;
    }
  }

  async function verifyRepairCapture(directory, snapshot) {
    const bindings = snapshot.certificate?.bindings;
    if (!bindings || snapshot.fileObservations?.length !== bindings.length)
      throw changedProjection();
    const verifyObservations = async () => {
      if (
        !sameJournalIdentity(
          await observeJournalDirectory(directory),
          snapshot.certificate.directory,
        ) ||
        !isDeepStrictEqual(
          await readJournalFilenames(directory),
          bindings.map((binding) => binding.filename),
        )
      )
        throw changedProjection();
      for (const [index, binding] of bindings.entries())
        if (
          !(await journalFileUnchanged(
            join(directory, binding.filename),
            snapshot.fileObservations[index],
          ))
        )
          throw changedProjection();
    };
    await verifyObservations();
    await verifyPrefix(directory, snapshot);
    await verifyObservations();
  }

  async function removePartialEventTail(directory, snapshot) {
    if (!snapshot.hasPartialTail) return snapshot;
    await verifyRepairCapture(directory, snapshot);
    const binding = snapshot.certificate.bindings.at(-1);
    if (
      binding.filename !== snapshot.eventFilename ||
      binding.length !== snapshot.validByteLength
    )
      throw changedProjection();
    const observation = await truncateJournalTail(
      join(directory, binding.filename),
      binding.length,
      snapshot.fileObservations.at(-1),
    );
    // Only filesystem observations change. The semantic certificate continues
    // to own exactly the original consumed bytes, state and revision endpoint.
    const repaired = {
      ...snapshot,
      fileObservations: [
        ...snapshot.fileObservations.slice(0, -1),
        observation,
      ],
    };
    await verifyRepairCapture(directory, repaired);
    return deepFreeze({ ...repaired, hasPartialTail: false });
  }

  async function* publicActivities(directory, snapshot, afterRevision = 0) {
    try {
      snapshot = await certifiedSnapshot(directory, snapshot);
      if (snapshot.projection.afterRevision <= afterRevision) {
        for (const activity of snapshot.projection.activities)
          if (activity.revision > afterRevision) yield activity;
        await verifyPrefix(directory, snapshot);
      } else {
        for await (const activity of streamSnapshotProjection(
          directory,
          snapshot,
        ))
          if (activity.revision > afterRevision) yield activity;
      }
    } catch (cause) {
      forget(directory);
      throw cause;
    }
  }

  // Certifies a later publication only through the original byte proof, as
  // publication does. Changed prefix bytes, identities or namespace grant none.
  async function extendSnapshot(directory, snapshot) {
    if (!snapshot.certificate) return null;
    let extended;
    try {
      extended = await loadSnapshot(
        directory,
        snapshot.state.runId,
        resolveStopBoundary,
        snapshot,
      );
    } catch (cause) {
      // Only unavailable proof is classified; every other failure propagates.
      if (cause instanceof CheckpointInvalid) return null;
      throw cause;
    }
    return extended.certificate &&
      extended.state.revision > snapshot.state.revision
      ? extended
      : null;
  }

  async function writeProgress(directory, snapshot) {
    await atomicWriteFile(
      join(directory, PROGRESS_FILENAME),
      renderProgress(snapshot.state, publicActivities(directory, snapshot)),
    );
  }

  async function verifyFailure(directory, snapshot, cause) {
    try {
      await verifyPrefix(directory, snapshot);
    } catch (proofError) {
      if (!(cause instanceof RunStoreError)) throw proofError;
    }
    throw cause;
  }

  async function publicationBoundary(directory, boundary, snapshot) {
    await onTransitionBoundary(boundary);
    // Callback-populated checkpoints never replace the original certificate.
    await verifyPrefix(directory, snapshot);
  }

  async function appendTransition(runDirectory, state, snapshot, activity) {
    snapshot = await removePartialEventTail(runDirectory, snapshot);

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
    if (snapshot.lastEvent != null) await verifyPrefix(runDirectory, snapshot);
    const published = await certifiedSnapshot(
      runDirectory,
      await loadSnapshot(
        runDirectory,
        state.runId,
        resolveStopBoundary,
        snapshot.lastEvent == null ? null : snapshot,
      ),
    );
    if (!isDeepStrictEqual(published.lastEvent, event))
      throw changedProjection();
    try {
      await publicationBoundary(runDirectory, "event-appended", published);
      await writeState(runDirectory, state);
      await publicationBoundary(runDirectory, "state-replaced", published);
      await writeProgress(runDirectory, published);
      await publicationBoundary(runDirectory, "progress-replaced", published);
      // Snapshot rollback may require canonical matching, but never changes the
      // original byte certificate against which publication must be verified.
      const verified = await loadSnapshot(
        runDirectory,
        state.runId,
        resolveStopBoundary,
        published,
      );
      if (
        !verified.certificate ||
        !sameJournalIdentity(
          verified.certificate.directory,
          published.certificate.directory,
        ) ||
        !isDeepStrictEqual(
          verified.certificate.bindings,
          published.certificate.bindings,
        ) ||
        !isDeepStrictEqual(verified.state, state)
      )
        throw changedProjection();
      remember(runDirectory, verified);
    } catch (cause) {
      await verifyFailure(runDirectory, published, cause);
    }
  }

  async function recover(runDirectory, snapshot) {
    snapshot = await certifiedSnapshot(runDirectory, snapshot);
    try {
      snapshot = await removePartialEventTail(runDirectory, snapshot);
      if (snapshot.stateLagged) {
        await writeState(runDirectory, snapshot.state);
      }

      await writeProgress(runDirectory, snapshot);
      await verifyPrefix(runDirectory, snapshot);
      return deepFreeze(snapshot);
    } catch (cause) {
      await verifyFailure(runDirectory, snapshot, cause);
    }
  }

  return Object.freeze({
    verifyCertificate: (directory, certificate) =>
      verifyPrefix(directory, {
        certificate,
        state: { runId: certificate.runId, revision: certificate.lastRevision },
      }),
    appendTransition: async (directory, state, snapshot, activity) => {
      try {
        if (snapshot.lastEvent != null)
          snapshot = await certifiedSnapshot(directory, snapshot);
        await appendTransition(directory, state, snapshot, activity);
      } catch (cause) {
        // Only prepublication checkpoints can survive successful publication;
        // failed callbacks must not leave evidence populated by nested reads.
        forget(directory);
        if (cause instanceof CheckpointInvalid) cause = changedProjection();
        if (snapshot.certificate)
          await verifyFailure(directory, snapshot, cause);
        throw cause;
      }
    },
    loadSnapshot: loadCheckpoint,
    extendSnapshot,
    replaySnapshot: (directory, snapshot) =>
      replaySnapshot(directory, snapshot, resolveStopBoundary),
    publicActivities,
    recover: async (directory, snapshot) => {
      try {
        return await recover(directory, snapshot);
      } catch (cause) {
        forget(directory);
        throw cause;
      }
    },
  });
}
