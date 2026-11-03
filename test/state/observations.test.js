import assert from "node:assert/strict";
import {
  appendFile,
  mkdir,
  mkdtemp,
  open,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  createRunStore,
  RUN_STATE_SCHEMA_VERSION,
  projectObservations,
} from "../../src/state/index.js";
import { isRecoveryPreparation } from "../../src/state/dispatch.js";
import { normalizeRunState } from "../../src/state/validation.js";
import {
  assertObservationContinuity,
  beginObservationAttempt,
  normalizeObservationState,
  recordObservations,
} from "../../src/state/observations.js";
import { runObservedAttempt } from "../../src/runner/observations.js";
import { normalizeFinalizationResult } from "../../pipelines/plan-execution/src/workflow-contract.js";
import {
  largeFinalizationResult,
  STRUCTURED_RESULT_BYTES,
} from "../support/index.js";

const selected = { role: "worker", checkpoint: "implement:workspace-write:1" };
const observation = {
  attempt: 1,
  turn: 1,
  kind: "primary",
  outcome: "failed",
  accounting: "incomplete",
  last: null,
  cumulative: {
    inputTokens: 100,
    cachedInputTokens: 40,
    cacheWriteInputTokens: null,
    outputTokens: 20,
    reasoningOutputTokens: 10,
    totalTokens: null,
  },
  cumulativeScope: "thread",
  inputIncludesCached: true,
  outputIncludesReasoning: true,
  contextCapacity: null,
  commandCompletions: 1,
  compactions: 0,
  factsIncomplete: false,
};
const identity = (state) => {
  const { id, role, checkpoint } = state.observations.attempts.at(-1);
  return { id, role, checkpoint };
};

test("an accepted two-mebibyte result survives interrupted durable publication without truncation", async (t) => {
  let armed = false;
  const f = await fixture(t, {
    onTransitionBoundary: async (point) => {
      if (armed && point === "event-appended") {
        armed = false;
        throw new Error("Interrupted result publication.");
      }
    },
  });
  const result = largeFinalizationResult("é");
  assert.equal(
    Buffer.byteLength(JSON.stringify(result)),
    STRUCTURED_RESULT_BYTES,
  );
  const accepted = await runObservedAttempt({
    runStore: f.store,
    lease: f.lease,
    ...selected,
    request: { prompt: "Inspect synthetic validation evidence." },
    operation: async () => ({ structured: result }),
  });
  const finalization = normalizeFinalizationResult(accepted.structured);
  armed = true;
  await assert.rejects(
    f.store.transitionRun(f.lease, {
      pipelineState: {
        workflowState: "CONFIRM",
        finalization,
      },
    }),
    /Interrupted result publication/u,
  );
  const reader = createRunStore({ stateRoot: f.stateRoot });
  const reloaded = await reader.loadRun(f.state.runId);
  assert.deepEqual(reloaded.pipelineState.finalization, finalization);
  assert.equal(reloaded.observations.attempts.at(-1).status, "completed");
  assert.equal(
    reloaded.observations.attempts.at(-1).measurements.structuredResultBytes,
    STRUCTURED_RESULT_BYTES,
  );
  const recovered = await f.store.recoverRun(f.lease);
  const history = await reader.loadRunHistory(f.state.runId);
  assert.deepEqual(history.events.at(-1).state, recovered);
  assert.deepEqual(recovered.pipelineState.finalization, finalization);
  assert.deepEqual(
    JSON.parse(await readFile(join(f.directoryPath, "state.json"), "utf8")),
    recovered,
  );
});

test("measured attempts survive durable failure and expose only allowlisted evidence and activity", async (t) => {
  const f = await fixture(t);
  const failure = new Error("private arbitrary provider error");
  const published = [];
  await assert.rejects(
    runObservedAttempt({
      runStore: f.store,
      lease: f.lease,
      ...selected,
      request: {
        prompt: "private prompt secret",
        recoveryPrompt: "private reconstruction secret",
        schema: { type: "object" },
        session: { id: "private-native-id", mode: "continue" },
      },
      publish: async (activity) => published.push(activity),
      operation: async ({ onObservation }) => {
        onObservation(observation);
        onObservation({
          ...observation,
          turn: 2,
          transcript: "private transcript",
          reasoning: "private reasoning",
          toolOutput: "private tool output",
        });
        throw failure;
      },
    }),
    (cause) => cause === failure,
  );
  const reader = createRunStore({ stateRoot: f.stateRoot });
  const run = await reader.loadRun(f.state.runId);
  const projected = projectObservations({
    ...run,
    providerMessage: "private message",
  });
  const attempt = projected.attempts[0];
  assert.equal(attempt.role, selected.role);
  assert.equal(attempt.checkpoint, selected.checkpoint);
  assert.equal(attempt.status, "failed");
  assert.equal(attempt.accounting, "incomplete");
  assert.equal(attempt.incomplete, true);
  assert.deepEqual(attempt.observations, [observation]);
  assert.deepEqual(attempt.measurements, {
    promptBytes: 21,
    recoveryPromptBytes: 29,
    schemaBytes: 17,
    resultBytes: null,
    structuredResultBytes: null,
    referencedFileCount: null,
    referencedFileBytes: null,
  });
  const page = await reader.readPublicActivity(run.runId, {
    afterRevision: 0,
    limit: 100,
  });
  assert.deepEqual(
    page.activities
      .filter(({ phase }) => phase === "observations")
      .map(({ message }) => message),
    published.map(({ message }) => message),
  );
  assert.match(
    page.activities.at(-1).message,
    /failed; accounting incomplete/u,
  );
  const response = {
    output: "private result ✓",
    structured: { summary: "private result" },
    sessionId: "private-native-id",
  };
  const successActivity = [];
  let otherTransitions = 0;
  await runObservedAttempt({
    runStore: f.store,
    lease: f.lease,
    ...selected,
    request: {
      prompt: "private reconstruction",
      onFreshSession: async () => {
        await f.store.transitionRun(f.lease, {
          counters: { fixRounds: ++otherTransitions },
        });
        return true;
      },
    },
    publish: async (activity) => successActivity.push(activity),
    operation: async ({ onObservation, onFreshSession }) => {
      onObservation(observation);
      onObservation({
        ...observation,
        turn: 2,
        kind: "compaction",
        compactions: 1,
      });
      assert.equal(await onFreshSession(), true);
      assert.equal(await onFreshSession(), true);
      onObservation({
        ...observation,
        attempt: 2,
        kind: "recovery",
        outcome: "completed",
        accounting: "reported",
      });
      return response;
    },
  });
  const succeeded = projectObservations(
    await reader.loadRun(run.runId),
  ).attempts.at(-1);
  assert.equal(succeeded.status, "completed");
  assert.equal(succeeded.accounting, "incomplete");
  assert.deepEqual(
    successActivity.map(({ kind }) => kind),
    ["active", "active", "completed"],
  );
  assert.equal(
    succeeded.measurements.resultBytes,
    Buffer.byteLength(response.output),
  );
  assert.equal(
    succeeded.measurements.structuredResultBytes,
    Buffer.byteLength(JSON.stringify(response.structured)),
  );
  assert.deepEqual(
    succeeded.observations.map(({ attempt, turn, kind }) => [
      attempt,
      turn,
      kind,
    ]),
    [
      [1, 1, "primary"],
      [1, 2, "compaction"],
      [2, 1, "recovery"],
    ],
  );
  assert.doesNotMatch(
    JSON.stringify([
      projected,
      published,
      page,
      await reader.loadRunHistory(run.runId),
    ]),
    /private|transcript|reasoning"|toolOutput|sessionId/u,
  );
});

test("measurement extensions preserve legacy absence and immutable source and terminal measurements", () => {
  const state = {
    schemaVersion: RUN_STATE_SCHEMA_VERSION,
    revision: 10,
    roles: { worker: {} },
    activeTurn: { role: "worker" },
    observations: null,
  };
  const legacy = {
    ...state,
    revision: 11,
    observations: beginObservationAttempt(state, selected),
  };
  assert.equal(projectObservations(legacy).attempts[0].measurements, null);
  const measurements = {
    promptBytes: 4,
    recoveryPromptBytes: 8,
    schemaBytes: 0,
    resultBytes: null,
    structuredResultBytes: null,
    referencedFileCount: null,
    referencedFileBytes: null,
  };
  const started = {
    ...legacy,
    revision: 12,
    observations: beginObservationAttempt(legacy, selected, measurements),
  };
  assertObservationContinuity(legacy, started);
  const completed = {
    ...started,
    revision: 13,
    observations: recordObservations(
      started,
      identity(started),
      [],
      "completed",
      false,
      { resultBytes: 6, structuredResultBytes: 2 },
    ),
  };
  assertObservationContinuity(started, completed);
  assert.deepEqual(
    normalizeObservationState(completed),
    completed.observations,
  );
  for (const patch of [
    { promptBytes: 99 },
    { prompt: "private" },
    { schemaBytes: -1 },
    { referencedFileBytes: 1 },
  ]) {
    const changed = structuredClone(completed);
    Object.assign(changed.observations.attempts.at(-1).measurements, patch);
    assert.throws(() => {
      normalizeObservationState(changed);
      assertObservationContinuity(started, changed);
    });
  }
  const rewritten = structuredClone(completed);
  rewritten.observations.attempts.at(-1).measurements.resultBytes = 9;
  assert.throws(() => assertObservationContinuity(completed, rewritten));
});

async function fixture(t, options = {}) {
  const root = await mkdtemp(join(tmpdir(), "observations-"));
  let lease;
  t.after(async () => {
    await lease?.release();
    await rm(root, { recursive: true, force: true });
  });
  const projectPath = join(root, "project"),
    taskPath = join(root, "task");
  await Promise.all([mkdir(projectPath), mkdir(taskPath)]);
  const stateRoot = join(root, "state");
  const store = createRunStore({ stateRoot, ...options });
  const created = await store.createRun({
    pipelineId: "plan-execution",
    pipelineStateVersion: 1,
    projectPath,
    taskPath,
    roles: { worker: { backend: "codex" } },
    pipelineState: { workflowState: "IMPLEMENT" },
  });
  lease = created.lease;
  await store.startAgentTurn(
    created.lease,
    { role: "worker", phase: "implement" },
    {
      activity: {
        actor: "worker",
        phase: "implement",
        kind: "turn-started",
        message: "Worker started.",
      },
    },
  );
  return { store, stateRoot, ...created };
}

test("runner identities reject stale callbacks and retain failed and interrupted evidence across replacement", async (t) => {
  const f = await fixture(t);
  const start = await f.store.startObservationAttempt(f.lease, selected);
  const first = identity(start);
  const accepted = await f.store.recordObservationBatch(f.lease, first, [
    observation,
  ]);
  const duplicate = await f.store.recordObservationBatch(f.lease, first, [
    { ...observation, commandCompletions: 99 },
  ]);
  assert.deepEqual(duplicate, accepted);
  const reconstructed = await f.store.startObservationAttempt(
    f.lease,
    selected,
  );
  assert.equal(reconstructed.observations.attempts[0].status, "interrupted");
  assert.deepEqual(reconstructed.observations.attempts[0].observations, [
    observation,
  ]);
  for (const stale of [
    first,
    { ...identity(reconstructed), role: "reviewer" },
    { ...identity(reconstructed), checkpoint: "implement:workspace-write:2" },
  ]) {
    assert.deepEqual(
      await f.store.recordObservationBatch(f.lease, stale, [observation]),
      reconstructed,
    );
  }
  const failed = await f.store.recordObservationBatch(
    f.lease,
    identity(reconstructed),
    [observation],
    { status: "failed" },
  );
  assert.equal(failed.observations.attempts.at(-1).accounting, "incomplete");
  assert.deepEqual(
    await f.store.recordObservationBatch(
      f.lease,
      identity(failed),
      [observation],
      { status: "completed" },
    ),
    failed,
  );
  const next = await f.store.startObservationAttempt(f.lease, selected);
  const unobserved = await f.store.recordObservationBatch(
    f.lease,
    identity(next),
    [],
    { status: "completed" },
  );
  assert.equal(
    unobserved.observations.attempts.at(-1).accounting,
    "incomplete",
  );
  assert.equal(unobserved.observations.attempts[1].status, "failed");
  assert.deepEqual(unobserved.counters, start.counters);
  assert.deepEqual(unobserved.pipelineState, start.pipelineState);
});

test("observation publication recovers at every write-ahead boundary and retires interrupted accounting", async (t) => {
  for (const boundary of [
    "event-appended",
    "state-replaced",
    "progress-replaced",
  ]) {
    let armed = false;
    const f = await fixture(t, {
      onTransitionBoundary: async (point) => {
        if (armed && point === boundary) {
          armed = false;
          throw new Error("interrupted publication");
        }
      },
    });
    const started = await f.store.startObservationAttempt(f.lease, selected);
    armed = true;
    await assert.rejects(
      f.store.recordObservationBatch(f.lease, identity(started), [observation]),
    );
    const reader = createRunStore({ stateRoot: f.stateRoot });
    const inspected = await reader.loadRun(started.runId);
    assert.deepEqual(inspected.observations.attempts[0].observations, [
      observation,
    ]);
    const recovered = await f.store.recoverRun(f.lease);
    assert.equal(recovered.observations.attempts[0].status, "interrupted");
    assert.equal(recovered.observations.attempts[0].accounting, "incomplete");
    const history = await reader.loadRunHistory(started.runId);
    assert.ok(isRecoveryPreparation(inspected, history.events.at(-1)));
    assert.equal(
      isRecoveryPreparation(inspected, {
        ...history.events.at(-1),
        state: { ...recovered, counters: { fixRounds: 1 } },
      }),
      false,
    );
    assert.deepEqual(
      JSON.parse(await readFile(join(f.directoryPath, "state.json"), "utf8")),
      recovered,
    );
    assert.deepEqual(await f.store.recoverRun(f.lease), recovered);
  }
});

test("one leased recovery hands repaired history directly to interrupted observation retirement", async (t) => {
  const f = await fixture(t);
  const started = await f.store.startObservationAttempt(f.lease, selected);
  const active = await f.store.recordObservationBatch(
    f.lease,
    identity(started),
    [observation],
  );
  const eventsPath = join(f.directoryPath, "events.jsonl");
  const statePath = join(f.directoryPath, "state.json");
  const prefix = await readFile(eventsPath, "utf8");
  await appendFile(eventsPath, '{"partial":');
  const eventsInode = (await stat(eventsPath)).ino;
  const stateInode = (await stat(statePath)).ino;
  const handle = await open(eventsPath, "r");
  const prototype = Object.getPrototypeOf(handle);
  await handle.close();
  const nativeStat = prototype.stat;
  const nativeTruncate = prototype.truncate;
  const nativeReadFile = prototype.readFile;
  const nativeWriteFile = prototype.writeFile;
  let truncations = 0;
  let repaired = false;
  let appended = false;
  const truncateMock = t.mock.method(
    prototype,
    "truncate",
    async function (...args) {
      if ((await nativeStat.call(this)).ino === eventsInode) {
        // Controlled equivalent of the later strict-verification interaction.
        // ERR_INVALID_EVENT_LOG was reproduced only in the unaccepted candidate;
        // the accepted base instead attempts this redundant truncation.
        assert.equal(
          ++truncations,
          1,
          "retirement must consume the repaired value",
        );
        await nativeTruncate.apply(this, args);
        repaired = true;
        return;
      }
      return nativeTruncate.apply(this, args);
    },
  );
  const readMock = t.mock.method(
    prototype,
    "readFile",
    async function (...args) {
      if (
        repaired &&
        !appended &&
        (await nativeStat.call(this)).ino === stateInode
      )
        assert.fail(
          "recovery must not reload canonical state before retirement append",
        );
      return nativeReadFile.apply(this, args);
    },
  );
  const writeMock = t.mock.method(
    prototype,
    "writeFile",
    async function (...args) {
      if ((await nativeStat.call(this)).ino === eventsInode) {
        assert.equal(repaired, true);
        assert.equal(
          JSON.parse(args[0]).activity.kind,
          "observations-interrupted",
        );
        appended = true;
      }
      return nativeWriteFile.apply(this, args);
    },
  );
  let recovered;
  try {
    recovered = await f.store.recoverRun(f.lease);
    assert.equal(truncations, 1);
    assert.equal(appended, true);
    const events = await readFile(eventsPath, "utf8");
    assert.equal(events.slice(0, prefix.length), prefix);
    const retirement = JSON.parse(events.slice(prefix.length));
    assert.equal(recovered.revision, active.revision + 1);
    assert.deepEqual(retirement.state, recovered);
    assert.equal(recovered.observations.attempts[0].status, "interrupted");
    assert.equal(recovered.observations.attempts[0].accounting, "incomplete");
    assert.equal(
      recovered.observations.attempts[0].incomplete,
      active.observations.attempts[0].incomplete,
    );
    assert.deepEqual(recovered.observations.attempts[0].observations, [
      observation,
    ]);
    assert.deepEqual(recovered.activeTurn, active.activeTurn);
    assert.deepEqual(recovered.pipelineState, active.pipelineState);
    assert.deepEqual(recovered.counters, active.counters);
    assert.deepEqual(JSON.parse(await readFile(statePath, "utf8")), recovered);
    const progress = await readFile(
      join(f.directoryPath, "progress.md"),
      "utf8",
    );
    assert.ok(progress.includes(`Revision: ${recovered.revision}\n`));
    assert.match(progress, /observations-interrupted/u);
    assert.deepEqual(await f.store.recoverRun(f.lease), recovered);
    assert.equal(truncations, 1);
    assert.equal(await readFile(eventsPath, "utf8"), events);
    assert.equal(
      await readFile(join(f.directoryPath, "progress.md"), "utf8"),
      progress,
    );
  } finally {
    truncateMock.mock.restore();
    readMock.mock.restore();
    writeMock.mock.restore();
  }
  assert.deepEqual(
    await createRunStore({ stateRoot: f.stateRoot }).loadRun(active.runId),
    recovered,
  );
});

test("repair and sync failures cannot retire an interrupted observation", async (t) => {
  for (const phase of ["truncate", "sync"]) {
    await t.test(phase, async (t) => {
      const f = await fixture(t);
      const active = await f.store.startObservationAttempt(f.lease, selected);
      const eventsPath = join(f.directoryPath, "events.jsonl");
      const prefix = await readFile(eventsPath, "utf8");
      const progressPath = join(f.directoryPath, "progress.md");
      const progress = await readFile(progressPath, "utf8");
      await appendFile(eventsPath, '{"partial":');
      const inode = (await stat(eventsPath)).ino;
      const handle = await open(eventsPath, "r");
      const prototype = Object.getPrototypeOf(handle);
      await handle.close();
      const nativeStat = prototype.stat;
      const failure = new Error(`Interrupted tail ${phase}.`);
      const nativeOperation = prototype[phase];
      const operation = t.mock.method(
        prototype,
        phase,
        async function (...args) {
          if ((await nativeStat.call(this)).ino === inode) throw failure;
          return nativeOperation.apply(this, args);
        },
      );
      try {
        await assert.rejects(
          f.store.recoverRun(f.lease),
          (cause) => cause === failure,
        );
      } finally {
        operation.mock.restore();
      }
      assert.equal(
        await readFile(eventsPath, "utf8"),
        prefix + (phase === "truncate" ? '{"partial":' : ""),
      );
      assert.equal(await readFile(progressPath, "utf8"), progress);
      assert.deepEqual(
        JSON.parse(await readFile(join(f.directoryPath, "state.json"), "utf8")),
        active,
      );
      assert.deepEqual(
        await createRunStore({ stateRoot: f.stateRoot }).loadRun(active.runId),
        active,
      );
    });
  }
});

test("recovery defers observation retirement until process and resource ownership are settled", async (t) => {
  const processIdentity = (pid) => ({
    bootId: "11111111-1111-4111-8111-111111111111",
    startTicks: String(pid),
  });
  const f = await fixture(t, { processIdentity });
  const started = await f.store.startObservationAttempt(f.lease, selected);
  await f.store.recordObservationBatch(f.lease, identity(started), [
    observation,
  ]);
  const owned = await f.store.recordExecutionProcess(f.lease, 300, {
    processIdentity: processIdentity(300),
  });
  assert.deepEqual(await f.store.recoverRun(f.lease), owned);
  assert.deepEqual(await f.store.loadRun(owned.runId), owned);

  await f.store.recordExecutionProcess(f.lease, null);
  const allocated = await f.store.recordExecutionResource(f.lease, {
    id: "22222222-2222-4222-8222-222222222222",
    hostname: "fixture-host",
    commandIdentity: "a".repeat(64),
    phase: "allocating",
    root: { path: f.stateRoot, device: "1", inode: "1" },
    directory: null,
  });
  assert.deepEqual(await f.store.recoverRun(f.lease), allocated);
  const retired = await f.store.recordExecutionResource(f.lease, null);
  const recovered = await f.store.recoverRun(f.lease);
  assert.equal(recovered.revision, retired.revision + 1);
  assert.equal(recovered.observations.attempts[0].status, "interrupted");
  assert.deepEqual(recovered.observations.attempts[0].observations, [
    observation,
  ]);
  assert.deepEqual(recovered.activeTurn, owned.activeTurn);
  assert.deepEqual(recovered.pipelineState, owned.pipelineState);
});

test("legacy absence migrates without inventing observations or rewriting historical events", async (t) => {
  const f = await fixture(t);
  const eventsPath = join(f.directoryPath, "events.jsonl"),
    statePath = join(f.directoryPath, "state.json");
  const events = (await readFile(eventsPath, "utf8"))
    .trim()
    .split("\n")
    .map(JSON.parse);
  for (const event of events) {
    event.schemaVersion = event.state.schemaVersion = 17;
    event.state.runtimeCompatibility.runStateVersion = 17;
    delete event.state.observations;
  }
  const source = events.map(JSON.stringify).join("\n") + "\n";
  await writeFile(eventsPath, source);
  await writeFile(statePath, JSON.stringify(events.at(-1).state));
  const legacy = await f.store.loadRun(f.state.runId);
  assert.equal(legacy.observations, null);
  assert.equal(await readFile(eventsPath, "utf8"), source);
  const migrated = await f.store.migrateRun(
    f.lease,
    {
      pipelineState: legacy.pipelineState,
      pipelineStateVersion: legacy.pipelineStateVersion,
    },
    {
      activity: {
        actor: "runner",
        phase: "runtime",
        kind: "migrated",
        message: "Migrated run envelope.",
      },
    },
  );
  assert.equal(migrated.schemaVersion, RUN_STATE_SCHEMA_VERSION);
  assert.equal(migrated.observations, null);
  assert.ok((await readFile(eventsPath, "utf8")).startsWith(source));
  assert.deepEqual(migrated.pipelineState, legacy.pipelineState);
  assert.throws(() =>
    normalizeRunState({ ...migrated, observations: undefined }),
  );
});

test("version-18 observations require migration before measurements and preserve accepted history", async (t) => {
  const f = await fixture(t);
  const started = await f.store.startObservationAttempt(f.lease, selected);
  await f.store.recordObservationBatch(
    f.lease,
    identity(started),
    [observation],
    {
      status: "failed",
    },
  );
  const eventsPath = join(f.directoryPath, "events.jsonl");
  const events = (await readFile(eventsPath, "utf8"))
    .trim()
    .split("\n")
    .map(JSON.parse);
  for (const event of events) {
    event.schemaVersion = event.state.schemaVersion = 18;
    event.state.runtimeCompatibility.runStateVersion = 18;
  }
  const source = events.map(JSON.stringify).join("\n") + "\n";
  await writeFile(eventsPath, source);
  await writeFile(
    join(f.directoryPath, "state.json"),
    JSON.stringify(events.at(-1).state),
  );
  const legacy = await f.store.loadRun(f.state.runId);
  const measurements = {
    promptBytes: 4,
    recoveryPromptBytes: 4,
    schemaBytes: null,
    resultBytes: null,
    structuredResultBytes: null,
    referencedFileCount: null,
    referencedFileBytes: null,
  };
  const invalid = structuredClone(legacy);
  invalid.observations.attempts[0].measurements = measurements;
  assert.throws(() => normalizeRunState(invalid));
  await assert.rejects(
    f.store.startObservationAttempt(f.lease, selected, measurements),
  );
  assert.equal(await readFile(eventsPath, "utf8"), source);
  const migrated = await f.store.migrateRun(
    f.lease,
    {
      pipelineState: legacy.pipelineState,
      pipelineStateVersion: legacy.pipelineStateVersion,
    },
    {
      activity: {
        actor: "runner",
        phase: "runtime",
        kind: "migrated",
        message: "Migrated measurement support.",
      },
    },
  );
  assert.equal(migrated.schemaVersion, RUN_STATE_SCHEMA_VERSION);
  assert.deepEqual(migrated.observations, legacy.observations);
  const measured = await f.store.startObservationAttempt(
    f.lease,
    selected,
    measurements,
  );
  await f.store.recordObservationBatch(f.lease, identity(measured), [], {
    status: "completed",
    resultBytes: 2,
  });
  const reader = createRunStore({ stateRoot: f.stateRoot });
  const projected = projectObservations(await reader.loadRun(legacy.runId));
  assert.equal(projected.attempts[0].measurements, null);
  assert.deepEqual(projected.attempts[0].observations, [observation]);
  assert.equal(projected.attempts[1].measurements.resultBytes, 2);
  assert.ok((await readFile(eventsPath, "utf8")).startsWith(source));
});

test("bounded retention and closed numeric contracts preserve nullable counters and native scopes", () => {
  let state = {
    schemaVersion: RUN_STATE_SCHEMA_VERSION,
    revision: 1,
    roles: { worker: {} },
    activeTurn: { role: "worker" },
    observations: null,
  };
  for (let index = 0; index < 40; index++) {
    const before = state;
    state = {
      ...state,
      revision: state.revision + 1,
      observations: beginObservationAttempt(state, selected),
    };
    assertObservationContinuity(before, state);
    state.observations = recordObservations(
      state,
      identity(state),
      [observation],
      "failed",
      false,
    );
  }
  const normalized = normalizeObservationState(state);
  assert.equal(normalized.attempts.length, 32);
  assert.equal(normalized.omittedAttempts, 8);
  assert.equal(normalized.attempts[0].id, 10);
  assert.equal(
    normalized.attempts.at(-1).observations[0].cumulative.totalTokens,
    null,
  );
  assert.equal(
    normalized.attempts.at(-1).observations[0].cumulativeScope,
    "thread",
  );
  const value = structuredClone(normalized);
  for (const patch of [
    { schemaVersion: 2 },
    { raw: "private payload" },
    { omittedAttempts: Infinity },
    { attempts: [...value.attempts, value.attempts.at(-1)] },
  ]) {
    assert.throws(() =>
      normalizeObservationState({
        ...state,
        observations: { ...value, ...patch },
      }),
    );
  }
  for (const patch of [
    { raw: "private payload" },
    { id: 0 },
    { checkpoint: "private\ntext" },
    { observations: [{ ...observation, nativeId: "private" }] },
    { observations: [{ ...observation, contextCapacity: -1 }] },
    { observations: [observation, observation] },
  ]) {
    const invalid = structuredClone(value);
    Object.assign(invalid.attempts[0], patch);
    assert.throws(() =>
      normalizeObservationState({ ...state, observations: invalid }),
    );
  }
  const rewritten = structuredClone(state);
  rewritten.observations.attempts[0].observations[0].commandCompletions++;
  assert.throws(() => assertObservationContinuity(state, rewritten));

  state = {
    ...state,
    revision: state.revision + 1,
    observations: beginObservationAttempt(state, selected),
  };
  const reported = {
    ...observation,
    outcome: "completed",
    accounting: "reported",
    cumulativeScope: "attempt",
    inputIncludesCached: false,
  };
  state.observations = recordObservations(
    state,
    identity(state),
    [reported],
    "completed",
    false,
  );
  const terminal = normalizeObservationState(state).attempts.at(-1);
  assert.equal(terminal.accounting, "reported");
  assert.deepEqual(terminal.observations, [reported]);
  assert.equal(terminal.observations[0].cumulative.totalTokens, null);
});
