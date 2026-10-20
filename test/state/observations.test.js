import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  createRunStore,
  RUN_STATE_SCHEMA_VERSION,
} from "../../src/state/index.js";
import { isRecoveryPreparation } from "../../src/state/dispatch.js";
import { normalizeRunState } from "../../src/state/validation.js";
import {
  assertObservationContinuity,
  beginObservationAttempt,
  normalizeObservationState,
  recordObservations,
} from "../../src/state/observations.js";

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
