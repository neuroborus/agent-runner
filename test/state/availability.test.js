import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  availabilityDelayMs,
  createRunStore,
  DEFAULT_AVAILABILITY_POLICY,
  MAX_AVAILABILITY_DELAY_MS,
  normalizeAvailabilityPolicy,
  RUN_STATE_SCHEMA_VERSION,
  RUNTIME_COMPATIBILITY_TOKEN,
} from "../../src/state/index.js";

const FINGERPRINT = "a".repeat(64);
const request = {
  role: "worker",
  checkpoint: "implement:1",
  reason: "transport_unavailable",
  contentFingerprint: FINGERPRINT,
};

async function fixture(t, maxDelayMs = 1_800_000) {
  const directory = await mkdtemp(join(tmpdir(), "availability-state-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const projectPath = join(directory, "project");
  const taskPath = join(directory, "task");
  await Promise.all([mkdir(projectPath), mkdir(taskPath)]);
  let now = Date.parse("2026-09-28T10:00:00.000Z");
  let crashAt;
  const options = {
    stateRoot: join(directory, "state"),
    clock: () => new Date(now),
    onTransitionBoundary(boundary) {
      if (boundary === crashAt) {
        crashAt = undefined;
        throw new Error(`Interrupted ${boundary}`);
      }
    },
  };
  const store = createRunStore(options);
  const created = await store.createRun({
    pipelineId: "plan-execution",
    pipelineStateVersion: 1,
    projectPath,
    taskPath,
    roles: { worker: { backend: "codex" } },
    availabilityPolicy: { initialDelayMs: 5_000, maxDelayMs },
    counters: { corrections: 2 },
    pipelineState: {
      workflowState: "IMPLEMENT",
      pendingCorrection: { counted: true },
    },
    sourceSession: "source",
    childSessions: [
      { role: "worker", sessionId: "child", contextKey: FINGERPRINT },
    ],
  });
  t.after(() => created.lease.release().catch(() => {}));
  return {
    ...created,
    store,
    options,
    advance: (ms) => {
      now += ms;
    },
    crash: (boundary) => {
      crashAt = boundary;
    },
  };
}

test("availability schedule repeats its ceiling without attempt exhaustion", () => {
  assert.deepEqual(
    Array.from(
      { length: 12 },
      (_, index) =>
        availabilityDelayMs(DEFAULT_AVAILABILITY_POLICY, index + 1) / 1_000,
    ),
    [5, 10, 20, 40, 80, 160, 320, 640, 1280, 1800, 1800, 1800],
  );
  for (const [maxDelayMs, expected] of [
    [5_000, [5_000, 5_000, 5_000]],
    [7_001, [5_000, 7_001, 7_001]],
  ]) {
    const policy = { initialDelayMs: 5_000, maxDelayMs };
    assert.deepEqual(
      [1, 2, 3].map((attempt) => availabilityDelayMs(policy, attempt)),
      expected,
    );
    assert.equal(
      availabilityDelayMs(policy, Number.MAX_SAFE_INTEGER),
      maxDelayMs,
    );
  }
  assert.equal(
    availabilityDelayMs(
      { initialDelayMs: 5_000, maxDelayMs: MAX_AVAILABILITY_DELAY_MS },
      100,
    ),
    MAX_AVAILABILITY_DELAY_MS,
  );
  for (const policy of [
    null,
    {},
    { ...DEFAULT_AVAILABILITY_POLICY, initialDelayMs: 1 },
    ...[4_999, 5_000.5, "1800000", MAX_AVAILABILITY_DELAY_MS + 1].map(
      (maxDelayMs) => ({ ...DEFAULT_AVAILABILITY_POLICY, maxDelayMs }),
    ),
    { ...DEFAULT_AVAILABILITY_POLICY, quota: 10 },
  ]) {
    assert.throws(() => normalizeAvailabilityPolicy(policy), TypeError);
  }
  for (const attempt of [
    0,
    -1,
    1.5,
    Infinity,
    "1",
    Number.MAX_SAFE_INTEGER + 1,
  ]) {
    assert.throws(
      () => availabilityDelayMs(DEFAULT_AVAILABILITY_POLICY, attempt),
      TypeError,
    );
  }
});

test("availability scheduling preserves identity, frozen policy and reconciled context across restart", async (t) => {
  const f = await fixture(t, 7_000);
  let state = await f.store.scheduleAvailabilityRetry(f.lease, {
    ...request,
    expectedRevision: f.state.revision,
  });
  const first = state.availabilityRetry;
  assert.equal(first.delayMs, 5_000);
  assert.equal(first.reconciledRevision, 1);
  assert.equal(first.nextRetryAt, "2026-09-28T10:00:05.000Z");
  assert.ok(Object.isFrozen(state.availabilityPolicy));
  assert.ok(Object.isFrozen(first));
  await assert.rejects(
    f.store.scheduleAvailabilityRetry(f.lease, {
      ...request,
      expectedRevision: 1,
    }),
    { code: "ERR_RUN_REVISION_CHANGED" },
  );
  await assert.rejects(
    f.store.scheduleAvailabilityRetry(f.lease, {
      ...request,
      expectedRevision: state.revision,
    }),
    { code: "ERR_INVALID_EVENT_LOG" },
  );
  state = await f.store.transitionRun(f.lease, {
    pause: { reason: "backend_unavailable" },
  });
  assert.deepEqual(state.availabilityRetry, first);
  await f.lease.release();
  f.advance(60_000);
  const resumed = createRunStore(f.options);
  assert.deepEqual(
    (await resumed.loadRun(state.runId)).availabilityRetry,
    first,
  );
  const lease = await resumed.acquireRunLease(state.runId);
  try {
    for (const reason of ["model_busy", "temporarily_overloaded"]) {
      state = await resumed.scheduleAvailabilityRetry(lease, {
        ...request,
        reason,
        contentFingerprint: "b".repeat(64),
        expectedRevision: state.revision,
      });
      assert.equal(state.availabilityRetry.id, first.id);
      assert.equal(state.availabilityRetry.delayMs, 7_000);
      assert.equal(
        Date.parse(state.availabilityRetry.nextRetryAt) -
          Date.parse(state.updatedAt),
        7_000,
      );
      assert.deepEqual(state.counters, f.state.counters);
      assert.deepEqual(state.sessionLineage, f.state.sessionLineage);
      assert.deepEqual(state.pipelineState, f.state.pipelineState);
      f.advance(7_000);
    }
    assert.equal(state.availabilityRetry.attempt, 3);
    // A pipeline migration must preserve the existing frozen policy and episode.
    state = await resumed.migrateRun(
      lease,
      {
        pipelineState: state.pipelineState,
        pipelineStateVersion: 2,
      },
      {
        activity: {
          actor: "runner",
          phase: "runtime",
          kind: "migrated",
          message: "Migrated fixture.",
        },
      },
    );
    assert.equal(state.availabilityPolicy.maxDelayMs, 7_000);
    assert.equal(state.availabilityRetry.attempt, 3);
  } finally {
    await lease.release();
  }
});

test("availability records reject malformed and discontinuous state without writing", async (t) => {
  const f = await fixture(t);
  const state = await f.store.scheduleAvailabilityRetry(f.lease, {
    ...request,
    expectedRevision: 1,
  });
  const statePath = join(f.directoryPath, "state.json");
  const eventsPath = join(f.directoryPath, "events.jsonl");
  const before = await Promise.all([
    readFile(statePath, "utf8"),
    readFile(eventsPath, "utf8"),
  ]);
  for (const patch of [
    { availabilityPolicy: { initialDelayMs: 5_000, maxDelayMs: 6_000 } },
    ...[
      { id: "invalid" },
      { role: "reviewer" },
      { checkpoint: "private prose here" },
      { reason: "raw diagnostic" },
      { attempt: 0 },
      { delayMs: 6_000 },
      { nextRetryAt: "2026-09-28T10:00:06.000Z" },
      { contentFingerprint: "unknown" },
      { reconciledRevision: state.revision + 1 },
      { secret: "DO_NOT_RETAIN" },
      { checkpoint: "confirm:1" },
      { attempt: 3, delayMs: 20_000, nextRetryAt: "2026-09-28T10:00:20.000Z" },
    ].map((change) => ({
      availabilityRetry: { ...state.availabilityRetry, ...change },
    })),
  ]) {
    await assert.rejects(f.store.transitionRun(f.lease, patch));
  }
  assert.deepEqual(
    await Promise.all([
      readFile(statePath, "utf8"),
      readFile(eventsPath, "utf8"),
    ]),
    before,
  );
  for (const field of ["availabilityPolicy", "availabilityRetry"]) {
    const malformed = JSON.parse(before[0]);
    delete malformed[field];
    await writeFile(statePath, JSON.stringify(malformed));
    await assert.rejects(f.store.loadRun(state.runId), {
      code: "ERR_INVALID_RUN_STATE",
    });
  }
  const legacy = {
    ...state,
    schemaVersion: 14,
    runtimeCompatibility: { runnerVersion: 1, runStateVersion: 14 },
  };
  await writeFile(statePath, JSON.stringify(legacy));
  await assert.rejects(f.store.loadRun(state.runId), {
    code: "ERR_INVALID_RUN_STATE",
  });
  await writeFile(statePath, before[0]);
  // Syntactically valid policy drift is rejected by journal continuity on read.
  const events = before[1].trim().split("\n").map(JSON.parse);
  events[1].state.availabilityPolicy.maxDelayMs = 6_000;
  await writeFile(
    eventsPath,
    events.map((event) => JSON.stringify(event)).join("\n") + "\n",
  );
  await writeFile(statePath, JSON.stringify(events[1].state));
  await assert.rejects(f.store.loadRun(state.runId), {
    code: "ERR_INVALID_EVENT_LOG",
  });
});

test("availability scheduling is durable at every journal publication boundary", async (t) => {
  for (const boundary of [
    "event-appended",
    "state-replaced",
    "progress-replaced",
  ]) {
    const f = await fixture(t);
    f.crash(boundary);
    await assert.rejects(
      f.store.scheduleAvailabilityRetry(f.lease, {
        ...request,
        expectedRevision: 1,
      }),
      /Interrupted/u,
    );
    await f.lease.release();
    f.advance(100_000);
    const resumed = createRunStore(f.options);
    const loaded = await resumed.loadRun(f.state.runId);
    assert.equal(loaded.availabilityRetry.attempt, 1);
    assert.equal(
      loaded.availabilityRetry.nextRetryAt,
      "2026-09-28T10:00:05.000Z",
    );
    const lease = await resumed.acquireRunLease(f.state.runId);
    try {
      assert.deepEqual(await resumed.recoverRun(lease), loaded);
      assert.deepEqual(
        JSON.parse(await readFile(join(f.directoryPath, "state.json"), "utf8")),
        loaded,
      );
      await assert.rejects(
        resumed.scheduleAvailabilityRetry(lease, {
          ...request,
          expectedRevision: 1,
        }),
        { code: "ERR_RUN_REVISION_CHANGED" },
      );
      assert.equal(
        (await resumed.loadRunHistory(f.state.runId)).events.length,
        2,
      );
    } finally {
      await lease.release();
    }
  }
});

test("legacy availability migration supplies only the default and no pending episode", async (t) => {
  const f = await fixture(t);
  await f.lease.release();
  const statePath = join(f.directoryPath, "state.json");
  const eventsPath = join(f.directoryPath, "events.jsonl");
  const legacy = JSON.parse(await readFile(statePath, "utf8"));
  legacy.schemaVersion = 14;
  legacy.runtimeCompatibility.runStateVersion = 14;
  delete legacy.availabilityPolicy;
  delete legacy.availabilityRetry;
  const event = JSON.parse((await readFile(eventsPath, "utf8")).trim());
  event.schemaVersion = 14;
  event.state = legacy;
  await writeFile(statePath, JSON.stringify(legacy));
  await writeFile(eventsPath, JSON.stringify(event) + "\n");
  const before = await readFile(eventsPath, "utf8");
  const loaded = await f.store.loadRun(legacy.runId);
  assert.deepEqual(loaded.availabilityPolicy, DEFAULT_AVAILABILITY_POLICY);
  assert.equal(loaded.availabilityRetry, null);
  assert.equal(await readFile(eventsPath, "utf8"), before);
  const lease = await f.store.acquireRunLease(legacy.runId);
  try {
    await assert.rejects(
      f.store.scheduleAvailabilityRetry(lease, {
        ...request,
        expectedRevision: 1,
      }),
      { code: "ERR_INVALID_RUN_STATE" },
    );
    const migrated = await f.store.migrateRun(
      lease,
      {
        pipelineState: loaded.pipelineState,
        pipelineStateVersion: loaded.pipelineStateVersion,
      },
      {
        activity: {
          actor: "runner",
          phase: "runtime",
          kind: "migrated",
          message: "Migrated availability policy.",
        },
      },
    );
    assert.equal(migrated.schemaVersion, RUN_STATE_SCHEMA_VERSION);
    assert.equal(RUNTIME_COMPATIBILITY_TOKEN, "1:17");
    for (const field of [
      "roles",
      "counters",
      "pipelineState",
      "sessionLineage",
      "availabilityPolicy",
      "availabilityRetry",
    ]) {
      assert.deepEqual(migrated[field], loaded[field]);
    }
    assert.ok((await readFile(eventsPath, "utf8")).startsWith(before));
  } finally {
    await lease.release();
  }
});
