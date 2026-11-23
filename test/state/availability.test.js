import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createRunStore as createPipelineRunStore } from "../../src/index.js";
import { stopSettlement } from "../../src/runner/stops.js";

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

async function fixture(
  t,
  maxDelayMs = 1_800_000,
  pipelineId = "plan-execution",
  openStore = createRunStore,
) {
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
    resolveStopBoundary: () => ({
      capability: "verified-commit-v1",
      step: 1,
      completedCommits: 0,
      baselineHead: null,
    }),
    onTransitionBoundary(boundary) {
      if (boundary === crashAt) {
        crashAt = undefined;
        throw new Error(`Interrupted ${boundary}`);
      }
    },
  };
  const store = openStore(options);
  const created = await store.createRun({
    pipelineId,
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

for (const pipelineId of ["plan-execution", "polishing"]) {
  test(`${pipelineId} binds atomic availability backoff to its read-only restatement`, async (t) => {
    const f = await fixture(t, undefined, pipelineId, createPipelineRunStore);
    const planExecution = pipelineId === "plan-execution";
    const field = planExecution ? "writableResult" : "resolutionCorrection";
    const turn = {
      role: "worker",
      phase: planExecution ? "writable-result" : "resolve-findings",
    };
    const unauthorizedTurn = {
      ...turn,
      phase: planExecution ? "commit" : "resolve-findings",
    };
    const workflowState = planExecution ? "IMPLEMENT" : "RESOLVE_FINDINGS";
    const repositoryBaseline = { contentFingerprint: FINGERPRINT };
    const reservation = {
      phase: workflowState,
      step: 1,
      access: "workspace-write",
      stage: "correcting",
      attempts: 1,
      additionalAttempts: 0,
      productDecision: null,
      candidateFingerprint: FINGERPRINT,
      candidate: repositoryBaseline,
    };
    const pipelineState = {
      workflowState,
      repositoryBaseline,
      currentStep: 1,
      pendingCommit: null,
    };
    const checkpoint = planExecution
      ? "writable-result:read-only:commit:1"
      : "resolve-findings:workspace-write:work";
    function start(activeTurn, checkpointState, preparePipelineState) {
      return f.store.startAgentTurn(f.lease, activeTurn, {
        pipelineState: { ...pipelineState, [field]: checkpointState },
        preparePipelineState,
        activity: {
          actor: activeTurn.role,
          phase: activeTurn.phase,
          kind: "turn-started",
          message: "Started fixture turn.",
        },
      });
    }
    const startAttempt = (providerCheckpoint) =>
      f.store.startObservationAttempt(f.lease, {
        role: turn.role,
        checkpoint: providerCheckpoint,
      });
    const failAttempt = (state) => {
      const { id, role, checkpoint } = state.observations.attempts.at(-1);
      return f.store.recordObservationBatch(
        f.lease,
        { id, role, checkpoint },
        [],
        { status: "failed" },
      );
    };
    const unauthorized = await start(unauthorizedTurn, {
      ...reservation,
      stage: planExecution ? "correcting" : "invoking",
      restatementStartedAfter: f.state.revision,
    });
    if (!planExecution) {
      const restatement = {
        ...reservation,
        restatementStartedAfter: unauthorized.revision,
      };
      await assert.rejects(start(turn, restatement), {
        code: "ERR_INVALID_AGENT_TURN",
      });

      const eventsPath = join(f.directoryPath, "events.jsonl");
      const source = await readFile(eventsPath, "utf8");
      const original = JSON.parse(source.trimEnd().split("\n").at(-1));
      const duplicate = {
        ...original,
        revision: unauthorized.revision + 1,
        state: {
          ...unauthorized,
          revision: unauthorized.revision + 1,
          pipelineState: { ...pipelineState, [field]: restatement },
        },
      };
      try {
        await writeFile(eventsPath, `${source}${JSON.stringify(duplicate)}\n`);
        await assert.rejects(
          createPipelineRunStore(f.options).loadRun(f.state.runId),
          { code: "ERR_INVALID_EVENT_LOG" },
        );
      } finally {
        await writeFile(eventsPath, source);
      }
    }
    const rejected = { code: "ERR_INVALID_RUN_STATE" };
    const unauthorizedFailure = await failAttempt(
      await startAttempt(checkpoint),
    );
    await assert.rejects(
      f.store.scheduleAvailabilityRetry(
        f.lease,
        {
          ...request,
          checkpoint,
          expectedRevision: unauthorizedFailure.revision,
        },
        { reconciledTurn: unauthorizedTurn },
      ),
      rejected,
    );
    const retired = await f.store.finishAgentTurn(f.lease, unauthorizedTurn);
    const ready = planExecution
      ? retired
      : await f.store.scheduleAvailabilityRetry(f.lease, {
          ...request,
          checkpoint,
          contentFingerprint: "b".repeat(64),
          expectedRevision: retired.revision,
        });
    if (!planExecution) f.advance(ready.availabilityRetry.delayMs);
    const stop = planExecution
      ? await f.store.requestOperatorStop({
          runId: f.state.runId,
          kind: "pause_requested",
          timing: "after-current-commit",
          expectedRevision: ready.revision,
          idempotencyKey: "deferred-restatement-pause",
        })
      : null;
    const active = await start(turn, reservation, (proposed, revision) => ({
      ...proposed,
      [field]: { ...proposed[field], restatementStartedAfter: revision },
    }));
    assert.equal(
      active.pipelineState[field].restatementStartedAfter,
      stop?.revision ?? ready.revision,
    );
    const continuation = {
      ...active.pipelineState,
      [field]: {
        ...active.pipelineState[field],
        stage: planExecution ? "retry-ready" : "correcting",
      },
    };
    const retirement = { reconciledTurn: turn, pipelineState: continuation };
    const inputFor = (state) => ({
      ...request,
      checkpoint,
      expectedRevision: state.revision,
    });
    await assert.rejects(
      f.store.scheduleAvailabilityRetry(f.lease, inputFor(active), retirement),
      rejected,
    );
    const unrelated = await failAttempt(await startAttempt(request.checkpoint));
    await assert.rejects(
      f.store.scheduleAvailabilityRetry(
        f.lease,
        inputFor(unrelated),
        retirement,
      ),
      rejected,
    );
    const observed = await startAttempt(checkpoint);
    await assert.rejects(
      f.store.scheduleAvailabilityRetry(
        f.lease,
        inputFor(observed),
        retirement,
      ),
      rejected,
    );
    const inspected = await failAttempt(observed);
    const input = inputFor(inspected);
    for (const change of [
      { checkpoint: request.checkpoint },
      { contentFingerprint: "b".repeat(64) },
    ])
      await assert.rejects(
        f.store.scheduleAvailabilityRetry(
          f.lease,
          { ...input, ...change },
          retirement,
        ),
        rejected,
      );
    f.crash("event-appended");
    await assert.rejects(
      f.store.scheduleAvailabilityRetry(f.lease, input, retirement),
      /Interrupted/u,
    );
    const recovered = await createPipelineRunStore(f.options).loadRun(
      f.state.runId,
    );
    assert.equal(recovered.activeTurn, null);
    assert.deepEqual(recovered.pipelineState, continuation);
    assert.equal(recovered.availabilityRetry.checkpoint, checkpoint);
    assert.equal(recovered.availabilityRetry.attempt, planExecution ? 1 : 2);
    assert.equal(
      recovered.availabilityRetry.reconciledRevision,
      inspected.revision,
    );

    const eventsPath = join(f.directoryPath, "events.jsonl");
    const statePath = join(f.directoryPath, "state.json");
    const [source, storedState] = await Promise.all([
      readFile(eventsPath, "utf8"),
      readFile(statePath, "utf8"),
    ]);
    const replayChanges = [
      (events) => {
        const state = events.at(-1).state;
        state.availabilityRetry.contentFingerprint = "b".repeat(64);
      },
      (events) => {
        for (const { state } of events.slice(observed.revision - 1))
          state.observations.attempts.at(-1).checkpoint = request.checkpoint;
      },
      (events) => {
        events[active.revision - 1].state.pipelineState[
          field
        ].restatementStartedAfter = unauthorized.revision;
      },
      (events) => {
        const started = events[active.revision - 1];
        started.activity.phase = unauthorizedTurn.phase;
        for (const event of events.slice(active.revision - 1, -1)) {
          event.state.activeTurn = unauthorizedTurn;
          if (!planExecution)
            event.state.pipelineState[field].stage = "invoking";
        }
      },
    ];
    try {
      for (const change of replayChanges) {
        const events = source
          .trimEnd()
          .split("\n")
          .map((line) => JSON.parse(line));
        change(events);
        await writeFile(
          eventsPath,
          events.map((event) => JSON.stringify(event)).join("\n") + "\n",
        );
        await writeFile(statePath, JSON.stringify(events.at(-1).state));
        await assert.rejects(
          createPipelineRunStore(f.options).loadRun(f.state.runId),
          { code: "ERR_INVALID_EVENT_LOG" },
        );
      }
    } finally {
      await writeFile(eventsPath, source);
      await writeFile(statePath, storedState);
      if (stop !== null) {
        await f.store.settleCheckpoint(f.lease, (latest) =>
          stopSettlement(latest, {
            activeTurn: null,
            pipelineState: latest.pipelineState,
            pause: null,
          }),
        );
      }
      await f.lease.release();
    }
  });
}

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
    assert.equal(RUNTIME_COMPATIBILITY_TOKEN, "1:28");
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
