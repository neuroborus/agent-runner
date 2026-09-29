import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  createInactivityWatchdog,
  createInactivityCoordinator,
} from "../src/runner/inactivity.js";
import {
  createRunStore,
  projectInactivityRecovery,
  providerInactivityFingerprint,
} from "../src/state/index.js";
import { createRunner } from "../src/runner/index.js";
import { parseRunnerConfiguration } from "../src/config/index.js";
import { normalizeRunState } from "../src/state/validation.js";

function clock() {
  let now = 0,
    id = 0;
  const timers = new Map();
  return {
    setTimeout(fn, delay) {
      const key = ++id;
      timers.set(key, { fn, at: now + delay });
      return key;
    },
    clearTimeout(key) {
      timers.delete(key);
    },
    advance(ms) {
      now += ms;
      for (const [key, timer] of timers)
        if (timer.at <= now) {
          timers.delete(key);
          timer.fn();
        }
    },
    get size() {
      return timers.size;
    },
  };
}

test("semantic progress resets inactivity, nested commands suspend it, unrelated bytes do neither", async () => {
  const timers = clock();
  let expired = 0;
  const watch = createInactivityWatchdog({
    timeoutMs: 100,
    timers,
    expire: () => {
      expired++;
    },
  });
  timers.advance(90);
  watch.progress({ kind: "semantic", activeCommands: 0 });
  timers.advance(90);
  assert.equal(expired, 0);
  watch.progress({ kind: "local-command-started", activeCommands: 1 });
  watch.progress({ kind: "local-command-started", activeCommands: 2 });
  timers.advance(10_000);
  assert.equal(timers.size, 0);
  watch.progress({ kind: "local-command-completed", activeCommands: 1 });
  timers.advance(10_000);
  assert.equal(timers.size, 0);
  watch.progress({ kind: "local-command-completed", activeCommands: 0 });
  timers.advance(99);
  for (const event of [
    { kind: "ping", activeCommands: 0 },
    { kind: "semantic", activeCommands: 0, raw: "bytes" },
    { kind: "local-command-started", activeCommands: 9 },
  ])
    watch.progress(event);
  timers.advance(1);
  await watch.close();
  assert.equal(expired, 1);
  assert.equal(timers.size, 0);
});

async function fixture(t, backend = "codex", storeOptions = {}) {
  const root = await mkdtemp(join(tmpdir(), "inactivity-"));
  const projectPath = join(root, "project"),
    taskPath = join(root, "task");
  await mkdir(projectPath);
  await mkdir(taskPath);
  const store = createRunStore({
    stateRoot: join(root, "state"),
    ...storeOptions,
  });
  const repository = {
    projectPath,
    allowedPaths: [],
    contentFingerprint: "a".repeat(64),
  };
  let { state: run, lease } = await store.createRun({
    pipelineId: "plan-execution",
    pipelineStateVersion: 1,
    projectPath,
    taskPath,
    roles: { worker: { backend } },
    providerInactivityTimeoutMs: 100,
    pipelineState: {
      workflowState: "IMPLEMENT",
      repositoryBaseline: repository,
    },
  });
  t.after(async () => {
    await lease.release();
    await rm(root, { recursive: true, force: true });
  });
  const timers = clock(),
    activities = [];
  const parameters = {
    runId: run.runId,
    lease,
    runStore: store,
    timers,
    initialRun: run,
    git: {
      async snapshot() {
        return { ...repository };
      },
      async assertUnchanged(value) {
        assert.equal(value.contentFingerprint, repository.contentFingerprint);
      },
    },
    monitor: { async check() {} },
    publish: async (event) => activities.push(event),
  };
  const input = {
    role: "worker",
    checkpoint: "implement:workspace-write:1",
    repository,
  };
  const turn = { role: "worker", phase: "implement" };
  return {
    run,
    store,
    repository,
    timers,
    activities,
    input,
    turn,
    coordinator: createInactivityCoordinator(parameters),
    start: () =>
      store.startAgentTurn(lease, turn, {
        activity: {
          actor: "worker",
          phase: "implement",
          kind: "turn-started",
          message: "Worker started.",
        },
      }),
    finish: () => store.finishAgentTurn(lease, turn),
    process: (pid) => store.recordExecutionProcess(lease, pid),
    async scheduleAvailability() {
      const state = await store.loadRun(run.runId);
      return store.scheduleAvailabilityRetry(lease, {
        role: input.role,
        checkpoint: input.checkpoint,
        reason: "transport_unavailable",
        contentFingerprint: repository.contentFingerprint,
        expectedRevision: state.revision,
      });
    },
    async restart() {
      await lease.release();
      lease = await store.acquireRunLease(run.runId);
      return createInactivityCoordinator({
        ...parameters,
        lease,
        initialRun: await store.loadRun(run.runId),
      });
    },
  };
}

async function expire(f, coordinator, access = "workspace-write") {
  const entered = Promise.withResolvers();
  let persistedBeforeAbort = false;
  const attempt = coordinator.invoke(
    "worker",
    ({ signal }) =>
      new Promise((resolve, reject) => {
        signal.addEventListener(
          "abort",
          () => {
            void f.store.loadRun(f.run.runId).then((run) => {
              persistedBeforeAbort =
                run.inactivityRecovery?.status === "expired";
              reject(signal.reason);
            }, reject);
          },
          { once: true },
        );
        entered.resolve();
      }),
    { access },
  );
  await entered.promise;
  f.timers.advance(100);
  await assert.rejects(attempt, { code: "ERR_PROVIDER_INACTIVE" });
  assert.equal(persistedBeforeAbort, true);
}

test("inactivity journals before abort, retains its one reconstruction across restart, and clears only after response reconciliation", async (t) => {
  for (const backend of ["codex", "claude"]) {
    const f = await fixture(t, backend);
    let coordinator = f.coordinator;
    await coordinator.before(f.input);
    await f.start();
    await expire(
      f,
      coordinator,
      backend === "codex" ? "read-only" : "workspace-write",
    );
    await f.finish();
    assert.equal(await coordinator.retry(f.input), true);
    let stored = await f.store.loadRun(f.run.runId);
    assert.equal(
      stored.inactivityRecovery.configurationFingerprint,
      providerInactivityFingerprint(100),
    );
    assert.deepEqual(projectInactivityRecovery(stored), {
      role: "worker",
      checkpoint: f.input.checkpoint,
      status: "expired",
      attempt: 1,
    });
    coordinator = await f.restart();
    await coordinator.before(f.input);
    await f.start();
    f.repository.contentFingerprint = "b".repeat(64);
    await expire(f, coordinator);
    await f.finish();
    assert.equal(await coordinator.retry(f.input), false);
    coordinator = await f.restart();
    await assert.rejects(coordinator.before(f.input), {
      code: "ERR_PROVIDER_INACTIVE",
    });
    stored = await f.store.loadRun(f.run.runId);
    assert.equal(stored.inactivityRecovery.attempt, 2);
    assert.equal(stored.inactivityRecovery.contentFingerprint, "b".repeat(64));
    assert.deepEqual(
      f.activities.map(({ kind }) => kind),
      ["expired", "reconstructing", "expired"],
    );
  }
});

test("a returned response clears recovery atomically with reconciled partial content", async (t) => {
  const f = await fixture(t);
  await f.coordinator.before(f.input);
  await f.start();
  await expire(f, f.coordinator);
  await f.finish();
  await f.coordinator.before(f.input);
  await f.start();
  f.repository.contentFingerprint = "b".repeat(64);
  await f.coordinator.invoke(
    "worker",
    async () => ({ structured: { status: "COMPLETED" } }),
    { access: "workspace-write" },
  );
  assert.notEqual(
    (await f.store.loadRun(f.run.runId)).inactivityRecovery,
    null,
  );
  await assert.rejects(f.coordinator.completed("worker"));
  const run = await f.coordinator.completed("worker", {
    patch: {
      pipelineState: {
        workflowState: "IMPLEMENT",
        repositoryBaseline: f.repository,
      },
      counters: { fixRounds: 1 },
    },
  });
  assert.equal(run.inactivityRecovery, null);
  assert.equal(
    run.pipelineState.repositoryBaseline.contentFingerprint,
    "b".repeat(64),
  );
  assert.equal(run.counters.fixRounds, 1);
});

test("commit executor and operator stops cannot acquire an inactivity retry", async (t) => {
  const f = await fixture(t);
  await f.coordinator.before(f.input);
  await f.start();
  await f.coordinator.invoke(
    "worker",
    async ({ onCommitExecution }) => {
      await onCommitExecution();
      f.timers.advance(10_000);
      assert.equal(f.timers.size, 0);
      return {};
    },
    { access: "local-commit" },
  );
  assert.equal((await f.store.loadRun(f.run.runId)).inactivityRecovery, null);
  const stop = new AbortController();
  const entered = Promise.withResolvers();
  const attempt = f.coordinator.invoke(
    "worker",
    ({ signal }) =>
      new Promise((resolve, reject) => {
        signal.addEventListener("abort", () => reject(signal.reason), {
          once: true,
        });
        entered.resolve();
      }),
    { access: "read-only", signal: stop.signal },
  );
  await entered.promise;
  const reason = new Error("operator stop");
  stop.abort(reason);
  f.timers.advance(10_000);
  await assert.rejects(attempt, (cause) => cause === reason);
  assert.equal((await f.store.loadRun(f.run.runId)).inactivityRecovery, null);
});

test("legacy migration freezes the default without configuration reload or fabricated recovery", async (t) => {
  const f = await fixture(t);
  const legacy = {
    ...f.run,
    schemaVersion: 16,
    runtimeCompatibility: { runnerVersion: 1, runStateVersion: 16 },
  };
  for (const field of [
    "providerInactivityTimeoutMs",
    "providerInactivityFingerprint",
    "inactivityRecovery",
  ])
    delete legacy[field];
  const normalized = normalizeRunState(legacy, legacy.runId);
  assert.equal(normalized.providerInactivityTimeoutMs, 1_800_000);
  assert.equal(
    normalized.providerInactivityFingerprint,
    providerInactivityFingerprint(1_800_000),
  );
  assert.equal(normalized.inactivityRecovery, null);
  assert.throws(() =>
    normalizeRunState(
      { ...legacy, providerInactivityTimeoutMs: 1 },
      legacy.runId,
    ),
  );
  assert.throws(() =>
    normalizeRunState(
      { ...f.run, providerInactivityFingerprint: "0".repeat(64) },
      f.run.runId,
    ),
  );
});

test("native fresh reconstruction and inactivity share a durable allowance", async (t) => {
  const f = await fixture(t);
  await f.coordinator.before(f.input);
  await f.start();
  const entered = Promise.withResolvers();
  const attempt = f.coordinator.invoke(
    "worker",
    async ({ onFreshSession, signal }) => {
      assert.equal(await onFreshSession(), true);
      assert.equal(await onFreshSession(), false);
      assert.equal(
        (await f.store.loadRun(f.run.runId)).inactivityRecovery.attempt,
        2,
      );
      return new Promise((resolve, reject) => {
        signal.addEventListener("abort", () => reject(signal.reason), {
          once: true,
        });
        entered.resolve();
      });
    },
    { access: "workspace-write" },
  );
  await entered.promise;
  f.timers.advance(100);
  await assert.rejects(attempt, { code: "ERR_PROVIDER_INACTIVE" });
  await f.finish();
  assert.equal(await f.coordinator.retry(f.input), false);
  const resumed = await f.restart();
  await assert.rejects(resumed.before(f.input), {
    code: "ERR_PROVIDER_INACTIVE",
  });
});

test("both provider roles pause a repeated read-only expiry and resume without refreezing configuration", async (t) => {
  for (const backend of ["codex", "claude"]) {
    const root = await mkdtemp(join(tmpdir(), "inactivity-runner-"));
    t.after(() => rm(root, { recursive: true, force: true }));
    const projectPath = join(root, "project"),
      taskPath = join(root, "task");
    await mkdir(projectPath);
    await mkdir(taskPath);
    await writeFile(join(taskPath, "task.md"), "Plan a change.\n");
    const store = createRunStore({ stateRoot: join(root, "state") });
    const timers = clock();
    const snapshot = ({ allowedPaths }) => ({
      schemaVersion: 1,
      projectPath,
      allowedPaths,
      contentFingerprint: "a".repeat(64),
    });
    const requests = [],
      events = [];
    let calls = 0,
      loads = 0;
    const parameters = {
      runStore: store,
      inactivityTimers: timers,
      onActivity: async (event) => events.push(event),
      loadConfiguration: async () => {
        assert.equal(++loads, 1);
        return parseRunnerConfiguration(
          JSON.stringify({
            schemaVersion: 1,
            defaultBackend: backend,
            providerInactivityTimeoutMs: 100,
          }),
        );
      },
      git: {
        async assertUnchanged() {},
        async inspectPath({ path }) {
          return { path, exists: false };
        },
        async snapshot(input) {
          return snapshot(input);
        },
        async preflight(input) {
          return { snapshot: snapshot(input) };
        },
        async reconcileInterrupted(baseline) {
          return baseline;
        },
      },
      adapters: {
        [backend]: {
          async probe() {
            return {
              version: "fixture",
              structuredOutput: true,
              readOnly: true,
              autonomousWrite: true,
              gitMetadataWriteBlocked: true,
              workspaceWrite: true,
              localCommit: true,
              remoteWriteBlocked: true,
              nativeSessionContinuation: true,
              nativeSessionFork: true,
            };
          },
          async run(request) {
            requests.push(request);
            calls++;
            return new Promise((resolve, reject) => {
              request.signal.addEventListener(
                "abort",
                () => reject(request.signal.reason),
                { once: true },
              );
              timers.advance(100);
            });
          },
        },
      },
    };
    const first = await createRunner(parameters).run({
      pipelineId: "plan-authoring",
      projectPath,
      taskPath,
      settingOverrides: { mode: "lazy" },
    });
    assert.equal(first.run.pause.reason, "backend_unavailable");
    assert.equal(first.run.pause.code, "ERR_PROVIDER_INACTIVE");
    assert.equal(calls, 2);
    assert.equal(first.run.inactivityRecovery.attempt, 2);
    assert.equal(requests[1].session, undefined);
    const second = await createRunner(parameters).resume({
      runId: first.run.runId,
      action: null,
    });
    assert.equal(second.run.pause.reason, "backend_unavailable");
    assert.equal(
      calls,
      3,
      "explicit resume gets one invocation and no new automatic allowance",
    );
    assert.equal(second.run.providerInactivityTimeoutMs, 100);
    assert.equal(loads, 1);
    assert.deepEqual(
      events
        .filter(({ phase }) => phase === "inactivity")
        .map(({ kind }) => kind),
      ["expired", "reconstructing", "expired", "reconstructing", "expired"],
    );
  }
});

test("an expiry already being journaled wins over late progress and settlement", async () => {
  const timers = clock(),
    entered = Promise.withResolvers(),
    persisted = Promise.withResolvers();
  let aborted = false;
  const watch = createInactivityWatchdog({
    timeoutMs: 100,
    timers,
    expire: async () => {
      entered.resolve();
      await persisted.promise;
      aborted = true;
    },
  });
  timers.advance(100);
  await entered.promise;
  watch.progress({ kind: "semantic", activeCommands: 0 });
  assert.equal(timers.size, 0);
  const settled = watch.close();
  assert.equal(aborted, false);
  persisted.resolve();
  await settled;
  assert.equal(aborted, true);
});

test("recovery survives an interrupted attempt-2 launch and cannot be cleared without response", async (t) => {
  const f = await fixture(t);
  await f.coordinator.before(f.input);
  await f.start();
  await expire(f, f.coordinator);
  await f.finish();
  await f.coordinator.before(f.input);
  const resumed = await f.restart();
  assert.equal(await resumed.completed("worker"), undefined);
  await assert.rejects(resumed.before(f.input), {
    code: "ERR_PROVIDER_INACTIVE",
  });
  const state = await f.store.loadRun(f.run.runId);
  assert.equal(state.inactivityRecovery.attempt, 2);
  for (const invalid of [
    { ...state.inactivityRecovery, attempt: 3 },
    { ...state.inactivityRecovery, reconstructionRevision: null },
    { ...state.inactivityRecovery, reconstructionRevision: state.revision + 1 },
    { ...state.inactivityRecovery, role: "unknown" },
    { ...state.inactivityRecovery, checkpoint: "private\ntext" },
    { ...state.inactivityRecovery, configurationFingerprint: "b".repeat(64) },
    { ...state.inactivityRecovery, raw: "payload" },
  ])
    assert.throws(() =>
      normalizeRunState({ ...state, inactivityRecovery: invalid }, state.runId),
    );
});

test("only a newly scheduled availability failure can continue a consumed reconstruction after restart", async (t) => {
  let now = Date.parse("2026-09-30T12:00:00.000Z");
  const f = await fixture(t, "codex", { clock: () => new Date(now) });
  await f.scheduleAvailability();
  now += 5_000;
  await f.coordinator.before(f.input);
  await f.start();
  await expire(f, f.coordinator);
  await f.finish();
  await f.coordinator.before(f.input);

  let resumed = await f.restart();
  await assert.rejects(resumed.before(f.input), {
    code: "ERR_PROVIDER_INACTIVE",
  });

  // A separate availability failure may continue its own backoff, once.
  await f.start();
  await f.finish();
  await f.scheduleAvailability();
  resumed = await f.restart();
  await resumed.before(f.input);
  resumed = await f.restart();
  await assert.rejects(resumed.before(f.input), {
    code: "ERR_PROVIDER_INACTIVE",
  });
});

test("expiry evidence can be journaled while execution is owned, without allowing workflow advancement", async (t) => {
  const f = await fixture(t);
  await f.coordinator.before(f.input);
  await f.start();
  await f.process(process.pid);
  await expire(f, f.coordinator);
  const stored = await f.store.loadRun(f.run.runId);
  assert.equal(stored.executionProcess.pid, process.pid);
  assert.equal(stored.inactivityRecovery.status, "expired");
  assert.deepEqual(stored.pipelineState, f.run.pipelineState);
  await assert.rejects(f.finish(), { code: "ERR_EXECUTION_PROCESS_ACTIVE" });
  await assert.rejects(f.coordinator.retry(f.input), {
    code: "ERR_INACTIVITY_RECOVERY",
  });
  await f.process(null);
  await f.finish();
  assert.equal(await f.coordinator.retry(f.input), true);
});

test("an interrupted expiry publication retains journal evidence before abort without authorizing an immediate retry", async (t) => {
  let interrupt = false;
  const f = await fixture(t, "codex", {
    onTransitionBoundary(point) {
      if (interrupt && point === "event-appended") {
        interrupt = false;
        throw new Error("lost publication");
      }
    },
  });
  await f.coordinator.before(f.input);
  await f.start();
  const entered = Promise.withResolvers();
  const attempt = f.coordinator.invoke(
    "worker",
    ({ signal }) =>
      new Promise((resolve, reject) => {
        signal.addEventListener("abort", () => reject(signal.reason), {
          once: true,
        });
        entered.resolve();
      }),
    { access: "read-only" },
  );
  await entered.promise;
  interrupt = true;
  f.timers.advance(100);
  await assert.rejects(attempt, { code: "ERR_INACTIVITY_RECOVERY" });
  assert.equal(
    (await f.store.loadRun(f.run.runId)).inactivityRecovery.attempt,
    1,
  );
  await f.finish();
  const resumed = await f.restart();
  await resumed.before(f.input);
  assert.equal(
    (await f.store.loadRun(f.run.runId)).inactivityRecovery.attempt,
    2,
  );
});

test("a provider safety failure keeps precedence over a raced inactivity abort", async (t) => {
  const f = await fixture(t);
  await f.coordinator.before(f.input);
  await f.start();
  const entered = Promise.withResolvers();
  const safety = Object.assign(new Error("Forbidden operation"), {
    code: "ERR_FORBIDDEN_OPERATION",
  });
  const attempt = f.coordinator.invoke(
    "worker",
    ({ signal }) =>
      new Promise((resolve, reject) => {
        signal.addEventListener("abort", () => reject(safety), { once: true });
        entered.resolve();
      }),
    { access: "workspace-write" },
  );
  await entered.promise;
  f.timers.advance(100);
  await assert.rejects(attempt, (cause) => cause === safety);
  assert.equal(f.coordinator.eligible(safety), false);
});
