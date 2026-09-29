import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { AgentBoundaryError, PROVIDER_REGISTRY } from "../src/agents/index.js";
import { createRunner } from "../src/runner/index.js";
import { parseRunnerConfiguration } from "../src/config/index.js";
import { createAvailabilityCoordinator } from "../src/runner/availability.js";
import { createStopMonitor } from "../src/runner/stops.js";
import {
  createRunStore,
  projectAvailabilityRetry,
} from "../src/state/index.js";

const fingerprint = "a".repeat(64);
function unavailable(backend, overrides = {}) {
  return new AgentBoundaryError(
    { code: "ERR_BACKEND_UNAVAILABLE" },
    {
      failureClass:
        backend === "codex" ? "turn_server_overloaded" : "provider_unavailable",
      checkpoint: "turn",
      outcome: "rejected",
      effect: "possible",
      retry: "transient",
      availabilityReason: "temporarily_overloaded",
      ...overrides,
    },
  );
}

async function fixture(t, backend = "codex") {
  const root = await mkdtemp(join(tmpdir(), "runner-availability-"));

  const projectPath = join(root, "project");
  const taskPath = join(root, "task");
  await Promise.all([mkdir(projectPath), mkdir(taskPath)]);
  let now = Date.parse("2026-09-29T10:00:00.000Z");
  const options = {
    stateRoot: join(root, "state"),
    clock: () => new Date(now),
  };
  let store = createRunStore(options);
  let { state: run, lease } = await store.createRun({
    pipelineId: "plan-execution",
    pipelineStateVersion: 1,
    projectPath,
    taskPath,
    roles: { worker: { backend } },
    pipelineState: { workflowState: "IMPLEMENT" },
    availabilityPolicy: { initialDelayMs: 5_000, maxDelayMs: 7_000 },
  });
  t.after(async () => {
    await lease.release();
    await rm(root, { recursive: true, force: true });
  });
  const events = [];
  const delays = [];
  let changed = false;
  const parameters = {
    runId: run.runId,
    lease,
    runStore: store,
    providers: PROVIDER_REGISTRY,
    git: {
      async assertUnchanged() {
        assert.equal(changed, false, "unsafe repository");
      },
    },
    publish: async (activity) => events.push(activity),
    validateRun() {},
    monitor: {
      async check() {},
      async wait(operation) {
        return operation(new AbortController().signal);
      },
    },
    clock: () => now,
    wait: async (delay) => {
      delays.push(delay);
      now += delay;
    },
  };
  return {
    get store() {
      return store;
    },
    get lease() {
      return lease;
    },
    run,
    events,
    delays,
    parameters,
    async restart() {
      await lease.release();
      store = createRunStore(options);
      lease = await store.acquireRunLease(run.runId);
      return createAvailabilityCoordinator({
        ...parameters,
        lease,
        runStore: store,
      });
    },
    coordinator: createAvailabilityCoordinator(parameters),
    input: {
      role: "worker",
      checkpoint: "implement:1",
      repository: { contentFingerprint: fingerprint },
    },
    reopen: () => createRunStore(options),
    advance: (ms) => {
      now += ms;
    },
    changeRepository: () => {
      changed = true;
    },
  };
}

test("availability retries survive restart, repeat a ceiling, and reset only on a provider response", async (t) => {
  for (const backend of ["codex", "claude"]) {
    const f = await fixture(t, backend);
    let coordinator = f.coordinator;
    let episodeId;
    const attempts = backend === "codex" ? 3 : 1;
    for (let attempt = 1; attempt <= attempts; attempt++) {
      const scheduled = await coordinator.schedule({
        ...f.input,
        cause: unavailable(backend),
      });
      episodeId ??= scheduled.availabilityRetry.id;
      assert.equal(scheduled.availabilityRetry.id, episodeId);
      assert.equal(scheduled.availabilityRetry.attempt, attempt);
      assert.equal(scheduled.availabilityRetry.contentFingerprint, fingerprint);
      const recovered = await f.reopen().loadRun(f.run.runId);
      assert.deepEqual(
        recovered.availabilityRetry,
        scheduled.availabilityRetry,
      );
      if (attempt === 1) coordinator = await f.restart();
      await coordinator.before(f.input);
      // Starting and retiring a failed turn is not progress.
      await f.store.startAgentTurn(
        f.lease,
        { role: "worker", phase: "implement" },
        {
          activity: {
            actor: "worker",
            phase: "implement",
            kind: "turn-started",
            message: "Provider turn.",
          },
        },
      );
      await f.store.finishAgentTurn(f.lease, {
        role: "worker",
        phase: "implement",
      });
    }
    assert.deepEqual(f.delays, [5000, 7000, 7000].slice(0, attempts));
    assert.deepEqual(
      f.events.map(({ kind }) => kind),
      Array(attempts).fill(["retry-scheduled", "retry-started"]).flat(),
    );
    await f.store.startAgentTurn(
      f.lease,
      { role: "worker", phase: "implement" },
      {
        activity: {
          actor: "worker",
          phase: "implement",
          kind: "turn-started",
          message: "Provider turn.",
        },
      },
    );
    const responseCheckpoint = await coordinator.completed("worker", {
      patch: {
        pipelineState: { workflowState: "REVIEW" },
        counters: { fixRounds: 1 },
      },
    });
    const completed = await f.reopen().loadRun(f.run.runId);
    assert.deepEqual(responseCheckpoint, completed);
    assert.equal(completed.availabilityRetry, null);
    assert.equal(completed.pipelineState.workflowState, "REVIEW");
    assert.equal(completed.counters.fixRounds, 1);
    await f.store.finishAgentTurn(f.lease, {
      role: "worker",
      phase: "implement",
    });
    const restarted = await coordinator.schedule({
      ...f.input,
      cause: unavailable(backend),
    });
    assert.equal(restarted.availabilityRetry.attempt, 1);
    assert.notEqual(restarted.availabilityRetry.id, episodeId);
    assert.deepEqual(Object.keys(projectAvailabilityRetry(restarted)), [
      "role",
      "checkpoint",
      "reason",
      "attempt",
      "delayMs",
      "nextRetryAt",
    ]);
  }
});

test("deadline interruption preserves the checkpoint; overdue recovery dispatches once and unsafe Git prevents retry", async (t) => {
  const f = await fixture(t);
  await f.coordinator.schedule({ ...f.input, cause: unavailable("codex") });
  const episode = (await f.store.loadRun(f.run.runId)).availabilityRetry;
  const abort = new AbortController();
  const interrupted = createAvailabilityCoordinator({
    ...f.parameters,
    wait: async (_delay, signal) => {
      abort.abort(new Error("Owner stopped"));
      signal.throwIfAborted();
    },
    monitor: {
      async check() {},
      async wait(operation) {
        return operation(abort.signal);
      },
    },
  });
  await assert.rejects(interrupted.before(f.input), {
    code: "ERR_AVAILABILITY_RECOVERY",
  });
  assert.deepEqual(
    (await f.reopen().loadRun(f.run.runId)).availabilityRetry,
    episode,
  );
  f.advance(100_000);
  await f.coordinator.before(f.input);
  assert.deepEqual(f.delays, []);
  assert.equal(
    f.events.filter(({ kind }) => kind === "retry-started").length,
    1,
  );
  f.changeRepository();
  await assert.rejects(f.coordinator.before(f.input), {
    code: "ERR_AVAILABILITY_RECOVERY",
  });
  assert.equal(
    f.events.filter(({ kind }) => kind === "retry-started").length,
    1,
  );
});

test("availability requires finite evidence and commit-executor non-start proof", async (t) => {
  const f = await fixture(t);
  for (const cause of [
    new Error("offline"),
    unavailable("codex", { availabilityReason: undefined }),
    unavailable("codex", { availabilityReason: "not_allowed" }),
    unavailable("codex", { effect: "started" }),
    unavailable("codex", { outcome: "ambiguous" }),
    unavailable("codex", { retry: "terminal" }),
  ]) {
    await assert.rejects(f.coordinator.schedule({ ...f.input, cause }), {
      code: "ERR_AVAILABILITY_RECOVERY",
    });
  }
  assert.equal(f.coordinator.preEffect(unavailable("codex")), null);
  assert.deepEqual(
    f.coordinator.preEffect(
      unavailable("codex", {
        checkpoint: "commit",
        commitExecutor: "not_started",
      }),
    ),
    { reason: "temporarily_overloaded", commitExecutor: "not_started" },
  );
  assert.equal((await f.store.loadRun(f.run.runId)).availabilityRetry, null);
});

test("both immediate and deferred operator stops interrupt an availability deadline", async () => {
  for (const effectiveTiming of ["immediate", "after-current-commit"]) {
    const changed = Promise.withResolvers();
    const entered = Promise.withResolvers();
    let current = { revision: 1, stopRequest: null };
    const monitor = createStopMonitor({
      runId: "run",
      lease: {},
      publish: async () => {},
      runStore: {
        async loadRun() {
          return current;
        },
        async waitForRunChange() {
          return changed.promise;
        },
        async recordStopActivity() {
          return current;
        },
      },
    });
    const waiting = monitor.wait(
      (signal) =>
        new Promise((resolve, reject) => {
          signal.addEventListener("abort", () => reject(signal.reason), {
            once: true,
          });
          entered.resolve();
        }),
    );
    await entered.promise;
    current = {
      revision: 2,
      stopRequest: { effectiveTiming, reconciledRevision: null },
    };
    changed.resolve(current);
    await assert.rejects(waiting, { code: "ERR_OPERATOR_STOP_BEFORE_COMMIT" });
    await monitor.close();
  }
});

test("the runner records provider progress before rejecting a malformed response", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "availability-response-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const projectPath = join(root, "project"),
    taskPath = join(root, "task");
  await Promise.all([mkdir(projectPath), mkdir(taskPath)]);
  await writeFile(join(taskPath, "task.md"), "Plan a change.\n");
  let now = Date.parse("2026-09-29T10:00:00.000Z");
  const store = createRunStore({
    stateRoot: join(root, "state"),
    clock: () => new Date(now),
  });
  const events = [];
  let runId,
    calls = 0;
  let reconciledAfterResponse = false;
  const snapshot = ({ allowedPaths }) => ({
    schemaVersion: 1,
    projectPath,
    allowedPaths,
    contentFingerprint: fingerprint,
  });
  const runner = createRunner({
    runStore: store,
    availabilityClock: () => now,
    availabilityWait: async (ms) => {
      now += ms;
    },
    loadConfiguration: async () =>
      parseRunnerConfiguration(
        JSON.stringify({ schemaVersion: 1, defaultBackend: "codex" }),
      ),
    onActivity: async (event) => {
      runId = event.runId;
      events.push(event);
    },
    git: {
      async assertUnchanged() {
        if (calls === 2 && !events.some(({ kind }) => kind === "recovered")) {
          assert.equal(
            (await store.loadRun(runId)).availabilityRetry.attempt,
            1,
          );
          reconciledAfterResponse = true;
        }
      },
      async inspectPath({ path }) {
        return { path, exists: false };
      },
      async snapshot(input) {
        return snapshot(input);
      },
      async preflight(input) {
        return { snapshot: snapshot(input) };
      },
    },
    adapters: {
      codex: {
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
        async run() {
          if (++calls === 1) throw unavailable("codex");
          assert.equal(
            (await store.loadRun(runId)).availabilityRetry.attempt,
            1,
          );
          return { structured: null };
        },
      },
    },
  });
  await assert.rejects(
    runner.run({
      pipelineId: "plan-authoring",
      projectPath,
      taskPath,
      settingOverrides: { mode: "lazy" },
    }),
    { code: "ERR_INVALID_PLAN_AUTHORING_OUTPUT" },
  );
  assert.equal(reconciledAfterResponse, true);
  assert.equal((await store.loadRun(runId)).availabilityRetry, null);
  assert.deepEqual(
    events
      .filter(({ phase }) => phase === "availability")
      .map(({ kind }) => kind),
    ["retry-scheduled", "retry-started", "recovered"],
  );
});
