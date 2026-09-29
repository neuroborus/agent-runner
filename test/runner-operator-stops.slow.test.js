import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { readlinkSync } from "node:fs";
import {
  cp,
  lstat,
  mkdir,
  readFile,
  readdir,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { hostname, tmpdir } from "node:os";
import { join } from "node:path";
import test, { after, before } from "node:test";

import {
  createClarificationService,
  createGitService,
  createRunner,
  createRunStore,
  createTrustedValidationService,
  DETACHED_RUNTIME_COMPATIBILITY_ENV,
  DETACHED_RUNTIME_COMPATIBILITY_TOKEN,
  DETACHED_STOP_CHECKPOINT_ENV,
  main,
} from "../src/index.js";
import { spawnOwnedProcess } from "../src/agents/index.js";
import { CLAUDE_STORAGE_IDENTITY } from "../src/agents/claude/index.js";
import { resolveStopBoundary } from "../src/pipeline-registry.js";
import {
  configurationLoader,
  createAdapter,
  createExecutionAdapter,
  executeFile,
  operatorFixture,
  PREPARED_RUN,
  runnerFor,
  RUNNER_CONFIGURATION,
  SOURCE_SESSION,
  strandedPreWorkOwner,
} from "./support/index.js";

const checkpointCleanups = [];
const POLISHING_TRUSTED_CONFIGURATION = {
  ...RUNNER_CONFIGURATION,
  trustedCommands: {
    hygiene: {
      command: "git diff --check HEAD",
      executable: "git",
      arguments: ["diff", "--check", "HEAD"],
    },
  },
  pipelines: { polishing: { trustedChecks: ["hygiene"] } },
};
const RECOVERED_FINALIZATION_SESSION = "recovered-finalization-session";
let executionLifecycle;
let polishingLifecycle;

async function removeCopiedLeases(directoryPath) {
  const entries = await readdir(directoryPath, { withFileTypes: true });
  await Promise.all(
    entries.map(async (entry) => {
      const path = join(directoryPath, entry.name);
      if (entry.isDirectory()) {
        await removeCopiedLeases(path);
      } else if ([".lease", ".lease-reclaiming"].includes(entry.name)) {
        await rm(path, { force: true });
      }
    }),
  );
}

async function createCheckpointFixture(pipelineId) {
  return operatorFixture(
    { after: (cleanup) => checkpointCleanups.push(cleanup) },
    pipelineId,
  );
}

async function captureCheckpoint(fixture, store, runId, name, validate) {
  const directory = join(fixture.workspace, "checkpoints", name);
  const projectSnapshot = join(directory, "project");
  const stateSnapshot = join(directory, "state");
  validate(await store.loadRun(runId));
  await mkdir(directory, { recursive: true });
  await Promise.all([
    cp(fixture.projectPath, projectSnapshot, { recursive: true }),
    cp(fixture.stateRoot, stateSnapshot, { recursive: true }),
  ]);
  await removeCopiedLeases(stateSnapshot);
  return {
    async restore() {
      await Promise.all([
        rm(fixture.projectPath, { recursive: true, force: true }),
        rm(fixture.stateRoot, { recursive: true, force: true }),
      ]);
      await Promise.all([
        cp(projectSnapshot, fixture.projectPath, { recursive: true }),
        cp(stateSnapshot, fixture.stateRoot, { recursive: true }),
      ]);
      validate(
        await createRunStore({ stateRoot: fixture.stateRoot }).loadRun(runId),
      );
      return { ...fixture, runId };
    },
  };
}

async function createExecutionLifecycle() {
  const fixture = await createCheckpointFixture("plan-execution");
  const store = createRunStore({ stateRoot: fixture.stateRoot });
  const git = createGitService();
  const delegate = createExecutionAdapter();
  const checkpoints = {};
  let runId;
  const runner = runnerFor(
    fixture,
    {
      codex: {
        ...delegate,
        async run(request) {
          if (
            request.access === "workspace-write" &&
            checkpoints.implementation === undefined
          )
            checkpoints.implementation = await captureCheckpoint(
              fixture,
              store,
              runId,
              "implementation",
              (run) => {
                assert.equal(run.pipelineState.workflowState, "IMPLEMENT");
                assert.notEqual(run.activeTurn, null);
              },
            );
          return delegate.run(request);
        },
      },
    },
    {
      runStore: store,
      git: {
        ...git,
        async prepareCommit(options) {
          return git.prepareCommit({
            ...options,
            persistPendingCommit: async (authorization) => {
              await options.persistPendingCommit(authorization);
              checkpoints.commit ??= await captureCheckpoint(
                fixture,
                store,
                runId,
                "commit",
                (run) => {
                  assert.equal(run.pipelineState.workflowState, "COMMIT");
                  assert.equal(
                    run.pipelineState.pendingCommit.status,
                    "prepared",
                  );
                },
              );
            },
          });
        },
      },
    },
  );
  runId = (
    await runner.create({
      pipelineId: "plan-execution",
      projectPath: fixture.projectPath,
      taskPath: fixture.taskPath,
      proactiveClarification: false,
      roleOverrides: {},
      sourceSession: { backend: "codex", id: SOURCE_SESSION },
    })
  ).run.runId;
  const completed = (await runner.resume({ runId, action: null })).run;
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.notEqual(checkpoints.implementation, undefined);
  assert.notEqual(checkpoints.commit, undefined);
  return checkpoints;
}

async function createPolishingLifecycle() {
  const fixture = await createCheckpointFixture("polishing");
  const store = createRunStore({ stateRoot: fixture.stateRoot });
  const git = createGitService();
  const delegate = createExecutionAdapter();
  const checkpoints = {};
  let runId;
  const runner = runnerFor(
    fixture,
    {
      codex: {
        ...delegate,
        async run(request) {
          if (
            request.prompt.includes(
              "Run the complete project finalization procedure",
            ) &&
            checkpoints.validation === undefined
          )
            checkpoints.validation = await captureCheckpoint(
              fixture,
              store,
              runId,
              "validation",
              (run) => {
                assert.equal(run.pipelineState.workflowState, "FINALIZE");
                assert.notEqual(run.activeTurn, null);
                assert.equal(run.pipelineState.finalizationResult, null);
              },
            );
          const response = await delegate.run(request);
          if (
            request.prompt.includes(
              "Run the complete project finalization procedure",
            )
          ) {
            (
              response.structured.result ?? response.structured
            ).checks[0].status = "NOT_RUN";
          }
          return response;
        },
      },
    },
    {
      runStore: store,
      configuration: POLISHING_TRUSTED_CONFIGURATION,
      git: {
        ...git,
        async stagePolishingHandoff(options) {
          checkpoints.handoff ??= await captureCheckpoint(
            fixture,
            store,
            runId,
            "handoff",
            (run) => {
              assert.equal(run.pipelineState.workflowState, "HANDOFF");
              assert.notEqual(run.pipelineState.finalizedFingerprint, null);
            },
          );
          return git.stagePolishingHandoff(options);
        },
      },
      trustedValidation: {
        async preflight() {},
        async inspectRequirements() {
          return { status: "READY", blockers: [] };
        },
        async execute(request) {
          return {
            ...request.bindings,
            status: "PASS",
            commandIdentity: request.commandIdentity,
            exitCode: 0,
            signal: null,
            timedOut: false,
            evidence: ["Fixture trusted check passed."],
          };
        },
      },
    },
  );
  runId = (
    await runner.create({
      pipelineId: "polishing",
      projectPath: fixture.projectPath,
      taskPath: fixture.taskPath,
      proactiveClarification: false,
      roleOverrides: {},
      sourceSession: null,
    })
  ).run.runId;
  const completed = (await runner.resume({ runId, action: null })).run;
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.notEqual(checkpoints.validation, undefined);
  assert.notEqual(checkpoints.handoff, undefined);
  return checkpoints;
}

before(async () => {
  executionLifecycle = await createExecutionLifecycle();
  polishingLifecycle = await createPolishingLifecycle();
});

after(async () => {
  await Promise.all(checkpointCleanups.map((cleanup) => cleanup()));
});

test("initial execution stop recovery settles before preflight despite a distinct stranded worktree owner", async (t) => {
  const fixture = await operatorFixture(t, "plan-execution");
  const { store, olderRunId, input } = await strandedPreWorkOwner(fixture);
  const olderStop = (await store.loadRun(olderRunId)).stopRequest;
  const delegate = {
    ...createExecutionAdapter(),
    run: () => assert.fail("Pre-work settlement must not invoke an agent."),
  };
  let worktreeAcquisitions = 0;
  const runner = createRunner({
    adapters: { codex: delegate },
    clarifications: createClarificationService({ interactive: false }),
    git: createGitService(),
    loadConfiguration: configurationLoader(),
    runStore: {
      ...store,
      async acquireWorktreeLease(...args) {
        worktreeAcquisitions += 1;
        return store.acquireWorktreeLease(...args);
      },
    },
  });
  const created = await runner.create(input);
  await store.acquireRunLease(created.run.runId);
  await store.requestOperatorStop({
    runId: created.run.runId,
    kind: "cancel_requested",
    expectedRevision: created.run.revision,
    idempotencyKey: "initial-stop",
  });
  await assert.rejects(runner.resume({ runId: created.run.runId }), {
    code: "ERR_RUN_LEASED",
  });
  const recoveredStore = createRunStore({
    stateRoot: fixture.stateRoot,
    hostName: "stop-recovery-host",
    processId: 300,
    processIsAlive: (pid) => pid === 300,
    processIdentity: (pid) => ({
      bootId: SOURCE_SESSION,
      startTicks: String(pid),
    }),
    leaseStaleMs: 0,
  });
  const recoveredRunner = runnerFor(
    fixture,
    { codex: delegate },
    {
      runStore: {
        ...recoveredStore,
        async acquireWorktreeLease(...args) {
          worktreeAcquisitions += 1;
          return recoveredStore.acquireWorktreeLease(...args);
        },
      },
    },
  );
  const stopped = (
    await recoveredRunner.resume({
      runId: created.run.runId,
      action: null,
    })
  ).run;
  assert.equal(await recoveredStore.runLeaseOwnerIsLive(stopped.runId), false);
  assert.equal(stopped.pipelineState.workflowState, "CANCELED");
  assert.equal(stopped.stopRequest.reconciledRevision, stopped.revision);
  assert.deepEqual(stopped.stopRequest.settlement, {
    kind: "quiescent",
    commit: null,
  });
  assert.equal(stopped.pause.operatorResume.workflowState, "CLARIFY");
  assert.equal(stopped.pipelineState.preflightComplete, false);
  assert.equal(stopped.pipelineState.repositoryBaseline, null);
  assert.equal(stopped.pipelineState.clarificationPath, null);
  assert.equal(worktreeAcquisitions, 0);
  await assert.rejects(lstat(join(fixture.projectPath, "LOCAL_ARTIFACTS")), {
    code: "ENOENT",
  });
  assert.equal(
    await store.worktreeLeaseOwner(fixture.projectPath, stopped.runId),
    olderRunId,
  );
  assert.deepEqual((await store.loadRun(olderRunId)).stopRequest, olderStop);
  await assert.rejects(
    store.acquireWorktreeLease(fixture.projectPath, stopped.runId),
    (error) =>
      error.code === "ERR_WORKTREE_LEASED" &&
      error.message.includes(olderRunId) &&
      error.message.includes(stopped.runId),
  );
  await assert.rejects(runner.resume({ runId: stopped.runId }), {
    code: "ERR_RUN_CANCELED",
  });
  assert.deepEqual((await store.loadRun(stopped.runId)).pause, stopped.pause);
});

test("delayed detached stop child preserves settlement without resuming work", async (t) => {
  const fixture = await operatorFixture(t, "plan-execution");
  const store = createRunStore({ stateRoot: fixture.stateRoot });
  const delegate = createExecutionAdapter();
  const runner = runnerFor(fixture, { codex: delegate }, { runStore: store });
  const { run } = await runner.create({
    pipelineId: "plan-execution",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
  });
  const stop = await store.requestOperatorStop({
    runId: run.runId,
    kind: "pause_requested",
    expectedRevision: run.revision,
    idempotencyKey: "delayed-pause",
  });
  const settled = (await runner.resume({ runId: run.runId })).run;
  const exitCode = await main(["resume", "--run", run.runId], {
    runner,
    environment: {
      [DETACHED_RUNTIME_COMPATIBILITY_ENV]:
        DETACHED_RUNTIME_COMPATIBILITY_TOKEN,
      [DETACHED_STOP_CHECKPOINT_ENV]: String(stop.expectedRevision),
    },
    stdout: { write() {} },
    stderr: {
      write(message) {
        assert.fail(message);
      },
    },
  });
  assert.equal(exitCode, 2);
  assert.deepEqual(await store.loadRun(run.runId), settled);
  assert.equal(delegate.calls.length, 0);
});

test("non-quiescent stop recovery retains worktree exclusion and identifies the other owner", async (t) => {
  const fixture = await operatorFixture(t, "plan-execution");
  const runner = runnerFor(fixture, { codex: createExecutionAdapter() });
  const created = await runner.create({
    pipelineId: "plan-execution",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    proactiveClarification: true,
    roleOverrides: {},
    sourceSession: null,
  });
  const paused = (await runner.resume({ runId: created.run.runId })).run;
  assert.equal(paused.pipelineState.preflightComplete, true);
  assert.notEqual(paused.pipelineState.clarificationPath, null);
  const { store, olderRunId } = await strandedPreWorkOwner(fixture);
  await store.requestOperatorStop({
    runId: paused.runId,
    kind: "cancel_requested",
    expectedRevision: paused.revision,
    idempotencyKey: "non-quiescent-stop",
  });
  const recovering = runnerFor(
    fixture,
    { codex: createExecutionAdapter() },
    { runStore: store },
  );
  await assert.rejects(
    recovering.resume({ runId: paused.runId }),
    (error) =>
      error.code === "ERR_WORKTREE_LEASED" &&
      error.message.includes(olderRunId) &&
      error.message.includes(paused.runId),
  );
  assert.equal(
    (await store.loadRun(paused.runId)).stopRequest.reconciledRevision,
    null,
  );
  assert.equal(
    await store.worktreeLeaseOwner(fixture.projectPath, paused.runId),
    olderRunId,
  );
  await assert.rejects(recovering.resume({ runId: paused.runId }), {
    code: "ERR_RUN_LEASED",
  });
});

test("operator pause aborts an active read-only turn and preserves its resume state", async (t) => {
  const fixture = await operatorFixture(t, "plan-execution");
  const store = createRunStore({ stateRoot: fixture.stateRoot });
  const delegate = createExecutionAdapter();
  const started = Promise.withResolvers();
  let requests = 0;
  const runner = runnerFor(
    fixture,
    {
      codex: {
        ...delegate,
        async run(request) {
          requests += 1;
          started.resolve();
          return new Promise((resolve, reject) => {
            request.signal.addEventListener(
              "abort",
              () => reject(request.signal.reason),
              { once: true },
            );
          });
        },
      },
    },
    { runStore: store },
  );
  const prepared = await runner.create({
    pipelineId: "plan-execution",
    settingOverrides: { mode: "lazy" },
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  });
  const runId = prepared.run.runId;
  const executing = runner.resume({ runId, action: null });
  await Promise.race([
    started.promise,
    executing.then(() => assert.fail("Turn did not start")),
  ]);
  const before = await store.loadRun(runId);
  const input = {
    runId,
    kind: "pause_requested",
    expectedRevision: before.revision,
    idempotencyKey: "pause-active-turn",
  };
  const receipt = await runner.requestOperatorStop(input);
  const stopped = (await executing).run;
  assert.equal(requests, 1);
  assert.equal(stopped.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.deepEqual(stopped.pause.operatorResume.activeTurn, before.activeTurn);
  assert.equal(stopped.pause.operatorResume.workflowState, "CLARIFY");
  assert.equal(stopped.pause.resumeAction, null);
  assert.equal(stopped.activeTurn, null);
  assert.deepEqual(stopped.roles, before.roles);
  assert.deepEqual(stopped.sessionLineage, before.sessionLineage);
  assert.deepEqual((await runner.status(runId)).run, stopped);
  assert.equal(await store.runIsLeased(runId), false);
  assert.equal(await store.worktreeIsLeased(fixture.projectPath, runId), false);
  assert.deepEqual(await runner.requestOperatorStop(input), receipt);
});

test("pre-work retry releases the worktree lease held at reconciliation", async (t) => {
  const fixture = await operatorFixture(t, "plan-execution");
  const store = createRunStore({
    stateRoot: fixture.stateRoot,
    resolveStopBoundary,
  });
  const reconciliationFailure = Object.assign(
    new Error("Simulated interrupted pre-work reconciliation"),
    { code: "ERR_TEST_RECONCILIATION_INTERRUPTED" },
  );
  let reconciliationFailures = 0;
  let runId;
  let worktreeAcquisitions = 0;
  const runner = createRunner({
    adapters: {
      codex: {
        ...createExecutionAdapter(),
        run: () => assert.fail("Pre-work settlement must not invoke an agent."),
      },
    },
    clarifications: createClarificationService({ interactive: false }),
    git: createGitService(),
    loadConfiguration: configurationLoader(),
    runStore: {
      ...store,
      async acquireWorktreeLease(...argumentsList) {
        worktreeAcquisitions += 1;
        return store.acquireWorktreeLease(...argumentsList);
      },
      async recordStopActivity(lease, activity) {
        if (activity.kind === "reconciling" && reconciliationFailures < 1) {
          reconciliationFailures += 1;
          throw reconciliationFailure;
        }
        return store.recordStopActivity(lease, activity);
      },
    },
    async onActivity(activity) {
      if (activity.kind !== "created") return;
      runId = activity.runId;
      await store.requestOperatorStop({
        runId,
        kind: "pause_requested",
        expectedRevision: activity.revision,
        idempotencyKey: "pre-work-retry-stop",
      });
    },
  });

  await assert.rejects(
    runner.run({
      pipelineId: "plan-execution",
      projectPath: fixture.projectPath,
      taskPath: fixture.taskPath,
      proactiveClarification: false,
      roleOverrides: {},
      sourceSession: null,
    }),
    (cause) => cause === reconciliationFailure,
  );
  const stopped = await store.loadRun(runId);
  assert.deepEqual(
    {
      pause: stopped.pause?.reason ?? null,
      reconciliationFailures,
      reconciledRevision: stopped.stopRequest.reconciledRevision,
      revision: stopped.revision,
      runLeased: await store.runIsLeased(runId),
      worktreeAcquisitions,
      worktreeLeased: await store.worktreeIsLeased(fixture.projectPath, runId),
    },
    {
      pause: "operator_paused",
      reconciliationFailures: 1,
      reconciledRevision: stopped.revision,
      revision: stopped.revision,
      runLeased: false,
      worktreeAcquisitions: 1,
      worktreeLeased: false,
    },
  );
});

test("release-time stop settlement releases its worktree lease after publication failure", async (t) => {
  const fixture = await operatorFixture(t, "plan-execution");
  const store = createRunStore({
    stateRoot: fixture.stateRoot,
    resolveStopBoundary,
  });
  const publicationFailure = new Error(
    "Simulated reconciled activity publication failure",
  );
  let runId;
  const runner = createRunner({
    adapters: {
      codex: {
        ...createExecutionAdapter(),
        run: () => assert.fail("Pre-work settlement must not invoke an agent."),
      },
    },
    clarifications: createClarificationService({ interactive: false }),
    git: createGitService(),
    loadConfiguration: configurationLoader(),
    runStore: store,
    async onActivity(activity) {
      if (activity.kind === "created") {
        runId = activity.runId;
        await store.requestOperatorStop({
          runId,
          kind: "pause_requested",
          expectedRevision: activity.revision,
          idempotencyKey: "publication-failure-stop",
        });
      } else if (activity.kind === "reconciled") {
        throw publicationFailure;
      }
    },
  });

  await assert.rejects(
    runner.run({
      pipelineId: "plan-execution",
      projectPath: fixture.projectPath,
      taskPath: fixture.taskPath,
      proactiveClarification: false,
      roleOverrides: {},
      sourceSession: null,
    }),
    (cause) => cause === publicationFailure,
  );
  const settled = await store.loadRun(runId);
  assert.equal(settled.pause.reason, "operator_paused");
  assert.equal(settled.stopRequest.reconciledRevision, settled.revision);
  assert.equal(await store.runIsLeased(runId), false);
  assert.equal(await store.worktreeIsLeased(fixture.projectPath, runId), false);
});

test("operator pause resume restores active state only after worktree ownership", async (t) => {
  const fixture = await operatorFixture(t, "plan-execution");
  const store = createRunStore({ stateRoot: fixture.stateRoot });
  const delegate = createExecutionAdapter();
  const started = Promise.withResolvers();
  let first = true;
  const runner = runnerFor(
    fixture,
    {
      codex: {
        ...delegate,
        async run(request) {
          if (!first) return delegate.run(request);
          first = false;
          started.resolve();
          return new Promise((resolve, reject) => {
            request.signal.addEventListener(
              "abort",
              () => reject(request.signal.reason),
              { once: true },
            );
          });
        },
      },
    },
    { runStore: store },
  );
  const prepared = await runner.create({
    pipelineId: "plan-execution",
    settingOverrides: { mode: "lazy" },
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  });
  const runId = prepared.run.runId;
  const executing = runner.resume({ runId, action: null });
  await Promise.race([
    started.promise,
    executing.then(() => assert.fail("Turn did not start")),
  ]);
  const active = await store.loadRun(runId);
  await runner.requestOperatorStop({
    runId,
    kind: "pause_requested",
    expectedRevision: active.revision,
    idempotencyKey: "pause-before-competing-owner",
  });
  const paused = (await executing).run;
  const competing = await store.acquireWorktreeLease(
    fixture.projectPath,
    PREPARED_RUN,
  );
  try {
    await assert.rejects(runner.resume({ runId, action: null }), {
      code: "ERR_WORKTREE_LEASED",
    });
    assert.deepEqual(await store.loadRun(runId), paused);
  } finally {
    await competing.release();
  }
});

test("runner fails closed when operator stop monitoring fails", async (t) => {
  const fixture = await operatorFixture(t, "plan-authoring");
  const store = createRunStore({ stateRoot: fixture.stateRoot });
  const watchStarted = Promise.withResolvers();
  const operationStarted = Promise.withResolvers();
  const monitorAborted = Promise.withResolvers();
  const releaseOperation = Promise.withResolvers();
  const delegate = createAdapter();
  const prepared = await runnerFor(
    fixture,
    { codex: delegate },
    { runStore: store },
  ).create({
    pipelineId: "plan-authoring",
    settingOverrides: { mode: "lazy" },
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  });
  const runner = runnerFor(
    fixture,
    {
      codex: {
        ...delegate,
        async run(request) {
          request.signal.addEventListener(
            "abort",
            () => monitorAborted.resolve(),
            { once: true },
          );
          operationStarted.resolve();
          await releaseOperation.promise;
          return delegate.run(request);
        },
      },
    },
    {
      runStore: {
        ...store,
        async waitForRunChange() {
          watchStarted.resolve();
          await operationStarted.promise;
          throw new Error("watch failed");
        },
      },
    },
  );

  const executing = runner.resume({ runId: prepared.run.runId, action: null });
  await Promise.all([
    watchStarted.promise,
    operationStarted.promise,
    monitorAborted.promise,
  ]);
  releaseOperation.resolve();

  await assert.rejects(executing, { code: "ERR_STOP_MONITOR_FAILED" });
  assert.equal(await store.runIsLeased(prepared.run.runId), false);
});

test("operator stop contains native provider work and preserves writable content", async (t) => {
  const fixture = await executionLifecycle.implementation.restore();
  const store = createRunStore({ stateRoot: fixture.stateRoot });
  const delegate = createExecutionAdapter();
  const started = Promise.withResolvers();
  let child;
  const runner = runnerFor(
    fixture,
    {
      codex: {
        ...delegate,
        async run(request) {
          if (request.access !== "workspace-write")
            return delegate.run(request);
          const source = `require('node:fs').writeFileSync('partial.txt', 'preserved');
          require('node:fs').writeSync(1, 'ready');
          Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0);`;
          child = spawnOwnedProcess(process.execPath, ["-e", source], {
            cwd: request.cwd,
            env: process.env,
            signal: request.signal,
            onProcess: request.onProcess,
          });
          child.stdout.once("data", () => started.resolve());
          child.stderr.resume();
          child.stdin.end();
          await child.ownedCompletion;
          request.signal.throwIfAborted();
          assert.fail("The native turn must be interrupted");
        },
      },
    },
    { runStore: store },
  );
  t.after(async () => {
    child?.kill();
    await child?.ownedCompletion.catch(() => {});
  });
  const executing = runner.resume({ runId: fixture.runId, action: null });
  await Promise.race([
    started.promise,
    executing.then(() => assert.fail("Provider did not start")),
  ]);
  const before = await store.loadRun(fixture.runId);
  assert.equal(before.executionProcess.pid, child.ownedPid);
  assert.ok(before.executionProcess.ancestryBaseline.length > 0);
  assert.equal(await store.runIsLeased(fixture.runId), true);
  await runner.requestOperatorStop({
    runId: fixture.runId,
    kind: "pause_requested",
    expectedRevision: before.revision,
    idempotencyKey: "native-stop",
  });
  const stopped = (await executing).run;
  assert.equal(stopped.pause.reason, "operator_paused");
  assert.equal(stopped.executionProcess, null);
  assert.equal(await store.runIsLeased(fixture.runId), false);
  assert.equal(
    await store.worktreeIsLeased(fixture.projectPath, fixture.runId),
    false,
  );
  assert.throws(() => process.kill(-child.pid, 0), { code: "ESRCH" });
  assert.equal(
    await readFile(join(fixture.projectPath, "partial.txt"), "utf8"),
    "preserved",
  );
});

test("operator pause preserves writable partial content and reconstructs the primary without reforking", async () => {
  const fixture = await executionLifecycle.implementation.restore();
  const store = createRunStore({ stateRoot: fixture.stateRoot });
  const delegate = createExecutionAdapter();
  let primaryTurns = 0;
  let runner;
  runner = runnerFor(
    fixture,
    {
      codex: {
        ...delegate,
        async run(request) {
          if (request.access !== "workspace-write")
            return delegate.run(request);
          primaryTurns += 1;
          if (primaryTurns === 2) assert.equal(request.session, undefined);
          await writeFile(
            join(fixture.projectPath, "partial.js"),
            "export const partial = true;\n",
          );
          const current = await store.loadRun(fixture.runId);
          await runner.requestOperatorStop({
            runId: fixture.runId,
            expectedRevision: current.revision,
            kind: primaryTurns === 1 ? "pause_requested" : "cancel_requested",
            idempotencyKey: `stop-${primaryTurns}`,
          });
          return delegate.run(request);
        },
      },
    },
    { runStore: store },
  );
  const paused = (await runner.resume({ runId: fixture.runId, action: null }))
    .run;
  assert.equal(paused.pause.reason, "operator_paused");
  assert.equal(paused.pause.operatorResume.workflowState, "IMPLEMENT");
  assert.match(
    await readFile(join(fixture.projectPath, "partial.js"), "utf8"),
    /partial = true/u,
  );
  assert.equal(paused.pipelineState.finalizedFingerprint, null);
  const canceled = (await runner.resume({ runId: fixture.runId, action: null }))
    .run;
  assert.equal(canceled.pipelineState.workflowState, "CANCELED");
  assert.equal(primaryTurns, 2);
  assert.deepEqual(canceled.sessionLineage, paused.sessionLineage);
});

test("operator pause over existing pending input restores the blocker without consuming its authorization", async (t) => {
  const fixture = await operatorFixture(t, "plan-authoring");
  const store = createRunStore({ stateRoot: fixture.stateRoot });
  const delegate = createAdapter({ questionFirst: true });
  const runner = runnerFor(fixture, { codex: delegate }, { runStore: store });
  const original = (
    await runner.run({
      pipelineId: "plan-authoring",
      projectPath: fixture.projectPath,
      taskPath: fixture.taskPath,
      proactiveClarification: false,
      roleOverrides: {},
      sourceSession: null,
    })
  ).run;
  const runId = original.runId;
  await runner.requestOperatorStop({
    runId,
    kind: "pause_requested",
    expectedRevision: original.revision,
    idempotencyKey: "pause",
  });
  const paused = (await runner.resume({ runId, action: null })).run;
  assert.equal(paused.pause.reason, "operator_paused");
  assert.deepEqual(
    paused.pipelineState.pendingEdit,
    original.pipelineState.pendingEdit,
  );
  const calls = delegate.calls.length;
  const restored = (await runner.resume({ runId, action: null })).run;
  assert.deepEqual(restored.pause, original.pause);
  assert.deepEqual(
    restored.pipelineState.pendingEdit,
    original.pipelineState.pendingEdit,
  );
  assert.equal(delegate.calls.length, calls);
});

test("operator cancellation racing a consumed commit verifies and records its effect exactly once", async () => {
  const fixture = await executionLifecycle.commit.restore();
  const store = createRunStore({ stateRoot: fixture.stateRoot });
  const delegate = createExecutionAdapter();
  let runner,
    commits = 0;
  runner = runnerFor(
    fixture,
    {
      codex: {
        ...delegate,
        async run(request) {
          const response = await delegate.run(request);
          if (request.access === "local-commit") {
            commits += 1;
            const current = await store.loadRun(fixture.runId);
            await runner.requestOperatorStop({
              runId: fixture.runId,
              kind: "cancel_requested",
              expectedRevision: current.revision,
              idempotencyKey: "cancel-commit",
            });
          }
          return response;
        },
      },
    },
    { runStore: store },
  );
  const stopped = (await runner.resume({ runId: fixture.runId, action: null }))
    .run;
  assert.equal(stopped.pipelineState.workflowState, "CANCELED");
  assert.equal(stopped.pipelineState.completedCommits.length, 1);
  assert.equal(stopped.pipelineState.pendingCommit, null);
  assert.equal(stopped.pause.operatorResume.workflowState, "DONE");
  assert.equal(
    (
      await executeFile("git", ["-C", fixture.projectPath, "rev-parse", "HEAD"])
    ).stdout.trim(),
    stopped.pipelineState.completedCommits[0],
  );
  await assert.rejects(runner.resume({ runId: fixture.runId, action: null }), {
    code: "ERR_RUN_CANCELED",
  });
  assert.equal(commits, 1);
});

test("operator pause after commit consumption but before invocation retires only the unused authorization", async () => {
  const fixture = await executionLifecycle.commit.restore();
  const store = createRunStore({ stateRoot: fixture.stateRoot });
  const git = createGitService();
  const delegate = createExecutionAdapter();
  let runner,
    consumptions = 0;
  runner = runnerFor(
    fixture,
    { codex: delegate },
    {
      runStore: store,
      git: {
        ...git,
        async consumeCommit(...args) {
          const request = await git.consumeCommit(...args);
          consumptions += 1;
          if (consumptions === 1) {
            const current = await store.loadRun(fixture.runId);
            await runner.requestOperatorStop({
              runId: fixture.runId,
              kind: "pause_requested",
              expectedRevision: current.revision,
              idempotencyKey: "before-commit",
            });
          }
          return request;
        },
      },
    },
  );
  const paused = (await runner.resume({ runId: fixture.runId, action: null }))
    .run;
  assert.equal(paused.pause.reason, "operator_paused");
  assert.equal(paused.pause.operatorResume.workflowState, "COMMIT");
  assert.equal(paused.pause.operatorResume.pause, null);
  assert.equal(paused.pipelineState.pendingCommit, null);
  assert.equal(
    delegate.calls.filter((request) => request.access === "local-commit")
      .length,
    0,
  );
  const completed = (
    await runner.resume({ runId: fixture.runId, action: null })
  ).run;
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.pipelineState.completedCommits.length, 1);
  assert.equal(
    delegate.calls.filter((request) => request.access === "local-commit")
      .length,
    1,
  );
});

test("operator pauses preserve wrapped pre-effect abort proof without discarding unrelated failures", async (t) => {
  for (const aborted of [true, false]) {
    await t.test(
      aborted ? "wrapped abort" : "unrelated rejection",
      async () => {
        const fixture = await executionLifecycle.commit.restore();
        const store = createRunStore({ stateRoot: fixture.stateRoot });
        const delegate = createExecutionAdapter();
        let runner,
          attempts = 0;
        runner = runnerFor(
          fixture,
          {
            codex: {
              ...delegate,
              async run(request) {
                if (request.access === "local-commit" && ++attempts === 1) {
                  const stopped = new Promise((resolve) => {
                    request.signal.addEventListener("abort", resolve, {
                      once: true,
                    });
                    if (request.signal.aborted) resolve();
                  });
                  const current = await store.loadRun(fixture.runId);
                  await runner.requestOperatorStop({
                    runId: fixture.runId,
                    kind: "pause_requested",
                    expectedRevision: current.revision,
                    idempotencyKey: "during-commit-readiness",
                  });
                  await stopped;
                  const cause = aborted
                    ? request.signal.reason
                    : new Error("PRIVATE_NATIVE_FAILURE");
                  throw Object.assign(
                    new Error("PRIVATE_PROVIDER_WRAPPER", {
                      cause: new Error("PRIVATE_PROCESS_WRAPPER", { cause }),
                    }),
                    {
                      code: "ERR_CODEX_LOCAL_COMMIT_INTERRUPTED",
                      effectStarted: false,
                    },
                  );
                }
                return delegate.run(request);
              },
            },
          },
          { runStore: store },
        );
        const paused = (
          await runner.resume({ runId: fixture.runId, action: null })
        ).run;
        assert.equal(paused.pause.reason, "operator_paused");
        assert.equal(paused.pipelineState.completedCommits.length, 0);
        assert.doesNotMatch(JSON.stringify(paused), /PRIVATE_/u);
        if (aborted) {
          assert.equal(paused.pause.operatorResume.pause, null);
          assert.equal(paused.pipelineState.pendingCommit, null);
          const completed = (
            await runner.resume({ runId: fixture.runId, action: null })
          ).run;
          assert.equal(completed.pipelineState.workflowState, "DONE");
          assert.equal(completed.pipelineState.completedCommits.length, 1);
          assert.equal(attempts, 2);
        } else {
          assert.equal(
            paused.pause.operatorResume.pause.reason,
            "commit_failed",
          );
          assert.equal(paused.pipelineState.pendingCommit, null);
          assert.equal(
            paused.pause.operatorResume.pause.code,
            "ERR_CODEX_LOCAL_COMMIT_INTERRUPTED",
          );
          const restored = (
            await runner.resume({ runId: fixture.runId, action: null })
          ).run;
          assert.equal(restored.pause.reason, "commit_failed");
          assert.equal(attempts, 1);
        }
      },
    );
  }
});

test("operator pause racing handoff preserves staged content without staging again on resume", async () => {
  const fixture = await polishingLifecycle.handoff.restore();
  const store = createRunStore({ stateRoot: fixture.stateRoot });
  const git = createGitService();
  let runner,
    handoffs = 0;
  runner = runnerFor(
    fixture,
    { codex: createExecutionAdapter() },
    {
      runStore: store,
      configuration: POLISHING_TRUSTED_CONFIGURATION,
      trustedValidation: {
        async preflight() {},
        async inspectRequirements() {
          return { status: "READY", blockers: [] };
        },
        execute: () =>
          assert.fail("Handoff recovery must not repeat trusted validation."),
      },
      git: {
        ...git,
        async stagePolishingHandoff(options) {
          handoffs += 1;
          const inspected = await git.stagePolishingHandoff(options);
          const current = await store.loadRun(fixture.runId);
          await runner.requestOperatorStop({
            runId: fixture.runId,
            kind: "pause_requested",
            expectedRevision: current.revision,
            idempotencyKey: "pause-handoff",
          });
          return inspected;
        },
      },
    },
  );
  const stopped = (await runner.resume({ runId: fixture.runId, action: null }))
    .run;
  assert.equal(stopped.pause.reason, "operator_paused");
  assert.equal(stopped.pause.operatorResume.workflowState, "DONE");
  assert.equal(
    (await runner.resume({ runId: fixture.runId, action: null })).run
      .pipelineState.workflowState,
    "DONE",
  );
  assert.equal(handoffs, 1);
});

test("operator cancellation supersedes pause during trusted validation without accepting check evidence", async () => {
  const fixture = await polishingLifecycle.validation.restore();
  const store = createRunStore({ stateRoot: fixture.stateRoot });
  const delegate = createExecutionAdapter();
  let runner,
    executions = 0;
  const activities = [];
  runner = runnerFor(
    fixture,
    {
      codex: {
        ...delegate,
        async run(request) {
          const response = await delegate.run(request);
          if (
            request.prompt.includes(
              "Run the complete project finalization procedure",
            )
          ) {
            assert.equal(request.session, undefined);
            response.sessionId = RECOVERED_FINALIZATION_SESSION;
            (
              response.structured.result ?? response.structured
            ).checks[0].status = "NOT_RUN";
          }
          return response;
        },
      },
    },
    {
      runStore: store,
      activities,
      configuration: POLISHING_TRUSTED_CONFIGURATION,
      trustedValidation: {
        async preflight() {},
        async inspectRequirements() {
          return { status: "READY", blockers: [] };
        },
        async execute(request) {
          executions += 1;
          assert.equal(typeof request.onProcess, "function");
          const current = await store.loadRun(fixture.runId);
          const stopped = new Promise((resolve, reject) =>
            request.signal.addEventListener(
              "abort",
              () => reject(request.signal.reason),
              { once: true },
            ),
          );
          // Attach rejection handling before asynchronously accepting both requests.
          stopped.catch(() => {});
          for (const kind of ["pause_requested", "cancel_requested"]) {
            await runner.requestOperatorStop({
              runId: fixture.runId,
              kind,
              expectedRevision: current.revision,
              idempotencyKey: kind,
            });
          }
          return stopped;
        },
      },
    },
  );
  const canceled = (await runner.resume({ runId: fixture.runId, action: null }))
    .run;
  assert.equal(canceled.pipelineState.workflowState, "CANCELED");
  assert.equal(canceled.pipelineState.finalizedFingerprint, null);
  assert.equal(executions, 1);
  assert.equal(await store.runIsLeased(fixture.runId), false);
  assert.deepEqual(
    activities.filter((item) => item.phase === "stop").map((item) => item.kind),
    ["stopping", "reconciling", "reconciled"],
  );
});

test("operator stop after host loss reclaims ownership and reconciles before further provider work", async () => {
  const fixture = await executionLifecycle.implementation.restore();
  const bootA = "11111111-1111-4111-8111-111111111111";
  const bootB = "22222222-2222-4222-8222-222222222222";
  const options = {
    stateRoot: fixture.stateRoot,
    resolveStopBoundary,
    hostName: "recovery-host",
    processId: 100,
    processIsAlive: () => true,
    processIdentity: (pid) => ({ bootId: bootA, startTicks: String(pid) }),
    leaseStaleMs: 0,
  };
  const store = createRunStore(options);
  const lease = await store.acquireRunLease(fixture.runId);
  await store.acquireWorktreeLease(fixture.projectPath, fixture.runId);
  const checkpoint = await store.recordExecutionProcess(lease, 4242, {
    processIdentity: { bootId: bootA, startTicks: "4242" },
    namespaceId: "pid:[4026533000]",
  });
  await assert.rejects(lease.release(), {
    code: "ERR_EXECUTION_PROCESS_ACTIVE",
  });
  assert.equal(checkpoint.executionProcess.namespaceId, "pid:[4026533000]");
  assert.deepEqual(checkpoint.executionProcess.processIdentity, {
    bootId: bootA,
    startTicks: "4242",
  });
  assert.deepEqual(
    checkpoint.executionProcess.launchCutoff,
    checkpoint.executionProcess.processIdentity,
  );

  const rebooted = createRunStore({
    ...options,
    processId: 200,
    processIdentity: (pid) => ({ bootId: bootB, startTicks: String(pid) }),
  });
  const delegate = createExecutionAdapter();
  const recoveredRunner = runnerFor(
    fixture,
    {
      codex: {
        ...delegate,
        async run() {
          assert.fail("Stop recovery must not invoke a provider");
        },
      },
    },
    { runStore: rebooted },
  );
  await recoveredRunner.requestOperatorStop({
    runId: fixture.runId,
    kind: "cancel_requested",
    expectedRevision: checkpoint.revision,
    idempotencyKey: "reboot-stop",
    timing: "after-current-commit",
  });
  const canceled = (
    await recoveredRunner.resume({ runId: fixture.runId, action: null })
  ).run;
  assert.equal(canceled.pipelineState.workflowState, "CANCELED");
  assert.equal(canceled.executionProcess, null);
  assert.deepEqual(canceled.stopRequest.settlement, {
    kind: "quiescent",
    commit: null,
  });
  assert.equal(canceled.pipelineState.completedCommits.length, 0);
  assert.deepEqual(
    canceled.pause.operatorResume.activeTurn,
    checkpoint.activeTurn,
  );
  assert.equal(await rebooted.runIsLeased(fixture.runId), false);
  assert.equal(
    await rebooted.worktreeIsLeased(fixture.projectPath, fixture.runId),
    false,
  );
});

test("action-free recovery retires a dead session before further provider work", async () => {
  const fixture = await executionLifecycle.implementation.restore();
  const bootId = "11111111-1111-4111-8111-111111111111";
  const executionPid = 2_000_000_001;
  const launchIdentity = { bootId, startTicks: String(executionPid) };
  const ancestryBaseline = [{ bootId, pid: 100, startTicks: "100" }];
  const namespaceId = readlinkSync("/proc/self/ns/pid");
  const options = {
    stateRoot: fixture.stateRoot,
    resolveStopBoundary,
    hostName: "current-boot-recovery-host",
    processId: 100,
    processIsAlive: () => true,
    processIdentity: (pid) =>
      pid === executionPid
        ? launchIdentity
        : { bootId, startTicks: String(pid) },
    leaseStaleMs: 0,
  };
  const store = createRunStore(options);
  const lease = await store.acquireRunLease(fixture.runId);
  await store.acquireWorktreeLease(fixture.projectPath, fixture.runId);
  const checkpoint = await store.recordExecutionProcess(lease, executionPid, {
    processIdentity: launchIdentity,
    namespaceId,
    ancestryBaseline,
  });
  await assert.rejects(lease.release(), {
    code: "ERR_EXECUTION_PROCESS_ACTIVE",
  });
  assert.deepEqual(checkpoint.executionProcess.launchCutoff, launchIdentity);
  assert.deepEqual(
    checkpoint.executionProcess.ancestryBaseline,
    ancestryBaseline,
  );
  const { stdout: repositoryBeforeRecovery } = await executeFile(
    "git",
    ["status", "--short"],
    { cwd: fixture.projectPath },
  );

  const recoveredStore = createRunStore({
    ...options,
    processId: 200,
    processIsAlive: (pid) => pid === 200,
  });
  let resumedTurns = 0;
  let retirementInspections = 0;
  const delegate = createExecutionAdapter();
  const recoveredRunner = runnerFor(
    fixture,
    {
      codex: {
        ...delegate,
        async run() {
          resumedTurns++;
          assert.equal(
            (await recoveredStore.loadRun(fixture.runId)).executionProcess,
            null,
          );
          throw Object.assign(new Error("Retryable proof failure"), {
            code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
          });
        },
      },
    },
    {
      runStore: recoveredStore,
      inspectSessionProcesses(sessionId, _token, inspection) {
        assert.equal(sessionId, executionPid);
        assert.deepEqual(inspection, {
          ancestryBaseline,
          controlGroup: null,
          includeSession: true,
        });
        retirementInspections++;
        return [];
      },
    },
  );
  await assert.rejects(
    recoveredRunner.resume({
      runId: fixture.runId,
      action: null,
      expectedRevision: checkpoint.revision,
    }),
    { code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE" },
  );

  const settled = await recoveredStore.loadRun(fixture.runId);
  assert.equal(
    settled.pipelineState.workflowState,
    checkpoint.pipelineState.workflowState,
  );
  assert.equal(settled.executionProcess, null);
  assert.equal(retirementInspections, 1);
  assert.equal(resumedTurns, 1);
  assert.deepEqual(settled.activeTurn, checkpoint.activeTurn);
  assert.equal(settled.pause, null);
  assert.equal(await recoveredStore.runIsLeased(fixture.runId), false);
  assert.equal(
    await recoveredStore.worktreeIsLeased(fixture.projectPath, fixture.runId),
    false,
  );
  const { stdout: repositoryAfterRecovery } = await executeFile(
    "git",
    ["status", "--short"],
    { cwd: fixture.projectPath },
  );
  assert.equal(repositoryAfterRecovery, repositoryBeforeRecovery);
});

test("legacy recovery evidence remains non-mutating and compatibility-blocked", async () => {
  const fixture = await executionLifecycle.implementation.restore();
  const bootId = "11111111-1111-4111-8111-111111111111";
  const executionPid = 2_000_000_002;
  const launchIdentity = { bootId, startTicks: String(executionPid) };
  const namespaceId = readlinkSync("/proc/self/ns/pid");
  const options = {
    stateRoot: fixture.stateRoot,
    resolveStopBoundary,
    hostName: "legacy-recovery-host",
    processId: 100,
    processIsAlive: () => true,
    processIdentity: (pid) =>
      pid === executionPid
        ? launchIdentity
        : { bootId, startTicks: String(pid) },
    leaseStaleMs: 0,
  };
  const store = createRunStore(options);
  const lease = await store.acquireRunLease(fixture.runId);
  await store.acquireWorktreeLease(fixture.projectPath, fixture.runId);
  const checkpoint = await store.recordExecutionProcess(lease, executionPid, {
    processIdentity: launchIdentity,
    namespaceId,
  });
  await assert.rejects(lease.release(), {
    code: "ERR_EXECUTION_PROCESS_ACTIVE",
  });
  assert.equal(checkpoint.executionProcess.ancestryBaseline, null);

  const recoveredStore = createRunStore({
    ...options,
    processId: 200,
    processIsAlive: (pid) => pid === 200,
  });
  const delegate = createExecutionAdapter();
  const recoveredRunner = runnerFor(
    fixture,
    {
      codex: {
        ...delegate,
        run: () =>
          assert.fail("Compatibility recovery must not invoke a provider."),
      },
    },
    { runStore: recoveredStore },
  );
  await recoveredRunner.requestOperatorStop({
    runId: fixture.runId,
    kind: "pause_requested",
    expectedRevision: checkpoint.revision,
    idempotencyKey: "legacy-evidence-stop",
    timing: "immediate",
  });
  const durableBefore = await recoveredStore.loadRun(fixture.runId);
  const { stdout: repositoryBefore } = await executeFile(
    "git",
    ["status", "--short"],
    { cwd: fixture.projectPath },
  );
  await assert.rejects(
    recoveredRunner.resume({ runId: fixture.runId, action: null }),
    {
      code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
      message:
        "Owned execution process predates frozen ancestry recovery evidence.",
    },
  );
  assert.deepEqual(await recoveredStore.loadRun(fixture.runId), durableBefore);
  assert.equal(await recoveredStore.runIsLeased(fixture.runId), true);
  const { stdout: repositoryAfter } = await executeFile(
    "git",
    ["status", "--short"],
    { cwd: fixture.projectPath },
  );
  assert.equal(repositoryAfter, repositoryBefore);
});

test("stop recovery preserves containment failure without reacquiring its held worktree lease", async () => {
  const fixture = await executionLifecycle.implementation.restore();
  const bootA = "11111111-1111-4111-8111-111111111111";
  const bootB = "22222222-2222-4222-8222-222222222222";
  let originalOwnerAlive = true;
  const options = {
    stateRoot: fixture.stateRoot,
    resolveStopBoundary,
    hostName: "recovery-host",
    processId: 100,
    processIsAlive: (pid) => (pid === 100 ? originalOwnerAlive : pid === 4242),
    processIdentity: (pid) => ({ bootId: bootA, startTicks: String(pid) }),
    leaseStaleMs: 0,
  };
  const store = createRunStore(options);
  const delegate = createExecutionAdapter();
  let worktreeAcquisitions = 0;
  const runner = runnerFor(
    fixture,
    {
      codex: {
        ...delegate,
        async run(request) {
          if (!request.prompt.includes("Implement the changes described")) {
            return delegate.run(request);
          }
          const registered = await request.onProcess(4242, {
            processIdentity: { bootId: bootA, startTicks: "4242" },
            namespaceId: "pid:[4026533000]",
          });
          await store.requestOperatorStop({
            runId: fixture.runId,
            kind: "pause_requested",
            expectedRevision: registered.revision,
            idempotencyKey: "containment-stop",
            timing: "immediate",
          });
          throw new Error("Simulated provider interruption");
        },
      },
    },
    {
      runStore: {
        ...store,
        async acquireWorktreeLease(...argumentsList) {
          worktreeAcquisitions += 1;
          return store.acquireWorktreeLease(...argumentsList);
        },
      },
    },
  );
  await assert.rejects(runner.resume({ runId: fixture.runId, action: null }), {
    code: "ERR_EXECUTION_PROCESS_ACTIVE",
  });
  assert.equal(worktreeAcquisitions, 1);
  assert.equal(
    await store.worktreeLeaseOwner(fixture.projectPath, fixture.runId),
    fixture.runId,
  );
  assert.equal((await store.loadRun(fixture.runId)).executionProcess.pid, 4242);

  originalOwnerAlive = false;
  const recoveredStore = createRunStore({
    ...options,
    processId: 200,
    processIsAlive: (pid) => pid === 200,
    processIdentity: (pid) => ({ bootId: bootB, startTicks: String(pid) }),
  });
  const recovered = runnerFor(
    fixture,
    {
      codex: {
        ...delegate,
        run: () => assert.fail("Recovery must not invoke a provider."),
      },
    },
    { runStore: recoveredStore },
  );
  const paused = (
    await recovered.resume({ runId: fixture.runId, action: null })
  ).run;
  assert.equal(paused.pause.reason, "operator_paused");
  assert.equal(paused.executionProcess, null);
  assert.equal(paused.stopRequest.reconciledRevision, paused.revision);
  assert.equal(await recoveredStore.runIsLeased(fixture.runId), false);
  assert.equal(
    await recoveredStore.worktreeIsLeased(fixture.projectPath, fixture.runId),
    false,
  );
});

test("stop recovery retries settlement after process retirement was journaled", async (t) => {
  const fixture = await operatorFixture(t, "plan-execution");
  const bootA = "11111111-1111-4111-8111-111111111111";
  const bootB = "22222222-2222-4222-8222-222222222222";
  let originalOwnerAlive = true;
  const options = {
    stateRoot: fixture.stateRoot,
    resolveStopBoundary,
    hostName: "recovery-host",
    processId: 100,
    processIsAlive: (pid) => pid === 100 && originalOwnerAlive,
    processIdentity: (pid) => ({ bootId: bootA, startTicks: String(pid) }),
    leaseStaleMs: 0,
  };
  const store = createRunStore(options);
  const delegate = createExecutionAdapter();
  const prepared = await runnerFor(
    fixture,
    { codex: delegate },
    { runStore: store },
  ).create({
    pipelineId: "plan-execution",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  });
  const runId = prepared.run.runId;
  const originalLease = await store.acquireRunLease(runId);
  let current = await store.recordExecutionProcess(originalLease, 4242, {
    processIdentity: { bootId: bootA, startTicks: "4242" },
    namespaceId: "pid:[4026533000]",
  });
  await store.requestOperatorStop({
    runId,
    kind: "pause_requested",
    expectedRevision: current.revision,
    idempotencyKey: "retirement-settlement-stop",
    timing: "immediate",
  });
  await assert.rejects(originalLease.release(), {
    code: "ERR_STOP_RECONCILIATION_REQUIRED",
  });

  originalOwnerAlive = false;
  const interruptedStore = createRunStore({
    ...options,
    processId: 200,
    processIsAlive: (pid) => pid === 200,
    processIdentity: (pid) => ({ bootId: bootB, startTicks: String(pid) }),
  });
  const settlementCrash = Object.assign(
    new Error("Simulated crash before stop settlement"),
    { code: "ERR_TEST_SETTLEMENT_CRASH" },
  );
  const interruptedRunner = runnerFor(
    fixture,
    {
      codex: {
        ...delegate,
        run: () => assert.fail("Recovery must not invoke a provider."),
      },
    },
    {
      runStore: {
        ...interruptedStore,
        settleCheckpoint: () => {
          throw settlementCrash;
        },
      },
    },
  );
  await assert.rejects(
    interruptedRunner.resume({ runId, action: null }),
    settlementCrash,
  );
  current = await interruptedStore.loadRun(runId);
  assert.equal(current.executionProcess, null);
  assert.equal(current.stopRequest.reconciledRevision, null);

  const recoveredStore = createRunStore({
    ...options,
    processId: 300,
    processIsAlive: (pid) => pid === 300,
    processIdentity: (pid) => ({ bootId: bootB, startTicks: String(pid) }),
  });
  const recovered = runnerFor(
    fixture,
    {
      codex: {
        ...delegate,
        run: () => assert.fail("Recovery must not invoke a provider."),
      },
    },
    { runStore: recoveredStore },
  );
  const paused = (await recovered.resume({ runId, action: null })).run;
  assert.equal(paused.pause.reason, "operator_paused");
  assert.equal(paused.executionProcess, null);
  assert.equal(paused.stopRequest.reconciledRevision, paused.revision);
  assert.equal(await recoveredStore.runIsLeased(runId), false);
  assert.equal(
    await recoveredStore.worktreeIsLeased(fixture.projectPath, runId),
    false,
  );
});

test("settled stop releases its recovered worktree lease after publication failure", async (t) => {
  const fixture = await operatorFixture(t, "plan-execution");
  const bootA = "11111111-1111-4111-8111-111111111111";
  const bootB = "22222222-2222-4222-8222-222222222222";
  const options = {
    stateRoot: fixture.stateRoot,
    resolveStopBoundary,
    hostName: "recovery-host",
    processId: 100,
    processIsAlive: (pid) => pid === 100,
    processIdentity: (pid) => ({ bootId: bootA, startTicks: String(pid) }),
    leaseStaleMs: 0,
  };
  const store = createRunStore(options);
  const delegate = createExecutionAdapter();
  const prepared = await runnerFor(
    fixture,
    { codex: delegate },
    { runStore: store },
  ).create({
    pipelineId: "plan-execution",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  });
  const runId = prepared.run.runId;
  const originalLease = await store.acquireRunLease(runId);
  const registered = await store.recordExecutionProcess(originalLease, 4242, {
    processIdentity: { bootId: bootA, startTicks: "4242" },
    namespaceId: "pid:[4026533000]",
  });
  await store.requestOperatorStop({
    runId,
    kind: "pause_requested",
    expectedRevision: registered.revision,
    idempotencyKey: "publication-failure-stop",
    timing: "immediate",
  });
  await assert.rejects(originalLease.release(), {
    code: "ERR_STOP_RECONCILIATION_REQUIRED",
  });

  const recoveredStore = createRunStore({
    ...options,
    processId: 200,
    processIsAlive: (pid) => pid === 200,
    processIdentity: (pid) => ({ bootId: bootB, startTicks: String(pid) }),
  });
  const publicationFailure = new Error(
    "Simulated reconciled activity publication failure",
  );
  const recovered = createRunner({
    adapters: {
      codex: {
        ...delegate,
        run: () => assert.fail("Recovery must not invoke a provider."),
      },
    },
    clarifications: createClarificationService({ interactive: false }),
    git: createGitService(),
    loadConfiguration: configurationLoader(),
    onActivity(activity) {
      if (activity.kind === "reconciled") throw publicationFailure;
    },
    runStore: recoveredStore,
  });

  await assert.rejects(
    recovered.resume({ runId, action: null }),
    (cause) => cause === publicationFailure,
  );
  const settled = await recoveredStore.loadRun(runId);
  assert.equal(settled.pause.reason, "operator_paused");
  assert.equal(settled.executionProcess, null);
  assert.equal(settled.stopRequest.reconciledRevision, settled.revision);
  assert.equal(await recoveredStore.runIsLeased(runId), false);
  assert.equal(
    await recoveredStore.worktreeIsLeased(fixture.projectPath, runId),
    false,
  );
});

test("retired Claude execution storage is inode-verified and cleaned after owner loss", async (t) => {
  const fixture = await operatorFixture(t, "plan-execution");
  const bootA = "11111111-1111-4111-8111-111111111111";
  const bootB = "22222222-2222-4222-8222-222222222222";
  const options = {
    stateRoot: fixture.stateRoot,
    resolveStopBoundary,
    hostName: "recovery-host",
    processId: 100,
    processIsAlive: () => true,
    processIdentity: (pid) => ({ bootId: bootA, startTicks: String(pid) }),
    leaseStaleMs: 0,
  };
  const store = createRunStore(options);
  const delegate = createExecutionAdapter();
  const runner = runnerFor(fixture, { codex: delegate }, { runStore: store });
  const { run } = await runner.create({
    pipelineId: "plan-execution",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  });
  const lease = await store.acquireRunLease(run.runId);
  const root = join(tmpdir(), `agent-runner-claude-${process.getuid()}`);
  await mkdir(root, { mode: 0o700 }).catch((cause) => {
    if (cause.code !== "EEXIST") throw cause;
  });
  const rootInfo = await lstat(root, { bigint: true });
  const intent = {
    id: randomUUID(),
    hostname: hostname(),
    commandIdentity: CLAUDE_STORAGE_IDENTITY,
    phase: "allocating",
    root: {
      path: root,
      device: String(rootInfo.dev),
      inode: String(rootInfo.ino),
    },
    directory: null,
  };
  await store.recordExecutionResource(lease, intent);
  const path = join(root, intent.id);
  t.after(async () => {
    await rm(path, { force: true, recursive: true });
    await rm(`${path}-retained`, { force: true, recursive: true });
  });
  await mkdir(path, { mode: 0o700 });
  const directory = await lstat(path, { bigint: true });
  await store.recordExecutionResource(lease, {
    ...intent,
    phase: "allocated",
    directory: {
      device: String(directory.dev),
      inode: String(directory.ino),
    },
  });
  await writeFile(join(path, "interrupted-cache"), "must not be reused");
  await store.recordExecutionProcess(lease, 4242, {
    processIdentity: { bootId: bootA, startTicks: "4242" },
    namespaceId: "pid:[4026533000]",
  });
  await assert.rejects(lease.release(), {
    code: "ERR_EXECUTION_PROCESS_ACTIVE",
  });

  const recoveredStore = createRunStore({
    ...options,
    processId: 200,
    processIdentity: (pid) => ({ bootId: bootB, startTicks: String(pid) }),
  });
  const interruption = new Error("Reached provider after recovery");
  const leaseInspectionFailure = new Error(
    "Transient lease inspection failure",
  );
  let failLeaseInspection = false;
  let providerCalls = 0;
  const recoveredRunner = runnerFor(
    fixture,
    {
      codex: {
        ...delegate,
        async run(request) {
          providerCalls++;
          const saved = await recoveredStore.loadRun(run.runId);
          assert.equal(saved.executionProcess, null);
          assert.equal(saved.executionResource, null);
          await assert.rejects(lstat(path), { code: "ENOENT" });
          // A terminal provider failure may also leave a cleanup record.
          // Resume must retire it without invoking another provider turn.
          await request.onResource(intent);
          await mkdir(path, { mode: 0o700 });
          const allocated = await lstat(path, { bigint: true });
          await request.onResource({
            ...intent,
            phase: "allocated",
            directory: {
              device: String(allocated.dev),
              inode: String(allocated.ino),
            },
          });
          throw interruption;
        },
      },
    },
    {
      runStore: {
        ...recoveredStore,
        async acquireRunLease(...args) {
          if (failLeaseInspection) {
            failLeaseInspection = false;
            throw leaseInspectionFailure;
          }
          return recoveredStore.acquireRunLease(...args);
        },
      },
      trustedValidation: createTrustedValidationService(),
    },
  );

  const ownedPath = `${path}-retained`;
  await rename(path, ownedPath);
  await mkdir(path, { mode: 0o700 });
  await writeFile(join(path, "replacement"), "unowned");
  const beforeCleanup = await recoveredStore.loadRun(run.runId);
  await assert.rejects(
    recoveredRunner.resume({ runId: run.runId, action: null }),
    { code: "ERR_EXECUTION_RESOURCE_UNVERIFIABLE" },
  );
  const blocked = await recoveredStore.loadRun(run.runId);
  assert.deepEqual(blocked.pipelineState, beforeCleanup.pipelineState);
  assert.deepEqual(blocked.executionResource, beforeCleanup.executionResource);
  assert.ok(
    (await recoveredStore.loadRunHistory(run.runId)).events.some(
      (event) => event.activity?.kind === "cleanup-pending",
    ),
  );
  assert.equal(providerCalls, 0);
  failLeaseInspection = true;
  await assert.rejects(
    recoveredRunner.resume({ runId: run.runId, action: null }),
    (cause) => cause === leaseInspectionFailure,
  );
  await assert.rejects(
    recoveredRunner.resume({
      runId: run.runId,
      action: null,
      expectedRevision: blocked.revision - 1,
    }),
    { code: "ERR_RUN_REVISION_CHANGED" },
  );
  assert.equal(await readFile(join(path, "replacement"), "utf8"), "unowned");
  await rm(path, { recursive: true });
  await rename(ownedPath, path);

  await assert.rejects(
    recoveredRunner.resume({ runId: run.runId, action: null }),
    (cause) => {
      assert.equal(cause.name, "AgentBoundaryError", cause.code);
      return true;
    },
  );
  assert.equal(providerCalls, 1);
  const failed = await recoveredStore.loadRun(run.runId);
  assert.equal(failed.pipelineState.workflowState, "FAILED");
  assert.notEqual(failed.executionResource, null);
  const recovered = await recoveredRunner.resume({
    runId: run.runId,
    action: null,
  });
  assert.equal(recovered.run.pipelineState.workflowState, "FAILED");
  assert.equal(recovered.run.pause.code, failed.pause.code);
  assert.equal(providerCalls, 1);
  assert.equal(recovered.run.executionProcess, null);
  assert.equal(recovered.run.executionResource, null);
  await assert.rejects(lstat(path), { code: "ENOENT" });
  assert.equal(await recoveredStore.runIsLeased(run.runId), false);
});
