import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { readlinkSync } from "node:fs";
import {
  lstat,
  mkdir,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { hostname, tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  createClarificationService,
  createGitService,
  createMcpControlPlane,
  createRunner,
  createRunStore,
  createTrustedValidationService,
  DETACHED_RUNTIME_COMPATIBILITY_ENV,
  DETACHED_RUNTIME_COMPATIBILITY_TOKEN,
  DETACHED_STOP_CHECKPOINT_ENV,
  main,
} from "../src/index.js";
import { readProcessIdentity, spawnOwnedProcess } from "../src/agents/index.js";
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

test("initial execution stops settle before preflight despite a distinct stranded worktree owner", async (t) => {
  for (const [kind, phase] of [
    ["cancel_requested", "resume"],
    ["pause_requested", "release"],
  ]) {
    await t.test(`${kind}/${phase}`, async (t) => {
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
        async onActivity(activity) {
          if (phase === "release" && activity.kind === "created") {
            await store.requestOperatorStop({
              runId: activity.runId,
              kind,
              expectedRevision: activity.revision,
              idempotencyKey: "release-stop",
            });
          }
        },
      });
      const created = await runner.create(input);
      let stopped = created.run;
      if (phase === "resume") {
        await store.acquireRunLease(created.run.runId);
        await store.requestOperatorStop({
          runId: created.run.runId,
          kind,
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
        stopped = (
          await recoveredRunner.resume({
            runId: created.run.runId,
            action: null,
          })
        ).run;
        assert.equal(
          await recoveredStore.runLeaseOwnerIsLive(stopped.runId),
          false,
        );
      }
      assert.equal(
        stopped.pipelineState.workflowState,
        kind === "cancel_requested" ? "CANCELED" : "WAITING_FOR_USER",
      );
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
      await assert.rejects(
        lstat(join(fixture.projectPath, "LOCAL_ARTIFACTS")),
        { code: "ENOENT" },
      );
      assert.equal(
        await store.worktreeLeaseOwner(fixture.projectPath, stopped.runId),
        olderRunId,
      );
      assert.deepEqual(
        (await store.loadRun(olderRunId)).stopRequest,
        olderStop,
      );
      await assert.rejects(
        store.acquireWorktreeLease(fixture.projectPath, stopped.runId),
        (error) =>
          error.code === "ERR_WORKTREE_LEASED" &&
          error.message.includes(olderRunId) &&
          error.message.includes(stopped.runId),
      );
      await assert.rejects(runner.resume({ runId: stopped.runId }), {
        code:
          kind === "cancel_requested"
            ? "ERR_RUN_CANCELED"
            : "ERR_WORKTREE_LEASED",
      });
      assert.deepEqual(
        (await store.loadRun(stopped.runId)).pause,
        stopped.pause,
      );
    });
  }
});

test("delayed detached stop children preserve settlement without resuming work", async (t) => {
  for (const kind of ["pause_requested", "cancel_requested"]) {
    await t.test(kind, async (t) => {
      const fixture = await operatorFixture(t, "plan-execution");
      const store = createRunStore({ stateRoot: fixture.stateRoot });
      const delegate = createExecutionAdapter();
      const runner = runnerFor(
        fixture,
        { codex: delegate },
        { runStore: store },
      );
      const { run } = await runner.create({
        pipelineId: "plan-execution",
        projectPath: fixture.projectPath,
        taskPath: fixture.taskPath,
      });
      const stop = await store.requestOperatorStop({
        runId: run.runId,
        kind,
        expectedRevision: run.revision,
        idempotencyKey: `delayed-${kind}`,
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
      assert.equal(exitCode, kind === "pause_requested" ? 2 : 0);
      assert.deepEqual(await store.loadRun(run.runId), settled);
      assert.equal(delegate.calls.length, 0);
    });
  }
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

test("operator stops abort active read-only turns across representative pipeline modes", async (t) => {
  for (const [pipelineId, mode, kind] of [
    ["plan-authoring", "independent", "cancel_requested"],
    ["plan-execution", "lazy", "pause_requested"],
    ["polishing", "independent", "cancel_requested"],
  ]) {
    await t.test(`${pipelineId} ${mode} ${kind}`, async (t) => {
      const fixture = await operatorFixture(t, pipelineId);
      const store = createRunStore({ stateRoot: fixture.stateRoot });
      const delegate =
        pipelineId === "plan-authoring"
          ? createAdapter()
          : createExecutionAdapter();
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
        pipelineId,
        settingOverrides: { mode },
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
      const receipt = await runner.requestOperatorStop({
        runId,
        kind,
        expectedRevision: before.revision,
        idempotencyKey: kind,
      });
      const stopped = (await executing).run;
      assert.equal(requests, 1);
      assert.equal(
        stopped.pipelineState.workflowState,
        kind === "pause_requested" ? "WAITING_FOR_USER" : "CANCELED",
      );
      assert.deepEqual(
        stopped.pause.operatorResume.activeTurn,
        before.activeTurn,
      );
      assert.equal(stopped.pause.operatorResume.workflowState, "CLARIFY");
      assert.equal(stopped.pause.resumeAction, null);
      assert.equal(stopped.activeTurn, null);
      assert.deepEqual(stopped.roles, before.roles);
      assert.deepEqual(stopped.sessionLineage, before.sessionLineage);
      assert.deepEqual((await runner.status(runId)).run, stopped);
      assert.equal(await store.runIsLeased(runId), false);
      if (pipelineId !== "plan-authoring")
        assert.equal(
          await store.worktreeIsLeased(fixture.projectPath, runId),
          false,
        );
      assert.deepEqual(
        await runner.requestOperatorStop({
          runId,
          kind,
          expectedRevision: before.revision,
          idempotencyKey: kind,
        }),
        receipt,
      );
      if (kind === "cancel_requested")
        await assert.rejects(runner.resume({ runId, action: null }), {
          code: "ERR_RUN_CANCELED",
        });
    });
  }
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

test("operator stops reconcile native provider ownership before releasing leases", async (t) => {
  for (const access of ["read-only", "workspace-write"]) {
    await t.test(access, async (t) => {
      const fixture = await operatorFixture(t, "polishing");
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
              if (request.access !== access) return delegate.run(request);
              const source = `${access === "workspace-write" ? "require('node:fs').writeFileSync('partial.txt', 'preserved');" : ""}
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
      const runId = (
        await runner.create({
          pipelineId: "polishing",
          projectPath: fixture.projectPath,
          taskPath: fixture.taskPath,
          proactiveClarification: false,
          roleOverrides: {},
          sourceSession: null,
        })
      ).run.runId;
      const executing = runner.resume({ runId, action: null });
      await Promise.race([
        started.promise,
        executing.then(() => assert.fail("Provider did not start")),
      ]);
      const before = await store.loadRun(runId);
      assert.equal(before.executionProcess.pid, child.ownedPid);
      assert.ok(before.executionProcess.ancestryBaseline.length > 0);
      assert.equal(await store.runIsLeased(runId), true);
      const kind =
        access === "read-only" ? "pause_requested" : "cancel_requested";
      await runner.requestOperatorStop({
        runId,
        kind,
        expectedRevision: before.revision,
        idempotencyKey: "native-stop",
      });
      const stopped = (await executing).run;
      assert.equal(
        stopped.pause.reason,
        access === "read-only" ? "operator_paused" : "operator_canceled",
      );
      assert.equal(stopped.executionProcess, null);
      assert.equal(await store.runIsLeased(runId), false);
      assert.equal(
        await store.worktreeIsLeased(fixture.projectPath, runId),
        false,
      );
      assert.throws(() => process.kill(-child.pid, 0), { code: "ESRCH" });
      if (access === "workspace-write")
        assert.equal(
          await readFile(join(fixture.projectPath, "partial.txt"), "utf8"),
          "preserved",
        );
    });
  }
});

test("operator pause preserves writable partial content and reconstructs the primary without reforking", async (t) => {
  for (const pipelineId of ["plan-execution", "polishing"]) {
    await t.test(pipelineId, async (t) => {
      const fixture = await operatorFixture(t, pipelineId);
      const store = createRunStore({ stateRoot: fixture.stateRoot });
      const delegate = createExecutionAdapter();
      let primaryTurns = 0;
      let runId;
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
              const current = await store.loadRun(runId);
              await runner.requestOperatorStop({
                runId,
                expectedRevision: current.revision,
                kind:
                  primaryTurns === 1 ? "pause_requested" : "cancel_requested",
                idempotencyKey: `stop-${primaryTurns}`,
              });
              return delegate.run(request);
            },
          },
        },
        { runStore: store },
      );
      const prepared = await runner.create({
        pipelineId,
        projectPath: fixture.projectPath,
        taskPath: fixture.taskPath,
        proactiveClarification: false,
        roleOverrides: {},
        sourceSession: { backend: "codex", id: SOURCE_SESSION },
      });
      runId = prepared.run.runId;
      const paused = (await runner.resume({ runId, action: null })).run;
      assert.equal(paused.pause.reason, "operator_paused");
      assert.equal(
        paused.pause.operatorResume.workflowState,
        pipelineId === "plan-execution" ? "IMPLEMENT" : "POLISH",
      );
      assert.match(
        await readFile(join(fixture.projectPath, "partial.js"), "utf8"),
        /partial = true/u,
      );
      assert.equal(paused.pipelineState.finalizedFingerprint, null);
      const canceled = (await runner.resume({ runId, action: null })).run;
      assert.equal(canceled.pipelineState.workflowState, "CANCELED");
      assert.equal(primaryTurns, 2);
      assert.deepEqual(canceled.sessionLineage, paused.sessionLineage);
    });
  }
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

test("operator cancellation racing a consumed commit verifies and records its effect exactly once", async (t) => {
  const fixture = await operatorFixture(t, "plan-execution");
  const store = createRunStore({ stateRoot: fixture.stateRoot });
  const delegate = createExecutionAdapter();
  let runner,
    runId,
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
            const current = await store.loadRun(runId);
            await runner.requestOperatorStop({
              runId,
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
  runId = (
    await runner.create({
      pipelineId: "plan-execution",
      projectPath: fixture.projectPath,
      taskPath: fixture.taskPath,
      proactiveClarification: false,
      roleOverrides: {},
      sourceSession: null,
    })
  ).run.runId;
  const stopped = (await runner.resume({ runId, action: null })).run;
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
  await assert.rejects(runner.resume({ runId, action: null }), {
    code: "ERR_RUN_CANCELED",
  });
  assert.equal(commits, 1);
});

test("operator pause after commit consumption but before invocation retires only the unused authorization", async (t) => {
  const fixture = await operatorFixture(t, "plan-execution");
  const store = createRunStore({ stateRoot: fixture.stateRoot });
  const git = createGitService();
  const delegate = createExecutionAdapter();
  let runner,
    runId,
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
            const current = await store.loadRun(runId);
            await runner.requestOperatorStop({
              runId,
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
  runId = (
    await runner.create({
      pipelineId: "plan-execution",
      projectPath: fixture.projectPath,
      taskPath: fixture.taskPath,
      proactiveClarification: false,
      roleOverrides: {},
      sourceSession: null,
    })
  ).run.runId;
  const paused = (await runner.resume({ runId, action: null })).run;
  assert.equal(paused.pause.reason, "operator_paused");
  assert.equal(paused.pause.operatorResume.workflowState, "COMMIT");
  assert.equal(paused.pause.operatorResume.pause, null);
  assert.equal(paused.pipelineState.pendingCommit, null);
  assert.equal(
    delegate.calls.filter((request) => request.access === "local-commit")
      .length,
    0,
  );
  const completed = (await runner.resume({ runId, action: null })).run;
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
      async (t) => {
        const fixture = await operatorFixture(t, "plan-execution");
        const store = createRunStore({ stateRoot: fixture.stateRoot });
        const delegate = createExecutionAdapter();
        let runner,
          runId,
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
                  const current = await store.loadRun(runId);
                  await runner.requestOperatorStop({
                    runId,
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
        runId = (
          await runner.create({
            pipelineId: "plan-execution",
            projectPath: fixture.projectPath,
            taskPath: fixture.taskPath,
            proactiveClarification: false,
            roleOverrides: {},
            sourceSession: null,
          })
        ).run.runId;
        const paused = (await runner.resume({ runId, action: null })).run;
        assert.equal(paused.pause.reason, "operator_paused");
        assert.equal(paused.pipelineState.completedCommits.length, 0);
        assert.doesNotMatch(JSON.stringify(paused), /PRIVATE_/u);
        if (aborted) {
          assert.equal(paused.pause.operatorResume.pause, null);
          assert.equal(paused.pipelineState.pendingCommit, null);
          const completed = (await runner.resume({ runId, action: null })).run;
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
          const restored = (await runner.resume({ runId, action: null })).run;
          assert.equal(restored.pause.reason, "commit_failed");
          assert.equal(attempts, 1);
        }
      },
    );
  }
});

test("operator pause racing handoff preserves staged content without staging again on resume", async (t) => {
  const fixture = await operatorFixture(t, "polishing");
  const store = createRunStore({ stateRoot: fixture.stateRoot });
  const git = createGitService();
  let runner,
    runId,
    handoffs = 0;
  runner = runnerFor(
    fixture,
    { codex: createExecutionAdapter() },
    {
      runStore: store,
      git: {
        ...git,
        async stagePolishingHandoff(options) {
          handoffs += 1;
          const inspected = await git.stagePolishingHandoff(options);
          const current = await store.loadRun(runId);
          await runner.requestOperatorStop({
            runId,
            kind: "pause_requested",
            expectedRevision: current.revision,
            idempotencyKey: "pause-handoff",
          });
          return inspected;
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
  const stopped = (await runner.resume({ runId, action: null })).run;
  assert.equal(stopped.pause.reason, "operator_paused");
  assert.equal(stopped.pause.operatorResume.workflowState, "DONE");
  assert.equal(
    (await runner.resume({ runId, action: null })).run.pipelineState
      .workflowState,
    "DONE",
  );
  assert.equal(handoffs, 1);
});

test("operator cancellation supersedes pause during trusted validation without accepting check evidence", async (t) => {
  const fixture = await operatorFixture(t, "polishing");
  const store = createRunStore({ stateRoot: fixture.stateRoot });
  const delegate = createExecutionAdapter();
  let runner,
    runId,
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
      configuration: {
        ...RUNNER_CONFIGURATION,
        trustedCommands: {
          hygiene: {
            command: "git diff --check HEAD",
            executable: "git",
            arguments: ["diff", "--check", "HEAD"],
          },
        },
        pipelines: { polishing: { trustedChecks: ["hygiene"] } },
      },
      trustedValidation: {
        async preflight() {},
        async inspectRequirements() {
          return { status: "READY", blockers: [] };
        },
        async execute(request) {
          executions += 1;
          assert.equal(typeof request.onProcess, "function");
          const current = await store.loadRun(runId);
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
              runId,
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
  const canceled = (await runner.resume({ runId, action: null })).run;
  assert.equal(canceled.pipelineState.workflowState, "CANCELED");
  assert.equal(canceled.pipelineState.finalizedFingerprint, null);
  assert.equal(executions, 1);
  assert.equal(await store.runIsLeased(runId), false);
  assert.deepEqual(
    activities.filter((item) => item.phase === "stop").map((item) => item.kind),
    ["stopping", "reconciling", "reconciled"],
  );
});

test("operator stop after host loss reclaims ownership and reconciles before further provider work", async (t) => {
  for (const [kind, timing] of [
    ["pause_requested", "immediate"],
    ["cancel_requested", "after-current-commit"],
  ]) {
    await t.test(`${kind}/${timing}`, async (t) => {
      const fixture = await operatorFixture(t, "plan-execution");
      const BOOT_A = "11111111-1111-4111-8111-111111111111";
      const BOOT_B = "22222222-2222-4222-8222-222222222222";
      const options = {
        stateRoot: fixture.stateRoot,
        resolveStopBoundary,
        hostName: "recovery-host",
        processId: 100,
        processIsAlive: () => true,
        processIdentity: (pid) => ({
          bootId: BOOT_A,
          startTicks: String(pid),
        }),
        leaseStaleMs: 0,
      };
      const store = createRunStore(options);
      const delegate = createExecutionAdapter();
      const runner = runnerFor(
        fixture,
        {
          codex: {
            ...delegate,
            async run(request) {
              if (
                timing === "after-current-commit" &&
                !request.prompt.includes("Implement the changes described")
              )
                return delegate.run(request);
              await request.onProcess(4242, {
                processIdentity: { bootId: BOOT_A, startTicks: "4242" },
                namespaceId: "pid:[4026533000]",
              });
              throw new Error("Simulated execution-owner loss");
            },
          },
        },
        { runStore: store },
      );
      const runId = (
        await runner.create({
          pipelineId: "plan-execution",
          projectPath: fixture.projectPath,
          taskPath: fixture.taskPath,
          proactiveClarification: false,
          roleOverrides: {},
          sourceSession: null,
        })
      ).run.runId;
      await assert.rejects(runner.resume({ runId, action: null }), {
        code: "ERR_EXECUTION_PROCESS_ACTIVE",
      });
      const checkpoint = await store.loadRun(runId);
      assert.equal(checkpoint.executionProcess.namespaceId, "pid:[4026533000]");
      assert.deepEqual(checkpoint.executionProcess.processIdentity, {
        bootId: BOOT_A,
        startTicks: "4242",
      });
      assert.deepEqual(
        checkpoint.executionProcess.launchCutoff,
        checkpoint.executionProcess.processIdentity,
      );
      const rebooted = createRunStore({
        ...options,
        processId: 200,
        processIdentity: (pid) => ({
          bootId: BOOT_B,
          startTicks: String(pid),
        }),
      });
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
        runId,
        kind,
        expectedRevision: checkpoint.revision,
        idempotencyKey: "reboot-stop",
        timing,
      });
      const canceled = (await recoveredRunner.resume({ runId, action: null }))
        .run;
      assert.equal(
        canceled.pipelineState.workflowState,
        kind === "cancel_requested" ? "CANCELED" : "WAITING_FOR_USER",
      );
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
      assert.equal(await rebooted.runIsLeased(runId), false);
      assert.equal(
        await rebooted.worktreeIsLeased(fixture.projectPath, runId),
        false,
      );
    });
  }
});

test("action-free CLI/MCP recovery settles dead sessions", async (t) => {
  for (const [transport, kind] of [
    ["runner", null],
    ["cli", null],
    ["mcp", null],
    ["cli", "pause_requested"],
    ["mcp", "cancel_requested"],
  ]) {
    await t.test(`${transport}/${kind}`, async (t) => {
      const fixture = await operatorFixture(t, "plan-execution");
      const launchIdentity = await readProcessIdentity(process.pid);
      assert.notEqual(launchIdentity, null);
      const ancestryBaseline = [{ ...launchIdentity, pid: process.pid }];
      const namespaceId = readlinkSync("/proc/self/ns/pid");
      const executionPid = 2_000_000_001;
      let originalOwnerAlive = true;
      let executionAlive = true;
      const processIdentity = (pid) =>
        pid === executionPid
          ? launchIdentity
          : { bootId: launchIdentity.bootId, startTicks: String(pid) };
      const options = {
        stateRoot: fixture.stateRoot,
        resolveStopBoundary,
        hostName: "current-boot-recovery-host",
        processId: 100,
        processIsAlive: (pid) =>
          (pid === 100 && originalOwnerAlive) ||
          (pid === executionPid && executionAlive),
        processIdentity,
        leaseStaleMs: 0,
      };
      const store = createRunStore(options);
      const delegate = createExecutionAdapter();
      const runner = runnerFor(
        fixture,
        {
          codex: {
            ...delegate,
            async run(request) {
              await request.onProcess(executionPid, {
                processIdentity: launchIdentity,
                namespaceId,
                ancestryBaseline,
              });
              throw new Error("Simulated execution-owner loss");
            },
          },
        },
        { runStore: store },
      );
      const runId = (
        await runner.create({
          pipelineId: "plan-execution",
          projectPath: fixture.projectPath,
          taskPath: fixture.taskPath,
          proactiveClarification: false,
          roleOverrides: {},
          sourceSession: null,
        })
      ).run.runId;
      await assert.rejects(runner.resume({ runId, action: null }), {
        code: "ERR_EXECUTION_PROCESS_ACTIVE",
      });
      const checkpoint = await store.loadRun(runId);
      assert.equal(checkpoint.executionProcess.pid, executionPid);
      assert.deepEqual(
        checkpoint.executionProcess.launchCutoff,
        launchIdentity,
      );
      assert.deepEqual(
        checkpoint.executionProcess.ancestryBaseline,
        ancestryBaseline,
      );
      const { stdout: repositoryBeforeRecovery } = await executeFile(
        "git",
        ["status", "--short"],
        { cwd: fixture.projectPath },
      );

      originalOwnerAlive = false;
      executionAlive = false;
      const recoveredStore = createRunStore({
        ...options,
        processId: 200,
        processIsAlive: (pid) => pid === 200,
      });
      let resumedTurns = 0;
      let retirementInspections = 0;
      const recoveredRunner = runnerFor(
        fixture,
        {
          codex: {
            ...delegate,
            async run() {
              if (kind !== null)
                assert.fail("Stop recovery must not invoke a provider.");
              resumedTurns++;
              assert.equal(
                (await recoveredStore.loadRun(runId)).executionProcess,
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
          // The owner is synthetic; unrelated host workers must not decide
          // this orchestration fixture's process-table result. Retirement
          // still performs its real identity and namespace checks.
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
      const stopRequest = {
        runId,
        kind,
        expectedRevision: checkpoint.revision,
        idempotencyKey: `${transport}-${kind}`,
        timing: "immediate",
      };
      if (kind !== null) {
        const accepted = await recoveredRunner.requestOperatorStop(stopRequest);
        assert.deepEqual(
          await recoveredRunner.requestOperatorStop(stopRequest),
          accepted,
        );
      }
      const pending = await recoveredStore.loadRun(runId);

      if (transport === "runner") {
        const resumed = recoveredRunner.resume({
          runId,
          action: null,
          expectedRevision: pending.revision,
        });
        if (kind === null)
          await assert.rejects(resumed, {
            code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
          });
        else await resumed;
      } else if (transport === "cli") {
        const exitCode = await main(
          [
            "resume",
            "--run",
            runId,
            "--expected-revision",
            String(pending.revision),
          ],
          {
            runner: recoveredRunner,
            stdout: { write() {} },
            stderr: {
              write(message) {
                if (kind !== null) assert.fail(message);
                else {
                  assert.match(message, /Agent backend turn failed/u);
                  assert.doesNotMatch(message, /Retryable proof failure/u);
                }
              },
            },
          },
        );
        assert.equal(
          exitCode,
          kind === null ? 1 : kind === "pause_requested" ? 2 : 0,
        );
      } else {
        let launches = 0;
        let completion;
        const control = createMcpControlPlane({
          runner: recoveredRunner,
          runStore: recoveredStore,
          launchRun(id, action, launchOptions) {
            launches += 1;
            completion = recoveredRunner
              .resume({
                runId: id,
                action,
                dispatch: launchOptions.dispatch,
                expectedRuntimeCompatibility:
                  launchOptions.expectedRuntimeCompatibility,
              })
              .then(
                ({ run }) =>
                  launchOptions.onExit(
                    run.pipelineState.workflowState === "WAITING_FOR_USER"
                      ? 2
                      : 0,
                  ),
                () => launchOptions.onExit(1),
              );
          },
        });
        const input = {
          runId,
          expectedRevision: pending.revision,
          action: null,
          idempotencyKey: `resume-${kind}`,
        };
        assert.deepEqual(await control.runResume(input), { runId });
        assert.deepEqual(await control.runResume(input), { runId });
        assert.equal(launches, 1);
        await completion;
      }

      const settled = await recoveredStore.loadRun(runId);
      assert.equal(
        settled.pipelineState.workflowState,
        kind === null
          ? checkpoint.pipelineState.workflowState
          : kind === "pause_requested"
            ? "WAITING_FOR_USER"
            : "CANCELED",
      );
      assert.equal(settled.executionProcess, null);
      assert.equal(retirementInspections, 1);
      assert.equal(resumedTurns, kind === null ? 1 : 0);
      if (kind === null) {
        assert.deepEqual(settled.activeTurn, checkpoint.activeTurn);
        assert.equal(settled.pause, null);
      } else {
        assert.deepEqual(settled.stopRequest.settlement, {
          kind: "quiescent",
          commit: null,
        });
        assert.equal(settled.stopRequest.reconciledRevision, settled.revision);
      }
      assert.equal(await recoveredStore.runIsLeased(runId), false);
      assert.equal(
        await recoveredStore.worktreeIsLeased(fixture.projectPath, runId),
        false,
      );
      const { stdout: repositoryAfterRecovery } = await executeFile(
        "git",
        ["status", "--short"],
        { cwd: fixture.projectPath },
      );
      assert.equal(repositoryAfterRecovery, repositoryBeforeRecovery);
    });
  }
});

test("legacy recovery evidence remains non-mutating and compatibility-blocked", async (t) => {
  const fixture = await operatorFixture(t, "plan-execution");
  const launchIdentity = await readProcessIdentity(process.pid);
  assert.notEqual(launchIdentity, null);
  const namespaceId = readlinkSync("/proc/self/ns/pid");
  const executionPid = 2_000_000_002;
  let originalOwnerAlive = true;
  let executionAlive = true;
  const options = {
    stateRoot: fixture.stateRoot,
    resolveStopBoundary,
    hostName: "legacy-recovery-host",
    processId: 100,
    processIsAlive: (pid) =>
      (pid === 100 && originalOwnerAlive) ||
      (pid === executionPid && executionAlive),
    processIdentity: (pid) =>
      pid === executionPid
        ? launchIdentity
        : { bootId: launchIdentity.bootId, startTicks: String(pid) },
    leaseStaleMs: 0,
  };
  const store = createRunStore(options);
  const delegate = createExecutionAdapter();
  const runner = runnerFor(
    fixture,
    {
      codex: {
        ...delegate,
        async run(request) {
          await request.onProcess(executionPid, {
            processIdentity: launchIdentity,
            namespaceId,
          });
          throw new Error("Simulated legacy execution-owner loss");
        },
      },
    },
    { runStore: store },
  );
  const runId = (
    await runner.create({
      pipelineId: "plan-execution",
      projectPath: fixture.projectPath,
      taskPath: fixture.taskPath,
      proactiveClarification: false,
      roleOverrides: {},
      sourceSession: null,
    })
  ).run.runId;
  await assert.rejects(runner.resume({ runId, action: null }), {
    code: "ERR_EXECUTION_PROCESS_ACTIVE",
  });
  const checkpoint = await store.loadRun(runId);
  assert.equal(checkpoint.executionProcess.ancestryBaseline, null);

  originalOwnerAlive = false;
  executionAlive = false;
  const recoveredStore = createRunStore({
    ...options,
    processId: 200,
    processIsAlive: (pid) => pid === 200,
  });
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
    runId,
    kind: "pause_requested",
    expectedRevision: checkpoint.revision,
    idempotencyKey: "legacy-evidence-stop",
    timing: "immediate",
  });
  const durableBefore = await recoveredStore.loadRun(runId);
  const { stdout: repositoryBefore } = await executeFile(
    "git",
    ["status", "--short"],
    { cwd: fixture.projectPath },
  );
  await assert.rejects(recoveredRunner.resume({ runId, action: null }), {
    code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
    message:
      "Owned execution process predates frozen ancestry recovery evidence.",
  });
  assert.deepEqual(await recoveredStore.loadRun(runId), durableBefore);
  assert.equal(await recoveredStore.runIsLeased(runId), true);
  const { stdout: repositoryAfter } = await executeFile(
    "git",
    ["status", "--short"],
    { cwd: fixture.projectPath },
  );
  assert.equal(repositoryAfter, repositoryBefore);
});

test("stop recovery preserves containment failure without reacquiring its held worktree lease", async (t) => {
  const fixture = await operatorFixture(t, "plan-execution");
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
  let runId;
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
            runId,
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
  runId = (
    await runner.create({
      pipelineId: "plan-execution",
      projectPath: fixture.projectPath,
      taskPath: fixture.taskPath,
      proactiveClarification: false,
      roleOverrides: {},
      sourceSession: null,
    })
  ).run.runId;

  await assert.rejects(runner.resume({ runId, action: null }), {
    code: "ERR_EXECUTION_PROCESS_ACTIVE",
  });
  assert.equal(worktreeAcquisitions, 1);
  assert.equal(
    await store.worktreeLeaseOwner(fixture.projectPath, runId),
    runId,
  );
  assert.equal((await store.loadRun(runId)).executionProcess.pid, 4242);

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

for (const recovery of [
  "resume",
  "cancel",
  "configuration pause",
  "Claude resume",
]) {
  test(`retired execution storage is cleaned before ${recovery} after owner loss`, async (t) => {
    const fixture = await operatorFixture(t, "plan-execution");
    if (recovery === "configuration pause") {
      await mkdir(join(fixture.projectPath, "LOCAL_ARTIFACTS"), {
        recursive: true,
      });
      await writeFile(
        join(fixture.projectPath, "LOCAL_ARTIFACTS", "agent-runner.json"),
        JSON.stringify({ schemaVersion: 1, defaultEffort: "current" }),
      );
    }
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
    const adapterOwned = recovery === "Claude resume";
    const root = adapterOwned
      ? join(tmpdir(), `agent-runner-claude-${process.getuid()}`)
      : join(fixture.stateRoot, "..", "execution-storage");
    await mkdir(root, { mode: 0o700 }).catch((cause) => {
      if (cause.code !== "EEXIST") throw cause;
    });
    const rootInfo = await lstat(root, { bigint: true });
    const intent = {
      id: adapterOwned ? randomUUID() : "55555555-5555-4555-8555-555555555555",
      hostname: hostname(),
      commandIdentity: adapterOwned ? CLAUDE_STORAGE_IDENTITY : "a".repeat(64),
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
    // Simulate a supervised child recorded before its owner was lost.
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
            if (adapterOwned) {
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
            }
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
    if (adapterOwned) {
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
      assert.deepEqual(
        blocked.executionResource,
        beforeCleanup.executionResource,
      );
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
      assert.equal(
        await readFile(join(path, "replacement"), "utf8"),
        "unowned",
      );
      await rm(path, { recursive: true });
      await rename(ownedPath, path);
    }
    if (recovery === "cancel") {
      const current = await recoveredStore.loadRun(run.runId);
      await recoveredRunner.requestOperatorStop({
        runId: run.runId,
        kind: "cancel_requested",
        expectedRevision: current.revision,
        idempotencyKey: "storage-recovery-stop",
        timing: "immediate",
      });
      const canceled = (
        await recoveredRunner.resume({ runId: run.runId, action: null })
      ).run;
      assert.equal(canceled.pipelineState.workflowState, "CANCELED");
      assert.equal(providerCalls, 0);
    } else if (recovery === "configuration pause") {
      await mkdir(join(fixture.projectPath, "LOCAL_ARTIFACTS"), {
        recursive: true,
      });
      await writeFile(
        join(fixture.projectPath, "LOCAL_ARTIFACTS", "agent-runner.json"),
        JSON.stringify({ schemaVersion: 1, defaultEffort: "high" }),
      );
      const paused = (
        await recoveredRunner.resume({ runId: run.runId, action: null })
      ).run;
      assert.equal(paused.pause.reason, "project_configuration_changed");
      assert.equal(providerCalls, 0);
    } else {
      await assert.rejects(
        recoveredRunner.resume({ runId: run.runId, action: null }),
        (cause) => {
          assert.equal(cause.name, "AgentBoundaryError", cause.code);
          return true;
        },
      );
      assert.equal(providerCalls, 1);
      if (adapterOwned) {
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
      }
    }
    const saved = await recoveredStore.loadRun(run.runId);
    assert.equal(saved.executionProcess, null);
    assert.equal(saved.executionResource, null);
    await assert.rejects(lstat(path), { code: "ENOENT" });
    assert.equal(await recoveredStore.runIsLeased(run.runId), false);
  });
}
