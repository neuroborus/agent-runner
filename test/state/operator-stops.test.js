import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  createRunStore,
  RUN_STATE_SCHEMA_VERSION,
} from "../../src/state/index.js";

const BOOT_A = "11111111-1111-4111-8111-111111111111";
const BOOT_B = "22222222-2222-4222-8222-222222222222";
const OTHER_RUN = "33333333-3333-4333-8333-333333333333";

function deferred() {
  let resolve;
  const promise = new Promise((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

async function fixture(
  t,
  options = {},
  pipelineState = {
    workflowState: "IMPLEMENT",
    settings: { mode: "independent" },
  },
) {
  const root = await mkdtemp(join(tmpdir(), "agent-runner-stops-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const projectPath = join(root, "project");
  const taskPath = join(root, "task");
  await Promise.all([mkdir(projectPath), mkdir(taskPath)]);
  const storeOptions = {
    stateRoot: join(root, "state"),
    hostName: "test-host",
    processId: 100,
    processIsAlive: () => true,
    processIdentity: (pid) => ({ bootId: BOOT_A, startTicks: String(pid) }),
    leaseStaleMs: 0,
    ...options,
  };
  const store = createRunStore(storeOptions);
  const created = await store.createRun({
    pipelineId: "plan-execution",
    pipelineStateVersion: 1,
    projectPath,
    taskPath,
    roles: { worker: { backend: "codex" } },
    pipelineState,
    hashes: { task: "frozen-task", plan: "frozen-plan" },
    sourceSession: "source-session",
  });
  t.after(() => created.lease.release().catch(() => {}));
  const input = {
    runId: created.state.runId,
    kind: "pause_requested",
    expectedRevision: 1,
    idempotencyKey: "pause-key",
  };
  return { ...created, store, storeOptions, projectPath, input };
}

function advancementOperations(f, activeTurn) {
  return [
    () => f.store.transitionRun(f.lease, { counters: { rounds: 1 } }),
    () =>
      f.store.startAgentTurn(f.lease, activeTurn, {
        activity: {
          actor: activeTurn.role,
          phase: activeTurn.phase,
          kind: "turn-started",
          message: "Worker started.",
        },
      }),
    () => f.store.finishAgentTurn(f.lease, activeTurn),
    () =>
      f.store.recordChildSession(f.lease, {
        role: "worker",
        sessionId: "late-child",
      }),
    () => f.store.writeRunArtifact(f.lease, "late.txt", "late artifact"),
    () => f.store.recordExecutionProcess(f.lease, 101),
  ];
}

async function complete(f, receipt, lease = f.lease, store = f.store) {
  const current = await store.loadRun(f.input.runId);
  const canceled = receipt.kind === "cancel_requested";
  return store.completeOperatorStop(lease, {
    requestId: receipt.requestId,
    patch: {
      pipelineState: {
        ...current.pipelineState,
        workflowState: canceled ? "CANCELED" : "WAITING_FOR_USER",
      },
      pause: {
        reason: canceled ? "operator_canceled" : "operator_paused",
        resumeAction: null,
        operatorResume: {
          workflowState: current.stopRequest.checkpoint.workflowState,
          pause:
            current.pause?.operatorResume === undefined
              ? current.pause
              : current.pause.operatorResume.pause,
          activeTurn: current.stopRequest.checkpoint.activeTurn,
        },
      },
    },
  });
}

test("validates suspended turn and input envelopes before completing an operator stop", async (t) => {
  const f = await fixture(t);
  const receipt = await f.store.requestOperatorStop(f.input);
  const checkpoint = {
    workflowState: "IMPLEMENT",
    pause: null,
    activeTurn: null,
  };
  for (const operatorResume of [
    { workflowState: "IMPLEMENT", pause: null, hidden: null },
    {
      ...checkpoint,
      activeTurn: { role: "worker", phase: "implement", hidden: true },
    },
    {
      ...checkpoint,
      pause: { reason: "clarification_answers_required", inputRequest: {} },
    },
    {
      ...checkpoint,
      pause: { reason: "operator_paused", operatorResume: checkpoint },
    },
  ]) {
    await assert.rejects(
      f.store.completeOperatorStop(f.lease, {
        requestId: receipt.requestId,
        patch: {
          pipelineState: {
            ...f.state.pipelineState,
            workflowState: "WAITING_FOR_USER",
          },
          pause: {
            reason: "operator_paused",
            resumeAction: null,
            operatorResume,
          },
        },
      }),
      { code: "ERR_INVALID_RUN_STATE" },
    );
  }
  await complete(f, receipt);
});

test("records a bounded stop checkpoint during a live turn and replays its receipt", async (t) => {
  const f = await fixture(t);
  const active = await f.store.startAgentTurn(
    f.lease,
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
  const input = { ...f.input, expectedRevision: active.revision };
  const result = await f.store.requestOperatorStop(input);
  const stopped = await f.store.loadRun(input.runId);
  assert.equal(result.revision, active.revision + 1);
  assert.deepEqual(stopped.pipelineState, active.pipelineState);
  assert.deepEqual(stopped.hashes, active.hashes);
  assert.deepEqual(stopped.sessionLineage, active.sessionLineage);
  assert.deepEqual(await f.store.loadStopCheckpoint(input.runId), active);
  assert.deepEqual(stopped.stopRequest.checkpoint, {
    revision: active.revision,
    workflowState: "IMPLEMENT",
    activeTurn: active.activeTurn,
    resumeAction: null,
  });
  assert.deepEqual(await f.store.requestOperatorStop(input), result);
  assert.equal((await f.store.loadRun(input.runId)).revision, result.revision);
  const activity = await f.store.readPublicActivity(input.runId);
  assert.doesNotMatch(
    JSON.stringify(activity),
    /pause-key|requestId|bootId|startTicks/u,
  );
  for (const operation of [
    () => f.lease.release(),
    () => f.store.transitionRun(f.lease, { counters: { rounds: 1 } }),
    () => f.store.finishAgentTurn(f.lease, active.activeTurn),
  ])
    await assert.rejects(operation, {
      code: "ERR_STOP_RECONCILIATION_REQUIRED",
    });
  await assert.rejects(
    f.store.requestOperatorStop({ ...input, kind: "cancel_requested" }),
    { code: "ERR_MCP_IDEMPOTENCY_CONFLICT" },
  );
  await complete(f, result);
});

test("cancellation wins competing requests at one inspected revision", async (t) => {
  for (const cancelFirst of [false, true]) {
    const f = await fixture(t);
    const peer = createRunStore({ ...f.storeOptions, processId: 200 });
    const cancel = {
      ...f.input,
      kind: "cancel_requested",
      idempotencyKey: "cancel-key",
    };
    const requests = [
      () => f.store.requestOperatorStop(f.input),
      () => peer.requestOperatorStop(cancel),
    ];
    if (cancelFirst) requests.reverse();
    const results = await Promise.allSettled(
      requests.map((request) => request()),
    );
    assert.ok(
      results.some(
        (result) =>
          result.status === "fulfilled" &&
          result.value.kind === "cancel_requested",
      ),
    );
    for (const result of results) {
      if (result.status === "rejected")
        assert.equal(result.reason.code, "ERR_STALE_RUN_REVISION");
    }
    const current = await f.store.loadRun(f.input.runId);
    assert.equal(current.stopRequest.kind, "cancel_requested");
    assert.equal(current.stopRequest.checkpoint.revision, 1);
    await assert.rejects(
      peer.requestOperatorStop({
        ...f.input,
        expectedRevision: current.revision,
        idempotencyKey: "late-pause",
      }),
      { code: "ERR_STOP_PENDING" },
    );
    const receipt = await peer.requestOperatorStop(cancel);
    await complete(f, receipt);
    assert.deepEqual(await peer.requestOperatorStop(cancel), receipt);
    await assert.rejects(
      f.store.transitionRun(f.lease, {
        pipelineState: { workflowState: "IMPLEMENT" },
      }),
      { code: "ERR_RUN_CANCELED" },
    );
  }
});

test("cancellation supersedes a pending pause without losing its original receipt", async (t) => {
  const f = await fixture(t);
  const paused = await f.store.requestOperatorStop(f.input);
  const canceled = await f.store.requestOperatorStop({
    ...f.input,
    kind: "cancel_requested",
    idempotencyKey: "cancel",
  });
  await assert.rejects(complete(f, paused), {
    code: "ERR_STOP_REQUEST_CHANGED",
  });
  const terminal = await complete(f, canceled);
  assert.deepEqual(await f.store.requestOperatorStop(f.input), paused);
  assert.deepEqual(await f.store.loadRun(f.input.runId), terminal);
  await assert.rejects(
    f.store.requestOperatorStop({
      ...f.input,
      expectedRevision: terminal.revision,
      idempotencyKey: "revive",
    }),
    { code: "ERR_RUN_TERMINAL" },
  );
});

test("rejects unrelated stale revisions, terminal requests, and malformed input", async (t) => {
  const f = await fixture(t);
  await f.store.transitionRun(f.lease, { counters: { round: 1 } });
  await assert.rejects(f.store.requestOperatorStop(f.input), {
    code: "ERR_STALE_RUN_REVISION",
  });
  for (const input of [
    { ...f.input, expectedRevision: 0 },
    { ...f.input, kind: "stop" },
    { ...f.input, signal: "SIGKILL" },
    { ...f.input, timing: "after-next-turn" },
  ]) {
    await assert.rejects(f.store.requestOperatorStop(input), {
      code: "ERR_INVALID_STOP_REQUEST",
    });
  }
  for (const workflowState of ["DONE", "FAILED", "CANCELED"]) {
    const terminal = await fixture(t, {}, { workflowState });
    await assert.rejects(terminal.store.requestOperatorStop(terminal.input), {
      code: "ERR_RUN_TERMINAL",
    });
    assert.equal(
      (await terminal.store.loadRun(terminal.input.runId)).revision,
      1,
    );
  }
});

test("retains existing pause requirements by reference to the exact suspended state", async (t) => {
  const f = await fixture(
    t,
    {},
    { workflowState: "WAITING_FOR_USER", pendingEdit: { action: "answer" } },
  );
  const baseline = await f.store.transitionRun(f.lease, {
    pause: { reason: "clarification_answers_required", resumeState: "CLARIFY" },
  });
  const result = await f.store.requestOperatorStop({
    ...f.input,
    expectedRevision: baseline.revision,
  });
  const finished = await complete(f, result);
  assert.deepEqual(await f.store.loadStopCheckpoint(f.input.runId), baseline);
  assert.deepEqual(
    finished.pipelineState.pendingEdit,
    baseline.pipelineState.pendingEdit,
  );
  assert.equal(finished.stopRequest.checkpoint.resumeAction, null);
  await assert.rejects(
    f.store.requestOperatorStop({
      ...f.input,
      expectedRevision: finished.revision,
      idempotencyKey: "already-paused",
    }),
    { code: "ERR_STOP_PENDING" },
  );
  // The later runner resume policy must consume the preserved blocker, not bypass it.
  await f.store.transitionRun(f.lease, {
    pause: baseline.pause,
    pipelineState: baseline.pipelineState,
  });
});

test("recovers accepted requests at every journal publication boundary", async (t) => {
  for (const kind of ["pause_requested", "cancel_requested"]) {
    for (const timing of ["immediate", "after-current-commit"]) {
      for (const boundary of [
        "event-appended",
        "state-replaced",
        "progress-replaced",
      ]) {
        let fail = false;
        const f = await fixture(t, {
          resolveStopBoundary: commitBoundary,
          onTransitionBoundary: async (point) => {
            if (fail && point === boundary) {
              fail = false;
              throw new Error("simulated interruption");
            }
          },
        });
        const input = { ...f.input, kind, timing };
        fail = true;
        await assert.rejects(
          f.store.requestOperatorStop(input),
          /simulated interruption/u,
        );
        const pending = await f.store.loadRun(f.input.runId);
        assert.equal(pending.revision, 2);
        const peer = createRunStore({
          ...f.storeOptions,
          onTransitionBoundary: async () => {},
        });
        const receipt = await peer.requestOperatorStop(input);
        assert.equal(receipt.revision, 2);
        assert.equal(receipt.timing, timing);
        assert.deepEqual(
          receipt.targetBoundary,
          pending.stopRequest.targetBoundary,
        );
        assert.equal((await peer.loadRun(f.input.runId)).revision, 2);
        assert.equal(
          (
            await peer.readAction({
              key: f.input.idempotencyKey,
              tool: kind === "pause_requested" ? "run_pause" : "run_cancel",
              arguments: { runId: f.input.runId, expectedRevision: 1, timing },
            })
          ).status,
          "completed",
        );
        await complete(f, receipt);
        const events = (
          await readFile(join(f.directoryPath, "events.jsonl"), "utf8")
        )
          .trim()
          .split("\n")
          .map(JSON.parse);
        assert.deepEqual(
          events.map((event) => event.revision),
          [1, 2, 3],
        );
      }
    }
  }
});

test("serializes a stop behind an ordinary transition without locking status", async (t) => {
  const entered = deferred();
  const release = deferred();
  let armed = false;
  const f = await fixture(t, {
    onTransitionBoundary: async (point) => {
      if (armed && point === "event-appended") {
        armed = false;
        entered.resolve();
        await release.promise;
      }
    },
  });
  armed = true;
  const transition = f.store.transitionRun(f.lease, { counters: { round: 1 } });
  await entered.promise;
  const peer = createRunStore({
    ...f.storeOptions,
    onTransitionBoundary: async () => {},
  });
  const request = assert.rejects(peer.requestOperatorStop(f.input), {
    code: "ERR_STALE_RUN_REVISION",
  });
  assert.equal((await peer.loadRun(f.input.runId)).revision, 2);
  release.resolve();
  await Promise.all([transition, request]);
  assert.equal((await peer.loadRun(f.input.runId)).stopRequest, null);
});

test("a stop winning the mutation boundary prevents a queued workflow transition", async (t) => {
  const entered = deferred();
  const release = deferred();
  let armed = false;
  const f = await fixture(t, {
    onTransitionBoundary: async (point) => {
      if (armed && point === "event-appended") {
        armed = false;
        entered.resolve();
        await release.promise;
      }
    },
  });
  armed = true;
  const request = f.store.requestOperatorStop(f.input);
  await entered.promise;
  const transition = assert.rejects(
    f.store.transitionRun(f.lease, { counters: { round: 1 } }),
    { code: "ERR_STOP_RECONCILIATION_REQUIRED" },
  );
  assert.equal(
    (await f.store.loadRun(f.input.runId)).stopRequest.kind,
    "pause_requested",
  );
  release.resolve();
  const receipt = await request;
  await transition;
  await complete(f, receipt);
});

test("retains worktree exclusion through owner loss until same-run reconciliation", async (t) => {
  for (const kind of ["pause_requested", "cancel_requested"]) {
    for (const timing of ["immediate", "after-current-commit"]) {
      const f = await fixture(t, { resolveStopBoundary: commitBoundary });
      const worktree = await f.store.acquireWorktreeLease(
        f.projectPath,
        f.input.runId,
      );
      const receipt = await f.store.requestOperatorStop({
        ...f.input,
        kind,
        timing,
      });
      await assert.rejects(worktree.release(), {
        code: "ERR_STOP_RECONCILIATION_REQUIRED",
      });
      const recovery = createRunStore({
        ...f.storeOptions,
        processId: 200,
        processIsAlive: (pid) => pid !== 100,
      });
      assert.equal(
        await recovery.worktreeLeaseOwner(f.projectPath, OTHER_RUN),
        f.input.runId,
      );
      assert.equal(await recovery.runLeaseOwnerIsLive(f.input.runId), false);
      await assert.rejects(
        recovery.acquireWorktreeLease(f.projectPath, OTHER_RUN),
        { code: "ERR_WORKTREE_LEASED" },
      );
      const lease = await recovery.acquireRunLease(f.input.runId);
      const reclaimedWorktree = await recovery.acquireWorktreeLease(
        f.projectPath,
        f.input.runId,
      );
      await recovery.recoverRun(lease);
      await complete(f, receipt, lease, recovery);
      await reclaimedWorktree.release();
      await lease.release();
      const next = await recovery.acquireWorktreeLease(
        f.projectPath,
        OTHER_RUN,
      );
      await next.release();
    }
  }
});

test("distinguishes reused PIDs and rebooted owners without trusting process liveness alone", async (t) => {
  for (const identity of [
    { bootId: BOOT_A, startTicks: "999" },
    { bootId: BOOT_B, startTicks: "100" },
  ]) {
    const f = await fixture(t);
    const receipt = await f.store.requestOperatorStop({
      ...f.input,
      kind: "cancel_requested",
    });
    const recovery = createRunStore({
      ...f.storeOptions,
      processId: 200,
      processIdentity: () => identity,
    });
    assert.equal(
      (await recovery.inspectRunLeaseOwner(f.input.runId)).status,
      "replaced",
    );
    assert.equal(await recovery.runLeaseOwnerIsLive(f.input.runId), false);
    const lease = await recovery.acquireRunLease(f.input.runId);
    const restored = await recovery.recoverRun(lease);
    assert.equal(restored.stopRequest.kind, "cancel_requested");
    await complete(f, receipt, lease, recovery);
    await lease.release();
    await assert.rejects(f.lease.release(), { code: "ERR_INVALID_RUN_LEASE" });
  }
});

test("durable subprocess ownership retains worktree exclusion and distinguishes host loss", async (t) => {
  const f = await fixture(t);
  await f.store.acquireWorktreeLease(f.projectPath, f.input.runId);
  const proof = {
    processIdentity: { bootId: BOOT_A, startTicks: "101" },
    namespaceId: "pid:[4026533000]",
  };
  const registered = await f.store.recordExecutionProcess(f.lease, 101, proof);
  assert.equal(registered.executionProcess.pid, 101);
  assert.equal(registered.executionProcess.namespaceId, proof.namespaceId);
  assert.equal(
    (await f.store.inspectExecutionProcess(f.input.runId)).namespaceId,
    proof.namespaceId,
  );
  await assert.rejects(f.store.transitionRun(f.lease, { pause: null }), {
    code: "ERR_EXECUTION_PROCESS_ACTIVE",
  });
  await assert.rejects(f.lease.release(), {
    code: "ERR_EXECUTION_PROCESS_ACTIVE",
  });
  const recovery = createRunStore({
    ...f.storeOptions,
    processId: 200,
    processIsAlive: (pid) => pid !== 100,
    processIdentity: (pid) => ({ bootId: BOOT_B, startTicks: String(pid) }),
  });
  assert.equal(
    (await recovery.inspectExecutionProcess(f.input.runId)).previousBoot,
    true,
  );
  await assert.rejects(
    recovery.acquireWorktreeLease(f.projectPath, OTHER_RUN),
    { code: "ERR_WORKTREE_LEASED" },
  );
  const lease = await recovery.acquireRunLease(f.input.runId);
  await recovery.recordExecutionProcess(lease, null);
  const worktree = await recovery.acquireWorktreeLease(
    f.projectPath,
    f.input.runId,
  );
  await worktree.release();
  await lease.release();
});

test("namespace registration rejects identity replacement without recording a new owner", async (t) => {
  const f = await fixture(t);
  const before = await f.store.loadRun(f.input.runId);
  for (const proof of [
    {
      processIdentity: { bootId: BOOT_A, startTicks: "999" },
      namespaceId: "pid:[1]",
    },
    {
      processIdentity: { bootId: BOOT_B, startTicks: "101" },
      namespaceId: "pid:[1]",
    },
  ]) {
    await assert.rejects(f.store.recordExecutionProcess(f.lease, 101, proof), {
      code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
    });
    assert.deepEqual(await f.store.loadRun(f.input.runId), before);
  }
});

test("unverifiable and foreign-host owners cannot be reclaimed", async (t) => {
  const f = await fixture(t);
  for (const overrides of [
    { processIdentity: () => null },
    { hostName: "other-host", processIsAlive: () => false },
  ]) {
    const peer = createRunStore({
      ...f.storeOptions,
      processId: 200,
      ...overrides,
    });
    assert.equal(
      (await peer.inspectRunLeaseOwner(f.input.runId)).status,
      "unverifiable",
    );
    assert.equal(await peer.runLeaseOwnerIsLive(f.input.runId), true);
    await assert.rejects(peer.acquireRunLease(f.input.runId), {
      code: "ERR_RUN_LEASED",
    });
  }
});

test("migrates legacy envelopes on stop acceptance without changing historical checkpoints", async (t) => {
  const f = await fixture(t);
  const statePath = join(f.directoryPath, "state.json");
  const journalPath = join(f.directoryPath, "events.jsonl");
  const legacy = JSON.parse(await readFile(statePath, "utf8"));
  legacy.schemaVersion = 3;
  legacy.runtimeCompatibility.runStateVersion = 3;
  delete legacy.stopRequest;
  const event = JSON.parse((await readFile(journalPath, "utf8")).trim());
  event.schemaVersion = 3;
  event.state = legacy;
  const historical = JSON.stringify(event) + "\n";
  await writeFile(statePath, JSON.stringify(legacy));
  await writeFile(journalPath, historical);
  assert.equal((await f.store.loadRun(f.input.runId)).stopRequest, null);
  assert.equal(await readFile(journalPath, "utf8"), historical);
  const result = await f.store.requestOperatorStop(f.input);
  const next = await f.store.loadRun(f.input.runId);
  assert.equal(next.schemaVersion, RUN_STATE_SCHEMA_VERSION);
  assert.equal(result.revision, 2);
  assert.ok((await readFile(journalPath, "utf8")).startsWith(historical));
  assert.deepEqual(next.pipelineState, legacy.pipelineState);
  assert.equal(
    (await f.store.loadStopCheckpoint(f.input.runId)).schemaVersion,
    3,
  );
  await complete(f, result);
});

test("recovers interrupted action intents and legacy action leases after reboot", async (t) => {
  const f = await fixture(t);
  const argumentsValue = { runId: f.input.runId, expectedRevision: 1 };
  const action = await f.store.beginAction({
    key: f.input.idempotencyKey,
    tool: "run_pause",
    arguments: argumentsValue,
    context: { runId: f.input.runId },
  });
  await action.release();
  const keyHash = createHash("sha256")
    .update(f.input.idempotencyKey)
    .digest("hex");
  const directory = join(f.storeOptions.stateRoot, "actions", keyHash);
  const legacyLease = {
    token: BOOT_A,
    pid: 99,
    hostname: "test-host",
    acquiredAt: "2020-01-01T00:00:00.000Z",
  };
  await writeFile(join(directory, ".lease"), JSON.stringify(legacyLease));
  const peer = createRunStore({
    ...f.storeOptions,
    processId: 200,
    processIsAlive: (pid) => pid !== 99,
  });
  const result = await peer.requestOperatorStop(f.input);
  assert.equal(result.revision, 2);
  assert.equal((await readdir(directory)).includes(".lease"), false);
  await complete(f, result);
});

test("rechecks a newly accepted stop before another run reclaims its worktree", async (t) => {
  const f = await fixture(t);
  await f.store.acquireWorktreeLease(f.projectPath, f.input.runId);
  const entered = deferred();
  const release = deferred();
  const recovery = createRunStore({
    ...f.storeOptions,
    processId: 200,
    processIsAlive: (pid) => pid !== 100,
    onLeasePublicationBoundary: async ({ filePath, phase }) => {
      if (
        filePath.includes("worktrees/") &&
        filePath.endsWith(".lease-reclaiming") &&
        phase === "prepared"
      ) {
        entered.resolve();
        await release.promise;
      }
    },
  });
  const reclamation = assert.rejects(
    recovery.acquireWorktreeLease(f.projectPath, OTHER_RUN),
    { code: "ERR_WORKTREE_LEASED" },
  );
  await entered.promise;
  const result = await f.store.requestOperatorStop(f.input);
  release.resolve();
  await reclamation;
  assert.equal(
    await recovery.worktreeLeaseOwner(f.projectPath, OTHER_RUN),
    f.input.runId,
  );
  await complete(f, result);
});

test("a stop accepted during reclaim-marker recovery retains the worktree reservation", async (t) => {
  const f = await fixture(t);
  await f.store.acquireWorktreeLease(f.projectPath, f.input.runId);
  const [key] = await readdir(join(f.storeOptions.stateRoot, "worktrees"));
  const directory = join(f.storeOptions.stateRoot, "worktrees", key);
  const record = await readFile(join(directory, ".lease"), "utf8");
  await writeFile(join(directory, ".lease-reclaiming"), record);
  await rm(join(directory, ".lease"));
  const entered = deferred();
  const release = deferred();
  let armed = true;
  const recovery = createRunStore({
    ...f.storeOptions,
    processId: 200,
    processIsAlive: (pid) => pid !== 100,
    onLeasePublicationBoundary: async ({ filePath, phase }) => {
      if (
        armed &&
        phase === "prepared" &&
        (filePath.startsWith(join(f.directoryPath, ".mutation-")) ||
          filePath === join(directory, ".lease"))
      ) {
        armed = false;
        entered.resolve();
        await release.promise;
      }
    },
  });
  const reclamation = assert.rejects(
    recovery.acquireWorktreeLease(f.projectPath, OTHER_RUN),
    { code: "ERR_WORKTREE_LEASED" },
  );
  await entered.promise;
  const receipt = await f.store.requestOperatorStop(f.input);
  release.resolve();
  await reclamation;
  assert.equal(
    await recovery.worktreeLeaseOwner(f.projectPath, OTHER_RUN),
    f.input.runId,
  );
  assert.equal(
    await readFile(join(directory, ".lease-reclaiming"), "utf8"),
    record,
  );
  await complete(f, receipt);
  const worktree = await recovery.acquireWorktreeLease(
    f.projectPath,
    OTHER_RUN,
  );
  await worktree.release();
});

test("serializes worktree recovery when the recorded owner has no pipeline run", async (t) => {
  const f = await fixture(t);
  await f.store.acquireWorktreeLease(f.projectPath, OTHER_RUN);
  const [key] = await readdir(join(f.storeOptions.stateRoot, "worktrees"));
  const directory = join(f.storeOptions.stateRoot, "worktrees", key);
  const leasePath = join(directory, ".lease");
  const record = await readFile(leasePath, "utf8");
  await writeFile(join(directory, ".lease-reclaiming"), record);
  await rm(leasePath);
  const entered = deferred();
  const release = deferred();
  let armed = true;
  const options = {
    ...f.storeOptions,
    processIsAlive: (pid) => pid !== 100,
  };
  const first = createRunStore({
    ...options,
    processId: 200,
    onLeasePublicationBoundary: async ({ filePath, phase }) => {
      if (armed && filePath === leasePath && phase === "prepared") {
        armed = false;
        entered.resolve();
        await release.promise;
      }
    },
  });
  const second = createRunStore({
    ...options,
    processId: 300,
    onLeasePublicationBoundary: async ({ phase }) => {
      if (phase === "published") release.resolve();
    },
  });
  const acquisition = first.acquireWorktreeLease(f.projectPath, f.input.runId);
  await entered.promise;
  const attempts = await Promise.allSettled([
    acquisition,
    second.acquireWorktreeLease(f.projectPath, BOOT_B),
  ]);
  assert.equal(attempts[0].status, "fulfilled");
  assert.equal(attempts[1].status, "rejected");
  assert.equal(attempts[1].reason.code, "ERR_WORKTREE_LEASED");
  assert.equal(
    await second.worktreeLeaseOwner(f.projectPath, BOOT_B),
    f.input.runId,
  );
  await attempts[0].value.release();
});

test("same-key contention creates only one accepted stop and remains exactly retryable", async (t) => {
  const entered = deferred();
  const release = deferred();
  let armed = false;
  const f = await fixture(t, {
    onTransitionBoundary: async (phase) => {
      if (armed && phase === "event-appended") {
        armed = false;
        entered.resolve();
        await release.promise;
      }
    },
  });
  armed = true;
  const first = f.store.requestOperatorStop(f.input);
  await entered.promise;
  const peer = createRunStore({
    ...f.storeOptions,
    onTransitionBoundary: async () => {},
  });
  await assert.rejects(peer.requestOperatorStop(f.input), {
    code: "ERR_MCP_ACTION_IN_PROGRESS",
  });
  release.resolve();
  const result = await first;
  assert.deepEqual(await peer.requestOperatorStop(f.input), result);
  assert.equal((await peer.loadRun(f.input.runId)).revision, 2);
  await complete(f, result);
});

test("completion survives a lost response without recording the outcome twice", async (t) => {
  let armed = false;
  const f = await fixture(t, {
    onTransitionBoundary: async (phase) => {
      if (armed && phase === "event-appended") {
        armed = false;
        throw new Error("completion response lost");
      }
    },
  });
  const result = await f.store.requestOperatorStop({
    ...f.input,
    kind: "cancel_requested",
  });
  armed = true;
  await assert.rejects(complete(f, result), /completion response lost/u);
  const state = await complete(f, result);
  assert.equal(state.revision, 3);
  assert.equal(state.pipelineState.workflowState, "CANCELED");
  assert.equal(await f.store.runIsLeased(f.input.runId), true);
  await f.lease.release();
  assert.equal(await f.store.runIsLeased(f.input.runId), false);
});

test("new mutation control files cannot be overwritten as run artifacts", async (t) => {
  const f = await fixture(t);
  for (const path of [`.mutation-${BOOT_A}`, `.mutation-${BOOT_A}/nested.md`]) {
    await assert.rejects(
      f.store.writeRunArtifact(f.lease, path, "replacement"),
      { code: "ERR_UNSAFE_RUN_ARTIFACT_PATH" },
    );
  }
  const result = await f.store.requestOperatorStop(f.input);
  await assert.rejects(
    f.store.writeRunArtifact(f.lease, "context/worker.md", "late result"),
    { code: "ERR_STOP_RECONCILIATION_REQUIRED" },
  );
  await complete(f, result);
});

test("rejects forged checkpoint and cancellation history without recovering it", async (t) => {
  for (const change of [
    (state) => {
      state.stopRequest.checkpoint.workflowState = "COMMIT";
    },
    (state) => {
      state.stopRequest.kind = "pause_requested";
    },
    (state) => {
      state.stopRequest.extra = "unsupported";
    },
  ]) {
    const f = await fixture(t);
    const result = await f.store.requestOperatorStop({
      ...f.input,
      kind: "cancel_requested",
    });
    await complete(f, result);
    const statePath = join(f.directoryPath, "state.json");
    const journalPath = join(f.directoryPath, "events.jsonl");
    const state = JSON.parse(await readFile(statePath, "utf8"));
    const events = (await readFile(journalPath, "utf8"))
      .trim()
      .split("\n")
      .map(JSON.parse);
    change(state);
    events.at(-1).state = state;
    await writeFile(statePath, JSON.stringify(state));
    await writeFile(journalPath, events.map(JSON.stringify).join("\n") + "\n");
    await assert.rejects(f.store.loadRun(f.input.runId), (error) =>
      ["ERR_INVALID_EVENT_LOG", "ERR_INVALID_RUN_STATE"].includes(error.code),
    );
  }
});

test("legacy completed action receipts replay unchanged and new intents upgrade on write", async (t) => {
  const f = await fixture(t);
  const request = {
    key: "legacy-action",
    tool: "run_resume",
    arguments: { runId: f.input.runId },
    context: { runId: f.input.runId },
  };
  const action = await f.store.beginAction(request);
  await action.release();
  const keyHash = createHash("sha256").update(request.key).digest("hex");
  const directory = join(f.storeOptions.stateRoot, "actions", keyHash);
  const path = join(directory, "action.json");
  const legacy = JSON.parse(await readFile(path, "utf8"));
  legacy.schemaVersion = 1;
  await writeFile(path, JSON.stringify(legacy));
  const resumed = await f.store.beginAction(request);
  await resumed.complete({ runId: f.input.runId });
  await resumed.release();
  assert.equal(JSON.parse(await readFile(path, "utf8")).schemaVersion, 3);
  const completed = JSON.parse(await readFile(path, "utf8"));
  completed.schemaVersion = 1;
  const historical = JSON.stringify(completed);
  await writeFile(path, historical);
  const replay = await f.store.beginAction(request);
  assert.equal(replay.record.status, "completed");
  await replay.release();
  assert.equal(await readFile(path, "utf8"), historical);
});

test("a crash inside worktree ownership transfer retains the stop reservation", async (t) => {
  const f = await fixture(t);
  await f.store.acquireWorktreeLease(f.projectPath, f.input.runId);
  const receipt = await f.store.requestOperatorStop(f.input);
  const [key] = await readdir(join(f.storeOptions.stateRoot, "worktrees"));
  const directory = join(f.storeOptions.stateRoot, "worktrees", key);
  const record = await readFile(join(directory, ".lease"), "utf8");
  await writeFile(join(directory, ".lease-reclaiming"), record);
  await rm(join(directory, ".lease"));
  const recovery = createRunStore({
    ...f.storeOptions,
    processId: 200,
    processIsAlive: (pid) => pid !== 100,
  });
  assert.equal(
    await recovery.worktreeLeaseOwner(f.projectPath, OTHER_RUN),
    f.input.runId,
  );
  await assert.rejects(
    recovery.acquireWorktreeLease(f.projectPath, OTHER_RUN),
    { code: "ERR_WORKTREE_LEASED" },
  );
  const lease = await recovery.acquireRunLease(f.input.runId);
  const worktree = await recovery.acquireWorktreeLease(
    f.projectPath,
    f.input.runId,
  );
  assert.equal((await readdir(directory)).includes(".lease-reclaiming"), false);
  await complete(f, receipt, lease, recovery);
  await worktree.release();
  await lease.release();
});

test("failed replacement publication preserves the original worktree reservation", async (t) => {
  for (const kind of ["pause_requested", "cancel_requested"]) {
    for (const timing of ["immediate", "after-current-commit"]) {
      await t.test(`${kind}/${timing}`, async (t) => {
        const f = await fixture(t, { resolveStopBoundary: commitBoundary });
        await f.store.acquireWorktreeLease(f.projectPath, f.input.runId);
        const receipt = await f.store.requestOperatorStop({
          ...f.input,
          kind,
          timing,
        });
        let armed = true;
        const recovery = createRunStore({
          ...f.storeOptions,
          processId: 200,
          processIsAlive: (pid) => pid !== 100,
          onLeasePublicationBoundary: async ({ filePath, phase }) => {
            if (
              armed &&
              filePath.includes("worktrees/") &&
              filePath.endsWith("/.lease") &&
              phase === "prepared"
            ) {
              // The initial no-replace attempt also prepares a file; fail only once
              // the old lease has been removed inside the owned reclaiming boundary.
              try {
                await readFile(filePath);
              } catch (cause) {
                if (cause.code !== "ENOENT") throw cause;
                armed = false;
                throw new Error("replacement unavailable");
              }
            }
          },
        });
        const lease = await recovery.acquireRunLease(f.input.runId);
        await assert.rejects(
          recovery.acquireWorktreeLease(f.projectPath, f.input.runId),
          /replacement unavailable/u,
        );
        assert.equal(
          await recovery.worktreeLeaseOwner(f.projectPath, OTHER_RUN),
          f.input.runId,
        );
        await assert.rejects(
          recovery.acquireWorktreeLease(f.projectPath, OTHER_RUN),
          { code: "ERR_WORKTREE_LEASED" },
        );
        const worktree = await recovery.acquireWorktreeLease(
          f.projectPath,
          f.input.runId,
        );
        await complete(f, receipt, lease, recovery);
        await worktree.release();
        await lease.release();
      });
    }
  }
});

test("competing controllers recover dead choosing and ready mutation claims", async (t) => {
  for (const ticket of [null, 1]) {
    const f = await fixture(t);
    await writeFile(
      join(f.directoryPath, `.mutation-${BOOT_A}`),
      JSON.stringify({
        schemaVersion: 1,
        token: BOOT_A,
        pid: 100,
        hostname: "test-host",
        processIdentity: { bootId: BOOT_A, startTicks: "100" },
        ticket,
      }),
    );
    const options = { ...f.storeOptions, processIsAlive: (pid) => pid !== 100 };
    const pauseStore = createRunStore({ ...options, processId: 200 });
    const cancelStore = createRunStore({ ...options, processId: 300 });
    const cancel = {
      ...f.input,
      kind: "cancel_requested",
      idempotencyKey: "cancel",
    };
    const results = await Promise.allSettled([
      pauseStore.requestOperatorStop(f.input),
      cancelStore.requestOperatorStop(cancel),
    ]);
    assert.equal(results[1].status, "fulfilled");
    if (results[0].status === "rejected")
      assert.equal(results[0].reason.code, "ERR_STALE_RUN_REVISION");
    assert.equal(
      (await cancelStore.loadRun(f.input.runId)).stopRequest.kind,
      "cancel_requested",
    );
    assert.equal(
      (await readdir(f.directoryPath)).some((path) =>
        path.startsWith(".mutation-"),
      ),
      false,
    );
    const lease = await cancelStore.acquireRunLease(f.input.runId);
    await complete(f, results[1].value, lease, cancelStore);
    await lease.release();
  }
});

test("accepted stops block each queued advancement while reads stay lock-free", async (t) => {
  const operations = [
    "transition",
    "start-turn",
    "finish-turn",
    "child-session",
    "artifact",
    "process",
  ];
  for (const kind of ["pause_requested", "cancel_requested"]) {
    for (const [index, name] of operations.entries()) {
      await t.test(`${kind}/${name}`, async (t) => {
        const entered = deferred();
        const release = deferred();
        let armed = false;
        const f = await fixture(t, {
          onTransitionBoundary: async (point) => {
            if (armed && point === "event-appended") {
              armed = false;
              entered.resolve();
              await release.promise;
            }
          },
        });
        const activeTurn = { role: "worker", phase: "implement" };
        const active = await f.store.startAgentTurn(f.lease, activeTurn, {
          activity: {
            actor: "worker",
            phase: "implement",
            kind: "turn-started",
            message: "Worker started.",
          },
        });
        const input = { ...f.input, kind, expectedRevision: active.revision };
        armed = true;
        const request = f.store.requestOperatorStop(input);
        await entered.promise;
        const queued = assert.rejects(
          advancementOperations(f, activeTurn)[index],
          {
            code: "ERR_STOP_RECONCILIATION_REQUIRED",
          },
        );
        let receipt;
        try {
          const read = await f.store.loadRun(input.runId);
          assert.equal(read.stopRequest.kind, kind);
          assert.equal(await f.store.runIsLeased(input.runId), true);
          assert.equal(
            (await f.store.readPublicActivity(input.runId)).cursor,
            read.revision,
          );
          assert.equal(
            (
              await f.store.waitForRunChange(input.runId, {
                afterRevision: active.revision,
                timeoutMs: 0,
              })
            ).revision,
            read.revision,
          );
        } finally {
          release.resolve();
          [receipt] = await Promise.all([request, queued]);
        }
        const stopped = await f.store.loadRun(input.runId);
        assert.equal(stopped.revision, receipt.revision);
        assert.deepEqual(stopped.sessionLineage, active.sessionLineage);
        assert.deepEqual(stopped.activeTurn, activeTurn);
        assert.equal(stopped.executionProcess, null);
        await assert.rejects(readFile(join(f.directoryPath, "late.txt")), {
          code: "ENOENT",
        });
        assert.deepEqual(await f.store.requestOperatorStop(input), receipt);
        await complete(f, receipt);
      });
    }
  }
});

test("retiring an owned process does not release pending stop accounting", async (t) => {
  for (const kind of ["pause_requested", "cancel_requested"]) {
    await t.test(kind, async (t) => {
      const f = await fixture(t);
      const worktree = await f.store.acquireWorktreeLease(
        f.projectPath,
        f.input.runId,
      );
      const registered = await f.store.recordExecutionProcess(f.lease, 101);
      const receipt = await f.store.requestOperatorStop({
        ...f.input,
        kind,
        expectedRevision: registered.revision,
      });
      await assert.rejects(complete(f, receipt), {
        code: "ERR_EXECUTION_PROCESS_ACTIVE",
      });
      for (const operation of advancementOperations(f, {
        role: "worker",
        phase: "implement",
      })) {
        await assert.rejects(operation, {
          code: "ERR_STOP_RECONCILIATION_REQUIRED",
        });
      }
      const retired = await f.store.recordExecutionProcess(f.lease, null);
      assert.equal(retired.executionProcess, null);
      assert.equal(retired.stopRequest.reconciledRevision, null);
      assert.deepEqual(
        await f.store.recordExecutionProcess(f.lease, null),
        retired,
      );
      for (const lease of [f.lease, worktree]) {
        await assert.rejects(lease.release(), {
          code: "ERR_STOP_RECONCILIATION_REQUIRED",
        });
      }
      await complete(f, receipt);
      await worktree.release();
      await f.lease.release();
      assert.equal(await f.store.runIsLeased(f.input.runId), false);
      const next = await f.store.acquireWorktreeLease(f.projectPath, OTHER_RUN);
      await next.release();
    });
  }
});

test("reconciled cancellation prevents advancement without retaining ownership", async (t) => {
  const f = await fixture(t);
  const input = { ...f.input, kind: "cancel_requested" };
  const receipt = await f.store.requestOperatorStop(input);
  const canceled = await complete(f, receipt);
  for (const operation of advancementOperations(f, {
    role: "worker",
    phase: "implement",
  })) {
    await assert.rejects(operation, { code: "ERR_RUN_CANCELED" });
  }
  await f.lease.release();
  assert.equal(await f.store.runIsLeased(input.runId), false);
  assert.deepEqual(await f.store.requestOperatorStop(input), receipt);
  assert.deepEqual(await f.store.loadRun(input.runId), canceled);
});

test("process ownership alone blocks advancement until its durable record is retired", async (t) => {
  const f = await fixture(t);
  const registered = await f.store.recordExecutionProcess(f.lease, 101);
  assert.equal(registered.stopRequest, null);
  for (const operation of advancementOperations(f, {
    role: "worker",
    phase: "implement",
  })) {
    await assert.rejects(operation, { code: "ERR_EXECUTION_PROCESS_ACTIVE" });
  }
  await f.store.recordExecutionProcess(f.lease, null);
  const advanced = await f.store.transitionRun(f.lease, {
    counters: { rounds: 1 },
  });
  assert.equal(advanced.counters.rounds, 1);
  await f.lease.release();
  assert.equal(await f.store.runIsLeased(f.input.runId), false);
});

test("checkpoint settlement reads the latest stop and publishes progress atomically", async (t) => {
  for (const kind of [null, "pause_requested", "cancel_requested"]) {
    for (const boundary of [
      "event-appended",
      "state-replaced",
      "progress-replaced",
    ]) {
      await t.test(`${kind ?? "ordinary"}/${boundary}`, async (t) => {
        let interrupt = false;
        const f = await fixture(t, {
          onTransitionBoundary: async (point) => {
            if (interrupt && point === boundary) {
              interrupt = false;
              throw new Error("settlement interrupted");
            }
          },
        });
        let receipt;
        if (kind !== null)
          receipt = await f.store.requestOperatorStop({ ...f.input, kind });
        const before = await f.store.loadRun(f.input.runId);
        interrupt = true;
        await assert.rejects(
          f.store.settleCheckpoint(f.lease, (latest) => {
            assert.equal(latest.revision, before.revision);
            assert.equal(latest.stopRequest?.kind ?? null, kind);
            const canceled = kind === "cancel_requested";
            return {
              patch: {
                pipelineState: {
                  ...latest.pipelineState,
                  workflowState:
                    kind === null
                      ? "DONE"
                      : canceled
                        ? "CANCELED"
                        : "WAITING_FOR_USER",
                  completedCommits: ["verified-sha"],
                },
                counters: { rounds: 7 },
                pause:
                  kind === null
                    ? null
                    : {
                        reason: canceled
                          ? "operator_canceled"
                          : "operator_paused",
                        resumeAction: null,
                        operatorResume: {
                          workflowState: "DONE",
                          pause: null,
                          activeTurn: null,
                        },
                      },
              },
              activity: {
                actor: "runner",
                phase: "commit",
                kind: "settled",
                message: "Verified progress settled.",
              },
            };
          }),
          /settlement interrupted/u,
        );
        const recovered = await f.store.recoverRun(f.lease);
        assert.equal(recovered.revision, before.revision + 1);
        assert.deepEqual(recovered.pipelineState.completedCommits, [
          "verified-sha",
        ]);
        assert.equal(recovered.counters.rounds, 7);
        assert.equal(recovered.activeTurn, null);
        if (kind !== null) {
          assert.equal(
            recovered.stopRequest.reconciledRevision,
            recovered.revision,
          );
          assert.deepEqual(
            await f.store.requestOperatorStop({ ...f.input, kind }),
            receipt,
          );
        }
        await f.lease.release();
        assert.equal(await f.store.runIsLeased(f.input.runId), false);
      });
    }
  }
});

test("checkpoint settlement cannot bypass owned processes or a pending stop outcome", async (t) => {
  const f = await fixture(t);
  const build = (current) => ({
    patch: {
      pipelineState: { ...current.pipelineState, workflowState: "DONE" },
    },
  });
  await f.store.recordExecutionProcess(f.lease, 101);
  await assert.rejects(f.store.settleCheckpoint(f.lease, build), {
    code: "ERR_EXECUTION_PROCESS_ACTIVE",
  });
  const retired = await f.store.recordExecutionProcess(f.lease, null);
  await assert.rejects(
    f.store.settleCheckpoint(f.lease, build, {
      validate() {
        throw new Error("invalid pipeline checkpoint");
      },
    }),
    /invalid pipeline checkpoint/u,
  );
  assert.equal(
    (await f.store.loadRun(f.input.runId)).revision,
    retired.revision,
  );
  const receipt = await f.store.requestOperatorStop({
    ...f.input,
    expectedRevision: retired.revision,
  });
  await assert.rejects(f.store.settleCheckpoint(f.lease, build), {
    code: "ERR_INVALID_STOP_RECONCILIATION",
  });
  assert.equal(
    (await f.store.loadRun(f.input.runId)).revision,
    receipt.revision,
  );
  await complete(f, receipt);
});

function commitBoundary(run) {
  if (
    run.pipelineId !== "plan-execution" ||
    run.pipelineState.currentStep === null
  )
    return null;
  return {
    capability: "verified-commit-v1",
    step: run.pipelineState.currentStep ?? 1,
    completedCommits: run.pipelineState.completedCommits?.length ?? 0,
    baselineHead: run.pipelineState.repositoryBaseline?.head ?? "a".repeat(40),
  };
}

test("deferred stops bind serialized targets and reserve ownership while the target advances", async (t) => {
  for (const kind of ["pause_requested", "cancel_requested"]) {
    await t.test(kind, async (t) => {
      const f = await fixture(t, { resolveStopBoundary: commitBoundary });
      const worktree = await f.store.acquireWorktreeLease(
        f.projectPath,
        f.input.runId,
      );
      const input = { ...f.input, kind, timing: "after-current-commit" };
      const receipt = await f.store.requestOperatorStop(input);
      assert.equal(receipt.timing, input.timing);
      assert.deepEqual(receipt.targetBoundary, commitBoundary(f.state));
      assert.ok(Object.isFrozen(receipt.targetBoundary));
      await f.store.transitionRun(f.lease, {
        counters: { rounds: 2 },
        pipelineState: { ...f.state.pipelineState, currentStep: 1 },
      });
      const turn = { role: "worker", phase: "implement" };
      await f.store.startAgentTurn(f.lease, turn, {
        activity: {
          actor: "worker",
          phase: "implement",
          kind: "turn-started",
          message: "Target step continues.",
        },
      });
      await f.store.recordChildSession(f.lease, {
        role: "worker",
        sessionId: "target-session",
      });
      await f.store.writeRunArtifact(f.lease, "target.txt", "target evidence");
      await f.store.recordExecutionProcess(f.lease, 101);
      await f.store.recordExecutionProcess(f.lease, null);
      await f.store.finishAgentTurn(f.lease, turn);
      const target = await f.store.loadRun(input.runId);
      for (const change of [
        { currentStep: 2 },
        { completedCommits: ["b".repeat(40)] },
        { repositoryBaseline: { head: "b".repeat(40) } },
      ]) {
        await assert.rejects(
          f.store.transitionRun(f.lease, {
            pipelineState: { ...target.pipelineState, ...change },
          }),
          { code: "ERR_STOP_BOUNDARY_SETTLEMENT_REQUIRED" },
        );
      }
      await assert.rejects(worktree.release(), {
        code: "ERR_STOP_RECONCILIATION_REQUIRED",
      });
      await assert.rejects(f.lease.release(), {
        code: "ERR_STOP_RECONCILIATION_REQUIRED",
      });
      const unsupported = createRunStore({
        ...f.storeOptions,
        resolveStopBoundary: null,
      });
      await assert.rejects(unsupported.loadRun(input.runId), {
        code: "ERR_STOP_BOUNDARY_UNSUPPORTED",
      });
      const canceled = kind === "cancel_requested";
      const settled = await f.store.settleCheckpoint(f.lease, (latest) => ({
        patch: {
          pipelineState: {
            ...latest.pipelineState,
            currentStep: 2,
            completedCommits: ["b".repeat(40)],
            workflowState: canceled ? "CANCELED" : "WAITING_FOR_USER",
          },
          pause: {
            reason: canceled ? "operator_canceled" : "operator_paused",
            resumeAction: null,
            operatorResume: {
              workflowState: "IMPLEMENT",
              pause: null,
              activeTurn: null,
            },
          },
        },
        settlement: { kind: "commit", commit: "b".repeat(40) },
      }));
      assert.deepEqual(
        settled.stopRequest.targetBoundary,
        receipt.targetBoundary,
      );
      assert.deepEqual(settled.stopRequest.settlement, {
        kind: "commit",
        commit: "b".repeat(40),
      });
      assert.equal(settled.stopRequest.reconciledRevision, settled.revision);
      assert.deepEqual(await f.store.requestOperatorStop(input), receipt);
      await worktree.release();
      await f.lease.release();
    });
  }
});

test("timing identities canonicalize immediate omission and reject changed requests", async (t) => {
  const f = await fixture(t, { resolveStopBoundary: commitBoundary });
  const accepted = await f.store.requestOperatorStop(f.input);
  assert.equal(accepted.timing, "immediate");
  assert.deepEqual(
    await f.store.requestOperatorStop({ ...f.input, timing: "immediate" }),
    accepted,
  );
  await assert.rejects(
    f.store.requestOperatorStop({ ...f.input, timing: "after-current-commit" }),
    { code: "ERR_MCP_IDEMPOTENCY_CONFLICT" },
  );
  await complete(f, accepted);
  const other = await fixture(t);
  await assert.rejects(
    other.store.requestOperatorStop({
      ...other.input,
      timing: "after-current-commit",
    }),
    { code: "ERR_STOP_BOUNDARY_UNSUPPORTED" },
  );
  assert.equal((await other.store.loadRun(other.input.runId)).revision, 1);
  for (const resolver of [
    () => null,
    () => ({ ...commitBoundary(f.state), capability: "unknown" }),
    () => ({ ...commitBoundary(f.state), secret: "forbidden" }),
  ]) {
    const invalid = await fixture(t, { resolveStopBoundary: resolver });
    await assert.rejects(
      invalid.store.requestOperatorStop({
        ...invalid.input,
        timing: "after-current-commit",
      }),
      { code: "ERR_STOP_BOUNDARY_UNSUPPORTED" },
    );
  }
});

test("cancellation supersession never postpones an earlier stop", async (t) => {
  for (const [pauseTiming, cancelTiming] of [
    ["immediate", "after-current-commit"],
    ["after-current-commit", "immediate"],
    ["after-current-commit", "after-current-commit"],
  ]) {
    const f = await fixture(t, { resolveStopBoundary: commitBoundary });
    const pauseInput = { ...f.input, timing: pauseTiming };
    const paused = await f.store.requestOperatorStop(pauseInput);
    const canceled = await f.store.requestOperatorStop({
      ...f.input,
      kind: "cancel_requested",
      timing: cancelTiming,
      idempotencyKey: "superseding-cancel",
    });
    assert.equal(canceled.timing, cancelTiming);
    assert.equal(
      canceled.effectiveTiming,
      pauseTiming === "immediate" ? "immediate" : cancelTiming,
    );
    assert.deepEqual(
      canceled.targetBoundary,
      canceled.effectiveTiming === "immediate" ? null : paused.targetBoundary,
    );
    assert.deepEqual(await f.store.requestOperatorStop(pauseInput), paused);
    if (canceled.effectiveTiming === "immediate")
      await assert.rejects(
        f.store.transitionRun(f.lease, { counters: { rounds: 3 } }),
        { code: "ERR_STOP_RECONCILIATION_REQUIRED" },
      );
    await complete(f, canceled);
  }
});

test("legacy timing-less receipts and pending intents preserve their original identities", async (t) => {
  for (const completed of [false, true]) {
    const f = await fixture(t);
    const identity = {
      key: f.input.idempotencyKey,
      tool: "run_pause",
      arguments: { runId: f.input.runId, expectedRevision: 1 },
      context: { runId: f.input.runId },
    };
    let expected;
    if (completed) expected = await f.store.requestOperatorStop(f.input);
    else {
      const action = await f.store.beginAction(identity);
      await action.release();
    }
    const hash = createHash("sha256")
      .update(f.input.idempotencyKey)
      .digest("hex");
    const path = join(f.storeOptions.stateRoot, "actions", hash, "action.json");
    const record = JSON.parse(await readFile(path, "utf8"));
    record.schemaVersion = 2;
    record.argumentsHash = createHash("sha256")
      .update(JSON.stringify({ expectedRevision: 1, runId: f.input.runId }))
      .digest("hex");
    if (completed) {
      const { timing, effectiveTiming, targetBoundary, ...legacyReceipt } =
        expected;
      expected = legacyReceipt;
      record.result = expected;
      const eventsPath = join(f.directoryPath, "events.jsonl");
      const events = (await readFile(eventsPath, "utf8"))
        .trim()
        .split("\n")
        .map(JSON.parse);
      for (const event of events) {
        event.schemaVersion = event.state.schemaVersion = 6;
        event.state.runtimeCompatibility.runStateVersion = 6;
        if (event.state.stopRequest)
          for (const field of [
            "timing",
            "effectiveTiming",
            "targetBoundary",
            "identityVersion",
            "settlement",
          ])
            delete event.state.stopRequest[field];
      }
      await writeFile(eventsPath, events.map(JSON.stringify).join("\n") + "\n");
      await writeFile(
        join(f.directoryPath, "state.json"),
        JSON.stringify(events.at(-1).state),
      );
    }
    const bytes = JSON.stringify(record);
    await writeFile(path, bytes);
    const receipt = await f.store.requestOperatorStop({
      ...f.input,
      timing: "immediate",
    });
    assert.equal(Object.hasOwn(receipt, "timing"), false);
    if (completed) {
      assert.deepEqual(receipt, expected);
      assert.equal(await readFile(path, "utf8"), bytes);
    }
    const loaded = await f.store.loadRun(f.input.runId);
    assert.equal(loaded.stopRequest.timing, "immediate");
    assert.equal(loaded.stopRequest.identityVersion, 1);
    await assert.rejects(
      f.store.requestOperatorStop({
        ...f.input,
        timing: "after-current-commit",
      }),
      { code: "ERR_MCP_IDEMPOTENCY_CONFLICT" },
    );
    if (!completed) await complete(f, receipt);
  }
});

test("deferred acceptance resolves the authoritative step while queued crossing stays blocked", async (t) => {
  const entered = deferred();
  const release = deferred();
  let armed = false;
  const f = await fixture(t, {
    resolveStopBoundary(run) {
      assert.ok(Object.isFrozen(run.pipelineState));
      return commitBoundary(run);
    },
    async onTransitionBoundary(point) {
      if (armed && point === "event-appended") {
        armed = false;
        entered.resolve();
        await release.promise;
      }
    },
  });
  const next = await f.store.transitionRun(f.lease, {
    pipelineState: { ...f.state.pipelineState, currentStep: 2 },
  });
  armed = true;
  const input = {
    ...f.input,
    expectedRevision: next.revision,
    timing: "after-current-commit",
  };
  const request = f.store.requestOperatorStop(input);
  await entered.promise;
  const crossing = assert.rejects(
    f.store.transitionRun(f.lease, {
      pipelineState: { ...next.pipelineState, currentStep: 3 },
    }),
    { code: "ERR_STOP_BOUNDARY_SETTLEMENT_REQUIRED" },
  );
  try {
    const read = await f.store.loadRun(input.runId);
    assert.equal(read.stopRequest.targetBoundary.step, 2);
    assert.equal(await f.store.runIsLeased(input.runId), true);
  } finally {
    release.resolve();
  }
  const [receipt] = await Promise.all([request, crossing]);
  await complete(f, receipt);
  assert.deepEqual(
    (await f.store.loadRun(input.runId)).stopRequest.settlement,
    {
      kind: "quiescent",
      commit: null,
    },
  );
});

test("deferred stop history rejects changed targets, timing, and settlement evidence", async (t) => {
  const f = await fixture(t, { resolveStopBoundary: commitBoundary });
  const receipt = await f.store.requestOperatorStop({
    ...f.input,
    timing: "after-current-commit",
  });
  await f.store.transitionRun(f.lease, { counters: { rounds: 1 } });
  await complete(f, receipt);
  const eventsPath = join(f.directoryPath, "events.jsonl");
  const statePath = join(f.directoryPath, "state.json");
  const originalEvents = await readFile(eventsPath, "utf8");
  const originalState = await readFile(statePath, "utf8");
  const changes = [
    (events) => {
      events[2].state.stopRequest.targetBoundary.step = 2;
    },
    (events) => {
      events[2].state.stopRequest.timing = "immediate";
    },
    (events) => {
      events[1].state.stopRequest.targetBoundary.capability = "unsupported";
    },
    (events) => {
      events[1].state.stopRequest.targetBoundary.privateData = "forbidden";
    },
    (events) => {
      events[1].state.stopRequest.targetBoundary.step = 0;
    },
    (events) => {
      events[1].state.stopRequest.targetBoundary.baselineHead = "not-a-sha";
    },
    (events) => {
      events[1].state.stopRequest.settlement = {
        kind: "quiescent",
        commit: null,
      };
    },
    (events) => {
      events.at(-1).state.stopRequest.settlement = null;
    },
    (events) => {
      events.at(-1).state.stopRequest.settlement = {
        kind: "commit",
        commit: "invalid",
      };
    },
    (events) => {
      for (const event of events.slice(1)) {
        event.state.stopRequest.effectiveTiming = "immediate";
        event.state.stopRequest.targetBoundary = null;
      }
    },
  ];
  try {
    for (const change of changes) {
      const events = originalEvents.trim().split("\n").map(JSON.parse);
      change(events);
      await writeFile(eventsPath, events.map(JSON.stringify).join("\n") + "\n");
      await writeFile(statePath, JSON.stringify(events.at(-1).state));
      await assert.rejects(f.store.loadRun(f.input.runId), (error) =>
        ["ERR_INVALID_EVENT_LOG", "ERR_INVALID_RUN_STATE"].includes(error.code),
      );
    }
  } finally {
    await writeFile(eventsPath, originalEvents);
    await writeFile(statePath, originalState);
  }
  assert.equal(
    (await f.store.loadRun(f.input.runId)).stopRequest.targetBoundary.step,
    1,
  );
});

test("deferred acceptance races advancement and completion at the serialized publication boundary", async (t) => {
  for (const kind of ["pause_requested", "cancel_requested"]) {
    for (const destination of ["IMPLEMENT", "DONE"]) {
      for (const winner of ["stop", "progress"]) {
        await t.test(`${kind}/${destination}/${winner}`, async (t) => {
          const entered = deferred();
          const release = deferred();
          let armed = false;
          const f = await fixture(t, {
            resolveStopBoundary: commitBoundary,
            async onTransitionBoundary(point) {
              if (armed && point === "event-appended") {
                armed = false;
                entered.resolve();
                await release.promise;
              }
            },
          });
          const input = { ...f.input, kind, timing: "after-current-commit" };
          const patch = {
            pipelineState: {
              ...f.state.pipelineState,
              workflowState: destination,
              currentStep: 2,
              completedCommits: ["b".repeat(40)],
            },
          };
          armed = true;
          const first =
            winner === "stop"
              ? f.store.requestOperatorStop(input)
              : f.store.transitionRun(f.lease, patch);
          await entered.promise;
          const second =
            winner === "stop"
              ? assert.rejects(f.store.transitionRun(f.lease, patch), {
                  code: "ERR_STOP_BOUNDARY_SETTLEMENT_REQUIRED",
                })
              : assert.rejects(f.store.requestOperatorStop(input), {
                  code:
                    destination === "DONE"
                      ? "ERR_RUN_TERMINAL"
                      : "ERR_STALE_RUN_REVISION",
                });
          try {
            const observed = await f.store.loadRun(input.runId);
            assert.equal(observed.revision, 2);
            assert.equal(await f.store.runIsLeased(input.runId), true);
            assert.equal(
              observed.stopRequest?.targetBoundary.step ?? null,
              winner === "stop" ? 1 : null,
            );
          } finally {
            release.resolve();
          }
          const [result] = await Promise.all([first, second]);
          if (winner === "stop") {
            await complete(f, result);
            assert.deepEqual(await f.store.requestOperatorStop(input), result);
            const stopped = await f.store.loadRun(input.runId);
            assert.equal(stopped.pipelineState.completedCommits, undefined);
            assert.equal(
              stopped.pause.operatorResume.workflowState,
              "IMPLEMENT",
            );
          } else if (destination === "IMPLEMENT") {
            const next = await f.store.requestOperatorStop({
              ...input,
              expectedRevision: result.revision,
              idempotencyKey: "inspected-next-step",
            });
            assert.equal(next.targetBoundary.step, 2);
            assert.equal(next.targetBoundary.completedCommits, 1);
            await complete(f, next);
          } else {
            const terminal = await f.store.loadRun(input.runId);
            assert.equal(terminal.pipelineState.workflowState, "DONE");
            assert.equal(terminal.stopRequest, null);
          }
        });
      }
    }
  }
});

test("deferred intent and lost receipt recovery retain one acceptance through ownership transfer", async (t) => {
  for (const kind of ["pause_requested", "cancel_requested"]) {
    for (const phase of ["intent", "accepted", "receipt"]) {
      await t.test(`${kind}/${phase}`, async (t) => {
        let interrupt = false;
        const f = await fixture(t, {
          resolveStopBoundary: commitBoundary,
          async onTransitionBoundary(point) {
            if (interrupt && point === "event-appended") {
              interrupt = false;
              throw new Error("response lost after acceptance");
            }
          },
        });
        const input = { ...f.input, kind, timing: "after-current-commit" };
        const identity = {
          key: input.idempotencyKey,
          tool: kind === "pause_requested" ? "run_pause" : "run_cancel",
          arguments: {
            runId: input.runId,
            expectedRevision: 1,
            timing: input.timing,
          },
        };
        const action = await f.store.beginAction({
          ...identity,
          context: { runId: input.runId },
        });
        await action.release();
        await f.store.acquireWorktreeLease(f.projectPath, input.runId);
        let original;
        if (phase === "accepted") {
          interrupt = true;
          await assert.rejects(
            f.store.requestOperatorStop(input),
            /response lost/u,
          );
          assert.equal((await f.store.readAction(identity)).status, "intent");
        } else if (phase === "receipt") {
          original = await f.store.requestOperatorStop(input);
        }
        const peer = createRunStore({
          ...f.storeOptions,
          processId: 200,
          processIsAlive: (pid) => pid !== 100,
        });
        const receipt = await peer.requestOperatorStop(input);
        if (original !== undefined) assert.deepEqual(receipt, original);
        assert.equal(receipt.revision, 2);
        assert.equal(receipt.targetBoundary.step, 1);
        await assert.rejects(
          peer.acquireWorktreeLease(f.projectPath, OTHER_RUN),
          { code: "ERR_WORKTREE_LEASED" },
        );
        const lease = await peer.acquireRunLease(input.runId);
        const worktree = await peer.acquireWorktreeLease(
          f.projectPath,
          input.runId,
        );
        await peer.recoverRun(lease);
        await complete(f, receipt, lease, peer);
        const finished = await peer.loadRun(input.runId);
        assert.equal(finished.stopRequest.reconciledRevision, 3);
        assert.equal(finished.pause.operatorResume.workflowState, "IMPLEMENT");
        assert.deepEqual(await peer.requestOperatorStop(input), receipt);
        await assert.rejects(
          peer.requestOperatorStop({ ...input, timing: "immediate" }),
          { code: "ERR_MCP_IDEMPOTENCY_CONFLICT" },
        );
        if (kind === "cancel_requested")
          await assert.rejects(
            peer.transitionRun(lease, { counters: { turns: 1 } }),
            { code: "ERR_RUN_CANCELED" },
          );
        const history = await peer.loadRunHistory(input.runId);
        assert.deepEqual(
          history.events.map((event) => event.revision),
          [1, 2, 3],
        );
        const activity = await peer.readPublicActivity(input.runId);
        assert.doesNotMatch(
          JSON.stringify(activity),
          /requestId|startTicks|bootId|pause-key/u,
        );
        await worktree.release();
        await lease.release();
        const next = await peer.acquireWorktreeLease(f.projectPath, OTHER_RUN);
        await next.release();
      });
    }
  }
});
