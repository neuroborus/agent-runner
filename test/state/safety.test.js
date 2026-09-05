import assert from "node:assert/strict";
import {
  access,
  appendFile,
  link,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createRunStore, RunStoreError } from "../../src/state/index.js";

function createPublicationBarrier() {
  let pending;
  return {
    async onBoundary(boundary) {
      if (pending === undefined || !pending.matches(boundary)) {
        return;
      }
      const current = pending;
      pending = undefined;
      current.reached(boundary);
      await current.continuation;
    },
    pause(matches) {
      let continuePublication;
      let publicationReached;
      const reached = new Promise((resolve) => {
        publicationReached = resolve;
      });
      const continuation = new Promise((resolve) => {
        continuePublication = resolve;
      });
      pending = {
        continuation,
        matches,
        reached: publicationReached,
      };
      return { reached, release: continuePublication };
    },
  };
}

function runInput(projectPath, taskPath, overrides = {}) {
  return {
    pipelineId: "plan-authoring",
    pipelineStateVersion: 1,
    projectPath,
    taskPath,
    roles: {
      planner: { backend: "codex", model: null },
      reviewer: { backend: "claude", model: "sonnet" },
    },
    ...overrides,
  };
}

async function createFixture(t, storeOptions = {}) {
  const workspace = await mkdtemp(join(tmpdir(), "agent-runner-state-safe-"));
  const projectPath = join(workspace, "project");
  const taskPath = join(workspace, "task");
  const stateRoot = join(workspace, "state");
  await Promise.all([mkdir(projectPath), mkdir(taskPath)]);
  t.after(() => rm(workspace, { recursive: true, force: true }));

  const store = createRunStore({ stateRoot, ...storeOptions });
  const created = await store.createRun(runInput(projectPath, taskPath));
  t.after(() => created.lease.release().catch(() => {}));
  return { created, projectPath, stateRoot, store, taskPath, workspace };
}

test("rejects invalid run-store options", async (t) => {
  for (const options of [
    { hostName: "invalid\nhost" },
    { onLeasePublicationBoundary: null },
  ]) {
    assert.throws(
      () => createRunStore(options),
      (error) =>
        error instanceof RunStoreError &&
        error.code === "ERR_INVALID_RUN_STORE_OPTIONS",
    );
  }
  await assert.rejects(
    createFixture(t, { clock: () => Symbol("invalid") }),
    (error) =>
      error instanceof RunStoreError &&
      error.code === "ERR_INVALID_RUN_STORE_OPTIONS",
  );
});

test("writes only confined run artifacts with atomic replacement", async (t) => {
  const { created, store, workspace } = await createFixture(t);
  const artifactPath = await store.writeRunArtifact(
    created.lease,
    "context/worker.md",
    "first\n",
  );
  await store.writeRunArtifact(created.lease, "context/worker.md", "second\n");

  assert.equal(await readFile(artifactPath, "utf8"), "second\n");
  assert.deepEqual(await readdir(join(created.directoryPath, "context")), [
    "worker.md",
  ]);

  for (const relativePath of [
    "/tmp/outside",
    "../outside",
    "context/../outside.md",
    "context\\..\\outside.md",
    "state.json",
    "STATE.JSON",
    "./state.json",
    "events.jsonl",
    ".lease",
    "context/",
    "context\\",
    "new/.",
    "new\\.",
  ]) {
    await assert.rejects(
      store.writeRunArtifact(created.lease, relativePath, "unsafe"),
      (error) =>
        error instanceof RunStoreError &&
        error.code === "ERR_UNSAFE_RUN_ARTIFACT_PATH",
      relativePath,
    );
  }

  const outsideDirectory = join(workspace, "outside");
  const outsideFile = join(workspace, "outside.md");
  await mkdir(outsideDirectory);
  await writeFile(outsideFile, "outside\n");
  await symlink(outsideDirectory, join(created.directoryPath, "linked"));
  await symlink(
    outsideFile,
    join(created.directoryPath, "context", "linked.md"),
  );

  for (const relativePath of ["linked/escape.md", "context/linked.md"]) {
    await assert.rejects(
      store.writeRunArtifact(created.lease, relativePath, "unsafe"),
      (error) =>
        error instanceof RunStoreError &&
        error.code === "ERR_UNSAFE_RUN_ARTIFACT_PATH",
    );
  }
  assert.equal(await readFile(outsideFile, "utf8"), "outside\n");
});

test("keeps status lock-free and rejects concurrent mutating ownership", async (t) => {
  const { created, stateRoot, store, workspace } = await createFixture(t);
  const competingStore = createRunStore({ stateRoot });
  const missingStateRoot = join(workspace, "missing-state");
  const missingStore = createRunStore({ stateRoot: missingStateRoot });

  assert.equal((await competingStore.loadRun(created.state.runId)).revision, 1);
  await assert.rejects(
    missingStore.loadRun("11111111-1111-4111-8111-111111111111"),
    (error) =>
      error instanceof RunStoreError && error.code === "ERR_RUN_NOT_FOUND",
  );
  await assert.rejects(access(missingStateRoot), /ENOENT/u);
  await assert.rejects(
    competingStore.acquireRunLease(created.state.runId),
    (error) =>
      error instanceof RunStoreError && error.code === "ERR_RUN_LEASED",
  );
  await assert.rejects(
    competingStore.transitionRun(
      { runId: created.state.runId },
      { counters: { attempts: 1 } },
    ),
    (error) =>
      error instanceof RunStoreError && error.code === "ERR_INVALID_RUN_LEASE",
  );

  await created.lease.release();
  const resumedLease = await competingStore.acquireRunLease(
    created.state.runId,
  );
  t.after(() => resumedLease.release().catch(() => {}));
  const resumed = await competingStore.recoverRun(resumedLease);
  assert.equal(resumed.revision, 1);
  assert.equal(
    (
      await competingStore.transitionRun(resumedLease, {
        pipelineState: { workflowState: "DRAFT" },
      })
    ).revision,
    2,
  );
});

test("publishes a complete run lease before contention can observe it", async (t) => {
  const barrier = createPublicationBarrier();
  const { created, stateRoot, store } = await createFixture(t, {
    onLeasePublicationBoundary: (boundary) => barrier.onBoundary(boundary),
  });
  await created.lease.release();
  const leasePath = join(created.directoryPath, ".lease");
  const paused = barrier.pause(
    (boundary) =>
      boundary.filePath === leasePath && boundary.phase === "prepared",
  );
  const acquisition = store.acquireRunLease(created.state.runId);
  await paused.reached;

  await assert.rejects(access(leasePath), (error) => error.code === "ENOENT");
  const [temporaryName] = (await readdir(created.directoryPath)).filter(
    (name) => name.includes(".lease.publish."),
  );
  assert.ok(temporaryName);
  assert.equal(
    (await lstat(join(created.directoryPath, temporaryName))).nlink,
    1,
  );
  assert.equal(
    JSON.parse(
      await readFile(join(created.directoryPath, temporaryName), "utf8"),
    ).runId,
    created.state.runId,
  );

  const competingStore = createRunStore({ stateRoot });
  assert.equal(await competingStore.runIsLeased(created.state.runId), false);
  const winner = await competingStore.acquireRunLease(created.state.runId);
  assert.equal(await competingStore.runIsLeased(created.state.runId), true);
  assert.equal(
    JSON.parse(await readFile(leasePath, "utf8")).runId,
    created.state.runId,
  );
  assert.equal((await lstat(leasePath)).nlink, 1);

  paused.release();
  await assert.rejects(
    acquisition,
    (error) =>
      error instanceof RunStoreError && error.code === "ERR_RUN_LEASED",
  );
  await winner.release();
  assert.equal(
    (await readdir(created.directoryPath)).some((name) =>
      name.includes(".lease.publish."),
    ),
    false,
  );
});

test("serializes ownership by canonical worktree without locking status", async (t) => {
  const { created, projectPath, stateRoot, store, workspace } =
    await createFixture(t);
  const aliasPath = join(workspace, "project-alias");
  const otherProjectPath = join(workspace, "other-project");
  const competingRunId = "11111111-1111-4111-8111-111111111111";
  await Promise.all([
    symlink(projectPath, aliasPath, "dir"),
    mkdir(otherProjectPath),
  ]);
  const competingStore = createRunStore({ stateRoot });
  const lease = await store.acquireWorktreeLease(
    projectPath,
    created.state.runId,
  );

  assert.equal((await competingStore.loadRun(created.state.runId)).revision, 1);
  assert.equal(
    await competingStore.worktreeIsLeased(aliasPath, competingRunId),
    true,
  );
  await assert.rejects(
    competingStore.acquireWorktreeLease(aliasPath, competingRunId),
    (error) =>
      error instanceof RunStoreError && error.code === "ERR_WORKTREE_LEASED",
  );
  const unrelatedLease = await competingStore.acquireWorktreeLease(
    otherProjectPath,
    competingRunId,
  );
  await unrelatedLease.release();

  await lease.release();
  const resumedLease = await competingStore.acquireWorktreeLease(
    aliasPath,
    competingRunId,
  );
  await resumedLease.release();
});

test("reads a complete worktree lease during no-replace publication", async (t) => {
  const barrier = createPublicationBarrier();
  const { created, projectPath, stateRoot, store } = await createFixture(t, {
    onLeasePublicationBoundary: (boundary) => barrier.onBoundary(boundary),
  });
  const paused = barrier.pause((boundary) => boundary.phase === "published");
  const acquisition = store.acquireWorktreeLease(
    projectPath,
    created.state.runId,
  );
  const { filePath: leasePath } = await paused.reached;

  assert.equal((await lstat(leasePath)).nlink, 2);
  const competingStore = createRunStore({ stateRoot });
  assert.equal(
    await competingStore.worktreeLeaseOwner(projectPath, created.state.runId),
    created.state.runId,
  );
  assert.equal(
    JSON.parse(await readFile(leasePath, "utf8")).runId,
    created.state.runId,
  );
  assert.equal((await lstat(leasePath)).nlink, 1);

  paused.release();
  const lease = await acquisition;
  await assert.rejects(
    competingStore.acquireWorktreeLease(projectPath, created.state.runId),
    (error) =>
      error instanceof RunStoreError && error.code === "ERR_WORKTREE_LEASED",
  );
  const hardLinkPath = join(stateRoot, "unexpected-lease-link");
  await link(leasePath, hardLinkPath);
  await assert.rejects(
    competingStore.worktreeLeaseOwner(projectPath, created.state.runId),
    (error) =>
      error instanceof RunStoreError && error.code === "ERR_UNSAFE_STATE_FILE",
  );
  await rm(hardLinkPath);
  await lease.release();
});

test("recovers only stale same-host worktree ownership and checks release ownership", async (t) => {
  const { created, projectPath, stateRoot } = await createFixture(t);
  const initialStore = createRunStore({ stateRoot });
  const initialLease = await initialStore.acquireWorktreeLease(
    projectPath,
    created.state.runId,
  );
  await initialLease.release();
  const [worktreeKey] = await readdir(join(stateRoot, "worktrees"));
  const leasePath = join(stateRoot, "worktrees", worktreeKey, ".lease");
  const staleLease = {
    runId: created.state.runId,
    token: "11111111-1111-4111-8111-111111111111",
    pid: 111,
    hostname: "test-host",
    acquiredAt: "2020-01-01T00:00:00.000Z",
  };
  await writeFile(leasePath, `${JSON.stringify(staleLease)}\n`);

  const recoveringRunId = "22222222-2222-4222-8222-222222222222";
  const recoveringStore = createRunStore({
    stateRoot,
    clock: () => new Date("2026-08-16T00:00:00.000Z"),
    hostName: "test-host",
    processId: 222,
    processIsAlive: (pid) => pid !== 111,
    leaseStaleMs: 0,
  });
  const recoveredLease = await recoveringStore.acquireWorktreeLease(
    projectPath,
    recoveringRunId,
  );
  const recoveredRecord = JSON.parse(await readFile(leasePath, "utf8"));
  assert.equal(recoveredRecord.runId, recoveringRunId);
  assert.equal(recoveredRecord.pid, 222);

  await writeFile(
    leasePath,
    `${JSON.stringify({
      ...recoveredRecord,
      runId: "33333333-3333-4333-8333-333333333333",
      token: "33333333-3333-4333-8333-333333333333",
    })}\n`,
  );
  await assert.rejects(
    recoveredLease.release(),
    (error) =>
      error instanceof RunStoreError &&
      error.code === "ERR_INVALID_WORKTREE_LEASE",
  );
  await writeFile(leasePath, `${JSON.stringify(recoveredRecord)}\n`);
  await recoveredLease.release();

  await writeFile(
    leasePath,
    `${JSON.stringify({ ...staleLease, hostname: "other-host" })}\n`,
  );
  await assert.rejects(
    recoveringStore.acquireWorktreeLease(projectPath, recoveringRunId),
    (error) =>
      error instanceof RunStoreError && error.code === "ERR_WORKTREE_LEASED",
  );
});

test("reads the durable event while a state replacement is pending", async (t) => {
  let continueTransition;
  let transitionPaused;
  let pauseNextTransition = false;
  const paused = new Promise((resolve) => {
    transitionPaused = resolve;
  });
  const continuation = new Promise((resolve) => {
    continueTransition = resolve;
  });
  const { created, store } = await createFixture(t, {
    async onTransitionBoundary(boundary) {
      if (pauseNextTransition && boundary === "event-appended") {
        transitionPaused();
        await continuation;
      }
    },
  });

  pauseNextTransition = true;
  const transition = store.transitionRun(
    created.lease,
    { pipelineState: { workflowState: "DRAFT" } },
    {
      activity: {
        actor: "planner",
        phase: "draft",
        kind: "summary",
        message: "Draft created.",
      },
    },
  );
  await paused;

  assert.equal((await store.loadRun(created.state.runId)).revision, 2);
  assert.equal((await store.readPublicActivity(created.state.runId)).cursor, 2);

  continueTransition();
  await transition;
});

test("revalidates the state root before every run lookup", async (t) => {
  const { created, stateRoot, store, workspace } = await createFixture(t);
  await created.lease.release();
  const outsideRuns = join(workspace, "outside-runs");
  const originalRuns = join(workspace, "original-runs");
  await Promise.all([
    mkdir(join(outsideRuns, created.state.runId), { recursive: true }),
    rename(join(stateRoot, "runs"), originalRuns),
  ]);
  await symlink(outsideRuns, join(stateRoot, "runs"));

  await assert.rejects(
    store.getRunDirectory(created.state.runId),
    (error) =>
      error instanceof RunStoreError && error.code === "ERR_UNSAFE_STATE_ROOT",
  );
});

test("recovers only a demonstrably stale execution lease", async (t) => {
  const { created, stateRoot } = await createFixture(t);
  await created.lease.release();
  const leasePath = join(created.directoryPath, ".lease");
  const staleLease = {
    runId: created.state.runId,
    token: "11111111-1111-4111-8111-111111111111",
    pid: 111,
    hostname: "test-host",
    acquiredAt: "2020-01-01T00:00:00.000Z",
  };
  await writeFile(leasePath, `${JSON.stringify(staleLease)}\n`);

  const recoveringStore = createRunStore({
    stateRoot,
    clock: () => new Date("2026-08-16T00:00:00.000Z"),
    hostName: "test-host",
    processId: 222,
    processIsAlive: (pid) => pid !== 111,
    leaseStaleMs: 0,
  });
  const recoveredLease = await recoveringStore.acquireRunLease(
    created.state.runId,
  );
  assert.equal(JSON.parse(await readFile(leasePath, "utf8")).pid, 222);
  await recoveredLease.release();

  await writeFile(leasePath, `${JSON.stringify(staleLease)}\n`);
  const liveOwnerStore = createRunStore({
    stateRoot,
    clock: () => new Date("2026-08-16T00:00:00.000Z"),
    hostName: "test-host",
    processId: 222,
    processIsAlive: () => true,
    leaseStaleMs: 0,
  });
  await assert.rejects(
    liveOwnerStore.acquireRunLease(created.state.runId),
    (error) =>
      error instanceof RunStoreError && error.code === "ERR_RUN_LEASED",
  );

  await writeFile(
    leasePath,
    `${JSON.stringify({ ...staleLease, hostname: "other-host" })}\n`,
  );
  await assert.rejects(
    recoveringStore.acquireRunLease(created.state.runId),
    (error) =>
      error instanceof RunStoreError && error.code === "ERR_RUN_LEASED",
  );
});

test("serializes stale recovery with an owned marker", async (t) => {
  const { created, stateRoot } = await createFixture(t);
  await created.lease.release();
  const leasePath = join(created.directoryPath, ".lease");
  const markerPath = join(created.directoryPath, ".lease-reclaiming");
  const existingLease = {
    runId: created.state.runId,
    token: "11111111-1111-4111-8111-111111111111",
    pid: 111,
    hostname: "test-host",
    acquiredAt: "2020-01-01T00:00:00.000Z",
  };
  const recoveryMarker = {
    ...existingLease,
    token: "22222222-2222-4222-8222-222222222222",
    pid: 222,
    acquiredAt: "2026-08-16T00:00:00.000Z",
  };
  await Promise.all([
    writeFile(leasePath, `${JSON.stringify(existingLease)}\n`),
    writeFile(markerPath, `${JSON.stringify(recoveryMarker)}\n`),
  ]);

  const store = createRunStore({
    stateRoot,
    clock: () => new Date("2026-08-16T00:01:00.000Z"),
    hostName: "test-host",
    processId: 333,
    processIsAlive: (pid) => pid === 222,
    leaseStaleMs: 0,
  });
  await assert.rejects(
    store.acquireRunLease(created.state.runId),
    (error) =>
      error instanceof RunStoreError && error.code === "ERR_RUN_LEASED",
  );
  assert.deepEqual(
    JSON.parse(await readFile(markerPath, "utf8")),
    recoveryMarker,
  );
  assert.deepEqual(
    JSON.parse(await readFile(leasePath, "utf8")),
    existingLease,
  );
});

test("publishes reclaiming ownership before stale-lease contention", async (t) => {
  const { created, stateRoot } = await createFixture(t);
  await created.lease.release();
  const leasePath = join(created.directoryPath, ".lease");
  const markerPath = join(created.directoryPath, ".lease-reclaiming");
  const staleLease = {
    runId: created.state.runId,
    token: "11111111-1111-4111-8111-111111111111",
    pid: 111,
    hostname: "test-host",
    acquiredAt: "2020-01-01T00:00:00.000Z",
  };
  await writeFile(leasePath, `${JSON.stringify(staleLease)}\n`);

  const barrier = createPublicationBarrier();
  const storeOptions = {
    stateRoot,
    clock: () => new Date("2026-08-16T00:00:00.000Z"),
    hostName: "test-host",
    processId: 222,
    processIsAlive: (pid) => pid !== 111,
    leaseStaleMs: 0,
  };
  const recoveringStore = createRunStore({
    ...storeOptions,
    onLeasePublicationBoundary: (boundary) => barrier.onBoundary(boundary),
  });
  const paused = barrier.pause(
    (boundary) =>
      boundary.filePath === markerPath && boundary.phase === "prepared",
  );
  const acquisition = recoveringStore.acquireRunLease(created.state.runId);
  await paused.reached;

  await assert.rejects(access(markerPath), (error) => error.code === "ENOENT");
  assert.deepEqual(JSON.parse(await readFile(leasePath, "utf8")), staleLease);
  assert.equal(await recoveringStore.runIsLeased(created.state.runId), false);

  const competingStore = createRunStore({ ...storeOptions, processId: 333 });
  const winner = await competingStore.acquireRunLease(created.state.runId);
  assert.equal(JSON.parse(await readFile(leasePath, "utf8")).pid, 333);
  assert.equal((await lstat(leasePath)).nlink, 1);

  paused.release();
  await assert.rejects(
    acquisition,
    (error) =>
      error instanceof RunStoreError && error.code === "ERR_RUN_LEASED",
  );
  await assert.rejects(access(markerPath), (error) => error.code === "ENOENT");
  await winner.release();
});

test("publishes complete MCP action leases under contention", async (t) => {
  const barrier = createPublicationBarrier();
  const { stateRoot, store } = await createFixture(t, {
    onLeasePublicationBoundary: (boundary) => barrier.onBoundary(boundary),
  });
  const input = {
    key: "action-lease-race",
    tool: "run_start",
    arguments: { pipelineId: "plan-authoring" },
    context: { runId: "11111111-1111-4111-8111-111111111111" },
  };
  const paused = barrier.pause((boundary) => boundary.phase === "prepared");
  const acquisition = store.beginAction(input);
  const { filePath: leasePath } = await paused.reached;

  await assert.rejects(access(leasePath), (error) => error.code === "ENOENT");
  assert.equal(await store.readAction(input), null);
  const competingStore = createRunStore({ stateRoot });
  const winner = await competingStore.beginAction(input);
  assert.equal((await competingStore.readAction(input)).status, "intent");
  assert.match(
    JSON.parse(await readFile(leasePath, "utf8")).token,
    /^[0-9a-f-]{36}$/u,
  );
  assert.equal((await lstat(leasePath)).nlink, 1);

  paused.release();
  await assert.rejects(
    acquisition,
    (error) =>
      error instanceof RunStoreError &&
      error.code === "ERR_MCP_ACTION_IN_PROGRESS",
  );
  await winner.release();
});

test("grants one owner during concurrent stale recovery", async (t) => {
  const { created, stateRoot } = await createFixture(t);
  await created.lease.release();
  const staleLease = {
    runId: created.state.runId,
    pid: 111,
    hostname: "test-host",
    acquiredAt: "2020-01-01T00:00:00.000Z",
  };
  await Promise.all([
    writeFile(
      join(created.directoryPath, ".lease"),
      `${JSON.stringify({
        ...staleLease,
        token: "11111111-1111-4111-8111-111111111111",
      })}\n`,
    ),
    writeFile(
      join(created.directoryPath, ".lease-reclaiming"),
      `${JSON.stringify({
        ...staleLease,
        token: "22222222-2222-4222-8222-222222222222",
      })}\n`,
    ),
  ]);

  const attempts = await Promise.allSettled(
    Array.from({ length: 8 }, (_, index) =>
      createRunStore({
        stateRoot,
        clock: () => new Date("2026-08-16T00:00:00.000Z"),
        hostName: "test-host",
        processId: 200 + index,
        processIsAlive: (pid) => pid !== 111,
        leaseStaleMs: 0,
      }).acquireRunLease(created.state.runId),
    ),
  );
  const acquired = attempts.filter(({ status }) => status === "fulfilled");
  const rejected = attempts.filter(({ status }) => status === "rejected");

  assert.equal(acquired.length, 1);
  assert.equal(rejected.length, 7);
  for (const { reason } of rejected) {
    assert.ok(
      reason instanceof RunStoreError && reason.code === "ERR_RUN_LEASED",
    );
  }
  await acquired[0].value.release();
});

test("reports opaque run-ID collisions without taking another run", async (t) => {
  const workspace = await mkdtemp(join(tmpdir(), "agent-runner-state-id-"));
  const projectPath = join(workspace, "project");
  const taskPath = join(workspace, "task");
  const stateRoot = join(workspace, "state");
  const runId = "11111111-1111-4111-8111-111111111111";
  await Promise.all([mkdir(projectPath), mkdir(taskPath)]);
  t.after(() => rm(workspace, { recursive: true, force: true }));

  const store = createRunStore({ stateRoot, runIdFactory: () => runId });
  const created = await store.createRun(runInput(projectPath, taskPath));
  t.after(() => created.lease.release().catch(() => {}));
  await assert.rejects(
    store.createRun(runInput(projectPath, taskPath)),
    (error) =>
      error instanceof RunStoreError && error.code === "ERR_RUN_ID_COLLISION",
  );
  assert.equal((await store.loadRun(runId)).runId, runId);
});

test("removes an incomplete run when initialization fails", async (t) => {
  const workspace = await mkdtemp(join(tmpdir(), "agent-runner-state-init-"));
  const projectPath = join(workspace, "project");
  const taskPath = join(workspace, "task");
  const stateRoot = join(workspace, "state");
  await Promise.all([mkdir(projectPath), mkdir(taskPath)]);
  t.after(() => rm(workspace, { recursive: true, force: true }));

  const store = createRunStore({
    stateRoot,
    onTransitionBoundary(boundary) {
      if (boundary === "event-appended") {
        throw new Error("initialization interrupted");
      }
    },
  });
  await assert.rejects(
    store.createRun(runInput(projectPath, taskPath)),
    /initialization interrupted/u,
  );
  assert.deepEqual(await readdir(join(stateRoot, "runs")), []);
});

test("validates opaque state and public activity without interpreting it", async (t) => {
  const { created, projectPath, store, taskPath } = await createFixture(t);
  const initialState = await store.loadRun(created.state.runId);

  for (const activity of [
    {
      actor: "worker",
      phase: "implement",
      kind: "summary",
      message: "line one\nline two",
    },
    {
      actor: "Worker",
      phase: "implement",
      kind: "summary",
      message: "Invalid actor.",
    },
    {
      actor: "worker",
      phase: "implement",
      kind: "summary",
      message: "x".repeat(501),
    },
    {
      actor: "worker",
      phase: "implement",
      kind: "summary",
      message: "line one\u2028line two",
    },
    Object.create({
      actor: "worker",
      phase: "implement",
      kind: "summary",
      message: "Inherited activity.",
    }),
  ]) {
    await assert.rejects(
      store.transitionRun(created.lease, {}, { activity }),
      (error) =>
        error instanceof RunStoreError &&
        error.code === "ERR_INVALID_PUBLIC_ACTIVITY",
    );
  }
  await assert.rejects(
    store.transitionRun(created.lease, {
      pipelineState: { invalid: () => {} },
    }),
    (error) =>
      error instanceof RunStoreError && error.code === "ERR_INVALID_RUN_STATE",
  );
  await assert.rejects(
    store.createRun(
      runInput(projectPath, taskPath, { childSessions: Array(1) }),
    ),
    (error) =>
      error instanceof RunStoreError && error.code === "ERR_INVALID_RUN_STATE",
  );
  await assert.rejects(
    store.createRun(runInput(projectPath, taskPath, { pipelineState: null })),
    (error) =>
      error instanceof RunStoreError && error.code === "ERR_INVALID_RUN_STATE",
  );
  await assert.rejects(
    store.transitionRun(created.lease, {
      pipelineState: { sparse: Array(1) },
    }),
    (error) =>
      error instanceof RunStoreError && error.code === "ERR_INVALID_RUN_STATE",
  );
  assert.deepEqual(await store.loadRun(created.state.runId), initialState);
  await assert.rejects(
    store.transitionRun(created.lease, { pipelineState: {} }),
    (error) =>
      error instanceof RunStoreError &&
      error.code === "ERR_EMPTY_RUN_TRANSITION",
  );
  assert.deepEqual(
    (
      await store.transitionRun(created.lease, {
        pipelineState: { normalizedNumber: -0 },
      })
    ).pipelineState,
    { normalizedNumber: 0 },
  );
  await assert.rejects(
    store.readPublicActivity(created.state.runId, { limit: 101 }),
    (error) =>
      error instanceof RunStoreError &&
      error.code === "ERR_INVALID_ACTIVITY_CURSOR",
  );
  await assert.rejects(
    store.readPublicActivity(created.state.runId, { afterRevision: 3 }),
    (error) =>
      error instanceof RunStoreError &&
      error.code === "ERR_INVALID_ACTIVITY_CURSOR",
  );
  await assert.rejects(
    store.writeRunArtifact(
      created.lease,
      "context/oversized.md",
      "x".repeat(1024 * 1024 + 1),
    ),
    (error) =>
      error instanceof RunStoreError &&
      error.code === "ERR_INVALID_RUN_ARTIFACT",
  );
  assert.deepEqual((await store.loadRun(created.state.runId)).pipelineState, {
    normalizedNumber: 0,
  });
});

test("rejects a durable malformed event instead of hiding it as a partial tail", async (t) => {
  const { created, store } = await createFixture(t);
  await created.lease.release();
  await appendFile(join(created.directoryPath, "events.jsonl"), "{}\n");

  await assert.rejects(
    store.loadRun(created.state.runId),
    (error) =>
      error instanceof RunStoreError && error.code === "ERR_INVALID_EVENT_LOG",
  );
});

test("rejects discontinuous durable event history", async (t) => {
  const { created, store, workspace } = await createFixture(t);
  await created.lease.release();
  const eventPath = join(created.directoryPath, "events.jsonl");
  const firstEvent = JSON.parse((await readFile(eventPath, "utf8")).trim());
  const recordedAt = new Date(
    Date.parse(firstEvent.recordedAt) + 1,
  ).toISOString();
  const secondEvent = {
    ...firstEvent,
    revision: 2,
    recordedAt,
    state: {
      ...firstEvent.state,
      revision: 2,
      projectPath: join(workspace, "different-project"),
      updatedAt: recordedAt,
    },
  };
  await appendFile(eventPath, `${JSON.stringify(secondEvent)}\n`);

  await assert.rejects(
    store.loadRun(created.state.runId),
    (error) =>
      error instanceof RunStoreError && error.code === "ERR_INVALID_EVENT_LOG",
  );
});

test("rejects empty durable transitions", async (t) => {
  const { created, store } = await createFixture(t);
  await created.lease.release();
  const eventPath = join(created.directoryPath, "events.jsonl");
  const firstEvent = JSON.parse((await readFile(eventPath, "utf8")).trim());
  const recordedAt = new Date(
    Date.parse(firstEvent.recordedAt) + 1,
  ).toISOString();
  const secondEvent = {
    ...firstEvent,
    revision: 2,
    recordedAt,
    state: {
      ...firstEvent.state,
      revision: 2,
      updatedAt: recordedAt,
    },
    activity: null,
  };
  await appendFile(eventPath, `${JSON.stringify(secondEvent)}\n`);

  await assert.rejects(
    store.loadRun(created.state.runId),
    (error) =>
      error instanceof RunStoreError && error.code === "ERR_INVALID_EVENT_LOG",
  );
});

test("rejects linked managed state files", async (t) => {
  const { created, store, workspace } = await createFixture(t);
  await created.lease.release();
  const eventPath = join(created.directoryPath, "events.jsonl");
  const outsidePath = join(workspace, "outside-events.jsonl");
  const outsideContent = await readFile(eventPath, "utf8");
  await Promise.all([rm(eventPath), writeFile(outsidePath, outsideContent)]);
  await symlink(outsidePath, eventPath);

  await assert.rejects(
    store.loadRun(created.state.runId),
    (error) =>
      error instanceof RunStoreError && error.code === "ERR_UNSAFE_STATE_FILE",
  );
  assert.equal(await readFile(outsidePath, "utf8"), outsideContent);

  await rm(eventPath);
  await link(outsidePath, eventPath);
  await assert.rejects(
    store.loadRun(created.state.runId),
    (error) =>
      error instanceof RunStoreError && error.code === "ERR_UNSAFE_STATE_FILE",
  );
  assert.equal(await readFile(outsidePath, "utf8"), outsideContent);
});
