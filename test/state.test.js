import assert from "node:assert/strict";
import {
  access,
  appendFile,
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
  resolveStateRoot,
  RUN_STATE_SCHEMA_VERSION,
  RunStoreError,
} from "../src/index.js";

function runInput(projectPath, taskPath) {
  return {
    pipelineId: "plan-execution",
    pipelineStateVersion: 1,
    projectPath,
    taskPath,
    roles: {
      reviewer: { backend: "claude", model: "sonnet" },
      worker: { backend: "codex", model: null },
    },
    counters: { fixRounds: 0 },
    hashes: { plan: "sha256:plan", task: "sha256:task" },
    pause: null,
    sourceSession: "codex:source-session",
    pipelineState: {
      arbitrationEpisodes: [],
      correctionRounds: [],
      workflowState: "CLARIFY",
    },
  };
}

async function createFixture(t, { taskInsideProject = false } = {}) {
  const workspace = await mkdtemp(join(tmpdir(), "agent-runner-state-"));
  const projectPath = join(workspace, "project");
  const taskPath = taskInsideProject
    ? join(projectPath, "LOCAL_ARTIFACTS", "task")
    : join(workspace, "task");
  const stateRoot = join(workspace, "state");
  await Promise.all([
    mkdir(projectPath, { recursive: true }),
    mkdir(taskPath, { recursive: true }),
  ]);
  t.after(() => rm(workspace, { recursive: true, force: true }));

  const store = createRunStore({ stateRoot });
  const created = await store.createRun(runInput(projectPath, taskPath));
  t.after(() => created.lease.release().catch(() => {}));
  return { created, projectPath, stateRoot, store, taskPath, workspace };
}

test("resolves the external state root and creates a complete run", async (t) => {
  const workspace = await mkdtemp(join(tmpdir(), "agent-runner-root-"));
  t.after(() => rm(workspace, { recursive: true, force: true }));

  assert.equal(
    resolveStateRoot({
      env: { XDG_STATE_HOME: join(workspace, "xdg") },
      homeDirectory: join(workspace, "home"),
    }),
    join(workspace, "xdg", "agent-runner"),
  );
  assert.equal(
    resolveStateRoot({
      env: {},
      homeDirectory: join(workspace, "home"),
    }),
    join(workspace, "home", ".local", "state", "agent-runner"),
  );
  assert.equal(
    resolveStateRoot({
      env: { XDG_STATE_HOME: "relative" },
      homeDirectory: join(workspace, "home"),
    }),
    join(workspace, "home", ".local", "state", "agent-runner"),
  );
  assert.throws(
    () => resolveStateRoot({ env: {}, homeDirectory: null }),
    (error) =>
      error instanceof RunStoreError &&
      error.code === "ERR_INVALID_STATE_ROOT",
  );

  const { created, projectPath, stateRoot, store, taskPath } =
    await createFixture(t, { taskInsideProject: true });
  const files = await readdir(created.directoryPath);
  const persistedState = JSON.parse(
    await readFile(join(created.directoryPath, "state.json"), "utf8"),
  );

  assert.match(
    created.state.runId,
    /^[0-9a-f]{8}-[0-9a-f-]{27}$/u,
  );
  assert.equal(created.state.schemaVersion, RUN_STATE_SCHEMA_VERSION);
  assert.equal(created.state.revision, 1);
  assert.equal(created.state.projectPath, projectPath);
  assert.equal(created.state.taskPath, taskPath);
  assert.deepEqual(created.state.sessionLineage, {
    source: "codex:source-session",
    children: [],
  });
  assert.deepEqual(persistedState, created.state);
  assert.deepEqual(files.sort(), [
    ".lease",
    "events.jsonl",
    "progress.md",
    "state.json",
  ]);
  assert.equal(await store.getRunDirectory(created.state.runId), created.directoryPath);
  assert.deepEqual(await store.loadRun(created.state.runId), created.state);
  assert.ok(Object.isFrozen(created.state));
  assert.ok(Object.isFrozen(created.state.pipelineState));
  assert.ok(created.directoryPath.startsWith(stateRoot));

  const progress = await readFile(
    join(created.directoryPath, "progress.md"),
    "utf8",
  );
  assert.match(progress, /Revision: 1/u);
  assert.match(progress, /runner\/run\/created: Run created\./u);
});

test("rejects a state root inside the project before creating it", async (t) => {
  const workspace = await mkdtemp(join(tmpdir(), "agent-runner-root-"));
  const projectPath = join(workspace, "project");
  const taskPath = join(workspace, "task");
  const unsafeRoot = join(projectPath, ".state", "agent-runner");
  await Promise.all([mkdir(projectPath), mkdir(taskPath)]);
  t.after(() => rm(workspace, { recursive: true, force: true }));

  const store = createRunStore({ stateRoot: unsafeRoot });
  await assert.rejects(
    store.createRun(runInput(projectPath, taskPath)),
    (error) =>
      error instanceof RunStoreError && error.code === "ERR_UNSAFE_STATE_ROOT",
  );
  await assert.rejects(access(unsafeRoot), /ENOENT/u);
});

test("persists child sessions, opaque pipeline state, and public activity", async (t) => {
  const { created, stateRoot, store } = await createFixture(t);
  const withWorkerSession = await store.recordChildSession(created.lease, {
    role: "worker",
    sessionId: "codex:worker-child",
  });
  assert.equal(withWorkerSession.revision, 2);
  await created.lease.release();

  const resumedStore = createRunStore({ stateRoot });
  const loaded = await resumedStore.loadRun(created.state.runId);
  assert.deepEqual(loaded.sessionLineage.children, [
    { role: "worker", sessionId: "codex:worker-child" },
  ]);

  const lease = await resumedStore.acquireRunLease(created.state.runId);
  t.after(() => lease.release().catch(() => {}));
  await resumedStore.recoverRun(lease);
  const transitioned = await resumedStore.transitionRun(
    lease,
    {
      counters: { fixRounds: 1 },
      hashes: { plan: "sha256:plan", task: "sha256:task-v2" },
      pause: { reason: "review_required" },
      pipelineState: {
        arbitrationEpisodes: [{ findingId: "R1", outcome: "WITHDRAW" }],
        correctionRounds: [{ findingIds: ["R1"], round: 1 }],
        internalDecision: "This is not part of the public projection.",
        workflowState: "REVIEW",
      },
    },
    {
      activity: {
        actor: "reviewer",
        phase: "review",
        kind: "decision",
        message: "Finding R1 was withdrawn.",
      },
    },
  );

  assert.equal(transitioned.revision, 3);
  assert.deepEqual(transitioned.counters, { fixRounds: 1 });
  assert.deepEqual(transitioned.pause, { reason: "review_required" });

  const firstPage = await resumedStore.readPublicActivity(
    created.state.runId,
    { limit: 1 },
  );
  const secondPage = await resumedStore.readPublicActivity(
    created.state.runId,
    { afterRevision: firstPage.cursor, limit: 1 },
  );
  assert.equal(firstPage.cursor, 1);
  assert.equal(firstPage.activities[0].message, "Run created.");
  assert.deepEqual(secondPage, {
    cursor: 3,
    activities: [
      {
        revision: 3,
        recordedAt: transitioned.updatedAt,
        actor: "reviewer",
        phase: "review",
        kind: "decision",
        message: "Finding R1 was withdrawn.",
      },
    ],
  });
  assert.ok(Object.isFrozen(secondPage));
  assert.ok(Object.isFrozen(secondPage.activities));

  const publicOutput = JSON.stringify(secondPage);
  const progress = await readFile(
    join(created.directoryPath, "progress.md"),
    "utf8",
  );
  assert.doesNotMatch(publicOutput, /internalDecision/u);
  assert.doesNotMatch(progress, /not part of the public projection/u);
  assert.match(progress, /Finding R1 was withdrawn\./u);
  await assert.rejects(
    resumedStore.recordChildSession(lease, {
      role: "reviewer",
      sessionId: "codex:worker-child",
    }),
    (error) =>
      error instanceof RunStoreError &&
      error.code === "ERR_DUPLICATE_CHILD_SESSION",
  );
});

test("validates the shared structured input envelope", async (t) => {
  const { created, taskPath, store } = await createFixture(t);
  const inputRequest = {
    id: "request-1",
    kind: "clarification",
    questions: [
      {
        id: "q1",
        question: "Which behavior is required?",
        options: [],
        rationale: "The answer changes behavior.",
      },
    ],
    rationale: "Answer the blocking question.",
    artifactPath: join(taskPath, "clarifications.md"),
  };

  await assert.rejects(
    store.transitionRun(created.lease, {
      pause: {
        reason: "clarification_answers_required",
        inputRequest,
        inputResponse: {
          requestId: "different-request",
          transcriptHash: "a".repeat(64),
        },
      },
    }),
    (error) =>
      error instanceof RunStoreError && error.code === "ERR_INVALID_RUN_STATE",
  );
});

test("recovers every transition write boundary from the complete event", async (t) => {
  const workspace = await mkdtemp(join(tmpdir(), "agent-runner-crash-"));
  t.after(() => rm(workspace, { recursive: true, force: true }));

  for (const boundary of [
    "event-appended",
    "state-replaced",
    "progress-replaced",
  ]) {
    const casePath = join(workspace, boundary);
    const projectPath = join(casePath, "project");
    const taskPath = join(casePath, "task");
    const stateRoot = join(casePath, "state");
    await Promise.all([
      mkdir(projectPath, { recursive: true }),
      mkdir(taskPath, { recursive: true }),
    ]);

    let crashAt;
    const crashingStore = createRunStore({
      stateRoot,
      onTransitionBoundary(currentBoundary) {
        if (currentBoundary === crashAt) {
          crashAt = undefined;
          throw new Error(`crash after ${currentBoundary}`);
        }
      },
    });
    const created = await crashingStore.createRun(
      runInput(projectPath, taskPath),
    );
    crashAt = boundary;
    await assert.rejects(
      crashingStore.transitionRun(
        created.lease,
        { counters: { fixRounds: 1 } },
        {
          activity: {
            actor: "worker",
            phase: "implement",
            kind: "summary",
            message: `Recovered ${boundary}.`,
          },
        },
      ),
      new RegExp(`crash after ${boundary}`, "u"),
    );
    await created.lease.release();

    const recoveringStore = createRunStore({ stateRoot });
    assert.equal((await recoveringStore.loadRun(created.state.runId)).revision, 2);
    const lease = await recoveringStore.acquireRunLease(created.state.runId);
    const recovered = await recoveringStore.recoverRun(lease);
    assert.equal(recovered.revision, 2);
    assert.equal(
      JSON.parse(
        await readFile(join(created.directoryPath, "state.json"), "utf8"),
      ).revision,
      2,
    );
    assert.match(
      await readFile(join(created.directoryPath, "progress.md"), "utf8"),
      new RegExp(`Recovered ${boundary}\\.`, "u"),
    );
    assert.equal(
      (await readFile(join(created.directoryPath, "events.jsonl"), "utf8"))
        .trimEnd()
        .split("\n").length,
      2,
    );
    await lease.release();
  }
});

test("repairs only a partial final event and rejects invalid durable state", async (t) => {
  const { created, stateRoot, store } = await createFixture(t);
  await created.lease.release();
  const eventPath = join(created.directoryPath, "events.jsonl");
  await appendFile(eventPath, '{"partial":');

  assert.equal((await store.loadRun(created.state.runId)).revision, 1);
  const lease = await store.acquireRunLease(created.state.runId);
  await store.recoverRun(lease);
  const transitioned = await store.transitionRun(
    lease,
    { counters: { fixRounds: 1 } },
    {
      activity: {
        actor: "worker",
        phase: "implement",
        kind: "summary",
        message: "Continued after recovery.",
      },
    },
  );
  assert.equal(transitioned.revision, 2);
  assert.equal(
    (await readFile(eventPath, "utf8")).trimEnd().split("\n").length,
    2,
  );
  await lease.release();

  await writeFile(join(created.directoryPath, "state.json"), "{}\n");
  const reopenedStore = createRunStore({ stateRoot });
  await assert.rejects(
    reopenedStore.loadRun(created.state.runId),
    (error) =>
      error instanceof RunStoreError &&
      error.code === "ERR_INVALID_RUN_STATE",
  );
});
