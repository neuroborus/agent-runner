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
  RUNTIME_COMPATIBILITY,
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
  assert.deepEqual(
    created.state.runtimeCompatibility,
    RUNTIME_COMPATIBILITY,
  );
  assert.equal(created.state.revision, 1);
  assert.equal(created.state.projectPath, projectPath);
  assert.equal(created.state.taskPath, taskPath);
  assert.deepEqual(created.state.sessionLineage, {
    source: "codex:source-session",
    sourceProfile: null,
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

test("normalizes legacy role records for every pipeline without rewriting history", async (t) => {
  const roleNames = {
    "plan-authoring": ["planner", "reviewer", "arbiter"],
    "plan-execution": ["worker", "reviewer", "arbiter"],
    polishing: ["worker", "reviewer", "arbiter"],
  };

  for (const [pipelineId, roles] of Object.entries(roleNames)) {
    const workspace = await mkdtemp(
      join(tmpdir(), `agent-runner-legacy-${pipelineId}-`),
    );
    t.after(() => rm(workspace, { recursive: true, force: true }));
    const projectPath = join(workspace, "project");
    const taskPath = join(workspace, "task");
    await Promise.all([mkdir(projectPath), mkdir(taskPath)]);
    const store = createRunStore({ stateRoot: join(workspace, "state") });
    const created = await store.createRun({
      pipelineId,
      pipelineStateVersion: 1,
      projectPath,
      taskPath,
      roles: Object.fromEntries(
        roles.map((role, index) => [
          role,
          {
            backend: "codex",
            profile: "current",
            model: index === 0 ? "current" : "model",
            contextSize: "current",
          },
        ]),
      ),
      pipelineState: { workflowState: "CLARIFY" },
    });
    await created.lease.release();

    const statePath = join(created.directoryPath, "state.json");
    const eventsPath = join(created.directoryPath, "events.jsonl");
    const legacyState = JSON.parse(await readFile(statePath, "utf8"));
    delete legacyState.sessionLineage.sourceProfile;
    for (const [index, role] of roles.entries()) {
      delete legacyState.roles[role].profile;
      delete legacyState.roles[role].contextSize;
      if (index === 0) {
        legacyState.roles[role].model = null;
      } else if (index === 1) {
        delete legacyState.roles[role].model;
      }
    }
    const legacyEvent = JSON.parse((await readFile(eventsPath, "utf8")).trim());
    legacyEvent.state = legacyState;
    const legacyStateSource = `${JSON.stringify(legacyState, null, 2)}\n`;
    const legacyEventSource = `${JSON.stringify(legacyEvent)}\n`;
    await Promise.all([
      writeFile(statePath, legacyStateSource),
      writeFile(eventsPath, legacyEventSource),
    ]);

    const loaded = await store.loadRun(created.state.runId);
    for (const [index, role] of roles.entries()) {
      assert.equal(loaded.roles[role].profile, "current");
      assert.equal(loaded.roles[role].model, index === 2 ? "model" : "current");
      assert.equal(loaded.roles[role].contextSize, "current");
    }
    assert.equal(loaded.sessionLineage.sourceProfile, null);
    assert.equal(await readFile(statePath, "utf8"), legacyStateSource);
    assert.equal(await readFile(eventsPath, "utf8"), legacyEventSource);
  }
});

test("projects version-2 activity state for every pipeline without rewriting", async (t) => {
  for (const pipelineId of [
    "plan-authoring",
    "plan-execution",
    "polishing",
  ]) {
    const workspace = await mkdtemp(
      join(tmpdir(), `agent-runner-v2-${pipelineId}-`),
    );
    t.after(() => rm(workspace, { recursive: true, force: true }));
    const projectPath = join(workspace, "project");
    const taskPath = join(workspace, "task");
    await Promise.all([mkdir(projectPath), mkdir(taskPath)]);
    const store = createRunStore({ stateRoot: join(workspace, "state") });
    const created = await store.createRun({
      pipelineId,
      pipelineStateVersion: 1,
      projectPath,
      taskPath,
      roles: {},
      pipelineState: { workflowState: "CLARIFY" },
    });
    await created.lease.release();

    const statePath = join(created.directoryPath, "state.json");
    const eventsPath = join(created.directoryPath, "events.jsonl");
    const versionTwoState = JSON.parse(await readFile(statePath, "utf8"));
    versionTwoState.schemaVersion = 2;
    versionTwoState.runtimeCompatibility.runStateVersion = 2;
    delete versionTwoState.activeTurn;
    const versionTwoEvent = JSON.parse(
      (await readFile(eventsPath, "utf8")).trim(),
    );
    versionTwoEvent.schemaVersion = 2;
    versionTwoEvent.state = versionTwoState;
    const stateSource = `${JSON.stringify(versionTwoState, null, 2)}\n`;
    const eventSource = `${JSON.stringify(versionTwoEvent)}\n`;
    await Promise.all([
      writeFile(statePath, stateSource),
      writeFile(eventsPath, eventSource),
    ]);

    const loaded = await store.loadRun(created.state.runId);
    assert.equal(loaded.schemaVersion, 2);
    assert.equal(loaded.activeTurn, null);
    assert.equal(await readFile(statePath, "utf8"), stateSource);
    assert.equal(await readFile(eventsPath, "utf8"), eventSource);
  }
});

test("persists bounded agent turns until owner-checked reconciliation", async (t) => {
  const { created, stateRoot, store } = await createFixture(t);
  const turn = { role: "worker", phase: "implement" };
  const started = await store.startAgentTurn(created.lease, turn, {
    activity: {
      actor: "worker",
      phase: "implement",
      kind: "turn-started",
      message: "worker implement turn started.",
    },
  });
  assert.deepEqual(started.activeTurn, turn);
  assert.deepEqual((await store.loadRun(started.runId)).activeTurn, turn);
  await assert.rejects(
    store.finishAgentTurn(created.lease, {
      role: "reviewer",
      phase: "review",
    }),
    (error) => error.code === "ERR_INVALID_AGENT_TURN",
  );

  await created.lease.release();
  const resumedStore = createRunStore({ stateRoot });
  assert.deepEqual((await resumedStore.loadRun(started.runId)).activeTurn, turn);
  const lease = await resumedStore.acquireRunLease(started.runId);
  const recovered = await resumedStore.recoverRun(lease);
  assert.deepEqual(recovered.activeTurn, turn);
  const resumedTurn = { role: "worker", phase: "finalize" };
  const restarted = await resumedStore.startAgentTurn(lease, resumedTurn, {
    activity: {
      actor: "worker",
      phase: "finalize",
      kind: "turn-started",
      message: "worker finalize turn started.",
    },
  });
  assert.deepEqual(restarted.activeTurn, resumedTurn);
  const finished = await resumedStore.finishAgentTurn(lease, resumedTurn);
  assert.equal(finished.activeTurn, null);
  await lease.release();

  const activities = await resumedStore.readPublicActivity(started.runId);
  assert.equal(
    activities.activities.filter(({ kind }) => kind === "turn-started").length,
    2,
  );
  assert.equal(activities.cursor, finished.revision);
});

test("migrates a legacy run envelope as one leased journal transition", async (t) => {
  const { created, stateRoot, store } = await createFixture(t);
  await created.lease.release();
  const statePath = join(created.directoryPath, "state.json");
  const eventsPath = join(created.directoryPath, "events.jsonl");
  const legacyState = JSON.parse(await readFile(statePath, "utf8"));
  legacyState.schemaVersion = 1;
  delete legacyState.runtimeCompatibility;
  delete legacyState.activeTurn;
  const legacyEvent = JSON.parse((await readFile(eventsPath, "utf8")).trim());
  legacyEvent.schemaVersion = 1;
  legacyEvent.state = legacyState;
  const legacyStateSource = `${JSON.stringify(legacyState, null, 2)}\n`;
  const legacyEventSource = `${JSON.stringify(legacyEvent)}\n`;
  await Promise.all([
    writeFile(statePath, legacyStateSource),
    writeFile(eventsPath, legacyEventSource),
  ]);

  const legacyRun = await store.loadRun(created.state.runId);
  assert.equal(legacyRun.schemaVersion, 1);
  assert.equal(legacyRun.runtimeCompatibility, null);
  assert.equal(await readFile(statePath, "utf8"), legacyStateSource);
  assert.equal(await readFile(eventsPath, "utf8"), legacyEventSource);

  const resumedStore = createRunStore({ stateRoot });
  const lease = await resumedStore.acquireRunLease(created.state.runId);
  const migrated = await resumedStore.migrateRun(
    lease,
    {
      pipelineState: legacyRun.pipelineState,
      pipelineStateVersion: legacyRun.pipelineStateVersion,
    },
    {
      activity: {
        actor: "runner",
        phase: "runtime",
        kind: "migrated",
        message: "Migrated legacy run state.",
      },
    },
  );
  await lease.release();

  assert.equal(migrated.schemaVersion, RUN_STATE_SCHEMA_VERSION);
  assert.equal(migrated.revision, 2);
  assert.deepEqual(migrated.runtimeCompatibility, RUNTIME_COMPATIBILITY);
  assert.deepEqual(await resumedStore.loadRun(created.state.runId), migrated);
  const events = (await readFile(eventsPath, "utf8"))
    .trimEnd()
    .split("\n")
    .map((line) => JSON.parse(line));
  assert.equal(events[0].schemaVersion, 1);
  assert.equal(events[1].schemaVersion, RUN_STATE_SCHEMA_VERSION);
  assert.equal(events[1].activity.kind, "migrated");
});

test("preserves actionable runtime skew errors from state and journal reads", async (t) => {
  const { created, store } = await createFixture(t);
  await created.lease.release();
  const statePath = join(created.directoryPath, "state.json");
  const eventsPath = join(created.directoryPath, "events.jsonl");
  const originalState = await readFile(statePath, "utf8");
  const originalEvent = await readFile(eventsPath, "utf8");
  const incompatibleState = JSON.parse(originalState);
  incompatibleState.runtimeCompatibility.runnerVersion += 1;
  await writeFile(
    statePath,
    `${JSON.stringify(incompatibleState, null, 2)}\n`,
  );

  await assert.rejects(
    store.loadRun(created.state.runId),
    (error) =>
      error instanceof RunStoreError &&
      error.code === "ERR_RUNTIME_VERSION_SKEW" &&
      /use the Agent Runner version/u.test(error.message),
  );

  const incompatibleEvent = JSON.parse(originalEvent.trim());
  incompatibleEvent.state.runtimeCompatibility.runnerVersion += 1;
  await Promise.all([
    writeFile(statePath, originalState),
    writeFile(eventsPath, `${JSON.stringify(incompatibleEvent)}\n`),
  ]);
  await assert.rejects(
    store.loadRun(created.state.runId),
    (error) =>
      error instanceof RunStoreError &&
      error.code === "ERR_RUNTIME_VERSION_SKEW" &&
      !/Run state is invalid/u.test(error.message) &&
      !/Invalid event/u.test(error.message),
  );
  assert.equal(await readFile(statePath, "utf8"), originalState);
  assert.equal(
    await readFile(eventsPath, "utf8"),
    `${JSON.stringify(incompatibleEvent)}\n`,
  );
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
  await assert.rejects(
    store.recordChildSession(created.lease, {
      role: "worker",
      sessionId: "codex:invalid-child",
      contextKey: "invalid",
    }),
    (error) =>
      error instanceof RunStoreError && error.code === "ERR_INVALID_RUN_STATE",
  );
  const contextKey = "a".repeat(64);
  const withWorkerSession = await store.recordChildSession(created.lease, {
    role: "worker",
    sessionId: "codex:worker-child",
    contextKey,
  });
  assert.equal(withWorkerSession.revision, 2);
  await created.lease.release();

  const resumedStore = createRunStore({ stateRoot });
  const loaded = await resumedStore.loadRun(created.state.runId);
  assert.deepEqual(loaded.sessionLineage.children, [
    { role: "worker", sessionId: "codex:worker-child", contextKey },
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

test("accepts only finite adapter diagnostics in durable pause state", async (t) => {
  const { created, store } = await createFixture(t);

  const transitioned = await store.transitionRun(created.lease, {
    pause: {
      reason: "internal_failure",
      code: "ERR_CODEX_ISOLATION",
      diagnosticClass: "operation_multi_agent",
    },
  });
  assert.equal(
    transitioned.pause.diagnosticClass,
    "operation_multi_agent",
  );

  await assert.rejects(
    store.transitionRun(created.lease, {
      pause: {
        reason: "internal_failure",
        code: "ERR_CODEX_ISOLATION",
        diagnosticClass: "native_provider_value",
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
