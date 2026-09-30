import assert from "node:assert/strict";
import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import {
  createClarificationService,
  createGitService,
  createRunner,
  createRunStore,
  DETACHED_RUNTIME_COMPATIBILITY_TOKEN,
  parseRunnerConfiguration,
  RUN_STATE_SCHEMA_VERSION,
  RunnerError,
} from "../src/index.js";
import {
  configurationLoader,
  createAdapter,
  createExecutionAdapter,
  createFixture,
  executeFile,
  operatorFixture,
  PLAN,
  PLANNER_SESSION,
  PLANNING_SESSION,
  POST_CLARIFICATION_PLANNER_SESSION,
  PREPARED_RUN,
  REVIEWER_SESSION,
  requestedStepAssessment,
  runnerFor,
  RUNNER_CONFIGURATION,
  SOURCE_SESSION,
} from "./support/index.js";

async function rewriteRunAsLegacy(directoryPath) {
  const statePath = join(directoryPath, "state.json");
  const eventsPath = join(directoryPath, "events.jsonl");
  const state = JSON.parse(await readFile(statePath, "utf8"));
  state.schemaVersion = 1;
  delete state.clientAttribution;
  delete state.clientAttributionFingerprint;
  delete state.providerPolicies;
  delete state.runtimeCompatibility;
  delete state.activeTurn;
  for (const role of Object.values(state.roles)) delete role.effort;
  const events = (await readFile(eventsPath, "utf8"))
    .trimEnd()
    .split("\n")
    .map((line) => JSON.parse(line));
  let previousActiveTurn = null;
  for (const event of events) {
    const activeTurn = event.state.activeTurn;
    if (
      event.activity === null &&
      activeTurn === null &&
      previousActiveTurn !== null
    ) {
      event.activity = {
        actor: previousActiveTurn.role,
        phase: previousActiveTurn.phase,
        kind: "turn-finished",
        message: `${previousActiveTurn.role} turn finished.`,
      };
    }
    previousActiveTurn = activeTurn;
    event.schemaVersion = 1;
    event.state.schemaVersion = 1;
    delete event.state.clientAttribution;
    delete event.state.clientAttributionFingerprint;
    delete event.state.providerPolicies;
    delete event.state.runtimeCompatibility;
    delete event.state.activeTurn;
    for (const role of Object.values(event.state.roles)) delete role.effort;
  }
  await Promise.all([
    writeFile(statePath, `${JSON.stringify(state, null, 2)}\n`),
    writeFile(
      eventsPath,
      `${events.map((event) => JSON.stringify(event)).join("\n")}\n`,
    ),
  ]);
}

test("validates the canonical Git root before creating external state", async (t) => {
  const fixture = await createFixture(t);
  const nestedProjectPath = join(fixture.projectPath, "nested");
  const unsafeStateRoot = join(fixture.projectPath, ".state");
  await mkdir(nestedProjectPath);
  const runner = runnerFor(
    fixture,
    { codex: createAdapter() },
    { runStore: createRunStore({ stateRoot: unsafeStateRoot }) },
  );

  await assert.rejects(
    runner.validateBoundary({
      projectPath: nestedProjectPath,
      taskPath: fixture.taskPath,
    }),
    (error) => error.code === "ERR_UNSAFE_STATE_ROOT",
  );
  await assert.rejects(readdir(unsafeStateRoot), /ENOENT/u);
});

test("serializes execution and polishing runs for one temporary worktree", async (t) => {
  const fixture = await createFixture(t);
  const runStore = createRunStore({ stateRoot: fixture.stateRoot });
  const runner = runnerFor(fixture, { codex: createAdapter() }, { runStore });
  const preparedRuns = await Promise.all(
    ["plan-execution", "polishing"].map((pipelineId) =>
      runner.create({
        pipelineId,
        projectPath: fixture.projectPath,
        taskPath: fixture.taskPath,
        proactiveClarification: false,
        roleOverrides: {},
        sourceSession: null,
      }),
    ),
  );
  const ownerLease = await runStore.acquireWorktreeLease(
    fixture.projectPath,
    PREPARED_RUN,
  );

  for (const prepared of preparedRuns) {
    await assert.rejects(
      runner.resume({ runId: prepared.run.runId, action: null }),
      (error) => error.code === "ERR_WORKTREE_LEASED",
    );
    assert.equal((await runner.status(prepared.run.runId)).run.revision, 1);
    const runLease = await runStore.acquireRunLease(prepared.run.runId);
    await runLease.release();
  }

  await ownerLease.release();
});

test("publishes blocking provider activity before a representative pipeline turn", async (t) => {
  const fixture = await createFixture(t);
  const delegate = createAdapter();
  const started = Promise.withResolvers();
  let blockFirstTurn = true;
  const runStore = createRunStore({ stateRoot: fixture.stateRoot });
  const adapter = {
    ...delegate,
    async run(request) {
      if (blockFirstTurn) {
        blockFirstTurn = false;
        const [runId] = await readdir(join(fixture.stateRoot, "runs"));
        const active = await runStore.loadRun(runId);
        assert.deepEqual(active.activeTurn, {
          role: "planner",
          phase: "clarify",
        });
        started.resolve({ runId, revision: active.revision });
        return new Promise((_, reject) => {
          request.signal.addEventListener(
            "abort",
            () => reject(request.signal.reason),
            { once: true },
          );
        });
      }
      return delegate.run(request);
    },
  };
  const activities = [];
  const runner = runnerFor(
    fixture,
    { codex: adapter },
    { activities, runStore },
  );
  const executing = runner.run({
    pipelineId: "plan-authoring",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  });
  const active = await Promise.race([
    started.promise,
    executing.then(
      () => assert.fail("Pipeline completed before its first provider turn."),
      (cause) => Promise.reject(cause),
    ),
  ]);
  assert.equal(await runStore.runIsLeased(active.runId), true);
  assert.deepEqual((await runner.status(active.runId)).run.activeTurn, {
    role: "planner",
    phase: "clarify",
  });

  await runner.requestOperatorStop({
    runId: active.runId,
    kind: "cancel_requested",
    expectedRevision: active.revision,
    idempotencyKey: "activity-boundary-stop",
  });
  const stopped = await executing;
  assert.equal(stopped.run.pipelineState.workflowState, "CANCELED");
  assert.equal(stopped.run.activeTurn, null);
  assert.equal(
    activities.filter(({ kind }) => kind === "turn-started").length,
    1,
  );
});

test("runs and resumes a registered pipeline from persisted configuration", async (t) => {
  const fixture = await createFixture(t);
  const adapter = createAdapter({ questionFirst: true });
  const activities = [];
  const clientAttribution = {
    name: "example/agent-runner",
    title: "Example Agent Runner",
  };
  const firstRunner = runnerFor(
    fixture,
    { codex: adapter },
    {
      activities,
      configuration: {
        ...RUNNER_CONFIGURATION,
        clientAttribution,
        defaultEffort: "xhigh",
        pipelines: { "plan-authoring": { preferredCommitLineLimit: 650 } },
      },
    },
  );

  const paused = await firstRunner.run({
    pipelineId: "plan-authoring",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    proactiveClarification: false,
    roleOverrides: { planner: { model: "planner-model" } },
    sourceSession: { backend: "codex", id: SOURCE_SESSION },
  });

  assert.equal(paused.run.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(
    paused.run.pipelineState.pendingEdit.transcriptPath,
    join(fixture.taskPath, "clarifications.md"),
  );
  assert.equal(paused.run.pause.reason, "clarification_answers_required");
  assert.equal(paused.run.sessionLineage.source, SOURCE_SESSION);
  assert.equal(paused.run.sessionLineage.sourceProfile, null);
  assert.deepEqual(paused.run.clientAttribution, clientAttribution);
  assert.match(paused.run.clientAttributionFingerprint, /^[a-f0-9]{64}$/u);
  assert.deepEqual(paused.run.roles.planner, {
    backend: "codex",
    profile: "current",
    model: "planner-model",
    contextSize: "current",
    effort: "xhigh",
  });
  assert.deepEqual(paused.run.pipelineState.settings, {
    maxRevisionRounds: 20,
    mode: "independent",
    preferredCommitLineLimit: 650,
    stagnationWindowRounds: 3,
  });
  assert.deepEqual(adapter.calls[0].session, {
    mode: "fork",
    id: SOURCE_SESSION,
  });

  const clarificationPath = join(fixture.taskPath, "clarifications.md");
  await writeFile(
    clarificationPath,
    `${await readFile(clarificationPath, "utf8")}\nUse behavior A.\n`,
  );
  const secondRunner = runnerFor(
    fixture,
    { codex: adapter },
    {
      activities,
      configuration: {
        schemaVersion: 1,
        clientAttribution: {
          name: "changed/agent-runner",
          title: "Changed Agent Runner",
        },
        defaultBackend: "claude",
        defaultEffort: "low",
        pipelines: { "plan-authoring": { preferredCommitLineLimit: 1200 } },
      },
    },
  );
  const beforeResume = await secondRunner.status(paused.run.runId);
  const completed = await secondRunner.resume({
    runId: paused.run.runId,
    action: null,
  });

  assert.equal(
    beforeResume.run.pipelineState.workflowState,
    "WAITING_FOR_USER",
  );
  assert.equal(completed.run.pipelineState.workflowState, "DONE");
  assert.equal(await readFile(join(fixture.taskPath, "plan.md"), "utf8"), PLAN);
  assert.deepEqual(completed.run.roles, paused.run.roles);
  assert.deepEqual(completed.run.clientAttribution, clientAttribution);
  assert.equal(
    completed.run.clientAttributionFingerprint,
    paused.run.clientAttributionFingerprint,
  );
  assert.ok(adapter.calls.every(({ effort }) => effort === "xhigh"));
  assert.ok(adapter.probes.every(({ effort }) => effort === "xhigh"));
  assert.deepEqual(completed.run.pipelineState.settings, {
    maxRevisionRounds: 20,
    mode: "independent",
    preferredCommitLineLimit: 650,
    stagnationWindowRounds: 3,
  });
  assert.deepEqual(
    completed.run.sessionLineage.children.map(({ role, sessionId }) => ({
      role,
      sessionId,
    })),
    [
      { role: "planner", sessionId: PLANNER_SESSION },
      { role: "planner", sessionId: POST_CLARIFICATION_PLANNER_SESSION },
      { role: "planner", sessionId: PLANNING_SESSION },
      { role: "reviewer", sessionId: REVIEWER_SESSION },
    ],
  );
  assert.deepEqual(
    adapter.calls.find((call) =>
      call.prompt.includes("Review the plan and verify that it is correct"),
    ).session,
    { mode: "fork", id: SOURCE_SESSION },
  );
  assert.ok(activities.some(({ actor }) => actor === "planner"));
  assert.ok(activities.some(({ actor }) => actor === "reviewer"));
  assert.ok(activities.every(({ runId }) => runId === paused.run.runId));
  for (const projection of [activities, adapter.calls]) {
    const serialized = JSON.stringify(projection);
    assert.doesNotMatch(serialized, /example\/agent-runner/u);
    assert.doesNotMatch(serialized, /Example Agent Runner/u);
    assert.ok(!serialized.includes(paused.run.clientAttributionFingerprint));
  }
});

test("migrates legacy authoring line targets under the lease without configuration reload", async (t) => {
  const fixture = await createFixture(t);
  const store = createRunStore({ stateRoot: fixture.stateRoot });
  const delegate = createAdapter();
  const initialRunner = runnerFor(
    fixture,
    { codex: delegate },
    { runStore: store },
  );
  const prepared = await initialRunner.create({
    pipelineId: "plan-authoring",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  });
  const statePath = join(prepared.directoryPath, "state.json");
  const eventsPath = join(prepared.directoryPath, "events.jsonl");
  const state = JSON.parse(await readFile(statePath, "utf8"));
  const events = (await readFile(eventsPath, "utf8"))
    .trimEnd()
    .split("\n")
    .map((line) => JSON.parse(line));
  for (const legacy of [state, ...events.map((event) => event.state)]) {
    legacy.pipelineStateVersion = 3;
    delete legacy.pipelineState.settings.preferredCommitLineLimit;
  }
  await writeFile(statePath, `${JSON.stringify(state)}\n`);
  await writeFile(
    eventsPath,
    `${events.map((event) => JSON.stringify(event)).join("\n")}\n`,
  );
  const before = await Promise.all([readFile(statePath), readFile(eventsPath)]);
  const runner = createRunner({
    adapters: {
      codex: {
        ...delegate,
        async run(request) {
          const saved = await store.loadRun(prepared.run.runId);
          assert.equal(await store.runIsLeased(prepared.run.runId), true);
          assert.equal(
            saved.pipelineStateVersion,
            prepared.run.pipelineStateVersion,
          );
          assert.equal(
            saved.pipelineState.settings.preferredCommitLineLimit,
            900,
          );
          return delegate.run(request);
        },
      },
    },
    clarifications: createClarificationService({ interactive: false }),
    git: createGitService(),
    runStore: store,
    async loadConfiguration() {
      throw new Error("Migration reloaded configuration.");
    },
  });
  const lease = await store.acquireRunLease(prepared.run.runId);
  try {
    const status = await runner.status(prepared.run.runId);
    assert.equal(
      status.run.pipelineState.settings.preferredCommitLineLimit,
      900,
    );
    await assert.rejects(runner.resume({ runId: prepared.run.runId }), {
      code: "ERR_RUN_LEASED",
    });
    assert.deepEqual(
      await Promise.all([readFile(statePath), readFile(eventsPath)]),
      before,
    );
  } finally {
    await lease.release();
  }
  const completed = await runner.resume({ runId: prepared.run.runId });
  assert.equal(completed.run.pipelineState.workflowState, "DONE");
  const persistedEvents = (await readFile(eventsPath, "utf8"))
    .trimEnd()
    .split("\n")
    .map((line) => JSON.parse(line));
  assert.equal(persistedEvents[1].activity.kind, "migrated");
  assert.equal(
    persistedEvents[1].state.pipelineState.settings.preferredCommitLineLimit,
    900,
  );
});

test("migrates a legacy runtime envelope under the run lease before resume", async (t) => {
  const fixture = await createFixture(t);
  const adapter = createAdapter();
  const activities = [];
  const runner = runnerFor(fixture, { codex: adapter }, { activities });
  const prepared = await runner.create({
    pipelineId: "plan-authoring",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  });
  await rewriteRunAsLegacy(prepared.directoryPath);

  const probeCount = adapter.probes.length;
  const callCount = adapter.calls.length;
  const legacyStatus = await runner.status(prepared.run.runId);
  assert.equal(adapter.probes.length, probeCount);
  assert.equal(adapter.calls.length, callCount);
  assert.ok(
    Object.values(legacyStatus.run.roles).every(
      ({ effort }) => effort === "current",
    ),
  );
  assert.equal(legacyStatus.run.schemaVersion, 1);
  assert.equal(legacyStatus.run.runtimeCompatibility, null);
  assert.deepEqual(legacyStatus.run.clientAttribution, {
    name: "agent_runner",
    title: "Agent Runner",
  });
  assert.equal(legacyStatus.run.revision, 1);

  const completed = await runner.resume({
    runId: prepared.run.runId,
    action: null,
  });
  assert.equal(completed.run.pipelineState.workflowState, "DONE");
  assert.equal(completed.run.schemaVersion, RUN_STATE_SCHEMA_VERSION);
  assert.deepEqual(completed.run.clientAttribution, {
    name: "agent_runner",
    title: "Agent Runner",
  });
  assert.equal(
    completed.run.runtimeCompatibility.runStateVersion,
    RUN_STATE_SCHEMA_VERSION,
  );
  assert.ok(
    activities.some(
      ({ actor, kind, phase }) =>
        actor === "runner" && kind === "migrated" && phase === "runtime",
    ),
  );
  const events = (
    await readFile(join(prepared.directoryPath, "events.jsonl"), "utf8")
  )
    .trimEnd()
    .split("\n")
    .map((line) => JSON.parse(line));
  assert.equal(events[0].schemaVersion, 1);
  assert.equal(events[1].activity.kind, "migrated");
});

test("rejects a detached runtime mismatch before touching a durable run", async (t) => {
  const fixture = await createFixture(t);
  const runner = runnerFor(fixture, { codex: createAdapter() });
  const prepared = await runner.create({
    pipelineId: "plan-authoring",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  });
  const statePath = join(prepared.directoryPath, "state.json");
  const eventsPath = join(prepared.directoryPath, "events.jsonl");
  const before = await Promise.all([
    readFile(statePath, "utf8"),
    readFile(eventsPath, "utf8"),
  ]);

  await assert.rejects(
    runner.resume({
      runId: prepared.run.runId,
      action: null,
      expectedRuntimeCompatibility: `${DETACHED_RUNTIME_COMPATIBILITY_TOKEN}-other`,
    }),
    (error) =>
      error instanceof RunnerError &&
      error.code === "ERR_RUNTIME_VERSION_SKEW" &&
      /restart the Agent Runner MCP server/u.test(error.message),
  );
  assert.deepEqual(
    await Promise.all([
      readFile(statePath, "utf8"),
      readFile(eventsPath, "utf8"),
    ]),
    before,
  );
});

test("prepares a durable run and submits identified input before continuation", async (t) => {
  const fixture = await createFixture(t);
  const adapter = createAdapter({ questionFirst: true });
  const runner = runnerFor(fixture, { codex: adapter });
  const input = {
    pipelineId: "plan-authoring",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  };

  const prepared = await runner.create(input, { runId: PREPARED_RUN });
  assert.equal(prepared.run.runId, PREPARED_RUN);
  assert.equal(prepared.run.pipelineState.workflowState, "CLARIFY");
  assert.equal(
    (await runner.status(PREPARED_RUN)).run.pipelineState.workflowState,
    "CLARIFY",
  );
  assert.equal(adapter.calls.length, 0);

  const paused = await runner.resume({ runId: PREPARED_RUN, action: null });
  assert.equal(paused.run.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.deepEqual(paused.run.pause.inputRequest.questions, [
    {
      id: "q1",
      question: "Which behavior is required?",
      options: [],
      rationale: "The answer changes the commit plan.",
    },
  ]);
  const response = {
    runId: PREPARED_RUN,
    requestId: paused.run.pause.inputRequest.id,
    expectedRevision: paused.run.revision,
    answers: [{ questionId: "q1", answer: "Use behavior A exactly." }],
  };
  const preview = await runner.previewInput(response);
  const submitted = await runner.submitInput({
    ...response,
    responseHash: preview.responseHash,
  });
  assert.equal(
    submitted.run.pause.inputResponse.transcriptHash,
    preview.responseHash,
  );

  const completed = await runner.resume({ runId: PREPARED_RUN, action: null });
  assert.equal(completed.run.pipelineState.workflowState, "DONE");
  assert.match(
    await readFile(join(fixture.taskPath, "clarifications.md"), "utf8"),
    /### A1\n\nUse behavior A exactly\./u,
  );
});

test("resumes plan execution from its durable trusted-command snapshot", async (t) => {
  const fixture = await createFixture(t);
  await writeFile(
    join(fixture.projectPath, ".gitignore"),
    "/LOCAL_ARTIFACTS/\n",
  );
  await writeFile(
    join(fixture.projectPath, "source.js"),
    "export const value = 1;\n",
  );
  await writeFile(join(fixture.taskPath, "plan.md"), PLAN);
  await executeFile("git", [
    "-C",
    fixture.projectPath,
    "config",
    "user.name",
    "Test",
  ]);
  await executeFile("git", [
    "-C",
    fixture.projectPath,
    "config",
    "user.email",
    "test@example.com",
  ]);
  await executeFile("git", ["-C", fixture.projectPath, "add", "."]);
  await executeFile("git", [
    "-C",
    fixture.projectPath,
    "commit",
    "-qm",
    "test: fixture",
  ]);
  const configuration = {
    schemaVersion: 1,
    defaultBackend: "codex",
    trustedCommandTimeoutMs: 12_345,
    trustedCommands: {
      "service-check": {
        command: "npm run test:service",
        executable: "npm",
        arguments: ["run", "test:service"],
        capabilities: { sourceProjection: true },
      },
    },
    pipelines: {
      "plan-execution": { trustedChecks: ["service-check"] },
    },
  };
  let configurationLoads = 0;
  const trustedPreflights = [];
  const trustedValidation = {
    async execute() {
      throw new Error("Trusted validation unexpectedly executed.");
    },
    async preflight(options) {
      trustedPreflights.push(options);
    },
  };
  const runStore = createRunStore({ stateRoot: fixture.stateRoot });
  const adapter = {
    async probe() {
      return {
        version: "fake-1.0.0",
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
      return {
        output: "structured",
        structured: {
          status: "PLAN_REVISION_REQUIRED",
          stepAssessment: requestedStepAssessment(request),
          questions: [],
          reason: "The durable test intentionally stops before bootstrap.",
          question: "",
          options: [],
          whyBlocked: "",
          evidence: ["No provider continuation is required."],
        },
        sessionId: PLANNER_SESSION,
      };
    },
  };
  const firstRunner = createRunner({
    adapters: { codex: adapter },
    clarifications: createClarificationService({ interactive: false }),
    git: createGitService(),
    async loadConfiguration() {
      configurationLoads += 1;
      return parseRunnerConfiguration(JSON.stringify(configuration));
    },
    runStore,
    trustedValidation,
  });
  const prepared = await firstRunner.create(
    {
      pipelineId: "plan-execution",
      projectPath: fixture.projectPath,
      taskPath: fixture.taskPath,
      proactiveClarification: false,
      roleOverrides: {},
      sourceSession: null,
    },
    { runId: PREPARED_RUN },
  );
  const durableSnapshot = prepared.run.pipelineState.trustedValidation;
  assert.equal(durableSnapshot.schemaVersion, 4);
  assert.equal(durableSnapshot.timeoutMs, 12_345);
  assert.deepEqual(durableSnapshot.commands[0].capabilities, {
    sourceProjection: true,
  });
  assert.equal(configurationLoads, 1);

  const resumed = await createRunner({
    adapters: { codex: adapter },
    clarifications: createClarificationService({ interactive: false }),
    git: createGitService(),
    async loadConfiguration() {
      throw new Error("Resume reloaded runner configuration.");
    },
    runStore,
    trustedValidation,
  }).resume({ runId: PREPARED_RUN, action: null });

  assert.equal(resumed.run.pause.reason, "plan_revision_required");
  assert.deepEqual(
    resumed.run.pipelineState.trustedValidation,
    durableSnapshot,
  );
  assert.equal(configurationLoads, 1);
  assert.deepEqual(trustedPreflights, [
    {
      projectPath: fixture.projectPath,
      snapshot: durableSnapshot,
      storageForbiddenPaths: [
        fixture.projectPath,
        fixture.taskPath,
        runStore.rootPath,
      ],
    },
    {
      projectPath: fixture.projectPath,
      snapshot: durableSnapshot,
      storageForbiddenPaths: [
        fixture.projectPath,
        fixture.taskPath,
        runStore.rootPath,
      ],
    },
  ]);
});

test("unavailable trusted capabilities persist early pauses and retry frozen requests before providers", async (t) => {
  for (const pipelineId of ["plan-execution", "polishing"]) {
    await t.test(pipelineId, async (t) => {
      const fixture = await createFixture(t);
      await writeFile(
        join(fixture.projectPath, ".gitignore"),
        "/LOCAL_ARTIFACTS/\n",
      );
      await writeFile(
        join(fixture.projectPath, "source.js"),
        "export const value = 1;\n",
      );
      await writeFile(join(fixture.taskPath, "plan.md"), PLAN);
      await executeFile("git", [
        "-C",
        fixture.projectPath,
        "config",
        "user.name",
        "Test",
      ]);
      await executeFile("git", [
        "-C",
        fixture.projectPath,
        "config",
        "user.email",
        "test@example.com",
      ]);
      await executeFile("git", ["-C", fixture.projectPath, "add", "."]);
      await executeFile("git", [
        "-C",
        fixture.projectPath,
        "commit",
        "-qm",
        "test: fixture",
      ]);
      if (pipelineId === "polishing")
        await writeFile(
          join(fixture.projectPath, "source.js"),
          "export const value = 2;\n",
        );
      const configuration = {
        schemaVersion: 1,
        defaultBackend: "codex",
        trustedCommands: {
          build: {
            command: "npm run build",
            executable: "npm",
            arguments: ["run", "build"],
            capabilities: { scratch: true },
          },
        },
        pipelines: { [pipelineId]: { trustedChecks: ["build"] } },
      };
      let unavailable = true;
      let providerCalls = 0;
      let loads = 0;
      const requests = [];
      const adapter = {
        async probe() {
          providerCalls += 1;
          return {
            version: "fake-1.0.0",
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
          providerCalls += 1;
          if (request.prompt.startsWith("Validate the proposed context"))
            return {
              structured: { stepAssessment: requestedStepAssessment(request) },
              sessionId: PLANNER_SESSION,
            };
          return {
            output: "structured",
            sessionId: PLANNER_SESSION,
            structured: {
              status: "PRODUCT_DECISION_REQUIRED",
              ...(request.schema.properties.stepAssessment
                ? { stepAssessment: requestedStepAssessment(request) }
                : {}),
              questions: [],
              reason: "",
              question: "Which behavior should the fixture implement?",
              options: [],
              whyBlocked: "The fixture intentionally stops at clarification.",
              evidence: ["The fixture task leaves behavior unspecified."],
            },
          };
        },
      };
      const trustedValidation = {
        async preflight({ snapshot }) {
          requests.push(snapshot);
          if (unavailable)
            throw Object.assign(new Error("Unavailable fixture capability"), {
              code: "ERR_TRUSTED_VALIDATION_CAPABILITY_UNAVAILABLE",
            });
        },
        async execute() {
          assert.fail("Preflight must not execute checks.");
        },
      };
      const runStore = createRunStore({ stateRoot: fixture.stateRoot });
      const open = () =>
        createRunner({
          adapters: { codex: adapter },
          clarifications: createClarificationService({ interactive: false }),
          trustedValidation,
          runStore,
          async loadConfiguration() {
            loads += 1;
            assert.equal(loads, 1);
            return parseRunnerConfiguration(JSON.stringify(configuration));
          },
        });
      const runner = open();
      const input = {
        pipelineId,
        projectPath: fixture.projectPath,
        taskPath: fixture.taskPath,
        proactiveClarification: false,
        roleOverrides: {},
        sourceSession: null,
      };
      const blocked =
        pipelineId === "plan-execution"
          ? await runner.run(input)
          : await runner.create(input);
      assert.equal(blocked.run.pause.reason, "environment_blocked");
      assert.equal(blocked.run.pipelineState.preflightComplete, false);
      assert.equal(blocked.run.pipelineState.repositoryBaseline, null);
      assert.equal(blocked.run.pipelineState.backendVersions, null);
      assert.deepEqual(blocked.run.hashes, {});
      assert.equal(providerCalls, 0);
      const runId = blocked.run.runId;
      await runner.status(runId);
      assert.equal(requests.length, 1);
      const retried = await open().resume({ runId });
      assert.equal(retried.run.pause.reason, "environment_blocked");
      assert.equal(providerCalls, 0);
      assert.equal(requests.length, 2);
      configuration.trustedCommands.build.capabilities = { cache: true };
      unavailable = false;
      const resumed = await open().resume({ runId });
      assert.equal(resumed.run.pause.reason, "product_decision_required");
      assert.ok(providerCalls > 0);
      assert.equal(loads, 1);
      assert.equal(requests.length, 3);
      for (const request of requests)
        assert.deepEqual(request, blocked.run.pipelineState.trustedValidation);
      assert.deepEqual(
        resumed.run.pipelineState.trustedValidation,
        blocked.run.pipelineState.trustedValidation,
      );
    });
  }
});

test("submits input previewed from a compatible legacy run", async (t) => {
  const fixture = await createFixture(t);
  const runner = runnerFor(fixture, {
    codex: createAdapter({ questionFirst: true }),
  });
  const paused = await runner.run({
    pipelineId: "plan-authoring",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  });
  await rewriteRunAsLegacy(paused.directoryPath);

  const response = {
    runId: paused.run.runId,
    requestId: paused.run.pause.inputRequest.id,
    expectedRevision: paused.run.revision,
    answers: [{ questionId: "q1", answer: "Use behavior A exactly." }],
  };
  const preview = await runner.previewInput(response);
  await assert.rejects(
    runner.submitInput({
      ...response,
      expectedRevision: response.expectedRevision + 1,
      responseHash: preview.responseHash,
    }),
    (error) => error.code === "ERR_STALE_INPUT_REQUEST",
  );
  const unchanged = await runner.status(paused.run.runId);
  assert.equal(unchanged.run.schemaVersion, 1);
  assert.equal(unchanged.run.revision, paused.run.revision);

  const submitted = await runner.submitInput({
    ...response,
    responseHash: preview.responseHash,
  });

  assert.equal(submitted.run.schemaVersion, RUN_STATE_SCHEMA_VERSION);
  assert.equal(submitted.run.revision, paused.run.revision + 2);
  assert.equal(
    submitted.run.pause.inputResponse.transcriptHash,
    preview.responseHash,
  );
  const events = (
    await readFile(join(paused.directoryPath, "events.jsonl"), "utf8")
  )
    .trimEnd()
    .split("\n")
    .map((line) => JSON.parse(line));
  assert.equal(events.at(-2).activity.kind, "migrated");
  assert.equal(events.at(-1).activity.kind, "submitted");
});

test("rejects incompatible or unsupported source sessions before creating a run", async (t) => {
  const fixture = await createFixture(t);
  const adapter = createAdapter();
  const runner = runnerFor(fixture, { codex: adapter });

  await assert.rejects(
    runner.run({
      pipelineId: "plan-authoring",
      projectPath: fixture.projectPath,
      taskPath: fixture.taskPath,
      roleOverrides: {
        planner: { backend: "codex" },
        reviewer: { backend: "codex" },
      },
      sourceSession: { backend: "claude", id: SOURCE_SESSION },
    }),
    (error) =>
      error instanceof RunnerError &&
      error.code === "ERR_SOURCE_BACKEND_MISMATCH",
  );

  const noForkRunner = runnerFor(fixture, {
    codex: createAdapter({ fork: false }),
  });
  await assert.rejects(
    noForkRunner.run({
      pipelineId: "plan-authoring",
      projectPath: fixture.projectPath,
      taskPath: fixture.taskPath,
      roleOverrides: {},
      sourceSession: { backend: "codex", id: SOURCE_SESSION },
    }),
    (error) =>
      error instanceof RunnerError &&
      error.code === "ERR_UNSUPPORTED_SOURCE_SESSION",
  );

  assert.deepEqual(
    await readdir(join(fixture.stateRoot, "runs")).catch((error) => {
      if (error?.code === "ENOENT") {
        return [];
      }
      throw error;
    }),
    [],
  );
});

test("persists a trusted source profile and applies resolved turn preferences", async (t) => {
  const fixture = await createFixture(t);
  const adapter = createAdapter();
  const profileDirectory = join(fixture.workspace, "claude-profile");
  const runner = runnerFor(
    fixture,
    { claude: adapter },
    {
      configuration: {
        schemaVersion: 1,
        profiles: {
          "claude-primary": {
            backend: "claude",
            configDirectory: profileDirectory,
          },
        },
        pipelines: {
          "plan-authoring": {
            roles: { arbiter: { profile: "claude-primary" } },
          },
        },
      },
    },
  );

  const result = await runner.run({
    pipelineId: "plan-authoring",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    roleOverrides: {},
    executionOverrides: { model: "sonnet", contextSize: "200000" },
    sourceSession: {
      backend: "claude",
      id: SOURCE_SESSION,
      profile: "claude-primary",
    },
  });

  assert.equal(result.run.pipelineState.workflowState, "DONE");
  assert.equal(result.run.sessionLineage.sourceProfile, "claude-primary");
  assert.deepEqual(result.run.roles.planner, {
    backend: "claude",
    profile: profileDirectory,
    model: "sonnet",
    contextSize: "200000",
    effort: "current",
  });
  assert.deepEqual(adapter.probes, [
    {
      profile: profileDirectory,
      model: "sonnet",
      contextSize: "200000",
      effort: "current",
    },
  ]);
  assert.ok(
    adapter.calls.every(
      ({ profile, model, contextSize }) =>
        profile === profileDirectory &&
        model === "sonnet" &&
        contextSize === "200000",
    ),
  );
  assert.deepEqual(adapter.calls[0].session, {
    mode: "fork",
    id: SOURCE_SESSION,
  });
});

test("persists project overrides and blocks later configuration changes", async (t) => {
  const fixture = await createFixture(t);
  const adapter = createAdapter({ questionFirst: true });
  const projectConfigurationDirectory = join(
    fixture.projectPath,
    "LOCAL_ARTIFACTS",
  );
  const projectConfigurationPath = join(
    projectConfigurationDirectory,
    "agent-runner.json",
  );
  await Promise.all([
    mkdir(projectConfigurationDirectory),
    writeFile(join(fixture.projectPath, ".gitignore"), "/LOCAL_ARTIFACTS/\n"),
  ]);
  await writeFile(
    projectConfigurationPath,
    JSON.stringify({
      schemaVersion: 1,
      artifactRoot: "project-artifacts",
      defaultProfile: "codex-work",
      defaultModel: "project-model",
      defaultEffort: "high",
      pipelines: {
        "plan-authoring": {
          mode: "lazy",
          maxRevisionRounds: 4,
          preferredCommitLineLimit: 450,
          roles: { reviewer: { contextSize: "200000" } },
        },
      },
    }),
  );
  const configuration = {
    schemaVersion: 1,
    defaultBackend: "claude",
    defaultModel: "runner-model",
    profiles: {
      "codex-work": { backend: "codex", profile: "native-work" },
    },
    pipelines: {
      "plan-authoring": {
        maxRevisionRounds: 9,
        preferredCommitLineLimit: 700,
        roles: { reviewer: { model: "runner-reviewer" } },
      },
    },
  };
  const runner = runnerFor(fixture, { codex: adapter }, { configuration });

  const paused = await runner.run({
    pipelineId: "plan-authoring",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    proactiveClarification: false,
    roleOverrides: { planner: { model: "cli-planner" } },
    settingOverrides: { mode: "independent" },
    sourceSession: null,
  });

  assert.equal(paused.run.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.deepEqual(paused.run.pipelineState.settings, {
    maxRevisionRounds: 4,
    mode: "independent",
    preferredCommitLineLimit: 450,
    stagnationWindowRounds: 3,
  });
  assert.equal(
    paused.run.pipelineState.pendingEdit.transcriptPath,
    join(fixture.taskPath, "clarifications.md"),
  );
  assert.deepEqual(paused.run.roles.planner, {
    backend: "codex",
    profile: "native-work",
    model: "cli-planner",
    contextSize: "current",
    effort: "high",
  });
  assert.deepEqual(paused.run.roles.reviewer, {
    backend: "codex",
    profile: "native-work",
    model: "project-model",
    contextSize: "200000",
    effort: "high",
  });
  assert.equal(
    paused.run.projectConfigurationProtection.path,
    projectConfigurationPath,
  );
  assert.match(
    paused.run.projectConfigurationProtection.contentHash,
    /^[a-f0-9]{64}$/u,
  );
  const preparedPolishing = await runner.create({
    pipelineId: "polishing",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  });
  assert.equal(
    preparedPolishing.run.pipelineState.artifactRoot,
    "project-artifacts",
  );

  await Promise.all([
    writeFile(
      projectConfigurationPath,
      '{"schemaVersion":1,"defaultEffort":"low"}\n',
    ),
    writeFile(
      join(fixture.taskPath, "clarifications.md"),
      `${await readFile(join(fixture.taskPath, "clarifications.md"), "utf8")}\nUse behavior A.\n`,
    ),
  ]);
  const completed = await runner.resume({
    runId: paused.run.runId,
    action: null,
  });

  assert.equal(completed.run.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.deepEqual(completed.run.pause, {
    reason: "project_configuration_changed",
    code: "ERR_PROJECT_CONFIGURATION_CHANGED",
  });
  assert.equal(
    (await runner.status(completed.run.runId)).run.pause.reason,
    "project_configuration_changed",
  );
  assert.deepEqual(completed.run.roles, paused.run.roles);
  assert.deepEqual(
    completed.run.pipelineState.settings,
    paused.run.pipelineState.settings,
  );
});

test("configuration drift cannot revive a canceled run", async (t) => {
  const fixture = await createFixture(t);
  const configurationDirectory = join(fixture.projectPath, "LOCAL_ARTIFACTS");
  const configurationPath = join(configurationDirectory, "agent-runner.json");
  await mkdir(configurationDirectory);
  await Promise.all([
    writeFile(join(fixture.projectPath, ".gitignore"), "/LOCAL_ARTIFACTS/\n"),
    writeFile(configurationPath, '{"schemaVersion":1}\n'),
  ]);
  const runner = runnerFor(fixture, { codex: createAdapter() });
  const created = await runner.create({
    pipelineId: "plan-authoring",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  });
  await runner.requestOperatorStop({
    runId: created.run.runId,
    kind: "cancel_requested",
    expectedRevision: created.run.revision,
    idempotencyKey: "cancel-before-configuration-drift",
  });
  const canceled = await runner.resume({
    runId: created.run.runId,
    action: null,
  });
  assert.equal(canceled.run.pipelineState.workflowState, "CANCELED");

  await writeFile(
    configurationPath,
    '{"schemaVersion":1,"artifactRoot":"changed"}\n',
  );
  await assert.rejects(
    runner.resume({ runId: created.run.runId, action: null }),
    { code: "ERR_RUN_CANCELED" },
  );
  const unchanged = await runner.status(created.run.runId);
  assert.equal(unchanged.run.pipelineState.workflowState, "CANCELED");
  assert.equal(unchanged.run.revision, canceled.run.revision);
});

test("guards project configuration after a representative provider turn", async (t) => {
  const fixture = await operatorFixture(t, "plan-execution");
  const configurationDirectory = join(fixture.projectPath, "LOCAL_ARTIFACTS");
  const configurationPath = join(configurationDirectory, "agent-runner.json");
  await mkdir(configurationDirectory, { recursive: true });
  await writeFile(configurationPath, '{"schemaVersion":1}\n');
  const delegate = createExecutionAdapter();
  let calls = 0;
  const runner = runnerFor(fixture, {
    codex: {
      ...delegate,
      async run(request) {
        calls += 1;
        const response = await delegate.run(request);
        await writeFile(
          configurationPath,
          '{"schemaVersion":1,"artifactRoot":"changed"}\n',
        );
        return response;
      },
    },
  });

  const result = await runner.run({
    pipelineId: "plan-execution",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  });

  assert.equal(calls, 1);
  assert.equal(result.run.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.deepEqual(result.run.pause, {
    reason: "project_configuration_changed",
    code: "ERR_PROJECT_CONFIGURATION_CHANGED",
  });
});

test("retains protected-configuration drift through stop reconciliation", async (t) => {
  const fixture = await operatorFixture(t, "plan-authoring");
  const configurationDirectory = join(fixture.projectPath, "LOCAL_ARTIFACTS");
  const configurationPath = join(configurationDirectory, "agent-runner.json");
  await mkdir(configurationDirectory, { recursive: true });
  await writeFile(configurationPath, '{"schemaVersion":1}\n');
  const entered = Promise.withResolvers();
  const store = createRunStore({ stateRoot: fixture.stateRoot });
  const runner = runnerFor(
    fixture,
    {
      codex: {
        ...createAdapter(),
        async run(request) {
          entered.resolve();
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
  const active = runner.run({
    pipelineId: "plan-authoring",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  });
  await entered.promise;
  await writeFile(
    configurationPath,
    '{"schemaVersion":1,"artifactRoot":"changed"}\n',
  );
  const [runId] = await readdir(join(fixture.stateRoot, "runs"));
  const current = (await runner.status(runId)).run;
  await runner.requestOperatorStop({
    runId: current.runId,
    kind: "pause_requested",
    expectedRevision: current.revision,
    idempotencyKey: "configuration-stop",
  });

  const stopped = (await active).run;
  assert.equal(stopped.pause.reason, "operator_paused");
  assert.deepEqual(stopped.pause.operatorResume.pause, {
    reason: "project_configuration_changed",
    code: "ERR_PROJECT_CONFIGURATION_CHANGED",
  });
  assert.equal(stopped.pause.operatorResume.workflowState, "WAITING_FOR_USER");
  const resumed = await runner.resume({ runId: stopped.runId, action: null });
  assert.equal(resumed.run.pause.reason, "project_configuration_changed");
});

test("never reads an Agent Runner configuration file in the target repository", async (t) => {
  const fixture = await createFixture(t);
  await writeFile(
    join(fixture.projectPath, ".agent-runner.json"),
    '{"schemaVersion":99}\n',
  );
  const roleOverrides = {
    planner: { backend: "codex", model: "planner-model" },
    reviewer: { backend: "codex", model: "reviewer-model" },
    arbiter: { backend: "codex", model: "arbiter-model" },
  };
  const runner = createRunner({
    adapters: { codex: createAdapter() },
    clarifications: createClarificationService({ interactive: false }),
    git: createGitService(),
    loadConfiguration: configurationLoader(),
    runStore: createRunStore({ stateRoot: fixture.stateRoot }),
  });

  const result = await runner.run({
    pipelineId: "plan-authoring",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    roleOverrides,
    sourceSession: null,
  });

  assert.equal(result.run.pipelineState.workflowState, "DONE");
  assert.deepEqual(result.run.roles, {
    planner: {
      ...roleOverrides.planner,
      profile: "current",
      contextSize: "current",
      effort: "current",
    },
    reviewer: {
      ...roleOverrides.reviewer,
      profile: "current",
      contextSize: "current",
      effort: "current",
    },
    arbiter: {
      ...roleOverrides.arbiter,
      profile: "current",
      contextSize: "current",
      effort: "current",
    },
  });
});

test("releases a new run lease when activity delivery fails", async (t) => {
  const fixture = await createFixture(t);
  const runStore = createRunStore({ stateRoot: fixture.stateRoot });
  const deliveryError = new Error("Activity delivery failed.");
  const runner = createRunner({
    adapters: { codex: createAdapter() },
    clarifications: createClarificationService({ interactive: false }),
    git: createGitService(),
    loadConfiguration: configurationLoader(),
    onActivity() {
      throw deliveryError;
    },
    runStore,
  });

  await assert.rejects(
    runner.run({
      pipelineId: "plan-authoring",
      projectPath: fixture.projectPath,
      taskPath: fixture.taskPath,
      roleOverrides: {},
      sourceSession: null,
    }),
    (error) => error === deliveryError,
  );

  const [runId] = await readdir(join(fixture.stateRoot, "runs"));
  const lease = await runStore.acquireRunLease(runId);
  await lease.release();
});
