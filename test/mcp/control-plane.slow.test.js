import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";

import {
  createClarificationService,
  createDetachedRuntimeCompatibilityToken,
  createGitService,
  createRunner,
  createRunStore,
  DETACHED_RUNTIME_COMPATIBILITY_TOKEN,
  listPipelines,
  main,
  parseRunnerConfiguration,
  RUNTIME_VERSION_SKEW_EXIT_CODE,
  RUN_STATE_SCHEMA_VERSION,
} from "../../src/index.js";
import {
  createDetachedLauncher,
  createMcpControlPlane,
  DETACHED_RUNTIME_COMPATIBILITY_ENV,
  MCP_INSTRUCTIONS,
} from "../../src/mcp/index.js";

import { resolveStopBoundary } from "../../src/pipeline-registry.js";

const RUN_ID = "11111111-1111-4111-8111-111111111111";
const SECOND_RUN_ID = "22222222-2222-4222-8222-222222222222";
const THIRD_RUN_ID = "33333333-3333-4333-8333-333333333333";
const RESPONSE_HASH = "a".repeat(64);
const executeFile = promisify(execFile);

test("detached IPC admission disconnects before execution and consumes its environment marker", async (t) => {
  const paths = await workspace(t, "agent-runner-dispatch-ipc-");
  const script = join(paths.taskPath, "child.mjs");
  const receipt = join(paths.taskPath, "admitted.json");
  await writeFile(
    script,
    `import { writeFile } from "node:fs/promises";
import { awaitDetachedDispatch } from ${JSON.stringify(new URL("../../src/mcp/index.js", import.meta.url).href)};
const dispatch = await awaitDetachedDispatch(process.env);
await writeFile(${JSON.stringify(receipt)}, JSON.stringify({ dispatch, connected: process.connected, marker: Object.hasOwn(process.env, "AGENT_RUNNER_PARENT_DISPATCH") }));
`,
  );
  const exited = Promise.withResolvers();
  let owner;
  const dispatch = { id: SECOND_RUN_ID, expectedRevision: 9 };
  await createDetachedLauncher({ executablePath: script })(RUN_ID, null, {
    dispatch,
    onSpawn(value) {
      owner = value;
    },
    onExit: exited.resolve,
  });
  assert.equal(await exited.promise, 0);
  assert.ok(owner.processIdentity.bootId);
  assert.deepEqual(JSON.parse(await readFile(receipt, "utf8")), {
    dispatch,
    connected: false,
    marker: false,
  });
});

async function childNodeStdoutIsAvailable() {
  const marker = "agent-runner-child-stdio-probe";
  try {
    const { stdout } = await executeFile(
      process.execPath,
      ["-e", `process.stdout.write(${JSON.stringify(marker)})`],
      { encoding: "utf8" },
    );
    return stdout === marker;
  } catch {
    return false;
  }
}

async function requireChildNodeStdout(
  t,
  { probe = childNodeStdoutIsAvailable, argumentsList = process.execArgv } = {},
) {
  if (await probe()) {
    return true;
  }
  // Explicit selection must establish coverage rather than pass through a skip.
  if (
    argumentsList.some(
      (argument) =>
        argument === "--test-name-pattern" ||
        argument.startsWith("--test-name-pattern="),
    )
  ) {
    assert.fail(
      "Explicitly selected STDIO tests require nested Node stdout; skipping is not permitted.",
    );
  }
  t.skip("Nested Node stdout is unavailable in this environment.");
  return false;
}

async function workspace(t, prefix = "agent-runner-mcp-") {
  const root = await mkdtemp(join(tmpdir(), prefix));
  const projectPath = join(root, "project");
  const taskPath = join(root, "task");
  const stateRoot = join(root, "state");
  await Promise.all([mkdir(projectPath), mkdir(taskPath)]);
  t.after(() => rm(root, { recursive: true, force: true }));
  return { projectPath, root, stateRoot, taskPath };
}

function deferred() {
  let resolvePromise;
  const promise = new Promise((resolve) => {
    resolvePromise = resolve;
  });
  return { promise, resolve: resolvePromise };
}

async function advanceMutatingStoredRun(store, runId, dispatch) {
  const lease = await store.acquireRunLease(runId);
  try {
    await store.recoverRun(lease);
    await store.recordRecoveryDispatch(lease, dispatch);
    await store.recordRecoveryDispatch(lease, dispatch, true);
    await store.transitionRun(
      lease,
      {},
      {
        activity: {
          actor: "runner",
          phase: "mcp",
          kind: "started",
          message: "Detached test continuation started.",
        },
      },
    );
  } finally {
    await lease.release();
  }
}

async function rewriteRunAsLegacy(directoryPath) {
  const statePath = join(directoryPath, "state.json");
  const eventsPath = join(directoryPath, "events.jsonl");
  const state = JSON.parse(await readFile(statePath, "utf8"));
  state.schemaVersion = 1;
  delete state.providerPolicies;
  delete state.runtimeCompatibility;
  delete state.activeTurn;
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
    delete event.state.providerPolicies;
    delete event.state.runtimeCompatibility;
    delete event.state.activeTurn;
  }
  await Promise.all([
    writeFile(statePath, `${JSON.stringify(state, null, 2)}\n`),
    writeFile(
      eventsPath,
      `${events.map((event) => JSON.stringify(event)).join("\n")}\n`,
    ),
  ]);
}

function questioningAdapter() {
  return {
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
    async run() {
      return {
        output: "structured",
        structured: {
          status: "QUESTIONS",
          questions: [
            {
              question: "Choose the required behavior?",
              whyItMatters: "The answer changes the plan.",
            },
          ],
        },
        sessionId: THIRD_RUN_ID,
      };
    },
  };
}

async function createStoredRun(
  store,
  { projectPath, taskPath },
  {
    id = RUN_ID,
    pipelineId = "plan-authoring",
    workflowState = "CLARIFY",
    pendingEdit = null,
    pause = null,
    sourceSession = null,
    sourceProfile = null,
    state = {},
  } = {},
) {
  const created = await store.createRun({
    runId: id,
    pipelineId,
    pipelineStateVersion: 1,
    projectPath,
    taskPath,
    roles: {},
    counters: {},
    hashes: {},
    pause,
    sourceSession,
    sourceProfile,
    pipelineState: {
      workflowState,
      pendingEdit,
      proactiveClarification: false,
      settings: { mode: "independent" },
      ...state,
    },
  });
  await created.lease.release();
  return created.state;
}

async function settleStoredStop(store, runId, existingLease) {
  const lease = existingLease ?? (await store.acquireRunLease(runId));
  try {
    return await store.settleCheckpoint(lease, (run) => {
      const canceled = run.stopRequest.kind === "cancel_requested";
      return {
        patch: {
          pipelineState: {
            ...run.pipelineState,
            workflowState: canceled ? "CANCELED" : "WAITING_FOR_USER",
          },
          pause: {
            reason: canceled ? "operator_canceled" : "operator_paused",
            resumeAction: null,
            operatorResume: {
              workflowState: run.pipelineState.workflowState,
              pause: run.pause,
              activeTurn: run.activeTurn,
            },
          },
        },
        activity: null,
      };
    });
  } finally {
    if (existingLease === undefined) await lease.release();
  }
}

function storedRunner(store, paths) {
  return {
    requestOperatorStop(input) {
      return store.requestOperatorStop(input);
    },
    validateBoundary(input) {
      return store.validateStateBoundary(input);
    },
    async create(input, { runId }) {
      const run = await createStoredRun(
        store,
        { projectPath: input.projectPath, taskPath: input.taskPath },
        {
          id: runId,
          pipelineId: input.pipelineId,
          sourceSession: input.sourceSession?.id ?? null,
          sourceProfile:
            input.sourceSession?.profile === undefined ||
            input.sourceSession.profile === "current"
              ? null
              : input.sourceSession.profile,
          state: {
            settings: {
              mode: input.settingOverrides?.mode ?? "independent",
            },
          },
        },
      );
      return { directoryPath: await store.getRunDirectory(run.runId), run };
    },
    async previewInput(input) {
      const run = await store.loadRun(input.runId);
      if (
        run.revision !== input.expectedRevision ||
        run.pause?.inputRequest?.id !== input.requestId ||
        run.pause.inputResponse !== undefined
      ) {
        throw new Error("Pending input request is stale.");
      }
      return { responseHash: RESPONSE_HASH };
    },
    async status(runId) {
      return {
        directoryPath: await store.getRunDirectory(runId),
        run: await store.loadRun(runId),
      };
    },
    async submitInput(input) {
      const lease = await store.acquireRunLease(input.runId);
      try {
        const run = await store.recoverRun(lease);
        const next = await store.transitionRun(
          lease,
          {
            pause: {
              ...run.pause,
              inputResponse: {
                requestId: input.requestId,
                transcriptHash: input.responseHash,
              },
            },
          },
          {
            activity: {
              actor: "runner",
              phase: "clarification",
              kind: "submitted",
              message: "Input submitted.",
            },
          },
        );
        return {
          directoryPath: await store.getRunDirectory(input.runId),
          run: next,
        };
      } finally {
        await lease.release();
      }
    },
  };
}

test("broad STDIO discovery may skip when child stdout is unavailable", async () => {
  const skipped = [];
  assert.equal(
    await requireChildNodeStdout(
      { skip: (reason) => skipped.push(reason) },
      { probe: async () => false, argumentsList: [] },
    ),
    false,
  );
  assert.deepEqual(skipped, [
    "Nested Node stdout is unavailable in this environment.",
  ]);
});

test("explicitly selected STDIO checks cannot pass through an unavailable probe", async () => {
  for (const argumentsList of [
    ["--test-name-pattern=protocol-clean|detached worktree"],
    ["--test-name-pattern", "protocol-clean|detached worktree"],
  ]) {
    await assert.rejects(
      requireChildNodeStdout(
        { skip: () => assert.fail("A selected test must not be skipped.") },
        { probe: async () => false, argumentsList },
      ),
      {
        code: "ERR_ASSERTION",
        message:
          "Explicitly selected STDIO tests require nested Node stdout; skipping is not permitted.",
      },
    );
  }
});

test("available child stdout permits selected STDIO assertions to run", async () => {
  assert.equal(
    await requireChildNodeStdout(
      { skip: () => assert.fail("An available test must not be skipped.") },
      {
        probe: async () => true,
        argumentsList: ["--test-name-pattern=protocol-clean|detached worktree"],
      },
    ),
    true,
  );
});

test("serves protocol-clean STDIO discovery through the official SDK", async (t) => {
  if (!(await requireChildNodeStdout(t))) {
    return;
  }
  const paths = await workspace(t, "agent-runner-mcp-protocol-");
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: ["bin/agent-run.js", "mcp"],
    cwd: new URL("../..", import.meta.url).pathname,
    env: { ...process.env, XDG_STATE_HOME: paths.stateRoot },
    stderr: "pipe",
  });
  let diagnostics = "";
  transport.stderr?.on("data", (chunk) => {
    diagnostics += chunk;
  });
  const client = new Client({ name: "agent-runner-test", version: "1.0.0" });
  t.after(() => client.close().catch(() => {}));

  await client.connect(transport);
  assert.equal(client.getInstructions(), MCP_INSTRUCTIONS);
  assert.match(
    MCP_INSTRUCTIONS,
    /Leave sourceSession unset unless the user deliberately chooses/u,
  );
  assert.match(
    MCP_INSTRUCTIONS,
    /independent is the default and recommended mode/u,
  );
  assert.match(MCP_INSTRUCTIONS, /more provider context and tokens/u);
  assert.match(MCP_INSTRUCTIONS, /lazy is opt-in/u);
  assert.match(MCP_INSTRUCTIONS, /does not provide independent review/u);
  assert.match(MCP_INSTRUCTIONS, /never select it automatically/u);
  assert.match(
    MCP_INSTRUCTIONS,
    /In independent and combined modes the primary and review roles fork/u,
  );
  assert.match(
    MCP_INSTRUCTIONS,
    /fresh start for a long, multi-topic, or uncertain source session/u,
  );
  const { tools } = await client.listTools();
  assert.deepEqual(tools.map((tool) => tool.name).sort(), [
    "guidance_read",
    "guidance_update",
    "pipelines_list",
    "run_activity",
    "run_cancel",
    "run_pause",
    "run_respond",
    "run_resume",
    "run_start",
    "run_status",
    "run_wait",
    "unexpected_issue_report",
  ]);
  assert.equal(
    tools.find((tool) => tool.name === "run_status").annotations.readOnlyHint,
    true,
  );
  assert.equal(
    tools.find((tool) => tool.name === "run_start").annotations.destructiveHint,
    true,
  );
  for (const name of ["run_pause", "run_cancel"]) {
    const tool = tools.find((candidate) => candidate.name === name);
    assert.equal(tool.annotations.readOnlyHint, false);
    assert.deepEqual(tool.inputSchema.required.sort(), [
      "expectedRevision",
      "idempotencyKey",
      "runId",
    ]);
    assert.match(tool.description, /same idempotency key and revision/u);
    assert.deepEqual(tool.inputSchema.properties.timing.enum, [
      "immediate",
      "after-current-commit",
    ]);
  }
  assert.match(
    tools.find((tool) => tool.name === "run_wait").description,
    /completion, cancellation, failure/u,
  );
  const resumeTool = tools.find((tool) => tool.name === "run_resume");
  assert.match(resumeTool.description, /ownerless applicable stop/u);
  assert.match(resumeTool.description, /original stop key/u);
  assert.match(resumeTool.description, /durable settlement or child exit/u);
  const startTool = tools.find((tool) => tool.name === "run_start");
  assert.match(startTool.description, /user deliberately selects/u);
  assert.match(
    startTool.description,
    /Recommend fresh for a long, multi-topic, or uncertain session/u,
  );
  assert.doesNotMatch(startTool.description, /by default/u);
  const modeSchema = startTool.inputSchema.properties.mode;
  assert.deepEqual(modeSchema.enum, ["independent", "lazy", "combined"]);
  assert.match(modeSchema.description, /default and recommended/u);
  assert.match(modeSchema.description, /higher context\/token use/u);
  assert.match(modeSchema.description, /without independent review/u);
  const sourceSessionSchema = startTool.inputSchema.properties.sourceSession;
  const sourceSessionMetadata = JSON.stringify(sourceSessionSchema);
  assert.equal(sourceSessionSchema.default, null);
  assert.match(sourceSessionMetadata, /Leave unset for a fresh start/u);
  assert.match(
    sourceSessionMetadata,
    /Opaque native session ID supplied only after the user chooses a fork/u,
  );
  assert.match(
    sourceSessionMetadata,
    /or \\"current\\" inheritance when unknown; never guess an alias/u,
  );
  const reportingTool = tools.find(
    (tool) => tool.name === "unexpected_issue_report",
  );
  assert.match(reportingTool.description, /genuinely unexpectedly/u);
  assert.match(reportingTool.description, /exhausted configured budgets/u);
  assert.match(reportingTool.description, /documented environment blockers/u);
  assert.match(reportingTool.description, /no logs, transcripts, prompts/u);
  assert.equal(reportingTool.annotations.destructiveHint, false);
  assert.deepEqual(reportingTool.inputSchema.required.sort(), [
    "actualBehavior",
    "expectedBehavior",
    "idempotencyKey",
    "occurrence",
    "projectPath",
    "summary",
    "unexpectedReason",
  ]);
  const pipelines = await client.callTool({
    name: "pipelines_list",
    arguments: {},
  });
  assert.deepEqual(
    pipelines.structuredContent.pipelines.map(({ id }) => id),
    ["plan-authoring", "plan-execution", "polishing"],
  );
  for (const pipeline of pipelines.structuredContent.pipelines) {
    assert.deepEqual(pipeline.settings.mode, {
      defaultValue: "independent",
      recommendedValue: "independent",
      values: ["independent", "lazy", "combined"],
    });
    assert.ok(pipeline.runOptions.includes("mode"));
  }
  assert.deepEqual(
    pipelines.structuredContent.pipelines.find(({ id }) => id === "polishing")
      .taskInputs,
    {
      task: { filename: "task.md", optional: false },
      taskClarifications: {
        filename: "clarifications.md",
        optional: true,
      },
      context: { filename: "context.md", optional: true },
    },
  );
  const invalid = await client.callTool({
    name: "run_status",
    arguments: { runId: "not-a-run-id" },
  });
  assert.equal(invalid.isError, true);

  await client.close();
  assert.equal(diagnostics, "");
});

test("reports unexpected issues from a detached worktree over fresh STDIO", async (t) => {
  if (!(await requireChildNodeStdout(t))) {
    return;
  }
  const paths = await workspace(t, "agent-runner-mcp-detached-report-");
  const repositoryPath = paths.projectPath;
  const worktreePath = join(paths.root, "worktree");
  await executeFile("git", ["init", "-q", "-b", "main", repositoryPath]);
  await Promise.all([
    writeFile(join(repositoryPath, ".gitignore"), "/LOCAL_ARTIFACTS/\n"),
    writeFile(join(repositoryPath, "tracked.txt"), "tracked\n"),
  ]);
  await executeFile("git", ["-C", repositoryPath, "add", "."]);
  await executeFile("git", [
    "-C",
    repositoryPath,
    "-c",
    "user.name=Fixture User",
    "-c",
    "user.email=fixture@example.com",
    "commit",
    "-qm",
    "initial",
  ]);
  await executeFile("git", [
    "-C",
    repositoryPath,
    "worktree",
    "add",
    "--detach",
    "-q",
    worktreePath,
    "HEAD",
  ]);

  const projectPath = await realpath(worktreePath);
  const issuesPath = join(
    projectPath,
    "LOCAL_ARTIFACTS",
    "agent-runner",
    "issues",
  );
  const preflight = await createGitService().preflight({
    projectPath,
    requiredIgnoredPaths: [issuesPath],
  });
  assert.equal(preflight.snapshot.projectPath, projectPath);
  assert.equal(preflight.snapshot.detached, true);
  assert.deepEqual(preflight.ignoredPaths, [
    {
      changed: false,
      exists: false,
      ignored: true,
      kind: null,
      path: issuesPath,
      relativePath: "LOCAL_ARTIFACTS/agent-runner/issues",
      tracked: false,
    },
  ]);

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: ["bin/agent-run.js", "mcp"],
    cwd: new URL("../..", import.meta.url).pathname,
    env: { ...process.env, XDG_STATE_HOME: paths.stateRoot },
    stderr: "pipe",
  });
  let diagnostics = "";
  transport.stderr?.on("data", (chunk) => {
    diagnostics += chunk;
  });
  const client = new Client({ name: "detached-report-test", version: "1.0.0" });
  t.after(() => client.close().catch(() => {}));
  await client.connect(transport);

  const input = {
    idempotencyKey: "detached-worktree-report",
    projectPath,
    summary: "The detached worktree report path was rejected unexpectedly.",
    expectedBehavior: "The canonical ignored destination accepts the report.",
    actualBehavior: "This regression verifies successful publication.",
    occurrence: "It occurred through a fresh STDIO MCP process.",
    unexpectedReason: "Run preflight accepted the exact same destination.",
  };
  const first = await client.callTool({
    name: "unexpected_issue_report",
    arguments: input,
  });
  assert.equal(first.isError, undefined);
  assert.equal(dirname(first.structuredContent.reportPath), issuesPath);
  assert.match(
    await readFile(first.structuredContent.reportPath, "utf8"),
    /The detached worktree report path was rejected unexpectedly\./u,
  );
  const retry = await client.callTool({
    name: "unexpected_issue_report",
    arguments: input,
  });
  assert.deepEqual(retry.structuredContent, first.structuredContent);
  assert.equal(diagnostics, "");
});

test("persists exact action receipts and rejects idempotency collisions", async (t) => {
  const paths = await workspace(t, "agent-runner-mcp-actions-");
  const store = createRunStore({ stateRoot: paths.stateRoot });
  const input = {
    key: "same-request",
    tool: "run_start",
    arguments: { pipelineId: "plan-authoring" },
    context: { runId: RUN_ID },
  };

  const first = await store.beginAction(input);
  assert.equal(first.created, true);
  await first.updateContext({ runId: RUN_ID, prepared: true });
  await first.release();

  const recovered = await store.beginAction(input);
  assert.equal(recovered.created, false);
  assert.equal(recovered.record.context.prepared, true);
  await recovered.complete({ runId: RUN_ID });
  await recovered.release();

  const retry = await store.beginAction(input);
  assert.equal(retry.record.status, "completed");
  assert.deepEqual(retry.record.result, { runId: RUN_ID });
  await assert.rejects(
    retry.complete({ runId: SECOND_RUN_ID }),
    /cannot be completed/u,
  );
  await retry.release();

  await assert.rejects(
    store.beginAction({
      ...input,
      arguments: { pipelineId: "plan-execution" },
    }),
    (error) => error.code === "ERR_MCP_IDEMPOTENCY_CONFLICT",
  );
});

test("detached stop supervision follows transient ownership until settlement or child exit", async (t) => {
  for (const exitCode of [1, RUNTIME_VERSION_SKEW_EXIT_CODE]) {
    await t.test(String(exitCode), async (t) => {
      const paths = await workspace(t, "agent-runner-stop-exit-");
      const store = createRunStore({ stateRoot: paths.stateRoot });
      const initial = await createStoredRun(store, paths, {
        pipelineId: "plan-execution",
      });
      const older = await createStoredRun(store, paths, {
        id: SECOND_RUN_ID,
        pipelineId: "plan-execution",
      });
      const olderLease = await store.acquireRunLease(older.runId);
      const worktree = await store.acquireWorktreeLease(
        paths.projectPath,
        older.runId,
      );
      await store.requestOperatorStop({
        runId: older.runId,
        kind: "cancel_requested",
        expectedRevision: older.revision,
        idempotencyKey: "older-cancel",
      });
      const inspected = deferred();
      let lease;
      let onExit;
      let finished = false;
      const runner = storedRunner(store, paths);
      const control = createMcpControlPlane({
        runner: {
          ...runner,
          async status(runId) {
            const current = await runner.status(runId);
            if (lease) inspected.resolve();
            return current;
          },
        },
        runStore: store,
        async launchRun(runId, action, options) {
          assert.equal(action, null);
          assert.equal(options.stopCheckpointRevision, initial.revision);
          assert.equal(
            options.expectedRuntimeCompatibility,
            DETACHED_RUNTIME_COMPATIBILITY_TOKEN,
          );
          lease = await store.acquireRunLease(runId);
          onExit = options.onExit;
        },
      });
      const pending = control.runCancel({
        runId: initial.runId,
        expectedRevision: initial.revision,
        idempotencyKey: "transient-owner-stop",
      });
      pending.then(
        () => {
          finished = true;
        },
        () => {
          finished = true;
        },
      );
      await inspected.promise;
      await new Promise(setImmediate);
      assert.equal(finished, false, "A run lease is not stop settlement.");
      assert.equal(
        (await store.loadRun(initial.runId)).stopRequest.reconciledRevision,
        null,
      );
      onExit(exitCode);
      await assert.rejects(
        pending,
        (error) =>
          error.code ===
            (exitCode === RUNTIME_VERSION_SKEW_EXIT_CODE
              ? "ERR_RUNTIME_VERSION_SKEW"
              : "ERR_DETACHED_START_FAILED") &&
          /before durable stop settlement/u.test(error.message) &&
          (exitCode === RUNTIME_VERSION_SKEW_EXIT_CODE
            ? /restart the Agent Runner MCP server/iu.test(error.message)
            : error.message.includes(`lease belongs to run ${older.runId}`)) &&
          error.message.includes(`reconciliation for run ${initial.runId}`),
      );
      await settleStoredStop(store, initial.runId, lease);
      await lease.release();
      assert.equal(
        (await store.loadRun(older.runId)).stopRequest.reconciledRevision,
        null,
      );
      await settleStoredStop(store, older.runId, olderLease);
      await worktree.release();
      await olderLease.release();
    });
  }
});

test("detached stop supervision rechecks settlement after a racing child exit", async (t) => {
  const paths = await workspace(t, "agent-runner-stop-settlement-race-");
  const store = createRunStore({ stateRoot: paths.stateRoot });
  const initial = await createStoredRun(store, paths);
  const runner = storedRunner(store, paths);
  let onExit;
  let exited = false;
  const control = createMcpControlPlane({
    runStore: store,
    runner: {
      ...runner,
      async status(runId) {
        const snapshot = await runner.status(runId);
        if (onExit !== undefined && !exited) {
          exited = true;
          await settleStoredStop(store, runId);
          onExit(0);
        }
        return snapshot;
      },
    },
    launchRun(_runId, _action, options) {
      onExit = options.onExit;
    },
  });
  const receipt = await control.runPause({
    runId: initial.runId,
    expectedRevision: initial.revision,
    idempotencyKey: "settlement-exit-race",
  });
  assert.equal(receipt.runId, initial.runId);
  assert.equal(exited, true);
  assert.notEqual(
    (await store.loadRun(initial.runId)).stopRequest.reconciledRevision,
    null,
  );
});

test("action-free ownerless stop recovery uses a new exact-revision key and waits for settlement", async (t) => {
  for (const kind of ["pause_requested", "cancel_requested"]) {
    await t.test(kind, async (t) => {
      const paths = await workspace(t, "agent-runner-stop-resume-");
      const store = createRunStore({ stateRoot: paths.stateRoot });
      const initial = await createStoredRun(store, paths, {
        pipelineId: "plan-execution",
      });
      await store.requestOperatorStop({
        runId: initial.runId,
        kind,
        expectedRevision: initial.revision,
        idempotencyKey: "unavailable-original-key",
      });
      const pending = await store.loadRun(initial.runId);
      const input = {
        runId: pending.runId,
        expectedRevision: pending.revision,
        action: null,
        idempotencyKey: "new-recovery-key",
      };
      const identity = {
        key: input.idempotencyKey,
        tool: "run_resume",
        arguments: {
          runId: input.runId,
          expectedRevision: input.expectedRevision,
          action: null,
        },
      };
      const launched = deferred();
      let lease;
      let onExit;
      let launches = 0;
      let finished = false;
      const control = createMcpControlPlane({
        runner: storedRunner(store, paths),
        runStore: store,
        async launchRun(runId, action, options) {
          launches += 1;
          assert.equal(action, null);
          assert.equal(options.stopCheckpointRevision, initial.revision);
          const intent = await store.readAction(identity);
          assert.equal(intent.status, "intent");
          assert.equal(intent.context.stopCheckpointRevision, initial.revision);
          lease = await store.acquireRunLease(runId);
          await store.recordStopActivity(lease, {
            actor: "runner",
            phase: "stop",
            kind: "reconciling",
            message: "Reconciling stop.",
          });
          onExit = options.onExit;
          launched.resolve();
        },
      });
      await assert.rejects(
        control.runResume({
          ...input,
          idempotencyKey: "stale",
          expectedRevision: initial.revision,
        }),
        /stale/u,
      );
      await assert.rejects(
        control.runResume({
          ...input,
          idempotencyKey: "non-null",
          action: { type: "extra-fix-rounds", amount: 1 },
        }),
        /action-free/u,
      );
      const recovering = control.runResume(input);
      recovering.then(
        () => {
          finished = true;
        },
        () => {
          finished = true;
        },
      );
      await launched.promise;
      await new Promise(setImmediate);
      assert.equal(finished, false);
      const active = await store.loadRun(initial.runId);
      await assert.rejects(
        control.runResume({
          ...input,
          expectedRevision: active.revision,
          idempotencyKey: "competing-recovery",
        }),
        { code: "ERR_RUN_LEASED" },
      );
      const settled = await settleStoredStop(store, initial.runId, lease);
      await lease.release();
      onExit(0);
      assert.deepEqual(await recovering, { runId: initial.runId });
      assert.deepEqual(await control.runResume(input), {
        runId: initial.runId,
      });
      assert.equal(launches, 1);
      assert.equal((await store.readAction(identity)).status, "completed");
      assert.equal(
        settled.pipelineState.workflowState,
        kind === "cancel_requested" ? "CANCELED" : "WAITING_FOR_USER",
      );
      assert.equal(settled.pause.operatorResume.workflowState, "CLARIFY");
    });
  }
});

test("ownerless stop recovery preserves version-skew retries and durable receipt replay", async (t) => {
  const paths = await workspace(t, "agent-runner-stop-retry-");
  const store = createRunStore({ stateRoot: paths.stateRoot });
  const initial = await createStoredRun(store, paths);
  const stop = await store.requestOperatorStop({
    runId: initial.runId,
    kind: "cancel_requested",
    expectedRevision: initial.revision,
    idempotencyKey: "original-stop",
  });
  const input = {
    runId: initial.runId,
    expectedRevision: stop.revision,
    action: null,
    idempotencyKey: "stop-retry",
  };
  let launches = 0;
  let loseReceipt = true;
  const control = createMcpControlPlane({
    runner: storedRunner(store, paths),
    runStore: {
      ...store,
      async beginAction(...args) {
        const action = await store.beginAction(...args);
        return {
          ...action,
          get record() {
            return action.record;
          },
          async complete(receipt) {
            if (loseReceipt) {
              loseReceipt = false;
              throw new Error("Receipt publication interrupted.");
            }
            return action.complete(receipt);
          },
        };
      },
    },
    async launchRun(runId, action, { onExit, stopCheckpointRevision }) {
      assert.equal(action, null);
      assert.equal(stopCheckpointRevision, initial.revision);
      launches += 1;
      if (launches === 1) {
        onExit(RUNTIME_VERSION_SKEW_EXIT_CODE);
        return;
      }
      const lease = await store.acquireRunLease(runId);
      await settleStoredStop(store, runId, lease);
      await lease.release();
      onExit(0);
    },
  });
  await assert.rejects(control.runResume(input), {
    code: "ERR_RUNTIME_VERSION_SKEW",
  });
  await assert.rejects(
    control.runResume(input),
    /Receipt publication interrupted/u,
  );
  assert.deepEqual(await control.runResume(input), { runId: initial.runId });
  assert.deepEqual(await control.runResume(input), { runId: initial.runId });
  assert.equal(launches, 2);
  assert.equal(
    (await store.loadRun(initial.runId)).pipelineState.workflowState,
    "CANCELED",
  );
});

test("concurrent ownerless stop recoveries cannot gain a second execution owner", async (t) => {
  const paths = await workspace(t, "agent-runner-stop-race-");
  const store = createRunStore({ stateRoot: paths.stateRoot });
  const initial = await createStoredRun(store, paths);
  const stop = await store.requestOperatorStop({
    runId: initial.runId,
    kind: "cancel_requested",
    expectedRevision: initial.revision,
    idempotencyKey: "race-stop",
  });
  const bothLaunched = deferred();
  const finishWinner = deferred();
  const rejected = deferred();
  const children = [];
  let launches = 0;
  let owners = 0;
  let winnerLease;
  const control = createMcpControlPlane({
    runner: storedRunner(store, paths),
    runStore: store,
    launchRun(runId, _action, { onExit, stopCheckpointRevision }) {
      assert.equal(stopCheckpointRevision, initial.revision);
      launches += 1;
      if (launches === 2) bothLaunched.resolve();
      const child = (async () => {
        await bothLaunched.promise;
        let lease;
        try {
          lease = await store.acquireRunLease(runId);
        } catch (error) {
          assert.equal(error.code, "ERR_RUN_LEASED");
          onExit(1);
          return;
        }
        owners += 1;
        winnerLease = lease;
        await finishWinner.promise;
        await lease.release();
        onExit(0);
      })();
      children.push(child);
    },
  });
  const requests = ["first-recovery", "second-recovery"].map(
    (idempotencyKey) => {
      const request = control.runResume({
        runId: initial.runId,
        expectedRevision: stop.revision,
        action: null,
        idempotencyKey,
      });
      request.catch((error) => rejected.resolve(error));
      return request;
    },
  );
  const error = await rejected.promise;
  assert.equal(error.code, "ERR_DETACHED_START_FAILED");
  assert.equal(owners, 1);
  await settleStoredStop(store, initial.runId, winnerLease);
  finishWinner.resolve();
  await Promise.all(children);
  const outcomes = await Promise.allSettled(requests);
  assert.equal(
    outcomes.filter(({ status }) => status === "fulfilled").length,
    1,
  );
  assert.equal(
    outcomes.filter(({ status }) => status === "rejected").length,
    1,
  );
});

test("replaying a settled stop receipt does not reconcile a later unrelated stop", async (t) => {
  const paths = await workspace(t, "agent-runner-stop-replay-");
  const store = createRunStore({ stateRoot: paths.stateRoot });
  const initial = await createStoredRun(store, paths);
  const input = {
    runId: initial.runId,
    expectedRevision: initial.revision,
    idempotencyKey: "old-pause",
  };
  const receipt = await store.requestOperatorStop({
    ...input,
    kind: "pause_requested",
  });
  await settleStoredStop(store, initial.runId);
  const lease = await store.acquireRunLease(initial.runId);
  const resumed = await store.transitionRun(lease, {
    pipelineState: initial.pipelineState,
    pause: null,
  });
  await lease.release();
  await store.requestOperatorStop({
    runId: initial.runId,
    kind: "cancel_requested",
    expectedRevision: resumed.revision,
    idempotencyKey: "later-cancel",
  });
  const control = createMcpControlPlane({
    runner: storedRunner(store, paths),
    runStore: store,
    launchRun: () =>
      assert.fail("An old receipt must not dispatch a later stop."),
  });
  assert.deepEqual(await control.runPause(input), receipt);
  assert.equal(
    (await store.loadRun(initial.runId)).stopRequest.reconciledRevision,
    null,
  );
});

test("persists stop receipts and projects pending stops without replacing a live owner", async (t) => {
  const paths = await workspace(t, "agent-runner-mcp-stop-");
  const store = createRunStore({ stateRoot: paths.stateRoot });
  const initial = await createStoredRun(store, paths);
  const runner = storedRunner(store, paths);
  const ownerIsLive = true;
  const launches = [];
  const control = createMcpControlPlane({
    runner,
    runStore: {
      ...store,
      async runLeaseOwnerIsLive() {
        return ownerIsLive;
      },
    },
    async launchRun(runId, action, options) {
      launches.push({ runId, action, options });
    },
  });
  const pauseInput = {
    runId: initial.runId,
    expectedRevision: initial.revision,
    idempotencyKey: "pause-key",
  };
  const pause = await control.runPause(pauseInput);
  assert.deepEqual(pause, {
    runId: initial.runId,
    requestId: pause.requestId,
    timing: "immediate",
    effectiveTiming: "immediate",
    targetBoundary: null,
    kind: "pause_requested",
    expectedRevision: initial.revision,
    revision: initial.revision + 1,
  });
  assert.match(pause.requestId, /^[a-f0-9]{64}$/u);
  assert.deepEqual(await control.runPause(pauseInput), pause);
  assert.deepEqual(
    await control.runPause({ ...pauseInput, timing: "immediate" }),
    pause,
  );
  await assert.rejects(
    control.runPause({ ...pauseInput, timing: "after-current-commit" }),
    { code: "ERR_MCP_IDEMPOTENCY_CONFLICT" },
  );
  assert.equal(launches.length, 0);
  const status = await control.runStatus({ runId: initial.runId });
  assert.deepEqual(status.pendingStop, {
    timing: "immediate",
    effectiveTiming: "immediate",
    targetStep: null,
    kind: "pause_requested",
    revision: initial.revision + 1,
  });
  assert.doesNotMatch(JSON.stringify(status), new RegExp(pause.requestId, "u"));
  await assert.rejects(
    control.runPause({
      ...pauseInput,
      expectedRevision: initial.revision + 1,
    }),
    { code: "ERR_MCP_IDEMPOTENCY_CONFLICT" },
  );
  await assert.rejects(
    control.runPause({
      ...pauseInput,
      idempotencyKey: "stale-pause",
    }),
    { code: "ERR_STALE_RUN_REVISION" },
  );
  await assert.rejects(
    control.runPause({
      ...pauseInput,
      expectedRevision: pause.revision,
      idempotencyKey: "competing-pause",
    }),
    { code: "ERR_STOP_PENDING" },
  );

  const cancelInput = {
    runId: initial.runId,
    expectedRevision: pause.revision,
    idempotencyKey: "cancel-key",
  };
  const cancel = await control.runCancel(cancelInput);
  assert.equal(cancel.kind, "cancel_requested");
  assert.equal(cancel.revision, pause.revision + 1);
  assert.deepEqual(
    (await control.runStatus({ runId: initial.runId })).pendingStop,
    {
      kind: "cancel_requested",
      revision: cancel.revision,
      timing: "immediate",
      effectiveTiming: "immediate",
      targetStep: null,
    },
  );
});

test("MCP deferred timing preserves replay, supersession, waits, and historical settlement", async (t) => {
  const paths = await workspace(t, "agent-runner-mcp-deferred-");
  const store = createRunStore({
    stateRoot: paths.stateRoot,
    resolveStopBoundary,
  });
  const initial = await createStoredRun(store, paths, {
    pipelineId: "plan-execution",
    workflowState: "IMPLEMENT",
    state: {
      currentStep: 1,
      completedCommits: [],
      repositoryBaseline: { head: "a".repeat(40) },
      canonicalPlan:
        "## Commit 1: feat(test): add behavior\n\nImplement behavior.\n",
    },
  });
  const lease = await store.acquireRunLease(initial.runId);
  const control = createMcpControlPlane({
    runner: storedRunner(store, paths),
    runStore: store,
    launchRun: () => assert.fail("A live owner must not be replaced."),
  });
  const input = {
    runId: initial.runId,
    expectedRevision: initial.revision,
    idempotencyKey: "deferred-pause",
    timing: "after-current-commit",
  };
  const receipt = await control.runPause(input);
  assert.equal(receipt.targetBoundary.step, 1);
  assert.equal(receipt.timing, "after-current-commit");
  assert.deepEqual(await control.runPause(input), receipt);
  await assert.rejects(control.runPause({ ...input, timing: "immediate" }), {
    code: "ERR_MCP_IDEMPOTENCY_CONFLICT",
  });
  await assert.rejects(
    control.runCancel({
      ...input,
      idempotencyKey: "stale-cancel",
      expectedRevision: receipt.revision + 10,
    }),
    { code: "ERR_STALE_RUN_REVISION" },
  );
  const changed = await store.waitForRunChange(initial.runId, {
    afterRevision: initial.revision,
    timeoutMs: 100,
  });
  assert.equal(changed.revision, receipt.revision);
  const pending = await control.runStatus({ runId: initial.runId });
  assert.equal(pending.stop.state, "pending");
  assert.equal(pending.stop.targetStep, 1);
  const abort = new AbortController();
  const waiting = control.runWait(
    { runId: initial.runId, cursor: receipt.revision, timeoutMs: 10000 },
    { signal: abort.signal },
  );
  abort.abort();
  await assert.rejects(waiting, { name: "AbortError" });
  assert.equal((await store.loadRun(initial.runId)).revision, receipt.revision);
  const cancel = await control.runCancel({
    ...input,
    idempotencyKey: "immediate-cancel",
    expectedRevision: receipt.revision,
    timing: "immediate",
  });
  assert.equal(cancel.effectiveTiming, "immediate");
  assert.equal(
    (await control.runStatus({ runId: initial.runId })).stop.state,
    "applicable",
  );
  await store.settleCheckpoint(lease, (run) => ({
    patch: {
      pipelineState: { ...run.pipelineState, workflowState: "CANCELED" },
      pause: {
        reason: "operator_canceled",
        resumeAction: null,
        operatorResume: {
          workflowState: "IMPLEMENT",
          pause: null,
          activeTurn: null,
        },
      },
    },
    settlement: { kind: "quiescent", commit: null },
    activity: {
      actor: "runner",
      phase: "stop",
      kind: "canceled",
      message: "Operator canceled.",
    },
  }));
  await lease.release();
  const settled = await control.runWait({
    runId: initial.runId,
    cursor: receipt.revision,
    timeoutMs: 0,
  });
  assert.equal(settled.stop.state, "settled");
  assert.deepEqual(settled.stop.settlement, {
    kind: "quiescent",
    commit: null,
  });
  const page = await control.runActivity({
    runId: initial.runId,
    cursor: 0,
    limit: 100,
  });
  assert.equal(
    page.activities.find((entry) => entry.revision === receipt.revision).stop
      .state,
    "pending",
  );
  assert.equal(page.activities.at(-1).stop.state, "settled");
  assert.doesNotMatch(
    JSON.stringify(page),
    /requestId|baselineHead|checkpoint/u,
  );
  assert.deepEqual(await control.runPause(input), receipt);
});

test("recovers an ownerless stop after the requesting client disconnects", async (t) => {
  for (const timing of ["immediate", "after-current-commit"]) {
    await t.test(timing, async (t) => {
      const paths = await workspace(t, "agent-runner-mcp-stop-disconnect-");
      const store = createRunStore({
        stateRoot: paths.stateRoot,
        resolveStopBoundary,
      });
      const initial = await createStoredRun(store, paths, {
        pipelineId: "plan-execution",
        workflowState: "IMPLEMENT",
        state: {
          currentStep: 1,
          completedCommits: [],
          repositoryBaseline: { head: "a".repeat(40) },
          canonicalPlan:
            "## Commit 1: feat(test): add behavior\n\nImplement behavior.\n",
        },
      });
      const runner = storedRunner(store, paths);
      const abort = new AbortController();
      const runStore = { ...store };
      const input = {
        runId: initial.runId,
        expectedRevision: initial.revision,
        idempotencyKey: "disconnected-cancel",
        timing,
      };
      const finish = deferred();
      let launches = 0;
      const control = createMcpControlPlane({
        runner,
        runStore,
        async launchRun() {
          launches++;
          abort.abort();
          await finish.promise;
          await settleStoredStop(store, initial.runId);
        },
      });
      await assert.rejects(control.runCancel(input, { signal: abort.signal }), {
        name: "AbortError",
      });
      assert.equal(
        (await runner.status(initial.runId)).run.stopRequest.kind,
        "cancel_requested",
      );

      finish.resolve();
      const receipt = await control.runCancel(input);
      assert.equal(receipt.kind, "cancel_requested");
      assert.equal(receipt.revision, initial.revision + 1);
      assert.equal(launches, 1);
      assert.equal(receipt.timing, timing);
    });
  }
});

test("reconciles an incomplete start intent after run creation", async (t) => {
  const paths = await workspace(t, "agent-runner-mcp-start-");
  const store = createRunStore({ stateRoot: paths.stateRoot });
  const runner = storedRunner(store, paths);
  const launches = [];
  const input = {
    idempotencyKey: "start-key",
    pipelineId: "plan-authoring",
    projectPath: paths.projectPath,
    taskPath: paths.taskPath,
    proactiveClarification: false,
    effort: "high",
    roleOverrides: { planner: { effort: "current" } },
    sourceSession: null,
  };
  const intent = await store.beginAction({
    key: input.idempotencyKey,
    tool: "run_start",
    arguments: {
      pipelineId: input.pipelineId,
      projectPath: input.projectPath,
      taskPath: input.taskPath,
      proactiveClarification: false,
      effort: input.effort,
      roleOverrides: input.roleOverrides,
      sourceSession: null,
    },
    context: { runId: RUN_ID },
  });
  await runner.create(input, { runId: RUN_ID });
  await intent.release();
  const control = createMcpControlPlane({
    async launchRun(id, _action, options) {
      launches.push({ id, options });
      await advanceMutatingStoredRun(store, id, options.dispatch);
    },
    runIdFactory: () => SECOND_RUN_ID,
    runner,
    runStore: store,
  });

  assert.deepEqual(await control.runStart(input), { runId: RUN_ID });
  await Promise.all([
    rm(paths.projectPath, { recursive: true }),
    rm(paths.taskPath, { recursive: true }),
  ]);
  assert.deepEqual(await control.runStart(input), { runId: RUN_ID });
  assert.equal(launches.length, 1);
  assert.equal(launches[0].id, RUN_ID);
  assert.equal(
    launches[0].options.expectedRuntimeCompatibility,
    DETACHED_RUNTIME_COMPATIBILITY_TOKEN,
  );
  await assert.rejects(
    control.runStart({ ...input, pipelineId: "plan-execution" }),
    (error) => error.code === "ERR_MCP_IDEMPOTENCY_CONFLICT",
  );
  await assert.rejects(
    control.runStart({ ...input, mode: "lazy" }),
    (error) => error.code === "ERR_MCP_IDEMPOTENCY_CONFLICT",
  );
});

test("keeps a conflicted detached start durable for idempotent retry", async (t) => {
  const paths = await workspace(t, "agent-runner-mcp-worktree-lease-");
  const store = createRunStore({ stateRoot: paths.stateRoot });
  const runner = storedRunner(store, paths);
  const ownerLease = await store.acquireWorktreeLease(
    paths.projectPath,
    SECOND_RUN_ID,
  );
  const launches = [];
  const control = createMcpControlPlane({
    async launchRun(id, _action, options) {
      launches.push(id);
      await advanceMutatingStoredRun(store, id, options.dispatch);
    },
    runIdFactory: () => RUN_ID,
    runner,
    runStore: store,
  });
  const input = {
    idempotencyKey: "worktree-conflict-start",
    pipelineId: "plan-execution",
    projectPath: paths.projectPath,
    taskPath: paths.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  };

  await assert.rejects(
    control.runStart(input),
    (error) =>
      error.code === "ERR_WORKTREE_LEASED" &&
      /durable.*same idempotency key/iu.test(error.message),
  );
  assert.deepEqual(launches, []);
  assert.equal((await store.loadRun(RUN_ID)).revision, 1);

  await ownerLease.release();
  assert.deepEqual(await control.runStart(input), { runId: RUN_ID });
  assert.deepEqual(launches, [RUN_ID]);
});

test("restart recovery bounds noisy observations and preserves recorded child identity", async (t) => {
  const paths = await workspace(t, "agent-runner-dispatch-restart-");
  let childState = "live";
  const identity = { bootId: RUN_ID, startTicks: "41" };
  const store = createRunStore({
    stateRoot: paths.stateRoot,
    hostName: "test-host",
    processIsAlive: (pid) => pid !== 42424 || childState !== "dead",
    processIdentity: (pid) =>
      pid !== 42424
        ? identity
        : childState === "unverifiable"
          ? null
          : childState === "replaced"
            ? { ...identity, startTicks: "42" }
            : identity,
  });
  await createStoredRun(store, paths);
  const lease = await store.acquireRunLease(RUN_ID);
  const interrupted = await store.startAgentTurn(
    lease,
    { role: "planner", phase: "clarify" },
    {
      activity: {
        actor: "planner",
        phase: "clarify",
        kind: "turn-started",
        message: "Interrupted clarification.",
      },
    },
  );
  await lease.release();
  const input = {
    runId: RUN_ID,
    expectedRevision: interrupted.revision,
    action: null,
    idempotencyKey: "restart-dispatch",
  };
  let launches = 0;
  let notifications = 0;
  let clock = 0;
  const options = {
    runner: storedRunner(store, paths),
    runStore: {
      ...store,
      async waitForRunChange(id) {
        notifications++;
        return store.loadRun(id);
      },
    },
    dispatchClock: () => clock,
    async launchRun(id, _action, options) {
      launches++;
      await options.onSpawn({
        pid: 42424,
        hostname: "test-host",
        processIdentity: identity,
      });
      if (launches === 1) {
        const lease = await store.acquireRunLease(id);
        await store.recordRecoveryDispatch(lease, options.dispatch);
        await lease.release();
        throw new Error("server interrupted after admission");
      }
      await advanceMutatingStoredRun(store, id, options.dispatch);
    },
  };
  await assert.rejects(
    createMcpControlPlane(options).runResume(input),
    /server interrupted/u,
  );
  await assert.rejects(createMcpControlPlane(options).runResume(input), {
    code: "ERR_DETACHED_OWNERSHIP_PENDING",
  });
  assert.equal(notifications, 64);
  assert.equal(launches, 1);
  // Elapsed time is a separate bound even with no wall-clock delay.
  options.runStore.waitForRunChange = async (id) => {
    clock += 30_000;
    return store.loadRun(id);
  };
  await assert.rejects(createMcpControlPlane(options).runResume(input), {
    code: "ERR_DETACHED_OWNERSHIP_PENDING",
  });
  childState = "unverifiable";
  await assert.rejects(createMcpControlPlane(options).runResume(input), {
    code: "ERR_DETACHED_OWNERSHIP_PENDING",
  });
  assert.equal(launches, 1);
  childState = "replaced";
  assert.deepEqual(await createMcpControlPlane(options).runResume(input), {
    runId: RUN_ID,
  });
  assert.deepEqual(await createMcpControlPlane(options).runResume(input), {
    runId: RUN_ID,
  });
  assert.equal(launches, 2);
});

test("an unrelated revision cannot acknowledge or replay a detached dispatch", async (t) => {
  const paths = await workspace(t, "agent-runner-dispatch-unrelated-");
  const store = createRunStore({ stateRoot: paths.stateRoot });
  let launches = 0;
  const options = {
    runner: storedRunner(store, paths),
    runStore: store,
    runIdFactory: () => RUN_ID,
    async launchRun(id, _action, options) {
      launches++;
      const lease = await store.acquireRunLease(id);
      await store.transitionRun(lease, { counters: { unrelated: 1 } });
      await lease.release();
      options.onExit(0);
    },
  };
  const input = {
    pipelineId: "plan-authoring",
    projectPath: paths.projectPath,
    taskPath: paths.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
    idempotencyKey: "unrelated-dispatch",
  };
  await assert.rejects(createMcpControlPlane(options).runStart(input), {
    code: "ERR_DETACHED_START_FAILED",
  });
  await assert.rejects(createMcpControlPlane(options).runStart(input), {
    code: "ERR_RUN_REVISION_CHANGED",
  });
  assert.equal(launches, 1);
});

test("an admitted dispatch cannot replay after another admission or CLI turn", async (t) => {
  for (const replacement of ["admission", "turn"]) {
    await t.test(replacement, async (t) => {
      const paths = await workspace(t, "agent-runner-dispatch-superseded-");
      const store = createRunStore({ stateRoot: paths.stateRoot });
      let launches = 0;
      const options = {
        runner: storedRunner(store, paths),
        runStore: store,
        runIdFactory: () => RUN_ID,
        async launchRun(id, _action, options) {
          launches++;
          const lease = await store.acquireRunLease(id);
          try {
            await store.recordRecoveryDispatch(lease, options.dispatch);
          } finally {
            await lease.release();
          }
          throw new Error("Interrupted after admission");
        },
      };
      const input = {
        pipelineId: "plan-authoring",
        projectPath: paths.projectPath,
        taskPath: paths.taskPath,
        proactiveClarification: false,
        roleOverrides: {},
        sourceSession: null,
        idempotencyKey: "superseded",
      };
      await assert.rejects(
        createMcpControlPlane(options).runStart(input),
        /Interrupted after admission/u,
      );
      const lease = await store.acquireRunLease(RUN_ID);
      try {
        if (replacement === "admission") {
          await store.recordRecoveryDispatch(lease, {
            id: SECOND_RUN_ID,
            expectedRevision: (await store.loadRun(RUN_ID)).revision,
          });
        } else {
          const turn = { role: "planner", phase: "clarify" };
          await store.startAgentTurn(lease, turn, {
            activity: {
              actor: "planner",
              phase: "clarify",
              kind: "turn-started",
              message: "CLI continuation started.",
            },
          });
          await store.finishAgentTurn(lease, turn);
        }
      } finally {
        await lease.release();
      }
      await assert.rejects(createMcpControlPlane(options).runStart(input), {
        code: "ERR_RUN_REVISION_CHANGED",
      });
      assert.equal(launches, 1);
    });
  }
});

test("durable readiness repairs interrupted receipts after later input or stops", async (t) => {
  for (const [tool, method] of [
    ["run_start", "runStart"],
    ["run_resume", "runResume"],
    ["run_respond", "runRespond"],
  ]) {
    await t.test(tool, async (t) => {
      const paths = await workspace(t, "agent-runner-dispatch-receipt-");
      const store = createRunStore({ stateRoot: paths.stateRoot });
      await createStoredRun(store, paths);
      const args =
        tool === "run_start"
          ? {
              pipelineId: "plan-authoring",
              projectPath: paths.projectPath,
              taskPath: paths.taskPath,
              proactiveClarification: false,
              roleOverrides: {},
              sourceSession: null,
            }
          : {
              runId: RUN_ID,
              expectedRevision: 1,
              ...(tool === "run_resume"
                ? { action: null }
                : {
                    requestId: "answered",
                    answers: [{ questionId: "q1", answer: "A" }],
                  }),
            };
      const dispatch = { id: SECOND_RUN_ID, expectedRevision: 1 };
      const intent = await store.beginAction({
        key: "lost-receipt",
        tool,
        arguments: args,
        context: {
          runId: RUN_ID,
          expectedRevision: 1,
          responseHash: RESPONSE_HASH,
          submittedRevision: 1,
          dispatch: { ...dispatch, owner: null },
        },
      });
      try {
        await advanceMutatingStoredRun(store, RUN_ID, dispatch);
      } finally {
        // The child acknowledged continuation, but the parent lost its receipt.
        await intent.release();
      }
      const run = await store.loadRun(RUN_ID);
      await store.requestOperatorStop({
        runId: RUN_ID,
        kind: "pause_requested",
        expectedRevision: run.revision,
        idempotencyKey: "later-pause",
      });
      const before = await store.loadRun(RUN_ID);
      const control = createMcpControlPlane({
        runner: {
          ...storedRunner(store, paths),
          validateBoundary() {
            assert.fail("Receipt repair cannot revalidate old start inputs.");
          },
        },
        runStore: store,
        launchRun() {
          assert.fail("Receipt repair cannot execute another turn.");
        },
      });
      const request = { ...args, idempotencyKey: "lost-receipt" };
      const receipt = await control[method](request);
      assert.deepEqual(receipt, {
        runId: RUN_ID,
        ...(tool === "run_respond" ? { requestId: "answered" } : {}),
      });
      assert.deepEqual(await store.loadRun(RUN_ID), before);
      assert.equal(
        (await store.readAction({ key: "lost-receipt", tool, arguments: args }))
          .status,
        "completed",
      );
    });
  }
});

test("rejects detached pipeline skew and retries the exact start after restart", async (t) => {
  const paths = await workspace(t, "agent-runner-mcp-runtime-skew-");
  const store = createRunStore({ stateRoot: paths.stateRoot });
  const runner = storedRunner(store, paths);
  const oldParentToken = createDetachedRuntimeCompatibilityToken({
    pipelines: listPipelines().map((pipeline) =>
      pipeline.id === "plan-execution"
        ? { ...pipeline, stateVersion: pipeline.stateVersion - 1 }
        : pipeline,
    ),
  });
  assert.notEqual(oldParentToken, DETACHED_RUNTIME_COMPATIBILITY_TOKEN);
  let childTouchedRunStore = false;
  let childExitCode = null;
  let launchedToken = null;
  const childRunner = createRunner({
    runStore: {
      async acquireRunLease() {
        childTouchedRunStore = true;
        throw new Error("The incompatible child acquired a run lease.");
      },
    },
  });
  const staleControl = createMcpControlPlane({
    detachedCompatibilityToken: oldParentToken,
    launchRun(id, _action, { expectedRuntimeCompatibility, onExit }) {
      launchedToken = expectedRuntimeCompatibility;
      queueMicrotask(async () => {
        childExitCode = await main(["resume", "--run", id], {
          environment: {
            [DETACHED_RUNTIME_COMPATIBILITY_ENV]: expectedRuntimeCompatibility,
          },
          runner: childRunner,
          stderr: { write() {} },
          stdout: { write() {} },
        });
        onExit(childExitCode);
      });
    },
    runIdFactory: () => RUN_ID,
    runner,
    runStore: store,
  });
  const input = {
    idempotencyKey: "runtime-skew-start",
    pipelineId: "plan-execution",
    projectPath: paths.projectPath,
    taskPath: paths.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  };

  await assert.rejects(
    staleControl.runStart(input),
    (error) =>
      error.code === "ERR_RUNTIME_VERSION_SKEW" &&
      /restart the Agent Runner MCP server/iu.test(error.message),
  );
  assert.equal(launchedToken, oldParentToken);
  assert.equal(childExitCode, RUNTIME_VERSION_SKEW_EXIT_CODE);
  assert.equal(childTouchedRunStore, false);
  assert.equal((await store.loadRun(RUN_ID)).revision, 1);
  assert.equal(await store.runIsLeased(RUN_ID), false);
  assert.equal(await store.worktreeIsLeased(paths.projectPath, RUN_ID), false);
  const identity = {
    key: input.idempotencyKey,
    tool: "run_start",
    arguments: Object.fromEntries(
      Object.entries(input).filter(([key]) => key !== "idempotencyKey"),
    ),
  };
  const pending = await store.readAction(identity);
  assert.equal(pending.status, "intent");
  assert.equal(pending.result, null);
  assert.equal(JSON.stringify(pending).includes(oldParentToken), false);
  const runDirectory = await store.getRunDirectory(RUN_ID);
  assert.equal(
    (await readFile(join(runDirectory, "events.jsonl"), "utf8"))
      .trimEnd()
      .split("\n").length,
    1,
  );

  const launches = [];
  const freshControl = createMcpControlPlane({
    async launchRun(id, _action, options) {
      launches.push({ id, token: options.expectedRuntimeCompatibility });
      await advanceMutatingStoredRun(store, id, options.dispatch);
    },
    runner,
    runStore: store,
  });
  assert.deepEqual(await freshControl.runStart(input), { runId: RUN_ID });
  assert.deepEqual(launches, [
    { id: RUN_ID, token: DETACHED_RUNTIME_COMPATIBILITY_TOKEN },
  ]);
  assert.equal((await store.readAction(identity)).status, "completed");
});

test("keeps one detached owner after the MCP caller disconnects", async (t) => {
  const paths = await workspace(t, "agent-runner-mcp-disconnect-");
  const store = createRunStore({ stateRoot: paths.stateRoot });
  const runner = storedRunner(store, paths);
  const launchStarted = deferred();
  const acquireChild = deferred();
  const childOwnedRun = deferred();
  const releaseChild = deferred();
  const childFinished = deferred();
  let launches = 0;
  const control = createMcpControlPlane({
    launchRun(id, _action, options) {
      launches += 1;
      launchStarted.resolve();
      void (async () => {
        await acquireChild.promise;
        const childLease = await store.acquireRunLease(id);
        await store.recordRecoveryDispatch(childLease, options.dispatch);
        await store.recordRecoveryDispatch(childLease, options.dispatch, true);
        childOwnedRun.resolve();
        await releaseChild.promise;
        await childLease.release();
        childFinished.resolve();
      })();
    },
    runIdFactory: () => RUN_ID,
    runner,
    runStore: store,
  });
  t.after(async () => {
    releaseChild.resolve();
    await childFinished.promise;
  });
  const input = {
    idempotencyKey: "disconnected-start",
    pipelineId: "plan-authoring",
    projectPath: paths.projectPath,
    taskPath: paths.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  };
  const controller = new AbortController();
  const disconnected = control.runStart(input, {
    signal: controller.signal,
  });
  await launchStarted.promise;
  controller.abort();
  await assert.rejects(disconnected, (error) => error.name === "AbortError");

  acquireChild.resolve();
  await childOwnedRun.promise;
  assert.deepEqual(await control.runStart(input), { runId: RUN_ID });
  assert.equal(launches, 1);
  assert.equal(await store.runIsLeased(RUN_ID), true);
  assert.equal((await store.loadRun(RUN_ID)).revision, 3);
  releaseChild.resolve();
  await childFinished.promise;
});

test("retries a simultaneous detached start that loses worktree ownership", async (t) => {
  const paths = await workspace(t, "agent-runner-mcp-worktree-race-");
  const store = createRunStore({ stateRoot: paths.stateRoot });
  const runner = storedRunner(store, paths);
  const firstChildrenStarted = deferred();
  const winnerOwnedWorktree = deferred();
  const releaseWinner = deferred();
  const retryOwnedWorktree = deferred();
  const releaseRetry = deferred();
  t.after(() => {
    releaseWinner.resolve();
    releaseRetry.resolve();
  });
  const launchCounts = new Map();
  const children = [];
  let firstStartCount = 0;

  function launchRun(runId, _action, options) {
    const attempt = (launchCounts.get(runId) ?? 0) + 1;
    launchCounts.set(runId, attempt);
    if (attempt === 1) {
      firstStartCount += 1;
      if (firstStartCount === 2) {
        firstChildrenStarted.resolve();
      }
    }

    const child = (async () => {
      const runLease = await store.acquireRunLease(runId);
      let worktreeLease;
      try {
        await store.recordRecoveryDispatch(runLease, options.dispatch);
        if (runId === RUN_ID) {
          await firstChildrenStarted.promise;
          worktreeLease = await store.acquireWorktreeLease(
            paths.projectPath,
            runId,
          );
          await store.recordRecoveryDispatch(runLease, options.dispatch, true);
          winnerOwnedWorktree.resolve();
          await releaseWinner.promise;
          return;
        }
        if (attempt === 1) {
          await winnerOwnedWorktree.promise;
          try {
            worktreeLease = await store.acquireWorktreeLease(
              paths.projectPath,
              runId,
            );
          } catch (cause) {
            if (cause?.code === "ERR_WORKTREE_LEASED") {
              return;
            }
            throw cause;
          }
          throw new Error("The losing detached child acquired the worktree.");
        }
        worktreeLease = await store.acquireWorktreeLease(
          paths.projectPath,
          runId,
        );
        await store.recordRecoveryDispatch(runLease, options.dispatch, true);
        retryOwnedWorktree.resolve();
        await releaseRetry.promise;
      } finally {
        await worktreeLease?.release();
        await runLease.release();
      }
    })();
    children.push(child);
  }

  const commonInput = {
    pipelineId: "plan-execution",
    projectPath: paths.projectPath,
    taskPath: paths.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  };
  const winnerInput = {
    ...commonInput,
    idempotencyKey: "simultaneous-start-winner",
  };
  const loserInput = {
    ...commonInput,
    idempotencyKey: "simultaneous-start-loser",
  };
  const winnerControl = createMcpControlPlane({
    launchRun,
    runIdFactory: () => RUN_ID,
    runner,
    runStore: store,
  });
  const loserControl = createMcpControlPlane({
    launchRun,
    runIdFactory: () => SECOND_RUN_ID,
    runner,
    runStore: store,
  });

  const [winner, loser] = await Promise.allSettled([
    winnerControl.runStart(winnerInput),
    loserControl.runStart(loserInput),
  ]);
  assert.deepEqual(winner, {
    status: "fulfilled",
    value: { runId: RUN_ID },
  });
  assert.equal(loser.status, "rejected");
  assert.equal(loser.reason.code, "ERR_WORKTREE_LEASED");
  assert.equal(
    (
      await store.readAction({
        key: loserInput.idempotencyKey,
        tool: "run_start",
        arguments: commonInput,
      })
    ).status,
    "intent",
  );
  assert.deepEqual(await winnerControl.runStart(winnerInput), {
    runId: RUN_ID,
  });
  assert.equal(launchCounts.get(RUN_ID), 1);

  releaseWinner.resolve();
  await Promise.all(children.slice(0, 2));

  const retry = loserControl.runStart(loserInput);
  await retryOwnedWorktree.promise;
  assert.deepEqual(await retry, { runId: SECOND_RUN_ID });
  assert.equal(launchCounts.get(SECOND_RUN_ID), 2);
  releaseRetry.resolve();
  await children.at(-1);
});

test("retries when a detached loser exits after transient ownership", async (t) => {
  const paths = await workspace(t, "agent-runner-mcp-worktree-exit-");
  const store = createRunStore({ stateRoot: paths.stateRoot });
  await createStoredRun(store, paths, {
    id: SECOND_RUN_ID,
    pipelineId: "plan-execution",
  });
  const runner = storedRunner(store, paths);
  const launches = [];
  const control = createMcpControlPlane({
    async launchRun(runId, _action, { onExit, dispatch } = {}) {
      launches.push(runId);
      if (launches.length > 1) {
        await advanceMutatingStoredRun(store, runId, dispatch);
        return;
      }

      const winnerRunLease = await store.acquireRunLease(SECOND_RUN_ID);
      let winnerWorktreeLease;
      let loserRunLease;
      try {
        winnerWorktreeLease = await store.acquireWorktreeLease(
          paths.projectPath,
          SECOND_RUN_ID,
        );
        loserRunLease = await store.acquireRunLease(runId);
        await assert.rejects(
          store.acquireWorktreeLease(paths.projectPath, runId),
          (error) => error.code === "ERR_WORKTREE_LEASED",
        );
      } finally {
        await loserRunLease?.release();
        await winnerWorktreeLease?.release();
        await winnerRunLease.release();
      }
      onExit();
    },
    runIdFactory: () => RUN_ID,
    runner,
    runStore: store,
  });
  const commonInput = {
    pipelineId: "plan-execution",
    projectPath: paths.projectPath,
    taskPath: paths.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  };
  const input = {
    ...commonInput,
    idempotencyKey: "transient-worktree-conflict",
  };

  await assert.rejects(
    control.runStart(input),
    (error) =>
      error.code === "ERR_DETACHED_START_FAILED" &&
      /retry.*same idempotency key/iu.test(error.message),
  );
  assert.equal(
    (
      await store.readAction({
        key: input.idempotencyKey,
        tool: "run_start",
        arguments: commonInput,
      })
    ).status,
    "intent",
  );

  assert.deepEqual(await control.runStart(input), { runId: RUN_ID });
  assert.deepEqual(launches, [RUN_ID, RUN_ID]);
});

test("records complete pending answers before detached continuation", async (t) => {
  const paths = await workspace(t, "agent-runner-mcp-respond-");
  const store = createRunStore({ stateRoot: paths.stateRoot });
  const pendingEdit = {
    schemaVersion: 1,
    id: "request-1",
    artifactRoot: paths.taskPath,
    transcriptPath: join(paths.taskPath, "clarifications.md"),
    suspendedState: "CLARIFY",
    action: "clarification-answers",
    preEditorHash: "b".repeat(64),
  };
  await createStoredRun(store, paths, {
    pendingEdit,
    pause: {
      reason: "clarification_answers_required",
      authorizationId: "request-1",
      inputRequest: {
        id: "request-1",
        kind: "clarification",
        questions: [{ id: "q1", question: "Choose?", options: ["A", "B"] }],
        rationale: "Required for scope.",
        artifactPath: pendingEdit.transcriptPath,
      },
    },
    workflowState: "WAITING_FOR_USER",
  });
  const runner = storedRunner(store, paths);
  const launches = [];
  const control = createMcpControlPlane({
    async launchRun(id, _action, options) {
      launches.push(id);
      await advanceMutatingStoredRun(store, id, options.dispatch);
    },
    runner,
    runStore: store,
  });
  const input = {
    idempotencyKey: "response-key",
    runId: RUN_ID,
    requestId: "request-1",
    expectedRevision: 1,
    answers: [{ questionId: "q1", answer: "A" }],
  };

  const pendingStatus = await control.runStatus({ runId: RUN_ID });
  assert.deepEqual(pendingStatus.pendingInput, {
    id: "request-1",
    kind: "clarification",
    questions: [{ id: "q1", question: "Choose?", options: ["A", "B"] }],
    rationale: "Required for scope.",
    artifactPath: pendingEdit.transcriptPath,
    revision: 1,
  });
  assert.deepEqual(pendingStatus.pause.nextActions, [
    { type: "respond", requestId: "request-1" },
  ]);

  assert.deepEqual(await control.runRespond(input), {
    runId: RUN_ID,
    requestId: "request-1",
  });
  assert.deepEqual(await control.runRespond(input), {
    runId: RUN_ID,
    requestId: "request-1",
  });
  assert.deepEqual(launches, [RUN_ID]);
  const status = await control.runStatus({ runId: RUN_ID });
  assert.equal(status.pendingInput, null);
  assert.equal(status.revision, 5);
  assert.equal(
    (
      await control.runWait({
        runId: RUN_ID,
        cursor: status.revision,
        timeoutMs: 10,
        progress: false,
      })
    ).timedOut,
    true,
  );
  await assert.rejects(
    control.runRespond({ ...input, idempotencyKey: "another-response-key" }),
    /stale/u,
  );

  const recoveredEdit = { ...pendingEdit, id: "request-2" };
  const recoveredInput = {
    ...input,
    idempotencyKey: "recovered-response-key",
    runId: SECOND_RUN_ID,
    requestId: recoveredEdit.id,
  };
  await createStoredRun(store, paths, {
    id: SECOND_RUN_ID,
    pendingEdit: recoveredEdit,
    pause: {
      reason: "clarification_answers_required",
      authorizationId: recoveredEdit.id,
      inputRequest: {
        id: recoveredEdit.id,
        kind: "clarification",
        questions: [{ id: "q1", question: "Choose?", options: [] }],
        rationale: "Required for scope.",
        artifactPath: recoveredEdit.transcriptPath,
      },
    },
    workflowState: "WAITING_FOR_USER",
  });
  const { idempotencyKey: recoveredKey, ...recoveredArguments } =
    recoveredInput;
  const intent = await store.beginAction({
    key: recoveredKey,
    tool: "run_respond",
    arguments: recoveredArguments,
    context: {
      runId: SECOND_RUN_ID,
      requestId: recoveredEdit.id,
      expectedRevision: 1,
      responseHash: RESPONSE_HASH,
      submittedRevision: null,
    },
  });
  await runner.submitInput({
    ...recoveredArguments,
    responseHash: RESPONSE_HASH,
  });
  await intent.release();

  assert.deepEqual(await control.runRespond(recoveredInput), {
    runId: SECOND_RUN_ID,
    requestId: recoveredEdit.id,
  });
  assert.deepEqual(launches, [RUN_ID, SECOND_RUN_ID]);
  assert.equal(
    (
      await store.readAction({
        key: recoveredKey,
        tool: "run_respond",
        arguments: recoveredArguments,
      })
    ).status,
    "completed",
  );
});

test("responds to pending input projected from a compatible legacy run", async (t) => {
  const paths = await workspace(t, "agent-runner-mcp-legacy-respond-");
  await executeFile("git", ["init", "-q", paths.projectPath]);
  await writeFile(
    join(paths.taskPath, "task.md"),
    "Implement the requested behavior.\n",
  );
  const store = createRunStore({ stateRoot: paths.stateRoot });
  const runner = createRunner({
    adapters: { codex: questioningAdapter() },
    clarifications: createClarificationService({ interactive: false }),
    loadConfiguration: async () =>
      parseRunnerConfiguration(
        JSON.stringify({ schemaVersion: 1, defaultBackend: "codex" }),
      ),
    runStore: store,
  });
  const paused = await runner.run({
    pipelineId: "plan-authoring",
    projectPath: paths.projectPath,
    taskPath: paths.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  });
  await rewriteRunAsLegacy(paused.directoryPath);

  const launches = [];
  const control = createMcpControlPlane({
    async launchRun(id, _action, options) {
      launches.push(id);
      await advanceMutatingStoredRun(store, id, options.dispatch);
    },
    runner,
    runStore: store,
  });
  const pendingInput = (
    await control.runStatus({
      runId: paused.run.runId,
    })
  ).pendingInput;
  const input = {
    idempotencyKey: "legacy-response-key",
    runId: paused.run.runId,
    requestId: pendingInput.id,
    expectedRevision: pendingInput.revision,
    answers: [
      {
        questionId: pendingInput.questions[0].id,
        answer: "Use behavior A exactly.",
      },
    ],
  };

  assert.deepEqual(await control.runRespond(input), {
    runId: paused.run.runId,
    requestId: pendingInput.id,
  });
  assert.deepEqual(launches, [paused.run.runId]);
  const persisted = await store.loadRun(paused.run.runId);
  assert.equal(persisted.schemaVersion, RUN_STATE_SCHEMA_VERSION);
  assert.equal(persisted.revision, paused.run.revision + 5);
  assert.equal(persisted.pause.inputResponse.requestId, pendingInput.id);
});

test("resumes only action-free ownerless interrupted runs at the exact revision", async (t) => {
  const paths = await workspace(t, "agent-runner-mcp-interrupted-resume-");
  const store = createRunStore({ stateRoot: paths.stateRoot });
  await createStoredRun(store, paths);
  const turn = { role: "planner", phase: "clarify" };
  const lease = await store.acquireRunLease(RUN_ID);
  const started = await store.startAgentTurn(lease, turn, {
    activity: {
      actor: turn.role,
      phase: turn.phase,
      kind: "turn-started",
      message: "planner clarify turn started.",
    },
  });
  await lease.release();

  const launches = [];
  const control = createMcpControlPlane({
    async launchRun(id, action, options) {
      launches.push({ action, id });
      await advanceMutatingStoredRun(store, id, options.dispatch);
    },
    runner: storedRunner(store, paths),
    runStore: store,
  });
  await assert.rejects(
    control.runResume({
      idempotencyKey: "interrupted-action",
      runId: RUN_ID,
      expectedRevision: started.revision,
      action: { type: "extra-fix-rounds", amount: 1 },
    }),
    /only an action-free resume/u,
  );
  await assert.rejects(
    control.runResume({
      idempotencyKey: "interrupted-stale-revision",
      runId: RUN_ID,
      expectedRevision: started.revision - 1,
      action: null,
    }),
    /revision is stale/u,
  );
  const input = {
    idempotencyKey: "interrupted-resume",
    runId: RUN_ID,
    expectedRevision: started.revision,
    action: null,
  };
  assert.deepEqual(await control.runResume(input), { runId: RUN_ID });
  assert.deepEqual(await control.runResume(input), { runId: RUN_ID });
  assert.deepEqual(launches, [{ action: null, id: RUN_ID }]);

  await createStoredRun(store, paths, { id: SECOND_RUN_ID });
  const ownedLease = await store.acquireRunLease(SECOND_RUN_ID);
  t.after(() => ownedLease.release().catch(() => {}));
  const owned = await store.startAgentTurn(ownedLease, turn, {
    activity: {
      actor: turn.role,
      phase: turn.phase,
      kind: "turn-started",
      message: "planner clarify turn started.",
    },
  });
  await assert.rejects(
    control.runResume({
      idempotencyKey: "interrupted-concurrent-owner",
      runId: SECOND_RUN_ID,
      expectedRevision: owned.revision,
      action: null,
    }),
    (error) => error.code === "ERR_RUN_LEASED",
  );
  assert.equal(launches.length, 1);
  // A crash after dispatch readiness can precede the first turn marker.
  await createStoredRun(store, paths, { id: THIRD_RUN_ID });
  assert.deepEqual(
    await control.runResume({
      ...input,
      runId: THIRD_RUN_ID,
      expectedRevision: 1,
      idempotencyKey: "checkpoint-before-turn",
    }),
    { runId: THIRD_RUN_ID },
  );
  assert.equal(launches.length, 2);
});

test("action-free resume immediately reclaims an exact dead owner", async (t) => {
  const paths = await workspace(t, "agent-runner-mcp-dead-owner-resume-");
  const bootId = "44444444-4444-4444-8444-444444444444";
  const storeOptions = {
    stateRoot: paths.stateRoot,
    hostName: "test-host",
    processIsAlive: (pid) => pid !== 100,
    processIdentity: (pid) => ({ bootId, startTicks: String(pid) }),
  };
  const ownerStore = createRunStore({ ...storeOptions, processId: 100 });
  await createStoredRun(ownerStore, paths);
  const ownerLease = await ownerStore.acquireRunLease(RUN_ID);
  const started = await ownerStore.startAgentTurn(
    ownerLease,
    { role: "planner", phase: "clarify" },
    {
      activity: {
        actor: "planner",
        phase: "clarify",
        kind: "turn-started",
        message: "planner clarify turn started.",
      },
    },
  );

  const recoveryStore = createRunStore({ ...storeOptions, processId: 200 });
  let launches = 0;
  const control = createMcpControlPlane({
    async launchRun(id, _action, options) {
      launches += 1;
      await advanceMutatingStoredRun(recoveryStore, id, options.dispatch);
    },
    runner: storedRunner(recoveryStore, paths),
    runStore: recoveryStore,
  });
  assert.deepEqual(
    await control.runResume({
      idempotencyKey: "dead-owner-resume",
      runId: RUN_ID,
      expectedRevision: started.revision,
      action: null,
    }),
    { runId: RUN_ID },
  );
  assert.equal(launches, 1);
});

test("rejects a live pausing owner and permits an exact-key retry after release", async (t) => {
  const paths = await workspace(t, "agent-runner-mcp-resume-lease-");
  const store = createRunStore({ stateRoot: paths.stateRoot });
  await createStoredRun(store, paths, {
    pipelineId: "plan-execution",
    pause: { reason: "backend_unavailable" },
    workflowState: "WAITING_FOR_USER",
  });
  const lease = await store.acquireRunLease(RUN_ID);
  const worktreeLease = await store.acquireWorktreeLease(
    paths.projectPath,
    RUN_ID,
  );
  t.after(async () => {
    await worktreeLease.release();
    await lease.release();
  });

  const launches = [];
  const control = createMcpControlPlane({
    async launchRun(id, _action, options) {
      launches.push(id);
      await advanceMutatingStoredRun(store, id, options.dispatch);
    },
    runner: storedRunner(store, paths),
    runStore: store,
  });
  const input = {
    idempotencyKey: "resume-after-lease",
    runId: RUN_ID,
    expectedRevision: 1,
    action: null,
  };
  await assert.rejects(control.runResume(input), { code: "ERR_RUN_LEASED" });
  assert.deepEqual(launches, []);
  await worktreeLease.release();
  await lease.release();
  assert.deepEqual(await control.runResume(input), { runId: RUN_ID });
  assert.deepEqual(launches, [RUN_ID]);
});

test("waits by revision, emits public progress, and leaves timeouts read-only", async (t) => {
  const paths = await workspace(t, "agent-runner-mcp-wait-");
  const store = createRunStore({ stateRoot: paths.stateRoot });
  await createStoredRun(store, paths);
  const runner = storedRunner(store, paths);
  const waitStarted = Promise.withResolvers();
  const observedStore = {
    ...store,
    async waitForRunChange(...argumentsList) {
      waitStarted.resolve();
      return store.waitForRunChange(...argumentsList);
    },
  };
  const control = createMcpControlPlane({ runner, runStore: observedStore });
  const notifications = [];
  const transition = (async () => {
    await waitStarted.promise;
    const lease = await store.acquireRunLease(RUN_ID);
    try {
      const run = await store.recoverRun(lease);
      await store.transitionRun(
        lease,
        {
          pause: { reason: "input_required" },
          pipelineState: {
            ...run.pipelineState,
            workflowState: "WAITING_FOR_USER",
          },
        },
        {
          activity: {
            actor: "planner",
            phase: "clarification",
            kind: "paused",
            message: "User input is required.",
          },
        },
      );
    } finally {
      await lease.release();
    }
  })();

  const waited = await control.runWait(
    { runId: RUN_ID, cursor: 0, timeoutMs: 1_000, progress: true },
    {
      progressToken: "progress-1",
      signal: new AbortController().signal,
      async notify(notification) {
        notifications.push(notification);
      },
    },
  );
  await transition;
  assert.equal(waited.status, "WAITING_FOR_USER");
  assert.equal(waited.mode, "independent");
  assert.equal(waited.timedOut, false);
  assert.match(
    notifications.at(-1).params.message,
    /^\[planner\/clarification\]/u,
  );
  assert.equal(notifications.at(-1).params.progress, waited.revision);
  const activity = await control.runActivity({
    runId: RUN_ID,
    cursor: 0,
    limit: 50,
  });
  assert.equal(activity.cursor, 2);
  assert.equal(activity.mode, "independent");
  assert.equal(activity.activities.length, 2);
  assert.equal("pipelineState" in activity.activities[1], false);

  await createStoredRun(store, paths, { id: SECOND_RUN_ID });
  const timedOut = await control.runWait({
    runId: SECOND_RUN_ID,
    cursor: 1,
    timeoutMs: 10,
    progress: false,
  });
  assert.equal(timedOut.timedOut, true);
  assert.equal((await store.loadRun(SECOND_RUN_ID)).revision, 1);

  await createStoredRun(store, paths, {
    id: THIRD_RUN_ID,
    workflowState: "LEGACY_WAIT",
  });
  const migrationAwareRunner = {
    ...runner,
    async status(runId) {
      const current = await runner.status(runId);
      if (runId !== THIRD_RUN_ID) {
        return current;
      }
      return {
        ...current,
        run: {
          ...current.run,
          pipelineStateVersion: current.run.pipelineStateVersion + 1,
          pipelineState: {
            ...current.run.pipelineState,
            workflowState: "CLARIFY",
          },
        },
      };
    },
  };
  const migrationAwareControl = createMcpControlPlane({
    runner: migrationAwareRunner,
    runStore: store,
  });
  const migratedTimeout = await migrationAwareControl.runWait({
    runId: THIRD_RUN_ID,
    cursor: 1,
    timeoutMs: 10,
    progress: false,
  });
  assert.equal(migratedTimeout.timedOut, true);
  assert.equal(migratedTimeout.status, "CLARIFY");

  await assert.rejects(
    control.runWait({
      runId: SECOND_RUN_ID,
      cursor: 2,
      timeoutMs: 0,
      progress: false,
    }),
    /cursor is ahead/u,
  );

  const abort = new AbortController();
  const abortWaitStarted = Promise.withResolvers();
  const abortingControl = createMcpControlPlane({
    runner,
    runStore: {
      ...store,
      async waitForRunChange(...argumentsList) {
        abortWaitStarted.resolve();
        return store.waitForRunChange(...argumentsList);
      },
    },
  });
  const aborted = abortingControl.runWait(
    {
      runId: SECOND_RUN_ID,
      cursor: 1,
      timeoutMs: 1_000,
      progress: false,
    },
    { signal: abort.signal },
  );
  await abortWaitStarted.promise;
  abort.abort();
  await assert.rejects(aborted, (error) => error.name === "AbortError");
  assert.equal((await store.loadRun(SECOND_RUN_ID)).revision, 1);
});

test("projects live and crashed provider activity through status and wait", async (t) => {
  const paths = await workspace(t, "agent-runner-mcp-provider-activity-");
  const ownerProcessId = 424_242;
  let ownerIsAlive = true;
  const store = createRunStore({
    stateRoot: paths.stateRoot,
    processId: ownerProcessId,
    processIsAlive: (pid) => pid === ownerProcessId && ownerIsAlive,
    processIdentity: (pid) => ({
      bootId: "11111111-1111-4111-8111-111111111111",
      startTicks: String(pid),
    }),
  });
  await createStoredRun(store, paths);
  const lease = await store.acquireRunLease(RUN_ID);
  const turn = { role: "planner", phase: "clarify" };
  const started = await store.startAgentTurn(lease, turn, {
    activity: {
      actor: turn.role,
      phase: turn.phase,
      kind: "turn-started",
      message: "planner clarify turn started.",
    },
  });
  const registered = await store.recordExecutionProcess(lease, 4242, {
    processIdentity: {
      bootId: "11111111-1111-4111-8111-111111111111",
      startTicks: "4242",
    },
    namespaceId: "pid:[4026533000]",
    ancestryBaseline: [
      {
        bootId: "11111111-1111-4111-8111-111111111111",
        pid: 1,
        startTicks: "1",
      },
    ],
  });
  assert.deepEqual(
    registered.executionProcess.launchCutoff,
    registered.executionProcess.processIdentity,
  );
  const control = createMcpControlPlane({
    runner: storedRunner(store, paths),
    runStore: store,
  });

  const liveStatus = await control.runStatus({ runId: RUN_ID });
  assert.deepEqual(liveStatus.execution, {
    state: "running",
    leaseOwner: "live",
    processRecord: "persisted",
    role: "planner",
    phase: "clarify",
  });
  assert.doesNotMatch(
    JSON.stringify(liveStatus),
    /ancestryBaseline|bootId|launchCutoff|startTicks/u,
  );
  const waiting = await control.runWait({
    runId: RUN_ID,
    cursor: started.revision,
    timeoutMs: 10,
    progress: false,
  });
  assert.equal(waiting.timedOut, true);
  assert.deepEqual(waiting.execution, {
    state: "running",
    leaseOwner: "live",
    processRecord: "persisted",
    role: "planner",
    phase: "clarify",
  });

  ownerIsAlive = false;
  assert.equal(await store.runIsLeased(RUN_ID), true);
  assert.equal(await store.runLeaseOwnerIsLive(RUN_ID), false);
  const leaseRecord = JSON.parse(
    await readFile(join(await store.getRunDirectory(RUN_ID), ".lease"), "utf8"),
  );
  assert.equal(leaseRecord.pid, ownerProcessId);
  const interruptedWait = await control.runWait({
    runId: RUN_ID,
    cursor: started.revision,
    timeoutMs: 10,
    progress: false,
  });
  assert.equal(interruptedWait.timedOut, true);
  assert.deepEqual(interruptedWait.execution, {
    state: "interrupted",
    leaseOwner: "dead",
    processRecord: "persisted",
    role: "planner",
    phase: "clarify",
  });

  await store.recordExecutionProcess(lease, null);
  await lease.release();
  ownerIsAlive = true;
  const resumedLease = await store.acquireRunLease(RUN_ID);
  await store.recoverRun(resumedLease);
  await store.finishAgentTurn(resumedLease, turn);
  await resumedLease.release();
  assert.deepEqual((await control.runStatus({ runId: RUN_ID })).execution, {
    state: "idle",
    leaseOwner: "none",
    processRecord: "none",
    role: null,
    phase: null,
  });
});
