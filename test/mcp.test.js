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
  createDetachedLauncher,
  createGitService,
  createMcpControlPlane,
  createRunner,
  createRunStore,
  DETACHED_RUNTIME_COMPATIBILITY_ENV,
  MCP_INSTRUCTIONS,
  parseRunnerConfiguration,
  RUNTIME_COMPATIBILITY_TOKEN,
  RUNTIME_VERSION_SKEW_EXIT_CODE,
  RUN_STATE_SCHEMA_VERSION,
} from "../src/index.js";

const RUN_ID = "11111111-1111-4111-8111-111111111111";
const SECOND_RUN_ID = "22222222-2222-4222-8222-222222222222";
const THIRD_RUN_ID = "33333333-3333-4333-8333-333333333333";
const FOURTH_RUN_ID = "44444444-4444-4444-8444-444444444444";
const FIFTH_RUN_ID = "55555555-5555-4555-8555-555555555555";
const SIXTH_RUN_ID = "66666666-6666-4666-8666-666666666666";
const SEVENTH_RUN_ID = "77777777-7777-4777-8777-777777777777";
const RESPONSE_HASH = "a".repeat(64);
const executeFile = promisify(execFile);

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

async function advanceMutatingStoredRun(store, runId) {
  const lease = await store.acquireRunLease(runId);
  try {
    await store.recoverRun(lease);
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
      ...state,
    },
  });
  await created.lease.release();
  return created.state;
}

function storedRunner(store, paths) {
  return {
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

test("serves protocol-clean STDIO discovery through the official SDK", async (t) => {
  if (!(await childNodeStdoutIsAvailable())) {
    t.skip("Nested Node stdout is unavailable in this environment.");
    return;
  }
  const paths = await workspace(t, "agent-runner-mcp-protocol-");
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: ["bin/agent-run.js", "mcp"],
    cwd: new URL("..", import.meta.url).pathname,
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
    /Primary and review roles fork the complete source context independently/u,
  );
  assert.match(
    MCP_INSTRUCTIONS,
    /fresh start for a long, multi-topic, or uncertain source session/u,
  );
  const { tools } = await client.listTools();
  assert.deepEqual(
    tools.map((tool) => tool.name).sort(),
    [
      "pipelines_list",
      "run_activity",
      "run_respond",
      "run_resume",
      "run_start",
      "run_status",
      "run_wait",
      "unexpected_issue_report",
    ],
  );
  assert.equal(
    tools.find((tool) => tool.name === "run_status").annotations.readOnlyHint,
    true,
  );
  assert.equal(
    tools.find((tool) => tool.name === "run_start").annotations.destructiveHint,
    true,
  );
  const startTool = tools.find((tool) => tool.name === "run_start");
  assert.match(startTool.description, /user deliberately selects/u);
  assert.match(
    startTool.description,
    /recommend fresh for a long, multi-topic, or uncertain session/u,
  );
  assert.doesNotMatch(startTool.description, /by default/u);
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
  if (!(await childNodeStdoutIsAvailable())) {
    t.skip("Nested Node stdout is unavailable in this environment.");
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
    cwd: new URL("..", import.meta.url).pathname,
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
    roleOverrides: {},
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
      roleOverrides: {},
      sourceSession: null,
    },
    context: { runId: RUN_ID },
  });
  await runner.create(input, { runId: RUN_ID });
  await intent.release();
  const control = createMcpControlPlane({
    async launchRun(id, _action, options) {
      launches.push({ id, options });
      await advanceMutatingStoredRun(store, id);
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
    RUNTIME_COMPATIBILITY_TOKEN,
  );
  await assert.rejects(
    control.runStart({ ...input, pipelineId: "plan-execution" }),
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
    async launchRun(id) {
      launches.push(id);
      await advanceMutatingStoredRun(store, id);
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

test("surfaces detached child runtime skew without changing the durable run", async (t) => {
  const paths = await workspace(t, "agent-runner-mcp-runtime-skew-");
  const store = createRunStore({ stateRoot: paths.stateRoot });
  const runner = storedRunner(store, paths);
  const control = createMcpControlPlane({
    launchRun(_id, _action, { onExit }) {
      queueMicrotask(() => onExit(RUNTIME_VERSION_SKEW_EXIT_CODE));
    },
    runIdFactory: () => RUN_ID,
    runner,
    runStore: store,
  });

  await assert.rejects(
    control.runStart({
      idempotencyKey: "runtime-skew-start",
      pipelineId: "plan-execution",
      projectPath: paths.projectPath,
      taskPath: paths.taskPath,
      proactiveClarification: false,
      roleOverrides: {},
      sourceSession: null,
    }),
    (error) =>
      error.code === "ERR_RUNTIME_VERSION_SKEW" &&
      /restart the Agent Runner MCP server/u.test(error.message),
  );
  assert.equal((await store.loadRun(RUN_ID)).revision, 1);
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
    launchRun(id) {
      launches += 1;
      launchStarted.resolve();
      void (async () => {
        await acquireChild.promise;
        const childLease = await store.acquireRunLease(id);
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
  assert.equal((await store.loadRun(RUN_ID)).revision, 1);
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

  function launchRun(runId) {
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
        if (runId === RUN_ID) {
          await firstChildrenStarted.promise;
          worktreeLease = await store.acquireWorktreeLease(
            paths.projectPath,
            runId,
          );
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
    async launchRun(runId, _action, { onExit } = {}) {
      launches.push(runId);
      if (launches.length > 1) {
        await advanceMutatingStoredRun(store, runId);
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

test("forwards additive run-wide, role, and source profile selections", async (t) => {
  const paths = await workspace(t, "agent-runner-mcp-preferences-");
  const store = createRunStore({ stateRoot: paths.stateRoot });
  const baseRunner = storedRunner(store, paths);
  let createdInput;
  const control = createMcpControlPlane({
    launchRun(id) {
      return advanceMutatingStoredRun(store, id);
    },
    runIdFactory: () => RUN_ID,
    runner: {
      ...baseRunner,
      async create(input, options) {
        createdInput = input;
        return baseRunner.create(input, options);
      },
    },
    runStore: store,
  });
  const input = {
    idempotencyKey: "preference-start",
    pipelineId: "plan-authoring",
    projectPath: paths.projectPath,
    projectConfigurationPath: join(paths.projectPath, "ignored", "runner.json"),
    taskPath: paths.taskPath,
    proactiveClarification: false,
    profile: "claude-primary",
    model: "sonnet",
    contextSize: "200000",
    roleOverrides: {
      planner: {
        profile: "claude-primary",
        model: "opus",
        contextSize: "300000",
      },
    },
    sourceSession: {
      backend: "claude",
      id: "opaque:source:id",
      profile: "claude-primary",
    },
  };

  assert.deepEqual(await control.runStart(input), { runId: RUN_ID });
  assert.deepEqual(createdInput, {
    pipelineId: "plan-authoring",
    projectPath: paths.projectPath,
    projectConfigurationPath: input.projectConfigurationPath,
    taskPath: paths.taskPath,
    proactiveClarification: false,
    roleOverrides: input.roleOverrides,
    sourceSession: input.sourceSession,
    executionOverrides: {
      profile: "claude-primary",
      model: "sonnet",
      contextSize: "200000",
    },
  });
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
        questions: [
          { id: "q1", question: "Choose?", options: ["A", "B"] },
        ],
        rationale: "Required for scope.",
        artifactPath: pendingEdit.transcriptPath,
      },
    },
    workflowState: "WAITING_FOR_USER",
  });
  const runner = storedRunner(store, paths);
  const launches = [];
  const control = createMcpControlPlane({
    async launchRun(id) {
      launches.push(id);
      await advanceMutatingStoredRun(store, id);
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
  assert.equal(status.revision, 3);
  assert.equal(
    (await control.runWait({
      runId: RUN_ID,
      cursor: 3,
      timeoutMs: 10,
      progress: false,
    })).timedOut,
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
  const {
    idempotencyKey: recoveredKey,
    ...recoveredArguments
  } = recoveredInput;
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
    (await store.readAction({
      key: recoveredKey,
      tool: "run_respond",
      arguments: recoveredArguments,
    })).status,
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
    async launchRun(id) {
      launches.push(id);
      await advanceMutatingStoredRun(store, id);
    },
    runner,
    runStore: store,
  });
  const pendingInput = (await control.runStatus({
    runId: paused.run.runId,
  })).pendingInput;
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
  assert.equal(persisted.revision, paused.run.revision + 3);
  assert.equal(persisted.pause.inputResponse.requestId, pendingInput.id);
});

test("resumes only an action valid for the persisted pause", async (t) => {
  const paths = await workspace(t, "agent-runner-mcp-resume-");
  const store = createRunStore({ stateRoot: paths.stateRoot });
  const pendingEdit = {
    schemaVersion: 1,
    id: "resume-request",
    artifactRoot: paths.taskPath,
    transcriptPath: join(paths.taskPath, "clarifications.md"),
    suspendedState: "CLARIFY",
    action: "proactive-clarification",
    preEditorHash: "c".repeat(64),
  };
  await createStoredRun(store, paths, {
    pendingEdit,
    pause: {
      reason: "proactive_clarification",
      authorizationId: pendingEdit.id,
    },
    workflowState: "WAITING_FOR_USER",
  });
  const launches = [];
  const control = createMcpControlPlane({
    async launchRun(id, action) {
      launches.push({ action, id });
      await advanceMutatingStoredRun(store, id);
    },
    runner: storedRunner(store, paths),
    runStore: store,
  });
  const input = {
    idempotencyKey: "resume-key",
    runId: RUN_ID,
    expectedRevision: 1,
    action: null,
  };

  assert.deepEqual(await control.runResume(input), { runId: RUN_ID });
  assert.deepEqual(await control.runResume(input), { runId: RUN_ID });
  assert.deepEqual(launches, [{ action: null, id: RUN_ID }]);

  await createStoredRun(store, paths, {
    id: FOURTH_RUN_ID,
    pipelineId: "plan-execution",
    pause: { reason: "fix_limit_reached", resumeState: "IMPLEMENT" },
    state: {
      additionalFixRounds: 0,
      settings: { maxFixRoundsPerStep: 15 },
    },
    workflowState: "WAITING_FOR_USER",
  });
  const extraFixAction = { type: "extra-fix-rounds", amount: 2 };
  assert.deepEqual(
    await control.runResume({
      ...input,
      idempotencyKey: "valid-fix-budget",
      runId: FOURTH_RUN_ID,
      action: extraFixAction,
    }),
    { runId: FOURTH_RUN_ID },
  );
  assert.deepEqual(launches.at(-1), {
    action: extraFixAction,
    id: FOURTH_RUN_ID,
  });
  await createStoredRun(store, paths, {
    id: FIFTH_RUN_ID,
    pipelineId: "polishing",
    pause: { reason: "fix_limit_reached", resumeState: "POLISH" },
    state: {
      additionalFixRounds: 0,
      finalizationResult: { status: "PASS" },
      findings: [{ id: "R1", problem: "Review is incomplete." }],
      reviewedFingerprint: "a".repeat(64),
      settings: { maxFixRounds: 5 },
    },
    workflowState: "WAITING_FOR_USER",
  });
  assert.deepEqual(
    await control.runStatus({ runId: FIFTH_RUN_ID }),
    {
      runId: FIFTH_RUN_ID,
      pipelineId: "polishing",
      revision: 1,
      activityCursor: 1,
      status: "WAITING_FOR_USER",
      execution: { state: "idle", role: null, phase: null },
      currentStep: null,
      pause: {
        reason: "fix_limit_reached",
        code: null,
        explanation: "Polishing reached its configured fix limit.",
        evidence: [],
        resumeState: "POLISH",
        nextActions: [
          {
            type: "resume",
            action: { type: "extra-fix-rounds", amount: 1 },
          },
          {
            type: "resume",
            action: { type: "override-finding", findingId: "R1" },
          },
        ],
      },
      clarificationPath: null,
      planPath: null,
      pendingInput: null,
      findings: [{ id: "R1", summary: "Review is incomplete." }],
      completedCommits: [],
      stagnationDirection: null,
      finalizedFingerprint: null,
      reviewedFingerprint: "a".repeat(12),
      stateDirectory: await store.getRunDirectory(FIFTH_RUN_ID),
    },
  );
  assert.deepEqual(
    await control.runResume({
      ...input,
      idempotencyKey: "valid-polishing-fix-budget",
      runId: FIFTH_RUN_ID,
      action: extraFixAction,
    }),
    { runId: FIFTH_RUN_ID },
  );
  assert.deepEqual(launches.at(-1), {
    action: extraFixAction,
    id: FIFTH_RUN_ID,
  });
  for (const [runId, reason] of [
    [SIXTH_RUN_ID, "local_artifacts_not_ignored"],
    [SEVENTH_RUN_ID, "unsafe_git_state"],
  ]) {
    await createStoredRun(store, paths, {
      id: runId,
      pipelineId: "polishing",
      pause: { reason },
      state: { preflightComplete: false },
      workflowState: "WAITING_FOR_USER",
    });
    assert.deepEqual(
      await control.runResume({
        ...input,
        idempotencyKey: `retry-${reason}`,
        runId,
      }),
      { runId },
    );
    assert.deepEqual(launches.at(-1), { action: null, id: runId });
  }
  await assert.rejects(
    control.runResume({
      ...input,
      idempotencyKey: "invalid-resume-key",
      expectedRevision: 2,
      action: { type: "extra-fix-rounds", amount: 1 },
    }),
    /not valid for this paused run/u,
  );

  await createStoredRun(store, paths, {
    id: THIRD_RUN_ID,
    pipelineId: "plan-execution",
    pause: { reason: "fix_limit_reached", resumeState: "IMPLEMENT" },
    state: {
      additionalFixRounds: Number.MAX_SAFE_INTEGER,
      settings: { maxFixRoundsPerStep: 15 },
    },
    workflowState: "WAITING_FOR_USER",
  });
  await assert.rejects(
    control.runResume({
      ...input,
      idempotencyKey: "overflowing-fix-budget",
      runId: THIRD_RUN_ID,
      action: { type: "extra-fix-rounds", amount: 1 },
    }),
    /not applicable/u,
  );

  await createStoredRun(store, paths, {
    id: SECOND_RUN_ID,
    pipelineId: "plan-execution",
    pause: { reason: "commit_failed" },
    workflowState: "WAITING_FOR_USER",
  });
  await assert.rejects(
    control.runResume({
      ...input,
      idempotencyKey: "invalid-commit-retry",
      runId: SECOND_RUN_ID,
    }),
    /not valid for this paused run/u,
  );
});

test("projects the same bounded pause through MCP status and wait", async (t) => {
  const paths = await workspace(t, "agent-runner-mcp-pause-");
  const store = createRunStore({ stateRoot: paths.stateRoot });
  await createStoredRun(store, paths, {
    pipelineId: "plan-execution",
    pause: {
      reason: "environment_blocked",
      code: "ERR_LOOPBACK_UNAVAILABLE",
      explanation: "Check C2 cannot bind a loopback listener.",
      evidence: ["C2: listener creation was denied."],
      resumeState: "IMPLEMENT",
      prompt: "private prompt",
      transcript: "private transcript",
      credentials: "private credentials",
      nativeResponse: "private native response",
      rawStderr: "private stderr",
    },
    state: { findings: [], preflightComplete: true },
    workflowState: "WAITING_FOR_USER",
  });
  const control = createMcpControlPlane({
    runner: storedRunner(store, paths),
    runStore: store,
  });
  const expectedPause = {
    reason: "environment_blocked",
    code: "ERR_LOOPBACK_UNAVAILABLE",
    explanation: "Check C2 cannot bind a loopback listener.",
    evidence: ["C2: listener creation was denied."],
    resumeState: "IMPLEMENT",
    nextActions: [{ type: "resume", action: null }],
  };

  const status = await control.runStatus({ runId: RUN_ID });
  const waited = await control.runWait({
    runId: RUN_ID,
    cursor: 0,
    timeoutMs: 0,
    progress: false,
  });

  assert.deepEqual(status.pause, expectedPause);
  assert.deepEqual(waited.pause, expectedPause);
  assert.equal(waited.timedOut, false);
  const serialized = JSON.stringify({ status, waited });
  assert.doesNotMatch(
    serialized,
    /private prompt|private transcript|private credentials|private native response|private stderr/u,
  );

  await createStoredRun(store, paths, {
    id: SECOND_RUN_ID,
    pipelineId: "plan-execution",
    pause: {
      reason: "plan_revision_required",
      explanation: "The accepted clarification conflicts with Commit 2.",
      evidence: ["The plan requires the opposite behavior."],
    },
    workflowState: "WAITING_FOR_USER",
  });
  await createStoredRun(store, paths, {
    id: THIRD_RUN_ID,
    pipelineId: "polishing",
    pause: {
      reason: "read_only_agent_mutated_repository",
      code: "ERR_READ_ONLY_REPOSITORY_CHANGED",
    },
    workflowState: "WAITING_FOR_USER",
  });
  assert.deepEqual(
    (await control.runStatus({ runId: SECOND_RUN_ID })).pause.nextActions,
    [{ type: "start-new-run", requirement: "revised-plan" }],
  );
  const contaminated = await control.runStatus({ runId: THIRD_RUN_ID });
  assert.match(contaminated.pause.explanation, /abandon this run/u);
  assert.deepEqual(contaminated.pause.nextActions, [
    { type: "start-new-run", requirement: "uncontaminated-worktree" },
  ]);
});

test("waits for a pausing owner to release its lease before resuming", async (t) => {
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

  let observeLease;
  const leaseObserved = new Promise((resolvePromise) => {
    observeLease = resolvePromise;
  });
  const launches = [];
  const control = createMcpControlPlane({
    async launchRun(id) {
      launches.push(id);
      await advanceMutatingStoredRun(store, id);
    },
    runner: storedRunner(store, paths),
    runStore: {
      ...store,
      async runIsLeased(id) {
        const leased = await store.runIsLeased(id);
        if (leased) {
          observeLease();
        }
        return leased;
      },
    },
  });
  const resuming = control.runResume({
    idempotencyKey: "resume-after-lease",
    runId: RUN_ID,
    expectedRevision: 1,
    action: null,
  });

  await leaseObserved;
  assert.deepEqual(launches, []);
  await worktreeLease.release();
  await lease.release();
  assert.deepEqual(await resuming, { runId: RUN_ID });
  assert.deepEqual(launches, [RUN_ID]);
});

test("waits by revision, emits public progress, and leaves timeouts read-only", async (t) => {
  const paths = await workspace(t, "agent-runner-mcp-wait-");
  const store = createRunStore({ stateRoot: paths.stateRoot });
  await createStoredRun(store, paths);
  const runner = storedRunner(store, paths);
  const control = createMcpControlPlane({ runner, runStore: store });
  const notifications = [];
  const transition = (async () => {
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 20));
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
  assert.equal(waited.timedOut, false);
  assert.match(notifications.at(-1).params.message, /^\[planner\/clarification\]/u);
  assert.equal(notifications.at(-1).params.progress, waited.revision);
  const activity = await control.runActivity({
    runId: RUN_ID,
    cursor: 0,
    limit: 50,
  });
  assert.equal(activity.cursor, 2);
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
  setTimeout(() => abort.abort(), 10);
  await assert.rejects(
    control.runWait(
      {
        runId: SECOND_RUN_ID,
        cursor: 1,
        timeoutMs: 1_000,
        progress: false,
      },
      { signal: abort.signal },
    ),
    (error) => error.name === "AbortError",
  );
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
  const control = createMcpControlPlane({
    runner: storedRunner(store, paths),
    runStore: store,
  });

  assert.deepEqual((await control.runStatus({ runId: RUN_ID })).execution, {
    state: "running",
    role: "planner",
    phase: "clarify",
  });
  const waiting = await control.runWait({
    runId: RUN_ID,
    cursor: started.revision,
    timeoutMs: 10,
    progress: false,
  });
  assert.equal(waiting.timedOut, true);
  assert.deepEqual(waiting.execution, {
    state: "running",
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
    role: "planner",
    phase: "clarify",
  });

  await lease.release();
  ownerIsAlive = true;
  const resumedLease = await store.acquireRunLease(RUN_ID);
  await store.recoverRun(resumedLease);
  await store.finishAgentTurn(resumedLease, turn);
  await resumedLease.release();
  assert.deepEqual((await control.runStatus({ runId: RUN_ID })).execution, {
    state: "idle",
    role: null,
    phase: null,
  });
});

test("launches continuation independently from the MCP process streams", async () => {
  const calls = [];
  const exitCallbacks = [];
  let unreferenced = false;
  const launch = createDetachedLauncher({
    environment: { XDG_STATE_HOME: "/state" },
    executablePath: "/agent-run",
    spawnProcess(command, args, options) {
      calls.push({ command, args, options });
      return {
        pid: 42,
        once(event, callback) {
          if (event === "spawn") {
            queueMicrotask(callback);
          } else if (event === "exit") {
            exitCallbacks.push(callback);
          }
        },
        unref() {
          unreferenced = true;
        },
      };
    },
  });

  let exited = false;
  assert.equal(
    await launch(RUN_ID, null, {
      onExit() {
        exited = true;
      },
    }),
    42,
  );
  exitCallbacks[0]();
  assert.equal(exited, true);
  await launch(RUN_ID, { type: "extra-fix-rounds", amount: 2 });
  await launch(RUN_ID, { type: "override-finding", findingId: "finding-1" });
  assert.equal(unreferenced, true);
  assert.deepEqual(calls[0].args, ["/agent-run", "resume", "--run", RUN_ID]);
  assert.deepEqual(calls[1].args, [
    "/agent-run",
    "resume",
    "--run",
    RUN_ID,
    "--extra-fix-rounds",
    "2",
  ]);
  assert.deepEqual(calls[2].args, [
    "/agent-run",
    "resume",
    "--run",
    RUN_ID,
    "--override-finding",
    "finding-1",
  ]);
  assert.equal(calls[0].options.detached, true);
  assert.equal(calls[0].options.stdio, "ignore");
  assert.deepEqual(calls[0].options.env, {
    XDG_STATE_HOME: "/state",
    [DETACHED_RUNTIME_COMPATIBILITY_ENV]: RUNTIME_COMPATIBILITY_TOKEN,
  });
  await assert.rejects(
    launch(RUN_ID, null, { expectedRuntimeCompatibility: "other" }),
    (error) => error.code === "ERR_RUNTIME_VERSION_SKEW",
  );
});

test("rejects an unsafe state root before persisting an action intent", async (t) => {
  const paths = await workspace(t, "agent-runner-mcp-boundary-");
  const stateRoot = join(paths.projectPath, "state");
  const store = createRunStore({ stateRoot });
  const control = createMcpControlPlane({
    runner: storedRunner(store, paths),
    runStore: store,
  });

  await assert.rejects(
    control.runStart({
      idempotencyKey: "unsafe-start",
      pipelineId: "plan-authoring",
      projectPath: paths.projectPath,
      taskPath: paths.taskPath,
      proactiveClarification: false,
      roleOverrides: {},
      sourceSession: null,
    }),
    (error) => error.code === "ERR_UNSAFE_STATE_ROOT",
  );
  await assert.rejects(mkdir(join(stateRoot, "actions")), /ENOENT/u);
});

test("rejects a missing resume run before persisting an action intent", async (t) => {
  const paths = await workspace(t, "agent-runner-mcp-missing-run-");
  const store = createRunStore({ stateRoot: paths.stateRoot });
  const control = createMcpControlPlane({
    runner: storedRunner(store, paths),
    runStore: store,
  });

  await assert.rejects(
    control.runResume({
      idempotencyKey: "missing-run",
      runId: RUN_ID,
      expectedRevision: 1,
      action: null,
    }),
    (error) => error.code === "ERR_RUN_NOT_FOUND",
  );
  await assert.rejects(mkdir(join(paths.stateRoot, "actions")), /ENOENT/u);
});
