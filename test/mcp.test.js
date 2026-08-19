import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";

import {
  createDetachedLauncher,
  createMcpControlPlane,
  createRunStore,
  MCP_INSTRUCTIONS,
} from "../src/index.js";

const RUN_ID = "11111111-1111-4111-8111-111111111111";
const SECOND_RUN_ID = "22222222-2222-4222-8222-222222222222";
const THIRD_RUN_ID = "33333333-3333-4333-8333-333333333333";
const FOURTH_RUN_ID = "44444444-4444-4444-8444-444444444444";
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

async function createStoredRun(
  store,
  { projectPath, taskPath },
  {
    id = RUN_ID,
    pipelineId = "plan-authoring",
    workflowState = "CLARIFY",
    pendingEdit = null,
    pause = null,
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
    sourceSession: null,
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
        { id: runId, pipelineId: input.pipelineId },
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
  const pipelines = await client.callTool({
    name: "pipelines_list",
    arguments: {},
  });
  assert.deepEqual(
    pipelines.structuredContent.pipelines.map(({ id }) => id),
    ["plan-authoring", "plan-execution"],
  );
  const invalid = await client.callTool({
    name: "run_status",
    arguments: { runId: "not-a-run-id" },
  });
  assert.equal(invalid.isError, true);

  await client.close();
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
    launchRun(id) {
      launches.push(id);
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
  assert.deepEqual(launches, [RUN_ID]);
  await assert.rejects(
    control.runStart({ ...input, pipelineId: "plan-execution" }),
    (error) => error.code === "ERR_MCP_IDEMPOTENCY_CONFLICT",
  );
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
    launchRun(id) {
      launches.push(id);
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

  assert.deepEqual((await control.runStatus({ runId: RUN_ID })).pendingInput, {
    id: "request-1",
    kind: "clarification",
    questions: [{ id: "q1", question: "Choose?", options: ["A", "B"] }],
    rationale: "Required for scope.",
    artifactPath: pendingEdit.transcriptPath,
    revision: 1,
  });

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
  assert.equal(status.revision, 2);
  assert.equal(
    (await control.runWait({
      runId: RUN_ID,
      cursor: 2,
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
    launchRun(id, action) {
      launches.push({ action, id });
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
  await assert.rejects(
    control.runResume({
      ...input,
      idempotencyKey: "invalid-resume-key",
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

test("waits for a pausing owner to release its lease before resuming", async (t) => {
  const paths = await workspace(t, "agent-runner-mcp-resume-lease-");
  const store = createRunStore({ stateRoot: paths.stateRoot });
  await createStoredRun(store, paths, {
    pipelineId: "plan-execution",
    pause: { reason: "backend_unavailable" },
    workflowState: "WAITING_FOR_USER",
  });
  const lease = await store.acquireRunLease(RUN_ID);
  t.after(() => lease.release());

  let observeLease;
  const leaseObserved = new Promise((resolvePromise) => {
    observeLease = resolvePromise;
  });
  const launches = [];
  const control = createMcpControlPlane({
    launchRun(id) {
      launches.push(id);
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

test("launches continuation independently from the MCP process streams", async () => {
  const calls = [];
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
          }
        },
        unref() {
          unreferenced = true;
        },
      };
    },
  });

  assert.equal(await launch(RUN_ID), 42);
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
