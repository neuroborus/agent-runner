import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import test from "node:test";

import { Client, InMemoryTransport } from "@modelcontextprotocol/client";

import {
  DETACHED_RUNTIME_COMPATIBILITY_TOKEN,
  RUNTIME_VERSION_SKEW_EXIT_CODE,
} from "../../src/index.js";
import {
  createDetachedLauncher,
  createMcpControlPlane,
  createMcpServer,
  DETACHED_RUNTIME_COMPATIBILITY_ENV,
  DETACHED_STOP_CHECKPOINT_ENV,
  MCP_INSTRUCTIONS,
} from "../../src/mcp/index.js";

const RUN_ID = "11111111-1111-4111-8111-111111111111";

test("status and wait expose bounded observation evidence without private run or session data", async () => {
  const run = {
    runId: RUN_ID,
    revision: 5,
    pipelineId: "plan-execution",
    taskPath: "/task",
    activeTurn: null,
    executionProcess: null,
    pause: null,
    providerMessage: "private arbitrary error",
    sessionId: "private-native-id",
    pipelineState: {
      workflowState: "DONE",
      settings: { mode: "combined" },
      currentStep: null,
      findings: [],
      findingOverrides: [],
      completedCommits: [],
    },
    observations: {
      schemaVersion: 1,
      omittedAttempts: 2,
      attempts: [
        {
          id: 3,
          role: "worker",
          checkpoint: "implement:workspace-write:1",
          status: "failed",
          accounting: "incomplete",
          incomplete: false,
          observations: [],
          prompt: "private prompt",
          transcript: "private transcript",
        },
      ],
    },
  };
  const control = createMcpControlPlane({
    runner: { status: async () => ({ run, directoryPath: "/state/run" }) },
    runStore: { inspectRunLeaseOwner: async () => ({ status: "none" }) },
  });
  const status = await control.runStatus({ runId: RUN_ID });
  assert.deepEqual(status.observations, {
    omittedAttempts: 2,
    attempts: [
      {
        id: 3,
        role: "worker",
        checkpoint: "implement:workspace-write:1",
        status: "failed",
        accounting: "incomplete",
        incomplete: false,
        measurements: null,
        observations: [],
      },
    ],
  });
  assert.doesNotMatch(
    JSON.stringify(status),
    /private|sessionId|transcript|providerMessage/u,
  );
  const waited = await control.runWait({
    runId: RUN_ID,
    cursor: 5,
    timeoutMs: 0,
  });
  assert.deepEqual(waited.observations, status.observations);
});

test("action acquisition returns retryable contention without polling", async () => {
  const failure = Object.assign(new Error("Action is owned"), {
    code: "ERR_MCP_ACTION_IN_PROGRESS",
  });
  let attempts = 0;
  const control = createMcpControlPlane({
    runner: { async status() {} },
    runStore: {
      async readAction() {
        return null;
      },
      async beginAction() {
        assert.equal(++attempts, 1);
        throw failure;
      },
    },
  });
  await assert.rejects(
    control.runResume({
      runId: RUN_ID,
      expectedRevision: 1,
      action: null,
      idempotencyKey: "owned",
    }),
    (error) => error === failure,
  );
  assert.equal(attempts, 1);
});

test("admits a detached child only after its identity is durable", async () => {
  const registered = Promise.withResolvers();
  const persist = Promise.withResolvers();
  const messages = [];
  let killed = false;
  const child = Object.assign(new EventEmitter(), {
    pid: process.pid,
    send(message, callback) {
      messages.push(message);
      callback();
    },
    unref() {},
    kill() {
      killed = true;
    },
  });
  const launch = createDetachedLauncher({
    spawnProcess(_command, _args, options) {
      assert.deepEqual(options.stdio, ["ignore", "ignore", "ignore", "ipc"]);
      queueMicrotask(() => {
        child.emit("spawn");
        child.emit("message", { type: "dispatch-listening" });
      });
      return child;
    },
  });
  const dispatch = { id: RUN_ID, expectedRevision: 7 };
  const admitted = launch(RUN_ID, null, {
    dispatch,
    async onSpawn(owner) {
      assert.equal(owner.pid, child.pid);
      assert.ok(owner.processIdentity.bootId);
      registered.resolve();
      await persist.promise;
    },
  });
  await registered.promise;
  assert.deepEqual(messages, []);
  persist.resolve();
  assert.equal(await admitted, child.pid);
  assert.deepEqual(messages, [{ type: "dispatch", dispatch }]);
  assert.equal(killed, false);
});

test("projects descriptor-owned pipeline mode guidance", async () => {
  assert.match(
    MCP_INSTRUCTIONS,
    /independent is the default and recommended mode/u,
  );
  assert.match(MCP_INSTRUCTIONS, /more provider context and tokens/u);
  assert.match(MCP_INSTRUCTIONS, /lazy is opt-in/u);
  assert.match(MCP_INSTRUCTIONS, /does not provide independent review/u);
  assert.match(MCP_INSTRUCTIONS, /never select it automatically/u);
  assert.match(MCP_INSTRUCTIONS, /run_pause or run_cancel/u);
  assert.match(MCP_INSTRUCTIONS, /never refresh a stale revision silently/u);
  assert.match(MCP_INSTRUCTIONS, /ownerless applicable stop/u);
  assert.match(MCP_INSTRUCTIONS, /original stop key is unnecessary/u);
  assert.match(MCP_INSTRUCTIONS, /durable stop settlement or child exit/u);

  const control = createMcpControlPlane({ runner: {}, runStore: {} });
  const { pipelines } = await control.pipelinesList();
  assert.deepEqual(
    pipelines.find(({ id }) => id === "plan-authoring").settings
      .preferredCommitLineLimit,
    { defaultValue: 900 },
  );
  for (const pipeline of pipelines) {
    assert.deepEqual(pipeline.settings.mode, {
      defaultValue: "independent",
      recommendedValue: "independent",
      values: ["independent", "lazy", "combined"],
    });
    assert.ok(pipeline.runOptions.includes("mode"));
  }
});

test("launches continuation independently from the MCP process streams", async () => {
  const calls = [];
  const exitCallbacks = [];
  let unreferenced = false;
  const launch = createDetachedLauncher({
    environment: {
      XDG_STATE_HOME: "/state",
      [DETACHED_STOP_CHECKPOINT_ENV]: "ambient-value-must-not-leak",
    },
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

  let exit;
  assert.equal(
    await launch(RUN_ID, null, {
      onExit(code, signal) {
        exit = { code, signal };
      },
    }),
    42,
  );
  exitCallbacks[0](null, "SIGTERM");
  assert.deepEqual(exit, { code: null, signal: "SIGTERM" });
  await launch(RUN_ID, { type: "extra-fix-rounds", amount: 2 });
  await launch(RUN_ID, { type: "override-finding", findingId: "finding-1" });
  await launch(RUN_ID, null, { stopCheckpointRevision: 7 });
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
  assert.deepEqual(calls[3].args, ["/agent-run", "resume", "--run", RUN_ID]);
  assert.equal(calls[0].options.detached, true);
  assert.equal(calls[0].options.stdio, "ignore");
  assert.deepEqual(calls[0].options.env, {
    XDG_STATE_HOME: "/state",
    [DETACHED_RUNTIME_COMPATIBILITY_ENV]: DETACHED_RUNTIME_COMPATIBILITY_TOKEN,
  });
  assert.deepEqual(calls[3].options.env, {
    XDG_STATE_HOME: "/state",
    [DETACHED_RUNTIME_COMPATIBILITY_ENV]: DETACHED_RUNTIME_COMPATIBILITY_TOKEN,
    [DETACHED_STOP_CHECKPOINT_ENV]: "7",
  });
  await assert.rejects(
    launch(
      RUN_ID,
      { type: "extra-fix-rounds", amount: 1 },
      { stopCheckpointRevision: 7 },
    ),
    { code: "ERR_INVALID_RUNNER_INPUT" },
  );
  await assert.rejects(
    launch(RUN_ID, null, { expectedRuntimeCompatibility: "other" }),
    (error) => error.code === "ERR_RUNTIME_VERSION_SKEW",
  );
});

test("MCP separates dispatch exit facts from safe correlated causes and leaves failures incomplete", async (t) => {
  const cause = {
    stage: "process-recovery",
    code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
    explanation: "Execution process ownership could not be verified.",
  };
  const journalCause = {
    stage: "state-recovery",
    code: "ERR_INVALID_EVENT_LOG",
    explanation: "The saved run journal is invalid.",
  };
  for (const [
    exitCode,
    signal,
    diagnostic,
    admissionFailure = false,
    inspection,
  ] of [
    [1, null, cause],
    [0, null, null],
    [null, "SIGTERM", null],
    [RUNTIME_VERSION_SKEW_EXIT_CODE, null, null, true],
    [1, null, journalCause, false, "status"],
    [null, "SIGTERM", journalCause, false, "proof"],
  ]) {
    let completed = false;
    let released = false;
    let launched = false;
    function inspect(boundary) {
      if (launched && inspection === boundary)
        throw Object.assign(new Error("private journal error"), {
          code: "ERR_INVALID_EVENT_LOG",
        });
    }
    const intent = {
      created: true,
      record: { status: "intent", context: {} },
      async updateContext(context) {
        this.record.context = context;
      },
      async complete() {
        completed = true;
      },
      async release() {
        released = true;
      },
    };
    const control = createMcpControlPlane({
      runner: {
        async status() {
          inspect("status");
          return {
            run: {
              runId: RUN_ID,
              revision: 1,
              pause: null,
              pipelineId: "plan-authoring",
              pipelineState: { workflowState: "CLARIFY" },
            },
          };
        },
      },
      runStore: {
        async readAction() {
          return null;
        },
        async beginAction() {
          return intent;
        },
        async runLeaseOwnerIsLive() {
          return false;
        },
        async inspectDispatchOwner() {
          return "live";
        },
        async inspectRecoveryDispatch() {
          inspect("proof");
          return { ready: false, started: false };
        },
        async readRecoveryFailure(id, dispatch) {
          assert.equal(id, RUN_ID);
          assert.deepEqual(dispatch, intent.record.context.dispatch);
          assert.equal(dispatch.owner.pid, 42);
          return diagnostic === null
            ? null
            : { ...diagnostic, transcript: "private transcript" };
        },
      },
      async launchRun(_id, _action, options) {
        await options.onSpawn({ pid: 42 });
        launched = true;
        options.onExit(exitCode, signal);
        if (admissionFailure) throw new Error("private admission error");
      },
    });
    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    const server = createMcpServer({ control, issueReportingEnabled: false });
    const client = new Client({ name: "dispatch-test", version: "1.0.0" });
    t.after(async () => {
      await client.close();
      await server.close();
    });
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    const response = await client.callTool({
      name: "run_resume",
      arguments: {
        runId: RUN_ID,
        expectedRevision: 1,
        action: null,
        idempotencyKey: "dispatch-failure",
      },
    });
    assert.equal(response.isError, true);
    assert.equal(
      response.structuredContent.code,
      exitCode === RUNTIME_VERSION_SKEW_EXIT_CODE
        ? "ERR_RUNTIME_VERSION_SKEW"
        : "ERR_DETACHED_START_FAILED",
    );
    if (exitCode === RUNTIME_VERSION_SKEW_EXIT_CODE)
      assert.match(
        response.structuredContent.message,
        /restart the Agent Runner MCP server/u,
      );
    assert.deepEqual(response.structuredContent.dispatchFailure, {
      exitCode,
      signal,
    });
    assert.deepEqual(response.structuredContent.recoveryCause, diagnostic);
    assert.ok(
      response.structuredContent.message.includes(
        diagnostic?.explanation ?? "The recovery cause is unavailable.",
      ),
    );
    assert.doesNotMatch(
      JSON.stringify(response),
      /private|transcript|processIdentity/u,
    );
    assert.equal(completed, false);
    assert.equal(released, true);
  }
});

test("recorded dispatch inspection failures retain safe causes on identical-key retries after restart", async () => {
  const dispatch = { id: RUN_ID, expectedRevision: 1, owner: { pid: 42 } };
  const recoveryCause = {
    stage: "state-recovery",
    code: "ERR_INVALID_EVENT_LOG",
    explanation: "The saved run journal is invalid.",
  };
  for (const tool of ["runResume", "runRespond", "runStart"]) {
    for (const boundary of ["status", "proof"]) {
      let released = false;
      const record = { status: "intent", context: { runId: RUN_ID, dispatch } };
      function inspect(name) {
        if (name === boundary)
          throw Object.assign(new Error("private journal error"), {
            code: "ERR_INVALID_EVENT_LOG",
          });
      }
      const options = {
        runner: {
          async status() {
            inspect("status");
            return { run: {} };
          },
          async validateBoundary() {
            return {};
          },
        },
        runStore: {
          async readAction() {
            return record;
          },
          async beginAction() {
            return {
              record,
              async complete() {
                assert.fail("Inspection failure must not complete the intent.");
              },
              async release() {
                released = true;
              },
            };
          },
          async inspectRecoveryDispatch() {
            inspect("proof");
            return { ready: false };
          },
          async readRecoveryFailure(runId, saved) {
            assert.equal(runId, RUN_ID);
            assert.deepEqual(saved, dispatch);
            return recoveryCause;
          },
        },
        launchRun() {
          assert.fail("Unreadable evidence excludes a replacement child.");
        },
      };
      for (let attempt = 0; attempt < 2; attempt++) {
        await assert.rejects(
          createMcpControlPlane(options)[tool]({
            runId: RUN_ID,
            expectedRevision: 1,
            action: null,
            idempotencyKey: "same-request",
          }),
          (error) => {
            assert.equal(error.code, "ERR_DETACHED_START_FAILED");
            assert.deepEqual(error.dispatchFailure, {
              exitCode: null,
              signal: null,
            });
            assert.deepEqual(error.recoveryCause, recoveryCause);
            assert.doesNotMatch(error.message, /private/u);
            return true;
          },
        );
        assert.equal(record.status, "intent");
        assert.equal(
          released,
          boundary === "proof" ? tool !== "runStart" : tool === "runStart",
        );
      }
    }
  }
});

test("retry-time lease and stop inspections retain correlated causes without completing recovery", async () => {
  const dispatch = { id: RUN_ID, expectedRevision: 3, owner: { pid: 42 } };
  const recoveryCause = {
    stage: "execution-lease",
    code: "ERR_INVALID_RUN_LEASE",
    explanation: "Execution lease evidence is invalid.",
  };
  for (const [tool, boundary, applicableStop = false] of [
    ["runResume", "lease"],
    ["runResume", "lease", true],
    ["runPause", "status"],
    ["runPause", "lease"],
    ["runCancel", "status"],
    ["runCancel", "lease"],
  ]) {
    const stopTool = tool !== "runResume";
    // A superseding cancellation can retain an earlier stop checkpoint.
    const receipt = {
      runId: RUN_ID,
      requestId: "a".repeat(64),
      expectedRevision: 2,
      revision: 3,
    };
    const record = {
      status: "intent",
      result: null,
      context: {
        runId: RUN_ID,
        expectedRevision: 3,
        dispatch,
        ...(stopTool ? { stopCheckpointRevision: 1 } : {}),
      },
    };
    let releases = 0;
    let diagnostics = 0;
    function inspect(name) {
      if (name === boundary)
        throw Object.assign(new Error("private inspection error"), {
          code: "ERR_INVALID_RUN_LEASE",
        });
    }
    const options = {
      runner: {
        async requestOperatorStop() {
          return receipt;
        },
        async status() {
          inspect("status");
          return {
            run: {
              runId: RUN_ID,
              revision: 3,
              pause: null,
              pipelineState: { workflowState: "CLARIFY" },
              stopRequest:
                stopTool || applicableStop
                  ? {
                      requestId: receipt.requestId,
                      reconciledRevision: null,
                      checkpoint: { revision: 1 },
                    }
                  : null,
            },
          };
        },
      },
      runStore: {
        async readAction(identity) {
          if (stopTool) {
            assert.equal(
              identity.key,
              `stop-recovery-${createHash("sha256").update(receipt.requestId).digest("hex")}`,
            );
            assert.equal(identity.tool, "run_resume");
            assert.deepEqual(identity.arguments(record.context), {
              runId: RUN_ID,
              stopCheckpointRevision: 1,
            });
          }
          return record;
        },
        async beginAction() {
          assert.equal(
            stopTool,
            false,
            "Failed stop inspection must not acquire an intent.",
          );
          return {
            record,
            async complete() {
              assert.fail("Inspection failure must not complete recovery.");
            },
            async release() {
              releases++;
            },
          };
        },
        async inspectRecoveryDispatch() {
          return { ready: false };
        },
        async runLeaseOwnerIsLive() {
          inspect("lease");
          return false;
        },
        async readRecoveryFailure(runId, saved) {
          assert.equal(runId, RUN_ID);
          assert.deepEqual(saved, dispatch);
          diagnostics++;
          return { ...recoveryCause, transcript: "private transcript" };
        },
      },
      launchRun() {
        assert.fail("Failed inspection must exclude a replacement child.");
      },
    };
    for (let attempt = 0; attempt < 2; attempt++) {
      await assert.rejects(
        createMcpControlPlane(options)[tool]({
          runId: RUN_ID,
          expectedRevision: 3,
          ...(stopTool ? {} : { action: null }),
          idempotencyKey: "same-request",
        }),
        (error) => {
          assert.equal(error.code, "ERR_DETACHED_START_FAILED");
          assert.deepEqual(error.dispatchFailure, {
            exitCode: null,
            signal: null,
          });
          assert.deepEqual(error.recoveryCause, recoveryCause);
          assert.ok(error.message.includes(recoveryCause.explanation));
          assert.doesNotMatch(error.message, /private/u);
          assert.doesNotMatch(JSON.stringify(error), /private|transcript/u);
          return true;
        },
      );
      assert.equal(record.status, "intent");
      assert.equal(record.result, null);
      assert.equal(diagnostics, attempt + 1);
      assert.equal(releases, stopTool ? 0 : attempt + 1);
    }
  }
});
