import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import test from "node:test";

import { DETACHED_RUNTIME_COMPATIBILITY_TOKEN } from "../../src/index.js";
import {
  createDetachedLauncher,
  createMcpControlPlane,
  DETACHED_RUNTIME_COMPATIBILITY_ENV,
  DETACHED_STOP_CHECKPOINT_ENV,
  MCP_INSTRUCTIONS,
} from "../../src/mcp/index.js";

const RUN_ID = "11111111-1111-4111-8111-111111111111";

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
