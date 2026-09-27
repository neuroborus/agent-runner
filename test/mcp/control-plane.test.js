import assert from "node:assert/strict";
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
