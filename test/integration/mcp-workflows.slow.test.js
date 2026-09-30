import assert from "node:assert/strict";
import test from "node:test";

import { createMcpControlPlane } from "../../src/index.js";
import {
  createBackend,
  fixture,
  ONE_STEP_PLAN,
  runtime,
} from "./support/index.js";

function deferred() {
  let resolvePromise;
  const promise = new Promise((resolve) => {
    resolvePromise = resolve;
  });
  return { promise, resolve: resolvePromise };
}

async function within(promise, milliseconds, message) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(message)), milliseconds);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

function detached(runner) {
  const failures = [];
  const pending = new Set();
  return {
    launchRun(runId, action = null, options = {}) {
      const execution = runner
        .resume({
          runId,
          action,
          dispatch: options.dispatch,
          expectedRuntimeCompatibility: options.expectedRuntimeCompatibility,
          ...(options.stopCheckpointRevision == null
            ? {}
            : { stopCheckpointRevision: options.stopCheckpointRevision }),
        })
        .then(({ run }) =>
          options.onExit?.(
            run.pipelineState.workflowState === "WAITING_FOR_USER" ? 2 : 0,
          ),
        )
        .catch((error) => {
          failures.push(error);
          options.onExit?.(1);
        })
        .finally(() => pending.delete(execution));
      pending.add(execution);
    },
    async settle() {
      while (pending.size > 0) {
        await Promise.all([...pending]);
      }
      if (failures.length > 0) {
        throw failures[0];
      }
    },
  };
}

test("continues one detached MCP execution after client replacement", async (t) => {
  const paths = await fixture(t, {
    autoCleanup: false,
    plan: ONE_STEP_PLAN,
  });
  const implementationGate = {
    entered: deferred(),
    release: deferred(),
  };
  const codex = createBackend("codex", {
    failExecutionClarification: true,
    implementationGate,
  });
  const { runner, runStore } = runtime(
    paths,
    { codex },
    { schemaVersion: 1, defaultBackend: "codex" },
  );
  const pipelineProcess = detached(runner);
  t.after(async () => {
    implementationGate.release.resolve();
    try {
      await pipelineProcess.settle();
    } finally {
      await paths.cleanup();
    }
  });

  const control = createMcpControlPlane({
    launchRun: pipelineProcess.launchRun,
    runner,
    runStore,
  });
  const execution = await control.runStart({
    idempotencyKey: "execution-start",
    pipelineId: "plan-execution",
    projectPath: paths.projectPath,
    taskPath: paths.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  });
  await pipelineProcess.settle();
  const paused = await control.runStatus({ runId: execution.runId });
  assert.equal(paused.status, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pause.resumeState, "CLARIFY");

  const reconnected = createMcpControlPlane({
    launchRun: pipelineProcess.launchRun,
    runner,
    runStore,
  });
  await reconnected.runResume({
    idempotencyKey: "execution-resume",
    runId: execution.runId,
    expectedRevision: paused.revision,
    action: null,
  });
  await within(
    implementationGate.entered.promise,
    30_000,
    "Execution did not reach implementation.",
  );

  const running = await reconnected.runStatus({ runId: execution.runId });
  assert.equal(running.execution.state, "running");
  await reconnected.runCancel({
    idempotencyKey: "execution-cancel",
    runId: execution.runId,
    expectedRevision: running.revision,
  });
  implementationGate.release.resolve();
  await pipelineProcess.settle();
  const canceled = await reconnected.runStatus({ runId: execution.runId });
  assert.equal(canceled.status, "CANCELED");
  assert.equal(canceled.completedCommits.length, 0);
});
