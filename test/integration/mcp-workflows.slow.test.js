import assert from "node:assert/strict";
import test from "node:test";

import {
  createClarificationService,
  createMcpControlPlane,
} from "../../src/index.js";
import { CodexAdapterError } from "../../src/agents/index.js";
import {
  appendReadFailure,
  clarificationAppendFixture,
  createExecutionAdapter,
  transcriptHash,
} from "../support/index.js";
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

test("cold clarification append MCP reconstructs and answers one polishing product decision", async (t) => {
  const cleanups = [];
  let pipelineProcess;
  t.after(async () => {
    try {
      await pipelineProcess?.settle();
    } finally {
      for (const cleanup of cleanups) await cleanup();
    }
  });
  const f = await clarificationAppendFixture(
    { after: (cleanup) => cleanups.push(cleanup) },
    "polishing",
    { kind: "product-decision", mode: "independent" },
  );
  const service = createClarificationService({ interactive: false });
  const initial = f.open({
    clarifications: {
      ...service,
      appendProductDecision(options) {
        return service.appendProductDecision({
          ...options,
          async persistAppend(proof) {
            await options.persistAppend(proof);
            throw appendReadFailure();
          },
        });
      },
    },
  });
  const runId = (await initial.runner.create(f.input)).run.runId;
  const interrupted = (await initial.runner.resume({ runId })).run;
  assert.equal(interrupted.pause.reason, "clarification_append_interrupted");
  const intent = interrupted.pipelineState.pendingClarificationAppend;
  const cold = f.open();
  pipelineProcess = detached(cold.runner);
  const control = createMcpControlPlane({
    runner: cold.runner,
    runStore: cold.store,
    launchRun: pipelineProcess.launchRun,
  });
  const resume = {
    runId,
    expectedRevision: interrupted.revision,
    action: null,
    idempotencyKey: "recover-product-decision",
  };
  await control.runResume(resume);
  await pipelineProcess.settle();
  const status = await control.runStatus({ runId });
  assert.equal(status.pendingInput.kind, "product-decision");
  assert.equal(status.pendingInput.questions.length, 1);
  assert.equal(
    status.pendingInput.questions[0].question,
    intent.decision.question,
  );
  const waiting = await cold.store.loadRun(runId);
  assert.equal(waiting.counters.productDecisions, 1);
  assert.equal(waiting.pipelineState.resolutionCorrection, null);
  assert.equal(waiting.pipelineState.pendingClarificationAppend, null);
  assert.equal(transcriptHash(await f.transcript(waiting)), intent.resultHash);
  assert.equal(f.calls.length, 2);

  // Submission and dispatch are real. A controlled unavailable backend stops
  // the next checkpoint after the answer, without another append-producing reply.
  let launches = 0;
  const respond = () => {
    const reopened = f.open({
      adapters: {
        codex: {
          ...createExecutionAdapter(),
          run() {
            throw new CodexAdapterError("Controlled backend unavailability.", {
              code: "ERR_CODEX_UNAVAILABLE",
              recoverable: true,
            });
          },
        },
      },
    });
    return createMcpControlPlane({
      runner: reopened.runner,
      runStore: reopened.store,
      async launchRun(id, action, options) {
        launches++;
        await reopened.runner.resume({
          runId: id,
          action,
          dispatch: options.dispatch,
          expectedRuntimeCompatibility: options.expectedRuntimeCompatibility,
        });
      },
    });
  };
  const answer = {
    runId,
    expectedRevision: status.revision,
    requestId: status.pendingInput.id,
    answers: [
      { questionId: status.pendingInput.questions[0].id, answer: "Behavior A" },
    ],
    idempotencyKey: "answer-product-decision",
  };
  const receipt = await respond().runRespond(answer);
  const answeredBytes = await f.transcript(waiting);
  assert.match(answeredBytes, /Behavior A/u);
  assert.deepEqual(await respond().runRespond(answer), receipt);
  assert.equal(await f.transcript(waiting), answeredBytes);
  assert.equal(launches, 1);
  assert.equal(f.calls.length, 2);
  const submitted = await f.open().store.loadRun(runId);
  assert.equal(submitted.counters.productDecisions, 1);
  assert.equal(submitted.pipelineState.pendingEdit, null);
  assert.equal(submitted.pause.reason, "backend_unavailable");
});

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
  const bootstrapped = await runStore.loadRun(execution.runId);
  assert.deepEqual(bootstrapped.pipelineState.bootstrapCorrections, []);
  assert.deepEqual(bootstrapped.pipelineState.validationSchedule, {
    commands: ["git diff --check HEAD"],
    steps: [{ step: 1, commandIndexes: [0] }],
  });
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
