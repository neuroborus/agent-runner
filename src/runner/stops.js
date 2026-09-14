import { terminateOwnedProcess } from "../agents/index.js";

import { RunnerError } from "./input.js";

export function stopPending(run) {
  return (
    run?.stopRequest !== null &&
    run?.stopRequest !== undefined &&
    run.stopRequest.reconciledRevision === null
  );
}

function stopError() {
  return Object.assign(
    new RunnerError("Operator stop requested.", {
      code: "ERR_OPERATOR_STOP_BEFORE_COMMIT",
    }),
    { effectStarted: false },
  );
}

export function restoreOperatorPause(run) {
  const checkpoint = run.pause.operatorResume;
  return Object.freeze({
    pipelineState: Object.freeze({
      ...run.pipelineState,
      workflowState: checkpoint.workflowState,
    }),
    pause: checkpoint.pause,
    activeTurn: checkpoint.activeTurn,
  });
}

export function createStopMonitor({ runId, lease, runStore, publish }) {
  const controller = new AbortController();
  const watcher = new AbortController();
  let closed = false;
  let stopping = null;
  let preEffectRejection = null;
  let monitoringFailure = null;

  async function detect(current = null) {
    current ??= await runStore.loadRun(runId);
    if (!stopPending(current)) return current;
    if (stopping === null) {
      if (!controller.signal.aborted) controller.abort(stopError());
      stopping = (async () => {
        const activity = {
          actor: "runner",
          phase: "stop",
          kind: "stopping",
          message: "Operator stop requested; owned execution is stopping.",
        };
        const next = await runStore.recordStopActivity(lease, activity);
        await publish(activity, next);
        return next;
      })();
    }
    await stopping;
    return current;
  }

  const watching = (async () => {
    let current = await runStore.loadRun(runId);
    while (!closed && !stopPending(current)) {
      current = await runStore.waitForRunChange(runId, {
        afterRevision: current.revision,
        timeoutMs: 1_000,
        signal: watcher.signal,
      });
    }
    if (!closed) await detect(current);
  })().catch((cause) => {
    if (!closed && !watcher.signal.aborted && !controller.signal.aborted) {
      monitoringFailure = new RunnerError("Operator stop monitoring failed.", {
        cause,
        code: "ERR_STOP_MONITOR_FAILED",
      });
      controller.abort(monitoringFailure);
    }
  });

  return Object.freeze({
    get preEffectRejection() {
      return preEffectRejection;
    },
    async check() {
      await detect();
      controller.signal.throwIfAborted();
    },
    async invoke(operation, request) {
      await detect();
      controller.signal.throwIfAborted();
      const signal =
        request.signal === undefined
          ? controller.signal
          : AbortSignal.any([request.signal, controller.signal]);
      try {
        return await operation({
          ...request,
          signal,
          onProcess: (pid, proof) =>
            runStore.recordExecutionProcess(lease, pid, proof),
        });
      } catch (cause) {
        if (
          request.access === "local-commit" &&
          cause?.effectStarted === false
        ) {
          preEffectRejection = {
            code: cause.code ?? "ERR_OPERATOR_STOP_BEFORE_COMMIT",
            recoverable: cause.recoverable === true,
          };
        }
        throw cause;
      }
    },
    rejectBeforeCommit(cause) {
      if (cause?.effectStarted === false) {
        preEffectRejection = {
          code: cause.code ?? "ERR_OPERATOR_STOP_BEFORE_COMMIT",
          recoverable: cause.recoverable === true,
        };
      }
    },
    async close() {
      closed = true;
      watcher.abort();
      await watching;
      await stopping?.catch(() => {});
      if (monitoringFailure !== null) throw monitoringFailure;
    },
  });
}

function reconciliationRuntime(runtime, initialRun) {
  let current = initialRun;
  const rejectEffect = () => {
    throw new RunnerError(
      "Stop reconciliation cannot start execution or write artifacts.",
      { code: "ERR_STOP_RECONCILIATION_EFFECT" },
    );
  };
  const update = (patch) => {
    current = Object.freeze({
      ...current,
      ...patch,
      revision: current.revision + 1,
    });
    return current;
  };
  return {
    runtime: Object.freeze({
      ...runtime,
      adapters: Object.freeze(
        Object.fromEntries(
          Object.keys(runtime.adapters).map((role) => [
            role,
            Object.freeze({ probe: rejectEffect, run: rejectEffect }),
          ]),
        ),
      ),
      clarifications: Object.freeze({
        ...runtime.clarifications,
        acceptEdit: rejectEffect,
        appendProductDecision: rejectEffect,
        appendQuestionRound: rejectEffect,
        ensureTranscript: rejectEffect,
        freezeTranscript: rejectEffect,
        openEditor: rejectEffect,
        prepareEdit: rejectEffect,
      }),
      git: Object.freeze({
        ...runtime.git,
        prepareCommit: rejectEffect,
        stagePolishingHandoff: rejectEffect,
      }),
      trustedValidation: Object.freeze({
        ...runtime.trustedValidation,
        execute: rejectEffect,
        preflight: rejectEffect,
      }),
      transition: async (patch) => update(patch),
      startAgentTurn: async (activeTurn, { pipelineState } = {}) =>
        update({
          activeTurn,
          ...(pipelineState === undefined ? {} : { pipelineState }),
        }),
      finishAgentTurn: async () => update({ activeTurn: null }),
      recordChildSession: async () => current,
      writePlan: rejectEffect,
      writeRunArtifact: rejectEffect,
    }),
    current: () => current,
  };
}

export async function reconcileOperatorStop({
  run,
  pipeline,
  lease,
  runStore,
  runtime,
  publish,
  preEffectRejection = null,
  configurationFailure = null,
}) {
  let current = await runStore.loadRun(run.runId);
  if (!stopPending(current)) return current;
  if (current.executionProcess !== null) {
    const owner = await runStore.inspectExecutionProcess(current.runId);
    await terminateOwnedProcess(owner.pid, () =>
      runStore.inspectExecutionProcess(current.runId),
    );
    current = await runStore.recordExecutionProcess(lease, null);
  }
  const activity = {
    actor: "runner",
    phase: "stop",
    kind: "reconciling",
    message: "Operator stop is reconciling repository and effect state.",
  };
  current = await runStore.recordStopActivity(lease, activity);
  await publish(activity, current);

  const simulated = reconciliationRuntime(runtime, current);
  let reconciled = await pipeline.workflow.run({
    action: null,
    operatorStop: true,
    operatorStopPreEffectRejection: preEffectRejection,
    run: current,
    settings: current.pipelineState.settings,
    runtime: simulated.runtime,
  });
  reconciled ??= simulated.current();
  current = await runStore.loadRun(run.runId);
  const canceled = current.stopRequest.kind === "cancel_requested";
  const checkpoint =
    configurationFailure === null
      ? {
          workflowState: reconciled.pipelineState.workflowState,
          pause: reconciled.pause,
          activeTurn: reconciled.activeTurn,
        }
      : {
          workflowState: "WAITING_FOR_USER",
          pause: {
            reason: "project_configuration_changed",
            code: "ERR_PROJECT_CONFIGURATION_CHANGED",
          },
          activeTurn: null,
        };
  const outcomeActivity = {
    actor: "runner",
    phase: "stop",
    kind: "reconciled",
    message: canceled
      ? "Operator cancellation reconciled."
      : "Operator pause reconciled.",
  };
  const completed = await runStore.completeOperatorStop(lease, {
    requestId: current.stopRequest.requestId,
    patch: {
      counters: reconciled.counters,
      hashes: reconciled.hashes,
      pipelineState: {
        ...reconciled.pipelineState,
        workflowState: canceled ? "CANCELED" : "WAITING_FOR_USER",
      },
      pause: {
        reason: canceled ? "operator_canceled" : "operator_paused",
        resumeAction: null,
        operatorResume: checkpoint,
      },
    },
    outcomeMessage: outcomeActivity.message,
  });
  await publish(outcomeActivity, completed);
  return completed;
}
