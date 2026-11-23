import { isDeepStrictEqual } from "node:util";

import {
  EFFORT_DIAGNOSTIC_CLASS,
  MODEL_CATALOG_INVALID_DIAGNOSTIC,
  MODEL_UNAVAILABLE_DIAGNOSTIC,
} from "../agents/index.js";
import { terminateOwnedProcess } from "../platform/index.js";
import { MODEL_CATALOG_RETRY_CODE } from "../state/index.js";

import { RunnerError } from "./input.js";

export function stopPending(run) {
  return (
    run?.stopRequest !== null &&
    run?.stopRequest !== undefined &&
    run.stopRequest.reconciledRevision === null
  );
}

function stopImmediately(run) {
  return (
    stopPending(run) &&
    run.stopRequest.effectiveTiming !== "after-current-commit"
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

function withoutLaunchRecovery(pause) {
  if (pause === null || !Object.hasOwn(pause, "launchRecovery")) return pause;
  const retained = { ...pause };
  delete retained.launchRecovery;
  return retained;
}

export function createStopMonitor({ runId, lease, runStore, publish }) {
  const controller = new AbortController();
  const watcher = new AbortController();
  let closed = false;
  let waiting = false;
  let stopping = null;
  let preEffectRejection = null;
  let writableNoEffectTurn = null;
  let monitoringFailure = null;
  let pendingWrite = Promise.resolve();

  function write(operation) {
    const result = pendingWrite.then(operation);
    pendingWrite = result.catch(() => {});
    return result;
  }

  function rejectBeforeCommit(authorizationId, cause) {
    const diagnosticClass = cause?.failure?.failureClass;
    if (
      typeof authorizationId !== "string" ||
      cause?.effectStarted !== false ||
      diagnosticClass === MODEL_UNAVAILABLE_DIAGNOSTIC
    )
      return;
    preEffectRejection = {
      authorizationId,
      rejection: {
        code: cause.code ?? "ERR_OPERATOR_STOP_BEFORE_COMMIT",
        recoverable: cause.recoverable === true,
        ...([
          MODEL_CATALOG_INVALID_DIAGNOSTIC,
          EFFORT_DIAGNOSTIC_CLASS,
        ].includes(diagnosticClass)
          ? { diagnosticClass }
          : {}),
      },
    };
  }

  async function detect(current = null) {
    current ??= await runStore.loadRun(runId);
    if (!(stopImmediately(current) || (waiting && stopPending(current))))
      return current;
    if (stopping === null) {
      if (!controller.signal.aborted) controller.abort(stopError());
      stopping = (async () => {
        const activity = {
          actor: "runner",
          phase: "stop",
          kind: "stopping",
          message: "Operator stop requested; owned execution is stopping.",
        };
        const next = await write(() =>
          runStore.recordStopActivity(lease, activity),
        );
        await publish(activity, next);
        return next;
      })();
    }
    await stopping;
    return current;
  }

  const watching = (async () => {
    let current = await runStore.loadRun(runId);
    while (
      !closed &&
      !(stopImmediately(current) || (waiting && stopPending(current)))
    ) {
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
    persist: write,
    async wait(operation) {
      waiting = true;
      try {
        await detect();
        controller.signal.throwIfAborted();
        return await operation(controller.signal);
      } finally {
        waiting = false;
      }
    },
    get preEffectRejection() {
      return preEffectRejection;
    },
    get writableNoEffectTurn() {
      return writableNoEffectTurn;
    },
    recordWritableNoEffect(turn) {
      writableNoEffectTurn = turn;
    },
    async check() {
      await detect();
      controller.signal.throwIfAborted();
    },
    async invoke(operation, request) {
      const committing = request.access === "local-commit";
      if (committing) preEffectRejection = null;
      const signal =
        request.signal === undefined
          ? controller.signal
          : AbortSignal.any([request.signal, controller.signal]);
      try {
        await detect();
        controller.signal.throwIfAborted();
        return await operation({
          ...request,
          signal,
          ...(request.onResource === undefined
            ? {}
            : {
                onResource: (resource) =>
                  write(() => request.onResource(resource)),
              }),
          onProcess: (pid, proof) =>
            write(() => runStore.recordExecutionProcess(lease, pid, proof)),
        });
      } catch (cause) {
        if (committing) rejectBeforeCommit(request.authorizationId, cause);
        throw cause;
      }
    },
    resetCommitRejection() {
      preEffectRejection = null;
    },
    rejectBeforeCommit,
    async close() {
      closed = true;
      watcher.abort();
      await watching;
      await stopping?.catch(() => {});
      await pendingWrite;
      if (monitoringFailure !== null) throw monitoringFailure;
    },
  });
}

// Wrap a pipeline-owned checkpoint without losing its underlying blocker.
export function stopSettlement(
  current,
  patch,
  activity,
  configurationFailure = null,
  continuesDeferredBoundary = false,
) {
  if (configurationFailure !== null) {
    patch = {
      ...patch,
      pipelineState: {
        ...patch.pipelineState,
        workflowState: "WAITING_FOR_USER",
      },
      pause: {
        reason: "project_configuration_changed",
        code: "ERR_PROJECT_CONFIGURATION_CHANGED",
      },
      activeTurn: null,
    };
  }
  if (
    !stopPending(current) ||
    (continuesDeferredBoundary && configurationFailure === null)
  )
    return { patch, activity };
  const canceled = current.stopRequest.kind === "cancel_requested";
  return {
    patch: {
      ...patch,
      pipelineState: {
        ...patch.pipelineState,
        workflowState: canceled ? "CANCELED" : "WAITING_FOR_USER",
      },
      pause: {
        reason: canceled ? "operator_canceled" : "operator_paused",
        resumeAction: null,
        operatorResume: {
          workflowState: patch.pipelineState.workflowState,
          pause: canceled ? withoutLaunchRecovery(patch.pause) : patch.pause,
          activeTurn: patch.activeTurn ?? null,
        },
      },
    },
    activity: {
      actor: "runner",
      phase: "stop",
      kind: "reconciled",
      message: canceled
        ? "Operator cancellation reconciled."
        : "Operator pause reconciled.",
    },
  };
}

function reconciliationRuntime(runtime, initialRun) {
  let current = initialRun;
  let settlement = { kind: "quiescent", commit: null };
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
      workspace: Object.freeze({
        ...runtime.workspace,
        reportArtifact: rejectEffect,
      }),
      trustedValidation: Object.freeze({
        ...runtime.trustedValidation,
        execute: rejectEffect,
        preflight: rejectEffect,
        inspectRequirements: rejectEffect,
      }),
      transition: async (patch) => update(patch),
      settleVerifiedCommit: async (patch, { verifiedCommit }) => {
        settlement = { kind: "commit", commit: verifiedCommit };
        return update(patch);
      },
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
    settlement: () => settlement,
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
  writableNoEffectTurn = null,
  configurationFailure = null,
  cleanupResources = async (run) => run,
  inspectSessionProcesses,
  onRecoveryStage = () => {},
}) {
  onRecoveryStage("state-recovery");
  let current = await runStore.loadRun(run.runId);
  if (!stopPending(current)) return current;
  if (current.preparation != null) {
    current = await runStore.recoverPreparation(lease, (owner, inspect) =>
      terminateOwnedProcess(owner.pid, inspect, { inspectSessionProcesses }),
    );
  }
  if (current.executionProcess !== null) {
    onRecoveryStage("process-recovery");
    const owner = await runStore.inspectExecutionProcess(current.runId);
    await terminateOwnedProcess(
      owner.pid,
      () => runStore.inspectExecutionProcess(current.runId),
      { inspectSessionProcesses },
    );
    current = await runStore.recordExecutionProcess(lease, null);
  }
  onRecoveryStage("resource-recovery");
  current = await cleanupResources(current);
  onRecoveryStage("state-recovery");
  if (current.observations?.attempts.at(-1).status === "active")
    current = await runStore.recoverRun(lease);
  const activity = {
    actor: "runner",
    phase: "stop",
    kind: "reconciling",
    message: "Operator stop is reconciling repository and effect state.",
  };
  current = await runStore.recordStopActivity(lease, activity);
  await publish(activity, current);

  onRecoveryStage("checkpoint-continuation");
  const history =
    current.workspacePreparation == null &&
    pipeline.prepareRecovery !== undefined &&
    runStore.loadRunHistory
      ? await runStore.loadRunHistory(current.runId, { stream: true })
      : null;
  // A cancellation can supersede the pause while activity is published.
  // Give recovery the same quiescent checkpoint as its certified history.
  current = history?.run ?? current;
  if (!stopPending(current)) return current;
  // Cancelling a settled pause reconciles its underlying checkpoint so that
  // settlement wraps it once rather than nesting operator checkpoints.
  if (current.pause?.reason === "operator_paused")
    current = { ...current, ...restoreOperatorPause(current) };
  const hasWritableNoEffect =
    (writableNoEffectTurn !== null &&
      isDeepStrictEqual(current.activeTurn, writableNoEffectTurn)) ||
    (history?.hasWritableCatalogRejection === true &&
      isDeepStrictEqual(current.activeTurn, history.run.activeTurn));
  const readOnlyCatalogRejection =
    current.stopRequest.kind === "pause_requested"
      ? (history?.readOnlyCatalogRejection ?? null)
      : null;
  if (history !== null) await pipeline.prepareRecovery(current, history);
  const simulated =
    current.workspacePreparation == null
      ? reconciliationRuntime(runtime, current)
      : null;
  let workspaceFailure = null;
  let inspectionFailure = null;
  if (simulated !== null && runtime.workspace?.kind === "directory") {
    try {
      await runtime.workspace.snapshot();
    } catch (cause) {
      inspectionFailure = pipeline.inspectionFailure?.(current, cause) ?? null;
      if (
        inspectionFailure === null &&
        !cause?.code?.startsWith("ERR_WORKSPACE_")
      )
        throw cause;
      workspaceFailure = cause;
    }
  }
  // Directory turns have no Git effects to reconcile. Retain their checkpoint
  // and the drift blocker after retirement, without accepting changed inputs.
  let reconciled =
    current.workspacePreparation != null
      ? current
      : workspaceFailure === null
        ? await pipeline.workflow.run({
            action: null,
            operatorStop: true,
            operatorStopPreEffectRejection: preEffectRejection,
            operatorStopReadOnlyCatalogRejection: readOnlyCatalogRejection,
            interruptedWritableNoEffect: hasWritableNoEffect,
            run: current,
            settings: current.pipelineState.settings,
            runtime: simulated.runtime,
          })
        : inspectionFailure !== null
          ? { ...current, ...inspectionFailure }
          : {
              ...current,
              pipelineState: {
                ...current.pipelineState,
                workflowState: "WAITING_FOR_USER",
              },
              pause: {
                reason: "workspace_changed",
                code: "ERR_WORKSPACE_DRIFT",
              },
              activeTurn: null,
            };
  reconciled ??= simulated.current();
  let outcomeActivity;
  const completed = await runStore.settleCheckpoint(
    lease,
    (latest) => {
      // The simulated restatement retry only retires the turn. If cancellation
      // won, keep the certified reservation and retire it without a retry.
      const canceledRestatement =
        latest.stopRequest?.kind === "cancel_requested" &&
        readOnlyCatalogRejection !== null &&
        current.pause === null &&
        reconciled.pause?.code === MODEL_CATALOG_RETRY_CODE;
      const checkpoint = canceledRestatement ? latest : reconciled;
      const settlement = stopSettlement(
        latest,
        {
          counters: checkpoint.counters,
          hashes: checkpoint.hashes,
          pipelineState: checkpoint.pipelineState,
          pause: checkpoint.pause,
          activeTurn: canceledRestatement ? null : checkpoint.activeTurn,
        },
        null,
        configurationFailure,
      );
      outcomeActivity = settlement.activity;
      return {
        ...settlement,
        settlement: simulated?.settlement() ?? {
          kind: "quiescent",
          commit: null,
        },
      };
    },
    { validate: pipeline.workflow.validateRun },
  );
  await publish(outcomeActivity, completed);
  return completed;
}
