import { inactivityActivity } from "../state/index.js";
import { RunnerError } from "./input.js";

const KINDS = new Set([
  "semantic",
  "local-command-started",
  "local-command-completed",
  "local-tool-started",
  "local-tool-completed",
]);
function inactive() {
  const error = new RunnerError(
    "Provider inactivity exhausted the current attempt.",
    { code: "ERR_PROVIDER_INACTIVE" },
  );
  error.recoverable = true;
  return error;
}

// This timer observes the adapter contract, never its transport or process output.
// A callback returning a promise is deliberately awaited before aborting ownership.
export function createInactivityWatchdog({
  timeoutMs,
  expire,
  timers = globalThis,
}) {
  let timer;
  let pending;
  let stopped = false;
  let commands = 0;
  function disarm() {
    if (timer !== undefined) timers.clearTimeout(timer);
    timer = undefined;
  }
  function arm() {
    disarm();
    if (!stopped && pending === undefined && commands === 0) {
      timer = timers.setTimeout(() => {
        timer = undefined;
        pending = Promise.resolve().then(expire);
        // Settlement is observed by close(), including persistence failures.
        pending.catch(() => {});
      }, timeoutMs);
    }
  }
  arm();
  return Object.freeze({
    progress(event) {
      if (
        stopped ||
        pending !== undefined ||
        event === null ||
        typeof event !== "object" ||
        Object.keys(event).length !== 2 ||
        !KINDS.has(event.kind) ||
        !Number.isSafeInteger(event.activeCommands) ||
        event.activeCommands < 0 ||
        event.activeCommands > 16_384
      )
        return;
      const expected =
        commands +
        (event.kind === "local-command-started"
          ? 1
          : event.kind === "local-command-completed"
            ? -1
            : 0);
      if (event.activeCommands !== expected) return;
      commands = expected;
      arm();
    },
    async close() {
      stopped = true;
      disarm();
      await pending;
    },
  });
}

export function createInactivityCoordinator({
  runId,
  lease,
  runStore,
  git,
  monitor,
  publish,
  initialRun,
  timers,
}) {
  let checkpoint;
  let responseRole;
  let pending = initialRun?.inactivityRecovery != null;
  let manualRetry = initialRun?.pause != null;
  async function guarded(operation) {
    try {
      return await operation();
    } catch (cause) {
      if (
        [
          "ERR_PROVIDER_INACTIVE",
          "ERR_OPERATOR_STOP_BEFORE_COMMIT",
          "ERR_INACTIVITY_RECOVERY",
        ].includes(cause?.code)
      )
        throw cause;
      throw new RunnerError(
        "Provider recovery retains its durable checkpoint.",
        { code: "ERR_INACTIVITY_RECOVERY", cause },
      );
    }
  }
  async function record(recovery, kind) {
    return guarded(async () => {
      const activity = inactivityActivity(recovery, kind);
      const next = await runStore.recordInactivity(lease, recovery, kind);
      pending = true;
      await publish(activity, next);
      return next;
    });
  }
  return Object.freeze({
    async pending() {
      // A journal append may have succeeded before publication threw.
      pending = (await runStore.loadRun(runId)).inactivityRecovery !== null;
      return pending;
    },
    eligible: (cause) =>
      cause?.code === "ERR_PROVIDER_INACTIVE" && cause.recoverable === true,
    async before({ role, checkpoint: selected, repository }) {
      checkpoint = selected;
      let run = await runStore.loadRun(runId);
      const recovery = run.inactivityRecovery;
      pending = recovery !== null;
      if (recovery === null) return run;
      if (recovery.role !== role || recovery.checkpoint !== selected)
        throw new RunnerError("Inactivity checkpoint changed.", {
          code: "ERR_INACTIVITY_RECOVERY",
        });
      await monitor.check();
      await git.assertUnchanged(repository);
      if (run.activeTurn !== null) {
        if (
          run.activeTurn.role !== role ||
          run.executionProcess !== null ||
          run.executionResource !== null
        )
          throw new RunnerError("Inactivity ownership is not reconciled.", {
            code: "ERR_INACTIVITY_RECOVERY",
          });
        run = await runStore.finishAgentTurn(lease, run.activeTurn);
      }
      // Backoff can continue after a new availability failure, but a stale
      // episode cannot replenish a reconstruction lost with its owner.
      if (
        recovery.attempt === 2 &&
        !manualRetry &&
        !(
          recovery.status === "reconstructing" &&
          run.availabilityRetry?.role === role &&
          run.availabilityRetry.checkpoint === selected &&
          run.availabilityRetry.reconciledRevision >=
            recovery.reconstructionRevision
        )
      )
        throw inactive();
      manualRetry = false;
      return record(
        { ...recovery, attempt: 2, status: "reconstructing" },
        "reconstructing",
      );
    },
    async retry({ repository }) {
      await monitor.check();
      await git.assertUnchanged(repository);
      const run = await runStore.loadRun(runId);
      if (
        run.executionProcess !== null ||
        run.executionResource !== null ||
        run.activeTurn !== null
      )
        throw new RunnerError(
          "Inactivity recovery requires retired ownership.",
          { code: "ERR_INACTIVITY_RECOVERY" },
        );
      return run.inactivityRecovery?.attempt === 1;
    },
    async invoke(role, operation, request) {
      const run = await runStore.loadRun(runId);
      if (run.activeTurn?.role !== role || checkpoint === undefined)
        throw new RunnerError("Inactivity attempt has no checkpoint.", {
          code: "ERR_INACTIVITY_RECOVERY",
        });
      const controller = new AbortController();
      const signal =
        request.signal === undefined
          ? controller.signal
          : AbortSignal.any([request.signal, controller.signal]);
      let expired = false;
      let attempt = run.inactivityRecovery?.attempt ?? 1;
      let reservation;
      let persistenceFailure;
      const watchdog = createInactivityWatchdog({
        timeoutMs: run.providerInactivityTimeoutMs,
        timers,
        expire: async () => {
          if (request.signal?.aborted) return;
          expired = true;
          try {
            await reservation;
            const observed = await git.snapshot({
              projectPath: run.projectPath,
              allowedPaths: [],
            });
            await record(
              {
                role,
                checkpoint,
                attempt,
                status: "expired",
                configurationFingerprint: run.providerInactivityFingerprint,
                contentFingerprint: observed.contentFingerprint,
              },
              "expired",
            );
          } catch (cause) {
            persistenceFailure = new RunnerError(
              "Inactivity evidence could not be persisted; recovery is not authorized.",
              { code: "ERR_INACTIVITY_RECOVERY", cause },
            );
          }
          // Persistence failure still retires owned work, but cannot authorize retry.
          controller.abort(persistenceFailure ?? inactive());
        },
      });
      const stop = () => {
        void watchdog.close().catch(() => {});
      };
      request.signal?.addEventListener("abort", stop, { once: true });
      let response;
      let failure;
      try {
        response = await operation({
          ...request,
          signal,
          onProgress: watchdog.progress,
          onFreshSession: async () => {
            if (attempt === 2 || expired || signal.aborted) return false;
            attempt = 2;
            reservation = (async () => {
              const observed = await git.snapshot({
                projectPath: run.projectPath,
                allowedPaths: [],
              });
              await record(
                {
                  role,
                  checkpoint,
                  attempt,
                  status: "reconstructing",
                  configurationFingerprint: run.providerInactivityFingerprint,
                  contentFingerprint: observed.contentFingerprint,
                },
                "reconstructing",
              );
            })();
            await reservation;
            return !expired && !signal.aborted;
          },
          onCommitExecution: async () => {
            await watchdog.close();
            signal.throwIfAborted();
            // The adapter has returned and validated readiness, but has not begun
            // the constrained executor. Reconcile that response before effects.
            const ready = await runStore.loadRun(runId);
            if (ready.inactivityRecovery !== null) {
              await git.assertUnchanged(ready.pipelineState.repositoryBaseline);
              const next = await runStore.completeInactivityTurn(lease, role);
              pending = false;
              await publish(
                inactivityActivity(ready.inactivityRecovery, "recovered"),
                next,
              );
            }
            signal.throwIfAborted();
          },
        });
      } catch (cause) {
        failure = cause;
      } finally {
        await watchdog.close();
        request.signal?.removeEventListener("abort", stop);
      }
      if (request.signal?.aborted) throw failure ?? request.signal.reason;
      const deadlineFailure =
        failure === undefined ||
        failure === signal.reason ||
        (signal.aborted && failure?.code === signal.reason?.code);
      if (persistenceFailure !== undefined && deadlineFailure)
        throw persistenceFailure;
      if (expired && deadlineFailure) {
        if (
          request.access === "local-commit" &&
          failure?.failure?.commitExecutor !== "not_started"
        )
          throw (
            failure ??
            new RunnerError("Commit outcome requires reconciliation.", {
              code: "ERR_COMMIT_OUTCOME_UNKNOWN",
            })
          );
        const cause = inactive();
        if (request.access === "local-commit") {
          cause.effectStarted = false;
          cause.failure = failure.failure;
        }
        throw cause;
      }
      if (failure !== undefined) throw failure;
      responseRole = role;
      return response;
    },
    async completed(role, { repositoryReconciled = true, ...options } = {}) {
      if (responseRole !== role) return;
      // A safety pause or failed repository check must retain recovery evidence
      // without replacing the pipeline's original failure during turn cleanup.
      if (!repositoryReconciled || options.patch?.pause != null) {
        responseRole = undefined;
        return;
      }
      if (!pending) {
        responseRole = undefined;
        return;
      }
      return guarded(async () => {
        const run = await runStore.loadRun(runId);
        if (run.inactivityRecovery === null) {
          pending = false;
          responseRole = undefined;
          return;
        }
        // The pipeline supplies its reconciled snapshot, including partial writes.
        const repository =
          options.patch?.pipelineState?.repositoryBaseline ??
          run.pipelineState.repositoryBaseline;
        await git.assertUnchanged(repository);
        const next = await runStore.completeInactivityTurn(
          lease,
          role,
          options,
        );
        responseRole = undefined;
        pending = false;
        await publish(
          inactivityActivity(run.inactivityRecovery, "recovered"),
          next,
        );
        return next;
      });
    },
  });
}
