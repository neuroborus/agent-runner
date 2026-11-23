import { isDeepStrictEqual } from "node:util";

import { inactivityActivity } from "../state/index.js";
import { RunnerError } from "./input.js";
import { runObservedAttempt } from "./observations.js";

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
  let suspensions = 0;
  function disarm() {
    if (timer !== undefined) timers.clearTimeout(timer);
    timer = undefined;
  }
  function arm() {
    disarm();
    if (
      !stopped &&
      pending === undefined &&
      commands === 0 &&
      suspensions === 0
    ) {
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
    async suspend(operation) {
      suspensions++;
      disarm();
      try {
        // An already observed deadline still owns its durable expiry.
        await pending;
        return await operation();
      } finally {
        suspensions--;
        arm();
      }
    },
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
  let catalogRetryRepository;
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
      const next = await monitor.persist(() =>
        runStore.recordInactivity(lease, recovery, kind),
      );
      pending = true;
      await publish(activity, next);
      return next;
    });
  }
  return Object.freeze({
    async pending() {
      // A journal append may have succeeded before publication threw.
      const recovery = (await runStore.loadRun(runId)).inactivityRecovery;
      pending = recovery !== null;
      return recovery?.expiryRevision != null;
    },
    eligible: (cause) =>
      cause?.code === "ERR_PROVIDER_INACTIVE" && cause.recoverable === true,
    async before({
      role,
      checkpoint: selected,
      repository,
      continueEpisode = false,
    }) {
      checkpoint = selected;
      catalogRetryRepository = undefined;
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
          run.preparation != null ||
          run.executionProcess !== null ||
          run.executionResource !== null
        )
          throw new RunnerError("Inactivity ownership is not reconciled.", {
            code: "ERR_INACTIVITY_RECOVERY",
          });
        run = await runStore.finishAgentTurn(lease, run.activeTurn);
      }
      // The owning checkpoint proved a continuation of a consumed attempt.
      // Keep its exact episode and any already-spent reconstruction.
      if (continueEpisode) {
        if (
          run.modelCatalogResume?.role === role &&
          recovery.status === "expired" &&
          recovery.attempt === 1 &&
          recovery.expiryRevision !== null &&
          repository.contentFingerprint ===
            run.pipelineState.repositoryBaseline?.contentFingerprint
        )
          catalogRetryRepository = repository;
        manualRetry = false;
        return run;
      }
      // Backoff can continue after a new availability failure, but a stale
      // episode cannot replenish a reconstruction lost with its owner.
      if (
        (recovery.attempt === 2 || recovery.expiryRevision == null) &&
        !manualRetry &&
        !(
          recovery.status === "reconstructing" &&
          run.availabilityRetry?.role === role &&
          run.availabilityRetry.checkpoint === selected &&
          run.availabilityRetry.reconciledRevision >=
            recovery.reconstructionRevision
        )
      )
        throw recovery.expiryRevision != null
          ? inactive()
          : Object.assign(
              new RunnerError(
                "Provider reconstruction allowance was consumed.",
                { code: "ERR_PROVIDER_RECONSTRUCTION_EXHAUSTED" },
              ),
              { recoverable: true },
            );
      manualRetry = false;
      return record(
        { ...recovery, attempt: 2, status: "reconstructing" },
        "reconstructing",
      );
    },
    // A reconciled turn binds the journaled expiry to its own invocation
    // marker and the unchanged content it observed.
    async retry({ repository, reconciledTurn = null, expiredAfter }) {
      await monitor.check();
      await git.assertUnchanged(repository);
      const run = await runStore.loadRun(runId);
      const recovery = run.inactivityRecovery;
      if (
        run.preparation != null ||
        run.executionProcess !== null ||
        run.executionResource !== null ||
        !isDeepStrictEqual(run.activeTurn, reconciledTurn) ||
        (reconciledTurn !== null &&
          (recovery?.role !== reconciledTurn.role ||
            recovery.checkpoint !== checkpoint ||
            recovery.status !== "expired" ||
            !(recovery.expiryRevision > expiredAfter) ||
            recovery.contentFingerprint !== repository.contentFingerprint))
      )
        throw new RunnerError(
          "Inactivity recovery requires a reconciled turn and retired provider ownership.",
          { code: "ERR_INACTIVITY_RECOVERY" },
        );
      return recovery?.attempt === 1 && recovery.expiryRevision != null;
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
      const hasRetainedRecovery = run.inactivityRecovery !== null;
      const retryRepository = hasRetainedRecovery
        ? catalogRetryRepository
        : undefined;
      catalogRetryRepository = undefined;
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
      const isDeadlineFailure = (cause) =>
        cause === undefined ||
        cause === signal.reason ||
        (signal.aborted && cause?.code === signal.reason?.code);
      async function reserveReconstruction() {
        if (attempt === 2 || expired || signal.aborted) return false;
        if (hasRetainedRecovery) {
          if (request.access !== "read-only" || retryRepository === undefined)
            return false;
          await monitor.check();
          await git.assertUnchanged(retryRepository);
          if (attempt === 2 || expired || signal.aborted) return false;
        }
        attempt = 2;
        reservation = (async () => {
          const repository =
            retryRepository ??
            (await git.snapshot({
              projectPath: run.projectPath,
              allowedPaths: [],
            }));
          await record(
            {
              role,
              checkpoint,
              attempt,
              status: "reconstructing",
              configurationFingerprint: run.providerInactivityFingerprint,
              contentFingerprint: repository.contentFingerprint,
            },
            "reconstructing",
          );
        })();
        await reservation;
        return !expired && !signal.aborted;
      }
      const observedOperation = (value) =>
        runObservedAttempt({
          runStore,
          lease,
          role,
          checkpoint,
          // Exclude startup storage latency. Mid-attempt diagnostics neither
          // suspend nor rearm the existing provider deadline.
          persist: (write, phase) =>
            phase === "start"
              ? watchdog.suspend(() => monitor.persist(write))
              : monitor.persist(write),
          publish,
          // Match the failure precedence below when settling attempt evidence.
          isInterrupted: (cause) =>
            request.signal?.aborted === true ||
            (signal.aborted && isDeadlineFailure(cause)),
          operation: async (attemptRequest) => {
            try {
              return await operation(attemptRequest);
            } finally {
              // Persistence latency after provider settlement is not inactivity.
              await watchdog.close();
            }
          },
          request: value,
        });
      try {
        response = await observedOperation({
          ...request,
          signal,
          onProgress: watchdog.progress,
          onFreshSession: reserveReconstruction,
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
      const deadlineFailure = isDeadlineFailure(failure);
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
    async completed(
      role,
      { repositoryReconciled = true, repository, ...options } = {},
    ) {
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
        const baseline =
          repository ??
          options.patch?.pipelineState?.repositoryBaseline ??
          run.pipelineState.repositoryBaseline;
        await git.assertUnchanged(baseline);
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
