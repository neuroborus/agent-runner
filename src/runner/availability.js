import { setTimeout } from "node:timers/promises";

import {
  AgentBoundaryError,
  AVAILABILITY_REASONS,
  normalizeFailureRecord,
} from "../agents/index.js";
import { availabilityActivity } from "../state/index.js";
import { RunnerError } from "./input.js";

// Only normalized provider evidence crosses this boundary. Repository and effect
// reconciliation remain prerequisites owned by the calling checkpoint.
export function createAvailabilityCoordinator({
  runId,
  lease,
  runStore,
  providers,
  git,
  publish,
  monitor,
  clock = Date.now,
  wait = (delay, signal) => setTimeout(delay, undefined, { signal }),
  validateRun,
  initialRun,
}) {
  let pending = initialRun?.availabilityRetry !== null;
  const failureClasses = [
    ...new Set(
      providers.list().flatMap(({ failures }) => [...failures.classes]),
    ),
  ];
  function failure(value, backend) {
    try {
      const record = normalizeFailureRecord(
        value,
        backend === undefined
          ? failureClasses
          : [...providers.get(backend).failures.classes],
      );
      return record.availabilityReason === undefined ? null : record;
    } catch {
      return null;
    }
  }

  function eligible(cause) {
    return (
      cause instanceof AgentBoundaryError &&
      cause.recoverable === true &&
      failure(cause.failure) !== null
    );
  }

  async function guarded(operation) {
    try {
      return await operation();
    } catch (cause) {
      throw new RunnerError(
        "Availability recovery retains its durable checkpoint.",
        {
          code: "ERR_AVAILABILITY_RECOVERY",
          cause,
        },
      );
    }
  }

  return Object.freeze({
    eligible,
    preEffect(cause) {
      return eligible(cause) &&
        cause.failure.checkpoint === "commit" &&
        cause.failure.commitExecutor === "not_started"
        ? Object.freeze({
            reason: cause.failure.availabilityReason,
            commitExecutor: "not_started",
          })
        : null;
    },
    async schedule({
      cause,
      proof,
      role,
      checkpoint,
      repository,
      pipelineState,
    }) {
      return guarded(async () => {
        await monitor.check();
        const run = await runStore.loadRun(runId);
        const record = failure(
          eligible(cause) ? cause.failure : null,
          run.roles[role]?.backend,
        );
        const reason =
          proof === undefined ? record?.availabilityReason : proof?.reason;
        if (
          !AVAILABILITY_REASONS.includes(reason) ||
          (proof !== undefined &&
            (Object.keys(proof).length !== 2 ||
              proof.commitExecutor !== "not_started" ||
              !checkpoint.startsWith("commit:")))
        ) {
          throw new Error("Availability evidence is invalid.");
        }
        await git.assertUnchanged(repository);
        validateRun({
          ...run,
          ...(pipelineState === undefined ? {} : { pipelineState }),
        });
        const next = await runStore.scheduleAvailabilityRetry(
          lease,
          {
            role,
            checkpoint,
            reason,
            contentFingerprint: repository.contentFingerprint,
            expectedRevision: run.revision,
          },
          { pipelineState },
        );
        pending = true;
        await publish(
          availabilityActivity(next.availabilityRetry, "retry-scheduled"),
          next,
        );
        return next;
      });
    },
    async before({ role, checkpoint, repository }) {
      return guarded(async () => {
        let run = await runStore.loadRun(runId);
        const episode = run.availabilityRetry;
        pending = episode != null;
        if (episode == null) return run;
        if (episode.role !== role || episode.checkpoint !== checkpoint) {
          throw new Error("Availability checkpoint changed.");
        }
        await monitor.wait(async (signal) => {
          for (;;) {
            const now = clock();
            if (!Number.isFinite(now))
              throw new Error("Availability clock is invalid.");
            const remaining = Date.parse(episode.nextRetryAt) - now;
            if (remaining <= 0) return;
            await wait(
              Math.min(remaining, run.availabilityPolicy.maxDelayMs),
              signal,
            );
            signal.throwIfAborted();
          }
        });
        await git.assertUnchanged(repository);
        run = await runStore.transitionRun(
          lease,
          {},
          {
            activity: availabilityActivity(episode, "retry-started"),
          },
        );
        await publish(availabilityActivity(episode, "retry-started"), run);
        return run;
      });
    },
    async completed(role, { patch, expectedRevision } = {}) {
      if (!pending) return;
      return guarded(async () => {
        const run = await runStore.loadRun(runId);
        if (run.availabilityRetry == null) {
          pending = false;
          return;
        }
        const next = await runStore.completeAvailabilityTurn(lease, role, {
          patch,
          expectedRevision,
        });
        pending = false;
        await publish(
          availabilityActivity(run.availabilityRetry, "recovered"),
          next,
        );
        return next;
      });
    },
  });
}
