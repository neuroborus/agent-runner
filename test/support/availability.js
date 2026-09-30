import { randomUUID } from "node:crypto";

import {
  AgentBoundaryError,
  PROVIDER_REGISTRY,
} from "../../src/agents/index.js";
import { createAvailabilityCoordinator } from "../../src/runner/availability.js";
import { availabilityDelayMs } from "../../src/state/index.js";

export function availabilityFailure({ commit = false } = {}) {
  return new AgentBoundaryError(
    { code: "ERR_BACKEND_UNAVAILABLE" },
    {
      failureClass: "turn_server_overloaded",
      checkpoint: commit ? "commit" : "turn",
      outcome: "rejected",
      effect: "possible",
      retry: "transient",
      availabilityReason: "temporarily_overloaded",
      ...(commit ? { commitExecutor: "not_started" } : {}),
    },
  );
}

// Pipeline routing uses the actual coordinator with in-memory persistence;
// durable journal and lease behavior is covered separately by runner tests.
export function attachAvailability(
  fixture,
  { onSchedule, onWait, onCompleted } = {},
) {
  const { runtime } = fixture;
  const transition = runtime.transition.bind(runtime);
  let responseRole = null;
  let now = 0;
  const scheduled = [];
  const delays = [];
  const coordinator = createAvailabilityCoordinator({
    runId: fixture.currentRun.runId,
    lease: {},
    providers: PROVIDER_REGISTRY,
    git: runtime.git,
    validateRun() {},
    publish: async () => {},
    monitor: {
      async check() {},
      async wait(operation) {
        return operation(new AbortController().signal);
      },
    },
    clock: () => now,
    wait: async (delay) => {
      delays.push(delay);
      now += delay;
      await onWait?.();
    },
    runStore: {
      async loadRun() {
        return fixture.currentRun;
      },
      async transitionRun(_lease, patch, options) {
        return transition(patch, options);
      },
      async completeAvailabilityTurn(_lease, _role, { patch } = {}) {
        const next = await transition({ ...patch, availabilityRetry: null });
        await onCompleted?.(next);
        return next;
      },
      async scheduleAvailabilityRetry(_lease, input, { pipelineState } = {}) {
        const previous = fixture.currentRun.availabilityRetry;
        const policy = { initialDelayMs: 5000, maxDelayMs: 7000 };
        const attempt = (previous?.attempt ?? 0) + 1;
        const delayMs = availabilityDelayMs(policy, attempt);
        const episode = {
          ...input,
          id: previous?.id ?? randomUUID(),
          attempt,
          delayMs,
          nextRetryAt: new Date(now + delayMs).toISOString(),
        };
        const next = await transition({
          availabilityPolicy: policy,
          availabilityRetry: episode,
          ...(pipelineState === undefined ? {} : { pipelineState }),
        });
        scheduled.push(next);
        await onSchedule?.(next);
        return next;
      },
    },
  });
  runtime.availability = coordinator;
  async function complete(options) {
    if (responseRole === null) return undefined;
    const next = await coordinator.completed(responseRole, options);
    responseRole = null;
    return next;
  }
  runtime.transition = async (patch, options) => {
    const completed = await complete({ patch });
    return completed ?? transition(patch, options);
  };
  const finish = runtime.finishAgentTurn.bind(runtime);
  runtime.finishAgentTurn = async (turn) => {
    await complete();
    return finish(turn);
  };
  for (const [role, adapter] of Object.entries(runtime.adapters)) {
    const run = adapter.run.bind(adapter);
    adapter.run = async (request) => {
      const result = await run(request);
      responseRole = role;
      return result;
    };
  }
  return { scheduled, delays };
}
