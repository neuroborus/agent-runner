import { createInactivityCoordinator } from "../../src/runner/inactivity.js";
import { providerInactivityFingerprint } from "../../src/state/index.js";

// Use the real coordinator; only persistence and the clock are in memory.
export async function attachInactivity(fixture, { onRecord } = {}) {
  const { runtime } = fixture;
  const transition = runtime.transition.bind(runtime);
  const finish = runtime.finishAgentTurn.bind(runtime);
  await transition({
    providerInactivityTimeoutMs: 100,
    providerInactivityFingerprint: providerInactivityFingerprint(100),
    inactivityRecovery: null,
    executionProcess: null,
    executionResource: null,
  });
  let fire;
  let responseRole;
  const events = [];
  const coordinator = createInactivityCoordinator({
    runId: fixture.currentRun.runId,
    lease: {},
    initialRun: fixture.currentRun,
    git: runtime.git,
    monitor: { async check() {} },
    timers: {
      setTimeout(callback) {
        fire = callback;
        return callback;
      },
      clearTimeout(handle) {
        if (fire === handle) fire = undefined;
      },
    },
    publish: async (event) => events.push(event),
    runStore: {
      async loadRun() {
        return fixture.currentRun;
      },
      async recordInactivity(_lease, recovery, kind) {
        const next = await transition({
          inactivityRecovery: {
            ...recovery,
            reconstructionRevision:
              kind === "reconstructing"
                ? fixture.currentRun.revision + 1
                : (fixture.currentRun.inactivityRecovery
                    ?.reconstructionRevision ?? null),
          },
        });
        await onRecord?.(next);
        return next;
      },
      async finishAgentTurn(_lease, turn) {
        return finish(turn);
      },
      async completeInactivityTurn(_lease, _role, { patch } = {}) {
        return transition({ ...patch, inactivityRecovery: null });
      },
    },
  });
  runtime.inactivity = coordinator;
  async function complete(options) {
    if (responseRole === undefined) return;
    const next = await coordinator.completed(responseRole, options);
    responseRole = undefined;
    return next;
  }
  runtime.transition = async (patch, options) =>
    (await complete({ patch })) ?? transition(patch, options);
  runtime.finishAgentTurn = async (turn, options) => {
    await complete(options);
    return finish(turn);
  };
  for (const [role, adapter] of Object.entries(runtime.adapters)) {
    const run = adapter.run.bind(adapter);
    adapter.run = async (request) => {
      const result = await coordinator.invoke(role, run, request);
      responseRole = role;
      return result;
    };
  }
  return {
    events,
    expire(request, { commit = false } = {}) {
      return new Promise((resolve, reject) => {
        request.signal.addEventListener(
          "abort",
          () => {
            const cause = request.signal.reason;
            if (commit) {
              cause.effectStarted = false;
              cause.failure = { commitExecutor: "not_started" };
            }
            reject(cause);
          },
          { once: true },
        );
        fire();
      });
    },
  };
}
