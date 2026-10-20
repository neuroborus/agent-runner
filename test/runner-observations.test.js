import assert from "node:assert/strict";
import test from "node:test";

import { runObservedAttempt } from "../src/runner/observations.js";
import { createInactivityCoordinator } from "../src/runner/inactivity.js";
import { createStopMonitor } from "../src/runner/stops.js";

const missing = {
  attempt: 1,
  turn: 1,
  kind: "primary",
  outcome: "incomplete",
  accounting: "missing",
  last: null,
  cumulative: null,
  cumulativeScope: "thread",
  inputIncludesCached: true,
  outputIncludesReasoning: true,
  contextCapacity: null,
  commandCompletions: 0,
  compactions: 0,
  factsIncomplete: false,
};
function fixture() {
  const writes = [];
  const starts = [];
  return {
    writes,
    starts,
    lease: {},
    role: "worker",
    checkpoint: "implement:workspace-write:1",
    runStore: {
      async startObservationAttempt(lease, selected, measurements) {
        starts.push(measurements);
        return {
          revision: 3,
          observations: {
            attempts: [
              {
                id: 3,
                ...selected,
                status: "active",
                accounting: "incomplete",
                incomplete: false,
                observations: [],
                measurements,
              },
            ],
          },
        };
      },
      async recordObservationBatch(lease, identity, records, options) {
        writes.push({ identity, records, options });
      },
    },
  };
}

test("observations coalesce until fallback and terminal boundaries, reject payloads, and ignore late callbacks", async () => {
  const f = fixture();
  let stale;
  let fallback = 0;
  const result = await runObservedAttempt({
    ...f,
    request: {
      onFreshSession: async () => {
        fallback++;
        return true;
      },
    },
    operation: async ({ onObservation, onFreshSession }) => {
      stale = onObservation;
      for (let index = 0; index < 100; index++) onObservation(missing);
      onObservation({ ...missing, raw: "private payload" });
      assert.equal(f.writes.length, 0);
      assert.equal(await onFreshSession(), true);
      assert.equal(f.writes.length, 1);
      onObservation({ ...missing, attempt: 2, kind: "recovery" });
      return "response";
    },
  });
  assert.equal(result, "response");
  assert.equal(fallback, 1);
  assert.equal(f.writes.length, 2);
  assert.deepEqual(f.writes[1].identity, {
    id: 3,
    role: f.role,
    checkpoint: f.checkpoint,
  });
  assert.equal(f.writes[0].records.length, 1);
  assert.equal(f.writes[1].records.length, 2);
  assert.deepEqual(f.writes[1].options, {
    status: "completed",
    incomplete: true,
    resultBytes: null,
    structuredResultBytes: null,
  });
  stale({ ...missing, turn: 2 });
  assert.equal(f.writes.length, 2);
  assert.ok(!JSON.stringify(f.writes).includes("private payload"));
});

test("runner measures supplied UTF-8 payloads without retaining content or inventing referenced-file reads", async () => {
  const f = fixture();
  const schema = { type: "object", description: "Résumé" };
  const structured = { summary: "✓" };
  await runObservedAttempt({
    ...f,
    request: {
      prompt: "Résumé; inspect a referenced file.",
      recoveryPrompt: "Full supplied context ✓",
      schema,
      session: { id: "private-native-id", mode: "continue" },
    },
    operation: async ({ onObservation, onFreshSession }) => {
      onObservation({ ...missing, outcome: "failed" });
      await onFreshSession();
      onObservation({ ...missing, turn: 2, kind: "compaction" });
      onObservation({ ...missing, attempt: 2, kind: "recovery" });
      return { output: "✓ output", structured, sessionId: "private-native-id" };
    },
  });
  assert.deepEqual(f.starts, [
    {
      promptBytes: Buffer.byteLength("Résumé; inspect a referenced file."),
      recoveryPromptBytes: Buffer.byteLength("Full supplied context ✓"),
      schemaBytes: Buffer.byteLength(JSON.stringify(schema)),
      resultBytes: null,
      structuredResultBytes: null,
      referencedFileCount: null,
      referencedFileBytes: null,
    },
  ]);
  assert.equal(f.writes[1].options.resultBytes, Buffer.byteLength("✓ output"));
  assert.equal(
    f.writes[1].options.structuredResultBytes,
    Buffer.byteLength(JSON.stringify(structured)),
  );
  assert.deepEqual(
    f.writes[1].records.map(({ attempt, turn, kind }) => [attempt, turn, kind]),
    [
      [1, 1, "primary"],
      [1, 2, "compaction"],
      [2, 1, "recovery"],
    ],
  );
  assert.doesNotMatch(
    JSON.stringify([f.starts, f.writes]),
    /Résumé|supplied context|native-id|✓ output/u,
  );
});

test("terminal evidence flushes on failure and interruption while persistence errors preserve failure precedence", async () => {
  for (const aborted of [false, true]) {
    const f = fixture(),
      controller = new AbortController();
    const failure = Object.assign(new Error("established safety failure"), {
      code: "ERR_EXECUTION_OWNERSHIP",
      effectStarted: true,
    });
    await assert.rejects(
      runObservedAttempt({
        ...f,
        request: { signal: controller.signal },
        operation: async ({ onObservation }) => {
          onObservation(missing);
          if (aborted) controller.abort(failure);
          throw failure;
        },
      }),
      (cause) => cause === failure,
    );
    assert.equal(
      f.writes[0].options.status,
      aborted ? "interrupted" : "failed",
    );
    assert.deepEqual(f.writes[0].records, [missing]);
    f.runStore.recordObservationBatch = async () => {
      throw new Error("private storage diagnostic");
    };
    if (aborted) {
      await assert.rejects(
        runObservedAttempt({
          ...f,
          request: { signal: controller.signal },
          operation: async () => "late response",
        }),
        (cause) => cause === failure,
      );
    }
    await assert.rejects(
      runObservedAttempt({
        ...f,
        request: {},
        operation: async () => {
          throw failure;
        },
      }),
      (cause) => cause === failure,
    );
    await assert.rejects(
      runObservedAttempt({
        ...f,
        request: {},
        operation: async () => "response",
      }),
      {
        code: "ERR_OBSERVATION_PERSISTENCE",
        message: "Attempt observations could not be persisted.",
      },
    );
  }
});

test("observation persistence serializes with operator stops under the same execution owner", async () => {
  const f = fixture();
  const entered = Promise.withResolvers();
  const release = Promise.withResolvers();
  const changed = Promise.withResolvers();
  const aborted = Promise.withResolvers();
  const events = [];
  let current = {
    revision: 1,
    activeTurn: { role: f.role },
    inactivityRecovery: null,
    stopRequest: null,
    providerInactivityTimeoutMs: 1_800_000,
  };
  const start = f.runStore.startObservationAttempt;
  Object.assign(f.runStore, {
    async loadRun() {
      return current;
    },
    async waitForRunChange() {
      return changed.promise;
    },
    async recordStopActivity() {
      events.push("stop");
      return current;
    },
    async startObservationAttempt(...args) {
      entered.resolve();
      await release.promise;
      events.push("started");
      return start(...args);
    },
    async recordObservationBatch(lease, identity, records, options) {
      events.push(options.status);
    },
  });
  const monitor = createStopMonitor({
    ...f,
    runId: "run",
    publish: async () => {},
  });
  const coordinator = createInactivityCoordinator({
    ...f,
    runId: "run",
    monitor,
  });
  await coordinator.before({ role: f.role, checkpoint: f.checkpoint });
  const execution = monitor.invoke((request) => {
    request.signal.addEventListener("abort", () => aborted.resolve(), {
      once: true,
    });
    return coordinator.invoke(
      f.role,
      async ({ signal }) => signal.throwIfAborted(),
      request,
    );
  }, {});
  await entered.promise;
  current = {
    ...current,
    revision: 2,
    stopRequest: { effectiveTiming: "immediate", reconciledRevision: null },
  };
  changed.resolve(current);
  await aborted.promise;
  release.resolve();
  await assert.rejects(execution, { code: "ERR_OPERATOR_STOP_BEFORE_COMMIT" });
  await monitor.close();
  assert.deepEqual(events, ["started", "stop", "interrupted"]);
});
