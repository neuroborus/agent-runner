import assert from "node:assert/strict";
import test from "node:test";

import { normalizeProviderObservation } from "../../src/agents/index.js";
import { createCodexObservations } from "../../src/agents/codex/observations.js";
import { createClaudeObservations } from "../../src/agents/claude/observations.js";

const observation = {
  attempt: 1,
  turn: 1,
  kind: "primary",
  outcome: "completed",
  accounting: "reported",
  last: null,
  cumulative: {
    inputTokens: 100,
    cachedInputTokens: 40,
    cacheWriteInputTokens: null,
    outputTokens: 30,
    reasoningOutputTokens: 20,
    totalTokens: 130,
  },
  cumulativeScope: "attempt",
  inputIncludesCached: true,
  outputIncludesReasoning: true,
  contextCapacity: null,
  commandCompletions: 0,
  compactions: 0,
  factsIncomplete: false,
};

function reportCodexUsage(observer, turnId, inputTokens = 100) {
  const snapshot = {
    ...observation.cumulative,
    inputTokens,
    totalTokens: inputTokens + 30,
    cacheWriteInputTokens: 0,
  };
  observer.notification({
    method: "thread/tokenUsage/updated",
    params: {
      threadId: "thread",
      turnId,
      tokenUsage: { last: snapshot, total: snapshot },
    },
  });
}

test("observation contract rejects unknown fields, contradictory scopes and unsafe numeric evidence", () => {
  const normalized = normalizeProviderObservation(observation);
  assert.ok(Object.isFrozen(normalized));
  assert.ok(Object.isFrozen(normalized.cumulative));
  assert.notEqual(normalized.cumulative, observation.cumulative);
  for (const change of [
    { nativeId: "private" },
    { attempt: 0 },
    { turn: 4 },
    { accounting: "missing" },
    { outcome: "failed" },
    { cumulativeScope: "unknown" },
    { commandCompletions: 16_385 },
    ...[-1, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, "10"].map(
      (contextCapacity) => ({ contextCapacity }),
    ),
    ...[-1, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, "10"].map(
      (inputTokens) => ({
        cumulative: { ...observation.cumulative, inputTokens },
      }),
    ),
    { cumulative: { ...observation.cumulative, cachedInputTokens: 101 } },
    { cumulative: { ...observation.cumulative, reasoningOutputTokens: 31 } },
  ])
    assert.throws(
      () => normalizeProviderObservation({ ...observation, ...change }),
      TypeError,
    );
  assert.equal(
    normalizeProviderObservation({
      ...observation,
      contextCapacity: Number.MAX_SAFE_INTEGER,
    }).contextCapacity,
    Number.MAX_SAFE_INTEGER,
  );
});

test("Codex observation correlation is bounded, keeps late prior-turn usage, and seals once", () => {
  const values = [];
  const observer = createCodexObservations(
    (value) => values.push(value),
    1,
    false,
  );
  const begin = (id) => {
    observer.begin("turn/start", { threadId: "thread" });
    observer.response("turn/start", { turn: { id } });
  };
  const usage = (turnId) => reportCodexUsage(observer, turnId);
  begin("first");
  observer.notification({
    method: "turn/completed",
    params: {
      threadId: "thread",
      turn: { id: "first", status: "failed", items: [] },
    },
  });
  begin("second");
  usage("first");
  usage("unrelated");
  observer.seal();
  usage("second");
  observer.seal();
  assert.equal(values.length, 2);
  assert.equal(values[0].accounting, "incomplete");
  assert.equal(values[0].outcome, "failed");
  assert.equal(values[1].accounting, "missing");
  const bounded = createCodexObservations(
    (value) => values.push(value),
    2,
    true,
  );
  bounded.begin("turn/start", { threadId: "thread" });
  for (let index = 0; index < 1025; index++)
    bounded.notification({
      method: "item/completed",
      params: {
        threadId: "thread",
        turnId: "bounded",
        item: {
          id: `item-${index}`,
          type: "commandExecution",
          command: "private",
          status: "completed",
        },
      },
    });
  bounded.response("turn/start", { turn: { id: "bounded" } });
  bounded.seal();
  assert.equal(values[2].commandCompletions, 1024);
  assert.equal(values[2].factsIncomplete, true);
});

test("Codex compaction binds the validated completion and counts a late native item once", () => {
  const values = [];
  const observer = createCodexObservations((value) => values.push(value), 1);
  observer.begin("thread/compact/start", { threadId: "thread" });
  observer.notification({
    method: "turn/started",
    params: {
      threadId: "thread",
      turn: { id: "unrelated", status: "inProgress", items: [] },
    },
  });
  reportCodexUsage(observer, "unrelated", 200);
  observer.notification({
    method: "turn/completed",
    params: {
      threadId: "thread",
      turn: { id: "compaction", status: "completed", items: [] },
    },
  });
  reportCodexUsage(observer, "compaction");
  observer.confirmCompaction("thread", "compaction");
  observer.begin("turn/start", { threadId: "thread" });
  observer.response("turn/start", { turn: { id: "recovery" } });
  for (let index = 0; index < 2; index++)
    observer.notification({
      method: "item/completed",
      params: {
        threadId: "thread",
        turnId: "compaction",
        item: { id: "compaction-item", type: "contextCompaction" },
      },
    });
  observer.seal();
  assert.equal(values[0].outcome, "completed");
  assert.equal(values[0].accounting, "reported");
  assert.equal(values[0].cumulative.inputTokens, 100);
  assert.equal(values[0].compactions, 1);
  assert.equal(values[1].compactions, 0);
});

test("Codex cumulative usage respects turn order while accepting matching late usage", () => {
  for (const [second, late, expected] of [
    [50, undefined, [100, null]],
    [200, 150, [150, 200]],
    [200, 250, [100, 200]],
  ]) {
    const values = [];
    const observer = createCodexObservations((value) => values.push(value), 1);
    for (const [id, inputTokens] of [
      ["first", 100],
      ["second", second],
    ]) {
      observer.begin("turn/start", { threadId: "thread" });
      observer.response("turn/start", { turn: { id } });
      reportCodexUsage(observer, id, inputTokens);
    }
    if (late !== undefined) reportCodexUsage(observer, "first", late);
    observer.seal();
    assert.deepEqual(
      values.map(({ cumulative }) => cumulative?.inputTokens ?? null),
      expected,
    );
  }
});

test("Codex rejects last-request counters above cumulative usage without replacing accepted evidence", () => {
  for (const field of Object.keys(observation.cumulative)) {
    const values = [];
    const observer = createCodexObservations((value) => values.push(value), 1);
    observer.begin("turn/start", { threadId: "thread" });
    observer.response("turn/start", { turn: { id: "turn" } });
    reportCodexUsage(observer, "turn");
    observer.notification({
      method: "turn/completed",
      params: {
        threadId: "thread",
        turn: { id: "turn", status: "completed", items: [] },
      },
    });
    const cumulative = { ...observation.cumulative, cacheWriteInputTokens: 0 };
    const last = { ...cumulative, [field]: cumulative[field] + 1 };
    observer.notification({
      method: "thread/tokenUsage/updated",
      params: {
        threadId: "thread",
        turnId: "turn",
        tokenUsage: { last, total: cumulative },
      },
    });
    observer.seal();
    assert.deepEqual(values[0].last, cumulative, field);
    assert.deepEqual(values[0].cumulative, cumulative, field);
    assert.equal(values[0].accounting, "incomplete", field);
  }
});

test("Claude observations reject malformed usage and retain incomplete failed accounting", () => {
  const values = [];
  for (const usage of [
    { input_tokens: Number.MAX_SAFE_INTEGER + 1 },
    { input_tokens: 0, output_tokens: 2 },
  ]) {
    const observer = createClaudeObservations(
      (value) => values.push(value),
      1,
      false,
    );
    observer.result({ is_error: true, usage });
    observer.seal(false);
    observer.result({ is_error: false, usage: { input_tokens: 99 } });
    observer.seal(true);
  }
  assert.equal(values.length, 2);
  assert.equal(values[0].accounting, "missing");
  assert.equal(values[1].accounting, "incomplete");
  assert.equal(values[1].outcome, "failed");
  assert.equal(values[1].cumulative.inputTokens, 0);
});
