import assert from "node:assert/strict";
import test from "node:test";

import {
  createClaudeAdapter,
  createCodexAdapter,
  PROVIDER_REGISTRY,
} from "../../src/agents/index.js";

test("registered providers validate portable effort separately from model IDs", () => {
  for (const backend of PROVIDER_REGISTRY.ids) {
    for (const effort of [
      undefined,
      "current",
      "low",
      "medium",
      "high",
      "xhigh",
    ]) {
      assert.doesNotThrow(() =>
        PROVIDER_REGISTRY.validateExecutionOptions(backend, { effort }),
      );
    }
    for (const effort of [
      null,
      "",
      "max",
      "minimal",
      "HIGH",
      " high",
      1,
      {},
      ["high"],
    ]) {
      assert.throws(() =>
        PROVIDER_REGISTRY.validateExecutionOptions(backend, { effort }),
      );
    }
    for (const model of [
      "gpt-5.6-sol xhigh",
      "sonnet high",
      "model\thigh",
      " model",
    ]) {
      assert.throws(() =>
        PROVIDER_REGISTRY.validateExecutionOptions(backend, { model }),
      );
    }
  }
});

test("invalid effort and combined model identifiers fail before provider probing", async () => {
  for (const createAdapter of [createClaudeAdapter, createCodexAdapter]) {
    let calls = 0;
    const adapter = createAdapter({
      execute: async () => {
        calls += 1;
        throw new Error("Unexpected provider call");
      },
    });
    for (const selection of [
      { effort: "max" },
      { effort: null },
      { effort: " high" },
      { model: "gpt-5.6-sol xhigh" },
    ]) {
      assert.throws(() => adapter.probe(selection), /Effort|Model/u);
      await assert.rejects(
        adapter.run({
          cwd: process.cwd(),
          access: "read-only",
          prompt: "Inspect.",
          ...selection,
        }),
        /Effort|Model/u,
      );
    }
    assert.equal(calls, 0);
  }
});
