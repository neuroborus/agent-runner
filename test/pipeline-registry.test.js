import assert from "node:assert/strict";
import test from "node:test";

import * as planAuthoringApi from "@agent-runner/plan-authoring";
import * as planExecutionApi from "@agent-runner/plan-execution";

import { getPipeline, listPipelines } from "../src/index.js";

test("registry exposes explicit immutable pipeline descriptors", () => {
  const pipelines = listPipelines();

  assert.deepEqual(
    pipelines.map((pipeline) => pipeline.id),
    ["plan-authoring", "plan-execution"],
  );

  for (const pipeline of pipelines) {
    assert.equal(getPipeline(pipeline.id), pipeline);
    assert.ok(Number.isSafeInteger(pipeline.stateVersion));
    assert.ok(pipeline.stateVersion > 0);
    assert.ok(Object.isFrozen(pipeline));
    assert.ok(Object.isFrozen(pipeline.runOptions));
    assert.ok(Object.isFrozen(pipeline.requiredRunOptions));
    for (const option of pipeline.requiredRunOptions) {
      assert.ok(pipeline.runOptions.includes(option));
    }
  }
});

test("pipelines own their pipeline-specific run options", () => {
  assert.deepEqual(getPipeline("plan-authoring").runOptions, [
    "project",
    "task",
    "planner",
    "reviewer",
  ]);
  assert.deepEqual(getPipeline("plan-execution").runOptions, [
    "project",
    "task",
    "worker",
    "reviewer",
    "arbiter",
  ]);
  assert.deepEqual(getPipeline("plan-authoring").requiredRunOptions, [
    "project",
    "task",
  ]);
  assert.deepEqual(getPipeline("plan-execution").requiredRunOptions, [
    "project",
    "task",
  ]);
  assert.equal(getPipeline("unknown"), undefined);
});

test("pipelines do not duplicate the shared validation API", () => {
  assert.equal("assertCommitSubject" in planAuthoringApi, false);
  assert.equal("assertCommitSubject" in planExecutionApi, false);
});
