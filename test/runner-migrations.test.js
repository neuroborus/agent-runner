import assert from "node:assert/strict";
import test from "node:test";
import { preparePipelineMigration, RunnerError } from "../src/runner/index.js";

test("applies explicit pipeline migrations in order without mutating input", () => {
  const run = Object.freeze({
    runId: "55555555-5555-4555-8555-555555555555",
    pipelineId: "test-pipeline",
    pipelineStateVersion: 1,
    pipelineState: Object.freeze({ value: 1 }),
  });
  const versions = [];
  const pipeline = {
    id: "test-pipeline",
    stateVersion: 3,
    migrations: {
      1(current) {
        versions.push(current.pipelineStateVersion);
        return { ...current.pipelineState, value: 2 };
      },
      2(current) {
        versions.push(current.pipelineStateVersion);
        return { ...current.pipelineState, value: 3 };
      },
    },
    workflow: {
      validateRun(current) {
        assert.equal(current.pipelineStateVersion, 3);
        assert.equal(current.pipelineState.value, 3);
      },
    },
  };

  const migrated = preparePipelineMigration(run, pipeline);
  assert.deepEqual(versions, [1, 2]);
  assert.equal(migrated.pipelineStateVersion, 3);
  assert.deepEqual(run.pipelineState, { value: 1 });
  assert.throws(
    () =>
      preparePipelineMigration(run, {
        ...pipeline,
        migrations: {},
      }),
    (error) =>
      error instanceof RunnerError &&
      error.code === "ERR_PIPELINE_VERSION_SKEW",
  );
  assert.throws(
    () =>
      preparePipelineMigration(run, {
        ...pipeline,
        workflow: {
          validateRun() {
            throw new Error("Invalid migrated shape.");
          },
        },
      }),
    (error) =>
      error instanceof RunnerError &&
      error.code === "ERR_PIPELINE_MIGRATION_FAILED",
  );
});
