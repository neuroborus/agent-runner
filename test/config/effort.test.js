import assert from "node:assert/strict";
import test from "node:test";

import {
  parseProjectConfiguration,
  parseRunnerConfiguration,
  resolvePipelineConfiguration,
} from "../../src/config/index.js";

const VALUES = ["current", "low", "medium", "high", "xhigh"];

test("root and project configuration strictly validate every effort declaration", () => {
  const root = { schemaVersion: 1, defaultBackend: "codex" };
  for (const parse of [
    parseRunnerConfiguration,
    (source) => parseProjectConfiguration(source, root),
  ]) {
    for (const effort of VALUES) {
      const configuration = parse(
        JSON.stringify({
          schemaVersion: 1,
          defaultEffort: effort,
          pipelines: { "plan-execution": { roles: { worker: { effort } } } },
        }),
      );
      assert.equal(configuration.defaultEffort, effort);
      assert.equal(
        configuration.pipelines["plan-execution"].roles.worker.effort,
        effort,
      );
    }
    for (const effort of [null, "", "max", "HIGH", " high", 1, {}, ["high"]]) {
      assert.throws(() =>
        parse(JSON.stringify({ schemaVersion: 1, defaultEffort: effort })),
      );
      assert.throws(() =>
        parse(
          JSON.stringify({
            schemaVersion: 1,
            pipelines: {
              "plan-execution": {
                mode: "lazy",
                roles: { reviewer: { effort } },
              },
            },
          }),
        ),
      );
    }
  }
  assert.equal(
    parseRunnerConfiguration(JSON.stringify(root)).defaultEffort,
    "current",
  );
  assert.equal(
    Object.hasOwn(
      parseProjectConfiguration('{"schemaVersion":1}', root),
      "defaultEffort",
    ),
    false,
  );
});

test("effort follows every precedence level including explicit current", () => {
  for (const backend of ["codex", "claude"]) {
    for (let winner = 0; winner < 6; winner += 1) {
      for (const effort of VALUES) {
        const layers = Array.from({ length: 6 }, (_, index) =>
          index < winner ? undefined : index === winner ? effort : "low",
        );
        const runner = {
          schemaVersion: 1,
          defaultBackend: backend,
          defaultEffort: layers[5],
          pipelines: {
            "plan-execution": { roles: { worker: { effort: layers[4] } } },
          },
        };
        const project = {
          schemaVersion: 1,
          defaultEffort: layers[3],
          pipelines: {
            "plan-execution": { roles: { worker: { effort: layers[2] } } },
          },
        };
        const resolved = resolvePipelineConfiguration(
          "plan-execution",
          runner,
          { worker: { effort: layers[0] } },
          { effort: layers[1] },
          null,
          project,
        );
        assert.equal(
          resolved.roles.worker.effort,
          effort,
          `${backend} layer ${winner}`,
        );
      }
    }
    const resolved = resolvePipelineConfiguration("plan-execution", {
      schemaVersion: 1,
      defaultBackend: backend,
    });
    assert.ok(
      Object.values(resolved.roles).every(({ effort }) => effort === "current"),
    );
  }
});

test("lazy effort resolution validates inactive vocabulary without resolving inactive providers", () => {
  for (const [pipelineId, primary] of [
    ["plan-authoring", "planner"],
    ["plan-execution", "worker"],
    ["polishing", "worker"],
  ]) {
    const runner = {
      schemaVersion: 1,
      defaultEffort: "xhigh",
      pipelines: {
        [pipelineId]: {
          mode: "lazy",
          roles: {
            [primary]: { backend: "codex" },
            reviewer: { effort: "high" },
          },
        },
      },
    };
    const resolved = resolvePipelineConfiguration(pipelineId, runner);
    assert.deepEqual(Object.keys(resolved.roles), [primary]);
    assert.equal(resolved.roles[primary].effort, "xhigh");
    assert.equal(runner.pipelines[pipelineId].roles.reviewer.effort, "high");
    assert.throws(() =>
      resolvePipelineConfiguration(pipelineId, runner, {
        reviewer: { effort: "max" },
      }),
    );
    assert.throws(() =>
      resolvePipelineConfiguration(pipelineId, runner, {}, { effort: "max" }),
    );
  }
});
