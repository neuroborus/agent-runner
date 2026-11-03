import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { join, relative } from "node:path";
import test from "node:test";

import {
  createExecutionAdapter,
  createFixture,
  PLAN,
  runnerFor,
} from "./support/index.js";

async function externalFixture(t, pipelineId, settings = {}) {
  const f = await createFixture(t);
  const projectPath = join(f.projectPath, "nested");
  const rootPath = join(f.workspace, "infrastructure");
  await Promise.all([mkdir(projectPath), mkdir(rootPath)]);
  const configurationPath = join(rootPath, "agent-runner.json");
  await writeFile(
    configurationPath,
    JSON.stringify({
      schemaVersion: 1,
      infrastructure: {
        schemaVersion: 1,
        placement: "external",
        projectPath: f.projectPath,
        rootPath,
      },
      pipelines: { [pipelineId]: { mode: "lazy", ...settings } },
    }),
  );
  const adapter = createExecutionAdapter();
  return {
    ...f,
    adapter,
    configurationPath,
    input: {
      pipelineId,
      projectPath,
      taskPath: f.taskPath,
      projectConfigurationPath: relative(projectPath, configurationPath),
    },
  };
}

test("polishing preserves a relative external selector when rebasing a Git subdirectory", async (t) => {
  const f = await externalFixture(t, "polishing");
  const runner = runnerFor(f, { codex: f.adapter });
  const { run } = await runner.create(f.input);
  assert.equal(run.projectPath, f.projectPath);
  assert.equal(run.workspace.kind, "git");
  assert.equal(run.pipelineState.settings.mode, "lazy");
  assert.equal(run.projectConfigurationProtection.path, f.configurationPath);
  assert.equal(run.projectConfigurationProtection.projectPath, f.projectPath);
  assert.deepEqual(f.adapter.calls, []);
});

for (const pipelineId of ["plan-authoring", "plan-execution"]) {
  test(`${pipelineId} resolves an external commit override of a runner custom default from a subdirectory`, async (t) => {
    const f = await externalFixture(t, pipelineId, { planKind: "commit" });
    await writeFile(join(f.taskPath, "plan.md"), PLAN);
    const runner = runnerFor(
      f,
      { codex: f.adapter },
      {
        configuration: {
          schemaVersion: 1,
          defaultBackend: "codex",
          pipelines: { [pipelineId]: { planKind: "custom" } },
        },
      },
    );
    assert.equal(
      (await runner.validateBoundary(f.input)).projectPath,
      f.projectPath,
    );
    const { run } = await runner.create(f.input);
    assert.equal(run.projectPath, f.projectPath);
    assert.equal(run.workspace.kind, "git");
    assert.equal(run.pipelineState.settings.planKind, "commit");
    assert.equal(run.projectConfigurationProtection.path, f.configurationPath);
    assert.equal(run.projectConfigurationProtection.projectPath, f.projectPath);
    assert.deepEqual(f.adapter.calls, []);
  });
}
