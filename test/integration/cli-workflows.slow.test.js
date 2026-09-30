import assert from "node:assert/strict";
import { readFile, readdir, writeFile } from "node:fs/promises";
import { isAbsolute, join, relative, sep } from "node:path";
import test from "node:test";

import { main } from "../../src/index.js";
import {
  createBackend,
  fixture,
  gitOutput,
  ONE_STEP_PLAN,
  runtime,
  TWO_STEP_PLAN,
} from "./support/index.js";

function sink() {
  let value = "";
  return {
    stream: {
      write(chunk) {
        value += chunk;
      },
    },
    value() {
      return value;
    },
  };
}

async function onlyRun(runStore) {
  const [runId] = await readdir(join(runStore.rootPath, "runs"));
  return runStore.loadRun(runId);
}

function outside(parent, child) {
  const path = relative(parent, child);
  return path === ".." || path.startsWith(`..${sep}`);
}

test("writes one plan artifact without modifying Git", async (t) => {
  const paths = await fixture(t, { plan: null });
  const codex = createBackend("codex");
  const { runner, runStore } = runtime(
    paths,
    { codex },
    { schemaVersion: 1, defaultBackend: "codex" },
  );
  const stdout = sink();
  const stderr = sink();

  const exitCode = await main(
    [
      "run",
      "plan-authoring",
      "--project",
      paths.projectPath,
      "--task",
      paths.taskPath,
    ],
    { runner, stderr: stderr.stream, stdout: stdout.stream },
  );

  assert.equal(exitCode, 0);
  assert.equal(stderr.value(), "");
  assert.match(stdout.value(), /State: DONE/u);
  assert.equal(
    await readFile(join(paths.taskPath, "plan.md"), "utf8"),
    TWO_STEP_PLAN,
  );
  assert.equal((await onlyRun(runStore)).pipelineState.workflowState, "DONE");
  assert.ok(codex.calls.every(({ access }) => access === "read-only"));
  assert.equal(
    await gitOutput(paths.projectPath, ["status", "--porcelain"]),
    "",
  );
  assert.equal(
    await gitOutput(paths.projectPath, ["log", "-1", "--pretty=%s"]),
    "chore(test): initialize",
  );
});

test("stages one polishing handoff without committing", async (t) => {
  const paths = await fixture(t, { plan: null });
  await writeFile(
    join(paths.projectPath, "src", "base.js"),
    "export const base = 2;\n",
  );
  const initialHead = await gitOutput(paths.projectPath, ["rev-parse", "HEAD"]);
  const codex = createBackend("codex");
  const { runner, runStore } = runtime(
    paths,
    { codex },
    { schemaVersion: 1, defaultBackend: "codex" },
  );
  const stdout = sink();
  const stderr = sink();

  const exitCode = await main(
    [
      "run",
      "polishing",
      "--project",
      paths.projectPath,
      "--task",
      paths.taskPath,
    ],
    { runner, stderr: stderr.stream, stdout: stdout.stream },
  );

  assert.equal(exitCode, 0, stderr.value());
  assert.equal(stderr.value(), "");
  assert.match(stdout.value(), /Pipeline: polishing/u);
  assert.match(stdout.value(), /State: DONE/u);
  assert.doesNotMatch(stdout.value(), /^Plan:/mu);
  assert.equal((await onlyRun(runStore)).pipelineState.workflowState, "DONE");
  assert.equal(
    codex.calls.some(({ access }) => access === "local-commit"),
    false,
  );
  assert.equal(
    await gitOutput(paths.projectPath, ["rev-parse", "HEAD"]),
    initialHead,
  );
  assert.equal(
    await gitOutput(paths.projectPath, ["status", "--porcelain"]),
    "M  src/base.js",
  );
});

test("commits one exact plan subject through combined root wiring", async (t) => {
  const paths = await fixture(t, { plan: ONE_STEP_PLAN });
  const codex = createBackend("codex");
  const { runner, runStore } = runtime(
    paths,
    { codex },
    {
      schemaVersion: 1,
      defaultBackend: "codex",
      pipelines: { "plan-execution": { mode: "combined" } },
    },
  );
  const stdout = sink();
  const stderr = sink();

  const exitCode = await main(
    [
      "run",
      "plan-execution",
      "--project",
      paths.projectPath,
      "--task",
      paths.taskPath,
      "--fork-from",
      "codex:source-codex",
    ],
    { runner, stderr: stderr.stream, stdout: stdout.stream },
  );

  assert.equal(exitCode, 0, `${stdout.value()}${stderr.value()}`);
  assert.equal(stderr.value(), "");
  assert.match(stdout.value(), /State: DONE/u);
  const run = await onlyRun(runStore);
  assert.equal(run.pipelineState.workflowState, "DONE");
  assert.equal(run.pipelineState.settings.mode, "combined");
  assert.equal(run.pipelineState.completedCommits.length, 1);
  assert.equal(
    await gitOutput(paths.projectPath, ["log", "-1", "--pretty=%s"]),
    "feat(feature): add value",
  );
  assert.equal(
    await gitOutput(paths.projectPath, ["status", "--porcelain"]),
    "",
  );
  assert.equal(
    await gitOutput(paths.projectPath, ["remote", "get-url", "origin"]),
    "https://example.invalid/repository.git",
  );
  assert.equal(
    await gitOutput(paths.projectPath, [
      "ls-files",
      ".agent-runner.json",
      "LOCAL_ARTIFACTS",
    ]),
    "",
  );
  assert.ok(isAbsolute(runStore.rootPath));
  assert.equal(outside(paths.projectPath, runStore.rootPath), true);
  assert.equal(outside(paths.taskPath, runStore.rootPath), true);

  assert.equal(
    codex.calls.filter(({ access }) => access === "local-commit").length,
    1,
  );
  assert.equal(
    codex.calls.some(({ commit }) =>
      /co-authored-by/iu.test(commit?.message ?? ""),
    ),
    false,
  );
  const sourceCalls = codex.calls.filter(
    ({ session }) => session?.id === "source-codex",
  );
  assert.ok(sourceCalls.length >= 2);
  assert.ok(sourceCalls.every(({ session }) => session.mode === "fork"));
  assert.equal(run.sessionLineage.source, "source-codex");
  const childRoles = new Set(
    run.sessionLineage.children.map(({ role }) => role),
  );
  assert.equal(childRoles.has("worker"), true);
  assert.equal(childRoles.has("reviewer"), true);
  assert.equal(
    new Set(run.sessionLineage.children.map(({ sessionId }) => sessionId)).size,
    run.sessionLineage.children.length,
  );
});
