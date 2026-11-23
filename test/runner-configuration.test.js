import assert from "node:assert/strict";
import { mkdir, readFile, readdir, symlink, writeFile } from "node:fs/promises";
import { join, relative } from "node:path";
import test from "node:test";

import {
  createClarificationService,
  createMcpControlPlane,
  getPipeline,
  main,
} from "../src/index.js";

import {
  appendReadFailure,
  clarificationAppendFixture,
  createExecutionAdapter,
  createFixture,
  executeFile,
  PLAN,
  runnerFor,
} from "./support/index.js";

const CLARIFICATION_OWNERSHIP_VERSIONS = Object.freeze({
  "plan-execution": 43,
  polishing: 23,
});

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

for (const change of [
  "provider alias",
  "target provider alias",
  "ignore rules",
]) {
  test(`external transcript answers reject changed ${change} before mutation`, async (t) => {
    const f = await clarificationAppendFixture(t, "plan-execution", {
      external: true,
      artifactRoot: "artifacts",
    });
    if (change === "ignore rules") {
      await executeFile("git", ["init", "-q", f.rootPath]);
      await writeFile(join(f.rootPath, ".git/info/exclude"), "artifacts/\n");
    }
    if (change === "target provider alias")
      await writeFile(join(f.projectPath, ".git/info/exclude"), "/.codex\n");
    const { runner } = f.open();
    const runId = (await runner.create(f.input)).run.runId;
    const waiting = (await runner.resume({ runId })).run;
    const response = {
      runId,
      requestId: waiting.pause.inputRequest.id,
      expectedRevision: waiting.revision,
      answers: [{ questionId: "q1", answer: "Use behavior A." }],
    };
    const preview = await runner.previewInput(response);
    const before = await f.transcript(waiting);
    if (change === "provider alias")
      await symlink("artifacts", join(f.rootPath, ".codex"));
    else if (change === "target provider alias")
      await symlink(
        join(f.rootPath, "artifacts"),
        join(f.projectPath, ".codex"),
      );
    else await writeFile(join(f.rootPath, ".git/info/exclude"), "");
    const cold = f.open();
    const rejection = {
      code:
        change === "provider alias"
          ? "ERR_UNSAFE_CLARIFICATION_PATH"
          : change === "target provider alias"
            ? "ERR_WORKSPACE_PATH"
            : "ERR_REPOSITORY_ARTIFACT_NOT_IGNORED",
    };
    await assert.rejects(cold.runner.previewInput(response), rejection);
    await assert.rejects(
      cold.runner.submitInput({
        ...response,
        responseHash: preview.responseHash,
      }),
      rejection,
    );
    assert.equal(await f.transcript(waiting), before);
    const retained = await cold.store.loadRun(runId);
    assert.deepEqual(
      retained.pipelineState.pendingEdit,
      waiting.pipelineState.pendingEdit,
    );
    assert.equal(retained.pause.inputResponse, undefined);
    assert.deepEqual(retained.counters, waiting.counters);
    assert.equal(f.calls.length, 1);
  });
}

test("external transcript append recovery rejects a new provider alias without replay", async (t) => {
  const f = await clarificationAppendFixture(t, "plan-execution", {
    external: true,
    artifactRoot: "artifacts",
  });
  const service = createClarificationService({ interactive: false });
  const { runner } = f.open({
    clarifications: {
      ...service,
      appendQuestionRound(request) {
        return service.appendQuestionRound({
          ...request,
          async persistAppend(proof) {
            await request.persistAppend(proof);
            throw appendReadFailure();
          },
        });
      },
    },
  });
  const runId = (await runner.create(f.input)).run.runId;
  const interrupted = (await runner.resume({ runId })).run;
  assert.equal(interrupted.pause.reason, "clarification_append_interrupted");
  const before = await f.transcript(interrupted);
  await symlink("artifacts", join(f.rootPath, ".codex"));
  const cold = f.open();
  const blocked = (await cold.runner.resume({ runId })).run;
  assert.equal(blocked.pause.reason, "clarifications_changed");
  assert.equal(await f.transcript(blocked), before);
  assert.deepEqual(
    blocked.pipelineState.pendingClarificationAppend,
    interrupted.pipelineState.pendingClarificationAppend,
  );
  assert.deepEqual(blocked.counters, interrupted.counters);
  assert.equal(f.calls.length, 1);
});

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

for (const pipelineId of ["plan-execution", "polishing"]) {
  test(`${pipelineId} freezes external clarification ownership and exposes only its transcript`, async (t) => {
    const f = await clarificationAppendFixture(t, pipelineId, {
      external: true,
      artifactRoot: "artifacts",
    });
    const { runner } = f.open();
    const created = (await runner.create(f.input)).run;
    assert.equal(created.pipelineState.clarificationRoot, f.rootPath);
    const pipeline = getPipeline(pipelineId);
    const { clarificationRoot: _selected, ...legacyInitial } =
      created.pipelineState;
    assert.equal(
      pipeline.migrations[CLARIFICATION_OWNERSHIP_VERSIONS[pipelineId]]({
        ...created,
        pipelineState: legacyInitial,
      }).clarificationRoot,
      null,
    );
    const waiting = (await runner.resume({ runId: created.runId })).run;
    const transcript = join(
      f.rootPath,
      "artifacts",
      "agent-runner",
      created.runId,
      "clarifications.md",
    );
    assert.equal(waiting.pause.reason, "clarification_answers_required");
    assert.equal(waiting.pipelineState.clarificationPath, transcript);
    assert.equal(waiting.pipelineState.pendingEdit.artifactRoot, f.rootPath);
    for (const mutate of [
      (run) => {
        delete run.pipelineState.clarificationRoot;
      },
      (run) => {
        run.pipelineState.clarificationRoot = null;
      },
      (run) => {
        run.pipelineState.clarificationRoot = join(f.rootPath, "other");
      },
      (run) => {
        run.pipelineState.pendingEdit.artifactRoot = f.projectPath;
      },
      (run) => {
        run.pipelineState.repositoryBaseline.allowedPaths = [transcript];
      },
    ]) {
      const rejected = structuredClone(waiting);
      mutate(rejected);
      assert.throws(() => pipeline.workflow.validateRun(rejected));
    }
    assert.deepEqual(waiting.pipelineState.repositoryBaseline.allowedPaths, []);
    assert.equal((await readdir(f.projectPath)).includes("artifacts"), false);
    assert.match(await readFile(transcript, "utf8"), /## Round 1/u);
    const cold = f.open();
    assert.equal(
      (await cold.store.loadRun(created.runId)).pipelineState.clarificationRoot,
      f.rootPath,
    );
    const status = await createMcpControlPlane({
      runner: cold.runner,
      runStore: cold.store,
    }).runStatus({ runId: created.runId });
    assert.equal(status.clarificationPath, transcript);
    assert.equal(
      JSON.stringify(status).includes(f.input.projectConfigurationPath),
      false,
    );
    let output = "";
    assert.equal(
      await main(["status", "--run", created.runId], {
        runner: cold.runner,
        stdout: {
          write(chunk) {
            output += chunk;
          },
        },
        stderr: {
          write(chunk) {
            assert.fail(chunk);
          },
        },
      }),
      0,
    );
    assert.ok(output.includes(transcript));
  });

  test(`${pipelineId} rejects an integrated unignored transcript before creation or role work`, async (t) => {
    const f = await clarificationAppendFixture(t, pipelineId, {
      artifactRoot: "visible-artifacts",
    });
    const { runner, store } = f.open();
    const runId = (await runner.create(f.input)).run.runId;
    const blocked = (await runner.resume({ runId })).run;
    assert.equal(blocked.pause.reason, "local_artifacts_not_ignored");
    assert.equal(blocked.pipelineState.preflightComplete, false);
    assert.deepEqual(f.calls, []);
    assert.equal(
      (await readdir(f.projectPath)).includes("visible-artifacts"),
      false,
    );
    const status = await createMcpControlPlane({
      runner,
      runStore: store,
    }).runStatus({ runId });
    assert.equal(status.pause.reason, "local_artifacts_not_ignored");
    assert.equal(JSON.stringify(status.pause).includes("provider"), false);
  });
}

for (const pipelineId of ["plan-execution", "polishing"]) {
  test(`${pipelineId} migration preserves the exact legacy pending editor and accounting`, async (t) => {
    const f = await clarificationAppendFixture(t, pipelineId);
    const { runner } = f.open();
    const runId = (await runner.create(f.input)).run.runId;
    const waiting = (await runner.resume({ runId })).run;
    const pipeline = getPipeline(pipelineId);
    const { clarificationRoot: _root, ...legacy } = waiting.pipelineState;
    const saved = structuredClone(legacy);
    const migrated = pipeline.migrations[
      CLARIFICATION_OWNERSHIP_VERSIONS[pipelineId]
    ]({
      ...waiting,
      pipelineState: legacy,
    });
    assert.deepEqual(migrated, waiting.pipelineState);
    assert.deepEqual(legacy, saved);
    assert.equal(migrated.pendingEdit.artifactRoot, f.projectPath);
    assert.doesNotThrow(() =>
      pipeline.workflow.validateRun({ ...waiting, pipelineState: migrated }),
    );
  });
}

test("external transcript admission checks a nested artifact worktree before creation", async (t) => {
  const f = await clarificationAppendFixture(t, "plan-execution", {
    external: true,
    artifactRoot: "nested/artifacts",
  });
  const nested = join(f.rootPath, "nested");
  await mkdir(nested);
  await executeFile("git", ["init", "-q", nested]);
  const { runner } = f.open();
  const runId = (await runner.create(f.input)).run.runId;
  const waiting = (await runner.resume({ runId })).run;
  assert.equal(waiting.pause.reason, "local_artifacts_not_ignored");
  assert.deepEqual(f.calls, []);
  assert.deepEqual(await readdir(nested), [".git"]);
});

for (const [kind, artifactRoot] of [
  ["reserved", ".codex/artifacts"],
  ["nested reserved", "artifacts/.codex"],
  ["aliased", "artifacts"],
  ["target-aliased", "artifacts"],
]) {
  test(`external transcript admission protects ${kind} provider controls`, async (t) => {
    const alias = kind === "aliased" || kind === "target-aliased";
    const f = await clarificationAppendFixture(t, "plan-execution", {
      external: true,
      artifactRoot,
    });
    if (alias) {
      await mkdir(join(f.rootPath, artifactRoot));
      if (kind === "target-aliased") {
        await writeFile(join(f.projectPath, ".git/info/exclude"), "/.codex\n");
        await symlink(
          join(f.rootPath, artifactRoot),
          join(f.projectPath, ".codex"),
        );
      } else await symlink(artifactRoot, join(f.rootPath, ".codex"));
    }
    const { runner, store } = f.open();
    const runId = (await runner.create(f.input)).run.runId;
    const code =
      kind === "target-aliased"
        ? "ERR_WORKSPACE_PATH"
        : "ERR_UNSAFE_CLARIFICATION_PATH";
    await assert.rejects(runner.resume({ runId }), { code });
    const blocked = await store.loadRun(runId);
    assert.equal(blocked.pause.code, code);
    assert.equal(blocked.pipelineState.preflightComplete, false);
    assert.deepEqual(f.calls, []);
    assert.deepEqual(
      await readdir(alias ? join(f.rootPath, artifactRoot) : f.rootPath),
      alias ? [] : ["agent-runner.json"],
    );
  });
}
