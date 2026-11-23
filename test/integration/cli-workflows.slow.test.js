import assert from "node:assert/strict";
import { watch } from "node:fs";
import { readFile, readdir, writeFile } from "node:fs/promises";
import { isAbsolute, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { createClarificationService, main } from "../../src/index.js";
import { spawnOwnedProcess } from "../../src/platform/index.js";
import {
  appendReadFailure,
  clarificationAppendFixture,
  transcriptHash,
} from "../support/index.js";
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

test("cold clarification append CLI reconstructs authoring questions from replaced bytes", async (t) => {
  const f = await clarificationAppendFixture(t, "plan-authoring", {
    mode: "lazy",
  });
  const service = createClarificationService({ interactive: false });
  const initial = f.open({
    clarifications: {
      ...service,
      async appendQuestionRound(options) {
        await service.appendQuestionRound(options);
        throw appendReadFailure();
      },
    },
  });
  const runId = (await initial.runner.create(f.input)).run.runId;
  assert.equal(
    (await initial.runner.resume({ runId })).run.pause.reason,
    "clarification_append_interrupted",
  );
  const cold = f.open();
  const retained = await cold.store.loadRun(runId);
  const intent = retained.pipelineState.pendingClarificationAppend;
  const bytes = await f.transcript(retained);
  const stdout = sink();
  const stderr = sink();
  assert.equal(
    await main(["resume", "--run", runId], {
      runner: cold.runner,
      stdout: stdout.stream,
      stderr: stderr.stream,
    }),
    2,
  );
  assert.equal(stderr.value(), "");
  assert.match(stdout.value(), /WAITING_FOR_USER/u);
  const waiting = await cold.store.loadRun(runId);
  assert.equal(waiting.pause.reason, "clarification_answers_required");
  assert.equal(waiting.pipelineState.pendingClarificationAppend, null);
  assert.equal(waiting.counters.clarificationRounds, 1);
  assert.equal(waiting.hashes.clarifications, intent.resultHash);
  assert.equal(transcriptHash(bytes), intent.resultHash);
  assert.equal(await f.transcript(waiting), bytes);
  assert.equal(f.calls.length, 1);
  const repeated = (await f.open().runner.resume({ runId })).run;
  assert.equal(repeated.counters.clarificationRounds, 1);
  assert.equal(await f.transcript(repeated), bytes);
  assert.equal(f.calls.length, 1);
});

test(
  "cold clarification append survives owned Runner process loss after readback",
  { timeout: 30_000 },
  async (t) => {
    const cleanups = [];
    let child;
    let watcher;
    let owner = null;
    const abort = () => child?.kill("SIGKILL");
    t.signal.addEventListener("abort", abort, { once: true });
    t.after(async () => {
      t.signal.removeEventListener("abort", abort);
      watcher?.close();
      child?.kill("SIGKILL");
      await child?.ownedCompletion;
      assert.equal(owner, null);
      // Uncertain retirement throws above and retains all fixture storage.
      for (const cleanup of cleanups) await cleanup();
    });
    const f = await clarificationAppendFixture(
      { after: (cleanup) => cleanups.push(cleanup) },
      "plan-authoring",
      { mode: "lazy" },
    );
    const initial = f.open();
    const runId = (await initial.runner.create(f.input)).run.runId;
    const receiptPath = join(f.workspace, "append-readback");
    const ready = Promise.withResolvers();
    watcher = watch(f.workspace, (event, filename) => {
      if (event === "rename" && filename === "append-readback") ready.resolve();
    });
    watcher.on("error", ready.reject);
    child = spawnOwnedProcess(
      process.execPath,
      [
        fileURLToPath(
          new URL("../support/clarification-append-child.js", import.meta.url),
        ),
        f.stateRoot,
        runId,
        receiptPath,
      ],
      {
        cwd: f.projectPath,
        env: process.env,
        onProcess(value) {
          owner = value;
        },
      },
    );
    let stderr = "";
    child.stdout.resume();
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    await Promise.race([
      ready.promise,
      child.ownedCompletion.then(() =>
        assert.fail(`Runner exited before append readback: ${stderr}`),
      ),
    ]);
    assert.equal(await readFile(receiptPath, "utf8"), "append-readback\n");
    const retained = await initial.store.loadRun(runId);
    const intent = retained.pipelineState.pendingClarificationAppend;
    assert.ok(intent);
    assert.equal(retained.pipelineState.pendingEdit, null);
    assert.equal(retained.counters.clarificationRounds, 0);
    const bytes = await f.transcript(retained);
    assert.equal(transcriptHash(bytes), intent.resultHash);
    assert.equal(await initial.store.runIsLeased(runId), true);
    child.kill("SIGKILL");
    await child.ownedCompletion;
    assert.equal(owner, null);
    const cold = f.open();
    const waiting = (await cold.runner.resume({ runId })).run;
    assert.equal(waiting.pause.reason, "clarification_answers_required");
    assert.equal(waiting.pipelineState.pendingClarificationAppend, null);
    assert.equal(waiting.counters.clarificationRounds, 1);
    assert.equal(waiting.hashes.clarifications, intent.resultHash);
    assert.equal(await f.transcript(waiting), bytes);
    assert.equal(
      f.calls.length,
      0,
      "The replacement Runner must not invoke a role",
    );
    const repeated = (await f.open().runner.resume({ runId })).run;
    assert.equal(repeated.counters.clarificationRounds, 1);
    assert.equal(await f.transcript(repeated), bytes);
    assert.equal(f.calls.length, 0);
  },
);

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
  assert.deepEqual(run.pipelineState.bootstrapCorrections, []);
  for (const role of ["worker", "reviewer"]) {
    assert.deepEqual(run.pipelineState[`${role}Validation`].requiredChecks, [
      { id: "C1", command: "git diff --check HEAD", steps: [1] },
    ]);
  }
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
