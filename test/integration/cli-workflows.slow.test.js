import assert from "node:assert/strict";
import { readFile, readdir, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, sep } from "node:path";
import test from "node:test";

import {
  createClarificationService,
  createGitService,
  createMcpControlPlane,
  createRunner,
  createRunStore,
  createTrustedValidationService,
  main,
  parseRunnerConfiguration,
} from "../../src/index.js";
import { sandboxTrustedCommand } from "../../src/trusted-validation/execution.js";
import { runExactCommand } from "../../src/trusted-validation/index.js";
import { CodexAdapterError } from "../../src/agents/index.js";
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

test("protocol rejection retains redacted diagnostics through reload, CLI and MCP activity", async (t) => {
  const paths = await fixture(t, { plan: ONE_STEP_PLAN });
  const codex = createBackend("codex");
  codex.run = async () => {
    throw new CodexAdapterError("PRIVATE_SYNTHETIC_RESPONSE", {
      code: "ERR_CODEX_PROTOCOL",
      diagnosticClass: "protocol_history_unsupported",
    });
  };
  const { runner, runStore } = runtime(
    paths,
    { codex },
    { schemaVersion: 1, defaultBackend: "codex" },
  );
  assert.equal(
    await main(
      [
        "run",
        "plan-execution",
        "--project",
        paths.projectPath,
        "--task",
        paths.taskPath,
        "--mode",
        "lazy",
      ],
      { runner, stdout: sink().stream, stderr: sink().stream },
    ),
    1,
  );
  const failed = await onlyRun(runStore);
  const reloadedStore = createRunStore({ stateRoot: paths.stateRoot });
  const readRunner = {
    async status(runId) {
      return {
        run: await reloadedStore.loadRun(runId),
        directoryPath: await reloadedStore.getRunDirectory(runId),
      };
    },
  };
  const control = createMcpControlPlane({
    runner: readRunner,
    runStore: reloadedStore,
    issueReportingEnabled: false,
  });
  const projected = await control.runStatus({ runId: failed.runId });
  assert.equal(projected.status, "FAILED");
  assert.deepEqual(projected.pause.nextActions, []);
  assert.match(
    projected.pause.explanation,
    /Adapter diagnostic: protocol_history_unsupported\./u,
  );
  const activity = await control.runActivity({
    runId: failed.runId,
    cursor: 0,
    limit: 100,
  });
  assert.ok(
    activity.activities.some(({ message }) =>
      message.includes("ERR_CODEX_PROTOCOL (protocol_history_unsupported)"),
    ),
  );
  const stdout = sink();
  assert.equal(
    await main(["status", "--run", failed.runId], {
      runner: readRunner,
      stdout: stdout.stream,
      stderr: sink().stream,
    }),
    0,
  );
  assert.ok(stdout.value().includes("protocol_history_unsupported"));
  assert.doesNotMatch(
    stdout.value() + JSON.stringify({ projected, activity, failed }),
    /PRIVATE_SYNTHETIC_RESPONSE/u,
  );
});

test("failed readiness-wrapped owned checks survive reload into findings and CLI/MCP diagnostics", async (t) => {
  const projectFiles = {};
  for (const path of [
    "package.json",
    "scripts/format.js",
    "scripts/index.js",
    "scripts/test.js",
    "scripts/test-selection.js",
    "scripts/test-storage.js",
  ]) {
    projectFiles[path] = await readFile(
      new URL(`../../${path}`, import.meta.url),
    );
  }
  projectFiles["test/synthetic.test.js"] = "// Synthetic inventory member.\n";
  const paths = await fixture(t, { plan: ONE_STEP_PLAN, projectFiles });
  const command = "npm run check";
  const diagnostic = "Trusted check error class: ERR_ASSERTION.";
  const identity = "Trusted check failed test file: test/synthetic.test.js.";
  const timing = "Runner-trusted check elapsed: 17 ms.";
  const requiredChecks = [{ id: "C1", command }];
  const backend = createBackend("codex");
  const resolutions = [];
  const adapter = {
    ...backend,
    async run(request) {
      if (request.prompt.startsWith("For each finding below")) {
        resolutions.push(request.prompt);
        return {
          structured: {
            status: "BLOCKED",
            decisions: [],
            reason: "A synthetic external prerequisite remains unavailable.",
            evidence: ["The fixture requires an explicit retry."],
            question: "",
            options: [],
            whyBlocked: "",
          },
          sessionId: request.session?.id ?? "resolution-session",
        };
      }
      const response = await backend.run(request);
      const result = response.structured?.result ?? response.structured;
      if (result?.requiredChecks) {
        const bootstrap = !result.checks;
        result.requiredChecks = requiredChecks.map((entry) => ({
          ...entry,
          ...(bootstrap ? { steps: [1] } : {}),
        }));
        if (!bootstrap)
          result.checks = [
            {
              checkId: "C1",
              command,
              status: "NOT_RUN",
              evidence: ["Reserved for Runner."],
            },
          ];
      }
      return response;
    },
  };
  const configuration = parseRunnerConfiguration(
    JSON.stringify({
      schemaVersion: 1,
      defaultBackend: "codex",
      trustedCommands: {
        "agent-runner-check": {
          command,
          executable: "npm",
          arguments: ["run", "check"],
          capabilities: { scratch: true },
        },
      },
      pipelines: {
        "plan-execution": { trustedChecks: ["agent-runner-check"] },
      },
    }),
  );
  const git = createGitService();
  const store = createRunStore({ stateRoot: paths.stateRoot });
  const registrations = [];
  let clockReads = 0;
  const trustedValidation = createTrustedValidationService({
    git,
    clock: () => clockReads++ * 17,
    storageRoot: join(dirname(paths.stateRoot), "storage"),
    // Exercise the production readiness wrapper and owned-process transport.
    // Isolation policy already has separate real and injected coverage.
    sandboxCommand(value, options) {
      const report = `not ok 1 - synthetic-private-title\n  ---\n  location: '${join(paths.projectPath, "test/synthetic.test.js")}:1:1'\n  failureType: 'testCodeFailure'\n  ...\n`;
      const synthetic = {
        ...value,
        executable: process.execPath,
        arguments: [
          "--eval",
          `const { writeSync } = require("node:fs"); writeSync(1, Buffer.alloc(2 ** 20, 120)); writeSync(1, "\\n" + ${JSON.stringify(report)}); writeSync(2, "AssertionError [ERR_ASSERTION]: synthetic-private-value\\n"); process.exitCode = 7;`,
        ],
      };
      const sandbox = sandboxTrustedCommand(synthetic, {
        ...options,
        bubblewrapPath: "/usr/bin/bwrap",
      });
      const offset = sandbox.command.arguments.indexOf("--") + 2;
      return {
        ...sandbox,
        ownershipMode: "ordinary",
        command: {
          executable: process.execPath,
          arguments: sandbox.command.arguments.slice(offset),
        },
      };
    },
    async runCommand(value, options) {
      const result = await runExactCommand(value, {
        ...options,
        async onProcess(pid, proof) {
          registrations.push(pid);
          await options.onProcess(pid, proof);
        },
      });
      if (result.exitCode === 7)
        assert.ok(result.diagnostics?.includes(diagnostic));
      return result;
    },
  });
  const runner = createRunner({
    adapters: { codex: adapter },
    git,
    runStore: store,
    trustedValidation,
    clarifications: createClarificationService({ interactive: false }),
    loadConfiguration: async () => configuration,
  });
  const first = await runner.run({
    pipelineId: "plan-execution",
    projectPath: paths.projectPath,
    taskPath: paths.taskPath,
  });
  assert.equal(first.run.pause.reason, "environment_blocked");
  assert.equal(first.run.pause.resumeState, "RESOLVE_FINDINGS");
  assert.match(resolutions[0], /Trusted check error class: ERR_ASSERTION\./u);
  assert.ok(resolutions[0].includes(identity));
  assert.ok(resolutions[0].includes(timing));
  assert.doesNotMatch(resolutions[0], /synthetic-private-value/u);
  const reloadedStore = createRunStore({ stateRoot: paths.stateRoot });
  const loaded = await reloadedStore.loadRun(first.run.runId);
  const finalization = loaded.pipelineState.finalizationResult;
  assert.equal(finalization.checks[0].status, "FAIL");
  assert.equal(finalization.checks[0].exitCode, 7);
  assert.ok(finalization.checks[0].evidence.includes(diagnostic));
  assert.ok(finalization.checks[0].evidence.includes(identity));
  assert.ok(finalization.checks[0].evidence.includes(timing));
  assert.equal(clockReads, 2);
  assert.deepEqual(finalization.checks[0].diagnosticInventory.files, [
    "test/synthetic.test.js",
  ]);
  assert.deepEqual(
    finalization.issues[0].evidence,
    finalization.checks[0].evidence,
  );
  assert.equal(loaded.executionProcess, null);
  assert.equal(loaded.executionResource, null);
  const launches = registrations.filter((pid) => pid !== null);
  assert.ok(launches.length >= 2);
  assert.equal(
    registrations.filter((pid) => pid === null).length,
    launches.length,
  );
  assert.deepEqual(
    await readdir(join(dirname(paths.stateRoot), "storage")),
    [],
  );
  const readRunner = {
    async status(runId) {
      return {
        run: await reloadedStore.loadRun(runId),
        directoryPath: await reloadedStore.getRunDirectory(runId),
      };
    },
  };
  const control = createMcpControlPlane({
    runner: readRunner,
    runStore: reloadedStore,
    issueReportingEnabled: false,
  });
  const projected = await control.runStatus({ runId: loaded.runId });
  assert.ok(
    projected.pause.evidence.includes(
      `Runner check C1, issue F1: ${diagnostic}`,
    ),
  );
  assert.deepEqual(projected.pause.nextActions, [
    { type: "resume", action: null },
  ]);
  assert.ok(
    projected.pause.evidence.includes(`Runner check C1, issue F1: ${identity}`),
  );
  assert.ok(
    projected.pause.evidence.includes(`Runner check C1, issue F1: ${timing}`),
  );
  let stdout = "";
  assert.equal(
    await main(["status", "--run", loaded.runId], {
      runner: readRunner,
      stdout: {
        write(value) {
          stdout += value;
        },
      },
      stderr: {
        write(value) {
          assert.fail(value);
        },
      },
    }),
    0,
  );
  assert.match(
    stdout,
    /Runner check C1, issue F1: Trusted check error class: ERR_ASSERTION\./u,
  );
  assert.doesNotMatch(
    stdout + JSON.stringify(projected),
    /synthetic-private-value|synthetic-private-title/u,
  );
  assert.ok(stdout.includes(identity));
  assert.ok(stdout.includes(timing));
  const lease = await reloadedStore.acquireRunLease(loaded.runId);
  try {
    for (const mutate of [
      (check) => {
        check.diagnosticInventory.contentFingerprint = "f".repeat(64);
      },
      (check) => {
        check.evidence.push("Runner-trusted check elapsed: NaN ms.");
      },
      (check) => {
        check.executor = "agent";
      },
    ]) {
      const altered = structuredClone(loaded.pipelineState);
      mutate(altered.finalizationResult.checks[0]);
      await assert.rejects(
        reloadedStore.transitionRun(lease, { pipelineState: altered }),
        { code: "ERR_INVALID_RUN_STATE" },
      );
    }
    assert.equal(
      (await reloadedStore.loadRun(loaded.runId)).revision,
      loaded.revision,
    );
  } finally {
    await lease.release();
  }
});
