import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join, relative, sep } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { createLegacyRecoveryFixture } from "../../pipelines/plan-execution/test/support/index.js";
import {
  createTrustedValidationService,
  createTrustedValidationSnapshot,
} from "../../src/trusted-validation/index.js";
import {
  createClarificationService,
  createGitService,
  createMcpControlPlane,
  createRunner,
  createRunStore,
  main,
  parseRunnerConfiguration,
} from "../../src/index.js";

const executeFile = promisify(execFile);

test("CLI legacy confirmation resume reaches the ordinary commit gate", async (t) => {
  const fixture = await createLegacyRecoveryFixture(t, {
    mode: "independent",
    pendingCorrection: false,
    steps: 1,
  });
  const stdout = sink();
  const stderr = sink();
  const before = fixture.calls.length;
  assert.equal(
    await main(["resume", "--run", fixture.runId], {
      stdout: stdout.stream,
      stderr: stderr.stream,
      runner: fixture.openRunner(),
    }),
    0,
  );
  assert.equal(fixture.calls.length - before, 2);
  assert.equal(
    (await fixture.store.loadRun(fixture.runId)).pipelineState.workflowState,
    "DONE",
  );
  assert.doesNotMatch(
    stdout.value() + stderr.value(),
    /PRIVATE_LEGACY_PROVIDER_PAYLOAD/u,
  );
});

test("legacy recovery shares CLI and MCP actions and survives a disconnected wait", async (t) => {
  const entered = deferred();
  const release = deferred();
  let hold = false;
  const fixture = await createLegacyRecoveryFixture(t, {
    steps: 1,
    onConfirmation: async () => {
      if (hold) {
        entered.resolve();
        await release.promise;
      }
    },
  });
  const stdout = sink();
  const stderr = sink();
  const runner = fixture.openRunner();
  const exitCode = await main(["status", "--run", fixture.runId], {
    stdout: stdout.stream,
    stderr: stderr.stream,
    createCommandRunner: () => runner,
  });
  assert.equal(exitCode, 0);
  assert.match(stdout.value(), /CONFIRM/u);
  assert.match(stdout.value(), /resume/u);
  const process = detached(fixture.openRunner());
  const control = createMcpControlPlane({
    runStore: fixture.store,
    runner,
    launchRun: process.launchRun,
  });
  const before = await control.runStatus({ runId: fixture.runId });
  assert.equal(before.pause.resumeState, "CONFIRM");
  hold = true;
  try {
    await control.runResume({
      runId: fixture.runId,
      expectedRevision: before.revision,
      action: null,
      idempotencyKey: "legacy-disconnect",
    });
    await entered.promise;
    const running = await control.runStatus({ runId: fixture.runId });
    const cancellation = new AbortController();
    const wait = control.runWait(
      {
        runId: fixture.runId,
        cursor: running.revision,
        timeoutMs: 10_000,
        progress: false,
      },
      { signal: cancellation.signal },
    );
    cancellation.abort();
    await assert.rejects(wait, { name: "AbortError" });
    assert.equal(await fixture.store.runIsLeased(fixture.runId), true);
  } finally {
    release.resolve();
    await process.settle();
  }
  const done = await createMcpControlPlane({
    runStore: fixture.openStore(),
    runner: fixture.openRunner(),
  }).runStatus({ runId: fixture.runId });
  assert.equal(done.status, "DONE");
  assert.equal(
    fixture.calls.filter(({ access }) => access === "local-commit").length,
    1,
  );
});

test("MCP pause and cancellation reconcile through the shared active runner", async (t) => {
  for (const action of ["pause", "cancel"]) {
    const paths = await fixture(t);
    const implementationGate = {
      entered: deferred(),
      release: deferred(),
    };
    const codex = createBackend("codex", { implementationGate });
    const { runner, runStore } = runtime(
      paths,
      { codex },
      { schemaVersion: 1, defaultBackend: "codex" },
    );
    const activeRun = runner.run({
      pipelineId: "plan-execution",
      projectPath: paths.projectPath,
      taskPath: paths.taskPath,
      roleOverrides: {},
      sourceSession: null,
    });
    await within(
      implementationGate.entered.promise,
      30_000,
      "Execution did not reach implementation.",
    );

    const control = createMcpControlPlane({ runner, runStore });
    const running = await onlyRun(runStore);
    const input = {
      runId: running.runId,
      expectedRevision: running.revision,
      idempotencyKey: `integration-${action}`,
    };
    const requestStop =
      action === "pause" ? control.runPause : control.runCancel;
    const receipt = await requestStop(input);
    assert.equal(receipt.kind, `${action}_requested`);
    assert.deepEqual(
      (await control.runStatus({ runId: running.runId })).pendingStop,
      { kind: `${action}_requested`, revision: receipt.revision },
    );
    assert.ok(
      (
        await control.runActivity({
          runId: running.runId,
          cursor: running.revision,
          limit: 10,
        })
      ).activities.some(({ kind }) => kind === `${action}-requested`),
    );

    implementationGate.release.resolve();
    const stopped = await within(
      activeRun,
      30_000,
      `Execution did not reconcile the ${action}.`,
    );
    assert.deepEqual(await requestStop(input), receipt);
    const projected = await control.runWait({
      runId: running.runId,
      cursor: 0,
      timeoutMs: 0,
      progress: false,
    });
    assert.equal(projected.pendingStop, null);
    if (action === "pause") {
      assert.equal(stopped.run.pipelineState.workflowState, "WAITING_FOR_USER");
      assert.equal(stopped.run.pause.reason, "operator_paused");
      assert.equal(projected.pause.reason, "operator_paused");
      assert.deepEqual(projected.pause.nextActions, [
        { type: "resume", action: null },
      ]);
    } else {
      assert.equal(stopped.run.pipelineState.workflowState, "CANCELED");
      assert.equal(projected.status, "CANCELED");
      await assert.rejects(
        control.runResume({
          runId: running.runId,
          expectedRevision: projected.revision,
          action: null,
          idempotencyKey: "revive-canceled",
        }),
      );
    }
  }
});
const TWO_STEP_PLAN = `## Commit 1: feat(feature): add value

Add the requested value.

## Commit 2: test(feature): cover value

Cover the requested value.`;

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

function deferred() {
  let resolvePromise;
  const promise = new Promise((resolve) => {
    resolvePromise = resolve;
  });
  return { promise, resolve: resolvePromise };
}

function capabilities() {
  return {
    version: "fake-1.0.0",
    structuredOutput: true,
    readOnly: true,
    autonomousWrite: true,
    gitMetadataWriteBlocked: true,
    workspaceWrite: true,
    localCommit: true,
    remoteWriteBlocked: true,
    nativeSessionContinuation: true,
    nativeSessionFork: true,
  };
}

function readyForExecution() {
  return {
    status: "READY",
    questions: [],
    reason: "",
    question: "",
    options: [],
    whyBlocked: "",
    evidence: [],
  };
}

function createBackend(
  backend,
  {
    authoringQuestion = false,
    bootstrapDisagreement = false,
    failAuthoringClarification = false,
    failExecutionClarification = false,
    implementationGate = null,
    polishingGate = null,
    rejectSource = false,
  } = {},
) {
  const calls = [];
  let authoringClarifications = 0;
  let executionClarifications = 0;
  let implementationCalls = 0;
  let reconciliations = 0;
  let sessionSequence = 0;

  function sessionId(request, role) {
    if (request.session?.mode === "continue") {
      return request.session.id;
    }
    sessionSequence += 1;
    return `${backend}-${role}-${sessionSequence}`;
  }

  async function implement(request) {
    implementationCalls += 1;
    if (implementationGate !== null && implementationCalls === 1) {
      implementationGate.entered.resolve();
      await implementationGate.release.promise;
    }
    if (
      request.prompt.includes(
        "Current planned commit:\n## Commit 1: feat(feature): add value",
      )
    ) {
      await mkdir(join(request.cwd, "src"), { recursive: true });
      await writeFile(
        join(request.cwd, "src", "feature.js"),
        "export const value = 1;\n",
      );
    } else if (
      request.prompt.includes(
        "Current planned commit:\n## Commit 2: test(feature): cover value",
      )
    ) {
      await mkdir(join(request.cwd, "test"), { recursive: true });
      await writeFile(
        join(request.cwd, "test", "feature.test.js"),
        "export const coveredValue = 1;\n",
      );
    } else {
      throw new Error("Unexpected planned commit.");
    }
    return {
      status: "COMPLETED",
      summary: "Implemented and self-reviewed the planned change.",
      reason: "",
      question: "",
      options: [],
      whyBlocked: "",
      evidence: [],
    };
  }

  return {
    backend,
    calls,
    async probe() {
      return capabilities();
    },
    async run(request) {
      calls.push(request);
      if (request.session?.mode === "fork" && rejectSource) {
        const error = new Error("Source session is unavailable.");
        error.recoverable = true;
        throw error;
      }
      if (request.access === "local-commit") {
        await executeFile("git", ["-C", request.cwd, "add", "-A"]);
        await executeFile("git", [
          "-C",
          request.cwd,
          "commit",
          "-qm",
          request.commit.message,
        ]);
        return {
          output: "committed",
          structured: { ready: true },
          sessionId: sessionId(request, "worker"),
        };
      }

      let role = "worker";
      let structured;
      if (request.prompt.includes("Study the task, existing clarifications")) {
        role = "planner";
        authoringClarifications += 1;
        if (failAuthoringClarification && authoringClarifications === 1) {
          const error = new Error("Claude usage capacity is unavailable.");
          error.code = "ERR_CLAUDE_USAGE_LIMIT";
          error.recoverable = true;
          throw error;
        }
        structured =
          authoringQuestion && authoringClarifications === 1
            ? {
                status: "QUESTIONS",
                questions: [
                  {
                    question: "Which public behavior is required?",
                    whyItMatters: "The answer affects the commit plan.",
                  },
                ],
              }
            : { status: "READY", questions: [] };
      } else if (
        request.prompt.includes("Write a concise commit-by-commit plan")
      ) {
        role = "planner";
        structured = {
          status: "DRAFT",
          plan: TWO_STEP_PLAN,
          question: "",
          options: [],
          whyBlocked: "",
          evidence: [],
        };
      } else if (
        request.prompt.includes("Review the plan and verify that it is correct")
      ) {
        role = "reviewer";
        structured = {
          status: "APPROVED",
          findings: [],
          question: "",
          options: [],
          whyBlocked: "",
          evidence: [],
        };
      } else if (request.prompt.includes("Study the task, validated plan")) {
        executionClarifications += 1;
        if (failExecutionClarification && executionClarifications === 1) {
          const error = new Error("Temporary backend failure.");
          error.recoverable = true;
          throw error;
        }
        structured = readyForExecution();
      } else if (
        request.prompt.includes(
          "Study the task, existing changes, task-level clarifications",
        )
      ) {
        structured = readyForExecution();
      } else if (
        request.prompt.includes("Provide a concise bootstrap summary") ||
        request.prompt.includes("Return a concise bootstrap summary")
      ) {
        const reviewer = request.prompt.includes("As Reviewer");
        role = reviewer ? "reviewer" : "worker";
        structured = {
          status: "READY",
          summary:
            `${reviewer ? "Reviewer" : "Worker"} understands the task, ` +
            "plan, risks, and finalization procedure.",
          requiredChecks: [{ id: "C1", command: "git diff --check HEAD" }],
          validationInfrastructure: [],
          capacityField: "",
          capacityLimit: 0,
          reason: "",
          question: "",
          options: [],
          whyBlocked: "",
          evidence: [],
        };
      } else if (
        request.prompt.includes("Reconcile the independent Worker and Reviewer")
      ) {
        reconciliations += 1;
        structured =
          bootstrapDisagreement && reconciliations === 1
            ? {
                status: "DISAGREEMENT",
                summary: "",
                disagreement: "The roles selected different module boundaries.",
                reason: "",
                question: "",
                options: [],
                whyBlocked: "",
                evidence: ["The summaries name different owning modules."],
              }
            : {
                status: "RESOLVED",
                summary: "Use the existing minimal module boundary.",
                disagreement: "",
                reason: "",
                question: "",
                options: [],
                whyBlocked: "",
                evidence: [],
              };
      } else if (
        request.prompt.includes("Resolve the bootstrap disagreement")
      ) {
        role = "arbiter";
        structured = {
          direction: "SYNTHESIZE",
          summary: "Use the existing minimal module boundary.",
          rationale: "Repository ownership supports that boundary.",
          reason: "",
          question: "",
          options: [],
          whyBlocked: "",
          evidence: [],
        };
      } else if (request.prompt.includes("Implement the changes described")) {
        structured = await implement(request);
      } else if (
        request.prompt.includes("Polish the existing local repository changes")
      ) {
        if (polishingGate !== null) {
          polishingGate.entered.resolve();
          await polishingGate.release.promise;
        }
        structured = {
          status: "COMPLETED",
          summary:
            "The existing dirty change is already idiomatic and minimal.",
          reason: "",
          question: "",
          options: [],
          whyBlocked: "",
          evidence: [],
        };
      } else if (
        request.prompt.includes(
          "Run the complete project finalization procedure",
        )
      ) {
        structured = {
          status: "PASS",
          skillPath: "",
          summary: "The repository finalization procedure passed.",
          issues: [],
          requiredChecks: [{ id: "C1", command: "git diff --check HEAD" }],
          validationInfrastructure: [],
          checks: [
            {
              checkId: "C1",
              command: "git diff --check HEAD",
              status: "PASS",
              evidence: ["git diff --check HEAD exited successfully."],
            },
          ],
          reason: "",
          question: "",
          options: [],
          whyBlocked: "",
          evidence: [],
        };
      } else if (request.prompt.includes("semantic candidate")) {
        role = "reviewer";
        structured = {
          status: "APPROVED",
          findings: [],
          question: "",
          options: [],
          whyBlocked: "",
          evidence: [],
        };
      } else if (
        request.prompt.includes("Confirm the finalized changes") ||
        request.prompt.includes("Confirm the finalized change set") ||
        request.prompt.includes("Review the complete current change set")
      ) {
        role = "reviewer";
        structured = {
          status: "APPROVED",
          findings: [],
          validationChange: "UNCHANGED",
          validationEvidence: [],
          ...(request.prompt.includes("Confirm the finalized changes") ||
          request.prompt.includes("Confirm the finalized change set")
            ? { finalizationFindingIds: [] }
            : {}),
          question: "",
          options: [],
          whyBlocked: "",
          evidence: [],
        };
      } else {
        throw new Error("Unexpected fake backend turn.");
      }

      return {
        output: "structured",
        structured:
          request.schema?.properties?.result?.anyOf === undefined
            ? structured
            : { result: structured },
        sessionId: sessionId(request, role),
      };
    },
  };
}

async function fixture(t, { autoCleanup = true, plan = TWO_STEP_PLAN } = {}) {
  const workspace = await mkdtemp(join(tmpdir(), "agent-runner-workflows-"));
  const projectPath = join(workspace, "project");
  const taskPath = join(workspace, "task");
  const stateRoot = join(workspace, "state");
  await Promise.all([
    mkdir(join(projectPath, "src"), { recursive: true }),
    mkdir(taskPath),
  ]);
  await executeFile("git", ["init", "-q", projectPath]);
  await executeFile("git", [
    "-C",
    projectPath,
    "config",
    "user.name",
    "Test User",
  ]);
  await executeFile("git", [
    "-C",
    projectPath,
    "config",
    "user.email",
    "test@example.com",
  ]);
  await Promise.all([
    writeFile(join(projectPath, ".gitignore"), "/LOCAL_ARTIFACTS/\n"),
    writeFile(join(projectPath, "src", "base.js"), "export const base = 1;\n"),
    writeFile(join(taskPath, "task.md"), "Implement the requested value.\n"),
  ]);
  if (plan !== null) {
    await writeFile(join(taskPath, "plan.md"), plan);
  }
  await executeFile("git", ["-C", projectPath, "add", ".gitignore", "src"]);
  await executeFile("git", [
    "-C",
    projectPath,
    "commit",
    "-qm",
    "chore(test): initialize",
  ]);
  await executeFile("git", [
    "-C",
    projectPath,
    "remote",
    "add",
    "origin",
    "https://example.invalid/repository.git",
  ]);
  const cleanup = () => rm(workspace, { recursive: true, force: true });
  if (autoCleanup) {
    t.after(cleanup);
  }
  return { cleanup, projectPath, stateRoot, taskPath };
}

function runtime(paths, adapters, configuration) {
  const runStore = createRunStore({ stateRoot: paths.stateRoot });
  const runner = createRunner({
    adapters,
    clarifications: createClarificationService({ interactive: false }),
    git: createGitService(),
    loadConfiguration: async () =>
      parseRunnerConfiguration(JSON.stringify(configuration)),
    runStore,
  });
  return { runner, runStore };
}

async function onlyRun(runStore) {
  const [runId] = await readdir(join(runStore.rootPath, "runs"));
  return runStore.loadRun(runId);
}

async function gitOutput(projectPath, args) {
  const { stdout } = await executeFile("git", ["-C", projectPath, ...args]);
  return stdout.trim();
}

function outside(parent, child) {
  const path = relative(parent, child);
  return path === ".." || path.startsWith(`..${sep}`);
}

async function within(promise, milliseconds, message) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(message)), milliseconds);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

function detached(runner) {
  const failures = [];
  const pending = new Set();
  return {
    launchRun(runId, action = null) {
      const execution = runner
        .resume({ runId, action })
        .catch((error) => {
          failures.push(error);
        })
        .finally(() => pending.delete(execution));
      pending.add(execution);
    },
    async settle() {
      while (pending.size > 0) {
        await Promise.all([...pending]);
      }
      if (failures.length > 0) {
        throw failures[0];
      }
    },
  };
}

test("authors a complete plan through mixed CLI roles", async (t) => {
  const paths = await fixture(t, { plan: null });
  const codex = createBackend("codex");
  const claude = createBackend("claude");
  const { runner, runStore } = runtime(
    paths,
    { claude, codex },
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
      "--planner",
      "codex",
      "--reviewer",
      "claude",
      "--arbiter",
      "codex",
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
  const run = await onlyRun(runStore);
  assert.equal(run.pipelineState.workflowState, "DONE");
  assert.equal(run.roles.planner.backend, "codex");
  assert.equal(run.roles.reviewer.backend, "claude");
  assert.equal(
    codex.calls.some((call) => call.access === "workspace-write"),
    false,
  );
  assert.equal(
    claude.calls.some((call) => call.access !== "read-only"),
    false,
  );
  assert.equal(
    await gitOutput(paths.projectPath, ["status", "--porcelain"]),
    "",
  );
  assert.equal(
    await gitOutput(paths.projectPath, ["log", "-1", "--pretty=%s"]),
    "chore(test): initialize",
  );
});

test("persists and resumes plan authoring after a Claude usage limit", async (t) => {
  const paths = await fixture(t, { plan: null });
  const claude = createBackend("claude", {
    failAuthoringClarification: true,
  });
  const configuration = { schemaVersion: 1, defaultBackend: "claude" };
  const firstRuntime = runtime(paths, { claude }, configuration);

  const paused = await firstRuntime.runner.run({
    pipelineId: "plan-authoring",
    projectPath: paths.projectPath,
    taskPath: paths.taskPath,
    roleOverrides: {},
    sourceSession: null,
  });

  assert.equal(paused.run.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.deepEqual(paused.run.pause, {
    reason: "backend_unavailable",
    code: "ERR_CLAUDE_USAGE_LIMIT",
    resumeState: "CLARIFY",
  });
  assert.equal(claude.calls.length, 1);
  assert.equal(
    (await firstRuntime.runStore.loadRun(paused.run.runId)).revision,
    paused.run.revision,
  );

  const reopened = runtime(paths, { claude }, configuration);
  const completed = await reopened.runner.resume({
    runId: paused.run.runId,
    action: null,
  });

  assert.equal(completed.run.pipelineState.workflowState, "DONE");
  assert.equal(completed.run.pause, null);
  assert.equal(claude.calls.length, 4);
  assert.equal(
    await readFile(join(paths.taskPath, "plan.md"), "utf8"),
    TWO_STEP_PLAN,
  );
  assert.equal(
    await gitOutput(paths.projectPath, ["status", "--porcelain"]),
    "",
  );
});

test("polishes a dirty worktree through mixed CLI roles without committing", async (t) => {
  const paths = await fixture(t, { plan: null });
  await writeFile(
    join(paths.projectPath, "src", "base.js"),
    "export const base = 2;\n",
  );
  const initialHead = await gitOutput(paths.projectPath, ["rev-parse", "HEAD"]);
  const codex = createBackend("codex");
  const claude = createBackend("claude");
  const { runner, runStore } = runtime(
    paths,
    { claude, codex },
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
      "--worker",
      "codex",
      "--reviewer",
      "claude",
      "--arbiter",
      "codex",
    ],
    { runner, stderr: stderr.stream, stdout: stdout.stream },
  );

  assert.equal(exitCode, 0, stderr.value());
  assert.equal(stderr.value(), "");
  assert.match(stdout.value(), /Pipeline: polishing/u);
  assert.match(stdout.value(), /State: DONE/u);
  assert.doesNotMatch(stdout.value(), /^Plan:/mu);
  const run = await onlyRun(runStore);
  assert.equal(run.pipelineState.workflowState, "DONE");
  assert.equal(run.roles.worker.backend, "codex");
  assert.equal(run.roles.reviewer.backend, "claude");
  assert.equal(
    [...codex.calls, ...claude.calls].some(
      (call) => call.access === "local-commit",
    ),
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

test("executes every planned commit across backend configurations", async (t) => {
  const cases = [
    {
      name: "Codex runner default",
      configuration: { schemaVersion: 1, defaultBackend: "codex" },
      args: ["--fork-from", "codex:source-codex"],
      roles: { worker: "codex", reviewer: "codex", arbiter: "codex" },
      source: "source-codex",
    },
    {
      name: "Claude runner default",
      configuration: { schemaVersion: 1, defaultBackend: "claude" },
      args: ["--fork-from", "claude:source-claude"],
      roles: { worker: "claude", reviewer: "claude", arbiter: "claude" },
      source: "source-claude",
    },
    {
      name: "runner role overrides",
      configuration: {
        schemaVersion: 1,
        defaultBackend: "codex",
        pipelines: {
          "plan-execution": {
            roles: {
              worker: { backend: "claude" },
              reviewer: { backend: "codex" },
              arbiter: { backend: "codex" },
            },
          },
        },
      },
      args: [],
      roles: { worker: "claude", reviewer: "codex", arbiter: "codex" },
      bootstrapDisagreement: true,
    },
    {
      name: "CLI role overrides",
      configuration: { schemaVersion: 1, defaultBackend: "codex" },
      args: [
        "--worker",
        "codex",
        "--reviewer",
        "claude",
        "--arbiter",
        "claude",
      ],
      roles: { worker: "codex", reviewer: "claude", arbiter: "claude" },
    },
  ];

  for (const scenario of cases) {
    await t.test(scenario.name, async (t) => {
      const paths = await fixture(t);
      const codex = createBackend("codex", {
        bootstrapDisagreement: scenario.bootstrapDisagreement,
      });
      const claude = createBackend("claude", {
        bootstrapDisagreement: scenario.bootstrapDisagreement,
      });
      const { runner, runStore } = runtime(
        paths,
        { claude, codex },
        scenario.configuration,
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
          ...scenario.args,
        ],
        { runner, stderr: stderr.stream, stdout: stdout.stream },
      );

      assert.equal(exitCode, 0, `${stdout.value()}${stderr.value()}`);
      assert.equal(stderr.value(), "");
      assert.match(stdout.value(), /State: DONE/u);
      const run = await onlyRun(runStore);
      assert.equal(run.pipelineState.workflowState, "DONE");
      assert.equal(run.pipelineState.completedCommits.length, 2);
      assert.deepEqual(
        Object.fromEntries(
          Object.entries(run.roles).map(([role, value]) => [
            role,
            value.backend,
          ]),
        ),
        scenario.roles,
      );
      assert.deepEqual(
        (
          await gitOutput(paths.projectPath, [
            "log",
            "--reverse",
            "--pretty=%s",
          ])
        )
          .split("\n")
          .slice(-2),
        ["feat(feature): add value", "test(feature): cover value"],
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

      const allCalls = [...codex.calls, ...claude.calls];
      assert.equal(
        allCalls.filter(({ access }) => access === "local-commit").length,
        2,
      );
      assert.equal(
        allCalls.some(({ commit }) =>
          /co-authored-by/iu.test(commit?.message ?? ""),
        ),
        false,
      );
      if (scenario.source !== undefined) {
        const sourceCalls = allCalls.filter(
          ({ session }) => session?.id === scenario.source,
        );
        assert.ok(sourceCalls.length >= 3);
        assert.ok(sourceCalls.every(({ session }) => session.mode === "fork"));
        const candidateReviews = allCalls.filter((call) =>
          call.prompt.includes("Review the changes and verify"),
        );
        const terminalConfirmations = allCalls.filter((call) =>
          call.prompt.includes("Confirm the finalized changes"),
        );
        assert.equal(candidateReviews.length, 2);
        assert.ok(
          candidateReviews.every(
            ({ session }) =>
              session?.mode === "fork" && session.id === scenario.source,
          ),
        );
        assert.equal(terminalConfirmations.length, 2);
        assert.ok(
          terminalConfirmations.every(
            ({ session }) => session?.mode === "continue",
          ),
        );
        assert.equal(
          run.sessionLineage.children.filter(({ role }) => role === "reviewer")
            .length,
          3,
        );
      }
      if (scenario.bootstrapDisagreement) {
        const arbitration = allCalls.find((call) =>
          call.prompt.includes("Resolve the bootstrap disagreement"),
        );
        assert.equal(arbitration?.session, undefined);
        assert.ok(
          run.sessionLineage.children.some(({ role }) => role === "arbiter"),
        );
      }
      assert.equal(
        new Set(run.sessionLineage.children.map(({ sessionId }) => sessionId))
          .size,
        run.sessionLineage.children.length,
      );
    });
  }
});

test("does not replace an unavailable source session", async (t) => {
  for (const backend of ["codex", "claude"]) {
    await t.test(backend, async (t) => {
      const paths = await fixture(t);
      const adapter = createBackend(backend, { rejectSource: true });
      const { runner } = runtime(
        paths,
        { [backend]: adapter },
        { schemaVersion: 1, defaultBackend: backend },
      );
      const result = await runner.run({
        pipelineId: "plan-execution",
        projectPath: paths.projectPath,
        taskPath: paths.taskPath,
        roleOverrides: {},
        sourceSession: { backend, id: `source-${backend}` },
      });

      assert.equal(result.run.pipelineState.workflowState, "WAITING_FOR_USER");
      assert.equal(result.run.pause.reason, "backend_unavailable");
      assert.equal(adapter.calls.length, 1);
      assert.deepEqual(adapter.calls[0].session, {
        mode: "fork",
        id: `source-${backend}`,
      });
    });
  }
});

test("projects a forbidden-delegation diagnostic without durable provider data", async (t) => {
  const sensitiveMarker = "DO_NOT_PERSIST_CODEX_TERMINAL_DATA";
  const paths = await fixture(t);
  const codex = createBackend("codex");
  const runCodex = codex.run.bind(codex);
  codex.run = async (request) => {
    if (
      request.prompt.includes("Provide a concise bootstrap summary") &&
      !request.prompt.includes("As Reviewer")
    ) {
      const error = new Error(sensitiveMarker);
      error.code = "ERR_CODEX_ISOLATION";
      error.diagnosticClass = "operation_multi_agent";
      error.nativeResponse = { message: sensitiveMarker };
      error.prompt = sensitiveMarker;
      error.transcript = sensitiveMarker;
      error.credentials = sensitiveMarker;
      throw error;
    }
    return runCodex(request);
  };
  const configuration = { schemaVersion: 1, defaultBackend: "codex" };
  const firstRuntime = runtime(paths, { codex }, configuration);

  await assert.rejects(
    firstRuntime.runner.run({
      pipelineId: "plan-execution",
      projectPath: paths.projectPath,
      taskPath: paths.taskPath,
      roleOverrides: {},
      sourceSession: null,
    }),
    (error) => error.code === "ERR_CODEX_ISOLATION",
  );

  const failed = await onlyRun(firstRuntime.runStore);
  assert.equal(failed.pipelineState.workflowState, "FAILED");
  assert.deepEqual(failed.pause, {
    reason: "internal_failure",
    code: "ERR_CODEX_ISOLATION",
    diagnosticClass: "operation_multi_agent",
  });

  const reopened = runtime(paths, { codex }, configuration);
  const recovered = await reopened.runStore.loadRun(failed.runId);
  assert.deepEqual(recovered.pause, failed.pause);
  const projected = await createMcpControlPlane({
    runner: reopened.runner,
    runStore: reopened.runStore,
  }).runStatus({ runId: failed.runId });
  assert.deepEqual(projected.pause, {
    reason: "internal_failure",
    code: "ERR_CODEX_ISOLATION",
    explanation:
      "Plan execution failed. Adapter diagnostic: operation_multi_agent.",
    evidence: [],
    resumeState: null,
    nextActions: [],
  });
  const runPath = join(paths.stateRoot, "runs", failed.runId);
  const durableData = (
    await Promise.all(
      ["state.json", "events.jsonl", "progress.md"].map((filename) =>
        readFile(join(runPath, filename), "utf8"),
      ),
    )
  ).join("\n");
  assert.match(durableData, /operation_multi_agent/u);
  assert.doesNotMatch(durableData, /DO_NOT_PERSIST/u);
  assert.doesNotMatch(durableData, /nativeResponse|"prompt":/u);
});

test("runs registered workflows through recoverable MCP controls", async (t) => {
  const paths = await fixture(t, { autoCleanup: false, plan: null });
  const implementationGate = {
    entered: deferred(),
    release: deferred(),
  };
  const polishingGate = {
    entered: deferred(),
    release: deferred(),
  };
  const codex = createBackend("codex", {
    authoringQuestion: true,
    failExecutionClarification: true,
    implementationGate,
    polishingGate,
  });
  const { runner, runStore } = runtime(
    paths,
    { codex },
    { schemaVersion: 1, defaultBackend: "codex" },
  );
  const pipelineProcess = detached(runner);
  t.after(async () => {
    implementationGate.release.resolve();
    polishingGate.release.resolve();
    try {
      await pipelineProcess.settle();
    } finally {
      await paths.cleanup();
    }
  });
  const control = createMcpControlPlane({
    launchRun: pipelineProcess.launchRun,
    runner,
    runStore,
  });
  const progress = [];

  const authored = await control.runStart({
    idempotencyKey: "author-start",
    pipelineId: "plan-authoring",
    projectPath: paths.projectPath,
    taskPath: paths.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  });
  await control.runWait(
    {
      runId: authored.runId,
      cursor: 0,
      timeoutMs: 5_000,
      progress: true,
    },
    {
      progressToken: "author-progress",
      async notify(notification) {
        progress.push(notification);
      },
    },
  );
  await pipelineProcess.settle();
  const authoringPause = await control.runStatus({ runId: authored.runId });
  assert.equal(authoringPause.status, "WAITING_FOR_USER");
  assert.equal(authoringPause.pendingInput.questions[0].id, "q1");
  assert.equal(
    (await control.runStatus({ runId: authored.runId })).pendingInput.id,
    authoringPause.pendingInput.id,
  );
  assert.ok(
    progress.some(({ params }) => /^\[planner\//u.test(params.message)),
  );
  const authoringActivity = await control.runActivity({
    runId: authored.runId,
    cursor: 0,
    limit: 100,
  });
  assert.ok(
    authoringActivity.activities.some(({ actor }) => actor === "planner"),
  );

  await control.runRespond({
    idempotencyKey: "author-response",
    runId: authored.runId,
    requestId: authoringPause.pendingInput.id,
    expectedRevision: authoringPause.revision,
    answers: [{ questionId: "q1", answer: "Expose the value directly." }],
  });
  await control.runWait({
    runId: authored.runId,
    cursor: authoringPause.activityCursor,
    timeoutMs: 5_000,
    progress: false,
  });
  await pipelineProcess.settle();
  const authoringDone = await control.runStatus({ runId: authored.runId });
  assert.equal(authoringDone.status, "DONE");
  assert.match(
    await readFile(join(paths.taskPath, "clarifications.md"), "utf8"),
    /### A1\n\nExpose the value directly\./u,
  );
  assert.equal(
    await readFile(join(paths.taskPath, "plan.md"), "utf8"),
    TWO_STEP_PLAN,
  );

  const execution = await control.runStart({
    idempotencyKey: "execution-start",
    pipelineId: "plan-execution",
    projectPath: paths.projectPath,
    taskPath: paths.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  });
  await control.runWait({
    runId: execution.runId,
    cursor: 0,
    timeoutMs: 5_000,
    progress: false,
  });
  await pipelineProcess.settle();
  const executionPause = await control.runStatus({ runId: execution.runId });
  assert.equal(executionPause.status, "WAITING_FOR_USER");
  assert.deepEqual(executionPause.pause, {
    reason: "backend_unavailable",
    code: "ERR_BACKEND_UNAVAILABLE",
    explanation: "The selected backend is temporarily unavailable.",
    evidence: [],
    resumeState: "CLARIFY",
    nextActions: [{ type: "resume", action: null }],
  });

  const reconnected = createMcpControlPlane({
    launchRun: pipelineProcess.launchRun,
    runner,
    runStore,
  });
  await reconnected.runResume({
    idempotencyKey: "execution-resume",
    runId: execution.runId,
    expectedRevision: executionPause.revision,
    action: null,
  });
  await within(
    implementationGate.entered.promise,
    30_000,
    "Execution did not reach implementation.",
  );
  const timedOut = await reconnected.runWait({
    runId: execution.runId,
    cursor: executionPause.activityCursor,
    timeoutMs: 10,
    progress: false,
  });
  assert.equal(timedOut.timedOut, true);
  assert.notEqual(timedOut.status, "DONE");

  const afterDisconnect = createMcpControlPlane({
    launchRun: pipelineProcess.launchRun,
    runner,
    runStore,
  });
  implementationGate.release.resolve();
  await afterDisconnect.runWait({
    runId: execution.runId,
    cursor: timedOut.activityCursor,
    timeoutMs: 5_000,
    progress: false,
  });
  await pipelineProcess.settle();
  const executionDone = await afterDisconnect.runStatus({
    runId: execution.runId,
  });
  assert.equal(executionDone.status, "DONE");
  assert.equal(executionDone.completedCommits.length, 2);
  const executionActivity = await afterDisconnect.runActivity({
    runId: execution.runId,
    cursor: 0,
    limit: 100,
  });
  assert.ok(
    executionActivity.activities.some(({ actor }) => actor === "worker"),
  );
  assert.ok(
    executionActivity.activities.some(({ actor }) => actor === "reviewer"),
  );
  assert.equal(
    await gitOutput(paths.projectPath, ["status", "--porcelain"]),
    "",
  );
  assert.equal(
    await gitOutput(paths.projectPath, ["remote", "get-url", "origin"]),
    "https://example.invalid/repository.git",
  );

  await writeFile(
    join(paths.projectPath, "src", "base.js"),
    "export const base = 2;\n",
  );
  const polishingHead = await gitOutput(paths.projectPath, [
    "rev-parse",
    "HEAD",
  ]);
  const callCount = codex.calls.length;
  const polishing = await afterDisconnect.runStart({
    idempotencyKey: "polishing-start",
    pipelineId: "polishing",
    projectPath: paths.projectPath,
    taskPath: paths.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  });
  assert.deepEqual(
    await afterDisconnect.runStart({
      idempotencyKey: "polishing-start",
      pipelineId: "polishing",
      projectPath: paths.projectPath,
      taskPath: paths.taskPath,
      proactiveClarification: false,
      roleOverrides: {},
      sourceSession: null,
    }),
    polishing,
  );
  await within(
    polishingGate.entered.promise,
    30_000,
    "Polishing did not reach the Worker turn.",
  );
  const polishingWait = await afterDisconnect.runWait({
    runId: polishing.runId,
    cursor: 0,
    timeoutMs: 10,
    progress: false,
  });
  assert.equal(polishingWait.timedOut, true);
  assert.notEqual(polishingWait.status, "DONE");
  polishingGate.release.resolve();
  await pipelineProcess.settle();
  // A timed-out wait remains a snapshot even after detached execution settles.
  const polishingDone = await afterDisconnect.runStatus({
    runId: polishing.runId,
  });
  assert.equal(
    polishingDone.status,
    "DONE",
    JSON.stringify(polishingDone.pause),
  );
  assert.equal(polishingDone.planPath, null);
  assert.equal(polishingDone.completedCommits.length, 0);
  assert.equal(
    codex.calls
      .slice(callCount)
      .some(({ access }) => access === "local-commit"),
    false,
  );
  assert.equal(
    await gitOutput(paths.projectPath, ["rev-parse", "HEAD"]),
    polishingHead,
  );
  assert.equal(
    await gitOutput(paths.projectPath, ["status", "--porcelain"]),
    "M  src/base.js",
  );
});

async function projectCommandScenario(t, pipelineId, hooks = {}) {
  const paths = await fixture(t);
  if (pipelineId === "polishing") {
    await writeFile(
      join(paths.projectPath, "src/base.js"),
      "export const base = 2;\n",
    );
  }
  const configurationPath = join(
    paths.projectPath,
    "LOCAL_ARTIFACTS/agent-runner.json",
  );
  const definition = {
    command: "node project-only validation",
    executable: process.execPath,
    arguments: ["--eval", "process.exit(0)", "argument with spaces"],
  };
  const projectConfiguration = {
    schemaVersion: 1,
    trustedCommands: { "project-check": definition },
    pipelines: { [pipelineId]: { trustedChecks: ["project-check"] } },
  };
  await mkdir(join(paths.projectPath, "LOCAL_ARTIFACTS"));
  await writeFile(configurationPath, JSON.stringify(projectConfiguration));
  const expected = createTrustedValidationSnapshot(
    projectConfiguration.trustedCommands,
    ["project-check"],
  );
  const requiredChecks = [
    { id: "C1", command: "git diff --check HEAD" },
    { id: "C2", command: definition.command },
  ];
  const runStore = createRunStore({ stateRoot: paths.stateRoot });
  const git = createGitService();
  const calls = [];
  const executions = [];
  let handoffs = 0;
  let loads = 0;
  let runId;
  let rootConfiguration = { schemaVersion: 1, defaultBackend: "codex" };
  const backend = createBackend("codex");
  const adapters = {
    codex: {
      ...backend,
      async run(request) {
        const durable = await runStore.loadRun(runId);
        assert.deepEqual(durable.pipelineState.trustedValidation, expected);
        assert.equal(
          durable.projectConfigurationProtection.path,
          configurationPath,
        );
        calls.push(request);
        await hooks.beforeTurn?.(request, durable, {
          configurationPath,
          projectConfiguration,
        });
        const response = await backend.run(request);
        const result = response.structured.result ?? response.structured;
        if (result.requiredChecks !== undefined) {
          result.requiredChecks = requiredChecks;
          if (result.checks !== undefined) {
            result.checks.push({
              checkId: "C2",
              command: definition.command,
              status: "NOT_RUN",
              evidence: [
                "Reserved for the runner's selected project-check vector.",
              ],
            });
          }
        }
        if (
          request.prompt.includes("Implement the changes described") ||
          request.prompt.includes(
            "Polish the existing local repository changes",
          )
        ) {
          assert.match(
            request.prompt,
            /Selected runner-trusted commands must never execute inside an agent turn/u,
          );
          assert.ok(request.prompt.includes(definition.command));
        }
        return response;
      },
    },
  };
  const trustedValidation = createTrustedValidationService({
    git,
    environment: {
      ...process.env,
      GH_TOKEN: "PRIVATE_CREDENTIAL",
      SSH_AUTH_SOCK: "/private/agent.sock",
    },
    // Inspect the real sandbox construction; no host launcher or process runs.
    resolveLauncher: () => "/usr/bin/bwrap",
    verifyLauncher: (path) => path,
    async runCommand(command, options) {
      executions.push(command);
      assert.ok(
        calls
          .at(-1)
          .prompt.includes("Run the complete project finalization procedure"),
      );
      assert.equal(command.executable, "/usr/bin/bwrap");
      assert.deepEqual(command.arguments.slice(-4), [
        definition.executable,
        ...definition.arguments,
      ]);
      for (const flag of [
        "--unshare-net",
        "--unshare-pid",
        "--cap-drop",
        "--ro-bind",
        "--tmpfs",
      ]) {
        assert.ok(command.arguments.includes(flag), flag);
      }
      assert.equal(command.arguments.includes("--bind"), false);
      assert.equal(options.environment.GH_TOKEN, undefined);
      assert.equal(options.environment.SSH_AUTH_SOCK, undefined);
      assert.equal(options.environment.GIT_SSH_COMMAND, "/bin/false");
      assert.equal(options.environment.GIT_CONFIG_GLOBAL, "/dev/null");
      assert.equal(options.readinessRequired, true);
      await hooks.execute?.(paths);
      return {
        status: "PASS",
        exitCode: 0,
        signal: null,
        timedOut: false,
        reason: "exit",
        stdout: "PRIVATE_EXECUTOR_OUTPUT",
        stderr: "PRIVATE_EXECUTOR_OUTPUT",
      };
    },
  });
  let runner;
  function openRunner() {
    runner = createRunner({
      adapters,
      runStore,
      clarifications: createClarificationService({ interactive: false }),
      git: {
        ...git,
        async stagePolishingHandoff(options) {
          handoffs += 1;
          const result = await git.stagePolishingHandoff(options);
          await hooks.afterHandoff?.(runner, await runStore.loadRun(runId));
          return result;
        },
      },
      loadConfiguration: async () => {
        loads += 1;
        return parseRunnerConfiguration(JSON.stringify(rootConfiguration));
      },
      trustedValidation,
    });
    return runner;
  }
  const prepared = await openRunner().create({
    pipelineId,
    projectPath: paths.projectPath,
    taskPath: paths.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  });
  runId = prepared.run.runId;
  assert.deepEqual(prepared.run.pipelineState.trustedValidation, expected);
  assert.equal(calls.length, 0);
  assert.equal(executions.length, 0);
  return {
    ...paths,
    configurationPath,
    runId,
    runStore,
    expected,
    calls,
    executions,
    resume: () => runner.resume({ runId, action: null }),
    reopen() {
      rootConfiguration = {
        schemaVersion: 1,
        defaultBackend: "claude",
        trustedCommands: {
          replacement: { command: "false", executable: "false", arguments: [] },
        },
        pipelines: { [pipelineId]: { trustedChecks: ["replacement"] } },
      };
      return openRunner();
    },
    get loads() {
      return loads;
    },
    get handoffs() {
      return handoffs;
    },
  };
}

for (const pipelineId of ["plan-execution", "polishing"]) {
  test(`project command snapshots survive interruption and complete ${pipelineId}`, async (t) => {
    let interrupted = false;
    const scenario = await projectCommandScenario(t, pipelineId, {
      beforeTurn(request) {
        if (
          !interrupted &&
          request.prompt.includes(
            "Run the complete project finalization procedure",
          )
        ) {
          interrupted = true;
          const error = new Error("Temporary provider interruption.");
          error.recoverable = true;
          throw error;
        }
      },
    });
    const initialHead = await gitOutput(scenario.projectPath, [
      "rev-parse",
      "HEAD",
    ]);
    const paused = (await scenario.resume()).run;
    assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
    assert.equal(paused.pause.resumeState, "FINALIZE");
    assert.equal(scenario.executions.length, 0);
    assert.deepEqual(paused.pipelineState.trustedValidation, scenario.expected);
    scenario.reopen();
    const completed = (await scenario.resume()).run;
    assert.equal(completed.pipelineState.workflowState, "DONE");
    assert.equal(scenario.loads, 1);
    assert.deepEqual(
      completed.pipelineState.trustedValidation,
      scenario.expected,
    );
    assert.equal(
      scenario.executions.length,
      pipelineId === "plan-execution" ? 2 : 1,
    );
    assert.equal(scenario.handoffs, pipelineId === "polishing" ? 1 : 0);
    assert.equal(
      scenario.calls.filter(({ access }) => access === "local-commit").length,
      pipelineId === "plan-execution" ? 2 : 0,
    );
    if (pipelineId === "plan-execution") {
      assert.equal(completed.pipelineState.completedCommits.length, 2);
    } else {
      assert.equal(
        await gitOutput(scenario.projectPath, ["rev-parse", "HEAD"]),
        initialHead,
      );
    }
    const evidence = completed.pipelineState.finalizationResult.checks.find(
      ({ checkId }) => checkId === "C2",
    );
    assert.equal(evidence.executor, "runner");
    assert.equal(
      evidence.commandIdentity,
      scenario.expected.commands[0].identity,
    );
    const durable = await readFile(
      join(scenario.stateRoot, "runs", scenario.runId, "events.jsonl"),
      "utf8",
    );
    assert.doesNotMatch(durable, /PRIVATE_EXECUTOR_OUTPUT|PRIVATE_CREDENTIAL/u);
    const turns = scenario.calls.length;
    const executions = scenario.executions.length;
    await scenario.resume();
    assert.equal(scenario.calls.length, turns);
    assert.equal(scenario.executions.length, executions);
  });

  for (const access of ["read-only", "workspace-write"]) {
    for (const mutation of ["content", "replacement"]) {
      test(`project command guard blocks ${pipelineId} ${access} ${mutation}`, async (t) => {
        let mutated = false;
        const scenario = await projectCommandScenario(t, pipelineId, {
          async beforeTurn(
            request,
            durable,
            { configurationPath, projectConfiguration },
          ) {
            if (mutated || request.access !== access) return;
            mutated = true;
            if (mutation === "replacement") {
              const replacement = `${configurationPath}.replacement`;
              await writeFile(
                replacement,
                JSON.stringify(projectConfiguration),
              );
              await rename(replacement, configurationPath);
            } else {
              await writeFile(
                configurationPath,
                JSON.stringify({
                  ...projectConfiguration,
                  trustedCommands: {},
                }),
              );
            }
          },
        });
        const initialHead = await gitOutput(scenario.projectPath, [
          "rev-parse",
          "HEAD",
        ]);
        const blocked = (await scenario.resume()).run;
        assert.equal(mutated, true);
        assert.equal(blocked.pause.reason, "project_configuration_changed");
        assert.deepEqual(
          blocked.pipelineState.trustedValidation,
          scenario.expected,
        );
        const calls = scenario.calls.length;
        await scenario.resume();
        assert.equal(scenario.calls.length, calls);
        assert.equal(scenario.executions.length, 0);
        assert.equal(scenario.handoffs, 0);
        assert.equal(
          await gitOutput(scenario.projectPath, ["rev-parse", "HEAD"]),
          initialHead,
        );
        assert.equal(
          scenario.calls.some(({ access }) => access === "local-commit"),
          false,
        );
      });
    }
  }

  test(`project command execution retains Git mutation guards in ${pipelineId}`, async (t) => {
    const scenario = await projectCommandScenario(t, pipelineId, {
      execute: (paths) =>
        writeFile(
          join(paths.projectPath, "src/base.js"),
          "unauthorized validation write\n",
        ),
    });
    const initialHead = await gitOutput(scenario.projectPath, [
      "rev-parse",
      "HEAD",
    ]);
    const blocked = (await scenario.resume()).run;
    assert.equal(blocked.pipelineState.workflowState, "WAITING_FOR_USER");
    assert.equal(blocked.pause.reason, "unsafe_git_state");
    assert.equal(scenario.executions.length, 1);
    assert.equal(scenario.handoffs, 0);
    assert.equal(
      scenario.calls.some(({ access }) => access === "local-commit"),
      false,
    );
    assert.equal(
      await gitOutput(scenario.projectPath, ["rev-parse", "HEAD"]),
      initialHead,
    );
  });
}

test("project command drift preserves an already verified commit", async (t) => {
  let preserved;
  const scenario = await projectCommandScenario(t, "plan-execution", {
    async beforeTurn(request, durable, { configurationPath }) {
      if (durable.pipelineState.completedCommits.length !== 1 || preserved)
        return;
      preserved = durable.pipelineState.completedCommits;
      await writeFile(configurationPath, '{"schemaVersion":1}\n');
    },
  });
  const blocked = (await scenario.resume()).run;
  assert.equal(blocked.pause.reason, "project_configuration_changed");
  assert.equal(preserved.length, 1);
  assert.deepEqual(blocked.pipelineState.completedCommits, preserved);
  const head = await gitOutput(scenario.projectPath, ["rev-parse", "HEAD"]);
  const turns = scenario.calls.length;
  await scenario.resume();
  assert.deepEqual(
    (await scenario.runStore.loadRun(scenario.runId)).pipelineState
      .completedCommits,
    preserved,
  );
  assert.equal(scenario.calls.length, turns);
  assert.equal(
    await gitOutput(scenario.projectPath, ["rev-parse", "HEAD"]),
    head,
  );
});

test("project command drift preserves completed polishing handoff evidence", async (t) => {
  const scenario = await projectCommandScenario(t, "polishing", {
    async afterHandoff(runner, run) {
      await runner.requestOperatorStop({
        runId: run.runId,
        kind: "pause_requested",
        expectedRevision: run.revision,
        idempotencyKey: "project-command-handoff",
      });
    },
  });
  const paused = (await scenario.resume()).run;
  assert.equal(paused.pause.reason, "operator_paused");
  assert.equal(paused.pause.operatorResume.workflowState, "DONE");
  const baseline = paused.pipelineState.repositoryBaseline;
  const finalization = paused.pipelineState.finalizationResult;
  const reviewedFingerprint = paused.pipelineState.reviewedFingerprint;
  assert.ok(finalization);
  assert.equal(reviewedFingerprint, paused.pipelineState.finalizedFingerprint);
  const turns = scenario.calls.length;
  await writeFile(scenario.configurationPath, '{"schemaVersion":1}\n');
  const blocked = (await scenario.resume()).run;
  assert.equal(blocked.pause.reason, "project_configuration_changed");
  assert.deepEqual(blocked.pipelineState.repositoryBaseline, baseline);
  assert.deepEqual(blocked.pipelineState.finalizationResult, finalization);
  assert.equal(blocked.pipelineState.reviewedFingerprint, reviewedFingerprint);
  assert.equal(scenario.calls.length, turns);
  assert.equal(scenario.handoffs, 1);
});

test("polishing migrates legacy 64/128 evidence under lease without replaying a completed handoff", async (t) => {
  const paths = await fixture(t, { plan: null });
  const inventory = (role) => ({
    requiredChecks: Array.from({ length: 64 }, (_, index) => ({
      id: `C${index + 1}`,
      command: `node validation/${role}-${index}.js`,
    })),
    validationInfrastructure: Array.from(
      { length: 64 },
      (_, index) => `validation/${role}-${index}.js`,
    ),
  });
  const worker = inventory("worker");
  const reviewer = inventory("reviewer");
  const merged = {
    requiredChecks: [...worker.requiredChecks, ...reviewer.requiredChecks].map(
      ({ command }, index) => ({ id: `C${index + 1}`, command }),
    ),
    validationInfrastructure: [
      ...worker.validationInfrastructure,
      ...reviewer.validationInfrastructure,
    ],
  };
  await mkdir(join(paths.projectPath, "validation"));
  await Promise.all(
    merged.validationInfrastructure.map((path) =>
      writeFile(join(paths.projectPath, path), "// validation runner\n"),
    ),
  );
  const store = createRunStore({ stateRoot: paths.stateRoot });
  const git = createGitService();
  const backend = createBackend("codex");
  let calls = 0;
  let handoffs = 0;
  let runId;
  let runner;
  const adapters = {
    codex: {
      ...backend,
      async run(request) {
        calls += 1;
        const response = await backend.run(request);
        const result = response.structured;
        if (result.requiredChecks !== undefined) {
          Object.assign(
            result,
            result.checks === undefined
              ? request.prompt.includes("As Reviewer")
                ? reviewer
                : worker
              : merged,
          );
          if (result.checks !== undefined)
            result.checks = merged.requiredChecks.map(({ id, command }) => ({
              checkId: id,
              command,
              status: "PASS",
              evidence: ["Fixture check passed."],
            }));
        }
        return response;
      },
    },
  };
  function openRunner(loadConfiguration) {
    return createRunner({
      adapters,
      runStore: store,
      clarifications: createClarificationService({ interactive: false }),
      git: {
        ...git,
        async stagePolishingHandoff(options) {
          handoffs += 1;
          const result = await git.stagePolishingHandoff(options);
          const run = await store.loadRun(runId);
          await runner.requestOperatorStop({
            runId,
            kind: "pause_requested",
            expectedRevision: run.revision,
            idempotencyKey: "capacity-handoff",
          });
          return result;
        },
      },
      loadConfiguration,
    });
  }
  runner = openRunner(async () =>
    parseRunnerConfiguration(
      JSON.stringify({
        schemaVersion: 1,
        defaultBackend: "codex",
        pipelines: { polishing: { finalization: "none" } },
      }),
    ),
  );
  const prepared = await runner.create({
    pipelineId: "polishing",
    projectPath: paths.projectPath,
    taskPath: paths.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  });
  runId = prepared.run.runId;
  const paused = (await runner.resume({ runId })).run;
  assert.equal(paused.pause.operatorResume.workflowState, "DONE");
  assert.equal(paused.pipelineState.workerValidation.requiredChecks.length, 64);
  assert.equal(paused.pipelineState.requiredChecks.length, 128);
  assert.equal(handoffs, 1);
  const turns = calls;
  const statePath = join(prepared.directoryPath, "state.json");
  const eventsPath = join(prepared.directoryPath, "events.jsonl");
  async function downgrade() {
    const state = JSON.parse(await readFile(statePath, "utf8"));
    const events = (await readFile(eventsPath, "utf8"))
      .trimEnd()
      .split("\n")
      .map((line) => JSON.parse(line));
    for (const saved of [state, ...events.map((event) => event.state)])
      saved.pipelineStateVersion = 11;
    await writeFile(statePath, `${JSON.stringify(state)}\n`);
    await writeFile(
      eventsPath,
      `${events.map((event) => JSON.stringify(event)).join("\n")}\n`,
    );
  }
  await downgrade();
  runner = openRunner(async () => {
    throw new Error("Resume reloaded configuration.");
  });
  const before = await Promise.all([readFile(statePath), readFile(eventsPath)]);
  const lease = await store.acquireRunLease(runId);
  try {
    assert.equal((await runner.status(runId)).run.pipelineStateVersion, 12);
    await assert.rejects(runner.resume({ runId }), { code: "ERR_RUN_LEASED" });
    assert.deepEqual(
      await Promise.all([readFile(statePath), readFile(eventsPath)]),
      before,
    );
  } finally {
    await lease.release();
  }
  const completed = (await runner.resume({ runId })).run;
  assert.equal(completed.pipelineStateVersion, 12);
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.deepEqual(
    completed.pipelineState.finalizationResult,
    paused.pipelineState.finalizationResult,
  );
  assert.deepEqual(completed.counters, paused.counters);
  assert.equal(calls, turns);
  assert.equal(handoffs, 1);
  const history = await store.loadRunHistory(runId);
  const migrations = history.events.filter(
    ({ activity }) => activity?.kind === "migrated",
  );
  assert.equal(migrations.length, 1);
  assert.deepEqual(migrations[0].state.pipelineState, paused.pipelineState);
  assert.equal(migrations[0].state.pipelineStateVersion, 12);
  const terminalState = completed.pipelineState;
  await downgrade();
  const terminal = (await runner.resume({ runId })).run;
  assert.deepEqual(terminal.pipelineState, terminalState);
  assert.equal(terminal.pipelineStateVersion, 12);
  assert.equal(calls, turns);
  assert.equal(handoffs, 1);
});
