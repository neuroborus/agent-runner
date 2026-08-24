import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join, relative, sep } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import {
  createClarificationService,
  createGitService,
  createMcpControlPlane,
  createRunner,
  createRunStore,
  main,
  parseRunnerConfiguration,
} from "../src/index.js";

const executeFile = promisify(execFile);
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
          requiredChecks: [{ id: "C1", command: "git diff --check" }],
          validationInfrastructure: [],
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
                requiredChecks: [],
                validationInfrastructure: [],
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
                requiredChecks: [{ id: "C1", command: "git diff --check" }],
                validationInfrastructure: [],
                reason: "",
                question: "",
                options: [],
                whyBlocked: "",
                evidence: [],
              };
      } else if (request.prompt.includes("Resolve the bootstrap disagreement")) {
        role = "arbiter";
        structured = {
          direction: "SYNTHESIZE",
          summary: "Use the existing minimal module boundary.",
          requiredChecks: [{ id: "C1", command: "git diff --check" }],
          validationInfrastructure: [],
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
        structured = {
          status: "COMPLETED",
          summary: "The existing dirty change is already idiomatic and minimal.",
          reason: "",
          question: "",
          options: [],
          whyBlocked: "",
          evidence: [],
        };
      } else if (
        request.prompt.includes("Run the complete project finalization procedure")
      ) {
        structured = {
          status: "PASS",
          skillPath: "",
          summary: "The repository finalization procedure passed.",
          issues: [],
          requiredChecks: [{ id: "C1", command: "git diff --check" }],
          validationInfrastructure: [],
          checks: [
            {
              checkId: "C1",
              command: "git diff --check",
              status: "PASS",
              evidence: ["git diff --check exited successfully."],
            },
          ],
          reason: "",
          question: "",
          options: [],
          whyBlocked: "",
          evidence: [],
        };
      } else if (
        request.prompt.includes("Review the changes and verify") ||
        request.prompt.includes("Review the complete current change set")
      ) {
        role = "reviewer";
        structured = {
          status: "APPROVED",
          findings: [],
          validationChange: "UNCHANGED",
          validationEvidence: [],
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
  assert.equal(await readFile(join(paths.taskPath, "plan.md"), "utf8"), TWO_STEP_PLAN);
  const run = await onlyRun(runStore);
  assert.equal(run.pipelineState.workflowState, "DONE");
  assert.equal(run.roles.planner.backend, "codex");
  assert.equal(run.roles.reviewer.backend, "claude");
  assert.equal(codex.calls.some((call) => call.access === "workspace-write"), false);
  assert.equal(claude.calls.some((call) => call.access !== "read-only"), false);
  assert.equal(await gitOutput(paths.projectPath, ["status", "--porcelain"]), "");
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
  assert.equal(await readFile(join(paths.taskPath, "plan.md"), "utf8"), TWO_STEP_PLAN);
  assert.equal(await gitOutput(paths.projectPath, ["status", "--porcelain"]), "");
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

  assert.equal(exitCode, 0);
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
  assert.equal(await gitOutput(paths.projectPath, ["rev-parse", "HEAD"]), initialHead);
  assert.equal(
    await gitOutput(paths.projectPath, ["status", "--porcelain"]),
    "M src/base.js",
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

      assert.equal(
        exitCode,
        0,
        `${stdout.value()}${stderr.value()}`,
      );
      assert.equal(stderr.value(), "");
      assert.match(stdout.value(), /State: DONE/u);
      const run = await onlyRun(runStore);
      assert.equal(run.pipelineState.workflowState, "DONE");
      assert.equal(run.pipelineState.completedCommits.length, 2);
      assert.deepEqual(
        Object.fromEntries(
          Object.entries(run.roles).map(([role, value]) => [role, value.backend]),
        ),
        scenario.roles,
      );
      assert.deepEqual(
        (await gitOutput(paths.projectPath, ["log", "--reverse", "--pretty=%s"]))
          .split("\n")
          .slice(-2),
        ["feat(feature): add value", "test(feature): cover value"],
      );
      assert.equal(await gitOutput(paths.projectPath, ["status", "--porcelain"]), "");
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
        const stepReviews = allCalls.filter((call) =>
          call.prompt.includes("Review the changes and verify"),
        );
        assert.equal(stepReviews.length, 2);
        assert.ok(
          stepReviews.every(
            ({ session }) =>
              session?.mode === "fork" && session.id === scenario.source,
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

test("runs registered workflows through recoverable MCP controls", async (t) => {
  const paths = await fixture(t, { autoCleanup: false, plan: null });
  const implementationGate = {
    entered: deferred(),
    release: deferred(),
  };
  const codex = createBackend("codex", {
    authoringQuestion: true,
    failExecutionClarification: true,
    implementationGate,
  });
  const { runner, runStore } = runtime(
    paths,
    { codex },
    { schemaVersion: 1, defaultBackend: "codex" },
  );
  const pipelineProcess = detached(runner);
  t.after(async () => {
    implementationGate.release.resolve();
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
  const authoringPause = await control.runWait(
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
  const authoringDone = await control.runWait({
    runId: authored.runId,
    cursor: authoringPause.activityCursor,
    timeoutMs: 5_000,
    progress: false,
  });
  assert.equal(authoringDone.status, "DONE");
  assert.match(
    await readFile(join(paths.taskPath, "clarifications.md"), "utf8"),
    /### A1\n\nExpose the value directly\./u,
  );
  assert.equal(await readFile(join(paths.taskPath, "plan.md"), "utf8"), TWO_STEP_PLAN);

  const execution = await control.runStart({
    idempotencyKey: "execution-start",
    pipelineId: "plan-execution",
    projectPath: paths.projectPath,
    taskPath: paths.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  });
  const executionPause = await control.runWait({
    runId: execution.runId,
    cursor: 0,
    timeoutMs: 5_000,
    progress: false,
  });
  assert.equal(executionPause.status, "WAITING_FOR_USER");
  assert.equal(executionPause.pause, "backend_unavailable");

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
    5_000,
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
  const executionDone = await afterDisconnect.runWait({
    runId: execution.runId,
    cursor: timedOut.activityCursor,
    timeoutMs: 5_000,
    progress: false,
  });
  await pipelineProcess.settle();
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
  assert.equal(await gitOutput(paths.projectPath, ["status", "--porcelain"]), "");
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
  const polishingDone = await afterDisconnect.runWait({
    runId: polishing.runId,
    cursor: 0,
    timeoutMs: 5_000,
    progress: false,
  });
  await pipelineProcess.settle();
  assert.equal(polishingDone.status, "DONE");
  assert.equal(polishingDone.planPath, null);
  assert.equal(polishingDone.completedCommits.length, 0);
  assert.equal(
    codex.calls.slice(callCount).some(({ access }) => access === "local-commit"),
    false,
  );
  assert.equal(
    await gitOutput(paths.projectPath, ["rev-parse", "HEAD"]),
    polishingHead,
  );
  assert.equal(
    await gitOutput(paths.projectPath, ["status", "--porcelain"]),
    "M src/base.js",
  );
});
