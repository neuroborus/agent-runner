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
        request.prompt.includes("Return a concise bootstrap summary")
      ) {
        const reviewer = request.prompt.includes("As Reviewer");
        role = reviewer ? "reviewer" : "worker";
        structured = {
          status: "READY",
          summary:
            `${reviewer ? "Reviewer" : "Worker"} understands the task, ` +
            "plan, risks, and finalization procedure.",
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
      } else if (request.prompt.includes("Resolve the bootstrap disagreement")) {
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
        request.prompt.includes(
          "Locate and validate the project's finalization skill",
        )
      ) {
        structured = {
          status: "PASS",
          skillPath: ".agents/skills/finalization/SKILL.md",
          summary: "The repository finalization procedure passed.",
          issues: [],
          reason: "",
          question: "",
          options: [],
          whyBlocked: "",
          evidence: [],
        };
      } else if (request.prompt.includes("Review the changes and verify")) {
        role = "reviewer";
        structured = {
          status: "APPROVED",
          findings: [],
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
        structured,
        sessionId: sessionId(request, role),
      };
    },
  };
}

async function fixture(
  t,
  configuration,
  { autoCleanup = true, plan = TWO_STEP_PLAN } = {},
) {
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
    writeFile(
      join(projectPath, ".gitignore"),
      "/.agent-runner.json\n/LOCAL_ARTIFACTS/\n",
    ),
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
  await writeFile(
    join(projectPath, ".agent-runner.json"),
    `${JSON.stringify(configuration)}\n`,
  );
  const cleanup = () => rm(workspace, { recursive: true, force: true });
  if (autoCleanup) {
    t.after(cleanup);
  }
  return { cleanup, projectPath, stateRoot, taskPath };
}

function runtime(paths, adapters) {
  const runStore = createRunStore({ stateRoot: paths.stateRoot });
  const runner = createRunner({
    adapters,
    clarifications: createClarificationService({ interactive: false }),
    git: createGitService(),
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
  const paths = await fixture(
    t,
    { schemaVersion: 1, defaultBackend: "codex" },
    { plan: null },
  );
  const codex = createBackend("codex");
  const claude = createBackend("claude");
  const { runner, runStore } = runtime(paths, { claude, codex });
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

test("executes every planned commit across backend configurations", async (t) => {
  const cases = [
    {
      name: "Codex repository default",
      configuration: { schemaVersion: 1, defaultBackend: "codex" },
      args: ["--fork-from", "codex:source-codex"],
      roles: { worker: "codex", reviewer: "codex", arbiter: "codex" },
      source: "source-codex",
    },
    {
      name: "Claude repository default",
      configuration: { schemaVersion: 1, defaultBackend: "claude" },
      args: ["--fork-from", "claude:source-claude"],
      roles: { worker: "claude", reviewer: "claude", arbiter: "claude" },
      source: "source-claude",
    },
    {
      name: "repository role overrides",
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
      const paths = await fixture(t, scenario.configuration);
      const codex = createBackend("codex", {
        bootstrapDisagreement: scenario.bootstrapDisagreement,
      });
      const claude = createBackend("claude", {
        bootstrapDisagreement: scenario.bootstrapDisagreement,
      });
      const { runner, runStore } = runtime(paths, { claude, codex });
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
        assert.equal(stepReviews[0].session?.mode, "continue");
        assert.notEqual(stepReviews[0].session?.id, scenario.source);
        assert.deepEqual(stepReviews[1].session, {
          mode: "fork",
          id: scenario.source,
        });
        assert.equal(
          run.sessionLineage.children.filter(({ role }) => role === "reviewer")
            .length,
          2,
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
      const paths = await fixture(t, {
        schemaVersion: 1,
        defaultBackend: backend,
      });
      const adapter = createBackend(backend, { rejectSource: true });
      const { runner } = runtime(paths, { [backend]: adapter });
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

test("runs both pipelines through recoverable MCP controls", async (t) => {
  const paths = await fixture(
    t,
    { schemaVersion: 1, defaultBackend: "codex" },
    { autoCleanup: false, plan: null },
  );
  const implementationGate = {
    entered: deferred(),
    release: deferred(),
  };
  const codex = createBackend("codex", {
    authoringQuestion: true,
    failExecutionClarification: true,
    implementationGate,
  });
  const { runner, runStore } = runtime(paths, { codex });
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
});
