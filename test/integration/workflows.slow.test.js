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
} from "../../src/index.js";

const executeFile = promisify(execFile);

const TWO_STEP_PLAN = `## Commit 1: feat(feature): add value

Add the requested value.

## Commit 2: test(feature): cover value

Cover the requested value.`;

const ONE_STEP_PLAN = TWO_STEP_PLAN.split("\n## Commit 2:")[0];

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
  { failExecutionClarification = false, implementationGate = null } = {},
) {
  const calls = [];
  let executionClarifications = 0;
  let implementationCalls = 0;
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
      const position = /Runner-selected plan position[^\n]*\n([^\n]+)/u.exec(
        request.prompt,
      );
      const assessment = position && {
        ...JSON.parse(position[1]),
        disposition: "CURRENT",
        evidence: [],
      };
      if (assessment) delete assessment.completed;
      if (request.prompt.startsWith("Validate the proposed context"))
        return {
          structured: { stepAssessment: assessment },
          sessionId: sessionId(request, "worker"),
        };
      calls.push(request);
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
      if (
        request.prompt.includes(
          "Return the complete revised plan only when content changed.",
        ) ||
        request.prompt.includes(
          "Concrete findings from the preceding clean confirmation:",
        )
      ) {
        const authoring = request.prompt.includes(
          "Return the complete revised plan",
        );
        role = authoring ? "planner" : "worker";
        structured = {
          status: "UNCHANGED",
          ...(authoring
            ? { plan: "" }
            : { summary: "The candidate needs no repair.", reason: "" }),
          question: "",
          options: [],
          whyBlocked: "",
          evidence: [],
        };
      } else if (
        request.prompt.includes(
          "A CLEAN result confirms primary convergence",
        ) ||
        request.prompt.includes("Inspected candidate fingerprint:")
      ) {
        role = request.prompt.includes("primary convergence")
          ? "planner"
          : "worker";
        structured = {
          status: "CLEAN",
          findings: [],
          question: "",
          options: [],
          whyBlocked: "",
          evidence: [],
        };
      } else if (
        request.prompt.includes("Study the task, existing clarifications")
      ) {
        role = "planner";
        structured = { status: "READY", questions: [] };
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
          requiredChecks: [
            {
              id: "C1",
              command: "git diff --check HEAD",
              ...(request.schema?.properties?.result?.anyOf?.[0]?.properties
                ?.requiredChecks?.items?.properties?.steps
                ? {
                    steps: [
                      ...new Set(
                        [
                          ...request.prompt.matchAll(/^## Commit ([0-9]+):/gm),
                        ].map((match) => Number(match[1])),
                      ),
                    ].sort((a, b) => a - b),
                  }
                : {}),
            },
          ],
          validationInfrastructure: [],
          ...((request.schema?.properties?.result?.anyOf?.[0]?.properties
            ?.capabilityRequirements ??
          request.schema?.properties?.capabilityRequirements)
            ? { capabilityRequirements: [], environmentBlockers: [] }
            : {}),
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
        structured = {
          status: "RESOLVED",
          summary: "Use the existing minimal module boundary.",
          disagreement: "",
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

      if (
        (
          request.schema?.properties?.result?.anyOf?.[0]?.properties ??
          request.schema?.properties
        )?.stepAssessment
      )
        structured.stepAssessment = assessment;
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
    launchRun(runId, action = null, options = {}) {
      const execution = runner
        .resume({
          runId,
          action,
          dispatch: options.dispatch,
          expectedRuntimeCompatibility: options.expectedRuntimeCompatibility,
          ...(options.stopCheckpointRevision == null
            ? {}
            : { stopCheckpointRevision: options.stopCheckpointRevision }),
        })
        .then(({ run }) =>
          options.onExit?.(
            run.pipelineState.workflowState === "WAITING_FOR_USER" ? 2 : 0,
          ),
        )
        .catch((error) => {
          failures.push(error);
          options.onExit?.(1);
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

test("continues one detached MCP execution after client replacement", async (t) => {
  const paths = await fixture(t, {
    autoCleanup: false,
    plan: ONE_STEP_PLAN,
  });
  const implementationGate = {
    entered: deferred(),
    release: deferred(),
  };
  const codex = createBackend("codex", {
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
  const execution = await control.runStart({
    idempotencyKey: "execution-start",
    pipelineId: "plan-execution",
    projectPath: paths.projectPath,
    taskPath: paths.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  });
  await pipelineProcess.settle();
  const paused = await control.runStatus({ runId: execution.runId });
  assert.equal(paused.status, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pause.resumeState, "CLARIFY");

  const reconnected = createMcpControlPlane({
    launchRun: pipelineProcess.launchRun,
    runner,
    runStore,
  });
  await reconnected.runResume({
    idempotencyKey: "execution-resume",
    runId: execution.runId,
    expectedRevision: paused.revision,
    action: null,
  });
  await within(
    implementationGate.entered.promise,
    30_000,
    "Execution did not reach implementation.",
  );

  const running = await reconnected.runStatus({ runId: execution.runId });
  assert.equal(running.execution.state, "running");
  await reconnected.runCancel({
    idempotencyKey: "execution-cancel",
    runId: execution.runId,
    expectedRevision: running.revision,
  });
  implementationGate.release.resolve();
  await pipelineProcess.settle();
  const canceled = await reconnected.runStatus({ runId: execution.runId });
  assert.equal(canceled.status, "CANCELED");
  assert.equal(canceled.completedCommits.length, 0);
});
