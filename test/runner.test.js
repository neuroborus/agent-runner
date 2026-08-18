import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import {
  createClarificationService,
  createGitService,
  createRunner,
  createRunStore,
  RunnerError,
} from "../src/index.js";

const executeFile = promisify(execFile);
const SOURCE_SESSION = "11111111-1111-4111-8111-111111111111";
const PLANNER_SESSION = "22222222-2222-4222-8222-222222222222";
const REVIEWER_SESSION = "33333333-3333-4333-8333-333333333333";
const ARBITER_SESSION = "44444444-4444-4444-8444-444444444444";
const PLAN = `## Commit 1: feat(test): add behavior

Implement the requested behavior.`;

function questions() {
  return {
    status: "QUESTIONS",
    questions: [
      {
        question: "Which behavior is required?",
        whyItMatters: "The answer changes the commit plan.",
      },
    ],
  };
}

function ready() {
  return { status: "READY", questions: [] };
}

function draft() {
  return {
    status: "DRAFT",
    plan: PLAN,
    question: "",
    options: [],
    whyBlocked: "",
    evidence: [],
  };
}

function approved() {
  return {
    status: "APPROVED",
    findings: [],
    question: "",
    options: [],
    whyBlocked: "",
    evidence: [],
  };
}

function createAdapter({ fork = true, questionFirst = false } = {}) {
  const calls = [];
  let clarificationCalls = 0;
  return {
    calls,
    async probe() {
      return {
        version: "fake-1.0.0",
        structuredOutput: true,
        readOnly: true,
        autonomousWrite: true,
        workspaceWrite: true,
        localCommit: true,
        remoteWriteBlocked: true,
        nativeSessionContinuation: true,
        nativeSessionFork: fork,
      };
    },
    async run(request) {
      calls.push(request);
      let structured;
      let sessionId =
        request.session?.mode === "continue" ? request.session.id : undefined;
      if (request.prompt.includes("Study the task, existing clarifications")) {
        clarificationCalls += 1;
        structured =
          questionFirst && clarificationCalls === 1 ? questions() : ready();
        sessionId ??= PLANNER_SESSION;
      } else if (
        request.prompt.includes("Write a concise commit-by-commit plan")
      ) {
        structured = draft();
        sessionId ??= PLANNER_SESSION;
      } else if (
        request.prompt.includes("Review the plan and verify that it is correct")
      ) {
        structured = approved();
        sessionId =
          request.session?.mode === "continue"
            ? request.session.id
            : REVIEWER_SESSION;
      } else {
        throw new Error("Unexpected fake adapter turn.");
      }
      return { output: "structured", structured, sessionId };
    },
  };
}

function createExecutionAdapter({ bootstrapDisagreement = false } = {}) {
  const calls = [];
  return {
    calls,
    async probe() {
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
    },
    async run(request) {
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
          sessionId: request.session.id,
        };
      }
      let structured;
      let sessionId =
        request.session?.mode === "continue" ? request.session.id : undefined;
      if (request.prompt.includes("Study the task, validated plan")) {
        structured = {
          status: "READY",
          questions: [],
          reason: "",
          question: "",
          options: [],
          whyBlocked: "",
          evidence: [],
        };
        sessionId ??= PLANNER_SESSION;
      } else if (request.prompt.includes("Return a concise bootstrap summary")) {
        const reviewer = request.prompt.includes("As Reviewer");
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
        sessionId ??= reviewer ? REVIEWER_SESSION : PLANNER_SESSION;
      } else if (
        request.prompt.includes("Reconcile the independent Worker and Reviewer")
      ) {
        structured = bootstrapDisagreement
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
              summary: "The roles agree on the minimal implementation.",
              disagreement: "",
              reason: "",
              question: "",
              options: [],
              whyBlocked: "",
              evidence: [],
            };
      } else if (request.prompt.includes("Implement the changes described")) {
        await writeFile(
          join(request.cwd, "feature.js"),
          "export const value = 1;\n",
        );
        structured = {
          status: "COMPLETED",
          summary: "Implemented and self-reviewed the planned change.",
          reason: "",
          question: "",
          options: [],
          whyBlocked: "",
          evidence: [],
        };
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
        structured = {
          status: "APPROVED",
          findings: [],
          question: "",
          options: [],
          whyBlocked: "",
          evidence: [],
        };
        sessionId ??= REVIEWER_SESSION;
      } else {
        throw new Error("Unexpected fake execution turn.");
      }
      return { output: "structured", structured, sessionId };
    },
  };
}

function createArbiterAdapter() {
  let probeCalls = 0;
  const calls = [];
  return {
    calls,
    get probeCalls() {
      return probeCalls;
    },
    async probe() {
      probeCalls += 1;
      return {
        version: "fake-1.0.0",
        structuredOutput: true,
        readOnly: true,
        remoteWriteBlocked: true,
      };
    },
    async run(request) {
      assert.equal(probeCalls, 1);
      calls.push(request);
      assert.match(request.prompt, /^Resolve the bootstrap disagreement/u);
      return {
        output: "structured",
        structured: {
          direction: "SYNTHESIZE",
          summary: "Use the existing minimal module boundary.",
          rationale: "Repository ownership supports that boundary.",
          reason: "",
          question: "",
          options: [],
          whyBlocked: "",
          evidence: [],
        },
        sessionId: ARBITER_SESSION,
      };
    },
  };
}

async function createFixture(t) {
  const workspace = await mkdtemp(join(tmpdir(), "agent-runner-runtime-"));
  const projectPath = join(workspace, "project");
  const taskPath = join(workspace, "task");
  const stateRoot = join(workspace, "state");
  await Promise.all([mkdir(projectPath), mkdir(taskPath)]);
  await executeFile("git", ["init", "-q", projectPath]);
  await Promise.all([
    writeFile(join(projectPath, ".gitignore"), "/.agent-runner.json\n"),
    writeFile(
      join(projectPath, ".agent-runner.json"),
      '{"schemaVersion":1,"defaultBackend":"codex"}\n',
    ),
    writeFile(join(taskPath, "task.md"), "Implement the requested behavior.\n"),
  ]);
  t.after(() => rm(workspace, { recursive: true, force: true }));
  return { projectPath, stateRoot, taskPath, workspace };
}

function runnerFor(fixture, adapters, activities = []) {
  return createRunner({
    adapters,
    clarifications: createClarificationService({ interactive: false }),
    git: createGitService(),
    onActivity(activity) {
      activities.push(activity);
    },
    runStore: createRunStore({ stateRoot: fixture.stateRoot }),
  });
}

test("runs and resumes a registered pipeline from persisted configuration", async (t) => {
  const fixture = await createFixture(t);
  const adapter = createAdapter({ questionFirst: true });
  const activities = [];
  const firstRunner = runnerFor(fixture, { codex: adapter }, activities);

  const paused = await firstRunner.run({
    pipelineId: "plan-authoring",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    proactiveClarification: false,
    roleOverrides: { planner: { model: "planner-model" } },
    sourceSession: { backend: "codex", id: SOURCE_SESSION },
  });

  assert.equal(paused.run.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.run.pause.reason, "clarification_answers_required");
  assert.equal(paused.run.sessionLineage.source, SOURCE_SESSION);
  assert.deepEqual(paused.run.roles.planner, {
    backend: "codex",
    model: "planner-model",
  });
  assert.deepEqual(paused.run.pipelineState.settings, {
    maxRevisionRounds: 15,
    stagnationWindowRounds: 3,
  });
  assert.deepEqual(adapter.calls[0].session, {
    mode: "fork",
    id: SOURCE_SESSION,
  });

  const clarificationPath = join(fixture.taskPath, "clarifications.md");
  await writeFile(
    clarificationPath,
    `${await readFile(clarificationPath, "utf8")}\nUse behavior A.\n`,
  );
  await writeFile(
    join(fixture.projectPath, ".agent-runner.json"),
    '{"schemaVersion":1,"defaultBackend":"claude"}\n',
  );

  const secondRunner = runnerFor(fixture, { codex: adapter }, activities);
  const beforeResume = await secondRunner.status(paused.run.runId);
  const completed = await secondRunner.resume({
    runId: paused.run.runId,
    action: null,
  });

  assert.equal(beforeResume.run.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(completed.run.pipelineState.workflowState, "DONE");
  assert.equal(await readFile(join(fixture.taskPath, "plan.md"), "utf8"), PLAN);
  assert.deepEqual(completed.run.roles, paused.run.roles);
  assert.deepEqual(completed.run.pipelineState.settings, {
    maxRevisionRounds: 15,
    stagnationWindowRounds: 3,
  });
  assert.deepEqual(
    completed.run.sessionLineage.children.map(({ role, sessionId }) => ({
      role,
      sessionId,
    })),
    [
      { role: "planner", sessionId: PLANNER_SESSION },
      { role: "reviewer", sessionId: REVIEWER_SESSION },
    ],
  );
  assert.deepEqual(
    adapter.calls.find((call) =>
      call.prompt.includes("Review the plan and verify that it is correct"),
    ).session,
    { mode: "fork", id: SOURCE_SESSION },
  );
  assert.ok(activities.some(({ actor }) => actor === "planner"));
  assert.ok(activities.some(({ actor }) => actor === "reviewer"));
  assert.ok(activities.every(({ runId }) => runId === paused.run.runId));
});

test("rejects incompatible or unsupported source sessions before creating a run", async (t) => {
  const fixture = await createFixture(t);
  const adapter = createAdapter();
  const runner = runnerFor(fixture, { codex: adapter });

  await assert.rejects(
    runner.run({
      pipelineId: "plan-authoring",
      projectPath: fixture.projectPath,
      taskPath: fixture.taskPath,
      roleOverrides: {},
      sourceSession: { backend: "claude", id: SOURCE_SESSION },
    }),
    (error) =>
      error instanceof RunnerError &&
      error.code === "ERR_SOURCE_BACKEND_MISMATCH",
  );

  const noForkRunner = runnerFor(fixture, {
    codex: createAdapter({ fork: false }),
  });
  await assert.rejects(
    noForkRunner.run({
      pipelineId: "plan-authoring",
      projectPath: fixture.projectPath,
      taskPath: fixture.taskPath,
      roleOverrides: {},
      sourceSession: { backend: "codex", id: SOURCE_SESSION },
    }),
    (error) =>
      error instanceof RunnerError &&
      error.code === "ERR_UNSUPPORTED_SOURCE_SESSION",
  );

  assert.deepEqual(
    await readdir(join(fixture.stateRoot, "runs")).catch((error) => {
      if (error?.code === "ENOENT") {
        return [];
      }
      throw error;
    }),
    [],
  );
});

test("does not require an unused Arbiter backend", async (t) => {
  const fixture = await createFixture(t);
  await writeFile(
    join(fixture.projectPath, ".agent-runner.json"),
    JSON.stringify({
      schemaVersion: 1,
      defaultBackend: "codex",
      pipelines: {
        "plan-authoring": {
          roles: { arbiter: { backend: "claude" } },
        },
      },
    }),
  );
  const adapter = createAdapter();
  const runner = runnerFor(fixture, { codex: adapter });

  const result = await runner.run({
    pipelineId: "plan-authoring",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    roleOverrides: {},
    sourceSession: null,
  });

  assert.equal(result.run.pipelineState.workflowState, "DONE");
  assert.deepEqual(result.run.roles.arbiter, {
    backend: "claude",
    model: null,
  });
});

test("releases a new run lease when activity delivery fails", async (t) => {
  const fixture = await createFixture(t);
  const runStore = createRunStore({ stateRoot: fixture.stateRoot });
  const deliveryError = new Error("Activity delivery failed.");
  const runner = createRunner({
    adapters: { codex: createAdapter() },
    clarifications: createClarificationService({ interactive: false }),
    git: createGitService(),
    onActivity() {
      throw deliveryError;
    },
    runStore,
  });

  await assert.rejects(
    runner.run({
      pipelineId: "plan-authoring",
      projectPath: fixture.projectPath,
      taskPath: fixture.taskPath,
      roleOverrides: {},
      sourceSession: null,
    }),
    (error) => error === deliveryError,
  );

  const [runId] = await readdir(join(fixture.stateRoot, "runs"));
  const lease = await runStore.acquireRunLease(runId);
  await lease.release();
});

test("dispatches plan execution through the root Git and state services", async (t) => {
  const fixture = await createFixture(t);
  await Promise.all([
    writeFile(
      join(fixture.projectPath, ".gitignore"),
      "/.agent-runner.json\n/LOCAL_ARTIFACTS/\n",
    ),
    writeFile(join(fixture.projectPath, "source.js"), "export const value = 0;\n"),
    writeFile(join(fixture.taskPath, "plan.md"), PLAN),
  ]);
  await executeFile("git", [
    "-C",
    fixture.projectPath,
    "config",
    "user.name",
    "Test User",
  ]);
  await executeFile("git", [
    "-C",
    fixture.projectPath,
    "config",
    "user.email",
    "test@example.com",
  ]);
  await executeFile("git", [
    "-C",
    fixture.projectPath,
    "add",
    ".gitignore",
    "source.js",
  ]);
  await executeFile("git", [
    "-C",
    fixture.projectPath,
    "commit",
    "-qm",
    "chore(test): initialize",
  ]);
  await writeFile(
    join(fixture.projectPath, ".agent-runner.json"),
    JSON.stringify({
      schemaVersion: 1,
      defaultBackend: "codex",
      pipelines: {
        "plan-execution": {
          roles: { arbiter: { backend: "claude" } },
        },
      },
    }),
  );
  const adapter = createExecutionAdapter({ bootstrapDisagreement: true });
  const arbiter = createArbiterAdapter();
  const activities = [];
  const runner = runnerFor(
    fixture,
    { codex: adapter, claude: arbiter },
    activities,
  );

  const result = await runner.run({
    pipelineId: "plan-execution",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    roleOverrides: {},
    sourceSession: null,
  });
  const { stdout } = await executeFile("git", [
    "-C",
    fixture.projectPath,
    "log",
    "-1",
    "--pretty=%s",
  ]);

  assert.equal(result.run.pipelineState.workflowState, "DONE");
  assert.equal(result.run.pipelineState.completedCommits.length, 1);
  assert.equal(stdout.trim(), "feat(test): add behavior");
  assert.equal(arbiter.probeCalls, 1);
  assert.equal(arbiter.calls.length, 1);
  assert.ok(adapter.calls.some(({ access }) => access === "local-commit"));
  assert.ok(
    activities.some(
      ({ actor, phase, kind }) =>
        actor === "worker" && phase === "commit" && kind === "created",
    ),
  );
});
