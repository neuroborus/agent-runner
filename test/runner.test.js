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
  parseRunnerConfiguration,
  RunnerError,
} from "../src/index.js";

const executeFile = promisify(execFile);
const SOURCE_SESSION = "11111111-1111-4111-8111-111111111111";
const PLANNER_SESSION = "22222222-2222-4222-8222-222222222222";
const POST_CLARIFICATION_PLANNER_SESSION = `${PLANNER_SESSION}:1`;
const PLANNING_SESSION = `${PLANNER_SESSION}:2`;
const REVIEWER_SESSION = "33333333-3333-4333-8333-333333333333";
const ARBITER_SESSION = "44444444-4444-4444-8444-444444444444";
const PREPARED_RUN = "55555555-5555-4555-8555-555555555555";
const RUNNER_CONFIGURATION = { schemaVersion: 1, defaultBackend: "codex" };
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
  const probes = [];
  let clarificationCalls = 0;
  let freshPlannerSessions = 0;
  function plannerSession() {
    const sessionId =
      freshPlannerSessions === 0
        ? PLANNER_SESSION
        : `${PLANNER_SESSION}:${freshPlannerSessions}`;
    freshPlannerSessions += 1;
    return sessionId;
  }
  return {
    calls,
    probes,
    async probe(options) {
      probes.push(options);
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
        sessionId ??= plannerSession();
      } else if (
        request.prompt.includes("Write a concise commit-by-commit plan")
      ) {
        structured = draft();
        sessionId ??= plannerSession();
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
  const probes = [];
  let freshSessionCount = 0;
  function freshSession() {
    const index = freshSessionCount;
    freshSessionCount += 1;
    return index === 0 ? PLANNER_SESSION : `${PLANNER_SESSION}:${index}`;
  }
  return {
    calls,
    probes,
    async probe(options) {
      probes.push(options);
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
      if (
        request.prompt.includes("Study the task, validated plan") ||
        request.prompt.includes("Study the task, existing changes")
      ) {
        structured = {
          status: "READY",
          questions: [],
          reason: "",
          question: "",
          options: [],
          whyBlocked: "",
          evidence: [],
        };
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
      } else if (
        request.prompt.includes("Implement the changes described") ||
        request.prompt.includes("Polish the existing local repository changes")
      ) {
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
        request.prompt.includes("Run the complete project finalization procedure")
      ) {
        structured = {
          status: "PASS",
          skillPath: "",
          summary: "The repository finalization procedure passed.",
          issues: [],
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
        structured = {
          status: "APPROVED",
          findings: [],
          question: "",
          options: [],
          whyBlocked: "",
          evidence: [],
        };
      } else {
        throw new Error("Unexpected fake execution turn.");
      }
      sessionId ??= freshSession();
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
  await writeFile(
    join(taskPath, "task.md"),
    "Implement the requested behavior.\n",
  );
  t.after(() => rm(workspace, { recursive: true, force: true }));
  return { projectPath, stateRoot, taskPath, workspace };
}

function configurationLoader(configuration = RUNNER_CONFIGURATION) {
  return async () => parseRunnerConfiguration(JSON.stringify(configuration));
}

function runnerFor(
  fixture,
  adapters,
  {
    activities = [],
    configuration = RUNNER_CONFIGURATION,
    git = createGitService(),
    runStore = createRunStore({ stateRoot: fixture.stateRoot }),
  } = {},
) {
  return createRunner({
    adapters,
    clarifications: createClarificationService({ interactive: false }),
    git,
    loadConfiguration: configurationLoader(configuration),
    onActivity(activity) {
      activities.push(activity);
    },
    runStore,
  });
}

test("validates the canonical Git root before creating external state", async (t) => {
  const fixture = await createFixture(t);
  const nestedProjectPath = join(fixture.projectPath, "nested");
  const unsafeStateRoot = join(fixture.projectPath, ".state");
  await mkdir(nestedProjectPath);
  const runner = runnerFor(
    fixture,
    { codex: createAdapter() },
    { runStore: createRunStore({ stateRoot: unsafeStateRoot }) },
  );

  await assert.rejects(
    runner.validateBoundary({
      projectPath: nestedProjectPath,
      taskPath: fixture.taskPath,
    }),
    (error) => error.code === "ERR_UNSAFE_STATE_ROOT",
  );
  await assert.rejects(readdir(unsafeStateRoot), /ENOENT/u);
});

test("runs and resumes a registered pipeline from persisted configuration", async (t) => {
  const fixture = await createFixture(t);
  const adapter = createAdapter({ questionFirst: true });
  const activities = [];
  const firstRunner = runnerFor(fixture, { codex: adapter }, { activities });

  const paused = await firstRunner.run({
    pipelineId: "plan-authoring",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    proactiveClarification: false,
    roleOverrides: { planner: { model: "planner-model" } },
    sourceSession: { backend: "codex", id: SOURCE_SESSION },
  });

  assert.equal(paused.run.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(
    paused.run.pipelineState.pendingEdit.transcriptPath,
    join(fixture.taskPath, "clarifications.md"),
  );
  assert.equal(paused.run.pause.reason, "clarification_answers_required");
  assert.equal(paused.run.sessionLineage.source, SOURCE_SESSION);
  assert.equal(paused.run.sessionLineage.sourceProfile, null);
  assert.deepEqual(paused.run.roles.planner, {
    backend: "codex",
    profile: "current",
    model: "planner-model",
    contextSize: "current",
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
  const secondRunner = runnerFor(
    fixture,
    { codex: adapter },
    {
      activities,
      configuration: { schemaVersion: 1, defaultBackend: "claude" },
    },
  );
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
      { role: "planner", sessionId: POST_CLARIFICATION_PLANNER_SESSION },
      { role: "planner", sessionId: PLANNING_SESSION },
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

test("prepares a durable run and submits identified input before continuation", async (t) => {
  const fixture = await createFixture(t);
  const adapter = createAdapter({ questionFirst: true });
  const runner = runnerFor(fixture, { codex: adapter });
  const input = {
    pipelineId: "plan-authoring",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  };

  const prepared = await runner.create(input, { runId: PREPARED_RUN });
  assert.equal(prepared.run.runId, PREPARED_RUN);
  assert.equal(prepared.run.pipelineState.workflowState, "CLARIFY");
  assert.equal(
    (await runner.status(PREPARED_RUN)).run.pipelineState.workflowState,
    "CLARIFY",
  );
  assert.equal(adapter.calls.length, 0);

  const paused = await runner.resume({ runId: PREPARED_RUN, action: null });
  assert.equal(paused.run.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.deepEqual(paused.run.pause.inputRequest.questions, [
    {
      id: "q1",
      question: "Which behavior is required?",
      options: [],
      rationale: "The answer changes the commit plan.",
    },
  ]);
  const response = {
    runId: PREPARED_RUN,
    requestId: paused.run.pause.inputRequest.id,
    expectedRevision: paused.run.revision,
    answers: [{ questionId: "q1", answer: "Use behavior A exactly." }],
  };
  const preview = await runner.previewInput(response);
  const submitted = await runner.submitInput({
    ...response,
    responseHash: preview.responseHash,
  });
  assert.equal(
    submitted.run.pause.inputResponse.transcriptHash,
    preview.responseHash,
  );

  const completed = await runner.resume({ runId: PREPARED_RUN, action: null });
  assert.equal(completed.run.pipelineState.workflowState, "DONE");
  assert.match(
    await readFile(join(fixture.taskPath, "clarifications.md"), "utf8"),
    /### A1\n\nUse behavior A exactly\./u,
  );
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
      roleOverrides: {
        planner: { backend: "codex" },
        reviewer: { backend: "codex" },
      },
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

test("persists a trusted source profile and applies resolved turn preferences", async (t) => {
  const fixture = await createFixture(t);
  const adapter = createAdapter();
  const profileDirectory = join(fixture.workspace, "claude-profile");
  const runner = runnerFor(
    fixture,
    { claude: adapter },
    {
      configuration: {
        schemaVersion: 1,
        profiles: {
          "claude-personal": {
            backend: "claude",
            configDirectory: profileDirectory,
          },
        },
        pipelines: {
          "plan-authoring": {
            roles: { arbiter: { profile: "claude-personal" } },
          },
        },
      },
    },
  );

  const result = await runner.run({
    pipelineId: "plan-authoring",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    roleOverrides: {},
    executionOverrides: { model: "sonnet", contextSize: "200000" },
    sourceSession: {
      backend: "claude",
      id: SOURCE_SESSION,
      profile: "claude-personal",
    },
  });

  assert.equal(result.run.pipelineState.workflowState, "DONE");
  assert.equal(result.run.sessionLineage.sourceProfile, "claude-personal");
  assert.deepEqual(result.run.roles.planner, {
    backend: "claude",
    profile: profileDirectory,
    model: "sonnet",
    contextSize: "200000",
  });
  assert.deepEqual(adapter.probes, [
    {
      profile: profileDirectory,
      model: "sonnet",
      contextSize: "200000",
    },
  ]);
  assert.ok(
    adapter.calls.every(
      ({ profile, model, contextSize }) =>
        profile === profileDirectory &&
        model === "sonnet" &&
        contextSize === "200000",
    ),
  );
  assert.deepEqual(adapter.calls[0].session, {
    mode: "fork",
    id: SOURCE_SESSION,
  });
});

test("does not require an unused Arbiter backend", async (t) => {
  const fixture = await createFixture(t);
  const adapter = createAdapter();
  const runner = runnerFor(
    fixture,
    { codex: adapter },
    {
      configuration: {
        ...RUNNER_CONFIGURATION,
        pipelines: {
          "plan-authoring": {
            roles: { arbiter: { backend: "claude" } },
          },
        },
      },
    },
  );

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
    profile: "current",
    model: "current",
    contextSize: "current",
  });
});

test("persists project overrides and ignores later configuration changes", async (t) => {
  const fixture = await createFixture(t);
  const adapter = createAdapter({ questionFirst: true });
  const projectConfigurationDirectory = join(
    fixture.projectPath,
    "LOCAL_ARTIFACTS",
  );
  const projectConfigurationPath = join(
    projectConfigurationDirectory,
    "agent-runner.json",
  );
  await Promise.all([
    mkdir(projectConfigurationDirectory),
    writeFile(join(fixture.projectPath, ".gitignore"), "/LOCAL_ARTIFACTS/\n"),
  ]);
  await writeFile(
    projectConfigurationPath,
    JSON.stringify({
      schemaVersion: 1,
      artifactRoot: "project-artifacts",
      defaultProfile: "codex-work",
      defaultModel: "project-model",
      pipelines: {
        "plan-authoring": {
          maxRevisionRounds: 4,
          roles: { reviewer: { contextSize: "200000" } },
        },
      },
    }),
  );
  const configuration = {
    schemaVersion: 1,
    defaultBackend: "claude",
    defaultModel: "runner-model",
    profiles: {
      "codex-work": { backend: "codex", profile: "native-work" },
    },
    pipelines: {
      "plan-authoring": {
        maxRevisionRounds: 9,
        roles: { reviewer: { model: "runner-reviewer" } },
      },
    },
  };
  const runner = runnerFor(
    fixture,
    { codex: adapter },
    { configuration },
  );

  const paused = await runner.run({
    pipelineId: "plan-authoring",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    proactiveClarification: false,
    roleOverrides: { planner: { model: "cli-planner" } },
    sourceSession: null,
  });

  assert.equal(paused.run.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.deepEqual(paused.run.pipelineState.settings, {
    maxRevisionRounds: 4,
    stagnationWindowRounds: 3,
  });
  assert.equal(
    paused.run.pipelineState.pendingEdit.transcriptPath,
    join(fixture.taskPath, "clarifications.md"),
  );
  assert.deepEqual(paused.run.roles.planner, {
    backend: "codex",
    profile: "native-work",
    model: "cli-planner",
    contextSize: "current",
  });
  assert.deepEqual(paused.run.roles.reviewer, {
    backend: "codex",
    profile: "native-work",
    model: "project-model",
    contextSize: "200000",
  });
  const preparedPolishing = await runner.create({
    pipelineId: "polishing",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  });
  assert.equal(
    preparedPolishing.run.pipelineState.artifactRoot,
    "project-artifacts",
  );

  await Promise.all([
    writeFile(projectConfigurationPath, '{"schemaVersion":2}\n'),
    writeFile(
      join(fixture.taskPath, "clarifications.md"),
      `${await readFile(join(fixture.taskPath, "clarifications.md"), "utf8")}\nUse behavior A.\n`,
    ),
  ]);
  const completed = await runner.resume({
    runId: paused.run.runId,
    action: null,
  });

  assert.equal(completed.run.pipelineState.workflowState, "DONE");
  assert.deepEqual(completed.run.roles, paused.run.roles);
  assert.deepEqual(
    completed.run.pipelineState.settings,
    paused.run.pipelineState.settings,
  );
});

test("never reads an Agent Runner configuration file in the target repository", async (t) => {
  const fixture = await createFixture(t);
  await writeFile(
    join(fixture.projectPath, ".agent-runner.json"),
    '{"schemaVersion":99}\n',
  );
  const roleOverrides = {
    planner: { backend: "codex", model: "planner-model" },
    reviewer: { backend: "codex", model: "reviewer-model" },
    arbiter: { backend: "codex", model: "arbiter-model" },
  };
  const runner = createRunner({
    adapters: { codex: createAdapter() },
    clarifications: createClarificationService({ interactive: false }),
    git: createGitService(),
    runStore: createRunStore({ stateRoot: fixture.stateRoot }),
  });

  const result = await runner.run({
    pipelineId: "plan-authoring",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    roleOverrides,
    sourceSession: null,
  });

  assert.equal(result.run.pipelineState.workflowState, "DONE");
  assert.deepEqual(result.run.roles, {
    planner: {
      ...roleOverrides.planner,
      profile: "current",
      contextSize: "current",
    },
    reviewer: {
      ...roleOverrides.reviewer,
      profile: "current",
      contextSize: "current",
    },
    arbiter: {
      ...roleOverrides.arbiter,
      profile: "current",
      contextSize: "current",
    },
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
    loadConfiguration: configurationLoader(),
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
    writeFile(join(fixture.projectPath, ".gitignore"), "/LOCAL_ARTIFACTS/\n"),
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
  const adapter = createExecutionAdapter({ bootstrapDisagreement: true });
  const arbiter = createArbiterAdapter();
  const activities = [];
  const runner = runnerFor(
    fixture,
    { codex: adapter, claude: arbiter },
    {
      activities,
      configuration: {
        ...RUNNER_CONFIGURATION,
        profiles: {
          "codex-work": { backend: "codex", profile: "work" },
        },
        pipelines: {
          "plan-execution": {
            roles: { arbiter: { backend: "claude" } },
          },
        },
      },
    },
  );

  const result = await runner.run({
    pipelineId: "plan-execution",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    roleOverrides: { arbiter: { profile: "current" } },
    executionOverrides: {
      profile: "codex-work",
      model: "execution-model",
      contextSize: "200000",
    },
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
  assert.deepEqual(
    adapter.probes,
    Array.from({ length: 3 }, () => ({
      profile: "work",
      model: "execution-model",
      contextSize: "200000",
    })),
  );
  assert.ok(
    activities.some(
      ({ actor, phase, kind }) =>
        actor === "worker" && phase === "commit" && kind === "created",
    ),
  );
});

for (const pauseReason of [
  "local_artifacts_not_ignored",
  "unsafe_git_state",
]) {
  test(`resumes polishing after ${pauseReason} preflight is corrected`, async (t) => {
    const fixture = await createFixture(t);
    const ignoreArtifacts = pauseReason === "unsafe_git_state";
    await Promise.all([
      writeFile(
        join(fixture.projectPath, ".gitignore"),
        ignoreArtifacts ? "/LOCAL_ARTIFACTS/\n" : "/ignored/\n",
      ),
      writeFile(join(fixture.projectPath, "source.js"), "export const value = 0;\n"),
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
      join(fixture.projectPath, "source.js"),
      "export const value = 1;\n",
    );

    const baseGit = createGitService();
    let preflightCalls = 0;
    const git =
      pauseReason === "unsafe_git_state"
        ? {
            ...baseGit,
            async preflight(options) {
              preflightCalls += 1;
              if (preflightCalls === 2) {
                const error = new Error(
                  "Git snapshot raced with another process.",
                );
                error.code = "ERR_GIT_SNAPSHOT_RACE";
                throw error;
              }
              return baseGit.preflight(options);
            },
          }
        : baseGit;
    const adapter = createExecutionAdapter();
    const runner = runnerFor(
      fixture,
      { codex: adapter },
      {
        git,
        configuration: {
          ...RUNNER_CONFIGURATION,
          profiles: {
            "codex-work": { backend: "codex", profile: "work" },
          },
        },
      },
    );

    const paused = await runner.run({
      pipelineId: "polishing",
      projectPath: fixture.projectPath,
      taskPath: fixture.taskPath,
      roleOverrides: {},
      executionOverrides: {
        profile: "codex-work",
        model: "polishing-model",
        contextSize: "200000",
      },
      sourceSession: null,
    });
    assert.equal(paused.run.pipelineState.workflowState, "WAITING_FOR_USER");
    assert.equal(paused.run.pipelineState.preflightComplete, false);
    assert.equal(paused.run.pause.reason, pauseReason);

    if (!ignoreArtifacts) {
      await writeFile(
        join(fixture.projectPath, ".gitignore"),
        "/ignored/\n/LOCAL_ARTIFACTS/\n",
      );
    }
    const completed = await runner.resume({
      runId: paused.run.runId,
      action: null,
    });

    assert.equal(completed.run.pipelineState.workflowState, "DONE");
    assert.equal(completed.run.pause, null);
    assert.deepEqual(
      adapter.probes,
      Array.from({ length: 3 }, () => ({
        profile: "work",
        model: "polishing-model",
        contextSize: "200000",
      })),
    );
  });
}
