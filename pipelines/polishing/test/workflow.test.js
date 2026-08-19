import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  appendFile,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

import { createClarificationService } from "../../../src/clarifications.js";
import { createGitService } from "../../../src/git.js";
import { createRunStore } from "../../../src/state.js";
import {
  createPolishingState,
  runPolishing,
} from "../src/index.js";

const executeFile = promisify(execFile);
const SOURCE_SESSION = "source-session";
const SETTINGS = Object.freeze({
  maxFixRounds: 5,
  maxDisputesPerFinding: 2,
  maxSameFindingRounds: 3,
  stagnationWindowRounds: 3,
});

function hash(value) {
  return createHash("sha256").update(value).digest("hex");
}

function emptyDecision() {
  return { question: "", options: [], whyBlocked: "", evidence: [] };
}

function clarificationReady() {
  return {
    status: "READY",
    questions: [],
    reason: "",
    ...emptyDecision(),
  };
}

function clarificationQuestions() {
  return {
    status: "QUESTIONS",
    questions: [
      {
        question: "Which public behavior should the existing changes preserve?",
        whyItMatters: "The answer changes how the dirty implementation is polished.",
      },
    ],
    reason: "",
    ...emptyDecision(),
  };
}

function bootstrapReady(role) {
  return {
    status: "READY",
    summary: `${role} independently understands the dirty change set and finalization procedure.`,
    reason: "",
    ...emptyDecision(),
  };
}

function reconciliationResolved() {
  return {
    status: "RESOLVED",
    summary:
      "Polish the existing change set within the established repository boundaries.",
    disagreement: "",
    reason: "",
    ...emptyDecision(),
  };
}

function reconciliationDisagreement() {
  return {
    status: "DISAGREEMENT",
    summary: "",
    disagreement: "The roles selected different owning modules.",
    reason: "",
    question: "",
    options: [],
    whyBlocked: "",
    evidence: ["The summaries identify different existing boundaries."],
  };
}

function arbitrationResolved() {
  return {
    direction: "SYNTHESIZE",
    summary: "Use the existing narrow module boundary and preserve the public behavior.",
    rationale: "Repository ownership and tests support the combined interpretation.",
    reason: "",
    ...emptyDecision(),
  };
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

async function runGit(repositoryPath, ...argumentsList) {
  return executeFile("git", ["-C", repositoryPath, ...argumentsList]);
}

async function optionalInput(path) {
  try {
    const content = await readFile(path, "utf8");
    return { path, content, hash: hash(content) };
  } catch (cause) {
    if (cause?.code === "ENOENT") {
      return null;
    }
    throw cause;
  }
}

async function createFixture(
  t,
  {
    dirty = true,
    ignoreArtifacts = true,
    interactive = false,
    onEdit,
    onRoleRun,
    proactiveClarification = false,
    reviewer = [bootstrapReady("Reviewer")],
    sourceSession = null,
    taskLocation = "external",
    worker = [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
    ],
    arbiter = [],
  } = {},
) {
  const workspace = await mkdtemp(join(tmpdir(), "agent-runner-polishing-"));
  const projectPath = join(workspace, "project");
  const externalTaskPath = join(workspace, "task");
  const stateRoot = join(workspace, "state");
  await mkdir(projectPath, { recursive: true });
  await runGit(projectPath, "init", "-q");
  await runGit(projectPath, "config", "user.name", "Polishing Test");
  await runGit(projectPath, "config", "user.email", "polishing@example.test");
  await writeFile(
    join(projectPath, ".gitignore"),
    `${ignoreArtifacts ? "LOCAL_ARTIFACTS/\n" : ""}ignored-task/\n`,
  );
  await writeFile(join(projectPath, "tracked.txt"), "base\n");
  await writeFile(join(projectPath, "deleted.txt"), "delete me\n");

  const taskPath =
    taskLocation === "external" || taskLocation === "symlinked-untracked"
      ? externalTaskPath
      : taskLocation === "ignored"
        ? join(projectPath, "ignored-task")
        : join(projectPath, "task");
  if (taskLocation === "symlinked-untracked") {
    const repositoryTaskPath = join(projectPath, "task");
    await mkdir(repositoryTaskPath, { recursive: true });
    await symlink(repositoryTaskPath, taskPath, "dir");
  } else {
    await mkdir(taskPath, { recursive: true });
  }
  await writeFile(join(taskPath, "task.md"), "# Polish fixture\n");
  if (taskLocation === "tracked" || taskLocation === "dirty-tracked") {
    await runGit(
      projectPath,
      "add",
      ".gitignore",
      "deleted.txt",
      "tracked.txt",
      "task/task.md",
    );
  } else {
    await runGit(
      projectPath,
      "add",
      ".gitignore",
      "deleted.txt",
      "tracked.txt",
    );
  }
  await runGit(projectPath, "commit", "-qm", "initialize fixture");
  if (taskLocation === "dirty-tracked") {
    await appendFile(join(taskPath, "task.md"), "Changed input.\n");
  }
  if (dirty) {
    await writeFile(join(projectPath, "change.txt"), "dirty change\n");
  }
  t.after(() => rm(workspace, { recursive: true, force: true }));

  const queues = {
    worker: [...worker],
    reviewer: [...reviewer],
    arbiter: [...arbiter],
  };
  const calls = { worker: [], reviewer: [], arbiter: [] };
  const probes = { worker: 0, reviewer: 0, arbiter: 0 };
  let sessionIndex = 0;
  const adapters = Object.fromEntries(
    Object.keys(queues).map((role) => [
      role,
      {
        async probe() {
          probes[role] += 1;
          return capabilities();
        },
        async run(request) {
          calls[role].push(request);
          await onRoleRun?.(role, request, calls[role].length, { projectPath });
          assert.ok(queues[role].length > 0, `Unexpected ${role} turn.`);
          const structured = queues[role].shift();
          sessionIndex += 1;
          return {
            output: "structured",
            structured,
            sessionId:
              request.session?.mode === "continue"
                ? request.session.id
                : `${role}-session-${sessionIndex}`,
          };
        },
      },
    ]),
  );

  const store = createRunStore({ stateRoot });
  let created = await store.createRun({
    pipelineId: "polishing",
    pipelineStateVersion: 1,
    projectPath,
    taskPath,
    roles: {
      worker: { backend: "codex", model: "worker-model" },
      reviewer: { backend: "codex", model: "reviewer-model" },
      arbiter: { backend: "codex", model: "arbiter-model" },
    },
    sourceSession,
    pipelineState: createPolishingState({
      proactiveClarification,
      settings: SETTINGS,
    }),
    activity: {
      actor: "runner",
      phase: "run",
      kind: "created",
      message: "Polishing test run created.",
    },
  });
  let lease = created.lease;
  let currentRun = created.state;
  t.after(() => lease?.release().catch(() => {}));

  const git = createGitService();
  const clarifications = createClarificationService({
    env: { EDITOR: "fixture-editor" },
    interactive,
    launchEditor: async (_command, transcriptPath) =>
      onEdit?.({ transcriptPath }),
  });
  const runtime = {
    adapters,
    clarifications,
    git,
    async readInputs({ taskPath: requestedTaskPath }) {
      const task = await optionalInput(join(requestedTaskPath, "task.md"));
      if (task === null) {
        const error = new Error("task.md is missing.");
        error.code = "ENOENT";
        error.path = join(requestedTaskPath, "task.md");
        throw error;
      }
      return {
        task,
        taskClarifications: await optionalInput(
          join(requestedTaskPath, "clarifications.md"),
        ),
        context: await optionalInput(join(requestedTaskPath, "context.md")),
      };
    },
    async transition(patch, options) {
      currentRun = await store.transitionRun(lease, patch, options);
      return currentRun;
    },
    async recordChildSession(child, options) {
      currentRun = await store.recordChildSession(lease, child, options);
      return currentRun;
    },
    writeRunArtifact({ path, content }) {
      return store.writeRunArtifact(lease, path, content);
    },
  };

  async function run() {
    currentRun = await runPolishing({
      action: null,
      run: currentRun,
      runtime,
      settings: SETTINGS,
    });
    return currentRun;
  }

  async function recover() {
    await lease.release();
    const reopened = createRunStore({ stateRoot });
    lease = await reopened.acquireRunLease(currentRun.runId);
    currentRun = await reopened.recoverRun(lease);
    runtime.transition = async (patch, options) => {
      currentRun = await reopened.transitionRun(lease, patch, options);
      return currentRun;
    };
    runtime.recordChildSession = async (child, options) => {
      currentRun = await reopened.recordChildSession(lease, child, options);
      return currentRun;
    };
    runtime.writeRunArtifact = ({ path, content }) =>
      reopened.writeRunArtifact(lease, path, content);
    return currentRun;
  }

  return {
    calls,
    get currentRun() {
      return currentRun;
    },
    directoryPath: created.directoryPath,
    probes,
    projectPath,
    recover,
    run,
    taskPath,
  };
}

test("prepares a dirty worktree through independent source-session bootstraps", async (t) => {
  const fixture = await createFixture(t, { sourceSession: SOURCE_SESSION });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "POLISH");
  assert.equal(result.pipelineState.clarificationFrozen, true);
  assert.equal(result.pipelineState.repositoryBaseline.clean, false);
  assert.deepEqual(result.pipelineState.backendVersions, {
    worker: "fake-1.0.0",
    reviewer: "fake-1.0.0",
    arbiter: null,
  });
  assert.deepEqual(
    result.sessionLineage.children.map(({ role }) => role),
    ["worker", "reviewer"],
  );
  assert.deepEqual(fixture.calls.worker[0].session, {
    mode: "fork",
    id: SOURCE_SESSION,
  });
  assert.deepEqual(fixture.calls.reviewer[0].session, {
    mode: "fork",
    id: SOURCE_SESSION,
  });
  assert.doesNotMatch(fixture.calls.reviewer[0].prompt, /Worker independently/u);
  assert.doesNotMatch(fixture.calls.worker[1].prompt, /Reviewer independently/u);
  assert.match(fixture.calls.worker[2].prompt, /Reviewer bootstrap summary/u);
  for (const call of [
    ...fixture.calls.worker,
    ...fixture.calls.reviewer,
  ]) {
    assert.equal(call.access, "read-only");
    assert.equal(call.schema.additionalProperties, false);
  }
  assert.match(
    await readFile(join(fixture.directoryPath, "context", "resolved.md"), "utf8"),
    /existing change set/u,
  );
});

test("accepts staged, unstaged, deleted, and untracked changes as one set", async (t) => {
  const fixture = await createFixture(t, { dirty: false });
  await writeFile(join(fixture.projectPath, "tracked.txt"), "staged change\n");
  await runGit(fixture.projectPath, "add", "tracked.txt");
  await rm(join(fixture.projectPath, "deleted.txt"));
  await writeFile(join(fixture.projectPath, "untracked.txt"), "untracked\n");

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "POLISH");
  assert.equal(result.pipelineState.repositoryBaseline.clean, false);
});

test("pauses clean repositories before creating a clarification artifact", async (t) => {
  const fixture = await createFixture(t, {
    dirty: false,
    reviewer: [],
    worker: [],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "no_changes");
  assert.equal(fixture.calls.worker.length, 0);
  assert.equal(fixture.calls.reviewer.length, 0);
  assert.equal(result.pipelineState.clarificationPath, null);
});

test("requires the repository-local clarification path to be ignored", async (t) => {
  const fixture = await createFixture(t, {
    ignoreArtifacts: false,
    reviewer: [],
    worker: [],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "local_artifacts_not_ignored");
  assert.equal(result.pipelineState.clarificationPath, null);
});

for (const taskLocation of [
  "dirty-tracked",
  "untracked",
  "symlinked-untracked",
]) {
  test(`rejects ${taskLocation} repository-local task input overlap`, async (t) => {
    const fixture = await createFixture(t, {
      taskLocation,
      reviewer: [],
      worker: [],
    });

    const result = await fixture.run();

    assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
    assert.equal(result.pause.reason, "task_input_overlaps_changes");
    assert.match(result.pause.path, /task\.md$/u);
    assert.equal(fixture.calls.worker.length, 0);
  });
}

test("rejects a tracked task input with an index-only change", async (t) => {
  const fixture = await createFixture(t, {
    taskLocation: "tracked",
    reviewer: [],
    worker: [],
  });
  const taskFile = join(fixture.taskPath, "task.md");
  await appendFile(taskFile, "Staged input change.\n");
  await runGit(fixture.projectPath, "add", "task/task.md");
  await writeFile(taskFile, "# Polish fixture\n");

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "task_input_overlaps_changes");
  assert.match(result.pause.path, /task\.md$/u);
  assert.equal(fixture.calls.worker.length, 0);
});

for (const [name, flag] of [
  ["assume-unchanged", "--assume-unchanged"],
  ["skip-worktree", "--skip-worktree"],
]) {
  test(`rejects tracked task input hidden by ${name}`, async (t) => {
    const fixture = await createFixture(t, {
      dirty: false,
      taskLocation: "tracked",
      reviewer: [],
      worker: [],
    });
    await runGit(fixture.projectPath, "update-index", flag, "task/task.md");
    await appendFile(join(fixture.taskPath, "task.md"), "Hidden change.\n");

    const result = await fixture.run();

    assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
    assert.equal(result.pause.reason, "task_input_overlaps_changes");
    assert.match(result.pause.path, /task\.md$/u);
    assert.equal(fixture.calls.worker.length, 0);
  });

  test(`accepts a hidden-only ${name} worktree change`, async (t) => {
    const fixture = await createFixture(t, { dirty: false });
    await runGit(fixture.projectPath, "update-index", flag, "tracked.txt");
    await writeFile(join(fixture.projectPath, "tracked.txt"), "hidden change\n");

    const result = await fixture.run();

    assert.equal(result.pipelineState.workflowState, "POLISH");
    assert.equal(result.pipelineState.repositoryBaseline.clean, false);
  });
}

for (const taskLocation of ["ignored", "tracked"]) {
  test(`accepts ${taskLocation} repository-local immutable task input`, async (t) => {
    const fixture = await createFixture(t, { taskLocation });

    const result = await fixture.run();

    assert.equal(result.pipelineState.workflowState, "POLISH");
  });
}

test("pauses for clarification answers and resumes without consuming an extra round", async (t) => {
  const fixture = await createFixture(t, {
    worker: [
      clarificationQuestions(),
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
    ],
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "clarification_answers_required");
  assert.equal(paused.counters.clarificationRounds, 1);
  await appendFile(
    paused.pipelineState.clarificationPath,
    "Use the existing public behavior.\n",
  );

  await fixture.recover();
  const resumed = await fixture.run();

  assert.equal(resumed.pipelineState.workflowState, "POLISH");
  assert.equal(resumed.counters.clarificationRounds, 1);
  assert.equal(resumed.pipelineState.pendingEdit, null);
});

test("accepts an unchanged proactive clarification without consuming a round", async (t) => {
  const fixture = await createFixture(t, {
    interactive: true,
    onEdit: async () => {},
    proactiveClarification: true,
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "POLISH");
  assert.equal(result.pipelineState.proactiveClarificationComplete, true);
  assert.equal(result.counters.clarificationRounds, 0);
});

test("stops after the bounded clarification question rounds", async (t) => {
  const fixture = await createFixture(t, {
    worker: [
      clarificationQuestions(),
      clarificationQuestions(),
      clarificationQuestions(),
      clarificationQuestions(),
    ],
    reviewer: [],
  });

  for (let round = 1; round <= 3; round += 1) {
    const paused = await fixture.run();
    assert.equal(paused.pause.reason, "clarification_answers_required");
    assert.equal(paused.counters.clarificationRounds, round);
    await appendFile(paused.pipelineState.clarificationPath, `Answer ${round}.\n`);
  }

  const exhausted = await fixture.run();
  assert.equal(exhausted.pause.reason, "clarification_limit_reached");
  assert.equal(exhausted.counters.clarificationRounds, 3);
});

test("detects immutable task-input drift during a read-only turn", async (t) => {
  let changed = false;
  const fixture = await createFixture(t, {
    async onRoleRun(role) {
      if (role === "worker" && !changed) {
        changed = true;
        await appendFile(join(fixture.taskPath, "task.md"), "Unexpected drift.\n");
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "task_input_changed");
});

test("detects unauthorized clarification drift during a read-only turn", async (t) => {
  let changed = false;
  const fixture = await createFixture(t, {
    async onRoleRun(role) {
      if (role === "worker" && !changed) {
        changed = true;
        await appendFile(
          fixture.currentRun.pipelineState.clarificationPath,
          "Unexpected clarification drift.\n",
        );
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "clarifications_changed");
});

test("arbitrates a material bootstrap disagreement in a fresh read-only context", async (t) => {
  const fixture = await createFixture(t, {
    arbiter: [arbitrationResolved()],
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationDisagreement(),
    ],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "POLISH");
  assert.equal(result.pipelineState.bootstrapArbitrationUsed, true);
  assert.equal(fixture.calls.arbiter.length, 1);
  assert.equal(fixture.calls.arbiter[0].access, "read-only");
  assert.equal(fixture.calls.arbiter[0].session, undefined);
});

for (const [name, mutate] of [
  [
    "content",
    async ({ projectPath }) =>
      writeFile(join(projectPath, "mutated.txt"), "mutated\n"),
  ],
  ["refs", async ({ projectPath }) => runGit(projectPath, "tag", "unexpected")],
  [
    "remotes",
    async ({ projectPath }) =>
      runGit(
        projectPath,
        "remote",
        "add",
        "origin",
        "https://example.invalid/repository.git",
      ),
  ],
  [
    "identity",
    async ({ projectPath }) =>
      runGit(projectPath, "config", "user.name", "Changed Identity"),
  ],
]) {
  test(`detects read-only ${name} mutation`, async (t) => {
    let mutated = false;
    const fixture = await createFixture(t, {
      async onRoleRun(role, _request, _turn, paths) {
        if (role === "worker" && !mutated) {
          mutated = true;
          await mutate(paths);
        }
      },
    });

    const result = await fixture.run();

    assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
    assert.equal(result.pause.reason, "read_only_agent_mutated_repository");
  });
}

test("persists complete transitions and resumes after recoverable interruption", async (t) => {
  let interrupted = false;
  const fixture = await createFixture(t, {
    async onRoleRun(role) {
      if (role === "worker" && !interrupted) {
        interrupted = true;
        const error = new Error("Temporary interruption.");
        error.code = "ERR_FAKE_INTERRUPTED";
        error.recoverable = true;
        throw error;
      }
    },
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pause.resumeState, "CLARIFY");
  const eventCount = (
    await readFile(join(fixture.directoryPath, "events.jsonl"), "utf8")
  )
    .trimEnd()
    .split("\n").length;
  assert.ok(eventCount > 1);

  const recovered = await fixture.recover();
  assert.equal(recovered.revision, paused.revision);
  const resumed = await fixture.run();

  assert.equal(resumed.pipelineState.workflowState, "POLISH");
  assert.ok(resumed.revision > recovered.revision);
});
