import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

import {
  createPlanExecutionState,
  runPlanExecution,
} from "../src/index.js";

const executeFile = promisify(execFile);
const SOURCE_SESSION = "11111111-1111-4111-8111-111111111111";
const ROLE_SESSIONS = Object.freeze({
  worker: "22222222-2222-4222-8222-222222222222",
  reviewer: "33333333-3333-4333-8333-333333333333",
  arbiter: "44444444-4444-4444-8444-444444444444",
});
const RESTARTED_ROLE_SESSIONS = Object.freeze({
  worker: "55555555-5555-4555-8555-555555555555",
  reviewer: "66666666-6666-4666-8666-666666666666",
});
const PLAN = `## Commit 1: feat(test): add behavior

Implement the requested behavior.`;
const SETTINGS = Object.freeze({
  maxFixRoundsPerStep: 5,
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
        question: "Which externally visible behavior is required?",
        whyItMatters: "The answer changes implementation of the plan.",
      },
    ],
    reason: "",
    ...emptyDecision(),
  };
}

function clarificationPlanRevision() {
  return {
    status: "PLAN_REVISION_REQUIRED",
    questions: [],
    reason: "The requested behavior conflicts with the validated plan.",
    question: "",
    options: [],
    whyBlocked: "",
    evidence: ["The plan excludes the required public behavior."],
  };
}

function bootstrapReady(role) {
  return {
    status: "READY",
    summary: `${role} understands the task, architecture, plan, risks, and finalization procedure.`,
    reason: "",
    ...emptyDecision(),
  };
}

function bootstrapProductDecision() {
  return {
    status: "PRODUCT_DECISION_REQUIRED",
    summary: "",
    reason: "",
    question: "Which public behavior should be implemented?",
    options: ["Behavior A", "Behavior B"],
    whyBlocked: "Both behaviors are valid but incompatible.",
    evidence: ["The task and plan do not choose a behavior."],
  };
}

function compatibilityReady() {
  return { status: "READY", reason: "", evidence: [] };
}

function compatibilityPlanRevision() {
  return {
    status: "PLAN_REVISION_REQUIRED",
    reason: "The product decision changes a planned commit boundary.",
    evidence: ["The selected behavior requires another commit."],
  };
}

function reconciliationResolved() {
  return {
    status: "RESOLVED",
    summary: "The roles agree on the minimal implementation and finalization procedure.",
    disagreement: "",
    reason: "",
    ...emptyDecision(),
  };
}

function reconciliationDisagreement() {
  return {
    status: "DISAGREEMENT",
    summary: "",
    disagreement: "The roles disagree about the required repository boundary.",
    reason: "",
    question: "",
    options: [],
    whyBlocked: "",
    evidence: ["Worker and Reviewer identify different owning modules."],
  };
}

function reconciliationProductDecision() {
  return {
    status: "PRODUCT_DECISION_REQUIRED",
    summary: "",
    disagreement: "",
    reason: "",
    question: "Which public behavior should be implemented?",
    options: ["Behavior A", "Behavior B"],
    whyBlocked: "Both behaviors are valid but incompatible.",
    evidence: ["The independent summaries expose an unresolved requirement."],
  };
}

function arbitrationResolved() {
  return {
    direction: "SYNTHESIZE",
    summary: "Use the existing repository boundary and keep the change local.",
    rationale: "Repository ownership evidence supports the existing boundary.",
    reason: "",
    ...emptyDecision(),
  };
}

function arbitrationProductDecision() {
  return {
    direction: "PRODUCT_DECISION_REQUIRED",
    summary: "",
    rationale: "The repository evidence cannot select a product behavior.",
    reason: "",
    question: "Which public behavior should be implemented?",
    options: ["Behavior A", "Behavior B"],
    whyBlocked: "Both behaviors are valid but incompatible.",
    evidence: ["The task and plan do not choose a behavior."],
  };
}

function assertStrictSchema(schema) {
  if (schema === null || typeof schema !== "object") {
    return;
  }
  if (!Array.isArray(schema) && schema.type === "object") {
    assert.equal(schema.additionalProperties, false);
    assert.deepEqual(
      new Set(schema.required),
      new Set(Object.keys(schema.properties)),
    );
  }
  for (const child of Object.values(schema)) {
    assertStrictSchema(child);
  }
}

async function repositoryFingerprint(root) {
  const entries = [];

  async function visit(directory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      if (entry.name === ".git") {
        continue;
      }
      const path = join(directory, entry.name);
      const pathFromRoot = relative(root, path);
      if (
        pathFromRoot === "LOCAL_ARTIFACTS" ||
        pathFromRoot.startsWith("LOCAL_ARTIFACTS/")
      ) {
        continue;
      }
      if (entry.isDirectory()) {
        await visit(path);
      } else {
        entries.push([pathFromRoot, hash(await readFile(path))]);
      }
    }
  }

  await visit(root);
  entries.sort(([left], [right]) => left.localeCompare(right));
  return hash(JSON.stringify(entries));
}

function createClarificationService({ interactive = false, onEdit } = {}) {
  let authorizationIndex = 0;

  async function inspectTranscript({ artifactRoot, transcriptPath }) {
    const content = await readFile(transcriptPath, "utf8");
    return Object.freeze({
      artifactRoot,
      transcriptPath,
      content,
      hash: hash(content),
    });
  }

  function assertExpectedHash(snapshot, expectedHash) {
    if (snapshot.hash !== expectedHash) {
      const error = new Error("Clarifications changed.");
      error.code = "ERR_CLARIFICATIONS_CHANGED";
      throw error;
    }
  }

  async function ensureTranscript(options) {
    await mkdir(dirname(options.transcriptPath), { recursive: true });
    await writeFile(options.transcriptPath, "", { flag: "a" });
    return inspectTranscript(options);
  }

  async function append(options, section) {
    const snapshot = await inspectTranscript(options);
    assertExpectedHash(snapshot, options.expectedHash);
    const separator = snapshot.content.length === 0 ? "" : "\n\n";
    await writeFile(
      options.transcriptPath,
      `${snapshot.content}${separator}${section}\n`,
    );
    return inspectTranscript(options);
  }

  async function appendQuestionRound(options) {
    return append(
      options,
      `## Round ${options.round}\n\n${options.questions[0].question}\n\n<!-- answer -->`,
    );
  }

  async function appendProductDecision(options) {
    return append(
      options,
      `## Product Decision ${options.number}\n\n${options.question}\n\n<!-- decision -->`,
    );
  }

  async function prepareEdit(options) {
    const snapshot = await inspectTranscript(options);
    assertExpectedHash(snapshot, options.expectedHash);
    const authorization = Object.freeze({
      schemaVersion: 1,
      id: `edit-${++authorizationIndex}`,
      artifactRoot: options.artifactRoot,
      transcriptPath: options.transcriptPath,
      suspendedState: options.suspendedState,
      action: options.action,
      preEditorHash: snapshot.hash,
    });
    await options.persistPendingEdit(authorization);
    return authorization;
  }

  async function acceptEdit(authorization, { consumePendingEdit }) {
    const snapshot = await inspectTranscript(authorization);
    const result = Object.freeze({
      authorizationId: authorization.id,
      suspendedState: authorization.suspendedState,
      action: authorization.action,
      transcriptPath: authorization.transcriptPath,
      preEditorHash: authorization.preEditorHash,
      hash: snapshot.hash,
      changed: snapshot.hash !== authorization.preEditorHash,
    });
    await consumePendingEdit(result);
    return result;
  }

  async function openEditor(authorization, options) {
    if (!interactive) {
      return Object.freeze({ status: "WAITING_FOR_USER", authorization });
    }
    await onEdit?.(authorization);
    return Object.freeze({
      status: "COMPLETED",
      result: await acceptEdit(authorization, options),
    });
  }

  return Object.freeze({
    acceptEdit,
    appendProductDecision,
    appendQuestionRound,
    ensureTranscript,
    freezeTranscript: async (options) => {
      const snapshot = await inspectTranscript(options);
      assertExpectedHash(snapshot, options.expectedHash);
      return snapshot;
    },
    inspectTranscript,
    openEditor,
    prepareEdit,
  });
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
    arbiter = [],
    capabilities = {},
    clarificationIgnored = true,
    dirty = false,
    interactive = false,
    models = {},
    onEdit,
    onRoleRun,
    onTransition,
    plan = PLAN,
    proactiveClarification = false,
    reviewer = [bootstrapReady("Reviewer")],
    sessionIds = ROLE_SESSIONS,
    sourceSession = null,
    worker = [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
    ],
  } = {},
) {
  const projectPath = await mkdtemp(join(tmpdir(), "agent-runner-execution-"));
  const statePath = await mkdtemp(join(tmpdir(), "agent-runner-state-"));
  const taskPath = join(projectPath, "task");
  const runId = "run-1";
  const clarificationPath = join(
    projectPath,
    "LOCAL_ARTIFACTS",
    "agent-runner",
    runId,
    "clarifications.md",
  );
  await executeFile("git", ["init", "-q", projectPath]);
  await executeFile("git", ["-C", projectPath, "config", "user.name", "Test"]);
  await executeFile("git", ["-C", projectPath, "config", "user.email", "test@example.com"]);
  await mkdir(taskPath);
  await writeFile(join(taskPath, "task.md"), "Implement the requested behavior.\n");
  await writeFile(join(taskPath, "plan.md"), plan);
  await writeFile(
    join(projectPath, ".gitignore"),
    `/.agent-runner.json\n${clarificationIgnored ? "/LOCAL_ARTIFACTS/\n" : ""}`,
  );
  await writeFile(join(projectPath, "source.js"), "export const value = 1;\n");
  await executeFile("git", ["-C", projectPath, "add", "."]);
  await executeFile("git", ["-C", projectPath, "commit", "-qm", "test: fixture"]);
  if (dirty) {
    await writeFile(join(projectPath, "dirty.txt"), "dirty\n");
  }
  t.after(() => rm(projectPath, { recursive: true, force: true }));
  t.after(() => rm(statePath, { recursive: true, force: true }));

  const queues = {
    worker: [...worker],
    reviewer: [...reviewer],
    arbiter: [...arbiter],
  };
  const calls = { worker: [], reviewer: [], arbiter: [] };
  const probeCalls = { worker: 0, reviewer: 0, arbiter: 0 };
  const freshSessionIndexes = { worker: 0, reviewer: 0, arbiter: 0 };

  function nextFreshSessionId(role) {
    const configured = sessionIds[role];
    if (!Array.isArray(configured)) {
      return configured;
    }
    const sessionId = configured[freshSessionIndexes[role]++];
    assert.notEqual(sessionId, undefined, `Missing fresh ${role} session ID.`);
    return sessionId;
  }

  const defaultCapabilities = {
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
  const adapters = Object.fromEntries(
    Object.keys(queues).map((role) => [
      role,
      {
        async probe() {
          probeCalls[role] += 1;
          return { ...defaultCapabilities, ...capabilities[role] };
        },
        async run(request) {
          calls[role].push(request);
          await onRoleRun?.(role, request, calls[role].length);
          assert.ok(queues[role].length > 0, `Unexpected ${role} turn.`);
          return {
            output: "structured",
            structured: queues[role].shift(),
            sessionId:
              request.session?.mode === "continue"
                ? request.session.id
                : nextFreshSessionId(role),
          };
        },
      },
    ]),
  );

  async function gitSnapshot({ allowedPaths = [] } = {}) {
    return {
      schemaVersion: 1,
      projectPath,
      allowedPaths: allowedPaths.map((path) => relative(projectPath, path)).sort(),
      fingerprint: await repositoryFingerprint(projectPath),
    };
  }

  let currentRun = {
    revision: 1,
    runId,
    pipelineId: "plan-execution",
    pipelineStateVersion: 1,
    projectPath,
    taskPath,
    roles: {
      worker: { backend: "codex", model: models.worker ?? null },
      reviewer: { backend: "codex", model: models.reviewer ?? null },
      arbiter: { backend: "codex", model: models.arbiter ?? null },
    },
    counters: {},
    hashes: {},
    pause: null,
    sessionLineage: { source: sourceSession, children: [] },
    pipelineState: createPlanExecutionState({ proactiveClarification }),
  };
  const preflights = [];
  const transitions = [];
  const artifacts = new Map();
  const runtime = {
    adapters,
    clarifications: createClarificationService({ interactive, onEdit }),
    git: {
      async preflight(options) {
        preflights.push(options);
        if (options.requireClean) {
          const { stdout } = await executeFile("git", [
            "-C",
            projectPath,
            "status",
            "--porcelain",
            "--untracked-files=all",
          ]);
          if (stdout.trim().length > 0) {
            const error = new Error("Repository is not clean.");
            error.code = "ERR_REPOSITORY_NOT_CLEAN";
            throw error;
          }
        }
        for (const path of options.requiredIgnoredPaths) {
          try {
            await executeFile("git", [
              "-C",
              projectPath,
              "check-ignore",
              "-q",
              "--",
              path,
            ]);
          } catch (cause) {
            const error = new Error("Artifact is not ignored.");
            error.code = "ERR_REPOSITORY_ARTIFACT_NOT_IGNORED";
            error.cause = cause;
            throw error;
          }
        }
        return { snapshot: await gitSnapshot(options) };
      },
      snapshot: gitSnapshot,
      async assertUnchanged(snapshot) {
        if (snapshot.fingerprint !== (await repositoryFingerprint(projectPath))) {
          const error = new Error("Read-only repository changed.");
          error.code = "ERR_READ_ONLY_REPOSITORY_CHANGED";
          throw error;
        }
      },
    },
    async readInputs() {
      const task = await optionalInput(join(taskPath, "task.md"));
      const planInput = await optionalInput(join(taskPath, "plan.md"));
      if (task === null || planInput === null) {
        const error = new Error("Required task input is missing.");
        error.code = "ENOENT";
        error.path = task === null ? join(taskPath, "task.md") : join(taskPath, "plan.md");
        throw error;
      }
      return {
        task,
        plan: planInput,
        taskClarifications: await optionalInput(join(taskPath, "clarifications.md")),
        context: await optionalInput(join(taskPath, "context.md")),
      };
    },
    async transition(patch, options) {
      currentRun = { ...currentRun, ...patch, revision: currentRun.revision + 1 };
      transitions.push({ patch, options });
      await onTransition?.(currentRun, patch, options);
      return currentRun;
    },
    async recordChildSession(child, options) {
      currentRun = {
        ...currentRun,
        revision: currentRun.revision + 1,
        sessionLineage: {
          ...currentRun.sessionLineage,
          children: [...currentRun.sessionLineage.children, child],
        },
      };
      transitions.push({ child, options });
      return currentRun;
    },
    async writeRunArtifact({ path, content }) {
      const artifactPath = join(statePath, path);
      await mkdir(dirname(artifactPath), { recursive: true });
      await writeFile(artifactPath, content);
      artifacts.set(path, content);
      return artifactPath;
    },
  };

  async function run(settings = {}) {
    currentRun = await runPlanExecution({
      run: currentRun,
      runtime,
      settings: { ...SETTINGS, ...settings },
    });
    return currentRun;
  }

  return {
    artifacts,
    calls,
    clarificationPath,
    get currentRun() {
      return currentRun;
    },
    preflights,
    probeCalls,
    projectPath,
    run,
    taskPath,
    transitions,
  };
}

test("clarifies and bootstraps through independent source-session forks", async (t) => {
  const fixture = await createFixture(t, {
    models: {
      worker: "worker-model",
      reviewer: "reviewer-model",
      arbiter: "arbiter-model",
    },
    sourceSession: SOURCE_SESSION,
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "IMPLEMENT");
  assert.equal(result.pipelineState.currentStep, 1);
  assert.equal(result.pipelineState.canonicalPlan, PLAN);
  assert.equal(result.pipelineState.clarificationPath, fixture.clarificationPath);
  assert.equal(result.pipelineState.clarificationFrozen, true);
  assert.deepEqual(result.pipelineState.backendVersions, {
    worker: "fake-1.0.0",
    reviewer: "fake-1.0.0",
    arbiter: null,
  });
  assert.equal(fixture.preflights.length, 2);
  assert.deepEqual(fixture.preflights[1].requiredIgnoredPaths, [
    fixture.clarificationPath,
  ]);
  assert.equal(fixture.preflights[1].requireClean, true);
  assert.equal(fixture.preflights[1].requireIdentity, true);
  assert.deepEqual(
    result.sessionLineage.children.map(({ role }) => role),
    ["worker", "reviewer"],
  );
  assert.deepEqual(fixture.calls.worker[0].session, {
    mode: "fork",
    id: SOURCE_SESSION,
  });
  assert.deepEqual(fixture.calls.worker[1].session, {
    mode: "continue",
    id: ROLE_SESSIONS.worker,
  });
  assert.deepEqual(fixture.calls.reviewer[0].session, {
    mode: "fork",
    id: SOURCE_SESSION,
  });
  assert.doesNotMatch(fixture.calls.reviewer[0].prompt, /Worker understands/u);
  assert.doesNotMatch(fixture.calls.worker[1].prompt, /Reviewer understands/u);
  assert.match(
    fixture.calls.reviewer[0].prompt,
    /As Reviewer, also state what you intend to verify\./u,
  );
  assert.doesNotMatch(
    fixture.calls.worker[1].prompt,
    /As Reviewer, also state what you intend to verify\./u,
  );
  assert.match(fixture.calls.worker[2].prompt, /Worker bootstrap summary/u);
  assert.match(fixture.calls.worker[2].prompt, /Reviewer bootstrap summary/u);
  assert.equal(fixture.calls.worker[0].model, "worker-model");
  assert.equal(fixture.calls.reviewer[0].model, "reviewer-model");
  for (const call of [...fixture.calls.worker, ...fixture.calls.reviewer]) {
    assert.equal(call.access, "read-only");
    assertStrictSchema(call.schema);
  }
  assert.match(fixture.artifacts.get("context/worker.md"), /Worker understands/u);
  assert.match(fixture.artifacts.get("context/reviewer.md"), /Reviewer understands/u);
  assert.match(fixture.artifacts.get("context/resolved.md"), /roles agree/u);
});

test("accepts an unchanged proactive clarification and uses fresh role sessions", async (t) => {
  const fixture = await createFixture(t, {
    interactive: true,
    proactiveClarification: true,
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "IMPLEMENT");
  assert.equal(result.pipelineState.proactiveClarificationComplete, true);
  assert.equal(await readFile(fixture.clarificationPath, "utf8"), "");
  assert.equal(fixture.calls.worker[0].session, undefined);
  assert.deepEqual(fixture.calls.worker[1].session, {
    mode: "continue",
    id: ROLE_SESSIONS.worker,
  });
  assert.equal(fixture.calls.reviewer[0].session, undefined);
  assert.equal(result.counters.clarificationRounds, 0);
});

test("pauses for clarification answers and resumes through the authorization", async (t) => {
  const fixture = await createFixture(t, {
    worker: [
      clarificationQuestions(),
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
    ],
  });

  const paused = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "clarification_answers_required");
  assert.equal(paused.counters.clarificationRounds, 1);
  await writeFile(
    fixture.clarificationPath,
    `${await readFile(fixture.clarificationPath, "utf8")}Use behavior A.\n`,
  );

  const resumed = await fixture.run();

  assert.equal(resumed.pipelineState.workflowState, "IMPLEMENT");
  assert.equal(resumed.pipelineState.pendingEdit, null);
  assert.equal(resumed.pipelineState.clarificationFrozen, true);
});

test("pauses before bootstrap when clarification requires a revised plan", async (t) => {
  const fixture = await createFixture(t, {
    reviewer: [],
    worker: [clarificationPlanRevision()],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "plan_revision_required");
  assert.match(result.pause.explanation, /conflicts with the validated plan/u);
  assert.equal(result.pipelineState.workerSummary, null);
  assert.equal(fixture.calls.reviewer.length, 0);
});

test("rejects an invalid plan before Git preflight or artifact creation", async (t) => {
  const fixture = await createFixture(t, {
    plan: "## Commit 2: invalid",
    reviewer: [],
    worker: [],
  });

  await assert.rejects(
    fixture.run(),
    (error) => error.code === "ERR_INVALID_EXECUTION_PLAN",
  );
  assert.equal(fixture.preflights.length, 0);
  assert.equal(fixture.calls.worker.length, 0);
  await assert.rejects(readFile(fixture.clarificationPath), { code: "ENOENT" });
  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
});

test("rejects an oversized plan before Git preflight or artifact creation", async (t) => {
  const fixture = await createFixture(t, {
    plan: "x".repeat(100_001),
    reviewer: [],
    worker: [],
  });

  await assert.rejects(
    fixture.run(),
    (error) =>
      error.code === "ERR_INVALID_EXECUTION_PLAN" &&
      /must not exceed/u.test(error.message),
  );
  assert.equal(fixture.preflights.length, 0);
  await assert.rejects(readFile(fixture.clarificationPath), { code: "ENOENT" });
  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
});

test("requires a clean repository and an ignored execution transcript", async (t) => {
  await t.test("dirty repository", async (t) => {
    const fixture = await createFixture(t, { dirty: true });

    const result = await fixture.run();

    assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
    assert.equal(result.pause.reason, "unsafe_git_state");
    assert.equal(result.pipelineState.preflightComplete, false);
    assert.equal(fixture.calls.worker.length, 0);
  });

  await t.test("unignored transcript", async (t) => {
    const fixture = await createFixture(t, { clarificationIgnored: false });

    const result = await fixture.run();

    assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
    assert.equal(result.pause.reason, "local_artifacts_not_ignored");
    assert.equal(result.pipelineState.preflightComplete, false);
    await assert.rejects(readFile(fixture.clarificationPath), { code: "ENOENT" });
    assert.equal(fixture.calls.worker.length, 0);
  });
});

test("pauses when an accepted task input changes between bootstrap turns", async (t) => {
  let changed = false;
  const fixture = await createFixture(t, {
    onTransition: async (run) => {
      if (!changed && run.pipelineState.workerSummary !== null) {
        changed = true;
        await writeFile(join(run.taskPath, "task.md"), "Changed task.\n");
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "task_input_changed");
  assert.equal(result.pipelineState.workerSummary, null);
  assert.equal(fixture.calls.reviewer.length, 0);
});

test("pauses when the repository changes between bootstrap turns", async (t) => {
  let changed = false;
  const fixture = await createFixture(t, {
    onTransition: async (run) => {
      if (!changed && run.pipelineState.workerSummary !== null) {
        changed = true;
        await writeFile(join(run.projectPath, "source.js"), "externally changed\n");
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "unsafe_git_state");
  assert.equal(result.pause.code, "ERR_READ_ONLY_REPOSITORY_CHANGED");
  assert.notEqual(result.pipelineState.workerSummary, null);
  assert.equal(fixture.calls.reviewer.length, 0);
});

test("invalidates bootstrap after a read-only role mutates the repository", async (t) => {
  const fixture = await createFixture(t, {
    onRoleRun: async (role) => {
      if (role === "reviewer") {
        await writeFile(join(fixture.projectPath, "source.js"), "mutated\n");
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "read_only_agent_mutated_repository");
  assert.equal(result.pipelineState.workerSummary, null);
  assert.equal(result.pipelineState.reviewerSummary, null);
});

test("detects an ignored transcript mutation during a read-only turn", async (t) => {
  const fixture = await createFixture(t, {
    onRoleRun: async (role, _request, turn) => {
      if (role === "worker" && turn === 2) {
        await writeFile(fixture.clarificationPath, "agent mutation\n");
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "clarifications_changed");
  assert.equal(result.pipelineState.workerSummary, null);
  assert.equal(fixture.calls.reviewer.length, 0);
});

test("enforces the bounded clarification round limit", async (t) => {
  const fixture = await createFixture(t, {
    interactive: true,
    onEdit: async (authorization) => {
      await writeFile(
        authorization.transcriptPath,
        `${await readFile(authorization.transcriptPath, "utf8")}Answer.\n`,
      );
    },
    reviewer: [],
    worker: [
      clarificationQuestions(),
      clarificationQuestions(),
      clarificationQuestions(),
      clarificationQuestions(),
    ],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "clarification_limit_reached");
  assert.equal(result.counters.clarificationRounds, 3);
  assert.equal(fixture.calls.worker.length, 4);
  assert.equal(fixture.calls.reviewer.length, 0);
});

test("uses a fresh Arbiter only for a recorded bootstrap disagreement", async (t) => {
  const fixture = await createFixture(t, {
    arbiter: [arbitrationResolved()],
    capabilities: { arbiter: { nativeSessionFork: false } },
    models: { arbiter: "arbiter-model" },
    sourceSession: SOURCE_SESSION,
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationDisagreement(),
    ],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "IMPLEMENT");
  assert.equal(result.pipelineState.bootstrapArbitrationUsed, true);
  assert.equal(result.pipelineState.bootstrapDisagreement, null);
  assert.equal(result.pipelineState.backendVersions.arbiter, "fake-1.0.0");
  assert.equal(fixture.calls.arbiter.length, 1);
  assert.equal(fixture.calls.arbiter[0].session, undefined);
  assert.equal(fixture.calls.arbiter[0].model, "arbiter-model");
  assert.match(
    fixture.calls.arbiter[0].prompt,
    /Resolve the bootstrap disagreement from the task, plan, repository, and evidence, choosing the minimal valid direction using the provided schema\./u,
  );
  assert.deepEqual(
    result.sessionLineage.children.map(({ role }) => role),
    ["worker", "reviewer", "arbiter"],
  );
});

test("starts a fresh Arbiter for a new bootstrap dispute", async (t) => {
  const secondArbiterSession = "77777777-7777-4777-8777-777777777777";
  const fixture = await createFixture(t, {
    arbiter: [arbitrationProductDecision(), arbitrationResolved()],
    reviewer: [bootstrapReady("Reviewer"), bootstrapReady("Reviewer")],
    sessionIds: {
      arbiter: [ROLE_SESSIONS.arbiter, secondArbiterSession],
      reviewer: [ROLE_SESSIONS.reviewer, RESTARTED_ROLE_SESSIONS.reviewer],
      worker: [ROLE_SESSIONS.worker, RESTARTED_ROLE_SESSIONS.worker],
    },
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationDisagreement(),
      compatibilityReady(),
      bootstrapReady("Worker"),
      reconciliationDisagreement(),
    ],
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "product_decision_required");
  await writeFile(
    fixture.clarificationPath,
    `${await readFile(fixture.clarificationPath, "utf8")}Behavior A.\n`,
  );

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "IMPLEMENT");
  assert.equal(fixture.calls.arbiter.length, 2);
  assert.equal(fixture.calls.arbiter[0].session, undefined);
  assert.equal(fixture.calls.arbiter[1].session, undefined);
  assert.deepEqual(
    result.sessionLineage.children
      .filter(({ role }) => role === "arbiter")
      .map(({ sessionId }) => sessionId),
    [ROLE_SESSIONS.arbiter, secondArbiterSession],
  );
});

test("checks plan compatibility after a bootstrap product decision", async (t) => {
  const fixture = await createFixture(t, {
    worker: [
      clarificationReady(),
      bootstrapProductDecision(),
      compatibilityReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
    ],
  });

  const paused = await fixture.run();

  assert.equal(paused.pause.reason, "product_decision_required");
  assert.equal(paused.pipelineState.pendingEdit.suspendedState, "BOOTSTRAP");
  await writeFile(
    fixture.clarificationPath,
    `${await readFile(fixture.clarificationPath, "utf8")}Behavior A.\n`,
  );

  const resumed = await fixture.run();

  assert.equal(resumed.pipelineState.workflowState, "IMPLEMENT");
  assert.equal(resumed.counters.productDecisions, 1);
  assert.match(fixture.calls.worker[2].prompt, /Review the updated clarifications/u);
  assert.equal(resumed.pipelineState.compatibilityCheckRequired, false);
});

test("restarts independent bootstrap after a reconciliation product decision", async (t) => {
  const fixture = await createFixture(t, {
    reviewer: [bootstrapReady("Reviewer"), bootstrapReady("Reviewer")],
    sessionIds: {
      arbiter: ROLE_SESSIONS.arbiter,
      reviewer: [ROLE_SESSIONS.reviewer, RESTARTED_ROLE_SESSIONS.reviewer],
      worker: [ROLE_SESSIONS.worker, RESTARTED_ROLE_SESSIONS.worker],
    },
    sourceSession: SOURCE_SESSION,
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationProductDecision(),
      compatibilityReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
    ],
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "product_decision_required");
  await writeFile(
    fixture.clarificationPath,
    `${await readFile(fixture.clarificationPath, "utf8")}Behavior A.\n`,
  );

  const resumed = await fixture.run();

  assert.equal(resumed.pipelineState.workflowState, "IMPLEMENT");
  assert.deepEqual(fixture.calls.worker[4].session, {
    mode: "fork",
    id: SOURCE_SESSION,
  });
  assert.deepEqual(fixture.calls.reviewer[1].session, {
    mode: "fork",
    id: SOURCE_SESSION,
  });
  assert.deepEqual(fixture.calls.worker[5].session, {
    mode: "continue",
    id: RESTARTED_ROLE_SESSIONS.worker,
  });
});

test("keeps the run paused when a product answer invalidates the plan", async (t) => {
  const fixture = await createFixture(t, {
    reviewer: [],
    worker: [
      clarificationReady(),
      bootstrapProductDecision(),
      compatibilityPlanRevision(),
    ],
  });

  await fixture.run();
  await writeFile(
    fixture.clarificationPath,
    `${await readFile(fixture.clarificationPath, "utf8")}Behavior B.\n`,
  );
  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "plan_revision_required");
  assert.match(result.pause.explanation, /changes a planned commit boundary/u);
  assert.equal(result.pipelineState.resolvedSummary, null);
  assert.equal(fixture.calls.reviewer.length, 0);
});

test("rejects a fork response that reuses the source session", async (t) => {
  const fixture = await createFixture(t, {
    sessionIds: { ...ROLE_SESSIONS, worker: SOURCE_SESSION },
    sourceSession: SOURCE_SESSION,
  });

  await assert.rejects(
    fixture.run(),
    (error) => error.code === "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
  );
  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
});

test("pauses before agent work when the selected backend is unsafe", async (t) => {
  const fixture = await createFixture(t, {
    capabilities: { worker: { localCommit: false } },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "backend_unavailable");
  assert.equal(result.pipelineState.preflightComplete, false);
  assert.equal(fixture.calls.worker.length, 0);
  await assert.rejects(readFile(fixture.clarificationPath), { code: "ENOENT" });
});

test("preserves settings while retrying a preflight pause", async (t) => {
  const fixture = await createFixture(t, { dirty: true });

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "unsafe_git_state");
  assert.deepEqual(paused.pipelineState.settings, SETTINGS);
  await rm(join(fixture.projectPath, "dirty.txt"));

  const resumed = await fixture.run({ maxFixRoundsPerStep: 99 });

  assert.equal(resumed.pipelineState.workflowState, "IMPLEMENT");
  assert.deepEqual(resumed.pipelineState.settings, SETTINGS);
});

test("verifies frozen inputs when an implementation-boundary run resumes", async (t) => {
  const fixture = await createFixture(t);
  await fixture.run();
  await writeFile(
    join(fixture.taskPath, "plan.md"),
    `${PLAN}\n\nChanged after bootstrap.`,
  );

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "task_input_changed");
  assert.equal(result.pipelineState.currentStep, null);
  assert.equal(result.pipelineState.resolvedSummary, null);
});

test("treats emptied required inputs as drift on resume", async (t) => {
  for (const file of ["task.md", "plan.md"]) {
    await t.test(file, async (t) => {
      const fixture = await createFixture(t);
      await fixture.run();
      await writeFile(join(fixture.taskPath, file), "");

      const result = await fixture.run();

      assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
      assert.equal(result.pause.reason, "task_input_changed");
      assert.equal(result.pipelineState.currentStep, null);
      assert.equal(result.pipelineState.resolvedSummary, null);
    });
  }
});

test("pauses when the repository changes at the implementation boundary", async (t) => {
  const fixture = await createFixture(t);
  await fixture.run();
  await writeFile(join(fixture.projectPath, "source.js"), "externally changed\n");

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "unsafe_git_state");
  assert.equal(result.pause.code, "ERR_READ_ONLY_REPOSITORY_CHANGED");
  assert.notEqual(result.pipelineState.resolvedSummary, null);
});

test("rejects inconsistent persisted workflow state", async (t) => {
  async function rejectsState(name, mutate) {
    await t.test(name, async (t) => {
      const fixture = await createFixture(t);
      await fixture.run();
      mutate(fixture.currentRun);

      await assert.rejects(
        fixture.run(),
        (error) => error.code === "ERR_INVALID_PLAN_EXECUTION_STATE",
      );
    });
  }

  await rejectsState("unresolved used arbitration", (run) => {
    Object.assign(run.pipelineState, {
      workflowState: "BOOTSTRAP",
      currentStep: null,
      resolvedSummary: null,
      bootstrapDisagreement: {
        description: "The roles still disagree.",
        evidence: ["The repository evidence supports different boundaries."],
      },
      bootstrapArbitrationUsed: true,
    });
  });

  await rejectsState("arbitration without backend metadata", (run) => {
    run.pipelineState.bootstrapArbitrationUsed = true;
  });

  await rejectsState("frozen compatibility re-entry", (run) => {
    Object.assign(run.pipelineState, {
      workflowState: "BOOTSTRAP",
      currentStep: null,
      clarificationFrozen: true,
      workerSummary: null,
      reviewerSummary: null,
      resolvedSummary: null,
      compatibilityCheckRequired: true,
    });
  });

  await rejectsState("edit pause without authorization", (run) => {
    run.pipelineState.workflowState = "WAITING_FOR_USER";
    run.pause = { reason: "product_decision_required" };
  });

  await rejectsState("duplicate child session", (run) => {
    run.sessionLineage.children.push({ ...run.sessionLineage.children[0] });
  });

  await t.test("bootstrap context before preflight", async (t) => {
    const fixture = await createFixture(t);
    fixture.currentRun.pipelineState = {
      ...fixture.currentRun.pipelineState,
      workflowState: "FAILED",
      clarificationFrozen: true,
      workerSummary: "Worker summary.",
      reviewerSummary: "Reviewer summary.",
      resolvedSummary: "Resolved summary.",
      currentStep: 1,
    };
    fixture.currentRun.pause = { reason: "internal_failure" };

    await assert.rejects(
      fixture.run(),
      (error) => error.code === "ERR_INVALID_PLAN_EXECUTION_STATE",
    );
  });
});

test("rejects a child session shared by Worker and Reviewer", async (t) => {
  const fixture = await createFixture(t, {
    sessionIds: {
      ...ROLE_SESSIONS,
      reviewer: ROLE_SESSIONS.worker,
    },
  });

  await assert.rejects(
    fixture.run(),
    (error) => error.code === "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
  );
  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
});

test("rejects a fresh role turn that reuses its previous session", async (t) => {
  const fixture = await createFixture(t, {
    sessionIds: {
      ...ROLE_SESSIONS,
      worker: [ROLE_SESSIONS.worker, ROLE_SESSIONS.worker],
    },
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationProductDecision(),
      compatibilityReady(),
      bootstrapReady("Worker"),
    ],
  });

  await fixture.run();
  await writeFile(
    fixture.clarificationPath,
    `${await readFile(fixture.clarificationPath, "utf8")}Behavior A.\n`,
  );

  await assert.rejects(
    fixture.run(),
    (error) => error.code === "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
  );
  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
});

test("retries an unavailable bootstrap Arbiter without repeating bootstrap", async (t) => {
  const arbiterCapabilities = { readOnly: false };
  const fixture = await createFixture(t, {
    arbiter: [arbitrationResolved()],
    capabilities: { arbiter: arbiterCapabilities },
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationDisagreement(),
    ],
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pause.resumeState, "BOOTSTRAP");
  assert.equal(paused.pipelineState.bootstrapDisagreement.description.length > 0, true);
  assert.equal(fixture.calls.worker.length, 3);
  arbiterCapabilities.readOnly = true;

  const resumed = await fixture.run();

  assert.equal(resumed.pipelineState.workflowState, "IMPLEMENT");
  assert.equal(fixture.calls.worker.length, 3);
  assert.equal(fixture.calls.reviewer.length, 1);
  assert.equal(fixture.calls.arbiter.length, 1);
  assert.equal(fixture.probeCalls.arbiter, 2);
});
