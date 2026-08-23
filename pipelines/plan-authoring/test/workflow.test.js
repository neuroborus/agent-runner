import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
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
import { join, relative } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

import {
  createPlanAuthoringState,
  runPlanAuthoring,
} from "../src/index.js";

const executeFile = promisify(execFile);
const SOURCE_SESSION = "11111111-1111-4111-8111-111111111111";
const ROLE_SESSIONS = Object.freeze({
  planner: "22222222-2222-4222-8222-222222222222",
  reviewer: "33333333-3333-4333-8333-333333333333",
  arbiter: "44444444-4444-4444-8444-444444444444",
});
const PLAN = `## Commit 1: feat(test): add behavior

Implement the requested behavior.`;
const REVISED_PLAN = `## Commit 1: feat(test): add behavior

Implement and verify the requested behavior.`;

function hash(value) {
  return createHash("sha256").update(value).digest("hex");
}

function ready() {
  return { status: "READY", questions: [] };
}

function questions() {
  return {
    status: "QUESTIONS",
    questions: [
      {
        question: "Which behavior is required?",
        whyItMatters: "The answer changes the commit boundary.",
      },
    ],
  };
}

function draft(plan = PLAN) {
  return {
    status: "DRAFT",
    plan,
    question: "",
    options: [],
    whyBlocked: "",
    evidence: [],
  };
}

function productDecision(resultField = { plan: "" }) {
  return {
    status: "PRODUCT_DECISION_REQUIRED",
    question: "Which public behavior should be used?",
    options: ["Behavior A", "Behavior B"],
    whyBlocked: "Both choices are valid but incompatible.",
    evidence: ["The task does not select either behavior."],
    ...resultField,
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

function findings(id) {
  return {
    status: "FINDINGS",
    findings: [
      {
        id,
        description: `Resolve finding ${id}.`,
        evidence: [`Evidence for ${id}.`],
      },
    ],
    question: "",
    options: [],
    whyBlocked: "",
    evidence: [],
  };
}

function continueRevision() {
  return {
    direction: "CONTINUE_REVISION",
    rationale: "The remaining finding has a direct correction.",
    findingIds: [],
    question: "",
    options: [],
    whyBlocked: "",
    evidence: [],
  };
}

function reconsiderFindings(...findingIds) {
  return {
    direction: "RECONSIDER_FINDINGS",
    rationale: "The Reviewer should reassess the current findings.",
    findingIds,
    question: "",
    options: [],
    whyBlocked: "",
    evidence: [],
  };
}

function arbitrationProductDecision() {
  return {
    direction: "PRODUCT_DECISION_REQUIRED",
    rationale: "The remaining blocker requires a product decision.",
    findingIds: [],
    question: "Which public behavior should be used?",
    options: ["Behavior A", "Behavior B"],
    whyBlocked: "Both choices are valid but incompatible.",
    evidence: ["The task does not select either behavior."],
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

function assertFindingIdSchema(schema) {
  assert.deepEqual(schema, {
    type: "string",
    maxLength: 64,
    pattern: "^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$",
  });
}

async function repositoryFingerprint(
  root,
  ignoredPaths = ["task/clarifications.md"],
) {
  const entries = [];
  const ignored = new Set(ignoredPaths);

  async function visit(directory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      if (entry.name === ".git") {
        continue;
      }
      const path = join(directory, entry.name);
      if (ignored.has(relative(root, path))) {
        continue;
      }
      if (entry.isDirectory()) {
        await visit(path);
      } else {
        entries.push([
          relative(root, path),
          hash(await readFile(path)),
        ]);
      }
    }
  }

  await visit(root);
  entries.sort(([left], [right]) => left.localeCompare(right));
  return hash(JSON.stringify(entries));
}

function createClarificationService({
  interactive = false,
  onEdit,
  onInspect,
} = {}) {
  let authorizationIndex = 0;

  function assertExpectedHash(snapshot, expectedHash) {
    if (snapshot.hash !== expectedHash) {
      const error = new Error("Clarifications changed.");
      error.code = "ERR_CLARIFICATIONS_CHANGED";
      throw error;
    }
  }

  async function inspectTranscript({ transcriptPath }) {
    await onInspect?.(transcriptPath);
    const content = await readFile(transcriptPath, "utf8");
    return Object.freeze({
      artifactRoot: join(transcriptPath, ".."),
      transcriptPath,
      content,
      hash: hash(content),
    });
  }

  async function ensureTranscript(options) {
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

async function createFixture(
  t,
  {
    arbiter = [],
    clarificationIgnored = true,
    emptyClarification = false,
    interactive = false,
    models = {},
    onEdit,
    onInspectTranscript,
    onPreflight,
    onReadInputs,
    onRoleRun,
    planner = [ready(), draft()],
    proactiveClarification = false,
    reviewer = [approved()],
    sessionIds = ROLE_SESSIONS,
    sourceSession = null,
  } = {},
) {
  const projectPath = await mkdtemp(join(tmpdir(), "agent-runner-authoring-"));
  const taskPath = join(projectPath, "task");
  const clarificationPath = join(taskPath, "clarifications.md");
  const planPath = join(taskPath, "plan.md");
  await executeFile("git", ["init", "-q", projectPath]);
  await mkdir(taskPath);
  await writeFile(join(taskPath, "task.md"), "Implement the requested behavior.\n");
  await writeFile(
    join(projectPath, ".gitignore"),
    clarificationIgnored ? "/task/clarifications.md\n" : "",
  );
  if (emptyClarification) {
    await writeFile(clarificationPath, "");
  }
  t.after(() => rm(projectPath, { recursive: true, force: true }));

  const queues = { planner: [...planner], reviewer: [...reviewer], arbiter: [...arbiter] };
  const calls = { planner: [], reviewer: [], arbiter: [] };
  const freshSessionCounts = { planner: 0, reviewer: 0, arbiter: 0 };
  const adapters = Object.fromEntries(
    Object.keys(queues).map((role) => [
      role,
      {
        async run(request) {
          calls[role].push(request);
          await onRoleRun?.(role, request, calls[role].length);
          assert.ok(queues[role].length > 0, `Unexpected ${role} turn.`);
          const freshSessionCount = freshSessionCounts[role];
          if (request.session?.mode !== "continue") {
            freshSessionCounts[role] += 1;
          }
          return {
            output: "structured",
            structured: queues[role].shift(),
            sessionId:
              request.session?.mode === "continue"
                ? request.session.id
                : freshSessionCount === 0
                  ? sessionIds[role]
                  : `${sessionIds[role]}-${freshSessionCount}`,
          };
        },
      },
    ]),
  );

  async function gitSnapshot({ allowedPaths = [] } = {}) {
    const normalizedAllowedPaths = allowedPaths
      .map((path) => relative(projectPath, path))
      .sort();
    const ignoredPaths = ["task/clarifications.md", ...normalizedAllowedPaths];
    return {
      schemaVersion: 1,
      projectPath,
      allowedPaths: normalizedAllowedPaths,
      fingerprint: await repositoryFingerprint(projectPath, ignoredPaths),
      ignoredPaths,
    };
  }

  let currentRun = {
    revision: 1,
    pipelineId: "plan-authoring",
    pipelineStateVersion: 1,
    projectPath,
    taskPath,
    roles: {
      planner: { backend: "codex", model: models.planner ?? null },
      reviewer: { backend: "codex", model: models.reviewer ?? null },
      arbiter: { backend: "codex", model: models.arbiter ?? null },
    },
    counters: {},
    hashes: {},
    pause: null,
    sessionLineage: { source: sourceSession, children: [] },
    pipelineState: createPlanAuthoringState({ proactiveClarification }),
  };
  const transitions = [];
  const runtime = {
    adapters,
    clarifications: createClarificationService({
      interactive,
      onEdit,
      onInspect: onInspectTranscript,
    }),
    git: {
      async preflight({ allowedPaths, requiredIgnoredPaths }) {
        for (const path of requiredIgnoredPaths) {
          try {
            await executeFile("git", ["-C", projectPath, "check-ignore", "-q", "--", path]);
          } catch (cause) {
            const error = new Error("Artifact is not ignored.");
            error.code = "ERR_REPOSITORY_ARTIFACT_NOT_IGNORED";
            error.cause = cause;
            throw error;
          }
        }
        const snapshot = await gitSnapshot({ allowedPaths });
        return { snapshot: (await onPreflight?.(snapshot)) ?? snapshot };
      },
      snapshot: gitSnapshot,
      async assertUnchanged(snapshot) {
        if (
          snapshot.fingerprint !==
          (await repositoryFingerprint(projectPath, snapshot.ignoredPaths))
        ) {
          const error = new Error("Read-only repository changed.");
          error.code = "ERR_READ_ONLY_REPOSITORY_CHANGED";
          throw error;
        }
      },
    },
    async readInputs() {
      await onReadInputs?.(taskPath);
      const taskContent = await readFile(join(taskPath, "task.md"), "utf8");
      let context = null;
      try {
        const content = await readFile(join(taskPath, "context.md"), "utf8");
        context = { path: join(taskPath, "context.md"), content, hash: hash(content) };
      } catch (cause) {
        if (cause?.code !== "ENOENT") {
          throw cause;
        }
      }
      return {
        task: { path: join(taskPath, "task.md"), content: taskContent, hash: hash(taskContent) },
        context,
      };
    },
    async transition(patch, options) {
      currentRun = { ...currentRun, ...patch, revision: currentRun.revision + 1 };
      transitions.push({ patch, options });
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
    async writePlan({ artifactRoot, path, content }) {
      assert.equal(artifactRoot, taskPath);
      assert.equal(path, planPath);
      const temporaryPath = join(taskPath, `.plan-${randomUUID()}.tmp`);
      await writeFile(temporaryPath, content);
      await rename(temporaryPath, path);
      return path;
    },
  };

  async function run(settings = {}) {
    currentRun = await runPlanAuthoring({
      run: currentRun,
      runtime,
      settings: {
        maxRevisionRounds: 15,
        stagnationWindowRounds: 3,
        ...settings,
      },
    });
    return currentRun;
  }

  return {
    calls,
    clarificationPath,
    get currentRun() {
      return currentRun;
    },
    planPath,
    projectPath,
    run,
    taskPath,
    transitions,
  };
}

test("writes one validated plan through independent source-session forks", async (t) => {
  const fixture = await createFixture(t, {
    models: { planner: "planner-model", reviewer: "reviewer-model" },
    sourceSession: SOURCE_SESSION,
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(await readFile(fixture.planPath, "utf8"), PLAN);
  assert.deepEqual(
    result.sessionLineage.children.map(({ role }) => role),
    ["planner", "reviewer"],
  );
  assert.deepEqual(fixture.calls.planner[0].session, {
    id: SOURCE_SESSION,
    mode: "fork",
  });
  assert.deepEqual(fixture.calls.planner[1].session, {
    id: ROLE_SESSIONS.planner,
    mode: "continue",
  });
  assert.match(fixture.calls.planner[0].prompt, /Task \(/u);
  assert.equal(
    fixture.calls.planner[0].recoveryPrompt,
    fixture.calls.planner[0].prompt,
  );
  for (const heading of [/Task \(/u, /Context \(/u, /Clarifications \(/u]) {
    assert.doesNotMatch(fixture.calls.planner[1].prompt, heading);
    assert.match(fixture.calls.planner[1].recoveryPrompt, heading);
  }
  assert.deepEqual(fixture.calls.reviewer[0].session, {
    id: SOURCE_SESSION,
    mode: "fork",
  });
  assert.equal(fixture.calls.arbiter.length, 0);
  for (const child of result.sessionLineage.children) {
    assert.match(child.contextKey, /^[a-f0-9]{64}$/u);
  }
  for (const request of fixture.calls.planner) {
    assert.equal(request.access, "read-only");
    assert.equal(request.cwd, fixture.projectPath);
    assert.equal(request.model, "planner-model");
    assertStrictSchema(request.schema);
  }
  for (const request of fixture.calls.reviewer) {
    assert.equal(request.access, "read-only");
    assert.equal(request.cwd, fixture.projectPath);
    assert.equal(request.model, "reviewer-model");
    assertStrictSchema(request.schema);
    assertFindingIdSchema(
      request.schema.properties.findings.items.properties.id,
    );
  }
  await assert.rejects(
    executeFile("git", ["-C", fixture.projectPath, "rev-parse", "HEAD"]),
  );
});

test("rejects a fork response that reuses the source session", async (t) => {
  const fixture = await createFixture(t, {
    reviewer: [],
    sessionIds: { ...ROLE_SESSIONS, planner: SOURCE_SESSION },
    sourceSession: SOURCE_SESSION,
  });

  await assert.rejects(
    fixture.run(),
    /returned the source session ID instead of a child session/u,
  );
  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
  assert.deepEqual(fixture.currentRun.sessionLineage.children, []);
});

test("rejects persisted child lineage that reuses the source session", async (t) => {
  const fixture = await createFixture(t, { sourceSession: SOURCE_SESSION });
  await fixture.run();
  fixture.currentRun.sessionLineage = {
    ...fixture.currentRun.sessionLineage,
    children: fixture.currentRun.sessionLineage.children.map((child, index) =>
      index === 0 ? { ...child, sessionId: SOURCE_SESSION } : child,
    ),
  };

  await assert.rejects(fixture.run(), /child session is invalid/u);
});

test("rejects duplicate persisted child sessions", async (t) => {
  const fixture = await createFixture(t);
  await fixture.run();
  fixture.currentRun.sessionLineage = {
    ...fixture.currentRun.sessionLineage,
    children: [
      ...fixture.currentRun.sessionLineage.children,
      fixture.currentRun.sessionLineage.children[0],
    ],
  };

  await assert.rejects(fixture.run(), /child sessions must be unique/u);
});

test("rejects a persisted write state that bypasses review", async (t) => {
  const fixture = await createFixture(t);
  await fixture.run();
  Object.assign(fixture.currentRun.pipelineState, {
    workflowState: "WRITE_PLAN",
    planPath: null,
    reviewApproved: false,
  });

  await assert.rejects(fixture.run(), /completion state is inconsistent/u);
});

test("never writes a canonical plan that differs from the reviewed draft", async (t) => {
  const fixture = await createFixture(t);
  await fixture.run();
  Object.assign(fixture.currentRun.pipelineState, {
    workflowState: "WRITE_PLAN",
    planPath: null,
    canonicalPlan: REVISED_PLAN,
  });

  await assert.rejects(
    fixture.run(),
    /Canonical plan does not match the reviewed draft/u,
  );
  assert.equal(fixture.currentRun.pipelineState.workflowState, "WRITE_PLAN");
  assert.equal(await readFile(fixture.planPath, "utf8"), PLAN);
});

test("rejects a completed state whose canonical plan differs from its draft", async (t) => {
  const fixture = await createFixture(t);
  await fixture.run();
  fixture.currentRun.pipelineState.canonicalPlan = REVISED_PLAN;

  await assert.rejects(
    fixture.run(),
    /Canonical plan does not match the reviewed draft/u,
  );
  assert.equal(fixture.currentRun.pipelineState.workflowState, "DONE");
});

test("rejects explicit null persisted counters", async (t) => {
  const fixture = await createFixture(t);
  fixture.currentRun.counters.revisionRounds = null;

  await assert.rejects(
    fixture.run(),
    /counter revisionRounds is invalid/u,
  );
});

test("rejects inconsistent persisted correction progress", async (t) => {
  const fixture = await createFixture(t);
  await fixture.run();
  fixture.currentRun.counters = {
    ...fixture.currentRun.counters,
    revisionRounds: 1,
    correctionRounds: 1,
  };

  await assert.rejects(fixture.run(), /persisted progress is invalid/u);
});

test("rejects stale persisted correction history", async (t) => {
  const fixture = await createFixture(t, {
    planner: [ready(), draft(), draft(REVISED_PLAN), draft(PLAN)],
    reviewer: [findings("scope-a"), findings("scope-b"), approved()],
  });
  await fixture.run();
  fixture.currentRun.counters = {
    ...fixture.currentRun.counters,
    revisionRounds: 2,
    correctionRounds: 2,
  };
  fixture.currentRun.pipelineState = {
    ...fixture.currentRun.pipelineState,
    lastCountedRevision: 2,
  };

  await assert.rejects(fixture.run(), /persisted progress is invalid/u);
});

test("rejects persisted progress outside configured budgets", async (t) => {
  const corruptions = [
    (run) => {
      run.counters = { ...run.counters, revisionRounds: 16 };
      run.pipelineState = { ...run.pipelineState, lastCountedRevision: 16 };
    },
    (run) => {
      run.pipelineState = { ...run.pipelineState, arbitrationUsed: true };
    },
    (run) => {
      run.counters = {
        ...run.counters,
        correctionRounds: 4,
        revisionRounds: 4,
      };
      run.pipelineState = {
        ...run.pipelineState,
        blockedSinceArbitration: 4,
        lastCountedRevision: 4,
      };
    },
  ];

  for (const corrupt of corruptions) {
    const fixture = await createFixture(t);
    await fixture.run();
    corrupt(fixture.currentRun);

    await assert.rejects(fixture.run(), /persisted progress is invalid/u);
  }
});

test("preserves an empty proactive clarification", async (t) => {
  const fixture = await createFixture(t, {
    emptyClarification: true,
    interactive: true,
    proactiveClarification: true,
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(await readFile(fixture.clarificationPath, "utf8"), "");
  assert.equal(result.counters.clarificationRounds, 0);
  assert.equal("model" in fixture.calls.planner[0], false);
});

test("rejects inconsistent persisted proactive clarification state", async (t) => {
  const completedFixture = await createFixture(t, {
    interactive: true,
    proactiveClarification: true,
  });
  await completedFixture.run();
  completedFixture.currentRun.pipelineState.proactiveClarificationComplete =
    false;

  await assert.rejects(
    completedFixture.run(),
    /proactive clarification state is invalid/u,
  );

  const waitingFixture = await createFixture(t, {
    proactiveClarification: true,
  });
  await waitingFixture.run();
  waitingFixture.currentRun.pipelineState.proactiveClarificationComplete = true;

  await assert.rejects(
    waitingFixture.run(),
    /proactive clarification state is invalid/u,
  );
});

test("pauses for questions and resumes after an authorized edit", async (t) => {
  const fixture = await createFixture(t, {
    planner: [questions(), ready(), draft()],
  });

  const waiting = await fixture.run();

  assert.equal(waiting.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(waiting.pause.reason, "clarification_answers_required");
  assert.equal(waiting.counters.clarificationRounds, 1);
  const roundTransitions = fixture.transitions.filter(
    ({ patch }) => patch?.counters?.clarificationRounds === 1,
  );
  assert.equal(roundTransitions.length, 1);
  assert.equal(
    roundTransitions[0].patch.pipelineState.workflowState,
    "WAITING_FOR_USER",
  );
  assert.equal(
    roundTransitions[0].patch.pipelineState.pendingEdit.preEditorHash,
    roundTransitions[0].patch.hashes.clarifications,
  );
  await writeFile(
    fixture.clarificationPath,
    `${await readFile(fixture.clarificationPath, "utf8")}Behavior A.\n`,
  );

  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.pause, null);
  assert.equal(fixture.calls.planner[1].session, undefined);
  assert.match(fixture.calls.planner[1].prompt, /Task \(/u);
  assert.notEqual(
    completed.sessionLineage.children[0].contextKey,
    completed.sessionLineage.children[1].contextKey,
  );
});

test("atomically replaces an unanswered edit authorization", async (t) => {
  const fixture = await createFixture(t, {
    interactive: true,
    planner: [questions()],
    reviewer: [],
  });

  const firstWaiting = await fixture.run();

  assert.equal(firstWaiting.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(firstWaiting.pipelineState.pendingEdit.id, "edit-2");
  assert.equal(firstWaiting.pause.authorizationId, "edit-2");
  assert.equal(fixture.calls.planner.length, 1);

  const secondWaiting = await fixture.run();

  assert.equal(secondWaiting.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(secondWaiting.pipelineState.pendingEdit.id, "edit-3");
  assert.equal(secondWaiting.pause.authorizationId, "edit-3");
  assert.equal(fixture.calls.planner.length, 1);
});

test("rejects a persisted edit authorization outside the task", async (t) => {
  const fixture = await createFixture(t, {
    planner: [questions()],
    reviewer: [],
  });
  await fixture.run();
  fixture.currentRun.pipelineState.pendingEdit = {
    ...fixture.currentRun.pipelineState.pendingEdit,
    transcriptPath: join(fixture.projectPath, "outside.md"),
  };

  await assert.rejects(fixture.run(), /pending edit path is invalid/u);
});

test("rejects a persisted edit authorization for another transcript version", async (t) => {
  const fixture = await createFixture(t, {
    planner: [questions()],
    reviewer: [],
  });
  await fixture.run();
  fixture.currentRun.pipelineState.pendingEdit = {
    ...fixture.currentRun.pipelineState.pendingEdit,
    preEditorHash: hash("stale transcript"),
  };

  await assert.rejects(fixture.run(), /pending edit hash is invalid/u);
});

test("rejects a persisted pause outside a paused state", async (t) => {
  const fixture = await createFixture(t);
  await fixture.run();
  fixture.currentRun.pause = { reason: "stale_pause" };

  await assert.rejects(fixture.run(), /pause state is invalid/u);
});

test("rejects a persisted pause for another edit authorization", async (t) => {
  const fixture = await createFixture(t, {
    planner: [questions()],
    reviewer: [],
  });
  await fixture.run();
  fixture.currentRun.pause = {
    ...fixture.currentRun.pause,
    authorizationId: "different-edit",
  };

  await assert.rejects(fixture.run(), /pending edit pause is invalid/u);
});

test("rejects malformed persisted structured input", async (t) => {
  const fixture = await createFixture(t, {
    planner: [questions()],
    reviewer: [],
  });
  await fixture.run();
  fixture.currentRun.pause.inputRequest.questions[0].id = "q2";

  await assert.rejects(fixture.run(), /input request is invalid/u);
});

test("pauses after three clarification question rounds", async (t) => {
  const fixture = await createFixture(t, {
    interactive: true,
    onEdit: async ({ transcriptPath }) => {
      await writeFile(
        transcriptPath,
        `${await readFile(transcriptPath, "utf8")}Answer.\n`,
      );
    },
    planner: [questions(), questions(), questions(), questions()],
    reviewer: [],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "clarification_limit_reached");
  assert.equal(result.counters.clarificationRounds, 3);
  assert.equal(fixture.calls.reviewer.length, 0);
});

test("invalid deterministic plans return to the Planner", async (t) => {
  const fixture = await createFixture(t, {
    planner: [ready(), draft("not a plan"), draft(REVISED_PLAN)],
    reviewer: [approved(), approved()],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.revisionRounds, 1);
  assert.equal(result.counters.correctionRounds, 0);
  assert.match(fixture.calls.planner[2].prompt, /must contain at least one/u);
});

test("rejects reviewer finding IDs that are not kebab-case", async (t) => {
  const fixture = await createFixture(t, {
    planner: [ready(), draft()],
    reviewer: [findings("scope-")],
  });

  await assert.rejects(fixture.run(), /invalid ID/u);

  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
});

test("routes product decisions through the transcript and invalidates inputs", async (t) => {
  const fixture = await createFixture(t, {
    planner: [ready(), productDecision(), draft()],
  });

  const waiting = await fixture.run();

  assert.equal(waiting.pause.reason, "product_decision_required");
  assert.deepEqual(waiting.pause.inputRequest, {
    id: waiting.pipelineState.pendingEdit.id,
    kind: "product-decision",
    questions: [
      {
        id: "decision",
        question: "Which public behavior should be used?",
        options: ["Behavior A", "Behavior B"],
      },
    ],
    rationale: "Both choices are valid but incompatible.",
    artifactPath: fixture.clarificationPath,
  });
  assert.equal(waiting.counters.productDecisions, 1);
  const decisionTransitions = fixture.transitions.filter(
    ({ patch }) => patch?.counters?.productDecisions === 1,
  );
  assert.equal(decisionTransitions.length, 1);
  assert.equal(
    decisionTransitions[0].patch.pipelineState.workflowState,
    "WAITING_FOR_USER",
  );
  assert.equal(
    decisionTransitions[0].patch.pipelineState.pendingEdit.preEditorHash,
    decisionTransitions[0].patch.hashes.clarifications,
  );
  assert.match(
    await readFile(fixture.clarificationPath, "utf8"),
    /Product Decision 1/u,
  );
  await writeFile(
    fixture.clarificationPath,
    `${await readFile(fixture.clarificationPath, "utf8")}Behavior A.\n`,
  );

  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(fixture.calls.planner.length, 3);
});

test("rejects product decisions that exceed the transcript contract", async (t) => {
  const decision = productDecision();
  decision.options = Array.from(
    { length: 17 },
    (_, index) => `Behavior ${index + 1}`,
  );
  const fixture = await createFixture(t, {
    planner: [ready(), decision],
    reviewer: [],
  });

  await assert.rejects(
    fixture.run(),
    /product decision options has an invalid number of items/u,
  );

  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
  assert.equal(fixture.currentRun.counters.productDecisions, 0);
});

test("does not count a pre-decision revision after replanning", async (t) => {
  const fixture = await createFixture(t, {
    planner: [
      ready(),
      draft(),
      draft(REVISED_PLAN),
      draft(PLAN),
      draft(REVISED_PLAN),
      draft(REVISED_PLAN),
    ],
    reviewer: [
      findings("scope-a"),
      findings("scope-b"),
      productDecision({ findings: [] }),
      findings("scope-c"),
      approved(),
    ],
  });

  const waiting = await fixture.run();
  await writeFile(
    fixture.clarificationPath,
    `${await readFile(fixture.clarificationPath, "utf8")}Behavior A.\n`,
  );

  const result = await fixture.run();

  assert.equal(waiting.pause.reason, "product_decision_required");
  assert.equal(waiting.counters.correctionRounds, 1);
  assert.equal(waiting.pipelineState.blockedSinceArbitration, 0);
  assert.deepEqual(waiting.pipelineState.correctionHistory, []);
  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.revisionRounds, 3);
  assert.equal(result.counters.correctionRounds, 1);
});

test("records finding churn and invokes one fresh stagnation Arbiter", async (t) => {
  const fixture = await createFixture(t, {
    sourceSession: SOURCE_SESSION,
    planner: [
      ready(),
      draft(),
      draft(REVISED_PLAN),
      draft(PLAN),
      draft(REVISED_PLAN),
    ],
    reviewer: [
      findings("scope-a"),
      findings("scope-b"),
      findings("scope-c"),
      approved(),
    ],
    arbiter: [continueRevision()],
  });

  const result = await fixture.run({ stagnationWindowRounds: 2 });

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.correctionRounds, 2);
  assert.deepEqual(
    result.pipelineState.correctionHistory.map(({ findingIds }) => findingIds),
    [["scope-b"], ["scope-c"]],
  );
  assert.equal(fixture.calls.arbiter.length, 1);
  assert.equal(fixture.calls.arbiter[0].access, "read-only");
  assert.equal(fixture.calls.arbiter[0].cwd, fixture.projectPath);
  assert.equal(fixture.calls.arbiter[0].session, undefined);
  assertStrictSchema(fixture.calls.arbiter[0].schema);
  assertFindingIdSchema(
    fixture.calls.arbiter[0].schema.properties.findingIds.items,
  );
  assert.match(
    fixture.calls.arbiter[0].prompt,
    /^Diagnose why the plan revision loop is not converging/u,
  );
  assert.match(fixture.calls.arbiter[0].prompt, /"currentPlan":/u);
  assert.match(
    fixture.calls.arbiter[0].prompt,
    /Implement the requested behavior/u,
  );
});

test("continues a recorded Arbiter after an interrupted result transition", async (t) => {
  const fixture = await createFixture(t, {
    planner: [
      ready(),
      draft(),
      draft(REVISED_PLAN),
      draft(PLAN),
      draft(REVISED_PLAN),
    ],
    reviewer: [
      findings("scope-a"),
      findings("scope-b"),
      findings("scope-c"),
      approved(),
    ],
    arbiter: [continueRevision(), arbitrationProductDecision()],
  });
  await fixture.run({ stagnationWindowRounds: 2 });
  const interrupted = fixture.transitions.find(
    ({ patch }) =>
      patch?.pipelineState?.workflowState === "REVISE" &&
      patch.pipelineState.blockedSinceArbitration === 2 &&
      !patch.pipelineState.arbitrationUsed,
  );
  assert.ok(interrupted);
  Object.assign(fixture.currentRun, {
    counters: interrupted.patch.counters,
    hashes: interrupted.patch.hashes,
    pause: interrupted.patch.pause,
    pipelineState: interrupted.patch.pipelineState,
  });

  const result = await fixture.run({ stagnationWindowRounds: 2 });

  assert.equal(result.pause.reason, "product_decision_required");
  assert.deepEqual(fixture.calls.arbiter[1].session, {
    id: ROLE_SESSIONS.arbiter,
    mode: "continue",
  });
});

test("routes applicable finding reconsideration back to the Reviewer", async (t) => {
  const fixture = await createFixture(t, {
    planner: [ready(), draft(), draft(REVISED_PLAN)],
    reviewer: [findings("scope-a"), findings("scope-b"), approved()],
    arbiter: [reconsiderFindings("scope-b")],
  });

  const result = await fixture.run({ stagnationWindowRounds: 1 });

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(fixture.calls.planner.length, 3);
  assert.equal(fixture.calls.reviewer.length, 3);
  assert.equal(fixture.calls.arbiter.length, 1);
  assert.match(fixture.calls.reviewer[2].prompt, /"id": "scope-b"/u);
});

test("rejects an inapplicable stagnation direction", async (t) => {
  const fixture = await createFixture(t, {
    planner: [ready(), draft(), draft(REVISED_PLAN)],
    reviewer: [findings("scope-a"), findings("scope-b")],
    arbiter: [reconsiderFindings("different-finding")],
  });

  await assert.rejects(
    fixture.run({ stagnationWindowRounds: 1 }),
    /Finding reconsideration is not applicable/u,
  );

  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
  await assert.rejects(readFile(fixture.planPath, "utf8"), /ENOENT/u);
});

test("pauses when plan corrections stagnate again", async (t) => {
  const fixture = await createFixture(t, {
    planner: [ready(), draft(), draft(REVISED_PLAN), draft(PLAN)],
    reviewer: [findings("scope-a"), findings("scope-b"), findings("scope-c")],
    arbiter: [continueRevision()],
  });

  const result = await fixture.run({ stagnationWindowRounds: 1 });

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "plan_revision_not_converging");
  assert.equal(fixture.calls.arbiter.length, 1);
  await assert.rejects(readFile(fixture.planPath, "utf8"), /ENOENT/u);
});

test("enforces the configured revision budget", async (t) => {
  const fixture = await createFixture(t, {
    planner: [ready(), draft(), draft(REVISED_PLAN)],
    reviewer: [findings("scope-a"), findings("scope-b")],
  });

  const result = await fixture.run({
    maxRevisionRounds: 1,
    stagnationWindowRounds: 10,
  });

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "plan_revision_limit_reached");
  assert.equal(result.counters.revisionRounds, 1);
  await assert.rejects(readFile(fixture.planPath, "utf8"), /ENOENT/u);
});

test("keeps resolved settings stable across resume", async (t) => {
  const fixture = await createFixture(t, {
    planner: [ready(), productDecision(), draft(), draft(REVISED_PLAN)],
    reviewer: [findings("scope-a"), findings("scope-b")],
  });

  await fixture.run({
    maxRevisionRounds: 1,
    stagnationWindowRounds: 10,
  });
  await writeFile(
    fixture.clarificationPath,
    `${await readFile(fixture.clarificationPath, "utf8")}Behavior A.\n`,
  );

  const resumed = await fixture.run({
    maxRevisionRounds: 2,
    stagnationWindowRounds: 10,
  });
  assert.equal(resumed.pause.reason, "plan_revision_limit_reached");
  assert.equal(resumed.counters.revisionRounds, 1);
  assert.deepEqual(resumed.pipelineState.settings, {
    maxRevisionRounds: 1,
    stagnationWindowRounds: 10,
  });
});

test("requires repository-local clarifications to be ignored before creation", async (t) => {
  const fixture = await createFixture(t, { clarificationIgnored: false });

  await assert.rejects(
    fixture.run(),
    (error) => error.code === "ERR_REPOSITORY_ARTIFACT_NOT_IGNORED",
  );

  await assert.rejects(readFile(fixture.clarificationPath, "utf8"), /ENOENT/u);
  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
});

test("rechecks artifact safety from the canonical repository root", async (t) => {
  const fixture = await createFixture(t, { clarificationIgnored: false });
  const projectSubdirectory = join(fixture.projectPath, "src");
  await mkdir(projectSubdirectory);
  fixture.currentRun.projectPath = projectSubdirectory;

  await assert.rejects(
    fixture.run(),
    (error) => error.code === "ERR_REPOSITORY_ARTIFACT_NOT_IGNORED",
  );

  await assert.rejects(readFile(fixture.clarificationPath, "utf8"), /ENOENT/u);
  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
});

test("rejects an unstable canonical repository root before artifact creation", async (t) => {
  let preflights = 0;
  const fixture = await createFixture(t, {
    onPreflight(snapshot) {
      preflights += 1;
      return preflights === 2
        ? { ...snapshot, projectPath: tmpdir() }
        : snapshot;
    },
  });
  const projectSubdirectory = join(fixture.projectPath, "src");
  await mkdir(projectSubdirectory);
  fixture.currentRun.projectPath = projectSubdirectory;

  await assert.rejects(fixture.run(), /unstable repository root/u);

  await assert.rejects(readFile(fixture.clarificationPath, "utf8"), /ENOENT/u);
  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
});

test("invalidates dependent work after a read-only repository mutation", async (t) => {
  let mutated = false;
  const fixture = await createFixture(t, {
    async onRoleRun(role) {
      if (role === "reviewer" && !mutated) {
        mutated = true;
        await writeFile(join(fixture.projectPath, "unexpected.txt"), "mutation");
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "read_only_mutation");
  assert.equal(result.pause.code, "ERR_READ_ONLY_REPOSITORY_CHANGED");
  assert.equal(result.pipelineState.draft, null);
  assert.equal(result.pipelineState.reviewApproved, false);
  assert.equal(fixture.calls.reviewer.length, 1);
});

test("pauses when an agent changes ignored clarifications", async (t) => {
  let mutated = false;
  const fixture = await createFixture(t, {
    async onRoleRun(role) {
      if (role === "planner" && !mutated) {
        mutated = true;
        await writeFile(fixture.clarificationPath, "unauthorized\n");
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "clarifications_changed");
  assert.equal(fixture.calls.reviewer.length, 0);
});

test("detects task drift before resuming dependent work", async (t) => {
  const fixture = await createFixture(t, {
    planner: [ready(), productDecision()],
  });
  await fixture.run();
  await writeFile(
    fixture.clarificationPath,
    `${await readFile(fixture.clarificationPath, "utf8")}Behavior A.\n`,
  );
  await writeFile(join(fixture.taskPath, "task.md"), "Changed task.\n");

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "input_changed");
  assert.equal(result.pipelineState.draft, null);
});

test("fails when the required task is missing before preflight", async (t) => {
  let preflights = 0;
  const fixture = await createFixture(t, {
    onPreflight() {
      preflights += 1;
    },
    reviewer: [],
  });
  await rm(join(fixture.taskPath, "task.md"));

  await assert.rejects(fixture.run(), (error) => error.code === "ENOENT");

  assert.equal(preflights, 0);
  await assert.rejects(readFile(fixture.clarificationPath, "utf8"), /ENOENT/u);
  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
  assert.equal(fixture.currentRun.pause.reason, "internal_failure");
});

test("does not mask unexpected input reader failures as drift", async (t) => {
  let reads = 0;
  const fixture = await createFixture(t, {
    async onReadInputs(taskPath) {
      reads += 1;
      if (reads > 1) {
        const error = new Error("Input reader failed.");
        error.code = "EIO";
        error.path = join(taskPath, "task.md");
        throw error;
      }
    },
    reviewer: [],
  });

  await assert.rejects(fixture.run(), /Input reader failed/u);

  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
  assert.equal(fixture.currentRun.pause.reason, "internal_failure");
});

test("does not mask unexpected clarification reader failures as drift", async (t) => {
  let reads = 0;
  const fixture = await createFixture(t, {
    onInspectTranscript(transcriptPath) {
      reads += 1;
      if (reads > 1) {
        const error = new Error("Clarification reader failed.");
        error.code = "ERR_CLARIFICATION_READ";
        error.cause = { code: "EIO", path: transcriptPath };
        throw error;
      }
    },
    reviewer: [],
  });

  await assert.rejects(fixture.run(), /Clarification reader failed/u);

  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
  assert.equal(fixture.currentRun.pause.reason, "internal_failure");
});

test("treats a deleted task as input drift", async (t) => {
  const fixture = await createFixture(t, {
    planner: [ready(), productDecision()],
  });
  await fixture.run();
  await writeFile(
    fixture.clarificationPath,
    `${await readFile(fixture.clarificationPath, "utf8")}Behavior A.\n`,
  );
  await rm(join(fixture.taskPath, "task.md"));

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "input_changed");
  assert.equal(result.pipelineState.draft, null);
});

test("treats an unreadable task path as input drift", async (t) => {
  const fixture = await createFixture(t, {
    planner: [ready(), productDecision()],
  });
  await fixture.run();
  await writeFile(
    fixture.clarificationPath,
    `${await readFile(fixture.clarificationPath, "utf8")}Behavior A.\n`,
  );
  await rm(join(fixture.taskPath, "task.md"));
  await mkdir(join(fixture.taskPath, "task.md"));

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "input_changed");
  assert.equal(result.pipelineState.draft, null);
});

test("treats a deleted clarification transcript as input drift", async (t) => {
  const fixture = await createFixture(t, {
    planner: [questions()],
    reviewer: [],
  });
  await fixture.run();
  await rm(fixture.clarificationPath);

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "clarifications_changed");
  assert.equal(result.pipelineState.pendingEdit, null);
});

test("detects repository changes made between turns", async (t) => {
  const fixture = await createFixture(t, {
    planner: [ready(), productDecision(), draft()],
  });
  await fixture.run();
  await writeFile(
    fixture.clarificationPath,
    `${await readFile(fixture.clarificationPath, "utf8")}Behavior A.\n`,
  );
  await writeFile(join(fixture.projectPath, "unexpected.txt"), "mutation\n");

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "read_only_mutation");
  assert.equal(fixture.calls.reviewer.length, 0);
});
