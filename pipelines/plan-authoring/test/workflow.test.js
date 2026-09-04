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
  migratePlanAuthoringStateV1,
  migratePlanAuthoringStateV2,
  planAuthoringPipeline,
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

function checkChanged(plan = REVISED_PLAN) {
  return {
    status: "CHANGED",
    plan,
    question: "",
    options: [],
    whyBlocked: "",
    evidence: [],
  };
}

function checkUnchanged() {
  return {
    status: "UNCHANGED",
    plan: "",
    question: "",
    options: [],
    whyBlocked: "",
    evidence: [],
  };
}

function invalidUnchanged(plan = "provider-native rejected output") {
  return { ...checkUnchanged(), plan };
}

function clean() {
  return {
    status: "CLEAN",
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
    mode = "independent",
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
          assert.match(request.prompt, /Do not delegate/u);
          assert.match(request.recoveryPrompt, /Do not delegate/u);
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
    pipelineStateVersion: 3,
    projectPath,
    taskPath,
    roles: Object.fromEntries(
      (mode === "lazy" ? ["planner"] : ["planner", "reviewer", "arbiter"]).map(
        (role) => [
          role,
          { backend: "codex", model: models[role] ?? null },
        ],
      ),
    ),
    counters: {},
    hashes: {},
    pause: null,
    activeTurn: null,
    sessionLineage: { source: sourceSession, children: [] },
    pipelineState: createPlanAuthoringState({
      proactiveClarification,
      settings: {
        maxRevisionRounds: 15,
        mode,
        stagnationWindowRounds: 3,
      },
    }),
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
      async reconcileInterrupted(snapshot, { allowWorkspaceChanges }) {
        assert.equal(allowWorkspaceChanges, false);
        await this.assertUnchanged(snapshot);
        return gitSnapshot({ allowedPaths: snapshot.allowedPaths });
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
    async startAgentTurn(activeTurn, { pipelineState } = {}) {
      currentRun = {
        ...currentRun,
        ...(pipelineState === undefined ? {} : { pipelineState }),
        activeTurn,
        revision: currentRun.revision + 1,
      };
      transitions.push({ activeTurn, kind: "turn-started", options: {} });
      return currentRun;
    },
    async finishAgentTurn(activeTurn) {
      assert.deepEqual(currentRun.activeTurn, activeTurn);
      currentRun = {
        ...currentRun,
        activeTurn: null,
        revision: currentRun.revision + 1,
      };
      transitions.push({ activeTurn, kind: "turn-finished", options: {} });
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
        mode,
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
    ["planner", "planner", "reviewer"],
  );
  assert.deepEqual(fixture.calls.planner[0].session, {
    id: SOURCE_SESSION,
    mode: "fork",
  });
  assert.deepEqual(fixture.calls.planner[1].session, {
    id: SOURCE_SESSION,
    mode: "fork",
  });
  assert.match(fixture.calls.planner[0].prompt, /Task \(/u);
  assert.equal(
    fixture.calls.planner[0].recoveryPrompt,
    fixture.calls.planner[0].prompt,
  );
  assert.equal(
    fixture.calls.planner[1].recoveryPrompt,
    fixture.calls.planner[1].prompt,
  );
  assert.notEqual(
    result.sessionLineage.children[0].contextKey,
    result.sessionLineage.children[1].contextKey,
  );
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

test("selects lazy Planner-only mode and migrates legacy runs to independent", async (t) => {
  assert.equal(planAuthoringPipeline.stateVersion, 3);
  assert.equal(
    planAuthoringPipeline.resolveActiveRoles(),
    planAuthoringPipeline.roles,
  );
  assert.deepEqual(
    planAuthoringPipeline.resolveActiveRoles({ mode: "independent" }),
    ["planner", "reviewer", "arbiter"],
  );
  assert.deepEqual(planAuthoringPipeline.resolveActiveRoles({ mode: "lazy" }), [
    "planner",
  ]);
  assert.equal(
    planAuthoringPipeline.settings.mode.defaultValue,
    "independent",
  );

  const initial = createPlanAuthoringState({
    settings: {
      maxRevisionRounds: 15,
      mode: "independent",
      stagnationWindowRounds: 3,
    },
  });
  const {
    cleanConfirmationFingerprint: _activeConfirmation,
    lazySourceForkConsumed: _activeSourceFork,
    ...activeState
  } = initial;
  const { mode: _activeMode, ...activeSettings } = activeState.settings;
  const migratedActive = migratePlanAuthoringStateV1({
    pipelineState: { ...activeState, settings: activeSettings },
  });
  assert.equal(migratedActive.workflowState, "CLARIFY");
  assert.equal(migratedActive.settings.mode, "independent");

  const fixture = await createFixture(t);
  const completed = await fixture.run();
  const {
    cleanConfirmationFingerprint: _confirmation,
    lazySourceForkConsumed: _sourceFork,
    ...legacyState
  } = completed.pipelineState;
  const { mode: _mode, ...legacySettings } = legacyState.settings;
  const migrated = migratePlanAuthoringStateV1({
    pipelineState: { ...legacyState, settings: legacySettings },
  });

  assert.equal(migrated.workflowState, "DONE");
  assert.equal(migrated.planPath, completed.pipelineState.planPath);
  assert.equal(migrated.settings.mode, "independent");
  assert.equal(migrated.cleanConfirmationFingerprint, null);

  const {
    lazyCorrections: _lazyCorrections,
    pendingLazyCorrection: _pendingLazyCorrection,
    ...versionTwoState
  } = completed.pipelineState;
  const migratedVersionTwo = migratePlanAuthoringStateV2({
    pipelineState: versionTwoState,
  });
  assert.equal(migratedVersionTwo.workflowState, "DONE");
  assert.equal(migratedVersionTwo.planPath, completed.pipelineState.planPath);
  assert.deepEqual(migratedVersionTwo.lazyCorrections, []);
  assert.equal(migratedVersionTwo.pendingLazyCorrection, null);
});

test("converges a lazy plan with one source fork and no review roles", async (t) => {
  const fixture = await createFixture(t, {
    mode: "lazy",
    planner: [
      ready(),
      draft(),
      checkChanged(),
      checkUnchanged(),
      clean(),
    ],
    reviewer: [],
    arbiter: [],
    sourceSession: SOURCE_SESSION,
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(await readFile(fixture.planPath, "utf8"), REVISED_PLAN);
  assert.deepEqual(Object.keys(result.roles), ["planner"]);
  assert.equal(fixture.calls.reviewer.length, 0);
  assert.equal(fixture.calls.arbiter.length, 0);
  assert.equal(
    fixture.calls.planner.filter(({ session }) => session?.mode === "fork")
      .length,
    1,
  );
  assert.deepEqual(fixture.calls.planner[0].session, {
    id: SOURCE_SESSION,
    mode: "fork",
  });
  assert.ok(
    fixture.calls.planner
      .slice(1)
      .every(({ session }) => ["continue", undefined].includes(session?.mode)),
  );
  assert.match(
    fixture.calls.planner[0].prompt,
    /\.agents.*unless the user's task explicitly requires them.*not a user question/u,
  );
  const compactCall = fixture.calls.planner.find(
    ({ prompt, recoveryPrompt }) => prompt !== recoveryPrompt,
  );
  assert.ok(compactCall);
  assert.doesNotMatch(compactCall.prompt, /\.agents/u);
  assert.match(
    compactCall.recoveryPrompt,
    /\.agents.*unless the user's task explicitly requires them.*not a user question/u,
  );
  assert.match(
    fixture.calls.planner[2].prompt,
    /If you find any problems, fix the plan idiomatically and minimally/u,
  );
  assert.match(fixture.calls.planner[3].prompt, /Plan to check and fix/u);
  assert.match(fixture.calls.planner[4].prompt, /Return CLEAN only/u);
  assert.equal(result.counters.revisionRounds, 2);
  assert.equal(result.counters.correctionRounds, 0);
  assert.equal(
    result.pipelineState.cleanConfirmationFingerprint,
    result.pipelineState.draftFingerprint,
  );
  assert.equal(result.pipelineState.lazySourceForkConsumed, true);
});

test("routes lazy confirmation findings back through fixing", async (t) => {
  const fixture = await createFixture(t, {
    mode: "lazy",
    planner: [
      ready(),
      draft(),
      checkUnchanged(),
      findings("missing-detail"),
      checkChanged(),
      checkUnchanged(),
      clean(),
    ],
    reviewer: [],
    arbiter: [],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(await readFile(fixture.planPath, "utf8"), REVISED_PLAN);
  assert.equal(result.counters.revisionRounds, 3);
  assert.equal(result.counters.correctionRounds, 1);
  assert.equal(fixture.calls.reviewer.length, 0);
  assert.equal(fixture.calls.arbiter.length, 0);
  assert.match(
    fixture.calls.planner[4].prompt,
    /missing-detail/u,
  );
});

test("corrects a provider-rejected lazy checkpoint in one fresh read-only session", async (t) => {
  let rejected = false;
  const fixture = await createFixture(t, {
    mode: "lazy",
    planner: [ready(), draft(), checkChanged(), checkUnchanged(), clean()],
    reviewer: [],
    arbiter: [],
    sourceSession: SOURCE_SESSION,
    onRoleRun(role, _request, callNumber) {
      if (role === "planner" && callNumber === 3 && !rejected) {
        rejected = true;
        const error = new Error("provider-native structured-output secret");
        error.code = "ERR_PROVIDER_STRUCTURED_OUTPUT";
        error.failureClass = "structured-output";
        throw error;
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.revisionRounds, 2);
  assert.equal(result.pipelineState.lazyCorrections.length, 1);
  assert.equal(result.pipelineState.pendingLazyCorrection, null);
  assert.deepEqual(result.pipelineState.lazyCorrections[0].diagnostics, [
    {
      role: "planner",
      phase: "check-and-fix",
      contract: "lazy-check-and-fix",
      field: "result",
      constraint: "provider-structured-output",
    },
  ]);
  const correctionRequest = fixture.calls.planner[3];
  assert.equal(correctionRequest.access, "read-only");
  assert.equal(correctionRequest.session, undefined);
  assert.equal(correctionRequest.schema, fixture.calls.planner[2].schema);
  assert.match(correctionRequest.prompt, /Pending correction diagnostic batch/u);
  assert.match(correctionRequest.prompt, /Plan to check and fix:\n## Commit 1/u);
  assert.equal(await readFile(fixture.planPath, "utf8"), REVISED_PLAN);
  assert.doesNotMatch(
    JSON.stringify({
      state: result.pipelineState,
      transitions: fixture.transitions,
    }),
    /provider-native structured-output secret/u,
  );
});

test("pauses after one invalid lazy correction and resumes the exact checkpoint", async (t) => {
  const fixture = await createFixture(t, {
    mode: "lazy",
    planner: [
      ready(),
      draft(),
      invalidUnchanged("provider-native first rejected output"),
      invalidUnchanged("provider-native second rejected output"),
      checkUnchanged(),
      clean(),
    ],
    reviewer: [],
    arbiter: [],
  });

  const paused = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "lazy_output_invalid");
  assert.equal(paused.pause.resumeState, "CHECK_AND_FIX");
  assert.equal(paused.counters.revisionRounds, 0);
  assert.equal(paused.counters.correctionRounds, 0);
  assert.equal(paused.pipelineState.lazyCorrections.length, 1);
  assert.notEqual(paused.pipelineState.pendingLazyCorrection, null);
  await assert.rejects(readFile(fixture.planPath, "utf8"), /ENOENT/u);
  const projected = planAuthoringPipeline.projections.pause(paused);
  assert.deepEqual(projected.nextActions, [{ type: "resume", action: null }]);
  assert.equal(projected.resumeState, "CHECK_AND_FIX");
  assert.deepEqual(projected.evidence, [
    "Planner field plan violated empty-for-unchanged.",
  ]);
  assert.doesNotMatch(JSON.stringify(paused), /provider-native/u);
  const {
    lazyCorrections: _lazyCorrections,
    pendingLazyCorrection: _pendingLazyCorrection,
    ...versionTwoState
  } = paused.pipelineState;
  const migrated = migratePlanAuthoringStateV2({
    pipelineState: versionTwoState,
  });
  assert.equal(migrated.workflowState, "WAITING_FOR_USER");
  assert.equal(migrated.draft, PLAN);

  const acceptedPause = fixture.currentRun.pause;
  fixture.currentRun.pause = {
    ...acceptedPause,
    evidence: ["provider-native secret"],
  };
  assert.doesNotMatch(
    JSON.stringify(planAuthoringPipeline.projections.pause(fixture.currentRun)),
    /provider-native/u,
  );
  await assert.rejects(fixture.run(), /lazy output pause is invalid/u);
  fixture.currentRun.pause = acceptedPause;

  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.counters.revisionRounds, 1);
  assert.equal(completed.counters.correctionRounds, 0);
  assert.equal(completed.pipelineState.lazyCorrections.length, 1);
  assert.equal(fixture.calls.planner[4].session, undefined);
});

test("rejects pending lazy correction scope after draft fingerprint drift", async (t) => {
  const fixture = await createFixture(t, {
    mode: "lazy",
    planner: [ready(), draft(), invalidUnchanged(), invalidUnchanged()],
    reviewer: [],
    arbiter: [],
  });
  await fixture.run();
  fixture.currentRun.pipelineState = {
    ...fixture.currentRun.pipelineState,
    draft: REVISED_PLAN,
    draftFingerprint: hash(REVISED_PLAN),
  };

  await assert.rejects(fixture.run(), /pending lazy correction is inconsistent/u);
  await assert.rejects(readFile(fixture.planPath, "utf8"), /ENOENT/u);
});

test("preserves a pending lazy correction across backend interruption", async (t) => {
  let interrupted = false;
  const fixture = await createFixture(t, {
    mode: "lazy",
    planner: [ready(), draft(), invalidUnchanged(), checkUnchanged(), clean()],
    reviewer: [],
    arbiter: [],
    onRoleRun(role, request) {
      if (
        role === "planner" &&
        request.prompt.includes("Pending correction diagnostic batch") &&
        !interrupted
      ) {
        interrupted = true;
        const error = new Error("provider-native interruption secret");
        error.code = "ERR_TEST_INTERRUPTED";
        error.recoverable = true;
        throw error;
      }
    },
  });

  const paused = await fixture.run();

  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pause.resumeState, "CHECK_AND_FIX");
  assert.notEqual(paused.pipelineState.pendingLazyCorrection, null);
  assert.equal(paused.counters.revisionRounds, 0);
  assert.doesNotMatch(JSON.stringify(paused), /interruption secret/u);
  Object.assign(fixture.currentRun, {
    activeTurn: { role: "planner", phase: "check-and-fix" },
    pause: null,
    pipelineState: {
      ...paused.pipelineState,
      workflowState: "CHECK_AND_FIX",
    },
  });

  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.counters.revisionRounds, 1);
  assert.equal(completed.pipelineState.pendingLazyCorrection, null);
  assert.equal(fixture.calls.planner[4].session, undefined);
});

test("accepts findings only after invalid clean confirmation is corrected", async (t) => {
  const rejected = {
    ...clean(),
    findings: [
      {
        id: "provider-native-secret",
        description: "provider-native rejected finding",
        evidence: ["provider-native rejected evidence"],
      },
    ],
  };
  const fixture = await createFixture(t, {
    mode: "lazy",
    planner: [
      ready(),
      draft(),
      checkUnchanged(),
      rejected,
      findings("after-correction"),
      checkChanged(),
      checkUnchanged(),
      clean(),
    ],
    reviewer: [],
    arbiter: [],
  });

  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.pipelineState.lazyCorrections.length, 1);
  assert.equal(completed.pipelineState.lazyCorrections[0].phase, "CLEAN_CONFIRM");
  assert.equal(completed.counters.revisionRounds, 3);
  assert.equal(completed.counters.correctionRounds, 1);
  assert.equal(fixture.calls.planner[4].session, undefined);
  assert.match(fixture.calls.planner[5].prompt, /after-correction/u);
  assert.doesNotMatch(
    JSON.stringify(completed.pipelineState),
    /provider-native/u,
  );
});

test("invalidates a pending correction after read-only repository mutation", async (t) => {
  let mutated = false;
  const fixture = await createFixture(t, {
    mode: "lazy",
    planner: [ready(), draft(), invalidUnchanged(), checkUnchanged()],
    reviewer: [],
    arbiter: [],
    async onRoleRun(role, request) {
      if (
        role === "planner" &&
        request.prompt.includes("Pending correction diagnostic batch") &&
        !mutated
      ) {
        mutated = true;
        await writeFile(join(fixture.projectPath, "contamination.txt"), "bad\n");
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pause.reason, "read_only_mutation");
  assert.equal(result.pipelineState.draft, null);
  assert.deepEqual(result.pipelineState.lazyCorrections, []);
  assert.equal(result.pipelineState.pendingLazyCorrection, null);
  assert.equal(result.counters.revisionRounds, 0);
  await assert.rejects(readFile(fixture.planPath, "utf8"), /ENOENT/u);
});

test("does not refork a lazy source after an interrupted first turn", async (t) => {
  let interrupt = true;
  const fixture = await createFixture(t, {
    mode: "lazy",
    planner: [ready(), draft(), checkUnchanged(), clean()],
    reviewer: [],
    arbiter: [],
    sourceSession: SOURCE_SESSION,
    onRoleRun(role) {
      if (role === "planner" && interrupt) {
        interrupt = false;
        const error = new Error("Provider interrupted.");
        error.code = "ERR_TEST_INTERRUPTED";
        error.recoverable = true;
        throw error;
      }
    },
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pipelineState.lazySourceForkConsumed, true);
  assert.deepEqual(paused.sessionLineage.children, []);

  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(
    fixture.calls.planner.filter(({ session }) => session?.mode === "fork")
      .length,
    1,
  );
  assert.equal(fixture.calls.planner[1].session, undefined);
  assert.deepEqual(
    completed.sessionLineage.children.map(({ role }) => role),
    ["planner"],
  );
});

for (const checkpoint of ["check-and-fix", "clean-confirm"]) {
  test(`reconstructs an interrupted lazy ${checkpoint} without recounting`, async (t) => {
    let interrupted = false;
    const targetCall = checkpoint === "check-and-fix" ? 3 : 4;
    const fixture = await createFixture(t, {
      mode: "lazy",
      planner: [ready(), draft(), checkUnchanged(), clean()],
      reviewer: [],
      arbiter: [],
      sourceSession: SOURCE_SESSION,
      onRoleRun(role, _request, callNumber) {
        if (role === "planner" && callNumber === targetCall && !interrupted) {
          interrupted = true;
          const error = new Error("Provider interrupted.");
          error.code = "ERR_TEST_INTERRUPTED";
          error.recoverable = true;
          throw error;
        }
      },
    });

    const paused = await fixture.run();
    const workflowState =
      checkpoint === "check-and-fix" ? "CHECK_AND_FIX" : "CLEAN_CONFIRM";
    assert.equal(paused.pause.reason, "backend_unavailable");
    assert.equal(paused.pause.resumeState, workflowState);
    Object.assign(fixture.currentRun, {
      activeTurn: { role: "planner", phase: checkpoint },
      pause: null,
      pipelineState: { ...paused.pipelineState, workflowState },
    });

    const completed = await fixture.run();

    assert.equal(completed.pipelineState.workflowState, "DONE");
    assert.equal(completed.counters.revisionRounds, 1);
    assert.equal(
      fixture.calls.planner.filter(({ session }) => session?.mode === "fork")
        .length,
      1,
    );
    assert.equal(fixture.calls.planner[targetCall].session, undefined);
  });
}

test("rejects repository mutation during lazy clean confirmation", async (t) => {
  let mutated = false;
  const fixture = await createFixture(t, {
    mode: "lazy",
    planner: [ready(), draft(), checkUnchanged(), clean()],
    reviewer: [],
    arbiter: [],
    async onRoleRun(role, request) {
      if (
        role === "planner" &&
        request.prompt.includes("Return CLEAN only") &&
        !mutated
      ) {
        mutated = true;
        await writeFile(join(fixture.projectPath, "contamination.txt"), "bad\n");
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "read_only_mutation");
  assert.equal(result.pipelineState.cleanConfirmationFingerprint, null);
  await assert.rejects(readFile(fixture.planPath, "utf8"), /ENOENT/u);
});

test("rejects lazy clean evidence for a different draft fingerprint", async (t) => {
  const fixture = await createFixture(t, {
    mode: "lazy",
    planner: [ready(), draft(), checkUnchanged(), clean()],
    reviewer: [],
    arbiter: [],
  });
  const completed = await fixture.run();
  fixture.currentRun.pipelineState = {
    ...completed.pipelineState,
    cleanConfirmationFingerprint: "0".repeat(64),
  };

  await assert.rejects(
    fixture.run(),
    /clean confirmation fingerprint is not applicable/u,
  );
});

test("bounds lazy confirmation findings without invoking an Arbiter", async (t) => {
  const fixture = await createFixture(t, {
    mode: "lazy",
    planner: [
      ready(),
      draft(),
      checkUnchanged(),
      findings("still-blocked"),
    ],
    reviewer: [],
    arbiter: [],
  });

  const result = await fixture.run({ stagnationWindowRounds: 1 });

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "plan_revision_not_converging");
  assert.equal(result.counters.revisionRounds, 1);
  assert.equal(result.counters.correctionRounds, 1);
  assert.equal(fixture.calls.reviewer.length, 0);
  assert.equal(fixture.calls.arbiter.length, 0);
});

test("reconstructs an interrupted read-only turn in a fresh session", async (t) => {
  let interrupt = true;
  const fixture = await createFixture(t, {
    onRoleRun(role) {
      if (role === "reviewer" && interrupt) {
        interrupt = false;
        const error = new Error("Provider interrupted.");
        error.code = "ERR_TEST_INTERRUPTED";
        error.recoverable = true;
        throw error;
      }
    },
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "backend_unavailable");
  Object.assign(fixture.currentRun, {
    activeTurn: { role: "reviewer", phase: "review" },
    pause: null,
    pipelineState: {
      ...paused.pipelineState,
      workflowState: "REVIEW",
    },
  });

  const completed = await fixture.run();
  const recoveredRequest = fixture.calls.reviewer.at(-1);
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.activeTurn, null);
  assert.equal(recoveredRequest.session, undefined);
  assert.equal(recoveredRequest.prompt, recoveredRequest.recoveryPrompt);
  assert.match(recoveredRequest.prompt, /Task \(/u);
});

test("rejects repository mutation before replaying an interrupted read-only turn", async (t) => {
  let interrupt = true;
  const fixture = await createFixture(t, {
    onRoleRun(role) {
      if (role === "reviewer" && interrupt) {
        interrupt = false;
        const error = new Error("Provider interrupted.");
        error.recoverable = true;
        throw error;
      }
    },
  });
  const paused = await fixture.run();
  Object.assign(fixture.currentRun, {
    activeTurn: { role: "reviewer", phase: "review" },
    pause: null,
    pipelineState: { ...paused.pipelineState, workflowState: "REVIEW" },
  });
  await writeFile(join(fixture.projectPath, "unexpected.txt"), "mutation\n");
  const reviewerCalls = fixture.calls.reviewer.length;

  const rejected = await fixture.run();
  assert.equal(rejected.pause.reason, "read_only_mutation");
  assert.deepEqual(rejected.activeTurn, {
    role: "reviewer",
    phase: "review",
  });
  assert.equal(fixture.calls.reviewer.length, reviewerCalls);
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
  assert.deepEqual(fixture.calls.planner[2].session, {
    id: fixture.currentRun.sessionLineage.children[1].sessionId,
    mode: "continue",
  });
  for (const heading of [/Task \(/u, /Context \(/u, /Clarifications \(/u]) {
    assert.doesNotMatch(fixture.calls.planner[2].prompt, heading);
    assert.match(fixture.calls.planner[2].recoveryPrompt, heading);
  }
});

test("lazy validation failures require another fix and clean confirmation", async (t) => {
  const fixture = await createFixture(t, {
    mode: "lazy",
    planner: [
      ready(),
      draft("not a plan"),
      checkUnchanged(),
      clean(),
      checkChanged(),
      checkUnchanged(),
      clean(),
    ],
    reviewer: [],
    arbiter: [],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.match(fixture.calls.planner[4].prompt, /must contain at least one/u);
  assert.equal(result.counters.correctionRounds, 1);
  assert.equal(
    fixture.calls.planner.filter(({ prompt }) =>
      prompt.includes("Return CLEAN only"),
    ).length,
    2,
  );
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
  assert.equal(fixture.calls.planner[2].session, undefined);
  assert.equal(
    fixture.calls.planner[2].prompt,
    fixture.calls.planner[2].recoveryPrompt,
  );
  const planningKeys = completed.sessionLineage.children
    .filter(({ role }) => role === "planner")
    .slice(-2)
    .map(({ contextKey }) => contextKey);
  assert.notEqual(planningKeys[0], planningKeys[1]);
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

test("restarts the Arbiter after an interrupted result transition", async (t) => {
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
  assert.equal(fixture.calls.arbiter[1].session, undefined);
  assert.notEqual(
    result.sessionLineage.children.at(-2).sessionId,
    result.sessionLineage.children.at(-1).sessionId,
  );
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
    mode: "independent",
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

test("reconstructs an allowlisted failed Claude read-only turn", async (t) => {
  let unavailable = true;
  const fixture = await createFixture(t, {
    onRoleRun(role) {
      if (role === "reviewer" && unavailable) {
        unavailable = false;
        const error = new Error("provider-native secret text");
        error.code = "ERR_CLAUDE_READ_ONLY_TURN_FAILED";
        error.recoverable = true;
        throw error;
      }
    },
  });

  const paused = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pause.code, "ERR_CLAUDE_READ_ONLY_TURN_FAILED");
  assert.equal(paused.pause.resumeState, "REVIEW");
  assert.notEqual(paused.pipelineState.draft, null);
  assert.doesNotMatch(JSON.stringify(fixture.transitions), /provider-native/u);

  const completed = await fixture.run();
  const resumedRequest = fixture.calls.reviewer.at(-1);

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(resumedRequest.session, undefined);
  assert.equal(resumedRequest.prompt, resumedRequest.recoveryPrompt);
});

test("keeps Claude authentication terminal for a read-only turn", async (t) => {
  const fixture = await createFixture(t, {
    onRoleRun(role) {
      if (role === "planner") {
        const error = new Error("provider-native authentication secret");
        error.code = "ERR_CLAUDE_AUTHENTICATION_UNAVAILABLE";
        throw error;
      }
    },
    reviewer: [],
  });

  await assert.rejects(
    fixture.run(),
    (error) => error.code === "ERR_CLAUDE_AUTHENTICATION_UNAVAILABLE",
  );

  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
  assert.equal(fixture.currentRun.pause.reason, "internal_failure");
  assert.equal(
    fixture.currentRun.pause.code,
    "ERR_CLAUDE_AUTHENTICATION_UNAVAILABLE",
  );
  assert.doesNotMatch(
    JSON.stringify(fixture.transitions),
    /authentication secret/u,
  );
});

test("persists a forbidden-delegation diagnostic without provider data", async (t) => {
  const sensitiveMarker = "DO_NOT_PERSIST_DELEGATED_TURN_DATA";
  const fixture = await createFixture(t, {
    onRoleRun(role) {
      if (role === "planner") {
        const error = new Error(sensitiveMarker);
        error.code = "ERR_CODEX_ISOLATION";
        error.diagnosticClass = "operation_multi_agent";
        error.subAgentActivity = sensitiveMarker;
        error.transcript = sensitiveMarker;
        throw error;
      }
    },
    reviewer: [],
  });

  await assert.rejects(
    fixture.run(),
    (error) => error.code === "ERR_CODEX_ISOLATION",
  );

  assert.deepEqual(fixture.currentRun.pause, {
    reason: "internal_failure",
    code: "ERR_CODEX_ISOLATION",
    diagnosticClass: "operation_multi_agent",
  });
  assert.doesNotMatch(JSON.stringify(fixture.transitions), /DO_NOT_PERSIST/u);
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
