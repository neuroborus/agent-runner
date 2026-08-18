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
import { dirname, isAbsolute, join, relative } from "node:path";
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

function implementationCompleted() {
  return {
    status: "COMPLETED",
    summary: "Implemented and self-reviewed the planned change.",
    reason: "",
    ...emptyDecision(),
  };
}

function implementationBlocked() {
  return {
    status: "BLOCKED",
    summary: "",
    reason: "A required local service is temporarily unavailable.",
    question: "",
    options: [],
    whyBlocked: "",
    evidence: ["The local service health check failed."],
  };
}

function finalizationPassed() {
  return {
    status: "PASS",
    skillPath: ".agents/skills/finalization/SKILL.md",
    summary: "The repository finalization procedure passed.",
    issues: [],
    reason: "",
    ...emptyDecision(),
  };
}

function reviewApproved() {
  return {
    status: "APPROVED",
    findings: [],
    ...emptyDecision(),
  };
}

function implementationProductDecision() {
  return {
    status: "PRODUCT_DECISION_REQUIRED",
    summary: "",
    reason: "",
    question: "Which public behavior should the implementation expose?",
    options: ["Behavior A", "Behavior B"],
    whyBlocked: "Both behaviors are valid but incompatible.",
    evidence: ["The validated inputs do not choose one."],
  };
}

function finalizationFailed(...ids) {
  return {
    status: "FAIL",
    skillPath: ".agents/skills/finalization/SKILL.md",
    summary: "The repository finalization procedure found blocking failures.",
    issues: ids.map((id) => ({
      id,
      command: "npm test",
      problem: `Validation failed for ${id}.`,
      evidence: [`${id} failed in the test output.`],
    })),
    reason: "",
    ...emptyDecision(),
  };
}

function finalizationUnavailable(status) {
  return {
    status,
    skillPath:
      status === "SKILL_MISSING"
        ? ""
        : ".agents/skills/finalization/SKILL.md",
    summary: "",
    issues: [],
    reason: "The finalization skill cannot be used safely.",
    question: "",
    options: [],
    whyBlocked: "",
    evidence: ["The repository instructions do not provide a valid procedure."],
  };
}

function reviewFindings(...ids) {
  return {
    status: "FINDINGS",
    findings: ids.map((id) => ({
      id,
      file: "source.js",
      problem: `Problem ${id} remains.`,
      reason: `The current implementation still exhibits ${id}.`,
      suggestedAction: `Fix ${id}.`,
    })),
    ...emptyDecision(),
  };
}

function reviewProductDecision() {
  return {
    status: "PRODUCT_DECISION_REQUIRED",
    findings: [],
    question: "Which public behavior should the review require?",
    options: ["Behavior A", "Behavior B"],
    whyBlocked: "Both behaviors are valid but incompatible.",
    evidence: ["The validated inputs do not select either behavior."],
  };
}

function resolution(...decisions) {
  return {
    status: "RESOLVED",
    decisions: decisions.map(({ decision, id }) => ({
      id,
      decision,
      reason:
        decision === "FIX"
          ? `Applied the correction for ${id}.`
          : `The implementation already satisfies ${id}.`,
      evidence:
        decision === "FIX" ? [] : [`source.js demonstrates why ${id} is invalid.`],
    })),
    ...emptyDecision(),
  };
}

function reconsideration(direction, ...ids) {
  return {
    status: "RESOLVED",
    decisions: ids.map((id) => ({
      id,
      direction,
      reason: `${direction} is supported for ${id}.`,
      evidence: [`The current repository evidence supports ${direction}.`],
    })),
    ...emptyDecision(),
  };
}

function reconsiderationProductDecision() {
  return {
    status: "PRODUCT_DECISION_REQUIRED",
    decisions: [],
    question: "Which public behavior should resolve the disputed finding?",
    options: ["Behavior A", "Behavior B"],
    whyBlocked: "Both interpretations remain valid and incompatible.",
    evidence: ["The plan and repository do not resolve the dispute."],
  };
}

function findingArbitration(direction) {
  return {
    direction,
    rationale: `Repository evidence supports ${direction}.`,
    ...emptyDecision(),
  };
}

function stagnation(direction, findingIds = []) {
  return {
    direction,
    rationale: `The minimal next direction is ${direction}.`,
    findingIds,
    reason: "",
    ...emptyDecision(),
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

function createClarificationService({
  interactive = false,
  onEdit,
  onFreeze,
} = {}) {
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
      return (await onFreeze?.(snapshot)) ?? snapshot;
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
    onFreeze,
    onCommitRun,
    onCommitVerify,
    onRoleRun,
    onTransition,
    plan = PLAN,
    proactiveClarification = false,
    reviewer = [bootstrapReady("Reviewer")],
    sessionIds = ROLE_SESSIONS,
    sourceSession = null,
    workReviewer = [reviewApproved()],
    workWorker = [implementationCompleted(), finalizationPassed()],
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
    worker: [...worker, ...workWorker],
    reviewer: [...reviewer, ...workReviewer],
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
          if (request.access === "local-commit") {
            if (onCommitRun === undefined) {
              await executeFile("git", ["-C", projectPath, "add", "-A"]);
              await executeFile("git", [
                "-C",
                projectPath,
                "commit",
                "-qm",
                request.commit.message,
              ]);
            } else {
              await onCommitRun(request);
            }
            return {
              output: "committed",
              sessionId: request.session?.id ?? nextFreshSessionId(role),
            };
          }
          assert.ok(queues[role].length > 0, `Unexpected ${role} turn.`);
          const structured = queues[role].shift();
          if (
            role === "worker" &&
            structured.status === "COMPLETED" &&
            request.prompt.includes("Implement the changes")
          ) {
            const step =
              /Current planned commit:\n## Commit ([1-9][0-9]*):/u.exec(
                request.prompt,
              )?.[1];
            assert.notEqual(step, undefined);
            await writeFile(
              join(projectPath, `implementation-${step}.txt`),
              `implemented step ${step}\n`,
            );
          }
          return {
            output: "structured",
            structured,
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
    const [head, branch, refs, status, index, remotes, identity] = await Promise.all([
      executeFile("git", ["-C", projectPath, "rev-parse", "HEAD"]),
      executeFile("git", ["-C", projectPath, "rev-parse", "--abbrev-ref", "HEAD"]),
      executeFile("git", ["-C", projectPath, "for-each-ref"]),
      executeFile("git", [
        "-C",
        projectPath,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
      ]),
      executeFile("git", ["-C", projectPath, "diff", "--cached", "--binary"]),
      executeFile("git", ["-C", projectPath, "config", "--get-regexp", "^(remote|url)\\."]).catch(
        () => ({ stdout: "" }),
      ),
      executeFile("git", [
        "-C",
        projectPath,
        "config",
        "--get-regexp",
        "^user\\.(name|email)$",
      ]),
    ]);
    const content = await repositoryFingerprint(projectPath);
    const normalizedAllowedPaths = allowedPaths
      .map((path) => (isAbsolute(path) ? relative(projectPath, path) : path))
      .sort();
    const snapshot = {
      schemaVersion: 1,
      projectPath,
      allowedPaths: normalizedAllowedPaths,
      head: head.stdout.trim(),
      branch: branch.stdout.trim() === "HEAD" ? null : `refs/heads/${branch.stdout.trim()}`,
      detached: branch.stdout.trim() === "HEAD",
      clean: status.stdout.trim().length === 0,
      refsFingerprint: hash(refs.stdout),
      trackedContentFingerprint: content,
      untrackedContentFingerprint: hash(status.stdout),
      contentFingerprint: content,
      indexFingerprint: hash(index.stdout),
      remoteConfigurationFingerprint: hash(remotes.stdout),
      identityAvailable: true,
      identityFingerprint: hash(identity.stdout),
    };
    return {
      ...snapshot,
      fingerprint: hash(JSON.stringify(snapshot)),
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
  let commitAuthorizationIndex = 0;
  const runtime = {
    adapters,
    clarifications: createClarificationService({
      interactive,
      onEdit,
      onFreeze,
    }),
    git: {
      async prepareCommit({ expectedSnapshot, subject, persistPendingCommit }) {
        const authorization = Object.freeze({
          schemaVersion: 1,
          id: `commit-${++commitAuthorizationIndex}`,
          projectPath,
          expectedHead: expectedSnapshot.head,
          expectedBranch: expectedSnapshot.branch,
          expectedRefsFingerprint: expectedSnapshot.refsFingerprint,
          expectedOtherRefsFingerprint: expectedSnapshot.refsFingerprint,
          expectedContentFingerprint: expectedSnapshot.contentFingerprint,
          expectedIndexFingerprint: expectedSnapshot.indexFingerprint,
          expectedRemoteConfigurationFingerprint:
            expectedSnapshot.remoteConfigurationFingerprint,
          expectedIdentityFingerprint: expectedSnapshot.identityFingerprint,
          expectedAuthorIdentityFingerprint: hash("author"),
          expectedCommitterIdentityFingerprint: hash("committer"),
          subject,
        });
        const current = await gitSnapshot({
          allowedPaths: expectedSnapshot.allowedPaths,
        });
        if (current.fingerprint !== expectedSnapshot.fingerprint) {
          const error = new Error("Commit gate changed.");
          error.code = "ERR_COMMIT_GATE_CHANGED";
          throw error;
        }
        await persistPendingCommit(authorization);
        return authorization;
      },
      async consumeCommit(authorization, { consumePendingCommit }) {
        await consumePendingCommit();
        return Object.freeze({
          authorizationId: authorization.id,
          cwd: authorization.projectPath,
          access: "local-commit",
          commit: Object.freeze({
            expectedHead: authorization.expectedHead,
            message: authorization.subject,
          }),
        });
      },
      async verifyCommit(authorization) {
        await onCommitVerify?.(authorization);
        const snapshot = await gitSnapshot();
        if (snapshot.head === authorization.expectedHead) {
          const error = new Error("Authorized commit was not created.");
          error.code = "ERR_COMMIT_NOT_CREATED";
          throw error;
        }
        const [{ stdout: parents }, { stdout: message }] = await Promise.all([
          executeFile("git", [
            "-C",
            projectPath,
            "show",
            "-s",
            "--format=%P",
            snapshot.head,
          ]),
          executeFile("git", [
            "-C",
            projectPath,
            "show",
            "-s",
            "--format=%B",
            snapshot.head,
          ]),
        ]);
        const changes = [];
        if (parents.trim() !== authorization.expectedHead) {
          changes.push("parent");
        }
        if (message.trimEnd() !== authorization.subject) {
          changes.push("message");
        }
        if (/(?:^|\n)co-authored-by[ \t]*:/iu.test(message)) {
          changes.push("co-author");
        }
        if (!snapshot.clean) {
          changes.push("worktree-or-index");
        }
        if (
          (await repositoryFingerprint(projectPath)) !==
          authorization.expectedContentFingerprint
        ) {
          changes.push("content");
        }
        if (changes.length > 0) {
          const error = new Error("Authorized commit violates its contract.");
          error.code = "ERR_COMMIT_CONTRACT_VIOLATED";
          error.changes = changes;
          throw error;
        }
        return Object.freeze({
          authorizationId: authorization.id,
          head: snapshot.head,
          subject: authorization.subject,
          contentFingerprint: authorization.expectedContentFingerprint,
        });
      },
      async contentFingerprint() {
        return repositoryFingerprint(projectPath);
      },
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
        const current = await gitSnapshot({ allowedPaths: snapshot.allowedPaths });
        if (snapshot.fingerprint !== current.fingerprint) {
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

  async function run(settings = {}, action) {
    currentRun = await runPlanExecution({
      action,
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

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.currentStep, null);
  assert.equal(result.pipelineState.completedCommits.length, 1);
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
    assertStrictSchema(call.schema);
  }
  for (const call of fixture.calls.worker.slice(0, 3)) {
    assert.equal(call.access, "read-only");
  }
  for (const call of fixture.calls.worker.filter(
    ({ access }) => access !== "local-commit",
  ).slice(3)) {
    assert.equal(call.access, "workspace-write");
  }
  assert.equal(fixture.calls.worker.at(-1).access, "local-commit");
  for (const call of fixture.calls.reviewer) {
    assert.equal(call.access, "read-only");
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

  assert.equal(result.pipelineState.workflowState, "DONE");
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

  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.equal(resumed.pipelineState.pendingEdit, null);
  assert.equal(resumed.pipelineState.clarificationFrozen, true);
});

test("retries a temporarily unavailable clarification Worker", async (t) => {
  let interruptClarification = true;
  const fixture = await createFixture(t, {
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("Study the task, validated plan") &&
        interruptClarification
      ) {
        interruptClarification = false;
        const error = new Error("Codex turn was interrupted.");
        error.code = "ERR_CODEX_TURN_INTERRUPTED";
        error.recoverable = true;
        throw error;
      }
    },
  });

  const paused = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pause.code, "ERR_CODEX_TURN_INTERRUPTED");
  assert.equal(paused.pause.resumeState, "CLARIFY");

  const resumed = await fixture.run();

  assert.equal(resumed.pipelineState.workflowState, "DONE");
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

test("validates the next pipeline state before persisting it", async (t) => {
  const invalidHash = "invalid-hash";
  const fixture = await createFixture(t, {
    onFreeze(snapshot) {
      return { ...snapshot, hash: invalidHash };
    },
  });

  await assert.rejects(
    fixture.run(),
    (error) => error.code === "ERR_INVALID_PLAN_EXECUTION_STATE",
  );
  assert.equal(
    fixture.transitions.some(
      ({ patch }) => patch?.hashes?.executionClarifications === invalidHash,
    ),
    false,
  );
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

test("invalidates correction counters when accepted task input changes", async (t) => {
  let changed = false;
  const fixture = await createFixture(t, {
    onTransition: async (run) => {
      if (!changed && run.counters.correctionRounds === 1) {
        changed = true;
        await writeFile(join(run.taskPath, "task.md"), "Changed task.\n");
      }
    },
    workReviewer: [reviewFindings("R1"), reviewFindings("R1")],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
    ],
  });

  const result = await fixture.run({
    maxSameFindingRounds: 10,
    stagnationWindowRounds: 10,
  });

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "task_input_changed");
  assert.equal(result.counters.fixRounds, 0);
  assert.equal(result.counters.correctionRounds, 0);
  assert.deepEqual(result.pipelineState.correctionHistory, []);
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

  assert.equal(result.pipelineState.workflowState, "DONE");
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

  assert.equal(result.pipelineState.workflowState, "DONE");
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

  assert.equal(resumed.pipelineState.workflowState, "DONE");
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

  assert.equal(resumed.pipelineState.workflowState, "DONE");
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

  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.deepEqual(resumed.pipelineState.settings, SETTINGS);
});

test("verifies frozen inputs at the implementation boundary", async (t) => {
  let changed = false;
  const fixture = await createFixture(t, {
    async onTransition(run) {
      if (!changed && run.pipelineState.workflowState === "IMPLEMENT") {
        changed = true;
        await writeFile(
          join(run.taskPath, "plan.md"),
          `${PLAN}\n\nChanged after bootstrap.`,
        );
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "task_input_changed");
  assert.equal(result.pipelineState.currentStep, null);
  assert.equal(result.pipelineState.resolvedSummary, null);
});

test("treats emptied required inputs as drift on resume", async (t) => {
  for (const file of ["task.md", "plan.md"]) {
    await t.test(file, async (t) => {
      let changed = false;
      const fixture = await createFixture(t, {
        async onTransition(run) {
          if (!changed && run.pipelineState.workflowState === "IMPLEMENT") {
            changed = true;
            await writeFile(join(run.taskPath, file), "");
          }
        },
      });

      const result = await fixture.run();

      assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
      assert.equal(result.pause.reason, "task_input_changed");
      assert.equal(result.pipelineState.currentStep, null);
      assert.equal(result.pipelineState.resolvedSummary, null);
    });
  }
});

test("pauses when the repository changes at the implementation boundary", async (t) => {
  let changed = false;
  const fixture = await createFixture(t, {
    async onTransition(run) {
      if (!changed && run.pipelineState.workflowState === "IMPLEMENT") {
        changed = true;
        await writeFile(join(run.projectPath, "source.js"), "externally changed\n");
      }
    },
  });

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
      const commitTransition = fixture.transitions.findLast(
        ({ patch }) => patch?.pipelineState?.workflowState === "COMMIT",
      );
      assert.notEqual(commitTransition, undefined);
      Object.assign(fixture.currentRun, commitTransition.patch);
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

  await rejectsState("retry pause with an invalid target", (run) => {
    run.pipelineState.workflowState = "WAITING_FOR_USER";
    run.pause = {
      reason: "environment_blocked",
      resumeState: "REVIEW",
    };
  });

  await rejectsState("retry pause without its target", (run) => {
    run.pipelineState.workflowState = "WAITING_FOR_USER";
    run.pause = { reason: "backend_unavailable" };
  });

  await rejectsState("retry pause with an inconsistent target state", (run) => {
    run.pipelineState.workflowState = "WAITING_FOR_USER";
    run.pause = {
      reason: "backend_unavailable",
      resumeState: "IMPLEMENT",
    };
  });

  await rejectsState("non-retryable pause with a target", (run) => {
    run.pipelineState.workflowState = "WAITING_FOR_USER";
    run.pause = {
      reason: "constructor",
      resumeState: "IMPLEMENT",
    };
  });

  await rejectsState("duplicate child session", (run) => {
    run.sessionLineage.children.push({ ...run.sessionLineage.children[0] });
  });

  await rejectsState("same-finding count without a correction", (run) => {
    run.pipelineState.sameFindingRounds = { R1: 1 };
  });

  await rejectsState("pending correction at the commit gate", (run) => {
    run.pipelineState.pendingCorrection = true;
  });

  await rejectsState("stagnation use without a direction", (run) => {
    run.pipelineState.stagnationArbitrationUsed = true;
  });

  await rejectsState("stagnation direction without recorded use", (run) => {
    run.pipelineState.stagnationDirection = {
      direction: "CONTINUE_FIXES",
      rationale: "Continue the current correction strategy.",
    };
  });

  await rejectsState("implementation rework without arbitration", (run) => {
    Object.assign(run.pipelineState, {
      workflowState: "IMPLEMENT",
      implementationDirection: {
        direction: "REWORK_IMPLEMENTATION",
        rationale: "Rework the current implementation.",
      },
      finalizationResult: null,
      finalizedFingerprint: null,
      reviewedFingerprint: null,
    });
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

  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.equal(fixture.calls.worker.length, 6);
  assert.equal(fixture.calls.reviewer.length, 2);
  assert.equal(fixture.calls.arbiter.length, 1);
  assert.equal(fixture.probeCalls.arbiter, 2);
  assert.equal(
    fixture.calls.worker.filter(({ prompt }) =>
      prompt.includes("Return a concise bootstrap summary"),
    ).length,
    1,
  );
});

test("implements, finalizes, reviews, and commits one step", async (t) => {
  let initialHead;
  const fixture = await createFixture(t, {
    async onRoleRun(role, request) {
      if (role === "worker" && request.prompt.includes("Implement the changes")) {
        initialHead ??= (
          await executeFile("git", ["-C", request.cwd, "rev-parse", "HEAD"])
        ).stdout.trim();
        await writeFile(join(request.cwd, "source.js"), "export const value = 2;\n");
      }
      if (
        role === "worker" &&
        request.prompt.includes("Locate and validate the project's finalization skill")
      ) {
        await writeFile(join(request.cwd, "generated.js"), "export const generated = true;\n");
      }
    },
  });

  const result = await fixture.run();
  const head = (
    await executeFile("git", ["-C", fixture.projectPath, "rev-parse", "HEAD"])
  ).stdout.trim();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.finalizationResult.status, "PASS");
  assert.equal(
    result.pipelineState.finalizedFingerprint,
    result.pipelineState.reviewedFingerprint,
  );
  assert.notEqual(head, initialHead);
  assert.equal(result.pipelineState.completedCommits[0], head);
  assert.equal(fixture.calls.worker.at(-3).access, "workspace-write");
  assert.equal(fixture.calls.worker.at(-2).access, "workspace-write");
  assert.equal(fixture.calls.worker.at(-1).access, "local-commit");
  assert.equal(fixture.calls.reviewer.at(-1).access, "read-only");
});

test("creates one verified local commit for every plan step", async (t) => {
  const plan = `## Commit 1: feat(test): add first behavior

Implement the first behavior.

## Commit 2: fix(test): add second behavior

Implement the second behavior.`;
  const fixture = await createFixture(t, {
    plan,
    sourceSession: SOURCE_SESSION,
    sessionIds: {
      ...ROLE_SESSIONS,
      reviewer: [ROLE_SESSIONS.reviewer, RESTARTED_ROLE_SESSIONS.reviewer],
    },
    workReviewer: [reviewApproved(), reviewApproved()],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      implementationCompleted(),
      finalizationPassed(),
    ],
  });

  const result = await fixture.run();
  const { stdout } = await executeFile("git", [
    "-C",
    fixture.projectPath,
    "log",
    "-2",
    "--pretty=%s",
  ]);

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.currentStep, null);
  assert.equal(result.pipelineState.completedCommits.length, 2);
  assert.deepEqual(stdout.trim().split("\n"), [
    "fix(test): add second behavior",
    "feat(test): add first behavior",
  ]);
  assert.deepEqual(
    fixture.calls.worker
      .filter(({ access }) => access === "local-commit")
      .map(({ commit }) => commit.message),
    ["feat(test): add first behavior", "fix(test): add second behavior"],
  );
  assert.deepEqual(fixture.calls.reviewer.at(-1).session, {
    mode: "fork",
    id: SOURCE_SESSION,
  });
});

test("accepts a verified commit after an interrupted adapter result", async (t) => {
  const fixture = await createFixture(t, {
    async onCommitRun(request) {
      await executeFile("git", ["-C", request.cwd, "add", "-A"]);
      await executeFile("git", [
        "-C",
        request.cwd,
        "commit",
        "-qm",
        request.commit.message,
      ]);
      const error = new Error("Commit result was lost.");
      error.code = "ERR_FAKE_LOCAL_COMMIT_INTERRUPTED";
      error.ambiguous = true;
      throw error;
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.completedCommits.length, 1);
  assert.equal(
    fixture.calls.worker.filter(({ access }) => access === "local-commit")
      .length,
    1,
  );
});

test("resumes commit verification without replaying the Worker", async (t) => {
  let verificationUnavailable = true;
  const fixture = await createFixture(t, {
    onCommitVerify() {
      if (verificationUnavailable) {
        verificationUnavailable = false;
        const error = new Error("Git verification was interrupted.");
        error.code = "ERR_FAKE_COMMIT_VERIFICATION";
        throw error;
      }
    },
  });

  const paused = await fixture.run();
  const resumed = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "commit_failed");
  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.equal(resumed.pipelineState.completedCommits.length, 1);
  assert.equal(
    fixture.calls.worker.filter(({ access }) => access === "local-commit")
      .length,
    1,
  );
});

test("never replays a consumed authorization when no commit was created", async (t) => {
  const fixture = await createFixture(t, {
    onCommitRun() {
      const error = new Error("Commit process was interrupted.");
      error.code = "ERR_FAKE_LOCAL_COMMIT_INTERRUPTED";
      error.ambiguous = true;
      throw error;
    },
  });

  const paused = await fixture.run();
  const resumed = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "commit_failed");
  assert.equal(paused.pipelineState.pendingCommit.status, "consumed");
  assert.equal(resumed.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(resumed.pause.reason, "commit_failed");
  assert.ok(resumed.revision > paused.revision);
  assert.equal(
    fixture.calls.worker.filter(({ access }) => access === "local-commit")
      .length,
    1,
  );
});

test("pauses without rewriting a commit that violates its authorization", async (t) => {
  const fixture = await createFixture(t, {
    async onCommitRun(request) {
      await executeFile("git", ["-C", request.cwd, "add", "-A"]);
      await executeFile("git", [
        "-C",
        request.cwd,
        "commit",
        "-qm",
        `${request.commit.message}\n\nCo-authored-by: Other <other@example.com>`,
      ]);
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "commit_contract_violated");
  assert.ok(result.pause.changes.includes("co-author"));
  assert.deepEqual(result.pipelineState.completedCommits, []);
  assert.equal(result.pipelineState.pendingCommit.status, "consumed");
});

test("resumes a workspace-write turn after a backend interruption", async (t) => {
  let interruptImplementation = true;
  const fixture = await createFixture(t, {
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("Implement the changes") &&
        interruptImplementation
      ) {
        interruptImplementation = false;
        await writeFile(
          join(request.cwd, "source.js"),
          "export const value = 2;\n",
        );
        const error = new Error("Worker backend is temporarily unavailable.");
        error.code = "ERR_PLAN_EXECUTION_BACKEND_UNAVAILABLE";
        throw error;
      }
    },
  });

  const paused = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pause.code, "ERR_PLAN_EXECUTION_BACKEND_UNAVAILABLE");
  assert.equal(paused.pause.resumeState, "IMPLEMENT");

  const resumed = await fixture.run();

  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.equal(
    await readFile(join(fixture.projectPath, "source.js"), "utf8"),
    "export const value = 2;\n",
  );
});

test("re-finalizes a partial correction after a backend interruption", async (t) => {
  let interruptResolution = true;
  const fixture = await createFixture(t, {
    workReviewer: [reviewFindings("R1"), reviewApproved()],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      finalizationPassed(),
    ],
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("For each finding below") &&
        interruptResolution
      ) {
        interruptResolution = false;
        await writeFile(
          join(request.cwd, "source.js"),
          "export const value = 2;\n",
        );
        const error = new Error("Claude process was interrupted.");
        error.code = "ERR_CLAUDE_PROCESS_INTERRUPTED";
        error.recoverable = true;
        throw error;
      }
    },
  });

  const paused = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pause.code, "ERR_CLAUDE_PROCESS_INTERRUPTED");
  assert.equal(paused.pause.resumeState, "FINALIZE");
  assert.equal(paused.pipelineState.finalizationResult, null);
  assert.equal(paused.pipelineState.finalizedFingerprint, null);
  assert.equal(paused.pipelineState.reviewedFingerprint, null);
  assert.deepEqual(paused.pipelineState.findings, []);
  assert.equal(paused.pipelineState.previousFindings[0].id, "R1");
  assert.equal(paused.counters.fixRounds, 1);

  const resumed = await fixture.run();

  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.match(
    fixture.calls.worker.findLast(({ prompt }) =>
      prompt.includes("Locate and validate the project's finalization skill"),
    ).prompt,
    /Locate and validate the project's finalization skill/u,
  );
  assert.match(
    fixture.calls.reviewer.at(-1).prompt,
    /Previous findings for this step:[\s\S]*"id": "R1"/u,
  );
});

test("retries implementation after an environment blocker clears", async (t) => {
  const fixture = await createFixture(t, {
    workWorker: [
      implementationBlocked(),
      implementationCompleted(),
      finalizationPassed(),
    ],
  });

  const paused = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "environment_blocked");
  assert.equal(paused.pause.resumeState, "IMPLEMENT");

  const resumed = await fixture.run();

  assert.equal(resumed.pipelineState.workflowState, "DONE");
});

test("routes finalization failures through a fix and the complete gate", async (t) => {
  const fixture = await createFixture(t, {
    workWorker: [
      implementationCompleted(),
      finalizationFailed("F1"),
      resolution({ id: "F1", decision: "FIX" }),
      finalizationPassed(),
    ],
    async onRoleRun(role, request) {
      if (role === "worker" && request.prompt.includes("For each finding below")) {
        await writeFile(join(request.cwd, "source.js"), "export const value = 2;\n");
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.fixRounds, 1);
  assert.equal(result.counters.correctionRounds, 0);
  assert.equal(result.pipelineState.finalizationResult.status, "PASS");
  assert.equal(fixture.calls.reviewer.length, 2);
});

test("invalidates finalization and review after fixing a review finding", async (t) => {
  const validationStates = [];
  const fixture = await createFixture(t, {
    workReviewer: [reviewFindings("R1"), reviewApproved()],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
    ],
    async onRoleRun(role, request) {
      if (role === "worker" && request.prompt.includes("For each finding below")) {
        await writeFile(join(request.cwd, "source.js"), "export const value = 2;\n");
      }
    },
    onTransition(run) {
      if (run.pipelineState.workflowState === "FINALIZE") {
        validationStates.push({
          finalizationResult: run.pipelineState.finalizationResult,
          finalizedFingerprint: run.pipelineState.finalizedFingerprint,
          reviewedFingerprint: run.pipelineState.reviewedFingerprint,
        });
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.fixRounds, 1);
  assert.ok(
    validationStates.every(
      (entry) =>
        entry.finalizationResult === null &&
        entry.finalizedFingerprint === null &&
        entry.reviewedFingerprint === null,
    ),
  );
  assert.equal(fixture.calls.reviewer.length, 3);
});

test("preserves disputes while accepted findings are fixed", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [
      reviewFindings("R1", "R2"),
      reconsideration("WITHDRAW", "R2"),
      reviewApproved(),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution(
        { id: "R1", decision: "FIX" },
        { id: "R2", decision: "DISPUTE" },
      ),
      finalizationPassed(),
    ],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.fixRounds, 1);
  assert.equal(result.pipelineState.disputeCounts.R2, 1);
  assert.equal(result.pipelineState.disputeHistory.at(-1).findingId, "R2");
  assert.equal(result.pipelineState.disputeHistory.at(-1).direction, "WITHDRAW");
  assert.match(fixture.calls.reviewer[2].prompt, /Worker disputes[\s\S]*R2/u);
  assert.match(
    fixture.calls.reviewer[3].prompt,
    /Review the changes[\s\S]*Prior decisions for this step[\s\S]*R2/u,
  );
});

test("resumes the complete review after reconsidering a deferred dispute", async (t) => {
  let interruptReview = true;
  let reviewTurns = 0;
  const fixture = await createFixture(t, {
    workReviewer: [
      reviewFindings("R1", "R2"),
      reconsideration("WITHDRAW", "R2"),
      reviewApproved(),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution(
        { id: "R1", decision: "FIX" },
        { id: "R2", decision: "DISPUTE" },
      ),
      finalizationPassed(),
    ],
    async onRoleRun(role, request) {
      if (
        role === "reviewer" &&
        request.prompt.includes("Review the changes")
      ) {
        reviewTurns += 1;
        if (reviewTurns === 2 && interruptReview) {
          interruptReview = false;
          const error = new Error(
            "Reviewer backend is temporarily unavailable.",
          );
          error.code = "ERR_PLAN_EXECUTION_BACKEND_UNAVAILABLE";
          throw error;
        }
      }
    },
  });

  const paused = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pause.resumeState, "REVIEW");
  assert.equal(paused.pipelineState.pendingDisputes.length, 0);
  assert.equal(paused.pipelineState.disputeHistory.at(-1).findingId, "R2");
  assert.equal(paused.pipelineState.reviewedFingerprint, null);

  const resumed = await fixture.run();

  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.equal(resumed.pipelineState.disputeHistory.at(-1).direction, "WITHDRAW");
  assert.match(
    fixture.calls.reviewer.at(-1).prompt,
    /Prior decisions for this step[\s\S]*"findingId": "R2"/u,
  );
});

test("preserves a mixed dispute when finalization pauses", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [reviewFindings("R1", "R2")],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution(
        { id: "R1", decision: "FIX" },
        { id: "R2", decision: "DISPUTE" },
      ),
      finalizationUnavailable("SKILL_MISSING"),
    ],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "finalization_skill_missing");
  assert.equal(result.pipelineState.pendingDisputes[0].findingId, "R2");
  assert.equal(result.pipelineState.disputeCounts.R2, 1);
});

test("preserves a mixed dispute through a finalization fix", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [
      reviewFindings("R1", "R2"),
      reconsideration("WITHDRAW", "R2"),
      reviewApproved(),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution(
        { id: "R1", decision: "FIX" },
        { id: "R2", decision: "DISPUTE" },
      ),
      finalizationFailed("F1"),
      resolution({ id: "F1", decision: "FIX" }),
      finalizationPassed(),
    ],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.fixRounds, 2);
  assert.equal(result.counters.correctionRounds, 1);
  assert.equal(result.pipelineState.disputeHistory.at(-1).findingId, "R2");
  assert.equal(result.pipelineState.disputeHistory.at(-1).direction, "WITHDRAW");
});

test("preserves a mixed dispute through stagnation rework", async (t) => {
  const fixture = await createFixture(t, {
    arbiter: [stagnation("REWORK_IMPLEMENTATION")],
    workReviewer: [
      reviewFindings("R1", "R2"),
      reconsideration("WITHDRAW", "R2"),
      reviewApproved(),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution(
        { id: "R1", decision: "FIX" },
        { id: "R2", decision: "DISPUTE" },
      ),
      finalizationFailed("F1"),
      implementationCompleted(),
      finalizationPassed(),
    ],
  });

  const result = await fixture.run({
    maxSameFindingRounds: 10,
    stagnationWindowRounds: 1,
  });

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.fixRounds, 2);
  assert.equal(result.pipelineState.disputeHistory.at(-1).findingId, "R2");
  assert.equal(result.pipelineState.disputeHistory.at(-1).direction, "WITHDRAW");
  assert.equal(fixture.calls.arbiter.length, 1);
  assert.match(
    fixture.calls.worker[7].prompt,
    /Persisted correction context[\s\S]*pendingDisputes[\s\S]*R2/u,
  );
});

test("arbitrates an upheld mixed dispute after the complete re-review", async (t) => {
  const fixture = await createFixture(t, {
    arbiter: [findingArbitration("WORKER_CORRECT")],
    workReviewer: [
      reviewFindings("R1", "R2"),
      reconsideration("UPHOLD", "R2"),
      reviewFindings("R2"),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution(
        { id: "R1", decision: "FIX" },
        { id: "R2", decision: "DISPUTE" },
      ),
      finalizationPassed(),
    ],
  });

  const result = await fixture.run({ maxDisputesPerFinding: 1 });

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.disputeCounts.R2, 1);
  assert.equal(result.pipelineState.disputeHistory.at(-1).direction, "UPHOLD");
  assert.equal(result.pipelineState.findingArbitrations.at(-1).findingId, "R2");
  assert.equal(fixture.calls.arbiter.length, 1);
});

test("lets the Reviewer withdraw an evidenced Worker dispute", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [reviewFindings("R1"), reconsideration("WITHDRAW", "R1")],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "DISPUTE" }),
    ],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.fixRounds, 0);
  assert.equal(result.pipelineState.disputeCounts.R1, 1);
  assert.equal(result.pipelineState.disputeHistory.at(-1).direction, "WITHDRAW");
  assert.equal(result.pipelineState.findings.length, 0);
});

test("arbitrates an upheld finding only after its dispute budget", async (t) => {
  const fixture = await createFixture(t, {
    arbiter: [findingArbitration("WORKER_CORRECT")],
    workReviewer: [
      reviewFindings("R1"),
      reconsideration("UPHOLD", "R1"),
      reconsideration("UPHOLD", "R1"),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "DISPUTE" }),
      resolution({ id: "R1", decision: "DISPUTE" }),
    ],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.disputeCounts.R1, 2);
  assert.equal(result.pipelineState.findingArbitrations[0].direction, "WORKER_CORRECT");
  assert.equal(fixture.calls.arbiter.length, 1);
  assert.match(
    fixture.calls.arbiter[0].prompt,
    /Resolve the disputed finding from the task, plan, repository, diff, and evidence, choosing the correct outcome using the provided schema\./u,
  );
  assert.match(
    fixture.calls.arbiter[0].prompt,
    /Do not ask questions after clarification closes\./u,
  );
  assert.match(
    fixture.calls.arbiter[0].prompt,
    /Prior decisions for this finding[\s\S]*"findingId": "R1"/u,
  );
});

test("requires a fix after the Arbiter upholds the Reviewer", async (t) => {
  const fixture = await createFixture(t, {
    arbiter: [findingArbitration("REVIEWER_CORRECT")],
    workReviewer: [
      reviewFindings("R1"),
      reconsideration("UPHOLD", "R1"),
      reconsideration("UPHOLD", "R1"),
      reviewApproved(),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "DISPUTE" }),
      resolution({ id: "R1", decision: "DISPUTE" }),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
    ],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.fixRounds, 1);
  assert.equal(
    result.pipelineState.findingArbitrations[0].direction,
    "REVIEWER_CORRECT",
  );
  const requiredFix = fixture.calls.worker
    .filter(({ prompt }) => prompt.includes("For each finding below"))
    .at(-1);
  assert.match(requiredFix.prompt, /"direction": "REVIEWER_CORRECT"/u);
  assert.match(requiredFix.prompt, /"findingId": "R1"/u);
});

test("pauses when the same finding survives the configured correction rounds", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [
      reviewFindings("R1"),
      reviewFindings("R1"),
      reviewFindings("R1"),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
    ],
  });

  const result = await fixture.run({
    maxSameFindingRounds: 2,
    stagnationWindowRounds: 10,
  });

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "no_progress");
  assert.deepEqual(result.pause.findingIds, ["R1"]);
  assert.equal(result.counters.fixRounds, 2);
  assert.equal(result.counters.correctionRounds, 2);
});

test("tracks stable findings beyond the bounded diagnostic history", async (t) => {
  const correctionRounds = 33;
  const fixture = await createFixture(t, {
    workReviewer: Array.from(
      { length: correctionRounds + 1 },
      () => reviewFindings("R1"),
    ),
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      ...Array.from({ length: correctionRounds }, () => [
        resolution({ id: "R1", decision: "FIX" }),
        finalizationPassed(),
      ]).flat(),
    ],
  });

  const result = await fixture.run({
    maxFixRoundsPerStep: correctionRounds,
    maxSameFindingRounds: correctionRounds,
    stagnationWindowRounds: correctionRounds + 1,
  });

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "no_progress");
  assert.equal(result.pipelineState.correctionHistory.length, 32);
  assert.equal(result.pipelineState.sameFindingRounds.R1, correctionRounds);
});

test("uses one stagnation arbitration for finding churn", async (t) => {
  const fixture = await createFixture(t, {
    arbiter: [stagnation("RECONSIDER_FINDINGS", ["R3"])],
    workReviewer: [
      reviewFindings("R1"),
      reviewFindings("R2"),
      reviewFindings("R3"),
      reviewApproved(),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
      resolution({ id: "R2", decision: "FIX" }),
      finalizationPassed(),
    ],
  });

  const result = await fixture.run({
    maxSameFindingRounds: 10,
    stagnationWindowRounds: 2,
  });

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.stagnationArbitrationUsed, true);
  assert.equal(
    result.pipelineState.stagnationDirection.direction,
    "RECONSIDER_FINDINGS",
  );
  assert.match(
    fixture.calls.arbiter[0].prompt,
    /Diagnose why the implementation correction loop is not converging and choose the minimal valid next direction using the provided schema\./u,
  );
});

test("routes stagnation rework through Worker, finalization, and review", async (t) => {
  const fixture = await createFixture(t, {
    arbiter: [stagnation("REWORK_IMPLEMENTATION")],
    workReviewer: [
      reviewFindings("R1"),
      reviewFindings("R2"),
      reviewApproved(),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
      implementationCompleted(),
      finalizationPassed(),
    ],
  });

  const result = await fixture.run({
    maxSameFindingRounds: 10,
    stagnationWindowRounds: 1,
  });

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.fixRounds, 2);
  assert.equal(
    result.pipelineState.stagnationDirection.direction,
    "REWORK_IMPLEMENTATION",
  );
  assert.match(
    fixture.calls.worker.findLast(({ prompt }) =>
      prompt.includes("Required rework direction"),
    ).prompt,
    /Required rework direction/u,
  );
});

test("preserves stagnation rework while waiting for fix budget", async (t) => {
  const fixture = await createFixture(t, {
    arbiter: [stagnation("REWORK_IMPLEMENTATION")],
    workReviewer: [
      reviewFindings("R1"),
      reviewFindings("R2"),
      reviewApproved(),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
      implementationCompleted(),
      finalizationPassed(),
    ],
  });

  const paused = await fixture.run({
    maxFixRoundsPerStep: 1,
    maxSameFindingRounds: 10,
    stagnationWindowRounds: 1,
  });

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "fix_limit_reached");
  assert.equal(paused.pause.resumeState, "IMPLEMENT");
  assert.equal(
    paused.pipelineState.implementationDirection.direction,
    "REWORK_IMPLEMENTATION",
  );
  assert.equal(paused.pipelineState.stagnationArbitrationUsed, true);
  assert.equal(fixture.calls.arbiter.length, 1);

  const result = await fixture.run(
    {},
    { type: "extra-fix-rounds", amount: 1 },
  );

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.fixRounds, 2);
  assert.equal(fixture.calls.arbiter.length, 1);
});

test("pauses after stagnation recurs following its one arbitration", async (t) => {
  const fixture = await createFixture(t, {
    arbiter: [stagnation("CONTINUE_FIXES")],
    workReviewer: [
      reviewFindings("R1"),
      reviewFindings("R2"),
      reviewFindings("R3"),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
      resolution({ id: "R2", decision: "FIX" }),
      finalizationPassed(),
    ],
  });

  const result = await fixture.run({
    maxSameFindingRounds: 10,
    stagnationWindowRounds: 1,
  });

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "no_progress");
  assert.equal(result.pause.resumeState, "RESOLVE_FINDINGS");
  assert.equal(fixture.calls.arbiter.length, 1);
});

test("accepts a finite extra fix budget only after exhaustion", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [reviewFindings("R1"), reviewFindings("R2"), reviewApproved()],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
      resolution({ id: "R2", decision: "FIX" }),
      resolution({ id: "R2", decision: "FIX" }),
      finalizationPassed(),
    ],
  });

  const paused = await fixture.run({
    maxFixRoundsPerStep: 1,
    maxSameFindingRounds: 10,
    stagnationWindowRounds: 10,
  });
  assert.equal(paused.pause.reason, "fix_limit_reached");

  const result = await fixture.run({}, { type: "extra-fix-rounds", amount: 1 });

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.additionalFixRounds, 1);
  assert.equal(result.counters.fixRounds, 2);
});

test("overrides one current finding only for its reviewed fingerprint", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [reviewFindings("R1"), reviewFindings("R1")],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
    ],
  });

  const paused = await fixture.run({
    maxFixRoundsPerStep: 1,
    maxSameFindingRounds: 10,
    stagnationWindowRounds: 10,
  });
  assert.equal(paused.pause.reason, "fix_limit_reached");

  const result = await fixture.run(
    {},
    { type: "override-finding", findingId: "R1" },
  );

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.deepEqual(result.pipelineState.findingOverrides, [
    {
      findingId: "R1",
      fingerprint: result.pipelineState.reviewedFingerprint,
    },
  ]);
});

test("preserves an unresolved dispute count when its finding is overridden", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [
      reviewFindings("R1", "R2"),
      reviewFindings("R1", "R2"),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution(
        { id: "R1", decision: "FIX" },
        { id: "R2", decision: "FIX" },
      ),
      finalizationPassed(),
      resolution(
        { id: "R1", decision: "FIX" },
        { id: "R2", decision: "DISPUTE" },
      ),
      resolution({ id: "R1", decision: "FIX" }),
    ],
  });

  const paused = await fixture.run({
    maxFixRoundsPerStep: 1,
    maxSameFindingRounds: 10,
    stagnationWindowRounds: 10,
  });
  assert.equal(paused.pause.reason, "fix_limit_reached");
  assert.equal(paused.pipelineState.disputeCounts.R2, 1);
  assert.deepEqual(paused.pipelineState.disputeHistory, []);

  const result = await fixture.run(
    {},
    { type: "override-finding", findingId: "R2" },
  );

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "fix_limit_reached");
  assert.equal(result.pipelineState.disputeCounts.R2, 1);
  assert.deepEqual(result.pipelineState.findingOverrides, [
    {
      findingId: "R2",
      fingerprint: result.pipelineState.reviewedFingerprint,
    },
  ]);
});

test("checks plan compatibility after a post-start product decision", async (t) => {
  const fixture = await createFixture(t, {
    workWorker: [
      implementationProductDecision(),
      compatibilityReady(),
      implementationCompleted(),
      finalizationPassed(),
    ],
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "product_decision_required");
  assert.equal(paused.pipelineState.pendingEdit.suspendedState, "IMPLEMENT");
  assert.equal(paused.pipelineState.currentStep, 1);
  assert.notEqual(paused.pipelineState.resolvedSummary, null);
  await writeFile(
    fixture.clarificationPath,
    `${await readFile(fixture.clarificationPath, "utf8")}Behavior A.\n`,
  );

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.productDecisions, 1);
  assert.match(fixture.calls.worker[4].prompt, /Review the updated clarifications/u);
});

test("preserves previous findings across a review product decision", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [
      reviewFindings("R1"),
      reviewProductDecision(),
      reviewApproved(),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
      compatibilityReady(),
      implementationCompleted(),
      finalizationPassed(),
    ],
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "product_decision_required");
  assert.deepEqual(paused.pipelineState.previousFindings, [
    reviewFindings("R1").findings[0],
  ]);
  await writeFile(
    fixture.clarificationPath,
    `${await readFile(fixture.clarificationPath, "utf8")}Behavior A.\n`,
  );

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.match(fixture.calls.reviewer[3].prompt, /Previous findings[\s\S]*"id": "R1"/u);
});

test("starts a new dispute episode after a product decision", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [
      reviewFindings("R1"),
      reconsideration("UPHOLD", "R1"),
      reconsiderationProductDecision(),
      reviewFindings("R1"),
      reconsideration("WITHDRAW", "R1"),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "DISPUTE" }),
      resolution({ id: "R1", decision: "DISPUTE" }),
      compatibilityReady(),
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "DISPUTE" }),
    ],
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "product_decision_required");
  assert.deepEqual(paused.pipelineState.disputeCounts, {});
  assert.deepEqual(paused.pipelineState.disputeHistory, []);
  await writeFile(
    fixture.clarificationPath,
    `${await readFile(fixture.clarificationPath, "utf8")}Behavior A.\n`,
  );

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.disputeCounts.R1, 1);
  assert.equal(result.pipelineState.disputeHistory.length, 1);
  assert.equal(result.pipelineState.disputeHistory[0].attempt, 1);
});

test("requires a revised plan when a post-start decision is incompatible", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [],
    workWorker: [implementationProductDecision(), compatibilityPlanRevision()],
  });

  await fixture.run();
  await writeFile(
    fixture.clarificationPath,
    `${await readFile(fixture.clarificationPath, "utf8")}Behavior B.\n`,
  );
  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "plan_revision_required");
  assert.equal(result.pipelineState.currentStep, 1);
  assert.notEqual(result.pipelineState.resolvedSummary, null);
});

test("records a blocking correction when finalization still fails", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [reviewFindings("R1")],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationFailed("F1"),
    ],
  });

  const result = await fixture.run({
    maxFixRoundsPerStep: 1,
    maxSameFindingRounds: 10,
    stagnationWindowRounds: 10,
  });

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "fix_limit_reached");
  assert.equal(result.counters.correctionRounds, 1);
  assert.deepEqual(result.pipelineState.correctionHistory.at(-1), {
    round: 1,
    fingerprint: result.pipelineState.finalizationResult.fingerprint,
    finalizationIssueIds: ["F1"],
    findingIds: [],
  });
  assert.deepEqual(result.pipelineState.sameFindingRounds, {});
});

test("pauses before finalization advances when its skill is unavailable", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [],
    workWorker: [
      implementationCompleted(),
      finalizationUnavailable("SKILL_MISSING"),
    ],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "finalization_skill_missing");
  assert.equal(result.pipelineState.finalizationResult, null);
  assert.equal(fixture.calls.reviewer.length, 1);
});

test("retries finalization after its environment blocker clears", async (t) => {
  const fixture = await createFixture(t, {
    workWorker: [
      implementationCompleted(),
      finalizationUnavailable("BLOCKED"),
      finalizationPassed(),
    ],
  });

  const paused = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "finalization_cannot_pass");
  assert.equal(paused.pause.resumeState, "FINALIZE");

  const resumed = await fixture.run();

  assert.equal(resumed.pipelineState.workflowState, "DONE");
});

test("rejects finalization changes made before skill validation", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [],
    workWorker: [
      implementationCompleted(),
      finalizationUnavailable("SKILL_MISSING"),
    ],
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes(
          "Locate and validate the project's finalization skill",
        )
      ) {
        await writeFile(
          join(request.cwd, "source.js"),
          "export const value = 2;\n",
        );
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "finalization_cannot_pass");
  assert.equal(
    result.pause.code,
    "ERR_FINALIZATION_MODIFIED_BEFORE_VALIDATION",
  );
  assert.equal(result.pipelineState.finalizationResult, null);
  assert.equal(fixture.calls.reviewer.length, 1);
});

test("allows project changes before finalization becomes blocked", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [],
    workWorker: [
      implementationCompleted(),
      finalizationUnavailable("BLOCKED"),
    ],
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes(
          "Locate and validate the project's finalization skill",
        )
      ) {
        await writeFile(
          join(request.cwd, "source.js"),
          "export const value = 2;\n",
        );
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "finalization_cannot_pass");
  assert.equal(result.pause.code, undefined);
  assert.equal(result.pipelineState.finalizationResult, null);
  assert.equal(fixture.calls.reviewer.length, 1);
});

test("requires a resolved skill path when finalization is blocked", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [],
    workWorker: [
      implementationCompleted(),
      { ...finalizationUnavailable("BLOCKED"), skillPath: "" },
    ],
  });

  await assert.rejects(
    fixture.run(),
    (error) => error.code === "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
  );
  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
});

test("pauses when a Worker changes Git history outside COMMIT", async (t) => {
  const fixture = await createFixture(t, {
    async onRoleRun(role, request) {
      if (role === "worker" && request.prompt.includes("Implement the changes")) {
        await executeFile("git", [
          "-C",
          request.cwd,
          "commit",
          "--allow-empty",
          "-qm",
          "test: unauthorized",
        ]);
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "unexpected_git_ref_change");
  assert.equal(result.pipelineState.finalizationResult, null);
});

test("pauses when a Worker changes remote configuration", async (t) => {
  const fixture = await createFixture(t, {
    async onRoleRun(role, request) {
      if (role === "worker" && request.prompt.includes("Implement the changes")) {
        await executeFile("git", [
          "-C",
          request.cwd,
          "remote",
          "add",
          "origin",
          "https://example.invalid/repository.git",
        ]);
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "unexpected_remote_configuration_change");
});

test("invalidates work when the Reviewer mutates the repository", async (t) => {
  const fixture = await createFixture(t, {
    async onRoleRun(role, request) {
      if (role === "reviewer" && request.prompt.includes("Review the changes")) {
        await writeFile(join(request.cwd, "source.js"), "reviewer mutation\n");
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "read_only_agent_mutated_repository");
  assert.equal(result.pipelineState.currentStep, null);
});
