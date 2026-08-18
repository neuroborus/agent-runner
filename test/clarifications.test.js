import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  link,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  CLARIFICATION_TEMPLATE,
  ClarificationError,
  createClarificationService,
} from "../src/index.js";

async function createFixture(t) {
  const workspace = await mkdtemp(join(tmpdir(), "agent-runner-clarifications-"));
  const artifactRoot = join(workspace, "artifacts");
  const transcriptPath = join(artifactRoot, "nested", "clarifications.md");
  await mkdir(artifactRoot);
  t.after(() => rm(workspace, { recursive: true, force: true }));
  return { artifactRoot, transcriptPath, workspace };
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function isClarificationError(code) {
  return (error) =>
    error instanceof ClarificationError && error.code === code;
}

test("uses the native process environment by default", () => {
  assert.doesNotThrow(() => createClarificationService());
  assert.throws(() => createClarificationService(null), ClarificationError);
});

test("creates a missing transcript and preserves existing and empty files", async (t) => {
  const { artifactRoot, transcriptPath } = await createFixture(t);
  const service = createClarificationService({ env: {}, interactive: false });

  const created = await service.ensureTranscript({
    artifactRoot,
    transcriptPath,
  });

  assert.equal(created.created, true);
  assert.equal(created.content, CLARIFICATION_TEMPLATE);
  assert.equal(created.hash, sha256(CLARIFICATION_TEMPLATE));
  assert.equal((await lstat(transcriptPath)).mode & 0o777, 0o600);
  assert.equal((await lstat(transcriptPath)).nlink, 1);

  const existingSource = `${CLARIFICATION_TEMPLATE}\nExisting answer.\n`;
  await writeFile(transcriptPath, existingSource);
  const existing = await service.ensureTranscript({
    artifactRoot,
    transcriptPath,
  });
  assert.equal(existing.created, false);
  assert.equal(existing.content, existingSource);

  const emptyPath = join(artifactRoot, "empty.md");
  await writeFile(emptyPath, "");
  const empty = await service.ensureTranscript({
    artifactRoot,
    transcriptPath: emptyPath,
  });
  assert.equal(empty.created, false);
  assert.equal(empty.content, "");
  assert.equal(empty.hash, sha256(""));
});

test("appends structured rounds and product decisions without changing prior content", async (t) => {
  const { artifactRoot, transcriptPath } = await createFixture(t);
  await mkdir(join(artifactRoot, "nested"));
  const prefix = "User supplied context without a final newline.";
  await writeFile(transcriptPath, prefix);
  const service = createClarificationService({ env: {}, interactive: false });
  const initial = await service.inspectTranscript({
    artifactRoot,
    transcriptPath,
  });

  const afterRound = await service.appendQuestionRound({
    artifactRoot,
    transcriptPath,
    expectedHash: initial.hash,
    round: 1,
    questions: [
      {
        question: "Which behavior is required?",
        whyItMatters: "It changes the public contract.",
      },
      {
        question: "Should old data be migrated?",
        whyItMatters: "It changes the commit boundary.",
      },
    ],
  });
  assert.ok(afterRound.content.startsWith(`${prefix}\n\n## Round 1\n`));
  assert.match(afterRound.content, /### Q1\n\nWhich behavior is required\?/u);
  assert.match(
    afterRound.content,
    /Why it matters: It changes the public contract\./u,
  );
  assert.match(afterRound.content, /### A2\n\n<!-- Write the answer here\. -->/u);

  const beforeDecision = afterRound.content;
  const afterDecision = await service.appendProductDecision({
    artifactRoot,
    transcriptPath,
    expectedHash: afterRound.hash,
    number: 1,
    question: "Which retention policy should be visible?",
    options: ["Keep all records", "Delete after 30 days"],
    whyBlocked: "Both policies are valid but incompatible.",
    evidence: ["The task does not choose a retention period."],
  });

  assert.ok(afterDecision.content.startsWith(beforeDecision));
  assert.match(afterDecision.content, /## Product Decision 1/u);
  assert.match(afterDecision.content, /1\. Keep all records/u);
  assert.match(afterDecision.content, /### Why Blocked/u);
  assert.match(afterDecision.content, /### Decision/u);
  assert.equal(afterDecision.hash, sha256(afterDecision.content));

  const frozen = await service.freezeTranscript({
    artifactRoot,
    transcriptPath,
    expectedHash: afterDecision.hash,
  });
  assert.deepEqual(frozen, {
    artifactRoot,
    transcriptPath,
    hash: afterDecision.hash,
  });
});

test("rejects traversal, linked targets, and symlink escapes", async (t) => {
  const { artifactRoot, transcriptPath, workspace } = await createFixture(t);
  const service = createClarificationService({ env: {}, interactive: false });
  const outsideDirectory = join(workspace, "outside");
  const outsideFile = join(workspace, "outside.md");
  await mkdir(outsideDirectory);
  await writeFile(outsideFile, "outside\n");
  await symlink(outsideDirectory, join(artifactRoot, "linked"));
  await symlink(outsideFile, join(artifactRoot, "linked.md"));
  await link(outsideFile, join(artifactRoot, "hard-linked.md"));

  for (const unsafePath of [
    "../outside.md",
    "nested/../outside.md",
    "nested\\..\\outside.md",
    `${artifactRoot}/`,
    outsideFile,
    join(artifactRoot, "linked", "clarifications.md"),
    join(artifactRoot, "linked.md"),
    join(artifactRoot, "hard-linked.md"),
  ]) {
    await assert.rejects(
      service.ensureTranscript({
        artifactRoot,
        transcriptPath: unsafePath,
      }),
      isClarificationError("ERR_UNSAFE_CLARIFICATION_PATH"),
      unsafePath,
    );
  }

  assert.equal(await readFile(outsideFile, "utf8"), "outside\n");
  await assert.rejects(readFile(transcriptPath), /ENOENT/u);
});

test("detects changes outside an authorized edit window", async (t) => {
  const { artifactRoot, transcriptPath } = await createFixture(t);
  const service = createClarificationService({ env: {}, interactive: false });
  const initial = await service.ensureTranscript({ artifactRoot, transcriptPath });
  await writeFile(transcriptPath, `${initial.content}\nUnexpected edit.\n`);

  await assert.rejects(
    service.freezeTranscript({
      artifactRoot,
      transcriptPath,
      expectedHash: initial.hash,
    }),
    isClarificationError("ERR_CLARIFICATIONS_CHANGED"),
  );
  await assert.rejects(
    service.appendQuestionRound({
      artifactRoot,
      transcriptPath,
      expectedHash: initial.hash,
      round: 1,
      questions: [
        {
          question: "Is this stale?",
          whyItMatters: "It must not overwrite user input.",
        },
      ],
    }),
    isClarificationError("ERR_CLARIFICATIONS_CHANGED"),
  );
});

test("persists authorization before opening the preferred editor and consumes it once", async (t) => {
  const { artifactRoot, transcriptPath } = await createFixture(t);
  const events = [];
  let persistedAuthorization;
  let consumedResult;
  const service = createClarificationService({
    env: { EDITOR: "fallback", VISUAL: "preferred --wait" },
    interactive: true,
    authorizationIdFactory: () => "authorization-1",
    launchEditor: async (command, path) => {
      assert.equal(persistedAuthorization?.id, "authorization-1");
      events.push(`launch:${command}`);
      await writeFile(path, `${await readFile(path, "utf8")}User context.\n`);
    },
  });
  const initial = await service.ensureTranscript({ artifactRoot, transcriptPath });
  const authorization = await service.prepareEdit({
    artifactRoot,
    transcriptPath,
    expectedHash: initial.hash,
    suspendedState: "CLARIFY",
    action: "proactive-context",
    persistPendingEdit: async (pending) => {
      events.push("persist");
      persistedAuthorization = pending;
    },
  });
  const outcome = await service.openEditor(authorization, {
    consumePendingEdit: async (result) => {
      events.push("consume");
      consumedResult = result;
    },
  });

  assert.deepEqual(events, ["persist", "launch:preferred --wait", "consume"]);
  assert.equal(outcome.status, "COMPLETED");
  assert.equal(outcome.result.changed, true);
  assert.equal(consumedResult.hash, outcome.result.hash);
  assert.ok(Object.isFrozen(authorization));
  await assert.rejects(
    service.acceptEdit(authorization, { consumePendingEdit: async () => {} }),
    isClarificationError("ERR_EDIT_AUTHORIZATION_CONSUMED"),
  );
});

test("falls back to EDITOR and accepts an unchanged proactive close", async (t) => {
  const { artifactRoot, transcriptPath } = await createFixture(t);
  const launched = [];
  const service = createClarificationService({
    env: { VISUAL: "missing", EDITOR: "available" },
    interactive: true,
    authorizationIdFactory: () => "authorization-2",
    launchEditor: async (command) => {
      launched.push(command);
      if (command === "missing") {
        const error = new Error("missing");
        error.code = "ENOENT";
        throw error;
      }
    },
  });
  const initial = await service.ensureTranscript({ artifactRoot, transcriptPath });
  const authorization = await service.prepareEdit({
    artifactRoot,
    transcriptPath,
    expectedHash: initial.hash,
    suspendedState: "CLARIFY",
    action: "proactive-context",
    persistPendingEdit: async () => {},
  });
  const outcome = await service.openEditor(authorization, {
    consumePendingEdit: async () => {},
  });

  assert.deepEqual(launched, ["missing", "available"]);
  assert.equal(outcome.status, "COMPLETED");
  assert.equal(outcome.result.changed, false);
  assert.equal(
    (await service.inspectTranscript({ artifactRoot, transcriptPath })).content,
    CLARIFICATION_TEMPLATE,
  );
  assert.doesNotMatch(CLARIFICATION_TEMPLATE, /## Round/u);
});

test("skips invalid editor environment values", async (t) => {
  const { artifactRoot, transcriptPath } = await createFixture(t);
  const launched = [];
  const service = createClarificationService({
    env: { VISUAL: "invalid\ncommand", EDITOR: "available" },
    interactive: true,
    authorizationIdFactory: () => "authorization-invalid-visual",
    launchEditor: async (command) => launched.push(command),
  });
  const initial = await service.ensureTranscript({ artifactRoot, transcriptPath });
  const authorization = await service.prepareEdit({
    artifactRoot,
    transcriptPath,
    expectedHash: initial.hash,
    suspendedState: "CLARIFY",
    action: "proactive-context",
    persistPendingEdit: async () => {},
  });
  const outcome = await service.openEditor(authorization, {
    consumePendingEdit: async () => {},
  });

  assert.equal(outcome.status, "COMPLETED");
  assert.deepEqual(launched, ["available"]);
});

test("consumes authorization whenever a launched editor closes", async (t) => {
  const { artifactRoot, transcriptPath, workspace } = await createFixture(t);
  const editorPath = join(workspace, "editor.mjs");
  await writeFile(
    editorPath,
    'import { appendFileSync } from "node:fs";\n' +
      'appendFileSync(process.argv.at(-1), "Edited despite exit code.\\n");\n' +
      "process.exitCode = 7;\n",
  );
  let consumed = false;
  const service = createClarificationService({
    env: { EDITOR: `${process.execPath} ${editorPath}` },
    interactive: true,
    authorizationIdFactory: () => "authorization-nonzero-editor",
  });
  const initial = await service.ensureTranscript({ artifactRoot, transcriptPath });
  const authorization = await service.prepareEdit({
    artifactRoot,
    transcriptPath,
    expectedHash: initial.hash,
    suspendedState: "CLARIFY",
    action: "proactive-context",
    persistPendingEdit: async () => {},
  });
  const outcome = await service.openEditor(authorization, {
    consumePendingEdit: async () => {
      consumed = true;
    },
  });

  assert.equal(outcome.status, "COMPLETED");
  assert.equal(outcome.result.changed, true);
  assert.equal(consumed, true);
  await assert.rejects(
    service.acceptEdit(authorization, { consumePendingEdit: async () => {} }),
    isClarificationError("ERR_EDIT_AUTHORIZATION_CONSUMED"),
  );
});

test("requires durable consumption before launch and never retries its failure", async (t) => {
  const { artifactRoot, transcriptPath } = await createFixture(t);
  const launched = [];
  const service = createClarificationService({
    env: { VISUAL: "preferred", EDITOR: "fallback" },
    interactive: true,
    authorizationIdFactory: () => "authorization-consume-failure",
    launchEditor: async (command) => launched.push(command),
  });
  const initial = await service.ensureTranscript({ artifactRoot, transcriptPath });
  const authorization = await service.prepareEdit({
    artifactRoot,
    transcriptPath,
    expectedHash: initial.hash,
    suspendedState: "CLARIFY",
    action: "clarification-answers",
    persistPendingEdit: async () => {},
  });

  await assert.rejects(
    service.openEditor(authorization),
    isClarificationError("ERR_INVALID_EDIT_AUTHORIZATION"),
  );
  assert.deepEqual(launched, []);

  const persistenceError = new Error("state unavailable");
  persistenceError.code = "ENOENT";
  await assert.rejects(
    service.openEditor(authorization, {
      consumePendingEdit: async () => {
        throw persistenceError;
      },
    }),
    (error) => error === persistenceError,
  );
  assert.deepEqual(launched, ["preferred"]);

  await assert.rejects(
    service.openEditor(authorization, {
      consumePendingEdit: async () => {},
    }),
    isClarificationError("ERR_EDIT_AUTHORIZATION_CLOSED"),
  );
  assert.deepEqual(launched, ["preferred"]);
  assert.equal(
    (
      await service.acceptEdit(authorization, {
        consumePendingEdit: async () => {},
      })
    ).changed,
    false,
  );
});

test("never opens an unpersisted or altered edit authorization", async (t) => {
  const { artifactRoot, transcriptPath } = await createFixture(t);
  let launches = 0;
  const service = createClarificationService({
    env: { EDITOR: "editor" },
    interactive: true,
    authorizationIdFactory: () => "authorization-integrity",
    launchEditor: async () => {
      launches += 1;
    },
  });
  const initial = await service.ensureTranscript({ artifactRoot, transcriptPath });
  const authorization = await service.prepareEdit({
    artifactRoot,
    transcriptPath,
    expectedHash: initial.hash,
    suspendedState: "CLARIFY",
    action: "clarification-answers",
    persistPendingEdit: async () => {},
  });

  await assert.rejects(
    service.openEditor(
      { ...authorization, action: "different-action" },
      { consumePendingEdit: async () => {} },
    ),
    isClarificationError("ERR_INVALID_EDIT_AUTHORIZATION"),
  );

  const freshService = createClarificationService({
    env: { EDITOR: "editor" },
    interactive: true,
    launchEditor: async () => {
      launches += 1;
    },
  });
  await assert.rejects(
    freshService.openEditor(authorization, {
      consumePendingEdit: async () => {},
    }),
    isClarificationError("ERR_INVALID_EDIT_AUTHORIZATION"),
  );
  assert.equal(launches, 0);
});

test("opens at most one editor for an authorization", async (t) => {
  const { artifactRoot, transcriptPath } = await createFixture(t);
  let markEditorStarted;
  const editorStarted = new Promise((resolvePromise) => {
    markEditorStarted = resolvePromise;
  });
  let releaseEditor;
  const editorOpen = new Promise((resolvePromise) => {
    releaseEditor = resolvePromise;
  });
  let launches = 0;
  const service = createClarificationService({
    env: { EDITOR: "editor" },
    interactive: true,
    authorizationIdFactory: () => "authorization-concurrent-editor",
    launchEditor: async () => {
      launches += 1;
      markEditorStarted();
      await editorOpen;
    },
  });
  const initial = await service.ensureTranscript({ artifactRoot, transcriptPath });
  const authorization = await service.prepareEdit({
    artifactRoot,
    transcriptPath,
    expectedHash: initial.hash,
    suspendedState: "CLARIFY",
    action: "clarification-answers",
    persistPendingEdit: async () => {},
  });
  const firstOpen = service.openEditor(authorization, {
    consumePendingEdit: async () => {},
  });
  await editorStarted;

  await assert.rejects(
    service.openEditor(authorization, {
      consumePendingEdit: async () => {},
    }),
    isClarificationError("ERR_EDIT_AUTHORIZATION_IN_USE"),
  );
  releaseEditor();
  assert.equal((await firstOpen).status, "COMPLETED");
  assert.equal(launches, 1);
});

test("reserves authorization IDs while pending edits are persisted", async (t) => {
  const { artifactRoot, transcriptPath } = await createFixture(t);
  let finishPersistence;
  const persistencePending = new Promise((resolvePromise) => {
    finishPersistence = resolvePromise;
  });
  let markPersistenceStarted;
  const persistenceStarted = new Promise((resolvePromise) => {
    markPersistenceStarted = resolvePromise;
  });
  const service = createClarificationService({
    env: {},
    interactive: false,
    authorizationIdFactory: () => "duplicate-authorization",
  });
  const initial = await service.ensureTranscript({ artifactRoot, transcriptPath });
  let pendingAuthorization;
  const firstPreparation = service.prepareEdit({
    artifactRoot,
    transcriptPath,
    expectedHash: initial.hash,
    suspendedState: "CLARIFY",
    action: "proactive-context",
    persistPendingEdit: async (authorization) => {
      pendingAuthorization = authorization;
      markPersistenceStarted();
      await persistencePending;
    },
  });
  await persistenceStarted;

  await assert.rejects(
    service.acceptEdit(pendingAuthorization, {
      consumePendingEdit: async () => {},
    }),
    isClarificationError("ERR_EDIT_AUTHORIZATION_IN_USE"),
  );

  await assert.rejects(
    service.prepareEdit({
      artifactRoot,
      transcriptPath,
      expectedHash: initial.hash,
      suspendedState: "CLARIFY",
      action: "clarification-answers",
      persistPendingEdit: async () => {},
    }),
    isClarificationError("ERR_INVALID_EDIT_AUTHORIZATION"),
  );
  finishPersistence();
  assert.equal((await firstPreparation).id, "duplicate-authorization");
});

test("keeps a non-interactive edit pending and accepts it after resume", async (t) => {
  const { artifactRoot, transcriptPath } = await createFixture(t);
  let pending;
  let consumed = false;
  const service = createClarificationService({
    env: { EDITOR: "unused" },
    interactive: false,
    authorizationIdFactory: () => "authorization-3",
    launchEditor: async () => assert.fail("editor must not be launched"),
  });
  const initial = await service.ensureTranscript({ artifactRoot, transcriptPath });
  const authorization = await service.prepareEdit({
    artifactRoot,
    transcriptPath,
    expectedHash: initial.hash,
    suspendedState: "REVIEW",
    action: "product-decision",
    persistPendingEdit: async (value) => {
      pending = JSON.parse(JSON.stringify(value));
    },
  });
  const waiting = await service.openEditor(authorization);
  assert.equal(waiting.status, "WAITING_FOR_USER");
  assert.equal(waiting.reason, "non-interactive");
  assert.equal(consumed, false);

  await writeFile(transcriptPath, `${initial.content}\nDecision: option A.\n`);
  const resumedService = createClarificationService({
    env: {},
    interactive: false,
  });
  const result = await resumedService.acceptEdit(pending, {
    consumePendingEdit: async (accepted) => {
      assert.equal(accepted.authorizationId, "authorization-3");
      consumed = true;
    },
  });

  assert.equal(result.changed, true);
  assert.equal(result.suspendedState, "REVIEW");
  assert.equal(consumed, true);
});

test("writes identified MCP answers atomically and retries the exact content", async (t) => {
  const { artifactRoot, transcriptPath } = await createFixture(t);
  const service = createClarificationService({
    env: {},
    interactive: false,
    authorizationIdFactory: () => "mcp-answer",
  });
  const initial = await service.ensureTranscript({ artifactRoot, transcriptPath });
  const questions = await service.appendQuestionRound({
    artifactRoot,
    transcriptPath,
    expectedHash: initial.hash,
    round: 1,
    questions: [
      { question: "First question?", whyItMatters: "It changes scope." },
      {
        question: "Does <!-- Write the answer here. --> remain in the question?",
        whyItMatters: "It changes behavior.",
      },
    ],
  });
  const authorization = await service.prepareEdit({
    artifactRoot,
    transcriptPath,
    expectedHash: questions.hash,
    suspendedState: "CLARIFY",
    action: "clarification-answers",
    persistPendingEdit: async () => {},
  });
  const answers = [
    "First answer, unchanged.",
    "Second answer with <!-- Write the answer here. --> intact.",
  ];
  const preview = await service.previewEditAnswers(authorization, answers);
  const written = await service.writeEditAnswers(authorization, answers, {
    expectedHash: preview.hash,
  });

  assert.equal(written.hash, preview.hash);
  assert.match(written.content, /### A1\n\nFirst answer, unchanged\./u);
  assert.match(
    written.content,
    /### A2\n\nSecond answer with <!-- Write the answer here\. --> intact\./u,
  );
  assert.match(
    written.content,
    /Does <!-- Write the answer here\. --> remain in the question\?/u,
  );
  assert.equal(
    (await service.writeEditAnswers(authorization, answers, {
      expectedHash: preview.hash,
    })).hash,
    preview.hash,
  );
  await assert.rejects(
    service.writeEditAnswers(authorization, answers, {
      expectedHash: "f".repeat(64),
    }),
    isClarificationError("ERR_CLARIFICATIONS_CHANGED"),
  );
});

test("accepts an empty proactive MCP response", async (t) => {
  const { artifactRoot, transcriptPath } = await createFixture(t);
  const service = createClarificationService({
    env: {},
    interactive: false,
    authorizationIdFactory: () => "mcp-empty",
  });
  const initial = await service.ensureTranscript({ artifactRoot, transcriptPath });
  const authorization = await service.prepareEdit({
    artifactRoot,
    transcriptPath,
    expectedHash: initial.hash,
    suspendedState: "CLARIFY",
    action: "proactive-clarification",
    persistPendingEdit: async () => {},
  });
  const preview = await service.previewEditAnswers(authorization, []);
  const written = await service.writeEditAnswers(authorization, [], {
    expectedHash: preview.hash,
  });

  assert.equal(written.hash, initial.hash);
  assert.equal(written.content, initial.content);
});

test("validates structured input and transcript size", async (t) => {
  const { artifactRoot, transcriptPath } = await createFixture(t);
  const service = createClarificationService({ env: {}, interactive: false });
  const initial = await service.ensureTranscript({ artifactRoot, transcriptPath });

  await assert.rejects(
    service.appendQuestionRound({
      artifactRoot,
      transcriptPath,
      expectedHash: initial.hash,
      round: 0,
      questions: [],
    }),
    ClarificationError,
  );
  await assert.rejects(
    service.appendProductDecision({
      artifactRoot,
      transcriptPath,
      expectedHash: initial.hash,
      number: 1,
      question: "Question",
      whyBlocked: "Blocked",
      evidence: [],
    }),
    ClarificationError,
  );
  await assert.rejects(
    service.previewEditAnswers(
      {
        schemaVersion: 1,
        id: "invalid-answer",
        artifactRoot,
        transcriptPath,
        suspendedState: "CLARIFY",
        action: "clarification-answers",
        preEditorHash: initial.hash,
      },
      ["   "],
    ),
    ClarificationError,
  );

  await writeFile(transcriptPath, Buffer.alloc(1024 * 1024 + 1));
  await assert.rejects(
    service.inspectTranscript({ artifactRoot, transcriptPath }),
    ClarificationError,
  );
});
