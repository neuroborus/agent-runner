import { createHash, randomUUID } from "node:crypto";
import { isAbsolute } from "node:path";

import {
  defaultLaunchEditor,
  editorCandidates,
} from "./clarification-editor.js";
import {
  CLARIFICATION_TEMPLATE,
  ClarificationError,
  createTranscriptFile,
  readTranscript,
  replaceTranscript,
  resolveTranscriptPath,
} from "./clarification-files.js";

export { CLARIFICATION_TEMPLATE, ClarificationError };

const EDIT_AUTHORIZATION_SCHEMA_VERSION = 1;
const MAX_STRUCTURED_TEXT_LENGTH = 4_000;
const MAX_QUESTIONS = 32;
const MAX_OPTIONS = 16;
const MAX_EVIDENCE_ITEMS = 32;
const MAX_ANSWER_LENGTH = 100_000;
const AUTHORIZATION_FIELDS = new Set([
  "schemaVersion",
  "id",
  "artifactRoot",
  "transcriptPath",
  "suspendedState",
  "action",
  "preEditorHash",
]);

function isRecord(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function isEnvironment(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function assertOptions(value, name) {
  if (!isRecord(value)) {
    throw new ClarificationError(`${name} must be an object.`);
  }
  return value;
}

function assertNonEmptyString(value, name, maximumLength = 256) {
  if (
    typeof value !== "string" ||
    value.trim().length === 0 ||
    value.length > maximumLength ||
    /[\0\p{Cc}\p{Zl}\p{Zp}]/u.test(value)
  ) {
    throw new ClarificationError(`${name} must be a non-empty string.`, {
      code: "ERR_INVALID_EDIT_AUTHORIZATION",
    });
  }
  return value.trim();
}

function assertHash(value, name = "expectedHash") {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/u.test(value)) {
    throw new ClarificationError(`${name} must be a SHA-256 hash.`, {
      code: "ERR_INVALID_CLARIFICATION_HASH",
    });
  }
  return value;
}

function normalizeStructuredText(value, name) {
  if (
    typeof value !== "string" ||
    value.trim().length === 0 ||
    value.length > MAX_STRUCTURED_TEXT_LENGTH ||
    /[\0\p{Cc}\p{Zl}\p{Zp}]/u.test(value)
  ) {
    throw new ClarificationError(`${name} must be concise plain text.`);
  }
  return value.trim().replace(/\s+/gu, " ");
}

function normalizeTextList(value, name, { maximum, optional = false }) {
  if (
    !Array.isArray(value) ||
    (!optional && value.length === 0) ||
    value.length > maximum
  ) {
    throw new ClarificationError(`${name} has an invalid number of items.`);
  }
  return Object.freeze(
    value.map((item, index) =>
      normalizeStructuredText(item, `${name}[${index}]`),
    ),
  );
}

function normalizeQuestions(questions) {
  if (
    !Array.isArray(questions) ||
    questions.length === 0 ||
    questions.length > MAX_QUESTIONS
  ) {
    throw new ClarificationError(
      `questions must contain between 1 and ${MAX_QUESTIONS} items.`,
    );
  }

  return Object.freeze(
    questions.map((question, index) => {
      if (!isRecord(question)) {
        throw new ClarificationError(`questions[${index}] must be an object.`);
      }
      const unknownField = Object.keys(question).find(
        (field) => !["question", "whyItMatters"].includes(field),
      );
      if (unknownField !== undefined) {
        throw new ClarificationError(
          `questions[${index}].${unknownField} is not supported.`,
        );
      }
      return Object.freeze({
        question: normalizeStructuredText(
          question.question,
          `questions[${index}].question`,
        ),
        whyItMatters: normalizeStructuredText(
          question.whyItMatters,
          `questions[${index}].whyItMatters`,
        ),
      });
    }),
  );
}

function assertPositiveInteger(value, name) {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new ClarificationError(`${name} must be a positive integer.`);
  }
  return value;
}

function normalizeAnswers(value) {
  if (!Array.isArray(value) || value.length > MAX_QUESTIONS) {
    throw new ClarificationError("answers must be a bounded array.", {
      code: "ERR_INVALID_CLARIFICATION_ANSWERS",
    });
  }
  return value.map((answer, index) => {
    if (
      typeof answer !== "string" ||
      answer.trim().length === 0 ||
      answer.length > MAX_ANSWER_LENGTH ||
      /[\0\p{Cc}\p{Zl}\p{Zp}]/u.test(answer.replace(/[\n\r\t]/gu, ""))
    ) {
      throw new ClarificationError(
        `answers[${index}] must be non-empty plain text.`,
        { code: "ERR_INVALID_CLARIFICATION_ANSWERS" },
      );
    }
    return answer;
  });
}

function replaceLastMarkers(source, marker, sectionPattern, replacements) {
  const matches = [...source.matchAll(sectionPattern)].slice(
    -replacements.length,
  );
  if (matches.length !== replacements.length) {
    throw new ClarificationError("Clarification answer marker is missing.", {
      code: "ERR_INVALID_CLARIFICATION_ANSWERS",
    });
  }
  const positions = matches.map(
    (match) => match.index + match[0].lastIndexOf(marker),
  );

  let content = source;
  for (let index = replacements.length - 1; index >= 0; index -= 1) {
    const position = positions[index];
    content =
      content.slice(0, position) +
      replacements[index] +
      content.slice(position + marker.length);
  }
  return content;
}

function answeredContent(source, action, answers) {
  if (action === "proactive-clarification") {
    if (answers.length !== 0) {
      throw new ClarificationError(
        "Proactive clarification accepts an empty answer set.",
        { code: "ERR_INVALID_CLARIFICATION_ANSWERS" },
      );
    }
    return source;
  }
  if (action === "product-decision") {
    if (answers.length !== 1) {
      throw new ClarificationError(
        "A product decision requires exactly one answer.",
        { code: "ERR_INVALID_CLARIFICATION_ANSWERS" },
      );
    }
    return replaceLastMarkers(
      source,
      "<!-- Write the decision here. -->",
      /^Decision:\n\n<!-- Write the decision here\. -->$/gmu,
      answers,
    );
  }
  if (action === "clarification-answers" && answers.length > 0) {
    return replaceLastMarkers(
      source,
      "<!-- Write the answer here. -->",
      /^### A[1-9][0-9]*\n\n<!-- Write the answer here\. -->$/gmu,
      answers,
    );
  }
  throw new ClarificationError("Clarification answer action is invalid.", {
    code: "ERR_INVALID_CLARIFICATION_ANSWERS",
  });
}

function contentHash(content) {
  return createHash("sha256").update(content).digest("hex");
}

function appendSection(source, section) {
  const separator =
    source.length === 0 || source.endsWith("\n\n")
      ? ""
      : source.endsWith("\n")
        ? "\n"
        : "\n\n";
  return `${source}${separator}${section}\n`;
}

function formatQuestionRound(round, questions) {
  const sections = [`## Round ${round}`];
  questions.forEach((question, index) => {
    const number = index + 1;
    sections.push(
      `### Q${number}`,
      question.question,
      `Why it matters: ${question.whyItMatters}`,
      `### A${number}`,
      "<!-- Write the answer here. -->",
    );
  });
  return sections.join("\n\n");
}

function formatProductDecision(number, decision) {
  const sections = [
    `## Product Decision ${number}`,
    "### Question",
    decision.question,
  ];
  if (decision.options.length > 0) {
    sections.push(
      "### Options",
      decision.options
        .map((option, index) => `${index + 1}. ${option}`)
        .join("\n"),
    );
  }
  sections.push(
    "### Why Blocked",
    decision.whyBlocked,
    "### Evidence",
    decision.evidence.map((item) => `- ${item}`).join("\n"),
    "### Decision",
    "<!-- Write the decision here. -->",
  );
  return sections.join("\n\n");
}

function assertExpectedHash(snapshot, expectedHash) {
  assertHash(expectedHash);
  if (snapshot.hash !== expectedHash) {
    throw new ClarificationError(
      "Clarification transcript changed outside an authorized edit window.",
      { code: "ERR_CLARIFICATIONS_CHANGED" },
    );
  }
}

function normalizeAuthorization(value) {
  if (!isRecord(value)) {
    throw new ClarificationError("Edit authorization must be an object.", {
      code: "ERR_INVALID_EDIT_AUTHORIZATION",
    });
  }
  const unknownField = Object.keys(value).find(
    (field) => !AUTHORIZATION_FIELDS.has(field),
  );
  if (unknownField !== undefined) {
    throw new ClarificationError(
      `Edit authorization field is not supported: ${unknownField}.`,
      { code: "ERR_INVALID_EDIT_AUTHORIZATION" },
    );
  }
  if (value.schemaVersion !== EDIT_AUTHORIZATION_SCHEMA_VERSION) {
    throw new ClarificationError("Edit authorization version is unsupported.", {
      code: "ERR_INVALID_EDIT_AUTHORIZATION",
    });
  }
  if (
    typeof value.artifactRoot !== "string" ||
    typeof value.transcriptPath !== "string" ||
    !isAbsolute(value.artifactRoot) ||
    !isAbsolute(value.transcriptPath)
  ) {
    throw new ClarificationError("Edit authorization paths must be absolute.", {
      code: "ERR_INVALID_EDIT_AUTHORIZATION",
    });
  }
  return Object.freeze({
    schemaVersion: EDIT_AUTHORIZATION_SCHEMA_VERSION,
    id: assertNonEmptyString(value.id, "authorization.id"),
    artifactRoot: value.artifactRoot,
    transcriptPath: value.transcriptPath,
    suspendedState: assertNonEmptyString(
      value.suspendedState,
      "authorization.suspendedState",
    ),
    action: assertNonEmptyString(value.action, "authorization.action"),
    preEditorHash: assertHash(
      value.preEditorHash,
      "authorization.preEditorHash",
    ),
  });
}

function sameAuthorization(left, right) {
  return [...AUTHORIZATION_FIELDS].every(
    (field) => left[field] === right[field],
  );
}

export function createClarificationService(options = {}) {
  assertOptions(options, "Clarification service options");
  const {
    env = process.env,
    interactive = process.stdin.isTTY === true && process.stdout.isTTY === true,
    launchEditor = defaultLaunchEditor,
    authorizationIdFactory = randomUUID,
  } = options;
  if (
    !isEnvironment(env) ||
    typeof interactive !== "boolean" ||
    typeof launchEditor !== "function" ||
    typeof authorizationIdFactory !== "function"
  ) {
    throw new ClarificationError("Clarification service options are invalid.", {
      code: "ERR_INVALID_CLARIFICATION_OPTIONS",
    });
  }

  const authorizationRecords = new Map();

  async function inspectTranscript(options) {
    return readTranscript(await resolveTranscriptPath(options));
  }

  async function ensureTranscript(options) {
    const location = await resolveTranscriptPath(options, {
      createParents: true,
    });
    let created = false;
    let snapshot;
    try {
      snapshot = await readTranscript(location);
    } catch (cause) {
      if (cause?.code !== "ERR_CLARIFICATION_NOT_FOUND") {
        throw cause;
      }
      created = await createTranscriptFile(location);
      snapshot = await inspectTranscript(location);
    }
    return Object.freeze({ ...snapshot, created });
  }

  async function appendQuestionRound(options) {
    assertOptions(options, "Question-round options");
    const {
      artifactRoot,
      transcriptPath,
      expectedHash,
      round,
      questions,
    } = options;
    assertPositiveInteger(round, "round");
    const normalizedQuestions = normalizeQuestions(questions);
    const snapshot = await inspectTranscript({ artifactRoot, transcriptPath });
    assertExpectedHash(snapshot, expectedHash);
    const content = appendSection(
      snapshot.content,
      formatQuestionRound(round, normalizedQuestions),
    );
    await replaceTranscript(snapshot, content);
    return inspectTranscript(snapshot);
  }

  async function appendProductDecision(input) {
    assertOptions(input, "Product-decision options");
    const {
      artifactRoot,
      transcriptPath,
      expectedHash,
      number,
      question,
      options = [],
      whyBlocked,
      evidence,
    } = input;
    assertPositiveInteger(number, "number");
    const decision = Object.freeze({
      question: normalizeStructuredText(question, "question"),
      options: normalizeTextList(options, "options", {
        maximum: MAX_OPTIONS,
        optional: true,
      }),
      whyBlocked: normalizeStructuredText(whyBlocked, "whyBlocked"),
      evidence: normalizeTextList(evidence, "evidence", {
        maximum: MAX_EVIDENCE_ITEMS,
      }),
    });
    const snapshot = await inspectTranscript({ artifactRoot, transcriptPath });
    assertExpectedHash(snapshot, expectedHash);
    const content = appendSection(
      snapshot.content,
      formatProductDecision(number, decision),
    );
    await replaceTranscript(snapshot, content);
    return inspectTranscript(snapshot);
  }

  async function freezeTranscript(options) {
    assertOptions(options, "Freeze options");
    const { artifactRoot, transcriptPath, expectedHash } = options;
    const snapshot = await inspectTranscript({ artifactRoot, transcriptPath });
    assertExpectedHash(snapshot, expectedHash);
    return Object.freeze({
      artifactRoot: snapshot.artifactRoot,
      transcriptPath: snapshot.transcriptPath,
      hash: snapshot.hash,
    });
  }

  async function previewEditAnswers(authorization, answers) {
    const normalized = normalizeAuthorization(authorization);
    const normalizedAnswers = normalizeAnswers(answers);
    const snapshot = await inspectTranscript({
      artifactRoot: normalized.artifactRoot,
      transcriptPath: normalized.transcriptPath,
    });
    if (
      snapshot.artifactRoot !== normalized.artifactRoot ||
      snapshot.transcriptPath !== normalized.transcriptPath
    ) {
      throw new ClarificationError(
        "Edit authorization path changed unexpectedly.",
        { code: "ERR_UNSAFE_CLARIFICATION_PATH" },
      );
    }
    assertExpectedHash(snapshot, normalized.preEditorHash);
    const content = answeredContent(
      snapshot.content,
      normalized.action,
      normalizedAnswers,
    );
    return Object.freeze({ hash: contentHash(content) });
  }

  async function writeEditAnswers(authorization, answers, options = {}) {
    assertOptions(options, "Answer-write options");
    const normalized = normalizeAuthorization(authorization);
    const normalizedAnswers = normalizeAnswers(answers);
    const expectedHash = assertHash(options.expectedHash);
    const snapshot = await inspectTranscript({
      artifactRoot: normalized.artifactRoot,
      transcriptPath: normalized.transcriptPath,
    });
    if (
      snapshot.artifactRoot !== normalized.artifactRoot ||
      snapshot.transcriptPath !== normalized.transcriptPath
    ) {
      throw new ClarificationError(
        "Edit authorization path changed unexpectedly.",
        { code: "ERR_UNSAFE_CLARIFICATION_PATH" },
      );
    }
    if (snapshot.hash === normalized.preEditorHash) {
      const content = answeredContent(
        snapshot.content,
        normalized.action,
        normalizedAnswers,
      );
      if (contentHash(content) !== expectedHash) {
        throw new ClarificationError("Clarification answer hash is invalid.", {
          code: "ERR_INVALID_CLARIFICATION_HASH",
        });
      }
      if (content !== snapshot.content) {
        await replaceTranscript(snapshot, content);
      }
      return inspectTranscript(snapshot);
    }
    if (snapshot.hash === expectedHash) {
      return snapshot;
    }
    throw new ClarificationError(
      "Clarification transcript changed outside an authorized edit window.",
      { code: "ERR_CLARIFICATIONS_CHANGED" },
    );
  }

  async function prepareEdit(options) {
    assertOptions(options, "Edit options");
    const {
      artifactRoot,
      transcriptPath,
      expectedHash,
      suspendedState,
      action,
      persistPendingEdit,
    } = options;
    if (typeof persistPendingEdit !== "function") {
      throw new ClarificationError(
        "persistPendingEdit must persist the pending edit before authorization.",
        { code: "ERR_INVALID_EDIT_AUTHORIZATION" },
      );
    }
    const snapshot = await inspectTranscript({ artifactRoot, transcriptPath });
    assertExpectedHash(snapshot, expectedHash);
    const authorization = normalizeAuthorization({
      schemaVersion: EDIT_AUTHORIZATION_SCHEMA_VERSION,
      id: authorizationIdFactory(),
      artifactRoot: snapshot.artifactRoot,
      transcriptPath: snapshot.transcriptPath,
      suspendedState,
      action,
      preEditorHash: snapshot.hash,
    });
    if (authorizationRecords.has(authorization.id)) {
      throw new ClarificationError("Edit authorization ID is not unique.", {
        code: "ERR_INVALID_EDIT_AUTHORIZATION",
      });
    }
    const record = { authorization, status: "persisting" };
    authorizationRecords.set(authorization.id, record);
    try {
      await persistPendingEdit(authorization);
      record.status = "ready";
    } catch (cause) {
      authorizationRecords.delete(authorization.id);
      throw cause;
    }
    return authorization;
  }

  async function acceptEdit(authorization, options = {}) {
    assertOptions(options, "Edit-consumption options");
    const { consumePendingEdit } = options;
    const normalized = normalizeAuthorization(authorization);
    if (typeof consumePendingEdit !== "function") {
      throw new ClarificationError(
        "consumePendingEdit must atomically consume the pending edit.",
        { code: "ERR_INVALID_EDIT_AUTHORIZATION" },
      );
    }
    let record = authorizationRecords.get(normalized.id);
    if (
      record !== undefined &&
      !sameAuthorization(record.authorization, normalized)
    ) {
      throw new ClarificationError("Edit authorization does not match.", {
        code: "ERR_INVALID_EDIT_AUTHORIZATION",
      });
    }
    if (record?.status === "consumed") {
      throw new ClarificationError("Edit authorization was already consumed.", {
        code: "ERR_EDIT_AUTHORIZATION_CONSUMED",
      });
    }
    if (["persisting", "editing", "consuming"].includes(record?.status)) {
      throw new ClarificationError("Edit authorization is already in use.", {
        code: "ERR_EDIT_AUTHORIZATION_IN_USE",
      });
    }

    const previousStatus = record?.status;
    if (record === undefined) {
      record = { authorization: normalized, status: "consuming" };
      authorizationRecords.set(normalized.id, record);
    } else {
      record.status = "consuming";
    }
    try {
      const snapshot = await inspectTranscript({
        artifactRoot: normalized.artifactRoot,
        transcriptPath: normalized.transcriptPath,
      });
      if (
        snapshot.artifactRoot !== normalized.artifactRoot ||
        snapshot.transcriptPath !== normalized.transcriptPath
      ) {
        throw new ClarificationError(
          "Edit authorization path changed unexpectedly.",
          { code: "ERR_UNSAFE_CLARIFICATION_PATH" },
        );
      }
      const result = Object.freeze({
        authorizationId: normalized.id,
        suspendedState: normalized.suspendedState,
        action: normalized.action,
        transcriptPath: normalized.transcriptPath,
        preEditorHash: normalized.preEditorHash,
        hash: snapshot.hash,
        changed: snapshot.hash !== normalized.preEditorHash,
      });
      await consumePendingEdit(result);
      record.status = "consumed";
      return result;
    } catch (cause) {
      if (previousStatus === undefined) {
        authorizationRecords.delete(normalized.id);
      } else {
        record.status = previousStatus;
      }
      throw cause;
    }
  }

  async function openEditor(authorization, options = {}) {
    assertOptions(options, "Editor options");
    const { consumePendingEdit } = options;
    const normalized = normalizeAuthorization(authorization);
    const record = authorizationRecords.get(normalized.id);
    if (
      record === undefined ||
      !sameAuthorization(record.authorization, normalized)
    ) {
      throw new ClarificationError(
        "Edit authorization was not persisted by this service.",
        { code: "ERR_INVALID_EDIT_AUTHORIZATION" },
      );
    }
    if (record.status === "closed") {
      throw new ClarificationError(
        "The authorized editor window was already closed.",
        { code: "ERR_EDIT_AUTHORIZATION_CLOSED" },
      );
    }
    if (["persisting", "editing", "consuming"].includes(record.status)) {
      throw new ClarificationError("Edit authorization is already in use.", {
        code: "ERR_EDIT_AUTHORIZATION_IN_USE",
      });
    }
    if (record.status === "consumed") {
      throw new ClarificationError("Edit authorization was already consumed.", {
        code: "ERR_EDIT_AUTHORIZATION_CONSUMED",
      });
    }
    if (!interactive) {
      return Object.freeze({
        status: "WAITING_FOR_USER",
        reason: "non-interactive",
        authorization: normalized,
      });
    }

    const candidates = editorCandidates(env);
    if (candidates.length === 0) {
      return Object.freeze({
        status: "WAITING_FOR_USER",
        reason: "editor-unavailable",
        authorization: normalized,
      });
    }
    if (typeof consumePendingEdit !== "function") {
      throw new ClarificationError(
        "consumePendingEdit must atomically consume the pending edit.",
        { code: "ERR_INVALID_EDIT_AUTHORIZATION" },
      );
    }

    record.status = "editing";
    try {
      for (const command of candidates) {
        try {
          await launchEditor(command, normalized.transcriptPath);
        } catch (cause) {
          if (
            cause instanceof ClarificationError &&
            ![
              "ERR_EDITOR_UNAVAILABLE",
              "ERR_INVALID_EDITOR_COMMAND",
            ].includes(cause.code)
          ) {
            throw cause;
          }
          if (
            !(cause instanceof ClarificationError) &&
            cause?.code !== "ENOENT"
          ) {
            throw cause;
          }
          continue;
        }
        record.status = "closed";
        const result = await acceptEdit(normalized, { consumePendingEdit });
        return Object.freeze({ status: "COMPLETED", result });
      }
    } finally {
      if (record.status === "editing") {
        record.status = "ready";
      }
    }

    return Object.freeze({
      status: "WAITING_FOR_USER",
      reason: "editor-unavailable",
      authorization: normalized,
    });
  }

  return Object.freeze({
    acceptEdit,
    appendProductDecision,
    appendQuestionRound,
    ensureTranscript,
    freezeTranscript,
    inspectTranscript,
    openEditor,
    prepareEdit,
    previewEditAnswers,
    writeEditAnswers,
  });
}
