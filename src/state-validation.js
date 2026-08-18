import { isAbsolute, resolve } from "node:path";

export const RUN_STATE_SCHEMA_VERSION = 1;

const IDENTIFIER_PATTERN = /^[a-z][a-z0-9-]{0,63}$/u;
const ACTIVITY_KIND_PATTERN = /^[a-z][a-z0-9.-]{0,63}$/u;
const UNSAFE_TEXT_PATTERN = /[\p{Cc}\p{Zl}\p{Zp}]/u;
const RUN_ID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const STATE_FIELDS = new Set([
  "schemaVersion",
  "revision",
  "runId",
  "pipelineId",
  "pipelineStateVersion",
  "projectPath",
  "taskPath",
  "roles",
  "counters",
  "hashes",
  "pause",
  "sessionLineage",
  "pipelineState",
  "createdAt",
  "updatedAt",
]);
const SESSION_LINEAGE_FIELDS = new Set(["source", "children"]);
const CHILD_SESSION_FIELDS = new Set(["role", "sessionId"]);
const ACTIVITY_FIELDS = new Set(["actor", "phase", "kind", "message"]);
const INPUT_REQUEST_FIELDS = new Set([
  "id",
  "kind",
  "questions",
  "rationale",
  "artifactPath",
]);
const INPUT_QUESTION_FIELDS = new Set([
  "id",
  "question",
  "options",
  "rationale",
]);
const INPUT_RESPONSE_FIELDS = new Set(["requestId", "transcriptHash"]);
const TRANSITION_FIELDS = new Set([
  "counters",
  "hashes",
  "pause",
  "pipelineState",
]);
const MAX_STATE_BYTES = 1024 * 1024;
const MAX_JSON_DEPTH = 20;
const MAX_COLLECTION_LENGTH = 10_000;
const MAX_OBJECT_KEYS = 1_000;
const MAX_KEY_LENGTH = 256;
const MAX_STRING_LENGTH = 100_000;
const MAX_SESSION_REFERENCE_LENGTH = 1_024;
const MAX_ACTIVITY_MESSAGE_LENGTH = 500;
const MAX_INPUT_ITEMS = 32;
const MAX_INPUT_OPTIONS = 16;
const MAX_INPUT_TEXT_LENGTH = 4_000;

export class RunStoreError extends Error {
  constructor(message, { cause, code = "ERR_RUN_STORE" } = {}) {
    super(message, { cause });
    this.name = "RunStoreError";
    this.code = code;
  }
}

function fail(message, code = "ERR_INVALID_RUN_STATE") {
  throw new RunStoreError(message, { code });
}

function isRecord(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertRecord(value, path, code) {
  if (!isRecord(value)) {
    fail(`${path} must be a plain object.`, code);
  }
}

function rejectUnknownFields(value, fields, path, code) {
  const unknownField = Object.keys(value).find((field) => !fields.has(field));
  if (unknownField !== undefined) {
    fail(`${path}.${unknownField} is not supported.`, code);
  }
}

function assertIdentifier(
  value,
  path,
  pattern = IDENTIFIER_PATTERN,
  code,
) {
  if (typeof value !== "string" || !pattern.test(value)) {
    fail(`${path} must be a lowercase kebab-case identifier.`, code);
  }

  return value;
}

function assertSessionReference(value, path) {
  if (
    typeof value !== "string" ||
    value.trim().length === 0 ||
    value.length > MAX_SESSION_REFERENCE_LENGTH ||
    UNSAFE_TEXT_PATTERN.test(value)
  ) {
    fail(`${path} must be a concise opaque string.`);
  }

  return value;
}

function assertInputText(value, path, maximumLength = MAX_INPUT_TEXT_LENGTH) {
  if (
    typeof value !== "string" ||
    value.trim().length === 0 ||
    value.length > maximumLength ||
    UNSAFE_TEXT_PATTERN.test(value)
  ) {
    fail(`${path} must be concise plain text.`);
  }
  return value;
}

function normalizePause(value) {
  const pause = cloneRecord(value, "run.pause");
  const hasRequest = Object.hasOwn(pause, "inputRequest");
  const hasResponse = Object.hasOwn(pause, "inputResponse");
  if (!hasRequest) {
    if (hasResponse) {
      fail("run.pause.inputResponse requires inputRequest.");
    }
    return pause;
  }

  const request = pause.inputRequest;
  assertRecord(request, "run.pause.inputRequest");
  rejectUnknownFields(request, INPUT_REQUEST_FIELDS, "run.pause.inputRequest");
  if (
    Object.keys(request).length !== INPUT_REQUEST_FIELDS.size ||
    !["clarification", "product-decision"].includes(request.kind) ||
    typeof request.artifactPath !== "string" ||
    !isAbsolute(request.artifactPath) ||
    resolve(request.artifactPath) !== request.artifactPath ||
    !Array.isArray(request.questions) ||
    request.questions.length > MAX_INPUT_ITEMS
  ) {
    fail("run.pause.inputRequest is invalid.");
  }
  assertInputText(request.id, "run.pause.inputRequest.id", 256);
  assertInputText(request.rationale, "run.pause.inputRequest.rationale");
  request.questions.forEach((question, index) => {
    const path = `run.pause.inputRequest.questions[${index}]`;
    assertRecord(question, path);
    rejectUnknownFields(question, INPUT_QUESTION_FIELDS, path);
    if (
      ![3, 4].includes(Object.keys(question).length) ||
      !Object.hasOwn(question, "id") ||
      !Object.hasOwn(question, "question") ||
      !Object.hasOwn(question, "options") ||
      !Array.isArray(question.options) ||
      question.options.length > MAX_INPUT_OPTIONS
    ) {
      fail(`${path} is invalid.`);
    }
    assertInputText(question.id, `${path}.id`, 256);
    assertInputText(question.question, `${path}.question`);
    question.options.forEach((option, optionIndex) =>
      assertInputText(option, `${path}.options[${optionIndex}]`),
    );
    if (Object.hasOwn(question, "rationale")) {
      assertInputText(question.rationale, `${path}.rationale`);
    }
  });

  if (hasResponse) {
    const response = pause.inputResponse;
    assertRecord(response, "run.pause.inputResponse");
    rejectUnknownFields(
      response,
      INPUT_RESPONSE_FIELDS,
      "run.pause.inputResponse",
    );
    if (
      Object.keys(response).length !== INPUT_RESPONSE_FIELDS.size ||
      response.requestId !== request.id ||
      typeof response.transcriptHash !== "string" ||
      !/^[a-f0-9]{64}$/u.test(response.transcriptHash)
    ) {
      fail("run.pause.inputResponse is invalid.");
    }
  }
  return pause;
}

function cloneJson(value, path, depth, ancestors) {
  if (value === null || typeof value === "boolean") {
    return value;
  }
  if (typeof value === "string") {
    if (value.length > MAX_STRING_LENGTH) {
      fail(`${path} exceeds the maximum string length.`);
    }
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      fail(`${path} must contain only finite numbers.`);
    }
    return Object.is(value, -0) ? 0 : value;
  }
  if (typeof value !== "object" || value === undefined) {
    fail(`${path} must contain only JSON values.`);
  }
  if (depth >= MAX_JSON_DEPTH) {
    fail(`${path} exceeds the maximum nesting depth.`);
  }
  if (ancestors.has(value)) {
    fail(`${path} must not contain circular references.`);
  }

  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      if (value.length > MAX_COLLECTION_LENGTH) {
        fail(`${path} exceeds the maximum array length.`);
      }
      return Array.from({ length: value.length }, (_, index) => {
        if (!Object.hasOwn(value, index)) {
          fail(`${path} must not contain sparse arrays.`);
        }
        return cloneJson(
          value[index],
          `${path}[${index}]`,
          depth + 1,
          ancestors,
        );
      });
    }

    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      fail(`${path} must contain only plain objects.`);
    }

    const entries = Object.entries(value);
    if (entries.length > MAX_OBJECT_KEYS) {
      fail(`${path} exceeds the maximum object size.`);
    }

    return Object.fromEntries(
      entries.map(([key, entry]) => {
        if (
          key.length === 0 ||
          key.length > MAX_KEY_LENGTH ||
          key === "__proto__" ||
          key === "prototype" ||
          key === "constructor"
        ) {
          fail(`${path} contains an unsupported field name.`);
        }
        return [
          key,
          cloneJson(entry, `${path}.${key}`, depth + 1, ancestors),
        ];
      }),
    );
  } finally {
    ancestors.delete(value);
  }
}

function cloneRecord(value, path) {
  assertRecord(value, path);
  return cloneJson(value, path, 0, new WeakSet());
}

function assertSerializedSize(value, path) {
  if (Buffer.byteLength(JSON.stringify(value)) > MAX_STATE_BYTES) {
    fail(`${path} exceeds ${MAX_STATE_BYTES} serialized bytes.`);
  }
}

function normalizeTimestamp(value, path) {
  if (
    typeof value !== "string" ||
    Number.isNaN(Date.parse(value)) ||
    new Date(value).toISOString() !== value
  ) {
    fail(`${path} must be an ISO 8601 timestamp.`);
  }

  return value;
}

export function assertRunId(runId) {
  if (typeof runId !== "string" || !RUN_ID_PATTERN.test(runId)) {
    fail("Run ID is invalid.", "ERR_INVALID_RUN_ID");
  }

  return runId;
}

export function normalizeChildSession(value, path = "childSession") {
  assertRecord(value, path);
  rejectUnknownFields(value, CHILD_SESSION_FIELDS, path);

  return {
    role: assertIdentifier(value.role, `${path}.role`),
    sessionId: assertSessionReference(value.sessionId, `${path}.sessionId`),
  };
}

function normalizeSessionLineage(value) {
  assertRecord(value, "run.sessionLineage");
  rejectUnknownFields(value, SESSION_LINEAGE_FIELDS, "run.sessionLineage");

  const source =
    value.source === null
      ? null
      : assertSessionReference(value.source, "run.sessionLineage.source");
  if (!Array.isArray(value.children)) {
    fail("run.sessionLineage.children must be an array.");
  }
  if (value.children.length > MAX_COLLECTION_LENGTH) {
    fail("run.sessionLineage.children exceeds the maximum array length.");
  }

  const children = Array.from({ length: value.children.length }, (_, index) => {
    if (!Object.hasOwn(value.children, index)) {
      fail("run.sessionLineage.children must not be sparse.");
    }
    return normalizeChildSession(
      value.children[index],
      `run.sessionLineage.children[${index}]`,
    );
  });
  const sessionIds = new Set(children.map((child) => child.sessionId));
  if (sessionIds.size !== children.length) {
    fail("run.sessionLineage.children must contain unique session IDs.");
  }

  return { source, children };
}

export function normalizeRunState(value, expectedRunId) {
  assertRecord(value, "run");
  rejectUnknownFields(value, STATE_FIELDS, "run");

  if (value.schemaVersion !== RUN_STATE_SCHEMA_VERSION) {
    fail(`Unsupported run.schemaVersion: ${String(value.schemaVersion)}.`);
  }
  if (!Number.isSafeInteger(value.revision) || value.revision < 1) {
    fail("run.revision must be a positive safe integer.");
  }

  const runId = assertRunId(value.runId);
  if (expectedRunId !== undefined && runId !== expectedRunId) {
    fail("Run ID does not match its state directory.");
  }
  const pipelineId = assertIdentifier(value.pipelineId, "run.pipelineId");
  if (
    !Number.isSafeInteger(value.pipelineStateVersion) ||
    value.pipelineStateVersion < 1
  ) {
    fail("run.pipelineStateVersion must be a positive safe integer.");
  }
  for (const [field, path] of [
    [value.projectPath, "run.projectPath"],
    [value.taskPath, "run.taskPath"],
  ]) {
    if (
      typeof field !== "string" ||
      !isAbsolute(field) ||
      resolve(field) !== field
    ) {
      fail(`${path} must be an absolute canonical path.`);
    }
  }

  const pause = value.pause === null ? null : normalizePause(value.pause);
  const createdAt = normalizeTimestamp(value.createdAt, "run.createdAt");
  const updatedAt = normalizeTimestamp(value.updatedAt, "run.updatedAt");
  if (Date.parse(updatedAt) < Date.parse(createdAt)) {
    fail("run.updatedAt must not precede run.createdAt.");
  }

  const normalized = {
    schemaVersion: RUN_STATE_SCHEMA_VERSION,
    revision: value.revision,
    runId,
    pipelineId,
    pipelineStateVersion: value.pipelineStateVersion,
    projectPath: value.projectPath,
    taskPath: value.taskPath,
    roles: cloneRecord(value.roles, "run.roles"),
    counters: cloneRecord(value.counters, "run.counters"),
    hashes: cloneRecord(value.hashes, "run.hashes"),
    pause,
    sessionLineage: normalizeSessionLineage(value.sessionLineage),
    pipelineState: cloneRecord(value.pipelineState, "run.pipelineState"),
    createdAt,
    updatedAt,
  };
  assertSerializedSize(normalized, "run");
  return normalized;
}

export function normalizeTransitionPatch(value) {
  const patch = value === undefined ? {} : value;
  assertRecord(patch, "transition");
  rejectUnknownFields(patch, TRANSITION_FIELDS, "transition");

  const normalized = {};
  for (const field of ["counters", "hashes", "pipelineState"]) {
    if (Object.hasOwn(patch, field)) {
      normalized[field] = cloneRecord(patch[field], `transition.${field}`);
    }
  }
  if (Object.hasOwn(patch, "pause")) {
    normalized.pause =
      patch.pause === null
        ? null
        : normalizePause(patch.pause);
  }

  return normalized;
}

export function normalizePublicActivity(value) {
  if (value === undefined || value === null) {
    return null;
  }

  assertRecord(value, "activity", "ERR_INVALID_PUBLIC_ACTIVITY");
  rejectUnknownFields(
    value,
    ACTIVITY_FIELDS,
    "activity",
    "ERR_INVALID_PUBLIC_ACTIVITY",
  );

  const rawMessage =
    typeof value.message === "string" ? value.message : "";
  const message =
    rawMessage.length <= MAX_ACTIVITY_MESSAGE_LENGTH * 2
      ? rawMessage.trim()
      : "";
  if (
    message.length === 0 ||
    [...message].length > MAX_ACTIVITY_MESSAGE_LENGTH ||
    UNSAFE_TEXT_PATTERN.test(message)
  ) {
    fail(
      "activity.message must be one concise line of at most " +
        `${MAX_ACTIVITY_MESSAGE_LENGTH} Unicode code points.`,
      "ERR_INVALID_PUBLIC_ACTIVITY",
    );
  }

  return {
    actor: assertIdentifier(
      value.actor,
      "activity.actor",
      IDENTIFIER_PATTERN,
      "ERR_INVALID_PUBLIC_ACTIVITY",
    ),
    phase: assertIdentifier(
      value.phase,
      "activity.phase",
      IDENTIFIER_PATTERN,
      "ERR_INVALID_PUBLIC_ACTIVITY",
    ),
    kind: assertIdentifier(
      value.kind,
      "activity.kind",
      ACTIVITY_KIND_PATTERN,
      "ERR_INVALID_PUBLIC_ACTIVITY",
    ),
    message,
  };
}

export function deepFreeze(value) {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const entry of Object.values(value)) {
      deepFreeze(entry);
    }
  }

  return value;
}
