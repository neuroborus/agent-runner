import { isAbsolute, resolve } from "node:path";

import { isAdapterDiagnosticClass } from "./agents/index.js";

export const RUN_STATE_SCHEMA_VERSION = 3;
export const RUNTIME_COMPATIBILITY_VERSION = 1;
export const RUNTIME_COMPATIBILITY = Object.freeze({
  runnerVersion: RUNTIME_COMPATIBILITY_VERSION,
  runStateVersion: RUN_STATE_SCHEMA_VERSION,
});
export const RUNTIME_COMPATIBILITY_TOKEN =
  `${RUNTIME_COMPATIBILITY.runnerVersion}:` +
  `${RUNTIME_COMPATIBILITY.runStateVersion}`;
export const RUNTIME_VERSION_SKEW_EXIT_CODE = 78;

const LEGACY_RUN_STATE_SCHEMA_VERSION = 1;
const ACTIVITY_RUN_STATE_SCHEMA_VERSION = 3;
const SUPPORTED_RUN_STATE_SCHEMA_VERSIONS = new Set([
  LEGACY_RUN_STATE_SCHEMA_VERSION,
  2,
  RUN_STATE_SCHEMA_VERSION,
]);

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
  "runtimeCompatibility",
  "projectPath",
  "taskPath",
  "roles",
  "counters",
  "hashes",
  "pause",
  "sessionLineage",
  "activeTurn",
  "pipelineState",
  "createdAt",
  "updatedAt",
]);
const SESSION_LINEAGE_FIELDS = new Set([
  "source",
  "sourceProfile",
  "children",
]);
const CHILD_SESSION_FIELDS = new Set(["role", "sessionId", "contextKey"]);
const ACTIVITY_FIELDS = new Set(["actor", "phase", "kind", "message"]);
const ACTIVE_TURN_FIELDS = new Set(["role", "phase"]);
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
  "activeTurn",
  "pipelineState",
]);
const RUNTIME_COMPATIBILITY_FIELDS = new Set([
  "runnerVersion",
  "runStateVersion",
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

function assertContextKey(value, path) {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/u.test(value)) {
    fail(`${path} is invalid.`);
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
  if (
    Object.hasOwn(pause, "diagnosticClass") &&
    !isAdapterDiagnosticClass(pause.diagnosticClass)
  ) {
    fail("run.pause.diagnosticClass is invalid.");
  }
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

function normalizeRuntimeCompatibility(value, schemaVersion) {
  if (schemaVersion === LEGACY_RUN_STATE_SCHEMA_VERSION) {
    if (value !== undefined && value !== null) {
      fail(
        "Legacy run state must not declare runtime compatibility.",
        "ERR_RUNTIME_VERSION_SKEW",
      );
    }
    return null;
  }

  assertRecord(value, "run.runtimeCompatibility");
  rejectUnknownFields(
    value,
    RUNTIME_COMPATIBILITY_FIELDS,
    "run.runtimeCompatibility",
  );
  if (
    Object.keys(value).length !== RUNTIME_COMPATIBILITY_FIELDS.size ||
    !Number.isSafeInteger(value.runnerVersion) ||
    value.runnerVersion < 1 ||
    !Number.isSafeInteger(value.runStateVersion) ||
    value.runStateVersion < 1
  ) {
    fail("run.runtimeCompatibility is invalid.");
  }
  if (
    value.runnerVersion !== RUNTIME_COMPATIBILITY.runnerVersion ||
    value.runStateVersion !== schemaVersion
  ) {
    fail(
      "Run state requires an incompatible Agent Runner runtime " +
        `(runner ${value.runnerVersion}, state ${value.runStateVersion}); ` +
        "use the Agent Runner version that created the run or a version " +
        "with an explicit migration.",
      "ERR_RUNTIME_VERSION_SKEW",
    );
  }

  return { ...value };
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
    ...(value.contextKey === undefined
      ? {}
      : {
          contextKey: assertContextKey(
            value.contextKey,
            `${path}.contextKey`,
          ),
        }),
  };
}

function normalizeSessionLineage(value) {
  assertRecord(value, "run.sessionLineage");
  rejectUnknownFields(value, SESSION_LINEAGE_FIELDS, "run.sessionLineage");

  const source =
    value.source === null
      ? null
      : assertSessionReference(value.source, "run.sessionLineage.source");
  const sourceProfile =
    value.sourceProfile === undefined || value.sourceProfile === null
      ? null
      : assertIdentifier(
          value.sourceProfile,
          "run.sessionLineage.sourceProfile",
        );
  if (source === null && sourceProfile !== null) {
    fail("run.sessionLineage.sourceProfile requires a source session.");
  }
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

  return { source, sourceProfile, children };
}

function normalizeRoles(value) {
  assertRecord(value, "run.roles");
  const roles = cloneRecord(value, "run.roles");
  for (const [role, configuration] of Object.entries(roles)) {
    assertRecord(configuration, `run.roles.${role}`);
    for (const field of ["profile", "model", "contextSize"]) {
      if (
        !Object.hasOwn(configuration, field) ||
        (field === "model" && configuration[field] === null)
      ) {
        configuration[field] = "current";
      }
    }
  }
  return roles;
}

function normalizeActiveTurn(
  value,
  schemaVersion = RUN_STATE_SCHEMA_VERSION,
) {
  if (schemaVersion < ACTIVITY_RUN_STATE_SCHEMA_VERSION) {
    if (value !== undefined) {
      fail("Legacy run state must not declare an active turn.");
    }
    return null;
  }
  if (value === null) {
    return null;
  }

  assertRecord(value, "run.activeTurn");
  rejectUnknownFields(value, ACTIVE_TURN_FIELDS, "run.activeTurn");
  if (Object.keys(value).length !== ACTIVE_TURN_FIELDS.size) {
    fail("run.activeTurn is invalid.");
  }
  return {
    role: assertIdentifier(value.role, "run.activeTurn.role"),
    phase: assertIdentifier(value.phase, "run.activeTurn.phase"),
  };
}

export function normalizeRunState(value, expectedRunId) {
  assertRecord(value, "run");
  rejectUnknownFields(value, STATE_FIELDS, "run");

  if (
    !Number.isSafeInteger(value.schemaVersion) ||
    value.schemaVersion < 1
  ) {
    fail("run.schemaVersion must be a positive safe integer.");
  }
  if (!SUPPORTED_RUN_STATE_SCHEMA_VERSIONS.has(value.schemaVersion)) {
    fail(
      `Unsupported run.schemaVersion: ${String(value.schemaVersion)}; ` +
        "use the Agent Runner version that created the run or a version " +
        "with an explicit migration.",
      "ERR_RUNTIME_VERSION_SKEW",
    );
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
    schemaVersion: value.schemaVersion,
    revision: value.revision,
    runId,
    pipelineId,
    pipelineStateVersion: value.pipelineStateVersion,
    runtimeCompatibility: normalizeRuntimeCompatibility(
      value.runtimeCompatibility,
      value.schemaVersion,
    ),
    projectPath: value.projectPath,
    taskPath: value.taskPath,
    roles: normalizeRoles(value.roles),
    counters: cloneRecord(value.counters, "run.counters"),
    hashes: cloneRecord(value.hashes, "run.hashes"),
    pause,
    sessionLineage: normalizeSessionLineage(value.sessionLineage),
    activeTurn: normalizeActiveTurn(value.activeTurn, value.schemaVersion),
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
  if (Object.hasOwn(patch, "activeTurn")) {
    normalized.activeTurn = normalizeActiveTurn(patch.activeTurn);
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
