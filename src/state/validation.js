import { dirname, isAbsolute, relative, resolve, sep } from "node:path";

import { isAdapterDiagnosticClass } from "../agents/index.js";
import { validStopTiming, validStopSettlement } from "./stop-contract.js";

export const RUN_STATE_SCHEMA_VERSION = 8;
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
  3,
  4,
  5,
  6,
  7,
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
  "projectConfigurationProtection",
  "roles",
  "counters",
  "hashes",
  "pause",
  "sessionLineage",
  "activeTurn",
  "executionProcess",
  "stopRequest",
  "pipelineState",
  "createdAt",
  "updatedAt",
]);
const SESSION_LINEAGE_FIELDS = new Set(["source", "sourceProfile", "children"]);
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
const PROJECT_CONFIGURATION_PROTECTION_FIELDS = new Set([
  "schemaVersion",
  "path",
  "projectPath",
  "relativePath",
  "contentHash",
  "identity",
  "ancestors",
]);
const FILE_IDENTITY_FIELDS = new Set([
  "device",
  "inode",
  "size",
  "modifiedNs",
  "changedNs",
]);
const ANCESTOR_IDENTITY_FIELDS = new Set(["path", "device", "inode"]);
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

function assertIdentifier(value, path, pattern = IDENTIFIER_PATTERN, code) {
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
  const operatorReason = ["operator_paused", "operator_canceled"].includes(
    pause.reason,
  );
  if (operatorReason !== Object.hasOwn(pause, "operatorResume")) {
    fail("Operator resume checkpoint is invalid.");
  }
  if (operatorReason) {
    const checkpoint = pause.operatorResume;
    assertRecord(checkpoint, "run.pause.operatorResume");
    rejectUnknownFields(
      checkpoint,
      new Set(["workflowState", "pause", "activeTurn"]),
      "run.pause.operatorResume",
    );
    if (
      Object.keys(checkpoint).length !== 3 ||
      typeof checkpoint.workflowState !== "string" ||
      !/^[A-Z][A-Z_]{0,63}$/u.test(checkpoint.workflowState) ||
      Object.hasOwn(checkpoint.pause ?? {}, "operatorResume") ||
      ["operator_paused", "operator_canceled"].includes(
        checkpoint.pause?.reason,
      )
    )
      fail("Operator resume checkpoint is invalid.");
    checkpoint.activeTurn = normalizeActiveTurn(checkpoint.activeTurn);
    checkpoint.pause =
      checkpoint.pause === null ? null : normalizePause(checkpoint.pause);
  }
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
        return [key, cloneJson(entry, `${path}.${key}`, depth + 1, ancestors)];
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

function decimalIdentity(value, path) {
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]*)$/u.test(value)) {
    fail(`${path} must be a decimal identity.`);
  }
  return value;
}

function normalizeProjectConfigurationProtection(value, state) {
  if ((value === undefined && state.schemaVersion < 6) || value === null) {
    return null;
  }
  assertRecord(value, "run.projectConfigurationProtection");
  rejectUnknownFields(
    value,
    PROJECT_CONFIGURATION_PROTECTION_FIELDS,
    "run.projectConfigurationProtection",
  );
  if (
    Object.keys(value).length !==
      PROJECT_CONFIGURATION_PROTECTION_FIELDS.size ||
    value.schemaVersion !== 1 ||
    value.projectPath !== state.projectPath ||
    typeof value.path !== "string" ||
    !isAbsolute(value.path) ||
    resolve(value.path) !== value.path ||
    typeof value.relativePath !== "string" ||
    value.relativePath.length === 0 ||
    value.relativePath.includes("\\") ||
    resolve(state.projectPath, value.relativePath) !== value.path ||
    relative(state.projectPath, value.path).split(sep).join("/") !==
      value.relativePath ||
    typeof value.contentHash !== "string" ||
    !/^[a-f0-9]{64}$/u.test(value.contentHash)
  ) {
    fail("run.projectConfigurationProtection is invalid.");
  }
  assertRecord(value.identity, "run.projectConfigurationProtection.identity");
  rejectUnknownFields(
    value.identity,
    FILE_IDENTITY_FIELDS,
    "run.projectConfigurationProtection.identity",
  );
  if (Object.keys(value.identity).length !== FILE_IDENTITY_FIELDS.size) {
    fail("run.projectConfigurationProtection.identity is invalid.");
  }
  const identity = Object.fromEntries(
    [...FILE_IDENTITY_FIELDS].map((field) => [
      field,
      decimalIdentity(
        value.identity[field],
        `run.projectConfigurationProtection.identity.${field}`,
      ),
    ]),
  );
  if (!Array.isArray(value.ancestors) || value.ancestors.length === 0) {
    fail("run.projectConfigurationProtection.ancestors is invalid.");
  }
  const expectedPaths = [];
  for (let current = dirname(value.path); ; current = dirname(current)) {
    expectedPaths.unshift(current);
    if (current === state.projectPath) break;
    if (current === dirname(current)) {
      fail("run.projectConfigurationProtection.ancestors is invalid.");
    }
  }
  if (value.ancestors.length !== expectedPaths.length) {
    fail("run.projectConfigurationProtection.ancestors is invalid.");
  }
  const ancestors = value.ancestors.map((ancestor, index) => {
    const path = `run.projectConfigurationProtection.ancestors[${index}]`;
    assertRecord(ancestor, path);
    rejectUnknownFields(ancestor, ANCESTOR_IDENTITY_FIELDS, path);
    if (
      Object.keys(ancestor).length !== ANCESTOR_IDENTITY_FIELDS.size ||
      ancestor.path !== expectedPaths[index]
    ) {
      fail(`${path} is invalid.`);
    }
    return {
      path: ancestor.path,
      device: decimalIdentity(ancestor.device, `${path}.device`),
      inode: decimalIdentity(ancestor.inode, `${path}.inode`),
    };
  });
  return {
    schemaVersion: 1,
    path: value.path,
    projectPath: value.projectPath,
    relativePath: value.relativePath,
    contentHash: value.contentHash,
    identity,
    ancestors,
  };
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
          contextKey: assertContextKey(value.contextKey, `${path}.contextKey`),
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

export function normalizeRoles(value, { allowMissingEffort = true } = {}) {
  assertRecord(value, "run.roles");
  const roles = cloneRecord(value, "run.roles");
  for (const [role, configuration] of Object.entries(roles)) {
    assertRecord(configuration, `run.roles.${role}`);
    if (allowMissingEffort && !Object.hasOwn(configuration, "effort")) {
      configuration.effort = "current";
    }
    if (
      !["current", "low", "medium", "high", "xhigh"].includes(
        configuration.effort,
      )
    ) {
      fail(`run.roles.${role}.effort is invalid.`);
    }
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

function normalizeActiveTurn(value, schemaVersion = RUN_STATE_SCHEMA_VERSION) {
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

function normalizeStopRequest(value, state) {
  if (value === undefined && state.schemaVersion < 4) return null;
  if (value === null) return null;
  if (state.schemaVersion < 4)
    fail("Legacy state cannot contain a stop request.");
  assertRecord(value, "run.stopRequest");
  const legacy = !Object.hasOwn(value, "timing");
  if (
    legacy &&
    ["effectiveTiming", "targetBoundary", "settlement", "identityVersion"].some(
      (field) => Object.hasOwn(value, field),
    )
  )
    fail("Partial stop timing is invalid.");
  if (legacy) {
    value = {
      ...value,
      timing: "immediate",
      effectiveTiming: "immediate",
      targetBoundary: null,
      settlement: null,
      identityVersion: 1,
    };
  }
  const fields = new Set([
    "requestId",
    "kind",
    "expectedRevision",
    "acceptedRevision",
    "requestedAt",
    "checkpoint",
    "reconciledRevision",
    "timing",
    "effectiveTiming",
    "targetBoundary",
    "settlement",
    "identityVersion",
  ]);
  rejectUnknownFields(value, fields, "run.stopRequest");
  if (
    Object.keys(value).length !== fields.size ||
    !validStopTiming(value) ||
    ![1, 2].includes(value.identityVersion) ||
    (state.schemaVersion < 7 && value.identityVersion !== 1) ||
    (value.identityVersion === 1 &&
      (value.timing !== "immediate" || value.settlement !== null)) ||
    (value.settlement !== null &&
      (!validStopSettlement(value.settlement) ||
        value.reconciledRevision === null)) ||
    (value.identityVersion === 2 &&
      value.reconciledRevision !== null &&
      value.settlement === null) ||
    !["pause_requested", "cancel_requested"].includes(value.kind) ||
    !Number.isSafeInteger(value.expectedRevision) ||
    value.expectedRevision < 1 ||
    !Number.isSafeInteger(value.acceptedRevision) ||
    value.acceptedRevision <= value.expectedRevision ||
    value.acceptedRevision > state.revision ||
    (value.reconciledRevision !== null &&
      (!Number.isSafeInteger(value.reconciledRevision) ||
        value.reconciledRevision <= value.acceptedRevision ||
        value.reconciledRevision > state.revision))
  ) {
    fail("run.stopRequest is invalid.");
  }
  assertContextKey(value.requestId, "run.stopRequest.requestId");
  normalizeTimestamp(value.requestedAt, "run.stopRequest.requestedAt");
  if (
    value.requestedAt < state.createdAt ||
    value.requestedAt > state.updatedAt
  )
    fail("Stop request timestamp is invalid.");
  if (
    value.kind === "cancel_requested" &&
    value.reconciledRevision !== null &&
    state.pipelineState?.workflowState !== "CANCELED"
  )
    fail("Reconciled cancellation must remain terminal.");
  const checkpoint = value.checkpoint;
  assertRecord(checkpoint, "run.stopRequest.checkpoint");
  rejectUnknownFields(
    checkpoint,
    new Set(["revision", "workflowState", "activeTurn", "resumeAction"]),
    "run.stopRequest.checkpoint",
  );
  if (
    Object.keys(checkpoint).length !== 4 ||
    !Number.isSafeInteger(checkpoint.revision) ||
    checkpoint.revision < 1 ||
    checkpoint.revision > value.expectedRevision ||
    typeof checkpoint.workflowState !== "string" ||
    !/^[A-Z][A-Z_]{0,63}$/u.test(checkpoint.workflowState) ||
    checkpoint.resumeAction !== null
  )
    fail("Stop checkpoint is invalid.");
  return {
    ...value,
    checkpoint: {
      ...checkpoint,
      activeTurn: normalizeActiveTurn(checkpoint.activeTurn),
    },
  };
}

export function validateProcessIdentity(value) {
  if (value === null) return null;
  if (
    value === undefined ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length !== 2 ||
    typeof value.bootId !== "string" ||
    !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/u.test(value.bootId) ||
    typeof value.startTicks !== "string" ||
    !/^(?:0|[1-9][0-9]{0,31})$/u.test(value.startTicks)
  ) {
    throw new RunStoreError("Process identity is invalid.", {
      code: "ERR_INVALID_PROCESS_IDENTITY",
    });
  }
  return { bootId: value.bootId, startTicks: value.startTicks };
}

function normalizeExecutionProcess(value, schemaVersion) {
  if ((value === undefined && schemaVersion < 5) || value === null) return null;
  assertRecord(value, "run.executionProcess");
  rejectUnknownFields(
    value,
    new Set(["pid", "hostname", "processIdentity", "namespaceId"]),
    "run.executionProcess",
  );
  if (
    schemaVersion < 5 ||
    ![3, 4].includes(Object.keys(value).length) ||
    (value.namespaceId != null &&
      (typeof value.namespaceId !== "string" ||
        !/^pid:\[\d{1,20}\]$/u.test(value.namespaceId))) ||
    !Number.isSafeInteger(value.pid) ||
    value.pid < 1 ||
    typeof value.hostname !== "string" ||
    value.hostname.length < 1 ||
    value.hostname.length > 255 ||
    UNSAFE_TEXT_PATTERN.test(value.hostname)
  )
    fail("Run execution process is invalid.");
  return {
    ...value,
    processIdentity: validateProcessIdentity(value.processIdentity),
    namespaceId: value.namespaceId ?? null,
  };
}

export function normalizeRunState(value, expectedRunId) {
  assertRecord(value, "run");
  rejectUnknownFields(value, STATE_FIELDS, "run");

  if (!Number.isSafeInteger(value.schemaVersion) || value.schemaVersion < 1) {
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
    projectConfigurationProtection: normalizeProjectConfigurationProtection(
      value.projectConfigurationProtection,
      value,
    ),
    roles: normalizeRoles(value.roles, {
      allowMissingEffort: value.schemaVersion < 8,
    }),
    counters: cloneRecord(value.counters, "run.counters"),
    hashes: cloneRecord(value.hashes, "run.hashes"),
    pause,
    sessionLineage: normalizeSessionLineage(value.sessionLineage),
    activeTurn: normalizeActiveTurn(value.activeTurn, value.schemaVersion),
    executionProcess: normalizeExecutionProcess(
      value.executionProcess,
      value.schemaVersion,
    ),
    stopRequest: normalizeStopRequest(value.stopRequest, value),
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
      patch.pause === null ? null : normalizePause(patch.pause);
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

  const rawMessage = typeof value.message === "string" ? value.message : "";
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
