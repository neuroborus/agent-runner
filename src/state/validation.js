import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";

import {
  clientAttributionFingerprint,
  DEFAULT_CLIENT_ATTRIBUTION,
  isAdapterDiagnosticClass,
  normalizeClientAttribution,
} from "../agents/index.js";
import { normalizeInactivityState } from "./inactivity.js";
import { normalizeAvailabilityState } from "./availability.js";
import { normalizeLaunchRecovery } from "./launch-recovery.js";
import { normalizeObservationState } from "./observations.js";
import {
  validStopBoundary,
  validStopTiming,
  validStopSettlement,
} from "./stop-contract.js";

export const RUN_STATE_SCHEMA_VERSION = 24;
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
const PROVIDER_POLICY_SCHEMA_VERSION = 13;
const CLIENT_ATTRIBUTION_SCHEMA_VERSION = 16;
const SUPPORTED_RUN_STATE_SCHEMA_VERSIONS = new Set([
  LEGACY_RUN_STATE_SCHEMA_VERSION,
  2,
  3,
  4,
  5,
  6,
  7,
  8,
  9,
  10,
  11,
  12,
  13,
  14,
  15,
  16,
  17,
  18,
  19,
  20,
  21,
  22,
  23,
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
  "workspace",
  "clientAttribution",
  "clientAttributionFingerprint",
  "roles",
  "providerPolicies",
  "providerInactivityTimeoutMs",
  "providerInactivityFingerprint",
  "inactivityRecovery",
  "observations",
  "availabilityPolicy",
  "availabilityRetry",
  "counters",
  "hashes",
  "pause",
  "sessionLineage",
  "activeTurn",
  "executionProcess",
  "executionResource",
  "preparation",
  "preservationRecords",
  "stopRequest",
  "pipelineState",
  "createdAt",
  "updatedAt",
]);
const SESSION_LINEAGE_FIELDS = new Set(["source", "sourceProfile", "children"]);
const CHILD_SESSION_FIELDS = new Set(["role", "sessionId", "contextKey"]);
const ACTIVITY_FIELDS = new Set(["actor", "phase", "kind", "message"]);
const ACTIVE_TURN_FIELDS = new Set(["role", "phase"]);
const PROVIDER_ACCESS_ORDER = Object.freeze([
  "read-only",
  "workspace-write",
  "local-commit",
]);
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
  "inactivityRecovery",
  "availabilityRetry",
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
// Pipeline results can be retained in several inventories and gate records.
const MAX_STATE_BYTES = 32 * 1024 * 1024;
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
const MAX_PROCESS_ANCESTRY_BASELINE_ENTRIES = 4_096;

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

export function preservationError(cause) {
  return new RunStoreError(
    "Durable preservation ownership or content is invalid.",
    {
      cause,
      code: "ERR_INVALID_PRESERVATION",
    },
  );
}

function normalizePreservationRecords(value, schemaVersion) {
  if (schemaVersion < 23 && value === undefined) return [];
  if (
    !Array.isArray(value) ||
    value.length > 1024 ||
    (schemaVersion < 23 && value.length !== 0)
  )
    throw preservationError();
  const ids = new Set();
  return value.map((record) => {
    if (
      !record ||
      Object.keys(record).sort().join() !== "fileId,hash,id,identity" ||
      !/^[a-f0-9]{64}$/u.test(record.hash) ||
      !record.identity ||
      Object.keys(record.identity).sort().join() !== "device,inode" ||
      ![record.identity.device, record.identity.inode].every(
        (part) => typeof part === "string" && /^\d+$/u.test(part),
      )
    )
      throw preservationError();
    assertRunId(record.id);
    assertRunId(record.fileId);
    if (ids.has(record.id)) throw preservationError();
    ids.add(record.id);
    return structuredClone(record);
  });
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
  if (Object.hasOwn(pause, "launchRecovery")) {
    if (pause.reason !== "backend_unavailable") {
      fail("run.pause.launchRecovery is invalid.");
    }
    try {
      pause.launchRecovery = normalizeLaunchRecovery(pause.launchRecovery);
    } catch {
      fail("run.pause.launchRecovery is invalid.");
    }
  }
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

function normalizeClientAttributionSnapshot(value, fingerprint, schemaVersion) {
  if (schemaVersion < CLIENT_ATTRIBUTION_SCHEMA_VERSION) {
    if (value !== undefined || fingerprint !== undefined) {
      let legacyAttribution;
      try {
        legacyAttribution = normalizeClientAttribution(value);
      } catch {
        fail("Legacy run state cannot grant custom client attribution.");
      }
      if (
        fingerprint !==
          clientAttributionFingerprint(DEFAULT_CLIENT_ATTRIBUTION) ||
        legacyAttribution.name !== DEFAULT_CLIENT_ATTRIBUTION.name ||
        legacyAttribution.title !== DEFAULT_CLIENT_ATTRIBUTION.title
      ) {
        fail("Legacy run state cannot grant custom client attribution.");
      }
    }
    return {
      clientAttribution: DEFAULT_CLIENT_ATTRIBUTION,
      clientAttributionFingerprint: clientAttributionFingerprint(
        DEFAULT_CLIENT_ATTRIBUTION,
      ),
    };
  }
  let clientAttribution;
  try {
    clientAttribution = normalizeClientAttribution(value);
  } catch {
    fail("run.clientAttribution is invalid.");
  }
  if (
    typeof fingerprint !== "string" ||
    fingerprint !== clientAttributionFingerprint(clientAttribution)
  ) {
    fail("run.clientAttributionFingerprint is invalid.");
  }
  return { clientAttribution, clientAttributionFingerprint: fingerprint };
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

function normalizeProviderPolicies(value, roles, schemaVersion) {
  if (schemaVersion < PROVIDER_POLICY_SCHEMA_VERSION) {
    if (value !== undefined) {
      fail("Legacy run state cannot contain provider policies.");
    }
    return Object.fromEntries(Object.keys(roles).map((role) => [role, null]));
  }
  assertRecord(value, "run.providerPolicies");
  const roleNames = Object.keys(roles);
  if (
    Object.keys(value).length !== roleNames.length ||
    roleNames.some((role) => !Object.hasOwn(value, role))
  ) {
    fail("run.providerPolicies must match the active roles.");
  }
  return Object.fromEntries(
    roleNames.map((role) => {
      const receipt = value[role];
      if (receipt === null) return [role, null];
      assertRecord(receipt, `run.providerPolicies.${role}`);
      if (
        Object.keys(receipt).length !== 3 ||
        receipt.schemaVersion !== 1 ||
        typeof receipt.fingerprint !== "string" ||
        !/^[a-f0-9]{64}$/u.test(receipt.fingerprint) ||
        !Array.isArray(receipt.supportedAccess) ||
        receipt.supportedAccess.length > PROVIDER_ACCESS_ORDER.length ||
        receipt.supportedAccess.some((access, index, values) => {
          const position = PROVIDER_ACCESS_ORDER.indexOf(access);
          return (
            position === -1 ||
            values.indexOf(access) !== index ||
            (index > 0 &&
              PROVIDER_ACCESS_ORDER.indexOf(values[index - 1]) >= position)
          );
        })
      ) {
        fail(`run.providerPolicies.${role} is invalid.`);
      }
      return [
        role,
        {
          schemaVersion: 1,
          fingerprint: receipt.fingerprint,
          supportedAccess: [...receipt.supportedAccess],
        },
      ];
    }),
  );
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

export function normalizeStopRequest(value, state) {
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

function normalizeProcessAncestryBaseline(value, processIdentity) {
  if (value === null) return null;
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    value.length > MAX_PROCESS_ANCESTRY_BASELINE_ENTRIES ||
    processIdentity === null
  ) {
    fail("Run execution process ancestry baseline is invalid.");
  }
  let previousPid = 0;
  return value.map((entry, index) => {
    const path = `run.executionProcess.ancestryBaseline[${index}]`;
    assertRecord(entry, path);
    rejectUnknownFields(entry, new Set(["bootId", "pid", "startTicks"]), path);
    if (
      Object.keys(entry).length !== 3 ||
      entry.bootId !== processIdentity.bootId ||
      !Number.isSafeInteger(entry.pid) ||
      entry.pid <= previousPid ||
      typeof entry.startTicks !== "string" ||
      !/^(?:0|[1-9][0-9]{0,31})$/u.test(entry.startTicks)
    ) {
      fail(`${path} is invalid.`);
    }
    previousPid = entry.pid;
    return {
      bootId: entry.bootId,
      pid: entry.pid,
      startTicks: entry.startTicks,
    };
  });
}

export function normalizeExecutionProcess(
  value,
  schemaVersion = RUN_STATE_SCHEMA_VERSION,
) {
  if ((value === undefined && schemaVersion < 5) || value === null) return null;
  assertRecord(value, "run.executionProcess");
  const fields = ["pid", "hostname", "processIdentity", "namespaceId"];
  if (schemaVersion >= 11) fields.push("launchCutoff");
  if (schemaVersion >= 12) fields.push("ancestryBaseline");
  if (schemaVersion >= 14) fields.push("controlGroup");
  rejectUnknownFields(value, new Set(fields), "run.executionProcess");
  if (
    schemaVersion < 5 ||
    (schemaVersion < 11
      ? ![3, 4].includes(Object.keys(value).length)
      : Object.keys(value).length !== fields.length) ||
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
  const processIdentity = validateProcessIdentity(value.processIdentity);
  const launchCutoff =
    schemaVersion < 11
      ? processIdentity === null
        ? null
        : { ...processIdentity }
      : validateProcessIdentity(value.launchCutoff);
  if (
    (processIdentity === null) !== (launchCutoff === null) ||
    (processIdentity !== null &&
      (processIdentity.bootId !== launchCutoff.bootId ||
        processIdentity.startTicks !== launchCutoff.startTicks))
  ) {
    fail("Run execution process launch cutoff is invalid.");
  }
  const ancestryBaseline =
    schemaVersion < 12
      ? null
      : normalizeProcessAncestryBaseline(
          value.ancestryBaseline,
          processIdentity,
        );
  const controlGroup = schemaVersion < 14 ? null : value.controlGroup;
  if (
    controlGroup !== null &&
    (typeof controlGroup !== "string" || !/^[a-f0-9]{64}$/u.test(controlGroup))
  ) {
    fail("Run execution process control group is invalid.");
  }
  return {
    pid: value.pid,
    hostname: value.hostname,
    processIdentity,
    namespaceId: value.namespaceId ?? null,
    launchCutoff,
    ancestryBaseline,
    controlGroup,
  };
}

export function preparationHeader(reservation) {
  return {
    runId: reservation.owner.runId,
    id: reservation.id,
    revision: reservation.revision,
    digest: reservation.digest,
  };
}

export function normalizePreparationCustody(records, reservation) {
  const invalid = () =>
    fail(
      "Preparation custody is invalid.",
      "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
    );
  if (!Array.isArray(records) || records.length < 1 || records.length > 16)
    invalid();
  let previous = null;
  let process = null;
  let admitted = null;
  let retired = false;
  let stopRevision = reservation.revision;
  const stopIds = new Set();
  let denied =
    reservation.stopRequest?.reconciledRevision === null &&
    (reservation.stopRequest.effectiveTiming !== "after-current-commit" ||
      !isDeepStrictEqual(
        reservation.stopRequest.targetBoundary,
        reservation.targetBoundary,
      ));
  for (const record of records) {
    assertRecord(record, "preparation custody record");
    const line = JSON.stringify(record);
    if (
      Object.keys(record).length !== 3 ||
      record.previous !== previous ||
      !Object.hasOwn(record, "value")
    )
      invalid();
    const { kind, value } = record;
    if (previous === null) {
      if (
        kind !== "reserved" ||
        !isDeepStrictEqual(value, preparationHeader(reservation))
      )
        invalid();
    } else if (kind === "attached") {
      if (process !== null || admitted !== null || retired) invalid();
      process = normalizeExecutionProcess(value);
      if (
        process === null ||
        process.processIdentity === null ||
        process.namespaceId === null ||
        process.ancestryBaseline === null ||
        process.controlGroup === null ||
        !isDeepStrictEqual(process, value)
      )
        invalid();
    } else if (kind === "admitted") {
      if (
        process === null ||
        admitted !== null ||
        retired ||
        typeof value !== "boolean" ||
        (value && denied)
      )
        invalid();
      admitted = value;
    } else if (kind === "stop") {
      assertRecord(value, "preparation stop disposition");
      if (
        retired ||
        value.reservationId !== reservation.id ||
        Object.keys(value).length !== 7 ||
        !/^[a-f0-9]{64}$/u.test(value.requestId) ||
        !Number.isSafeInteger(value.expectedRevision) ||
        value.expectedRevision < 1 ||
        !Number.isSafeInteger(value.acceptedRevision) ||
        value.acceptedRevision <= value.expectedRevision ||
        value.acceptedRevision <= stopRevision ||
        stopIds.has(value.requestId) ||
        !["pause_requested", "cancel_requested"].includes(value.kind) ||
        !(value.effectiveTiming === "immediate"
          ? value.targetBoundary === null
          : value.effectiveTiming === "after-current-commit" &&
            validStopBoundary(value.targetBoundary))
      )
        invalid();
      stopRevision = value.acceptedRevision;
      stopIds.add(value.requestId);
      denied ||=
        value.effectiveTiming !== "after-current-commit" ||
        !isDeepStrictEqual(value.targetBoundary, reservation.targetBoundary);
    } else if (kind === "revoked") {
      if (value !== null || retired) invalid();
      denied = true;
    } else if (kind === "no-launch") {
      if (retired || process !== null || value !== null) invalid();
      retired = true;
    } else if (kind === "retired") {
      if (retired || value !== null || process === null) invalid();
      retired = true;
    } else invalid();
    previous = createHash("sha256").update(line).digest("hex");
  }
  return { records, endpoint: previous, process, admitted, retired, denied };
}

function normalizePreparation(value, state) {
  if ((value === undefined && state.schemaVersion < 22) || value === null)
    return null;
  assertRecord(value, "run.preparation");
  const fields = new Set([
    "id",
    "revision",
    "owner",
    "certificate",
    "bindings",
    "resource",
    "targetBoundary",
    "stopRequest",
    "settlement",
    "digest",
  ]);
  rejectUnknownFields(value, fields, "run.preparation");
  assertRunId(value.id);
  assertRecord(value.owner, "preparation.owner");
  assertRunId(value.owner.token);
  assertRecord(value.certificate, "preparation.certificate");
  assertRecord(value.bindings, "preparation.bindings");
  for (const [name, keys] of [
    [
      "owner",
      [
        "schemaVersion",
        "runId",
        "token",
        "pid",
        "hostname",
        "processIdentity",
        "acquiredAt",
      ],
    ],
    [
      "bindings",
      [
        "commandIdentity",
        "commandFingerprint",
        "configurationFingerprint",
        "contentFingerprint",
        "inputFingerprint",
      ],
    ],
    [
      "certificate",
      ["runId", "firstRevision", "lastRevision", "directory", "bindings"],
    ],
  ]) {
    rejectUnknownFields(value[name], new Set(keys), `preparation.${name}`);
    if (Object.keys(value[name]).length !== keys.length)
      fail("Preparation authority is incomplete.");
  }
  if (
    state.schemaVersion < 22 ||
    Object.keys(value).length !== fields.size ||
    !Number.isSafeInteger(value.revision) ||
    value.revision < 2 ||
    value.revision > state.revision ||
    value.certificate.runId !== state.runId ||
    value.certificate.firstRevision !== 1 ||
    value.certificate.lastRevision !== value.revision - 1 ||
    !Array.isArray(value.certificate.bindings) ||
    value.certificate.bindings.length < 1 ||
    value.certificate.bindings.length > 1024 ||
    value.owner.runId !== state.runId ||
    value.owner.schemaVersion !== 2 ||
    typeof value.owner.hostname !== "string" ||
    value.owner.hostname.length < 1 ||
    value.owner.hostname.length > 255 ||
    UNSAFE_TEXT_PATTERN.test(value.owner.hostname) ||
    !Number.isSafeInteger(value.owner.pid) ||
    value.owner.pid < 1 ||
    validateProcessIdentity(value.owner.processIdentity) === null ||
    !(
      value.targetBoundary === null || validStopBoundary(value.targetBoundary)
    ) ||
    !Object.hasOwn(value, "stopRequest") ||
    (value.settlement !== null &&
      (!Array.isArray(value.settlement.records) ||
        value.settlement.records.length > 16 ||
        !/^[a-f0-9]{64}$/u.test(value.settlement.endpoint)))
  )
    fail("Preparation reservation is invalid.");
  normalizeTimestamp(value.owner.acquiredAt, "preparation.owner.acquiredAt");
  normalizeExecutionResource(value.resource);
  normalizeStopRequest(value.stopRequest, {
    ...state,
    revision: value.revision - 1,
  });
  for (const key of [
    "commandIdentity",
    "commandFingerprint",
    "configurationFingerprint",
    "contentFingerprint",
    "inputFingerprint",
  ])
    if (!/^[a-f0-9]{64}$/u.test(value.bindings[key]))
      fail("Preparation bindings are invalid.");
  const { digest, settlement, ...authority } = value;
  if (
    digest !==
    createHash("sha256").update(JSON.stringify(authority)).digest("hex")
  )
    fail("Preparation authority digest is invalid.");
  if (settlement !== null) {
    const facts = normalizePreparationCustody(settlement.records, value);
    if (
      Object.keys(settlement).length !== 2 ||
      !facts.retired ||
      facts.endpoint !== settlement.endpoint
    )
      fail("Preparation settlement is invalid.");
  }
  return cloneRecord(value, "run.preparation");
}

export function normalizeExecutionResource(
  value,
  schemaVersion = RUN_STATE_SCHEMA_VERSION,
) {
  if (value === null || (value === undefined && schemaVersion < 9)) return null;
  if (schemaVersion < 9) fail("Legacy runs cannot grant storage ownership.");
  assertRecord(value, "run.executionResource");
  const fields = [
    "id",
    "hostname",
    "commandIdentity",
    "phase",
    "root",
    "directory",
    ...(value.phase === "acquiring" ? ["owner"] : []),
  ];
  if (
    Object.keys(value).length !== fields.length ||
    fields.some((key) => !Object.hasOwn(value, key)) ||
    typeof value.id !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
      value.id,
    ) ||
    typeof value.hostname !== "string" ||
    value.hostname.length < 1 ||
    value.hostname.length > 255 ||
    UNSAFE_TEXT_PATTERN.test(value.hostname) ||
    typeof value.commandIdentity !== "string" ||
    !/^[a-f0-9]{64}$/u.test(value.commandIdentity) ||
    !["allocating", "allocated", "acquiring"].includes(value.phase)
  )
    fail("Run execution resource is invalid.");
  if (value.phase === "acquiring") {
    if (schemaVersion < 10)
      fail("Legacy runs cannot grant acquisition ownership.");
    assertRecord(value.owner, "resource.owner");
    if (
      Object.keys(value.owner).length !== 2 ||
      !Number.isSafeInteger(value.owner.pid) ||
      value.owner.pid < 1 ||
      validateProcessIdentity(value.owner.processIdentity) === null
    )
      fail("Resource acquisition owner is invalid.");
  }
  assertRecord(value.root, "resource.root");
  if (
    Object.keys(value.root).length !== 3 ||
    typeof value.root.path !== "string" ||
    !isAbsolute(value.root.path) ||
    resolve(value.root.path) !== value.root.path
  )
    fail("Resource root is invalid.");
  for (const identity of [
    value.root,
    ...(value.phase !== "allocating" ? [value.directory] : []),
  ]) {
    assertRecord(identity, "resource.identity");
    if (
      typeof identity.device !== "string" ||
      typeof identity.inode !== "string" ||
      !/^\d{1,32}$/u.test(identity.device) ||
      !/^\d{1,32}$/u.test(identity.inode)
    )
      fail("Resource identity is invalid.");
  }
  if (
    value.phase === "allocating"
      ? value.directory !== null
      : Object.keys(value.directory).length !== 2
  )
    fail("Resource allocation identity is invalid.");
  return structuredClone(value);
}

function normalizeWorkspace(value, run) {
  if (value == null) return null; // Legacy runs retain Git semantics, never new authority.
  assertRecord(value, "run.workspace");
  const fields = new Set([
    "schemaVersion",
    "kind",
    "lease",
    "leasePath",
    "policy",
    "bindingFingerprint",
    "protectedFingerprint",
    "ancestorBindings",
    "absentInputPaths",
    "retrievalPermissions",
  ]);
  rejectUnknownFields(value, fields, "run.workspace");
  const canonical = (path) =>
    typeof path === "string" &&
    isAbsolute(path) &&
    resolve(path) === path &&
    path !== sep &&
    !/[\0\r\n]/u.test(path);
  const contains = (root, path) => {
    const name = relative(root, path);
    return (
      name === "" ||
      (!isAbsolute(name) && name !== ".." && !name.startsWith(`..${sep}`))
    );
  };
  if (
    run.schemaVersion < 24 ||
    Object.keys(value).length !== fields.size ||
    value.schemaVersion !== 1 ||
    !["git", "directory"].includes(value.kind) ||
    !["none", "exclusive"].includes(value.lease) ||
    !canonical(value.leasePath) ||
    !contains(value.leasePath, run.projectPath) ||
    !Array.isArray(value.ancestorBindings) ||
    !Array.isArray(value.absentInputPaths) ||
    value.absentInputPaths.length > 256 ||
    value.absentInputPaths.some(
      (path, index) =>
        !canonical(path) ||
        path === run.taskPath ||
        !contains(run.taskPath, path) ||
        (index > 0 && value.absentInputPaths[index - 1] >= path),
    ) ||
    value.ancestorBindings.length > 4096 ||
    value.ancestorBindings.some(
      (entry, index) =>
        !isRecord(entry) ||
        Object.keys(entry).sort().join() !== "device,inode,mode,path" ||
        (!canonical(entry.path) && entry.path !== sep) ||
        [entry.device, entry.inode, entry.mode].some(
          (field) => typeof field !== "string" || !/^[0-9]+$/u.test(field),
        ) ||
        (index > 0 && value.ancestorBindings[index - 1].path >= entry.path),
    ) ||
    !Array.isArray(value.retrievalPermissions) ||
    value.retrievalPermissions.length !== 0
  )
    fail("run.workspace is invalid.");
  if (value.kind === "git") {
    if (
      value.leasePath !== run.projectPath ||
      value.policy !== null ||
      value.bindingFingerprint !== null ||
      value.protectedFingerprint !== null ||
      value.ancestorBindings.length !== 0 ||
      value.absentInputPaths.length !== 0
    )
      fail("Git workspace binding is invalid.");
  } else {
    const paths = [
      "inputPaths",
      "sourcePaths",
      "outputPaths",
      "configurationPaths",
      "artifactPaths",
      "infrastructurePaths",
    ];
    const policy = value.policy;
    assertRecord(policy, "run.workspace.policy");
    rejectUnknownFields(
      policy,
      new Set(["kind", "workspacePath", "taskPath", "stateRoot", ...paths]),
      "run.workspace.policy",
    );
    if (
      Object.keys(policy).length !== paths.length + 4 ||
      value.lease !== "exclusive" ||
      policy.kind !== "directory" ||
      policy.workspacePath !== run.projectPath ||
      policy.taskPath !== run.taskPath ||
      !canonical(policy.stateRoot) ||
      paths.some(
        (name) =>
          !Array.isArray(policy[name]) ||
          policy[name].length > 256 ||
          policy[name].some((path) => !canonical(path)) ||
          new Set(policy[name]).size !== policy[name].length,
      ) ||
      [value.bindingFingerprint, value.protectedFingerprint].some(
        (entry) => typeof entry !== "string" || !/^[a-f0-9]{64}$/u.test(entry),
      )
    )
      fail("Directory workspace binding is invalid.");
  }
  return structuredClone(value);
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

  const roles = normalizeRoles(value.roles, {
    allowMissingEffort: value.schemaVersion < 8,
  });
  const clientAttribution = normalizeClientAttributionSnapshot(
    value.clientAttribution,
    value.clientAttributionFingerprint,
    value.schemaVersion,
  );
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
    workspace: normalizeWorkspace(value.workspace, value),
    projectConfigurationProtection: normalizeProjectConfigurationProtection(
      value.projectConfigurationProtection,
      value,
    ),
    ...clientAttribution,
    roles,
    providerPolicies: normalizeProviderPolicies(
      value.providerPolicies,
      roles,
      value.schemaVersion,
    ),
    counters: cloneRecord(value.counters, "run.counters"),
    hashes: cloneRecord(value.hashes, "run.hashes"),
    pause,
    sessionLineage: normalizeSessionLineage(value.sessionLineage),
    activeTurn: normalizeActiveTurn(value.activeTurn, value.schemaVersion),
    executionProcess: normalizeExecutionProcess(
      value.executionProcess,
      value.schemaVersion,
    ),
    executionResource: normalizeExecutionResource(
      value.executionResource,
      value.schemaVersion,
    ),
    preparation: normalizePreparation(value.preparation, value),
    preservationRecords: normalizePreservationRecords(
      value.preservationRecords,
      value.schemaVersion,
    ),
    stopRequest: normalizeStopRequest(value.stopRequest, value),
    pipelineState: cloneRecord(value.pipelineState, "run.pipelineState"),
    createdAt,
    updatedAt,
  };
  try {
    Object.assign(
      normalized,
      normalizeAvailabilityState({ ...value, roles }),
      normalizeInactivityState({ ...value, roles }),
    );
    normalized.observations = normalizeObservationState({ ...value, roles });
  } catch {
    fail("Run provider recovery policy or observation evidence is invalid.");
  }
  assertSerializedSize(normalized, "run");
  return normalized;
}

export function normalizeTransitionPatch(value) {
  const patch = value === undefined ? {} : value;
  assertRecord(patch, "transition");
  rejectUnknownFields(patch, TRANSITION_FIELDS, "transition");

  const normalized = {};
  if (Object.hasOwn(patch, "inactivityRecovery")) {
    normalized.inactivityRecovery =
      patch.inactivityRecovery === null
        ? null
        : cloneRecord(
            patch.inactivityRecovery,
            "transition.inactivityRecovery",
          );
  }
  if (Object.hasOwn(patch, "availabilityRetry")) {
    normalized.availabilityRetry =
      patch.availabilityRetry === null
        ? null
        : cloneRecord(patch.availabilityRetry, "transition.availabilityRetry");
  }
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
