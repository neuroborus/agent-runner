import { createHash } from "node:crypto";
import { dirname, isAbsolute, resolve } from "node:path";

const ACCESS_ORDER = Object.freeze([
  "read-only",
  "workspace-write",
  "local-commit",
]);
const ACCESS_MODES = new Set(ACCESS_ORDER);
const REQUEST_FIELDS = Object.freeze([
  "access",
  "authorizationId",
  "commit",
  "contextSize",
  "effort",
  "cwd",
  "model",
  "profile",
  "prompt",
  "recoveryPrompt",
  "schema",
  "session",
  "signal",
  "onProcess",
  "onProgress",
  "onCommitExecution",
  "onFreshSession",
  "onResource",
  "storageForbiddenPaths",
]);
const EXECUTION_FIELDS = Object.freeze([
  "contextSize",
  "effort",
  "model",
  "profile",
]);
const EFFORT_VALUES = new Set(["current", "low", "medium", "high", "xhigh"]);
export const EFFORT_DIAGNOSTIC_CLASS = "effort_unsupported";
export const ADAPTER_FAILURE_CLASS = "adapter_failure";
export const LAUNCH_CHECKPOINTS = Object.freeze([
  "probe",
  "spawn",
  "initialize",
  "session",
  "turn_start",
  "turn",
  "commit",
]);
export const LAUNCH_RECOVERY_CHECKPOINTS = Object.freeze([
  "spawn",
  "initialize",
  "session",
  "turn_start",
]);
export const LAUNCH_OUTCOMES = Object.freeze([
  "not_started",
  "rejected",
  "exited",
  "completed",
  "ambiguous",
]);
export const EFFECT_EVIDENCE = Object.freeze(["none", "possible", "started"]);
export const RETRY_ELIGIBILITY = Object.freeze(["transient", "terminal"]);
export const AVAILABILITY_REASONS = Object.freeze([
  "transport_unavailable",
  "temporarily_overloaded",
  "model_busy",
  "server_unavailable",
]);
export const AUTHENTICATION_REQUIRED_DISPOSITION = "authentication_required";
export const FAILURE_DISPOSITIONS = Object.freeze([
  AUTHENTICATION_REQUIRED_DISPOSITION,
]);
export const PROVIDER_NEUTRAL_LAUNCH_FAILURE_CLASSES = Object.freeze([
  "launch_process_exited",
  "launch_version_unsupported",
  "launch_arguments_unsupported",
  "launch_protocol_incompatible",
  "launch_configuration_rejected",
]);
const SESSION_FIELDS = Object.freeze(["id", "mode"]);
const COMMIT_FIELDS = Object.freeze(["expectedHead", "message"]);
const FAILURE_FIELDS = Object.freeze([
  "failureClass",
  "checkpoint",
  "outcome",
  "effect",
  "retry",
  "commitExecutor",
  "processOutcome",
  "availabilityReason",
  "disposition",
  "reconstruction",
]);
const PROCESS_OUTCOME_FIELDS = Object.freeze(["exitCode", "signal"]);
const CAPABILITY_FIELDS = Object.freeze([
  "version",
  "structuredOutput",
  "readOnly",
  "autonomousWrite",
  "gitMetadataWriteBlocked",
  "workspaceWrite",
  "localCommit",
  "remoteWriteBlocked",
  "nativeSessionContinuation",
  "nativeSessionFork",
  "policyReceipt",
]);
const POLICY_RECEIPT_FIELDS = Object.freeze([
  "schemaVersion",
  "fingerprint",
  "supportedAccess",
]);
const FAILURE_CLASS_PATTERN = /^[a-z][a-z0-9_]{0,63}$/u;
const CAPABILITY_NAME_PATTERN = /^[a-z][A-Za-z0-9]{0,63}$/u;
const SIGNAL_PATTERN = /^SIG[A-Z0-9]{1,15}$/u;
const FINGERPRINT_PATTERN = /^[a-f0-9]{64}$/u;
const OBJECT_ID_PATTERN = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/u;
const CLIENT_ATTRIBUTION_FIELDS = Object.freeze(["name", "title"]);
const MAX_CLIENT_ATTRIBUTION_LENGTH = 256;
const UNSAFE_CLIENT_ATTRIBUTION_PATTERN =
  /[\u0000-\u001f\u007f-\u009f\u2028-\u202e\u2066-\u2069]/u;
const MAX_PROMPT_BYTES = 1024 * 1024;
const MAX_SCHEMA_BYTES = 1024 * 1024;
const MAX_SCHEMA_DEPTH = 128;
const SCHEMA_CHILD_KEYWORDS = Object.freeze([
  "additionalItems",
  "additionalProperties",
  "allOf",
  "anyOf",
  "contains",
  "contentSchema",
  "else",
  "if",
  "items",
  "not",
  "oneOf",
  "prefixItems",
  "propertyNames",
  "then",
  "unevaluatedItems",
  "unevaluatedProperties",
]);
const SCHEMA_MAP_KEYWORDS = Object.freeze([
  "$defs",
  "definitions",
  "dependencies",
  "dependentSchemas",
  "patternProperties",
  "properties",
]);

export const STRUCTURED_OUTPUT_FAILURE_CLASS = "structured-output";
export const DEFAULT_CLIENT_ATTRIBUTION = Object.freeze({
  name: "agent_runner",
  title: "Agent Runner",
});

const CHECKPOINT_SET = new Set(LAUNCH_CHECKPOINTS);
const OUTCOME_SET = new Set(LAUNCH_OUTCOMES);
const EFFECT_SET = new Set(EFFECT_EVIDENCE);
const RETRY_SET = new Set(RETRY_ELIGIBILITY);
const FAILURE_DISPOSITION_SET = new Set(FAILURE_DISPOSITIONS);
const SHARED_FAILURE_CLASS_SET = new Set([
  ADAPTER_FAILURE_CLASS,
  ...PROVIDER_NEUTRAL_LAUNCH_FAILURE_CLASSES,
]);
const DETERMINISTIC_LAUNCH_FAILURE_CLASS_SET = new Set([
  "launch_version_unsupported",
  "launch_arguments_unsupported",
  "launch_protocol_incompatible",
  "launch_configuration_rejected",
]);
const PROCESS_EXIT_OUTCOME_SET = new Set(["exited", "ambiguous"]);

export function isRecord(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

export function isEnvironment(value) {
  return (
    Object.prototype.toString.call(value) === "[object Object]" &&
    Object.values(value).every(
      (entry) => typeof entry === "string" || entry === undefined,
    )
  );
}

function isFilesystemRoot(value) {
  const normalized = resolve(value);
  return dirname(normalized) === normalized;
}

export function isolateGitEnvironment(value) {
  const environment = { ...value };
  for (const name of Object.keys(environment)) {
    const normalizedName = name.toUpperCase();
    if (normalizedName === "EMAIL" || normalizedName.startsWith("GIT_")) {
      delete environment[name];
    }
  }
  environment.GIT_TERMINAL_PROMPT = "0";
  return Object.freeze(environment);
}

export function deepFreeze(value) {
  const pending = [value];
  while (pending.length > 0) {
    const entry = pending.pop();
    if (
      entry !== null &&
      typeof entry === "object" &&
      !Object.isFrozen(entry)
    ) {
      Object.freeze(entry);
      for (const child of Object.values(entry)) {
        pending.push(child);
      }
    }
  }
  return value;
}

function hasExactFields(value, fields, required = fields) {
  const keys = Reflect.ownKeys(value);
  return (
    keys.every((field) => fields.includes(field)) &&
    required.every((field) => Object.hasOwn(value, field))
  );
}

export function normalizeClientAttribution(value) {
  if (
    !isRecord(value) ||
    !hasExactFields(value, CLIENT_ATTRIBUTION_FIELDS) ||
    CLIENT_ATTRIBUTION_FIELDS.some(
      (field) =>
        typeof value[field] !== "string" ||
        value[field].length === 0 ||
        [...value[field]].length > MAX_CLIENT_ATTRIBUTION_LENGTH ||
        value[field].trim() !== value[field] ||
        UNSAFE_CLIENT_ATTRIBUTION_PATTERN.test(value[field]),
    )
  ) {
    throw new TypeError("Client attribution is invalid.");
  }
  return Object.freeze({ name: value.name, title: value.title });
}

export function clientAttributionFingerprint(value) {
  const attribution = normalizeClientAttribution(value);
  return createHash("sha256").update(JSON.stringify(attribution)).digest("hex");
}

export function isDefaultClientAttribution(value) {
  const attribution = normalizeClientAttribution(value);
  return (
    attribution.name === DEFAULT_CLIENT_ATTRIBUTION.name &&
    attribution.title === DEFAULT_CLIENT_ATTRIBUTION.title
  );
}

function isFailureClassList(value) {
  return (
    Array.isArray(value) &&
    value.length <= 256 &&
    new Set(value).size === value.length &&
    [...value].every(
      (entry) => typeof entry === "string" && FAILURE_CLASS_PATTERN.test(entry),
    )
  );
}

function normalizeProcessOutcome(value) {
  if (
    !isRecord(value) ||
    !hasExactFields(value, PROCESS_OUTCOME_FIELDS, []) ||
    Reflect.ownKeys(value).length !== 1 ||
    (Object.hasOwn(value, "exitCode") &&
      (!Number.isInteger(value.exitCode) ||
        value.exitCode < 0 ||
        value.exitCode > 2_147_483_647)) ||
    (Object.hasOwn(value, "signal") &&
      (typeof value.signal !== "string" || !SIGNAL_PATTERN.test(value.signal)))
  ) {
    throw new TypeError("Adapter process outcome is invalid.");
  }
  return Object.freeze(
    Object.hasOwn(value, "exitCode")
      ? { exitCode: value.exitCode }
      : { signal: value.signal },
  );
}

export function normalizeFailureRecord(value, failureClasses = []) {
  if (
    !isFailureClassList(failureClasses) ||
    !isRecord(value) ||
    !hasExactFields(value, FAILURE_FIELDS, [
      "failureClass",
      "checkpoint",
      "outcome",
      "effect",
      "retry",
    ]) ||
    typeof value.failureClass !== "string" ||
    !FAILURE_CLASS_PATTERN.test(value.failureClass) ||
    (!SHARED_FAILURE_CLASS_SET.has(value.failureClass) &&
      !failureClasses.includes(value.failureClass)) ||
    !CHECKPOINT_SET.has(value.checkpoint) ||
    !OUTCOME_SET.has(value.outcome) ||
    !EFFECT_SET.has(value.effect) ||
    !RETRY_SET.has(value.retry) ||
    (Object.hasOwn(value, "commitExecutor") &&
      (value.commitExecutor !== "not_started" ||
        value.checkpoint !== "commit" ||
        !["none", "possible"].includes(value.effect))) ||
    (value.outcome === "not_started" && value.effect !== "none") ||
    (value.outcome === "ambiguous" && value.effect === "none") ||
    (DETERMINISTIC_LAUNCH_FAILURE_CLASS_SET.has(value.failureClass) &&
      (value.outcome !== "rejected" ||
        value.effect !== "none" ||
        value.retry !== "terminal")) ||
    (value.failureClass === "launch_process_exited" &&
      (!PROCESS_EXIT_OUTCOME_SET.has(value.outcome) ||
        (value.outcome === "exited" && value.effect !== "none"))) ||
    (value.processOutcome !== undefined && value.outcome === "not_started") ||
    (Object.hasOwn(value, "availabilityReason") &&
      (!AVAILABILITY_REASONS.includes(value.availabilityReason) ||
        value.retry !== "transient" ||
        !["not_started", "rejected", "exited"].includes(value.outcome) ||
        value.effect === "started" ||
        (value.checkpoint === "commit" &&
          value.commitExecutor !== "not_started"))) ||
    (Object.hasOwn(value, "disposition") &&
      (!FAILURE_DISPOSITION_SET.has(value.disposition) ||
        value.outcome !== "rejected" ||
        value.effect === "started" ||
        value.retry !== "terminal" ||
        value.processOutcome !== undefined ||
        Object.hasOwn(value, "availabilityReason"))) ||
    (Object.hasOwn(value, "reconstruction") &&
      (!isRecord(value.reconstruction) ||
        !hasExactFields(value.reconstruction, ["schemaVersion", "kind"]) ||
        value.reconstruction.schemaVersion !== 1 ||
        value.reconstruction.kind !== "completed_turn_acquisition" ||
        value.failureClass === ADAPTER_FAILURE_CLASS ||
        value.checkpoint !== "turn" ||
        value.outcome !== "rejected" ||
        value.effect !== "possible" ||
        value.retry !== "terminal" ||
        [
          "commitExecutor",
          "processOutcome",
          "availabilityReason",
          "disposition",
        ].some((field) => Object.hasOwn(value, field))))
  ) {
    throw new TypeError("Adapter failure record is invalid.");
  }
  return Object.freeze({
    failureClass: value.failureClass,
    checkpoint: value.checkpoint,
    outcome: value.outcome,
    effect: value.effect,
    retry: value.retry,
    ...(Object.hasOwn(value, "reconstruction")
      ? { reconstruction: Object.freeze({ ...value.reconstruction }) }
      : {}),
    ...(Object.hasOwn(value, "availabilityReason")
      ? { availabilityReason: value.availabilityReason }
      : {}),
    ...(Object.hasOwn(value, "disposition")
      ? { disposition: value.disposition }
      : {}),
    ...(Object.hasOwn(value, "commitExecutor")
      ? { commitExecutor: value.commitExecutor }
      : {}),
    ...(value.processOutcome === undefined
      ? {}
      : { processOutcome: normalizeProcessOutcome(value.processOutcome) }),
  });
}

export function deriveEffectStarted(record) {
  if (record.effect === "none" || record.commitExecutor === "not_started") {
    return false;
  }
  if (record.effect === "started") return true;
  return undefined;
}

export function deriveLaunchRecovery(record) {
  if (
    record.retry !== "transient" ||
    record.effect !== "none" ||
    !["not_started", "exited"].includes(record.outcome) ||
    !LAUNCH_RECOVERY_CHECKPOINTS.includes(record.checkpoint) ||
    Object.hasOwn(record, "commitExecutor")
  ) {
    return undefined;
  }
  return Object.freeze({
    failureClass: record.failureClass,
    checkpoint: record.checkpoint,
  });
}

export function createCapabilityProof(
  capabilities,
  requiredCapabilities,
  policyReceipt,
) {
  if (
    !isRecord(capabilities) ||
    !hasExactFields(capabilities, CAPABILITY_FIELDS, ["version"]) ||
    typeof capabilities.version !== "string" ||
    capabilities.version.length === 0 ||
    capabilities.version.length > 256 ||
    capabilities.version.trim() !== capabilities.version ||
    /[\0\r\n]/u.test(capabilities.version) ||
    !Array.isArray(requiredCapabilities) ||
    requiredCapabilities.length === 0 ||
    requiredCapabilities.length > 32 ||
    new Set(requiredCapabilities).size !== requiredCapabilities.length ||
    [...requiredCapabilities].some(
      (name) =>
        typeof name !== "string" ||
        !CAPABILITY_NAME_PATTERN.test(name) ||
        !CAPABILITY_FIELDS.includes(name) ||
        name === "version" ||
        name === "policyReceipt" ||
        !Object.hasOwn(capabilities, name) ||
        capabilities[name] !== true,
    ) ||
    CAPABILITY_FIELDS.some(
      (name) =>
        name !== "version" &&
        name !== "policyReceipt" &&
        Object.hasOwn(capabilities, name) &&
        typeof capabilities[name] !== "boolean",
    ) ||
    !isRecord(policyReceipt) ||
    !hasExactFields(policyReceipt, POLICY_RECEIPT_FIELDS) ||
    policyReceipt.schemaVersion !== 1 ||
    typeof policyReceipt.fingerprint !== "string" ||
    !FINGERPRINT_PATTERN.test(policyReceipt.fingerprint) ||
    !Array.isArray(policyReceipt.supportedAccess) ||
    policyReceipt.supportedAccess.length > ACCESS_ORDER.length ||
    new Set(policyReceipt.supportedAccess).size !==
      policyReceipt.supportedAccess.length ||
    [...policyReceipt.supportedAccess].some(
      (access) => !ACCESS_ORDER.includes(access),
    ) ||
    ACCESS_ORDER.filter((access) =>
      policyReceipt.supportedAccess.includes(access),
    ).some((access, index) => access !== policyReceipt.supportedAccess[index])
  ) {
    throw new TypeError("Adapter capability proof is invalid.");
  }
  return Object.freeze({
    ...Object.fromEntries(
      CAPABILITY_FIELDS.filter(
        (name) => name !== "policyReceipt" && Object.hasOwn(capabilities, name),
      ).map((name) => [name, capabilities[name]]),
    ),
    requiredCapabilities: Object.freeze([...requiredCapabilities]),
    policyReceipt: Object.freeze({
      schemaVersion: 1,
      fingerprint: policyReceipt.fingerprint,
      supportedAccess: Object.freeze([...policyReceipt.supportedAccess]),
    }),
  });
}

export function createAdapterContract({
  AdapterError,
  backendName,
  failureClasses = [],
  reconstructionClasses = [],
}) {
  const errorPrefix = backendName.toUpperCase();

  if (!isFailureClassList(failureClasses)) {
    throw new TypeError(`${backendName} failure classes are invalid.`);
  }
  const supportedFailureClasses = Object.freeze([...failureClasses]);
  if (
    !isFailureClassList(reconstructionClasses) ||
    reconstructionClasses.some((value) => !failureClasses.includes(value))
  )
    throw new TypeError(`${backendName} reconstruction classes are invalid.`);
  const supportedReconstructionClasses = Object.freeze([
    ...reconstructionClasses,
  ]);

  function optionsError(message) {
    return new AdapterError(message, {
      code: `ERR_INVALID_${errorPrefix}_OPTIONS`,
    });
  }

  function schemaError(message) {
    return new AdapterError(message, {
      code: `ERR_INVALID_${errorPrefix}_SCHEMA`,
    });
  }

  function assertFields(value, fields, name) {
    if (!isRecord(value)) {
      throw optionsError(`${name} must be an object.`);
    }
    const unknown = Object.keys(value).find((field) => !fields.includes(field));
    if (unknown !== undefined) {
      throw optionsError(`${name} field is not supported: ${unknown}.`);
    }
    return value;
  }

  function assertString(value, name, maximumLength = 4096) {
    if (
      typeof value !== "string" ||
      value.length === 0 ||
      value.length > maximumLength ||
      /[\0\r\n]/u.test(value)
    ) {
      throw optionsError(`${name} is invalid.`);
    }
    return value;
  }

  function assertJsonValue(value) {
    const ancestors = new Set();
    const pending = [{ depth: 0, value }];
    while (pending.length > 0) {
      const entry = pending.pop();
      if (entry.exit === true) {
        ancestors.delete(entry.value);
        continue;
      }
      if (
        entry.value === null ||
        typeof entry.value === "string" ||
        typeof entry.value === "boolean" ||
        (typeof entry.value === "number" && Number.isFinite(entry.value))
      ) {
        continue;
      }
      if (typeof entry.value !== "object" || ancestors.has(entry.value)) {
        throw schemaError("JSON Schema must contain only JSON values.");
      }
      if (entry.depth > MAX_SCHEMA_DEPTH) {
        throw schemaError("JSON Schema is too deeply nested.");
      }
      let children;
      if (Array.isArray(entry.value)) {
        children = entry.value;
      } else if (isRecord(entry.value)) {
        children = Object.values(entry.value);
      } else {
        throw schemaError("JSON Schema must be a plain JSON object.");
      }
      ancestors.add(entry.value);
      pending.push({ exit: true, value: entry.value });
      for (let index = children.length - 1; index >= 0; index -= 1) {
        pending.push({ depth: entry.depth + 1, value: children[index] });
      }
    }
  }

  function assertStrictObjectSchemas(schema) {
    const pending = [schema];
    while (pending.length > 0) {
      const entry = pending.pop();
      if (Array.isArray(entry)) {
        for (const child of entry) {
          pending.push(child);
        }
        continue;
      }
      if (!isRecord(entry)) {
        continue;
      }
      const describesObject =
        entry.type === "object" ||
        (Array.isArray(entry.type) && entry.type.includes("object")) ||
        entry.properties !== undefined;
      if (describesObject) {
        const properties = isRecord(entry.properties)
          ? Object.keys(entry.properties)
          : [];
        if (
          !isRecord(entry.properties) ||
          entry.additionalProperties !== false ||
          !Array.isArray(entry.required) ||
          entry.required.length !== properties.length ||
          new Set(entry.required).size !== properties.length ||
          properties.some((property) => !entry.required.includes(property))
        ) {
          throw schemaError(
            "Object schemas must declare properties, every required field, " +
              "and additionalProperties: false.",
          );
        }
      }
      for (const keyword of SCHEMA_CHILD_KEYWORDS) {
        if (entry[keyword] !== undefined) {
          pending.push(entry[keyword]);
        }
      }
      for (const keyword of SCHEMA_MAP_KEYWORDS) {
        if (isRecord(entry[keyword])) {
          for (const child of Object.values(entry[keyword])) {
            pending.push(child);
          }
        }
      }
    }
  }

  function normalizeSchema(value) {
    if (value === undefined) {
      return undefined;
    }
    assertJsonValue(value);
    if (!isRecord(value) || value.type !== "object") {
      throw schemaError(
        `${backendName} output schema must describe an object.`,
      );
    }
    assertStrictObjectSchemas(value);
    const source = JSON.stringify(value);
    if (Buffer.byteLength(source) > MAX_SCHEMA_BYTES) {
      throw schemaError(`${backendName} output schema is too large.`);
    }
    return deepFreeze(JSON.parse(source));
  }

  function normalizeSession(value) {
    if (value === undefined) {
      return undefined;
    }
    assertFields(value, SESSION_FIELDS, `${backendName} session`);
    if (!["continue", "fork"].includes(value.mode)) {
      throw optionsError(`${backendName} session mode is invalid.`);
    }
    return Object.freeze({
      id: assertString(value.id, `${backendName} session ID`),
      mode: value.mode,
    });
  }

  function normalizePrompt(value, name) {
    if (
      typeof value !== "string" ||
      value.trim().length === 0 ||
      /\0/u.test(value) ||
      Buffer.byteLength(value) > MAX_PROMPT_BYTES
    ) {
      throw optionsError(`${name} is invalid.`);
    }
    return value;
  }

  function normalizeCommit(value) {
    assertFields(value, COMMIT_FIELDS, `${backendName} commit constraint`);
    if (
      typeof value.expectedHead !== "string" ||
      !OBJECT_ID_PATTERN.test(value.expectedHead) ||
      typeof value.message !== "string" ||
      value.message.length === 0 ||
      value.message.trim() !== value.message ||
      /[\0\r\n]/u.test(value.message) ||
      [...value.message].length > 72
    ) {
      throw optionsError(`${backendName} commit constraint is invalid.`);
    }
    return Object.freeze({
      expectedHead: value.expectedHead,
      message: value.message,
    });
  }

  function normalizeExecutionOptions(value = {}) {
    assertFields(value, EXECUTION_FIELDS, `${backendName} execution options`);
    if (value.effort !== undefined && !EFFORT_VALUES.has(value.effort)) {
      throw optionsError(
        "Effort must be current, low, medium, high, or xhigh.",
      );
    }
    if (typeof value.model === "string" && /\s/u.test(value.model)) {
      throw optionsError(
        "Model must be one identifier; select effort separately.",
      );
    }
    return Object.freeze({
      effort:
        value.effort === undefined || value.effort === "current"
          ? undefined
          : value.effort,
      contextSize:
        value.contextSize === undefined || value.contextSize === "current"
          ? undefined
          : assertString(value.contextSize, `${backendName} context size`, 64),
      model:
        value.model === undefined || value.model === "current"
          ? undefined
          : assertString(value.model, `${backendName} model`, 256),
      profile:
        value.profile === undefined || value.profile === "current"
          ? undefined
          : assertString(value.profile, `${backendName} profile`),
    });
  }

  function normalizeRequest(value) {
    assertFields(value, REQUEST_FIELDS, `${backendName} request`);
    if (
      (value.signal !== undefined && !(value.signal instanceof AbortSignal)) ||
      (value.onProcess !== undefined &&
        typeof value.onProcess !== "function") ||
      (value.onFreshSession !== undefined &&
        typeof value.onFreshSession !== "function") ||
      (value.onCommitExecution !== undefined &&
        typeof value.onCommitExecution !== "function") ||
      (value.onProgress !== undefined &&
        typeof value.onProgress !== "function") ||
      (value.onResource !== undefined &&
        typeof value.onResource !== "function") ||
      (value.storageForbiddenPaths !== undefined &&
        (!Array.isArray(value.storageForbiddenPaths) ||
          value.storageForbiddenPaths.length > 256 ||
          value.storageForbiddenPaths.some(
            (path) =>
              typeof path !== "string" ||
              !isAbsolute(path) ||
              resolve(path) !== path ||
              /[\0\r\n]/u.test(path),
          )))
    ) {
      throw optionsError("Execution cancellation boundary is invalid.");
    }
    if (
      typeof value.cwd !== "string" ||
      !isAbsolute(value.cwd) ||
      isFilesystemRoot(value.cwd) ||
      /[\0\r\n]/u.test(value.cwd) ||
      !ACCESS_MODES.has(value.access)
    ) {
      throw optionsError(`${backendName} request is invalid.`);
    }
    const prompt = normalizePrompt(value.prompt, `${backendName} prompt`);
    const execution = normalizeExecutionOptions({
      contextSize: value.contextSize,
      effort: value.effort,
      model: value.model,
      profile: value.profile,
    });
    const normalized = {
      access: value.access,
      ...execution,
      cwd: value.cwd,
      prompt,
      recoveryPrompt:
        value.recoveryPrompt === undefined
          ? prompt
          : normalizePrompt(
              value.recoveryPrompt,
              `${backendName} recovery prompt`,
            ),
      schema: normalizeSchema(value.schema),
      session: normalizeSession(value.session),
      ...(value.signal === undefined ? {} : { signal: value.signal }),
      ...(value.onProcess === undefined ? {} : { onProcess: value.onProcess }),
      ...(value.onFreshSession === undefined
        ? {}
        : { onFreshSession: value.onFreshSession }),
      ...(value.onCommitExecution === undefined
        ? {}
        : { onCommitExecution: value.onCommitExecution }),
      ...(value.onProgress === undefined
        ? {}
        : { onProgress: value.onProgress }),
      ...(value.onResource === undefined
        ? {}
        : { onResource: value.onResource }),
      ...(value.storageForbiddenPaths === undefined
        ? {}
        : {
            storageForbiddenPaths: Object.freeze([
              ...value.storageForbiddenPaths,
            ]),
          }),
    };
    if (value.access === "local-commit") {
      if (normalized.schema !== undefined) {
        throw optionsError(
          "Local-commit requests use the adapter confirmation schema.",
        );
      }
      normalized.authorizationId = assertString(
        value.authorizationId,
        "Commit authorization ID",
      );
      normalized.commit = normalizeCommit(value.commit);
    } else if (
      value.authorizationId !== undefined ||
      value.commit !== undefined
    ) {
      throw optionsError("Commit constraints require local-commit access.");
    }
    return Object.freeze(normalized);
  }

  return Object.freeze({
    assertFields,
    effortError: () =>
      new AdapterError(
        "Selected effort is unsupported by the provider or model.",
        {
          code: "ERR_UNSUPPORTED_EFFORT",
          diagnosticClass: EFFORT_DIAGNOSTIC_CLASS,
        },
      ),
    failure(value) {
      const record = normalizeFailureRecord(value, supportedFailureClasses);
      if (
        record.reconstruction !== undefined &&
        !supportedReconstructionClasses.includes(record.failureClass)
      )
        throw new TypeError("Adapter reconstruction evidence is unsupported.");
      return record;
    },
    normalizeExecutionOptions,
    normalizeRequest,
  });
}
