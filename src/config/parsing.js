import { isAbsolute, posix, resolve } from "node:path";

import { BACKEND_IDS } from "../agents/index.js";
import { listPipelines } from "../pipeline-registry.js";
import {
  createTrustedValidationSnapshot,
  normalizeTrustedValidationDefinitions,
} from "../trusted-validation/index.js";

export const CONFIG_FILENAME = ".agent-runner.json";
export const DEFAULT_ARTIFACT_ROOT = "LOCAL_ARTIFACTS";
export const PROJECT_CONFIG_FILENAME = "agent-runner.json";
export const CONFIG_SCHEMA_VERSION = 1;

const BACKENDS = new Set(BACKEND_IDS);
export const CURRENT = "current";
const PROFILE_NAME_PATTERN = /^[a-z][a-z0-9-]{0,63}$/u;
const TOP_LEVEL_FIELDS = new Set([
  "artifactRoot",
  "schemaVersion",
  "defaultBackend",
  "defaultContextSize",
  "defaultModel",
  "defaultProfile",
  "issueReporting",
  "pipelines",
  "profiles",
  "trustedCommands",
]);
const PROJECT_TOP_LEVEL_FIELDS = new Set(
  [...TOP_LEVEL_FIELDS].filter(
    (field) =>
      !["issueReporting", "profiles", "trustedCommands"].includes(field),
  ),
);
const ROLE_FIELDS = new Set(["backend", "contextSize", "model", "profile"]);
const PROFILE_FIELDS = Object.freeze({
  claude: new Set(["backend", "configDirectory"]),
  codex: new Set(["backend", "profile"]),
});

export class ConfigurationError extends Error {
  constructor(message, { cause, code = "ERR_INVALID_CONFIGURATION" } = {}) {
    super(message, { cause });
    this.name = "ConfigurationError";
    this.code = code;
  }
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function assertRecord(value, path) {
  if (!isRecord(value)) {
    throw new ConfigurationError(`${path} must be an object.`);
  }
}

export function rejectUnknownFields(value, allowedFields, path) {
  const unknownField = Object.keys(value).find(
    (field) => !allowedFields.has(field),
  );

  if (unknownField !== undefined) {
    throw new ConfigurationError(`${path}.${unknownField} is not supported.`);
  }
}

export function assertBackend(value, path) {
  if (typeof value !== "string" || !BACKENDS.has(value)) {
    throw new ConfigurationError(
      `${path} must be one of: ${BACKEND_IDS.join(", ")}.`,
    );
  }
}

export function assertSelection(value, path) {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new ConfigurationError(`${path} must be a non-empty string.`);
  }
}

function assertArtifactRoot(value, path) {
  assertSelection(value, path);
  if (
    value.includes("\\") ||
    /^[a-zA-Z]:\//u.test(value) ||
    posix.isAbsolute(value) ||
    posix.normalize(value) !== value ||
    value === "." ||
    value === ".." ||
    value.startsWith("../") ||
    value === ".git" ||
    value.startsWith(".git/") ||
    /[\0\p{Cc}\p{Zl}\p{Zp}]/u.test(value)
  ) {
    throw new ConfigurationError(
      `${path} must be a normalized repository-relative directory.`,
    );
  }
}

export function normalizeRole(role, path) {
  assertRecord(role, path);
  rejectUnknownFields(role, ROLE_FIELDS, path);

  const normalized = {};
  if (role.backend !== undefined) {
    assertBackend(role.backend, `${path}.backend`);
    normalized.backend = role.backend;
  }
  for (const field of ["profile", "model", "contextSize"]) {
    if (role[field] !== undefined) {
      assertSelection(role[field], `${path}.${field}`);
      normalized[field] = role[field];
    }
  }

  return Object.freeze(normalized);
}

function normalizeProfile(name, value) {
  const path = `configuration.profiles.${name}`;
  if (!PROFILE_NAME_PATTERN.test(name) || name === CURRENT) {
    throw new ConfigurationError(
      "configuration profile names must be lowercase kebab-case aliases other than current.",
    );
  }
  assertRecord(value, path);
  assertBackend(value.backend, `${path}.backend`);
  rejectUnknownFields(value, PROFILE_FIELDS[value.backend], path);

  if (value.backend === "codex") {
    assertSelection(value.profile, `${path}.profile`);
    if (value.profile === CURRENT) {
      throw new ConfigurationError(`${path}.profile must not be current.`);
    }
    return Object.freeze({ backend: value.backend, profile: value.profile });
  }

  assertSelection(value.configDirectory, `${path}.configDirectory`);
  if (
    !isAbsolute(value.configDirectory) ||
    resolve(value.configDirectory) !== value.configDirectory
  ) {
    throw new ConfigurationError(
      `${path}.configDirectory must be an absolute normalized path.`,
    );
  }
  return Object.freeze({
    backend: value.backend,
    configDirectory: value.configDirectory,
  });
}

function normalizeTrustedCommands(value) {
  assertRecord(value, "configuration.trustedCommands");
  try {
    return normalizeTrustedValidationDefinitions(value);
  } catch (cause) {
    throw new ConfigurationError(cause.message, { cause });
  }
}

function assertKnownTrustedSelection(settings, trustedCommands, path) {
  if (!Object.hasOwn(settings, "trustedChecks")) {
    return;
  }
  try {
    createTrustedValidationSnapshot(trustedCommands, settings.trustedChecks);
  } catch (cause) {
    throw new ConfigurationError(
      `${path}.trustedChecks is invalid: ${cause.message}`,
      {
        cause,
        code: cause.code,
      },
    );
  }
}

function normalizePipeline(
  pipeline,
  input,
  { applyDefaults = true, rootPath = "configuration" } = {},
) {
  const path = `${rootPath}.pipelines.${pipeline.id}`;
  assertRecord(input, path);
  rejectUnknownFields(
    input,
    new Set(["roles", ...Object.keys(pipeline.settings)]),
    path,
  );

  const normalized = {};
  for (const [settingName, definition] of Object.entries(pipeline.settings)) {
    const value = input[settingName];
    if (value === undefined && !applyDefaults) {
      continue;
    }
    const resolvedValue = value === undefined ? definition.defaultValue : value;
    if (!definition.validate(resolvedValue)) {
      throw new ConfigurationError(
        `${path}.${settingName} ${definition.errorMessage}.`,
      );
    }
    normalized[settingName] = Array.isArray(resolvedValue)
      ? Object.freeze([...resolvedValue])
      : resolvedValue;
  }

  const inputRoles = input.roles === undefined ? {} : input.roles;
  assertRecord(inputRoles, `${path}.roles`);
  const unknownRole = Object.keys(inputRoles).find(
    (role) => !pipeline.roles.includes(role),
  );
  if (unknownRole !== undefined) {
    throw new ConfigurationError(
      `${path}.roles.${unknownRole} is not a supported role.`,
    );
  }

  normalized.roles = Object.freeze(
    Object.fromEntries(
      Object.entries(inputRoles).map(([role, value]) => [
        role,
        normalizeRole(value, `${path}.roles.${role}`),
      ]),
    ),
  );

  return Object.freeze(normalized);
}

export function normalizeConfiguration(input) {
  assertRecord(input, "configuration");
  rejectUnknownFields(input, TOP_LEVEL_FIELDS, "configuration");

  if (!Object.hasOwn(input, "schemaVersion")) {
    throw new ConfigurationError("configuration.schemaVersion is required.");
  }
  if (input.schemaVersion !== CONFIG_SCHEMA_VERSION) {
    throw new ConfigurationError(
      `Unsupported configuration.schemaVersion: ${String(input.schemaVersion)}.`,
      { code: "ERR_UNSUPPORTED_CONFIGURATION_VERSION" },
    );
  }
  if (input.defaultBackend !== undefined) {
    assertBackend(input.defaultBackend, "configuration.defaultBackend");
  }
  if (input.artifactRoot !== undefined) {
    assertArtifactRoot(input.artifactRoot, "configuration.artifactRoot");
  }
  if (
    input.issueReporting !== undefined &&
    typeof input.issueReporting !== "boolean"
  ) {
    throw new ConfigurationError(
      "configuration.issueReporting must be a boolean.",
    );
  }
  for (const field of [
    "defaultProfile",
    "defaultModel",
    "defaultContextSize",
  ]) {
    if (input[field] !== undefined) {
      assertSelection(input[field], `configuration.${field}`);
    }
  }

  const inputProfiles = input.profiles === undefined ? {} : input.profiles;
  assertRecord(inputProfiles, "configuration.profiles");
  const profiles = Object.freeze(
    Object.fromEntries(
      Object.entries(inputProfiles).map(([name, value]) => [
        name,
        normalizeProfile(name, value),
      ]),
    ),
  );
  const trustedCommands = normalizeTrustedCommands(
    input.trustedCommands === undefined ? {} : input.trustedCommands,
  );

  const inputPipelines = input.pipelines === undefined ? {} : input.pipelines;
  assertRecord(inputPipelines, "configuration.pipelines");
  const pipelines = listPipelines();
  const pipelineIds = new Set(pipelines.map((pipeline) => pipeline.id));
  const unknownPipeline = Object.keys(inputPipelines).find(
    (pipelineId) => !pipelineIds.has(pipelineId),
  );
  if (unknownPipeline !== undefined) {
    throw new ConfigurationError(
      `configuration.pipelines.${unknownPipeline} is not supported.`,
    );
  }

  const normalized = {
    schemaVersion: CONFIG_SCHEMA_VERSION,
    artifactRoot: input.artifactRoot ?? DEFAULT_ARTIFACT_ROOT,
    issueReporting: input.issueReporting ?? true,
    defaultProfile: input.defaultProfile ?? CURRENT,
    defaultModel: input.defaultModel ?? CURRENT,
    defaultContextSize: input.defaultContextSize ?? CURRENT,
    profiles,
    trustedCommands,
    pipelines: Object.freeze(
      Object.fromEntries(
        pipelines.map((pipeline) => [
          pipeline.id,
          normalizePipeline(
            pipeline,
            inputPipelines[pipeline.id] === undefined
              ? {}
              : inputPipelines[pipeline.id],
          ),
        ]),
      ),
    ),
  };
  if (input.defaultBackend !== undefined) {
    normalized.defaultBackend = input.defaultBackend;
  }

  for (const [selection, path] of [
    [normalized.defaultProfile, "configuration.defaultProfile"],
    ...pipelines.flatMap((pipeline) =>
      Object.entries(normalized.pipelines[pipeline.id].roles).map(
        ([role, configuration]) => [
          configuration.profile,
          `configuration.pipelines.${pipeline.id}.roles.${role}.profile`,
        ],
      ),
    ),
  ]) {
    if (
      selection !== undefined &&
      selection !== CURRENT &&
      !Object.hasOwn(profiles, selection)
    ) {
      throw new ConfigurationError(
        `${path} selects unknown profile: ${selection}.`,
        { code: "ERR_UNKNOWN_PROFILE" },
      );
    }
  }
  for (const pipeline of pipelines) {
    assertKnownTrustedSelection(
      normalized.pipelines[pipeline.id],
      trustedCommands,
      `configuration.pipelines.${pipeline.id}`,
    );
  }

  return Object.freeze(normalized);
}

export function normalizeProjectConfiguration(input, runnerConfiguration) {
  const rootPath = "projectConfiguration";
  assertRecord(input, rootPath);
  rejectUnknownFields(input, PROJECT_TOP_LEVEL_FIELDS, rootPath);
  if (!Object.hasOwn(input, "schemaVersion")) {
    throw new ConfigurationError(
      "projectConfiguration.schemaVersion is required.",
    );
  }
  if (input.schemaVersion !== CONFIG_SCHEMA_VERSION) {
    throw new ConfigurationError(
      `Unsupported projectConfiguration.schemaVersion: ${String(input.schemaVersion)}.`,
      { code: "ERR_UNSUPPORTED_CONFIGURATION_VERSION" },
    );
  }
  if (input.artifactRoot !== undefined) {
    assertArtifactRoot(input.artifactRoot, `${rootPath}.artifactRoot`);
  }
  if (input.defaultBackend !== undefined) {
    assertBackend(input.defaultBackend, `${rootPath}.defaultBackend`);
  }
  for (const field of [
    "defaultProfile",
    "defaultModel",
    "defaultContextSize",
  ]) {
    if (input[field] !== undefined) {
      assertSelection(input[field], `${rootPath}.${field}`);
    }
  }

  const inputPipelines = input.pipelines === undefined ? {} : input.pipelines;
  assertRecord(inputPipelines, `${rootPath}.pipelines`);
  const pipelines = listPipelines();
  const pipelineIds = new Set(pipelines.map(({ id }) => id));
  const unknownPipeline = Object.keys(inputPipelines).find(
    (pipelineId) => !pipelineIds.has(pipelineId),
  );
  if (unknownPipeline !== undefined) {
    throw new ConfigurationError(
      `${rootPath}.pipelines.${unknownPipeline} is not supported.`,
    );
  }

  const normalized = {
    schemaVersion: CONFIG_SCHEMA_VERSION,
    pipelines: Object.freeze(
      Object.fromEntries(
        pipelines.flatMap((pipeline) =>
          inputPipelines[pipeline.id] === undefined
            ? []
            : [
                [
                  pipeline.id,
                  normalizePipeline(pipeline, inputPipelines[pipeline.id], {
                    applyDefaults: false,
                    rootPath,
                  }),
                ],
              ],
        ),
      ),
    ),
  };
  for (const field of [
    "artifactRoot",
    "defaultBackend",
    "defaultProfile",
    "defaultModel",
    "defaultContextSize",
  ]) {
    if (input[field] !== undefined) {
      normalized[field] = input[field];
    }
  }

  for (const [selection, path] of [
    [normalized.defaultProfile, `${rootPath}.defaultProfile`],
    ...pipelines.flatMap((pipeline) =>
      Object.entries(normalized.pipelines[pipeline.id]?.roles ?? {}).map(
        ([role, configuration]) => [
          configuration.profile,
          `${rootPath}.pipelines.${pipeline.id}.roles.${role}.profile`,
        ],
      ),
    ),
  ]) {
    if (
      selection !== undefined &&
      selection !== CURRENT &&
      !Object.hasOwn(runnerConfiguration.profiles, selection)
    ) {
      throw new ConfigurationError(
        `${path} selects unknown trusted profile: ${selection}.`,
        { code: "ERR_UNKNOWN_PROFILE" },
      );
    }
  }
  for (const pipeline of pipelines) {
    const settings = normalized.pipelines[pipeline.id];
    if (settings !== undefined) {
      assertKnownTrustedSelection(
        settings,
        runnerConfiguration.trustedCommands,
        `${rootPath}.pipelines.${pipeline.id}`,
      );
    }
  }

  return Object.freeze(normalized);
}

export function parseRunnerConfiguration(source) {
  if (typeof source !== "string") {
    throw new ConfigurationError("Configuration source must be a string.");
  }

  let parsed;
  try {
    parsed = JSON.parse(source);
  } catch (cause) {
    throw new ConfigurationError("Configuration must contain valid JSON.", {
      cause,
    });
  }

  return normalizeConfiguration(parsed);
}

export function parseProjectConfiguration(source, runnerConfiguration) {
  if (typeof source !== "string") {
    throw new ConfigurationError(
      "Project configuration source must be a string.",
    );
  }

  let parsed;
  try {
    parsed = JSON.parse(source);
  } catch (cause) {
    throw new ConfigurationError(
      "Project configuration must contain valid JSON.",
      { cause },
    );
  }

  return normalizeProjectConfiguration(
    parsed,
    normalizeConfiguration(runnerConfiguration),
  );
}
