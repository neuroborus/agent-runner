import { constants } from "node:fs";
import { lstat, open, readFile } from "node:fs/promises";
import { isAbsolute, join, posix, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { BACKEND_IDS } from "./agents/index.js";
import { getPipeline, listPipelines } from "./pipeline-registry.js";

export const CONFIG_FILENAME = ".agent-runner.json";
export const DEFAULT_ARTIFACT_ROOT = "LOCAL_ARTIFACTS";
export const PROJECT_CONFIG_FILENAME = "agent-runner.json";
const CONFIG_PATH = fileURLToPath(
  new URL(`../${CONFIG_FILENAME}`, import.meta.url),
);
export const CONFIG_SCHEMA_VERSION = 1;
const MAX_CONFIGURATION_BYTES = 1024 * 1024;
const NO_FOLLOW = constants.O_NOFOLLOW ?? 0;
const NONBLOCK = constants.O_NONBLOCK ?? 0;

const BACKENDS = new Set(BACKEND_IDS);
const CURRENT = "current";
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
]);
const PROJECT_TOP_LEVEL_FIELDS = new Set(
  [...TOP_LEVEL_FIELDS].filter(
    (field) => !["issueReporting", "profiles"].includes(field),
  ),
);
const ROLE_FIELDS = new Set(["backend", "contextSize", "model", "profile"]);
const EXECUTION_FIELDS = new Set(["contextSize", "model", "profile"]);
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

function assertRecord(value, path) {
  if (!isRecord(value)) {
    throw new ConfigurationError(`${path} must be an object.`);
  }
}

function rejectUnknownFields(value, allowedFields, path) {
  const unknownField = Object.keys(value).find(
    (field) => !allowedFields.has(field),
  );

  if (unknownField !== undefined) {
    throw new ConfigurationError(`${path}.${unknownField} is not supported.`);
  }
}

function assertBackend(value, path) {
  if (typeof value !== "string" || !BACKENDS.has(value)) {
    throw new ConfigurationError(
      `${path} must be one of: ${BACKEND_IDS.join(", ")}.`,
    );
  }
}

function assertSelection(value, path) {
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

function normalizeRole(role, path) {
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

function normalizeExecution(value, path) {
  assertRecord(value, path);
  rejectUnknownFields(value, EXECUTION_FIELDS, path);
  return normalizeRole(value, path);
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
    const resolvedValue =
      value === undefined ? definition.defaultValue : value;
    if (!definition.validate(resolvedValue)) {
      throw new ConfigurationError(
        `${path}.${settingName} ${definition.errorMessage}.`,
      );
    }
    normalized[settingName] = resolvedValue;
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

function normalizeConfiguration(input) {
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

  return Object.freeze(normalized);
}

function normalizeProjectConfiguration(input, runnerConfiguration) {
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

  const inputPipelines =
    input.pipelines === undefined ? {} : input.pipelines;
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

  return Object.freeze(normalized);
}

function selectedProfile(configuration, selection, path) {
  if (selection === CURRENT) {
    return null;
  }
  const profile = configuration.profiles[selection];
  if (profile === undefined) {
    throw new ConfigurationError(
      `${path} selects unknown profile: ${selection}.`,
      { code: "ERR_UNKNOWN_PROFILE" },
    );
  }
  return profile;
}

function profileImplementation(profile) {
  return profile === null
    ? CURRENT
    : profile.backend === "codex"
      ? profile.profile
      : profile.configDirectory;
}

function normalizeSourceSession(value) {
  if (value === undefined || value === null) {
    return null;
  }
  assertRecord(value, "sourceSession");
  rejectUnknownFields(
    value,
    new Set(["backend", "id", "profile"]),
    "sourceSession",
  );
  assertBackend(value.backend, "sourceSession.backend");
  assertSelection(value.id, "sourceSession.id");
  if (value.profile !== undefined) {
    assertSelection(value.profile, "sourceSession.profile");
  }
  return Object.freeze({
    backend: value.backend,
    id: value.id,
    profile: value.profile ?? CURRENT,
  });
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

async function readConfinedConfiguration(path) {
  let handle;
  try {
    const pathBefore = await lstat(path, { bigint: true });
    if (
      !pathBefore.isFile() ||
      pathBefore.size > BigInt(MAX_CONFIGURATION_BYTES)
    ) {
      throw new ConfigurationError(
        "Project configuration must be a bounded regular file.",
        { code: "ERR_PROJECT_CONFIGURATION_READ" },
      );
    }
    handle = await open(path, constants.O_RDONLY | NO_FOLLOW | NONBLOCK);
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.size > BigInt(MAX_CONFIGURATION_BYTES)) {
      throw new ConfigurationError(
        "Project configuration must be a bounded regular file.",
        { code: "ERR_PROJECT_CONFIGURATION_READ" },
      );
    }
    if (
      pathBefore.dev !== before.dev ||
      pathBefore.ino !== before.ino ||
      pathBefore.size !== before.size ||
      pathBefore.mtimeNs !== before.mtimeNs ||
      pathBefore.ctimeNs !== before.ctimeNs
    ) {
      throw new ConfigurationError(
        "Project configuration changed while it was read.",
        { code: "ERR_PROJECT_CONFIGURATION_READ" },
      );
    }
    const buffer = Buffer.allocUnsafe(MAX_CONFIGURATION_BYTES + 1);
    let length = 0;
    while (length < buffer.length) {
      const { bytesRead } = await handle.read(
        buffer,
        length,
        buffer.length - length,
        null,
      );
      if (bytesRead === 0) {
        break;
      }
      length += bytesRead;
    }
    const source = buffer.subarray(0, length);
    if (source.length > MAX_CONFIGURATION_BYTES) {
      throw new ConfigurationError(
        "Project configuration must be a bounded regular file.",
        { code: "ERR_PROJECT_CONFIGURATION_READ" },
      );
    }
    const [after, pathAfter] = await Promise.all([
      handle.stat({ bigint: true }),
      lstat(path, { bigint: true }),
    ]);
    if (
      !pathAfter.isFile() ||
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.size !== after.size ||
      before.mtimeNs !== after.mtimeNs ||
      before.ctimeNs !== after.ctimeNs ||
      after.dev !== pathAfter.dev ||
      after.ino !== pathAfter.ino ||
      after.size !== pathAfter.size ||
      after.mtimeNs !== pathAfter.mtimeNs ||
      after.ctimeNs !== pathAfter.ctimeNs
    ) {
      throw new ConfigurationError(
        "Project configuration changed while it was read.",
        { code: "ERR_PROJECT_CONFIGURATION_READ" },
      );
    }
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(source);
    } catch (cause) {
      throw new ConfigurationError(
        "Project configuration must contain valid UTF-8.",
        { cause, code: "ERR_PROJECT_CONFIGURATION_READ" },
      );
    }
  } catch (cause) {
    if (cause instanceof ConfigurationError) {
      throw cause;
    }
    throw new ConfigurationError(
      `Cannot read project configuration at ${path}.`,
      { cause, code: "ERR_PROJECT_CONFIGURATION_READ" },
    );
  } finally {
    await handle?.close();
  }
}

export async function loadProjectConfiguration({
  configurationPath,
  inspectPath,
  projectPath,
  runnerConfiguration,
}) {
  if (typeof inspectPath !== "function") {
    throw new ConfigurationError(
      "Project configuration path inspection is unavailable.",
      { code: "ERR_PROJECT_CONFIGURATION_READ" },
    );
  }
  const explicit = configurationPath !== undefined;
  if (
    explicit &&
    (typeof configurationPath !== "string" ||
      configurationPath.trim().length === 0)
  ) {
    throw new ConfigurationError(
      "Project configuration path must be a non-empty string.",
    );
  }
  const requestedPath =
    configurationPath ??
    join(projectPath, DEFAULT_ARTIFACT_ROOT, PROJECT_CONFIG_FILENAME);
  const inspection = await inspectPath({ path: requestedPath, projectPath });
  if (!inspection.exists) {
    if (!explicit) {
      return null;
    }
    throw new ConfigurationError(
      `Project configuration does not exist at ${inspection.path}.`,
      { code: "ERR_PROJECT_CONFIGURATION_READ" },
    );
  }
  if (inspection.tracked || !inspection.ignored) {
    throw new ConfigurationError(
      "Project configuration must be ignored and untracked.",
      { code: "ERR_PROJECT_CONFIGURATION_NOT_IGNORED" },
    );
  }
  return Object.freeze({
    path: inspection.path,
    configuration: parseProjectConfiguration(
      await readConfinedConfiguration(inspection.path),
      runnerConfiguration,
    ),
  });
}

export async function loadRunnerConfiguration() {
  let source;
  try {
    source = await readFile(CONFIG_PATH, "utf8");
  } catch (cause) {
    if (cause?.code === "ENOENT") {
      return normalizeConfiguration({ schemaVersion: CONFIG_SCHEMA_VERSION });
    }

    throw new ConfigurationError(
      `Cannot read runner configuration at ${CONFIG_PATH}.`,
      { cause, code: "ERR_CONFIGURATION_READ" },
    );
  }

  return parseRunnerConfiguration(source);
}

export function resolvePipelineConfiguration(
  pipelineId,
  configuration,
  roleOverrides = {},
  executionOverrides = {},
  sourceSession = null,
  projectConfiguration = null,
) {
  const pipeline = getPipeline(pipelineId);
  if (pipeline === undefined) {
    throw new ConfigurationError(`Unknown pipeline: ${pipelineId}.`, {
      code: "ERR_UNKNOWN_PIPELINE",
    });
  }
  const normalizedConfiguration = normalizeConfiguration(configuration);
  const normalizedProjectConfiguration =
    projectConfiguration === null
      ? null
      : normalizeProjectConfiguration(
          projectConfiguration,
          normalizedConfiguration,
        );
  assertRecord(roleOverrides, "roleOverrides");
  const normalizedExecutionOverrides = normalizeExecution(
    executionOverrides,
    "executionOverrides",
  );
  const normalizedSourceSession = normalizeSourceSession(sourceSession);

  const unknownRole = Object.keys(roleOverrides).find(
    (role) => !pipeline.roles.includes(role),
  );
  if (unknownRole !== undefined) {
    throw new ConfigurationError(
      `roleOverrides.${unknownRole} is not a supported role for ${pipelineId}.`,
    );
  }

  const pipelineConfiguration = normalizedConfiguration.pipelines[pipelineId];
  const projectPipelineConfiguration =
    normalizedProjectConfiguration?.pipelines[pipelineId] ?? {};

  let sourceProfile = null;
  if (
    normalizedSourceSession !== null &&
    normalizedSourceSession.profile !== CURRENT
  ) {
    sourceProfile = selectedProfile(
      normalizedConfiguration,
      normalizedSourceSession.profile,
      "sourceSession.profile",
    );
    if (sourceProfile.backend !== normalizedSourceSession.backend) {
      throw new ConfigurationError(
        `Source profile ${normalizedSourceSession.profile} uses ${sourceProfile.backend}, not ${normalizedSourceSession.backend}.`,
        { code: "ERR_SOURCE_PROFILE_BACKEND_MISMATCH" },
      );
    }
  }

  const resolvedRoles = Object.fromEntries(
    pipeline.roles.map((role) => {
      const override = normalizeRole(
        roleOverrides[role] === undefined ? {} : roleOverrides[role],
        `roleOverrides.${role}`,
      );
      const configuredRole = pipelineConfiguration.roles[role] ?? {};
      const projectRole = projectPipelineConfiguration.roles?.[role] ?? {};
      const explicitRoleBackend =
        override.backend ?? projectRole.backend ?? configuredRole.backend;
      let profileSelection =
        override.profile ??
        normalizedExecutionOverrides.profile ??
        projectRole.profile ??
        normalizedProjectConfiguration?.defaultProfile ??
        configuredRole.profile ??
        normalizedConfiguration.defaultProfile;

      if (normalizedSourceSession !== null && role !== "arbiter") {
        if (sourceProfile === null) {
          if (profileSelection !== CURRENT) {
            throw new ConfigurationError(
              `${pipelineId}.${role} must use current when the source profile is unknown.`,
              { code: "ERR_SOURCE_PROFILE_MISMATCH" },
            );
          }
        } else if (profileSelection === CURRENT) {
          profileSelection = normalizedSourceSession.profile;
        } else if (profileSelection !== normalizedSourceSession.profile) {
          throw new ConfigurationError(
            `${pipelineId}.${role} profile does not match source profile ${normalizedSourceSession.profile}.`,
            { code: "ERR_SOURCE_PROFILE_MISMATCH" },
          );
        }
      }

      const profile = selectedProfile(
        normalizedConfiguration,
        profileSelection,
        `${pipelineId}.${role}.profile`,
      );
      const pinnedBackend =
        normalizedSourceSession !== null && role !== "arbiter"
          ? normalizedSourceSession.backend
          : profile?.backend;
      if (
        explicitRoleBackend !== undefined &&
        pinnedBackend !== undefined &&
        explicitRoleBackend !== pinnedBackend
      ) {
        throw new ConfigurationError(
          `Backend ${explicitRoleBackend} conflicts with the selected profile for ${pipelineId}.${role}.`,
          {
            code:
              normalizedSourceSession !== null && role !== "arbiter"
                ? "ERR_SOURCE_BACKEND_MISMATCH"
                : "ERR_PROFILE_BACKEND_MISMATCH",
          },
        );
      }
      const backend =
        pinnedBackend ??
        explicitRoleBackend ??
        normalizedProjectConfiguration?.defaultBackend ??
        normalizedConfiguration.defaultBackend;
      if (backend === undefined) {
        throw new ConfigurationError(
          `No backend is configured for ${pipelineId}.${role}.`,
          { code: "ERR_MISSING_ROLE_BACKEND" },
        );
      }

      return [
        role,
        Object.freeze({
          backend,
          profile: profileImplementation(profile),
          model:
            override.model ??
            normalizedExecutionOverrides.model ??
            projectRole.model ??
            normalizedProjectConfiguration?.defaultModel ??
            configuredRole.model ??
            normalizedConfiguration.defaultModel,
          contextSize:
            override.contextSize ??
            normalizedExecutionOverrides.contextSize ??
            projectRole.contextSize ??
            normalizedProjectConfiguration?.defaultContextSize ??
            configuredRole.contextSize ??
            normalizedConfiguration.defaultContextSize,
        }),
      ];
    }),
  );

  const { roles: _roles, ...runnerSettings } = pipelineConfiguration;
  const { roles: _projectRoles, ...projectSettings } =
    projectPipelineConfiguration;
  return Object.freeze({
    artifactRoot:
      normalizedProjectConfiguration?.artifactRoot ??
      normalizedConfiguration.artifactRoot,
    pipelineId,
    roles: Object.freeze(resolvedRoles),
    settings: Object.freeze({ ...runnerSettings, ...projectSettings }),
    sourceProfile:
      sourceProfile === null ? null : normalizedSourceSession.profile,
  });
}
