import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { BACKEND_IDS } from "./agents/index.js";
import { getPipeline, listPipelines } from "./pipeline-registry.js";

export const CONFIG_FILENAME = ".agent-runner.json";
export const CONFIG_SCHEMA_VERSION = 1;

const BACKENDS = new Set(BACKEND_IDS);
const TOP_LEVEL_FIELDS = new Set([
  "schemaVersion",
  "defaultBackend",
  "pipelines",
]);
const ROLE_FIELDS = new Set(["backend", "model"]);

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

function assertModel(value, path) {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new ConfigurationError(`${path} must be a non-empty string.`);
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
  if (role.model !== undefined) {
    assertModel(role.model, `${path}.model`);
    normalized.model = role.model;
  }

  return Object.freeze(normalized);
}

function normalizePipeline(pipeline, input) {
  const path = `configuration.pipelines.${pipeline.id}`;
  assertRecord(input, path);
  rejectUnknownFields(
    input,
    new Set(["roles", ...Object.keys(pipeline.settings)]),
    path,
  );

  const normalized = {};
  for (const [settingName, definition] of Object.entries(pipeline.settings)) {
    const value =
      input[settingName] === undefined
        ? definition.defaultValue
        : input[settingName];
    if (!definition.validate(value)) {
      throw new ConfigurationError(
        `${path}.${settingName} ${definition.errorMessage}.`,
      );
    }
    normalized[settingName] = value;
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

  return Object.freeze(normalized);
}

export function parseRepositoryConfiguration(source) {
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

export async function loadRepositoryConfiguration(projectPath) {
  if (typeof projectPath !== "string" || projectPath.trim().length === 0) {
    throw new ConfigurationError("Project path must be a non-empty string.");
  }

  const configurationPath = resolve(projectPath, CONFIG_FILENAME);
  let source;
  try {
    source = await readFile(configurationPath, "utf8");
  } catch (cause) {
    if (cause?.code === "ENOENT") {
      return normalizeConfiguration({ schemaVersion: CONFIG_SCHEMA_VERSION });
    }

    throw new ConfigurationError(
      `Cannot read repository configuration at ${configurationPath}.`,
      { cause, code: "ERR_CONFIGURATION_READ" },
    );
  }

  return parseRepositoryConfiguration(source);
}

export function resolvePipelineConfiguration(
  pipelineId,
  configuration,
  roleOverrides = {},
) {
  const pipeline = getPipeline(pipelineId);
  if (pipeline === undefined) {
    throw new ConfigurationError(`Unknown pipeline: ${pipelineId}.`, {
      code: "ERR_UNKNOWN_PIPELINE",
    });
  }
  const normalizedConfiguration = normalizeConfiguration(configuration);
  assertRecord(roleOverrides, "roleOverrides");

  const unknownRole = Object.keys(roleOverrides).find(
    (role) => !pipeline.roles.includes(role),
  );
  if (unknownRole !== undefined) {
    throw new ConfigurationError(
      `roleOverrides.${unknownRole} is not a supported role for ${pipelineId}.`,
    );
  }

  const pipelineConfiguration = normalizedConfiguration.pipelines[pipelineId];

  const resolvedRoles = Object.fromEntries(
    pipeline.roles.map((role) => {
      const override = normalizeRole(
        roleOverrides[role] === undefined ? {} : roleOverrides[role],
        `roleOverrides.${role}`,
      );
      const repositoryRole = pipelineConfiguration.roles[role] ?? {};
      const backend =
        override.backend ??
        repositoryRole.backend ??
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
          model: override.model ?? repositoryRole.model ?? null,
        }),
      ];
    }),
  );

  const { roles: _roles, ...settings } = pipelineConfiguration;
  return Object.freeze({
    pipelineId,
    roles: Object.freeze(resolvedRoles),
    settings: Object.freeze(settings),
  });
}
