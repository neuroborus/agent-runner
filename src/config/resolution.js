import { PROVIDER_REGISTRY } from "../agents/index.js";
import { getPipeline } from "../pipeline-registry.js";
import { createTrustedValidationSnapshot } from "../trusted-validation/index.js";

import {
  assertBackend,
  assertRecord,
  assertSelection,
  ConfigurationError,
  CURRENT,
  normalizeConfiguration,
  normalizeProjectConfiguration,
  normalizeRole,
  rejectUnknownFields,
} from "./parsing.js";
import { profileImplementation, selectedProfile } from "./profiles.js";

const EXECUTION_FIELDS = new Set(["contextSize", "model", "profile"]);

function normalizeExecution(value, path, providers) {
  assertRecord(value, path);
  rejectUnknownFields(value, EXECUTION_FIELDS, path);
  return normalizeRole(value, path, providers);
}

function normalizeSettingOverrides(pipeline, input) {
  const path = "settingOverrides";
  const acceptedSettings = Object.keys(pipeline.settings).filter((name) =>
    pipeline.runOptions.includes(name),
  );
  assertRecord(input, path);
  rejectUnknownFields(input, new Set(acceptedSettings), path);

  return Object.freeze(
    Object.fromEntries(
      Object.entries(input).map(([settingName, value]) => {
        const definition = pipeline.settings[settingName];
        if (!definition.validate(value)) {
          throw new ConfigurationError(
            `${path}.${settingName} ${definition.errorMessage}.`,
          );
        }
        return [
          settingName,
          Array.isArray(value) ? Object.freeze([...value]) : value,
        ];
      }),
    ),
  );
}

function normalizeSourceSession(value, providers) {
  if (value === undefined || value === null) {
    return null;
  }
  assertRecord(value, "sourceSession");
  rejectUnknownFields(
    value,
    new Set(["backend", "id", "profile"]),
    "sourceSession",
  );
  assertBackend(value.backend, "sourceSession.backend", providers);
  if (!providers.supportsSourceSessionFork(value.backend)) {
    throw new ConfigurationError(
      `Source backend ${value.backend} does not support session forks.`,
      { code: "ERR_UNSUPPORTED_SOURCE_SESSION" },
    );
  }
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

export function resolvePipelineConfiguration(
  pipelineId,
  configuration,
  roleOverrides = {},
  executionOverrides = {},
  sourceSession = null,
  projectConfiguration = null,
  settingOverrides = {},
  providers = PROVIDER_REGISTRY,
) {
  const pipeline = getPipeline(pipelineId);
  if (pipeline === undefined) {
    throw new ConfigurationError(`Unknown pipeline: ${pipelineId}.`, {
      code: "ERR_UNKNOWN_PIPELINE",
    });
  }
  const normalizedConfiguration = normalizeConfiguration(
    configuration,
    providers,
  );
  const normalizedProjectConfiguration =
    projectConfiguration === null
      ? null
      : normalizeProjectConfiguration(
          projectConfiguration,
          normalizedConfiguration,
          providers,
        );
  assertRecord(roleOverrides, "roleOverrides");
  const normalizedExecutionOverrides = normalizeExecution(
    executionOverrides,
    "executionOverrides",
    providers,
  );
  const normalizedSourceSession = normalizeSourceSession(
    sourceSession,
    providers,
  );
  const normalizedSettingOverrides = normalizeSettingOverrides(
    pipeline,
    settingOverrides,
  );

  const unknownRole = Object.keys(roleOverrides).find(
    (role) => !pipeline.roles.includes(role),
  );
  if (unknownRole !== undefined) {
    throw new ConfigurationError(
      `roleOverrides.${unknownRole} is not a supported role for ${pipelineId}.`,
    );
  }
  const normalizedRoleOverrides = Object.freeze(
    Object.fromEntries(
      Object.entries(roleOverrides).map(([role, value]) => [
        role,
        normalizeRole(value, `roleOverrides.${role}`, providers),
      ]),
    ),
  );

  const pipelineConfiguration = normalizedConfiguration.pipelines[pipelineId];
  const projectPipelineConfiguration =
    normalizedProjectConfiguration?.pipelines[pipelineId] ?? {};
  const { roles: _roles, ...runnerSettings } = pipelineConfiguration;
  const { roles: _projectRoles, ...projectSettings } =
    projectPipelineConfiguration;
  const settings = Object.freeze({
    ...runnerSettings,
    ...projectSettings,
    ...normalizedSettingOverrides,
  });
  const selectedRoles = pipeline.resolveActiveRoles(settings);
  if (
    !Array.isArray(selectedRoles) ||
    selectedRoles.length === 0 ||
    new Set(selectedRoles).size !== selectedRoles.length ||
    selectedRoles.some((role) => !pipeline.roles.includes(role))
  ) {
    throw new ConfigurationError(
      `${pipelineId} resolved an invalid active role selection.`,
    );
  }
  const activeRoles = Object.freeze([...selectedRoles]);

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
    activeRoles.map((role) => {
      const override = normalizedRoleOverrides[role] ?? {};
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

      const execution = Object.freeze({
        profile: profileImplementation(profile, providers),
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
      });
      try {
        providers.validateExecutionOptions(backend, execution);
      } catch (cause) {
        throw new ConfigurationError(cause.message, {
          cause,
          code: cause.code,
        });
      }
      return [role, Object.freeze({ backend, ...execution })];
    }),
  );

  let trustedValidation;
  if (Object.hasOwn(settings, "trustedChecks")) {
    try {
      trustedValidation = createTrustedValidationSnapshot(
        normalizedConfiguration.trustedCommands,
        settings.trustedChecks,
      );
    } catch (cause) {
      throw new ConfigurationError(cause.message, {
        cause,
        code: cause.code,
      });
    }
  }
  return Object.freeze({
    artifactRoot:
      normalizedProjectConfiguration?.artifactRoot ??
      normalizedConfiguration.artifactRoot,
    pipelineId,
    roles: Object.freeze(resolvedRoles),
    settings,
    sourceProfile:
      sourceProfile === null ? null : normalizedSourceSession.profile,
    ...(trustedValidation === undefined ? {} : { trustedValidation }),
  });
}
