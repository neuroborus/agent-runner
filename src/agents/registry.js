import { isAbsolute, resolve } from "node:path";

import {
  CLAUDE_BACKEND_ID,
  createClaudeAdapter,
  normalizeClaudeDiagnosticClass,
  validateClaudeExecutionOptions,
} from "./claude/index.js";
import {
  CODEX_BACKEND_ID,
  createCodexAdapter,
  normalizeCodexDiagnosticClass,
  validateCodexExecutionOptions,
} from "./codex/index.js";

const BACKEND_ID_PATTERN = /^[a-z][a-z0-9-]{0,63}$/u;
const CURRENT = "current";

export class ProviderRegistryError extends Error {
  constructor(message) {
    super(message);
    this.name = "ProviderRegistryError";
    this.code = "ERR_INVALID_PROVIDER_REGISTRY";
  }
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function assertSelection(value, path) {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new ProviderRegistryError(`${path} must be a non-empty string.`);
  }
}

function normalizeCodexTrustedProfile(value, path) {
  assertSelection(value.profile, `${path}.profile`);
  if (value.profile === CURRENT) {
    throw new ProviderRegistryError(`${path}.profile must not be current.`);
  }
  return Object.freeze({ backend: CODEX_BACKEND_ID, profile: value.profile });
}

function normalizeClaudeTrustedProfile(value, path) {
  assertSelection(value.configDirectory, `${path}.configDirectory`);
  if (
    !isAbsolute(value.configDirectory) ||
    resolve(value.configDirectory) !== value.configDirectory
  ) {
    throw new ProviderRegistryError(
      `${path}.configDirectory must be an absolute normalized path.`,
    );
  }
  return Object.freeze({
    backend: CLAUDE_BACKEND_ID,
    configDirectory: value.configDirectory,
  });
}

const BUILTIN_PROVIDER_DESCRIPTORS = Object.freeze([
  Object.freeze({
    id: CODEX_BACKEND_ID,
    createAdapter: createCodexAdapter,
    validateExecutionOptions: validateCodexExecutionOptions,
    trustedProfile: Object.freeze({
      fields: Object.freeze(["backend", "profile"]),
      normalize: normalizeCodexTrustedProfile,
      resolve: (profile) => profile.profile,
    }),
    sourceSession: Object.freeze({ fork: true }),
    normalizeDiagnosticClass: normalizeCodexDiagnosticClass,
  }),
  Object.freeze({
    id: CLAUDE_BACKEND_ID,
    createAdapter: createClaudeAdapter,
    validateExecutionOptions: validateClaudeExecutionOptions,
    trustedProfile: Object.freeze({
      fields: Object.freeze(["backend", "configDirectory"]),
      normalize: normalizeClaudeTrustedProfile,
      resolve: (profile) => profile.configDirectory,
    }),
    sourceSession: Object.freeze({ fork: true }),
    normalizeDiagnosticClass: normalizeClaudeDiagnosticClass,
  }),
]);

function normalizeDescriptor(value, index) {
  const path = `providerDescriptors[${index}]`;
  if (
    !isRecord(value) ||
    !BACKEND_ID_PATTERN.test(value.id) ||
    typeof value.createAdapter !== "function" ||
    typeof value.validateExecutionOptions !== "function" ||
    !isRecord(value.trustedProfile) ||
    !Array.isArray(value.trustedProfile.fields) ||
    value.trustedProfile.fields.length === 0 ||
    new Set(value.trustedProfile.fields).size !==
      value.trustedProfile.fields.length ||
    !value.trustedProfile.fields.includes("backend") ||
    value.trustedProfile.fields.some(
      (field) => typeof field !== "string" || field.length === 0,
    ) ||
    typeof value.trustedProfile.normalize !== "function" ||
    typeof value.trustedProfile.resolve !== "function" ||
    !isRecord(value.sourceSession) ||
    typeof value.sourceSession.fork !== "boolean" ||
    typeof value.normalizeDiagnosticClass !== "function"
  ) {
    throw new ProviderRegistryError(`${path} is invalid.`);
  }
  return Object.freeze({
    id: value.id,
    createAdapter: value.createAdapter,
    validateExecutionOptions: value.validateExecutionOptions,
    trustedProfile: Object.freeze({
      fields: Object.freeze([...value.trustedProfile.fields]),
      normalize: value.trustedProfile.normalize,
      resolve: value.trustedProfile.resolve,
    }),
    sourceSession: Object.freeze({ fork: value.sourceSession.fork }),
    normalizeDiagnosticClass: value.normalizeDiagnosticClass,
  });
}

export function createProviderRegistry(
  descriptors = BUILTIN_PROVIDER_DESCRIPTORS,
) {
  if (!Array.isArray(descriptors) || descriptors.length === 0) {
    throw new ProviderRegistryError(
      "providerDescriptors must be a non-empty array.",
    );
  }
  const normalized = Object.freeze(descriptors.map(normalizeDescriptor));
  if (new Set(normalized.map(({ id }) => id)).size !== normalized.length) {
    throw new ProviderRegistryError("Provider backend IDs must be unique.");
  }
  const byId = new Map(
    normalized.map((descriptor) => [descriptor.id, descriptor]),
  );
  const ids = Object.freeze(normalized.map(({ id }) => id));
  const sourceSessionIds = Object.freeze(
    normalized
      .filter(({ sourceSession }) => sourceSession.fork)
      .map(({ id }) => id),
  );

  function get(backend) {
    return byId.get(backend);
  }

  function requireDescriptor(backend) {
    const descriptor = get(backend);
    if (descriptor === undefined) {
      throw new ProviderRegistryError(`Unknown provider backend: ${backend}.`);
    }
    return descriptor;
  }

  return Object.freeze({
    ids,
    sourceSessionIds,
    list: () => normalized,
    get,
    createAdapters() {
      return Object.freeze(
        Object.fromEntries(
          normalized.map((descriptor) => [
            descriptor.id,
            descriptor.createAdapter(),
          ]),
        ),
      );
    },
    validateExecutionOptions(backend, value) {
      requireDescriptor(backend).validateExecutionOptions(value);
      return value;
    },
    normalizeTrustedProfile(value, path) {
      if (!isRecord(value)) {
        throw new ProviderRegistryError(`${path} must be an object.`);
      }
      const descriptor = requireDescriptor(value.backend);
      const unknown = Object.keys(value).find(
        (field) => !descriptor.trustedProfile.fields.includes(field),
      );
      if (unknown !== undefined) {
        throw new ProviderRegistryError(`${path}.${unknown} is not supported.`);
      }
      const profile = descriptor.trustedProfile.normalize(value, path);
      if (!isRecord(profile) || profile.backend !== descriptor.id) {
        throw new ProviderRegistryError(
          `${path} did not normalize to its provider backend.`,
        );
      }
      return Object.freeze({ ...profile });
    },
    resolveTrustedProfile(profile) {
      if (!isRecord(profile)) {
        throw new ProviderRegistryError("Trusted profile is invalid.");
      }
      const implementation = requireDescriptor(
        profile.backend,
      ).trustedProfile.resolve(profile);
      if (typeof implementation !== "string" || implementation.length === 0) {
        throw new ProviderRegistryError(
          "Trusted profile implementation is invalid.",
        );
      }
      return implementation;
    },
    supportsSourceSessionFork(backend) {
      return get(backend)?.sourceSession.fork === true;
    },
    normalizeDiagnosticClass(backend, value) {
      const diagnosticClass = get(backend)?.normalizeDiagnosticClass(value);
      return typeof diagnosticClass === "string" ? diagnosticClass : undefined;
    },
    isDiagnosticClass(value) {
      return normalized.some(
        (descriptor) =>
          typeof descriptor.normalizeDiagnosticClass(value) === "string",
      );
    },
  });
}

export const PROVIDER_REGISTRY = createProviderRegistry();
