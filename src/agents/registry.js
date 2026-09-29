import { isAbsolute, resolve } from "node:path";

import {
  CLAUDE_BACKEND_ID,
  CLAUDE_STORAGE_IDENTITY,
  recoverClaudeStorage,
  CLAUDE_FAILURE_CLASSES,
  classifyClaudeFailure,
  createClaudeAdapter,
  validateClaudeExecutionOptions,
} from "./claude/index.js";
import {
  CODEX_BACKEND_ID,
  CODEX_FAILURE_CLASSES,
  classifyCodexFailure,
  createCodexAdapter,
  validateCodexExecutionOptions,
} from "./codex/index.js";
import {
  normalizeFailureRecord,
  PROVIDER_NEUTRAL_LAUNCH_FAILURE_CLASSES,
} from "./adapter-contract.js";

const BACKEND_ID_PATTERN = /^[a-z][a-z0-9-]{0,63}$/u;
const FAILURE_CLASS_PATTERN = /^[a-z][a-z0-9_]{0,63}$/u;
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

function readonlySet(values) {
  const target = new Set(values);
  const reject = () => {
    throw new ProviderRegistryError("Provider failure classes are immutable.");
  };
  let result;
  result = new Proxy(target, {
    get(set, property, receiver) {
      if (["add", "clear", "delete"].includes(property)) return reject;
      if (property === "size") return set.size;
      if (property === "forEach") {
        return (callback, thisArgument) => {
          if (typeof callback !== "function") {
            throw new TypeError("Set callback must be a function.");
          }
          return set.forEach((value) =>
            Reflect.apply(callback, thisArgument, [value, value, result]),
          );
        };
      }
      if (
        property === Symbol.iterator ||
        ["entries", "has", "keys", "values"].includes(property)
      ) {
        return Set.prototype[property].bind(set);
      }
      return Reflect.get(set, property, receiver);
    },
  });
  return Object.freeze(result);
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
    failures: Object.freeze({
      classes: new Set(CODEX_FAILURE_CLASSES),
      classify: classifyCodexFailure,
    }),
  }),
  Object.freeze({
    id: CLAUDE_BACKEND_ID,
    resources: Object.freeze({
      identity: CLAUDE_STORAGE_IDENTITY,
      recover: recoverClaudeStorage,
    }),
    createAdapter: createClaudeAdapter,
    validateExecutionOptions: validateClaudeExecutionOptions,
    trustedProfile: Object.freeze({
      fields: Object.freeze(["backend", "configDirectory"]),
      normalize: normalizeClaudeTrustedProfile,
      resolve: (profile) => profile.configDirectory,
    }),
    sourceSession: Object.freeze({ fork: true }),
    failures: Object.freeze({
      classes: new Set(CLAUDE_FAILURE_CLASSES),
      classify: classifyClaudeFailure,
    }),
  }),
]);

function normalizeDescriptor(value, index) {
  const path = `providerDescriptors[${index}]`;
  if (
    !isRecord(value) ||
    !BACKEND_ID_PATTERN.test(value.id) ||
    (value.resources !== undefined &&
      (!isRecord(value.resources) ||
        Reflect.ownKeys(value.resources).length !== 2 ||
        typeof value.resources.identity !== "string" ||
        !/^[a-f0-9]{64}$/u.test(value.resources.identity) ||
        typeof value.resources.recover !== "function")) ||
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
    !isRecord(value.failures) ||
    Reflect.ownKeys(value.failures).length !== 2 ||
    !Object.hasOwn(value.failures, "classes") ||
    !Object.hasOwn(value.failures, "classify") ||
    !(value.failures.classes instanceof Set) ||
    value.failures.classes.size > 256 ||
    [...value.failures.classes].some(
      (failureClass) =>
        typeof failureClass !== "string" ||
        !FAILURE_CLASS_PATTERN.test(failureClass),
    ) ||
    typeof value.failures.classify !== "function"
  ) {
    throw new ProviderRegistryError(`${path} is invalid.`);
  }
  return Object.freeze({
    id: value.id,
    ...(value.resources === undefined
      ? {}
      : {
          resources: Object.freeze({
            identity: value.resources.identity,
            recover: value.resources.recover,
          }),
        }),
    createAdapter: value.createAdapter,
    validateExecutionOptions: value.validateExecutionOptions,
    trustedProfile: Object.freeze({
      fields: Object.freeze([...value.trustedProfile.fields]),
      normalize: value.trustedProfile.normalize,
      resolve: value.trustedProfile.resolve,
    }),
    sourceSession: Object.freeze({ fork: value.sourceSession.fork }),
    failures: Object.freeze({
      classes: readonlySet(value.failures.classes),
      classify: value.failures.classify,
    }),
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
  const resourceIds = normalized.flatMap(({ resources }) =>
    resources === undefined ? [] : [resources.identity],
  );
  if (new Set(resourceIds).size !== resourceIds.length) {
    throw new ProviderRegistryError(
      "Provider resource identities must be unique.",
    );
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
    classifyFailure(backend, cause) {
      const failures = get(backend)?.failures;
      if (failures === undefined) return undefined;
      try {
        const failure = failures.classify(cause);
        if (failure === undefined) return undefined;
        return normalizeFailureRecord(failure, [...failures.classes]);
      } catch {
        throw new ProviderRegistryError(
          `Provider ${backend} returned an invalid failure record.`,
        );
      }
    },
    isDiagnosticClass(value) {
      return (
        PROVIDER_NEUTRAL_LAUNCH_FAILURE_CLASSES.includes(value) ||
        normalized.some((descriptor) => descriptor.failures.classes.has(value))
      );
    },
  });
}

export const PROVIDER_REGISTRY = createProviderRegistry();
