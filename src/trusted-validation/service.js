import { createHash } from "node:crypto";

import { createGitService } from "../git/index.js";
import {
  gitMetadataExposures,
  resolveTrustedBubblewrap,
  runExactCommand,
  runtimeStorageExposures,
  sandboxTrustedCommand,
  verifyTrustedBubblewrap,
} from "./execution.js";
import {
  acquisitionOwner,
  createResourceStorage,
  needsStorage,
} from "./resources.js";
import { normalizeArtifacts } from "./artifact-contract.js";
import { createArtifactAcquirer } from "./acquisition.js";
import { TrustedValidationError } from "./errors.js";
import {
  normalizeRequirementRequest,
  requirementBlockers,
} from "./requirements.js";

export { TrustedValidationError } from "./errors.js";

const ALIAS_PATTERN = /^[a-z][a-z0-9-]{0,63}$/u;
const HASH_PATTERN = /^[a-f0-9]{64}$/u;
const MAX_ARGUMENTS = 64;
const MAX_COMMAND_DEFINITIONS = 256;
const MAX_SELECTED_COMMANDS = 32;
const MAX_TEXT_LENGTH = 4_000;
const DEFAULT_TIMEOUT_MS = 15 * 60 * 1_000;
const SNAPSHOT_SCHEMA_VERSION = 2;
const SNAPSHOT_FIELDS = Object.freeze([
  "schemaVersion",
  "commands",
  "commandFingerprint",
  "configurationFingerprint",
]);
const COMMAND_FIELDS = Object.freeze([
  "alias",
  "command",
  "executable",
  "arguments",
  "identity",
]);

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasExactFields(value, fields) {
  return (
    isRecord(value) &&
    Object.keys(value).length === fields.length &&
    fields.every((field) => Object.hasOwn(value, field))
  );
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function assertExactText(
  value,
  name,
  { allowEmpty = false, allowLineFeeds = false, requireTrimmed = false } = {},
) {
  const inspectedValue =
    allowLineFeeds && typeof value === "string"
      ? value.replaceAll("\n", "")
      : value;
  if (
    typeof value !== "string" ||
    (!allowEmpty && value.length === 0) ||
    [...value].length > MAX_TEXT_LENGTH ||
    /[\0\p{Cc}\p{Zl}\p{Zp}]/u.test(inspectedValue) ||
    (requireTrimmed && value.trim() !== value)
  ) {
    throw new TrustedValidationError(`${name} is invalid.`, {
      code: "ERR_INVALID_TRUSTED_VALIDATION",
    });
  }
  return value;
}

function capabilityError() {
  return new TrustedValidationError(
    "Trusted execution capabilities are invalid.",
    { code: "ERR_INVALID_TRUSTED_VALIDATION" },
  );
}

function normalizeCapabilities(value) {
  if (
    !isRecord(value) ||
    Object.keys(value).some(
      (key) => !["scratch", "cache", "artifacts"].includes(key),
    )
  ) {
    throw capabilityError();
  }
  const normalized = {};
  for (const key of ["scratch", "cache"]) {
    if (Object.hasOwn(value, key)) {
      if (value[key] !== true) throw capabilityError();
      normalized[key] = true;
    }
  }
  if (Object.hasOwn(value, "artifacts")) {
    normalized.artifacts = normalizeArtifacts(value.artifacts);
    if (normalized.artifacts === null) throw capabilityError();
  }
  return Object.freeze(normalized);
}

function commandIdentity(command) {
  return sha256(
    JSON.stringify({
      alias: command.alias,
      command: command.command,
      executable: command.executable,
      arguments: command.arguments,
      ...(command.capabilities === undefined
        ? {}
        : { capabilities: command.capabilities }),
    }),
  );
}

function normalizeCommand(alias, value) {
  if (
    !ALIAS_PATTERN.test(alias) ||
    !hasExactFields(value, [
      "command",
      "executable",
      "arguments",
      ...(Object.hasOwn(value ?? {}, "capabilities") ? ["capabilities"] : []),
    ])
  ) {
    throw new TrustedValidationError(`Trusted command ${alias} is invalid.`, {
      code: "ERR_INVALID_TRUSTED_VALIDATION",
    });
  }
  const command = assertExactText(
    value.command,
    `Trusted command ${alias} command`,
    { requireTrimmed: true },
  );
  const executable = assertExactText(
    value.executable,
    `Trusted command ${alias} executable`,
    { requireTrimmed: true },
  );
  if (
    !Array.isArray(value.arguments) ||
    value.arguments.length > MAX_ARGUMENTS
  ) {
    throw new TrustedValidationError(
      `Trusted command ${alias} vector is invalid.`,
      { code: "ERR_INVALID_TRUSTED_VALIDATION" },
    );
  }
  const argumentsList = Object.freeze(
    value.arguments.map((argument, index) =>
      assertExactText(
        argument,
        `Trusted command ${alias} argument ${index + 1}`,
        { allowEmpty: true, allowLineFeeds: true },
      ),
    ),
  );
  const normalized = {
    alias,
    command,
    executable,
    arguments: argumentsList,
    ...(Object.hasOwn(value, "capabilities")
      ? { capabilities: normalizeCapabilities(value.capabilities) }
      : {}),
  };
  return Object.freeze({
    ...normalized,
    identity: commandIdentity(normalized),
  });
}

function normalizeCommandDefinitions(definitions) {
  if (
    !isRecord(definitions) ||
    Object.keys(definitions).length > MAX_COMMAND_DEFINITIONS
  ) {
    throw new TrustedValidationError(
      `Trusted validation may define at most ${MAX_COMMAND_DEFINITIONS} commands.`,
      { code: "ERR_INVALID_TRUSTED_VALIDATION" },
    );
  }
  return Object.freeze(
    Object.fromEntries(
      Object.entries(definitions).map(([alias, value]) => [
        alias,
        normalizeCommand(alias, value),
      ]),
    ),
  );
}

export function normalizeTrustedValidationDefinitions(definitions = {}) {
  const normalized = normalizeCommandDefinitions(definitions);
  return Object.freeze(
    Object.fromEntries(
      Object.entries(normalized).map(
        ([
          alias,
          { command, executable, arguments: argumentsList, capabilities },
        ]) => [
          alias,
          Object.freeze({
            command,
            executable,
            arguments: argumentsList,
            ...(capabilities === undefined ||
            Object.keys(capabilities).length === 0
              ? {}
              : { capabilities }),
          }),
        ],
      ),
    ),
  );
}

function snapshotFingerprints(
  commands,
  schemaVersion = SNAPSHOT_SCHEMA_VERSION,
) {
  return Object.freeze({
    commandFingerprint: sha256(
      JSON.stringify(commands.map(({ identity }) => identity)),
    ),
    configurationFingerprint: sha256(
      JSON.stringify({
        schemaVersion,
        commands: commands.map(
          ({
            alias,
            command,
            executable,
            arguments: argumentsList,
            capabilities,
          }) => ({
            alias,
            command,
            executable,
            arguments: argumentsList,
            ...(capabilities === undefined ? {} : { capabilities }),
          }),
        ),
      }),
    ),
  });
}

export function createTrustedValidationSnapshot(
  definitions = {},
  selections = [],
) {
  if (
    !Array.isArray(selections) ||
    selections.length > MAX_SELECTED_COMMANDS ||
    new Set(selections).size !== selections.length ||
    selections.some(
      (alias) => typeof alias !== "string" || !ALIAS_PATTERN.test(alias),
    )
  ) {
    throw new TrustedValidationError(
      "Trusted validation selection is invalid.",
      {
        code: "ERR_INVALID_TRUSTED_VALIDATION",
      },
    );
  }
  const normalizedDefinitions = normalizeCommandDefinitions(definitions);
  const commands = Object.freeze(
    selections.map((alias) => {
      const command = normalizedDefinitions[alias];
      if (!Object.hasOwn(normalizedDefinitions, alias)) {
        throw new TrustedValidationError(
          `Trusted validation selects unknown command: ${alias}.`,
          { code: "ERR_UNKNOWN_TRUSTED_COMMAND" },
        );
      }
      return normalizeCommand(alias, {
        command: command.command,
        executable: command.executable,
        arguments: command.arguments,
        capabilities: command.capabilities ?? {},
      });
    }),
  );
  return Object.freeze({
    schemaVersion: SNAPSHOT_SCHEMA_VERSION,
    commands,
    ...snapshotFingerprints(commands),
  });
}

export function validateTrustedValidationSnapshot(value) {
  if (
    !hasExactFields(value, SNAPSHOT_FIELDS) ||
    ![1, SNAPSHOT_SCHEMA_VERSION].includes(value.schemaVersion) ||
    !Array.isArray(value.commands) ||
    value.commands.length > MAX_SELECTED_COMMANDS ||
    !HASH_PATTERN.test(value.commandFingerprint) ||
    !HASH_PATTERN.test(value.configurationFingerprint)
  ) {
    throw new TrustedValidationError(
      "Trusted validation snapshot is invalid.",
      {
        code: "ERR_INVALID_TRUSTED_VALIDATION",
      },
    );
  }
  const snapshotVersion = value.schemaVersion;
  const commands = Object.freeze(
    value.commands.map((value, index) => {
      if (
        !hasExactFields(value, [
          ...COMMAND_FIELDS,
          ...(snapshotVersion === 2 ? ["capabilities"] : []),
        ])
      ) {
        throw new TrustedValidationError(
          `Trusted validation command ${index + 1} is invalid.`,
          { code: "ERR_INVALID_TRUSTED_VALIDATION" },
        );
      }
      const normalized = normalizeCommand(value.alias, {
        command: value.command,
        executable: value.executable,
        arguments: value.arguments,
        ...(snapshotVersion === 2 ? { capabilities: value.capabilities } : {}),
      });
      if (normalized.identity !== value.identity) {
        throw new TrustedValidationError(
          `Trusted validation command ${index + 1} identity is invalid.`,
          { code: "ERR_INVALID_TRUSTED_VALIDATION" },
        );
      }
      return normalized;
    }),
  );
  if (
    new Set(commands.map(({ alias }) => alias)).size !== commands.length ||
    new Set(commands.map(({ command }) => command)).size !== commands.length ||
    new Set(commands.map(({ identity }) => identity)).size !== commands.length
  ) {
    throw new TrustedValidationError(
      "Trusted validation commands must be unique.",
      { code: "ERR_INVALID_TRUSTED_VALIDATION" },
    );
  }
  const fingerprints = snapshotFingerprints(commands, snapshotVersion);
  if (
    value.commandFingerprint !== fingerprints.commandFingerprint ||
    value.configurationFingerprint !== fingerprints.configurationFingerprint
  ) {
    throw new TrustedValidationError(
      "Trusted validation snapshot fingerprint is invalid.",
      { code: "ERR_INVALID_TRUSTED_VALIDATION" },
    );
  }
  return Object.freeze({
    schemaVersion: snapshotVersion,
    commands,
    ...fingerprints,
  });
}

function normalizeBindings(value) {
  const fields = [
    "contentFingerprint",
    "validationInfrastructureFingerprint",
    "commandFingerprint",
    "configurationFingerprint",
  ];
  if (
    !hasExactFields(value, fields) ||
    fields.some((field) => !HASH_PATTERN.test(value[field]))
  ) {
    throw new TrustedValidationError(
      "Trusted validation bindings are invalid.",
      {
        code: "ERR_INVALID_TRUSTED_VALIDATION",
      },
    );
  }
  return Object.freeze({ ...value });
}

function boundedEvidence(command, result) {
  if (result.status === "BLOCKED") {
    const explanations = {
      isolation: `Runner-trusted command ${command.alias} could not start in the required isolated executor.`,
      "process-tree": `Runner-trusted command ${command.alias} left a child process that the runner terminated.`,
      "process-tree-supervision": `Runner-trusted command ${command.alias} could not run with complete process-tree supervision.`,
      spawn: `Runner-trusted command ${command.alias} could not be started safely.`,
      timeout: `Runner-trusted command ${command.alias} timed out without retaining process output.`,
      acquisition: `Runner-trusted command ${command.alias} could not acquire its verified dependencies.`,
    };
    return Object.freeze([
      explanations[result.reason] ??
        `Runner-trusted command ${command.alias} could not complete safely.`,
    ]);
  }
  if (result.timedOut) {
    return Object.freeze([
      `Runner-trusted command ${command.alias} timed out without retaining process output.`,
    ]);
  }
  return Object.freeze([
    `Runner-trusted command ${command.alias} exited with code ${result.exitCode}.`,
  ]);
}

export function createTrustedValidationService(options = {}) {
  if (!isRecord(options)) {
    throw new TrustedValidationError(
      "Trusted validation options are invalid.",
      {
        code: "ERR_INVALID_TRUSTED_VALIDATION_OPTIONS",
      },
    );
  }
  const environment = options.environment ?? process.env;
  const git = options.git ?? createGitService();
  const sandboxCommand = options.sandboxCommand ?? sandboxTrustedCommand;
  const runCommand = options.runCommand ?? runExactCommand;
  const resolveLauncher = options.resolveLauncher ?? resolveTrustedBubblewrap;
  const verifyLauncher = options.verifyLauncher ?? verifyTrustedBubblewrap;
  const terminationGraceMs = options.terminationGraceMs ?? 1_000;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (
    !isRecord(environment) ||
    !isRecord(git) ||
    typeof sandboxCommand !== "function" ||
    typeof runCommand !== "function" ||
    typeof resolveLauncher !== "function" ||
    typeof verifyLauncher !== "function" ||
    !Number.isSafeInteger(terminationGraceMs) ||
    terminationGraceMs < 1 ||
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs < 1
  ) {
    throw new TrustedValidationError(
      "Trusted validation options are invalid.",
      {
        code: "ERR_INVALID_TRUSTED_VALIDATION_OPTIONS",
      },
    );
  }
  const storage = createResourceStorage({ storageRoot: options.storageRoot });
  const acquire = createArtifactAcquirer(options.acquisition);
  // Same-service retirement proof complements the journaled process identity.
  const acquiring = new Set();
  const retiredAcquisitions = new Set();
  const defaultSandbox = options.sandboxCommand === undefined;
  let launcherPath = null;
  function trustedLauncher(projectPath) {
    launcherPath ??= resolveLauncher(options.bubblewrapExecutable ?? null);
    launcherPath = verifyLauncher(launcherPath, projectPath);
    return launcherPath;
  }

  async function preflight({
    projectPath,
    snapshot,
    storageForbiddenPaths = [],
  }) {
    const selected =
      snapshot === undefined
        ? undefined
        : validateTrustedValidationSnapshot(snapshot);
    for (const command of selected?.commands ?? []) {
      const { capabilities } = command;
      if (!needsStorage(capabilities)) continue;
      await storage.preflight(
        [
          projectPath,
          ...gitMetadataExposures(projectPath),
          ...runtimeStorageExposures(command, {
            cwd: projectPath,
            environment,
          }),
          ...storageForbiddenPaths,
        ],
        capabilities,
      );
    }
    if (!defaultSandbox) {
      return;
    }
    trustedLauncher(projectPath);
  }

  async function runSelected(
    {
      bindings,
      commandIdentity: identity,
      projectPath,
      snapshot,
      signal,
      onProcess,
      onResource,
      storageForbiddenPaths = [],
    },
    preparationOnly = false,
  ) {
    signal?.throwIfAborted();
    if (
      typeof git.snapshot !== "function" ||
      typeof git.assertUnchanged !== "function"
    ) {
      throw new TrustedValidationError(
        "Trusted validation Git safety service is unavailable.",
        { code: "ERR_INVALID_TRUSTED_VALIDATION_OPTIONS" },
      );
    }
    const trustedSnapshot = validateTrustedValidationSnapshot(snapshot);
    const normalizedBindings = preparationOnly
      ? null
      : normalizeBindings(bindings);
    if (
      !preparationOnly &&
      (trustedSnapshot.commandFingerprint !==
        normalizedBindings.commandFingerprint ||
        trustedSnapshot.configurationFingerprint !==
          normalizedBindings.configurationFingerprint)
    ) {
      throw new TrustedValidationError(
        "Trusted validation bindings do not match the durable snapshot.",
        { code: "ERR_INVALID_TRUSTED_VALIDATION" },
      );
    }
    const command = trustedSnapshot.commands.find(
      ({ identity: commandIdentity }) => commandIdentity === identity,
    );
    if (command === undefined) {
      throw new TrustedValidationError(
        "Trusted validation command is not allowlisted by the durable snapshot.",
        { code: "ERR_TRUSTED_COMMAND_NOT_ALLOWLISTED" },
      );
    }
    if (
      (preparationOnly || needsStorage(command.capabilities)) &&
      (typeof onProcess !== "function" || typeof onResource !== "function")
    ) {
      throw new TrustedValidationError(
        "Trusted storage requires durable resource and process ownership.",
        { code: "ERR_TRUSTED_VALIDATION_RESOURCE_UNVERIFIABLE" },
      );
    }
    const before = await git.snapshot({ allowedPaths: [], projectPath });
    if (
      !preparationOnly &&
      before.contentFingerprint !== normalizedBindings.contentFingerprint
    ) {
      throw new TrustedValidationError(
        "Trusted validation content binding changed before execution.",
        { code: "ERR_TRUSTED_VALIDATION_BINDING_CHANGED" },
      );
    }
    let result;
    let resource = null;
    let persistenceFailed = false;
    let processActive = false;
    const forbiddenPaths = [
      before.projectPath,
      ...gitMetadataExposures(before.projectPath),
      ...storageForbiddenPaths,
    ];
    const persistResource = async (value) => {
      try {
        await onResource(value);
        resource = value;
      } catch (cause) {
        persistenceFailed = true;
        if (command.capabilities?.artifacts && !signal?.aborted) {
          throw new TrustedValidationError(
            "Trusted acquisition ownership could not be persisted.",
            { cause, code: "ERR_TRUSTED_VALIDATION_RESOURCE_UNVERIFIABLE" },
          );
        }
        throw cause;
      }
    };
    let failure;
    try {
      if (needsStorage(command.capabilities))
        forbiddenPaths.push(
          ...runtimeStorageExposures(command, {
            cwd: before.projectPath,
            environment,
          }),
        );
      const bubblewrapPath = defaultSandbox
        ? trustedLauncher(before.projectPath)
        : null;
      const allocated = needsStorage(command.capabilities)
        ? await storage.allocate({
            command,
            forbiddenPaths,
            signal,
            onResource: persistResource,
          })
        : null;
      if (command.capabilities?.artifacts) {
        // Until the journal accepts this transition, no transport can start.
        retiredAcquisitions.add(resource.id);
        await persistResource({
          ...resource,
          phase: "acquiring",
          owner: await acquisitionOwner(),
        });
        acquiring.add(resource.id);
        retiredAcquisitions.delete(resource.id);
        let retirement;
        try {
          const directory = await storage.openDependencies(allocated);
          try {
            await acquire({
              artifacts: command.capabilities.artifacts,
              directory,
              signal,
            });
          } catch (cause) {
            if (cause?.code === "ERR_TRUSTED_ACQUISITION_RETIREMENT") {
              retirement = cause.retirement;
              const id = resource.id;
              retirement.then(() => {
                acquiring.delete(id);
                retiredAcquisitions.add(id);
              });
              throw new TrustedValidationError(
                "Trusted acquisition transport retirement is unverified.",
                { code: "ERR_TRUSTED_VALIDATION_RESOURCE_UNVERIFIABLE" },
              );
            }
            throw cause;
          } finally {
            await directory.close();
          }
        } finally {
          if (!retirement) {
            acquiring.delete(resource.id);
            retiredAcquisitions.add(resource.id);
            await persistResource(allocated.record);
            retiredAcquisitions.delete(resource.id);
          }
        }
      }
      if (allocated !== null) await storage.verify(allocated);
      signal?.throwIfAborted();
      const execution = await sandboxCommand(command, {
        bubblewrapPath,
        cwd: before.projectPath,
        environment,
        resources: allocated?.mounts ?? {},
        privateStorageRoot: allocated?.record.root.path,
        preparationOnly,
      });
      result = await runCommand(execution.command, {
        cwd: before.projectPath,
        environment: execution.environment,
        ownershipMode: execution.ownershipMode,
        readinessRequired: execution.readinessRequired ?? false,
        terminationGraceMs,
        timeoutMs: preparationOnly ? Math.min(timeoutMs, 10_000) : timeoutMs,
        signal,
        onProcess:
          allocated === null && !preparationOnly
            ? onProcess
            : async (pid, proof) => {
                if (pid !== null) processActive = true;
                await onProcess(pid, proof);
                if (pid === null) processActive = false;
              },
      });
      if (processActive)
        throw new TrustedValidationError(
          "Trusted execution process retirement is unverified.",
          { code: "ERR_EXECUTION_PROCESS_ACTIVE" },
        );
    } catch (cause) {
      failure = cause;
      if (
        persistenceFailed ||
        cause?.code === "ERR_TRUSTED_VALIDATION_RESOURCE_UNVERIFIABLE" ||
        signal?.aborted ||
        [
          "ERR_EXECUTION_PROCESS_ACTIVE",
          "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
        ].includes(cause?.code)
      )
        throw cause;
      if (cause?.code === "ERR_TRUSTED_VALIDATION_PROCESS_TREE_ACTIVE") {
        throw cause;
      }
      if (processActive) {
        throw new TrustedValidationError(
          "Trusted execution process retirement is unverified.",
          { cause, code: "ERR_EXECUTION_PROCESS_ACTIVE" },
        );
      }
      result = {
        status: "BLOCKED",
        exitCode: null,
        signal: null,
        timedOut: false,
        reason: cause?.code?.startsWith("ERR_TRUSTED_ACQUISITION_")
          ? "acquisition"
          : cause?.code === "ERR_TRUSTED_VALIDATION_ISOLATION_UNAVAILABLE"
            ? "isolation"
            : "spawn",
      };
    } finally {
      // The process boundary clears registration only after retiring descendants.
      // Uncertain process or journal ownership leaves the durable record intact.
      const retired =
        !processActive &&
        ![
          "ERR_EXECUTION_PROCESS_ACTIVE",
          "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
          "ERR_TRUSTED_VALIDATION_PROCESS_TREE_ACTIVE",
        ].includes(failure?.code);
      try {
        if (
          resource !== null &&
          retired &&
          !persistenceFailed &&
          failure?.code !== "ERR_TRUSTED_VALIDATION_RESOURCE_UNVERIFIABLE" &&
          !acquiring.has(resource.id)
        ) {
          const id = resource.id;
          await storage.cleanup(resource, {
            forbiddenPaths,
            onResource: persistResource,
          });
          retiredAcquisitions.delete(id);
        }
      } finally {
        if (retired) {
          try {
            await git.assertUnchanged(before);
          } catch (cause) {
            throw new TrustedValidationError(
              "Runner-trusted validation mutated repository state.",
              {
                changes: Array.isArray(cause?.changes) ? cause.changes : [],
                code: "ERR_TRUSTED_VALIDATION_MUTATED_REPOSITORY",
              },
            );
          }
        }
      }
    }
    if (
      !isRecord(result) ||
      !["PASS", "FAIL", "BLOCKED"].includes(result.status) ||
      (result.exitCode !== null && !Number.isSafeInteger(result.exitCode)) ||
      (result.signal !== null &&
        (typeof result.signal !== "string" || result.signal.length > 32)) ||
      typeof result.timedOut !== "boolean" ||
      ![
        "exit",
        "isolation",
        "process-tree",
        "process-tree-supervision",
        "spawn",
        "timeout",
        "acquisition",
      ].includes(result.reason) ||
      (result.status === "PASS" &&
        (result.exitCode !== 0 || result.signal !== null || result.timedOut)) ||
      (result.status === "FAIL" &&
        (result.timedOut ||
          (result.exitCode === null && result.signal === null) ||
          result.exitCode === 0)) ||
      (result.status === "BLOCKED" &&
        !result.timedOut &&
        (result.exitCode !== null || result.signal !== null))
    ) {
      throw new TrustedValidationError(
        "Trusted validation executor returned an invalid bounded result.",
        { code: "ERR_INVALID_TRUSTED_VALIDATION_RESULT" },
      );
    }
    if (preparationOnly)
      return Object.freeze({ available: result.status === "PASS" });
    return Object.freeze({
      status: result.status,
      commandIdentity: command.identity,
      exitCode: result.exitCode,
      signal: result.signal,
      timedOut: result.timedOut,
      evidence: boundedEvidence(command, result),
      ...normalizedBindings,
    });
  }

  async function recoverResources({
    resource,
    projectPath,
    storageForbiddenPaths = [],
    onResource,
  }) {
    if (acquiring.has(resource?.id)) {
      throw new TrustedValidationError(
        "Trusted acquisition transport retirement is unverified.",
        { code: "ERR_TRUSTED_VALIDATION_RESOURCE_UNVERIFIABLE" },
      );
    }
    if (
      resource?.phase === "acquiring" &&
      retiredAcquisitions.has(resource.id)
    ) {
      const { owner, ...allocation } = resource;
      resource = { ...allocation, phase: "allocated" };
      try {
        await onResource(resource);
      } catch (cause) {
        throw new TrustedValidationError(
          "Trusted acquisition retirement could not be persisted.",
          { cause, code: "ERR_TRUSTED_VALIDATION_RESOURCE_UNVERIFIABLE" },
        );
      }
    }
    await createResourceStorage({ storageRoot: resource?.root?.path }).cleanup(
      resource,
      {
        forbiddenPaths: [
          projectPath,
          ...gitMetadataExposures(projectPath),
          ...storageForbiddenPaths,
        ],
        onResource,
      },
    );
    retiredAcquisitions.delete(resource.id);
  }

  async function inspectRequirements({
    inventory,
    requirements = [],
    snapshot,
    ...context
  }) {
    context.signal?.throwIfAborted();
    const request = normalizeRequirementRequest({ inventory, requirements });
    const selected =
      snapshot === undefined
        ? createTrustedValidationSnapshot({}, [])
        : validateTrustedValidationSnapshot(snapshot);
    if (
      selected.commands.some(
        (command) => !request.inventory.includes(command.command),
      )
    ) {
      throw new TrustedValidationError(
        "The inventory omits a frozen trusted command.",
        {
          code: "ERR_INVALID_TRUSTED_REQUIREMENTS",
        },
      );
    }
    const blockers = requirementBlockers(request, selected);
    // Validate the complete request and authority before any preparation effects.
    if (blockers.length === 0) {
      for (const command of selected.commands) {
        context.signal?.throwIfAborted();
        const result = await runSelected(
          { ...context, snapshot: selected, commandIdentity: command.identity },
          true,
        );
        if (!result.available)
          blockers.push(
            Object.freeze({
              command: command.command,
              commandIdentity: command.identity,
              reason: "unavailable",
              evidence: Object.freeze([
                "The runner could not prepare the frozen command capabilities.",
              ]),
            }),
          );
      }
    }
    context.signal?.throwIfAborted();
    return Object.freeze({
      status: blockers.length === 0 ? "READY" : "BLOCKED",
      blockers: Object.freeze(blockers),
    });
  }

  return Object.freeze({
    execute: (request) => runSelected(request),
    preflight,
    inspectRequirements,
    recoverResources,
  });
}
