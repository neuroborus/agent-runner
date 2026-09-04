import { createHash } from "node:crypto";

import { createGitService } from "./git.js";
import {
  resolveTrustedBubblewrap,
  runExactCommand,
  sandboxTrustedCommand,
  verifyTrustedBubblewrap,
} from "./trusted-validation-execution.js";

const ALIAS_PATTERN = /^[a-z][a-z0-9-]{0,63}$/u;
const HASH_PATTERN = /^[a-f0-9]{64}$/u;
const MAX_ARGUMENTS = 64;
const MAX_COMMAND_DEFINITIONS = 256;
const MAX_SELECTED_COMMANDS = 32;
const MAX_TEXT_LENGTH = 4_000;
const DEFAULT_TIMEOUT_MS = 15 * 60 * 1_000;
const SNAPSHOT_SCHEMA_VERSION = 1;
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

export class TrustedValidationError extends Error {
  constructor(
    message,
    { cause, changes = [], code = "ERR_TRUSTED_VALIDATION" } = {},
  ) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "TrustedValidationError";
    this.code = code;
    this.changes = Object.freeze([...changes]);
  }
}

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

function commandIdentity(command) {
  return sha256(
    JSON.stringify({
      alias: command.alias,
      command: command.command,
      executable: command.executable,
      arguments: command.arguments,
    }),
  );
}

function normalizeCommand(alias, value) {
  if (
    !ALIAS_PATTERN.test(alias) ||
    !hasExactFields(value, ["command", "executable", "arguments"])
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
        ([alias, { command, executable, arguments: argumentsList }]) => [
          alias,
          Object.freeze({
            command,
            executable,
            arguments: argumentsList,
          }),
        ],
      ),
    ),
  );
}

function snapshotFingerprints(commands) {
  return Object.freeze({
    commandFingerprint: sha256(
      JSON.stringify(commands.map(({ identity }) => identity)),
    ),
    configurationFingerprint: sha256(
      JSON.stringify({
        schemaVersion: SNAPSHOT_SCHEMA_VERSION,
        commands: commands.map(
          ({ alias, command, executable, arguments: argumentsList }) => ({
            alias,
            command,
            executable,
            arguments: argumentsList,
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
      if (command === undefined) {
        throw new TrustedValidationError(
          `Trusted validation selects unknown command: ${alias}.`,
          { code: "ERR_UNKNOWN_TRUSTED_COMMAND" },
        );
      }
      return command;
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
    value.schemaVersion !== SNAPSHOT_SCHEMA_VERSION ||
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
  const commands = Object.freeze(
    value.commands.map((value, index) => {
      if (!hasExactFields(value, COMMAND_FIELDS)) {
        throw new TrustedValidationError(
          `Trusted validation command ${index + 1} is invalid.`,
          { code: "ERR_INVALID_TRUSTED_VALIDATION" },
        );
      }
      const normalized = normalizeCommand(value.alias, {
        command: value.command,
        executable: value.executable,
        arguments: value.arguments,
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
  const fingerprints = snapshotFingerprints(commands);
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
    schemaVersion: SNAPSHOT_SCHEMA_VERSION,
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
  const defaultSandbox = options.sandboxCommand === undefined;
  let launcherPath = null;
  let launcherError = null;
  if (defaultSandbox) {
    try {
      launcherPath = resolveLauncher(options.bubblewrapExecutable ?? null);
    } catch (cause) {
      launcherError = cause;
    }
  }

  async function preflight({ projectPath }) {
    if (!defaultSandbox) {
      return;
    }
    if (launcherError !== null) {
      throw launcherError;
    }
    launcherPath = verifyLauncher(launcherPath, projectPath);
  }

  async function execute({
    bindings,
    commandIdentity: identity,
    projectPath,
    snapshot,
  }) {
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
    const normalizedBindings = normalizeBindings(bindings);
    if (
      trustedSnapshot.commandFingerprint !==
        normalizedBindings.commandFingerprint ||
      trustedSnapshot.configurationFingerprint !==
        normalizedBindings.configurationFingerprint
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
    const before = await git.snapshot({ allowedPaths: [], projectPath });
    if (before.contentFingerprint !== normalizedBindings.contentFingerprint) {
      throw new TrustedValidationError(
        "Trusted validation content binding changed before execution.",
        { code: "ERR_TRUSTED_VALIDATION_BINDING_CHANGED" },
      );
    }
    let result;
    try {
      const bubblewrapPath = defaultSandbox
        ? verifyLauncher(launcherPath, before.projectPath)
        : null;
      const execution = await sandboxCommand(command, {
        bubblewrapPath,
        cwd: before.projectPath,
        environment,
      });
      result = await runCommand(execution.command, {
        cwd: before.projectPath,
        environment: execution.environment,
        readinessRequired: execution.readinessRequired ?? false,
        terminationGraceMs,
        timeoutMs,
      });
    } catch (cause) {
      if (cause?.code === "ERR_TRUSTED_VALIDATION_PROCESS_TREE_ACTIVE") {
        throw cause;
      }
      result = {
        status: "BLOCKED",
        exitCode: null,
        signal: null,
        timedOut: false,
        reason:
          cause?.code === "ERR_TRUSTED_VALIDATION_ISOLATION_UNAVAILABLE"
            ? "isolation"
            : "spawn",
      };
    }
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

  return Object.freeze({ execute, preflight });
}
