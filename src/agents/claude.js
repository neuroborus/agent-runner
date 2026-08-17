import { execFile as executeFileCallback } from "node:child_process";
import { realpath } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import { promisify } from "node:util";

import {
  createAdapterContract,
  deepFreeze,
  isEnvironment,
  isRecord,
  isolateGitEnvironment,
} from "./adapter-contract.js";
import {
  executeClaudeLocalCommit,
  probeClaudeLocalCommit,
} from "./claude-local-commit.js";

export const CLAUDE_BACKEND_ID = "claude";

const executeFileAsync = promisify(executeFileCallback);
const BUBBLEWRAP_BINARY = "bwrap";
const SOCAT_BINARY = "socat";
const MINIMUM_CLAUDE_VERSION = Object.freeze([2, 1, 233]);
const MAX_ARGUMENT_BYTES = 128 * 1024 - 1;
const MAX_PROCESS_OUTPUT_BYTES = 64 * 1024 * 1024;
const SESSION_ID_PATTERN =
  /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/iu;
const REQUIRED_HELP_FLAGS = Object.freeze([
  "--append-system-prompt",
  "--autocompact",
  "--fork-session",
  "--json-schema",
  "--mcp-config",
  "--model",
  "--no-chrome",
  "--output-format",
  "--permission-mode",
  "--print",
  "--prompt-suggestions",
  "--resume",
  "--safe-mode",
  "--settings",
  "--strict-mcp-config",
  "--tools",
]);
const LOCAL_COMMIT_OUTPUT_SCHEMA = Object.freeze({
  type: "object",
  properties: Object.freeze({
    ready: Object.freeze({ type: "boolean" }),
  }),
  required: Object.freeze(["ready"]),
  additionalProperties: false,
});
const BASE_OPTIONS = Object.freeze([
  "--output-format",
  "json",
  "--prompt-suggestions",
  "false",
  "--autocompact",
  "auto",
  "--safe-mode",
  "--no-chrome",
  "--strict-mcp-config",
  "--mcp-config",
  '{"mcpServers":{}}',
]);
const READ_ONLY_TOOLS = "Bash,Read,Glob,Grep";
const WORKSPACE_TOOLS = "Bash,Read,Edit,Write,Glob,Grep";
const SYSTEM_INSTRUCTIONS =
  "Operate only inside the requested repository. Read and follow its agent " +
  "instructions and relevant SKILL.md files directly. Do not stage, restore, " +
  "or mutate Git state; perform remote writes; change Git remotes; create " +
  "commits; or ask for native permission approval. Use only the exposed tools.";
const COMPACTION_PREFIX =
  "Compact the existing Claude session context, preserving decisions and " +
  "valid progress. Then complete this durable request from the observed " +
  "current workspace without repeating completed work.";
const RECOVERY_PREFIX =
  "The previous Claude session could not continue. Reconstruct context from " +
  "this durable request and the observed current workspace. Preserve valid " +
  "progress and do not repeat completed work.";
const CONTEXT_ERROR_PATTERN =
  /(?:context(?:[_ -]window)?[^\n]{0,80}(?:exceed|full|limit)|prompt is too long)/iu;
const SESSION_ERROR_PATTERN =
  /(?:no conversation found|(?:conversation|session)[^\n]{0,80}(?:not found|unavailable|cannot|could not|invalid))/iu;
const MODEL_ERROR_PATTERN =
  /(?:model)[^\n]{0,80}(?:not found|unavailable|invalid|unsupported|access)/iu;
const AUTO_ERROR_PATTERN =
  /(?:auto mode|permission mode[^\n]*auto)[^\n]{0,80}(?:unavailable|disabled|unsupported|invalid)/iu;
const PERMISSION_MODE_FALLBACK_PATTERN =
  /permission mode forced to (?:default|manual)/iu;
const IGNORED_CONTROL_ENVIRONMENT = new Set([
  "CLAUDE_AUTO_BACKGROUND_TASKS",
  "CLAUDE_CODE_AUTO_CONNECT_IDE",
  "CLAUDE_CODE_AUTO_COMPACT_WINDOW",
  "CLAUDE_CODE_DEBUG_LOGS_DIR",
  "CLAUDE_CODE_ENABLE_TELEMETRY",
  "CLAUDE_CODE_MAX_CONTEXT_TOKENS",
  "CLAUDE_CODE_RESUME_INTERRUPTED_TURN",
  "CLAUDE_CODE_SAFE_MODE",
  "CLAUDE_CODE_SIMPLE",
  "CLAUDE_CODE_SKIP_PROMPT_HISTORY",
  "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB",
  "CLAUDE_ENV_FILE",
  "DEBUG",
  "DISABLE_AUTO_COMPACT",
  "DISABLE_COMPACT",
]);

function executeFile(file, argumentsList, { input, ...options }) {
  const execution = executeFileAsync(file, argumentsList, options);
  execution.child.stdin.once("error", () => execution.child.kill());
  execution.child.stdin.end(input);
  return execution;
}

export class ClaudeAdapterError extends Error {
  constructor(
    message,
    {
      ambiguous = false,
      cause,
      code = "ERR_CLAUDE_ADAPTER",
      recoverable = false,
      sessionId,
    } = {},
  ) {
    super(message, { cause });
    this.name = "ClaudeAdapterError";
    this.code = code;
    this.ambiguous = ambiguous;
    this.recoverable = recoverable;
    if (sessionId !== undefined) {
      this.sessionId = sessionId;
    }
  }
}

const { assertFields, normalizeRequest } = createAdapterContract({
  AdapterError: ClaudeAdapterError,
  backendName: "Claude",
});

function isCredentialEnvironmentName(name) {
  return (
    /(?:^|_)(?:AUTH|CREDENTIALS?|KEY|PASSWORD|SECRET|TOKEN)(?:_|$)/iu.test(
      name,
    ) ||
    /(?:^|_)PROXY$/iu.test(name) ||
    /(?:^|_)SOCK(?:ET)?$/iu.test(name) ||
    ["ANTHROPIC_CUSTOM_HEADERS", "DOCKER_HOST", "KUBECONFIG"].includes(
      name.toUpperCase(),
    )
  );
}

function isRuntimeInjectionEnvironmentName(name) {
  const normalizedName = name.toUpperCase();
  return (
    normalizedName.startsWith("LD_") ||
    normalizedName.startsWith("DYLD_") ||
    [
      "BASH_ENV",
      "ENV",
      "NODE_OPTIONS",
      "NODE_PATH",
      "SHELLOPTS",
    ].includes(normalizedName)
  );
}

function isolateRuntimeEnvironment(value) {
  const environment = { ...value };
  for (const name of Object.keys(environment)) {
    if (isRuntimeInjectionEnvironmentName(name)) {
      delete environment[name];
    }
  }
  return Object.freeze(environment);
}

function isolateCommandEnvironment(value) {
  const environment = { ...isolateRuntimeEnvironment(value) };
  for (const name of Object.keys(environment)) {
    if (isCredentialEnvironmentName(name)) {
      delete environment[name];
    }
  }
  return Object.freeze(environment);
}

function isolateProcessEnvironment(value) {
  const environment = {
    ...isolateRuntimeEnvironment(isolateGitEnvironment(value)),
  };
  for (const name of IGNORED_CONTROL_ENVIRONMENT) {
    delete environment[name];
  }
  for (const name of Object.keys(environment)) {
    if (name.toUpperCase().startsWith("OTEL_")) {
      delete environment[name];
    }
  }
  environment.CLAUDE_AGENT_SDK_DISABLE_BUILTIN_AGENTS = "1";
  environment.CLAUDE_CODE_AUTO_CONNECT_IDE = "false";
  environment.CLAUDE_CODE_SUBPROCESS_ENV_SCRUB = "0";
  return Object.freeze(environment);
}

function parseVersion(value) {
  const match =
    /^(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?(?:\s+\(Claude Code\))?\s*$/u.exec(
      String(value),
    );
  if (match === null) {
    throw new ClaudeAdapterError("Claude CLI returned an invalid version.", {
      code: "ERR_UNSUPPORTED_CLAUDE_VERSION",
    });
  }
  return Object.freeze({
    text:
      `${match[1]}.${match[2]}.${match[3]}${match[4] ?? ""}` +
      (match[5] ?? ""),
    parts: Object.freeze(match.slice(1, 4).map(Number)),
    prerelease: match[4] !== undefined,
  });
}

function versionAtLeast(actual, minimum) {
  if (actual.prerelease) {
    return false;
  }
  for (let index = 0; index < minimum.length; index += 1) {
    if (actual.parts[index] !== minimum[index]) {
      return actual.parts[index] > minimum[index];
    }
  }
  return true;
}

function processOutput(value) {
  if (typeof value === "string") {
    return value;
  }
  if (Buffer.isBuffer(value)) {
    return value.toString("utf8");
  }
  return "";
}

function parseJsonOutput(value) {
  try {
    const parsed = JSON.parse(value);
    return isRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function outputSchemaFor(request) {
  return request.access === "local-commit"
    ? LOCAL_COMMIT_OUTPUT_SCHEMA
    : request.schema;
}

function turnPrompt(request, recovery) {
  const prefix =
    recovery === "compact"
      ? COMPACTION_PREFIX
      : recovery === "fresh"
        ? RECOVERY_PREFIX
        : undefined;
  let prompt =
    prefix === undefined ? request.prompt : `${prefix}\n\n${request.prompt}`;
  if (request.access === "local-commit") {
    prompt +=
      `\n\nConfirm that HEAD is ${request.commit.expectedHead} and that the ` +
      "current workspace is ready for the authorized commit. Do not modify " +
      "files, stage changes, create a commit, or mutate Git state. The adapter " +
      "will perform the constrained commit after this turn. Return whether it " +
      "is safe to proceed through the provided schema.";
  }
  return prompt;
}

function cliSettings(request, gitDirectories, credentialEnvironmentNames) {
  const deniedWritePaths =
    request.access === "workspace-write"
      ? gitDirectories
      : [request.cwd, ...gitDirectories];
  return JSON.stringify({
    attribution: { commit: "", pr: "", sessionUrl: false },
    autoCompactEnabled: true,
    autoMemoryEnabled: false,
    autoMode: { classifyAllShell: true },
    disableBypassPermissionsMode: "disable",
    env: {
      CLAUDE_AGENT_SDK_DISABLE_BUILTIN_AGENTS: "1",
      CLAUDE_CODE_AUTO_CONNECT_IDE: "false",
      CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: "0",
    },
    fallbackModel: [],
    fileCheckpointingEnabled: false,
    permissions: {
      deny: [
        "Agent",
        "Task",
        "WebFetch",
        "WebSearch",
        "Edit(/.git)",
        "Edit(/.git/**)",
        "Bash(git add *)",
        "Bash(git branch *)",
        "Bash(git checkout *)",
        "Bash(git cherry-pick *)",
        "Bash(git clean *)",
        "Bash(git commit *)",
        "Bash(git merge *)",
        "Bash(git push *)",
        "Bash(git rebase *)",
        "Bash(git remote *)",
        "Bash(git reset *)",
        "Bash(git restore *)",
        "Bash(git revert *)",
        "Bash(git stash *)",
        "Bash(git switch *)",
        "Bash(git tag *)",
        "Bash(gh *)",
        "Bash(glab *)",
      ],
    },
    sandbox: {
      enabled: true,
      failIfUnavailable: true,
      autoAllowBashIfSandboxed: false,
      excludedCommands: [],
      allowUnsandboxedCommands: false,
      enableWeakerNestedSandbox: false,
      credentials: {
        envVars: credentialEnvironmentNames.map((name) => ({
          mode: "deny",
          name,
        })),
      },
      filesystem: {
        disabled: false,
        denyWrite: [...new Set(deniedWritePaths)],
      },
      network: {
        allowedDomains: [],
        deniedDomains: ["*"],
        allowAllUnixSockets: false,
        strictAllowlist: true,
      },
    },
  });
}

function commandArguments(
  request,
  gitDirectories,
  credentialEnvironmentNames,
  session,
) {
  const argumentsList = [
    "-p",
    ...BASE_OPTIONS,
    "--settings",
    cliSettings(request, gitDirectories, credentialEnvironmentNames),
    "--append-system-prompt",
    SYSTEM_INSTRUCTIONS,
    "--permission-mode",
    request.access === "workspace-write" ? "auto" : "plan",
    "--tools",
    request.access === "workspace-write" ? WORKSPACE_TOOLS : READ_ONLY_TOOLS,
  ];
  if (request.model !== undefined) {
    argumentsList.push("--model", request.model);
  }
  const schema = outputSchemaFor(request);
  if (schema !== undefined) {
    argumentsList.push("--json-schema", JSON.stringify(schema));
  }
  if (session !== undefined && session !== null) {
    argumentsList.push("--resume", session.id);
    if (session.mode === "fork") {
      argumentsList.push("--fork-session");
    }
  }
  if (
    argumentsList.some(
      (argument) => Buffer.byteLength(argument) > MAX_ARGUMENT_BYTES,
    )
  ) {
    throw new ClaudeAdapterError("Claude CLI argument is too large.", {
      code: "ERR_INVALID_CLAUDE_OPTIONS",
    });
  }
  return argumentsList;
}

function outputError(payload, fallback = "Claude turn failed.") {
  const message =
    typeof payload?.result === "string" && payload.result.length > 0
      ? payload.result
      : fallback;
  const sessionId =
    typeof payload?.session_id === "string" &&
    SESSION_ID_PATTERN.test(payload.session_id)
      ? payload.session_id
      : undefined;
  if (CONTEXT_ERROR_PATTERN.test(message)) {
    return new ClaudeAdapterError("Claude context window is full.", {
      code: "ERR_CLAUDE_CONTEXT_EXHAUSTED",
      recoverable: true,
      sessionId,
    });
  }
  if (MODEL_ERROR_PATTERN.test(message)) {
    return new ClaudeAdapterError("Claude model is unavailable.", {
      code: "ERR_CLAUDE_MODEL_UNAVAILABLE",
      sessionId,
    });
  }
  if (AUTO_ERROR_PATTERN.test(message)) {
    return new ClaudeAdapterError("Claude auto mode is unavailable.", {
      code: "ERR_UNSUPPORTED_CLAUDE_CAPABILITY",
      sessionId,
    });
  }
  if (SESSION_ERROR_PATTERN.test(message)) {
    return new ClaudeAdapterError("Claude session is unavailable.", {
      code: "ERR_CLAUDE_SESSION_UNAVAILABLE",
      recoverable: true,
      sessionId,
    });
  }
  return new ClaudeAdapterError(fallback, {
    code: "ERR_CLAUDE_TURN_FAILED",
    sessionId,
  });
}

function validateRequestedModel(payload, model) {
  if (model === undefined || !model.startsWith("claude-")) {
    return;
  }
  const usage = payload.modelUsage ?? payload.model_usage;
  const usedModels = isRecord(usage) ? Object.keys(usage) : [];
  if (usedModels.length !== 1 || usedModels[0] !== model) {
    throw new ClaudeAdapterError(
      `Claude substituted the requested model: ${model}.`,
      { code: "ERR_CLAUDE_MODEL_REROUTED" },
    );
  }
}

function normalizeResult(payload, request) {
  const schema = outputSchemaFor(request);
  const hasValidOutput =
    typeof payload?.result === "string"
      ? payload.result.length > 0 || schema !== undefined
      : payload?.result == null && schema !== undefined;
  const hasValidPermissionDenials =
    payload?.permission_denials == null ||
    Array.isArray(payload.permission_denials);
  if (
    !isRecord(payload) ||
    payload.type !== "result" ||
    payload.subtype !== "success" ||
    payload.is_error !== false ||
    !hasValidOutput ||
    typeof payload.session_id !== "string" ||
    !SESSION_ID_PATTERN.test(payload.session_id) ||
    !hasValidPermissionDenials
  ) {
    throw outputError(payload, "Claude returned an invalid result.");
  }
  if (payload.permission_denials?.length > 0) {
    throw new ClaudeAdapterError("Claude requested denied permission.", {
      code: "ERR_CLAUDE_PERMISSION_DENIED",
      sessionId: payload.session_id,
    });
  }
  validateRequestedModel(payload, request.model);
  let structured = null;
  if (schema !== undefined) {
    if (!isRecord(payload.structured_output)) {
      throw new ClaudeAdapterError(
        "Claude returned invalid structured output.",
        { code: "ERR_CLAUDE_STRUCTURED_OUTPUT" },
      );
    }
    structured = deepFreeze(payload.structured_output);
  }
  if (
    request.access === "local-commit" &&
    (structured.ready !== true || Object.keys(structured).length !== 1)
  ) {
    throw new ClaudeAdapterError(
      "Claude did not confirm the authorized local commit.",
      { code: "ERR_CLAUDE_LOCAL_COMMIT_POLICY" },
    );
  }
  return Object.freeze({
    output:
      typeof payload.result === "string" && payload.result.length > 0
        ? payload.result
        : JSON.stringify(structured),
    structured,
    sessionId: payload.session_id,
  });
}

export function createClaudeAdapter(options = {}) {
  assertFields(
    options,
    ["claudeBinary", "env", "execute", "platform"],
    "Claude adapter options",
  );
  const {
    claudeBinary = "claude",
    env = process.env,
    execute = executeFile,
    platform = process.platform,
  } = options;
  if (
    typeof claudeBinary !== "string" ||
    claudeBinary.trim().length === 0 ||
    /[\0\r\n]/u.test(claudeBinary) ||
    !isEnvironment(env) ||
    typeof execute !== "function" ||
    typeof platform !== "string" ||
    platform.length === 0 ||
    /[\0\r\n]/u.test(platform)
  ) {
    throw new ClaudeAdapterError("Claude adapter options are invalid.", {
      code: "ERR_INVALID_CLAUDE_OPTIONS",
    });
  }
  const processEnvironment = isolateProcessEnvironment(env);
  const commandEnvironment = isolateCommandEnvironment(processEnvironment);
  const credentialEnvironmentNames = Object.freeze(
    Object.keys(processEnvironment)
      .filter(isCredentialEnvironmentName)
      .filter((name) => /^[A-Za-z_][A-Za-z0-9_]*$/u.test(name))
      .sort(),
  );
  let probePromise;

  async function inspectCapabilities() {
    let versionResult;
    let helpResult;
    let socatAvailable = false;
    try {
      [versionResult, helpResult] = await Promise.all([
        execute(claudeBinary, ["--version"], {
          encoding: "utf8",
          env: processEnvironment,
          maxBuffer: 1024 * 1024,
          timeout: 10_000,
        }),
        execute(claudeBinary, ["--help"], {
          encoding: "utf8",
          env: processEnvironment,
          maxBuffer: 1024 * 1024,
          timeout: 10_000,
        }),
      ]);
    } catch (cause) {
      throw new ClaudeAdapterError("Claude CLI is unavailable.", {
        cause,
        code: "ERR_CLAUDE_UNAVAILABLE",
      });
    }
    if (platform === "linux") {
      try {
        await execute(SOCAT_BINARY, ["-V"], {
          encoding: "utf8",
          env: commandEnvironment,
          maxBuffer: 1024 * 1024,
          timeout: 10_000,
        });
        socatAvailable = true;
      } catch {
        socatAvailable = false;
      }
    }
    const version = parseVersion(processOutput(versionResult.stdout).trim());
    const help =
      processOutput(helpResult.stdout) + processOutput(helpResult.stderr);
    const cliSupported =
      versionAtLeast(version, MINIMUM_CLAUDE_VERSION) &&
      REQUIRED_HELP_FLAGS.every((flag) => help.includes(flag));
    const isolated =
      cliSupported &&
      platform === "linux" &&
      socatAvailable &&
      (await probeClaudeLocalCommit({
        bubblewrapBinary: BUBBLEWRAP_BINARY,
        env: commandEnvironment,
        execute,
      }));
    return Object.freeze({
      version: version.text,
      structuredOutput: cliSupported,
      readOnly: cliSupported,
      autonomousWrite: isolated,
      workspaceWrite: isolated,
      localCommit: isolated,
      remoteWriteBlocked: isolated,
      nativeSessionContinuation: cliSupported,
      nativeSessionFork: cliSupported,
    });
  }

  function probe() {
    probePromise ??= inspectCapabilities();
    return probePromise;
  }

  async function assertCapabilities(request) {
    const capabilities = await probe();
    const required = ["remoteWriteBlocked"];
    if (outputSchemaFor(request) !== undefined) {
      required.push("structuredOutput");
    }
    if (request.access === "workspace-write") {
      required.push("autonomousWrite", "workspaceWrite");
    } else {
      required.push("readOnly");
    }
    if (request.access === "local-commit") {
      required.push("localCommit");
    }
    if (request.session?.mode === "continue") {
      required.push("nativeSessionContinuation");
    }
    if (request.session?.mode === "fork") {
      required.push("nativeSessionFork");
    }
    if (required.some((capability) => capabilities[capability] !== true)) {
      throw new ClaudeAdapterError(
        "Installed Claude CLI cannot enforce the requested capability.",
        { code: "ERR_UNSUPPORTED_CLAUDE_CAPABILITY" },
      );
    }
  }

  async function gitMetadataDirectories(cwd) {
    let result;
    try {
      result = await execute(
        "git",
        [
          "-C",
          cwd,
          "rev-parse",
          "--absolute-git-dir",
          "--git-common-dir",
        ],
        {
          encoding: "utf8",
          env: processEnvironment,
          maxBuffer: 1024 * 1024,
          timeout: 10_000,
        },
      );
    } catch (cause) {
      throw new ClaudeAdapterError("Cannot resolve Git metadata paths.", {
        cause,
        code: "ERR_CLAUDE_ISOLATION",
      });
    }
    const directories = processOutput(result.stdout)
      .trim()
      .split(/\r?\n/u)
      .map((path) => (isAbsolute(path) ? path : resolve(cwd, path)));
    if (
      directories.length !== 2 ||
      directories.some(
        (path) =>
          !isAbsolute(path) || path.length === 0 || /[\0\r\n]/u.test(path),
      )
    ) {
      throw new ClaudeAdapterError("Git returned invalid metadata paths.", {
        code: "ERR_CLAUDE_ISOLATION",
      });
    }
    let canonicalDirectories;
    try {
      canonicalDirectories = await Promise.all(
        directories.map((path) => realpath(path)),
      );
    } catch (cause) {
      throw new ClaudeAdapterError("Cannot canonicalize Git metadata paths.", {
        cause,
        code: "ERR_CLAUDE_ISOLATION",
      });
    }
    return Object.freeze([
      ...new Set([
        resolve(cwd, ".git"),
        ...directories,
        ...canonicalDirectories,
      ]),
    ]);
  }

  async function runAttempt(request, { recovery, session } = {}) {
    const gitDirectories = await gitMetadataDirectories(request.cwd);
    const selectedSession = session === undefined ? request.session : session;
    const argumentsList = commandArguments(
      request,
      gitDirectories,
      credentialEnvironmentNames,
      selectedSession,
    );
    let processResult;
    try {
      processResult = await execute(
        claudeBinary,
        argumentsList,
        {
          cwd: request.cwd,
          encoding: "utf8",
          env: processEnvironment,
          input: turnPrompt(request, recovery),
          maxBuffer: MAX_PROCESS_OUTPUT_BYTES,
        },
      );
    } catch (cause) {
      const standardError = processOutput(cause?.stderr);
      if (PERMISSION_MODE_FALLBACK_PATTERN.test(standardError)) {
        throw new ClaudeAdapterError(
          "Claude permission mode fell back to Manual mode.",
          {
            cause,
            code: "ERR_UNSUPPORTED_CLAUDE_CAPABILITY",
          },
        );
      }
      const standardOutput = processOutput(cause?.stdout);
      const payload = parseJsonOutput(standardOutput);
      if (payload === null) {
        const reportedError = outputError(
          { result: `${standardError}\n${standardOutput}`.trim() },
          "Claude process failed.",
        );
        if (reportedError.code !== "ERR_CLAUDE_TURN_FAILED") {
          throw reportedError;
        }
        throw new ClaudeAdapterError("Claude process was interrupted.", {
          ambiguous: true,
          cause,
          code: "ERR_CLAUDE_PROCESS_INTERRUPTED",
          recoverable: true,
        });
      }
      throw outputError(payload, standardError || "Claude process failed.");
    }
    if (
      PERMISSION_MODE_FALLBACK_PATTERN.test(processOutput(processResult.stderr))
    ) {
      throw new ClaudeAdapterError(
        "Claude permission mode fell back to Manual mode.",
        { code: "ERR_UNSUPPORTED_CLAUDE_CAPABILITY" },
      );
    }
    const payload = parseJsonOutput(processOutput(processResult.stdout));
    const result = normalizeResult(payload, request);
    if (
      selectedSession?.mode === "fork" &&
      result.sessionId === selectedSession.id
    ) {
      throw new ClaudeAdapterError("Claude returned invalid fork lineage.", {
        code: "ERR_CLAUDE_PROTOCOL",
      });
    }
    if (
      selectedSession?.mode === "continue" &&
      result.sessionId !== selectedSession.id
    ) {
      throw new ClaudeAdapterError(
        "Claude continued an unexpected session.",
        { code: "ERR_CLAUDE_PROTOCOL" },
      );
    }
    return result;
  }

  async function createAuthorizedCommit(request) {
    try {
      await executeClaudeLocalCommit({
        bubblewrapBinary: BUBBLEWRAP_BINARY,
        cwd: request.cwd,
        env: commandEnvironment,
        execute,
        expectedHead: request.commit.expectedHead,
        message: request.commit.message,
      });
    } catch (cause) {
      throw new ClaudeAdapterError(
        "Authorized local commit outcome requires Git-state verification.",
        {
          ambiguous: true,
          cause,
          code: "ERR_CLAUDE_LOCAL_COMMIT_INTERRUPTED",
        },
      );
    }
  }

  async function run(value) {
    const request = normalizeRequest(value);
    if (
      (request.model?.startsWith("-") ?? false) ||
      (request.session !== undefined &&
        !SESSION_ID_PATTERN.test(request.session.id))
    ) {
      throw new ClaudeAdapterError("Claude request is invalid.", {
        code: "ERR_INVALID_CLAUDE_OPTIONS",
      });
    }
    await assertCapabilities(request);
    let result;
    try {
      result = await runAttempt(request);
    } catch (cause) {
      if (!(cause instanceof ClaudeAdapterError)) {
        throw cause;
      }
      if (request.access === "local-commit") {
        if (!cause.ambiguous && !cause.recoverable) {
          throw cause;
        }
        throw new ClaudeAdapterError(
          "Claude local-commit outcome requires Git-state verification.",
          {
            ambiguous: true,
            cause,
            code: "ERR_CLAUDE_LOCAL_COMMIT_INTERRUPTED",
          },
        );
      }
      if (
        request.session?.mode === "fork" &&
        cause.code === "ERR_CLAUDE_SESSION_UNAVAILABLE" &&
        (cause.sessionId === undefined || cause.sessionId === request.session.id)
      ) {
        throw new ClaudeAdapterError("Claude source session is unavailable.", {
          cause,
          code: "ERR_CLAUDE_SOURCE_SESSION_UNAVAILABLE",
        });
      }
      if (cause.code === "ERR_CLAUDE_CONTEXT_EXHAUSTED") {
        const forkSourceId =
          request.session?.mode === "fork" ? request.session.id : undefined;
        const sessionId =
          cause.sessionId ??
          (request.session?.mode === "continue"
            ? request.session.id
            : undefined);
        if (
          forkSourceId !== undefined &&
          (sessionId === undefined || sessionId === forkSourceId)
        ) {
          throw new ClaudeAdapterError(
            "Claude did not report a recoverable forked session.",
            {
              cause,
              code: "ERR_CLAUDE_PROTOCOL",
            },
          );
        }
        if (sessionId !== undefined) {
          try {
            return await runAttempt(request, {
              recovery: "compact",
              session: { id: sessionId, mode: "continue" },
            });
          } catch (recoveryCause) {
            if (
              !(recoveryCause instanceof ClaudeAdapterError) ||
              recoveryCause.code !== "ERR_CLAUDE_CONTEXT_EXHAUSTED"
            ) {
              throw recoveryCause;
            }
            if (forkSourceId !== undefined) {
              throw new ClaudeAdapterError(
                "Claude forked session context is still full.",
                {
                  cause: recoveryCause,
                  code: "ERR_CLAUDE_CONTEXT_EXHAUSTED",
                  recoverable: true,
                  sessionId,
                },
              );
            }
          }
        }
        result = await runAttempt(request, {
          recovery: "fresh",
          session: null,
        });
      } else if (
        cause.code === "ERR_CLAUDE_SESSION_UNAVAILABLE" &&
        request.session?.mode === "continue"
      ) {
        result = await runAttempt(request, {
          recovery: "fresh",
          session: null,
        });
      } else {
        throw cause;
      }
    }
    if (request.access === "local-commit") {
      await createAuthorizedCommit(request);
    }
    return result;
  }

  return Object.freeze({ id: CLAUDE_BACKEND_ID, probe, run });
}
