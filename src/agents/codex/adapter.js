import { execFile as executeFileCallback, spawn } from "node:child_process";
import { lstatSync } from "node:fs";
import { join } from "node:path";
import { promisify } from "node:util";

import { executeOwnedProcess, spawnOwnedProcess } from "../owned-process.js";
import packageMetadata from "../../../package.json" with { type: "json" };
import {
  createAdapterContract,
  deepFreeze,
  isEnvironment,
  isRecord,
  isolateGitEnvironment,
  STRUCTURED_OUTPUT_FAILURE_CLASS,
} from "../adapter-contract.js";
import { createCodexAppServerClient } from "./app-server.js";
import {
  executeCodexLocalCommit,
  probeCodexLocalCommit,
} from "./local-commit.js";
import { assertCodexSchema } from "./schema.js";
import {
  assertCodexWorkspaceStorage,
  createCodexWorkspaceStorage,
} from "./workspace-storage.js";

export const CODEX_BACKEND_ID = "codex";

const executeFile = promisify(executeFileCallback);
const MINIMUM_CODEX_VERSION = Object.freeze([0, 147, 0]);
const MAX_MCP_SERVERS = 256;
const MCP_DISCOVERY_TIMEOUT_MS = 30_000;
const MCP_SERVER_NAME_PATTERN = /^[A-Za-z0-9_-]+$/u;
const MAX_MODEL_PAGES = 32;
const CODEX_PROFILE_PATTERN = /^[A-Za-z0-9_][A-Za-z0-9_-]{0,255}$/u;
const DECIMAL_CONTEXT_SIZE_PATTERN = /^[1-9][0-9]*$/u;
const MAX_CONTEXT_SIZE = 9_223_372_036_854_775_807n;
const CAPABILITY_DIAGNOSTICS = Object.freeze({
  autonomousWrite: "capability_autonomous_write",
  gitMetadataWriteBlocked: "capability_git_metadata_write_blocked",
  localCommit: "capability_local_commit",
  nativeSessionContinuation: "capability_session_continuation",
  nativeSessionFork: "capability_session_fork",
  readOnly: "capability_read_only",
  remoteWriteBlocked: "capability_remote_write_blocked",
  structuredOutput: "capability_structured_output",
  workspaceWrite: "capability_workspace_write",
});
const TERMINAL_TURN_DIAGNOSTICS = Object.freeze({
  activeTurnNotSteerable: "turn_active_not_steerable",
  badRequest: "turn_bad_request",
  cyberPolicy: "turn_cyber_policy",
  httpConnectionFailed: "turn_http_connection_failed",
  internalServerError: "turn_internal_server_error",
  misalignmentPolicyViolation: "turn_misalignment_policy_violation",
  other: "turn_other",
  responseStreamConnectionFailed: "turn_response_stream_connection_failed",
  responseStreamDisconnected: "turn_response_stream_disconnected",
  responseTooManyFailedAttempts: "turn_response_too_many_failed_attempts",
  sandboxError: "turn_sandbox_error",
  serverOverloaded: "turn_server_overloaded",
  sessionBudgetExceeded: "turn_session_budget_exceeded",
  threadRollbackFailed: "turn_thread_rollback_failed",
  unauthorized: "turn_unauthorized",
  usageLimitExceeded: "turn_usage_limit_exceeded",
});
const MAX_HTTP_ERROR_BYTES = 16_384;
const CLIENT_ERROR_STATUSES = new Map([
  [400, "Bad Request"],
  [401, "Unauthorized"],
  [403, "Forbidden"],
  [404, "Not Found"],
  [405, "Method Not Allowed"],
  [413, "Payload Too Large"],
  [415, "Unsupported Media Type"],
  [422, "Unprocessable Entity"],
]);
const CLIENT_ERROR_CODES = new Set([
  "invalid_api_key",
  "invalid_json_schema",
  "invalid_parameter",
  "invalid_value",
  "missing_required_parameter",
  "model_not_found",
  "unsupported_parameter",
]);
const CODEX_DIAGNOSTIC_CLASSES = new Set([
  ...Object.values(CAPABILITY_DIAGNOSTICS),
  ...Object.values(TERMINAL_TURN_DIAGNOSTICS),
  "isolation_command_host",
  "isolation_effective_configuration",
  "isolation_feature",
  "isolation_mcp",
  "isolation_mcp_discovery",
  "isolation_memory",
  "isolation_network",
  "isolation_notification",
  "isolation_shell_environment",
  "operation_dynamic_tool",
  "operation_hosted_tool",
  "operation_lifecycle_hook",
  "operation_local_commit",
  "operation_mcp_tool",
  "operation_memory",
  "operation_multi_agent",
  "operation_plugin",
  "operation_read_only_write",
  "operation_remote_write",
]);
const DISABLED_FEATURES = Object.freeze([
  "apps",
  "artifact",
  "browser_use",
  "browser_use_external",
  "browser_use_full_cdp_access",
  "code_mode",
  "code_mode_only",
  "computer_use",
  "goals",
  "guardian_approval",
  "guardianv2",
  "hooks",
  "image_generation",
  "in_app_browser",
  "js_repl",
  "memories",
  "multi_agent",
  "plugins",
  "remote_plugin",
  "shell_snapshot",
  "skill_mcp_dependency_install",
]);
const EMPTY_SHELL_ENVIRONMENT = Object.freeze({});
const CODEX_CORE_SHELL_ENVIRONMENT_NAMES = Object.freeze([
  "HOME",
  "LOGNAME",
  "PATH",
  "SHELL",
  "USER",
]);
const OWNED_PROCESS_ENVIRONMENT_NAME = "AGENT_RUNNER_OWNED_PROCESS";
const SHELL_ENVIRONMENT_POLICY_FIELDS = Object.freeze([
  "exclude",
  "experimental_use_profile",
  "filters",
  "ignore_default_excludes",
  "include_only",
  "inherit",
  "set",
]);

function shellEnvironmentNames(environment) {
  return [
    ...CODEX_CORE_SHELL_ENVIRONMENT_NAMES,
    OWNED_PROCESS_ENVIRONMENT_NAME,
    ...Object.keys(environment),
  ];
}

function shellEnvironmentPolicy(environment) {
  const values = Object.entries(environment)
    .map(([name, value]) => `${name}=${JSON.stringify(value)}`)
    .join(",");
  const names = shellEnvironmentNames(environment)
    .map((name) => JSON.stringify(name))
    .join(",");
  return (
    'shell_environment_policy={inherit="all",ignore_default_excludes=false,' +
    `exclude=[],set={${values}},include_only=[${names}],` +
    "experimental_use_profile=false}"
  );
}

const EMPTY_SHELL_ENVIRONMENT_POLICY = shellEnvironmentPolicy(
  EMPTY_SHELL_ENVIRONMENT,
);
const APP_SERVER_BASE_ARGUMENTS = Object.freeze([
  "app-server",
  "--listen",
  "stdio://",
  "--strict-config",
  "--enable",
  "code_mode_host",
  ...DISABLED_FEATURES.flatMap((feature) => ["--disable", feature]),
  "-c",
  "notify=[]",
  "-c",
  EMPTY_SHELL_ENVIRONMENT_POLICY,
  "-c",
  "memories.generate_memories=false",
  "-c",
  "memories.use_memories=false",
  "-c",
  'web_search="disabled"',
]);
const LOCAL_COMMIT_OUTPUT_SCHEMA = Object.freeze({
  type: "object",
  properties: Object.freeze({
    ready: Object.freeze({ type: "boolean" }),
  }),
  required: Object.freeze(["ready"]),
  additionalProperties: false,
});
const COMPACTION_PREFIX =
  "Compact the existing Codex session context, preserving decisions and " +
  "valid progress. Then complete this durable request from the observed " +
  "current workspace without repeating completed work.";
const RECOVERY_PREFIX =
  "The previous Codex session could not continue. Reconstruct context from " +
  "this durable request and the observed current workspace. Preserve valid " +
  "progress and do not repeat completed work.";
const GIT_COMMAND_PREFIX =
  String.raw`(?:^|[\n;&|]\s*)(?:[^\s;&|]*/)?git` +
  String.raw`(?:\s+(?:(?:-C|-c|--git-dir|--work-tree|--namespace)\s+\S+|` +
  String.raw`--(?:git-dir|work-tree|namespace)=\S+|--[a-z-]+))*\s+`;
const REMOTE_MUTATION_PATTERNS = Object.freeze([
  new RegExp(`${GIT_COMMAND_PREFIX}push\\b`, "iu"),
  new RegExp(
    `${GIT_COMMAND_PREFIX}remote\\s+` +
      "(?:add|remove|rename|set-head|set-branches|set-url|update|prune)\\b",
    "iu",
  ),
  new RegExp(
    `${GIT_COMMAND_PREFIX}config\\b` +
      "[^\\n;&|]*\\b(?:--add|--replace-all|--unset(?:-all)?|" +
      "--rename-section|--remove-section|set|unset|rename-section|" +
      "remove-section)\\b[^\\n;&|]*(?:remote\\.|url\\.)",
    "iu",
  ),
  new RegExp(
    `${GIT_COMMAND_PREFIX}config\\b` +
      "(?![^\\n;&|]*\\b(?:--get(?:-all|-regexp|-urlmatch)?|" +
      "get(?:-all|-regexp|-urlmatch)?|list)\\b" +
      "[^\\n;&|]*(?:remote\\.|url\\.))" +
      "[^\\n;&|]*(?:remote\\.|url\\.)[^\\s;&|]*" +
      "\\s+(?!\\d*[<>]|#)[^\\s;&|]+",
    "iu",
  ),
  new RegExp(
    String.raw`(?:^|[\n;&|]\s*)(?:[^\s;&|]*/)?(?:gh|glab)\b[^\n;&|]*` +
      String.raw`\b(?:approve|archive|cancel|close|comment|create|delete|` +
      String.raw`disable|edit|enable|fork|merge|rename|reopen|rerun|sync|` +
      String.raw`transfer|unarchive|upload)\b`,
    "iu",
  ),
  new RegExp(
    String.raw`(?:^|[\n;&|]\s*)(?:[^\s;&|]*/)?(?:gh|glab)\b[^\n;&|]*` +
      String.raw`\b(?:ci|workflow)\s+run\b`,
    "iu",
  ),
  new RegExp(
    String.raw`(?:^|[\n;&|]\s*)(?:[^\s;&|]*/)?(?:gh|glab)\b[^\n;&|]*` +
      String.raw`\bapi\b[^\n;&|]*(?:--method(?:=|\s+)|-X\s*)` +
      String.raw`(?:DELETE|PATCH|POST|PUT)\b`,
    "iu",
  ),
]);
const GIT_COMMAND_PATTERN = new RegExp(
  `${GIT_COMMAND_PREFIX}([a-z][a-z-]*)\\b`,
  "giu",
);
const LOCAL_COMMIT_READ_ONLY_GIT_COMMANDS = new Set([
  "cat-file",
  "diff",
  "diff-files",
  "diff-index",
  "diff-tree",
  "for-each-ref",
  "log",
  "ls-files",
  "ls-tree",
  "merge-base",
  "name-rev",
  "rev-list",
  "rev-parse",
  "show",
  "show-ref",
  "status",
]);
const SAFE_TURN_ITEM_TYPES = new Set([
  "agentMessage",
  "commandExecution",
  "contextCompaction",
  "enteredReviewMode",
  "exitedReviewMode",
  "fileChange",
  "imageView",
  "plan",
  "reasoning",
  "sleep",
  "userMessage",
]);
const TERMINAL_ITEM_STATUSES = new Set(["completed", "declined", "failed"]);
const TERMINAL_TURN_STATUSES = new Set(["completed", "failed", "interrupted"]);

export function normalizeCodexDiagnosticClass(value) {
  return CODEX_DIAGNOSTIC_CLASSES.has(value) ? value : undefined;
}

export class CodexAdapterError extends Error {
  constructor(
    message,
    {
      ambiguous = false,
      cause,
      code = "ERR_CODEX_ADAPTER",
      diagnosticClass,
      effectStarted,
      failureClass,
      method,
      recoverable = false,
    } = {},
  ) {
    super(message, { cause });
    this.name = "CodexAdapterError";
    this.code = code;
    this.ambiguous = ambiguous;
    this.recoverable = recoverable;
    if (typeof effectStarted === "boolean") {
      this.effectStarted = effectStarted;
    }
    if (failureClass === STRUCTURED_OUTPUT_FAILURE_CLASS) {
      this.failureClass = failureClass;
    }
    const normalizedDiagnosticClass =
      normalizeCodexDiagnosticClass(diagnosticClass);
    if (normalizedDiagnosticClass !== undefined) {
      this.diagnosticClass = normalizedDiagnosticClass;
    }
    if (method !== undefined) {
      this.method = method;
    }
  }
}

const {
  assertFields,
  normalizeExecutionOptions: normalizeContractExecutionOptions,
  normalizeRequest: normalizeContractRequest,
} = createAdapterContract({
  AdapterError: CodexAdapterError,
  backendName: "Codex",
});

function validateExecutionOptions(options) {
  if (
    (options.profile !== undefined &&
      !CODEX_PROFILE_PATTERN.test(options.profile)) ||
    (options.contextSize !== undefined &&
      (!DECIMAL_CONTEXT_SIZE_PATTERN.test(options.contextSize) ||
        BigInt(options.contextSize) > MAX_CONTEXT_SIZE))
  ) {
    throw new CodexAdapterError("Codex execution options are invalid.", {
      code: "ERR_INVALID_CODEX_OPTIONS",
    });
  }
  return options;
}

function normalizeExecutionOptions(value) {
  return validateExecutionOptions(normalizeContractExecutionOptions(value));
}

export function validateCodexExecutionOptions(value) {
  normalizeExecutionOptions(value);
  return value;
}

function normalizeRequest(value) {
  return validateExecutionOptions(normalizeContractRequest(value));
}

function executionOptionsFor(request) {
  return Object.freeze({
    contextSize: request.contextSize,
    model: request.model,
    profile: request.profile,
  });
}

function nativeArguments(options, argumentsList) {
  const result = [];
  if (options.profile !== undefined) {
    result.push("--profile", options.profile);
  }
  if (options.contextSize !== undefined) {
    result.push("-c", `model_context_window=${options.contextSize}`);
  }
  result.push(...argumentsList);
  return result;
}

function isolateCommandEnvironment(value) {
  const environment = { ...value };
  for (const name of Object.keys(environment)) {
    if (/(?:KEY|SECRET|TOKEN)/iu.test(name)) {
      delete environment[name];
    }
  }
  return Object.freeze(environment);
}

function parseVersion(value) {
  const match =
    /^codex-cli\s+(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?\s*$/u.exec(
      String(value),
    );
  if (match === null) {
    throw new CodexAdapterError("Codex CLI returned an invalid version.", {
      code: "ERR_UNSUPPORTED_CODEX_VERSION",
    });
  }
  return Object.freeze({
    text: `${match[1]}.${match[2]}.${match[3]}${match[4] ?? ""}${match[5] ?? ""}`,
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

function processError(message, cause, code = "ERR_CODEX_UNAVAILABLE") {
  if (cause instanceof CodexAdapterError) {
    return cause;
  }
  return new CodexAdapterError(message, { cause, code });
}

function parseMcpServerNames(value) {
  let servers;
  try {
    servers = JSON.parse(value);
  } catch {
    throw new CodexAdapterError("Codex returned invalid MCP configuration.", {
      code: "ERR_CODEX_ISOLATION",
      diagnosticClass: "isolation_mcp",
    });
  }
  if (!Array.isArray(servers) || servers.length > MAX_MCP_SERVERS) {
    throw new CodexAdapterError("Codex returned invalid MCP configuration.", {
      code: "ERR_CODEX_ISOLATION",
      diagnosticClass: "isolation_mcp",
    });
  }
  const names = servers.map((server) => server?.name);
  if (
    names.some(
      (name) =>
        typeof name !== "string" ||
        name.length === 0 ||
        name.length > 256 ||
        !MCP_SERVER_NAME_PATTERN.test(name),
    ) ||
    new Set(names).size !== names.length
  ) {
    throw new CodexAdapterError("Codex returned invalid MCP configuration.", {
      code: "ERR_CODEX_ISOLATION",
      diagnosticClass: "isolation_mcp",
    });
  }
  return names;
}

function sameEnvironment(actual, expected) {
  const names = Object.keys(expected);
  return (
    isRecord(actual) &&
    Object.keys(actual).length === names.length &&
    names.every((name) => actual[name] === expected[name])
  );
}

function sameNames(actual, expected) {
  return (
    Array.isArray(actual) &&
    actual.length === expected.length &&
    actual.every((name, index) => name === expected[index])
  );
}

function hasExactFields(value, fields) {
  return (
    isRecord(value) &&
    Object.keys(value).length === fields.length &&
    fields.every((field) => Object.hasOwn(value, field))
  );
}

function assertIsolatedConfiguration(
  value,
  expectedMcpServers,
  expectedShellEnvironment,
) {
  const config = value?.config;
  const features = config?.features;
  const memories = config?.memories;
  const mcpServers = config?.mcp_servers;
  const shellEnvironment = config?.shell_environment_policy;
  const expectedShellEnvironmentNames = shellEnvironmentNames(
    expectedShellEnvironment,
  );
  let diagnosticClass;
  if (!isRecord(config) || !isRecord(features)) {
    diagnosticClass = "isolation_effective_configuration";
  } else if (DISABLED_FEATURES.some((feature) => features[feature] !== false)) {
    diagnosticClass = "isolation_feature";
  } else if (features.code_mode_host !== true) {
    diagnosticClass = "isolation_command_host";
  } else if (
    !isRecord(memories) ||
    memories.generate_memories !== false ||
    memories.use_memories !== false
  ) {
    diagnosticClass = "isolation_memory";
  } else if (!Array.isArray(config.notify) || config.notify.length !== 0) {
    diagnosticClass = "isolation_notification";
  } else if (
    !hasExactFields(shellEnvironment, SHELL_ENVIRONMENT_POLICY_FIELDS) ||
    shellEnvironment.inherit !== "all" ||
    shellEnvironment.ignore_default_excludes !== false ||
    shellEnvironment.experimental_use_profile !== false ||
    !sameEnvironment(shellEnvironment.set, expectedShellEnvironment) ||
    !sameNames(shellEnvironment.exclude, []) ||
    !sameNames(shellEnvironment.include_only, expectedShellEnvironmentNames) ||
    shellEnvironment.filters !== null
  ) {
    diagnosticClass = "isolation_shell_environment";
  } else if (config.web_search !== "disabled") {
    diagnosticClass = "isolation_network";
  } else if (
    !isRecord(mcpServers) ||
    expectedMcpServers.some((name) => !Object.hasOwn(mcpServers, name)) ||
    Object.values(mcpServers).some(
      (server) => !isRecord(server) || server.enabled !== false,
    )
  ) {
    diagnosticClass = "isolation_mcp";
  }
  if (diagnosticClass !== undefined) {
    throw new CodexAdapterError("Codex external tools are not isolated.", {
      code: "ERR_CODEX_ISOLATION",
      diagnosticClass,
    });
  }
}

function existingProjectAgentsDirectory(cwd) {
  const projectAgentsPath = join(cwd, ".agents");
  try {
    return lstatSync(projectAgentsPath).isDirectory()
      ? projectAgentsPath
      : undefined;
  } catch {
    return undefined;
  }
}

function sandboxFor(request, workspaceStorage) {
  if (request.access !== "workspace-write") {
    return Object.freeze({ type: "readOnly", networkAccess: false });
  }
  const projectAgentsPath = existingProjectAgentsDirectory(request.cwd);
  return Object.freeze({
    type: "workspaceWrite",
    writableRoots: Object.freeze([
      request.cwd,
      ...(projectAgentsPath === undefined ? [] : [projectAgentsPath]),
      workspaceStorage.rootPath,
    ]),
    networkAccess: false,
    excludeTmpdirEnvVar: true,
    excludeSlashTmp: true,
  });
}

function threadSandboxFor(request) {
  return request.access === "workspace-write" ? "workspace-write" : "read-only";
}

function threadOptions(request) {
  const options = {
    approvalPolicy: "never",
    approvalsReviewer: "user",
    cwd: request.cwd,
    sandbox: threadSandboxFor(request),
  };
  if (request.model !== undefined) {
    options.model = request.model;
  }
  return options;
}

function turnPrompt(request, recovery) {
  const prefix =
    recovery === "compact"
      ? COMPACTION_PREFIX
      : recovery === "fresh"
        ? RECOVERY_PREFIX
        : undefined;
  let prompt =
    prefix === undefined
      ? request.prompt
      : `${prefix}\n\n${request.recoveryPrompt}`;
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

function outputSchemaFor(request) {
  return request.access === "local-commit"
    ? LOCAL_COMMIT_OUTPUT_SCHEMA
    : request.schema;
}

function turnOptions(request, threadId, prompt, workspaceStorage) {
  const options = {
    threadId,
    input: Object.freeze([{ type: "text", text: prompt }]),
    cwd: request.cwd,
    approvalPolicy: "never",
    approvalsReviewer: "user",
    sandboxPolicy: sandboxFor(request, workspaceStorage),
  };
  if (request.model !== undefined) {
    options.model = request.model;
  }
  const outputSchema = outputSchemaFor(request);
  if (outputSchema !== undefined) {
    options.outputSchema = outputSchema;
  }
  return options;
}

function assertThreadResponse(value) {
  if (
    !isRecord(value) ||
    !isRecord(value.thread) ||
    typeof value.thread.id !== "string" ||
    value.thread.id.length === 0
  ) {
    throw new CodexAdapterError("Codex returned an invalid thread.", {
      code: "ERR_CODEX_PROTOCOL",
    });
  }
  return value.thread.id;
}

async function validateModel(client, model) {
  if (model === undefined) {
    return;
  }
  const cursors = new Set();
  let cursor = null;
  for (let page = 0; page < MAX_MODEL_PAGES; page += 1) {
    const result = await client.request("model/list", {
      cursor,
      includeHidden: true,
      limit: 100,
    });
    if (!isRecord(result) || !Array.isArray(result.data)) {
      throw new CodexAdapterError("Codex returned an invalid model list.", {
        code: "ERR_CODEX_PROTOCOL",
      });
    }
    if (
      result.data.some(
        (entry) =>
          isRecord(entry) && (entry.id === model || entry.model === model),
      )
    ) {
      return;
    }
    if (result.nextCursor === null || result.nextCursor === undefined) {
      break;
    }
    if (
      typeof result.nextCursor !== "string" ||
      result.nextCursor.length === 0 ||
      cursors.has(result.nextCursor)
    ) {
      throw new CodexAdapterError("Codex model pagination is invalid.", {
        code: "ERR_CODEX_PROTOCOL",
      });
    }
    cursors.add(result.nextCursor);
    cursor = result.nextCursor;
  }
  throw new CodexAdapterError(`Codex model is unavailable: ${model}.`, {
    code: "ERR_CODEX_MODEL_UNAVAILABLE",
  });
}

async function selectThread(client, request, fresh) {
  const options = threadOptions(request);
  if (fresh || request.session === undefined) {
    const result = await client.request("thread/start", {
      ...options,
      serviceName: "agent_runner",
    });
    return assertThreadResponse(result);
  }
  if (request.session.mode === "fork") {
    try {
      const result = await client.request("thread/fork", {
        ...options,
        threadId: request.session.id,
      });
      const threadId = assertThreadResponse(result);
      if (
        threadId === request.session.id ||
        result.thread.forkedFromId !== request.session.id
      ) {
        throw new CodexAdapterError("Codex returned invalid fork lineage.", {
          code: "ERR_CODEX_PROTOCOL",
        });
      }
      return threadId;
    } catch (cause) {
      if (
        cause instanceof CodexAdapterError &&
        cause.code === "ERR_CODEX_PROTOCOL"
      ) {
        throw cause;
      }
      throw new CodexAdapterError("Codex source session is unavailable.", {
        cause,
        code: "ERR_CODEX_SOURCE_SESSION_UNAVAILABLE",
      });
    }
  }
  try {
    const result = await client.request("thread/resume", {
      ...options,
      threadId: request.session.id,
    });
    const threadId = assertThreadResponse(result);
    if (threadId !== request.session.id) {
      throw new CodexAdapterError("Codex resumed an unexpected thread.", {
        code: "ERR_CODEX_PROTOCOL",
      });
    }
    return threadId;
  } catch (cause) {
    if (
      cause instanceof CodexAdapterError &&
      cause.code === "ERR_CODEX_PROTOCOL"
    ) {
      throw cause;
    }
    throw new CodexAdapterError("Codex session cannot be continued.", {
      cause,
      code: "ERR_CODEX_SESSION_UNAVAILABLE",
      recoverable: true,
    });
  }
}

function isContextWindowExceeded(turn) {
  const info = turn?.error?.codexErrorInfo;
  return (
    typeof info === "string" &&
    info.replaceAll(/[_-]/gu, "").toLowerCase() === "contextwindowexceeded"
  );
}

function terminalTurnDiagnosticClass(turn) {
  const info = turn?.error?.codexErrorInfo;
  const variant =
    typeof info === "string"
      ? info
      : isRecord(info) && Object.keys(info).length === 1
        ? Object.keys(info)[0]
        : undefined;
  return Object.hasOwn(TERMINAL_TURN_DIAGNOSTICS, variant)
    ? TERMINAL_TURN_DIAGNOSTICS[variant]
    : undefined;
}

function hasStructuredClientError(message) {
  if (
    typeof message !== "string" ||
    message.length > MAX_HTTP_ERROR_BYTES ||
    Buffer.byteLength(message, "utf8") > MAX_HTTP_ERROR_BYTES
  ) {
    return false;
  }
  // Recognize the native HTTP wrapper, never a status mentioned in prose,
  // additionalDetails, or an arbitrary codexErrorInfo payload.
  const match =
    /^unexpected status ([0-9]{3})(?: ([A-Za-z ]+))?: [\t\r\n ]*(\{[\s\S]*\})[\t\r\n ]*((?:, (?:url|cf-ray|request id): [^,\s{}]+)*)$/u.exec(
      message,
    );
  if (match === null) {
    return false;
  }
  const [, statusText, reason, body, metadata] = match;
  const status = Number(statusText);
  if (
    !CLIENT_ERROR_STATUSES.has(status) ||
    (reason !== undefined && reason !== CLIENT_ERROR_STATUSES.get(status))
  ) {
    return false;
  }
  const metadataKeys = [...metadata.matchAll(/, ([^:]+):/gu)].map(
    (entry) => entry[1],
  );
  if (new Set(metadataKeys).size !== metadataKeys.length) {
    return false;
  }
  let envelope;
  try {
    envelope = JSON.parse(body);
  } catch {
    return false;
  }
  if (
    !isRecord(envelope) ||
    Object.keys(envelope).length !== 1 ||
    !isRecord(envelope.error)
  ) {
    return false;
  }
  const error = envelope.error;
  const keys = Object.keys(error);
  if (
    keys.some((key) => !["message", "type", "param", "code"].includes(key)) ||
    typeof error.message !== "string" ||
    !(
      error.type === "invalid_request_error" ||
      (status === 401 && error.type === "authentication_error") ||
      (status === 403 && error.type === "permission_error")
    ) ||
    (error.param !== undefined &&
      error.param !== null &&
      typeof error.param !== "string") ||
    (error.code !== undefined &&
      error.code !== null &&
      !CLIENT_ERROR_CODES.has(error.code))
  ) {
    return false;
  }
  // This envelope is shallow and all values are scalar. Count JSON keys while
  // consuming whole strings to reject duplicates, including escaped names,
  // which JSON.parse would otherwise silently overwrite.
  const keyCount = [...body.matchAll(/"(?:[^"\\]|\\.)*"\s*(:)?/gsu)].filter(
    (entry) => entry[1] !== undefined,
  ).length;
  return keyCount === keys.length + 1;
}

function hasFullItemsView(turn) {
  return turn.itemsView === undefined || turn.itemsView === "full";
}

function invalidCompletedTurn(cause) {
  return new CodexAdapterError("Codex returned an invalid completed turn.", {
    cause,
    code: "ERR_CODEX_PROTOCOL",
  });
}

function assertCompletedTurnEnvelope(value, threadId, turnId) {
  if (
    !isRecord(value) ||
    value.threadId !== threadId ||
    !isRecord(value.turn) ||
    typeof value.turn.id !== "string" ||
    value.turn.id.length === 0 ||
    (turnId !== undefined && value.turn.id !== turnId) ||
    !Array.isArray(value.turn.items) ||
    !TERMINAL_TURN_STATUSES.has(value.turn.status)
  ) {
    throw invalidCompletedTurn();
  }
  return value.turn;
}

function assertCompletedTurn(value, threadId, turnId) {
  const turn = assertCompletedTurnEnvelope(value, threadId, turnId);
  if (!hasFullItemsView(turn)) {
    throw invalidCompletedTurn();
  }
  return turn;
}

async function resolveCompletedTurn(client, value, threadId, turnId) {
  const turn = assertCompletedTurnEnvelope(value, threadId, turnId);
  if (hasFullItemsView(turn)) {
    return turn;
  }
  if (turn.itemsView !== "summary" && turn.itemsView !== "notLoaded") {
    throw invalidCompletedTurn();
  }
  let response;
  try {
    response = await client.request("thread/read", {
      threadId,
      includeTurns: true,
    });
  } catch (cause) {
    throw invalidCompletedTurn(cause);
  }
  if (
    !isRecord(response) ||
    !isRecord(response.thread) ||
    response.thread.id !== threadId ||
    !Array.isArray(response.thread.turns)
  ) {
    throw invalidCompletedTurn();
  }
  const matches = response.thread.turns.filter(
    (candidate) => isRecord(candidate) && candidate.id === turnId,
  );
  if (matches.length !== 1) {
    throw invalidCompletedTurn();
  }
  return assertCompletedTurn({ threadId, turn: matches[0] }, threadId, turnId);
}

async function startTurn(client, request, threadId, prompt, workspaceStorage) {
  let response;
  try {
    response = await client.request(
      "turn/start",
      turnOptions(request, threadId, prompt, workspaceStorage),
    );
  } catch (cause) {
    if (
      cause instanceof CodexAdapterError &&
      cause.code === "ERR_CODEX_PROCESS_EXITED"
    ) {
      throw new CodexAdapterError("Codex turn outcome is ambiguous.", {
        ambiguous: true,
        cause,
        code: "ERR_CODEX_TURN_INTERRUPTED",
        recoverable: true,
      });
    }
    throw cause;
  }
  if (
    !isRecord(response) ||
    !isRecord(response.turn) ||
    typeof response.turn.id !== "string" ||
    response.turn.id.length === 0
  ) {
    throw new CodexAdapterError("Codex returned an invalid turn.", {
      code: "ERR_CODEX_PROTOCOL",
    });
  }
  let completion;
  try {
    completion = await client.waitForNotification(
      "turn/completed",
      (params) =>
        isRecord(params) &&
        params.threadId === threadId &&
        params.turn?.id === response.turn.id,
    );
  } catch (cause) {
    throw new CodexAdapterError("Codex turn outcome is ambiguous.", {
      ambiguous: true,
      cause,
      code: "ERR_CODEX_TURN_INTERRUPTED",
      recoverable: true,
    });
  }
  return resolveCompletedTurn(client, completion, threadId, response.turn.id);
}

async function compactThread(client, threadId) {
  try {
    await client.request("thread/compact/start", { threadId });
    const completion = await client.waitForNotification(
      "turn/completed",
      (params) => isRecord(params) && params.threadId === threadId,
    );
    const notificationTurn = assertCompletedTurnEnvelope(completion, threadId);
    const turn = await resolveCompletedTurn(
      client,
      completion,
      threadId,
      notificationTurn.id,
    );
    if (
      turn.status !== "completed" ||
      !turn.items.some(
        (item) => isRecord(item) && item.type === "contextCompaction",
      )
    ) {
      throw new CodexAdapterError("Codex context compaction failed.", {
        code: "ERR_CODEX_CONTEXT_RECOVERY_FAILED",
      });
    }
  } catch (cause) {
    throw new CodexAdapterError("Codex context compaction failed.", {
      cause,
      code: "ERR_CODEX_CONTEXT_RECOVERY_FAILED",
      recoverable: true,
    });
  }
}

async function runTurn(
  client,
  request,
  threadId,
  prompt,
  recoveryPrompt,
  workspaceStorage,
) {
  let turn = await startTurn(
    client,
    request,
    threadId,
    prompt,
    workspaceStorage,
  );
  if (isContextWindowExceeded(turn)) {
    if (request.access === "local-commit") {
      throw new CodexAdapterError(
        "Codex local-commit turn cannot be replayed after context exhaustion.",
        {
          ambiguous: true,
          code: "ERR_CODEX_LOCAL_COMMIT_INTERRUPTED",
        },
      );
    }
    await compactThread(client, threadId);
    turn = await startTurn(
      client,
      request,
      threadId,
      recoveryPrompt,
      workspaceStorage,
    );
    if (isContextWindowExceeded(turn)) {
      throw new CodexAdapterError(
        "Codex context remains full after compaction.",
        {
          code: "ERR_CODEX_CONTEXT_RECOVERY_FAILED",
          recoverable: true,
        },
      );
    }
  }
  if (
    request.model !== undefined &&
    client.receivedNotification("model/rerouted")
  ) {
    throw new CodexAdapterError(
      `Codex substituted the requested model: ${request.model}.`,
      { code: "ERR_CODEX_MODEL_REROUTED" },
    );
  }
  if (turn.status === "interrupted") {
    throw new CodexAdapterError("Codex turn was interrupted.", {
      ambiguous: true,
      code: "ERR_CODEX_TURN_INTERRUPTED",
      recoverable: true,
    });
  }
  if (turn.status !== "completed") {
    let diagnosticClass = terminalTurnDiagnosticClass(turn);
    if (diagnosticClass === TERMINAL_TURN_DIAGNOSTICS.usageLimitExceeded) {
      throw new CodexAdapterError("Codex usage capacity is unavailable.", {
        code: "ERR_CODEX_USAGE_LIMIT",
        diagnosticClass,
        recoverable: true,
      });
    }
    if (diagnosticClass === TERMINAL_TURN_DIAGNOSTICS.other) {
      // Classification and recovery cannot hide policy or protocol violations.
      auditItems(turn.items, request);
      if (hasStructuredClientError(turn.error.message)) {
        diagnosticClass = TERMINAL_TURN_DIAGNOSTICS.badRequest;
      }
    }
    throw new CodexAdapterError("Codex turn failed.", {
      code: "ERR_CODEX_TURN_FAILED",
      diagnosticClass,
      recoverable: diagnosticClass === TERMINAL_TURN_DIAGNOSTICS.other,
    });
  }
  return turn;
}

function commandPolicyViolation(command, localCommit) {
  if (REMOTE_MUTATION_PATTERNS.some((pattern) => pattern.test(command))) {
    return "remote";
  }
  if (localCommit) {
    for (const match of command.matchAll(GIT_COMMAND_PATTERN)) {
      if (!LOCAL_COMMIT_READ_ONLY_GIT_COMMANDS.has(match[1].toLowerCase())) {
        return "local-commit";
      }
    }
  }
  return null;
}

function auditItems(items, request) {
  for (const item of items) {
    if (!isRecord(item)) {
      throw new CodexAdapterError("Codex returned an invalid turn item.", {
        code: "ERR_CODEX_PROTOCOL",
      });
    }
    if (
      (item.type === "commandExecution" || item.type === "fileChange") &&
      !TERMINAL_ITEM_STATUSES.has(item.status)
    ) {
      throw new CodexAdapterError("Codex returned an unfinished turn item.", {
        code: "ERR_CODEX_PROTOCOL",
      });
    }
    if (item.type === "mcpToolCall") {
      throw new CodexAdapterError("Codex used a disabled MCP server.", {
        code: "ERR_CODEX_ISOLATION",
        diagnosticClass: "operation_mcp_tool",
      });
    }
    if (
      item.type === "collabAgentToolCall" ||
      item.type === "subAgentActivity"
    ) {
      throw new CodexAdapterError(
        "Codex used disabled multi-agent collaboration.",
        {
          code: "ERR_CODEX_ISOLATION",
          diagnosticClass: "operation_multi_agent",
        },
      );
    }
    if (item.type === "hookPrompt") {
      throw new CodexAdapterError("Codex used a disabled lifecycle hook.", {
        code: "ERR_CODEX_ISOLATION",
        diagnosticClass: "operation_lifecycle_hook",
      });
    }
    if (item.type === "dynamicToolCall") {
      throw new CodexAdapterError(
        "Codex attempted an untrusted dynamic tool call.",
        {
          code: "ERR_CODEX_REMOTE_WRITE_ATTEMPT",
          diagnosticClass: "operation_dynamic_tool",
        },
      );
    }
    if (item.type === "webSearch" || item.type === "imageGeneration") {
      throw new CodexAdapterError("Codex attempted a disabled hosted tool.", {
        code: "ERR_CODEX_NETWORK_POLICY",
        diagnosticClass: "operation_hosted_tool",
      });
    }
    if (request.access !== "workspace-write" && item.type === "fileChange") {
      throw new CodexAdapterError(
        "Codex reported a file change during a read-only turn.",
        {
          code:
            request.access === "local-commit"
              ? "ERR_CODEX_LOCAL_COMMIT_POLICY"
              : "ERR_CODEX_READ_ONLY_POLICY",
          diagnosticClass:
            request.access === "local-commit"
              ? "operation_local_commit"
              : "operation_read_only_write",
        },
      );
    }
    if (
      item.type === "agentMessage" &&
      item.memoryCitation !== undefined &&
      item.memoryCitation !== null
    ) {
      throw new CodexAdapterError("Codex used disabled memories.", {
        code: "ERR_CODEX_ISOLATION",
        diagnosticClass: "operation_memory",
      });
    }
    if (item.type === "commandExecution") {
      if (typeof item.command !== "string") {
        throw new CodexAdapterError("Codex returned an invalid command item.", {
          code: "ERR_CODEX_PROTOCOL",
        });
      }
      if (item.pluginId !== undefined && item.pluginId !== null) {
        throw new CodexAdapterError("Codex used a disabled plugin.", {
          code: "ERR_CODEX_ISOLATION",
          diagnosticClass: "operation_plugin",
        });
      }
      const violation = commandPolicyViolation(
        item.command,
        request.access === "local-commit",
      );
      if (violation === "remote") {
        throw new CodexAdapterError("Codex attempted a remote write.", {
          code: "ERR_CODEX_REMOTE_WRITE_ATTEMPT",
          diagnosticClass: "operation_remote_write",
        });
      }
      if (violation === "local-commit") {
        throw new CodexAdapterError(
          "Codex attempted a forbidden local-commit operation.",
          {
            code: "ERR_CODEX_LOCAL_COMMIT_POLICY",
            diagnosticClass: "operation_local_commit",
          },
        );
      }
    }
    if (!SAFE_TURN_ITEM_TYPES.has(item.type)) {
      throw new CodexAdapterError("Codex returned an unknown turn item.", {
        code: "ERR_CODEX_PROTOCOL",
      });
    }
  }
}

function normalizeResult(turn, request, sessionId) {
  auditItems(turn.items, request);
  const messages = turn.items.filter(
    (item) => isRecord(item) && item.type === "agentMessage",
  );
  const output = messages.at(-1)?.text;
  if (typeof output !== "string" || output.length === 0) {
    throw new CodexAdapterError("Codex turn did not return an agent message.", {
      code: "ERR_CODEX_OUTPUT",
    });
  }
  let structured = null;
  if (outputSchemaFor(request) !== undefined) {
    try {
      structured = JSON.parse(output);
    } catch (cause) {
      throw new CodexAdapterError("Codex returned invalid structured output.", {
        cause,
        code: "ERR_CODEX_STRUCTURED_OUTPUT",
        failureClass: STRUCTURED_OUTPUT_FAILURE_CLASS,
      });
    }
    if (!isRecord(structured)) {
      throw new CodexAdapterError(
        "Codex structured output must be an object.",
        {
          code: "ERR_CODEX_STRUCTURED_OUTPUT",
          failureClass: STRUCTURED_OUTPUT_FAILURE_CLASS,
        },
      );
    }
    deepFreeze(structured);
  }
  if (
    request.access === "local-commit" &&
    (structured.ready !== true || Object.keys(structured).length !== 1)
  ) {
    throw new CodexAdapterError(
      "Codex did not confirm the authorized local commit.",
      {
        code: "ERR_CODEX_LOCAL_COMMIT_POLICY",
        diagnosticClass: "operation_local_commit",
      },
    );
  }
  return Object.freeze({ output, structured, sessionId });
}

export function createCodexAdapter(options = {}) {
  assertFields(
    options,
    [
      "codexBinary",
      "env",
      "execute",
      "spawnProcess",
      "workspaceStorageFactory",
    ],
    "Codex adapter options",
  );
  const {
    codexBinary = "codex",
    env = process.env,
    execute = executeFile,
    spawnProcess = spawn,
    workspaceStorageFactory = createCodexWorkspaceStorage,
  } = options;
  if (
    typeof codexBinary !== "string" ||
    codexBinary.trim().length === 0 ||
    /[\0\r\n]/u.test(codexBinary) ||
    !isEnvironment(env) ||
    typeof execute !== "function" ||
    typeof spawnProcess !== "function" ||
    typeof workspaceStorageFactory !== "function"
  ) {
    throw new CodexAdapterError("Codex adapter options are invalid.", {
      code: "ERR_INVALID_CODEX_OPTIONS",
    });
  }
  const processEnvironment = isolateGitEnvironment(env);
  const commandEnvironment = isolateCommandEnvironment(processEnvironment);
  let probePromise;

  async function inspectCapabilities() {
    let versionResult;
    let helpResult;
    try {
      [versionResult, helpResult] = await Promise.all([
        execute(codexBinary, ["--version"], {
          encoding: "utf8",
          env: processEnvironment,
          maxBuffer: 1024 * 1024,
          timeout: 10_000,
        }),
        execute(codexBinary, ["app-server", "--help"], {
          encoding: "utf8",
          env: processEnvironment,
          maxBuffer: 1024 * 1024,
          timeout: 10_000,
        }),
      ]);
    } catch (cause) {
      throw processError("Codex CLI is unavailable.", cause);
    }
    const version = parseVersion(processOutput(versionResult.stdout).trim());
    const help =
      processOutput(helpResult.stdout) + processOutput(helpResult.stderr);
    const supported =
      versionAtLeast(version, MINIMUM_CODEX_VERSION) &&
      ["--disable", "--enable", "--listen", "--strict-config"].every((flag) =>
        help.includes(flag),
      );
    const localCommit =
      supported &&
      (await probeCodexLocalCommit({
        codexBinary,
        env: commandEnvironment,
        execute,
      }));
    return Object.freeze({
      version: version.text,
      structuredOutput: supported,
      readOnly: supported,
      autonomousWrite: supported,
      gitMetadataWriteBlocked: supported,
      workspaceWrite: supported,
      localCommit,
      remoteWriteBlocked: supported,
      nativeSessionContinuation: supported,
      nativeSessionFork: supported,
    });
  }

  function probe(value) {
    normalizeExecutionOptions(value);
    probePromise ??= inspectCapabilities();
    return probePromise;
  }

  function workspaceStorageFailure() {
    return new CodexAdapterError("Codex workspace storage is unsafe.", {
      code: "ERR_CODEX_ISOLATION",
      diagnosticClass: "isolation_shell_environment",
    });
  }

  async function prepareWorkspaceStorage(request) {
    if (request.access !== "workspace-write") {
      return undefined;
    }
    try {
      return assertCodexWorkspaceStorage(await workspaceStorageFactory());
    } catch {
      throw workspaceStorageFailure();
    }
  }

  async function cleanupWorkspaceStorage(workspaceStorage) {
    if (workspaceStorage === undefined) {
      return;
    }
    try {
      await workspaceStorage.cleanup();
    } catch {
      throw workspaceStorageFailure();
    }
  }

  async function appServerLaunch(request, workspaceStorage) {
    let result;
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        result = await (
          request.onProcess !== undefined && execute === executeFile
            ? executeOwnedProcess
            : execute
        )(
          codexBinary,
          nativeArguments(request, [
            "-C",
            request.cwd,
            "mcp",
            "list",
            "--json",
          ]),
          {
            encoding: "utf8",
            env: processEnvironment,
            maxBuffer: 1024 * 1024,
            timeout: MCP_DISCOVERY_TIMEOUT_MS,
            ...(request.signal === undefined ? {} : { signal: request.signal }),
            ...(request.onProcess === undefined
              ? {}
              : { onProcess: request.onProcess }),
          },
        );
        break;
      } catch (cause) {
        request.signal?.throwIfAborted();
        if (
          [
            "ERR_EXECUTION_PROCESS_ACTIVE",
            "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
          ].includes(cause?.code)
        )
          throw cause;
        if (attempt === 1) {
          throw new CodexAdapterError(
            "Codex MCP configuration is temporarily unavailable.",
            {
              code: "ERR_CODEX_UNAVAILABLE",
              diagnosticClass: "isolation_mcp_discovery",
              method: "mcp/list",
              recoverable: true,
            },
          );
        }
      }
    }
    const mcpServerNames = parseMcpServerNames(processOutput(result.stdout));
    const shellEnvironment =
      workspaceStorage?.shellEnvironment ?? EMPTY_SHELL_ENVIRONMENT;
    const argumentsList = nativeArguments(
      request,
      APP_SERVER_BASE_ARGUMENTS.map((argument) =>
        argument === EMPTY_SHELL_ENVIRONMENT_POLICY
          ? shellEnvironmentPolicy(shellEnvironment)
          : argument,
      ),
    );
    for (const name of mcpServerNames) {
      argumentsList.push("-c", `mcp_servers.${name}.enabled=false`);
    }
    return Object.freeze({
      argumentsList: Object.freeze(argumentsList),
      mcpServerNames: Object.freeze(mcpServerNames),
    });
  }

  async function assertCapabilities(request) {
    const capabilities = await probe(executionOptionsFor(request));
    const required = ["remoteWriteBlocked"];
    if (outputSchemaFor(request) !== undefined) {
      required.push("structuredOutput");
    }
    if (request.access !== "workspace-write") {
      required.push("readOnly");
    } else {
      required.push("gitMetadataWriteBlocked", "workspaceWrite");
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
    const missingCapability = required.find(
      (capability) => capabilities[capability] !== true,
    );
    if (missingCapability !== undefined) {
      throw new CodexAdapterError(
        "Installed Codex CLI cannot enforce the requested capability.",
        {
          code: "ERR_UNSUPPORTED_CODEX_CAPABILITY",
          diagnosticClass: CAPABILITY_DIAGNOSTICS[missingCapability],
        },
      );
    }
  }

  async function createAuthorizedCommit(request) {
    let effectStarted = false;
    try {
      request.signal?.throwIfAborted();
      await executeCodexLocalCommit({
        codexBinary,
        cwd: request.cwd,
        env: commandEnvironment,
        execute: (file, args, executionOptions) => {
          const options =
            request.onProcess === undefined
              ? executionOptions
              : {
                  ...executionOptions,
                  signal: request.signal,
                  onProcess: request.onProcess,
                };
          return request.onProcess !== undefined && execute === executeFile
            ? executeOwnedProcess(file, args, options)
            : execute(file, args, options);
        },
        beforeEffect: () => {
          request.signal?.throwIfAborted();
          effectStarted = true;
        },
        expectedHead: request.commit.expectedHead,
        message: request.commit.message,
      });
    } catch (cause) {
      if (cause?.effectStarted === false) effectStarted = false;
      throw new CodexAdapterError(
        "Authorized local commit outcome requires Git-state verification.",
        {
          ambiguous: effectStarted,
          effectStarted,
          cause,
          code: "ERR_CODEX_LOCAL_COMMIT_INTERRUPTED",
        },
      );
    }
  }

  async function runAttempt(request, { fresh = false, recovery = false } = {}) {
    request.signal?.throwIfAborted();
    const workspaceStorage = await prepareWorkspaceStorage(request);
    try {
      const launch = await appServerLaunch(request, workspaceStorage);
      let child;
      try {
        request.signal?.throwIfAborted();
        const launchProcess =
          request.onProcess !== undefined && spawnProcess === spawn
            ? spawnOwnedProcess
            : spawnProcess;
        child = launchProcess(codexBinary, launch.argumentsList, {
          cwd: request.cwd,
          env: processEnvironment,
          stdio: ["pipe", "pipe", "pipe"],
          ...(request.onProcess === undefined
            ? {}
            : {
                signal: request.signal,
                onProcess: request.onProcess,
                ownershipMode: "native-sandbox-provider",
              }),
        });
      } catch (cause) {
        throw processError("Cannot start Codex app-server.", cause);
      }
      const ownedCompletion = child.ownedCompletion;
      const ownedFailureSignal =
        ownedCompletion === undefined
          ? undefined
          : new Promise((_, reject) => {
              ownedCompletion.catch(reject);
            });
      ownedFailureSignal?.catch(() => {});
      const client = createCodexAppServerClient(
        child,
        CodexAdapterError,
        request.signal,
      );
      let result;
      let operationFailed = false;
      try {
        const protocolOperation = (async () => {
          await client.request("initialize", {
            clientInfo: {
              name: "agent_runner",
              title: "Agent Runner",
              version: packageMetadata.version,
            },
            capabilities: null,
          });
          client.notify("initialized", {});
          assertIsolatedConfiguration(
            await client.request("config/read", { includeLayers: false }),
            launch.mcpServerNames,
            workspaceStorage?.shellEnvironment ?? EMPTY_SHELL_ENVIRONMENT,
          );
          await validateModel(client, request.model);
          const threadId = await selectThread(client, request, fresh);
          const turn = await runTurn(
            client,
            request,
            threadId,
            turnPrompt(request, recovery),
            turnPrompt(request, "compact"),
            workspaceStorage,
          );
          return normalizeResult(turn, request, threadId);
        })();
        result = await (ownedFailureSignal === undefined
          ? protocolOperation
          : Promise.race([protocolOperation, ownedFailureSignal]));
      } catch (cause) {
        operationFailed = true;
        throw cause;
      } finally {
        try {
          await client.close({
            retainProcess: child.ownedContainmentRetained === true,
          });
        } catch (cause) {
          if (!operationFailed) {
            throw cause;
          }
        } finally {
          await ownedCompletion;
        }
      }
      return result;
    } finally {
      await cleanupWorkspaceStorage(workspaceStorage);
    }
  }

  async function run(value) {
    const request = normalizeRequest(value);
    try {
      assertCodexSchema(outputSchemaFor(request), CodexAdapterError);
      await assertCapabilities(request);
    } catch (cause) {
      if (
        request.access === "local-commit" &&
        cause instanceof CodexAdapterError
      ) {
        cause.effectStarted = false;
      }
      throw cause;
    }
    let result;
    try {
      result = await runAttempt(request);
    } catch (cause) {
      if (request.signal?.aborted) {
        if (request.access === "local-commit") {
          throw new CodexAdapterError(
            "Local commit stopped before execution.",
            {
              cause,
              code: cause?.code ?? "ERR_CODEX_LOCAL_COMMIT_INTERRUPTED",
              effectStarted: false,
            },
          );
        }
        throw cause;
      }
      request.signal?.throwIfAborted();
      if (
        cause instanceof CodexAdapterError &&
        cause.recoverable &&
        cause.method === "mcp/list"
      ) {
        if (request.access === "local-commit") {
          cause.effectStarted = false;
        }
        throw cause;
      }
      if (
        request.access === "local-commit" &&
        cause instanceof CodexAdapterError
      ) {
        cause.effectStarted = false;
        throw cause;
      }
      if (
        cause instanceof CodexAdapterError &&
        cause.code === "ERR_CODEX_USAGE_LIMIT"
      ) {
        throw cause;
      }
      if (
        cause instanceof CodexAdapterError &&
        cause.recoverable &&
        request.session?.mode !== "fork"
      ) {
        result = await runAttempt(request, {
          fresh: true,
          recovery: "fresh",
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

  return Object.freeze({ id: CODEX_BACKEND_ID, probe, run });
}
