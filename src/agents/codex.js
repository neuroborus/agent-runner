import {
  execFile as executeFileCallback,
  spawn,
} from "node:child_process";
import { promisify } from "node:util";

import packageMetadata from "../../package.json" with { type: "json" };
import {
  createAdapterContract,
  deepFreeze,
  isEnvironment,
  isRecord,
  isolateGitEnvironment,
} from "./adapter-contract.js";
import { createCodexAppServerClient } from "./codex-app-server.js";
import {
  executeCodexLocalCommit,
  probeCodexLocalCommit,
} from "./codex-local-commit.js";

export const CODEX_BACKEND_ID = "codex";

const executeFile = promisify(executeFileCallback);
const MINIMUM_CODEX_VERSION = Object.freeze([0, 147, 0]);
const MAX_MCP_SERVERS = 256;
const MCP_SERVER_NAME_PATTERN = /^[A-Za-z0-9_-]+$/u;
const MAX_MODEL_PAGES = 32;
const DISABLED_FEATURES = Object.freeze([
  "apps",
  "artifact",
  "browser_use",
  "browser_use_external",
  "browser_use_full_cdp_access",
  "code_mode",
  "code_mode_host",
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
const APP_SERVER_BASE_ARGUMENTS = Object.freeze([
  "app-server",
  "--listen",
  "stdio://",
  "--strict-config",
  ...DISABLED_FEATURES.flatMap((feature) => ["--disable", feature]),
  "-c",
  "notify=[]",
  "-c",
  'shell_environment_policy={inherit="core",ignore_default_excludes=false,' +
    'experimental_use_profile=false,set={}}',
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

export class CodexAdapterError extends Error {
  constructor(
    message,
    {
      ambiguous = false,
      cause,
      code = "ERR_CODEX_ADAPTER",
      method,
      recoverable = false,
    } = {},
  ) {
    super(message, { cause });
    this.name = "CodexAdapterError";
    this.code = code;
    this.ambiguous = ambiguous;
    this.recoverable = recoverable;
    if (method !== undefined) {
      this.method = method;
    }
  }
}

const { assertFields, normalizeRequest } = createAdapterContract({
  AdapterError: CodexAdapterError,
  backendName: "Codex",
});

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
  } catch (cause) {
    throw new CodexAdapterError("Codex returned invalid MCP configuration.", {
      cause,
      code: "ERR_CODEX_ISOLATION",
    });
  }
  if (!Array.isArray(servers) || servers.length > MAX_MCP_SERVERS) {
    throw new CodexAdapterError("Codex returned invalid MCP configuration.", {
      code: "ERR_CODEX_ISOLATION",
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
    });
  }
  return names;
}

function assertIsolatedConfiguration(value, expectedMcpServers) {
  const config = value?.config;
  const features = config?.features;
  const memories = config?.memories;
  const mcpServers = config?.mcp_servers;
  const shellEnvironment = config?.shell_environment_policy;
  if (
    !isRecord(config) ||
    !isRecord(features) ||
    DISABLED_FEATURES.some((feature) => features[feature] !== false) ||
    !isRecord(memories) ||
    memories.generate_memories !== false ||
    memories.use_memories !== false ||
    !Array.isArray(config.notify) ||
    config.notify.length !== 0 ||
    !isRecord(shellEnvironment) ||
    shellEnvironment.inherit !== "core" ||
    shellEnvironment.ignore_default_excludes !== false ||
    shellEnvironment.experimental_use_profile !== false ||
    !isRecord(shellEnvironment.set) ||
    Object.keys(shellEnvironment.set).length !== 0 ||
    shellEnvironment.exclude !== null ||
    shellEnvironment.include_only !== null ||
    shellEnvironment.filters !== null ||
    config.web_search !== "disabled" ||
    !isRecord(mcpServers) ||
    expectedMcpServers.some((name) => !Object.hasOwn(mcpServers, name)) ||
    Object.values(mcpServers).some(
      (server) => !isRecord(server) || server.enabled !== false,
    )
  ) {
    throw new CodexAdapterError("Codex external tools are not isolated.", {
      code: "ERR_CODEX_ISOLATION",
    });
  }
}

function sandboxFor(request) {
  if (request.access !== "workspace-write") {
    return Object.freeze({ type: "readOnly", networkAccess: false });
  }
  return Object.freeze({
    type: "workspaceWrite",
    writableRoots: Object.freeze([request.cwd]),
    networkAccess: false,
    excludeTmpdirEnvVar: true,
    excludeSlashTmp: true,
  });
}

function threadSandboxFor(request) {
  return request.access === "workspace-write"
    ? "workspace-write"
    : "read-only";
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
  let prompt = recovery ? `${RECOVERY_PREFIX}\n\n${request.prompt}` : request.prompt;
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

function turnOptions(request, threadId, prompt) {
  const options = {
    threadId,
    input: Object.freeze([{ type: "text", text: prompt }]),
    cwd: request.cwd,
    approvalPolicy: "never",
    approvalsReviewer: "user",
    sandboxPolicy: sandboxFor(request),
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
    typeof value.turn.status !== "string"
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
  return assertCompletedTurn(
    { threadId, turn: matches[0] },
    threadId,
    turnId,
  );
}

async function startTurn(client, request, threadId, prompt) {
  let response;
  try {
    response = await client.request(
      "turn/start",
      turnOptions(request, threadId, prompt),
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

async function runTurn(client, request, threadId, prompt) {
  let turn = await startTurn(client, request, threadId, prompt);
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
    turn = await startTurn(client, request, threadId, prompt);
    if (isContextWindowExceeded(turn)) {
      throw new CodexAdapterError("Codex context remains full after compaction.", {
        code: "ERR_CODEX_CONTEXT_RECOVERY_FAILED",
        recoverable: true,
      });
    }
  }
  if (turn.status === "interrupted") {
    throw new CodexAdapterError("Codex turn was interrupted.", {
      ambiguous: true,
      code: "ERR_CODEX_TURN_INTERRUPTED",
      recoverable: true,
    });
  }
  if (turn.status !== "completed") {
    throw new CodexAdapterError("Codex turn failed.", {
      code: "ERR_CODEX_TURN_FAILED",
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
      throw new CodexAdapterError(
        "Codex returned an unfinished turn item.",
        { code: "ERR_CODEX_PROTOCOL" },
      );
    }
    if (item.type === "mcpToolCall") {
      throw new CodexAdapterError(
        "Codex used a disabled MCP server.",
        { code: "ERR_CODEX_ISOLATION" },
      );
    }
    if (
      item.type === "collabAgentToolCall" ||
      item.type === "subAgentActivity"
    ) {
      throw new CodexAdapterError(
        "Codex used disabled multi-agent collaboration.",
        { code: "ERR_CODEX_ISOLATION" },
      );
    }
    if (item.type === "hookPrompt") {
      throw new CodexAdapterError("Codex used a disabled lifecycle hook.", {
        code: "ERR_CODEX_ISOLATION",
      });
    }
    if (item.type === "dynamicToolCall") {
      throw new CodexAdapterError(
        "Codex attempted an untrusted dynamic tool call.",
        { code: "ERR_CODEX_REMOTE_WRITE_ATTEMPT" },
      );
    }
    if (item.type === "webSearch" || item.type === "imageGeneration") {
      throw new CodexAdapterError(
        "Codex attempted a disabled hosted tool.",
        { code: "ERR_CODEX_NETWORK_POLICY" },
      );
    }
    if (request.access !== "workspace-write" && item.type === "fileChange") {
      throw new CodexAdapterError(
        "Codex reported a file change during a read-only turn.",
        {
          code:
            request.access === "local-commit"
              ? "ERR_CODEX_LOCAL_COMMIT_POLICY"
              : "ERR_CODEX_READ_ONLY_POLICY",
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
      });
    }
    if (item.type === "commandExecution") {
      if (typeof item.command !== "string") {
        throw new CodexAdapterError(
          "Codex returned an invalid command item.",
          { code: "ERR_CODEX_PROTOCOL" },
        );
      }
      if (item.pluginId !== undefined && item.pluginId !== null) {
        throw new CodexAdapterError("Codex used a disabled plugin.", {
          code: "ERR_CODEX_ISOLATION",
        });
      }
      const violation = commandPolicyViolation(
        item.command,
        request.access === "local-commit",
      );
      if (violation === "remote") {
        throw new CodexAdapterError("Codex attempted a remote write.", {
          code: "ERR_CODEX_REMOTE_WRITE_ATTEMPT",
        });
      }
      if (violation === "local-commit") {
        throw new CodexAdapterError(
          "Codex attempted a forbidden local-commit operation.",
          { code: "ERR_CODEX_LOCAL_COMMIT_POLICY" },
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
      });
    }
    if (!isRecord(structured)) {
      throw new CodexAdapterError(
        "Codex structured output must be an object.",
        { code: "ERR_CODEX_STRUCTURED_OUTPUT" },
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
      { code: "ERR_CODEX_LOCAL_COMMIT_POLICY" },
    );
  }
  return Object.freeze({ output, structured, sessionId });
}

export function createCodexAdapter(options = {}) {
  assertFields(
    options,
    ["codexBinary", "env", "execute", "spawnProcess"],
    "Codex adapter options",
  );
  const {
    codexBinary = "codex",
    env = process.env,
    execute = executeFile,
    spawnProcess = spawn,
  } = options;
  if (
    typeof codexBinary !== "string" ||
    codexBinary.trim().length === 0 ||
    /[\0\r\n]/u.test(codexBinary) ||
    !isEnvironment(env) ||
    typeof execute !== "function" ||
    typeof spawnProcess !== "function"
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
      ["--disable", "--listen", "--strict-config"].every((flag) =>
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
      workspaceWrite: supported,
      localCommit,
      remoteWriteBlocked: supported,
      nativeSessionContinuation: supported,
      nativeSessionFork: supported,
    });
  }

  function probe() {
    probePromise ??= inspectCapabilities();
    return probePromise;
  }

  async function appServerLaunch(cwd) {
    let result;
    try {
      result = await execute(
        codexBinary,
        ["-C", cwd, "mcp", "list", "--json"],
        {
          encoding: "utf8",
          env: processEnvironment,
          maxBuffer: 1024 * 1024,
          timeout: 10_000,
        },
      );
    } catch (cause) {
      throw processError(
        "Cannot inspect Codex MCP configuration.",
        cause,
        "ERR_CODEX_ISOLATION",
      );
    }
    const mcpServerNames = parseMcpServerNames(processOutput(result.stdout));
    const argumentsList = [...APP_SERVER_BASE_ARGUMENTS];
    for (const name of mcpServerNames) {
      argumentsList.push("-c", `mcp_servers.${name}.enabled=false`);
    }
    return Object.freeze({
      argumentsList: Object.freeze(argumentsList),
      mcpServerNames: Object.freeze(mcpServerNames),
    });
  }

  async function assertCapabilities(request) {
    const capabilities = await probe();
    const required = ["remoteWriteBlocked"];
    if (outputSchemaFor(request) !== undefined) {
      required.push("structuredOutput");
    }
    if (request.access !== "workspace-write") {
      required.push("readOnly");
    } else {
      required.push("workspaceWrite");
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
      throw new CodexAdapterError(
        "Installed Codex CLI cannot enforce the requested capability.",
        { code: "ERR_UNSUPPORTED_CODEX_CAPABILITY" },
      );
    }
  }

  async function createAuthorizedCommit(request) {
    try {
      await executeCodexLocalCommit({
        codexBinary,
        cwd: request.cwd,
        env: commandEnvironment,
        execute,
        expectedHead: request.commit.expectedHead,
        message: request.commit.message,
      });
    } catch (cause) {
      throw new CodexAdapterError(
        "Authorized local commit outcome requires Git-state verification.",
        {
          ambiguous: true,
          cause,
          code: "ERR_CODEX_LOCAL_COMMIT_INTERRUPTED",
        },
      );
    }
  }

  async function runAttempt(request, { fresh = false, recovery = false } = {}) {
    const launch = await appServerLaunch(request.cwd);
    let child;
    try {
      child = spawnProcess(codexBinary, launch.argumentsList, {
        cwd: request.cwd,
        env: processEnvironment,
        stdio: ["pipe", "pipe", "pipe"],
      });
    } catch (cause) {
      throw processError("Cannot start Codex app-server.", cause);
    }
    const client = createCodexAppServerClient(child, CodexAdapterError);
    let result;
    let operationFailed = false;
    try {
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
      );
      await validateModel(client, request.model);
      const threadId = await selectThread(client, request, fresh);
      const turn = await runTurn(
        client,
        request,
        threadId,
        turnPrompt(request, recovery),
      );
      if (
        request.model !== undefined &&
        client.receivedNotification("model/rerouted")
      ) {
        throw new CodexAdapterError(
          `Codex substituted the requested model: ${request.model}.`,
          { code: "ERR_CODEX_MODEL_REROUTED" },
        );
      }
      result = normalizeResult(turn, request, threadId);
    } catch (cause) {
      operationFailed = true;
      throw cause;
    } finally {
      try {
        await client.close();
      } catch (cause) {
        if (!operationFailed) {
          throw cause;
        }
      }
    }
    if (request.access === "local-commit") {
      await createAuthorizedCommit(request);
    }
    return result;
  }

  async function run(value) {
    const request = normalizeRequest(value);
    await assertCapabilities(request);
    try {
      return await runAttempt(request);
    } catch (cause) {
      if (
        request.access === "local-commit" &&
        cause instanceof CodexAdapterError &&
        (cause.ambiguous || cause.recoverable)
      ) {
        if (cause.code === "ERR_CODEX_LOCAL_COMMIT_INTERRUPTED") {
          throw cause;
        }
        throw new CodexAdapterError(
          "Codex local-commit outcome requires Git-state verification.",
          {
            ambiguous: true,
            cause,
            code: "ERR_CODEX_LOCAL_COMMIT_INTERRUPTED",
          },
        );
      }
      if (
        cause instanceof CodexAdapterError &&
        cause.recoverable &&
        request.session?.mode !== "fork"
      ) {
        return runAttempt(request, { fresh: true, recovery: true });
      }
      throw cause;
    }
  }

  return Object.freeze({ id: CODEX_BACKEND_ID, probe, run });
}
