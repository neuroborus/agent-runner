import {
  observationList,
  observationObject,
  requireObservation,
} from "../index.js";

export const CLAUDE_TOOLS = Object.freeze([
  "Bash",
  "Read",
  "Glob",
  "Grep",
  "Edit",
  "Write",
  "EndConversation",
]);
const fields = Object.freeze({
  Bash: [
    "command",
    "timeout",
    "run_in_background",
    "dangerouslyDisableSandbox",
  ],
  Read: ["file_path", "offset", "limit"],
  Glob: ["pattern", "path"],
  Grep: [
    "pattern",
    "path",
    "glob",
    "output_mode",
    "-B",
    "-A",
    "-C",
    "context",
    "-n",
    "-i",
    "type",
    "head_limit",
    "offset",
    "multiline",
  ],
  Edit: ["file_path", "old_string", "new_string", "replace_all"],
  Write: ["file_path", "content"],
});
function canonicalInput(value, depth = 0) {
  requireObservation(depth <= 8);
  if (typeof value === "string") {
    requireObservation(value.isWellFormed() && !value.includes("\0"));
    return value;
  }
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "number") {
    requireObservation(Number.isFinite(value));
    return value;
  }
  if (Array.isArray(value))
    return Object.freeze(
      observationList(value, 32).map((item) => canonicalInput(item, depth + 1)),
    );
  requireObservation(
    value && Object.getPrototypeOf(value) === Object.prototype,
  );
  const keys = Object.keys(value).sort();
  requireObservation(
    keys.length <= 32 &&
      keys.every((key) => /^[A-Za-z0-9_-]{1,128}$/u.test(key)),
  );
  observationObject(value, keys);
  return Object.freeze(
    Object.fromEntries(
      keys.map((key) => [key, canonicalInput(value[key], depth + 1)]),
    ),
  );
}
// Shared only by the opaque stream/case and protected upstream joins. Terminal
// inputs remain independently reviewed JSON; no dispatcher schema is invented.
export function normalizeClaudeToolInput(name, value) {
  requireObservation(
    CLAUDE_TOOLS.includes(name) &&
      value &&
      Object.getPrototypeOf(value) === Object.prototype,
  );
  if (name === "EndConversation") {
    requireObservation(Buffer.byteLength(JSON.stringify(value)) <= 16384);
    return canonicalInput(value);
  }
  const { description, ...input } = value;
  requireObservation(
    (description === undefined ||
      (name === "Bash" &&
        typeof description === "string" &&
        description.length <= 1024)) &&
      Object.keys(input).every((key) => fields[name].includes(key)) &&
      Buffer.byteLength(JSON.stringify(input)) <= 16384,
  );
  const required = {
    Bash: ["command"],
    Read: ["file_path"],
    Glob: ["pattern"],
    Grep: ["pattern"],
    Edit: ["file_path", "old_string", "new_string"],
    Write: ["file_path", "content"],
  }[name];
  requireObservation(
    required.every(
      (key) =>
        typeof input[key] === "string" &&
        input[key].isWellFormed() &&
        !input[key].includes("\0"),
    ),
  );
  return canonicalInput(input);
}

// Published gateway/CLI surface only. The dispatcher remains opaque/untrusted.
export function normalizeClaudeToolSet(input = CLAUDE_TOOLS) {
  const tools = observationList(input, CLAUDE_TOOLS.length);
  requireObservation(
    tools.length > 1 &&
      tools.includes("EndConversation") &&
      new Set(tools).size === tools.length &&
      tools.every((name) => CLAUDE_TOOLS.includes(name)),
  );
  return Object.freeze([...tools]);
}

export function claudeInvocation(spec, token, selectedTools) {
  const tools = normalizeClaudeToolSet(selectedTools);
  return {
    environment: {
      ANTHROPIC_BASE_URL: spec.endpoint,
      ANTHROPIC_AUTH_TOKEN: token,
      ANTHROPIC_MODEL: spec.model,
      CLAUDE_CONFIG_DIR: spec.home,
      DISABLE_AUTOUPDATER: "1",
      CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
    },
    arguments: [
      "--bare",
      "--print",
      "--verbose",
      "--input-format",
      "stream-json",
      "--output-format",
      "stream-json",
      "--model",
      spec.model,
      "--permission-mode",
      "bypassPermissions",
      "--tools",
      tools.join(","),
      "--settings",
      '{"disableAllHooks":true,"enabledPlugins":{}}',
      "--setting-sources",
      "",
      "--strict-mcp-config",
      "--mcp-config",
      '{"mcpServers":{}}',
      "--disable-slash-commands",
      "--no-session-persistence",
      "--max-turns",
      "4",
    ],
  };
}
