import assert from "node:assert/strict";
import { execFile as executeFileCallback, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import {
  access,
  chmod,
  mkdir,
  mkdtemp,
  readdir,
  rename,
  open,
  readFile,
  realpath,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { delimiter, dirname, isAbsolute, join, parse } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { createGitService } from "../../src/git/index.js";

import {
  CLAUDE_BACKEND_ID,
  ClaudeAdapterError,
  createClaudeAdapter,
  recoverClaudeStorage,
  CLAUDE_STORAGE_IDENTITY,
} from "../../src/agents/claude/index.js";
import {
  STRUCTURED_OUTPUT_FAILURE_CLASS,
  normalizeAdapterFailure,
} from "../../src/agents/index.js";

import {
  BOOTSTRAP_SCHEMA as EXECUTION_BOOTSTRAP_SCHEMA,
  FINALIZATION_SCHEMA as EXECUTION_FINALIZATION_SCHEMA,
} from "../../pipelines/plan-execution/src/schemas.js";
import {
  BOOTSTRAP_SCHEMA as POLISHING_BOOTSTRAP_SCHEMA,
  FINALIZATION_SCHEMA as POLISHING_FINALIZATION_SCHEMA,
} from "../../pipelines/polishing/src/schemas.js";

const PROJECT_PATH = process.cwd();
const EXPECTED_HEAD = "a".repeat(40);
const SOURCE_SESSION = "11111111-1111-4111-8111-111111111111";
const CHILD_SESSION = "22222222-2222-4222-8222-222222222222";
const FRESH_SESSION = "33333333-3333-4333-8333-333333333333";
const COMMAND_LAUNCHER_TOKEN = "AGENT_RUNNER_CLAUDE_COMMAND_LAUNCHER_TOKEN";
const CLAUDE_LOG_PATH = join(homedir(), ".npm/_logs");
const executeFile = promisify(executeFileCallback);
const HELP = [
  "--append-system-prompt",
  "--autocompact",
  "--fork-session",
  "--json-schema",
  "--include-partial-messages",
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
  "--verbose",
].join("\n");
const STRICT_SCHEMA = Object.freeze({
  type: "object",
  properties: { ok: { type: "boolean" } },
  required: ["ok"],
  additionalProperties: false,
});
const COMMON_DENY_POLICY = [
  "Agent",
  "Task",
  "WebFetch",
  "WebSearch",
  "Edit(/.git)",
  "Edit(/.git/**)",
];
const WORKSPACE_DENY_POLICY = [
  ...COMMON_DENY_POLICY,
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
];
const EXPECTED_SECCOMP_INSTRUCTIONS = Object.freeze({
  arm64: Object.freeze([
    [0x20, 0, 0, 4],
    [0x15, 1, 0, 0xc00000b7],
    [0x06, 0, 0, 0x80000000],
    [0x20, 0, 0, 0],
    [0x15, 6, 0, 425],
    [0x15, 5, 0, 426],
    [0x15, 4, 0, 427],
    [0x15, 0, 2, 198],
    [0x20, 0, 0, 16],
    [0x15, 1, 0, 1],
    [0x06, 0, 0, 0x7fff0000],
    [0x06, 0, 0, 0x00050001],
  ]),
  x64: Object.freeze([
    [0x20, 0, 0, 4],
    [0x15, 1, 0, 0xc000003e],
    [0x06, 0, 0, 0x80000000],
    [0x20, 0, 0, 0],
    [0x15, 10, 0, 425],
    [0x15, 9, 0, 426],
    [0x15, 8, 0, 427],
    [0x15, 7, 0, 0x40000000 | 425],
    [0x15, 6, 0, 0x40000000 | 426],
    [0x15, 5, 0, 0x40000000 | 427],
    [0x15, 1, 0, 41],
    [0x15, 0, 2, 0x40000000 | 41],
    [0x20, 0, 0, 16],
    [0x15, 1, 0, 1],
    [0x06, 0, 0, 0x7fff0000],
    [0x06, 0, 0, 0x00050001],
  ]),
});

function hasCode(code) {
  return (error) => error instanceof ClaudeAdapterError && error.code === code;
}

function hasFailureClass(code, failureClass) {
  return (error) => hasCode(code)(error) && error.failureClass === failureClass;
}

function hasDiagnostic(code, diagnosticClass) {
  return (error) =>
    hasCode(code)(error) && error.diagnosticClass === diagnosticClass;
}

function result({
  error = false,
  output = "done",
  sessionId = FRESH_SESSION,
  structured,
  ...extra
} = {}) {
  return {
    type: "result",
    subtype: error ? "error_during_execution" : "success",
    is_error: error,
    result: output,
    session_id: sessionId,
    permission_denials: [],
    ...extra,
    ...(structured === undefined ? {} : { structured_output: structured }),
  };
}

function processFailure(payload, stderr = "") {
  return Object.assign(new Error("process failed"), {
    stdout: payload === undefined ? "" : JSON.stringify(payload),
    stderr,
  });
}

function option(argumentsList, name) {
  const index = argumentsList.indexOf(name);
  return index === -1 ? undefined : argumentsList[index + 1];
}

function includesSequence(argumentsList, sequence) {
  return argumentsList.some((_, index) =>
    sequence.every((value, offset) => argumentsList[index + offset] === value),
  );
}

function expectedSeccompFilter(architecture) {
  const instructions = EXPECTED_SECCOMP_INSTRUCTIONS[architecture];
  const buffer = Buffer.alloc(instructions.length * 8);
  for (const [
    index,
    [code, trueOffset, falseOffset, value],
  ] of instructions.entries()) {
    const offset = index * 8;
    buffer.writeUInt16LE(code, offset);
    buffer.writeUInt8(trueOffset, offset + 2);
    buffer.writeUInt8(falseOffset, offset + 3);
    buffer.writeUInt32LE(value, offset + 4);
  }
  return buffer;
}

function expectedSeccompIdentity(architecture) {
  const sha256 = createHash("sha256")
    .update(expectedSeccompFilter(architecture))
    .digest("hex");
  return `claude-restricted-host-seccomp-v1:${architecture}:${sha256}`;
}

function shellArgument(value) {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}

function isNativeSandboxProbe({ file, argumentsList }) {
  return (
    file === process.execPath &&
    argumentsList.includes("apply-seccomp") &&
    argumentsList.includes("--cap-drop")
  );
}

function isRunnerBoundaryProbe({ file, argumentsList }) {
  return (
    parse(file).base === "bwrap" &&
    argumentsList.some(
      (argument) =>
        typeof argument === "string" &&
        argument.includes("agent-runner-claude-isolation-ok"),
    )
  );
}

function isIsolationProbe({ file, argumentsList }) {
  return (
    isNativeSandboxProbe({ file, argumentsList }) ||
    isRunnerBoundaryProbe({ file, argumentsList })
  );
}

function isolationProbeScripts(argumentsList) {
  const scriptIndexes = argumentsList.flatMap((value, index) =>
    value === "-e" ? [index + 1] : [],
  );
  return [
    ...scriptIndexes.map((index) => argumentsList[index]),
    ...argumentsList.filter(
      (argument) =>
        typeof argument === "string" &&
        argument.includes("agent-runner-claude-isolation-ok") &&
        !scriptIndexes.some((index) => argumentsList[index] === argument),
    ),
  ];
}

function assertReadOnlyInspectionProbe(script) {
  assert.match(
    script,
    /git log -1 --format=%H[\s\S]+git cat-file -e[\s\S]+git branch -a[\s\S]+ls/u,
  );
  assert.match(script, /GIT_CONFIG_GLOBAL: "\/dev\/null"/u);
  assert.match(script, /GIT_CONFIG_NOSYSTEM: "1"/u);
  assert.match(script, /GIT_TERMINAL_PROMPT: "0"/u);
  assert.match(script, /workspace-command-probe/u);
  assert.match(script, /"branch", "sandbox-command-probe"/u);
  assert.match(script, /"push", outsideDirectory/u);
}

function isProbeRepositorySetup({ file, argumentsList }) {
  const directory = argumentsList[1];
  return (
    file === "git" &&
    argumentsList[0] === "-C" &&
    typeof directory === "string" &&
    parse(dirname(directory)).base.startsWith("ar-c-") &&
    ["outside", "w"].includes(parse(directory).base) &&
    ["add", "commit", "init"].some((command) => argumentsList.includes(command))
  );
}

function localCommitSandboxCalls(fixture) {
  return fixture.calls.filter(
    (call) => call.file === "bwrap" && !isIsolationProbe(call),
  );
}

function claudeArguments({ file, argumentsList }) {
  return file === "claude" ? argumentsList : null;
}

function fallbackAccess(argumentsList) {
  return ["read-only", "workspace-write", "local-commit"].find((access) =>
    argumentsList.some(
      (argument) =>
        typeof argument === "string" && argument.includes(`'${access}'`),
    ),
  );
}

async function createFallbackProject(t) {
  // The launcher validates real paths; do not depend on this checkout's Git layout.
  const projectPath = await mkdtemp(join(tmpdir(), "claude-fallback-project-"));
  t.after(() => rm(projectPath, { force: true, recursive: true }));
  await Promise.all([
    mkdir(join(projectPath, ".git")),
    mkdir(join(projectPath, ".claude")),
  ]);
  await Promise.all([
    writeFile(join(projectPath, ".git/config"), "[core]\n\tbare = false\n"),
    writeFile(join(projectPath, "package.json"), '{"private":true}\n'),
    writeFile(join(projectPath, "README.md"), "Fixture project.\n"),
  ]);
  return projectPath;
}

function claudeBubblewrapArguments({
  access,
  emptyMaskPath,
  payload,
  projectPath = PROJECT_PATH,
}) {
  const argumentsList = [
    "--new-session",
    "--die-with-parent",
    "--unsetenv",
    "ANTHROPIC_API_KEY",
    "--unshare-net",
    "--ro-bind",
    "/",
    "/",
  ];
  if (access === "workspace-write") {
    argumentsList.push(
      "--bind",
      projectPath,
      projectPath,
      "--ro-bind",
      projectPath,
      projectPath,
    );
  }
  argumentsList.push(
    "--bind",
    CLAUDE_LOG_PATH,
    CLAUDE_LOG_PATH,
    "--ro-bind",
    `${projectPath}/.git`,
    `${projectPath}/.git`,
    ...(access !== "workspace-write"
      ? []
      : [
          "--ro-bind",
          `${projectPath}/.git/config`,
          `${projectPath}/.git/config`,
          "--ro-bind",
          `${projectPath}/package.json`,
          `${projectPath}/package.json`,
          ...(emptyMaskPath === undefined
            ? []
            : ["--ro-bind", emptyMaskPath, `${projectPath}/.claude`]),
        ]),
    "--dev",
    "/dev",
    "--unshare-pid",
    "--unshare-user",
    "--bind",
    "/proc",
    "/proc",
    "--",
    "/bin/sh",
    "-c",
    payload,
  );
  return argumentsList;
}

async function createFakeBubblewrap(t) {
  const directory = await mkdtemp(
    join(tmpdir(), "agent-runner-fake-claude-bwrap-"),
  );
  const logPath = join(directory, "arguments.jsonl");
  const filterLogPath = join(directory, "filters.jsonl");
  const helperLogPath = join(directory, "helper.jsonl");
  await Promise.all([
    writeFile(
      join(directory, "claude"),
      `#!${process.execPath}\n` +
        `const { appendFileSync } = require("node:fs");\n` +
        `appendFileSync(${JSON.stringify(helperLogPath)}, "invoked\\n");\n` +
        `process.exit(125);\n`,
      { mode: 0o700 },
    ),
    writeFile(
      join(directory, "bwrap"),
      `#!${process.execPath}\n` +
        `const { spawnSync } = require("node:child_process");\n` +
        `const { appendFileSync, fstatSync, readFileSync, writeSync, existsSync, mkdirSync, writeFileSync } = require("node:fs");\n` +
        `if (process.env.ARGV0 !== undefined || ` +
        `process.env.${COMMAND_LAUNCHER_TOKEN} !== undefined || ` +
        `process.env.ANTHROPIC_API_KEY !== undefined || ` +
        `process.env.HTTPS_PROXY !== undefined || ` +
        `process.env.AGENT_RUNNER_CLAUDE_PROBE_CREDENTIAL !== undefined) ` +
        `process.exit(12);\n` +
        `const args = process.argv.slice(2);\n` +
        `if (process.env.AGENT_RUNNER_FAKE_BWRAP_MATERIALIZE) {\n` +
        `  for (let i = 0; i < args.indexOf("--"); i++) {\n` +
        `    if (args[i] !== "--ro-bind" || args[i+1] === args[i+2]) continue;\n` +
        `    const target = args[i+2];\n` +
        `    if (!target.startsWith(process.env.AGENT_RUNNER_FAKE_BWRAP_MATERIALIZE + "/") || existsSync(target)) continue;\n` +
        `    mkdirSync(require("node:path").dirname(target), { recursive: true });\n` +
        `    writeFileSync(target, "", { mode: 0o400 });\n` +
        `  }\n` +
        `}\n` +
        `if (process.env.AGENT_RUNNER_FAKE_BWRAP_NATIVE === "1") {\n` +
        `  appendFileSync(process.env.AGENT_RUNNER_FAKE_BWRAP_LOG, JSON.stringify(args) + "\\n");\n` +
        `  writeSync(1, "agent-runner-claude-isolation-ok"); process.exit(0);\n` +
        `}\n` +
        `const seccompIndex = args.indexOf("--seccomp");\n` +
        `if (seccompIndex === -1 || args[seccompIndex + 1] !== "3" || ` +
        `args.indexOf("--seccomp", seccompIndex + 1) !== -1) process.exit(13);\n` +
        `const filter = readFileSync(3);\n` +
        `const metadata = fstatSync(3);\n` +
        `let writeError;\n` +
        `try { writeSync(3, Buffer.from([0])); } catch (cause) { writeError = cause?.code; }\n` +
        `appendFileSync(${JSON.stringify(filterLogPath)}, ` +
        `JSON.stringify({ base64: filter.toString("base64"), ` +
        `descriptor: args[seccompIndex + 1], mode: metadata.mode & 0o777, ` +
        `nlink: metadata.nlink, writeError }) + "\\n");\n` +
        `appendFileSync(process.env.AGENT_RUNNER_FAKE_BWRAP_LOG, ` +
        `JSON.stringify(args) + "\\n");\n` +
        `if (process.env.AGENT_RUNNER_FAKE_BWRAP_REJECT_SECCOMP === "1") ` +
        `process.exit(15);\n` +
        `if (process.env.AGENT_RUNNER_FAKE_BWRAP_EXECUTE_PAYLOAD === "1") {\n` +
        `  const separator = args.indexOf("--");\n` +
        `  const environment = { ...process.env };\n` +
        `  for (let index = 0; index < separator; index += 1) {\n` +
        `    if (args[index] === "--unsetenv") {\n` +
        `      delete environment[args[index + 1]];\n` +
        `      index += 1;\n` +
        `    } else if (args[index] === "--setenv") {\n` +
        `      environment[args[index + 1]] = args[index + 2];\n` +
        `      index += 2;\n` +
        `    }\n` +
        `  }\n` +
        `  const result = spawnSync(args[separator + 1], args.slice(separator + 2), ` +
        `{ env: environment, stdio: "inherit" });\n` +
        `  process.exit(result.status ?? 125);\n` +
        `}\n` +
        `writeSync(1, "agent-runner-claude-isolation-ok");\n`,
      { mode: 0o700 },
    ),
    writeFile(join(directory, "package.json"), '{"type":"commonjs"}\n'),
  ]);
  t.after(() => rm(directory, { force: true, recursive: true }));
  return { directory, filterLogPath, helperLogPath, logPath };
}

async function resolveTestExecutable(binary) {
  for (const directory of (process.env.PATH ?? "")
    .split(delimiter)
    .filter(isAbsolute)) {
    const candidate = join(directory, binary);
    try {
      await access(candidate, constants.X_OK);
      const path = await realpath(candidate);
      if ((await stat(path)).isFile()) return path;
    } catch {
      // The real-process regression is capability-gated.
    }
  }
  return undefined;
}

async function commandLauncherEvidence(path) {
  const directory = parse(path).dir;
  const [fileStatus, directoryStatus] = await Promise.all([
    stat(path),
    stat(directory),
  ]);
  return {
    commandLauncherDirectoryMode: directoryStatus.mode & 0o777,
    commandLauncherFileMode: fileStatus.mode & 0o777,
    commandLauncherPath: path,
  };
}

function capabilitiesWithoutReceipt(capabilities) {
  const { policyReceipt, ...rest } = capabilities;
  assert.equal(policyReceipt.schemaVersion, 1);
  assert.match(policyReceipt.fingerprint, /^[a-f0-9]{64}$/u);
  return rest;
}

function policyFingerprint(
  contract,
  policies,
  version = "2.1.233",
  architecture = "x64",
) {
  const fallbackFilterIdentity = Object.values(policies).includes(
    "runner-boundary",
  )
    ? expectedSeccompIdentity(architecture)
    : undefined;
  const accessPolicies = Object.fromEntries(
    Object.entries(policies).map(([access, isolationPolicy]) => {
      const readOnly = access !== "workspace-write";
      return [
        access,
        {
          autoMode: { classifyAllShell: true },
          disableBypassPermissionsMode: "disable",
          permissionMode: "auto",
          permissions: {
            deny: readOnly ? COMMON_DENY_POLICY : WORKSPACE_DENY_POLICY,
          },
          sandbox: {
            allowUnsandboxedCommands: false,
            autoAllowBashIfSandboxed: readOnly,
            credentials: { denyDiscoveredEnvironment: true },
            enabled: true,
            enableWeakerNestedSandbox: isolationPolicy === "runner-boundary",
            excludedCommands: [],
            failIfUnavailable: true,
            filesystem: {
              disabled: false,
              gitMetadataWrite: false,
              outsideWrite: false,
              workspaceWrite: !readOnly,
            },
            isolationPolicy,
            ...(isolationPolicy === "runner-boundary"
              ? { seccompFilter: fallbackFilterIdentity }
              : {}),
            network: {
              allowedDomains: [],
              allowAllUnixSockets: isolationPolicy === "runner-boundary",
              deniedDomains: ["*"],
              strictAllowlist: true,
            },
          },
          tools: readOnly
            ? "Bash,Read,Glob,Grep"
            : "Bash,Read,Edit,Write,Glob,Grep",
        },
      ];
    }),
  );
  return createHash("sha256")
    .update(JSON.stringify({ accessPolicies, contract, policies, version }))
    .digest("hex");
}

function socketServerFixture(socketServers) {
  const listeners = new Map();
  const server = {
    closed: false,
    listening: false,
    close(callback) {
      server.closed = true;
      server.listening = false;
      callback();
    },
    listen() {
      server.listening = true;
      const listener = listeners.get("listening");
      listeners.delete("listening");
      listener?.();
    },
    off(event, listener) {
      if (listeners.get(event) === listener) listeners.delete(event);
    },
    once(event, listener) {
      listeners.set(event, listener);
    },
  };
  socketServers.push(server);
  return server;
}

function createFixture({
  architecture = "x64",
  claudeBinary,
  clientAttribution,
  env,
  handle,
  help = HELP,
  nativeSandbox = true,
  executeFallbackLauncher = false,
  fallbackSandbox = true,
  probeOutput = "agent-runner-claude-commit-ok",
  platform = "linux",
  version = "2.1.233",
} = {}) {
  const calls = [];
  const socketServers = [];
  let turnIndex = 0;
  const execute = async (file, argumentsList, options) => {
    const call = { file, argumentsList, options };
    const isClaudeCall = file === (claudeBinary ?? "claude");
    calls.push(call);
    if (isRunnerBoundaryProbe(call)) {
      Object.assign(call, await commandLauncherEvidence(file));
    } else if (
      isClaudeCall &&
      argumentsList.includes("-p") &&
      options.env[COMMAND_LAUNCHER_TOKEN] !== undefined
    ) {
      const managedSettings = JSON.parse(
        option(argumentsList, "--managed-settings"),
      );
      Object.assign(
        call,
        await commandLauncherEvidence(managedSettings.sandbox.bwrapPath),
      );
    }
    const handled = await handle?.({ call, calls, turnIndex });
    if (handled !== undefined) {
      if (isClaudeCall && argumentsList.includes("-p")) {
        turnIndex += 1;
      }
      return handled;
    }
    if (isClaudeCall && argumentsList.at(-1) === "--version") {
      return { stdout: `${version} (Claude Code)\n`, stderr: "" };
    }
    if (isClaudeCall && argumentsList[0] === "--help") {
      return { stdout: help, stderr: "" };
    }
    if (file === "socat") {
      return { stdout: "socat version 1.8", stderr: "" };
    }
    if (isIsolationProbe(call)) {
      if (isNativeSandboxProbe(call) && nativeSandbox !== true) {
        const error = new Error("Claude isolation probe failed.");
        error.stderr =
          nativeSandbox === "nested-denied"
            ? "apply-seccomp: write /proc/self/setgroups (nested userns is capability-restricted; caller must provide CAP_SYS_ADMIN) Permission denied"
            : "bwrap: Creating new namespace failed: Operation not permitted host-secret-value";
        throw error;
      }
      const access = fallbackAccess(argumentsList);
      if (
        !isNativeSandboxProbe(call) &&
        (fallbackSandbox === false ||
          (Array.isArray(fallbackSandbox) && !fallbackSandbox.includes(access)))
      ) {
        throw new Error("Fallback unavailable host-secret-value");
      }
      if (!isNativeSandboxProbe(call) && executeFallbackLauncher) {
        return executeFile(file, argumentsList, {
          ...options,
          env: { ...options.env, PATH: "" },
        });
      }
      return {
        stdout: "agent-runner-claude-isolation-ok",
        stderr: "",
      };
    }
    if (file === "git") {
      return { stdout: `${argumentsList[1]}/.git\n.git\n`, stderr: "" };
    }
    const effectiveArguments = isClaudeCall ? argumentsList : null;
    if (effectiveArguments?.includes("-p")) {
      const resume = option(effectiveArguments, "--resume");
      const schema = option(effectiveArguments, "--json-schema");
      const model = option(effectiveArguments, "--model");
      const localCommit = schema?.includes('"ready"') === true;
      const payload = result({
        sessionId:
          resume === undefined
            ? FRESH_SESSION
            : effectiveArguments.includes("--fork-session")
              ? CHILD_SESSION
              : resume,
        structured:
          schema === undefined
            ? undefined
            : localCommit
              ? { ready: true }
              : { ok: true },
        ...(model?.startsWith("claude-") === true
          ? { modelUsage: { [model]: {} } }
          : {}),
      });
      turnIndex += 1;
      return { stdout: JSON.stringify(payload), stderr: "" };
    }
    if (file === "bwrap") {
      return { stdout: probeOutput, stderr: "" };
    }
    throw new Error(`Unexpected command: ${file} ${argumentsList.join(" ")}`);
  };
  const adapter = createClaudeAdapter({
    architecture,
    ...(claudeBinary === undefined ? {} : { claudeBinary }),
    ...(clientAttribution === undefined ? {} : { clientAttribution }),
    createSocketServer: () => socketServerFixture(socketServers),
    env: env ?? process.env,
    execute,
    platform,
  });
  return { adapter, calls, socketServers };
}

function request(overrides = {}) {
  return {
    access: "read-only",
    cwd: PROJECT_PATH,
    prompt: "Inspect the repository.",
    ...overrides,
  };
}

test("streams Claude progress before completion without exposing payloads or losing command nesting", async (t) => {
  const entered = Promise.withResolvers();
  const release = Promise.withResolvers();
  const events = [];
  const fixture = createFixture({
    async handle({ call }) {
      if (call.file !== "claude" || !call.argumentsList.includes("-p")) return;
      entered.resolve(call);
      await release.promise;
      return { stdout: "", stderr: "" };
    },
  });
  await assert.rejects(
    fixture.adapter.run(request({ onProgress: true })),
    hasCode("ERR_INVALID_CLAUDE_OPTIONS"),
  );
  const running = fixture.adapter.run(
    request({
      schema: STRICT_SCHEMA,
      session: { id: FRESH_SESSION, mode: "continue" },
      onProgress: (event) => events.push(event),
    }),
  );
  t.after(async () => {
    release.resolve();
    await running.catch(() => {});
  });
  const call = await entered.promise;
  assert.equal(option(call.argumentsList, "--output-format"), "stream-json");
  assert.ok(call.argumentsList.includes("--verbose"));
  assert.ok(call.argumentsList.includes("--include-partial-messages"));
  const send = (record) =>
    call.options.onStdout(
      Buffer.from(
        `${JSON.stringify({ session_id: FRESH_SESSION, ...record })}\n`,
      ),
    );
  send({ type: "system", subtype: "init" });
  const partial = (event) => send({ type: "stream_event", event });
  partial({
    type: "message_start",
    message: { id: "message", role: "assistant" },
  });
  partial({
    type: "content_block_start",
    index: 0,
    content_block: { type: "text", text: "" },
  });
  const text = Buffer.from(
    `${JSON.stringify({
      type: "stream_event",
      session_id: FRESH_SESSION,
      event: {
        type: "content_block_delta",
        index: 0,
        delta: { type: "text_delta", text: "private-🙂" },
      },
    })}\n`,
  );
  const split = text.indexOf(Buffer.from("🙂")) + 1;
  call.options.onStdout(text.subarray(0, split));
  call.options.onStdout(text.subarray(split));
  assert.equal(events.length, 4);
  const beforeIgnored = events.length;
  send({ type: "ping" });
  send({
    type: "tool_progress",
    tool_use_id: "first",
    elapsed_time_seconds: 300,
  });
  partial({
    type: "content_block_delta",
    index: 5,
    delta: { type: "text_delta", text: "unowned" },
  });
  partial({
    type: "content_block_delta",
    index: 0,
    delta: { type: "text_delta", text: 123 },
  });
  partial({
    type: "content_block_delta",
    index: 5,
    delta: { type: "__proto__", undefined: "unowned" },
  });
  send({ type: "system", subtype: "init", session_id: SOURCE_SESSION });
  assert.equal(events.length, beforeIgnored);
  const assistant = {
    type: "assistant",
    message: {
      id: "tools",
      role: "assistant",
      content: ["first", "second"].map((id) => ({
        type: "tool_use",
        id,
        name: "Bash",
        input: { command: "private-command" },
      })),
    },
  };
  send(assistant);
  send(assistant);
  send({
    type: "assistant",
    message: {
      id: "read",
      role: "assistant",
      content: [
        {
          type: "tool_use",
          id: "read",
          name: "Read",
          input: { file_path: "private-path" },
        },
      ],
    },
  });
  send({
    type: "user",
    message: {
      role: "user",
      content: [
        { type: "tool_result", tool_use_id: "read", content: "private-file" },
      ],
    },
  });
  send({
    type: "system",
    subtype: "task_started",
    task_type: "local_bash",
    task_id: "background",
    tool_use_id: "first",
  });
  send({
    type: "user",
    message: {
      role: "user",
      content: ["second", "unknown", "first", "first"].map((tool_use_id) => ({
        type: "tool_result",
        tool_use_id,
        content: "private-output",
      })),
    },
  });
  assert.equal(events.at(-1).activeCommands, 1);
  send({
    type: "system",
    subtype: "task_notification",
    task_id: "background",
    status: "completed",
  });
  send(result({ structured: { ok: true }, output: "done🙂" }));
  release.resolve();
  const response = await running;
  assert.equal(response.output, "done🙂");
  assert.deepEqual(response.structured, { ok: true });
  assert.equal(response.sessionId, FRESH_SESSION);
  assert.deepEqual(
    events
      .filter(({ kind }) => kind.startsWith("local-command-"))
      .map(({ activeCommands }) => activeCommands),
    [1, 2, 3, 2, 1, 0],
  );
  assert.deepEqual(
    events.filter(({ kind }) => kind.startsWith("local-tool-")),
    [
      { kind: "local-tool-started", activeCommands: 2 },
      { kind: "local-tool-completed", activeCommands: 2 },
    ],
  );
  for (const event of events) {
    assert.ok(Object.isFrozen(event));
    assert.deepEqual(Object.keys(event), ["kind", "activeCommands"]);
  }
  assert.doesNotMatch(
    JSON.stringify(events),
    /private-|first|second|background|session/u,
  );
});

test("rejects malformed, duplicate, mismatched, missing, and oversized Claude stream results", async (t) => {
  const init = JSON.stringify({
    type: "system",
    subtype: "init",
    session_id: FRESH_SESSION,
  });
  const final = JSON.stringify(result());
  for (const [name, stdout, failed] of [
    ["malformed", `bad-json\n${final}\n`],
    ["duplicate", `${final}\n${final}\n`],
    ["trailing-init", `${final}\n${init}\n`],
    [
      "trailing",
      `${final}\n${JSON.stringify({ type: "assistant", session_id: FRESH_SESSION, message: {} })}\n`,
    ],
    [
      "mismatched",
      `${init}\n${JSON.stringify(result({ sessionId: CHILD_SESSION }))}\n`,
    ],
    ["missing", `${init}\n`],
    ["failed-incomplete", `${init}\n`, true],
    ["oversized", "x".repeat(16 * 1024 * 1024 + 1)],
    ["oversized-whitespace", `${" ".repeat(16 * 1024 * 1024 + 1)}\n`],
    ["invalid-utf8", Buffer.from([0xff, 10])],
    [
      "stream-limit",
      (write) => {
        const line = `${JSON.stringify({ type: "ping", padding: "x".repeat(1024 * 1024) })}\n`;
        for (let index = 0; index < 64; index += 1) write(line);
      },
    ],
  ])
    await t.test(name, async () => {
      const fixture = createFixture({
        handle({ call }) {
          if (call.file !== "claude" || !call.argumentsList.includes("-p"))
            return;
          if (typeof stdout === "function") stdout(call.options.onStdout);
          else call.options.onStdout(stdout);
          if (failed) throw processFailure();
          return { stdout: "", stderr: "" };
        },
      });
      await assert.rejects(
        fixture.adapter.run(request()),
        hasCode("ERR_CLAUDE_PROTOCOL"),
      );
      assert.equal(turnCalls(fixture).length, 1);
    });
});

test("Claude streaming preserves permission precedence and retires unfinished command activity", async () => {
  const events = [];
  const fixture = createFixture({
    handle({ call }) {
      if (call.file !== "claude" || !call.argumentsList.includes("-p")) return;
      for (const record of [
        { type: "system", subtype: "init" },
        {
          type: "assistant",
          message: {
            id: "message",
            role: "assistant",
            content: [
              {
                type: "tool_use",
                id: "command",
                name: "Bash",
                input: { command: "private-command" },
              },
            ],
          },
        },
        result({
          error: true,
          api_error_status: 503,
          permission_denials: [
            { tool_name: "Bash", tool_input: { command: "git push" } },
          ],
        }),
      ])
        call.options.onStdout(
          `${JSON.stringify({ session_id: FRESH_SESSION, ...record })}\n`,
        );
      throw Object.assign(new Error("private-process-error"), {
        stdout: "",
        stderr: "",
      });
    },
  });
  await assert.rejects(
    fixture.adapter.run(request({ onProgress: (event) => events.push(event) })),
    hasDiagnostic(
      "ERR_CLAUDE_PERMISSION_DENIED",
      "permission_forbidden_operation",
    ),
  );
  assert.equal(turnCalls(fixture).length, 1);
  assert.deepEqual(events.at(-1), {
    kind: "local-command-completed",
    activeCommands: 0,
  });
});

test("redacts Claude retirement observer errors without replacing provider failures", async (t) => {
  for (const failed of [false, true])
    await t.test(
      failed ? "provider failure" : "successful result",
      async () => {
        const fixture = createFixture({
          handle({ call }) {
            if (call.file !== "claude" || !call.argumentsList.includes("-p"))
              return;
            for (const record of [
              { type: "system", subtype: "init" },
              {
                type: "assistant",
                message: {
                  id: "message",
                  role: "assistant",
                  content: [
                    {
                      type: "tool_use",
                      id: "command",
                      name: "Bash",
                      input: { command: "inspection" },
                    },
                  ],
                },
              },
              result(failed ? { error: true, api_error_status: 429 } : {}),
            ])
              call.options.onStdout(
                `${JSON.stringify({ session_id: FRESH_SESSION, ...record })}\n`,
              );
            return { stdout: "", stderr: "" };
          },
        });
        await assert.rejects(
          fixture.adapter.run(
            request({
              onProgress({ kind }) {
                if (kind === "local-command-completed")
                  throw new Error("private-observer-error");
              },
            }),
          ),
          (error) => {
            assert.ok(
              hasCode(
                failed ? "ERR_CLAUDE_USAGE_LIMIT" : "ERR_CLAUDE_PROTOCOL",
              )(error),
            );
            assert.doesNotMatch(error.message, /private-observer-error/u);
            assert.equal(error.cause, undefined);
            return true;
          },
        );
        assert.equal(turnCalls(fixture).length, 1);
      },
    );
});

function turnCalls(fixture) {
  return fixture.calls.filter(
    (call) => claudeArguments(call)?.includes("-p") === true,
  );
}

const EFFORT_HELP = `${HELP}\n--effort <level> Effort level (low, medium, high, max)`;

test("maps portable Claude effort across sessions and commit readiness", async () => {
  for (const effort of ["low", "medium", "high", "xhigh"]) {
    for (const mode of [undefined, "continue", "fork"]) {
      const fixture = createFixture({ help: EFFORT_HELP });
      await fixture.adapter.run(
        request({
          effort,
          ...(mode === undefined
            ? {}
            : { session: { id: SOURCE_SESSION, mode } }),
        }),
      );
      assert.equal(
        option(turnCalls(fixture)[0].argumentsList, "--effort"),
        effort === "xhigh" ? "max" : effort,
      );
    }
  }
  const fixture = createFixture({ help: EFFORT_HELP });
  await fixture.adapter.run(
    request({
      effort: "xhigh",
      access: "local-commit",
      authorizationId: "effort-commit",
      commit: {
        expectedHead: EXPECTED_HEAD,
        message: "feat(test): preserve effort",
      },
    }),
  );
  assert.equal(option(turnCalls(fixture)[0].argumentsList, "--effort"), "max");
});

test("requires Claude effort support only for explicit selections", async () => {
  for (const help of [
    HELP,
    `${HELP}\n--effort <level> Effort level (low, medium, high)`,
  ]) {
    const fixture = createFixture({ help });
    await fixture.adapter.run(request({ effort: "current" }));
    await assert.rejects(
      fixture.adapter.probe({ effort: "xhigh" }),
      hasDiagnostic("ERR_UNSUPPORTED_EFFORT", "effort_unsupported"),
    );
    await assert.rejects(
      fixture.adapter.run(request({ effort: "xhigh" })),
      hasCode("ERR_UNSUPPORTED_EFFORT"),
    );
    assert.equal(turnCalls(fixture).length, 1);
    assert.equal(
      option(turnCalls(fixture)[0].argumentsList, "--effort"),
      undefined,
    );
  }
  const fixture = createFixture({
    help: `${HELP}\n--effort <level> Effort level\n    (low, medium, high)\n--extra <value>`,
  });
  await fixture.adapter.run(request({ effort: "high" }));
  assert.equal(option(turnCalls(fixture)[0].argumentsList, "--effort"), "high");
});

test("preserves Claude effort during fresh reconstruction and compaction", async () => {
  for (const recovery of ["fresh", "compact"]) {
    let turns = 0;
    const fixture = createFixture({
      help: EFFORT_HELP,
      handle({ call }) {
        if (
          call.file === "claude" &&
          call.argumentsList.includes("-p") &&
          turns++ === 0
        ) {
          throw processFailure(
            result({
              error: true,
              sessionId: SOURCE_SESSION,
              output:
                recovery === "fresh"
                  ? "Session not found"
                  : "Context window exceeded",
            }),
          );
        }
      },
    });
    await fixture.adapter.run(
      request({
        effort: "high",
        session: { id: SOURCE_SESSION, mode: "continue" },
      }),
    );
    assert.equal(turns, 2);
    for (const turn of turnCalls(fixture))
      assert.equal(option(turn.argumentsList, "--effort"), "high");
    assert.equal(
      option(turnCalls(fixture)[1].argumentsList, "--resume"),
      recovery === "fresh" ? undefined : SOURCE_SESSION,
    );
  }
});

test("normalizes Claude effort rejections without availability retry", async () => {
  for (const status of [undefined, 400, 422]) {
    for (const access of ["read-only", "workspace-write", "local-commit"]) {
      const fixture = createFixture({
        help: EFFORT_HELP,
        handle({ call }) {
          if (call.file === "claude" && call.argumentsList.includes("-p"))
            throw processFailure(
              result({
                error: true,
                output:
                  "Effort max is not supported for this model PRIVATE_NATIVE_DETAIL",
                ...(status === undefined ? {} : { api_error_status: status }),
              }),
            );
        },
      });
      await assert.rejects(
        fixture.adapter.run(
          request({
            effort: "xhigh",
            access,
            ...(access === "local-commit"
              ? {
                  authorizationId: "effort-rejected",
                  commit: {
                    expectedHead: EXPECTED_HEAD,
                    message: "feat(test): reject effort",
                  },
                }
              : {}),
          }),
        ),
        (error) => {
          assert.ok(
            hasDiagnostic(
              "ERR_UNSUPPORTED_EFFORT",
              "effort_unsupported",
            )(error),
          );
          assert.equal(error.recoverable, false);
          assert.equal(error.cause, undefined);
          assert.equal(
            error.effectStarted,
            access === "local-commit" ? false : undefined,
          );
          const normalized = normalizeAdapterFailure("claude", error);
          assert.equal(normalized.code, "ERR_UNSUPPORTED_EFFORT");
          assert.equal(normalized.diagnosticClass, "effort_unsupported");
          assert.doesNotMatch(
            JSON.stringify(normalized),
            /PRIVATE_NATIVE_DETAIL/u,
          );
          return true;
        },
      );
      assert.equal(turnCalls(fixture).length, 1);
      assert.equal(localCommitSandboxCalls(fixture).length, 1); // Capability probe only.
    }
  }
});

test("keeps transient Claude status authoritative over effort-like prose", async () => {
  const fixture = createFixture({
    help: EFFORT_HELP,
    handle({ call }) {
      if (call.file === "claude" && call.argumentsList.includes("-p"))
        throw processFailure(
          result({
            error: true,
            api_error_status: 503,
            output: "Effort is not supported",
          }),
        );
    },
  });
  await assert.rejects(
    fixture.adapter.run(request({ effort: "high" })),
    hasCode("ERR_CLAUDE_PROVIDER_UNAVAILABLE"),
  );
  assert.equal(turnCalls(fixture).length, 1);
});

test("classifies explicit Claude effort rejection during turn setup as terminal", async () => {
  const fixture = createFixture({
    help: EFFORT_HELP,
    handle({ call }) {
      if (call.file === "claude" && call.argumentsList.includes("-p"))
        throw processFailure(
          result({
            error: true,
            terminal_reason: "turn_setup_failed",
            output: "Effort max is not supported for this model",
          }),
        );
    },
  });
  await assert.rejects(
    fixture.adapter.run(request({ effort: "xhigh" })),
    (error) => {
      assert.ok(
        hasDiagnostic("ERR_UNSUPPORTED_EFFORT", "effort_unsupported")(error),
      );
      assert.equal(error.recoverable, false);
      return true;
    },
  );
  assert.equal(turnCalls(fixture).length, 1);
});

test("marks only Claude native-sandbox executions as provider-owned", async () => {
  const fixture = createFixture();
  await fixture.adapter.run(request({ onProcess: async () => {} }));

  const turn = turnCalls(fixture)[0];
  const metadata = fixture.calls.find(
    ({ file, argumentsList }) =>
      file === "git" && argumentsList.includes("--absolute-git-dir"),
  );
  assert.equal(turn.options.ownershipMode, "native-sandbox-provider");
  assert.equal(metadata.options.ownershipMode, undefined);
});

test("constructs and probes enforceable Claude capabilities", async () => {
  assert.doesNotThrow(() => createClaudeAdapter());
  assert.equal(
    new ClaudeAdapterError("invalid failure class", {
      failureClass: "native-provider-text",
    }).failureClass,
    undefined,
  );
  const invalidDiagnostic = new ClaudeAdapterError("invalid diagnostic class", {
    diagnosticClass: "native-provider-text",
    recoverable: true,
  });
  assert.equal(invalidDiagnostic.diagnosticClass, undefined);
  assert.equal(invalidDiagnostic.recoverable, false);
  assert.throws(
    () => createClaudeAdapter({ env: new Map() }),
    hasCode("ERR_INVALID_CLAUDE_OPTIONS"),
  );
  const invalidRequestFixture = createFixture();
  await assert.rejects(
    invalidRequestFixture.adapter.run(request({ recoveryPrompt: "" })),
    hasCode("ERR_INVALID_CLAUDE_OPTIONS"),
  );
  assert.equal(turnCalls(invalidRequestFixture).length, 0);
  const fixture = createFixture();

  assert.equal(fixture.adapter.id, CLAUDE_BACKEND_ID);
  const capabilities = await fixture.adapter.probe({ model: "claude-test" });
  assert.deepEqual(capabilitiesWithoutReceipt(capabilities), {
    version: "2.1.233",
    structuredOutput: true,
    readOnly: true,
    autonomousWrite: true,
    gitMetadataWriteBlocked: true,
    workspaceWrite: true,
    localCommit: true,
    remoteWriteBlocked: true,
    nativeSessionContinuation: true,
    nativeSessionFork: true,
  });
  assert.equal(
    capabilities.policyReceipt.fingerprint,
    policyFingerprint(
      "claude-isolation-v2",
      {
        "read-only": "native",
        "workspace-write": "native",
        "local-commit": "native",
      },
      capabilities.version,
    ),
  );
  const probeRepositoryCalls = fixture.calls.filter(isProbeRepositorySetup);
  assert.ok(probeRepositoryCalls.length > 0);
  for (const { options } of probeRepositoryCalls) {
    assert.equal(options.env.GIT_CONFIG_GLOBAL, "/dev/null");
    assert.equal(options.env.GIT_CONFIG_NOSYSTEM, "1");
    assert.equal(options.env.GIT_TERMINAL_PROMPT, "0");
  }
  assert.deepEqual(
    fixture.calls
      .filter(({ file }) => file !== "git")
      .slice(0, 8)
      .map(({ file, argumentsList }) => [file, argumentsList[0]]),
    [
      ["claude", "--version"],
      ["claude", "--help"],
      ["socat", "-V"],
      [process.execPath, "--input-type=module"],
      ["claude", "--managed-settings"],
      [process.execPath, "--input-type=module"],
      [process.execPath, "--input-type=module"],
      ["bwrap", "--die-with-parent"],
    ],
  );
  const nativeSandboxCall = fixture.calls.find(isNativeSandboxProbe);
  assert.ok(nativeSandboxCall);
  assert.deepEqual(nativeSandboxCall.argumentsList.slice(0, 4), [
    "--input-type=module",
    "-e",
    nativeSandboxCall.argumentsList[2],
    nativeSandboxCall.argumentsList[3],
  ]);
  assert.equal(parse(nativeSandboxCall.argumentsList[3]).base, "bwrap");
  assert.ok(isAbsolute(nativeSandboxCall.argumentsList[3]));
  const [providerProbe, commandProbe] = isolationProbeScripts(
    nativeSandboxCall.argumentsList,
  );
  assert.match(providerProbe, /spawnSync/u);
  assert.match(providerProbe, /String\(process\.pid\)/u);
  assert.match(
    providerProbe,
    /delete commandEnvironment\.AGENT_RUNNER_CLAUDE_PROBE_CREDENTIAL/u,
  );
  assert.match(commandProbe, /readFileSync/u);
  assert.match(commandProbe, /join\("\/proc", providerPid, "environ"\)/u);
  assert.match(commandProbe, /readFileSync\([^;]+\);\n  process\.exit\(18\)/u);
  assert.match(commandProbe, /AGENT_RUNNER_CLAUDE_PROBE_CREDENTIAL/u);
  assertReadOnlyInspectionProbe(commandProbe);
  assert.ok(nativeSandboxCall.argumentsList.includes("--unshare-net"));
  assert.ok(nativeSandboxCall.argumentsList.includes("--unshare-user"));
  assert.ok(nativeSandboxCall.argumentsList.includes("--cap-drop"));
  assert.ok(
    includesSequence(nativeSandboxCall.argumentsList, [
      "--setenv",
      "ARGV0",
      "apply-seccomp",
    ]),
  );
  assert.equal(nativeSandboxCall.options.timeout, 10_000);
  assert.equal(nativeSandboxCall.options.maxBuffer, 1024 * 1024);
  assert.equal(nativeSandboxCall.options.shell, undefined);
  assert.equal(turnCalls(fixture).length, 0);
  assert.ok(
    fixture.calls
      .filter(({ file }) => file === "claude")
      .every(({ argumentsList }) => !argumentsList.includes("--model")),
  );
  assert.equal(
    fixture.calls.some(({ file }) => file === "/usr/bin/unshare"),
    false,
  );
  assert.strictEqual(
    await fixture.adapter.probe(),
    await fixture.adapter.probe(),
  );

  assert.equal(
    (await createFixture({ version: "2.1.233+distribution.1" }).adapter.probe())
      .version,
    "2.1.233+distribution.1",
  );
});

test("reports custom client attribution as unsupported without provider activity", async () => {
  const sensitiveMarker = "DO_NOT_RETAIN_CUSTOM_CLIENT_IDENTITY";
  const fixture = createFixture({
    clientAttribution: {
      name: sensitiveMarker,
      title: `${sensitiveMarker} title`,
    },
  });
  let nativeFailure;

  await assert.rejects(fixture.adapter.probe(), (error) => {
    nativeFailure = error;
    return (
      error instanceof ClaudeAdapterError &&
      error.code === "ERR_UNSUPPORTED_CLAUDE_CLIENT_ATTRIBUTION"
    );
  });

  assert.equal(fixture.calls.length, 0);
  const normalized = normalizeAdapterFailure("claude", nativeFailure);
  assert.equal(normalized.message, "Agent backend turn failed.");
  assert.equal(normalized.code, "ERR_UNSUPPORTED_CLAUDE_CLIENT_ATTRIBUTION");
  assert.doesNotMatch(
    JSON.stringify({ ...normalized, message: normalized.message }),
    new RegExp(sensitiveMarker, "u"),
  );
});

test("fails preflight when the CLI or isolation is unsupported", async () => {
  for (const fixture of [
    createFixture({ version: "2.1.232" }),
    createFixture({ version: "2.1.234-beta.1" }),
    createFixture({ platform: "darwin" }),
    createFixture({ nativeSandbox: false }),
    createFixture({
      handle({ call }) {
        if (call.argumentsList.includes("--managed-settings")) {
          throw new Error("managed settings unavailable");
        }
        return undefined;
      },
      nativeSandbox: "nested-denied",
    }),
    createFixture({
      handle({ call }) {
        if (call.file === "socat") {
          throw new Error("socat unavailable");
        }
        return undefined;
      },
    }),
  ]) {
    await assert.rejects(
      fixture.adapter.run(request()),
      hasCode("ERR_UNSUPPORTED_CLAUDE_CAPABILITY"),
    );
    assert.equal(turnCalls(fixture).length, 0);
  }
});

test("keeps native-turn and local-commit isolation proofs independent", async () => {
  const unsupportedLocalCommit = createFixture({ probeOutput: "" });

  assert.deepEqual(
    capabilitiesWithoutReceipt(await unsupportedLocalCommit.adapter.probe()),
    {
      version: "2.1.233",
      structuredOutput: true,
      readOnly: true,
      autonomousWrite: true,
      gitMetadataWriteBlocked: true,
      workspaceWrite: true,
      localCommit: false,
      remoteWriteBlocked: true,
      nativeSessionContinuation: true,
      nativeSessionFork: true,
    },
  );
  await unsupportedLocalCommit.adapter.run(
    request({ access: "workspace-write" }),
  );
  await assert.rejects(
    unsupportedLocalCommit.adapter.run(
      request({
        access: "local-commit",
        authorizationId: "authorization-1",
        commit: {
          expectedHead: EXPECTED_HEAD,
          message: "test(scope): keep probes independent",
        },
      }),
    ),
    hasCode("ERR_UNSUPPORTED_CLAUDE_CAPABILITY"),
  );
  assert.equal(turnCalls(unsupportedLocalCommit).length, 1);
  assert.equal(
    unsupportedLocalCommit.calls.some(({ argumentsList }) =>
      argumentsList.includes("--managed-settings"),
    ),
    true,
  );

  const incompatibleNativeSandbox = createFixture({
    env: {
      ...process.env,
      ANTHROPIC_API_KEY: "provider-token",
      CLAUDE_CONFIG_DIR: "/profiles/current",
      HTTPS_PROXY: "http://credential.invalid",
      NODE_OPTIONS: "--require=/tmp/agent.cjs",
    },
    nativeSandbox: false,
  });
  assert.deepEqual(
    capabilitiesWithoutReceipt(
      await incompatibleNativeSandbox.adapter.probe({
        profile: "/profiles/work",
        model: "claude-test",
      }),
    ),
    {
      version: "2.1.233",
      structuredOutput: true,
      readOnly: false,
      autonomousWrite: false,
      gitMetadataWriteBlocked: false,
      workspaceWrite: false,
      localCommit: false,
      remoteWriteBlocked: false,
      nativeSessionContinuation: true,
      nativeSessionFork: true,
    },
  );
  await assert.rejects(
    incompatibleNativeSandbox.adapter.run(request()),
    (error) => {
      assert.ok(hasCode("ERR_UNSUPPORTED_CLAUDE_CAPABILITY")(error));
      assert.equal(
        error.message,
        "Installed Claude CLI cannot enforce the requested capability.",
      );
      assert.equal(error.cause, undefined);
      assert.doesNotMatch(error.message, /host-secret|setgroups/u);
      return true;
    },
  );
  const nativeSandboxCall =
    incompatibleNativeSandbox.calls.find(isNativeSandboxProbe);
  assert.equal(nativeSandboxCall.options.env.ANTHROPIC_API_KEY, undefined);
  assert.equal(nativeSandboxCall.options.env.HTTPS_PROXY, undefined);
  assert.equal(nativeSandboxCall.options.env.NODE_OPTIONS, undefined);
  assert.equal(
    nativeSandboxCall.options.env.CLAUDE_CONFIG_DIR,
    "/profiles/current",
  );
  assert.ok(!nativeSandboxCall.argumentsList.includes("/profiles/work"));
  assert.equal(
    incompatibleNativeSandbox.calls.filter(({ file }) => file === "bwrap")
      .length,
    1,
  );
  assert.equal(
    incompatibleNativeSandbox.calls.filter(isNativeSandboxProbe).length,
    3,
  );
  assert.equal(
    incompatibleNativeSandbox.calls.some(
      ({ file }) => file === "/usr/bin/unshare",
    ),
    false,
  );
  assert.deepEqual(
    incompatibleNativeSandbox.calls
      .filter(({ file }) => file === "claude")
      .map(({ argumentsList }) => argumentsList),
    [["--version"], ["--help"]],
  );
  assert.equal(turnCalls(incompatibleNativeSandbox).length, 0);
});

test("isolates fallback commands without blocking Claude transport", async (t) => {
  const projectPath = await createFallbackProject(t);
  const fakeBubblewrap = await createFakeBubblewrap(t);
  const emptyMaskPath = await mkdtemp(join(tmpdir(), "claude-empty-"));
  await chmod(emptyMaskPath, 0o700);
  t.after(() => rm(emptyMaskPath, { force: true, recursive: true }));
  const providerPath = `${fakeBubblewrap.directory}${delimiter}${process.env.PATH ?? ""}`;
  const fixture = createFixture({
    architecture: "x64",
    env: {
      ...process.env,
      AGENT_RUNNER_FAKE_BWRAP_LOG: fakeBubblewrap.logPath,
      [COMMAND_LAUNCHER_TOKEN]: "inherited-launcher-token",
      ANTHROPIC_API_KEY: "provider-token",
      ARGV0: "inherited-argv0",
      HTTPS_PROXY: "http://credential.invalid",
      PATH: providerPath,
    },
    executeFallbackLauncher: true,
    handle: async ({ call, turnIndex }) => {
      if (call.file !== "claude" || !call.argumentsList.includes("-p")) return;
      const managedSettings = JSON.parse(
        option(call.argumentsList, "--managed-settings"),
      );
      const access = ["read-only", "workspace-write", "local-commit"][
        turnIndex
      ];
      await executeFile(
        managedSettings.sandbox.bwrapPath,
        claudeBubblewrapArguments({
          projectPath,
          access,
          emptyMaskPath,
          payload: `model-command ${turnIndex}`,
        }),
        {
          encoding: "utf8",
          env: { ...call.options.env, PATH: "" },
          timeout: 10_000,
        },
      );
      const schema = option(call.argumentsList, "--json-schema");
      const payload = result({
        structured:
          schema === undefined
            ? undefined
            : schema.includes('"ready"')
              ? { ready: true }
              : { ok: true },
      });
      return { stdout: JSON.stringify(payload), stderr: "" };
    },
    nativeSandbox: "nested-denied",
  });

  const capabilities = await fixture.adapter.probe();
  assert.deepEqual(capabilities.policyReceipt.supportedAccess, [
    "read-only",
    "workspace-write",
    "local-commit",
  ]);
  assert.equal(capabilities.readOnly, true);
  assert.equal(capabilities.workspaceWrite, true);
  assert.equal(capabilities.localCommit, true);
  assert.equal(
    capabilities.policyReceipt.fingerprint,
    policyFingerprint(
      "claude-command-boundary-v8",
      {
        "read-only": "runner-boundary",
        "workspace-write": "runner-boundary",
        "local-commit": "runner-boundary",
      },
      capabilities.version,
    ),
  );
  assert.equal(
    fixture.calls.filter(
      ({ file, argumentsList }) =>
        file === "claude" &&
        argumentsList[0] === "--managed-settings" &&
        argumentsList.at(-1) === "--version",
    ).length,
    1,
  );
  assert.equal(fixture.calls.filter(isNativeSandboxProbe).length, 3);
  const fallbackProbes = fixture.calls.filter(
    (call) => isIsolationProbe(call) && !isNativeSandboxProbe(call),
  );
  assert.equal(fallbackProbes.length, 3);
  assert.equal(fixture.socketServers.length, 6);
  assert.ok(fixture.socketServers.every(({ closed }) => closed));
  assert.deepEqual(
    fallbackProbes.map(({ argumentsList }) => fallbackAccess(argumentsList)),
    ["read-only", "workspace-write", "local-commit"],
  );
  const provedBoundaries = (await readFile(fakeBubblewrap.logPath, "utf8"))
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  assert.equal(provedBoundaries.length, 3);
  for (const [index, call] of fallbackProbes.entries()) {
    const { argumentsList } = call;
    const access = ["read-only", "workspace-write", "local-commit"][index];
    const boundaryArguments = provedBoundaries[index];
    const commandIndex = boundaryArguments.indexOf("--");
    const workspaceDirectory = option(boundaryArguments, "--chdir");
    const gitDirectory = join(workspaceDirectory, ".git");
    const socketPath = join(workspaceDirectory, "s");
    assert.equal(call.file, call.commandLauncherPath);
    assert.equal(
      call.options.env.PATH.split(delimiter)[0],
      fakeBubblewrap.directory,
    );
    const fallbackPayload = argumentsList.at(-1);
    const nodeExecutable = shellArgument(process.execPath);
    assert.equal(
      fallbackPayload.slice(0, fallbackPayload.indexOf(" --input-type=module")),
      nodeExecutable,
    );
    assert.ok(fallbackPayload.includes(`'${socketPath}'`));
    assert.equal(
      includesSequence(boundaryArguments, [
        "--setenv",
        "ARGV0",
        "apply-seccomp",
      ]),
      false,
    );
    assert.equal(
      boundaryArguments.filter((argument) => argument === "--unshare-user")
        .length,
      1,
    );
    assert.ok(boundaryArguments.includes("--unshare-net"));
    assert.ok(boundaryArguments.includes("--as-pid-1"));
    assert.ok(includesSequence(boundaryArguments, ["--cap-drop", "ALL"]));
    assert.ok(includesSequence(boundaryArguments, ["--ro-bind", "/", "/"]));
    assert.ok(includesSequence(boundaryArguments, ["--proc", "/proc"]));
    assert.ok(includesSequence(boundaryArguments, ["--seccomp", "3"]));
    assert.ok(includesSequence(boundaryArguments, ["--tmpfs", "/tmp"]));
    assert.ok(includesSequence(boundaryArguments, ["--dir", "/tmp/claude"]));
    assert.ok(includesSequence(boundaryArguments, ["--tmpfs", "/run"]));
    assert.ok(
      includesSequence(boundaryArguments, [
        "--unsetenv",
        "AGENT_RUNNER_CLAUDE_PROBE_CREDENTIAL",
      ]),
    );
    assert.ok(
      includesSequence(boundaryArguments, ["--unsetenv", "ANTHROPIC_API_KEY"]),
    );
    assert.ok(
      includesSequence(boundaryArguments, ["--unsetenv", "HTTPS_PROXY"]),
    );
    assert.ok(
      includesSequence(boundaryArguments, [
        "--unsetenv",
        "AGENT_RUNNER_CLAUDE_COMMAND_LAUNCHER_TOKEN",
      ]),
    );
    assert.ok(includesSequence(boundaryArguments, ["--unsetenv", "ARGV0"]));
    assert.equal(
      includesSequence(boundaryArguments, [
        "--bind",
        workspaceDirectory,
        workspaceDirectory,
      ]),
      access === "workspace-write",
    );
    assert.equal(
      includesSequence(boundaryArguments, [
        "--ro-bind",
        workspaceDirectory,
        workspaceDirectory,
      ]),
      access !== "workspace-write",
    );
    assert.ok(
      includesSequence(boundaryArguments, [
        "--ro-bind",
        gitDirectory,
        gitDirectory,
      ]),
    );
    assert.equal(
      includesSequence(boundaryArguments, [
        "--bind",
        "/tmp/claude",
        "/tmp/claude",
      ]),
      false,
    );
    assert.equal(
      includesSequence(boundaryArguments, [
        "--tmpfs",
        join(workspaceDirectory, ".claude"),
        "--remount-ro",
        join(workspaceDirectory, ".claude"),
      ]),
      access === "workspace-write",
    );
    assert.deepEqual(boundaryArguments.slice(commandIndex + 1, -1), [
      "/bin/sh",
      "-c",
    ]);
    assert.equal(boundaryArguments.at(-1), argumentsList.at(-1));
    assert.equal(
      boundaryArguments.filter(
        (argument) => argument === join(fakeBubblewrap.directory, "bwrap"),
      ).length,
      0,
    );
    assert.equal(call.commandLauncherDirectoryMode, 0o500);
    assert.equal(call.commandLauncherFileMode, 0o500);
    assert.equal(
      argumentsList.some(
        (argument) =>
          typeof argument === "string" && argument.includes("apply-seccomp"),
      ),
      false,
    );
    const [commandProbe] = isolationProbeScripts(argumentsList);
    assertReadOnlyInspectionProbe(commandProbe);
    assert.match(commandProbe, /readFileSync/u);
    assert.match(commandProbe, /join\("\/proc", providerPid, "environ"\)/u);
    assert.match(
      commandProbe,
      /readFileSync\([^;]+\);\n  process\.exit\(18\)/u,
    );
    assert.match(commandProbe, /AGENT_RUNNER_CLAUDE_PROBE_CREDENTIAL/u);
    assert.match(commandProbe, /statSync\("\.claude"\)\.isDirectory/u);
    assert.match(commandProbe, /\.claude\/mask-probe/u);
    assert.match(commandProbe, /statSync\(socketPath\)\.isSocket/u);
    assert.match(
      commandProbe,
      /finish\("pathname", code, new Set\(\["EACCES", "EPERM"\]\)\)/u,
    );
    assert.match(commandProbe, /String\.fromCharCode\(0\)/u);
    assert.match(commandProbe, /"EACCES", "ECONNREFUSED", "ENOENT", "EPERM"/u);
    assert.match(
      commandProbe,
      /write\("\/tmp\/agent-runner-claude-probe", true\)/u,
    );
    assert.match(
      commandProbe,
      /write\("\/run\/agent-runner-claude-probe", true\)/u,
    );
    assert.match(commandProbe, /AGENT_RUNNER_CLAUDE_COMMAND_LAUNCHER_TOKEN/u);
    assert.match(commandProbe, /process\.env\.ARGV0/u);
  }

  await fixture.adapter.run(request({ cwd: projectPath }));
  await fixture.adapter.run(
    request({ cwd: projectPath, access: "workspace-write" }),
  );
  await fixture.adapter.run(
    request({
      cwd: projectPath,
      access: "local-commit",
      authorizationId: "restricted-host-commit",
      commit: {
        expectedHead: EXPECTED_HEAD,
        message: "test(claude): prove restricted host commit",
      },
    }),
  );

  const turns = turnCalls(fixture);
  assert.equal(turns.length, 3);
  const turn = turns[0];
  assert.equal(turn.file, "claude");
  const exercisedBoundaries = (await readFile(fakeBubblewrap.logPath, "utf8"))
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  assert.equal(exercisedBoundaries.length, 6);
  for (const [index, call] of turns.entries()) {
    const settings = JSON.parse(option(call.argumentsList, "--settings"));
    const sandbox = settings.sandbox;
    const managedSettings = JSON.parse(
      option(call.argumentsList, "--managed-settings"),
    );
    const boundaryArguments = exercisedBoundaries[index + 3];
    const commandIndex = boundaryArguments.indexOf("--");
    assert.equal(call.file, "claude");
    assert.equal(call.options.env.ANTHROPIC_API_KEY, "provider-token");
    assert.equal(call.options.env.ARGV0, undefined);
    assert.equal(call.options.env.HTTPS_PROXY, "http://credential.invalid");
    assert.equal(call.options.env.PATH, providerPath);
    assert.equal(
      typeof call.options.env.AGENT_RUNNER_CLAUDE_COMMAND_LAUNCHER_TOKEN,
      "string",
    );
    assert.notEqual(
      call.options.env.AGENT_RUNNER_CLAUDE_COMMAND_LAUNCHER_TOKEN,
      "inherited-launcher-token",
    );
    assert.equal(sandbox.bwrapPath, undefined);
    assert.deepEqual(managedSettings, {
      sandbox: { bwrapPath: call.commandLauncherPath },
    });
    assert.equal(parse(call.commandLauncherPath).base, "bwrap");
    assert.equal(call.commandLauncherDirectoryMode, 0o700);
    assert.equal(call.commandLauncherFileMode, 0o500);
    assert.equal(sandbox.enableWeakerNestedSandbox, true);
    assert.equal(sandbox.network.allowAllUnixSockets, true);
    assert.deepEqual(sandbox.network.deniedDomains, ["*"]);
    assert.deepEqual(
      sandbox.credentials.envVars.find(
        ({ name }) => name === "ANTHROPIC_API_KEY",
      ),
      { mode: "deny", name: "ANTHROPIC_API_KEY" },
    );
    assert.deepEqual(
      sandbox.credentials.envVars.find(({ name }) => name === "HTTPS_PROXY"),
      { mode: "deny", name: "HTTPS_PROXY" },
    );
    assert.equal(
      sandbox.credentials.envVars.some(
        ({ name }) => name === "AGENT_RUNNER_CLAUDE_COMMAND_LAUNCHER_TOKEN",
      ),
      false,
    );
    assert.equal(
      boundaryArguments.filter((argument) => argument === "--unshare-user")
        .length,
      1,
    );
    assert.ok(boundaryArguments.includes("--unshare-pid"));
    assert.ok(boundaryArguments.includes("--unshare-net"));
    assert.ok(includesSequence(boundaryArguments, ["--proc", "/proc"]));
    assert.ok(includesSequence(boundaryArguments, ["--seccomp", "3"]));
    assert.ok(includesSequence(boundaryArguments, ["--tmpfs", "/tmp"]));
    assert.ok(includesSequence(boundaryArguments, ["--dir", "/tmp/claude"]));
    assert.ok(includesSequence(boundaryArguments, ["--tmpfs", "/run"]));
    assert.ok(includesSequence(boundaryArguments, ["--ro-bind", "/", "/"]));
    assert.ok(
      includesSequence(boundaryArguments, [
        "--unsetenv",
        "AGENT_RUNNER_CLAUDE_COMMAND_LAUNCHER_TOKEN",
      ]),
    );
    assert.ok(includesSequence(boundaryArguments, ["--unsetenv", "ARGV0"]));
    assert.ok(
      includesSequence(boundaryArguments, ["--unsetenv", "ANTHROPIC_API_KEY"]),
    );
    assert.ok(
      includesSequence(boundaryArguments, ["--unsetenv", "HTTPS_PROXY"]),
    );
    assert.ok(
      includesSequence(boundaryArguments, [
        index === 1 ? "--bind" : "--ro-bind",
        projectPath,
        projectPath,
      ]),
    );
    assert.ok(
      includesSequence(boundaryArguments, [
        "--ro-bind",
        `${projectPath}/.git`,
        `${projectPath}/.git`,
      ]),
    );
    assert.equal(
      includesSequence(boundaryArguments, [
        "--ro-bind",
        `${projectPath}/.git/config`,
        `${projectPath}/.git/config`,
      ]),
      false,
    );
    assert.equal(
      includesSequence(boundaryArguments, [
        "--ro-bind",
        "/dev/null",
        `${projectPath}/.mcp.json`,
      ]),
      false,
    );
    assert.equal(
      includesSequence(boundaryArguments, [
        "--ro-bind",
        `${projectPath}/package.json`,
        `${projectPath}/package.json`,
      ]),
      index === 1,
    );
    assert.equal(
      includesSequence(boundaryArguments, [
        "--ro-bind",
        emptyMaskPath,
        `${projectPath}/.claude`,
      ]),
      false,
    );
    assert.equal(
      includesSequence(boundaryArguments, [
        "--tmpfs",
        `${projectPath}/.claude`,
        "--remount-ro",
        `${projectPath}/.claude`,
      ]),
      index === 1,
    );
    assert.equal(
      includesSequence(boundaryArguments, [
        "--bind",
        CLAUDE_LOG_PATH,
        CLAUDE_LOG_PATH,
      ]),
      false,
    );
    assert.deepEqual(boundaryArguments.slice(commandIndex + 1), [
      "/bin/sh",
      "-c",
      `model-command ${index}`,
    ]);
  }
  const settings = JSON.parse(option(turn.argumentsList, "--settings"));
  assert.equal(settings.sandbox.enableWeakerNestedSandbox, true);
  assert.equal(settings.sandbox.failIfUnavailable, true);
  assert.equal(settings.sandbox.network.allowAllUnixSockets, true);
  assert.deepEqual(settings.sandbox.network.deniedDomains, ["*"]);
  assert.ok(
    turns.every(
      ({ argumentsList }) =>
        option(argumentsList, "--permission-mode") === "auto",
    ),
  );
  const filters = (await readFile(fakeBubblewrap.filterLogPath, "utf8"))
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  assert.equal(filters.length, 6);
  for (const filter of filters) {
    assert.equal(filter.descriptor, "3");
    assert.equal(filter.mode, 0o400);
    assert.equal(filter.nlink, 0);
    assert.equal(filter.writeError, "EBADF");
  }
  await assert.rejects(readFile(fakeBubblewrap.helperLogPath), {
    code: "ENOENT",
  });
});

test("serializes every supported fallback seccomp instruction", async (t) => {
  const fakeBubblewrap = await createFakeBubblewrap(t);
  for (const architecture of ["x64", "arm64"]) {
    const fixture = createFixture({
      architecture,
      env: {
        ...process.env,
        AGENT_RUNNER_FAKE_BWRAP_LOG: fakeBubblewrap.logPath,
        PATH: `${fakeBubblewrap.directory}${delimiter}${process.env.PATH ?? ""}`,
      },
      executeFallbackLauncher: true,
      nativeSandbox: "nested-denied",
    });
    const capabilities = await fixture.adapter.probe();
    assert.equal(
      capabilities.policyReceipt.fingerprint,
      policyFingerprint(
        "claude-command-boundary-v8",
        {
          "read-only": "runner-boundary",
          "workspace-write": "runner-boundary",
          "local-commit": "runner-boundary",
        },
        capabilities.version,
        architecture,
      ),
    );
  }
  const filters = (await readFile(fakeBubblewrap.filterLogPath, "utf8"))
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  assert.equal(filters.length, 6);
  for (const [index, filter] of filters.entries()) {
    const architecture = index < 3 ? "x64" : "arm64";
    assert.deepEqual(
      Buffer.from(filter.base64, "base64"),
      expectedSeccompFilter(architecture),
    );
  }
});

test("fails closed before bubblewrap when the direct filter is tampered", async (t) => {
  const fakeBubblewrap = await createFakeBubblewrap(t);
  const fixture = createFixture({
    architecture: "x64",
    env: {
      ...process.env,
      AGENT_RUNNER_FAKE_BWRAP_LOG: fakeBubblewrap.logPath,
      PATH: `${fakeBubblewrap.directory}${delimiter}${process.env.PATH ?? ""}`,
    },
    handle: async ({ call }) => {
      if (!isRunnerBoundaryProbe(call)) return;
      const launcherDirectory = parse(call.file).dir;
      await chmod(launcherDirectory, 0o700);
      await chmod(call.file, 0o700);
      const source = await readFile(call.file, "utf8");
      const changed = source.replace(
        "    fsyncSync(writeDescriptor);\n",
        "    writeSync(writeDescriptor, Buffer.from([expectedFilter[0] ^ 0xff]), 0, 1, 0);\n" +
          "    fsyncSync(writeDescriptor);\n",
      );
      assert.notEqual(changed, source);
      await writeFile(call.file, changed);
      await chmod(call.file, 0o500);
      await chmod(launcherDirectory, 0o500);
      return executeFile(call.file, call.argumentsList, {
        ...call.options,
        env: { ...call.options.env, PATH: "" },
      });
    },
    nativeSandbox: "nested-denied",
  });

  const capabilities = await fixture.adapter.probe();
  assert.deepEqual(capabilities.policyReceipt.supportedAccess, []);
  await assert.rejects(readFile(fakeBubblewrap.logPath), { code: "ENOENT" });
});

test("fails closed when bubblewrap rejects direct seccomp setup", async (t) => {
  const fakeBubblewrap = await createFakeBubblewrap(t);
  const fixture = createFixture({
    architecture: "x64",
    env: {
      ...process.env,
      AGENT_RUNNER_FAKE_BWRAP_LOG: fakeBubblewrap.logPath,
      AGENT_RUNNER_FAKE_BWRAP_REJECT_SECCOMP: "1",
      PATH: `${fakeBubblewrap.directory}${delimiter}${process.env.PATH ?? ""}`,
    },
    executeFallbackLauncher: true,
    nativeSandbox: "nested-denied",
  });

  const capabilities = await fixture.adapter.probe();
  assert.deepEqual(capabilities.policyReceipt.supportedAccess, []);
  const invocations = (await readFile(fakeBubblewrap.logPath, "utf8"))
    .trim()
    .split("\n");
  assert.equal(invocations.length, 3);
});

test("rejects unauthenticated and invalid fallback arguments before execution", async (t) => {
  const projectPath = await createFallbackProject(t);
  const fakeBubblewrap = await createFakeBubblewrap(t);
  const emptyMaskPath = await mkdtemp(join(tmpdir(), "claude-empty-"));
  await chmod(emptyMaskPath, 0o700);
  const markerDirectory = await mkdtemp(
    join(tmpdir(), "agent-runner-claude-rejected-command-"),
  );
  t.after(() => rm(emptyMaskPath, { force: true, recursive: true }));
  t.after(() => rm(markerDirectory, { force: true, recursive: true }));
  const cases = [
    {
      name: "unauthenticated",
      transform({ environment }) {
        delete environment[COMMAND_LAUNCHER_TOKEN];
      },
    },
    {
      access: "workspace-write",
      name: "relative-optional-mask",
      transform({ argumentsList }) {
        argumentsList.splice(
          argumentsList.indexOf("--dev"),
          0,
          "--ro-bind",
          "/dev/null",
          ".mcp.json",
        );
      },
    },
    {
      access: "workspace-write",
      name: "unknown-absent-mask",
      transform({ argumentsList }) {
        argumentsList.splice(
          argumentsList.indexOf("--dev"),
          0,
          "--ro-bind",
          "/dev/null",
          `${PROJECT_PATH}/unknown-optional-mask`,
        );
      },
    },
    {
      name: "writable-root",
      transform({ argumentsList }) {
        argumentsList[argumentsList.indexOf("--ro-bind")] = "--bind";
      },
    },
    {
      name: "conflicting-environment",
      transform({ argumentsList }) {
        argumentsList.splice(4, 0, "--unsetenv", "ANTHROPIC_API_KEY");
      },
    },
    {
      name: "protected-environment-assignment",
      transform({ argumentsList }) {
        argumentsList[2] = "--setenv";
        argumentsList.splice(4, 0, "restored-provider-token");
      },
    },
    {
      name: "native-seccomp-dispatch",
      transform({ argumentsList }) {
        argumentsList.splice(2, 0, "--setenv", "ARGV0", "apply-seccomp");
      },
    },
    {
      name: "unsupported-option",
      transform({ argumentsList }) {
        argumentsList[argumentsList.indexOf("--unshare-net")] = "--share-net";
      },
    },
    {
      name: "missing-user-namespace",
      transform({ argumentsList }) {
        argumentsList.splice(argumentsList.indexOf("--unshare-user"), 1);
      },
    },
    {
      name: "malformed-user-namespace",
      transform({ argumentsList }) {
        argumentsList[argumentsList.indexOf("--unshare-user")] =
          "--unshare-uts";
      },
    },
    {
      name: "duplicate-user-namespace",
      transform({ argumentsList }) {
        const index = argumentsList.indexOf("--unshare-user");
        argumentsList.splice(index, 0, "--unshare-user");
      },
    },
    {
      access: "workspace-write",
      name: "conflicting-workspace-access",
      transform({ argumentsList }) {
        const workspaceParent = parse(projectPath).dir;
        argumentsList.splice(
          argumentsList.indexOf("--dev"),
          0,
          "--ro-bind",
          workspaceParent,
          workspaceParent,
        );
      },
    },
    {
      access: "workspace-write",
      name: "unexpected-outside-write",
      transform({ argumentsList }) {
        const workspaceParent = parse(projectPath).dir;
        argumentsList.splice(
          argumentsList.indexOf("--dev"),
          0,
          "--bind",
          workspaceParent,
          workspaceParent,
        );
      },
    },
    {
      access: "workspace-write",
      name: "weakened-workspace-mask",
      transform({ argumentsList }) {
        const maskedPath = `${projectPath}/package.json`;
        argumentsList.splice(
          argumentsList.indexOf("--dev"),
          0,
          "--bind",
          maskedPath,
          maskedPath,
        );
      },
    },
    {
      access: "workspace-write",
      name: "reexposed-private-mask",
      transform({ argumentsList }) {
        const maskedPath = `${projectPath}/.claude`;
        argumentsList.splice(
          argumentsList.indexOf("--dev"),
          0,
          "--ro-bind",
          "/dev/null",
          maskedPath,
        );
      },
    },
    {
      access: "workspace-write",
      name: "reexposed-file-mask",
      transform({ argumentsList }) {
        const maskedPath = `${projectPath}/README.md`;
        argumentsList.splice(
          argumentsList.indexOf("--dev"),
          0,
          "--ro-bind",
          "/dev/null",
          maskedPath,
          "--ro-bind",
          maskedPath,
          maskedPath,
        );
      },
    },
    {
      access: "workspace-write",
      name: "directory-mask-on-file",
      transform({ argumentsList }) {
        const sourceIndex = argumentsList.indexOf(emptyMaskPath);
        argumentsList[sourceIndex + 1] = `${projectPath}/package.json`;
      },
    },
    {
      name: "private-runtime-rebind",
      transform({ argumentsList }) {
        argumentsList.splice(
          argumentsList.indexOf("--dev"),
          0,
          "--ro-bind",
          "/run",
          "/run",
        );
      },
    },
    {
      name: "private-process-rebind",
      transform({ argumentsList }) {
        argumentsList.splice(
          argumentsList.indexOf("--dev"),
          0,
          "--ro-bind",
          "/proc/self",
          "/proc/self",
        );
      },
    },
    {
      name: "relocated-read-only-bind",
      transform({ argumentsList }) {
        argumentsList.splice(
          argumentsList.indexOf("--dev"),
          0,
          "--ro-bind",
          "/etc",
          projectPath,
        );
      },
    },
    {
      name: "unsupported-tmpfs",
      transform({ argumentsList }) {
        argumentsList.splice(
          argumentsList.indexOf("--dev"),
          0,
          "--tmpfs",
          "/var",
        );
      },
    },
    {
      name: "extra-payload-argument",
      transform({ argumentsList }) {
        argumentsList.push("unsupported");
      },
    },
  ];
  let caseIndex = 0;
  const fixture = createFixture({
    env: {
      ...process.env,
      AGENT_RUNNER_FAKE_BWRAP_LOG: fakeBubblewrap.logPath,
      ANTHROPIC_API_KEY: "provider-token",
      PATH: `${fakeBubblewrap.directory}${delimiter}${process.env.PATH ?? ""}`,
    },
    executeFallbackLauncher: true,
    handle: async ({ call }) => {
      if (call.file !== "claude" || !call.argumentsList.includes("-p")) return;
      const current = cases[caseIndex];
      caseIndex += 1;
      const markerPath = join(markerDirectory, current.name);
      const managedSettings = JSON.parse(
        option(call.argumentsList, "--managed-settings"),
      );
      const argumentsList = claudeBubblewrapArguments({
        projectPath,
        access: current.access ?? "read-only",
        emptyMaskPath,
        payload: `printf executed > '${markerPath}'`,
      });
      const environment = {
        ...call.options.env,
        AGENT_RUNNER_FAKE_BWRAP_EXECUTE_PAYLOAD: "1",
      };
      current.transform({ argumentsList, environment });
      await executeFile(managedSettings.sandbox.bwrapPath, argumentsList, {
        encoding: "utf8",
        env: environment,
        timeout: 10_000,
      });
    },
    nativeSandbox: "nested-denied",
  });

  assert.equal((await fixture.adapter.probe()).readOnly, true);
  for (const current of cases) {
    await assert.rejects(
      fixture.adapter.run(
        request({ cwd: projectPath, access: current.access ?? "read-only" }),
      ),
      hasCode("ERR_CLAUDE_PROCESS_INTERRUPTED"),
    );
    await assert.rejects(readFile(join(markerDirectory, current.name)), {
      code: "ENOENT",
    });
  }
  const bubblewrapInvocations = (await readFile(fakeBubblewrap.logPath, "utf8"))
    .trim()
    .split("\n");
  assert.equal(bubblewrapInvocations.length, 3);
});

test("rejects unsupported fallback seccomp architectures", async (t) => {
  const fakeBubblewrap = await createFakeBubblewrap(t);
  const fixture = createFixture({
    architecture: "riscv64",
    env: {
      ...process.env,
      AGENT_RUNNER_FAKE_BWRAP_LOG: fakeBubblewrap.logPath,
      PATH: `${fakeBubblewrap.directory}${delimiter}${process.env.PATH ?? ""}`,
    },
    nativeSandbox: "nested-denied",
  });
  const capabilities = await fixture.adapter.probe();
  assert.deepEqual(capabilities.policyReceipt.supportedAccess, []);
  assert.equal(capabilities.readOnly, false);
  assert.equal(capabilities.workspaceWrite, false);
  assert.equal(capabilities.localCommit, false);
  assert.equal(
    fixture.calls.filter(
      (call) => isIsolationProbe(call) && !isNativeSandboxProbe(call),
    ).length,
    0,
  );
});

test("fails closed when the restricted-host fallback cannot be proved", async (t) => {
  const fakeBubblewrap = await createFakeBubblewrap(t);
  const fixture = createFixture({
    env: {
      ...process.env,
      PATH: `${fakeBubblewrap.directory}${delimiter}${process.env.PATH ?? ""}`,
    },
    nativeSandbox: "nested-denied",
    fallbackSandbox: false,
  });

  const capabilities = await fixture.adapter.probe();
  assert.deepEqual(capabilities.policyReceipt.supportedAccess, []);
  assert.equal(capabilities.readOnly, false);
  assert.equal(capabilities.workspaceWrite, false);
  assert.equal(capabilities.localCommit, false);
  await assert.rejects(fixture.adapter.run(request()), (error) => {
    assert.ok(hasCode("ERR_UNSUPPORTED_CLAUDE_CAPABILITY")(error));
    assert.doesNotMatch(error.message, /setgroups|CAP_SYS_ADMIN|host-secret/u);
    return true;
  });
  assert.equal(turnCalls(fixture).length, 0);
});

test("advertises restricted-host access modes only after their own proof", async (t) => {
  const fakeBubblewrap = await createFakeBubblewrap(t);
  const fixture = createFixture({
    env: {
      ...process.env,
      PATH: `${fakeBubblewrap.directory}${delimiter}${process.env.PATH ?? ""}`,
    },
    nativeSandbox: "nested-denied",
    fallbackSandbox: ["read-only", "local-commit"],
  });

  const capabilities = await fixture.adapter.probe();
  assert.deepEqual(capabilities.policyReceipt.supportedAccess, [
    "read-only",
    "local-commit",
  ]);
  assert.equal(capabilities.readOnly, true);
  assert.equal(capabilities.workspaceWrite, false);
  assert.equal(capabilities.localCommit, true);
  await assert.rejects(
    fixture.adapter.run(request({ access: "workspace-write" })),
    hasCode("ERR_UNSUPPORTED_CLAUDE_CAPABILITY"),
  );
  assert.equal(turnCalls(fixture).length, 0);
});

test("does not clear resource ownership when allocation intent is rejected", async () => {
  const fixture = createFixture();
  const records = [];
  await assert.rejects(
    fixture.adapter.run(
      request({
        onResource: async (value) => {
          records.push(value?.phase ?? "cleaned");
          throw new Error("another resource is retained");
        },
      }),
    ),
    { code: "ERR_AGENT_ENVIRONMENT_PREPARATION" },
  );
  assert.deepEqual(records, ["allocating"]);
  assert.equal(turnCalls(fixture).length, 0);
});

test("preserves resource ownership when cleanup acknowledgement fails", async () => {
  let resource;
  const fixture = createFixture();
  const onResource = async (value) => {
    if (value === null) throw new Error("private journal diagnostic");
    resource = value;
  };
  await assert.rejects(
    fixture.adapter.run(request({ access: "workspace-write", onResource })),
    (error) => {
      assert.equal(error.code, "ERR_EXECUTION_RESOURCE_UNVERIFIABLE");
      assert.equal(error.failure.failureClass, "environment_cleanup");
      assert.equal(error.failure.retry, "transient");
      assert.equal(error.cause, undefined);
      return true;
    },
  );
  assert.equal(resource.phase, "allocated");
  await recoverClaudeStorage({
    resource,
    storageForbiddenPaths: [PROJECT_PATH],
    onResource: async (value) => {
      resource = value;
    },
  });
  assert.equal(resource, null);
});

test("runs autonomous read-only turns with isolated tools and an explicit model", async () => {
  const fixture = createFixture({
    env: {
      ...process.env,
      ANTHROPIC_API_KEY: "provider-token",
      CLAUDE_CODE_SKIP_PROMPT_HISTORY: "1",
      CLAUDE_ENV_FILE: "/tmp/agent-env.sh",
      DISABLE_AUTO_COMPACT: "1",
      NODE_OPTIONS: "--require=/tmp/agent.cjs",
      OTEL_LOG_USER_PROMPTS: "1",
      EMAIL: "override@example.invalid",
      GIT_DIR: "/tmp/redirected.git",
    },
  });

  const response = await fixture.adapter.run(
    request({ model: "claude-test", schema: STRICT_SCHEMA }),
  );

  assert.deepEqual(response, {
    output: "done",
    structured: { ok: true },
    sessionId: FRESH_SESSION,
  });
  assert.ok(Object.isFrozen(response));
  assert.ok(Object.isFrozen(response.structured));
  const turn = turnCalls(fixture)[0];
  assert.equal(turn.file, "claude");
  assert.equal(turn.argumentsList[0], "-p");
  assert.equal(turn.options.input, "Inspect the repository.");
  assert.ok(!turn.argumentsList.includes("Inspect the repository."));
  assert.equal(option(turn.argumentsList, "--permission-mode"), "auto");
  assert.equal(option(turn.argumentsList, "--tools"), "Bash,Read,Glob,Grep");
  assert.equal(option(turn.argumentsList, "--model"), "claude-test");
  assert.equal(option(turn.argumentsList, "--prompt-suggestions"), "false");
  assert.deepEqual(
    JSON.parse(option(turn.argumentsList, "--json-schema")),
    STRICT_SCHEMA,
  );
  assert.equal(option(turn.argumentsList, "--autocompact"), undefined);
  for (const required of [
    "--no-chrome",
    "--safe-mode",
    "--strict-mcp-config",
  ]) {
    assert.ok(turn.argumentsList.includes(required));
  }
  assert.ok(!turn.argumentsList.includes("--dangerously-skip-permissions"));
  assert.ok(!turn.argumentsList.includes("--fallback-model"));
  const settings = JSON.parse(option(turn.argumentsList, "--settings"));
  assert.equal(settings.disableBypassPermissionsMode, "disable");
  assert.deepEqual(settings.fallbackModel, []);
  assert.deepEqual(settings.attribution, {
    commit: "",
    pr: "",
    sessionUrl: false,
  });
  assert.equal(settings.sandbox.enabled, true);
  assert.equal(settings.sandbox.bwrapPath, undefined);
  assert.equal(
    JSON.parse(option(turn.argumentsList, "--managed-settings")).sandbox
      .bwrapPath,
    turn.commandLauncherPath,
  );
  assert.equal(settings.sandbox.failIfUnavailable, true);
  assert.equal(settings.sandbox.autoAllowBashIfSandboxed, true);
  assert.equal(settings.sandbox.allowUnsandboxedCommands, false);
  assert.equal(settings.sandbox.enableWeakerNestedSandbox, false);
  assert.equal(settings.sandbox.filesystem.disabled, false);
  assert.deepEqual(
    settings.sandbox.credentials.envVars.find(
      ({ name }) => name === "ANTHROPIC_API_KEY",
    ),
    { mode: "deny", name: "ANTHROPIC_API_KEY" },
  );
  assert.deepEqual(settings.permissions.deny, COMMON_DENY_POLICY);
  assert.ok(
    settings.permissions.deny.every((entry) => !entry.startsWith("Bash(")),
  );
  assert.deepEqual(settings.sandbox.network.deniedDomains, ["*"]);
  assert.equal(settings.sandbox.network.strictAllowlist, true);
  assert.ok(settings.sandbox.filesystem.denyWrite.includes(PROJECT_PATH));
  assert.ok(
    settings.sandbox.filesystem.denyWrite.includes(`${PROJECT_PATH}/.git`),
  );
  assert.equal(turn.options.env.ANTHROPIC_API_KEY, "provider-token");
  assert.equal(turn.options.env.CLAUDE_CODE_SKIP_PROMPT_HISTORY, undefined);
  assert.equal(turn.options.env.DISABLE_AUTO_COMPACT, undefined);
  assert.equal(turn.options.env.CLAUDE_AGENT_SDK_DISABLE_BUILTIN_AGENTS, "1");
  assert.equal(turn.options.env.CLAUDE_CODE_AUTO_CONNECT_IDE, "false");
  assert.equal(turn.options.env.CLAUDE_CODE_SUBPROCESS_ENV_SCRUB, "0");
  assert.equal(turn.options.env.CLAUDE_ENV_FILE, undefined);
  assert.equal(turn.options.env.EMAIL, undefined);
  assert.equal(turn.options.env.GIT_DIR, undefined);
  assert.equal(turn.options.env.NODE_OPTIONS, undefined);
  assert.equal(turn.options.env.OTEL_LOG_USER_PROMPTS, undefined);
});

test("applies isolated profile and context selections to Claude", async () => {
  const fixture = createFixture({
    env: {
      ...process.env,
      CLAUDE_CONFIG_DIR: "/profiles/current",
    },
  });
  const execution = {
    profile: "/profiles/work",
    model: "claude-test",
    contextSize: "200000",
  };

  const capabilities = await fixture.adapter.probe(execution);
  await fixture.adapter.run(request(execution));

  assert.strictEqual(await fixture.adapter.probe(execution), capabilities);
  const claudeCalls = fixture.calls.filter(({ file }) => file === "claude");
  assert.equal(claudeCalls.length, 4);
  for (const call of claudeCalls.slice(0, 2)) {
    assert.equal(call.options.env.CLAUDE_CONFIG_DIR, "/profiles/current");
  }
  const turn = turnCalls(fixture)[0];
  assert.equal(turn.options.env.CLAUDE_CONFIG_DIR, "/profiles/work");
  assert.equal(option(turn.argumentsList, "--model"), "claude-test");
  assert.equal(option(turn.argumentsList, "--autocompact"), "200000");
});

test("omits current Claude execution overrides", async () => {
  const fixture = createFixture({
    env: {
      ...process.env,
      CLAUDE_CONFIG_DIR: "/profiles/process-default",
    },
  });

  await fixture.adapter.run(
    request({
      profile: "current",
      model: "current",
      contextSize: "current",
      effort: "current",
    }),
  );

  const turn = turnCalls(fixture)[0];
  assert.equal(option(turn.argumentsList, "--model"), undefined);
  assert.equal(option(turn.argumentsList, "--autocompact"), undefined);
  assert.equal(option(turn.argumentsList, "--effort"), undefined);
  assert.equal(turn.options.env.CLAUDE_CONFIG_DIR, "/profiles/process-default");
});

test("rejects invalid Claude profiles and context sizes", async () => {
  const fixture = createFixture();

  for (const execution of [
    { profile: "relative-profile" },
    { profile: "/" },
    { profile: "/profiles/../work" },
    { contextSize: "99999" },
    { contextSize: "1000001" },
    { contextSize: "0200000" },
    { contextSize: "200k" },
    { model: "--model" },
  ]) {
    assert.throws(
      () => fixture.adapter.probe(execution),
      hasCode("ERR_INVALID_CLAUDE_OPTIONS"),
    );
    await assert.rejects(
      fixture.adapter.run(request(execution)),
      hasCode("ERR_INVALID_CLAUDE_OPTIONS"),
    );
  }
  assert.throws(
    () =>
      fixture.adapter.probe({
        env: { CLAUDE_CONFIG_DIR: "/profiles/work" },
      }),
    hasCode("ERR_INVALID_CLAUDE_OPTIONS"),
  );
  assert.equal(fixture.calls.length, 0);
});

test("keeps autonomous workspace policy unchanged", async () => {
  const fixture = createFixture();

  await fixture.adapter.run(request({ access: "workspace-write" }));

  const turn = turnCalls(fixture)[0];
  assert.equal(option(turn.argumentsList, "--permission-mode"), "auto");
  assert.equal(
    option(turn.argumentsList, "--tools"),
    "Bash,Read,Edit,Write,Glob,Grep",
  );
  const settings = JSON.parse(option(turn.argumentsList, "--settings"));
  assert.equal(settings.sandbox.autoAllowBashIfSandboxed, false);
  assert.ok(settings.sandbox.filesystem.denyWrite.includes(PROJECT_PATH));
  assert.ok(
    settings.sandbox.filesystem.denyWrite.includes(`${PROJECT_PATH}/.git`),
  );
  assert.deepEqual(settings.permissions.deny, WORKSPACE_DENY_POLICY);
});

test("passes option-like prompts through stdin", async () => {
  const fixture = createFixture();

  await fixture.adapter.run(request({ prompt: "--inspect-the-repository" }));

  const turn = turnCalls(fixture)[0];
  assert.equal(turn.options.input, "--inspect-the-repository");
  assert.ok(!turn.argumentsList.includes("--inspect-the-repository"));
});

test("validates requests, strict schemas, and structured results", async () => {
  const fixture = createFixture();
  await assert.rejects(
    fixture.adapter.run(request({ extra: true })),
    hasCode("ERR_INVALID_CLAUDE_OPTIONS"),
  );
  await assert.rejects(
    fixture.adapter.run(request({ cwd: parse(PROJECT_PATH).root })),
    hasCode("ERR_INVALID_CLAUDE_OPTIONS"),
  );
  await assert.rejects(
    fixture.adapter.run(
      request({ session: { id: "--continue", mode: "continue" } }),
    ),
    hasCode("ERR_INVALID_CLAUDE_OPTIONS"),
  );
  await assert.rejects(
    fixture.adapter.run(request({ model: "--model" })),
    hasCode("ERR_INVALID_CLAUDE_OPTIONS"),
  );
  await assert.rejects(
    fixture.adapter.run(
      request({
        schema: {
          type: "object",
          properties: {
            value: { type: "string", description: "x".repeat(128 * 1024) },
          },
          required: ["value"],
          additionalProperties: false,
        },
      }),
    ),
    hasCode("ERR_INVALID_CLAUDE_OPTIONS"),
  );
  await assert.rejects(
    fixture.adapter.run(
      request({
        schema: {
          type: "object",
          properties: { ok: { type: "boolean" } },
          required: [],
        },
      }),
    ),
    hasCode("ERR_INVALID_CLAUDE_SCHEMA"),
  );
  const invalidOutput = createFixture({
    handle({ call }) {
      if (call.file === "claude" && call.argumentsList.includes("-p")) {
        return {
          stdout: JSON.stringify(result({ structured: [true] })),
          stderr: "",
        };
      }
      return undefined;
    },
  });
  await assert.rejects(
    invalidOutput.adapter.run(request({ schema: STRICT_SCHEMA })),
    hasFailureClass(
      "ERR_CLAUDE_STRUCTURED_OUTPUT",
      STRUCTURED_OUTPUT_FAILURE_CLASS,
    ),
  );

  for (const payload of [
    result({ subtype: "error_during_execution" }),
    result({ permission_denials: "invalid" }),
    result({ sessionId: "invalid-session" }),
  ]) {
    const invalidProtocol = createFixture({
      handle({ call }) {
        if (call.file === "claude" && call.argumentsList.includes("-p")) {
          return { stdout: JSON.stringify(payload), stderr: "" };
        }
        return undefined;
      },
    });
    await assert.rejects(
      invalidProtocol.adapter.run(request()),
      hasCode("ERR_CLAUDE_TURN_FAILED"),
    );
  }

  const nullableOutput = createFixture({
    handle({ call }) {
      if (call.file === "claude" && call.argumentsList.includes("-p")) {
        return {
          stdout: JSON.stringify(
            result({
              output: null,
              permission_denials: null,
              structured: { ok: true },
            }),
          ),
          stderr: "",
        };
      }
      return undefined;
    },
  });
  assert.equal(
    (await nullableOutput.adapter.run(request({ schema: STRICT_SCHEMA })))
      .output,
    '{"ok":true}',
  );
});

test("rejects permission fallback and explicit model rerouting", async (t) => {
  const denied = createFixture({
    handle({ call }) {
      if (call.file === "claude" && call.argumentsList.includes("-p")) {
        return {
          stdout: JSON.stringify(
            result({
              permission_denials: [
                {
                  tool_input: { file_path: "source.js" },
                  tool_name: "Edit",
                },
              ],
            }),
          ),
          stderr: "",
        };
      }
      return undefined;
    },
  });
  await assert.rejects(
    denied.adapter.run(request({ access: "workspace-write" })),
    (error) =>
      hasDiagnostic(
        "ERR_CLAUDE_PERMISSION_DENIED",
        "permission_capability",
      )(error) && error.recoverable === true,
  );

  const safeInspection = createFixture({
    handle({ call }) {
      if (call.file === "claude" && call.argumentsList.includes("-p")) {
        return {
          stdout: JSON.stringify(
            result({
              permission_denials: [
                {
                  tool_input: { command: "git status --short" },
                  tool_name: "Bash",
                },
              ],
            }),
          ),
          stderr: "",
        };
      }
      return undefined;
    },
  });
  await assert.rejects(
    safeInspection.adapter.run(request()),
    (error) =>
      hasDiagnostic(
        "ERR_CLAUDE_PERMISSION_DENIED",
        "permission_capability",
      )(error) && error.recoverable === true,
  );

  for (const forbiddenCommand of [
    "git branch release",
    "git clean -fd",
    "git tag release",
    "git add source.js",
    "git restore source.js",
    "command git commit -m provider-secret-value",
    "env git push origin HEAD",
    "sh -c 'git remote set-url origin forbidden'",
    "/usr/bin/git -C . tag release",
    "curl https://provider-secret-value.invalid",
  ]) {
    await t.test(`fails closed for ${forbiddenCommand}`, async () => {
      const forbidden = createFixture({
        handle({ call }) {
          if (call.file === "claude" && call.argumentsList.includes("-p")) {
            return {
              stdout: JSON.stringify(
                result({
                  permission_denials: [
                    {
                      tool_input: { command: forbiddenCommand },
                      tool_name: "Bash",
                    },
                  ],
                }),
              ),
              stderr: "",
            };
          }
          return undefined;
        },
      });
      await assert.rejects(forbidden.adapter.run(request()), (error) => {
        assert.ok(
          hasDiagnostic(
            "ERR_CLAUDE_PERMISSION_DENIED",
            "permission_forbidden_operation",
          )(error),
        );
        assert.equal(error.recoverable, false);
        assert.doesNotMatch(error.message, /provider-secret-value/u);
        assert.equal(error.cause, undefined);
        return true;
      });
    });
  }

  const rerouted = createFixture({
    handle({ call }) {
      if (call.file === "claude" && call.argumentsList.includes("-p")) {
        return {
          stdout: JSON.stringify(
            result({ modelUsage: { "claude-other": {} } }),
          ),
          stderr: "",
        };
      }
      return undefined;
    },
  });
  await assert.rejects(
    rerouted.adapter.run(request({ model: "claude-exact" })),
    hasCode("ERR_CLAUDE_MODEL_REROUTED"),
  );

  const fallback = createFixture({
    handle({ call }) {
      if (call.file === "claude" && call.argumentsList.includes("-p")) {
        return {
          stdout: JSON.stringify(
            result({
              modelUsage: {
                "claude-exact": {},
                "claude-fallback": {},
              },
            }),
          ),
          stderr: "",
        };
      }
      return undefined;
    },
  });
  await assert.rejects(
    fallback.adapter.run(request({ model: "claude-exact" })),
    hasCode("ERR_CLAUDE_MODEL_REROUTED"),
  );

  const unavailableAuto = createFixture({
    handle({ call }) {
      if (call.file === "claude" && call.argumentsList.includes("-p")) {
        throw processFailure(
          result({ error: true, output: "Auto mode is unavailable." }),
        );
      }
      return undefined;
    },
  });
  await assert.rejects(
    unavailableAuto.adapter.run(request({ access: "workspace-write" })),
    (error) =>
      hasDiagnostic(
        "ERR_UNSUPPORTED_CLAUDE_CAPABILITY",
        "capability_unavailable",
      )(error) && error.recoverable === true,
  );
  assert.equal(turnCalls(unavailableAuto).length, 1);

  const manualFallback = createFixture({
    handle({ call }) {
      if (call.file === "claude" && call.argumentsList.includes("-p")) {
        return {
          stdout: JSON.stringify(result()),
          stderr: "Permission mode forced to default.",
        };
      }
      return undefined;
    },
  });
  await assert.rejects(
    manualFallback.adapter.run(request({ access: "workspace-write" })),
    (error) =>
      hasDiagnostic(
        "ERR_UNSUPPORTED_CLAUDE_CAPABILITY",
        "capability_unavailable",
      )(error) && error.recoverable === true,
  );
});

test("classifies explicit usage limits without retrying the rejected turn", async (t) => {
  for (const [message, exitsSuccessfully] of [
    ["Rate limit exceeded.", true],
    ["Your organization quota has been exhausted.", false],
    ["You have exceeded your quota.", false],
    ["Insufficient credits to complete this request.", false],
    ["Credits exhausted.", false],
    ["Monthly spend limit reached.", false],
    ["You've hit your limit · resets 3pm", false],
  ]) {
    await t.test(message, async () => {
      const fixture = createFixture({
        handle({ call }) {
          if (call.file === "claude" && call.argumentsList.includes("-p")) {
            const payload = result({
              error: true,
              output: message,
              sessionId: SOURCE_SESSION,
            });
            if (exitsSuccessfully) {
              return { stdout: JSON.stringify(payload), stderr: "" };
            }
            throw processFailure(payload);
          }
          return undefined;
        },
      });

      await assert.rejects(
        fixture.adapter.run(
          request({
            prompt: "Continue from the current session.",
            recoveryPrompt: "Inspect the complete durable request.",
            session: { id: SOURCE_SESSION, mode: "continue" },
          }),
        ),
        (error) =>
          hasCode("ERR_CLAUDE_USAGE_LIMIT")(error) &&
          error.recoverable === true &&
          error.ambiguous === false,
      );
      assert.equal(turnCalls(fixture).length, 1);
    });
  }
});

test("normalizes Claude availability while preserving rejection precedence and commit proof", async () => {
  let payload;
  const fixture = createFixture({
    handle({ call }) {
      if (call.file === "claude" && call.argumentsList.includes("-p")) {
        return { stdout: JSON.stringify(payload), stderr: "" };
      }
    },
  });
  for (const [message, fields, expected, expectedCode] of [
    ...[
      "network is offline",
      "EAI_AGAIN",
      "ENOTFOUND",
      "connection refused",
      "ECONNRESET",
      "request timed out",
    ].map((text) => [text, {}, "transport_unavailable"]),
    ["overloaded_error", {}, "temporarily_overloaded"],
    ["model is busy", {}, "model_busy"],
    ...[
      [408, "transport_unavailable"],
      [425, "server_unavailable"],
      [500, "server_unavailable"],
      [502, "server_unavailable"],
      [503, "server_unavailable"],
      [504, "transport_unavailable"],
      [529, "temporarily_overloaded"],
    ].map(([api_error_status, reason]) => [
      "native error",
      { api_error_status },
      reason,
    ]),
    ...[400, 401, 403, 429, 501, "503"].map((api_error_status) => [
      "ECONNRESET",
      { api_error_status },
      undefined,
    ]),
    ...[
      [503, "ERR_CLAUDE_USAGE_LIMIT"],
      [401, "ERR_CLAUDE_AUTHENTICATION_UNAVAILABLE"],
      [403, "ERR_CLAUDE_AUTHENTICATION_UNAVAILABLE"],
      [400, "ERR_CLAUDE_REQUEST_REJECTED"],
    ].map(([api_error_status, code]) => [
      "ENOTFOUND",
      { api_error_status, terminal_reason: "budget_exhausted" },
      undefined,
      code,
    ]),
    [
      "ENOTFOUND",
      {
        subtype: "error_max_structured_output_retries",
        terminal_reason: "budget_exhausted",
      },
      undefined,
      "ERR_CLAUDE_STRUCTURED_OUTPUT",
    ],
    ["ENOTFOUND", { terminal_reason: "api_error" }, undefined],
    ["model is busy; quota exhausted", {}, undefined],
    ["permission denied; connection reset", {}, undefined],
    ["refresh token expired; ECONNRESET", {}, undefined],
    ["refresh token expired", { api_error_status: 503 }, undefined],
    ...["not authenticated", "please log in"].map((message) => [
      `${message}; ECONNRESET`,
      { api_error_status: 503 },
      undefined,
    ]),
    ["rate_limit_error; ECONNRESET", { api_error_status: 503 }, undefined],
    ["ENOTFOUND" + "x".repeat(4_096), {}, undefined],
    ["unclassified failure", {}, undefined],
    [
      "model is busy",
      {
        permission_denials: [
          { tool_name: "Agent", tool_input: "DO_NOT_RETAIN" },
        ],
      },
      undefined,
    ],
  ]) {
    payload = result({
      error: true,
      output: `${message}: DO_NOT_RETAIN`,
      ...fields,
    });
    await assert.rejects(
      fixture.adapter.run(
        request({
          access: "local-commit",
          authorizationId: "availability-authorization",
          commit: {
            expectedHead: EXPECTED_HEAD,
            message: "fix(test): preserve readiness",
          },
        }),
      ),
      (error) => {
        const normalized = normalizeAdapterFailure("claude", error);
        assert.equal(normalized.failure.availabilityReason, expected, message);
        if (expectedCode !== undefined)
          assert.equal(normalized.code, expectedCode);
        assert.equal(normalized.effectStarted, false);
        assert.equal(normalized.failure.commitExecutor, "not_started");
        if (expected !== undefined) assert.equal(normalized.recoverable, true);
        assert.doesNotMatch(JSON.stringify(error), /DO_NOT_RETAIN/u);
        assert.doesNotMatch(JSON.stringify(normalized), /DO_NOT_RETAIN/u);
        return true;
      },
    );
  }
  assert.equal(
    fixture.calls.filter(
      ({ file, argumentsList }) =>
        file === "bwrap" && argumentsList.includes("git"),
    ).length,
    0,
  );
});

test("Claude availability diagnostics cannot hide interrupted effects", async () => {
  let payload;
  const fixture = createFixture({
    handle({ call }) {
      if (call.file === "claude" && call.argumentsList.includes("-p")) {
        throw Object.assign(
          processFailure(payload, "ECONNRESET DO_NOT_RETAIN"),
          { signal: "SIGKILL" },
        );
      }
    },
  });
  for (payload of [undefined, result({ error: true, output: "ECONNRESET" })]) {
    await assert.rejects(
      fixture.adapter.run(request({ access: "workspace-write" })),
      (error) => {
        const normalized = normalizeAdapterFailure("claude", error);
        assert.equal(normalized.ambiguous, true);
        assert.equal(normalized.recoverable, false);
        assert.equal(normalized.failure.availabilityReason, undefined);
        assert.doesNotMatch(JSON.stringify(normalized), /DO_NOT_RETAIN/u);
        return true;
      },
    );
  }
});

test("prefers structured Claude failure fields over native text", async (t) => {
  for (const { code, diagnosticClass, payload, recoverable } of [
    {
      code: "ERR_CLAUDE_USAGE_LIMIT",
      diagnosticClass: "usage_limit",
      payload: result({
        api_error_status: 429,
        error: true,
        output: "Authentication required: provider-secret-value.",
      }),
      recoverable: true,
    },
    {
      code: "ERR_CLAUDE_PROVIDER_UNAVAILABLE",
      diagnosticClass: "provider_unavailable",
      payload: result({
        api_error_status: 503,
        error: true,
        output: "provider-secret-value",
        terminal_reason: "api_error",
      }),
      recoverable: true,
    },
    {
      code: "ERR_CLAUDE_AUTHENTICATION_UNAVAILABLE",
      diagnosticClass: "authentication_unavailable",
      payload: result({
        api_error_status: 401,
        error: true,
        output: "provider-secret-value",
        terminal_reason: "api_error",
      }),
      recoverable: false,
    },
    {
      code: "ERR_CLAUDE_BACKEND_UNAVAILABLE",
      diagnosticClass: "backend_unavailable",
      payload: result({
        error: true,
        output: "provider-secret-value",
        terminal_reason: "turn_setup_failed",
      }),
      recoverable: true,
    },
  ]) {
    await t.test(code, async () => {
      const fixture = createFixture({
        handle({ call }) {
          if (call.file === "claude" && call.argumentsList.includes("-p")) {
            return { stdout: JSON.stringify(payload), stderr: "" };
          }
          return undefined;
        },
      });

      await assert.rejects(fixture.adapter.run(request()), (error) => {
        assert.ok(hasDiagnostic(code, diagnosticClass)(error));
        assert.equal(error.recoverable, recoverable);
        assert.doesNotMatch(error.message, /provider-secret-value/u);
        assert.equal(error.cause, undefined);
        return true;
      });
    });
  }
});

test("fails closed for non-transient structured Claude API errors", async (t) => {
  for (const status of [400, 404, 422, undefined]) {
    await t.test(
      status === undefined ? "missing status" : String(status),
      async () => {
        const payload = result({
          error: true,
          output: "Provider unavailable: provider-secret-value.",
          terminal_reason: "api_error",
          ...(status === undefined ? {} : { api_error_status: status }),
        });
        const fixture = createFixture({
          handle({ call }) {
            if (call.file === "claude" && call.argumentsList.includes("-p")) {
              return { stdout: JSON.stringify(payload), stderr: "" };
            }
            return undefined;
          },
        });

        await assert.rejects(fixture.adapter.run(request()), (error) => {
          assert.ok(hasCode("ERR_CLAUDE_REQUEST_REJECTED")(error));
          assert.equal(error.diagnosticClass, undefined);
          assert.equal(error.recoverable, false);
          assert.doesNotMatch(error.message, /provider-secret-value/u);
          assert.equal(error.cause, undefined);
          return true;
        });
      },
    );
  }
});

test("classifies bounded native error arrays without retaining them", async () => {
  const payload = result({ error: true });
  delete payload.result;
  payload.errors = ["API rate_limit_error provider-secret-value"];
  const fixture = createFixture({
    handle({ call }) {
      if (call.file === "claude" && call.argumentsList.includes("-p")) {
        throw processFailure(payload, "raw standard error secret");
      }
      return undefined;
    },
  });

  await assert.rejects(fixture.adapter.run(request()), (error) => {
    assert.ok(hasDiagnostic("ERR_CLAUDE_USAGE_LIMIT", "usage_limit")(error));
    assert.equal(error.recoverable, true);
    assert.doesNotMatch(error.message, /secret/u);
    assert.equal(error.cause, undefined);
    return true;
  });
});

test("maps native structured-output exhaustion to the shared failure class", async () => {
  const fixture = createFixture({
    handle({ call }) {
      if (call.file === "claude" && call.argumentsList.includes("-p")) {
        return {
          stdout: JSON.stringify(
            result({
              error: true,
              output: "provider-native structured output text",
              subtype: "error_max_structured_output_retries",
              terminal_reason: "structured_output_retry_exhausted",
            }),
          ),
          stderr: "",
        };
      }
      return undefined;
    },
  });

  await assert.rejects(
    fixture.adapter.run(request({ schema: STRICT_SCHEMA })),
    hasFailureClass(
      "ERR_CLAUDE_STRUCTURED_OUTPUT",
      STRUCTURED_OUTPUT_FAILURE_CLASS,
    ),
  );
});

test("retries only harmless unclassified read-only process failures", async () => {
  for (const [access, recoverable, diagnosticClass] of [
    ["read-only", true, "read_only_process_failed"],
    ["workspace-write", false, "writable_process_ambiguous"],
  ]) {
    const fixture = createFixture({
      handle({ call }) {
        if (call.file === "claude" && call.argumentsList.includes("-p")) {
          throw processFailure(undefined, "provider-native secret text");
        }
        return undefined;
      },
    });

    await assert.rejects(fixture.adapter.run(request({ access })), (error) => {
      assert.ok(hasCode("ERR_CLAUDE_PROCESS_INTERRUPTED")(error));
      assert.equal(error.diagnosticClass, diagnosticClass);
      assert.equal(error.recoverable, recoverable);
      assert.equal(error.ambiguous, access === "workspace-write");
      assert.doesNotMatch(error.message, /provider-native/u);
      assert.equal(error.cause, undefined);
      return true;
    });
  }
});

test("makes only unclassified read-only result failures resumable", async () => {
  for (const [access, code, recoverable, diagnosticClass] of [
    [
      "read-only",
      "ERR_CLAUDE_READ_ONLY_TURN_FAILED",
      true,
      "read_only_execution_failed",
    ],
    ["workspace-write", "ERR_CLAUDE_TURN_FAILED", false, undefined],
  ]) {
    const fixture = createFixture({
      handle({ call }) {
        if (call.file === "claude" && call.argumentsList.includes("-p")) {
          return {
            stdout: JSON.stringify(
              result({
                error: true,
                output: "unclassified provider-native secret text",
              }),
            ),
            stderr: "",
          };
        }
        return undefined;
      },
    });

    await assert.rejects(fixture.adapter.run(request({ access })), (error) => {
      assert.ok(hasCode(code)(error));
      assert.equal(error.recoverable, recoverable);
      assert.equal(error.diagnosticClass, diagnosticClass);
      assert.doesNotMatch(error.message, /provider-native/u);
      return true;
    });
  }
});

test("keeps a usage-rejected local commit unambiguous", async () => {
  const fixture = createFixture({
    handle({ call }) {
      if (call.file === "claude" && call.argumentsList.includes("-p")) {
        throw processFailure(
          result({ error: true, output: "API rate_limit_error" }),
        );
      }
      return undefined;
    },
  });

  await assert.rejects(
    fixture.adapter.run(
      request({
        access: "local-commit",
        authorizationId: "authorization-1",
        commit: {
          expectedHead: EXPECTED_HEAD,
          message: "test(scope): verify usage limit",
        },
      }),
    ),
    (error) =>
      hasCode("ERR_CLAUDE_USAGE_LIMIT")(error) &&
      error.recoverable === true &&
      error.ambiguous === false &&
      error.effectStarted === false,
  );
  assert.equal(turnCalls(fixture).length, 1);
  assert.equal(localCommitSandboxCalls(fixture).length, 1);
});

test("classifies fresh-turn profile, authentication, and provider failures", async (t) => {
  for (const {
    code,
    diagnosticClass,
    message,
    options = {},
    recoverable = true,
  } of [
    {
      code: "ERR_CLAUDE_PROFILE_UNAVAILABLE",
      diagnosticClass: "configuration_unavailable",
      message: "Session unavailable for the selected configuration.",
      options: { profile: "/profiles/work" },
    },
    {
      code: "ERR_CLAUDE_AUTHENTICATION_UNAVAILABLE",
      diagnosticClass: "authentication_unavailable",
      message: "Authentication required: API key secret-value is invalid.",
      recoverable: false,
    },
    {
      code: "ERR_CLAUDE_PROVIDER_UNAVAILABLE",
      diagnosticClass: "provider_unavailable",
      message: "Provider service unavailable.",
    },
    {
      code: "ERR_CLAUDE_PROVIDER_UNAVAILABLE",
      diagnosticClass: "provider_unavailable",
      message: "Session unavailable.",
    },
  ]) {
    await t.test(code, async () => {
      const fixture = createFixture({
        handle({ call }) {
          if (call.file === "claude" && call.argumentsList.includes("-p")) {
            throw processFailure(result({ error: true, output: message }));
          }
          return undefined;
        },
      });

      await assert.rejects(fixture.adapter.run(request(options)), (error) => {
        assert.ok(hasCode(code)(error));
        assert.equal(error.diagnosticClass, diagnosticClass);
        assert.equal(error.recoverable, recoverable);
        assert.doesNotMatch(error.message, /secret-value/u);
        assert.equal(error.cause, undefined);
        return true;
      });
      assert.equal(turnCalls(fixture).length, 1);

      const localCommitFixture = createFixture({
        handle({ call }) {
          if (call.file === "claude" && call.argumentsList.includes("-p")) {
            throw processFailure(result({ error: true, output: message }));
          }
          return undefined;
        },
      });
      await assert.rejects(
        localCommitFixture.adapter.run(
          request({
            ...options,
            access: "local-commit",
            authorizationId: "authorization-1",
            commit: {
              expectedHead: EXPECTED_HEAD,
              message: "test(scope): preserve classified failure",
            },
          }),
        ),
        (error) => {
          assert.ok(hasCode(code)(error));
          assert.equal(error.diagnosticClass, diagnosticClass);
          assert.equal(error.recoverable, recoverable);
          assert.equal(error.effectStarted, false);
          assert.doesNotMatch(error.message, /secret-value/u);
          return true;
        },
      );
      assert.equal(turnCalls(localCommitFixture).length, 1);
      assert.equal(localCommitSandboxCalls(localCommitFixture).length, 1);
    });
  }
});

test("continues sessions and reconstructs when continuation is unavailable", async () => {
  let attempts = 0;
  const fixture = createFixture({
    handle({ call }) {
      if (call.file !== "claude" || !call.argumentsList.includes("-p")) {
        return undefined;
      }
      attempts += 1;
      if (attempts === 1) {
        throw processFailure(
          undefined,
          `No conversation found with session ID: ${SOURCE_SESSION}`,
        );
      }
      return {
        stdout: JSON.stringify(result({ sessionId: FRESH_SESSION })),
        stderr: "",
      };
    },
  });

  const response = await fixture.adapter.run(
    request({
      prompt: "Continue from the current session.",
      recoveryPrompt: "Inspect the complete durable request.",
      session: { id: SOURCE_SESSION, mode: "continue" },
    }),
  );

  assert.equal(response.sessionId, FRESH_SESSION);
  const turns = turnCalls(fixture);
  assert.equal(option(turns[0].argumentsList, "--resume"), SOURCE_SESSION);
  assert.equal(turns[0].options.input, "Continue from the current session.");
  assert.equal(option(turns[1].argumentsList, "--resume"), undefined);
  assert.match(turns[1].options.input, /could not continue/u);
  assert.match(turns[1].options.input, /complete durable request/u);
  assert.doesNotMatch(turns[1].options.input, /current session/u);
});

test("forks a supplied source directly and preserves child lineage", async () => {
  const fixture = createFixture();

  const response = await fixture.adapter.run(
    request({ session: { id: SOURCE_SESSION, mode: "fork" } }),
  );

  assert.equal(response.sessionId, CHILD_SESSION);
  const turn = turnCalls(fixture)[0];
  assert.equal(option(turn.argumentsList, "--resume"), SOURCE_SESSION);
  assert.ok(turn.argumentsList.includes("--fork-session"));

  const invalid = createFixture({
    handle({ call }) {
      if (call.file === "claude" && call.argumentsList.includes("-p")) {
        return {
          stdout: JSON.stringify(result({ sessionId: SOURCE_SESSION })),
          stderr: "",
        };
      }
      return undefined;
    },
  });
  await assert.rejects(
    invalid.adapter.run(
      request({ session: { id: SOURCE_SESSION, mode: "fork" } }),
    ),
    hasCode("ERR_CLAUDE_PROTOCOL"),
  );
});

test("fails instead of replacing an unavailable fork source", async () => {
  const fixture = createFixture({
    handle({ call }) {
      if (call.file === "claude" && call.argumentsList.includes("-p")) {
        throw processFailure(
          undefined,
          `No conversation found with session ID: ${SOURCE_SESSION}`,
        );
      }
      return undefined;
    },
  });

  await assert.rejects(
    fixture.adapter.run(
      request({ session: { id: SOURCE_SESSION, mode: "fork" } }),
    ),
    (error) => {
      assert.ok(hasCode("ERR_CLAUDE_SOURCE_SESSION_UNAVAILABLE")(error));
      assert.equal(error.recoverable, false);
      assert.equal(error.cause, undefined);
      assert.ok(!error.message.includes(SOURCE_SESSION));
      return true;
    },
  );
  assert.equal(turnCalls(fixture).length, 1);
});

test("retries a compacted context and then reconstructs fresh", async () => {
  let attempts = 0;
  const fixture = createFixture({
    handle({ call }) {
      if (call.file !== "claude" || !call.argumentsList.includes("-p")) {
        return undefined;
      }
      attempts += 1;
      if (attempts < 3) {
        throw processFailure(
          result({
            error: true,
            output: "Context window exceeded.",
            sessionId: SOURCE_SESSION,
          }),
        );
      }
      return {
        stdout: JSON.stringify(result({ sessionId: FRESH_SESSION })),
        stderr: "",
      };
    },
  });

  const response = await fixture.adapter.run(
    request({
      prompt: "Continue from the current session.",
      recoveryPrompt: "Inspect the complete durable request.",
      session: { id: SOURCE_SESSION, mode: "continue" },
    }),
  );

  assert.equal(response.sessionId, FRESH_SESSION);
  const turns = turnCalls(fixture);
  assert.equal(option(turns[1].argumentsList, "--resume"), SOURCE_SESSION);
  assert.match(turns[1].options.input, /^Compact the existing/u);
  assert.match(turns[1].options.input, /complete durable request/u);
  assert.doesNotMatch(turns[1].options.input, /current session/u);
  assert.equal(option(turns[2].argumentsList, "--resume"), undefined);
  assert.match(turns[2].options.input, /^The previous Claude/u);
  assert.match(turns[2].options.input, /complete durable request/u);
  assert.doesNotMatch(turns[2].options.input, /current session/u);
});

test("never resumes an invalid session ID reported on failure", async () => {
  let attempts = 0;
  const fixture = createFixture({
    handle({ call }) {
      if (call.file !== "claude" || !call.argumentsList.includes("-p")) {
        return undefined;
      }
      attempts += 1;
      if (attempts === 1) {
        throw processFailure(
          result({
            error: true,
            output: "Context window exceeded.",
            sessionId: "--invalid-session",
          }),
        );
      }
      return {
        stdout: JSON.stringify(result({ sessionId: FRESH_SESSION })),
        stderr: "",
      };
    },
  });

  await fixture.adapter.run(request());

  const turns = turnCalls(fixture);
  assert.equal(turns.length, 2);
  assert.equal(option(turns[1].argumentsList, "--resume"), undefined);
});

test("never loses fork lineage while recovering a full context", async () => {
  const fixture = createFixture({
    handle({ call }) {
      if (call.file === "claude" && call.argumentsList.includes("-p")) {
        throw processFailure(
          result({
            error: true,
            output: "Context window exceeded.",
            sessionId: CHILD_SESSION,
          }),
        );
      }
      return undefined;
    },
  });

  await assert.rejects(
    fixture.adapter.run(
      request({ session: { id: SOURCE_SESSION, mode: "fork" } }),
    ),
    hasCode("ERR_CLAUDE_CONTEXT_EXHAUSTED"),
  );
  const turns = turnCalls(fixture);
  assert.equal(turns.length, 2);
  assert.equal(option(turns[0].argumentsList, "--resume"), SOURCE_SESSION);
  assert.ok(turns[0].argumentsList.includes("--fork-session"));
  assert.equal(option(turns[1].argumentsList, "--resume"), CHILD_SESSION);
  assert.ok(!turns[1].argumentsList.includes("--fork-session"));
});

test("never continues a fork source after context exhaustion", async () => {
  const fixture = createFixture({
    handle({ call }) {
      if (call.file === "claude" && call.argumentsList.includes("-p")) {
        throw processFailure(
          result({
            error: true,
            output: "Context window exceeded.",
            sessionId: SOURCE_SESSION,
          }),
        );
      }
      return undefined;
    },
  });

  await assert.rejects(
    fixture.adapter.run(
      request({ session: { id: SOURCE_SESSION, mode: "fork" } }),
    ),
    hasCode("ERR_CLAUDE_PROTOCOL"),
  );
  assert.equal(turnCalls(fixture).length, 1);
});

test("creates one exact authorized commit in a networkless sandbox", async () => {
  const fixture = createFixture({
    env: {
      ...process.env,
      ANTHROPIC_API_KEY: "provider-token",
      HTTP_PROXY: "http://proxy.invalid",
      LD_PRELOAD: "/tmp/agent.so",
      NODE_OPTIONS: "--require=/tmp/agent.cjs",
      SSH_AUTH_SOCK: "/tmp/agent.sock",
    },
  });
  const message = "feat(test): create commit";

  await fixture.adapter.run(
    request({
      access: "local-commit",
      authorizationId: "authorization-1",
      commit: { expectedHead: EXPECTED_HEAD, message },
    }),
  );

  const metadata = fixture.calls.find(
    ({ file, argumentsList }) =>
      file === "git" && argumentsList.includes("--absolute-git-dir"),
  );
  const commitSandbox = localCommitSandboxCalls(fixture).find(
    ({ options }) => options.ownershipMode === "native-sandbox-provider",
  );
  assert.equal(metadata.options.ownershipMode, undefined);
  assert.ok(commitSandbox);

  const readinessTurn = turnCalls(fixture)[0];
  assert.equal(
    option(readinessTurn.argumentsList, "--permission-mode"),
    "auto",
  );
  assert.equal(
    option(readinessTurn.argumentsList, "--tools"),
    "Bash,Read,Glob,Grep",
  );
  assert.deepEqual(
    JSON.parse(option(readinessTurn.argumentsList, "--settings")).permissions
      .deny,
    COMMON_DENY_POLICY,
  );
  const bubblewrapCalls = localCommitSandboxCalls(fixture);
  assert.equal(bubblewrapCalls.length, 2);
  const commitCall = bubblewrapCalls[1];
  assert.ok(commitCall.argumentsList.includes("--unshare-net"));
  assert.ok(commitCall.argumentsList.includes(EXPECTED_HEAD));
  assert.ok(commitCall.argumentsList.includes(message));
  const commitScript =
    commitCall.argumentsList[commitCall.argumentsList.indexOf("-e") + 1];
  assert.match(commitScript, /runGit\(\["diff", "--quiet"\]\)/u);
  assert.match(commitScript, /runGit\(\["diff", "--cached", "--check"\]\)/u);
  assert.match(commitScript, /"diff", "--cached", "--quiet"/u);
  assert.ok(
    commitScript.indexOf('["add", "-A"]') <
      commitScript.lastIndexOf("assertStagedDiff()"),
  );
  assert.ok(
    commitScript.lastIndexOf("assertStagedDiff()") <
      commitScript.indexOf('["commit", "--message", message]'),
  );
  assert.equal(commitCall.options.env.ANTHROPIC_API_KEY, undefined);
  assert.equal(commitCall.options.env.HTTP_PROXY, undefined);
  assert.equal(commitCall.options.env.LD_PRELOAD, undefined);
  assert.equal(commitCall.options.env.NODE_OPTIONS, undefined);
  assert.equal(commitCall.options.env.SSH_AUTH_SOCK, undefined);
});

test("proves a rejected local-commit policy did not start the effect", async () => {
  const fixture = createFixture({
    handle({ call }) {
      if (call.file === "claude" && call.argumentsList.includes("-p")) {
        return {
          stdout: JSON.stringify(
            result({
              structured: { ready: false },
            }),
          ),
          stderr: "",
        };
      }
      return undefined;
    },
  });

  await assert.rejects(
    fixture.adapter.run(
      request({
        access: "local-commit",
        authorizationId: "authorization-1",
        commit: {
          expectedHead: EXPECTED_HEAD,
          message: "feat(test): create commit",
        },
      }),
    ),
    (error) => {
      assert.ok(hasCode("ERR_CLAUDE_LOCAL_COMMIT_POLICY")(error));
      assert.equal(error.effectStarted, false);
      assert.equal(error.failure.effect, "none");
      assert.equal(error.failure.commitExecutor, "not_started");
      return true;
    },
  );
  assert.equal(localCommitSandboxCalls(fixture).length, 1);
});

test("preserves immutable and primitive abort reasons before local commit execution", async () => {
  for (const reason of [
    Object.freeze(new Error("Operator pause")),
    "Operator cancel",
  ]) {
    const fixture = createFixture();
    await assert.rejects(
      fixture.adapter.run(
        request({
          access: "local-commit",
          authorizationId: "authorization-1",
          commit: {
            expectedHead: EXPECTED_HEAD,
            message: "feat(test): create commit",
          },
          signal: AbortSignal.abort(reason),
        }),
      ),
      (error) => {
        assert.ok(error instanceof ClaudeAdapterError);
        assert.equal(error.effectStarted, false);
        assert.equal(error.cause, reason);
        return true;
      },
    );
    assert.equal(turnCalls(fixture).length, 0);
    assert.equal(
      fixture.calls.filter(
        (call) => call.file === "git" && !isProbeRepositorySetup(call),
      ).length,
      0,
    );
  }
});

test("never replays an interrupted local-commit turn", async () => {
  const fixture = createFixture({
    handle({ call }) {
      if (call.file === "claude" && call.argumentsList.includes("-p")) {
        throw processFailure(undefined, "terminated");
      }
      return undefined;
    },
  });

  await assert.rejects(
    fixture.adapter.run(
      request({
        access: "local-commit",
        authorizationId: "authorization-1",
        commit: {
          expectedHead: EXPECTED_HEAD,
          message: "feat(test): create commit",
        },
      }),
    ),
    (error) => {
      assert.ok(hasCode("ERR_CLAUDE_PROCESS_INTERRUPTED")(error));
      assert.equal(error.ambiguous, true);
      assert.equal(error.recoverable, false);
      assert.equal(error.diagnosticClass, "writable_process_ambiguous");
      assert.equal(error.effectStarted, false);
      assert.equal(error.failure.outcome, "ambiguous");
      assert.equal(error.failure.effect, "possible");
      assert.equal(error.failure.commitExecutor, "not_started");
      const normalized = normalizeAdapterFailure("claude", error);
      assert.equal(normalized.ambiguous, true);
      assert.equal(normalized.effectStarted, false);
      assert.equal(normalized.failure.commitExecutor, "not_started");
      assert.equal(normalized.diagnosticClass, "writable_process_ambiguous");
      return true;
    },
  );
  assert.equal(turnCalls(fixture).length, 1);
  assert.equal(localCommitSandboxCalls(fixture).length, 1);
});

test("keeps commit-executor failures ambiguous", async () => {
  let bubblewrapCalls = 0;
  const fixture = createFixture({
    handle({ call }) {
      if (call.file === "bwrap" && !isNativeSandboxProbe(call)) {
        bubblewrapCalls += 1;
        if (bubblewrapCalls === 2) {
          throw new Error("commit executor failed");
        }
      }
      return undefined;
    },
  });

  await assert.rejects(
    fixture.adapter.run(
      request({
        access: "local-commit",
        authorizationId: "authorization-1",
        commit: {
          expectedHead: EXPECTED_HEAD,
          message: "feat(test): create commit",
        },
      }),
    ),
    (error) => {
      assert.ok(hasCode("ERR_CLAUDE_LOCAL_COMMIT_INTERRUPTED")(error));
      assert.equal(error.ambiguous, true);
      assert.notEqual(error.effectStarted, false);
      return true;
    },
  );
  assert.equal(bubblewrapCalls, 2);
});

test(
  "runs read-only inspection and denies mutations through direct bubblewrap seccomp",
  { skip: process.platform !== "linux" },
  async (t) => {
    const bubblewrapBinary = await resolveTestExecutable("bwrap");
    if (
      bubblewrapBinary === undefined ||
      !Object.hasOwn(EXPECTED_SECCOMP_INSTRUCTIONS, process.arch)
    ) {
      t.skip("A supported architecture and bubblewrap are required.");
      return;
    }
    const capabilityDirectory = await mkdtemp(
      join(tmpdir(), "agent-runner-bwrap-seccomp-"),
    );
    let capabilityResult;
    try {
      const filterPath = join(capabilityDirectory, "filter.bpf");
      await writeFile(filterPath, expectedSeccompFilter(process.arch), {
        mode: 0o400,
      });
      const descriptor = await open(filterPath, constants.O_RDONLY);
      try {
        await rm(filterPath);
        capabilityResult = spawnSync(
          bubblewrapBinary,
          [
            "--new-session",
            "--die-with-parent",
            "--unshare-net",
            "--ro-bind",
            "/",
            "/",
            "--dev",
            "/dev",
            "--unshare-pid",
            "--unshare-user",
            "--as-pid-1",
            "--cap-drop",
            "ALL",
            "--proc",
            "/proc",
            "--seccomp",
            "3",
            "--",
            "/bin/true",
          ],
          {
            env: process.env,
            stdio: ["ignore", "ignore", "ignore", descriptor.fd],
            timeout: 10_000,
          },
        );
      } finally {
        await descriptor.close();
      }
    } finally {
      await rm(capabilityDirectory, { force: true, recursive: true });
    }
    if (capabilityResult.error !== undefined || capabilityResult.status !== 0) {
      t.skip("The direct bubblewrap seccomp capability is unavailable.");
      return;
    }

    let fallbackProbeCount = 0;
    let realProbeCount = 0;
    const execute = async (file, argumentsList, options) => {
      const call = { file, argumentsList, options };
      if (file === process.execPath && argumentsList.at(-1) === "--version") {
        return { stdout: "2.1.233 (Claude Code)\n", stderr: "" };
      }
      if (file === process.execPath && argumentsList[0] === "--help") {
        return { stdout: HELP, stderr: "" };
      }
      if (file === "socat") {
        return { stdout: "socat version 1.8", stderr: "" };
      }
      if (file === "git") {
        return executeFile(file, argumentsList, options);
      }
      if (isNativeSandboxProbe(call)) {
        const error = new Error("Claude isolation probe failed.");
        error.stderr =
          "apply-seccomp: write /proc/self/setgroups (nested userns is " +
          "capability-restricted; caller must provide CAP_SYS_ADMIN) " +
          "Permission denied";
        throw error;
      }
      if (isRunnerBoundaryProbe(call)) {
        fallbackProbeCount += 1;
        if (realProbeCount === 0) {
          realProbeCount += 1;
          return executeFile(file, argumentsList, options);
        }
        return { stdout: "agent-runner-claude-isolation-ok", stderr: "" };
      }
      if (file === "bwrap") {
        return { stdout: "agent-runner-claude-commit-ok", stderr: "" };
      }
      throw new Error(`Unexpected command: ${file} ${argumentsList.join(" ")}`);
    };
    const adapter = createClaudeAdapter({
      claudeBinary: process.execPath,
      env: {
        ...process.env,
        PATH: `${dirname(bubblewrapBinary)}${delimiter}${process.env.PATH ?? ""}`,
      },
      execute,
      platform: "linux",
    });

    const capabilities = await adapter.probe();
    assert.equal(capabilities.readOnly, true);
    assert.equal(fallbackProbeCount, 3);
    assert.equal(realProbeCount, 1);
  },
);

test(
  "runs an opt-in real Claude read-only inspection smoke turn",
  { skip: process.env.AGENT_RUNNER_LIVE_CLAUDE !== "1" },
  async () => {
    const adapter = createClaudeAdapter();
    const response = await adapter.run(
      request({
        prompt:
          "Use Bash to run `git status --short` in the current repository. " +
          "Return ok=true only when the command completes successfully.",
        schema: STRICT_SCHEMA,
      }),
    );
    assert.equal(typeof response.sessionId, "string");
    assert.equal(response.structured.ok, true);
  },
);

test("expanded pipeline inventory schemas preserve strict Claude preflight and sandboxing", async (t) => {
  for (const [name, schema, access] of [
    ["execution bootstrap", EXECUTION_BOOTSTRAP_SCHEMA, "read-only"],
    [
      "execution finalization",
      EXECUTION_FINALIZATION_SCHEMA,
      "workspace-write",
    ],
    ["polishing bootstrap", POLISHING_BOOTSTRAP_SCHEMA, "read-only"],
    [
      "polishing finalization",
      POLISHING_FINALIZATION_SCHEMA,
      "workspace-write",
    ],
  ]) {
    await t.test(name, async () => {
      const baseline = createFixture();
      await baseline.adapter.run(request({ access, schema: STRICT_SCHEMA }));
      const fixture = createFixture();
      await fixture.adapter.run(request({ access, schema }));
      const turn = turnCalls(fixture)[0];
      assert.deepEqual(
        JSON.parse(option(turn.argumentsList, "--json-schema")),
        schema,
      );
      const settings = JSON.parse(option(turn.argumentsList, "--settings"));
      assert.deepEqual(
        settings,
        JSON.parse(option(turnCalls(baseline)[0].argumentsList, "--settings")),
      );
      assert.equal(settings.sandbox.enabled, true);
      assert.equal(settings.sandbox.failIfUnavailable, true);
      assert.equal(settings.sandbox.allowUnsandboxedCommands, false);
      assert.equal(settings.sandbox.enableWeakerNestedSandbox, false);
      assert.notEqual(settings.sandbox.network.allowAllUnixSockets, true);
      assert.deepEqual(settings.sandbox.network.deniedDomains, ["*"]);
      assert.deepEqual(
        settings.permissions.deny,
        access === "read-only" ? COMMON_DENY_POLICY : WORKSPACE_DENY_POLICY,
      );
      assert.ok(
        settings.sandbox.filesystem.denyWrite.includes(`${PROJECT_PATH}/.git`),
      );
      if (access === "read-only")
        assert.ok(settings.sandbox.filesystem.denyWrite.includes(PROJECT_PATH));
      const unsupported = createFixture({ nativeSandbox: false });
      await assert.rejects(
        unsupported.adapter.run(request({ access, schema })),
        hasCode("ERR_UNSUPPORTED_CLAUDE_CAPABILITY"),
      );
      assert.equal(turnCalls(unsupported).length, 0);
    });
  }
});

test("keeps missing HOME/config scaffolding outside every project view", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "claude-projection-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const project = join(directory, "project");
  const providerHome = join(directory, "provider-home");
  await mkdir(project);
  await mkdir(providerHome);
  await executeFile("git", ["init", project]);
  await executeFile("git", [
    "-C",
    project,
    "-c",
    "user.name=Fixture",
    "-c",
    "user.email=fixture@example.invalid",
    "commit",
    "--allow-empty",
    "-m",
    "fixture",
  ]);
  await writeFile(join(project, "content.txt"), "project content\n");
  await writeFile(join(project, "package.json"), "{}\n");
  const git = createGitService();
  const fingerprint = () => git.contentFingerprint({ projectPath: project });
  const baseline = await fingerprint();
  const listing = await readdir(project);
  const status = async () =>
    (
      await executeFile("git", [
        "-C",
        project,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
      ])
    ).stdout;
  const initialStatus = await status();
  const bwrap = await createFakeBubblewrap(t);
  // Reproduce the recorded host-visible mount-point side effect without a model.
  await executeFile(
    join(bwrap.directory, "bwrap"),
    ["--ro-bind", "/dev/null", join(project, ".bashrc"), "--", "/bin/true"],
    {
      env: {
        AGENT_RUNNER_FAKE_BWRAP_LOG: bwrap.logPath,
        AGENT_RUNNER_FAKE_BWRAP_MATERIALIZE: project,
        AGENT_RUNNER_FAKE_BWRAP_NATIVE: "1",
      },
    },
  );
  assert.notEqual(await fingerprint(), baseline);
  assert.match(await status(), /\.bashrc/u);
  await rm(join(project, ".bashrc"));
  assert.equal(await fingerprint(), baseline);
  for (const policy of ["native", "runner-boundary"]) {
    for (const accessMode of ["read-only", "workspace-write"]) {
      let resource;
      let resourcePath;
      const records = [];
      const fixture = createFixture({
        nativeSandbox: policy === "native" ? true : "nested-denied",
        env: {
          ...process.env,
          HOME: providerHome,
          CLAUDE_CONFIG_DIR: join(providerHome, "missing-config"),
          ANTHROPIC_API_KEY: "provider-only",
          PATH: `${bwrap.directory}${delimiter}${process.env.PATH}`,
        },
        async handle({ call }) {
          if (call.file === "git" && call.argumentsList.includes("rev-parse")) {
            return { stdout: `${project}/.git\n.git\n`, stderr: "" };
          }
          if (call.file !== "claude" || !call.argumentsList.includes("-p"))
            return;
          assert.equal(resource.phase, "allocated");
          assert.equal(resource.commandIdentity, CLAUDE_STORAGE_IDENTITY);
          resourcePath = join(resource.root.path, resource.id);
          assert.ok(!resourcePath.startsWith(directory + "/"));
          assert.equal(call.options.env.HOME, providerHome);
          assert.equal(
            call.options.env.CLAUDE_CONFIG_DIR,
            join(providerHome, "missing-config"),
          );
          assert.equal(call.options.env.ANTHROPIC_API_KEY, "provider-only");
          assert.ok(call.options.env.TMPDIR.startsWith(resourcePath + "/"));
          const args = claudeBubblewrapArguments({
            access: accessMode,
            payload: "inspect",
          }).map((value) =>
            value
              .replaceAll(PROJECT_PATH, project)
              .replaceAll(CLAUDE_LOG_PATH, join(providerHome, ".npm/_logs")),
          );
          const settings = JSON.parse(option(call.argumentsList, "--settings"));
          // The recorded CLI version omits absent deny targets when an
          // existing read-only directory already covers them. Without that
          // preparation reservation it registers these targets for cleanup.
          if (!settings.sandbox.filesystem.denyWrite.includes(project)) {
            args.splice(
              args.indexOf("--dev"),
              0,
              ...[
                ".bashrc",
                ".gitconfig",
                ".idea",
                ".vscode",
                ".claude/commands",
                ".claude/agents",
              ].flatMap((name) => [
                "--ro-bind",
                "/dev/null",
                join(project, name),
              ]),
            );
          }
          assert.ok(settings.sandbox.filesystem.denyWrite.includes(project));
          // Reproduce bubblewrap's host-visible creation of absent mask targets.
          // Both views must stay unchanged while the provider is still running.
          await executeFile(call.commandLauncherPath, args, {
            env: {
              ...call.options.env,
              AGENT_RUNNER_FAKE_BWRAP_LOG: bwrap.logPath,
              AGENT_RUNNER_FAKE_BWRAP_MATERIALIZE: project,
              AGENT_RUNNER_FAKE_BWRAP_NATIVE: policy === "native" ? "1" : "0",
            },
          });
          assert.deepEqual(await readdir(project), listing);
          assert.equal(await status(), initialStatus);
          assert.equal(await fingerprint(), baseline);
          const mounts = JSON.parse(
            (await readFile(bwrap.logPath, "utf8")).trim().split("\n").at(-1),
          );
          const homeIndex = mounts.findIndex(
            (value, index) =>
              value === "--setenv" && mounts[index + 1] === "HOME",
          );
          const home = mounts[homeIndex + 2];
          assert.ok(home.startsWith(resourcePath + "/"));
          assert.equal(await readFile(join(home, ".bashrc"), "utf8"), "");
          assert.ok(includesSequence(mounts, ["--ro-bind", home, home]));
          assert.ok(
            includesSequence(mounts, [
              "--ro-bind",
              `${project}/.git`,
              `${project}/.git`,
            ]),
          );
        },
      });
      await fixture.adapter.run(
        request({
          cwd: project,
          access: accessMode,
          storageForbiddenPaths: [directory],
          onResource: async (value) => {
            resource = value;
            records.push(value?.phase ?? "cleaned");
          },
        }),
      );
      assert.deepEqual(records, ["allocating", "allocated", "cleaned"]);
      assert.equal(resource, null);
      await assert.rejects(access(resourcePath), { code: "ENOENT" });
      // This is also the unfiltered tree presented to subsequent trusted checks.
      assert.equal(await fingerprint(), baseline);
      assert.equal(await status(), initialStatus);
    }
  }
});

test("rejects absent native project targets before any mount can create them", async (t) => {
  const bwrap = await createFakeBubblewrap(t);
  const project = join(bwrap.directory, "project");
  await mkdir(join(project, ".git"), { recursive: true });
  await writeFile(join(project, ".git", "config"), "");
  await writeFile(join(project, "package.json"), "{}");
  const fixture = createFixture({
    env: {
      ...process.env,
      AGENT_RUNNER_FAKE_BWRAP_LOG: bwrap.logPath,
      AGENT_RUNNER_FAKE_BWRAP_NATIVE: "1",
      PATH: `${bwrap.directory}${delimiter}${process.env.PATH}`,
    },
    async handle({ call }) {
      if (call.file === "git" && call.argumentsList.includes("rev-parse"))
        return { stdout: `${project}/.git\n.git\n`, stderr: "" };
      if (call.file !== "claude" || !call.argumentsList.includes("-p")) return;
      for (const operation of ["--dir", "--tmpfs", "--dev", "--proc"]) {
        const args = claudeBubblewrapArguments({
          access: "workspace-write",
          payload: "inspect",
        }).map((value) => value.replaceAll(PROJECT_PATH, project));
        args.splice(
          args.indexOf("--"),
          0,
          operation,
          join(project, "absent-mount-target"),
        );
        await assert.rejects(
          executeFile(call.commandLauncherPath, args, {
            env: call.options.env,
          }),
          { code: 125 },
          operation,
        );
      }
      await assert.rejects(access(bwrap.logPath), { code: "ENOENT" });
    },
  });
  await fixture.adapter.run(
    request({ access: "workspace-write", cwd: project }),
  );
});

test("retires storage after provider failure and interruption without hiding the failure", async () => {
  for (const interrupted of [false, true]) {
    const controller = new AbortController();
    let resource;
    let directory;
    const fixture = createFixture({
      handle({ call }) {
        if (call.file !== "claude" || !call.argumentsList.includes("-p"))
          return;
        directory = join(resource.root.path, resource.id);
        if (interrupted) controller.abort();
        throw processFailure(
          result({ error: true, output: "authentication failed" }),
        );
      },
    });
    await assert.rejects(
      fixture.adapter.run(
        request({
          signal: controller.signal,
          onResource: async (value) => {
            resource = value;
          },
        }),
      ),
      interrupted
        ? { name: "AbortError" }
        : hasCode("ERR_CLAUDE_AUTHENTICATION_UNAVAILABLE"),
    );
    assert.equal(resource, null);
    await assert.rejects(access(directory), { code: "ENOENT" });
  }
});

test("retains storage until process retirement and rejects replacement during owner recovery", async (t) => {
  let resource;
  const fixture = createFixture({
    async handle({ call }) {
      if (call.file !== "claude" || !call.argumentsList.includes("-p")) return;
      await call.options.onProcess(4242, {});
      throw Object.assign(new Error("unverifiable retirement"), {
        code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
      });
    },
  });
  await assert.rejects(
    fixture.adapter.run(
      request({
        onProcess: async () => {},
        onResource: async (value) => {
          resource = value;
        },
      }),
    ),
    { code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE" },
  );
  assert.equal(resource.phase, "allocated");
  const directory = join(resource.root.path, resource.id);
  const moved = `${directory}-moved`;
  t.after(async () => {
    await rm(directory, { recursive: true, force: true });
    await rm(moved, { recursive: true, force: true });
  });
  // The runner calls recovery only after independently retiring the process.
  await rename(directory, moved);
  await mkdir(directory, { mode: 0o700 });
  await writeFile(join(directory, "unowned"), "preserve");
  await assert.rejects(
    recoverClaudeStorage({
      resource,
      storageForbiddenPaths: [PROJECT_PATH],
      onResource: async () => assert.fail("must retain ownership"),
    }),
    { code: "ERR_EXECUTION_RESOURCE_UNVERIFIABLE" },
  );
  assert.equal(await readFile(join(directory, "unowned"), "utf8"), "preserve");
  await rm(directory, { recursive: true });
  await rename(moved, directory);
  await recoverClaudeStorage({
    resource,
    storageForbiddenPaths: [PROJECT_PATH],
    onResource: async (value) => {
      resource = value;
    },
  });
  assert.equal(resource, null);
  await assert.rejects(access(directory), { code: "ENOENT" });
});

test("reports setup failure before launch with bounded not-started evidence", async () => {
  const fixture = createFixture();
  await assert.rejects(
    fixture.adapter.run(request({ storageForbiddenPaths: [tmpdir()] })),
    (cause) => {
      const failure = normalizeAdapterFailure("claude", cause);
      assert.equal(failure.code, "ERR_AGENT_ENVIRONMENT_PREPARATION");
      assert.equal(failure.failure.failureClass, "environment_preparation");
      assert.equal(failure.failure.effect, "none");
      assert.deepEqual(failure.launchRecovery, {
        failureClass: "environment_preparation",
        checkpoint: "initialize",
      });
      assert.equal(failure.recoverable, true);
      assert.equal(cause.cause, undefined);
      return true;
    },
  );
  assert.equal(turnCalls(fixture).length, 0);
});

test("cleanup failure does not replace an ambiguous writable outcome", async () => {
  let resource;
  const fixture = createFixture({
    handle({ call }) {
      if (call.file === "claude" && call.argumentsList.includes("-p"))
        throw processFailure();
    },
  });
  await assert.rejects(
    fixture.adapter.run(
      request({
        access: "workspace-write",
        onResource: async (value) => {
          if (value === null)
            throw new Error("cleanup acknowledgement unavailable");
          resource = value;
        },
      }),
    ),
    hasDiagnostic(
      "ERR_CLAUDE_PROCESS_INTERRUPTED",
      "writable_process_ambiguous",
    ),
  );
  await recoverClaudeStorage({
    resource,
    storageForbiddenPaths: [PROJECT_PATH],
    onResource: async (value) => {
      resource = value;
    },
  });
  assert.equal(resource, null);
});
