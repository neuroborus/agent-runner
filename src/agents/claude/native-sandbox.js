import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const APPLY_SECCOMP_ARGV0 = "apply-seccomp";
const PROBE_CREDENTIAL = "AGENT_RUNNER_CLAUDE_PROBE_CREDENTIAL";
const PROBE_OUTPUT = "agent-runner-claude-isolation-ok";
const ACCESS_MODES = Object.freeze([
  "read-only",
  "workspace-write",
  "local-commit",
]);
const NESTED_USER_NAMESPACE_DENIAL =
  /apply-seccomp:\s*write \/proc\/self\/setgroups[\s\S]{0,240}(?:(?:nested userns)[\s\S]{0,160}CAP_SYS_ADMIN|permission denied)/iu;
const PROVIDER_PROBE_SCRIPT = String.raw`
import { spawnSync } from "node:child_process";
import { writeSync } from "node:fs";

const [bubblewrapBinary, ...argumentsList] = process.argv.slice(1);
if (process.env.${PROBE_CREDENTIAL} === undefined) process.exit(20);
const commandEnvironment = { ...process.env };
delete commandEnvironment.${PROBE_CREDENTIAL};
const result = spawnSync(
  bubblewrapBinary,
  [...argumentsList, String(process.pid)],
  {
    encoding: "utf8",
    env: commandEnvironment,
    maxBuffer: 1024 * 1024,
    timeout: 8_000,
  },
);
if (result.stdout) writeSync(1, result.stdout);
if (result.stderr) writeSync(2, result.stderr);
if (result.error !== undefined || result.signal !== null) process.exit(21);
process.exit(result.status ?? 22);
`.trim();
const PROBE_SCRIPT = String.raw`
import { readFileSync, writeFileSync, writeSync } from "node:fs";
import { createConnection, createServer } from "node:net";
import { join } from "node:path";

const [access, gitDirectory, outsideDirectory, socketPath, providerPid] =
  process.argv.slice(1);
const writable = access === "workspace-write";
const denied = new Set(["EACCES", "ENOENT", "EPERM", "EROFS"]);
function write(path, expected) {
  try {
    writeFileSync(path, "");
    if (!expected) process.exit(10);
  } catch ({ code }) {
    if (expected || !denied.has(code)) process.exit(11);
  }
}
if (process.env.${PROBE_CREDENTIAL} !== undefined) process.exit(12);
if (!/^[1-9][0-9]*$/.test(providerPid)) process.exit(17);
try {
  readFileSync(join("/proc", providerPid, "environ"));
  process.exit(18);
} catch ({ code }) {
  if (!denied.has(code)) process.exit(19);
}
write("workspace-probe", writable);
write(join(gitDirectory, "git-probe"), false);
write(join(outsideDirectory, "outside-probe"), false);

const results = new Set();
function finish(kind, code) {
  if (!new Set(["EACCES", "ENETUNREACH", "EPERM"]).has(code)) process.exit(13);
  results.add(kind);
  if (results.size === 2) {
    writeSync(1, ${JSON.stringify(PROBE_OUTPUT)});
    process.exit(0);
  }
}
const internet = createConnection({ host: "1.1.1.1", port: 53 });
internet.once("connect", () => process.exit(14));
internet.once("error", ({ code }) => finish("internet", code));
const server = createServer();
server.once("error", ({ code }) => finish("unix", code));
server.listen(socketPath, () => {
  const unix = createConnection(socketPath);
  unix.once("connect", () => process.exit(15));
  unix.once("error", ({ code }) => finish("unix", code));
});
setTimeout(() => process.exit(16), 1_000);
`.trim();

function processOutput(value) {
  if (typeof value === "string") return value;
  return Buffer.isBuffer(value) ? value.toString("utf8") : "";
}

function innerArguments({
  access,
  basePath,
  claudeBinary,
  gitDirectory,
  outsideDirectory,
  weaker,
  workspaceDirectory,
}) {
  const argumentsList = [
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
    ...(weaker
      ? ["--bind", "/proc", "/proc"]
      : ["--cap-drop", "ALL", "--proc", "/proc"]),
    "--tmpfs",
    "/tmp",
    "--tmpfs",
    "/run",
    "--ro-bind",
    basePath,
    basePath,
  ];
  if (access === "workspace-write") {
    argumentsList.push("--bind", workspaceDirectory, workspaceDirectory);
  }
  argumentsList.push("--ro-bind", gitDirectory, gitDirectory);
  argumentsList.push(
    "--chdir",
    workspaceDirectory,
    "--unsetenv",
    PROBE_CREDENTIAL,
    "--setenv",
    "ARGV0",
    APPLY_SECCOMP_ARGV0,
    "--",
    claudeBinary,
    process.execPath,
    "--input-type=module",
    "-e",
    PROBE_SCRIPT,
    access,
    gitDirectory,
    outsideDirectory,
    "/run/agent-runner-claude-probe.sock",
  );
  return argumentsList;
}

function boundaryArguments(cwd, command) {
  return [
    "--new-session",
    "--die-with-parent",
    "--unshare-pid",
    "--as-pid-1",
    "--bind",
    "/",
    "/",
    "--dev",
    "/dev",
    "--proc",
    "/proc",
    "--chdir",
    cwd,
    "--",
    ...command,
  ];
}

async function probePolicy({
  access,
  bubblewrapBinary,
  claudeBinary,
  env,
  execute,
  weaker,
}) {
  let basePath;
  let outcome;
  try {
    basePath = await mkdtemp(join(tmpdir(), "agent-runner-claude-policy-"));
    const workspaceDirectory = join(basePath, "workspace");
    const gitDirectory = join(workspaceDirectory, ".git");
    const outsideDirectory = join(basePath, "outside");
    await mkdir(workspaceDirectory);
    await Promise.all(
      [gitDirectory, outsideDirectory].map((path) => mkdir(path)),
    );
    const inner = innerArguments({
      access,
      basePath,
      claudeBinary,
      gitDirectory,
      outsideDirectory,
      weaker,
      workspaceDirectory,
    });
    const providerCommand = [
      process.execPath,
      "--input-type=module",
      "-e",
      PROVIDER_PROBE_SCRIPT,
      bubblewrapBinary,
      ...inner,
    ];
    const result = await execute(
      weaker ? bubblewrapBinary : providerCommand[0],
      weaker
        ? boundaryArguments(workspaceDirectory, providerCommand)
        : providerCommand.slice(1),
      {
        encoding: "utf8",
        env: { ...env, [PROBE_CREDENTIAL]: "unavailable-to-model-commands" },
        maxBuffer: 1024 * 1024,
        timeout: 10_000,
      },
    );
    outcome = {
      available: processOutput(result.stdout) === PROBE_OUTPUT,
      nestedUserNamespaceDenied: false,
    };
  } catch (cause) {
    const diagnostic = `${processOutput(cause?.stderr)}\n${String(cause?.message ?? "")}`;
    outcome = {
      available: false,
      nestedUserNamespaceDenied:
        !weaker && NESTED_USER_NAMESPACE_DENIAL.test(diagnostic),
    };
  } finally {
    if (basePath !== undefined) {
      try {
        await rm(basePath, { force: true, recursive: true });
      } catch {
        outcome = {
          available: false,
          nestedUserNamespaceDenied: false,
        };
      }
    }
  }
  return Object.freeze(outcome);
}

export async function probeClaudeIsolationPolicies(options) {
  const selected = {};
  for (const access of ACCESS_MODES) {
    const native = await probePolicy({ ...options, access, weaker: false });
    if (native.available) {
      selected[access] = "native";
      continue;
    }
    if (!native.nestedUserNamespaceDenied) {
      selected[access] = "unavailable";
      continue;
    }
    const fallback = await probePolicy({ ...options, access, weaker: true });
    selected[access] = fallback.available ? "runner-boundary" : "unavailable";
  }
  return Object.freeze(selected);
}

export function claudeIsolationCommand({
  argumentsList,
  bubblewrapBinary,
  claudeBinary,
  cwd,
  policy,
}) {
  if (policy === "native") {
    return Object.freeze({ file: claudeBinary, argumentsList });
  }
  if (policy === "runner-boundary") {
    return Object.freeze({
      file: bubblewrapBinary,
      argumentsList: boundaryArguments(cwd, [claudeBinary, ...argumentsList]),
    });
  }
  throw new Error("Claude isolation policy is unavailable.");
}
