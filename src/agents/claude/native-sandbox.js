import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";

import {
  CLAUDE_COMMAND_LAUNCHER_TOKEN,
  claudeCommandLauncherSettings,
  createClaudeCommandLauncher,
} from "./command-launcher.js";

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
const NATIVE_PROBE_SCRIPT = String.raw`
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync, writeSync } from "node:fs";
import { createConnection, createServer } from "node:net";
import { join } from "node:path";

const [access, gitDirectory, outsideDirectory, socketPath, providerPid] =
  process.argv.slice(1);
const writable = access === "workspace-write";
const denied = new Set(["EACCES", "ENOENT", "EPERM", "EROFS"]);
const gitEnvironment = {
  ...process.env,
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_TERMINAL_PROMPT: "0",
};
function write(path, expected) {
  try {
    writeFileSync(path, "");
    if (!expected) process.exit(10);
  } catch ({ code }) {
    if (expected || !denied.has(code)) process.exit(11);
  }
}
function run(file, argumentsList, expected) {
  const result = spawnSync(file, argumentsList, {
    encoding: "utf8",
    env: gitEnvironment,
    maxBuffer: 1024 * 1024,
    timeout: 1_000,
  });
  if (result.error !== undefined || result.signal !== null) process.exit(27);
  if ((result.status === 0) !== expected) process.exit(26);
}
if (process.env.${PROBE_CREDENTIAL} !== undefined) process.exit(12);
if (!/^[1-9][0-9]*$/.test(providerPid)) process.exit(17);
try {
  readFileSync(join("/proc", providerPid, "environ"));
  process.exit(18);
} catch ({ code }) {
  if (!denied.has(code)) process.exit(19);
}
run(
  "/bin/sh",
  [
    "-c",
    "git log -1 --format=%H >/dev/null && git cat-file -e 'HEAD^{commit}' && git branch -a >/dev/null && ls >/dev/null",
  ],
  true,
);
if (!writable) {
  run("/bin/sh", ["-c", ": > workspace-command-probe"], false);
  run("git", ["branch", "sandbox-command-probe"], false);
  run(
    "git",
    ["push", outsideDirectory, "HEAD:refs/heads/sandbox-command-probe"],
    false,
  );
}
if (process.env.HOME === process.cwd()) process.exit(28);
if (readFileSync(join(process.env.HOME, ".bashrc"), "utf8") !== "") process.exit(29);
write(join(process.env.HOME, "home-probe"), false);
write(join(process.env.TMPDIR, "temporary-probe"), true);
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
const RUNNER_BOUNDARY_PROBE_SCRIPT = String.raw`
import { spawnSync } from "node:child_process";
import { readFileSync, statSync, writeFileSync, writeSync } from "node:fs";
import { createConnection } from "node:net";
import { join } from "node:path";

const [
  access,
  gitDirectory,
  outsideDirectory,
  socketPath,
  abstractSocketName,
  providerPid,
] = process.argv.slice(1);
const writable = access === "workspace-write";
const denied = new Set(["EACCES", "ENOENT", "EPERM", "EROFS"]);
const gitEnvironment = {
  ...process.env,
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_TERMINAL_PROMPT: "0",
};
function write(path, expected) {
  try {
    writeFileSync(path, "");
    if (!expected) process.exit(10);
  } catch ({ code }) {
    if (expected || !denied.has(code)) process.exit(11);
  }
}
function run(file, argumentsList, expected) {
  const result = spawnSync(file, argumentsList, {
    encoding: "utf8",
    env: gitEnvironment,
    maxBuffer: 1024 * 1024,
    timeout: 1_000,
  });
  if (result.error !== undefined || result.signal !== null) process.exit(27);
  if ((result.status === 0) !== expected) process.exit(26);
}
if (
  process.env.${PROBE_CREDENTIAL} !== undefined ||
  process.env.${CLAUDE_COMMAND_LAUNCHER_TOKEN} !== undefined ||
  process.env.ARGV0 !== undefined
) process.exit(12);
if (!/^[1-9][0-9]*$/.test(providerPid)) process.exit(17);
try {
  readFileSync(join("/proc", providerPid, "environ"));
  process.exit(18);
} catch ({ code }) {
  if (!denied.has(code)) process.exit(19);
}
run(
  "/bin/sh",
  [
    "-c",
    "git log -1 --format=%H >/dev/null && git cat-file -e 'HEAD^{commit}' && git branch -a >/dev/null && ls >/dev/null",
  ],
  true,
);
if (!writable) {
  run("/bin/sh", ["-c", ": > workspace-command-probe"], false);
  run("git", ["branch", "sandbox-command-probe"], false);
  run(
    "git",
    ["push", outsideDirectory, "HEAD:refs/heads/sandbox-command-probe"],
    false,
  );
}
if (process.env.HOME === process.cwd()) process.exit(28);
if (readFileSync(join(process.env.HOME, ".bashrc"), "utf8") !== "") process.exit(29);
write(join(process.env.HOME, "home-probe"), false);
write(join(process.env.TMPDIR, "temporary-probe"), true);
write("workspace-probe", writable);
if (writable && !statSync(".claude").isDirectory()) process.exit(23);
write(".claude/mask-probe", false);
write(join(gitDirectory, "git-probe"), false);
write(join(outsideDirectory, "outside-probe"), false);
write("/tmp/agent-runner-claude-probe", true);
write("/run/agent-runner-claude-probe", true);

const results = new Set();
function finish(kind, code, expected) {
  if (!expected.has(code)) process.exit(13);
  results.add(kind);
  if (results.size === 3) {
    writeSync(1, ${JSON.stringify(PROBE_OUTPUT)});
    process.exit(0);
  }
}
const internet = createConnection({ host: "1.1.1.1", port: 53 });
internet.once("connect", () => process.exit(14));
internet.once("error", ({ code }) =>
  finish("internet", code, new Set(["EACCES", "ENETUNREACH", "EPERM"])),
);
if (!statSync(socketPath).isSocket()) process.exit(24);
const unix = createConnection(socketPath);
unix.once("connect", () => process.exit(15));
unix.once("error", ({ code }) =>
  finish("pathname", code, new Set(["EACCES", "EPERM"])),
);
const abstract = createConnection(String.fromCharCode(0) + abstractSocketName);
abstract.once("connect", () => process.exit(25));
abstract.once("error", ({ code }) =>
  finish(
    "abstract",
    code,
    new Set(["EACCES", "ECONNREFUSED", "ENOENT", "EPERM"]),
  ),
);
setTimeout(() => process.exit(16), 1_000);
`.trim();

function processOutput(value) {
  if (typeof value === "string") return value;
  return Buffer.isBuffer(value) ? value.toString("utf8") : "";
}

function shellArgument(value) {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}

function nativeArguments({
  access,
  basePath,
  claudeBinary,
  gitDirectory,
  outsideDirectory,
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
    "--cap-drop",
    "ALL",
    "--proc",
    "/proc",
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
  argumentsList.push(
    "--ro-bind",
    workspaceDirectory,
    workspaceDirectory,
    "--ro-bind",
    gitDirectory,
    gitDirectory,
  );
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
    NATIVE_PROBE_SCRIPT,
    access,
    gitDirectory,
    outsideDirectory,
    "/run/agent-runner-claude-probe.sock",
  );
  return argumentsList;
}

function fallbackProbeArguments({
  access,
  abstractSocketName,
  credentialEnvironmentNames,
  emptyMaskDirectory,
  gitDirectory,
  outsideDirectory,
  socketPath,
  workspaceDirectory,
}) {
  const argumentsList = ["--new-session", "--die-with-parent"];
  for (const name of new Set([
    ...credentialEnvironmentNames,
    PROBE_CREDENTIAL,
  ])) {
    argumentsList.push("--unsetenv", name);
  }
  argumentsList.push("--unshare-net", "--ro-bind", "/", "/");
  if (access === "workspace-write") {
    argumentsList.push(
      "--bind",
      workspaceDirectory,
      workspaceDirectory,
      "--ro-bind",
      workspaceDirectory,
      workspaceDirectory,
      "--ro-bind",
      emptyMaskDirectory,
      join(workspaceDirectory, ".claude"),
    );
  }
  argumentsList.push(
    "--bind",
    "/tmp/claude",
    "/tmp/claude",
    "--ro-bind",
    gitDirectory,
    gitDirectory,
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
    `${shellArgument(process.execPath)} --input-type=module -e ${shellArgument(RUNNER_BOUNDARY_PROBE_SCRIPT)} ${[
      access,
      gitDirectory,
      outsideDirectory,
      socketPath,
      abstractSocketName,
      String(process.pid),
    ]
      .map(shellArgument)
      .join(" ")}`,
  );
  return argumentsList;
}

async function listen(server, socketPath) {
  await new Promise((resolve, reject) => {
    const onError = (cause) => {
      server.off("listening", onListening);
      reject(cause);
    };
    const onListening = () => {
      server.off("error", onError);
      resolve();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(socketPath);
  });
}

async function close(server) {
  if (!server.listening) return;
  await new Promise((resolve, reject) => {
    server.close((cause) => (cause === undefined ? resolve() : reject(cause)));
  });
}

async function probeManagedSettings({ claudeBinary, env, execute }) {
  try {
    await execute(
      claudeBinary,
      [
        "--managed-settings",
        claudeCommandLauncherSettings(process.execPath),
        "--version",
      ],
      {
        encoding: "utf8",
        env,
        maxBuffer: 1024 * 1024,
        timeout: 10_000,
      },
    );
    return true;
  } catch {
    return false;
  }
}

async function initializeProbeRepositories({
  env,
  execute,
  outsideDirectory,
  workspaceDirectory,
}) {
  const options = {
    encoding: "utf8",
    env: {
      ...env,
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_TERMINAL_PROMPT: "0",
    },
    maxBuffer: 1024 * 1024,
    timeout: 10_000,
  };
  await execute(
    "git",
    [
      "-C",
      workspaceDirectory,
      "-c",
      "init.defaultBranch=main",
      "init",
      "--quiet",
    ],
    options,
  );
  await writeFile(join(workspaceDirectory, "inspection.txt"), "inspection\n");
  await execute(
    "git",
    ["-C", workspaceDirectory, "add", "inspection.txt"],
    options,
  );
  await execute(
    "git",
    [
      "-C",
      workspaceDirectory,
      "-c",
      "commit.gpgSign=false",
      "-c",
      "core.hooksPath=/dev/null",
      "-c",
      "user.email=agent-runner@example.invalid",
      "-c",
      "user.name=Agent Runner",
      "commit",
      "--quiet",
      "--message",
      "probe",
    ],
    options,
  );
  await execute(
    "git",
    ["-C", outsideDirectory, "init", "--bare", "--quiet"],
    options,
  );
}

async function probePolicy({
  access,
  architecture,
  bubblewrapBinary,
  claudeBinary,
  createSocketServer = createServer,
  credentialEnvironmentNames = [],
  env,
  execute,
  weaker,
}) {
  let basePath;
  let commandLauncher;
  let outcome;
  const socketServers = [];
  try {
    // Keep the workspace socket below Linux's bounded AF_UNIX pathname size,
    // including when the test runner supplies a nested private temporary root.
    basePath = await mkdtemp(join(tmpdir(), "ar-c-"));
    const workspaceDirectory = join(basePath, "w");
    const gitDirectory = join(workspaceDirectory, ".git");
    const outsideDirectory = join(basePath, "outside");
    const emptyMaskDirectory = join(basePath, "claude-empty-probe");
    await mkdir(workspaceDirectory);
    await Promise.all(
      [
        gitDirectory,
        outsideDirectory,
        emptyMaskDirectory,
        join(workspaceDirectory, ".claude"),
      ].map((path) => mkdir(path, { mode: 0o700 })),
    );
    await initializeProbeRepositories({
      env,
      execute,
      outsideDirectory,
      workspaceDirectory,
    });
    let file;
    let argumentsList;
    if (weaker) {
      const socketPath = join(workspaceDirectory, "s");
      const abstractSocketName = `${basename(basePath)}-${process.pid}`;
      const pathnameServer = createSocketServer();
      const abstractServer = createSocketServer();
      socketServers.push(pathnameServer, abstractServer);
      await Promise.all([
        listen(pathnameServer, socketPath),
        listen(abstractServer, String.fromCharCode(0) + abstractSocketName),
      ]);
      commandLauncher = await createClaudeCommandLauncher({
        access,
        architecture,
        bubblewrapBinary,
        cwd: workspaceDirectory,
        environment: env,
        gitDirectories: [gitDirectory],
        unsetEnvironmentNames: [
          ...credentialEnvironmentNames,
          PROBE_CREDENTIAL,
        ],
      });
      file = commandLauncher.path;
      argumentsList = fallbackProbeArguments({
        access,
        abstractSocketName,
        credentialEnvironmentNames,
        emptyMaskDirectory,
        gitDirectory,
        outsideDirectory,
        socketPath,
        workspaceDirectory,
      });
    } else {
      commandLauncher = await createClaudeCommandLauncher({
        access,
        architecture,
        bubblewrapBinary,
        cwd: workspaceDirectory,
        environment: env,
        gitDirectories: [gitDirectory],
        isolationPolicy: "native",
        unsetEnvironmentNames: credentialEnvironmentNames,
      });
      const inner = nativeArguments({
        access,
        basePath,
        claudeBinary,
        gitDirectory,
        outsideDirectory,
        workspaceDirectory,
      });
      const providerCommand = [
        process.execPath,
        "--input-type=module",
        "-e",
        PROVIDER_PROBE_SCRIPT,
        commandLauncher.path,
        ...inner,
      ];
      file = providerCommand[0];
      argumentsList = providerCommand.slice(1);
    }
    const probeEnvironment = {
      ...env,
      [PROBE_CREDENTIAL]: "unavailable-to-model-commands",
    };
    const result = await execute(file, argumentsList, {
      encoding: "utf8",
      env:
        commandLauncher === undefined
          ? probeEnvironment
          : commandLauncher.environment(probeEnvironment),
      maxBuffer: 1024 * 1024,
      timeout: 10_000,
    });
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
    let cleanupFailed = false;
    if (commandLauncher !== undefined) {
      try {
        await commandLauncher.remove();
      } catch {
        cleanupFailed = true;
      }
    }
    for (const socketServer of socketServers) {
      try {
        await close(socketServer);
      } catch {
        cleanupFailed = true;
      }
    }
    if (basePath !== undefined) {
      try {
        await rm(basePath, { force: true, recursive: true });
      } catch {
        cleanupFailed = true;
      }
    }
    if (cleanupFailed) {
      outcome = {
        available: false,
        nestedUserNamespaceDenied: false,
      };
    }
  }
  return Object.freeze(outcome);
}

export async function probeClaudeIsolationPolicies(options) {
  const selected = {};
  let managedSettingsAvailable;
  for (const access of ACCESS_MODES) {
    const native = await probePolicy({ ...options, access, weaker: false });
    if (native.available) {
      managedSettingsAvailable ??= await probeManagedSettings(options);
      selected[access] = managedSettingsAvailable ? "native" : "unavailable";
      continue;
    }
    if (!native.nestedUserNamespaceDenied) {
      selected[access] = "unavailable";
      continue;
    }
    if (managedSettingsAvailable === undefined) {
      managedSettingsAvailable = await probeManagedSettings(options);
    }
    if (!managedSettingsAvailable) {
      selected[access] = "unavailable";
      continue;
    }
    const fallback = await probePolicy({ ...options, access, weaker: true });
    selected[access] = fallback.available ? "runner-boundary" : "unavailable";
  }
  return Object.freeze(selected);
}
