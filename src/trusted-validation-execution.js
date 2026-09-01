import { spawn } from "node:child_process";
import {
  accessSync,
  constants,
  existsSync,
  lstatSync,
  readFileSync,
  readlinkSync,
  realpathSync,
} from "node:fs";
import {
  basename,
  delimiter,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";

const BUBBLEWRAP_CANDIDATES = Object.freeze([
  "/usr/bin/bwrap",
  "/bin/bwrap",
  "/usr/local/bin/bwrap",
  "/usr/local/sbin/bwrap",
]);
const DEFAULT_TERMINATION_GRACE_MS = 1_000;
const SYSTEM_MOUNTS = Object.freeze([
  "/usr",
  "/bin",
  "/sbin",
  "/lib",
  "/lib64",
  "/etc",
]);
const READINESS_SCRIPT = `
const { spawn } = require("node:child_process");
const { writeSync } = require("node:fs");
const [executable, ...argumentsList] = process.argv.slice(1);
writeSync(3, Buffer.from([1]));
const child = spawn(executable, argumentsList, {
  stdio: ["ignore", "ignore", "ignore"],
});
child.once("error", () => {
  process.exitCode = 126;
});
child.once("exit", (exitCode, signal) => {
  if (signal === null) {
    process.exitCode = exitCode ?? 1;
    return;
  }
  process.kill(process.pid, signal);
});
`.trim();
const ENVIRONMENT_NAMES = new Set([
  "CI",
  "COLORTERM",
  "FORCE_COLOR",
  "LANG",
  "LANGUAGE",
  "NO_COLOR",
  "PATH",
  "TERM",
  "TZ",
]);

export class TrustedExecutionError extends Error {
  constructor(message, { code = "ERR_TRUSTED_EXECUTION" } = {}) {
    super(message);
    this.name = "TrustedExecutionError";
    this.code = code;
  }
}

function assertReadOnlyPath(path) {
  let current = path;
  while (true) {
    try {
      accessSync(current, constants.W_OK);
    } catch (cause) {
      if (!["EACCES", "EPERM", "EROFS"].includes(cause?.code)) {
        throw new TrustedExecutionError(
          "Trusted validation launcher changed during verification.",
          { code: "ERR_TRUSTED_VALIDATION_ISOLATION_UNAVAILABLE" },
        );
      }
      // Continue only when this path cannot be changed by the runner identity.
      if (current === sep) {
        return;
      }
      current = dirname(current);
      continue;
    }
    throw new TrustedExecutionError(
      "Trusted validation launcher is writable by the runner identity.",
      { code: "ERR_TRUSTED_VALIDATION_ISOLATION_UNAVAILABLE" },
    );
  }
}

export function verifyTrustedBubblewrap(path, projectPath = null) {
  if (typeof path !== "string" || !isAbsolute(path) || !existsSync(path)) {
    throw new TrustedExecutionError(
      "Trusted validation launcher is unavailable.",
      { code: "ERR_TRUSTED_VALIDATION_ISOLATION_UNAVAILABLE" },
    );
  }
  const canonicalPath = realpathSync(path);
  const metadata = lstatSync(canonicalPath);
  if (
    path !== canonicalPath ||
    !metadata.isFile() ||
    metadata.nlink !== 1 ||
    (projectPath !== null && coversPath(projectPath, canonicalPath))
  ) {
    throw new TrustedExecutionError(
      "Trusted validation launcher is unsafe.",
      { code: "ERR_TRUSTED_VALIDATION_ISOLATION_UNAVAILABLE" },
    );
  }
  try {
    accessSync(canonicalPath, constants.X_OK);
  } catch {
    throw new TrustedExecutionError(
      "Trusted validation launcher is not executable.",
      { code: "ERR_TRUSTED_VALIDATION_ISOLATION_UNAVAILABLE" },
    );
  }
  assertReadOnlyPath(canonicalPath);
  return canonicalPath;
}

export function resolveTrustedBubblewrap(executable = null) {
  if (
    executable !== null &&
    (typeof executable !== "string" || !isAbsolute(executable))
  ) {
    throw new TrustedExecutionError(
      "Trusted validation launcher must be absolute.",
      { code: "ERR_TRUSTED_VALIDATION_ISOLATION_UNAVAILABLE" },
    );
  }
  for (const candidate of
    executable === null ? BUBBLEWRAP_CANDIDATES : [executable]) {
    if (!existsSync(candidate)) {
      continue;
    }
    try {
      return verifyTrustedBubblewrap(realpathSync(candidate));
    } catch (cause) {
      if (executable !== null) {
        throw cause;
      }
    }
  }
  throw new TrustedExecutionError(
    "Trusted validation launcher is unavailable.",
    { code: "ERR_TRUSTED_VALIDATION_ISOLATION_UNAVAILABLE" },
  );
}

function delay(milliseconds) {
  return new Promise((resolvePromise) => {
    setTimeout(resolvePromise, milliseconds);
  });
}

function processGroupExists(processId) {
  try {
    process.kill(-processId, 0);
    return true;
  } catch (cause) {
    if (cause?.code === "ESRCH") {
      return false;
    }
    if (cause?.code === "EPERM") {
      return true;
    }
    throw cause;
  }
}

function signalProcessGroup(processId, signal) {
  try {
    process.kill(-processId, signal);
  } catch (cause) {
    if (cause?.code !== "ESRCH") {
      throw cause;
    }
  }
}

async function waitForProcessGroupExit(processId, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (processGroupExists(processId)) {
    if (Date.now() >= deadline) {
      return false;
    }
    await delay(Math.min(20, Math.max(1, deadline - Date.now())));
  }
  return true;
}

async function terminateProcessGroup(processId, graceMs) {
  if (!processGroupExists(processId)) {
    return true;
  }
  signalProcessGroup(processId, "SIGTERM");
  if (await waitForProcessGroupExit(processId, graceMs)) {
    return true;
  }
  signalProcessGroup(processId, "SIGKILL");
  return waitForProcessGroupExit(processId, graceMs);
}

export async function runExactCommand(
  command,
  {
    cwd,
    environment,
    readinessRequired = false,
    terminationGraceMs = DEFAULT_TERMINATION_GRACE_MS,
    timeoutMs,
  },
) {
  if (process.platform === "win32") {
    return {
      status: "BLOCKED",
      exitCode: null,
      signal: null,
      timedOut: false,
      reason: "process-tree-supervision",
    };
  }
  let child;
  try {
    child = spawn(command.executable, command.arguments, {
      cwd,
      detached: true,
      env: environment,
      shell: false,
      stdio: readinessRequired
        ? ["ignore", "ignore", "ignore", "pipe"]
        : "ignore",
    });
  } catch {
    return {
      status: "BLOCKED",
      exitCode: null,
      signal: null,
      timedOut: false,
      reason: "spawn",
    };
  }
  const closed = new Promise((resolvePromise) => {
    child.once("error", () => resolvePromise({ type: "error" }));
    child.once("close", (exitCode, signal) =>
      resolvePromise({ type: "close", exitCode, signal }),
    );
  });
  let ready = !readinessRequired;
  child.stdio?.[3]?.once("data", (value) => {
    ready = value[0] === 1;
  });
  let timeout;
  const expired = new Promise((resolvePromise) => {
    timeout = setTimeout(() => resolvePromise({ type: "timeout" }), timeoutMs);
    timeout.unref();
  });
  const outcome = await Promise.race([closed, expired]);
  clearTimeout(timeout);
  if (outcome.type === "error" || !Number.isSafeInteger(child.pid)) {
    return {
      status: "BLOCKED",
      exitCode: null,
      signal: null,
      timedOut: false,
      reason: "spawn",
    };
  }
  if (outcome.type === "timeout") {
    const terminated = await terminateProcessGroup(
      child.pid,
      terminationGraceMs,
    );
    const finalOutcome = await Promise.race([
      closed,
      delay(terminationGraceMs).then(() => null),
    ]);
    if (!terminated) {
      throw new TrustedExecutionError(
        "Trusted validation process tree could not be terminated.",
        { code: "ERR_TRUSTED_VALIDATION_PROCESS_TREE_ACTIVE" },
      );
    }
    return {
      status: "BLOCKED",
      exitCode: Number.isSafeInteger(finalOutcome?.exitCode)
        ? finalOutcome.exitCode
        : null,
      signal:
        typeof finalOutcome?.signal === "string" ? finalOutcome.signal : null,
      timedOut: true,
      reason: ready ? "timeout" : "isolation",
    };
  }
  let descendantsActive = processGroupExists(child.pid);
  if (descendantsActive && ready && outcome.exitCode === 0) {
    descendantsActive = !(await waitForProcessGroupExit(
      child.pid,
      terminationGraceMs,
    ));
  }
  if (descendantsActive) {
    const terminated = await terminateProcessGroup(
      child.pid,
      terminationGraceMs,
    );
    if (!terminated) {
      throw new TrustedExecutionError(
        "Trusted validation process tree could not be terminated.",
        { code: "ERR_TRUSTED_VALIDATION_PROCESS_TREE_ACTIVE" },
      );
    }
    return {
      status: "BLOCKED",
      exitCode: null,
      signal: null,
      timedOut: false,
      reason: ready ? "process-tree" : "isolation",
    };
  }
  if (!ready) {
    return {
      status: "BLOCKED",
      exitCode: null,
      signal: null,
      timedOut: false,
      reason: "isolation",
    };
  }
  return {
    status: outcome.exitCode === 0 ? "PASS" : "FAIL",
    exitCode: Number.isSafeInteger(outcome.exitCode) ? outcome.exitCode : null,
    signal: typeof outcome.signal === "string" ? outcome.signal : null,
    timedOut: false,
    reason: "exit",
  };
}

function safeEnvironment(environment) {
  const isolated = {};
  for (const [name, value] of Object.entries(environment)) {
    const normalizedName = name.toUpperCase();
    if (
      ENVIRONMENT_NAMES.has(normalizedName) ||
      normalizedName.startsWith("LC_")
    ) {
      isolated[name] = value;
    }
  }
  isolated.GIT_ASKPASS = "/bin/false";
  isolated.GIT_CONFIG_GLOBAL = "/dev/null";
  isolated.GIT_CONFIG_NOSYSTEM = "1";
  isolated.GIT_SSH_COMMAND = "/bin/false";
  isolated.GIT_TERMINAL_PROMPT = "0";
  isolated.HOME = "/nonexistent";
  isolated.SSH_ASKPASS = "/bin/false";
  isolated.TMPDIR = "/tmp";
  isolated.XDG_CACHE_HOME = "/tmp/agent-runner-cache";
  isolated.XDG_CONFIG_HOME = "/nonexistent";
  isolated.XDG_DATA_HOME = "/nonexistent";
  return Object.freeze(isolated);
}

function isInside(parent, child) {
  const path = relative(parent, child);
  return path !== "" && path !== ".." && !path.startsWith(`..${sep}`);
}

function coversPath(parent, child) {
  return parent === child || isInside(parent, child);
}

function mountParents(targetPath) {
  const parts = relative(sep, targetPath).split(sep);
  const parents = [];
  let current = sep;
  for (const part of parts.slice(0, -1)) {
    current = join(current, part);
    parents.push(current);
  }
  return parents;
}

function appendSystemMounts(argumentsList) {
  for (const path of SYSTEM_MOUNTS) {
    if (!existsSync(path)) {
      continue;
    }
    const metadata = lstatSync(path);
    if (metadata.isSymbolicLink()) {
      argumentsList.push("--symlink", readlinkSync(path), path);
    } else {
      argumentsList.push("--ro-bind", path, path);
    }
  }
}

function executableCandidate(executable, environment) {
  if (isAbsolute(executable)) {
    return existsSync(executable) ? executable : null;
  }
  for (const path of String(environment.PATH ?? "").split(delimiter)) {
    const candidate = resolve(path, executable);
    if (existsSync(candidate)) {
      return candidate;
    }
  }
  return null;
}

function commonParent(left, right) {
  const leftParts = resolve(left).split(sep);
  const rightParts = resolve(right).split(sep);
  const common = [];
  while (
    common.length < leftParts.length &&
    common.length < rightParts.length &&
    leftParts[common.length] === rightParts[common.length]
  ) {
    common.push(leftParts[common.length]);
  }
  return common.length <= 1 ? sep : common.join(sep);
}

function executableExposure(executable, environment) {
  const candidate = executableCandidate(executable, environment);
  if (candidate === null) {
    return null;
  }
  const candidateDirectory = dirname(candidate);
  const canonicalDirectory = realpathSync(candidateDirectory);
  if (basename(candidateDirectory) !== "bin") {
    return { source: canonicalDirectory, target: candidateDirectory };
  }
  return {
    source: commonParent(
      dirname(canonicalDirectory),
      dirname(realpathSync(candidate)),
    ),
    target: dirname(candidateDirectory),
  };
}

function gitMetadataExposures(cwd) {
  const dotGit = join(cwd, ".git");
  if (!existsSync(dotGit) || !lstatSync(dotGit).isFile()) {
    return [];
  }
  const match = /^gitdir: ([^\r\n]+)\r?\n?$/u.exec(
    readFileSync(dotGit, "utf8"),
  );
  if (match === null) {
    throw new Error("Git metadata pointer is invalid.");
  }
  const gitDirectory = realpathSync(resolve(cwd, match[1]));
  const commonPath = join(gitDirectory, "commondir");
  if (!existsSync(commonPath)) {
    return [gitDirectory];
  }
  const commonDirectory = realpathSync(
    resolve(gitDirectory, readFileSync(commonPath, "utf8").trim()),
  );
  return [gitDirectory, commonDirectory];
}

function dynamicExposures(command, { cwd, environment, homePath }) {
  const exposures = [
    { source: cwd, target: cwd },
    ...gitMetadataExposures(cwd).map((path) => ({ source: path, target: path })),
  ];
  for (const path of String(environment.PATH ?? "").split(delimiter)) {
    if (isAbsolute(path) && existsSync(path)) {
      exposures.push({ source: realpathSync(path), target: path });
    }
  }
  for (const executable of [command.executable, process.execPath]) {
    const exposure = executableExposure(executable, environment);
    if (exposure !== null) {
      exposures.push(exposure);
    }
  }
  const systemPaths = SYSTEM_MOUNTS.filter((path) => existsSync(path)).map(
    (path) => realpathSync(path),
  );
  const ordered = [
    ...new Map(
      exposures.map((value) => [value.target, value]),
    ).values(),
  ]
    .filter(
      ({ target }) =>
        !systemPaths.some((systemPath) => coversPath(systemPath, target)),
    )
    .sort(
      (left, right) =>
        left.target.length - right.target.length ||
        left.target.localeCompare(right.target),
    );
  const confined = [];
  for (const exposure of ordered) {
    if (
      [exposure.source, exposure.target].some(
        (path) => path === sep || path === homePath,
      )
    ) {
      throw new Error("Trusted validation exposure is too broad.");
    }
    if (
      !confined.some(({ target }) => coversPath(target, exposure.target))
    ) {
      confined.push(exposure);
    }
  }
  return confined;
}

function sandboxArguments(command, { cwd, environment, homePath }) {
  const argumentsList = [
    "--die-with-parent",
    "--unshare-net",
    "--unshare-pid",
    "--cap-drop",
    "ALL",
    "--proc",
    "/proc",
    "--dev",
    "/dev",
    "--tmpfs",
    "/run",
    "--tmpfs",
    "/tmp",
  ];
  appendSystemMounts(argumentsList);
  const createdParents = new Set();
  for (const { source, target } of dynamicExposures(command, {
    cwd,
    environment,
    homePath,
  })) {
    for (const parent of mountParents(target)) {
      if (!createdParents.has(parent)) {
        argumentsList.push("--dir", parent);
        createdParents.add(parent);
      }
    }
    argumentsList.push("--ro-bind", source, target);
  }
  argumentsList.push(
    "--chdir",
    cwd,
    "--",
    process.execPath,
    "--eval",
    READINESS_SCRIPT,
    "--",
    command.executable,
    ...command.arguments,
  );
  return Object.freeze(argumentsList);
}

export function sandboxTrustedCommand(
  command,
  {
    bubblewrapPath,
    cwd,
    environment,
    platform = process.platform,
  },
) {
  const homePath = environment.HOME;
  if (
    platform !== "linux" ||
    typeof bubblewrapPath !== "string" ||
    !isAbsolute(bubblewrapPath) ||
    typeof homePath !== "string" ||
    !isAbsolute(homePath) ||
    homePath === "/" ||
    cwd === homePath
  ) {
    throw new TrustedExecutionError(
      "Trusted validation isolation is unavailable.",
      { code: "ERR_TRUSTED_VALIDATION_ISOLATION_UNAVAILABLE" },
    );
  }
  try {
    return Object.freeze({
      command: Object.freeze({
        executable: bubblewrapPath,
        arguments: sandboxArguments(command, {
          cwd,
          environment,
          homePath,
        }),
      }),
      environment: safeEnvironment(environment),
      readinessRequired: true,
    });
  } catch (cause) {
    throw new TrustedExecutionError(
      "Trusted validation isolation is unavailable.",
      {
        cause,
        code: "ERR_TRUSTED_VALIDATION_ISOLATION_UNAVAILABLE",
      },
    );
  }
}
