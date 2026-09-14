import { spawn, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  accessSync,
  constants,
  existsSync,
  lstatSync,
  readdirSync,
  readFileSync,
  readlinkSync,
  realpathSync,
} from "node:fs";
import { dirname, isAbsolute, sep } from "node:path";

import {
  readProcessChildren,
  readProcessIdentity,
  readProcessNamespace,
} from "./process-containment.js";

const BUBBLEWRAP_CANDIDATES = Object.freeze([
  "/usr/bin/bwrap",
  "/bin/bwrap",
  "/usr/local/bin/bwrap",
  "/usr/local/sbin/bwrap",
]);
const DEFAULT_DESCENDANT_GRACE_MS = 1_000;
// Linux reserves this procfs inode for the initial PID namespace.
const INITIAL_PID_NAMESPACE = "pid:[4026531836]";
const activeProcesses = new Map();
const namespaceLaunchSupport = new Map();

const SUPERVISOR_SOURCE = String.raw`
const { readdirSync } = require("node:fs");
const { spawn } = require("node:child_process");
const [mode, graceText, executable, encodedArguments, extraText, ownerToken] = process.argv.slice(1);
const grace = Number(graceText);
const argumentsList = JSON.parse(encodedArguments);
const extra = Number(extraText);
let target;
let settled = false;
let outcome;
function ownedMembers() {
  if (mode !== "session") return [];
  const session = String(process.pid);
  // The enclosing namespace may host concurrent trusted work. Limit ownership
  // to this supervisor's session and descendants carrying its launch token.
  try {
    return readdirSync("/proc").filter((name) => {
      if (!/^\d+$/.test(name) || name === String(process.pid)) return false;
      try {
        const stat = require("node:fs").readFileSync("/proc/" + name + "/stat", "utf8");
        const fields = stat.slice(stat.lastIndexOf(")") + 2).trim().split(/\s+/);
        if (fields[3] === session) return true;
        const environment = require("node:fs")
          .readFileSync("/proc/" + name + "/environ", "utf8")
          .split("\0");
        return environment.includes("AGENT_RUNNER_OWNED_PROCESS=" + ownerToken);
      } catch {
        return false;
      }
    });
  } catch {
    return null;
  }
}
function descendantsExist() {
  const members = ownedMembers();
  if (members !== null && mode === "session") return members.length > 0;
  try {
    return readdirSync("/proc").some((name) => /^\d+$/.test(name) && name !== "1");
  } catch {
    return true;
  }
}
function signalDescendants(signal) {
  if (mode !== "session") return;
  for (const pid of ownedMembers() ?? []) {
    try { process.kill(Number(pid), signal); } catch {}
  }
}
function finish() {
  if (settled) return;
  settled = true;
  const report = () => {
    const descendantsStopped = descendantsExist();
    const send = () => {
      const exit = () => process.exit(descendantsStopped ? 125 : 0);
      if (process.connected) {
        process.send({ type: "outcome", outcome, descendantsStopped }, exit);
      } else {
        exit();
      }
    };
    if (!descendantsStopped || mode !== "session") return send();
    signalDescendants("SIGTERM");
    setTimeout(() => {
      signalDescendants("SIGKILL");
      const deadline = Date.now() + grace;
      const waitForExit = () => {
        if (!descendantsExist() || Date.now() >= deadline) return send();
        setTimeout(waitForExit, Math.min(10, Math.max(1, grace))).unref();
      };
      waitForExit();
    }, grace).unref();
  };
  if (descendantsExist()) setTimeout(report, grace).unref();
  else report();
}
function terminate(signal = "SIGTERM") {
  signalDescendants(signal);
  if (target?.pid) {
    try { target.kill(signal); } catch {}
  }
  setTimeout(() => process.exit(124), grace).unref();
}
process.on("disconnect", () => terminate("SIGKILL"));
process.on("SIGTERM", () => terminate("SIGTERM"));
process.on("SIGINT", () => terminate("SIGINT"));
process.on("message", (message) => {
  if (message?.type === "terminate") {
    terminate(message.signal);
    return;
  }
  if (message?.type !== "start" || target !== undefined) return;
  const stdio = [0, 1, 2];
  for (let index = 0; index < extra; index += 1) stdio.push(index + 4);
  try {
    target = spawn(executable, argumentsList, {
      env: { ...process.env, AGENT_RUNNER_OWNED_PROCESS: ownerToken },
      stdio,
    });
  } catch {
    outcome = { type: "error" };
    finish();
    return;
  }
  target.once("error", () => {
    outcome = { type: "error" };
    finish();
  });
  target.once("exit", (exitCode, signal) => {
    outcome = { type: "close", exitCode, signal };
    finish();
  });
});
if (process.connected) process.send({ type: "ready" });
`.trim();

function ownedError(message, code, cause) {
  return Object.assign(
    new Error(message, cause === undefined ? {} : { cause }),
    {
      code,
    },
  );
}

function decodeMountPath(value) {
  return value.replace(/\\([0-7]{3})/gu, (_match, octal) =>
    String.fromCharCode(Number.parseInt(octal, 8)),
  );
}

function readMountTable() {
  const mounts = readFileSync("/proc/self/mountinfo", "utf8")
    .trim()
    .split("\n")
    .map((line) => {
      const fields = line.split(" ");
      const separator = fields.indexOf("-");
      if (separator < 6) {
        throw ownedError(
          "Owned-process mount protection is unavailable.",
          "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
        );
      }
      const mountPoint = decodeMountPath(fields[4]);
      if (!isAbsolute(mountPoint)) {
        throw ownedError(
          "Owned-process mount protection is unavailable.",
          "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
        );
      }
      const options = fields[5].split(",");
      if (options.includes("ro") === options.includes("rw")) {
        throw ownedError(
          "Owned-process mount protection is unavailable.",
          "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
        );
      }
      return {
        id: Number(fields[0]),
        mountPoint,
        readOnly: options.includes("ro"),
      };
    });
  if (
    mounts.length === 0 ||
    mounts.some(({ id }) => !Number.isSafeInteger(id) || id < 1)
  ) {
    throw ownedError(
      "Owned-process mount protection is unavailable.",
      "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
    );
  }
  return mounts;
}

function mountCoversPath(mountPoint, path) {
  return (
    mountPoint === path ||
    mountPoint === sep ||
    path.startsWith(`${mountPoint}${sep}`)
  );
}

function effectiveMount(path, mounts) {
  let selected = null;
  for (const mount of mounts) {
    if (
      mountCoversPath(mount.mountPoint, path) &&
      (selected === null ||
        mount.mountPoint.length > selected.mountPoint.length ||
        (mount.mountPoint.length === selected.mountPoint.length &&
          mount.id > selected.id))
    ) {
      selected = mount;
    }
  }
  return selected;
}

function runnerCanWrite(path) {
  try {
    accessSync(path, constants.W_OK);
    return true;
  } catch (cause) {
    if (["EACCES", "EPERM", "EROFS"].includes(cause?.code)) return false;
    throw cause;
  }
}

export function assertOwnedProcessLauncherProtected(
  path,
  { canWrite = runnerCanWrite, mounts = readMountTable() } = {},
) {
  let current = path;
  let readOnlyAnchor = null;
  while (true) {
    const mount = effectiveMount(current, mounts);
    if (
      mount === null ||
      lstatSync(current).isSymbolicLink() ||
      (readOnlyAnchor !== null &&
        (!mount.readOnly || mount.mountPoint !== readOnlyAnchor)) ||
      (readOnlyAnchor === null && !mount.readOnly && canWrite(current))
    ) {
      throw ownedError(
        "Owned-process launcher is writable by the runner identity.",
        "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
      );
    }
    if (readOnlyAnchor === null && mount.readOnly) {
      readOnlyAnchor = mount.mountPoint;
    }
    if (current === readOnlyAnchor) return;
    if (current === sep) return;
    current = dirname(current);
  }
}

function resolveBubblewrap() {
  if (process.platform !== "linux") {
    throw ownedError(
      "Owned process containment requires Linux.",
      "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
    );
  }
  let failure;
  for (const candidate of BUBBLEWRAP_CANDIDATES) {
    if (!existsSync(candidate)) continue;
    try {
      const canonical = realpathSync(candidate);
      const metadata = lstatSync(canonical);
      if (!isAbsolute(canonical) || !metadata.isFile() || metadata.nlink !== 1)
        continue;
      accessSync(canonical, constants.X_OK);
      assertOwnedProcessLauncherProtected(canonical);
      return canonical;
    } catch (cause) {
      failure = cause;
    }
  }
  throw ownedError(
    "Owned-process launcher is unavailable.",
    "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
    failure,
  );
}

function currentPidNamespace() {
  try {
    return readlinkSync("/proc/self/ns/pid");
  } catch {
    return null;
  }
}

function sessionMembers(sessionId, ownerToken) {
  try {
    return readdirSync("/proc")
      .filter((name) => /^\d+$/u.test(name))
      .map(Number)
      .filter((pid) => {
        try {
          const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
          const fields = stat
            .slice(stat.lastIndexOf(")") + 2)
            .trim()
            .split(/\s+/u);
          if (fields[3] === String(sessionId)) return true;
          const environment = readFileSync(`/proc/${pid}/environ`, "utf8");
          return environment
            .split("\0")
            .includes(`AGENT_RUNNER_OWNED_PROCESS=${ownerToken}`);
        } catch {
          return false;
        }
      });
  } catch {
    return [];
  }
}

function signalSession(sessionId, ownerToken, signal) {
  for (const pid of sessionMembers(sessionId, ownerToken)) {
    try {
      process.kill(pid, signal);
    } catch (cause) {
      if (cause?.code !== "ESRCH") throw cause;
    }
  }
}

function supportsNestedPidNamespace(bubblewrap, namespaceId) {
  if (namespaceLaunchSupport.has(namespaceId))
    return namespaceLaunchSupport.get(namespaceId);
  const probe = spawnSync(
    bubblewrap,
    [
      "--die-with-parent",
      "--unshare-pid",
      "--as-pid-1",
      "--ro-bind",
      "/",
      "/",
      "--proc",
      "/proc",
      "--",
      "/bin/true",
    ],
    { stdio: "ignore" },
  );
  const supported = probe.status === 0;
  namespaceLaunchSupport.set(namespaceId, supported);
  return supported;
}

function resolveLauncher(cwd) {
  const bubblewrap = resolveBubblewrap();
  const namespaceId = currentPidNamespace();
  if (supportsNestedPidNamespace(bubblewrap, namespaceId)) {
    return {
      file: bubblewrap,
      arguments: [
        "--die-with-parent",
        "--unshare-pid",
        "--as-pid-1",
        "--bind",
        "/",
        "/",
        "--proc",
        "/proc",
        "--chdir",
        cwd,
        "--",
        process.execPath,
        "-e",
        SUPERVISOR_SOURCE,
        "namespace",
      ],
      isolatedNamespace: true,
    };
  }
  // A non-initial enclosing namespace remains the ultimate containment
  // boundary when its policy denies creating another nested namespace.
  const enclosingNamespaceCanBeReused =
    namespaceId !== null && namespaceId !== INITIAL_PID_NAMESPACE;
  if (!enclosingNamespaceCanBeReused) {
    throw ownedError(
      "Owned process PID isolation is unavailable.",
      "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
    );
  }
  return {
    file: process.execPath,
    arguments: ["-e", SUPERVISOR_SOURCE, "session"],
    isolatedNamespace: false,
  };
}

function normalizedStdio(value) {
  if (value === undefined) return ["pipe", "pipe", "pipe"];
  if (typeof value === "string") return [value, value, value];
  if (!Array.isArray(value)) {
    throw ownedError(
      "Owned-process stdio is invalid.",
      "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
    );
  }
  return [...value];
}

export function spawnOwnedProcess(file, argumentsList = [], options = {}) {
  if (typeof file !== "string" || !Array.isArray(argumentsList)) {
    throw ownedError(
      "Owned-process command is invalid.",
      "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
    );
  }
  const {
    descendantGraceMs = DEFAULT_DESCENDANT_GRACE_MS,
    onProcess,
    signal,
    stdio: requestedStdio,
    ...spawnOptions
  } = options;
  if (
    typeof onProcess !== "function" ||
    !Number.isSafeInteger(descendantGraceMs) ||
    descendantGraceMs < 0
  ) {
    throw ownedError(
      "Owned-process supervision options are invalid.",
      "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
    );
  }
  signal?.throwIfAborted();
  const stdio = normalizedStdio(requestedStdio);
  const extra = Math.max(0, stdio.length - 3);
  const cwd = spawnOptions.cwd ?? process.cwd();
  const launcher = resolveLauncher(cwd);
  const ownerToken = randomUUID();
  const child = spawn(
    launcher.file,
    [
      ...launcher.arguments,
      String(descendantGraceMs),
      file,
      JSON.stringify(argumentsList),
      String(extra),
      ownerToken,
    ],
    {
      ...spawnOptions,
      detached: true,
      shell: false,
      stdio: [...stdio.slice(0, 3), "ipc", ...stdio.slice(3)],
    },
  );
  child.ownedPid = child.pid;
  let terminationRequested = false;
  let terminationTimer;
  let terminationFailureTimer;
  let rejectCompletion;
  const killChild = child.kill.bind(child);
  const kill = (signal) => {
    if (!launcher.isolatedNamespace)
      signalSession(child.pid, ownerToken, signal);
    return killChild(signal);
  };
  child.kill = (signal = "SIGTERM") => {
    if (child.exitCode !== null || child.signalCode !== null) return false;
    terminationRequested = true;
    if (child.connected) {
      try {
        child.send({ type: "terminate", signal }, (cause) => {
          if (cause !== null && cause !== undefined) kill(signal);
        });
      } catch {
        kill(signal);
      }
    } else {
      kill(signal);
    }
    if (terminationTimer === undefined) {
      terminationTimer = setTimeout(() => {
        kill("SIGKILL");
      }, descendantGraceMs);
      terminationTimer.unref();
      terminationFailureTimer = setTimeout(
        () => {
          rejectCompletion?.(
            ownedError(
              "Owned process namespace did not terminate within its bound.",
              "ERR_EXECUTION_PROCESS_ACTIVE",
            ),
          );
        },
        descendantGraceMs * 2 + 1,
      );
      terminationFailureTimer.unref();
    }
    return true;
  };
  let abort;
  child.ownedCompletion = new Promise((resolve, reject) => {
    rejectCompletion = reject;
    let registered = false;
    let registration = null;
    let failure = null;
    let supervision = null;
    let closed = false;
    let settled = false;
    const finish = async () => {
      if (settled || !closed) return;
      // A successful durable registration must be cleared before completion.
      if (registration !== null) {
        await registration.catch(() => {});
        if (settled || !closed) return;
      }
      settled = true;
      clearTimeout(terminationTimer);
      clearTimeout(terminationFailureTimer);
      signal?.removeEventListener("abort", abort);
      activeProcesses.delete(child.ownedPid);
      try {
        if (registered) await onProcess(null);
      } catch (cause) {
        reject(cause);
        return;
      }
      if (failure !== null) {
        reject(failure);
        return;
      }
      if (supervision === null) {
        if (registered && terminationRequested) {
          resolve({
            outcome: { type: "close", exitCode: null, signal: "SIGKILL" },
            descendantsStopped: true,
          });
          return;
        }
        reject(
          ownedError(
            "Owned process ended without supervision evidence.",
            "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
          ),
        );
        return;
      }
      resolve(supervision);
    };
    child.once("error", (cause) => {
      failure = cause;
      supervision = { outcome: { type: "error" }, descendantsStopped: false };
      closed = true;
      void finish();
    });
    child.once("close", () => {
      closed = true;
      void finish();
    });
    child.on("message", async (message) => {
      if (message?.type === "outcome") {
        supervision = message;
        return;
      }
      if (message?.type !== "ready" || registered || registration !== null)
        return;
      registration = (async () => {
        const children = await readProcessChildren(child.pid);
        if (children !== null && children.length > 1) {
          throw ownedError(
            "Owned process namespace identity is ambiguous.",
            "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
          );
        }
        child.ownedPid = children?.[0] ?? child.pid;
        const [processIdentity, namespaceId, runnerNamespaceId] =
          await Promise.all([
            readProcessIdentity(child.ownedPid),
            readProcessNamespace(child.ownedPid),
            readProcessNamespace(process.pid),
          ]);
        const proof = { processIdentity, namespaceId };
        if (
          processIdentity === null ||
          namespaceId === null ||
          runnerNamespaceId === null ||
          (launcher.isolatedNamespace
            ? namespaceId === runnerNamespaceId
            : namespaceId !== runnerNamespaceId)
        ) {
          throw ownedError(
            "Owned process identity is unavailable.",
            "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
          );
        }
        await onProcess(child.ownedPid, proof);
        registered = true;
        if (closed) return;
        activeProcesses.set(child.ownedPid, child);
        child.send({ type: "start" }, (cause) => {
          if (cause !== null && cause !== undefined) child.kill("SIGKILL");
        });
      })();
      try {
        await registration;
      } catch (cause) {
        failure = cause;
        supervision = { outcome: { type: "error" }, descendantsStopped: false };
        child.kill("SIGKILL");
      } finally {
        registration = null;
        if (closed) void finish();
      }
    });
    abort = () => child.kill("SIGKILL");
    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted) abort();
  });
  return child;
}

export async function terminateOwnedProcess(pid, inspect) {
  const child = activeProcesses.get(pid);
  if (child !== undefined) {
    child.kill("SIGKILL");
    await child.ownedCompletion;
    return;
  }
  const owner = await inspect();
  if (
    owner === null ||
    owner.previousBoot === true ||
    ["dead", "replaced"].includes(owner.status)
  )
    return;
  throw ownedError(
    "Owned execution process cannot be safely terminated.",
    owner.status === "unverifiable"
      ? "ERR_EXECUTION_PROCESS_UNVERIFIABLE"
      : "ERR_EXECUTION_PROCESS_ACTIVE",
  );
}

export async function executeOwnedProcess(file, argumentsList, options = {}) {
  const {
    encoding = "utf8",
    input,
    maxBuffer = 1024 * 1024,
    ...spawnOptions
  } = options;
  const child = spawnOwnedProcess(file, argumentsList, {
    ...spawnOptions,
    stdio: ["pipe", "pipe", "pipe"],
  });
  const output = { stdout: [], stderr: [] };
  let size = 0;
  for (const [name, stream] of [
    ["stdout", child.stdout],
    ["stderr", child.stderr],
  ]) {
    stream.on("data", (chunk) => {
      size += chunk.length;
      output[name].push(chunk);
      if (size > maxBuffer) child.kill("SIGKILL");
    });
  }
  if (input !== undefined) child.stdin.end(input);
  else child.stdin.end();
  const supervision = await child.ownedCompletion;
  const stdout = Buffer.concat(output.stdout).toString(encoding);
  const stderr = Buffer.concat(output.stderr).toString(encoding);
  if (size > maxBuffer) {
    throw Object.assign(new Error("Owned process output exceeded maxBuffer."), {
      code: "ERR_CHILD_PROCESS_STDIO_MAXBUFFER",
      stdout,
      stderr,
    });
  }
  const outcome = supervision.outcome;
  if (outcome?.type !== "close" || outcome.exitCode !== 0) {
    throw Object.assign(new Error("Owned process failed."), {
      code: outcome?.exitCode ?? "ERR_OWNED_PROCESS_FAILED",
      signal: outcome?.signal ?? null,
      stdout,
      stderr,
    });
  }
  return { stdout, stderr };
}
