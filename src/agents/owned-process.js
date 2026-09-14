import { spawn, spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
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
const OWNERSHIP_MODES = new Set(["ordinary", "native-sandbox-provider"]);
// Linux reserves this procfs inode for the initial PID namespace.
const INITIAL_PID_NAMESPACE = "pid:[4026531836]";
const activeProcesses = new Map();
const namespaceLaunchSupport = new Map();

const SUPERVISOR_SOURCE = String.raw`
const { readdirSync } = require("node:fs");
const { spawn } = require("node:child_process");
const [mode, graceText, executable, encodedArguments, extraText, initialToken] =
  process.argv.slice(1);
const grace = Number(graceText);
const argumentsList = JSON.parse(encodedArguments);
const extra = Number(extraText);
let target;
let settled = false;
let outcome;
let ownerToken = initialToken;
let retentionTimer;
function processUid(pid) {
  const status = require("node:fs").readFileSync(
    "/proc/" + pid + "/status",
    "utf8",
  );
  const match = /^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/m.exec(status);
  if (match === null) throw new Error("invalid process uid");
  return match.slice(1).map(Number);
}
function inspectOwnedAncestry(parentPid, session) {
  const seen = new Set();
  let incomplete = false;
  while (parentPid > 1 && !seen.has(parentPid)) {
    if (String(parentPid) === session) return "current";
    seen.add(parentPid);
    const ancestorPid = parentPid;
    try {
      const stat = require("node:fs").readFileSync(
        "/proc/" + ancestorPid + "/stat",
        "utf8",
      );
      const separator = stat.lastIndexOf(")");
      if (separator < 0) return null;
      const fields = stat.slice(separator + 2).trim().split(/\s+/);
      if (
        fields.length < 4 ||
        !/^\d+$/.test(fields[1]) ||
        !/^\d+$/.test(fields[3])
      ) return null;
      if (fields[3] === session) return "current";
      parentPid = Number(fields[1]);
      const environment = require("node:fs")
        .readFileSync("/proc/" + ancestorPid + "/environ", "utf8")
        .split("\0");
      if (environment.includes("AGENT_RUNNER_OWNED_PROCESS=" + ownerToken)) {
        return "current";
      }
    } catch (cause) {
      if (cause?.code === "EACCES" || cause?.code === "EPERM") {
        incomplete = true;
        continue;
      }
      return null;
    }
  }
  if (parentPid > 1 || incomplete) return null;
  return "unrelated";
}
function ownedMembers() {
  if (mode !== "session") return [];
  const session = String(process.pid);
  // The enclosing namespace may host concurrent trusted work. Limit ownership
  // to this supervisor's session and descendants carrying its launch token.
  try {
    const members = [];
    for (const name of readdirSync("/proc")) {
      if (!/^\d+$/.test(name) || name === String(process.pid)) continue;
      let parentPid;
      try {
        const stat = require("node:fs").readFileSync(
          "/proc/" + name + "/stat",
          "utf8",
        );
        const separator = stat.lastIndexOf(")");
        if (separator < 0) throw new Error("invalid process stat");
        const fields = stat.slice(separator + 2).trim().split(/\s+/);
        if (
          fields.length < 4 ||
          !/^\d+$/.test(fields[1]) ||
          !/^\d+$/.test(fields[3])
        ) {
          throw new Error("invalid process session");
        }
        parentPid = Number(fields[1]);
        if (fields[3] === session) {
          members.push(Number(name));
          continue;
        }
        if (processUid(name).some((uid) => uid !== process.getuid())) continue;
        const environment = require("node:fs")
          .readFileSync("/proc/" + name + "/environ", "utf8")
          .split("\0");
        if (environment.includes("AGENT_RUNNER_OWNED_PROCESS=" + ownerToken)) {
          members.push(Number(name));
          continue;
        }
        const ancestry = inspectOwnedAncestry(parentPid, session);
        if (ancestry === "current") members.push(Number(name));
        else if (ancestry === null) return null;
      } catch (cause) {
        if (cause?.code === "ENOENT" || cause?.code === "ESRCH") continue;
        if (
          (cause?.code === "EACCES" || cause?.code === "EPERM") &&
          parentPid !== undefined
        ) {
          const ancestry = inspectOwnedAncestry(parentPid, session);
          if (ancestry === "current") {
            members.push(Number(name));
            continue;
          }
          if (parentPid !== 1 && ancestry !== null) continue;
        }
        return null;
      }
    }
    return members;
  } catch {
    return null;
  }
}
function inspectDescendants() {
  const members = ownedMembers();
  if (mode === "session") {
    return members === null
      ? { active: true, complete: false }
      : { active: members.length > 0, complete: true };
  }
  try {
    return {
      active: readdirSync("/proc").some(
        (name) => /^\d+$/.test(name) && name !== "1",
      ),
      complete: true,
    };
  } catch {
    return { active: true, complete: false };
  }
}
function signalDescendants(signal) {
  if (mode !== "session") return true;
  const members = ownedMembers();
  if (members === null) return false;
  for (const pid of members) {
    try { process.kill(Number(pid), signal); } catch {}
  }
  return true;
}
function retainContainmentFailure(code) {
  if (process.connected) {
    process.send({ type: "containment-failure", code });
  }
  retentionTimer ??= setInterval(() => {}, 60_000);
}
function finish() {
  if (settled) return;
  settled = true;
  const report = () => {
    const initial = inspectDescendants();
    const send = (inspection, descendantsStopped = initial.active) => {
      const descendantsActive = mode === "session" && inspection.active;
      const failed = !inspection.complete || descendantsActive;
      const exit = () => process.exit(failed || descendantsStopped ? 125 : 0);
      if (process.connected) {
        process.send({
          type: "outcome",
          outcome,
          descendantsStopped,
          descendantsActive,
          inspectionComplete: inspection.complete,
        }, exit);
      } else {
        exit();
      }
    };
    if (!initial.complete) return retainContainmentFailure("unverifiable");
    if (!initial.active || mode !== "session") return send(initial);
    if (!signalDescendants("SIGTERM")) {
      return retainContainmentFailure("unverifiable");
    }
    setTimeout(() => {
      if (!signalDescendants("SIGKILL")) {
        return retainContainmentFailure("unverifiable");
      }
      const deadline = Date.now() + grace;
      const waitForExit = () => {
        const inspection = inspectDescendants();
        if (!inspection.complete) {
          return retainContainmentFailure("unverifiable");
        }
        if (!inspection.active) return send(inspection, true);
        if (Date.now() >= deadline) return retainContainmentFailure("active");
        setTimeout(waitForExit, Math.min(10, Math.max(1, grace))).unref();
      };
      waitForExit();
    }, grace).unref();
  };
  if (inspectDescendants().active) setTimeout(report, grace).unref();
  else report();
}
function terminate(signal = "SIGTERM", verify = false) {
  const inspectionComplete = signalDescendants(signal);
  if (target?.pid) {
    try { target.kill(signal); } catch {}
  }
  if (!inspectionComplete) return retainContainmentFailure("unverifiable");
  const terminationCheck = setTimeout(() => {
    if (!verify) return process.exit(124);
    const inspection = inspectDescendants();
    if (!inspection.complete) return retainContainmentFailure("unverifiable");
    if (inspection.active) return retainContainmentFailure("active");
    process.exit(124);
  }, grace);
  if (!verify) terminationCheck.unref();
}
process.on("disconnect", () => terminate("SIGKILL", true));
process.on("SIGTERM", () => terminate("SIGTERM"));
process.on("SIGINT", () => terminate("SIGINT"));
process.on("message", (message) => {
  if (message?.type === "terminate") {
    terminate(message.signal);
    return;
  }
  if (message?.type !== "start" || target !== undefined) return;
  if (typeof message.ownerToken !== "string" || message.ownerToken.length !== 64) {
    process.exit(126);
  }
  ownerToken = message.ownerToken;
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

function ownedProcessToken(pid, processIdentity) {
  return createHash("sha256")
    .update(
      `${pid}\0${processIdentity.bootId}\0${processIdentity.startTicks}`,
      "utf8",
    )
    .digest("hex");
}

function processUid(pid, read = readFileSync) {
  const status = read(`/proc/${pid}/status`, "utf8");
  const match = /^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/mu.exec(status);
  if (match === null) return null;
  return match.slice(1).map(Number);
}

function inspectOwnedAncestry(
  parentPid,
  sessionId,
  ownerToken,
  includeSession,
  read,
) {
  const seen = new Set();
  let incomplete = false;
  while (parentPid > 1 && !seen.has(parentPid)) {
    if (includeSession && parentPid === sessionId) return "current";
    seen.add(parentPid);
    const ancestorPid = parentPid;
    try {
      const stat = read(`/proc/${ancestorPid}/stat`, "utf8");
      const separator = stat.lastIndexOf(")");
      if (separator < 0) return null;
      const fields = stat
        .slice(separator + 2)
        .trim()
        .split(/\s+/u);
      if (
        fields.length < 4 ||
        !/^\d+$/u.test(fields[1]) ||
        !/^\d+$/u.test(fields[3])
      )
        return null;
      if (includeSession && fields[3] === String(sessionId)) return "current";
      parentPid = Number(fields[1]);
      const environment = read(`/proc/${ancestorPid}/environ`, "utf8").split(
        "\0",
      );
      if (environment.includes(`AGENT_RUNNER_OWNED_PROCESS=${ownerToken}`)) {
        return "current";
      }
    } catch (cause) {
      if (["EACCES", "EPERM"].includes(cause?.code)) {
        incomplete = true;
        continue;
      }
      return null;
    }
  }
  if (parentPid > 1 || incomplete) return null;
  return "unrelated";
}

export function inspectOwnedSessionProcesses(
  sessionId,
  ownerToken,
  {
    getuid = () => process.getuid(),
    includeSession = true,
    list = readdirSync,
    read = readFileSync,
  } = {},
) {
  try {
    const members = [];
    for (const name of list("/proc")) {
      if (!/^\d+$/u.test(name)) continue;
      const pid = Number(name);
      let parentPid;
      try {
        const stat = read(`/proc/${pid}/stat`, "utf8");
        const separator = stat.lastIndexOf(")");
        if (separator < 0) return null;
        const fields = stat
          .slice(separator + 2)
          .trim()
          .split(/\s+/u);
        if (
          fields.length < 4 ||
          !/^\d+$/u.test(fields[1]) ||
          !/^\d+$/u.test(fields[3])
        )
          return null;
        parentPid = Number(fields[1]);
        if (includeSession && fields[3] === String(sessionId)) {
          members.push(pid);
          continue;
        }
        const uids = processUid(pid, read);
        if (uids === null) return null;
        if (uids.some((uid) => uid !== getuid())) continue;
        const environment = read(`/proc/${pid}/environ`, "utf8");
        if (
          environment
            .split("\0")
            .includes(`AGENT_RUNNER_OWNED_PROCESS=${ownerToken}`)
        ) {
          members.push(pid);
          continue;
        }
        const ancestry = inspectOwnedAncestry(
          parentPid,
          sessionId,
          ownerToken,
          includeSession,
          read,
        );
        if (ancestry === "current") members.push(pid);
        else if (ancestry === null) return null;
      } catch (cause) {
        if (["ENOENT", "ESRCH"].includes(cause?.code)) continue;
        if (
          ["EACCES", "EPERM"].includes(cause?.code) &&
          parentPid !== undefined
        ) {
          const ancestry = inspectOwnedAncestry(
            parentPid,
            sessionId,
            ownerToken,
            includeSession,
            read,
          );
          if (ancestry === "current") {
            members.push(pid);
            continue;
          }
          if (parentPid !== 1 && ancestry !== null) continue;
        }
        return null;
      }
    }
    return members;
  } catch {
    return null;
  }
}

function signalSession(sessionId, ownerToken, signal) {
  const members = inspectOwnedSessionProcesses(sessionId, ownerToken);
  if (members === null) {
    throw ownedError(
      "Owned process descendants are unverifiable.",
      "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
    );
  }
  for (const pid of members) {
    try {
      process.kill(pid, signal);
    } catch (cause) {
      if (cause?.code !== "ESRCH") throw cause;
    }
  }
}

function namespaceProbeArguments(bubblewrap, nativeSandboxProvider) {
  const inner = nativeSandboxProvider
    ? [
        bubblewrap,
        "--new-session",
        "--die-with-parent",
        "--unshare-user",
        "--unshare-pid",
        "--unshare-net",
        "--as-pid-1",
        "--cap-drop",
        "ALL",
        "--ro-bind",
        "/",
        "/",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--",
        "/bin/true",
      ]
    : ["/bin/true"];
  return [
    "--die-with-parent",
    "--unshare-pid",
    "--as-pid-1",
    nativeSandboxProvider ? "--bind" : "--ro-bind",
    "/",
    "/",
    "--dev",
    "/dev",
    "--proc",
    "/proc",
    "--chdir",
    "/",
    "--",
    ...inner,
  ];
}

function supportsNamespaceLaunch(
  bubblewrap,
  namespaceId,
  nativeSandboxProvider,
  { cache = namespaceLaunchSupport, probe = spawnSync } = {},
) {
  const key = [
    bubblewrap,
    namespaceId,
    nativeSandboxProvider ? "provider" : "ordinary",
  ].join("\0");
  if (cache.has(key)) return cache.get(key);
  const result = probe(
    bubblewrap,
    namespaceProbeArguments(bubblewrap, nativeSandboxProvider),
    { stdio: "ignore", timeout: 10_000 },
  );
  if (
    result.error !== undefined ||
    (result.signal !== null && result.signal !== undefined) ||
    ![0, 1].includes(result.status)
  ) {
    throw ownedError(
      "Owned-process namespace capability is unverifiable.",
      "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
      result.error,
    );
  }
  const supported = result.status === 0;
  cache.set(key, supported);
  return supported;
}

export function resolveOwnedProcessLauncher(
  cwd,
  {
    bubblewrap = resolveBubblewrap(),
    cache = namespaceLaunchSupport,
    namespaceId = currentPidNamespace(),
    ownershipMode = "ordinary",
    probe = spawnSync,
  } = {},
) {
  if (!OWNERSHIP_MODES.has(ownershipMode)) {
    throw ownedError(
      "Owned-process supervision mode is invalid.",
      "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
    );
  }
  const nativeSandboxProvider = ownershipMode === "native-sandbox-provider";
  if (
    supportsNamespaceLaunch(bubblewrap, namespaceId, nativeSandboxProvider, {
      cache,
      probe,
    })
  ) {
    return {
      file: bubblewrap,
      arguments: [
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
        process.execPath,
        "-e",
        SUPERVISOR_SOURCE,
        "namespace",
      ],
      isolatedNamespace: true,
    };
  }
  // A non-initial enclosing namespace remains the ultimate containment
  // boundary when its policy denies creating another nested namespace. On the
  // initial namespace this narrower mode is available only to a provider that
  // will establish its own mandatory native sandbox before model-issued work.
  const enclosingNamespaceCanBeReused =
    namespaceId !== null && namespaceId !== INITIAL_PID_NAMESPACE;
  const providerCanUseHostSession =
    namespaceId === INITIAL_PID_NAMESPACE && nativeSandboxProvider;
  if (!enclosingNamespaceCanBeReused && !providerCanUseHostSession) {
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
    ownershipMode = "ordinary",
    signal,
    stdio: requestedStdio,
    ...spawnOptions
  } = options;
  if (
    typeof onProcess !== "function" ||
    !OWNERSHIP_MODES.has(ownershipMode) ||
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
  const launcher = resolveOwnedProcessLauncher(cwd, {
    ownershipMode,
  });
  let ownerToken = randomUUID();
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
  let containmentFailure = null;
  const kill = (signal) => {
    if (!launcher.isolatedNamespace) {
      try {
        signalSession(child.pid, ownerToken, signal);
      } catch (cause) {
        containmentFailure ??= cause;
        return false;
      }
    }
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
      let terminationContainmentVerified = false;
      if (
        !launcher.isolatedNamespace &&
        registered &&
        supervision === null &&
        terminationRequested &&
        containmentFailure === null
      ) {
        const members = inspectOwnedSessionProcesses(child.pid, ownerToken);
        if (members === null) {
          containmentFailure = ownedError(
            "Owned process descendants are unverifiable.",
            "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
          );
        } else {
          terminationContainmentVerified = members.length === 0;
        }
      }
      const safelyStopped =
        launcher.isolatedNamespace ||
        (supervision?.inspectionComplete === true &&
          supervision.descendantsActive !== true) ||
        (terminationRequested && terminationContainmentVerified);
      if (registered && safelyStopped) {
        try {
          await onProcess(null);
        } catch (cause) {
          reject(cause);
          return;
        }
      }
      if (failure !== null) {
        reject(failure);
        return;
      }
      if (containmentFailure !== null) {
        reject(containmentFailure);
        return;
      }
      if (supervision === null) {
        if (registered && safelyStopped) {
          resolve({
            outcome: { type: "close", exitCode: null, signal: "SIGKILL" },
            descendantsStopped: true,
          });
          return;
        }
        reject(
          ownedError(
            registered && !safelyStopped
              ? "Owned process ended without safe descendant evidence."
              : "Owned process ended without supervision evidence.",
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
      if (message?.type === "containment-failure") {
        const unverifiable = message.code === "unverifiable";
        rejectCompletion?.(
          ownedError(
            unverifiable
              ? "Owned process descendants are unverifiable."
              : "Owned process descendants did not terminate within their bound.",
            unverifiable
              ? "ERR_EXECUTION_PROCESS_UNVERIFIABLE"
              : "ERR_EXECUTION_PROCESS_ACTIVE",
          ),
        );
        return;
      }
      if (message?.type === "outcome") {
        supervision = message;
        if (message.inspectionComplete !== true) {
          failure = ownedError(
            "Owned process descendants are unverifiable.",
            "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
          );
        } else if (message.descendantsActive === true) {
          failure = ownedError(
            "Owned process descendants did not terminate within their bound.",
            "ERR_EXECUTION_PROCESS_ACTIVE",
          );
        }
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
        ownerToken = ownedProcessToken(child.ownedPid, processIdentity);
        if (closed) return;
        activeProcesses.set(child.ownedPid, child);
        child.send({ type: "start", ownerToken }, (cause) => {
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

export async function terminateOwnedProcess(
  pid,
  inspect,
  { inspectSessionProcesses = inspectOwnedSessionProcesses } = {},
) {
  const child = activeProcesses.get(pid);
  if (child !== undefined) {
    child.kill("SIGKILL");
    await child.ownedCompletion;
    return;
  }
  const owner = await inspect();
  if (owner === null || owner.previousBoot === true) return;
  if (["dead", "replaced"].includes(owner.status)) {
    if (owner.namespaceId === null) return;
    const namespaceId = await readProcessNamespace(process.pid);
    if (namespaceId === null || owner.processIdentity === null) {
      throw ownedError(
        "Owned execution process cannot be safely reconciled.",
        "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
      );
    }
    if (owner.namespaceId !== namespaceId) {
      if (owner.namespaceId === INITIAL_PID_NAMESPACE) {
        throw ownedError(
          "Owned host-session descendants are not visible from this namespace.",
          "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
        );
      }
      return;
    }
    const members = inspectSessionProcesses(
      owner.pid,
      ownedProcessToken(owner.pid, owner.processIdentity),
      { includeSession: owner.status === "dead" },
    );
    if (members === null) {
      throw ownedError(
        "Owned execution process descendants are unverifiable.",
        "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
      );
    }
    if (members.length > 0) {
      throw ownedError(
        "Owned execution process descendants remain active.",
        "ERR_EXECUTION_PROCESS_ACTIVE",
      );
    }
    return;
  }
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
