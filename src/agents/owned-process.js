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
  readProcessControlGroup,
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
const OWNED_PROCESS_INSPECTION_ATTEMPTS = 3;
const MAX_PROCESS_ANCESTRY_BASELINE_ENTRIES = 4_096;
const MAX_INSPECTION_WORK = 65_536;
const MAX_INSPECTION_MS = 250;

// Both live supervision and replacement-owner inspection use this same bound.
// Charge reads, entries, and ancestry hops; a slow final read must also fail.
function inspectionBudget(now, maxWork, maxElapsedMs) {
  const started = now();
  let spent = 0;
  return (amount = 1) => {
    const elapsed = now() - started;
    spent += amount;
    if (
      !Number.isFinite(elapsed) ||
      elapsed < 0 ||
      elapsed >= maxElapsedMs ||
      spent > maxWork
    ) {
      throw new Error("Ownership inspection budget exhausted.");
    }
  };
}

const OWNERSHIP_MODES = new Set(["ordinary", "native-sandbox-provider"]);
// Linux reserves this procfs inode for the initial PID namespace.
const INITIAL_PID_NAMESPACE = "pid:[4026531836]";
const activeProcesses = new Map();
const namespaceLaunchSupport = new Map();

const SUPERVISOR_SOURCE = String.raw`
const { readdirSync } = require("node:fs");
const { spawn } = require("node:child_process");
const { createHash } = require("node:crypto");
const [mode, graceText, executable, encodedArguments, extraText, initialToken] =
  process.argv.slice(1);
const grace = Number(graceText);
const argumentsList = JSON.parse(encodedArguments);
const extra = Number(extraText);
const OWNED_PROCESS_INSPECTION_ATTEMPTS = ${OWNED_PROCESS_INSPECTION_ATTEMPTS};
let target;
let settled = false;
let outcome;
let ownerToken = initialToken;
let launchCutoff;
let ancestryBaseline;
let controlGroup;
let retentionTimer;
const inspectionBudget = ${inspectionBudget.toString()};
let charge;
function readProc(path, encoding) {
  charge();
  try { return require("node:fs").readFileSync(path, encoding); }
  finally { charge(0); }
}

function processStatDetails(stat) {
  const separator = stat.lastIndexOf(")");
  if (separator < 0) return null;
  const fields = stat.slice(separator + 2).trim().split(/\s+/);
  if (
    fields.length < 20 ||
    !/^\d+$/.test(fields[1]) ||
    !/^\d+$/.test(fields[3]) ||
    !/^(?:0|[1-9]\d{0,31})$/.test(fields[19])
  ) return null;
  return {
    parentPid: Number(fields[1]),
    sessionId: fields[3],
    startTicks: fields[19],
  };
}
function normalizedLaunchCutoff(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length !== 2 ||
    typeof value.bootId !== "string" ||
    !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value.bootId) ||
    typeof value.startTicks !== "string" ||
    !/^(?:0|[1-9]\d{0,31})$/.test(value.startTicks)
  ) return null;
  return value;
}
function normalizedAncestryBaseline(value, cutoff) {
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    value.length > ${MAX_PROCESS_ANCESTRY_BASELINE_ENTRIES}
  ) return null;
  let previousPid = 0;
  const identities = new Map();
  for (const entry of value) {
    if (
      entry === null ||
      typeof entry !== "object" ||
      Array.isArray(entry) ||
      Object.keys(entry).length !== 3 ||
      typeof entry.bootId !== "string" ||
      !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(entry.bootId) ||
      !Number.isSafeInteger(entry.pid) ||
      entry.pid <= previousPid ||
      typeof entry.startTicks !== "string" ||
      !/^(?:0|[1-9]\d{0,31})$/.test(entry.startTicks) ||
      entry.bootId !== cutoff.bootId
    ) return null;
    previousPid = entry.pid;
    identities.set(entry.pid, entry.startTicks);
  }
  return identities;
}
function isBaselineIdentity(pid, startTicks) {
  return ancestryBaseline?.get(pid) === startTicks;
}
function processUid(pid) {
  const status = readProc(
    "/proc/" + pid + "/status",
    "utf8",
  );
  const match = /^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/m.exec(status);
  if (match === null) throw new Error("invalid process uid");
  return match.slice(1).map(Number);
}
function processControlGroup(pid) {
  const source = readProc(
    "/proc/" + pid + "/cgroup",
    "utf8",
  );
  if (
    Buffer.byteLength(source) === 0 ||
    Buffer.byteLength(source) > 64 * 1024 ||
    !source.endsWith("\n")
  ) throw new Error("invalid process control group");
  return createHash("sha256").update(source).digest("hex");
}
function verifyProcessDetails(pid, expected) {
  try {
    const current = processStatDetails(
      readProc("/proc/" + pid + "/stat", "utf8"),
    );
    if (current === null || current.startTicks !== expected.startTicks) {
      return null;
    }
    return current.parentPid === expected.parentPid &&
      current.sessionId === expected.sessionId
      ? "stable"
      : "retry";
  } catch (cause) {
    return cause?.code === "ENOENT" || cause?.code === "ESRCH"
      ? "retry"
      : null;
  }
}
function inspectOwnedAncestry(parentPid, session) {
  const seen = new Set();
  while (parentPid > 0 && !seen.has(parentPid)) {
    charge();
    if (String(parentPid) === session) return "current";
    seen.add(parentPid);
    const ancestorPid = parentPid;
    let details;
    try {
      details = processStatDetails(
        readProc(
          "/proc/" + ancestorPid + "/stat",
          "utf8",
        ),
      );
      if (details === null) return null;
      if (details.sessionId === session) {
        const verification = verifyProcessDetails(ancestorPid, details);
        return verification === "stable" ? "current" : verification;
      }
      const environment = readProc("/proc/" + ancestorPid + "/environ", "utf8")
        .split("\0");
      const verification = verifyProcessDetails(ancestorPid, details);
      if (verification !== "stable") return verification;
      if (environment.includes("AGENT_RUNNER_OWNED_PROCESS=" + ownerToken)) {
        return "current";
      }
      if (isBaselineIdentity(ancestorPid, details.startTicks)) {
        return "anchored";
      }
      parentPid = details.parentPid;
    } catch (cause) {
      if (cause?.code === "ENOENT" || cause?.code === "ESRCH") return "retry";
      if (cause?.code === "EACCES" || cause?.code === "EPERM") {
        if (details === undefined) return null;
        const verification = verifyProcessDetails(ancestorPid, details);
        if (verification !== "stable") return verification;
        if (isBaselineIdentity(ancestorPid, details.startTicks)) {
          return "anchored";
        }
        parentPid = details.parentPid;
        continue;
      }
      return null;
    }
  }
  return null;
}
function inspectSessionProcess(pid, session) {
  let pinnedStartTicks;
  for (
    let attempt = 0;
    attempt < OWNED_PROCESS_INSPECTION_ATTEMPTS;
    attempt += 1
  ) {
    let details;
    try {
      details = processStatDetails(
        readProc("/proc/" + pid + "/stat", "utf8"),
      );
    } catch (cause) {
      if (cause?.code === "ENOENT" || cause?.code === "ESRCH") return "absent";
      return null;
    }
    if (details === null) return null;
    if (pinnedStartTicks === undefined) pinnedStartTicks = details.startTicks;
    else if (details.startTicks !== pinnedStartTicks) return null;

    let ownership;
    try {
      if (details.sessionId === session) ownership = "current";
      else if (processUid(pid).some((uid) => uid !== process.getuid())) {
        ownership = "unrelated";
      } else {
        const environment = readProc("/proc/" + pid + "/environ", "utf8")
          .split("\0");
        if (environment.includes("AGENT_RUNNER_OWNED_PROCESS=" + ownerToken)) {
          ownership = "current";
        } else if (isBaselineIdentity(pid, details.startTicks)) {
          ownership = "anchored";
        } else {
          ownership = inspectOwnedAncestry(details.parentPid, session);
        }
      }
    } catch (cause) {
      if (cause?.code === "ENOENT" || cause?.code === "ESRCH") {
        ownership = "retry";
      } else if (cause?.code === "EACCES" || cause?.code === "EPERM") {
        const verification = verifyProcessDetails(pid, details);
        if (verification !== "stable") ownership = verification;
        else if (isBaselineIdentity(pid, details.startTicks)) {
          ownership = "anchored";
        } else {
          const ancestry = inspectOwnedAncestry(details.parentPid, session);
          if (["current", "retry"].includes(ancestry)) ownership = ancestry;
          else if (processControlGroup(pid) !== controlGroup) {
            ownership = "unrelated";
          } else ownership = null;
        }
      } else return null;
    }
    if (ownership === "retry") continue;
    if (ownership === null) return null;
    const verification = verifyProcessDetails(pid, details);
    if (verification === "retry") continue;
    if (verification === null) return null;
    return ownership === "anchored" ? "unrelated" : ownership;
  }
  return null;
}
function ownedMembers() {
  if (mode !== "session") return [];
  const session = String(process.pid);
  // The enclosing namespace may host concurrent trusted work. Limit ownership
  // to this supervisor's session and descendants carrying its launch token.
  try {
    charge = inspectionBudget(() => performance.now(), ${MAX_INSPECTION_WORK}, ${MAX_INSPECTION_MS});
    charge();
    const names = readdirSync("/proc");
    charge(names.length);
    const members = [];
    for (const name of names) {
      charge();
      if (!/^\d+$/.test(name) || name === String(process.pid)) continue;
      const ownership = inspectSessionProcess(Number(name), session);
      if (ownership === null) return null;
      if (ownership === "current") members.push(Number(name));
    }
    charge(0);
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
  let inspectionDeadline;
  const withCompleteInspection = (inspect, complete) => {
    const inspection = inspect();
    if (inspection !== null) {
      complete(inspection);
      return;
    }
    inspectionDeadline ??= Date.now() + grace;
    if (Date.now() >= inspectionDeadline) {
      retainContainmentFailure("unverifiable");
      return;
    }
    setTimeout(
      () => withCompleteInspection(inspect, complete),
      Math.min(10, Math.max(1, inspectionDeadline - Date.now())),
    ).unref();
  };
  const inspectCompletely = (complete) =>
    withCompleteInspection(() => {
      const inspection = inspectDescendants();
      return inspection.complete ? inspection : null;
    }, complete);
  const signalCompletely = (signal, complete) =>
    withCompleteInspection(
      () => (signalDescendants(signal) ? true : null),
      complete,
    );
  const report = (observed) => {
    const continueReport = (initial) => {
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
      if (!initial.active || mode !== "session") return send(initial);
      signalCompletely("SIGTERM", () => {
        setTimeout(() => {
          signalCompletely("SIGKILL", () => {
            const deadline = Date.now() + grace;
            const waitForExit = () => {
              inspectCompletely((inspection) => {
                if (!inspection.active) return send(inspection, true);
                if (Date.now() >= deadline) {
                  return retainContainmentFailure("active");
                }
                setTimeout(
                  waitForExit,
                  Math.min(10, Math.max(1, grace)),
                ).unref();
              });
            };
            waitForExit();
          });
        }, grace).unref();
      });
    };
    if (observed === undefined) inspectCompletely(continueReport);
    else continueReport(observed);
  };
  inspectCompletely((initial) => {
    if (initial.active) setTimeout(report, grace).unref();
    else report(initial);
  });
}
function terminate(signal = "SIGTERM", verify = false) {
  // Before the start message, this inert supervisor cannot have descendants.
  if (target === undefined) process.exit(124);
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
  launchCutoff = normalizedLaunchCutoff(message.launchCutoff);
  ancestryBaseline =
    launchCutoff === null
      ? null
      : normalizedAncestryBaseline(message.ancestryBaseline, launchCutoff);
  controlGroup =
    typeof message.controlGroup === "string" &&
    /^[a-f0-9]{64}$/.test(message.controlGroup)
      ? message.controlGroup
      : null;
  if (
    mode === "session" &&
    (ancestryBaseline === null || controlGroup === null)
  ) process.exit(126);
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

function processControlGroup(pid, read = readFileSync) {
  const source = read(`/proc/${pid}/cgroup`, "utf8");
  if (
    Buffer.byteLength(source) === 0 ||
    Buffer.byteLength(source) > 64 * 1024 ||
    !source.endsWith("\n")
  )
    return null;
  return createHash("sha256").update(source).digest("hex");
}

function hasDifferentControlGroup(pid, controlGroup, read = readFileSync) {
  if (controlGroup === null) return false;
  const candidate = processControlGroup(pid, read);
  return candidate !== null && candidate !== controlGroup;
}

function processStatDetails(stat) {
  const separator = stat.lastIndexOf(")");
  if (separator < 0) return null;
  const fields = stat
    .slice(separator + 2)
    .trim()
    .split(/\s+/u);
  if (
    fields.length < 20 ||
    !/^\d+$/u.test(fields[1]) ||
    !/^\d+$/u.test(fields[3]) ||
    !/^(?:0|[1-9]\d{0,31})$/u.test(fields[19])
  )
    return null;
  return {
    parentPid: Number(fields[1]),
    sessionId: fields[3],
    startTicks: fields[19],
  };
}

function validBootId(value) {
  return (
    typeof value === "string" &&
    /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/u.test(value)
  );
}

function normalizedAncestryBaseline(value) {
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    value.length > MAX_PROCESS_ANCESTRY_BASELINE_ENTRIES
  )
    return null;
  const entries = [];
  let previousPid = 0;
  let bootId = null;
  for (const entry of value) {
    if (
      entry === null ||
      typeof entry !== "object" ||
      Array.isArray(entry) ||
      Object.keys(entry).length !== 3 ||
      !validBootId(entry.bootId) ||
      !Number.isSafeInteger(entry.pid) ||
      entry.pid <= previousPid ||
      typeof entry.startTicks !== "string" ||
      !/^(?:0|[1-9]\d{0,31})$/u.test(entry.startTicks) ||
      (bootId !== null && entry.bootId !== bootId)
    )
      return null;
    bootId ??= entry.bootId;
    previousPid = entry.pid;
    entries.push({
      bootId: entry.bootId,
      pid: entry.pid,
      startTicks: entry.startTicks,
    });
  }
  return entries;
}

function captureProcessAncestryBaseline({
  list = readdirSync,
  read = readFileSync,
} = {}) {
  try {
    const charge = inspectionBudget(
      () => performance.now(),
      MAX_INSPECTION_WORK,
      MAX_INSPECTION_MS,
    );
    const rawRead = read;
    read = (...args) => {
      charge();
      try {
        return rawRead(...args);
      } finally {
        charge(0);
      }
    };
    const bootPath = "/proc/sys/kernel/random/boot_id";
    const bootId = read(bootPath, "utf8").trim();
    if (!validBootId(bootId)) return null;
    const names = list("/proc");
    charge(names.length);
    const pids = [
      ...new Set(
        names
          .filter((name) => /^(?:[1-9]\d*)$/u.test(name))
          .map(Number)
          .filter(Number.isSafeInteger),
      ),
    ].sort((left, right) => left - right);
    if (
      pids.length === 0 ||
      pids.length > MAX_PROCESS_ANCESTRY_BASELINE_ENTRIES
    )
      return null;
    const entries = [];
    for (const pid of pids) {
      try {
        const details = processStatDetails(read(`/proc/${pid}/stat`, "utf8"));
        if (details === null) return null;
        entries.push({ bootId, pid, startTicks: details.startTicks });
      } catch (cause) {
        if (!["ENOENT", "ESRCH"].includes(cause?.code)) return null;
      }
    }
    if (entries.length === 0 || read(bootPath, "utf8").trim() !== bootId)
      return null;
    return entries;
  } catch {
    return null;
  }
}

function ancestryBaselineIndex(value, read) {
  const entries = normalizedAncestryBaseline(value);
  if (entries === null) return null;
  let currentBootId;
  try {
    currentBootId = read("/proc/sys/kernel/random/boot_id", "utf8").trim();
  } catch {
    return null;
  }
  if (!validBootId(currentBootId) || entries[0].bootId !== currentBootId) {
    return null;
  }
  return new Map(entries.map(({ pid, startTicks }) => [pid, startTicks]));
}

function isBaselineIdentity(baseline, pid, startTicks) {
  return baseline?.get(pid) === startTicks;
}

function verifyProcessDetails(pid, expected, read) {
  try {
    const current = processStatDetails(read(`/proc/${pid}/stat`, "utf8"));
    if (current === null || current.startTicks !== expected.startTicks) {
      return null;
    }
    return current.parentPid === expected.parentPid &&
      current.sessionId === expected.sessionId
      ? "stable"
      : "retry";
  } catch (cause) {
    return ["ENOENT", "ESRCH"].includes(cause?.code) ? "retry" : null;
  }
}

function inspectOwnedAncestry(
  parentPid,
  sessionId,
  ownerToken,
  includeSession,
  ancestryBaseline,
  read,
) {
  const seen = new Set();
  while (parentPid > 0 && !seen.has(parentPid)) {
    if (includeSession && parentPid === sessionId) return "current";
    seen.add(parentPid);
    const ancestorPid = parentPid;
    let details;
    try {
      details = processStatDetails(read(`/proc/${ancestorPid}/stat`, "utf8"));
      if (details === null) return null;
      if (includeSession && details.sessionId === String(sessionId)) {
        const verification = verifyProcessDetails(ancestorPid, details, read);
        return verification === "stable" ? "current" : verification;
      }
      const environment = read(`/proc/${ancestorPid}/environ`, "utf8").split(
        "\0",
      );
      const verification = verifyProcessDetails(ancestorPid, details, read);
      if (verification !== "stable") return verification;
      if (environment.includes(`AGENT_RUNNER_OWNED_PROCESS=${ownerToken}`)) {
        return "current";
      }
      if (
        isBaselineIdentity(ancestryBaseline, ancestorPid, details.startTicks)
      ) {
        return "anchored";
      }
      parentPid = details.parentPid;
    } catch (cause) {
      if (["ENOENT", "ESRCH"].includes(cause?.code)) return "retry";
      if (["EACCES", "EPERM"].includes(cause?.code)) {
        if (details === undefined) return null;
        const verification = verifyProcessDetails(ancestorPid, details, read);
        if (verification !== "stable") return verification;
        if (
          isBaselineIdentity(ancestryBaseline, ancestorPid, details.startTicks)
        ) {
          return "anchored";
        }
        parentPid = details.parentPid;
        continue;
      }
      return null;
    }
  }
  return null;
}

function inspectSessionProcess(
  pid,
  sessionId,
  ownerToken,
  includeSession,
  ancestryBaseline,
  controlGroup,
  getuid,
  read,
) {
  let pinnedStartTicks;
  for (
    let attempt = 0;
    attempt < OWNED_PROCESS_INSPECTION_ATTEMPTS;
    attempt += 1
  ) {
    let details;
    try {
      details = processStatDetails(read(`/proc/${pid}/stat`, "utf8"));
    } catch (cause) {
      if (["ENOENT", "ESRCH"].includes(cause?.code)) return "absent";
      return null;
    }
    if (details === null) return null;
    if (pinnedStartTicks === undefined) pinnedStartTicks = details.startTicks;
    else if (details.startTicks !== pinnedStartTicks) return null;

    let ownership;
    try {
      if (includeSession && details.sessionId === String(sessionId)) {
        ownership = "current";
      } else {
        const uids = processUid(pid, read);
        if (uids === null) return null;
        if (uids.some((uid) => uid !== getuid())) ownership = "unrelated";
        else {
          const environment = read(`/proc/${pid}/environ`, "utf8");
          if (
            environment
              .split("\0")
              .includes(`AGENT_RUNNER_OWNED_PROCESS=${ownerToken}`)
          ) {
            ownership = "current";
          } else if (
            isBaselineIdentity(ancestryBaseline, pid, details.startTicks)
          ) {
            ownership = "anchored";
          } else {
            ownership = inspectOwnedAncestry(
              details.parentPid,
              sessionId,
              ownerToken,
              includeSession,
              ancestryBaseline,
              read,
            );
          }
        }
      }
    } catch (cause) {
      if (["ENOENT", "ESRCH"].includes(cause?.code)) ownership = "retry";
      else if (["EACCES", "EPERM"].includes(cause?.code)) {
        const verification = verifyProcessDetails(pid, details, read);
        if (verification !== "stable") ownership = verification;
        else if (
          isBaselineIdentity(ancestryBaseline, pid, details.startTicks)
        ) {
          ownership = "anchored";
        } else {
          const ancestry = inspectOwnedAncestry(
            details.parentPid,
            sessionId,
            ownerToken,
            includeSession,
            ancestryBaseline,
            read,
          );
          if (["current", "retry"].includes(ancestry)) ownership = ancestry;
          else if (hasDifferentControlGroup(pid, controlGroup, read)) {
            ownership = "unrelated";
          } else ownership = null;
        }
      } else return null;
    }
    if (ownership === "retry") continue;
    if (ownership === null) return null;
    const verification = verifyProcessDetails(pid, details, read);
    if (verification === "retry") continue;
    if (verification === null) return null;
    return ownership === "anchored" ? "unrelated" : ownership;
  }
  return null;
}

export function inspectOwnedSessionProcesses(
  sessionId,
  ownerToken,
  {
    ancestryBaseline = null,
    controlGroup = null,
    getuid = () => process.getuid(),
    includeSession = true,
    list = readdirSync,
    read = readFileSync,
    now = () => performance.now(),
    maxWork = MAX_INSPECTION_WORK,
    maxElapsedMs = MAX_INSPECTION_MS,
  } = {},
) {
  if (
    !Number.isSafeInteger(maxWork) ||
    maxWork < 1 ||
    maxWork > MAX_INSPECTION_WORK ||
    !Number.isFinite(maxElapsedMs) ||
    maxElapsedMs <= 0 ||
    maxElapsedMs > MAX_INSPECTION_MS
  )
    return null;
  try {
    const charge = inspectionBudget(now, maxWork, maxElapsedMs);
    charge(Array.isArray(ancestryBaseline) ? ancestryBaseline.length : 1);
    const rawRead = read;
    read = (...args) => {
      charge();
      try {
        return rawRead(...args);
      } finally {
        charge(0);
      }
    };
    const baseline =
      ancestryBaseline === null
        ? null
        : ancestryBaselineIndex(ancestryBaseline, read);
    if (ancestryBaseline !== null && baseline === null) return null;
    if (controlGroup !== null && !/^[a-f0-9]{64}$/u.test(controlGroup))
      return null;
    const names = list("/proc");
    charge(names.length);
    const members = [];
    for (const name of names) {
      charge();
      if (!/^\d+$/u.test(name)) continue;
      const pid = Number(name);
      const ownership = inspectSessionProcess(
        pid,
        sessionId,
        ownerToken,
        includeSession,
        baseline,
        controlGroup,
        getuid,
        read,
      );
      if (ownership === null) return null;
      if (ownership === "current") members.push(pid);
    }
    charge(0);
    return members;
  } catch {
    return null;
  }
}

function signalSession(
  sessionId,
  ownerToken,
  signal,
  ancestryBaseline,
  controlGroup,
  inspectSessionProcesses,
) {
  const members = inspectSessionProcesses(sessionId, ownerToken, {
    ancestryBaseline,
    controlGroup,
  });
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
      hostSession: false,
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
    hostSession: providerCanUseHostSession,
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
    captureAncestryBaseline = captureProcessAncestryBaseline,
    descendantGraceMs = DEFAULT_DESCENDANT_GRACE_MS,
    inspectSessionProcesses = inspectOwnedSessionProcesses,
    onProcess,
    ownershipMode = "ordinary",
    resolveLauncher = resolveOwnedProcessLauncher,
    signal,
    stdio: requestedStdio,
    ...spawnOptions
  } = options;
  if (
    typeof captureAncestryBaseline !== "function" ||
    typeof inspectSessionProcesses !== "function" ||
    typeof onProcess !== "function" ||
    !OWNERSHIP_MODES.has(ownershipMode) ||
    typeof resolveLauncher !== "function" ||
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
  const launcher = resolveLauncher(cwd, {
    ownershipMode,
  });
  const capturedAncestryBaseline = normalizedAncestryBaseline(
    captureAncestryBaseline(),
  );
  if (capturedAncestryBaseline === null) {
    throw ownedError(
      "Owned-process launch ancestry is unavailable.",
      "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
    );
  }
  const ancestryBaseline = Object.freeze(
    capturedAncestryBaseline.map((entry) => Object.freeze(entry)),
  );
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
  let retainedContainmentFailure = null;
  let closed = false;
  const killChild = child.kill.bind(child);
  let containmentFailure = null;
  let launchCutoff = null;
  let controlGroup = null;
  let startRequested = false;
  const killLauncher = (signal) => {
    if (launcher.isolatedNamespace) {
      try {
        process.kill(-child.pid, signal);
        return true;
      } catch (cause) {
        if (cause?.code !== "ESRCH") {
          containmentFailure ??= cause;
          return false;
        }
      }
    }
    return killChild(signal);
  };
  const kill = (signal) => {
    if (!launcher.isolatedNamespace) {
      try {
        signalSession(
          child.pid,
          ownerToken,
          signal,
          ancestryBaseline,
          controlGroup,
          inspectSessionProcesses,
        );
      } catch (cause) {
        containmentFailure ??= cause;
        return false;
      }
    }
    return killLauncher(signal);
  };
  child.kill = (signal = "SIGTERM") => {
    if (child.exitCode !== null || child.signalCode !== null) return false;
    terminationRequested = true;
    if (!startRequested) {
      killLauncher(signal);
    } else if (child.connected) {
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
        if (startRequested) kill("SIGKILL");
        else killLauncher("SIGKILL");
        if (containmentFailure !== null && !launcher.isolatedNamespace) {
          // The live ChildProcess handle identifies only this supervisor. A
          // failed session scan must not leave that empty control process
          // behind; descendant uncertainty remains protected by registration.
          killLauncher("SIGKILL");
        }
      }, descendantGraceMs);
      terminationTimer.unref();
      terminationFailureTimer = setTimeout(
        () => {
          if (closed) return;
          child.unref();
          child.channel?.unref?.();
          rejectCompletion?.(
            retainedContainmentFailure ??
              ownedError(
                "Owned process namespace did not terminate within its bound.",
                "ERR_EXECUTION_PROCESS_ACTIVE",
              ),
          );
        },
        descendantGraceMs * 2 + 1,
      );
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
        startRequested &&
        terminationRequested
      ) {
        const members = inspectSessionProcesses(child.pid, ownerToken, {
          ancestryBaseline,
          controlGroup,
        });
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
        (registered && !startRequested) ||
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
        retainedContainmentFailure ??= ownedError(
          unverifiable
            ? "Owned process descendants are unverifiable."
            : "Owned process descendants did not terminate within their bound.",
          unverifiable
            ? "ERR_EXECUTION_PROCESS_UNVERIFIABLE"
            : "ERR_EXECUTION_PROCESS_ACTIVE",
        );
        failure ??= retainedContainmentFailure;
        if (!child.ownedContainmentRetained) {
          child.kill("SIGKILL");
          const terminationSignaled = kill("SIGKILL");
          // The supervisor has already reported that it cannot provide a
          // trustworthy outcome. Retire that live control process directly;
          // durable registration continues to protect any uncertain
          // descendants until the parent can prove the session empty.
          if (!terminationSignaled) killLauncher("SIGKILL");
        }
        child.ownedContainmentRetained = true;
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
        const [
          processIdentity,
          namespaceId,
          runnerNamespaceId,
          ownerControlGroup,
        ] = await Promise.all([
          readProcessIdentity(child.ownedPid),
          readProcessNamespace(child.ownedPid),
          readProcessNamespace(process.pid),
          readProcessControlGroup(child.ownedPid),
        ]);
        launchCutoff = processIdentity;
        controlGroup = ownerControlGroup;
        if (
          processIdentity === null ||
          namespaceId === null ||
          runnerNamespaceId === null ||
          controlGroup === null ||
          (launcher.isolatedNamespace
            ? namespaceId === runnerNamespaceId
            : namespaceId !== runnerNamespaceId)
        ) {
          throw ownedError(
            "Owned process identity is unavailable.",
            "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
          );
        }
        if (ancestryBaseline[0].bootId !== processIdentity.bootId) {
          throw ownedError(
            "Owned-process launch ancestry is stale.",
            "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
          );
        }
        const proof = {
          processIdentity,
          namespaceId,
          launchCutoff,
          ancestryBaseline,
          controlGroup,
        };
        await onProcess(child.ownedPid, proof);
        registered = true;
        ownerToken = ownedProcessToken(child.ownedPid, processIdentity);
        if (closed || terminationRequested) return;
        startRequested = true;
        activeProcesses.set(child.ownedPid, child);
        child.send(
          {
            type: "start",
            ownerToken,
            launchCutoff,
            ancestryBaseline,
            controlGroup,
          },
          (cause) => {
            if (cause !== null && cause !== undefined) child.kill("SIGKILL");
          },
        );
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
  if (owner.status === "replaced") {
    throw ownedError(
      "Owned execution process identity was replaced.",
      "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
    );
  }
  if (owner.status === "dead") {
    const namespaceId = await readProcessNamespace(process.pid);
    if (
      namespaceId === null ||
      owner.namespaceId === null ||
      owner.processIdentity === null
    ) {
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
      throw ownedError(
        "Owned execution process namespace does not match recovery.",
        "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
      );
    }
    if (owner.ancestryBaseline === null) {
      throw ownedError(
        "Owned execution process predates frozen ancestry recovery evidence.",
        "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
      );
    }
    const members = inspectSessionProcesses(
      owner.pid,
      ownedProcessToken(owner.pid, owner.processIdentity),
      {
        ancestryBaseline: owner.ancestryBaseline,
        controlGroup: owner.controlGroup ?? null,
        includeSession: true,
      },
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
    onStdout,
    ...spawnOptions
  } = options;
  const child = spawnOwnedProcess(file, argumentsList, {
    ...spawnOptions,
    stdio: ["pipe", "pipe", "pipe"],
  });
  const output = { stdout: [], stderr: [] };
  let size = 0;
  let outputError;
  for (const [name, stream] of [
    ["stdout", child.stdout],
    ["stderr", child.stderr],
  ]) {
    stream.on("data", (chunk) => {
      size += chunk.length;
      if (size > maxBuffer) {
        child.kill("SIGKILL");
        return;
      }
      output[name].push(chunk);
      if (
        name === "stdout" &&
        onStdout !== undefined &&
        outputError === undefined
      ) {
        try {
          onStdout(chunk);
        } catch (cause) {
          outputError = cause;
          child.kill();
        }
      }
    });
  }
  if (input !== undefined) child.stdin.end(input);
  else child.stdin.end();
  const supervision = await child.ownedCompletion;
  if (outputError !== undefined) throw outputError;
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
