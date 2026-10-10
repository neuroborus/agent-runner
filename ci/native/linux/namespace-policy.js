import { createHash } from "node:crypto";
import {
  observationObject,
  observationList,
  requireObservation,
} from "../index.js";

const SHA = /^[a-f0-9]{64}$/u;
const LABELS = [
  "unconfined",
  "restricted-userns",
  "distribution-bwrap",
  "owned",
  "other",
];
const OPERATIONS = ["namespace", "mapping", "capability", "unknown"];
const CAPABILITIES = ["sys_admin", "setuid", "setgid"];
export const namespaceDigest = (bytes) =>
  createHash("sha256").update(bytes).digest("hex");

export function linuxNamespaceContext(value) {
  observationObject(value, ["candidateSha", "runId", "runAttempt"]);
  requireObservation(
    Object.values(value).every((member) => typeof member === "string") &&
      /^[a-f0-9]{40}$/u.test(value.candidateSha) &&
      /^[1-9][0-9]{0,19}$/u.test(value.runId) &&
      /^[1-9][0-9]{0,19}$/u.test(value.runAttempt),
  );
  return {
    candidateSha: value.candidateSha,
    runId: value.runId,
    runAttempt: value.runAttempt,
  };
}
export function linuxNamespaceProfileName(context) {
  return `agent-runner-native-bwrap-${namespaceDigest(JSON.stringify(linuxNamespaceContext(context))).slice(0, 24)}`;
}

/** The Ubuntu opt-in changes only userns authority for this executable. It is
 * never attached to a shell, interpreter, payload path or a glob. */
export function linuxNamespaceProfile(context) {
  return `abi <abi/4.0>,\nprofile ${linuxNamespaceProfileName(context)} /usr/bin/bwrap flags=(unconfined) {\n  userns,\n}\n`;
}
export function linuxNamespaceLabel(bytes, name) {
  const value = bytes.trim();
  if (value === "unconfined") return "unconfined";
  if (value === `${name} (unconfined)`) return "owned";
  if (value === "bwrap (unconfined)") return "distribution-bwrap";
  if (value === "unprivileged_userns (enforce)") return "restricted-userns";
  return "other";
}

/** Membership is independent of mode and includes stacked labels and children;
 * an unexpected owned label cannot be mistaken for an unrelated process. */
export function linuxNamespaceProfileMembership(value, context) {
  requireObservation(
    typeof value === "string" && Buffer.byteLength(value) <= 4096,
  );
  const name = linuxNamespaceProfileName(context);
  return value
    .trim()
    .split("//&")
    .some(
      (member) =>
        member === name ||
        member.startsWith(`${name} (`) ||
        member.startsWith(`${name}//`),
    );
}

/** Only exact exec/clone trace facts attribute audit PIDs. Trace text and paths
 * remain transient; unrelated kernel records can never select a remedy. */
export function linuxNamespaceTracePids(trace, activeOnly = false) {
  requireObservation(
    typeof trace === "string" && Buffer.byteLength(trace) <= 65536,
  );
  const pids = new Set(),
    active = new Set();
  let entered = false;
  for (const line of trace.split("\n")) {
    const prefix =
      /^(?:\[pid\s+([1-9][0-9]{0,9})\]|([1-9][0-9]{0,9}))\s+(.*)$/u.exec(line);
    if (!prefix) continue;
    const pid = prefix[1] ?? prefix[2];
    const exec = /^execve\("([^"\n]+)",.*\)\s+= 0$/u.exec(prefix[3]);
    if (exec?.[1] === "/usr/bin/bwrap") entered = true;
    if (!entered) continue;
    // The fixed -f replay traces only bwrap descendants and /bin/true. Its
    // numeric prefixes are host PIDs; clone return values inside the nested
    // PID namespace are not usable for host /proc or kernel-audit joins.
    if (!pids.has(pid)) {
      pids.add(pid);
      active.add(pid);
    }
    if (exec && exec[1] !== "/usr/bin/bwrap") active.delete(pid);
  }
  requireObservation(pids.size <= 32);
  return [...(activeOnly ? active : pids)];
}
export function linuxNamespaceDenials(trace, journal, name) {
  requireObservation(
    typeof journal === "string" && Buffer.byteLength(journal) <= 65536,
  );
  const pids = new Set(linuxNamespaceTracePids(trace, true));
  const denials = [];
  for (const line of journal.split("\n").filter(Boolean)) {
    const message = JSON.parse(line).MESSAGE;
    if (typeof message !== "string" || !message.includes('apparmor="DENIED"'))
      continue;
    const fields = new Map();
    for (const match of message.matchAll(
      /(?:^|\s)([a-z_]+)=(?:"([^"\n]*)"|([^\s]+))/gu,
    )) {
      requireObservation(!fields.has(match[1]));
      fields.set(match[1], match[2] ?? match[3]);
    }
    if (!pids.has(fields.get("pid")) || fields.get("comm") !== "bwrap")
      continue;
    let operation = fields.get("operation"),
      capability = fields.get("capname") ?? null;
    const numbers = { sys_admin: "21", setuid: "7", setgid: "6" };
    if (
      !["userns_create", "capable"].includes(operation) ||
      (operation === "capable" &&
        (!CAPABILITIES.includes(capability) ||
          fields.get("capability") !== numbers[capability]))
    ) {
      operation = "other";
      capability = null;
    }
    const profile = fields.get("profile");
    const label =
      profile === name
        ? "owned"
        : profile === "unconfined"
          ? "unconfined"
          : profile === "unprivileged_userns"
            ? "restricted-userns"
            : "other";
    denials.push({
      operation,
      label,
      capability: operation === "capable" ? capability : null,
    });
  }
  requireObservation(denials.length <= 16);
  return denials;
}

/** A closed observation contains no command, trace, kernel prose or private path. */
export function normalizeLinuxNamespaceObservation(value) {
  observationObject(value, [
    "executable",
    "sysctls",
    "apparmor",
    "callerLabel",
    "effectiveLabel",
    "procVisible",
    "probes",
  ]);
  observationObject(value.executable, ["sha256", "packageVersion", "version"]);
  requireObservation(
    Object.values(value.executable).every(
      (member) => typeof member === "string",
    ) &&
      SHA.test(value.executable.sha256) &&
      /^[0-9][a-zA-Z0-9.+~\-]{0,95}$/u.test(value.executable.packageVersion) &&
      /^bubblewrap [0-9]+\.[0-9]+\.[0-9]+$/u.test(value.executable.version),
  );
  observationObject(value.sysctls, [
    "restrictedUserns",
    "unprivilegedUserns",
    "maxUserNamespaces",
  ]);
  for (const number of Object.values(value.sysctls))
    requireObservation(
      number === null || (Number.isSafeInteger(number) && number >= 0),
    );
  observationObject(value.apparmor, [
    "enabled",
    "parserVersion",
    "abiSha256",
    "usernsFeature",
  ]);
  requireObservation(
    typeof value.apparmor.enabled === "boolean" &&
      typeof value.apparmor.usernsFeature === "boolean" &&
      (value.apparmor.parserVersion === null ||
        (typeof value.apparmor.parserVersion === "string" &&
          /^[0-9]+\.[0-9]+\.[0-9]+$/u.test(value.apparmor.parserVersion))) &&
      (value.apparmor.abiSha256 === null ||
        (typeof value.apparmor.abiSha256 === "string" &&
          SHA.test(value.apparmor.abiSha256))) &&
      LABELS.includes(value.callerLabel) &&
      (value.effectiveLabel === null ||
        LABELS.includes(value.effectiveLabel)) &&
      typeof value.procVisible === "boolean" &&
      Array.isArray(value.probes) &&
      value.probes.length === 2,
  );
  for (const [index, probe] of observationList(value.probes, 2).entries()) {
    observationObject(probe, [
      "mode",
      "passed",
      "settled",
      "replayMatched",
      "exitCode",
      "signal",
      "timedOut",
      "operation",
      "errno",
      "denials",
    ]);
    requireObservation(
      probe.mode === ["ordinary", "nested"][index] &&
        typeof probe.passed === "boolean" &&
        typeof probe.settled === "boolean" &&
        typeof probe.replayMatched === "boolean" &&
        (probe.exitCode === null ||
          (Number.isInteger(probe.exitCode) &&
            probe.exitCode >= 0 &&
            probe.exitCode <= 255)) &&
        [
          null,
          "SIGTERM",
          "SIGKILL",
          "SIGABRT",
          "SIGSEGV",
          "SIGBUS",
          "SIGILL",
          "SIGSYS",
          "SIGALRM",
          "SIGTRAP",
          "SIGFPE",
          "SIGPIPE",
          "SIGINT",
          "SIGHUP",
          "SIGQUIT",
          "SIGXCPU",
          "SIGXFSZ",
        ].includes(probe.signal) &&
        typeof probe.timedOut === "boolean" &&
        OPERATIONS.includes(probe.operation) &&
        [null, "EACCES", "EPERM", "EINVAL", "ENOSPC", "ENOSYS"].includes(
          probe.errno,
        ) &&
        Array.isArray(probe.denials) &&
        probe.denials.length <= 16,
    );
    requireObservation(
      !probe.passed ||
        (probe.settled &&
          probe.replayMatched &&
          probe.exitCode === 0 &&
          probe.signal === null &&
          !probe.timedOut &&
          !probe.denials.length),
    );
    for (const denial of observationList(probe.denials, 16)) {
      observationObject(denial, ["operation", "label", "capability"]);
      requireObservation(
        ["userns_create", "capable", "other"].includes(denial.operation) &&
          LABELS.includes(denial.label) &&
          (denial.operation === "capable"
            ? CAPABILITIES.includes(denial.capability)
            : denial.capability === null),
      );
    }
  }
  requireObservation(Buffer.byteLength(JSON.stringify(value)) <= 8192);
  return structuredClone(value);
}

export function linuxNamespacePolicyDecision(input) {
  const value = normalizeLinuxNamespaceObservation(input);
  if (
    value.procVisible &&
    value.probes.every(({ passed }) => passed) &&
    ["unconfined", "distribution-bwrap", "owned"].includes(value.effectiveLabel)
  )
    return "verified";
  // The inspected package's mapping path needs capabilities inside userns.
  // A permission errno without a PID-attributed policy denial proves no cause.
  if (
    value.executable.packageVersion !== "0.9.0-1ubuntu0.3" ||
    value.executable.version !== "bubblewrap 0.9.0" ||
    !value.procVisible ||
    value.callerLabel !== "unconfined" ||
    !value.apparmor.enabled ||
    value.sysctls.restrictedUserns !== 1 ||
    value.sysctls.unprivilegedUserns !== 1 ||
    !(value.sysctls.maxUserNamespaces > 0) ||
    !/^4\./u.test(value.apparmor.parserVersion ?? "") ||
    !value.apparmor.abiSha256 ||
    !value.apparmor.usernsFeature
  )
    return "blocked";
  const failed = value.probes.filter(({ passed }) => !passed);
  return failed.length &&
    value.probes.every(
      ({ settled, replayMatched }) => settled && replayMatched,
    ) &&
    failed.every(
      (probe) =>
        probe.exitCode === 1 &&
        !probe.signal &&
        !probe.timedOut &&
        ["namespace", "mapping", "capability"].includes(probe.operation) &&
        ["EACCES", "EPERM"].includes(probe.errno) &&
        probe.denials.length &&
        probe.denials.every(
          (denial) =>
            (denial.operation === "userns_create" &&
              denial.label === "unconfined") ||
            (denial.operation === "capable" &&
              denial.label === "restricted-userns"),
        ),
    )
    ? "prepare"
    : "blocked";
}

export function initialLinuxNamespacePreparation(context) {
  return {
    schemaVersion: 1,
    ...linuxNamespaceContext(context),
    status: "NOT_RUN",
    phase: null,
    before: null,
    after: null,
    owned: null,
    cause: null,
    cleanupCause: null,
  };
}
export function normalizeLinuxNamespacePreparation(value, context) {
  observationObject(value, [
    "schemaVersion",
    "candidateSha",
    "runId",
    "runAttempt",
    "status",
    "phase",
    "before",
    "after",
    "owned",
    "cause",
    "cleanupCause",
  ]);
  for (const [key, expected] of Object.entries(linuxNamespaceContext(context)))
    requireObservation(value[key] === expected);
  requireObservation(
    value.schemaVersion === 1 &&
      ["NOT_RUN", "RUNNING", "PASS", "BLOCKED", "FAIL"].includes(
        value.status,
      ) &&
      [null, "diagnosis", "installation", "verification", "cleanup"].includes(
        value.phase,
      ),
  );
  for (const key of ["before", "after"])
    if (value[key] !== null) normalizeLinuxNamespaceObservation(value[key]);
  if (value.owned !== null) {
    observationObject(value.owned, ["name", "sha256", "status"]);
    requireObservation(
      value.owned.name === linuxNamespaceProfileName(context) &&
        value.owned.sha256 ===
          namespaceDigest(linuxNamespaceProfile(context)) &&
        ["POSSIBLE", "LOADED", "REMOVED"].includes(value.owned.status),
    );
  }
  for (const key of ["cause", "cleanupCause"]) {
    if (value[key] === null) continue;
    observationObject(value[key], ["code", "detail"]);
    requireObservation(
      value[key].code ===
        (key === "cause" ? "prerequisite-unavailable" : "cleanup-unobserved") &&
        value[key].detail ===
          (key === "cause"
            ? linuxNamespacePreparationCause(value.before).detail
            : LINUX_NAMESPACE_CLEANUP_BLOCKER),
    );
  }
  return structuredClone(value);
}
export function linuxNamespacePreparationCause(observation) {
  const first = observation?.probes.find(({ passed }) => !passed);
  return {
    code: "prerequisite-unavailable",
    detail: `prepare linux-namespace-policy: exit=${first?.exitCode ?? "unknown"}, signal=${first?.signal ?? "none"}, timeout=${first?.timedOut ? "yes" : "no"}; ${first?.mode ?? "policy"}-${first?.operation ?? "unknown"}, native=${first?.errno ?? "unknown"}. Require attributed matching Ubuntu policy and both fixed probes before admission.`,
  };
}
export const LINUX_NAMESPACE_CLEANUP_BLOCKER =
  "Owned Linux namespace policy remains quarantined until independent native settlement and policy removal are observed.";

export function linuxNamespacePolicyRetired(value, context) {
  const record = normalizeLinuxNamespacePreparation(value, context);
  return (
    record.cleanupCause === null &&
    (record.owned === null || record.owned.status === "REMOVED")
  );
}

export function assertLinuxNamespacePreparation(value, context) {
  const record = normalizeLinuxNamespacePreparation(value, context);
  const observation = record.after ?? record.before;
  requireObservation(
    record.status === "PASS" &&
      record.phase === "verification" &&
      record.cause === null &&
      record.cleanupCause === null &&
      observation !== null &&
      linuxNamespacePolicyDecision(observation) === "verified" &&
      (record.owned === null
        ? observation.effectiveLabel !== "owned"
        : record.owned.status === "LOADED" &&
          observation.effectiveLabel === "owned"),
  );
  return record;
}
