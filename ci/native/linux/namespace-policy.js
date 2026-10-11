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
const AUDIT_OPERATIONS = [
  "userns_create",
  "capable",
  "open",
  "file_perm",
  "file_inherit",
  "change_profile",
  "change_onexec",
];
const MAPPING_REJECTIONS = [
  "audit-name-missing",
  "audit-name-encoding",
  "audit-target-absolute",
  "audit-target-relative",
  "audit-mask",
  "syscall-missing",
  "syscall-operation",
  "syscall-form",
  "syscall-errno",
  "syscall-target",
];
// Linux UAPI capability numbers. Diagnosis does not grant these capabilities.
const CAPABILITY_NUMBERS = Object.freeze(
  Object.fromEntries(
    [
      "chown",
      "dac_override",
      "dac_read_search",
      "fowner",
      "fsetid",
      "kill",
      "setgid",
      "setuid",
      "setpcap",
      "linux_immutable",
      "net_bind_service",
      "net_broadcast",
      "net_admin",
      "net_raw",
      "ipc_lock",
      "ipc_owner",
      "sys_module",
      "sys_rawio",
      "sys_chroot",
      "sys_ptrace",
      "sys_pacct",
      "sys_admin",
      "sys_boot",
      "sys_nice",
      "sys_resource",
      "sys_time",
      "sys_tty_config",
      "mknod",
      "lease",
      "audit_write",
      "audit_control",
      "setfcap",
      "mac_override",
      "mac_admin",
      "syslog",
      "wake_alarm",
      "block_suspend",
      "audit_read",
      "perfmon",
      "bpf",
      "checkpoint_restore",
    ].map((name, number) => [name, String(number)]),
  ),
);
const SIGNAL =
  /^SIG(?:TERM|KILL|ABRT|SEGV|BUS|ILL|SYS|ALRM|TRAP|FPE|PIPE|INT|HUP|QUIT|XCPU|XFSZ)$/u;
const STAGE =
  /^(?:host|executable|policy|trace-options|journal-cursor|probe|trace-capture|trace-attribution|process-retirement|journal-read|proc-visibility|effective-label|image-recheck)$/u;
const NATIVE_CODE =
  /^(?:unknown|unsupported-options|image-substitution|capture-substitution|capture-bound|capture-unsettled|capture-cleanup|trace-incomplete|ENOENT|ENXIO|EACCES|EPERM|EFBIG|ENOSPC|ENOBUFS|EIO|ETIMEDOUT)$/u;
const JOURNAL_REMEDIES = Object.freeze({
  "journal-command-rejected":
    "Correct the fixed journalctl command in matching CI.",
  "journal-authority-unavailable":
    "Require noninteractive sudo and complete hosted journal read authority.",
  "journal-unavailable":
    "Require an accessible current-boot kernel journal in matching CI.",
  "journal-cursor-unavailable":
    "Require an available current-boot kernel journal cursor in matching CI.",
  "journal-cursor-absent":
    "Require a complete journalctl cursor receipt before either probe.",
  "journal-cursor-malformed":
    "Require matching JSON and terminal cursors before either probe.",
  "journal-output-bound":
    "Require complete journal output within the 64 KiB capture bound.",
  "journal-output-malformed":
    "Require complete UTF-8 journal JSON and its cursor before admission.",
  "journal-command-failed":
    "Collect the finite sudo/timeout/journalctl failure in matching CI.",
  "journal-command-killed":
    "Require bounded journal completion; exit 137 cannot identify a deadline.",
});
const isNativeCode = (value) =>
  typeof value === "string" &&
  (NATIVE_CODE.test(value) || Object.hasOwn(JOURNAL_REMEDIES, value));
const FAILURE_FIELDS = ["stage", "mode", "nativeCode", "outcome", "probes"];
const OUTCOME_FIELDS = ["exitCode", "signal", "timedOut"];
const validExit = (value) =>
  Number.isInteger(value) && value >= 0 && value <= 255;
const signal = (value) =>
  value === null || (typeof value === "string" && SIGNAL.test(value));
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
function namespaceTrace(trace) {
  requireObservation(
    typeof trace === "string" &&
      trace.isWellFormed() &&
      Buffer.byteLength(trace) < 65536 &&
      trace.endsWith("\n"),
  );
  const pids = new Set(),
    active = new Set(),
    exited = new Set(),
    pending = new Map(),
    calls = [];
  let entered = false;
  for (const line of trace.trimEnd().split("\n")) {
    const prefix =
      /^(?:\[pid\s+([1-9][0-9]{0,9})\]|([1-9][0-9]{0,9}))\s+(.*)$/u.exec(line);
    requireObservation(prefix);
    const pid = prefix[1] ?? prefix[2],
      body = prefix[3];
    requireObservation(!exited.has(pid));
    const terminal =
      /^\+\+\+ (?:exited with [0-9]+|killed by SIG[A-Z0-9]+(?: \(core dumped\))?) \+\+\+$/u.test(
        body,
      );
    let exec = null,
      success = false;
    const resumed =
      /^<\.\.\. (execve|clone3?|unshare|capset|openat|open|write|close) resumed>(.*)$/u.exec(
        body,
      );
    let complete = body;
    if (resumed) {
      const call = pending.get(pid);
      requireObservation(
        call?.name === resumed[1] && /\)\s+= /u.test(resumed[2]),
      );
      pending.delete(pid);
      exec = call.exec;
      success = /\)\s+= 0$/u.test(resumed[2]);
      complete = call.body + resumed[2];
    } else {
      const call =
        /^(execve|clone3?|unshare|capset|openat|open|write|close)\(/u.exec(
          body,
        );
      requireObservation(
        call || terminal || /^--- SIG[A-Z0-9]+ .* ---$/u.test(body),
      );
      if (call) requireObservation(!pending.has(pid));
      exec = /^execve\("([^"\n]+)"/u.exec(body)?.[1] ?? null;
      if (body.endsWith("<unfinished ...>")) {
        requireObservation(call);
        pending.set(pid, {
          name: call[1],
          exec,
          body: body.slice(0, -"<unfinished ...>".length),
        });
        complete = null;
      } else if (call) {
        requireObservation(/\)\s+= /u.test(body));
        success = /\)\s+= 0$/u.test(body);
      }
    }
    if (exec === "/usr/bin/bwrap" && success) entered = true;
    if (!entered) {
      requireObservation(exec === "/usr/bin/bwrap");
      continue;
    }
    // The fixed -f replay traces only bwrap descendants and /bin/true. Its
    // numeric prefixes are host PIDs; clone return values inside the nested
    // PID namespace are not usable for host /proc or kernel-audit joins.
    if (!pids.has(pid)) {
      pids.add(pid);
      active.add(pid);
      requireObservation(pids.size <= 32);
    }
    if (exec && success && exec !== "/usr/bin/bwrap") active.delete(pid);
    if (complete && active.has(pid) && !terminal)
      calls.push({ pid, body: complete });
    if (terminal) {
      exited.add(pid);
    }
  }
  requireObservation(
    entered && pending.size === 0 && exited.size === pids.size,
  );
  return { pids: [...pids], active: [...active], calls };
}
export function linuxNamespaceTracePids(trace, activeOnly = false) {
  const facts = namespaceTrace(trace);
  return activeOnly ? facts.active : facts.pids;
}

// Only the procfs targets used by write_uid_gid_map in the inspected package.
function mappingPath(value) {
  const match =
    /^\/(?:proc\/)?(self|[1-9][0-9]{0,9})\/(uid_map|gid_map|setgroups)$/u.exec(
      value ?? "",
    );
  return match ? { path: `${match[1]}/${match[2]}`, target: match[2] } : null;
}
function mappingCall(body, pid) {
  const open =
    /^open\("([^"\\]+)",\s*(?:O_RDWR\|O_CLOEXEC|O_CLOEXEC\|O_RDWR)\s*\)/u.exec(
      body,
    );
  const openat =
    /^openat\((?:AT_FDCWD|[0-9]+)(?:<([^>\\]+)>)?,\s*"([^"\\]+)",\s*(?:O_RDWR\|O_CLOEXEC|O_CLOEXEC\|O_RDWR)\s*\)/u.exec(
      body,
    );
  const write = /^write\([0-9]+<([^>\\]+)>,\s*/u.exec(body);
  let file = open?.[1] ?? write?.[1];
  if (openat)
    file = openat[2].startsWith("/")
      ? openat[2]
      : openat[1] && `${openat[1]}/${openat[2]}`;
  // Audit names can be procfs-relative; syscall paths must name actual procfs.
  const mapping = file?.startsWith("/proc/") ? mappingPath(file) : null;
  return (
    mapping && { ...mapping, path: mapping.path.replace(/^self\//u, `${pid}/`) }
  );
}

// Match the terminal result, never errno-like text in a write buffer.
function refusedErrno(body) {
  return (
    /\)\s+= -1 (EACCES|EPERM)(?: \((?:Permission denied|Operation not permitted)\))?$/u.exec(
      body,
    )?.[1] ?? null
  );
}

// audit_log_untrustedstring quotes safe names and hex-encodes unsafe bytes.
// Decode only the unquoted representation; neither encoding invents an alias.
function auditMappingName(value, quoted) {
  if (value === undefined) return { rejection: "audit-name-missing" };
  if (!quoted && /^[0-9a-fA-F]+$/u.test(value)) {
    if (value.length % 2) return { rejection: "audit-name-encoding" };
    try {
      value = new TextDecoder("utf-8", {
        fatal: true,
        ignoreBOM: true,
      }).decode(Buffer.from(value, "hex"));
    } catch {
      return { rejection: "audit-name-encoding" };
    }
  }
  return {
    target: mappingPath(value),
    rejection: value.startsWith("/")
      ? "audit-target-absolute"
      : "audit-target-relative",
  };
}

/** Partial facts are distinct from the complete two-probe admission record. */
export function linuxNamespaceProbeOutcome(result) {
  const status = result?.status;
  return {
    exitCode: validExit(status) ? status : null,
    signal: signal(result?.signal) ? result.signal : "unknown",
    timedOut: result ? result.error?.code === "ETIMEDOUT" : null,
  };
}
export function linuxNamespaceObservationFailure(stage, mode, error, probes) {
  const code = error?.namespaceNativeCode ?? error?.code;
  const outcome = linuxNamespaceProbeOutcome(error?.namespaceOutcome);
  if (code === "ETIMEDOUT") outcome.timedOut = true;
  if (code === "journal-command-killed") outcome.timedOut = null;
  return normalizeObservationFailure({
    stage,
    mode,
    nativeCode: isNativeCode(code) ? code : "unknown",
    outcome,
    probes,
  });
}
function normalizeObservationFailure(value) {
  observationObject(value, FAILURE_FIELDS);
  requireObservation(
    typeof value.stage === "string" &&
      STAGE.test(value.stage) &&
      [null, "ordinary", "nested"].includes(value.mode) &&
      isNativeCode(value.nativeCode),
  );
  if (Object.hasOwn(JOURNAL_REMEDIES, value.nativeCode))
    requireObservation(
      ["journal-cursor", "journal-read"].includes(value.stage),
    );
  if (value.nativeCode === "image-substitution")
    requireObservation(value.stage === "image-recheck");
  const outcome = (facts, keys = OUTCOME_FIELDS) => {
    observationObject(facts, keys);
    requireObservation(
      (facts.exitCode === null || validExit(facts.exitCode)) &&
        (signal(facts.signal) || facts.signal === "unknown") &&
        [null, true, false].includes(facts.timedOut),
    );
  };
  outcome(value.outcome);
  if (value.nativeCode === "journal-command-killed")
    requireObservation(
      value.outcome.exitCode === 137 && value.outcome.timedOut === null,
    );
  for (const [index, probe] of observationList(value.probes, 2).entries()) {
    if (probe && Object.hasOwn(probe, "passed"))
      namespaceProbes([probe], index);
    else outcome(probe, ["mode", ...OUTCOME_FIELDS]);
    requireObservation(probe.mode === ["ordinary", "nested"][index]);
  }
  requireObservation(Buffer.byteLength(JSON.stringify(value)) <= 8192);
  return structuredClone(value);
}
export function linuxNamespaceDenials(
  trace,
  journal,
  name,
  window = null,
  errno = null,
) {
  requireObservation(
    typeof journal === "string" &&
      journal.isWellFormed() &&
      Buffer.byteLength(journal) <= 65536,
  );
  requireObservation([null, "EACCES", "EPERM"].includes(errno));
  if (window !== null) {
    observationObject(window, ["start", "end"]);
    requireObservation(
      Number.isSafeInteger(window.start) &&
        Number.isSafeInteger(window.end) &&
        window.start <= window.end,
    );
  }
  const facts = namespaceTrace(trace),
    pids = new Set(facts.active);
  const denials = [];
  for (const line of journal.split("\n").filter(Boolean)) {
    const entry = JSON.parse(line),
      message = entry.MESSAGE;
    if (typeof message !== "string" || !message.includes('apparmor="DENIED"'))
      continue;
    const fields = new Map();
    let quotedName = false;
    for (const match of message.matchAll(
      /(?:^|\s)([a-z_]+)=(?:"([^"\n]*)"|([^\s]+))(?=\s|$)/gu,
    )) {
      requireObservation(!fields.has(match[1]));
      fields.set(match[1], match[2] ?? match[3]);
      if (match[1] === "name") quotedName = match[2] !== undefined;
    }
    if (!pids.has(fields.get("pid")) || fields.get("comm") !== "bwrap")
      continue;
    if (window !== null) {
      const stamp = entry.__REALTIME_TIMESTAMP;
      requireObservation(
        typeof stamp === "string" &&
          /^[0-9]{1,16}$/u.test(stamp) &&
          Number.isSafeInteger(Number(stamp)),
      );
      if (Number(stamp) < window.start || Number(stamp) > window.end) continue;
    }
    let operation = fields.get("operation"),
      capability = fields.get("capname") ?? null;
    if (
      !AUDIT_OPERATIONS.includes(operation) ||
      (operation === "capable" &&
        (!Object.hasOwn(CAPABILITY_NUMBERS, capability) ||
          fields.get("capability") !== CAPABILITY_NUMBERS[capability]))
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
    const pid = fields.get("pid");
    const auditName = auditMappingName(fields.get("name"), quotedName),
      target = auditName.target;
    const requested = fields.get("requested_mask"),
      denied = fields.get("denied_mask");
    const mask =
      ["w", "rw", "wr"].includes(requested) &&
      ["w", "rw", "wr"].includes(denied) &&
      [...denied].every((bit) => requested.includes(bit))
        ? "write"
        : "other";
    const refused = facts.calls.filter(
      (call) => call.pid === pid && refusedErrno(call.body) !== null,
    );
    requireObservation(refused.length <= 4096);
    const fileOperation = ["open", "file_perm"].includes(operation);
    const operationCalls = refused.filter(({ body }) =>
      operation === "open"
        ? /^open(?:at)?\(/u.test(body)
        : /^write\(/u.test(body),
    );
    const mappings = operationCalls
      .map(({ body }) => ({ body, mapping: mappingCall(body, pid) }))
      .filter(({ mapping }) => mapping !== null);
    const errnoCalls = mappings.filter(
      ({ body }) => !errno || refusedErrno(body) === errno,
    );
    const syscallMatched = refused.some(({ body }) => {
      const sameErrno = !errno || refusedErrno(body) === errno;
      const mapping = mappingCall(body, pid);
      if (["open", "file_perm"].includes(operation))
        return (
          sameErrno &&
          target &&
          mask === "write" &&
          (operation === "open"
            ? /^open(?:at)?\(/u.test(body)
            : /^write\(/u.test(body)) &&
          mapping?.path === target.path.replace(/^self\//u, `${pid}/`)
        );
      if (operation === "capable")
        return sameErrno && (/^capset\(/u.test(body) || mapping !== null);
      return (
        sameErrno &&
        operation === "userns_create" &&
        /^(?:clone3?|unshare)\(/u.test(body) &&
        body.includes("CLONE_NEWUSER")
      );
    });
    const rejection = !target
      ? auditName.rejection
      : mask !== "write"
        ? "audit-mask"
        : !refused.length
          ? "syscall-missing"
          : !operationCalls.length
            ? "syscall-operation"
            : !mappings.length
              ? "syscall-form"
              : !errnoCalls.length
                ? "syscall-errno"
                : "syscall-target";
    denials.push({
      operation,
      label,
      capability: operation === "capable" ? capability : null,
      target: ["open", "file_perm"].includes(operation)
        ? (target?.target ?? "other")
        : null,
      mask: ["open", "file_perm"].includes(operation) ? mask : null,
      syscallMatched,
      ...(!syscallMatched && fileOperation
        ? { rejection, refusedCalls: refused.length }
        : {}),
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
  namespaceProbes(value.probes);
  requireObservation(Buffer.byteLength(JSON.stringify(value)) <= 8192);
  return structuredClone(value);
}
function namespaceProbes(probes, offset = 0) {
  for (const [index, probe] of observationList(probes, 2).entries()) {
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
      probe.mode === ["ordinary", "nested"][index + offset] &&
        typeof probe.passed === "boolean" &&
        typeof probe.settled === "boolean" &&
        typeof probe.replayMatched === "boolean" &&
        (probe.exitCode === null ||
          (Number.isInteger(probe.exitCode) &&
            probe.exitCode >= 0 &&
            probe.exitCode <= 255)) &&
        signal(probe.signal) &&
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
      const legacy = !Object.hasOwn(denial, "syscallMatched");
      const diagnostic = Object.hasOwn(denial, "rejection");
      observationObject(denial, [
        "operation",
        "label",
        "capability",
        ...(legacy ? [] : ["target", "mask", "syscallMatched"]),
        ...(diagnostic ? ["rejection", "refusedCalls"] : []),
      ]);
      requireObservation(
        [...AUDIT_OPERATIONS, "other"].includes(denial.operation) &&
          LABELS.includes(denial.label) &&
          (denial.operation === "capable"
            ? Object.hasOwn(CAPABILITY_NUMBERS, denial.capability)
            : denial.capability === null),
      );
      if (!legacy)
        requireObservation(
          [null, "uid_map", "gid_map", "setgroups", "other"].includes(
            denial.target,
          ) &&
            [null, "write", "other"].includes(denial.mask) &&
            typeof denial.syscallMatched === "boolean" &&
            (["open", "file_perm"].includes(denial.operation)
              ? denial.target !== null && denial.mask !== null
              : denial.target === null && denial.mask === null),
        );
      if (diagnostic)
        requireObservation(
          !legacy &&
            denial.syscallMatched === false &&
            ["open", "file_perm"].includes(denial.operation) &&
            MAPPING_REJECTIONS.includes(denial.rejection) &&
            Number.isInteger(denial.refusedCalls) &&
            denial.refusedCalls >= 0 &&
            denial.refusedCalls <= 4096,
        );
    }
  }
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
  // AppArmor caches repeated capability audits per CPU/profile. Require at least
  // one attributed denial for this pair, not a fresh log line per replay. This
  // permits only a scoped policy trial; both actual after-probes must still pass.
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
  return failed.some((probe) => probe.denials.length > 0) &&
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
        probe.denials.every(
          (denial) =>
            denial.syscallMatched === true &&
            ((denial.operation === "userns_create" &&
              denial.label === "unconfined") ||
              (denial.operation === "capable" &&
                denial.label === "restricted-userns" &&
                ["setuid", "setgid", "setpcap"].includes(denial.capability)) ||
              (["open", "file_perm"].includes(denial.operation) &&
                denial.label === "restricted-userns" &&
                ["uid_map", "gid_map", "setgroups"].includes(denial.target) &&
                denial.mask === "write")),
        ),
    )
    ? "prepare"
    : "blocked";
}

export function initialLinuxNamespacePreparation(context) {
  return {
    schemaVersion: 2,
    ...linuxNamespaceContext(context),
    status: "NOT_RUN",
    phase: null,
    before: null,
    after: null,
    owned: null,
    cause: null,
    cleanupCause: null,
    observationFailure: null,
  };
}
export function normalizeLinuxNamespacePreparation(value, context) {
  const legacy = value?.schemaVersion === 1;
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
    ...(legacy ? [] : ["observationFailure"]),
  ]);
  for (const [key, expected] of Object.entries(linuxNamespaceContext(context)))
    requireObservation(value[key] === expected);
  requireObservation(
    [1, 2].includes(value.schemaVersion) &&
      ["NOT_RUN", "RUNNING", "PASS", "BLOCKED", "FAIL"].includes(
        value.status,
      ) &&
      [null, "diagnosis", "installation", "verification", "cleanup"].includes(
        value.phase,
      ),
  );
  const observationFailure = legacy ? null : value.observationFailure;
  if (observationFailure !== null)
    normalizeObservationFailure(observationFailure);
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
    const details =
      key === "cause"
        ? [
            linuxNamespacePreparationCause(value.before, observationFailure)
              .detail,
          ]
        : [
            LINUX_NAMESPACE_CLEANUP_BLOCKER,
            ...(legacy ? [] : [LINUX_NAMESPACE_CAPTURE_CLEANUP_BLOCKER]),
          ];
    requireObservation(
      value[key].code ===
        (key === "cause" ? "prerequisite-unavailable" : "cleanup-unobserved") &&
        details.includes(value[key].detail),
    );
  }
  return structuredClone({ ...value, schemaVersion: 2, observationFailure });
}
export function linuxNamespacePreparationCause(observation, failure = null) {
  if (failure !== null) {
    normalizeObservationFailure(failure);
    const facts = failure.outcome;
    const remedy =
      JOURNAL_REMEDIES[failure.nativeCode] ??
      "Require complete fixed-probe tracing and independent retirement before admission.";
    return {
      code: "prerequisite-unavailable",
      detail: `prepare linux-namespace-policy: exit=${facts.exitCode ?? "unknown"}, signal=${facts.signal ?? "none"}, timeout=${facts.timedOut === null ? "unknown" : facts.timedOut ? "yes" : "no"}; ${failure.mode ?? "policy"}-${failure.stage}, native=${failure.nativeCode}. ${remedy}`,
    };
  }
  const first = observation?.probes.find(({ passed }) => !passed);
  return {
    code: "prerequisite-unavailable",
    detail: `prepare linux-namespace-policy: exit=${first?.exitCode ?? "unknown"}, signal=${first?.signal ?? "none"}, timeout=${first?.timedOut ? "yes" : "no"}; ${first?.mode ?? "policy"}-${first?.operation ?? "unknown"}, native=${first?.errno ?? "unknown"}. Require attributed matching Ubuntu policy and both fixed probes before admission.`,
  };
}
export const LINUX_NAMESPACE_CLEANUP_BLOCKER =
  "Owned Linux namespace policy remains quarantined until independent native settlement and policy removal are observed.";
export const LINUX_NAMESPACE_CAPTURE_CLEANUP_BLOCKER =
  "Linux namespace probe/capture cleanup remains unproved. Require independent process retirement and identity-checked removal of any owned capture.";

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
      record.observationFailure === null &&
      observation !== null &&
      linuxNamespacePolicyDecision(observation) === "verified" &&
      (record.owned === null
        ? observation.effectiveLabel !== "owned"
        : record.owned.status === "LOADED" &&
          observation.effectiveLabel === "owned"),
  );
  return record;
}
