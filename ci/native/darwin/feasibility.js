import { execFile, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { once } from "node:events";
import {
  chown,
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rename,
  rmdir,
  unlink,
  writeFile,
} from "node:fs/promises";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { StringDecoder } from "node:string_decoder";
import {
  nativeException,
  attemptNativeBuilds,
  hasUnsettledNativeBuild,
  nativeDiagnostic,
  diagnosticCommand,
  observeNativeProcess,
} from "../diagnostics.js";
import {
  darwinStartupCrashDetail,
  darwinStartupDenialDetail,
  readDarwinStartupCrash,
  readDarwinStartupDenial,
  darwinStartupImageUUID,
} from "./startup-crash.js";
import {
  DARWIN_STARTUP_TRACE_INTENT,
  openDarwinStartupTrace,
} from "./startup-trace.js";
import {
  LITERAL_ARGUMENTS,
  feasibilityCapabilities,
  feasibilityFailureCause,
  unavailableFeasibilityResults,
} from "../feasibility/index.js";
import {
  digest,
  normalizeDarwinIdentity,
  sameDarwinIdentity,
} from "./protocol.js";
import {
  openDarwinFaultDomain,
  feasibilityDomainPath,
} from "./feasibility-domain.js";

const execute = diagnosticCommand("darwin/feasibility.js", promisify(execFile));
const SOURCE = fileURLToPath(new URL("./", import.meta.url));
const ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const ENV = Object.freeze({
  CI: "true",
  GITHUB_ACTIONS: "true",
  RUNNER_ENVIRONMENT: "github-hosted",
  RUNNER_OS: "macOS",
  PATH: "/usr/bin:/bin",
  LANG: "C",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_OPTIONAL_LOCKS: "0",
});
const ACCESS = [
  "access.read-only",
  "access.workspace-write",
  "git.denial",
  "network.tcp-denial",
  "ipc.local-denial",
];
const STORAGE = ["storage.private", "storage.substitution"];
const OWNERSHIP = ["ownership.cancel", "ownership.owner-loss"];
const ACCESS_OPERATIONS = [
  "inspect",
  "edit",
  "git-status",
  "git-index",
  "git-ref",
  "control",
  "outside",
  "tcp",
  "unix",
];
const need = (ok) => {
  if (!ok) throw new Error("Incomplete Darwin feasibility observation");
};
function completed(exit, signal = null, code = 0) {
  if (exit.signal === signal && exit.code === (signal ? null : code)) return;
  throw Object.assign(new Error("Native helper did not complete"), exit);
}

/** Complete, bounded transcripts are required even after expected receipts arrive. */
export function assertDarwinFeasibilityTranscript(bytes, expectedRecords) {
  need(
    typeof bytes === "string" &&
      bytes.isWellFormed() &&
      Buffer.byteLength(bytes) <= 65536 &&
      bytes.endsWith("\n") &&
      Number.isSafeInteger(expectedRecords) &&
      expectedRecords > 0,
  );
  const lines = bytes.slice(0, -1).split("\n");
  need(lines.length === expectedRecords);
  for (const line of lines) JSON.parse(line);
}

const STARTUP_PHASES = Object.freeze({
  exec: ["policy-enter", "policy-applied", "exec-enter", "fixture-main"],
  "exec-control": ["policy-enter", "policy-applied", "exec-enter"],
  "fixture-control": ["exec-enter", "fixture-main"],
  "policy-only": ["policy-enter", "policy-applied"],
  "policy-invalid": ["policy-enter"],
  bundle: ["policy-enter", "policy-applied"],
});
// Exact public dyld halt literals, never an arbitrary message tail.
const DYLD_HALTS = Object.freeze({
  "ignition failed": "dyld-ignition",
  "no shared cache in cryptex": "dyld-cryptex",
  "dyld shared region dynamic config data was not set": "dyld-region",
  "dyld private shared cache could not be found": "dyld-cache-missing",
  "dyld shared cache could not be mapped": "dyld-cache-map",
  "missing lazy symbol called": "dyld-lazy-symbol",
});
function expectedPhases(operation) {
  if (Object.hasOwn(STARTUP_PHASES, operation))
    return STARTUP_PHASES[operation];
  need(operation === "storage" || operation === "fault");
  return [];
}

/** Markers describe a bounded prefix only; they prove no admission or retirement. */
export function darwinFeasibilityPhases(bytes, operation, complete = true) {
  need(
    Buffer.isBuffer(bytes) &&
      bytes.length <= 65536 &&
      typeof complete === "boolean",
  );
  const captured = complete
    ? bytes
    : bytes.subarray(0, bytes.lastIndexOf(10) + 1);
  const source = new TextDecoder("utf-8", {
    fatal: true,
    ignoreBOM: true,
  }).decode(captured);
  const phases = [],
    expected = expectedPhases(operation);
  for (const line of source.split("\n")) {
    if (!line.trimStart().startsWith("native-darwin-phase")) continue;
    const phase = /^native-darwin-phase: phase=([a-z-]+)$/u.exec(line)?.[1];
    need(phase !== undefined && phase === expected[phases.length]);
    phases.push(phase);
  }
  if (complete && !source.endsWith("\n"))
    need(
      !source
        .slice(source.lastIndexOf("\n") + 1)
        .trimStart()
        .startsWith("native-darwin-phase"),
    );
  return phases;
}

/** A small experiment policy, independent of the full reviewed policy factory. */
export function darwinFeasibilityPolicy(
  root,
  workspaceWrite = false,
  fixtureExec = true,
) {
  need(
    typeof root === "string" &&
      root.isWellFormed() &&
      Buffer.byteLength(root) <= 4096 &&
      path.posix.isAbsolute(root) &&
      path.posix.normalize(root) === root &&
      root !== "/" &&
      !/[\p{Cc}\p{Zl}\p{Zp}]/u.test(root),
  );
  need(
    ["/usr/lib", "/System/Library"].every(
      (base) => root !== base && !root.startsWith(`${base}/`),
    ),
  );
  need(typeof workspaceWrite === "boolean");
  need(typeof fixtureExec === "boolean");
  const quote = (value) =>
    `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
  const literal = (relative) =>
    `(literal ${quote(path.posix.join(root, relative))})`;
  const images = ["build/helper", "build/argv-fixture", "build/git"]
    .map(literal)
    .join(" ");
  const executables = (
    fixtureExec
      ? ["build/helper", "build/argv-fixture", "build/git"]
      : ["build/helper", "build/git"]
  )
    .map(literal)
    .join(" ");
  const runtime = '(subpath "/usr/lib") (subpath "/System/Library")';
  return [
    "(version 1)",
    "(deny default)",
    "(allow process-fork)",
    "(allow process-info* (target same-sandbox))",
    // Pinned runtime baseline: only the loader's Sandbox container query.
    '(allow system-mac-syscall (require-all (mac-policy-name "Sandbox") (mac-syscall-number 67)))',
    `(allow process-exec ${executables})`,
    `(allow file-map-executable ${runtime} ${images})`,
    `(allow file-read* ${runtime} (literal "/dev/null") ${images} (subpath ${quote(path.posix.join(root, "workspace"))}))`,
    '(allow file-read-data (literal "/"))',
    `(allow file-write* (literal "/dev/null")${workspaceWrite ? ` ${literal("workspace/edited.txt")}` : ""})`,
    "",
  ].join("\n");
}

export function darwinFeasibilityIdentityArguments(input) {
  const i = normalizeDarwinIdentity(input);
  return [
    i.auid,
    i.uid,
    i.gid,
    i.ruid,
    i.rgid,
    i.pid,
    i.asid,
    i.pidVersion,
    i.startSeconds,
    i.startMicroseconds,
    i.svuid,
    i.svgid,
  ].map(String);
}

function assertDarwinFaultRetirement(evidence, completeFault = true) {
  const { record, fresh, settled } = evidence;
  need(
    evidence.complete === true &&
      evidence.independent === true &&
      evidence.nonEmergency === true &&
      record.stage === 5 &&
      record.emergency === false &&
      record.asid > 0 &&
      (completeFault ? /^[a-f0-9]{64}$/u : /^(?:[a-f0-9]{64})?$/u).test(
        record.intentSha256,
      ) &&
      Array.isArray(record.members) &&
      record.members.length >= (completeFault ? 2 : 0) &&
      record.members.length <= 32 &&
      fresh.complete === true &&
      fresh.independent === true &&
      fresh.held === true &&
      settled.complete === true &&
      settled.independent === true &&
      settled.held === false &&
      settled.record.stage === 6 &&
      JSON.stringify(fresh.record) === JSON.stringify(record),
  );
  const custodian = normalizeDarwinIdentity(record.custodian),
    verifier = normalizeDarwinIdentity(fresh.verifier),
    final = normalizeDarwinIdentity(settled.verifier);
  need(
    [custodian, verifier, final].every((value) =>
      ["uid", "ruid", "svuid", "gid", "rgid", "svgid", "auid"].every(
        (field) => value[field] === 0,
      ),
    ) &&
      verifier.pid !== final.pid &&
      [custodian, verifier, final].every(
        (value) => value.asid !== record.asid,
      ) &&
      verifier.pid !== custodian.pid &&
      final.pid !== custodian.pid,
  );
  for (const field of [
    "candidateSha",
    "caseId",
    "asid",
    "intentSha256",
    "helperSha256",
    "policySha256",
    "owner",
    "descendant",
    "custodian",
    "members",
    "emergency",
  ])
    need(
      JSON.stringify(settled.record[field]) === JSON.stringify(record[field]),
    );
  const members = record.members.map(normalizeDarwinIdentity);
  if (!completeFault) {
    const owner = normalizeDarwinIdentity(record.owner);
    need(
      owner.asid === record.asid &&
        ["auid", "uid", "ruid", "svuid"].every(
          (field) => owner[field] === 90001,
        ) &&
        ["gid", "rgid", "svgid"].every((field) => owner[field] === 90002),
    );
  }
  need(
    members.every(
      (value) => value.asid === record.asid && value.auid === record.owner.auid,
    ) &&
      (!completeFault ||
        [record.owner, record.descendant].every((value) =>
          members.some((member) => sameDarwinIdentity(member, value)),
        )),
  );
}

/** Individual recorded retirement is cleanup, never a complete domain boundary. */
export function assessDarwinFeasibilityDomain(observations, evidence = null) {
  need(
    Array.isArray(observations) &&
      observations.length === 2 &&
      observations.every(
        (value) => value?.status === "LIVE" || value?.status === "RETIRED",
      ),
  );
  if (evidence) {
    assertDarwinFaultRetirement(evidence);
    return { status: "PASS", cause: null };
  }
  return observations.some(({ status }) => status === "LIVE")
    ? {
        status: "FAIL",
        cause: {
          code: "observed-escape",
          detail:
            "A recorded detached Darwin fixture survived the acknowledged ownership fault.",
        },
      }
    : {
        status: "BLOCKED",
        cause: {
          code: "prerequisite-unavailable",
          detail:
            "Recorded fixture retirement cannot verify recovery of a complete Darwin descendant domain.",
        },
      };
}

function prerequisiteDiagnostic(error, cleanupOnly = false) {
  const operations = [
    "helper-invariant",
    "helper-output",
    "worker-identity",
    "worker-environment",
    "audit-binding",
    "sandbox-binding",
    "bsd-identity",
    "bsd-identity-again",
    "task-name",
    "task-audit",
    "task-audit-again",
    "task-audit-count",
    "identity-stable",
    "identity-parent",
    "task-release",
    "audit-signal",
    "prerequisite-pipe",
    "prerequisite-fork",
    "prerequisite-close",
    "prerequisite-wait",
    "prerequisite-backstop",
    "prerequisite-child-status",
    "prerequisite-settlement",
    "bundle-pipe",
    "bundle-fork",
    "bundle-close",
    "bundle-read",
    "bundle-write",
    "bundle-wait",
    "bundle-child-status",
    "bundle-authorization",
    "bundle-signal",
    "fault-pipe",
    "fault-fork",
    "fault-close",
    "fault-read",
    "fault-write",
    "fault-wait",
    "fault-child-status",
    "fault-child-backstop",
    "fault-authorization",
    "fault-acknowledgment",
    "fault-command",
    "fault-detach",
    "fault-signal",
    "fault-settlement",
    "audit-census-audit",
    "audit-census-audit-again",
    "audit-census-binding",
    "audit-census-bsd",
    "audit-census-bsd-again",
    "audit-census-capacity",
    "audit-census-duplicate",
    "audit-census-list",
    "audit-census-pid",
    "audit-census-session",
    "audit-session-binding",
    "audit-session-create",
    "audit-session-hold",
    "audit-session-port",
    "audit-session-read",
    "fault-access-authority",
    "fault-access-kind",
    "fault-access-port",
    "fault-access-release",
    "fault-access-service",
    "fault-birth-binding",
    "fault-birth-read",
    "fault-birth-write",
    "fault-bootstrap-port",
    "fault-control-audit-binding",
    "fault-control-audit-create",
    "fault-control-audit-hold",
    "fault-control-audit-port",
    "fault-control-audit-read",
    "fault-control-gid",
    "fault-control-groups",
    "fault-control-parent",
    "fault-control-task",
    "fault-control-task-port",
    "fault-control-uid",
    "fault-copy-binding",
    "fault-copy-buffer",
    "fault-copy-close",
    "fault-copy-create",
    "fault-copy-hash",
    "fault-copy-mode",
    "fault-copy-open",
    "fault-copy-owner",
    "fault-copy-read",
    "fault-copy-shape",
    "fault-copy-stat",
    "fault-copy-sync",
    "fault-copy-write",
    "fault-debug-port",
    "fault-environment",
    "fault-fd-count",
    "fault-fd-list",
    "fault-gate-read",
    "fault-gate-value",
    "fault-gate-write",
    "fault-gid",
    "fault-groups",
    "fault-host-kind",
    "fault-host-port",
    "fault-host-release",
    "fault-inherited-stat",
    "fault-journal-access",
    "fault-journal-binding",
    "fault-journal-close",
    "fault-journal-duplicate",
    "fault-journal-flags",
    "fault-journal-mode",
    "fault-journal-open",
    "fault-journal-owner",
    "fault-journal-read",
    "fault-journal-shape",
    "fault-journal-stat",
    "fault-journal-sync",
    "fault-journal-transfer",
    "fault-journal-write",
    "fault-lease-lock",
    "fault-lease-mode",
    "fault-lease-open",
    "fault-lease-owner",
    "fault-lease-shape",
    "fault-lease-stat",
    "fault-notify-port",
    "fault-output-drain",
    "fault-output-bound",
    "fault-output-read",
    "fault-output-state",
    "fault-payload-exec",
    "fault-poll",
    "fault-port-authority",
    "fault-port-count",
    "fault-port-destroy",
    "fault-port-list",
    "fault-port-list-release",
    "fault-process-limit",
    "fault-reexec",
    "fault-reexec-binding",
    "fault-registered-ports",
    "fault-root-create",
    "fault-root-mode",
    "fault-root-open",
    "fault-root-owner",
    "fault-root-resolve",
    "fault-root-shape",
    "fault-root-stat",
    "fault-root-sync",
    "fault-start-input",
    "fault-start-root",
    "fault-stdio",
    "fault-task-exceptions",
    "fault-thread-exceptions",
    "fault-thread-release",
    "fault-uid",
    "fault-uid-empty",
    "signal-control",
    "filesec-init",
    "filesec-stat",
    "acl-query",
    "acl-presence",
    "acl-read",
    "acl-valid",
    "acl-empty",
    "acl-release",
    "file-stat",
    "file-stat-again",
    "file-stable",
    "file-owner",
    "file-group",
    "file-shape",
    "volume-stat",
    "volume-uuid",
    "volume-length",
    "volume-nonzero",
    "directory-open",
    "directory-close",
    "sandbox-query",
    "sandbox-active",
    "exec-launch",
    "policy-open",
    "policy-read",
    "policy-close",
    "sandbox-apply",
    "image-open",
    "image-read",
    "image-close",
  ];
  const statusOperations = [
    "audit-census-list",
    "audit-census-capacity",
    "audit-census-pid",
    "audit-census-duplicate",
    "audit-census-bsd",
    "audit-census-bsd-again",
    "fault-birth-read",
    "fault-birth-write",
    "fault-copy-read",
    "fault-copy-write",
    "fault-journal-read",
    "fault-journal-write",
    "fault-gate-read",
    "fault-gate-write",
    "fault-child-status",
    "fault-output-drain",
    "fault-fd-list",
    "fault-poll",
    "fault-control-uid",
    "fault-control-gid",
    "fault-control-groups",
    "fault-control-audit-create",
    "fault-control-audit-hold",
  ];
  for (const output of [error?.stderr, error?.stdout]) {
    const bytes = Buffer.isBuffer(output)
      ? output.subarray(0, 65536)
      : typeof output === "string"
        ? Buffer.from(output.slice(0, 65536)).subarray(0, 65536)
        : Buffer.alloc(0);
    for (const line of bytes.toString("utf8").split(/\r?\n/u)) {
      const fields =
        /^native-darwin(-cleanup)?: operation=([a-z-]+) domain=(errno|mach|invariant|status) value=(-?(?:0|[1-9][0-9]{0,9})) effects=(none|possible) settlement=(settled|unsettled)$/u.exec(
          line,
        );
      if (
        fields &&
        Boolean(fields[1]) === cleanupOnly &&
        operations.includes(fields[2]) &&
        Number(fields[4]) >= -2147483648 &&
        Number(fields[4]) <= 2147483647 &&
        (fields[3] !== "status" ||
          (!fields[1] &&
            ((fields[2] === "sandbox-apply" && fields[4] === "-1") ||
              statusOperations.includes(fields[2]))))
      )
        return {
          operation: fields[2],
          domain: fields[3],
          value: Number(fields[4]),
          effects: fields[5],
          settlement: fields[6],
        };
    }
  }
  return null;
}

export function darwinFeasibilityCause(stage, error) {
  if (error?.feasibilityCause)
    return unavailableFeasibilityResults("darwin", error.feasibilityCause)[0]
      .cause;
  const nativeOperation =
    typeof error?.nativeOperation === "string" &&
    Object.hasOwn(STARTUP_PHASES, error.nativeOperation)
      ? error.nativeOperation
      : null;
  const operation = nativeOperation
    ? `${stage}-${nativeOperation}`
    : ACCESS_OPERATIONS.includes(error?.operation)
      ? `${stage}-${error.operation}`
      : stage;
  const cause = feasibilityFailureCause(
    "darwin",
    operation,
    {
      ...error,
      code: error?.code,
      signal: error?.signal,
      timedOut:
        error?.timedOut ?? (error?.signal === "SIGALRM" ? true : undefined),
    },
    error?.code === "ERR_FEASIBILITY_ESCAPE"
      ? "observed-escape"
      : error?.code === 78 || error?.code === "ERR_FEASIBILITY_UNAVAILABLE"
        ? "prerequisite-unavailable"
        : "setup-failed",
  );
  const diagnostic = prerequisiteDiagnostic(error);
  const diagnosed = diagnostic
    ? {
        ...cause,
        detail: cause.detail
          .replace(
            /; output=.*$/u,
            `; output=recognized; Native ${diagnostic.operation} failed (${diagnostic.domain}=${diagnostic.value}).`,
          )
          .slice(0, 256),
      }
    : cause;
  // Recheck the operation's ordered prefix at the public boundary.
  const phases = error?.nativePhases,
    expected = nativeOperation ? STARTUP_PHASES[nativeOperation] : [];
  const phase =
    Array.isArray(phases) &&
    phases.length > 0 &&
    phases.length <= expected.length &&
    expected
      .slice(0, phases.length)
      .every((value, index) => value === phases[index])
      ? phases.at(-1)
      : null;
  let abort = null,
    detail = diagnosed.detail;
  if (nativeOperation && error?.signal === "SIGABRT") {
    // Only fixed loader prefixes survive; image paths and arbitrary tails do not.
    const bytes = Buffer.isBuffer(error.stderr)
      ? error.stderr.subarray(0, 65536)
      : typeof error.stderr === "string"
        ? Buffer.from(error.stderr.slice(0, 65536)).subarray(0, 65536)
        : Buffer.alloc(0);
    abort = "unobserved";
    for (const line of bytes.toString("utf8").split(/\r?\n/u)) {
      const loader =
        /^dyld(?:\[[1-9][0-9]{0,9}\])?: (Library not loaded|Symbol not found): /u.exec(
          line,
        );
      const halt = /^dyld(?:\[[1-9][0-9]{0,9}\])?: (.+)$/u.exec(line);
      if (loader || (halt && Object.hasOwn(DYLD_HALTS, halt[1]))) {
        abort = loader
          ? loader[1] === "Library not loaded"
            ? "dyld-library"
            : "dyld-symbol"
          : DYLD_HALTS[halt[1]];
        if (!diagnostic)
          detail = detail.replace(/; output=.*$/u, "; output=recognized");
        break;
      }
    }
  }
  const crashDetail =
    error?.signal === "SIGABRT" && nativeOperation
      ? darwinStartupCrashDetail(error.nativeCrash)
      : "";
  const denialDetail =
    nativeOperation && error?.signal === "SIGABRT"
      ? darwinStartupDenialDetail(error.nativeDenial)
      : "";
  const observationDetail =
    Array.isArray(error?.feasibilityObservationFailures) &&
    error.feasibilityObservationFailures.length > 0 &&
    error.feasibilityObservationFailures.length <= 2 &&
    error.feasibilityObservationFailures.every(
      (failure) =>
        failure &&
        Object.keys(failure).sort().join(",") === "source,status" &&
        ["nativeCrash", "nativeDenial"].includes(failure.source) &&
        failure.status === "read-failed",
    )
      ? "; observation=failed"
      : "";
  const trace = error?.nativeTrace;
  const traceDetail =
    trace &&
    ["unavailable", "refused", "partial", "observed"].includes(trace.status)
      ? `; startup-trace=${trace.status}${trace.cleanup === "UNCERTAIN" ? "; trace-cleanup=uncertain" : ""}`
      : "";
  const startupDetail = `${phase ? `; phase=${phase}` : ""}${abort ? `; abort-cause=${abort}` : ""}`;
  const diagnosisDetail = `${crashDetail}${denialDetail}${observationDetail}`;
  // The full trace record stays private. Its optional summary cannot displace
  // the original signal, phase or crash/log diagnosis in the bounded cause.
  const traceSummary =
    startupDetail.length + diagnosisDetail.length + traceDetail.length + 18 <=
    256
      ? traceDetail
      : "";
  const suffix = startupDetail + traceSummary + diagnosisDetail;
  let prefix = detail.slice(0, 256 - suffix.length);
  if (abort && !prefix.includes("signal=SIGABRT")) {
    const signal = "; signal=SIGABRT";
    prefix = detail.slice(0, 256 - suffix.length - signal.length) + signal;
  }
  const argumentDetail =
    traceDetail &&
    [
      "complete",
      "unsupported",
      "missing",
      "copy-failed",
      "truncated",
      "malformed",
      "unavailable",
    ].includes(trace.argumentStatus)
      ? `; trace-args=${trace.argumentStatus}`
      : "";
  // Additional argument status has lower priority than every existing fact.
  const argumentSummary =
    prefix.length + suffix.length + argumentDetail.length <= 256
      ? argumentDetail
      : "";
  return {
    ...diagnosed,
    detail: prefix + suffix + argumentSummary,
  };
}
function uncertain(emergency = false) {
  return {
    status: "UNCERTAIN",
    independent: false,
    emergency,
    elapsedMs: null,
    witnessSha256: null,
    cause: {
      code: "cleanup-unobserved",
      detail: "Darwin fixture cleanup was not independently settled.",
    },
  };
}
function unavailable(ids, cause, components = [], possible = false) {
  return unavailableFeasibilityResults("darwin", cause)
    .filter(({ capability }) => ids.includes(capability))
    .map((entry) => ({
      ...entry,
      components,
      // The report gate escalates unsettled cleanup without replacing first cause.
      ...(possible ? { cleanup: uncertain() } : {}),
    }));
}
function result(
  capability,
  components,
  observation,
  before,
  after,
  cleanup,
  started,
  decision = null,
) {
  const outcome = feasibilityCapabilities("darwin").find(
    ({ id }) => id === capability,
  ).outcome;
  return {
    capability,
    status: decision?.status ?? "PASS",
    cause: decision?.cause ?? null,
    elapsedMs: Math.ceil(performance.now() - started),
    components,
    evidence: {
      ready: true,
      positiveControl: true,
      attemptAcknowledged: true,
      independent: true,
      outcome: decision ? null : outcome,
      observationSha256: digest(JSON.stringify(observation)),
      sentinelsBeforeSha256: digest(JSON.stringify(before)),
      sentinelsAfterSha256: digest(JSON.stringify(after)),
    },
    cleanup,
  };
}
function settled(observation, elapsedMs, emergency = false) {
  return {
    status: emergency ? "UNCERTAIN" : "PASS",
    independent: true,
    emergency,
    elapsedMs: Math.ceil(elapsedMs),
    witnessSha256: digest(JSON.stringify(observation)),
    cause: emergency
      ? {
          code: "cleanup-unobserved",
          detail:
            "Intervention retired recorded Darwin fixtures without verifying a complete descendant domain.",
        }
      : null,
  };
}
async function command(
  file,
  args,
  cwd,
  env = ENV,
  timeout = 12000,
  run = execute,
) {
  let timedOut = false;
  // Observe our deadline directly: a killed flag can also mean an output limit.
  const timer = setTimeout(() => {
    timedOut = true;
  }, timeout);
  try {
    return await run(file, args, {
      cwd,
      env,
      encoding: "utf8",
      timeout,
      maxBuffer: 65536,
    });
  } catch (error) {
    nativeException("darwin/feasibility.js:exception", error);
    error.timedOut ??=
      timedOut ||
      ["ETIMEDOUT", "ERR_FEASIBILITY_DEADLINE"].includes(error.code);
    throw error;
  } finally {
    clearTimeout(timer);
  }
}
async function native(root, operation, ...args) {
  const { stdout } = await command(
    path.join(root, "build/helper"),
    [operation, ...args],
    root,
  );
  return JSON.parse(stdout);
}
export async function startupObserver(
  root,
  operation,
  value,
  helperSha256,
  { run = execute, read = readFile } = {},
) {
  let args;
  if (operation === "startup-observer") {
    need(Number.isSafeInteger(value) && value > 1 && value <= 0x7fffffff);
    args = [String(value)];
  } else {
    need(
      ["startup-observer-observe", "startup-observer-retire"].includes(
        operation,
      ),
    );
    args = darwinFeasibilityIdentityArguments(value);
    need(Number(args[5]) > 1);
  }
  const helper = path.join(root, "build/helper");
  need(
    /^[a-f0-9]{64}$/u.test(helperSha256) &&
      digest(await read(helper)) === helperSha256,
  );
  const { stdout } = await command(
    "/usr/bin/sudo",
    [
      "--non-interactive",
      "CI=true",
      "GITHUB_ACTIONS=true",
      "RUNNER_ENVIRONMENT=github-hosted",
      "RUNNER_OS=macOS",
      "--",
      helper,
      operation,
      ...args,
    ],
    root,
    { PATH: "/usr/bin:/bin", LANG: "C" },
    12000,
    run,
  );
  need(digest(await read(helper)) === helperSha256);
  return JSON.parse(stdout);
}
async function persist(root, name, value, write = writeFile) {
  await write(
    path.join(root, "evidence", `${name}.json`),
    JSON.stringify(value),
    { flag: "wx", mode: 0o600 },
  );
}

/* Interactive helpers stay parked until their receipt is independently joined.
 * Deadlines reject without a numeric-PID signal; recorded identity owns teardown. */
export function openDarwinFeasibilitySession(
  root,
  operation,
  args,
  { launch = spawn, startupCustody = false } = {},
) {
  need(typeof startupCustody === "boolean");
  if (startupCustody)
    need(Object.hasOwn(STARTUP_PHASES, operation) && operation !== "bundle");
  const requiredPhases = expectedPhases(operation);
  // The existing self-exec fault vector has no argv fixture main.
  const faultSession =
    operation === "exec" &&
    args.length === 3 &&
    args[1] === path.join(root, "build/helper") &&
    args[2] === "fault";
  const gated = operation === "bundle" || faultSession;
  const phaseCount = requiredPhases.length - (faultSession ? 1 : 0);
  let child;
  try {
    child = launch(path.join(root, "build/helper"), [operation, ...args], {
      cwd: root,
      env: {
        ...ENV,
        NATIVE_OWNERSHIP_CUSTODY: "true",
        ...(startupCustody ? { NATIVE_STARTUP_CUSTODY: "true" } : {}),
      },
      stdio: ["pipe", "pipe", "pipe"],
    });
  } catch (error) {
    nativeException("darwin/feasibility.js:exception", error);
    throw Object.assign(error, {
      nativeOperation: operation,
      nativePhases: [],
    });
  }
  const records = [],
    waiting = [];
  observeNativeProcess(`darwin-helper:${operation}`, child);
  let bytes = "",
    transcript = "",
    stderr = Buffer.alloc(0),
    failureCause = null,
    ended = false,
    total = 0,
    consumed = 0,
    phases = [],
    exit,
    pendingOutputBytes = 0,
    inputClosing = false,
    inputCloseError,
    authorizations = 0;
  const observedFailure = (error) =>
    Object.assign(error, {
      ...exit,
      ...error,
      ...(exit ? { exitCode: exit.code, signal: exit.signal } : {}),
      stderr,
      nativeOperation: operation,
      nativePhases: [...phases],
    });
  const closed = new Promise((resolve) =>
    child.once("close", (code, signal) => {
      ended = true;
      exit = { code, signal };
      nativeDiagnostic(`darwin-helper:${operation}`, {
        partial: Boolean(failureCause),
        truncated: total > 65536,
      });
      if (failureCause) observedFailure(failureCause);
      resolve(exit);
      drain();
    }),
  );
  const waitClosed = async () => {
    let timer;
    try {
      return await Promise.race([
        closed,
        new Promise((_, reject) => {
          timer = setTimeout(
            () =>
              reject(
                observedFailure(
                  Object.assign(new Error("Native pipe closure deadline"), {
                    code: "ERR_FEASIBILITY_DEADLINE",
                  }),
                ),
              ),
            30000,
          );
        }),
      ]);
    } finally {
      clearTimeout(timer);
    }
  };
  const drain = () => {
    while (waiting.length && (records.length || failureCause || ended)) {
      const { resolve, reject, timer } = waiting.shift();
      clearTimeout(timer);
      if (failureCause) reject(observedFailure(failureCause));
      else if (records.length) {
        consumed++;
        resolve(records.shift());
      } else reject(observedFailure(new Error("Missing native receipt")));
    }
  };
  const closeInput = () => {
    if (inputClosing) {
      if (inputCloseError) throw inputCloseError;
      return;
    }
    inputClosing = true;
    try {
      child.stdin.end();
    } catch (error) {
      inputCloseError = error;
      child.stdin.destroy();
      throw error;
    }
  };
  const refuse = (error) => {
    failureCause ??= error;
    if (gated)
      try {
        closeInput();
      } catch (cleanupError) {
        nativeException("darwin-helper-input-close", cleanupError);
      }
    drain();
  };
  child.on("error", (error) => {
    refuse(error);
  });
  child.stdin.on("error", (error) => {
    nativeException("darwin-helper-input", error);
    refuse(error);
  });
  for (const stream of ["stdout", "stderr"])
    child[stream]
      .on("error", (error) => {
        nativeException(`darwin-helper-${stream}`, error);
        refuse(error);
      })
      .on("close", () => {
        if (gated && !child[stream].readableEnded)
          refuse(new Error("Native gated output closed before EOF"));
      });
  child.stderr.on("end", () => {
    if (gated && authorizations !== 2)
      refuse(new Error("Native gated diagnostic stream ended before release"));
  });
  child.stderr.on("data", (chunk) => {
    total += chunk.length;
    stderr = Buffer.concat([stderr, chunk.subarray(0, 65536 - stderr.length)]);
    if (total > 65536)
      nativeDiagnostic(`darwin-helper:${operation}`, {
        truncated: true,
        partial: true,
      });
    try {
      need(total <= 65536);
      phases = darwinFeasibilityPhases(stderr, operation, false);
      if (gated && prerequisiteDiagnostic({ stderr }))
        refuse(new Error("Native gated helper refused admission"));
    } catch (error) {
      nativeException("darwin/feasibility.js:exception", error);
      refuse(error);
    }
  });
  const decoder = new StringDecoder("utf8");
  const consume = (chunk) => {
    if (failureCause) return;
    if (total > 65536)
      nativeDiagnostic(`darwin-helper:${operation}`, {
        truncated: true,
        partial: true,
      });
    try {
      need(total <= 65536);
      transcript += chunk;
      bytes += chunk;
      while (bytes.includes("\n")) {
        const index = bytes.indexOf("\n");
        records.push(JSON.parse(bytes.slice(0, index)));
        bytes = bytes.slice(index + 1);
      }
    } catch (error) {
      nativeException("darwin/feasibility.js:exception", error);
      refuse(error);
    }
    drain();
  };
  child.stdout.on("data", (chunk) => {
    total += chunk.length;
    const newline = chunk.lastIndexOf(10);
    pendingOutputBytes =
      newline < 0
        ? pendingOutputBytes + chunk.length
        : chunk.length - newline - 1;
    consume(decoder.write(chunk));
  });
  child.stdout.on("end", () => {
    consume(decoder.end());
    if (
      gated &&
      (authorizations !== 2 ||
        pendingOutputBytes !== 0 ||
        consumed + records.length !==
          (faultSession ? 3 : 1 + ACCESS_OPERATIONS.length * 2))
    )
      refuse(new Error("Native bundle receipt stream ended before completion"));
  });
  return {
    child,
    closeInput,
    authorize: async (value) => {
      if (failureCause) throw observedFailure(failureCause);
      try {
        need(
          gated &&
            (faultSession && authorizations === 1
              ? ["C", "L"].includes(value)
              : value ===
                (faultSession ? ["A"] : ["A", "G"])[authorizations]) &&
            !ended &&
            !inputClosing &&
            !child.stdin.destroyed &&
            child.stdin.writable &&
            !child.stdout.destroyed &&
            !child.stdout.readableEnded &&
            !child.stderr.destroyed &&
            !child.stderr.readableEnded &&
            records.length === 0 &&
            bytes.length === 0 &&
            pendingOutputBytes === 0,
        );
        authorizations++;
        await new Promise((resolve, reject) =>
          child.stdin.write(value, (error) =>
            error ? reject(error) : resolve(),
          ),
        );
        if (failureCause) throw failureCause;
      } catch (error) {
        refuse(error);
        throw observedFailure(failureCause);
      }
    },
    waitClosed,
    authorizationStarted: () => authorizations > 0,
    diagnostic: (cleanupOnly = false) =>
      prerequisiteDiagnostic({ stderr }, cleanupOnly),
    failure: () => (failureCause ? observedFailure(failureCause) : null),
    phases: () => [...phases],
    finish: async (signal = null, code = 0) => {
      await waitClosed();
      try {
        if (failureCause) throw failureCause;
        assertDarwinFeasibilityTranscript(transcript, consumed);
        phases = darwinFeasibilityPhases(stderr, operation);
        need(phases.length === phaseCount);
        completed(exit, signal, code);
        return exit;
      } catch (error) {
        nativeException("darwin/feasibility.js:exception", error);
        throw observedFailure(error);
      }
    },
    next: () =>
      new Promise((resolve, reject) => {
        const waiter = {
          resolve,
          reject,
          timer: setTimeout(() => {
            waiting.splice(waiting.indexOf(waiter), 1);
            const error = Object.assign(new Error("Native receipt deadline"), {
              code: "ERR_FEASIBILITY_DEADLINE",
            });
            refuse(error);
            reject(observedFailure(error));
            drain();
          }, 12000),
        };
        waiting.push(waiter);
        drain();
      }),
  };
}
function session(root, operation, ...args) {
  return openDarwinFeasibilitySession(root, operation, args);
}
function startupSession(root, operation, ...args) {
  return openDarwinFeasibilitySession(root, operation, args, {
    startupCustody: true,
  });
}

async function armStartup(
  root,
  operation,
  running,
  components,
  policy,
  inspect,
  save,
  retain,
  options,
) {
  need(
    JSON.stringify(await running.next()) ===
      JSON.stringify({ phase: "launch-armed" }),
  );
  const identity = normalizeDarwinIdentity(
    await inspect(root, "identity", String(running.child.pid)),
  );
  need(identity.pid === running.child.pid);
  retain(identity);
  const image = await inspect(
      root,
      "image",
      ...darwinFeasibilityIdentityArguments(identity),
      path.join(root, "build/helper"),
    ),
    absent = await inspect(
      root,
      "policy-absent",
      ...darwinFeasibilityIdentityArguments(identity),
    );
  need(
    image.sha256 ===
      components.find(
        ({ role, name }) => role === "helper" && name === "helper",
      )?.sha256 && absent.sandboxed === false,
  );
  const policyRead =
    policy === null
      ? null
      : await inspect(
          root,
          "files",
          path.join(
            root,
            "evidence",
            operation === "exec" ? "argv.sb" : `startup-${operation}.sb`,
          ),
        );
  if (policy !== null)
    need(
      Array.isArray(policyRead) &&
        policyRead.length === 1 &&
        policyRead[0].sha256 === digest(policy),
    );
  const launch = {
    identity,
    image,
    startedAt: Date.now(),
    policySha256: policy === null ? null : digest(policy),
    policy: policyRead === null ? null : policyRead[0],
    traceIntent: DARWIN_STARTUP_TRACE_INTENT,
  };
  // The signed original image, native birth and exact policy precede release.
  await save(root, `startup-${operation}-intent`, launch);
  const observe = (selector, value) =>
    startupObserver(root, selector, value, image.sha256, {
      run: options.observerRun,
      read: options.observerRead,
    });
  running.startupTrace = (options.openTrace ?? openDarwinStartupTrace)(launch, {
    readObserver: (pid) => observe("startup-observer", pid),
    observeObserver: (value) => observe("startup-observer-observe", value),
    retireObserver: (value) => observe("startup-observer-retire", value),
  });
  launch.trace = await running.startupTrace.arm();
  // DTrace attachment and diagnostics cannot authorize a substituted birth,
  // helper, sandbox state or policy. Rejoin the original parked child before E.
  need(
    sameDarwinIdentity(
      identity,
      await inspect(root, "identity", String(identity.pid)),
    ),
  );
  need(
    (
      await inspect(
        root,
        "image",
        ...darwinFeasibilityIdentityArguments(identity),
        path.join(root, "build/helper"),
      )
    ).sha256 === image.sha256,
  );
  need(
    (
      await inspect(
        root,
        "policy-absent",
        ...darwinFeasibilityIdentityArguments(identity),
      )
    ).sandboxed === false,
  );
  if (policyRead !== null)
    need(
      JSON.stringify(
        await inspect(
          root,
          "files",
          path.join(
            root,
            "evidence",
            operation === "exec" ? "argv.sb" : `startup-${operation}.sb`,
          ),
        ),
      ) === JSON.stringify(policyRead),
    );
  running.child.stdin.write("E");
  return launch;
}

async function finishStartupTrace(running, error) {
  if (!running?.startupTrace) return null;
  let trace;
  try {
    trace = await running.startupTrace.finish();
    need(
      trace &&
        ["unavailable", "refused", "partial", "observed"].includes(
          trace.status,
        ) &&
        ["NOT_RUN", "RETIRED", "UNCERTAIN"].includes(trace.cleanup),
    );
  } catch (failure) {
    nativeException("darwin/startup-trace-retirement", failure);
    trace = { status: "refused", cleanup: "UNCERTAIN" };
  }
  if (error) error.nativeTrace = trace;
  return trace;
}

function sameStartupBirth(before, after) {
  return (
    before.pid === after.pid &&
    before.startSeconds === after.startSeconds &&
    before.startMicroseconds === after.startMicroseconds &&
    ["uid", "gid", "ruid", "rgid", "svuid", "svgid", "auid", "asid"].every(
      (key) => before[key] === after[key],
    )
  );
}

async function observeStartupFailure(
  root,
  operation,
  running,
  launch,
  components,
  error,
  options,
) {
  if (error.signal !== "SIGABRT" || !launch) return;
  const name =
      ["exec", "fixture-control", "exec-control"].includes(operation) &&
      error.nativePhases?.includes("exec-enter")
        ? "argv-fixture"
        : "helper",
    binding = {
      pid: running.child.pid,
      identity: launch.identity,
      image: path.join(root, "build", name),
      sha256: components.find(
        ({ role, name: image }) => role === "helper" && image === name,
      )?.sha256,
      // Only this already held sibling is compared; report paths never select
      // an additional image or an alias for either native binding.
      alternatives:
        name === "argv-fixture"
          ? [
              {
                image: path.join(root, "build/helper"),
                sha256: components.find(
                  ({ role, name }) => role === "helper" && name === "helper",
                )?.sha256,
              },
            ]
          : [],
      startedAt: launch.startedAt,
      endedAt: launch.endedAt ?? Date.now(),
    };
  const failures = [];
  for (const [field, read] of [
    ["nativeCrash", options.readCrash ?? readDarwinStartupCrash],
    ["nativeDenial", options.readDenial ?? readDarwinStartupDenial],
  ]) {
    try {
      error[field] = await read(binding);
    } catch (diagnosticError) {
      nativeException("darwin/feasibility.js:exception", diagnosticError);
      error[field] = { status: "read-failed" };
      failures.push({ source: field, status: "read-failed" });
    }
  }
  if (failures.length) error.feasibilityObservationFailures = failures;
}

async function retireStartup(root, running, identity, error, inspect) {
  error.feasibilityCleanup ??= uncertain();
  if (!running) return;
  error.nativePhases ??= running.phases();
  let cleanupError;
  try {
    running.child.stdin.end();
  } catch (failure) {
    cleanupError = failure;
  }
  // A close event or phase marker cannot authorize a numeric-PID signal.
  if (identity)
    try {
      const args = darwinFeasibilityIdentityArguments(identity);
      need((await inspect(root, "retire", ...args)).status === "RETIRED");
    } catch (failure) {
      cleanupError ??= failure;
    }
  try {
    await running.waitClosed();
  } catch (failure) {
    cleanupError ??= failure;
  }
  if (cleanupError)
    error.feasibilityCleanup = {
      ...uncertain(),
      cause: darwinFeasibilityCause("startup-retirement", cleanupError),
    };
}

/** The matching-worker owner supplies native effects; portable coverage injects them. */
export async function buildDarwinFeasibility(
  root,
  components,
  {
    executeFile = execute,
    fs = { realpath, readFile, chmod, writeFile },
    commandObservation = false,
    recordResource = async () => {},
  } = {},
) {
  let operation = "compiler-discovery",
    firstCompileOperation;
  const run = (file, args, timeout = 12000) =>
    command(file, args, root, ENV, timeout, executeFile);
  const discover = async (args) => {
    const selected = (await run("/usr/bin/xcrun", args)).stdout.trim();
    need(
      path.isAbsolute(selected) &&
        path.normalize(selected) === selected &&
        Buffer.byteLength(selected) <= 4096 &&
        !/[\p{Cc}\p{Zl}\p{Zp}]/u.test(selected),
    );
    return fs.realpath(selected);
  };
  try {
    const clang = await discover(["--find", "clang"]);
    operation = "compiler-identity";
    const compiler = {
      role: "tool",
      name: "apple-clang",
      version: "unobserved",
      sha256: digest(await fs.readFile(clang)),
    };
    components.push(compiler);
    operation = "compiler-version";
    const compilerVersion = (await run(clang, ["--version"])).stdout.match(
      /^(?:Apple )?clang version [0-9]+(?:\.[0-9]+){1,3}(?: \([A-Za-z0-9._-]{1,64}\))?/u,
    )?.[0];
    need(compilerVersion && Buffer.byteLength(compilerVersion) <= 128);
    compiler.version = compilerVersion;
    operation = "sdk-discovery";
    const sdk = await discover(["--show-sdk-path"]);
    operation = "sdk-identity";
    const sdkComponent = {
      role: "tool",
      name: "macos-sdk",
      version: "unobserved",
      sha256: digest(await fs.readFile(path.join(sdk, "SDKSettings.json"))),
    };
    components.push(sdkComponent);
    operation = "sdk-version";
    const version = (
      await run("/usr/bin/xcrun", ["--show-sdk-version"])
    ).stdout.trim();
    need(
      /^[0-9]+\.[0-9]+(?:\.[0-9]+)?$/u.test(version) &&
        Buffer.byteLength(version) <= 128,
    );
    sdkComponent.version = version;
    operation = "startup-runtime-identity";
    const runtime = Object.fromEntries(
      await Promise.all(
        [
          ["loader", "/usr/lib/dyld"],
          ["signatureVerifier", "/usr/bin/codesign"],
        ].map(async ([name, file]) => [
          name,
          { path: file, sha256: digest(await fs.readFile(file)) },
        ]),
      ),
    );
    const builds = [],
      recipes = [
        ["feasibility-helper.c", "helper"],
        ["argv-fixture.c", "argv-fixture"],
      ].map(([source, name]) => {
        const args = [
          "-std=c11",
          "-arch",
          "x86_64",
          "-isysroot",
          sdk,
          "-O2",
          "-Wall",
          "-Wextra",
          "-Wno-deprecated-declarations",
          "-Wl,-adhoc_codesign",
          ...(name === "helper" ? ["-lsandbox", "-lbsm"] : []),
          ...(name === "helper" && commandObservation
            ? ["-DNATIVE_FEASIBILITY_COMMAND"]
            : []),
          "-o",
          path.join(root, "build", name),
          path.join(SOURCE, source),
        ];
        return { source, name, args };
      });
    const pins = new Map([
      [clang, compiler.sha256],
      [path.join(sdk, "SDKSettings.json"), sdkComponent.sha256],
      ...Object.values(runtime).map((image) => [image.path, image.sha256]),
    ]);
    for (const file of [
      "feasibility-helper.c",
      "argv-fixture.c",
      "feasibility-sandbox.h",
      "feasibility-domain.h",
      "custody.h",
      ...(commandObservation ? ["feasibility-command.h"] : []),
    ])
      pins.set(
        path.join(SOURCE, file),
        digest(await fs.readFile(path.join(SOURCE, file))),
      );
    await attemptNativeBuilds(
      "darwin-feasibility-builds",
      recipes.map(({ name, args }) => ({
        name,
        run: async () => {
          operation = `${name}-compile-link`;
          let result;
          try {
            result = await run(clang, args, 60000);
          } catch (error) {
            firstCompileOperation ??= operation;
            throw error;
          }
          operation = `${name}-acquisition`;
          await recordResource(path.join(root, "build", name));
          return result;
        },
      })),
      {
        verify: async () => {
          for (const [file, pin] of pins)
            need(digest(await fs.readFile(file)) === pin);
        },
      },
    );
    for (const { source, name, args } of recipes) {
      const file = path.join(root, "build", name);
      operation = `${name}-publication`;
      await fs.chmod(file, 0o500);
      await recordResource(file);
      const bytes = await fs.readFile(file);
      operation = `${name}-inspection`;
      const imageUUID = darwinStartupImageUUID(bytes);
      need(imageUUID);
      operation = `${name}-signature-verification`;
      await run("/usr/bin/codesign", ["--verify", "--strict", file]);
      need(digest(await fs.readFile(file)) === digest(bytes));
      for (const image of Object.values(runtime))
        need(digest(await fs.readFile(image.path)) === image.sha256);
      components.push({
        role: "helper",
        name,
        version: "1",
        sha256: digest(bytes),
      });
      operation = `${name}-source-identity`;
      builds.push({
        args,
        imageUUID,
        imageSha256: digest(bytes),
        runtime,
        sourceSha256: digest(await fs.readFile(path.join(SOURCE, source))),
        ...(name === "helper"
          ? {
              bindingSha256: digest(
                await fs.readFile(path.join(SOURCE, "feasibility-sandbox.h")),
              ),
              domainSourceSha256: digest(
                await fs.readFile(path.join(SOURCE, "feasibility-domain.h")),
              ),
              custodySourceSha256: digest(
                await fs.readFile(path.join(SOURCE, "custody.h")),
              ),
              ...(commandObservation
                ? {
                    commandSourceSha256: digest(
                      await fs.readFile(
                        path.join(SOURCE, "feasibility-command.h"),
                      ),
                    ),
                  }
                : {}),
            }
          : {}),
      });
    }
    operation = "git-discovery";
    const git = await discover(["--find", "git"]);
    // Stock Git can be universal; the matching native loader selects its slice.
    // Only the experiment's explicitly x64 compiled helpers use the thin validator.
    operation = "git-identity";
    const gitBytes = await fs.readFile(git);
    const gitComponent = {
      role: "tool",
      name: "apple-git",
      version: "unobserved",
      sha256: digest(gitBytes),
    };
    components.push(gitComponent);
    operation = "git-publication";
    await fs.writeFile(path.join(root, "build/git"), gitBytes, {
      flag: "wx",
      mode: 0o500,
    });
    await recordResource(path.join(root, "build/git"));
    operation = "git-version";
    const gitVersion = (await run(git, ["--version"])).stdout.match(
      /^git version [0-9]+(?:\.[0-9]+){1,3}(?: \(Apple Git-[0-9]+\))?/u,
    )?.[0];
    need(gitVersion && Buffer.byteLength(gitVersion) <= 128);
    gitComponent.version = gitVersion;
    operation = "build-report";
    await persist(root, "build", { components, builds, git }, fs.writeFile);
    await recordResource(path.join(root, "evidence/build.json"));
    return components;
  } catch (error) {
    operation = firstCompileOperation ?? operation;
    nativeException("darwin/feasibility.js:exception", error);
    const stderr =
      typeof error.stderr === "string"
        ? Buffer.from(error.stderr.slice(0, 65536))
            .subarray(0, 65536)
            .toString("utf8")
        : "";
    const missing =
      [
        "compiler-discovery",
        "sdk-discovery",
        "sdk-version",
        "git-discovery",
      ].includes(operation) &&
      (error.code === "ENOENT" ||
        (Number.isInteger(error.code) &&
          error.signal === null &&
          error.timedOut !== true &&
          /unable to find utility|SDK.*cannot be located|invalid active developer path|no developer tools were found/u.test(
            stderr,
          )));
    const condition = error?.darwinInspection;
    if (
      [
        "header",
        "command-table",
        "load-command",
        "segment",
        "purpose",
        "library-name",
        "system-library",
        "loader",
        "signature",
      ].includes(condition)
    )
      operation += `-${condition}`;
    const cause = feasibilityFailureCause(
      "build",
      operation,
      error,
      missing ? "prerequisite-unavailable" : "setup-failed",
    );
    throw Object.assign(
      new Error("Darwin build operation failed.", { cause: error }),
      {
        code: error.code,
        feasibilityCause: missing
          ? {
              ...cause,
              detail: cause.detail.replace(
                "No recognized native explanation was captured.",
                "Installed tool or SDK discovery was unavailable.",
              ),
            }
          : cause,
      },
    );
  }
}

async function snapshots(root) {
  const files = [
    "workspace/.git/index",
    "workspace/.git/refs/heads/fixture",
    "control/sentinel",
    "outside/sentinel",
  ];
  const records = await native(
    root,
    "files",
    ...files.map((file) => path.join(root, file)),
  );
  need(Array.isArray(records) && records.length === files.length);
  for (let i = 0; i < files.length; i++)
    need(
      records[i].sha256 === digest(await readFile(path.join(root, files[i]))),
    );
  let lockAbsent = false;
  try {
    await lstat(path.join(root, "workspace/.git/index.lock"));
  } catch (error) {
    nativeException("darwin/feasibility.js:exception", error);
    if (error.code !== "ENOENT") throw error;
    lockAbsent = true;
  }
  return { records, lockAbsent };
}

/** Fixed startup controls run only inside the matching-worker entry. Tests inject
 * every effect; an outside fixture control is never a fallback after failure. */
export async function runDarwinFeasibilityStartup(
  root,
  components,
  sentinel,
  {
    write = writeFile,
    openSession = startupSession,
    inspect = native,
    readSnapshots = snapshots,
    save = persist,
    ...observers
  } = {},
) {
  const controls = [],
    fixture = path.join(root, "build/argv-fixture");
  for (const operation of [
    "policy-only",
    "fixture-control",
    "policy-invalid",
    "exec-control",
  ]) {
    const negative =
      operation === "policy-invalid" || operation === "exec-control";
    const file = path.join(root, "evidence", `startup-${operation}.sb`);
    let running, identity, launch;
    const policyBytes =
      operation === "fixture-control"
        ? null
        : operation === "policy-invalid"
          ? "(version 1)\n(deliberately-invalid-policy)\n"
          : darwinFeasibilityPolicy(root, false, operation !== "exec-control");
    try {
      if (operation !== "fixture-control")
        await write(file, policyBytes, { flag: "wx", mode: 0o600 });
      const args =
        operation === "fixture-control"
          ? LITERAL_ARGUMENTS
          : operation === "exec-control"
            ? [file, fixture, ...LITERAL_ARGUMENTS]
            : [file];
      running = openSession(root, operation, ...args);
      launch = await armStartup(
        root,
        operation,
        running,
        components,
        policyBytes,
        inspect,
        save,
        (value) => {
          identity = value;
        },
        observers,
      );
      identity = launch.identity;
      need(
        JSON.stringify(await running.next()) ===
          JSON.stringify({ phase: "armed" }),
      );
      const currentIdentity = normalizeDarwinIdentity(
        await inspect(root, "identity", String(running.child.pid)),
      );
      need(sameStartupBirth(launch.identity, currentIdentity));
      identity = currentIdentity;
      const imageName =
        operation === "fixture-control" ? "argv-fixture" : "helper";
      const image = await inspect(
        root,
        "image",
        ...darwinFeasibilityIdentityArguments(identity),
        path.join(root, "build", imageName),
      );
      const component = components.find(
        ({ role, name }) => role === "helper" && name === imageName,
      );
      need(component && image.sha256 === component.sha256);
      const policy = await inspect(
        root,
        operation === "policy-only" ? "policy" : "policy-absent",
        ...darwinFeasibilityIdentityArguments(identity),
      );
      need(policy.sandboxed === (operation === "policy-only"));
      running.child.stdin.end("A");
      if (!negative) {
        const receipt = await running.next();
        need(
          JSON.stringify(receipt) ===
            JSON.stringify(
              operation === "fixture-control"
                ? LITERAL_ARGUMENTS
                : { policyApplied: true },
            ),
        );
      }
      const exit = await running.finish(null, negative ? 126 : 0);
      const diagnostic = running.diagnostic();
      if (negative)
        need(
          operation === "policy-invalid"
            ? diagnostic?.operation === "sandbox-apply" &&
                diagnostic.domain === "status" &&
                diagnostic.value === -1
            : diagnostic?.operation === "exec-launch" &&
                diagnostic.domain === "errno" &&
                [1, 13].includes(diagnostic.value),
        );
      else need(diagnostic === null);
      const retired = await inspect(
        root,
        "observe",
        ...darwinFeasibilityIdentityArguments(identity),
      );
      need(retired.status === "RETIRED");
      launch.trace = await finishStartupTrace(running);
      need(launch.trace.cleanup !== "UNCERTAIN");
      const after = await readSnapshots(root);
      need(JSON.stringify(sentinel) === JSON.stringify(after));
      const observed = {
        operation,
        launch,
        identity,
        image,
        policy,
        exit,
        phases: running.phases(),
        diagnostic,
        retired,
        after,
      };
      await save(root, `startup-${operation}`, observed);
      controls.push(observed);
    } catch (error) {
      nativeException("darwin/feasibility.js:exception", error);
      error.nativeOperation = operation;
      if (launch) launch.endedAt = Date.now();
      await retireStartup(root, running, identity, error, inspect);
      await finishStartupTrace(running, error);
      await observeStartupFailure(
        root,
        operation,
        running,
        launch,
        components,
        error,
        observers,
      );
      throw error;
    }
  }
  return controls;
}
/** Startup controls and the actual confined positive execution share one owner. */
export async function runDarwinFeasibilityArgv(
  root,
  components,
  sentinel,
  options = {},
) {
  const {
    write = writeFile,
    openSession = startupSession,
    inspect = native,
    readSnapshots = snapshots,
    save = persist,
  } = options;
  const started = performance.now();
  const startup = await runDarwinFeasibilityStartup(
    root,
    components,
    sentinel,
    options,
  );
  const file = path.join(root, "evidence/argv.sb");
  const policyBytes = darwinFeasibilityPolicy(root);
  let running, identity, launch;
  try {
    await write(file, policyBytes, {
      flag: "wx",
      mode: 0o600,
    });
    running = openSession(
      root,
      "exec",
      file,
      path.join(root, "build/argv-fixture"),
      ...LITERAL_ARGUMENTS,
    );
    launch = await armStartup(
      root,
      "exec",
      running,
      components,
      policyBytes,
      inspect,
      save,
      (value) => {
        identity = value;
      },
      options,
    );
    identity = launch.identity;
    need(
      JSON.stringify(await running.next()) ===
        JSON.stringify({ phase: "armed" }),
    );
    const currentIdentity = normalizeDarwinIdentity(
      await inspect(root, "identity", String(running.child.pid)),
    );
    need(sameStartupBirth(launch.identity, currentIdentity));
    identity = currentIdentity;
    const image = await inspect(
      root,
      "image",
      ...darwinFeasibilityIdentityArguments(identity),
      path.join(root, "build/argv-fixture"),
    );
    need(
      image.sha256 ===
        components.find(
          ({ role, name }) => role === "helper" && name === "argv-fixture",
        )?.sha256,
    );
    const policy = await inspect(
      root,
      "policy",
      ...darwinFeasibilityIdentityArguments(identity),
    );
    need(policy.sandboxed === true);
    running.child.stdin.end("A");
    const args = await running.next();
    await running.finish();
    need(JSON.stringify(args) === JSON.stringify(LITERAL_ARGUMENTS));
    const closing = performance.now(),
      retired = await inspect(
        root,
        "observe",
        ...darwinFeasibilityIdentityArguments(identity),
      );
    need(retired.status === "RETIRED");
    launch.trace = await finishStartupTrace(running);
    need(launch.trace.cleanup !== "UNCERTAIN");
    const after = await readSnapshots(root);
    need(JSON.stringify(sentinel) === JSON.stringify(after));
    const observation = {
      operation: "exec",
      launch,
      startup,
      phases: running.phases(),
      identity,
      image,
      policy,
      args,
      retired,
      after,
    };
    await save(root, "argv", observation);
    return result(
      "launch.argv",
      components,
      observation,
      sentinel,
      after,
      settled(observation, performance.now() - closing),
      started,
    );
  } catch (error) {
    nativeException("darwin/feasibility.js:exception", error);
    error.nativeOperation = "exec";
    if (launch) launch.endedAt = Date.now();
    await retireStartup(root, running, identity, error, inspect);
    await finishStartupTrace(running, error);
    await observeStartupFailure(
      root,
      "exec",
      running,
      launch,
      components,
      error,
      options,
    );
    throw error;
  }
}

async function controls(root, nonce) {
  let acknowledged = 0,
    firstError;
  const servers = [],
    sockets = new Set();
  const listener = (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    socket.on("error", () => {});
    socket.setTimeout(3000, () => socket.destroy());
    let data = "";
    socket.on("data", (chunk) => {
      data += chunk.toString("utf8");
      if (data.length >= 32) {
        if (data === nonce) {
          acknowledged++;
          socket.end(nonce);
        } else socket.destroy();
      }
    });
  };
  const open = async (options) => {
    const server = net.createServer(listener),
      controller = new AbortController();
    server.on("error", (error) => {
      firstError ??= error;
    });
    servers.push({ server, controller });
    const started = once(server, "listening", { signal: controller.signal });
    const timer = setTimeout(() => controller.abort(), 12000);
    try {
      server.listen({ ...options, signal: controller.signal });
      await started;
      return server;
    } catch (error) {
      nativeException("darwin/feasibility.js:exception", error);
      controller.abort();
      await started.catch(() => {});
      if (error.name === "AbortError")
        throw Object.assign(new Error("Outside control readiness deadline"), {
          code: "ERR_FEASIBILITY_DEADLINE",
        });
      throw error;
    } finally {
      clearTimeout(timer);
    }
  };
  const close = async () => {
    for (const { controller } of servers) controller.abort();
    for (const socket of sockets) socket.destroy();
    await Promise.all(
      servers.map(
        ({ server }) =>
          new Promise((resolve, reject) =>
            server.close((error) =>
              error && error.code !== "ERR_SERVER_NOT_RUNNING"
                ? reject(error)
                : resolve(),
            ),
          ),
      ),
    );
    need(servers.every(({ server }) => !server.listening));
  };
  try {
    const tcp = await open({ port: 0, host: "127.0.0.1" });
    const socket = path.join(root, "outside/endpoint");
    need(Buffer.byteLength(socket) < 104);
    await open({ path: socket });
    const port = String(tcp.address().port);
    const check = async () => {
      if (firstError) throw firstError;
      const before = acknowledged;
      need((await native(root, "control", "tcp", port, nonce)).ready === true);
      need(
        (await native(root, "control", "unix", socket, nonce)).ready === true,
      );
      if (firstError) throw firstError;
      need(acknowledged === before + 2);
      return acknowledged;
    };
    return { port, socket, check, count: () => acknowledged, close };
  } catch (error) {
    nativeException("darwin/feasibility.js:exception", error);
    try {
      await close();
    } catch (diagnosticError) {
      nativeException("darwin/feasibility.js:exception", diagnosticError);
      /* The original setup failure remains authoritative. */
    }
    throw error;
  }
}
/** The confined PID is only a locator; outside observers own admission and retirement. */
export async function runDarwinFeasibilityBundle(
  root,
  running,
  components,
  policyPath,
  policyBytes,
  {
    inspect = native,
    save = persist,
    ownerPid = process.pid,
    workspaceWrite = false,
  } = {},
) {
  const custody = {
    ownerPid: running.child.pid,
    owner: null,
    child: null,
    childPid: null,
    initialReleasePossible: false,
    gitReleasePossible: false,
    childRetired: null,
    ownerRetired: null,
    nativeCleanup: null,
    closed: false,
  };
  running.bundleCustody = custody;
  const receipts = [];
  let error, cleanupError, parentBinding, childBinding, policyFile;
  const helper = path.join(root, "build/helper");
  const helperHash = components.find(
    ({ role, name }) => role === "helper" && name === "helper",
  )?.sha256;
  const identityAt = async (pid, parent) =>
    normalizeDarwinIdentity(
      await inspect(root, "identity", String(pid), String(parent)),
    );
  const recheck = async (identity, parent) =>
    need(sameDarwinIdentity(identity, await identityAt(identity.pid, parent)));
  const binding = async (identity) => {
    const args = darwinFeasibilityIdentityArguments(identity);
    const image = await inspect(root, "image", ...args, helper);
    need(image.sha256 === helperHash);
    const policy = await inspect(root, "policy", ...args);
    need(policy.sandboxed === true);
    return { image, policy };
  };
  try {
    need(
      /^[a-f0-9]{64}$/u.test(helperHash ?? "") &&
        typeof workspaceWrite === "boolean" &&
        Number.isSafeInteger(ownerPid) &&
        ownerPid > 1 &&
        ownerPid <= 0x7fffffff,
    );
    const ready = await running.next();
    need(JSON.stringify(ready) === JSON.stringify({ event: "ready" }));
    receipts.push(ready);
    const owner = await identityAt(running.child.pid, ownerPid);
    need(owner.pid === running.child.pid);
    custody.owner = owner; // Retain the independently acquired birth before other queries.
    parentBinding = await binding(owner);
    policyFile = await inspect(root, "files", policyPath);
    need(
      Array.isArray(policyFile) &&
        policyFile.length === 1 &&
        policyFile[0].sha256 === digest(policyBytes),
    );
    await recheck(owner, ownerPid);
    custody.initialReleasePossible = true;
    await running.authorize("A");
    for (const operation of ACCESS_OPERATIONS) {
      const attempt = await running.next();
      need(attempt.event === "attempt" && attempt.operation === operation);
      receipts.push(attempt);
      if (operation === "git-status") {
        need(
          Object.keys(attempt).length === 3 &&
            Number.isSafeInteger(attempt.childPid) &&
            attempt.childPid > 1 &&
            attempt.childPid <= 0x7fffffff &&
            attempt.childPid !== owner.pid,
        );
        custody.childPid = attempt.childPid;
        await recheck(owner, ownerPid);
        const child = await identityAt(attempt.childPid, owner.pid);
        need(child.pid === attempt.childPid);
        custody.child = child;
        need(
          [
            "auid",
            "asid",
            "uid",
            "gid",
            "ruid",
            "rgid",
            "svuid",
            "svgid",
          ].every((field) => child[field] === owner[field]),
        );
        childBinding = await binding(child);
        need(
          JSON.stringify(await inspect(root, "files", policyPath)) ===
            JSON.stringify(policyFile),
        );
        parentBinding = await binding(owner);
        await recheck(owner, ownerPid);
        await recheck(child, owner.pid);
        custody.gitReleasePossible = true;
        await running.authorize("G");
      } else need(Object.keys(attempt).length === 2);
      const receipt = await running.next();
      need(
        Object.keys(receipt).length === 3 &&
          receipt.event === "completed" &&
          receipt.operation === operation,
      );
      receipts.push(receipt);
      const permitted =
        ["inspect", "git-status"].includes(operation) ||
        (workspaceWrite && operation === "edit");
      if (!permitted && receipt.error === 0)
        throw Object.assign(
          new Error("Prohibited Darwin operation completed"),
          {
            code: "ERR_FEASIBILITY_ESCAPE",
            operation,
          },
        );
      need(permitted ? receipt.error === 0 : [1, 13].includes(receipt.error));
    }
    running.closeInput();
    await running.finish();
  } catch (failure) {
    error = running.failure() ?? failure;
  }
  try {
    running.closeInput();
  } catch (failure) {
    cleanupError = failure;
  }
  if (custody.child)
    try {
      const args = darwinFeasibilityIdentityArguments(custody.child);
      custody.childRetired = await inspect(root, "observe", ...args);
      if (custody.childRetired.status === "LIVE") {
        error ??= new Error("Original Git child remains live");
        custody.childRetired = await inspect(root, "retire", ...args);
      }
      need(custody.childRetired.status === "RETIRED");
    } catch (failure) {
      cleanupError ??= failure;
    }
  const childSettled =
    !custody.initialReleasePossible ||
    custody.childRetired?.status === "RETIRED";
  if (!childSettled)
    cleanupError ??= new Error("Original Git child settlement is unobserved");
  if (!custody.owner)
    cleanupError ??= new Error("Original bundle birth is unobserved");
  if (custody.owner)
    try {
      // Unknown child custody forbids tearing down its original parent.
      custody.ownerRetired = await inspect(
        root,
        childSettled ? "retire" : "observe",
        ...darwinFeasibilityIdentityArguments(custody.owner),
      );
      need(custody.ownerRetired.status === "RETIRED");
    } catch (failure) {
      cleanupError ??= failure;
    }
  try {
    await running.waitClosed();
    custody.closed = true;
  } catch (failure) {
    cleanupError ??= failure;
  }
  custody.nativeCleanup = running.diagnostic(true);
  if (custody.nativeCleanup) {
    const { operation, domain, value } = custody.nativeCleanup;
    cleanupError ??= Object.assign(
      new Error("Native bundle cleanup remains uncertain"),
      {
        feasibilityCause: {
          code: "cleanup-unobserved",
          detail: `Native cleanup ${operation} failed (${domain}=${value}); original Git child settlement remains uncertain.`,
        },
      },
    );
  }
  try {
    await save(root, `${path.basename(policyPath, ".sb")}-custody`, custody);
  } catch (failure) {
    cleanupError ??= failure;
  }
  if (cleanupError) {
    error ??= cleanupError;
    error.feasibilityCleanup = {
      ...uncertain(),
      cause: darwinFeasibilityCause("bundle-cleanup", cleanupError),
    };
  }
  if (error) {
    error.nativeCustody = custody;
    throw error;
  }
  return {
    receipts,
    identity: custody.owner,
    policy: parentBinding.policy,
    image: parentBinding.image,
    policyFile,
    gitIdentity: custody.child,
    gitImage: childBinding.image,
    gitPolicy: childBinding.policy,
    gitRetired: custody.childRetired,
    retired: custody.ownerRetired,
    custody,
  };
}

async function accessEntries(root, nonce, components, baseline) {
  const started = performance.now(),
    observations = [];
  let outside;
  let cleanup = uncertain();
  try {
    outside = await controls(root, nonce);
    // Working host writes distinguish policy denial from permission/setup defects.
    for (const file of ["control/sentinel", "outside/sentinel"])
      await writeFile(path.join(root, file), nonce, { flag: "r+" });
    const ref = path.join(root, "workspace/.git/refs/heads/fixture");
    await writeFile(ref, await readFile(ref), { flag: "r+" });
    for (const relative of [
      "workspace/edited.txt",
      "workspace/.git/index.lock",
    ]) {
      const file = path.join(root, relative);
      await writeFile(file, nonce, { flag: "wx", mode: 0o600 });
      const [observed, parent] = await native(
        root,
        "files",
        file,
        path.dirname(file),
      );
      need(
        (
          await native(
            root,
            "remove",
            path.dirname(file),
            path.basename(file),
            observed.identity,
            parent.identity,
          )
        ).removed,
      );
    }
    need(JSON.stringify(await snapshots(root)) === JSON.stringify(baseline));
    for (const edit of [false, true]) {
      const name = edit ? "workspace-write" : "read-only",
        file = path.join(root, "evidence", `${name}.sb`);
      const policyBytes = darwinFeasibilityPolicy(root, edit);
      await writeFile(file, policyBytes, {
        flag: "wx",
        mode: 0o600,
      });
      const before = await snapshots(root),
        count = await outside.check();
      const running = session(
        root,
        "bundle",
        file,
        path.join(root, "workspace"),
        path.join(root, "control/sentinel"),
        path.join(root, "outside/sentinel"),
        outside.port,
        outside.socket,
        nonce,
        path.join(root, "build/git"),
      );
      const proof = await runDarwinFeasibilityBundle(
        root,
        running,
        components,
        file,
        policyBytes,
        { workspaceWrite: edit },
      );
      const { receipts, identity, policy, retired, gitIdentity, gitRetired } =
        proof;
      const after = await snapshots(root);
      if (
        JSON.stringify(before) !== JSON.stringify(after) ||
        !before.lockAbsent ||
        outside.count() !== count
      )
        throw Object.assign(new Error("Protected Darwin observation changed"), {
          code: "ERR_FEASIBILITY_ESCAPE",
        });
      if (edit)
        need(
          (await readFile(path.join(root, "workspace/edited.txt"), "utf8")) ===
            nonce,
        );
      else {
        let absent = false;
        try {
          await lstat(path.join(root, "workspace/edited.txt"));
        } catch (error) {
          nativeException("darwin/feasibility.js:exception", error);
          if (error.code !== "ENOENT") throw error;
          absent = true;
        }
        need(absent);
      }
      await outside.check();
      observations.push({
        name,
        proof,
        identity,
        policy,
        retired,
        gitIdentity,
        gitRetired,
        receipts,
        before,
        after,
        controlCount: outside.count(),
      });
    }
    const closing = performance.now();
    await outside.close();
    const tcpClosed = await native(
      root,
      "control-closed",
      "tcp",
      outside.port,
      nonce,
    );
    const unixClosed = await native(
      root,
      "control-closed",
      "unix",
      outside.socket,
      nonce,
    );
    need(tcpClosed.closed === true && unixClosed.closed === true);
    cleanup = settled(
      { tcpClosed, unixClosed, observations, after: await snapshots(root) },
      performance.now() - closing,
    );
    await persist(root, "access", { observations, cleanup });
    return ACCESS.map((capability) =>
      result(
        capability,
        components,
        observations,
        baseline,
        observations.at(-1).after,
        cleanup,
        started,
      ),
    );
  } catch (error) {
    nativeException("darwin/feasibility.js:exception", error);
    try {
      await outside?.close();
    } catch (diagnosticError) {
      nativeException("darwin/feasibility.js:exception", diagnosticError);
      /* Retain the original cause and cleanup uncertainty. */
    }
    return unavailable(
      ACCESS,
      darwinFeasibilityCause("access", error),
      components,
      true,
    ).map((entry) =>
      error.feasibilityCleanup
        ? { ...entry, cleanup: error.feasibilityCleanup }
        : entry,
    );
  }
}

async function storageEntry(root, components, baseline, substitution) {
  const started = performance.now(),
    capability = substitution ? "storage.substitution" : "storage.private";
  const parent = path.join(
      root,
      substitution ? "storage-substitution" : "storage-private",
    ),
    allocation = path.join(parent, "allocation");
  const running = session(root, "storage", parent);
  let identity,
    cleanup = uncertain(),
    observation;
  try {
    const allocated = await running.next();
    need(allocated.event === "allocated");
    identity = normalizeDarwinIdentity(
      await native(root, "identity", String(running.child.pid)),
    );
    const held = await native(
      root,
      "files",
      parent,
      allocation,
      path.join(allocation, "leaf"),
    );
    need(
      JSON.stringify(held) ===
        JSON.stringify([allocated.owner, allocated.parent, allocated.leaf]),
    );
    let replacement;
    if (substitution) {
      await rename(
        path.join(allocation, "leaf"),
        path.join(allocation, "saved"),
      );
      await writeFile(path.join(allocation, "leaf"), "replacement", {
        flag: "wx",
        mode: 0o600,
      });
      [replacement] = await native(
        root,
        "files",
        path.join(allocation, "leaf"),
      );
      need(replacement.identity !== allocated.leaf.identity);
    }
    running.child.stdin.end(substitution ? "S" : "N");
    const receipt = await running.next();
    await running.finish();
    need(
      receipt.event === "cleanup" &&
        receipt.removed === !substitution &&
        JSON.stringify(receipt.held) === JSON.stringify(allocated.leaf),
    );
    const closing = performance.now();
    if (substitution) {
      const preserved = await native(
        root,
        "files",
        path.join(allocation, "leaf"),
        path.join(allocation, "saved"),
      );
      need(
        JSON.stringify(preserved) ===
          JSON.stringify([replacement, allocated.leaf]),
      );
      need(
        (
          await native(
            root,
            "remove",
            allocation,
            "leaf",
            replacement.identity,
            allocated.parent.identity,
          )
        ).removed,
      );
      need(
        (
          await native(
            root,
            "remove",
            allocation,
            "saved",
            allocated.leaf.identity,
            allocated.parent.identity,
          )
        ).removed,
      );
      observation = { allocated, held, replacement, preserved, receipt };
    } else observation = { allocated, held, receipt };
    need(
      (
        await native(
          root,
          "remove-dir",
          parent,
          "allocation",
          allocated.parent.identity,
          allocated.owner.identity,
        )
      ).removed,
    );
    let absent = false;
    try {
      await lstat(allocation);
    } catch (error) {
      nativeException("darwin/feasibility.js:exception", error);
      if (error.code !== "ENOENT") throw error;
      absent = true;
    }
    need(absent);
    const retired = await native(
      root,
      "observe",
      ...darwinFeasibilityIdentityArguments(identity),
    );
    need(retired.status === "RETIRED");
    const after = await snapshots(root);
    need(JSON.stringify(after) === JSON.stringify(baseline));
    cleanup = settled({ absent, retired, after }, performance.now() - closing);
    await persist(root, capability.replaceAll(".", "-"), {
      observation,
      cleanup,
    });
    return result(
      capability,
      components,
      observation,
      baseline,
      after,
      cleanup,
      started,
    );
  } catch (error) {
    nativeException("darwin/feasibility.js:exception", error);
    running.child.stdin.end();
    if (identity)
      try {
        await native(
          root,
          "retire",
          ...darwinFeasibilityIdentityArguments(identity),
        );
      } catch (diagnosticError) {
        nativeException("darwin/feasibility.js:exception", diagnosticError);
        /* Never signal by PID or remove unknown storage. */
      }
    await running.waitClosed().catch(() => {});
    return unavailable(
      [capability],
      darwinFeasibilityCause("storage", error),
      components,
      true,
    )[0];
  }
}
async function ownershipEntry(root, components, baseline, caseId, checkoutSha) {
  const nonce = randomBytes(16).toString("hex"),
    helper = feasibilityDomainPath(nonce) + "/helper";
  const policyBytes = darwinFeasibilityPolicy(root)
    .replace(
      "(allow process-exec ",
      `(allow process-exec (literal ${JSON.stringify(helper)}) `,
    )
    .replace(
      "(allow file-map-executable ",
      `(allow file-map-executable (literal ${JSON.stringify(helper)}) `,
    )
    .replace(
      "(allow file-read* ",
      `(allow file-read* (literal ${JSON.stringify(helper)}) `,
    );
  const policy = path.join(root, "evidence", `${caseId}.sb`);
  await writeFile(policy, policyBytes, {
    flag: "wx",
    mode: 0o600,
  });
  const helperHash = components.find(
    ({ role, name }) => role === "helper" && name === "helper",
  )?.sha256;
  const domain = await openDarwinFaultDomain(
    root,
    checkoutSha,
    caseId,
    nonce,
    helperHash,
    digest(policyBytes),
    ENV,
    openDarwinFeasibilitySession,
  );
  return runDarwinFeasibilityFault(
    root,
    domain.running,
    components,
    baseline,
    caseId,
    checkoutSha,
    { domain, policyBytes },
  );
}

/** Preserve the original fault pair. Only separately held native domain evidence
 * can turn recorded-birth cleanup into successful complete retirement. */
export async function runDarwinFeasibilityFault(
  root,
  running,
  components,
  baseline,
  caseId,
  checkoutSha,
  {
    domain = null,
    policyBytes = darwinFeasibilityPolicy(root),
    inspect = domain?.inspect ?? native,
    save = persist,
    read = readFile,
    snapshot = snapshots,
    ownerPid = domain?.parentPid ?? process.pid,
    now = () => performance.now(),
  } = {},
) {
  const started = now(),
    policy = path.join(root, "evidence", `${caseId}.sb`);
  const custody = {
    ownerPid: running.child.pid,
    childPid: null,
    owner: null,
    child: null,
    releasePossible: false,
    childRetired: null,
    ownerRetired: null,
    closed: false,
    nativeCleanup: null,
  };
  running.faultCustody = custody;
  const observations = [],
    helper = domain?.helper ?? path.join(root, "build/helper");
  const helperHash = components.find(
    ({ role, name }) => role === "helper" && name === "helper",
  )?.sha256;
  let error,
    cleanupError,
    receipt = null,
    acknowledged = null,
    released;
  const pid = (value) =>
    Number.isSafeInteger(value) && value > 1 && value <= 0x7fffffff;
  const identityAt = async (selected, parent) => {
    const identity = normalizeDarwinIdentity(
      await inspect(root, "identity", String(selected), String(parent)),
    );
    need(identity.pid === selected);
    return identity;
  };
  const recheck = async (identity, parent) =>
    need(sameDarwinIdentity(identity, await identityAt(identity.pid, parent)));
  const inspectBirth = (operation, identity, ...args) =>
    inspect(
      root,
      operation,
      ...darwinFeasibilityIdentityArguments(identity),
      ...args,
    );
  const binding = async (identity) => {
    const image = await inspectBirth("image", identity, helper),
      applied = await inspectBirth("policy", identity);
    need(image.sha256 === helperHash && applied.sandboxed === true);
    return { image, policy: applied };
  };
  try {
    need(
      ["cancel", "owner-loss"].includes(caseId) &&
        /^[a-f0-9]{40}$/u.test(checkoutSha) &&
        /^[a-f0-9]{64}$/u.test(helperHash ?? "") &&
        pid(ownerPid) &&
        pid(custody.ownerPid) &&
        ownerPid !== custody.ownerPid,
    );
    const armed = await running.next();
    need(
      Object.keys(armed).length === (domain ? 4 : 3) &&
        (!domain || armed.controls === true) &&
        armed.event === "armed" &&
        armed.ownerPid === custody.ownerPid &&
        pid(armed.childPid) &&
        armed.childPid !== armed.ownerPid &&
        armed.childPid !== ownerPid,
    );
    custody.childPid = armed.childPid;
    custody.owner = await identityAt(armed.ownerPid, ownerPid);
    custody.child = await identityAt(armed.childPid, armed.ownerPid);
    need(
      ["auid", "asid", "uid", "gid", "ruid", "rgid", "svuid", "svgid"].every(
        (field) => custody.child[field] === custody.owner[field],
      ),
    );
    const ownerBinding = await binding(custody.owner),
      childBinding = await binding(custody.child);
    const policyFile = await inspect(root, "files", policy);
    need(
      Array.isArray(policyFile) &&
        policyFile.length === 1 &&
        policyFile[0].sha256 === digest(policyBytes),
    );
    receipt = {
      checkoutSha,
      caseId,
      owner: custody.owner,
      descendant: custody.child,
      ownerBinding,
      childBinding,
      policyFile,
      sandboxed: true,
      completeDomainBoundary: Boolean(domain),
    };
    const intentFile = path.join(root, "evidence", `${caseId}-intent.json`),
      intentHash = digest(JSON.stringify(receipt));
    await save(root, `${caseId}-intent`, receipt);
    need(digest(await read(intentFile)) === intentHash);
    await recheck(custody.owner, ownerPid);
    await recheck(custody.child, custody.owner.pid);
    need(
      JSON.stringify(await binding(custody.owner)) ===
        JSON.stringify(ownerBinding) &&
        JSON.stringify(await binding(custody.child)) ===
          JSON.stringify(childBinding) &&
        JSON.stringify(await inspect(root, "files", policy)) ===
          JSON.stringify(policyFile),
    );
    await recheck(custody.owner, ownerPid);
    await recheck(custody.child, custody.owner.pid);
    need(digest(await read(intentFile)) === intentHash);
    if (domain) {
      const held = await domain.intent(intentHash);
      need(
        held.candidateSha === checkoutSha &&
          held.caseId === caseId &&
          held.asid === custody.owner.asid &&
          held.helperSha256 === helperHash &&
          held.policySha256 === digest(policyBytes) &&
          sameDarwinIdentity(held.owner, custody.owner) &&
          sameDarwinIdentity(held.descendant, custody.child) &&
          normalizeDarwinIdentity(held.custodian).uid === 0 &&
          held.custodian.asid !== held.asid,
      );
      custody.sessionCustody = held;
    }
    released = now();
    await running.authorize("A");
    need(
      JSON.stringify(await running.next()) ===
        JSON.stringify({ event: "detached" }),
    );
    await running.authorize(caseId === "cancel" ? "C" : "L");
    acknowledged = await running.next();
    need(
      Object.keys(acknowledged).length === 2 &&
        acknowledged.event === "fault-ack" &&
        acknowledged.caseId === caseId,
    );
    need(
      (
        await inspectBirth(
          caseId === "cancel" ? "cancel" : "retire",
          custody.owner,
        )
      ).status === "RETIRED",
    );
    await running.finish(caseId === "cancel" ? "SIGTERM" : "SIGKILL");
    need(digest(await read(intentFile)) === intentHash);
  } catch (failure) {
    error = running.failure() ?? failure;
  }
  custody.releasePossible = running.authorizationStarted();
  // Inspect both original births before descendant intervention, even if the
  // acknowledgment or fault effect failed. Missing fault evidence stays missing.
  if (custody.releasePossible) {
    for (const identity of [custody.owner, custody.child]) {
      try {
        const observed = await inspectBirth("observe", identity);
        need(["LIVE", "RETIRED"].includes(observed.status));
        observations.push(observed);
      } catch (failure) {
        error ??= failure;
        observations.push(null);
      }
    }
    if (now() - released >= 25000)
      error ??= Object.assign(new Error("Fault fixture safety deadline"), {
        code: "ERR_FEASIBILITY_DEADLINE",
      });
  }
  const id = `ownership.${caseId}`;
  if (domain) {
    let proof,
      after = baseline;
    try {
      need(
        !error &&
          receipt &&
          acknowledged &&
          observations.length === 2 &&
          observations.every(Boolean),
      );
      proof = await domain.retire();
      const decision = assessDarwinFeasibilityDomain(observations, proof);
      need(
        decision.status === "PASS" &&
          [
            "candidateSha",
            "caseId",
            "asid",
            "intentSha256",
            "helperSha256",
            "policySha256",
          ].every(
            (field) => proof.record[field] === custody.sessionCustody[field],
          ) &&
          sameDarwinIdentity(
            proof.record.custodian,
            custody.sessionCustody.custodian,
          ) &&
          sameDarwinIdentity(proof.record.owner, custody.owner) &&
          sameDarwinIdentity(proof.record.descendant, custody.child),
      );
      need(now() - released < 25000);
      after = await snapshot(root);
      need(JSON.stringify(after) === JSON.stringify(baseline));
      custody.closed = true;
      const original = { receipt, acknowledged, observations, domain: proof };
      const cleanup = settled(
        { original, after, completeDomainBoundary: true },
        now() - started,
      );
      await save(root, caseId, original);
      await save(root, `${caseId}-custody`, { ...custody, cleanup });
      return result(
        id,
        components,
        original,
        baseline,
        after,
        cleanup,
        started,
      );
    } catch (failure) {
      error ??= failure;
      let recovered;
      try {
        if (typeof domain.recover === "function") {
          recovered = await domain.recover();
          assertDarwinFaultRetirement(recovered, false);
          need(
            recovered.record.candidateSha === checkoutSha &&
              recovered.record.caseId === caseId &&
              recovered.record.helperSha256 === helperHash &&
              recovered.record.policySha256 === digest(policyBytes),
          );
        } else await domain.abort();
      } catch (cleanupFailure) {
        recovered = null;
        cleanupError = cleanupFailure;
        try {
          await domain.abort();
        } catch {
          /* Emergency exit cannot supply proof. */
        }
      }
      const entry = unavailable(
        [id],
        darwinFeasibilityCause(caseId, error),
        components,
        true,
      )[0];
      entry.cleanup = recovered
        ? settled(
            { originalFailure: entry.cause, domain: recovered },
            now() - started,
          )
        : {
            ...uncertain(true),
            cause: darwinFeasibilityCause(
              "fault-domain-cleanup",
              cleanupError ?? error,
            ),
          };
      try {
        await save(root, `${caseId}-custody`, {
          ...custody,
          error: entry.cause,
          cleanup: entry.cleanup,
          domain: recovered ?? proof ?? null,
        });
      } catch {
        /* Original failure and retained exclusion survive publication loss. */
      }
      return entry;
    }
  }
  const refused = error
    ? unavailable(
        [id],
        darwinFeasibilityCause(caseId, error),
        components,
        true,
      )[0]
    : null;
  const decision = refused
    ? { status: refused.status, cause: refused.cause }
    : assessDarwinFeasibilityDomain(observations);
  const original = { receipt, acknowledged, observations, decision };
  try {
    await save(root, caseId, original);
  } catch (failure) {
    cleanupError = failure;
  }
  const closing = now();
  try {
    running.closeInput();
  } catch (failure) {
    cleanupError ??= failure;
  }
  // Refusal lets the helper close gates and check reaping before any parent
  // teardown. Closure itself never proves settlement of an unobserved birth.
  if (!custody.releasePossible)
    try {
      await running.waitClosed();
      custody.closed = true;
    } catch (failure) {
      cleanupError ??= failure;
    }
  let childSettled = false;
  for (const [field, identity] of [
    ["childRetired", custody.child],
    ["ownerRetired", custody.owner],
  ]) {
    if (!identity) {
      cleanupError ??= new Error("Original fault birth is unobserved");
      continue;
    }
    try {
      const child = field === "childRetired";
      const mayRetire = child
        ? custody.releasePossible &&
          observations.length === 2 &&
          observations.every((value) => value !== null)
        : childSettled;
      let retired = await inspectBirth("observe", identity);
      if (retired.status === "LIVE" && mayRetire)
        retired = await inspectBirth("retire", identity);
      need(retired.status === "RETIRED");
      custody[field] = await inspectBirth("observe", identity);
      need(custody[field].status === "RETIRED");
      if (child) childSettled = custody.releasePossible || custody.closed;
    } catch (failure) {
      cleanupError ??= failure;
      custody[field] = null;
    }
  }
  if (custody.releasePossible)
    try {
      await running.waitClosed();
      custody.closed = true;
    } catch (failure) {
      cleanupError ??= failure;
    }
  custody.nativeCleanup = running.diagnostic(true);
  if (custody.nativeCleanup) {
    const { operation, domain, value } = custody.nativeCleanup;
    cleanupError ??= {
      feasibilityCause: {
        code: "cleanup-unobserved",
        detail: `Native cleanup ${operation} failed (${domain}=${value}); original fault child settlement remains uncertain.`,
      },
    };
  }
  let after = baseline;
  try {
    after = await snapshot(root);
    need(JSON.stringify(after) === JSON.stringify(baseline));
  } catch (failure) {
    cleanupError ??= failure;
  }
  let cleanup = cleanupError
    ? {
        ...uncertain(),
        cause: {
          code: "cleanup-unobserved",
          detail: darwinFeasibilityCause("fault-cleanup", cleanupError).detail,
        },
      }
    : settled(
        { custody, after, completeDomainBoundary: false },
        now() - closing,
        observations.some((value) => value?.status === "LIVE"),
      );
  try {
    await save(root, `${caseId}-custody`, { ...custody, cleanup });
  } catch (failure) {
    cleanupError ??= failure;
    cleanup = {
      ...uncertain(cleanup.emergency),
      cause: cleanup.cause ?? uncertain().cause,
    };
  }
  if (refused) return { ...refused, cleanup };
  const entry = result(
    id,
    components,
    original,
    baseline,
    after,
    cleanup,
    started,
    decision,
  );
  if (cleanupError) entry.evidence = null;
  return entry;
}

/** Explicit matching hosted CI operation; imports and portable exports are inert. */
export async function runDarwinFeasibility({ expectedSha, checkoutSha } = {}) {
  const ids = feasibilityCapabilities("darwin")
    .filter(({ tier }) => tier === "native")
    .map(({ id }) => id);
  if (
    process.platform !== "darwin" ||
    process.arch !== "x64" ||
    process.env.CI !== "true" ||
    process.env.GITHUB_ACTIONS !== "true" ||
    process.env.RUNNER_ENVIRONMENT !== "github-hosted" ||
    process.env.RUNNER_OS !== "macOS"
  ) {
    const error = new Error("Matching Darwin CI unavailable");
    error.code = "ERR_NATIVE_FEASIBILITY_WORKER_UNAVAILABLE";
    throw error;
  }
  let root,
    stage = "prerequisites";
  const components = [],
    results = [];
  try {
    need(
      /^[a-f0-9]{40}$/u.test(expectedSha ?? "") && checkoutSha === expectedSha,
    );
    need(
      (
        await command("/usr/bin/git", ["rev-parse", "HEAD"], ROOT)
      ).stdout.trim() === expectedSha,
    );
    if (
      process.getuid() <= 500 ||
      process.geteuid() !== process.getuid() ||
      !process.env.RUNNER_TEMP
    )
      throw Object.assign(
        new Error("Unprivileged CI prerequisite unavailable"),
        { code: "ERR_FEASIBILITY_UNAVAILABLE" },
      );
    root = await prepareDarwinFeasibility(process.env.RUNNER_TEMP, components);
    const nonce = randomBytes(16).toString("hex");
    // Preparation owns the synthetic repository; the experiment never uses host Git state.
    stage = "fixture";
    await prepareFixture(root, nonce);
    await persist(root, "intent", {
      expectedSha,
      checkoutSha,
      nonce,
      uid: process.getuid(),
      completeDomainBoundary: false,
    });
    const baseline = await snapshots(root);
    stage = "argv";
    results.push(await runDarwinFeasibilityArgv(root, components, baseline));
    stage = "access";
    results.push(...(await accessEntries(root, nonce, components, baseline)));
    if (
      results.some(
        ({ status, cleanup }) => status === "FAIL" || cleanup.status !== "PASS",
      )
    )
      return [
        ...results,
        ...unavailable(
          [...STORAGE, ...OWNERSHIP],
          {
            code: "prerequisite-unavailable",
            detail:
              "An earlier Darwin probe did not settle; subsequent admission is refused.",
          },
          components,
        ),
      ];
    for (const substitution of [false, true]) {
      stage = substitution ? "storage-substitution" : "storage-private";
      const entry = await storageEntry(
        root,
        components,
        baseline,
        substitution,
      );
      results.push(entry);
      if (entry.status !== "PASS")
        return [
          ...results,
          ...unavailable(
            [...STORAGE, ...OWNERSHIP].filter(
              (id) => !results.some(({ capability }) => capability === id),
            ),
            {
              code: "prerequisite-unavailable",
              detail:
                "Darwin private storage did not settle; fault admission is refused.",
            },
            components,
          ),
        ];
    }
    for (const caseId of ["cancel", "owner-loss"]) {
      stage = caseId;
      const entry = await ownershipEntry(
        root,
        components,
        baseline,
        caseId,
        checkoutSha,
      );
      results.push(entry);
      // Complete independent non-emergency retirement alone authorizes the next fault.
      if (
        entry.status !== "PASS" ||
        entry.cleanup.status !== "PASS" ||
        entry.cleanup.emergency ||
        !entry.cleanup.independent ||
        !entry.cleanup.witnessSha256
      )
        break;
    }
    return [
      ...results,
      ...unavailable(
        ids.filter(
          (id) => !results.some(({ capability }) => capability === id),
        ),
        {
          code: "prerequisite-unavailable",
          detail:
            "Darwin fault cleanup did not settle; subsequent admission is refused.",
        },
        components,
      ),
    ];
  } catch (error) {
    nativeException("darwin/feasibility.js:exception", error);
    return [
      ...results,
      ...unavailable(
        ids.filter(
          (id) => !results.some(({ capability }) => capability === id),
        ),
        darwinFeasibilityCause(stage, error),
        components,
        root !== undefined,
      ).map((entry) =>
        error.feasibilityCleanup
          ? { ...entry, cleanup: error.feasibilityCleanup }
          : entry,
      ),
    ];
  }
}

async function prepareFixture(root, nonce) {
  // build/evidence exist already, so prepare only the remaining owned fixture.
  for (const name of [
    "workspace",
    "control",
    "outside",
    "storage-private",
    "storage-substitution",
  ])
    await mkdir(path.join(root, name), { mode: 0o700 });
  for (const name of [
    "workspace/inspection.txt",
    "control/sentinel",
    "outside/sentinel",
  ])
    await writeFile(path.join(root, name), nonce, { flag: "wx", mode: 0o600 });
  const workspace = path.join(root, "workspace");
  for (const args of [
    ["init", "--initial-branch=fixture"],
    ["add", "inspection.txt"],
    [
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.invalid",
      "-c",
      "commit.gpgsign=false",
      "-c",
      "core.hooksPath=/dev/null",
      "commit",
      "-m",
      "fixture",
    ],
  ])
    await command(path.join(root, "build/git"), args, workspace);
  await chmod(path.join(workspace, ".git"), 0o700);
  for (const file of [".git/index", ".git/refs/heads/fixture"])
    await chmod(path.join(workspace, file), 0o600);
  await native(
    root,
    "files",
    root,
    path.join(root, "control"),
    path.join(root, "outside"),
  );
}

/** Preparation tracks its exclusive allocation before canonicalization. Native
 * effects are supplied only by the matching-worker entry; tests inject them. */
export async function prepareDarwinFeasibility(
  temporary,
  components,
  {
    fs = { realpath, mkdtemp, lstat, chown, mkdir, unlink, rmdir },
    build = buildDarwinFeasibility,
    readNative = native,
    save = persist,
    uid = process.getuid(),
    gid = process.getgid(),
  } = {},
) {
  let root,
    operation = "fixture-root-acquire",
    helperStarted = false;
  const directories = new Map(),
    files = new Map();
  const same = (a, b) =>
    a.dev === b.dev &&
    a.ino === b.ino &&
    a.birthtimeMs === b.birthtimeMs &&
    a.uid === b.uid &&
    a.gid === b.gid &&
    a.mode === b.mode;
  const privateDirectory = (st) =>
    st.isDirectory() &&
    !st.isSymbolicLink() &&
    st.uid === uid &&
    (st.mode & 0o7777) === 0o700;
  const pin = async (file) => {
    const st = await fs.lstat(file);
    need(privateDirectory(st));
    directories.set(file, st);
    return st;
  };
  const recordResource = async (file) => {
    const st = await fs.lstat(file);
    need(
      st.isFile() &&
        !st.isSymbolicLink() &&
        st.nlink === 1 &&
        st.uid === uid &&
        st.gid === gid,
    );
    const original = files.get(file);
    need(!original || same({ ...original, mode: st.mode }, st));
    files.set(file, st);
  };
  const cleanup = async (error) => {
    if (!root) return null;
    const started = performance.now(),
      removed = [];
    let failed = false;
    const verify = async (directory) => {
      const expected = directories.get(directory);
      need(expected && same(expected, await fs.lstat(directory)));
    };
    // Fixed preparation outputs only. Unknown entries and replaced parents are
    // retained; there is no recursive deletion or adoption of a foreign tree.
    for (const [parent, names] of [
      ["build", ["helper", "argv-fixture", "git"]],
      ["evidence", ["build.json", "prerequisites.json"]],
    ])
      for (const name of names) {
        const directory = path.join(root, parent),
          file = path.join(directory, name);
        try {
          const st = await fs.lstat(file);
          await verify(root);
          await verify(directory);
          need(
            st.isFile() &&
              !st.isSymbolicLink() &&
              st.nlink === 1 &&
              st.uid === uid &&
              st.gid === gid &&
              files.has(file) &&
              same(files.get(file), st) &&
              (st.mode & 0o7022) === 0 &&
              same(st, await fs.lstat(file)),
          );
          await fs.unlink(file);
          try {
            await fs.lstat(file);
            need(false);
          } catch (absent) {
            if (absent.code !== "ENOENT") throw absent;
          }
          removed.push(`${parent}-${name}`);
        } catch (failure) {
          if (failure.code !== "ENOENT") failed = true;
        }
      }
    for (const directory of [...directories.keys()].reverse()) {
      try {
        await verify(directory);
        if (directory !== root) await verify(root);
        await fs.rmdir(directory);
        try {
          await fs.lstat(directory);
          need(false);
        } catch (absent) {
          if (absent.code !== "ENOENT") throw absent;
        }
        removed.push(directory === root ? "root" : path.basename(directory));
      } catch (diagnosticError) {
        nativeException("darwin/feasibility.js:exception", diagnosticError);
        failed = true;
      }
    }
    // An allocation with no captured creation identity cannot be removed.
    if (!directories.has(root)) failed = true;
    const diagnostic = prerequisiteDiagnostic(error);
    const cleanupDiagnostic = prerequisiteDiagnostic(error, true);
    const helperSettled =
      !helperStarted ||
      (error.signal === null &&
        error.timedOut === false &&
        [78, 126].includes(error.code) &&
        diagnostic?.effects === "none" &&
        diagnostic.settlement === "settled");
    const processUncertain =
      hasUnsettledNativeBuild(error) ||
      error.timedOut === true ||
      typeof error.signal === "string" ||
      ["deadline", "crash"].includes(error.feasibilityCause?.code);
    return !failed && helperSettled && !processUncertain && !cleanupDiagnostic
      ? settled(
          { removed, admitted: false, helperSettled },
          performance.now() - started,
        )
      : {
          ...uncertain(),
          emergency: cleanupDiagnostic?.operation === "prerequisite-backstop",
          elapsedMs: Math.ceil(performance.now() - started),
          cause: {
            code: "cleanup-unobserved",
            detail: cleanupDiagnostic
              ? `Native cleanup ${cleanupDiagnostic.operation} failed (${cleanupDiagnostic.domain}=${cleanupDiagnostic.value}); Darwin preparation settlement remains uncertain.`
              : "Darwin preparation resources or prerequisite child settlement could not be independently verified.",
          },
        };
  };
  try {
    const parent = await fs.realpath(temporary);
    root = await fs.mkdtemp(path.join(parent, "nf-"));
    await pin(root);
    operation = "fixture-root-canonical";
    need((await fs.realpath(root)) === root);
    operation = "fixture-root-group";
    // mkdir/mkdtemp inherit the parent's group on Darwin. Normalize only our
    // exclusive, mode-0700 allocation; all descendants inherit this owned group.
    need(same(directories.get(root), await fs.lstat(root)));
    await fs.chown(root, -1, gid);
    const grouped = await fs.lstat(root),
      original = directories.get(root);
    need(
      privateDirectory(grouped) &&
        grouped.gid === gid &&
        grouped.dev === original.dev &&
        grouped.ino === original.ino &&
        grouped.birthtimeMs === original.birthtimeMs,
    );
    directories.set(root, grouped);
    for (const name of ["build", "evidence"]) {
      operation = "fixture-directory";
      const directory = path.join(root, name);
      await fs.mkdir(directory, { mode: 0o700 });
      await pin(directory);
    }
    operation = "build";
    await build(root, components, { recordResource });
    operation = "identity-prerequisites";
    helperStarted = true;
    const prerequisites = await readNative(root, "prerequisites", root);
    need(
      prerequisites.identitySafeSignal === true &&
        prerequisites.sandboxCheckBinding === true,
    );
    // The successful strict protocol is emitted only after the control is reaped.
    helperStarted = false;
    await save(root, "prerequisites", prerequisites);
    await recordResource(path.join(root, "evidence/prerequisites.json"));
    return root;
  } catch (error) {
    nativeException("darwin/feasibility.js:exception", error);
    const firstCause = darwinFeasibilityCause(operation, error);
    const retirement = await cleanup(error);
    throw Object.assign(new Error("Darwin preparation failed."), {
      feasibilityCause: firstCause,
      feasibilityCleanup: retirement,
    });
  }
}
