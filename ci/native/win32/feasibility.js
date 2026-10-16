import { execFile, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  realpath,
  rename,
} from "node:fs/promises";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import {
  nativeException,
  attemptNativeBuilds,
  hasUnsettledNativeBuild,
  nativeDiagnostic,
  diagnosticCommand,
} from "../diagnostics.js";
import {
  feasibilityCapabilities,
  unavailableFeasibilityResults,
} from "../feasibility/index.js";
import {
  digest,
  normalizeWindowsIdentity,
  sameWindowsIdentity,
  quoteWindowsArgument,
  WINDOWS_LITERAL_ARGUMENTS,
} from "./protocol.js";
import {
  prepareWindowsFeasibilityGit,
  validateWindowsFeasibilityGitStart,
  windowsFeasibilityPeError,
  windowsFeasibilityPeCause,
} from "./feasibility-git.js";
import {
  createWindowsFeasibilityWorkspace,
  windowsFeasibilityWorkspaceLaunch,
} from "./feasibility-workspace.js";

const execute = diagnosticCommand("win32/feasibility.js", promisify(execFile));
const SOURCE = fileURLToPath(new URL("./", import.meta.url));
const REPOSITORY = fileURLToPath(new URL("../../../", import.meta.url));
const WFP_SDK_HEADERS = Object.freeze({
  "fwpmu.h": "um",
  "fwpmtypes.h": "shared",
});
const ACCESS = [
  "access.read-only",
  "access.workspace-write",
  "git.denial",
  "network.tcp-denial",
  "ipc.local-denial",
];
const OPERATIONS = [
  "inspect",
  "edit",
  "git-status",
  "git-index",
  "git-ref",
  "control",
  "outside",
  "tcp",
  "pipe",
];
const SENTINELS = [
  "workspace\\.git\\index",
  "workspace\\.git\\refs\\heads\\fixture",
  "control\\sentinel",
  "outside\\sentinel",
];
const REJECTIONS = [
  "encoding",
  "framing",
  "json",
  "stdout-bound",
  "diagnostic-bound",
  "diagnostic-form",
  "eof",
  "record-count",
  "git-receipt",
];
const need = (value) => {
  if (!value) throw new Error("Incomplete Windows feasibility observation");
};
const hash = (value) => digest(Buffer.from(JSON.stringify(value)));
const validDigest = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);

export function windowsFeasibilityProfileName(nonce) {
  need(typeof nonce === "string" && /^[a-f0-9]{32}$/u.test(nonce));
  return `native.feasibility.${nonce}`;
}

/** Keep helper and nested Git admissions distinct in exclusive storage. */
export function windowsFeasibilityAdmissionName(caseId, isGit = false) {
  return `${caseId}${isGit ? "-git" : ""}-admission`;
}

/** AppContainer creation needs the host caller's local profile directory, not
 * a payload grant. Capture only bounded literal paths and fixed CI markers. */
export function windowsFeasibilityCallerEnvironment(environment) {
  const directories = {};
  for (const key of ["SystemRoot", "LOCALAPPDATA"]) {
    const value = environment?.[key];
    if (!(
      typeof value === "string" &&
      value.isWellFormed() &&
      value.length > 3 &&
      value.length < 4096 &&
      /^[A-Za-z]:\\/u.test(value) &&
      path.win32.normalize(value) === value &&
      !/[\p{Cc}\p{Zl}\p{Zp}<>"|?*]/u.test(value) &&
      !value.slice(2).includes(":") &&
      value
        .slice(3)
        .split("\\")
        .every(
          (part) =>
            part.length > 0 &&
            !/[ .]$/u.test(part) &&
            !/^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/iu.test(part),
        )
    )) {
      const detail = `Windows AppContainer caller requires a bounded canonical drive-absolute ${key} directory. Restore the hosted worker's caller environment before retrying.`;
      throw Object.assign(new Error(detail), {
        feasibilityCause: { code: "prerequisite-unavailable", detail },
      });
    }
    directories[key] = value;
  }
  return {
    CI: "true",
    GITHUB_ACTIONS: "true",
    RUNNER_ENVIRONMENT: "github-hosted",
    RUNNER_OS: "Windows",
    SystemRoot: directories.SystemRoot,
    PATH: path.win32.join(directories.SystemRoot, "System32"),
    LOCALAPPDATA: directories.LOCALAPPDATA,
  };
}

/** Keep native SDK setup, but exclude ambient Git repository/configuration routes. */
export function windowsFeasibilityToolEnvironment(environment) {
  // process.env is case-insensitive on Windows; its plain copy is not.
  const entries = Object.entries(environment),
    directories = {};
  for (const name of ["SystemRoot", "ProgramFiles(x86)"]) {
    const aliases = entries.filter(
      ([key]) => key.toLowerCase() === name.toLowerCase(),
    );
    need(aliases.every(([, value]) => value === aliases[0][1]));
    if (aliases.length) directories[name] = aliases[0][1];
  }
  return {
    ...Object.fromEntries(
      entries.filter(
        ([key]) =>
          !/^(?:GIT_|GH_TOKEN$|SystemRoot$|ProgramFiles\(x86\)$)/iu.test(key),
      ),
    ),
    ...directories,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "NUL",
    GIT_OPTIONAL_LOCKS: "0",
    GIT_TERMINAL_PROMPT: "0",
  };
}

/** Unsigned experiment images have no release/signature closure claim. */
export function windowsFeasibilityImports(bytes) {
  const need = (value, rule, ...facts) => {
    if (!value) throw windowsFeasibilityPeError(rule, ...facts);
  };
  need(Buffer.isBuffer(bytes), "file-type");
  need(
    bytes.length >= 256 && bytes.length <= 134217728,
    "file-size",
    bytes.length,
  );
  need(
    bytes.readUInt16LE(0) === 0x5a4d,
    "dos-signature",
    bytes.readUInt16LE(0),
  );
  const pe = bytes.readUInt32LE(60);
  need(pe >= 64 && pe + 24 <= bytes.length, "pe-offset", pe, bytes.length);
  need(
    bytes.readUInt32LE(pe) === 0x4550,
    "pe-signature",
    bytes.readUInt32LE(pe),
  );
  need(
    bytes.readUInt16LE(pe + 4) === 0x8664,
    "machine",
    bytes.readUInt16LE(pe + 4),
  );
  const count = bytes.readUInt16LE(pe + 6),
    size = bytes.readUInt16LE(pe + 20),
    optional = pe + 24,
    sections = optional + size;
  need(count > 0 && count <= 96, "section-count", count);
  need(
    size >= 112 && sections <= bytes.length,
    "optional-range",
    size,
    bytes.length,
  );
  need(
    bytes.readUInt16LE(optional) === 0x20b,
    "optional-magic",
    bytes.readUInt16LE(optional),
  );
  // Microsoft's PE format specifies a variable optional header. Probe only
  // declared directory entries, bounded by SizeOfOptionalHeader; absent entries
  // are not section-header bytes. This remains PE32+ / AMD64 only.
  const directories = bytes.readUInt32LE(optional + 108);
  need(
    directories <= 16 && 112 + directories * 8 <= size,
    "directory-count",
    directories,
    size,
  );
  need(
    sections + count * 40 <= bytes.length,
    "section-table",
    sections,
    count,
    bytes.length,
  );
  const ranges = [];
  for (let i = 0; i < count; i++) {
    const section = sections + i * 40,
      virtual = bytes.readUInt32LE(section + 8),
      rva = bytes.readUInt32LE(section + 12),
      raw = bytes.readUInt32LE(section + 16),
      at = bytes.readUInt32LE(section + 20),
      span = Math.max(virtual, raw);
    need(
      !raw || (at >= sections + count * 40 && at + raw <= bytes.length),
      "section-raw-range",
      i,
      at,
      raw,
    );
    need(rva + span <= 0x100000000, "section-rva-range", i, rva, span);
    for (const [other, previous] of ranges.entries()) {
      need(
        !raw ||
          !previous.raw ||
          at + raw <= previous.at ||
          previous.at + previous.raw <= at,
        "raw-overlap",
        i,
        other,
      );
      need(
        !span ||
          !previous.span ||
          rva + span <= previous.rva ||
          previous.rva + previous.span <= rva,
        "rva-overlap",
        i,
        other,
      );
    }
    ranges.push({ rva, raw, at, span });
  }
  const offset = (rva, length) => {
    need(
      rva > 0 && length > 0 && rva + length <= 0x100000000,
      "rva-range",
      rva,
      length,
    );
    for (const { rva: start, raw, at } of ranges) {
      if (rva >= start && rva - start + length <= raw) return at + rva - start;
    }
    throw windowsFeasibilityPeError("rva-unmapped", rva, length);
  };
  const directory = (index) =>
    index < directories
      ? [
          bytes.readUInt32LE(optional + 112 + index * 8),
          bytes.readUInt32LE(optional + 116 + index * 8),
        ]
      : [0, 0];
  // Delay-loaded dependencies need a separate loader observation; do not omit them.
  const [delayRva, delaySize] = directory(13);
  need(!delayRva && !delaySize, "delay-imports", delayRva, delaySize);
  const [rva, length] = directory(1);
  need(Boolean(rva) === Boolean(length), "import-pair", rva, length);
  if (!rva) {
    return [];
  }
  need(length >= 20, "import-size", length);
  const at = offset(rva, length),
    imports = [];
  // The import directory's extent can include lookup/address tables and names
  // beyond 4 KiB. Preserve the old bounded descriptor walk separately from that
  // extent: at most floor(4096 / 20) slots, including the null terminator.
  const descriptors = Math.min(Math.floor(length / 20), 204);
  for (let descriptor = 0; descriptor < descriptors; descriptor++) {
    const i = descriptor * 20;
    if (bytes.subarray(at + i, at + i + 20).every((b) => b === 0))
      return imports;
    const nameRva = bytes.readUInt32LE(at + i + 12),
      name = offset(nameRva, 1);
    let nameSize = 0;
    for (; nameSize <= 128; nameSize++) {
      const current = offset(nameRva + nameSize, 1);
      need(
        current === name + nameSize,
        "name-contiguity",
        descriptor,
        nameSize,
      );
      if (!bytes[current]) break;
    }
    need(nameSize <= 128, "name-terminator", descriptor, nameSize);
    const end = name + nameSize;
    const dll = bytes.toString("ascii", name, end);
    need(
      bytes.subarray(name, end).every((b) => b < 128),
      "name-ascii",
      descriptor,
      nameSize,
    );
    need(
      /^[a-zA-Z0-9_.-]+\.dll$/iu.test(dll) &&
        !/^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])\./iu.test(dll),
      "name-safe",
      descriptor,
      nameSize,
    );
    imports.push(dll);
  }
  throw windowsFeasibilityPeError("import-terminator", length, descriptors);
}

const COMMAND_PROTECTION_OWNER_OPERATIONS = Object.freeze(
  ["process", "job", "intent-event", "closed-event"].flatMap((object) =>
    ["baseline", "input", "readback"].map(
      (stage) => `command-protect-${object}-${stage}-owner`,
    ),
  ),
);
const GIT_HELPER_DOMAINS = Object.freeze({
  ...Object.fromEntries(
    COMMAND_PROTECTION_OWNER_OPERATIONS.map((operation) => [
      operation,
      ["win32", "invariant"],
    ]),
  ),
  ...Object.fromEntries(
    ["original", "launch", "verifier", "git"].flatMap((site) => [
      [`${site}-image-query`, ["win32"]],
      [`${site}-image-bound`, ["invariant"]],
      [`${site}-image-equal`, ["invariant"]],
    ]),
  ),
  "original-self-query": ["win32"],
  "original-self-bound": ["invariant"],
  "stdout-mode": ["errno"],
  "stdout-write": ["invariant"],
  "helper-arguments": ["invariant"],
  "helper-nonce": ["invariant"],
  "helper-role": ["invariant"],
  "argument-number": ["invariant"],
  "payload-token": ["win32"],
  "payload-container": ["invariant"],
  "payload-capabilities": ["invariant"],
  "payload-job": ["win32", "invariant"],
  "bundle-open": ["win32"],
  "bundle-read": ["win32"],
  "bundle-read-size": ["invariant"],
  "bundle-nonce": ["invariant"],
  "bundle-write": ["win32"],
  "bundle-write-size": ["invariant"],
  "bundle-truncate": ["win32"],
  "launch-record": ["invariant"],
  "forward-create": ["win32"],
  "forward-release": ["win32", "invariant"],
  "stderr-pipe": ["win32"],
  "stderr-inherit": ["win32"],
  "diagnostic-forward-read": ["win32"],
  "diagnostic-forward-bound": ["invariant"],
  "diagnostic-forward-write": ["win32"],
  "diagnostic-forward-write-size": ["invariant"],
  "diagnostic-forward-eof": ["invariant"],
  "forward-read": ["win32"],
  "forward-read-size": ["invariant"],
  "forward-bound": ["invariant"],
  "forward-write": ["win32"],
  "forward-write-size": ["invariant"],
  "forward-wait": ["win32", "invariant"],
  "forward-close": ["win32"],
  "process-wait": ["win32", "invariant"],
  "thread-close": ["win32"],
  "git-null-close": ["win32"],
  "owner-read": ["win32"],
  "owner-write": ["win32"],
  "owner-write-size": ["invariant"],
  "owner-channel": ["invariant"],
  "git-null-input-type": ["win32", "invariant"],
  "git-null-output-type": ["win32", "invariant"],
  "git-diagnostic-read-type": ["win32", "invariant"],
  "git-diagnostic-write-type": ["win32", "invariant"],
  "winsock-cleanup": ["win32"],
  "tcp-nonblocking": ["win32"],
  "tcp-bind": ["win32"],
  "tcp-connect": ["win32"],
  "tcp-completion": ["win32"],
  "tcp-select": ["win32"],
  "tcp-send": ["win32"],
  "tcp-receive": ["win32"],
  "tcp-close": ["win32"],
  "tcp-deadline": ["invariant"],
  "tcp-ready": ["invariant"],
  "tcp-eof": ["invariant"],
  "tcp-progress": ["invariant"],
  "tcp-nonce": ["invariant"],
  ...Object.fromEntries(
    `command-interface command-security-read command-privilege-token
    command-privilege-lookup command-privilege-adjust command-audit-principals
    command-medium-source command-medium-create command-medium-sid command-medium-integrity command-medium-launch
    command-integrity-token command-impersonate command-null-open command-audit-categories
    command-audit-policy command-publisher-open command-enumerator-open command-audit-event
    command-audit-subscribe command-event-next command-event-id command-event-version
    command-timer-create command-timer-thread command-lifetime-read command-lifetime-clear command-token-close command-null-close command-event-close
    command-metadata-close command-revert command-environment-close
    file-protect command-protect-label command-protect-process command-protect-job
    command-protect-intent-event command-protect-closed-event command-protect-free command-fixture-descriptor command-fixture-label
    command-parent-open command-file-open command-file-protect command-file-sacl
    command-audit-allocation command-audit-init command-audit-ace-read command-audit-ace-copy command-audit-ace
    command-image-query command-job-query command-members-query command-member-open
    command-stdin-pipe command-stdout-pipe command-stderr-pipe command-stdin-inherit command-stdout-inherit command-stderr-inherit
    command-attribute-init command-attribute-job command-attribute-handles command-launch-environment command-process-create
    command-build-open command-build-descriptor command-build-label command-helper-open command-helper-label command-image-open
    command-job-create command-job-config command-broker-token command-intent-event command-closed-event
    command-capture-event command-bookmark command-admission-terminate command-subscription-create command-gate-descriptor command-gate-create
    command-gate-impersonate command-gate-open command-gate-read command-gate-nonce-encode
    command-capture-next command-capture-reset command-capture-render command-capture-bookmark command-bookmark-render
    command-owner-read command-cleanup-begin command-retirement-event command-retirement-terminate`
      .split(/\s+/u)
      .map((operation) => [operation, ["win32"]]),
  ),
  ...Object.fromEntries(
    `command-integrity-sid command-medium-level command-audit-principal command-audit-buffer
    command-principal-kind command-integrity command-audit-existing command-audit-count
    command-audit-category command-metadata-count command-event-id-type command-event-version-type
    command-version-count command-version-range command-version-missing command-preflight-arguments command-lifetime-size command-lifetime-range
    command-protect-format command-file-identity command-parent-baseline command-file-baseline command-audit-size
    command-image-match command-job-limits command-members-count command-member-pid
    command-launch-state command-attribute-allocation command-launch-bound command-broker-arguments command-broker-nonce
    command-helper-digest-match command-image-digest-match command-admission-line command-admission-members command-subscription-query command-gate-name
    command-gate-identity command-gate-size command-gate-nonce command-capture-bound command-capture-allocation
    command-ready-output command-owner-bound command-coverage-state command-deadline command-retirement-delivery command-retirement-state command-retirement-records`
      .split(/\s+/u)
      .map((operation) => [operation, ["invariant"]]),
  ),
  ...Object.fromEntries(
    `command-host-actions command-host-os command-null-control command-timer-wait
    command-protect-descriptor command-protect-owner command-protect-control command-protect-dacl command-protect-sacl command-fixture-sacl command-parent-tag command-file-tag command-file-dacl command-file-owner
    command-member-job command-child-job command-image-digest command-helper-digest command-build-sacl command-job-membership command-admission-wait
    command-capture-query command-capture-wait command-bookmark-query command-coverage-wait command-retirement-wait command-retirement-status`
      .split(/\s+/u)
      .map((operation) => [operation, ["win32", "invariant"]]),
  ),
  "command-com-initialize": ["hresult"],
  ...Object.fromEntries(
    [
      "command-hash-open",
      "command-hash-create",
      "command-hash-update",
      "command-hash-final",
      "command-hash-close",
      "command-algorithm-close",
    ].map((operation) => [operation, ["ntstatus"]]),
  ),
  "null-cancel": ["win32"],
  "null-close": ["win32"],
  "null-remove": ["win32"],
  "null-retirement": ["win32", "invariant"],
  "null-endpoint-size": ["win32"],
  "null-endpoint-state": ["invariant"],
});
const GIT_EXIT_OPERATIONS = Object.freeze([
  "git-process-exit",
  "git-dubious-owner",
  "git-repository-read",
  "git-config-read",
  "git-user-name",
  "git-cwd-read",
  "git-home-missing",
  "git-path-read",
  "git-path-normalize",
  "git-index-read",
  "git-stdio-io",
  "git-random-read",
  "git-winsock-init",
  "git-console-init",
  "git-stderr-empty",
  "git-stderr-invalid",
  ...["fatal", "error", "warning", "other"].flatMap((kind) => [
    `git-stderr-${kind}`,
    `git-stderr-${kind}-partial`,
  ]),
]);
const FILE_TYPES = [0, 1, 2, 3, 0x8000, 0x8001, 0x8002, 0x8003];
const GIT_HELPER_FACTS = Object.freeze({
  ...Object.fromEntries(
    COMMAND_PROTECTION_OWNER_OPERATIONS.map((operation) => [
      operation,
      (value) =>
        [1, 2].includes(value) ||
        (value === 3 && !operation.endsWith("-baseline-owner")),
    ]),
  ),
  "payload-capabilities": (value) => value > 0 && value <= 4096,
  "bundle-read-size": (value) => value < 32,
  "bundle-write-size": (value) => value < 32,
  "git-null-input-type": (value) => FILE_TYPES.includes(value) && value !== 2,
  "git-null-output-type": (value) => FILE_TYPES.includes(value) && value !== 2,
  "git-diagnostic-read-type": (value) =>
    FILE_TYPES.includes(value) && value !== 3,
  "git-diagnostic-write-type": (value) =>
    FILE_TYPES.includes(value) && value !== 3,
});
const NATIVE_OPERATIONS = new Set(
  `
  helper-invariant path-bound ack-read ack-value token-size token-allocation
  token-read token-close principal-token principal-sid principal-allocation
  principal-container process-time process-token process-id process-sid
  container-token container-identity security-descriptor acl-read acl-owner
  acl-control acl-entries acl-entry acl-sid acl-mask file-open file-tag file-path
  file-id file-shape file-size file-seek file-close hash-open hash-create hash-read
  hash-update hash-final hash-close hash-provider-close receipt-open receipt-size
  receipt-write receipt-flush receipt-read receipt-close profile-name profile-derive
  profile-sid profile-receipt profile-binding profile-intent argv-bound job-query
  job-limits launch-case launch-image executable-open executable-tag job-create
  job-config stdin-pipe stdout-pipe stdin-inherit stdout-inherit attribute-size
  attribute-allocation attribute-init attribute-security attribute-job
  attribute-handles local-appdata windows-directory environment-bound launch-intent
  process-create launch-absence launch-accounting pipe-close process-job
  process-image process-release process-open process-close process-wait
  handle-duplicate thread-query thread-state thread-process thread-close host-ci host-actions host-worker
  host-os deadline-create winsock-start job-terminate job-close profile-delete audit-remove audit-remove-settle
  git-command-bound git-null-input git-null-output git-null-close git-attribute-size
  git-attribute-allocation git-attribute-init git-attribute-handles git-process-create
  git-process-wait git-process-status git-process-exit git-thread-close git-process-close
  git-diagnostic-pipe git-diagnostic-inherit git-diagnostic-close git-diagnostic-read git-diagnostic-bound
  git-dubious-owner git-repository-read git-config-read git-user-name git-cwd-read
  git-home-missing git-path-read git-path-normalize executable-close
  tcp-endpoint tcp-exclusive observer-child observer-job observer-image observer-once observer-carrier
  observer-protocol observer-socket observer-local observer-unconnected observer-token
  observer-engine observer-collection observer-owner observer-transfer observer-socket-close observer-engine-close observer-enum-close observer-token-close
`
    .trim()
    .split(/\s+/u)
    .concat(Object.keys(GIT_HELPER_DOMAINS), GIT_EXIT_OPERATIONS),
);

/** This closed diagnostic grammar supplies no admission or retirement proof. */
export function windowsFeasibilityDiagnostics(output) {
  const bytes = Buffer.isBuffer(output)
    ? output
    : typeof output === "string"
      ? Buffer.from(output)
      : Buffer.alloc(0);
  if (!bytes.length || bytes.length > 4096) return null;
  const text = bytes.toString("utf8");
  if (
    !Buffer.from(text).equals(bytes) ||
    /[^\x20-\x7e\r\n]/u.test(text) ||
    !text.endsWith("\n")
  )
    return null;
  const lines = text.replace(/\r\n/gu, "\n").slice(0, -1).split("\n");
  if (lines.length > 2) return null;
  const read = (line, cleanup) => {
    const match =
      /^(native-windows(?:-cleanup)?): operation=([a-z-]+) domain=(win32|hresult|ntstatus|invariant|exit|errno) value=(0|[1-9][0-9]{0,9})$/u.exec(
        line,
      );
    if (
      !match ||
      match[1] !== (cleanup ? "native-windows-cleanup" : "native-windows") ||
      !NATIVE_OPERATIONS.has(match[2])
    )
      return null;
    const value = Number(match[4]);
    const domains = GIT_HELPER_DOMAINS[match[2]];
    if (
      value > 0xffffffff ||
      (domains &&
        (!domains.includes(match[3]) ||
          (match[3] === "win32" && value === 0))) ||
      (match[3] === "errno" &&
        (match[2] !== "stdout-mode" || ![9, 22].includes(value))) ||
      (match[3] === "exit") !== GIT_EXIT_OPERATIONS.includes(match[2]) ||
      (match[3] === "exit" && value === 0) ||
      (match[3] === "invariant" &&
        (Object.hasOwn(GIT_HELPER_FACTS, match[2])
          ? !GIT_HELPER_FACTS[match[2]](value)
          : value !== 0)) ||
      (["ntstatus", "hresult"].includes(match[3]) && value < 0x80000000)
    )
      return null;
    if (
      [
        "git-diagnostic-close",
        "git-thread-close",
        "git-process-close",
        "executable-close",
        "file-close",
        "pipe-close",
        "process-close",
        "forward-close",
        "git-null-close",
        "thread-close",
        "winsock-cleanup",
        "tcp-close",
        "observer-socket-close",
        "observer-engine-close",
        "observer-enum-close",
        "observer-token-close",
        "null-close",
        "null-remove",
      ].includes(match[2]) &&
      (match[3] !== "win32" || value === 0)
    )
      return null;
    if (
      cleanup &&
      ![
        "job-terminate",
        "job-close",
        "profile-delete",
        "audit-remove-settle",
        "git-diagnostic-close",
        "git-thread-close",
        "git-process-close",
        "executable-close",
        "file-close",
        "pipe-close",
        "process-close",
        "forward-close",
        "git-null-close",
        "thread-close",
        "forward-release",
        "forward-wait",
        "process-wait",
        "winsock-cleanup",
        "tcp-close",
        "observer-socket-close",
        "observer-engine-close",
        "observer-enum-close",
        "observer-token-close",
        "command-token-close",
        "command-null-close",
        "command-event-close",
        "command-metadata-close",
        "command-revert",
        "command-hash-close",
        "command-algorithm-close",
        "command-environment-close",
        "command-protect-free",
        "null-close",
        "null-remove",
        "null-retirement",
      ].includes(match[2])
    )
      return null;
    return Object.freeze({ operation: match[2], domain: match[3], value });
  };
  const failure = read(lines[0], false),
    cleanup = lines.length === 2 ? read(lines[1], true) : null;
  return failure && (lines.length === 1 || cleanup)
    ? Object.freeze({ failure, cleanup })
    : null;
}

/** Preserve narrow preparation causes without inventing process or deadline facts. */
export function windowsFeasibilityCause(stage, error) {
  if (error?.feasibilityCause)
    return unavailableFeasibilityResults("win32", error.feasibilityCause)[0]
      .cause;
  const rejection = REJECTIONS.includes(error?.nativeRejection)
    ? error.nativeRejection
    : null;
  const prerequisite =
    (error?.code === 78 &&
      !error?.signal &&
      !rejection &&
      !error?.nativeDiagnosticInvalid &&
      !error?.nativeStreamInvalid) ||
    (stage === "outside-controls" &&
      ["ENOSYS", "ENOTSUP", "EACCES"].includes(error?.code));
  const cause = windowsFeasibilityPeCause(
    "win32",
    OPERATIONS.includes(error?.operation)
      ? `${stage}-${error.operation}`
      : stage,
    {
      ...error,
      code: error?.code,
      signal: error?.signal,
      timedOut: error?.timedOut ?? (error?.code === 124 ? true : undefined),
    },
    prerequisite
      ? "prerequisite-unavailable"
      : error?.escape
        ? "observed-escape"
        : "setup-failed",
  );
  const diagnostic = !error?.nativeDiagnosticInvalid
    ? windowsFeasibilityDiagnostics(error?.stderr)?.failure
    : null;
  const remedy =
    diagnostic?.operation === "local-appdata"
      ? " Restore the hosted worker's LOCALAPPDATA before launch."
      : "";
  const explanation = rejection
    ? `Native helper ${rejection.startsWith("diagnostic-") ? "diagnostic" : "stream"} rejected (${rejection}).`
    : diagnostic
      ? `Native ${diagnostic.operation} failed (${diagnostic.domain}=${diagnostic.value}).${remedy}${error?.nativeStreamInvalid ? " Native helper stream rejected." : ""}`
      : error?.nativeDiagnosticInvalid
        ? "Native helper diagnostic rejected as malformed or oversized."
        : error?.nativeStreamInvalid
          ? "Native helper stream rejected as malformed or incomplete."
          : null;
  return explanation
    ? {
        ...cause,
        detail:
          `${cause.detail.split(";")[0]}; output=${diagnostic || rejection ? "recognized" : "unrecognized"}; ${explanation}`.slice(
            0,
            256,
          ),
      }
    : cause;
}

/** Validate custody before fault release; optional settlement must prove retirement. */
export function assertWindowsFeasibilityWitness(
  kind,
  ready,
  expected,
  settled,
) {
  need(
    ["holder", "final"].includes(kind) &&
      ready?.event === "witness-ready" &&
      ready.jobHeld === (kind === "holder") &&
      Array.isArray(ready.members) &&
      ready.members.length === 2,
  );
  normalizeWindowsIdentity(ready.owner);
  normalizeWindowsIdentity(ready.child);
  need(
    Array.isArray(expected) &&
      expected.length === 2 &&
      !sameWindowsIdentity(expected[0], expected[1]) &&
      expected.every((identity) =>
        ready.members.some((member) => sameWindowsIdentity(member, identity)),
      ) &&
      expected.every((identity) => !sameWindowsIdentity(ready.owner, identity)),
  );
  const handle = (value) =>
    typeof value === "string" &&
    /^[1-9][0-9]{0,19}$/u.test(value) &&
    BigInt(value) <= 0xffffffffffffffffn;
  need(sameWindowsIdentity(ready.child, expected[0]) && handle(ready.process));
  need(
    kind === "holder"
      ? handle(ready.job) && ready.job !== ready.process
      : ready.job === "0",
  );
  if (settled !== undefined)
    need(
      settled?.retired === true &&
        (kind === "holder"
          ? settled.jobEmpty === true
          : settled.jobHeld === false),
    );
}

async function durable(file, bytes) {
  const handle = await open(file, "wx", 0o600);
  try {
    await handle.writeFile(bytes);
    await handle.sync();
  } finally {
    await handle.close();
  }
}
async function regular(file) {
  // Installed SDK/system files may have hard links. Their bytes are read only;
  // exclusive copies and native cleanup identities never adopt those links.
  const stat = await lstat(file);
  if (!(
    stat.isFile() &&
    !stat.isSymbolicLink() &&
    stat.nlink >= 1 &&
    stat.size <= 134217728
  ))
    throw Object.assign(new Error("Invalid native prerequisite file"), {
      code: "ERR_FEASIBILITY_WINDOWS_FILE",
    });
  return readFile(file);
}
const IMAGE_PREFIX = "native-windows-image:";
const CWD_PREFIX = "native-windows-cwd:";
const TCP_PREFIX = "native-windows-tcp:";
const WFP_PREFIX = "native-windows-wfp:";
const isWfpLine = (bytes) => {
  const text = bytes.toString("utf8");
  return (
    text.length >= "native-windows-w".length &&
    (text.startsWith(WFP_PREFIX) || WFP_PREFIX.startsWith(text))
  );
};
function wfpCapture() {
  let bytes = 0,
    invalid = false,
    tuple,
    observation,
    settle;
  const ready = new Promise((resolve) => {
    settle = resolve;
  });
  const incomplete = () => {
    invalid = true;
    observation = undefined;
    settle();
  };
  const snapshot = () => ({
    status: invalid
      ? "incomplete"
      : observation
        ? "complete"
        : bytes
          ? "incomplete"
          : "unavailable",
    tuple: tuple ? structuredClone(tuple) : null,
    observation: observation && !invalid ? structuredClone(observation) : null,
  });
  return {
    incomplete,
    snapshot,
    consume(line) {
      bytes += line.length;
      if (invalid || bytes > 4096 || observation) return incomplete();
      const text = line.toString("utf8");
      if (!Buffer.from(text).equals(line)) return incomplete();
      try {
        const carrier =
          /^native-windows-wfp: tuple=([a-f0-9]{144})\r?\n$/u.exec(text);
        if (carrier) {
          need(!tuple);
          const data = Buffer.from(carrier[1], "hex");
          need(
            data.readUInt32LE(0) === 0x57465031 && data.readUInt32LE(68) <= 1,
          );
          const endpoint = (remote) => {
            const status = data.readUInt32LE(remote ? 36 : 32),
              size = data.readUInt32LE(remote ? 64 : 60),
              family = data.readUInt32LE(remote ? 56 : 52);
            const read = status === 0 && size === 16 && family === 2;
            return {
              status,
              size,
              family,
              address: read ? data.readUInt32LE(remote ? 44 : 40) : null,
              port: read ? data.readUInt16LE(remote ? 50 : 48) : null,
            };
          };
          tuple = {
            child: {
              pid: data.readUInt32LE(4),
              creationTime: data.readBigUInt64LE(8).toString(),
            },
            startedAt: data.readBigUInt64LE(16).toString(),
            endedAt: data.readBigUInt64LE(24).toString(),
            attempted: data.readUInt32LE(68) === 1,
            local: endpoint(false),
            remote: endpoint(true),
          };
          return;
        }
        const row = /^native-windows-wfp: snapshot=(.+)\r?\n$/u.exec(text);
        need(tuple && row);
        observation = JSON.parse(row[1]);
        settle();
      } catch {
        incomplete();
      }
    },
    close() {
      if (bytes && !observation) incomplete();
      settle();
    },
    async wait() {
      let timer;
      try {
        await Promise.race([
          ready,
          new Promise((resolve) => {
            timer = setTimeout(() => {
              incomplete();
              resolve();
            }, 10000);
          }),
        ]);
      } finally {
        clearTimeout(timer);
      }
      return snapshot();
    },
  };
}
const wfpUint = (value) =>
  Number.isSafeInteger(value) && value >= 0 && value <= 0xffffffff;
const wfpTime = (value) =>
  typeof value === "string" &&
  /^[1-9][0-9]{0,19}$/u.test(value) &&
  BigInt(value) <= 0xffffffffffffffffn;
const wfpClosed = (value, keys) =>
  value &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.keys(value).sort().join(",") === [...keys].sort().join(",");
/** Diagnostic evidence only. Native receipts and lifecycle retirement retain authority. */
export async function observeWindowsFeasibilityWfp(run, persist) {
  let evidence = {
    status: "unproved",
    reason: "capture",
    cleanup: "UNCERTAIN",
    matches: [],
  };
  try {
    const captured = await run.session.wfp();
    if (captured.status === "unavailable")
      evidence = { ...evidence, reason: "unavailable", cleanup: "NOT_RUN" };
    else {
      const tuple = captured.tuple,
        row = captured.observation,
        receipt = run.receipt;
      need(captured.status === "complete" && tuple && row);
      need(
        tuple.child.pid === receipt.child.pid &&
          tuple.child.creationTime === receipt.child.creationTime &&
          wfpTime(tuple.startedAt) &&
          wfpTime(tuple.endedAt) &&
          BigInt(tuple.startedAt) >= BigInt(receipt.child.creationTime) &&
          BigInt(tuple.endedAt) >= BigInt(tuple.startedAt) &&
          BigInt(tuple.endedAt) - BigInt(tuple.startedAt) <= 60000000n,
      );
      need(
        wfpClosed(row, [
          "status",
          "reason",
          "nativeStatus",
          "enumClose",
          "engineClose",
          "child",
          "sid",
          "userSid",
          "image",
          "matches",
        ]) &&
          ["matched", "disabled", "unproved"].includes(row.status) &&
          [
            "none",
            "binding",
            "api",
            "fields",
            "lookup",
            "empty",
            "exhausted",
          ].includes(row.reason),
      );
      need(
        wfpUint(row.nativeStatus) &&
          [row.enumClose, row.engineClose].every(
            (value) => value === null || wfpUint(value),
          ) &&
          Array.isArray(row.matches) &&
          row.matches.length <= 8,
      );
      need(
        wfpClosed(row.child, ["pid", "creationTime"]) &&
          row.child.pid === receipt.child.pid &&
          row.child.creationTime === receipt.child.creationTime &&
          row.sid === receipt.sid &&
          row.userSid === receipt.child.userSid &&
          wfpClosed(row.image, ["identity", "sha256", "private"]) &&
          row.image.identity === receipt.image.identity &&
          row.image.sha256 === receipt.image.sha256 &&
          row.image.private === false,
      );
      const bound =
        tuple.attempted &&
        [tuple.local, tuple.remote].every(
          (endpoint) =>
            endpoint.status === 0 &&
            endpoint.size === 16 &&
            endpoint.family === 2 &&
            endpoint.address === 0x7f000001 &&
            endpoint.port > 0,
        );
      if (row.status === "matched") {
        need(
          bound &&
            row.reason === "none" &&
            row.nativeStatus === 0 &&
            row.enumClose === 0 &&
            row.engineClose === 0 &&
            row.matches.length > 0,
        );
        for (const event of row.matches)
          need(
            wfpClosed(event, [
              "filterId",
              "layerId",
              "direction",
              "actionType",
              "flags",
              "isLoopback",
              "time",
              "filterKey",
              "layerKey",
            ]) &&
              wfpTime(event.filterId) &&
              Number.isSafeInteger(event.layerId) &&
              event.layerId > 0 &&
              event.layerId <= 65535 &&
              [0, 1].includes(event.direction) &&
              event.actionType === 0x1001 &&
              wfpUint(event.flags) &&
              (event.flags & 0x57f) === 0x57f &&
              !(event.flags & ~0x7ff) &&
              event.isLoopback === true &&
              wfpTime(event.time) &&
              BigInt(event.time) >= BigInt(tuple.startedAt) &&
              BigInt(event.time) <= BigInt(tuple.endedAt) &&
              [event.filterKey, event.layerKey].every(
                (key) => typeof key === "string" && /^[a-f0-9]{32}$/u.test(key),
              ),
          );
      } else
        need(
          row.matches.length === 0 &&
            (row.status !== "disabled" || row.nativeStatus === 0x80320013),
        );
      evidence = {
        ...row,
        tuple,
        cleanup: row.enumClose || row.engineClose ? "UNCERTAIN" : "CLOSED",
      };
    }
  } catch (error) {
    nativeException("windows-wfp-observation", error);
  }
  run.wfpObservation = evidence;
  try {
    await persist(`${run.caseId}-wfp`, evidence);
  } catch (error) {
    nativeException("windows-wfp-persistence", error);
  }
  return evidence;
}
// The feasibility gate requires WSAEACCES, even when the full PoC separately
// permits a socket-correlated kernel DROP. Diagnostic snapshots have no authority.
const tcpBindingKeys = [
  "child",
  "owner",
  "sid",
  "userSid",
  "image",
  "tokenId",
  "authenticationId",
  "preparedAt",
  "exclusive",
];
const tcpEndpoint = (value, port) =>
  wfpClosed(value, ["address", "port"]) &&
  value.address === 0x7f000001 &&
  Number.isSafeInteger(value.port) &&
  value.port > 0 &&
  value.port <= 65535 &&
  (port === undefined || value.port === port);
function assertTcpBinding(row, receipt) {
  for (const key of ["child", "owner"])
    need(
      wfpClosed(row[key], ["pid", "creationTime"]) &&
        row[key].pid === receipt[key].pid &&
        row[key].creationTime === receipt[key].creationTime,
    );
  need(
    row.exclusive === true &&
      row.sid === receipt.sid &&
      row.userSid === receipt.child.userSid &&
      wfpClosed(row.image, ["identity", "sha256", "private"]) &&
      row.image.private === false &&
      row.image.identity === receipt.image.identity &&
      row.image.sha256 === receipt.image.sha256 &&
      [row.tokenId, row.authenticationId].every(
        (value) =>
          typeof value === "string" &&
          /^[a-f0-9]{16}$/u.test(value) &&
          !/^0+$/u.test(value),
      ) &&
      wfpTime(row.preparedAt) &&
      BigInt(row.preparedAt) >= BigInt(receipt.child.creationTime),
  );
}
export function assertWindowsFeasibilityTcpObserver(row, receipt, endpoint) {
  need(
    wfpClosed(row, [
      "event",
      ...tcpBindingKeys,
      "local",
      "requested",
      "collectionEnabled",
      "peerStatus",
    ]) &&
      row.event === "tcp-observer-ready" &&
      row.collectionEnabled === true &&
      row.peerStatus === 10057 &&
      typeof endpoint === "string" &&
      /^[1-9][0-9]{0,4}$/u.test(endpoint) &&
      tcpEndpoint(row.requested, Number(endpoint)) &&
      tcpEndpoint(row.local),
  );
  assertTcpBinding(row, receipt);
  return row;
}
function assertWindowsFeasibilityTcpAttribution(
  row,
  prepared,
  receipt,
  endpoint,
) {
  assertWindowsFeasibilityTcpObserver(prepared, receipt, endpoint);
  need(
    wfpClosed(row, [
      "event",
      ...tcpBindingKeys,
      "requested",
      "local",
      "localStatus",
      "peerStatus",
      "startedAt",
      "endedAt",
      "socketClose",
      "tokenClosed",
      "status",
      "reason",
      "nativeStatus",
      "enumClose",
      "engineClose",
      "matches",
    ]) &&
      row.event === "tcp-attribution" &&
      row.status === "matched" &&
      row.reason === "none" &&
      row.nativeStatus === 0 &&
      row.enumClose === 0 &&
      row.engineClose === 0 &&
      row.socketClose === 0 &&
      row.tokenClosed === true &&
      row.localStatus === 0 &&
      wfpUint(row.peerStatus) &&
      tcpEndpoint(row.local, prepared.local.port) &&
      tcpEndpoint(row.requested, Number(endpoint)) &&
      wfpTime(row.startedAt) &&
      wfpTime(row.endedAt) &&
      BigInt(row.startedAt) >= BigInt(prepared.preparedAt) &&
      BigInt(row.endedAt) >= BigInt(row.startedAt) &&
      BigInt(row.endedAt) - BigInt(prepared.preparedAt) <= 50000000n &&
      Array.isArray(row.matches) &&
      row.matches.length > 0 &&
      row.matches.length <= 8,
  );
  assertTcpBinding(row, receipt);
  need(
    ["tokenId", "authenticationId", "preparedAt"].every(
      (key) => row[key] === prepared[key],
    ),
  );
  for (const event of row.matches)
    need(
      wfpClosed(event, [
        "filterId",
        "layerId",
        "direction",
        "actionType",
        "flags",
        "isLoopback",
        "time",
        "filterKey",
        "layerKey",
      ]) &&
        wfpTime(event.filterId) &&
        Number.isSafeInteger(event.layerId) &&
        event.layerId > 0 &&
        event.layerId <= 65535 &&
        event.layerKey === "d1578dc3a705334c904f7fbceee60e82" &&
        event.direction === 0 &&
        event.actionType === 0x1001 &&
        wfpUint(event.flags) &&
        (event.flags & 0x57f) === 0x57f &&
        !(event.flags & ~0x7ff) &&
        event.isLoopback === true &&
        wfpTime(event.time) &&
        BigInt(event.time) >= BigInt(row.startedAt) &&
        BigInt(event.time) <= BigInt(row.endedAt) &&
        typeof event.filterKey === "string" &&
        /^[a-f0-9]{32}$/u.test(event.filterKey) &&
        !/^0+$/u.test(event.filterKey),
    );
  return row;
}
export function assertWindowsFeasibilityTcpDenial(
  row,
  prepared,
  receipt,
  endpoint,
  result,
) {
  need(result === 10013);
  return assertWindowsFeasibilityTcpAttribution(
    row,
    prepared,
    receipt,
    endpoint,
  );
}
const isTcpLine = (bytes) => {
  const text = bytes.toString("utf8");
  return (
    text.length >= "native-windows-t".length &&
    (text.startsWith(TCP_PREFIX) || TCP_PREFIX.startsWith(text))
  );
};
function tcpCapture() {
  const calls = [];
  let bytes = 0,
    invalid = false,
    ended = false;
  const incomplete = () => {
    invalid = true;
  };
  return {
    incomplete,
    consume: (line) => {
      bytes += line.length;
      if (invalid || bytes > 2048 || ended) return incomplete();
      const text = line.toString("utf8");
      if (/^native-windows-tcp: end\r?\n$/u.test(text)) {
        const first = calls[0],
          last = calls.at(-1);
        if (
          first?.api !== "WSASocketW" ||
          first.phase !== "enter" ||
          !["complete", "failed"].includes(last?.phase) ||
          (last.api !== "closesocket" &&
            !(last.api === "WSASocketW" && last.phase === "failed"))
        )
          return incomplete();
        ended = true;
        return;
      }
      const row =
        /^native-windows-tcp: api=(WSASocketW|ioctlsocket|bind|connect|select|getsockopt|setsockopt|send|recv|closesocket|transaction) phase=(enter|complete|pending|failed) value=(0|[1-9][0-9]{0,9})\r?\n$/u.exec(
          text,
        );
      if (!row) return incomplete();
      const [, api, phase, digits] = row,
        value = Number(digits);
      if (
        value > 0xffffffff ||
        (["enter", "complete"].includes(phase) && value !== 0) ||
        (phase === "pending" && (api !== "connect" || value !== 10035)) ||
        (phase === "failed" && api !== "transaction" && value === 0)
      )
        return incomplete();
      calls.push({ api, phase, value });
    },
    snapshot: () => ({
      status:
        ended && !invalid
          ? "complete"
          : bytes || invalid
            ? "incomplete"
            : "unavailable",
      calls: calls.map((call) => ({ ...call })),
    }),
  };
}
const isCwdLine = (bytes) => {
  const text = bytes.toString("utf8");
  return (
    text.length >= "native-windows-c".length &&
    (text.startsWith(CWD_PREFIX) || CWD_PREFIX.startsWith(text))
  );
};
const isImageLine = (bytes) => {
  const text = bytes.toString("utf8");
  return (
    text.length >= "native-windows-i".length &&
    (text.startsWith(IMAGE_PREFIX) || IMAGE_PREFIX.startsWith(text))
  );
};
function imageBindingCapture() {
  let query,
    bytes = 0,
    invalid = false,
    ended = false;
  const paths = {
    expected: { length: null, utf16: "" },
    actual: { length: null, utf16: "" },
  };
  const incomplete = () => {
    invalid = true;
  };
  return {
    incomplete,
    consume: (line) => {
      if (invalid) return;
      bytes += line.length;
      if (bytes > 36864 || ended) return incomplete();
      const text = line.toString("utf8");
      const header =
        /^native-windows-image: query=([01]) capacity=4096 flags=1 length=([0-9]{1,10}) error=(unavailable|[0-9]{1,10}) expected=([0-9]{1,4}) actual=([01])\r?\n$/u.exec(
          text,
        );
      if (header) {
        const value = {
          succeeded: header[1] === "1",
          capacity: 4096,
          flags: 1,
          returnedLength: Number(header[2]),
          lastError: header[3] === "unavailable" ? null : Number(header[3]),
        };
        const expectedLength = Number(header[4]),
          available =
            value.succeeded &&
            value.returnedLength > 0 &&
            value.returnedLength < 4096;
        if (
          query ||
          value.returnedLength > 0xffffffff ||
          value.lastError > 0xffffffff ||
          expectedLength === 0 ||
          expectedLength >= 4096 ||
          value.succeeded !== (value.lastError === null) ||
          available !== (header[5] === "1")
        )
          return incomplete();
        query = value;
        paths.expected.length = expectedLength;
        paths.actual.length = available ? value.returnedLength : null;
      } else if (/^native-windows-image: end\r?\n$/u.test(text)) {
        if (
          !query ||
          Object.values(paths).some(
            ({ length, utf16 }) => utf16.length !== (length ?? 0) * 4,
          )
        )
          return incomplete();
        ended = true;
      } else {
        const row =
          /^native-windows-image: (expected|actual) ((?:[a-f0-9]{4}){1,512})\r?\n$/u.exec(
            text,
          );
        const path = row && paths[row[1]];
        if (
          !query ||
          !path ||
          path.length === null ||
          path.utf16.length + row[2].length > path.length * 4
        )
          return incomplete();
        path.utf16 += row[2];
      }
    },
    snapshot: () => {
      const complete = Boolean(query && ended && !invalid);
      const path = (name) => ({
        available: complete && paths[name].length !== null,
        ...paths[name],
      });
      return {
        status: complete ? "complete" : query ? "incomplete" : "unavailable",
        query: query ? { ...query } : null,
        expected: path("expected"),
        actual: path("actual"),
      };
    },
  };
}

function cwdCapture(workspaceRooted = false) {
  const names = ["current", "open", "dos", "nt", "long"],
    calls = {};
  let owner = null,
    closure = null,
    bytes = 0,
    invalid = false,
    ended = false,
    context = "payload-original";
  const incomplete = () => {
    invalid = true;
  };
  return {
    incomplete,
    consume: (line) => {
      bytes += line.length;
      if (invalid || bytes > 8192 || ended) return incomplete();
      const text = line.toString("utf8");
      const header =
        /^native-windows-cwd: pid=([1-9][0-9]{0,9}) birth=(unavailable|[1-9][0-9]{0,19}) error=(unavailable|0|[1-9][0-9]{0,9}) context=(payload-original|payload-private-workspace-rooted) capacity=260\r?\n$/u.exec(
          text,
        );
      if (header) {
        const birth = header[2] === "unavailable" ? null : header[2];
        const lastError =
          header[3] === "unavailable" ? null : Number(header[3]);
        if (
          owner ||
          (header[4] !== "payload-original" && !workspaceRooted) ||
          Number(header[1]) > 0xffffffff ||
          lastError > 0xffffffff ||
          (birth !== null && BigInt(birth) > 0xffffffffffffffffn) ||
          (birth === null) !== (lastError !== null)
        )
          return incomplete();
        owner = { pid: Number(header[1]), creationTime: birth, lastError };
        context = header[4];
        return;
      }
      const end =
        /^native-windows-cwd: end close=(not-attempted|success|failed)\r?\n$/u.exec(
          text,
        );
      if (end) {
        closure = end[1];
        if (!owner || Object.keys(calls).length !== names.length)
          return incomplete();
        const attempted = (name) => calls[name].outcome !== "not-attempted";
        const opened = calls.open.outcome === "success";
        if (
          !attempted("current") ||
          attempted("open") !== (calls.current.outcome === "success") ||
          attempted("dos") !== opened ||
          attempted("nt") !== opened ||
          (closure !== "not-attempted") !== opened ||
          attempted("long") !==
            (opened && closure === "success" && calls.dos.outcome !== "success")
        )
          return incomplete();
        ended = true;
        return;
      }
      const row =
        /^native-windows-cwd: (current|open|dos|nt|long) outcome=(not-attempted|failed|oversized|success) length=(unavailable|0|[1-9][0-9]{0,9}) error=(unavailable|0|[1-9][0-9]{0,9}) utf16=((?:[a-f0-9]{4}){0,259})\r?\n$/u.exec(
          text,
        );
      if (!owner || !row || row[1] !== names[Object.keys(calls).length])
        return incomplete();
      const [, name, outcome, length, error, utf16] = row;
      const returnedLength = length === "unavailable" ? null : Number(length);
      const lastError = error === "unavailable" ? null : Number(error);
      const skipped = outcome === "not-attempted",
        open = name === "open";
      if (
        returnedLength > 0xffffffff ||
        lastError > 0xffffffff ||
        (outcome === "failed") !== (lastError !== null) ||
        (returnedLength === null) !== (skipped || open) ||
        (open && (outcome === "oversized" || utf16)) ||
        (!open &&
          !skipped &&
          (outcome === "failed"
            ? returnedLength !== 0
            : outcome === "oversized"
              ? returnedLength < 260
              : returnedLength < 1 || returnedLength >= 260)) ||
        utf16.length !==
          (!open && outcome === "success" ? returnedLength * 4 : 0)
      )
        return incomplete();
      calls[name] = { outcome, returnedLength, lastError, utf16 };
    },
    snapshot: () => ({
      status:
        ended && !invalid && owner?.creationTime
          ? "complete"
          : bytes || invalid
            ? "incomplete"
            : "unavailable",
      context,
      capacity: 260,
      owner: owner ? { ...owner } : null,
      calls: Object.fromEntries(
        Object.entries(calls).map(([name, call]) => [name, { ...call }]),
      ),
      closure,
    }),
  };
}

/** Explicit helper effect; portable callers inject the child-process boundary. */
export function windowsFeasibilityHelperSession(
  helper,
  root,
  nonce,
  env,
  role,
  args = [],
  { spawnProcess = spawn, diagnostics = nativeDiagnostic } = {},
) {
  const rootedHolder =
    role === "null-map" && args.at(-1) === "workspace-rooted";
  const stdoutLimit = rootedHolder
    ? 524288
    : role === "null-map" && args.at(-1) === "no-shadow-mapped"
      ? 262144
      : 65536;
  const callerEnvironment = windowsFeasibilityCallerEnvironment(env);
  const child = spawnProcess(
    helper,
    [role, root, nonce, ...args].map(quoteWindowsArgument),
    {
      env: callerEnvironment,
      argv0: quoteWindowsArgument(helper),
      windowsVerbatimArguments: true,
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
    },
  );
  const rows = [],
    pending = [];
  const imageBinding = imageBindingCapture();
  const rootedLaunch = windowsFeasibilityWorkspaceLaunch(role, args);
  const cwdObservation = cwdCapture(rootedLaunch);
  const tcpObservation = tcpCapture();
  const wfpObservation = wfpCapture();
  let targetSent = false;
  let bytes = Buffer.alloc(0),
    parsed = 0,
    stderr = Buffer.alloc(0),
    diagnosticPending = Buffer.alloc(0),
    discardingDiagnosticLine = false,
    rawBytes = 0,
    rawComplete = false,
    rawPartial = false,
    rawTruncated = false,
    rawCapture = [],
    diagnosticParsed = 0,
    nativeLine,
    cleanup,
    failures = 0,
    cleanups = 0,
    nativeDiagnosticInvalid = false,
    stdoutInvalid = false,
    captureTruncated = false,
    inputEnded = false,
    firstFailure,
    error,
    exit;
  const streamNeed = (value, rejection) => {
    if (!value)
      throw Object.assign(new Error("Rejected native helper stream"), {
        nativeRejection: rejection,
      });
  };
  const attach = (problem) => {
    Object.assign(problem, {
      // Only the first validated refusal and earliest validated cleanup are
      // projected. Later output still gets checked without replacing that cause.
      stderr: nativeLine
        ? nativeLine.toString("utf8") +
          (cleanup
            ? `native-windows-cleanup: operation=${cleanup.operation} domain=${cleanup.domain} value=${cleanup.value}\n`
            : "")
        : stderr.toString("utf8"),
      nativeDiagnosticInvalid: nativeDiagnosticInvalid && !firstFailure?.native,
      nativeRejection: firstFailure?.rejection,
      imageBinding: imageBinding.snapshot(),
      cwdObservation: cwdObservation.snapshot(),
      tcpObservation: tcpObservation.snapshot(),
      wfpObservation: wfpObservation.snapshot(),
    });
    if (exit) {
      Object.assign(problem, { exitCode: exit.code, signal: exit.signal });
      problem.code ??= exit.code;
    }
    return problem;
  };
  const endInput = () => {
    if (inputEnded) return;
    inputEnded = true;
    child.stdin.end();
  };
  const reject = (problem, rejection) => {
    diagnostics("windows-helper", { exception: problem });
    if (["diagnostic-bound", "stdout-bound"].includes(rejection))
      captureTruncated = true;
    firstFailure ??= REJECTIONS.includes(rejection) ? { rejection } : {};
    error ??= problem;
    // A complete refusal explains absent receipts, but cannot explain away
    // partial stdout or a concrete encoding, framing or diagnostic rejection.
    if (
      problem.nativeStreamInvalid ||
      (REJECTIONS.includes(rejection) &&
        (rejection !== "eof" || !firstFailure.native))
    )
      error.nativeStreamInvalid = true;
    attach(error);
    for (const waiter of pending.splice(0)) waiter.reject(error);
    endInput();
  };
  const refuseDiagnostic = (rejection) => {
    nativeDiagnosticInvalid = true;
    reject(
      Object.assign(new Error("Rejected native helper stream"), {
        nativeRejection: rejection,
      }),
      rejection,
    );
  };
  child.on("error", reject);
  child.stdin.on("error", reject);
  child.stdout.on("error", reject);
  child.stderr.on("error", reject);
  child.stderr.on("data", (chunk) => {
    diagnostics("windows-helper-transport", { stderr: chunk });
    try {
      const strictLines = [];
      let strictBytes = 0;
      for (let offset = 0; offset < chunk.length;) {
        const end = chunk.indexOf(10, offset);
        const next = end < 0 ? chunk.length : end + 1;
        if (
          discardingDiagnosticLine ||
          diagnosticPending.length + next - offset > 4096
        ) {
          if (!discardingDiagnosticLine) {
            const prefix = Buffer.concat([
              diagnosticPending,
              chunk.subarray(
                offset,
                Math.min(next, offset + IMAGE_PREFIX.length),
              ),
            ]);
            if (isImageLine(prefix)) imageBinding.incomplete();
            else if (isCwdLine(prefix)) cwdObservation.incomplete();
            else if (isTcpLine(prefix)) tcpObservation.incomplete();
            else if (isWfpLine(prefix)) wfpObservation.incomplete();
            else refuseDiagnostic("diagnostic-bound");
          }
          diagnosticPending = Buffer.alloc(0);
          discardingDiagnosticLine = end < 0;
          offset = next;
          continue;
        }
        diagnosticPending = Buffer.concat([
          diagnosticPending,
          chunk.subarray(offset, next),
        ]);
        offset = next;
        if (end < 0) break;
        const line = diagnosticPending;
        diagnosticPending = Buffer.alloc(0);
        const text = line.toString("utf8");
        if (isImageLine(line)) {
          imageBinding.consume(line);
          continue;
        }
        if (isCwdLine(line)) {
          cwdObservation.consume(line);
          continue;
        }
        if (isTcpLine(line)) {
          tcpObservation.consume(line);
          continue;
        }
        if (isWfpLine(line)) {
          wfpObservation.consume(line);
          continue;
        }
        if (text.startsWith("native-windows-output:")) {
          const carrier =
            /^native-windows-output: ((?:[a-f0-9]{2}){1,1024})\r?\n$/u.exec(
              text,
            );
          if (!carrier || rawComplete) {
            refuseDiagnostic("diagnostic-form");
            continue;
          }
          const bytes = Buffer.from(carrier[1], "hex");
          if (rawBytes + bytes.length > 65536) {
            refuseDiagnostic("diagnostic-bound");
            continue;
          }
          rawBytes += bytes.length;
          rawCapture.push(bytes);
          diagnostics("windows-confined-git", { stderr: bytes });
          continue;
        }
        if (text.startsWith("native-windows-output-end:")) {
          const completion =
            /^native-windows-output-end: (complete|partial|truncated)\r?\n$/u.exec(
              text,
            );
          if (!completion || rawComplete) {
            refuseDiagnostic("diagnostic-form");
            continue;
          }
          rawComplete = true;
          rawPartial = completion[1] !== "complete";
          rawTruncated = completion[1] === "truncated";
          diagnostics("windows-confined-git", {
            partial: rawPartial,
            truncated: rawTruncated,
          });
          continue;
        }
        if (!nativeDiagnosticInvalid) {
          strictBytes += line.length;
          if (stderr.length + strictBytes <= 4096) strictLines.push(line);
        }
      }
      // Evidence refusal never stops decoding a later complete raw carrier.
      if (error) attach(error);
      if (nativeDiagnosticInvalid) return;
      const fragment = diagnosticPending.toString("ascii");
      const carrierPending = [
        IMAGE_PREFIX,
        CWD_PREFIX,
        TCP_PREFIX,
        WFP_PREFIX,
        "native-windows-output: ",
        "native-windows-output-end: ",
      ].some(
        (prefix) => prefix.startsWith(fragment) || fragment.startsWith(prefix),
      );
      // Check the entire strict contribution before admitting any line from
      // this event, retaining the original aggregate failure/cleanup budget.
      streamNeed(
        stderr.length +
          strictBytes +
          (carrierPending ? 0 : diagnosticPending.length) <=
          4096,
        "diagnostic-bound",
      );
      for (const line of strictLines) {
        stderr = Buffer.concat([stderr, line]);
        const isCleanup = line
          .toString("ascii")
          .startsWith("native-windows-cleanup:");
        const diagnosis = windowsFeasibilityDiagnostics(
          isCleanup && nativeLine ? Buffer.concat([nativeLine, line]) : line,
        );
        streamNeed(Boolean(diagnosis), "diagnostic-form");
        // Payload and launcher may each emit one failure and one cleanup.
        // Complete line writes can interleave, but a cleanup needs a failure.
        streamNeed(
          isCleanup ? cleanups < failures && cleanups < 2 : failures < 2,
          "diagnostic-form",
        );
        diagnosticParsed = stderr.length;
        if (isCleanup) {
          cleanups++;
          cleanup ??= diagnosis.cleanup;
          if (error) attach(error);
        } else {
          failures++;
          nativeLine ??= line;
          firstFailure ??= { native: nativeLine };
          // Latch before ending owner input: its error/close callbacks cannot
          // admit a queued receipt or steal the original validated refusal.
          reject(new Error("Native helper refused"));
        }
      }
    } catch (problem) {
      diagnostics("windows-helper-parser", { exception: problem });
      diagnostics("windows-helper", {
        stderr: diagnosticPending,
        partial: true,
      });
      nativeDiagnosticInvalid = true;
      reject(problem, problem.nativeRejection);
    }
  });
  child.stdout.on("data", (chunk) => {
    diagnostics("windows-helper", { stdout: chunk });
    if (stdoutInvalid) return;
    try {
      streamNeed(bytes.length + chunk.length <= stdoutLimit, "stdout-bound");
      bytes = Buffer.concat([bytes, chunk]);
      for (;;) {
        const end = bytes.indexOf(10, parsed);
        if (end < 0) break;
        const line = bytes.subarray(parsed, end).toString("utf8");
        streamNeed(
          Buffer.from(line).equals(bytes.subarray(parsed, end)),
          "encoding",
        );
        streamNeed(!line.includes("\r"), "framing");
        let row;
        try {
          row = JSON.parse(line);
        } catch (diagnosticError) {
          diagnostics("windows-helper-parser", { exception: diagnosticError });
          streamNeed(false, "json");
        }
        parsed = end + 1;
        // Continue bounded validation after refusal, without admitting output.
        if (error) continue;
        rows.push(row);
        if (pending.length) pending.shift().resolve(row);
      }
    } catch (problem) {
      diagnostics("windows-helper-parser", { exception: problem });
      stdoutInvalid = true;
      reject(
        Object.assign(problem, { nativeStreamInvalid: true }),
        problem.nativeRejection,
      );
    }
  });
  const closed = new Promise((resolve) =>
    child.once("close", (code, signal) => {
      exit = { code, signal };
      if (diagnosticPending.length)
        diagnostics("windows-helper", {
          stderr: diagnosticPending,
          partial: true,
        });
      diagnostics("windows-helper", {
        exitCode: code,
        signal,
        partial:
          rawPartial ||
          captureTruncated ||
          discardingDiagnosticLine ||
          diagnosticPending.length > 0 ||
          (rawBytes > 0 && !rawComplete),
        truncated: rawTruncated || captureTruncated,
      });
      if (parsed !== bytes.length)
        reject(
          Object.assign(new Error("Incomplete native stream"), {
            nativeStreamInvalid: true,
          }),
          "eof",
        );
      if (isImageLine(diagnosticPending)) {
        imageBinding.incomplete();
        diagnosticPending = Buffer.alloc(0);
      }
      if (isCwdLine(diagnosticPending)) {
        cwdObservation.incomplete();
        diagnosticPending = Buffer.alloc(0);
      }
      if (isTcpLine(diagnosticPending)) {
        tcpObservation.incomplete();
        diagnosticPending = Buffer.alloc(0);
      }
      if (isWfpLine(diagnosticPending)) {
        wfpObservation.incomplete();
        diagnosticPending = Buffer.alloc(0);
      }
      wfpObservation.close();
      if (diagnosticPending.length || diagnosticParsed !== stderr.length) {
        nativeDiagnosticInvalid = true;
        reject(new Error("Malformed native diagnostic"), "diagnostic-form");
      }
      if (error) attach(error);
      if (pending.length)
        reject(attach(new Error("Native stream ended")), "eof");
      resolve(exit);
    }),
  );
  let cursor = 0;
  const bounded = async (promise) => {
    let timer;
    try {
      return await Promise.race([
        promise,
        new Promise((_, fail) => {
          timer = setTimeout(() => {
            const failure = Object.assign(
              new Error("Native experiment deadline"),
              { code: "ERR_FEASIBILITY_DEADLINE" },
            );
            reject(failure);
            fail(attach(error));
          }, 15000);
        }),
      ]);
    } finally {
      clearTimeout(timer);
    }
  };
  return {
    pid: child.pid,
    role,
    get imageBinding() {
      return imageBinding.snapshot();
    },
    get cwdObservation() {
      return cwdObservation.snapshot();
    },
    get tcpObservation() {
      return tcpObservation.snapshot();
    },
    wfp: () => wfpObservation.wait(),
    get gitCapture() {
      return {
        stdout: {
          available: false,
          reason: "Inherited real NUL output handle",
        },
        stderr: {
          hex: Buffer.concat(rawCapture).toString("hex"),
          available: rawComplete || rawBytes > 0,
          complete:
            rawComplete &&
            !rawPartial &&
            !rawTruncated &&
            !captureTruncated &&
            !nativeDiagnosticInvalid &&
            !diagnosticPending.length,
          truncated: rawTruncated || captureTruncated,
        },
      };
    },
    get exited() {
      return exit !== undefined;
    },
    get refused() {
      return error !== undefined;
    },
    drainRefused: async () => {
      need(rootedLaunch && error);
      await bounded(closed);
      return attach(error);
    },
    next: async () => {
      if (error) throw attach(error);
      if (cursor < rows.length) return rows[cursor++];
      if (exit) {
        reject(new Error("Missing native record"), "eof");
        throw attach(error);
      }
      const value = await bounded(
        new Promise((resolve, fail) => pending.push({ resolve, reject: fail })),
      );
      if (error) throw attach(error);
      cursor++;
      return value;
    },
    send: (value) => {
      if (exit && !error) reject(new Error("Native stream ended"), "eof");
      if (error) throw attach(error);
      need(
        /^[RAGFWQNS]$/u.test(value) ||
          (rootedLaunch &&
            ["read", "edit"].includes(args[0]) &&
            /^[OTU]$/u.test(value)),
      );
      child.stdin.write(value);
    },
    sendTarget: (started) => {
      if (error) throw attach(error);
      need(rootedHolder && !targetSent && !exit);
      normalizeWindowsIdentity(started.child);
      need(
        [started.process, started.thread, started.child.creationTime].every(
          (value) =>
            /^[1-9][0-9]{0,19}$/u.test(value) &&
            BigInt(value) <= 0xffffffffffffffffn,
        ),
      );
      targetSent = true;
      child.stdin.write(
        `T${started.process} ${started.child.creationTime} ${started.thread} ${started.child.pid}\n`,
      );
    },
    stop: endInput,
    checkGitReceipt: (check) => {
      if (error) throw attach(error);
      try {
        return check();
      } catch (diagnosticError) {
        diagnostics("windows-helper-receipt", { exception: diagnosticError });
        reject(new Error("Rejected fixed Git receipt"), "git-receipt");
        throw attach(error);
      }
    },
    finish: async (count, expected = 0) => {
      const result = await bounded(closed);
      if (error) throw attach(error);
      if (result.code !== expected || result.signal)
        throw attach(
          Object.assign(new Error("Native helper failed"), {
            ...result,
            profileUnowned:
              role === "profile-create" &&
              result.code === 78 &&
              rows.length === 1 &&
              parsed === bytes.length &&
              rows[0].created === false &&
              rows[0].profileUnowned === true &&
              !stderr.length,
          }),
        );
      if (!(
        parsed === bytes.length &&
        rows.length === count &&
        cursor === count &&
        !stderr.length
      )) {
        reject(
          Object.assign(new Error("Incomplete native stream"), {
            nativeStreamInvalid: true,
          }),
          rows.length < count ? "eof" : "record-count",
        );
        throw attach(error);
      }
      return rows;
    },
  };
}

function assertNullProbeCase(caseId) {
  need(
    caseId === "shadow" ||
      caseId === "no-shadow-control" ||
      caseId === "no-shadow-mapped" ||
      caseId === "workspace-rooted",
  );
}

/** One diagnostic lifecycle. Injected effects test refusals, never native proof. */
export async function observeWindowsGitNullProbe(effects) {
  const { caseId = "shadow" } = effects;
  assertNullProbeCase(caseId);
  const probe = {
    purpose: "diagnostic-only",
    caseId,
    hypothesis:
      caseId === "shadow"
        ? "controller-read-only-shadow"
        : caseId === "workspace-rooted"
          ? "unshadowed-held-workspace-root"
          : caseId === "no-shadow-mapped"
            ? "unshadowed-proven-drive-links"
            : "unshadowed-directory",
    events: [],
    git: null,
    reusable: false,
    imageBinding: imageBindingCapture().snapshot(),
    cwdObservation: cwdCapture().snapshot(),
  };
  let operation = "allocate",
    refusal;
  try {
    if (effects.acquisitions) probe.start = effects.acquisitions;
    probe.start = await effects.start((row) => probe.events.push(row));
    operation = "bind";
    probe.binding = await effects.bind((row) => probe.events.push(row));
    need(typeof probe.binding.bound === "boolean");
    operation = "git";
    const release =
      probe.binding.bound &&
      (caseId === "shadow" ||
        (caseId === "no-shadow-mapped" &&
          probe.binding.mappedSetup === true &&
          probe.binding.setSucceeded === true) ||
        (caseId === "workspace-rooted" &&
          probe.binding.workspaceReady === true &&
          probe.binding.mappedSetup === true &&
          probe.binding.setSucceeded === true &&
          probe.binding.payloadAssignment?.setSucceeded === true &&
          probe.binding.gitAssignment?.setSucceeded === true &&
          sameWindowsIdentity(
            probe.binding.payloadAssignment.identity,
            probe.start.receipt.child,
          ) &&
          sameWindowsIdentity(
            probe.binding.gitAssignment.identity,
            probe.start.gitStarted.child,
          ) &&
          !sameWindowsIdentity(
            probe.binding.payloadAssignment.identity,
            probe.binding.gitAssignment.identity,
          )));
    probe.git = await effects.execute(release);
    need(
      typeof probe.git.ran === "boolean" &&
        probe.git.ran === release &&
        (probe.git.ran
          ? Number.isInteger(probe.git.exitCode)
          : probe.git.exitCode === null),
    );
    probe.failure =
      probe.events.find(({ event }) => event === "null-error") ?? null;
    if (!probe.failure && probe.git.exitCode)
      probe.failure = { operation, exitCode: probe.git.exitCode };
  } catch (error) {
    nativeException("windows-null-probe", error);
    refusal = error;
    probe.failure = probe.events.find(
      ({ event }) => event === "null-error",
    ) ?? {
      operation,
      message: error.message,
      code: error.code ?? null,
      stderr: error.stderr ?? null,
    };
  } finally {
    try {
      const cleanup = await effects.retire((row) => probe.events.push(row));
      need(
        cleanup.independent === true &&
          cleanup.jobEmpty === true &&
          cleanup.processRetired === true &&
          cleanup.resourcesClosed === true &&
          cleanup.endpointAbsent === true &&
          cleanup.holderRetired === true &&
          cleanup.outsideUnchanged === true,
      );
      probe.cleanup = { ...cleanup, status: "SETTLED" };
      probe.reusable = true;
    } catch (error) {
      nativeException("windows-null-probe-cleanup", error);
      probe.cleanup = {
        status: "UNCERTAIN",
        message: error.message,
        code: error.code ?? null,
        stderr: error.stderr ?? null,
      };
    }
  }
  probe.imageBinding = refusal?.imageBinding ?? probe.imageBinding;
  probe.cwdObservation = refusal?.cwdObservation ?? probe.cwdObservation;
  return probe;
}

/** Explicit matching-worker effects. Portable callers receive prerequisite refusal. */
export async function runWindowsFeasibility(
  dispatch,
  observed,
  { nullDeviceProbe = false, nullDeviceProbeCase = "shadow" } = {},
) {
  assertNullProbeCase(nullDeviceProbeCase);
  const definitions = feasibilityCapabilities("win32").filter(
    ({ tier }) => tier === "native",
  );
  const unavailable = (cause) =>
    unavailableFeasibilityResults("win32", cause).filter(({ capability }) =>
      definitions.some(({ id }) => id === capability),
    );
  const notStarted = (cause) =>
    nullDeviceProbe
      ? {
          purpose: "diagnostic-only",
          caseId: nullDeviceProbeCase,
          events: [],
          git: { ran: false, exitCode: null },
          imageBinding: imageBindingCapture().snapshot(),
          cwdObservation: cwdCapture().snapshot(),
          failure: cause,
          cleanup: { status: "NOT_RUN" },
          reusable: true,
        }
      : unavailable(cause);
  if (!(
    process.platform === "win32" &&
    process.arch === "x64" &&
    process.env.CI === "true" &&
    process.env.GITHUB_ACTIONS === "true" &&
    process.env.RUNNER_ENVIRONMENT === "github-hosted" &&
    process.env.RUNNER_OS === "Windows"
  ))
    return notStarted({
      code: "prerequisite-unavailable",
      detail:
        "Windows feasibility requires a matching hosted Windows x64 CI worker.",
    });
  need(
    dispatch.platform === "win32" &&
      dispatch.expectedSha === observed.checkoutSha &&
      observed.os === "win32" &&
      observed.architecture === "x64",
  );
  let env;
  try {
    env = windowsFeasibilityCallerEnvironment(process.env);
  } catch (error) {
    nativeException("win32/feasibility.js:exception", error);
    return notStarted(windowsFeasibilityCause("caller-prerequisites", error));
  }
  const tools = windowsFeasibilityToolEnvironment(process.env);
  const command = async (image, args, options = {}) => {
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
    }, options.timeout ?? 30000);
    try {
      return await execute(image, args, {
        timeout: 30000,
        maxBuffer: 65536,
        windowsHide: true,
        env: tools,
        ...options,
      });
    } catch (error) {
      nativeException("win32/feasibility.js:exception", error);
      error.timedOut ??=
        timedOut ||
        ["ETIMEDOUT", "ERR_FEASIBILITY_DEADLINE"].includes(error.code);
      throw error;
    } finally {
      clearTimeout(timer);
    }
  };
  let stage = "checkout",
    root,
    helper,
    nonce,
    profileAttempted = false,
    created = false,
    outsideBaseline,
    components = [],
    records = [],
    servers = [],
    active = [],
    workspaces = [];
  const started = Date.now();
  let diagnostic, probeSession, workspaceCleanup, workspaceRefusal;
  const native = async (role, ...args) => {
    const session = windowsFeasibilityHelperSession(
      helper,
      root,
      nonce,
      env,
      role,
      args,
    );
    active.push(session);
    const row = await session.next();
    if (row.verifier) {
      normalizeWindowsIdentity(row.verifier);
      need(row.verifier.pid === session.pid);
    }
    await session.finish(1);
    active.splice(active.indexOf(session), 1);
    return row;
  };
  const persist = (name, value) =>
    durable(path.join(root, "control", `${name}.json`), JSON.stringify(value));
  const files = (...names) => native("files", ...names);
  const absent = async (name) => {
    try {
      await lstat(path.join(root, name));
      throw new Error("Owned name survived cleanup");
    } catch (error) {
      nativeException("win32/feasibility.js:exception", error);
      if (error.code !== "ENOENT") throw error;
    }
  };
  const cleanup = (witness, began) => ({
    status: "PASS",
    independent: true,
    emergency: false,
    elapsedMs: Date.now() - began,
    witnessSha256: hash(witness),
    cause: null,
  });
  const result = async (id, evidence, cleanupRecord, elapsedMs) => {
    const began = Date.now() - elapsedMs;
    const definition = definitions.find(
      ({ id: capability }) => capability === id,
    );
    need(definition && elapsedMs <= 120000);
    const outsideAfter = await files("outside\\sentinel");
    need(hash(outsideBaseline) === hash(outsideAfter));
    const witnessed = {
      ...evidence,
      outsideBefore: outsideBaseline,
      outsideAfter,
    };
    await persist(id.replaceAll(".", "-"), witnessed);
    records.push({
      capability: id,
      status: "PASS",
      cause: null,
      elapsedMs: Date.now() - began,
      components: [...components],
      evidence: {
        ready: true,
        positiveControl: true,
        attemptAcknowledged: true,
        independent: true,
        outcome: definition.outcome,
        observationSha256: hash(witnessed),
        sentinelsBeforeSha256: hash(evidence.before ?? outsideBaseline),
        sentinelsAfterSha256: hash(evidence.after ?? outsideAfter),
      },
      cleanup: cleanupRecord,
    });
  };
  const observerArgs = (receipt, caseId, thread = "0") => [
    String(receipt.owner.pid),
    receipt.owner.creationTime,
    receipt.job,
    receipt.process,
    receipt.child.creationTime,
    thread,
    caseId,
  ];
  const launch = async (caseId, image, args, hooks) => {
    if (hooks)
      need(
        windowsFeasibilityWorkspaceLaunch("launch", [caseId, image, ...args]),
      );
    const session = windowsFeasibilityHelperSession(
      helper,
      root,
      nonce,
      env,
      "launch",
      [caseId, image, ...args],
    );
    active.push(session);
    const receipt = await session.next();
    need(
      receipt.event === "suspended" &&
        receipt.owner?.pid === session.pid &&
        /^S-1-15-2-(?:[0-9]+-){6}[0-9]+$/u.test(receipt.sid) &&
        ["job", "process", "thread"].every((key) =>
          /^[1-9][0-9]*$/u.test(receipt[key]),
        ),
    );
    normalizeWindowsIdentity(receipt.owner);
    normalizeWindowsIdentity(receipt.child);
    const run = { session, receipt, caseId, admission: null };
    hooks?.acquired(run);
    const admission = await native(
      "inspect",
      ...observerArgs(receipt, caseId, receipt.thread),
    );
    const component = components.find(
      ({ name }) =>
        name ===
        `windows-feasibility-${caseId === "argv" ? "argv-fixture" : "helper"}`,
    );
    need(
      admission.admitted === true &&
        admission.suspended === true &&
        admission.capabilities === 0 &&
        admission.sid === receipt.sid &&
        sameWindowsIdentity(admission.child, receipt.child) &&
        !sameWindowsIdentity(admission.verifier, receipt.owner) &&
        hash(admission.image) === hash(receipt.image) &&
        admission.image.private === false &&
        admission.image.sha256 === component.sha256,
    );
    await persist(windowsFeasibilityAdmissionName(caseId), {
      receipt,
      admission,
    });
    run.admission = admission;
    if (hooks) await hooks.beforeRelease(run);
    hooks?.releasingPayload();
    session.send("R");
    return run;
  };
  const finishLaunch = async (run, count, settle = true) => {
    const witness = settle
      ? await native("settle", ...observerArgs(run.receipt, run.caseId))
      : null;
    if (settle) need(witness.retired === true && witness.jobEmpty === true);
    run.session.send("Q");
    need((await run.session.next()).event === "closed");
    await run.session.finish(count + 2);
    active.splice(active.indexOf(run.session), 1);
    return witness;
  };
  const recovery = async (receipt, caseId, expected) => {
    const session = windowsFeasibilityHelperSession(
      helper,
      root,
      nonce,
      env,
      "recover",
      observerArgs(receipt, caseId),
    );
    active.push(session);
    const ready = await session.next();
    normalizeWindowsIdentity(ready.verifier);
    need(
      ready.event === "recovery-ready" &&
        ready.verifier.pid === session.pid &&
        ready.members?.length === 2 &&
        expected.every(
          (identity) =>
            !sameWindowsIdentity(identity, ready.verifier) &&
            ready.members.some((member) =>
              sameWindowsIdentity(member, identity),
            ),
        ),
    );
    await persist(`${caseId}-recovery`, { receipt, ready });
    return async () => {
      session.send("A");
      const settled = await session.next();
      need(settled.retired === true && settled.jobEmpty === true);
      await session.finish(2);
      active.splice(active.indexOf(session), 1);
      return { ...settled, members: ready.members };
    };
  };
  const stopControls = async () => {
    const began = Date.now();
    await Promise.all(
      servers.map(
        ({ server }) =>
          new Promise((resolve, reject) =>
            server.close((error) => (error ? reject(error) : resolve())),
          ),
      ),
    );
    const observations = [];
    for (const control of servers)
      observations.push(
        await native("control-closed", control.kind, control.address),
      );
    need(
      observations.length === servers.length &&
        observations.every((v) => v.closed === true),
    );
    servers = [];
    return cleanup(observations, began);
  };
  try {
    need(
      (
        await command("git.exe", ["rev-parse", "HEAD"], { cwd: REPOSITORY })
      ).stdout.trim() === dispatch.expectedSha,
    );
    stage = "compiler-prerequisites";
    let compiler;
    try {
      compiler = (await command("where.exe", ["cl.exe"])).stdout
        .trim()
        .split(/\r?\n/u)[0];
    } catch (error) {
      nativeException("win32/feasibility.js:exception", error);
      if (error.code !== 1 || error.signal || error.killed) throw error;
      throw Object.assign(
        new Error("Native compiler unavailable", { cause: error }),
        { code: 78 },
      );
    }
    need(path.win32.isAbsolute(compiler));
    const sdkVersion = process.env.WindowsSDKVersion?.replace(/\\$/u, "");
    if (
      !sdkVersion ||
      !/^[0-9.]+$/u.test(sdkVersion) ||
      !process.env.WindowsSdkDir
    )
      throw Object.assign(new Error("Native SDK unavailable"), { code: 78 });
    const sdkHeader = await regular(
      path.join(
        process.env.WindowsSdkDir,
        "Include",
        sdkVersion,
        "um",
        "Windows.h",
      ),
    );
    const compilerBytes = await regular(compiler);
    let compilerBanner;
    try {
      compilerBanner = await command(compiler, ["/Bv"]);
    } catch (error) {
      nativeException("win32/feasibility.js:exception", error);
      if (error.code !== 2 || error.signal || error.killed) throw error;
      compilerBanner = error;
    }
    const compilerVersion = /Compiler Version ([0-9.]+) for x64/u.exec(
      `${compilerBanner.stdout}\n${compilerBanner.stderr}`,
    )?.[1];
    need(compilerVersion);
    components = [
      {
        role: "tool",
        name: "msvc",
        version: compilerVersion,
        sha256: digest(compilerBytes),
      },
      {
        role: "tool",
        name: "windows-sdk-header",
        version: sdkVersion,
        sha256: digest(sdkHeader),
      },
    ];
    for (const [header, directory] of Object.entries(WFP_SDK_HEADERS))
      components.push({
        role: "tool",
        name: `windows-wfp-${header}`,
        version: sdkVersion,
        sha256: digest(
          await regular(
            path.join(
              process.env.WindowsSdkDir,
              "Include",
              sdkVersion,
              directory,
              header,
            ),
          ),
        ),
      });
    stage = "exclusive-fixture";
    need(
      process.env.RUNNER_TEMP && path.win32.isAbsolute(process.env.RUNNER_TEMP),
    );
    root = await realpath(
      await mkdtemp(
        path.join(process.env.RUNNER_TEMP, "native-feasibility-win32-"),
      ),
    );
    nonce = randomBytes(16).toString("hex");
    for (const name of ["build", "control", "storage", "outside", "workspace"])
      await mkdir(path.join(root, name));
    helper = path.join(root, "build", "helper.exe");
    stage = "native-build";
    components.push({
      role: "tool",
      name: "windows-feasibility-source",
      version: "1",
      sha256: digest(await regular(path.join(SOURCE, "feasibility-helper.c"))),
    });
    const sdkInclude = path.join(
      process.env.WindowsSdkDir,
      "Include",
      sdkVersion,
    );
    const buildPins = new Map([
      [compiler, digest(compilerBytes)],
      [path.join(sdkInclude, "um", "Windows.h"), digest(sdkHeader)],
      ...Object.entries(WFP_SDK_HEADERS).map(([header, directory]) => [
        path.join(sdkInclude, directory, header),
        components.find(({ name }) => name === `windows-wfp-${header}`).sha256,
      ]),
    ]);
    for (const name of [
      "feasibility-helper.c",
      "argv-fixture.c",
      "feasibility-null-probe.h",
    ])
      buildPins.set(
        path.join(SOURCE, name),
        digest(await regular(path.join(SOURCE, name))),
      );
    await attemptNativeBuilds(
      "windows-feasibility-builds",
      [
        ["feasibility-helper.c", "helper"],
        ["argv-fixture.c", "argv-fixture"],
      ].map(([source, target]) => ({
        name: target,
        run: () =>
          command(
            compiler,
            [
              "/nologo",
              "/std:c17",
              "/O2",
              "/W4",
              "/MT",
              "/Brepro",
              path.join(SOURCE, source),
              `/Fo${path.join(root, "build", `${target}.obj`)}`,
              `/Fe${path.join(root, "build", `${target}.exe`)}`,
              "/link",
              "/INCREMENTAL:NO",
              ...(target === "helper" ? ["fwpuclnt.lib"] : []),
            ],
            { cwd: path.join(root, "build") },
          ),
      })),
      {
        verify: async () => {
          for (const [file, pin] of buildPins)
            need(digest(await regular(file)) === pin);
        },
      },
    );
    for (const target of ["helper", "argv-fixture"]) {
      const bytes = await regular(path.join(root, "build", `${target}.exe`));
      const imports = windowsFeasibilityImports(bytes);
      if (target === "helper") {
        need(imports.some((dll) => dll.toLowerCase() === "fwpuclnt.dll"));
        components.push({
          role: "tool",
          name: "windows-wfp-loader",
          version: "installed",
          sha256: digest(
            await regular(
              path.join(process.env.SystemRoot, "System32", "fwpuclnt.dll"),
            ),
          ),
        });
      }
      components.push({
        role: "helper",
        name: `windows-feasibility-${target}`,
        version: "1",
        sha256: digest(bytes),
      });
    }
    for (const [file, name] of [
      [path.join(SOURCE, "feasibility-helper.c"), "windows-feasibility-source"],
      ...Object.entries(WFP_SDK_HEADERS).map(([header, directory]) => [
        path.join(
          process.env.WindowsSdkDir,
          "Include",
          sdkVersion,
          directory,
          header,
        ),
        `windows-wfp-${header}`,
      ]),
    ])
      need(
        digest(await regular(file)) ===
          components.find((value) => value.name === name).sha256,
      );
    stage = "synthetic-git";
    const preparedGit = await prepareWindowsFeasibilityGit(
      { root, nonce, systemRoot: process.env.SystemRoot, components },
      {
        command,
        read: regular,
        write: durable,
        inspect: windowsFeasibilityImports,
      },
    );
    const intent = JSON.stringify({
      nonce,
      profile: windowsFeasibilityProfileName(nonce),
      candidateSha: observed.checkoutSha,
    });
    await durable(path.join(root, "control", "intent.json"), intent);
    stage = "private-profile";
    need((await native("seal")).sealed === true);
    profileAttempted = true;
    const profile = await native("profile-create", digest(Buffer.from(intent)));
    need(profile.created === true);
    created = true;
    const profileWitness = await native("profile-observe");
    need(
      profileWitness.profileObserved === true &&
        profileWitness.sid === profile.sid,
    );
    need((await native("grants", "read")).granted === true);
    outsideBaseline = await files("outside\\sentinel");
    need(
      outsideBaseline.length === 1 &&
        outsideBaseline[0].private &&
        outsideBaseline[0].sha256 === digest(Buffer.from(nonce)),
    );

    const gitNames = [
      ...preparedGit.manifest.map(({ name }) => `build\\${name}`),
      "workspace",
      "workspace\\.git",
      "workspace\\.git\\runner-global.conf",
      "workspace\\.git\\config",
    ];
    const gitFiles = async () => {
      const rows = [];
      for (let offset = 0; offset < gitNames.length; offset += 8)
        rows.push(...(await files(...gitNames.slice(offset, offset + 8))));
      return rows;
    };
    const workspaceOwner = (caseId) => {
      const owner = createWindowsFeasibilityWorkspace(caseId, {
        normalizeWindowsIdentity,
        sameWindowsIdentity,
        native,
        persist,
        observerArgs,
        absent,
        files,
        outsideBaseline,
        gitFiles,
        holder: (args) => {
          const session = windowsFeasibilityHelperSession(
            helper,
            root,
            nonce,
            env,
            "null-map",
            args,
          );
          active.push(session);
          return session;
        },
        releaseSession: (session) => active.splice(active.indexOf(session), 1),
      });
      workspaces.push(owner);
      return owner;
    };
    const closeWorkspaceLaunch = async (run, next, count, limit, events) => {
      let refusal;
      try {
        if (!run.session.refused) {
          run.session.send("Q");
          for (;;) {
            need(count() < limit);
            const row = await next();
            if (row.event === "closed") break;
            need(events.includes(row.event));
          }
          await run.session.finish(count());
        } else refusal = await run.session.drainRefused();
      } catch (error) {
        if (!run.session.refused) throw error;
        refusal = await run.session.drainRefused();
      }
      need(
        !refusal?.nativeDiagnosticInvalid &&
          !windowsFeasibilityDiagnostics(refusal?.stderr)?.cleanup,
      );
      active.splice(active.indexOf(run.session), 1);
    };
    if (nullDeviceProbe) {
      stage = "null-device-probe";
      const rooted = nullDeviceProbeCase === "workspace-rooted",
        workspace = rooted ? workspaceOwner("null-probe") : null;
      let run,
        mapper,
        binding,
        target,
        controllerBefore,
        controllerAfter,
        actionSent = false,
        gitRan = null,
        gitResult,
        before,
        mapRows = 0,
        runRows = 1;
      const mapRowLimit = nullDeviceProbeCase === "no-shadow-mapped" ? 64 : 32;
      const nextRun = async () => {
        const row = await run.session.next();
        runRows++;
        return row;
      };
      const completeGit = async () => {
        const release = await nextRun();
        need(release.event === "git-probe-release");
        need(typeof release.ran === "boolean");
        gitRan = release.ran;
        gitResult = await nextRun();
        need(
          gitResult.event === "git-probe-result" &&
            gitResult.ran === release.ran,
        );
        return gitResult;
      };
      diagnostic = await observeWindowsGitNullProbe({
        caseId: nullDeviceProbeCase,
        acquisitions: workspace?.acquisitions,
        start: async (capture) => {
          before = await gitFiles();
          const trusted = workspace
            ? await workspace.prepare(before, preparedGit.manifest.length)
            : null;
          workspace?.launching();
          run = await launch(
            "null-probe",
            helper,
            [
              "null-probe",
              root,
              nonce,
              "0",
              "unused",
              nullDeviceProbeCase,
              ...(rooted ? [trusted.identity, trusted.nativePathUtf16] : []),
            ],
            workspace
              ? {
                  acquired: (partial) => {
                    run = partial;
                    probeSession = partial.session;
                    workspace.acquired(partial);
                  },
                  beforeRelease: (partial) =>
                    workspace.beforeRelease(partial, capture),
                  releasingPayload: workspace.releasingPayload,
                }
              : undefined,
          );
          probeSession = run.session;
          need((await nextRun()).event === "ready");
          await workspace?.beforeGit();
          run.session.send("A");
          need((await nextRun()).operation === "git-status");
          const gitStarted = await nextRun();
          target = gitStarted.child;
          workspace?.startedGit(gitStarted);
          const args = [
            String(run.receipt.owner.pid),
            run.receipt.owner.creationTime,
            run.receipt.job,
            gitStarted.process,
            gitStarted.child.creationTime,
            gitStarted.thread,
            "git",
            String(gitStarted.owner.pid),
            gitStarted.owner.creationTime,
          ];
          const admission = await native("git-inspect", ...args);
          workspace?.admittedGit(admission);
          run.session.checkGitReceipt(() =>
            validateWindowsFeasibilityGitStart({
              root,
              prepared: preparedGit,
              receipt: run.receipt,
              started: gitStarted,
              files: before,
              admission,
              caseId: rooted ? "workspace-rooted" : null,
              workspaceProof: workspace?.proof ?? null,
            }),
          );
          need(hash(await gitFiles()) === hash(before));
          if (!rooted)
            await persist(windowsFeasibilityAdmissionName("null-probe", true), {
              receipt: run.receipt,
              gitStarted,
              admission,
            });
          if (!rooted)
            mapper = windowsFeasibilityHelperSession(
              helper,
              root,
              nonce,
              env,
              "null-map",
              [...args, nullDeviceProbeCase],
            );
          if (!rooted) active.push(mapper);
          return {
            ...workspace?.acquisitions,
            receipt: run.receipt,
            gitStarted,
            admission,
            files: before,
            outside: outsideBaseline,
          };
        },
        bind: async (capture) => {
          if (workspace) return workspace.assignGit(capture);
          for (;;) {
            need(mapRows < mapRowLimit);
            const row = await mapper.next();
            mapRows++;
            capture(row);
            if (row.event === "null-controller" && row.phase === "before")
              controllerBefore = row;
            if (row.event === "null-bound") {
              need(row.caseId === nullDeviceProbeCase);
              normalizeWindowsIdentity(row.owner);
              need(row.owner.pid === mapper.pid);
              binding = row;
              return row;
            }
          }
        },
        execute: async (release) => {
          workspace?.releasingGit(release);
          run.session.send(
            release && nullDeviceProbeCase !== "no-shadow-control" ? "G" : "N",
          );
          actionSent = true;
          return completeGit();
        },
        retire: async (capture) => {
          if (workspace)
            return workspace.retire(
              {
                cancelPayload: async () => {
                  run.session.send("N");
                  need((await nextRun()).event === "payload-canceled");
                },
                cancelGit: async () => {
                  run.session.send("N");
                  actionSent = true;
                  await completeGit();
                },
                closePayload: () =>
                  closeWorkspaceLaunch(run, nextRun, () => runRows, 8, [
                    "ready",
                    "attempt",
                    "git-started",
                    "git-probe-release",
                    "git-probe-result",
                  ]),
                complete: () => Boolean(gitResult),
              },
              capture,
            );
          if (!run || !mapper)
            throw new Error(
              "Partial acquisition lacks complete independent settlement",
            );
          if (!actionSent) {
            run.session.send("N");
            actionSent = true;
            await completeGit();
          }
          need(gitResult && binding);
          const retired = await finishLaunch(run, 5);
          const gitRetired = await native(
            "process-retired",
            String(target.pid),
            target.creationTime,
          );
          const outsideAfter = await files("outside\\sentinel");
          capture({ event: "null-outside", after: outsideAfter });
          mapper.send("Q");
          let resources;
          for (;;) {
            need(mapRows < mapRowLimit);
            const row = await mapper.next();
            mapRows++;
            capture(row);
            if (row.event === "null-controller" && row.phase === "after")
              controllerAfter = row;
            if (row.event === "null-retired") {
              resources = row;
              break;
            }
          }
          await mapper.finish(mapRows);
          active.splice(active.indexOf(mapper), 1);
          const holder = await native(
            "process-retired",
            String(binding.owner.pid),
            binding.owner.creationTime,
          );
          await absent("workspace\\null-endpoint");
          need(
            controllerBefore &&
              controllerAfter &&
              hash({ ...controllerBefore, phase: null }) ===
                hash({ ...controllerAfter, phase: null }),
          );
          need(
            hash(await gitFiles()) === hash(before) &&
              hash(outsideAfter) === hash(outsideBaseline),
          );
          return {
            independent: true,
            jobEmpty: retired.jobEmpty,
            processRetired: retired.retired && gitRetired.retired,
            resourcesClosed: resources.resourcesClosed,
            endpointAbsent: true,
            holderRetired: holder.retired,
            outsideUnchanged: true,
          };
        },
      });
      diagnostic.git ??= gitResult ?? {
        ran: rooted && !actionSent ? false : gitRan,
        exitCode: null,
      };
      if (run) diagnostic.git.capture = run.session.gitCapture;
      if (run) diagnostic.imageBinding = run.session.imageBinding;
      if (run) diagnostic.cwdObservation = run.session.cwdObservation;
      if (!diagnostic.reusable)
        throw new Error("Diagnostic resources remain uncertain; exclude reuse");
      need((await native("profile-delete")).deleted === true);
      need((await native("profile-absent")).absent === true);
      created = false;
      if (rooted) diagnostic.cleanup.profileRetired = true;
      diagnostic.components = components;
      diagnostic.fixture = {
        root,
        nonce,
        ...(rooted ? { profile: windowsFeasibilityProfileName(nonce) } : {}),
      };
      return diagnostic;
    }

    stage = "literal-argv";
    let began = Date.now();
    const argv = await launch(
      "argv",
      path.join(root, "build", "argv-fixture.exe"),
      WINDOWS_LITERAL_ARGUMENTS,
    );
    const actual = await argv.session.next(),
      expected = WINDOWS_LITERAL_ARGUMENTS.map((arg) => {
        let value = "";
        for (let i = 0; i < arg.length; i++)
          value += arg.charCodeAt(i).toString(16).padStart(4, "0");
        return value;
      });
    need(JSON.stringify(actual) === JSON.stringify({ argvUtf16: expected }));
    const argvCleanupStart = Date.now(),
      retired = await finishLaunch(argv, 1);
    await result(
      "launch.argv",
      { admission: argv.admission, actual, retired },
      cleanup(retired, argvCleanupStart),
      Date.now() - began,
    );

    stage = "outside-controls";
    for (const kind of ["tcp", "pipe"]) {
      const control = {
        kind,
        address: "",
        accepted: 0,
        server: net.createServer((socket) => {
          control.accepted++;
          let bytes = Buffer.alloc(0);
          socket.setTimeout(5000, () => socket.destroy());
          socket.on("error", () => {});
          socket.on("data", (chunk) => {
            bytes = Buffer.concat([bytes, chunk]);
            if (bytes.length === 32 && bytes.toString() === nonce)
              socket.end(bytes);
            else if (bytes.length >= 32) socket.destroy();
          });
        }),
      };
      await new Promise((resolve, reject) => {
        control.server.once("error", reject);
        if (kind === "tcp") control.server.listen(0, "127.0.0.1", resolve);
        else
          control.server.listen(
            `\\\\.\\pipe\\native-feasibility-${nonce}`,
            resolve,
          );
      });
      control.address =
        kind === "tcp"
          ? String(control.server.address().port)
          : `\\\\.\\pipe\\native-feasibility-${nonce}`;
      servers.push(control);
    }
    const bundles = [];
    began = Date.now();
    for (const mode of ["read", "edit"]) {
      stage = `${mode}-access`;
      need((await native("grants", mode)).granted === true);
      const before = await files(...SENTINELS);
      const gitBefore = await gitFiles();
      need(
        before.length === 4 &&
          before.every((v, i) => validDigest(v.sha256) && v.private === i >= 2),
      );
      const writeControls = await native("write-controls");
      need(
        writeControls.writesReady === true &&
          writeControls.indexMutationReady === true &&
          hash(await files(...SENTINELS)) === hash(before),
      );
      const tcpEndpoint = servers[0].address;
      const controlsBefore = [];
      for (const c of servers)
        controlsBefore.push(await native("control", c.kind, c.address));
      need(controlsBefore.every((v) => v.ready === true));
      const counts = servers.map((c) => c.accepted);
      const heldWorkspace = workspaceOwner(mode);
      let run,
        runRows = 1,
        complete = false;
      const nextRun = async () => {
        const row = await run.session.next();
        runRows++;
        return row;
      };
      const operations = [];
      let gitStart;
      workspaceRefusal = heldWorkspace;
      workspaceCleanup = () => {
        workspaceCleanup = null;
        return heldWorkspace.retire({
          cancelPayload: async () => {
            run.session.send("N");
            need((await nextRun()).event === "payload-canceled");
          },
          closePayload: async () => {
            await closeWorkspaceLaunch(run, nextRun, () => runRows, 24, [
              "ready",
              "attempt",
              "completed",
              "git-started",
              "tcp-observer-ready",
              "tcp-attribution",
            ]);
            if (complete) need(runRows === 24);
          },
          complete: () => complete,
        });
      };
      const trusted = await heldWorkspace.prepare(
        gitBefore,
        preparedGit.manifest.length,
      );
      heldWorkspace.launching();
      run = await launch(
        mode,
        helper,
        [
          "bundle",
          root,
          nonce,
          tcpEndpoint,
          servers[1].address,
          mode,
          trusted.identity,
          trusted.nativePathUtf16,
        ],
        {
          acquired: (partial) => {
            run = partial;
            heldWorkspace.acquired(partial);
          },
          beforeRelease: heldWorkspace.beforeRelease,
          releasingPayload: heldWorkspace.releasingPayload,
        },
      );
      need((await nextRun()).event === "ready");
      await heldWorkspace.beforeGit();
      run.session.send("A");
      for (const operation of OPERATIONS) {
        const checkReceipt = (check) =>
          operation === "git-status"
            ? run.session.checkGitReceipt(check)
            : check();
        let attempt, completed;
        try {
          attempt = await nextRun();
          checkReceipt(() => {
            need(
              attempt.event === "attempt" && attempt.operation === operation,
            );
          });
          if (operation === "git-status") {
            const started = await nextRun();
            run.session.checkGitReceipt(() => {
              normalizeWindowsIdentity(started.child);
              need(
                started.event === "git-started" &&
                  sameWindowsIdentity(started.owner, run.receipt.child) &&
                  ["process", "thread"].every((key) =>
                    /^[1-9][0-9]*$/u.test(started[key]),
                  ),
              );
            });
            heldWorkspace.startedGit(started);
            const admission = await native(
              "git-inspect",
              String(run.receipt.owner.pid),
              run.receipt.owner.creationTime,
              run.receipt.job,
              started.process,
              started.child.creationTime,
              started.thread,
              "git",
              String(started.owner.pid),
              started.owner.creationTime,
            );
            heldWorkspace.admittedGit(admission);
            run.session.checkGitReceipt(() => {
              validateWindowsFeasibilityGitStart({
                root,
                prepared: preparedGit,
                receipt: run.receipt,
                started,
                files: gitBefore,
                admission,
                caseId: mode,
                workspaceProof: heldWorkspace.proof,
              });
            });
            const currentGitFiles = await gitFiles();
            run.session.checkGitReceipt(() => {
              need(hash(currentGitFiles) === hash(gitBefore));
            });
            gitStart = {
              started,
              admission,
              files: gitBefore,
              invocation: preparedGit.invocation,
            };
            await persist(`${mode}-git-start`, gitStart);
            const assigned = await heldWorkspace.assignGit();
            need(assigned.bound === true);
            heldWorkspace.releasingGit();
            run.session.send("G");
          }
          if (operation === "tcp") {
            run.session.send("O");
            const prepared = await nextRun();
            assertWindowsFeasibilityTcpObserver(
              prepared,
              run.receipt,
              tcpEndpoint,
            );
            run.tcpAttribution = {
              prepared,
              requestedEndpoint: tcpEndpoint,
              pending: true,
            };
            // Persist the actual socket/observer and frozen endpoint before the
            // one original connect. A lost acknowledgment never replays it.
            await persist(`${mode}-tcp-intent`, run.tcpAttribution);
            run.session.send("T");
            const attribution = await nextRun();
            // This acknowledgment permits closure, never another connect or
            // case. Keep the original completion even when attribution fails.
            need(attribution.event === "tcp-attribution");
            run.tcpAttribution = { ...run.tcpAttribution, attribution };
            await persist(`${mode}-tcp-observed`, run.tcpAttribution);
            run.session.send("U");
          }
          completed = await nextRun();
          checkReceipt(() => {
            need(
              completed.event === "completed" &&
                completed.operation === operation,
            );
          });
        } catch (error) {
          nativeException("win32/feasibility.js:exception", error);
          if (operation === "tcp") {
            await observeWindowsFeasibilityWfp(run, persist);
            error.wfpCleanup = run.wfpObservation?.cleanup === "UNCERTAIN";
          }
          throw Object.assign(error, { operation });
        }
        if (operation === "tcp")
          await observeWindowsFeasibilityWfp(run, persist);
        const permitted =
          operation === "inspect" ||
          operation === "git-status" ||
          (mode === "edit" && operation === "edit");
        if (
          !(permitted
            ? completed.error === 0
            : completed.error === (operation === "tcp" ? 10013 : 5))
        )
          throw Object.assign(new Error("Unexpected restricted operation"), {
            operation,
            escape: completed.error === 0,
            wfpCleanup: run.wfpObservation?.cleanup === "UNCERTAIN",
          });
        if (operation === "tcp") {
          try {
            assertWindowsFeasibilityTcpDenial(
              run.tcpAttribution.attribution,
              run.tcpAttribution.prepared,
              run.receipt,
              tcpEndpoint,
              completed.error,
            );
          } catch (error) {
            throw Object.assign(error, { operation });
          }
          run.tcpAttribution.pending = false;
          await persist(`${mode}-tcp-denial`, run.tcpAttribution);
        }
        if (operation === "tcp" && run.wfpObservation?.cleanup === "UNCERTAIN")
          throw Object.assign(
            new Error("WFP observation resources remain unproved"),
            { operation, wfpCleanup: true },
          );
        operations.push({ attempt, completed });
      }
      complete = true;
      const { retirement } = await workspaceCleanup();
      workspaceCleanup = null;
      const after = await files(...SENTINELS);
      need(hash(before) === hash(after));
      need(hash(await gitFiles()) === hash(gitBefore));
      await absent("workspace\\.git\\index.lock");
      need(
        (await readFile(path.join(workspace, "edited.txt"), "utf8")) ===
          (mode === "edit" ? nonce : "before"),
      );
      need(servers.every((c, i) => c.accepted === counts[i]));
      const controlsAfter = [];
      for (const c of servers)
        controlsAfter.push(await native("control", c.kind, c.address));
      need(controlsAfter.every((v) => v.ready === true));
      bundles.push({
        mode,
        admission: run.admission,
        gitStart,
        workspace: heldWorkspace.evidence,
        operations,
        before,
        after,
        writeControls,
        controlsBefore,
        controlsAfter,
        retirement,
        wfpObservation: run.wfpObservation,
        tcpAttribution: run.tcpAttribution,
      });
      workspaceRefusal = null;
    }
    const accessCleanup = await stopControls();
    const before = bundles.map((v) => v.before),
      after = bundles.map((v) => v.after);
    for (const id of ACCESS)
      await result(
        id,
        { bundles, before, after },
        accessCleanup,
        Date.now() - began,
      );

    for (const substitute of [false, true]) {
      stage = substitute ? "storage-substitution" : "private-storage";
      began = Date.now();
      const session = windowsFeasibilityHelperSession(
        helper,
        root,
        nonce,
        env,
        "storage",
      );
      active.push(session);
      const allocated = await session.next();
      need(
        allocated.event === "allocated" && allocated.owner?.pid === session.pid,
      );
      normalizeWindowsIdentity(allocated.owner);
      const initial = await files("storage", "storage\\leaf");
      need(
        initial.length === 2 &&
          initial.every((v) => v.private) &&
          initial[0].identity === allocated.parent &&
          initial[1].identity === allocated.identity &&
          initial[1].sha256 === digest(Buffer.from("owned")),
      );
      let replacement;
      if (substitute) {
        await rename(
          path.join(root, "storage", "leaf"),
          path.join(root, "storage", "saved"),
        );
        need((await native("replacement")).created === true);
        replacement = await files("storage\\leaf", "storage\\saved");
        need(
          replacement[0].identity !== allocated.identity &&
            replacement[1].identity === allocated.identity,
        );
      }
      const cleanupStart = Date.now();
      session.send(substitute ? "S" : "N");
      const cleaned = await session.next();
      need(cleaned.event === "cleanup" && cleaned.removed === !substitute);
      await session.finish(2);
      active.splice(active.indexOf(session), 1);
      const preserved = substitute
        ? await files("storage\\leaf", "storage\\saved")
        : null;
      if (substitute) need(hash(preserved) === hash(replacement));
      else await absent("storage\\leaf");
      if (substitute)
        for (const [index, name] of [
          "storage\\leaf",
          "storage\\saved",
        ].entries()) {
          need(
            (
              await native(
                "remove",
                name,
                preserved[index].identity,
                allocated.parent,
              )
            ).removed === true,
          );
          await absent(name);
        }
      const retirement = await native(
        "process-retired",
        String(allocated.owner.pid),
        allocated.owner.creationTime,
      );
      need(retirement.retired === true);
      const outside = await files("outside\\sentinel");
      need(
        outside[0].private === true &&
          outside[0].sha256 === digest(Buffer.from(nonce)),
      );
      await result(
        substitute ? "storage.substitution" : "storage.private",
        { allocated, initial, replacement, preserved, cleaned, outside },
        cleanup({ retirement, outside }, cleanupStart),
        Date.now() - began,
      );
    }

    for (const kind of ["cancel", "owner-loss", "final-handle-close"]) {
      stage = kind;
      began = Date.now();
      const run = await launch(kind, helper, ["fault", root, nonce]);
      const ready = await run.session.next();
      need(ready.event === "fault-ready");
      normalizeWindowsIdentity(ready.descendant);
      const expected = [run.receipt.child, ready.descendant];
      need(!sameWindowsIdentity(...expected));
      let watcher, watchReady, settled;
      if (kind !== "cancel") {
        watcher = windowsFeasibilityHelperSession(
          helper,
          root,
          nonce,
          env,
          kind === "owner-loss" ? "hold" : "witness",
          observerArgs(run.receipt, kind),
        );
        active.push(watcher);
        watchReady = await watcher.next();
        assertWindowsFeasibilityWitness(
          kind === "owner-loss" ? "holder" : "final",
          watchReady,
          expected,
        );
        need(
          watchReady.owner.pid === watcher.pid &&
            !sameWindowsIdentity(watchReady.owner, run.receipt.owner),
        );
        await persist(`${kind}-witness`, {
          receipt: run.receipt,
          ready,
          watchReady,
        });
      }
      const cancel =
        kind === "cancel" ? await recovery(run.receipt, kind, expected) : null;
      run.session.send("F");
      need((await run.session.next()).event === "fault-ack");
      const cleanupStart = Date.now();
      if (kind === "cancel") {
        settled = await cancel();
        await finishLaunch(run, 2, false);
      } else if (kind === "owner-loss") {
        watcher.send("A");
        need((await watcher.next()).event === "owner-lost");
        await run.session.finish(3, 125);
        active.splice(active.indexOf(run.session), 1);
        const recover = await recovery(watchReady, kind, expected);
        settled = await recover();
        assertWindowsFeasibilityWitness(
          "holder",
          watchReady,
          expected,
          settled,
        );
        watcher.send("W");
        await watcher.finish(2);
        active.splice(active.indexOf(watcher), 1);
      } else {
        watcher.send("A");
        await finishLaunch(run, 2, false);
        watcher.send("W");
        settled = await watcher.next();
        assertWindowsFeasibilityWitness("final", watchReady, expected, settled);
        await watcher.finish(2);
        active.splice(active.indexOf(watcher), 1);
      }
      await result(
        `ownership.${kind}`,
        {
          admission: run.admission,
          ready,
          watchReady: watchReady ?? null,
          settled,
          survivingHolderRequired: kind === "owner-loss",
        },
        cleanup({ settled, watchReady: watchReady ?? null }, cleanupStart),
        Date.now() - began,
      );
    }
    stage = "profile-cleanup";
    const cleanupStart = Date.now();
    need((await native("profile-delete")).deleted === true);
    const removed = await native("profile-absent");
    need(removed.absent === true);
    created = false;
    const profileCleanup = cleanup({ profileWitness, removed }, cleanupStart);
    records = records.map((record) => ({
      ...record,
      cleanup: {
        ...profileCleanup,
        elapsedMs: record.cleanup.elapsedMs + profileCleanup.elapsedMs,
        witnessSha256: hash([record.cleanup, profileCleanup]),
      },
    }));
    need(records.length === definitions.length && active.length === 0);
    return records;
  } catch (error) {
    nativeException("win32/feasibility.js:exception", error);
    if (workspaceCleanup) {
      try {
        await workspaceCleanup();
      } catch (cleanupError) {
        error.workspaceCleanup = {
          message: cleanupError.message,
          code: cleanupError.code ?? null,
          stderr: cleanupError.stderr ?? null,
        };
      }
    }
    if (workspaceRefusal) {
      try {
        await persist(`${workspaceRefusal.caseId}-workspace-refusal`, {
          failure: windowsFeasibilityCause(stage, error),
          workspace: workspaceRefusal.evidence,
          cleanupUncertain:
            workspaceRefusal.possibleEffects || Boolean(error.workspaceCleanup),
        });
      } catch (persistenceError) {
        nativeException("workspace-refusal-persistence", persistenceError);
      }
    }
    const interrupted = active.some((session) => !session.exited);
    const intervention = active.some(
      (session) =>
        !session.exited && ["launch", "hold", "recover"].includes(session.role),
    );
    const unsettledWorkspaces = workspaces.filter(
      (workspace) => workspace.possibleEffects,
    );
    const retained = new Set(
      unsettledWorkspaces.map((workspace) => workspace.holderSession),
    );
    for (const session of active) if (!retained.has(session)) session.stop();
    let cleanupWitness = null;
    const cleanupStart = Date.now();
    // Only an explicit complete no-ownership receipt excludes profile cleanup.
    if (
      error.profileUnowned === true &&
      stage === "private-profile" &&
      !created
    )
      profileAttempted = false;
    // Safe rollback uses only native, nonce/SID-bound receipts and fresh retirement.
    try {
      if (servers.length) await stopControls();
      if (unsettledWorkspaces.length)
        throw new Error(
          "Held workspace retirement remains uncertain; retain the profile",
        );
      if (created) need((await native("profile-delete")).deleted === true);
      else if (profileAttempted && stage === "private-profile") {
        try {
          need((await native("profile-delete")).deleted === true);
        } catch (diagnosticError) {
          nativeException("win32/feasibility.js:exception", diagnosticError);
          /* Creation may already have rolled back before publishing its receipt. */
        }
      }
      if (profileAttempted) {
        cleanupWitness = await native("profile-absent");
        need(cleanupWitness.absent === true);
        created = false;
      }
    } catch (diagnosticError) {
      nativeException("win32/feasibility.js:exception", diagnosticError);
      /* Preserve exclusions and the original failure. */
    }
    const cause = windowsFeasibilityCause(stage, error);
    const nativeCleanup = error.nativeDiagnosticInvalid
      ? null
      : windowsFeasibilityDiagnostics(error.stderr)?.cleanup;
    const failedCleanup =
      hasUnsettledNativeBuild(error) ||
      interrupted ||
      unsettledWorkspaces.length ||
      error.workspaceCleanup ||
      error.wfpCleanup ||
      nativeCleanup ||
      (profileAttempted && !cleanupWitness)
        ? {
            status: "UNCERTAIN",
            independent: false,
            emergency: intervention,
            elapsedMs: null,
            witnessSha256: null,
            cause: {
              code: "cleanup-unobserved",
              detail: error.wfpCleanup
                ? "Read-only WFP observer resource closure remains unproved."
                : unsettledWorkspaces.length || error.workspaceCleanup
                  ? "Held workspace completion remains unproved; retain surviving resources and the fixture profile."
                  : nativeCleanup
                    ? `Native cleanup ${nativeCleanup.operation} failed (${nativeCleanup.domain}=${nativeCleanup.value}).`
                    : hasUnsettledNativeBuild(error)
                      ? "A required compiler completion remains unproved; profile absence cannot establish its retirement."
                      : interrupted
                        ? "Windows rollback interrupted an unsettled native session; profile absence cannot establish its retirement."
                        : stage === "profile-cleanup"
                          ? cause.detail
                          : "Windows rollback lacks an independent owned-profile and process retirement witness.",
            },
          }
        : cleanupWitness
          ? cleanup(cleanupWitness, cleanupStart)
          : null;
    const missing = unavailable(cause)
      .filter(
        ({ capability }) =>
          !records.some((entry) => entry.capability === capability),
      )
      .map((entry) => ({
        ...entry,
        components,
        elapsedMs: Date.now() - started,
        ...(failedCleanup ? { cleanup: failedCleanup } : {}),
      }));
    if (nullDeviceProbe)
      return {
        ...(diagnostic ?? {
          purpose: "diagnostic-only",
          caseId: nullDeviceProbeCase,
          events: [],
          git: null,
        }),
        components,
        imageBinding:
          probeSession?.imageBinding ??
          diagnostic?.imageBinding ??
          error.imageBinding ??
          imageBindingCapture().snapshot(),
        cwdObservation:
          probeSession?.cwdObservation ??
          diagnostic?.cwdObservation ??
          error.cwdObservation ??
          cwdCapture().snapshot(),
        failure: diagnostic?.failure ?? {
          operation: stage,
          message: error.message,
          stderr: error.stderr ?? null,
        },
        cleanup: {
          status: "UNCERTAIN",
          original: diagnostic?.cleanup ?? null,
          rollback: failedCleanup,
        },
        reusable: false,
      };
    return [
      ...records.map((entry) =>
        failedCleanup
          ? {
              ...entry,
              ...(failedCleanup.status !== "PASS" || stage === "profile-cleanup"
                ? { status: "FAIL", cause }
                : {}),
              cleanup: failedCleanup,
            }
          : entry,
      ),
      ...missing,
    ];
  }
}
