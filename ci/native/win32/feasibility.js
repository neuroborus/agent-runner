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

const execute = diagnosticCommand("win32/feasibility.js", promisify(execFile));
const SOURCE = fileURLToPath(new URL("./", import.meta.url));
const REPOSITORY = fileURLToPath(new URL("../../../", import.meta.url));
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
  const roots = Object.entries(environment).filter(([key]) =>
    /^systemroot$/iu.test(key),
  );
  need(roots.every(([, value]) => value === roots[0][1]));
  return {
    ...Object.fromEntries(
      Object.entries(environment).filter(
        ([key]) => !/^(?:GIT_|systemroot$)/iu.test(key),
      ),
    ),
    ...(roots.length ? { SystemRoot: roots[0][1] } : {}),
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

const GIT_HELPER_DOMAINS = Object.freeze({
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
        /^native-windows-image: query=([01]) capacity=4096 flags=0 length=([0-9]{1,10}) error=(unavailable|[0-9]{1,10}) expected=([0-9]{1,4}) actual=([01])\r?\n$/u.exec(
          text,
        );
      if (header) {
        const value = {
          succeeded: header[1] === "1",
          capacity: 4096,
          flags: 0,
          returnedLength: Number(header[2]),
          lastError: header[3] === "unavailable" ? null : Number(header[3]),
        };
        const expectedLength = Number(header[4]),
          available = value.succeeded && value.returnedLength < 4096;
        if (
          query ||
          value.returnedLength > 0xffffffff ||
          value.lastError > 0xffffffff ||
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
      streamNeed(bytes.length + chunk.length <= 65536, "stdout-bound");
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
      need(/^[RAGFWQNS]$/u.test(value));
      child.stdin.write(value);
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

/** One diagnostic lifecycle. Injected effects test refusals, never native proof. */
export async function observeWindowsGitNullProbe(effects) {
  const probe = {
    purpose: "diagnostic-only",
    hypothesis: "controller-read-only-shadow",
    events: [],
    git: null,
    reusable: false,
    imageBinding: imageBindingCapture().snapshot(),
  };
  let operation = "allocate",
    refusal;
  try {
    probe.start = await effects.start();
    operation = "bind";
    probe.binding = await effects.bind((row) => probe.events.push(row));
    need(typeof probe.binding.bound === "boolean");
    operation = "git";
    probe.git = await effects.execute(probe.binding.bound);
    need(
      typeof probe.git.ran === "boolean" &&
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
  return probe;
}

/** Explicit matching-worker effects. Portable callers receive prerequisite refusal. */
export async function runWindowsFeasibility(
  dispatch,
  observed,
  { nullDeviceProbe = false } = {},
) {
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
          events: [],
          git: { ran: false, exitCode: null },
          imageBinding: imageBindingCapture().snapshot(),
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
    active = [];
  const started = Date.now();
  let diagnostic, probeSession;
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
  const launch = async (caseId, image, args) => {
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
    session.send("R");
    return { session, receipt, admission, caseId };
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
    for (const [source, target] of [
      ["feasibility-helper.c", "helper"],
      ["argv-fixture.c", "argv-fixture"],
    ])
      await command(
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
        ],
        { cwd: path.join(root, "build") },
      );
    for (const target of ["helper", "argv-fixture"]) {
      const bytes = await regular(path.join(root, "build", `${target}.exe`));
      windowsFeasibilityImports(bytes);
      components.push({
        role: "helper",
        name: `windows-feasibility-${target}`,
        version: "1",
        sha256: digest(bytes),
      });
    }
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
    if (nullDeviceProbe) {
      stage = "null-device-probe";
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
        mapRows = 0;
      const completeGit = async () => {
        const release = await run.session.next();
        need(release.event === "git-probe-release");
        need(typeof release.ran === "boolean");
        gitRan = release.ran;
        gitResult = await run.session.next();
        need(
          gitResult.event === "git-probe-result" &&
            gitResult.ran === release.ran,
        );
        return gitResult;
      };
      diagnostic = await observeWindowsGitNullProbe({
        start: async () => {
          before = await gitFiles();
          run = await launch("null-probe", helper, [
            "null-probe",
            root,
            nonce,
            "0",
            "unused",
          ]);
          probeSession = run.session;
          need((await run.session.next()).event === "ready");
          run.session.send("A");
          need((await run.session.next()).operation === "git-status");
          const gitStarted = await run.session.next();
          target = gitStarted.child;
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
          run.session.checkGitReceipt(() =>
            validateWindowsFeasibilityGitStart({
              root,
              prepared: preparedGit,
              receipt: run.receipt,
              started: gitStarted,
              files: before,
              admission,
            }),
          );
          need(hash(await gitFiles()) === hash(before));
          await persist(windowsFeasibilityAdmissionName("null-probe", true), {
            receipt: run.receipt,
            gitStarted,
            admission,
          });
          mapper = windowsFeasibilityHelperSession(
            helper,
            root,
            nonce,
            env,
            "null-map",
            args,
          );
          active.push(mapper);
          return {
            receipt: run.receipt,
            gitStarted,
            admission,
            files: before,
            outside: outsideBaseline,
          };
        },
        bind: async (capture) => {
          for (;;) {
            need(mapRows < 32);
            const row = await mapper.next();
            mapRows++;
            capture(row);
            if (row.event === "null-controller" && row.phase === "before")
              controllerBefore = row;
            if (row.event === "null-bound") {
              normalizeWindowsIdentity(row.owner);
              need(row.owner.pid === mapper.pid);
              binding = row;
              return row;
            }
          }
        },
        execute: async (bound) => {
          run.session.send(bound ? "G" : "N");
          actionSent = true;
          return completeGit();
        },
        retire: async (capture) => {
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
            need(mapRows < 32);
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
      diagnostic.git ??= gitResult ?? { ran: gitRan, exitCode: null };
      if (run) diagnostic.git.capture = run.session.gitCapture;
      if (run) diagnostic.imageBinding = run.session.imageBinding;
      if (!diagnostic.reusable)
        throw new Error("Diagnostic resources remain uncertain; exclude reuse");
      need((await native("profile-delete")).deleted === true);
      need((await native("profile-absent")).absent === true);
      created = false;
      diagnostic.components = components;
      diagnostic.fixture = { root, nonce };
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
      const controlsBefore = [];
      for (const c of servers)
        controlsBefore.push(await native("control", c.kind, c.address));
      need(controlsBefore.every((v) => v.ready === true));
      const counts = servers.map((c) => c.accepted);
      const run = await launch(mode, helper, [
        "bundle",
        root,
        nonce,
        ...servers.map((c) => c.address),
      ]);
      need((await run.session.next()).event === "ready");
      run.session.send("A");
      const operations = [];
      let gitStart;
      for (const operation of OPERATIONS) {
        const checkReceipt = (check) =>
          operation === "git-status"
            ? run.session.checkGitReceipt(check)
            : check();
        let attempt, completed;
        try {
          attempt = await run.session.next();
          checkReceipt(() => {
            need(
              attempt.event === "attempt" && attempt.operation === operation,
            );
          });
          if (operation === "git-status") {
            const started = await run.session.next();
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
            run.session.checkGitReceipt(() => {
              validateWindowsFeasibilityGitStart({
                root,
                prepared: preparedGit,
                receipt: run.receipt,
                started,
                files: gitBefore,
                admission,
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
            run.session.send("G");
          }
          completed = await run.session.next();
          checkReceipt(() => {
            need(
              completed.event === "completed" &&
                completed.operation === operation,
            );
          });
        } catch (error) {
          nativeException("win32/feasibility.js:exception", error);
          throw Object.assign(error, { operation });
        }
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
          });
        operations.push({ attempt, completed });
      }
      const retirement = await finishLaunch(run, 20),
        after = await files(...SENTINELS);
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
        operations,
        before,
        after,
        writeControls,
        controlsBefore,
        controlsAfter,
        retirement,
      });
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
    const interrupted = active.some((session) => !session.exited);
    const intervention = active.some(
      (session) =>
        !session.exited && ["launch", "hold", "recover"].includes(session.role),
    );
    for (const session of active) session.stop();
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
      interrupted || nativeCleanup || (profileAttempted && !cleanupWitness)
        ? {
            status: "UNCERTAIN",
            independent: false,
            emergency: intervention,
            elapsedMs: null,
            witnessSha256: null,
            cause: {
              code: "cleanup-unobserved",
              detail: nativeCleanup
                ? `Native cleanup ${nativeCleanup.operation} failed (${nativeCleanup.domain}=${nativeCleanup.value}).`
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
          events: [],
          git: null,
        }),
        components,
        imageBinding:
          probeSession?.imageBinding ??
          diagnostic?.imageBinding ??
          error.imageBinding ??
          imageBindingCapture().snapshot(),
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
