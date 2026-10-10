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
  windowsFeasibilityPeError,
  windowsFeasibilityPeCause,
} from "./feasibility-git.js";

const execute = promisify(execFile);
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

/** Keep native SDK setup, but exclude ambient Git repository/configuration routes. */
export function windowsFeasibilityToolEnvironment(environment) {
  return {
    ...Object.fromEntries(
      Object.entries(environment).filter(([key]) => !/^GIT_/iu.test(key)),
    ),
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
  attribute-handles windows-directory environment-bound launch-intent
  process-create launch-absence launch-accounting pipe-close process-job
  process-image process-release process-open process-close process-wait
  handle-duplicate thread-query thread-state thread-process thread-close host-ci host-actions host-worker
  host-os deadline-create winsock-start job-terminate job-close profile-delete
`
    .trim()
    .split(/\s+/u),
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
      /^(native-windows(?:-cleanup)?): operation=([a-z-]+) domain=(win32|hresult|ntstatus|invariant) value=(0|[1-9][0-9]{0,9})$/u.exec(
        line,
      );
    if (
      !match ||
      match[1] !== (cleanup ? "native-windows-cleanup" : "native-windows") ||
      !NATIVE_OPERATIONS.has(match[2])
    )
      return null;
    const value = Number(match[4]);
    if (
      value > 0xffffffff ||
      (match[3] === "invariant" && value !== 0) ||
      (["ntstatus", "hresult"].includes(match[3]) && value < 0x80000000)
    )
      return null;
    if (
      cleanup &&
      !["job-terminate", "job-close", "profile-delete"].includes(match[2])
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
  const prerequisite =
    (error?.code === 78 &&
      !error?.signal &&
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
  const explanation = diagnostic
    ? `Native ${diagnostic.operation} failed (${diagnostic.domain}=${diagnostic.value}).${error?.nativeStreamInvalid ? " Native helper stream rejected." : ""}`
    : error?.nativeDiagnosticInvalid
      ? "Native helper diagnostic rejected as malformed or oversized."
      : error?.nativeStreamInvalid
        ? "Native helper stream rejected as malformed or incomplete."
        : null;
  return explanation
    ? {
        ...cause,
        detail:
          `${cause.detail.split(";")[0]}; output=${diagnostic ? "recognized" : "unrecognized"}; ${explanation}`.slice(
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
/** Explicit helper effect; portable callers inject the child-process boundary. */
export function windowsFeasibilityHelperSession(
  helper,
  root,
  nonce,
  env,
  role,
  args = [],
  { spawnProcess = spawn } = {},
) {
  const child = spawnProcess(
    helper,
    [role, root, nonce, ...args].map(quoteWindowsArgument),
    {
      env,
      argv0: quoteWindowsArgument(helper),
      windowsVerbatimArguments: true,
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
    },
  );
  const rows = [],
    pending = [];
  let bytes = Buffer.alloc(0),
    parsed = 0,
    stderr = Buffer.alloc(0),
    nativeDiagnosticInvalid = false,
    error,
    exit;
  const attach = (problem) => {
    Object.assign(problem, {
      stderr: stderr.toString("utf8"),
      nativeDiagnosticInvalid,
    });
    if (exit) {
      Object.assign(problem, { exitCode: exit.code, signal: exit.signal });
      problem.code ??= exit.code;
    }
    return problem;
  };
  const reject = (problem) => {
    error ??= problem;
    if (problem.nativeStreamInvalid) error.nativeStreamInvalid = true;
    attach(error);
    for (const waiter of pending.splice(0)) waiter.reject(error);
    child.stdin.end();
  };
  child.on("error", reject);
  child.stdin.on("error", reject);
  child.stderr.on("data", (chunk) => {
    if (nativeDiagnosticInvalid) return;
    if (stderr.length + chunk.length > 4096) {
      nativeDiagnosticInvalid = true;
      reject(new Error("Oversized native diagnostic"));
    } else stderr = Buffer.concat([stderr, chunk]);
  });
  child.stdout.on("data", (chunk) => {
    if (error) return;
    try {
      need(bytes.length + chunk.length <= 65536);
      bytes = Buffer.concat([bytes, chunk]);
      for (;;) {
        const end = bytes.indexOf(10, parsed);
        if (end < 0) break;
        const line = bytes.subarray(parsed, end).toString("utf8");
        need(
          Buffer.from(line).equals(bytes.subarray(parsed, end)) &&
            !line.includes("\r"),
        );
        parsed = end + 1;
        const row = JSON.parse(line);
        rows.push(row);
        if (pending.length) pending.shift().resolve(row);
      }
    } catch (problem) {
      reject(Object.assign(problem, { nativeStreamInvalid: true }));
    }
  });
  const closed = new Promise((resolve) =>
    child.once("close", (code, signal) => {
      exit = { code, signal };
      if (parsed !== bytes.length)
        reject(
          Object.assign(new Error("Incomplete native stream"), {
            nativeStreamInvalid: true,
          }),
        );
      if (stderr.length && !windowsFeasibilityDiagnostics(stderr)) {
        nativeDiagnosticInvalid = true;
        reject(new Error("Malformed native diagnostic"));
      }
      if (error) attach(error);
      if (pending.length) reject(attach(new Error("Native stream ended")));
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
            fail(failure);
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
    get exited() {
      return exit !== undefined;
    },
    next: async () => {
      if (error) throw attach(error);
      if (cursor < rows.length) return rows[cursor++];
      if (exit) throw attach(new Error("Missing native record"));
      const value = await bounded(
        new Promise((resolve, fail) => pending.push({ resolve, reject: fail })),
      );
      cursor++;
      return value;
    },
    send: (value) => {
      need(!error && !exit && /^[RAFWQNS]$/u.test(value));
      child.stdin.write(value);
    },
    stop: () => child.stdin.end(),
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
      ))
        throw attach(
          Object.assign(new Error("Incomplete native stream"), {
            nativeStreamInvalid: true,
          }),
        );
      return rows;
    },
  };
}

/** Explicit matching-worker effects. Portable callers receive prerequisite refusal. */
export async function runWindowsFeasibility(dispatch, observed) {
  const definitions = feasibilityCapabilities("win32").filter(
    ({ tier }) => tier === "native",
  );
  const unavailable = (cause) =>
    unavailableFeasibilityResults("win32", cause).filter(({ capability }) =>
      definitions.some(({ id }) => id === capability),
    );
  if (!(
    process.platform === "win32" &&
    process.arch === "x64" &&
    process.env.CI === "true" &&
    process.env.GITHUB_ACTIONS === "true" &&
    process.env.RUNNER_ENVIRONMENT === "github-hosted" &&
    process.env.RUNNER_OS === "Windows"
  ))
    return unavailable({
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
  const env = {
    CI: "true",
    GITHUB_ACTIONS: "true",
    RUNNER_ENVIRONMENT: "github-hosted",
    RUNNER_OS: "Windows",
    SystemRoot: process.env.SystemRoot,
    PATH: path.join(process.env.SystemRoot, "System32"),
  };
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
    await persist(`${caseId}-admission`, { receipt, admission });
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
    await prepareWindowsFeasibilityGit(
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
      for (const operation of OPERATIONS) {
        let attempt, completed;
        try {
          attempt = await run.session.next();
          completed = await run.session.next();
        } catch (error) {
          throw Object.assign(error, { operation });
        }
        need(
          attempt.event === "attempt" &&
            attempt.operation === operation &&
            completed.event === "completed" &&
            completed.operation === operation,
        );
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
      const retirement = await finishLaunch(run, 19),
        after = await files(...SENTINELS);
      need(hash(before) === hash(after));
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
        } catch {
          /* Creation may already have rolled back before publishing its receipt. */
        }
      }
      if (profileAttempted) {
        cleanupWitness = await native("profile-absent");
        need(cleanupWitness.absent === true);
        created = false;
      }
    } catch {
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
