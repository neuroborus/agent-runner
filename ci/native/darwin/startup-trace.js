import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, realpath } from "node:fs/promises";
import { constants as osConstants } from "node:os";
import {
  digest,
  normalizeDarwinIdentity,
  sameDarwinIdentity,
} from "./protocol.js";
import { nativeException, observeNativeProcess } from "../diagnostics.js";

// One cold schema run emits thousands of syscall rows and hundreds of paths.
// Bound each retained collection independently; never trim a successful prefix.
export const DARWIN_STARTUP_TRACE_LIMITS = Object.freeze({
  bytes: 8 * 1024 * 1024,
  rows: 131072,
  rowBytes: 8192,
  argumentBytes: 1024,
  arguments: 8192,
  numeric: 8192,
});
// Producer storage is independent of capture bounds; hosted sufficiency is unproved.
const COLD_PRODUCER_BYTES = 16 * 1024 * 1024;

// No raw proc/CTF offsets: compiling args[0]->pr_pid requires the installed
// proc provider's public psinfo translation. Every description is mandatory.
// XNU 43a90889846e00bfb5cf1d255cdc0a701a1e05a4 systrace.c reports the
// mach_reply_port trap result in arg0 (not the pid-provider return arg1).
const CONSTRUCTOR_PROGRAM = `#pragma D option quiet
int child_pid; uint64_t constructors; int gates;
dtrace:::BEGIN { printf("armed %d %llu\\n", pid, timestamp); }
proc:::create /pid == $1/ {
  printf("created %d %llu %d\\n", pid, timestamp, args[0]->pr_pid);
  child_pid = child_pid == 0 ? args[0]->pr_pid : child_pid;
}
proc:::start /pid == child_pid/ {
  printf("started %d %llu %llu\\n", pid, timestamp, (uint64_t)tid);
}
mach_trap::mach_reply_port:return /pid == child_pid/ {
  constructors++; printf("constructor %d %llu %llu %llu %llu\\n", pid, timestamp, (uint64_t)tid, constructors, (uint64_t)arg0);
}
syscall::read:entry,syscall::read_nocancel:entry /pid == child_pid && arg0 == 4/ {
  gates++; self->creator_gate = gates;
  printf("fence %d %llu %llu %d %llu %llu\\n", pid, timestamp, (uint64_t)tid, gates, constructors, (uint64_t)arg2);
}
syscall::read:entry,syscall::read_nocancel:entry /pid == child_pid && arg0 == 4 && gates == 2/ { exit(0); }
syscall::read:return,syscall::read_nocancel:return /pid == child_pid && self->creator_gate == 1/ {
  printf("imported %d %llu %lld\\n", pid, timestamp, (int64_t)arg0); self->creator_gate = 0;
}
proc:::exec-success,proc:::exit /pid == $1 || pid == child_pid/ { printf("invalid %d %llu\\n", pid, timestamp); exit(1); }
dtrace:::ERROR { printf("invalid %d %llu\\n", pid, timestamp); exit(1); }
dtrace:::END { printf("terminal %d %llu %llu %d\\n", child_pid, timestamp, constructors, gates); }
`;
export const DARWIN_CONSTRUCTOR_TRACE_INTENT = Object.freeze({
  tool: "/usr/sbin/dtrace",
  programSha256: digest(CONSTRUCTOR_PROGRAM),
});
const DARWIN_CREATOR_RECEIPT_BYTES = 512;

/** Live capture and protected recovery receipts share this one-shot exchange.
 * Settlement is evidence only; it grants no new signal or reap authority. */
export function createDarwinRefusalBinding(
  parent,
  identity,
  candidateSha,
  receiptSha256,
) {
  parent = normalizeDarwinIdentity(parent);
  identity = normalizeDarwinIdentity(identity);
  need(
    /^[a-f0-9]{40}$/u.test(candidateSha) &&
      /^[a-f0-9]{64}$/u.test(receiptSha256),
  );
  let registration, settlement, bindingSha256;
  return {
    consume(value) {
      need(value && !Array.isArray(value) && value.version === 1);
      if (value.phase === "register") {
        need(
          !registration &&
            Object.keys(value).sort().join(",") ===
              "candidateSha,observer,original,parent,phase,receiptSha256,refusedName,version" &&
            value.candidateSha === candidateSha &&
            sameDarwinIdentity(value.parent, parent) &&
            sameDarwinIdentity(value.original, identity) &&
            value.receiptSha256 === receiptSha256 &&
            Number.isSafeInteger(value.refusedName) &&
            value.refusedName > 0 &&
            value.refusedName < 0xffffffff,
        );
        const observer = value.observer;
        need(
          observer &&
            Object.keys(observer).sort().join(",") ===
              "parentPid,pid,startMicroseconds,startSeconds" &&
            Number.isSafeInteger(observer.pid) &&
            observer.pid > 1 &&
            observer.pid <= 0x7fffffff &&
            observer.pid !== identity.pid &&
            observer.pid !== parent.pid &&
            observer.parentPid === parent.pid &&
            Number.isSafeInteger(observer.startSeconds) &&
            observer.startSeconds > 0 &&
            Number.isSafeInteger(observer.startMicroseconds) &&
            observer.startMicroseconds >= 0 &&
            observer.startMicroseconds < 1000000,
        );
        registration = {
          ...value,
          parent,
          original: identity,
          observer: { ...observer },
        };
        bindingSha256 = digest(
          JSON.stringify([
            DARWIN_CONSTRUCTOR_TRACE_INTENT.programSha256,
            registration,
          ]),
        );
      } else {
        need(
          registration &&
            !settlement &&
            value.phase === "settle" &&
            Object.keys(value).sort().join(",") ===
              "bindingSha256,channelLost,cleanup,error,observed,phase,reaped,status,version" &&
            value.bindingSha256 === bindingSha256 &&
            [value.reaped, value.channelLost, value.observed].every(
              (field) => typeof field === "boolean",
            ) &&
            [value.cleanup, value.error, value.status].every(
              (field) =>
                Number.isSafeInteger(field) &&
                field >= 0 &&
                field <= 0x7fffffff,
            ),
        );
        settlement = { ...value };
      }
      return bindingSha256;
    },
    evidence() {
      need(registration && settlement);
      return {
        registration,
        settlement,
        bindingSha256,
        cleanup:
          settlement.reaped && !settlement.cleanup ? "RETIRED" : "UNCERTAIN",
      };
    },
  };
}

/** Bounded unordered delivery, ordered kernel sequence. A fence is not a flush:
 * all records through its count must arrive before a receipt can be issued. */
export function createDarwinConstructorCapture(parent, candidateSha) {
  parent = normalizeDarwinIdentity(parent);
  const rows = [],
    records = new Map(),
    fences = new Map(),
    children = new Map();
  let created, started, imported, terminal, identity, receipt, refusal;
  const ready = () => {
    created = started && children.get(started[1]);
    if (!created || !started || !fences.has(1)) return false;
    const fence = fences.get(1);
    return (
      records.size >= Number(fence[5]) &&
      Array.from({ length: Number(fence[5]) }, (_, i) =>
        records.has(i + 1),
      ).every(Boolean)
    );
  };
  const validate = (final = false) => {
    need(ready() && created[1] === String(parent.pid));
    const pid = created[3],
      epoch = BigInt(created[2]),
      thread = started[3],
      pre = fences.get(1);
    need(
      started[1] === pid &&
        BigInt(started[2]) >= epoch &&
        pre[1] === pid &&
        pre[3] === thread &&
        pre[4] === "1" &&
        pre[6] === "512" &&
        BigInt(pre[2]) >= BigInt(started[2]),
    );
    const names = new Set();
    let previous = BigInt(started[2]);
    for (const [sequence, row] of [...records].sort(([a], [b]) => a - b)) {
      need(
        row[1] === pid &&
          row[3] === thread &&
          sequence <= Number(pre[5]) &&
          BigInt(row[2]) >= previous &&
          BigInt(row[2]) <= BigInt(pre[2]) &&
          !names.has(row[5]),
      );
      names.add(row[5]);
      previous = BigInt(row[2]);
    }
    if (identity) need(identity.pid === Number(pid));
    if (final) {
      need(children.size === 1 && !refusal);
      const post = fences.get(2);
      need(
        identity &&
          receipt &&
          imported &&
          post &&
          terminal &&
          imported[1] === pid &&
          imported[3] === "512" &&
          BigInt(imported[2]) >= BigInt(pre[2]) &&
          BigInt(imported[2]) <= BigInt(post[2]) &&
          post[1] === pid &&
          post[3] === thread &&
          post[4] === "2" &&
          post[5] === pre[5] &&
          post[6] === "1" &&
          terminal[1] === pid &&
          terminal[3] === pre[5] &&
          terminal[4] === "2" &&
          BigInt(terminal[2]) >= BigInt(post[2]) &&
          records.size === Number(pre[5]),
      );
    }
    return [...records]
      .sort(([a], [b]) => a - b)
      .map(([, row]) => Number(row[5]));
  };
  return {
    consume(line) {
      const row = line.split(" "),
        [kind] = row;
      const sizes = {
        created: 4,
        started: 4,
        constructor: 6,
        fence: 7,
        imported: 4,
        terminal: 5,
      };
      need(
        Object.hasOwn(sizes, kind) &&
          row.length === sizes[kind] &&
          rows.length < 32 &&
          row.slice(1).every((field) => unsigned(field, 0xffffffffffffffffn)) &&
          row[1] !== "0" &&
          row[2] !== "0",
      );
      rows.push(row);
      if (kind === "created") {
        need(
          children.size < 2 &&
            !children.has(row[3]) &&
            row[1] === String(parent.pid) &&
            Number(row[3]) > 1 &&
            Number(row[3]) <= 0x7fffffff,
        );
        children.set(row[3], row);
      }
      if (kind === "started") {
        need(!started && row[3] !== "0");
        started = row;
      }
      if (kind === "constructor") {
        const sequence = Number(row[4]);
        need(
          sequence > 0 &&
            sequence <= 8 &&
            !records.has(sequence) &&
            BigInt(row[5]) > 0n &&
            BigInt(row[5]) < 0xffffffffn,
        );
        records.set(sequence, row);
      }
      if (kind === "fence") {
        const phase = Number(row[4]);
        need(
          [1, 2].includes(phase) &&
            !fences.has(phase) &&
            Number(row[5]) > 0 &&
            Number(row[5]) <= 8,
        );
        fences.set(phase, row);
      }
      if (kind === "imported") {
        need(!imported);
        imported = row;
      }
      if (kind === "terminal") {
        need(!terminal);
        terminal = row;
      }
      if (receipt && ready()) validate();
      return ready();
    },
    receipt(value) {
      need(!receipt);
      identity = normalizeDarwinIdentity(value);
      const names = validate();
      const fields = [
        "CR1",
        parent.pid,
        created[2],
        identity.auid,
        identity.uid,
        identity.gid,
        identity.ruid,
        identity.rgid,
        identity.pid,
        identity.asid,
        identity.pidVersion,
        identity.startSeconds,
        identity.startMicroseconds,
        identity.svuid,
        identity.svgid,
        names.length,
        ...names,
      ];
      const text = fields.join(" ") + "\n";
      need(Buffer.byteLength(text) < DARWIN_CREATOR_RECEIPT_BYTES);
      receipt = Buffer.alloc(DARWIN_CREATOR_RECEIPT_BYTES);
      receipt.write(text, "ascii");
      return Buffer.from(receipt);
    },
    refusal(value) {
      need(receipt);
      refusal ??= createDarwinRefusalBinding(
        parent,
        identity,
        candidateSha,
        digest(receipt),
      );
      return refusal.consume(value);
    },
    diagnostic() {
      if (!refusal) {
        need(children.size <= 1);
        return null;
      }
      validate();
      const evidence = refusal.evidence();
      const observer = children.get(String(evidence.registration.observer.pid));
      need(
        children.size === 2 &&
          observer &&
          BigInt(observer[2]) > BigInt(created[2]) &&
          (!terminal ||
            (terminal[1] === String(identity.pid) &&
              BigInt(observer[2]) <= BigInt(terminal[2]))),
      );
      return evidence;
    },
    complete() {
      validate(true);
      return {
        identity,
        forkEpoch: created[2],
        constructors: validate(true),
        receiptSha256: digest(receipt),
      };
    },
  };
}

// XNU syscalls.master and systrace.c establish these entry argument positions.
const PATH_ARGUMENTS = Object.freeze({
  open: 0,
  open_nocancel: 0,
  open_extended: 0,
  open_dprotected_np: 0,
  guarded_open_np: 0,
  guarded_open_dprotected_np: 0,
  openat: 1,
  openat_nocancel: 1,
  openat_dprotected_np: 1,
});
const ARGUMENT_FUNCTIONS = Object.freeze([
  ...Object.keys(PATH_ARGUMENTS),
  "abort_with_payload",
  "csrctl",
  "sysctl",
  "sysctlbyname",
]);
const probes = (names) =>
  names.map((name) => `probefunc == "${name}"`).join(" || ");
// No fallback, generic argument decoding, destructive action or unrelated-process
// predicate. Cold numeric descriptions may match zero probes; core observations
// are required independently of compilation and BEGIN acknowledgement.
const startupProgram = (argumentBytes, cold = false) => {
  const started = cold ? " && target_exec" : "";
  return `#pragma D option quiet
#pragma D option strsize=${argumentBytes + 1}
${cold ? `#pragma D option dynvarsize=${COLD_PRODUCER_BYTES}\nint target_exec;\n` : ""}dtrace:::BEGIN { printf("armed %d %llu\\n", pid, timestamp); }
syscall:::entry /pid == $1${started}/ { printf("entry %d %llu %s\\n", pid, timestamp, probefunc); }
syscall:::entry /pid == $1${started} && (${probes([...Object.keys(PATH_ARGUMENTS), "abort_with_payload"])})/ {
  self->operation = probefunc; self->namespace = probefunc == "abort_with_payload" ? (uint32_t)arg0 : 0;
  self->code = probefunc == "abort_with_payload" ? (uint64_t)arg1 : 0;
  self->pointer = probefunc == "abort_with_payload" ? arg4 : (${probes(Object.keys(PATH_ARGUMENTS).filter((name) => PATH_ARGUMENTS[name] === 1))}) ? arg1 : arg0;
  self->copying = self->pointer != 0; self->text = self->pointer ? copyinstr(self->pointer, ${argumentBytes}) : "";
  self->copying = 0;
  printf("argument-entry %d %llu %s %llu %s %u %llu %S\\n", pid, timestamp, probefunc, (uint64_t)tid, self->pointer == 0 ? "missing" : strlen(self->text) < ${argumentBytes} ? "complete" : "truncated", (uint32_t)self->namespace, (uint64_t)self->code, self->text);
  self->text = 0; self->operation = 0; self->pointer = 0; self->namespace = 0; self->code = 0;
}
syscall:::entry /pid == $1${started} && probefunc == "csrctl"/ { printf("argument-entry %d %llu %s %llu complete %u 0 \\n", pid, timestamp, probefunc, (uint64_t)tid, (uint32_t)arg0); }
syscall:::entry /pid == $1${started} && (probefunc == "sysctl" || probefunc == "sysctlbyname")/ { printf("argument-entry %d %llu %s %llu unsupported 0 0 \\n", pid, timestamp, probefunc, (uint64_t)tid); }
dtrace:::ERROR /pid == $1${started} && self->copying/ { printf("argument-entry %d %llu %s %llu copy-failed %u %llu \\n", pid, timestamp, self->operation, (uint64_t)tid, (uint32_t)self->namespace, (uint64_t)self->code); self->copying = 0; self->operation = 0; self->text = 0; self->pointer = 0; self->namespace = 0; self->code = 0; }
syscall:::return /pid == $1${started}/ { printf("return %d %llu %s %d %lld\\n", pid, timestamp, probefunc, errno, (int64_t)arg0); }
syscall:::return /pid == $1${started} && (${probes(ARGUMENT_FUNCTIONS.filter((name) => name !== "abort_with_payload"))})/ { printf("argument-return %d %llu %s %llu %d %lld\\n", pid, timestamp, probefunc, (uint64_t)tid, errno, (int64_t)arg0); }
proc:::exec-success /pid == $1/ { ${cold ? "target_exec = 1; " : ""}printf("exec %d %llu\\n", pid, timestamp); }
proc:::exit /pid == $1/ { printf("exit %d %llu\\n", pid, timestamp); exit(0); }
`;
};
const PROGRAM = startupProgram(128);
export const DARWIN_STARTUP_TRACE_INTENT = Object.freeze({
  tool: "/usr/sbin/dtrace",
  programSha256: digest(PROGRAM),
});
// Cold Rust startup obtains the main-thread stack bounds through libpthread,
// then maps its guard with mmap before mprotect. Preserve raw integer bits and
// the actual return; a trace of the policy launcher cannot supply these values.
const NUMERIC_ARGUMENTS = Object.freeze({
  sysconf: ["selector"],
  pthread_get_stackaddr_np: ["threadHandle"],
  pthread_get_stacksize_np: ["threadHandle"],
  mmap: [
    "address",
    "length",
    "protection",
    "flags",
    "descriptorBits",
    "offsetBits",
  ],
  mprotect: ["address", "length", "protection"],
});
const COLD_PROGRAM =
  startupProgram(DARWIN_STARTUP_TRACE_LIMITS.argumentBytes, true) +
  Object.entries(NUMERIC_ARGUMENTS)
    .map(([name, args]) => {
      const syscall = name === "mmap" || name === "mprotect",
        provider = syscall
          ? "syscall::"
          : `pid$1:${name === "sysconf" ? "libsystem_c.dylib" : "libsystem_pthread.dylib"}:`,
        probe = syscall ? `${provider}:` : `${provider}${name}:`,
        predicate = `pid == $1 && target_exec${syscall ? ` && probefunc == "${name}"` : ""}`;
      return `${probe}entry /${predicate}/ { printf("numeric-entry %d %llu ${name} %llu${args.map(() => " %llu").join("")}\\n", pid, timestamp, (uint64_t)tid, ${args.map((_, i) => `(uint64_t)arg${i}`).join(", ")}); }
${probe}return /${predicate}/ { printf("numeric-return %d %llu ${name} %llu %d %lld\\n", pid, timestamp, (uint64_t)tid, ${syscall ? "errno, (int64_t)arg0" : "-1, (int64_t)arg1"}); }
`;
    })
    .join("");
export const DARWIN_COLD_STARTUP_TRACE_INTENT = Object.freeze({
  tool: "/usr/sbin/dtrace",
  programSha256: digest(COLD_PROGRAM),
});
const numericRuntime = (records = []) =>
  Object.fromEntries(
    Object.keys(NUMERIC_ARGUMENTS).map((name) => {
      const calls = records.filter((record) => record.operation === name);
      return [name, calls.length ? calls : null];
    }),
  );
const matchingCI = () =>
  process.platform === "darwin" &&
  process.arch === "x64" &&
  process.env.CI === "true" &&
  process.env.GITHUB_ACTIONS === "true" &&
  process.env.RUNNER_ENVIRONMENT === "github-hosted" &&
  process.env.RUNNER_OS === "macOS";
const need = (value) => {
  if (!value) throw new Error("Unproved startup trace");
};
/** Cold-command admission consumes the same bounds as the streaming producer.
 * Optional coverage stays diagnostic; retained numeric entries require results. */
export function assertDarwinColdStartupTrace(trace) {
  need(
    trace?.status === "observed" &&
      trace.captureComplete === true &&
      trace.cleanup === "RETIRED" &&
      trace.exit?.code === 0 &&
      trace.exit.signal === null &&
      trace.programSha256 === DARWIN_COLD_STARTUP_TRACE_INTENT.programSha256 &&
      Number.isSafeInteger(trace.events) &&
      trace.events > 0 &&
      trace.events <= DARWIN_STARTUP_TRACE_LIMITS.rows &&
      /^[a-f0-9]{64}$/u.test(trace.sha256) &&
      [
        "complete",
        "empty",
        "unsupported",
        "missing",
        "copy-failed",
        "truncated",
      ].includes(trace.argumentStatus) &&
      ["complete", "empty", "missing"].includes(trace.numericStatus) &&
      Array.isArray(trace.arguments) &&
      trace.arguments.length <= DARWIN_STARTUP_TRACE_LIMITS.arguments,
  );
  let count = 0;
  for (const name of Object.keys(NUMERIC_ARGUMENTS)) {
    const records = trace.runtime?.[name];
    need(records === null || Array.isArray(records));
    need(trace.numericStatus !== "complete" || records !== null);
    if (records) {
      count += records.length;
      need(
        records.length > 0 &&
          records.every((record) => record.operation === name && record.result),
      );
    }
  }
  need(
    count <= DARWIN_STARTUP_TRACE_LIMITS.numeric &&
      (trace.numericStatus === "empty" ? count === 0 : count > 0),
  );
  return trace;
}
async function installed() {
  for (const file of ["/usr/bin/sudo", "/usr/sbin/dtrace"]) {
    const info = await lstat(file);
    need(
      info.isFile() &&
        info.uid === 0 &&
        !(info.mode & 0o022) &&
        (await realpath(file)) === file,
    );
  }
}
async function bounded(promise, milliseconds) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(
          () => reject(new Error("Startup trace deadline")),
          milliseconds,
        );
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

const TRACE_FIELDS = Object.freeze({
  armed: 3,
  entry: 4,
  return: 6,
  exec: 3,
  exit: 3,
  "argument-entry": 9,
  "argument-return": 7,
  "numeric-entry": 0,
  "numeric-return": 7,
});
const unsigned = (value, maximum) =>
  /^(?:0|[1-9][0-9]{0,19})$/u.test(value) && BigInt(value) <= maximum;
function traceRow(line, argumentBytes) {
  const fields = line.split(" "),
    [kind, pid, time, name] = fields;
  need(
    line.length <=
      (argumentBytes === 128 ? 1024 : DARWIN_STARTUP_TRACE_LIMITS.rowBytes) &&
      Object.hasOwn(TRACE_FIELDS, kind) &&
      (kind === "numeric-entry"
        ? Object.hasOwn(NUMERIC_ARGUMENTS, name) &&
          fields.length === 5 + NUMERIC_ARGUMENTS[name].length
        : kind === "argument-entry"
          ? fields.length >= 9
          : fields.length === TRACE_FIELDS[kind]),
  );
  need(
    /^[1-9][0-9]{0,9}$/u.test(pid) &&
      Number(pid) <= 0x7fffffff &&
      /^[1-9][0-9]{0,19}$/u.test(time),
  );
  const timestamp = BigInt(time);
  need(timestamp <= 0xffffffffffffffffn);
  if (name !== undefined) need(/^[a-zA-Z0-9_]{1,64}$/u.test(name));
  const numeric = kind.startsWith("numeric-"),
    diagnostic = numeric || kind.startsWith("argument-"),
    thread = diagnostic ? fields[4] : undefined;
  if (diagnostic)
    need(
      (numeric
        ? Object.hasOwn(NUMERIC_ARGUMENTS, name)
        : ARGUMENT_FUNCTIONS.includes(name)) &&
        unsigned(thread, 0xffffffffffffffffn) &&
        thread !== "0",
    );
  const error = fields[kind === "return" ? 4 : 5],
    value = fields[kind === "return" ? 5 : 6];
  if (
    kind === "return" ||
    kind === "argument-return" ||
    kind === "numeric-return"
  )
    need(
      (kind === "numeric-return" && !["mmap", "mprotect"].includes(name)
        ? error === "-1"
        : /^(0|[1-9][0-9]{0,4})$/u.test(error)) &&
        Number(error) <= 65535 &&
        /^(?:0|-?[1-9][0-9]{0,18})$/u.test(value) &&
        BigInt(value) >= -0x8000000000000000n &&
        BigInt(value) <= 0x7fffffffffffffffn,
    );
  let argument;
  if (kind === "numeric-entry") {
    need(
      fields.slice(5).every((value) => unsigned(value, 0xffffffffffffffffn)),
    );
    argument = Object.fromEntries(
      NUMERIC_ARGUMENTS[name].map((key, i) => [key, fields[5 + i]]),
    );
  }
  if (kind === "argument-entry") {
    const [, , , , , state, first, second] = fields;
    let text = fields.slice(8).join(" ");
    const tokens =
      text.match(/\\(?:[abfnrtv\\'"?]|[0-3][0-7]{2}|0)|[ -[\]-~]/gu) ?? [];
    need(
      unsigned(first, 0xffffffffn) &&
        unsigned(second, 0xffffffffffffffffn) &&
        tokens.join("") === text,
    );
    const string =
      Object.hasOwn(PATH_ARGUMENTS, name) || name === "abort_with_payload";
    const isNul = (token) => token === "\\0" || token === "\\000";
    // pfprint_estr/strchr2esc frames strings; an escaped backslash is not a NUL.
    if (string && ["complete", "truncated", "missing"].includes(state))
      need(isNul(tokens.pop()));
    text = tokens.join("");
    need(text.length <= argumentBytes * 4 && !tokens.some(isNul));
    need(
      string
        ? (state === "complete" && tokens.length < argumentBytes) ||
            (state === "truncated" && tokens.length === argumentBytes) ||
            (["missing", "copy-failed"].includes(state) && !text)
        : !text &&
            (name === "csrctl"
              ? state === "complete"
              : state === "unsupported"),
    );
    need(
      name === "abort_with_payload" ||
        (second === "0" && (name === "csrctl" || first === "0")),
    );
    argument = {
      acquisition: ["complete", "truncated"].includes(state)
        ? "acquired"
        : state,
      completeness: ["complete", "truncated"].includes(state)
        ? state
        : "unavailable",
      text: string && state === "complete" ? text : null,
      namespace: name === "abort_with_payload" ? Number(first) : null,
      code: name === "abort_with_payload" ? second : null,
      selector: name === "csrctl" ? Number(first) : null,
    };
  }
  return {
    kind,
    pid: Number(pid),
    timestamp,
    name,
    thread,
    error,
    value,
    argument,
  };
}

function traceFailure(error, reason) {
  return {
    reason,
    code:
      Number.isInteger(error?.code) && error.code >= 0 && error.code <= 255
        ? error.code
        : ["ENOENT", "EACCES", "EPERM", "ESRCH", "ETIMEDOUT"].includes(
              error?.code,
            )
          ? error.code
          : null,
    signal:
      typeof error?.signal === "string" &&
      Object.hasOwn(osConstants.signals, error.signal)
        ? error.signal
        : null,
  };
}
function requireRetired(results) {
  need(Array.isArray(results));
  const rejected = results.find((result) => result.status === "rejected");
  if (rejected) throw rejected.reason;
  need(
    results.every(
      (result) =>
        result.status === "fulfilled" &&
        retirementState(result.value).status === "RETIRED",
    ),
  );
}
function retirementState(value) {
  need(
    value &&
      !Array.isArray(value) &&
      Object.keys(value).join(",") === "status" &&
      ["LIVE", "RETIRED"].includes(value.status),
  );
  return value;
}

const STARTUP_EXEC_REQUIRED = Object.freeze({
  "policy-only": false,
  "policy-invalid": false,
  "exec-control": false,
  "fixture-control": true,
  exec: true,
});

/** Private diagnostic owner. Tests replace all effects; default launch is CI-only. */
export function openDarwinStartupTrace(
  binding,
  {
    isMatchingCI = matchingCI(),
    verifyInstalled = installed,
    launch = spawn,
    readObserver,
    observeObserver,
    retireObserver,
    parentPid = process.pid,
    coldCommand = false,
    constructorMode = false,
    operation = coldCommand || constructorMode ? "exec" : undefined,
    onObserver,
    onFailure,
  } = {},
) {
  need(
    typeof coldCommand === "boolean" &&
      typeof constructorMode === "boolean" &&
      !(coldCommand && constructorMode),
  );
  need(
    typeof operation === "string" &&
      Object.hasOwn(STARTUP_EXEC_REQUIRED, operation) &&
      (!coldCommand || operation === "exec"),
  );
  const execRequired = !constructorMode && STARTUP_EXEC_REQUIRED[operation];
  const creators = constructorMode
    ? createDarwinConstructorCapture(binding.identity, binding.candidateSha)
    : null;
  const creatorReady = Promise.withResolvers();
  creatorReady.promise.catch(() => {});
  let boundPid,
    parkedIdentity,
    targetIdentity,
    bindingExec = false,
    child,
    closed,
    armedPid,
    armTime,
    previousTime,
    pending = "",
    count = 0,
    execSeen = false,
    exitSeen = false,
    syscallEntrySeen = false,
    syscallReturnSeen = false,
    stdoutBytes = 0,
    stderrBytes = 0,
    invalid = false,
    failure,
    cleanupFailure,
    exit,
    status = "unavailable",
    arming = false,
    domainBound = false,
    armDeadline,
    captureDeadline,
    terminalSeparator = false,
    captureTimer,
    finished,
    argumentMalformed = false;
  const owners = [],
    traceHash = createHash("sha256"),
    argumentsSeen = [],
    pendingArguments = new Map(),
    expectedArguments = new Map();
  const numericSeen = [],
    pendingNumeric = new Map(),
    expectedNumeric = new Map();
  const withinArm = () =>
    arming && !failure && !exit && Date.now() < armDeadline;
  let acknowledge, refuse;
  const ready = new Promise((resolve, reject) => {
    acknowledge = resolve;
    refuse = reject;
  });
  ready.catch(() => {});
  const executed = Promise.withResolvers();
  executed.promise.catch(() => {});
  const fail = (error, reason) => {
    nativeException("darwin/startup-trace.js", error);
    const facts = traceFailure(error, reason);
    failure ??= facts;
    if (reason === "retirement") cleanupFailure ??= facts;
    status = reason === "capture" ? "partial" : "refused";
    refuse(error);
    executed.reject(error);
    creatorReady.reject(error);
    // Capture can fail after E while the cold request is still running. Let its
    // existing owner fence work immediately; observer settlement stays separate.
    try {
      onFailure?.(error);
    } catch {
      /* An owner callback cannot replace the original trace refusal. */
    }
  };
  const observer = (observed) => {
    need(
      observed &&
        !Array.isArray(observed) &&
        Object.keys(observed).sort().join(",") ===
          (constructorMode
            ? "identity,kind,parentPid,toolSha256"
            : "identity,kind,parentPid") &&
        (!constructorMode || /^[a-f0-9]{64}$/u.test(observed.toolSha256)) &&
        ["sudo", "dtrace"].includes(observed.kind) &&
        Number.isSafeInteger(observed.parentPid) &&
        observed.parentPid > 0 &&
        observed.parentPid <= 0x7fffffff,
    );
    const identity = normalizeDarwinIdentity(observed.identity);
    return { ...observed, identity };
  };
  const retain = (observed) => {
    const { identity } = observed;
    need(
      !constructorMode ||
        owners.every(
          (owner) =>
            owner.kind !== observed.kind ||
            owner.toolSha256 === observed.toolSha256,
        ),
    );
    if (!owners.some((value) => sameDarwinIdentity(value.identity, identity)))
      owners.push({ ...observed, identity });
    return observed;
  };
  const retireOwned = async (owner) => {
    try {
      const state = retirementState(await observeObserver(owner.identity));
      if (state.status === "RETIRED") return state;
      const again = observer(await readObserver(owner.identity.pid));
      need(
        sameDarwinIdentity(owner.identity, again.identity) &&
          owner.kind === again.kind &&
          owner.parentPid === again.parentPid &&
          (!constructorMode || owner.toolSha256 === again.toolSha256),
      );
      need(
        retirementState(await retireObserver(owner.identity)).status ===
          "RETIRED",
      );
      return retirementState(await observeObserver(owner.identity));
    } catch (error) {
      // Reconcile disappearance only by a fresh observation of the bound birth.
      const state = retirementState(await observeObserver(owner.identity));
      if (state.status === "RETIRED") return state;
      throw error;
    }
  };
  const consume = (chunk) => {
    stdoutBytes += chunk.length;
    if (invalid) return;
    if (
      stdoutBytes > DARWIN_STARTUP_TRACE_LIMITS.bytes ||
      Date.now() >= captureDeadline ||
      (terminalSeparator && chunk.length > 0) ||
      chunk.some((byte) => byte !== 10 && (byte < 32 || byte > 126))
    ) {
      invalid = true;
      fail(new Error("Startup trace capture rejected"), "capture");
      return;
    }
    pending += chunk.toString("ascii");
    let newline;
    while ((newline = pending.indexOf("\n")) !== -1) {
      const line = pending.slice(0, newline);
      pending = pending.slice(newline + 1);
      let row;
      try {
        if (!line) {
          need(count > 0 && !terminalSeparator && !pending);
          terminalSeparator = true;
          continue;
        }
        if (constructorMode && !line.startsWith("armed ")) {
          need(
            armTime !== undefined &&
              line.length <= 512 &&
              BigInt(line.split(" ")[2]) >= armTime &&
              BigInt(line.split(" ")[2]) - armTime <= 30000000000n &&
              count < 32,
          );
          if (creators.consume(line)) creatorReady.resolve();
          if (count++) traceHash.update("\n");
          traceHash.update(line);
          continue;
        }
        row = traceRow(
          line,
          coldCommand ? DARWIN_STARTUP_TRACE_LIMITS.argumentBytes : 128,
        );
        need(coldCommand || !row.kind.startsWith("numeric-"));
        need(
          row.kind === "armed"
            ? armTime === undefined && withinArm()
            : armTime !== undefined &&
                row.pid === boundPid &&
                row.timestamp >= previousTime &&
                row.timestamp - armTime <= 30000000000n,
        );
        need(!exitSeen);
        // A pre-exec helper syscall cannot satisfy target startup coverage.
        need(
          !coldCommand ||
            row.kind === "armed" ||
            row.kind === "exec" ||
            execSeen,
        );
        if (row.kind === "exec") {
          need(execRequired && !execSeen);
          execSeen = true;
          executed.resolve();
        } else if (row.kind === "exit") {
          need(execSeen === execRequired);
          exitSeen = true;
        } else if (row.kind === "entry") syscallEntrySeen = true;
        else if (row.kind === "return") syscallReturnSeen = true;
        if (row.kind === "entry" && ARGUMENT_FUNCTIONS.includes(row.name))
          expectedArguments.set(
            row.name,
            (expectedArguments.get(row.name) ?? 0) + 1,
          );
        if (row.kind === "entry" && ["mmap", "mprotect"].includes(row.name))
          expectedNumeric.set(
            row.name,
            (expectedNumeric.get(row.name) ?? 0) + 1,
          );
        if (row.kind === "numeric-entry") {
          const key = `${row.thread}:${row.name}`;
          need(
            !pendingNumeric.has(key) &&
              numericSeen.length < DARWIN_STARTUP_TRACE_LIMITS.numeric,
          );
          const record = {
            operation: row.name,
            thread: row.thread,
            timestamp: String(row.timestamp),
            arguments: row.argument,
            result: null,
          };
          numericSeen.push(record);
          pendingNumeric.set(key, record);
        } else if (row.kind === "numeric-return") {
          const key = `${row.thread}:${row.name}`,
            record = pendingNumeric.get(key);
          need(record);
          record.result = {
            timestamp: String(row.timestamp),
            errno: row.error === "-1" ? null : Number(row.error),
            value: row.value,
          };
          pendingNumeric.delete(key);
        }
        if (row.kind === "argument-entry") {
          need(
            !pendingArguments.has(row.thread) &&
              argumentsSeen.length < DARWIN_STARTUP_TRACE_LIMITS.arguments,
          );
          const observation = {
            pid: row.pid,
            thread: row.thread,
            syscall: row.name,
            ...row.argument,
            result: null,
          };
          pendingArguments.set(row.thread, observation);
          argumentsSeen.push(observation);
        } else if (row.kind === "argument-return") {
          const observation = pendingArguments.get(row.thread);
          need(
            observation &&
              observation.syscall === row.name &&
              row.name !== "abort_with_payload",
          );
          observation.result = { errno: Number(row.error), value: row.value };
          pendingArguments.delete(row.thread);
        }
      } catch (error) {
        argumentMalformed ||= line.startsWith("argument-");
        invalid = true;
        fail(error, "capture");
        return;
      }
      const { kind, pid, timestamp } = row;
      previousTime = timestamp;
      if (kind === "armed") {
        armedPid = pid;
        armTime = timestamp;
        acknowledge();
      } else {
        if (count >= DARWIN_STARTUP_TRACE_LIMITS.rows) {
          invalid = true;
          fail(new Error("Startup trace row count exceeded bound"), "capture");
          return;
        }
        if (count++) traceHash.update("\n");
        traceHash.update(line);
      }
    }
    if (
      pending.length >
      (coldCommand ? DARWIN_STARTUP_TRACE_LIMITS.rowBytes : 1024)
    ) {
      argumentMalformed ||= pending.startsWith("argument-");
      invalid = true;
      fail(new Error("Startup trace record exceeded bound"), "capture");
    }
  };
  return {
    async arm() {
      if (!isMatchingCI) return { status };
      try {
        await verifyInstalled();
      } catch (error) {
        nativeException("darwin/startup-trace.js", error);
        return { status };
      }
      try {
        const identity = normalizeDarwinIdentity(binding.identity);
        need(
          !child &&
            !finished &&
            typeof readObserver === "function" &&
            typeof observeObserver === "function" &&
            typeof retireObserver === "function",
        );
        boundPid = identity.pid;
        parkedIdentity = identity;
        arming = true;
        const started = Date.now();
        armDeadline = started + 15000;
        captureDeadline = started + 30000;
        child = launch(
          "/usr/bin/sudo",
          [
            "--non-interactive",
            "--",
            "/usr/sbin/dtrace",
            "-q",
            // pid$1 descriptions acquire their own libproc tracking and retained
            // matches for replacement images. An explicit -p additionally makes
            // CLI completion depend on the grabbed helper's process state: it
            // must not end capture at SETEXEC before the target resumes.
            ...(coldCommand ? ["-Z"] : []),
            "-n",
            constructorMode
              ? CONSTRUCTOR_PROGRAM
              : coldCommand
                ? COLD_PROGRAM
                : PROGRAM,
            String(boundPid),
          ],
          {
            env: { PATH: "/usr/bin:/bin", LANG: "C" },
            stdio: ["ignore", "pipe", "pipe"],
          },
        );
        closed = new Promise((resolve) =>
          child.once("close", (code, signal) => {
            clearTimeout(captureTimer);
            exit = { code, signal };
            if (!invalid && Date.now() >= captureDeadline) {
              invalid = true;
              fail(new Error("Startup trace capture deadline"), "capture");
            }
            resolve();
            if (arming)
              fail(new Error("Startup trace closed before binding"), "attach");
            else if (
              constructorMode
                ? !targetIdentity
                : !exitSeen || (coldCommand && !targetIdentity)
            )
              fail(
                new Error("Startup trace closed before target completion"),
                "capture",
              );
          }),
        );
        child.on("error", (error) => fail(error, "attach"));
        observeNativeProcess("darwin/startup-trace.js", child);
        child.stdout.on("data", consume);
        child.stdout.on("error", (error) => {
          invalid = true;
          fail(error, "capture");
        });
        child.stderr.on("data", (chunk) => {
          stderrBytes += chunk.length;
          if (stderrBytes > 4096) {
            invalid = true;
            fail(new Error("Startup trace stderr exceeded bound"), "capture");
          } else
            fail(
              new Error(
                "Startup trace diagnostics prevent complete observation",
              ),
              "attach",
            );
        });
        child.stderr.on("error", (error) => {
          invalid = true;
          fail(error, "capture");
        });
        captureTimer = setTimeout(
          () => {
            invalid = true;
            fail(new Error("Startup trace capture deadline"), "capture");
          },
          Math.max(0, captureDeadline - Date.now()),
        );
        await bounded(
          (async () => {
            const wrapper = observer(await readObserver(child.pid));
            need(
              wrapper.identity.pid === child.pid &&
                wrapper.parentPid === parentPid &&
                withinArm(),
            );
            retain(wrapper);
            await onObserver?.(wrapper);
            await ready;
            let pid = armedPid;
            const chain = [];
            for (let index = 0; index < 4; index++) {
              need(withinArm());
              const owner = observer(await readObserver(pid));
              need(
                withinArm() &&
                  owner.identity.pid === pid &&
                  (index === 0
                    ? owner.kind === "dtrace"
                    : owner.kind === "sudo"),
              );
              chain.push(owner);
              if (pid === child.pid) {
                need(owner.parentPid === parentPid);
                break;
              }
              pid = owner.parentPid;
            }
            need(chain.at(-1).identity.pid === child.pid);
            for (const owner of chain) {
              need(withinArm());
              const again = await readObserver(owner.identity.pid);
              need(
                withinArm() &&
                  sameDarwinIdentity(owner.identity, again.identity) &&
                  owner.kind === again.kind &&
                  owner.parentPid === again.parentPid &&
                  (!constructorMode || owner.toolSha256 === again.toolSha256),
              );
            }
            need(withinArm());
            chain.forEach(retain);
            for (const owner of chain) await onObserver?.(owner);
            domainBound = true;
          })(),
          Math.max(0, armDeadline - Date.now()),
        );
        need(withinArm());
        status = "armed";
      } catch (error) {
        fail(error, invalid ? "capture" : "identity");
      } finally {
        arming = false;
      }
      return { status };
    },
    async receipt(value, signal) {
      let aborted;
      try {
        need(
          constructorMode &&
            status === "armed" &&
            !targetIdentity &&
            !signal?.aborted,
        );
        const pending = signal
          ? Promise.race([
              creatorReady.promise,
              new Promise((_, reject) => {
                aborted = () =>
                  reject(new Error("Constructor receipt interrupted"));
                signal.addEventListener("abort", aborted, { once: true });
                if (signal.aborted) aborted();
              }),
            ])
          : creatorReady.promise;
        await bounded(pending, Math.max(0, captureDeadline - Date.now()));
        need(
          !failure &&
            !exit &&
            !signal?.aborted &&
            domainBound &&
            Date.now() < captureDeadline,
        );
        const bytes = creators.receipt(value);
        targetIdentity = normalizeDarwinIdentity(value);
        return bytes;
      } catch (error) {
        fail(error, "capture");
        throw error;
      } finally {
        if (aborted) signal.removeEventListener("abort", aborted);
      }
    },
    refusal(value) {
      try {
        need(
          constructorMode &&
            domainBound &&
            targetIdentity &&
            Date.now() < captureDeadline,
        );
        return creators.refusal(value);
      } catch (error) {
        fail(error, "capture");
        throw error;
      }
    },
    async bindExec(value, signal) {
      let aborted;
      try {
        const target = normalizeDarwinIdentity(value);
        need(
          coldCommand &&
            status === "armed" &&
            !bindingExec &&
            !targetIdentity &&
            !signal?.aborted &&
            target.pidVersion !== parkedIdentity.pidVersion &&
            sameDarwinIdentity(parkedIdentity, {
              ...target,
              pidVersion: parkedIdentity.pidVersion,
            }),
        );
        bindingExec = true;
        // The native owner keeps the verified replacement image suspended until
        // this actual exec row arrives. BEGIN alone cannot release that image.
        const pending = signal
          ? Promise.race([
              executed.promise,
              new Promise((_, reject) => {
                aborted = () =>
                  reject(new Error("Startup trace release interrupted"));
                signal.addEventListener("abort", aborted, { once: true });
                if (signal.aborted) aborted();
              }),
            ])
          : executed.promise;
        await bounded(pending, Math.max(0, captureDeadline - Date.now()));
        need(
          !failure &&
            !exit &&
            !signal?.aborted &&
            domainBound &&
            Date.now() < captureDeadline,
        );
        targetIdentity = target;
        return { status: "bound" };
      } catch (error) {
        fail(error, "capture");
        throw error;
      } finally {
        if (aborted) signal.removeEventListener("abort", aborted);
      }
    },
    finish() {
      return (finished ??= (async () => {
        if (!child)
          return {
            status,
            cleanup: "NOT_RUN",
            ...(coldCommand
              ? {
                  runtime: numericRuntime(),
                  numericStatus: "unavailable",
                  programSha256: digest(COLD_PROGRAM),
                }
              : {}),
          };
        let cleanup = "UNCERTAIN";
        let retirementFailed = false;
        try {
          // The target is already independently retired. exit(0) ends tracing;
          // a timeout still requires identity-safe retirement, never child.kill.
          try {
            await bounded(closed, 10000);
          } catch (error) {
            fail(error, "retirement");
            const attempts = await bounded(
              Promise.allSettled(owners.map(retireOwned)),
              10000,
            ).catch((error) => {
              fail(error, "retirement");
              return null;
            });
            try {
              requireRetired(attempts);
            } catch (error) {
              fail(error, "retirement");
              retirementFailed = true;
            }
            await bounded(closed, 10000).catch((error) => {
              fail(error, "retirement");
              retirementFailed = true;
            });
          }
          const observations = await bounded(
            Promise.allSettled(owners.map(retireOwned)),
            10000,
          );
          requireRetired(observations);
          need(
            !retirementFailed &&
              domainBound &&
              owners.some((owner) => owner.identity.pid === child.pid),
          );
          cleanup = "RETIRED";
        } catch (error) {
          fail(error, "retirement");
        }
        clearTimeout(captureTimer);
        if (!child.stdout.readableEnded || !child.stderr.readableEnded) {
          invalid = true;
          cleanup = "UNCERTAIN";
          fail(new Error("Startup trace streams did not drain"), "retirement");
          await bounded(
            Promise.all(
              [child.stdout, child.stderr].map(
                (stream) =>
                  new Promise((resolve) => {
                    if (stream.closed) return resolve();
                    stream.once("close", resolve);
                    stream.destroy();
                  }),
              ),
            ),
            1000,
          ).catch((error) => fail(error, "retirement"));
        }
        let constructorEvidence, refusalEvidence;
        if (constructorMode) {
          try {
            refusalEvidence = creators.diagnostic();
            if (refusalEvidence?.cleanup === "UNCERTAIN")
              throw new Error("Refusal observer settlement is uncertain");
          } catch (error) {
            cleanup = "UNCERTAIN";
            fail(error, "retirement");
          }
          try {
            constructorEvidence = creators.complete();
          } catch (error) {
            invalid = true;
            fail(error, "capture");
          }
        }
        const mandatory = constructorMode
          ? !!constructorEvidence
          : execSeen === execRequired &&
            exitSeen &&
            syscallEntrySeen &&
            syscallReturnSeen &&
            (!coldCommand || !!targetIdentity);
        if (!invalid && !pending && !mandatory)
          fail(
            new Error("Startup trace missing mandatory observations"),
            "capture",
          );
        const intact =
          !invalid &&
          !pending &&
          count > 0 &&
          mandatory &&
          child.stdout.readableEnded &&
          child.stderr.readableEnded;
        const complete = intact && !stderrBytes;
        if (!complete) {
          status = intact ? "refused" : "partial";
        } else if (
          !failure &&
          exit?.code === 0 &&
          !exit.signal &&
          status === "armed"
        )
          status = "observed";
        else if (!failure) status = "refused";
        const argumentsObserved =
          complete && status === "observed"
            ? argumentsSeen.map((record) => ({
                ...record,
                pairing: record.result
                  ? "returned"
                  : record.syscall === "abort_with_payload"
                    ? "nonreturning"
                    : "missing-return",
                text:
                  record.result || record.syscall === "abort_with_payload"
                    ? record.text
                    : null,
              }))
            : null;
        const missingArguments =
          argumentsObserved &&
          [...expectedArguments].some(
            ([name, count]) =>
              argumentsObserved.filter(({ syscall }) => syscall === name)
                .length < count,
          );
        const argumentStatus = argumentMalformed
          ? "malformed"
          : !argumentsObserved
            ? "unavailable"
            : (["copy-failed", "missing", "truncated", "unsupported"].find(
                (state) =>
                  (state === "missing" && missingArguments) ||
                  argumentsObserved.some(
                    (record) =>
                      record.acquisition === state ||
                      record.completeness === state ||
                      (state === "missing" &&
                        record.pairing === "missing-return"),
                  ),
              ) ?? (argumentsObserved.length ? "complete" : "empty"));
        return {
          status,
          cleanup,
          exit: exit ?? null,
          failure: failure ?? null,
          cleanupFailure: cleanupFailure ?? null,
          captureComplete: complete,
          argumentStatus,
          arguments: argumentsObserved,
          ...(constructorMode
            ? {
                programSha256: DARWIN_CONSTRUCTOR_TRACE_INTENT.programSha256,
                creator: constructorEvidence ?? null,
                refusal: refusalEvidence ?? null,
              }
            : {}),
          ...(coldCommand
            ? {
                runtime: numericRuntime(
                  complete && status === "observed" ? numericSeen : [],
                ),
                numericStatus:
                  !complete || status !== "observed"
                    ? "unavailable"
                    : pendingNumeric.size ||
                        (numericSeen.length > 0 &&
                          Object.keys(NUMERIC_ARGUMENTS).some(
                            (name) =>
                              !numericSeen.some(
                                (record) => record.operation === name,
                              ),
                          )) ||
                        [...expectedNumeric].some(
                          ([name, count]) =>
                            numericSeen.filter(
                              (record) => record.operation === name,
                            ).length !== count,
                        )
                      ? "missing"
                      : numericSeen.length
                        ? "complete"
                        : "empty",
                programSha256: digest(COLD_PROGRAM),
              }
            : {}),
          observers: owners,
          events: complete && status === "observed" ? count : null,
          sha256:
            complete && status === "observed" ? traceHash.digest("hex") : null,
        };
      })());
    },
  };
}
