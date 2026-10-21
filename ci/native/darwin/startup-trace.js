import { spawn } from "node:child_process";
import { lstat, realpath } from "node:fs/promises";
import { constants as osConstants } from "node:os";
import {
  digest,
  normalizeDarwinIdentity,
  sameDarwinIdentity,
} from "./protocol.js";
import { nativeException, observeNativeProcess } from "../diagnostics.js";

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
const PROGRAM = `#pragma D option quiet
#pragma D option strsize=129
dtrace:::BEGIN { printf("armed %d %llu\\n", pid, timestamp); }
syscall:::entry /pid == $1/ { printf("entry %d %llu %s\\n", pid, timestamp, probefunc); }
syscall:::entry /pid == $1 && (${probes([...Object.keys(PATH_ARGUMENTS), "abort_with_payload"])})/ {
  self->operation = probefunc; self->namespace = probefunc == "abort_with_payload" ? (uint32_t)arg0 : 0;
  self->code = probefunc == "abort_with_payload" ? (uint64_t)arg1 : 0;
  self->pointer = probefunc == "abort_with_payload" ? arg4 : (${probes(Object.keys(PATH_ARGUMENTS).filter((name) => PATH_ARGUMENTS[name] === 1))}) ? arg1 : arg0;
  self->copying = self->pointer != 0; self->text = self->pointer ? copyinstr(self->pointer, 128) : "";
  self->copying = 0;
  printf("argument-entry %d %llu %s %llu %s %u %llu %S\\n", pid, timestamp, probefunc, (uint64_t)tid, self->pointer == 0 ? "missing" : strlen(self->text) < 128 ? "complete" : "truncated", (uint32_t)self->namespace, (uint64_t)self->code, self->text);
  self->text = 0; self->operation = 0;
}
syscall:::entry /pid == $1 && probefunc == "csrctl"/ { printf("argument-entry %d %llu %s %llu complete %u 0 \\n", pid, timestamp, probefunc, (uint64_t)tid, (uint32_t)arg0); }
syscall:::entry /pid == $1 && (probefunc == "sysctl" || probefunc == "sysctlbyname")/ { printf("argument-entry %d %llu %s %llu unsupported 0 0 \\n", pid, timestamp, probefunc, (uint64_t)tid); }
dtrace:::ERROR /pid == $1 && self->copying/ { printf("argument-entry %d %llu %s %llu copy-failed %u %llu \\n", pid, timestamp, self->operation, (uint64_t)tid, (uint32_t)self->namespace, (uint64_t)self->code); self->copying = 0; self->operation = 0; }
syscall:::return /pid == $1/ { printf("return %d %llu %s %d %lld\\n", pid, timestamp, probefunc, errno, (int64_t)arg0); }
syscall:::return /pid == $1 && (${probes(ARGUMENT_FUNCTIONS.filter((name) => name !== "abort_with_payload"))})/ { printf("argument-return %d %llu %s %llu %d %lld\\n", pid, timestamp, probefunc, (uint64_t)tid, errno, (int64_t)arg0); }
proc:::exec-success /pid == $1/ { printf("exec %d %llu\\n", pid, timestamp); }
proc:::exit /pid == $1/ { printf("exit %d %llu\\n", pid, timestamp); exit(0); }
`;
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
  PROGRAM +
  Object.entries(NUMERIC_ARGUMENTS)
    .map(([name, args]) => {
      const syscall = name === "mmap" || name === "mprotect",
        provider = syscall
          ? "syscall::"
          : `pid$1:${name === "sysconf" ? "libsystem_c.dylib" : "libsystem_pthread.dylib"}:`,
        probe = syscall ? `${provider}:` : `${provider}${name}:`,
        predicate = `pid == $1${syscall ? ` && probefunc == "${name}"` : ""}`;
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
function traceRow(line) {
  const fields = line.split(" "),
    [kind, pid, time, name] = fields;
  need(
    line.length <= 1024 &&
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
    need(text.length <= 512 && !tokens.some(isNul));
    need(
      string
        ? (state === "complete" && tokens.length < 128) ||
            (state === "truncated" && tokens.length === 128) ||
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
  } = {},
) {
  need(typeof coldCommand === "boolean");
  let boundPid,
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
    rows = [],
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
  const fail = (error, reason) => {
    nativeException("darwin/startup-trace.js", error);
    const facts = traceFailure(error, reason);
    failure ??= facts;
    if (reason === "retirement") cleanupFailure ??= facts;
    status = reason === "capture" ? "partial" : "refused";
    refuse(error);
  };
  const observer = (observed) => {
    need(
      observed &&
        !Array.isArray(observed) &&
        Object.keys(observed).sort().join(",") === "identity,kind,parentPid" &&
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
          owner.parentPid === again.parentPid,
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
      stdoutBytes > 65536 ||
      Date.now() >= captureDeadline ||
      (terminalSeparator && chunk.length > 0) ||
      [...chunk].some((byte) => byte !== 10 && (byte < 32 || byte > 126))
    ) {
      invalid = true;
      rows.length = 0;
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
        row = traceRow(line);
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
        if (row.kind === "exec") {
          need(!execSeen);
          execSeen = true;
        } else if (row.kind === "exit") {
          need(execSeen);
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
          need(!pendingNumeric.has(key) && numericSeen.length < 64);
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
          need(!pendingArguments.has(row.thread) && argumentsSeen.length < 64);
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
        rows.length = 0;
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
        count++;
        rows.push(line);
      }
    }
    if (pending.length > 1024) {
      argumentMalformed ||= pending.startsWith("argument-");
      invalid = true;
      rows.length = 0;
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
            ...(coldCommand ? ["-Z"] : []),
            "-n",
            coldCommand ? COLD_PROGRAM : PROGRAM,
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
                  owner.parentPid === again.parentPid,
              );
            }
            need(withinArm());
            chain.forEach(retain);
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
        const mandatory =
          execSeen && exitSeen && syscallEntrySeen && syscallReturnSeen;
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
          rows.length = 0;
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
            complete && status === "observed" ? digest(rows.join("\n")) : null,
        };
      })());
    },
  };
}
