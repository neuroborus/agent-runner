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
import {
  darwinStartupCrashDetail,
  readDarwinStartupCrash,
} from "./startup-crash.js";
import {
  LITERAL_ARGUMENTS,
  feasibilityCapabilities,
  feasibilityFailureCause,
  unavailableFeasibilityResults,
} from "../feasibility/index.js";
import {
  digest,
  inspectDarwinMachO,
  normalizeDarwinIdentity,
  sameDarwinIdentity,
} from "./protocol.js";

const execute = promisify(execFile);
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

/** Individual recorded retirement is cleanup, never a complete domain boundary. */
export function assessDarwinFeasibilityDomain(observations) {
  need(
    Array.isArray(observations) &&
      observations.length === 2 &&
      observations.every(
        (value) => value?.status === "LIVE" || value?.status === "RETIRED",
      ),
  );
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
    "task-release",
    "audit-signal",
    "prerequisite-pipe",
    "prerequisite-fork",
    "prerequisite-close",
    "prerequisite-wait",
    "prerequisite-backstop",
    "prerequisite-child-status",
    "prerequisite-settlement",
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
          (!fields[1] && fields[2] === "sandbox-apply" && fields[4] === "-1"))
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
  const suffix = `${phase ? `; phase=${phase}` : ""}${abort ? `; abort-cause=${abort}` : ""}${crashDetail}`;
  return {
    ...diagnosed,
    detail: detail.slice(0, 256 - suffix.length) + suffix,
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
  { launch = spawn } = {},
) {
  const requiredPhases = expectedPhases(operation);
  // The existing self-exec fault vector has no argv fixture main.
  const phaseCount =
    operation === "exec" &&
    args.length === 3 &&
    args[1] === path.join(root, "build/helper") &&
    args[2] === "fault"
      ? requiredPhases.length - 1
      : requiredPhases.length;
  let child;
  try {
    child = launch(path.join(root, "build/helper"), [operation, ...args], {
      cwd: root,
      env: { ...ENV, NATIVE_OWNERSHIP_CUSTODY: "true" },
      stdio: ["pipe", "pipe", "pipe"],
    });
  } catch (error) {
    throw Object.assign(error, {
      nativeOperation: operation,
      nativePhases: [],
    });
  }
  const records = [],
    waiting = [];
  let bytes = "",
    transcript = "",
    stderr = Buffer.alloc(0),
    failureCause = null,
    ended = false,
    total = 0,
    consumed = 0,
    phases = [],
    exit;
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
  child.on("error", (error) => {
    failureCause ??= error;
    drain();
  });
  child.stdin.on("error", (error) => {
    failureCause ??= error;
    drain();
  });
  child.stderr.on("data", (chunk) => {
    total += chunk.length;
    stderr = Buffer.concat([stderr, chunk.subarray(0, 65536 - stderr.length)]);
    try {
      need(total <= 65536);
      phases = darwinFeasibilityPhases(stderr, operation, false);
    } catch (error) {
      failureCause ??= error;
      drain();
    }
  });
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    if (failureCause) return;
    total += Buffer.byteLength(chunk);
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
      failureCause ??= error;
    }
    drain();
  });
  return {
    child,
    waitClosed,
    diagnostic: () => prerequisiteDiagnostic({ stderr }),
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
            failureCause ??= error;
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
  let operation = "compiler-discovery";
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
    const builds = [];
    for (const [source, name] of [
      ["feasibility-helper.c", "helper"],
      ["argv-fixture.c", "argv-fixture"],
    ]) {
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
        ...(name === "helper" ? ["-lsandbox"] : []),
        ...(name === "helper" && commandObservation
          ? ["-DNATIVE_FEASIBILITY_COMMAND", "-lbsm"]
          : []),
        "-o",
        path.join(root, "build", name),
        path.join(SOURCE, source),
      ];
      operation = `${name}-compile-link`;
      await run(clang, args, 60000);
      const file = path.join(root, "build", name);
      operation = `${name}-acquisition`;
      await recordResource(file);
      operation = `${name}-publication`;
      await fs.chmod(file, 0o500);
      await recordResource(file);
      const bytes = await fs.readFile(file);
      operation = `${name}-inspection`;
      inspectDarwinMachO(bytes);
      components.push({
        role: "helper",
        name,
        version: "1",
        sha256: digest(bytes),
      });
      operation = `${name}-source-identity`;
      builds.push({
        args,
        sourceSha256: digest(await fs.readFile(path.join(SOURCE, source))),
        ...(name === "helper"
          ? {
              bindingSha256: digest(
                await fs.readFile(path.join(SOURCE, "feasibility-sandbox.h")),
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
    throw Object.assign(new Error("Darwin build operation failed."), {
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
    });
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
    openSession = session,
    inspect = native,
    readSnapshots = snapshots,
    save = persist,
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
    let running, identity;
    try {
      if (operation !== "fixture-control")
        await write(
          file,
          operation === "policy-invalid"
            ? "(version 1)\n(deliberately-invalid-policy)\n"
            : darwinFeasibilityPolicy(
                root,
                false,
                operation !== "exec-control",
              ),
          { flag: "wx", mode: 0o600 },
        );
      const args =
        operation === "fixture-control"
          ? LITERAL_ARGUMENTS
          : operation === "exec-control"
            ? [file, fixture, ...LITERAL_ARGUMENTS]
            : [file];
      running = openSession(root, operation, ...args);
      need(
        JSON.stringify(await running.next()) ===
          JSON.stringify({ phase: "armed" }),
      );
      identity = normalizeDarwinIdentity(
        await inspect(root, "identity", String(running.child.pid)),
      );
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
      const after = await readSnapshots(root);
      need(JSON.stringify(sentinel) === JSON.stringify(after));
      const observed = {
        operation,
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
      error.nativeOperation = operation;
      await retireStartup(root, running, identity, error, inspect);
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
    openSession = session,
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
  const startedAt = Date.now();
  let running, identity;
  try {
    await write(file, darwinFeasibilityPolicy(root), {
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
    need(
      JSON.stringify(await running.next()) ===
        JSON.stringify({ phase: "armed" }),
    );
    identity = normalizeDarwinIdentity(
      await inspect(root, "identity", String(running.child.pid)),
    );
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
    const after = await readSnapshots(root);
    need(JSON.stringify(sentinel) === JSON.stringify(after));
    const observation = {
      operation: "exec",
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
    error.nativeOperation = "exec";
    await retireStartup(root, running, identity, error, inspect);
    if (error.signal === "SIGABRT" && running?.child.pid) {
      error.nativeCrash = await readDarwinStartupCrash({
        pid: running.child.pid,
        image: path.join(root, "build/argv-fixture"),
        sha256: components.find(
          ({ role, name }) => role === "helper" && name === "argv-fixture",
        )?.sha256,
        startedAt,
        endedAt: Date.now(),
      });
    }
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
    try {
      await close();
    } catch {
      /* The original setup failure remains authoritative. */
    }
    throw error;
  }
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
      await writeFile(file, darwinFeasibilityPolicy(root, edit), {
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
      const receipts = [],
        operations = ACCESS_OPERATIONS;
      let identity,
        retired,
        policy,
        sessionCleanupFailed = false;
      try {
        receipts.push(await running.next());
        need(receipts[0].event === "ready");
        identity = normalizeDarwinIdentity(
          await native(root, "identity", String(running.child.pid)),
        );
        policy = await native(
          root,
          "policy",
          ...darwinFeasibilityIdentityArguments(identity),
        );
        need(policy.sandboxed === true);
        running.child.stdin.end("A");
        for (let index = 0; index < operations.length * 2; index++)
          receipts.push(await running.next());
        await running.finish();
        retired = await native(
          root,
          "observe",
          ...darwinFeasibilityIdentityArguments(identity),
        );
        need(retired.status === "RETIRED");
      } finally {
        running.child.stdin.end();
        if (identity)
          try {
            need(
              (
                await native(
                  root,
                  "retire",
                  ...darwinFeasibilityIdentityArguments(identity),
                )
              ).status === "RETIRED",
            );
          } catch {
            sessionCleanupFailed = true;
          }
        try {
          await running.waitClosed();
        } catch {
          sessionCleanupFailed = true;
        }
      }
      need(!sessionCleanupFailed);
      need(
        receipts.length === 1 + operations.length * 2 &&
          receipts[0].event === "ready",
      );
      for (const [index, operation] of operations.entries()) {
        const attempt = receipts[1 + index * 2],
          completed = receipts[2 + index * 2];
        need(
          attempt.event === "attempt" &&
            attempt.operation === operation &&
            completed.event === "completed" &&
            completed.operation === operation,
        );
        const permitted =
          ["inspect", "git-status"].includes(operation) ||
          (edit && operation === "edit");
        if (!permitted && completed.error === 0)
          throw Object.assign(
            new Error("Prohibited Darwin operation completed"),
            { code: "ERR_FEASIBILITY_ESCAPE", operation },
          );
        need(
          permitted ? completed.error === 0 : [1, 13].includes(completed.error),
        );
      }
      const gitIdentity = normalizeDarwinIdentity(receipts[5].child);
      const gitRetired = await native(
        root,
        "observe",
        ...darwinFeasibilityIdentityArguments(gitIdentity),
      );
      need(gitRetired.status === "RETIRED");
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
          if (error.code !== "ENOENT") throw error;
          absent = true;
        }
        need(absent);
      }
      await outside.check();
      observations.push({
        name,
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
    try {
      await outside?.close();
    } catch {
      /* Retain the original cause and cleanup uncertainty. */
    }
    return unavailable(
      ACCESS,
      darwinFeasibilityCause("access", error),
      components,
      true,
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
    running.child.stdin.end();
    if (identity)
      try {
        await native(
          root,
          "retire",
          ...darwinFeasibilityIdentityArguments(identity),
        );
      } catch {
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
  const started = performance.now(),
    policy = path.join(root, "evidence", `${caseId}.sb`);
  await writeFile(policy, darwinFeasibilityPolicy(root), {
    flag: "wx",
    mode: 0o600,
  });
  const running = session(
      root,
      "exec",
      policy,
      path.join(root, "build/helper"),
      "fault",
    ),
    identities = [];
  let cleanup = uncertain(),
    decision;
  try {
    const armed = await running.next();
    need(armed.event === "armed");
    const owner = normalizeDarwinIdentity(armed.owner),
      descendant = normalizeDarwinIdentity(armed.descendant);
    need(owner.pid === running.child.pid && owner.pid !== descendant.pid);
    identities.push(owner, descendant);
    for (const expected of identities) {
      need(
        sameDarwinIdentity(
          expected,
          await native(root, "identity", String(expected.pid)),
        ),
      );
      need(
        (
          await native(
            root,
            "policy",
            ...darwinFeasibilityIdentityArguments(expected),
          )
        ).sandboxed === true,
      );
    }
    const receipt = {
      checkoutSha,
      caseId,
      owner,
      descendant,
      sandboxed: true,
      completeDomainBoundary: false,
    };
    await persist(root, `${caseId}-intent`, receipt);
    const intentFile = path.join(root, "evidence", `${caseId}-intent.json`),
      intentSha256 = digest(JSON.stringify(receipt));
    need(digest(await readFile(intentFile)) === intentSha256);
    const released = performance.now();
    running.child.stdin.write("A");
    need((await running.next()).event === "detached");
    running.child.stdin.write(caseId === "cancel" ? "C" : "L");
    const acknowledged = await running.next();
    need(acknowledged.event === "fault-ack" && acknowledged.caseId === caseId);
    need(
      (
        await native(
          root,
          caseId === "cancel" ? "cancel" : "retire",
          ...darwinFeasibilityIdentityArguments(owner),
        )
      ).status === "RETIRED",
    );
    await running.finish(caseId === "cancel" ? "SIGTERM" : "SIGKILL");
    const observations = [];
    for (const i of identities)
      observations.push(
        await native(root, "observe", ...darwinFeasibilityIdentityArguments(i)),
      );
    if (performance.now() - released >= 25000)
      throw Object.assign(new Error("Fault fixture safety deadline"), {
        code: "ERR_FEASIBILITY_DEADLINE",
      });
    need(digest(await readFile(intentFile)) === intentSha256);
    decision = assessDarwinFeasibilityDomain(observations);
    const closing = performance.now();
    for (const i of identities)
      need(
        (await native(root, "retire", ...darwinFeasibilityIdentityArguments(i)))
          .status === "RETIRED",
      );
    const fresh = [];
    for (const i of identities) {
      const value = await native(
        root,
        "observe",
        ...darwinFeasibilityIdentityArguments(i),
      );
      need(value.status === "RETIRED");
      fresh.push(value);
    }
    const after = await snapshots(root);
    need(JSON.stringify(after) === JSON.stringify(baseline));
    // This cleans recorded fixtures only. Surviving descendants retain FAIL.
    cleanup = settled(
      { fresh, after, completeDomainBoundary: false },
      performance.now() - closing,
      observations.some(({ status }) => status === "LIVE"),
    );
    await persist(root, caseId, {
      receipt,
      acknowledged,
      observations,
      decision,
      cleanup,
    });
    return result(
      `ownership.${caseId}`,
      components,
      { receipt, acknowledged, observations },
      baseline,
      after,
      cleanup,
      started,
      decision,
    );
  } catch (error) {
    running.child.stdin.end();
    for (const i of identities)
      try {
        await native(root, "retire", ...darwinFeasibilityIdentityArguments(i));
      } catch {
        /* No numeric-PID fallback. */
      }
    await running.waitClosed().catch(() => {});
    return unavailable(
      [`ownership.${caseId}`],
      decision?.cause ?? darwinFeasibilityCause(caseId, error),
      components,
      true,
    )[0];
  }
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
      // Another fixed fault is safe only after fresh recorded-fixture retirement.
      // This does not promote intervention into whole-domain cleanup evidence.
      if (!entry.cleanup.independent || !entry.cleanup.witnessSha256) break;
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
      } catch {
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
    const firstCause = darwinFeasibilityCause(operation, error);
    const retirement = await cleanup(error);
    throw Object.assign(new Error("Darwin preparation failed."), {
      feasibilityCause: firstCause,
      feasibilityCleanup: retirement,
    });
  }
}
