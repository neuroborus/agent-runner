import { execFile, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { once } from "node:events";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rename,
  writeFile,
} from "node:fs/promises";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import {
  LITERAL_ARGUMENTS,
  feasibilityCapabilities,
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
function completed(exit, signal = null) {
  if (exit.signal === signal && exit.code === (signal ? null : 0)) return;
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

/** A small experiment policy, independent of the full reviewed policy factory. */
export function darwinFeasibilityPolicy(root, workspaceWrite = false) {
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
  const quote = (value) =>
    `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
  const literal = (relative) =>
    `(literal ${quote(path.posix.join(root, relative))})`;
  const images = ["build/helper", "build/argv-fixture", "build/git"]
    .map(literal)
    .join(" ");
  const runtime = '(subpath "/usr/lib") (subpath "/System/Library")';
  return [
    "(version 1)",
    "(deny default)",
    "(allow process-fork)",
    "(allow process-info* (target same-sandbox))",
    `(allow process-exec ${images})`,
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

function failure(stage, error) {
  const timedOut =
    error?.killed === true ||
    error?.signal === "SIGALRM" ||
    error?.code === "ERR_FEASIBILITY_DEADLINE";
  const operation = ACCESS_OPERATIONS.includes(error?.operation)
    ? ` ${error.operation}`
    : "";
  return {
    code: timedOut
      ? "deadline"
      : error?.signal
        ? "crash"
        : error?.code === "ERR_FEASIBILITY_ESCAPE"
          ? "observed-escape"
          : error?.code === 78 || error?.code === "ERR_FEASIBILITY_UNAVAILABLE"
            ? "prerequisite-unavailable"
            : "setup-failed",
    detail: `Darwin ${stage}${operation} ${timedOut ? "exceeded its deadline" : error?.signal ? "terminated by signal" : error?.code === "ERR_FEASIBILITY_ESCAPE" ? "changed a protected sentinel or completed a prohibited operation" : error?.code === 78 || error?.code === "ERR_FEASIBILITY_UNAVAILABLE" ? "requires an unavailable native prerequisite" : "failed before complete observation"}.`,
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
async function command(file, args, cwd, env = ENV, timeout = 12000) {
  return execute(file, args, {
    cwd,
    env,
    encoding: "utf8",
    timeout,
    maxBuffer: 65536,
  });
}
async function native(root, operation, ...args) {
  const { stdout } = await command(
    path.join(root, "build/helper"),
    [operation, ...args],
    root,
  );
  return JSON.parse(stdout);
}
async function persist(root, name, value) {
  await writeFile(
    path.join(root, "evidence", `${name}.json`),
    JSON.stringify(value),
    { flag: "wx", mode: 0o600 },
  );
}

/* Interactive helpers stay parked until their receipt is independently joined.
 * Deadlines reject without a numeric-PID signal; recorded identity owns teardown. */
function session(root, operation, ...args) {
  const child = spawn(path.join(root, "build/helper"), [operation, ...args], {
    cwd: root,
    env: { ...ENV, NATIVE_OWNERSHIP_CUSTODY: "true" },
    stdio: ["pipe", "pipe", "pipe"],
  });
  const records = [],
    waiting = [];
  let bytes = "",
    transcript = "",
    failureCause = null,
    ended = false,
    total = 0,
    consumed = 0,
    exit;
  const closed = new Promise((resolve) =>
    child.once("close", (code, signal) => {
      ended = true;
      exit = { code, signal };
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
                Object.assign(new Error("Native pipe closure deadline"), {
                  code: "ERR_FEASIBILITY_DEADLINE",
                }),
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
      if (failureCause) reject(failureCause);
      else if (records.length) {
        consumed++;
        resolve(records.shift());
      } else reject(Object.assign(new Error("Missing native receipt"), exit));
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
    if (total > 65536) {
      failureCause ??= new Error("Oversized native output");
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
    finish: async (signal = null) => {
      await waitClosed();
      if (failureCause) throw failureCause;
      assertDarwinFeasibilityTranscript(transcript, consumed);
      completed(exit, signal);
    },
    next: () =>
      new Promise((resolve, reject) => {
        const waiter = {
          resolve,
          reject,
          timer: setTimeout(() => {
            waiting.splice(waiting.indexOf(waiter), 1);
            reject(
              Object.assign(new Error("Native receipt deadline"), {
                code: "ERR_FEASIBILITY_DEADLINE",
              }),
            );
          }, 12000),
        };
        waiting.push(waiter);
        drain();
      }),
  };
}

async function build(root, components) {
  let clang, sdk, version;
  try {
    clang = (
      await command("/usr/bin/xcrun", ["--find", "clang"], root)
    ).stdout.trim();
    sdk = (
      await command("/usr/bin/xcrun", ["--show-sdk-path"], root)
    ).stdout.trim();
    version = (
      await command("/usr/bin/xcrun", ["--show-sdk-version"], root)
    ).stdout.trim();
  } catch (error) {
    if (
      error.code === "ENOENT" ||
      (Number.isInteger(error.code) &&
        !error.signal &&
        !error.killed &&
        /unable to find utility|SDK.*cannot be located|invalid active developer path|no developer tools were found/u.test(
          error.stderr ?? "",
        ))
    )
      error.code = "ERR_FEASIBILITY_UNAVAILABLE";
    throw error;
  }
  need(path.isAbsolute(clang) && path.isAbsolute(sdk));
  clang = await realpath(clang);
  sdk = await realpath(sdk);
  const compilerVersion = (await command(clang, ["--version"], root)).stdout
    .split("\n")[0]
    .trim();
  components.push({
    role: "tool",
    name: "apple-clang",
    version: compilerVersion,
    sha256: digest(await readFile(clang)),
  });
  components.push({
    role: "tool",
    name: "macos-sdk",
    version,
    sha256: digest(await readFile(path.join(sdk, "SDKSettings.json"))),
  });
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
      "-o",
      path.join(root, "build", name),
      path.join(SOURCE, source),
    ];
    await command(clang, args, root, ENV, 60000);
    const file = path.join(root, "build", name);
    await chmod(file, 0o500);
    const bytes = await readFile(file);
    inspectDarwinMachO(bytes);
    components.push({
      role: "helper",
      name,
      version: "1",
      sha256: digest(bytes),
    });
    builds.push({
      args,
      sourceSha256: digest(await readFile(path.join(SOURCE, source))),
    });
  }
  const git = await realpath(
    (await command("/usr/bin/xcrun", ["--find", "git"], root)).stdout.trim(),
  );
  // Stock Git can be universal; the matching native loader selects its slice.
  // Only the experiment's explicitly x64 compiled helpers use the thin validator.
  const gitBytes = await readFile(git);
  await writeFile(path.join(root, "build/git"), gitBytes, {
    flag: "wx",
    mode: 0o500,
  });
  components.push({
    role: "tool",
    name: "apple-git",
    version: (await command(git, ["--version"], root)).stdout.trim(),
    sha256: digest(gitBytes),
  });
  await persist(root, "build", { components, builds, git });
  return components;
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
async function argvEntry(root, components, sentinel) {
  const started = performance.now();
  const file = path.join(root, "evidence/argv.sb");
  await writeFile(file, darwinFeasibilityPolicy(root), {
    flag: "wx",
    mode: 0o600,
  });
  const running = session(
    root,
    "exec",
    file,
    path.join(root, "build/argv-fixture"),
    ...LITERAL_ARGUMENTS,
  );
  let identity;
  try {
    need((await running.next()).phase === "armed");
    identity = normalizeDarwinIdentity(
      await native(root, "identity", String(running.child.pid)),
    );
    const policy = await native(
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
      retired = await native(
        root,
        "observe",
        ...darwinFeasibilityIdentityArguments(identity),
      );
    need(retired.status === "RETIRED");
    const after = await snapshots(root);
    need(JSON.stringify(sentinel) === JSON.stringify(after));
    const observation = { identity, policy, args, retired, after };
    await persist(root, "argv", observation);
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
    running.child.stdin.end();
    if (identity)
      try {
        await native(
          root,
          "retire",
          ...darwinFeasibilityIdentityArguments(identity),
        );
      } catch {
        /* Identity uncertainty retains exclusion. */
      }
    await running.waitClosed().catch(() => {});
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
    return unavailable(ACCESS, failure("access", error), components, true);
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
      failure("storage", error),
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
      decision?.cause ?? failure(caseId, error),
      components,
      !(error.code === 78 && identities.length === 0),
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
    const temporary = await realpath(process.env.RUNNER_TEMP);
    root = await realpath(await mkdtemp(path.join(temporary, "nf-")));
    await chmod(root, 0o700);
    const nonce = randomBytes(16).toString("hex");
    for (const name of ["build", "evidence"])
      await mkdir(path.join(root, name), { mode: 0o700 });
    stage = "build";
    await build(root, components);
    stage = "identity-prerequisites";
    need(
      (await native(root, "prerequisites", root)).identitySafeSignal === true,
    );
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
    results.push(await argvEntry(root, components, baseline));
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
    const possible =
      root !== undefined &&
      stage !== "build" &&
      stage !== "prerequisites" &&
      !(stage === "identity-prerequisites" && error.code === 78);
    return [
      ...results,
      ...unavailable(
        ids.filter(
          (id) => !results.some(({ capability }) => capability === id),
        ),
        failure(stage, error),
        components,
        possible,
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
