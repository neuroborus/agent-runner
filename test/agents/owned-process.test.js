import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readlinkSync, realpathSync } from "node:fs";
import { dirname } from "node:path";
import test from "node:test";

import {
  assertOwnedProcessLauncherProtected,
  inspectOwnedSessionProcesses,
  resolveOwnedProcessLauncher,
  spawnOwnedProcess,
  terminateOwnedProcess,
} from "../../src/agents/index.js";

const INITIAL_PID_NAMESPACE = "pid:[4026531836]";

test("read-only launcher mounts still protect namespace-root paths", () => {
  const launcher = realpathSync(process.execPath);
  const protectedAncestor = dirname(dirname(launcher));
  const readOnlyLauncher = [
    { id: 1, mountPoint: "/", readOnly: false },
    { id: 2, mountPoint: protectedAncestor, readOnly: true },
  ];
  assert.doesNotThrow(() =>
    assertOwnedProcessLauncherProtected(launcher, {
      canWrite: () => true,
      mounts: readOnlyLauncher,
    }),
  );

  assert.throws(
    () =>
      assertOwnedProcessLauncherProtected(launcher, {
        canWrite: (path) => path !== launcher,
        mounts: [{ id: 1, mountPoint: "/", readOnly: false }],
      }),
    { code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE" },
  );
});

test("owned processes can write to /dev/null", async () => {
  const child = spawnOwnedProcess(
    process.execPath,
    ["-e", 'require("node:fs").writeFileSync("/dev/null", "owned process");'],
    { onProcess: async () => {} },
  );

  const { outcome } = await child.ownedCompletion;
  assert.deepEqual(outcome, { type: "close", exitCode: 0, signal: null });
});

test("selects complete nested isolation and caches it by ownership mode", () => {
  const calls = [];
  const cache = new Map();
  const options = {
    bubblewrap: "/system/bwrap",
    cache,
    namespaceId: INITIAL_PID_NAMESPACE,
    ownershipMode: "native-sandbox-provider",
    probe(file, argumentsList) {
      calls.push({ file, argumentsList });
      return { status: 0 };
    },
  };

  const first = resolveOwnedProcessLauncher(process.cwd(), options);
  const second = resolveOwnedProcessLauncher(process.cwd(), options);

  assert.equal(first.isolatedNamespace, true);
  assert.equal(second.isolatedNamespace, true);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].file, "/system/bwrap");
  assert.deepEqual(
    calls[0].argumentsList.filter((argument) => argument === "--unshare-pid"),
    ["--unshare-pid", "--unshare-pid"],
  );
  assert.ok(calls[0].argumentsList.includes("--unshare-user"));
  assert.ok(calls[0].argumentsList.includes("--unshare-net"));
  assert.ok(calls[0].argumentsList.includes("/system/bwrap"));
  assert.equal(
    calls[0].argumentsList[calls[0].argumentsList.indexOf("--chdir") + 1],
    "/",
  );
  assert.ok(first.arguments.includes("--bind"));

  const ordinary = resolveOwnedProcessLauncher(process.cwd(), {
    ...options,
    ownershipMode: "ordinary",
  });
  assert.equal(calls.length, 2);
  assert.ok(calls[1].argumentsList.includes("--ro-bind"));
  assert.ok(ordinary.arguments.includes("--bind"));
  assert.equal(ordinary.arguments.includes("--ro-bind"), false);
});

test("allows failed nesting only for provider or enclosing sessions", () => {
  const unsupported = () => ({ status: 1 });
  const provider = resolveOwnedProcessLauncher(process.cwd(), {
    bubblewrap: "/system/bwrap",
    cache: new Map(),
    namespaceId: INITIAL_PID_NAMESPACE,
    ownershipMode: "native-sandbox-provider",
    probe: unsupported,
  });
  assert.equal(provider.isolatedNamespace, false);
  assert.deepEqual(provider.arguments.slice(-1), ["session"]);

  assert.throws(
    () =>
      resolveOwnedProcessLauncher(process.cwd(), {
        bubblewrap: "/system/bwrap",
        cache: new Map(),
        namespaceId: INITIAL_PID_NAMESPACE,
        probe: unsupported,
      }),
    { code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE" },
  );

  const enclosing = resolveOwnedProcessLauncher(process.cwd(), {
    bubblewrap: "/system/bwrap",
    cache: new Map(),
    namespaceId: "pid:[987654321]",
    probe: unsupported,
  });
  assert.equal(enclosing.isolatedNamespace, false);
});

test("rejects indeterminate namespace capability evidence", () => {
  assert.throws(
    () =>
      resolveOwnedProcessLauncher(process.cwd(), {
        bubblewrap: "/system/bwrap",
        cache: new Map(),
        namespaceId: INITIAL_PID_NAMESPACE,
        ownershipMode: "native-sandbox-provider",
        probe: () => ({ error: new Error("probe failed"), status: null }),
      }),
    { code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE" },
  );
});

test("uses ancestry and rejects incomplete owned-session evidence", () => {
  const ownerToken = "a".repeat(64);
  const options = {
    getuid: () => 1000,
    list: () => ["101"],
    read(path) {
      if (path.endsWith("/stat")) return "101 (child) S 44 2 3 4";
      if (path.endsWith("/status")) return "Uid:\t1000\t1000\t1000\t1000\n";
      throw Object.assign(new Error("denied"), { code: "EACCES" });
    },
  };

  assert.deepEqual(
    inspectOwnedSessionProcesses(44, ownerToken, options),
    [101],
  );

  assert.deepEqual(
    inspectOwnedSessionProcesses(44, ownerToken, {
      ...options,
      read(path) {
        if (path.endsWith("/stat")) return "101 (nested) S 44 2 3 4";
        if (path.endsWith("/environ")) return "";
        return options.read(path);
      },
    }),
    [101],
  );

  assert.equal(
    inspectOwnedSessionProcesses(44, ownerToken, {
      ...options,
      read(path) {
        return path.endsWith("/stat")
          ? "101 (unrelated) S 1 2 3 4"
          : options.read(path);
      },
    }),
    null,
  );

  assert.deepEqual(
    inspectOwnedSessionProcesses(44, ownerToken, {
      ...options,
      read(path) {
        if (path === "/proc/101/stat") return "101 (nested) S 202 2 3 4";
        if (path === "/proc/202/stat") return "202 (owned) S 44 2 3 4";
        if (path === "/proc/202/environ") {
          return `AGENT_RUNNER_OWNED_PROCESS=${"b".repeat(64)}\0`;
        }
        return options.read(path);
      },
    }),
    [101],
  );

  assert.deepEqual(
    inspectOwnedSessionProcesses(44, ownerToken, {
      ...options,
      read(path) {
        if (path === "/proc/101/stat") return "101 (unrelated) S 202 2 3 4";
        if (path === "/proc/202/stat") return "202 (owned) S 1 2 3 4";
        if (path === "/proc/202/environ") {
          return `AGENT_RUNNER_OWNED_PROCESS=${"b".repeat(64)}\0`;
        }
        return options.read(path);
      },
    }),
    [],
  );

  assert.deepEqual(
    inspectOwnedSessionProcesses(44, ownerToken, {
      ...options,
      read(path) {
        if (path === "/proc/101/stat") return "101 (unrelated) S 202 2 3 4";
        if (path === "/proc/202/stat") return "202 (parent) S 1 2 3 4";
        if (path === "/proc/202/environ") return "";
        return options.read(path);
      },
    }),
    [],
  );
});

test("cleans detached descendants and supports cancellation", async () => {
  const detached = spawnOwnedProcess(
    process.execPath,
    [
      "-e",
      `const { spawn } = require("node:child_process");
       const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"],
         { detached: true, stdio: "ignore" });
       child.unref();`,
    ],
    { descendantGraceMs: 25, onProcess: async () => {} },
  );
  const cleanup = await detached.ownedCompletion;
  assert.equal(cleanup.descendantsStopped, true);

  const controller = new AbortController();
  const registrations = [];
  const canceled = spawnOwnedProcess(
    process.execPath,
    ["-e", "setInterval(() => {}, 1000)"],
    {
      descendantGraceMs: 25,
      onProcess: async (pid) => registrations.push(pid),
      signal: controller.signal,
    },
  );
  await new Promise((resolve) => {
    const wait = () =>
      registrations.length === 0 ? setImmediate(wait) : resolve();
    wait();
  });
  controller.abort();
  await canceled.ownedCompletion;
  assert.equal(Number.isSafeInteger(registrations[0]), true);
  assert.equal(registrations.at(-1), null);
});

test("retires an inert supervisor before reporting failed registration", async () => {
  const failure = Object.assign(new Error("registration failed"), {
    code: "ERR_TEST_REGISTRATION",
  });
  const child = spawnOwnedProcess(process.execPath, ["-e", "process.exit(0)"], {
    descendantGraceMs: 100,
    onProcess: async (pid) => {
      if (pid !== null) throw failure;
    },
  });

  await assert.rejects(child.ownedCompletion, failure);
  assert.throws(() => process.kill(child.pid, 0), { code: "ESRCH" });
});

test("does not signal through a completed owned-process handle", async () => {
  const child = spawnOwnedProcess(process.execPath, ["-e", "process.exit(0)"], {
    onProcess: async () => {},
  });

  await child.ownedCompletion;
  assert.equal(child.kill("SIGKILL"), false);
});

test("recovery clears proven-dead owners without signaling reused PIDs", async () => {
  for (const owner of [
    null,
    { status: "dead", previousBoot: false },
    { status: "replaced", previousBoot: false },
    { status: "unverifiable", previousBoot: true },
  ]) {
    let inspections = 0;
    await terminateOwnedProcess(987_654, async () => {
      inspections += 1;
      return owner;
    });
    assert.equal(inspections, 1);
  }
});

test("recovery retains a dead session owner while descendants remain", async () => {
  const ownerPid = 987_654;
  const processIdentity = { bootId: "boot-a", startTicks: "1234" };
  const ownerToken = createHash("sha256")
    .update(
      `${ownerPid}\0${processIdentity.bootId}\0${processIdentity.startTicks}`,
      "utf8",
    )
    .digest("hex");
  await assert.rejects(
    terminateOwnedProcess(
      ownerPid,
      async () => ({
        namespaceId: readlinkSync("/proc/self/ns/pid"),
        pid: ownerPid,
        previousBoot: false,
        processIdentity,
        status: "dead",
      }),
      {
        inspectSessionProcesses(sessionId, token, options) {
          assert.equal(sessionId, ownerPid);
          assert.equal(token, ownerToken);
          assert.deepEqual(options, { includeSession: true });
          return [123_456];
        },
      },
    ),
    { code: "ERR_EXECUTION_PROCESS_ACTIVE" },
  );
});

test("recovery retains exclusion for live or unverifiable owners", async () => {
  for (const [status, code] of [
    ["live", "ERR_EXECUTION_PROCESS_ACTIVE"],
    ["unverifiable", "ERR_EXECUTION_PROCESS_UNVERIFIABLE"],
  ]) {
    await assert.rejects(
      terminateOwnedProcess(987_654, async () => ({
        status,
        previousBoot: false,
      })),
      { code },
    );
  }
});
