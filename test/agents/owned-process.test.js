import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, readlinkSync, realpathSync } from "node:fs";
import { access, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  assertOwnedProcessLauncherProtected,
  inspectOwnedSessionProcesses,
  readProcessIdentity,
  resolveOwnedProcessLauncher,
  spawnOwnedProcess,
  terminateOwnedProcess,
} from "../../src/agents/index.js";

const INITIAL_PID_NAMESPACE = "pid:[4026531836]";
const BOOT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
// Keep synthetic procfs identities outside Linux's PID range so they cannot
// alias the live supervisor or its target in a small test PID namespace.
const TOPOLOGY_PIDS = Object.freeze({
  process: 2 ** 32,
  parent: 2 ** 32 + 1,
  anchor: 2 ** 32 + 2,
  session: 2 ** 32 + 3,
});
const OWNED_PROCESS_MODULE = fileURLToPath(
  new URL("../../src/agents/index.js", import.meta.url),
);

function hostSessionLauncher(cwd, { ownershipMode }) {
  return resolveOwnedProcessLauncher(cwd, {
    bubblewrap: process.execPath,
    cache: new Map(),
    namespaceId: INITIAL_PID_NAMESPACE,
    ownershipMode,
    probe: () => ({ status: 1 }),
  });
}

async function inspectionSequenceFixture(t, sequence, { record = false } = {}) {
  const directory = await mkdtemp(join(tmpdir(), "owned-process-inspection-"));
  t.after(() => rm(directory, { force: true, recursive: true }));
  const preloadPath = join(directory, "inspection-sequence.cjs");
  const inspectionPath = record ? join(directory, "inspections.txt") : null;
  await writeFile(
    preloadPath,
    `if (process.argv[1] === "session") {
  const { createHash } = require("node:crypto");
  const fs = require("node:fs");
  const original = fs.readdirSync;
  const originalRead = fs.readFileSync;
  const sequence = ${JSON.stringify(sequence)};
  let index = 0;
  const bootId = originalRead("/proc/sys/kernel/random/boot_id", "utf8").trim();
  const ownStat = originalRead("/proc/" + process.pid + "/stat", "utf8");
  const ownFields = ownStat.slice(ownStat.lastIndexOf(")") + 2).trim().split(/\\s+/);
  const ownerToken = createHash("sha256")
    .update(process.pid + "\\0" + bootId + "\\0" + ownFields[19], "utf8")
    .digest("hex");
  fs.readdirSync = function readdirSync(path, ...argumentsList) {
    if (path === "/proc") {
      if (${JSON.stringify(inspectionPath)} !== null) {
        fs.appendFileSync(${JSON.stringify(inspectionPath)}, "inspection\\n");
      }
      const observation = sequence[Math.min(index, sequence.length - 1)];
      index += 1;
      if (observation === "incomplete") {
        throw Object.assign(new Error("transient procfs inspection"), {
          code: "EACCES",
        });
      }
      return Reflect.apply(original, this, [path, ...argumentsList]).filter(
        (name) => {
          if (!/^\\d+$/.test(name) || name === String(process.pid)) return false;
          try {
            const stat = originalRead("/proc/" + name + "/stat", "utf8");
            const fields = stat.slice(stat.lastIndexOf(")") + 2).trim().split(/\\s+/);
            if (fields[3] === String(process.pid)) return true;
            return originalRead("/proc/" + name + "/environ", "utf8")
              .split("\\0")
              .includes("AGENT_RUNNER_OWNED_PROCESS=" + ownerToken);
          } catch {
            return false;
          }
        },
      );
    }
    return Reflect.apply(original, this, [path, ...argumentsList]);
  };
}
`,
  );
  return {
    environment: {
      ...process.env,
      NODE_OPTIONS: [process.env.NODE_OPTIONS, `--require=${preloadPath}`]
        .filter(Boolean)
        .join(" "),
    },
    inspectionPath,
  };
}

async function inspectionSequenceEnvironment(t, sequence) {
  return (await inspectionSequenceFixture(t, sequence)).environment;
}

async function productionTopologyEnvironment(t, bootId) {
  const { process: pid, parent, anchor, session } = TOPOLOGY_PIDS;
  const directory = await mkdtemp(join(tmpdir(), "owned-process-topology-"));
  t.after(() => rm(directory, { force: true, recursive: true }));
  const preloadPath = join(directory, "production-topology.cjs");
  const denied = `{ throw Object.assign(new Error("denied"), { code: "EACCES" }); }`;
  await writeFile(
    preloadPath,
    `if (process.argv[1] === "session") {
  const fs = require("node:fs");
  const originalRead = fs.readFileSync;
  const originalList = fs.readdirSync;
  const values = new Map(${JSON.stringify([
    [`/proc/${pid}/stat`, processStat(pid, parent, session)],
    [
      `/proc/${pid}/status`,
      `Uid:\t${process.getuid()}\t${process.getuid()}\t${process.getuid()}\t${process.getuid()}\n`,
    ],
    [`/proc/${pid}/environ`, ""],
    [`/proc/${parent}/stat`, processStat(parent, anchor, session, "5678")],
    [`/proc/${anchor}/stat`, processStat(anchor, 1, session, "6789")],
    [`/proc/${anchor}/environ`, ""],
    ["/proc/sys/kernel/random/boot_id", `${bootId}\n`],
  ])});
  fs.readdirSync = function readdirSync(path, ...argumentsList) {
    return path === "/proc"
      ? [${JSON.stringify(String(pid))}]
      : Reflect.apply(originalList, this, [path, ...argumentsList]);
  };
  fs.readFileSync = function readFileSync(path, ...argumentsList) {
    if (path === "/proc/${parent}/environ") ${denied}
    return values.has(path)
      ? values.get(path)
      : Reflect.apply(originalRead, this, [path, ...argumentsList]);
  };
}
`,
  );
  return {
    ...process.env,
    NODE_OPTIONS: [process.env.NODE_OPTIONS, `--require=${preloadPath}`]
      .filter(Boolean)
      .join(" "),
  };
}

function detachedDescendantCommand() {
  return `const { spawn } = require("node:child_process");
const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], {
  detached: true,
  stdio: "ignore",
});
child.unref();`;
}

function spawnUnrelatedProcessChurn() {
  return spawn(
    process.execPath,
    [
      "-e",
      `const { spawn } = require("node:child_process");
let remaining = 100;
function launch() {
  if (remaining <= 0) return setTimeout(() => process.exit(0), 100);
  remaining -= 1;
  const child = spawn(process.execPath, ["-e", ""], { stdio: "ignore" });
  child.once("exit", launch);
}
process.send("ready");
launch();`,
    ],
    { stdio: ["ignore", "ignore", "ignore", "ipc"] },
  );
}

async function waitForChurn(churn) {
  await new Promise((resolve, reject) => {
    churn.once("error", reject);
    churn.once("message", resolve);
  });
}

function processStat(pid, parentPid, sessionId, startTicks = "1234") {
  const fields = Array(20).fill("0");
  fields[0] = "S";
  fields[1] = String(parentPid);
  fields[3] = String(sessionId);
  fields[19] = startTicks;
  return `${pid} (process) ${fields.join(" ")}`;
}

function processRaceError(code = "ENOENT") {
  return Object.assign(new Error(`simulated ${code}`), { code });
}

function ancestryBaseline(...entries) {
  return entries
    .map(([pid, startTicks]) => ({ bootId: BOOT_ID, pid, startTicks }))
    .sort((left, right) => left.pid - right.pid);
}

function churnProcessList(churn) {
  let children = [];
  try {
    children = readFileSync(
      `/proc/${churn.pid}/task/${churn.pid}/children`,
      "utf8",
    )
      .trim()
      .split(/\s+/u)
      .filter(Boolean);
  } catch (cause) {
    if (!["ENOENT", "ESRCH"].includes(cause?.code)) throw cause;
  }
  return [String(churn.pid), ...children];
}

function processRaceOptions(sequences = {}) {
  const reads = new Map();
  const ownerToken = "a".repeat(64);
  const defaults = {
    "/proc/101/stat": processStat(101, 202, 3),
    "/proc/101/status": "Uid:\t1000\t1000\t1000\t1000\n",
    "/proc/101/environ": "",
    "/proc/202/stat": processStat(202, 1, 3, "5678"),
    "/proc/202/environ": "",
    "/proc/303/stat": processStat(303, 1, 3, "6789"),
    "/proc/303/environ": "",
    "/proc/1/stat": processStat(1, 0, 1, "1"),
    "/proc/1/environ": "",
    "/proc/sys/kernel/random/boot_id": `${BOOT_ID}\n`,
  };
  return {
    options: {
      ancestryBaseline: ancestryBaseline([1, "1"]),
      getuid: () => 1000,
      list: () => ["101"],
      read(path) {
        const count = reads.get(path) ?? 0;
        reads.set(path, count + 1);
        const sequence = sequences[path];
        const value =
          sequence === undefined
            ? defaults[path]
            : sequence[Math.min(count, sequence.length - 1)];
        if (value instanceof Error) throw value;
        if (value === undefined) throw processRaceError("EACCES");
        return typeof value === "function" ? value() : value;
      },
    },
    ownerToken,
    reads,
  };
}

async function waitForFile(path, timeoutMs = 1_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      return await readFile(path, "utf8");
    } catch (cause) {
      if (cause?.code !== "ENOENT") throw cause;
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(`File was not written within ${timeoutMs}ms: ${path}`);
}

async function waitForProcessRetirement(pid, identity, timeoutMs = 1_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const current = await readProcessIdentity(pid);
    if (
      current === null ||
      current.bootId !== identity.bootId ||
      current.startTicks !== identity.startTicks
    ) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(`Process ${pid} was not retired within ${timeoutMs}ms.`);
}

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

test("owned processes can write to /dev/null", { timeout: 5_000 }, async () => {
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
  assert.equal(first.hostSession, false);
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
  assert.equal(provider.hostSession, true);
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
  assert.equal(enclosing.hostSession, false);
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
    ancestryBaseline: ancestryBaseline([1, "1"]),
    getuid: () => 1000,
    list: () => ["101"],
    read(path) {
      if (path === "/proc/sys/kernel/random/boot_id") return `${BOOT_ID}\n`;
      if (path === "/proc/1/stat") return processStat(1, 0, 1, "1");
      if (path === "/proc/1/environ") return "";
      if (path.endsWith("/stat")) return processStat(101, 44, 3);
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
        if (path.endsWith("/stat")) return processStat(101, 44, 3);
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
          ? processStat(101, 1, 3)
          : options.read(path);
      },
    }),
    null,
  );

  assert.deepEqual(
    inspectOwnedSessionProcesses(44, ownerToken, {
      ...options,
      read(path) {
        if (path === "/proc/101/stat") return processStat(101, 202, 3);
        if (path === "/proc/202/stat") return processStat(202, 44, 3);
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
        if (path === "/proc/101/stat") return processStat(101, 202, 3);
        if (path === "/proc/101/environ") return "";
        if (path === "/proc/202/stat") return processStat(202, 1, 3);
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
        if (path === "/proc/101/stat") return processStat(101, 202, 3);
        if (path === "/proc/101/environ") return "";
        if (path === "/proc/202/stat") return processStat(202, 1, 3);
        if (path === "/proc/202/environ") return "";
        return options.read(path);
      },
    }),
    [],
  );
});

test("retries process churn from each current and ancestry read", async (t) => {
  const stableCurrent = processStat(101, 202, 3);
  const stableAncestor = processStat(202, 1, 3, "5678");
  const cases = [
    {
      name: "current status",
      sequences: {
        "/proc/101/status": [
          processRaceError(),
          "Uid:\t1000\t1000\t1000\t1000\n",
        ],
      },
    },
    {
      name: "current environment",
      sequences: { "/proc/101/environ": [processRaceError(), ""] },
    },
    {
      name: "ancestor stat",
      sequences: {
        "/proc/202/stat": [processRaceError(), stableAncestor, stableAncestor],
      },
    },
    {
      name: "ancestor environment",
      sequences: { "/proc/202/environ": [processRaceError(), ""] },
    },
    {
      name: "ancestor verification",
      sequences: {
        "/proc/202/stat": [
          stableAncestor,
          processRaceError(),
          stableAncestor,
          stableAncestor,
        ],
      },
    },
    {
      name: "current verification",
      sequences: {
        "/proc/101/stat": [
          stableCurrent,
          processRaceError(),
          stableCurrent,
          stableCurrent,
        ],
      },
    },
  ];

  for (const fixture of cases) {
    await t.test(fixture.name, () => {
      const { options, ownerToken } = processRaceOptions(fixture.sequences);
      assert.deepEqual(
        inspectOwnedSessionProcesses(44, ownerToken, options),
        [],
      );
    });
  }
});

test("restarts classification after current or ancestor reparenting", async (t) => {
  const currentAt202 = processStat(101, 202, 3);
  const currentAt303 = processStat(101, 303, 3);
  const ancestorAtOne = processStat(202, 1, 3, "5678");
  const ancestorAt303 = processStat(202, 303, 3, "5678");
  for (const fixture of [
    {
      name: "current process",
      sequences: {
        "/proc/101/stat": [
          currentAt202,
          currentAt303,
          currentAt303,
          currentAt303,
        ],
      },
    },
    {
      name: "ancestor process",
      sequences: {
        "/proc/202/stat": [
          ancestorAtOne,
          ancestorAt303,
          ancestorAt303,
          ancestorAt303,
        ],
      },
    },
  ]) {
    await t.test(fixture.name, () => {
      const { options, ownerToken } = processRaceOptions(fixture.sequences);
      assert.deepEqual(
        inspectOwnedSessionProcesses(44, ownerToken, options),
        [],
      );
    });
  }
});

test("ignores an exited entry but fails closed for reuse or exhausted churn", async (t) => {
  const stableCurrent = processStat(101, 202, 3);
  for (const fixture of [
    {
      name: "current PID exits before its first read",
      sequences: { "/proc/101/stat": [processRaceError()] },
      expected: [],
    },
    {
      name: "current PID exits during classification",
      sequences: {
        "/proc/101/stat": [stableCurrent, processRaceError()],
        "/proc/101/status": [processRaceError()],
      },
      expected: [],
    },
    {
      name: "current PID is reused",
      sequences: {
        "/proc/101/stat": [stableCurrent, processStat(101, 202, 3, "9999")],
        "/proc/101/status": [processRaceError()],
      },
      expected: null,
    },
    {
      name: "ancestor PID is reused",
      sequences: {
        "/proc/202/stat": [
          processStat(202, 1, 3, "5678"),
          processStat(202, 1, 3, "9999"),
        ],
      },
      expected: null,
    },
    {
      name: "churn exhausts its attempt bound",
      sequences: { "/proc/101/status": [processRaceError()] },
      expected: null,
      expectedStatusReads: 3,
    },
  ]) {
    await t.test(fixture.name, () => {
      const { options, ownerToken, reads } = processRaceOptions(
        fixture.sequences,
      );
      assert.deepEqual(
        inspectOwnedSessionProcesses(44, ownerToken, options),
        fixture.expected,
      );
      if (fixture.expectedStatusReads !== undefined) {
        assert.equal(
          reads.get("/proc/101/status"),
          fixture.expectedStatusReads,
        );
      }
    });
  }
});

test("retains an owned descendant that survives ancestry churn", () => {
  const ownedAncestor = processStat(303, 1, 44, "6789");
  const { options, ownerToken } = processRaceOptions({
    "/proc/101/stat": [
      processStat(101, 202, 3),
      processStat(101, 303, 3),
      processStat(101, 303, 3),
    ],
    "/proc/202/stat": [processRaceError()],
    "/proc/303/stat": [ownedAncestor],
  });
  assert.deepEqual(
    inspectOwnedSessionProcesses(44, ownerToken, options),
    [101],
  );
});

test(
  "classifies an unrelated process tree during process churn",
  { timeout: 5_000 },
  async (t) => {
    let frozenBaseline;
    const baselineOwner = spawnOwnedProcess(process.execPath, ["-e", ""], {
      onProcess: async (pid, proof) => {
        if (pid !== null) frozenBaseline = proof.ancestryBaseline;
      },
      ownershipMode: "native-sandbox-provider",
      resolveLauncher: hostSessionLauncher,
      stdio: "ignore",
    });
    await baselineOwner.ownedCompletion;
    assert.ok(Array.isArray(frozenBaseline));
    const churn = spawnUnrelatedProcessChurn();
    t.after(() => {
      try {
        churn.kill("SIGKILL");
      } catch {}
    });
    await waitForChurn(churn);

    for (let index = 0; index < 25; index += 1) {
      assert.deepEqual(
        inspectOwnedSessionProcesses(Number.MAX_SAFE_INTEGER, "f".repeat(64), {
          ancestryBaseline: frozenBaseline,
          list: () => churnProcessList(churn),
        }),
        [],
      );
      await new Promise(setImmediate);
    }
  },
);

test(
  "host-session supervision completes during unrelated process churn",
  { timeout: 5_000 },
  async (t) => {
    const churn = spawnUnrelatedProcessChurn();
    t.after(() => {
      try {
        churn.kill("SIGKILL");
      } catch {}
    });
    await waitForChurn(churn);
    const registrations = [];
    const child = spawnOwnedProcess(process.execPath, ["-e", ""], {
      onProcess: async (pid) => registrations.push(pid),
      ownershipMode: "native-sandbox-provider",
      resolveLauncher: hostSessionLauncher,
      stdio: "ignore",
    });

    const result = await child.ownedCompletion;
    assert.equal(result.inspectionComplete, true);
    assert.equal(result.descendantsActive, false);
    assert.deepEqual(registrations, [child.pid, null]);
  },
);

function inaccessibleProcessOptions(startTicks = ["1234"]) {
  let identityReads = 0;
  return {
    getuid: () => 1000,
    list: () => ["101"],
    read(path) {
      if (path === "/proc/sys/kernel/random/boot_id") return `${BOOT_ID}\n`;
      if (path === "/proc/101/stat") {
        const current =
          startTicks[Math.min(identityReads, startTicks.length - 1)];
        identityReads += 1;
        return processStat(101, 1, 3, current);
      }
      if (path === "/proc/101/status") {
        return "Uid:\t1000\t1000\t1000\t1000\n";
      }
      throw Object.assign(new Error("denied"), { code: "EACCES" });
    },
  };
}

test("ignores a proven pre-existing inaccessible process", () => {
  assert.deepEqual(
    inspectOwnedSessionProcesses("44", "a".repeat(64), {
      ...inaccessibleProcessOptions(),
      ancestryBaseline: ancestryBaseline([101, "1234"]),
    }),
    [],
  );
});

test("anchors the production SSH and tmux topology to frozen ancestry", () => {
  const ownerToken = "a".repeat(64);
  assert.deepEqual(
    inspectOwnedSessionProcesses("44", ownerToken, {
      ancestryBaseline: ancestryBaseline([303, "6789"]),
      getuid: () => 1000,
      list: () => ["101"],
      read(path) {
        if (path === "/proc/sys/kernel/random/boot_id") {
          return `${BOOT_ID}\n`;
        }
        if (path === "/proc/101/stat") {
          return processStat(101, 202, 3);
        }
        if (path === "/proc/101/status") {
          return "Uid:\t1000\t1000\t1000\t1000\n";
        }
        if (path === "/proc/101/environ") return "";
        if (path === "/proc/202/stat") {
          return processStat(202, 303, 3, "5678");
        }
        if (path === "/proc/202/environ") {
          throw processRaceError("EACCES");
        }
        if (path === "/proc/303/stat") {
          return processStat(303, 1, 3, "6789");
        }
        if (path === "/proc/303/environ") return "";
        throw processRaceError("EACCES");
      },
    }),
    [],
  );
});

test(
  "embedded supervision uses the same production-shaped ancestry anchor",
  { timeout: 5_000 },
  async (t) => {
    const identity = await readProcessIdentity(process.pid);
    assert.notEqual(identity, null);
    const frozenBaseline = [
      {
        bootId: identity.bootId,
        pid: TOPOLOGY_PIDS.anchor,
        startTicks: "6789",
      },
    ];
    const child = spawnOwnedProcess(process.execPath, ["-e", ""], {
      captureAncestryBaseline: () => frozenBaseline,
      env: await productionTopologyEnvironment(t, identity.bootId),
      onProcess: async (_pid, proof) => {
        if (proof !== undefined) {
          assert.deepEqual(proof.ancestryBaseline, frozenBaseline);
        }
      },
      ownershipMode: "native-sandbox-provider",
      resolveLauncher: hostSessionLauncher,
      stdio: "ignore",
    });

    const result = await child.ownedCompletion;
    assert.equal(result.inspectionComplete, true);
    assert.equal(result.descendantsActive, false);
  },
);

test("does not let a baseline anchor hide observed owned evidence", async (t) => {
  for (const fixture of [
    {
      name: "owned token",
      environment: `AGENT_RUNNER_OWNED_PROCESS=${"a".repeat(64)}\0`,
      ancestorSession: 3,
    },
    {
      name: "owned session",
      environment: "",
      ancestorSession: 44,
    },
  ]) {
    await t.test(fixture.name, () => {
      assert.deepEqual(
        inspectOwnedSessionProcesses(44, "a".repeat(64), {
          ancestryBaseline: ancestryBaseline([303, "6789"]),
          getuid: () => 1000,
          list: () => ["101"],
          read(path) {
            if (path === "/proc/sys/kernel/random/boot_id") {
              return `${BOOT_ID}\n`;
            }
            if (path === "/proc/101/stat") {
              return processStat(101, 202, 3);
            }
            if (path === "/proc/101/status") {
              return "Uid:\t1000\t1000\t1000\t1000\n";
            }
            if (path === "/proc/101/environ") return fixture.environment;
            if (path === "/proc/202/stat") {
              return processStat(202, 303, fixture.ancestorSession, "5678");
            }
            if (path === "/proc/202/environ") return fixture.environment;
            if (path === "/proc/303/stat") {
              return processStat(303, 1, 3, "6789");
            }
            if (path === "/proc/303/environ") return "";
            throw processRaceError("EACCES");
          },
        }),
        [101],
      );
    });
  }
});

test("fails closed for stale, reused, malformed, or wrong-boot anchors", async (t) => {
  const ownerToken = "a".repeat(64);
  for (const fixture of [
    {
      name: "reused anchor",
      baseline: ancestryBaseline([303, "6789"]),
      anchorTicks: "9999",
      bootId: BOOT_ID,
    },
    {
      name: "wrong boot",
      baseline: [
        {
          bootId: "ffffffff-1111-2222-3333-444444444444",
          pid: 303,
          startTicks: "6789",
        },
      ],
      anchorTicks: "6789",
      bootId: BOOT_ID,
    },
    {
      name: "unsorted baseline",
      baseline: ancestryBaseline([303, "6789"], [1, "1"]).reverse(),
      anchorTicks: "6789",
      bootId: BOOT_ID,
    },
  ]) {
    await t.test(fixture.name, () => {
      assert.equal(
        inspectOwnedSessionProcesses(44, ownerToken, {
          ancestryBaseline: fixture.baseline,
          getuid: () => 1000,
          list: () => ["101"],
          read(path) {
            if (path === "/proc/sys/kernel/random/boot_id") {
              return `${fixture.bootId}\n`;
            }
            if (path === "/proc/101/stat") {
              return processStat(101, 303, 3);
            }
            if (path === "/proc/101/status") {
              return "Uid:\t1000\t1000\t1000\t1000\n";
            }
            if (path === "/proc/101/environ") return "";
            if (path === "/proc/303/stat") {
              return processStat(303, 1, 3, fixture.anchorTicks);
            }
            if (path === "/proc/303/environ") return "";
            throw processRaceError("EACCES");
          },
        }),
        null,
      );
    });
  }
});

test("fails closed for an ancestry cycle before the frozen anchor", () => {
  assert.equal(
    inspectOwnedSessionProcesses(44, "a".repeat(64), {
      ancestryBaseline: ancestryBaseline([303, "6789"]),
      getuid: () => 1000,
      list: () => ["101"],
      read(path) {
        if (path === "/proc/sys/kernel/random/boot_id") {
          return `${BOOT_ID}\n`;
        }
        if (path === "/proc/101/stat") return processStat(101, 202, 3);
        if (path === "/proc/101/status") {
          return "Uid:\t1000\t1000\t1000\t1000\n";
        }
        if (path === "/proc/101/environ") return "";
        if (path === "/proc/202/stat") {
          return processStat(202, 101, 3, "5678");
        }
        if (path === "/proc/202/environ") return "";
        throw processRaceError("EACCES");
      },
    }),
    null,
  );
});

test("fails closed before scanning when current boot evidence is unavailable", () => {
  let listed = false;
  assert.equal(
    inspectOwnedSessionProcesses(44, "a".repeat(64), {
      ancestryBaseline: ancestryBaseline([1, "1"]),
      list: () => {
        listed = true;
        return [];
      },
      read: () => {
        throw processRaceError("EACCES");
      },
    }),
    null,
  );
  assert.equal(listed, false);
});

test("rejects inaccessible new processes but retains an owned session", () => {
  const options = inaccessibleProcessOptions();
  assert.equal(
    inspectOwnedSessionProcesses("44", "a".repeat(64), options),
    null,
  );
  assert.deepEqual(
    inspectOwnedSessionProcesses("3", "a".repeat(64), {
      ...options,
      ancestryBaseline: ancestryBaseline([1, "1"]),
    }),
    [101],
  );
});

test("ignores an unowned inaccessible process in a different control group", () => {
  const ownerSource = "0::/owned.scope\n";
  const ownerControlGroup = createHash("sha256")
    .update(ownerSource)
    .digest("hex");
  const options = inaccessibleProcessOptions();
  const read = options.read;
  const inspect = (source, sessionId = "44") =>
    inspectOwnedSessionProcesses(sessionId, "a".repeat(64), {
      ...options,
      controlGroup: ownerControlGroup,
      read(path) {
        return path === "/proc/101/cgroup" ? source : read(path);
      },
    });

  assert.deepEqual(inspect("0::/unrelated.scope\n"), []);
  assert.equal(inspect(ownerSource), null);
  assert.deepEqual(inspect("0::/unrelated.scope\n", 1), [101]);
});

test(
  "recovers from a transient incomplete completion inspection",
  { timeout: 5_000 },
  async (t) => {
    const registrations = [];
    const child = spawnOwnedProcess(
      process.execPath,
      ["-e", detachedDescendantCommand()],
      {
        descendantGraceMs: 50,
        env: await inspectionSequenceEnvironment(t, [
          "complete",
          "incomplete",
          "complete",
        ]),
        onProcess: async (pid) => registrations.push(pid),
        ownershipMode: "native-sandbox-provider",
        resolveLauncher: hostSessionLauncher,
      },
    );

    const result = await child.ownedCompletion;
    assert.equal(result.descendantsStopped, true);
    assert.equal(Number.isSafeInteger(registrations[0]), true);
    assert.equal(registrations.at(-1), null);
  },
);

test(
  "bounds persistent incomplete inspection and retires an empty supervisor",
  { timeout: 5_000 },
  async (t) => {
    // Drive the parent's watchdog separately from the real supervisor's
    // inspection grace; host load must not decide which proof is observed.
    t.mock.timers.enable({ apis: ["setTimeout"] });
    const registrations = [];
    const deregistrationStarted = Promise.withResolvers();
    const releaseDeregistration = Promise.withResolvers();
    const inspection = await inspectionSequenceFixture(t, ["incomplete"], {
      record: true,
    });
    let registeredIdentity;
    const child = spawnOwnedProcess(
      process.execPath,
      ["-e", "process.exit(0)"],
      {
        descendantGraceMs: 50,
        env: inspection.environment,
        onProcess: async (pid, proof) => {
          if (pid === null) {
            deregistrationStarted.resolve();
            await releaseDeregistration.promise;
          }
          registrations.push(pid);
          if (pid !== null) registeredIdentity = proof.processIdentity;
        },
        ownershipMode: "native-sandbox-provider",
        resolveLauncher: hostSessionLauncher,
        stdio: "ignore",
      },
    );
    t.after(async () => {
      const currentIdentity = await readProcessIdentity(child.pid);
      if (
        registeredIdentity !== undefined &&
        currentIdentity?.bootId === registeredIdentity.bootId &&
        currentIdentity.startTicks === registeredIdentity.startTicks
      ) {
        try {
          process.kill(child.pid, "SIGKILL");
        } catch {}
      }
    });
    let completed = false;
    const completion = assert
      .rejects(child.ownedCompletion, {
        code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
      })
      .then(() => {
        completed = true;
      });
    await deregistrationStarted.promise;
    try {
      await new Promise(setImmediate);
      assert.equal(
        completed,
        false,
        "completion must await durable deregistration",
      );
      assert.throws(() => process.kill(child.pid, 0), { code: "ESRCH" });
    } finally {
      releaseDeregistration.resolve();
    }
    await completion;
    assert.ok(
      (await readFile(inspection.inspectionPath, "utf8"))
        .split("\n")
        .filter(Boolean).length > 1,
      "persistent uncertainty must consume the bounded retry window",
    );
    assert.deepEqual(registrations, [child.ownedPid, null]);
    assert.equal(child.ownedContainmentRetained, true);
    assert.throws(() => process.kill(child.pid, 0), { code: "ESRCH" });
  },
);

test(
  "retires a retained supervisor when parent descendant inspection is unavailable",
  { timeout: 5_000 },
  async (t) => {
    const registrations = [];
    let registeredIdentity;
    const child = spawnOwnedProcess(
      process.execPath,
      ["-e", "process.exit(0)"],
      {
        descendantGraceMs: 50,
        env: await inspectionSequenceEnvironment(t, ["incomplete"]),
        inspectSessionProcesses: () => null,
        onProcess: async (pid, proof) => {
          registrations.push(pid);
          if (pid !== null) registeredIdentity = proof.processIdentity;
        },
        ownershipMode: "native-sandbox-provider",
        resolveLauncher: hostSessionLauncher,
        stdio: "ignore",
      },
    );
    t.after(async () => {
      const currentIdentity = await readProcessIdentity(child.pid);
      if (
        registeredIdentity !== undefined &&
        currentIdentity?.bootId === registeredIdentity.bootId &&
        currentIdentity.startTicks === registeredIdentity.startTicks
      ) {
        try {
          process.kill(child.pid, "SIGKILL");
        } catch {}
      }
    });

    await assert.rejects(child.ownedCompletion, {
      code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
    });
    assert.deepEqual(registrations, [child.ownedPid]);
    assert.equal(child.ownedContainmentRetained, true);
    assert.throws(() => process.kill(child.pid, 0), { code: "ESRCH" });
  },
);

test(
  "rechecks descendant absence after a transient parent inspection failure",
  { timeout: 5_000 },
  async (t) => {
    const registrations = [];
    let inspections = 0;
    let registeredIdentity;
    const child = spawnOwnedProcess(
      process.execPath,
      ["-e", "process.exit(0)"],
      {
        descendantGraceMs: 50,
        env: await inspectionSequenceEnvironment(t, ["incomplete"]),
        inspectSessionProcesses() {
          inspections += 1;
          return inspections === 1 ? null : [];
        },
        onProcess: async (pid, proof) => {
          registrations.push(pid);
          if (pid !== null) registeredIdentity = proof.processIdentity;
        },
        ownershipMode: "native-sandbox-provider",
        resolveLauncher: hostSessionLauncher,
        stdio: "ignore",
      },
    );
    t.after(async () => {
      const currentIdentity = await readProcessIdentity(child.pid);
      if (
        registeredIdentity !== undefined &&
        currentIdentity?.bootId === registeredIdentity.bootId &&
        currentIdentity.startTicks === registeredIdentity.startTicks
      ) {
        try {
          process.kill(child.pid, "SIGKILL");
        } catch {}
      }
    });

    await assert.rejects(child.ownedCompletion, {
      code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
    });
    assert.equal(inspections, 2);
    assert.deepEqual(registrations, [child.ownedPid, null]);
    assert.throws(() => process.kill(child.pid, 0), { code: "ESRCH" });
  },
);

test(
  "retires an inert shared-host supervisor when its owner exits during registration",
  { timeout: 5_000 },
  async (t) => {
    const directory = await mkdtemp(
      join(tmpdir(), "owned-process-registration-exit-"),
    );
    t.after(() => rm(directory, { force: true, recursive: true }));
    const environment = await inspectionSequenceEnvironment(t, ["incomplete"]);
    const owners = [];
    const supervisors = [];
    t.after(async () => {
      for (const owner of owners) {
        try {
          owner.kill("SIGKILL");
        } catch {}
      }
      for (const { pid, processIdentity } of supervisors) {
        const current = await readProcessIdentity(pid);
        if (
          current?.bootId === processIdentity.bootId &&
          current.startTicks === processIdentity.startTicks
        ) {
          try {
            process.kill(pid, "SIGKILL");
          } catch {}
        }
      }
    });

    // The after-registration marker models a durable journal side effect that
    // completed immediately before the owner died and its callback returned.
    for (const phase of ["before", "after"]) {
      const ownerPath = join(directory, `${phase}-owner.mjs`);
      const supervisorPath = join(directory, `${phase}-supervisor.json`);
      const registrationPath = join(directory, `${phase}-registration.json`);
      const startedPath = join(directory, `${phase}-started.txt`);
      await writeFile(
        ownerPath,
        `import { writeFile } from "node:fs/promises";
const { resolveOwnedProcessLauncher, spawnOwnedProcess } = await import(process.argv[2]);
const child = spawnOwnedProcess(
  process.execPath,
  ["-e", ${JSON.stringify(
    `require("node:fs").writeFileSync(${JSON.stringify(startedPath)}, "started")`,
  )}],
  {
    descendantGraceMs: 50,
    env: process.env,
    onProcess: async (pid, proof) => {
      if (pid !== null && ${JSON.stringify(phase)} === "after") {
        await writeFile(
          ${JSON.stringify(registrationPath)},
          JSON.stringify({ pid, processIdentity: proof.processIdentity }),
        );
      }
      await new Promise(() => {});
    },
    ownershipMode: "native-sandbox-provider",
    resolveLauncher(cwd, { ownershipMode }) {
      return resolveOwnedProcessLauncher(cwd, {
        bubblewrap: process.execPath,
        cache: new Map(),
        namespaceId: ${JSON.stringify(INITIAL_PID_NAMESPACE)},
        ownershipMode,
        probe: () => ({ status: 1 }),
      });
    },
    stdio: "ignore",
  },
);
await writeFile(${JSON.stringify(supervisorPath)}, JSON.stringify({ pid: child.pid }));
await child.ownedCompletion;
`,
      );
      const owner = spawn(
        process.execPath,
        [ownerPath, pathToFileURL(OWNED_PROCESS_MODULE).href],
        { env: environment, stdio: "ignore" },
      );
      owners.push(owner);
      const ownerExit = new Promise((resolve, reject) => {
        owner.once("error", reject);
        owner.once("exit", (code, signal) => resolve({ code, signal }));
      });
      const { pid } = JSON.parse(await waitForFile(supervisorPath));
      if (phase === "after") await waitForFile(registrationPath);
      const processIdentity = await readProcessIdentity(pid);
      assert.notEqual(processIdentity, null);
      supervisors.push({ pid, processIdentity });

      owner.kill("SIGKILL");
      assert.deepEqual(await ownerExit, { code: null, signal: "SIGKILL" });
      await waitForProcessRetirement(pid, processIdentity);
      await assert.rejects(access(startedPath), { code: "ENOENT" });
    }
  },
);

test(
  "retained containment does not keep the run owner alive",
  { timeout: 5_000 },
  async (t) => {
    const directory = await mkdtemp(
      join(tmpdir(), "owned-process-owner-exit-"),
    );
    t.after(() => rm(directory, { force: true, recursive: true }));
    const ownerPath = join(directory, "owner.mjs");
    const registrationPath = join(directory, "registration.txt");
    const failurePath = join(directory, "failure.txt");
    const environment = await inspectionSequenceEnvironment(t, ["incomplete"]);
    await writeFile(
      ownerPath,
      `import { writeFile } from "node:fs/promises";
const { resolveOwnedProcessLauncher, spawnOwnedProcess } = await import(process.argv[2]);
const child = spawnOwnedProcess(process.execPath, ["-e", "process.exit(0)"], {
  descendantGraceMs: 50,
  env: process.env,
  onProcess: async (pid, proof) => {
    if (pid !== null) {
      await writeFile(
        process.argv[3],
        JSON.stringify({ pid, processIdentity: proof.processIdentity }),
      );
    }
  },
  ownershipMode: "native-sandbox-provider",
  resolveLauncher(cwd, { ownershipMode }) {
    return resolveOwnedProcessLauncher(cwd, {
      bubblewrap: process.execPath,
      cache: new Map(),
      namespaceId: ${JSON.stringify(INITIAL_PID_NAMESPACE)},
      ownershipMode,
      probe: () => ({ status: 1 }),
    });
  },
  stdio: "ignore",
});
try {
  await child.ownedCompletion;
} catch (cause) {
  await writeFile(process.argv[4], cause.code);
}
`,
    );
    const owner = spawn(
      process.execPath,
      [
        ownerPath,
        pathToFileURL(OWNED_PROCESS_MODULE).href,
        registrationPath,
        failurePath,
      ],
      { env: environment, stdio: "ignore" },
    );
    const exitCode = await new Promise((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error("run owner did not exit within its bound")),
        2_000,
      );
      owner.once("error", reject);
      owner.once("exit", (code) => {
        clearTimeout(timer);
        resolve(code);
      });
    });
    const registration = JSON.parse(await readFile(registrationPath, "utf8"));
    t.after(async () => {
      const currentIdentity = await readProcessIdentity(registration.pid);
      if (
        currentIdentity?.bootId === registration.processIdentity.bootId &&
        currentIdentity.startTicks === registration.processIdentity.startTicks
      ) {
        try {
          process.kill(registration.pid, "SIGKILL");
        } catch {}
      }
    });

    assert.equal(exitCode, 0);
    assert.equal(
      await readFile(failurePath, "utf8"),
      "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
    );
    assert.throws(() => process.kill(registration.pid, 0), { code: "ESRCH" });
  },
);

test(
  "cleans detached descendants and supports cancellation",
  {
    timeout: 5_000,
  },
  async () => {
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
    const registered = Promise.withResolvers();
    const canceled = spawnOwnedProcess(
      process.execPath,
      ["-e", "setInterval(() => {}, 1000)"],
      {
        descendantGraceMs: 25,
        onProcess: async (pid) => {
          registrations.push(pid);
          if (pid !== null) registered.resolve();
        },
        signal: controller.signal,
      },
    );
    await registered.promise;
    controller.abort();
    await canceled.ownedCompletion;
    assert.equal(Number.isSafeInteger(registrations[0]), true);
    assert.equal(registrations.at(-1), null);
  },
);

test(
  "settles cancellation while durable registration is pending",
  {
    timeout: 5_000,
  },
  async (t) => {
    const directory = await mkdtemp(
      join(tmpdir(), "owned-process-registration-cancel-"),
    );
    t.after(() => rm(directory, { force: true, recursive: true }));
    const startedPath = join(directory, "started.txt");
    const controller = new AbortController();
    const registrations = [];
    let inspections = 0;
    let releaseRegistration;
    let registrationStarted;
    const registrationPending = new Promise((resolve) => {
      releaseRegistration = resolve;
    });
    const registrationObserved = new Promise((resolve) => {
      registrationStarted = resolve;
    });
    const child = spawnOwnedProcess(
      process.execPath,
      [
        "-e",
        `require("node:fs").writeFileSync(${JSON.stringify(startedPath)}, "started")`,
      ],
      {
        descendantGraceMs: 25,
        inspectSessionProcesses() {
          inspections += 1;
          return null;
        },
        onProcess: async (pid) => {
          registrations.push(pid);
          if (pid === null) return;
          registrationStarted();
          await registrationPending;
        },
        ownershipMode: "native-sandbox-provider",
        resolveLauncher: hostSessionLauncher,
        signal: controller.signal,
        stdio: "ignore",
      },
    );

    await registrationObserved;
    controller.abort();
    releaseRegistration();

    await child.ownedCompletion;
    assert.deepEqual(registrations, [child.pid, null]);
    assert.equal(inspections, 0);
    await assert.rejects(access(startedPath), { code: "ENOENT" });
  },
);

test(
  "retires an inert supervisor before reporting failed registration",
  {
    timeout: 5_000,
  },
  async () => {
    const failure = Object.assign(new Error("registration failed"), {
      code: "ERR_TEST_REGISTRATION",
    });
    const child = spawnOwnedProcess(
      process.execPath,
      ["-e", "process.exit(0)"],
      {
        descendantGraceMs: 100,
        onProcess: async (pid) => {
          if (pid !== null) throw failure;
        },
      },
    );

    await assert.rejects(child.ownedCompletion, failure);
    assert.throws(() => process.kill(child.pid, 0), { code: "ESRCH" });
  },
);

test(
  "records bounded frozen ancestry before provider work starts",
  {
    timeout: 5_000,
  },
  async (t) => {
    const directory = await mkdtemp(join(tmpdir(), "owned-process-baseline-"));
    t.after(() => rm(directory, { force: true, recursive: true }));
    const startedPath = join(directory, "started.txt");
    const registrations = [];
    const child = spawnOwnedProcess(
      process.execPath,
      [
        "-e",
        `require("node:fs").writeFileSync(${JSON.stringify(startedPath)}, "started")`,
      ],
      {
        descendantGraceMs: 100,
        onProcess: async (pid, proof) => {
          registrations.push(pid);
          if (pid === null) return;
          await assert.rejects(access(startedPath), { code: "ENOENT" });
          assert.deepEqual(proof.launchCutoff, proof.processIdentity);
          assert.ok(proof.ancestryBaseline.length > 0);
          assert.ok(proof.ancestryBaseline.length <= 4_096);
          assert.equal(
            proof.ancestryBaseline.every(
              (entry, index, entries) =>
                entry.bootId === proof.processIdentity.bootId &&
                (index === 0 || entries[index - 1].pid < entry.pid),
            ),
            true,
          );
        },
        ownershipMode: "native-sandbox-provider",
        resolveLauncher(cwd, { ownershipMode }) {
          return resolveOwnedProcessLauncher(cwd, {
            bubblewrap: process.execPath,
            cache: new Map(),
            namespaceId: INITIAL_PID_NAMESPACE,
            ownershipMode,
            probe: () => ({ status: 1 }),
          });
        },
      },
    );

    await child.ownedCompletion;
    assert.deepEqual(registrations, [child.pid, null]);
    assert.equal(await readFile(startedPath, "utf8"), "started");
  },
);

test("rejects an oversized launch ancestry before spawning work", () => {
  let launcherResolved = false;
  assert.throws(
    () =>
      spawnOwnedProcess(process.execPath, ["-e", ""], {
        captureAncestryBaseline: () =>
          Array.from({ length: 4_097 }, (_, index) => ({
            bootId: BOOT_ID,
            pid: index + 1,
            startTicks: String(index + 1),
          })),
        onProcess: async () => {},
        resolveLauncher: () => {
          launcherResolved = true;
          return {
            file: process.execPath,
            arguments: [],
            isolatedNamespace: true,
          };
        },
      }),
    {
      code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
      message: "Owned-process launch ancestry is unavailable.",
    },
  );
  assert.equal(launcherResolved, true);
});

test(
  "does not signal through a completed owned-process handle",
  {
    timeout: 5_000,
  },
  async () => {
    const child = spawnOwnedProcess(
      process.execPath,
      ["-e", "process.exit(0)"],
      {
        onProcess: async () => {},
      },
    );

    await child.ownedCompletion;
    assert.equal(child.kill("SIGKILL"), false);
  },
);

test("recovery clears absent and previous-boot owners", async () => {
  for (const owner of [null, { status: "unverifiable", previousBoot: true }]) {
    let inspections = 0;
    await terminateOwnedProcess(987_654, async () => {
      inspections += 1;
      return owner;
    });
    assert.equal(inspections, 1);
  }
});

test("recovery clears a dead session only after proving descendants absent", async () => {
  const ownerPid = 987_654;
  const processIdentity = { bootId: BOOT_ID, startTicks: "1234" };
  const frozenBaseline = ancestryBaseline([1, "1"]);
  await terminateOwnedProcess(
    ownerPid,
    async () => ({
      namespaceId: readlinkSync("/proc/self/ns/pid"),
      pid: ownerPid,
      previousBoot: false,
      processIdentity,
      launchCutoff: processIdentity,
      ancestryBaseline: frozenBaseline,
      status: "dead",
    }),
    {
      inspectSessionProcesses(sessionId, _token, options) {
        assert.equal(sessionId, ownerPid);
        assert.deepEqual(options, {
          ancestryBaseline: frozenBaseline,
          controlGroup: null,
          includeSession: true,
        });
        return [];
      },
    },
  );
});

test("recovery retains a dead session owner while descendants remain", async () => {
  const ownerPid = 987_654;
  const processIdentity = { bootId: BOOT_ID, startTicks: "1234" };
  const frozenBaseline = ancestryBaseline([1, "1"]);
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
        launchCutoff: processIdentity,
        ancestryBaseline: frozenBaseline,
        status: "dead",
      }),
      {
        inspectSessionProcesses(sessionId, token, options) {
          assert.equal(sessionId, ownerPid);
          assert.equal(token, ownerToken);
          assert.deepEqual(options, {
            ancestryBaseline: frozenBaseline,
            controlGroup: null,
            includeSession: true,
          });
          return [123_456];
        },
      },
    ),
    { code: "ERR_EXECUTION_PROCESS_ACTIVE" },
  );
});

test("recovery rejects legacy sessions without frozen ancestry evidence", async () => {
  await assert.rejects(
    terminateOwnedProcess(987_654, async () => ({
      ancestryBaseline: null,
      namespaceId: readlinkSync("/proc/self/ns/pid"),
      pid: 987_654,
      previousBoot: false,
      processIdentity: { bootId: BOOT_ID, startTicks: "1234" },
      status: "dead",
    })),
    {
      code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
      message:
        "Owned execution process predates frozen ancestry recovery evidence.",
    },
  );
});

test("recovery rejects a dead owner from another PID namespace", async () => {
  let scanned = false;
  await assert.rejects(
    terminateOwnedProcess(
      987_654,
      async () => ({
        ancestryBaseline: ancestryBaseline([1, "1"]),
        namespaceId: "pid:[987654321]",
        pid: 987_654,
        previousBoot: false,
        processIdentity: { bootId: BOOT_ID, startTicks: "1234" },
        status: "dead",
      }),
      {
        inspectSessionProcesses() {
          scanned = true;
          return [];
        },
      },
    ),
    {
      code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
      message: "Owned execution process namespace does not match recovery.",
    },
  );
  assert.equal(scanned, false);
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

test("recovery rejects replaced and incompletely recorded owners", async () => {
  for (const owner of [
    { status: "replaced", previousBoot: false },
    {
      namespaceId: null,
      processIdentity: null,
      status: "dead",
      previousBoot: false,
    },
  ]) {
    await assert.rejects(
      terminateOwnedProcess(987_654, async () => owner),
      { code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE" },
    );
  }
});
