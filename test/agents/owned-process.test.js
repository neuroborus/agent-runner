import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { readlinkSync, realpathSync } from "node:fs";
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

async function inspectionSequenceEnvironment(t, sequence) {
  const directory = await mkdtemp(join(tmpdir(), "owned-process-inspection-"));
  t.after(() => rm(directory, { force: true, recursive: true }));
  const preloadPath = join(directory, "inspection-sequence.cjs");
  await writeFile(
    preloadPath,
    `if (process.argv[1] === "session") {
  const fs = require("node:fs");
  const original = fs.readdirSync;
  const sequence = ${JSON.stringify(sequence)};
  let index = 0;
  fs.readdirSync = function readdirSync(path, ...argumentsList) {
    if (path === "/proc") {
      const observation = sequence[Math.min(index, sequence.length - 1)];
      index += 1;
      if (observation === "incomplete") {
        throw Object.assign(new Error("transient procfs inspection"), {
          code: "EACCES",
        });
      }
    }
    return Reflect.apply(original, this, [path, ...argumentsList]);
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

function processStat(pid, parentPid, sessionId, startTicks = "1234") {
  const fields = Array(20).fill("0");
  fields[0] = "S";
  fields[1] = String(parentPid);
  fields[3] = String(sessionId);
  fields[19] = startTicks;
  return `${pid} (process) ${fields.join(" ")}`;
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
    getuid: () => 1000,
    list: () => ["101"],
    read(path) {
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
        if (path === "/proc/202/stat") return processStat(202, 1, 3);
        if (path === "/proc/202/environ") return "";
        return options.read(path);
      },
    }),
    [],
  );
});

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
      launchCutoff: { bootId: BOOT_ID, startTicks: "1235" },
    }),
    [],
  );
});

test("ignores a proven pre-existing inaccessible ancestor", () => {
  assert.deepEqual(
    inspectOwnedSessionProcesses("44", "a".repeat(64), {
      launchCutoff: { bootId: BOOT_ID, startTicks: "5679" },
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
          return processStat(202, 1, 3, "5678");
        }
        throw Object.assign(new Error("denied"), { code: "EACCES" });
      },
    }),
    [],
  );
});

test("ignores complete unrelated ancestry independently of the cutoff", () => {
  const ownerToken = "a".repeat(64);
  assert.deepEqual(
    inspectOwnedSessionProcesses("44", ownerToken, {
      launchCutoff: { bootId: BOOT_ID, startTicks: "1000" },
      getuid: () => 1000,
      list: () => ["101"],
      read(path) {
        if (path === "/proc/101/stat") {
          return processStat(101, 202, 3, "2000");
        }
        if (path === "/proc/101/status") {
          return "Uid:\t1000\t1000\t1000\t1000\n";
        }
        if (path === "/proc/202/stat") return processStat(202, 1, 3);
        if (path === "/proc/202/environ") return "";
        throw Object.assign(new Error("denied"), { code: "EACCES" });
      },
    }),
    [],
  );
});

test("rejects inaccessible processes created at or after the cutoff", () => {
  for (const startTicks of ["1234", "1235"]) {
    assert.equal(
      inspectOwnedSessionProcesses("44", "a".repeat(64), {
        ...inaccessibleProcessOptions([startTicks]),
        launchCutoff: { bootId: BOOT_ID, startTicks: "1234" },
      }),
      null,
    );
  }
});

test("rejects an inaccessible process with a reused identity or another boot", () => {
  assert.equal(
    inspectOwnedSessionProcesses("44", "a".repeat(64), {
      ...inaccessibleProcessOptions(["1234", "5678"]),
      launchCutoff: { bootId: BOOT_ID, startTicks: "2000" },
    }),
    null,
  );
  assert.equal(
    inspectOwnedSessionProcesses("44", "a".repeat(64), {
      ...inaccessibleProcessOptions(),
      launchCutoff: {
        bootId: "ffffffff-1111-2222-3333-444444444444",
        startTicks: "1235",
      },
    }),
    null,
  );
});

test("rejects malformed current process identity", () => {
  const options = inaccessibleProcessOptions(["01234"]);
  assert.equal(
    inspectOwnedSessionProcesses("44", "a".repeat(64), {
      ...options,
      launchCutoff: { bootId: BOOT_ID, startTicks: "1235" },
    }),
    null,
  );
});

test("rejects inaccessible new processes and retains inaccessible owned ones", () => {
  const options = inaccessibleProcessOptions();
  assert.equal(
    inspectOwnedSessionProcesses("44", "a".repeat(64), options),
    null,
  );
  assert.deepEqual(
    inspectOwnedSessionProcesses("3", "a".repeat(64), {
      ...options,
      launchCutoff: { bootId: BOOT_ID, startTicks: "1235" },
    }),
    [101],
  );
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
    const registrations = [];
    let registeredIdentity;
    const child = spawnOwnedProcess(
      process.execPath,
      ["-e", "process.exit(0)"],
      {
        descendantGraceMs: 50,
        env: await inspectionSequenceEnvironment(t, ["incomplete"]),
        onProcess: async (pid, proof) => {
          if (pid === null) {
            await new Promise((resolve) => setTimeout(resolve, 125));
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
    const startedAt = Date.now();

    await assert.rejects(child.ownedCompletion, {
      code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
    });
    const elapsed = Date.now() - startedAt;
    assert.ok(elapsed >= 40, `inspection failed after only ${elapsed}ms`);
    assert.ok(elapsed < 1_000, `inspection remained pending for ${elapsed}ms`);
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
  "records the bounded launch cutoff before provider work starts",
  {
    timeout: 5_000,
  },
  async (t) => {
    const directory = await mkdtemp(join(tmpdir(), "owned-process-cutoff-"));
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
  const processIdentity = { bootId: "boot-a", startTicks: "1234" };
  await terminateOwnedProcess(
    ownerPid,
    async () => ({
      namespaceId: readlinkSync("/proc/self/ns/pid"),
      pid: ownerPid,
      previousBoot: false,
      processIdentity,
      launchCutoff: processIdentity,
      status: "dead",
    }),
    {
      inspectSessionProcesses(sessionId, _token, options) {
        assert.equal(sessionId, ownerPid);
        assert.deepEqual(options, {
          includeSession: true,
          launchCutoff: processIdentity,
        });
        return [];
      },
    },
  );
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
        launchCutoff: processIdentity,
        status: "dead",
      }),
      {
        inspectSessionProcesses(sessionId, token, options) {
          assert.equal(sessionId, ownerPid);
          assert.equal(token, ownerToken);
          assert.deepEqual(options, {
            includeSession: true,
            launchCutoff: processIdentity,
          });
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
