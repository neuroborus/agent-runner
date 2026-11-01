import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { readFile, symlink, mkdir, lstat } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { createRunStore } from "../../src/state/index.js";
import { runtimeFixtureDirectory } from "../support/index.js";

const BOOT = "11111111-1111-4111-8111-111111111111";
const runtime = (id) => ({
  payloadId: id.repeat(64),
  rootPath: `/payloads/${id}`,
  executablePath: `/payloads/${id}/bin/agent-run.js`,
  nodePath: "/node/bin/node",
  nodeVersion: "v24.1.0",
  nodeIdentity: { dev: "1", ino: "2", size: "3", mtimeNs: "4", ctimeNs: "5" },
});

async function fixture(t) {
  const root = await runtimeFixtureDirectory(t);
  const stateRoot = join(root, "state");
  const live = new Set([101, 202]);
  const unavailable = new Set();
  const replaced = new Set();
  const namespaces = new Map();
  const observed = [];
  const store = (processId, extra = {}) =>
    createRunStore({
      stateRoot,
      processId,
      hostName: "fixture-host",
      processIsAlive: async (pid) => {
        observed.push(pid);
        return live.has(pid);
      },
      processIdentity: async (pid) =>
        unavailable.has(pid)
          ? null
          : {
              bootId: BOOT,
              startTicks: String(pid + (replaced.has(pid) ? 1 : 0)),
            },
      runtimeProcessNamespace: async (pid) => namespaces.get(pid) ?? "pid:[42]",
      ...extra,
    });
  return {
    stateRoot,
    store,
    live,
    unavailable,
    replaced,
    namespaces,
    observed,
    read: async () =>
      JSON.parse(
        await readFile(
          join(stateRoot, "runtime-admission/runtime.json"),
          "utf8",
        ),
      ),
  };
}

test("admission and activation serialize; live users defer selection until retirement", async (t) => {
  const f = await fixture(t);
  const reached = Promise.withResolvers();
  const proceed = Promise.withResolvers();
  const a = f.store(101, {
    onRuntimeBoundary: async ({ operation }) => {
      if (operation === "admit") {
        reached.resolve();
        await proceed.promise;
      }
    },
  });
  const b = f.store(202);
  const id = randomUUID();
  const admission = a.admitRuntime({ id, runtime: runtime("a"), kind: "mcp" });
  await reached.promise;
  const activation = b.activateRuntime({ runtime: runtime("b") });
  proceed.resolve();
  const outcomes = await Promise.allSettled([admission, activation]);
  for (const result of outcomes)
    assert.equal(result.status, "fulfilled", result.reason?.stack);
  assert.equal(outcomes[0].value.status, "admitted");
  assert.equal(outcomes[1].value.status, "deferred");
  let state = await f.read();
  assert.deepEqual(state.active, runtime("a"));
  assert.deepEqual(state.pending, runtime("b"));
  assert.equal(state.users.length, 1);
  await a.releaseRuntime(id);
  assert.equal(
    (await b.activateRuntime({ runtime: runtime("b") })).status,
    "active",
  );
  state = await f.read();
  assert.deepEqual(state.active, runtime("b"));
  assert.equal(state.pending, null);
  assert.deepEqual(state.users, []);
});

test("owned users recover after exit or PID replacement without inspecting unrelated processes", async (t) => {
  for (const mode of ["dead", "replaced"])
    await t.test(mode, async (t) => {
      const f = await fixture(t);
      await f.store(101).admitRuntime({ runtime: runtime("a"), kind: "cli" });
      if (mode === "dead") f.live.delete(101);
      else f.replaced.add(101);
      f.live.add(999);
      assert.equal(
        (await f.store(202).activateRuntime({ runtime: runtime("b") })).status,
        "active",
      );
      assert.deepEqual((await f.read()).users, []);
      assert.ok(!f.observed.includes(999));
    });
});

test("unverifiable owned identity or namespace blocks activation and preserves usable selection", async (t) => {
  for (const mode of ["identity", "namespace", "self"])
    await t.test(mode, async (t) => {
      const f = await fixture(t);
      await f.store(101).admitRuntime({ runtime: runtime("a"), kind: "mcp" });
      const before = await f.read();
      if (mode === "identity") f.unavailable.add(101);
      if (mode === "namespace") f.namespaces.set(202, "pid:[43]");
      if (mode === "self") f.unavailable.add(202);
      await assert.rejects(
        f.store(202).activateRuntime({ runtime: runtime("b") }),
        { code: "ERR_RUNTIME_OWNER_UNVERIFIABLE" },
      );
      assert.deepEqual(await f.read(), before);
    });
});

test("write-ahead runtime effects reconcile once and completed admissions cannot be replayed", async (t) => {
  const f = await fixture(t);
  let interrupted = true;
  let writes = 0;
  const a = f.store(101, {
    onRuntimeBoundary: async ({ operation }) => {
      if (operation === "admit") {
        writes += 1;
        if (interrupted) {
          interrupted = false;
          throw new Error("interrupted publication");
        }
      }
    },
  });
  const input = { id: randomUUID(), runtime: runtime("a"), kind: "run" };
  await assert.rejects(a.admitRuntime(input), /interrupted publication/u);
  assert.equal((await a.admitRuntime(input)).status, "admitted");
  assert.equal(writes, 1);
  assert.equal((await f.read()).users.length, 1);
  await a.releaseRuntime(input.id);
  await assert.rejects(a.admitRuntime(input), /no longer held/u);
});

test("owner-loss recovery confirms a consumed activation without replaying its write", async (t) => {
  const f = await fixture(t);
  let writes = 0;
  const original = f.store(101, {
    onRuntimeBoundary: async () => {
      writes += 1;
      throw new Error("interrupted activation");
    },
  });
  const request = { id: randomUUID(), runtime: runtime("a") };
  await assert.rejects(
    original.activateRuntime(request),
    /interrupted activation/u,
  );
  const before = await f.read();
  f.live.delete(101);
  assert.equal((await f.store(202).activateRuntime(request)).status, "active");
  assert.deepEqual(await f.read(), before);
  assert.equal(writes, 1);
});

test("runtime coordination refuses a foreign namespace before probing a colliding PID", async (t) => {
  const f = await fixture(t);
  const reached = Promise.withResolvers();
  const proceed = Promise.withResolvers();
  const a = f.store(101, {
    onLeasePublicationBoundary: async ({ filePath, phase }) => {
      if (
        phase === "published" &&
        filePath.startsWith(join(f.stateRoot, "runtime-admission"))
      ) {
        reached.resolve();
        await proceed.promise;
      }
    },
  });
  let probes = 0;
  const b = f.store(101, {
    processIdentity: async () => ({ bootId: BOOT, startTicks: "999" }),
    processIsAlive: async () => {
      probes += 1;
      return true;
    },
    runtimeProcessNamespace: async () => "pid:[43]",
  });
  const first = a.admitRuntime({ runtime: runtime("a"), kind: "cli" });
  await reached.promise;
  let finished;
  try {
    await assert.rejects(b.activateRuntime({ runtime: runtime("b") }), {
      code: "ERR_RUNTIME_OWNER_UNVERIFIABLE",
    });
    assert.equal(probes, 0);
  } finally {
    proceed.resolve();
    [finished] = await Promise.allSettled([first]);
  }
  assert.equal(finished.status, "fulfilled", finished.reason?.stack);
});

test("an interrupted activation cannot overwrite a later selection", async (t) => {
  const f = await fixture(t);
  let once = true;
  const a = f.store(101, {
    onRuntimeBoundary: async () => {
      if (once) {
        once = false;
        throw new Error("interrupted");
      }
    },
  });
  const input = { id: randomUUID(), runtime: runtime("a") };
  await assert.rejects(a.activateRuntime(input), /interrupted/u);
  await f.store(202).activateRuntime({ runtime: runtime("b") });
  await assert.rejects(a.activateRuntime(input), {
    code: "ERR_RUNTIME_RECONCILIATION_REQUIRED",
  });
  assert.deepEqual((await f.read()).active, runtime("b"));
});

test("runtime admission refuses substituted state directories", async (t) => {
  const f = await fixture(t);
  await mkdir(f.stateRoot);
  const outside = join(f.stateRoot, "unrelated");
  await mkdir(outside);
  await symlink(outside, join(f.stateRoot, "runtime-admission"));
  await assert.rejects(
    f.store(101).admitRuntime({ runtime: runtime("a"), kind: "cli" }),
    { code: "ERR_UNSAFE_STATE_ROOT" },
  );
});

test("missing or malformed runtime authority cannot initialize or clear selection", async (t) => {
  const f = await fixture(t);
  const store = f.store(101);
  await assert.rejects(store.activateRuntime({}), {
    code: "ERR_RUNTIME_ADMISSION",
  });
  await assert.rejects(store.admitRuntime({ kind: "cli" }), {
    code: "ERR_RUNTIME_ADMISSION",
  });
  await assert.rejects(
    store.activateRuntime({ runtime: runtime("a"), unrelated: true }),
    { code: "ERR_RUNTIME_ADMISSION" },
  );
  await assert.rejects(lstat(f.stateRoot), { code: "ENOENT" });
});
