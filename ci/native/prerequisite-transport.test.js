import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

import { observationDigest } from "./observation.js";
import { prerequisiteSourceSnapshot } from "./prerequisite-source.js";
import {
  createPrerequisiteTransport,
  prerequisiteTransportCommand,
} from "./prerequisite-transport.js";
import { prerequisiteFixture as fixture } from "./prerequisite-fixture.js";

const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");

test("transport construction is effect-free and protected intent precedes fixed worker release", async () => {
  const f = await fixture(),
    transport = f.transport();
  assert.equal(f.events.length, 0);
  assert.equal(f.handles.size, 0);
  try {
    const birth = await transport.start();
    assert.equal(birth.birth.startTicks, "1000");
    assert.equal(
      JSON.parse(f.nodes.get(f.recordPath("birth")).content).requestSha256,
      birth.requestSha256,
    );
    const bytes = Buffer.alloc(40000, 7),
      result = await transport.create("/private/assets/data", bytes);
    assert.equal(result.birthProtected, true);
    const held = await transport.hold("/private/assets/data", {
      maximum: bytes.length,
    });
    assert.deepEqual(held.bytes, bytes);
    const retired = await transport.close();
    assert.equal(retired.independent, true);
    assert.equal(retired.noLiveMembers, true);
    assert.ok(f.nodes.has(f.recordPath("completion")));
    assert.equal(f.handles.size, 0);
  } finally {
    await f.teardown();
  }
});

test("invalid allocation bounds cannot release a worker or reach filesystem operations", async () => {
  const f = await fixture(),
    transport = f.transport();
  try {
    assert.throws(() =>
      transport.hold("/private/data", { maximum: Number.MAX_SAFE_INTEGER }),
    );
    assert.throws(() =>
      transport.create("/private/assets/data", "unbounded coercion"),
    );
    assert.equal(f.events.length, 0);
    assert.equal(f.handles.size, 0);
    assert.equal((await transport.close()).custodianRetired, false);
  } finally {
    await f.teardown();
  }
});

test("missing separate approval, changed hosts/source and failed protected persistence prevent spawn", async () => {
  for (const damage of [
    "source-approval",
    "runtime-approval",
    "privilege-approval",
    "scope-approval",
    "manifest-approval",
    "host",
    "source",
    "controller-source",
    "intent",
  ]) {
    const f = await fixture(),
      failure = new Error("Protected receipt unavailable");
    if (damage.endsWith("-approval"))
      delete f.input.approvals[damage.split("-")[0] + "Sha256"];
    if (damage === "host") f.nodes.get("/stock/node").content.fill(0);
    if (damage === "source")
      f.nodes
        .get(
          fileURLToPath(new URL("prerequisite-worker.mjs", import.meta.url), {
            windows: false,
          }),
        )
        .content.fill(0);
    if (damage === "controller-source")
      f.nodes
        .get(
          fileURLToPath(new URL("first-failure.js", import.meta.url), {
            windows: false,
          }),
        )
        .content.fill(0);
    if (damage === "intent") f.faults.persist = failure;
    const transport = f.transport();
    await assert.rejects(transport.start());
    assert.ok(!f.events.includes("spawn"));
    await assert.rejects(transport.close());
    await f.teardown();
  }
});

test("disconnect before init acknowledgement retains the exact cause and persisted process identity", async () => {
  const f = await fixture(),
    failure = new Error("Lost private acknowledgement");
  f.faults.ack = failure;
  const transport = f.transport();
  try {
    await assert.rejects(transport.start(), (error) => error === failure);
    assert.ok(f.nodes.has(f.recordPath("birth")));
    assert.ok(f.nodes.has(f.recordPath("1-operation")));
    await assert.rejects(transport.close(), (error) => error === failure);
    assert.ok(f.nodes.has(f.recordPath("completion")));
    assert.equal(f.handles.size, 0);
  } finally {
    await f.teardown();
  }
});

test("interruption after file creation retains possible writes and the original transport failure", async () => {
  const f = await fixture(),
    failure = new Error("Controller disconnected after creation");
  f.faults.write = failure;
  const transport = f.transport();
  try {
    await assert.rejects(
      transport.create("/private/assets/data", Buffer.from("data")),
      (error) => error === failure,
    );
    assert.ok(f.nodes.has("/private/assets/data"));
    assert.ok(f.nodes.has(f.recordPath("2-operation")));
    assert.ok(f.nodes.has(f.recordPath("2-creation")));
    await assert.rejects(transport.close(), (error) => error === failure);
    assert.equal(f.handles.size, 0);
  } finally {
    await f.teardown();
  }
});

test("one cleanup deadline bounds parked startup, file operations and cleanup publication without releasing pending handles", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  for (const phase of ["startup", "operation", "cleanup"]) {
    const f = await fixture(),
      transport = f.transport(),
      parked = {
        ready: Promise.withResolvers(),
        resume: Promise.withResolvers(),
      };
    let pending,
      closing,
      cleanupError,
      finished = false;
    try {
      if (phase === "startup") {
        f.faults.park = { ...parked, id: 1 };
        pending = assert.rejects(transport.start());
        await parked.ready.promise;
      } else {
        await transport.start();
        f.faults.parkWrite = parked;
        if (phase === "operation") {
          pending = assert.rejects(
            transport.create("/private/assets/data", Buffer.from("data")),
          );
          await parked.ready.promise;
        }
      }
      closing = transport.close().then(
        () => {
          finished = true;
        },
        (error) => {
          cleanupError = error;
          finished = true;
        },
      );
      if (phase === "cleanup") await parked.ready.promise;
      f.advance(30000);
      t.mock.timers.tick(30000);
      // Drain timer reactions at an event-loop boundary, without a timed wait.
      await new Promise(setImmediate);
      assert.equal(finished, true);
      assert.equal(
        cleanupError?.message,
        "Native CI preparation failed: deadline",
      );
      assert.ok(f.handles.size > 0);
      assert.ok(!f.nodes.has(f.recordPath("completion")));
      assert.ok(!f.nodes.has("/private/assets/data"));
      if (phase === "startup")
        f.faults.park.release(new Error("Closed parked pipe"));
      else parked.resume.resolve();
      await pending;
      await closing;
      // The previous raw operation must settle before another cleanup attempt.
      await new Promise(setImmediate);
      await assert.rejects(
        transport.close(),
        (error) => error === cleanupError,
      );
      assert.equal(f.handles.size, 0);
    } finally {
      f.faults.park?.release?.(new Error("Disposed parked pipe"));
      parked.resume.resolve();
      await pending;
      await closing;
      await f.teardown();
    }
  }
});

test("close acknowledgement and exit cannot replace fresh absence or retire reused identities and surviving children", async () => {
  for (const damage of ["live", "reuse", "child", "census", "visibility"]) {
    const f = await fixture(),
      transport = f.transport();
    try {
      await transport.start();
      if (damage === "census")
        f.faults.census = Object.assign(new Error("Inaccessible procfs"), {
          code: "EACCES",
        });
      else if (damage === "visibility")
        f.faults.mount = "1 0 0:1 / /proc rw - proc proc rw,hidepid=2\n";
      else f.faults[damage] = true;
      await assert.rejects(transport.close());
      assert.ok(!f.nodes.has(f.recordPath("completion")));
      assert.ok(f.handles.size > 0);
      delete f.faults.census;
      delete f.faults.mount;
      f.processes.delete(73);
      f.processes.delete(74);
      await assert.rejects(transport.close());
      assert.equal(f.handles.size, 0);
    } finally {
      await f.teardown();
    }
  }
});

test("recovery uses protected requests and fresh reads without relaunch, final output or unexpired admission", async () => {
  const f = await fixture(),
    failure = new Error("Lost acknowledgement");
  f.faults.ack = failure;
  const original = f.transport();
  try {
    await assert.rejects(original.start());
    await assert.rejects(original.close());
    f.nodes.delete(f.recordPath("completion"));
    f.expire();
    const count = f.events.filter((event) => event === "spawn").length,
      recovered = f.transport();
    const intent = f.intent(),
      reconstruction = recovered.recover(intent);
    intent.sha256 = "0".repeat(64);
    const proof = await reconstruction;
    assert.equal(proof.status, "RETIRED");
    assert.equal(proof.independent, true);
    const receipts = [...f.nodes].filter(([path]) =>
      /-recovery-[a-f0-9]{32}\.json$/u.test(path),
    );
    assert.equal(receipts.length, 1);
    assert.equal(receipts[0][1].mode, 0o400n);
    assert.deepEqual(JSON.parse(receipts[0][1].content).settlement, proof);
    assert.equal(f.events.filter((event) => event === "spawn").length, count);
    await assert.rejects(recovered.start());
    const repeated = f.transport();
    assert.equal((await repeated.recover(f.intent())).status, "RETIRED");
    assert.equal(f.handles.size, 0);
  } finally {
    await f.teardown();
  }
});

test("oversize recovery records are rejected before reads or process release", async () => {
  const f = await fixture(),
    transport = f.transport();
  try {
    await assert.rejects(
      transport.recover({
        file: f.recordPath("intent"),
        bytes: 8388609,
        sha256: "a".repeat(64),
      }),
    );
    assert.equal(f.handles.size, 0);
    assert.equal(f.events.length, 0);
    await assert.rejects(transport.close());
  } finally {
    await f.teardown();
  }
});

test("missing birth evidence cannot hide a possible worker and missing completion cannot grant retirement", async () => {
  const f = await fixture(),
    transport = f.transport();
  try {
    await transport.start();
    f.nodes.delete(f.recordPath("birth"));
    const recovered = f.transport(),
      retained = await recovered.recover(f.intent());
    assert.equal(retained.status, "RETAINED");
    assert.equal(retained.noLiveMembers, false);
    await transport.close();
    const absent = f.transport();
    assert.equal((await absent.recover(f.intent())).status, "RETAINED");
    await assert.rejects(absent.close());
    assert.ok(f.handles.size > 0);
  } finally {
    await f.teardown();
  }
});

test("failed reconstruction cannot lose its original kernel observation failure during cleanup", async () => {
  const f = await fixture(),
    original = f.transport(),
    failure = Object.assign(new Error("Kernel census unavailable"), {
      code: "EACCES",
    });
  try {
    await original.start();
    await original.close();
    f.nodes.delete(f.recordPath("completion"));
    f.faults.census = failure;
    const recovered = f.transport();
    await assert.rejects(
      recovered.recover(f.intent()),
      (error) => error === failure,
    );
    delete f.faults.census;
    await assert.rejects(recovered.close(), (error) => error === failure);
    assert.ok(f.nodes.has(f.recordPath("completion")));
    assert.equal(f.handles.size, 0);
  } finally {
    await f.teardown();
  }
});

test("fixed vectors have no PATH fallback and unsupported native custody cannot launch a host", async () => {
  const f = await fixture(),
    snapshot = await prerequisiteSourceSnapshot(
      f.input.manifest,
      async (name) => f.source.get(name),
    );
  const plan = { ...f.input.admission, platform: "darwin" },
    runtime = structuredClone(f.input.runtime);
  assert.throws(() => prerequisiteTransportCommand(snapshot, plan, runtime));
  runtime.dependencies.push(
    { path: "/usr/bin/sudo", bytes: 1, sha256: "c".repeat(64) },
    { path: "/usr/bin/env", bytes: 1, sha256: "d".repeat(64) },
  );
  const command = prerequisiteTransportCommand(snapshot, plan, runtime);
  assert.equal(command.file, "/usr/bin/sudo");
  assert.deepEqual(command.args.slice(0, 4), [
    "-n",
    "/usr/bin/env",
    "-i",
    "/stock/node",
  ]);
  const darwin = structuredClone(f.input);
  darwin.job.platform =
    darwin.manifest.platform =
    darwin.admission.platform =
      "darwin";
  const inactive = createPrerequisiteTransport(darwin, {
    ...f.edges,
    platform: "darwin",
  });
  await assert.rejects(inactive.start());
  assert.equal(f.events.length, 0);
  await assert.rejects(inactive.close());
  const windows = structuredClone(f.input);
  windows.job.platform =
    windows.manifest.platform =
    windows.admission.platform =
      "win32";
  Object.assign(windows.admission, {
    root: "C:\\Private",
    readRoots: ["C:\\Private"],
    writeRoots: ["C:\\Private\\assets"],
    controllerUid: null,
    controllerSid: "S-1-5-21-1",
  });
  windows.output = "C:\\Private\\records";
  const system = createPrerequisiteTransport(windows, {
    ...f.edges,
    platform: "win32",
  });
  await assert.rejects(system.start());
  assert.equal(f.events.length, 0);
  await assert.rejects(system.close());
  await f.teardown();
});

test("malformed frames and wrong nonces fence a real worker before file commands", async () => {
  for (const damage of ["nonce", "json"]) {
    const f = await fixture();
    f.faults.frame = damage;
    const transport = f.transport();
    try {
      await assert.rejects(transport.start());
      await assert.rejects(transport.close());
      assert.ok(!f.nodes.has("/private/assets/data"));
      assert.equal(f.handles.size, 0);
    } finally {
      await f.teardown();
    }
  }
});

test("late worker completion cannot admit bytes after the transport deadline", async () => {
  const f = await fixture();
  f.faults.expireAfterAck = true;
  const transport = f.transport();
  try {
    await assert.rejects(
      transport.create("/private/assets/data", Buffer.from("data")),
    );
    assert.ok(f.nodes.has("/private/assets/data"));
    await assert.rejects(transport.close());
    assert.equal(f.handles.size, 0);
  } finally {
    await f.teardown();
  }
});

test("held byte frames must match the independently observed file digest", async () => {
  const f = await fixture(),
    transport = f.transport();
  try {
    await transport.create("/private/assets/data", Buffer.from("data"));
    f.faults.chunk = true;
    await assert.rejects(
      transport.hold("/private/assets/data", { maximum: 4 }),
    );
    await assert.rejects(transport.close());
    assert.equal(f.handles.size, 0);
  } finally {
    await f.teardown();
  }
});

test("concurrent callers retain distinct creation intents and snapshot caller bytes", async () => {
  const f = await fixture(),
    transport = f.transport(),
    first = Buffer.from("first");
  try {
    const pending = transport.create("/private/assets/first", first);
    first.fill(0);
    await Promise.all([
      pending,
      transport.create("/private/assets/second", Buffer.from("second")),
    ]);
    assert.equal(
      f.nodes.get("/private/assets/first").content.toString(),
      "first",
    );
    assert.equal(
      f.nodes.get("/private/assets/second").content.toString(),
      "second",
    );
    assert.ok(f.nodes.has(f.recordPath("2-creation")));
    assert.ok(f.nodes.has(f.recordPath("3-creation")));
    await transport.close();
    assert.equal(f.handles.size, 0);
  } finally {
    await f.teardown();
  }
});

test("descriptor closure failure retains custody for retry after independently proved process retirement", async () => {
  const f = await fixture(),
    transport = f.transport(),
    failure = new Error("Held runtime reader cannot close");
  let observedFailure;
  try {
    await transport.start();
    f.faults.close = failure;
    await assert.rejects(transport.close(), (error) => {
      observedFailure = error;
      return error.message === "Unverified native tool observation";
    });
    assert.ok(f.nodes.has(f.recordPath("completion")));
    assert.ok(f.handles.size > 0);
    await assert.rejects(
      transport.close(),
      (error) => error === observedFailure,
    );
    assert.equal(f.handles.size, 0);
  } finally {
    await f.teardown();
  }
});
