import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import * as filesystem from "node:fs/promises";
import { posix } from "node:path";
import { fileURLToPath } from "node:url";
import { EventEmitter } from "node:events";
import { PassThrough, Writable } from "node:stream";
import { finished } from "node:stream/promises";

import { observationDigest } from "./observation.js";
import {
  prerequisiteSourceMembers,
  prerequisiteSourceSnapshot,
} from "./prerequisite-source.js";
import { runPrerequisiteWorker } from "./prerequisite-worker.mjs";
import {
  createPrerequisiteTransport,
  prerequisiteTransportCommand,
} from "./prerequisite-transport.js";

const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");

// Retained descriptors, procfs bytes and raw streams only. The explicit worker
// entry and file owners execute repository operations; no owner callback or
// accepted native evidence is supplied by this fixture.
async function fixture() {
  const nodes = new Map(),
    handles = new Set(),
    events = [],
    processes = new Map(),
    streams = [],
    workers = [];
  let inode = 0,
    child,
    time = Date.now();
  const faults = {};
  const add = (
    path,
    content = null,
    mode = content === null ? 0o700 : 0o444,
  ) => {
    if (path !== "/" && !nodes.has(posix.dirname(path)))
      add(posix.dirname(path));
    const node = {
      dev: 1n,
      ino: BigInt(++inode),
      uid: 0n,
      gid: 0n,
      mode: BigInt(mode),
      nlink: 1n,
      mtimeNs: 1n,
      ctimeNs: 1n,
      content: content === null ? null : Buffer.from(content),
    };
    nodes.set(path, node);
    return node;
  };
  add("/", null, 0o755);
  add("/private");
  add("/private/records");
  add("/stock/node", Buffer.from("approved stock Node"));
  add("/stock/runtime", Buffer.from("approved dependency"));
  const stat = (node) => ({
    ...node,
    size: BigInt(node.content?.length ?? 0),
    isFile: () => node.content !== null,
    isDirectory: () => node.content === null,
  });
  const processStat = ({ pid, parent, group, session, startTicks }) =>
    `${pid} (stock worker) S ${parent} ${group} ${session} ${Array(15).fill("0").join(" ")} ${startTicks}\n`;
  processes.set(1, {
    pid: 1,
    parent: 0,
    group: 1,
    session: 1,
    startTicks: "1",
  });
  processes.set(42, {
    pid: 42,
    parent: 1,
    group: 42,
    session: 42,
    startTicks: "100",
  });
  const raw = (path) => {
    if (path === "/proc/sys/kernel/random/boot_id")
      return Buffer.from("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\n");
    if (path === "/proc/self/mountinfo")
      return Buffer.from(faults.mount ?? "1 0 0:1 / /proc rw - proc proc rw\n");
    if (path === "/proc/self/stat")
      return Buffer.from(processStat(processes.get(42)));
    const match = path.match(/^\/proc\/([0-9]+)\/(stat|status|cmdline)$/u),
      member = match && processes.get(Number(match[1]));
    if (member) {
      if (match[2] === "stat") return Buffer.from(processStat(member));
      if (match[2] === "status") return Buffer.from("Uid:\t0\t0\t0\t0\n");
      return Buffer.from(member.argv ?? "");
    }
    throw Object.assign(new Error("Missing kernel object"), { code: "ENOENT" });
  };
  const lookup = (path) => {
    const node = nodes.get(path);
    if (!node)
      throw Object.assign(new Error("Missing file"), { code: "ENOENT" });
    return node;
  };
  const fs = {
    async realpath(path) {
      lookup(path);
      return path;
    },
    async lstat(path) {
      return stat(lookup(path));
    },
    async stat(path) {
      assert.equal(path, "/proc/73/exe");
      return stat(lookup("/stock/node"));
    },
    async readlink(path) {
      assert.match(path, /^\/proc\/(?:self|1|73)\/ns\/pid$/u);
      return "pid:[1]";
    },
    async readdir(path) {
      assert.equal(path, "/proc");
      if (faults.census) throw faults.census;
      return [...processes.keys()].map(String);
    },
    async mkdir(path, options) {
      assert.equal(options.mode, 0o700);
      assert.ok(!nodes.has(path));
      add(path);
      events.push("mkdir:" + path);
    },
    async open(path, flags, mode) {
      let node;
      if (path.startsWith("/proc/")) node = { content: raw(path) };
      else if (flags & constants.O_CREAT) {
        assert.ok(flags & constants.O_EXCL);
        assert.ok(flags & constants.O_NOFOLLOW);
        assert.equal(mode, 0o600);
        if (nodes.has(path))
          throw Object.assign(new Error("Existing object"), { code: "EEXIST" });
        lookup(posix.dirname(path));
        node = add(path, Buffer.alloc(0), mode);
        events.push("create:" + path);
      } else node = lookup(path);
      const handle = {
        async stat() {
          return stat(node);
        },
        async read(buffer, offset, count, position) {
          const bytesRead = Math.min(
            count,
            Math.max(0, node.content.length - position),
          );
          node.content.copy(buffer, offset, position, position + bytesRead);
          return { bytesRead };
        },
        async writeFile(bytes) {
          node.content = Buffer.from(bytes);
          node.mtimeNs++;
          node.ctimeNs++;
          if (faults.parkWrite && path.endsWith("-2-operation.json")) {
            faults.parkWrite.ready.resolve();
            await faults.parkWrite.resume.promise;
          }
          if (faults.write && path === "/private/assets/data") {
            const failure = faults.write;
            delete faults.write;
            child.stdout.destroy(failure);
          }
        },
        async chmod(mode) {
          node.mode = BigInt(mode);
          node.ctimeNs++;
        },
        async sync() {
          events.push("sync:" + path);
          if (faults.persist && path.endsWith("-intent.json"))
            throw faults.persist;
        },
        async close() {
          if (faults.close && path === "/stock/runtime") {
            const failure = faults.close;
            delete faults.close;
            throw failure;
          }
          assert.ok(handles.delete(handle));
        },
      };
      handles.add(handle);
      return handle;
    },
  };
  const names = [
      ...prerequisiteSourceMembers("linux").map((member) =>
        member.slice("candidate/ci/native/".length),
      ),
      "first-failure.js",
      "prerequisite-source.js",
      "prerequisite-transport.js",
    ],
    source = new Map();
  for (const name of names) {
    const path = fileURLToPath(new URL(name, import.meta.url)),
      bytes = await filesystem.readFile(path);
    source.set(name, bytes);
    add(path, bytes);
  }
  const admission = {
      schemaVersion: 1,
      platform: "linux",
      root: "/private",
      readRoots: ["/private"],
      writeRoots: ["/private/assets"],
      controllerUid: 0,
      controllerSid: null,
      nonce: "b".repeat(32),
      expires: time + 60000,
    },
    manifest = {
      candidateSha: "a".repeat(40),
      platform: "linux",
      source: {
        citations: [...source].map(([name, bytes]) => ({
          kind: "reached-code",
          member: "candidate/ci/native/" + name,
          sha256: digest(bytes),
        })),
      },
    },
    runtime = {
      node: {
        path: "/stock/node",
        bytes: nodes.get("/stock/node").content.length,
        sha256: digest(nodes.get("/stock/node").content),
      },
      dependencies: [
        {
          path: "/stock/runtime",
          bytes: nodes.get("/stock/runtime").content.length,
          sha256: digest(nodes.get("/stock/runtime").content),
        },
      ],
    },
    privilege = { uid: 0, session: "private", worker: "files-only" },
    sources = names.map((name) => ({
      name,
      bytes: source.get(name).length,
      sha256: digest(source.get(name)),
    })),
    input = {
      job: { candidateSha: manifest.candidateSha, platform: "linux" },
      manifest,
      admission,
      runtime,
      privilege,
      output: "/private/records",
      approvals: {
        sourceSha256: observationDigest(sources),
        runtimeSha256: observationDigest(runtime),
        privilegeSha256: observationDigest(privilege),
        manifestSha256: observationDigest(manifest),
        scopeSha256: observationDigest({
          schemaVersion: 1,
          platform: admission.platform,
          root: admission.root,
          readRoots: admission.readRoots,
          writeRoots: admission.writeRoots,
          controllerUid: admission.controllerUid,
          controllerSid: admission.controllerSid,
          output: "/private/records",
        }),
      },
    };
  const recordPath = (suffix) =>
    `/private/records/prerequisite-custody-${admission.nonce}-${suffix}.json`;
  const spawnProcess = (file, args, options) => {
    events.push("spawn");
    const intent = nodes.get(recordPath("intent"));
    assert.equal(intent.mode, 0o400n);
    assert.ok(events.includes("sync:/private/records"));
    const request = JSON.parse(intent.content);
    assert.deepEqual({ file, args }, request.command);
    assert.deepEqual(options, request.options);
    assert.deepEqual(options.env, {});
    child = new EventEmitter();
    child.pid = 73;
    child.stdin = new PassThrough();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    streams.push(child.stdin, child.stdout, child.stderr);
    processes.set(73, {
      pid: 73,
      parent: 42,
      group: 73,
      session: 73,
      startTicks: "1000",
      argv: [file, ...args, ""].join("\0"),
    });
    const match = args
      .at(-1)
      .match(/runPrerequisiteWorker\(\{\.\.\.(\{[^\n]+\}), pipe: null\}\);/u);
    assert.ok(match);
    const config = JSON.parse(match[1]);
    const output = new Writable({
      write(bytes, encoding, done) {
        const frame = JSON.parse(bytes);
        assert.ok(nodes.has(recordPath(`${frame.id}-operation`)));
        if (faults.park?.id === frame.id) {
          faults.park.release = (error) => {
            faults.park.release = undefined;
            done(error);
          };
          faults.park.ready.resolve();
        } else if (faults.ack && frame.id === 1) {
          child.stdout.destroy(faults.ack);
          done(faults.ack);
        } else if (faults.frame && frame.id === 1) {
          const damaged =
            faults.frame === "nonce"
              ? Buffer.from(
                  JSON.stringify({ ...frame, nonce: "0".repeat(32) }) + "\n",
                )
              : Buffer.from("{bad}\n");
          child.stdout.write(damaged, done);
        } else if (faults.chunk && frame.result?.nativeBytes) {
          const changed = Buffer.from(frame.result.nativeBytes, "base64");
          changed[0] ^= 1;
          frame.result.nativeBytes = changed.toString("base64");
          child.stdout.write(JSON.stringify(frame) + "\n", done);
        } else {
          if (faults.expireAfterAck && frame.id === 2)
            time = admission.expires + 1;
          child.stdout.write(bytes, done);
        }
      },
    });
    // Own late raw-stream errors even after the worker removes its listeners.
    output.on("error", () => {});
    streams.push(output);
    queueMicrotask(() => {
      child.emit("spawn");
      const worker = runPrerequisiteWorker(config, {
        fs,
        input: child.stdin,
        output,
        env: {},
        platform: "linux",
        uid: 0,
        pid: 73,
        clock: () => time,
      });
      workers.push(worker);
      worker.then(
        () => exit(0),
        () => exit(1),
      );
    });
    function exit(code) {
      if (!faults.live) processes.delete(73);
      if (faults.reuse)
        processes.set(73, {
          pid: 73,
          parent: 1,
          group: 73,
          session: 73,
          startTicks: "2000",
          argv: "foreign\0",
        });
      if (faults.child)
        processes.set(74, {
          pid: 74,
          parent: 1,
          group: 73,
          session: 73,
          startTicks: "1001",
          argv: "child\0",
        });
      child.stdout.end();
      child.stderr.end();
      child.emit("close", code, null);
    }
    return child;
  };
  const edges = {
    fs,
    spawnProcess,
    platform: "linux",
    uid: 0,
    pid: 42,
    execPath: "/stock/node",
    clock: () => time,
  };
  return {
    input,
    edges,
    nodes,
    handles,
    events,
    processes,
    source,
    faults,
    recordPath,
    transport: () => createPrerequisiteTransport(input, edges),
    intent() {
      const file = recordPath("intent"),
        bytes = nodes.get(file).content;
      return { file, bytes: bytes.length, sha256: digest(bytes) };
    },
    expire() {
      time = admission.expires + 120000;
    },
    advance(ms) {
      time += ms;
    },
    async teardown() {
      for (const stream of streams) stream.destroy();
      await Promise.allSettled(workers);
      await Promise.allSettled(
        streams.map((stream) => finished(stream, { cleanup: true })),
      );
      // Dispose the raw model at test end without issuing retirement evidence
      // for a reservation whose missing identity correctly remained retained.
      for (const handle of [...handles]) await handle.close();
    },
  };
}

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
        .get(fileURLToPath(new URL("prerequisite-worker.mjs", import.meta.url)))
        .content.fill(0);
    if (damage === "controller-source")
      f.nodes
        .get(fileURLToPath(new URL("first-failure.js", import.meta.url)))
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
