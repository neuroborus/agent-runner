import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import * as filesystem from "node:fs/promises";
import { posix } from "node:path";
import { fileURLToPath } from "node:url";
import { EventEmitter } from "node:events";
import { PassThrough, Writable } from "node:stream";
import { finished } from "node:stream/promises";

import { observationDigest } from "./observation.js";
import { prerequisiteSourceMembers } from "./prerequisite-source.js";
import { runPrerequisiteWorker } from "./prerequisite-worker.mjs";
import { createPrerequisiteTransport } from "./prerequisite-transport.js";

const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");

// Retained descriptors, procfs bytes and raw streams only. The explicit worker
// entry and file owners execute repository operations; no owner callback or
// accepted native evidence is supplied by this fixture.
export async function prerequisiteFixture() {
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
      if (path !== "/proc") {
        assert.equal(lookup(path).content, null);
        return [...nodes.keys()]
          .filter((name) => name !== path && posix.dirname(name) === path)
          .map((name) => posix.basename(name));
      }
      if (faults.census) throw faults.census;
      return [...processes.keys()].map(String);
    },
    async mkdir(path, options) {
      assert.equal(options.mode, 0o700);
      assert.ok(!nodes.has(path));
      add(path);
      events.push("mkdir:" + path);
    },
    async opendir(path, options) {
      assert.equal(lookup(path).content, null);
      assert.deepEqual(options, { bufferSize: 32 });
      const names = [...nodes.keys()].filter(
        (name) => name !== path && posix.dirname(name) === path,
      );
      let index = 0;
      const reader = {
        async read() {
          return index < names.length
            ? { name: posix.basename(names[index++]) }
            : null;
        },
        async close() {
          assert.ok(handles.delete(reader));
        },
      };
      handles.add(reader);
      return reader;
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
          if (
            faults.write &&
            path === (faults.writePath ?? "/private/assets/data")
          ) {
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
    const url = new URL(name, import.meta.url),
      path = fileURLToPath(url, { windows: false }),
      bytes = await filesystem.readFile(url);
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
    add,
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
