import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import { constants } from "node:fs";
import filesystem, {
  lstat,
  mkdtemp,
  open,
  readFile,
  readdir,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import test from "node:test";
import { rootCertificates } from "node:tls";

import {
  createArtifactAcquirer,
  ACQUISITION_LIMITS,
} from "../src/trusted-validation/acquisition.js";
import { publicAddress } from "../src/trusted-validation/public-address.js";
import {
  createTrustedValidationService,
  createTrustedValidationSnapshot,
} from "../src/trusted-validation/index.js";

const digest = (body) => createHash("sha256").update(body).digest("hex");
const artifact = (body = "verified", path = "file") => ({
  url: `https://downloads.example.com/${path}`,
  sha256: digest(body),
});
const publicAnswer = { address: "8.8.8.8", family: 4 };
const code = (kind) => ({ code: `ERR_TRUSTED_ACQUISITION_${kind}` });

async function fixture(t, options = {}) {
  const root = await mkdtemp(join(tmpdir(), "agent-runner-acquisition-"));
  const directory = await open(
    root,
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
  );
  t.after(async () => {
    await directory.close();
    await rm(root, { recursive: true, force: true });
  });
  const started = Promise.withResolvers();
  const resolved = Promise.withResolvers();
  const retiring = Promise.withResolvers();
  const dnsReply = Promise.withResolvers();
  const timers = new Map();
  const requests = [];
  const resources = [];
  let reply;
  const schedule = (callback, ms) => {
    const key = {};
    timers.set(key, { callback, ms });
    return () => timers.delete(key);
  };
  const emitter = () => {
    const resource = new EventEmitter();
    resource.destroy = () => {
      resource.destroyed = true;
      retiring.resolve();
      if (!options.stuck)
        queueMicrotask(() => {
          resource.closed = true;
          resource.emit("close");
        });
      return resource;
    };
    resources.push(resource);
    return resource;
  };
  const request = (settings, callback) => {
    requests.push(settings);
    reply = callback;
    const req = emitter();
    req.end = () =>
      queueMicrotask(() => {
        const socket = emitter();
        Object.assign(
          socket,
          {
            encrypted: true,
            authorized: true,
            remotePort: 443,
            remoteAddress: publicAnswer.address,
          },
          options.socket,
        );
        req.emit("socket", socket);
        if (options.phase !== "connection") socket.emit("secureConnect");
        if (!options.phase) {
          const response = new PassThrough();
          Object.assign(
            response,
            { statusCode: 200, headers: {}, rawHeaders: [], complete: true },
            options.response,
          );
          resources.push(response);
          callback(response);
          if (options.bodyError)
            response.destroy(new Error("private transport detail"));
          else if (options.chunks) {
            const chunks = [...options.chunks];
            const send = () => {
              if (response.destroyed) return;
              if (chunks.length === 0) response.end();
              else {
                response.write(chunks.shift());
                setImmediate(send);
              }
            };
            send();
          } else response.end(options.body ?? "verified");
        }
        started.resolve();
      });
    return req;
  };
  const acquire = createArtifactAcquirer({
    request,
    schedule,
    limits: options.limits,
    lookup(hostname, settings) {
      assert.equal(hostname, "downloads.example.com");
      assert.ok(settings.signal instanceof AbortSignal);
      assert.equal(settings.timeout, ACQUISITION_LIMITS.dnsMs);
      resolved.resolve();
      if (options.phase === "dns") return dnsReply.promise;
      if (options.dnsError) throw new Error("private resolver detail");
      return Promise.resolve(options.answers ?? [publicAnswer]);
    },
  });
  return {
    root,
    directory,
    requests,
    resources,
    timers,
    started,
    resolved,
    retiring,
    dnsReply,
    acquire: (input = {}) =>
      acquire({ directory, artifacts: [artifact()], ...input }),
    fire(ms) {
      const entry = [...timers.values()].find((timer) => timer.ms === ms);
      assert.ok(entry);
      entry.callback();
    },
    reply(response) {
      reply(response);
    },
  };
}

test("public address classification rejects special-use and transition ranges", () => {
  for (const address of [
    "0.1.2.3",
    "10.0.0.1",
    "100.64.0.1",
    "100.127.255.255",
    "127.0.0.1",
    "169.254.169.254",
    "172.16.0.1",
    "172.31.255.255",
    "192.0.0.9",
    "192.0.2.1",
    "192.88.99.1",
    "192.168.1.1",
    "198.18.0.1",
    "198.19.255.255",
    "198.51.100.1",
    "203.0.113.1",
    "224.0.0.1",
    "255.255.255.255",
    "::",
    "::1",
    "::ffff:8.8.8.8",
    "::ffff:808:808",
    "64:ff9b::808:808",
    "100::1",
    "fc00::1",
    "fe80::1",
    "ff02::1",
    "2001::1",
    "2001:20::1",
    "2001:db8::1",
    "2002:808:808::1",
    "3ffe::1",
    "3fff::1",
    "2001:4860::1%eth0",
    "4000::1",
    "127.1",
    "0x7f000001",
    "invalid",
    null,
  ])
    assert.equal(publicAddress(address), null, String(address));
  for (const address of [
    "8.8.8.8",
    "1.1.1.1",
    "100.128.0.1",
    "172.32.0.1",
    "198.20.0.1",
    "2001:4860:4860::8888",
    "2606:4700::1111",
  ])
    assert.ok(publicAddress(address), address);
  assert.equal(
    publicAddress("2001:4860::8888").key,
    publicAddress("2001:4860:0:0:0:0:0:8888").key,
  );
});

test("verified publication pins destination and TLS policy, with read-only digest filenames", async (t) => {
  const f = await fixture(t, { chunks: ["ver", "if", "ied"] });
  assert.deepEqual(await f.acquire(), [artifact().sha256]);
  assert.deepEqual(await readdir(f.root), [artifact().sha256]);
  assert.equal(
    await readFile(join(f.root, artifact().sha256), "utf8"),
    "verified",
  );
  assert.equal(
    (await lstat(join(f.root, artifact().sha256))).mode & 0o777,
    0o444,
  );
  assert.ok(f.resources.every((resource) => resource.closed));
  assert.equal(f.timers.size, 0);
  const settings = f.requests[0];
  assert.equal(settings.hostname, publicAnswer.address);
  assert.equal(settings.servername, "downloads.example.com");
  assert.equal(settings.headers.Host, settings.servername);
  assert.equal(settings.headers["Accept-Encoding"], "identity");
  assert.equal(settings.port, 443);
  assert.equal(settings.agent, false);
  assert.deepEqual(settings.proxyEnv, {});
  assert.equal(settings.rejectUnauthorized, true);
  assert.deepEqual(settings.ca, [...rootCertificates]);
  assert.equal(settings.minVersion, "TLSv1.2");
  assert.equal(settings.maxHeaderSize, 16384);
  assert.equal(settings.insecureHTTPParser, false);
  assert.equal(settings.auth, undefined);
  settings.lookup("rebound.example.com", {}, (error) =>
    assert.equal(error.code, code("ADDRESS").code),
  );
  assert.equal(
    settings.checkServerIdentity("ignored", {
      subjectaltname: "DNS:downloads.example.com",
    }),
    undefined,
  );
  assert.ok(
    settings.checkServerIdentity(settings.hostname, {
      subjectaltname: "DNS:8.8.8.8",
    }),
  );
});

test("IPv6 connections pin the validated address and compare normalized peer identity", async (t) => {
  const f = await fixture(t, {
    answers: [{ address: "2001:4860::8888", family: 6 }],
    socket: { remoteAddress: "2001:4860:0:0:0:0:0:8888" },
  });
  await f.acquire();
  assert.equal(f.requests[0].hostname, "2001:4860::8888");
  assert.equal(f.requests[0].family, 6);
});

test("every resolved address must be public and have the correct family", async (t) => {
  for (const answers of [
    [],
    [publicAnswer, { address: "127.0.0.1", family: 4 }],
    [{ address: "8.8.8.8", family: 6 }],
    Array(65).fill(publicAnswer),
  ]) {
    const f = await fixture(t, { answers });
    await assert.rejects(f.acquire(), code("ADDRESS"));
    assert.equal(f.requests.length, 0);
    assert.deepEqual(await readdir(f.root), []);
  }
});

test("TLS authorization and the actual peer cannot disagree with the pinned connection", async (t) => {
  for (const socket of [
    { authorized: false },
    { encrypted: false },
    { remoteAddress: "1.1.1.1" },
    { remoteAddress: "127.0.0.1" },
    { remotePort: 80 },
  ]) {
    const f = await fixture(t, { socket });
    await assert.rejects(f.acquire(), code("TLS"));
    assert.deepEqual(await readdir(f.root), []);
  }
});

test("redirects, encodings, duplicate framing and incomplete responses fail closed", async (t) => {
  for (const response of [
    {
      statusCode: 302,
      headers: { location: "https://other.example.com/file" },
    },
    { statusCode: 206 },
    { headers: { "content-encoding": "gzip" } },
    { headers: { "transfer-encoding": "gzip" } },
    { headers: { "transfer-encoding": "chunked", "content-length": "8" } },
    { headers: { "content-length": "eight" } },
    { headers: { "content-length": "9" } },
    {
      headers: { "content-length": "8" },
      rawHeaders: ["Content-Length", "8", "content-length", "8"],
    },
    { headers: { "content-range": "bytes 0-7/8" } },
    { complete: false },
  ]) {
    const f = await fixture(t, { response });
    await assert.rejects(f.acquire(), code("RESPONSE"));
    assert.equal(f.requests.length, 1);
    assert.deepEqual(await readdir(f.root), []);
    assert.ok(f.resources.every((resource) => resource.closed));
  }
});

test("integrity, advertised lengths and streamed per-file/aggregate limits are enforced", async (t) => {
  for (const [options, kind] of [
    [{ body: "tampered" }, "INTEGRITY"],
    [{ chunks: ["ver", "if", "ied"], limits: { fileBytes: 7 } }, "LIMIT"],
    [{ response: { headers: { "content-length": "67108865" } } }, "LIMIT"],
    [
      { response: { headers: { "content-length": "999999999999999999999" } } },
      "LIMIT",
    ],
    [{ bodyError: true }, "TRANSPORT"],
    [{ dnsError: true }, "TRANSPORT"],
  ]) {
    const f = await fixture(t, options);
    await assert.rejects(f.acquire(), code(kind));
    assert.deepEqual(await readdir(f.root), []);
  }
  const f = await fixture(t, { limits: { totalBytes: 12 } });
  await assert.rejects(
    f.acquire({ artifacts: [artifact(), artifact("verified", "second")] }),
    code("LIMIT"),
  );
  assert.deepEqual(await readdir(f.root), [artifact().sha256]); // Only the previously verified file exists.
});

test("DNS, connection, body and overall deadlines reject without late publication", async (t) => {
  for (const [phase, ms] of [
    ["dns", ACQUISITION_LIMITS.dnsMs],
    ["connection", ACQUISITION_LIMITS.connectionMs],
    ["body", ACQUISITION_LIMITS.bodyMs],
    ["body", ACQUISITION_LIMITS.overallMs],
  ]) {
    const f = await fixture(t, { phase });
    const pending = f.acquire();
    const rejected = assert.rejects(pending, code("TIMEOUT"));
    await (phase === "dns" ? f.resolved.promise : f.started.promise);
    f.fire(ms);
    await rejected;
    assert.deepEqual(await readdir(f.root), []);
    assert.equal(f.timers.size, 0);
    if (phase === "dns") {
      f.dnsReply.resolve([publicAnswer]);
      await new Promise((resolve) => setImmediate(resolve));
      assert.equal(f.requests.length, 0);
    } else {
      const late = new PassThrough();
      f.reply(late);
      assert.ok(late.destroyed);
      assert.deepEqual(await readdir(f.root), []);
    }
  }
});

test("cancellation retires transports before cleaning partials and preserves the reason", async (t) => {
  for (const phase of ["dns", "connection", "body"]) {
    const f = await fixture(t, { phase });
    const controller = new AbortController();
    const reason = new Error("cancelled");
    const pending = assert.rejects(
      f.acquire({ signal: controller.signal }),
      (error) => error === reason,
    );
    await (phase === "dns" ? f.resolved.promise : f.started.promise);
    assert.equal((await readdir(f.root)).length, 1);
    controller.abort(reason);
    await pending;
    assert.ok(f.resources.every((resource) => resource.closed));
    assert.deepEqual(await readdir(f.root), []);
    assert.equal(f.timers.size, 0);
  }
});

test("unverified transport retirement is bounded and retains the private partial", async (t) => {
  const f = await fixture(t, { stuck: true });
  const pending = assert.rejects(f.acquire(), code("RETIREMENT"));
  await f.retiring.promise;
  f.fire(ACQUISITION_LIMITS.retirementMs);
  await pending;
  const files = await readdir(f.root);
  assert.equal(files.length, 1);
  assert.match(files[0], /^\.partial-/u);
  assert.equal(f.timers.size, 0);
});

test("destinations are digest-only, exclusive and never follow existing symlinks", async (t) => {
  const f = await fixture(t);
  await symlink("outside", join(f.root, artifact().sha256));
  await assert.rejects(f.acquire(), code("STORAGE"));
  assert.ok((await lstat(join(f.root, artifact().sha256))).isSymbolicLink());
  assert.deepEqual(await readdir(f.root), [artifact().sha256]);
  await assert.rejects(
    f.acquire({ destination: "elsewhere" }),
    code("CONTRACT"),
  );
  const other = await fixture(t);
  assert.deepEqual(
    await other.acquire({
      artifacts: [artifact(), artifact("verified", "second")],
    }),
    [artifact().sha256],
  );
});

test("failed publication preserves a substituted partial instead of deleting unowned content", async (t) => {
  const f = await fixture(t, { phase: "body" });
  const rejected = assert.rejects(f.acquire(), code("STORAGE"));
  await f.started.promise;
  const [name] = await readdir(f.root);
  const partial = join(f.root, name);
  await rename(partial, join(f.root, "original-partial"));
  await writeFile(partial, "unowned replacement");
  const response = Object.assign(new PassThrough(), {
    statusCode: 200,
    headers: {},
    rawHeaders: [],
    complete: true,
  });
  f.reply(response);
  response.end("verified");
  await rejected;
  assert.equal(await readFile(partial, "utf8"), "unowned replacement");
  assert.ok(!(await readdir(f.root)).includes(artifact().sha256));
});

test("file ownership comparisons distinguish inode values above the safe integer range", async (t) => {
  const f = await fixture(t);
  const inode = 1n << 54n;
  const originalStat = f.directory.constructor.prototype.stat;
  const originalLstat = filesystem.lstat;
  t.mock.method(
    f.directory.constructor.prototype,
    "stat",
    async function (options) {
      const info = await originalStat.call(this, options);
      if (this !== f.directory)
        info.ino = options?.bigint ? inode : Number(inode);
      return info;
    },
  );
  t.mock.method(filesystem, "lstat", async (path, options) => {
    const info = await originalLstat(path, options);
    info.ino = options?.bigint ? inode + 1n : Number(inode + 1n);
    return info;
  });
  syncBuiltinESMExports();
  t.after(() => {
    t.mock.restoreAll();
    syncBuiltinESMExports();
  });
  await assert.rejects(f.acquire(), code("STORAGE"));
  const [name] = await readdir(f.root);
  assert.match(name, /^\.partial-/u);
  assert.ok(!(await readdir(f.root)).includes(artifact().sha256));
});

test("acquisition reuses the declaration contract and production artifact requests remain unavailable", async (t) => {
  for (const input of [null, [], "path"])
    await assert.rejects(createArtifactAcquirer()(input), code("CONTRACT"));
  assert.throws(
    () =>
      createArtifactAcquirer({
        limits: { overallMs: ACQUISITION_LIMITS.overallMs + 1 },
      }),
    code("CONTRACT"),
  );
  const f = await fixture(t);
  for (const invalid of [
    { ...artifact(), url: "http://downloads.example.com/file" },
    { ...artifact(), url: "https://user:password@downloads.example.com/file" },
    { ...artifact(), url: "https://127.0.0.1/file" },
    { ...artifact(), url: "https://downloads.local/file" },
    { ...artifact(), url: "https://downloads.example.com:444/file" },
    { ...artifact(), url: "https://downloads.example.com/file#fragment" },
    { ...artifact(), sha256: "not-a-digest" },
    { ...artifact(), destination: "file" },
  ])
    await assert.rejects(f.acquire({ artifacts: [invalid] }), code("CONTRACT"));
  assert.equal(f.requests.length, 0);
  const snapshot = createTrustedValidationSnapshot(
    {
      build: {
        command: "node build.js",
        executable: "node",
        arguments: ["build.js"],
        capabilities: { artifacts: [artifact()] },
      },
    },
    ["build"],
  );
  await assert.rejects(
    createTrustedValidationService().preflight({
      projectPath: f.root,
      snapshot,
    }),
    { code: "ERR_TRUSTED_VALIDATION_CAPABILITY_UNAVAILABLE" },
  );
});
