import assert from "node:assert/strict";
import test from "node:test";
import { EventEmitter } from "node:events";
import { PassThrough, Writable } from "node:stream";
import { createDarwinCustodyReader, encodeDarwinCustodyPlan } from "./index.js";
import { darwinCustodyChannel } from "./channel.js";

const hash = "a".repeat(64),
  candidateSha = "b".repeat(40),
  cdhash = "c".repeat(40);
const identity = (pid) => ({
  pid,
  pidVersion: 1,
  asid: 0,
  auid: 0,
  uid: 0,
  gid: 0,
  ruid: 0,
  rgid: 0,
  svuid: 0,
  svgid: 0,
  startSeconds: 100,
  startMicroseconds: pid,
});
const fileId = (inode) => `1:2:3:${inode}:100:0:${"d".repeat(32)}`;
const context = {
  candidateSha,
  platform: "darwin",
  tier: "system",
  runId: "1",
  runAttempt: 1,
  jobBindingSha256: hash,
  executionId: "darwin.files",
  closureSha256: hash,
  selectedSystemSha256: null,
};
const image = { path: "/fixture/sealed/reader", sha256: hash, cdhash };
const input = {
  context,
  reader: image,
  sources: [
    "custody-reader.c",
    "custody.h",
    "file-identity.h",
    "effective-reader.h",
  ].map((name) => ({
    path: `/fixture/sealed/${name}`,
    sha256: hash,
  })),
  plan: { path: "/fixture/sealed/plan", sha256: hash },
  tools: {
    elevation: { path: "/usr/bin/sudo", sha256: hash },
    environment: { path: "/usr/bin/env", sha256: hash },
  },
  reportDirectory: "/fixture/report",
  reviewSha256: hash,
  sdkSha256: hash,
  buildSha256: hash,
};
function fixture({ failure, onPersist } = {}) {
  const events = [],
    receipts = [],
    probed = [],
    frames = [{ helper: identity(20) }];
  let helperLive = true,
    fileLive = true,
    finishing = false,
    reserved = false;
  const object = (index) => ({
    identity: fileId(index + 1),
    bytes: index === 0 ? 4 : index === 3 ? 23 : 0,
    uid: 0,
    gid: 0,
    mode: index === 0 ? 0o550 : index === 3 ? 0o400 : 0o700,
    directory: index !== 0 && index !== 3,
  });
  const transport = async (_, args) => {
    events.push(args[0]);
    if (args[0] === "--probe") {
      const pid = Number(args[1]);
      probed.push(pid);
      const subject = (pid === 20 ? helperLive : fileLive)
        ? {
            status: "live",
            identity: identity(
              finishing && failure === "foreign-retirement" ? pid + 1 : pid,
            ),
            sha256: failure === "image" ? "e".repeat(64) : hash,
            signature: { cdhash, entitlementsSha256: hash, valid: true },
            directories:
              pid === 30
                ? [3, 4].map((fd) => ({
                    fd,
                    dev: "1",
                    ino: String(fd === 3 ? 2 : 3),
                    uid: 0,
                    gid: 0,
                    mode: 0o700,
                  }))
                : [],
          }
        : { status: "absent" };
      return {
        receive: async () => ({ verifier: identity(40), subject }),
        completion: Promise.resolve({ code: 0, signal: null }),
        close() {},
      };
    }
    return {
      async send(line) {
        events.push(line.trim());
        if (line === "P\n") {
          frames.push({ candidateSha, entries: 4, uid: 1001, gid: 1002 });
          return;
        }
        const [op, sequence, a, b, c] = line.trim().split(" ");
        let value = null;
        if (["open", "inspect"].includes(op)) value = object(Number(a));
        if (
          op === "inspect" &&
          (failure === "substitution" ||
            (failure === "lease-substitution" && reserved && Number(a) === 3))
        )
          value.identity = fileId(99);
        if (op === "reserve") {
          reserved = true;
          value = object(Number(a));
        }
        if (op === "reservation") value = { held: true };
        if (op === "pf-write") value = { pid: 50, settled: true };
        if (["process", "session"].includes(op)) {
          value = identity(Number(a));
          if (failure === "process-substitution") value.pid++;
          if (failure === "process-malformed") value.pidVersion = 0;
        }
        if (op === "read")
          value = {
            hex: Buffer.from("data")
              .subarray(Number(b), Number(b) + Number(c))
              .toString("hex"),
          };
        if (op === "signature")
          value = { cdhash, entitlementsSha256: hash, valid: true };
        const metadata = {
          headerSha256: hash,
          dependencies: [
            Buffer.from("/usr/lib/libfixture.dylib").toString("hex"),
          ],
          rpaths: [],
          sdk: 0xf0000,
          minimum: 0xf0000,
          uuid: "d".repeat(32),
        };
        if (op === "macho") value = metadata;
        if (op === "build")
          value = {
            osBuild: Buffer.from("fixture-build").toString("hex"),
            macho: metadata,
          };
        if (op === "cache")
          value = {
            cacheUuid: "e".repeat(32),
            imageUuid: metadata.uuid,
            signatureSha256: hash,
            macho: metadata,
          };
        if (op === "transfer") value = { pid: 30 };
        if (op === "file-read")
          value = {
            nonce: "f".repeat(32),
            phase: "ready",
            base: fileId(3),
            root: fileId(2),
            allocation: null,
            leaf: null,
            temporary: null,
            alias: false,
          };
        if (op === "file-close") {
          fileLive = false;
          value = {
            code: 0,
            signal: null,
            ...(failure === "file-trailing" ? {} : { drained: true }),
          };
        }
        if (op === "finish") {
          if (reserved) throw new Error("Unreleased PF reservation");
          finishing = true;
          helperLive = ["live-retirement", "foreign-retirement"].includes(
            failure,
          );
          value = { closed: true };
        }
        frames.push({
          sequence:
            failure === "sequence" ? Number(sequence) + 1 : Number(sequence),
          value,
        });
      },
      receive: async () => frames.shift(),
      completion: Promise.resolve({ code: 0, signal: null }),
      close() {
        events.push("fault");
      },
    };
  };
  const reader = createDarwinCustodyReader(input, {
    runtime: {
      platform: "darwin",
      arch: "x64",
      env: { CI: "true", GITHUB_ACTIONS: "true", ImageOS: "macos15" },
    },
    transport,
    verifyAssets: async () => {
      events.push("assets");
      if (failure === "source") throw new Error("private detail");
    },
    persist: async (record) => {
      receipts.push(structuredClone(record));
      events.push(`intent:${record.phase}`);
      await onPersist?.(record);
      if (failure === "persistence") throw new Error("private detail");
    },
  });
  return { reader, events, receipts, probed };
}
test("Darwin custody construction is effect-free; sealed source and intent precede elevation and independent admission precedes release", async () => {
  const value = fixture();
  assert.deepEqual(value.events, []);
  await value.reader.start();
  assert.ok(
    value.events.indexOf("assets") < value.events.indexOf("intent:entry"),
  );
  assert.ok(
    value.events.indexOf("intent:entry") < value.events.indexOf("--serve"),
  );
  assert.ok(value.events.indexOf("--probe") < value.events.indexOf("P"));
  assert.ok(
    value.events.indexOf("intent:admitted") < value.events.indexOf("P"),
  );
  assert.deepEqual(
    value.receipts.find((record) => record.phase === "admitted").subjects,
    {
      helper: identity(20),
      verifier: identity(40),
    },
  );
  const opened = await value.reader.open(0);
  opened.identity = fileId(99);
  assert.equal((await value.reader.inspect(0)).identity, fileId(1));
  assert.equal((await value.reader.read(0)).toString(), "data");
  assert.equal((await value.reader.signature(0)).cdhash, cdhash);
  assert.deepEqual((await value.reader.macho(0)).dependencies, [
    "/usr/lib/libfixture.dylib",
  ]);
  assert.equal((await value.reader.build()).osBuild, "fixture-build");
  assert.equal(
    (await value.reader.cache(0, "/usr/lib/libfixture.dylib")).imageUuid,
    "d".repeat(32),
  );
  assert.equal((await value.reader.close()).status, "RETIRED");
  assert.ok(
    value.receipts.every(
      (record) =>
        record.context.runId === "1" && record.context.closureSha256 === hash,
    ),
  );
  assert.ok(!JSON.stringify(value.receipts).includes("data"));
});
test("Darwin missing source approval, persistence failure and substituted helper withhold the root setup barrier", async () => {
  for (const failure of ["source", "persistence", "image"]) {
    const value = fixture({ failure });
    await assert.rejects(
      value.reader.start(),
      /custody admission unavailable/u,
    );
    assert.ok(!value.events.includes("P"), failure);
    assert.equal((await value.reader.close()).status, "RETAINED");
    assert.ok(!JSON.stringify(value.receipts).includes("private detail"));
  }
  assert.throws(() => createDarwinCustodyReader({ ...input, sources: [] }));
});
test("Darwin stale held objects and malformed response sequences retain custody instead of declaring closure", async () => {
  for (const failure of [
    "sequence",
    "substitution",
    "process-substitution",
    "process-malformed",
    "live-retirement",
    "foreign-retirement",
  ]) {
    const value = fixture({ failure });
    await value.reader.start();
    if (failure === "sequence") await assert.rejects(value.reader.open(0));
    else if (failure === "substitution") {
      await value.reader.open(0);
      await assert.rejects(value.reader.read(0));
    } else if (failure.startsWith("process-"))
      await assert.rejects(value.reader.process(60, { retainSession: true }));
    assert.equal((await value.reader.close()).status, "RETAINED", failure);
  }
});
test("Darwin materialized plans reject undeclared paths, members and duplicate inputs without manufacturing approval", () => {
  const plan = {
    candidateSha,
    uid: 1001,
    gid: 1002,
    entries: [{ kind: "data", path: "/fixture/sealed/input", sha256: hash }],
  };
  assert.ok(
    encodeDarwinCustodyPlan(plan)
      .toString()
      .startsWith(`native-custody-v1 ${candidateSha} 1001 1002\n`),
  );
  for (const entries of [
    [{ ...plan.entries[0], path: "/fixture/../input" }],
    [plan.entries[0], plan.entries[0]],
    [{ ...plan.entries[0], extra: true }],
    [{ ...plan.entries[0], path: "/" + "p".repeat(1023) }],
  ])
    assert.throws(() => encodeDarwinCustodyPlan({ ...plan, entries }));
});
test("PF exclusion rejoins the shared lease pathname and retains custody on substitution", async () => {
  const intact = fixture();
  await intact.reader.start();
  await intact.reader.open(3);
  await intact.reader.reserve(3, "f".repeat(32));
  assert.deepEqual(await intact.reader.reservation(), { held: true });
  assert.equal((await intact.reader.close()).status, "RETAINED");
  const substituted = fixture({ failure: "lease-substitution" });
  await substituted.reader.start();
  await substituted.reader.open(3);
  await substituted.reader.reserve(3, "f".repeat(32));
  await assert.rejects(substituted.reader.reservation(), /Unverified/);
  assert.ok(
    !substituted.events.some((event) => event.startsWith("reservation ")),
  );
  assert.equal((await substituted.reader.close()).status, "RETAINED");
});
test("Darwin descriptor transfer requires fresh exclusive custody and verifies the signed helper and its creation-time handles before start", async () => {
  const value = fixture();
  await value.reader.start();
  await value.reader.open(0);
  await value.reader.open(1);
  await value.reader.open(2);
  const file = {
    request: {
      schemaVersion: 1,
      candidateSha,
      nonce: "f".repeat(32),
      uid: 1001,
      gid: 1002,
      custody: "/fixture/custody",
      storage: "/fixture/storage",
      workspace: "/fixture/storage/work",
      launcher: { path: "/fixture/custody/launcher", sha256: hash },
      executable: {
        path: "/fixture/storage/file-helper",
        sha256: hash,
        cdhash,
      },
      policy: { path: "/fixture/custody/policy", sha256: hash },
      bindings: { system: hash, source: hash, closure: hash, policy: hash },
    },
    base: fileId(3),
    root: fileId(2),
    reviewSha256: hash,
  };
  const transfer = {
    helperIndex: 0,
    rootIndex: 1,
    baseIndex: 2,
    authority: {
      context,
      base: file.base,
      root: file.root,
      held: true,
      exclusive: true,
      independent: true,
      verifier: identity(50),
      verifierSha256: hash,
      nativeEventSha256: hash,
    },
  };
  await assert.rejects(
    value.reader.openFile(file, {
      ...transfer,
      authority: { ...transfer.authority, exclusive: false },
    }),
  );
  assert.ok(!value.events.some((event) => event.startsWith("transfer ")));
  const channel = await value.reader.openFile(file, transfer);
  assert.equal(channel.admission.helper.pid, 30);
  assert.equal(channel.admission.soleParentAuthority, true);
  channel.admission.helper.pid = 99;
  const admitted = value.events.indexOf("intent:file-admitted"),
    start = value.events.findIndex((event) => event.startsWith("file-send "));
  assert.ok(admitted < start);
  channel.close();
  await channel.completion;
  assert.equal(value.probed.at(-1), 30);
  assert.equal((await value.reader.close()).status, "RETIRED");

  const incomplete = fixture({ failure: "file-trailing" });
  await incomplete.reader.start();
  for (const index of [0, 1, 2]) await incomplete.reader.open(index);
  const unread = await incomplete.reader.openFile(file, transfer);
  unread.close();
  await assert.rejects(unread.completion, /custody retained/u);
  assert.equal((await incomplete.reader.close()).status, "RETAINED");
});
test("Darwin expiration fences further native operations", async () => {
  const value = fixture(),
    controller = new AbortController();
  await value.reader.start({ signal: controller.signal });
  controller.abort();
  await assert.rejects(value.reader.open(0));
  assert.ok(!value.events.some((event) => event.startsWith("open ")));
  assert.equal((await value.reader.close()).status, "RETAINED");
});
test("Darwin bounded cleanup preserves held observations and restoration without reopening admission", async () => {
  for (const operation of ["restore", "open", "install", "expired"]) {
    const value = fixture(),
      work = new AbortController(),
      cleanup = new AbortController();
    await value.reader.start({ signal: work.signal });
    for (const index of [0, 3]) await value.reader.open(index);
    work.abort();
    await value.reader.beginCleanup({ signal: cleanup.signal });
    assert.equal(value.receipts.at(-1).phase, "cleanup");
    if (operation === "restore") {
      assert.equal((await value.reader.read(0)).toString(), "data");
      await value.reader.writePf(0, 3, cdhash, "restore");
      assert.equal((await value.reader.close()).status, "RETIRED");
    } else {
      if (operation === "expired") cleanup.abort();
      const before = value.events.length;
      await assert.rejects(
        operation === "open"
          ? value.reader.open(1)
          : operation === "install"
            ? value.reader.writePf(0, 3, cdhash, "install")
            : value.reader.read(0),
      );
      assert.ok(
        !value.events
          .slice(before)
          .some(
            (event) =>
              event.startsWith("open ") ||
              event.startsWith("pf-write ") ||
              event.startsWith("read "),
          ),
      );
      assert.equal((await value.reader.close()).status, "RETAINED");
    }
    cleanup.abort();
  }
});
test("Darwin cancellation while persisting admission withholds the setup barrier", async () => {
  const controller = new AbortController();
  const value = fixture({
    onPersist(record) {
      if (record.phase === "admitted") controller.abort();
    },
  });
  await assert.rejects(value.reader.start({ signal: controller.signal }));
  assert.ok(!value.events.includes("P"));
  assert.equal((await value.reader.close()).status, "RETAINED");
});
test("Darwin custody deadlines reject pending completion without claiming process exit", async () => {
  const child = new EventEmitter();
  child.stdin = new Writable({ write() {} });
  child.stdout = new PassThrough();
  let expire;
  const transport = darwinCustodyChannel(child, {
    deadlineMs: 390000,
    schedule(callback, delay) {
      assert.equal(delay, 390000);
      expire = callback;
    },
    cancel() {},
  });
  try {
    const completion = assert.rejects(transport.completion),
      pending = assert.rejects(transport.receive()),
      writing = assert.rejects(transport.send("P\n"));
    expire();
    await Promise.all([pending, completion, writing]);
    assert.equal(child.stdin.destroyed, true);
  } finally {
    child.emit("close", 0, null);
    child.stdin.destroy();
    child.stdout.destroy();
  }
});
test("Darwin custody completion rejects an unconsumed trailing frame", async () => {
  const child = new EventEmitter();
  child.stdin = new PassThrough();
  child.stdout = new PassThrough();
  const transport = darwinCustodyChannel(child, { schedule() {}, cancel() {} });
  try {
    child.stdout.emit("data", Buffer.from('{"closed":true}\n{"extra":true}\n'));
    assert.deepEqual(await transport.receive(), { closed: true });
    child.emit("close", 0, null);
    await assert.rejects(transport.completion);
  } finally {
    transport.close();
    child.stdin.destroy();
    child.stdout.destroy();
  }
});
