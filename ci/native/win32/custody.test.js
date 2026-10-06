import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { PassThrough, Writable } from "node:stream";
import test from "node:test";

import {
  createWindowsCustodyReader,
  encodeWindowsCustodyPlan,
} from "./index.js";
import { windowsCustodyChannel } from "./channel.js";
import { digest } from "./protocol.js";
import { observationDigest } from "../index.js";
import { windowsPolicyFixture } from "./policy.fixture.js";

const hash = "a".repeat(64),
  candidateSha = "b".repeat(40),
  nonce = "c".repeat(32),
  runnerSid = "S-1-5-21-1-2-3-1001";
const identity = (pid, userSid = "S-1-5-18") => ({
  pid,
  userSid,
  sessionId: 0,
  creationTime: String(10000 + pid),
});
const id = (number) => `0000000000000001:${String(number).padStart(32, "0")}`;
const hex = (text) => Buffer.from(text, "utf16le").toString("hex");
function executable() {
  const bytes = Buffer.alloc(512),
    optional = 88,
    cert = 448;
  bytes.writeUInt16LE(0x5a4d);
  bytes.writeUInt32LE(64, 0x3c);
  bytes.writeUInt32LE(0x4550, 64);
  bytes.writeUInt16LE(0x8664, 68);
  bytes.writeUInt16LE(1, 70);
  bytes.writeUInt16LE(240, 84);
  bytes.writeUInt16LE(0x20b, optional);
  bytes.writeUInt32LE(16, optional + 108);
  bytes.writeUInt32LE(cert, optional + 144);
  bytes.writeUInt32LE(8, optional + 148);
  bytes.writeUInt32LE(8, cert);
  bytes.writeUInt16LE(0x200, cert + 4);
  bytes.writeUInt16LE(2, cert + 6);
  return bytes;
}
function fixture({ policy = false } = {}) {
  const events = [],
    records = [],
    frames = [],
    bytes = new Map();
  const image = (name) => {
    const data = executable(),
      path = "C:\\Fixture\\Sealed\\" + name;
    bytes.set(path, data);
    return { path, sha256: digest(data), signatureSha256: hash };
  };
  const source = (name) => {
    const data = Buffer.from("reviewed fixture " + name),
      path = "C:\\Fixture\\Sealed\\" + name;
    bytes.set(path, data);
    return { path, sha256: digest(data) };
  };
  const helperImage = image("file-helper.exe"),
    bridge = identity(10, runnerSid),
    helper = identity(20),
    verifier = identity(40),
    fileHelper = identity(30);
  bytes.delete(helperImage.path);
  helperImage.path = "C:\\Fixture\\Storage\\file-helper.exe";
  bytes.set(helperImage.path, executable());
  const entries = [
    { kind: "helper", ...helperImage },
    {
      kind: "directory",
      path: "C:\\Fixture\\Storage",
      sha256: null,
      signatureSha256: null,
    },
    {
      kind: "directory",
      path: "C:\\Fixture\\Storage\\Work",
      sha256: null,
      signatureSha256: null,
    },
    {
      kind: "data",
      path: "C:\\Fixture\\Sealed\\data",
      sha256: digest("data"),
      signatureSha256: null,
    },
  ];
  const file = {
    request: {
      schemaVersion: 1,
      candidateSha,
      nonce,
      restrictingSid: "S-1-5-21-4-5-6-1002",
      custody: "C:\\Fixture\\Sealed",
      storage: entries[1].path,
      workspace: entries[2].path,
      launcher: {
        path: "C:\\Fixture\\Sealed\\launcher.exe",
        sha256: hash,
        signatureSha256: hash,
      },
      executable: { ...helperImage, parser: "msvc-ucrt-wmain-v1" },
      policy: { path: "C:\\Fixture\\Sealed\\policy.json", sha256: hash },
      bindings: { system: hash, source: hash, closure: hash, policy: hash },
    },
    root: id(2),
    base: id(3),
    reviewSha256: hash,
  };
  let policyFixture, policyHelper, policyObjects;
  if (policy) {
    policyFixture = windowsPolicyFixture(file.request, runnerSid);
    policyHelper = entries.length;
    entries.push({ kind: "helper", ...image("policy-helper.exe") });
    policyObjects = policyFixture.plan.manifest.objects
      .filter((entry) => entry.name !== "registry")
      .map((entry) => {
        let index = entries.findIndex((held) => held.path === entry.path);
        if (index < 0) {
          index = entries.length;
          const directory = [
            "custody",
            "storage",
            "workspace",
            "metadata",
            "checkout",
            "configuration",
            "credentials",
            "provider-home",
            "provider-cache",
          ].includes(entry.name);
          entries.push({
            kind: directory ? "directory" : "data",
            path: entry.path,
            sha256: directory ? null : hash,
            signatureSha256: null,
          });
        }
        return index;
      });
  }
  const planPath = "C:\\Fixture\\Sealed\\plan",
    planBytes = encodeWindowsCustodyPlan({ candidateSha, nonce, entries });
  bytes.set(planPath, planBytes);
  const input = {
    context: {
      candidateSha,
      platform: "win32",
      tier: "system",
      runId: "1",
      runAttempt: 1,
      jobBindingSha256: hash,
      executionId: "windows.files",
      closureSha256: hash,
      selectedSystemSha256: null,
    },
    nonce,
    reader: image("custody-reader.exe"),
    bridge: image("custody-bridge.exe"),
    sources: ["custody-reader.c", "custody-bridge.c", "custody.h"].map(source),
    plan: { path: planPath, sha256: digest(planBytes) },
    runnerSid,
    reviewSha256: hash,
    sdkSha256: hash,
    buildSha256: hash,
  };
  const object = (index) => ({
    identity: id(index + 1),
    pathHex: hex(entries[index].path),
    volumeHex: hex("\\\\?\\Volume{11111111-2222-3333-4444-555555555555}\\"),
    filesystemHex: hex("NTFS"),
    daclSha256: hash,
    links: 1,
    directory: entries[index].kind === "directory",
    held: true,
    reparse: false,
  });
  const process = {
    identity: identity(50, runnerSid),
    processDaclSha256: hash,
    tokenId: "1".padStart(16, "0"),
    authenticationId: "2".padStart(16, "0"),
    integritySid: "S-1-16-4096",
    groups: [],
    restricting: [],
    privileges: [],
    retired: false,
  };
  const job = {
    daclSha256: hash,
    limitFlags: 0x2008,
    processLimit: 1,
    uiRestrictions: 255,
    members: [fileHelper],
  };
  const retirement = (subject) => ({
    status: "RETIRED",
    independent: true,
    emergencyCleanup: false,
    nativeEventSha256: hash,
    noLiveMembers: true,
    helper: subject,
    verifier,
  });
  const owner = {
    pid: bridge.pid,
    async send(line) {
      events.push(line.trim());
      if (line === "T") {
        frames.push({ phase: "task-registered", taskSha256: hash });
        return;
      }
      if (line === "B") {
        frames.push(
          { phase: "entry", helper, bridge, processDaclSha256: hash },
          { helper, peer: bridge },
        );
        return;
      }
      if (line === "P\n") {
        frames.push({ candidateSha, nonce, entries: entries.length });
        return;
      }
      const parts = line.trim().split(" "),
        [op, sequence, a, b, c] = parts;
      let value;
      if (["open", "inspect"].includes(op)) value = object(Number(a));
      if (op === "read")
        value = {
          hex: Buffer.from("data")
            .subarray(Number(b), Number(b) + Number(c))
            .toString("hex"),
        };
      if (op === "signature") value = { sha256: hash };
      if (op === "process-open") value = { slot: 0, observation: process };
      if (op === "process") value = process;
      if (op === "job-open") value = { slot: 0, observation: job };
      if (op === "job") value = job;
      if (op === "loader")
        value = {
          complete: true,
          loaded: [
            {
              pathHex: hex(helperImage.path),
              identity: id(1),
              sha256: helperImage.sha256,
              signatureSha256: hash,
              daclSha256: hash,
              links: 1,
            },
          ],
          imports: [
            {
              source: 0,
              resolved: 0,
              delay: false,
              importHex: Buffer.from("fixture.dll").toString("hex"),
            },
          ],
          linkerMajor: 14,
          linkerMinor: 0,
          timestamp: 1,
        };
      if (op === "build")
        value = {
          major: 10,
          minor: 0,
          build: 26100,
          sdkRootHex: hex("C:\\SDK\\"),
        };
      if (op === "helper-start")
        value = {
          helper: fileHelper,
          processDaclSha256: hash,
          threadDaclSha256: hash,
          inheritedHandleCount: Number(parts[5 + Number(parts[4])]) + 2,
          job,
        };
      if (op === "helper-release") value = { released: true };
      if (op === "helper-send") value = { sent: true };
      if (op === "helper-read")
        value = {
          hex: Buffer.from(JSON.stringify({ ready: true })).toString("hex"),
        };
      if (op === "helper-finish")
        value = { retired: true, members: 0, drained: true };
      if (op === "finish") value = { closed: true };
      const frame = {
        sequence: Number(sequence),
        value: structuredClone(value),
      };
      frames.push(options.damage ? options.damage(op, frame) : frame);
      if (op === "finish")
        frames.push({
          phase: "retired",
          taskSha256: hash,
          taskRemoved: true,
          helperRetired: true,
        });
    },
    receive: async () => structuredClone(frames.shift()),
    completion: Promise.resolve({ code: 0, signal: null }),
    close() {
      events.push("fault");
    },
  };
  const options = {
    persist: async (record) => {
      records.push(structuredClone(record));
      events.push("persist-" + record.phase);
    },
    read: async (path) => {
      events.push("read-" + path);
      return bytes.get(path);
    },
    open: async () => {
      events.push("entry");
      frames.push({ phase: "task-intent", taskSha256: hash, bridge });
      return owner;
    },
    verifyBootstrap: async () => {
      events.push("verify-bootstrap");
      return {
        independent: true,
        held: true,
        protectedDacl: true,
        protectedParents: true,
        reviewSha256: hash,
        sdkSha256: hash,
        buildSha256: hash,
        nativeEventSha256: hash,
        entries: [input.bridge, input.reader, input.plan, ...input.sources].map(
          (entry, index) => ({
            path: entry.path,
            sha256: entry.sha256,
            signatureSha256: entry.signatureSha256 ?? null,
            identity: id(index + 10),
            daclSha256: hash,
          }),
        ),
      };
    },
    verifyAdmission: async () => {
      events.push("verify-admission");
      return {
        independent: true,
        helper,
        verifier,
        planSha256: input.plan.sha256,
        taskSha256: hash,
        imageSha256: input.reader.sha256,
        signatureSha256: hash,
        processDaclSha256: hash,
        nativeEventSha256: hash,
      };
    },
    verifyTransfer: async (value) => {
      events.push("verify-transfer");
      return {
        independent: true,
        helper: fileHelper,
        verifier,
        explicitHandleList: true,
        inheritedHandleCount: value.transfer.objects.length + 2,
        transferSha256: value.transferSha256,
        imageSha256: value.transfer.image.sha256,
        signatureSha256: value.transfer.image.signatureSha256,
        processDaclSha256: hash,
        threadDaclSha256: hash,
        jobSha256: observationDigest(job),
        nativeEventSha256: hash,
      };
    },
    verifyHelperRetirement: async () => retirement(fileHelper),
    verifyRetirement: async () => {
      events.push("verify-retirement");
      return retirement(helper);
    },
    verifyTaskRemoval: async () => {
      events.push("verify-removal");
      return { ...retirement(helper), taskRemoved: true };
    },
  };
  return {
    input,
    options,
    owner,
    events,
    records,
    entries,
    bytes,
    file,
    process,
    helper,
    verifier,
    fileHelper,
    object,
    policyFixture,
    policyHelper,
    policyObjects,
    reader: () => createWindowsCustodyReader(input, options),
    transfer: { helper: 0, root: 1, base: 2 },
  };
}

test("Windows custody is effect-free until write-ahead task and verified setup admission", async () => {
  const f = fixture(),
    reader = f.reader();
  assert.deepEqual(f.events, []);
  const result = await reader.start();
  assert.equal(result.independent, true);
  for (const [first, next] of [
    ["persist-task-possible", "verify-bootstrap"],
    ["verify-bootstrap", "entry"],
    ["persist-task-register-possible", "T"],
    ["persist-task-run-possible", "B"],
    ["verify-admission", "P"],
    ["persist-admitted", "P"],
  ])
    assert.ok(f.events.indexOf(first) < f.events.indexOf(next));
  await reader.open(3);
  const effects = f.events.length;
  await assert.rejects(reader.read(3, 134217728, 1));
  assert.equal(f.events.length, effects);
  assert.equal((await reader.read(3, 0, 4)).toString(), "data");
  assert.equal((await reader.close()).closed, true);
  assert.ok(
    f.events.indexOf("verify-retirement") < f.events.indexOf("finish 3"),
  );
  assert.equal(f.records.at(-1).custody, "RETIRED");
});

test("Windows entry requires separately observed sealed code, SDK and build pins before execution", async () => {
  for (const damage of [
    (seal) => {
      seal.entries[0].sha256 = "d".repeat(64);
    },
    (seal) => {
      seal.sdkSha256 = "d".repeat(64);
    },
    (seal) => {
      seal.protectedParents = false;
    },
  ]) {
    const f = fixture(),
      verify = f.options.verifyBootstrap;
    f.options.verifyBootstrap = async (...args) => {
      const seal = await verify(...args);
      damage(seal);
      return seal;
    };
    await assert.rejects(f.reader().start());
    assert.ok(!f.events.includes("entry"));
    assert.equal(f.records.at(-1).custody, "POSSIBLE");
  }
  const f = fixture();
  f.bytes.set(f.input.sources[0].path, Buffer.from("substituted"));
  await assert.rejects(f.reader().start());
  assert.ok(!f.events.includes("entry"));
});

test("Windows sealed task paths cannot expand environment variables", () => {
  const f = fixture();
  for (const asset of [
    f.input.bridge,
    f.input.reader,
    f.input.plan,
    ...f.input.sources,
  ])
    asset.path = asset.path.replace("\\Sealed\\", "\\%TASK_ROOT%\\");
  assert.throws(() => f.reader());
  assert.deepEqual(f.events, []);
});

test("Windows an administrator, reused creation identity or self-verifier cannot acknowledge setup", async () => {
  for (const damage of [
    (value) => {
      value.helper.userSid = runnerSid;
    },
    (value) => {
      value.helper.creationTime = "90000";
    },
    (value) => {
      value.verifier = value.helper;
    },
  ]) {
    const f = fixture(),
      verify = f.options.verifyAdmission;
    f.options.verifyAdmission = async (...args) => {
      const value = structuredClone(await verify(...args));
      damage(value);
      return value;
    };
    await assert.rejects(f.reader().start());
    assert.ok(!f.events.includes("P"));
    assert.equal(f.records.at(-1).phase, "uncertain");
  }
});

test("Windows absent independent admission retains a registered possible task", async () => {
  const f = fixture();
  delete f.options.verifyAdmission;
  const reader = f.reader();
  await assert.rejects(reader.start());
  assert.ok(f.events.includes("B"));
  assert.ok(!f.events.includes("P"));
  assert.equal((await reader.close()).status, "RETAINED");
  assert.equal(f.records.at(-1).custody, "POSSIBLE");
});

test("Windows admission failure survives an unsuccessful uncertainty receipt", async () => {
  const f = fixture(),
    failure = new Error("independent admission unavailable"),
    persist = f.options.persist;
  f.options.verifyAdmission = async () => {
    throw failure;
  };
  f.options.persist = async (record) => {
    if (record.phase === "uncertain") throw new Error("receipt unavailable");
    return persist(record);
  };
  const reader = f.reader();
  await assert.rejects(reader.start(), (error) => error === failure);
  assert.equal(f.records.at(-1).phase, "task-run-possible");
  assert.equal(f.records.at(-1).custody, "POSSIBLE");
  assert.ok(f.events.includes("fault"));
  assert.equal((await reader.close()).status, "RETAINED");
});

test("Windows callback and returned identity snapshots cannot rewrite admitted custody", async () => {
  const f = fixture(),
    verify = f.options.verifyAdmission;
  f.options.verifyAdmission = async (value) => {
    value.input.reader.sha256 = "d".repeat(64);
    return verify();
  };
  const reader = f.reader(),
    admitted = await reader.start();
  admitted.helper.pid = 99;
  admitted.verifier.pid = 99;
  for (const index of [0, 1, 2]) await reader.open(index);
  const file = await reader.openFile(f.file, f.transfer);
  file.identity.pid = 99;
  await file.close();
  assert.equal((await reader.close()).closed, true);
});

test("Windows held files, volumes, process creation identities and loader edges reject substitution", async () => {
  for (const [operation, damage] of [
    [
      "inspect",
      (value) => {
        value.identity = id(99);
      },
    ],
    [
      "inspect",
      (value) => {
        value.volumeHex = hex(
          "\\\\?\\Volume{99999999-2222-3333-4444-555555555555}\\",
        );
      },
    ],
    [
      "process",
      (value) => {
        value.identity.creationTime = "90000";
      },
    ],
    [
      "loader",
      (value) => {
        value.imports[0].resolved = 1;
      },
    ],
    [
      "loader",
      (value) => {
        value.complete = false;
      },
    ],
  ]) {
    const f = fixture(),
      reader = f.reader();
    await reader.start();
    await reader.open(0);
    await reader.retainProcess(f.process.identity);
    f.options.damage = (op, frame) => {
      if (op === operation) damage(frame.value);
      return frame;
    };
    await assert.rejects(
      operation === "inspect"
        ? reader.inspect(0)
        : operation === "process"
          ? reader.process(0)
          : reader.loader(0, 0),
    );
  }
});

test("Windows file transfer admits only the joined held roots and creation-time Job before release", async () => {
  const f = fixture(),
    reader = f.reader();
  await reader.start();
  for (const index of [0, 1, 2]) await reader.open(index);
  const file = await reader.openFile(f.file, f.transfer);
  assert.ok(
    f.events.indexOf("verify-transfer") <
      f.events.findIndex((event) => event.startsWith("helper-release ")),
  );
  assert.ok(
    f.events.indexOf("persist-helper-admitted") <
      f.events.findIndex((event) => event.startsWith("helper-release ")),
  );
  assert.deepEqual(await file.receive(), { ready: true });
  await file.send("P");
  assert.equal((await file.close()).closed, true);
  await assert.rejects(file.send("P"));
  assert.equal((await reader.close()).closed, true);
});

test("Windows pending helper creation excludes a second launch before native effects", async () => {
  const f = fixture(),
    reader = f.reader(),
    entered = Promise.withResolvers(),
    release = Promise.withResolvers(),
    send = f.owner.send;
  await reader.start();
  for (const index of [0, 1, 2]) await reader.open(index);
  f.owner.send = async (bytes) => {
    if (bytes.startsWith("helper-start ")) {
      entered.resolve();
      await release.promise;
    }
    return send(bytes);
  };
  const first = reader.openFile(f.file, f.transfer);
  await entered.promise;
  const pending = Promise.allSettled([
    first,
    reader.openFile(f.file, f.transfer),
  ]);
  release.resolve();
  const results = await pending;
  assert.equal(results[0].status, "fulfilled");
  await results[0].value.close();
  assert.equal((await reader.close()).closed, true);
  assert.equal(results[1].status, "rejected");
  assert.equal(
    f.events.filter((event) => event.startsWith("helper-start ")).length,
    1,
  );
});

test("Windows retirement verification excludes new helper effects", async () => {
  const f = fixture(),
    reader = f.reader(),
    entered = Promise.withResolvers(),
    release = Promise.withResolvers(),
    verify = f.options.verifyRetirement;
  await reader.start();
  for (const index of [0, 1, 2]) await reader.open(index);
  f.options.verifyRetirement = async (...args) => {
    entered.resolve();
    await release.promise;
    return verify(...args);
  };
  const closing = reader.close();
  await entered.promise;
  const [result] = await Promise.allSettled([
    reader.openFile(f.file, f.transfer),
  ]);
  if (result.status === "fulfilled") await result.value.close();
  release.resolve();
  assert.equal((await closing).closed, true);
  assert.equal(result.status, "rejected");
  assert.ok(!f.events.some((event) => event.startsWith("helper-start ")));
});

test("Windows incorrect transferred roots and unobserved creation authority withhold helper release", async () => {
  const wrong = fixture(),
    first = wrong.reader();
  await first.start();
  for (const index of [0, 1, 2]) await first.open(index);
  wrong.transfer.base = 1;
  await assert.rejects(first.openFile(wrong.file, wrong.transfer));
  assert.ok(!wrong.events.some((event) => event.startsWith("helper-start ")));
  assert.equal((await first.close()).closed, true);
  for (const damage of [
    (f) => {
      f.options.damage = (op, frame) => {
        if (op === "helper-start") frame.value.job.limitFlags |= 0x800;
        return frame;
      };
    },
    (f) => {
      f.options.verifyTransfer = async () => ({ independent: false });
    },
  ]) {
    const f = fixture(),
      reader = f.reader();
    await reader.start();
    for (const index of [0, 1, 2]) await reader.open(index);
    damage(f);
    await assert.rejects(reader.openFile(f.file, f.transfer));
    assert.ok(!f.events.some((event) => event.startsWith("helper-release ")));
    assert.equal((await reader.close()).status, "RETAINED");
  }
});

test("Windows policy handle lists cannot substitute a different observed pathname", async () => {
  const f = fixture(),
    policy = windowsPolicyFixture(f.file.request, runnerSid),
    reader = f.reader();
  await reader.start();
  for (const index of [0, 1, 2]) await reader.open(index);
  const objects = policy.plan.manifest.objects
    .filter((object) => object.name !== "registry")
    .map(() => 1);
  await assert.rejects(
    reader.openPolicy(policy.input, "install", { helper: 0, objects }),
  );
  assert.ok(!f.events.some((event) => event.startsWith("helper-start ")));
});

test("Windows policy transfer uses the complete ordered held-object list through the private helper pipe", async () => {
  const f = fixture({ policy: true }),
    reader = f.reader();
  await reader.start();
  for (const index of new Set([f.policyHelper, ...f.policyObjects]))
    await reader.open(index);
  const helper = await reader.openPolicy(f.policyFixture.input, "install", {
    helper: f.policyHelper,
    objects: f.policyObjects,
  });
  const command = f.events
      .find((event) => event.startsWith("helper-start "))
      .split(" "),
    argc = Number(command[4]),
    count = Number(command[5 + argc]);
  assert.equal(count, f.policyObjects.length);
  assert.deepEqual(command.slice(6 + argc).map(Number), f.policyObjects);
  assert.ok(
    f.events.indexOf("verify-transfer") <
      f.events.findIndex((event) => event.startsWith("helper-release ")),
  );
  await helper.send("P");
  assert.equal((await helper.close()).closed, true);
  assert.equal((await reader.close()).closed, true);
});

test("Windows cancellation while admission is pending cannot send a late setup acknowledgement", async () => {
  const f = fixture(),
    abort = new AbortController();
  let entered, finish;
  const waiting = new Promise((resolve) => {
    entered = resolve;
  });
  f.options.verifyAdmission = () => {
    entered();
    return new Promise((resolve) => {
      finish = resolve;
    });
  };
  const running = f.reader().start({ signal: abort.signal });
  await waiting;
  abort.abort();
  finish({
    independent: true,
    helper: f.helper,
    verifier: f.verifier,
    planSha256: f.input.plan.sha256,
    nativeEventSha256: hash,
  });
  await assert.rejects(running);
  assert.ok(!f.events.includes("P"));
  assert.equal(f.records.at(-1).custody, "POSSIBLE");
});

test("Windows child exit never replaces independent domain retirement or owned task removal", async () => {
  for (const name of ["verifyRetirement", "verifyTaskRemoval"]) {
    const f = fixture(),
      reader = f.reader();
    await reader.start();
    f.options[name] = async () => ({ status: "RETAINED", independent: false });
    assert.equal((await reader.close()).status, "RETAINED");
    assert.equal(f.records.at(-1).custody, "POSSIBLE");
    if (name === "verifyRetirement")
      assert.ok(!f.events.some((event) => event.startsWith("finish ")));
  }
});

test("Windows helper retirement cannot discard unread private output", async () => {
  const f = fixture(),
    reader = f.reader();
  await reader.start();
  for (const index of [0, 1, 2]) await reader.open(index);
  const helper = await reader.openFile(f.file, f.transfer);
  f.options.damage = (op, frame) => {
    if (op === "helper-finish") frame.value.drained = false;
    return frame;
  };
  await assert.rejects(helper.close());
  assert.equal((await reader.close()).status, "RETAINED");
});

function transport({ holdWrites = false } = {}) {
  const child = new EventEmitter();
  child.pid = 10;
  child.stdin = new Writable({
    write(_, __, done) {
      if (!holdWrites) done();
    },
  });
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  let deadline;
  const channel = windowsCustodyChannel(child, {
    schedule(callback, ms) {
      assert.equal(ms, 390000);
      deadline = callback;
      return 1;
    },
    cancel() {},
  });
  return { child, channel, expire: () => deadline() };
}
test("Windows private transport rejects truncation, malformed bytes, unread frames and expired completion", async () => {
  const pending = transport(),
    read = pending.channel.receive();
  pending.expire();
  await assert.rejects(read);
  await assert.rejects(pending.channel.completion);
  const malformed = transport(),
    bad = malformed.channel.receive();
  malformed.child.stdout.write(Buffer.from([0xff, 10]));
  await assert.rejects(bad);
  const truncated = transport(),
    frame = truncated.channel.receive();
  truncated.child.stdout.write('{"phase":');
  truncated.child.emit("close", 0, null);
  await assert.rejects(frame);
  await assert.rejects(truncated.channel.completion);
  const trailing = transport();
  trailing.child.stdout.write("{}\n");
  trailing.child.emit("close", 0, null);
  await assert.rejects(trailing.channel.completion);
  const exited = transport(),
    verification = exited.channel.wait(new Promise(() => {}));
  exited.child.emit("close", 0, null);
  exited.expire();
  await assert.rejects(verification);
  const writing = transport({ holdWrites: true }),
    written = assert.rejects(writing.channel.send("P\n"));
  writing.child.emit("close", 0, null);
  try {
    await assert.rejects(writing.channel.completion);
    assert.throws(() => writing.channel.settle());
  } finally {
    writing.channel.close();
    await written;
  }
});
