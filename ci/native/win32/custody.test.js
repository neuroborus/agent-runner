import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { PassThrough, Writable } from "node:stream";
import test from "node:test";

import {
  createWindowsCustodyReader,
  createWindowsCustodyVerifier,
  encodeWindowsCustodyPlan,
  windowsCompilerArguments,
  WINDOWS_CUSTODY_DEADLINE_MS,
} from "./index.js";
import { windowsCustodyChannel } from "./channel.js";
import { digest } from "./protocol.js";
import { observationDigest } from "../index.js";
import { createPrerequisiteTransport } from "../prerequisite-transport.js";
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
function fixture({ policy = false, git = false, observer = false } = {}) {
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
  let gitInput, gitTransfer, gitPolicyTransfer;
  if (git) {
    const add = (entry) => {
      entries.push(entry);
      return entries.length - 1;
    };
    const gitImage = {
      ...image("git-fixture.exe"),
      path: file.request.storage + "\\git-fixture.exe",
    };
    bytes.set(gitImage.path, executable());
    const helperSlot = add({ kind: "helper", ...gitImage });
    const gitTool = {
      ...image("git.exe"),
      path: file.request.storage + "\\git.exe",
    };
    bytes.set(gitTool.path, executable());
    const gitSlot = add({ kind: "image", ...gitTool });
    const directory = (name) =>
      add({
        kind: "directory",
        path: file.request.storage + "\\" + name,
        sha256: null,
        signatureSha256: null,
      });
    const metadata = directory("metadata"),
      hooks = directory("hooks");
    const content = add({
      kind: "data",
      path: file.request.workspace + "\\content.txt",
      sha256: hash,
      signatureSha256: null,
    });
    gitInput = {
      request: {
        ...file.request,
        executable: { ...gitImage, parser: "msvc-ucrt-wmain-v1" },
      },
      git: gitTool,
      metadata: entries[metadata].path,
      hooks: entries[hooks].path,
      parent: "e".repeat(40),
      accountSid: runnerSid,
      reviewSha256: hash,
    };
    gitTransfer = {
      helper: helperSlot,
      git: gitSlot,
      metadata,
      workspace: 2,
      hooks,
    };
    gitPolicyTransfer = {
      helper: add({ kind: "helper", ...image("git-policy.exe") }),
      storage: 1,
      workspace: 2,
      objects: [metadata, hooks, content],
    };
  }
  let observerSlot;
  if (observer) {
    observerSlot = entries.length;
    entries.push({ kind: "helper", ...image("observer-helper.exe") });
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
    sources: [
      "custody-reader.c",
      "custody-bridge.c",
      "custody.h",
      "effective-reader.h",
      "account.h",
    ].map(source),
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
      if (op === "verifier") value = verifier;
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
      if (op === "helper-start") {
        job.processLimit = ["git", "build"].includes(a) ? 32 : 1;
        const actor = a === "observer" ? identity(31) : fileHelper;
        job.members = [actor];
        value = {
          helper: actor,
          processDaclSha256: hash,
          threadDaclSha256: hash,
          inheritedHandleCount: Number(parts[5 + Number(parts[4])]) + 2,
          job,
          ...(["git", "build"].includes(a)
            ? { creatorDefaultDaclSha256: hash }
            : {}),
          ...(a === "file" ? { fileRootDeleteSharing: true } : {}),
        };
      }
      if (op === "helper-release") value = { released: true };
      if (op === "helper-send") value = { sent: true };
      if (op === "helper-close-input") value = { closed: true };
      if (op === "helper-read")
        value = {
          hex: Buffer.from(JSON.stringify({ ready: true })).toString("hex"),
        };
      if (op === "helper-bytes") value = { hex: "00" };
      if (op === "audit-install") value = { installed: true, objects: 1 };
      if (op === "audit-restore") value = { restored: true };
      if (op === "helper-finish")
        value = { retired: true, members: 0, drained: true, exitCode: 0 };
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
        helper: value.child,
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
        ...(["git", "build"].includes(value.transfer.kind)
          ? { creatorDefaultDaclSha256: hash }
          : {}),
        ...(value.transfer.kind === "file"
          ? { fileRootDeleteSharing: true }
          : {}),
      };
    },
    verifyHelperRetirement: async (child) => retirement(child),
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
    gitInput,
    gitTransfer,
    gitPolicyTransfer,
    policyObjects,
    observerSlot,
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
  await assert.rejects(reader.read(3, 536870912, 1));
  assert.equal(f.events.length, effects);
  assert.equal((await reader.read(3, 0, 4)).toString(), "data");
  assert.equal((await reader.close()).closed, true);
  assert.ok(
    f.events.indexOf("verify-retirement") < f.events.indexOf("finish 3"),
  );
  assert.equal(f.records.at(-1).custody, "RETIRED");
});

test("Windows native XML and path arguments stay on private transport, outside persisted command intents", async () => {
  const f = fixture();
  f.options.damage = (op, frame) =>
    op === "xml" ? { ...frame, value: { kind: "event", fields: [] } } : frame;
  const reader = f.reader();
  await reader.start();
  const bytes = Buffer.from("<Event>protected selector</Event>\0", "utf16le");
  await reader.xml(bytes);
  const record = f.records.find((item) => item.phase === "xml");
  assert.equal(
    record.argumentsSha256,
    observationDigest([bytes.toString("hex")]),
  );
  assert.ok(!JSON.stringify(f.records).includes(bytes.toString("hex")));
  await reader.close();
});
test("Windows live verifier checks use temporary custody without retaining a payload process", async () => {
  const f = fixture(),
    reader = f.reader();
  await reader.start();
  assert.deepEqual(await reader.verifier(f.verifier), f.verifier);
  const effects = f.events.length;
  await assert.rejects(
    reader.verifier({ ...f.verifier, creationTime: "10999" }),
  );
  assert.equal(f.events.length, effects);
  assert.ok(!f.events.some((event) => event.startsWith("process-open")));
  await reader.close();
});
test("Windows owned audit restoration fences new custody until fresh retirement verification settles", async () => {
  const f = fixture(),
    reader = f.reader();
  f.options.damage = (op, frame) =>
    op === "audit-install"
      ? { ...frame, value: { installed: true, objects: 1 } }
      : op === "audit-restore"
        ? { ...frame, value: { restored: true } }
        : frame;
  const retirement = Promise.withResolvers(),
    verificationStarted = Promise.withResolvers();
  f.options.verifyAuditRetirement = () => {
    verificationStarted.resolve();
    return retirement.promise;
  };
  await reader.start();
  await reader.open(3);
  await reader.retainProcess(f.process.identity);
  await reader.installAudit(0, [{ index: 3, descriptorSha256: hash }], hash);
  f.process.retired = true;
  const pending = reader.restoreAudit();
  await verificationStarted.promise;
  const effects = f.events.length;
  await assert.rejects(
    reader.retainProcess({ ...f.process.identity, pid: 51 }),
  );
  await assert.rejects(reader.job());
  assert.equal(f.events.length, effects);
  retirement.resolve({
    status: "RETIRED",
    independent: true,
    emergencyCleanup: false,
    candidateSha,
    nonce,
    noLiveMembers: true,
    noForeignCreators: true,
    noPrincipalFlows: true,
    exclusiveWriter: true,
    admissionsClosed: true,
    verifier: f.verifier,
    nativeEventSha256: hash,
  });
  assert.equal((await pending).restored, true);
  await reader.close();
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
  assert.deepEqual(await file.completion, {
    code: 0,
    signal: null,
    failed: false,
    partialBytes: 0,
    remainingMessages: 0,
  });
  file.dispose();
  await assert.rejects(file.send("P"));
  assert.equal((await reader.close()).closed, true);
});

test("Windows file completion exposes only native drained retirement and the bounded interruption exit", async () => {
  for (const exitCode of [126, 1]) {
    const f = fixture(),
      reader = f.reader();
    await reader.start();
    for (const index of [0, 1, 2]) await reader.open(index);
    const channel = await reader.openFile(f.file, f.transfer);
    f.options.damage = (op, frame) => {
      if (op === "helper-finish") frame.value.exitCode = exitCode;
      return frame;
    };
    if (exitCode === 126) {
      channel.close();
      assert.equal((await channel.completion).code, 126);
      assert.equal((await reader.close()).closed, true);
    } else {
      await assert.rejects(channel.close());
      await assert.rejects(channel.completion);
    }
    assert.ok(
      f.events.some((event) => event.startsWith("helper-close-input ")),
    );
  }
});

test("Windows active Security observation has separate helper pipes through file work and retirement", async () => {
  const f = fixture({ observer: true }),
    reader = f.reader();
  await reader.start();
  for (const index of [0, 1, 2, 3, f.observerSlot]) await reader.open(index);
  await reader.retainProcess(f.process.identity);
  await reader.installAudit(0, [{ index: 3, descriptorSha256: hash }], hash);
  const domain = {
    accountSid: runnerSid,
    restrictingSid: f.file.request.restrictingSid,
    jobSha256: hash,
  };
  const value = {
    plan: {
      schemaVersion: 1,
      candidateSha,
      nonce,
      domainSha256: observationDigest(domain),
      policySha256: hash,
      reviewSha256: hash,
      routes: [
        {
          id: "inspect",
          operation: "read",
          targetSha256: digest("target"),
          permitTargetSha256: digest("permit"),
          denyTargetSha256: digest("deny"),
          nonceSha256: hash,
          beforeSha256: hash,
          afterSha256: hash,
          outcome: "permit",
        },
      ],
    },
    domain,
    bindings: ["control-permit", "control-deny", "tool"].map((phase) => ({
      routeId: "inspect",
      phase,
      selector: f.entries[3].path,
      opcode: "4663",
      accessMask: 1,
      filterId: null,
    })),
    pins: {
      manifestSha256: hash,
      imageSha256: f.entries[f.observerSlot].sha256,
      sourceSha256: hash,
      abiSha256: hash,
    },
  };
  const observer = await reader.openObserver(value, f.observerSlot);
  const file = await reader.openFile(f.file, f.transfer);
  assert.notEqual(observer.identity.pid, file.helper.pid);
  await observer.send("P");
  await file.send("P");
  await observer.receive(1);
  await file.receive();
  await file.close();
  await observer.send("S");
  assert.equal((await observer.close()).drained, true);
  const lanes = f.events
    .filter((event) => event.startsWith("helper-send "))
    .map((event) => event.split(" ")[2]);
  assert.deepEqual(lanes, ["1", "0", "1"]);
  f.process.retired = true;
  f.options.verifyAuditRetirement = async () => ({
    status: "RETIRED",
    independent: true,
    emergencyCleanup: false,
    nativeEventSha256: hash,
    exclusiveWriter: true,
    admissionsClosed: true,
    candidateSha,
    nonce,
    noLiveMembers: true,
    noForeignCreators: true,
    noPrincipalFlows: true,
    verifier: f.verifier,
  });
  await reader.restoreAudit();
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

test("Windows file release requires native and independent delete-sharing evidence for owned root controls", async () => {
  for (const damage of ["missing", "proof"]) {
    const f = fixture(),
      reader = f.reader();
    await reader.start();
    for (const index of [0, 1, 2]) await reader.open(index);
    if (damage === "missing")
      f.options.damage = (op, frame) => {
        if (op === "helper-start") delete frame.value.fileRootDeleteSharing;
        return frame;
      };
    else {
      const verify = f.options.verifyTransfer;
      f.options.verifyTransfer = async (value) => ({
        ...(await verify(value)),
        fileRootDeleteSharing: false,
      });
    }
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

test("Windows admitted work cancellation retains custody for bounded cleanup and fences new process/Job/helper admissions", async () => {
  const f = fixture(),
    work = new AbortController(),
    reader = f.reader();
  await reader.start({ signal: work.signal });
  for (const index of [0, 1, 2]) await reader.open(index);
  await assert.rejects(
    reader.beginCleanup({ signal: new AbortController().signal }),
  );
  work.abort();
  assert.ok(!f.events.includes("fault"));
  await reader.beginCleanup({ signal: new AbortController().signal });
  const before = f.events.length;
  await assert.rejects(reader.retainProcess(f.fileHelper));
  await assert.rejects(reader.job());
  await assert.rejects(reader.openFile(f.file, f.transfer));
  assert.equal(f.events.length, before);
  assert.equal((await reader.close()).closed, true);
  assert.equal(
    f.records.find((record) => record.phase === "cleanup").admission,
    "CLOSED",
  );
});

test("Windows cleanup cancellation retains the possible task and cannot acknowledge retirement", async () => {
  const f = fixture(),
    work = new AbortController(),
    finish = new AbortController(),
    reader = f.reader();
  await reader.start({ signal: work.signal });
  work.abort();
  await reader.beginCleanup({ signal: finish.signal });
  finish.abort();
  assert.ok(f.events.includes("fault"));
  assert.equal((await reader.close()).status, "RETAINED");
  assert.ok(!f.records.some((record) => record.phase === "retired"));
});

test("Windows cleanup only admits owned removal with fresh unchanged-state and retirement evidence", async () => {
  for (const damage of [null, "installed", "retirement"]) {
    const f = fixture({ policy: true }),
      work = new AbortController(),
      reader = f.reader();
    await reader.start({ signal: work.signal });
    for (const index of new Set([f.policyHelper, ...f.policyObjects]))
      await reader.open(index);
    work.abort();
    await reader.beginCleanup({ signal: new AbortController().signal });
    const transfer = { helper: f.policyHelper, objects: f.policyObjects };
    await assert.rejects(
      reader.openPolicy(f.policyFixture.input, "remove", transfer),
    );
    const retirement = {
      status: "RETIRED",
      independent: true,
      emergencyCleanup: false,
      nativeEventSha256: hash,
      candidateSha,
      nonce,
      noLiveMembers: damage !== "retirement",
    };
    if (damage === "retirement") {
      await assert.rejects(reader.authorizeRestoration(retirement));
      continue;
    }
    await reader.authorizeRestoration(retirement);
    f.options.verifyRestoration = async (observations) => ({
      independent: true,
      noLiveMembers: true,
      unchangedInstalled: damage !== "installed",
      observationsSha256: observationDigest(observations),
      verifier: f.verifier,
      nativeEventSha256: hash,
    });
    await assert.rejects(
      reader.openPolicy(f.policyFixture.input, "install", transfer),
    );
    if (damage)
      await assert.rejects(
        reader.openPolicy(f.policyFixture.input, "remove", transfer),
      );
    else {
      const helper = await reader.openPolicy(
        f.policyFixture.input,
        "remove",
        transfer,
      );
      await helper.close();
      assert.equal((await reader.close()).closed, true);
      assert.ok(
        f.records.some((record) => record.phase === "restore-helper-possible"),
      );
    }
    if (damage)
      assert.ok(!f.events.some((event) => event.startsWith("helper-start ")));
  }
});

test("Windows Git helpers use fixed vectors and a complete distinct held-object list", async () => {
  const f = fixture({ git: true }),
    reader = f.reader();
  await reader.start();
  for (const index of new Set([
    ...Object.values(f.gitTransfer),
    f.gitPolicyTransfer.helper,
    f.gitPolicyTransfer.storage,
    ...f.gitPolicyTransfer.objects,
  ]))
    await reader.open(index);
  const policy = await reader.openGitPolicy(
    f.gitInput,
    "install",
    f.gitPolicyTransfer,
  );
  const command = f.events
      .find((event) => event.startsWith("helper-start "))
      .split(" "),
    argc = Number(command[4]);
  assert.equal(command[2], "git-policy");
  assert.deepEqual(command.slice(6 + argc).map(Number), [
    1,
    2,
    ...f.gitPolicyTransfer.objects,
  ]);
  await policy.close();
  await assert.rejects(
    reader.openGitPolicy(f.gitInput, "install", {
      ...f.gitPolicyTransfer,
      objects: [1, ...f.gitPolicyTransfer.objects],
    }),
  );
  const helper = await reader.openGit(f.gitInput, f.gitTransfer);
  assert.ok(
    f.events.some(
      (event) =>
        event.startsWith("helper-start ") && event.split(" ")[2] === "git",
    ),
  );
  await helper.close();
  assert.equal((await reader.close()).closed, true);
});

test("Windows fixed Git release requires independently joined creator default DACL evidence", async () => {
  for (const damage of ["missing", "mismatch"]) {
    const f = fixture({ git: true }),
      reader = f.reader();
    await reader.start();
    for (const index of Object.values(f.gitTransfer)) await reader.open(index);
    if (damage === "missing")
      f.options.damage = (op, frame) => {
        if (op === "helper-start") delete frame.value.creatorDefaultDaclSha256;
        return frame;
      };
    else {
      const verify = f.options.verifyTransfer;
      f.options.verifyTransfer = async (value) => ({
        ...(await verify(value)),
        creatorDefaultDaclSha256: "f".repeat(64),
      });
    }
    await assert.rejects(reader.openGit(f.gitInput, f.gitTransfer));
    assert.ok(!f.events.some((event) => event.startsWith("helper-release ")));
    assert.equal((await reader.close()).status, "RETAINED");
  }
});

test("Windows build publication joins held output and reviewed certificate image to independent closed-writer proof", async () => {
  for (const damage of [null, "image", "proof"]) {
    const f = fixture();
    f.input.context.executionId = "build";
    const request = { candidateSha, cwd: f.entries[1].path },
      operation = {
        mode: "compile",
        helper: { sha256: f.entries[0].sha256 },
        source: { path: "C:\\Fixture\\Sealed\\file-helper.c", sha256: hash },
        target: f.entries[1].path + "\\file-helper.exe",
      };
    request.args = windowsCompilerArguments(
      operation.source.path,
      operation.target,
    );
    f.options.damage = (op, frame) =>
      op === "publish-build"
        ? {
            ...frame,
            value: {
              identity: id(5),
              sha256: damage === "image" ? hash : f.entries[0].sha256,
              signatureSha256: hash,
              daclSha256: hash,
              writerClosed: true,
            },
          }
        : frame;
    f.options.verifyPublication = async (observations) => ({
      independent: true,
      verifier: f.verifier,
      observationsSha256:
        damage === "proof" ? hash : observationDigest(observations),
      protectedDacl: true,
      writerClosed: true,
      nativeEventSha256: hash,
      settlement: {
        status: "RETIRED",
        independent: true,
        emergencyCleanup: false,
        nativeEventSha256: hash,
      },
    });
    const reader = f.reader();
    await reader.start();
    await reader.open(0);
    await reader.open(1);
    const result = reader.publishBuild(request, operation, hash, {
      image: 0,
      root: 1,
    });
    if (damage) await assert.rejects(result);
    else {
      assert.equal((await result).imageSha256, f.entries[0].sha256);
      assert.ok(f.records.some((record) => record.phase === "build-published"));
    }
    await reader.close();
  }
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
      assert.equal(ms, WINDOWS_CUSTODY_DEADLINE_MS);
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

// Only raw native frames are replaced. These tests supply no approval,
// transfer, retirement or completed-custody callback implementation.
function verificationFixture(f = fixture()) {
  const transferred = new Set(),
    events = [],
    subjects = [],
    files = [],
    jobs = [];
  const states = new Map(
    [f.helper, identity(10, runnerSid), f.fileHelper].map((actor) => [
      actor.pid,
      { ...structuredClone(f.process), identity: actor },
    ]),
  );
  const observerPlanPath = "C:\\Fixture\\Sealed\\verification-plan",
    observerPlan = encodeWindowsCustodyPlan({
      candidateSha,
      nonce: "e".repeat(32),
      entries: [
        ...f.entries,
        ...[
          f.input.bridge,
          f.input.reader,
          f.input.plan,
          ...f.input.sources,
        ].map((pin) => ({
          kind: pin.signatureSha256 ? "image" : "data",
          ...pin,
          signatureSha256: pin.signatureSha256 ?? null,
        })),
      ],
    });
  f.bytes.set(observerPlanPath, observerPlan);
  const observer = {
    verification: {
      input: {
        ...structuredClone(f.input),
        nonce: "e".repeat(32),
        plan: { path: observerPlanPath, sha256: digest(observerPlan) },
      },
      identity: f.verifier,
    },
  };
  const state = {
    absent: false,
    instances: 1,
    damage: null,
    jobMembers: [f.fileHelper],
    jobDacl: hash,
    unknownHandle: false,
    removedTasks: new Set(),
  };
  const exchange = async (bytes) => {
    assert.ok(Buffer.isBuffer(bytes));
    const [operation, sequence, ...args] = bytes.toString().trim().split(" ");
    events.push({ operation, args });
    let value;
    const name = operation.slice(7);
    if (name === "file") {
      const file = Buffer.from(args[0], "hex").toString("utf16le"),
        data = f.bytes.get(file),
        slot = files.length;
      assert.ok(data);
      assert.ok(data.length <= Number(args[3]));
      files.push(data);
      value = {
        identity: id(slot + 100),
        sha256: digest(data),
        signatureSha256: args[2] === "-" ? null : args[2],
        daclSha256: hash,
        slot,
        bytes: data.length,
      };
    } else if (name === "read")
      value = {
        hex: files[Number(args[0])]
          .subarray(Number(args[1]), Number(args[1]) + Number(args[2]))
          .toString("hex"),
      };
    else if (name === "retain") {
      const actor = states.get(Number(args[0]));
      assert.ok(actor);
      let slot = subjects.indexOf(actor);
      if (slot < 0) {
        slot = subjects.length;
        subjects.push(actor);
      }
      value = { slot, process: actor };
    } else if (name === "process") value = subjects[Number(args[0])];
    else if (name === "subjects")
      value = {
        identities: subjects.map((actor) => actor.identity),
        jobs: jobs.map((_, slot) => slot),
      };
    else if (name === "image") {
      const pid = subjects[Number(args[0])].identity.pid,
        pin =
          pid === f.helper.pid
            ? f.input.reader
            : pid === 10
              ? f.input.bridge
              : f.entries[0];
      value = {
        sha256: pin.sha256,
        signatureSha256: pin.signatureSha256,
        pathHex: hex(pin.path),
      };
    } else if (name === "task")
      value =
        state.absent || state.removedTasks.has(args[1])
          ? { absent: true }
          : { absent: false, sha256: hash, instances: state.instances };
    else if (name === "transfer") {
      transferred.add(Number(args[0]));
      value = {
        threadDaclSha256: hash,
        job: {
          daclSha256: hash,
          limitFlags: 0x2008,
          processLimit: 1,
          uiRestrictions: 255,
          members: state.jobMembers,
        },
        objects: [
          null,
          null,
          id(2),
          id(3),
          ...(state.unknownHandle ? [id(9)] : []),
        ],
        inheritedHandleCount: state.unknownHandle ? 5 : 4,
        pipeDaclSha256: [hash, hash],
        creatorDefaultDaclSha256: hash,
      };
    } else if (name === "sharing") value = { identity: id(2) };
    else if (name === "job")
      value = transferred.has(Number(args[0]))
        ? {
            daclSha256: hash,
            limitFlags: 0x2008,
            processLimit: 1,
            uiRestrictions: 255,
            members: state.jobMembers,
          }
        : { absent: true };
    else if (name === "job-open") {
      value = {
        slot: jobs.length,
        observation: {
          daclSha256: state.jobDacl,
          limitFlags: 0x2008,
          processLimit: 32,
          uiRestrictions: 255,
          members: state.jobMembers,
        },
      };
      jobs.push(args[0]);
    } else if (name === "job-read") {
      assert.equal(jobs[Number(args[0])], args[1]);
      value = {
        daclSha256: state.jobDacl,
        limitFlags: 0x2008,
        processLimit: 32,
        uiRestrictions: 255,
        members: state.jobMembers,
      };
    } else if (name === "task-remove") {
      assert.ok(subjects.every((actor) => actor.retired));
      assert.equal(state.jobMembers.length, 0);
      state.removedTasks.add(args[1]);
      value = { removed: true, sha256: args[2] };
    } else throw new Error("Undeclared raw native command");
    const frame = { sequence: Number(sequence), value: structuredClone(value) };
    return state.damage
      ? state.damage(operation, frame)
      : Buffer.from(JSON.stringify(frame) + "\n");
  };
  const verifier = createWindowsCustodyVerifier(observer, { exchange });
  const admission = {
    input: f.input,
    helper: f.helper,
    bridge: identity(10, runnerSid),
    taskSha256: hash,
    processDaclSha256: hash,
  };
  const transfer = {
    kind: "file",
    args: [],
    request: f.file.request,
    image: f.entries[0],
    objects: [f.object(1), f.object(2)],
  };
  const helperTransfer = {
    input: f.input,
    child: f.fileHelper,
    creator: f.helper,
    transfer,
    transferSha256: observationDigest(transfer),
    actual: {
      processDaclSha256: hash,
      threadDaclSha256: hash,
      job: {
        daclSha256: hash,
        limitFlags: 0x2008,
        processLimit: 1,
        uiRestrictions: 255,
        members: [f.fileHelper],
      },
    },
  };
  return {
    f,
    events,
    states,
    state,
    observer,
    verifier,
    admission,
    helperTransfer,
    exchange,
  };
}

test("Windows repository verifier joins separately admitted source, process/token, task and transferred objects through raw native frames", async () => {
  const k = verificationFixture();
  assert.equal(k.events.length, 0);
  const sealed = await k.verifier.verifyBootstrap(k.f.input);
  assert.equal(sealed.entries.length, 8);
  const admitted = await k.verifier.verifyAdmission(k.admission);
  assert.deepEqual(admitted.verifier, k.f.verifier);
  const transferred = await k.verifier.verifyTransfer(k.helperTransfer);
  assert.equal(transferred.fileRootDeleteSharing, true);
  k.states.get(k.f.fileHelper.pid).retired = true;
  k.state.jobMembers = [];
  assert.equal(
    (await k.verifier.verifyHelperRetirement(k.f.fileHelper)).status,
    "RETIRED",
  );
  assert.equal(
    (
      await k.verifier.verifyRetirement({
        input: k.f.input,
        helper: k.f.helper,
        processes: [],
        jobs: [],
      })
    ).noLiveMembers,
    true,
  );
  k.states.get(k.f.helper.pid).retired = true;
  k.states.get(10).retired = true;
  k.state.absent = true;
  const closed = await k.verifier.verifyTaskRemoval({
    input: k.f.input,
    helper: k.f.helper,
    taskSha256: hash,
  });
  assert.equal(closed.taskRemoved, true);
  assert.deepEqual(closed.verifier, k.f.verifier); // Preparation retains this live observer.
  assert.equal(
    k.events.filter((entry) => entry.operation === "verify-task").length,
    3,
  );
});

test("Windows verifier rejects reused births, changed task identity and malformed native frames without accepting later replies", async () => {
  for (const damage of [
    "birth",
    "task",
    "inactive-task",
    "sequence",
    "utf8",
    "extra",
  ]) {
    const k = verificationFixture();
    await k.verifier.verifyBootstrap(k.f.input);
    k.state.damage = (operation, frame) => {
      if (damage === "birth" && operation === "verify-retain")
        frame.value.process.identity.creationTime = "99999";
      if (damage === "task" && operation === "verify-task")
        frame.value.sha256 = "f".repeat(64);
      if (damage === "inactive-task" && operation === "verify-task")
        frame.value.instances = 0;
      if (damage === "sequence") frame.sequence++;
      if (damage === "utf8") return Buffer.from([0xff, 10]);
      if (damage === "extra") frame.unexpected = true;
      return Buffer.from(JSON.stringify(frame) + "\n");
    };
    let first;
    await assert.rejects(k.verifier.verifyAdmission(k.admission), (error) => {
      first = error;
      return true;
    });
    const count = k.events.length;
    k.state.damage = null;
    await assert.rejects(
      k.verifier.verifyAdmission(k.admission),
      (error) => error === first,
    );
    assert.equal(k.events.length, count);
  }
});

test("Windows whole-Job retirement and independent transferred handles cannot be replaced by process exit", async () => {
  for (const damage of [
    "extra-handle",
    "missing-pipe-dacl",
    "survivor",
    "unreadable",
  ]) {
    const k = verificationFixture();
    await k.verifier.verifyBootstrap(k.f.input);
    await k.verifier.verifyAdmission(k.admission);
    if (["extra-handle", "missing-pipe-dacl"].includes(damage)) {
      k.state.unknownHandle = damage === "extra-handle";
      if (damage === "missing-pipe-dacl")
        k.state.damage = (operation, frame) => {
          if (operation === "verify-transfer")
            delete frame.value.pipeDaclSha256;
          return Buffer.from(JSON.stringify(frame) + "\n");
        };
      await assert.rejects(k.verifier.verifyTransfer(k.helperTransfer));
      continue;
    }
    await k.verifier.verifyTransfer(k.helperTransfer);
    k.states.get(k.f.fileHelper.pid).retired = true;
    if (damage === "unreadable")
      k.state.damage = () => {
        throw new Error("Native Job observation inaccessible");
      };
    await assert.rejects(k.verifier.verifyHelperRetirement(k.f.fileHelper));
  }
});

test("Windows completed custody rereads retained subjects and task absence twice, retaining missing handles and untracked Jobs", async () => {
  const k = verificationFixture();
  for (const actor of [k.f.helper, k.f.fileHelper])
    await k.exchange(
      Buffer.from(
        ["verify-retain", 1, actor.pid, actor.creationTime].join(" ") + "\n",
      ),
    );
  for (const state of k.states.values()) state.retired = true;
  k.state.absent = true;
  const proof = await k.verifier.verifyCompleted(
    k.f.input,
    [k.f.helper, k.f.fileHelper],
    [nonce],
  );
  assert.equal(proof.tasksRemoved, true);
  assert.equal(
    k.events.filter((entry) => entry.operation === "verify-task").length,
    2,
  );
  const empty = verificationFixture();
  empty.state.absent = true;
  await assert.rejects(
    empty.verifier.verifyCompleted(empty.f.input, [], [nonce]),
  );
  assert.equal(empty.events.length, 0);
  const missing = verificationFixture();
  missing.states.get(missing.f.helper.pid).retired = true;
  missing.state.absent = true;
  await assert.rejects(
    missing.verifier.verifyCompleted(
      missing.f.input,
      [missing.f.helper],
      [nonce],
    ),
  );
  assert.equal(
    missing.events.filter((entry) => entry.operation === "verify-retain")
      .length,
    0,
  ); // Reconstruction never opens replacement process handles.
  const job = verificationFixture();
  job.states.get(job.f.helper.pid).retired = true;
  await assert.rejects(
    job.verifier.verifyCompleted(job.f.input, [job.f.helper], [nonce], [0]),
  );
  const joined = verificationFixture();
  await joined.verifier.verifyBootstrap(joined.f.input);
  await joined.verifier.verifyAdmission(joined.admission);
  await joined.verifier.verifyTransfer(joined.helperTransfer);
  for (const actor of joined.states.values()) actor.retired = true;
  joined.state.absent = true;
  const identities = [
    joined.f.helper,
    identity(10, runnerSid),
    joined.f.fileHelper,
  ];
  const fresh = () =>
    createWindowsCustodyVerifier(joined.observer, {
      exchange: joined.exchange,
    });
  // The native transfer Job survives loss of the old JavaScript maps.
  await assert.rejects(
    fresh().verifyCompleted(joined.f.input, identities, [nonce]),
  );
  joined.state.jobMembers = [];
  // A declaration cannot omit a subject still retained by the native reader.
  await assert.rejects(
    fresh().verifyCompleted(joined.f.input, [joined.f.helper], [nonce]),
  );
  assert.equal(
    (await fresh().verifyCompleted(joined.f.input, identities, [nonce])).status,
    "RETIRED",
  );
});

test("Windows verifier captures concurrent caller declarations and bounds protected records before native reads", async () => {
  const k = verificationFixture(),
    declaration = structuredClone(k.f.input),
    admission = structuredClone(k.admission);
  const sealed = k.verifier.verifyBootstrap(declaration),
    admitted = k.verifier.verifyAdmission(admission);
  declaration.reader.sha256 = "f".repeat(64);
  admission.helper.pid = 99;
  await sealed;
  assert.deepEqual((await admitted).helper, k.f.helper);
  const bounded = verificationFixture();
  await assert.rejects(
    bounded.verifier.read({
      path: "C:\\Fixture\\record",
      sha256: hash,
      bytes: 8388609,
    }),
  );
  assert.equal(bounded.events.length, 0);
  const context = verificationFixture(),
    wrong = structuredClone(context.f.input);
  wrong.context.runAttempt++;
  await assert.rejects(context.verifier.verifyBootstrap(wrong));
  assert.equal(context.events.length, 0);
  for (const operation of ["retain", "recover"]) {
    const collision = verificationFixture();
    collision.observer.verification.record = async () => {};
    const request = {
      platform: "win32",
      job: collision.f.input.context,
      admission: {
        platform: "win32",
        nonce: collision.observer.verification.input.nonce,
      },
    };
    await assert.rejects(
      operation === "retain"
        ? collision.verifier.retainPrerequisiteJob(request)
        : collision.verifier.recoverPrerequisite(
            request,
            { file: "C:\\Fixture\\Storage\\intent", bytes: 1, sha256: hash },
            {},
          ),
    );
    assert.equal(collision.events.length, 0);
  }
});

test("Windows task-removal acknowledgement cannot replace fresh independent absence or settle the live observer", async () => {
  const k = verificationFixture();
  await k.verifier.verifyBootstrap(k.f.input);
  await k.verifier.verifyAdmission(k.admission);
  k.states.get(k.f.helper.pid).retired = true;
  k.states.get(10).retired = true;
  await assert.rejects(
    k.verifier.verifyTaskRemoval({
      input: k.f.input,
      helper: k.f.helper,
      taskSha256: hash,
    }),
  );
  const self = verificationFixture();
  await assert.rejects(
    self.verifier.verifyCompleted(self.f.input, [self.f.verifier], [nonce]),
  );
  const unowned = verificationFixture();
  await assert.rejects(
    unowned.verifier.recoverPrerequisite(
      {},
      { file: "C:\\Fixture\\intent", bytes: 1, sha256: hash },
      {},
    ),
  );
  assert.equal(unowned.events.length, 0); // No owned deletion without protected settlement persistence.
});

test("Windows final task absence cannot settle a surviving retained child or its Job", async () => {
  for (const damage of ["child", "job"]) {
    const k = verificationFixture();
    await k.verifier.verifyBootstrap(k.f.input);
    await k.verifier.verifyAdmission(k.admission);
    await k.verifier.verifyTransfer(k.helperTransfer);
    k.states.get(k.f.helper.pid).retired = true;
    k.states.get(10).retired = true;
    k.states.get(k.f.fileHelper.pid).retired = damage !== "child";
    k.state.jobMembers = damage === "job" ? [identity(31)] : [];
    k.state.absent = true;
    await assert.rejects(
      k.verifier.verifyTaskRemoval({
        input: k.f.input,
        helper: k.f.helper,
        taskSha256: hash,
      }),
    );
  }
});

test("Windows completed custody cannot omit a retained named Job", async () => {
  const k = verificationFixture();
  await k.exchange(
    Buffer.from(
      ["verify-retain", 1, k.f.helper.pid, k.f.helper.creationTime].join(" ") +
        "\n",
    ),
  );
  await k.exchange(
    Buffer.from(
      ["verify-job-open", 2, hex("Local\\NativeProof-" + nonce)].join(" ") +
        "\n",
    ),
  );
  k.states.get(k.f.helper.pid).retired = true;
  k.state.absent = true;
  await assert.rejects(
    k.verifier.verifyCompleted(k.f.input, [k.f.helper], [nonce]),
  );
});

async function prerequisiteVerificationFixture({
  lostObserver = false,
  missingBirth = false,
  liveMember = false,
  lostJobSlot = false,
  changedJob = false,
  changedTask = false,
  writableOutput = false,
} = {}) {
  const f = fixture(),
    bootstrap = verificationFixture(f),
    kernel = verificationFixture(f);
  // Exercise the repository adapter and verifier. Only byte reads, persistence
  // and the two independently admitted native channels are replaced.
  let bootstrapSequence = 0;
  bootstrap.observer.verification.command = async (name, args) => {
    const reply = await bootstrap.exchange(
      Buffer.from(
        ["verify-" + name, ++bootstrapSequence, ...args].join(" ") + "\n",
      ),
    );
    return JSON.parse(reply).value;
  };
  f.options.verificationReader = bootstrap.observer;
  for (const name of Object.keys(f.options))
    if (name.startsWith("verify"))
      f.options[name] = () => {
        throw new Error("High-level verification replacement reached");
      };
  const send = f.owner.send;
  f.owner.send = async (line) => {
    if (line.startsWith("verify-")) {
      const reply = await kernel.exchange(Buffer.from(line));
      f.events.push("native-" + line.trim().split(" ")[0]);
      const receive = f.owner.receive;
      f.owner.receive = async () => {
        f.owner.receive = receive;
        return JSON.parse(reply);
      };
    } else {
      await send(line);
      if (line.startsWith("finish ")) {
        bootstrap.states.get(f.helper.pid).retired = true;
        bootstrap.states.get(10).retired = true;
        bootstrap.state.absent = true;
      }
    }
  };
  const reader = f.reader();
  await reader.start();
  const admission = {
    schemaVersion: 1,
    platform: "win32",
    nonce: "d".repeat(32),
    root: "C:\\Fixture\\Storage",
    readRoots: ["C:\\Fixture\\Storage"],
    writeRoots: ["C:\\Fixture\\Storage\\assets"],
    controllerUid: null,
    controllerSid: runnerSid,
    expires: 1,
  };
  const runtime = {
      node: { path: "C:\\Stock\\node.exe", bytes: 1, sha256: hash },
      dependencies: [],
    },
    privilege = {
      userSid: "S-1-5-18",
      sessionId: 0,
      task: "exclusive",
      pipe: "private",
    },
    source = [
      "observation.js",
      "prerequisite-files.js",
      "prerequisite-windows.js",
      "prerequisite-worker.mjs",
      "prerequisite-gateway.ps1",
      "first-failure.js",
      "prerequisite-source.js",
      "prerequisite-transport.js",
      "win32/custody-verifier.js",
    ].map((name) => ({ name, bytes: 1, sha256: hash })),
    manifest = {
      platform: "win32",
      candidateSha,
      source: {
        citations: source.map((entry) => ({
          kind: "reached-code",
          member: "candidate/ci/native/" + entry.name,
          sha256: entry.sha256,
        })),
      },
    },
    output = writableOutput
      ? "C:\\Fixture\\Storage\\assets\\records"
      : "C:\\Fixture\\Storage\\records";
  const { nonce: _nonce, expires: _expires, ...scope } = admission;
  const approvals = {
    sourceSha256: observationDigest(source),
    runtimeSha256: observationDigest(runtime),
    privilegeSha256: observationDigest(privilege),
    scopeSha256: observationDigest({ ...scope, output }),
    manifestSha256: observationDigest(manifest),
  };
  const request = {
    schemaVersion: 1,
    platform: "win32",
    job: f.input.context,
    admission,
    output,
    source,
    privilege,
    approvals,
    manifestSha256: approvals.manifestSha256,
  };
  const actors = [identity(21), identity(22), identity(23)];
  kernel.state.jobMembers = actors;
  for (const actor of actors)
    kernel.states.set(actor.pid, {
      ...structuredClone(f.process),
      identity: actor,
      retired: false,
    });
  const verifier = createWindowsCustodyVerifier(reader);
  const binding = await verifier.retainPrerequisiteJob(request);
  // Retain creation identities before disconnect. A new JS verifier later
  // rejoins these same native slots, including already signalled processes.
  for (const actor of actors)
    await reader.verification.command("retain", [
      actor.pid,
      actor.creationTime,
    ]);
  kernel.state.jobMembers = liveMember ? [actors[1]] : [];
  kernel.state.instances = 0;
  if (changedJob) kernel.state.jobDacl = "f".repeat(64);
  if (changedTask)
    kernel.state.damage = (operation, frame) => {
      if (operation === "verify-task") frame.value.sha256 = "f".repeat(64);
      return Buffer.from(JSON.stringify(frame) + "\n");
    };
  for (const actor of actors) kernel.states.get(actor.pid).retired = true;
  const record = (phase, value) => {
    const file =
        output +
        "\\prerequisite-custody-" +
        admission.nonce +
        "-" +
        phase +
        ".json",
      bytes = Buffer.from(JSON.stringify(value));
    f.bytes.set(file, bytes);
    return { file, bytes: bytes.length, sha256: digest(bytes) };
  };
  const intent = record("intent", request),
    birth = record("birth", {
      schemaVersion: 1,
      requestSha256: binding.requestSha256,
      worker: actors[0],
      children: [actors[1]],
      verifiers: [actors[2]],
      observer: lostObserver ? identity(99) : binding.observer,
      jobSlot: lostJobSlot ? 31 : binding.jobSlot,
      jobName: binding.jobName,
      job: binding.job,
      taskSha256: hash,
    });
  if (missingBirth) f.bytes.delete(birth.file);
  const transport = createPrerequisiteTransport(
    {
      job: f.input.context,
      admission,
      manifest,
      output,
      runtime,
      privilege,
      approvals,
      windowsRequest: request,
      windowsBirth: birth,
    },
    { platform: "win32", windowsReader: reader },
  );
  return { f, kernel, reader, transport, intent, birth };
}

test("Windows interrupted prerequisite custody rejoins held births and Job before exact owned task removal and protected settlement", async () => {
  const k = await prerequisiteVerificationFixture();
  try {
    const proof = await k.transport.recover(k.intent);
    assert.equal(proof.taskRemoved, true);
    const closed = await k.transport.close();
    assert.equal(closed.custodianRetired, true);
    assert.equal(closed.verifierRetired, false);
    const intent = k.f.records.find(
      (record) => record.phase === "verify-task-remove",
    );
    assert.deepEqual(intent.arguments.slice(0, 3), [
      "prerequisite",
      hex("d".repeat(32)),
      hash,
    ]);
    assert.ok(
      k.f.events.indexOf("persist-verify-task-remove") <
        k.f.events.indexOf("native-verify-task-remove"),
    );
    assert.equal(k.f.records.at(-1).phase, "verify-prerequisite-settled");
    assert.equal(
      k.kernel.events.filter((entry) => entry.operation === "verify-job-open")
        .length,
      1,
    );
    assert.equal(
      k.kernel.events.filter((entry) => entry.operation === "verify-task")
        .length,
      6,
    );
    assert.equal(k.f.events.filter((entry) => entry === "entry").length, 1); // No recovery launch.
  } finally {
    assert.equal((await k.reader.close()).status, "RETIRED");
  }
});

test("Windows reconstruction retains missing birth, replaced observer and surviving whole-Job custody with the first failure", async () => {
  for (const fault of [
    "lostObserver",
    "missingBirth",
    "liveMember",
    "lostJobSlot",
    "changedJob",
    "changedTask",
    "writableOutput",
  ]) {
    const k = await prerequisiteVerificationFixture({ [fault]: true });
    try {
      let first;
      await assert.rejects(k.transport.recover(k.intent), (error) => {
        first = error;
        return true;
      });
      await assert.rejects(k.transport.close(), (error) => error === first);
      assert.ok(
        !k.kernel.events.some(
          (entry) => entry.operation === "verify-task-remove",
        ),
      );
      assert.ok(
        !k.f.records.some(
          (record) => record.phase === "verify-prerequisite-settled",
        ),
      );
    } finally {
      k.f.owner.close();
    }
  }
});

test("Windows verification expiry fences later native reads and late protected receipts, preserving the first error", async () => {
  const k = verificationFixture();
  let time = 100;
  const verifier = createWindowsCustodyVerifier(k.observer, {
    exchange: k.exchange,
    clock: () => time,
    deadline: 200,
  });
  k.state.damage = (_operation, frame) => {
    time = 200;
    return Buffer.from(JSON.stringify(frame) + "\n");
  };
  let first;
  await assert.rejects(verifier.verifyBootstrap(k.f.input), (error) => {
    first = error;
    return true;
  });
  assert.equal(k.events.length, 1);
  time = 100;
  k.state.damage = null;
  await assert.rejects(
    verifier.verifyBootstrap(k.f.input),
    (error) => error === first,
  );
  assert.equal(k.events.length, 1);

  const receipt = verificationFixture();
  time = 100;
  receipt.observer.verification.record = async () => {
    time = 200;
  };
  const late = createWindowsCustodyVerifier(receipt.observer, {
    exchange: receipt.exchange,
    clock: () => time,
    deadline: 200,
  });
  const request = {
    platform: "win32",
    job: receipt.f.input.context,
    admission: { nonce },
  };
  await assert.rejects(late.retainPrerequisiteJob(request), (error) => {
    first = error;
    return true;
  });
  assert.equal(receipt.events.length, 1);
  time = 100;
  await assert.rejects(
    late.retainPrerequisiteJob(request),
    (error) => error === first,
  );
  assert.equal(receipt.events.length, 1);
});
