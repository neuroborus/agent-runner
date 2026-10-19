import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { readFile } from "node:fs/promises";
import { PassThrough, Writable } from "node:stream";
import test from "node:test";
import { Script } from "node:vm";

import {
  createWindowsCustodyReader,
  createWindowsCustodyVerifier,
  encodeWindowsCustodyPlan,
  windowsCompilerArguments,
  WINDOWS_CUSTODY_DEADLINE_MS,
} from "./index.js";
import { windowsCustodyChannel } from "./channel.js";
import {
  digest,
  quoteWindowsArgument,
  windowsBuildHelperCommandLine,
  WINDOWS_BUILD_ENVIRONMENT_MAX_UNITS,
} from "./protocol.js";
import { observationDigest } from "../index.js";
import { createPrerequisiteTransport } from "../prerequisite-transport.js";
import { windowsPolicyFixture } from "./policy.fixture.js";
import { compilerTrustFixture } from "./compiler-trust.fixture.js";
import {
  createNativeDiagnosticWriter,
  withNativeDiagnostics,
} from "../diagnostics.js";

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
const instance = {
  guid: "{11111111-2222-3333-4444-555555555555}",
  state: 4,
  enginePid: 20,
};
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
function fixture({
  policy = false,
  git = false,
  observer = false,
  build = false,
} = {}) {
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
  let buildRequest, buildEntry;
  if (build) {
    const tool = image("cl.exe");
    buildEntry = {
      helper: entries.length,
      tool: entries.length + 1,
      toolSignatureSha256: hash,
    };
    entries.push(
      { kind: "helper", ...image("build-helper.exe") },
      { kind: "image", ...tool },
    );
    buildRequest = {
      candidateSha,
      platform: "win32",
      file: tool.path,
      toolSha256: tool.sha256,
      args: ["/Bv"],
      cwd: entries[1].path,
      env: {
        CI: "true",
        GITHUB_ACTIONS: "true",
        LANG: "C",
        INCLUDE: "include",
        LIB: "lib",
        SystemRoot: "C:\\Windows",
        PATH: "tools",
      },
      deadlineMs: 30000,
    };
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
      "audit-policy-remove.h",
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
          {
            phase: "entry",
            helper,
            bridge,
            processDaclSha256: hash,
            instance: { ...instance, enginePid: helper.pid },
          },
          { helper, peer: bridge },
        );
        return;
      }
      if (line === "P\n") {
        frames.push({ candidateSha, nonce, entries: entries.length });
        return;
      }
      if (line === "D") {
        frames.push({
          phase: "retired",
          taskSha256: hash,
          taskRemoved: true,
          helperRetired: true,
        });
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
        job.limitFlags = a === "build" ? 0x2808 : 0x2008;
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
        frames.push({ phase: "helper-retired", helper, exitCode: 0 });
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
    frames,
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
    buildRequest,
    buildEntry,
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
  assert.equal(f.records.at(-1).phase, "task-parked");
  assert.equal(f.records.at(-1).custody, "POSSIBLE");
  assert.ok(!f.events.includes("fault"));
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
      "loader",
      (value) => {
        value.importScope = "private-runtime";
      },
    ],
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

test("Windows build controller admission rejects stale policy, extra flags and members before release", async () => {
  for (const damage of ["nested", "silent", "member", "proof"]) {
    const f = fixture({ build: true }),
      reader = f.reader();
    await reader.start();
    for (const index of [f.buildEntry.helper, f.buildEntry.tool])
      await reader.open(index);
    f.options.damage = (op, frame) => {
      if (op === "helper-start") {
        if (damage === "nested") frame.value.job.limitFlags = 0x2008;
        if (damage === "silent") frame.value.job.limitFlags |= 0x1000;
        if (damage === "member") frame.value.job.members.push(identity(41));
      }
      return frame;
    };
    if (damage === "proof") {
      const verify = f.options.verifyTransfer;
      f.options.verifyTransfer = async (...args) => ({
        ...(await verify(...args)),
        jobSha256: "f".repeat(64),
      });
    }
    await assert.rejects(
      reader.openBuild(
        f.buildRequest,
        { mode: "compiler-version" },
        f.buildEntry,
      ),
    );
    assert.ok(!f.events.some((event) => event.startsWith("helper-release ")));
    assert.equal((await reader.close()).status, "RETAINED");
  }
});

test("actual build-only creation separates UI-restricted Jobs without compiler breakaway authority", async () => {
  const [reader, helper] = await Promise.all(
    ["custody-reader.c", "build-helper.c"].map((name) =>
      readFile(new URL(name, import.meta.url), "utf8"),
    ),
  );
  const controller = reader.slice(
      reader.indexOf("static void start_helper("),
      reader.indexOf("static void build(void)"),
    ),
    policy = controller.slice(
      controller.indexOf("limits.BasicLimitInformation.LimitFlags ="),
      controller.indexOf("JOBOBJECT_BASIC_UI_RESTRICTIONS ui"),
    );
  for (const kind of [
    "build",
    "git",
    "file",
    "observer",
    "policy",
    "git-policy",
  ]) {
    const limits = { BasicLimitInformation: {} };
    new Script(policy.replace(/\/\*[\s\S]*?\*\//gu, "")).runInNewContext({
      limits,
      compiler: kind === "build",
      git: kind === "git",
      JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: 0x2000,
      JOB_OBJECT_LIMIT_ACTIVE_PROCESS: 8,
      JOB_OBJECT_LIMIT_BREAKAWAY_OK: 0x800,
    });
    assert.equal(
      limits.BasicLimitInformation.LimitFlags,
      kind === "build" ? 0x2808 : 0x2008,
    );
    assert.equal(
      limits.BasicLimitInformation.ActiveProcessLimit,
      ["build", "git"].includes(kind) ? 32 : 1,
    );
  }
  const flags =
    /CreateProcessW\(tool\.path, command, &private, &private, TRUE, ([^,]+), NULL/u.exec(
      helper,
    )[1];
  assert.equal(
    new Script(flags).runInNewContext({
      CREATE_BREAKAWAY_FROM_JOB: 0x1000000,
      CREATE_SUSPENDED: 4,
      CREATE_UNICODE_ENVIRONMENT: 0x400,
      EXTENDED_STARTUPINFO_PRESENT: 0x80000,
    }),
    0x1080404,
  );
  assert.equal(helper.match(/CREATE_BREAKAWAY_FROM_JOB/gu).length, 1);
  assert.ok(!controller.includes("CREATE_BREAKAWAY_FROM_JOB"));
  assert.match(
    helper,
    /LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE \| JOB_OBJECT_LIMIT_ACTIVE_PROCESS; limits.BasicLimitInformation.ActiveProcessLimit = 31;/u,
  );
  assert.match(
    helper,
    /HANDLE handles\[\] = \{childIn, childOut, childError\}/u,
  );
  assert.match(helper, /PROC_THREAD_ATTRIBUTE_JOB_LIST, &job, sizeof\(job\)/u);
});

test("Windows build input bounds refuse invalid environment text before helper-start", async () => {
  const f = fixture({ build: true }),
    reader = f.reader(),
    request = f.buildRequest,
    baseline = { ...request.env },
    starts = () =>
      f.events.filter((event) => event.startsWith("helper-start "));
  await reader.start();
  for (const index of [f.buildEntry.helper, f.buildEntry.tool])
    await reader.open(index);
  for (const name of ["INCLUDE", "LIB", "SystemRoot", "PATH"]) {
    const maximum = name === "SystemRoot" ? 4095 : 16384;
    for (const value of [
      "x".repeat(maximum),
      "x".repeat(maximum + 1),
      "",
      "x\0y",
      "\n",
      "\u001f",
      "\u007f",
      "\ud800",
      "\udc00",
    ]) {
      Object.assign(request.env, baseline, { [name]: value });
      const before = starts().length,
        pending = reader.openBuild(
          request,
          { mode: "compiler-version" },
          f.buildEntry,
        );
      if (value.length === maximum) {
        const channel = await pending,
          args = starts()
            .at(-1)
            .split(" ")
            .slice(5, 19)
            .map((part) => Buffer.from(part, "hex").toString("utf16le"));
        assert.deepEqual(
          args.slice(10),
          ["INCLUDE", "LIB", "SystemRoot", "PATH"].map(
            (key) => request.env[key],
          ),
        );
        await channel.close();
      } else {
        await assert.rejects(pending);
        assert.equal(starts().length, before);
      }
    }
  }
  Object.assign(request.env, baseline, {
    INCLUDE: "i".repeat(16384),
    PATH: "p".repeat(16384),
  });
  const before = starts().length;
  await assert.rejects(
    reader.openBuild(request, { mode: "compiler-version" }, f.buildEntry),
  );
  assert.equal(
    starts().length,
    before,
    "Individually valid lists must still fit the quoted command",
  );
  assert.equal((await reader.close()).closed, true);
});

test("actual helper startup refuses invalid OS directories before launch effects", async () => {
  for (const environment of [
    { length: 0 },
    { length: 4096 },
    { terminated: false },
    { directory: "C:\\Bad|OS" },
  ]) {
    for (const kind of ["build", "file"]) {
      const source = await compilerTrustFixture({ entries: [], environment });
      assert.throws(() => source.startHelper(kind), /native guard rejected/u);
      assert.deepEqual(source.events, ["windows-directory"]);
      assert.deepEqual(source.helperStarts, []);
      assert.deepEqual(source.calls, []);
      assert.deepEqual(source.records, []);
    }
  }
});

test("Windows build quoting preserves UCRT literals and counts the final separator and NUL", () => {
  const image = "C:\\Fixture\\build-helper.exe",
    args = Array(14).fill("x");
  for (const value of ["λ雪😀", 'a"b', "tail\\", 'slash\\"quote']) {
    args[10] = value;
    assert.equal(
      windowsBuildHelperCommandLine(image, args),
      [image, ...args].map(quoteWindowsArgument).join(" ") + " ",
    );
  }
  for (const index of [2, 8, 12]) {
    args[index] = "x".repeat(4095);
    assert.doesNotThrow(() => windowsBuildHelperCommandLine(image, args));
    args[index] += "x";
    assert.throws(() => windowsBuildHelperCommandLine(image, args));
    args[index] = "x";
  }
  args[10] = "i".repeat(16384);
  assert.throws(
    () => quoteWindowsArgument(args[10]),
    "Generic quoting retains its original bound",
  );
  const remaining = 32766 - windowsBuildHelperCommandLine(image, args).length;
  args[13] += "p".repeat(remaining);
  assert.equal(windowsBuildHelperCommandLine(image, args).length, 32766);
  args[13] += "p";
  assert.throws(() => windowsBuildHelperCommandLine(image, args));
});

test("actual Windows decoder and child argument guards share only the build list capacity", async () => {
  const [header, reader, helper] = await Promise.all(
    ["custody.h", "custody-reader.c", "build-helper.c"].map((name) =>
      readFile(new URL(name, import.meta.url), "utf8"),
    ),
  );
  const definitions = [
      ...header.matchAll(/^#define (WINDOWS_BUILD_ENVIRONMENT_\w+) (.+)$/gmu),
    ]
      .map(([, name, value]) => `const ${name} = ${value};`)
      .join("\n"),
    body = header
      .slice(
        header.indexOf("static unsigned nibble("),
        header.indexOf("static void decode("),
      )
      .replace("static unsigned nibble(char value)", "function nibble(value)")
      .replace(
        /static void bounded_text\([^)]*\)/u,
        "function bounded_text(value, size, maximum)",
      )
      .replace(
        /static void decode_bounded\([^)]*\)/u,
        "function decode_bounded(bytes, out, maximum)",
      )
      .replaceAll("size_t ", "let ")
      .replace(
        "BYTE *target = (BYTE *)out;",
        "const target = new Uint8Array(out.buffer);",
      )
      .replaceAll("(BYTE)", "")
      .replace(/'([0-9a-f])'/gu, (_, value) => String(value.charCodeAt(0))),
    readerLoop =
      /  for \(unsigned i = 0; i < argc; i\+\+\) decode_bounded\([\s\S]*?(?=\n  need\(wcslen\(args\[0\]\))/u.exec(
        reader,
      )?.[0],
    helperLoop =
      /  for \(unsigned i = 3; i < 15; i\+\+\)[\s\S]*?(?=\n  wchar_t \*end;)/u.exec(
        helper,
      )?.[0];
  assert.ok(body && definitions && readerLoop && helperLoop);
  const length = (value) =>
      value.includes(0) ? value.indexOf(0) : value.length,
    native = new Script(`${definitions}\n${body}
      function decodeArguments(values, args, compiler, observer) {
        const argc = args.length; ${readerLoop.replace("unsigned i", "let i")}
      }
      function validateArguments(argv) { ${helperLoop.replace("unsigned i", "let i")} }
      ({decode_bounded, decodeArguments, validateArguments,
        maximum: WINDOWS_BUILD_ENVIRONMENT_MAX_UNITS,
        capacity: WINDOWS_BUILD_ENVIRONMENT_CAPACITY});`).runInNewContext({
      need: assert.ok,
      strlen: length,
      wcslen: length,
    }),
    wide = (value) =>
      Uint16Array.from(
        value
          .split("")
          .map((unit) => unit.charCodeAt(0))
          .concat(0),
      ),
    inspect = (args, compiler = true, observer = false) => {
      const decoded = args.map(() => new Uint16Array(native.capacity));
      native.decodeArguments(
        [...Array(5), ...args.map((value) => Buffer.from(hex(value), "ascii"))],
        decoded,
        compiler,
        observer,
      );
      return decoded;
    };
  assert.equal(native.maximum, WINDOWS_BUILD_ENVIRONMENT_MAX_UNITS);
  assert.equal(native.capacity, 16385);
  const observed = [
      [10, 663],
      [11, 376],
      [12, 10],
      [13, 4516],
    ],
    args = Array(14).fill("x");
  for (const [index, size] of observed)
    args[index] =
      index === 12 ? "C:\\Windows" : 'λ雪😀"'.padEnd(size - 1, "x") + "\\";
  const decoded = inspect(args);
  native.validateArguments([wide("helper"), ...decoded]);
  for (const [index, size] of observed)
    assert.deepEqual(
      Buffer.from(decoded[index].buffer).subarray(0, size * 2),
      Buffer.from(args[index], "utf16le"),
    );
  for (const [index, maximum] of [
    [10, 16384],
    [11, 16384],
    [13, 16384],
    [12, 4095],
    [2, 4095],
  ]) {
    for (const value of [
      "x".repeat(maximum),
      "x".repeat(maximum + 1),
      "",
      "\0",
      "\n",
      "\u001f",
      "\u007f",
      "\ud800",
      "\udc00",
      "\ud800x",
    ]) {
      const args = Array(14).fill("x");
      args[index] = value;
      if (value.length === maximum) {
        const decoded = inspect(args);
        assert.deepEqual(
          Buffer.from(decoded[index].buffer).subarray(0, value.length * 2),
          Buffer.from(value, "utf16le"),
        );
        native.validateArguments([wide("helper"), ...decoded]);
      } else {
        assert.throws(() => inspect(args));
        assert.throws(() =>
          native.validateArguments([wide("helper"), ...args.map(wide)]),
        );
      }
    }
    if (maximum === 16384) {
      const args = Array(14).fill("x");
      args[index] = "x".repeat(maximum);
      assert.throws(
        () => inspect(args, false),
        "Other helper kinds retain ordinary bounds",
      );
    }
  }
  const query = ["x", "x".repeat(16384)];
  assert.doesNotThrow(() => inspect(query, false, true));
  assert.throws(() => inspect(query, false, false));
  for (const encoded of ["", "123", "zzzz", hex("x\0y")])
    assert.throws(() =>
      native.decode_bounded(
        Buffer.from(encoded, "ascii"),
        new Uint16Array(16385),
        16385,
      ),
    );
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

test("Windows task removal requires the original finish response, held exit and durable acknowledgement", async () => {
  for (const fault of [null, "lost", "identity", "persist", "removal"]) {
    const f = fixture(),
      reader = f.reader(),
      primary = new Error("lost original completion"),
      cleanup = new Error("removal response lost");
    await reader.start();
    const receive = f.owner.receive,
      send = f.owner.send,
      persist = f.options.persist;
    f.owner.receive = async () => {
      const frame = await receive();
      if (fault === "lost" && frame.value?.closed) throw primary;
      if (fault === "identity" && frame.phase === "helper-retired")
        frame.helper.pid++;
      return frame;
    };
    f.options.persist = async (record) => {
      if (fault === "persist" && record.phase === "finish-acknowledged")
        throw cleanup;
      return persist(record);
    };
    f.owner.send = async (line) => {
      if (line === "D") {
        assert.ok(
          f.records.some((record) => record.phase === "finish-acknowledged"),
        );
        if (fault === "removal") throw cleanup;
      }
      return send(line);
    };
    const result = await reader.close();
    assert.equal(result.status, fault ? "RETAINED" : "RETIRED");
    if (fault) {
      assert.equal(result.independent, false);
      if (fault === "lost") assert.equal(result.primaryCause, primary);
      assert.equal(f.events.includes("D"), false);
      assert.equal(f.events.includes("verify-removal"), false);
      assert.equal(f.records.at(-1).command.name, "finish");
    } else {
      assert.ok(
        f.events.indexOf("persist-finish-acknowledged") < f.events.indexOf("D"),
      );
      assert.ok(f.events.indexOf("D") < f.events.indexOf("verify-removal"));
    }
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
test("Windows terminal reader faults settle outstanding work before bridge exit without retiring it", async () => {
  for (const diagnostic of [false, true]) {
    const f = transport({ holdWrites: true }),
      work = [
        f.channel.send("open 2 14\n"),
        f.channel.receive(),
        f.channel.wait(new Promise(() => {})),
        f.channel.completion,
      ],
      rejected = Promise.all(
        work.map((value) => value.catch((cause) => cause)),
      );
    let exited = false;
    f.channel.exited.then(() => {
      exited = true;
    });
    if (diagnostic)
      f.child.stdout.write(
        '\x1e{"phase":"reader-failure","sequence":2,"command":"open","source":"custody.h","line":1}\n',
      );
    else f.child.stdout.emit("end");
    const causes = await rejected;
    assert.ok(causes[0] instanceof Error);
    assert.ok(causes.every((cause) => cause === causes[0]));
    assert.equal(!!causes[0].custodyReaderFailure, diagnostic);
    assert.equal(exited, false);
    f.child.emit("close", 126, null);
    assert.deepEqual(await f.channel.exited, { code: 126, signal: null });
    assert.throws(() => f.channel.settle());
  }
});

test("Windows reader failure rejects queued commands while the dependent journal remains pending", async () => {
  const f = fixture(),
    reader = f.reader(),
    fault = Promise.withResolvers(),
    entered = Promise.withResolvers(),
    release = Promise.withResolvers(),
    primary = new Error("original reader EOF");
  fault.promise.catch(() => {});
  f.owner.wait = (value) => Promise.race([value, fault.promise]);
  await reader.start();
  const persist = f.options.persist;
  f.options.persist = async (record) => {
    await persist(record);
    if (record.phase === "open") {
      entered.resolve();
      await release.promise;
    }
  };
  const first = reader.open(3),
    queued = reader.open(2),
    rejected = Promise.all(
      [first, queued].map((value) =>
        assert.rejects(value, (cause) => cause === primary),
      ),
    );
  await entered.promise;
  fault.reject(primary);
  await rejected;
  assert.ok(!f.events.some((event) => /^open [0-9]/u.test(event)));
  release.resolve();
  const result = await reader.close();
  assert.equal(result.status, "RETAINED");
  assert.equal(result.primaryCause, primary);
  assert.ok(!f.events.some((event) => /^open [0-9]/u.test(event)));
});

test("Windows custody EOF refuses a lost response while reader diagnostics remain failures, never receipts", async () => {
  const source = await readFile(
      new URL("./custody-reader.c", import.meta.url),
      "utf8",
    ),
    body = /static void reader_failure\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(
      source,
    )[1],
    value = {
      phase: "reader-failure",
      sequence: 2,
      command: "open",
      source: "custody.h",
      line: 149,
      lastError: 5,
    },
    diagnosticProgram = new Script(
      `(file,line,error)=>{${body
        .replace("const char *source", "let source")
        .replace("source+1", "source.slice(1)")
        .replace(
          'char bytes[1024], transfer[256] = ""; DWORD written;',
          'let bytes={},transfer={value:""},written;',
        )
        .replace("sizeof(transfer)", "256")
        .replace("int size", "let size")
        .replace("sizeof(bytes)", "1024")
        .replace("\\036", "\\x1e")
        .replace("(DWORD)size", "size")
        .replace("&written", "value=>written=value")}}`,
    );
  for (const diagnostic of [false, true]) {
    const f = transport(),
      response = f.channel.receive();
    if (diagnostic) {
      f.child.stdout.write('{"sequence":2,"value":');
      diagnosticProgram.runInNewContext({
        reader_diagnostics_ready: true,
        signature_trust: { active: false },
        reader_context_failure: () => false,
        reader_open_failure: () => false,
        reader_command: "open",
        reader_transfer: { active: false },
        sequence: 2,
        control: "authenticated",
        NULL: null,
        strrchr: (file, separator) => {
          const index = file.lastIndexOf(separator);
          return index < 0 ? null : file.slice(index);
        },
        sprintf_s: (bytes, maximum, format, ...values) => {
          let index = 0;
          bytes.value = format.replace(/%(?:lu|[su])/gu, () => {
            const value = values[index++];
            return value?.value ?? value;
          });
          assert.ok(Buffer.byteLength(bytes.value) < maximum);
          return bytes.value.length;
        },
        WriteFile: (handle, bytes, size, out) => {
          assert.equal(handle, "authenticated");
          out(size);
          f.child.stdout.write(bytes.value.slice(0, 25));
          f.child.stdout.write(bytes.value.slice(25));
          return true;
        },
      })("C:\\Fixture\\custody.h", 149, 5);
      await assert.rejects(response, (error) => {
        assert.deepEqual(error.custodyReaderFailure, value);
        return true;
      });
    } else {
      f.child.stdout.emit("end");
      await assert.rejects(response);
    }
    await assert.rejects(f.channel.completion);
    assert.throws(() => f.channel.settle());
    assert.equal(f.child.exitCode, undefined);
    f.child.emit("close", 0, null);
    await assert.rejects(f.channel.receive());
  }
  for (const field of ["command", "source"]) {
    const f = transport(),
      response = f.channel.receive();
    f.child.stdout.write(
      "\x1e" + JSON.stringify({ ...value, [field]: [value[field]] }) + "\n",
    );
    await assert.rejects(
      response,
      (error) => !Object.hasOwn(error, "custodyReaderFailure"),
    );
    await assert.rejects(f.channel.completion);
    assert.throws(() => f.channel.settle());
    f.child.emit("close", 0, null);
  }
  const f = transport();
  f.child.stdout.emit("end");
  assert.throws(() => f.channel.settle());
  await assert.rejects(f.channel.receive());
  await assert.rejects(f.channel.completion);
});

test("original creator-census calls retain guard errors, clear successful context and never retry a refusal", async () => {
  const [header, reader] = await Promise.all([
    readFile(new URL("./custody.h", import.meta.url), "utf8"),
    readFile(new URL("./custody-reader.c", import.meta.url), "utf8"),
  ]);
  // Control workers use the same guard hook; their native storage starts empty.
  assert.match(
    reader,
    /static __declspec\(thread\) struct \{[^}]+\} reader_transfer;/u,
    "Creator-census context must be private to its native thread",
  );
  const body = (source, name) =>
    new RegExp(
      `static void ${name}\\([^\\n]+\\) \\{([\\s\\S]*?)\\n\\}`,
      "u",
    ).exec(source)[1];
  const translate = (source) =>
    source
      .replace(/#ifdef NATIVE_CUSTODY_FAILURE\n([\s\S]*?)#endif/gu, "$1")
      .replace("NATIVE_CUSTODY_FAILURE", "reader_failure")
      .replace("DWORD error", "let error")
      .replace("const char *source", "let source")
      .replace("source+1", "source.slice(1)")
      .replace(
        'char bytes[1024], transfer[256] = ""; DWORD written;',
        'let bytes={},transfer={text:""},written;',
      )
      .replace("int size", "let size")
      .replace(
        "struct verify_handle *entry = &list->entries[i];",
        "let entry = list.entries[i];",
      )
      .replace("HANDLE duplicate;", "let duplicate;")
      .replaceAll("sizeof(transfer)", "256")
      .replaceAll("sizeof(bytes)", "1024")
      .replaceAll("->", ".")
      .replaceAll("(HANDLE)", "")
      .replaceAll("(DWORD)size", "size")
      .replaceAll("&duplicate", "out")
      .replaceAll("&written", "out")
      .replaceAll("\\036", "\\x1e");
  for (const [name, command] of [
    ["verifier_transfer", "verify-transfer"],
    ["compiler_policy", "verify-compiler-policy"],
  ]) {
    const fragment =
      /    struct verify_handle \*entry = &list->entries\[i\]; if \(entry->pid != GetProcessId\(source\) \|\| [^\n]*types\[0\][^\n]*\) continue;\n[\s\S]*?    reader_transfer\.active = FALSE;/u.exec(
        body(reader, name),
      )[0];
    const program = new Script(`
      function reader_failure(file,line,error) {${translate(body(reader, "reader_failure"))}}
      function need_at(ok,file,line) {${translate(body(header, "need_at"))}}
      function need(ok) {need_at(!!ok,"custody-reader.c",1);}
      for (let i=0; i<list.count; i++) {${translate(fragment)} after();}
      if (unrelated) {SetLastError(31); need(false);}
    `);
    for (const fault of [0, 1, 2, -1]) {
      const calls = [],
        records = [],
        errors = [],
        out = {},
        refusal = new Error("exit 126"),
        nativeError = fault === 2 ? 50 : 5;
      const entry = {
        pid: 10,
        type: 0xffff,
        access: 0xffffffff,
        flags: 0xffffffff,
      };
      let lastError = 0,
        reads = 0;
      const context = { active: false },
        api = {
          source: 10,
          creator: 127,
          child: 126,
          index: 126,
          sequence: 270,
          types: [0xffff, 7],
          list: {
            count: 3,
            entries: [
              { pid: 99 },
              { ...entry, handle: 11 },
              { ...entry, handle: 12 },
            ],
          },
          reader_transfer: context,
          reader_command: command,
          reader_diagnostics_ready: true,
          signature_trust: { active: false },
          reader_context_failure: () => false,
          reader_open_failure: () => false,
          control: "authenticated",
          out,
          TRUE: true,
          FALSE: false,
          DUPLICATE_SAME_ACCESS: 2,
          NULL: null,
          stderr: null,
          unrelated: fault === -1,
          GetProcessId: (source) => source,
          GetCurrentProcess: () => 20,
          GetLastError: () => {
            reads++;
            return lastError;
          },
          SetLastError: (error) => {
            lastError = error;
          },
          DuplicateHandle: (...args) => {
            assert.deepEqual(args, [
              10,
              11 + calls.length,
              20,
              out,
              0,
              false,
              2,
            ]);
            calls.push(args[1]);
            lastError = nativeError;
            return calls.length !== fault;
          },
          after: () => assert.equal(context.active, false),
          strrchr: (file) => null,
          sprintf_s: (target, maximum, format, ...values) => {
            let i = 0;
            target.text = format.replace(/%(?:llu|lu|[su])/gu, () => {
              const value = values[i++];
              return value?.text ?? value;
            });
            assert.ok(Buffer.byteLength(target.text) < maximum);
            lastError = 87;
            return target.text.length;
          },
          WriteFile: (handle, bytes, size) => {
            assert.equal(handle, "authenticated");
            records.push(bytes.text.slice(0, size));
            lastError = 88;
            return true;
          },
          fprintf: (_stream, _format, _file, _line, error) => {
            errors.push(error);
            lastError = 89;
          },
          fflush: () => {
            lastError = 90;
          },
          ExitProcess: (code) => {
            assert.equal(code, 126);
            throw refusal;
          },
        };
      if (fault)
        assert.throws(
          () => program.runInNewContext(api),
          (error) => error === refusal,
        );
      else program.runInNewContext(api);
      assert.deepEqual(calls, fault === 1 ? [11] : [11, 12]);
      assert.equal(reads, fault ? 1 : 0);
      assert.deepEqual(errors, fault ? [fault === -1 ? 31 : nativeError] : []);
      assert.equal(records.length, fault ? 1 : 0);
      if (!fault) continue;
      const f = transport(),
        response = f.channel.receive();
      f.child.stdout.write('{"sequence":270,"value":');
      for (const part of [records[0].slice(0, 25), records[0].slice(25)])
        f.child.stdout.write(part);
      await assert.rejects(response, (error) => {
        const value = error.custodyReaderFailure;
        assert.equal(value.lastError, fault === -1 ? 31 : nativeError);
        if (fault === -1) assert.ok(!Object.hasOwn(value, "transfer"));
        else
          assert.deepEqual(value.transfer, {
            ordinal: fault,
            count: 3,
            type: 0xffff,
            access: 0xffffffff,
            attributes: 0xffffffff,
            creator: 127,
            child: 126,
          });
        return true;
      });
      await assert.rejects(f.channel.completion);
      assert.throws(() => f.channel.settle());
      f.child.emit("close", 126, null);
    }
  }
});

test("runtime creator types preserve required duplication, membership and complete inherited censuses", async () => {
  const source = await readFile(
      new URL("./custody-reader.c", import.meta.url),
      "utf8",
    ),
    body = (name) =>
      new RegExp(
        `static [^\\n]+\\b${name}\\([^\\n]+\\) \\{([\\s\\S]*?)\\n\\}`,
        "u",
      ).exec(source)[1],
    translate = (text) =>
      text
        .replace(
          "HANDLE anchors[2] = {CreateJobObjectW(NULL, NULL), NULL};",
          "let anchors=[CreateJobObjectW(NULL,NULL),NULL];",
        )
        .replace(
          "unsigned required = with_thread ? 2 : 1, matches[2] = {0};",
          "let required=with_thread?2:1,matches=[0,0];",
        )
        .replaceAll("USHORT types[2];", "let types=[];")
        .replace("char pipe_dacl[2][65]", "let pipe_dacl=[[],[]]")
        .replace("char dacl[65]", "let dacl=[]")
        .replace(
          "JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;",
          "let limits={BasicLimitInformation:{}};",
        )
        .replace("FILE_ID_INFO id;", "let id={FileId:{Identifier:[]}};")
        .replaceAll("struct verify_handles *list", "let list")
        .replaceAll(
          "struct verify_handle *entry = &list->entries[i];",
          "let entry=list.entries[i];",
        )
        .replace("TOKEN_DEFAULT_DACL *creation", "let creation")
        .replaceAll("(BYTE *)", "")
        .replaceAll("(HANDLE)", "")
        .replaceAll("(ULONG_PTR)", "")
        .replaceAll('L"', '"')
        .replaceAll("->", ".")
        .replace(/&(duplicate|flags|belongs|member)\b/gu, "value=>$1=value")
        .replace(/&(limits|id)\b/gu, "$1")
        .replace(/sizeof\([^)]*\)/gu, "1")
        .replace(
          /\b(?:HANDLE|DWORD|USHORT|ULONG_PTR|BOOL|unsigned)\b/gu,
          "let",
        ),
    program = new Script(`
      function creator_inventory(types,with_thread){${translate(body("creator_inventory"))}}
      function verifier_transfer(child,creator){${translate(body("verifier_transfer"))}}
      function compiler_policy(index,creator){${translate(body("compiler_policy"))}}
    `);
  function fixture(name, types, fault) {
    const anchors = [0x100000011n, 0x200000022n],
      alive = new Set(),
      created = [],
      closed = [],
      calls = [],
      security = [],
      inventories = [],
      freed = [],
      refusal = new Error("native guard"),
      thread = name === "verifier_transfer";
    const row = (pid, handle, type, flags = 0) => ({
      pid,
      handle,
      type,
      flags,
      access: 0x812,
    });
    const api = {
      NULL: null,
      TRUE: true,
      FALSE: false,
      INVALID_HANDLE_VALUE: -1n,
      THREAD_QUERY_LIMITED_INFORMATION: 0x800,
      HANDLE_FLAG_INHERIT: 1,
      DUPLICATE_SAME_ACCESS: 2,
      FILE_TYPE_DISK: 1,
      FILE_TYPE_PIPE: 3,
      SE_KERNEL_OBJECT: 6,
      SE_FILE_OBJECT: 1,
      TokenDefaultDacl: 6,
      JobObjectExtendedLimitInformation: 9,
      FileIdInfo: 18,
      WAIT_TIMEOUT: 258,
      processes: [10, 30],
      tokens: [0, 1],
      process_count: 2,
      verified_jobs: [{ outer: true }],
      reader_transfer: {},
      need: (ok) => {
        if (!ok) throw refusal;
      },
      CreateJobObjectW: (attributes, name) => {
        assert.deepEqual([attributes, name], [null, null]);
        if (fault === "job-create") return null;
        if (fault === "invalid-handle") return -1n;
        created.push(anchors[0]);
        alive.add(anchors[0]);
        return anchors[0];
      },
      OpenThread: (rights, inherit, id) => {
        assert.ok(thread);
        assert.deepEqual([rights, inherit, id], [0x800, false, 77]);
        if (fault === "thread-create") return null;
        created.push(anchors[1]);
        alive.add(anchors[1]);
        return anchors[1];
      },
      GetCurrentThreadId: () => 77,
      GetCurrentProcessId: () => 20,
      GetCurrentProcess: () => 20,
      GetProcessId: (process) => process,
      GetHandleInformation: (handle, out) => {
        assert.ok(alive.has(handle));
        out(fault === "inheritable" ? 1 : 0);
        return fault !== "anchor-query";
      },
      object_type: (handle, expected) => {
        if (typeof handle === "bigint") {
          assert.ok(alive.has(handle));
          return (
            fault !== "anchor-type" &&
            expected === (handle === anchors[0] ? "Job" : "Thread")
          );
        }
        assert.equal(api.reader_transfer.active, false);
        return fault !== "actual-type" && handle.kind === expected;
      },
      handle_inventory: () => {
        let rows;
        if (alive.size) {
          assert.equal(alive.size, thread ? 2 : 1);
          rows = [
            row(99, anchors[0], types[0]),
            row(20, 0x11n, types[0]),
            row(20, anchors[0], types[0]),
            ...(thread ? [row(20, anchors[1], types[1])] : []),
            row(10, 99, 500),
            row(10, 11, types[0]),
            row(10, 12, types[1]),
          ];
          if (fault === "missing-anchor") rows.splice(2, 1);
          if (fault === "ambiguous-anchor") rows.push({ ...rows[2] });
          if (fault === "contradictory-anchor")
            rows.push({ ...rows[2], type: types[1] });
          if (fault === "zero-index") rows[2].type = 0;
          if (fault === "inherited-anchor") rows[2].flags = 2;
          if (fault === "same-index" && thread) rows[3].type = types[0];
          if (fault === "missing-thread" && thread) rows.splice(3, 1);
          if (fault === "missing-job")
            rows = rows.filter((entry) => entry.handle !== 11);
          if (fault === "duplicate-job") rows.push(row(10, 13, types[0]));
          if (fault === "duplicate-thread") rows.push(row(10, 14, types[1]));
        } else {
          rows = [201, 202, 203].map((handle) => row(30, handle, 500, 2));
          if (fault === "missing-pipe") rows.shift();
          if (fault === "extra-pipe") rows.push(row(30, 204, 500, 2));
          if (fault === "inherited-refusal")
            rows.push(row(30, 299, types[0], 2));
          if (fault === "handle-bound")
            rows = Array.from({ length: 131 }, (_, i) =>
              row(30, 201 + i, 500, 2),
            );
        }
        const list = { entries: rows, count: rows.length };
        inventories.push(list);
        return list;
      },
      duplicate_process_owner: (slot) => api.processes[slot],
      DuplicateHandle: (
        source,
        handle,
        target,
        out,
        rights,
        inherit,
        options,
      ) => {
        assert.deepEqual(
          [source, target, rights, inherit, options],
          [handle < 200 ? 10 : 30, 20, 0, false, 2],
        );
        calls.push(handle);
        if (
          handle === 99 ||
          (fault === "inherited-refusal" && handle === 299) ||
          (fault === "required-refusal" && handle === 11)
        )
          return false;
        out({
          handle,
          kind: handle === 12 || handle === 14 ? "Thread" : "Job",
        });
        return true;
      },
      CloseHandle: (handle) => {
        closed.push(handle);
        if (typeof handle === "bigint") assert.ok(alive.delete(handle));
        return fault !== "anchor-close" || handle !== anchors[0];
      },
      IsProcessInJob: (child, job, out) => {
        out(
          job.outer
            ? child === 10 || fault === "nested-compiler"
            : child === 30
              ? fault !== "job-membership"
              : fault === "nested-controller",
        );
        return true;
      },
      GetProcessIdOfThread: () => (fault === "thread-membership" ? 99 : 30),
      QueryInformationJobObject: (_job, _kind, limits) => {
        limits.BasicLimitInformation.LimitFlags =
          fault === "compiler-breakaway"
            ? 0x2808
            : fault === "compiler-silent-breakaway"
              ? 0x3008
              : 0x2008;
        limits.BasicLimitInformation.ActiveProcessLimit =
          fault === "compiler-limit" ? 32 : 31;
        return true;
      },
      security: (handle, kind, privateDacl) => {
        assert.equal(privateDacl, true);
        security.push(handle.handle);
        if (fault === "dacl" || (fault === "pipe-dacl" && kind === 1))
          throw refusal;
      },
      job_read: () => {
        security.push("job");
        if (fault === "job-dacl") throw refusal;
      },
      GetFileType: ({ handle }) =>
        fault === "unknown-inherited" && handle === 202
          ? 0
          : thread &&
              handle >= 203 &&
              !(fault === "extra-pipe" && handle === 204)
            ? 1
            : 3,
      GetFileInformationByHandleEx: () => fault !== "file-identity",
      token_info: () => ({
        DefaultDacl: fault === "default-dacl" ? null : { AclSize: 8 },
      }),
      IsValidAcl: () => fault !== "default-dacl",
      acl_read: (acl) => {
        if (!acl) throw refusal;
      },
      WaitForSingleObject: () => 258,
      free: (value) => freed.push(value),
      printf: () => {},
      putchar: () => {},
      hex: () => {},
      sum: () => {},
    };
    program.runInNewContext(api);
    return {
      api,
      calls,
      security,
      created,
      closed,
      inventories,
      freed,
      refusal,
      run: () => api[name](1, 0),
    };
  }
  for (const name of ["verifier_transfer", "compiler_policy"]) {
    const thread = name === "verifier_transfer";
    for (const types of [
      [55, 84],
      [101, 55],
      [0xffff, 7],
    ]) {
      const f = fixture(name, types);
      f.run();
      assert.deepEqual(
        f.calls,
        thread ? [11, 12, 201, 202, 203] : [201, 202, 203, 11],
      );
      assert.deepEqual(
        f.closed.filter((handle) => typeof handle === "bigint"),
        f.created,
      );
      assert.equal(f.created.length, thread ? 2 : 1);
      assert.ok(f.security.includes("job"));
      if (thread) {
        assert.deepEqual(f.security, [12, "job", 201, 202]);
        assert.equal(f.api.verified_jobs[1].handle, 11);
      } else {
        assert.equal(f.api.verified_jobs[1], undefined);
        assert.ok(
          f.closed.some((handle) => handle?.handle === 11),
          "Compiler inspection must close its duplicate",
        );
      }
      assert.ok(f.inventories.every((list) => f.freed.includes(list)));
    }
    for (const fault of [
      "job-create",
      "invalid-handle",
      "anchor-query",
      "anchor-type",
      "inheritable",
      "missing-anchor",
      "ambiguous-anchor",
      "contradictory-anchor",
      "zero-index",
      "inherited-anchor",
      "anchor-close",
      ...(thread ? ["thread-create", "missing-thread", "same-index"] : []),
    ]) {
      const f = fixture(name, [55, 84], fault);
      assert.throws(f.run, (error) => error === f.refusal, `${name}: ${fault}`);
      assert.deepEqual(
        f.closed.filter((handle) => typeof handle === "bigint"),
        f.created,
        fault,
      );
      assert.deepEqual(f.calls, thread ? [] : [201, 202, 203], fault);
      assert.ok(
        f.inventories.every((list) => f.freed.includes(list)),
        fault,
      );
    }
    for (const fault of [
      "required-refusal",
      "actual-type",
      "missing-job",
      "duplicate-job",
      "job-membership",
      "missing-pipe",
      "extra-pipe",
      "inherited-refusal",
      "unknown-inherited",
      "default-dacl",
      "job-dacl",
      ...(thread
        ? [
            "duplicate-thread",
            "thread-membership",
            "dacl",
            "pipe-dacl",
            "file-identity",
            "handle-bound",
          ]
        : [
            "compiler-limit",
            "compiler-breakaway",
            "compiler-silent-breakaway",
            "nested-compiler",
            "nested-controller",
          ]),
    ]) {
      const f = fixture(name, [55, 84], fault);
      assert.throws(f.run, (error) => error === f.refusal, `${name}: ${fault}`);
      if (fault === "required-refusal")
        assert.deepEqual(f.calls, thread ? [11] : [201, 202, 203, 11]);
      if (fault === "inherited-refusal") assert.ok(f.calls.includes(299));
      if (fault === "handle-bound")
        assert.equal(f.calls.filter((handle) => handle >= 200).length, 130);
    }
  }
});

test("ordinary DLL inspection avoids initialization while retain failures describe only evaluated calls", async () => {
  const source = await readFile(
      new URL("./custody-reader.c", import.meta.url),
      "utf8",
    ),
    importStart = source.indexOf(
      "  DWORD flags = LOAD_LIBRARY_SEARCH_SYSTEM32 |",
    ),
    importEnd = source.indexOf("  /* Open the observed NT path", importStart),
    retainStart = source.indexOf("  reader_retain.pid = pid;"),
    retainEnd = source.indexOf(
      "  for (unsigned i = 0; i < process_count;",
      retainStart,
    );
  assert.ok(
    importStart > 0 &&
      importEnd > importStart &&
      retainStart > 0 &&
      retainEnd > retainStart,
  );
  const mapping = new Script(
    source
      .slice(importStart, importEnd)
      .replace("DWORD flags", "const flags")
      .replace("size_t size", "const size")
      .replace("HMODULE module", "let module")
      .replace(
        "GetModuleHandleExW(0, name, &module)",
        "GetModuleHandleExW(0, name, value=>(module=value))",
      )
      .replaceAll('L"', '"')
      .replace("name+size-4", "name.slice(size-4)"),
  );
  for (const outcome of ["loaded", "mapped", "missing"]) {
    const context = {},
      calls = [],
      refusal = new Error("Original mapping failure");
    const run = () =>
      mapping.runInNewContext({
        reader_loader: context,
        image: "C:\\Fixture\\image.dll",
        name: "fixture.dll",
        TRUE: true,
        NULL: null,
        LOAD_LIBRARY_SEARCH_SYSTEM32: 0x800,
        DONT_RESOLVE_DLL_REFERENCES: 1,
        wcslen: (name) => name.length,
        _wcsicmp: (left, right) =>
          Number(left.toLowerCase() !== right.toLowerCase()),
        wcsspn: (name) => name.length,
        GetModuleHandleExW: (flags, name, set) => {
          assert.equal(flags, 0);
          assert.equal(name, "fixture.dll");
          if (outcome === "loaded") set(77);
          return outcome === "loaded";
        },
        LoadLibraryExW: (name, reserved, flags) => {
          calls.push({ name, reserved, flags });
          return outcome === "mapped" ? 77 : null;
        },
        need: (ok) => {
          if (!ok) throw refusal;
        },
      });
    if (outcome === "missing") assert.throws(run, (error) => error === refusal);
    else run();
    assert.deepEqual(
      calls,
      outcome === "loaded"
        ? []
        : [
            {
              name: "fixture.dll",
              reserved: null,
              flags: 0x801,
            },
          ],
    );
    assert.equal(context.active, true);
    assert.equal(context.image, "C:\\Fixture\\image.dll");
    assert.equal(context.name, "fixture.dll");
  }
  const selection = new Script(
    source
      .slice(
        importEnd,
        source.indexOf("  reader_loader.active = FALSE;", importEnd),
      )
      .replace(
        /wchar_t ([^;]+);/u,
        (_text, names) => `let ${names.replace(/\[\d+\]/gu, '=""')};`,
      )
      .replace(
        "FILE_ATTRIBUTE_TAG_INFO tag; FILE_ID_INFO before, after;",
        "const tag={},before={},after={};",
      )
      .replace("struct held_file file", "const file")
      .replace("char dacl[65]", "const dacl={}")
      .replace(/\b(?:DWORD|HANDLE)\b/gu, "const")
      .replaceAll('L"', '"')
      .replace(/sizeof\([^)]*\)/gu, "1")
      .replace(/&(tag|before|after)\b/gu, "$1")
      .replace(", mapped, 4100)", ", value=>(mapped=value), 4100)")
      .replace(
        "GetSystemDirectoryW(system,",
        "GetSystemDirectoryW(value=>(system=value),",
      )
      .replace(
        "swprintf_s(mappedPath,",
        "swprintf_s(value=>(mappedPath=value),",
      )
      .replace(
        /(GetFinalPathNameByHandleW\(selected, )(canonical|named),/gu,
        "$1value=>($2=value),",
      )
      .replace(
        "wcscpy_s(actual, 4096, canonical+4)",
        "actual=canonical.slice(4)",
      )
      .replace("actual+prefix+1", "actual.slice(prefix+1)"),
  );
  for (const fault of [
    null,
    "mapped-query",
    "mapped-truncated",
    "outside",
    "nested",
    "reparse",
    "mapped-identity",
    "held-identity",
    "release",
  ]) {
    const module = 0x100000000n,
      mapped = "\\Device\\FixtureVolume\\Windows\\System32\\fixture.dll",
      actual =
        fault === "outside"
          ? "C:\\Other\\fixture.dll"
          : "C:\\Windows\\System32\\" +
            (fault === "nested" ? "child\\" : "") +
            "fixture.dll",
      calls = [],
      refusal = new Error("Mapping identity refused");
    const run = () =>
      selection.runInNewContext({
        module,
        actual: "",
        FALSE: false,
        NULL: null,
        GENERIC_READ: 1,
        READ_CONTROL: 2,
        FILE_READ_ATTRIBUTES: 4,
        FILE_SHARE_READ: 1,
        OPEN_EXISTING: 3,
        FILE_FLAG_OPEN_REPARSE_POINT: 0x200000,
        INVALID_HANDLE_VALUE: -1,
        FileAttributeTagInfo: 1,
        FileIdInfo: 2,
        FILE_ATTRIBUTE_REPARSE_POINT: 0x400,
        FILE_NAME_NORMALIZED: 0,
        VOLUME_NAME_DOS: 0,
        VOLUME_NAME_NT: 2,
        GetCurrentProcess: () => 77,
        GetMappedFileNameW: (process, address, out) => {
          assert.equal(process, 77);
          assert.equal(address, module);
          out(mapped);
          return fault === "mapped-query"
            ? 0
            : fault === "mapped-truncated"
              ? 4100
              : mapped.length;
        },
        GetSystemDirectoryW: (out) => {
          const system = "C:\\Windows\\System32";
          out(system);
          return system.length;
        },
        swprintf_s: (out, capacity, format, value) => {
          const path = format.replace("%ls", value);
          assert.ok(path.length < capacity);
          out(path);
          return path.length;
        },
        CreateFileW: (path, ...options) => {
          assert.equal(path, "\\\\?\\GLOBALROOT" + mapped);
          assert.deepEqual(options, [7, 1, null, 3, 0x200000, null]);
          calls.push("open");
          return 55;
        },
        GetFileInformationByHandleEx: (handle, kind, out) => {
          if (kind === 1) out.FileAttributes = fault === "reparse" ? 0x400 : 0;
          else out.id = fault === "held-identity" && handle === 56 ? 8 : 7;
          return true;
        },
        GetFinalPathNameByHandleW: (handle, out, _capacity, flags) => {
          assert.equal(handle, 55);
          const value =
            flags === 0
              ? "\\\\?\\" + actual
              : fault === "mapped-identity"
                ? mapped + ".other"
                : mapped;
          out(value);
          return value.length;
        },
        wcsncmp: (left, right, count) =>
          Number(left.slice(0, count) !== right.slice(0, count)),
        _wcsnicmp: (left, right, count) =>
          Number(
            left.slice(0, count).toLowerCase() !==
              right.slice(0, count).toLowerCase(),
          ),
        _wcsicmp: (left, right) =>
          Number(left.toLowerCase() !== right.toLowerCase()),
        wcschr: (text, character) => text.includes(character),
        hold: (path) => {
          assert.equal(path, actual);
          calls.push("hold");
          return { handle: 56 };
        },
        stock_security: (handle) => {
          assert.equal(handle, 56);
          calls.push("security");
        },
        memcmp: (left, right) => Number(left.id !== right.id),
        CloseHandle: (handle) => {
          assert.equal(handle, 55);
          calls.push("close");
          return true;
        },
        FreeLibrary: (handle) => {
          assert.equal(handle, module);
          calls.push("free");
          return fault !== "release";
        },
        need: (ok) => {
          if (!ok) throw refusal;
        },
      });
    if (fault) assert.throws(run, (error) => error === refusal, fault);
    else run();
    if (!fault || fault === "release")
      assert.deepEqual(calls, ["open", "hold", "security", "close", "free"]);
    else assert.ok(!calls.includes("free"), fault);
  }
  const acquisition = new Script(
    source
      .slice(retainStart, retainEnd)
      .replace("HANDLE process", "let process")
      .replace("DWORD error", "let error")
      .replace(
        "reader_retain.observedPid == pid",
        "Number(reader_retain.observedPid === pid)",
      )
      .replace(
        "!!OpenProcessToken(process, reader_retain.tokenAccess, &token)",
        "Number(!!OpenProcessToken(process, reader_retain.tokenAccess, outToken))",
      ),
  );
  for (const fault of ["process", "identity", "token", null]) {
    const context = {},
      calls = [],
      refusal = new Error("Original acquisition failure");
    let lastError = 0,
      captured;
    const run = () =>
      acquisition.runInNewContext({
        reader_retain: context,
        pid: 33,
        TRUE: true,
        FALSE: false,
        NULL: null,
        PROCESS_QUERY_INFORMATION: 0x400,
        PROCESS_VM_READ: 0x10,
        READ_CONTROL: 0x20000,
        SYNCHRONIZE: 0x100000,
        TOKEN_QUERY: 8,
        TOKEN_DUPLICATE: 2,
        OpenProcess: (access, inherit, pid) => {
          assert.deepEqual([access, inherit, pid], [0x120410, false, 33]);
          calls.push("process");
          lastError = 87;
          return fault === "process" ? null : 1;
        },
        GetProcessId: () => {
          calls.push("identity");
          lastError = 5;
          return fault === "identity" ? 34 : 33;
        },
        OpenProcessToken: (_process, access, out) => {
          assert.equal(access, 10);
          calls.push("token");
          lastError = 10022;
          out(2);
          return fault !== "token";
        },
        outToken: () => {},
        GetLastError: () => lastError,
        SetLastError: (error) => {
          lastError = error;
        },
        need: (ok) => {
          if (ok) return;
          captured = { error: lastError, context: { ...context } };
          lastError = 999; // Diagnostic effects cannot replace the sampled error.
          throw refusal;
        },
      });
    if (fault) assert.throws(run, (error) => error === refusal);
    else {
      run();
      assert.equal(context.active, false);
    }
    assert.deepEqual(
      calls,
      fault === "process"
        ? ["process"]
        : fault === "identity"
          ? ["process", "identity"]
          : ["process", "identity", "token"],
    );
    if (!fault) continue;
    assert.equal(
      captured.error,
      { process: 87, identity: 5, token: 10022 }[fault],
    );
    assert.equal(
      captured.context.matched,
      fault === "process" ? -1 : fault === "identity" ? 0 : 1,
    );
    assert.equal(captured.context.tokenResult, fault === "token" ? 0 : -1);
  }
});

test("native loader and retain diagnostics preserve bounded UTF-16 context on the authenticated channel", async () => {
  const source = await readFile(
      new URL("./custody-reader.c", import.meta.url),
      "utf8",
    ),
    body =
      /static BOOL reader_context_failure\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(
        source,
      )[1],
    program = new Script(
      `(source,line,error)=>{${body
        .replace(
          "char bytes[2048], context[1400]; DWORD written;",
          "const bytes={},context={};let written;",
        )
        .replace(
          "char image[513] = {0}, name[513] = {0};",
          'const image={value:""},name={value:""};',
        )
        .replace("size_t units", "const units")
        .replace(
          "const BYTE *imageBytes = (const BYTE *)reader_loader.image, *nameBytes = (const BYTE *)reader_loader.name;",
          'const imageBytes=Buffer.from(reader_loader.image,"utf16le"),nameBytes=Buffer.from(reader_loader.name,"utf16le");',
        )
        .replaceAll("size_t i", "let i")
        .replace("image+i*2", "pointer(image,i*2)")
        .replace("name+i*2", "pointer(name,i*2)")
        .replaceAll("sizeof(image)", "513")
        .replaceAll("sizeof(name)", "513")
        .replaceAll("sizeof(context)", "1400")
        .replaceAll("sizeof(bytes)", "2048")
        .replace("int size", "const size")
        .replace("(DWORD)size", "size")
        .replace("&written", "out")
        .replace("\\036", "\\x1e")}}`,
    );
  const image = "C:\\Fixture\\" + "λ".repeat(4084),
    name = "x".repeat(124) + ".dll";
  assert.equal(image.length, 4095);
  for (const kind of ["loader", "retain"]) {
    const f = transport(),
      response = f.channel.receive(),
      frames = [],
      retain = {
        active: true,
        pid: 33,
        processAccess: 0x120410,
        tokenAccess: 10,
        process: false,
        observedPid: 0,
        matched: -1,
        tokenResult: -1,
      };
    let lastError = 126;
    const emit = program.runInNewContext({
      reader_loader:
        kind === "loader"
          ? { active: true, image, name, flags: 0x860 }
          : { active: false },
      reader_retain: kind === "retain" ? retain : { active: false },
      reader_command:
        kind === "loader" ? "prepare-experiment-loader" : "verify-retain",
      sequence: 1378,
      control: "authenticated",
      TRUE: true,
      FALSE: false,
      NULL: null,
      Buffer,
      wcsnlen_s: (text, maximum) => Math.min(text.length, maximum),
      pointer: (parent, at) => ({ parent, at }),
      out: () => {},
      sprintf_s: (target, maximum, format, ...values) => {
        let at = 0;
        const value = format.replace(/%(?:02x|zu|lu|[sud])/gu, (specifier) => {
          const value = values[at++];
          return specifier === "%02x"
            ? value.toString(16).padStart(2, "0")
            : (value?.value ?? value);
        });
        assert.ok(Buffer.byteLength(value) < maximum);
        if (target.parent)
          target.parent.value = target.parent.value.slice(0, target.at) + value;
        else target.value = value;
        lastError = 999;
        return value.length;
      },
      WriteFile: (handle, bytes, size) => {
        assert.equal(handle, "authenticated");
        frames.push(bytes.value.slice(0, size));
        return true;
      },
    });
    assert.equal(emit("custody-reader.c", 307, lastError), true);
    assert.equal(frames.length, 1);
    assert.ok(Buffer.byteLength(frames[0]) <= 2048);
    f.child.stdout.write(frames[0].slice(0, 25));
    f.child.stdout.write(frames[0].slice(25));
    await assert.rejects(response, (error) => {
      const value = error.custodyReaderFailure;
      assert.equal(value.lastError, 126);
      assert.equal(value.sequence, 1378);
      if (kind === "loader") {
        assert.equal(value.loader.imageUnits, image.length);
        assert.equal(
          Buffer.from(value.loader.imageHex, "hex").toString("utf16le"),
          image.slice(0, 128),
        );
        assert.equal(
          Buffer.from(value.loader.importHex, "hex").toString("utf16le"),
          name,
        );
      } else {
        const { active: _active, ...expected } = retain;
        assert.deepEqual(value.retain, expected);
      }
      return true;
    });
    await assert.rejects(f.channel.completion);
    f.child.emit("close", 126, null);
  }
});

test("Windows failure metadata stays closed and bounded across complete and fragmented frames", async () => {
  const legacy = {
    phase: "reader-failure",
    sequence: 270,
    command: "verify-transfer",
    source: "custody-reader.c",
    line: 1,
  };
  const trust = {
    mode: "embedded",
    result: "0x00000005",
    closeResult: "0x00000000",
    entry: null,
    identity: id(11),
    sha256: null,
    signatureSha256: null,
  };
  const value = {
    ...legacy,
    lastError: 0xffffffff,
    transfer: {
      ordinal: 838859,
      count: 838860,
      type: 0xffff,
      access: 0xffffffff,
      attributes: 0xffffffff,
      creator: 127,
      child: 126,
    },
  };
  const loader = {
    ...legacy,
    command: "prepare-experiment-loader",
    lastError: 126,
    loader: {
      imageUnits: 4095,
      imageHex: Buffer.from("C:\\" + "x".repeat(125), "utf16le").toString(
        "hex",
      ),
      importHex: Buffer.from("fixture.dll", "utf16le").toString("hex"),
      flags: 0x860,
    },
  };
  const retain = {
    ...legacy,
    command: "verify-retain",
    lastError: 87,
    retain: {
      pid: 33,
      processAccess: 0x120410,
      tokenAccess: 10,
      process: false,
      observedPid: 0,
      matched: -1,
      tokenResult: -1,
    },
  };
  const opened = {
    ...legacy,
    lastError: 3,
    open: {
      operation: "CreateFileW",
      pathUnits: 4,
      pathUtf16: "0043003a005c0066",
      directory: false,
      apiFailure: true,
      attributes: null,
      tag: null,
    },
  };
  const invalid = [
    ...[
      { pathUnits: 4096 },
      { apiFailure: false },
      { attributes: 0 },
      { extra: true },
    ].map((damage) => ({ ...opened, open: { ...opened.open, ...damage } })),
    {
      ...opened,
      open: {
        ...opened.open,
        operation: "file-kind",
        apiFailure: false,
        attributes: 0x10,
        tag: 0xcafebabe,
      },
    },
    { ...opened, retain: retain.retain },
    ...[
      { flags: 0x800 },
      { flags: 0x801 },
      { imageUnits: 4096 },
      { imageUnits: 0 },
      { imageHex: "aa" },
      { importHex: "bad" },
      { importHex: "" },
      { importHex: Buffer.from("../fixture.dll", "utf16le").toString("hex") },
      { extra: true },
    ].map((damage) => ({ ...loader, loader: { ...loader.loader, ...damage } })),
    { ...loader, command: "open" },
    { ...loader, retain: retain.retain },
    { ...loader, trust },
    { ...loader, lastError: undefined },
    ...[
      { pid: 0 },
      { processAccess: 0 },
      { tokenAccess: 0 },
      { process: 0 },
      { observedPid: 33 },
      { matched: 0 },
      { tokenResult: 0 },
      { process: true, observedPid: 33, matched: 1, tokenResult: 1 },
      { extra: true },
    ].map((damage) => ({ ...retain, retain: { ...retain.retain, ...damage } })),
    { ...retain, transfer: value.transfer },
    { ...retain, lastError: undefined },
    ...[null, -1, 0x100000000, 1.5, "5", true, []].map((lastError) => ({
      ...value,
      lastError,
    })),
    { ...value, lastError: undefined },
    { ...value, command: "open" },
    { ...value, trust },
    { ...legacy, lastError: 5, trust },
    { ...value, extra: 1 },
    { ...value, transfer: null },
    ...[
      "ordinal",
      "count",
      "type",
      "access",
      "attributes",
      "creator",
      "child",
    ].flatMap((field) =>
      [-1, 1.5, "1", null, 0x100000000, undefined].map((entry) => ({
        ...value,
        transfer: { ...value.transfer, [field]: entry },
      })),
    ),
    ...[
      { ordinal: 838860 },
      { count: 0 },
      { count: 838861 },
      { type: 65536 },
      { creator: 128 },
      { child: 128 },
      { child: 127 },
      { extra: 1 },
    ].map((damage) => ({
      ...value,
      transfer: { ...value.transfer, ...damage },
    })),
  ];
  const valid = [
    opened,
    loader,
    {
      ...loader,
      command: "release-import",
      loader: { ...loader.loader, flags: 0x800 },
    },
    retain,
    {
      ...retain,
      retain: { ...retain.retain, process: true, observedPid: 34, matched: 0 },
    },
    {
      ...retain,
      retain: {
        ...retain.retain,
        process: true,
        observedPid: 33,
        matched: 1,
        tokenResult: 0,
      },
    },
    legacy,
    { ...legacy, trust },
    { ...legacy, lastError: 0 },
    value,
    { ...value, command: "verify-compiler-policy" },
  ];
  for (const [expected, packet] of [
    ...valid.map((p) => [true, p]),
    ...invalid.map((p) => [false, p]),
  ]) {
    const frame = "\x1e" + JSON.stringify(packet) + "\n";
    for (const split of [false, true]) {
      const f = transport(),
        response = f.channel.receive();
      f.child.stdout.write(frame.slice(0, split ? 25 : frame.length));
      if (split) f.child.stdout.write(frame.slice(25));
      await assert.rejects(response, (error) => {
        assert.equal(Object.hasOwn(error, "custodyReaderFailure"), expected);
        if (expected) assert.deepEqual(error.custodyReaderFailure, packet);
        return true;
      });
      await assert.rejects(f.channel.completion);
      assert.throws(() => f.channel.settle());
      f.child.emit("close", 126, null);
    }
  }
  const json = JSON.stringify(value);
  for (const [bytes, complete] of [
    [2048, true],
    [2049, true],
    [2049, false],
  ]) {
    const frame =
      "\x1e" +
      json +
      " ".repeat(bytes - 1 - json.length - Number(complete)) +
      (complete ? "\n" : "");
    for (const split of [false, true]) {
      const f = transport(),
        response = f.channel.receive();
      // A large interrupted ordinary response does not consume the diagnostic budget.
      f.child.stdout.write('{"value":"' + "x".repeat(2048));
      f.child.stdout.write(frame.slice(0, split ? 2048 : frame.length));
      if (split) f.child.stdout.write(frame.slice(2048));
      await assert.rejects(response, (error) => {
        assert.equal(
          Object.hasOwn(error, "custodyReaderFailure"),
          bytes === 2048,
        );
        return true;
      });
      await assert.rejects(f.channel.completion);
      assert.throws(() => f.channel.settle());
      f.child.emit("close", 126, null);
    }
  }
});

test("Windows trust diagnostics reject malformed status, entry and held-pin context", async () => {
  const trust = {
    mode: "embedded",
    result: "0x800b0100",
    closeResult: "0x00000000",
    entry: 11,
    identity: id(11),
    sha256: hash,
    signatureSha256: hash,
    inputs: [
      88, 32, 1, 1, 1, 0, 2, 0, 1, 0x1010, 0, 0, 0, 0, 0, 0, 0, 1024, 0, 1024,
    ],
    provider: [1, 1, 1, 1, 8, 0, 3, 1, 3, 1, 1, 5, 1],
  };
  for (const damage of [
    { result: 2148204800 },
    { result: "0x1" },
    { result: "0x00000000" },
    { closeResult: "0x100000000" },
    { mode: "fallback" },
    { entry: 128 },
    { entry: null },
    { identity: [id(11)] },
    { sha256: null },
    { signatureSha256: "substituted" },
    { inputs: [] },
    { inputs: Array(20).fill("unknown") },
    { inputs: Array(20).fill(2) },
    { provider: [] },
    { provider: Array(13).fill("unknown") },
    ...[
      [0, 2],
      [2, 0],
      [4, -1],
      [5, 0x100000000],
      [6, 2],
      [7, 0],
      [8, 65],
      [9, 4],
      [10, 3],
      [11, 0],
      [12, 0],
    ].map(([index, value]) => ({
      provider: trust.provider.with(index, value),
    })),
    { result: "0x00000000", closeResult: "0x00000005" },
    { extra: true },
  ]) {
    const f = transport(),
      response = f.channel.receive();
    f.child.stdout.write(
      "\x1e" +
        JSON.stringify({
          phase: "reader-failure",
          sequence: 2,
          command: "open",
          source: "custody.h",
          line: 1,
          trust: { ...trust, ...damage },
        }) +
        "\n",
    );
    await assert.rejects(
      response,
      (error) => !Object.hasOwn(error, "custodyReaderFailure"),
    );
    await assert.rejects(f.channel.completion);
    assert.throws(() => f.channel.settle());
    f.child.emit("close", 126, null);
  }
  const f = transport(),
    response = f.channel.receive(),
    unbound = {
      ...trust,
      mode: "catalog",
      entry: null,
      sha256: null,
      signatureSha256: null,
    };
  f.child.stdout.write(
    "\x1e" +
      JSON.stringify({
        phase: "reader-failure",
        sequence: 2,
        command: "signature",
        source: "custody.h",
        line: 1,
        trust: unbound,
      }) +
      "\n",
  );
  await assert.rejects(response, (error) => {
    assert.deepEqual(error.custodyReaderFailure.trust, unbound);
    return true;
  });
  await assert.rejects(f.channel.completion);
  assert.throws(() => f.channel.settle());
  f.child.emit("close", 126, null);
});

test("actual bridge relay settles original overlapped I/O and separates wait, exit-query and exit-code results", async () => {
  const source = await readFile(
      new URL("./custody-bridge.c", import.meta.url),
      "utf8",
    ),
    body = (name) =>
      new RegExp(
        `static DWORD ${name}\\([^\\n]+\\) \\{([\\s\\S]*?)\\n\\}`,
        "u",
      ).exec(source)[1],
    translate = (text) =>
      text
        .replace("OVERLAPPED operation = {0};", "let operation={};")
        .replaceAll("(DWORD)", "")
        .replace(/\b(?:BOOL|DWORD|ULONGLONG)\b/gu, "let")
        .replaceAll("operation->", "operation.")
        .replaceAll("*used", "used.value")
        .replaceAll("&operation", "operation")
        .replace(/&(exit|code|forward_stopping)\b/gu, "value=>$1=value"),
    program =
      new Script(`function relay_wait(operation,timeout,used){${translate(body("relay_wait"))}}
      function relay_io(writing,bytes,size,used,timeout){${translate(body("relay_io"))}}
      function relay_retire(process,input){${translate(body("relay_retire"))}}`),
    constants = {
      TRUE: true,
      FALSE: false,
      NULL: null,
      ERROR_SUCCESS: 0,
      ERROR_IO_PENDING: 997,
      ERROR_IO_INCOMPLETE: 996,
      ERROR_GEN_FAILURE: 31,
      ERROR_TIMEOUT: 1460,
      ERROR_NOT_FOUND: 1168,
      WAIT_OBJECT_0: 0,
      WAIT_TIMEOUT: 258,
      WAIT_FAILED: 0xffffffff,
      STILL_ACTIVE: 259,
    },
    fixture = () => {
      const calls = [],
        reports = [];
      let error = 109;
      const api = {
        ...constants,
        pipe: "pipe",
        forward_stopping: 0,
        GetLastError: () => error,
        relay_report: (...record) => reports.push(record),
        relay_check: (operation, ok, value, error) => {
          if (!ok) throw { operation, value, error };
        },
        CloseHandle: (handle) => {
          calls.push(["close", handle]);
          error = 109;
          return true;
        },
      };
      program.runInNewContext(api);
      return { api, calls, reports, setError: (value) => (error = value) };
    };
  for (const fault of [
    null,
    "timeout",
    "wait",
    "completion",
    "close",
    "incomplete",
    "cancel-stalled",
    "cancel-wait",
  ]) {
    const f = fixture();
    let settled = false,
      tick = 1000,
      waits = 0;
    const cancelled = [
        "timeout",
        "wait",
        "cancel-stalled",
        "cancel-wait",
      ].includes(fault),
      unsettled = ["incomplete", "cancel-stalled", "cancel-wait"].includes(
        fault,
      );
    Object.assign(f.api, {
      GetTickCount64: () => tick,
      CreateEventW: () => "event",
      HasOverlappedIoCompleted: () => settled,
      WriteFile: () => {
        f.calls.push(["start"]);
        f.setError(997);
        return false;
      },
      WaitForSingleObject: (_event, timeout) => {
        f.calls.push(["wait", timeout]);
        f.setError(6);
        if (waits++ === 0) {
          assert.equal(timeout, 30000);
          tick += fault === "wait" ? 5 : cancelled ? 30000 : 0;
          return fault === "wait" ? 0xffffffff : cancelled ? 258 : 0;
        }
        assert.equal(timeout, fault === "wait" ? 29995 : 0);
        return fault === "cancel-stalled"
          ? 258
          : fault === "cancel-wait"
            ? 0xffffffff
            : 0;
      },
      CancelIoEx: () => {
        f.calls.push(["cancel"]);
        f.setError(fault === "cancel-stalled" ? 109 : 1168);
        return fault === "cancel-stalled";
      },
      GetOverlappedResult: (_pipe, _operation, used, wait) => {
        assert.equal(wait, false, "Completion queries must never block");
        f.calls.push(["complete", wait]);
        used.value = 8;
        const error =
          fault === "completion"
            ? 109
            : fault === "incomplete"
              ? 996
              : fault === "wait"
                ? 995
                : 0;
        settled = error !== 996;
        f.setError(error);
        return !error;
      },
      CloseHandle: () => {
        assert.equal(settled, true);
        f.calls.push(["close"]);
        f.setError(6);
        return fault !== "close";
      },
    });
    if (fault === "close" || unsettled)
      assert.throws(
        () => f.api.relay_io(true, {}, 8, { value: 0 }, 30000),
        (error) =>
          error.operation ===
          (fault === "close"
            ? "pipe-event-close"
            : fault === "incomplete"
              ? "pipe-settlement"
              : "pipe-settlement-wait"),
      );
    else
      assert.equal(
        f.api.relay_io(true, {}, 8, { value: 0 }, 30000),
        fault === "timeout"
          ? 1460
          : fault === "wait"
            ? 6
            : fault === "completion"
              ? 109
              : 0,
      );
    assert.equal(
      f.calls.some(([name]) => name === "cancel"),
      cancelled,
    );
    assert.equal(
      f.calls.some(([name]) => name === "complete"),
      !["cancel-stalled", "cancel-wait"].includes(fault),
    );
    assert.equal(
      f.calls.some(([name]) => name === "close"),
      !unsettled,
    );
    if (fault === "cancel-stalled")
      assert.ok(
        f.reports.some(
          ([name, value, error]) =>
            name === "pipe-cancel" && value === true && error === 0,
        ),
      );
    if (fault === "wait")
      assert.ok(
        f.reports.some(
          ([name, value, error]) =>
            name === "pipe-wait" && value === 0xffffffff && error === 6,
        ),
      );
  }
  for (const fault of [
    null,
    "wait-timeout",
    "wait-failed",
    "query",
    "exit126",
    "exit124",
    "input",
    "input-late",
  ]) {
    const f = fixture();
    let tick = 0;
    Object.assign(f.api, {
      WaitForSingleObject: (handle, timeout) => {
        f.setError(5);
        if (handle === "input" && fault === "input-late") {
          assert.equal(timeout, 5);
          tick = 30000;
          return 0;
        }
        return handle === "reader"
          ? fault === "wait-timeout"
            ? 258
            : fault === "wait-failed"
              ? 0xffffffff
              : 0
          : 0;
      },
      GetExitCodeProcess: (_process, out) => {
        out(fault === "exit126" ? 126 : fault === "exit124" ? 124 : 0);
        f.setError(6);
        return fault !== "query";
      },
      InterlockedExchange: (out, value) => out(value),
      GetTickCount64: () => tick++,
      CancelSynchronousIo: () => {
        if (fault === "input-late") tick = 29995;
        f.setError(1168);
        return false;
      },
      CancelIoEx: () => {
        f.setError(1168);
        return false;
      },
      GetExitCodeThread: (_thread, out) => {
        out(fault === "input" ? 126 : 0);
        return true;
      },
    });
    if (fault)
      assert.throws(
        () => f.api.relay_retire("reader", "input"),
        (error) => {
          assert.equal(
            error.operation,
            fault.startsWith("wait")
              ? "reader-wait"
              : fault === "query"
                ? "reader-exit-query"
                : ["input", "input-late"].includes(fault)
                  ? "input-settlement"
                  : "reader-exit",
          );
          assert.equal(
            error.error,
            fault === "wait-failed" ? 5 : fault === "query" ? 6 : 0,
          );
          return true;
        },
      );
    else assert.equal(f.api.relay_retire("reader", "input"), 0);
    assert.deepEqual(
      f.calls,
      fault === "input-late" ? [] : [["close", "input"]],
    );
    assert.ok(
      f.reports.some(
        ([name, value]) =>
          name === "reader-exit-query" && value === (fault !== "query"),
      ),
    );
  }
});
test("Windows custody and observer task XML delegates service-account logon to registration", async () => {
  // Decode the actual C literal without invoking a Windows compiler or scheduler.
  const source = await readFile(
      new URL("./custody-bridge.c", import.meta.url),
      "utf8",
    ),
    literal = source.match(
      /\bwchar_t xml\[\d+\] = L("(?:[^"\\]|\\.)*");/u,
    )?.[1];
  assert.ok(literal, "Expected the bridge task XML literal");
  const xml = JSON.parse(literal);
  assert.doesNotMatch(xml, /<LogonType\b/u);
  assert.match(
    xml,
    /<Principal id="System"><UserId>S-1-5-18<\/UserId><RunLevel>HighestAvailable<\/RunLevel><\/Principal>/u,
  );
  assert.match(source, /definition = SysAllocString\(xml\)/u);
  assert.match(source, /VariantInit\(&empty\);/u);
  assert.match(
    source,
    /user\.vt = VT_BSTR; user\.bstrVal = SysAllocString\(L"S-1-5-18"\);/u,
  );
  const registration = source.match(
    /need_hr\(ITaskFolder_RegisterTask,\s*([^;]+)\);/u,
  );
  assert.ok(registration, "Expected checked Task Scheduler registration");
  assert.deepEqual(
    registration[1].split(",").map((argument) => argument.trim()),
    [
      "folder",
      "taskName",
      "definition",
      "TASK_CREATE | TASK_DONT_ADD_PRINCIPAL_ACE",
      "user",
      "empty",
      "TASK_LOGON_SERVICE_ACCOUNT",
      "securityValue",
      "&task",
    ],
  );
});

test("Windows task principals route SID syntax and account names to exact LocalSystem validation", async () => {
  const source = await readFile(
      new URL("./custody-bridge.c", import.meta.url),
      "utf8",
    ),
    body = source.match(
      /need\(CreateWellKnownSid\(WinLocalSystemSid,[\s\S]*?(?=  SysFreeString\(text\);)/u,
    )?.[0];
  assert.ok(body);
  const check = new Script(
    body
      .replace("PSID actual;", "const actual = {};")
      .replaceAll('L"', '"')
      .replaceAll(/&([a-zA-Z]+)/gu, "$1")
      .replaceAll(/\bNULL\b/gu, "null"),
  );
  for (const [text, route, result, accepted] of [
    ["S-1-5-18", "sid", "S-1-5-18", true],
    ["SYSTEM", "name", "S-1-5-18", true],
    ["S-1-invalid", "sid", null, false],
    ["S-1-5-19", "sid", "S-1-5-19", false],
    ["FixtureUser", "name", "S-1-5-21-1-2-3-1001", false],
    ["UnmappedUser", "name", null, false],
    ["S-1-5-18", "sid", "invalid-sid", false],
  ]) {
    const calls = [],
      resolve = (kind, value, output) => {
        assert.equal(value, text);
        calls.push(kind);
        output.valid = result !== "invalid-sid";
        output.value = output.valid ? result : "S-1-5-18";
        return result !== null;
      };
    const api = {
      text,
      sid: {},
      expected: {},
      size: 0,
      expectedSize: 0,
      domain: null,
      domainSize: 0,
      type: 0,
      WinLocalSystemSid: "system",
      need: assert.ok,
      LocalFree() {},
      CreateWellKnownSid(_, __, output) {
        output.value = "S-1-5-18";
        return true;
      },
      _wcsnicmp: (left, right, size) =>
        left.slice(0, size).toLowerCase().localeCompare(right.toLowerCase()),
      ConvertStringSidToSidW: (value, output) => resolve("sid", value, output),
      LookupAccountNameW: (_, value, output) => resolve("name", value, output),
      IsValidSid: (sid) => sid.valid,
      EqualSid: (left, right) => left.value === right.value,
    };
    if (accepted) check.runInNewContext(api);
    else assert.throws(() => check.runInNewContext(api), assert.AssertionError);
    assert.deepEqual(calls, [route]);
  }
});

test("Windows installed-input open guards diagnose only sampled failures and preserve native errors", async () => {
  const source = await readFile(new URL("custody.h", import.meta.url), "utf8"),
    refusal = /static void open_file_refusal\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(
      source,
    )?.[1],
    opening = /static HANDLE open_file_shared\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(
      source,
    )?.[1];
  assert.ok(refusal && opening);
  const reader = await readFile(
      new URL("custody-reader.c", import.meta.url),
      "utf8",
    ),
    start = reader.indexOf("  if (open_file_failure.name) {"),
    sending = reader.slice(start, reader.indexOf("#endif", start));
  assert.ok(start > 0 && sending);
  const failure = /static void reader_failure\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(
      reader,
    )[1],
    dispatch = new Script(
      `(file,line,error)=>{${failure
        .slice(0, failure.indexOf("  char bytes[1024]"))
        .replace("const char *source", "let source")
        .replace("source+1", "source.slice(1)")}
        throw new Error("Missing native failure context");
      }`,
    ),
    strrchr = (file, separator) => {
      const index = file.lastIndexOf(separator);
      return index < 0 ? null : file.slice(index);
    };
  const formatC = (text, args) => {
    let i = 0;
    return text.replace(/%(?:0(\d+))?(s|lu|zu|u|lx|x)/gu, (_, width, kind) => {
      const argument = args[i++],
        value = argument?.value ?? argument;
      return kind === "s"
        ? value
        : Number(value)
            .toString(kind.endsWith("x") ? 16 : 10)
            .padStart(Number(width ?? 0), "0");
    });
  };
  const translate = (body) =>
    body
      .replace(
        "FILE_ATTRIBUTE_TAG_INFO tag; wchar_t canonical[4100]; DWORD size;",
        "const tag = {}, canonical = 0; let size;",
      )
      .replaceAll(/\((?:unsigned long|unsigned)\)/gu, "")
      .replaceAll(/\b(?:DWORD|HANDLE|size_t|int) /gu, "let ")
      .replaceAll("tag->", "tag.")
      .replaceAll("&tag", "tag")
      .replaceAll('L"', '"')
      .replaceAll(/\bNULL\b/gu, "null");
  const sender = new Script(
    `function publish(source, line, error) {${translate(sending)
      .replace(
        'char bytes[17408], path[16385] = {0}, attributes[16] = "null", tag[16] = "null";',
        'const bytes = {value:""}, path = {value:""}, attributes = {value:"null"}, tag = {value:"null"};',
      )
      .replaceAll(
        /sizeof\((bytes|path|attributes|tag)\)/gu,
        (_, name) =>
          ({ bytes: 17408, path: 16385, attributes: 16, tag: 16 })[name],
      )
      .replaceAll("path+i*4", "{parent:path, offset:i*4}")
      .replaceAll("(DWORD)", "")
      .replaceAll("&written", "null")
      .replaceAll("\\036", "\\x1e")} return FALSE;} publish;`,
  );
  const selected = "C:\\Fixture SDK\\\ud83d\ude00\\Windows.h";
  for (const experiment of [false, true]) {
    const body = opening.replace(
        /#ifdef NATIVE_CI_EXPERIMENT\n([\s\S]*?)#else\n([\s\S]*?)#endif/gu,
        (_, ordinary, reviewed) => (experiment ? ordinary : reviewed),
      ),
      program = new Script(`
        function open_file_refusal(name, operation, api_failure, directory, tag) {${translate(refusal)}}
        function open_file_shared(name, directory, access, mutable) {${translate(body).replaceAll("sizeof(tag)", "8")}}
        open_file_shared(name, directory, 1, false);
      `);
    for (const [fault, directory, file = selected] of [
      ["open", false],
      ["query", false],
      ["reparse", false],
      ["kind", false],
      ["kind", true, "C:\\Fixture SDK"],
      ["query", true, "C:\\Fixture SDK"],
      ["open", true, "C:\\"],
      ["write", false],
      ["open", false, "C:\\" + "x".repeat(4092)],
      [null, false],
      [null, true, "C:\\"],
    ]) {
      const calls = [],
        chunks = [],
        name = Uint16Array.from(
          file
            .split("")
            .map((unit) => unit.charCodeAt(0))
            .concat(0),
        ),
        apiFailure = ["open", "write", "query"].includes(fault),
        attributes =
          fault === "reparse"
            ? 0x420
            : directory !== (fault === "kind")
              ? 0x10
              : 0x20,
        // Without the reparse attribute, Windows leaves ReparseTag undefined.
        tag = fault === "reparse" ? 0xa000000c : 0xcafebabe;
      let error = 87;
      const emit = (bytes) => {
          error = 999;
          api.errno = 99;
          if (fault === "write") return -1;
          chunks.push(bytes);
          return bytes.length;
        },
        api = {
          name,
          directory: Number(directory),
          errno: 23,
          stderr: "stderr",
          open_file_failure: { tag: {} },
          TRUE: 1,
          FALSE: 0,
          INVALID_HANDLE_VALUE: -1,
          READ_CONTROL: 0x20000,
          FILE_READ_ATTRIBUTES: 0x80,
          FILE_SHARE_READ: 1,
          FILE_SHARE_WRITE: 2,
          OPEN_EXISTING: 3,
          FILE_FLAG_OPEN_REPARSE_POINT: 0x200000,
          FILE_FLAG_BACKUP_SEMANTICS: 0x2000000,
          FILE_ATTRIBUTE_REPARSE_POINT: 0x400,
          FILE_ATTRIBUTE_DIRECTORY: 0x10,
          FileAttributeTagInfo: 9,
          FILE_NAME_NORMALIZED: 0,
          VOLUME_NAME_DOS: 0,
          HANDLE_FLAG_INHERIT: 1,
          CreateFileW(actual, access, share) {
            assert.equal(actual, name);
            assert.equal(access, 0x20081);
            assert.equal(share, directory ? 3 : 1);
            calls.push("open");
            if (["open", "write"].includes(fault)) {
              error = 3;
              return -1;
            }
            return 7;
          },
          GetFileInformationByHandleEx(handle, kind, actual, size) {
            assert.equal(handle, 7);
            assert.equal(kind, 9);
            assert.equal(size, 8);
            calls.push("query");
            if (fault === "query") {
              error = 5;
              return 0;
            }
            Object.assign(actual, {
              FileAttributes: attributes,
              ReparseTag: tag,
            });
            return 1;
          },
          GetFinalPathNameByHandleW() {
            calls.push("canonical");
            return 20;
          },
          SetHandleInformation() {
            calls.push("inheritance");
            return 1;
          },
          GetLastError() {
            calls.push("error");
            return error;
          },
          SetLastError(value) {
            error = value;
          },
          wcslen: (value) => value.indexOf(0),
          wcsncmp: () => 0,
          wcscmp: () => 0,
          fprintf(stream, format, ...args) {
            assert.equal(stream, "stderr");
            return emit(formatC(format, args));
          },
          fputs: (text) => emit(text),
          fputc: (unit) => emit(unit),
          fflush: () => {
            error = 998;
          },
          need(ok) {
            if (!ok)
              throw Object.assign(new Error("Original open refusal"), {
                lastError: error,
              });
          },
        };
      if (fault) {
        assert.throws(
          () => program.runInNewContext(api),
          (cause) => {
            assert.equal(cause.message, "Original open refusal");
            assert.equal(
              cause.lastError,
              apiFailure ? (fault === "query" ? 5 : 3) : 87,
            );
            return true;
          },
        );
        assert.equal(api.errno, 23);
        assert.deepEqual(calls, [
          "open",
          ...(["open", "write"].includes(fault) ? [] : ["query"]),
          ...(experiment ? ["error"] : []),
        ]);
      } else {
        assert.equal(program.runInNewContext(api), 7);
        assert.deepEqual(calls, ["open", "query", "canonical", "inheritance"]);
      }
      const output = chunks.join("");
      if (!experiment || !fault || fault === "write") assert.equal(output, "");
      else {
        const operation =
          fault === "open"
            ? "CreateFileW"
            : fault === "query"
              ? "GetFileInformationByHandleEx/FileAttributeTagInfo"
              : fault === "reparse"
                ? "reparse-point"
                : "file-kind";
        assert.ok(
          output.includes(
            `operation=${operation} domain=${apiFailure ? "win32" : "invariant"} expected-kind=${directory ? "directory" : "file"}`,
          ),
        );
        assert.ok(
          output.includes(
            apiFailure
              ? `error=${fault === "query" ? 5 : 3} attributes=unavailable tag=unavailable`
              : `error=unavailable attributes=0x${attributes.toString(16).padStart(8, "0")} tag=${fault === "reparse" ? `0x${tag.toString(16).padStart(8, "0")}` : "unavailable"}`,
          ),
        );
        assert.ok(
          output.endsWith(
            `path-units=${file.length} path-utf16=${file
              .split("")
              .map((unit) => unit.charCodeAt(0).toString(16).padStart(4, "0"))
              .join("")}\n`,
          ),
        );
      }
      if (experiment && fault) {
        const frames = [];
        Object.assign(api, {
          capturedError: apiFailure ? (fault === "query" ? 5 : 3) : 87,
          reader_diagnostics_ready: true,
          signature_trust: { active: false },
          strrchr,
          reader_context_failure() {
            assert.fail("Loader context masked the sampled open refusal");
          },
          sequence: 459,
          reader_command: "prepare-experiment-input",
          control: "authenticated",
          sprintf_s(target, maximum, format, ...args) {
            const text = formatC(format, args);
            assert.ok(text.length < maximum);
            if (target.parent)
              target.parent.value =
                target.parent.value.slice(0, target.offset) + text;
            else target.value = text;
            return text.length;
          },
          WriteFile(handle, bytes, size) {
            assert.equal(handle, "authenticated");
            if (fault === "write") return false;
            frames.push(bytes.value.slice(0, size));
            return true;
          },
        });
        api.reader_open_failure = sender.runInNewContext(api);
        dispatch.runInNewContext(api)("custody.h", 174, api.capturedError);
        if (fault === "write") assert.deepEqual(frames, []);
        else {
          assert.equal(frames.length, 1);
          assert.ok(Buffer.byteLength(frames[0]) < 17408);
          const f = transport(),
            pending = f.channel.receive().catch((cause) => cause),
            completion = f.channel.completion.catch((cause) => cause);
          try {
            f.child.stdout.write(frames[0].slice(0, 29));
            f.child.stdout.write(frames[0].slice(29));
            const cause = await pending;
            assert.equal(
              cause.custodyReaderFailure.lastError,
              api.capturedError,
            );
            const observed = cause.custodyReaderFailure.open;
            assert.equal(observed.pathUnits, file.length);
            assert.equal(
              observed.pathUtf16,
              file
                .split("")
                .map((unit) => unit.charCodeAt(0).toString(16).padStart(4, "0"))
                .join(""),
            );
            assert.equal(observed.apiFailure, apiFailure);
            assert.equal(observed.attributes, apiFailure ? null : attributes);
            assert.equal(observed.tag, fault === "reparse" ? tag : null);
            f.child.emit("close", 126, null);
            assert.equal(await completion, cause);
          } finally {
            f.channel.close();
            f.child.stdin.destroy();
            f.child.stdout.destroy();
            f.child.stderr.destroy();
          }
        }
      }
    }
  }
  const fallback = [];
  dispatch.runInNewContext({
    reader_diagnostics_ready: true,
    signature_trust: { active: false },
    strrchr,
    reader_open_failure() {
      fallback.push("open");
      return false;
    },
    reader_context_failure(source, line, error) {
      fallback.push([source, line, error]);
      return true;
    },
  })("custody-reader.c", 274, 87);
  assert.deepEqual(fallback, ["open", ["custody-reader.c", 274, 87]]);
});

test("Windows open, guard and scheduler HRESULT diagnostics retain independent original and cleanup failures", async () => {
  const chunks = [],
    inputPath = "C:\\Fixture SDK\\Windows.h",
    open = `native-windows-open: operation=CreateFileW domain=win32 expected-kind=file error=3 attributes=unavailable tag=unavailable path-units=${inputPath.length} path-utf16=${inputPath
      .split("")
      .map((unit) => unit.charCodeAt(0).toString(16).padStart(4, "0"))
      .join("")}\n`,
    guard = Buffer.from(
      open +
        "native-windows-hresult: operation=ITaskFolder_RegisterTask hresult=0x80070005 file=fixture.c line=23\n" +
        "native-windows-guard: file=fixture.c line=23 last-error=5\n",
    ),
    cleanup = Buffer.from(
      "native-windows-hresult: operation=ITaskFolder_DeleteTask hresult=0x80070002 file=fixture.c line=47\n",
    );
  await withNativeDiagnostics(
    async () => {
      for (const cleanupFailure of [false, true]) {
        const f = transport();
        try {
          const pending = f.channel.receive().catch((error) => error),
            completion = f.channel.completion.catch((error) => error);
          const at = guard.indexOf("file=");
          f.child.stderr.write(guard.subarray(0, at));
          f.child.stderr.write(guard.subarray(at));
          let original;
          if (cleanupFailure) {
            f.child.stdout.emit(
              "error",
              new Error("Original scheduler transport failure"),
            );
            original = await pending;
            f.child.stderr.write(cleanup);
            f.child.stderr.emit(
              "error",
              new Error("Independent scheduler cleanup failure"),
            );
          }
          f.child.emit("close", 126, null);
          const [first, last] = await Promise.all([pending, completion]);
          assert.ok(first instanceof Error);
          assert.equal(last, first);
          if (cleanupFailure) assert.equal(last, original);
        } finally {
          f.channel.close();
          f.child.stdin.destroy();
          f.child.stdout.destroy();
          f.child.stderr.destroy();
        }
      }
    },
    createNativeDiagnosticWriter((bytes) => chunks.push(bytes)),
  );
  const output = Buffer.concat(chunks).toString();
  assert.ok(output.includes(open.trim()));
  assert.ok(output.includes("native-windows-guard"));
  assert.ok(output.includes("file=fixture.c line=23 last-error=5"));
  assert.ok(
    output.includes("operation=ITaskFolder_RegisterTask hresult=0x80070005"),
  );
  assert.ok(
    output.includes("operation=ITaskFolder_DeleteTask hresult=0x80070002"),
  );
  assert.ok(output.includes("Original scheduler transport failure"));
  assert.ok(output.includes("Independent scheduler cleanup failure"));
});

// Only raw native frames are replaced. These tests supply no approval,
// transfer, retirement or completed-custody callback implementation.
function verificationFixture(f = fixture()) {
  const build = Boolean(f.buildEntry),
    transferred = new Set(),
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
      ...(f.input.purpose === "experiment" ? { purpose: "experiment" } : {}),
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
    worker: identity(41),
    jobFlags: build ? 0x2808 : 0x2008,
    jobLimit: build ? 32 : 1,
  };
  if (build)
    states.set(state.worker.pid, {
      ...structuredClone(f.process),
      identity: state.worker,
    });
  state.compilerJob = {
    daclSha256: hash,
    limitFlags: 0x2008,
    processLimit: 31,
    uiRestrictions: 255,
    members: [state.worker],
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
              : build
                ? f.entries[
                    pid === state.worker.pid
                      ? f.buildEntry.tool
                      : f.buildEntry.helper
                  ]
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
    else if (name === "task-instance")
      value = {
        absent: false,
        sha256: hash,
        instances: state.instances,
        registeredInstances: 0,
        running:
          state.instances === 0
            ? []
            : Array.from({ length: state.instances }, () => ({
                guid: instance.guid,
                state: 4,
                engine: f.helper,
                helperLinked: true,
              })),
      };
    else if (name === "process-exit") value = { exitCode: state.exitCode ?? 0 };
    else if (name === "recovery-jobs")
      value = {
        nonce: args[1],
        identity: subjects[Number(args[0])].identity,
        jobs: Array.from({ length: 128 }, (_, i) =>
          i === 0 && state.recoveryMembers
            ? {
                daclSha256: hash,
                limitFlags: state.recoveryFlags ?? 0x2008,
                processLimit: 32,
                uiRestrictions: 255,
                members: state.recoveryMembers,
              }
            : { absent: true },
        ),
        compilerJob:
          build && subjects[Number(args[0])].identity.pid === f.fileHelper.pid
            ? state.compilerJob
            : { absent: true },
      };
    else if (name === "transfer") {
      transferred.add(Number(args[0]));
      value = {
        threadDaclSha256: hash,
        job: {
          daclSha256: hash,
          limitFlags: state.jobFlags,
          processLimit: state.jobLimit,
          uiRestrictions: 255,
          members: state.jobMembers,
        },
        objects: [
          null,
          null,
          ...(build ? [] : [id(2), id(3)]),
          ...(state.unknownHandle ? [id(9)] : []),
        ],
        inheritedHandleCount: (build ? 2 : 4) + (state.unknownHandle ? 1 : 0),
        pipeDaclSha256: [hash, hash],
        creatorDefaultDaclSha256: hash,
      };
    } else if (name === "compiler-policy")
      value = {
        defaultDacl: [{ type: 0, flags: 0, mask: 0x10000000, sid: "S-1-5-18" }],
        inheritedHandles: ["pipe", "pipe", "pipe"],
        compilerJob: state.compilerJob,
      };
    else if (name === "sharing") value = { identity: id(2) };
    else if (name === "job")
      value = transferred.has(Number(args[0]))
        ? {
            daclSha256: hash,
            limitFlags: state.jobFlags,
            processLimit: state.jobLimit,
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
    instance: { ...instance, enginePid: f.helper.pid },
  };
  const transfer = {
    kind: build ? "build" : "file",
    args: [],
    request: build ? f.buildRequest : f.file.request,
    image: f.entries[build ? f.buildEntry.helper : 0],
    objects: build ? [] : [f.object(1), f.object(2)],
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
        limitFlags: state.jobFlags,
        processLimit: state.jobLimit,
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
  assert.equal(sealed.entries.length, 9);
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

test("Windows admission joins the original scheduler instance, including hidden tasks, and diagnoses each rejected predicate", async () => {
  for (const fault of [
    null,
    "registered-one",
    "zero",
    "multiple",
    "registered-multiple",
    "guid",
    "state",
    "engine",
    "helper",
  ]) {
    const k = verificationFixture();
    if (fault === "zero") k.state.instances = 0;
    if (fault === "multiple") k.state.instances = 2;
    k.state.damage = (operation, frame) => {
      if (operation === "verify-task-instance" && frame.value.running[0]) {
        const row = frame.value.running[0];
        if (fault === "registered-one") frame.value.registeredInstances = 1;
        if (fault === "registered-multiple")
          frame.value.registeredInstances = 2;
        if (fault === "guid")
          row.guid = "{22222222-2222-3333-4444-555555555555}";
        if (fault === "state") row.state = 2;
        if (fault === "engine") row.engine.pid = 2048;
        if (fault === "helper") row.helperLinked = false;
      }
      return Buffer.from(JSON.stringify(frame) + "\n");
    };
    await k.verifier.verifyBootstrap(k.f.input);
    if (!fault || fault === "registered-one")
      assert.equal(
        (await k.verifier.verifyAdmission(k.admission)).taskSha256,
        hash,
      );
    else
      await assert.rejects(k.verifier.verifyAdmission(k.admission), (error) => {
        assert.equal(error.admission.expectedDigest, hash);
        assert.equal(error.admission.actualDigest, hash);
        assert.equal(
          error.admission.registeredInstances,
          fault === "registered-multiple" ? 2 : 0,
        );
        const predicate = {
          zero: "unique",
          multiple: "unique",
          "registered-multiple": "unique",
          guid: "original",
          state: "state",
          engine: "engine",
          helper: "helper",
        }[fault];
        assert.equal(error.admission.predicates[predicate], false);
        return true;
      });
  }
});

test("Windows rejected admission aborts only the original parked helper before unchanged task removal", async () => {
  for (const fault of [
    null,
    "exit124",
    "job",
    "lost-abort",
    "removed-reply",
    "retained-receipt",
  ]) {
    const f = fixture(),
      k = verificationFixture(f),
      primary = new Error("admission pending"),
      cleanup = new Error("cleanup interrupted");
    k.state.instances = 0;
    f.options.verifyAdmission = async (value) => {
      await k.verifier.verifyBootstrap(f.input);
      try {
        return await k.verifier.verifyAdmission(value);
      } catch (error) {
        primary.cause = error;
        throw primary;
      }
    };
    f.options.preSetupVerifier = async () => {
      await assert.rejects(
        k.verifier.verifyAdmission(k.admission),
        (error) => error === primary.cause,
      );
      return createWindowsCustodyVerifier(k.observer, { exchange: k.exchange });
    };
    const send = f.owner.send;
    f.owner.send = async (line) => {
      if (line === "X\n") {
        f.events.push("X");
        assert.ok(
          f.records.some((record) => record.phase === "pre-setup-bound"),
        );
        k.states.get(f.helper.pid).retired = true;
        if (fault === "exit124") k.state.exitCode = 124;
        if (fault === "job") k.state.recoveryMembers = [f.fileHelper];
        if (["lost-abort", "retained-receipt"].includes(fault)) throw cleanup;
        f.frames.push({
          phase: "helper-retired",
          helper: f.helper,
          exitCode: 0,
        });
      } else if (line === "D") {
        f.events.push("D");
        assert.ok(
          f.records.some(
            (record) => record.phase === "pre-setup-helper-retired",
          ),
        );
        k.states.get(10).retired = true;
        k.state.absent = true;
        if (fault === "removed-reply") throw cleanup;
        f.frames.push({
          phase: "retired",
          taskSha256: hash,
          taskRemoved: true,
          helperRetired: true,
        });
      } else return send(line);
    };
    const reader = f.reader();
    await assert.rejects(reader.start(), (error) => error === primary);
    const parked = f.records.find((record) => record.phase === "task-parked");
    assert.deepEqual(parked.helper, f.helper);
    assert.equal(parked.taskSha256, hash);
    assert.equal(f.events.includes("fault"), false);
    if (fault === "retained-receipt") {
      const persist = f.options.persist;
      f.options.persist = async (record) => {
        if (record.phase === "retained")
          throw new Error("Receipt writer unavailable");
        return persist(record);
      };
    }
    const settled = await reader.close();
    assert.equal(settled.status, fault ? "RETAINED" : "RETIRED");
    assert.equal(f.events.includes("P"), false);
    if (fault) {
      assert.equal(settled.primaryCause, primary);
      assert.notEqual(settled.cause, primary);
      if (["lost-abort", "removed-reply", "retained-receipt"].includes(fault))
        assert.equal(settled.cause, cleanup);
      assert.equal(f.records.at(-1).custody, "POSSIBLE");
      assert.equal(f.events.includes("D"), fault === "removed-reply");
    } else {
      assert.equal(settled.independent, true);
      assert.equal(settled.emergencyCleanup, false);
      assert.equal(settled.taskRemoved, true);
      const exit = k.events.findIndex(
        (event) => event.operation === "verify-process-exit",
      );
      assert.ok(exit >= 0);
    }
    await assert.rejects(reader.start());
  }
});

test("Windows bridge completion acknowledgement uses the held identity after process retirement", async () => {
  const source = await readFile(
      new URL("./custody-bridge.c", import.meta.url),
      "utf8",
    ),
    body =
      /  DWORD exit = relay_retire\(process, input\);[\s\S]*?ack\('D'\);/u.exec(
        source,
      )?.[0];
  assert.ok(
    body,
    "Expected the shared bridge retirement and acknowledgement boundary",
  );
  const program = new Script(body.replace("DWORD exit", "const exit"));
  for (const input of [null, {}]) {
    const process = { retired: false },
      helperToken = {},
      calls = [];
    program.runInNewContext({
      process,
      input,
      helperToken,
      helperSession: 0,
      stdout: {},
      relay_retire(actual, thread) {
        assert.equal(actual, process);
        assert.equal(thread, input);
        process.retired = true;
        calls.push("retire");
        return 0;
      },
      printf() {},
      puts() {},
      fflush() {},
      identity() {
        assert.fail(
          "Retired processes cannot supply a fresh token/session observation",
        );
      },
      retained_identity(actual, token, session) {
        assert.equal(actual, process);
        assert.equal(process.retired, true);
        assert.equal(token, helperToken);
        assert.equal(session, 0);
        calls.push("identity");
      },
      ack(value) {
        assert.equal(value, "D");
        calls.push("remove");
      },
    });
    assert.deepEqual(calls, ["retire", "identity", "remove"]);
  }
});

test("actual scheduler query explicitly includes hidden instances and selects the exact task path", async () => {
  const source = await readFile(
      new URL("./custody-reader.c", import.meta.url),
      "utf8",
    ),
    body = /static LONG task_instances\([^\n]*\) \{([\s\S]*?)\n\}/u
      .exec(source)[1]
      .replace(
        "IRunningTaskCollection *all; LONG count, found=0; wchar_t path[132];",
        "let all,count,found=0,path;",
      )
      .replace(
        /swprintf_s\(path,132,L"[^\n]*?",name\)/u,
        "format(value=>path=value,name)",
      )
      .replace(/\bLONG\b/gu, "let")
      .replace(
        "VARIANT index;VariantInit(&index);",
        "let index={};VariantInit(index);",
      )
      .replace("IRunningTask *running;BSTR actual;", "let running,actual;")
      .replace(/(?<!&)&(all|count|running|actual)\b/gu, "value=>$1=value");
  for (const paths of [[], ["\\other"], ["\\owned"], ["\\owned", "\\owned"]]) {
    const owned = [],
      released = [],
      api = {
        service: {},
        name: "owned",
        owned,
        TASK_ENUM_HIDDEN: 1,
        VT_I4: 3,
        format: (out, name) => {
          out("\\" + name);
          return 1;
        },
        need: assert.ok,
        need_hr: (fn, ...args) => fn(...args),
        VariantInit: () => {},
        ITaskService_GetRunningTasks: (_service, flags, out) => {
          assert.equal(flags, 1);
          out(paths);
        },
        IRunningTaskCollection_get_Count: (all, out) => out(all.length),
        IRunningTaskCollection_get_Item: (all, index, out) =>
          out(all[index.lVal - 1]),
        IRunningTask_get_Path: (task, out) => out(task),
        _wcsicmp: (a, b) => (a.toLowerCase() === b.toLowerCase() ? 0 : 1),
        IRunningTask_Release: (task) => released.push(task),
        SysFreeString: () => {},
        IRunningTaskCollection_Release: () => {},
      };
    assert.equal(
      new Script(`(function(){${body}})()`).runInNewContext(api),
      paths.filter((p) => p === "\\owned").length,
    );
    assert.deepEqual(
      released,
      paths.filter((p) => p !== "\\owned"),
    );
  }
});

test("actual task removal refuses any live retained process or surviving held Job", async () => {
  const source = await readFile(
      new URL("./custody-reader.c", import.meta.url),
      "utf8",
    ),
    body =
      /      for \(unsigned i = 0; i < process_count; i\+\+\) need\(WaitForSingleObject\(processes\[i\], 0\) == WAIT_OBJECT_0\);[\s\S]*?(?=      need_hr\(ITaskFolder_DeleteTask)/u.exec(
        source,
      )?.[0];
  assert.ok(body, "Expected the native task-removal retirement boundary");
  const program = new Script(
    body
      .replaceAll("unsigned i", "let i")
      .replaceAll(
        "JOBOBJECT_BASIC_ACCOUNTING_INFORMATION current;",
        "const current = {};",
      )
      .replaceAll("sizeof(current)", "1")
      .replaceAll("&current", "current")
      .replaceAll("NULL", "null") + "remove();",
  );
  for (const fault of [
    null,
    "reader",
    "observer",
    "verified-job",
    "named-job",
    "query",
  ]) {
    const processes = [
        { retired: fault !== "reader" },
        { retired: fault !== "observer" },
      ],
      verified_jobs = [{ active: fault === "verified-job" }],
      jobs = [{ active: fault === "named-job" }];
    let removed = false;
    const run = () =>
      program.runInNewContext({
        processes,
        process_count: processes.length,
        verified_jobs,
        jobs,
        job_count: jobs.length,
        WAIT_OBJECT_0: 0,
        JobObjectBasicAccountingInformation: 1,
        WaitForSingleObject: (process, timeout) => {
          assert.equal(timeout, 0);
          return process.retired ? 0 : 258;
        },
        QueryInformationJobObject: (job, _kind, current) => {
          current.ActiveProcesses = job.active ? 1 : 0;
          return fault !== "query";
        },
        need: assert.ok,
        remove: () => {
          removed = true;
        },
      });
    if (fault) assert.throws(run);
    else run();
    assert.equal(removed, fault === null);
  }
});

test("independent build admission and retirement bind separate original controller and compiler domains", async () => {
  for (const fault of [
    null,
    "controller-policy",
    "controller-member",
    "compiler-breakaway",
    "compiler-silent",
    "compiler-member",
    "unknown-policy",
    "worker-birth",
    "worker-live",
    "compiler-survivor",
    "missing-retirement",
    "unbound-recovery-policy",
  ]) {
    const k = verificationFixture(fixture({ build: true }));
    await k.verifier.verifyBootstrap(k.f.input);
    await k.verifier.verifyAdmission(k.admission);
    if (fault === "controller-policy") {
      k.state.jobFlags = k.helperTransfer.actual.job.limitFlags = 0x2008;
      await assert.rejects(k.verifier.verifyTransfer(k.helperTransfer));
      continue;
    }
    await k.verifier.verifyTransfer(k.helperTransfer);
    const record = {
        phase: "worker-admitted",
        requestSha256: hash,
        helper: k.f.fileHelper,
        worker: k.state.worker,
      },
      admissionFault = [
        "controller-member",
        "compiler-breakaway",
        "compiler-silent",
        "compiler-member",
        "unknown-policy",
      ].includes(fault);
    if (fault === "controller-member") k.state.jobMembers.push(k.state.worker);
    if (fault === "compiler-breakaway") k.state.compilerJob.limitFlags |= 0x800;
    if (fault === "compiler-silent") k.state.compilerJob.limitFlags |= 0x1000;
    if (fault === "compiler-member")
      k.state.compilerJob.members.push(k.f.fileHelper);
    if (fault === "unknown-policy")
      k.state.damage = (operation, frame) => {
        if (operation === "verify-compiler-policy") frame.value.extra = true;
        return Buffer.from(JSON.stringify(frame) + "\n");
      };
    const admit = () =>
      k.verifier.verifyBuildWorker(
        record,
        k.f.entries[k.f.buildEntry.tool],
        hash,
      );
    if (admissionFault) {
      await assert.rejects(admit);
      continue;
    }
    const proof = await admit();
    assert.deepEqual(proof.compilerPolicy.outerJob.members, [k.f.fileHelper]);
    assert.deepEqual(proof.compilerPolicy.compilerJob.members, [
      k.state.worker,
    ]);
    k.states.get(k.f.fileHelper.pid).retired = true;
    k.states.get(k.state.worker.pid).retired = fault !== "worker-live";
    k.state.jobMembers = [];
    k.state.compilerJob.members =
      fault === "compiler-survivor" ? [identity(99)] : [];
    if (fault === "worker-birth")
      k.states.get(k.state.worker.pid).identity.creationTime = "999";
    if (fault === "missing-retirement")
      k.state.damage = (operation, frame) => {
        if (operation === "verify-recovery-jobs")
          throw new Error("Original named Job inaccessible");
        return Buffer.from(JSON.stringify(frame) + "\n");
      };
    if (fault === "unbound-recovery-policy") {
      k.state.recoveryMembers = [];
      k.state.recoveryFlags = 0x2808;
    }
    const finish = () => k.verifier.verifyHelperRetirement(k.f.fileHelper);
    if (fault) await assert.rejects(finish);
    else {
      assert.equal((await finish()).status, "RETIRED");
      assert.equal(
        k.events.filter(({ operation }) => operation === "verify-recovery-jobs")
          .length,
        2,
      );
      const before = k.events.length;
      await assert.rejects(
        k.verifier.recoverOwnedTask(nonce, hash, k.admission.bridge),
      );
      assert.equal(
        k.events.length,
        before,
        "One compiler's settlement must not authorize whole-run task removal",
      );
    }
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

test("Windows recovery removes original tasks before admitting live dependent observer births", async () => {
  const k = verificationFixture(),
    original = [k.f.helper, identity(10, runnerSid)],
    observer = k.f.fileHelper;
  k.state.instances = 0;
  k.state.jobMembers = [];
  for (const identity of original) k.states.get(identity.pid).retired = true;
  const proof = await k.verifier.recoverCompleted(k.f.input, original);
  assert.equal(proof.status, "RETIRED");
  assert.ok(
    !k.events.some(
      (event) =>
        event.operation === "verify-retain" &&
        Number(event.args[0]) === observer.pid,
    ),
  );
  await k.verifier.recoverOwnedTask(nonce, hash, original[1]);
  const custody = await k.verifier.retainObservers(k.f.input, [observer]);
  assert.equal(custody.independent, true);
  assert.deepEqual(custody.identities, [observer]);
  assert.equal(Object.hasOwn(custody, "status"), false);
  const removal = k.events.findIndex(
      (event) => event.operation === "verify-task-remove",
    ),
    retained = k.events.findIndex(
      (event) =>
        event.operation === "verify-retain" &&
        Number(event.args[0]) === observer.pid,
    );
  assert.ok(removal >= 0 && retained > removal);
  assert.equal(
    k.events
      .slice(retained)
      .filter((event) => event.operation === "verify-process").length,
    2,
  );
  await assert.rejects(
    k.verifier.recoverCompleted(k.f.input, [...original, observer]),
  );

  const premature = verificationFixture();
  premature.state.instances = 0;
  premature.state.jobMembers = [];
  for (const identity of original)
    premature.states.get(identity.pid).retired = true;
  await premature.verifier.recoverCompleted(premature.f.input, original);
  await premature.verifier.retainObservers(premature.f.input, [observer]);
  await assert.rejects(
    premature.verifier.recoverOwnedTask(nonce, hash, original[1]),
  );
  assert.equal(premature.state.removedTasks.size, 0);
});

test("Windows original-owner recovery retains a failed process hold despite later observer completion", async () => {
  const k = verificationFixture(),
    original = [k.f.helper, identity(10, runnerSid)],
    cause = Object.assign(new Error("Original process hold unavailable"), {
      nativeFailure: {
        phase: "reader-failure",
        command: "verify-retain",
        line: 213,
        lastError: 87,
        retain: {
          pid: 33,
          processAccess: 0x120410,
          tokenAccess: 10,
          process: false,
          observedPid: 0,
          matched: -1,
          tokenResult: -1,
        },
      },
    });
  k.state.instances = 0;
  k.state.jobMembers = [];
  for (const birth of original) k.states.get(birth.pid).retired = true;
  k.state.damage = (operation, frame) => {
    if (operation === "verify-retain") throw cause;
    return Buffer.from(JSON.stringify(frame) + "\n");
  };
  await assert.rejects(
    k.verifier.recoverCompleted(k.f.input, original),
    (error) => error === cause,
  );
  k.state.damage = null;
  // Completing an observer supplies no held original process/token proof.
  k.states.get(k.f.fileHelper.pid).retired = true;
  await assert.rejects(
    k.verifier.recoverCompleted(k.f.input, original),
    (error) => error === cause,
  );
  assert.equal(k.state.removedTasks.size, 0);
});

test("Windows observer custody rejects missing, substituted or changed births and incomplete inventories", async () => {
  for (const fault of [
    "missing",
    "substituted",
    "changed",
    "inventory",
    "duplicate",
    "reader",
  ]) {
    const k = verificationFixture(),
      expected = k.f.fileHelper;
    if (fault === "reader") {
      k.states.get(expected.pid).retired = true;
      await k.verifier.recoverCompleted(k.f.input, [expected]);
    }
    if (fault === "missing") k.states.delete(expected.pid);
    if (fault === "substituted")
      k.states.get(expected.pid).identity = {
        ...expected,
        creationTime: "999",
      };
    let reads = 0;
    k.state.damage = (operation, frame) => {
      if (
        operation === "verify-process" &&
        ++reads === 2 &&
        fault === "changed"
      )
        frame.value.identity.creationTime = "999";
      if (operation === "verify-subjects" && fault === "inventory")
        frame.value.identities = [];
      return Buffer.from(JSON.stringify(frame) + "\n");
    };
    await assert.rejects(
      k.verifier.retainObservers(
        k.f.input,
        fault === "duplicate" ? [expected, expected] : [expected],
      ),
    );
    const commands = k.events.length;
    await assert.rejects(k.verifier.retainObservers(k.f.input, [expected]));
    assert.equal(
      k.events.length,
      commands,
      "Failed verification remains terminal",
    );
  }
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
      }
      if (line === "D") {
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

test("Windows experiment custody retains native Job and handle protection requirements", async () => {
  const f = fixture();
  f.input.purpose = "experiment";
  f.input.bindingSha256 = f.input.reviewSha256;
  delete f.input.reviewSha256;
  const header = {
    path: "C:\\Fixture\\Sealed\\experiment.h",
    sha256: digest("experiment header"),
  };
  f.bytes.set(header.path, Buffer.from("experiment header"));
  f.input.sources.push(header);
  const plan = encodeWindowsCustodyPlan({
    purpose: "experiment",
    candidateSha,
    nonce,
    entries: f.entries,
  });
  f.bytes.set(f.input.plan.path, plan);
  f.input.plan.sha256 = digest(plan);
  const mixed = verificationFixture(f);
  delete mixed.observer.verification.input.purpose;
  mixed.observer.verification.input.reviewSha256 =
    mixed.observer.verification.input.bindingSha256;
  delete mixed.observer.verification.input.bindingSha256;
  mixed.observer.verification.input.sources.pop();
  const reviewed = createWindowsCustodyVerifier(mixed.observer, {
    exchange: mixed.exchange,
  });
  await assert.rejects(reviewed.verifyBootstrap(f.input));
  const k = verificationFixture(f);
  await k.verifier.verifyBootstrap(f.input);
  await k.verifier.verifyAdmission(k.admission);
  k.state.damage = (operation, frame) => {
    if (operation === "verify-transfer") frame.value.job.limitFlags |= 0x800;
    return Buffer.from(JSON.stringify(frame) + "\n");
  };
  await assert.rejects(k.verifier.verifyTransfer(k.helperTransfer));
  const bootstrap = f.options.verifyBootstrap;
  f.options.verifyBootstrap = async (...args) => {
    const { reviewSha256, ...seal } = await bootstrap(...args);
    return { ...seal, purpose: "experiment", bindingSha256: reviewSha256 };
  };
  const reader = f.reader();
  await reader.start();
  await reader.open(0);
  await reader.retainProcess(f.process.identity);
  let missing = false;
  f.options.damage = (op, frame) => {
    if (op === "loader" && !missing)
      frame.value.importScope = "private-runtime";
    return frame;
  };
  assert.equal((await reader.loader(0, 0)).importScope, "private-runtime");
  missing = true;
  await assert.rejects(reader.loader(0, 0));
});

test("installed Git admission shares a bounded UCRT and MinGW path predicate", async () => {
  const source = await readFile(
      new URL("./custody-reader.c", import.meta.url),
      "utf8",
    ),
    body = /static BOOL installed_git_runtime\([^\n]+\) \{([\s\S]*?)\n\}/u
      .exec(source)[1]
      .replace(/\bL(?=["'])/gu, "")
      .replace("const wchar_t *prefixes[] = {", "const prefixes = [")
      .replace("};", "];")
      .replace("unsigned i", "let i")
      .replace("size_t length", "const length")
      .replace(
        "const wchar_t *leaf = name+2+length, *extension = wcsrchr(leaf, '.');",
        "const leaf = name.slice(2+length), extension = wcsrchr(leaf, '.');",
      )
      .replace("name+2,", "name.slice(2),")
      .replace("*leaf &&", "leaf.length &&"),
    script = new Script(`(function(name){${body}})`),
    find = (text, character, last = false) => {
      const index = last
        ? text.lastIndexOf(character)
        : text.indexOf(character);
      return index < 0 ? null : text.slice(index);
    },
    admitted = script.runInNewContext({
      TRUE: true,
      FALSE: false,
      wcslen: (text) => text.length,
      wcschr: find,
      wcsrchr: (text, character) => find(text, character, true),
      _wcsicmp: (a, b) => (a.toLowerCase() === b.toLowerCase() ? 0 : 1),
      _wcsnicmp: (a, b, length) =>
        a.slice(0, length).toLowerCase() === b.slice(0, length).toLowerCase()
          ? 0
          : 1,
    });
  for (const layout of ["ucrt64", "mingw64"])
    for (const leaf of ["git.exe", "runtime.DLL"])
      assert.equal(
        admitted(`C:\\Program Files\\Git\\${layout}\\bin\\${leaf}`),
        true,
      );
  for (const file of [
    "C:\\Other\\Git\\ucrt64\\bin\\git.exe",
    "C:\\Program Files\\Git\\cmd\\git.exe",
    "C:\\Program Files\\Git\\bin\\git.exe",
    "C:\\Program Files\\Git\\other\\bin\\git.exe",
    "C:\\Program Files\\Git\\ucrt64\\bin-other\\git.exe",
    "C:\\Program Files\\Git\\ucrt64\\bin\\nested\\runtime.dll",
    "C:\\Program Files\\Git\\ucrt64\\bin\\runtime.dll:stream",
    "C:\\Program Files\\Git\\ucrt64\\bin\\runtime:stream.dll",
    "C:\\Program Files\\Git\\ucrt64\\bin\\input.h",
  ])
    assert.equal(admitted(file), false, file);
  for (const section of [
    source.slice(
      source.indexOf("static BOOL stock_entry"),
      source.indexOf("static void stock_security"),
    ),
    source.slice(
      source.indexOf(
        'experimentInput = !strcmp(v[0], "prepare-experiment-input")',
      ),
      source.indexOf(
        "if (snapshot) {",
        source.indexOf(
          'experimentInput = !strcmp(v[0], "prepare-experiment-input")',
        ),
      ),
    ),
  ])
    assert.match(section, /installed_git_runtime\(name\)/u);
});

test("cold account recovery cannot signal a Job reopened by name or remove a surviving principal", async () => {
  const source = await readFile(
    new URL("./custody-reader.c", import.meta.url),
    "utf8",
  );
  const start = source.indexOf(
    "static void recovery_case(unsigned custody, const char *context, const char *caseNonce, BOOL required) {",
  );
  const body = source.slice(start, source.indexOf("int wmain", start));
  assert.ok(start > 0);
  assert.doesNotMatch(
    body,
    /operation_stop_job|TerminateJobObject|TerminateProcess/u,
  );
  assert.ok(
    body.indexOf("need(!members)") < body.indexOf("LsaRemoveAccountRights"),
  );
  assert.match(body, /operation_empty\(job\)/u);
});
