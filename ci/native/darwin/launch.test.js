import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import test from "node:test";
import {
  admitDarwinLaunch,
  darwinLaunchDigest,
  DARWIN_LITERAL_ARGUMENTS,
  inspectDarwinMachO,
  normalizeDarwinLaunch,
  sameDarwinIdentity,
} from "./index.js";
import { darwinAdmissionChannel } from "./channel.js";

const HASH = "a".repeat(64),
  CANDIDATE = "b".repeat(40);
function fixture() {
  const request = normalizeDarwinLaunch({
    schemaVersion: 1,
    candidateSha: CANDIDATE,
    nonce: "c".repeat(32),
    uid: 90001,
    gid: 90002,
    custody: "/fixture/custody",
    storage: "/fixture/storage",
    workspace: "/fixture/storage/work",
    launcher: { path: "/fixture/custody/launcher", sha256: HASH },
    executable: {
      path: "/fixture/storage/payload",
      sha256: HASH,
      cdhash: "d".repeat(40),
    },
    policy: { path: "/fixture/custody/policy", sha256: HASH },
    bindings: {
      system: HASH,
      source: HASH,
      closure: HASH,
      policy: "e".repeat(64),
    },
  });
  const identity = (pid, uid, gid, asid) => ({
    pid,
    pidVersion: 1,
    asid,
    auid: uid,
    uid,
    gid,
    ruid: uid,
    rgid: gid,
    svuid: uid,
    svgid: gid,
    startSeconds: 100,
    startMicroseconds: 1,
  });
  const helper = identity(100, 0, 0, 0),
    payload = identity(101, request.uid, request.gid, 99),
    verifier = identity(102, 0, 0, 0);
  const metadata = (uid, gid, mode, ino) => ({
    dev: "1",
    ino: String(ino),
    uid,
    gid,
    mode,
  });
  const authority = {
    bindings: request.bindings,
    helper,
    payload,
    custody: metadata(0, 0, 0o700, 1),
    storage: metadata(0, request.gid, 0o710, 2),
    workspace: metadata(request.uid, request.gid, 0o700, 3),
    cwd: metadata(request.uid, request.gid, 0o700, 3),
    executable: {
      ...metadata(0, request.gid, 0o550, 4),
      nlink: 1,
      sha256: HASH,
      cdhash: request.executable.cdhash,
    },
    policy: {
      sha256: HASH,
      compositionSha256: request.bindings.policy,
      installed: true,
    },
    groups: [request.gid],
    mach: {
      bootstrap: false,
      access: false,
      registered: 0,
      exceptions: 0,
      foreignRights: 0,
      host: "ordinary",
    },
  };
  const calls = [],
    records = [];
  const transport = {
    ready: Promise.resolve({ helper, payload }),
    release: () => calls.push("release"),
    settle: () => calls.push("settle"),
    close: () => calls.push("close"),
  };
  const effects = {
    persist: async (value) => {
      records.push(structuredClone(value));
      calls.push(`persist-${value.phase}`);
    },
    verifyInputs: async () => ({
      approvedSha256: darwinLaunchDigest(request, DARWIN_LITERAL_ARGUMENTS),
      bindings: request.bindings,
      libraries: [],
    }),
    launchParked: async (_, args, verified, onHelper) => {
      calls.push("park");
      assert.deepEqual(args, DARWIN_LITERAL_ARGUMENTS);
      await onHelper(helper);
      calls.push("helper-admitted");
      return transport;
    },
    inspect: async (_, expected) => ({
      helper,
      payload: expected.payload,
      verifiers: [verifier],
    }),
    verifyAuthority: async () => structuredClone(authority),
    verifyReceipt: async (_, record) => ({
      sha256: createHash("sha256")
        .update(JSON.stringify(record) + "\n")
        .digest("hex"),
    }),
    retire: async () => {
      throw new Error("Retirement is a separate phase");
    },
  };
  const options = {
    platform: "darwin",
    architecture: "x64",
    uid: 0,
    now: () => 0,
    env: { CI: "true", GITHUB_ACTIONS: "true", ImageOS: "macos15" },
  };
  return {
    request,
    helper,
    payload,
    verifier,
    authority,
    calls,
    records,
    effects,
    options,
    run: () =>
      admitDarwinLaunch(
        request,
        DARWIN_LITERAL_ARGUMENTS,
        darwinLaunchDigest(request, DARWIN_LITERAL_ARGUMENTS),
        effects,
        options,
      ),
  };
}

test("Darwin admission persists and rechecks protected authority before literal release", async () => {
  const f = fixture(),
    result = await f.run();
  assert.equal(result.record.status, "ADMITTED");
  assert.equal(result.record.reservation, "RETAINED");
  assert.deepEqual(
    result.record.helpers.map(({ role }) => role),
    ["launcher", "verifier"],
  );
  assert.ok(f.calls.indexOf("persist-release") < f.calls.indexOf("release"));
  assert.ok(
    f.calls.indexOf("persist-helper") < f.calls.indexOf("helper-admitted"),
  );
  assert.equal(f.records[0].admission, "possible");
  assert.equal(f.records[0].payload, null);
  await assert.rejects(
    result.transport.settle(),
    /Retirement is a separate phase/u,
  );
  assert.ok(!f.calls.includes("settle"));
  assert.notEqual(
    darwinLaunchDigest(f.request, DARWIN_LITERAL_ARGUMENTS),
    darwinLaunchDigest(
      { ...f.request, candidateSha: "f".repeat(40) },
      DARWIN_LITERAL_ARGUMENTS,
    ),
  );
  assert.notEqual(
    darwinLaunchDigest(f.request, DARWIN_LITERAL_ARGUMENTS),
    darwinLaunchDigest(f.request, ["changed"]),
  );
});

test("Darwin settlement retains the admitted identities despite caller mutation", async () => {
  const f = fixture();
  let retired;
  f.effects.retire = async (_, record) => {
    retired = record;
  };
  const result = await f.run(),
    admitted = structuredClone(result.record);
  result.record.payload.pid = 999;
  result.record.helpers.length = 0;
  result.record.authority.bindings.source = "f".repeat(64);
  await result.transport.settle();
  assert.deepEqual(retired, admitted);
  assert.equal(f.calls.at(-1), "settle");
  await assert.rejects(result.transport.settle());
});

test("Darwin missing capabilities, stale identities, changed storage and incomplete policy prevent release", async () => {
  for (const failure of [
    "missing",
    "input",
    "identity",
    "helper",
    "groups",
    "mach",
    "signature",
    "policy",
    "storage",
    "cwd",
    "receipt",
    "deadline",
  ]) {
    const f = fixture();
    if (failure === "missing") delete f.effects.retire;
    if (failure === "input")
      f.effects.verifyInputs = async () => ({
        missingInputs: ["contract.audit-domain.mach_port_kobject"],
      });
    if (failure === "identity")
      f.effects.inspect = async (_, expected) => ({
        helper: f.helper,
        payload: expected.payload && { ...f.payload, pidVersion: 2 },
        verifiers: [f.verifier],
      });
    if (failure === "helper")
      f.effects.inspect = async (_, expected) => ({
        helper: f.helper,
        payload: expected.payload,
        verifiers: [f.payload],
      });
    if (failure === "groups") f.authority.groups.push(0);
    if (failure === "mach") f.authority.mach.host = "privileged";
    if (failure === "signature") f.authority.executable.cdhash = "f".repeat(40);
    if (failure === "policy") f.authority.policy.installed = false;
    if (failure === "cwd") f.authority.cwd.ino = "999";
    if (failure === "storage") {
      let reads = 0;
      f.effects.verifyAuthority = async () => {
        const value = structuredClone(f.authority);
        if (reads++) value.storage.ino = "999";
        return value;
      };
    }
    if (failure === "receipt")
      f.effects.verifyReceipt = async () => ({ sha256: "f".repeat(64) });
    if (failure === "deadline") {
      let reads = 0;
      f.options.now = () => (reads++ ? 30001 : 0);
    }
    const result = await f.run();
    assert.equal(
      result.record.status,
      ["missing", "input"].includes(failure) ? "BLOCKED" : "FAIL",
      failure,
    );
    assert.ok(!f.calls.includes("release"), failure);
    assert.equal(result.record.reservation, "RETAINED");
    if (["missing", "input"].includes(failure))
      assert.ok(!f.calls.includes("park"));
    if (failure === "input")
      assert.deepEqual(result.record.missingInputs, [
        "contract.audit-domain.mach_port_kobject",
      ]);
  }
  assert.equal(
    sameDarwinIdentity(fixture().payload, {
      ...fixture().payload,
      startMicroseconds: 2,
    }),
    false,
  );
});

test("Darwin argument and expected-input contracts reject aliases and ambient authority", async () => {
  const f = fixture();
  for (const change of [
    { uid: 0 },
    { workspace: "/fixture/storage/../work" },
    {
      executable: {
        ...f.request.executable,
        path: "/fixture/storage/work/payload",
      },
    },
    { extra: true },
  ])
    assert.throws(() => normalizeDarwinLaunch({ ...f.request, ...change }));
  for (const args of [["\0"], ["\ud800"], ["a".repeat(4097)], new Array(1)])
    await assert.rejects(
      admitDarwinLaunch(
        f.request,
        args,
        darwinLaunchDigest(f.request, DARWIN_LITERAL_ARGUMENTS),
        f.effects,
        f.options,
      ),
    );
  assert.ok(!f.calls.includes("park"));
});

test("Darwin channel bounds frames and never acknowledges a helper after admission failure", async () => {
  const f = fixture();
  for (const failure of ["deadline", "oversized", "pipe", "close"]) {
    const child = new EventEmitter();
    child.pid = f.helper.pid;
    child.stdin = new PassThrough();
    child.stdout = new PassThrough();
    child.stdio = [child.stdin, child.stdout, null, new PassThrough()];
    let expire, finish;
    const helper = new Promise((resolve) => {
      finish = resolve;
    });
    const channel = darwinAdmissionChannel(child, () => helper, {
      schedule: (callback) => {
        expire = callback;
        return 1;
      },
      cancel: () => {},
    });
    const commands = [];
    child.stdin.on("data", (data) => commands.push(data.toString()));
    const rejected = assert.rejects(channel.ready, /admission unavailable/u);
    if (failure !== "close")
      child.stdout.write(
        JSON.stringify({ helper: f.helper, payload: null }) + "\n",
      );
    if (failure === "deadline") expire();
    if (failure === "oversized") child.stdout.emit("data", Buffer.alloc(4097));
    if (failure === "pipe") child.stdin.emit("error", new Error("closed"));
    if (failure === "close") channel.close();
    finish();
    await rejected;
    await helper;
    assert.deepEqual(commands, [], failure);
    assert.throws(() => channel.release());
    child.emit("close", 126, null);
    await channel.completion;
    for (const stream of [child.stdin, child.stdout, child.stdio[3]])
      stream.destroy();
  }
});

test("Darwin admission failure follows pending receipt writes and stops helper verification", async () => {
  const f = fixture(),
    child = new EventEmitter();
  child.pid = f.helper.pid;
  child.stdin = new PassThrough();
  child.stdout = new PassThrough();
  child.stdio = [child.stdin, child.stdout, null, new PassThrough()];
  let expire,
    finishWrite,
    enteredWrite,
    finishHelper,
    channel,
    inspections = 0;
  const writing = new Promise((resolve) => {
      enteredWrite = resolve;
    }),
    writeBarrier = new Promise((resolve) => {
      finishWrite = resolve;
    }),
    helperFinished = new Promise((resolve) => {
      finishHelper = resolve;
    });
  f.effects.persist = async (value) => {
    if (value.phase === "helper" && value.status === "RUNNING") {
      enteredWrite();
      await writeBarrier;
    }
    f.records.push(structuredClone(value));
  };
  f.effects.inspect = async () => {
    inspections++;
    throw new Error("Verification started after channel failure");
  };
  f.effects.launchParked = async (_, args, verified, onHelper) => {
    channel = darwinAdmissionChannel(
      child,
      async (value) => {
        try {
          await onHelper(value);
        } finally {
          finishHelper();
        }
      },
      {
        schedule: (callback) => {
          expire = callback;
          return 1;
        },
        cancel: () => {},
      },
    );
    child.stdout.write(
      JSON.stringify({ helper: f.helper, payload: null }) + "\n",
    );
    return channel;
  };
  const running = f.run();
  await writing;
  expire();
  finishWrite();
  const result = await running;
  await helperFinished;
  try {
    assert.equal(result.record.status, "FAIL");
    assert.equal(inspections, 0);
    assert.deepEqual(
      f.records.map(({ status }) => status),
      ["RUNNING", "RUNNING", "FAIL"],
    );
  } finally {
    child.emit("close", 126, null);
    await channel.completion;
    for (const stream of [child.stdin, child.stdout, child.stdio[3]])
      stream.destroy();
  }
});

test("Darwin Mach-O inspection excludes alternate loaders, rpaths and unsigned or wrong architectures", () => {
  const bytes = Buffer.alloc(96);
  for (const [offset, value] of [
    [0, 0xfeedfacf],
    [4, 0x01000007],
    [12, 2],
    [16, 2],
    [20, 48],
    [32, 0xe],
    [36, 32],
    [40, 12],
    [64, 0x1d],
    [68, 16],
    [72, 80],
    [76, 16],
  ])
    bytes.writeUInt32LE(value, offset);
  bytes.write("/usr/lib/dyld\0", 44);
  assert.equal(inspectDarwinMachO(bytes).loader, "/usr/lib/dyld");
  for (const [offset, value] of [
    [4, 0x0100000c],
    [32, 0x8000001c],
    [64, 0],
    [72, 200],
    [40, 0],
  ]) {
    const changed = Buffer.from(bytes);
    changed.writeUInt32LE(value, offset);
    assert.throws(() => inspectDarwinMachO(changed));
  }
  const lazy = Buffer.alloc(160);
  bytes.copy(lazy);
  for (const [offset, value] of [
    [16, 3],
    [20, 112],
    [72, 144],
    [80, 0x20],
    [84, 64],
    [88, 24],
  ])
    lazy.writeUInt32LE(value, offset);
  lazy.write("/usr/lib/libSystem.B.dylib\0", 104);
  assert.deepEqual(inspectDarwinMachO(lazy).libraries, [
    "/usr/lib/libSystem.B.dylib",
  ]);
  lazy.fill(0, 104, 144);
  lazy.write("/fixture/unreviewed.dylib\0", 104);
  assert.throws(() => inspectDarwinMachO(lazy));
  for (const command of [0x6, 0x9, 0x10]) {
    lazy.writeUInt32LE(command, 80);
    assert.throws(() => inspectDarwinMachO(lazy));
  }
});
