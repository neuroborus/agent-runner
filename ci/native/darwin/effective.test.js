import assert from "node:assert/strict";
import test from "node:test";
import {
  createDarwinPfPreparation,
  createDarwinEffectiveReaders,
  normalizeDarwinAuthorityRead,
  normalizeDarwinBarrierRead,
  normalizeDarwinPfRead,
  buildDarwinPolicy,
} from "./index.js";
import { digest, darwinLaunchDigest } from "./protocol.js";

const hash = "a".repeat(64),
  nonce = "b".repeat(32);
const context = {
  candidateSha: "c".repeat(40),
  platform: "darwin",
  tier: "system",
  runId: "1",
  runAttempt: 1,
  jobBindingSha256: hash,
  executionId: "darwin.pf",
  closureSha256: hash,
  selectedSystemSha256: null,
};
const baseline = {
  active: true,
  states: 0,
  graph: [{ anchor: "", rules: [] }],
  interfaces: [{ name: "lo0", skip: true }],
  routesSha256: hash,
};
const installed = {
  ...baseline,
  graph: [
    {
      anchor: "",
      rules: [
        {
          set: 1,
          action: 0,
          quick: true,
          state: 0,
          call: "native-poc/*",
          raw: "00",
        },
      ],
    },
  ],
  interfaces: [{ name: "lo0", skip: false }],
};
const rootSha = digest(
  JSON.stringify({
    active: installed.active,
    root: installed.graph[0],
    interfaces: installed.interfaces,
    routesSha256: installed.routesSha256,
  }),
);
function fixture({
  writeFailure = false,
  uncertainReceiptFailure = false,
  baselineValue = baseline,
} = {}) {
  let current = structuredClone(baselineValue),
    retirement = true;
  const phases = [],
    mutations = [],
    records = [];
  const input = {
    context,
    approval: {
      schemaVersion: 1,
      contextSha256: digest(JSON.stringify(context)),
      manifestSha256: hash,
      baselineSha256: digest(JSON.stringify(baselineValue)),
      installedRootSha256: rootSha,
      routesSha256: hash,
      loopbackSkip: true,
    },
    tool: { index: 0, cdhash: "d".repeat(40) },
    install: 1,
    restore: 2,
    reservation: 3,
    nonce,
  };
  const preparation = createDarwinPfPreparation(input, {
    review: async (approval) => ({
      status: "MATCHED",
      contextSha256: approval.contextSha256,
      manifestSha256: approval.manifestSha256,
    }),
    read: async () => structuredClone(current),
    reserve: async () => {
      assert.equal(phases.at(-1), "reservation-possible");
      mutations.push("reserve");
    },
    reservation: async () => {},
    persist: async (record) => {
      assert.equal(JSON.stringify(record).includes("raw"), false);
      phases.push(record.phase);
      records.push(structuredClone(record));
      if (uncertainReceiptFailure && record.phase === "uncertain")
        throw new Error("private receipt failure");
    },
    write: async (_, __, ___, operation) => {
      assert.equal(
        phases.at(-1),
        operation === "install" ? "setup-possible" : "restore-possible",
      );
      mutations.push(operation);
      current = structuredClone(
        operation === "install"
          ? {
              ...installed,
              graph: [
                ...installed.graph,
                ...baselineValue.graph.filter((entry) => entry.anchor !== ""),
              ],
            }
          : baselineValue,
      );
      if (writeFailure) throw new Error("private tool output");
    },
    verifyRetirement: async () => retirement,
  });
  return {
    preparation,
    phases,
    mutations,
    records,
    change: (value) => {
      current = value;
    },
    retire: (value) => {
      retirement = value;
    },
  };
}
test("PF setup constructs without effects, persists effects and restores only retired owned setup", async () => {
  const f = fixture({
    baselineValue: {
      ...baseline,
      graph: [...baseline.graph, { anchor: "native-poc", rules: [] }],
    },
  });
  assert.deepEqual(f.phases, []);
  assert.deepEqual(f.mutations, []);
  assert.equal((await f.preparation.prepare()).status, "INSTALLED");
  assert.equal((await f.preparation.restore({})).status, "RESTORED");
  assert.deepEqual(f.mutations, ["reserve", "install", "restore-skip"]);
});
test("unsupported PF baseline cannot reserve or mutate", async () => {
  const f = fixture();
  f.change({ ...baseline, states: 1 });
  await assert.rejects(f.preparation.prepare(), /Unverified/);
  assert.deepEqual(f.mutations, []);
  assert.equal(f.phases.at(-1), "uncertain");
  assert.equal(f.records.at(-1).setup, "NOT_ADMITTED");
  assert.equal(f.records.at(-1).reservation, "NOT_ADMITTED");
  const foreign = fixture({
    baselineValue: {
      ...baseline,
      graph: [...baseline.graph, { anchor: "foreign", rules: [] }],
    },
  });
  await assert.rejects(foreign.preparation.prepare(), /Unverified/);
  assert.deepEqual(foreign.mutations, []);
  assert.equal(foreign.records.at(-1).setup, "NOT_ADMITTED");
  assert.equal(foreign.records.at(-1).reservation, "NOT_ADMITTED");
});
test("lost PF mutation acknowledgement retains possible effects and the reservation", async () => {
  const f = fixture({ writeFailure: true, uncertainReceiptFailure: true });
  let first;
  await assert.rejects(f.preparation.prepare(), (cause) => {
    first = cause;
    return cause.message === "Unverified Darwin PF preparation";
  });
  assert.equal(f.records.at(-1).setup, "POSSIBLE");
  assert.equal(f.records.at(-1).reservation, "RETAINED");
  assert.equal(
    JSON.stringify(f.records).includes("private tool output"),
    false,
  );
  await assert.rejects(f.preparation.restore({}), (cause) => cause === first);
  await assert.rejects(f.preparation.prepare(), (cause) => cause === first);
  assert.deepEqual(f.mutations, ["reserve", "install"]);
});
test("changed PF state and uncertain retirement retain installed exclusion", async () => {
  for (const mode of ["changed", "retirement"]) {
    const f = fixture();
    await f.preparation.prepare();
    if (mode === "changed")
      f.change({ ...installed, routesSha256: "e".repeat(64) });
    else f.retire(false);
    await assert.rejects(f.preparation.restore({}), /Unverified/);
    assert.deepEqual(f.mutations, ["reserve", "install"]);
    await assert.rejects(f.preparation.restore({}));
  }
});
test("effective reads reject truncated graphs, substituted bytes and changed subjects", () => {
  assert.throws(() => normalizeDarwinPfRead({ ...baseline, graph: [] }));
  const object = {
    identity: `1:2:3:4:100:0:${"d".repeat(32)}`,
    bytes: 4,
    uid: 0,
    gid: 0,
    mode: 0o400,
    directory: false,
  };
  const read = {
    object,
    sha256: digest("data"),
    hex: Buffer.from("data").toString("hex"),
  };
  assert.deepEqual(normalizeDarwinBarrierRead(read), read);
  assert.throws(() => normalizeDarwinBarrierRead({ ...read, hex: "00000000" }));
  const identity = {
    pid: 20,
    pidVersion: 1,
    uid: 1001,
    gid: 1002,
    ruid: 1001,
    rgid: 1002,
    svuid: 1001,
    svgid: 1002,
    auid: 1001,
    asid: 30,
    startSeconds: 100,
    startMicroseconds: 0,
  };
  const authority = {
    subject: identity,
    sandboxed: true,
    path: Buffer.from("/fixture/object").toString("hex"),
    object,
    aclSha256: hash,
    decisions: [0, 1, 1, 1, 1],
  };
  assert.deepEqual(
    normalizeDarwinAuthorityRead(authority, identity, object),
    authority,
  );
  assert.throws(() =>
    normalizeDarwinAuthorityRead(
      { ...authority, subject: { ...identity, pidVersion: 2 } },
      identity,
      object,
    ),
  );
});

test("Git snapshots rejoin held bytes and reject mixed metadata generations", async () => {
  const verifier = {
    pid: 10,
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
    startMicroseconds: 0,
  };
  const request = {
    schemaVersion: 1,
    candidateSha: context.candidateSha,
    nonce,
    uid: 1001,
    gid: 1002,
    custody: "/fixture/custody",
    storage: "/fixture/storage",
    workspace: "/fixture/storage/work",
    launcher: { path: "/fixture/custody/launcher", sha256: hash },
    executable: {
      path: "/fixture/storage/helper",
      sha256: hash,
      cdhash: "d".repeat(40),
    },
    policy: { path: "/fixture/custody/policy", sha256: hash },
    bindings: { system: hash, source: hash, closure: hash, policy: hash },
  };
  const input = {
    request,
    git: { path: "/fixture/storage/git", sha256: hash, cdhash: "d".repeat(40) },
    metadata: "/fixture/storage/metadata",
    hooks: "/fixture/storage/hooks",
    parent: context.candidateSha,
    reviewSha256: hash,
  };
  const values = {
    config:
      "[user]\n\tname = Fixture User\n\temail = fixture@example.invalid\n",
    HEAD: "ref: refs/heads/proof\n",
    "refs/heads/proof": `${input.parent}\n`,
  };
  const file = (name, bytes) => ({
    object: {
      identity: `1:2:3:${Object.keys(values).indexOf(name) + 4}:100:0:${"d".repeat(32)}`,
      bytes: Buffer.byteLength(bytes),
      uid: 0,
      gid: 0,
      mode: 0o400,
      directory: false,
    },
    sha256: digest(bytes),
    hex: Buffer.from(bytes).toString("hex"),
  });
  let substituted = false;
  const readers = createDarwinEffectiveReaders(
    {
      process: async () => verifier,
      barrier: async (_, name) => file(name, values[name]),
      tree: async (index) =>
        index === 1
          ? []
          : Object.entries(values).map(([name, bytes]) => {
              const { hex, ...observed } = file(
                name,
                substituted && name === "config" ? "changed\n" : bytes,
              );
              return { name, file: observed };
            }),
    },
    context,
    verifier,
  );
  const actual = await readers.gitSnapshot(input, 0, 1);
  assert.equal(actual.identity, "Fixture User <fixture@example.invalid>");
  assert.equal(actual.head, input.parent);
  await assert.rejects(
    readers.gitSnapshot(
      {
        ...input,
        request: {
          ...request,
          bindings: { ...request.bindings, closure: "e".repeat(64) },
        },
      },
      0,
      1,
    ),
    /Unverified/,
  );
  substituted = true;
  await assert.rejects(readers.gitSnapshot(input, 0, 1), /Unverified/);
});
test("Seatbelt observations require the exact acknowledged launch and complete held policy objects", async () => {
  const identity = (pid, uid = 0, gid = 0, asid = 0) => ({
    pid,
    pidVersion: 1,
    uid,
    gid,
    ruid: uid,
    rgid: gid,
    svuid: uid,
    svgid: gid,
    auid: uid,
    asid,
    startSeconds: 100,
    startMicroseconds: pid,
  });
  const verifier = identity(10),
    payload = identity(20, 1001, 1002, 30);
  const input = {
    request: {
      schemaVersion: 1,
      candidateSha: context.candidateSha,
      nonce,
      uid: 1001,
      gid: 1002,
      custody: "/fixture/custody",
      storage: "/fixture/storage",
      workspace: "/fixture/storage/work",
      launcher: { path: "/fixture/custody/launcher", sha256: hash },
      executable: {
        path: "/fixture/storage/helper",
        sha256: hash,
        cdhash: "d".repeat(40),
      },
      policy: { path: "/fixture/custody/policy", sha256: hash },
      bindings: { system: hash, source: hash, closure: hash, policy: hash },
    },
    profile: "read-only",
    disposable: true,
    metadata: "/fixture/storage/metadata",
    pointer: "/fixture/storage/work/.git",
    checkout: "/protected/checkout",
    configuration: "/protected/config",
    credentials: "/protected/credentials",
    runtime: [
      {
        path: "/fixture/storage/helper",
        sha256: hash,
        executable: true,
        mapped: true,
      },
    ],
    endpoints: [
      { family: "inet", protocol: "tcp", clientPort: 41001, serverPort: 41002 },
      { family: "inet", protocol: "udp", clientPort: 41003, serverPort: 41004 },
      {
        family: "inet6",
        protocol: "tcp",
        clientPort: 41005,
        serverPort: 41006,
      },
      {
        family: "inet6",
        protocol: "udp",
        clientPort: 41007,
        serverPort: 41008,
      },
    ],
    reviewSha256: hash,
  };
  const plan = buildDarwinPolicy(input);
  input.request.policy.sha256 = plan.seatbeltSha256;
  input.request.bindings.policy = plan.compositionSha256;
  const args = ["fixture"],
    record = {
      phase: "verify",
      candidateSha: context.candidateSha,
      nonce,
      requestSha256: darwinLaunchDigest(input.request, args),
      payload,
      helpers: [{ role: "launcher", identity: identity(40) }],
    };
  const paths = [
    input.request.custody,
    input.request.storage,
    input.request.workspace,
    input.metadata,
    input.pointer,
    input.checkout,
    input.configuration,
    input.credentials,
    input.runtime[0].path,
  ];
  const objects = paths.map((path, index) => ({
    path,
    index,
    identity: `1:2:3:${index + 4}:100:0:${"d".repeat(32)}`,
    decisions: [0, 1, 1, 1, 1],
    aclSha256: hash,
  }));
  let reads = 0,
    changed = false;
  const readers = createDarwinEffectiveReaders(
    {
      process: async (pid) => (pid === verifier.pid ? verifier : payload),
      helper: async () => ({ sha256: hash }),
      read: async () => {
        reads++;
        return Buffer.from(plan.seatbelt);
      },
      inspect: async (index) => ({
        identity: objects[index].identity,
        bytes: 0,
        uid: 0,
        gid: 0,
        mode: 0o700,
        directory: true,
      }),
      authority: async (_, index) => ({
        path: Buffer.from(paths[index]).toString("hex"),
        decisions: objects[index].decisions,
        aclSha256: changed ? "e".repeat(64) : hash,
      }),
    },
    context,
    verifier,
  );
  for (const phase of ["verify", "release"]) {
    const receipt = await readers.seatbelt(
      input,
      { ...record, phase },
      10,
      objects,
      args,
    );
    assert.equal(receipt.installed, true);
    assert.deepEqual(receipt.verifier, verifier);
    receipt.verifier.pid = 99;
  }
  const before = reads;
  for (const bad of [
    { ...record, candidateSha: "e".repeat(40) },
    { ...record, nonce: "e".repeat(32) },
    { ...record, requestSha256: hash },
    { ...record, phase: "park" },
  ])
    await assert.rejects(
      readers.seatbelt(input, bad, 10, objects, args),
      /Unverified/,
    );
  for (const change of [
    (value) => {
      value.request.candidateSha = "e".repeat(40);
    },
    (value) => {
      value.request.bindings.closure = "e".repeat(64);
    },
  ]) {
    const substituted = structuredClone(input);
    change(substituted);
    await assert.rejects(
      readers.seatbelt(substituted, record, 10, objects, args),
      /Unverified/,
    );
  }
  await assert.rejects(
    readers.seatbelt(input, record, 10, objects, []),
    /Unverified/,
  );
  assert.equal(reads, before);
  await assert.rejects(
    readers.seatbelt(input, record, 10, objects.slice(1), args),
    /Unverified/,
  );
  changed = true;
  await assert.rejects(
    readers.seatbelt(input, record, 10, objects, args),
    /Unverified/,
  );
});
