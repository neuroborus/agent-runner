import assert from "node:assert/strict";
import test from "node:test";
import {
  darwinPfAuthorityDigest,
  assertDarwinPfWindow,
  assertDarwinPfOwned,
  assertDarwinPfCounters,
  darwinPfExpectedRules,
  assertDarwinPfPreserved,
} from "./pf-kernel.js";
import { kernelPfFixture, stockPfFixture } from "./pf.fixture.js";
import { darwinPfRootDigest } from "./pf-preparation.js";
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
test("experiment PF graph transcripts require every child, ruleset and stable generation", () => {
  const read = kernelPfFixture({
    ...baseline,
    interfaces: [{ name: "lo0", skip: false }],
    graph: [
      { anchor: "", rules: [] },
      { anchor: "com.apple", rules: [] },
      {
        anchor: "com.apple/stock",
        rules: [
          { ...installed.graph[0].rules[0], set: 5, action: 11, call: "" },
        ],
      },
    ],
  });
  const observed = normalizeDarwinPfRead(read, "experiment");
  assert.equal(observed.graph[2].rules[0].set, 5);
  for (const mutate of [
    (value) => value.kernel.anchors[0].sets.pop(),
    (value) => value.kernel.anchors[2].sets[5].count++,
    (value) => value.graph.splice(1, 1),
    (value) => value.kernel.anchors[1].children.pop(),
    (value) => value.graph[2].rules[0].index++,
    (value) => (value.graph[2].rules[0].match.interface = null),
    (value) => (value.graph[2].rules[0].match.interface = 0),
    (value) => (value.graph[2].anchor = "com.apple/../stock"),
    (value) => (value.kernel.states.bytes = 1),
    (value) => (value.states = 1),
    (value) => (value.interfaces = []),
    (value) => (value.interfaces[0].flags = 0x100),
  ]) {
    const changed = structuredClone(read);
    mutate(changed);
    assert.throws(() => normalizeDarwinPfRead(changed, "experiment"));
  }
  const changed = structuredClone(observed);
  changed.kernel.anchors[2].sets[5].ticket++;
  assert.equal(
    darwinPfAuthorityDigest(observed),
    darwinPfAuthorityDigest(changed),
  );
  assert.throws(() => assertDarwinPfWindow(observed, changed));
  changed.kernel = observed.kernel;
  changed.graph[2].rules[0].ticket = "2";
  assert.equal(
    darwinPfAuthorityDigest(observed),
    darwinPfAuthorityDigest(changed),
  );
  assert.throws(() => assertDarwinPfWindow(observed, changed));
  changed.graph[2].rules[0].ticket = observed.graph[2].rules[0].ticket;
  changed.routesSha256 = "f".repeat(64);
  assertDarwinPfWindow(observed, changed);
  assert.equal(
    darwinPfAuthorityDigest(observed),
    darwinPfAuthorityDigest(changed),
  );
  assert.equal(darwinPfRootDigest(observed), darwinPfRootDigest(changed));
  for (const routesSha256 of [null, "", "invalid"]) {
    assert.throws(() => normalizeDarwinPfRead({ ...changed, routesSha256 }));
  }
  assert.notEqual(
    darwinPfRootDigest(installed),
    darwinPfRootDigest({ ...installed, routesSha256: changed.routesSha256 }),
  );
  assert.throws(() => normalizeDarwinPfRead(read, "reviewed"));
  assert.throws(() => normalizeDarwinPfRead(baseline, "experiment"));
});
test("experiment PF controls derive owned policy independently and attribute each counter to its generation", () => {
  const plan = {
    anchor: "native-poc/" + nonce,
    value: {
      request: { uid: 1001 },
      endpoints: ["inet", "inet6"].flatMap((family, i) =>
        ["tcp", "udp"].map((protocol, j) => ({
          family,
          protocol,
          clientPort: 41001 + i * 4 + j * 2,
          serverPort: 41002 + i * 4 + j * 2,
        })),
      ),
    },
  };
  const expected = darwinPfExpectedRules(plan);
  assert.equal(expected.length, 36);
  assert.deepEqual(
    expected.slice(0, 4).map((rule) => rule.match.direction),
    [2, 1, 2, 1],
  );
  assert.deepEqual(
    expected.slice(-4).map((rule) => rule.match.protocol),
    [6, 17, 6, 17],
  );
  const read = kernelPfFixture({
    ...installed,
    graph: [
      ...installed.graph,
      {
        anchor: plan.anchor,
        rules: expected.map((rule, i) => ({
          ...rule,
          set: 1,
          raw: i.toString(16).padStart(2, "0"),
        })),
      },
    ],
  });
  normalizeDarwinPfRead(read, "experiment");
  assertDarwinPfOwned(read, plan);
  const rules = read.graph.find((node) => node.anchor === plan.anchor).rules;
  const counters = rules.map((rule, index) => ({
    purpose: "experiment",
    anchor: plan.anchor,
    set: 1,
    ticket: 1,
    ruleTicket: "1",
    index,
    packets: "2",
    ruleSha256: digest(Buffer.from(rule.raw, "hex")),
    action: rule.action === 0 ? "permit" : "deny",
  }));
  assertDarwinPfCounters(counters, read, plan.anchor);
  for (const patch of [
    { ticket: 2 },
    { ruleTicket: "2" },
    { set: 5 },
    { index: 1 },
    { anchor: "com.apple" },
    { ruleSha256: hash },
    { packets: "18446744073709551616" },
  ]) {
    const changed = structuredClone(counters);
    Object.assign(changed[0], patch);
    assert.throws(() => assertDarwinPfCounters(changed, read, plan.anchor));
  }
  const changed = structuredClone(read);
  changed.graph.find((node) => node.anchor === plan.anchor).rules[0].match
    .uid++;
  assert.throws(() => assertDarwinPfOwned(changed, plan));
  assertDarwinPfOwned(kernelPfFixture(baseline), plan, true);
});
function fixture({
  purpose = "reviewed",
  writeFailure = false,
  uncertainReceiptFailure = false,
  baselineValue = baseline,
} = {}) {
  const experiment = purpose === "experiment";
  if (experiment) baselineValue = { ...baselineValue, active: false };
  let current = structuredClone(baselineValue),
    retirement = true;
  const phases = [],
    mutations = [],
    records = [];
  const input = {
    ...(experiment ? { purpose } : {}),
    context,
    [experiment ? "bindings" : "approval"]: {
      schemaVersion: 1,
      contextSha256: digest(JSON.stringify(context)),
      [experiment ? "bindingSha256" : "manifestSha256"]: hash,
      baselineSha256: darwinPfAuthorityDigest(
        experiment ? kernelPfFixture(baselineValue) : baselineValue,
      ),
      installedRootSha256: experiment ? null : rootSha,
      routesSha256: hash,
      loopbackSkip: true,
    },
    tool: { index: 0, cdhash: "d".repeat(40) },
    install: 1,
    restore: 2,
    reservation: 3,
    nonce,
  };
  const effects = {
    [experiment ? "verifyInputs" : "review"]: async (value) => ({
      ...(experiment ? { purpose } : {}),
      status: "MATCHED",
      contextSha256: value.contextSha256,
      [experiment ? "bindingSha256" : "manifestSha256"]:
        value[experiment ? "bindingSha256" : "manifestSha256"],
    }),
    read: async () =>
      experiment ? kernelPfFixture(current) : structuredClone(current),
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
  };
  const preparation = createDarwinPfPreparation(input, effects);
  return {
    input,
    effects,
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
test("experiment PF setup rejects altered root semantics despite an observed root pin", async () => {
  for (const patch of [
    { action: 1 },
    ...Object.entries({
      uid: 1002,
      protocol: 6,
      direction: 1,
      interface: "lo0",
      family: "inet",
      source: "127.0.0.1",
      destination: "::1",
      sourcePort: 41001,
      destinationPort: 41002,
      returns: true,
    }).map(([key, value]) => ({ match: { [key]: value } })),
  ]) {
    const f = fixture({ purpose: "experiment" }),
      write = f.effects.write;
    f.effects.write = async (...args) => {
      await write(...args);
      const changed = kernelPfFixture(installed),
        rule = changed.graph[0].rules[0];
      Object.assign(rule, patch, { match: { ...rule.match, ...patch.match } });
      f.change(changed);
    };
    await assert.rejects(f.preparation.prepare(), /Unverified/);
    assert.equal(f.records.at(-1).setup, "POSSIBLE");
    assert.equal(f.records.at(-1).reservation, "RETAINED");
    assert.equal(f.phases.includes("installed"), false);
  }
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
  const target = { ...identity, pidVersion: 2 },
    control = {
      creator: { ...identity, pid: 19, asid: 29 },
      target: { ...target, pid: 19, asid: 29 },
    },
    witness = {
      subject: identity,
      target,
      control,
      policySha256: hash,
      assetSha256: hash,
      imageSha256: hash,
      gitSha256: "b".repeat(64),
      status: 1,
    },
    exec = {
      version: 1,
      subject: target,
      creator: identity,
      target,
      controlCreator: control.creator,
      controlTarget: control.target,
      controlRetired: true,
      parent: null,
      policySha256: hash,
      assetSha256: hash,
      imageSha256: hash,
      inheritance: null,
      status: 1,
    },
    experimental = {
      ...authority,
      version: 2,
      subject: target,
      decisions: [0, 1, 1, 1],
      exec,
    };
  assert.deepEqual(
    normalizeDarwinAuthorityRead(
      experimental,
      target,
      object,
      "experiment",
      witness,
    ),
    experimental,
  );
  for (const changed of [
    { ...experimental, decisions: [0, 1, 1, 1, 1] },
    { ...experimental, decisions: [-1, 1, 1, 1] },
    { ...experimental, exec: { ...exec, status: -1 } },
    { ...experimental, exec: { ...exec, policySha256: "b".repeat(64) } },
    { ...experimental, exec: { ...exec, assetSha256: "b".repeat(64) } },
    { ...experimental, exec: { ...exec, subject: identity } },
    { ...experimental, exec: { ...exec, controlTarget: target } },
  ])
    assert.throws(() =>
      normalizeDarwinAuthorityRead(
        changed,
        target,
        object,
        "experiment",
        witness,
      ),
    );
  assert.throws(() =>
    normalizeDarwinAuthorityRead(experimental, target, object, "experiment"),
  );
  assert.throws(() =>
    normalizeDarwinAuthorityRead(
      { ...experimental, exec: { ...exec, status: -1 } },
      target,
      object,
      "experiment",
      { ...witness, status: -1 },
    ),
  );
  const worker = { ...target, pid: 21 },
    inherited = {
      ...experimental,
      subject: worker,
      exec: {
        ...exec,
        subject: worker,
        parent: target,
        inheritance: "posix-spawn-inherit-v1",
        imageSha256: witness.gitSha256,
      },
    };
  assert.deepEqual(
    normalizeDarwinAuthorityRead(
      inherited,
      worker,
      object,
      "experiment",
      witness,
    ),
    inherited,
  );
  for (const proof of [
    exec,
    { ...inherited.exec, parent: identity },
    { ...inherited.exec, inheritance: null },
  ])
    assert.throws(() =>
      normalizeDarwinAuthorityRead(
        { ...inherited, exec: proof },
        worker,
        object,
        "experiment",
        witness,
      ),
    );
  const hosted = { ...object, uid: 501, mode: 0o777 },
    installed = {
      ...authority,
      object: hosted,
      path: Buffer.from("/usr/lib/dyld").toString("hex"),
    };
  assert.deepEqual(
    normalizeDarwinAuthorityRead(
      installed,
      identity,
      hosted,
      "reviewed",
      undefined,
      "experiment",
    ),
    installed,
  );
  assert.throws(() =>
    normalizeDarwinAuthorityRead(installed, identity, hosted),
  );
  assert.throws(() =>
    normalizeDarwinAuthorityRead(
      { ...installed, path: authority.path },
      identity,
      hosted,
      "reviewed",
      undefined,
      "experiment",
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

test("experiment PF setup binds its journal and requires independent retirement without review fallback", async () => {
  const f = fixture({ purpose: "experiment" });
  // The controller owns its admitted purpose after construction, independently
  // of later caller changes to the declaration used to create it.
  f.input.purpose = "reviewed";
  assert.equal((await f.preparation.prepare()).status, "INSTALLED");
  f.retire(false);
  await assert.rejects(f.preparation.restore({}));
  assert.deepEqual(f.mutations, ["reserve", "install"]);
  assert.ok(
    f.records.every(
      (record) =>
        record.purpose === "experiment" &&
        record.bindingSha256 === hash &&
        !Object.hasOwn(record, "approvalSha256"),
    ),
  );
  f.input.purpose = "experiment";
  const legacy = { ...f.effects, review: f.effects.verifyInputs };
  delete legacy.verifyInputs;
  assert.throws(() => createDarwinPfPreparation(f.input, legacy));
  assert.throws(() =>
    createDarwinPfPreparation(
      { ...f.input, approval: f.input.bindings },
      f.effects,
    ),
  );
});

function stockLifecycle(fault = null) {
  const before = normalizeDarwinPfRead(
      stockPfFixture({ ...baseline, active: false }),
    ),
    rootRule = kernelPfFixture(installed).graph[0].rules[0],
    records = [],
    events = [];
  let current = structuredClone(before),
    reference = false,
    retired = true,
    installEffects = 0,
    restoreEffects = 0,
    completed = false;
  const input = {
    purpose: "experiment",
    context,
    nonce,
    tool: { index: 0, cdhash: "d".repeat(40) },
    install: 1,
    restore: 2,
    reservation: 3,
    bindings: {
      schemaVersion: 1,
      contextSha256: digest(JSON.stringify(context)),
      bindingSha256: hash,
      baselineSha256: darwinPfAuthorityDigest(before),
      installedRootSha256: null,
      routesSha256: hash,
      loopbackSkip: true,
    },
  };
  const effects = {
    verifyInputs: async () => ({
      purpose: "experiment",
      status: "MATCHED",
      contextSha256: input.bindings.contextSha256,
      bindingSha256: hash,
    }),
    read: async () => structuredClone(current),
    reserve: async () => events.push("reserve"),
    reservation: async () => {},
    persist: async (record) => {
      records.push(record);
      events.push(record.phase);
    },
    verifyRetirement: async () => {
      events.push("retirement");
      return retired;
    },
    recoverReference: async () => {
      events.push("original-operation");
      assert.ok(reference && retired);
    },
    write: async (_, __, ___, operation) => {
      assert.equal(
        records.at(-1).phase,
        operation === "install" ? "setup-possible" : "restore-possible",
      );
      events.push(operation);
      if (operation === "install") {
        installEffects++;
        reference = true;
        current.active = true;
        if (fault === "enabled") throw new Error("interrupted enable reply");
        const root = current.graph.find((node) => node.anchor === "");
        root.rules.push(structuredClone(rootRule));
        root.rules.sort(
          (a, b) => a.set - b.set || (a.call === "native-poc/*" ? -1 : 1),
        );
        current = normalizeDarwinPfRead(kernelPfFixture(current));
        current.kernel.anchors.find((node) => !node.anchor).sets[1].ticket = 2;
        if (fault === "attached")
          throw new Error("interrupted attachment reply");
        current.interfaces[0] = { name: "lo0", skip: false, flags: 0 };
        if (fault === "ready") throw new Error("lost installation reply");
      } else if (!completed) {
        restoreEffects++;
        current = structuredClone(before);
        current.kernel.anchors.find((node) => !node.anchor).sets[1].ticket = 3;
        completed = true;
        if (fault === "restore-reply")
          throw new Error("lost restoration reply");
      }
    },
  };
  return {
    before,
    input,
    effects,
    records,
    events,
    owner: () => createDarwinPfPreparation(input, effects),
    change: (mutate) => mutate(current),
    reference: (value) => {
      reference = value;
    },
    retired: (value) => {
      retired = value;
    },
    current: () => current,
    effectsCount: () => ({ install: installEffects, restore: restoreEffects }),
  };
}
test("experiment PF preserves the stock graph across routing changes and recovers without replay", async () => {
  for (const fault of [null, "enabled", "attached", "ready", "restore-reply"]) {
    const f = stockLifecycle(fault),
      read = f.effects.read,
      owner = f.owner();
    let routeReads = 0;
    f.effects.read = async () => ({
      ...(await read()),
      routesSha256: digest(`route-observation-${++routeReads}`),
    });
    if (["enabled", "attached", "ready"].includes(fault))
      await assert.rejects(owner.prepare());
    else {
      await owner.prepare();
      assertDarwinPfPreserved(f.before, f.current(), true);
      if (fault) await assert.rejects(owner.restore({}));
      else await owner.restore({});
    }
    const records = structuredClone(f.records);
    assert.equal((await f.owner().recover(records, {})).status, "RESTORED");
    assert.deepEqual(f.effectsCount(), { install: 1, restore: 1 });
    assertDarwinPfPreserved(f.before, f.current(), false, true);
    assert.equal(f.current().active, false);
    assert.equal(f.current().interfaces[0].skip, true);
    assert.ok(
      f.events.indexOf("retirement") < f.events.indexOf("original-operation"),
    );
    assert.equal(
      f.records.every(
        (record) =>
          record.purpose === "experiment" && record.schemaVersion === 2,
      ),
      true,
    );
    await f.owner().recover(structuredClone(f.records), {});
    assert.deepEqual(f.effectsCount(), { install: 1, restore: 1 });
    assert.ok(routeReads > 2);
    assert.notEqual(
      f.records[0].before.routesSha256,
      f.input.bindings.routesSha256,
    );
  }
});
test("PF recovery retains exclusion for competing authority, rule identity, generation or missing original operations", async () => {
  for (const mutate of [
    (value) => {
      value.graph.find(
        (node) => node.anchor === "com.apple/stock",
      ).rules[0].raw = "bf";
    },
    (value) => {
      value.graph.find(
        (node) => node.anchor === "com.apple/stock",
      ).rules[0].ticket = "99";
    },
    (value) => {
      value.kernel.anchors.find((node) => node.anchor === "com.apple/stock")
        .sets[1].ticket++;
    },
    (value) => {
      value.routesSha256 = "invalid";
    },
    (value) => {
      value.interfaces.push({ name: "en0", flags: 0, skip: false });
    },
    (value) => {
      value.states = 1;
    },
  ]) {
    const f = stockLifecycle("ready");
    await assert.rejects(f.owner().prepare());
    f.change(mutate);
    await assert.rejects(f.owner().recover(structuredClone(f.records), {}));
    assert.deepEqual(f.effectsCount(), { install: 1, restore: 0 });
  }
  for (const fault of ["reference", "retirement", "journal"]) {
    const f = stockLifecycle("enabled");
    await assert.rejects(f.owner().prepare());
    if (fault === "reference") f.reference(false);
    if (fault === "retirement") f.retired(false);
    if (fault === "journal") f.records[0].schemaVersion = 1;
    await assert.rejects(f.owner().recover(structuredClone(f.records), {}));
    assert.deepEqual(f.effectsCount(), { install: 1, restore: 0 });
  }
});

test("stock PF admission rejects unsupported selectors before reservation and preserves relocated foreign rule identities", async () => {
  for (const mutate of [
    (read) => {
      read.active = true;
    },
    (read) => {
      read.graph[0].rules[0].quick = true;
    },
    (read) => {
      read.graph[0].rules[0].action = 1;
    },
    (read) => {
      read.graph[0].rules[0].match.uid = 1002;
    },
    (read) => {
      read.graph[0].rules[0].call = "other/*";
    },
    (read) => {
      read.interfaces.push({ name: "en0", flags: 0x100, skip: true });
    },
  ]) {
    const f = stockLifecycle();
    f.change(mutate);
    // A matching observed pin cannot authorize unsupported baseline semantics.
    f.input.bindings.baselineSha256 = darwinPfAuthorityDigest(f.current());
    await assert.rejects(f.owner().prepare());
    assert.equal(f.events.includes("reserve"), false);
  }
  const before = normalizeDarwinPfRead(
      stockPfFixture({ ...baseline, active: false }),
    ),
    rule = before.graph[0].rules.find((rule) => rule.set === 1);
  rule.raw = Buffer.alloc(1040).toString("hex");
  const after = structuredClone(before),
    root = after.graph[0],
    shifted = root.rules.find((rule) => rule.set === 1),
    raw = Buffer.from(shifted.raw, "hex");
  raw.writeUInt32LE(1, 948);
  raw.writeUInt32LE(2, 128);
  shifted.raw = raw.toString("hex");
  shifted.index = 1;
  root.rules.splice(1, 0, kernelPfFixture(installed).graph[0].rules[0]);
  after.active = true;
  after.interfaces[0] = { name: "lo0", skip: false, flags: 0 };
  after.kernel.anchors[0].sets[1] = { ticket: 2, count: 2 };
  assertDarwinPfPreserved(before, after, true);
  raw[1000] = 1;
  shifted.raw = raw.toString("hex");
  assert.throws(() => assertDarwinPfPreserved(before, after, true));
  raw[1000] = 0;
  shifted.raw = raw.toString("hex");
  const child = before.graph.find((node) => node.anchor === "com.apple/stock")
      .rules[0],
    other = after.graph.find((node) => node.anchor === "com.apple/stock")
      .rules[0];
  child.call = other.call = "native-poc/*";
  child.raw = other.raw = Buffer.alloc(1040).toString("hex");
  assertDarwinPfPreserved(before, after, true);
  const childRaw = Buffer.from(other.raw, "hex");
  childRaw.writeUInt32LE(2, 128);
  other.raw = childRaw.toString("hex");
  assert.throws(() => assertDarwinPfPreserved(before, after, true));

  const restored = structuredClone(before);
  restored.kernel.anchors[0].sets[1].ticket += 2;
  assertDarwinPfPreserved(before, restored, false, true);
  const restoredRule = restored.graph[0].rules.find((rule) => rule.set === 1),
    restoredRaw = Buffer.from(restoredRule.raw, "hex");
  restoredRaw.writeUInt32LE(2, 128);
  restoredRule.raw = restoredRaw.toString("hex");
  assert.throws(() => assertDarwinPfPreserved(before, restored, false, true));
});

test("PF setup and normal restoration reject competing root generations before further effects", async () => {
  const f = stockLifecycle(),
    reserve = f.effects.reserve;
  f.effects.reserve = async () => {
    await reserve();
    f.change((read) => read.kernel.anchors[0].sets[1].ticket++);
  };
  await assert.rejects(f.owner().prepare());
  assert.deepEqual(f.effectsCount(), { install: 0, restore: 0 });
  const g = stockLifecycle(),
    owner = g.owner();
  await owner.prepare();
  g.change((read) => read.kernel.anchors[0].sets[1].ticket++);
  await assert.rejects(owner.restore({}));
  assert.deepEqual(g.effectsCount(), { install: 1, restore: 0 });
});
