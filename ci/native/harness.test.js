import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { resolveOwnedProcessLauncher } from "../../src/agents/index.js";

import {
  aggregateNativeEvidence,
  hasNativeProcessEffects,
  CHECK_IDS,
  initializeNativeJob,
  isWindows2025Image,
  joinNativeArtifacts,
  nativeArtifactName,
  nativeCleanupFailure,
  normalizeNativeJob,
  normalizeNativeResult,
  PLATFORMS,
  PROVIDER_CHECK_IDS,
  recordNativeStage,
  recordNativeResults,
  recordNativeAdmission,
  renderNativeJob,
  renderNativeReport,
  renderPublicInputReport,
  PUBLIC_INPUT_REQUIREMENTS,
  resolveNativeDispatch,
  selectNativeArtifacts,
  SOURCE_FINDING_IDS,
  verifyPreparedPublicInputs,
  LINUX_PREREQUISITE_IDS,
  normalizeLinuxPrerequisites,
  linuxPrerequisiteEvidence,
} from "./index.js";
import {
  assessLinuxRetirement,
  createLinuxProtocolQueue,
  normalizeLinuxReceipt,
  runLinuxOwnershipCase,
  accessGrants,
  DENIAL_IDS,
  validateAccessObservation,
  recordAccessSetupFailure,
  validateCommitRequest,
  validateCommitEffect,
  validateCommitMetadata,
  prepareLinuxFixture,
  blockedLinuxPrerequisites,
  initialLinuxPreparation,
  linuxPreparationVersion,
  prepareLinuxBubblewrap,
  buildLinuxFileHelper,
  normalizeLinuxFileBuildPins,
  verifyLinuxFileElf,
  encodeLinuxFileRequest,
  normalizeLinuxFileMessage,
  runLinuxFileTransaction,
  retireLinuxFileStorage,
  inspectFixtureMounts,
  linuxFileSessionPolicy,
  normalizeLinuxFileRecovery,
  settleLinuxFileSessionFailure,
} from "./linux/index.js";

const CANDIDATE = "a".repeat(40);
const DIGEST = "b".repeat(64);

test("Linux declared interruptions cannot hide owner-settlement failures or expiry", async () => {
  for (const scenario of [
    "declared",
    "settlement-failed",
    "expired",
    "emergency",
    "undeclared",
  ]) {
    let now = 100;
    const completion = Promise.withResolvers();
    const events = [];
    const pending = settleLinuxFileSessionFailure(
      {
        interrupted: scenario !== "undeclared",
        emergencyCleanup: scenario === "emergency",
        deadline: 130,
      },
      {
        stop: () => events.push("stop"),
        settle() {
          events.push("settle");
          return completion.promise;
        },
        now: () => now,
      },
    );
    assert.deepEqual(events, ["stop", "settle"]);
    now = scenario === "expired" ? 130 : 120;
    if (scenario === "settlement-failed")
      completion.reject(new Error("Owner settlement deadline"));
    else completion.resolve();
    assert.equal(await pending, scenario !== "declared");
  }
});

test("Linux helper mount inspection excludes procfs without changing ordinary fixture requirements", async () => {
  const helper = {
    fileHelper: true,
    executable: "/fixture/helper",
    policy: {},
  };
  const ordinary = {
    executable: "/fixture/node",
    payload: "/fixture/payload",
    policy: { libraries: [] },
  };
  for (const scenario of [
    "helper",
    "helper-procfs",
    "helper-writable-code",
    "helper-substitute",
    "ordinary",
    "ordinary-missing-procfs",
  ]) {
    const fixture = scenario.startsWith("helper") ? helper : ordinary;
    const inputs = fixture.fileHelper
      ? [
          ["/proof/bin/file-helper", helper.executable],
          ["/anchor", "/fixture/anchor"],
        ]
      : [
          ["/proof/bin/node", ordinary.executable],
          ["/proof/payload.cjs", ordinary.payload],
          ["/output", "/fixture/anchor"],
        ];
    const mounts = [
      "1 0 0:1 / / rw - tmpfs tmpfs rw",
      ...inputs.map(
        ([target], index) =>
          `${index + 2} 1 0:2 / ${target} ${["/anchor", "/output"].includes(target) || scenario === "helper-writable-code" ? "rw" : "ro"} - ext4 fixture rw`,
      ),
    ];
    if (["helper-procfs", "ordinary"].includes(scenario))
      mounts.push("9 1 0:3 / /proc rw - proc proc rw");
    const observed = [];
    const fs = {
      async readFile(file) {
        assert.equal(file, "/proc/23/mountinfo");
        return mounts.join("\n");
      },
      async lstat(file, options) {
        assert.deepEqual(options, { bigint: true });
        observed.push(file);
        const index = inputs.findIndex(
          ([target, source]) =>
            file === `/proc/23/root${target}` || file === source,
        );
        assert.ok(index >= 0);
        return {
          dev: 3n,
          ino:
            BigInt(index + 1) +
            (scenario === "helper-substitute" && file.startsWith("/proc/")
              ? 1n
              : 0n),
        };
      },
    };
    if (["helper", "ordinary"].includes(scenario)) {
      await inspectFixtureMounts(23, fixture, "/fixture/anchor", fs);
      assert.equal(observed.length, inputs.length * 2);
    } else
      await assert.rejects(
        inspectFixtureMounts(23, fixture, "/fixture/anchor", fs),
      );
  }
});

test("Linux recovery keeps comparable policies separate from protected session identities", () => {
  const hash = (value) =>
    createHash("sha256").update(JSON.stringify(value)).digest("hex");
  const comparable = [],
    bindings = [];
  for (const nonce of [
    "11111111-1111-1111-1111-111111111111",
    "22222222-2222-2222-2222-222222222222",
  ]) {
    const policy = linuxFileSessionPolicy(DIGEST);
    const policyDigest = hash(policy);
    const anchorName = `file-${nonce}`;
    const binding = hash({ policyDigest, anchorName });
    comparable.push(policyDigest);
    bindings.push(binding);
    const native = {
      allocation: "1:2:3:4:10:0",
      leaf: "1:2:5:4:10:0",
      temporary: "1:2:6:4:10:0",
    };
    const recovery = {
      candidateSha: CANDIDATE,
      nonce,
      anchorName,
      receiptDigest: DIGEST,
      nativeAnchor: "1:2:1:4:10:0",
      nativeRecord: "barrier-0",
      native,
      status: "FAIL",
      interrupted: true,
    };
    const evidence = {
      candidateSha: CANDIDATE,
      executableDigest: DIGEST,
      receipt: {
        ...linuxReceipt(),
        caseId: "file-helper",
        nonce,
        policyDigest: binding,
      },
      admission: {
        schemaVersion: 1,
        candidateSha: CANDIDATE,
        nonce,
        anchorName,
        admission: "possible",
        policy,
        policyDigest,
        sessionPolicyDigest: binding,
      },
      ready: {
        candidateSha: CANDIDATE,
        type: "file",
        nonce,
        phase: "ready",
        anchor: recovery.nativeAnchor,
        allocation: null,
        leaf: null,
        temporary: null,
      },
      operation: {
        candidateSha: CANDIDATE,
        type: "file",
        nonce,
        phase: "prepared",
        anchor: recovery.nativeAnchor,
        ...native,
      },
    };
    const normalized = normalizeLinuxFileRecovery(recovery, evidence);
    assert.equal(normalized.status, "FAIL");
    assert.equal(normalized.interrupted, true);
    assert.ok(
      Object.isFrozen(normalized) && Object.isFrozen(normalized.native),
    );
    assert.ok(Object.isFrozen(policy) && Object.isFrozen(policy.namespaces));
    for (const [input, records] of [
      [{ ...recovery, candidateSha: "c".repeat(40) }, evidence],
      [{ ...recovery, native: { ...native, type: "cleanup" } }, evidence],
      [{ ...recovery, nativeRecord: "../operation-0" }, evidence],
      [
        recovery,
        { ...evidence, receipt: { ...evidence.receipt, policyDigest } },
      ],
      [
        recovery,
        {
          ...evidence,
          admission: {
            ...evidence.admission,
            policy: { ...policy, procfs: true },
          },
        },
      ],
      [
        recovery,
        { ...evidence, ready: { ...evidence.ready, anchor: "1:2:9:4:10:0" } },
      ],
      [
        recovery,
        {
          ...evidence,
          operation: { ...evidence.operation, temporary: "1:2:7:4:10:0" },
        },
      ],
      [
        recovery,
        {
          ...evidence,
          operation: { ...evidence.operation, phase: "finished" },
        },
      ],
    ])
      assert.throws(() => normalizeLinuxFileRecovery(input, records));
    native.temporary = "1:2:7:4:10:0";
    assert.equal(normalized.native.temporary, "1:2:6:4:10:0");
  }
  assert.equal(comparable[0], comparable[1]);
  assert.notEqual(bindings[0], bindings[1]);
});

test("Linux file protocol rejects malformed authority without releasing operations", async () => {
  const request = {
    type: "replace",
    allocation: "1:2:3:4:10:0",
    leaf: "1:2:5:4:10:0",
    temporary: null,
    bytes: "00ff",
  };
  let sent = 0;
  for (const invalid of [
    { ...request, path: "../value" },
    { ...request, leaf: null },
    { ...request, allocation: "1:2:0:4:10:0" },
    { ...request, bytes: "0" },
    { ...request, bytes: "ab".repeat(4097) },
    { ...request, type: "execute" },
  ]) {
    assert.throws(() => encodeLinuxFileRequest(invalid));
    const result = await runLinuxFileTransaction(invalid, {
      send: () => {
        sent++;
      },
    });
    assert.deepEqual(result, {
      status: "FAIL",
      exclusion: "RETAINED",
      message: null,
    });
  }
  assert.equal(sent, 0);
  const nonce = "11111111-1111-1111-1111-111111111111";
  for (const authority of [
    { nonce: "invalid", anchor: "1:2:1:4:10:0" },
    { nonce, anchor: null },
    { nonce, anchor: "1:2:1:18446744073709551616:10:0" },
  ]) {
    const result = await runLinuxFileTransaction(request, {
      ...authority,
      allocation: request.allocation,
      previousLeaf: request.leaf,
      temporary: null,
      send: () => {
        sent++;
      },
    });
    assert.equal(result.status, "FAIL");
    assert.equal(result.exclusion, "RETAINED");
    assert.equal(sent, 0);
  }
  const unparked = await runLinuxFileTransaction(
    {
      type: "continue",
      allocation: null,
      leaf: null,
      temporary: null,
      bytes: "",
    },
    {
      nonce,
      anchor: "1:2:1:4:10:0",
      allocation: null,
      previousLeaf: null,
      temporary: null,
      send: () => {
        sent++;
      },
    },
  );
  assert.equal(unparked.status, "FAIL");
  assert.equal(sent, 0);
  const message = {
    type: "file",
    nonce,
    phase: "complete",
    anchor: "1:2:1:4:10:0",
    allocation: "1:2:3:4:10:0",
    leaf: "1:2:5:4:10:0",
    temporary: null,
  };
  for (const invalid of [
    { ...message, nonce: "22222222-2222-2222-2222-222222222222" },
    { ...message, leaf: null },
    { ...message, phase: "exists", leaf: null },
    { ...message, allocation: "1:2:3:18446744073709551616:10:0" },
    {
      ...message,
      phase: "finished",
      allocation: null,
      leaf: null,
      temporary: message.leaf,
    },
    { ...message, phase: "removed" },
    { ...message, extra: true },
  ])
    assert.throws(() => normalizeLinuxFileMessage(invalid, nonce));
});

test("Linux allocation and recovery require an empty held-object state", async () => {
  const nonce = "11111111-1111-1111-1111-111111111111";
  const anchor = "1:2:1:9:10:0",
    allocation = "1:2:3:9:10:0",
    leaf = "1:2:5:9:10:0";
  for (const type of ["allocate", "recover"]) {
    const request = {
      type,
      allocation: type === "allocate" ? null : "1:2:3:4:10:0",
      leaf: type === "allocate" ? null : "1:2:5:4:10:0",
      temporary: null,
      bytes: "",
    };
    const message = {
      type: "file",
      nonce,
      anchor,
      phase: type === "allocate" ? "allocated" : "recovered",
      allocation: type === "allocate" ? "1:2:7:9:10:0" : allocation,
      leaf: type === "allocate" ? null : leaf,
      temporary: null,
    };
    for (const held of [false, true]) {
      let sent = 0;
      const result = await runLinuxFileTransaction(request, {
        nonce,
        anchor,
        allocation: held ? allocation : null,
        previousLeaf: held ? leaf : null,
        temporary: null,
        send: async () => {
          sent++;
        },
        receive: async () => message,
      });
      assert.equal(result.status, held ? "FAIL" : "PASS");
      assert.equal(result.exclusion, "RETAINED");
      assert.equal(sent, held ? 0 : 1);
      assert.equal(
        result.message?.allocation ?? null,
        held ? null : message.allocation,
      );
    }
  }
});

test("Linux publication accepts only complete publication or the known winner and retains protocol failures", async () => {
  const nonce = "11111111-1111-1111-1111-111111111111";
  const anchor = "1:2:1:4:10:0",
    allocation = "1:2:3:4:10:0";
  const winner = "1:2:5:4:10:0",
    pending = "1:2:6:4:10:0";
  const request = {
    type: "publish",
    allocation,
    leaf: null,
    temporary: null,
    bytes: "002a",
  };
  for (const scenario of [
    "published",
    "exists",
    "retained",
    "mismatch",
    "replaced-winner",
  ]) {
    const previousLeaf = scenario === "published" ? null : winner;
    const frame = (phase, leaf, temporary = null) => ({
      type: "file",
      nonce,
      phase,
      anchor,
      allocation,
      leaf,
      temporary,
    });
    const messages = [
      frame("prepared", previousLeaf, pending),
      ...(["published", "replaced-winner"].includes(scenario)
        ? [frame("published", pending), frame("complete", pending)]
        : scenario === "retained"
          ? [
              {
                type: "file",
                nonce,
                phase: "retained",
                anchor: null,
                allocation: null,
                leaf: null,
                temporary: null,
              },
            ]
          : [frame("exists", scenario === "mismatch" ? pending : winner)]),
    ];
    const events = [];
    const result = await runLinuxFileTransaction(request, {
      nonce,
      anchor,
      allocation,
      previousLeaf,
      temporary: null,
      send: async ({ type }) => {
        events.push(type);
      },
      receive: async () => messages.shift(),
      barrier: async ({ phase }) => {
        events.push(`ack:${phase}`);
      },
    });
    assert.equal(
      result.status,
      ["published", "exists"].includes(scenario) ? "PASS" : "FAIL",
    );
    assert.equal(result.exclusion, "RETAINED");
    assert.equal(
      result.message?.leaf ?? null,
      scenario === "published"
        ? pending
        : scenario === "exists"
          ? winner
          : null,
    );
    assert.deepEqual(events, [
      "publish",
      "ack:prepared",
      "continue",
      ...(scenario === "published" ? ["ack:published", "continue"] : []),
    ]);
    assert.equal(messages.length, scenario === "replaced-winner" ? 1 : 0);
  }
});

test("Linux file transactions retain their request, authority and acknowledgement bindings", async () => {
  const nonce = "11111111-1111-1111-1111-111111111111";
  const anchor = "1:2:1:4:10:0",
    allocation = "1:2:3:4:10:0",
    pending = "1:2:6:4:10:0";
  for (const scenario of ["request", "anchor", "acknowledgement"]) {
    const request = {
      type: "publish",
      allocation,
      leaf: null,
      temporary: null,
      bytes: "00",
    };
    const messages = [
      { phase: "prepared", leaf: null, temporary: pending },
      { phase: "published", leaf: pending, temporary: null },
      { phase: "complete", leaf: pending, temporary: null },
    ].map((message) => ({
      type: "file",
      nonce,
      anchor,
      allocation,
      ...message,
    }));
    const effects = {
      nonce,
      anchor,
      allocation,
      previousLeaf: null,
      temporary: null,
      async send(message) {
        if (scenario === "request" && message.type === "publish") {
          request.type = "finish";
          messages.splice(0, messages.length, {
            type: "file",
            nonce,
            anchor,
            phase: "finished",
            allocation,
            leaf: null,
            temporary: null,
          });
        }
        if (scenario === "acknowledgement" && message.type === "continue")
          message.type = "cleanup";
      },
      receive: async () => messages.shift(),
      async barrier() {
        if (scenario === "anchor") {
          effects.anchor = "1:2:9:4:10:0";
          for (const message of messages) message.anchor = effects.anchor;
        }
      },
    };
    assert.deepEqual(await runLinuxFileTransaction(request, effects), {
      status: "FAIL",
      exclusion: "RETAINED",
      message: null,
    });
  }
});

test("Linux replacement acknowledges both barriers and retains exclusion on identity mismatch", async () => {
  const nonce = "11111111-1111-1111-1111-111111111111";
  const allocation = "1:2:3:4:10:0",
    oldLeaf = "1:2:5:4:10:0",
    newLeaf = "1:2:6:4:10:0";
  const request = {
    type: "replace",
    allocation,
    leaf: oldLeaf,
    temporary: null,
    bytes: "0001",
  };
  for (const mismatch of [false, true]) {
    const events = [];
    const messages = [
      { phase: "prepared", leaf: oldLeaf, temporary: newLeaf },
      { phase: "published", leaf: newLeaf, temporary: null },
      {
        phase: "complete",
        leaf: mismatch ? oldLeaf : newLeaf,
        temporary: null,
      },
    ].map((value) => ({
      type: "file",
      nonce,
      anchor: "1:2:1:4:10:0",
      allocation,
      ...value,
    }));
    const reached = {
      prepared: Promise.withResolvers(),
      published: Promise.withResolvers(),
    };
    const acknowledged = {
      prepared: Promise.withResolvers(),
      published: Promise.withResolvers(),
    };
    const pending = runLinuxFileTransaction(request, {
      nonce,
      anchor: "1:2:1:4:10:0",
      allocation,
      previousLeaf: oldLeaf,
      temporary: null,
      send: async ({ type }) => {
        events.push(type);
      },
      receive: async () => messages.shift(),
      barrier: async ({ phase }) => {
        events.push(`entered:${phase}`);
        reached[phase].resolve();
        await acknowledged[phase].promise;
        events.push(`ack:${phase}`);
      },
    });
    await reached.prepared.promise;
    assert.deepEqual(events, ["replace", "entered:prepared"]);
    acknowledged.prepared.resolve();
    await reached.published.promise;
    assert.deepEqual(events, [
      "replace",
      "entered:prepared",
      "ack:prepared",
      "continue",
      "entered:published",
    ]);
    acknowledged.published.resolve();
    const result = await pending;
    assert.deepEqual(events, [
      "replace",
      "entered:prepared",
      "ack:prepared",
      "continue",
      "entered:published",
      "ack:published",
      "continue",
    ]);
    assert.equal(result.status, mismatch ? "FAIL" : "PASS");
    assert.equal(result.exclusion, "RETAINED");
    assert.equal(result.message?.leaf ?? null, mismatch ? null : newLeaf);
  }
  let sent = false;
  const result = await runLinuxFileTransaction(
    { ...request, leaf: newLeaf },
    {
      nonce,
      anchor: "1:2:1:4:10:0",
      allocation,
      previousLeaf: oldLeaf,
      temporary: null,
      send: async () => {
        sent = true;
      },
    },
  );
  assert.equal(result.status, "FAIL");
  assert.equal(sent, false);
  const released = [];
  const redirected = [
    { phase: "prepared", leaf: oldLeaf, temporary: newLeaf },
    { phase: "published", leaf: oldLeaf, temporary: null },
    { phase: "complete", leaf: oldLeaf, temporary: null },
  ].map((message) => ({
    type: "file",
    nonce,
    anchor: "1:2:1:4:10:0",
    allocation,
    ...message,
  }));
  const mutated = await runLinuxFileTransaction(request, {
    nonce,
    anchor: "1:2:1:4:10:0",
    allocation,
    previousLeaf: oldLeaf,
    temporary: null,
    send: async ({ type }) => {
      released.push(type);
    },
    receive: async () => redirected.shift(),
    barrier: async (message) => {
      message.temporary = oldLeaf;
    },
  });
  assert.deepEqual(mutated, {
    status: "FAIL",
    exclusion: "RETAINED",
    message: null,
  });
  assert.deepEqual(released, ["replace"]);
  for (const interrupted of ["prepared", "published"]) {
    const events = [];
    const messages = [
      { phase: "prepared", leaf: oldLeaf, temporary: newLeaf },
      { phase: "published", leaf: newLeaf, temporary: null },
      { phase: "complete", leaf: newLeaf, temporary: null },
    ].map((message) => ({
      type: "file",
      nonce,
      anchor: "1:2:1:4:10:0",
      allocation,
      ...message,
    }));
    const result = await runLinuxFileTransaction(request, {
      nonce,
      anchor: "1:2:1:4:10:0",
      allocation,
      previousLeaf: oldLeaf,
      temporary: null,
      send: async ({ type }) => events.push(type),
      receive: async () => messages.shift(),
      async barrier({ phase }) {
        if (phase === interrupted) throw new Error("Declared interruption");
      },
    });
    assert.deepEqual(result, {
      status: "FAIL",
      exclusion: "RETAINED",
      message: null,
    });
    assert.deepEqual(events, [
      "replace",
      ...(interrupted === "published" ? ["continue"] : []),
    ]);
  }
});

test("Linux file storage requires fresh retirement and preserves failed or uncertain cleanup", async () => {
  const retired = {
    status: "RETIRED",
    independent: true,
    emergencyCleanup: false,
  };
  const initial = {
    status: "PASS",
    storage: "RETAINED",
    exclusion: "RETAINED",
    settlement: {
      status: "RETAINED",
      independent: false,
      emergencyCleanup: false,
    },
  };
  for (const scenario of [
    "success",
    "live",
    "interrupted",
    "failed-operation",
    "emergency",
    "removed-but-live",
    "nonindependent",
    "cleanup-failed",
    "verification-failed",
  ]) {
    const events = [];
    const result = await retireLinuxFileStorage(
      ["interrupted", "failed-operation", "emergency"].includes(scenario)
        ? {
            ...initial,
            status: scenario === "emergency" ? "PASS" : "FAIL",
            settlement: {
              ...initial.settlement,
              emergencyCleanup: scenario !== "failed-operation",
            },
          }
        : scenario === "removed-but-live"
          ? { ...initial, storage: "REMOVED" }
          : initial,
      {
        async verify() {
          events.push("verify");
          if (scenario === "verification-failed") throw new Error("Uncertain");
          return ["live", "removed-but-live"].includes(scenario)
            ? initial.settlement
            : scenario === "nonindependent"
              ? { ...retired, independent: false }
              : retired;
        },
        async cleanup() {
          events.push("cleanup");
          if (scenario === "cleanup-failed")
            throw new Error("Substitute retained");
        },
      },
    );
    assert.equal(result.status, scenario === "success" ? "PASS" : "FAIL");
    assert.equal(
      result.storage,
      scenario === "success" ? "REMOVED" : "RETAINED",
    );
    assert.equal(
      result.exclusion,
      scenario === "success" ? "RELEASED" : "RETAINED",
    );
    assert.deepEqual(events, [
      "verify",
      ...(["success", "cleanup-failed"].includes(scenario) ? ["cleanup"] : []),
    ]);
    if (["interrupted", "emergency"].includes(scenario))
      assert.equal(result.settlement.emergencyCleanup, true);
    if (scenario === "cleanup-failed") {
      const retried = await retireLinuxFileStorage(result, {
        verify: async () => retired,
        cleanup: async () => events.push("later-cleanup"),
      });
      assert.equal(retried.status, "FAIL");
      assert.equal(retried.storage, "RETAINED");
      assert.equal(retried.exclusion, "RETAINED");
      assert.deepEqual(events, ["verify", "cleanup"]);
    }
  }
});

test("Linux recovery checks object identity in the new confined mount", async () => {
  const nonce = "11111111-1111-1111-1111-111111111111";
  const request = {
    type: "recover",
    allocation: "1:2:3:4:10:0",
    leaf: "1:2:5:4:10:0",
    temporary: "1:2:6:4:10:0",
    bytes: "",
  };
  for (const substituted of [false, true]) {
    const message = {
      type: "file",
      nonce,
      phase: "recovered",
      anchor: "1:2:1:9:10:0",
      allocation: "1:2:3:9:10:0",
      leaf: substituted ? "1:2:5:9:11:0" : "1:2:5:9:10:0",
      temporary: "1:2:6:9:10:0",
    };
    const result = await runLinuxFileTransaction(request, {
      nonce,
      anchor: message.anchor,
      allocation: null,
      previousLeaf: null,
      temporary: null,
      send: async () => {},
      receive: async () => message,
    });
    assert.equal(result.status, substituted ? "FAIL" : "PASS");
    assert.equal(result.exclusion, "RETAINED");
    assert.equal(
      result.message?.allocation ?? null,
      substituted ? null : message.allocation,
    );
  }
});

test("Linux file build rejects missing revision pins and dynamic ABI fallback", () => {
  const pins = {
    schemaVersion: 1,
    candidateSha: CANDIDATE,
    sourceSha256: DIGEST,
    compilerVersion: "13.2.0",
    inputs: [
      {
        source: "/usr/bin/x86_64-linux-gnu-gcc-13",
        target: "/usr/bin/x86_64-linux-gnu-gcc-13",
        sha256: DIGEST,
      },
    ],
  };
  assert.deepEqual(normalizeLinuxFileBuildPins(pins, CANDIDATE), pins);
  const loader = {
    source: "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
    target: "/lib64/ld-linux-x86-64.so.2",
    sha256: DIGEST,
  };
  const dynamicCompiler = { ...pins, inputs: [...pins.inputs, loader] };
  assert.deepEqual(
    normalizeLinuxFileBuildPins(dynamicCompiler, CANDIDATE),
    dynamicCompiler,
  );
  const redirectedInputs = [pins.inputs[0]];
  const redirectedPrototype = Object.create(Array.prototype);
  redirectedPrototype[Symbol.iterator] = function* () {
    yield pins.inputs[0];
    yield {
      source: "/usr/bin/extra-input",
      target: "/usr/bin/extra-input",
      sha256: DIGEST,
    };
  };
  Object.setPrototypeOf(redirectedInputs, redirectedPrototype);
  for (const invalid of [
    { ...pins, observedSha256: DIGEST },
    { ...pins, inputs: redirectedInputs },
    { ...pins, candidateSha: "c".repeat(40) },
    { ...pins, sourceSha256: "unknown" },
    { ...pins, compilerVersion: "14.2.0" },
    { ...pins, inputs: [] },
    { ...pins, inputs: [pins.inputs[0], pins.inputs[0]] },
    { ...pins, inputs: [...pins.inputs, { ...loader, source: loader.target }] },
    {
      ...pins,
      inputs: [
        ...pins.inputs,
        { ...loader, target: "/lib64/unreviewed-loader" },
      ],
    },
    { ...pins, inputs: [{ ...pins.inputs[0], target: "/usr/bin/../bin/gcc" }] },
  ])
    assert.throws(() => normalizeLinuxFileBuildPins(invalid, CANDIDATE));
  const nonString = { toString: () => CANDIDATE };
  assert.throws(() =>
    normalizeLinuxFileBuildPins(
      { ...pins, candidateSha: nonString },
      nonString,
    ),
  );
  // Only a structural ABI control; these bytes are never executable evidence.
  const elf = Buffer.alloc(192);
  Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]).copy(elf);
  elf.writeUInt16LE(2, 16);
  elf.writeUInt16LE(62, 18);
  elf.writeUInt32LE(1, 20);
  elf.writeBigUInt64LE(4096n, 24);
  elf.writeBigUInt64LE(64n, 32);
  elf.writeUInt16LE(64, 52);
  elf.writeUInt16LE(56, 54);
  elf.writeUInt16LE(2, 56);
  elf.writeUInt32LE(1, 64);
  elf.writeUInt32LE(5, 68);
  elf.writeBigUInt64LE(4096n, 80);
  elf.writeBigUInt64LE(192n, 96);
  elf.writeBigUInt64LE(192n, 104);
  elf.writeUInt32LE(0x6474e551, 120);
  assert.equal(verifyLinuxFileElf(elf).linkage, "static");
  for (const corrupt of [
    (value) => value.writeUInt16LE(183, 18),
    (value) => value.writeBigUInt64LE(192n, 32),
    (value) => value.writeUInt32LE(7, 68),
    (value) => value.writeUInt32LE(6, 68),
    (value) => value.writeBigUInt64LE(0n, 104),
    (value) => value.writeUInt32LE(0, 120),
  ]) {
    const invalid = Buffer.from(elf);
    corrupt(invalid);
    assert.throws(() => verifyLinuxFileElf(invalid));
  }
  for (const type of [2, 3]) {
    elf.writeUInt32LE(type, 120);
    assert.throws(() => verifyLinuxFileElf(elf));
  }
  elf.writeUInt32LE(0x6474e551, 120);
  elf.writeUInt32LE(1, 124);
  assert.throws(() => verifyLinuxFileElf(elf));
});

test("Linux helper build cannot admit the compiler with missing or altered reviewed inputs", async () => {
  for (const scenario of [
    "missing-pins",
    "source-mismatch",
    "source-bound",
    "input-mismatch",
  ]) {
    const source = Buffer.alloc(scenario === "source-bound" ? 65537 : 16, 1);
    const compiler = Buffer.from("synthetic compiler input");
    const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
    const pins = {
      schemaVersion: 1,
      candidateSha: CANDIDATE,
      sourceSha256: scenario === "source-mismatch" ? DIGEST : hash(source),
      compilerVersion: "13.2.0",
      inputs: [
        {
          source: "/usr/bin/x86_64-linux-gnu-gcc-13",
          target: "/usr/bin/x86_64-linux-gnu-gcc-13",
          sha256: hash(compiler),
        },
      ],
    };
    const copies = [];
    let reads = 0;
    let admitted = 0;
    await assert.rejects(
      buildLinuxFileHelper(
        CANDIDATE,
        "/fixture/build",
        "/usr/bin/bwrap",
        scenario === "missing-pins" ? null : pins,
        {
          platform: "linux",
          architecture: "x64",
          env: { CI: "true", GITHUB_ACTIONS: "true", ImageOS: "ubuntu24" },
          protect: () => {},
          fs: {
            realpath: async (file) => file,
            mkdir: async () => {},
            lstat: async () => ({
              isFile: () => true,
              nlink: 1,
              size: compiler.length,
              mode: 0o500,
            }),
            readFile: async (file) => {
              reads++;
              if (file === "/etc/os-release")
                return 'ID=ubuntu\nVERSION_ID="24.04"\n';
              return file.endsWith("/file-helper.c")
                ? source
                : Buffer.alloc(compiler.length);
            },
            writeFile: async (file, bytes, options) => {
              assert.deepEqual(options, { flag: "wx", mode: 0o400 });
              copies.push(file);
            },
          },
          run: async () => {
            admitted++;
            throw new Error("Unexpected compiler admission");
          },
        },
      ),
      /Missing or mismatched Linux helper build inputs/u,
    );
    assert.equal(admitted, 0);
    if (scenario === "missing-pins") assert.equal(reads, 0);
    assert.deepEqual(
      copies,
      scenario === "input-mismatch" ? ["/fixture/build/file-helper.c"] : [],
    );
  }
});

const passedPhase = () => ({
  status: "PASS",
  elapsedMs: 1,
  deadlineMs: 100,
  reason: null,
});

function publicFixture() {
  const source = Buffer.from("pub fn main() {}\n");
  const binary = Buffer.from("::warning::token=fixture-secret");
  const file = (path, kind, bytes) => ({
    path,
    kind,
    url: `https://example.org/source/${CANDIDATE}/${path}`,
    bytes: bytes.length,
    sha256: createHash("sha256").update(bytes).digest("hex"),
    gitBlobSha1:
      kind === "source"
        ? createHash("sha1")
            .update(`blob ${bytes.length}\0`)
            .update(bytes)
            .digest("hex")
        : null,
    archiveSha256: null,
  });
  return {
    candidateSha: CANDIDATE,
    reviewed: [
      {
        id: "fixture",
        version: "1.2.3",
        revision: CANDIDATE,
        findings: ["A-RELEASE-CLOSURE"],
        urls: ["https://example.org/releases/1.2.3"],
        priorArchive: null,
        files: [
          file("src/main.rs", "source", source),
          file("helper.bin", "binary", binary),
        ],
        license: "Synthetic fixture license; no candidate installation.",
        buildInputs: ["Synthetic source and helper; build provenance absent."],
        abi: ["Synthetic ABI is unproved."],
        setupPrivileges: [],
        missing: ["Independent release/build provenance."],
      },
    ],
    bytes: new Map([
      ["fixture/src/main.rs", source],
      ["fixture/helper.bin", binary],
    ]),
  };
}

test("prepared public inputs reject altered bytes, mismatched blob identities and missing members independently", () => {
  for (const mutate of [
    (input) =>
      input.bytes.set("fixture/src/main.rs", Buffer.from("altered source")),
    (input) => {
      input.reviewed[0].files[0].bytes++;
    },
    (input) => {
      input.reviewed[0].files[0].gitBlobSha1 = "0".repeat(40);
    },
  ]) {
    const input = publicFixture();
    mutate(input);
    const result = verifyPreparedPublicInputs(input);
    const file = result.bundles[0].files.find(
      (entry) => entry.path === "src/main.rs",
    );
    assert.equal(result.status, "FAIL");
    assert.equal(file.reason, "ALTERED");
    assert.equal(
      result.source.inspected.some(
        (entry) => entry.id === "fixture/src/main.rs",
      ),
      false,
    );
    assert.equal(
      result.bundles[0].files.find((entry) => entry.path === "helper.bin")
        .status,
      "PASS",
    );
  }
  const input = publicFixture();
  input.bytes.delete("fixture/src/main.rs");
  const result = verifyPreparedPublicInputs(input);
  assert.equal(result.bundles[0].byteStatus, "BLOCKED");
  assert.equal(
    result.bundles[0].files.find((entry) => entry.path === "src/main.rs")
      .reason,
    "MISSING",
  );
});

test("public provenance rejects self-asserted bindings, moving revisions, duplicate members and unresolved digests", () => {
  for (const mutate of [
    (input) => {
      input.reviewed[0].binding = "VERIFIED";
    },
    (input) => {
      input.reviewed[0].files[0].url =
        "https://example.org/source/main/src/main.rs";
    },
    (input) => {
      input.reviewed[0].files[0].kind = "manifest";
      input.reviewed[0].files[0].url =
        "https://example.org/source/main/src/main.rs";
    },
    (input) => {
      input.reviewed[0].files[0].path = "../outside.rs";
    },
    (input) => input.reviewed[0].files.push({ ...input.reviewed[0].files[0] }),
    (input) => input.bytes.set("fixture/unreviewed", Buffer.from("extra")),
  ]) {
    const input = publicFixture();
    mutate(input);
    assert.throws(() => verifyPreparedPublicInputs(input), {
      code: "ERR_INVALID_NATIVE_EVIDENCE",
    });
  }
  for (const mutate of [
    (input) => {
      input.reviewed[0].files[0].sha256 = null;
    },
    (input) => {
      input.reviewed[0].revision = null;
    },
    (input) => {
      input.reviewed[0].files[0].kind = "manifest";
      input.reviewed[0].revision = null;
    },
    (input) => {
      input.reviewed[0].files[0].url = null;
    },
  ]) {
    const input = publicFixture();
    mutate(input);
    const result = verifyPreparedPublicInputs(input);
    assert.equal(
      result.bundles[0].files.find((entry) => entry.path === "src/main.rs")
        .reason,
      "PROVENANCE",
    );
    assert.equal(
      result.source.inspected.some(
        (entry) => entry.id === "fixture/src/main.rs",
      ),
      false,
    );
  }
  const reviewed = structuredClone(PUBLIC_INPUT_REQUIREMENTS);
  reviewed.find(
    (bundle) => bundle.id === "srt-release",
  ).files[0].archiveSha256 = "0".repeat(64);
  assert.throws(
    () =>
      verifyPreparedPublicInputs({
        candidateSha: CANDIDATE,
        bytes: new Map(),
        reviewed,
      }),
    { code: "ERR_INVALID_NATIVE_EVIDENCE" },
  );
});

test("matching source and helper bytes cannot close release findings, authorize installation or expose candidate contents", () => {
  const input = publicFixture();
  input.reviewed[0].missing = [];
  const rendered = renderPublicInputReport(input);
  const bundle = rendered.report.publicInputs.bundles[0];
  assert.equal(bundle.byteStatus, "PASS");
  assert.equal(bundle.binding, "UNPROVED");
  assert.equal(bundle.admission, "BLOCKED");
  assert.equal(bundle.installation, "NOT_AUTHORIZED");
  assert.equal(rendered.report.decision, "BLOCKED");
  assert.ok(
    rendered.report.source.findings.every(
      (entry) => entry.status === "BLOCKED",
    ),
  );
  assert.ok(
    rendered.report.source.inspected.every(
      (entry) => !entry.complete && entry.binding === "UNPROVED",
    ),
  );
  assert.ok(rendered.report.source.missingInputs.length > 0);
  assert.equal(JSON.stringify(rendered).includes("fixture-secret"), false);
  input.bytes = new Map([...input.bytes].reverse());
  input.reviewed[0].files.reverse();
  assert.deepEqual(renderPublicInputReport(input), rendered);

  const incomplete = { ...structuredClone(input.reviewed[0]), id: "absent" };
  input.reviewed.push(incomplete);
  const independent = verifyPreparedPublicInputs(input);
  assert.equal(
    independent.bundles.find((entry) => entry.id === "fixture").byteStatus,
    "PASS",
  );
  assert.equal(
    independent.bundles.find((entry) => entry.id === "absent").byteStatus,
    "BLOCKED",
  );

  const retained = verifyPreparedPublicInputs({
    candidateSha: CANDIDATE,
    bytes: new Map(),
  });
  const release = retained.bundles.find((entry) => entry.id === "srt-release");
  assert.deepEqual(
    release.priorArchive,
    PUBLIC_INPUT_REQUIREMENTS.find((entry) => entry.id === "srt-release")
      .priorArchive,
  );
  assert.equal(release.byteStatus, "BLOCKED");
  assert.equal(
    retained.source.inspected.find(
      (entry) => entry.id === "srt-release/prior-archive",
    ).complete,
    false,
  );
});

test("Linux fixture profiles separate ordinary edits from fixed executor metadata authority", () => {
  const storage = {
    workspace: "/owned/disposable",
    metadata: "/protected/metadata",
    pointer: "/protected/pointer",
    git: "/protected/git",
    operation: "/protected/operation",
    hooks: "/protected/hooks",
    protocol: "/protected/protocol",
  };
  for (const profile of [
    "read-only",
    "workspace-write",
    "trusted-command",
    "commit",
  ]) {
    const grants = accessGrants(profile, storage);
    assert.deepEqual(
      grants.filter((grant) => grant.writable).map((grant) => grant.target),
      profile === "read-only"
        ? []
        : profile === "commit"
          ? ["/metadata"]
          : ["/workspace"],
    );
    assert.ok(
      grants
        .filter(
          (grant) =>
            grant.target !== "/workspace" && grant.target !== "/metadata",
        )
        .every((grant) => !grant.writable),
    );
  }
  assert.throws(() => accessGrants("unknown", storage), {
    code: "ERR_INVALID_NATIVE_EVIDENCE",
  });
  const subject = "test(fixture): record owned edit";
  assert.deepEqual(validateCommitRequest({ operation: "commit", subject }), {
    operation: "commit",
    subject,
  });
  for (const request of [
    { operation: "add", subject },
    { operation: "commit", subject: `${subject}\n\nBody` },
    {
      operation: "commit",
      subject: `${subject}\nCo-authored-by: Fixture <fixture@example.invalid>`,
    },
    { operation: "commit", subject, args: [] },
  ])
    assert.throws(() => validateCommitRequest(request), {
      code: "ERR_INVALID_NATIVE_EVIDENCE",
    });
});

test("Linux access denials require complete attempts, ready controls, isolated loopback and unchanged sentinels", () => {
  const value = {
    type: "access-result",
    profile: "workspace-write",
    inspection: true,
    edit: "permitted",
    loopback: true,
    denials: DENIAL_IDS.map((id) => ({
      id,
      code: ["git-add", "git-commit"].includes(id) ? "EXIT_128" : "EACCES",
      attempted: true,
      denied: true,
      positiveControl: true,
    })),
  };
  assert.equal(
    validateAccessObservation("workspace-write", value, true).length,
    DENIAL_IDS.length,
  );
  for (const mutate of [
    (entry) => {
      entry.denials.pop();
    },
    (entry) => {
      entry.denials[1] = { ...entry.denials[0] };
    },
    (entry) => {
      entry.denials[0].attempted = false;
    },
    (entry) => {
      entry.denials[0].denied = false;
    },
    (entry) => {
      entry.denials[0].positiveControl = false;
    },
    (entry) => {
      entry.denials[0].code = "EXIT_0";
    },
    (entry) => {
      entry.denials[0].code = "ETIMEDOUT";
    },
    (entry) => {
      entry.denials[0].code = "ENOENT";
    },
    (entry) => {
      entry.loopback = false;
    },
    (entry) => {
      entry.edit = "denied";
    },
  ]) {
    const input = structuredClone(value);
    mutate(input);
    assert.throws(
      () => validateAccessObservation("workspace-write", input, true),
      { code: "ERR_INVALID_NATIVE_EVIDENCE" },
    );
  }
  assert.throws(
    () => validateAccessObservation("workspace-write", value, false),
    { code: "ERR_INVALID_NATIVE_EVIDENCE" },
  );
  const readOnly = {
    ...value,
    profile: "read-only",
    edit: "denied",
    denials: [
      ...value.denials,
      {
        id: "content-write",
        code: "EROFS",
        attempted: true,
        denied: true,
        positiveControl: true,
      },
    ],
  };
  assert.equal(
    validateAccessObservation("read-only", readOnly, true).length,
    DENIAL_IDS.length + 1,
  );
});

test("Linux fixture setup failures remain failed without probe or retirement evidence", async () => {
  const { effects } = injectedLinuxFixture();
  effects.fs.realpath = async () => {
    throw prerequisiteError("ENOENT");
  };
  const result = blockedLinuxPrerequisites(
    reportingJob(),
    await diagnosedFixture(effects),
  ).results.find(
    (entry) =>
      entry.platform === "linux" && entry.checkId === "profile.read-only",
  );
  for (const [elapsed, reason] of [
    [1, "setup-failed"],
    [30001, "deadline"],
  ]) {
    const failed = recordAccessSetupFailure(result, elapsed);
    assert.equal(failed.status, "FAIL");
    assert.equal(failed.admission, "not-started");
    assert.equal(hasNativeProcessEffects(failed), false);
    assert.equal(
      nativeCleanupFailure({ ...reportingJob(), results: [failed] }),
      null,
    );
    assert.equal(failed.reason, reason);
    assert.equal(failed.phases.setup.status, "FAIL");
    assert.equal(failed.phases.probe.status, "NOT_RUN");
    assert.equal(failed.phases.cleanup.status, "NOT_RUN");
    assert.deepEqual(failed.observations, []);
    assert.equal(failed.settlement.status, "RETAINED");
    assert.equal(failed.settlement.independent, false);
  }
});

test("a later fixture failure preserves previous admitted-case observations and settlement", () => {
  const original = completeEvidence().results.find(
    (entry) => entry.platform === "linux" && entry.checkId === "network.deny",
  );
  for (const settlement of [
    original.settlement,
    { status: "RETAINED", independent: false, emergencyCleanup: true },
  ]) {
    const previous = {
      ...original,
      status: "FAIL",
      reason: "probe-failed",
      settlement,
      phases: {
        ...original.phases,
        probe: { ...passedPhase(), status: "FAIL", reason: "probe-failed" },
      },
    };
    const failed = recordAccessSetupFailure(previous, 1);
    assert.equal(failed.admission, "possible");
    assert.equal(failed.phases.setup.status, "FAIL");
    assert.deepEqual(failed.phases.probe, previous.phases.probe);
    assert.deepEqual(failed.phases.cleanup, previous.phases.cleanup);
    assert.deepEqual(failed.observations, previous.observations);
    assert.deepEqual(failed.settlement, settlement);
    const job = reportingJob();
    assert.equal(
      nativeCleanupFailure({
        ...job,
        results: linuxCaseRecords(job, [failed]),
      }),
      settlement.independent ? null : "unretired",
    );
  }
  const incomplete = recordAccessSetupFailure(original, 1);
  assert.equal(incomplete.phases.probe.status, "FAIL");
  assert.deepEqual(incomplete.observations, original.observations);
  assert.deepEqual(incomplete.settlement, original.settlement);
});

test("Linux fixed commit rejects extra refs, message authority, changed configuration or identity", () => {
  const before = {
    branch: "refs/heads/proof",
    head: CANDIDATE,
    identity: "Fixture Author <fixture@example.invalid>",
    config: "synthetic unchanged configuration",
    refs: [
      ["refs/heads/proof", CANDIDATE],
      ["refs/tags/witness", CANDIDATE],
    ],
  };
  const after = {
    ...before,
    head: "c".repeat(40),
    parent: before.head,
    message: "test(fixture): record owned edit\n",
    changed: "content.txt\n",
    content: "owned edit\n",
    status: "",
    author: before.identity,
    committer: before.identity,
    refs: [
      ["refs/heads/proof", "c".repeat(40)],
      ["refs/tags/witness", CANDIDATE],
    ],
  };
  assert.equal(validateCommitEffect(before, after), true);
  for (const mutate of [
    (entry) => {
      entry.refs[1][1] = entry.head;
    },
    (entry) => {
      entry.refs.push(["refs/heads/extra", entry.head]);
    },
    (entry) => {
      entry.message += "\nBody\n";
    },
    (entry) => {
      entry.changed += "extra.txt\n";
    },
    (entry) => {
      entry.config += "changed";
    },
    (entry) => {
      entry.author = "Other <other@example.invalid>";
    },
    (entry) => {
      entry.committer = "Other <other@example.invalid>";
    },
    (entry) => {
      entry.parent = entry.head;
    },
  ]) {
    const input = structuredClone(after);
    mutate(input);
    assert.throws(() => validateCommitEffect(before, input), {
      code: "ERR_INVALID_NATIVE_EVIDENCE",
    });
  }
  const metadata = [
    ["config", DIGEST, 0o644],
    ["objects/aa/initial", DIGEST, 0o444],
  ];
  const commitMetadata = [
    ...metadata,
    ["index", DIGEST, 0o644],
    ["objects/cc/" + "c".repeat(38), DIGEST, 0o444],
  ];
  const objects = [after.head, CANDIDATE, "d".repeat(40)];
  assert.equal(validateCommitMetadata(metadata, commitMetadata, objects), true);
  for (const extra of [
    ["objects/info/alternates", DIGEST, 0o644],
    ["hooks/extra", DIGEST, 0o500],
  ])
    assert.throws(
      () =>
        validateCommitMetadata(metadata, [...commitMetadata, extra], objects),
      { code: "ERR_INVALID_NATIVE_EVIDENCE" },
    );
  const replaced = structuredClone(commitMetadata);
  replaced[1][1] = "changed";
  assert.throws(() => validateCommitMetadata(metadata, replaced, objects), {
    code: "ERR_INVALID_NATIVE_EVIDENCE",
  });
});

function linuxReceipt() {
  const identity = {
    bootId: "11111111-1111-4111-8111-111111111111",
    startTicks: "44",
  };
  return {
    schemaVersion: 1,
    candidateSha: CANDIDATE,
    caseId: "cancel",
    nonce: "22222222-2222-4222-8222-222222222222",
    policyDigest: DIGEST,
    executableDigest: DIGEST,
    isolatedNamespace: true,
    hostSession: false,
    parentNamespaceId: "pid:[100]",
    init: {
      pid: 23,
      identity: { ...identity },
      namespaceId: "pid:[101]",
      nspid: [23, 1],
    },
    launcher: { pid: 22, identity: { ...identity, startTicks: "43" } },
    controller: { pid: 21, identity: { ...identity, startTicks: "42" } },
    admission: {
      processIdentity: { ...identity },
      namespaceId: "pid:[101]",
      launchCutoff: { ...identity },
      ancestryBaseline: [{ ...identity, startTicks: "42", pid: 21 }],
      controlGroup: DIGEST,
    },
  };
}

test("Linux helper receipts reuse retirement validation while ownership proof cases stay fixed", async () => {
  const receipt = { ...linuxReceipt(), caseId: "file-helper" };
  assert.deepEqual(normalizeLinuxReceipt(receipt), receipt);
  assert.equal(
    assessLinuxRetirement(receipt, {
      bootId: receipt.init.identity.bootId,
      observerNamespaceId: receipt.parentNamespaceId,
      procVisible: true,
      before: "absent",
      after: "absent",
    }).status,
    "RETIRED",
  );
  let invoked = false;
  await assert.rejects(
    runLinuxOwnershipCase(receipt.caseId, {
      now: () => {
        invoked = true;
        return 0;
      },
    }),
    { code: "ERR_INVALID_NATIVE_EVIDENCE" },
  );
  assert.equal(invoked, false);
});

test("Linux ownership release and faults follow protected admission and acknowledged readiness", async () => {
  const receipt = linuxReceipt();
  const log = [];
  const effect = (name, result) => async () => {
    log.push(name);
    return result;
  };
  const observation = {
    expected: "synthetic owned descendant",
    observed: "synthetic matched identity",
    matched: true,
    positiveControl: true,
    attempted: true,
    sentinelsUnchanged: true,
  };
  const effects = {
    now: () => log.length,
    admit: effect("persist", receipt),
    confirmReceipt: effect("inspect"),
    acknowledgeAdmission: effect("ack"),
    ready: effect("ready"),
    release: effect("release"),
    observe: effect("observe", [observation]),
    armFault: effect("arm-ack", {
      caseId: "cancel",
      nonce: receipt.nonce,
      armed: true,
    }),
    fireFault: effect("fault"),
    settle: effect("settle"),
    verify: effect("fresh-verify", {
      status: "RETIRED",
      independent: true,
      emergencyCleanup: false,
    }),
    cleanup: effect("cleanup"),
    emergencyStop: effect("emergency"),
  };
  const result = await runLinuxOwnershipCase("cancel", effects);
  assert.equal(result.status, "PASS");
  assert.deepEqual(log, [
    "persist",
    "inspect",
    "ack",
    "ready",
    "release",
    "observe",
    "arm-ack",
    "fault",
    "settle",
    "fresh-verify",
    "cleanup",
  ]);
  for (const boundary of [
    "admit",
    "confirmReceipt",
    "acknowledgeAdmission",
    "ready",
  ]) {
    log.length = 0;
    const failed = await runLinuxOwnershipCase("cancel", {
      ...effects,
      [boundary]: async () => {
        throw new Error("Synthetic admission failure");
      },
    });
    assert.equal(failed.status, "FAIL");
    assert.equal(failed.phases.setup.status, "FAIL");
    assert.ok(!log.includes("release") && !log.includes("fault"));
    assert.equal(failed.settlement.emergencyCleanup, true);
    assert.ok(log.includes("emergency"));
  }
  for (const acknowledgement of [
    { caseId: "cancel", nonce: receipt.nonce, armed: false },
    { caseId: "owner-loss", nonce: receipt.nonce, armed: true },
    { caseId: "cancel", nonce: "substitution", armed: true },
  ]) {
    log.length = 0;
    const failed = await runLinuxOwnershipCase("cancel", {
      ...effects,
      armFault: effect("bad-ack", acknowledgement),
    });
    assert.equal(failed.status, "FAIL");
    assert.ok(!log.includes("fault"));
    assert.equal(failed.settlement.emergencyCleanup, true);
  }
  for (const status of ["RETAINED", "RETIRED"]) {
    log.length = 0;
    const retained = await runLinuxOwnershipCase("cancel", {
      ...effects,
      verify: effect("fresh-verify", {
        status,
        independent: false,
        emergencyCleanup: false,
      }),
    });
    assert.equal(retained.status, "FAIL");
    assert.equal(retained.reason, "unretired");
    assert.ok(!log.includes("cleanup"));
  }
  const cleanupFailed = await runLinuxOwnershipCase("cancel", {
    ...effects,
    fireFault: async () => {
      throw new Error("Synthetic fault failure");
    },
    cleanup: async () => {
      throw new Error("Synthetic cleanup failure");
    },
  });
  assert.equal(cleanupFailed.status, "FAIL");
  assert.equal(cleanupFailed.phases.probe.reason, "probe-failed");
  assert.equal(cleanupFailed.phases.cleanup.status, "FAIL");
  assert.equal(cleanupFailed.phases.cleanup.reason, "cleanup-failed");
  assert.equal(cleanupFailed.settlement.status, "RETIRED");
  assert.equal(cleanupFailed.settlement.emergencyCleanup, true);
  log.length = 0;
  let now = 0;
  const expired = await runLinuxOwnershipCase("cancel", {
    ...effects,
    now: () => now,
    ready: async () => {
      log.push("ready");
      now = 10000;
    },
    observe: async () => {
      log.push("observe");
      now = 31000;
      return [observation];
    },
  });
  assert.equal(expired.status, "FAIL");
  assert.equal(expired.phases.probe.reason, "deadline");
  assert.ok(!log.includes("fault"));
  assert.equal(expired.settlement.emergencyCleanup, true);
});

test("Linux protocol keeps acknowledgements selective and failures terminal", async () => {
  let now = 0;
  const timers = new Map();
  const clock = {
    now: () => now,
    setTimer: (callback) => {
      timers.set(callback, callback);
      return callback;
    },
    clearTimer: (timer) => timers.delete(timer),
  };
  const queue = createLinuxProtocolQueue(100, clock);
  const command = queue.take((message) => message.type !== "admission-ack");
  queue.push({ type: "admission-ack" });
  assert.deepEqual(
    await queue.take((message) => message.type === "admission-ack"),
    { type: "admission-ack" },
  );
  queue.push({ type: "release" });
  assert.deepEqual(await command, { type: "release" });
  assert.equal(timers.size, 0);
  queue.push({ type: "ready" });
  const failure = new Error("Synthetic lost controller");
  queue.fail(failure);
  queue.push({ type: "admission-ack" });
  await assert.rejects(
    queue.take(() => true),
    failure,
  );
  const expired = createLinuxProtocolQueue(100, clock);
  const waiting = assert.rejects(
    expired.take(() => true),
    /CI protocol deadline/u,
  );
  now = 100;
  expired.push({ type: "ready" });
  await waiting;
  await assert.rejects(
    expired.take(() => true),
    /CI protocol deadline/u,
  );
  assert.equal(timers.size, 0);
});

test("Linux recovery requires complete namespace-init evidence and explicit procfs absence", () => {
  const receipt = linuxReceipt();
  const observed = {
    bootId: receipt.init.identity.bootId,
    observerNamespaceId: receipt.parentNamespaceId,
    procVisible: true,
    before: "absent",
    after: "absent",
  };
  assert.equal(assessLinuxRetirement(receipt, observed).status, "RETIRED");
  for (const change of [
    { bootId: "33333333-3333-4333-8333-333333333333" },
    { observerNamespaceId: "pid:[102]" },
    { procVisible: false },
    ...["live", "replaced", "mismatched", "inaccessible", null].flatMap(
      (state) => [{ before: state }, { after: state }],
    ),
  ])
    assert.equal(
      assessLinuxRetirement(receipt, { ...observed, ...change }).status,
      "RETAINED",
    );
  for (const mutate of [
    (value) => {
      value.hostSession = true;
    },
    (value) => {
      value.isolatedNamespace = false;
    },
    (value) => {
      value.init.nspid = [23, 2];
    },
    (value) => {
      value.init.namespaceId = value.parentNamespaceId;
    },
    (value) => {
      value.admission.processIdentity.startTicks = "45";
    },
    (value) => {
      value.admission.ancestryBaseline = [];
    },
    (value) => {
      value.admission.ancestryBaseline.push({
        ...value.admission.ancestryBaseline[0],
      });
    },
    (value) => {
      delete value.admission.controlGroup;
    },
    (value) => {
      value.admission.ancestryBaseline[0].startTicks = "45";
    },
  ]) {
    const value = structuredClone(receipt);
    mutate(value);
    assert.throws(() => normalizeLinuxReceipt(value), {
      code: "ERR_INVALID_NATIVE_EVIDENCE",
    });
  }
});

// Synthetic controller inputs only. A GO here tests the evidence predicate;
// it is never a native observation or an attestation of the real candidate.
function completeEvidence() {
  const source = {
    candidateSha: CANDIDATE,
    inspected: SOURCE_FINDING_IDS.map((id) => ({
      id,
      kind: "implementation",
      url: "https://example.org/source.js",
      revision: CANDIDATE,
      sha256: DIGEST,
      binding: "VERIFIED",
      complete: true,
      summary: "Synthetic reviewed implementation binding.",
    })),
    hypotheses: [],
    missingInputs: [],
    findings: SOURCE_FINDING_IDS.map((id) => ({
      id,
      status: "CLOSED",
      sourceIds: [id],
    })),
  };
  const results = [];
  const bindings = [];
  for (const [index, platform] of PLATFORMS.entries()) {
    for (const [offset, tier] of ["system", "provider"].entries()) {
      const provenance = {
        repository: "example/native-proof",
        workflow: "native-poc.yml",
        runId: "101",
        runAttempt: 1,
        jobId: String(1 + 2 * index + offset),
      };
      bindings.push({
        artifactId: String(101 + 2 * index + offset),
        candidateSha: CANDIDATE,
        platform: platform.os,
        tier,
        provenance: { ...provenance },
        conclusion: "success",
        authority: tier === "provider" ? "operator-protected" : "ordinary",
      });
      for (const checkId of CHECK_IDS.filter(
        (id) => PROVIDER_CHECK_IDS.includes(id) === (tier === "provider"),
      )) {
        const profile = checkId.startsWith("profile.")
          ? checkId.slice(8)
          : checkId === "git.fixed-commit"
            ? "commit"
            : "fixture";
        results.push({
          schemaVersion: 1,
          candidateSha: CANDIDATE,
          checkoutSha: CANDIDATE,
          platform: platform.os,
          declaredImage: platform.image,
          observed: {
            os: platform.os,
            image: platform.image,
            build: "synthetic-build",
            architecture: platform.architecture,
          },
          provenance: { ...provenance },
          checkId,
          profile,
          tier,
          dispatch: tier === "provider" ? "protected" : "native",
          implemented: true,
          versions: [{ name: "fixture", version: "1.0.0", sha256: DIGEST }],
          policy: { id: "fixture", sha256: DIGEST },
          phases: {
            setup: passedPhase(),
            probe: passedPhase(),
            cleanup: passedPhase(),
          },
          observations: [
            {
              expected: "permitted positive control and denied attempt",
              observed: "synthetic matching observation",
              matched: true,
              positiveControl: true,
              attempted: true,
              sentinelsUnchanged: true,
            },
          ],
          settlement: {
            status: "RETIRED",
            independent: true,
            emergencyCleanup: false,
          },
          status: "PASS",
          reason: null,
        });
      }
    }
  }
  return { candidateSha: CANDIDATE, source, results, bindings };
}

test("synthetic complete same-revision evidence passes the predicate independent of input order", () => {
  const input = completeEvidence();
  const before = structuredClone(input);
  const expected = aggregateNativeEvidence(input);
  assert.equal(expected.decision, "GO");
  assert.deepEqual(input, before);
  input.results.reverse();
  input.bindings.reverse();
  input.source.inspected.reverse();
  input.source.findings.reverse();
  assert.deepEqual(aggregateNativeEvidence(input), expected);
});

test("reporting alone cannot pass missing native or source evidence", () => {
  const input = completeEvidence();
  input.results = [];
  input.bindings = [];
  input.source.inspected = [];
  input.source.findings = [];
  const { report, summary, annotations } = renderNativeReport(input);
  assert.equal(report.decision, "BLOCKED");
  assert.equal(
    report.issues.filter(({ code }) => code === "MISSING").length,
    PLATFORMS.length * CHECK_IDS.length,
  );
  assert.equal(
    report.issues.filter(({ code }) => code === "SOURCE").length,
    SOURCE_FINDING_IDS.length,
  );
  assert.ok(summary.length < 8192);
  assert.equal(annotations.length, 32);
  assert.match(summary, /additional findings remain/u);
});

test("strict result validation rejects incomplete, inconsistent, and unretired PASS records", () => {
  for (const repair of [
    (r) => {
      r.schemaVersion = 2;
      r.admission = "not-started";
    },
    (r) => {
      r.schemaVersion = 2;
      r.admission = "unknown";
    },
    (r) => {
      delete r.phases.cleanup;
    },
    (r) => {
      r.rawOutput = "token=private-value";
    },
    (r) => {
      r.checkId = "unrecognized.check";
    },
    (r) => {
      r.versions.push({ ...r.versions[0] });
    },
    (r) => {
      r.observations = [];
    },
    (r) => {
      r.observations = Array(1);
    },
    (r) => {
      r.phases.probe.elapsedMs = 101;
    },
    (r) => {
      r.phases.setup.status = "FAIL";
      r.phases.setup.reason = "setup-failed";
    },
    (r) => {
      r.settlement.status = "RETAINED";
    },
    (r) => {
      r.settlement.independent = false;
    },
    (r) => {
      r.settlement.emergencyCleanup = true;
    },
    (r) => {
      r.observations[0].positiveControl = false;
    },
    (r) => {
      r.observations[0].attempted = false;
    },
    (r) => {
      r.observations[0].sentinelsUnchanged = false;
    },
    (r) => {
      r.implemented = false;
    },
    (r) => {
      r.phases.cleanup.elapsedMs = null;
    },
    (r) => {
      r.checkoutSha = "c".repeat(40);
    },
    (r) => {
      r.provenance.jobId = null;
    },
    (r) => {
      r.observed.build = "/private/fixture";
    },
    (r) => {
      r.versions[0].version = "x".repeat(513);
    },
  ]) {
    const input = completeEvidence();
    repair(input.results[0]);
    assert.throws(() => normalizeNativeResult(input.results[0]), {
      code: "ERR_INVALID_NATIVE_EVIDENCE",
    });
    const report = aggregateNativeEvidence(input);
    assert.equal(report.decision, "BLOCKED");
    assert.ok(report.issues.some(({ code }) => code === "INVALID"));
  }
});

test("duplicate, absent, unknown-platform, wrong-image, and mixed-revision evidence cannot yield GO", () => {
  for (const alter of [
    (i) => {
      i.results.push(structuredClone(i.results[0]));
    },
    (i) => {
      i.results.pop();
    },
    (i) => {
      i.bindings.push(structuredClone(i.bindings[0]));
    },
    (i) => {
      i.results[0].platform = "unknown";
    },
    (i) => {
      i.results[0].observed.architecture = "arm64";
    },
    (i) => {
      i.results[0].declaredImage = i.results[0].observed.image =
        "substituted-image";
    },
    (i) => {
      i.results[0].candidateSha = i.results[0].checkoutSha = "c".repeat(40);
    },
    (i) => {
      i.source.candidateSha = "c".repeat(40);
    },
    (i) => {
      i.bindings[0].candidateSha = "c".repeat(40);
    },
    (i) => {
      i.bindings[0].provenance.jobId = "901";
    },
    (i) => {
      i.bindings[0].conclusion = "cancelled";
    },
    (i) => {
      i.bindings.find(({ tier }) => tier === "provider").authority = "ordinary";
    },
    (i) => {
      i.results[0].observed.build = "different-build";
    },
    (i) => {
      i.results[0].policy.sha256 = "c".repeat(64);
    },
    (i) => {
      i.results[0].versions[0].version = "different-version";
    },
    (i) => {
      i.bindings = [];
    },
  ]) {
    const input = completeEvidence();
    alter(input);
    assert.equal(aggregateNativeEvidence(input).decision, "BLOCKED");
  }
});

test("revision text or publication bytes alone cannot close source findings", () => {
  for (const alter of [
    (i) => {
      i.source.inspected[0].complete = false;
    },
    (i) => {
      i.source.inspected[0].binding = "UNPROVED";
    },
    (i) => {
      i.source.inspected[0].kind = "publication";
    },
    (i) => {
      i.source.inspected[0].revision = null;
    },
    (i) => {
      i.source.findings[0].status = "BLOCKED";
    },
    (i) => {
      i.source.missingInputs.push({
        findingId: SOURCE_FINDING_IDS[0],
        summary: "Missing release/build binding.",
      });
    },
    (i) => {
      i.source.hypotheses.push({
        findingId: SOURCE_FINDING_IDS[0],
        summary: "Unproved ownership mechanism.",
      });
    },
  ]) {
    const input = completeEvidence();
    alter(input);
    assert.equal(aggregateNativeEvidence(input).decision, "BLOCKED");
  }
});

test("skipped and cancelled phases stay distinct from real probe or cleanup failure", () => {
  for (const status of ["SKIPPED", "CANCELLED", "FAIL"]) {
    const input = completeEvidence();
    const result = input.results[0];
    result.phases.probe = {
      status,
      elapsedMs: status === "FAIL" ? 100 : null,
      deadlineMs: 100,
      reason: status === "FAIL" ? "deadline" : status.toLowerCase(),
    };
    result.observations = [];
    result.status = status === "FAIL" ? "FAIL" : "BLOCKED";
    result.reason = result.phases.probe.reason;
    const report = aggregateNativeEvidence(input);
    assert.equal(report.decision, status === "FAIL" ? "NO_GO" : "BLOCKED");
    assert.ok(report.issues.some(({ code }) => code === "PROBE"));
    assert.equal(
      report.results.find(
        ({ checkId, platform }) =>
          checkId === result.checkId && platform === result.platform,
      ).phases.probe.status,
      status,
    );
  }
  const input = completeEvidence();
  input.results[0].status = "FAIL";
  input.results[0].reason = "unretired";
  input.results[0].settlement.emergencyCleanup = true;
  assert.equal(aggregateNativeEvidence(input).decision, "NO_GO");
  input.results[0].status = "BLOCKED";
  input.results[0].phases.cleanup = {
    status: "FAIL",
    elapsedMs: 100,
    deadlineMs: 100,
    reason: "cleanup-failed",
  };
  const report = aggregateNativeEvidence(input);
  assert.equal(report.decision, "NO_GO");
  assert.ok(report.issues.some(({ code }) => code === "INCONSISTENT"));
});

test("protected dispatch is required by default and cannot be replaced by a transport claim", () => {
  const input = completeEvidence();
  const result = input.results.find(({ tier }) => tier === "provider");
  result.tier = "system";
  result.dispatch = "model-free";
  const report = aggregateNativeEvidence(input);
  assert.equal(report.decision, "BLOCKED");
  assert.ok(report.issues.some(({ code }) => code === "DISPATCH"));
});

test("unimplemented checks retain explicit BLOCKED records and profile checks cannot borrow another profile", () => {
  const input = completeEvidence();
  const result = input.results[0];
  result.implemented = false;
  result.status = "BLOCKED";
  result.reason = "unimplemented";
  result.provenance.jobId = null;
  result.observations = [];
  for (const name of ["setup", "probe", "cleanup"])
    result.phases[name] = {
      status: "NOT_RUN",
      elapsedMs: null,
      deadlineMs: 100,
      reason: "unimplemented",
    };
  result.settlement = {
    status: "RETAINED",
    independent: false,
    emergencyCleanup: false,
  };
  const report = aggregateNativeEvidence(input);
  assert.equal(report.decision, "BLOCKED");
  assert.ok(
    report.results.some(
      (entry) => !entry.implemented && entry.reason === "unimplemented",
    ),
  );
  assert.ok(
    report.results.some(
      (entry) =>
        entry.provenance.jobId === null &&
        entry.phases.probe.status === "NOT_RUN",
    ),
  );
  const wrongProfile = completeEvidence().results.find(
    ({ checkId }) => checkId === "profile.read-only",
  );
  wrongProfile.profile = "workspace-write";
  assert.throws(() => normalizeNativeResult(wrongProfile), {
    code: "ERR_INVALID_NATIVE_EVIDENCE",
  });
});

test("diagnostic prose is bounded and never becomes Markdown or annotation instructions", () => {
  const input = completeEvidence();
  const diagnostic =
    'token=private-value password="private-password" Bearer private-bearer https://example.org/?key=private-query /private/fixture C:\\private\\fixture\n::error title=injected::private-instruction\u001b[31m\u202e';
  input.results[0].observations[0].observed = diagnostic;
  input.source.inspected[0].summary = diagnostic;
  input.source.missingInputs = [
    { findingId: SOURCE_FINDING_IDS[0], summary: diagnostic },
  ];
  const { report, summary, annotations } = renderNativeReport(input);
  const serialized = JSON.stringify(report);
  for (const value of [
    "private-value",
    "private-password",
    "private-bearer",
    "private-query",
    "/private/fixture",
    "C:\\private\\fixture",
  ])
    assert.ok(!serialized.includes(value));
  assert.ok(!summary.includes("private-instruction"));
  assert.ok(!annotations.join("\n").includes("injected"));
  const result = structuredClone(input.results[0]);
  result.observations[0].observed = "x".repeat(4096);
  assert.equal(
    normalizeNativeResult(result).observations[0].observed.length,
    512,
  );
  assert.ok(
    !/[\p{Cc}\p{Cf}]/u.test(
      normalizeNativeResult(input.results[0]).observations[0].observed,
    ),
  );
});

test("redaction covers isolated credentials, paths, and control-obfuscated assignments", () => {
  for (const diagnostic of [
    'password="private-value"',
    'token="private-value\nprivate-value"',
    "access_token=private-value",
    "refresh_token=private-value",
    "client_secret=private-value",
    "to\u001b[31mken=private-value",
    "to\u202eken=private-value",
    "Bearer private-value",
    "Basic private-value",
    "sk-private-value",
    "https://example.org/private-value",
    "/private-value/fixture",
    "C:\\private-value\\fixture",
    "::error title=private-value::injected",
  ]) {
    const result = completeEvidence().results[0];
    result.observations[0].observed = diagnostic;
    const normalized = normalizeNativeResult(result);
    assert.ok(!JSON.stringify(normalized).includes("private-value"));
  }
});

const ciContext = () => ({
  candidateSha: CANDIDATE,
  repository: "example/native-proof",
  runId: "101",
  runAttempt: 1,
  workflowSha: "c".repeat(40),
});

function reportingJob(platform = PLATFORMS[0], jobId = "1") {
  const { workflowSha, ...context } = ciContext();
  let job = initializeNativeJob({ ...context, platform: platform.os });
  job = recordNativeStage(job, "setup", passedPhase(), {
    checkoutSha: CANDIDATE,
    observed: {
      os: platform.os,
      image: platform.image,
      build: "synthetic-build",
      architecture: "x64",
    },
    provenance: { ...job.provenance, jobId },
    versions: [{ name: "node", version: "v24.21.0", sha256: DIGEST }],
  });
  job = recordNativeStage(job, "probe", passedPhase());
  return recordNativeStage(job, "cleanup", passedPhase());
}

function windowsImageObservation() {
  return {
    build: "10.0.26100",
    imageOS: "win25-vs2026",
    imageVersion: "20260925.250.1",
  };
}

test("Windows 2025 recognition accepts both reviewed identifiers within the original build and version bounds", () => {
  for (const imageOS of ["win25", "win25-vs2026"])
    for (const build of ["10.0.26100", "10.0.26100.1234"])
      for (const imageVersion of [
        "20260925.250.1",
        "0",
        "v1_A-0.",
        "v".repeat(128),
      ])
        assert.equal(
          isWindows2025Image({ build, imageOS, imageVersion }),
          true,
        );
});

test("Windows 2025 recognition rejects other images, suffixes, builds and malformed versions", () => {
  for (const rejected of [
    { imageOS: "win25-extra" },
    { imageOS: "win25-vs2026-extra" },
    { imageOS: "win25-vs2022" },
    { imageOS: "windows-2025" },
    { imageOS: "win22" },
    { imageOS: "ubuntu24" },
    { imageOS: "macos15" },
    { imageOS: "WIN25" },
    { imageOS: null },
    { imageOS: ["win25"] },
    { build: "10.0.20348" },
    { build: "10.0.26101" },
    { build: "10.0.26100-extra" },
    { build: "10.0.26100.1.2" },
    { build: "10.0.26100\n" },
    { build: null },
    { imageVersion: undefined },
    { imageVersion: null },
    { imageVersion: "" },
    { imageVersion: "v".repeat(129) },
    { imageVersion: "20260925/250" },
    { imageVersion: "20260925 250" },
    { imageVersion: "20260925.250.1\n" },
    { imageVersion: 20260925 },
  ])
    assert.equal(
      isWindows2025Image({ ...windowsImageObservation(), ...rejected }),
      false,
    );
});

test("reviewed Windows recognition retains setup identity gates and supplies no native proof", () => {
  const { workflowSha, ...context } = ciContext();
  const initial = initializeNativeJob({ ...context, platform: "win32" });
  const observation = windowsImageObservation();
  const setup = {
    checkoutSha: CANDIDATE,
    observed: {
      os: "win32",
      image: isWindows2025Image(observation) ? "windows-2025" : null,
      build: `${observation.build} image-${observation.imageVersion}`,
      architecture: "x64",
    },
    provenance: { ...initial.provenance, jobId: "3" },
    versions: [{ name: "node", version: "v24.21.0", sha256: DIGEST }],
  };
  const job = recordNativeStage(initial, "setup", passedPhase(), setup);
  assert.deepEqual(job.observed, setup.observed);
  assert.deepEqual(job.versions, setup.versions);
  assert.deepEqual(job.provenance, setup.provenance);
  const { report } = renderNativeJob(job);
  assert.equal(report.ciStages.setup.status, "PASS");
  assert.equal(report.decision, "BLOCKED");
  assert.equal(
    report.results.length,
    CHECK_IDS.length - PROVIDER_CHECK_IDS.length,
  );
  assert.ok(
    report.results.every(
      (result) =>
        !result.implemented &&
        result.status === "BLOCKED" &&
        result.observations.length === 0,
    ),
  );
  assert.deepEqual(
    report.source.findings.map(({ id }) => id),
    SOURCE_FINDING_IDS.filter((id) => id !== "A-MAC-OWNERSHIP").sort(),
  );
  assert.ok(report.source.findings.every(({ status }) => status === "BLOCKED"));
  assert.equal(report.bindings.length, 0);
  for (const rejected of [
    { checkoutSha: "d".repeat(40) },
    { observed: { ...setup.observed, architecture: "arm64" } },
    { observed: { ...setup.observed, image: "windows-2022" } },
    { provenance: { ...setup.provenance, jobId: null } },
    { versions: [{ ...setup.versions[0], version: "v24.20.0" }] },
    { versions: [{ ...setup.versions[0], sha256: null }] },
  ])
    assert.throws(
      () =>
        recordNativeStage(initial, "setup", passedPhase(), {
          ...setup,
          ...rejected,
        }),
      { code: "ERR_INVALID_NATIVE_EVIDENCE" },
    );
});

test("system dispatch is closed and cannot activate protected provider execution", () => {
  assert.deepEqual(resolveNativeDispatch(["--tier", "system"]), {
    tier: "system",
    stage: "all",
  });
  assert.equal(
    resolveNativeDispatch(["--tier", "system", "--stage", "cleanup"]).stage,
    "cleanup",
  );
  assert.equal(
    resolveNativeDispatch(["--tier", "system", "--stage", "prepare-linux"])
      .stage,
    "prepare-linux",
  );
  for (const args of [
    [],
    ["--tier", "provider"],
    ["--tier", "system", "--stage"],
    ["--tier", "system", "--stage", "unknown"],
    ["--tier", "system", "--retry", "all"],
  ])
    assert.throws(() => resolveNativeDispatch(args), {
      code: "ERR_INVALID_NATIVE_EVIDENCE",
    });
  const report = renderNativeJob(reportingJob()).report;
  assert.equal(report.decision, "BLOCKED");
  assert.equal(report.ciStatus, "PASS");
  assert.ok(
    report.results.every(
      ({ implemented, status, observations, settlement }) =>
        !implemented &&
        status === "BLOCKED" &&
        observations.length === 0 &&
        settlement.status === "RETAINED",
    ),
  );
});

test("initialized Windows placeholders report only their platform without phantom native settlement", () => {
  const { workflowSha, ...context } = ciContext();
  const job = initializeNativeJob({ ...context, platform: "win32" });
  const { report, summary, annotations } = renderNativeJob(job);
  assert.equal(report.scope, "win32");
  assert.equal(report.decision, "BLOCKED");
  assert.equal(report.ciStatus, "BLOCKED");
  assert.equal(report.results.length, 23);
  assert.ok(
    report.results.every(
      (result) =>
        result.platform === "win32" &&
        result.admission === "not-started" &&
        !hasNativeProcessEffects(result) &&
        result.status === "BLOCKED" &&
        result.settlement.status === "RETAINED",
    ),
  );
  assert.ok(
    report.issues.every(
      (issue) => issue.platform === null || issue.platform === "win32",
    ),
  );
  assert.ok(
    !report.issues.some((issue) =>
      ["SETUP", "PROBE", "CLEANUP", "SETTLEMENT"].includes(issue.code),
    ),
  );
  assert.equal(
    report.issues.filter((issue) => issue.code === "RESULT").length,
    23,
  );
  assert.equal(
    report.issues.filter((issue) => issue.code === "MISSING").length,
    6,
  );
  assert.equal(report.source.findings.length, 3);
  assert.deepEqual(report.linuxPrerequisites, []);
  assert.equal(nativeCleanupFailure(job), null);
  assert.match(summary, /\| win32 \| 0 \| 23 \|/u);
  assert.doesNotMatch(summary, /\| (?:linux|darwin) \|/u);
  assert.match(summary, /absent provider records 6/u);
  assert.match(summary, /Source closure: 0\/3/u);
  assert.match(annotations[0], /Native CI setup/u);
  assert.equal(annotations.length, 32);
  for (const schemaVersion of [1, 2, 3]) {
    const legacy = { ...reportingJob(PLATFORMS[2], "3"), schemaVersion };
    delete legacy.unrecordedAdmission;
    if (schemaVersion < 3) delete legacy.linuxPrerequisites;
    if (schemaVersion === 1) delete legacy.results;
    const historical = renderNativeJob(legacy).report;
    assert.equal(historical.ciStatus, "PASS");
    assert.equal(historical.decision, "BLOCKED");
    assert.equal(
      historical.issues.filter((issue) => issue.code === "SETTLEMENT").length,
      23,
    );
    const pending = {
      ...legacy,
      stages: {
        ...legacy.stages,
        cleanup: {
          status: "NOT_RUN",
          elapsedMs: null,
          deadlineMs: 30000,
          reason: "missing-input",
        },
      },
    };
    assert.throws(() => recordNativeStage(pending, "cleanup", passedPhase()), {
      code: "ERR_INVALID_NATIVE_EVIDENCE",
    });
  }
  const actions = report.issues.filter((issue) => issue.code === "RESULT");
  assert.match(
    actions.find((issue) => issue.checkId === "ownership.admission").message,
    /suspended two-hop admission/u,
  );
  assert.match(
    actions.find((issue) => issue.checkId === "files.private").message,
    /no file helper is admitted/u,
  );
  assert.match(
    actions.find((issue) => issue.checkId === "audit.release").message,
    /release\/build/u,
  );
  const mac = renderNativeJob(reportingJob(PLATFORMS[1], "2")).report;
  assert.ok(
    mac.results.every(
      (result) => !result.implemented && result.status === "BLOCKED",
    ),
  );
  assert.match(
    mac.issues.find(
      (issue) =>
        issue.code === "RESULT" && issue.checkId === "ownership.owner-loss",
    ).message,
    /recovered retirement.*Mach\/service/u,
  );
});

test("a scoped report cannot narrow the fixed aggregate acceptance inventory", () => {
  const complete = completeEvidence();
  assert.equal(aggregateNativeEvidence(complete).decision, "GO");
  for (const { os } of PLATFORMS) {
    const { report } = renderNativeReport(complete, { platform: os });
    assert.equal(report.decision, "BLOCKED");
    assert.equal(report.scope, os);
    assert.equal(report.results.length, CHECK_IDS.length);
    assert.ok(report.results.every((result) => result.platform === os));
    const narrowed = {
      ...complete,
      results: complete.results.filter((result) => result.platform === os),
      bindings: complete.bindings.filter((binding) => binding.platform === os),
    };
    const aggregate = aggregateNativeEvidence(narrowed);
    assert.equal(aggregate.decision, "BLOCKED");
    assert.equal(
      aggregate.issues.filter((issue) => issue.code === "MISSING").length,
      2 * CHECK_IDS.length,
    );
  }
});

function pendingNativeJob() {
  const job = reportingJob();
  const notRun = {
    status: "NOT_RUN",
    elapsedMs: null,
    deadlineMs: 30000,
    reason: "missing-input",
  };
  return {
    ...job,
    stages: { ...job.stages, probe: { ...notRun }, cleanup: { ...notRun } },
  };
}

// The real producer returns every implemented case, including explicit records
// for cases never admitted. Keep isolated attempted-case fixtures equally clear.
function linuxCaseRecords(job, results) {
  const { results: blocked } = blockedLinuxPrerequisites(job, {
    schemaVersion: 1,
    status: "BLOCKED",
    failedPrerequisite: LINUX_PREREQUISITE_IDS[0],
    checks: LINUX_PREREQUISITE_IDS.map((id, index) => ({
      id,
      status: index === 0 ? "BLOCKED" : "NOT_RUN",
      diagnosis: index === 0 ? "unverifiable" : null,
      observation: {
        errno: null,
        exitCode: null,
        signal: null,
        timedOut: null,
      },
    })),
  });
  return [
    ...blocked.filter(
      (result) => !results.some((entry) => entry.checkId === result.checkId),
    ),
    ...results,
  ];
}

test("known pre-admission fixture failures preserve setup FAIL while probe and cleanup stay NOT_RUN", () => {
  const job = pendingNativeJob();
  const pending = renderNativeJob(job).report.results.find(
    (result) => result.checkId === "profile.read-only",
  );
  const failed = recordAccessSetupFailure({ ...pending, implemented: true }, 1);
  let recorded = recordNativeResults(job, [failed]);
  assert.equal(nativeCleanupFailure(recorded), null);
  recorded = recordNativeStage(recorded, "probe", {
    ...passedPhase(),
    status: "FAIL",
    reason: "probe-failed",
  });
  recorded = recordNativeStage(recorded, "cleanup", passedPhase());
  const { report } = renderNativeJob(recorded);
  assert.equal(report.decision, "NO_GO");
  assert.equal(report.ciStatus, "FAIL");
  assert.deepEqual(
    report.results.find((result) => result.checkId === failed.checkId),
    failed,
  );
  assert.equal(failed.phases.setup.status, "FAIL");
  assert.equal(failed.phases.probe.status, "NOT_RUN");
  assert.equal(failed.phases.cleanup.status, "NOT_RUN");
  assert.equal(failed.settlement.status, "RETAINED");
  assert.ok(
    report.issues.some(
      (issue) => issue.code === "SETUP" && issue.checkId === failed.checkId,
    ),
  );
  assert.ok(
    !report.issues.some((issue) =>
      ["PROBE", "CLEANUP", "SETTLEMENT"].includes(issue.code),
    ),
  );
  for (const phase of ["probe", "cleanup"]) {
    const conflicting = structuredClone(failed);
    conflicting.phases[phase].reason = "unretired";
    const possible = recordNativeResults(job, [conflicting]);
    assert.equal(hasNativeProcessEffects(possible.results[0]), true);
    assert.equal(nativeCleanupFailure(possible), "unretired");
    assert.throws(() => recordNativeStage(possible, "cleanup", passedPhase()), {
      code: "ERR_INVALID_NATIVE_EVIDENCE",
    });
  }
});

test("missing observations, labels and conflicting non-admission cannot erase possible process effects", () => {
  const job = pendingNativeJob();
  const pending = renderNativeJob(job).report.results.find(
    (result) => result.checkId === "launch.argv",
  );
  const legacy = { ...pending, schemaVersion: 1 };
  delete legacy.admission;
  for (const mutate of [
    (result) => {
      result.admission = "possible";
    },
    (result) => {
      result.reason = "unretired";
    },
    (result) => {
      result.policy = { id: "fixture", sha256: DIGEST };
    },
    (result) => {
      result.observations = completeEvidence().results[0].observations;
    },
    (result) => {
      result.phases.setup = passedPhase();
    },
    ...["setup", "probe", "cleanup"].map((phase) => (result) => {
      result.phases[phase].reason = "unretired";
    }),
    (result) => {
      result.phases.probe.elapsedMs = 1;
    },
    (result) => {
      result.phases.cleanup = passedPhase();
    },
    (result) => {
      result.settlement.status = "UNVERIFIABLE";
    },
    (result) => {
      result.settlement.emergencyCleanup = true;
    },
    (result) => {
      Object.assign(result, legacy);
      delete result.admission;
    },
  ]) {
    const raw = structuredClone(pending);
    mutate(raw);
    const result = normalizeNativeResult(raw);
    assert.equal(hasNativeProcessEffects(result), true);
    const report = aggregateNativeEvidence({
      candidateSha: CANDIDATE,
      source: completeEvidence().source,
      results: [result],
      bindings: [],
    });
    assert.equal(report.decision, "BLOCKED");
    assert.ok(
      report.issues.some(
        (issue) =>
          issue.code === "SETTLEMENT" && issue.checkId === result.checkId,
      ),
    );
    if (result.admission === "not-started")
      assert.ok(report.issues.some((issue) => issue.code === "INCONSISTENT"));
  }
});

test("persisted possible admission retains settlement obligations when a controller produces no result", () => {
  const pending = pendingNativeJob();
  assert.throws(
    () => normalizeNativeJob({ ...pending, unrecordedAdmission: "unknown" }),
    { code: "ERR_INVALID_NATIVE_EVIDENCE" },
  );
  const started = recordNativeAdmission(pending);
  assert.equal(started.unrecordedAdmission, "possible");
  assert.throws(() => recordNativeAdmission(started), {
    code: "ERR_INVALID_NATIVE_EVIDENCE",
  });
  assert.throws(
    () =>
      recordNativeAdmission(
        initializeNativeJob({
          candidateSha: CANDIDATE,
          platform: "linux",
          repository: "example/native-proof",
          runId: "101",
          runAttempt: 1,
        }),
      ),
    { code: "ERR_INVALID_NATIVE_EVIDENCE" },
  );
  const recovered = normalizeNativeJob(JSON.parse(JSON.stringify(started)));
  assert.equal(nativeCleanupFailure(recovered), "unretired");
  assert.throws(() => recordNativeStage(recovered, "cleanup", passedPhase()), {
    code: "ERR_INVALID_NATIVE_EVIDENCE",
  });
  const { report } = renderNativeJob(recovered);
  assert.equal(report.decision, "BLOCKED");
  assert.equal(report.results.filter(hasNativeProcessEffects).length, 16);
  assert.equal(
    report.issues.filter((issue) => issue.code === "SETTLEMENT").length,
    16,
  );
  assert.ok(
    report.results
      .filter(hasNativeProcessEffects)
      .every((result) => result.reason === "missing-input"),
  );
});

test("conflicting job admission cannot erase unrecorded process obligations", () => {
  const pending = pendingNativeJob();
  const attempted = completeEvidence().results.find(
    (result) => result.platform === "linux" && result.checkId === "launch.argv",
  );
  attempted.versions = pending.versions;
  attempted.policy = { id: "linux-ownership-fixture-v1", sha256: DIGEST };
  const conflicting = recordNativeResults(pending, [attempted]);
  assert.equal(conflicting.unrecordedAdmission, "not-started");
  assert.equal(nativeCleanupFailure(conflicting), "unretired");
  assert.throws(
    () => recordNativeStage(conflicting, "cleanup", passedPhase()),
    { code: "ERR_INVALID_NATIVE_EVIDENCE" },
  );
  const { report } = renderNativeJob(conflicting);
  assert.equal(report.results.filter(hasNativeProcessEffects).length, 16);
  assert.equal(
    report.issues.filter((issue) => issue.code === "SETTLEMENT").length,
    15,
  );
  assert.ok(!report.issues.some((issue) => issue.code === "INCONSISTENT"));
  assert.deepEqual(
    report.results.find((result) => result.checkId === attempted.checkId),
    normalizeNativeResult(attempted),
  );
  for (const platform of ["darwin", "win32"]) {
    const { workflowSha, ...context } = ciContext();
    const job = {
      ...initializeNativeJob({ ...context, platform }),
      unrecordedAdmission: "possible",
    };
    const rendered = renderNativeJob(job);
    assert.equal(nativeCleanupFailure(job), "unretired");
    assert.equal(rendered.report.decision, "BLOCKED");
    assert.equal(
      rendered.report.results.filter(hasNativeProcessEffects).length,
      23,
    );
    assert.equal(
      rendered.report.issues.filter((issue) => issue.code === "SETTLEMENT")
        .length,
      23,
    );
    assert.throws(() => recordNativeStage(job, "cleanup", passedPhase()), {
      code: "ERR_INVALID_NATIVE_EVIDENCE",
    });
  }
});

test("CI stage failures remain distinct, cleanup is attempted, and probe cannot precede admission", () => {
  const { workflowSha, ...context } = ciContext();
  const initial = initializeNativeJob({ ...context, platform: "linux" });
  assert.throws(() => recordNativeStage(initial, "probe", passedPhase()), {
    code: "ERR_INVALID_NATIVE_EVIDENCE",
  });
  assert.equal(initial.stages.setup.status, "NOT_RUN");
  const ready = reportingJob();
  const setup = {
    checkoutSha: ready.checkoutSha,
    observed: ready.observed,
    provenance: ready.provenance,
    versions: ready.versions,
  };
  for (const stage of ["setup", "probe", "cleanup"]) {
    let job = initial;
    for (const name of ["setup", "probe", "cleanup"])
      job = recordNativeStage(
        job,
        name,
        name === stage
          ? { ...passedPhase(), status: "FAIL", reason: `${name}-failed` }
          : name === "probe" && stage === "setup"
            ? { ...passedPhase(), status: "NOT_RUN", reason: "setup-failed" }
            : passedPhase(),
        name === "setup" ? setup : {},
      );
    const { report, summary } = renderNativeJob(job);
    assert.equal(report.decision, "BLOCKED");
    assert.equal(report.ciStatus, "FAIL");
    assert.equal(report.ciStages[stage].status, "FAIL");
    assert.ok(
      report.results.every(
        (result) =>
          !result.implemented &&
          result.status === "BLOCKED" &&
          Object.values(result.phases).every(
            ({ status, reason }) =>
              status === "NOT_RUN" && reason === "unimplemented",
          ),
      ),
    );
    assert.match(summary, new RegExp(`${stage}: FAIL`, "u"));
    assert.equal(
      job.stages.cleanup.status,
      stage === "cleanup" ? "FAIL" : "PASS",
    );
    assert.throws(() => recordNativeStage(job, "setup", passedPhase()), {
      code: "ERR_INVALID_NATIVE_EVIDENCE",
    });
  }
});

function ciMetadata() {
  const context = ciContext();
  const run = {
    id: 101,
    run_attempt: 1,
    repository: { full_name: context.repository },
    path: ".github/workflows/native-poc.yml",
    event: "pull_request",
    head_sha: context.workflowSha,
  };
  const jobs = PLATFORMS.map(({ os }, index) => ({
    id: index + 1,
    name: `native-system-${os}`,
    run_id: 101,
    run_attempt: 1,
    status: "completed",
    conclusion: "success",
    started_at: "2026-01-01T00:00:00Z",
    completed_at: "2026-01-01T00:01:00Z",
    steps: [
      { name: `Bind native artifact ${201 + index}`, conclusion: "success" },
      ...[
        "Setup",
        "Probe reporting harness",
        "Cleanup",
        "Report per-OS evidence",
      ].map((name) => ({ name, conclusion: "success" })),
    ],
  }));
  const artifacts = PLATFORMS.map(({ os }, index) => ({
    id: 201 + index,
    name: nativeArtifactName(context, os),
    expired: false,
    size_in_bytes: 1000,
    digest: `sha256:${DIGEST}`,
    workflow_run: { id: 101, head_sha: context.workflowSha },
    created_at: "2026-01-01T00:00:30Z",
  }));
  const payloads = Object.fromEntries(
    PLATFORMS.map((platform, index) => [
      nativeArtifactName(context, platform.os),
      reportingJob(platform, String(index + 1)),
    ]),
  );
  return { context, run, jobs, artifacts, payloads };
}

test("same-revision stage failures outrank prerequisites and proof gaps without inventing artifact defects", async () => {
  const input = ciMetadata();
  const win = input.jobs.find((job) => job.name === "native-system-win32");
  win.conclusion = "failure";
  win.steps.find((step) => step.name === "Setup").conclusion = "failure";
  win.steps.find((step) => step.name === "Probe reporting harness").conclusion =
    "skipped";
  const name = nativeArtifactName(input.context, "win32");
  const original = input.payloads[name];
  const { workflowSha, ...context } = input.context;
  let windows = initializeNativeJob({ ...context, platform: "win32" });
  windows = recordNativeStage(
    windows,
    "setup",
    {
      ...passedPhase(),
      status: "BLOCKED",
      reason: "incompatible-image",
    },
    {
      checkoutSha: CANDIDATE,
      observed: { ...original.observed, image: null },
      provenance: original.provenance,
      versions: original.versions,
    },
  );
  windows = recordNativeStage(windows, "probe", {
    ...passedPhase(),
    status: "NOT_RUN",
    reason: "setup-failed",
  });
  input.payloads[name] = recordNativeStage(windows, "cleanup", passedPhase());
  const effects = injectedLinuxFixture().effects;
  effects.probe = () => ({ status: 1, signal: null });
  const diagnosis = await diagnosedFixture(effects);
  const linuxName = nativeArtifactName(input.context, "linux");
  const blocked = blockedLinuxPrerequisites(pendingNativeJob(), diagnosis);
  let linux = recordNativeResults(
    recordNativeAdmission(pendingNativeJob()),
    blocked.results,
    diagnosis,
  );
  linux = recordNativeStage(linux, "probe", passedPhase());
  input.payloads[linuxName] = recordNativeStage(
    linux,
    "cleanup",
    passedPhase(),
  );
  const selected = selectNativeArtifacts(
    input.context,
    input.run,
    input.jobs,
    input.artifacts,
  );
  assert.deepEqual(selected.issues, []);
  assert.equal(selected.entries.length, 3);
  const rendered = joinNativeArtifacts(input.context, selected, input.payloads);
  const { report, annotations, summary } = rendered;
  assert.deepEqual(report.ciIssues, [
    { code: "setup", platform: "win32" },
    { code: "probe", platform: "win32" },
  ]);
  assert.equal(report.ciStatus, "FAIL");
  assert.equal(report.decision, "BLOCKED");
  assert.equal(report.results.length, 69);
  assert.equal(report.source.findings.length, 4);
  assert.equal(
    report.issues.filter((issue) => issue.code === "SETTLEMENT").length,
    0,
  );
  assert.equal(
    report.issues.filter((issue) => issue.code === "MISSING").length,
    18,
  );
  const provenance = report.issues.filter(
    (issue) => issue.code === "PROVENANCE",
  );
  assert.equal(provenance.length, 1);
  assert.equal(provenance[0].platform, "win32");
  assert.match(
    provenance[0].message,
    /recorded CI setup\/probe\/cleanup\/report failure/u,
  );
  assert.doesNotMatch(provenance[0].message, /Bind the artifact/u);
  assert.equal(report.prerequisiteIssues[0].checkId, "ordinary-namespace");
  assert.match(annotations[0], /Native CI setup.*exact checkout/u);
  assert.match(annotations[1], /Native CI probe.*reporting harness/u);
  assert.match(
    annotations[2],
    /Native Linux prerequisite.*ordinary-namespace/u,
  );
  assert.equal(annotations.length, 32);
  assert.ok(report.issues.length > annotations.length);
  assert.doesNotMatch(
    summary,
    /repair artifact|Repair the selected artifact download|fresh bounded artifact/u,
  );
  assert.match(summary, /nested-namespaces: NOT_RUN/u);
  assert.match(summary, /\| win32 \| 0 \| 23 \|/u);
  const reordered = structuredClone(selected);
  reordered.jobs.reverse();
  reordered.entries.reverse();
  assert.deepEqual(
    joinNativeArtifacts(input.context, reordered, input.payloads),
    rendered,
  );
  delete input.payloads[name];
  const unavailable = joinNativeArtifacts(
    input.context,
    selected,
    input.payloads,
  );
  assert.ok(
    unavailable.report.ciIssues.some((issue) => issue.code === "payload"),
  );
  assert.match(unavailable.annotations[0], /Native CI setup/u);
  assert.match(unavailable.annotations[1], /Native CI probe/u);
  const absent = joinNativeArtifacts(
    input.context,
    { ...selected, entries: [] },
    {},
  );
  assert.deepEqual(
    absent.report.ciIssues.filter((issue) => issue.code === "missing"),
    PLATFORMS.map(({ os }) => ({ code: "missing", platform: os })),
  );
  assert.match(absent.annotations[0], /Native CI setup/u);
});

test("attempted native failures keep independent retirement, cleanup and emergency obligations", () => {
  const original = completeEvidence().results.find(
    (result) => result.platform === "linux" && result.checkId === "launch.argv",
  );
  original.versions = pendingNativeJob().versions;
  const failed = {
    ...original,
    policy: { id: "linux-ownership-fixture-v1", sha256: DIGEST },
    status: "FAIL",
    reason: "probe-failed",
    phases: {
      ...original.phases,
      probe: { ...passedPhase(), status: "FAIL", reason: "probe-failed" },
    },
  };
  for (const [change, expectedCleanup, findings] of [
    [
      {
        observations: [],
        policy: null,
        settlement: {
          status: "UNVERIFIABLE",
          independent: false,
          emergencyCleanup: true,
        },
      },
      "unretired",
      ["PROBE", "SETTLEMENT"],
    ],
    [
      {
        phases: {
          ...failed.phases,
          cleanup: {
            ...passedPhase(),
            status: "FAIL",
            reason: "cleanup-failed",
          },
        },
      },
      "cleanup-failed",
      ["PROBE", "CLEANUP"],
    ],
    [
      {
        settlement: {
          status: "RETIRED",
          independent: true,
          emergencyCleanup: true,
        },
      },
      null,
      ["PROBE", "SETTLEMENT"],
    ],
  ]) {
    const pending = pendingNativeJob();
    const job = recordNativeResults(
      pending,
      linuxCaseRecords(pending, [{ ...failed, ...change }]),
    );
    assert.equal(nativeCleanupFailure(job), expectedCleanup);
    if (expectedCleanup)
      assert.throws(() => recordNativeStage(job, "cleanup", passedPhase()), {
        code: "ERR_INVALID_NATIVE_EVIDENCE",
      });
    const { report } = renderNativeJob(job);
    assert.equal(report.decision, "NO_GO");
    for (const code of findings)
      assert.ok(
        report.issues.some(
          (issue) => issue.code === code && issue.checkId === failed.checkId,
        ),
      );
    assert.deepEqual(
      report.results.find((result) => result.checkId === failed.checkId),
      normalizeNativeResult({ ...failed, ...change }),
    );
  }
});

function injectedLinuxFixture() {
  const calls = [];
  const reached = (name) => {
    calls.push(name);
  };
  const effects = {
    fs: {
      realpath: async (file) => {
        reached("realpath");
        return file;
      },
      lstat: async () => {
        reached("identity");
        return { isFile: () => true, nlink: 1 };
      },
      access: async () => {
        reached("executable");
      },
      mkdir: async () => {
        reached("storage");
      },
      copyFile: async () => {
        reached("copy");
      },
      chmod: async () => {},
      readFile: async () => Buffer.from("synthetic fixture bytes"),
    },
    protect: () => {
      reached("protection");
    },
    resolveLauncher: (cwd, options) =>
      resolveOwnedProcessLauncher(cwd, { ...options, namespaceId: null }),
    probe: () => {
      reached("probe");
      return { status: 0, signal: null };
    },
    procVisibility: async () => {
      reached("procfs");
    },
    librariesFor: async () => {
      reached("abi");
      return [
        {
          target: "/lib/fixture.so",
          source: "/lib/fixture.so",
          sha256: DIGEST,
        },
      ];
    },
    executeFile: async () => {
      reached("version");
      return { stdout: "bubblewrap 0.11.0\n" };
    },
  };
  return { effects, calls };
}

function injectedLinuxPreparation() {
  const archive = Buffer.from("synthetic package bytes");
  const executable = Buffer.from("synthetic executable bytes");
  const records = [];
  const calls = [];
  const files = new Map();
  const effects = {
    platform: "linux",
    architecture: "x64",
    env: {
      CI: "true",
      GITHUB_ACTIONS: "true",
      ImageOS: "ubuntu24",
      GH_TOKEN: "fixture-secret",
    },
    now: () => 0,
    protect: (file) => calls.push({ protection: file }),
    fs: {
      realpath: async (file) => file,
      mkdir: async () => {},
      writeFile: async (file, bytes) => {
        files.set(file, bytes);
      },
      lstat: async () => ({
        isFile: () => true,
        nlink: 1,
        size: archive.length,
      }),
      readFile: async (file) =>
        file === "/etc/os-release"
          ? 'ID=ubuntu\nVERSION_ID="24.04"\n'
          : file === "/usr/bin/bwrap"
            ? executable
            : archive,
    },
    run: async (file, args, options) => {
      assert.equal(
        file,
        args.includes("--no-download") ? "/usr/bin/sudo" : "/usr/bin/timeout",
      );
      if (file === "/usr/bin/sudo") {
        assert.equal(args[3], "/usr/bin/timeout");
        assert.ok(args.includes("--preserve-env=APT_CONFIG,DEBIAN_FRONTEND"));
      }
      assert.ok(options.timeout > 0 && options.timeout <= 42000);
      assert.equal(options.env.GH_TOKEN, undefined);
      if (
        args.includes("/usr/bin/apt-get") ||
        args.includes("/usr/bin/apt-cache")
      ) {
        assert.equal(
          options.env.APT_CONFIG,
          "/fixture/report/linux-packages/apt.conf",
        );
        assert.equal(
          files.get(options.env.APT_CONFIG),
          'Dir::Etc::parts "/fixture/report/linux-packages/configuration";\nDir::Etc::main "/dev/null";\n',
        );
      }
      const phase = args.includes("download")
        ? "acquisition"
        : args.includes("--no-download")
          ? "installation"
          : args.includes("/usr/bin/dpkg-query") ||
              args.includes("/usr/bin/bwrap")
            ? "verification"
            : "metadata";
      assert.equal(records.at(-1).status, "RUNNING");
      assert.equal(records.at(-1).phase, phase);
      calls.push({ phase, file, args });
      if (args.includes("/usr/bin/apt-cache"))
        return {
          stdout:
            [
              "Package: bubblewrap",
              "Architecture: amd64",
              "Version: 1.2.3-1",
              "Filename: pool/universe/b/bubblewrap/bubblewrap_1.2.3-1_amd64.deb",
              `Size: ${archive.length}`,
              `SHA256: ${createHash("sha256").update(archive).digest("hex")}`,
            ].join("\n") + "\n",
        };
      if (args.includes("--simulate"))
        return {
          stdout:
            "Inst bubblewrap (1.2.3-1 Ubuntu:24.04/noble [amd64])\nConf bubblewrap (1.2.3-1 Ubuntu:24.04/noble [amd64])\n",
        };
      if (args.includes("/usr/bin/dpkg-query")) return { stdout: "1.2.3-1" };
      return {
        stdout: args.includes("/usr/bin/bwrap") ? "bubblewrap 1.2.3\n" : "",
      };
    },
  };
  const persist = async (record) => records.push(structuredClone(record));
  return { effects, persist, records, calls, executable };
}

test("Linux preparation writes admission-independent phases before exact authenticated acquisition and installation", async () => {
  const { effects, persist, records, calls, executable } =
    injectedLinuxPreparation();
  const prepared = await prepareLinuxBubblewrap(
    CANDIDATE,
    "/fixture/report",
    persist,
    effects,
  );
  assert.deepEqual(
    records.map(({ status, phase }) => [status, phase]),
    [
      ["RUNNING", "metadata"],
      ["RUNNING", "acquisition"],
      ["RUNNING", "installation"],
      ["RUNNING", "verification"],
      ["PASS", "verification"],
    ],
  );
  assert.deepEqual(linuxPreparationVersion(prepared, CANDIDATE), {
    name: "bubblewrap",
    version: "bubblewrap 1.2.3",
    sha256: createHash("sha256").update(executable).digest("hex"),
  });
  for (const { args } of calls.filter(({ args }) =>
    args?.includes("install"),
  )) {
    assert.equal(args.at(-1), "bubblewrap=1.2.3-1");
    assert.ok(
      args.includes("--no-remove") && args.includes("--no-install-recommends"),
    );
    assert.ok(
      args.includes("Acquire::Retries=0") &&
        args.includes("APT::Get::AllowUnauthenticated=false"),
    );
  }
  const acquisition = calls.find(({ args }) => args?.includes("download")).args;
  assert.equal(acquisition.at(-1), "bubblewrap=1.2.3-1");
  assert.ok(!acquisition.includes("/usr/bin/sudo"));
  assert.equal(calls.filter(({ file }) => file === "/usr/bin/sudo").length, 1);
});

test("Linux preparation failures never publish verified versions or permit dependent admission", async () => {
  for (const [phase, configure] of [
    [
      "metadata",
      (effects) => {
        const run = effects.run;
        effects.run = async (file, args, options) =>
          args.includes("--simulate")
            ? { stdout: "Inst extra-component (1.0 Synthetic [amd64])\n" }
            : run(file, args, options);
      },
    ],
    [
      "acquisition",
      (effects) => {
        const read = effects.fs.readFile;
        effects.fs.readFile = async (file) =>
          file.endsWith(".deb") ? Buffer.from("substituted") : read(file);
      },
    ],
    [
      "installation",
      (effects) => {
        const run = effects.run;
        effects.run = async (file, args, options) => {
          if (args.includes("--no-download")) throw new Error("fixture-secret");
          return run(file, args, options);
        };
      },
    ],
    [
      "verification",
      (effects) => {
        effects.protect = (file) => {
          if (file === "/usr/bin/bwrap") throw new Error("fixture-secret");
        };
      },
    ],
  ]) {
    const { effects, persist, records, calls } = injectedLinuxPreparation();
    configure(effects);
    const failed = await prepareLinuxBubblewrap(
      CANDIDATE,
      "/fixture/report",
      persist,
      effects,
    );
    assert.equal(failed.status, "FAIL");
    assert.equal(failed.phase, phase);
    assert.equal(failed.version, null);
    assert.throws(() => linuxPreparationVersion(failed, CANDIDATE));
    assert.ok(!calls.some(({ args }) => args?.includes("/usr/bin/bwrap")));
    if (["metadata", "acquisition"].includes(phase))
      assert.ok(!calls.some(({ args }) => args?.includes("--no-download")));
    assert.doesNotMatch(JSON.stringify(records), /fixture-secret/u);
  }
});

test("Linux setup rejects absent, interrupted, failed-action and substituted preparation receipts", async () => {
  const { effects, persist, records } = injectedLinuxPreparation();
  const prepared = await prepareLinuxBubblewrap(
    CANDIDATE,
    "/fixture/report",
    persist,
    effects,
  );
  for (const [receipt, outcome] of [
    [null, "success"],
    [initialLinuxPreparation(CANDIDATE), "success"],
    ...records.slice(0, -1).map((receipt) => [receipt, "success"]),
    [prepared, "cancelled"],
    [{ ...prepared, candidateSha: "c".repeat(40) }, "success"],
    [{ ...prepared, unexpected: "fixture-value" }, "success"],
    [
      { ...prepared, version: { ...prepared.version, sha256: null } },
      "success",
    ],
  ])
    assert.throws(() => linuxPreparationVersion(receipt, CANDIDATE, outcome));
  const { workflowSha, ...context } = ciContext();
  let job = initializeNativeJob({ ...context, platform: "linux" });
  job = recordNativeStage(job, "setup", {
    ...passedPhase(),
    status: "FAIL",
    reason: "setup-failed",
  });
  job = recordNativeStage(job, "probe", {
    status: "NOT_RUN",
    elapsedMs: 0,
    deadlineMs: 100,
    reason: "setup-failed",
  });
  assert.throws(() => recordNativeAdmission(job));
  assert.equal(renderNativeJob(job).report.ciStatus, "FAIL");
  assert.equal(job.unrecordedAdmission, "not-started");
});

test("Linux preparation cannot publish success after its overall deadline", async () => {
  const { effects, persist, records } = injectedLinuxPreparation();
  let elapsed = 0;
  effects.now = () => elapsed;
  const read = effects.fs.readFile;
  effects.fs.readFile = async (file, ...args) => {
    const bytes = await read(file, ...args);
    if (file === "/usr/bin/bwrap") elapsed = 150000;
    return bytes;
  };
  const failed = await prepareLinuxBubblewrap(
    CANDIDATE,
    "/fixture/report",
    persist,
    effects,
  );
  assert.equal(failed.status, "FAIL");
  assert.equal(failed.phase, "verification");
  assert.equal(failed.version, null);
  assert.equal(records.at(-1).status, "FAIL");
  assert.throws(() => linuxPreparationVersion(failed, CANDIDATE));
});

test("Linux fixtures bind launcher bytes and version to verified preparation before payload admission", async () => {
  for (const [expected, prerequisite] of [
    [{ expectedLauncherDigest: DIGEST }, "bubblewrap-identity"],
    [{ expectedLauncherVersion: "bubblewrap 9.9.9" }, "bubblewrap-version"],
  ]) {
    const { effects, calls } = injectedLinuxFixture();
    const diagnosis = await diagnosedFixture({ ...effects, ...expected });
    assert.equal(diagnosis.failedPrerequisite, prerequisite);
    if (prerequisite === "bubblewrap-identity")
      assert.ok(!calls.includes("probe") && !calls.includes("storage"));
  }
});

async function diagnosedFixture(effects) {
  let diagnosis;
  await assert.rejects(
    () => prepareLinuxFixture("/fixture/native", effects),
    (error) => {
      assert.equal(error.code, "ERR_NATIVE_PREREQUISITE_UNAVAILABLE");
      diagnosis = error.prerequisites;
      assert.doesNotMatch(
        JSON.stringify(error),
        /fixture-secret|AppArmor|\/fixture\/native|stderr/u,
      );
      return true;
    },
  );
  const failed = LINUX_PREREQUISITE_IDS.indexOf(diagnosis.failedPrerequisite);
  for (const [index, check] of diagnosis.checks.entries()) {
    assert.equal(
      check.status,
      index < failed ? "PASS" : index === failed ? "BLOCKED" : "NOT_RUN",
    );
    if (index > failed)
      assert.ok(
        Object.values(check.observation).every((value) => value === null),
      );
  }
  return diagnosis;
}

const prerequisiteError = (code) =>
  Object.assign(new Error("fixture-secret ::error::AppArmor stderr"), { code });

test("Linux prerequisites distinguish fixed discovery, identity, protection, namespace failure and rejected fallback", async () => {
  const scenarios = [
    [
      "bubblewrap-discovery",
      "absent",
      (effects) => {
        effects.fs.realpath = async () => {
          throw prerequisiteError("ENOENT");
        };
      },
    ],
    [
      "bubblewrap-discovery",
      "unverifiable",
      (effects) => {
        effects.fs.realpath = async () => {
          throw prerequisiteError("ERR_EXECUTION_PROCESS_UNVERIFIABLE");
        };
      },
    ],
    [
      "bubblewrap-identity",
      "invalid-identity",
      (effects) => {
        effects.fs.lstat = async () => ({ isFile: () => true, nlink: 2 });
      },
    ],
    [
      "bubblewrap-identity",
      "not-executable",
      (effects) => {
        effects.fs.access = async () => {
          throw prerequisiteError("EACCES");
        };
      },
    ],
    [
      "bubblewrap-protection",
      "protection-unavailable",
      (effects) => {
        effects.protect = () => {
          throw prerequisiteError("ERR_EXECUTION_PROCESS_UNVERIFIABLE");
        };
      },
    ],
    [
      "ordinary-namespace",
      "probe-failed",
      (effects) => {
        effects.probe = () => ({ status: 1, signal: null });
      },
    ],
    [
      "ordinary-namespace",
      "non-isolated-fallback",
      (effects) => {
        effects.probe = () => ({ status: 1, signal: null });
        effects.resolveLauncher = (cwd, options) =>
          resolveOwnedProcessLauncher(cwd, {
            ...options,
            namespaceId: "pid:[1234]",
          });
      },
    ],
  ];
  for (const [id, expected, configure] of scenarios) {
    const { effects, calls } = injectedLinuxFixture();
    configure(effects);
    const diagnosis = await diagnosedFixture(effects);
    assert.equal(diagnosis.failedPrerequisite, id);
    assert.equal(
      diagnosis.checks.find((check) => check.id === id).diagnosis,
      expected,
    );
    assert.ok(
      !calls.includes("procfs") &&
        !calls.includes("storage") &&
        !calls.includes("abi") &&
        !calls.includes("version"),
    );
  }
});

test("Linux prerequisite diagnoses stop at later procfs, nested namespace, storage, ABI and version failures", async () => {
  for (const [id, expected, configure] of [
    [
      "procfs-retirement",
      "unverifiable",
      (effects) => {
        effects.procVisibility = async () => {
          throw prerequisiteError("ERR_UNKNOWN_SECRET");
        };
      },
    ],
    [
      "nested-namespaces",
      "probe-failed",
      (effects) => {
        effects.probe = (file, args) => ({
          status: args.includes(file) ? 1 : 0,
          signal: null,
        });
      },
    ],
    [
      "private-fixture-storage",
      "unverifiable",
      (effects) => {
        effects.fs.mkdir = async () => {
          throw prerequisiteError("EROFS");
        };
      },
    ],
    [
      "protected-executable-abi",
      "unverifiable",
      (effects) => {
        effects.librariesFor = async () => {
          throw prerequisiteError(127);
        };
      },
    ],
    [
      "protected-executable-abi",
      "runtime-mismatch",
      (effects) => {
        effects.expectedExecutableDigest = DIGEST;
      },
    ],
    [
      "bubblewrap-version",
      "invalid-version",
      (effects) => {
        effects.executeFile = async () => ({ stdout: "fixture-secret" });
      },
    ],
  ]) {
    const { effects } = injectedLinuxFixture();
    configure(effects);
    const diagnosis = await diagnosedFixture(effects);
    assert.equal(diagnosis.failedPrerequisite, id);
    assert.equal(
      diagnosis.checks.find((check) => check.id === id).diagnosis,
      expected,
    );
  }
});

test("Linux diagnostics retain only allowlisted observations and reuse actual public namespace probes", async () => {
  for (const [result, observation] of [
    [
      { status: 42, signal: null, stdout: "fixture-secret" },
      { errno: null, exitCode: 42, signal: null, timedOut: false },
    ],
    [
      {
        status: null,
        signal: "SIGTERM",
        error: prerequisiteError("ETIMEDOUT"),
      },
      { errno: "ETIMEDOUT", exitCode: null, signal: "SIGTERM", timedOut: true },
    ],
    [
      {
        status: null,
        signal: "SIGUSR1",
        error: prerequisiteError("ERR_UNKNOWN_SECRET"),
      },
      { errno: null, exitCode: null, signal: null, timedOut: null },
    ],
  ]) {
    const { effects } = injectedLinuxFixture();
    effects.probe = () => result;
    const diagnosis = await diagnosedFixture(effects);
    const check = diagnosis.checks.find(
      (check) => check.id === "ordinary-namespace",
    );
    assert.equal(check.diagnosis, "unverifiable");
    assert.deepEqual(check.observation, observation);
  }
  const { effects } = injectedLinuxFixture();
  const probes = [];
  effects.probe = (file, args, options) => {
    probes.push({ file, args, options });
    return { status: 0, signal: null };
  };
  effects.fs.mkdir = async () => {
    throw prerequisiteError("ENOSPC");
  };
  const diagnosis = await diagnosedFixture(effects);
  assert.equal(probes.length, 2);
  assert.equal(probes[0].args.includes("--unshare-user"), false);
  assert.equal(probes[1].args.includes("--unshare-user"), true);
  for (const probe of probes)
    assert.deepEqual(probe.options, { stdio: "ignore", timeout: 10000 });
  for (const id of ["ordinary-namespace", "nested-namespaces"])
    assert.deepEqual(
      diagnosis.checks.find((check) => check.id === id).observation,
      { errno: null, exitCode: 0, signal: null, timedOut: false },
    );
  const versionFailure = injectedLinuxFixture().effects;
  versionFailure.executeFile = async () => {
    throw Object.assign(prerequisiteError(2), {
      signal: "SIGTERM",
      killed: true,
    });
  };
  assert.deepEqual(
    (await diagnosedFixture(versionFailure)).checks.at(-1).observation,
    { errno: null, exitCode: 2, signal: "SIGTERM", timedOut: null },
  );
  for (const [code, errno] of [
    [127, null],
    ["ETIMEDOUT", "ETIMEDOUT"],
  ]) {
    const opaque = injectedLinuxFixture().effects;
    opaque.librariesFor = async () => {
      throw Object.assign(prerequisiteError(code), {
        signal: "SIGTERM",
        killed: true,
      });
    };
    const diagnosis = await diagnosedFixture(opaque);
    const check = diagnosis.checks.find(
      (check) => check.id === "protected-executable-abi",
    );
    assert.equal(check.diagnosis, "unverifiable");
    assert.deepEqual(check.observation, {
      errno,
      exitCode: null,
      signal: null,
      timedOut: null,
    });
  }
  const healthy = await prepareLinuxFixture(
    "/fixture/native",
    injectedLinuxFixture().effects,
  );
  assert.equal(healthy.version.version, "bubblewrap 0.11.0");
  const alternative = injectedLinuxFixture().effects;
  const candidates = [];
  alternative.fs.realpath = async (file) => {
    if (file.endsWith("/bwrap")) {
      candidates.push(file);
      if (file !== "/usr/local/bin/bwrap") throw prerequisiteError("ENOENT");
    }
    return file;
  };
  alternative.probe = (file) => {
    assert.equal(file, "/usr/local/bin/bwrap");
    return { status: 0, signal: null };
  };
  assert.equal(
    (await prepareLinuxFixture("/fixture/native", alternative)).launcher,
    "/usr/local/bin/bwrap",
  );
  assert.deepEqual(candidates, [
    "/usr/bin/bwrap",
    "/bin/bwrap",
    "/usr/local/bin/bwrap",
  ]);
});

test("bounded Linux prerequisite evidence survives exact-job reporting and joining without attesting cases", async () => {
  const { effects } = injectedLinuxFixture();
  effects.fs.realpath = async () => {
    throw prerequisiteError("ENOENT");
  };
  const diagnosis = await diagnosedFixture(effects);
  const input = ciMetadata();
  const name = nativeArtifactName(input.context, "linux");
  const settled = input.payloads[name];
  const pending = {
    ...settled,
    stages: {
      ...settled.stages,
      probe: {
        status: "NOT_RUN",
        elapsedMs: null,
        deadlineMs: 30000,
        reason: "missing-input",
      },
    },
  };
  const blocked = blockedLinuxPrerequisites(pending, diagnosis);
  let recorded = recordNativeResults(
    pending,
    blocked.results,
    blocked.linuxPrerequisites,
  );
  assert.equal(recorded.schemaVersion, 4);
  assert.equal(recorded.results.length, 16);
  assert.ok(
    recorded.results.every(
      (result) =>
        result.status === "BLOCKED" &&
        result.reason === "missing-input" &&
        result.observations.length === 0 &&
        Object.values(result.phases).every(
          (phase) => phase.status === "NOT_RUN",
        ),
    ),
  );
  recorded = recordNativeStage(recorded, "probe", passedPhase());
  input.payloads[name] = recorded;
  const bound = linuxPrerequisiteEvidence(recorded, diagnosis);
  const local = renderNativeJob(recorded);
  assert.deepEqual(local.report.linuxPrerequisites, [bound]);
  assert.equal(local.report.results.length, 23);
  assert.equal(local.report.ciStatus, "PASS");
  assert.ok(
    local.report.results.every((result) => !hasNativeProcessEffects(result)),
  );
  assert.ok(
    !local.report.issues.some(({ code }) =>
      ["SETUP", "PROBE", "CLEANUP", "SETTLEMENT"].includes(code),
    ),
  );
  assert.match(
    local.annotations[0],
    /Native Linux prerequisite.*bubblewrap-discovery.*absent/u,
  );
  assert.match(local.summary, /bubblewrap-identity: NOT_RUN/u);
  const aggregate = joinNativeArtifacts(
    input.context,
    selectNativeArtifacts(
      input.context,
      input.run,
      input.jobs,
      input.artifacts,
    ),
    input.payloads,
  );
  const joined = aggregate.report;
  assert.deepEqual(joined.linuxPrerequisites, [bound]);
  assert.equal(joined.decision, "BLOCKED");
  assert.deepEqual(joined.ciIssues, []);
  assert.equal(joined.results.length, 69);
  assert.equal(joined.source.findings.length, 4);
  assert.equal(
    joined.issues.filter(({ code }) => code === "SETTLEMENT").length,
    0,
  );
  assert.match(aggregate.annotations[0], /Native Linux prerequisite/u);
  assert.equal(aggregate.annotations.length, 32);
  for (const alter of [
    (value) => {
      value.checks[0].observation.errno = "ERR_UNKNOWN_SECRET";
    },
    (value) => {
      value.checks[1].status = "PASS";
    },
    (value) => {
      value.checks[0].raw = "fixture-secret";
    },
    (value) => {
      value.candidateSha = "d".repeat(40);
    },
  ]) {
    const malformed = structuredClone(diagnosis);
    alter(malformed);
    assert.throws(() => normalizeLinuxPrerequisites(malformed), {
      code: "ERR_INVALID_NATIVE_EVIDENCE",
    });
  }
  const inventedRetirement = structuredClone(blocked.results);
  inventedRetirement[0].settlement = {
    status: "RETIRED",
    independent: true,
    emergencyCleanup: false,
  };
  assert.doesNotThrow(() => normalizeNativeResult(inventedRetirement[0]));
  assert.throws(
    () => recordNativeResults(pending, inventedRetirement, diagnosis),
    { code: "ERR_INVALID_NATIVE_EVIDENCE" },
  );
  for (const version of [1, 2, 3]) {
    const legacy = { ...recorded, schemaVersion: version };
    delete legacy.unrecordedAdmission;
    if (version < 3) delete legacy.linuxPrerequisites;
    if (version === 1) delete legacy.results;
    const report = renderNativeJob(legacy).report;
    assert.deepEqual(report.linuxPrerequisites, version === 3 ? [bound] : []);
    assert.equal(
      report.results.filter((result) => result.implemented).length,
      version === 1 ? 0 : 16,
    );
  }
  const changed = structuredClone(input.payloads);
  changed[name].observed.build = "different-image-build";
  const mismatched = joinNativeArtifacts(
    input.context,
    selectNativeArtifacts(
      input.context,
      input.run,
      input.jobs,
      input.artifacts,
    ),
    changed,
  ).report;
  assert.deepEqual(mismatched.linuxPrerequisites, []);
  assert.ok(mismatched.ciIssues.some((issue) => issue.code === "payload"));
});

test("Linux check records join only their exact job and keep unrelated contracts blocked", () => {
  const input = ciMetadata();
  const name = nativeArtifactName(input.context, "linux");
  const settled = input.payloads[name];
  const pending = {
    ...settled,
    stages: {
      ...settled.stages,
      probe: {
        status: "NOT_RUN",
        elapsedMs: null,
        deadlineMs: 30000,
        reason: "missing-input",
      },
    },
  };
  const result = completeEvidence().results.find(
    (entry) => entry.platform === "linux" && entry.checkId === "launch.argv",
  );
  result.versions = settled.versions;
  result.policy = { id: "linux-ownership-fixture-v1", sha256: DIGEST };
  result.profile = "ownership";
  const access = completeEvidence().results.find(
    (entry) => entry.platform === "linux" && entry.checkId === "network.deny",
  );
  access.versions = settled.versions;
  access.policy = { id: "linux-access-fixture-v1", sha256: "c".repeat(64) };
  access.profile = "access";
  const acceptedRecords = linuxCaseRecords(pending, [result, access]);
  const recorded = recordNativeResults(pending, acceptedRecords);
  input.payloads[name] = recordNativeStage(recorded, "probe", passedPhase());
  const selection = selectNativeArtifacts(
    input.context,
    input.run,
    input.jobs,
    input.artifacts,
  );
  const report = joinNativeArtifacts(
    input.context,
    selection,
    input.payloads,
  ).report;
  assert.equal(
    report.results.find(
      (entry) => entry.platform === "linux" && entry.checkId === "launch.argv",
    ).status,
    "PASS",
  );
  assert.equal(
    report.results.find(
      (entry) =>
        entry.platform === "linux" && entry.checkId === "profile.read-only",
    ).status,
    "BLOCKED",
  );
  assert.equal(report.decision, "BLOCKED");
  assert.ok(!report.issues.some((issue) => issue.code === "INCONSISTENT"));
  const disagreeing = {
    ...result,
    checkId: "launch.storage",
    policy: { ...result.policy, sha256: "d".repeat(64) },
  };
  const mismatch = recordNativeResults(
    pending,
    linuxCaseRecords(pending, [result, access, disagreeing]),
  );
  const disagreement = renderNativeJob(mismatch).report;
  assert.ok(disagreement.issues.some((issue) => issue.code === "INCONSISTENT"));
  for (const results of [
    [result, result],
    [{ ...result, candidateSha: "d".repeat(40), checkoutSha: "d".repeat(40) }],
    [{ ...result, provenance: { ...result.provenance, jobId: "99" } }],
    [{ ...result, checkId: "files.private" }],
  ])
    assert.throws(
      () => {
        const invalid = [...acceptedRecords];
        invalid[invalid.length - 2] = results[0];
        if (results.length === 2) invalid[0] = results[1];
        return recordNativeResults(pending, invalid);
      },
      {
        code: "ERR_INVALID_NATIVE_EVIDENCE",
      },
    );
  const failed = {
    ...result,
    status: "FAIL",
    reason: "probe-failed",
    phases: {
      ...result.phases,
      probe: { ...passedPhase(), status: "FAIL", reason: "probe-failed" },
    },
  };
  const failedJob = recordNativeResults(
    pending,
    linuxCaseRecords(pending, [failed]),
  );
  assert.throws(() => recordNativeStage(failedJob, "probe", passedPhase()), {
    code: "ERR_INVALID_NATIVE_EVIDENCE",
  });
  for (const change of [
    { settlement: { ...failed.settlement, independent: false } },
    {
      phases: {
        ...failed.phases,
        cleanup: { ...passedPhase(), status: "FAIL", reason: "cleanup-failed" },
      },
    },
  ]) {
    const beforeCleanup = {
      ...pending,
      stages: {
        ...pending.stages,
        cleanup: {
          status: "NOT_RUN",
          elapsedMs: null,
          deadlineMs: 30000,
          reason: "missing-input",
        },
      },
    };
    const cleanupFailed = recordNativeResults(
      beforeCleanup,
      linuxCaseRecords(beforeCleanup, [{ ...failed, ...change }]),
    );
    assert.throws(
      () => recordNativeStage(cleanupFailed, "cleanup", passedPhase()),
      { code: "ERR_INVALID_NATIVE_EVIDENCE" },
    );
  }
});

test("artifact joining uses actual run/job upload receipts and rejects missing or mixed-revision payloads", () => {
  const input = ciMetadata();
  const before = structuredClone(input);
  const selection = selectNativeArtifacts(
    input.context,
    input.run,
    input.jobs,
    input.artifacts,
  );
  assert.equal(selection.entries.length, 3);
  assert.deepEqual(selection.issues, []);
  const rendered = joinNativeArtifacts(
    input.context,
    selection,
    input.payloads,
  );
  assert.deepEqual(rendered.report.ciIssues, []);
  assert.equal(rendered.report.bindings.length, 3);
  assert.equal(rendered.report.decision, "BLOCKED");
  assert.equal(rendered.report.ciStatus, "PASS");
  assert.deepEqual(input, before);
  const reordered = structuredClone(selection);
  reordered.entries.reverse();
  reordered.jobs.reverse();
  for (const entry of reordered.entries)
    entry.stages = Object.fromEntries(Object.entries(entry.stages).reverse());
  assert.deepEqual(
    joinNativeArtifacts(input.context, reordered, input.payloads),
    rendered,
  );
  assert.throws(
    () =>
      joinNativeArtifacts(
        input.context,
        {
          entries: [],
          issues: [{ code: "token=private-value", platform: null }],
          jobs: [],
        },
        {},
      ),
    { code: "ERR_INVALID_NATIVE_EVIDENCE" },
  );
  const unsafe = structuredClone(selection);
  unsafe.entries[0].name = "../private-control";
  assert.throws(() => joinNativeArtifacts(input.context, unsafe, {}), {
    code: "ERR_INVALID_NATIVE_EVIDENCE",
  });
  const missingSelection = { ...selection, entries: [] };
  const missingReport = joinNativeArtifacts(
    input.context,
    missingSelection,
    {},
  ).report;
  assert.equal(missingReport.ciStatus, "BLOCKED");
  assert.deepEqual(
    missingReport.ciIssues,
    PLATFORMS.map(({ os }) => ({ code: "missing", platform: os })),
  );
  for (const alter of [
    (i) => {
      i.run.run_attempt = 2;
    },
    (i) => {
      i.artifacts.pop();
    },
    (i) => {
      i.artifacts.push(structuredClone(i.artifacts[0]));
    },
    (i) => {
      i.artifacts[0].workflow_run.head_sha = "d".repeat(40);
    },
    (i) => {
      i.jobs[0].steps[0].name = "Bind native artifact 999";
    },
    (i) => {
      i.jobs[0].steps[0].conclusion = "skipped";
    },
    (i) => {
      delete i.payloads[i.artifacts[0].name];
    },
    (i) => {
      i.payloads[i.artifacts[0].name].candidateSha = "d".repeat(40);
    },
    (i) => {
      i.payloads[i.artifacts[0].name].provenance.jobId = "999";
    },
  ]) {
    const changed = ciMetadata();
    alter(changed);
    const selected = selectNativeArtifacts(
      changed.context,
      changed.run,
      changed.jobs,
      changed.artifacts,
    );
    const report = joinNativeArtifacts(
      changed.context,
      selected,
      changed.payloads,
    ).report;
    assert.equal(report.decision, "BLOCKED");
    assert.ok(report.ciIssues.length > 0);
  }
  const cancelled = ciMetadata();
  cancelled.jobs[0].conclusion = "cancelled";
  const cancelledReport = joinNativeArtifacts(
    cancelled.context,
    selectNativeArtifacts(
      cancelled.context,
      cancelled.run,
      cancelled.jobs,
      cancelled.artifacts,
    ),
    cancelled.payloads,
  ).report;
  assert.equal(
    cancelledReport.bindings.find(({ platform }) => platform === "linux")
      .conclusion,
    "cancelled",
  );
  assert.equal(cancelledReport.decision, "BLOCKED");
  assert.equal(cancelledReport.ciStatus, "BLOCKED");
  cancelled.artifacts = [];
  const absent = joinNativeArtifacts(
    cancelled.context,
    selectNativeArtifacts(
      cancelled.context,
      cancelled.run,
      cancelled.jobs,
      cancelled.artifacts,
    ),
    {},
  ).report;
  assert.equal(
    absent.ciJobs.find(({ platform }) => platform === "linux").conclusion,
    "cancelled",
  );
  assert.equal(
    absent.ciJobs.find(({ platform }) => platform === "linux").artifactId,
    null,
  );
  assert.ok(absent.ciIssues.some(({ code }) => code === "missing"));
  const partial = ciMetadata();
  partial.artifacts.pop();
  const partialSelection = selectNativeArtifacts(
    partial.context,
    partial.run,
    partial.jobs,
    partial.artifacts,
  );
  partialSelection.issues.push({ code: "download", platform: null });
  const incomplete = joinNativeArtifacts(
    partial.context,
    partialSelection,
    partial.payloads,
  ).report;
  assert.equal(incomplete.ciStatus, "BLOCKED");
  assert.ok(incomplete.ciIssues.some(({ code }) => code === "download"));
  const failed = ciMetadata();
  failed.jobs[0].conclusion = "failure";
  failed.jobs[0].steps.find(
    ({ name }) => name === "Probe reporting harness",
  ).conclusion = "failure";
  failed.payloads[failed.artifacts[0].name].stages.probe = {
    ...passedPhase(),
    status: "FAIL",
    reason: "probe-failed",
  };
  const failedReport = joinNativeArtifacts(
    failed.context,
    selectNativeArtifacts(
      failed.context,
      failed.run,
      failed.jobs,
      failed.artifacts,
    ),
    failed.payloads,
  ).report;
  assert.equal(failedReport.decision, "BLOCKED");
  assert.equal(failedReport.ciStatus, "FAIL");
  assert.equal(
    failedReport.ciJobs.find(({ platform }) => platform === "linux").stages
      .probe,
    "failure",
  );
});
