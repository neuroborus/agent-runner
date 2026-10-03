import assert from "node:assert/strict";
import test from "node:test";
import {
  assessDarwinEnumeration,
  darwinLaunchDigest,
  darwinRetirementArguments,
  normalizeDarwinLaunch,
  retireDarwinDomain,
  runDarwinOwnershipCase,
} from "./index.js";
import { digest } from "./protocol.js";

function fixture() {
  const hash = "a".repeat(64),
    request = normalizeDarwinLaunch({
      schemaVersion: 1,
      candidateSha: "b".repeat(40),
      nonce: "c".repeat(32),
      uid: 90001,
      gid: 90002,
      custody: "/fixture/custody",
      storage: "/fixture/storage",
      workspace: "/fixture/storage/work",
      launcher: { path: "/fixture/custody/launcher", sha256: hash },
      executable: {
        path: "/fixture/storage/payload",
        sha256: hash,
        cdhash: "d".repeat(40),
      },
      policy: { path: "/fixture/custody/policy", sha256: hash },
      bindings: {
        system: hash,
        source: hash,
        closure: hash,
        policy: "e".repeat(64),
      },
    });
  const identity = (pid, uid = 0, gid = 0, asid = 0) => ({
    pid,
    pidVersion: 1,
    uid,
    gid,
    asid,
    auid: uid,
    ruid: uid,
    rgid: gid,
    svuid: uid,
    svgid: gid,
    startSeconds: 100,
    startMicroseconds: pid,
  });
  const payload = identity(20, request.uid, request.gid, 55),
    helpers = [identity(10), identity(11)],
    custodian = identity(100),
    approved = darwinLaunchDigest(request, []),
    receipt = {
      schemaVersion: 1,
      candidateSha: request.candidateSha,
      nonce: request.nonce,
      requestSha256: approved,
      status: "ADMITTED",
      admission: "possible",
      processLimit: 32,
      reservation: "RETAINED",
      payload,
      helpers: helpers.map((identity, index) => ({
        role: index ? "verifier" : "launcher",
        identity,
      })),
    };
  let nextVerifier = 200;
  const calls = [],
    records = [],
    verifier = () => identity(nextVerifier++),
    enumeration = (live = [], zombies = []) => ({
      uid: request.uid,
      complete: true,
      capacity: 33,
      live,
      zombies,
    }),
    views = [
      [
        { ...payload, pidVersion: 2 },
        { ...payload, pid: 21, startMicroseconds: 21 },
      ],
      [{ ...payload, pid: 22, startMicroseconds: 22 }],
      [],
    ];
  const effects = {
    persist: async (record) => records.push(structuredClone(record)),
    recover: async () => ({
      receipt: structuredClone(receipt),
      receiptSha256: digest(JSON.stringify(receipt) + "\n"),
    }),
    verifyRecovery: async () => ({
      bindings: request.bindings,
      requestSha256: approved,
      auditSessionHeld: true,
      asid: 55,
      custodian,
    }),
    stopAdmissions: async () => {
      calls.push("closed");
      return { closed: true, requestSha256: approved, receiptSha256: hash };
    },
    signal: async (_, value, role) => {
      calls.push(role + "-" + value.pid);
      return { identity: value, outcome: "sent", verifier: verifier() };
    },
    enumerate: async () => {
      calls.push("enumerate");
      return {
        enumeration: enumeration(views.shift() ?? []),
        verifier: verifier(),
      };
    },
    verifyRetirement: async () => {
      calls.push("fresh");
      return {
        verifier: verifier(),
        enumeration: enumeration(),
        bindings: request.bindings,
        stopSha256: hash,
        helpersSettled: helpers,
        custodyStillHeld: true,
        custodian,
      };
    },
    settleCustody: async () => {
      calls.push("custody-settled");
      return {
        custodian,
        verifier: verifier(),
        settled: true,
        independent: true,
      };
    },
  };
  const options = {
    platform: "darwin",
    architecture: "x64",
    uid: 0,
    env: { CI: "true", GITHUB_ACTIONS: "true", ImageOS: "macos15" },
    now: () => 0,
  };
  return {
    request,
    payload,
    helpers,
    custodian,
    receipt,
    approved,
    calls,
    records,
    effects,
    options,
    enumeration,
    verifier,
    run: () => retireDarwinDomain(request, approved, effects, options),
  };
}

function ownershipFixture(caseId = "cancel") {
  const f = fixture(),
    calls = [],
    observation = {
      caseId,
      nonce: f.request.nonce,
      attempted: true,
      independent: true,
      outsideUnchanged: true,
      nativeEventSha256: "a".repeat(64),
      bytesSha256: "b".repeat(64),
      members: [f.payload, { ...f.payload, pid: 21, startMicroseconds: 21 }],
    },
    acknowledgement = {
      caseId,
      nonce: f.request.nonce,
      armed: true,
      receiptSha256: "c".repeat(64),
    },
    retired = {
      status: "RETIRED",
      candidateSha: f.request.candidateSha,
      nonce: f.request.nonce,
      requestSha256: f.approved,
      domain: { uid: f.request.uid, gid: f.request.gid, asid: 55 },
      helpersSettled: true,
      reservation: "RETAINED",
      freshVerifier: f.verifier(),
    },
    fresh = {
      verifier: f.verifier(),
      independent: true,
      noLiveMembers: true,
      helpersSettled: true,
      outsideUnchanged: true,
      nonce: f.request.nonce,
      requestSha256: f.approved,
    };
  const effects = {
    persist: async () => {},
    admit: async () => structuredClone(f.receipt),
    observe: async () => structuredClone(observation),
    armFault: async () => structuredClone(acknowledgement),
    fireFault: async () => calls.push("fault"),
    recoverAndRetire: async () => structuredClone(retired),
    verify: async () => structuredClone(fresh),
  };
  return {
    ...f,
    calls,
    observation,
    acknowledgement,
    retired,
    fresh,
    effects,
    run: () => runDarwinOwnershipCase(caseId, f.request, effects),
  };
}

test("Darwin recovery stops verified helpers, follows late forks and independently settles custody", async () => {
  const f = fixture(),
    result = await f.run();
  assert.equal(result.status, "RETIRED");
  assert.equal(result.reservation, "RETAINED");
  assert.equal(result.helpersSettled, true);
  assert.deepEqual(f.calls, [
    "closed",
    "helper-10",
    "helper-11",
    "enumerate",
    "member-20",
    "member-21",
    "enumerate",
    "member-22",
    "enumerate",
    "fresh",
    "custody-settled",
  ]);
  assert.equal(
    result.members.find((value) => value.pid === 20 && value.pidVersion === 2)
      .asid,
    55,
  );
  assert.ok(
    f.records.some(
      (value) =>
        value.pending?.identity.pid === 22 && value.status === "RUNNING",
    ),
  );
  assert.ok(result.freshVerifier);
});

test("Darwin recovery rejects altered receipts and preserves exact unavailable inputs", async () => {
  for (const failure of [
    "missing",
    "audit",
    "candidate",
    "digest",
    "source",
    "abi",
  ]) {
    const f = fixture();
    if (failure === "missing") delete f.effects.enumerate;
    if (failure === "audit") f.receipt.payload = null;
    if (failure === "candidate") f.receipt.candidateSha = "f".repeat(40);
    if (failure === "digest")
      f.effects.recover = async () => ({
        receipt: f.receipt,
        receiptSha256: "f".repeat(64),
      });
    if (failure === "source")
      f.effects.verifyRecovery = async () => ({
        bindings: { ...f.request.bindings, source: "f".repeat(64) },
      });
    if (failure === "abi")
      f.effects.verifyRecovery = async () => ({
        missingInputs: ["darwin.SDK.proc_signal_with_audittoken"],
      });
    const result = await f.run();
    assert.equal(
      result.status,
      ["missing", "audit", "abi"].includes(failure) ? "BLOCKED" : "FAIL",
      failure,
    );
    assert.equal(result.reservation, "RETAINED");
    assert.deepEqual(f.calls, []);
    if (failure === "abi")
      assert.deepEqual(result.missingInputs, [
        "darwin.SDK.proc_signal_with_audittoken",
      ]);
  }
});

test("Darwin repeated recovery retains helpers from every interrupted custodian", async () => {
  const f = fixture(),
    older = { ...f.custodian, pid: 600, startMicroseconds: 600 },
    previous = {
      schemaVersion: 1,
      candidateSha: f.request.candidateSha,
      nonce: f.request.nonce,
      requestSha256: f.approved,
      reservation: "RETAINED",
      helpers: [...f.helpers, older],
      members: [f.payload],
      custodian: { ...f.custodian, pid: 601, startMicroseconds: 601 },
    },
    recover = f.effects.recover,
    verify = f.effects.verifyRetirement;
  f.effects.recover = async () => ({
    ...(await recover()),
    previousRetirement: structuredClone(previous),
  });
  f.effects.verifyRetirement = async () => ({
    ...(await verify()),
    helpersSettled: [...previous.helpers, previous.custodian],
  });
  const result = await f.run();
  assert.equal(result.status, "RETIRED");
  assert.deepEqual(f.calls.slice(0, 6), [
    "closed",
    "helper-10",
    "helper-11",
    "helper-600",
    "helper-601",
    "enumerate",
  ]);
  assert.equal(result.helpers.length, 4);
  const complete = structuredClone(previous);
  for (const failure of [
    "nonce",
    "members",
    "helpers",
    "custodian",
    "missing-helpers",
  ]) {
    Object.assign(previous, structuredClone(complete));
    if (failure === "missing-helpers") delete previous.helpers;
    else previous[failure] = failure === "nonce" ? "f".repeat(32) : null;
    assert.equal((await f.run()).status, "FAIL", failure);
  }
});

test("Darwin retirement retains exclusion for partial views, foreign domains, stale signals and uncertain helpers", async () => {
  for (const failure of [
    "truncated",
    "duplicate",
    "foreign",
    "unknown-zombie",
    "stale",
    "helpers",
    "same-verifier",
    "custody",
    "deadline",
    "work",
  ]) {
    const f = fixture();
    if (failure === "truncated")
      f.effects.enumerate = async () => ({
        verifier: f.verifier(),
        enumeration: { ...f.enumeration(), complete: false },
      });
    if (failure === "duplicate")
      f.effects.enumerate = async () => ({
        verifier: f.verifier(),
        enumeration: f.enumeration([f.payload, f.payload]),
      });
    if (failure === "foreign")
      f.effects.enumerate = async () => ({
        verifier: f.verifier(),
        enumeration: f.enumeration([{ ...f.payload, asid: 56 }]),
      });
    if (failure === "unknown-zombie")
      f.effects.enumerate = async () => ({
        verifier: f.verifier(),
        enumeration: f.enumeration([], [{ pid: 999 }]),
      });
    if (failure === "stale")
      f.effects.signal = async (_, identity) => ({
        identity,
        verifier: f.verifier(),
        outcome: "stale",
      });
    if (failure === "helpers" || failure === "same-verifier") {
      const original = f.effects.verifyRetirement;
      f.effects.verifyRetirement = async () => ({
        ...(await original()),
        ...(failure === "helpers"
          ? { helpersSettled: [] }
          : { verifier: f.helpers[0] }),
      });
    }
    if (failure === "custody")
      f.effects.settleCustody = async () => ({
        custodian: f.custodian,
        settled: true,
        independent: false,
      });
    if (failure === "deadline") {
      let first = true;
      f.options.now = () => {
        if (first) {
          first = false;
          return 0;
        }
        return 30001;
      };
    }
    if (failure === "work")
      f.effects.enumerate = async () => ({
        verifier: f.verifier(),
        enumeration: f.enumeration([f.payload]),
      });
    const result = await f.run();
    assert.equal(result.status, "FAIL", failure);
    assert.equal(result.reservation, "RETAINED");
    assert.equal(result.helpersSettled, false);
    assert.ok(!f.records.some((value) => value.status === "RETIRED"), failure);
  }
});

test("Darwin zombie observations require a previously verified native identity", () => {
  const f = fixture(),
    dead = Object.fromEntries(
      Object.entries(f.payload).filter(
        ([key]) => !["auid", "asid", "pidVersion"].includes(key),
      ),
    );
  assert.equal(
    assessDarwinEnumeration(f.enumeration([], [dead]), f.request, 55, [
      f.payload,
    ]).live.length,
    0,
  );
  assert.throws(() =>
    assessDarwinEnumeration(f.enumeration([], [dead]), f.request, 55),
  );
  assert.throws(() =>
    assessDarwinEnumeration(
      f.enumeration([], [{ ...dead, startMicroseconds: 999 }]),
      f.request,
      55,
      [f.payload],
    ),
  );
});

test("Darwin retirement never starts a signal after receipt persistence consumes the deadline", async () => {
  const f = fixture();
  let time = 0;
  f.options.now = () => time;
  f.effects.persist = async (record) => {
    if (record.pending) time = 30001;
  };
  const result = await f.run();
  assert.equal(result.status, "FAIL");
  assert.deepEqual(f.calls, ["closed"]);
  assert.equal(result.pending.identity.pid, f.helpers[0].pid);
  assert.equal(result.reservation, "RETAINED");
});

test("Darwin native signal vectors bind the full token and reject foreign credentials without PID reuse", () => {
  const f = fixture();
  const vector = darwinRetirementArguments("signal", f.request, f.payload);
  assert.deepEqual(vector, [
    "--signal",
    "90001",
    "90001",
    "90002",
    "90001",
    "90002",
    "20",
    "55",
    "1",
    "100",
    "20",
    "90001",
    "90002",
  ]);
  assert.notDeepEqual(
    vector,
    darwinRetirementArguments("signal", f.request, {
      ...f.payload,
      pidVersion: 2,
    }),
  );
  assert.throws(() =>
    darwinRetirementArguments("signal", f.request, { ...f.payload, svuid: 0 }),
  );
  assert.throws(() =>
    darwinRetirementArguments("signal", f.request, { ...f.payload, pid: 1 }),
  );
  assert.deepEqual(darwinRetirementArguments("members", f.request), [
    "--members",
    "90001",
  ]);
});

test("Darwin fault cases require the matching acknowledged native barrier before effects", async () => {
  for (const wrongNonce of [false, true]) {
    const f = ownershipFixture();
    if (wrongNonce) f.acknowledgement.nonce = "f".repeat(32);
    const result = await f.run();
    assert.equal(result.status, wrongNonce ? "FAIL" : "OBSERVED");
    assert.deepEqual(f.calls, wrongNonce ? [] : ["fault"]);
    assert.equal(result.reservation, "RETAINED");
    if (wrongNonce)
      assert.deepEqual(result.cleanup, {
        status: "RETIRED",
        helpersSettled: true,
      });
  }
});

test("Darwin stale-token observations join the admitted process and independently observed execution epoch", async () => {
  for (const failure of [null, "foreign", "unobserved", "other-process"]) {
    const f = ownershipFixture("stale-identity"),
      before = { ...f.payload, pidVersion: 2 },
      after = { ...f.payload, pidVersion: 3 };
    if (failure === "foreign") before.asid++;
    if (failure === "unobserved") after.pidVersion++;
    if (failure === "other-process") {
      before.pid = after.pid = 21;
      before.startMicroseconds = after.startMicroseconds = 21;
    }
    f.observation.members = [{ ...f.payload, pidVersion: 3 }];
    Object.assign(f.observation, {
      before,
      after,
      staleRejected: true,
      forcedPidReuse: false,
    });
    const result = await f.run();
    assert.equal(result.status, failure ? "FAIL" : "OBSERVED", failure);
    assert.deepEqual(f.calls, failure ? [] : ["fault"]);
  }
});

test("Darwin ownership cases reject retirement of a different domain or a reused verifier", async () => {
  for (const failure of ["domain", "missing-verifier", "same-process"]) {
    const f = ownershipFixture();
    if (failure === "domain") f.retired.domain.asid++;
    if (failure === "missing-verifier") delete f.retired.freshVerifier;
    if (failure === "same-process")
      f.fresh.verifier = { ...f.retired.freshVerifier, pidVersion: 2 };
    const result = await f.run();
    assert.equal(result.status, "FAIL", failure);
    assert.equal(result.reservation, "RETAINED");
    assert.equal(
      result.cleanup.status,
      failure === "same-process" ? "RETIRED" : "RETAINED",
      failure,
    );
  }
});
