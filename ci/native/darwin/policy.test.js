import assert from "node:assert/strict";
import test from "node:test";
import {
  DARWIN_ACCESS_DENIALS,
  assertDarwinAccessObservation,
  assertDarwinPfSettlement,
  buildDarwinPolicy,
  configureDarwinPolicy,
  darwinPfctlArguments,
  runDarwinAccessCase,
} from "./index.js";
import { digest } from "./protocol.js";
const HASH = "a".repeat(64),
  CANDIDATE = "b".repeat(40),
  NONCE = "c".repeat(32);
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
function fixture(profile = "workspace-write") {
  const input = {
    request: {
      schemaVersion: 1,
      candidateSha: CANDIDATE,
      nonce: NONCE,
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
      bindings: { system: HASH, source: HASH, closure: HASH, policy: HASH },
    },
    profile,
    disposable: true,
    metadata: "/fixture/storage/metadata",
    pointer: "/fixture/storage/work/.git",
    checkout: "/protected/checkout",
    configuration: "/protected/config",
    credentials: "/protected/credentials",
    runtime: [
      {
        path: "/fixture/storage/payload",
        sha256: HASH,
        executable: true,
        mapped: true,
      },
      { path: "/usr/lib/dyld", sha256: HASH, executable: false, mapped: true },
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
    reviewSha256: HASH,
  };
  let plan = buildDarwinPolicy(input);
  input.request.policy.sha256 = plan.seatbeltSha256;
  input.request.bindings.policy = plan.compositionSha256;
  plan = buildDarwinPolicy(input);
  let current = "f".repeat(64),
    sequence = 100;
  const calls = [],
    records = [];
  const snapshot = () => ({
    candidateSha: CANDIDATE,
    nonce: NONCE,
    compositionSha256: plan.compositionSha256,
    reviewSha256: HASH,
    anchor: plan.anchor,
    anchorSha256: current,
    savedAnchorSha256: "f".repeat(64),
    rootSha256: HASH,
    evidenceSha256: HASH,
    reservationSha256: HASH,
    active: true,
    loopbackFiltered: true,
    anchorReachable: true,
    anchorQuick: true,
    earlierMatchingQuickRules: 0,
    conflictingStates: 0,
    conflictingNat: 0,
    skipExemptions: 0,
    unfilteredRoutes: 0,
    endpointsExclusive: true,
    ownerLookup: "sending-out-receiving-in",
    unknownOwner: "blocked",
    ruleState: "none",
    anchorOwned: true,
    exclusiveWriter: true,
    admissionsClosed: true,
    independent: true,
    verifier: identity(sequence++),
  });
  const effects = {
    persist: async (value) => records.push(structuredClone(value)),
    review: async () => ({
      approvedSha256: plan.compositionSha256,
      reviewSha256: HASH,
      toolSha256: HASH,
    }),
    snapshot: async () => snapshot(),
    stage: async () => ({
      seatbeltSha256: plan.seatbeltSha256,
      pfSha256: plan.pfSha256,
      restoreSha256: "f".repeat(64),
      receiptSha256: HASH,
      immutable: true,
    }),
    pfctl: async (_, args) => {
      calls.push(args);
      if (!args.includes("-n"))
        current = args.at(-1).endsWith("before.conf")
          ? "f".repeat(64)
          : plan.pfSha256;
      return {
        exitCode: 0,
        signal: null,
        timedOut: false,
        toolSha256: HASH,
        settled: true,
        helper: identity(sequence++),
        worker: identity(sequence++),
        verifier: identity(sequence++),
        receiptSha256: HASH,
      };
    },
    verifySettlement: async (_, record) => ({
      independent: true,
      helpersSettled: true,
      compositionSha256: plan.compositionSha256,
      verifier: identity(sequence++),
      helpers: record.helperReceipts.flatMap((entry) => [
        entry.helper,
        entry.worker,
      ]),
    }),
    verifyRetirement: async (_, retired) => ({
      independent: true,
      noLiveUid: true,
      helpersSettled: true,
      uid: 90001,
      gid: 90002,
      asid: 55,
      requestSha256: retired.requestSha256,
      authoritySha256: plan.compositionSha256,
      receiptSha256: HASH,
      verifier: identity(sequence++),
    }),
  };
  const options = {
    platform: "darwin",
    architecture: "x64",
    uid: 0,
    env: { CI: "true", GITHUB_ACTIONS: "true", ImageOS: "macos15" },
    now: () => 0,
  };
  return {
    input,
    plan,
    calls,
    records,
    snapshot,
    effects,
    options,
    install: () =>
      configureDarwinPolicy(input, plan.compositionSha256, effects, options),
  };
}

test("Darwin policies seal writable roots, images and both directions of every private flow", () => {
  for (const profile of ["read-only", "workspace-write", "trusted-command"]) {
    const f = fixture(profile),
      { seatbelt, pf } = f.plan;
    assert.match(seatbelt, /^\(version 1\)\n\(deny default\)/u);
    assert.equal(
      seatbelt.includes("(allow file-write*"),
      profile !== "read-only",
    );
    assert.ok(
      !seatbelt.includes("(allow mach-") &&
        !seatbelt.includes("(allow ipc-") &&
        !seatbelt.includes("unix-socket") &&
        !seatbelt.includes("localhost:*"),
    );
    for (const endpoint of f.input.endpoints)
      for (const direction of ["in", "out"])
        for (const [source, destination] of [
          [endpoint.clientPort, endpoint.serverPort],
          [endpoint.serverPort, endpoint.clientPort],
        ]) {
          const address = endpoint.family === "inet" ? "127.0.0.1" : "::1";
          const expected = `pass ${direction} quick on lo0 ${endpoint.family} proto ${endpoint.protocol} from ${address} port ${source} to ${address} port ${destination} user = 90001`;
          assert.ok(
            pf
              .split("\n")
              .some(
                (line) =>
                  line.startsWith(expected) && line.endsWith("no state"),
              ),
          );
        }
    assert.equal(
      pf.split("\n").filter((line) => line.startsWith("pass ")).length,
      16,
    );
    assert.ok(!pf.includes("keep state") && !pf.includes("user !="));
    assert.ok(
      pf.includes(
        "block return quick inet proto tcp from any to 127.0.0.1 port 41002",
      ),
    );
  }
});

test("Darwin policy inputs reject broad images, host aliases, collisions and unreviewed disposable grants", () => {
  for (const failure of [
    "runtime",
    "execute",
    "workspace-image",
    "alias",
    "collision",
    "disposable",
    "pointer",
    "review",
    "control-path",
    "metadata-root",
    "metadata-parent",
  ]) {
    const f = fixture("trusted-command");
    if (failure === "runtime") f.input.runtime[1].path = "/usr/lib";
    if (failure === "execute") f.input.runtime[1].executable = true;
    if (failure === "workspace-image")
      f.input.runtime[0].path = f.input.request.workspace + "/payload";
    if (failure === "alias")
      f.input.configuration = "/fixture/storage/work/../config";
    if (failure === "collision") f.input.endpoints[1].clientPort = 41001;
    if (failure === "disposable") f.input.disposable = false;
    if (failure === "pointer")
      f.input.pointer = "/fixture/storage/work/nested/.git";
    if (failure === "review") f.input.reviewSha256 = "observed";
    if (failure === "control-path")
      f.input.request.workspace = "/fixture/storage/work\n";
    if (failure === "metadata-root")
      f.input.metadata = f.input.request.workspace;
    if (failure === "metadata-parent") {
      f.input.metadata = f.input.request.workspace;
      f.input.request.workspace += "/nested";
      f.input.pointer = f.input.request.workspace + "/.git";
    }
    assert.throws(() => buildDarwinPolicy(f.input), failure);
  }
  const f = fixture();
  f.input.request.policy.path += "-substitute";
  assert.notEqual(
    buildDarwinPolicy(f.input).compositionSha256,
    f.plan.compositionSha256,
  );
});

test("Darwin PF setup applies only a fixed anchor and restores only after fresh independent retirement", async () => {
  const f = fixture(),
    installed = await f.install();
  assert.equal(installed.status, "INSTALLED");
  assert.deepEqual(f.calls, [
    darwinPfctlArguments(f.input, "validate"),
    darwinPfctlArguments(f.input, "install"),
  ]);
  const retired = {
    status: "RETIRED",
    helpersSettled: true,
    candidateSha: CANDIDATE,
    nonce: NONCE,
    requestSha256: HASH,
    authoritySha256: f.plan.compositionSha256,
    reservation: "RETAINED",
    domain: { uid: 90001, gid: 90002, asid: 55 },
    freshVerifier: identity(600),
  };
  const restored = await configureDarwinPolicy(
    f.input,
    f.plan.compositionSha256,
    f.effects,
    {
      ...f.options,
      operation: "restore",
      previous: installed,
      retirement: retired,
    },
  );
  assert.equal(restored.status, "RESTORED");
  assert.equal(restored.reservation, "RETAINED");
  assert.deepEqual(f.calls.slice(2), [
    darwinPfctlArguments(f.input, "validate-restore"),
    darwinPfctlArguments(f.input, "restore"),
  ]);
});

test("Darwin PF settlement rejects receipts for missing or stale native helpers", () => {
  const helper = identity(20),
    worker = identity(21),
    receipt = {
      independent: true,
      settled: true,
      operationSha256: HASH,
      receiptSha256: HASH,
      verifier: identity(22),
      helper,
      worker,
    };
  assert.deepEqual(
    assertDarwinPfSettlement(receipt, helper, worker, HASH),
    receipt.verifier,
  );
  for (const key of ["helper", "worker"]) {
    const missing = structuredClone(receipt);
    delete missing[key];
    assert.throws(() =>
      assertDarwinPfSettlement(missing, helper, worker, HASH),
    );
    const stale = structuredClone(receipt);
    stale[key].pidVersion++;
    assert.throws(() => assertDarwinPfSettlement(stale, helper, worker, HASH));
  }
});

test("Darwin policy execution snapshots receipts and native facts before awaited effects", async () => {
  const f = fixture(),
    installed = await f.install();
  const retired = {
    status: "RETIRED",
    helpersSettled: true,
    candidateSha: CANDIDATE,
    nonce: NONCE,
    requestSha256: HASH,
    authoritySha256: f.plan.compositionSha256,
    reservation: "RETAINED",
    domain: { uid: 90001, gid: 90002, asid: 55 },
    freshVerifier: identity(600),
  };
  const snapshot = f.effects.snapshot,
    stage = f.effects.stage,
    verifyRetirement = f.effects.verifyRetirement,
    verifySettlement = f.effects.verifySettlement;
  let lastView;
  f.effects.snapshot = async (...args) => {
    lastView = await snapshot(...args);
    installed.before.savedAnchorSha256 = "e".repeat(64);
    retired.domain.uid = 90003;
    return lastView;
  };
  f.effects.stage = async (input, files) => {
    assert.equal(files.restoreSha256, "f".repeat(64));
    return stage(input, files);
  };
  f.effects.verifyRetirement = async (input, receipt) => {
    assert.equal(receipt.domain.uid, 90001);
    return verifyRetirement(input, receipt);
  };
  f.effects.verifySettlement = async (...args) => {
    lastView.active = false;
    return verifySettlement(...args);
  };
  const restored = await configureDarwinPolicy(
    f.input,
    f.plan.compositionSha256,
    f.effects,
    {
      ...f.options,
      operation: "restore",
      previous: installed,
      retirement: retired,
    },
  );
  assert.equal(restored.status, "RESTORED");
  assert.equal(restored.effective.active, true);
  assert.equal(restored.before.savedAnchorSha256, "f".repeat(64));
});

test("Darwin PF setup retains exclusion on missing SDK review, unsafe effective state or exhausted persistence budget", async () => {
  for (const failure of [
    "sdk",
    "state",
    "skip",
    "inactive",
    "root-race",
    "unknown",
    "saved",
    "worker",
    "budget",
  ]) {
    const f = fixture();
    if (failure === "sdk")
      f.effects.review = async () => ({
        missingInputs: ["darwin.SDK.Seatbelt.socket-protocol"],
      });
    if (
      ["state", "skip", "inactive", "unknown", "root-race", "saved"].includes(
        failure,
      )
    ) {
      let count = 0;
      f.effects.snapshot = async () => ({
        ...f.snapshot(),
        ...(failure === "state"
          ? { conflictingStates: 1 }
          : failure === "skip"
            ? { skipExemptions: 1 }
            : failure === "inactive"
              ? { active: false }
              : failure === "unknown"
                ? { unknownOwner: "allowed" }
                : failure === "saved"
                  ? { savedAnchorSha256: "e".repeat(64) }
                  : ++count > 1
                    ? { rootSha256: "e".repeat(64) }
                    : {}),
      });
    }
    if (failure === "worker") {
      const perform = f.effects.pfctl;
      f.effects.pfctl = async (...args) => ({
        ...(await perform(...args)),
        worker: identity(0),
      });
    }
    if (failure === "budget") {
      let time = 0;
      f.options.now = () => time;
      f.effects.persist = async (value) => {
        if (value.phase === "pf-install") time = 30001;
      };
    }
    const result = await f.install();
    assert.equal(
      result.status,
      failure === "sdk" ? "BLOCKED" : "FAIL",
      failure,
    );
    assert.equal(result.reservation, "RETAINED");
    assert.ok(!f.calls.some((args) => !args.includes("-n")), failure);
    if (failure === "sdk")
      assert.deepEqual(result.missingInputs, [
        "darwin.SDK.Seatbelt.socket-protocol",
      ]);
  }
});

test("Darwin restoration requires a fresh empty UID view and unchanged owned reservations before writing", async () => {
  for (const failure of ["live", "settlement", "reservation", "saved"]) {
    const f = fixture(),
      installed = await f.install();
    const retired = {
      status: "RETIRED",
      helpersSettled: true,
      candidateSha: CANDIDATE,
      nonce: NONCE,
      requestSha256: HASH,
      authoritySha256: f.plan.compositionSha256,
      reservation: "RETAINED",
      domain: { uid: 90001, gid: 90002, asid: 55 },
      freshVerifier: identity(600),
    };
    const verify = f.effects.verifyRetirement;
    f.effects.verifyRetirement = async (...args) => ({
      ...(await verify(...args)),
      ...(failure === "live"
        ? { noLiveUid: false }
        : failure === "settlement"
          ? { helpersSettled: false }
          : {}),
    });
    if (failure === "reservation")
      f.effects.snapshot = async () => ({
        ...f.snapshot(),
        reservationSha256: "e".repeat(64),
      });
    if (failure === "saved")
      installed.before.savedAnchorSha256 = "e".repeat(64);
    const result = await configureDarwinPolicy(
      f.input,
      f.plan.compositionSha256,
      f.effects,
      {
        ...f.options,
        operation: "restore",
        previous: installed,
        retirement: retired,
      },
    );
    assert.equal(result.status, "FAIL", failure);
    assert.equal(result.reservation, "RETAINED");
    assert.equal(
      f.calls.length,
      2,
      "Uncertain retirement must not run any restoration command",
    );
  }
});

function observation(f) {
  const payload = identity(20, 90001, 90002, 55),
    requestSha256 = HASH;
  const value = {
    candidateSha: CANDIDATE,
    nonce: NONCE,
    compositionSha256: f.plan.compositionSha256,
    requestSha256,
    verifier: identity(700),
    independent: true,
    inspectionSha256: digest(NONCE),
    inspectionObservation: {
      identity: payload,
      attempted: true,
      code: "OK",
      nativeDecision: "permit",
      bytesSha256: digest(NONCE),
      nativeEventSha256: HASH,
    },
    edit: f.input.profile === "read-only" ? "denied" : "permitted",
    editEventSha256: HASH,
    editObservation: {
      identity: payload,
      attempted: true,
      beforeSha256: digest(NONCE),
      afterSha256: digest(
        f.input.profile === "read-only" ? NONCE : NONCE + "-edit",
      ),
      code: f.input.profile === "read-only" ? "EPERM" : "OK",
      nativeDecision: f.input.profile === "read-only" ? "deny" : "permit",
    },
    protectedUnchanged: true,
    policyPreserved: true,
    denials: DARWIN_ACCESS_DENIALS.map((id) => ({
      id,
      identity: payload,
      attempted: true,
      denied: true,
      timedOut: false,
      code: "EPERM",
      nativeDecision: "deny",
      nativeEventSha256: HASH,
      beforeSha256: HASH,
      afterSha256: HASH,
      control: {
        identity: identity(701),
        ready: true,
        reachable: true,
        independent: true,
        discretionaryAllowed: true,
        nonce: NONCE,
        acknowledgementSha256: HASH,
        nativeEventSha256: HASH,
        targetSha256: HASH,
      },
    })),
    loopback: f.input.endpoints.map((endpoint) => ({
      family: endpoint.family,
      protocol: endpoint.protocol,
      requestSha256: digest(NONCE),
      responseSha256: digest(NONCE),
      timedOut: false,
      events: ["request", "return"].flatMap((leg) =>
        ["out", "in"].map((direction) => ({
          leg,
          direction,
          identity: payload,
          decision: "permit",
          ownerUid: 90001,
          nativeEventSha256: HASH,
          sourceAddress: endpoint.family === "inet" ? "127.0.0.1" : "::1",
          destinationAddress: endpoint.family === "inet" ? "127.0.0.1" : "::1",
          sourcePort:
            leg === "request" ? endpoint.clientPort : endpoint.serverPort,
          destinationPort:
            leg === "request" ? endpoint.serverPort : endpoint.clientPort,
        })),
      ),
    })),
  };
  return {
    value,
    admitted: {
      status: "ADMITTED",
      candidateSha: CANDIDATE,
      nonce: NONCE,
      requestSha256,
      payload,
      authority: { policy: { compositionSha256: f.plan.compositionSha256 } },
    },
  };
}

test("Darwin access proof rejects timeout, missing native attempts, unready controls and wrong return owners", () => {
  for (const failure of [
    null,
    "timeout",
    "missing",
    "text-only",
    "control",
    "owner",
    "edit",
    "read",
  ]) {
    const f = fixture("read-only"),
      { value, admitted } = observation(f);
    if (failure === "timeout") value.denials[0].timedOut = true;
    if (failure === "missing") value.denials.pop();
    if (failure === "text-only") delete value.denials[0].nativeEventSha256;
    if (failure === "control") value.denials[0].control.ready = false;
    if (failure === "owner") value.loopback[0].events[3].ownerUid = 90003;
    if (failure === "edit") value.editObservation.afterSha256 = HASH;
    if (failure === "read")
      delete value.inspectionObservation.nativeEventSha256;
    if (failure)
      assert.throws(
        () => assertDarwinAccessObservation(value, f.input, admitted),
        failure,
      );
    else assertDarwinAccessObservation(value, f.input, admitted);
  }
});

test("Darwin access cases require native proof and preserve failure after verified policy restoration", async () => {
  const f = fixture(),
    installed = await f.install(),
    { value, admitted } = observation(f);
  const phases = [],
    retired = {
      status: "RETIRED",
      helpersSettled: true,
      caseHelpersSettled: true,
      candidateSha: CANDIDATE,
      nonce: NONCE,
      requestSha256: HASH,
      authoritySha256: f.plan.compositionSha256,
      domain: { uid: 90001, gid: 90002, asid: 55 },
      freshVerifier: identity(800),
      reservation: "RETAINED",
    };
  const effects = {
    persist: async () => {},
    prepare: async () => ({ policy: installed, launchSha256: HASH }),
    verifyPolicy: async () => installed,
    admit: async () => admitted,
    observe: async () => value,
    retire: async () => {
      phases.push("retire");
      return retired;
    },
    restore: async () => {
      phases.push("restore");
      return { ...installed, status: "RESTORED" };
    },
  };
  const observed = await runDarwinAccessCase(f.input, effects);
  assert.equal(observed.status, "OBSERVED");
  assert.equal(
    observed.nativeEvidence.denials.length,
    DARWIN_ACCESS_DENIALS.length,
  );
  assert.deepEqual(phases, ["retire", "restore"]);
  phases.length = 0;
  effects.persist = async (record) => {
    if (record.phase === "restoration") {
      retired.domain.asid++;
      retired.requestSha256 = "f".repeat(64);
    }
  };
  effects.restore = async (_, receipt) => {
    assert.equal(receipt.domain.asid, 55);
    assert.equal(receipt.requestSha256, HASH);
    phases.push("restore");
    return { ...installed, status: "RESTORED" };
  };
  const immutable = await runDarwinAccessCase(f.input, effects);
  assert.equal(immutable.status, "OBSERVED");
  assert.deepEqual(phases, ["retire", "restore"]);
  retired.domain.asid = 55;
  retired.requestSha256 = HASH;
  effects.persist = async () => {};
  phases.length = 0;
  value.denials[0].control.ready = false;
  const result = await runDarwinAccessCase(f.input, effects);
  assert.equal(result.status, "FAIL");
  assert.equal(result.cleanup.status, "RESTORED");
  assert.deepEqual(phases, ["retire", "restore"]);
  retired.domain.asid++;
  const failed = await runDarwinAccessCase(f.input, {
    persist: async () => {},
    prepare: async () => ({ policy: installed, launchSha256: HASH }),
    verifyPolicy: async () => installed,
    admit: async () => admitted,
    observe: async () => value,
    retire: async () => retired,
    restore: async () => {
      assert.fail("Unbound retirement must not restore policy");
    },
  });
  assert.equal(failed.cleanup.status, "RETAINED");
});
