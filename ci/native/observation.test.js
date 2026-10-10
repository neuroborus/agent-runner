import assert from "node:assert/strict";
import test from "node:test";
import {
  observationDigest,
  normalizeToolObservationPlan,
  assertNativeToolAttempt,
  joinNativeToolObservations,
} from "./index.js";
import {
  assertLinuxObserverEvent,
  createLinuxObserverDecoder,
  runLinuxToolObserver,
} from "./linux/index.js";
import {
  assertDarwinObserverEvent,
  runDarwinToolObserver,
} from "./darwin/index.js";
import {
  assertWindowsObserverEvent,
  windowsObserverConfiguration,
  runWindowsToolObserver,
} from "./win32/index.js";

const sha = (value) => observationDigest(value);
function fixture(domain = { fixture: 1 }) {
  const plan = {
    schemaVersion: 1,
    candidateSha: "a".repeat(40),
    nonce: "b".repeat(32),
    domainSha256: sha(domain),
    policySha256: sha("policy"),
    reviewSha256: sha("review"),
    routes: [
      {
        id: "inspect",
        operation: "read",
        targetSha256: sha("target"),
        permitTargetSha256: sha("permit"),
        denyTargetSha256: sha("deny"),
        nonceSha256: sha("nonce"),
        beforeSha256: sha("nonce"),
        afterSha256: sha("nonce"),
        outcome: "permit",
      },
    ],
  };
  const events = ["control-permit", "control-deny", "tool"].map(
    (phase, index) => ({
      sequence: index + 1,
      routeId: "inspect",
      phase,
      operation: "read",
      outcome: phase === "control-deny" ? "deny" : "permit",
      nativeId: "native:" + (index + 1),
      subjectSha256: plan.domainSha256,
      targetSha256: sha(["permit", "deny", "target"][index]),
      barrierSha256: sha("barrier" + index),
    }),
  );
  const reads = events.map((event) => ({
    eventSequence: event.sequence,
    routeId: "inspect",
    phase: event.phase,
    targetSha256: event.targetSha256,
    barrierSha256: event.barrierSha256,
    nonceSha256: sha("nonce"),
    beforeSha256: sha("nonce"),
    afterSha256: sha("nonce"),
    sentinelsBeforeSha256: sha("sentinels"),
    sentinelsAfterSha256: sha("sentinels"),
    verifierSha256: sha("reader"),
    independent: true,
  }));
  const value = {
    candidateSha: plan.candidateSha,
    nonce: plan.nonce,
    domainSha256: plan.domainSha256,
    policySha256: plan.policySha256,
    observerSha256: sha("observer"),
    providerStartSequence: 3,
    events,
    reads,
    health: {
      complete: true,
      dropped: 0,
      truncated: 0,
      ambiguous: 0,
      overflow: false,
      bytes: 1024,
    },
    settlement: {
      candidateSha: plan.candidateSha,
      nonce: plan.nonce,
      domainSha256: plan.domainSha256,
      payloadsRetired: true,
      observersRetired: true,
      independent: true,
      verifierSha256: sha("fresh-reader"),
      beforeAuditSha256: sha("before-audit"),
      installedAuditSha256: sha("installed-audit"),
      restoredAuditSha256: sha("before-audit"),
      ownedChangesOnly: true,
      reservation: "RETAINED",
    },
  };
  return { plan, value };
}

test("native join rejects missing attempts, late controls, loss and unretired custody", () => {
  const { plan, value } = fixture();
  assert.equal(joinNativeToolObservations(plan, value).status, "OBSERVED");
  for (const change of [
    (v) => v.events.pop(),
    (v) => {
      v.events[2].providerText = "tool completed";
    },
    (v) => {
      v.events[2].nativeId = v.events[0].nativeId;
    },
    (v) => {
      v.events[2].barrierSha256 = v.events[0].barrierSha256;
      v.reads[2].barrierSha256 = v.events[0].barrierSha256;
    },
    (v) => {
      v.events[2].subjectSha256 = sha("foreign-domain");
    },
    (v) => {
      v.events[2].targetSha256 = sha("foreign-object");
    },
    (v) => {
      v.providerStartSequence = 2;
    },
    (v) => {
      v.providerStartSequence = 4;
    },
    (v) => {
      v.health.dropped = 1;
    },
    (v) => {
      v.health.truncated = 1;
    },
    (v) => {
      v.health.ambiguous = 1;
    },
    (v) => {
      v.health.overflow = true;
    },
    (v) => {
      v.health.complete = false;
    },
    (v) => {
      v.health.bytes = 8388609;
    },
    (v) => {
      v.reads[2].nonceSha256 = sha("stale-nonce");
    },
    (v) => {
      v.reads[2].barrierSha256 = sha("stale-barrier");
    },
    (v) => {
      v.reads[2].sentinelsAfterSha256 = sha("changed");
    },
    (v) => {
      v.reads[2].independent = false;
    },
    (v) => {
      v.reads[2].verifierSha256 = v.observerSha256;
    },
    (v) => {
      v.settlement.observersRetired = false;
    },
    (v) => {
      v.settlement.payloadsRetired = false;
    },
    (v) => {
      v.settlement.ownedChangesOnly = false;
    },
    (v) => {
      v.settlement.restoredAuditSha256 = sha("foreign-restoration");
    },
    (v) => {
      v.settlement.candidateSha = "c".repeat(40);
    },
  ]) {
    const invalid = structuredClone(value);
    change(invalid);
    assert.throws(
      () => joinNativeToolObservations(plan, invalid),
      /Unverified/,
    );
  }
});

test("positive-control failure is rejected before a tool window can open", () => {
  const { plan, value } = fixture();
  assertNativeToolAttempt(
    plan,
    value.events[0],
    value.reads[0],
    value.observerSha256,
  );
  for (const mutate of [
    (event, read) => {
      event.outcome = "deny";
    },
    (event, read) => {
      read.afterSha256 = sha("missing-permit-nonce");
    },
    (event, read) => {
      read.verifierSha256 = plan.domainSha256;
    },
  ]) {
    const event = structuredClone(value.events[0]),
      read = structuredClone(value.reads[0]);
    mutate(event, read);
    assert.throws(() =>
      assertNativeToolAttempt(plan, event, read, value.observerSha256),
    );
  }
  const duplicated = structuredClone(plan);
  duplicated.routes.push(duplicated.routes[0]);
  assert.throws(() => normalizeToolObservationPlan(duplicated));
  const accessor = { ...plan };
  Object.defineProperty(accessor, "nonce", {
    enumerable: true,
    get() {
      assert.fail("untrusted getter");
    },
  });
  assert.throws(() => normalizeToolObservationPlan(accessor), /Unverified/);
  const readAccessor = structuredClone(value);
  Object.defineProperty(readAccessor.reads[0], "eventSequence", {
    enumerable: true,
    get() {
      assert.fail("untrusted read getter");
    },
  });
  assert.throws(
    () => joinNativeToolObservations(plan, readAccessor),
    /Unverified/,
  );
});

function nativeFixture(domain, opcode, selector = "/fixture/value") {
  const { plan } = fixture(domain);
  const bindings = ["control-permit", "control-deny", "tool"].map((phase) => ({
    routeId: "inspect",
    phase,
    opcode,
    selector,
    accessMask: null,
    filterId: null,
  }));
  const input = {
    plan,
    domain,
    bindings,
    pins: {
      manifestSha256: plan.reviewSha256,
      sourceSha256: sha("source"),
      imageSha256: sha("image"),
      abiSha256: sha("abi"),
    },
  };
  const bound = {
    independent: true,
    held: true,
    timeBound: true,
    nativeId: "native:3",
    selector,
    objectSha256: plan.routes[0].targetSha256,
  };
  return { input, bound, binding: bindings[2] };
}

test("native attribution rejects reused processes, wrong audit sessions and foreign SID objects", () => {
  const linux = nativeFixture(
    {
      bootId: "11111111-1111-1111-1111-111111111111",
      namespaceId: "pid:[20]",
      initPid: 20,
      initStartTicks: "50",
    },
    "openat",
  );
  linux.bound.before = {
    pid: 21,
    identity: { bootId: linux.input.domain.bootId, startTicks: "51" },
    namespaceId: "pid:[20]",
  };
  linux.bound.after = structuredClone(linux.bound.before);
  const linuxRaw = {
    id: "native:3",
    pid: 21,
    opcode: "openat",
    target: "/fixture/value",
    result: 3,
    errno: null,
  };
  assert.equal(
    assertLinuxObserverEvent(linuxRaw, linux.bound, linux.input, linux.binding),
    "permit",
  );
  linux.bound.after.identity.startTicks = "52";
  assert.throws(() =>
    assertLinuxObserverEvent(linuxRaw, linux.bound, linux.input, linux.binding),
  );
  delete linux.bound.before.identity.startTicks;
  delete linux.bound.after.identity.startTicks;
  assert.throws(() =>
    assertLinuxObserverEvent(linuxRaw, linux.bound, linux.input, linux.binding),
  );
  const darwin = nativeFixture(
    { uid: 501, gid: 501, auid: 501, asid: 7 },
    "72",
  );
  darwin.bound.before = {
    pid: 21,
    pidVersion: 2,
    asid: 7,
    auid: 501,
    uid: 501,
    gid: 501,
    ruid: 501,
    rgid: 501,
    svuid: 501,
    svgid: 501,
    startSeconds: 100,
    startMicroseconds: 2,
  };
  darwin.bound.after = structuredClone(darwin.bound.before);
  const darwinRaw = {
    id: "native:3",
    pid: 21,
    opcode: "72",
    target: "/fixture/value",
    auid: 501,
    asid: 7,
    result: 3,
    error: 0,
  };
  assert.equal(
    assertDarwinObserverEvent(
      darwinRaw,
      darwin.bound,
      darwin.input,
      darwin.binding,
    ),
    "permit",
  );
  darwinRaw.error = 61;
  assert.throws(() =>
    assertDarwinObserverEvent(
      darwinRaw,
      darwin.bound,
      darwin.input,
      darwin.binding,
    ),
  );
  darwin.input.plan.routes[0].operation = "network";
  assert.equal(
    assertDarwinObserverEvent(
      darwinRaw,
      darwin.bound,
      darwin.input,
      darwin.binding,
    ),
    "deny",
  );
  darwinRaw.error = 0;
  darwinRaw.asid = 8;
  assert.throws(() =>
    assertDarwinObserverEvent(
      darwinRaw,
      darwin.bound,
      darwin.input,
      darwin.binding,
    ),
  );
  const win = nativeFixture(
    {
      accountSid: "S-1-5-21-1-2-3-4",
      restrictingSid: "S-1-5-21-1-2-3-5",
      jobSha256: sha("job"),
    },
    "4663",
  );
  win.binding.accessMask = 1;
  win.input.bindings[0].accessMask = 1;
  win.input.bindings[1].accessMask = 1;
  win.bound.before = {
    pid: 21,
    creationTime: "1000",
    sessionId: 0,
    userSid: win.input.domain.accountSid,
  };
  win.bound.after = structuredClone(win.bound.before);
  win.bound.jobSha256 = win.input.domain.jobSha256;
  win.bound.restrictingSid = win.input.domain.restrictingSid;
  const winRaw = {
    id: "native:3",
    pid: 21,
    opcode: "4663",
    target: "/fixture/value",
    subjectSid: win.input.domain.accountSid,
    auditFailure: false,
    accessMask: 1,
    filterId: null,
  };
  const configuration = windowsObserverConfiguration(win.input);
  assert.equal(configuration.systemPolicy, "snapshot-only");
  assert.ok(
    configuration.query.includes(
      "SubjectUserSid']='" + win.input.domain.accountSid,
    ),
  );
  assert.equal(configuration.query.includes("EventID=5156"), false);
  assert.equal(
    assertWindowsObserverEvent(winRaw, win.bound, win.input, win.binding),
    "permit",
  );
  winRaw.accessMask = 0x80000000;
  win.binding.accessMask = 0x80000000;
  assert.equal(
    assertWindowsObserverEvent(winRaw, win.bound, win.input, win.binding),
    "permit",
  );
  winRaw.accessMask = 0x180000000;
  assert.throws(() =>
    assertWindowsObserverEvent(winRaw, win.bound, win.input, win.binding),
  );
  winRaw.accessMask = 0x80000000;
  winRaw.subjectSid = "S-1-5-21-1-2-3-6";
  assert.throws(() =>
    assertWindowsObserverEvent(winRaw, win.bound, win.input, win.binding),
  );
});

test("Linux private-pipe decoder discards arguments and rejects unfinished or ambiguous traces", () => {
  const decoder = createLinuxObserverDecoder(["/fixture/value"]);
  const event = decoder.line(
    '21 100.001 execve("/fixture/value", ["untrusted request text"], 0x1) = 0',
  );
  assert.equal(event.target, "/fixture/value");
  assert.equal(JSON.stringify(event).includes("untrusted request text"), false);
  assert.equal(
    decoder.line(
      '21 100.002 openat(AT_FDCWD, "/unrelated/value", O_RDONLY) = 3',
    ),
    null,
  );
  assert.equal(decoder.finish().complete, true);
  const partial = createLinuxObserverDecoder(["/fixture/value"]);
  partial.line(
    '21 100.003 openat(AT_FDCWD, "/fixture/value", <unfinished ...>',
  );
  assert.throws(() => partial.finish());
  assert.throws(() =>
    partial.line("21 100.004 <... openat resumed>O_RDONLY) = 3"),
  );
  const mismatched = createLinuxObserverDecoder(["/fixture/value"]);
  mismatched.line(
    '21 100.003 openat(AT_FDCWD, "/fixture/value", <unfinished ...>',
  );
  assert.throws(() => mismatched.line("21 100.004 <... read resumed>) = 3"));
  const paired = createLinuxObserverDecoder(["/fixture/value"]);
  paired.line('21 100.003 openat(AT_FDCWD, "/fixture/value", <unfinished ...>');
  assert.equal(
    paired.line("21 100.004 <... openat resumed>O_RDONLY) = 3").result,
    3,
  );
  assert.equal(paired.finish().complete, true);
  const metadata = createLinuxObserverDecoder(["process:25", "/fixture/value"]);
  assert.equal(
    metadata.line(
      "21 100.005 process_vm_readv(25, 0x1, 1, 0x2, 1, 0) = -1 EPERM (Operation not permitted)",
    ).target,
    "process:25",
  );
  assert.equal(
    metadata.line(
      '21 100.006 rename("/fixture/source", "/fixture/value") = -1 EACCES (Permission denied)',
    ).target,
    "/fixture/value",
  );
});

test("Linux decoder accepts native FD annotations and selects socket metadata independently of payload", () => {
  const decoder = createLinuxObserverDecoder(
    ["/fixture/value", "fd:4", "127.0.0.1:80"],
    { initialPid: 21 },
  );
  assert.equal(
    decoder.line(
      '100.001 openat(AT_FDCWD, "/fixture/value", O_RDONLY) = 3</fixture/value>',
    ).pid,
    21,
  );
  assert.equal(
    decoder.line("21 100.002 read(4</fixture/value>, 0x1, 32) = 32").target,
    "fd:4",
  );
  assert.equal(
    decoder.line(
      '21 100.003 sendto(4<TCP:[127.0.0.1:81->127.0.0.1:80]>, "sun_path=\\\"/fixture/value\\\"", 27, 0, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("127.0.0.1")}, 16) = 27',
    ).target,
    "127.0.0.1:80",
  );
  assert.equal(
    decoder.line(
      '21 100.004 sendmsg(4, {msg_name={sa_family=AF_UNIX, sun_path="/unrelated/socket"}, msg_namelen=32, msg_iov=[{iov_base="sun_path=\\\"/fixture/value\\\"", iov_len=27}]}, 0) = 27',
    ),
    null,
  );
  assert.equal(decoder.line("21 100.005 exit_group(0) = ?"), null);
  assert.equal(decoder.finish().complete, true);
  const unknown = createLinuxObserverDecoder(["/fixture/value"]);
  assert.throws(() =>
    unknown.line(
      '100.001 openat(AT_FDCWD, "/fixture/value", O_RDONLY) = 3</fixture/value>',
    ),
  );
  assert.throws(() => unknown.finish());
});

// Pure injected effects: no native reader, filesystem, provider or process is
// started. Exercise each owner because their effect lifecycles remain separate.
function observerSession(platform) {
  const domain =
    platform === "linux"
      ? {
          bootId: "11111111-1111-1111-1111-111111111111",
          namespaceId: "pid:[20]",
          initPid: 20,
          initStartTicks: "50",
        }
      : platform === "darwin"
        ? { uid: 501, gid: 501, auid: 501, asid: 7 }
        : {
            accountSid: "S-1-5-21-1-2-3-4",
            restrictingSid: "S-1-5-21-1-2-3-5",
            jobSha256: sha("job"),
          };
  const { input, bound } = nativeFixture(
    domain,
    platform === "linux" ? "openat" : platform === "darwin" ? "72" : "4663",
  );
  if (platform === "linux")
    bound.before = {
      pid: 21,
      identity: { bootId: domain.bootId, startTicks: "51" },
      namespaceId: domain.namespaceId,
    };
  else if (platform === "darwin")
    bound.before = {
      pid: 21,
      pidVersion: 2,
      asid: 7,
      auid: 501,
      uid: 501,
      gid: 501,
      ruid: 501,
      rgid: 501,
      svuid: 501,
      svgid: 501,
      startSeconds: 100,
      startMicroseconds: 2,
    };
  else {
    bound.before = {
      pid: 21,
      creationTime: "1000",
      sessionId: 0,
      userSid: domain.accountSid,
    };
    bound.jobSha256 = domain.jobSha256;
    bound.restrictingSid = domain.restrictingSid;
    input.bindings.forEach((binding) => {
      binding.accessMask = 1;
      binding.opcode = binding.phase === "control-deny" ? "4656" : "4663";
    });
  }
  bound.after = structuredClone(bound.before);
  const { value } = fixture(domain),
    { plan } = input;
  const receipt = {
    candidateSha: plan.candidateSha,
    nonce: plan.nonce,
    domainSha256: plan.domainSha256,
    independent: true,
  };
  let configurationSha256,
    snapshots = 0,
    captures = 0,
    clock = 0;
  const observed = { admitted: 0, retired: 0, restored: 0 };
  const effects = {
    persist: async () => {},
    review: async (_, digest) => {
      configurationSha256 = digest;
      return {
        ...input.pins,
        candidateSha: plan.candidateSha,
        configurationSha256,
        status: "MATCHED",
      };
    },
    snapshot: async () => ({
      ...receipt,
      configurationSha256,
      ownedChangesOnly: true,
      exclusiveWriter: true,
      sha256:
        ++snapshots === 1
          ? value.settlement.beforeAuditSha256
          : value.settlement.installedAuditSha256,
    }),
    admit: async () => {
      observed.admitted++;
      return {};
    },
    verifyAdmission: async () => ({
      ...receipt,
      configurationSha256,
      policySha256: plan.policySha256,
      imageSha256: input.pins.imageSha256,
      sourceSha256: input.pins.sourceSha256,
      abiSha256: input.pins.abiSha256,
      protected: true,
      beforeProviderRelease: true,
      observerSha256: value.observerSha256,
    }),
    arm: async (_, binding) => ({
      ...receipt,
      configurationSha256,
      routeId: binding.routeId,
      phase: binding.phase,
      acknowledged: true,
      barrierSha256: sha(binding),
    }),
    control: async () => {},
    collect: async (_, binding) => {
      const deny = binding.phase === "control-deny";
      const raw = {
        id: "native:" + ++captures,
        pid: 21,
        opcode: binding.opcode,
        target: binding.selector,
      };
      Object.assign(
        raw,
        platform === "linux"
          ? { result: deny ? -1 : 3, errno: deny ? "EACCES" : null }
          : platform === "darwin"
            ? {
                result: deny ? -1 : 3,
                error: deny ? 13 : 0,
                auid: 501,
                asid: 7,
              }
            : {
                subjectSid: domain.accountSid,
                auditFailure: deny,
                accessMask: 1,
                filterId: null,
              },
      );
      return { health: value.health, records: [raw] };
    },
    bind: async (_, raw, binding) => ({
      ...bound,
      nativeId: raw.id,
      selector: binding.selector,
      objectSha256:
        binding.phase === "control-permit"
          ? plan.routes[0].permitTargetSha256
          : binding.phase === "control-deny"
            ? plan.routes[0].denyTargetSha256
            : plan.routes[0].targetSha256,
    }),
    read: async (_, event) => ({
      ...value.reads[event.sequence - 1],
      barrierSha256: event.barrierSha256,
    }),
    retirePayloads: async () => ({ ...receipt, noLiveMembers: true }),
    drain: async () => value.health,
    retireObserver: async () => {
      observed.retired++;
      return {
        ...receipt,
        noLiveMembers: true,
        observerSha256: value.observerSha256,
      };
    },
    restore: async () => {
      observed.restored++;
    },
    verifySettlement: async () => value.settlement,
  };
  const run = {
    linux: runLinuxToolObserver,
    darwin: runDarwinToolObserver,
    win32: runWindowsToolObserver,
  }[platform];
  return {
    effects,
    observed,
    advance: (ms) => {
      clock += ms;
    },
    run: (execute) =>
      run(input, effects, execute, {
        platform,
        architecture: "x64",
        build: "10.0.26100",
        now: () => clock,
        env: {
          CI: "true",
          GITHUB_ACTIONS: "true",
          ImageOS: { linux: "ubuntu24", darwin: "macos15", win32: "win25" }[
            platform
          ],
          ImageVersion: "fixture",
        },
      }),
  };
}

test("each observer rejects stale barriers, latches loss and fences cleanup", async () => {
  for (const platform of ["linux", "darwin", "win32"]) {
    const valid = observerSession(platform);
    assert.equal(
      (await valid.run(({ attempt }) => attempt("inspect", async () => {})))
        .status,
      "OBSERVED",
    );
    const stale = observerSession(platform),
      arm = stale.effects.arm;
    let controlReleases = 0,
      providerReleases = 0;
    stale.effects.arm = async (...args) => ({
      ...(await arm(...args)),
      phase: "tool",
    });
    stale.effects.control = async () => {
      controlReleases++;
    };
    assert.equal(
      (
        await stale.run(() => {
          providerReleases++;
        })
      ).status,
      "FAIL",
    );
    assert.equal(controlReleases, 0);
    assert.equal(providerReleases, 0);
    const lost = observerSession(platform),
      collect = lost.effects.collect;
    let lostOnce = false;
    lost.effects.collect = async (...args) => {
      const capture = await collect(...args);
      if (args[1].phase === "tool" && !lostOnce) {
        lostOnce = true;
        return { ...capture, health: { ...capture.health, dropped: 1 } };
      }
      return capture;
    };
    let actions = 0;
    const failed = await lost.run(async ({ attempt }) => {
      await assert.rejects(
        attempt("inspect", async () => {
          actions++;
        }),
      );
      await assert.rejects(
        attempt("inspect", async () => {
          actions++;
        }),
      );
    });
    assert.equal(actions, 1);
    assert.equal(failed.status, "FAIL");
    const payload = observerSession(platform);
    payload.effects.retirePayloads = async () => {
      throw new Error("Unverified retirement");
    };
    assert.equal(
      (await payload.run(({ attempt }) => attempt("inspect", async () => {})))
        .phase,
      "retained",
    );
    assert.equal(payload.observed.retired, 1);
    assert.equal(payload.observed.restored, 0);
    const expired = observerSession(platform),
      review = expired.effects.review;
    expired.effects.review = async (...args) => {
      const result = await review(...args);
      expired.advance(120001);
      return result;
    };
    assert.equal(
      (await expired.run(() => assert.fail("expired release"))).status,
      "FAIL",
    );
    assert.equal(expired.observed.admitted, 0);
    const cleanup = observerSession(platform),
      retire = cleanup.effects.retireObserver;
    cleanup.effects.retireObserver = async (...args) => {
      const result = await retire(...args);
      cleanup.advance(30001);
      return result;
    };
    const unsettled = await cleanup.run(({ attempt }) =>
      attempt("inspect", async () => {}),
    );
    assert.equal(unsettled.status, "FAIL");
    assert.equal(unsettled.phase, "retained");
    assert.equal(cleanup.observed.restored, 0);
  }
});
