import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import {
  normalizeWindowsLaunch,
  windowsLaunchDigest,
  windowsAccountName,
  retireWindowsDomain,
  assessWindowsRecovery,
  assessWindowsDomain,
  runWindowsOwnershipCase,
  WINDOWS_OWNERSHIP_CASES,
} from "./index.js";

const HASH = "a".repeat(64),
  ACCOUNT = "S-1-5-21-1-2-3-1001";
const sha = (value) => createHash("sha256").update(value).digest("hex");
const identity = (pid, userSid = "S-1-5-18") => ({
  pid,
  creationTime: String(10000 + pid),
  sessionId: 0,
  userSid,
});
function fixture(jobPresent = true) {
  const request = normalizeWindowsLaunch({
    schemaVersion: 1,
    candidateSha: "b".repeat(40),
    nonce: "c".repeat(32),
    restrictingSid: "S-1-5-21-4-5-6-1002",
    custody: "C:\\Fixture\\Custody",
    storage: "C:\\Fixture\\Storage",
    workspace: "C:\\Fixture\\Storage\\Work",
    launcher: {
      path: "C:\\Fixture\\Custody\\launcher.exe",
      sha256: HASH,
      signatureSha256: HASH,
    },
    executable: {
      path: "C:\\Fixture\\Storage\\payload.exe",
      sha256: HASH,
      signatureSha256: HASH,
      parser: "msvc-ucrt-wmain-v1",
    },
    policy: { path: "C:\\Fixture\\Custody\\policy.json", sha256: HASH },
    bindings: { system: HASH, source: HASH, closure: HASH, policy: HASH },
  });
  const approved = windowsLaunchDigest(request, []),
    payload = identity(101, ACCOUNT),
    child = identity(130, ACCOUNT);
  const object = (path, fileId = "1".padStart(32, "0")) => ({
    path,
    ownerSid: "S-1-5-18",
    protectedDacl: true,
    systemOnlyDacl: true,
    noReparse: true,
    exclusiveParents: true,
    daclSha256: HASH,
    volumeSerial: "1".padStart(16, "0"),
    fileId,
  });
  const account = {
    name: windowsAccountName(request.nonce),
    sid: ACCOUNT,
    restrictingSid: request.restrictingSid,
    restrictingSidExclusive: true,
    fresh: true,
    nonLogin: true,
    passwordPrivate: true,
    batchOnly: true,
    ordinaryGroups: [],
    deniedLogons: ["interactive", "network", "remote-interactive", "service"],
  };
  const job = {
    name: "Local\\NativeProof-" + request.nonce,
    heldObjectSha256: HASH,
    systemOnlyDacl: true,
    protectedDacl: true,
    inheritable: false,
    breakaway: false,
    silentBreakaway: false,
    killOnLastClose: true,
    creationTimeAdmission: true,
    processLimit: 32,
    uiRestrictions: 255,
  };
  const helpers = ["launcher", "verifier", "wfp"].map((role, index) => ({
    role,
    identity: identity(100 + index * 2),
    imageSha256: HASH,
    sourceSha256: HASH,
    settled: role === "wfp",
  }));
  const admission = {
    schemaVersion: 1,
    candidateSha: request.candidateSha,
    nonce: request.nonce,
    requestSha256: approved,
    request,
    arguments: [],
    admission: "possible",
    status: "ADMITTED",
    reservation: "RETAINED",
    helpers,
    accountSid: ACCOUNT,
    payload,
    setup: { account, job },
  };
  const recovered = {
    receipt: admission,
    receiptSha256: sha(JSON.stringify(admission) + "\n"),
    custody: object(request.custody),
    receiptFile: {
      ...object(
        request.custody + "\\windows-admission.json",
        "2".padStart(32, "0"),
      ),
      immutable: true,
      links: 1,
    },
  };
  recovered.receiptFile.sha256 = recovered.receiptSha256;
  const log = [],
    writes = [];
  let live = jobPresent,
    deadline;
  const enumeration = (members = live ? [payload, child] : []) => ({
    complete: true,
    accountSid: ACCOUNT,
    accountReservationVerified: true,
    capacity: 33,
    truncated: false,
    nativeEventSha256: HASH,
    processes: members.map((member) => ({
      identity: member,
      heldProcessVerified: true,
      signaled: !live,
      inJob: true,
      jobObjectSha256: HASH,
    })),
  });
  const verified = {
    independent: true,
    verifier: identity(210),
    custodian: {
      identity: identity(200),
      imageSha256: HASH,
      sourceSha256: HASH,
    },
    bindings: request.bindings,
    requestSha256: approved,
    privilegedContext: "local-system-session-0",
    sdkExportsVerified: true,
    possibleEffectsInventoried: true,
    helperInventoryComplete: true,
    receiptSha256: recovered.receiptSha256,
    nativeEventSha256: HASH,
    custody: recovered.custody,
    accountSid: ACCOUNT,
    accountReserved: true,
    namesNeverReused: true,
    policyStillInstalled: true,
    compositionSha256: HASH,
    immutableTokenInheritance: true,
    noHostMediatedCreation: true,
    noBreakaway: true,
    nestedJobsContained: true,
    parentSpoofDenied: true,
    jobObjectSha256: HASH,
    processLimit: 32,
    jobPresent,
    exactJobVerified: true,
    heldJobVerified: jobPresent,
    jobHandleHeld: jobPresent,
    jobAbsenceVerified: !jobPresent,
    recoveryImageSha256: HASH,
    recoverySourceSha256: HASH,
    processHandles: jobPresent ? [payload] : [payload, child],
    processHandlesVerified: true,
    close: () => log.push("close"),
  };
  const effects = {
    persist: async (record) => {
      writes.push(structuredClone(record));
      log.push("persist:" + record.phase);
    },
    recover: async () => recovered,
    verifyRecovery: async () => verified,
    verifyReceipt: async (_request, record) => {
      log.push("receipt:" + record.phase);
      return {
        independent: true,
        immutable: true,
        verifier: identity(211),
        sha256: sha(JSON.stringify(record) + "\n"),
        receiptSha256: HASH,
      };
    },
    stopAdmissions: async (_request, record) => {
      log.push("stop");
      return {
        independent: true,
        verifier: identity(212),
        closed: true,
        requestSha256: approved,
        creationSealed: true,
        receiptSha256: HASH,
        helpersSettled: record.helpers
          .slice(0, -1)
          .map((entry) => entry.identity),
      };
    },
    snapshot: async () => ({
      verifier: identity(213),
      enumeration: enumeration(),
    }),
    terminateJob: async () => {
      log.push("terminate-held-job");
      live = false;
      return {
        independent: true,
        verifier: identity(214),
        heldJobVerified: true,
        jobObjectSha256: HASH,
        requestSha256: approved,
        terminated: true,
        nativeEventSha256: HASH,
      };
    },
    waitProcesses: async (_request, record) => {
      log.push("wait-held-processes");
      return {
        independent: true,
        verifier: identity(215),
        requestSha256: approved,
        heldHandlesVerified: true,
        signaled: record.members,
      };
    },
    verifyRetirement: async (_request, record) => {
      log.push("fresh-census");
      return {
        independent: true,
        verifier: identity(230),
        bindings: request.bindings,
        requestSha256: approved,
        jobObjectSha256: HASH,
        stopSha256: HASH,
        policyStillInstalled: true,
        accountReserved: true,
        helperInventoryComplete: true,
        custodyStillHeld: true,
        nativeEventSha256: HASH,
        helpersSettled: record.helpers
          .slice(0, -1)
          .map((entry) => entry.identity),
        enumeration: enumeration(),
        knownProcessHandlesSignaled: true,
        holderInventoryComplete: true,
        onlyRecoveryHolder: jobPresent,
        jobHandleHeld: jobPresent,
        jobHolders: jobPresent ? 1 : 0,
      };
    },
    settleCustody: async () => {
      log.push("settle");
      return {
        independent: true,
        verifier: identity(240),
        requestSha256: approved,
        custodian: identity(200),
        settled: true,
        jobHolders: 0,
        policyStillInstalled: true,
        reservation: "RETAINED",
      };
    },
  };
  const options = {
    platform: "win32",
    architecture: "x64",
    env: {
      CI: "true",
      GITHUB_ACTIONS: "true",
      ImageOS: "win25",
      ImageVersion: "fixture-1",
    },
    build: "10.0.26100.1",
    now: () => 0,
    schedule: (callback) => {
      deadline = callback;
      return 1;
    },
    cancel: () => {},
  };
  return {
    request,
    approved,
    payload,
    child,
    recovered,
    verified,
    effects,
    options,
    enumeration,
    log,
    writes,
    expire: () => deadline(),
    run: () => retireWindowsDomain(request, approved, effects, options),
  };
}

test("Windows recovery binds protected receipts, native custody and the exact retained allocation", () => {
  const f = fixture();
  const recovered = assessWindowsRecovery(f.recovered, f.request, f.approved);
  assert.equal(recovered.accountSid, ACCOUNT);
  assert.equal(recovered.job.heldObjectSha256, HASH);
  for (const change of [
    (value) => {
      value.receiptFile.links = 2;
    },
    (value) => {
      value.custody.systemOnlyDacl = false;
    },
    (value) => {
      value.receipt.setup.job.breakaway = true;
    },
    (value) => {
      value.receipt.helpers[0].identity.creationTime = "0";
    },
    (value) => {
      value.receipt.nonce = "d".repeat(32);
    },
  ]) {
    const copy = structuredClone(f.recovered);
    change(copy);
    copy.receiptSha256 = sha(JSON.stringify(copy.receipt) + "\n");
    copy.receiptFile.sha256 = copy.receiptSha256;
    assert.throws(() => assessWindowsRecovery(copy, f.request, f.approved));
  }
  const interrupted = structuredClone(f.recovered);
  delete interrupted.receipt.setup;
  interrupted.receiptSha256 = sha(JSON.stringify(interrupted.receipt) + "\n");
  interrupted.receiptFile.sha256 = interrupted.receiptSha256;
  assert.deepEqual(
    assessWindowsRecovery(interrupted, f.request, f.approved).missingInputs,
    ["windows-protected-account-job-admission-binding"],
  );
});

test("Windows complete principal enumeration rejects truncation, stale tokens and foreign Job members", () => {
  const f = fixture(),
    census = f.enumeration();
  assert.equal(assessWindowsDomain(census, ACCOUNT, HASH, true).length, 2);
  for (const change of [
    (value) => {
      value.complete = false;
    },
    (value) => {
      value.truncated = true;
    },
    (value) => {
      value.capacity = 32;
    },
    (value) => {
      value.processes[0].identity.userSid = "S-1-5-18";
    },
    (value) => {
      value.processes[0].inJob = false;
    },
    (value) => {
      value.processes.push(value.processes[0]);
    },
  ]) {
    const copy = structuredClone(census);
    change(copy);
    assert.throws(() => assessWindowsDomain(copy, ACCOUNT, HASH, true));
  }
});

test("Windows retirement seals admissions, terminates only the held Job and waits before fresh settlement", async () => {
  const f = fixture(),
    result = await f.run();
  assert.equal(result.status, "RETIRED");
  assert.equal(result.reservation, "RETAINED");
  assert.equal(result.helpersSettled, true);
  assert.deepEqual(result.members, [f.payload, f.child]);
  const order = [
    "receipt:stop-admissions",
    "stop",
    "receipt:terminate-job",
    "terminate-held-job",
    "wait-held-processes",
    "fresh-census",
    "receipt:custody-settlement",
    "settle",
  ];
  for (let i = 1; i < order.length; i++)
    assert(f.log.indexOf(order[i - 1]) < f.log.indexOf(order[i]), order[i]);
  assert.equal(
    f.log.filter((value) => value === "terminate-held-job").length,
    1,
  );
});

test("Windows empty or disappeared Jobs use known process waits and a complete empty principal census", async () => {
  for (const jobPresent of [true, false]) {
    const f = fixture(jobPresent),
      verify = f.effects.verifyRetirement;
    f.effects.snapshot = async () => ({
      verifier: identity(213),
      enumeration: f.enumeration([]),
    });
    f.effects.verifyRetirement = async (...args) => ({
      ...(await verify(...args)),
      enumeration: f.enumeration([]),
    });
    assert.equal((await f.run()).status, "RETIRED");
    assert(!f.log.includes("terminate-held-job"));
    assert(f.log.includes("wait-held-processes"));
  }
  const live = fixture(false);
  live.effects.snapshot = async () => ({
    verifier: identity(213),
    enumeration: {
      ...live.enumeration([live.payload]),
      processes: [
        { identity: live.payload, signaled: false, heldProcessVerified: true },
      ],
    },
  });
  assert.equal((await live.run()).status, "FAIL");
  assert(!live.log.includes("terminate-held-job"));
  assert(!live.log.includes("settle"));
});

test("Windows uncertain source, custody, handles, waits or fresh settlement never establish retirement", async () => {
  for (const change of [
    (f) => {
      f.verified.namesNeverReused = false;
    },
    (f) => {
      f.verified.noHostMediatedCreation = false;
    },
    (f) => {
      f.verified.processHandles[0] = { ...f.payload, creationTime: "20000" };
    },
    (f) => {
      f.effects.waitProcesses = async () => ({
        independent: true,
        verifier: identity(215),
        requestSha256: f.approved,
        heldHandlesVerified: true,
        signaled: [],
      });
    },
    (f) => {
      const verify = f.effects.verifyRetirement;
      f.effects.verifyRetirement = async (...args) => ({
        ...(await verify(...args)),
        holderInventoryComplete: false,
      });
    },
    (f) => {
      const verify = f.effects.verifyRetirement;
      f.effects.verifyRetirement = async (...args) => ({
        ...(await verify(...args)),
        verifier: identity(213),
      });
    },
  ]) {
    const f = fixture();
    change(f);
    const result = await f.run();
    assert.equal(result.status, "FAIL");
    assert.equal(result.reservation, "RETAINED");
    assert.equal(result.noLiveMembers, false);
    assert(!f.log.includes("settle"));
  }
  const missing = fixture();
  delete missing.effects.snapshot;
  assert.equal((await missing.run()).status, "BLOCKED");
  assert(!missing.log.includes("stop"));
});

test("Windows interrupted recovery carries old native helpers and member identities into fresh settlement", async () => {
  const f = fixture();
  const previous = {
    schemaVersion: 1,
    requestSha256: f.approved,
    candidateSha: f.request.candidateSha,
    nonce: f.request.nonce,
    accountSid: ACCOUNT,
    jobObjectSha256: HASH,
    reservation: "RETAINED",
    helpers: [
      {
        role: "recovery",
        identity: identity(190),
        imageSha256: HASH,
        sourceSha256: HASH,
      },
    ],
    members: [f.child],
  };
  f.recovered.previousRetirement = previous;
  f.recovered.previousSha256 = sha(JSON.stringify(previous) + "\n");
  f.recovered.previousFile = {
    ...f.recovered.receiptFile,
    path: f.request.custody + "\\windows-retirement.json",
    sha256: f.recovered.previousSha256,
  };
  f.verified.processHandles.push(f.child);
  const result = await f.run();
  assert.equal(result.status, "RETIRED");
  assert(result.helpers.some((entry) => entry.identity.pid === 190));
  assert.deepEqual(result.members, [f.payload, f.child]);
});

test("Windows retirement deadline cannot be overwritten by a late independent recovery callback", async () => {
  const f = fixture();
  let entered, release;
  const reached = new Promise((resolve) => {
    entered = resolve;
  });
  f.effects.verifyRecovery = () => {
    entered();
    return new Promise((resolve) => {
      release = resolve;
    });
  };
  const pending = f.run();
  await reached;
  f.expire();
  const result = await pending;
  assert.equal(result.status, "FAIL");
  release(f.verified);
  await Promise.resolve();
  await Promise.resolve();
  assert.equal(f.writes.at(-1).status, "FAIL");
  assert(!f.log.includes("stop"));
  assert(!f.log.includes("settle"));
});

test("Windows recovery transport failure cannot prevent retained failure publication", async () => {
  const f = fixture();
  f.verified.close = () => {
    throw new Error("Native control transport unavailable");
  };
  f.effects.snapshot = async () => {
    throw new Error("Native enumeration unavailable");
  };
  const result = await f.run();
  assert.equal(result.status, "FAIL");
  assert.equal(result.reservation, "RETAINED");
  assert.equal(f.writes.at(-1).status, "FAIL");
  assert(!f.log.includes("settle"));
});

test("Windows contradictory waits and nonconverging complete views cannot establish retirement", async () => {
  const inconsistent = fixture(),
    read = inconsistent.effects.verifyRetirement;
  inconsistent.effects.verifyRetirement = async (...args) => ({
    ...(await read(...args)),
    enumeration: {
      ...inconsistent.enumeration([]),
      processes: [
        {
          identity: inconsistent.payload,
          heldProcessVerified: true,
          signaled: false,
          inJob: true,
          jobObjectSha256: HASH,
        },
      ],
    },
  });
  assert.equal((await inconsistent.run()).status, "FAIL");
  assert.equal(
    inconsistent.log.filter((value) => value === "terminate-held-job").length,
    1,
  );
  const racing = fixture(),
    freshRead = racing.effects.verifyRetirement;
  let pass = 0,
    next;
  const snapshot = racing.effects.snapshot;
  racing.effects.snapshot = async () =>
    next
      ? {
          verifier: identity(213),
          enumeration: {
            ...racing.enumeration([]),
            processes: [
              {
                identity: next,
                heldProcessVerified: true,
                signaled: false,
                inJob: true,
                jobObjectSha256: HASH,
              },
            ],
          },
        }
      : snapshot();
  racing.effects.verifyRetirement = async (...args) => {
    next = identity(500 + pass, ACCOUNT);
    return {
      ...(await freshRead(...args)),
      verifier: identity(230 + pass++),
      enumeration: {
        ...racing.enumeration([]),
        processes: [
          {
            identity: next,
            heldProcessVerified: true,
            signaled: false,
            inJob: true,
            jobObjectSha256: HASH,
          },
        ],
      },
    };
  };
  const result = await racing.run();
  assert.equal(result.status, "FAIL");
  assert.equal(result.noLiveMembers, false);
  assert.equal(
    racing.log.filter((value) => value === "terminate-held-job").length,
    8,
  );
  assert(!racing.log.includes("settle"));
});

function ownership(f, caseId) {
  const admitted = structuredClone(f.recovered.receipt);
  const early = [
    "admission-interruption",
    "receipt-before",
    "receipt-after",
  ].includes(caseId);
  if (early) {
    admitted.status = "RUNNING";
    f.recovered.receipt = admitted;
    f.recovered.receiptSha256 = sha(JSON.stringify(admitted) + "\n");
    f.recovered.receiptFile.sha256 = f.recovered.receiptSha256;
    f.verified.receiptSha256 = f.recovered.receiptSha256;
    f.effects.snapshot = async () => ({
      verifier: identity(213),
      enumeration: f.enumeration([f.payload]),
    });
  }
  const effects = {
    persist: async () => {},
    verifyComposition: async () => ({
      independent: true,
      verifier: identity(300),
      sourceSha256: HASH,
      policySha256: HASH,
      nativeEventSha256: HASH,
      sdkExportsVerified: true,
      immutableRestrictedToken: true,
      creationTimeJob: true,
      noBreakaway: true,
      nestedJobsContained: true,
      parentObjectAccessDenied: true,
      hostServicesDenied: true,
      noDelegation: true,
      jobDaclProtected: true,
      receiptDaclProtected: true,
      noForeignHandles: true,
      processLimit: 32,
    }),
    admit: async () => admitted,
    observe: async () => ({
      independent: true,
      verifier: identity(301),
      caseId,
      nonce: f.request.nonce,
      requestSha256: f.approved,
      attempted: true,
      complete: true,
      timedOut: false,
      outsideUnchanged: true,
      nativeEventSha256: HASH,
      bytesSha256: HASH,
      members: early ? [f.payload] : [f.payload, f.child],
      childAcknowledged: true,
      creationTimeJobVerified: true,
      inheritedTokenVerified: true,
      creatorSignaled: true,
      outerMembershipVerified: true,
      nestedOutcome: "contained",
      denied: true,
      nativeError: "E_ACCESSDENIED",
      control: {
        ready: true,
        reachable: true,
        operation: caseId,
        nativeEventSha256: HASH,
        protectedBeforeSha256: HASH,
        protectedAfterSha256: HASH,
      },
      payloadReleased: false,
      receiptBoundary: caseId === "receipt-after" ? "after" : "before",
      barrierAcknowledged: true,
    }),
    armFault: async () => ({
      armed: true,
      independent: true,
      caseId,
      nonce: f.request.nonce,
      requestSha256: f.approved,
      receiptSha256: HASH,
      point: caseId,
      jobHandleHeld: false,
      processHandlesVerified: true,
      processHandles: [f.payload, f.child],
      holderInventoryComplete: true,
    }),
    fireFault: async () => ({
      acknowledged: true,
      caseId,
      nonce: f.request.nonce,
      faultSha256: HASH,
      nativeEventSha256: HASH,
    }),
    recoverAndRetire: async () => f.run(),
    verify: async () => ({
      independent: true,
      verifier: identity(302),
      requestSha256: f.approved,
      nonce: f.request.nonce,
      helpersSettled: true,
      knownProcessHandlesSignaled: true,
      jobHolders: 0,
      outsideUnchanged: true,
      reservation: "RETAINED",
      nativeEventSha256: HASH,
      enumeration: f.enumeration([]),
      lastHandleCloseObserved: true,
      jobAbsent: true,
      jobHandleHeld: false,
    }),
  };
  return effects;
}

test("Windows acknowledged child and fault cases require source composition and fresh independent retirement", async () => {
  for (const caseId of WINDOWS_OWNERSHIP_CASES.filter(
    (value) => !["process-limit", "stale-identity"].includes(value),
  )) {
    const f = fixture(caseId !== "last-handle-close");
    const result = await runWindowsOwnershipCase(
      caseId,
      f.request,
      ownership(f, caseId),
      f.options,
    );
    assert.equal(result.status, "OBSERVED", caseId);
    assert.equal(result.reservation, "RETAINED");
  }
});

test("Windows process-limit and stale-creation cases bind actual members and reject incomplete fault observations", async () => {
  for (const caseId of ["process-limit", "stale-identity"]) {
    const f = fixture(),
      effects = ownership(f, caseId),
      observe = effects.observe;
    const members =
      caseId === "process-limit"
        ? [
            f.payload,
            ...Array.from({ length: 31 }, (_, index) =>
              identity(400 + index, ACCOUNT),
            ),
          ]
        : [f.payload, f.child];
    effects.observe = async () => ({
      ...(await observe()),
      members,
      activeProcessLimit: 32,
      creationRejected: true,
      nativeError: "ERROR_NOT_ENOUGH_QUOTA",
      staleRejected: true,
      forcedPidReuse: false,
      stale: { ...f.payload, creationTime: "20000" },
      current: f.payload,
    });
    f.effects.snapshot = async () => ({
      verifier: identity(213),
      enumeration: f.enumeration(members),
    });
    assert.equal(
      (await runWindowsOwnershipCase(caseId, f.request, effects, f.options))
        .status,
      "OBSERVED",
    );
    const observed = effects.observe;
    effects.observe = async () => ({
      ...(await observed()),
      forcedPidReuse: true,
      creationRejected: false,
    });
    assert.equal(
      (await runWindowsOwnershipCase(caseId, f.request, effects, f.options))
        .status,
      "FAIL",
    );
  }
});

test("Windows stale-creation proof requires a complete tuple for the same principal and session", async () => {
  for (const change of [
    (stale) => {
      delete stale.creationTime;
    },
    (stale) => {
      stale.userSid = "S-1-5-18";
    },
    (stale) => {
      stale.sessionId = 1;
    },
  ]) {
    const f = fixture(),
      effects = ownership(f, "stale-identity"),
      observe = effects.observe,
      stale = { ...f.payload, creationTime: "20000" };
    change(stale);
    effects.observe = async () => ({
      ...(await observe()),
      staleRejected: true,
      forcedPidReuse: false,
      stale,
      current: f.payload,
    });
    assert.equal(
      (
        await runWindowsOwnershipCase(
          "stale-identity",
          f.request,
          effects,
          f.options,
        )
      ).status,
      "FAIL",
    );
  }
});

test("Windows denial needs a ready external control and cannot pass on timeout or self-reported emptiness", async () => {
  for (const [caseId, change] of [
    [
      "wmi",
      (effects) => {
        const observe = effects.observe;
        effects.observe = async () => ({
          ...(await observe()),
          timedOut: true,
        });
      },
    ],
    [
      "wmi",
      (effects) => {
        const observe = effects.observe;
        effects.observe = async () => ({
          ...(await observe()),
          control: { ready: false },
        });
      },
    ],
    [
      "detached",
      (effects) => {
        const verify = effects.verifyComposition;
        effects.verifyComposition = async () => ({
          ...(await verify()),
          immutableRestrictedToken: false,
        });
      },
    ],
    [
      "detached",
      (effects) => {
        const verify = effects.verify;
        effects.verify = async () => ({
          ...(await verify()),
          verifier: identity(200),
        });
      },
    ],
    [
      "last-handle-close",
      (effects) => {
        const arm = effects.armFault;
        effects.armFault = async () => ({
          ...(await arm()),
          jobHandleHeld: true,
        });
      },
    ],
    [
      "last-handle-close",
      (effects) => {
        const verify = effects.verify;
        effects.verify = async () => ({
          ...(await verify()),
          enumeration: { complete: false },
        });
      },
    ],
  ]) {
    const f = fixture(false),
      effects = ownership(f, caseId);
    change(effects);
    assert.equal(
      (await runWindowsOwnershipCase(caseId, f.request, effects, f.options))
        .status,
      "FAIL",
    );
  }
});

test("Windows failed observation bounds its separate retirement attempt without turning cleanup into proof", async () => {
  const f = fixture(),
    effects = ownership(f, "wmi");
  let entered;
  const reached = new Promise((resolve) => {
    entered = resolve;
  });
  const observe = effects.observe;
  effects.observe = async () => ({ ...(await observe()), timedOut: true });
  effects.recoverAndRetire = () => {
    entered();
    return new Promise(() => {});
  };
  const pending = runWindowsOwnershipCase("wmi", f.request, effects, f.options);
  await reached;
  f.expire();
  const result = await pending;
  assert.equal(result.status, "FAIL");
  assert.deepEqual(result.cleanup, { status: "RETAINED" });
});

test("Windows ownership deadline leaves failure durable after an outstanding successful receipt write", async () => {
  const f = fixture(),
    effects = ownership(f, "detached"),
    writes = [];
  let reached, release, expire;
  const writing = new Promise((resolve) => {
    reached = resolve;
  });
  effects.persist = async (record) => {
    if (record.status === "OBSERVED") {
      reached();
      await new Promise((resolve) => {
        release = resolve;
      });
    }
    writes.push(record);
  };
  const pending = runWindowsOwnershipCase("detached", f.request, effects, {
    ...f.options,
    schedule: (callback) => {
      expire = callback;
      return 1;
    },
  });
  await writing;
  expire();
  // Let the deadline rejection reach failure persistence before completing the
  // outstanding success write, reproducing the former out-of-order publication.
  await new Promise((resolve) => setImmediate(resolve));
  release();
  assert.equal((await pending).status, "FAIL");
  assert.equal(writes.at(-1).status, "FAIL");
});
