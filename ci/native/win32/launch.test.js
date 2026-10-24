import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { Script } from "node:vm";
import { createHash } from "node:crypto";
import { EventEmitter, once } from "node:events";
import { PassThrough } from "node:stream";
import test from "node:test";
import {
  admitWindowsLaunch,
  assertWindowsLiteralObservation,
  inspectWindowsPe,
  normalizeWindowsLaunch,
  normalizeWindowsArguments,
  quoteWindowsArgument,
  windowsCommandLine,
  windowsLaunchDigest,
  windowsAccountName,
  sameWindowsIdentity,
  WINDOWS_LITERAL_ARGUMENTS,
  WINDOWS_ARGUMENT_PARSER,
  WINDOWS_SYSTEM_SID,
} from "./index.js";
import { windowsAdmissionChannel } from "./channel.js";
import { windowsPolicyFixture } from "./policy.fixture.js";
import {
  nativePolicyLaunchData,
  nativePolicyTemplateDigest,
  materializeNativePolicy,
} from "../index.js";

const HASH = "a".repeat(64),
  ACCOUNT = "S-1-5-21-1-2-3-1001";
const sha = (value) => createHash("sha256").update(value).digest("hex");
function fixture(runtimePath) {
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
      parser: WINDOWS_ARGUMENT_PARSER,
    },
    policy: { path: "C:\\Fixture\\Custody\\policy.json", sha256: HASH },
    bindings: {
      system: HASH,
      source: HASH,
      closure: HASH,
      policy: "d".repeat(64),
    },
  });
  const identity = (pid, userSid = WINDOWS_SYSTEM_SID) => ({
    pid,
    creationTime: String(10000 + pid),
    sessionId: 0,
    userSid,
  });
  const helper = identity(100),
    payload = identity(101, ACCOUNT),
    verifier = identity(102),
    wfp = identity(103);
  const object = (path, id) => ({
    path,
    volumeSerial: "1".padStart(16, "0"),
    fileId: String(id).padStart(32, "0"),
    ownerSid: WINDOWS_SYSTEM_SID,
    noReparse: true,
    exclusiveParents: true,
    protectedDacl: true,
    privateDacl: true,
    systemOnlyDacl: true,
    daclSha256: HASH,
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
    sameHeldObject: true,
    protectedDacl: true,
    systemOnlyDacl: true,
    inheritable: false,
    breakaway: false,
    silentBreakaway: false,
    killOnLastClose: true,
    processLimit: 32,
    uiRestrictions: 255,
    creationTimeAdmission: true,
    member: false,
  };
  const desktop = {
    station: "np_" + request.nonce,
    name: "payload",
    noninteractive: true,
    protectedDacl: true,
    privateDacl: true,
    foreignHandles: 0,
    inheritable: false,
    nativeObjectSha256: HASH,
  };
  const policyFixture = windowsPolicyFixture(
    request,
    ACCOUNT,
    "workspace-write",
    runtimePath,
  );
  const policy = {
    installed: true,
    compositionSha256: request.bindings.policy,
    receiptSha256: HASH,
    wfpInstalled: true,
    filesystemInstalled: true,
    effectiveGrantsMatchManifest: true,
    hostDelegationDenied: true,
    foreignHandlesDenied: true,
    credentialsProtected: true,
    checkoutProtected: true,
    providersExcluded: true,
    inheritanceReviewed: true,
    manifest: policyFixture.input,
    installation: policyFixture.installation,
  };
  const setup = {
    independent: true,
    requestSha256: windowsLaunchDigest(request, WINDOWS_LITERAL_ARGUMENTS),
    nativeEventSha256: HASH,
    helper,
    verifier,
    account,
    job,
    desktop,
    custody: object(request.custody, 1),
    storage: object(request.storage, 2),
    workspace: object(request.workspace, 3),
  };
  const image = (key, id) => ({
    ...object(request[key].path, id),
    links: 1,
    sha256: request[key].sha256,
    signatureSha256: request[key].signatureSha256,
    authenticode: true,
    architecture: "x64",
    loaderSha256: request.bindings.closure,
    untrustedWritable: false,
  });
  const authority = {
    ...structuredClone(setup),
    payload: structuredClone(payload),
    suspended: true,
    threadSuspendCount: 1,
    processProtectedDacl: true,
    threadProtectedDacl: true,
    processSystemOnlyDacl: true,
    threadSystemOnlyDacl: true,
    job: { ...job, member: true },
    cwd: request.workspace,
    cwdIdentity: setup.workspace.volumeSerial + ":" + setup.workspace.fileId,
    token: {
      userSid: ACCOUNT,
      restrictedSids: [request.restrictingSid],
      privileges: [],
      enabledGroups: [],
      integritySid: "S-1-16-4096",
      sessionId: 0,
      tokenId: "1".padStart(16, "0"),
      authenticationId: "2".padStart(16, "0"),
      primary: true,
      virtualized: false,
      writeRestricted: false,
    },
    handles: {
      explicitList: true,
      count: 2,
      kinds: "stdin-read,stdout-stderr-write",
      foreign: 0,
      token: 0,
      job: 0,
      hostService: 0,
    },
    launcher: image("launcher", 4),
    executable: {
      ...image(
        "executable",
        Number(
          policyFixture.installation.effective.objects.find(
            (entry) =>
              entry.descriptor.path.toLowerCase() ===
              request.executable.path.toLowerCase(),
          ).fileId,
        ),
      ),
      parser: WINDOWS_ARGUMENT_PARSER,
      parserVerified: true,
    },
    policyFile: {
      ...object(request.policy.path, 6),
      sha256: request.policy.sha256,
      untrustedWritable: false,
    },
    policy,
  };
  const calls = [],
    records = [];
  let expire,
    closed = false;
  const transport = {
    ready: Promise.resolve({ helper, payload, accountSid: ACCOUNT }),
    release: () => calls.push("release"),
    close: () => {
      if (!closed) {
        closed = true;
        calls.push("close");
      }
    },
  };
  const binding = (identity) => ({
    identity,
    imageSha256: HASH,
    sourceSha256: HASH,
  });
  const effects = {
    persist: async (value) => {
      records.push(structuredClone(value));
      calls.push("persist-" + value.phase);
    },
    verifyInputs: async (_, approvedSha256) => ({
      approvedSha256,
      bindings: request.bindings,
      privilegedContext: "local-system-session-0",
      sdkExportsVerified: true,
      loaderClosureVerified: true,
      parser: WINDOWS_ARGUMENT_PARSER,
      helperBindings: Object.fromEntries(
        ["launcher", "verifier", "wfp"].map((role) => [
          role,
          { sha256: HASH, sourceSha256: HASH },
        ]),
      ),
    }),
    launchParked: async (_, args, verified, onHelper, onSetup) => {
      calls.push("park");
      assert.deepEqual(args, WINDOWS_LITERAL_ARGUMENTS);
      try {
        await onHelper({ helper, payload: null, accountSid: null });
        calls.push("helper-ack");
        await onSetup({ helper, payload: null, accountSid: ACCOUNT });
        calls.push("create-ack");
        return transport;
      } catch (error) {
        transport.close();
        throw error;
      }
    },
    inspect: async (_, expected) => ({
      independent: true,
      nativeEventSha256: HASH,
      requestSha256: setup.requestSha256,
      helper,
      payload: expected.payload,
      verifiers: [binding(verifier)],
      helpers: expected.helpers.map((entry) => ({
        ...binding(
          entry.role === "launcher"
            ? helper
            : entry.role === "verifier"
              ? verifier
              : wfp,
        ),
        role: entry.role,
      })),
    }),
    verifySetup: async () => {
      calls.push("verify-setup");
      return structuredClone(setup);
    },
    installPolicy: async (_, record, onHelper) => {
      calls.push("install-policy");
      await onHelper({ ...binding(wfp), role: "wfp", settled: false });
      calls.push("wfp-admitted");
      return {
        ...structuredClone(policy),
        independent: true,
        requestSha256: setup.requestSha256,
        nativeEventSha256: HASH,
        verifier,
        accountSid: ACCOUNT,
        restrictingSid: request.restrictingSid,
        helpers: [{ ...binding(wfp), role: "wfp", settled: true }],
      };
    },
    verifyAuthority: async () => {
      calls.push("verify-authority");
      return structuredClone(authority);
    },
    verifyReceipt: async (_, record) => {
      calls.push("receipt-" + record.phase);
      return {
        independent: true,
        immutable: true,
        sha256: sha(JSON.stringify(record) + "\n"),
        receiptSha256: HASH,
        verifier,
      };
    },
    retire: async () => ({
      status: "RETIRED",
      independent: true,
      nativeEventSha256: HASH,
      requestSha256: setup.requestSha256,
      accountSid: ACCOUNT,
      noLiveMembers: true,
      helpersSettled: true,
      jobObjectSha256: HASH,
      reservation: "RETAINED",
      freshVerifier: identity(104),
    }),
  };
  const options = {
    platform: "win32",
    architecture: "x64",
    build: "10.0.26100.1",
    now: () => 0,
    env: {
      CI: "true",
      GITHUB_ACTIONS: "true",
      ImageOS: "win25",
      ImageVersion: "fixture-1",
    },
    schedule: (callback) => {
      expire = callback;
      return 1;
    },
    cancel: () => {},
  };
  return {
    request,
    helper,
    payload,
    verifier,
    wfp,
    setup,
    authority,
    effects,
    options,
    calls,
    records,
    transport,
    expire: () => expire(),
    run: () =>
      admitWindowsLaunch(
        request,
        WINDOWS_LITERAL_ARGUMENTS,
        windowsLaunchDigest(request, WINDOWS_LITERAL_ARGUMENTS),
        effects,
        options,
      ),
  };
}

function templateFixture(failure) {
  const f = fixture();
  f.request.schemaVersion = 3;
  const { request, ...parameters } = f.authority.policy.manifest;
  const value = {
    schemaVersion: 1,
    candidateSha: f.request.candidateSha,
    platform: "win32",
    sourceReviewSha256: HASH,
    provisioningReviewSha256: HASH,
    policy: {
      launch: nativePolicyLaunchData(f.request, WINDOWS_LITERAL_ARGUMENTS),
      policy: { ...parameters, accountSid: { binding: "account" } },
    },
    bindings: [
      {
        id: "account",
        kind: "sid",
        paths: [["policy", "accountSid"]],
        minimum: null,
        maximum: null,
      },
    ],
  };
  const approval = {
    candidateSha: value.candidateSha,
    platform: "win32",
    authority: "operator-protected",
    manifestSha256: nativePolicyTemplateDigest(value),
  };
  const context = {
    candidateSha: value.candidateSha,
    platform: "win32",
    tier: "system",
    runId: "1",
    runAttempt: 1,
    jobBindingSha256: HASH,
    executionId: "fixture",
    closureSha256: HASH,
    selectedSystemSha256: null,
  };
  const binding = { template: value, approval, context };
  const provisioning = {
    schemaVersion: 1,
    context,
    authoritySha256: HASH,
    bindings: [{ id: "account", kind: "sid", value: ACCOUNT }],
    held: true,
    independent: true,
    verifierSha256: HASH,
    nativeEventSha256: HASH,
  };
  const expected = materializeNativePolicy(
    value,
    approval,
    provisioning,
    context,
  );
  const initial = structuredClone(f.request);
  initial.policy.sha256 = initial.bindings.policy = null;
  const inputs = f.effects.verifyInputs,
    inspect = f.effects.inspect,
    setup = f.effects.verifySetup,
    install = f.effects.installPolicy;
  f.effects.verifyInputs = async (input, pin) => ({
    ...(await inputs(input, pin)),
    bindings: input.bindings,
  });
  f.effects.inspect = async (input, identities) => ({
    ...(await inspect(input, identities)),
    requestSha256: windowsLaunchDigest(input, WINDOWS_LITERAL_ARGUMENTS),
  });
  f.effects.verifySetup = async (input) => ({
    ...(await setup()),
    requestSha256: windowsLaunchDigest(input, WINDOWS_LITERAL_ARGUMENTS),
  });
  f.effects.readProvisioning = async (_, record) => {
    f.calls.push("held-provisioning");
    assert.equal(record.accountSid, ACCOUNT);
    assert.equal(record.payload, null);
    return failure === "identity"
      ? {
          ...provisioning,
          bindings: [
            { id: "account", kind: "sid", value: "S-1-5-21-1-2-3-1009" },
          ],
        }
      : provisioning;
  };
  f.effects.installPolicy = async (input, record, onHelper, proof) => {
    assert.equal(proof.input.accountSid, ACCOUNT);
    assert.deepEqual(proof.input.request, input);
    assert.notEqual(
      proof.binding.approval.manifestSha256,
      record.requestSha256,
    );
    f.setup.requestSha256 = f.authority.requestSha256 = record.requestSha256;
    f.authority.policy.manifest.request = structuredClone(input);
    return install(input, record, onHelper);
  };
  let reads = 0;
  f.effects.readPolicy = async (_, record) => {
    f.calls.push("policy-read-" + ++reads);
    assert.equal(record.payload === null, reads === 1);
    return {
      schemaVersion: 1,
      context,
      templateSha256: expected.templateSha256,
      provisioningSha256: expected.provisioningSha256,
      requestSha256: record.requestSha256,
      policySha256: expected.expectedPolicySha256,
      policy: expected.policy,
      held: true,
      complete: true,
      independent: !(
        failure === "create" ||
        (failure === "release" && reads === 2)
      ),
      verifierSha256: HASH,
      nativeEventSha256: HASH,
    };
  };
  if (failure === "missing") delete f.effects.readPolicy;
  return {
    ...f,
    binding,
    run: () =>
      admitWindowsLaunch(
        initial,
        WINDOWS_LITERAL_ARGUMENTS,
        binding,
        f.effects,
        f.options,
      ),
  };
}

test("template admission allocates and holds the SID before policy bytes, then verifies both payload barriers", async () => {
  const f = templateFixture(),
    result = await f.run();
  assert.equal(result.record.status, "ADMITTED");
  assert.ok(
    f.calls.indexOf("verify-setup") < f.calls.indexOf("held-provisioning"),
  );
  assert.ok(
    f.calls.indexOf("held-provisioning") < f.calls.indexOf("install-policy"),
  );
  assert.ok(f.calls.indexOf("policy-read-1") < f.calls.indexOf("create-ack"));
  assert.ok(f.calls.indexOf("policy-read-2") < f.calls.indexOf("release"));
  assert.ok(
    f.records.find((record) => record.phase === "create").policyReceipt,
  );
  assert.equal(result.record.request.schemaVersion, 3);
  assert.notEqual(result.record.request.policy.sha256, null);
  assert.notEqual(result.record.requestSha256, result.record.templateSha256);
  for (const failure of ["identity", "create", "release", "missing"]) {
    const bad = templateFixture(failure),
      outcome = await bad.run();
    assert.notEqual(outcome.record.status, "ADMITTED");
    assert.ok(!bad.calls.includes("release"));
    if (failure !== "release") assert.ok(!bad.calls.includes("create-ack"));
  }
});

test("Windows UCRT vectors preserve empty, quoted and trailing-backslash arguments without a shell", () => {
  for (const [input, expected] of [
    ["", '""'],
    ["space value", '"space value"'],
    ["λ雪😀", '"λ雪😀"'],
    ['a"b', '"a\\"b"'],
    ["tail\\", '"tail' + "\\".repeat(2) + '"'],
    ['slash\\"quote', '"slash' + "\\".repeat(3) + '"quote"'],
    ["$(false); & | < > *", '"$(false); & | < > *"'],
  ])
    assert.equal(quoteWindowsArgument(input), expected);
  assert.equal(normalizeWindowsArguments(Array(64).fill("")).length, 64);
  assert.ok(
    windowsCommandLine("C:\\Fixture\\app.exe", Array(74).fill("")).startsWith(
      '"C:\\Fixture\\app.exe" ',
    ),
  );
  assert.throws(() =>
    windowsCommandLine("C:\\Fixture\\app.exe", Array(75).fill("")),
  );
  for (const args of [
    Array(65).fill(""),
    ["\ud800"],
    ["\0"],
    ["x".repeat(4097)],
    new Array(1),
  ])
    assert.throws(() => normalizeWindowsArguments(args));
  const { request } = fixture();
  for (const custody of [
    "c:\\Fixture\\Custody",
    "C:\\Fixture\\..\\Custody",
    "C:\\Fixture\\NUL",
    "C:\\Fixture\\Custody.",
  ])
    assert.throws(() => normalizeWindowsLaunch({ ...request, custody }));
  assert.throws(() =>
    normalizeWindowsLaunch({
      ...request,
      restrictingSid: "S-1-05-21-4-5-6-1002",
    }),
  );
  assert.throws(() => normalizeWindowsLaunch({ ...request, unexpected: true }));
});

test("Windows PE inspection rejects missing signatures, unsupported architecture and truncated structures", () => {
  const bytes = Buffer.alloc(768),
    pe = 128,
    optional = pe + 24;
  bytes.writeUInt16LE(0x5a4d);
  bytes.writeUInt32LE(pe, 0x3c);
  bytes.writeUInt32LE(0x4550, pe);
  bytes.writeUInt16LE(0x8664, pe + 4);
  bytes.writeUInt16LE(1, pe + 6);
  bytes.writeUInt16LE(240, pe + 20);
  bytes.writeUInt16LE(0x20b, optional);
  bytes.writeUInt32LE(16, optional + 108);
  bytes.writeUInt32LE(512, optional + 144);
  bytes.writeUInt32LE(16, optional + 148);
  bytes.writeUInt32LE(16, 512);
  bytes.writeUInt16LE(0x200, 516);
  bytes.writeUInt16LE(2, 518);
  assert.deepEqual(inspectWindowsPe(bytes), {
    architecture: "x64",
    sha256: sha(bytes),
    signatureSha256: sha(bytes.subarray(512, 528)),
  });
  for (const change of [
    (copy) => copy.writeUInt16LE(0xaa64, pe + 4),
    (copy) => copy.writeUInt32LE(0, optional + 144),
    (copy) => copy.writeUInt32LE(0xffffffff, 0x3c),
    (copy) => copy.writeUInt32LE(1000, optional + 148),
  ]) {
    const copy = Buffer.from(bytes);
    change(copy);
    assert.throws(() => inspectWindowsPe(copy));
  }
  assert.throws(() => inspectWindowsPe(bytes.subarray(0, 520)));
});

test("Windows missing native inputs block before any account or Job admission intent", async () => {
  const f = fixture();
  delete f.effects.installPolicy;
  const result = await f.run();
  assert.equal(result.record.status, "BLOCKED");
  assert.equal(result.record.admission, "not-started");
  assert.deepEqual(result.record.missingInputs, [
    "windows-complete-authority-policy-owner",
  ]);
  assert.deepEqual(f.calls, ["persist-inputs"]);
  const unavailable = fixture();
  unavailable.effects.verifyInputs = async () => ({
    missingInputs: ["windows-build-matched-sdk-exports"],
  });
  assert.equal((await unavailable.run()).record.status, "BLOCKED");
  assert.ok(!unavailable.calls.includes("park"));
});

test("Windows policy, held authority and protected receipts precede suspended payload release", async () => {
  const f = fixture();
  let observations = 0;
  let lateHelper;
  const install = f.effects.installPolicy;
  f.effects.installPolicy = (...args) => {
    lateHelper = args[2];
    return install(...args);
  };
  f.effects.verifyAuthority = async () => {
    f.calls.push("verify-authority");
    return {
      ...structuredClone(f.authority),
      nativeEventSha256: (++observations === 1 ? "a" : "e").repeat(64),
    };
  };
  const result = await f.run();
  assert.equal(result.record.status, "ADMITTED");
  assert.equal(result.record.reservation, "RETAINED");
  assert.deepEqual(
    result.record.helpers.map(({ role }) => role),
    ["launcher", "verifier", "wfp"],
  );
  assert.equal(result.record.helpers[2].settled, true);
  assert.ok(
    f.calls.indexOf("receipt-policy") < f.calls.indexOf("wfp-admitted"),
  );
  assert.ok(f.calls.indexOf("receipt-helper") < f.calls.indexOf("helper-ack"));
  assert.ok(
    f.calls.indexOf("verify-setup") < f.calls.indexOf("install-policy"),
  );
  assert.ok(f.calls.indexOf("receipt-create") < f.calls.indexOf("create-ack"));
  assert.ok(
    f.calls.indexOf("persist-release") < f.calls.indexOf("receipt-release"),
  );
  assert.deepEqual(
    f.calls.filter((value) =>
      ["verify-authority", "receipt-release", "release"].includes(value),
    ),
    ["verify-authority", "receipt-release", "verify-authority", "release"],
  );
  assert.ok(f.records.every((record) => record.reservation === "RETAINED"));
  const writes = f.records.length;
  await assert.rejects(lateHelper({ role: "wfp", settled: false }));
  assert.equal(f.records.length, writes);
  result.record.helpers.length = 0;
  await result.transport.settle();
  assert.equal(f.calls.at(-1), "close");
  await assert.rejects(result.transport.settle());
});

test("Windows launch joins case-equivalent policy paths by held executable identity", async () => {
  const f = fixture("C:\\fixture\\storage\\PAYLOAD.EXE");
  const result = await f.run();
  assert.equal(result.record.status, "ADMITTED");
  assert.ok(f.calls.includes("release"));
  await result.transport.settle();
});

test("Windows authority mismatches retain exclusions and never release", async () => {
  const failures = [
    (f) => {
      f.authority.job.breakaway = true;
    },
    (f) => {
      f.authority.job.heldObjectSha256 = "e".repeat(64);
    },
    (f) => {
      f.authority.token.privileges = ["SeChangeNotifyPrivilege"];
    },
    (f) => {
      f.authority.token.writeRestricted = true;
    },
    (f) => {
      f.authority.handles.hostService = 1;
    },
    (f) => {
      f.authority.workspace.fileId = "f".repeat(32);
    },
    (f) => {
      f.authority.workspace.privateDacl = false;
    },
    (f) => {
      f.authority.executable.authenticode = false;
    },
    (f) => {
      f.authority.executable.fileId = "f".repeat(32);
    },
    (f) => {
      f.authority.payload.creationTime = "20000";
    },
    (f) => {
      f.authority.verifier = f.helper;
    },
    (f) => {
      f.effects.verifyReceipt = async () => ({
        independent: true,
        immutable: true,
        sha256: HASH,
        receiptSha256: HASH,
        verifier: f.verifier,
      });
    },
  ];
  for (const damage of failures) {
    const f = fixture();
    damage(f);
    const result = await f.run();
    assert.equal(result.record.status, "FAIL");
    assert.equal(result.record.reservation, "RETAINED");
    assert.equal(result.transport, null);
    assert.ok(!f.calls.includes("release"));
    assert.ok(f.calls.includes("close"));
  }
  const fresh = fixture();
  let observations = 0;
  fresh.effects.verifyAuthority = async () => ({
    ...structuredClone(fresh.authority),
    threadSuspendCount: ++observations === 1 ? 1 : 0,
  });
  assert.equal((await fresh.run()).record.status, "FAIL");
  assert.ok(!fresh.calls.includes("release"));
});

test("Windows incomplete policy or unbound setup helpers prevent creation acknowledgement", async () => {
  for (const damage of [
    (value) => {
      value.filesystemInstalled = false;
    },
    (value) => {
      value.helpers[0].identity.creationTime = "20000";
      value.helpers[0].identity.pid = 100;
    },
    (value) => {
      value.helpers[0].sourceSha256 = "e".repeat(64);
    },
    (value) => {
      value.helpers[0].settled = false;
    },
  ]) {
    const f = fixture(),
      install = f.effects.installPolicy;
    f.effects.installPolicy = async (...args) => {
      const value = await install(...args);
      damage(value);
      return value;
    };
    const result = await f.run();
    assert.equal(result.record.status, "FAIL");
    assert.ok(!f.calls.includes("create-ack"));
    assert.ok(!f.calls.includes("release"));
  }
});

test("Windows independently mismatched WFP helpers cannot begin policy effects", async () => {
  const f = fixture(),
    inspect = f.effects.inspect;
  f.effects.inspect = async (...args) => {
    const value = await inspect(...args);
    for (const helper of value.helpers)
      if (helper.role === "wfp") helper.imageSha256 = "e".repeat(64);
    return value;
  };
  assert.equal((await f.run()).record.status, "FAIL");
  assert.ok(!f.calls.includes("wfp-admitted"));
  assert.ok(!f.calls.includes("create-ack"));
});

test("Windows caught or unfinished policy-helper verification cannot authorize creation", async () => {
  const caught = fixture(),
    inspect = caught.effects.inspect,
    install = caught.effects.installPolicy;
  let rejectedHelper = false;
  caught.effects.inspect = async (...args) => {
    const value = await inspect(...args);
    for (const helper of value.helpers)
      if (helper.role === "wfp" && !rejectedHelper) {
        helper.imageSha256 = "e".repeat(64);
        rejectedHelper = true;
      }
    return value;
  };
  caught.effects.installPolicy = (request, record, onHelper) =>
    install(request, record, (entry) => onHelper(entry).catch(() => {}));
  assert.equal((await caught.run()).record.status, "FAIL");
  assert.ok(!caught.calls.includes("create-ack"));
  assert.ok(!caught.calls.includes("release"));

  const pending = fixture(),
    installPending = pending.effects.installPolicy,
    inspectPending = pending.effects.inspect;
  let finish, admission;
  pending.effects.inspect = async (...args) => {
    const value = await inspectPending(...args);
    if (value.helpers.some((helper) => helper.role === "wfp"))
      await new Promise((resolve) => {
        finish = resolve;
      });
    return value;
  };
  pending.effects.installPolicy = (request, record, onHelper) =>
    installPending(request, record, (entry) => {
      admission = onHelper(entry);
      admission.catch(() => {});
    });
  const result = await pending.run();
  assert.equal(result.record.status, "FAIL");
  assert.ok(!pending.calls.includes("create-ack"));
  assert.ok(!pending.calls.includes("release"));
  finish?.();
  await assert.rejects(admission);
});

test("Windows a stalled independent verifier cannot release or overwrite its failed receipt after deadline", async () => {
  const f = fixture();
  let entered, finish;
  const waiting = new Promise((resolve) => {
    entered = resolve;
  });
  f.effects.verifyAuthority = () => {
    entered();
    return new Promise((resolve) => {
      finish = resolve;
    });
  };
  const running = f.run();
  await waiting;
  f.expire();
  const result = await running;
  assert.equal(result.record.status, "FAIL");
  assert.ok(f.calls.includes("close"));
  const writes = f.records.length;
  finish(structuredClone(f.authority));
  await Promise.resolve();
  await Promise.resolve();
  assert.equal(f.records.length, writes);
  assert.ok(!f.calls.includes("release"));
});

test("Windows a pipe fault during admission persistence retains a failed possible-effect receipt", async () => {
  const f = fixture(),
    persist = f.effects.persist;
  let reject;
  const fault = new Promise((_, fail) => {
    reject = fail;
  });
  f.transport.wait = (value) => Promise.race([value, fault]);
  f.effects.persist = async (record) => {
    await persist(record);
    if (record.status === "ADMITTED") reject(new Error("Fixture pipe lost"));
  };
  const result = await f.run();
  assert.equal(result.record.status, "FAIL");
  assert.equal(result.record.admission, "possible");
  assert.equal(result.record.reservation, "RETAINED");
  assert.equal(result.transport, null);
  assert.equal(f.records.at(-1).status, "FAIL");
  assert.ok(f.calls.includes("release"));
  assert.ok(f.calls.includes("close"));
});

test("Windows literal observation joins actual UTF-16 output to admitted native identity and private storage", async () => {
  const f = fixture(),
    { record } = await f.run();
  const observation = {
    independent: true,
    verifier: f.verifier,
    requestSha256: record.requestSha256,
    payload: f.payload,
    cwdIdentity: record.authority.cwdIdentity,
    imageSha256: f.request.executable.sha256,
    output:
      JSON.stringify({
        argvUtf16: WINDOWS_LITERAL_ARGUMENTS.map((arg) =>
          Buffer.from(arg, "utf16le").swap16().toString("hex"),
        ),
      }) + "\n",
    exitCode: 0,
    timedOut: false,
    complete: true,
    nativeEventSha256: HASH,
  };
  assert.equal(
    assertWindowsLiteralObservation(
      f.request,
      WINDOWS_LITERAL_ARGUMENTS,
      record,
      observation,
    ).status,
    "OBSERVED",
  );
  for (const bad of [
    { output: observation.output.slice(0, -1) },
    { timedOut: true },
    { payload: { ...f.payload, creationTime: "20000" } },
    { cwdIdentity: "foreign" },
  ])
    assert.throws(() =>
      assertWindowsLiteralObservation(
        f.request,
        WINDOWS_LITERAL_ARGUMENTS,
        record,
        { ...observation, ...bad },
      ),
    );
  assert.equal(
    sameWindowsIdentity(f.payload, { ...f.payload, creationTime: "20000" }),
    false,
  );
});

function channelFixture(setup = async () => {}, materializedPolicy = false) {
  const child = new EventEmitter();
  child.pid = 100;
  for (const kind of ["stdin", "stdout", "stderr"])
    child[kind] = new PassThrough();
  const f = fixture();
  let expire;
  const acknowledgements = [];
  child.stdin.on("data", (bytes) => acknowledgements.push(bytes.toString()));
  const channel = windowsAdmissionChannel(
    child,
    f.request.nonce,
    async () => {},
    setup,
    {
      schedule: (callback) => {
        expire = callback;
        return 1;
      },
      cancel: () => {},
      materializedPolicy,
    },
  );
  const frame = (phase) =>
    child.stdout.write(
      JSON.stringify({
        nonce: f.request.nonce,
        phase,
        helper: f.helper,
        payload: phase === "ready" ? f.payload : null,
        accountSid: phase === "helper" ? null : ACCOUNT,
      }) + "\n",
    );
  const teardown = () => {
    channel.close();
    child.emit("close", 0, null);
    for (const kind of ["stdin", "stdout", "stderr"]) child[kind].destroy();
  };
  return {
    child,
    channel,
    frame,
    acknowledgements,
    expire: () => expire(),
    teardown,
  };
}
test("Windows private control frames acknowledge helper, policy and payload separately from output", async () => {
  const f = channelFixture();
  try {
    let ack = once(f.child.stdin, "data");
    f.frame("helper");
    await ack;
    ack = once(f.child.stdin, "data");
    f.frame("setup");
    await ack;
    f.frame("ready");
    await f.channel.ready;
    assert.equal(f.channel.output, f.child.stderr);
    assert.deepEqual(f.acknowledgements, ["P", "C"]);
    await f.channel.release();
    assert.deepEqual(f.acknowledgements, ["P", "C", "R"]);
    f.child.emit("close", 0, null);
    assert.equal((await f.channel.completion).phase, "released");
  } finally {
    f.teardown();
  }
});
test("Windows setup sends only the independently materialized hash and rejects an invalid pin", async () => {
  for (const pin of [HASH, "invalid", null]) {
    const f = channelFixture(async () => ({ policySha256: pin }), true);
    try {
      const helper = once(f.child.stdin, "data");
      f.frame("helper");
      await helper;
      const setup =
        pin === HASH
          ? once(f.child.stdin, "data")
          : assert.rejects(f.channel.ready);
      f.frame("setup");
      await setup;
      assert.deepEqual(
        f.acknowledgements,
        pin === HASH ? ["P", "C" + HASH + "\n"] : ["P"],
      );
      if (pin === HASH) {
        f.frame("ready");
        await f.channel.ready;
        await f.channel.release();
        assert.equal(f.acknowledgements.at(-1), "R");
      }
    } finally {
      f.teardown();
    }
  }
});
test("Windows release awaits pipe delivery and rejects asynchronous write failure", async () => {
  const f = channelFixture();
  try {
    let ack = once(f.child.stdin, "data");
    f.frame("helper");
    await ack;
    ack = once(f.child.stdin, "data");
    f.frame("setup");
    await ack;
    f.frame("ready");
    await f.channel.ready;
    let finish;
    f.child.stdin._write = (_, __, callback) => {
      finish = callback;
    };
    const release = Promise.resolve(f.channel.release());
    finish(new Error("Fixture pipe rejected the release byte"));
    await assert.rejects(release);
    await assert.rejects(f.channel.completion);
    assert.deepEqual(f.acknowledgements, ["P", "C"]);
  } finally {
    f.teardown();
  }
});
test("Windows malformed or expired control channels cannot grant payload release", async () => {
  for (const fault of [
    (f) => f.frame("ready"),
    (f) => f.child.stdout.write(Buffer.alloc(4097)),
    (f) => f.child.stderr.emit("error", new Error("Fixture output pipe lost")),
    (f) => f.child.emit("close", 0, null),
    (f) => f.expire(),
  ]) {
    const f = channelFixture();
    try {
      fault(f);
      await assert.rejects(f.channel.ready);
      await assert.rejects(f.channel.completion);
      assert.throws(() => f.channel.release());
      assert.deepEqual(f.acknowledgements, []);
    } finally {
      f.teardown();
    }
  }
});

test("the actual launcher keeps experiment image admission separate from reviewed trust and preserves trust failures", async () => {
  const source = await readFile(new URL("launcher.c", import.meta.url), "utf8"),
    body = /static void image\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(source)[1],
    head = body.slice(0, body.indexOf("  LARGE_INTEGER zero")),
    tail = body.slice(body.indexOf("#ifdef NATIVE_CI_EXPERIMENT"));
  // The held file/hash and PE parser have their own admission fixtures. Execute
  // the actual trust decision with the independently observed PE directory.
  for (const experiment of [false, true])
    for (const fault of [
      "unsigned",
      "signed",
      "verify",
      "close",
      "both",
      "digest",
      "directory",
    ]) {
      const calls = [],
        diagnostics = [];
      let error = 87;
      const status = 0x800b0100,
        cert = {
          Size: ["unsigned", "directory", "digest"].includes(fault) ? 0 : 16,
          VirtualAddress: fault === "directory" ? 128 : 0,
        },
        program = head + tail;
      const actual = program
        .replace(
          /#ifdef NATIVE_CI_EXPERIMENT\n([\s\S]*?)#endif/gu,
          (_, text) => (experiment ? text : ""),
        )
        .replace("LARGE_INTEGER length;", "const length={};")
        .replace(
          "IMAGE_DATA_DIRECTORY cert = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];",
          "const cert=pe.OptionalHeader.DataDirectory[0];",
        )
        .replace(/(?:GUID|LONG) (action|result|closed)/gu, "let $1")
        .replace("WINTRUST_FILE_INFO info = {0}", "const info = {}")
        .replace("WINTRUST_DATA trust = {0}", "const trust = {}")
        .replace(/sizeof\((?:info|trust)\)/gu, "1")
        .replace(/\((?:DWORD|ULONGLONG)\)/gu, "")
        .replace(/&(action|trust|info|length)/gu, "$1");
      const run = () =>
        new Script(`(function(){${actual}})()`).runInNewContext({
          NULL: null,
          FALSE: false,
          ERROR_SUCCESS: 0,
          WINTRUST_ACTION_GENERIC_VERIFY_V2: 1,
          WTD_UI_NONE: 2,
          WTD_REVOKE_NONE: 4,
          WTD_CHOICE_FILE: 8,
          WTD_STATEACTION_VERIFY: 16,
          WTD_STATEACTION_CLOSE: 32,
          WTD_CACHE_ONLY_URL_RETRIEVAL: 64,
          WTD_REVOCATION_CHECK_NONE: 128,
          file: "held",
          name: "C:\\Fixture\\payload.exe",
          pin: HASH,
          maximum: 2048,
          exact: true,
          pe: { OptionalHeader: { DataDirectory: [cert] } },
          file_hash: (...args) => {
            calls.push(["hash", ...args]);
            assert.notEqual(fault, "digest");
          },
          GetFileSizeEx: (_, length) => {
            length.QuadPart = 2048;
            return true;
          },
          WinVerifyTrust: (_, __, trust) => {
            const closing = trust.dwStateAction === 32;
            calls.push([closing ? "close" : "verify"]);
            error = 5; // WinVerifyTrust returns its status; LastError supplies no cause.
            return closing
              ? ["close", "both"].includes(fault)
                ? 6
                : 0
              : ["unsigned", "directory", "verify", "both"].includes(fault)
                ? status
                : 0;
          },
          stderr: {},
          fprintf: (_, ...values) => diagnostics.push(values),
          fflush: () => {
            error = 90;
          },
          SetLastError: (value) => {
            error = value;
          },
          need: (value) => {
            if (!value) throw new Error(String(error));
          },
        });
      const skipped =
          experiment &&
          !cert.Size &&
          fault !== "directory" &&
          fault !== "digest",
        accepted = skipped || fault === "signed";
      if (accepted) run();
      else
        assert.throws(
          run,
          fault === "digest" || (experiment && fault === "directory")
            ? undefined
            : new RegExp(String(fault === "close" ? 6 : status), "u"),
        );
      assert.equal(calls[0][0], "hash");
      assert.deepEqual(
        calls.filter(([name]) => name !== "hash").map(([name]) => name),
        skipped || fault === "digest" || (experiment && fault === "directory")
          ? []
          : ["verify", "close"],
      );
      if (["verify", "close", "both"].includes(fault))
        assert.equal(diagnostics.length, 1);
    }
});

test("the native ownership producer carries the exact literal argv and existing finite modes as data", async () => {
  const source = await readFile(
      new URL("custody-reader.c", import.meta.url),
      "utf8",
    ),
    start = source.indexOf(
      "  need(case_token && case_job",
      source.indexOf("static void ownership_launch("),
    ),
    body = source
      .slice(start, source.indexOf("  char sig[65];", start))
      .replace(
        'wchar_t command[32767] = L"", temp[4096];',
        'const command=[],temp={text:""};',
      )
      .replace("wchar_t first[4096];", 'const first={text:""};')
      .replace(
        /const wchar_t \*corpus\[\] = \{([^}]+)\};/u,
        "const corpus=[$1];",
      )
      .replaceAll("sizeof(corpus)/sizeof(corpus[0])", "corpus.length")
      .replace(/\b(?:unsigned|BOOL)\b/gu, "let")
      .replace(/\bL(?=["'])/gu, "")
      .replace(/\\x([a-f0-9]{4})/giu, "\\u$1")
      .replace(/(temp|first)\[0\] = 0/gu, '$1.text = ""')
      .replace(/temp\[([ij0-9]+)\]/gu, "temp.text[$1]");
  for (const args of [
    WINDOWS_LITERAL_ARGUMENTS,
    ["detached", "c".repeat(32)],
    ["suite", "c".repeat(32)],
  ]) {
    const text = (value) => (typeof value === "object" ? value.text : value),
      entries = Array.from({ length: 7 }, (_, i) => ({
        path: `C:\\Fixture\\Private Root\\slot-${i}`,
        pin: HASH,
      })),
      values = [
        "ownership-launch",
        "31",
        String(args.length),
        ...args.map((arg) =>
          arg === "" ? "-" : Buffer.from(arg, "utf16le").toString("hex"),
        ),
      ],
      api = {
        values,
        n: values.length,
        entries,
        nonce: "c".repeat(32),
        case_record: { restrictingSid: ACCOUNT },
        case_token: true,
        case_job: true,
        ownership_launcher: { hProcess: null },
        helpers: [{}, {}],
        package_mode: false,
        ownership_literal: false,
        ownership_spoofed: false,
        access_mode: false,
        need: assert.ok,
        bounded_number: (value, maximum) => {
          const n = Number(value);
          assert.ok(n >= 0 && n <= maximum);
          return n;
        },
        decode: (value, out) => {
          out.text = Buffer.from(value, "hex").toString("utf16le");
        },
        strcmp: (a, b) => (a === b ? 0 : 1),
        wcscmp: (a, b) => (text(a) === text(b) ? 0 : 1),
        wcslen: (value) => text(value).length,
        swprintf_s: (out, _, format, ...args) => {
          let i = 0;
          out.text = format.replace(/%[hl]s/gu, () => text(args[i++]));
          return out.text.length;
        },
        quoted: (out, _, value) => out.push(text(value)),
      };
    const command = new Script(`${body}\ncommand;`).runInNewContext(api);
    assert.deepEqual(Array.from(command), [
      entries[5].path,
      api.nonce,
      ACCOUNT,
      entries[2].path,
      entries[3].path,
      entries[4].path,
      entries[6].path,
      HASH,
      entries[2].path + "\\policy",
      "pending",
      args === WINDOWS_LITERAL_ARGUMENTS
        ? "--ownership-literal"
        : args[0] === "suite"
          ? "--access"
          : "--ownership",
      ...args,
    ]);
  }
});

test("actual Job adoption samples every query and rejects assignment history even with no active members", async () => {
  const source = await readFile(new URL("account.h", import.meta.url), "utf8"),
    body = /static void account_job_unused\([^\n]+\) \{([\s\S]*?)\n\}/u.exec(
      source,
    )?.[1];
  assert.ok(body);
  const program = new Script(
    `(job, phase) => {${body
      .replace(
        /JOBOBJECT_\w+ (limits|ui|accounting) = \{0\};/gu,
        (_, name) =>
          `const ${name} = ${name === "limits" ? "{BasicLimitInformation:{LimitFlags:0,ActiveProcessLimit:0}}" : name === "ui" ? "{UIRestrictionsClass:0}" : "{ActiveProcesses:0,TotalProcesses:0,TotalTerminatedProcesses:0}"};`,
      )
      .replace(/\b(?:BOOL|DWORD)\b/gu, "const")
      .replace(/sizeof\(\w+\)/gu, "1")
      .replace(/&(limits|ui|accounting)\b/gu, "$1")
      .replace(/\(unsigned\)/gu, "")}}`,
  );
  for (const fault of [
    null,
    "limits",
    "ui",
    "accounting",
    "flags",
    "limit",
    "restrictions",
    "active",
    "history",
  ]) {
    let error = 999;
    const calls = [],
      diagnostics = [],
      run = () =>
        program.runInNewContext({
          ERROR_SUCCESS: 0,
          ERROR_INVALID_DATA: 13,
          JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: 0x2000,
          JOB_OBJECT_LIMIT_ACTIVE_PROCESS: 8,
          JobObjectExtendedLimitInformation: "limits",
          JobObjectBasicUIRestrictions: "ui",
          JobObjectBasicAccountingInformation: "accounting",
          NULL: null,
          stderr: "stderr",
          SetLastError: (value) => {
            error = value;
          },
          GetLastError: () => error,
          QueryInformationJobObject: (job, kind, value) => {
            assert.equal(job, "original-job");
            calls.push(kind);
            if (kind === "limits")
              Object.assign(value.BasicLimitInformation, {
                LimitFlags: fault === "flags" ? 0x2808 : 0x2008,
                ActiveProcessLimit: fault === "limit" ? 1 : 32,
              });
            if (kind === "ui")
              value.UIRestrictionsClass = fault === "restrictions" ? 0 : 255;
            if (kind === "accounting")
              Object.assign(value, {
                ActiveProcesses: fault === "active" ? 1 : 0,
                TotalProcesses: fault === "history" ? 1 : 0,
                TotalTerminatedProcesses: fault === "history" ? 1 : 0,
              });
            error = fault === kind ? 5 : 777;
            return fault !== kind;
          },
          fprintf: (_stream, format, ...values) => {
            diagnostics.push(values);
            assert.match(format, /active=%lu total=%lu terminated=%lu/u);
            error = 6; // Reporting cannot replace the sampled API failure.
          },
          fflush: () => {},
          need: (accepted) => {
            if (!accepted) throw new Error("adoption refused: " + error);
          },
        })("original-job", "adopt");
    if (fault)
      assert.throws(
        run,
        new RegExp(
          `adoption refused: ${["limits", "ui", "accounting"].includes(fault) ? 5 : 13}`,
          "u",
        ),
      );
    else run();
    assert.deepEqual(calls, ["limits", "ui", "accounting"], String(fault));
    assert.equal(diagnostics.length, fault ? 1 : 0);
    if (fault === "history")
      assert.deepEqual(diagnostics[0].slice(-3), [0, 1, 1]);
  }
});

test("the actual Job producer preserves creation errors across descriptor release", async () => {
  const source = await readFile(
      new URL("custody-reader.c", import.meta.url),
      "utf8",
    ),
    begin = source.indexOf(
      '  need(swprintf_s(jobName, 96, L"Local\\\\NativeProof-%hs"',
    ),
    end = source.indexOf("JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits", begin),
    body = source
      .slice(begin, end)
      .replace("DWORD jobError", "const jobError")
      .replace("&sa", "sa")
      .replaceAll('L"', '"'),
    program = new Script(body);
  assert.ok(begin > 0 && end > begin);
  for (const status of [0, 5, 183]) {
    let error = 0;
    const api = {
      case_job: null,
      jobName: {},
      nonce: "c".repeat(32),
      sa: {},
      sd: {},
      ERROR_ALREADY_EXISTS: 183,
      swprintf_s: () => 1,
      SetLastError: (value) => {
        error = value;
      },
      GetLastError: () => error,
      CreateJobObjectW: () => {
        error = status;
        return status === 5 ? null : "job";
      },
      LocalFree: () => {
        error = 6;
      },
      need: (ok) => {
        if (!ok) throw new Error("Job creation refused: " + error);
      },
    };
    if (status)
      assert.throws(
        () => program.runInNewContext(api),
        new RegExp(`Job creation refused: ${status}`, "u"),
      );
    else program.runInNewContext(api);
    assert.equal(error, status);
  }
});

test("the actual named Job handoff opens provisioned authority and never resets its limits", async () => {
  const source = await readFile(new URL("launcher.c", import.meta.url), "utf8"),
    begin = source.indexOf(
      "  SetLastError(ERROR_SUCCESS);\n  HANDLE createdJob",
    ),
    body = source
      .slice(begin, source.indexOf("  if (provisioned) {", begin))
      .replace("&protectedSa", "protectedSa")
      .replace(/\b(?:HANDLE|DWORD)\b/gu, "const");
  assert.ok(begin > 0);
  const program = new Script(`${body}\ncreatedJob;`);
  for (const provisioned of [false, true]) {
    const calls = [];
    const result = program.runInNewContext({
      provisioned,
      protectedSa: {},
      jobName: "Local\\NativeProof-fixture",
      JOB_OBJECT_ALL_ACCESS: 0x1f003f,
      ERROR_SUCCESS: 0,
      FALSE: false,
      NULL: null,
      SetLastError: () => {},
      GetLastError: () => 0,
      OpenJobObjectW: (_access, inherit, name) => {
        assert.equal(inherit, false);
        calls.push(["open", name]);
        return "original";
      },
      CreateJobObjectW: (_attributes, name) => {
        calls.push(["create", name]);
        return "new";
      },
      checked: assert.ok,
      SetInformationJobObject: assert.fail,
    });
    assert.equal(result, provisioned ? "original" : "new");
    assert.deepEqual(calls, [
      [provisioned ? "open" : "create", "Local\\NativeProof-fixture"],
    ]);
  }
  const adopted = source.slice(
    source.indexOf("  if (provisioned) {", begin),
    source.indexOf("  wchar_t stationName", begin),
  );
  assert.match(adopted, /account_job_unused\(createdJob, "adopt"\)/u);
  assert.match(
    adopted,
    /if \(!provisioned\) \{[\s\S]*SetInformationJobObject/u,
  );
});
