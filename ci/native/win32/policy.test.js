import assert from "node:assert/strict";
import test from "node:test";
import {
  buildWindowsPolicy,
  assertWindowsPolicyInstallation,
  configureWindowsPolicy,
  assertWindowsAccessObservation,
  WINDOWS_ACCESS_DENIALS,
  runWindowsAccessCase,
} from "./index.js";
import { digest, windowsLaunchDigest } from "./protocol.js";
import { windowsPolicyFixture, policyIdentity } from "./policy.fixture.js";

const HASH = "a".repeat(64),
  ACCOUNT = "S-1-5-21-1-2-3-1001";
function fixture(profile = "workspace-write") {
  const request = {
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
  };
  return windowsPolicyFixture(request, ACCOUNT, profile);
}
const options = {
  platform: "win32",
  architecture: "x64",
  build: "10.0.26100.1",
  env: {
    CI: "true",
    GITHUB_ACTIONS: "true",
    ImageOS: "win25",
    ImageVersion: "20250928.1.0",
  },
  now: () => 0,
  schedule: () => 1,
  cancel: () => {},
};

test("Windows policy binds three profiles, protected parents and both ALE tuple directions", () => {
  for (const profile of ["read-only", "workspace-write", "trusted-command"]) {
    const { input, plan, installation } = fixture(profile);
    assert.equal(
      assertWindowsPolicyInstallation(installation, input),
      installation,
    );
    assert.equal(
      plan.manifest.objects.find((entry) => entry.name === "workspace").grant,
      profile === "read-only" ? "read-tree" : "workspace",
    );
    assert.equal(
      plan.manifest.objects.find((entry) => entry.name === "pointer").grant,
      "read",
    );
    for (const endpoint of input.endpoints)
      for (const layer of ["CONNECT", "RECV_ACCEPT"]) {
        const permits = plan.manifest.filters.filter(
          (entry) =>
            entry.layer ===
              `ALE_AUTH_${layer}_${endpoint.family.toUpperCase()}` &&
            entry.action === "PERMIT" &&
            entry.conditions.protocol === endpoint.protocol,
        );
        assert.deepEqual(
          permits.map((entry) => [
            entry.conditions.localPort,
            entry.conditions.remotePort,
          ]),
          [
            [endpoint.clientPort, endpoint.serverPort],
            [endpoint.serverPort, endpoint.clientPort],
          ],
        );
        assert.ok(
          permits.every(
            (entry) => entry.principal === ACCOUNT && entry.persistent,
          ),
        );
      }
    if (profile === "trusted-command")
      assert.throws(() => buildWindowsPolicy({ ...input, disposable: false }));
  }
  const { input } = fixture();
  for (const mutate of [
    (value) => {
      value.runtime[0].path = "C:\\Windows\\System32\\ambient.dll";
    },
    (value) => {
      value.endpoints[0].serverPort = value.endpoints[0].clientPort;
    },
    (value) => {
      value.runtime[0].path = "C:\\Fixture\\Storage\\Work\\alias.exe";
    },
  ]) {
    const changed = structuredClone(input);
    mutate(changed);
    assert.throws(() => buildWindowsPolicy(changed));
  }
});

test("Windows admission rejects incomplete filters, unknown token semantics and inherited deletion authority", () => {
  const { input, installation } = fixture();
  for (const mutate of [
    (value) => {
      value.effective.wfp.filters.pop();
    },
    (value) => {
      value.effective.wfp.filters[0].descriptor.principal = null;
    },
    (value) => {
      value.effective.wfp.unknownIdentityDenied = false;
    },
    (value) => {
      value.effective.wfp.loopbackAleVerified = false;
    },
    (value) => {
      value.effective.wfp.udpReturnAleVerified = false;
    },
    (value) => {
      value.effective.wfp.noConflictingHardPermit = false;
    },
    (value) => {
      value.effective.wfp.noLoopbackExemption = false;
    },
    (value) => {
      value.effective.wfp.dynamicSession = true;
    },
    (value) => {
      value.effective.objects[2].rights.deleteChild = true;
    },
    (value) => {
      value.effective.inheritedOwnerRightsProtected = false;
    },
    (value) => {
      value.effective.creationDaclProtectionVerified = false;
    },
    (value) => {
      value.effective.token.writeRestricted = true;
    },
    (value) => {
      value.effective.objects[4].foreignWritableHandles = 1;
    },
  ]) {
    const changed = structuredClone(installation);
    mutate(changed);
    assert.throws(() => assertWindowsPolicyInstallation(changed, input));
  }
});

function policyEffects(installation) {
  const calls = [],
    records = [];
  const helper = {
    identity: policyIdentity(103),
    imageSha256: HASH,
    sourceSha256: HASH,
  };
  return {
    calls,
    records,
    helper,
    effects: {
      persist: async (record) => {
        calls.push(record.phase);
        records.push(structuredClone(record));
      },
      review: async (_, approvedSha256) => ({
        approvedSha256,
        localSystemSession0: true,
        helperImageSha256: HASH,
        helperSourceSha256: HASH,
        sdkExportsVerified: true,
        loaderClosureVerified: true,
        completeCompositionReviewed: true,
      }),
      snapshot: async (input, phase) =>
        phase === "effective"
          ? structuredClone(installation.effective)
          : {
              independent: true,
              admissionsClosed: true,
              exclusiveWriter: true,
              noExistingOwnedPolicy: true,
              accountReservationVerified: true,
              registryAbsent: true,
              baselineInventoryVerified: true,
              candidateSha: input.request.candidateSha,
              objects: installation.effective.objects
                .filter((entry) => entry.descriptor.name !== "registry")
                .map((entry) => ({
                  ...entry,
                  path: entry.descriptor.path,
                  systemOnlyDacl: true,
                })),
              nonce: input.request.nonce,
              compositionSha256: installation.compositionSha256,
              nativeEventSha256: HASH,
              verifier: policyIdentity(102),
            },
      mutate: async (_, operation, admit) => {
        await admit(helper);
        calls.push(operation + "-native");
      },
      verifySettlement: async () => ({
        independent: true,
        signaled: true,
        exitCode: 0,
        timedOut: false,
        nativeEventSha256: HASH,
        helper: helper.identity,
        verifier: policyIdentity(104),
      }),
      verifyReceipt: async (record) => ({
        independent: true,
        immutable: true,
        sha256: HASH,
        verifier: policyIdentity(104),
        contentSha256: digest(JSON.stringify(record) + "\n"),
      }),
    },
  };
}
test("Windows policy writes follow persisted helper/intent barriers and uncertainty retains persistent custody", async () => {
  const { input, plan, installation } = fixture();
  const good = policyEffects(installation);
  const result = await configureWindowsPolicy(
    input,
    plan.compositionSha256,
    good.effects,
    options,
  );
  assert.equal(result.status, "INSTALLED");
  assert.ok(
    good.calls.indexOf("install-intent") < good.calls.indexOf("install-native"),
  );
  assert.equal(
    good.records.find((record) => record.helpers.length).helpers[0].settled,
    false,
  );
  const failed = policyEffects(installation);
  failed.effects.verifySettlement = async () => ({
    independent: true,
    signaled: false,
  });
  const excluded = await configureWindowsPolicy(
    input,
    plan.compositionSha256,
    failed.effects,
    options,
  );
  assert.equal(excluded.status, "FAILED");
  assert.equal(excluded.reservation, "RETAINED");
  assert.ok(!failed.calls.includes("remove-native"));
  const missing = policyEffects(installation);
  delete missing.effects.snapshot;
  assert.equal(
    (
      await configureWindowsPolicy(
        input,
        plan.compositionSha256,
        missing.effects,
        options,
      )
    ).status,
    "BLOCKED",
  );
  assert.ok(!missing.calls.includes("install-native"));
});

test("Windows policy rejects late, caught and unfinished helper acknowledgments", async () => {
  const { input, plan, installation } = fixture();
  for (const mode of ["late", "caught", "unfinished"]) {
    const fixture = policyEffects(installation);
    const entered = Promise.withResolvers();
    const finish = Promise.withResolvers();
    let acknowledge, pending;
    fixture.effects.mutate = async (_, _operation, admit) => {
      acknowledge = () => admit(fixture.helper);
      if (mode === "late") return;
      if (mode === "unfinished") {
        pending = acknowledge();
        pending.catch(() => {});
        await entered.promise;
      } else {
        try {
          await acknowledge();
        } catch {}
      }
    };
    const result = await configureWindowsPolicy(
      input,
      plan.compositionSha256,
      fixture.effects,
      {
        ...options,
        onHelper: async () => {
          if (mode === "caught")
            throw new Error("helper acknowledgment failed");
          entered.resolve();
          await finish.promise;
        },
      },
    );
    assert.equal(result.status, "FAILED");
    assert.equal(result.reservation, "RETAINED");
    assert.equal(result.helpersSettled, false);
    const writes = fixture.records.length;
    if (mode === "unfinished") {
      finish.resolve();
      await assert.rejects(pending);
    } else if (mode === "late") {
      await assert.rejects(acknowledge());
    }
    assert.equal(fixture.records.length, writes);
  }
});

test("Windows policy removal requires fresh independent retirement and the exact owned filters", async () => {
  const { input, plan, installation } = fixture();
  const admission = {
    status: "ADMITTED",
    candidateSha: input.request.candidateSha,
    nonce: input.request.nonce,
    request: input.request,
    arguments: [
      input.request.nonce,
      "read",
      input.request.workspace + "\\owned.txt",
    ],
    accountSid: ACCOUNT,
    admission: "possible",
    reservation: "RETAINED",
    policyReceiptSha256: installation.receiptSha256,
    helpers: [{ role: "launcher", identity: policyIdentity(103) }],
    setup: { job: { heldObjectSha256: HASH } },
  };
  admission.requestSha256 = windowsLaunchDigest(
    admission.request,
    admission.arguments,
  );
  const retirement = {
    schemaVersion: 1,
    candidateSha: input.request.candidateSha,
    nonce: input.request.nonce,
    status: "RETIRED",
    independent: true,
    freshVerifier: policyIdentity(104),
    requestSha256: admission.requestSha256,
    accountSid: ACCOUNT,
    jobObjectSha256: HASH,
    noLiveMembers: true,
    helpersSettled: true,
    reservation: "RETAINED",
    nativeEventSha256: HASH,
    members: [],
    helpers: structuredClone(admission.helpers),
  };
  const fresh = {
    independent: true,
    candidateSha: input.request.candidateSha,
    nonce: input.request.nonce,
    requestSha256: admission.requestSha256,
    retirementSha256: digest(JSON.stringify(retirement) + "\n"),
    admissionsClosed: true,
    helpersSettled: true,
    heldProcessesSignaled: true,
    noForeignCreators: true,
    noPrincipalFlows: true,
    protectedReceiptVerified: true,
    admissionReceiptVerified: true,
    policyReceiptSha256: HASH,
    jobPresent: false,
    nativeEventSha256: HASH,
    verifier: policyIdentity(105),
    domain: {
      complete: true,
      candidateSha: input.request.candidateSha,
      nonce: input.request.nonce,
      accountSid: ACCOUNT,
      jobObjectSha256: HASH,
      accountReservationVerified: true,
      capacity: 33,
      truncated: false,
      nativeEventSha256: HASH,
      jobPresent: false,
      processes: [],
    },
  };
  for (const mutation of [
    null,
    (value) => {
      value.heldProcessesSignaled = false;
    },
    (value) => {
      value.domain.truncated = true;
    },
    (value) => {
      value.requestSha256 = "d".repeat(64);
    },
    (value) => {
      value.retirementSha256 = "d".repeat(64);
    },
    (value) => {
      value.domain.nonce = "d".repeat(32);
    },
    (value) => {
      value.domain.jobObjectSha256 = "d".repeat(64);
    },
  ]) {
    const current = structuredClone(fresh);
    mutation?.(current);
    const state = policyEffects(installation);
    state.effects.verifyRetirement = async () => current;
    state.effects.snapshot = async (_, phase) => {
      const result = structuredClone(installation.effective);
      if (phase === "effective") result.wfp.filters = [];
      return result;
    };
    const result = await configureWindowsPolicy(
      input,
      plan.compositionSha256,
      state.effects,
      {
        ...options,
        operation: "remove",
        previous: installation,
        retirement,
        admission,
      },
    );
    assert.equal(result.status, mutation ? "FAILED" : "REMOVED");
    assert.equal(state.calls.includes("remove-native"), !mutation);
    assert.equal(result.reservation, "RETAINED");
  }
  for (const helpers of [
    [],
    [{ role: "launcher", identity: policyIdentity(203) }],
  ]) {
    const omitted = { ...retirement, helpers };
    const state = policyEffects(installation);
    state.effects.verifyRetirement = async () => ({
      ...fresh,
      retirementSha256: digest(JSON.stringify(omitted) + "\n"),
    });
    state.effects.snapshot = async (_, phase) => {
      const result = structuredClone(installation.effective);
      if (phase === "effective") result.wfp.filters = [];
      return result;
    };
    const result = await configureWindowsPolicy(
      input,
      plan.compositionSha256,
      state.effects,
      {
        ...options,
        operation: "remove",
        previous: installation,
        retirement: omitted,
        admission,
      },
    );
    assert.equal(result.status, "FAILED");
    assert.equal(state.calls.includes("remove-native"), false);
    assert.equal(result.reservation, "RETAINED");
  }
  for (const changedPhase of ["remove", "effective"]) {
    const state = policyEffects(installation);
    state.effects.verifyRetirement = async () => fresh;
    state.effects.snapshot = async (_, phase) => {
      const result = structuredClone(installation.effective);
      if (phase === "effective") result.wfp.filters = [];
      if (phase === changedPhase)
        result.endpoints[0].client.reservationIdentitySha256 = "d".repeat(64);
      return result;
    };
    const result = await configureWindowsPolicy(
      input,
      plan.compositionSha256,
      state.effects,
      {
        ...options,
        operation: "remove",
        previous: installation,
        retirement,
        admission,
      },
    );
    assert.equal(result.status, "FAILED");
    assert.equal(
      state.calls.includes("remove-native"),
      changedPhase === "effective",
    );
    assert.equal(result.reservation, "RETAINED");
  }
});

test("Windows a stalled policy mutation cannot settle or release reservations after its deadline", async () => {
  const { input, plan, installation } = fixture(),
    state = policyEffects(installation);
  let expire, acknowledged;
  const ready = new Promise((resolve) => {
    acknowledged = resolve;
  });
  state.effects.mutate = async (_, operation, admit) => {
    await admit({
      identity: policyIdentity(103),
      imageSha256: HASH,
      sourceSha256: HASH,
    });
    acknowledged();
    return new Promise(() => {});
  };
  const pending = configureWindowsPolicy(
    input,
    plan.compositionSha256,
    state.effects,
    {
      ...options,
      schedule: (callback) => {
        expire = callback;
        return 1;
      },
    },
  );
  await ready;
  expire();
  const result = await pending;
  assert.equal(result.status, "FAILED");
  assert.equal(result.reservation, "RETAINED");
  assert.equal(result.helpersSettled, false);
  assert.equal(state.records.at(-1).phase, "excluded");
});

function accessObservation(input, installation) {
  const payload = policyIdentity(101, ACCOUNT),
    native = {
      independent: true,
      nonce: input.request.nonce,
      nativeEventSha256: HASH,
      timedOut: false,
      lossCount: 0,
      identityVerified: true,
    };
  const state = {
    identitySha256: HASH,
    bytesSha256: HASH,
    nativeEventSha256: HASH,
  };
  const observation = {
    ...native,
    candidateSha: input.request.candidateSha,
    compositionSha256: installation.compositionSha256,
    jobObjectSha256: HASH,
    members: [
      payload,
      policyIdentity(102, ACCOUNT),
      policyIdentity(202, ACCOUNT),
    ].map((identity) => ({
      ...native,
      identity,
      verifier: policyIdentity(104),
      token: structuredClone(installation.effective.token),
      jobObjectSha256: HASH,
      creationTimeJobVerified: true,
      heldIdentityVerified: true,
    })),
    identity: payload,
    verifier: policyIdentity(104),
    token: structuredClone(installation.effective.token),
    privateChannelsOnly: true,
    providersExcluded: true,
    read: {
      ...native,
      identity: payload,
      allowed: true,
      nativeCode: 0,
      bytes: input.request.nonce,
      fileIdentitySha256: HASH,
    },
    edit: {
      ...native,
      identity: payload,
      allowed: input.profile !== "read-only",
      nativeCode: input.profile === "read-only" ? 5 : 0,
      bytes: input.request.nonce + "-owned-edit",
      before: state,
      after: {
        ...state,
        bytesSha256: input.profile === "read-only" ? HASH : "d".repeat(64),
      },
    },
    denials: WINDOWS_ACCESS_DENIALS.map((caseId) => ({
      ...native,
      caseId,
      identity: payload,
      attempted: true,
      allowed: false,
      nativeCode:
        caseId === "com" ? 0x80070005 : caseId === "wmi" ? 0x80041003 : 5,
      before: state,
      after: state,
      control: {
        ...native,
        identity: policyIdentity(200),
        ready: true,
        reachable: true,
        readyBeforeAttempt: true,
        verifier: policyIdentity(205),
        bytes: input.request.nonce,
        targetIdentitySha256: HASH,
      },
      filterId: installation.effective.wfp.filters.find(
        (entry) =>
          entry.descriptor.purpose === "account-default" &&
          entry.descriptor.layer.endsWith(
            caseId.includes("-v6-") ? "V6" : "V4",
          ),
      ).id,
      wfpAction: "DROP",
      layer: "ALE_AUTH_CONNECT_" + (caseId.includes("-v6-") ? "V6" : "V4"),
      localPrincipalSid: ACCOUNT,
      protocol: caseId.endsWith("-tcp") ? "tcp" : "udp",
      filterIdentity: payload,
      socketIdentityVerified: true,
      socketIdentitySha256: HASH,
    })),
    loopback: input.endpoints.map((endpoint) => ({
      ...native,
      family: endpoint.family,
      protocol: endpoint.protocol,
      readyBeforeAttempt: true,
      client: {
        identity: payload,
        userSid: ACCOUNT,
        restrictedSids: [input.request.restrictingSid],
        heldIdentityVerified: true,
        reservationIdentitySha256: HASH,
        socketIdentitySha256: digest(
          endpoint.family + endpoint.protocol + "client",
        ),
      },
      server: {
        identity: policyIdentity(102, ACCOUNT),
        userSid: ACCOUNT,
        restrictedSids: [input.request.restrictingSid],
        heldIdentityVerified: true,
        reservationIdentitySha256: HASH,
        socketIdentitySha256: digest(
          endpoint.family + endpoint.protocol + "server",
        ),
      },
      bytes: input.request.nonce,
      echo: input.request.nonce,
      events: ["request", "return"].flatMap((leg) =>
        ["connect", "receive"].map((direction) => {
          const clientLocal = (leg === "request") === (direction === "connect"),
            localPort = clientLocal ? endpoint.clientPort : endpoint.serverPort;
          const flowReturn = endpoint.protocol === "tcp" && leg === "return",
            connectLayer = (direction === "connect") !== flowReturn;
          const layer = `ALE_AUTH_${connectLayer ? "CONNECT" : "RECV_ACCEPT"}_${endpoint.family.toUpperCase()}`;
          const filter = installation.effective.wfp.filters.find(
            (entry) =>
              entry.descriptor.action === "PERMIT" &&
              entry.descriptor.layer === layer &&
              entry.descriptor.conditions.protocol === endpoint.protocol &&
              entry.descriptor.conditions.localPort === localPort,
          );
          return {
            ...native,
            identity: clientLocal ? payload : policyIdentity(102, ACCOUNT),
            leg,
            direction,
            action: "PERMIT",
            localPrincipalSid: ACCOUNT,
            socketIdentityVerified: true,
            authorization: flowReturn ? "verified-flow" : "ale",
            flowAuthorizationVerified: true,
            flowIdentitySha256: HASH,
            restrictedSids: [input.request.restrictingSid],
            socketIdentitySha256: digest(
              endpoint.family +
                endpoint.protocol +
                (clientLocal ? "client" : "server"),
            ),
            filterId: filter.id,
            layer,
            ...filter.descriptor.conditions,
          };
        }),
      ),
    })),
  };
  const owned = installation.effective.objects.find(
    (entry) => entry.descriptor.name === "owned",
  );
  observation.read.fileIdentitySha256 = digest(
    owned.volumeSerial + ":" + owned.fileId,
  );
  observation.edit.before = {
    ...state,
    identitySha256: observation.read.fileIdentitySha256,
    bytesSha256: digest(input.request.nonce),
  };
  observation.edit.after = {
    ...observation.edit.before,
    bytesSha256: digest(
      input.profile === "read-only"
        ? input.request.nonce
        : observation.edit.bytes,
    ),
  };
  for (const entry of observation.denials) {
    const name = entry.caseId.startsWith("parent-")
      ? "workspace"
      : entry.caseId.split("-")[0];
    const target = installation.effective.objects.find(
      (object) => object.descriptor.name === name,
    );
    if (target) {
      const identitySha256 =
        name === "registry"
          ? target.registryIdentitySha256
          : digest(target.volumeSerial + ":" + target.fileId);
      entry.target = target.descriptor.path;
      entry.nativeCode = 5;
      entry.before = { ...state, identitySha256 };
      entry.after = { ...entry.before };
      entry.control.targetIdentitySha256 = identitySha256;
    }
  }
  for (const entry of observation.denials.filter((item) =>
    item.caseId.startsWith("foreign-sender-"),
  )) {
    const family = entry.caseId.includes("-v4-") ? "V4" : "V6";
    const guard = installation.effective.wfp.filters.find(
      (item) =>
        item.descriptor.purpose === "reserved-endpoint" &&
        item.descriptor.layer === "ALE_AUTH_CONNECT_" + family &&
        item.descriptor.conditions.protocol === entry.protocol &&
        item.descriptor.conditions.remotePort ===
          input.endpoints.find(
            (endpoint) =>
              endpoint.family.toUpperCase() === family &&
              endpoint.protocol === entry.protocol,
          ).serverPort,
    );
    Object.assign(entry, {
      identity: policyIdentity(201),
      protectedIdentity: payload,
      filterIdentity: policyIdentity(201),
      localPrincipalSid: "S-1-5-18",
      filterId: guard.id,
      layer: guard.descriptor.layer,
      nativeCode: entry.protocol === "tcp" ? 10035 : 0,
      ...guard.descriptor.conditions,
    });
    Object.assign(entry.control, {
      identity: policyIdentity(202, ACCOUNT),
      privatePeer: true,
      tokenReviewed: true,
    });
  }
  for (const [index, entry] of observation.denials.entries()) {
    if (!entry.caseId.endsWith("-tcp") && !entry.caseId.endsWith("-udp"))
      continue;
    const family = entry.caseId.includes("-v4-") ? "v4" : "v6",
      loop = family === "v4" ? "127.0.0.1" : "::1",
      hostNetwork = entry.caseId.startsWith("host-network-"),
      foreignSender = entry.caseId.startsWith("foreign-sender-");
    if (entry.caseId.startsWith("cross-allocation-")) {
      entry.control.identity = policyIdentity(200, "S-1-5-21-1-2-3-1003");
      entry.control.tokenReviewed = true;
      entry.control.accountReservationVerified = true;
    }
    if (!foreignSender) entry.nativeCode = 10013;
    const remoteAddress = hostNetwork
        ? family === "v4"
          ? "198.51.100.10"
          : "2001:db8::10"
        : loop,
      remotePort = foreignSender ? entry.remotePort : 50000 + index;
    entry.attempt = {
      ...native,
      identity: entry.identity,
      socketIdentitySha256: digest(entry.caseId + "sender"),
      protocol: entry.protocol,
      localAddress: hostNetwork
        ? family === "v4"
          ? "198.51.100.11"
          : "2001:db8::11"
        : loop,
      localPort: 52000 + index,
      remoteAddress,
      remotePort,
    };
    entry.control.endpoint = {
      protocol: entry.protocol,
      identity: foreignSender ? payload : entry.control.identity,
      identityVerified: true,
      socketIdentitySha256: digest(entry.caseId + "receiver"),
      address: remoteAddress,
      port: remotePort,
      bindAddress: entry.caseId.startsWith("wildcard-listener-")
        ? family === "v4"
          ? "0.0.0.0"
          : "::"
        : remoteAddress,
    };
    Object.assign(entry, {
      localAddress: entry.attempt.localAddress,
      localPort: entry.attempt.localPort,
      remoteAddress,
      remotePort,
      socketIdentitySha256: entry.attempt.socketIdentitySha256,
    });
  }
  return { observation, payload };
}
test("Windows access joins every ready denial and all four request/return loopback paths", () => {
  for (const profile of ["read-only", "workspace-write", "trusted-command"]) {
    const { input, installation } = fixture(profile),
      { observation, payload } = accessObservation(input, installation);
    assert.equal(
      assertWindowsAccessObservation(
        observation,
        input,
        installation,
        payload,
        HASH,
      ),
      observation,
    );
    observation.denials.find((entry) => entry.caseId === "wmi").nativeCode =
      0x80070005;
    const host = observation.denials.find(
      (entry) => entry.caseId === "host-listener-v4-tcp",
    );
    const guard = installation.effective.wfp.filters.find(
      (entry) =>
        entry.descriptor.purpose === "reserved-endpoint" &&
        entry.descriptor.layer === "ALE_AUTH_RECV_ACCEPT_V4" &&
        entry.descriptor.conditions.protocol === "tcp" &&
        entry.descriptor.conditions.localPort,
    );
    Object.assign(host, {
      filterId: guard.id,
      layer: guard.descriptor.layer,
      localPrincipalSid: host.control.identity.userSid,
      filterIdentity: host.control.identity,
      nativeCode: 10035,
      ...guard.descriptor.conditions,
    });
    host.attempt.remotePort = host.localPort;
    host.control.endpoint.port = host.localPort;
    host.localAddress = host.attempt.remoteAddress;
    host.remoteAddress = host.attempt.localAddress;
    host.remotePort = host.attempt.localPort;
    host.socketIdentitySha256 = host.control.endpoint.socketIdentitySha256;
    assert.equal(
      assertWindowsAccessObservation(
        observation,
        input,
        installation,
        payload,
        HASH,
      ),
      observation,
    );
    for (const mutate of [
      (value) => {
        value.denials.pop();
      },
      (value) => {
        value.denials[0].control.readyBeforeAttempt = false;
      },
      (value) => {
        value.denials[1].after = {
          ...value.denials[1].after,
          bytesSha256: "d".repeat(64),
        };
      },
      (value) => {
        value.denials[0].target = input.request.workspace + "\\owned.txt";
      },
      (value) => {
        value.denials[0].nativeCode = 0x80070005;
      },
      (value) => {
        value.denials.find((entry) => entry.caseId === "alpc").nativeCode =
          0x80041003;
      },
      (value) => {
        value.denials.find((entry) => entry.caseId === "com").nativeCode = 5;
      },
      (value) => {
        value.denials.find((entry) => entry.caseId === "wmi").nativeCode = 5;
      },
      (value) => {
        value.read.fileIdentitySha256 = HASH;
      },
      (value) => {
        value.members[1].jobObjectSha256 = "d".repeat(64);
      },
      (value) => {
        value.members[1].token.restrictedSids = ["S-1-5-21-4-5-6-1003"];
      },
      (value) => {
        value.read.identity = policyIdentity(301, ACCOUNT);
      },
      (value) => {
        value.denials.at(-1).wfpAction = "UNKNOWN";
      },
      (value) => {
        value.denials.find(
          (entry) => entry.caseId === "host-listener-v6-tcp",
        ).filterIdentity = policyIdentity(301, ACCOUNT);
      },
      (value) => {
        value.denials.find((entry) => entry.caseId === "host-listener-v4-tcp")
          .attempt.remotePort++;
      },
      (value) => {
        value.denials.find(
          (entry) => entry.caseId === "host-listener-v4-tcp",
        ).socketIdentitySha256 = HASH;
      },
      (value) => {
        value.denials.find(
          (entry) => entry.caseId === "wildcard-listener-v4-tcp",
        ).control.endpoint.bindAddress = "127.0.0.1";
      },
      (value) => {
        value.denials.find(
          (entry) => entry.caseId === "host-network-v4-tcp",
        ).control.endpoint.address = "127.0.0.1";
      },
      (value) => {
        value.denials.find(
          (entry) => entry.caseId === "foreign-sender-v4-udp",
        ).nativeCode = 10035;
      },
      (value) => {
        value.loopback[0].events[3].localPrincipalSid = "S-1-5-18";
      },
      (value) => {
        value.loopback[1].events.pop();
      },
      (value) => {
        value.loopback[0].server.socketIdentitySha256 =
          value.loopback[0].client.socketIdentitySha256;
        for (const event of value.loopback[0].events)
          event.socketIdentitySha256 =
            value.loopback[0].client.socketIdentitySha256;
      },
      (value) => {
        value.loopback[0].events[0].identity = policyIdentity(301, ACCOUNT);
      },
      (value) => {
        value.timedOut = true;
      },
    ]) {
      const changed = structuredClone(observation);
      mutate(changed);
      assert.throws(() =>
        assertWindowsAccessObservation(
          changed,
          input,
          installation,
          payload,
          HASH,
        ),
      );
    }
    const split = structuredClone(observation);
    split.edit.identity = split.members[1].identity;
    assert.equal(
      assertWindowsAccessObservation(split, input, installation, payload, HASH),
      split,
    );
  }
});

test("Windows access binds owner/helper loss to held identities and retains policy through retirement", async () => {
  const { input, installation } = fixture(),
    { observation, payload } = accessObservation(input, installation),
    phases = [];
  const admission = {
    status: "ADMITTED",
    candidateSha: input.request.candidateSha,
    nonce: input.request.nonce,
    request: input.request,
    arguments: [
      input.request.nonce,
      "read",
      input.request.workspace + "\\owned.txt",
    ],
    accountSid: ACCOUNT,
    policyReceiptSha256: installation.receiptSha256,
    helpers: [
      { role: "launcher", identity: policyIdentity(103), settled: false },
    ],
    payload,
    setup: { job: { heldObjectSha256: HASH } },
  };
  admission.requestSha256 = windowsLaunchDigest(
    admission.request,
    admission.arguments,
  );
  const owner = policyIdentity(100),
    native = {
      independent: true,
      nonce: input.request.nonce,
      nativeEventSha256: HASH,
      timedOut: false,
      lossCount: 0,
      identityVerified: true,
      verifier: policyIdentity(104),
    };
  const effects = {
    persist: async (record) => phases.push(record.phase),
    prepare: async () => ({
      independent: true,
      completeCompositionReviewed: true,
      profile: input.profile,
      reviewSha256: HASH,
      disposable: true,
      controlsReady: true,
      barriersAcknowledged: true,
      nativeEventSha256: HASH,
      installation,
      owner,
      ownerIdentityVerified: true,
    }),
    admit: async () => admission,
    observe: async () => observation,
    armFault: async (fault) => ({
      ...native,
      fault,
      requestSha256: admission.requestSha256,
      identity: fault === "owner-loss" ? owner : admission.helpers[0].identity,
      signaled: false,
      heldIdentityVerified: true,
      acknowledged: true,
    }),
    fireFault: async (fault, _, armed) => ({
      ...native,
      fault,
      requestSha256: admission.requestSha256,
      identity: armed.identity,
      faultSha256: armed.nativeEventSha256,
      heldIdentityVerified: true,
      signaled: true,
    }),
    snapshot: async () => installation.effective,
    retire: async () => ({
      schemaVersion: 1,
      independent: true,
      status: "RETIRED",
      candidateSha: input.request.candidateSha,
      nonce: input.request.nonce,
      requestSha256: admission.requestSha256,
      accountSid: ACCOUNT,
      jobObjectSha256: HASH,
      noLiveMembers: true,
      helpersSettled: true,
      reservation: "RETAINED",
      nativeEventSha256: HASH,
      freshVerifier: policyIdentity(105),
      members: observation.members.map((entry) => entry.identity),
      helpers: structuredClone(admission.helpers),
    }),
  };
  for (const fault of ["owner-loss", "helper-loss"]) {
    const result = await runWindowsAccessCase(input, effects, {
      ...options,
      fault,
    });
    assert.equal(result.status, "OBSERVED");
    assert.equal(result.reservation, "RETAINED");
  }
  assert.ok(
    phases.indexOf("fault-intent") < phases.indexOf("retirement-intent"),
  );
  const fire = effects.fireFault;
  effects.fireFault = async (...args) => ({
    ...(await fire(...args)),
    identity: policyIdentity(301),
  });
  assert.equal(
    (
      await runWindowsAccessCase(input, effects, {
        ...options,
        fault: "owner-loss",
      })
    ).status,
    "FAILED",
  );
  effects.fireFault = fire;
  const arm = effects.armFault;
  effects.armFault = async (...args) => ({
    ...(await arm(...args)),
    identity: policyIdentity(301),
  });
  assert.equal(
    (
      await runWindowsAccessCase(input, effects, {
        ...options,
        fault: "helper-loss",
      })
    ).status,
    "FAILED",
  );
  effects.armFault = arm;
  effects.admit = async () => ({
    ...admission,
    policyReceiptSha256: "d".repeat(64),
  });
  assert.equal(
    (await runWindowsAccessCase(input, effects, options)).status,
    "FAILED",
  );
  effects.admit = async () => admission;
  const retire = effects.retire;
  effects.retire = async () => ({ ...(await retire()), helpers: [] });
  assert.equal(
    (await runWindowsAccessCase(input, effects, options)).status,
    "FAILED",
  );
  effects.retire = async () => ({ ...(await retire()), members: [payload] });
  assert.equal(
    (await runWindowsAccessCase(input, effects, options)).status,
    "FAILED",
  );
  effects.retire = retire;
  for (const changedSnapshot of [1, 2]) {
    for (const mutate of [
      (value) => {
        value.objects[0].fileId = "d".repeat(32);
      },
      (value) => {
        value.objects[0].daclSha256 = "d".repeat(64);
      },
      (value) => {
        value.objects.find(
          (entry) => entry.descriptor.name === "registry",
        ).registryIdentitySha256 = "d".repeat(64);
      },
      (value) => {
        value.endpoints[0].client.reservationIdentitySha256 = "d".repeat(64);
      },
    ]) {
      let snapshots = 0;
      effects.snapshot = async () => {
        const value = structuredClone(installation.effective);
        if (++snapshots === changedSnapshot) mutate(value);
        return value;
      };
      assert.equal(
        (
          await runWindowsAccessCase(input, effects, {
            ...options,
            fault: "owner-loss",
          })
        ).status,
        "FAILED",
      );
    }
  }
});
