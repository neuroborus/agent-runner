import { buildWindowsPolicy } from "./policy.js";
import { windowsEffectiveRights } from "./policy-effects.js";

const HASH = "a".repeat(64);
export const policyIdentity = (pid, userSid = "S-1-5-18") => ({
  pid,
  creationTime: String(10000 + pid),
  sessionId: 0,
  userSid,
});

/** Shared synthetic native-reader fixture for launch admission and policy tests.
 * No host effects, SDK attestation or native acceptance are supplied here. */
export function windowsPolicyFixture(
  request,
  accountSid,
  profile = "workspace-write",
  runtimePath = request.executable.path,
) {
  const input = {
    request: structuredClone(request),
    accountSid,
    profile,
    disposable: true,
    runtime: [
      {
        path: runtimePath,
        sha256: request.executable.sha256,
        reviewSha256: HASH,
      },
    ],
    endpoints: ["v4", "v6"].flatMap((family, index) =>
      ["tcp", "udp"].map((protocol, number) => ({
        family,
        protocol,
        clientPort: 41000 + index * 4 + number * 2,
        serverPort: 41001 + index * 4 + number * 2,
      })),
    ),
    reviewSha256: HASH,
  };
  let plan = buildWindowsPolicy(input);
  request.policy.sha256 = input.request.policy.sha256 = plan.policySha256;
  request.bindings.policy = input.request.bindings.policy =
    plan.compositionSha256;
  plan = buildWindowsPolicy(input);
  const token = {
    userSid: accountSid,
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
  };
  const effective = {
    independent: true,
    candidateSha: request.candidateSha,
    nonce: request.nonce,
    compositionSha256: plan.compositionSha256,
    reviewSha256: HASH,
    nativeEventSha256: HASH,
    reservationSha256: HASH,
    exclusiveWriter: true,
    admissionsClosed: true,
    verifier: policyIdentity(102),
    token,
    inheritedAccessVerified: true,
    mandatoryLabelsVerified: true,
    hostObjectAccessReviewed: true,
    noForeignHandles: true,
    noDelegation: true,
    noUnreviewedLoaderExceptions: true,
    accountReservationVerified: true,
    ancestorTraversalVerified: true,
    disposableStorageVerified: true,
    baselineInventoryVerified: true,
    inheritedOwnerRightsProtected: true,
    creationDaclProtectionVerified: true,
    registryParentProtected: true,
    objects: plan.manifest.objects.map((descriptor, index) => ({
      descriptor: structuredClone(descriptor),
      daclSha256: HASH,
      ownerSid: "S-1-5-18",
      protectedDacl: true,
      noReparse: true,
      exclusiveParents: true,
      identityVerified: true,
      accessCheckNative: true,
      nativeEventSha256: HASH,
      unexpectedAces: 0,
      foreignWritableHandles: 0,
      rights: windowsEffectiveRights(descriptor.grant),
      registryIdentitySha256: HASH,
      volumeSerial: "1".padStart(16, "0"),
      fileId: String(index + 1).padStart(32, "0"),
      links: 1,
      sha256: descriptor.sha256,
    })),
    wfp: {
      bfeRunning: true,
      providerKey: plan.manifest.providerKey,
      sublayerKey: plan.manifest.sublayerKey,
      sublayerWeight: 65535,
      ownerSid: "S-1-5-18",
      protectedDacl: true,
      systemOnlyDacl: true,
      persistent: true,
      dynamicSession: false,
      transactionCommitted: true,
      tokenConditionSha256: HASH,
      localSocketPrincipal: true,
      restrictedTokenMatchVerified: true,
      unknownIdentityDenied: true,
      connectAndReceiveBothDirections: true,
      loopbackAleVerified: true,
      udpReturnAleVerified: true,
      globalPrecedenceVerified: true,
      noConflictingHardPermit: true,
      noLoopbackExemption: true,
      noUnfilteredRoute: true,
      noPreexistingFlows: true,
      noForeignCallout: true,
      nativeEventSha256: HASH,
      globalConfigurationSha256: HASH,
      filters: plan.manifest.filters.map((descriptor, index) => ({
        descriptor: structuredClone(descriptor),
        id: String(index + 1),
        nativeEventSha256: HASH,
        providerKey: plan.manifest.providerKey,
        sublayerKey: plan.manifest.sublayerKey,
        userConditionIncludesRestrictingSid: descriptor.principal !== null,
      })),
    },
    endpoints: plan.value.endpoints.map((endpoint) => ({
      endpoint,
      reserved: true,
      exclusive: true,
      noWildcard: true,
      noPortReuse: true,
      ipv6Only: endpoint.family === "v6",
      nativeEventSha256: HASH,
      systemCustodied: true,
      transferOnlyToVerifiedPrincipal: true,
      client: {
        userSid: accountSid,
        restrictedSids: [request.restrictingSid],
        heldReservationVerified: true,
        reservationIdentitySha256: HASH,
      },
      server: {
        userSid: accountSid,
        restrictedSids: [request.restrictingSid],
        heldReservationVerified: true,
        reservationIdentitySha256: HASH,
      },
    })),
  };
  const installation = {
    status: "INSTALLED",
    candidateSha: request.candidateSha,
    nonce: request.nonce,
    compositionSha256: plan.compositionSha256,
    policySha256: plan.policySha256,
    reservation: "RETAINED",
    helpersSettled: true,
    receiptSha256: HASH,
    effective,
  };
  return { input, plan, installation };
}
