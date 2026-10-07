import {
  observationDigest,
  observationObject,
  requireObservation,
} from "../index.js";
import { buildWindowsPolicy, assertWindowsPolicyToken } from "./policy.js";
import {
  dense,
  digest,
  hash,
  sameWindowsIdentity,
  systemIdentity,
} from "./protocol.js";
import { decode, jobObservation } from "./custody-protocol.js";
import {
  assertWindowsWfpFilterRead,
  assertWindowsWfpOwnersRead,
  normalizeWindowsWfpGlobalRead,
} from "./wfp-reader.js";
import {
  normalizeWindowsSecurityRead,
  systemOnly,
} from "./effective-protocol.js";
import { createWindowsAuditDecoder } from "./audit-decoder.js";

const flags = [
  "inheritedAccessVerified",
  "hostObjectAccessReviewed",
  "noForeignHandles",
  "noDelegation",
  "noUnreviewedLoaderExceptions",
  "accountReservationVerified",
  "ancestorTraversalVerified",
  "disposableStorageVerified",
  "baselineInventoryVerified",
  "inheritedOwnerRightsProtected",
  "creationDaclProtectionVerified",
  "registryParentProtected",
];
const network = [
  "localSocketPrincipal",
  "restrictedTokenMatchVerified",
  "unknownIdentityDenied",
  "loopbackAleVerified",
  "udpReturnAleVerified",
  "globalPrecedenceVerified",
  "noConflictingHardPermit",
  "noLoopbackExemption",
  "noUnfilteredRoute",
  "noForeignCallout",
];
const same = (a, b) => observationDigest(a) === observationDigest(b);

export function validateWindowsAccessApproval(approval, input, binding) {
  observationObject(approval, [
    "schemaVersion",
    "candidateSha",
    "contextSha256",
    "sourceReviewSha256",
    "profile",
    "disposable",
    "sourceFacts",
    "wfpFacts",
    "foreignGraphSha256",
    "audit",
  ]);
  observationObject(approval.sourceFacts, flags);
  observationObject(approval.wfpFacts, network);
  observationObject(approval.audit, ["pins", "mapping"]);
  observationObject(approval.audit.pins, [
    "manifestSha256",
    "imageSha256",
    "sourceSha256",
    "abiSha256",
  ]);
  requireObservation(
    approval.schemaVersion === 1 &&
      approval.candidateSha === input.request.candidateSha &&
      approval.contextSha256 === observationDigest(binding.context) &&
      approval.sourceReviewSha256 === binding.template.sourceReviewSha256 &&
      approval.profile === input.profile &&
      approval.disposable === input.disposable &&
      hash(approval.foreignGraphSha256) &&
      Object.values(approval.audit.pins).every(hash) &&
      flags.every(
        (key) =>
          approval.sourceFacts[key] ===
          (key === "disposableStorageVerified" ? input.disposable : true),
      ) &&
      network.every((key) => approval.wfpFacts[key] === true),
  );
  requireObservation(
    createWindowsAuditDecoder({}, approval.audit.mapping).binding()
      .abiSha256 === approval.audit.pins.abiSha256,
  );
  return structuredClone(approval);
}

/** Approved source conclusions and fresh kernel observations are separate
 * inputs. Neither a fixture error nor an observed digest creates an approval. */
export function createWindowsAccessReaders(current) {
  const { reader, binding, provisioned, admission } = current,
    plan = buildWindowsPolicy(current.input),
    approval = validateWindowsAccessApproval(
      provisioned.access,
      plan.value,
      binding,
    );
  let original, installed;
  const foreignGraph = async () => {
    const keys = [...dense(await reader.wfpInventory(), 2048)].sort(),
      graph = [];
    requireObservation(new Set(keys).size === keys.length);
    for (const key of keys)
      if (!plan.manifest.filters.some((filter) => filter.key === key))
        graph.push(
          normalizeWindowsWfpGlobalRead(await reader.wfpGlobal(key), key),
        );
    requireObservation(
      observationDigest(graph) === approval.foreignGraphSha256,
    );
  };
  const read = async () => {
    const proof = await reader.readAccessCoverage(),
      raw = proof.actual;
    observationObject(raw, [
      "accountSid",
      "restrictingSid",
      "contextSha256",
      "bfeRunning",
      "token",
      "creator",
      "job",
      "members",
      "creationSealed",
      "observerAbsent",
      "objects",
      "flows",
      "endpoints",
      "registryPresent",
      "registry",
      "reservations",
      "ownedWfp",
      "fileRoots",
    ]);
    dense(raw.fileRoots, 2).forEach((root, i) => {
      observationObject(root, ["index", "identity", "accessMask"]);
      requireObservation(
        root.index === i + 1 &&
          root.identity ===
            provisioned.actual.objects.find(({ index }) => index === root.index)
              ?.object.identity &&
          root.accessMask === 0x1000a0,
      );
    });
    requireObservation(
      sameWindowsIdentity(systemIdentity(raw.creator), admission.helper),
    );
    assertWindowsPolicyToken(raw.token, plan.value);
    requireObservation(Boolean(raw.registry) === raw.registryPresent);
    if (raw.registry) {
      observationObject(raw.registry, [
        "nameHex",
        "children",
        "values",
        "written",
        "security",
      ]);
      requireObservation(
        decode(raw.registry.nameHex) ===
          "\\REGISTRY\\MACHINE\\SOFTWARE\\NativeProof\\" +
            plan.value.request.nonce &&
          raw.registry.children === 0 &&
          raw.registry.values === 0 &&
          /^[a-f0-9]{16}$/u.test(raw.registry.written),
      );
      systemOnly(raw.registry.security);
    }
    observationObject(raw.ownedWfp, [
      "provider",
      "sublayer",
      "filters",
      "observations",
    ]);
    observationObject(raw.ownedWfp.observations, [
      "provider",
      "sublayer",
      "filters",
    ]);
    requireObservation(
      typeof raw.registryPresent === "boolean" &&
        typeof raw.ownedWfp.provider === "boolean" &&
        typeof raw.ownedWfp.sublayer === "boolean" &&
        dense(raw.ownedWfp.filters, 52).length === 52 &&
        raw.ownedWfp.filters.every((value) => typeof value === "boolean"),
    );
    requireObservation(
      dense(raw.ownedWfp.observations.filters, 52).length === 52,
    );
    requireObservation(
      Boolean(raw.ownedWfp.observations.provider) === raw.ownedWfp.provider &&
        Boolean(raw.ownedWfp.observations.sublayer) === raw.ownedWfp.sublayer &&
        raw.ownedWfp.provider === raw.ownedWfp.sublayer,
    );
    if (raw.ownedWfp.provider)
      assertWindowsWfpOwnersRead(
        raw.ownedWfp.observations.provider,
        raw.ownedWfp.observations.sublayer,
        plan,
      );
    raw.ownedWfp.observations.filters.forEach((actual, i) => {
      requireObservation(Boolean(actual) === raw.ownedWfp.filters[i]);
      if (actual)
        assertWindowsWfpFilterRead(actual, plan.manifest.filters[i], plan);
    });
    requireObservation(
      proof.independent &&
        sameWindowsIdentity(
          systemIdentity(proof.verifier),
          admission.verifier,
        ) &&
        raw.contextSha256 === observationDigest(binding.context) &&
        raw.accountSid === plan.value.accountSid &&
        raw.restrictingSid === plan.value.request.restrictingSid &&
        raw.bfeRunning === true &&
        typeof raw.creationSealed === "boolean" &&
        typeof raw.observerAbsent === "boolean" &&
        dense(raw.objects, 44).length === provisioned.accessSlots.length,
    );
    raw.objects.forEach((object, i) => {
      observationObject(object, [
        "index",
        "identity",
        "foreignWritableHandles",
        "parents",
        "security",
      ]);
      normalizeWindowsSecurityRead(object.security);
      requireObservation(
        object.index === provisioned.accessSlots[i] &&
          object.foreignWritableHandles === 0 &&
          object.identity ===
            provisioned.actual.objects.find(
              ({ index }) => index === object.index,
            )?.object.identity &&
          dense(object.parents, 32).length > 0 &&
          object.parents.every((id) => /^[a-f0-9]{16}:[a-f0-9]{32}$/u.test(id)),
      );
    });
    dense(raw.members, 32).forEach((member) => {
      observationObject(member, ["identity", "signaled", "inJob", "token"]);
      assertWindowsPolicyToken(member.token, plan.value);
      requireObservation(
        member.identity.userSid === plan.value.accountSid &&
          member.identity.sessionId === 0 &&
          typeof member.signaled === "boolean" &&
          typeof member.inJob === "boolean" &&
          (member.signaled || (raw.job !== null && member.inJob)),
      );
    });
    if (raw.job !== null) {
      const job = jobObservation(raw.job);
      requireObservation(
        job.limitFlags === 0x2008 &&
          job.processLimit === 32 &&
          job.uiRestrictions === 255 &&
          job.members.every((identity) =>
            raw.members.some((member) =>
              sameWindowsIdentity(identity, member.identity),
            ),
          ),
      );
    }
    dense(raw.flows, 65536).forEach((flow) => {
      observationObject(flow, [
        "family",
        "protocol",
        "pid",
        "state",
        "localPort",
        "remotePort",
      ]);
      requireObservation(
        ["v4", "v6"].includes(flow.family) &&
          ["tcp", "udp"].includes(flow.protocol) &&
          (raw.members.some(({ identity }) => identity.pid === flow.pid) ||
            (flow.protocol === "tcp" && flow.pid === raw.creator.pid)) &&
          [flow.state, flow.localPort, flow.remotePort].every(
            Number.isSafeInteger,
          ) &&
          flow.state >= 0 &&
          flow.localPort >= 0 &&
          flow.localPort <= 65535 &&
          flow.remotePort >= 0 &&
          flow.remotePort <= 65535,
      );
    });
    requireObservation(
      same(raw.endpoints, provisioned.native.endpoints) &&
        dense(raw.reservations, 8).length === 8,
    );
    for (const reservation of raw.reservations) {
      observationObject(reservation, ["identitySha256", "payloadVerified"]);
      requireObservation(
        hash(reservation.identitySha256) &&
          typeof reservation.payloadVerified === "boolean",
      );
    }
    return proof;
  };
  return {
    read,
    rememberInstalled(actual) {
      requireObservation(
        !installed &&
          actual.registryPresent &&
          actual.ownedWfp.filters.every(Boolean),
      );
      installed = structuredClone({
        objects: actual.objects,
        registry: actual.registry,
        wfp: actual.ownedWfp,
      });
    },
    async unchangedInstalled() {
      const actual = (await read()).actual;
      requireObservation(
        installed &&
          same(
            {
              objects: actual.objects,
              registry: actual.registry,
              wfp: actual.ownedWfp,
            },
            installed,
          ),
      );
      await foreignGraph();
    },
    async control(value) {
      const actual = await reader.accessControl("outside-write");
      requireObservation(
        same(value.context, binding.context) &&
          value.nonce === plan.value.request.nonce &&
          sameWindowsIdentity(value.subject, actual.identity) &&
          actual.ready &&
          actual.reachable &&
          actual.targetIdentitySha256 === digest(value.target.identity) &&
          value.target.sha256 === digest(plan.value.request.nonce),
      );
      return {
        independent: true,
        reached: true,
        discretionaryAllowed: true,
        nonce: value.nonce,
        subject: actual.identity,
        targetIdentity: value.target.identity,
        targetSha256: value.target.sha256,
        verifier: actual.verifier,
        nativeEventSha256: actual.nativeEventSha256,
      };
    },
    async baseline() {
      const proof = await read(),
        raw = proof.actual,
        inventory = await reader.wfpInventory();
      requireObservation(
        !original &&
          !raw.registryPresent &&
          !raw.ownedWfp.provider &&
          !raw.ownedWfp.sublayer &&
          raw.ownedWfp.filters.every((value) => !value) &&
          raw.members.length === 0 &&
          raw.job?.members.length === 0 &&
          !inventory.some((key) =>
            [
              plan.manifest.providerKey,
              plan.manifest.sublayerKey,
              ...plan.manifest.filters.map(({ key }) => key),
            ].includes(key),
          ),
      );
      original = structuredClone(raw.objects);
      await foreignGraph();
      return {
        independent: true,
        verifier: proof.verifier,
        candidateSha: binding.context.candidateSha,
        nonce: plan.value.request.nonce,
        compositionSha256: plan.compositionSha256,
        admissionsClosed: true,
        exclusiveWriter: true,
        noExistingOwnedPolicy: true,
        accountReservationVerified: true,
        registryAbsent: true,
        baselineInventoryVerified: true,
        nativeEventSha256: proof.nativeEventSha256,
        objects: raw.objects.map((object, index) => {
          const security = normalizeWindowsSecurityRead(object.security);
          systemOnly(security);
          const descriptor = plan.manifest.objects.filter(
            ({ name }) => name !== "registry",
          )[index];
          return {
            path: descriptor.path,
            ownerSid: security.ownerSid,
            protectedDacl: true,
            systemOnlyDacl: true,
            exclusiveParents: true,
            noReparse: true,
            links: 1,
            identityVerified: true,
            foreignWritableHandles: 0,
            nativeEventSha256: observationDigest(object),
            daclSha256: security.daclSha256,
            volumeSerial: object.identity.slice(0, 16),
            fileId: object.identity.slice(17),
            ...(descriptor.sha256 ? { sha256: descriptor.sha256 } : {}),
          };
        }),
      };
    },
    async restored() {
      const proof = await read(),
        raw = proof.actual;
      requireObservation(
        original &&
          !raw.registryPresent &&
          !raw.ownedWfp.provider &&
          !raw.ownedWfp.sublayer &&
          raw.ownedWfp.filters.every((value) => !value) &&
          raw.creationSealed &&
          raw.members.every(({ signaled }) => signaled) &&
          raw.flows.length === 0 &&
          raw.objects.every((object, index) => same(object, original[index])),
      );
      await foreignGraph();
      return {
        status: "RESTORED",
        independent: true,
        unchangedInstalled: true,
        verifier: proof.verifier,
        nativeEventSha256: proof.nativeEventSha256,
      };
    },
    async coverage({ context, plan: manifest, observations }) {
      requireObservation(
        same(context, binding.context) && same(manifest, plan.manifest),
      );
      const proof = await read(),
        raw = proof.actual;
      const foreign = observations.globalGraph.filter(
        ({ key }) => !manifest.filters.some((filter) => filter.key === key),
      );
      requireObservation(
        observationDigest(foreign) === approval.foreignGraphSha256 &&
          observations.actual.length === manifest.objects.length,
      );
      // All source-dependent guarantees come from the separately pinned review.
      // Held identities, write handles, Job members and socket reservations are
      // independently read above; the effective owner rereads every policy item.
      return {
        independent: true,
        verifier: proof.verifier,
        candidateSha: context.candidateSha,
        nonce: manifest.nonce,
        compositionSha256: plan.compositionSha256,
        observationsSha256: observationDigest(observations),
        nativeEventSha256: proof.nativeEventSha256,
        reservationSha256: observationDigest({
          context,
          provisioning: provisioned.provisioning,
          endpoints: raw.endpoints,
        }),
        exclusiveWriter: true,
        admissionsClosed: true,
        flags: structuredClone(approval.sourceFacts),
        wfp: {
          ...approval.wfpFacts,
          bfeRunning: raw.bfeRunning,
          dynamicSession: false,
          transactionCommitted:
            observations.nativeFilters.length === manifest.filters.length ||
            observations.nativeFilters.length === 0,
          noPreexistingFlows: provisioned.native.job.members.length === 0,
          globalConfigurationSha256: observationDigest(
            observations.globalGraph,
          ),
        },
        endpoints: plan.value.endpoints.map((endpoint, index) => {
          const reservation = (side) => ({
            userSid: plan.value.accountSid,
            restrictedSids: [plan.value.request.restrictingSid],
            heldReservationVerified: true,
            reservationIdentitySha256:
              raw.reservations[index * 2 + (side === "server" ? 1 : 0)]
                .identitySha256,
          });
          return {
            endpoint,
            reserved: true,
            exclusive: true,
            noWildcard: true,
            noPortReuse: true,
            ipv6Only: endpoint.family === "v6",
            nativeEventSha256: proof.nativeEventSha256,
            systemCustodied: true,
            transferOnlyToVerifiedPrincipal: true,
            client: reservation("client"),
            server: reservation("server"),
          };
        }),
        objects: observations.actual.map((actual) => ({
          nativeEventSha256: observationDigest(actual),
          exclusiveParents: true,
          foreignWritableHandles: 0,
        })),
      };
    },
    async retirement(observations) {
      requireObservation(same(observations.context, binding.context));
      const proof = await read(),
        raw = proof.actual;
      requireObservation(
        (raw.job === null || raw.job.members.length === 0) &&
          raw.creationSealed &&
          raw.members.every(({ signaled }) => signaled) &&
          raw.flows.length === 0,
      );
      return {
        status: "RETIRED",
        independent: true,
        emergencyCleanup: false,
        candidateSha: binding.context.candidateSha,
        nonce: plan.value.request.nonce,
        noLiveMembers: true,
        noForeignCreators: true,
        noPrincipalFlows: true,
        observationsSha256: observationDigest(observations),
        verifier: proof.verifier,
        nativeEventSha256: proof.nativeEventSha256,
      };
    },
  };
}
