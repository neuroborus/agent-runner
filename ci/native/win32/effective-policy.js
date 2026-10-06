import {
  observationDigest,
  normalizeNativePolicyBinding,
  assertNativePolicyParameters,
} from "../index.js";
import {
  closed,
  dense,
  hash,
  requireWindows,
  systemIdentity,
  sameWindowsIdentity,
} from "./protocol.js";
import { decode } from "./custody-protocol.js";
import { normalizeWindowsFileIdentity } from "./files-protocol.js";
import { buildWindowsPolicy, assertWindowsPolicyToken } from "./policy.js";
import {
  assertWindowsPolicySnapshot,
  windowsEffectiveRights,
} from "./policy-effects.js";
import {
  normalizeWindowsSecurityRead,
  normalizeWindowsBarrierRead,
  access,
  expectedAces,
  rights,
  systemOnly,
} from "./effective-protocol.js";
import {
  assertWindowsWfpFilterRead,
  normalizeWindowsWfpGlobalRead,
  windowsGuid as guid,
} from "./wfp-reader.js";
const equal = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const allMask = 0x1f01ff;
const ace = (sid, mask, flags = 0, type = 0) => ({ type, flags, mask, sid });

const coverageFlags = [
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
const wfpFlags = [
  "bfeRunning",
  "dynamicSession",
  "transactionCommitted",
  "localSocketPrincipal",
  "restrictedTokenMatchVerified",
  "unknownIdentityDenied",
  "loopbackAleVerified",
  "udpReturnAleVerified",
  "globalPrecedenceVerified",
  "noConflictingHardPermit",
  "noLoopbackExemption",
  "noUnfilteredRoute",
  "noPreexistingFlows",
  "noForeignCallout",
];

/** Policy reads use retained tokens even after retirement, but that mode is
 * reachable only through the factory's freshly proved retirement barrier. */
export async function readWindowsEffectivePolicy(
  reader,
  context,
  verifier,
  options,
  fresh,
  bound,
  value,
  transfer,
  { installed = true, retired = false } = {},
) {
  const plan = buildWindowsPolicy(value);
  bound(plan.value.request);
  const binding = normalizeNativePolicyBinding(options.binding);
  requireWindows(
    observationDigest(binding.context) === observationDigest(context),
  );
  assertNativePolicyParameters(
    binding,
    options.provisioning,
    plan.value,
    options.arguments ?? [],
  );
  requireWindows(
    plan.value.request.policy.sha256 === plan.policySha256 &&
      plan.value.request.bindings.policy === plan.compositionSha256,
  );
  closed(transfer, ["subject", "objects"]);
  requireWindows(
    dense(transfer.objects, 44).length === plan.manifest.objects.length - 1 &&
      new Set(transfer.objects).size === transfer.objects.length,
  );
  transfer = structuredClone(transfer);
  await fresh();
  const subject = await reader.process(transfer.subject),
    token = await reader.effectiveToken(transfer.subject);
  requireWindows(
    subject.independent === true &&
      subject.retired === retired &&
      subject.identity.pid !== verifier.pid,
  );
  assertWindowsPolicyToken(token, plan.value);
  requireWindows(token.tokenId === subject.tokenId);
  const actual = [],
    objects = [];
  let file = 0;
  for (const descriptor of plan.manifest.objects) {
    let read,
      identity,
      directory = false;
    if (descriptor.name === "registry") {
      read = await reader.registry(transfer.subject);
      closed(read, [
        "nameHex",
        "children",
        "values",
        "written",
        "security",
        "access",
      ]);
      requireWindows(
        decode(read.nameHex).toLowerCase() ===
          "\\registry\\machine\\software\\nativeproof\\" +
            plan.value.request.nonce &&
          read.children === 0 &&
          read.values === 0 &&
          /^[a-f0-9]{16}$/u.test(read.written),
      );
      identity = {
        registryIdentitySha256: observationDigest({
          nameHex: read.nameHex,
          written: read.written,
        }),
      };
      systemOnly(read.security);
    } else {
      const index = transfer.objects[file++];
      read = await reader.acl(transfer.subject, index);
      closed(read, ["object", "security", "access"]);
      const held = await reader.inspect(index);
      requireWindows(
        equal(
          read.object,
          Object.fromEntries(
            Object.entries(held).filter(([key]) => key !== "independent"),
          ),
        ) &&
          decode(held.pathHex).toLowerCase() ===
            descriptor.path.toLowerCase() &&
          held.held === true &&
          held.reparse === false &&
          held.links === 1,
      );
      normalizeWindowsFileIdentity(held.identity);
      directory = held.directory;
      identity = {
        volumeSerial: held.identity.slice(0, 16),
        fileId: held.identity.slice(17),
        links: held.links,
      };
      const sd = normalizeWindowsSecurityRead(read.security);
      requireWindows(
        sd.ownerSid === "S-1-5-18" &&
          sd.protectedDacl &&
          equal(sd.aces, expectedAces(descriptor)),
      );
      const labels = sd.sacl.filter((ace) => ace.type === 17),
        low = ["edit", "workspace", "private-tree"].includes(descriptor.grant);
      requireWindows(equal(labels, low ? [ace("S-1-16-4096", 1, 3, 17)] : []));
      requireWindows(
        sd.sacl.every(
          (item) =>
            item.type === 17 ||
            (item.type === 2 &&
              item.sid === plan.value.accountSid &&
              item.flags === 0xc0 &&
              item.mask === allMask),
        ),
      );
      if (descriptor.sha256) {
        const bytes = normalizeWindowsBarrierRead(
          await reader.file(index),
          false,
        );
        requireWindows(
          bytes.identity === held.identity &&
            bytes.sha256 === descriptor.sha256,
        );
        identity.sha256 = bytes.sha256;
      }
    }
    const sd = normalizeWindowsSecurityRead(read.security),
      effective = rights(
        access(read.access, token),
        directory,
        descriptor.name === "registry",
      );
    requireWindows(equal(effective, windowsEffectiveRights(descriptor.grant)));
    actual.push(read);
    objects.push({
      descriptor,
      ...identity,
      daclSha256: sd.daclSha256,
      ownerSid: sd.ownerSid,
      protectedDacl: sd.protectedDacl,
      noReparse: true,
      identityVerified: true,
      accessCheckNative: true,
      unexpectedAces: 0,
      rights: effective,
      nativeEventSha256: observationDigest(read),
    });
  }
  const provider = await reader.wfp("provider", plan.manifest.providerKey),
    sublayer = await reader.wfp("sublayer", plan.manifest.sublayerKey);
  closed(provider, [
    "key",
    "flags",
    "providerData",
    "serviceNameHex",
    "security",
  ]);
  closed(sublayer, [
    "key",
    "providerKey",
    "weight",
    "flags",
    "providerData",
    "security",
  ]);
  requireWindows(
    provider.key === plan.manifest.providerKey &&
      provider.flags === 1 &&
      provider.providerData === "" &&
      provider.serviceNameHex === null &&
      sublayer.key === plan.manifest.sublayerKey &&
      sublayer.providerKey === provider.key &&
      sublayer.flags === 1 &&
      sublayer.providerData === "" &&
      sublayer.weight === 65535,
  );
  systemOnly(provider.security);
  systemOnly(sublayer.security);
  const inventory = dense(await reader.wfpInventory(), 2048);
  requireWindows(
    inventory.every(guid) && new Set(inventory).size === inventory.length,
  );
  const filters = [],
    nativeFilters = [];
  for (const descriptor of plan.manifest.filters) {
    requireWindows(inventory.includes(descriptor.key) === installed);
    if (!installed) continue;
    const read = await reader.wfp("filter", descriptor.key);
    filters.push(assertWindowsWfpFilterRead(read, descriptor, plan));
    nativeFilters.push(read);
  }
  const observations = {
    subject,
    token,
    actual,
    provider,
    sublayer,
    inventory: [...inventory].sort(),
    nativeFilters,
    globalGraph: [],
  };
  for (const key of observations.inventory)
    observations.globalGraph.push(
      normalizeWindowsWfpGlobalRead(await reader.wfpGlobal(key), key),
    );
  requireWindows(
    new Set(observations.globalGraph.map((item) => item.id)).size ===
      observations.globalGraph.length,
  );
  requireWindows(typeof options.coverage === "function");
  const proof = await options.coverage(
    structuredClone({ context, plan: plan.manifest, observations }),
  );
  closed(proof, [
    "independent",
    "verifier",
    "candidateSha",
    "nonce",
    "compositionSha256",
    "observationsSha256",
    "nativeEventSha256",
    "reservationSha256",
    "exclusiveWriter",
    "admissionsClosed",
    "flags",
    "wfp",
    "endpoints",
    "objects",
  ]);
  requireWindows(
    proof.independent === true &&
      sameWindowsIdentity(systemIdentity(proof.verifier), verifier) &&
      proof.candidateSha === context.candidateSha &&
      proof.nonce === plan.value.request.nonce &&
      proof.compositionSha256 === plan.compositionSha256 &&
      proof.observationsSha256 === observationDigest(observations) &&
      proof.exclusiveWriter === true &&
      proof.admissionsClosed === true &&
      hash(proof.nativeEventSha256) &&
      hash(proof.reservationSha256),
  );
  const flags = [
    ...coverageFlags,
    ...(plan.value.request.execution
      ? [
          "privateTreeChildrenVerified",
          "separateStdioVerified",
          "brokerSystemPrincipalVerified",
        ]
      : []),
  ];
  closed(proof.flags, flags);
  requireWindows(
    flags.every(
      (key) =>
        proof.flags[key] ===
        (key === "disposableStorageVerified" ? plan.value.disposable : true),
    ),
  );
  closed(proof.wfp, [...wfpFlags, "globalConfigurationSha256"]);
  requireWindows(
    proof.wfp.globalConfigurationSha256 ===
      observationDigest(observations.globalGraph) &&
      wfpFlags.every((key) => proof.wfp[key] === (key !== "dynamicSession")),
  );
  requireWindows(dense(proof.objects, 44).length === objects.length);
  objects.forEach((object, index) => {
    const item = proof.objects[index];
    closed(item, [
      "nativeEventSha256",
      "exclusiveParents",
      "foreignWritableHandles",
    ]);
    requireWindows(
      item.nativeEventSha256 === object.nativeEventSha256 &&
        item.exclusiveParents === true &&
        item.foreignWritableHandles === 0,
    );
    Object.assign(object, {
      exclusiveParents: true,
      foreignWritableHandles: 0,
    });
  });
  for (let index = 0; index < transfer.objects.length; index++)
    requireWindows(
      equal(
        await reader.acl(transfer.subject, transfer.objects[index]),
        actual.filter((item) => item.object)[index],
      ),
    );
  requireWindows(
    equal(
      await reader.registry(transfer.subject),
      actual.find((item) => item.nameHex),
    ) &&
      equal(await reader.effectiveToken(transfer.subject), token) &&
      equal(await reader.process(transfer.subject), subject),
  );
  for (const [index, descriptor] of (installed
    ? plan.manifest.filters
    : []
  ).entries())
    requireWindows(
      equal(await reader.wfp("filter", descriptor.key), nativeFilters[index]),
    );
  for (const [index, key] of observations.inventory.entries())
    requireWindows(
      equal(
        normalizeWindowsWfpGlobalRead(await reader.wfpGlobal(key), key),
        observations.globalGraph[index],
      ),
    );
  requireWindows(
    equal([...(await reader.wfpInventory())].sort(), observations.inventory) &&
      equal(await reader.wfp("provider", provider.key), provider) &&
      equal(await reader.wfp("sublayer", sublayer.key), sublayer),
  );
  await fresh();
  const snapshot = {
    ...proof.flags,
    independent: true,
    verifier,
    candidateSha: context.candidateSha,
    nonce: plan.value.request.nonce,
    compositionSha256: plan.compositionSha256,
    reviewSha256: plan.value.reviewSha256,
    nativeEventSha256: observationDigest(observations),
    reservationSha256: proof.reservationSha256,
    exclusiveWriter: true,
    admissionsClosed: true,
    token,
    mandatoryLabelsVerified: true,
    objects,
    endpoints: proof.endpoints,
    wfp: {
      ...proof.wfp,
      providerKey: provider.key,
      sublayerKey: sublayer.key,
      sublayerWeight: sublayer.weight,
      ownerSid: provider.security.ownerSid,
      protectedDacl: true,
      systemOnlyDacl: true,
      persistent: true,
      tokenConditionSha256: plan.value.reviewSha256,
      connectAndReceiveBothDirections: true,
      nativeEventSha256: observationDigest({
        provider,
        sublayer,
        nativeFilters,
      }),
      filters,
    },
  };
  assertWindowsPolicySnapshot(snapshot, value, { installed });
  return snapshot;
}
