import {
  nativePolicyLaunchData,
  nativePolicyTemplateDigest,
  observationDigest,
} from "../index.js";
import { buildWindowsPolicy } from "./policy.js";
import { windowsPolicyFixture, policyIdentity } from "./policy.fixture.js";
import { digest } from "./protocol.js";
import { encode } from "./custody-protocol.js";

export const hash = "a".repeat(64),
  candidateSha = "b".repeat(40),
  nonce = "c".repeat(32),
  account = "S-1-5-21-1-2-3-1001";
export const fileId = (number) =>
  `0000000000000001:${String(number).padStart(32, "0")}`;
const allowed = (sid, mask, flags = 0, type = 0) => ({
  type,
  flags,
  mask,
  sid,
});
export function effectiveFixture() {
  const request = {
    schemaVersion: 3,
    candidateSha,
    nonce,
    restrictingSid: "S-1-5-21-1-2-3-1002",
    custody: "C:\\Fixture\\custody",
    storage: "C:\\Fixture\\storage",
    workspace: "C:\\Fixture\\storage\\workspace",
    launcher: {
      path: "C:\\Fixture\\custody\\launcher.exe",
      sha256: hash,
      signatureSha256: hash,
    },
    executable: {
      path: "C:\\Fixture\\storage\\fixture.exe",
      sha256: digest("fixture executable"),
      signatureSha256: hash,
      parser: "msvc-ucrt-wmain-v1",
    },
    policy: { path: "C:\\Fixture\\custody\\policy.json", sha256: hash },
    bindings: { system: hash, source: hash, closure: hash, policy: hash },
  };
  const legacy = windowsPolicyFixture(request, account),
    input = legacy.input,
    plan = buildWindowsPolicy(input),
    verifier = policyIdentity(900),
    subject = policyIdentity(901, account);
  const context = {
    candidateSha,
    platform: "win32",
    tier: "system",
    runId: "1",
    runAttempt: 1,
    jobBindingSha256: hash,
    executionId: "fixture",
    closureSha256: hash,
    selectedSystemSha256: null,
  };
  const { request: _, ...parameters } = input;
  const template = {
    schemaVersion: 1,
    candidateSha,
    platform: "win32",
    sourceReviewSha256: hash,
    provisioningReviewSha256: hash,
    policy: {
      launch: nativePolicyLaunchData(request, []),
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
  const binding = {
    template,
    approval: {
      candidateSha,
      platform: "win32",
      authority: "operator-protected",
      manifestSha256: nativePolicyTemplateDigest(template),
    },
    context,
  };
  const provisioning = {
    schemaVersion: 1,
    context,
    authoritySha256: hash,
    bindings: [{ id: "account", kind: "sid", value: account }],
    held: true,
    independent: true,
    verifierSha256: hash,
    nativeEventSha256: hash,
  };
  const objects = plan.manifest.objects
    .filter((item) => item.name !== "registry")
    .map((descriptor, index) => {
      const directory = [
        "custody",
        "storage",
        "workspace",
        "metadata",
        "checkout",
        "configuration",
        "credentials",
      ].includes(descriptor.name);
      const object = {
        identity: fileId(index + 1),
        pathHex: encode(descriptor.path),
        volumeHex: encode(
          "\\\\?\\Volume{00000000-0000-0000-0000-000000000001}\\",
        ),
        filesystemHex: encode("NTFS"),
        daclSha256: hash,
        links: 1,
        directory,
        held: true,
        reparse: false,
      };
      const masks = {
          custody: 0,
          storage: 0x120020,
          workspace: 0x1200af,
          owned: 0x13019f,
          pointer: 0x120089,
          metadata: 0,
          checkout: 0,
          configuration: 0,
          credentials: 0,
          outside: 0,
          "runtime-0": 0x1200a9,
        },
        mask = masks[descriptor.name];
      const aces = [
        allowed("S-1-5-18", 0x1f01ff),
        ...(mask
          ? [allowed(account, mask), allowed(request.restrictingSid, mask)]
          : []),
      ];
      if (descriptor.name === "workspace")
        aces.push(
          allowed("S-1-3-4", 0xc0000, 11, 1),
          allowed("S-1-5-18", 0x1f01ff, 11),
          allowed(account, 0x13019f, 9),
          allowed(request.restrictingSid, 0x13019f, 9),
          allowed(account, 0x1301bf, 10),
          allowed(request.restrictingSid, 0x1301bf, 10),
        );
      const low = ["workspace", "owned"].includes(descriptor.name);
      return {
        object,
        security: {
          ownerSid: "S-1-5-18",
          protectedDacl: true,
          daclSha256: hash,
          descriptorSha256: hash,
          aces,
          sacl: low ? [allowed("S-1-16-4096", 1, 3, 17)] : [],
        },
        access: {
          granted: mask,
          micDenied: 0,
          subjectLevel: 4096,
          objectLevel: low ? 4096 : 8192,
          label: 1,
          tokenId: legacy.installation.effective.token.tokenId,
        },
      };
    });
  const security = {
    ownerSid: "S-1-5-18",
    protectedDacl: true,
    daclSha256: hash,
    descriptorSha256: hash,
    aces: [allowed("S-1-5-18", 0x10000000)],
    sacl: [],
  };
  const filters = plan.manifest.filters.map((descriptor, index) => ({
    key: descriptor.key,
    providerKey: plan.manifest.providerKey,
    sublayerKey: plan.manifest.sublayerKey,
    id: String(index + 1),
    layer: descriptor.layer,
    flags: 9,
    weight: descriptor.weight,
    action: descriptor.action,
    security: structuredClone(security),
    conditions: [
      ...(descriptor.principal
        ? [
            {
              field: "principal",
              type: 13,
              value: [allowed(account, 1), allowed(request.restrictingSid, 1)],
            },
          ]
        : []),
      ...Object.entries(descriptor.conditions).map(([field, value]) => ({
        field,
        type:
          field === "protocol"
            ? 1
            : field.endsWith("Port")
              ? 2
              : descriptor.layer.endsWith("V4")
                ? 3
                : 11,
        value:
          field === "protocol"
            ? value === "tcp"
              ? 6
              : 17
            : field.endsWith("Port")
              ? value
              : descriptor.layer.endsWith("V4")
                ? 0x7f000001
                : "0".repeat(31) + "1",
      })),
    ],
  }));
  const registry = {
    nameHex: encode("\\REGISTRY\\MACHINE\\SOFTWARE\\NativeProof\\" + nonce),
    children: 0,
    values: 0,
    written: "0".repeat(15) + "1",
    security,
    access: {
      granted: 0,
      micDenied: 0,
      subjectLevel: 4096,
      objectLevel: 8192,
      label: 1,
      tokenId: legacy.installation.effective.token.tokenId,
    },
  };
  const reader = {
    verifier: async () => structuredClone(verifier),
    process: async (slot) => ({
      identity: slot === 31 ? verifier : subject,
      tokenId: legacy.installation.effective.token.tokenId,
      independent: true,
      retired: false,
    }),
    effectiveToken: async () =>
      structuredClone(legacy.installation.effective.token),
    acl: async (_, slot) => structuredClone(objects[slot]),
    inspect: async (slot) => ({
      ...structuredClone(objects[slot].object),
      independent: true,
    }),
    registry: async () => structuredClone(registry),
    file: async (slot) => ({
      identity: objects[slot].object.identity,
      bytes: 18,
      sha256: request.executable.sha256,
      daclSha256: hash,
    }),
    wfp: async (kind, key) =>
      kind === "provider"
        ? {
            key,
            flags: 1,
            providerData: "",
            serviceNameHex: null,
            security: structuredClone(security),
          }
        : kind === "sublayer"
          ? {
              key,
              providerKey: plan.manifest.providerKey,
              flags: 1,
              providerData: "",
              weight: 65535,
              security: structuredClone(security),
            }
          : structuredClone(filters.find((item) => item.key === key)),
    wfpInventory: async () => filters.map((item) => item.key),
    wfpGlobal: async (key) => {
      const filter = filters.find((item) => item.key === key);
      return {
        key,
        providerKey: filter.providerKey,
        layer: "00000000-0000-0000-0000-000000000001",
        sublayer: filter.sublayerKey,
        sublayerWeight: 65535,
        sublayerFlags: 1,
        sublayerProviderKey: filter.providerKey,
        sublayerSecurity: structuredClone(security),
        id: filter.id,
        flags: filter.flags,
        action: filter.action === "BLOCK" ? 4097 : 4098,
        callout: null,
        context: "0",
        providerData: "",
        weight: { type: 4, value: String(filter.weight) },
        effectiveWeight: { type: 4, value: String(filter.weight) },
        conditions: filter.conditions.map((item, index) => ({
          field:
            "00000000-0000-0000-0000-" + String(index + 1).padStart(12, "0"),
          match: 0,
          value: {
            type: item.type,
            value: item.type === 13 ? "0100" : item.value,
          },
        })),
        security: structuredClone(security),
      };
    },
  };
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
  const wfp = [
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
  const options = {
    binding,
    provisioning,
    arguments: [],
    coverage: async ({ observations }) => ({
      independent: true,
      verifier,
      candidateSha,
      nonce,
      compositionSha256: plan.compositionSha256,
      observationsSha256: observationDigest(observations),
      nativeEventSha256: hash,
      reservationSha256: hash,
      exclusiveWriter: true,
      admissionsClosed: true,
      flags: Object.fromEntries(flags.map((key) => [key, true])),
      wfp: {
        ...Object.fromEntries(
          wfp.map((key) => [key, key !== "dynamicSession"]),
        ),
        globalConfigurationSha256: observationDigest(observations.globalGraph),
      },
      endpoints: structuredClone(legacy.installation.effective.endpoints),
      objects: observations.actual.map((item) => ({
        nativeEventSha256: observationDigest(item),
        exclusiveParents: true,
        foreignWritableHandles: 0,
      })),
    }),
  };
  return {
    input,
    plan,
    reader,
    options,
    context,
    verifier,
    subject,
    objects,
    filters,
    registry,
    token: legacy.installation.effective.token,
  };
}
