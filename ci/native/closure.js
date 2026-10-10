import {
  observationDigest,
  observationObject as closed,
  observationList as list,
  requireObservation as requireValue,
} from "./observation.js";
import { PLATFORMS } from "./catalog.js";

const hash = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
const label = (value) =>
  typeof value === "string" && /^[a-z][a-z0-9.-]{0,95}$/u.test(value);
const same = (a, b) => observationDigest(a) === observationDigest(b);
const bindings = ["publication", "source", "build", "license", "abi"];
const sorted = (values) => [...values].sort();
function ids(values, maximum = 128) {
  const result = list(values, maximum);
  requireValue(result.every(label) && new Set(result).size === result.length);
  return sorted(result);
}

/** Independently admitted review input, not an observed status or provider claim. */
export function normalizeReleaseClosure(value) {
  const version = Object.getOwnPropertyDescriptor(
    value ?? {},
    "schemaVersion",
  )?.value;
  closed(value, [
    "schemaVersion",
    "candidateSha",
    "platform",
    "image",
    "osBuild",
    "sdkBuild",
    ...(version === 2 ? ["policyTemplates"] : ["policySha256"]),
    "privileges",
    "components",
    "providers",
  ]);
  const platform = PLATFORMS.find(({ os }) => os === value.platform);
  requireValue(
    [1, 2].includes(version) &&
      /^[a-f0-9]{40}$/u.test(value.candidateSha) &&
      platform?.image === value.image &&
      (version === 2 || hash(value.policySha256)),
  );
  for (const key of ["osBuild", "sdkBuild"])
    requireValue(
      typeof value[key] === "string" &&
        /^[a-zA-Z0-9 ._-]{1,128}$/u.test(value[key]),
    );
  const components = list(value.components, 128)
    .map((component) => {
      closed(component, [
        "id",
        "role",
        "sha256",
        "format",
        "loader",
        "bindings",
      ]);
      requireValue(
        label(component.id) &&
          ["executable", "helper", "dependency"].includes(component.role) &&
          hash(component.sha256),
      );
      requireValue(
        component.format ===
          { linux: "elf-x64", darwin: "macho-x64", win32: "pe-x64" }[
            value.platform
          ],
      );
      closed(component.bindings, bindings);
      requireValue(bindings.every((key) => hash(component.bindings[key])));
      return {
        id: component.id,
        role: component.role,
        sha256: component.sha256,
        format: component.format,
        loader: ids(component.loader),
        bindings: Object.fromEntries(
          bindings.map((key) => [key, component.bindings[key]]),
        ),
      };
    })
    .sort((a, b) => a.id.localeCompare(b.id, "en"));
  requireValue(
    components.length > 0 &&
      new Set(components.map(({ id }) => id)).size === components.length,
  );
  requireValue(components.some(({ role }) => role === "helper"));
  requireValue(
    components.every(({ loader }) =>
      loader.every((id) => components.some((item) => item.id === id)),
    ),
  );
  closed(value.providers, ["codex", "claude"]);
  const providers = Object.fromEntries(
    ["codex", "claude"].map((name) => {
      const entry = value.providers[name];
      closed(entry, ["reviewSha256", "closureSha256", "members"]);
      requireValue(hash(entry.reviewSha256) && hash(entry.closureSha256));
      const members = ids(entry.members);
      requireValue(
        members.length > 0 &&
          members.every((id) => components.some((item) => item.id === id)),
      );
      requireValue(
        members.every((id) =>
          components
            .find((item) => item.id === id)
            .loader.every((dependency) => members.includes(dependency)),
        ),
      );
      requireValue(
        members.some(
          (id) =>
            components.find((item) => item.id === id).role === "executable",
        ),
      );
      return [
        name,
        {
          reviewSha256: entry.reviewSha256,
          closureSha256: entry.closureSha256,
          members,
        },
      ];
    }),
  );
  return {
    schemaVersion: version,
    candidateSha: value.candidateSha,
    platform: value.platform,
    image: value.image,
    osBuild: value.osBuild,
    sdkBuild: value.sdkBuild,
    ...(version === 2
      ? { policyTemplates: normalizePolicyTemplatePins(value.policyTemplates) }
      : { policySha256: value.policySha256 }),
    privileges: ids(value.privileges, 32),
    components,
    providers,
  };
}
export const releaseClosureDigest = (value) =>
  observationDigest(normalizeReleaseClosure(value));

export function normalizeReviewAuthority(value, candidateSha, platform = null) {
  closed(value, ["candidateSha", "platform", "manifestSha256", "authority"]);
  requireValue(
    value.candidateSha === candidateSha &&
      value.platform === platform &&
      value.authority === "operator-protected" &&
      hash(value.manifestSha256),
  );
  return { ...value };
}

/** Held native identity and actual loader reads are supplied by the platform
 * verifier. Expected manifests cannot manufacture those reads. */
export function verifyReleaseClosure(input, observed, authority) {
  const manifest = normalizeReleaseClosure(input);
  normalizeReviewAuthority(authority, manifest.candidateSha, manifest.platform);
  requireValue(authority.manifestSha256 === releaseClosureDigest(manifest));
  closed(observed, [
    "schemaVersion",
    "candidateSha",
    "platform",
    "image",
    "osBuild",
    "sdkBuild",
    ...(manifest.schemaVersion === 2 ? ["policyTemplates"] : ["policySha256"]),
    "privileges",
    "components",
    "providers",
    "independent",
    "settlementSha256",
  ]);
  requireValue(
    observed.schemaVersion === manifest.schemaVersion &&
      observed.independent === true &&
      hash(observed.settlementSha256),
  );
  for (const key of [
    "candidateSha",
    "platform",
    "image",
    "osBuild",
    "sdkBuild",
    ...(manifest.schemaVersion === 2 ? [] : ["policySha256"]),
  ])
    requireValue(observed[key] === manifest[key]);
  if (manifest.schemaVersion === 2)
    requireValue(
      same(
        normalizePolicyTemplatePins(observed.policyTemplates),
        manifest.policyTemplates,
      ),
    );
  requireValue(same(ids(observed.privileges, 32), manifest.privileges));
  const components = list(observed.components, 128)
    .map((entry) => {
      closed(entry, [
        "id",
        "sha256",
        "format",
        "loader",
        "bindings",
        "identityBefore",
        "identityAfter",
        "held",
        "independent",
      ]);
      requireValue(
        entry.held === true &&
          entry.independent === true &&
          hash(entry.identityBefore) &&
          entry.identityBefore === entry.identityAfter,
      );
      const expected = manifest.components.find(({ id }) => id === entry.id);
      requireValue(
        expected &&
          expected.sha256 === entry.sha256 &&
          expected.format === entry.format &&
          same(ids(entry.loader), expected.loader),
      );
      closed(entry.bindings, bindings);
      requireValue(
        bindings.every((key) => entry.bindings[key] === expected.bindings[key]),
      );
      return {
        ...entry,
        loader: ids(entry.loader),
        bindings: Object.fromEntries(
          bindings.map((key) => [key, entry.bindings[key]]),
        ),
      };
    })
    .sort((a, b) => a.id.localeCompare(b.id, "en"));
  requireValue(
    same(
      components.map(({ id }) => id),
      manifest.components.map(({ id }) => id),
    ),
  );
  closed(observed.providers, ["codex", "claude"]);
  const providerBindings = Object.fromEntries(
    ["codex", "claude"].map((name) => {
      const entry = observed.providers[name],
        expected = manifest.providers[name];
      closed(entry, [
        "reviewSha256",
        "closureSha256",
        "members",
        "liveBindingSha256",
        "independent",
      ]);
      requireValue(
        entry.independent === true &&
          hash(entry.liveBindingSha256) &&
          entry.reviewSha256 === expected.reviewSha256 &&
          entry.closureSha256 === expected.closureSha256 &&
          same(ids(entry.members), expected.members),
      );
      return [name, entry.liveBindingSha256];
    }),
  );
  return {
    ...(manifest.schemaVersion === 2
      ? { schemaVersion: 2, policyTemplates: manifest.policyTemplates }
      : {}),
    manifestSha256: authority.manifestSha256,
    observationSha256: observationDigest({
      ...observed,
      privileges: ids(observed.privileges, 32),
      components,
    }),
    providerBindings,
  };
}

export function normalizeClosureReference(value) {
  const version = Object.getOwnPropertyDescriptor(
    value ?? {},
    "schemaVersion",
  )?.value;
  closed(value, [
    ...(version === 2 ? ["schemaVersion", "policyTemplates"] : []),
    "manifestSha256",
    "observationSha256",
    "sourceReviewSha256",
    "providerBindings",
  ]);
  requireValue(
    [
      value.manifestSha256,
      value.observationSha256,
      value.sourceReviewSha256,
    ].every(hash),
  );
  closed(value.providerBindings, ["codex", "claude"]);
  requireValue(Object.values(value.providerBindings).every(hash));
  return {
    ...(version === 2
      ? {
          schemaVersion: 2,
          policyTemplates: normalizePolicyTemplatePins(value.policyTemplates),
        }
      : {}),
    manifestSha256: value.manifestSha256,
    observationSha256: value.observationSha256,
    sourceReviewSha256: value.sourceReviewSha256,
    providerBindings: {
      codex: value.providerBindings.codex,
      claude: value.providerBindings.claude,
    },
  };
}

function normalizePolicyTemplatePins(value) {
  const pins = list(value, 256);
  requireValue(
    pins.length > 0 && pins.every(hash) && new Set(pins).size === pins.length,
  );
  return sorted(pins);
}
