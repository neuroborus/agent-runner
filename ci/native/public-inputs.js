import { createHash } from "node:crypto";

import { SOURCE_FINDING_IDS } from "./catalog.js";
import {
  NativeEvidenceError,
  normalizeSourceEvidence,
  normalizeSystemObservation,
} from "./evidence.js";
import {
  PUBLIC_INPUT_REQUIREMENTS,
  SYSTEM_INPUT_REQUIREMENTS,
  SYSTEM_BINDING_KINDS,
} from "./public-input-catalog.js";

const SHA = /^[a-f0-9]{40}$/;
const DIGEST = /^[a-f0-9]{64}$/;
const LABEL = /^[a-z][a-z0-9-]{0,31}$/;
const MEMBER = /^[a-zA-Z0-9._/-]{1,90}$/;
const MAX_BYTES = 64 * 1024 * 1024;
const ACTIONS = Object.freeze({
  MISSING:
    "Prepare the missing immutable member; do not retrieve or execute it in a role.",
  PROVENANCE:
    "Resolve and review exact public URLs, revision and member digests before using these bytes.",
  ALTERED:
    "Reject altered bytes and request a separately prepared bundle against the reviewed provenance.",
});

function assert(condition) {
  if (!condition) throw new NativeEvidenceError();
}

function object(value, fields) {
  assert(value !== null && typeof value === "object" && !Array.isArray(value));
  assert(
    Object.getPrototypeOf(value) === Object.prototype ||
      Object.getPrototypeOf(value) === null,
  );
  assert(
    Reflect.ownKeys(value).length === fields.length &&
      fields.every((field) => Object.hasOwn(value, field)),
  );
  assert(
    Object.values(Object.getOwnPropertyDescriptors(value)).every(
      (descriptor) =>
        descriptor.enumerable && Object.hasOwn(descriptor, "value"),
    ),
  );
}

function list(value, limit) {
  assert(
    Array.isArray(value) &&
      Object.getPrototypeOf(value) === Array.prototype &&
      value.length <= limit,
  );
  assert(Reflect.ownKeys(value).length === value.length + 1);
  for (let index = 0; index < value.length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(value, index);
    assert(descriptor?.enumerable && Object.hasOwn(descriptor, "value"));
  }
  return value;
}

function text(value, limit = 512) {
  assert(
    typeof value === "string" &&
      value.length > 0 &&
      value.length <= limit &&
      !/[^\x20-\x7e]/.test(value),
  );
  return value;
}

function nullable(value, pattern) {
  assert(value === null || (typeof value === "string" && pattern.test(value)));
  return value;
}

function member(value) {
  assert(typeof value === "string" && MEMBER.test(value));
  assert(
    value.split("/").every((part) => part && part !== "." && part !== ".."),
  );
  return value;
}

function publicUrl(value) {
  text(value, 2048);
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new NativeEvidenceError();
  }
  assert(
    url.protocol === "https:" &&
      !url.username &&
      !url.password &&
      !url.port &&
      !url.hash &&
      url.href === value,
  );
  assert(!/[{}<>\\]/.test(value));
  assert(
    !url.search ||
      (url.searchParams.size === 1 &&
        SHA.test(url.searchParams.get("ref") ?? "")),
  );
  return value;
}

function compare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function unique(values) {
  assert(new Set(values).size === values.length);
  return values;
}

function isRevisionRequired(entry) {
  return entry.kind === "source" || entry.gitBlobSha1 !== null;
}

function normalizeBundle(value) {
  object(value, [
    "id",
    "version",
    "revision",
    "findings",
    "urls",
    "priorArchive",
    "files",
    "license",
    "buildInputs",
    "abi",
    "setupPrivileges",
    "missing",
  ]);
  assert(typeof value.id === "string" && LABEL.test(value.id));
  assert(
    value.version === null ||
      /^[0-9]+\.[0-9]+\.[0-9]+$/.test(text(value.version, 32)),
  );
  nullable(value.revision, SHA);
  const findings = unique(
    list(value.findings, 4).map((id) => {
      assert(SOURCE_FINDING_IDS.includes(id));
      return id;
    }),
  ).sort(compare);
  assert(findings.length > 0);
  const urls = unique(list(value.urls, 16).map(publicUrl)).sort(compare);
  const files = list(value.files, 64)
    .map((entry) => {
      object(entry, [
        "path",
        "kind",
        "url",
        "bytes",
        "sha256",
        "gitBlobSha1",
        "archiveSha256",
      ]);
      member(entry.path);
      assert(
        ["archive", "member", "source", "binary", "manifest"].includes(
          entry.kind,
        ),
      );
      if (entry.url !== null) publicUrl(entry.url);
      nullable(entry.sha256, DIGEST);
      nullable(entry.gitBlobSha1, SHA);
      nullable(entry.archiveSha256, DIGEST);
      assert(
        entry.bytes === null ||
          (Number.isSafeInteger(entry.bytes) &&
            entry.bytes >= 0 &&
            entry.bytes <= MAX_BYTES),
      );
      if (
        isRevisionRequired(entry) &&
        value.revision !== null &&
        entry.url !== null
      ) {
        const url = new URL(entry.url);
        assert(
          url.pathname.split("/").includes(value.revision) ||
            url.searchParams.get("ref") === value.revision,
        );
      }
      return { ...entry };
    })
    .sort((left, right) => compare(left.path, right.path));
  unique(files.map((entry) => entry.path));
  let priorArchive = null;
  if (value.priorArchive !== null) {
    const prior = value.priorArchive;
    object(prior, [
      "status",
      "metadataUrl",
      "archiveUrl",
      "keysUrl",
      "sha256",
      "integrity",
      "signatureKeyIds",
      "gitHead",
      "rustSourceMembers",
    ]);
    assert(prior.status === "PRIOR_VERIFIED");
    assert(nullable(prior.sha256, DIGEST) !== null);
    assert(/^sha512-[A-Za-z0-9+/]{86}==$/.test(text(prior.integrity, 128)));
    nullable(prior.gitHead, SHA);
    priorArchive = {
      ...prior,
      metadataUrl: publicUrl(prior.metadataUrl),
      archiveUrl: publicUrl(prior.archiveUrl),
      keysUrl: publicUrl(prior.keysUrl),
      signatureKeyIds: unique(
        list(prior.signatureKeyIds, 8).map((key) => {
          assert(
            typeof key === "string" && /^SHA256:[A-Za-z0-9+/]{43}$/.test(key),
          );
          return key;
        }),
      ).sort(compare),
      rustSourceMembers: unique(
        list(prior.rustSourceMembers, 64).map(member),
      ).sort(compare),
    };
    assert(
      priorArchive.signatureKeyIds.length > 0 &&
        !files.some((entry) => entry.path === "prior-archive"),
    );
    for (const entry of files) {
      if (entry.archiveSha256 !== null)
        assert(
          entry.archiveSha256 === prior.sha256 &&
            entry.url === prior.archiveUrl,
        );
      if (entry.kind === "archive")
        assert(entry.sha256 === prior.sha256 && entry.url === prior.archiveUrl);
    }
  }
  const notes = (key) =>
    list(value[key], 32)
      .map((note) => text(note))
      .sort(compare);
  return {
    id: value.id,
    version: value.version,
    revision: value.revision,
    findings,
    urls,
    priorArchive,
    files,
    license: text(value.license),
    buildInputs: notes("buildInputs"),
    abi: notes("abi"),
    setupPrivileges: notes("setupPrivileges"),
    missing: notes("missing"),
  };
}

/** Consume reviewed provenance separately from immutable, already prepared bytes.
 * Keys are bundle-id/member names, never filesystem paths to open. No extraction,
 * retrieval, installation, candidate import, build or execution occurs here.
 * Even a complete byte match cannot establish source/binary equivalence. */
export function verifyPreparedPublicInputs(input) {
  assert(input !== null && typeof input === "object");
  object(
    input,
    Object.hasOwn(input, "reviewed")
      ? ["candidateSha", "bytes", "reviewed"]
      : ["candidateSha", "bytes"],
  );
  const { candidateSha, bytes } = input;
  const reviewed = Object.hasOwn(input, "reviewed")
    ? input.reviewed
    : PUBLIC_INPUT_REQUIREMENTS;
  assert(typeof candidateSha === "string" && SHA.test(candidateSha));
  assert(
    bytes instanceof Map &&
      Object.getPrototypeOf(bytes) === Map.prototype &&
      Reflect.ownKeys(bytes).length === 0 &&
      bytes.size <= 256,
  );
  const bundles = list(reviewed, 8)
    .map(normalizeBundle)
    .sort((left, right) => compare(left.id, right.id));
  unique(bundles.map((bundle) => bundle.id));
  assert(
    bundles.reduce((count, bundle) => count + bundle.files.length, 0) <= 128,
  );
  const expected = new Set(
    bundles.flatMap((bundle) =>
      bundle.files.map((entry) => `${bundle.id}/${entry.path}`),
    ),
  );
  let totalBytes = 0;
  for (const [key, value] of bytes) {
    assert(
      expected.has(key) &&
        value instanceof Uint8Array &&
        !(value.buffer instanceof SharedArrayBuffer),
    );
    assert(value.byteLength <= MAX_BYTES);
    totalBytes += value.byteLength;
    assert(totalBytes <= 4 * MAX_BYTES);
  }
  const inspected = [];
  const hypotheses = [];
  const missingInputs = [];
  const sourceIds = new Map(SOURCE_FINDING_IDS.map((id) => [id, []]));
  const results = bundles.map((bundle) => {
    const files = bundle.files.map((entry) => {
      const supplied = bytes.get(`${bundle.id}/${entry.path}`);
      const snapshot = supplied === undefined ? null : Buffer.from(supplied);
      const observedSha256 =
        snapshot === null
          ? null
          : createHash("sha256").update(snapshot).digest("hex");
      const observedGitBlobSha1 =
        snapshot === null || entry.gitBlobSha1 === null
          ? null
          : createHash("sha1")
              .update(`blob ${snapshot.length}\0`)
              .update(snapshot)
              .digest("hex");
      const hasProvenance =
        entry.url !== null &&
        entry.sha256 !== null &&
        (!isRevisionRequired(entry) || bundle.revision !== null);
      const isAltered =
        snapshot !== null &&
        ((entry.sha256 !== null && entry.sha256 !== observedSha256) ||
          (entry.bytes !== null && entry.bytes !== snapshot.length) ||
          (entry.gitBlobSha1 !== null &&
            entry.gitBlobSha1 !== observedGitBlobSha1));
      const reason = isAltered
        ? "ALTERED"
        : snapshot === null
          ? "MISSING"
          : !hasProvenance
            ? "PROVENANCE"
            : null;
      const status = isAltered ? "FAIL" : reason !== null ? "BLOCKED" : "PASS";
      if (status === "PASS") {
        const id = `${bundle.id}/${entry.path}`;
        inspected.push({
          id,
          kind: entry.kind === "source" ? "implementation" : "publication",
          url: entry.url,
          revision: bundle.revision,
          sha256: observedSha256,
          binding: "UNPROVED",
          complete: false,
          summary:
            "Prepared bytes match reviewed provenance; release equivalence and reached-source completeness remain unproved.",
        });
        for (const finding of bundle.findings) sourceIds.get(finding).push(id);
      }
      return {
        ...entry,
        status,
        reason,
        observedSha256,
        observedGitBlobSha1,
        observedBytes: snapshot?.length ?? null,
        action: reason === null ? null : ACTIONS[reason],
      };
    });
    // This retained record is a prior publication attestation, not a fresh
    // archive/signature check and never an implementation or helper binding.
    if (bundle.priorArchive !== null) {
      const id = `${bundle.id}/prior-archive`;
      inspected.push({
        id,
        kind: "publication",
        url: bundle.priorArchive.archiveUrl,
        revision: bundle.priorArchive.gitHead,
        sha256: bundle.priorArchive.sha256,
        binding: "VERIFIED",
        complete: false,
        summary:
          "Prior archive SRI/signature reconciliation retained; not rerun and not source/binary equivalence.",
      });
      for (const finding of bundle.findings) sourceIds.get(finding).push(id);
    }
    for (const findingId of bundle.findings) {
      hypotheses.push({
        findingId,
        summary: `Bundle ${bundle.id} remains hypothesis evidence; byte verification cannot bind a released binary or prove native authority.`,
      });
      missingInputs.push({
        findingId,
        summary: `Bundle ${bundle.id} still requires independent release/build binding and complete source review; see its structured missing material.`,
      });
    }
    return {
      ...bundle,
      files,
      byteStatus: files.some((entry) => entry.status === "FAIL")
        ? "FAIL"
        : files.length === 0 ||
            files.some((entry) => entry.status === "BLOCKED")
          ? "BLOCKED"
          : "PASS",
      binding: "UNPROVED",
      admission: "BLOCKED",
      installation: "NOT_AUTHORIZED",
    };
  });
  return {
    schemaVersion: 1,
    candidateSha,
    status: results.some((bundle) => bundle.byteStatus === "FAIL")
      ? "FAIL"
      : "BLOCKED",
    bundles: results,
    source: normalizeSourceEvidence({
      candidateSha,
      inspected,
      hypotheses,
      missingInputs,
      findings: SOURCE_FINDING_IDS.map((id) => ({
        id,
        status: "BLOCKED",
        sourceIds: sourceIds.get(id).slice(0, 32),
      })),
    }),
  };
}

function systemRequirement(platform) {
  const requirement = SYSTEM_INPUT_REQUIREMENTS.find(
    (entry) => entry.platform === platform,
  );
  assert(requirement !== undefined);
  return requirement;
}

function systemId(value) {
  assert(typeof value === "string" && LABEL.test(value));
  return value;
}

function systemInterfaces(value) {
  return unique(
    list(value, 64).map((name) => {
      assert(
        typeof name === "string" &&
          /^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$/.test(name),
      );
      return name;
    }),
  ).sort(compare);
}

function systemReference(value) {
  if (value === null) return null;
  object(value, ["url", "revision", "sha256"]);
  const url = new URL(publicUrl(value.url));
  assert(
    /^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/.test(url.hostname) &&
      !/^[0-9.]+$/.test(url.hostname) &&
      !/(?:^|\.)(?:localhost|local|internal|test|invalid)$/.test(url.hostname),
  );
  nullable(value.revision, SHA);
  assert(nullable(value.sha256, DIGEST) !== null);
  if (value.revision !== null)
    assert(
      url.pathname.split("/").includes(value.revision) ||
        url.searchParams.get("ref") === value.revision,
    );
  return { url: value.url, revision: value.revision, sha256: value.sha256 };
}

/** A separately reviewed snapshot. Null pins describe missing input; no host
 * observation, payload manifest, or source-reference hash can supply them. */
export function normalizeReviewedSystemManifest(value, candidateSha) {
  object(value, [
    "schemaVersion",
    "candidateSha",
    "platform",
    "image",
    "architecture",
    "envelope",
    "components",
    "contracts",
  ]);
  assert(
    typeof candidateSha === "string" &&
      SHA.test(candidateSha) &&
      value.schemaVersion === 1 &&
      value.candidateSha === candidateSha,
  );
  const requirement = systemRequirement(value.platform);
  assert(
    value.image === requirement.image &&
      value.architecture === requirement.architecture,
  );
  object(value.envelope, ["osBuild", "sdkBuild"]);
  const version = (entry) => (entry === null ? null : text(entry, 128));
  const components = list(value.components, 128)
    .map((entry) => {
      object(entry, ["id", "version", "sha256", "dependencies", "bindings"]);
      object(entry.bindings, SYSTEM_BINDING_KINDS);
      return {
        id: systemId(entry.id),
        version: version(entry.version),
        sha256: nullable(entry.sha256, DIGEST),
        dependencies: unique(list(entry.dependencies, 128).map(systemId)).sort(
          compare,
        ),
        bindings: Object.fromEntries(
          SYSTEM_BINDING_KINDS.map((kind) => [
            kind,
            systemReference(entry.bindings[kind]),
          ]),
        ),
      };
    })
    .sort((a, b) => compare(a.id, b.id));
  unique(components.map((entry) => entry.id));
  const byId = new Map(components.map((entry) => [entry.id, entry]));
  // Explicit transitive closure: no external dependency, cycle or orphan grant.
  const visiting = new Set(),
    visited = new Set();
  function visit(id) {
    assert(byId.has(id) && !visiting.has(id));
    if (visited.has(id)) return;
    visiting.add(id);
    for (const dependency of byId.get(id).dependencies) visit(dependency);
    visiting.delete(id);
    visited.add(id);
  }
  for (const id of requirement.components) if (byId.has(id)) visit(id);
  assert(visited.size === components.length);
  const contracts = list(value.contracts, 16)
    .map((entry) => {
      object(entry, ["id", "interfaces", "binding"]);
      assert(
        requirement.contracts.some((contract) => contract.id === entry.id),
      );
      return {
        id: systemId(entry.id),
        interfaces: systemInterfaces(entry.interfaces),
        binding: systemReference(entry.binding),
      };
    })
    .sort((a, b) => compare(a.id, b.id));
  unique(contracts.map((entry) => entry.id));
  const result = {
    schemaVersion: 1,
    candidateSha,
    platform: requirement.platform,
    image: requirement.image,
    architecture: requirement.architecture,
    envelope: {
      osBuild: version(value.envelope.osBuild),
      sdkBuild: version(value.envelope.sdkBuild),
    },
    components,
    contracts,
  };
  assert(Buffer.byteLength(JSON.stringify(result)) <= 1048576);
  return result;
}

/** Pure review/observation join. MATCHED is consistency only: no installation,
 * native admission, source closure or full PoC acceptance is granted here. */
export function verifyReviewedSystemInputs(input) {
  object(input, ["candidateSha", "platform", "reviewed", "observed"]);
  assert(
    typeof input.candidateSha === "string" && SHA.test(input.candidateSha),
  );
  const requirement = systemRequirement(input.platform);
  const reviewed =
    input.reviewed === null
      ? null
      : normalizeReviewedSystemManifest(input.reviewed, input.candidateSha);
  assert(reviewed === null || reviewed.platform === input.platform);
  const observed =
    input.observed === null ? null : normalizeSystemObservation(input.observed);
  const missingInputs = [],
    mismatches = [];
  if (reviewed === null) {
    missingInputs.push("reviewed-system-manifest", ...requirement.missing);
  } else {
    for (const key of ["osBuild", "sdkBuild"])
      if (reviewed.envelope[key] === null)
        missingInputs.push(`envelope.${key}`);
    for (const id of requirement.components)
      if (!reviewed.components.some((entry) => entry.id === id))
        missingInputs.push(`component.${id}`);
    for (const component of reviewed.components) {
      for (const key of ["version", "sha256"])
        if (component[key] === null)
          missingInputs.push(`component.${component.id}.${key}`);
      for (const kind of SYSTEM_BINDING_KINDS)
        if (component.bindings[kind] === null)
          missingInputs.push(`component.${component.id}.${kind}`);
    }
    for (const contract of requirement.contracts) {
      const binding = reviewed.contracts.find(
        (entry) => entry.id === contract.id,
      );
      if (!binding || binding.binding === null)
        missingInputs.push(`contract.${contract.id}.binding`);
      for (const name of contract.interfaces)
        if (!binding?.interfaces.includes(name))
          missingInputs.push(`contract.${contract.id}.${name}`);
    }
  }
  if (observed === null) missingInputs.push("independent-system-observation");
  else {
    for (const key of ["candidateSha", "platform", "image", "architecture"]) {
      const expected =
        key === "candidateSha" ? input.candidateSha : requirement[key];
      if (observed[key] !== expected) mismatches.push(key);
    }
    for (const key of ["osBuild", "sdkBuild"])
      if (observed.envelope[key] === null)
        missingInputs.push(`observation.envelope.${key}`);
    for (const id of requirement.components)
      if (!observed.components.some((entry) => entry.id === id))
        missingInputs.push(`observation.component.${id}`);
    for (const component of observed.components)
      for (const kind of SYSTEM_BINDING_KINDS)
        if (component.bindings[kind] === null)
          missingInputs.push(`observation.component.${component.id}.${kind}`);
    // Unsupported mandatory APIs remain failures even if review pins are absent.
    for (const contract of requirement.contracts) {
      const actual = observed.contracts.find(
        (entry) => entry.id === contract.id,
      );
      if (!actual) missingInputs.push(`observation.contract.${contract.id}`);
      else {
        if (!actual.supported)
          mismatches.push(`contract.${contract.id}.unsupported`);
        if (actual.bindingSha256 === null)
          missingInputs.push(`observation.contract.${contract.id}.binding`);
        for (const name of contract.interfaces)
          if (!actual.interfaces.includes(name))
            mismatches.push(`contract.${contract.id}.${name}`);
      }
    }
    if (reviewed !== null) {
      for (const key of ["osBuild", "sdkBuild"])
        if (
          reviewed.envelope[key] !== null &&
          observed.envelope[key] !== null &&
          reviewed.envelope[key] !== observed.envelope[key]
        )
          mismatches.push(`envelope.${key}`);
      if (
        JSON.stringify(reviewed.components.map((entry) => entry.id)) !==
        JSON.stringify(observed.components.map((entry) => entry.id))
      )
        mismatches.push("component-inventory");
      if (
        JSON.stringify(reviewed.contracts.map((entry) => entry.id)) !==
        JSON.stringify(observed.contracts.map((entry) => entry.id))
      )
        mismatches.push("contract-inventory");
      for (const expected of reviewed.components) {
        const actual = observed.components.find(
          (entry) => entry.id === expected.id,
        );
        if (!actual) continue;
        for (const key of ["version", "sha256"])
          if (expected[key] !== null && expected[key] !== actual[key])
            mismatches.push(`component.${expected.id}.${key}`);
        if (
          JSON.stringify(expected.dependencies) !==
          JSON.stringify(actual.dependencies)
        )
          mismatches.push(`component.${expected.id}.dependencies`);
        for (const kind of SYSTEM_BINDING_KINDS)
          if (
            expected.bindings[kind] !== null &&
            actual.bindings[kind] !== null &&
            expected.bindings[kind].sha256 !== actual.bindings[kind]
          )
            mismatches.push(`component.${expected.id}.${kind}`);
      }
      for (const expected of reviewed.contracts) {
        const actual = observed.contracts.find(
          (entry) => entry.id === expected.id,
        );
        if (!actual) continue;
        if (
          expected.binding !== null &&
          actual.bindingSha256 !== null &&
          expected.binding.sha256 !== actual.bindingSha256
        )
          mismatches.push(`contract.${expected.id}.binding`);
        if (
          JSON.stringify(expected.interfaces) !==
          JSON.stringify(actual.interfaces)
        )
          mismatches.push(`contract.${expected.id}.interfaces`);
      }
    }
  }
  return {
    schemaVersion: 1,
    candidateSha: input.candidateSha,
    platform: requirement.platform,
    reviewedSha256:
      reviewed === null
        ? null
        : createHash("sha256").update(JSON.stringify(reviewed)).digest("hex"),
    status: mismatches.length ? "FAIL" : "BLOCKED",
    bindingStatus: mismatches.length
      ? "MISMATCH"
      : missingInputs.length
        ? "MISSING"
        : "MATCHED",
    missingInputs: [...new Set(missingInputs)].sort(compare),
    mismatches: [...new Set(mismatches)].sort(compare),
    admission: "BLOCKED",
    source: normalizeSourceEvidence({
      candidateSha: input.candidateSha,
      inspected: [],
      hypotheses: [],
      missingInputs: SOURCE_FINDING_IDS.map((findingId) => ({
        findingId,
        summary:
          "System manifest consistency cannot establish complete source review, native authority or external acceptance.",
      })),
      findings: SOURCE_FINDING_IDS.map((id) => ({
        id,
        status: "BLOCKED",
        sourceIds: [],
      })),
    }),
  };
}
