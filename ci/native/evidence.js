import {
  CHECK_IDS,
  PROVIDER_CHECK_IDS,
  SOURCE_FINDING_IDS,
  linuxNativeGroup,
} from "./catalog.js";
import { SYSTEM_BINDING_KINDS } from "./public-input-catalog.js";

const SHA256 = /^[a-f0-9]{64}$/u;
const SHA = /^[a-f0-9]{40}$/u;
const LABEL = /^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,127}$/u;
const STATUSES = ["PASS", "FAIL", "BLOCKED", "NOT_RUN", "CANCELLED", "SKIPPED"];
const REASONS = [
  "missing-input",
  "unimplemented",
  "unsupported-platform",
  "incompatible-image",
  "setup-failed",
  "probe-failed",
  "cleanup-failed",
  "deadline",
  "observation-mismatch",
  "unretired",
  "cancelled",
  "skipped",
];
const REQUIRED_PROFILES = Object.freeze({
  "profile.read-only": "read-only",
  "profile.workspace-write": "workspace-write",
  "profile.trusted-command": "trusted-command",
  "git.fixed-commit": "commit",
});

export class NativeEvidenceError extends Error {
  constructor() {
    super(
      "Invalid native proof evidence; inspect the closed evidence contract.",
    );
    this.name = "NativeEvidenceError";
    this.code = "ERR_INVALID_NATIVE_EVIDENCE";
  }
}

function requireValue(condition) {
  if (!condition) throw new NativeEvidenceError();
}

function object(value, fields) {
  requireValue(
    value !== null && typeof value === "object" && !Array.isArray(value),
  );
  requireValue(
    Object.getPrototypeOf(value) === Object.prototype ||
      Object.getPrototypeOf(value) === null,
  );
  requireValue(
    Reflect.ownKeys(value).length === fields.length &&
      fields.every((key) => Object.hasOwn(value, key)),
  );
  requireValue(
    Object.values(Object.getOwnPropertyDescriptors(value)).every(
      (descriptor) =>
        descriptor.enumerable && Object.hasOwn(descriptor, "value"),
    ),
  );
  return value;
}

function array(value, maximum) {
  requireValue(
    Array.isArray(value) &&
      Object.getPrototypeOf(value) === Array.prototype &&
      value.length <= maximum,
  );
  requireValue(Reflect.ownKeys(value).length === value.length + 1);
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    requireValue(descriptor?.enumerable && Object.hasOwn(descriptor, "value"));
  }
}

function list(value, normalize, maximum = 256) {
  array(value, maximum);
  return Array.from(value, normalize);
}

function unique(values, key) {
  requireValue(new Set(values.map(key)).size === values.length);
  return values;
}

function text(value, pattern = LABEL) {
  requireValue(
    typeof value === "string" && value.length <= 256 && pattern.test(value),
  );
  return value;
}

function oneOf(value, allowed) {
  requireValue(allowed.includes(value));
  return value;
}

function boolean(value) {
  requireValue(typeof value === "boolean");
  return value;
}

function integer(value, minimum = 0) {
  requireValue(
    Number.isSafeInteger(value) && value >= minimum && value <= 2147483647,
  );
  return value;
}

// Diagnostic prose is bounded and never used to select an outcome. Raw output,
// environments, provider responses, and sessions are not fields in this contract.
function prose(value) {
  requireValue(typeof value === "string" && value.length <= 4096);
  return value
    .replace(/\u001b\[[0-?]*[ -/]*[@-~]/gu, "")
    .replace(
      /[\p{Cf}\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/gu,
      "",
    )
    .replace(/\b(?:https?|wss?):\/\/[^\s<>"']+/giu, "[url omitted]")
    .replace(/\b(?:Bearer|Basic)\s+\S+/giu, "[authorization omitted]")
    .replace(
      /\b(?:password|passwd|secret|token|(?:access|refresh|id)[-_]?token|client[-_]?secret|api[-_]?key|authorization|cookie|session[-_]?id)\b["']?\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\r\n]*)/giu,
      "[redacted]",
    )
    .replace(/\b(?:sk-|gh[pousr]_)[a-zA-Z0-9_-]+/gu, "[redacted]")
    .replace(/(?:[a-zA-Z]:[\\/]|\/)[^\s<>"']+/gu, "[path omitted]")
    .replace(/::[a-zA-Z][^\r\n]*/gu, "[workflow command omitted]")
    .replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, " ")
    .replace(/\s+/gu, " ")
    .trim()
    .slice(0, 512);
}

// Identity-bearing metadata must survive unchanged. Sanitization must not make
// distinct builds or versions compare equal or retain sensitive identifiers.
function metadata(value) {
  requireValue(
    typeof value === "string" && value.length > 0 && value.length <= 512,
  );
  requireValue(prose(value) === value);
  return value;
}

function publicUrl(value) {
  requireValue(typeof value === "string" && value.length <= 2048);
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new NativeEvidenceError();
  }
  requireValue(
    url.href === value &&
      url.protocol === "https:" &&
      !url.username &&
      !url.password &&
      !url.port &&
      !url.hash,
  );
  const parameters = [...url.searchParams];
  requireValue(
    parameters.length === 0 ||
      (parameters.length === 1 &&
        parameters[0][0] === "ref" &&
        SHA.test(parameters[0][1])),
  );
  requireValue(
    /^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/u.test(url.hostname) &&
      !/^[0-9.]+$/u.test(url.hostname) &&
      !/(?:^|\.)(?:localhost|local|internal|test|invalid)$/u.test(url.hostname),
  );
  return value;
}

function provenance(value) {
  object(value, ["repository", "workflow", "runId", "runAttempt", "jobId"]);
  return {
    repository:
      value.repository === null
        ? null
        : text(value.repository, /^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/u),
    workflow: value.workflow === null ? null : text(value.workflow),
    runId:
      value.runId === null ? null : text(value.runId, /^[1-9][0-9]{0,19}$/u),
    runAttempt: value.runAttempt === null ? null : integer(value.runAttempt, 1),
    jobId:
      value.jobId === null ? null : text(value.jobId, /^[1-9][0-9]{0,19}$/u),
  };
}

function phase(value) {
  object(value, ["status", "elapsedMs", "deadlineMs", "reason"]);
  const result = {
    status: oneOf(value.status, STATUSES),
    elapsedMs: value.elapsedMs === null ? null : integer(value.elapsedMs),
    deadlineMs: integer(value.deadlineMs, 1),
    reason: value.reason === null ? null : oneOf(value.reason, REASONS),
  };
  if (result.status === "PASS") {
    requireValue(
      result.elapsedMs !== null &&
        result.elapsedMs <= result.deadlineMs &&
        result.reason === null,
    );
  } else {
    requireValue(result.reason !== null);
  }
  return result;
}

function observation(value) {
  object(value, [
    "expected",
    "observed",
    "matched",
    "positiveControl",
    "attempted",
    "sentinelsUnchanged",
  ]);
  return {
    expected: prose(value.expected),
    observed: value.observed === null ? null : prose(value.observed),
    matched: boolean(value.matched),
    positiveControl: boolean(value.positiveControl),
    attempted: boolean(value.attempted),
    sentinelsUnchanged: boolean(value.sentinelsUnchanged),
  };
}

/** Effect ledgers are producer evidence, never inferred from reporting cleanup. */
export function normalizeNativeAdmission(value) {
  object(value, ["admission", "settlement"]);
  object(value.settlement, ["status", "independent", "emergencyCleanup"]);
  const result = {
    admission: oneOf(value.admission, ["not-started", "possible"]),
    settlement: {
      status: oneOf(value.settlement.status, [
        "RETIRED",
        "RETAINED",
        "UNVERIFIABLE",
      ]),
      independent: boolean(value.settlement.independent),
      emergencyCleanup: boolean(value.settlement.emergencyCleanup),
    },
  };
  requireValue(
    result.settlement.independent === (result.settlement.status === "RETIRED"),
  );
  if (result.admission === "not-started")
    requireValue(
      result.settlement.status === "RETAINED" &&
        !result.settlement.emergencyCleanup,
    );
  return result;
}

/** References retain bounded evidence identities/digests, not native raw output. */
export function normalizeNativeSupportingEvidence(value) {
  const records = unique(
    list(
      value,
      (entry) => {
        object(entry, ["checkId", "kind", "id", "sha256"]);
        const group = linuxNativeGroup(entry.checkId);
        requireValue(group !== null);
        const kinds =
          group === "files"
            ? ["build", "receipt", "operation", "interruption", "recovery"]
            : group === "release"
              ? ["release"]
              : ["receipt"];
        return {
          checkId: oneOf(entry.checkId, CHECK_IDS),
          kind: oneOf(entry.kind, kinds),
          id: text(entry.id, /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/u),
          sha256: text(entry.sha256, SHA256),
        };
      },
      32,
    ),
    (entry) => JSON.stringify([entry.checkId, entry.kind, entry.id]),
  );
  const identities = new Map();
  for (const entry of records) {
    const key = JSON.stringify([
      linuxNativeGroup(entry.checkId),
      entry.kind,
      entry.id,
    ]);
    requireValue(!identities.has(key) || identities.get(key) === entry.sha256);
    identities.set(key, entry.sha256);
  }
  return records.sort((a, b) => {
    const first = JSON.stringify(a),
      second = JSON.stringify(b);
    return first < second ? -1 : first > second ? 1 : 0;
  });
}

export function normalizeNativeResult(value) {
  const version =
    value && typeof value === "object"
      ? Object.getOwnPropertyDescriptor(value, "schemaVersion")?.value
      : null;
  object(value, [
    "schemaVersion",
    "candidateSha",
    "checkoutSha",
    "platform",
    "declaredImage",
    "observed",
    "provenance",
    "checkId",
    "profile",
    "tier",
    "dispatch",
    "implemented",
    "versions",
    "policy",
    "phases",
    "observations",
    "settlement",
    "status",
    "reason",
    ...(version === 2 ? ["admission"] : []),
  ]);
  requireValue([1, 2].includes(version));
  object(value.observed, ["os", "image", "build", "architecture"]);
  object(value.phases, ["setup", "probe", "cleanup"]);
  object(value.settlement, ["status", "independent", "emergencyCleanup"]);
  if (value.policy !== null) object(value.policy, ["id", "sha256"]);
  const result = {
    schemaVersion: 2,
    admission:
      version === 2
        ? oneOf(value.admission, ["possible", "not-started"])
        : "possible",
    candidateSha: text(value.candidateSha, SHA),
    checkoutSha:
      value.checkoutSha === null ? null : text(value.checkoutSha, SHA),
    platform: text(value.platform),
    declaredImage: text(value.declaredImage),
    observed: {
      os: value.observed.os === null ? null : text(value.observed.os),
      image: value.observed.image === null ? null : text(value.observed.image),
      build:
        value.observed.build === null ? null : metadata(value.observed.build),
      architecture:
        value.observed.architecture === null
          ? null
          : text(value.observed.architecture),
    },
    provenance: provenance(value.provenance),
    checkId: oneOf(value.checkId, CHECK_IDS),
    profile: text(value.profile),
    tier: oneOf(value.tier, ["system", "provider"]),
    dispatch: oneOf(value.dispatch, ["native", "model-free", "protected"]),
    implemented: boolean(value.implemented),
    versions: unique(
      list(
        value.versions,
        (entry) => {
          object(entry, ["name", "version", "sha256"]);
          return {
            name: text(entry.name),
            version: metadata(entry.version),
            sha256: text(entry.sha256, SHA256),
          };
        },
        32,
      ),
      ({ name }) => name,
    ),
    policy:
      value.policy === null
        ? null
        : {
            id: text(value.policy.id),
            sha256: text(value.policy.sha256, SHA256),
          },
    phases: Object.fromEntries(
      ["setup", "probe", "cleanup"].map((name) => [
        name,
        phase(value.phases[name]),
      ]),
    ),
    observations: list(value.observations, observation, 32),
    settlement: {
      status: oneOf(value.settlement.status, [
        "RETIRED",
        "RETAINED",
        "UNVERIFIABLE",
      ]),
      independent: boolean(value.settlement.independent),
      emergencyCleanup: boolean(value.settlement.emergencyCleanup),
    },
    status: oneOf(value.status, ["PASS", "FAIL", "BLOCKED"]),
    reason: value.reason === null ? null : oneOf(value.reason, REASONS),
  };
  const provider = PROVIDER_CHECK_IDS.includes(result.checkId);
  requireValue(
    provider
      ? (result.dispatch === "model-free" && result.tier === "system") ||
          (result.dispatch === "protected" && result.tier === "provider")
      : result.dispatch === "native" && result.tier === "system",
  );
  if (Object.hasOwn(REQUIRED_PROFILES, result.checkId))
    requireValue(result.profile === REQUIRED_PROFILES[result.checkId]);
  if (result.phases.probe.status === "PASS")
    requireValue(result.phases.setup.status === "PASS");
  if (result.status === "PASS") {
    requireValue(
      Object.values(result.provenance).every((entry) => entry !== null),
    );
    requireValue(
      result.implemented &&
        result.admission === "possible" &&
        result.reason === null &&
        result.checkoutSha === result.candidateSha &&
        result.observed.image === result.declaredImage &&
        result.observed.build &&
        result.versions.length > 0 &&
        result.versions.every(({ version }) => version.length > 0) &&
        result.policy !== null,
    );
    requireValue(
      Object.values(result.phases).every(({ status }) => status === "PASS"),
    );
    requireValue(
      result.observations.length > 0 &&
        result.observations.every(
          (entry) =>
            entry.expected &&
            entry.observed &&
            entry.matched &&
            entry.positiveControl &&
            entry.attempted &&
            entry.sentinelsUnchanged,
        ),
    );
    requireValue(
      result.settlement.status === "RETIRED" &&
        result.settlement.independent &&
        !result.settlement.emergencyCleanup,
    );
  } else {
    requireValue(result.reason !== null);
    if (result.status === "FAIL")
      requireValue(
        Object.values(result.phases).some(({ status }) => status === "FAIL") ||
          result.observations.some(
            (entry) =>
              !entry.matched ||
              !entry.positiveControl ||
              !entry.attempted ||
              !entry.sentinelsUnchanged,
          ) ||
          result.settlement.status !== "RETIRED" ||
          !result.settlement.independent ||
          result.settlement.emergencyCleanup,
      );
  }
  return result;
}

/** Only explicit, compatible producer evidence excludes process effects.
 * Labels, absent receipts and legacy empty observations cannot establish it. */
export function hasNativeProcessEffects(result) {
  const nonAdmission =
    result.status === "BLOCKED"
      ? ["missing-input", "unimplemented"].includes(result.reason) &&
        result.phases.setup.status === "NOT_RUN" &&
        result.phases.setup.elapsedMs === null &&
        result.phases.setup.reason === result.reason
      : result.status === "FAIL" &&
        ["setup-failed", "deadline"].includes(result.reason) &&
        result.phases.setup.status === "FAIL" &&
        result.phases.setup.reason === result.reason;
  const notRunReason =
    result.status === "BLOCKED" ? result.reason : "missing-input";
  return !(
    result.schemaVersion === 2 &&
    result.admission === "not-started" &&
    nonAdmission &&
    result.policy === null &&
    result.observations.length === 0 &&
    result.phases.probe.status === "NOT_RUN" &&
    result.phases.cleanup.status === "NOT_RUN" &&
    result.phases.probe.elapsedMs === null &&
    result.phases.cleanup.elapsedMs === null &&
    result.phases.probe.reason === notRunReason &&
    result.phases.cleanup.reason === notRunReason &&
    result.settlement.status === "RETAINED" &&
    !result.settlement.independent &&
    !result.settlement.emergencyCleanup
  );
}

export function normalizeSourceEvidence(value) {
  object(value, [
    "candidateSha",
    "inspected",
    "hypotheses",
    "missingInputs",
    "findings",
  ]);
  const notes = (entry) => {
    object(entry, ["findingId", "summary"]);
    return {
      findingId: oneOf(entry.findingId, SOURCE_FINDING_IDS),
      summary: prose(entry.summary),
    };
  };
  const inspected = unique(
    list(value.inspected, (entry) => {
      object(entry, [
        "id",
        "kind",
        "url",
        "revision",
        "sha256",
        "binding",
        "complete",
        "summary",
      ]);
      return {
        id: text(entry.id),
        kind: oneOf(entry.kind, ["publication", "implementation"]),
        url: publicUrl(entry.url),
        revision: entry.revision === null ? null : text(entry.revision, SHA),
        sha256: text(entry.sha256, SHA256),
        binding: oneOf(entry.binding, ["UNPROVED", "VERIFIED"]),
        complete: boolean(entry.complete),
        summary: prose(entry.summary),
      };
    }),
    ({ id }) => id,
  );
  const findings = unique(
    list(
      value.findings,
      (entry) => {
        object(entry, ["id", "status", "sourceIds"]);
        const sourceIds = unique(
          list(entry.sourceIds, (id) => text(id), 32),
          (id) => id,
        );
        requireValue(
          sourceIds.every((id) => inspected.some((fact) => fact.id === id)),
        );
        return {
          id: oneOf(entry.id, SOURCE_FINDING_IDS),
          status: oneOf(entry.status, ["CLOSED", "BLOCKED"]),
          sourceIds,
        };
      },
      SOURCE_FINDING_IDS.length,
    ),
    ({ id }) => id,
  );
  return {
    candidateSha: text(value.candidateSha, SHA),
    inspected: inspected.sort((a, b) =>
      a.id < b.id ? -1 : a.id > b.id ? 1 : 0,
    ),
    hypotheses: list(value.hypotheses, notes).sort((a, b) =>
      JSON.stringify(a) < JSON.stringify(b)
        ? -1
        : JSON.stringify(a) > JSON.stringify(b)
          ? 1
          : 0,
    ),
    missingInputs: list(value.missingInputs, notes).sort((a, b) =>
      JSON.stringify(a) < JSON.stringify(b)
        ? -1
        : JSON.stringify(a) > JSON.stringify(b)
          ? 1
          : 0,
    ),
    findings: findings
      .map((entry) => ({ ...entry, sourceIds: entry.sourceIds.sort() }))
      .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)),
  };
}

/** Independent CI observations are comparison inputs, never review authority.
 * Interface availability and evidence digests cannot close a source finding. */
export function normalizeSystemObservation(value) {
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
  requireValue(value.schemaVersion === 1);
  object(value.envelope, ["osBuild", "sdkBuild"]);
  const ids = (values) =>
    unique(
      list(values, (id) => text(id, /^[a-z][a-z0-9-]{0,31}$/u), 128),
      (id) => id,
    ).sort();
  const components = unique(
    list(
      value.components,
      (entry) => {
        object(entry, ["id", "version", "sha256", "dependencies", "bindings"]);
        object(entry.bindings, SYSTEM_BINDING_KINDS);
        return {
          id: text(entry.id, /^[a-z][a-z0-9-]{0,31}$/u),
          version: metadata(entry.version),
          sha256: text(entry.sha256, SHA256),
          dependencies: ids(entry.dependencies),
          bindings: Object.fromEntries(
            SYSTEM_BINDING_KINDS.map((kind) => [
              kind,
              entry.bindings[kind] === null
                ? null
                : text(entry.bindings[kind], SHA256),
            ]),
          ),
        };
      },
      128,
    ),
    (entry) => entry.id,
  ).sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  const contracts = unique(
    list(
      value.contracts,
      (entry) => {
        object(entry, ["id", "interfaces", "bindingSha256", "supported"]);
        return {
          id: text(entry.id, /^[a-z][a-z0-9-]{0,31}$/u),
          interfaces: unique(
            list(
              entry.interfaces,
              (name) => text(name, /^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$/u),
              64,
            ),
            (name) => name,
          ).sort(),
          bindingSha256:
            entry.bindingSha256 === null
              ? null
              : text(entry.bindingSha256, SHA256),
          supported: boolean(entry.supported),
        };
      },
      16,
    ),
    (entry) => entry.id,
  ).sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  return {
    schemaVersion: 1,
    candidateSha: text(value.candidateSha, SHA),
    platform: oneOf(value.platform, ["linux", "darwin", "win32"]),
    image: metadata(value.image),
    architecture: metadata(value.architecture),
    envelope: {
      osBuild:
        value.envelope.osBuild === null
          ? null
          : metadata(value.envelope.osBuild),
      sdkBuild:
        value.envelope.sdkBuild === null
          ? null
          : metadata(value.envelope.sdkBuild),
    },
    components,
    contracts,
  };
}

export function normalizeBinding(value) {
  object(value, [
    "artifactId",
    "candidateSha",
    "platform",
    "tier",
    "provenance",
    "conclusion",
    "authority",
  ]);
  const identity = provenance(value.provenance);
  requireValue(Object.values(identity).every((entry) => entry !== null));
  return {
    artifactId: text(value.artifactId, /^[1-9][0-9]{0,19}$/u),
    candidateSha: text(value.candidateSha, SHA),
    platform: text(value.platform),
    tier: oneOf(value.tier, ["system", "provider"]),
    provenance: identity,
    conclusion: oneOf(value.conclusion, [
      "success",
      "failure",
      "cancelled",
      "skipped",
      "in_progress",
    ]),
    authority: oneOf(value.authority, ["ordinary", "operator-protected"]),
  };
}

export function normalizeRequest(value) {
  const fields = ["candidateSha", "source", "results", "bindings"];
  const hasModes = Object.hasOwn(value ?? {}, "providerModes");
  object(value, hasModes ? [...fields, "providerModes"] : fields);
  text(value.candidateSha, SHA);
  array(value.results, 256);
  array(value.bindings, 32);
  const providerModes = hasModes
    ? value.providerModes
    : Object.fromEntries(PROVIDER_CHECK_IDS.map((id) => [id, "protected"]));
  object(providerModes, PROVIDER_CHECK_IDS);
  for (const id of PROVIDER_CHECK_IDS)
    oneOf(providerModes[id], ["protected", "model-free"]);
  return { ...value, providerModes: { ...providerModes } };
}

// Common CI-fixture predicates; native execution remains platform-owned.
export const FIXED_SUBJECT = "test(fixture): record owned edit";

export function validateCommitRequest(request) {
  requireValue(request && Object.getPrototypeOf(request) === Object.prototype);
  requireValue(
    Reflect.ownKeys(request).sort().join(",") === "operation,subject",
  );
  for (const key of ["operation", "subject"])
    requireValue(
      Object.getOwnPropertyDescriptor(request, key)?.enumerable &&
        Object.hasOwn(
          Object.getOwnPropertyDescriptor(request, key) ?? {},
          "value",
        ),
    );
  requireValue(
    request.operation === "commit" && request.subject === FIXED_SUBJECT,
  );
  return { operation: "commit", subject: FIXED_SUBJECT };
}

/** Snapshot values come from independent protected Git reads, never payload
 * claims. One new commit must change precisely the current branch and file. */
export function validateCommitEffect(before, after) {
  requireValue(
    before.branch === "refs/heads/proof" &&
      after.branch === before.branch &&
      before.head !== after.head &&
      after.parent === before.head &&
      after.message === `${FIXED_SUBJECT}\n` &&
      after.changed === "content.txt\n" &&
      after.content === "owned edit\n" &&
      after.status === "" &&
      after.author === before.identity &&
      after.committer === before.identity &&
      after.config === before.config &&
      after.identity === before.identity,
  );
  const expected = before.refs.map(([ref, sha]) => [
    ref,
    ref === before.branch ? after.head : sha,
  ]);
  requireValue(JSON.stringify(after.refs) === JSON.stringify(expected));
  return true;
}

export function validateCommitMetadata(before, after, objectIds) {
  requireValue(
    objectIds.length === 3 &&
      objectIds.every((sha) => /^[a-f0-9]{40}$/u.test(sha)),
  );
  const allowed = new Set([
    "index",
    "refs/heads/proof",
    "logs/HEAD",
    "logs/refs/heads/proof",
    "COMMIT_EDITMSG",
  ]);
  for (const sha of objectIds)
    allowed.add(`objects/${sha.slice(0, 2)}/${sha.slice(2)}`);
  const prior = new Map(before.map((entry) => [entry[0], entry]));
  for (const entry of after) {
    const changed =
      JSON.stringify(entry) !== JSON.stringify(prior.get(entry[0]));
    requireValue(
      !changed ||
        (allowed.has(entry[0]) &&
          (!entry[0].startsWith("objects/") || !prior.has(entry[0]))),
    );
  }
  for (const entry of before)
    requireValue(after.some(([file]) => file === entry[0]));
  return true;
}
