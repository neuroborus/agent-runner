import { normalizeArtifacts } from "./artifact-contract.js";
import { TrustedValidationError } from "./errors.js";

// Two active role inventories, including their separate blocker reports.
const INVENTORY_LIMIT = 512;
const REQUIREMENT_LIMIT = 1024;
const FIELDS = new Set([
  "command",
  "commandIdentity",
  "capabilities",
  "unsupported",
]);

function invalid() {
  throw new TrustedValidationError(
    "Exact-command capability requirements are invalid.",
    {
      code: "ERR_INVALID_TRUSTED_REQUIREMENTS",
    },
  );
}

function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function commandText(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 4_000 &&
    value.trim() === value &&
    !/[\p{Cc}\p{Zl}\p{Zp}]/u.test(value)
  );
}

// Pipeline schemas own reporting. This boundary accepts only bounded needs,
// never executable vectors, authority grants, host paths, or environment values.
export function normalizeRequirementRequest({ inventory, requirements }) {
  if (
    !Array.isArray(inventory) ||
    inventory.length > INVENTORY_LIMIT ||
    inventory.some((value) => !commandText(value)) ||
    new Set(inventory).size !== inventory.length ||
    !Array.isArray(requirements) ||
    requirements.length > REQUIREMENT_LIMIT
  )
    invalid();
  const normalized = requirements.map((value) => {
    if (
      !record(value) ||
      Object.keys(value).some((key) => !FIELDS.has(key)) ||
      !inventory.includes(value.command)
    )
      invalid();
    const commandIdentity = value.commandIdentity ?? null;
    if (
      commandIdentity !== null &&
      (typeof commandIdentity !== "string" ||
        !/^[a-f0-9]{64}$/u.test(commandIdentity))
    )
      invalid();
    const needs = Object.hasOwn(value, "capabilities")
      ? value.capabilities
      : {};
    if (
      !record(needs) ||
      Object.keys(needs).some(
        (key) =>
          !["scratch", "cache", "artifacts", "sourceProjection"].includes(key),
      )
    )
      invalid();
    const capabilities = {};
    for (const name of ["scratch", "cache"]) {
      if (!Object.hasOwn(needs, name)) continue;
      if (needs[name] !== true) invalid();
      capabilities[name] = true;
    }
    if (Object.hasOwn(needs, "sourceProjection")) {
      if (needs.sourceProjection !== true) invalid();
      capabilities.sourceProjection = true;
    }
    if (Object.hasOwn(needs, "artifacts")) {
      capabilities.artifacts = normalizeArtifacts(needs.artifacts);
      if (capabilities.artifacts === null) invalid();
    }
    const unsupported = Object.hasOwn(value, "unsupported")
      ? value.unsupported
      : [];
    if (
      !Array.isArray(unsupported) ||
      unsupported.length > 16 ||
      unsupported.some(
        (item) =>
          typeof item !== "string" || !/^[a-z][a-z0-9-]{0,63}$/u.test(item),
      ) ||
      new Set(unsupported).size !== unsupported.length
    )
      invalid();
    return Object.freeze({
      command: value.command,
      commandIdentity,
      capabilities: Object.freeze(capabilities),
      unsupported: Object.freeze([...unsupported]),
    });
  });
  return Object.freeze({
    inventory: Object.freeze([...inventory]),
    requirements: Object.freeze(normalized),
  });
}

const CAPABILITY_ORDER = Object.freeze([
  "scratch",
  "cache",
  "sourceProjection",
]);
const DIAGNOSTIC_REASONS = new Set([
  "not-selected",
  "unsupported",
  "insufficient-authority",
]);
const DIAGNOSTIC_FIELDS = ["schemaVersion", "blockers", "omittedBlockers"];
const DIAGNOSTIC_BLOCKER_FIELDS = [
  "checkIndex",
  "reason",
  "missingCapabilities",
  "unmatchedArtifactDigests",
  "commandIdentityMismatch",
  "omittedArtifactDigests",
];
const DIAGNOSTIC_BLOCKER_LIMIT = 16;
const DIAGNOSTIC_DIGEST_LIMIT = 32;
// Every report may name at most 32 artifacts.
const OMITTED_DIGEST_LIMIT =
  REQUIREMENT_LIMIT * DIAGNOSTIC_DIGEST_LIMIT - DIAGNOSTIC_DIGEST_LIMIT;

function invalidDiagnostic() {
  throw new TrustedValidationError(
    "The capability mismatch diagnostic is invalid.",
    { code: "ERR_INVALID_CAPABILITY_DIAGNOSTIC" },
  );
}

// Read each closed field once so validation and output see the same values.
function closedRecord(value, fields) {
  if (!record(value)) invalidDiagnostic();
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== fields.length ||
    fields.some((field) => !keys.includes(field))
  )
    invalidDiagnostic();
  return Object.fromEntries(fields.map((field) => [field, value[field]]));
}

// Copy a bounded array by index, rejecting holes and ignoring custom iterators.
function denseArray(value, maximum) {
  if (!Array.isArray(value)) invalidDiagnostic();
  const { length } = value;
  if (length > maximum) invalidDiagnostic();
  const items = [];
  for (let index = 0; index < length; index += 1) {
    if (!Object.hasOwn(value, index)) invalidDiagnostic();
    items.push(value[index]);
  }
  return items;
}

function count(value, maximum) {
  return Number.isSafeInteger(value) && value >= 0 && value <= maximum;
}

// Public, closed version 1 of the comparison-owned diagnostic. Detail fields
// carry only normalized requirement evidence, never URLs, vectors or text.
export function normalizeCapabilityMismatchDiagnostic(value) {
  const diagnostic = closedRecord(value, DIAGNOSTIC_FIELDS);
  const entries = denseArray(diagnostic.blockers, DIAGNOSTIC_BLOCKER_LIMIT);
  const { omittedBlockers } = diagnostic;
  if (
    diagnostic.schemaVersion !== 1 ||
    entries.length === 0 ||
    !count(omittedBlockers, INVENTORY_LIMIT - DIAGNOSTIC_BLOCKER_LIMIT) ||
    (omittedBlockers > 0 && entries.length !== DIAGNOSTIC_BLOCKER_LIMIT)
  )
    invalidDiagnostic();
  let previous = -1;
  // Every blocker needs its own reports; each names one command and at most
  // 32 artifacts, so the shared report limit bounds the published evidence.
  let reports = omittedBlockers;
  const blockers = entries.map((entry) => {
    const blocker = closedRecord(entry, DIAGNOSTIC_BLOCKER_FIELDS);
    const missingCapabilities = denseArray(
      blocker.missingCapabilities,
      CAPABILITY_ORDER.length,
    );
    const unmatchedArtifactDigests = denseArray(
      blocker.unmatchedArtifactDigests,
      DIAGNOSTIC_DIGEST_LIMIT,
    );
    const {
      checkIndex,
      reason,
      commandIdentityMismatch,
      omittedArtifactDigests,
    } = blocker;
    if (
      !count(checkIndex, INVENTORY_LIMIT - 1) ||
      checkIndex <= previous ||
      !DIAGNOSTIC_REASONS.has(reason) ||
      typeof commandIdentityMismatch !== "boolean" ||
      !count(omittedArtifactDigests, OMITTED_DIGEST_LIMIT) ||
      (omittedArtifactDigests > 0 &&
        unmatchedArtifactDigests.length !== DIAGNOSTIC_DIGEST_LIMIT)
    )
      invalidDiagnostic();
    previous = checkIndex;
    const order = missingCapabilities.map((name) =>
      CAPABILITY_ORDER.indexOf(name),
    );
    if (
      order.some(
        (position, index) =>
          position < 0 || (index > 0 && position <= order[index - 1]),
      ) ||
      unmatchedArtifactDigests.some(
        (digest, index, digests) =>
          typeof digest !== "string" ||
          !/^[a-f0-9]{64}$/u.test(digest) ||
          (index > 0 && digest <= digests[index - 1]),
      )
    )
      invalidDiagnostic();
    const concrete =
      missingCapabilities.length > 0 ||
      unmatchedArtifactDigests.length > 0 ||
      commandIdentityMismatch;
    if (concrete !== (reason === "insufficient-authority")) invalidDiagnostic();
    reports += Math.max(
      1,
      Math.ceil(
        (unmatchedArtifactDigests.length + omittedArtifactDigests) /
          DIAGNOSTIC_DIGEST_LIMIT,
      ),
    );
    return Object.freeze({
      checkIndex,
      reason,
      missingCapabilities: Object.freeze(missingCapabilities),
      unmatchedArtifactDigests: Object.freeze(unmatchedArtifactDigests),
      commandIdentityMismatch,
      omittedArtifactDigests,
    });
  });
  if (
    previous + omittedBlockers >= INVENTORY_LIMIT ||
    reports > REQUIREMENT_LIMIT
  )
    invalidDiagnostic();
  return Object.freeze({
    schemaVersion: 1,
    blockers: Object.freeze(blockers),
    omittedBlockers,
  });
}

// Additive union of every report's unmet needs; null when authority suffices.
function authorityMismatch(reports, selected) {
  const authority = selected?.capabilities ?? {};
  const allowed = authority.artifacts ?? [];
  const missingCapabilities = CAPABILITY_ORDER.filter(
    (name) =>
      authority[name] !== true &&
      reports.some((item) => item.capabilities[name] === true),
  );
  const unmatched = new Set();
  for (const item of reports)
    for (const artifact of item.capabilities.artifacts ?? [])
      if (
        !allowed.some(
          ({ url, sha256 }) =>
            artifact.url === url && artifact.sha256 === sha256,
        )
      )
        unmatched.add(artifact.sha256);
  const commandIdentityMismatch = reports.some(
    (item) =>
      item.commandIdentity !== null &&
      item.commandIdentity !== selected?.identity,
  );
  if (
    missingCapabilities.length === 0 &&
    unmatched.size === 0 &&
    !commandIdentityMismatch
  )
    return null;
  const digests = [...unmatched].sort();
  return {
    missingCapabilities,
    unmatchedArtifactDigests: digests.slice(0, DIAGNOSTIC_DIGEST_LIMIT),
    commandIdentityMismatch,
    omittedArtifactDigests: Math.max(
      0,
      digests.length - DIAGNOSTIC_DIGEST_LIMIT,
    ),
  };
}

const NO_MISMATCH = Object.freeze({
  missingCapabilities: [],
  unmatchedArtifactDigests: [],
  commandIdentityMismatch: false,
  omittedArtifactDigests: 0,
});

export function compareRequirements(request, snapshot) {
  const blockers = [];
  const details = [];
  request.inventory.forEach((command, checkIndex) => {
    const selected = snapshot.commands.find((item) => item.command === command);
    const reports = request.requirements.filter(
      (item) => item.command === command,
    );
    let reason;
    let mismatch = null;
    if (!selected && reports.length > 0) reason = "not-selected";
    else if (reports.some((item) => item.unsupported.length > 0))
      reason = "unsupported";
    else {
      mismatch = authorityMismatch(reports, selected);
      if (mismatch !== null) reason = "insufficient-authority";
    }
    if (!reason) return;
    blockers.push(
      Object.freeze({
        command,
        commandIdentity: selected?.identity ?? null,
        reason,
        evidence: Object.freeze([
          "The reported needs cannot be satisfied by the frozen runner authority.",
        ]),
      }),
    );
    details.push({ checkIndex, reason, ...(mismatch ?? NO_MISMATCH) });
  });
  return {
    blockers,
    diagnostic:
      details.length === 0
        ? null
        : normalizeCapabilityMismatchDiagnostic({
            schemaVersion: 1,
            blockers: details.slice(0, DIAGNOSTIC_BLOCKER_LIMIT),
            omittedBlockers: Math.max(
              0,
              details.length - DIAGNOSTIC_BLOCKER_LIMIT,
            ),
          }),
  };
}
