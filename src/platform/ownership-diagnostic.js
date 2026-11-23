// Supplemental evidence only: this contract cannot establish process absence,
// an outcome, retirement, or permission to retry an effect.
const SITES = new Set([
  "launcher-setup",
  "registration",
  "parent-session-signal",
  "parent-completion-inspection",
  "parent-containment-relay",
  "parent-outcome-incomplete",
  "parent-outcome-active",
  "parent-invalid-observations",
  "parent-invalid-frame",
  "parent-missing-descendant-proof",
  "parent-missing-supervision",
  "parent-termination-deadline",
  "recovery-identity",
  "recovery-namespace",
  "recovery-inspection",
  "recovery-active",
  "state-custody",
  "state-registration",
  "state-process-active",
  "state-resource-custody",
  "trusted-resource-custody",
  "adapter-resource-custody",
]);
const BRANCHES = new Set([
  "finish-inspection-deadline",
  "finish-retirement-deadline",
  "terminate-signal",
  "terminate-check",
]);
const FIELDS = [
  "schemaVersion",
  "site",
  "branch",
  "phase",
  "startRequested",
  "terminationRequested",
  "ownershipHandedOff",
  "inspection",
];
const FLAG_FIELDS = [
  "startRequested",
  "terminationRequested",
  "ownershipHandedOff",
];
const SAMPLE_FIELDS = [
  "work",
  "elapsedMs",
  "maxWork",
  "maxElapsedMs",
  "maxAttempts",
];
const INSPECTION_SITES = new Set([
  "parent-session-signal",
  "parent-completion-inspection",
  "parent-containment-relay",
  "parent-outcome-incomplete",
  "parent-outcome-active",
  "recovery-inspection",
  "recovery-active",
]);

function exact(value, fields) {
  return (
    value !== null &&
    typeof value === "object" &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value)) &&
    Reflect.ownKeys(value).length === fields.length &&
    fields.every((field) => Object.hasOwn(value, field))
  );
}

function invalid() {
  throw new TypeError("Ownership diagnostic is invalid.");
}

export function normalizeOwnershipDiagnostic(value) {
  if (value === null) return null;
  if (
    !exact(value, FIELDS) ||
    value.schemaVersion !== 1 ||
    !SITES.has(value.site) ||
    (value.site === "parent-containment-relay"
      ? !BRANCHES.has(value.branch)
      : value.branch !== null) ||
    ![null, "session-inspection"].includes(value.phase) ||
    FLAG_FIELDS.some(
      (field) => value[field] !== null && typeof value[field] !== "boolean",
    ) ||
    (!value.site.startsWith("parent-") &&
      value.site !== "registration" &&
      FLAG_FIELDS.some((field) => value[field] !== null))
  )
    invalid();
  const sample = value.inspection;
  if (sample === null) {
    if (value.phase !== null) invalid();
  } else if (
    value.phase !== "session-inspection" ||
    !INSPECTION_SITES.has(value.site) ||
    !exact(sample, SAMPLE_FIELDS) ||
    SAMPLE_FIELDS.some(
      (field) =>
        sample[field] !== null &&
        (!Number.isFinite(sample[field]) ||
          sample[field] < 0 ||
          sample[field] > Number.MAX_SAFE_INTEGER),
    ) ||
    (sample.work !== null && !Number.isSafeInteger(sample.work)) ||
    (sample.maxWork !== null &&
      (!Number.isSafeInteger(sample.maxWork) ||
        sample.maxWork < 1 ||
        sample.maxWork > 65_536)) ||
    (sample.maxElapsedMs !== null &&
      (sample.maxElapsedMs <= 0 || sample.maxElapsedMs > 250)) ||
    sample.maxAttempts !== 3
  )
    invalid();
  return Object.freeze({
    ...value,
    inspection: sample === null ? null : Object.freeze({ ...sample }),
  });
}

export function createOwnershipDiagnostic(
  site,
  {
    branch = null,
    startRequested = null,
    terminationRequested = null,
    ownershipHandedOff = null,
    inspection = null,
  } = {},
) {
  return normalizeOwnershipDiagnostic({
    schemaVersion: 1,
    site,
    branch,
    phase: inspection === null ? null : "session-inspection",
    startRequested,
    terminationRequested,
    ownershipHandedOff,
    inspection,
  });
}

// Errors and native frames are untrusted inputs. Invalid supplemental evidence
// is unavailable, never a replacement for the original refusal.
export function ownershipDiagnosticFrom(error) {
  try {
    return normalizeOwnershipDiagnostic(error?.ownershipDiagnostic ?? null);
  } catch {
    return null;
  }
}
