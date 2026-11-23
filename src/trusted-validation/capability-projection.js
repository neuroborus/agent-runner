import { normalizeOwnershipDiagnostic } from "../platform/index.js";
import { normalizeCapabilityMismatchDiagnostic } from "./requirements.js";

// Required-check IDs are the only public labels; commands are never published.
const CHECK_LABEL_PATTERN = /^C[1-9][0-9]{0,8}$/u;
const MAX_BINDINGS = 16;
const MAX_EVIDENCE_ITEMS = 32;
const MAX_ENVELOPE_LENGTH = 4_000;
const OWNERSHIP_PREFIX = "Ownership diagnostic: ";

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

// Saved bindings are untrusted history. An unsafe, missing, duplicated,
// ambiguous or unbound label is unknown; it never removes or changes a blocker.
// Rows for indexes outside the diagnostic are ignored. Required-check IDs are
// unique per inventory, so an ID saved for more than one published index is
// ambiguous for each of them, even when one of those indexes is also repeated.
function savedLabels(bindings, published) {
  const labels = new Map();
  const indexesById = new Map();
  try {
    if (!Array.isArray(bindings) || bindings.length > MAX_BINDINGS)
      return labels;
    for (let index = 0; index < bindings.length; index += 1) {
      const item = bindings[index];
      if (
        !isRecord(item) ||
        Reflect.ownKeys(item).length !== 2 ||
        !Object.hasOwn(item, "checkIndex") ||
        !Object.hasOwn(item, "label")
      )
        continue;
      const { checkIndex, label } = item;
      if (!published.has(checkIndex)) continue;
      const valid =
        typeof label === "string" && CHECK_LABEL_PATTERN.test(label);
      if (valid)
        indexesById.set(
          label,
          (indexesById.get(label) ?? new Set()).add(checkIndex),
        );
      labels.set(checkIndex, labels.has(checkIndex) || !valid ? null : label);
    }
  } catch {
    return new Map();
  }
  for (const [checkIndex, label] of labels)
    if (label !== null && indexesById.get(label).size > 1)
      labels.set(checkIndex, null);
  return labels;
}

// One public association per published blocker, keyed by its inventory index.
export function projectCapabilityChecks(diagnostic, bindings) {
  if (diagnostic === null) return Object.freeze([]);
  const { blockers } = normalizeCapabilityMismatchDiagnostic(diagnostic);
  const labels = savedLabels(
    bindings,
    new Set(blockers.map(({ checkIndex }) => checkIndex)),
  );
  return Object.freeze(
    blockers.map(({ checkIndex }) =>
      Object.freeze({ checkIndex, label: labels.get(checkIndex) ?? null }),
    ),
  );
}

// Only the existing structured envelope is accepted, revalidated by the
// platform. Any other saved evidence text is ignored.
export function projectCapabilityOwnership(evidence) {
  const diagnostics = [];
  try {
    if (!Array.isArray(evidence)) return Object.freeze(diagnostics);
    for (const entry of evidence) {
      if (diagnostics.length === MAX_EVIDENCE_ITEMS) break;
      if (
        typeof entry !== "string" ||
        entry.length > MAX_ENVELOPE_LENGTH ||
        !entry.startsWith(OWNERSHIP_PREFIX)
      )
        continue;
      try {
        const diagnostic = normalizeOwnershipDiagnostic(
          JSON.parse(entry.slice(OWNERSHIP_PREFIX.length)),
        );
        if (diagnostic !== null) diagnostics.push(diagnostic);
      } catch {
        // Invalid supplemental evidence is unavailable.
      }
    }
  } catch {
    return Object.freeze([]);
  }
  return Object.freeze(diagnostics);
}

function blockerLine(blocker, label) {
  const list = (values) => (values.length === 0 ? "none" : values.join(", "));
  return [
    `Check ${label ?? "unknown"} at inventory index ${blocker.checkIndex}: ${blocker.reason}`,
    `missing capabilities ${list(blocker.missingCapabilities)}`,
    `unmatched artifact digests ${list(blocker.unmatchedArtifactDigests)}`,
    `omitted artifact digests ${blocker.omittedArtifactDigests}`,
    `command identity mismatch ${blocker.commandIdentityMismatch ? "yes" : "no"}.`,
  ].join("; ");
}

// Public evidence for a required-check capability pause, including historical
// records. It reads only the typed diagnostic, saved labels and ownership
// envelopes; saved prose, command text and the inventory are never published.
export function projectCapabilityBlockerEvidence(pause) {
  let diagnostic = null;
  let bindings;
  let evidence;
  try {
    if (pause.capabilityDiagnostic !== undefined)
      diagnostic = normalizeCapabilityMismatchDiagnostic(
        pause.capabilityDiagnostic,
      );
    ({ capabilityChecks: bindings, evidence } = pause);
  } catch {
    diagnostic = null;
  }
  const lines = [];
  if (diagnostic === null) lines.push("Capability mismatch details: unknown.");
  else {
    const checks = projectCapabilityChecks(diagnostic, bindings);
    diagnostic.blockers.forEach((blocker, position) =>
      lines.push(blockerLine(blocker, checks[position].label)),
    );
    if (diagnostic.omittedBlockers > 0)
      lines.push(`Omitted capability blockers: ${diagnostic.omittedBlockers}.`);
  }
  lines.push(
    ...projectCapabilityOwnership(evidence)
      .slice(0, MAX_EVIDENCE_ITEMS - lines.length)
      .map((item) => `${OWNERSHIP_PREFIX}${JSON.stringify(item)}`),
  );
  return Object.freeze(lines);
}
