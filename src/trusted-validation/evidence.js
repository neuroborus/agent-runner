import { isRepositoryCheck, normalizeTestInventory } from "./test-inventory.js";
import {
  isFailureDiagnostic,
  normalizeFailureDiagnostics,
} from "./diagnostics.js";

const TIMING_PREFIX = "Runner-trusted check elapsed: ";
const FILE_PREFIX = "Trusted check failed test file: ";
const MAX_ELAPSED_MS = 2_147_483_647;

export function elapsedEvidence(start, end) {
  const elapsed = Math.round(end - start);
  if (
    ![start, end].every(Number.isFinite) ||
    end < start ||
    !Number.isSafeInteger(elapsed) ||
    elapsed < 0 ||
    elapsed > MAX_ELAPSED_MS
  ) {
    throw new TypeError("Invalid runner monotonic elapsed time.");
  }
  return `${TIMING_PREFIX}${elapsed} ms.`;
}

export function hasObservedEvidence(check) {
  return (
    Object.hasOwn(check, "diagnosticInventory") ||
    check.evidence?.some(
      (entry) =>
        typeof entry === "string" &&
        (entry.startsWith(TIMING_PREFIX.trimEnd()) ||
          entry.startsWith(FILE_PREFIX.trimEnd())),
    )
  );
}

export function normalizeTimingEvidence(evidence) {
  const timings = evidence.filter(
    (entry) =>
      typeof entry === "string" && entry.startsWith(TIMING_PREFIX.trimEnd()),
  );
  if (
    timings.length > 1 ||
    timings.some((entry) => {
      const matched =
        /^Runner-trusted check elapsed: (0|[1-9][0-9]{0,9}) ms\.$/u.exec(entry);
      return matched === null || Number(matched[1]) > MAX_ELAPSED_MS;
    })
  )
    throw new TypeError("Invalid normalized runner timing.");
  return timings;
}

// This capability owns both normalized spelling and Runner provenance. Timing
// lives in existing evidence arrays and therefore requires no timing migration.
export function normalizeObservedEvidence(check, command, contentFingerprint) {
  if (!Array.isArray(check.evidence))
    throw new TypeError("Invalid trusted evidence.");
  const inventory = Object.hasOwn(check, "diagnosticInventory")
    ? normalizeTestInventory(check.diagnosticInventory, {
        commandIdentity: command?.identity,
        contentFingerprint,
      })
    : null;
  const observed = hasObservedEvidence(check);
  if (
    observed &&
    (check.executor !== "runner" ||
      command?.identity !== check.commandIdentity ||
      command.command !== check.command ||
      !["PASS", "FAIL"].includes(check.status) ||
      check.timedOut !== false ||
      (check.exitCode !== null && !Number.isSafeInteger(check.exitCode)) ||
      (check.signal !== null &&
        (typeof check.signal !== "string" || check.signal.length > 32)) ||
      (check.status === "PASS"
        ? check.exitCode !== 0 || check.signal !== null
        : check.exitCode === 0 ||
          (check.exitCode === null && check.signal === null)))
  ) {
    throw new TypeError("Invalid trusted evidence provenance.");
  }
  if (
    inventory !== null &&
    (!isRepositoryCheck(command) || check.status !== "FAIL")
  ) {
    throw new TypeError("Invalid trusted test inventory provenance.");
  }
  const timings = normalizeTimingEvidence(check.evidence);
  const files = check.evidence.filter(
    (entry) =>
      typeof entry === "string" && entry.startsWith(FILE_PREFIX.trimEnd()),
  );
  if (files.length > 0 && inventory === null)
    throw new TypeError("Missing trusted test inventory.");
  if (inventory !== null && files.length === 0)
    throw new TypeError("Unused trusted test inventory.");
  if (files.some((entry) => !isFailureDiagnostic(entry, inventory)))
    throw new TypeError("Invalid trusted test identity.");
  const diagnostics = normalizeFailureDiagnostics(
    check.evidence.filter((entry) => isFailureDiagnostic(entry, inventory)),
    inventory,
  );
  if (check.status === "PASS" && diagnostics.length > 0)
    throw new TypeError("Successful checks cannot retain diagnostics.");
  return Object.freeze([...diagnostics, ...timings]);
}
