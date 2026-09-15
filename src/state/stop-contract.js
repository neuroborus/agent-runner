export const STOP_TIMINGS = new Set(["immediate", "after-current-commit"]);
const SHA = /^[a-f0-9]{40}(?:[a-f0-9]{24})?$/u;
const record = (value) =>
  value !== null && typeof value === "object" && !Array.isArray(value);

export function validStopBoundary(value) {
  return (
    record(value) &&
    Object.keys(value).length === 4 &&
    value.capability === "verified-commit-v1" &&
    Number.isSafeInteger(value.step) &&
    value.step > 0 &&
    Number.isSafeInteger(value.completedCommits) &&
    value.completedCommits >= 0 &&
    typeof value.baselineHead === "string" &&
    SHA.test(value.baselineHead)
  );
}

export function validStopTiming(value) {
  return (
    STOP_TIMINGS.has(value.timing) &&
    STOP_TIMINGS.has(value.effectiveTiming) &&
    (value.timing !== "immediate" || value.effectiveTiming === "immediate") &&
    (value.effectiveTiming === "immediate"
      ? value.targetBoundary === null
      : validStopBoundary(value.targetBoundary))
  );
}

export function validStopSettlement(value) {
  return (
    record(value) &&
    Object.keys(value).length === 2 &&
    (value.kind === "quiescent"
      ? value.commit === null
      : value.kind === "commit" &&
        typeof value.commit === "string" &&
        SHA.test(value.commit))
  );
}
