import { isRecord } from "./adapter-contract.js";

const TOKEN_FIELDS = Object.freeze([
  "inputTokens",
  "cachedInputTokens",
  "cacheWriteInputTokens",
  "outputTokens",
  "reasoningOutputTokens",
  "totalTokens",
]);
const FIELDS = Object.freeze([
  "attempt",
  "turn",
  "kind",
  "outcome",
  "accounting",
  "last",
  "cumulative",
  "cumulativeScope",
  "inputIncludesCached",
  "outputIncludesReasoning",
  "contextCapacity",
  "commandCompletions",
  "compactions",
  "factsIncomplete",
]);
export const isObservationCount = (value) =>
  Number.isSafeInteger(value) && value >= 0;

function exact(value, fields) {
  return (
    isRecord(value) &&
    Object.keys(value).length === fields.length &&
    fields.every((field) => Object.hasOwn(value, field))
  );
}

// Unknown counters remain null; native snapshots are never added together.
function normalizeUsageSnapshot(value) {
  if (
    !exact(value, TOKEN_FIELDS) ||
    TOKEN_FIELDS.some(
      (field) => value[field] !== null && !isObservationCount(value[field]),
    )
  ) {
    throw new TypeError("Provider usage snapshot is invalid.");
  }
  return Object.freeze({ ...value });
}

export function normalizeProviderObservation(value) {
  if (
    !exact(value, FIELDS) ||
    !isObservationCount(value.attempt) ||
    value.attempt < 1 ||
    value.attempt > 3 ||
    !isObservationCount(value.turn) ||
    value.turn < 1 ||
    value.turn > 3 ||
    !["primary", "recovery", "compaction"].includes(value.kind) ||
    !["completed", "failed", "incomplete"].includes(value.outcome) ||
    !["missing", "incomplete", "reported"].includes(value.accounting) ||
    !["thread", "attempt"].includes(value.cumulativeScope) ||
    typeof value.factsIncomplete !== "boolean" ||
    typeof value.inputIncludesCached !== "boolean" ||
    ![true, false, null].includes(value.outputIncludesReasoning) ||
    (value.contextCapacity !== null &&
      !isObservationCount(value.contextCapacity)) ||
    !isObservationCount(value.commandCompletions) ||
    value.commandCompletions > 16_384 ||
    !isObservationCount(value.compactions) ||
    value.compactions > 16_384 ||
    (value.accounting === "missing") !==
      (value.last === null && value.cumulative === null) ||
    (value.accounting === "reported" && value.outcome !== "completed")
  ) {
    throw new TypeError("Provider observation is invalid.");
  }
  const normalized = { ...value };
  for (const field of ["last", "cumulative"]) {
    normalized[field] =
      value[field] === null ? null : normalizeUsageSnapshot(value[field]);
    const usage = normalized[field];
    if (
      usage &&
      ((value.inputIncludesCached &&
        usage.inputTokens !== null &&
        usage.cachedInputTokens !== null &&
        usage.cachedInputTokens > usage.inputTokens) ||
        (value.outputIncludesReasoning === true &&
          usage.outputTokens !== null &&
          usage.reasoningOutputTokens !== null &&
          usage.reasoningOutputTokens > usage.outputTokens))
    ) {
      throw new TypeError("Provider observation subsets are invalid.");
    }
  }
  return Object.freeze(normalized);
}
