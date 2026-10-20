import { isRecord } from "../adapter-contract.js";
import { normalizeProviderObservation } from "../observations.js";

export function createClaudeObservations(onObservation, attempt, recovery) {
  if (onObservation === undefined) return undefined;
  const completed = new Set();
  const compactions = new Set();
  const value = {
    attempt,
    turn: 1,
    kind: recovery ? "recovery" : "primary",
    outcome: "incomplete",
    accounting: "missing",
    last: null,
    cumulative: null,
    cumulativeScope: "attempt",
    inputIncludesCached: false,
    outputIncludesReasoning: null,
    contextCapacity: null,
    commandCompletions: 0,
    compactions: 0,
    factsIncomplete: false,
  };
  let sealed = false;
  return Object.freeze({
    incompleteFacts() {
      if (!sealed) value.factsIncomplete = true;
    },
    command(id) {
      if (sealed || completed.has(id)) return;
      if (completed.size >= 16_384) {
        value.factsIncomplete = true;
        return;
      }
      completed.add(id);
      value.commandCompletions += 1;
    },
    compact(id) {
      if (sealed || compactions.has(id)) return;
      if (compactions.size >= 16_384) {
        value.factsIncomplete = true;
        return;
      }
      compactions.add(id);
      value.compactions += 1;
    },
    result(payload) {
      if (sealed) return;
      value.outcome = payload.is_error ? "failed" : "completed";
      const usage = payload.usage;
      if (!isRecord(usage)) return;
      try {
        const models = payload.modelUsage ?? payload.model_usage;
        const model =
          isRecord(models) && Object.keys(models).length === 1
            ? Object.values(models)[0]
            : null;
        const normalized = normalizeProviderObservation({
          ...value,
          contextCapacity: model?.contextWindow ?? null,
          accounting: payload.is_error ? "incomplete" : "reported",
          cumulative: {
            inputTokens: usage.input_tokens ?? null,
            cachedInputTokens: usage.cache_read_input_tokens ?? null,
            cacheWriteInputTokens: usage.cache_creation_input_tokens ?? null,
            outputTokens: usage.output_tokens ?? null,
            reasoningOutputTokens: null,
            totalTokens: null,
          },
        });
        if (
          Object.values(normalized.cumulative).every((count) => count === null)
        )
          return;
        Object.assign(value, normalized);
      } catch {
        /* Invalid optional accounting cannot replace a provider failure. */
      }
    },
    seal(valid) {
      if (sealed) return;
      sealed = true;
      if (!valid && value.outcome !== "failed") {
        value.outcome = "incomplete";
        if (value.accounting === "reported") value.accounting = "incomplete";
      }
      onObservation(normalizeProviderObservation(value));
      completed.clear();
      compactions.clear();
    },
  });
}
