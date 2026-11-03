import { isRecord } from "../adapter-contract.js";
import {
  isObservationCount,
  normalizeProviderObservation,
} from "../observations.js";

const identifier = (value) =>
  typeof value === "string" &&
  value.length > 0 &&
  value.length <= 512 &&
  !/[\0\r\n]/u.test(value);
function snapshot(value) {
  const fields = [
    "inputTokens",
    "cachedInputTokens",
    "outputTokens",
    "reasoningOutputTokens",
    "totalTokens",
  ];
  if (
    !isRecord(value) ||
    fields.some((field) => !isObservationCount(value[field])) ||
    (Object.hasOwn(value, "cacheWriteInputTokens") &&
      !isObservationCount(value.cacheWriteInputTokens))
  )
    throw new TypeError("Codex usage is invalid.");
  return {
    ...Object.fromEntries(fields.map((field) => [field, value[field]])),
    cacheWriteInputTokens: value.cacheWriteInputTokens ?? null,
  };
}

export function createCodexObservations(onObservation, attempt, recovery) {
  if (onObservation === undefined) return undefined;
  const turns = [];
  let active;
  let sealed = false;

  function accept(entry, event) {
    if (event.usage) {
      if (
        turns.some(
          (candidate) =>
            candidate.threadId === entry.threadId &&
            candidate.value.cumulative !== null &&
            Object.keys(event.usage.cumulative).some((field) => {
              const previous = candidate.value.cumulative[field];
              const next = event.usage.cumulative[field];
              return (
                previous !== null &&
                next !== null &&
                (candidate.value.turn <= entry.value.turn
                  ? next < previous
                  : next > previous)
              );
            }),
        )
      )
        return;
      Object.assign(entry.value, event.usage);
      entry.terminalUsage = entry.value.outcome === "completed";
    } else if (event.outcome) {
      if (entry.value.outcome === "incomplete")
        entry.value.outcome = event.outcome;
    } else if (event.id && !entry.items.has(event.id)) {
      if (entry.items.size >= 16_384) {
        entry.value.factsIncomplete = true;
        return;
      }
      entry.items.add(event.id);
      if (event.counter === "compactions") {
        entry.observedCompactions += 1;
        entry.value.compactions = Math.max(
          entry.value.compactions,
          entry.observedCompactions,
        );
      } else entry.value[event.counter] += 1;
    }
  }

  function select(id) {
    if (!identifier(id) || turns.some((entry) => entry.id === id)) return;
    active.id = id;
    for (const event of active.pending)
      if (event.turnId === id) accept(active, event);
    active.pending = [];
  }

  function selectCompaction(threadId, turnId) {
    if (
      !sealed &&
      active?.threadId === threadId &&
      active.value.kind === "compaction" &&
      active.id === undefined
    )
      select(turnId);
  }

  return Object.freeze({
    selectCompaction,
    confirmCompaction(threadId, turnId) {
      if (
        sealed ||
        active?.threadId !== threadId ||
        active.value.kind !== "compaction"
      )
        return;
      // The validated completion, rather than a provisional start, owns this ID.
      selectCompaction(threadId, turnId);
      if (active.id === turnId && active.value.compactions === 0)
        active.value.compactions = 1;
    },
    begin(method, params) {
      if (sealed || !["turn/start", "thread/compact/start"].includes(method))
        return;
      if (turns.length >= 3 || !identifier(params.threadId)) return;
      active = {
        threadId: params.threadId,
        pending: [],
        items: new Set(),
        observedCompactions: 0,
        value: {
          attempt,
          turn: turns.length + 1,
          kind:
            method === "thread/compact/start"
              ? "compaction"
              : recovery || turns.length > 0
                ? "recovery"
                : "primary",
          outcome: "incomplete",
          accounting: "missing",
          last: null,
          cumulative: null,
          cumulativeScope: "thread",
          inputIncludesCached: true,
          outputIncludesReasoning: true,
          contextCapacity: null,
          commandCompletions: 0,
          compactions: 0,
          factsIncomplete: false,
        },
      };
      turns.push(active);
    },
    response(method, response) {
      if (!sealed && active && method === "turn/start")
        select(response?.turn?.id);
    },
    notification({ method, params }) {
      if (
        sealed ||
        !active ||
        !isRecord(params) ||
        !identifier(params.threadId)
      )
        return;
      const turnId = ["turn/started", "turn/completed"].includes(method)
        ? params.turn?.id
        : params.turnId;
      if (!identifier(turnId)) return;
      let event = { turnId };
      if (method === "thread/tokenUsage/updated") {
        const native = params.tokenUsage;
        try {
          const usage = normalizeProviderObservation({
            ...active.value,
            accounting: "incomplete",
            last: snapshot(native?.last),
            cumulative: snapshot(native?.total),
            contextCapacity: native?.modelContextWindow ?? null,
          });
          if (
            Object.keys(usage.last).some(
              (field) =>
                usage.last[field] !== null &&
                usage.cumulative[field] !== null &&
                usage.last[field] > usage.cumulative[field],
            )
          )
            return;
          event.usage = {
            last: usage.last,
            cumulative: usage.cumulative,
            contextCapacity: usage.contextCapacity,
          };
        } catch {
          return;
        }
      } else if (
        method === "turn/completed" &&
        ["completed", "failed", "interrupted"].includes(params.turn?.status) &&
        Array.isArray(params.turn.items)
      ) {
        event.outcome =
          params.turn.status === "completed" ? "completed" : "failed";
      } else if (method === "item/completed" && identifier(params.item?.id)) {
        const item = params.item;
        if (
          item.type === "commandExecution" &&
          typeof item.command === "string" &&
          ["completed", "failed", "declined"].includes(item.status)
        )
          event.counter = "commandCompletions";
        else if (item.type === "contextCompaction")
          event.counter = "compactions";
        else return;
        event.id = item.id;
      } else if (!(
        method === "turn/started" &&
        params.turn?.status === "inProgress" &&
        Array.isArray(params.turn.items)
      ))
        return;
      const entry = turns.find(
        (candidate) =>
          candidate.threadId === params.threadId && candidate.id === turnId,
      );
      if (entry) accept(entry, event);
      else if (active.threadId === params.threadId && active.id === undefined) {
        if (active.pending.length >= 1024) {
          active.value.factsIncomplete = true;
          return;
        }
        active.pending.push(event);
      }
    },
    seal() {
      if (sealed) return;
      sealed = true;
      for (const entry of turns) {
        const value = entry.value;
        value.accounting =
          value.last === null
            ? "missing"
            : entry.terminalUsage && value.outcome === "completed"
              ? "reported"
              : "incomplete";
        onObservation(normalizeProviderObservation(value));
      }
      turns.length = 0;
    },
  });
}
