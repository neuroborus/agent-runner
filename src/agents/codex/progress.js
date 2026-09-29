import { isRecord } from "../adapter-contract.js";
import { createTurnProgress } from "../turn-progress.js";

const TERMINAL = new Set(["completed", "failed", "declined"]);
const DELTAS = new Set([
  "item/agentMessage/delta",
  "item/plan/delta",
  "item/reasoning/textDelta",
  "item/reasoning/summaryTextDelta",
]);
const identifier = (value) =>
  typeof value === "string" && value.length > 0 && value.length <= 512;

function semanticItem(item) {
  switch (item.type) {
    case "agentMessage":
    case "plan":
      return typeof item.text === "string";
    case "reasoning":
      return (
        Array.isArray(item.summary) &&
        Array.isArray(item.content) &&
        [...item.summary, ...item.content].every(
          (value) => typeof value === "string",
        )
      );
    case "fileChange":
      return Array.isArray(item.changes);
    case "imageView":
      return typeof item.path === "string";
    case "contextCompaction":
      return true;
    default:
      return false;
  }
}

export function createCodexProgress(onProgress) {
  const progress = createTurnProgress(onProgress);
  let threadId;
  let turnId;
  let compacting = false;
  let ended = false;
  let pending = [];

  function accept(event) {
    if (ended || event.turnId !== turnId) return;
    if (event.kind === "start")
      progress.start(JSON.stringify([turnId, event.id]), event.command);
    else if (event.kind === "complete")
      progress.complete(JSON.stringify([turnId, event.id]), event.command);
    else progress.semantic();
    if (event.terminal) ended = true;
  }

  function select(id) {
    turnId = id;
    for (const event of pending) accept(event);
    pending = [];
  }

  return Object.freeze({
    begin(method, params) {
      if (!["turn/start", "thread/compact/start"].includes(method)) return;
      threadId = params.threadId;
      turnId = undefined;
      compacting = method === "thread/compact/start";
      ended = false;
      pending = [];
    },
    response(method, response) {
      if (method === "turn/start" && identifier(response?.turn?.id)) {
        select(response.turn.id);
      }
    },
    notification({ method, params }) {
      if (
        threadId === undefined ||
        !isRecord(params) ||
        params.threadId !== threadId ||
        ended
      )
        return;
      let event;
      if (method === "turn/started" || method === "turn/completed") {
        const turn = params.turn;
        const terminal = method === "turn/completed";
        if (
          !isRecord(turn) ||
          !identifier(turn.id) ||
          !Array.isArray(turn.items) ||
          !(terminal
            ? ["completed", "failed", "interrupted"].includes(turn.status)
            : turn.status === "inProgress")
        )
          return;
        event = { turnId: turn.id, terminal };
        if (compacting && turnId === undefined) select(turn.id);
      } else {
        if (
          !identifier(params.turnId) ||
          !identifier(params.itemId ?? params.item?.id)
        )
          return;
        event = { turnId: params.turnId };
        if (DELTAS.has(method)) {
          if (
            !identifier(params.itemId) ||
            typeof params.delta !== "string" ||
            params.delta.length === 0
          )
            return;
          for (const field of ["contentIndex", "summaryIndex"]) {
            if (
              params[field] !== undefined &&
              (!Number.isSafeInteger(params[field]) || params[field] < 0)
            )
              return;
          }
        } else if (method === "item/started" || method === "item/completed") {
          const item = params.item;
          if (!isRecord(item) || !identifier(item.id)) return;
          if (item.type === "commandExecution") {
            if (
              typeof item.command !== "string" ||
              (method === "item/started"
                ? item.status !== "inProgress"
                : !TERMINAL.has(item.status))
            )
              return;
            event.id = item.id;
            event.command = true;
            event.kind = method === "item/started" ? "start" : "complete";
          } else if (!semanticItem(item)) return;
          else if (["fileChange", "imageView"].includes(item.type)) {
            if (
              item.type === "fileChange" &&
              (method === "item/started"
                ? item.status !== "inProgress"
                : !TERMINAL.has(item.status))
            )
              return;
            event.id = item.id;
            event.command = false;
            event.kind = method === "item/started" ? "start" : "complete";
          }
        } else return;
      }
      if (turnId !== undefined) accept(event);
      else {
        // Notifications can precede the turn/start reply. Retain bounded,
        // payload-free facts until that reply establishes the exact turn.
        if (pending.length >= 1024)
          throw new RangeError("Codex progress exceeds its bound.");
        pending.push(event);
      }
    },
    retire() {
      progress.retire();
    },
  });
}
