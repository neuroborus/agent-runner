import { closed, digest, requireWindows } from "./protocol.js";

const HASH = /^[a-f0-9]{64}$/u;
const NONCE = /^[a-f0-9]{32}$/u;
const ID = /^[a-f0-9]{16}:[a-f0-9]{32}$/u;
const STATE = ["base", "root", "allocation", "leaf", "temporary", "alias"];
const TYPES = [
  "allocate",
  "recover",
  "publish",
  "replace",
  "inspect",
  "cleanup",
  "finish",
];
const PHASES = [
  "ready",
  "allocated",
  "recovered",
  "prepared",
  "linked",
  "published",
  "complete",
  "exists",
  "inspected",
  "removing",
  "removed",
  "finished",
];

export function normalizeWindowsFileIdentity(value) {
  requireWindows(
    typeof value === "string" &&
      ID.test(value) &&
      value.slice(0, 16) !== "0".repeat(16) &&
      value.slice(17) !== "0".repeat(32),
  );
  return value;
}
const volume = (value) => value.slice(0, 16);
const identity = (value) =>
  value === null ? null : normalizeWindowsFileIdentity(value);
export function normalizeWindowsFileState(value) {
  closed(value, STATE);
  const state = Object.fromEntries(
    STATE.slice(0, -1).map((key) => [key, identity(value[key])]),
  );
  requireWindows(
    state.base &&
      state.root &&
      state.base !== state.root &&
      typeof value.alias === "boolean" &&
      Object.values(state).every(
        (id) => id === null || volume(id) === volume(state.root),
      ) &&
      (state.allocation !== null ||
        (state.leaf === null && state.temporary === null)) &&
      (!value.alias ||
        (state.leaf !== null && state.leaf === state.temporary)) &&
      (value.alias || state.leaf === null || state.leaf !== state.temporary),
  );
  const distinct = Object.values(state).filter((id) => id !== null);
  requireWindows(
    new Set(distinct).size === distinct.length - (value.alias ? 1 : 0),
  );
  return { ...state, alias: value.alias };
}
function request(value) {
  closed(value, ["type", "allocation", "leaf", "temporary", "bytes"]);
  requireWindows(
    TYPES.includes(value.type) &&
      typeof value.bytes === "string" &&
      /^(?:[a-f0-9]{2}){0,4096}$/u.test(value.bytes) &&
      (["publish", "replace"].includes(value.type) || value.bytes === ""),
  );
  const result = {
    type: value.type,
    allocation: identity(value.allocation),
    leaf: identity(value.leaf),
    temporary: identity(value.temporary),
    bytes: value.bytes,
  };
  requireWindows(
    value.type !== "allocate" ||
      [result.allocation, result.leaf, result.temporary].every(
        (id) => id === null,
      ),
  );
  requireWindows(
    !["publish", "replace", "recover", "inspect"].includes(result.type) ||
      result.allocation !== null,
  );
  requireWindows(
    !["publish", "replace"].includes(result.type) || result.temporary === null,
  );
  requireWindows(result.type !== "replace" || result.leaf !== null);
  return result;
}
export function encodeWindowsFileRequest(value) {
  const normalized = request(value);
  return (
    [
      normalized.type,
      normalized.allocation ?? "-",
      normalized.leaf ?? "-",
      normalized.temporary ?? "-",
      normalized.bytes || "-",
    ].join(" ") + "\n"
  );
}
export function normalizeWindowsFileMessage(value, nonce) {
  closed(value, ["nonce", "phase", ...STATE]);
  requireWindows(
    typeof nonce === "string" &&
      NONCE.test(nonce) &&
      value.nonce === nonce &&
      PHASES.includes(value.phase),
  );
  const state = normalizeWindowsFileState(
    Object.fromEntries(STATE.map((key) => [key, value[key]])),
  );
  requireWindows(value.phase !== "linked" || state.alias);
  requireWindows(
    ![
      "ready",
      "allocated",
      "prepared",
      "published",
      "complete",
      "exists",
      "inspected",
      "removed",
    ].includes(value.phase) || !state.alias,
  );
  return { nonce, phase: value.phase, ...state };
}
const same = (left, right) => STATE.every((key) => left[key] === right[key]);
const stateOf = (value) =>
  Object.fromEntries(STATE.map((key) => [key, value[key]]));

/** Replies are diagnostic until a protected independent reader joins the held
 * identities and bytes. Every continuation follows a persisted fault barrier. */
export async function runWindowsFileTransaction(input, effects) {
  let state,
    observation,
    interrupted = false;
  try {
    const operation = request(input),
      nonce = effects.nonce;
    state = normalizeWindowsFileState(effects.state);
    requireWindows(
      typeof nonce === "string" &&
        NONCE.test(nonce) &&
        ["send", "receive", "persist", "verify", "barrier"].every(
          (key) => typeof effects[key] === "function",
        ),
    );
    const allocationEmpty =
      state.allocation === null &&
      state.leaf === null &&
      state.temporary === null;
    requireWindows(
      ["allocate", "recover"].includes(operation.type)
        ? allocationEmpty
        : operation.allocation === state.allocation &&
            operation.leaf === state.leaf &&
            operation.temporary === state.temporary,
    );
    const authorizeCleanup = async () => {
      requireWindows(typeof effects.authorizeCleanup === "function");
      const permission = await effects.authorizeCleanup(structuredClone(state));
      requireWindows(
        permission.independent === true &&
          permission.retired === true &&
          permission.stateSha256 === digest(JSON.stringify(state)) &&
          hashReceipt(permission.receiptSha256),
      );
      await effects.persist(
        "authorization",
        structuredClone({
          operation,
          message: null,
          state,
          observation,
          authorization: {
            stateSha256: permission.stateSha256,
            receiptSha256: permission.receiptSha256,
          },
        }),
      );
    };
    if (operation.type === "cleanup") await authorizeCleanup();
    const receive = async () => {
      const message = normalizeWindowsFileMessage(
        await effects.receive(),
        nonce,
      );
      requireWindows(
        message.root === state.root && message.base === state.base,
      );
      return message;
    };
    const persist = (kind, message) =>
      effects.persist(
        kind,
        structuredClone({ operation, message, state, observation }),
      );
    const verified = async (message) => {
      const evidence = await effects.verify(
        structuredClone(message),
        structuredClone(operation),
      );
      requireWindows(
        evidence.independent === true &&
          evidence.stateSha256 === digest(JSON.stringify(stateOf(message))) &&
          typeof evidence.receiptSha256 === "string" &&
          HASH.test(evidence.receiptSha256),
      );
      for (const key of ["leaf", "temporary"])
        requireWindows(
          message[key] === null || hashReceipt(evidence[key + "Sha256"]),
        );
      if (["publish", "replace"].includes(operation.type)) {
        const expected = digest(Buffer.from(operation.bytes, "hex"));
        if (["prepared", "linked"].includes(message.phase))
          requireWindows(evidence.temporarySha256 === expected);
        if (["linked", "published", "complete"].includes(message.phase))
          requireWindows(evidence.leafSha256 === expected);
      }
      observation = {
        stateSha256: evidence.stateSha256,
        receiptSha256: evidence.receiptSha256,
        leafSha256: message.leaf === null ? null : evidence.leafSha256,
        temporarySha256:
          message.temporary === null ? null : evidence.temporarySha256,
      };
    };
    const park = async (message) => {
      await verified(message);
      state = stateOf(message);
      await persist("barrier", message);
      const decision = await effects.barrier(structuredClone(message));
      requireWindows(["continue", "interrupt"].includes(decision));
      if (decision === "interrupt") {
        await persist("interruption", message);
        interrupted = true;
        throw new Error("Declared file interruption");
      }
      if (message.phase === "removing") await authorizeCleanup();
      await effects.send("continue - - - -\n");
    };
    await persist("intent", null);
    await effects.send(encodeWindowsFileRequest(operation));
    let message = await receive();
    if (["publish", "replace"].includes(operation.type)) {
      requireWindows(
        message.phase === "prepared" &&
          message.allocation === state.allocation &&
          message.leaf === state.leaf &&
          message.temporary !== null &&
          !message.alias,
      );
      const prepared = message;
      await park(message);
      message = await receive();
      if (message.phase === "exists") {
        requireWindows(
          operation.type === "publish" &&
            operation.leaf !== null &&
            message.leaf === operation.leaf &&
            message.allocation === state.allocation &&
            message.temporary === null,
        );
      } else {
        requireWindows(operation.type !== "publish" || operation.leaf === null);
        if (operation.type === "publish") {
          requireWindows(
            message.phase === "linked" &&
              message.allocation === state.allocation &&
              message.leaf === prepared.temporary &&
              message.temporary === prepared.temporary &&
              message.alias,
          );
          await park(message);
          message = await receive();
        }
        requireWindows(
          message.phase === "published" &&
            message.allocation === state.allocation &&
            message.leaf === prepared.temporary &&
            message.temporary === null &&
            !message.alias,
        );
        await park(message);
        message = await receive();
        requireWindows(message.phase === "complete" && same(message, state));
      }
    } else if (operation.type === "allocate") {
      requireWindows(
        message.phase === "allocated" &&
          message.allocation !== null &&
          message.leaf === null &&
          message.temporary === null,
      );
    } else if (operation.type === "recover") {
      requireWindows(
        message.phase === "recovered" &&
          (message.allocation === operation.allocation ||
            (effects.recoveryOperation === "cleanup" &&
              message.allocation === null)) &&
          [null, operation.leaf, operation.temporary].includes(message.leaf) &&
          [null, operation.temporary].includes(message.temporary),
      );
      const prior = {
        ...state,
        allocation: operation.allocation,
        leaf: operation.leaf,
        temporary: operation.temporary,
        alias:
          operation.leaf !== null && operation.leaf === operation.temporary,
      };
      const unchanged = same(message, prior);
      const published =
        operation.temporary !== null &&
        message.allocation === operation.allocation &&
        message.leaf === operation.temporary &&
        message.temporary === null;
      switch (effects.recoveryOperation) {
        case "publish":
          requireWindows(
            unchanged ||
              (operation.leaf === null &&
                (published ||
                  (message.allocation === operation.allocation &&
                    message.alias &&
                    message.leaf === operation.temporary))) ||
              (operation.leaf !== null &&
                message.allocation === operation.allocation &&
                message.leaf === operation.leaf &&
                message.temporary === null),
          );
          break;
        case "replace":
          requireWindows(unchanged || published);
          break;
        case "cleanup":
          requireWindows(
            unchanged ||
              (message.temporary === null &&
                [null, operation.leaf].includes(message.leaf)),
          );
          break;
        case "inspect":
        case "finish":
          requireWindows(unchanged);
          break;
        default:
          requireWindows(false);
      }
    } else if (operation.type === "cleanup") {
      requireWindows(message.phase === "removing" && same(message, state));
      await park(message);
      message = await receive();
      requireWindows(
        message.phase === "removed" &&
          message.allocation === null &&
          message.leaf === null &&
          message.temporary === null,
      );
    } else
      requireWindows(
        message.phase ===
          (operation.type === "inspect" ? "inspected" : "finished") &&
          same(message, state),
      );
    await verified(message);
    state = stateOf(message);
    await persist("acknowledgement", message);
    return { status: "OBSERVED", state, reservation: "RETAINED" };
  } catch {
    return {
      status: interrupted ? "INTERRUPTED" : "FAIL",
      state,
      reservation: "RETAINED",
    };
  }
}
const hashReceipt = (value) => typeof value === "string" && HASH.test(value);
