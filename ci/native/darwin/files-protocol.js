import { digest, requireDarwin } from "./protocol.js";

const HASH = /^[a-f0-9]{64}$/u;
const NONCE = /^[a-f0-9]{32}$/u;
const ID =
  /^(0|[1-9][0-9]{0,9}):(0|[1-9][0-9]{0,9}):(0|[1-9][0-9]{0,9}):([1-9][0-9]{0,19}):([1-9][0-9]{0,18}):(0|[1-9][0-9]{0,8}):([a-f0-9]{32})$/u;
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

function closed(value, keys) {
  requireDarwin(
    value &&
      Object.getPrototypeOf(value) === Object.prototype &&
      Reflect.ownKeys(value).length === keys.length &&
      keys.every((key) => {
        const field = Object.getOwnPropertyDescriptor(value, key);
        return field?.enumerable && Object.hasOwn(field, "value");
      }),
  );
}
export function normalizeDarwinFileIdentity(value) {
  requireDarwin(typeof value === "string");
  const match = ID.exec(value);
  requireDarwin(
    match &&
      match.slice(1, 4).every((part) => BigInt(part) <= 0xffffffffn) &&
      BigInt(match[4]) <= 0xffffffffffffffffn &&
      BigInt(match[5]) <= 0x7fffffffffffffffn &&
      BigInt(match[6]) < 1000000000n &&
      match[7] !== "0".repeat(32),
  );
  return value;
}
const volume = (value) =>
  value
    .split(":")
    .filter((_, index) => [0, 1, 2, 6].includes(index))
    .join(":");
const identity = (value) =>
  value === null ? null : normalizeDarwinFileIdentity(value);
export function normalizeDarwinFileState(value) {
  closed(value, STATE);
  const state = Object.fromEntries(
    STATE.slice(0, -1).map((key) => [key, identity(value[key])]),
  );
  requireDarwin(
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
  requireDarwin(
    new Set(distinct).size === distinct.length - (value.alias ? 1 : 0),
  );
  return { ...state, alias: value.alias };
}
function request(value) {
  closed(value, ["type", "allocation", "leaf", "temporary", "bytes"]);
  requireDarwin(
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
  requireDarwin(
    value.type !== "allocate" ||
      [result.allocation, result.leaf, result.temporary].every(
        (id) => id === null,
      ),
  );
  requireDarwin(
    !["publish", "replace", "recover", "cleanup", "inspect"].includes(
      result.type,
    ) || result.allocation !== null,
  );
  requireDarwin(
    !["publish", "replace"].includes(result.type) || result.temporary === null,
  );
  requireDarwin(result.type !== "replace" || result.leaf !== null);
  return result;
}
export function encodeDarwinFileRequest(value) {
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
export function normalizeDarwinFileMessage(value, nonce) {
  closed(value, ["nonce", "phase", ...STATE]);
  requireDarwin(
    typeof nonce === "string" &&
      NONCE.test(nonce) &&
      value.nonce === nonce &&
      PHASES.includes(value.phase),
  );
  const state = normalizeDarwinFileState(
    Object.fromEntries(STATE.map((key) => [key, value[key]])),
  );
  requireDarwin(value.phase !== "linked" || state.alias);
  requireDarwin(
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
export async function runDarwinFileTransaction(input, effects) {
  let state,
    interrupted = false;
  try {
    const operation = request(input),
      nonce = effects.nonce;
    state = normalizeDarwinFileState(effects.state);
    requireDarwin(
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
    requireDarwin(
      ["allocate", "recover"].includes(operation.type)
        ? allocationEmpty
        : operation.allocation === state.allocation &&
            operation.leaf === state.leaf &&
            operation.temporary === state.temporary,
    );
    if (operation.type === "cleanup") {
      requireDarwin(typeof effects.authorizeCleanup === "function");
      const permission = await effects.authorizeCleanup(structuredClone(state));
      requireDarwin(
        permission.independent === true &&
          permission.retired === true &&
          permission.stateSha256 === digest(JSON.stringify(state)) &&
          hashReceipt(permission.receiptSha256),
      );
    }
    const receive = async () => {
      const message = normalizeDarwinFileMessage(
        await effects.receive(),
        nonce,
      );
      requireDarwin(message.root === state.root && message.base === state.base);
      return message;
    };
    const persist = (kind, message) =>
      effects.persist(kind, structuredClone({ operation, message, state }));
    const verified = async (message) => {
      const evidence = await effects.verify(
        structuredClone(message),
        structuredClone(operation),
      );
      requireDarwin(
        evidence.independent === true &&
          evidence.stateSha256 === digest(JSON.stringify(stateOf(message))) &&
          typeof evidence.receiptSha256 === "string" &&
          HASH.test(evidence.receiptSha256),
      );
      if (["publish", "replace"].includes(operation.type)) {
        const expected = digest(Buffer.from(operation.bytes, "hex"));
        if (["prepared", "linked"].includes(message.phase))
          requireDarwin(evidence.temporarySha256 === expected);
        if (["linked", "published", "complete"].includes(message.phase))
          requireDarwin(evidence.leafSha256 === expected);
      }
    };
    const park = async (message) => {
      await verified(message);
      state = stateOf(message);
      await persist("barrier", message);
      const decision = await effects.barrier(structuredClone(message));
      requireDarwin(["continue", "interrupt"].includes(decision));
      if (decision === "interrupt") {
        await persist("interruption", message);
        interrupted = true;
        throw new Error("Declared file interruption");
      }
      await effects.send("continue - - - -\n");
    };
    await persist("intent", null);
    await effects.send(encodeDarwinFileRequest(operation));
    let message = await receive();
    if (["publish", "replace"].includes(operation.type)) {
      requireDarwin(
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
        requireDarwin(
          operation.type === "publish" &&
            operation.leaf !== null &&
            message.leaf === operation.leaf &&
            message.allocation === state.allocation &&
            message.temporary === null,
        );
      } else {
        requireDarwin(operation.type !== "publish" || operation.leaf === null);
        if (operation.type === "publish") {
          requireDarwin(
            message.phase === "linked" &&
              message.allocation === state.allocation &&
              message.leaf === prepared.temporary &&
              message.temporary === prepared.temporary &&
              message.alias,
          );
          await park(message);
          message = await receive();
        }
        requireDarwin(
          message.phase === "published" &&
            message.allocation === state.allocation &&
            message.leaf === prepared.temporary &&
            message.temporary === null &&
            !message.alias,
        );
        await park(message);
        message = await receive();
        requireDarwin(message.phase === "complete" && same(message, state));
      }
    } else if (operation.type === "allocate") {
      requireDarwin(
        message.phase === "allocated" &&
          message.allocation !== null &&
          message.leaf === null &&
          message.temporary === null,
      );
    } else if (operation.type === "recover") {
      requireDarwin(
        message.phase === "recovered" &&
          message.allocation === operation.allocation &&
          [null, operation.leaf, operation.temporary].includes(message.leaf) &&
          [null, operation.temporary].includes(message.temporary),
      );
    } else if (operation.type === "cleanup") {
      requireDarwin(message.phase === "removing" && same(message, state));
      await park(message);
      message = await receive();
      requireDarwin(
        message.phase === "removed" &&
          message.allocation === null &&
          message.leaf === null &&
          message.temporary === null,
      );
    } else
      requireDarwin(
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
