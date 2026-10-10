const IDENTITY =
  /^(?:0|[1-9][0-9]{0,9}):(?:0|[1-9][0-9]{0,9}):[1-9][0-9]{0,19}:[1-9][0-9]{0,19}:[1-9][0-9]{0,18}:(?:0|[1-9][0-9]{0,8})$/u;
const NONCE = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/u;
const TYPES = [
  "allocate",
  "recover",
  "publish",
  "replace",
  "inspect",
  "cleanup",
  "check",
  "continue",
  "finish",
];
const PHASES = [
  "ready",
  "allocated",
  "recovered",
  "prepared",
  "published",
  "complete",
  "exists",
  "inspected",
  "removed",
  "finished",
  "retained",
  "checking",
  "removing",
  "denied",
];

export const LINUX_FILE_CONTROLS = Object.freeze([
  "ancestor",
  "leaf",
  "symlink",
  "magic-link",
  "mount",
  "hard-link",
  "cleanup",
  "cleanup-leaf",
]);

export function normalizeLinuxFileControl(value) {
  requireValue(value === null || LINUX_FILE_CONTROLS.includes(value));
  return value;
}

export function assertLinuxFileControlPolicy(policy, control) {
  normalizeLinuxFileControl(control);
  requireValue(control !== null);
  closed(policy, [
    "id",
    "executableDigest",
    "namespaces",
    "anchor",
    "hostCheckout",
    "procfs",
    "payloads",
    "inheritedDescriptors",
    "control",
    "readOnlyCrossing",
  ]);
  requireValue(
    policy.id === "linux-file-authority-v1" &&
      typeof policy.executableDigest === "string" &&
      /^[a-f0-9]{64}$/u.test(policy.executableDigest) &&
      JSON.stringify(policy.namespaces) ===
        JSON.stringify(["user", "pid", "net", "ipc", "uts"]) &&
      policy.anchor === "/anchor" &&
      policy.hostCheckout === false &&
      policy.payloads === false &&
      policy.inheritedDescriptors === false &&
      policy.control === control &&
      policy.procfs === (control === "magic-link") &&
      policy.readOnlyCrossing === (control === "mount"),
  );
}

function requireValue(condition) {
  if (!condition)
    throw new Error("Invalid Linux file protocol; exclusion retained");
}

function closed(value, keys) {
  requireValue(
    value !== null &&
      typeof value === "object" &&
      Object.getPrototypeOf(value) === Object.prototype &&
      Reflect.ownKeys(value).length === keys.length &&
      keys.every((key) => {
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        return descriptor?.enumerable && Object.hasOwn(descriptor, "value");
      }),
  );
}

function identity(value) {
  requireValue(
    value === null ||
      (typeof value === "string" &&
        IDENTITY.test(value) &&
        value
          .split(":")
          .every(
            (part, index) =>
              BigInt(part) <=
              (index < 2
                ? 4294967295n
                : index === 4
                  ? 9223372036854775807n
                  : index === 5
                    ? 999999999n
                    : 18446744073709551615n),
          )),
  );
  return value;
}

/** Fixed names and bounded bytes only; no path, shell, mode or argv authority. */
export function encodeLinuxFileRequest(value) {
  closed(value, ["type", "allocation", "leaf", "temporary", "bytes"]);
  requireValue(TYPES.includes(value.type));
  identity(value.allocation);
  identity(value.leaf);
  identity(value.temporary);
  requireValue(
    typeof value.bytes === "string" &&
      value.bytes.length <= 8192 &&
      /^(?:[a-f0-9]{2})*$/u.test(value.bytes),
  );
  const mutation = value.type === "publish" || value.type === "replace";
  const empty = ["allocate", "continue", "finish"].includes(value.type);
  requireValue(
    (mutation || value.bytes === "") &&
      (empty
        ? value.allocation === null &&
          value.leaf === null &&
          value.temporary === null
        : value.allocation !== null) &&
      (!mutation || value.temporary === null) &&
      (value.type !== "publish" || value.leaf === null) &&
      (value.type !== "replace" || value.leaf !== null),
  );
  return `${value.type} ${value.allocation ?? "-"} ${value.leaf ?? "-"} ${value.temporary ?? "-"} ${value.bytes || "-"}\n`;
}

export function normalizeLinuxFileMessage(value, nonce) {
  const denial =
    Object.getOwnPropertyDescriptor(value ?? {}, "phase")?.value === "denied";
  closed(value, [
    "type",
    "nonce",
    "phase",
    "anchor",
    "allocation",
    "leaf",
    "temporary",
    ...(denial ? ["operation", "reason", "positiveControl"] : []),
  ]);
  requireValue(
    typeof nonce === "string" &&
      NONCE.test(nonce) &&
      value.type === "file" &&
      value.nonce === nonce &&
      PHASES.includes(value.phase),
  );
  if (denial)
    requireValue(
      ["replace", "cleanup", "check"].includes(value.operation) &&
        ["identity", "symlink", "magic-link", "mount", "hard-link"].includes(
          value.reason,
        ) &&
        value.positiveControl === true,
    );
  identity(value.allocation);
  identity(value.anchor);
  identity(value.leaf);
  identity(value.temporary);
  requireValue(
    value.phase === "retained" ? value.anchor === null : value.anchor !== null,
  );
  for (const entry of [value.allocation, value.leaf, value.temporary])
    if (entry !== null)
      requireValue(entry.split(":")[3] === value.anchor?.split(":")[3]);
  requireValue(
    (value.leaf === null && value.temporary === null) ||
      value.allocation !== null,
  );
  if (["ready", "removed", "retained"].includes(value.phase))
    requireValue(
      value.allocation === null &&
        value.leaf === null &&
        value.temporary === null,
    );
  else if (value.phase !== "finished") requireValue(value.allocation !== null);
  if (["published", "complete", "exists"].includes(value.phase))
    requireValue(value.leaf !== null);
  if (value.phase === "allocated")
    requireValue(value.leaf === null && value.temporary === null);
  if (value.phase === "prepared") requireValue(value.temporary !== null);
  if (["published", "complete", "exists"].includes(value.phase))
    requireValue(value.temporary === null);
  return Object.freeze({ ...value });
}

function sameObject(first, second) {
  return first === null || second === null
    ? first === second
    : first
        .split(":")
        .filter((_, index) => index !== 3)
        .join(":") ===
        second
          .split(":")
          .filter((_, index) => index !== 3)
          .join(":");
}

/** An operation acknowledgement never proves domain retirement. On any error
 * the caller must stop the session and retain storage and launch exclusion. */
export async function runLinuxFileTransaction(request, effects) {
  let denial = null;
  try {
    encodeLinuxFileRequest(request);
    // Callbacks cannot redirect a validated operation or its identity bindings.
    request = Object.freeze({ ...request });
    const { nonce, anchor, allocation, previousLeaf, temporary } = effects;
    requireValue(typeof nonce === "string" && NONCE.test(nonce));
    requireValue(identity(anchor) !== null);
    if (["allocate", "recover"].includes(request.type)) {
      requireValue(
        allocation === null && previousLeaf === null && temporary === null,
      );
    } else {
      identity(allocation);
      identity(previousLeaf);
      identity(temporary);
    }
    let current = { anchor, allocation, leaf: previousLeaf, temporary };
    let parked = false;
    const receive = async () => {
      const value = normalizeLinuxFileMessage(await effects.receive(), nonce);
      if (value.phase === "denied") {
        requireValue(
          parked &&
            value.operation === request.type &&
            ["anchor", "allocation", "leaf", "temporary"].every(
              (key) => value[key] === current[key],
            ),
        );
        await effects.denied?.(value);
        denial = value;
        throw new Error("Native operation denied");
      }
      return value;
    };
    const read = async (phase, expectedAllocation, leaf, pending = null) => {
      const value = await receive();
      requireValue(value.anchor === anchor);
      requireValue(
        value.phase === phase &&
          value.allocation === expectedAllocation &&
          value.leaf === leaf &&
          value.temporary === pending,
      );
      return value;
    };
    const acknowledgement = Object.freeze({
      type: "continue",
      allocation: null,
      leaf: null,
      temporary: null,
      bytes: "",
    });
    requireValue(request.type !== "continue");
    requireValue(
      request.type === "allocate" ||
        request.type === "recover" ||
        request.type === "finish" ||
        (request.allocation === allocation &&
          request.temporary === temporary &&
          (request.type === "publish" || request.leaf === previousLeaf)),
    );
    await effects.send(request);
    let message;
    if (["publish", "replace"].includes(request.type)) {
      const prepared = await receive();
      requireValue(
        prepared.anchor === anchor &&
          prepared.phase === "prepared" &&
          prepared.allocation === request.allocation &&
          prepared.leaf === previousLeaf &&
          prepared.temporary !== prepared.leaf,
      );
      current = prepared;
      await effects.barrier(prepared);
      parked = true;
      await effects.send(acknowledgement);
      message = await receive();
      requireValue(
        message.anchor === anchor && message.allocation === request.allocation,
      );
      if (message.phase === "exists") {
        requireValue(
          request.type === "publish" && message.leaf === previousLeaf,
        );
      } else {
        requireValue(
          (request.type === "replace" || previousLeaf === null) &&
            message.phase === "published" &&
            message.leaf === prepared.temporary,
        );
        current = message;
        await effects.barrier(message);
        parked = true;
        await effects.send(acknowledgement);
        message = await read("complete", request.allocation, message.leaf);
      }
    } else if (request.type === "allocate") {
      message = await receive();
      requireValue(message.anchor === anchor && message.phase === "allocated");
    } else if (request.type === "inspect") {
      message = await read(
        "inspected",
        request.allocation,
        request.leaf,
        request.temporary,
      );
    } else if (request.type === "recover") {
      message = await receive();
      requireValue(
        message.anchor === anchor &&
          message.phase === "recovered" &&
          sameObject(message.allocation, request.allocation) &&
          sameObject(message.leaf, request.leaf) &&
          sameObject(message.temporary, request.temporary),
      );
    } else if (request.type === "cleanup") {
      message = await receive();
      if (message.phase === "removing") {
        requireValue(
          ["anchor", "allocation", "leaf", "temporary"].every(
            (key) => message[key] === current[key],
          ),
        );
        await effects.barrier(message);
        parked = true;
        await effects.send(acknowledgement);
        message = await receive();
      }
      requireValue(
        message.phase === "removed" &&
          message.anchor === anchor &&
          message.allocation === null &&
          message.leaf === null &&
          message.temporary === null,
      );
    } else if (request.type === "check") {
      message = await read(
        "checking",
        request.allocation,
        request.leaf,
        request.temporary,
      );
      await effects.barrier(message);
      parked = true;
      await effects.send(acknowledgement);
      await receive();
      requireValue(false); // A successful alias probe is never an expected denial.
    } else if (request.type === "finish") {
      message = await read("finished", allocation, previousLeaf, temporary);
    } else requireValue(false); // continue belongs exclusively to an acknowledged barrier.
    return { status: "PASS", exclusion: "RETAINED", message };
  } catch {
    return { status: "FAIL", exclusion: "RETAINED", message: denial };
  }
}

/** Fresh independent retirement is necessary even after native removal. A
 * failed/interrupted operation or uncertain cleanup never releases exclusion. */
export async function retireLinuxFileStorage(result, effects) {
  const next = {
    ...result,
    settlement: {
      status: "RETAINED",
      independent: false,
      emergencyCleanup: result.settlement.emergencyCleanup,
    },
    storage: "RETAINED",
    exclusion: "RETAINED",
  };
  try {
    requireValue(typeof next.settlement.emergencyCleanup === "boolean");
    const verified = await effects.verify();
    closed(verified, ["status", "independent", "emergencyCleanup"]);
    requireValue(
      ["RETIRED", "RETAINED"].includes(verified.status) &&
        verified.independent === (verified.status === "RETIRED") &&
        verified.emergencyCleanup === false,
    );
    next.settlement = {
      ...verified,
      emergencyCleanup: next.settlement.emergencyCleanup,
    };
    if (
      next.status !== "PASS" ||
      next.settlement.status !== "RETIRED" ||
      !next.settlement.independent ||
      next.settlement.emergencyCleanup !== false
    )
      throw new Error("Excluded");
    await effects.cleanup();
    next.storage = "REMOVED";
    next.exclusion = "RELEASED";
  } catch {
    next.status = "FAIL";
    next.storage = "RETAINED";
    next.exclusion = "RETAINED";
  }
  return next;
}
