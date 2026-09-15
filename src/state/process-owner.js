import { isDeepStrictEqual } from "node:util";

import { readProcessIdentity as readNativeProcessIdentity } from "../agents/index.js";
import { RunStoreError, validateProcessIdentity } from "./validation.js";

// Linux process start ticks and boot identity distinguish a PID from its owner.
// Other platforms and inaccessible process metadata remain unverifiable.
export async function readProcessIdentity(pid) {
  return validateProcessIdentity(await readNativeProcessIdentity(pid));
}

export async function inspectProcessOwner(
  record,
  { hostName, processIsAlive, processIdentity },
) {
  if (record.hostname !== hostName) return "unverifiable";
  const alive = await processIsAlive(record.pid);
  if (typeof alive !== "boolean") {
    throw new RunStoreError("Process liveness check is invalid.", {
      code: "ERR_INVALID_RUN_STORE_OPTIONS",
    });
  }
  if (!alive) return "dead";
  if (record.processIdentity === undefined || record.processIdentity === null)
    return "unverifiable";
  const current = validateProcessIdentity(await processIdentity(record.pid));
  if (current === null) return "unverifiable";
  return isDeepStrictEqual(record.processIdentity, current)
    ? "live"
    : "replaced";
}
