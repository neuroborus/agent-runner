import { readFile } from "node:fs/promises";
import { isDeepStrictEqual } from "node:util";

import { RunStoreError } from "./validation.js";

export function validateProcessIdentity(value) {
  if (value === null) return null;
  if (
    value === undefined ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length !== 2 ||
    typeof value.bootId !== "string" ||
    !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/u.test(value.bootId) ||
    typeof value.startTicks !== "string" ||
    !/^(?:0|[1-9][0-9]{0,31})$/u.test(value.startTicks)
  ) {
    throw new RunStoreError("Process identity is invalid.", {
      code: "ERR_INVALID_PROCESS_IDENTITY",
    });
  }
  return { bootId: value.bootId, startTicks: value.startTicks };
}

// Linux process start ticks and boot identity distinguish a PID from its owner.
// Other platforms and inaccessible process metadata remain unverifiable.
export async function readProcessIdentity(pid) {
  if (process.platform !== "linux") return null;
  try {
    const [bootId, stat] = await Promise.all([
      readFile("/proc/sys/kernel/random/boot_id", "utf8"),
      readFile(`/proc/${pid}/stat`, "utf8"),
    ]);
    const fields = stat
      .slice(stat.lastIndexOf(")") + 2)
      .trim()
      .split(/\s+/u);
    return validateProcessIdentity({
      bootId: bootId.trim(),
      startTicks: fields[19],
    });
  } catch (cause) {
    if (["ENOENT", "ESRCH", "EACCES", "EPERM"].includes(cause?.code))
      return null;
    throw cause;
  }
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
