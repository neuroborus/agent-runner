import { readFile, readlink } from "node:fs/promises";

const UNAVAILABLE_CODES = new Set(["EACCES", "ENOENT", "EPERM", "ESRCH"]);

export async function readProcessIdentity(pid) {
  if (process.platform !== "linux" || !Number.isSafeInteger(pid) || pid < 1)
    return null;
  try {
    const [bootId, stat] = await Promise.all([
      readFile("/proc/sys/kernel/random/boot_id", "utf8"),
      readFile(`/proc/${pid}/stat`, "utf8"),
    ]);
    const fields = stat
      .slice(stat.lastIndexOf(")") + 2)
      .trim()
      .split(/\s+/u);
    return Object.freeze({
      bootId: bootId.trim(),
      startTicks: fields[19],
    });
  } catch (cause) {
    if (UNAVAILABLE_CODES.has(cause?.code)) return null;
    throw cause;
  }
}

export async function readProcessNamespace(pid) {
  if (process.platform !== "linux" || !Number.isSafeInteger(pid) || pid < 1)
    return null;
  try {
    return await readlink(`/proc/${pid}/ns/pid`);
  } catch (cause) {
    if (UNAVAILABLE_CODES.has(cause?.code)) return null;
    throw cause;
  }
}

export async function readProcessChildren(pid) {
  if (process.platform !== "linux" || !Number.isSafeInteger(pid) || pid < 1)
    return null;
  try {
    const value = await readFile(`/proc/${pid}/task/${pid}/children`, "utf8");
    return value.trim().split(/\s+/u).filter(Boolean).map(Number);
  } catch (cause) {
    if (UNAVAILABLE_CODES.has(cause?.code)) return null;
    throw cause;
  }
}
