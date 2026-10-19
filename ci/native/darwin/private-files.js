import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import path from "node:path";
import { digest, requireDarwin } from "./protocol.js";

const STOCK_TOOLS = new Set([
  "/usr/bin/clang",
  "/usr/bin/xcrun",
  "/usr/bin/codesign",
  "/usr/bin/env",
  "/usr/bin/sudo",
  "/usr/bin/git",
  "/usr/bin/hdiutil",
  "/usr/bin/log",
  "/sbin/pfctl",
]);
const STABILITY = [
  "dev",
  "ino",
  "mode",
  "uid",
  "gid",
  "nlink",
  "size",
  "mtimeMs",
  "ctimeMs",
  "mtimeNs",
  "ctimeNs",
];
const validIdentity = (stat) =>
  [stat.dev, stat.ino].every(
    (value) =>
      typeof value === "bigint" &&
      value >= 0n &&
      value <= 18446744073709551615n,
  );
const same = (before, after) =>
  STABILITY.every((key) => before[key] === after[key]);
const installedCache = (file) =>
  (file.startsWith("/System/Library/dyld/") ||
    file.startsWith("/System/Volumes/Preboot/")) &&
  /^dyld_shared_cache_x86_64h?$/u.test(path.basename(file));

// Path classification grants no identity, byte, signature or private-file proof.
export const isDarwinInstalledPath = (file) =>
  typeof file === "string" &&
  file.length < 4096 &&
  path.isAbsolute(file) &&
  path.normalize(file) === file &&
  (STOCK_TOOLS.has(file) ||
    file === "/usr/lib/dyld" ||
    /^\/(?:private\/)?etc\/security\/audit_(?:event|class)$/u.test(file) ||
    file.startsWith("/Library/Developer/") ||
    (file.startsWith("/Applications/") &&
      file.includes("/Contents/Developer/")) ||
    file.startsWith("/usr/include/") ||
    file.startsWith("/usr/lib/clang/") ||
    installedCache(file));

/** Reviewed reads require protected metadata; experiment installed inputs trust
 * the hosted image. Both retain canonical ancestry and stable identities. */
export async function protectedInstalledInput(
  file,
  stat,
  fs,
  purpose = "reviewed",
) {
  try {
    if (!["reviewed", "experiment"].includes(purpose)) return false;
    const hosted = purpose === "experiment" && isDarwinInstalledPath(file);
    // Existing Number-stat callers classify scalar eligibility only. The held
    // reader and ancestry snapshots independently acquire exact identities.
    const bounded = (value, maximum) =>
      typeof value === "bigint"
        ? value >= 0n && value <= BigInt(maximum)
        : Number.isSafeInteger(value) && value >= 0 && value <= maximum;
    if (
      ((typeof stat.dev === "bigint" || typeof stat.ino === "bigint") &&
        !validIdentity(stat)) ||
      !bounded(stat.mode, 0xffffffff) ||
      !bounded(stat.nlink, Number.MAX_SAFE_INTEGER)
    )
      return false;
    const mode = Number(stat.mode) & 0o7777,
      stock = STOCK_TOOLS.has(file),
      installed = isDarwinInstalledPath(file);
    if (
      !installed ||
      file.length >= 4096 ||
      path.normalize(file) !== file ||
      (!hosted &&
        stock &&
        !(
          file === "/usr/bin/sudo" ? [0o4555, 0o4755] : [0o555, 0o755]
        ).includes(mode)) ||
      (!hosted && !stock && mode & 0o6022) ||
      (!hosted && stat.uid !== 0 && stat.uid !== 0n) ||
      (!hosted && stock && stat.gid !== 0 && stat.gid !== 0n) ||
      stat.nlink <= 0 ||
      !stat.isFile() ||
      stat.isSymbolicLink() ||
      (await fs.realpath(file)) !== file
    )
      return false;
    let parent = path.dirname(file);
    for (let depth = 0; depth < 32; depth++) {
      const before = await fs.lstat(parent, { bigint: true });
      if (
        !validIdentity(before) ||
        !before.isDirectory() ||
        before.isSymbolicLink() ||
        (!hosted && (before.uid !== 0n || before.mode & 0o22n)) ||
        (await fs.realpath(parent)) !== parent ||
        !same(before, await fs.lstat(parent, { bigint: true }))
      )
        return false;
      if (parent === "/")
        return same(
          stat,
          await fs.lstat(file, { bigint: typeof stat.uid === "bigint" }),
        );
      parent = path.dirname(parent);
    }
  } catch {
    // Retain the owning reader's original predicate failure and diagnostics.
  }
  return false;
}

export async function protectedBytes(
  entry,
  gid,
  mode,
  maximum,
  fs = { lstat, open, realpath },
  installed = false,
  purpose = "reviewed",
) {
  requireDarwin((await fs.realpath(entry.path)) === entry.path);
  const handle = await fs.open(
    entry.path,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const before = await handle.stat({ bigint: true }),
      hosted =
        installed &&
        purpose === "experiment" &&
        isDarwinInstalledPath(entry.path);
    requireDarwin(
      validIdentity(before) &&
        before.isFile() &&
        (hosted || before.uid === 0n) &&
        (hosted || before.gid === BigInt(gid)) &&
        ((!hosted && before.nlink === 1n) ||
          (installed &&
            (await protectedInstalledInput(
              entry.path,
              before,
              fs,
              purpose,
            )))) &&
        (hosted || (before.mode & 0o7777n) === BigInt(mode)) &&
        before.size > 0n &&
        before.size <= BigInt(maximum),
    );
    const buffer = Buffer.alloc(Number(before.size) + 1);
    let size = 0;
    while (size < buffer.length) {
      const { bytesRead } = await handle.read(
        buffer,
        size,
        buffer.length - size,
        size,
      );
      if (!bytesRead) break;
      size += bytesRead;
    }
    const after = await handle.stat({ bigint: true }),
      named = await fs.lstat(entry.path, { bigint: true });
    requireDarwin(
      BigInt(size) === before.size &&
        validIdentity(after) &&
        validIdentity(named) &&
        [
          "dev",
          "ino",
          "mode",
          "uid",
          "gid",
          "nlink",
          "size",
          "mtimeNs",
          "ctimeNs",
        ].every(
          (key) => before[key] === after[key] && before[key] === named[key],
        ) &&
        (await fs.realpath(entry.path)) === entry.path &&
        ((!hosted && before.nlink === 1n) ||
          (await protectedInstalledInput(entry.path, named, fs, purpose))),
    );
    const bytes = buffer.subarray(0, size);
    requireDarwin(digest(bytes) === entry.sha256);
    return bytes;
  } finally {
    await handle.close();
  }
}
