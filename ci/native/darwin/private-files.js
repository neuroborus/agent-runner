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
const same = (before, after) =>
  STABILITY.every((key) => before[key] === after[key]);

/** Bootstrap observations only; native custody independently checks held ACLs.
 * Neither root ownership nor a caller's pin classifies a generated input. */
export async function protectedInstalledInput(file, stat, fs) {
  try {
    const mode = Number(stat.mode) & 0o7777,
      stock = STOCK_TOOLS.has(file),
      installed =
        stock ||
        file === "/usr/lib/dyld" ||
        /^\/(?:private\/)?etc\/security\/audit_(?:event|class)$/u.test(file) ||
        file.startsWith("/Library/Developer/") ||
        (file.startsWith("/Applications/") &&
          file.includes("/Contents/Developer/")) ||
        file.startsWith("/usr/include/") ||
        file.startsWith("/usr/lib/clang/") ||
        ((file.startsWith("/System/Library/dyld/") ||
          file.startsWith("/System/Volumes/Preboot/")) &&
          /^dyld_shared_cache_x86_64h?$/u.test(path.basename(file)));
    if (
      !installed ||
      file.length >= 4096 ||
      path.normalize(file) !== file ||
      (stock &&
        !(
          file === "/usr/bin/sudo" ? [0o4555, 0o4755] : [0o555, 0o755]
        ).includes(mode)) ||
      (!stock && mode & 0o6022) ||
      Number(stat.uid) !== 0 ||
      (stock && Number(stat.gid) !== 0) ||
      !Number.isSafeInteger(Number(stat.nlink)) ||
      Number(stat.nlink) <= 0 ||
      !stat.isFile() ||
      stat.isSymbolicLink() ||
      (await fs.realpath(file)) !== file
    )
      return false;
    let parent = path.dirname(file);
    for (let depth = 0; depth < 32; depth++) {
      const before = await fs.lstat(parent);
      if (
        !before.isDirectory() ||
        before.isSymbolicLink() ||
        Number(before.uid) !== 0 ||
        Number(before.mode) & 0o22 ||
        (await fs.realpath(parent)) !== parent ||
        !same(before, await fs.lstat(parent))
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
) {
  requireDarwin((await fs.realpath(entry.path)) === entry.path);
  const handle = await fs.open(
    entry.path,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const before = await handle.stat({ bigint: true });
    requireDarwin(
      before.isFile() &&
        before.uid === 0n &&
        before.gid === BigInt(gid) &&
        (before.nlink === 1n ||
          (installed &&
            (await protectedInstalledInput(entry.path, before, fs)))) &&
        (before.mode & 0o7777n) === BigInt(mode) &&
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
        (before.nlink === 1n ||
          (await protectedInstalledInput(entry.path, named, fs))),
    );
    const bytes = buffer.subarray(0, size);
    requireDarwin(digest(bytes) === entry.sha256);
    return bytes;
  } finally {
    await handle.close();
  }
}
