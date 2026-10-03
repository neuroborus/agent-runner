import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import { digest, requireDarwin } from "./protocol.js";

export async function protectedBytes(entry, gid, mode, maximum) {
  requireDarwin((await realpath(entry.path)) === entry.path);
  const handle = await open(
    entry.path,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const before = await handle.stat({ bigint: true });
    requireDarwin(
      before.isFile() &&
        before.uid === 0n &&
        before.gid === BigInt(gid) &&
        before.nlink === 1n &&
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
      named = await lstat(entry.path, { bigint: true });
    requireDarwin(
      BigInt(size) === before.size &&
        after.size === before.size &&
        after.mtimeNs === before.mtimeNs &&
        after.ctimeNs === before.ctimeNs &&
        named.dev === before.dev &&
        named.ino === before.ino &&
        named.mode === before.mode &&
        named.uid === 0n &&
        named.gid === BigInt(gid) &&
        named.nlink === 1n &&
        (await realpath(entry.path)) === entry.path,
    );
    const bytes = buffer.subarray(0, size);
    requireDarwin(digest(bytes) === entry.sha256);
    return bytes;
  } finally {
    await handle.close();
  }
}
