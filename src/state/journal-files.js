import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat } from "node:fs/promises";
import { isDeepStrictEqual } from "node:util";

import { openRegularFile } from "./files.js";
import { RunStoreError } from "./validation.js";

function observation(stat) {
  return {
    dev: String(stat.dev),
    ino: String(stat.ino),
    size: Number(stat.size),
    mtime: String(stat.mtimeNs),
    ctime: String(stat.ctimeNs),
    mode: String(stat.mode),
    links: Number(stat.nlink),
  };
}

export async function observeJournalDirectory(directory) {
  const stat = await lstat(directory, { bigint: true });
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new RunStoreError("Run path must be a real directory.", {
      code: "ERR_INVALID_RUN_STATE",
    });
  }
  return observation(stat);
}

export function sameJournalIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

export async function journalFileUnchanged(filePath, expected) {
  try {
    return (
      expected !== null &&
      isDeepStrictEqual(
        expected,
        observation(await lstat(filePath, { bigint: true })),
      )
    );
  } catch (cause) {
    if (cause?.code === "ENOENT") return false;
    throw cause;
  }
}

// Hash the exact opened bytes, retaining only the uncached suffix. A binding
// requires stable handle/path observations; timestamps never replace hashing.
export async function readJournalSegment(filePath, limit, prefix = null) {
  const handle = await openRegularFile(filePath, constants.O_RDONLY);
  try {
    const before = observation(await handle.stat({ bigint: true }));
    if (before.size > limit) {
      throw new RunStoreError("Run event log exceeds its size limit.", {
        code: "ERR_INVALID_EVENT_LOG",
      });
    }
    if (
      prefix &&
      (!sameJournalIdentity(before, prefix) || before.size < prefix.length)
    )
      return null;
    const hash = createHash("sha256");
    const chunks = [];
    const buffer = Buffer.alloc(64 * 1024);
    const prefixLength = prefix?.length ?? 0;
    let position = 0;
    while (position < before.size) {
      const end = position < prefixLength ? prefixLength : before.size;
      const { bytesRead } = await handle.read(
        buffer,
        0,
        Math.min(buffer.length, end - position),
        position,
      );
      if (bytesRead === 0) break;
      const chunk = buffer.subarray(0, bytesRead);
      hash.update(chunk);
      if (position >= prefixLength) chunks.push(Buffer.from(chunk));
      position += bytesRead;
      if (
        prefix &&
        position === prefixLength &&
        hash.copy().digest("hex") !== prefix.digest
      )
        return null;
    }
    const after = observation(await handle.stat({ bigint: true }));
    const pathAfter = observation(await lstat(filePath, { bigint: true }));
    const stable =
      position === before.size &&
      before.links === 1 &&
      isDeepStrictEqual(before, after) &&
      isDeepStrictEqual(after, pathAfter);
    if (prefix && !stable) return null;
    return {
      source: Buffer.concat(chunks).toString("utf8"),
      observation: stable ? after : null,
      binding: stable
        ? {
            dev: before.dev,
            ino: before.ino,
            length: position,
            digest: hash.digest("hex"),
          }
        : null,
    };
  } finally {
    await handle.close();
  }
}
