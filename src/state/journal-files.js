import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat } from "node:fs/promises";
import { isDeepStrictEqual } from "node:util";

import { openRegularFile } from "./files.js";
import { RunStoreError } from "./validation.js";

function identity(stat) {
  return {
    dev: String(stat.dev),
    ino: String(stat.ino),
    mode: String(stat.mode),
    uid: String(stat.uid),
    gid: String(stat.gid),
  };
}

function observation(stat) {
  return {
    ...identity(stat),
    size: Number(stat.size),
    mtime: String(stat.mtimeNs),
    ctime: String(stat.ctimeNs),
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
  return isDeepStrictEqual(identity(left), identity(right));
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

// The caller proves the complete captured prefix and namespace on both sides
// of repair. This handle binds the authorized size change to that capture.
export async function truncateJournalTail(filePath, size, expected) {
  const invalid = () => {
    throw new RunStoreError("Run changed during event tail repair.", {
      code: "ERR_INVALID_EVENT_LOG",
    });
  };
  const handle = await openRegularFile(filePath, constants.O_RDWR);
  try {
    const before = observation(await handle.stat({ bigint: true }));
    if (
      !isDeepStrictEqual(before, expected) ||
      before.links !== 1 ||
      size >= before.size ||
      !(await journalFileUnchanged(filePath, before))
    )
      invalid();
    await handle.truncate(size);
    await handle.sync();
    const after = observation(await handle.stat({ bigint: true }));
    if (
      after.size !== size ||
      after.links !== 1 ||
      !sameJournalIdentity(before, after) ||
      !(await journalFileUnchanged(filePath, after))
    )
      invalid();
    return after;
  } finally {
    await handle.close();
  }
}

// Hash the exact opened bytes, normally retaining only the uncached suffix.
// Canonical snapshot matching can also decode the prefix without dropping its
// byte proof. Bindings require stable handle/path observations, not timestamps.
export async function readJournalSegment(
  filePath,
  limit,
  prefix = null,
  includePrefix = false,
) {
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
    const sourceOffset = includePrefix ? 0 : prefixLength;
    let position = 0;
    let prefixHash = hash.copy();
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
      if (position >= sourceOffset) chunks.push(Buffer.from(chunk));
      position += bytesRead;
      if (position === prefixLength && !includePrefix) prefixHash = hash.copy();
      if (
        prefix &&
        position === prefixLength &&
        hash.copy().digest("hex") !== prefix.digest
      )
        return null;
    }
    const source = Buffer.concat(chunks);
    const completeEnd = source.lastIndexOf(10) + 1;
    const after = observation(await handle.stat({ bigint: true }));
    const pathAfter = observation(await lstat(filePath, { bigint: true }));
    const stable =
      position === before.size &&
      before.links === 1 &&
      isDeepStrictEqual(before, after) &&
      isDeepStrictEqual(after, pathAfter);
    if (prefix && !stable) return null;
    return {
      source: source.toString("utf8"),
      observation: stable ? after : null,
      binding: stable
        ? {
            ...identity(before),
            length: sourceOffset + completeEnd,
            digest: prefixHash
              .update(source.subarray(0, completeEnd))
              .digest("hex"),
          }
        : null,
    };
  } finally {
    await handle.close();
  }
}

// Yield one record at a time, hashing the very bytes decoded by the consumer.
// Completion, not any individual yield, proves this previously validated range.
export async function* streamJournalPrefix(
  filePath,
  limit,
  binding,
  metadata,
  allowAppend,
  decode = true,
) {
  const invalid = () => {
    throw new RunStoreError("Run changed during projection streaming.", {
      code: "ERR_INVALID_EVENT_LOG",
    });
  };
  const handle = await openRegularFile(filePath, constants.O_RDONLY);
  try {
    const before = observation(await handle.stat({ bigint: true }));
    if (
      before.links !== 1 ||
      !sameJournalIdentity(before, binding) ||
      before.size < binding.length ||
      (!allowAppend && before.size !== binding.length) ||
      before.size > limit ||
      !(await journalFileUnchanged(filePath, before))
    )
      invalid();
    const hash = createHash("sha256");
    const buffer = Buffer.alloc(64 * 1024);
    let position = 0;
    let pending = [];
    let pendingBytes = 0;
    while (position < binding.length) {
      const { bytesRead } = await handle.read(
        buffer,
        0,
        Math.min(buffer.length, binding.length - position),
        position,
      );
      if (bytesRead === 0) invalid();
      const chunk = buffer.subarray(0, bytesRead);
      hash.update(chunk);
      position += bytesRead;
      if (!decode) continue;
      let start = 0;
      for (let end; (end = chunk.indexOf(10, start)) !== -1; start = end + 1) {
        const part = chunk.subarray(start, end);
        const line = Buffer.concat(
          [...pending, part],
          pendingBytes + part.length,
        ).toString("utf8");
        pending = [];
        pendingBytes = 0;
        yield line;
      }
      if (start < bytesRead) {
        pending.push(Buffer.from(chunk.subarray(start)));
        pendingBytes += bytesRead - start;
      }
    }
    const after = observation(await handle.stat({ bigint: true }));
    if (
      pendingBytes !== 0 ||
      hash.digest("hex") !== binding.digest ||
      !isDeepStrictEqual(before, after) ||
      !(await journalFileUnchanged(filePath, after))
    )
      invalid();
    metadata.observation = after;
  } finally {
    await handle.close();
  }
}
