import { constants } from "node:fs";
import { lstat, mkdir, open, realpath, stat } from "node:fs/promises";
import { join, parse, relative, sep } from "node:path";

import { absolutePath, RuntimePayloadError } from "./contract.js";

export const DIRECTORY_FLAGS =
  constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW;
const FILE_FLAGS =
  constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK;
const FILE_KEYS = [
  "dev",
  "ino",
  "mode",
  "size",
  "mtimeNs",
  "ctimeNs",
  "nlink",
  "uid",
];
export const sameFile = (a, b) => FILE_KEYS.every((key) => a[key] === b[key]);

export function assertOwned(metadata, mode) {
  if (
    typeof process.getuid !== "function" ||
    metadata.uid !== BigInt(process.getuid()) ||
    Number(metadata.mode & 0o7777n) !== mode
  )
    throw new RuntimePayloadError(
      "Runtime storage must be private, owned, and have its expected permissions.",
    );
}

export async function descriptorPath(handle) {
  const expected = await handle.stat();
  for (const base of ["/proc/self/fd", "/dev/fd"]) {
    const path = join(base, String(handle.fd));
    try {
      const actual = await stat(path);
      if (actual.dev === expected.dev && actual.ino === expected.ino)
        return path;
    } catch (error) {
      if (error.code !== "ENOENT" && error.code !== "ENOTDIR") throw error;
    }
  }
  throw new RuntimePayloadError(
    "Descriptor-bound runtime storage is unavailable.",
  );
}

// Keep every ancestor pinned until the operation finishes, including creation.
export async function bindDirectory(
  path,
  { create = false, privateParents = 0 } = {},
) {
  absolutePath(path);
  const bindings = [];
  try {
    let current = parse(path).root;
    let handle = await open(current, DIRECTORY_FLAGS);
    bindings.push({
      path: current,
      handle,
      identity: await handle.stat({ bigint: true }),
    });
    for (const name of relative(current, path).split(sep).filter(Boolean)) {
      const child = join(await descriptorPath(handle), name);
      let next;
      try {
        next = await open(child, DIRECTORY_FLAGS);
      } catch (error) {
        if (!create || error.code !== "ENOENT") throw error;
        try {
          await mkdir(child, { mode: 0o700 });
          await handle.sync();
        } catch (cause) {
          if (cause.code !== "EEXIST") throw cause;
        }
        next = await open(child, DIRECTORY_FLAGS);
      }
      current = join(current, name);
      handle = next;
      bindings.push({
        path: current,
        handle,
        identity: await handle.stat({ bigint: true }),
      });
    }
    const verify = async () => {
      for (const binding of bindings) {
        const actual = await lstat(binding.path, { bigint: true });
        if (
          !actual.isDirectory() ||
          actual.dev !== binding.identity.dev ||
          actual.ino !== binding.identity.ino ||
          actual.mode !== binding.identity.mode ||
          actual.uid !== binding.identity.uid ||
          (await realpath(binding.path)) !== binding.path
        )
          throw new RuntimePayloadError("Runtime directory identity changed.");
      }
    };
    await verify();
    if (bindings.length <= privateParents)
      throw new RuntimePayloadError("Runtime storage ancestry is incomplete.");
    for (const binding of bindings.slice(-1 - privateParents, -1))
      assertOwned(binding.identity, 0o700);
    return {
      handle,
      anchor: await descriptorPath(handle),
      verify,
      close: async () => {
        for (const binding of bindings.reverse()) await binding.handle.close();
      },
    };
  } catch (error) {
    for (const binding of bindings.reverse()) await binding.handle.close();
    throw error;
  }
}

export async function readRegular(path, maximum = 64 * 1024 * 1024) {
  const before = await lstat(path, { bigint: true });
  if (!before.isFile() || before.nlink !== 1n || before.size > BigInt(maximum))
    throw new RuntimePayloadError(
      "Runtime input is not a bounded, unlinked regular file.",
    );
  const handle = await open(path, FILE_FLAGS);
  try {
    if (!sameFile(before, await handle.stat({ bigint: true })))
      throw new RuntimePayloadError("Runtime input changed before reading.");
    const bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(
        bytes,
        offset,
        bytes.length - offset,
        offset,
      );
      if (bytesRead === 0)
        throw new RuntimePayloadError(
          "Runtime input was truncated while reading.",
        );
      offset += bytesRead;
    }
    if ((await handle.read(Buffer.alloc(1), 0, 1, offset)).bytesRead !== 0)
      throw new RuntimePayloadError("Runtime input grew while reading.");
    if (
      !sameFile(before, await handle.stat({ bigint: true })) ||
      !sameFile(before, await lstat(path, { bigint: true }))
    )
      throw new RuntimePayloadError("Runtime input changed while reading.");
    return { bytes, metadata: before };
  } finally {
    await handle.close();
  }
}
