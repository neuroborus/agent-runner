import { constants } from "node:fs";
import { lstat, mkdir, open, realpath, rename, unlink } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, relative, sep } from "node:path";

import {
  contentHash,
  GuidanceError,
  MAX_GUIDANCE_BYTES,
  unsafePath,
  validateContent,
} from "./content.js";
import { FILE_IDENTITY_FIELDS } from "./contract.js";

const READ_FLAGS =
  constants.O_RDONLY |
  (constants.O_NOFOLLOW ?? 0) |
  (constants.O_NONBLOCK ?? 0);
const DIRECTORY_FLAGS = READ_FLAGS | (constants.O_DIRECTORY ?? 0);

async function metadata(path) {
  try {
    return await lstat(path, { bigint: true });
  } catch (cause) {
    if (cause?.code === "ENOENT") return null;
    throw unsafePath(cause);
  }
}

function fileIdentity(stat) {
  return Object.fromEntries(
    FILE_IDENTITY_FIELDS.map((key) => [key, stat[key].toString()]),
  );
}

export function sameFile(left, right, { renamed = false } = {}) {
  if (left === null || right === null) return left === right;
  return Object.keys(left).every(
    (key) => (renamed && key === "ctimeNs") || left[key] === right[key],
  );
}

function assertFile(stat) {
  if (!stat?.isFile() || stat.nlink !== 1n) throw unsafePath();
  if (stat.size > BigInt(MAX_GUIDANCE_BYTES)) {
    throw new GuidanceError(
      "Guidance must be a Markdown document of at most 64 KiB.",
    );
  }
}

export async function readDocument(path) {
  const before = await metadata(path);
  if (before === null) return { content: "", hash: null, identity: null };
  assertFile(before);
  let handle;
  try {
    handle = await open(path, READ_FLAGS);
    const opened = await handle.stat({ bigint: true });
    assertFile(opened);
    if (!sameFile(fileIdentity(before), fileIdentity(opened)))
      throw unsafePath();
    const buffer = Buffer.alloc(MAX_GUIDANCE_BYTES + 1);
    let length = 0;
    while (length < buffer.length) {
      const { bytesRead } = await handle.read(
        buffer,
        length,
        buffer.length - length,
        length,
      );
      if (bytesRead === 0) break;
      length += bytesRead;
    }
    const after = await handle.stat({ bigint: true });
    const atPath = await metadata(path);
    assertFile(after);
    assertFile(atPath);
    const identity = fileIdentity(after);
    if (
      !sameFile(fileIdentity(opened), identity) ||
      !sameFile(identity, fileIdentity(atPath))
    )
      throw unsafePath();
    if (length > MAX_GUIDANCE_BYTES)
      throw new GuidanceError("Guidance exceeds the 64 KiB limit.");
    let content;
    try {
      content = new TextDecoder("utf-8", {
        fatal: true,
        ignoreBOM: true,
      }).decode(buffer.subarray(0, length));
    } catch (cause) {
      throw new GuidanceError("Guidance must contain valid UTF-8.", { cause });
    }
    validateContent(content);
    return { content, hash: contentHash(content), identity };
  } catch (cause) {
    if (cause instanceof GuidanceError) throw cause;
    throw unsafePath(cause);
  } finally {
    await handle?.close();
  }
}

async function descriptorPath(handle, expectedPath) {
  for (const root of ["/proc/self/fd", "/dev/fd"]) {
    const path = join(root, String(handle.fd));
    try {
      if ((await realpath(path)) === expectedPath) return path;
    } catch (cause) {
      if (!["ENOENT", "ENOTDIR", "EACCES"].includes(cause?.code))
        throw unsafePath(cause);
    }
  }
  throw new GuidanceError(
    "Confined directory-descriptor access is unavailable.",
    { code: "ERR_GUIDANCE_STORAGE_UNAVAILABLE" },
  );
}

// Keep filesystem effects relative to open directories, so replacing a lexical
// ancestor cannot redirect a read, temporary write, rename, or cleanup elsewhere.
export async function openLocalDirectory(
  projectPath,
  localPath,
  { create = false } = {},
) {
  const pathFromProject = relative(projectPath, dirname(localPath));
  const components = pathFromProject.split(sep);
  if (
    !pathFromProject ||
    isAbsolute(pathFromProject) ||
    components.some((part) =>
      ["", ".", "..", ".git", ".agents", ".codex", ".claude"].includes(part),
    ) ||
    basename(localPath) !== "rules.md"
  )
    throw unsafePath();
  const directories = [];
  let missingPath = null;
  async function verify() {
    for (const directory of directories) {
      const current = await metadata(directory.path);
      if (
        !current?.isDirectory() ||
        current.dev !== directory.stat.dev ||
        current.ino !== directory.stat.ino
      )
        throw unsafePath();
      if ((await realpath(directory.path)) !== directory.path)
        throw unsafePath();
    }
    if (missingPath !== null && (await metadata(missingPath)) !== null)
      throw unsafePath();
  }
  async function close() {
    for (const directory of directories.toReversed())
      await directory.handle.close();
  }
  try {
    let currentPath = projectPath;
    for (let index = -1; index < components.length; index += 1) {
      await verify();
      const parent = directories.at(-1);
      const anchoredPath = parent
        ? join(parent.anchor, components[index])
        : projectPath;
      if (parent) currentPath = join(currentPath, components[index]);
      let stat = await metadata(anchoredPath);
      // The project is an existing boundary, never an artifact to create.
      if (stat === null && parent === undefined) throw unsafePath();
      if (stat === null && create) {
        try {
          await mkdir(anchoredPath, { mode: 0o700 });
        } catch (cause) {
          if (cause?.code !== "EEXIST") throw cause;
        }
        await parent.handle.sync();
        stat = await metadata(anchoredPath);
      }
      if (stat === null) {
        missingPath = currentPath;
        break;
      }
      if (!stat.isDirectory()) throw unsafePath();
      const handle = await open(anchoredPath, DIRECTORY_FLAGS);
      try {
        const opened = await handle.stat({ bigint: true });
        if (
          !opened.isDirectory() ||
          stat.dev !== opened.dev ||
          stat.ino !== opened.ino
        )
          throw unsafePath();
        const anchor = await descriptorPath(handle, currentPath);
        directories.push({ path: currentPath, stat: opened, handle, anchor });
      } catch (cause) {
        await handle.close();
        throw cause;
      }
    }
    await verify();
    const parent = missingPath === null ? directories.at(-1) : null;
    function child(name) {
      if (!parent || basename(name) !== name || [".", ".."].includes(name))
        throw unsafePath();
      return join(parent.anchor, name);
    }
    return {
      close,
      verify,
      exists: parent !== null,
      async read(name = "rules.md") {
        await verify();
        const result = parent
          ? await readDocument(child(name))
          : { content: "", hash: null, identity: null };
        await verify();
        return result;
      },
      async writeTemporary(name, content, recordIdentity) {
        await verify();
        const handle = await open(
          child(name),
          constants.O_WRONLY |
            constants.O_CREAT |
            constants.O_EXCL |
            (constants.O_NOFOLLOW ?? 0),
          0o600,
        );
        let writtenIdentity;
        try {
          const initial = fileIdentity(await handle.stat({ bigint: true }));
          await recordIdentity(initial);
          await verify();
          const atPath = await metadata(child(name));
          assertFile(atPath);
          if (!sameFile(fileIdentity(atPath), initial)) throw unsafePath();
          await handle.writeFile(content);
          await handle.sync();
          const written = await handle.stat({ bigint: true });
          assertFile(written);
          writtenIdentity = fileIdentity(written);
        } finally {
          await handle.close();
        }
        await parent.handle.sync();
        await verify();
        const document = await this.read(name);
        if (!sameFile(document.identity, writtenIdentity)) throw unsafePath();
        return document;
      },
      async removeTemporary(name, identity) {
        await verify();
        const stat = await metadata(child(name));
        if (stat === null) return;
        if (
          !stat.isFile() ||
          stat.nlink !== 1n ||
          !["dev", "ino", "birthtimeNs"].every(
            (key) => stat[key].toString() === identity[key],
          )
        )
          throw unsafePath();
        await unlink(child(name));
        await parent.handle.sync();
        await verify();
      },
      async publish(name) {
        await verify();
        await rename(child(name), child("rules.md"));
        await parent.handle.sync();
        await verify();
      },
    };
  } catch (cause) {
    await close();
    if (cause instanceof GuidanceError) throw cause;
    throw unsafePath(cause);
  }
}
