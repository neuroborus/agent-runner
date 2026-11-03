import { constants } from "node:fs";
import { lstat, mkdir, open, realpath, stat, unlink } from "node:fs/promises";
import { join, parse, relative, sep } from "node:path";

import { IssueError, MAX_ISSUE_BYTES } from "./contract.js";

const DIRECTORY_FLAGS =
  constants.O_RDONLY |
  (constants.O_DIRECTORY ?? 0) |
  (constants.O_NOFOLLOW ?? 0);
const READ_FLAGS =
  constants.O_RDONLY |
  (constants.O_NOFOLLOW ?? 0) |
  (constants.O_NONBLOCK ?? 0);
const CREATE_FLAGS =
  constants.O_WRONLY |
  constants.O_CREAT |
  constants.O_EXCL |
  (constants.O_NOFOLLOW ?? 0);

function unsafe(message, cause) {
  return new IssueError(message, { cause, code: "ERR_UNSAFE_ISSUE_STORE" });
}

function ownership(message) {
  return new IssueError(message, { code: "ERR_ISSUE_REPORT_OWNERSHIP" });
}

function writeError(cause) {
  if (cause instanceof IssueError) return cause;
  return new IssueError("Cannot publish the issue document.", {
    cause,
    code: "ERR_ISSUE_REPORT_WRITE",
  });
}

const ownedByUser = (metadata) =>
  process.getuid === undefined || metadata.uid === BigInt(process.getuid());
const isPrivate = (metadata) =>
  process.getuid === undefined || (metadata.mode & 0o077n) === 0n;
const sameFile = (left, right) =>
  left.dev === right.dev && left.ino === right.ino;

async function descriptorPath(handle) {
  const identity = await handle.stat({ bigint: true });
  for (const root of ["/proc/self/fd", "/dev/fd"]) {
    const path = join(root, String(handle.fd));
    try {
      if (sameFile(await stat(path, { bigint: true }), identity)) return path;
    } catch (cause) {
      if (!["ENOENT", "ENOTDIR"].includes(cause?.code)) throw cause;
    }
  }
  throw unsafe("Issue storage requires descriptor-bound directory access.");
}

async function entry(directory, name) {
  try {
    return await lstat(join(directory, name), { bigint: true });
  } catch (cause) {
    if (cause?.code === "ENOENT") return null;
    throw cause;
  }
}

// Opens every component without following links and keeps the chain bound.
// Missing components are created privately; existing ancestors stay unchanged.
export async function openIssueStore(path) {
  const bindings = [];
  const close = () =>
    Promise.all(bindings.map(({ handle }) => handle.close().catch(() => {})));
  try {
    const root = parse(path).root;
    let current = root;
    let handle = await open(root, DIRECTORY_FLAGS);
    bindings.push({
      path: root,
      handle,
      identity: await handle.stat({ bigint: true }),
    });
    for (const name of relative(root, path).split(sep).filter(Boolean)) {
      const child = join(await descriptorPath(handle), name);
      let next;
      try {
        next = await open(child, DIRECTORY_FLAGS);
      } catch (cause) {
        if (cause?.code !== "ENOENT") throw cause;
        try {
          await mkdir(child, { mode: 0o700 });
          await handle.sync();
        } catch (creationError) {
          if (creationError?.code !== "EEXIST") throw creationError;
        }
        next = await open(child, DIRECTORY_FLAGS);
      }
      handle = next;
      current = join(current, name);
      bindings.push({
        path: current,
        handle,
        identity: await handle.stat({ bigint: true }),
      });
    }
    const { identity } = bindings.at(-1);
    // Shared platform ancestors may be public; the store itself stays private.
    const verify = async () => {
      for (const binding of bindings) {
        const metadata = await lstat(binding.path, { bigint: true });
        if (
          !metadata.isDirectory() ||
          !sameFile(metadata, binding.identity) ||
          (await realpath(binding.path)) !== binding.path
        ) {
          throw unsafe("Issue storage directory identity changed.");
        }
      }
      const [described, current] = await Promise.all([
        handle.stat({ bigint: true }),
        lstat(path, { bigint: true }),
      ]);
      if (
        [described, current].some(
          (metadata) => !ownedByUser(metadata) || !isPrivate(metadata),
        )
      ) {
        throw unsafe("Issue storage must be a private directory of this user.");
      }
    };
    await verify();
    return Object.freeze({
      path,
      device: String(identity.dev),
      inode: String(identity.ino),
      anchor: await descriptorPath(handle),
      sync: () => handle.sync(),
      verify,
      close,
    });
  } catch (cause) {
    await close();
    if (cause instanceof IssueError) throw cause;
    throw unsafe("Cannot open private issue storage safely.", cause);
  }
}

async function readBounded(handle) {
  const buffer = Buffer.alloc(MAX_ISSUE_BYTES + 1);
  let offset = 0;
  while (offset < buffer.length) {
    const { bytesRead } = await handle.read(
      buffer,
      offset,
      buffer.length - offset,
      offset,
    );
    if (bytesRead === 0) break;
    offset += bytesRead;
  }
  return buffer.subarray(0, offset);
}

// Reads a bounded private regular file and proves its identity did not change.
async function readOwned(store, name, linkCount) {
  const path = join(store.anchor, name);
  let handle;
  try {
    handle = await open(path, READ_FLAGS);
    const before = await handle.stat({ bigint: true });
    if (
      !before.isFile() ||
      before.nlink !== linkCount ||
      before.size > BigInt(MAX_ISSUE_BYTES) ||
      !ownedByUser(before) ||
      !isPrivate(before)
    ) {
      throw unsafe("Issue document must be an isolated private regular file.");
    }
    const bytes = await readBounded(handle);
    const [after, current] = await Promise.all([
      handle.stat({ bigint: true }),
      lstat(path, { bigint: true }),
    ]);
    if (
      !sameFile(before, after) ||
      !sameFile(after, current) ||
      after.nlink !== linkCount ||
      after.size !== before.size ||
      after.mtimeNs !== before.mtimeNs ||
      after.ctimeNs !== before.ctimeNs ||
      BigInt(bytes.byteLength) !== after.size
    ) {
      throw unsafe("Issue document changed while it was read.");
    }
    return bytes;
  } catch (cause) {
    if (cause instanceof IssueError) throw cause;
    throw unsafe("Cannot safely read the issue document.", cause);
  } finally {
    await handle?.close();
  }
}

// Birth time distinguishes a recreated file that reuses a device and inode.
const fileIdentity = (metadata) =>
  Object.freeze({
    device: String(metadata.dev),
    inode: String(metadata.ino),
    birthtimeNs: String(metadata.birthtimeNs),
  });

const isBoundFile = (metadata, identity) =>
  identity !== null &&
  metadata.isFile() &&
  ownedByUser(metadata) &&
  Object.entries(fileIdentity(metadata)).every(
    ([field, value]) => identity[field] === value,
  );

// Removes the reserved temporary name only while it is the bound file; a
// substituted or unbound entry is preserved and fails explicitly.
async function removeOwnedTemporary(store, name, identity) {
  const metadata = await entry(store.anchor, name);
  if (metadata !== null) {
    if (!isBoundFile(metadata, identity)) {
      throw ownership("Issue temporary file ownership is uncertain.");
    }
    try {
      await unlink(join(store.anchor, name));
    } catch (cause) {
      if (cause?.code !== "ENOENT") throw cause;
    }
  }
  await store.sync();
}

// Durably binds the exclusive file's identity before writing its content.
async function writeTemporary(store, name, bytes, bindTemporary) {
  const handle = await open(join(store.anchor, name), CREATE_FLAGS, 0o600);
  let identity = null;
  let written = false;
  try {
    const metadata = await handle.stat({ bigint: true });
    if (!metadata.isFile() || metadata.nlink !== 1n) {
      throw unsafe("Issue temporary file is unsafe.");
    }
    identity = fileIdentity(metadata);
    await bindTemporary(identity);
    await handle.writeFile(bytes);
    await handle.sync();
    written = true;
    return identity;
  } finally {
    await handle.close();
    if (!written && identity !== null) {
      await removeOwnedTemporary(store, name, identity);
    }
  }
}

// Publishes or recovers one reserved document. A completed hard link to the
// reserved temporary file proves ownership until the published phase is durable.
export async function publishIssue(
  store,
  {
    name,
    temporaryName,
    temporaryIdentity,
    bytes,
    phase,
    bindTemporary,
    markPublished,
    linkFile,
  },
) {
  let identity = temporaryIdentity;
  await store.verify();
  const [published, temporary] = await Promise.all([
    entry(store.anchor, name),
    entry(store.anchor, temporaryName),
  ]);
  if (published !== null) {
    if (
      temporary === null
        ? phase !== "published"
        : !sameFile(published, temporary) ||
          published.nlink !== 2n ||
          !isBoundFile(temporary, identity)
    ) {
      throw ownership("Issue document ownership is uncertain.");
    }
    if (!(await readOwned(store, name, published.nlink)).equals(bytes)) {
      throw ownership("Issue document content differs from its reservation.");
    }
  } else {
    if (phase === "published") {
      throw ownership("Published issue document is missing.");
    }
    if (temporary !== null) {
      // An interrupted reserved write may leave an incomplete bound file.
      if (temporary.nlink !== 1n) {
        throw unsafe("Issue temporary file is unsafe.");
      }
      await removeOwnedTemporary(store, temporaryName, identity);
    }
    try {
      identity = await writeTemporary(
        store,
        temporaryName,
        bytes,
        bindTemporary,
      );
    } catch (cause) {
      throw writeError(cause);
    }
    await store.verify();
    try {
      await linkFile(
        join(store.anchor, temporaryName),
        join(store.anchor, name),
      );
    } catch (cause) {
      if (cause?.code !== "EEXIST") {
        // The link may exist; retain the temporary file as ownership proof.
        throw writeError(cause);
      }
      await removeOwnedTemporary(store, temporaryName, identity);
      throw ownership("Issue identity collides with an existing document.");
    }
  }
  // The final entry is durable and private before the phase claims it.
  await store.sync();
  await store.verify();
  if (phase !== "published") {
    await markPublished();
  }
  await removeOwnedTemporary(store, temporaryName, identity);
  await store.verify();
  if (!(await readOwned(store, name, 1n)).equals(bytes)) {
    throw ownership("Published issue document content is invalid.");
  }
}
