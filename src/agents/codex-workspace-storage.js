import {
  lstat,
  mkdir,
  mkdtemp,
  realpath,
  rm,
} from "node:fs/promises";
import { isAbsolute, join, relative, resolve, sep } from "node:path";

const STORAGE_PARENT =
  process.platform === "darwin" ? "/private/tmp" : "/tmp";
const STORAGE_PREFIX = "agent-runner-codex-workspace-";
const DIRECTORY_MODE = 0o700;
const DIRECTORY_MODE_BIGINT = 0o700n;
const STORAGE_DIRECTORIES = Object.freeze({
  TMPDIR: "tmp",
  XDG_CACHE_HOME: "cache",
  XDG_RUNTIME_DIR: "runtime",
});

export class CodexWorkspaceStorageError extends Error {
  constructor(message, { cause } = {}) {
    super(message, { cause });
    this.name = "CodexWorkspaceStorageError";
    this.code = "ERR_CODEX_WORKSPACE_STORAGE";
  }
}

function storageError(message, cause) {
  return new CodexWorkspaceStorageError(message, { cause });
}

function isWithin(parentPath, childPath) {
  const pathFromParent = relative(parentPath, childPath);
  return (
    pathFromParent.length > 0 &&
    !isAbsolute(pathFromParent) &&
    pathFromParent !== ".." &&
    !pathFromParent.startsWith(`..${sep}`)
  );
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

async function inspectParent(parentPath, expectedIdentity) {
  const before = await lstat(parentPath, { bigint: true });
  const canonicalPath = await realpath(parentPath);
  const metadata = await lstat(parentPath, { bigint: true });
  if (
    !sameIdentity(before, metadata) ||
    metadata.isSymbolicLink() ||
    !metadata.isDirectory() ||
    canonicalPath !== parentPath ||
    (expectedIdentity !== undefined &&
      !sameIdentity(metadata, expectedIdentity))
  ) {
    throw storageError("Codex workspace storage parent is unsafe.");
  }
  return metadata;
}

async function inspectOwnedDirectory(
  path,
  { expectedIdentity, expectedOwner, rootPath },
) {
  const before = await lstat(path, { bigint: true });
  const canonicalPath = await realpath(path);
  const metadata = await lstat(path, { bigint: true });
  if (
    !sameIdentity(before, metadata) ||
    metadata.isSymbolicLink() ||
    !metadata.isDirectory() ||
    canonicalPath !== path ||
    metadata.uid !== expectedOwner ||
    (metadata.mode & 0o7777n) !== DIRECTORY_MODE_BIGINT ||
    (expectedIdentity !== undefined &&
      !sameIdentity(metadata, expectedIdentity)) ||
    (rootPath !== undefined && !isWithin(rootPath, canonicalPath))
  ) {
    throw storageError("Codex workspace storage directory is unsafe.");
  }
  return metadata;
}

async function inspectCreatedRoot(rootPath, { expectedOwner, parentPath }) {
  const before = await lstat(rootPath, { bigint: true });
  const canonicalPath = await realpath(rootPath);
  const metadata = await lstat(rootPath, { bigint: true });
  if (
    !sameIdentity(before, metadata) ||
    metadata.isSymbolicLink() ||
    !metadata.isDirectory() ||
    canonicalPath !== rootPath ||
    metadata.uid !== expectedOwner ||
    !isWithin(parentPath, canonicalPath)
  ) {
    throw storageError("Codex workspace storage identity changed.");
  }
  return metadata;
}

async function inspectRootForRemoval(
  rootPath,
  { expectedIdentity, expectedOwner, parentPath },
) {
  const metadata = await inspectCreatedRoot(rootPath, {
    expectedOwner,
    parentPath,
  });
  if (!sameIdentity(metadata, expectedIdentity)) {
    throw storageError("Codex workspace storage identity changed.");
  }
}

async function assertRemoved(path) {
  try {
    await lstat(path);
  } catch (cause) {
    if (cause?.code === "ENOENT") {
      return;
    }
    throw cause;
  }
  throw storageError("Codex workspace storage cleanup was incomplete.");
}

export function assertCodexWorkspaceStorage(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    typeof value.rootPath !== "string" ||
    !isAbsolute(value.rootPath) ||
    value.shellEnvironment === null ||
    typeof value.shellEnvironment !== "object" ||
    Array.isArray(value.shellEnvironment) ||
    typeof value.cleanup !== "function"
  ) {
    throw storageError("Codex workspace storage is invalid.");
  }
  const names = Object.keys(STORAGE_DIRECTORIES);
  if (
    Object.keys(value.shellEnvironment).length !== names.length ||
    names.some(
      (name) =>
        value.shellEnvironment[name] !==
        join(value.rootPath, STORAGE_DIRECTORIES[name]),
    )
  ) {
    throw storageError("Codex workspace storage environment is invalid.");
  }
  return value;
}

export async function createCodexWorkspaceStorage({
  parentPath = STORAGE_PARENT,
} = {}) {
  if (
    typeof parentPath !== "string" ||
    !isAbsolute(parentPath) ||
    resolve(parentPath) !== parentPath ||
    typeof process.geteuid !== "function"
  ) {
    throw storageError("Codex workspace storage is unavailable.");
  }
  const expectedOwner = BigInt(process.geteuid());
  let parentIdentity;
  let rootIdentity;
  let rootPath;
  const childIdentities = new Map();
  try {
    parentIdentity = await inspectParent(parentPath);
    rootPath = await mkdtemp(join(parentPath, STORAGE_PREFIX));
    rootIdentity = await inspectCreatedRoot(rootPath, {
      expectedOwner,
      parentPath,
    });
    await inspectOwnedDirectory(rootPath, {
      expectedIdentity: rootIdentity,
      expectedOwner,
      rootPath: parentPath,
    });
    const shellEnvironment = {};
    for (const [name, directory] of Object.entries(STORAGE_DIRECTORIES)) {
      const childPath = join(rootPath, directory);
      await mkdir(childPath, { mode: DIRECTORY_MODE });
      childIdentities.set(
        childPath,
        await inspectOwnedDirectory(childPath, {
          expectedOwner,
          rootPath,
        }),
      );
      shellEnvironment[name] = childPath;
    }
    await inspectParent(parentPath, parentIdentity);
    await inspectOwnedDirectory(rootPath, {
      expectedIdentity: rootIdentity,
      expectedOwner,
      rootPath: parentPath,
    });

    let cleaned = false;
    const storage = {
      rootPath,
      shellEnvironment: Object.freeze(shellEnvironment),
      async cleanup() {
        if (cleaned) {
          return;
        }
        let validationFailure;
        try {
          await inspectParent(parentPath, parentIdentity);
          await inspectOwnedDirectory(rootPath, {
            expectedIdentity: rootIdentity,
            expectedOwner,
            rootPath: parentPath,
          });
          for (const [childPath, identity] of childIdentities) {
            await inspectOwnedDirectory(childPath, {
              expectedIdentity: identity,
              expectedOwner,
              rootPath,
            });
          }
        } catch (cause) {
          validationFailure = cause;
        }
        try {
          await inspectParent(parentPath, parentIdentity);
          await inspectRootForRemoval(rootPath, {
            expectedIdentity: rootIdentity,
            expectedOwner,
            parentPath,
          });
          await rm(rootPath, { force: false, recursive: true });
          await assertRemoved(rootPath);
          cleaned = true;
        } catch (cause) {
          throw storageError("Cannot safely clean Codex workspace storage.", cause);
        }
        if (validationFailure !== undefined) {
          throw storageError(
            "Codex workspace storage changed before cleanup.",
            validationFailure,
          );
        }
      },
    };
    return Object.freeze(assertCodexWorkspaceStorage(storage));
  } catch (cause) {
    if (rootPath !== undefined && rootIdentity !== undefined) {
      try {
        await inspectParent(parentPath, parentIdentity);
        await inspectRootForRemoval(rootPath, {
          expectedIdentity: rootIdentity,
          expectedOwner,
          parentPath,
        });
        await rm(rootPath, { force: false, recursive: true });
        await assertRemoved(rootPath);
      } catch (cleanupCause) {
        throw storageError(
          "Cannot safely prepare or clean Codex workspace storage.",
          cleanupCause,
        );
      }
    }
    if (cause instanceof CodexWorkspaceStorageError) {
      throw cause;
    }
    throw storageError("Cannot safely prepare Codex workspace storage.", cause);
  }
}
