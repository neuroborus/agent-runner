import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import {
  link,
  lstat,
  mkdir,
  open,
  readdir,
  realpath,
  rename,
  unlink,
} from "node:fs/promises";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  normalize,
  relative,
  resolve,
  sep,
} from "node:path";

import { RunStoreError } from "./state-validation.js";

const RESERVED_RUN_PATHS = new Set([
  ".lease",
  ".lease-reclaiming",
  "events.jsonl",
  "progress.md",
  "state.json",
]);
const NO_FOLLOW = constants.O_NOFOLLOW ?? 0;
const READ_REPLACEMENT_ATTEMPTS = 5;

async function openRegularFile(filePath, flags, mode) {
  const attempts = flags === constants.O_RDONLY ? READ_REPLACEMENT_ATTEMPTS : 1;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    let handle;
    try {
      try {
        const metadata = await lstat(filePath);
        if (
          metadata.isSymbolicLink() ||
          !metadata.isFile() ||
          metadata.nlink !== 1
        ) {
          throw new RunStoreError(
            `Managed state path is not a regular file: ${filePath}.`,
            { code: "ERR_UNSAFE_STATE_FILE" },
          );
        }
      } catch (cause) {
        if (cause?.code !== "ENOENT" || !(flags & constants.O_CREAT)) {
          throw cause;
        }
      }

      handle = await open(filePath, flags | NO_FOLLOW, mode);
      const metadata = await handle.stat();
      if (metadata.isFile() && metadata.nlink === 0 && attempt + 1 < attempts) {
        // Atomic replacement may unlink the validated inode before it is read.
        const replacedHandle = handle;
        handle = undefined;
        await replacedHandle.close();
        continue;
      }
      if (!metadata.isFile() || metadata.nlink !== 1) {
        throw new RunStoreError(
          `Managed state path is not a regular file: ${filePath}.`,
          { code: "ERR_UNSAFE_STATE_FILE" },
        );
      }
      return handle;
    } catch (cause) {
      await handle?.close();
      if (
        cause instanceof RunStoreError ||
        !["ELOOP", "EMLINK"].includes(cause?.code)
      ) {
        throw cause;
      }
      throw new RunStoreError(
        `Managed state path must not be a symbolic link: ${filePath}.`,
        { cause, code: "ERR_UNSAFE_STATE_FILE" },
      );
    }
  }
  throw new RunStoreError(
    `Managed state path could not be read: ${filePath}.`,
    {
      code: "ERR_UNSAFE_STATE_FILE",
    },
  );
}

async function syncDirectory(directoryPath) {
  let handle;
  try {
    handle = await open(directoryPath, "r");
    await handle.sync();
  } catch (cause) {
    if (!["EINVAL", "ENOTSUP", "EPERM", "EISDIR"].includes(cause?.code)) {
      throw cause;
    }
  } finally {
    await handle?.close();
  }
}

async function unlinkIfPresent(filePath) {
  try {
    await unlink(filePath);
  } catch (cause) {
    if (cause?.code !== "ENOENT") {
      throw cause;
    }
  }
}

export async function atomicWriteFile(filePath, content) {
  const temporaryPath = join(
    dirname(filePath),
    `.${basename(filePath)}.${process.pid}.${randomUUID()}.tmp`,
  );
  let handle;

  try {
    handle = await open(temporaryPath, "wx", 0o600);
    await handle.writeFile(content);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(temporaryPath, filePath);
    await syncDirectory(dirname(filePath));
  } catch (cause) {
    await handle?.close();
    await unlinkIfPresent(temporaryPath);
    throw cause;
  }
}

export async function appendDurableLine(filePath, value) {
  const handle = await openRegularFile(
    filePath,
    constants.O_APPEND | constants.O_CREAT | constants.O_WRONLY,
    0o600,
  );
  try {
    await handle.writeFile(`${value}\n`);
    await handle.sync();
  } finally {
    await handle.close();
  }
  await syncDirectory(dirname(filePath));
}

function isPublicationTemporaryName(filePath, name) {
  const prefix = `.${basename(filePath)}.publish.`;
  if (!name.startsWith(prefix) || !name.endsWith(".tmp")) {
    return false;
  }
  const identity = name.slice(prefix.length, -4);
  const separator = identity.indexOf(".");
  return (
    /^[1-9][0-9]*$/u.test(identity.slice(0, separator)) &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
      identity.slice(separator + 1),
    )
  );
}

async function settleExclusivePublication(filePath) {
  let publishedMetadata;
  try {
    publishedMetadata = await lstat(filePath);
  } catch (cause) {
    if (cause?.code === "ENOENT") {
      return;
    }
    throw cause;
  }
  if (
    publishedMetadata.isSymbolicLink() ||
    !publishedMetadata.isFile() ||
    publishedMetadata.nlink !== 2
  ) {
    return;
  }

  const directoryPath = dirname(filePath);
  const names = await readdir(directoryPath);
  for (const name of names) {
    if (!isPublicationTemporaryName(filePath, name)) {
      continue;
    }
    const temporaryPath = join(directoryPath, name);
    let temporaryMetadata;
    try {
      temporaryMetadata = await lstat(temporaryPath);
    } catch (cause) {
      if (cause?.code === "ENOENT") {
        continue;
      }
      throw cause;
    }
    if (
      !temporaryMetadata.isSymbolicLink() &&
      temporaryMetadata.isFile() &&
      temporaryMetadata.dev === publishedMetadata.dev &&
      temporaryMetadata.ino === publishedMetadata.ino
    ) {
      await unlinkIfPresent(temporaryPath);
      await syncDirectory(directoryPath);
      return;
    }
  }
}

export async function publishExclusiveFile(
  filePath,
  content,
  { onPublicationBoundary = async () => {} } = {},
) {
  const directoryPath = dirname(filePath);
  const temporaryPath = join(
    directoryPath,
    `.${basename(filePath)}.publish.${process.pid}.${randomUUID()}.tmp`,
  );
  let handle;
  let preparedMetadata;
  let published = false;
  try {
    handle = await open(temporaryPath, "wx", 0o600);
    await handle.writeFile(content);
    await handle.sync();
    preparedMetadata = await handle.stat();
    if (!preparedMetadata.isFile() || preparedMetadata.nlink !== 1) {
      throw new RunStoreError(
        `Managed state path is not a regular file: ${temporaryPath}.`,
        { code: "ERR_UNSAFE_STATE_FILE" },
      );
    }
    await handle.close();
    handle = undefined;

    await onPublicationBoundary({ filePath, phase: "prepared" });
    await link(temporaryPath, filePath);
    published = true;
    await onPublicationBoundary({ filePath, phase: "published" });
    await unlinkIfPresent(temporaryPath);
    await syncDirectory(directoryPath);
    const publishedMetadata = await lstat(filePath);
    if (
      !publishedMetadata.isFile() ||
      publishedMetadata.nlink !== 1 ||
      publishedMetadata.dev !== preparedMetadata.dev ||
      publishedMetadata.ino !== preparedMetadata.ino
    ) {
      throw new RunStoreError(
        `Managed state path is not a regular file: ${filePath}.`,
        { code: "ERR_UNSAFE_STATE_FILE" },
      );
    }
  } catch (cause) {
    await handle?.close();
    handle = undefined;
    await unlinkIfPresent(temporaryPath);
    if (published && preparedMetadata !== undefined) {
      try {
        const currentMetadata = await lstat(filePath);
        if (
          currentMetadata.dev === preparedMetadata.dev &&
          currentMetadata.ino === preparedMetadata.ino
        ) {
          await unlinkIfPresent(filePath);
        }
      } catch (cleanupCause) {
        if (cleanupCause?.code !== "ENOENT") {
          throw cleanupCause;
        }
      }
    }
    await syncDirectory(directoryPath);
    throw cause;
  } finally {
    await handle?.close();
  }
}

export async function readOptionalText(filePath) {
  let handle;
  try {
    handle = await openRegularFile(filePath, constants.O_RDONLY);
    return await handle.readFile("utf8");
  } catch (cause) {
    if (cause?.code === "ENOENT") {
      return null;
    }
    throw cause;
  } finally {
    await handle?.close();
  }
}

export async function readOptionalPublishedText(filePath) {
  await settleExclusivePublication(filePath);
  return readOptionalText(filePath);
}

export async function removeFile(filePath) {
  await unlinkIfPresent(filePath);
  await syncDirectory(dirname(filePath));
}

export async function truncateDurableFile(filePath, size) {
  const handle = await openRegularFile(filePath, constants.O_RDWR);
  try {
    await handle.truncate(size);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

function isWithin(parentPath, childPath) {
  const pathFromParent = relative(parentPath, childPath);
  return (
    pathFromParent === "" ||
    (!pathFromParent.startsWith(`..${sep}`) &&
      pathFromParent !== ".." &&
      !isAbsolute(pathFromParent))
  );
}

async function ensureDirectoryWithoutSymlink(directoryPath) {
  try {
    const metadata = await lstat(directoryPath);
    if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
      throw new RunStoreError(
        `Run artifact parent is not a real directory: ${directoryPath}.`,
        { code: "ERR_UNSAFE_RUN_ARTIFACT_PATH" },
      );
    }
  } catch (cause) {
    if (cause?.code !== "ENOENT") {
      throw cause;
    }

    try {
      await mkdir(directoryPath, { mode: 0o700 });
    } catch (mkdirCause) {
      if (mkdirCause?.code !== "EEXIST") {
        throw mkdirCause;
      }
    }
    const metadata = await lstat(directoryPath);
    if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
      throw new RunStoreError(
        `Run artifact parent is not a real directory: ${directoryPath}.`,
        { code: "ERR_UNSAFE_RUN_ARTIFACT_PATH" },
      );
    }
  }
}

export async function resolveRunArtifactPath(runDirectory, relativePath) {
  const components =
    typeof relativePath === "string" ? relativePath.split(/[\\/]/u) : [];
  if (
    typeof relativePath !== "string" ||
    relativePath.length === 0 ||
    relativePath.includes("\0") ||
    components.at(-1) === "" ||
    components.includes("..") ||
    components.at(-1) === "." ||
    isAbsolute(relativePath)
  ) {
    throw new RunStoreError("Run artifact path must be a relative path.", {
      code: "ERR_UNSAFE_RUN_ARTIFACT_PATH",
    });
  }

  const normalizedPath = normalize(relativePath);
  const topLevelPath = normalizedPath.split(sep)[0];
  if (
    normalizedPath === "." ||
    normalizedPath === ".." ||
    normalizedPath.startsWith(`..${sep}`) ||
    RESERVED_RUN_PATHS.has(topLevelPath.toLowerCase())
  ) {
    throw new RunStoreError("Run artifact path escapes its declared area.", {
      code: "ERR_UNSAFE_RUN_ARTIFACT_PATH",
    });
  }

  const canonicalRunDirectory = await realpath(runDirectory);
  const artifactPath = resolve(runDirectory, normalizedPath);
  const parentPath = dirname(artifactPath);
  const parentFromRun = relative(runDirectory, parentPath);
  let currentPath = runDirectory;

  for (const component of parentFromRun.split(sep).filter(Boolean)) {
    currentPath = join(currentPath, component);
    await ensureDirectoryWithoutSymlink(currentPath);
  }

  const canonicalParent = await realpath(parentPath);
  if (!isWithin(canonicalRunDirectory, canonicalParent)) {
    throw new RunStoreError("Run artifact path escapes through a symlink.", {
      code: "ERR_UNSAFE_RUN_ARTIFACT_PATH",
    });
  }

  try {
    const metadata = await lstat(artifactPath);
    if (metadata.isSymbolicLink() || !metadata.isFile()) {
      throw new RunStoreError(
        `Run artifact target is not a regular file: ${relativePath}.`,
        { code: "ERR_UNSAFE_RUN_ARTIFACT_PATH" },
      );
    }
  } catch (cause) {
    if (cause?.code !== "ENOENT") {
      throw cause;
    }
  }

  return artifactPath;
}
