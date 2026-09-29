import { createHash } from "node:crypto";
import { constants } from "node:fs";
import {
  lstat,
  mkdir,
  open,
  readlink,
  realpath,
  readdir,
  symlink,
} from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";

import {
  decodeNullList,
  GitSafetyError,
  hashBuffer,
  isWithin,
} from "./command.js";
import { sourceChangesAtRoot } from "./content.js";

const NO_FOLLOW = constants.O_NOFOLLOW ?? 0;
const OBJECT_ID_PATTERN = /^[a-f0-9]{40}(?:[a-f0-9]{24})?$/u;

function materializationError(message, cause) {
  return new GitSafetyError(message, {
    cause,
    code: "ERR_GIT_SOURCE_MATERIALIZATION",
  });
}

function destinationChangedError(cause) {
  return new GitSafetyError("Git source projection destination changed.", {
    cause,
    code: "ERR_GIT_SOURCE_DESTINATION_CHANGED",
  });
}

async function openDestination(rootPath, destinationIdentity) {
  let root;
  try {
    const canonicalRoot = await realpath(rootPath);
    root = await open(
      canonicalRoot,
      constants.O_RDONLY | constants.O_DIRECTORY | NO_FOLLOW,
    );
    const metadata = await root.stat({ bigint: true });
    if (
      canonicalRoot !== rootPath ||
      !metadata.isDirectory() ||
      metadata.uid !== BigInt(process.getuid()) ||
      (metadata.mode & 0o777n) !== 0o700n ||
      String(metadata.dev) !== destinationIdentity.device ||
      String(metadata.ino) !== destinationIdentity.inode ||
      (await readdir(`/proc/self/fd/${root.fd}`)).length !== 0
    ) {
      throw destinationChangedError();
    }
    return { metadata, root };
  } catch (cause) {
    await root?.close();
    if (cause?.code === "ERR_GIT_SOURCE_DESTINATION_CHANGED") throw cause;
    throw destinationChangedError(cause);
  }
}

async function assertDestinationUnchanged(rootPath, before) {
  try {
    const after = await lstat(rootPath, { bigint: true });
    if (
      !after.isDirectory() ||
      after.dev !== before.dev ||
      after.ino !== before.ino ||
      after.uid !== before.uid ||
      (after.mode & 0o777n) !== 0o700n ||
      (await realpath(rootPath)) !== rootPath
    ) {
      throw destinationChangedError();
    }
  } catch (cause) {
    if (cause?.code === "ERR_GIT_SOURCE_DESTINATION_CHANGED") throw cause;
    throw destinationChangedError(cause);
  }
}

function safeRelativePath(path) {
  return (
    typeof path === "string" &&
    path.length > 0 &&
    !isAbsolute(path) &&
    !path.includes("\0") &&
    path !== ".git" &&
    !path.startsWith(".git/") &&
    path
      .split("/")
      .every((part) => part.length > 0 && ![".", ".."].includes(part))
  );
}

async function withDestination(root, path, callback) {
  if (!safeRelativePath(path)) {
    throw materializationError("Git source path is unsafe.");
  }
  const parts = path.split("/");
  const opened = [];
  let parent = root;
  try {
    for (const part of parts.slice(0, -1)) {
      const directoryPath = join(`/proc/self/fd/${parent.fd}`, part);
      await mkdir(directoryPath, { mode: 0o700 }).catch((cause) => {
        if (cause?.code !== "EEXIST") throw cause;
      });
      const directory = await open(
        directoryPath,
        constants.O_RDONLY | constants.O_DIRECTORY | NO_FOLLOW,
      );
      const metadata = await directory.stat({ bigint: true });
      if (
        !metadata.isDirectory() ||
        metadata.uid !== BigInt(process.getuid()) ||
        (metadata.mode & 0o777n) !== 0o700n
      ) {
        await directory.close();
        throw materializationError("Git source projection parent is invalid.");
      }
      opened.push(directory);
      parent = directory;
    }
    return await callback(join(`/proc/self/fd/${parent.fd}`, parts.at(-1)));
  } finally {
    await Promise.all(opened.reverse().map((handle) => handle.close()));
  }
}

function parseHeadEntries(value) {
  const entries = [];
  const paths = new Set();
  for (const record of decodeNullList(value, "Git source tree")) {
    const separator = record.indexOf("\t");
    const metadata =
      separator === -1 ? [] : record.slice(0, separator).split(" ");
    const path = separator === -1 ? "" : record.slice(separator + 1);
    if (
      metadata.length !== 3 ||
      !["100644", "100755", "120000"].includes(metadata[0]) ||
      metadata[1] !== "blob" ||
      !OBJECT_ID_PATTERN.test(metadata[2]) ||
      !safeRelativePath(path) ||
      paths.has(path)
    ) {
      throw materializationError("Git source tree is unsupported.");
    }
    paths.add(path);
    entries.push({
      mode: metadata[0],
      objectId: metadata[2],
      path,
    });
  }
  return entries;
}

function assertNoPathCollisions(entries) {
  const paths = new Set(entries.map(({ path }) => path));
  if (paths.size !== entries.length) {
    throw materializationError("Git source paths are not unique.");
  }
  for (const path of paths) {
    const parts = path.split("/");
    for (let index = 1; index < parts.length; index++) {
      if (paths.has(parts.slice(0, index).join("/"))) {
        throw materializationError("Git source paths overlap.");
      }
    }
  }
}

function assertNoProtectedEntries(repositoryPath, entries, protectedPaths) {
  for (const entry of entries) {
    const sourcePath = resolve(repositoryPath, ...entry.path.split("/"));
    if (
      protectedPaths.some(
        (protectedPath) =>
          isWithin(protectedPath, sourcePath) ||
          isWithin(sourcePath, protectedPath),
      )
    ) {
      throw materializationError(
        "Git source projection overlaps a protected path.",
      );
    }
  }
}

async function writeBuffer(root, path, value, mode) {
  return withDestination(root, path, async (destination) => {
    const handle = await open(
      destination,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | NO_FOLLOW,
      mode,
    );
    try {
      await handle.writeFile(value);
      await handle.chmod(mode);
    } finally {
      await handle.close();
    }
  });
}

async function writeHeadEntry(runGit, repositoryPath, root, entry) {
  const result = await runGit(repositoryPath, [
    "--no-replace-objects",
    "cat-file",
    "blob",
    entry.objectId,
  ]);
  if (entry.mode === "120000") {
    await withDestination(root, entry.path, (destination) =>
      symlink(result.stdout, destination),
    );
    return {
      hash: hashBuffer(result.stdout),
      kind: "symlink",
      mode: entry.mode,
      path: entry.path,
      size: result.stdout.length,
    };
  }
  await writeBuffer(
    root,
    entry.path,
    result.stdout,
    entry.mode === "100755" ? 0o755 : 0o644,
  );
  return {
    hash: hashBuffer(result.stdout),
    kind: "file",
    mode: entry.mode,
    path: entry.path,
    size: result.stdout.length,
  };
}

function metadataChanged(before, after) {
  return (
    before.dev !== after.dev ||
    before.ino !== after.ino ||
    before.mode !== after.mode ||
    before.size !== after.size ||
    before.mtimeNs !== after.mtimeNs ||
    before.ctimeNs !== after.ctimeNs
  );
}

async function writeWorktreeFile(repositoryPath, root, entry) {
  const sourcePath = resolve(repositoryPath, ...entry.path.split("/"));
  const source = await open(sourcePath, constants.O_RDONLY | NO_FOLLOW);
  try {
    const before = await source.stat({ bigint: true });
    if (!before.isFile())
      throw materializationError("Git source file changed type.");
    return await withDestination(root, entry.path, async (targetPath) => {
      const target = await open(
        targetPath,
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | NO_FOLLOW,
        entry.mode === "100755" ? 0o755 : 0o644,
      );
      try {
        const hash = createHash("sha256");
        let size = 0;
        for await (const chunk of source.createReadStream({
          autoClose: false,
        })) {
          hash.update(chunk);
          size += chunk.length;
          let offset = 0;
          while (offset < chunk.length) {
            const written = await target.write(
              chunk,
              offset,
              chunk.length - offset,
            );
            offset += written.bytesWritten;
          }
        }
        await target.chmod(entry.mode === "100755" ? 0o755 : 0o644);
        const after = await source.stat({ bigint: true });
        const pathAfter = await lstat(sourcePath, { bigint: true });
        const digest = hash.digest("hex");
        if (
          !pathAfter.isFile() ||
          metadataChanged(before, after) ||
          metadataChanged(after, pathAfter) ||
          digest !== entry.hash ||
          size !== entry.size
        ) {
          throw materializationError(
            "Git source changed during materialization.",
          );
        }
        return { ...entry };
      } finally {
        await target.close();
      }
    });
  } finally {
    await source.close();
  }
}

async function writeWorktreeSymlink(repositoryPath, root, entry) {
  const sourcePath = resolve(repositoryPath, ...entry.path.split("/"));
  const before = await lstat(sourcePath, { bigint: true });
  if (!before.isSymbolicLink()) {
    throw materializationError("Git source symlink changed type.");
  }
  const target = await readlink(sourcePath, { encoding: "buffer" });
  const after = await lstat(sourcePath, { bigint: true });
  if (
    !after.isSymbolicLink() ||
    metadataChanged(before, after) ||
    target.length !== entry.size ||
    hashBuffer(target) !== entry.hash
  ) {
    throw materializationError("Git source changed during materialization.");
  }
  await withDestination(root, entry.path, (destination) =>
    symlink(target, destination),
  );
  return { ...entry };
}

async function writeWorktreeEntry(repositoryPath, root, entry) {
  if (entry.kind === "file") {
    return writeWorktreeFile(repositoryPath, root, entry);
  }
  if (entry.kind === "symlink") {
    return writeWorktreeSymlink(repositoryPath, root, entry);
  }
  throw materializationError("Git source entry is unsupported.");
}

async function mapLimited(values, limit, callback) {
  const results = new Array(values.length);
  let cursor = 0;
  let failed = false;
  let failure;
  await Promise.all(
    Array.from({ length: Math.min(limit, values.length) }, async () => {
      while (!failed && cursor < values.length) {
        const index = cursor++;
        try {
          results[index] = await callback(values[index], index);
        } catch (cause) {
          if (!failed) {
            failed = true;
            failure = cause;
          }
        }
      }
    }),
  );
  if (failed) throw failure;
  return results;
}

async function inspectProjectedFile(path, relativePath) {
  const handle = await open(path, constants.O_RDONLY | NO_FOLLOW);
  try {
    const before = await handle.stat({ bigint: true });
    const permissions = Number(before.mode & 0o777n);
    if (
      !before.isFile() ||
      before.uid !== BigInt(process.getuid()) ||
      ![0o644, 0o755].includes(permissions)
    ) {
      throw materializationError("Git source projection file is invalid.");
    }
    const hash = createHash("sha256");
    let size = 0;
    for await (const chunk of handle.createReadStream({ autoClose: false })) {
      hash.update(chunk);
      size += chunk.length;
    }
    const after = await handle.stat({ bigint: true });
    const pathAfter = await lstat(path, { bigint: true });
    if (
      !pathAfter.isFile() ||
      metadataChanged(before, after) ||
      metadataChanged(after, pathAfter)
    ) {
      throw materializationError("Git source projection file was substituted.");
    }
    return {
      hash: hash.digest("hex"),
      kind: "file",
      mode: permissions === 0o755 ? "100755" : "100644",
      path: relativePath,
      size,
    };
  } finally {
    await handle.close();
  }
}

async function inspectProjectedSymlink(path, relativePath, before) {
  if (before.uid !== BigInt(process.getuid())) {
    throw materializationError("Git source projection symlink is invalid.");
  }
  const target = await readlink(path, { encoding: "buffer" });
  const after = await lstat(path, { bigint: true });
  if (!after.isSymbolicLink() || metadataChanged(before, after)) {
    throw materializationError(
      "Git source projection symlink was substituted.",
    );
  }
  return {
    hash: hashBuffer(target),
    kind: "symlink",
    mode: "120000",
    path: relativePath,
    size: target.length,
  };
}

async function inspectProjectedDirectory(directory, prefix = "") {
  const directoryBefore = await directory.stat({ bigint: true });
  const entries = [];
  const directoryPath = `/proc/self/fd/${directory.fd}`;
  const names = await readdir(directoryPath);
  for (const name of names) {
    const relativePath = prefix.length === 0 ? name : `${prefix}/${name}`;
    if (!safeRelativePath(relativePath)) {
      throw materializationError("Git source projection path is unsafe.");
    }
    const path = join(directoryPath, name);
    const before = await lstat(path, { bigint: true });
    if (before.isFile()) {
      entries.push(await inspectProjectedFile(path, relativePath));
      continue;
    }
    if (before.isSymbolicLink()) {
      entries.push(await inspectProjectedSymlink(path, relativePath, before));
      continue;
    }
    if (!before.isDirectory()) {
      throw materializationError(
        "Git source projection contains an unsupported entry.",
      );
    }
    const child = await open(
      path,
      constants.O_RDONLY | constants.O_DIRECTORY | NO_FOLLOW,
    );
    try {
      const opened = await child.stat({ bigint: true });
      if (
        metadataChanged(before, opened) ||
        opened.uid !== BigInt(process.getuid()) ||
        (opened.mode & 0o777n) !== 0o700n
      ) {
        throw materializationError(
          "Git source projection directory is invalid.",
        );
      }
      entries.push({ kind: "directory", path: relativePath });
      entries.push(...(await inspectProjectedDirectory(child, relativePath)));
      const after = await child.stat({ bigint: true });
      const pathAfter = await lstat(path, { bigint: true });
      if (
        !pathAfter.isDirectory() ||
        metadataChanged(opened, after) ||
        metadataChanged(after, pathAfter)
      ) {
        throw materializationError(
          "Git source projection directory was substituted.",
        );
      }
    } finally {
      await child.close();
    }
  }
  const directoryAfter = await directory.stat({ bigint: true });
  const namesAfter = new Set(await readdir(directoryPath));
  if (
    metadataChanged(directoryBefore, directoryAfter) ||
    namesAfter.size !== names.length ||
    names.some((name) => !namesAfter.has(name))
  ) {
    throw materializationError(
      "Git source projection directory changed during inspection.",
    );
  }
  return entries;
}

function expectedProjectionEntries(entries) {
  const directories = new Set();
  for (const { path } of entries) {
    const parts = path.split("/");
    for (let index = 1; index < parts.length; index++) {
      directories.add(parts.slice(0, index).join("/"));
    }
  }
  return [
    ...[...directories].map((path) => ({ kind: "directory", path })),
    ...entries,
  ];
}

function projectionEntriesMatch(expectedEntries, actualEntries) {
  const actualByPath = new Map(
    actualEntries.map((entry) => [entry.path, entry]),
  );
  return (
    expectedEntries.length === actualEntries.length &&
    actualEntries.length === actualByPath.size &&
    expectedEntries.every((expected) => {
      const actual = actualByPath.get(expected.path);
      return (
        actual !== undefined &&
        Object.keys(expected).every((key) => expected[key] === actual[key])
      );
    })
  );
}

export function createSourceMaterializer({ currentHead, runGit }) {
  return async function materializeSource({
    baseHead,
    destinationIdentity,
    destinationPath: rootPath,
    expectedContentFingerprint,
    protectedPaths = [],
    repositoryPath,
    signal,
  }) {
    let root;
    try {
      signal?.throwIfAborted();
      let rootMetadata;
      ({ metadata: rootMetadata, root } = await openDestination(
        rootPath,
        destinationIdentity,
      ));
      if (
        baseHead !== null &&
        (typeof baseHead !== "string" || !OBJECT_ID_PATTERN.test(baseHead))
      ) {
        throw materializationError("Git source base is invalid.");
      }
      const changes = await sourceChangesAtRoot(
        { currentHead, runGit },
        repositoryPath,
        { baseHead },
      );
      if (changes.contentFingerprint !== expectedContentFingerprint) {
        throw new GitSafetyError(
          "Git source fingerprint changed before materialization.",
          {
            code: "ERR_GIT_SOURCE_CHANGED",
          },
        );
      }
      const changed = new Map(
        changes.entries.map((entry) => [entry.path, entry]),
      );
      const headEntries =
        baseHead === null
          ? []
          : parseHeadEntries(
              (
                await runGit(repositoryPath, [
                  "--no-replace-objects",
                  "ls-tree",
                  "-r",
                  "-z",
                  "--full-tree",
                  baseHead,
                ])
              ).stdout,
            );
      const projectedHead = headEntries.filter(
        (entry) => !changed.has(entry.path),
      );
      const projectedWorktree = changes.entries.filter(
        (entry) => entry.kind !== "deleted",
      );
      const projectedEntries = [...projectedHead, ...projectedWorktree];
      assertNoPathCollisions(projectedEntries);
      assertNoProtectedEntries(
        repositoryPath,
        projectedEntries,
        protectedPaths,
      );
      const materializedHead = await mapLimited(projectedHead, 8, (entry) =>
        writeHeadEntry(runGit, repositoryPath, root, entry),
      );
      const materializedWorktree = await mapLimited(
        projectedWorktree,
        8,
        (entry) => writeWorktreeEntry(repositoryPath, root, entry),
      );
      signal?.throwIfAborted();
      const materializedEntries = [
        ...materializedHead,
        ...materializedWorktree,
      ];
      if (
        !projectionEntriesMatch(
          expectedProjectionEntries(materializedEntries),
          await inspectProjectedDirectory(root),
        )
      ) {
        throw materializationError("Git source projection is incomplete.");
      }
      const after = await sourceChangesAtRoot(
        { currentHead, runGit },
        repositoryPath,
        { baseHead },
      );
      if (after.contentFingerprint !== expectedContentFingerprint) {
        throw new GitSafetyError(
          "Git source fingerprint changed during materialization.",
          {
            code: "ERR_GIT_SOURCE_CHANGED",
          },
        );
      }
      if ((await currentHead(repositoryPath)) !== baseHead) {
        throw new GitSafetyError(
          "Git source base changed during materialization.",
          {
            code: "ERR_GIT_SOURCE_CHANGED",
          },
        );
      }
      await assertDestinationUnchanged(rootPath, rootMetadata);
      return Object.freeze({
        contentFingerprint: expectedContentFingerprint,
      });
    } catch (cause) {
      if (cause instanceof GitSafetyError || signal?.aborted) throw cause;
      throw materializationError(
        "Git source could not be materialized safely.",
        cause,
      );
    } finally {
      await root?.close();
    }
  };
}
