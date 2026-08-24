import { createHash } from "node:crypto";
import { constants } from "node:fs";
import {
  lstat,
  open,
  readlink,
  realpath,
} from "node:fs/promises";
import { dirname, relative, resolve, sep } from "node:path";

import {
  decodeLine,
  decodeNullList,
  GitSafetyError,
  hashBuffer,
  isWithin,
} from "./git-command.js";

const NO_FOLLOW = constants.O_NOFOLLOW ?? 0;

function hashEntries(entries) {
  const hash = createHash("sha256");
  for (const entry of [...entries].sort((left, right) =>
    Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)),
  )) {
    const path = Buffer.from(entry.path);
    const descriptor = Buffer.from(
      JSON.stringify({
        hash: entry.hash,
        kind: entry.kind,
        mode: entry.mode,
        size: entry.size,
      }),
    );
    const lengths = Buffer.allocUnsafe(8);
    lengths.writeUInt32BE(path.length, 0);
    lengths.writeUInt32BE(descriptor.length, 4);
    hash.update(lengths).update(path).update(descriptor);
  }
  return hash.digest("hex");
}

export async function pathsFingerprintAtRoot(
  context,
  repositoryPath,
  requestedPaths,
) {
  const locations = await Promise.all(
    requestedPaths.map((path) => normalizeRepositoryPath(repositoryPath, path)),
  );
  const relativePaths = [
    ...new Set(locations.map(({ relativePath }) => relativePath)),
  ].sort();
  const entries = await Promise.all(
    relativePaths.map((path) =>
      contentEntry(context, repositoryPath, path, {
        allowedPaths: [],
        missingAllowed: true,
      }),
    ),
  );
  return hashEntries(entries);
}

const EMPTY_CONTENT_FINGERPRINT = hashEntries([]);

function literalPathspec(relativePath) {
  return `:(top,literal)${relativePath}`;
}

function hiddenIndexPaths(value) {
  // Git diff hides skip-worktree and assume-unchanged paths.
  return decodeNullList(value, "Git index paths").flatMap((entry) => {
    if (entry.length < 3 || entry[1] !== " ") {
      throw new GitSafetyError("Git index path is invalid.", {
        code: "ERR_UNSUPPORTED_GIT_PATH",
      });
    }
    const tag = entry[0];
    return tag === "S" || (tag >= "a" && tag <= "z")
      ? [entry.slice(2)]
      : [];
  });
}

async function canonicalPotentialPath(requestedPath) {
  const missing = [];
  let currentPath = resolve(requestedPath);
  while (true) {
    try {
      const canonicalParent = await realpath(currentPath);
      return resolve(canonicalParent, ...missing.reverse());
    } catch (cause) {
      if (cause?.code !== "ENOENT") {
        throw cause;
      }
      if (await pathExists(currentPath)) {
        throw cause;
      }
      const parentPath = dirname(currentPath);
      if (parentPath === currentPath) {
        throw cause;
      }
      missing.push(currentPath.slice(parentPath.length + 1));
      currentPath = parentPath;
    }
  }
}

async function pathExists(path) {
  try {
    await lstat(path);
    return true;
  } catch (cause) {
    if (cause?.code === "ENOENT") {
      return false;
    }
    throw cause;
  }
}

function snapshotRace(cause) {
  return new GitSafetyError("Repository content changed during snapshot.", {
    cause,
    code: "ERR_GIT_SNAPSHOT_RACE",
  });
}

function deletedEntry(path) {
  return Object.freeze({
    hash: null,
    kind: "deleted",
    mode: null,
    path,
    size: 0,
  });
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

async function hashRegularFile(filePath) {
  try {
    let handle;
    try {
      handle = await open(filePath, constants.O_RDONLY | NO_FOLLOW);
      const before = await handle.stat({ bigint: true });
      if (!before.isFile()) {
        throw snapshotRace();
      }
      const hash = createHash("sha256");
      for await (const chunk of handle.createReadStream({ autoClose: false })) {
        hash.update(chunk);
      }
      const after = await handle.stat({ bigint: true });
      const pathAfter = await lstat(filePath, { bigint: true });
      if (
        !pathAfter.isFile() ||
        metadataChanged(before, after) ||
        metadataChanged(after, pathAfter)
      ) {
        throw snapshotRace();
      }
      return {
        hash: hash.digest("hex"),
        mode: Number(before.mode & 0o111n) === 0 ? "100644" : "100755",
        size: Number(before.size),
      };
    } finally {
      await handle?.close();
    }
  } catch (cause) {
    if (cause instanceof GitSafetyError) {
      throw cause;
    }
    throw snapshotRace(cause);
  }
}

async function indexTracksGitlink(runGit, repositoryPath, path) {
  const result = await runGit(repositoryPath, [
    "ls-files",
    "--stage",
    "-z",
    "--",
    literalPathspec(path),
  ]);
  return decodeNullList(result.stdout, "Git index entries").some((entry) => {
    const separator = entry.indexOf("\t");
    return (
      entry.startsWith("160000 ") &&
      separator !== -1 &&
      entry.slice(separator + 1) === path
    );
  });
}

async function contentParentIsSafe(
  repositoryPath,
  absolutePath,
  { missingAllowed },
) {
  const parentPath = dirname(absolutePath);
  try {
    const canonicalParent = await realpath(parentPath);
    if (
      canonicalParent === parentPath &&
      isWithin(repositoryPath, canonicalParent)
    ) {
      return true;
    }
  } catch (cause) {
    if (
      !missingAllowed ||
      (cause?.code !== "ENOENT" && cause?.code !== "ENOTDIR")
    ) {
      throw snapshotRace(cause);
    }
    return false;
  }
  if (missingAllowed) {
    return false;
  }
  throw new GitSafetyError("Repository content path escapes through a symlink.", {
    code: "ERR_UNSUPPORTED_GIT_PATH",
  });
}

async function directoryReplacement(
  runGit,
  repositoryPath,
  path,
  missingAllowed,
  cause,
) {
  if (
    missingAllowed &&
    !(await indexTracksGitlink(runGit, repositoryPath, path))
  ) {
    return deletedEntry(path);
  }
  throw new GitSafetyError("Changed repository path is not a file.", {
    cause,
    code: "ERR_UNSUPPORTED_GIT_PATH",
  });
}

export async function normalizeRepositoryPath(
  repositoryPath,
  requestedPath,
) {
  if (
    typeof requestedPath !== "string" ||
    requestedPath.length === 0 ||
    requestedPath.includes("\0")
  ) {
    throw new GitSafetyError("Repository path is invalid.", {
      code: "ERR_UNSAFE_REPOSITORY_PATH",
    });
  }
  const absolutePath = resolve(repositoryPath, requestedPath);
  let canonicalPath;
  try {
    canonicalPath = await canonicalPotentialPath(absolutePath);
  } catch (cause) {
    throw new GitSafetyError("Cannot resolve repository path.", {
      cause,
      code: "ERR_UNSAFE_REPOSITORY_PATH",
    });
  }
  if (
    canonicalPath !== absolutePath ||
    !isWithin(repositoryPath, canonicalPath)
  ) {
    throw new GitSafetyError("Repository path escapes through a symlink.", {
      code: "ERR_UNSAFE_REPOSITORY_PATH",
    });
  }
  const relativePath = relative(repositoryPath, canonicalPath)
    .split(sep)
    .join("/");
  if (
    relativePath.length === 0 ||
    relativePath === ".git" ||
    relativePath.startsWith(".git/")
  ) {
    throw new GitSafetyError("Repository path is outside project content.", {
      code: "ERR_UNSAFE_REPOSITORY_PATH",
    });
  }
  return Object.freeze({
    path: canonicalPath,
    relativePath,
  });
}

export async function inspectPathAtRoot(
  { currentHead, runGit },
  repositoryPath,
  requestedPath,
) {
  const location = await normalizeRepositoryPath(
    repositoryPath,
    requestedPath,
  );
  const pathspec = literalPathspec(location.relativePath);
  const indexResult = await runGit(
    repositoryPath,
    ["ls-files", "--error-unmatch", "--", pathspec],
    { allowedExitCodes: [0, 1] },
  );
  let tracked = indexResult.exitCode === 0;
  const head = await currentHead(repositoryPath);
  if (!tracked && head !== null) {
    const headResult = await runGit(repositoryPath, [
      "ls-tree",
      "-r",
      "--name-only",
      "-z",
      head,
      "--",
      pathspec,
    ]);
    tracked = headResult.stdout.length > 0;
  }
  const ignoredResult = await runGit(
    repositoryPath,
    ["check-ignore", "--no-index", "-q", "--", location.relativePath],
    { allowedExitCodes: [0, 1] },
  );
  const changedResult = await runGit(repositoryPath, [
    "status",
    "--porcelain=v1",
    "-z",
    "--untracked-files=all",
    "--ignore-submodules=none",
    "--",
    pathspec,
  ]);
  const { changedPaths } = await contentChangesAtRoot(
    { currentHead, runGit },
    repositoryPath,
    [],
    { baseHead: head },
  );
  const prefix = `${location.relativePath}/`;
  return Object.freeze({
    ...location,
    changed:
      changedResult.stdout.length > 0 ||
      changedPaths.some(
        (path) => path === location.relativePath || path.startsWith(prefix),
      ),
    exists: await pathExists(location.path),
    ignored: ignoredResult.exitCode === 0,
    tracked,
  });
}

export async function normalizeAllowedPaths(repositoryPath, allowedPaths) {
  const locations = await Promise.all(
    allowedPaths.map((path) => normalizeRepositoryPath(repositoryPath, path)),
  );
  return Object.freeze(
    [...new Set(locations.map((location) => location.relativePath))].sort(),
  );
}

async function contentEntry(
  context,
  repositoryPath,
  path,
  { allowedPaths, missingAllowed },
) {
  const { runGit } = context;
  const absolutePath = resolve(repositoryPath, ...path.split("/"));
  if (
    !(await contentParentIsSafe(repositoryPath, absolutePath, {
      missingAllowed,
    }))
  ) {
    return deletedEntry(path);
  }
  let metadata;
  try {
    metadata = await lstat(absolutePath, { bigint: true });
  } catch (cause) {
    if (
      missingAllowed &&
      (cause?.code === "ENOENT" || cause?.code === "ENOTDIR")
    ) {
      return deletedEntry(path);
    }
    throw snapshotRace(cause);
  }

  if (metadata.isFile()) {
    return Object.freeze({
      ...(await hashRegularFile(absolutePath)),
      kind: "file",
      path,
    });
  }
  if (metadata.isSymbolicLink()) {
    try {
      const target = await readlink(absolutePath, { encoding: "buffer" });
      const after = await lstat(absolutePath, { bigint: true });
      if (!after.isSymbolicLink() || metadataChanged(metadata, after)) {
        throw snapshotRace();
      }
      return Object.freeze({
        hash: hashBuffer(target),
        kind: "symlink",
        mode: "120000",
        path,
        size: target.length,
      });
    } catch (cause) {
      if (cause instanceof GitSafetyError) {
        throw cause;
      }
      throw snapshotRace(cause);
    }
  }
  if (metadata.isDirectory()) {
    let gitlinkRoot;
    try {
      const rootResult = await runGit(absolutePath, [
        "rev-parse",
        "--show-toplevel",
      ]);
      gitlinkRoot = await realpath(
        decodeLine(rootResult.stdout, "Gitlink root"),
      );
    } catch (cause) {
      return directoryReplacement(
        runGit,
        repositoryPath,
        path,
        missingAllowed,
        cause,
      );
    }
    if (gitlinkRoot !== absolutePath) {
      return directoryReplacement(
        runGit,
        repositoryPath,
        path,
        missingAllowed,
        new GitSafetyError("Gitlink root does not match its path.", {
          code: "ERR_UNSUPPORTED_GIT_PATH",
        }),
      );
    }
    const result = await runGit(absolutePath, [
      "rev-parse",
      "--verify",
      "HEAD",
    ]);
    const objectId = decodeLine(result.stdout, "Gitlink HEAD");
    const prefix = `${path}/`;
    const content = await contentFingerprintsAtRoot(
      context,
      absolutePath,
      allowedPaths
        .filter((allowedPath) => allowedPath.startsWith(prefix))
        .map((allowedPath) => allowedPath.slice(prefix.length)),
    );
    const after = await lstat(absolutePath, { bigint: true });
    if (!after.isDirectory() || metadataChanged(metadata, after)) {
      throw snapshotRace();
    }
    return Object.freeze({
      hash: hashBuffer(`${objectId}\0${content.contentFingerprint}`),
      kind: "gitlink",
      mode: "160000",
      path,
      size: objectId.length,
    });
  }
  throw new GitSafetyError("Changed repository path has unsupported type.", {
    code: "ERR_UNSUPPORTED_GIT_PATH",
  });
}

async function headContentEntry(
  { runGit },
  repositoryPath,
  head,
  path,
) {
  const result = await runGit(repositoryPath, [
    "ls-tree",
    "-z",
    head,
    "--",
    literalPathspec(path),
  ]);
  const records = decodeNullList(result.stdout, "Git tree entries");
  const record = records.find((entry) => entry.endsWith(`\t${path}`));
  if (record === undefined) {
    return null;
  }
  const separator = record.indexOf("\t");
  const [mode, type, objectId, ...extra] = record
    .slice(0, separator)
    .split(" ");
  if (
    separator === -1 ||
    extra.length > 0 ||
    !/^[0-7]{6}$/u.test(mode) ||
    !/^[a-f0-9]{40}(?:[a-f0-9]{24})?$/u.test(objectId)
  ) {
    throw new GitSafetyError("Git tree entry is invalid.", {
      code: "ERR_UNSUPPORTED_GIT_PATH",
    });
  }
  if (type === "commit" && mode === "160000") {
    return Object.freeze({
      hash: hashBuffer(`${objectId}\0${EMPTY_CONTENT_FINGERPRINT}`),
      kind: "gitlink",
      mode,
      path,
      size: objectId.length,
    });
  }
  if (type !== "blob" || !["100644", "100755", "120000"].includes(mode)) {
    throw new GitSafetyError("Git tree entry has unsupported type.", {
      code: "ERR_UNSUPPORTED_GIT_PATH",
    });
  }
  const blob = await runGit(repositoryPath, ["cat-file", "blob", objectId]);
  return Object.freeze({
    hash: hashBuffer(blob.stdout),
    kind: mode === "120000" ? "symlink" : "file",
    mode,
    path,
    size: blob.stdout.length,
  });
}

function entriesMatch(left, right) {
  return (
    right !== null &&
    left.hash === right.hash &&
    left.kind === right.kind &&
    left.mode === right.mode &&
    left.size === right.size
  );
}

export async function contentChangesAtRoot(
  context,
  repositoryPath,
  allowedPaths,
  { baseHead } = {},
) {
  const { currentHead, runGit } = context;
  const excludedPaths = new Set(allowedPaths);
  const head = baseHead === undefined
    ? await currentHead(repositoryPath)
    : baseHead;
  const trackedResult =
    head === null
      ? await runGit(repositoryPath, ["ls-files", "--cached", "-z"])
      : await runGit(repositoryPath, [
          "diff",
          "--name-only",
          "--ita-invisible-in-index",
          "--no-ext-diff",
          "--no-textconv",
          "--no-renames",
          "--ignore-submodules=none",
          "-z",
          head,
          "--",
        ]);
  const untrackedResult = await runGit(repositoryPath, [
    "ls-files",
    "--others",
    "--exclude-standard",
    "-z",
  ]);
  const indexResult = await runGit(repositoryPath, [
    "ls-files",
    "-v",
    "-z",
  ]);
  const trackedPaths = new Set(
    decodeNullList(trackedResult.stdout, "Tracked Git paths").filter(
      (path) => !excludedPaths.has(path),
    ),
  );
  for (const path of hiddenIndexPaths(indexResult.stdout)) {
    if (excludedPaths.has(path) || trackedPaths.has(path)) {
      continue;
    }
    if (head === null) {
      trackedPaths.add(path);
      continue;
    }
    const entry = await contentEntry(context, repositoryPath, path, {
      allowedPaths,
      missingAllowed: true,
    });
    const headEntry = await headContentEntry(
      context,
      repositoryPath,
      head,
      path,
    );
    if (!entriesMatch(entry, headEntry)) {
      trackedPaths.add(path);
    }
  }
  const untrackedPaths = [
    ...new Set(
      decodeNullList(untrackedResult.stdout, "Untracked Git paths").map(
        (path) => (path.endsWith("/") ? path.slice(0, -1) : path),
      ),
    ),
  ].filter((path) => !excludedPaths.has(path));
  const trackedEntries = [];
  for (const path of trackedPaths) {
    const entry = await contentEntry(context, repositoryPath, path, {
      allowedPaths,
      missingAllowed: true,
    });
    if (head !== null || entry.kind !== "deleted") {
      trackedEntries.push(entry);
    }
  }
  const untrackedEntries = [];
  for (const path of untrackedPaths) {
    untrackedEntries.push(
      await contentEntry(context, repositoryPath, path, {
        allowedPaths,
        missingAllowed: false,
      }),
    );
  }
  const combinedEntries = new Map();
  for (const entry of [...trackedEntries, ...untrackedEntries]) {
    combinedEntries.set(entry.path, entry);
  }
  return Object.freeze({
    changedPaths: Object.freeze(
      [...new Set([...trackedPaths, ...untrackedPaths])].sort(),
    ),
    contentFingerprint: hashEntries(combinedEntries.values()),
    trackedContentFingerprint: hashEntries(trackedEntries),
    untrackedContentFingerprint: hashEntries(untrackedEntries),
  });
}

export async function contentFingerprintsAtRoot(
  context,
  repositoryPath,
  allowedPaths,
  options,
) {
  const { changedPaths: _changedPaths, ...fingerprints } =
    await contentChangesAtRoot(
      context,
      repositoryPath,
      allowedPaths,
      options,
    );
  return Object.freeze(fingerprints);
}
