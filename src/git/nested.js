import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import { dirname, join } from "node:path";

import { decodeNullList, GitSafetyError } from "./command.js";

export function unsupportedNestedRepository() {
  return new GitSafetyError(
    "Git content observation does not support gitlinks or embedded repositories.",
    { code: "ERR_UNSUPPORTED_GIT_PATH" },
  );
}

function race(cause) {
  return new GitSafetyError("Repository content changed during snapshot.", {
    cause,
    code: "ERR_GIT_SNAPSHOT_RACE",
  });
}

function sourcePaths(value, index) {
  return decodeNullList(value, "Git source entries").map((record) => {
    const separator = record.indexOf("\t");
    const fields = record.slice(0, separator).split(" ");
    const path = record.slice(separator + 1);
    if (
      separator === -1 ||
      fields.length !== 3 ||
      !["100644", "100755", "120000"].includes(fields[0]) ||
      !/^[a-f0-9]{40}(?:[a-f0-9]{24})?$/u.test(fields[index ? 1 : 2]) ||
      (index ? !/^[0-3]$/u.test(fields[2]) : fields[1] !== "blob")
    )
      throw unsupportedNestedRepository();
    return path;
  });
}

// Literal tree/index metadata cannot run nested worktree programs. Inspect all
// entries, even unchanged, index-hidden, deleted, ignored or allowed paths.
export async function supportedTrackedPaths({ runGit }, repositoryPath, head) {
  const tree =
    head === null
      ? Buffer.alloc(0)
      : (
          await runGit(repositoryPath, [
            "--no-replace-objects",
            "ls-tree",
            "-r",
            "-z",
            "--full-tree",
            head,
          ])
        ).stdout;
  const index = await runGit(repositoryPath, ["ls-files", "--stage", "-z"]);
  return [
    ...new Set([
      ...sourcePaths(tree, false),
      ...sourcePaths(index.stdout, true),
    ]),
  ];
}

async function metadata(path) {
  try {
    return await lstat(path, { bigint: true });
  } catch (cause) {
    if (cause.code === "ENOENT" || cause.code === "ENOTDIR") return null;
    throw race(cause);
  }
}

function same(left, right) {
  return left === null || right === null
    ? left === right
    : ["dev", "ino", "mode", "size", "mtimeNs", "ctimeNs"].every(
        (key) => left[key] === right[key],
      );
}

async function inspectDirectory(path, before, repositoryPath) {
  let handle;
  try {
    handle = await open(
      path,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
    );
    if (
      !same(before, await handle.stat({ bigint: true })) ||
      (await realpath(path)) !== path
    )
      throw race();
    // Descriptor anchoring prevents a replacement link from redirecting these
    // metadata-only reads. Never open or interpret nested Git configuration.
    const anchor = `/proc/self/fd/${handle.fd}`;
    if (path !== repositoryPath) {
      if (await metadata(join(anchor, ".git")))
        throw unsupportedNestedRepository();
      const [head, objects, refs] = await Promise.all(
        ["HEAD", "objects", "refs"].map((name) => metadata(join(anchor, name))),
      );
      if (
        (head?.isFile() || head?.isSymbolicLink()) &&
        (objects?.isDirectory() || objects?.isSymbolicLink()) &&
        (refs?.isDirectory() || refs?.isSymbolicLink())
      )
        throw unsupportedNestedRepository();
    }
    if (
      !same(before, await handle.stat({ bigint: true })) ||
      !same(before, await metadata(path)) ||
      (await realpath(path)) !== path
    )
      throw race();
  } catch (cause) {
    if (cause instanceof GitSafetyError) throw cause;
    throw race(cause);
  } finally {
    await handle?.close();
  }
}

// Git prunes ignored untracked trees. Check only selected source ancestors and
// directory candidates, without following pointers, links or arbitrary subtrees.
// Recheck the same bindings after content reads; absence grants no authority.
export async function inspectContentDirectories(repositoryPath, paths, signal) {
  const directories = new Set([repositoryPath]);
  for (const path of paths) {
    signal?.throwIfAborted();
    const parts = path.replace(/\/$/u, "").split("/");
    if (parts.some((part) => !part || [".", "..", ".git"].includes(part)))
      throw unsupportedNestedRepository();
    let current = repositoryPath;
    for (const part of path.endsWith("/") ? parts : parts.slice(0, -1)) {
      current = join(current, part);
      directories.add(current);
    }
  }
  const bindings = new Map();
  for (const path of [...directories].sort()) {
    signal?.throwIfAborted();
    if (path !== repositoryPath && !bindings.get(dirname(path))?.isDirectory())
      continue;
    const stat = await metadata(path);
    bindings.set(path, stat);
    if (stat?.isDirectory()) await inspectDirectory(path, stat, repositoryPath);
  }
  signal?.throwIfAborted();
  return async () => {
    for (const [path, before] of bindings) {
      signal?.throwIfAborted();
      if (!same(before, await metadata(path))) throw race();
      if (before?.isDirectory())
        await inspectDirectory(path, before, repositoryPath);
    }
    signal?.throwIfAborted();
  };
}
