import { lstat } from "node:fs/promises";
import { join } from "node:path";

import { decodeNullList, GitSafetyError, hashBuffer } from "./command.js";
import { safeRelativePath } from "./materialization.js";

const OBJECT_ID = /^[a-f0-9]{40}(?:[a-f0-9]{24})?$/u;

function unsupported() {
  return new GitSafetyError(
    "Git source selection contains an unsupported path or entry.",
    {
      code: "ERR_UNSUPPORTED_GIT_PATH",
    },
  );
}

function changed(cause) {
  return new GitSafetyError("Git source membership or provenance changed.", {
    cause,
    code: "ERR_GIT_SOURCE_SELECTION_CHANGED",
  });
}

function trackedPaths(value, index) {
  const paths = new Set();
  for (const record of decodeNullList(value, "Git source entries")) {
    const separator = record.indexOf("\t");
    const fields = record.slice(0, separator).split(" ");
    const path = record.slice(separator + 1);
    const [mode, middle, last] = fields;
    if (
      separator === -1 ||
      fields.length !== 3 ||
      !safeRelativePath(path) ||
      !OBJECT_ID.test(index ? middle : last)
    )
      throw unsupported();
    if (index && last !== "0") {
      throw new GitSafetyError(
        "Git index contains unresolved source entries.",
        {
          code: "ERR_UNSAFE_GIT_STATE",
        },
      );
    }
    // Never turn a gitlink (or a sparse directory entry) into a recursive
    // filesystem root. Existing Git snapshot/gitlink behavior stays separate.
    if (
      !["100644", "100755", "120000"].includes(mode) ||
      (!index && middle !== "blob") ||
      paths.has(path)
    )
      throw unsupported();
    paths.add(path);
  }
  return [...paths];
}

async function membership(
  { currentHead, indexFingerprint, runGit },
  projectPath,
) {
  const head = await currentHead(projectPath);
  if (head !== null && !OBJECT_ID.test(head)) throw unsupported();
  const tree =
    head === null
      ? Buffer.alloc(0)
      : (
          await runGit(projectPath, [
            "--no-replace-objects",
            "ls-tree",
            "-r",
            "-z",
            "--full-tree",
            head,
          ])
        ).stdout;
  const index = (await runGit(projectPath, ["ls-files", "--stage", "-z"]))
    .stdout;
  // Git prunes ignored untracked trees. Do not enumerate directories ourselves
  // or use status/diff, which omit unchanged and index-hidden tracked sources.
  const others = (
    await runGit(projectPath, [
      "ls-files",
      "--others",
      "--exclude-standard",
      "-z",
    ])
  ).stdout;
  const tracked = [
    ...new Set([...trackedPaths(tree, false), ...trackedPaths(index, true)]),
  ].sort();
  const untracked = decodeNullList(others, "Untracked Git sources");
  if (untracked.some((path) => !safeRelativePath(path))) throw unsupported();
  const trackedSet = new Set(tracked);
  return {
    head,
    indexFingerprint: await indexFingerprint(projectPath),
    trackedPaths: tracked,
    untrackedPaths: [
      ...new Set(untracked.filter((path) => !trackedSet.has(path))),
    ].sort(),
  };
}

async function sourceKinds(projectPath, paths, tracked, signal) {
  const kinds = new Map();
  const ancestors = new Map();
  for (const path of paths) {
    signal?.throwIfAborted();
    let parent = projectPath;
    let missing = false;
    const parts = path.split("/");
    // Check real routing ancestors before touching a leaf. Leaf symlinks are
    // selected as links; their targets remain the workspace capture's concern.
    for (const part of parts.slice(0, -1)) {
      signal?.throwIfAborted();
      parent = join(parent, part);
      if (!ancestors.has(parent)) {
        try {
          const stat = await lstat(parent);
          if (!stat.isDirectory()) throw unsupported();
          ancestors.set(parent, true);
        } catch (cause) {
          if (cause.code !== "ENOENT") throw cause;
          ancestors.set(parent, false);
        }
      }
      if (!ancestors.get(parent)) {
        missing = true;
        break;
      }
    }
    let kind = "missing";
    if (!missing) {
      try {
        const stat = await lstat(join(projectPath, path));
        if (!stat.isFile() && !stat.isSymbolicLink()) throw unsupported();
        kind = stat.isFile() ? "file" : "symlink";
      } catch (cause) {
        if (cause.code !== "ENOENT") throw cause;
      }
    }
    if (kind === "missing" && !tracked.has(path)) throw changed();
    kinds.set(path, kind);
  }
  return kinds;
}

// Membership/provenance only: workspace-owned confined capture supplies bytes,
// identities, link safety and content fingerprints. Re-select around capture
// with the saved fingerprint to detect new, removed or reclassified sources.
export async function selectSourcesAtRoot(
  context,
  projectPath,
  expectedSelectionFingerprint,
) {
  try {
    const before = await membership(context, projectPath);
    const paths = [...before.trackedPaths, ...before.untrackedPaths].sort();
    const tracked = new Set(before.trackedPaths);
    const kinds = await sourceKinds(
      projectPath,
      paths,
      tracked,
      context.signal,
    );
    const after = await membership(context, projectPath);
    if (JSON.stringify(before) !== JSON.stringify(after)) throw changed();
    const currentKinds = await sourceKinds(
      projectPath,
      paths,
      tracked,
      context.signal,
    );
    if (paths.some((path) => kinds.get(path) !== currentKinds.get(path)))
      throw changed();
    const selection = {
      projectPath,
      ...before,
      deletedPaths: paths.filter((path) => kinds.get(path) === "missing"),
      inspection: Object.freeze({
        inspectionPaths: Object.freeze(
          paths.map((path) => join(projectPath, path)),
        ),
        inspectionFilesOnly: true,
      }),
    };
    const selectionFingerprint = hashBuffer(JSON.stringify(selection));
    if (
      expectedSelectionFingerprint !== undefined &&
      expectedSelectionFingerprint !== selectionFingerprint
    )
      throw changed();
    for (const value of Object.values(selection)) {
      if (Array.isArray(value)) Object.freeze(value);
    }
    return Object.freeze({ ...selection, selectionFingerprint });
  } catch (cause) {
    if (context.signal?.aborted) throw context.signal.reason;
    if (cause instanceof GitSafetyError) throw cause;
    throw new GitSafetyError("Cannot safely select Git workspace sources.", {
      cause,
      code: "ERR_GIT_SOURCE_SELECTION",
    });
  }
}
