import { basename, dirname, isAbsolute, join, relative, sep } from "node:path";

import {
  assertBindings,
  assertSafe,
  identity,
  inspectPath,
  location,
  metadata,
  observation,
  openDirectory,
  overlaps,
  readDirectory,
  same,
  within,
} from "./paths.js";
import { readControlFile } from "./snapshot.js";
import { exclusions, isExcluded } from "./scope.js";

export const CONTROL_NAMES = [
  ".git",
  ".codex",
  ".claude",
  ".agents",
  ".claude.json",
];

// Routing directory identity is stable across unrelated sibling creation.
function resolutionMetadata(stat) {
  return stat.isDirectory() ? identity(stat) : observation(stat);
}

export async function discoverControls(
  fs,
  declarations,
  { recursive = true, checkpoint = async () => {} } = {},
) {
  const { workspacePath, stateRoot } = declarations;
  const excludePaths = exclusions(declarations);
  assertSafe(
    !workspacePath.split(sep).some((part) => CONTROL_NAMES.includes(part)),
    "Workspace cannot be inside a control tree.",
  );
  const paths = new Set();
  const roots = [];
  function protect(path, stateOnly) {
    assertSafe(
      excludePaths.every((excluded) => !overlaps(path, excluded)),
      "Exclusions overlap a protected control boundary.",
    );
    assertSafe(
      !overlaps(path, stateRoot),
      "State storage must be disjoint from discovered controls.",
    );
    if (
      !stateOnly ||
      overlaps(path, workspacePath) ||
      (!recursive &&
        declarations.infrastructurePaths.some((destination) =>
          within(path, destination),
        ))
    )
      paths.add(path);
  }
  // Provider control aliases grant no reads, but every resolution hop must be
  // immutable to the workspace writer, even when later dot segments leave it.
  async function aliasTarget(path) {
    let current = dirname(path);
    let pending = [basename(path)];
    let links = 0;
    const observed = new Map();
    while (pending.length) {
      await checkpoint("controls");
      const component = pending.shift();
      if (component === "" || component === ".") continue;
      current =
        component === ".." ? dirname(current) : join(current, component);
      assertSafe(
        !isExcluded(current, excludePaths),
        "Control dependencies cannot enter excluded trees.",
      );
      assertSafe(
        !within(stateRoot, current) &&
          declarations.outputPaths.every((output) => !within(output, current)),
        "Provider control aliases cannot traverse writable outputs or state storage.",
      );
      const stat = await metadata(fs, current);
      assertSafe(
        stat && (stat.isDirectory() || stat.isFile() || stat.isSymbolicLink()),
        "Provider control aliases must resolve to ordinary content.",
      );
      assertSafe(
        !observed.has(current) ||
          same(observed.get(current), resolutionMetadata(stat)),
        "Provider control aliases changed during resolution.",
        "ERR_WORKSPACE_SNAPSHOT_RACE",
      );
      observed.set(current, resolutionMetadata(stat));
      if (stat.isSymbolicLink()) {
        assertSafe(
          stat.nlink === 1n && ++links <= 40,
          "Provider control aliases are unsafe or cyclic.",
        );
        const target = new TextDecoder("utf-8", {
          fatal: true,
          ignoreBOM: true,
        }).decode(await fs.readlink(current, { encoding: "buffer" }));
        current = isAbsolute(target) ? sep : dirname(current);
        pending = [...target.split(sep), ...pending];
      } else
        assertSafe(
          pending.length === 0 || stat.isDirectory(),
          "Provider control alias ancestors must be directories.",
        );
    }
    for (const [dependency, before] of observed) {
      const after = await metadata(fs, dependency);
      assertSafe(
        after && same(before, resolutionMetadata(after)),
        "Provider control aliases changed during resolution.",
        "ERR_WORKSPACE_SNAPSHOT_RACE",
      );
    }
    assertSafe(
      (await fs.realpath(path)) === current,
      "Provider control aliases changed during resolution.",
      "ERR_WORKSPACE_SNAPSHOT_RACE",
    );
    return current;
  }
  // Internal aliases protect both the link and its canonical target. The target
  // must be a real directory below the parent, outside Git metadata.
  async function internalAlias(parent, path) {
    const target = await aliasTarget(path);
    assertSafe(
      target !== parent && within(parent, target),
      "Provider control aliases must target a directory inside their parent.",
    );
    assertSafe(
      !relative(parent, target).split(sep).includes(".git"),
      "Provider control aliases cannot target Git metadata.",
    );
    assertSafe(
      !within(target, workspacePath),
      "Control metadata cannot contain the workspace.",
    );
    assertSafe(
      (await inspectPath(fs, target)).kind === "directory",
      "Provider control aliases must target a real directory.",
    );
    protect(target, false);
    roots.push({ path: target, stateOnly: false });
  }
  async function pointerDirectory(base, value) {
    let path = isAbsolute(value) ? sep : base;
    for (const component of value.split(sep).filter(Boolean)) {
      await checkpoint("controls");
      path = location(path, component);
      assertSafe(
        !isExcluded(path, excludePaths),
        "Git metadata dependencies cannot enter excluded trees.",
      );
      const inspection = await inspectPath(fs, path);
      assertSafe(
        inspection.kind === "directory",
        "Git metadata pointer ancestors must be real directories.",
      );
    }
    return path;
  }
  async function directory(path, stateOnly) {
    protect(path, stateOnly);
    const inspection = await inspectPath(fs, path);
    assertSafe(
      inspection.kind === "directory",
      "Git metadata must name a real directory.",
    );
    assertSafe(
      !within(path, workspacePath),
      "Control metadata cannot contain the workspace.",
    );
    roots.push({ path, stateOnly });
  }
  async function gitMetadata(path, stateOnly) {
    await directory(path, stateOnly);
    const commonPath = join(path, "commondir");
    if (await metadata(fs, commonPath)) {
      const text = await readControlFile(fs, commonPath);
      const match = /^([^\r\n\0]+)\r?\n?$/u.exec(text);
      assertSafe(match !== null, "Git common-directory pointer is malformed.");
      await directory(await pointerDirectory(path, match[1]), stateOnly);
    }
  }
  async function inspectControls(
    parent,
    { reserve = false, ancestor = false, stateOnly = false } = {},
  ) {
    await checkpoint("controls");
    const [head, objects, refs] = await Promise.all(
      ["HEAD", "objects", "refs"].map((name) =>
        isExcluded(join(parent, name), excludePaths)
          ? null
          : metadata(fs, join(parent, name)),
      ),
    );
    // An opaque marker cannot disguise a bare control boundary when the other
    // markers match. Protect the boundary without inspecting the excluded leaf.
    if (
      (head?.isFile() ||
        head?.isSymbolicLink() ||
        isExcluded(join(parent, "HEAD"), excludePaths)) &&
      (objects?.isDirectory() ||
        objects?.isSymbolicLink() ||
        isExcluded(join(parent, "objects"), excludePaths)) &&
      (refs?.isDirectory() ||
        refs?.isSymbolicLink() ||
        isExcluded(join(parent, "refs"), excludePaths))
    ) {
      await gitMetadata(parent, stateOnly);
    }
    const enclosingRepository =
      ancestor && (await metadata(fs, join(parent, ".git"))) !== null;
    for (const name of CONTROL_NAMES) {
      const path = join(parent, name);
      const stat = await metadata(fs, path);
      if (
        (stateOnly || (ancestor && !enclosingRepository)) &&
        name !== ".git"
      ) {
        if (stat === null) continue;
        const target = await aliasTarget(path);
        assertSafe(
          !overlaps(path, stateRoot) && !overlaps(target, stateRoot),
          "State storage must be disjoint from ancestor provider controls.",
        );
        // Ancestor aliases grant no external snapshot reads. A controls-only
        // query also protects exact infrastructure destinations in their target.
        if (
          overlaps(target, workspacePath) ||
          (!recursive &&
            declarations.infrastructurePaths.some((path) =>
              within(target, path),
            ))
        ) {
          protect(target, false);
          if ((await inspectPath(fs, target)).kind === "directory")
            roots.push({ path: target, stateOnly: false });
        }
        continue;
      }
      if (reserve || stat !== null) protect(path, stateOnly);
      if (stat === null) continue;
      if (stat.isSymbolicLink()) {
        assertSafe(name !== ".git", "Git controls must be ordinary paths.");
        await internalAlias(parent, path);
        continue;
      }
      await inspectPath(fs, path);
      if (name !== ".git") {
        if (!stateOnly && stat.isDirectory()) roots.push({ path, stateOnly });
        continue;
      }
      let gitDirectory = path;
      if (stat.isFile()) {
        const text = await readControlFile(fs, path);
        const match = /^gitdir: ([^\r\n\0]+)\r?\n?$/u.exec(text);
        assertSafe(match !== null, "Git directory pointer is malformed.");
        gitDirectory = await pointerDirectory(parent, match[1]);
      }
      await gitMetadata(gitDirectory, stateOnly);
    }
  }
  async function inspectScope(scope, stateOnly = false, traverse = true) {
    const binding = await inspectPath(fs, scope, {
      missing: true,
      allowLink: true,
    });
    if (recursive && traverse && !stateOnly && binding.kind === "directory")
      roots.push({ path: scope, stateOnly });
    for (
      let path = binding.kind === "directory" ? scope : dirname(scope);
      ;
      path = dirname(path)
    ) {
      if ((await metadata(fs, path))?.isDirectory())
        await inspectControls(path, {
          reserve: path === workspacePath,
          ancestor: path !== scope,
          stateOnly,
        });
      if (path === dirname(path)) break;
    }
  }
  await inspectScope(
    workspacePath,
    false,
    declarations.inspectionPaths === undefined,
  );
  for (const scope of new Set([
    ...(declarations.inspectionPaths ?? []),
    ...declarations.inputPaths,
    ...declarations.sourcePaths,
    ...declarations.configurationPaths,
    ...declarations.artifactPaths,
    ...declarations.infrastructurePaths,
    ...(declarations.inspectionPaths === undefined
      ? []
      : declarations.outputPaths),
    ...(declarations.taskPath ? [declarations.taskPath] : []),
  ]))
    await inspectScope(scope);
  await inspectScope(stateRoot, true);
  // Controls-only queries skip ordinary scope traversal, but still follow all
  // discovered control dependencies. State-only traversal grants no read roots.
  // A later full traversal upgrades an earlier state-only visit.
  const visited = new Map();
  async function descend(path, stateOnly) {
    if (isExcluded(path, excludePaths)) return;
    if (visited.has(path) && (stateOnly || !visited.get(path))) return;
    visited.set(path, stateOnly);
    await inspectControls(path, { stateOnly });
    const parent = await openDirectory(fs, path);
    try {
      const names = await readDirectory(fs, parent.anchor);
      for (const entry of names) {
        await checkpoint("controls");
        if (entry.directory) await descend(join(path, entry.name), stateOnly);
      }
      assertSafe(
        same(
          observation(parent.stat),
          observation(await parent.handle.stat({ bigint: true })),
        ) && (await fs.realpath(parent.anchor)) === path,
        "Workspace directories changed during control discovery.",
        "ERR_WORKSPACE_SNAPSHOT_RACE",
      );
      await assertBindings(fs, [parent.binding]);
    } finally {
      await parent.handle.close();
    }
  }
  for (const { path, stateOnly } of roots) await descend(path, stateOnly);
  return [...paths].sort();
}
