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
  { recursive = true } = {},
) {
  const { workspacePath, stateRoot } = declarations;
  assertSafe(
    !workspacePath.split(sep).some((part) => CONTROL_NAMES.includes(part)),
    "Workspace cannot be inside a control tree.",
  );
  const paths = new Set();
  const roots = [];
  function protect(path, stateOnly) {
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
      const component = pending.shift();
      if (component === "" || component === ".") continue;
      current =
        component === ".." ? dirname(current) : join(current, component);
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
      path = location(path, component);
      const inspection = await inspectPath(fs, path);
      assertSafe(
        inspection.kind === "directory",
        "Git metadata pointer ancestors must be real directories.",
      );
    }
    return path;
  }
  async function directory(path, stateOnly) {
    const inspection = await inspectPath(fs, path);
    assertSafe(
      inspection.kind === "directory",
      "Git metadata must name a real directory.",
    );
    assertSafe(
      !within(path, workspacePath),
      "Control metadata cannot contain the workspace.",
    );
    protect(path, stateOnly);
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
    const [head, objects, refs] = await Promise.all(
      ["HEAD", "objects", "refs"].map((name) =>
        metadata(fs, join(parent, name)),
      ),
    );
    if (
      (head?.isFile() || head?.isSymbolicLink()) &&
      (objects?.isDirectory() || objects?.isSymbolicLink()) &&
      (refs?.isDirectory() || refs?.isSymbolicLink())
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
  async function inspectScope(scope, stateOnly = false) {
    const binding = await inspectPath(fs, scope, { missing: true });
    if (recursive && !stateOnly && binding.kind === "directory")
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
  for (const scope of new Set([
    workspacePath,
    ...declarations.inputPaths,
    ...declarations.sourcePaths,
    ...declarations.configurationPaths,
    ...declarations.artifactPaths,
    ...declarations.infrastructurePaths,
    ...(declarations.taskPath ? [declarations.taskPath] : []),
  ]))
    await inspectScope(scope);
  await inspectScope(stateRoot, true);
  // Controls-only queries skip ordinary scope traversal, but still follow all
  // discovered control dependencies. State-only traversal grants no read roots.
  // A later full traversal upgrades an earlier state-only visit.
  const visited = new Map();
  async function descend(path, stateOnly) {
    if (visited.has(path) && (stateOnly || !visited.get(path))) return;
    visited.set(path, stateOnly);
    await inspectControls(path, { stateOnly });
    const parent = await openDirectory(fs, path);
    try {
      const names = await readDirectory(fs, parent.anchor);
      for (const entry of names) {
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
