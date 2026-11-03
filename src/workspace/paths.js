import { constants } from "node:fs";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { isDeepStrictEqual } from "node:util";

export class WorkspaceSafetyError extends Error {
  constructor(message, { code = "ERR_WORKSPACE_PATH", cause } = {}) {
    super(message, { cause });
    this.name = "WorkspaceSafetyError";
    this.code = code;
  }
}

export function assertSafe(condition, message, code) {
  if (!condition) throw new WorkspaceSafetyError(message, { code });
}

export function within(parent, path) {
  const value = relative(parent, path);
  return (
    value === "" ||
    (value !== ".." && !value.startsWith(`..${sep}`) && !isAbsolute(value))
  );
}

export function overlaps(left, right) {
  return within(left, right) || within(right, left);
}

export function location(base, value) {
  assertSafe(
    typeof value === "string" &&
      value.trim() !== "" &&
      !value.includes("\0") &&
      !/^[a-z][a-z0-9+.-]*:\/\//iu.test(value),
    "Workspace paths must be non-empty local paths.",
  );
  return resolve(base, value);
}

// A parent read already covers descendants; it never expands output authority.
export function compactPaths(paths) {
  return [...new Set(paths)]
    .sort()
    .filter(
      (path, index, all) =>
        !all.some((parent, other) => other !== index && within(parent, path)),
    );
}

export function identity(stat) {
  return {
    device: String(stat.dev),
    inode: String(stat.ino),
    mode: String(stat.mode),
  };
}

export function observation(stat) {
  return {
    ...identity(stat),
    size: String(stat.size),
    modifiedNs: String(stat.mtimeNs),
    changedNs: String(stat.ctimeNs),
    links: String(stat.nlink),
  };
}

export function same(left, right) {
  return isDeepStrictEqual(left, right);
}

export async function metadata(fs, path) {
  try {
    return await fs.lstat(path, { bigint: true });
  } catch (cause) {
    if (cause.code === "ENOENT") return null;
    throw cause;
  }
}

export async function readDirectory(fs, path) {
  const entries = await fs.readdir(path, {
    withFileTypes: true,
    encoding: "buffer",
  });
  const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
  return entries
    .map((entry) => ({
      name: decoder.decode(entry.name),
      directory: entry.isDirectory(),
    }))
    .sort((left, right) =>
      left.name < right.name ? -1 : left.name > right.name ? 1 : 0,
    );
}

// Bind every existing ancestor, including ancestors above the selected root.
export async function inspectPath(fs, path, { missing = false } = {}) {
  const chain = [];
  for (let current = path; ; current = dirname(current)) {
    chain.unshift(current);
    if (current === dirname(current)) break;
  }
  const ancestors = [];
  let leaf = null;
  for (const current of chain) {
    const stat = await metadata(fs, current);
    if (stat === null) {
      assertSafe(missing, "A declared workspace path is missing.");
      break;
    }
    assertSafe(
      stat.isDirectory() || stat.isFile(),
      "Workspace paths cannot contain aliases or special files.",
    );
    assertSafe(
      current === path || stat.isDirectory(),
      "Workspace ancestors must be real directories.",
    );
    assertSafe(
      (await fs.realpath(current)) === current,
      "Workspace paths cannot traverse aliases.",
    );
    if (current === path) leaf = stat;
    else ancestors.push({ path: current, ...identity(stat) });
  }
  return {
    path,
    exists: leaf !== null,
    kind: leaf?.isDirectory() ? "directory" : leaf ? "file" : "missing",
    ancestors,
    identity: leaf ? identity(leaf) : null,
  };
}

export async function assertBindings(fs, bindings) {
  for (const binding of bindings) {
    for (const ancestor of binding.ancestors) {
      const stat = await metadata(fs, ancestor.path);
      assertSafe(
        stat?.isDirectory() &&
          same(identity(stat), {
            device: ancestor.device,
            inode: ancestor.inode,
            mode: ancestor.mode,
          }) &&
          (await fs.realpath(ancestor.path)) === ancestor.path,
        "Workspace ancestor identity changed.",
        "ERR_WORKSPACE_DRIFT",
      );
    }
  }
}

// Descriptor paths prevent a renamed parent from redirecting descendant reads.
export async function openDirectory(fs, path) {
  const before = await inspectPath(fs, path);
  assertSafe(
    before.kind === "directory",
    "Workspace root must be a real directory.",
  );
  const handle = await fs.open(
    path,
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
  );
  try {
    const stat = await handle.stat({ bigint: true });
    const anchor = `/proc/self/fd/${handle.fd}`;
    assertSafe(
      stat.isDirectory() &&
        same(identity(stat), before.identity) &&
        (await fs.realpath(anchor)) === path,
      "Workspace directory changed during inspection.",
      "ERR_WORKSPACE_SNAPSHOT_RACE",
    );
    await assertBindings(fs, [before]);
    return { handle, anchor, stat, binding: before };
  } catch (cause) {
    await handle.close();
    throw cause;
  }
}
