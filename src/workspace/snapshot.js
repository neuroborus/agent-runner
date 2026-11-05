import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { basename, dirname, isAbsolute, join, sep } from "node:path";

import {
  assertBindings,
  assertSafe,
  compactPaths,
  identity,
  inspectPath,
  metadata,
  observation,
  openDirectory,
  overlaps,
  readDirectory,
  same,
  within,
} from "./paths.js";
import { assertInspectionDirectory, isExcluded } from "./scope.js";

const RACE = "ERR_WORKSPACE_SNAPSHOT_RACE";
const hash = (value) => createHash("sha256").update(value).digest("hex");

async function readRegularFile(
  fs,
  path,
  sourcePath,
  limit,
  retain,
  checkpoint = async () => {},
) {
  await checkpoint("capture");
  const before = await fs.lstat(sourcePath, { bigint: true });
  assertSafe(
    before.isFile() && before.nlink === 1n && before.size <= BigInt(limit),
    "Workspace content must be a singly linked regular file within its read limit.",
  );
  const handle = await fs.open(
    sourcePath,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    assertSafe(
      same(
        observation(before),
        observation(await handle.stat({ bigint: true })),
      ),
      "Workspace file changed before reading.",
      RACE,
    );
    const digest = createHash("sha256");
    const chunks = [];
    const buffer = Buffer.alloc(65536);
    let size = 0;
    while (true) {
      await checkpoint("capture");
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      size += bytesRead;
      assertSafe(
        BigInt(size) <= before.size,
        "Workspace file grew during reading.",
        RACE,
      );
      assertSafe(size <= limit, "Workspace content exceeded its read limit.");
      digest.update(buffer.subarray(0, bytesRead));
      if (retain) chunks.push(Buffer.from(buffer.subarray(0, bytesRead)));
    }
    assertSafe(
      BigInt(size) === before.size &&
        same(
          observation(before),
          observation(await handle.stat({ bigint: true })),
        ) &&
        same(
          observation(before),
          observation(await fs.lstat(sourcePath, { bigint: true })),
        ) &&
        (await fs.realpath(path)) === path,
      "Workspace file changed during reading.",
      RACE,
    );
    return {
      stat: before,
      hash: digest.digest("hex"),
      bytes: retain ? Buffer.concat(chunks) : null,
    };
  } finally {
    await handle.close();
  }
}

export async function readTextFile(fs, path, limit = Number.MAX_SAFE_INTEGER) {
  const parent = await openDirectory(fs, dirname(path));
  try {
    const result = await readRegularFile(
      fs,
      path,
      join(parent.anchor, basename(path)),
      limit,
      true,
    );
    await assertBindings(fs, [parent.binding]);
    assertSafe(
      (await fs.realpath(parent.anchor)) === dirname(path),
      "File parent changed during reading.",
      RACE,
    );
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
      result.bytes,
    );
  } finally {
    await parent.handle.close();
  }
}

export const readControlFile = (fs, path) => readTextFile(fs, path, 8192);

export async function capture(
  fs,
  roots,
  outputPaths,
  protectedPaths,
  verifyBindings,
  linkResolutions = [],
  {
    excludePaths = [],
    checkpoint = async () => {},
    linkPaths = [],
    inspectionFilesOnly,
  } = {},
) {
  const selection = { inspectionPaths: linkPaths, inspectionFilesOnly };
  const entries = new Map();
  const observed = new Map();
  const bindings = [];
  function observe(path, stat) {
    const value = stat ? observation(stat) : null;
    assertSafe(
      !observed.has(path) || same(observed.get(path), value),
      "Workspace resolution dependencies changed during snapshot.",
      RACE,
    );
    observed.set(path, value);
  }
  // Resolve components before normalizing '..', checking every link hop.
  async function resolveLink(path, root) {
    const linkRoots = compactPaths([root, ...protectedPaths, ...linkPaths]);
    const inTree = (candidate) =>
      linkRoots.some((tree) => within(tree, candidate));
    let current = dirname(path);
    let pending = [basename(path)];
    let links = 0;
    const dependencies = new Set();
    while (pending.length) {
      await checkpoint("capture");
      const component = pending.shift();
      if (component === "" || component === ".") continue;
      current =
        component === ".." ? dirname(current) : join(current, component);
      assertSafe(
        !isExcluded(current, excludePaths),
        "Workspace link dependencies cannot enter excluded trees.",
      );
      assertSafe(
        inTree(current) || linkRoots.some((tree) => within(current, tree)),
        "Workspace snapshot link escapes its declared tree.",
      );
      assertSafe(
        outputPaths.every((output) =>
          within(output, path)
            ? within(output, current)
            : !within(output, current),
        ),
        "A workspace link crosses a writable boundary.",
      );
      const stat = await metadata(fs, current);
      if (stat?.isDirectory()) assertInspectionDirectory(current, selection);
      observe(current, stat);
      dependencies.add(current);
      assertSafe(
        stat && (stat.isDirectory() || stat.isFile() || stat.isSymbolicLink()),
        "Workspace snapshot links must resolve to ordinary content.",
      );
      assertSafe(
        inTree(current) ||
          (stat.isDirectory() && (await fs.realpath(current)) === current),
        "Workspace snapshot link ancestors must be real directories.",
      );
      if (stat.isSymbolicLink()) {
        assertSafe(
          stat.nlink === 1n && ++links <= 40,
          "Workspace snapshot link resolution is unsafe or cyclic.",
        );
        const target = new TextDecoder("utf-8", {
          fatal: true,
          ignoreBOM: true,
        }).decode(await fs.readlink(current, { encoding: "buffer" }));
        let suffix = target;
        if (isAbsolute(target)) {
          const targetRoot = linkRoots.find(
            (tree) => target === tree || target.startsWith(`${tree}${sep}`),
          );
          assertSafe(
            targetRoot !== undefined,
            "Workspace snapshot link escapes its declared tree.",
          );
          // Process the selected root itself before its suffix, including its
          // file-only constraint, link hops and resolution-dependency binding.
          current = dirname(targetRoot);
          suffix = basename(targetRoot) + target.slice(targetRoot.length);
        } else current = dirname(current);
        pending = [...suffix.split(sep), ...pending];
      } else
        assertSafe(
          pending.length === 0 || stat.isDirectory(),
          "Workspace snapshot link ancestors must be directories.",
        );
    }
    assertSafe(
      inTree(current),
      "Workspace snapshot link escapes its declared tree.",
    );
    assertSafe(
      excludePaths.every((excluded) => !overlaps(current, excluded)),
      "Workspace link targets overlap excluded trees.",
    );
    assertSafe(
      (await fs.realpath(path)) === current,
      "Workspace link changed during resolution.",
      RACE,
    );
    return { target: current, paths: [...dependencies].sort() };
  }
  async function visit(path, sourcePath, root) {
    if (isExcluded(path, excludePaths)) return;
    await checkpoint("capture");
    const before = await metadata(fs, sourcePath);
    if (before?.isDirectory()) assertInspectionDirectory(path, selection);
    observe(path, before);
    if (before === null) {
      entries.set(path, {
        path,
        kind: "missing",
        mode: null,
        size: 0,
        hash: null,
      });
      return;
    }
    assertSafe(
      before.isFile() || before.isDirectory() || before.isSymbolicLink(),
      "Workspace snapshots reject special files.",
    );
    let contentHash = null;
    if (before.isSymbolicLink()) {
      const target = await fs.readlink(sourcePath, { encoding: "buffer" });
      const resolution = await resolveLink(path, root);
      assertSafe(
        before.nlink === 1n,
        "Workspace snapshot link escapes its declared tree.",
      );
      assertSafe(
        outputPaths.every((output) =>
          within(output, path)
            ? within(output, resolution.target)
            : !overlaps(output, resolution.target),
        ),
        "A workspace link crosses a writable boundary.",
      );
      contentHash = hash(target);
      linkResolutions.push({ path, ...resolution });
    } else if (before.isFile()) {
      const result = await readRegularFile(
        fs,
        path,
        sourcePath,
        Number.MAX_SAFE_INTEGER,
        false,
        checkpoint,
      );
      assertSafe(
        same(observation(before), observation(result.stat)),
        "Workspace file changed during snapshot.",
        RACE,
      );
      contentHash = result.hash;
    } else {
      const handle = await fs.open(
        sourcePath,
        constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
      );
      try {
        const anchor = `/proc/self/fd/${handle.fd}`;
        assertSafe(
          same(
            observation(before),
            observation(await handle.stat({ bigint: true })),
          ) && (await fs.realpath(anchor)) === path,
          "Workspace directory changed before snapshot.",
          RACE,
        );
        const names = await readDirectory(fs, anchor);
        for (const { name } of names)
          await visit(join(path, name), join(anchor, name), root);
        assertSafe(
          same(names, await readDirectory(fs, anchor)) &&
            same(
              observation(before),
              observation(await handle.stat({ bigint: true })),
            ) &&
            (await fs.realpath(anchor)) === path,
          "Workspace directory changed during snapshot.",
          RACE,
        );
      } finally {
        await handle.close();
      }
    }
    entries.set(path, {
      path,
      kind: before.isSymbolicLink()
        ? "symlink"
        : before.isFile()
          ? "file"
          : "directory",
      mode: Number(before.mode & 0o777n),
      size: before.isDirectory() ? 0 : Number(before.size),
      hash: contentHash,
      identity: identity(before),
      ...(!before.isDirectory()
        ? {
            modifiedNs: String(before.mtimeNs),
            changedNs: String(before.ctimeNs),
          }
        : {}),
    });
  }
  for (const path of compactPaths(roots)) {
    if (isExcluded(path, excludePaths)) continue;
    await checkpoint("capture");
    const binding = await inspectPath(fs, path, {
      missing: true,
      allowLink: true,
    });
    bindings.push(binding);
    if (!binding.exists) {
      entries.set(path, {
        path,
        kind: "missing",
        mode: null,
        size: 0,
        hash: null,
      });
      observe(path, null);
    } else {
      const parent = await openDirectory(fs, dirname(path));
      try {
        await visit(path, join(parent.anchor, basename(path)), path);
        assertSafe(
          (await fs.realpath(parent.anchor)) === dirname(path),
          "Workspace snapshot parent changed.",
          RACE,
        );
      } finally {
        await parent.handle.close();
      }
    }
  }
  await verifyBindings();
  for (const binding of bindings) {
    await checkpoint("verify");
    assertSafe(
      same(
        binding,
        await inspectPath(fs, binding.path, { missing: true, allowLink: true }),
      ),
      "Workspace path bindings changed during snapshot.",
      RACE,
    );
  }
  for (const [path, before] of observed) {
    await checkpoint("verify");
    const after = await metadata(fs, path);
    assertSafe(
      same(before, after ? observation(after) : null),
      "Workspace changed before snapshot completed.",
      RACE,
    );
  }
  return [...entries.values()].sort((left, right) =>
    left.path < right.path ? -1 : left.path > right.path ? 1 : 0,
  );
}

export function fingerprints(entries, scope) {
  const content = entries.map(({ path, kind, mode, size, hash }) => ({
    path,
    kind,
    mode,
    size,
    hash,
  }));
  return {
    contentFingerprint: hash(
      JSON.stringify(
        scope === undefined ? content : { scope, entries: content },
      ),
    ),
    identityFingerprint: hash(
      JSON.stringify(scope === undefined ? entries : { scope, entries }),
    ),
  };
}
