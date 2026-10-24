import { constants } from "node:fs";
import {
  lstat,
  mkdir,
  open,
  realpath,
  rename,
  rmdir,
  symlink,
  unlink,
} from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { isDeepStrictEqual } from "node:util";

import { decodeLine, GitSafetyError, hashBuffer, isWithin } from "./command.js";
import {
  contentEntry,
  entriesMatch,
  fileContentEntry,
  hashEntries,
  headContentEntry,
  sourceChangesAtRoot,
} from "./content.js";
import { safeRelativePath, withDestination } from "./materialization.js";

const NO_FOLLOW = constants.O_NOFOLLOW ?? 0;
const absent = (path) => ({
  path,
  kind: "deleted",
  hash: null,
  mode: null,
  size: 0,
});
const identity = (stat) => ({
  device: String(stat.dev),
  inode: String(stat.ino),
});
const fail = () => {
  throw new GitSafetyError(
    "Preserved content or repository ownership changed.",
    {
      code: "ERR_GIT_PRESERVATION_CHANGED",
    },
  );
};

function assertEntry(entry) {
  if (
    !entry ||
    Object.keys(entry).sort().join() !== "hash,kind,mode,path,size" ||
    !safeRelativePath(entry.path) ||
    !Number.isSafeInteger(entry.size) ||
    entry.size < 0 ||
    (entry.kind === "deleted"
      ? entry.hash !== null || entry.mode !== null || entry.size !== 0
      : !/^[a-f0-9]{64}$/u.test(entry.hash) ||
        !(
          (entry.kind === "file" &&
            ["100644", "100755"].includes(entry.mode)) ||
          (entry.kind === "symlink" && entry.mode === "120000")
        ))
  )
    fail();
}

// A descendant hidden by a file or link is absent. Inspect each component
// separately so even metadata reads never follow a replacement link.
async function pathMetadata(projectPath, path) {
  const parts = path.split("/");
  let current = projectPath;
  for (const [index, part] of parts.entries()) {
    current = join(current, part);
    const stat = await lstat(current, { bigint: true }).catch((cause) => {
      if (cause.code !== "ENOENT") throw cause;
      return null;
    });
    if (stat === null || index === parts.length - 1) return stat;
    if (!stat.isDirectory()) return null;
  }
}

export function createGitPreservationService({
  contentContext,
  assertSnapshot,
  assertUnchanged,
  reconcileInterrupted,
  snapshot,
}) {
  const context = {
    ...contentContext,
    runGit: (path, args, options) =>
      contentContext.runGit(path, ["--no-replace-objects", ...args], options),
  };
  const inspect = async (projectPath, path, includeContent = false) =>
    (await pathMetadata(projectPath, path)) === null
      ? absent(path)
      : contentEntry(context, projectPath, path, {
          allowedPaths: [],
          missingAllowed: true,
          includeContent,
        });

  async function inspectAncestors(projectPath, paths, selectedPaths = paths) {
    const ancestors = Object.create(null);
    for (const path of paths) {
      // A selected directory can itself be replaced, even without saved children.
      let parent = path;
      while (parent !== ".") {
        const stat = await pathMetadata(projectPath, parent);
        if (stat && !stat.isDirectory() && !selectedPaths.includes(parent))
          fail();
        if (stat?.isDirectory()) ancestors[parent] = identity(stat);
        parent = dirname(parent);
      }
    }
    return ancestors;
  }

  async function rootIdentity(projectPath) {
    const stat = await lstat(projectPath, { bigint: true });
    if (!stat.isDirectory() || (await realpath(projectPath)) !== projectPath)
      fail();
    return identity(stat);
  }

  async function assertPaths(
    projectPath,
    paths,
    protectedPaths = [],
    selectedPaths = paths,
  ) {
    if (
      !Array.isArray(protectedPaths) ||
      protectedPaths.some(
        (path) => typeof path !== "string" || resolve(path) !== path,
      )
    )
      fail();
    const controls = [...protectedPaths];
    for (const flag of ["--absolute-git-dir", "--git-common-dir"]) {
      const result = await context.runGit(projectPath, ["rev-parse", flag]);
      controls.push(
        await realpath(
          resolve(projectPath, decodeLine(result.stdout, "Git control path")),
        ),
      );
    }
    for (const path of paths) {
      if (
        !safeRelativePath(path) ||
        path.split("/").some((part) => part.toLowerCase() === ".git") ||
        controls.some(
          (control) =>
            isWithin(control, resolve(projectPath, path)) ||
            isWithin(resolve(projectPath, path), control),
        )
      )
        fail();
      await inspectAncestors(projectPath, [path], selectedPaths);
      const stat = await pathMetadata(projectPath, path);
      if (
        stat &&
        !stat.isSymbolicLink() &&
        !stat.isDirectory() &&
        (!stat.isFile() || stat.nlink !== 1n)
      )
        fail();
    }
  }

  async function controlBindings(projectPath) {
    const paths = new Set([join(projectPath, ".git")]);
    for (const flag of ["--absolute-git-dir", "--git-common-dir"]) {
      const result = await context.runGit(projectPath, ["rev-parse", flag]);
      paths.add(
        resolve(projectPath, decodeLine(result.stdout, "Git control path")),
      );
    }
    const bindings = [];
    for (const path of paths) {
      const stat = await lstat(path, { bigint: true });
      if (
        (!stat.isDirectory() && !stat.isFile()) ||
        (await realpath(path)) !== path
      )
        fail();
      const binding = { path, identity: identity(stat) };
      if (stat.isFile()) {
        const handle = await open(path, constants.O_RDONLY | NO_FOLLOW);
        try {
          const before = await handle.stat({ bigint: true });
          if (
            !before.isFile() ||
            before.nlink !== 1n ||
            !isDeepStrictEqual(identity(before), binding.identity)
          )
            fail();
          const bytes = await handle.readFile();
          const after = await lstat(path, { bigint: true });
          if (
            ["dev", "ino", "mode", "nlink", "size", "mtimeNs", "ctimeNs"].some(
              (key) => before[key] !== after[key],
            )
          )
            fail();
          binding.hash = hashBuffer(bytes);
        } finally {
          await handle.close();
        }
      }
      bindings.push(binding);
    }
    return bindings;
  }

  async function captureChanges({
    expectedSnapshot,
    writeBlob,
    protectedPaths = [],
    signal,
  }) {
    assertSnapshot(expectedSnapshot);
    if (
      expectedSnapshot.allowedPaths.length !== 0 ||
      typeof writeBlob !== "function"
    )
      fail();
    await assertUnchanged(expectedSnapshot);
    const { projectPath, head } = expectedSnapshot;
    const repositoryIdentity = await rootIdentity(projectPath);
    const controls = await controlBindings(projectPath);
    const changes = await sourceChangesAtRoot(context, projectPath, {
      baseHead: head,
    });
    if (changes.contentFingerprint !== expectedSnapshot.contentFingerprint)
      fail();
    await assertPaths(projectPath, changes.changedPaths, protectedPaths);
    const entries = [];
    for (const entry of changes.entries) {
      signal?.throwIfAborted();
      const after = await inspect(projectPath, entry.path, true);
      if (!entriesMatch(after, entry)) fail();
      const before =
        (head === null
          ? null
          : await headContentEntry(context, projectPath, head, entry.path, {
              includeContent: true,
            })) ?? absent(entry.path);
      const pair = {};
      for (const [side, value] of [
        ["before", before],
        ["after", after],
      ]) {
        const { content, ...descriptor } = value;
        assertEntry(descriptor);
        if (content !== undefined) await writeBlob(descriptor, content);
        pair[side] = descriptor;
      }
      entries.push(pair);
    }
    await assertUnchanged(expectedSnapshot);
    if (
      !isDeepStrictEqual(await rootIdentity(projectPath), repositoryIdentity) ||
      !isDeepStrictEqual(await controlBindings(projectPath), controls)
    )
      fail();
    return {
      schemaVersion: 1,
      projectPath,
      baseHead: head,
      repositoryIdentity,
      controls,
      contentFingerprint: changes.contentFingerprint,
      entries,
    };
  }

  function assertManifest(manifest) {
    if (
      !manifest ||
      Object.keys(manifest).sort().join() !==
        "baseHead,contentFingerprint,controls,entries,projectPath,repositoryIdentity,schemaVersion" ||
      manifest.schemaVersion !== 1 ||
      !Array.isArray(manifest.entries) ||
      !Array.isArray(manifest.controls)
    )
      fail();
    const paths = new Set();
    for (const pair of manifest.entries) {
      if (!pair || Object.keys(pair).sort().join() !== "after,before") fail();
      assertEntry(pair.before);
      assertEntry(pair.after);
      if (pair.before.path !== pair.after.path || paths.has(pair.before.path))
        fail();
      paths.add(pair.before.path);
    }
    if (
      hashEntries(manifest.entries.map(({ after }) => after)) !==
      manifest.contentFingerprint
    )
      fail();
    return paths;
  }

  async function prepareRestoration({
    manifest,
    expectedSnapshot,
    paths,
    target,
    protectedPaths = [],
  }) {
    const savedPaths = assertManifest(manifest);
    assertSnapshot(expectedSnapshot);
    if (
      !Array.isArray(paths) ||
      paths.length === 0 ||
      new Set(paths).size !== paths.length ||
      paths.some((path) => !savedPaths.has(path)) ||
      !["before", "after"].includes(target) ||
      expectedSnapshot.projectPath !== manifest.projectPath ||
      expectedSnapshot.allowedPaths.length !== 0
    )
      fail();
    await assertUnchanged(expectedSnapshot);
    const { projectPath } = expectedSnapshot;
    if (
      !isDeepStrictEqual(
        await rootIdentity(projectPath),
        manifest.repositoryIdentity,
      ) ||
      !isDeepStrictEqual(await controlBindings(projectPath), manifest.controls)
    )
      fail();
    await assertPaths(projectPath, paths, protectedPaths);
    const writes = [];
    for (const pair of manifest.entries.filter(({ before }) =>
      paths.includes(before.path),
    )) {
      const from = await inspect(projectPath, pair.before.path);
      if (!entriesMatch(from, pair.before) && !entriesMatch(from, pair.after))
        fail();
      // A child baseline may advance only on paths outside the saved remainder.
      const baseline =
        expectedSnapshot.head === null
          ? absent(from.path)
          : ((await headContentEntry(
              context,
              projectPath,
              expectedSnapshot.head,
              from.path,
            )) ?? absent(from.path));
      if (!entriesMatch(baseline, pair.before)) fail();
      writes.push({ from, to: pair[target] });
    }
    const ancestors = await inspectAncestors(projectPath, paths);
    // Remove checked leaves before restoring files or creating their parents.
    writes.sort((left, right) => {
      const leftDeleted = left.to.kind === "deleted";
      const rightDeleted = right.to.kind === "deleted";
      return leftDeleted !== rightDeleted
        ? leftDeleted
          ? -1
          : 1
        : leftDeleted
          ? right.to.path.length - left.to.path.length
          : left.to.path.length - right.to.path.length;
    });
    const source = await sourceChangesAtRoot(context, projectPath, {
      baseHead: expectedSnapshot.head,
    });
    if (source.contentFingerprint !== expectedSnapshot.contentFingerprint)
      fail();
    await assertUnchanged(expectedSnapshot);
    return {
      schemaVersion: 1,
      snapshot: expectedSnapshot,
      repositoryIdentity: manifest.repositoryIdentity,
      sourceEntries: source.entries,
      protectedPaths,
      ancestors,
      controls: manifest.controls,
      writes,
    };
  }

  async function applyRestoration({
    operation,
    operationId,
    readBlob,
    readPrepared,
    recordPrepared,
    onApplied,
    signal,
  }) {
    const {
      snapshot: expected,
      writes,
      sourceEntries,
      repositoryIdentity,
      protectedPaths,
      ancestors,
      controls,
    } = operation;
    assertSnapshot(expected);
    if (
      operation.schemaVersion !== 1 ||
      expected.allowedPaths.length !== 0 ||
      Object.keys(operation).sort().join() !==
        "ancestors,controls,protectedPaths,repositoryIdentity,schemaVersion,snapshot,sourceEntries,writes" ||
      !/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u.test(
        operationId,
      ) ||
      !ancestors ||
      !Array.isArray(controls) ||
      !Array.isArray(protectedPaths) ||
      !Array.isArray(writes) ||
      !Array.isArray(sourceEntries)
    )
      fail();
    for (const entry of sourceEntries) assertEntry(entry);
    if (
      hashEntries(sourceEntries) !== expected.contentFingerprint ||
      new Set(sourceEntries.map(({ path }) => path)).size !==
        sourceEntries.length ||
      new Set(writes.map(({ from }) => from.path)).size !== writes.length
    )
      fail();
    for (const { from, to } of writes) {
      assertEntry(from);
      assertEntry(to);
      if (from.path !== to.path) fail();
    }
    const projectPath = expected.projectPath;
    const writePaths = writes.map(({ to }) => to.path);
    const temporaryPaths = writes.map(({ to }, index) =>
      join(dirname(to.path), `.preservation-${operationId}-${index}.tmp`),
    );
    const prepared = await Promise.all(
      writes.map((_, index) => readPrepared(index)),
    );
    async function verifyTemporary(index) {
      const entry = prepared[index];
      const path = temporaryPaths[index];
      const stat = await pathMetadata(projectPath, path);
      if (stat === null) {
        if (
          entry?.identity &&
          (!entry.ready ||
            !entriesMatch(
              await inspect(projectPath, writes[index].to.path),
              writes[index].to,
            ))
        )
          fail();
        return;
      }
      if (
        !entry ||
        stat.nlink !== 1n ||
        stat.uid !== BigInt(process.getuid()) ||
        (entry.identity !== null &&
          !isDeepStrictEqual(identity(stat), entry.identity))
      )
        fail();
      const to = writes[index].to;
      const actual = await inspect(projectPath, path, !entry.ready);
      if (entry.ready || to.kind === "symlink") {
        if (!entriesMatch(actual, to)) fail();
      } else {
        // Before identity publication only an empty exclusive creation is
        // recoverable. Once pinned, interrupted writes must be saved-byte prefixes.
        if (
          to.kind !== "file" ||
          !stat.isFile() ||
          (entry.identity === null
            ? (stat.mode & 0o777n) !== 0o600n
            : ![0o600n, to.mode === "100755" ? 0o755n : 0o644n].includes(
                stat.mode & 0o777n,
              )) ||
          actual.size > to.size ||
          (entry.identity === null && actual.size !== 0) ||
          !actual.content.equals((await readBlob(to)).subarray(0, actual.size))
        )
          fail();
      }
    }
    async function verify() {
      if (
        !isDeepStrictEqual(
          await rootIdentity(projectPath),
          repositoryIdentity,
        ) ||
        !isDeepStrictEqual(await controlBindings(projectPath), controls)
      )
        fail();
      const parentBindings = [ancestors];
      for (const entry of prepared) {
        if (entry === null) continue;
        if (
          !entry ||
          Object.keys(entry).sort().join() !== "ancestors,identity,ready" ||
          !entry.ancestors ||
          typeof entry.ready !== "boolean" ||
          (entry.ready && entry.identity === null)
        )
          fail();
        parentBindings.push(entry.ancestors);
      }
      for (const [path, expectedIdentity] of parentBindings.flatMap(
        (bindings) => Object.entries(bindings),
      )) {
        if (!safeRelativePath(path)) fail();
        const stat = await pathMetadata(projectPath, path);
        // An interrupted creation without a published identity grants no
        // ownership of an existing directory, even if it is still empty.
        if (expectedIdentity === null) {
          if (stat !== null) fail();
          continue;
        }
        // An explicitly selected file/directory replacement may remove this
        // directory. Every surviving parent must retain its inspected identity.
        if (!stat?.isDirectory()) {
          if (
            !writes.some(
              ({ to }) =>
                to.kind !== "deleted" &&
                (path === to.path || path.startsWith(`${to.path}/`)),
            ) ||
            (stat !== null &&
              !writes.some(
                ({ to }) => to.path === path && to.kind !== "deleted",
              ))
          )
            fail();
        } else if (!isDeepStrictEqual(identity(stat), expectedIdentity)) fail();
      }
      await reconcileInterrupted(expected, {
        allowWorkspaceChanges: true,
        allowIndexChanges: false,
      });
      const current = await sourceChangesAtRoot(context, projectPath, {
        baseHead: expected.head,
      });
      const allowed = new Map(
        sourceEntries.map((entry) => [entry.path, entry]),
      );
      for (const { from, to } of writes) {
        const actual = await inspect(projectPath, from.path);
        if (!entriesMatch(actual, from) && !entriesMatch(actual, to)) fail();
        allowed.set(from.path, actual);
      }
      for (const index of writes.keys()) await verifyTemporary(index);
      for (const entry of current.entries) {
        const temporaryIndex = temporaryPaths.indexOf(entry.path);
        if (temporaryIndex !== -1 && prepared[temporaryIndex]) {
          continue;
        }
        if (!entriesMatch(entry, allowed.get(entry.path) ?? null)) fail();
      }
      for (const [path, entry] of allowed) {
        if (!entriesMatch(await inspect(projectPath, path), entry)) fail();
      }
    }
    async function syncAppliedParent(path) {
      const opened = [];
      try {
        let directory = await open(
          projectPath,
          constants.O_RDONLY | constants.O_DIRECTORY | NO_FOLLOW,
        );
        opened.push(directory);
        if (
          !isDeepStrictEqual(
            identity(await directory.stat({ bigint: true })),
            repositoryIdentity,
          )
        )
          fail();
        let parentPath = projectPath;
        for (const part of path.split("/").slice(0, -1)) {
          const childPath = join(`/proc/self/fd/${directory.fd}`, part);
          const stat = await lstat(childPath, { bigint: true }).catch(
            (cause) => {
              if (cause.code !== "ENOENT") throw cause;
              return null;
            },
          );
          // A later authorized replacement may have removed this parent.
          // Sync its nearest surviving directory without following a link.
          if (!stat?.isDirectory()) break;
          directory = await open(
            childPath,
            constants.O_RDONLY | constants.O_DIRECTORY | NO_FOLLOW,
          );
          opened.push(directory);
          parentPath = join(parentPath, part);
          if (
            !isDeepStrictEqual(
              identity(await directory.stat({ bigint: true })),
              identity(stat),
            )
          )
            fail();
        }
        await verify();
        if ((await realpath(`/proc/self/fd/${directory.fd}`)) !== parentPath)
          fail();
        await directory.sync();
      } finally {
        await Promise.all(
          opened.reverse().map((directory) => directory.close()),
        );
      }
    }
    await verify();
    // Verify every required blob before the first destructive effect.
    for (const { to } of writes) if (to.kind !== "deleted") await readBlob(to);
    for (const [index, { from, to }] of writes.entries()) {
      signal?.throwIfAborted();
      await verify();
      await assertPaths(projectPath, [to.path], protectedPaths, writePaths);
      if (entriesMatch(await inspect(projectPath, to.path), to)) {
        // Seeing the namespace change does not prove its parent was synced
        // before interruption. Complete durability before accepting recovery.
        await syncAppliedParent(to.path);
        continue;
      }
      if (!entriesMatch(await inspect(projectPath, to.path), from)) fail();
      if (to.kind !== "deleted" && !prepared[index]) {
        prepared[index] = {
          identity: null,
          ancestors: await inspectAncestors(projectPath, [to.path], writePaths),
          ready: false,
        };
        await recordPrepared(index, prepared[index]);
      }
      async function prepareDirectory(
        directoryPath,
        path,
        bindings = prepared[index]?.ancestors ?? ancestors,
      ) {
        const stat = await lstat(directoryPath, { bigint: true }).catch(
          (cause) => {
            if (cause.code !== "ENOENT") throw cause;
            return null;
          },
        );
        if (stat !== null) {
          if (
            !stat.isDirectory() ||
            !isDeepStrictEqual(identity(stat), bindings[path])
          )
            fail();
          return;
        }
        if (
          to.kind === "deleted" ||
          (Object.hasOwn(bindings, path) && bindings[path] !== null)
        )
          fail();
        if (!Object.hasOwn(bindings, path)) {
          prepared[index] = {
            ...prepared[index],
            ancestors: { ...bindings, [path]: null },
          };
          await recordPrepared(index, prepared[index]);
        }
        await mkdir(directoryPath, { mode: 0o700 });
        const created = await lstat(directoryPath, { bigint: true });
        if (!created.isDirectory()) fail();
        const directory = await open(
          `${dirname(directoryPath)}/.`,
          constants.O_RDONLY | constants.O_DIRECTORY | NO_FOLLOW,
        );
        try {
          await directory.sync();
        } finally {
          await directory.close();
        }
        if (
          !isDeepStrictEqual(
            identity(await lstat(directoryPath, { bigint: true })),
            identity(created),
          )
        )
          fail();
        prepared[index] = {
          ...prepared[index],
          ancestors: {
            ...prepared[index].ancestors,
            [path]: identity(created),
          },
        };
        await recordPrepared(index, prepared[index]);
      }
      const root = await open(
        projectPath,
        constants.O_RDONLY | constants.O_DIRECTORY | NO_FOLLOW,
      );
      try {
        if (
          !isDeepStrictEqual(
            identity(await root.stat({ bigint: true })),
            repositoryIdentity,
          )
        )
          fail();
        await withDestination(
          root,
          to.path,
          async (destination) => {
            const parent = dirname(destination);
            async function assertDestination() {
              await verify();
              await assertPaths(
                projectPath,
                [to.path],
                protectedPaths,
                writePaths,
              );
              if (
                (await realpath(parent)) !==
                dirname(resolve(projectPath, to.path))
              )
                fail();
              const stat = await lstat(destination, { bigint: true }).catch(
                (cause) => {
                  if (cause.code !== "ENOENT") throw cause;
                  return null;
                },
              );
              if (
                (stat?.isFile() && stat.nlink !== 1n) ||
                (stat?.isDirectory() &&
                  !isDeepStrictEqual(identity(stat), ancestors[to.path]))
              )
                fail();
              const entry =
                stat === null || stat.isDirectory()
                  ? absent(from.path)
                  : await fileContentEntry(destination, from.path, stat);
              if (
                entry === null ||
                !entriesMatch(entry, from) ||
                (await realpath(parent)) !==
                  dirname(resolve(projectPath, to.path))
              )
                fail();
              return stat;
            }
            const temporary = join(
              parent,
              `.preservation-${operationId}-${index}.tmp`,
            );
            if (to.kind === "deleted") {
              await readBlob(from);
              await assertDestination();
              await unlink(destination);
            } else {
              const bytes = await readBlob(to);
              if (prepared[index].identity === null) {
                await verify();
                const existing = await lstat(temporary).catch((cause) => {
                  if (cause.code === "ENOENT") return null;
                  throw cause;
                });
                if (existing === null && to.kind === "symlink")
                  await symlink(bytes, temporary);
                else if (existing === null) {
                  const handle = await open(
                    temporary,
                    constants.O_WRONLY |
                      constants.O_CREAT |
                      constants.O_EXCL |
                      NO_FOLLOW,
                    0o600,
                  );
                  try {
                    await handle.sync();
                  } finally {
                    await handle.close();
                  }
                }
                prepared[index] = {
                  ...prepared[index],
                  identity: identity(await lstat(temporary, { bigint: true })),
                };
                const directory = await open(
                  `${parent}/.`,
                  constants.O_RDONLY | constants.O_DIRECTORY | NO_FOLLOW,
                );
                try {
                  await directory.sync();
                } finally {
                  await directory.close();
                }
                await recordPrepared(index, prepared[index]);
              }
              if (!prepared[index].ready) {
                await verify();
                if (to.kind === "file") {
                  const handle = await open(
                    temporary,
                    constants.O_WRONLY | NO_FOLLOW,
                  );
                  try {
                    const stat = await handle.stat({ bigint: true });
                    if (
                      !stat.isFile() ||
                      stat.nlink !== 1n ||
                      !isDeepStrictEqual(
                        identity(stat),
                        prepared[index].identity,
                      )
                    )
                      fail();
                    await handle.writeFile(bytes);
                    await handle.chmod(to.mode === "100755" ? 0o755 : 0o644);
                    await handle.sync();
                  } finally {
                    await handle.close();
                  }
                }
                prepared[index] = { ...prepared[index], ready: true };
                await recordPrepared(index, prepared[index]);
              }
              // Publication can suspend the operation. Recheck controls,
              // ancestors and the pinned destination after all saved-blob reads.
              await readBlob(to);
              if (from.kind !== "deleted") await readBlob(from);
              const stat = await lstat(temporary, { bigint: true });
              if (
                !isDeepStrictEqual(identity(stat), prepared[index].identity) ||
                stat.nlink !== 1n ||
                !entriesMatch(
                  await inspect(projectPath, temporaryPaths[index]),
                  { ...to, path: temporaryPaths[index] },
                )
              )
                fail();
              const destinationStat = await assertDestination();
              // Never recursively remove a directory or its uninspected children.
              if (destinationStat?.isDirectory()) {
                // Only these inspected ancestors can become empty after the
                // authorized leaf deletions. Never discover new removal paths.
                const directories = Object.keys(ancestors)
                  .filter((path) => path.startsWith(`${to.path}/`))
                  .sort((left, right) => right.length - left.length);
                for (const path of directories) {
                  const current = await lstat(resolve(projectPath, path), {
                    bigint: true,
                  }).catch((cause) => {
                    if (cause.code !== "ENOENT") throw cause;
                    return null;
                  });
                  if (current === null) continue;
                  if (
                    !current.isDirectory() ||
                    !isDeepStrictEqual(identity(current), ancestors[path])
                  )
                    fail();
                  await withDestination(
                    root,
                    path,
                    async (directoryPath) => {
                      const checked = await lstat(directoryPath, {
                        bigint: true,
                      });
                      if (
                        !checked.isDirectory() ||
                        !isDeepStrictEqual(
                          identity(checked),
                          ancestors[path],
                        ) ||
                        (await realpath(dirname(directoryPath))) !==
                          dirname(resolve(projectPath, path))
                      )
                        fail();
                      try {
                        await rmdir(directoryPath);
                      } catch (cause) {
                        if (["ENOTEMPTY", "EEXIST"].includes(cause.code))
                          fail();
                        throw cause;
                      }
                      const parentDirectory = await open(
                        `${dirname(directoryPath)}/.`,
                        constants.O_RDONLY | constants.O_DIRECTORY | NO_FOLLOW,
                      );
                      try {
                        await parentDirectory.sync();
                      } finally {
                        await parentDirectory.close();
                      }
                    },
                    {
                      privateDirectories: false,
                      // Cleanup descends beyond this write's own parents.
                      prepareDirectory: (directoryPath, path) =>
                        prepareDirectory(directoryPath, path, ancestors),
                    },
                  );
                }
                await assertDestination();
                try {
                  await rmdir(destination);
                } catch (cause) {
                  if (["ENOTEMPTY", "EEXIST"].includes(cause.code)) fail();
                  throw cause;
                }
                await assertDestination();
              }
              await rename(temporary, destination);
            }
            const directory = await open(
              `${parent}/.`,
              constants.O_RDONLY | constants.O_DIRECTORY | NO_FOLLOW,
            );
            try {
              await directory.sync();
            } finally {
              await directory.close();
            }
          },
          { privateDirectories: false, prepareDirectory },
        );
      } finally {
        await root.close();
      }
      await onApplied(index);
    }
    await verify();
    for (const { to } of writes)
      if (!entriesMatch(await inspect(projectPath, to.path), to)) fail();
    for (const path of temporaryPaths)
      if ((await inspect(projectPath, path)).kind !== "deleted") fail();
    return snapshot({ projectPath });
  }

  return Object.freeze({
    captureChanges,
    prepareRestoration,
    applyRestoration,
  });
}
