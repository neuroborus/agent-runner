import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { basename, dirname, join } from "node:path";

import {
  assertBindings,
  assertSafe,
  identity,
  inspectPath,
  metadata,
  openDirectory,
  same,
} from "./paths.js";

async function createDirectory(fs, storage, staging) {
  // Allocation stays in private durable state. Pin its identity before making
  // it reachable from the workspace, where an arriving root is untrusted.
  const destination = join(storage.anchor, basename(staging.path));
  try {
    await fs.mkdir(destination, { mode: 0o700 });
  } catch (cause) {
    if (cause.code !== "EEXIST") throw cause;
    assertSafe(
      false,
      "A private output allocation already exists; preserve it for reconciliation.",
      "ERR_WORKSPACE_OUTPUT_AMBIGUOUS",
    );
  }
  const stat = await metadata(fs, destination);
  let handle;
  try {
    assertSafe(
      stat?.isDirectory(),
      "Output directory changed during creation.",
      "ERR_WORKSPACE_OUTPUT_AMBIGUOUS",
    );
    handle = await fs.open(
      destination,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
    );
    const expected = identity(stat);
    const verify = async () => {
      assertSafe(
        same(identity(await handle.stat({ bigint: true })), expected) &&
          same(
            identity(await fs.lstat(destination, { bigint: true })),
            expected,
          ) &&
          (await fs.realpath(`/proc/self/fd/${handle.fd}`)) === staging.path &&
          (await fs.readdir(`/proc/self/fd/${handle.fd}`)).length === 0,
        "Output directory changed during creation.",
        "ERR_WORKSPACE_OUTPUT_AMBIGUOUS",
      );
    };
    await verify();
    await handle.sync();
    await verify();
    return { handle, identity: expected };
  } catch (cause) {
    // Unrecorded allocation identities stay ambiguous. Preserve the allocation
    // and its intent; never clean up a possible replacement.
    await handle?.close();
    throw cause;
  }
}

// Preparation publishes only the exact declared directory. In particular, a
// missing mount root never grants creation of its otherwise read-only parents.
export async function inspectOutputDirectory(
  fs,
  inspection,
  path,
  stagingPath,
) {
  assertSafe(
    inspection.outputPaths.includes(path),
    "Only an authorized output root may be prepared.",
  );
  const before = await inspectPath(fs, path, { missing: true });
  assertSafe(
    before.kind === "missing" || before.kind === "directory",
    "An output mount root must be a real directory.",
  );
  const parent = await inspectPath(fs, dirname(path));
  assertSafe(parent.kind === "directory", "Output parents must already exist.");
  if (before.exists)
    return { path, before, parent, storage: null, staging: null };
  const storage = await inspectPath(fs, inspection.stateRoot);
  const stat = await metadata(fs, storage.path);
  assertSafe(
    storage.kind === "directory" &&
      stat?.isDirectory() &&
      (stat.mode & 0o077n) === 0n &&
      stat.uid === BigInt(process.getuid()),
    "Output allocation requires private runner state storage.",
  );
  stagingPath ??= join(storage.path, `output-${randomUUID()}`);
  assertSafe(
    dirname(stagingPath) === storage.path &&
      /^output-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/u.test(
        basename(stagingPath),
      ),
    "Output allocation must remain in private runner state storage.",
  );
  const staging = await inspectPath(fs, stagingPath, { missing: true });
  return { path, before, parent, storage, staging };
}

export async function prepareOutputDirectory(
  fs,
  inspection,
  intent,
  { signal, beforeCreate, publishDirectory } = {},
) {
  const fresh = await inspectOutputDirectory(
    fs,
    inspection,
    intent?.path,
    intent?.staging?.path,
  );
  assertSafe(
    same(fresh, intent),
    "Output preparation may have completed or its bindings changed; preserve it for reconciliation.",
    "ERR_WORKSPACE_OUTPUT_AMBIGUOUS",
  );
  const parent = await openDirectory(fs, dirname(intent.path));
  let storage;
  let created;
  try {
    assertSafe(same(parent.binding, intent.parent), "Output parent changed.");
    const destination = join(parent.anchor, basename(intent.path));
    let expected = intent.before.identity;
    if (!intent.before.exists) {
      assertSafe(
        !intent.staging.exists && typeof publishDirectory === "function",
        "Output allocation requires an absent journaled allocation and supervised no-replace publication.",
        "ERR_WORKSPACE_OUTPUT_AMBIGUOUS",
      );
      storage = await openDirectory(fs, intent.storage.path);
      assertSafe(
        same(storage.binding, intent.storage),
        "State storage changed.",
      );
      assertSafe(
        storage.stat.dev === parent.stat.dev,
        "Output preparation requires state storage on the same filesystem.",
      );
      await beforeCreate?.();
      signal?.throwIfAborted();
      created = await createDirectory(fs, storage, intent.staging);
      expected = created.identity;
      await storage.handle.sync();
      await assertBindings(fs, [storage.binding, parent.binding]);
      assertSafe(
        (await fs.realpath(storage.anchor)) === intent.storage.path &&
          (await fs.realpath(parent.anchor)) === dirname(intent.path),
        "Output publication bindings changed.",
      );
      await beforeCreate?.();
      signal?.throwIfAborted();
      await publishDirectory({
        sourceParent: storage.handle.fd,
        sourceName: basename(intent.staging.path),
        destinationParent: parent.handle.fd,
        destinationName: basename(intent.path),
      });
      assertSafe(
        (await metadata(
          fs,
          join(storage.anchor, basename(intent.staging.path)),
        )) === null,
        "Output publication did not consume its owned allocation.",
        "ERR_WORKSPACE_OUTPUT_AMBIGUOUS",
      );
      await storage.handle.sync();
      await parent.handle.sync();
    }
    await assertBindings(fs, [parent.binding]);
    assertSafe(
      (await fs.realpath(parent.anchor)) === dirname(intent.path),
      "Output parent changed during preparation.",
    );
    const result = await inspectPath(fs, intent.path);
    const stat = await metadata(fs, destination);
    assertSafe(
      result.kind === "directory" &&
        stat?.isDirectory() &&
        same(result.identity, expected) &&
        same(result.identity, identity(stat)) &&
        (!intent.before.exists || same(result, intent.before)),
      "Prepared output directory changed.",
      "ERR_WORKSPACE_OUTPUT_AMBIGUOUS",
    );
    if (created)
      assertSafe(
        same(identity(await created.handle.stat({ bigint: true })), expected) &&
          (await fs.realpath(`/proc/self/fd/${created.handle.fd}`)) ===
            intent.path,
        "Prepared output directory changed before settlement.",
        "ERR_WORKSPACE_OUTPUT_AMBIGUOUS",
      );
    return result;
  } finally {
    await created?.handle.close();
    await storage?.handle.close();
    await parent.handle.close();
  }
}
