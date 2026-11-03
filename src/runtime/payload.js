import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import {
  lstat,
  mkdir,
  open,
  readdir,
  readlink,
  symlink,
} from "node:fs/promises";
import { basename, dirname, join } from "node:path";

import {
  digest,
  parseManifest,
  payloadDirectoryId,
  RuntimePayloadError,
} from "./contract.js";
import {
  assertOwned,
  bindDirectory,
  descriptorPath,
  DIRECTORY_FLAGS,
  readRegular,
  sameFile,
} from "./files.js";

// Read the publication reference as metadata, never as a filesystem traversal.
// Its only valid destination is one sibling tree carrying this exact identity.
async function readPublication(payloadsPath, id) {
  const path = join(payloadsPath, id);
  const identity = await lstat(path, { bigint: true });
  if (
    !identity.isSymbolicLink() ||
    identity.nlink !== 1n ||
    typeof process.getuid !== "function" ||
    identity.uid !== BigInt(process.getuid())
  )
    throw new RuntimePayloadError("Invalid payload publication reference.");
  const name = await readlink(path);
  if (payloadDirectoryId(name) !== id)
    throw new RuntimePayloadError("Payload publication escaped its identity.");
  const verify = async () => {
    if (!sameFile(identity, await lstat(path, { bigint: true })))
      throw new RuntimePayloadError("Payload publication changed.");
  };
  await verify();
  return { name, verify };
}

export async function inspectPayload(
  rootPath,
  { immutable = false, published = false } = {},
) {
  const root = await bindDirectory(rootPath, {
    privateParents: immutable ? 2 : 0,
  });
  try {
    const manifestFile = await readRegular(
      join(root.anchor, "release-manifest.json"),
      2 * 1024 * 1024,
    );
    const parsed = parseManifest(manifestFile.bytes);
    const publication = published
      ? await readPublication(dirname(rootPath), parsed.id)
      : null;
    if (publication && publication.name !== basename(rootPath))
      throw new RuntimePayloadError("Payload is not the published tree.");
    const captured = new Map();
    const guards = [];
    async function walk(handle, path) {
      const anchor = await descriptorPath(handle);
      const before = await handle.stat({ bigint: true });
      if (immutable) assertOwned(before, 0o500);
      guards.push({ path, metadata: before });
      for (const name of (await readdir(anchor)).sort()) {
        const child = join(anchor, name);
        const childPath = path ? `${path}/${name}` : name;
        // The documented legacy global file stays at the outer installation.
        if (!immutable && childPath === ".agent-runner.json") continue;
        const metadata = await lstat(child, { bigint: true });
        if (metadata.isDirectory()) {
          if (
            ![...parsed.files.keys()].some((file) =>
              file.startsWith(`${childPath}/`),
            )
          )
            throw new RuntimePayloadError(
              "Application contains an undeclared directory.",
            );
          const nested = await open(child, DIRECTORY_FLAGS);
          try {
            if (!sameFile(metadata, await nested.stat({ bigint: true })))
              throw new RuntimePayloadError("Application directory changed.");
            await walk(nested, childPath);
          } finally {
            await nested.close();
          }
          continue;
        }
        const expected = parsed.files.get(childPath);
        if (!expected && childPath !== "release-manifest.json")
          throw new RuntimePayloadError(
            "Application contains an undeclared file.",
          );
        const file = await readRegular(
          child,
          childPath === "release-manifest.json"
            ? 2 * 1024 * 1024
            : expected.size,
        );
        if (immutable)
          assertOwned(file.metadata, expected?.mode === 0o755 ? 0o500 : 0o400);
        else if (
          (file.metadata.mode & 0o7000n) !== 0n ||
          ((file.metadata.mode & 0o111n) !== 0n ? 0o755 : 0o644) !==
            (expected?.mode ?? 0o644)
        )
          throw new RuntimePayloadError(
            "Application permissions disagree with the manifest.",
          );
        if (
          expected
            ? file.bytes.length !== expected.size ||
              digest(file.bytes) !== expected.sha256
            : !file.bytes.equals(manifestFile.bytes)
        )
          throw new RuntimePayloadError(
            "Application content disagrees with the manifest.",
          );
        guards.push({ path: childPath, metadata: file.metadata });
        captured.set(childPath, {
          bytes: file.bytes,
          mode: expected?.mode ?? 0o644,
        });
      }
      if (!sameFile(before, await handle.stat({ bigint: true })))
        throw new RuntimePayloadError(
          "Application directory changed during inspection.",
        );
    }
    await walk(root.handle, "");
    for (const guard of guards)
      if (
        !sameFile(
          guard.metadata,
          guard.path
            ? await lstat(join(root.anchor, guard.path), { bigint: true })
            : await root.handle.stat({ bigint: true }),
        )
      )
        throw new RuntimePayloadError("Application changed during inspection.");
    await publication?.verify();
    await root.verify();
    if (captured.size !== parsed.files.size + 1)
      throw new RuntimePayloadError("Application payload is incomplete.");
    const metadata = JSON.parse(captured.get("package.json").bytes.toString());
    if (
      metadata.name !== parsed.manifest.name ||
      metadata.version !== parsed.manifest.version ||
      metadata.type !== "module" ||
      metadata.engines?.node !== ">=24 <25" ||
      metadata.workspaces !== undefined
    )
      throw new RuntimePayloadError(
        "Application metadata disagrees with its manifest.",
      );
    if (
      metadata.exports !== "./src/index.js" ||
      !["./bin/agent-run.js", "bin/agent-run.js"].includes(
        metadata.bin?.["agent-run"],
      ) ||
      parsed.files.get("bin/agent-run.js").mode !== 0o755
    )
      throw new RuntimePayloadError("Application entry points are incomplete.");
    const packages = new Map([["", metadata]]);
    for (const dependency of parsed.manifest.dependencies) {
      const metadata = JSON.parse(
        captured.get(`${dependency.path}/package.json`).bytes.toString(),
      );
      if (
        metadata.name !== dependency.name ||
        metadata.version !== dependency.version
      )
        throw new RuntimePayloadError(
          "Application dependency identity changed.",
        );
      packages.set(dependency.path, metadata);
    }
    const visited = new Set();
    function visit(slot) {
      if (visited.has(slot)) return;
      visited.add(slot);
      const metadata = packages.get(slot);
      if (
        Object.keys(metadata.optionalDependencies ?? {}).length ||
        Object.keys(metadata.peerDependencies ?? {}).length
      )
        throw new RuntimePayloadError(
          "Unsupported application dependency closure.",
        );
      for (const name of Object.keys(metadata.dependencies ?? {})) {
        if (!/^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/u.test(name))
          throw new RuntimePayloadError("Invalid application dependency name.");
        let owner = slot;
        let target;
        for (;;) {
          const candidate = `${owner ? owner + "/" : ""}node_modules/${name}`;
          if (!owner.endsWith("node_modules") && packages.has(candidate)) {
            target = candidate;
            break;
          }
          if (owner === "") break;
          owner = dirname(owner);
          if (owner === ".") owner = "";
        }
        if (!target || packages.get(target).name !== name)
          throw new RuntimePayloadError(
            "Application production dependency is missing.",
          );
        visit(target);
      }
    }
    visit("");
    if (visited.size !== packages.size)
      throw new RuntimePayloadError(
        "Application contains an unreferenced dependency.",
      );
    return { ...parsed, captured, manifestBytes: manifestFile.bytes };
  } finally {
    await root.close();
  }
}

export async function materializePayload(
  source,
  storageRoot,
  { beforeSeal = async () => {}, beforePublish = async () => {} } = {},
) {
  const storage = await bindDirectory(storageRoot, { create: true });
  let payloads;
  let preparationBinding;
  try {
    assertOwned(await storage.handle.stat({ bigint: true }), 0o700);
    try {
      await mkdir(join(storage.anchor, "payloads"), { mode: 0o700 });
      await storage.handle.sync();
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
    }
    payloads = await bindDirectory(join(storageRoot, "payloads"));
    assertOwned(await payloads.handle.stat({ bigint: true }), 0o700);
    async function verifyTarget() {
      const publication = await readPublication(payloads.anchor, source.id);
      const target = join(storageRoot, "payloads", publication.name);
      const ready = await inspectPayload(target, {
        immutable: true,
        published: true,
      });
      if (!ready.manifestBytes.equals(source.manifestBytes))
        throw new RuntimePayloadError("Stored payload was substituted.");
      await publication.verify();
      await storage.verify();
      await payloads.verify();
      return target;
    }
    async function targetExists() {
      try {
        await lstat(join(payloads.anchor, source.id));
        return true;
      } catch (error) {
        if (error.code === "ENOENT") return false;
        throw error;
      }
    }
    if (await targetExists()) return await verifyTarget();
    const name = `.payload-${source.id}-${randomUUID()}`;
    await mkdir(join(payloads.anchor, name), { mode: 0o700 });
    const preparationPath = join(storageRoot, "payloads", name);
    preparationBinding = await bindDirectory(preparationPath);
    const preparation = preparationBinding.anchor;
    const directories = new Set([preparation]);
    const files = new Map();
    for (const [path, file] of source.captured) {
      const destination = join(preparation, path);
      for (
        let directory = dirname(destination);
        directory !== preparation;
        directory = dirname(directory)
      )
        directories.add(directory);
      await mkdir(dirname(destination), { recursive: true, mode: 0o700 });
      const handle = await open(destination, "wx", 0o600);
      try {
        await handle.writeFile(file.bytes);
        await handle.sync();
        files.set(destination, await handle.stat({ bigint: true }));
      } finally {
        await handle.close();
      }
    }
    const directoryIdentities = new Map();
    const directoryIdentity = (directory) =>
      directory === preparation
        ? preparationBinding.handle.stat({ bigint: true })
        : lstat(directory, { bigint: true });
    for (const directory of directories)
      directoryIdentities.set(directory, await directoryIdentity(directory));
    await beforeSeal({ preparationPath, payloadId: source.id });
    await preparationBinding.verify();
    // Seal only descriptors matching the entries this preparation created.
    // A substituted ancestor or leaf must never redirect a permission change.
    for (const [directory, identity] of directoryIdentities)
      if (!sameFile(identity, await directoryIdentity(directory)))
        throw new RuntimePayloadError("Preparation directory changed.");
    for (const [path, file] of source.captured) {
      const destination = join(preparation, path);
      const handle = await open(
        destination,
        constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
      );
      try {
        if (
          !sameFile(files.get(destination), await handle.stat({ bigint: true }))
        )
          throw new RuntimePayloadError("Preparation file changed.");
        await handle.chmod(file.mode === 0o755 ? 0o500 : 0o400);
        await handle.sync();
      } finally {
        await handle.close();
      }
    }
    for (const directory of [...directories].sort(
      (a, b) => b.length - a.length,
    )) {
      const handle = await open(
        directory === preparation ? `${directory}/.` : directory,
        DIRECTORY_FLAGS,
      );
      try {
        if (
          !sameFile(
            directoryIdentities.get(directory),
            await handle.stat({ bigint: true }),
          )
        )
          throw new RuntimePayloadError("Preparation directory changed.");
        await handle.chmod(0o500);
        await handle.sync();
      } finally {
        await handle.close();
      }
    }
    await inspectPayload(preparationPath, {
      immutable: true,
    });
    await storage.verify();
    await payloads.verify();
    if (await targetExists()) return await verifyTarget();
    await beforePublish({ preparationPath, payloadId: source.id });
    try {
      // Exclusive link creation cannot replace even an arriving empty directory.
      await symlink(name, join(payloads.anchor, source.id), "dir");
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
    }
    await payloads.handle.sync();
    await storage.handle.sync();
    return await verifyTarget();
  } finally {
    await preparationBinding?.close();
    await payloads?.close();
    await storage.close();
  }
}
