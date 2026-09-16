import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { access, lstat, mkdir, open, realpath, rm } from "node:fs/promises";
import { hostname, tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

const ID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
export const STORAGE_PATHS = Object.freeze({
  scratch: "/run/agent-runner/scratch",
  cache: "/run/agent-runner/cache",
});

function resourceError(cause) {
  return Object.assign(
    new Error("Trusted execution storage ownership cannot be verified.", {
      cause,
    }),
    {
      code: "ERR_TRUSTED_VALIDATION_RESOURCE_UNVERIFIABLE",
    },
  );
}

function overlaps(left, right) {
  const path = relative(left, right);
  return (
    path === "" ||
    (path !== ".." && !path.startsWith(`..${sep}`) && !isAbsolute(path))
  );
}

async function directoryIdentity(path) {
  const info = await lstat(path, { bigint: true });
  if (
    !info.isDirectory() ||
    info.uid !== BigInt(process.getuid()) ||
    (info.mode & 0o777n) !== 0o700n ||
    (await realpath(path)) !== path
  )
    throw resourceError();
  return { device: String(info.dev), inode: String(info.ino) };
}

function sameIdentity(left, right) {
  return left?.device === right?.device && left?.inode === right?.inode;
}

export function createResourceStorage({
  storageRoot = join(tmpdir(), `agent-runner-validation-${process.getuid?.()}`),
} = {}) {
  async function checkRoot(forbiddenPaths) {
    if (
      process.platform !== "linux" ||
      typeof storageRoot !== "string" ||
      !isAbsolute(storageRoot) ||
      resolve(storageRoot) !== storageRoot ||
      forbiddenPaths.some(
        (path) => overlaps(path, storageRoot) || overlaps(storageRoot, path),
      )
    )
      throw resourceError();
    if ((await realpath(dirname(storageRoot))) !== dirname(storageRoot))
      throw resourceError();
    try {
      await directoryIdentity(storageRoot);
      await access(storageRoot, constants.W_OK | constants.X_OK);
    } catch (cause) {
      if (cause?.code !== "ENOENT") throw cause;
      await access(dirname(storageRoot), constants.W_OK | constants.X_OK);
    }
  }

  async function preflight(forbiddenPaths, capabilities = {}) {
    try {
      for (const [name, target] of Object.entries(STORAGE_PATHS)) {
        if (
          capabilities[name] === true &&
          forbiddenPaths.some(
            (path) => overlaps(path, target) || overlaps(target, path),
          )
        )
          throw resourceError();
      }
      await checkRoot(forbiddenPaths);
    } catch (cause) {
      throw Object.assign(
        new Error("Isolated trusted execution storage is unavailable.", {
          cause,
        }),
        {
          code: "ERR_TRUSTED_VALIDATION_CAPABILITY_UNAVAILABLE",
        },
      );
    }
  }

  async function allocate({ command, forbiddenPaths, onResource, signal }) {
    if (typeof onResource !== "function") throw resourceError();
    await preflight(forbiddenPaths, command.capabilities);
    await mkdir(storageRoot, { mode: 0o700 }).catch((cause) => {
      if (cause.code !== "EEXIST") throw cause;
    });
    const root = {
      path: storageRoot,
      ...(await directoryIdentity(storageRoot)),
    };
    const intent = {
      id: randomUUID(),
      hostname: hostname(),
      commandIdentity: command.identity,
      phase: "allocating",
      root,
      directory: null,
    };
    const parent = await open(
      storageRoot,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
    );
    try {
      const info = await parent.stat({ bigint: true });
      if (
        !sameIdentity(
          { device: String(info.dev), inode: String(info.ino) },
          root,
        )
      )
        throw resourceError();
      // The journal owns the intent before any per-execution storage exists.
      await onResource(intent);
      signal?.throwIfAborted();
      await mkdir(join(`/proc/self/fd/${parent.fd}`, intent.id), {
        mode: 0o700,
      });
      await parent.sync();
      const path = join(root.path, intent.id);
      if (!sameIdentity(await directoryIdentity(storageRoot), root))
        throw resourceError();
      const allocated = {
        ...intent,
        phase: "allocated",
        directory: await directoryIdentity(path),
      };
      await onResource(allocated);
      const child = await open(
        path,
        constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
      );
      try {
        const info = await child.stat({ bigint: true });
        if (
          !sameIdentity(
            { device: String(info.dev), inode: String(info.ino) },
            allocated.directory,
          )
        )
          throw resourceError();
        const mounts = {};
        for (const name of Object.keys(STORAGE_PATHS)) {
          if (command.capabilities?.[name] !== true) continue;
          await mkdir(join(`/proc/self/fd/${child.fd}`, name), { mode: 0o700 });
          const source = join(path, name);
          await directoryIdentity(source);
          mounts[name] = source;
        }
        await child.sync();
        if (
          !sameIdentity(await directoryIdentity(storageRoot), root) ||
          !sameIdentity(await directoryIdentity(path), allocated.directory)
        )
          throw resourceError();
        signal?.throwIfAborted();
        return { record: allocated, mounts };
      } finally {
        await child.close();
      }
    } finally {
      await parent.close();
    }
  }

  async function cleanup(record, { forbiddenPaths, onResource }) {
    try {
      if (
        !record ||
        !ID.test(record.id) ||
        record.hostname !== hostname() ||
        record.root?.path !== storageRoot ||
        !["allocating", "allocated"].includes(record.phase)
      )
        throw resourceError();
      await checkRoot(forbiddenPaths);
      if (!sameIdentity(await directoryIdentity(storageRoot), record.root))
        throw resourceError();
      // Pin the private parent while removing the owned child. Command processes
      // cannot reach this parent and must already be retired by the caller.
      const parent = await open(
        storageRoot,
        constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
      );
      try {
        const info = await parent.stat({ bigint: true });
        if (
          !sameIdentity(
            { device: String(info.dev), inode: String(info.ino) },
            record.root,
          )
        )
          throw resourceError();
        const path = join(`/proc/self/fd/${parent.fd}`, record.id);
        let child;
        try {
          child = await lstat(path, { bigint: true });
        } catch (cause) {
          if (cause.code !== "ENOENT") throw cause;
        }
        if (child !== undefined) {
          if (
            record.phase !== "allocated" ||
            !child.isDirectory() ||
            child.uid !== BigInt(process.getuid()) ||
            (child.mode & 0o777n) !== 0o700n ||
            !sameIdentity(
              { device: String(child.dev), inode: String(child.ino) },
              record.directory,
            )
          )
            throw resourceError();
          await rm(path, { recursive: true, force: false });
        }
        // Persist removal before clearing ownership, including recovery after
        // an interrupted cleanup whose child is already absent.
        await parent.sync();
      } finally {
        await parent.close();
      }
      await onResource(null);
    } catch (cause) {
      throw resourceError(cause);
    }
  }

  return Object.freeze({ preflight, allocate, cleanup });
}
