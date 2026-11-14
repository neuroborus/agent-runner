import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { lstat, mkdir, open, realpath, rm, stat } from "node:fs/promises";
import { hostname } from "node:os";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";

import { createWorkspaceService } from "../../workspace/index.js";

// New allocations use the fixed platform temporary location so the provider
// TMPDIR leaves room for Claude's Unix-socket bridge names (sun_path is 108
// bytes including the terminator). Ambient temporary variables never apply.
const STORAGE_PARENT = "/tmp";

// The execution-resource journal uses a frozen command identity for each owner.
// This identity belongs to adapter preparation, never to a trusted check.
export const CLAUDE_STORAGE_IDENTITY = createHash("sha256")
  .update("agent-runner:claude:environment:v1")
  .digest("hex");

export function environmentError(stage) {
  return Object.assign(new Error(`Agent environment ${stage} is incomplete.`), {
    code:
      stage === "preparation"
        ? "ERR_AGENT_ENVIRONMENT_PREPARATION"
        : "ERR_EXECUTION_RESOURCE_UNVERIFIABLE",
    failure: {
      failureClass: `environment_${stage}`,
      checkpoint: stage === "preparation" ? "initialize" : "turn",
      outcome: stage === "preparation" ? "not_started" : "rejected",
      effect: stage === "preparation" ? "none" : "possible",
      retry: "transient",
    },
  });
}

function contains(parent, child) {
  const path = relative(parent, child);
  return (
    path === "" ||
    (!isAbsolute(path) && path !== ".." && !path.startsWith(`..${sep}`))
  );
}

function identity(info) {
  return { device: String(info.dev), inode: String(info.ino) };
}

function same(left, right) {
  return left?.device === right?.device && left?.inode === right?.inode;
}

async function inspect(path) {
  const info = await lstat(path, { bigint: true });
  if (
    !info.isDirectory() ||
    info.uid !== BigInt(process.getuid()) ||
    (info.mode & 0o777n) !== 0o700n ||
    (await realpath(path)) !== path
  ) {
    throw environmentError("cleanup");
  }
  return identity(info);
}

async function storageRoot(forbiddenPaths, recordedPath) {
  const name = `agent-runner-claude-${process.getuid()}`;
  const root = recordedPath ?? join(await realpath(STORAGE_PARENT), name);
  if (
    !isAbsolute(root) ||
    resolve(root) !== root ||
    basename(root) !== name ||
    (await realpath(dirname(root))) !== dirname(root)
  )
    throw environmentError("preparation");
  for (const path of forbiddenPaths) {
    // Task artifacts may not exist yet; check the normalized spelling as well.
    let ancestor = resolve(path);
    const missing = [];
    let canonical;
    while (canonical === undefined) {
      try {
        const info = await stat(ancestor);
        if (missing.length > 0 && !info.isDirectory())
          throw environmentError("preparation");
        canonical = join(await realpath(ancestor), ...missing);
      } catch (cause) {
        if (cause.code !== "ENOENT" || dirname(ancestor) === ancestor)
          throw cause;
        missing.unshift(basename(ancestor));
        ancestor = dirname(ancestor);
      }
    }
    if (
      [resolve(path), canonical].some(
        (candidate) => contains(candidate, root) || contains(root, candidate),
      )
    )
      throw environmentError("preparation");
  }
  return root;
}

async function pinnedRoot(root) {
  const handle = await open(
    root.path,
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
  );
  try {
    if (
      !same(identity(await handle.stat({ bigint: true })), root) ||
      !same(await inspect(root.path), root)
    )
      throw environmentError("cleanup");
    return handle;
  } catch (cause) {
    await handle.close();
    throw cause;
  }
}

export async function recoverClaudeStorage({
  resource,
  storageForbiddenPaths = [],
  workspacePolicy,
  onResource,
}) {
  try {
    if (workspacePolicy !== undefined) {
      const { kind, ...declarations } = workspacePolicy;
      if (kind !== "directory") throw environmentError("cleanup");
      // Retired turns may have changed a control pointer to reference storage.
      // Discover current exclusions before deletion without accepting frozen
      // input drift or requiring deleted inputs to exist for owned cleanup.
      const inspection = await createWorkspaceService().inspect({
        ...declarations,
        inputPaths: [],
        sourcePaths: [],
        configurationPaths: [],
        artifactPaths: [
          ...(declarations.artifactPaths ?? []),
          ...(declarations.inputPaths ?? []),
          ...(declarations.sourcePaths ?? []),
          ...(declarations.configurationPaths ?? []),
        ],
      });
      storageForbiddenPaths = [
        ...storageForbiddenPaths,
        inspection.stateRoot,
        ...inspection.protectedPaths,
      ];
    }
    if (
      resource.commandIdentity !== CLAUDE_STORAGE_IDENTITY ||
      resource.hostname !== hostname() ||
      !/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/u.test(resource.id) ||
      !["allocating", "allocated"].includes(resource.phase) ||
      resource.root.path !==
        (await storageRoot(storageForbiddenPaths, resource.root.path))
    ) {
      throw environmentError("cleanup");
    }
    const parent = await pinnedRoot(resource.root);
    try {
      const path = join(`/proc/self/fd/${parent.fd}`, resource.id);
      let info;
      try {
        info = await lstat(path, { bigint: true });
      } catch (cause) {
        if (cause.code !== "ENOENT") throw cause;
      }
      if (info !== undefined) {
        if (
          resource.phase !== "allocated" ||
          !info.isDirectory() ||
          info.uid !== BigInt(process.getuid()) ||
          (info.mode & 0o777n) !== 0o700n ||
          !same(identity(info), resource.directory)
        )
          throw environmentError("cleanup");
        await rm(path, { recursive: true });
      }
      await parent.sync();
    } finally {
      await parent.close();
    }
    await onResource?.(null);
  } catch {
    // Retain the journal; never publish filesystem paths or raw diagnostics.
    throw environmentError("cleanup");
  }
}

export async function allocateClaudeStorage({
  cwd,
  storageForbiddenPaths = [],
  workspacePolicy,
  onResource,
  signal,
}) {
  const forbiddenPaths = [cwd, ...storageForbiddenPaths];
  let resource;
  const publish = async (value) => {
    resource = value;
    await onResource?.(value);
  };
  try {
    const path = await storageRoot(forbiddenPaths);
    await mkdir(path, { mode: 0o700 }).catch((cause) => {
      if (cause.code !== "EEXIST") throw cause;
    });
    const root = { path, ...(await inspect(path)) };
    const parent = await pinnedRoot(root);
    try {
      const intent = {
        id: randomUUID(),
        hostname: hostname(),
        commandIdentity: CLAUDE_STORAGE_IDENTITY,
        phase: "allocating",
        root,
        directory: null,
      };
      // A rejected initial write may belong to another retained resource.
      // Do not acknowledge its removal or allocate before this intent is owned.
      await onResource?.(intent);
      resource = intent;
      signal?.throwIfAborted();
      await mkdir(join(`/proc/self/fd/${parent.fd}`, resource.id), {
        mode: 0o700,
      });
      await parent.sync();
      const directory = join(path, resource.id);
      await publish({
        ...resource,
        phase: "allocated",
        directory: await inspect(directory),
      });
      return Object.freeze({
        directory,
        async verify() {
          if (
            !same(await inspect(path), root) ||
            !same(await inspect(directory), resource.directory)
          ) {
            throw environmentError("preparation");
          }
        },
        async remove() {
          await recoverClaudeStorage({
            resource,
            storageForbiddenPaths: forbiddenPaths,
            workspacePolicy,
            onResource: publish,
          });
        },
      });
    } finally {
      await parent.close();
    }
  } catch {
    if (resource !== undefined && resource !== null) {
      await recoverClaudeStorage({
        resource,
        storageForbiddenPaths: forbiddenPaths,
        workspacePolicy,
        onResource: publish,
      });
    }
    throw environmentError("preparation");
  }
}
