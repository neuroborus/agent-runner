import {
  accessSync,
  constants,
  existsSync,
  lstatSync,
  readlinkSync,
  realpathSync,
} from "node:fs";
import { dirname, isAbsolute, join, relative, sep } from "node:path";

import { BUBBLEWRAP_CANDIDATES } from "./linux-owned-process.js";

export const ISOLATION_SYSTEM_PATHS = Object.freeze([
  "/usr",
  "/bin",
  "/sbin",
  "/lib",
  "/lib64",
  "/etc",
]);

// Callers map each closed reason to their own diagnostic.
function launcherError(reason) {
  const error = new Error(`Isolation launcher check failed: ${reason}.`);
  error.reason = reason;
  return error;
}

function assertReadOnlyPath(path) {
  let current = path;
  while (true) {
    try {
      accessSync(current, constants.W_OK);
    } catch (cause) {
      if (!["EACCES", "EPERM", "EROFS"].includes(cause?.code)) {
        throw launcherError("changed");
      }
      // Continue only when this path cannot be changed by the runner identity.
      if (current === sep) {
        return;
      }
      current = dirname(current);
      continue;
    }
    throw launcherError("writable");
  }
}

export function verifyIsolationLauncher(path) {
  if (typeof path !== "string" || !isAbsolute(path) || !existsSync(path)) {
    throw launcherError("unavailable");
  }
  const canonicalPath = realpathSync(path);
  const metadata = lstatSync(canonicalPath);
  if (path !== canonicalPath || !metadata.isFile() || metadata.nlink !== 1) {
    throw launcherError("unsafe");
  }
  try {
    accessSync(canonicalPath, constants.X_OK);
  } catch {
    throw launcherError("not-executable");
  }
  assertReadOnlyPath(canonicalPath);
  return canonicalPath;
}

export function resolveIsolationLauncher(executable = null) {
  if (
    executable !== null &&
    (typeof executable !== "string" || !isAbsolute(executable))
  ) {
    throw launcherError("relative");
  }
  for (const candidate of executable === null
    ? BUBBLEWRAP_CANDIDATES
    : [executable]) {
    if (!existsSync(candidate)) {
      continue;
    }
    try {
      return verifyIsolationLauncher(realpathSync(candidate));
    } catch (cause) {
      if (executable !== null) {
        throw cause;
      }
    }
  }
  throw launcherError("unavailable");
}

function mountParents(targetPath) {
  const parts = relative(sep, targetPath).split(sep);
  const parents = [];
  let current = sep;
  for (const part of parts.slice(0, -1)) {
    current = join(current, part);
    parents.push(current);
  }
  return parents;
}

// Renders the fixed Linux profile; callers own mount authorization and order.
export function createIsolatedCommand({ launcher, cwd, mounts, command }) {
  if (process.platform !== "linux") {
    throw new Error("Command isolation requires Linux.");
  }
  const argumentsList = [
    "--die-with-parent",
    "--unshare-user",
    "--unshare-net",
    "--unshare-pid",
    "--cap-drop",
    "ALL",
    "--proc",
    "/proc",
    "--dev",
    "/dev",
    "--tmpfs",
    "/run",
    "--tmpfs",
    "/tmp",
  ];
  for (const path of ISOLATION_SYSTEM_PATHS) {
    if (!existsSync(path)) {
      continue;
    }
    if (lstatSync(path).isSymbolicLink()) {
      argumentsList.push("--symlink", readlinkSync(path), path);
    } else {
      argumentsList.push("--ro-bind", path, path);
    }
  }
  const createdParents = new Set();
  for (const { source, target, writable, parents } of mounts) {
    if (parents === "all") {
      for (const parent of mountParents(target)) {
        if (!createdParents.has(parent)) {
          argumentsList.push("--dir", parent);
          createdParents.add(parent);
        }
      }
    } else if (parents === "direct") {
      argumentsList.push("--dir", dirname(target));
    } else {
      throw new Error("Isolation mount parents are invalid.");
    }
    argumentsList.push(writable ? "--bind" : "--ro-bind", source, target);
  }
  argumentsList.push("--chdir", cwd, "--", ...command);
  return Object.freeze({
    executable: launcher,
    arguments: Object.freeze(argumentsList),
  });
}
