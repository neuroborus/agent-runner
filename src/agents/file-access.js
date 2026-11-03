import { constants } from "node:fs";
import { access, lstat, realpath } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";

// Preservation already verifies the bytes. Admission additionally requires
// exact regular-file paths visible through the provider's command mounts.
export async function canReadFiles(paths, hiddenRoots = []) {
  if (!Array.isArray(paths) || paths.length === 0) return false;
  try {
    for (const path of paths) {
      if (
        typeof path !== "string" ||
        !isAbsolute(path) ||
        resolve(path) !== path ||
        hiddenRoots.some((root) => {
          const name = relative(root, path);
          return name === "" || (name !== ".." && !name.startsWith(`..${sep}`));
        }) ||
        (await realpath(path)) !== path ||
        !(await lstat(path)).isFile()
      )
        return false;
      await access(path, constants.R_OK);
    }
    return true;
  } catch {
    return false;
  }
}
