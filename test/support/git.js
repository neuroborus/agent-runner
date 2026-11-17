import { chmod, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";

// Isolated identity queries drop GIT_CONFIG_NOSYSTEM, so fixtures that assert
// identity restore the exclusion of host system configuration in a wrapper.
export async function createFixtureGitBinary(directory) {
  const path = join(resolve(directory), "fixture-git");
  await writeFile(
    path,
    '#!/bin/sh\nexport GIT_CONFIG_NOSYSTEM=1\nexec git "$@"\n',
    { flag: "wx", mode: 0o700 },
  );
  await chmod(path, 0o700);
  return path;
}
