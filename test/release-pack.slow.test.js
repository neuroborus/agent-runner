import assert from "node:assert/strict";
import { lstat, mkdtemp, readFile, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";

import { assembleRelease, packRelease } from "../scripts/assemble-release.js";

test("the actual npm archive contains the complete standalone application", async (t) => {
  const directory = await realpath(
    await mkdtemp(join(tmpdir(), "agent-runner-pack-")),
  );
  t.after(() => rm(directory, { recursive: true, force: true }));
  const release = await assembleRelease({
    outputPath: join(directory, "candidate"),
  });
  const packed = await packRelease(release);
  assert.equal(packed.files, release.manifest.files.length + 1);
  const application = await import(
    pathToFileURL(join(release.packagePath, "src/index.js"))
  );
  assert.equal(application.listPipelines().length, 5);
  assert.equal(release.manifest.dependencies.length, 10);
  assert.deepEqual(
    await readFile(join(release.packagePath, "docs/OPERATOR_GUIDE.md")),
    await readFile(new URL("../docs/OPERATOR_GUIDE.md", import.meta.url)),
  );
  for (const dependency of release.manifest.dependencies)
    assert.equal(
      (await lstat(join(release.packagePath, dependency.path))).isDirectory(),
      true,
    );
  assert.equal(
    (await lstat(join(release.packagePath, "bin/agent-run.js"))).mode & 0o111,
    0o111,
  );
});
