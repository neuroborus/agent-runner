import assert from "node:assert/strict";
import { lstat, readFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";

import { assembleRelease, packRelease } from "../scripts/assemble-release.js";
import { prepareRuntime } from "../src/runtime/index.js";
import { runtimeFixtureDirectory } from "./support/index.js";

test("the actual npm archive contains the complete standalone application", async (t) => {
  const directory = await runtimeFixtureDirectory(t);
  const release = await assembleRelease({
    outputPath: join(directory, "candidate"),
  });
  const packed = await packRelease(release);
  assert.equal(packed.files, release.manifest.files.length + 1);
  const runtime = await prepareRuntime({
    rootPath: release.packagePath,
    storageRoot: join(directory, "runtime"),
  });
  assert.equal(runtime.mode, "pinned");
  assert.equal((await lstat(runtime.executablePath)).mode & 0o777, 0o500);
  const application = await import(
    pathToFileURL(join(runtime.rootPath, "src/index.js"))
  );
  assert.equal(application.listPipelines().length, 5);
  assert.equal(release.manifest.dependencies.length, 10);
  assert.deepEqual(
    await readFile(join(runtime.rootPath, "docs/OPERATOR_GUIDE.md")),
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
