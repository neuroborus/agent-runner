import assert from "node:assert/strict";
import {
  link,
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  inspectFinalizationFile,
  parseRunnerConfiguration,
} from "../../src/config/index.js";

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), "runner-finalization-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const projectPath = join(root, "project");
  const infrastructureRoot = join(root, "infrastructure");
  await Promise.all([mkdir(projectPath), mkdir(infrastructureRoot)]);
  await mkdir(join(infrastructureRoot, "finalization"));
  const path = "finalization/SKILL.md";
  const file = join(infrastructureRoot, path);
  await writeFile(file, "Run the project checks.\n");
  return { root, projectPath, infrastructureRoot, path, file };
}

test("accepts exact Markdown procedures without skill frontmatter in both pipeline settings", () => {
  const configuration = parseRunnerConfiguration(
    JSON.stringify({
      schemaVersion: 1,
      pipelines: {
        "plan-execution": {
          finalization: ".agents/skills/finalization/RUNNER.md",
        },
        polishing: { finalization: "finalization/SKILL.md" },
      },
    }),
  );
  assert.equal(
    configuration.pipelines["plan-execution"].finalization,
    ".agents/skills/finalization/RUNNER.md",
  );
  assert.equal(
    configuration.pipelines.polishing.finalization,
    "finalization/SKILL.md",
  );
});

test("binds external file bytes and identity without copying its content", async (t) => {
  const f = await fixture(t);
  const original = await inspectFinalizationFile(f);
  assert.equal(original.path, f.file);
  assert.equal(original.relativePath, f.path);
  assert.equal(original.inventoryPath, `finalization://${f.path}`);
  assert.deepEqual(await inspectFinalizationFile(f), original);
  assert.doesNotMatch(JSON.stringify(original), /Run the project checks/u);
  const content = await readFile(f.file);
  await rename(f.file, `${f.file}.saved`);
  await writeFile(f.file, content);
  assert.notEqual(
    (await inspectFinalizationFile(f)).fingerprint,
    original.fingerprint,
  );
  await writeFile(f.file, "Run a different check.\n");
  assert.notEqual(
    (await inspectFinalizationFile(f)).fingerprint,
    original.fingerprint,
  );
});

test("rejects file and ancestor links, hard links, escape and non-file selections", async (t) => {
  const f = await fixture(t);
  const invalid = { code: "ERR_FINALIZATION_FILE_INVALID" };
  await symlink(f.file, join(f.infrastructureRoot, "linked.md"));
  await assert.rejects(
    inspectFinalizationFile({ ...f, path: "linked.md" }),
    invalid,
  );
  await symlink(
    join(f.infrastructureRoot, "finalization"),
    join(f.infrastructureRoot, "alias"),
  );
  await assert.rejects(
    inspectFinalizationFile({ ...f, path: "alias/SKILL.md" }),
    invalid,
  );
  for (const path of ["alias/missing.md", "alias/missing/SKILL.md"]) {
    await assert.rejects(inspectFinalizationFile({ ...f, path }), invalid);
  }
  await link(f.file, join(f.infrastructureRoot, "hard.md"));
  await assert.rejects(inspectFinalizationFile(f), invalid);
  await assert.rejects(
    inspectFinalizationFile({ ...f, path: "../project/README.md" }),
    invalid,
  );
  await mkdir(join(f.infrastructureRoot, "directory.md"));
  await assert.rejects(
    inspectFinalizationFile({ ...f, path: "directory.md" }),
    invalid,
  );
  assert.equal(
    (await inspectFinalizationFile({ ...f, path: "absent.md" })).exists,
    false,
  );
});

test("binds the target and real infrastructure ancestors across replacement", async (t) => {
  const f = await fixture(t);
  const original = await inspectFinalizationFile(f);
  await rename(f.projectPath, `${f.projectPath}.original`);
  await mkdir(f.projectPath);
  const replacedTarget = await inspectFinalizationFile(f);
  assert.notEqual(replacedTarget.fingerprint, original.fingerprint);
  const parent = join(f.infrastructureRoot, "finalization");
  await rename(parent, `${parent}.original`);
  await mkdir(parent);
  await writeFile(f.file, "Run the project checks.\n");
  assert.notEqual(
    (await inspectFinalizationFile(f)).fingerprint,
    replacedTarget.fingerprint,
  );
});
