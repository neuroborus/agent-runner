import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import filesystem, {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { createGitService } from "../../src/git/index.js";

const executeFile = promisify(execFile);

async function fixture(t, { unborn = false } = {}) {
  const root = await mkdtemp(join(tmpdir(), "agent-runner-measurement-"));
  t.after(() => rm(root, { force: true, recursive: true }));
  const projectPath = join(root, "project");
  await mkdir(projectPath);
  const env = {
    ...Object.fromEntries(
      Object.entries(process.env).filter(([name]) => !name.startsWith("GIT_")),
    ),
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_OPTIONAL_LOCKS: "0",
    GIT_TERMINAL_PROMPT: "0",
    HOME: root,
    LC_ALL: "C",
    XDG_CONFIG_HOME: root,
  };
  const git = (...args) =>
    executeFile("git", ["-C", projectPath, ...args], { env });
  await git("init", "-q", "-b", "main");
  await git("config", "user.name", "Fixture User");
  await git("config", "user.email", "fixture@example.com");
  const write = (path, content) => writeFile(join(projectPath, path), content);
  if (!unborn) {
    await write(".gitignore", "ignored.txt\n");
    await write(".gitattributes", "*.txt diff=blocked\n");
    await write("changed.txt", "first\nsecond\nthird\n");
    await write("deleted.txt", "remove\nlast line");
    await write("mode.txt", "same\n");
    await write("binary.dat", Buffer.from([0, 1, 2]));
    await mkdir(join(projectPath, "directory"));
    await write("directory/child.txt", "child\n");
    await git("add", ".");
    await git("commit", "-qm", "fixture");
  }
  const service = createGitService({ env });
  const { head: baseHead } = await service.inspectHead({ projectPath });
  const measure = async () =>
    service.measureChanges({
      projectPath,
      baseHead,
      expectedContentFingerprint: await service.contentFingerprint({
        projectPath,
      }),
    });
  return { root, projectPath, service, baseHead, git, write, measure };
}

test("measures final worktree lines once across mixed staging without effects", async (t) => {
  const f = await fixture(t);
  await f.write("changed.txt", "first\nstaged\nthird\n");
  await f.git("add", "changed.txt");
  await f.write("changed.txt", "first\nreplacement\nthird\nextra\n");
  await rm(join(f.projectPath, "deleted.txt"));
  await f.write("new\tfile.txt", Buffer.from([0xff, 10, 0xfe]));
  await f.write("ignored.txt", "ignored\n".repeat(100));
  const indexBefore = await readFile(join(f.projectPath, ".git/index"));
  const result = await f.measure();
  assert.deepEqual(result, {
    baseHead: f.baseHead,
    contentFingerprint: await f.service.contentFingerprint({
      projectPath: f.projectPath,
    }),
    additions: 4,
    deletions: 3,
    changedLines: 7,
    changedPaths: ["changed.txt", "deleted.txt", "new\tfile.txt"],
    binaryPaths: [],
    gitlinkPaths: [],
  });
  assert.deepEqual(
    await readFile(join(f.projectPath, ".git/index")),
    indexBefore,
  );
  assert.equal(
    (await f.service.inspectHead({ projectPath: f.projectPath })).head,
    f.baseHead,
  );
  await f.git("add", "-A");
  assert.deepEqual(await f.measure(), result);
});

test("separates binary changes, ignores index-only bytes and counts link text safely", async (t) => {
  const f = await fixture(t);
  await f.write("binary.dat", Buffer.from([0, 3, 4]));
  await f.write("new.dat", Buffer.from([0, 5]));
  await chmod(join(f.projectPath, "mode.txt"), 0o755);
  await f.write("changed.txt", "staged only\n");
  await f.git("add", "changed.txt");
  await f.write("changed.txt", "first\nsecond\nthird\n");
  await f.write("index-only.dat", Buffer.from([0, 6]));
  await f.git("add", "index-only.dat");
  await rm(join(f.projectPath, "index-only.dat"));
  const outside = join(f.root, "outside.txt");
  await writeFile(outside, "outside\n".repeat(100));
  await symlink(outside, join(f.projectPath, "link.txt"));
  const first = await f.measure();
  assert.equal(first.additions, 1);
  assert.equal(first.deletions, 0);
  assert.deepEqual(first.binaryPaths, ["binary.dat", "new.dat"]);
  await writeFile(outside, "different outside content\n");
  assert.deepEqual(await f.measure(), first);
  await rm(join(f.projectPath, "binary.dat"));
  const deleted = await f.measure();
  assert.deepEqual(deleted.binaryPaths, first.binaryPaths);
  assert.equal(deleted.changedLines, 1);
});

test("measures index-hidden changes and raw newline changes without configured helpers", async (t) => {
  const f = await fixture(t);
  await f.git("config", "diff.external", "/not-a-diff-helper");
  await f.git("config", "diff.blocked.command", "/not-a-diff-helper");
  await f.git("config", "diff.blocked.textconv", "/not-a-text-converter");
  await f.git("config", "diff.algorithm", "histogram");
  await f.git("update-index", "--assume-unchanged", "changed.txt");
  await f.git("update-index", "--skip-worktree", "deleted.txt");
  await f.write("changed.txt", "first\nsecond\nthird");
  await f.write("deleted.txt", "replacement\n");
  const result = await f.measure();
  assert.equal(result.additions, 2);
  assert.equal(result.deletions, 3);
  assert.equal(result.changedLines, 5);
});

test("measures file/directory replacements and renames as independent paths", async (t) => {
  const f = await fixture(t);
  await rm(join(f.projectPath, "directory"), { recursive: true });
  await f.write("directory", "replacement\n");
  await rm(join(f.projectPath, "changed.txt"));
  await mkdir(join(f.projectPath, "changed.txt"));
  await f.write("changed.txt/new.txt", "new\n");
  await rename(
    join(f.projectPath, "deleted.txt"),
    join(f.projectPath, "renamed.txt"),
  );
  const result = await f.measure();
  assert.equal(result.additions, 4);
  assert.equal(result.deletions, 6);
  assert.equal(result.changedLines, 10);
  await f.git("add", "-A");
  assert.deepEqual(await f.measure(), result);
});

test("counts repeated and reordered lines with byte-exact line endings", async (t) => {
  const f = await fixture(t);
  await f.write("changed.txt", "third\nsecond\nthird\nfirst\n");
  const reordered = await f.measure();
  assert.equal(reordered.additions, 2);
  assert.equal(reordered.deletions, 1);
  await f.write("changed.txt", "first\r\nsecond\nthird\n");
  const endings = await f.measure();
  assert.equal(endings.additions, 1);
  assert.equal(endings.deletions, 1);
});

test("reports embedded repository changes without inventing text lines", async (t) => {
  const f = await fixture(t);
  const nestedPath = join(f.projectPath, "nested");
  await mkdir(nestedPath);
  await f.git("-C", nestedPath, "init", "-q", "-b", "main");
  await f.write("nested/child.txt", "child\n");
  await f.git("-C", nestedPath, "add", ".");
  await f.git(
    "-C",
    nestedPath,
    "-c",
    "user.name=Fixture User",
    "-c",
    "user.email=fixture@example.com",
    "commit",
    "-qm",
    "nested fixture",
  );
  const result = await f.measure();
  assert.equal(result.changedLines, 0);
  assert.deepEqual(result.binaryPaths, []);
  assert.deepEqual(result.gitlinkPaths, ["nested"]);
  await f.git("add", "nested");
  assert.deepEqual(await f.measure(), result);
});

test("returns deterministic threshold inputs, including an unborn baseline", async (t) => {
  const f = await fixture(t, { unborn: true });
  assert.equal((await f.measure()).changedLines, 0);
  await f.write("new.txt", "line\n".repeat(2700));
  const first = await f.measure();
  assert.equal(first.changedLines, 2700);
  assert.equal(first.deletions, 0);
  await f.git("add", "new.txt");
  assert.deepEqual(await f.measure(), first);
  await f.write("new.txt", "line\n".repeat(2701));
  assert.equal((await f.measure()).changedLines, 2701);
});

test("never follows replaced directory aliases or scans ordinary unchanged files", async (t) => {
  const f = await fixture(t);
  const outside = join(f.root, "outside");
  await mkdir(outside);
  await writeFile(join(outside, "child.txt"), "outside\n".repeat(100));
  await rm(join(f.projectPath, "directory"), { recursive: true });
  await symlink(outside, join(f.projectPath, "directory"));
  const nativeOpen = filesystem.open;
  const mockedOpen = t.mock.method(
    filesystem,
    "open",
    async (path, ...args) => {
      assert.notEqual(String(path), join(f.projectPath, "mode.txt"));
      assert.notEqual(String(path), join(f.projectPath, "directory/child.txt"));
      return nativeOpen(path, ...args);
    },
  );
  syncBuiltinESMExports();
  try {
    const result = await f.measure();
    assert.equal(result.additions, 1);
    assert.equal(result.deletions, 1);
  } finally {
    mockedOpen.mock.restore();
    syncBuiltinESMExports();
  }
});

test("rejects stale fingerprints and content races rather than returning stale counts", async (t) => {
  const f = await fixture(t);
  await f.write("changed.txt", "new\n");
  const options = {
    projectPath: f.projectPath,
    baseHead: f.baseHead,
    expectedContentFingerprint: await f.service.contentFingerprint({
      projectPath: f.projectPath,
    }),
  };
  await f.write("changed.txt", "later\n");
  await assert.rejects(f.service.measureChanges(options), {
    code: "ERR_GIT_MEASUREMENT_CHANGED",
  });
  const nativeOpen = filesystem.open;
  // Exercise both the guarded byte read and the final candidate reinspection.
  for (const changeOnRead of [2, 3]) {
    await f.write("changed.txt", "later\n");
    options.expectedContentFingerprint = await f.service.contentFingerprint({
      projectPath: f.projectPath,
    });
    let reads = 0;
    const mockedOpen = t.mock.method(
      filesystem,
      "open",
      async (path, ...args) => {
        if (
          String(path) === join(f.projectPath, "changed.txt") &&
          ++reads === changeOnRead
        ) {
          await f.write("changed.txt", "raced\n");
        }
        return nativeOpen(path, ...args);
      },
    );
    syncBuiltinESMExports();
    try {
      await assert.rejects(f.service.measureChanges(options), {
        code: "ERR_GIT_MEASUREMENT_CHANGED",
      });
      assert.equal(reads, changeOnRead);
    } finally {
      mockedOpen.mock.restore();
      syncBuiltinESMExports();
    }
  }
  await assert.rejects(
    f.service.measureChanges({ ...options, baseHead: "HEAD" }),
    { code: "ERR_INVALID_GIT_OPTIONS" },
  );
});
