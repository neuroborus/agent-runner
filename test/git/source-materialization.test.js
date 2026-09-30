import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import filesystem, {
  access,
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  readlink,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { createGitService } from "../../src/git/index.js";

const executeFile = promisify(execFile);

async function directoryIdentity(path) {
  const metadata = await lstat(path, { bigint: true });
  return {
    device: String(metadata.dev),
    inode: String(metadata.ino),
  };
}

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), "agent-runner-source-"));
  t.after(() => rm(root, { force: true, recursive: true }));
  const projectPath = join(root, "project");
  const configPath = join(root, "config");
  const destinationPath = join(root, "projection");
  await mkdir(projectPath);
  await mkdir(configPath);
  await mkdir(destinationPath, { mode: 0o700 });
  const env = {
    ...process.env,
    GIT_CONFIG_GLOBAL: join(configPath, "global.gitconfig"),
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_OPTIONAL_LOCKS: "0",
    GIT_TERMINAL_PROMPT: "0",
    HOME: root,
    LC_ALL: "C",
    XDG_CONFIG_HOME: configPath,
  };
  for (const name of [
    "EMAIL",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_AUTHOR_EMAIL",
    "GIT_AUTHOR_NAME",
    "GIT_CEILING_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_COMMITTER_EMAIL",
    "GIT_COMMITTER_NAME",
    "GIT_CONFIG",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_PARAMETERS",
    "GIT_DIR",
    "GIT_INDEX_FILE",
    "GIT_NAMESPACE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_SHALLOW_FILE",
    "GIT_WORK_TREE",
  ]) {
    delete env[name];
  }
  const runGit = (...argumentsList) =>
    executeFile("git", argumentsList, { env });
  await runGit("init", "-q", "-b", "main", projectPath);
  await runGit("-C", projectPath, "config", "user.name", "Test");
  await runGit("-C", projectPath, "config", "user.email", "test@example.com");
  await writeFile(join(projectPath, ".gitignore"), "ignored.txt\n");
  await writeFile(join(projectPath, "changed.txt"), "head\n");
  await writeFile(join(projectPath, "deleted.txt"), "delete\n");
  await writeFile(join(projectPath, "script.sh"), "#!/bin/sh\nexit 0\n");
  await chmod(join(projectPath, "script.sh"), 0o755);
  await symlink("changed.txt", join(projectPath, "link.txt"));
  await runGit("-C", projectPath, "add", ".");
  await runGit("-C", projectPath, "commit", "-qm", "fixture");
  return {
    destinationPath,
    projectPath,
    runGit,
    service: createGitService({ env }),
  };
}

test("waits for in-flight source writes before reporting materialization failure", async (t) => {
  const f = await fixture(t);
  const snapshot = await f.service.snapshot({ projectPath: f.projectPath });
  const pending = Promise.withResolvers();
  const pendingStarted = Promise.withResolvers();
  const failed = Promise.withResolvers();
  const nativeOpen = filesystem.open;
  const mockedOpen = t.mock.method(
    filesystem,
    "open",
    async (path, ...argumentsList) => {
      if (basename(String(path)) === "changed.txt") {
        pendingStarted.resolve();
        await pending.promise;
      }
      if (basename(String(path)) === "deleted.txt") {
        await pendingStarted.promise;
        failed.resolve();
        throw Object.assign(new Error("Materialization write failed"), {
          code: "EIO",
        });
      }
      return nativeOpen(path, ...argumentsList);
    },
  );
  syncBuiltinESMExports();
  const attempt = f.service.materializeSource({
    baseHead: snapshot.head,
    destinationIdentity: await directoryIdentity(f.destinationPath),
    destinationPath: f.destinationPath,
    expectedContentFingerprint: snapshot.contentFingerprint,
    projectPath: f.projectPath,
  });
  let settled = false;
  const observed = assert
    .rejects(attempt, { code: "ERR_GIT_SOURCE_MATERIALIZATION" })
    .finally(() => {
      settled = true;
    });

  try {
    await failed.promise;
    await Promise.resolve();
    assert.equal(settled, false);
  } finally {
    pending.resolve();
    try {
      await observed;
    } finally {
      mockedOpen.mock.restore();
      syncBuiltinESMExports();
    }
  }
});

test("materializes exact source without ignored untracked or Git data", async (t) => {
  const f = await fixture(t);
  await writeFile(join(f.projectPath, "changed.txt"), "staged\n");
  await f.runGit("-C", f.projectPath, "add", "changed.txt");
  await writeFile(join(f.projectPath, "changed.txt"), "workspace\n");
  await rm(join(f.projectPath, "deleted.txt"));
  await writeFile(join(f.projectPath, "untracked.txt"), "untracked\n");
  await writeFile(join(f.projectPath, "ignored.txt"), "private\n");
  const snapshot = await f.service.snapshot({ projectPath: f.projectPath });

  const result = await f.service.materializeSource({
    baseHead: snapshot.head,
    destinationIdentity: await directoryIdentity(f.destinationPath),
    destinationPath: f.destinationPath,
    expectedContentFingerprint: snapshot.contentFingerprint,
    projectPath: f.projectPath,
  });

  assert.equal(result.contentFingerprint, snapshot.contentFingerprint);
  assert.equal(
    await readFile(join(f.destinationPath, "changed.txt"), "utf8"),
    "workspace\n",
  );
  assert.equal(
    await readFile(join(f.destinationPath, "untracked.txt"), "utf8"),
    "untracked\n",
  );
  assert.equal(
    await readlink(join(f.destinationPath, "link.txt")),
    "changed.txt",
  );
  assert.notEqual(
    (await lstat(join(f.destinationPath, "script.sh"))).mode & 0o111,
    0,
  );
  for (const path of ["deleted.txt", "ignored.txt", ".git"]) {
    await assert.rejects(access(join(f.destinationPath, path)), {
      code: "ENOENT",
    });
  }
  assert.deepEqual((await readdir(f.destinationPath)).sort(), [
    ".gitignore",
    "changed.txt",
    "link.txt",
    "script.sh",
    "untracked.txt",
  ]);
});

test("rejects stale source bindings before populating a projection", async (t) => {
  const f = await fixture(t);
  const snapshot = await f.service.snapshot({ projectPath: f.projectPath });
  await writeFile(join(f.projectPath, "changed.txt"), "later\n");
  await assert.rejects(
    f.service.materializeSource({
      baseHead: snapshot.head,
      destinationIdentity: await directoryIdentity(f.destinationPath),
      destinationPath: f.destinationPath,
      expectedContentFingerprint: snapshot.contentFingerprint,
      projectPath: f.projectPath,
    }),
    { code: "ERR_GIT_SOURCE_CHANGED" },
  );
  assert.deepEqual(await readdir(f.destinationPath), []);
});

test("rejects source fingerprints interpreted through replacement objects", async (t) => {
  const f = await fixture(t);
  const originalHead = (
    await f.runGit("-C", f.projectPath, "rev-parse", "HEAD")
  ).stdout.trim();
  await writeFile(join(f.projectPath, "changed.txt"), "replacement\n");
  await f.runGit("-C", f.projectPath, "commit", "-qam", "replacement");
  const replacementHead = (
    await f.runGit("-C", f.projectPath, "rev-parse", "HEAD")
  ).stdout.trim();
  await f.runGit("-C", f.projectPath, "reset", "-q", "--hard", originalHead);
  await f.runGit("-C", f.projectPath, "replace", originalHead, replacementHead);
  await writeFile(join(f.projectPath, "changed.txt"), "replacement\n");
  const snapshot = await f.service.snapshot({ projectPath: f.projectPath });

  await assert.rejects(
    f.service.materializeSource({
      baseHead: snapshot.head,
      destinationIdentity: await directoryIdentity(f.destinationPath),
      destinationPath: f.destinationPath,
      expectedContentFingerprint: snapshot.contentFingerprint,
      projectPath: f.projectPath,
    }),
    { code: "ERR_GIT_SOURCE_CHANGED" },
  );
  assert.deepEqual(await readdir(f.destinationPath), []);
});

test("rejects a projection root changed during completeness inspection", async (t) => {
  const f = await fixture(t);
  const snapshot = await f.service.snapshot({ projectPath: f.projectPath });
  const nativeReaddir = filesystem.readdir;
  let injected = false;
  const mockedReaddir = t.mock.method(
    filesystem,
    "readdir",
    async (path, ...argumentsList) => {
      const entries = await nativeReaddir(path, ...argumentsList);
      if (
        !injected &&
        String(path).startsWith("/proc/self/fd/") &&
        entries.length > 0
      ) {
        injected = true;
        await writeFile(join(f.destinationPath, "late.txt"), "late\n");
      }
      return entries;
    },
  );
  syncBuiltinESMExports();

  try {
    await assert.rejects(
      f.service.materializeSource({
        baseHead: snapshot.head,
        destinationIdentity: await directoryIdentity(f.destinationPath),
        destinationPath: f.destinationPath,
        expectedContentFingerprint: snapshot.contentFingerprint,
        projectPath: f.projectPath,
      }),
      { code: "ERR_GIT_SOURCE_MATERIALIZATION" },
    );
  } finally {
    mockedReaddir.mock.restore();
    syncBuiltinESMExports();
  }
  assert.equal(injected, true);
});

test("rejects a source destination inside the protected repository", async (t) => {
  const f = await fixture(t);
  const snapshot = await f.service.snapshot({ projectPath: f.projectPath });
  const unsafeDestination = join(f.projectPath, "projection");
  await mkdir(unsafeDestination, { mode: 0o700 });

  await assert.rejects(
    f.service.materializeSource({
      baseHead: snapshot.head,
      destinationIdentity: await directoryIdentity(unsafeDestination),
      destinationPath: unsafeDestination,
      expectedContentFingerprint: snapshot.contentFingerprint,
      projectPath: f.projectPath,
    }),
    { code: "ERR_UNSAFE_REPOSITORY_PATH" },
  );
  assert.deepEqual(await readdir(unsafeDestination), []);
});

test("rejects repository content that overlaps a protected control path", async (t) => {
  const f = await fixture(t);
  const snapshot = await f.service.snapshot({ projectPath: f.projectPath });

  await assert.rejects(
    f.service.materializeSource({
      baseHead: snapshot.head,
      destinationIdentity: await directoryIdentity(f.destinationPath),
      destinationPath: f.destinationPath,
      expectedContentFingerprint: snapshot.contentFingerprint,
      projectPath: f.projectPath,
      protectedPaths: [join(f.projectPath, "changed.txt")],
    }),
    { code: "ERR_GIT_SOURCE_MATERIALIZATION" },
  );
  assert.deepEqual(await readdir(f.destinationPath), []);
});

test("rejects a replaced destination before materialization effects", async (t) => {
  const f = await fixture(t);
  const snapshot = await f.service.snapshot({ projectPath: f.projectPath });
  const destinationIdentity = await directoryIdentity(f.destinationPath);
  const originalDestination = `${f.destinationPath}-original`;
  await rename(f.destinationPath, originalDestination);
  await mkdir(f.destinationPath, { mode: 0o700 });

  await assert.rejects(
    f.service.materializeSource({
      baseHead: snapshot.head,
      destinationIdentity,
      destinationPath: f.destinationPath,
      expectedContentFingerprint: snapshot.contentFingerprint,
      projectPath: f.projectPath,
    }),
    { code: "ERR_GIT_SOURCE_DESTINATION_CHANGED" },
  );
  assert.deepEqual(await readdir(f.destinationPath), []);
  assert.deepEqual(await readdir(originalDestination), []);
});
