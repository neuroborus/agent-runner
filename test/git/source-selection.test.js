import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import filesystem, {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { createGitService } from "../../src/git/index.js";
import {
  createWorkspaceService,
  WorkspaceSafetyError,
} from "../../src/workspace/index.js";

const executeFile = promisify(execFile);

function observeDescendantReads(path, beforeRead = async () => {}) {
  const reads = [];
  const fileSystem = Object.fromEntries(
    Object.entries(filesystem).map(([method, native]) => [
      method,
      ["lstat", "open", "readdir", "readlink", "realpath"].includes(method)
        ? async (candidate, ...args) => {
            let actual = String(candidate);
            const descriptor = /^\/proc\/self\/fd\/\d+/u.exec(actual)?.[0];
            if (descriptor)
              actual =
                (await filesystem.realpath(descriptor)) +
                actual.slice(descriptor.length);
            await beforeRead(method, actual, String(candidate));
            if (actual.startsWith(`${path}/`)) reads.push([method, actual]);
            return native(candidate, ...args);
          }
        : native,
    ]),
  );
  return { reads, fileSystem };
}

async function fixture(t, { unborn = false } = {}) {
  const root = await mkdtemp(join(tmpdir(), "agent-runner-selection-"));
  t.after(() => rm(root, { recursive: true, force: true }));
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
  const write = async (path, content = "initial\n") => {
    await mkdir(dirname(join(projectPath, path)), { recursive: true });
    await writeFile(join(projectPath, path), content);
  };
  await git("init", "-q", "-b", "main");
  await git("config", "user.name", "Fixture User");
  await git("config", "user.email", "fixture@example.com");
  if (!unborn) {
    await write(".gitignore", "opaque/\ndependencies/\nignored.txt\n");
    for (const path of [
      "unchanged.txt",
      "dirty.txt",
      "deleted.txt",
      "hidden.txt",
      "sparse.txt",
      "staged-deletion.txt",
    ])
      await write(path);
    await write("dependencies/tracked.txt");
    await git("add", ".");
    await git("add", "-f", "dependencies/tracked.txt");
    await git("commit", "-qm", "fixture");
  }
  const service = createGitService({ env });
  const select = (expectedSelectionFingerprint) =>
    service.selectSources({ projectPath, expectedSelectionFingerprint });
  const workspace = createWorkspaceService();
  const capture = async (selection) => {
    const inspection = await workspace.inspect({
      workspacePath: projectPath,
      stateRoot: join(root, "state"),
      ...selection.inspection,
    });
    return workspace.snapshot({ inspection });
  };
  return { root, projectPath, git, write, service, select, workspace, capture };
}

test("selects complete working-tree sources and missing tracked paths without Git effects", async (t) => {
  const f = await fixture(t);
  await f.write("dirty.txt", "worktree\n");
  await f.git("add", "dirty.txt");
  await f.write("dirty.txt", "final worktree\n");
  await rm(join(f.projectPath, "deleted.txt"));
  await f.git("rm", "-q", "staged-deletion.txt");
  await f.git("update-index", "--assume-unchanged", "hidden.txt");
  await f.git("update-index", "--skip-worktree", "sparse.txt");
  await f.write("hidden.txt", "hidden worktree\n");
  await f.write("sparse.txt", "sparse worktree\n");
  await f.write("dependencies/tracked.txt", "ignored tracked worktree\n");
  await f.write("new\tfile.txt", "untracked\n");
  await f.write("ignored.txt");
  await f.git(
    "config",
    "remote.origin.url",
    "https://example.invalid/repository.git",
  );
  const before = await f.service.snapshot({ projectPath: f.projectPath });
  const index = await readFile(join(f.projectPath, ".git/index"));
  const selection = await f.select();
  assert.deepEqual(selection.trackedPaths, [
    ".gitignore",
    "deleted.txt",
    "dependencies/tracked.txt",
    "dirty.txt",
    "hidden.txt",
    "sparse.txt",
    "staged-deletion.txt",
    "unchanged.txt",
  ]);
  assert.deepEqual(selection.untrackedPaths, ["new\tfile.txt"]);
  assert.deepEqual(selection.deletedPaths, [
    "deleted.txt",
    "staged-deletion.txt",
  ]);
  assert.equal(selection.head, before.head);
  assert.equal(selection.indexFingerprint, before.indexFingerprint);
  for (const value of Object.values(selection).filter(Array.isArray))
    assert.ok(Object.isFrozen(value));
  assert.ok(Object.isFrozen(selection));
  assert.ok(Object.isFrozen(selection.inspection));
  assert.ok(Object.isFrozen(selection.inspection.inspectionPaths));
  const snapshot = await f.capture(JSON.parse(JSON.stringify(selection)));
  assert.equal(snapshot.inspectionFilesOnly, true);
  assert.throws(
    () =>
      f.workspace.assertUnchanged({
        before: snapshot,
        after: { ...snapshot, inspectionFilesOnly: undefined },
      }),
    { code: "ERR_WORKSPACE_DRIFT" },
  );
  const source = (name) =>
    snapshot.entries.find(({ path }) => path === join(f.projectPath, name));
  assert.equal(source("unchanged.txt").kind, "file");
  assert.equal(source("deleted.txt").kind, "missing");
  assert.equal(source("staged-deletion.txt").kind, "missing");
  const hash = (value) => createHash("sha256").update(value).digest("hex");
  assert.equal(source("dirty.txt").hash, hash("final worktree\n"));
  assert.equal(source("hidden.txt").hash, hash("hidden worktree\n"));
  assert.equal(source("sparse.txt").hash, hash("sparse worktree\n"));
  assert.equal(
    source("dependencies/tracked.txt").hash,
    hash("ignored tracked worktree\n"),
  );
  assert.equal(source("ignored.txt"), undefined);
  assert.deepEqual(await f.select(selection.selectionFingerprint), selection);
  await f.service.assertUnchanged(before);
  assert.deepEqual(await readFile(join(f.projectPath, ".git/index")), index);
});

test("ignored untracked trees stay outside selection and confined capture", async (t) => {
  const f = await fixture(t);
  await f.write("opaque/child.txt");
  await f.write("dependencies/cache/child.txt");
  await symlink("/unavailable-control", join(f.projectPath, "opaque/.git"));
  const opaque = [
    join(f.projectPath, "opaque"),
    join(f.projectPath, "dependencies/cache"),
  ];
  const native = { ...filesystem };
  const mocks = ["lstat", "open", "readdir", "readlink", "realpath"].map(
    (name) =>
      t.mock.method(filesystem, name, async (path, ...args) => {
        let actual = String(path);
        const descriptor = /^\/proc\/self\/fd\/\d+/u.exec(actual)?.[0];
        if (descriptor)
          actual =
            (await native.realpath(descriptor)) +
            actual.slice(descriptor.length);
        assert.ok(
          !opaque.some(
            (tree) => actual === tree || actual.startsWith(`${tree}/`),
          ),
          `Unexpected ${name} in an ignored tree`,
        );
        return native[name](path, ...args);
      }),
  );
  syncBuiltinESMExports();
  try {
    const selection = await f.select();
    assert.deepEqual(selection.untrackedPaths, []);
    const snapshot = await f.capture(selection);
    assert.ok(
      snapshot.entries.some(
        ({ path }) => path === join(f.projectPath, "dependencies/tracked.txt"),
      ),
    );
    assert.ok(
      snapshot.entries.every(
        ({ path }) =>
          !opaque.some((tree) => path === tree || path.startsWith(`${tree}/`)),
      ),
    );
  } finally {
    for (const mock of mocks) mock.mock.restore();
    syncBuiltinESMExports();
  }
});

test("selected files and missing tracked leaves cannot become recursive roots at workspace handoff", async (t) => {
  const f = await fixture(t);
  await f.write(".gitignore", "**/ignored/\n");
  await rm(join(f.projectPath, "deleted.txt"));
  for (const name of ["unchanged.txt", "deleted.txt"]) {
    const selection = await f.select();
    const path = join(f.projectPath, name);
    await rm(path, { force: true });
    await f.write(`${name}/ignored/child.txt`);
    const { reads, fileSystem } = observeDescendantReads(path);
    const service = createWorkspaceService({ fileSystem });
    const error = await service
      .inspect({
        workspacePath: f.projectPath,
        stateRoot: join(f.root, "state"),
        ...selection.inspection,
      })
      .then(
        () => null,
        (cause) => cause,
      );
    assert.deepEqual(reads, []);
    assert.ok(error instanceof WorkspaceSafetyError);
    await rm(path, { recursive: true });
    if (name === "unchanged.txt") await f.write(name);
  }
});

test("file-only constraints survive reconstruction and late discovery/capture replacements", async (t) => {
  const f = await fixture(t);
  await f.write(".gitignore", "**/ignored/\n");
  await rm(join(f.projectPath, "deleted.txt"));
  const selection = JSON.parse(JSON.stringify(await f.select()));
  const declarations = {
    workspacePath: f.projectPath,
    stateRoot: join(f.root, "state"),
    ...selection.inspection,
  };
  for (const phase of ["discovery", "snapshot", "capture"]) {
    const name = phase === "capture" ? "unchanged.txt" : "deleted.txt";
    const path = join(f.projectPath, name);
    let replaced = false;
    let armed = phase === "discovery";
    let inspections = 0;
    async function replace() {
      await rm(path, { force: true });
      await f.write(`${name}/ignored/child.txt`);
      replaced = true;
    }
    const { reads, fileSystem } = observeDescendantReads(
      path,
      async (method, actual, candidate) => {
        if (!armed || replaced || method !== "lstat" || actual !== path) return;
        // The second ordinary observation is control discovery after initial
        // declaration binding; a descriptor-relative observation is capture.
        if (
          (phase === "discovery" && ++inspections === 2) ||
          (phase === "capture" && candidate.startsWith("/proc/self/fd/"))
        )
          await replace();
      },
    );
    const service = createWorkspaceService({ fileSystem });
    let error;
    if (phase === "discovery") {
      error = await service.inspect(declarations).then(
        () => null,
        (cause) => cause,
      );
    } else {
      const inspection = JSON.parse(
        JSON.stringify(await service.inspect(declarations)),
      );
      assert.equal(inspection.inspectionFilesOnly, true);
      if (phase === "snapshot") await replace();
      else armed = true;
      error = await service.snapshot({ inspection }).then(
        () => null,
        (cause) => cause,
      );
    }
    assert.ok(replaced, `Replacement must occur during ${phase}`);
    assert.deepEqual(reads, []);
    assert.ok(error instanceof WorkspaceSafetyError);
    await rm(path, { recursive: true });
    if (name === "unchanged.txt") await f.write(name);
  }
});

test("absolute links validate selected missing roots before accessing replacement descendants", async (t) => {
  const f = await fixture(t);
  await f.write(".gitignore", "**/ignored/\n");
  await f.write("z-source");
  await f.git("add", "z-source");
  const path = join(f.projectPath, "z-source");
  await rm(path);
  const link = join(f.projectPath, "a-link");
  await symlink(join(path, "ignored/child.txt"), link);
  const selection = await f.select();
  assert.ok(selection.deletedPaths.includes("z-source"));
  let armed = false;
  let replaced = false;
  let rootReads = 0;
  const { reads, fileSystem } = observeDescendantReads(
    path,
    async (method, actual) => {
      if (armed && !replaced && method === "readlink" && actual === link) {
        await f.write("z-source/ignored/child.txt");
        replaced = true;
      }
      if (replaced && method === "lstat" && actual === path) rootReads++;
    },
  );
  const service = createWorkspaceService({ fileSystem });
  const inspection = await service.inspect({
    workspacePath: f.projectPath,
    stateRoot: join(f.root, "state"),
    ...selection.inspection,
  });
  armed = true;
  const error = await service.snapshot({ inspection }).then(
    () => null,
    (cause) => cause,
  );
  assert.ok(replaced);
  assert.deepEqual(reads, []);
  assert.ok(rootReads > 0);
  assert.ok(error instanceof WorkspaceSafetyError);
});

test("selection fingerprints bind membership, deletions and index/HEAD provenance rather than file bytes", async (t) => {
  const f = await fixture(t);
  const first = await f.select();
  const before = await f.capture(first);
  await f.write("unchanged.txt", "new bytes\n");
  assert.deepEqual(await f.select(first.selectionFingerprint), first);
  const after = await f.capture(first);
  assert.throws(() => f.workspace.assertUnchanged({ before, after }), {
    code: "ERR_WORKSPACE_DRIFT",
  });
  await f.write("new.txt");
  await assert.rejects(f.select(first.selectionFingerprint), {
    code: "ERR_GIT_SOURCE_SELECTION_CHANGED",
  });
  const added = await f.select();
  await rm(join(f.projectPath, "deleted.txt"));
  await assert.rejects(f.select(added.selectionFingerprint), {
    code: "ERR_GIT_SOURCE_SELECTION_CHANGED",
  });
  const deleted = await f.select();
  await f.git("update-index", "--assume-unchanged", "hidden.txt");
  await assert.rejects(f.select(deleted.selectionFingerprint), {
    code: "ERR_GIT_SOURCE_SELECTION_CHANGED",
  });
  const hidden = await f.select();
  await f.git("commit", "--allow-empty", "-qm", "next fixture");
  await assert.rejects(f.select(hidden.selectionFingerprint), {
    code: "ERR_GIT_SOURCE_SELECTION_CHANGED",
  });
  await assert.rejects(f.select("HEAD"), { code: "ERR_INVALID_GIT_OPTIONS" });
  await assert.rejects(
    f.service.selectSources({
      projectPath: f.projectPath,
      excludePaths: ["dirty.txt"],
    }),
    { code: "ERR_INVALID_GIT_OPTIONS" },
  );
});

test("leaf links retain workspace confinement and routing aliases never become recursive roots", async (t) => {
  const f = await fixture(t);
  const link = join(f.projectPath, "link.txt");
  const target = join(f.projectPath, "unchanged.txt");
  for (const value of ["unchanged.txt", target]) {
    await symlink(value, link);
    const snapshot = await f.capture(await f.select());
    assert.equal(
      snapshot.entries.find(({ path }) => path === link).kind,
      "symlink",
    );
    assert.ok(
      snapshot.linkResolutions
        .find(({ path }) => path === link)
        .paths.includes(target),
    );
    await rm(link);
  }
  const outside = join(f.root, "outside");
  await mkdir(outside);
  await writeFile(join(outside, "child.txt"), "outside\n");
  await symlink(outside, join(f.projectPath, "outside-link"));
  const selection = await f.select();
  assert.ok(selection.untrackedPaths.includes("outside-link"));
  await assert.rejects(f.capture(selection), { code: "ERR_WORKSPACE_PATH" });
  await rm(join(f.projectPath, "outside-link"));
  await rm(join(f.projectPath, "dependencies"), { recursive: true });
  await symlink(outside, join(f.projectPath, "dependencies"));
  await assert.rejects(f.select(), { code: "ERR_UNSUPPORTED_GIT_PATH" });
});

test("rejects gitlinks, embedded repositories and directory replacements without recursive capture", async (t) => {
  const f = await fixture(t);
  await rm(join(f.projectPath, "dirty.txt"));
  await f.write("dirty.txt/ignored-child.txt");
  await assert.rejects(f.select(), { code: "ERR_UNSUPPORTED_GIT_PATH" });
  await rm(join(f.projectPath, "dirty.txt"), { recursive: true });
  const { head } = await f.select();
  await f.git("update-index", "--add", "--cacheinfo", `160000,${head},module`);
  await assert.rejects(f.select(), { code: "ERR_UNSUPPORTED_GIT_PATH" });
  await f.git("update-index", "--force-remove", "module");
  await mkdir(join(f.projectPath, "nested"));
  await f.git("-C", join(f.projectPath, "nested"), "init", "-q", "-b", "main");
  await f.write("nested/child.txt");
  await assert.rejects(f.select(), { code: "ERR_UNSUPPORTED_GIT_PATH" });
});

test("supports unborn worktrees and rejects membership publication races", async (t) => {
  const f = await fixture(t, { unborn: true });
  const empty = await f.select();
  assert.equal(empty.head, null);
  assert.deepEqual(empty.inspection.inspectionPaths, []);
  const ordinary = join(f.root, "ordinary");
  await mkdir(ordinary);
  await assert.rejects(f.service.selectSources({ projectPath: ordinary }), {
    code: "ERR_NOT_GIT_REPOSITORY",
  });
  assert.deepEqual(await filesystem.readdir(ordinary), []);
  await f.write("\ufefffirst.txt");
  assert.deepEqual((await f.select()).untrackedPaths, ["\ufefffirst.txt"]);
  await f.git("add", "\ufefffirst.txt");
  await f.write("first.txt");
  await f.git("add", "first.txt");
  assert.deepEqual((await f.select()).trackedPaths, [
    "first.txt",
    "\ufefffirst.txt",
  ]);
  const native = filesystem.lstat;
  let published = false;
  const mock = t.mock.method(filesystem, "lstat", async (path, ...args) => {
    if (path === join(f.projectPath, "first.txt") && !published) {
      published = true;
      await f.write("arriving.txt");
    }
    return native(path, ...args);
  });
  syncBuiltinESMExports();
  try {
    await assert.rejects(f.select(), {
      code: "ERR_GIT_SOURCE_SELECTION_CHANGED",
    });
    assert.ok(published);
  } finally {
    mock.mock.restore();
    syncBuiltinESMExports();
  }
});
