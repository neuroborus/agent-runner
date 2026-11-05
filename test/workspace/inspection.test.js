import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { constants } from "node:fs";
import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import {
  createWorkspaceService,
  WorkspaceSafetyError,
} from "../../src/workspace/index.js";

async function fixture(t) {
  const root = await fs.mkdtemp(join(tmpdir(), "agent-runner-workspace-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const workspacePath = join(root, "project");
  await fs.mkdir(workspacePath);
  return { root, workspacePath, stateRoot: join(root, "state") };
}

const executeFile = promisify(execFile);
const unsafe = (code) => (error) =>
  error instanceof WorkspaceSafetyError &&
  (code === undefined || error.code === code);

// Include descriptor-anchored reads in the non-visitation assertion.
function withoutReadsOf(paths) {
  return Object.fromEntries(
    Object.entries(fs).map(([name, method]) => [
      name,
      ["lstat", "open", "readdir", "readlink", "realpath"].includes(name)
        ? async (candidate, ...args) => {
            const match = /^(\/proc\/self\/fd\/\d+)(.*)$/u.exec(candidate);
            const path = match
              ? `${await fs.realpath(match[1])}${match[2]}`
              : candidate;
            assert.ok(
              !paths.some(
                (excluded) =>
                  path === excluded || path.startsWith(`${excluded}/`),
              ),
              `Unexpected ${name} of an opaque tree`,
            );
            return method(candidate, ...args);
          }
        : method,
    ]),
  );
}

test("scoped snapshots prune excluded and unselected trees before discovery or reads", async (t) => {
  const f = await fixture(t);
  const source = join(f.workspacePath, "src");
  const cache = join(source, "cache");
  const unselected = join(f.workspacePath, "unselected");
  await fs.mkdir(cache, { recursive: true });
  await fs.mkdir(unselected);
  // Neither an unsafe nested control nor an escaping link may be visited.
  await fs.symlink(f.root, join(cache, ".git"));
  await fs.symlink(f.root, join(unselected, "outside"));
  await fs.writeFile(join(source, "input.txt"), "source\n");
  await fs.mkdir(join(source, ".agents"));
  await fs.writeFile(join(source, ".agents", "guide.md"), "protected\n");
  const service = createWorkspaceService({
    fileSystem: withoutReadsOf([cache, unselected]),
  });
  const declarations = {
    workspacePath: f.workspacePath,
    stateRoot: f.stateRoot,
    inspectionPaths: ["src", "./src/input.txt"],
    excludePaths: ["src/cache", "src/cache/nested"],
  };
  const inspection = await service.inspect(declarations);
  declarations.inspectionPaths.push("unselected");
  declarations.excludePaths.length = 0;
  assert.deepEqual(inspection.inspectionPaths, [source]);
  assert.deepEqual(inspection.excludePaths, ["src/cache"]);
  assert.deepEqual(inspection.readPaths, [source]);
  assert.ok(Object.isFrozen(inspection.inspectionPaths));
  assert.ok(inspection.controlPaths.includes(join(source, ".agents")));
  const before = await service.snapshot({ inspection });
  assert.ok(
    !before.entries.some(
      ({ path }) => path.startsWith(cache) || path.startsWith(unselected),
    ),
  );
  await fs.writeFile(join(cache, "new.txt"), "opaque\n");
  await fs.writeFile(join(unselected, "new.txt"), "unselected\n");
  const reconstructed = JSON.parse(JSON.stringify(inspection));
  service.assertUnchanged({
    before,
    after: await service.snapshot({ inspection: reconstructed }),
  });
  await fs.writeFile(join(source, "input.txt"), "changed\n");
  const changed = await service.snapshot({ inspection });
  assert.throws(
    () => service.assertUnchanged({ before, after: changed }),
    unsafe("ERR_WORKSPACE_DRIFT"),
  );
  await fs.writeFile(join(source, ".agents", "guide.md"), "changed control\n");
  assert.notEqual(
    changed.contentFingerprint,
    (await service.snapshot({ inspection })).contentFingerprint,
  );
});

test("scope admission rejects escapes, hidden protected declarations and aliased routing ancestors", async (t) => {
  const f = await fixture(t);
  await fs.mkdir(join(f.workspacePath, "data"));
  await fs.mkdir(join(f.workspacePath, "cache"));
  await fs.symlink("cache", join(f.workspacePath, "alias"));
  const service = createWorkspaceService();
  const base = { workspacePath: f.workspacePath, stateRoot: f.stateRoot };
  for (const scope of [
    { inspectionPaths: null },
    { excludePaths: null },
    { inspectionPaths: ["../outside"] },
    { inspectionPaths: ["alias/../data"] },
    { inspectionPaths: ["alias/child"] },
    { inspectionPaths: [".", "alias/child"] },
    { excludePaths: ["."] },
    { excludePaths: ["../outside"] },
    { excludePaths: [join(f.workspacePath, "cache")] },
    { excludePaths: ["alias/child"] },
    { excludePaths: ["data/.agents"] },
    { inspectionPaths: ["data"], excludePaths: ["data"] },
    { inspectionPaths: ["data/input.md"], excludePaths: ["data"] },
    { inspectionPaths: [".", "data/input.md"], excludePaths: ["data"] },
    { sourcePaths: ["data"], excludePaths: ["data/cache"] },
    ...[
      "inputPaths",
      "sourcePaths",
      "configurationPaths",
      "artifactPaths",
      "infrastructurePaths",
      "outputPaths",
    ].map((name) => ({ [name]: ["data/required.md"], excludePaths: ["data"] })),
    { taskPath: "data", excludePaths: ["data/cache"] },
  ])
    await assert.rejects(service.inspect({ ...base, ...scope }), unsafe());
  // A Git pointer makes its metadata protected even outside the selected tree.
  await fs.writeFile(join(f.workspacePath, ".git"), "gitdir: cache\n");
  let excludedMetadataRead = false;
  const pointed = createWorkspaceService({
    fileSystem: {
      ...fs,
      async lstat(path, ...args) {
        if (
          path === join(f.workspacePath, "cache") ||
          path.startsWith(`${join(f.workspacePath, "cache")}/`)
        )
          excludedMetadataRead = true;
        return fs.lstat(path, ...args);
      },
    },
  });
  await assert.rejects(
    pointed.inspect({
      ...base,
      inspectionPaths: ["data"],
      excludePaths: ["cache"],
    }),
    unsafe(),
  );
  assert.equal(excludedMetadataRead, false);
  await fs.rm(join(f.workspacePath, ".git"));
  await fs.mkdir(join(f.workspacePath, "cache/objects"));
  await fs.mkdir(join(f.workspacePath, "cache/refs"));
  await fs.writeFile(
    join(f.workspacePath, "cache/HEAD"),
    "ref: refs/heads/main\n",
  );
  await assert.rejects(
    service.inspect({
      ...base,
      inspectionPaths: ["cache"],
      excludePaths: ["cache/objects"],
    }),
    unsafe(),
  );
  // Writable roots are inspected for controls even outside the source scope.
  await fs.mkdir(join(f.workspacePath, "data/.git"));
  await assert.rejects(
    service.inspect({ ...base, inspectionPaths: [], outputPaths: ["data"] }),
    unsafe(),
  );
  // Excluding a subtree never grants state storage inside the workspace.
  await assert.rejects(
    service.inspect({
      ...base,
      excludePaths: ["cache"],
      stateRoot: join(f.workspacePath, "cache/state"),
    }),
    unsafe(),
  );
});

test("scoped links require selected targets and reject excluded intermediate hops", async (t) => {
  const f = await fixture(t);
  await fs.mkdir(join(f.workspacePath, "data"));
  await fs.mkdir(join(f.workspacePath, "cache"));
  await fs.writeFile(join(f.workspacePath, "data/input.md"), "input\n");
  const link = join(f.workspacePath, "input-link.md");
  await fs.symlink("data/input.md", link);
  const service = createWorkspaceService();
  const base = { workspacePath: f.workspacePath, stateRoot: f.stateRoot };
  const inspection = await service.inspect({
    ...base,
    inspectionPaths: ["input-link.md", "data/input.md"],
    excludePaths: ["cache"],
  });
  const snapshot = await service.snapshot({ inspection });
  assert.equal(
    snapshot.entries.find(({ path }) => path === link).kind,
    "symlink",
  );
  const unbound = await service.inspect({
    ...base,
    inspectionPaths: ["input-link.md"],
  });
  await assert.rejects(service.snapshot({ inspection: unbound }), unsafe());
  await fs.rm(link);
  await fs.symlink("cache/../data/input.md", link);
  const intermediate = await service.inspect({
    ...base,
    excludePaths: ["cache"],
  });
  await assert.rejects(
    service.snapshot({ inspection: intermediate }),
    unsafe(),
  );
  await fs.rm(link);
  await fs.symlink("data", link);
  const excludedTarget = await service.inspect({
    ...base,
    excludePaths: ["data/input.md"],
  });
  await assert.rejects(
    service.snapshot({ inspection: excludedTarget }),
    unsafe(),
  );
});

test("scope bindings reject routing substitution and bind even empty selection declarations", async (t) => {
  const f = await fixture(t);
  await fs.mkdir(join(f.workspacePath, "data"));
  await fs.mkdir(join(f.workspacePath, "data/cache"));
  const service = createWorkspaceService();
  const base = {
    workspacePath: f.workspacePath,
    stateRoot: f.stateRoot,
    inspectionPaths: [],
  };
  const inspection = await service.inspect({
    ...base,
    excludePaths: ["data/cache"],
  });
  const before = await service.snapshot({ inspection });
  const different = await service.inspect({
    ...base,
    excludePaths: ["another"],
  });
  const after = await service.snapshot({ inspection: different });
  assert.deepEqual(before.entries, after.entries);
  assert.notEqual(before.contentFingerprint, after.contentFingerprint);
  assert.throws(
    () => service.assertUnchanged({ before, after }),
    unsafe("ERR_WORKSPACE_DRIFT"),
  );
  await fs.rename(
    join(f.workspacePath, "data"),
    join(f.workspacePath, "old-data"),
  );
  await fs.mkdir(join(f.workspacePath, "data"));
  await assert.rejects(
    service.snapshot({ inspection }),
    unsafe("ERR_WORKSPACE_DRIFT"),
  );
});

test("traversal cancellation closes discovery and hashing handles with bounded anonymous progress", async (t) => {
  const f = await fixture(t);
  await fs.mkdir(join(f.workspacePath, "src"));
  const large = join(f.workspacePath, "src/input.txt");
  await fs.writeFile(large, Buffer.alloc(130 * 65536, 65));
  let controller = new AbortController();
  const stopped = new Error("controlled cancellation");
  const handles = new Set();
  let cancelRead = false;
  let reads = 0;
  let cancelDiscovery = false;
  const service = createWorkspaceService({
    fileSystem: {
      ...fs,
      async readdir(path, options) {
        const result = await fs.readdir(path, options);
        if (
          cancelDiscovery &&
          (await fs.realpath(path)) === join(f.workspacePath, "src")
        )
          controller.abort(stopped);
        return result;
      },
      async open(path, flags) {
        const handle = await fs.open(path, flags);
        handles.add(handle);
        const close = handle.close.bind(handle);
        handle.close = async () => {
          try {
            await close();
          } finally {
            handles.delete(handle);
          }
        };
        const read = handle.read.bind(handle);
        handle.read = async (...args) => {
          const result = await read(...args);
          if (cancelRead && path.endsWith("/input.txt")) {
            reads += 1;
            controller.abort(stopped);
          }
          return result;
        };
        return handle;
      },
    },
  });
  const declarations = {
    workspacePath: f.workspacePath,
    stateRoot: f.stateRoot,
    inspectionPaths: ["src"],
  };
  cancelDiscovery = true;
  await assert.rejects(
    service.inspect(declarations, { signal: controller.signal }),
    (error) => error === stopped,
  );
  assert.equal(handles.size, 0);
  cancelDiscovery = false;
  const inspection = await service.inspect(declarations);
  controller = new AbortController();
  cancelRead = true;
  await assert.rejects(
    service.snapshot({ inspection, signal: controller.signal }),
    (error) => error === stopped,
  );
  assert.equal(reads, 1);
  assert.equal(handles.size, 0);
  cancelRead = false;
  const progress = [];
  await service.snapshot({
    inspection,
    onProgress: (entry) => {
      progress.push(entry);
    },
  });
  assert.ok(progress.some(({ phase }) => phase === "capture"));
  assert.ok(
    progress.some(
      (entry, index) =>
        index > 0 &&
        entry.phase === "capture" &&
        progress[index - 1].phase === "capture",
    ),
  );
  assert.ok(
    progress.every(
      (entry, index) =>
        Object.isFrozen(entry) &&
        Object.keys(entry).join(",") === "phase,completed" &&
        (index === 0 || progress[index - 1].completed < entry.completed),
    ),
  );
  assert.ok(
    progress.every(
      (entry, index) =>
        index === 0 ||
        entry.phase !== progress[index - 1].phase ||
        entry.completed % 128 === 0,
    ),
  );
});

test("confined input reads reject leaf substitution before consuming content", async (t) => {
  const f = await fixture(t);
  const path = join(f.workspacePath, "task.md");
  await fs.writeFile(path, "declared input\n");
  const outside = join(f.root, "outside.md");
  await fs.writeFile(outside, "undeclared input\n");
  let opened = false;
  const service = createWorkspaceService({
    fileSystem: {
      ...fs,
      async open(candidate, flags) {
        if (candidate.endsWith("/task.md")) {
          opened = true;
          assert.ok(flags & constants.O_NOFOLLOW);
          assert.ok(flags & constants.O_NONBLOCK);
          await fs.rm(path);
          await fs.symlink(outside, path);
        }
        return fs.open(candidate, flags);
      },
    },
  });
  await assert.rejects(
    service.readFile({ path, projectPath: f.workspacePath }),
    unsafe("ERR_WORKSPACE_INSPECTION"),
  );
  assert.equal(opened, true);
});

test("ordinary directory snapshots bind external reads, preserve unrelated files and grant only declared outputs", async (t) => {
  const f = await fixture(t);
  await fs.mkdir(join(f.root, "reference"));
  await fs.writeFile(join(f.root, "reference", "source.txt"), "source\n");
  await fs.writeFile(join(f.workspacePath, "input.md"), "criteria\n");
  await fs.symlink("input.md", join(f.workspacePath, "input-link.md"));
  await fs.writeFile(join(f.workspacePath, "unrelated.txt"), "keep\n");
  const service = createWorkspaceService();
  const inspection = await service.inspect({
    workspacePath: f.workspacePath,
    stateRoot: f.stateRoot,
    inputPaths: ["input.md", "./input.md"],
    sourcePaths: [
      "../reference/source.txt",
      "../reference",
      "../reference/./source.txt",
    ],
    outputPaths: ["result/report.md"],
  });
  assert.deepEqual(inspection.inputPaths, [join(f.workspacePath, "input.md")]);
  assert.deepEqual(inspection.sourcePaths, [join(f.root, "reference")]);
  assert.deepEqual(inspection.outputPaths, [
    join(f.workspacePath, "result/report.md"),
  ]);
  assert.ok(Object.isFrozen(inspection.bindings));
  const before = await service.snapshot({ inspection });
  assert.equal(
    before.entries.find(
      (entry) => entry.path === join(f.workspacePath, "input-link.md"),
    ).kind,
    "symlink",
  );
  const repeated = await service.snapshot({ inspection });
  assert.equal(before.contentFingerprint, repeated.contentFingerprint);
  assert.equal(before.identityFingerprint, repeated.identityFingerprint);
  await fs.mkdir(join(f.workspacePath, "result"));
  await fs.writeFile(join(f.workspacePath, "result/report.md"), "accepted\n");
  const after = await service.snapshot({ inspection });
  service.assertUnchanged({ before, after, allowOutputs: true });
  assert.throws(
    () => service.assertUnchanged({ before, after }),
    unsafe("ERR_WORKSPACE_DRIFT"),
  );
  await fs.writeFile(join(f.workspacePath, "result/sibling.md"), "unrelated\n");
  const sibling = await service.snapshot({ inspection });
  assert.throws(
    () =>
      service.assertUnchanged({ before, after: sibling, allowOutputs: true }),
    unsafe("ERR_WORKSPACE_DRIFT"),
  );
  await fs.rm(join(f.workspacePath, "result/sibling.md"));
  await fs.writeFile(join(f.workspacePath, "unrelated.txt"), "unexpected\n");
  const unrelated = await service.snapshot({ inspection });
  assert.throws(
    () =>
      service.assertUnchanged({ before, after: unrelated, allowOutputs: true }),
    unsafe("ERR_WORKSPACE_DRIFT"),
  );
  await fs.writeFile(
    join(f.root, "reference", "source.txt"),
    "changed source\n",
  );
  const sourceChanged = await service.snapshot({ inspection });
  assert.throws(
    () =>
      service.assertUnchanged({
        before: unrelated,
        after: sourceChanged,
        allowOutputs: true,
      }),
    unsafe("ERR_WORKSPACE_DRIFT"),
  );
});

test("read-only guards detect content and equal-byte identity drift", async (t) => {
  const f = await fixture(t);
  const path = join(f.workspacePath, "source.txt");
  await fs.writeFile(path, "first\n");
  const service = createWorkspaceService();
  const inspection = await service.inspect({
    workspacePath: f.workspacePath,
    stateRoot: f.stateRoot,
  });
  const before = await service.snapshot({ inspection });
  await fs.writeFile(path, "second\n");
  const changed = await service.snapshot({ inspection });
  assert.notEqual(before.contentFingerprint, changed.contentFingerprint);
  assert.throws(
    () => service.assertUnchanged({ before, after: changed }),
    unsafe("ERR_WORKSPACE_DRIFT"),
  );
  await fs.writeFile(join(f.workspacePath, "replacement"), "second\n");
  await fs.rename(join(f.workspacePath, "replacement"), path);
  const replaced = await service.snapshot({ inspection });
  assert.equal(changed.contentFingerprint, replaced.contentFingerprint);
  assert.notEqual(changed.identityFingerprint, replaced.identityFingerprint);
  assert.throws(
    () => service.assertUnchanged({ before: changed, after: replaced }),
    unsafe("ERR_WORKSPACE_DRIFT"),
  );
});

test("snapshot filenames preserve leading Unicode byte-order marks", async (t) => {
  const f = await fixture(t);
  const path = join(f.workspacePath, "\ufeffsource.txt");
  await fs.writeFile(path, "protected\n");
  await fs.writeFile(join(f.workspacePath, "source.txt"), "unrelated\n");
  const service = createWorkspaceService();
  const inspection = await service.inspect({
    workspacePath: f.workspacePath,
    stateRoot: f.stateRoot,
  });
  const before = await service.snapshot({ inspection });
  assert.ok(before.entries.some((entry) => entry.path === path));
  await fs.writeFile(path, "changed\n");
  const after = await service.snapshot({ inspection });
  assert.notEqual(before.contentFingerprint, after.contentFingerprint);
  assert.throws(
    () => service.assertUnchanged({ before, after }),
    unsafe("ERR_WORKSPACE_DRIFT"),
  );
});

test("output admission rejects protected overlap in both directions and never promotes reads", async (t) => {
  const f = await fixture(t);
  await fs.mkdir(join(f.workspacePath, "data"));
  await fs.writeFile(join(f.workspacePath, "data", "input.md"), "input\n");
  const service = createWorkspaceService();
  const base = { workspacePath: f.workspacePath, stateRoot: f.stateRoot };
  for (const declarations of [
    { inputPaths: ["data/input.md"], outputPaths: ["data"] },
    { sourcePaths: ["data"], outputPaths: ["data/new.md"] },
    { configurationPaths: ["data/input.md"], outputPaths: ["data/input.md"] },
    { artifactPaths: ["artifacts"], outputPaths: ["artifacts/report.md"] },
    { infrastructurePaths: ["infra"], outputPaths: ["infra"] },
    { taskPath: "data", outputPaths: ["data/new.md"] },
    { outputPaths: ["../escaped.md"] },
    { outputPaths: ["."] },
    { outputPaths: ["new/.git/config"] },
    { sourcePaths: [".", "data"], outputPaths: ["new.md"] },
    { sourcePaths: ["https://example.invalid/source"] },
    { unexpected: true },
    { sourcePaths: null },
  ])
    await assert.rejects(
      service.inspect({ ...base, ...declarations }),
      unsafe(),
    );
});

test("state storage is disjoint from workspace, task and infrastructure even at missing destinations", async (t) => {
  const f = await fixture(t);
  const service = createWorkspaceService();
  for (const declarations of [
    { stateRoot: join(f.workspacePath, "state") },
    { stateRoot: f.root },
    { stateRoot: f.stateRoot, taskPath: "../state/tasks" },
    { stateRoot: f.stateRoot, infrastructurePaths: ["../state/infra"] },
  ])
    await assert.rejects(
      service.inspect({ workspacePath: f.workspacePath, ...declarations }),
      unsafe(),
    );
  await fs.symlink(f.root, join(f.workspacePath, "alias"));
  await assert.rejects(
    service.inspect({
      workspacePath: f.workspacePath,
      stateRoot: join(f.workspacePath, "alias/state"),
    }),
    unsafe(),
  );
});

test("filesystem discovery protects ancestor Git pointers, shared metadata and nested provider controls without Git", async (t) => {
  const f = await fixture(t);
  const gitDirectory = join(f.root, "metadata", "worktrees", "child");
  const common = join(f.root, "shared metadata ");
  await fs.mkdir(gitDirectory, { recursive: true });
  await fs.mkdir(common);
  await fs.writeFile(
    join(f.root, ".git"),
    "gitdir: metadata/worktrees/child\n",
  );
  await fs.writeFile(
    join(gitDirectory, "commondir"),
    "../../../shared metadata \r\n",
  );
  await fs.writeFile(join(common, "config"), "configuration\n");
  await fs.mkdir(join(f.workspacePath, "nested", ".codex"), {
    recursive: true,
  });
  await fs.mkdir(join(f.workspacePath, ".claude"));
  const service = createWorkspaceService();
  const options = {
    workspacePath: f.workspacePath,
    stateRoot: f.stateRoot,
    outputPaths: ["result.md"],
  };
  const inspection = await service.inspect(options);
  await assert.rejects(
    service.inspect({ ...options, stateRoot: join(common, "state") }),
    unsafe(),
  );
  for (const path of [
    join(f.root, ".git"),
    gitDirectory,
    common,
    join(f.workspacePath, "nested/.codex"),
    join(f.workspacePath, ".claude"),
  ])
    assert.ok(inspection.controlPaths.includes(path), path);
  const before = await service.snapshot({ inspection });
  await fs.writeFile(join(common, "config"), "changed\n");
  const after = await service.snapshot({ inspection });
  assert.throws(
    () => service.assertUnchanged({ before, after, allowOutputs: true }),
    unsafe("ERR_WORKSPACE_DRIFT"),
  );
  await assert.rejects(
    service.inspect({ ...options, outputPaths: ["nested"] }),
    unsafe(),
  );
  await fs.writeFile(join(f.root, ".git"), "not a git pointer\n");
  await assert.rejects(service.inspect(options), unsafe());
  await fs.rm(join(f.root, ".git"));
  await fs.mkdir(join(f.root, ".git"));
  await fs.writeFile(join(f.root, ".git", "HEAD"), "ref: refs/heads/main\n");
  const ordinaryRepository = await service.inspect(options);
  const ordinarySnapshot = await service.snapshot({
    inspection: ordinaryRepository,
  });
  assert.ok(
    ordinarySnapshot.entries.some(
      (entry) => entry.path === join(f.root, ".git", "HEAD"),
    ),
  );
});

test("workspace roots cannot be inside provider controls outside Git repositories", async (t) => {
  const f = await fixture(t);
  const workspacePath = join(f.root, ".codex", "project");
  await fs.mkdir(workspacePath, { recursive: true });
  await assert.rejects(
    createWorkspaceService().inspect({
      workspacePath,
      stateRoot: f.stateRoot,
    }),
    unsafe(),
  );
});

test("Git pointers nested in protected controls bind external and shared metadata", async (t) => {
  for (const placement of ["workspace", "enclosing", "metadata"]) {
    const f = await fixture(t);
    if (placement === "enclosing") await fs.mkdir(join(f.root, ".git"));
    const control =
      placement === "enclosing"
        ? join(f.root, ".agents")
        : join(f.workspacePath, placement === "metadata" ? ".git" : ".agents");
    if (placement === "metadata") {
      await fs.mkdir(join(control, "objects"), { recursive: true });
      await fs.mkdir(join(control, "refs"));
      await fs.writeFile(join(control, "HEAD"), "ref: refs/heads/main\n");
    }
    const packagePath =
      placement === "enclosing" ? control : join(control, "skills", "package");
    const gitDirectory = join(f.root, "metadata", "worktrees", "package");
    const common = join(f.root, "shared");
    const dependency = join(f.root, "dependency");
    await fs.mkdir(packagePath, { recursive: true });
    await fs.mkdir(join(gitDirectory, "nested"), { recursive: true });
    await fs.mkdir(common);
    await fs.mkdir(dependency);
    await fs.writeFile(join(packagePath, ".git"), `gitdir: ${gitDirectory}\n`);
    await fs.writeFile(join(gitDirectory, "commondir"), `${common}\n`);
    await fs.writeFile(join(gitDirectory, "HEAD"), "ref: refs/heads/main\n");
    await fs.writeFile(
      join(gitDirectory, "nested", ".git"),
      `gitdir: ${dependency}\n`,
    );
    await fs.writeFile(join(dependency, "HEAD"), "ref: refs/heads/main\n");
    await fs.writeFile(join(common, "config"), "configuration\n");
    const service = createWorkspaceService();
    const options = {
      workspacePath: f.workspacePath,
      stateRoot: f.stateRoot,
      outputPaths: ["report.md"],
    };
    const inspection = await service.inspect(options);
    assert.ok(inspection.controlPaths.includes(gitDirectory));
    assert.ok(inspection.controlPaths.includes(common));
    assert.ok(inspection.controlPaths.includes(dependency));
    await assert.rejects(
      service.inspect({ ...options, stateRoot: join(common, "state") }),
      unsafe(),
    );
    let before = await service.snapshot({ inspection });
    for (const path of [
      join(gitDirectory, "HEAD"),
      join(common, "config"),
      join(dependency, "HEAD"),
    ]) {
      await fs.writeFile(path, "changed\n");
      const after = await service.snapshot({ inspection });
      assert.notEqual(before.contentFingerprint, after.contentFingerprint);
      assert.notEqual(before.identityFingerprint, after.identityFingerprint);
      assert.throws(
        () => service.assertUnchanged({ before, after, allowOutputs: true }),
        unsafe("ERR_WORKSPACE_DRIFT"),
      );
      before = after;
    }
  }
});

test("state ancestors exclude unrelated control trees without adding snapshot scope", async (t) => {
  const f = await fixture(t);
  const unrelated = join(f.root, "unrelated");
  await fs.mkdir(unrelated);
  const service = createWorkspaceService();
  for (const name of [".git", ".agents"]) {
    const control = join(unrelated, name);
    await fs.mkdir(control);
    await assert.rejects(
      service.inspect({
        workspacePath: f.workspacePath,
        stateRoot: join(control, "runner-state"),
      }),
      unsafe(),
    );
  }
  const providerStorage = join(unrelated, "provider-storage");
  await fs.mkdir(providerStorage);
  await fs.symlink(providerStorage, join(unrelated, ".codex"));
  await assert.rejects(
    service.inspect({
      workspacePath: f.workspacePath,
      stateRoot: providerStorage,
    }),
    unsafe(),
  );
  const bare = join(unrelated, "metadata");
  await fs.mkdir(join(bare, "objects"), { recursive: true });
  await fs.mkdir(join(bare, "refs"));
  await fs.writeFile(join(bare, "HEAD"), "ref: refs/heads/main\n");
  await assert.rejects(
    service.inspect({
      workspacePath: f.workspacePath,
      stateRoot: join(bare, "runner-state"),
    }),
    unsafe(),
  );
  const inspection = await service.inspect({
    workspacePath: f.workspacePath,
    stateRoot: join(unrelated, "state"),
  });
  assert.deepEqual(inspection.readPaths, [f.workspacePath]);
  assert.ok(
    !inspection.controlPaths.some((path) => path.startsWith(unrelated)),
  );
  const before = await service.snapshot({ inspection });
  assert.ok(!before.entries.some((entry) => entry.path.startsWith(unrelated)));
  await fs.writeFile(join(unrelated, ".git", "HEAD"), "changed\n");
  const after = await service.snapshot({ inspection });
  service.assertUnchanged({ before, after });
  await fs.rm(join(unrelated, ".git"), { recursive: true });
  await fs.mkdir(join(unrelated, "worktree-metadata"));
  await fs.writeFile(join(unrelated, ".git"), "gitdir: worktree-metadata\n");
  await fs.writeFile(
    join(unrelated, "worktree-metadata", "commondir"),
    "../state\n",
  );
  await fs.mkdir(inspection.stateRoot);
  await assert.rejects(
    service.inspect({
      workspacePath: f.workspacePath,
      stateRoot: inspection.stateRoot,
    }),
    unsafe(),
  );
});

test("state-ancestor Git pointers protect workspace metadata without capturing unrelated storage", async (t) => {
  const f = await fixture(t);
  const unrelated = join(f.root, "unrelated");
  const metadata = join(f.workspacePath, "metadata");
  const shared = join(f.workspacePath, "shared");
  const external = join(unrelated, "metadata");
  await fs.mkdir(unrelated);
  for (const path of [metadata, shared, external]) await fs.mkdir(path);
  await fs.writeFile(join(metadata, "commondir"), `${external}\n`);
  await fs.writeFile(join(external, "HEAD"), "ref: refs/heads/main\n");
  const service = createWorkspaceService();
  const options = {
    workspacePath: f.workspacePath,
    stateRoot: join(unrelated, "state"),
  };
  for (const gitDirectory of [metadata, external]) {
    await fs.writeFile(join(unrelated, ".git"), `gitdir: ${gitDirectory}\n`);
    if (gitDirectory === external)
      await fs.writeFile(join(external, "commondir"), `${shared}\n`);
    const protectedPath = gitDirectory === metadata ? metadata : shared;
    const head = join(protectedPath, "HEAD");
    await fs.writeFile(head, "ref: refs/heads/main\n");
    for (const output of [protectedPath, head])
      await assert.rejects(
        service.inspect({ ...options, outputPaths: [output] }),
        unsafe(),
      );
    const inspection = await service.inspect({
      ...options,
      outputPaths: ["report.md"],
    });
    assert.ok(inspection.controlPaths.includes(protectedPath));
    const before = await service.snapshot({ inspection });
    assert.ok(
      !before.entries.some((entry) => entry.path.startsWith(unrelated)),
    );
    await fs.writeFile(head, "ref: refs/heads/changed\n");
    const after = await service.snapshot({ inspection });
    assert.throws(
      () => service.assertUnchanged({ before, after, allowOutputs: true }),
      unsafe("ERR_WORKSPACE_DRIFT"),
    );
  }
});

test("state-only metadata traversal follows nested Git pointers without adding snapshot scope", async (t) => {
  const f = await fixture(t);
  const unrelated = join(f.root, "unrelated");
  const metadata = join(f.root, "metadata");
  const shared = join(f.root, "shared");
  const stateRoot = join(unrelated, "state");
  for (const path of [stateRoot, metadata, shared])
    await fs.mkdir(path, { recursive: true });
  await fs.writeFile(join(unrelated, ".git"), `gitdir: ${metadata}\n`);
  await fs.writeFile(join(metadata, "commondir"), `${shared}\n`);
  await fs.writeFile(join(shared, "HEAD"), "ref: refs/heads/main\n");
  const service = createWorkspaceService();
  const options = { workspacePath: f.workspacePath, stateRoot };
  for (const parent of [metadata, shared]) {
    const nested = join(parent, "nested");
    await fs.mkdir(nested);
    const pointer = join(nested, ".git");
    await fs.writeFile(pointer, `gitdir: ${stateRoot}\n`);
    await assert.rejects(service.inspect(options), unsafe());
    // A safe cycle still needs bounded traversal, without exporting its reads.
    await fs.writeFile(pointer, `gitdir: ${metadata}\n`);
  }
  const inspection = await service.inspect(options);
  assert.deepEqual(inspection.readPaths, [f.workspacePath]);
  for (const path of [unrelated, metadata, shared])
    assert.ok(!inspection.controlPaths.includes(path));
  const before = await service.snapshot({ inspection });
  for (const path of [unrelated, metadata, shared])
    assert.ok(!before.entries.some((entry) => entry.path.startsWith(path)));
  await fs.writeFile(join(shared, "HEAD"), "ref: refs/heads/changed\n");
  const after = await service.snapshot({ inspection });
  service.assertUnchanged({ before, after });
});

test("repository-contained snapshots bind cross-control skill links without permitting unbound hops", async (t) => {
  const f = await fixture(t);
  await fs.mkdir(join(f.root, ".git"));
  const skills = join(f.root, ".agents", "skills");
  await fs.mkdir(skills, { recursive: true });
  await fs.writeFile(join(skills, "guide.md"), "instructions\n");
  await fs.mkdir(join(f.root, ".claude"));
  const link = join(f.root, ".claude", "skills");
  await fs.symlink("../.agents/skills", link);
  const service = createWorkspaceService();
  const inspection = await service.inspect({
    workspacePath: f.workspacePath,
    stateRoot: f.stateRoot,
    outputPaths: ["report.md"],
  });
  const before = await service.snapshot({ inspection });
  assert.equal(
    before.entries.find((entry) => entry.path === link).kind,
    "symlink",
  );
  await fs.writeFile(join(skills, "guide.md"), "changed instructions\n");
  const after = await service.snapshot({ inspection });
  assert.throws(
    () => service.assertUnchanged({ before, after, allowOutputs: true }),
    unsafe("ERR_WORKSPACE_DRIFT"),
  );
  await fs.mkdir(join(f.root, "unbound"));
  await fs.rm(link);
  await fs.symlink("../unbound/../.agents/skills", link);
  await assert.rejects(service.snapshot({ inspection }), unsafe());
});

test("bare Git metadata is protected at workspace roots, ancestors and nested outputs", async (t) => {
  const f = await fixture(t);
  const bare = join(f.workspacePath, "cache.git");
  await fs.mkdir(join(bare, "objects"), { recursive: true });
  await fs.mkdir(join(bare, "refs"));
  await fs.writeFile(join(bare, "HEAD"), "ref: refs/heads/main\n");
  await fs.writeFile(join(bare, "config"), "[core]\n\tbare = true\n");
  const service = createWorkspaceService();
  const options = { workspacePath: f.workspacePath, stateRoot: f.stateRoot };
  for (const output of ["cache.git/HEAD", "cache.git/refs", "cache.git"])
    await assert.rejects(
      service.inspect({ ...options, outputPaths: [output] }),
      unsafe(),
    );
  await assert.rejects(
    service.inspect({ ...options, workspacePath: bare }),
    unsafe(),
  );
  const child = join(bare, "project");
  await fs.mkdir(child);
  await assert.rejects(
    service.inspect({ ...options, workspacePath: child }),
    unsafe(),
  );
  const inspection = await service.inspect({
    ...options,
    outputPaths: ["result.md"],
  });
  assert.ok(inspection.controlPaths.includes(bare));
  const before = await service.snapshot({ inspection });
  await fs.writeFile(join(bare, "HEAD"), "ref: refs/heads/changed\n");
  const after = await service.snapshot({ inspection });
  assert.throws(
    () => service.assertUnchanged({ before, after, allowOutputs: true }),
    unsafe("ERR_WORKSPACE_DRIFT"),
  );
});

test("non-Git ancestor provider controls exclude state without granting snapshot reads", async (t) => {
  const f = await fixture(t);
  const control = join(f.root, ".codex");
  await fs.mkdir(control);
  await fs.writeFile(join(control, "settings.json"), "{}\n");
  const service = createWorkspaceService();
  await assert.rejects(
    service.inspect({
      workspacePath: f.workspacePath,
      stateRoot: join(control, "runner-state"),
    }),
    unsafe(),
  );
  const inspection = await service.inspect({
    workspacePath: f.workspacePath,
    stateRoot: f.stateRoot,
  });
  assert.ok(!inspection.controlPaths.includes(control));
  const before = await service.snapshot({ inspection });
  assert.ok(!before.entries.some((entry) => entry.path.startsWith(control)));
  await fs.writeFile(join(control, "settings.json"), '{"changed":true}\n');
  const after = await service.snapshot({ inspection });
  service.assertUnchanged({ before, after });
});

test("ancestor provider aliases exclude canonical state overlap without granting snapshot reads", async (t) => {
  const f = await fixture(t);
  const storage = join(f.root, "storage");
  const provider = join(storage, "provider");
  const control = join(f.root, ".codex");
  await fs.mkdir(provider, { recursive: true });
  await fs.writeFile(join(provider, "settings.json"), "{}\n");
  await fs.symlink(provider, control);
  const service = createWorkspaceService();
  for (const stateRoot of [storage, provider, join(provider, "state")])
    await assert.rejects(
      service.inspect({ workspacePath: f.workspacePath, stateRoot }),
      unsafe(),
    );
  const inspection = await service.inspect({
    workspacePath: f.workspacePath,
    stateRoot: f.stateRoot,
  });
  assert.ok(!inspection.controlPaths.includes(control));
  assert.ok(!inspection.controlPaths.includes(provider));
  const before = await service.snapshot({ inspection });
  assert.ok(!before.entries.some((entry) => entry.path.startsWith(provider)));
  await fs.writeFile(join(provider, "settings.json"), '{"changed":true}\n');
  const after = await service.snapshot({ inspection });
  service.assertUnchanged({ before, after });
});

test("ancestor provider alias resolution tolerates unrelated sibling creation but rejects directory replacement", async (t) => {
  for (const replace of [false, true]) {
    await t.test(replace ? "replacement" : "sibling creation", async (t) => {
      const f = await fixture(t);
      const provider = join(f.root, "provider-storage");
      await fs.mkdir(provider);
      await fs.symlink(provider, join(f.root, ".codex"));
      let mutate = true;
      const service = createWorkspaceService({
        fileSystem: {
          ...fs,
          async lstat(path, options) {
            const stat = await fs.lstat(path, options);
            if (mutate && path === provider) {
              mutate = false;
              if (replace) {
                await fs.rename(provider, `${provider}-previous`);
                await fs.mkdir(provider);
              } else await fs.mkdir(join(f.root, "unrelated"));
            }
            return stat;
          },
        },
      });
      const inspected = service.inspect({
        workspacePath: f.workspacePath,
        stateRoot: f.stateRoot,
      });
      if (replace)
        await assert.rejects(inspected, unsafe("ERR_WORKSPACE_SNAPSHOT_RACE"));
      else {
        const inspection = await inspected;
        assert.deepEqual(inspection.readPaths, [f.workspacePath]);
        assert.ok(!inspection.controlPaths.includes(provider));
      }
      assert.equal(mutate, false);
    });
  }
});

test("ancestor provider aliases protect canonical workspace targets from output authority", async (t) => {
  const f = await fixture(t);
  const storage = join(f.workspacePath, "storage");
  const control = join(f.root, ".codex");
  await fs.mkdir(storage);
  await fs.writeFile(join(storage, "config.toml"), "setting = true\n");
  await fs.symlink(storage, control);
  const service = createWorkspaceService();
  const options = { workspacePath: f.workspacePath, stateRoot: f.stateRoot };
  for (const output of ["storage/config.toml", "storage"])
    await assert.rejects(
      service.inspect({ ...options, outputPaths: [output] }),
      unsafe(),
    );
  const inspection = await service.inspect({
    ...options,
    outputPaths: ["report.md"],
  });
  assert.ok(inspection.controlPaths.includes(storage));
  assert.ok(!inspection.controlPaths.includes(control));
  const before = await service.snapshot({ inspection });
  await fs.writeFile(join(storage, "config.toml"), "setting = false\n");
  const after = await service.snapshot({ inspection });
  assert.throws(
    () => service.assertUnchanged({ before, after, allowOutputs: true }),
    unsafe("ERR_WORKSPACE_DRIFT"),
  );
  await fs.rm(control);
  await fs.symlink(f.workspacePath, control);
  await assert.rejects(service.inspect(options), unsafe());
});

test("ancestor provider aliases cannot traverse writable output intermediaries", async (t) => {
  const f = await fixture(t);
  const area = join(f.root, "area");
  await fs.mkdir(area);
  const workspacePath = join(area, "project");
  await fs.rename(f.workspacePath, workspacePath);
  const output = join(workspacePath, "out");
  await fs.mkdir(join(output, "branch", "deep"), { recursive: true });
  const storage = join(area, "storage");
  const alternate = join(f.root, "storage");
  await fs.mkdir(storage);
  await fs.mkdir(alternate);
  await fs.writeFile(join(storage, "config.toml"), "setting = true\n");
  const bridge = join(output, "bridge");
  await fs.symlink("branch/deep", bridge);
  const control = join(f.root, ".codex");
  await fs.symlink("area/project/out/bridge/../../../../storage", control);
  assert.equal(await fs.realpath(control), storage);
  const service = createWorkspaceService();
  const options = { workspacePath, stateRoot: f.stateRoot };
  await assert.rejects(
    service.inspect({ ...options, outputPaths: ["out"] }),
    unsafe(),
  );
  await fs.rm(bridge);
  await fs.symlink("branch", bridge);
  assert.equal(await fs.realpath(control), alternate);
  await assert.rejects(
    service.inspect({ ...options, outputPaths: ["out"] }),
    unsafe(),
  );
  const inspection = await service.inspect({
    ...options,
    outputPaths: ["report.md"],
  });
  for (const path of [control, storage, alternate])
    assert.ok(!inspection.controlPaths.includes(path));
  const snapshot = await service.snapshot({ inspection });
  for (const path of [control, storage, alternate])
    assert.ok(!snapshot.entries.some((entry) => entry.path.startsWith(path)));
});

test("internal provider-control directory aliases protect canonical targets and reject unsupported aliases", async (t) => {
  const query = (f, fileSystem) =>
    createWorkspaceService({ fileSystem }).inspectControls({
      workspacePath: f.workspacePath,
      paths: ["notes.md"],
      stateRoot: f.stateRoot,
    });
  for (const target of [".agents", "shared/provider"]) {
    await t.test(`accepts ${target}`, async (t) => {
      const f = await fixture(t);
      const canonical = join(f.workspacePath, target);
      const link = join(f.workspacePath, ".claude");
      await fs.mkdir(canonical, { recursive: true });
      await fs.symlink(target, link);
      const controls = await query(f);
      assert.ok(controls.includes(link));
      assert.ok(controls.includes(canonical));
      await assert.rejects(
        createWorkspaceService().inspect({
          workspacePath: f.workspacePath,
          stateRoot: f.stateRoot,
        }),
        {
          name: "WorkspaceSafetyError",
          message: "Workspace inspection cannot bind provider control aliases.",
        },
      );
    });
  }
  const parentTarget =
    "Provider control aliases must target a directory inside their parent.";
  const ordinaryContent =
    "Provider control aliases must resolve to ordinary content.";
  for (const [name, prepare, message] of [
    [
      "escaping",
      async (f) => {
        await fs.mkdir(join(f.root, "outside"));
        await fs.symlink("../outside", join(f.workspacePath, ".claude"));
      },
      parentTarget,
    ],
    [
      "dangling",
      (f) => fs.symlink("missing", join(f.workspacePath, ".claude")),
      ordinaryContent,
    ],
    [
      "cyclic",
      async (f) => {
        await fs.symlink(".codex", join(f.workspacePath, ".claude"));
        await fs.symlink(".claude", join(f.workspacePath, ".codex"));
      },
      "Provider control aliases are unsafe or cyclic.",
    ],
    [
      "regular file",
      async (f) => {
        await fs.writeFile(join(f.workspacePath, "settings.json"), "{}\n");
        await fs.symlink(
          "settings.json",
          join(f.workspacePath, ".claude.json"),
        );
      },
      "Provider control aliases must target a real directory.",
    ],
    [
      "fifo",
      async (f) => {
        await executeFile("mkfifo", [join(f.workspacePath, "pipe")]);
        await fs.symlink("pipe", join(f.workspacePath, ".claude"));
      },
      ordinaryContent,
    ],
    [
      "parent",
      (f) => fs.symlink(".", join(f.workspacePath, ".claude")),
      parentTarget,
    ],
    [
      "Git metadata",
      async (f) => {
        await fs.mkdir(join(f.workspacePath, ".git", "info"), {
          recursive: true,
        });
        await fs.symlink(".git/info", join(f.workspacePath, ".claude"));
      },
      "Provider control aliases cannot target Git metadata.",
    ],
    [
      "Git link",
      async (f) => {
        await fs.mkdir(join(f.workspacePath, "metadata"));
        await fs.symlink("metadata", join(f.workspacePath, ".git"));
      },
      "Git controls must be ordinary paths.",
    ],
    [
      "state overlap",
      async (f) => {
        await fs.mkdir(join(f.workspacePath, "shared"));
        await fs.symlink("shared", join(f.workspacePath, ".claude"));
        f.stateRoot = join(f.workspacePath, "shared", "state");
      },
      "State storage must be disjoint from discovered controls.",
    ],
  ])
    await t.test(`rejects ${name}`, async (t) => {
      const f = await fixture(t);
      await prepare(f);
      await assert.rejects(query(f), {
        name: "WorkspaceSafetyError",
        message,
      });
    });
  await t.test("rejects target replacement during resolution", async (t) => {
    const f = await fixture(t);
    const target = join(f.workspacePath, ".agents");
    await fs.mkdir(target);
    await fs.symlink(".agents", join(f.workspacePath, ".claude"));
    let replaced = false;
    await assert.rejects(
      query(f, {
        ...fs,
        async lstat(path, options) {
          const stat = await fs.lstat(path, options);
          if (!replaced && path === target) {
            replaced = true;
            await fs.rename(target, `${target}-previous`);
            await fs.mkdir(target);
          }
          return stat;
        },
      }),
      unsafe("ERR_WORKSPACE_SNAPSHOT_RACE"),
    );
    assert.equal(replaced, true);
  });
});

test("external reads bind enclosing and nested Git pointers, shared metadata and provider controls", async (t) => {
  const f = await fixture(t);
  const reference = join(f.root, "reference");
  const gitDirectory = join(f.workspacePath, "metadata");
  const common = join(f.root, "shared");
  const nested = join(reference, "nested");
  await fs.mkdir(join(reference, "content"), { recursive: true });
  await fs.mkdir(join(reference, ".codex"));
  await fs.mkdir(nested);
  await fs.mkdir(gitDirectory);
  await fs.mkdir(common);
  await fs.writeFile(join(reference, "content", "input.md"), "reference\n");
  await fs.writeFile(join(reference, ".git"), `gitdir: ${gitDirectory}\n`);
  await fs.writeFile(join(gitDirectory, "commondir"), `${common}\n`);
  await fs.writeFile(join(gitDirectory, "HEAD"), "ref: refs/heads/main\n");
  await fs.writeFile(join(common, "config"), "configuration\n");
  const service = createWorkspaceService();
  const options = {
    workspacePath: f.workspacePath,
    stateRoot: f.stateRoot,
    sourcePaths: [join(reference, "content", "input.md")],
  };
  for (const declarations of [
    { sourcePaths: options.sourcePaths },
    { inputPaths: options.sourcePaths },
  ]) {
    const base = { ...options, sourcePaths: [], ...declarations };
    await assert.rejects(
      service.inspect({ ...base, outputPaths: ["metadata/HEAD"] }),
      unsafe(),
    );
    await assert.rejects(
      service.inspect({ ...base, stateRoot: join(common, "state") }),
      unsafe(),
    );
  }
  const inspection = await service.inspect(options);
  for (const path of [
    join(reference, ".git"),
    join(reference, ".codex"),
    gitDirectory,
    common,
  ])
    assert.ok(inspection.controlPaths.includes(path), path);
  const before = await service.snapshot({ inspection });
  await fs.writeFile(join(common, "config"), "changed configuration\n");
  const after = await service.snapshot({ inspection });
  assert.throws(
    () => service.assertUnchanged({ before, after, allowOutputs: true }),
    unsafe("ERR_WORKSPACE_DRIFT"),
  );
  await fs.writeFile(join(nested, ".git"), `gitdir: ${gitDirectory}\n`);
  await fs.rm(join(reference, ".git"));
  await assert.rejects(service.snapshot({ inspection }), unsafe());
  const nestedInspection = await service.inspect({
    ...options,
    sourcePaths: [reference],
  });
  assert.ok(nestedInspection.controlPaths.includes(join(nested, ".git")));
  assert.ok(nestedInspection.controlPaths.includes(gitDirectory));
});

test("symlink resolution cannot leave its declared tree through an external intermediate link", async (t) => {
  const f = await fixture(t);
  await fs.writeFile(join(f.workspacePath, "first.txt"), "first\n");
  await fs.writeFile(join(f.workspacePath, "second.txt"), "second\n");
  const intermediate = join(f.root, "intermediate");
  await fs.symlink(join(f.workspacePath, "first.txt"), intermediate);
  await fs.symlink(intermediate, join(f.workspacePath, "link"));
  const service = createWorkspaceService();
  const inspection = await service.inspect({
    workspacePath: f.workspacePath,
    stateRoot: f.stateRoot,
  });
  await assert.rejects(service.snapshot({ inspection }), unsafe());
  await fs.rm(intermediate);
  await fs.symlink(join(f.workspacePath, "second.txt"), intermediate);
  await assert.rejects(service.snapshot({ inspection }), unsafe());
  await fs.rm(join(f.workspacePath, "link"));
  await fs.symlink("first.txt", join(f.workspacePath, "local-link"));
  await fs.symlink("local-link", join(f.workspacePath, "link"));
  const before = await service.snapshot({ inspection });
  await fs.rm(join(f.workspacePath, "local-link"));
  await fs.symlink("second.txt", join(f.workspacePath, "local-link"));
  const after = await service.snapshot({ inspection });
  assert.notEqual(before.contentFingerprint, after.contentFingerprint);
  assert.throws(
    () => service.assertUnchanged({ before, after }),
    unsafe("ERR_WORKSPACE_DRIFT"),
  );
});

test("read-only links cannot traverse mutable output intermediaries", async (t) => {
  const f = await fixture(t);
  const output = join(f.workspacePath, "data", "out");
  await fs.mkdir(join(output, "branch", "deep"), { recursive: true });
  await fs.writeFile(join(f.workspacePath, "source.txt"), "outer source\n");
  await fs.writeFile(
    join(f.workspacePath, "data", "source.txt"),
    "inner source\n",
  );
  const bridge = join(output, "bridge");
  await fs.symlink("branch/deep", bridge);
  const service = createWorkspaceService();
  const inspection = await service.inspect({
    workspacePath: f.workspacePath,
    stateRoot: f.stateRoot,
    outputPaths: ["data/out"],
  });
  const before = await service.snapshot({ inspection });
  const link = join(f.workspacePath, "read-link");
  await fs.symlink("data/out/bridge/../../../source.txt", link);
  assert.equal(
    await fs.realpath(link),
    join(f.workspacePath, "data", "source.txt"),
  );
  await assert.rejects(service.snapshot({ inspection }), unsafe());
  await fs.rm(bridge);
  await fs.symlink("branch", bridge);
  assert.equal(await fs.realpath(link), join(f.workspacePath, "source.txt"));
  await assert.rejects(service.snapshot({ inspection }), unsafe());
  await fs.rm(link);
  const after = await service.snapshot({ inspection });
  service.assertUnchanged({ before, after, allowOutputs: true });
});

test("Git metadata pointers reject aliases hidden by dot-segment normalization", async (t) => {
  const f = await fixture(t);
  const reference = join(f.root, "reference");
  const gitDirectory = join(f.root, "git-metadata");
  await fs.mkdir(join(reference, "metadata"), { recursive: true });
  await fs.mkdir(join(gitDirectory, "metadata"), { recursive: true });
  await fs.mkdir(join(f.workspacePath, "anchor"));
  await fs.mkdir(join(f.workspacePath, "metadata"));
  await fs.writeFile(join(reference, "input.md"), "reference\n");
  await fs.symlink(
    join(f.workspacePath, "anchor"),
    join(reference, "redirect"),
  );
  await fs.symlink(
    join(f.workspacePath, "anchor"),
    join(gitDirectory, "redirect"),
  );
  const options = {
    workspacePath: f.workspacePath,
    stateRoot: f.stateRoot,
    sourcePaths: [join(reference, "input.md")],
    outputPaths: ["metadata/HEAD"],
  };
  const service = createWorkspaceService();
  await fs.writeFile(join(reference, ".git"), "gitdir: redirect/../metadata\n");
  await assert.rejects(service.inspect(options), unsafe());
  await fs.writeFile(join(reference, ".git"), `gitdir: ${gitDirectory}\n`);
  await fs.writeFile(join(gitDirectory, "commondir"), "redirect/../metadata\n");
  await assert.rejects(service.inspect(options), unsafe());
});

test("directory aliases cannot expose output descendants through Git metadata", async (t) => {
  const f = await fixture(t);
  await fs.mkdir(join(f.workspacePath, ".git"));
  await fs.mkdir(join(f.workspacePath, "store"));
  await fs.symlink("../store", join(f.workspacePath, ".git", "objects"));
  const service = createWorkspaceService();
  const inspection = await service.inspect({
    workspacePath: f.workspacePath,
    stateRoot: f.stateRoot,
    outputPaths: ["store/new-object"],
  });
  await assert.rejects(service.snapshot({ inspection }), unsafe());
});

test("aliases, hard links, missing reads and ancestor substitution fail closed", async (t) => {
  const f = await fixture(t);
  const service = createWorkspaceService();
  const options = { workspacePath: f.workspacePath, stateRoot: f.stateRoot };
  await fs.writeFile(join(f.root, "outside.txt"), "outside\n");
  await fs.symlink(f.root, join(f.workspacePath, "alias"));
  await assert.rejects(
    service.inspect({ ...options, sourcePaths: ["alias/outside.txt"] }),
    unsafe(),
  );
  await assert.rejects(
    service.inspect({ ...options, outputPaths: ["alias/new.md"] }),
    unsafe(),
  );
  await assert.rejects(
    service.inspect({ ...options, inputPaths: ["missing.md"] }),
    unsafe(),
  );
  const inspection = await service.inspect(options);
  await assert.rejects(service.snapshot({ inspection }), unsafe());
  await fs.rm(join(f.workspacePath, "alias"));
  await fs.writeFile(join(f.workspacePath, "source.txt"), "protected\n");
  await fs.mkdir(join(f.workspacePath, "results"));
  await fs.symlink("../source.txt", join(f.workspacePath, "results/link"));
  const writable = await service.inspect({
    ...options,
    outputPaths: ["results"],
  });
  await assert.rejects(service.snapshot({ inspection: writable }), unsafe());
  await fs.rm(join(f.workspacePath, "results/link"));
  await fs.writeFile(join(f.workspacePath, "results/value"), "output\n");
  await fs.symlink("results/value", join(f.workspacePath, "read-link"));
  await assert.rejects(service.snapshot({ inspection: writable }), unsafe());
  await fs.rm(join(f.workspacePath, "read-link"));
  await fs.rm(join(f.workspacePath, "results"), { recursive: true });
  await fs.link(
    join(f.root, "outside.txt"),
    join(f.workspacePath, "linked.txt"),
  );
  await assert.rejects(service.snapshot({ inspection }), unsafe());
  await fs.rm(join(f.workspacePath, "linked.txt"));
  await fs.rename(f.workspacePath, `${f.workspacePath}-moved`);
  await fs.mkdir(f.workspacePath);
  await assert.rejects(
    service.snapshot({ inspection }),
    unsafe("ERR_WORKSPACE_DRIFT"),
  );
});

test("snapshot races and special files are rejected without opening unsafe content", async (t) => {
  const f = await fixture(t);
  const path = join(f.workspacePath, "source.txt");
  await fs.writeFile(path, "original\n");
  let active = false;
  const service = createWorkspaceService({
    fileSystem: {
      ...fs,
      async open(candidate, flags) {
        const handle = await fs.open(candidate, flags);
        if (active && candidate.endsWith("/source.txt")) {
          active = false;
          await fs.writeFile(path, "mutated\n");
        }
        return handle;
      },
    },
  });
  const inspection = await service.inspect({
    workspacePath: f.workspacePath,
    stateRoot: f.stateRoot,
  });
  active = true;
  await assert.rejects(
    service.snapshot({ inspection }),
    unsafe("ERR_WORKSPACE_SNAPSHOT_RACE"),
  );
  let opened = false;
  const special = createWorkspaceService({
    fileSystem: {
      ...fs,
      async lstat(candidate, options) {
        const stat = await fs.lstat(candidate, options);
        if (candidate.endsWith("/source.txt"))
          return {
            ...stat,
            isFile: () => false,
            isDirectory: () => false,
            isSymbolicLink: () => false,
          };
        return stat;
      },
      async open(candidate, flags) {
        if (candidate.endsWith("/source.txt")) opened = true;
        return fs.open(candidate, flags);
      },
    },
  });
  await assert.rejects(special.snapshot({ inspection }), unsafe());
  assert.equal(opened, false);
  const invalidName = Buffer.concat([
    Buffer.from(`${f.workspacePath}/`),
    Buffer.from([0xff]),
  ]);
  await fs.writeFile(invalidName, "unrepresentable\n");
  await fs.writeFile(join(f.workspacePath, "\ufffd"), "distinct file\n");
  await assert.rejects(service.snapshot({ inspection }), unsafe());
});

test("a redirected ancestor cannot redirect snapshot file reads", async (t) => {
  const f = await fixture(t);
  const source = join(f.workspacePath, "source.txt");
  const outside = join(f.root, "outside");
  await fs.writeFile(source, "original\n");
  await fs.mkdir(outside);
  await fs.writeFile(join(outside, "source.txt"), "unrelated\n");
  let redirect = false;
  let readPath;
  const service = createWorkspaceService({
    fileSystem: {
      ...fs,
      async open(path, flags) {
        if (redirect && path.endsWith("/source.txt")) {
          redirect = false;
          await fs.rename(f.workspacePath, `${f.workspacePath}-moved`);
          await fs.symlink(outside, f.workspacePath);
          readPath = await fs.realpath(path);
        }
        return fs.open(path, flags);
      },
    },
  });
  const inspection = await service.inspect({
    workspacePath: f.workspacePath,
    stateRoot: f.stateRoot,
  });
  redirect = true;
  await assert.rejects(
    service.snapshot({ inspection }),
    unsafe("ERR_WORKSPACE_SNAPSHOT_RACE"),
  );
  assert.equal(readPath, join(`${f.workspacePath}-moved`, "source.txt"));
  assert.equal(
    await fs.readFile(join(outside, "source.txt"), "utf8"),
    "unrelated\n",
  );
});

test("missing protected paths reject ancestor aliases introduced during capture", async (t) => {
  const f = await fixture(t);
  const artifacts = join(f.root, "artifacts");
  const outside = join(f.root, "outside");
  await fs.mkdir(artifacts);
  await fs.mkdir(outside);
  let redirect = false;
  const service = createWorkspaceService({
    fileSystem: {
      ...fs,
      async open(path, flags) {
        if (
          redirect &&
          path.startsWith("/proc/self/fd/") &&
          (await fs.realpath(path)) === f.workspacePath
        ) {
          redirect = false;
          await fs.symlink(outside, join(artifacts, "future"));
        }
        return fs.open(path, flags);
      },
    },
  });
  const inspection = await service.inspect({
    workspacePath: f.workspacePath,
    stateRoot: f.stateRoot,
    artifactPaths: [join(artifacts, "future", "report.md")],
  });
  redirect = true;
  await assert.rejects(service.snapshot({ inspection }), unsafe());
  assert.equal(redirect, false);
});

test("snapshot capture preserves the original declared input identity", async (t) => {
  const f = await fixture(t);
  const reference = join(f.root, "reference");
  await fs.mkdir(reference);
  const input = join(reference, "criteria.md");
  const replacement = join(reference, "replacement.md");
  await fs.writeFile(input, "criteria\n");
  await fs.writeFile(replacement, "criteria\n");
  let replace = false;
  const service = createWorkspaceService({
    fileSystem: {
      ...fs,
      async open(path, flags) {
        if (
          replace &&
          path.startsWith("/proc/self/fd/") &&
          (await fs.realpath(path)) === f.workspacePath
        ) {
          replace = false;
          await fs.rename(replacement, input);
        }
        return fs.open(path, flags);
      },
    },
  });
  const inspection = await service.inspect({
    workspacePath: f.workspacePath,
    stateRoot: f.stateRoot,
    inputPaths: [input],
  });
  replace = true;
  await assert.rejects(
    service.snapshot({ inspection }),
    unsafe("ERR_WORKSPACE_DRIFT"),
  );
  assert.equal(replace, false);
});
