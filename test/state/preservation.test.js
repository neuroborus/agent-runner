import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  chmod,
  cp,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readlink,
  realpath,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { createGitService } from "../../src/git/index.js";
import {
  createRunStore,
  RUN_STATE_SCHEMA_VERSION,
  RUNTIME_COMPATIBILITY,
} from "../../src/state/index.js";

const execute = promisify(execFile);

async function fixture(t, { linked = false } = {}) {
  const root = await mkdtemp(join(tmpdir(), "agent-runner-preservation-"));
  let projectPath = join(root, "project");
  const taskPath = join(root, "task");
  await Promise.all([mkdir(projectPath), mkdir(taskPath)]);
  const env = {
    ...Object.fromEntries(
      Object.entries(process.env).filter(([name]) => !name.startsWith("GIT_")),
    ),
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_OPTIONAL_LOCKS: "0",
    HOME: root,
    XDG_CONFIG_HOME: root,
  };
  const command = (...args) =>
    execute("git", ["-C", projectPath, ...args], { env });
  const write = (path, bytes) => writeFile(join(projectPath, path), bytes);
  await command("init", "-q", "-b", "main");
  await command("config", "user.name", "Fixture User");
  await command("config", "user.email", "fixture@example.com");
  await write(".gitignore", "ignored.txt\n");
  for (const path of ["first.txt", "removed.txt", "script.sh"])
    await write(path, "baseline\n");
  await mkdir(join(projectPath, "old-directory", "one", "two"), {
    recursive: true,
  });
  await write("old-directory/one/two/child.txt", "baseline child\n");
  await command("add", ".");
  await command("commit", "-qm", "fixture");
  if (linked) {
    const linkedPath = join(root, "linked");
    await command("worktree", "add", "-q", "-b", "linked", linkedPath);
    projectPath = linkedPath;
  }
  const git = createGitService({ env });
  let boundary = () => {};
  let transitionBoundary = () => {};
  const options = {
    stateRoot: join(root, "state"),
    onPreservationBoundary: (event) => boundary(event),
    onTransitionBoundary: (phase) => transitionBoundary(phase),
  };
  let store = createRunStore(options);
  const created = await store.createRun({
    pipelineId: "plan-execution",
    pipelineStateVersion: 1,
    projectPath,
    taskPath,
    roles: { worker: { backend: "codex", model: null } },
  });
  let lease = created.lease;
  let worktreeLease = await store.acquireWorktreeLease(
    projectPath,
    created.state.runId,
  );
  t.after(async () => {
    await worktreeLease.release();
    await lease.release();
    await rm(root, { recursive: true, force: true });
  });
  const preservationId = randomUUID();
  let captureInput;
  return {
    root,
    projectPath,
    created,
    get store() {
      return store;
    },
    get lease() {
      return lease;
    },
    async release() {
      await worktreeLease.release();
      await lease.release();
    },
    git,
    command,
    write,
    preservationId,
    boundary(callback) {
      boundary = callback;
    },
    transitionBoundary(callback) {
      transitionBoundary = callback;
    },
    async capture(overrides = {}) {
      captureInput ??= {
        preservationId,
        expectedRevision: created.state.revision,
        expectedSnapshot: await git.snapshot({ projectPath }),
        git,
      };
      return store.capturePreservation(lease, {
        ...captureInput,
        ...overrides,
        worktreeLease,
      });
    },
    async restore(paths, target, { git: restorationGit = git, ...input } = {}) {
      const request = {
        preservationId,
        operationId: randomUUID(),
        paths,
        target,
        expectedSnapshot: await git.snapshot({ projectPath }),
        ...input,
      };
      return {
        request,
        result: await store.restorePreservation(lease, {
          ...request,
          worktreeLease,
          git: restorationGit,
        }),
      };
    },
    retry(request) {
      return store.restorePreservation(lease, {
        ...request,
        worktreeLease,
        git,
      });
    },
    reconcile(request) {
      return store.reconcilePreservation(lease, {
        ...request,
        worktreeLease,
        git,
      });
    },
    async restart() {
      await worktreeLease.release();
      await lease.release();
      const restarted = createRunStore(options);
      lease = await restarted.acquireRunLease(created.state.runId);
      worktreeLease = await restarted.acquireWorktreeLease(
        projectPath,
        created.state.runId,
      );
      store = restarted;
      return restarted;
    },
    read() {
      return store.readPreservation(created.state.runId, preservationId);
    },
  };
}

test("preserves raw changes, deletions, modes and link targets without changing the index", async (t) => {
  const f = await fixture(t);
  await f.write("first.txt", "staged\n");
  await f.command("add", "first.txt");
  await f.write("first.txt", "workspace\n");
  await rm(join(f.projectPath, "removed.txt"));
  await chmod(join(f.projectPath, "script.sh"), 0o755);
  const binary = Buffer.alloc(1024 * 1024 + 1, 0xff);
  binary[0] = 0;
  await f.write("binary.dat", binary);
  await f.write("ignored.txt", "private\n");
  await symlink("/unavailable/reference", join(f.projectPath, "link"));
  const before = await f.git.snapshot({ projectPath: f.projectPath });
  await assert.rejects(
    f.store.capturePreservation(f.created.lease, {
      preservationId: f.preservationId,
      expectedRevision: f.created.state.revision,
      expectedSnapshot: before,
      git: f.git,
    }),
    { code: "ERR_INVALID_WORKTREE_LEASE" },
  );
  const record = await f.capture();
  await assert.rejects(
    f.capture({ expectedRevision: f.created.state.revision + 1 }),
    { code: "ERR_INVALID_PRESERVATION" },
  );
  assert.deepEqual(
    await f.git.snapshot({ projectPath: f.projectPath }),
    before,
  );
  const savedPath = join(
    f.created.directoryPath,
    `.preservation-${record.directoryId}`,
    record.ready.payloadId,
  );
  const payload = JSON.parse(
    await readFile(join(savedPath, "manifest.json"), "utf8"),
  );
  assert.deepEqual(
    payload.manifest.entries.map(({ after }) => after.path).sort(),
    ["binary.dat", "first.txt", "link", "removed.txt", "script.sh"],
  );
  const inspected = await f.store.readPreservation(
    f.created.state.runId,
    f.preservationId,
    { includeSources: true },
  );
  assert.deepEqual(inspected.record, record);
  assert.deepEqual(
    inspected.changes.map(({ after }) => after.path).sort(),
    payload.manifest.entries.map(({ after }) => after.path).sort(),
  );
  const savedBinary = inspected.changes.find(
    ({ after }) => after.path === "binary.dat",
  );
  assert.deepEqual(
    await readFile(
      join(inspected.source.blobDirectory, savedBinary.after.hash),
    ),
    binary,
  );
  assert.equal(inspected.source.manifestPath, join(savedPath, "manifest.json"));
  assert.equal(inspected.source.manifestHash, record.ready.manifestHash);
  assert.equal(
    inspected.changes.find(({ after }) => after.path === "removed.txt").after
      .kind,
    "deleted",
  );
  const state = await f.store.loadRun(f.created.state.runId);
  assert.equal(state.preservationRecords.length, 1);
  assert.deepEqual(state.pipelineState, f.created.state.pipelineState);
  assert.ok(JSON.stringify(state).length < 16000);
  const paths = payload.manifest.entries.map(({ after }) => after.path);
  await f.restore(paths, "before");
  assert.equal(
    await readFile(join(f.projectPath, "first.txt"), "utf8"),
    "baseline\n",
  );
  await f.restore(paths, "after");
  assert.equal(
    await readFile(join(f.projectPath, "first.txt"), "utf8"),
    "workspace\n",
  );
  assert.deepEqual(await readFile(join(f.projectPath, "binary.dat")), binary);
  assert.equal(
    await readlink(join(f.projectPath, "link")),
    "/unavailable/reference",
  );
  assert.ok((await lstat(join(f.projectPath, "script.sh"))).mode & 0o111);
  await assert.rejects(lstat(join(f.projectPath, "removed.txt")), {
    code: "ENOENT",
  });
  assert.equal(
    (await f.git.snapshot({ projectPath: f.projectPath })).indexFingerprint,
    before.indexFingerprint,
  );
  await assert.rejects(
    f.store.writeRunArtifact(
      f.created.lease,
      `.preservation-${f.preservationId}.json`,
      "{}",
    ),
    { code: "ERR_UNSAFE_RUN_ARTIFACT_PATH" },
  );
});

test("restores a baseline file over an inspected empty directory", async (t) => {
  const f = await fixture(t);
  await rm(join(f.projectPath, "first.txt"));
  await mkdir(join(f.projectPath, "first.txt"));
  await f.capture();
  await f.restore(["first.txt"], "before");
  assert.equal(
    await readFile(join(f.projectPath, "first.txt"), "utf8"),
    "baseline\n",
  );
});

test("restores deeply nested file/directory replacements by checked leaves", async (t) => {
  const f = await fixture(t);
  await rm(join(f.projectPath, "first.txt"));
  await mkdir(join(f.projectPath, "first.txt", "one", "two"), {
    recursive: true,
  });
  await f.write("first.txt/one/two/child.txt", "new child\n");
  await rm(join(f.projectPath, "old-directory"), { recursive: true });
  await f.write("old-directory", "new file\n");
  await f.capture();
  const paths = [
    "first.txt",
    "first.txt/one/two/child.txt",
    "old-directory",
    "old-directory/one/two/child.txt",
  ];
  await f.write("first.txt/one/two/ignored.txt", "uninspected\n");
  const request = {
    preservationId: f.preservationId,
    operationId: randomUUID(),
    paths,
    target: "before",
    expectedSnapshot: await f.git.snapshot({ projectPath: f.projectPath }),
  };
  await assert.rejects(f.retry(request), {
    code: "ERR_GIT_PRESERVATION_CHANGED",
  });
  assert.equal(
    await readFile(
      join(f.projectPath, "first.txt/one/two/ignored.txt"),
      "utf8",
    ),
    "uninspected\n",
  );
  await rm(join(f.projectPath, "first.txt/one/two/ignored.txt"));
  const nested = join(f.projectPath, "first.txt", "one");
  const originalNested = join(f.root, "original-nested");
  await rename(nested, originalNested);
  await mkdir(join(nested, "two"), { recursive: true });
  await assert.rejects(f.retry(request), {
    code: "ERR_GIT_PRESERVATION_CHANGED",
  });
  await rm(nested, { recursive: true });
  await rename(originalNested, nested);
  await f.restart();
  await f.retry(request);
  assert.equal(
    await readFile(join(f.projectPath, "first.txt"), "utf8"),
    "baseline\n",
  );
  assert.equal(
    await readFile(
      join(f.projectPath, "old-directory/one/two/child.txt"),
      "utf8",
    ),
    "baseline child\n",
  );
  await f.restore(paths, "after");
  assert.equal(
    await readFile(join(f.projectPath, "first.txt/one/two/child.txt"), "utf8"),
    "new child\n",
  );
  assert.equal(
    await readFile(join(f.projectPath, "old-directory"), "utf8"),
    "new file\n",
  );
});

for (const baselineLink of [true, false]) {
  test(`round-trips deeply nested ${baselineLink ? "symlink/directory" : "directory/symlink"} replacements without following the link`, async (t) => {
    const f = await fixture(t);
    const path = baselineLink ? "link" : "old-directory";
    const reference = join(f.root, "reference");
    await mkdir(join(reference, "one", "two"), { recursive: true });
    await writeFile(
      join(reference, "one/two/child.txt"),
      "unrelated reference\n",
    );
    if (baselineLink) {
      await symlink("../reference", join(f.projectPath, path));
      await f.command("add", path);
      await f.command("commit", "-qm", "fixture link");
      await rm(join(f.projectPath, path));
      await mkdir(join(f.projectPath, path, "one", "two"), { recursive: true });
      await f.write(`${path}/one/two/child.txt`, "unfinished child\n");
    } else {
      await rm(join(f.projectPath, path), { recursive: true });
      await symlink("../reference", join(f.projectPath, path));
    }
    const candidate = await f.git.snapshot({ projectPath: f.projectPath });
    await f.capture();
    const paths = [path, `${path}/one/two/child.txt`];
    for (const target of ["before", "after"]) {
      const request = {
        preservationId: f.preservationId,
        operationId: randomUUID(),
        paths,
        target,
        expectedSnapshot: await f.git.snapshot({ projectPath: f.projectPath }),
      };
      f.boundary(({ phase }) => {
        if (phase === "path-applied")
          throw new Error("Interrupted replacement");
      });
      await assert.rejects(f.retry(request), /Interrupted replacement/u);
      f.boundary(() => {});
      await f.restart();
      assert.equal((await f.retry(request)).complete, true);
      if (baselineLink === (target === "before")) {
        assert.equal(await readlink(join(f.projectPath, path)), "../reference");
        await assert.rejects(
          f.restore(
            [`${path}/one/two/child.txt`],
            target === "before" ? "after" : "before",
          ),
          { code: "ERR_GIT_PRESERVATION_CHANGED" },
        );
      } else {
        assert.equal(
          await readFile(
            join(f.projectPath, path, "one/two/child.txt"),
            "utf8",
          ),
          baselineLink ? "unfinished child\n" : "baseline child\n",
        );
      }
      assert.equal(
        await readFile(join(reference, "one/two/child.txt"), "utf8"),
        "unrelated reference\n",
      );
    }
    assert.deepEqual(
      await f.git.snapshot({ projectPath: f.projectPath }),
      candidate,
    );
  });
}

test("stop reconciliation settles only an existing restoration intent with its exact authority", async (t) => {
  const f = await fixture(t);
  await f.write("first.txt", "unfinished\n");
  await f.capture();
  const request = {
    preservationId: f.preservationId,
    operationId: randomUUID(),
    paths: ["first.txt"],
    target: "before",
    expectedSnapshot: await f.git.snapshot({ projectPath: f.projectPath }),
  };
  await assert.rejects(
    f.retry({
      ...request,
      signal: AbortSignal.abort(new Error("Interrupted restoration")),
    }),
    /Interrupted restoration/u,
  );
  const current = await f.store.transitionRun(f.lease, {
    pipelineState: { workflowState: "IMPLEMENT" },
  });
  await f.store.requestOperatorStop({
    runId: current.runId,
    kind: "cancel_requested",
    expectedRevision: current.revision,
    idempotencyKey: "preservation-stop",
  });
  const stopped = await f.store.loadRun(current.runId);
  const unstarted = { ...request, operationId: randomUUID() };
  assert.equal(await f.reconcile(unstarted), null);
  assert.deepEqual(await f.store.loadRun(current.runId), stopped);
  await assert.rejects(f.retry(unstarted), {
    code: "ERR_STOP_RECONCILIATION_REQUIRED",
  });
  await assert.rejects(f.reconcile({ ...request, target: "after" }), {
    code: "ERR_INVALID_PRESERVATION",
  });
  assert.equal((await f.reconcile(request)).complete, true);
  assert.equal(
    await readFile(join(f.projectPath, "first.txt"), "utf8"),
    "baseline\n",
  );
  assert.ok((await f.read()).ready);
  await f.store.settleCheckpoint(f.lease, (latest) => ({
    patch: {
      pipelineState: { ...latest.pipelineState, workflowState: "CANCELED" },
      pause: {
        reason: "operator_canceled",
        resumeAction: null,
        operatorResume: {
          workflowState: "IMPLEMENT",
          pause: null,
          activeTurn: null,
        },
      },
    },
  }));
});

test("capture interruption and cancellation retain saved work across reconstruction", async (t) => {
  const f = await fixture(t);
  await f.write("first.txt", "unfinished\n");
  for (const phase of ["capture-intent", "captured"]) {
    f.boundary((event) => {
      if (event.phase === phase) throw new Error("Interrupted capture");
    });
    await assert.rejects(f.capture(), /Interrupted capture/u);
    assert.equal(
      await readFile(join(f.projectPath, "first.txt"), "utf8"),
      "unfinished\n",
    );
    if (phase === "capture-intent") {
      f.boundary(() => {});
      const interrupted = {
        ...f.git,
        captureChanges: (input) =>
          f.git.captureChanges({
            ...input,
            async writeBlob(...args) {
              await input.writeBlob(...args);
              throw new Error("Interrupted blob capture");
            },
          }),
      };
      await assert.rejects(
        f.capture({ git: interrupted }),
        /Interrupted blob capture/u,
      );
      assert.equal((await f.read()).ready, null);
    }
  }
  f.boundary(() => {});
  const saved = await f.capture();
  const restarted = await f.restart();
  assert.deepEqual(
    await restarted.readPreservation(f.created.state.runId, f.preservationId),
    saved,
  );
  const aborted = AbortSignal.abort(new Error("Canceled restoration"));
  await assert.rejects(
    f.restore(["first.txt"], "before", { signal: aborted }),
    /Canceled restoration/u,
  );
  assert.deepEqual(await f.read(), saved);
  assert.equal(
    await readFile(join(f.projectPath, "first.txt"), "utf8"),
    "unfinished\n",
  );
});

test("resumes prepared and partially applied restorations without replaying completed writes", async (t) => {
  const f = await fixture(t);
  await f.write("first.txt", "first remainder\n");
  await f.write("script.sh", "second remainder\n");
  await f.capture();
  for (const phase of ["path-prepared", "path-applied"]) {
    const request = {
      preservationId: f.preservationId,
      operationId: randomUUID(),
      paths: ["first.txt", "script.sh"],
      target: "before",
      expectedSnapshot: await f.git.snapshot({ projectPath: f.projectPath }),
    };
    let interrupted = false;
    f.boundary((event) => {
      if (!interrupted && event.phase === phase) {
        interrupted = true;
        throw new Error("Interrupted restore");
      }
    });
    await assert.rejects(f.retry(request), /Interrupted restore/u);
    f.boundary(() => {});
    if (phase === "path-prepared") {
      const temporary = join(
        f.projectPath,
        `.preservation-${request.operationId}-0.tmp`,
      );
      const original = join(f.root, "original-temporary");
      const bytes = await readFile(temporary);
      await rename(temporary, original);
      await writeFile(temporary, bytes);
      await assert.rejects(f.retry(request), {
        code: "ERR_GIT_PRESERVATION_CHANGED",
      });
      await rm(temporary);
      await assert.rejects(f.retry(request), {
        code: "ERR_GIT_PRESERVATION_CHANGED",
      });
      await rename(original, temporary);
    }
    await f.restart();
    assert.equal((await f.retry(request)).complete, true);
    const inode = (await lstat(join(f.projectPath, "first.txt"))).ino;
    await f.retry(request);
    assert.equal((await lstat(join(f.projectPath, "first.txt"))).ino, inode);
    await f.restore(["first.txt", "script.sh"], "after");
  }
});

test("recovery syncs already-applied replacements and deletions before completion", async (t) => {
  const f = await fixture(t);
  await f.write("first.txt", "unfinished\n");
  await f.write("new.txt", "new work\n");
  await f.capture();
  const handle = await open(f.projectPath, "r");
  const prototype = Object.getPrototypeOf(handle);
  const sync = prototype.sync;
  await handle.close();
  for (const path of ["first.txt", "new.txt"]) {
    const request = {
      preservationId: f.preservationId,
      operationId: randomUUID(),
      paths: [path],
      target: "before",
      expectedSnapshot: await f.git.snapshot({ projectPath: f.projectPath }),
    };
    let interrupted = false;
    let synced = false;
    const mocked = t.mock.method(prototype, "sync", async function () {
      if ((await realpath(`/proc/self/fd/${this.fd}`)) === f.projectPath) {
        const applied =
          path === "first.txt"
            ? (await readFile(join(f.projectPath, path), "utf8")) ===
              "baseline\n"
            : (await lstat(join(f.projectPath, path)).catch((cause) => {
                if (cause.code !== "ENOENT") throw cause;
                return null;
              })) === null;
        if (applied) {
          if (!interrupted) {
            interrupted = true;
            throw new Error("Interrupted directory sync");
          }
          await sync.call(this);
          synced = true;
          return;
        }
      }
      return sync.call(this);
    });
    await assert.rejects(f.retry(request), /Interrupted directory sync/u);
    assert.equal(interrupted, true);
    await f.restart();
    f.boundary(({ phase }) => {
      if (phase === "restored") assert.equal(synced, true);
    });
    assert.equal((await f.retry(request)).complete, true);
    mocked.mock.restore();
    f.boundary(() => {});
  }
});

test("recovers temporary creation before its identity is published", async (t) => {
  const f = await fixture(t);
  await f.write("first.txt", "first remainder\n");
  await f.write("script.sh", "second remainder\n");
  await symlink("saved-target", join(f.projectPath, "saved-link"));
  await f.capture();
  await f.restore(["saved-link"], "before");
  for (const [paths, target] of [
    [["first.txt", "script.sh"], "before"],
    [["saved-link"], "after"],
  ]) {
    const request = {
      preservationId: f.preservationId,
      operationId: randomUUID(),
      paths,
      target,
      expectedSnapshot: await f.git.snapshot({ projectPath: f.projectPath }),
    };
    const interruptedIndex = paths.length - 1;
    const git = {
      ...f.git,
      applyRestoration: (input) =>
        f.git.applyRestoration({
          ...input,
          async recordPrepared(index, entry) {
            if (index === interruptedIndex && entry.identity !== null)
              throw new Error("Interrupted temporary publication");
            await input.recordPrepared(index, entry);
          },
        }),
    };
    await assert.rejects(
      f.restore(paths, target, { ...request, git }),
      /Interrupted temporary publication/u,
    );
    const temporary = join(
      f.projectPath,
      `.preservation-${request.operationId}-${interruptedIndex}.tmp`,
    );
    if (target === "before") await writeFile(temporary, "unrelated\n");
    else {
      await rm(temporary);
      await symlink("unrelated-target", temporary);
    }
    await f.restart();
    await assert.rejects(f.retry(request), {
      code: "ERR_GIT_PRESERVATION_CHANGED",
    });
    if (target === "before") await writeFile(temporary, "");
    else {
      await rm(temporary);
      await symlink("saved-target", temporary);
    }
    const applied = await lstat(join(f.projectPath, "first.txt"));
    await f.restart();
    assert.equal((await f.retry(request)).complete, true);
    assert.equal(
      (await lstat(join(f.projectPath, "first.txt"))).ino,
      applied.ino,
    );
  }
  assert.equal(
    await readFile(join(f.projectPath, "script.sh"), "utf8"),
    "baseline\n",
  );
  assert.equal(
    await readlink(join(f.projectPath, "saved-link")),
    "saved-target",
  );
});

test("recovers a partially written temporary only under its journaled identity", async (t) => {
  const f = await fixture(t);
  await f.write("first.txt", "unfinished\n");
  await f.capture();
  const request = {
    preservationId: f.preservationId,
    operationId: randomUUID(),
    paths: ["first.txt"],
    target: "before",
    expectedSnapshot: await f.git.snapshot({ projectPath: f.projectPath }),
  };
  f.boundary(({ phase }) => {
    if (phase === "path-created")
      throw new Error("Interrupted temporary write");
  });
  await assert.rejects(f.retry(request), /Interrupted temporary write/u);
  f.boundary(() => {});
  const temporary = join(
    f.projectPath,
    `.preservation-${request.operationId}-0.tmp`,
  );
  await writeFile(temporary, "base");
  const original = join(f.root, "original-temporary");
  await rename(temporary, original);
  await writeFile(temporary, "base", { mode: 0o600 });
  await f.restart();
  await assert.rejects(f.retry(request), {
    code: "ERR_GIT_PRESERVATION_CHANGED",
  });
  await rm(temporary);
  await rename(original, temporary);
  assert.equal((await f.retry(request)).complete, true);
  assert.equal(
    await readFile(join(f.projectPath, "first.txt"), "utf8"),
    "baseline\n",
  );
});

test("rejects replacement of a parent created during an interrupted restoration", async (t) => {
  const f = await fixture(t);
  await rm(join(f.projectPath, "first.txt"));
  await mkdir(join(f.projectPath, "first.txt"));
  await f.write("first.txt/child.txt", "unfinished\n");
  await f.capture();
  const paths = ["first.txt", "first.txt/child.txt"];
  await f.restore(paths, "before");
  const request = {
    preservationId: f.preservationId,
    operationId: randomUUID(),
    paths,
    target: "after",
    expectedSnapshot: await f.git.snapshot({ projectPath: f.projectPath }),
  };
  let preparedIndex;
  f.boundary(({ phase, index }) => {
    if (phase === "path-prepared") {
      preparedIndex = index;
      throw new Error("Interrupted new parent");
    }
  });
  await assert.rejects(f.retry(request), /Interrupted new parent/u);
  f.boundary(() => {});
  const parent = join(f.projectPath, "first.txt");
  const originalParent = join(f.root, "original-parent");
  const temporary = `.preservation-${request.operationId}-${preparedIndex}.tmp`;
  await rename(parent, originalParent);
  await mkdir(parent);
  await rename(join(originalParent, temporary), join(parent, temporary));
  await f.restart();
  await assert.rejects(f.retry(request), {
    code: "ERR_GIT_PRESERVATION_CHANGED",
  });
  await assert.rejects(lstat(join(parent, "child.txt")), { code: "ENOENT" });
  await rename(join(parent, temporary), join(originalParent, temporary));
  await rm(parent, { recursive: true });
  await rename(originalParent, parent);
  assert.equal((await f.retry(request)).complete, true);
  assert.equal(
    await readFile(join(parent, "child.txt"), "utf8"),
    "unfinished\n",
  );
});

for (const phase of ["blob read", "parent identity publication"]) {
  test(`rejects parent substitution after interrupted ${phase}`, async (t) => {
    const f = await fixture(t);
    await mkdir(join(f.projectPath, "new-parent"));
    await f.write("new-parent/child.txt", "unfinished\n");
    await f.capture();
    await f.restore(["new-parent/child.txt"], "before");
    await rm(join(f.projectPath, "new-parent"), { recursive: true });
    const request = {
      preservationId: f.preservationId,
      operationId: randomUUID(),
      paths: ["new-parent/child.txt"],
      target: "after",
      expectedSnapshot: await f.git.snapshot({ projectPath: f.projectPath }),
    };
    let reads = 0;
    const git = {
      ...f.git,
      applyRestoration: (input) =>
        f.git.applyRestoration({
          ...input,
          async readBlob(entry) {
            const bytes = await input.readBlob(entry);
            if (++reads === 2 && phase === "blob read")
              throw new Error("Interrupted parent preparation");
            return bytes;
          },
          async recordPrepared(index, entry) {
            if (
              phase === "parent identity publication" &&
              entry.ancestors["new-parent"]
            )
              throw new Error("Interrupted parent preparation");
            await input.recordPrepared(index, entry);
          },
        }),
    };
    await assert.rejects(
      f.restore(request.paths, request.target, { ...request, git }),
      /Interrupted parent preparation/u,
    );
    const parent = join(f.projectPath, "new-parent");
    const original = join(f.root, "original-parent");
    await rename(parent, original);
    await mkdir(parent);
    await f.restart();
    await assert.rejects(f.retry(request), {
      code: "ERR_GIT_PRESERVATION_CHANGED",
    });
    await assert.rejects(lstat(join(parent, "child.txt")), { code: "ENOENT" });
    await rm(parent, { recursive: true });
    await rename(original, parent);
    if (phase === "parent identity publication") {
      await assert.rejects(f.retry(request), {
        code: "ERR_GIT_PRESERVATION_CHANGED",
      });
      await rm(parent, { recursive: true });
    }
    assert.equal((await f.retry(request)).complete, true);
  });
}

test("retains the remainder after a verified child commit and rejects drift before restoring", async (t) => {
  const f = await fixture(t);
  await f.write("first.txt", "child change\n");
  await f.write("script.sh", "future change\n");
  await f.capture();
  await f.restore(["script.sh"], "before");
  await f.command("add", "first.txt");
  await f.command("commit", "-qm", "child fixture");
  await f.restart();
  await f.restore(["script.sh"], "after");
  assert.equal(
    await readFile(join(f.projectPath, "first.txt"), "utf8"),
    "child change\n",
  );
  assert.equal(
    await readFile(join(f.projectPath, "script.sh"), "utf8"),
    "future change\n",
  );
  const request = {
    preservationId: f.preservationId,
    operationId: randomUUID(),
    paths: ["script.sh"],
    target: "before",
    expectedSnapshot: await f.git.snapshot({ projectPath: f.projectPath }),
  };
  f.boundary((event) => {
    if (event.phase === "restore-intent") throw new Error("Stop before apply");
  });
  await assert.rejects(f.retry(request), /Stop before apply/u);
  f.boundary(() => {});
  await f.write("unrelated.txt", "unexpected\n");
  await assert.rejects(f.retry(request), {
    code: "ERR_GIT_PRESERVATION_CHANGED",
  });
  await rm(join(f.projectPath, "unrelated.txt"));
  await f.command("add", "script.sh");
  await assert.rejects(f.retry(request), {
    code: "ERR_INTERRUPTED_REPOSITORY_CONTROL_CHANGED",
  });
  assert.equal(
    await readFile(join(f.projectPath, "script.sh"), "utf8"),
    "future change\n",
  );
});

test("rejects substituted durable storage and escaping workspace parents", async (t) => {
  const f = await fixture(t);
  await mkdir(join(f.projectPath, "nested"));
  await f.write("nested/new.txt", "remainder\n");
  const record = await f.capture();
  const rootPath = join(
    f.created.directoryPath,
    `.preservation-${record.directoryId}`,
  );
  const payloadPath = join(rootPath, record.ready.payloadId);
  const payload = JSON.parse(
    await readFile(join(payloadPath, "manifest.json"), "utf8"),
  );
  const blobPath = join(payloadPath, payload.manifest.entries[0].after.hash);
  const bytes = await readFile(blobPath);
  await rename(blobPath, `${blobPath}.original`);
  await writeFile(blobPath, bytes);
  await assert.rejects(f.read(), { code: "ERR_INVALID_PRESERVATION" });
  await rm(blobPath);
  await rename(`${blobPath}.original`, blobPath);
  await f.restore(["nested/new.txt"], "before");
  await rm(join(f.projectPath, "nested"), { recursive: true });
  await symlink(f.root, join(f.projectPath, "nested"));
  await assert.rejects(f.restore(["nested/new.txt"], "after"), {
    code: "ERR_GIT_PRESERVATION_CHANGED",
  });
  await rename(rootPath, `${rootPath}.original`);
  await mkdir(rootPath, { mode: 0o700 });
  await assert.rejects(f.read(), { code: "ERR_INVALID_PRESERVATION" });
});

test("rejects storage substitution before applying a prepared replacement", async (t) => {
  const f = await fixture(t);
  await f.write("first.txt", "unfinished\n");
  await f.write("new.txt", "new work\n");
  const record = await f.capture();
  await f.restore(["new.txt"], "before");
  const storageRoot = join(
    f.created.directoryPath,
    `.preservation-${record.directoryId}`,
  );
  const originalRoot = join(f.created.directoryPath, "original-storage");
  const manifestPath = join(
    storageRoot,
    record.ready.payloadId,
    "manifest.json",
  );
  const manifestBytes = await readFile(manifestPath);
  const state = await f.store.loadRun(f.created.state.runId);
  const reference = state.preservationRecords.find(
    ({ id }) => id === f.preservationId,
  );
  const recordPath = join(
    f.created.directoryPath,
    `.preservation-record-${reference.fileId}.json`,
  );
  const recordBytes = await readFile(recordPath);
  for (const substitution of [
    "directory",
    "manifest",
    "content",
    "record",
    "record-content",
  ]) {
    const request = {
      preservationId: f.preservationId,
      operationId: randomUUID(),
      paths: [substitution === "directory" ? "new.txt" : "first.txt"],
      target: substitution === "directory" ? "after" : "before",
      expectedSnapshot: await f.git.snapshot({ projectPath: f.projectPath }),
    };
    f.boundary(async ({ phase }) => {
      if (phase !== "path-prepared") return;
      if (substitution === "directory") {
        await rename(storageRoot, originalRoot);
        await mkdir(storageRoot, { mode: 0o700 });
        await rename(
          join(originalRoot, record.ready.payloadId),
          join(storageRoot, record.ready.payloadId),
        );
      } else if (substitution === "manifest") {
        await rename(manifestPath, `${manifestPath}.original`);
        await writeFile(manifestPath, manifestBytes, { mode: 0o600 });
      } else if (substitution === "record") {
        await rename(recordPath, `${recordPath}.original`);
        await writeFile(recordPath, recordBytes, { mode: 0o600 });
      } else if (substitution === "record-content") {
        await writeFile(recordPath, "{}\n");
      } else {
        const changed = Buffer.from(manifestBytes);
        changed[0] = 0x5b;
        await writeFile(manifestPath, changed);
      }
    });
    await assert.rejects(f.retry(request), {
      code: "ERR_INVALID_PRESERVATION",
    });
    assert.equal(
      await readFile(join(f.projectPath, "first.txt"), "utf8"),
      "unfinished\n",
    );
    if (substitution === "directory")
      await assert.rejects(lstat(join(f.projectPath, "new.txt")), {
        code: "ENOENT",
      });
    f.boundary(() => {});
    if (substitution === "directory") {
      await rename(
        join(storageRoot, record.ready.payloadId),
        join(originalRoot, record.ready.payloadId),
      );
      await rm(storageRoot, { recursive: true });
      await rename(originalRoot, storageRoot);
    } else if (substitution === "manifest") {
      await rm(manifestPath);
      await rename(`${manifestPath}.original`, manifestPath);
    } else if (substitution === "record") {
      await rm(recordPath);
      await rename(`${recordPath}.original`, recordPath);
    } else if (substitution === "record-content") {
      await writeFile(recordPath, recordBytes);
    } else {
      await writeFile(manifestPath, manifestBytes);
    }
    await f.restart();
    assert.equal((await f.retry(request)).complete, true);
    if (substitution !== "directory") await f.restore(["first.txt"], "after");
  }
});

test("rejects identical record, ancestor and Git control replacements", async (t) => {
  const f = await fixture(t);
  await mkdir(join(f.projectPath, "__proto__"));
  await f.write("__proto__/new.txt", "unfinished\n");
  await f.capture();
  const state = await f.store.loadRun(f.created.state.runId);
  const reference = state.preservationRecords.find(
    ({ id }) => id === f.preservationId,
  );
  const recordPath = join(
    f.created.directoryPath,
    `.preservation-record-${reference.fileId}.json`,
  );
  const recordBytes = await readFile(recordPath);
  await rename(recordPath, `${recordPath}.original`);
  await writeFile(recordPath, recordBytes);
  await assert.rejects(f.read(), { code: "ERR_INVALID_PRESERVATION" });
  await rm(recordPath);
  await rename(`${recordPath}.original`, recordPath);

  const request = {
    preservationId: f.preservationId,
    operationId: randomUUID(),
    paths: ["__proto__/new.txt"],
    target: "before",
    expectedSnapshot: await f.git.snapshot({ projectPath: f.projectPath }),
  };
  f.boundary(({ phase }) => {
    if (phase === "restore-intent") throw new Error("Interrupted intent");
  });
  await assert.rejects(f.retry(request), /Interrupted intent/u);
  f.boundary(() => {});
  const nested = join(f.projectPath, "__proto__");
  await rename(nested, join(f.root, "original-parent"));
  await mkdir(nested);
  await f.write("__proto__/new.txt", "unfinished\n");
  await assert.rejects(f.retry(request), {
    code: "ERR_GIT_PRESERVATION_CHANGED",
  });
  await rm(nested, { recursive: true });
  await rename(join(f.root, "original-parent"), nested);
  const controls = join(f.projectPath, ".git");
  await rename(controls, join(f.root, "original-controls"));
  await cp(join(f.root, "original-controls"), controls, { recursive: true });
  await assert.rejects(f.retry(request), {
    code: "ERR_GIT_PRESERVATION_CHANGED",
  });
  assert.equal(await readFile(join(nested, "new.txt"), "utf8"), "unfinished\n");
});

test("recovers a journaled capture intent when state publication is interrupted", async (t) => {
  const f = await fixture(t);
  await f.write("first.txt", "unfinished\n");
  let interrupted = false;
  f.transitionBoundary((phase) => {
    if (!interrupted && phase === "event-appended") {
      interrupted = true;
      throw new Error("Interrupted publication");
    }
  });
  await assert.rejects(f.capture(), /Interrupted publication/u);
  f.transitionBoundary(() => {});
  await f.restart();
  assert.equal((await f.read()).ready, null);
  await f.capture();
  await f.restore(["first.txt"], "before");
  await f.restore(["first.txt"], "after");
  assert.equal(
    await readFile(join(f.projectPath, "first.txt"), "utf8"),
    "unfinished\n",
  );
});

test("migrates version-22 state without inventing preservation authority", async (t) => {
  const f = await fixture(t);
  await f.release();
  const legacy = structuredClone(f.created.state);
  legacy.schemaVersion = 22;
  legacy.runtimeCompatibility.runStateVersion = 22;
  delete legacy.preservationRecords;
  const eventPath = join(f.created.directoryPath, "events.jsonl");
  const event = JSON.parse(await readFile(eventPath, "utf8"));
  event.schemaVersion = 22;
  event.state = legacy;
  await writeFile(eventPath, JSON.stringify(event) + "\n");
  await writeFile(
    join(f.created.directoryPath, "state.json"),
    JSON.stringify(legacy) + "\n",
  );
  await f.restart();
  assert.deepEqual(
    (await f.store.loadRun(legacy.runId)).preservationRecords,
    [],
  );
  // Migration uses the existing leased transition and preserves pipeline progress.
  const migrated = await f.store.migrateRun(
    f.lease,
    {
      pipelineStateVersion: legacy.pipelineStateVersion,
      pipelineState: legacy.pipelineState,
    },
    {
      activity: {
        actor: "runner",
        phase: "runtime",
        kind: "migrated",
        message: "Migrated legacy preservation state.",
      },
    },
  );
  assert.equal(migrated.schemaVersion, RUN_STATE_SCHEMA_VERSION);
  assert.deepEqual(migrated.runtimeCompatibility, RUNTIME_COMPATIBILITY);
  assert.deepEqual(migrated.preservationRecords, []);
  assert.deepEqual(migrated.pipelineState, legacy.pipelineState);
});

test("rejects a changed linked-worktree pointer even when it resolves to the same controls", async (t) => {
  const f = await fixture(t, { linked: true });
  await f.write("first.txt", "unfinished\n");
  await f.capture();
  const expectedSnapshot = await f.git.snapshot({ projectPath: f.projectPath });
  const request = {
    preservationId: f.preservationId,
    operationId: randomUUID(),
    paths: ["first.txt"],
    target: "before",
    expectedSnapshot,
  };
  f.boundary(({ phase }) => {
    if (phase === "restore-intent")
      throw new Error("Interrupted pointer restore");
  });
  await assert.rejects(f.retry(request), /Interrupted pointer restore/u);
  f.boundary(() => {});
  const pointer = join(f.projectPath, ".git");
  const original = await readFile(pointer, "utf8");
  await writeFile(pointer, original.trimEnd() + "/.\n");
  assert.deepEqual(
    await f.git.snapshot({ projectPath: f.projectPath }),
    expectedSnapshot,
  );
  await assert.rejects(f.retry(request), {
    code: "ERR_GIT_PRESERVATION_CHANGED",
  });
  assert.equal(
    await readFile(join(f.projectPath, "first.txt"), "utf8"),
    "unfinished\n",
  );
});

test("rejects index drift during temporary publication before replacing workspace content", async (t) => {
  const f = await fixture(t);
  await f.write("first.txt", "unfinished\n");
  await f.capture();
  f.boundary(async ({ phase }) => {
    if (phase === "path-prepared") await f.command("add", "first.txt");
  });
  await assert.rejects(f.restore(["first.txt"], "before"), {
    code: "ERR_INTERRUPTED_REPOSITORY_CONTROL_CHANGED",
  });
  assert.equal(
    await readFile(join(f.projectPath, "first.txt"), "utf8"),
    "unfinished\n",
  );
  assert.ok((await f.read()).ready);
});

for (const path of ["new.txt", "first.txt"]) {
  test(`retains edits during the final blob read before restoring ${path}`, async (t) => {
    const f = await fixture(t);
    const unfinished = Buffer.from("unfinished\n");
    await f.write(path, unfinished);
    await f.capture();
    let changed = false;
    const git = {
      ...f.git,
      applyRestoration: (input) =>
        f.git.applyRestoration({
          ...input,
          async readBlob(entry) {
            const bytes = await input.readBlob(entry);
            if (bytes.equals(unfinished)) {
              await f.write(path, "concurrent edit\n");
              changed = true;
            }
            return bytes;
          },
        }),
    };
    await assert.rejects(f.restore([path], "before", { git }), {
      code: "ERR_GIT_PRESERVATION_CHANGED",
    });
    assert.equal(changed, true);
    assert.equal(
      await readFile(join(f.projectPath, path), "utf8"),
      "concurrent edit\n",
    );
    assert.ok((await f.read()).ready);
  });
}
