import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import filesystem, {
  access,
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
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

import { createGitService } from "../src/git/index.js";
import {
  createTrustedValidationService,
  createTrustedValidationSnapshot,
} from "../src/trusted-validation/index.js";
import { sandboxTrustedCommand } from "../src/trusted-validation/execution.js";
import { createRunStore } from "../src/state/index.js";

const hash = "a".repeat(64);
const passed = {
  status: "PASS",
  exitCode: 0,
  signal: null,
  timedOut: false,
  reason: "exit",
};

async function fixture(t, capabilities = { scratch: true, cache: true }) {
  const root = await mkdtemp(join(tmpdir(), "trusted-storage-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const projectPath = join(root, "project");
  const stateRoot = join(root, "state");
  const taskPath = join(root, "task");
  await mkdir(projectPath);
  await mkdir(taskPath);
  const store = createRunStore({ stateRoot });
  const { state, lease } = await store.createRun({
    pipelineId: "polishing",
    pipelineStateVersion: 1,
    projectPath,
    taskPath,
    roles: { worker: { backend: "codex", model: null } },
    pipelineState: { workflowState: "FINALIZE" },
  });
  t.after(() => lease.release().catch(() => {}));
  const storageRoot = join(root, "storage");
  const snapshot = createTrustedValidationSnapshot(
    {
      build: {
        command: "node build.js",
        executable: process.execPath,
        arguments: ["build.js"],
        capabilities,
      },
    },
    ["build"],
  );
  const records = [];
  let checks = 0;
  const git = {
    async snapshot() {
      return { projectPath, contentFingerprint: hash };
    },
    async assertUnchanged() {
      checks++;
    },
  };
  const onResource = async (record) => {
    if (record?.phase === "allocating")
      await assert.rejects(access(join(record.root.path, record.id)), {
        code: "ENOENT",
      });
    await store.recordExecutionResource(lease, record);
    records.push(record);
  };
  const request = {
    projectPath,
    snapshot,
    commandIdentity: snapshot.commands[0].identity,
    storageForbiddenPaths: [projectPath, stateRoot, taskPath],
    onResource,
    onProcess: async () => {},
    bindings: {
      contentFingerprint: hash,
      validationInfrastructureFingerprint: hash,
      commandFingerprint: snapshot.commandFingerprint,
      configurationFingerprint: snapshot.configurationFingerprint,
    },
  };
  const service = (options) =>
    createTrustedValidationService({
      storageRoot,
      git,
      environment: {
        HOME: root,
        PATH: "/usr/bin:/bin",
        SECRET: "private",
        HTTPS_PROXY: "untrusted",
      },
      sandboxCommand(command, options) {
        return sandboxTrustedCommand(command, {
          ...options,
          bubblewrapPath: "/usr/bin/bwrap",
        });
      },
      ...options,
    });
  return {
    root,
    projectPath,
    stateRoot,
    storageRoot,
    store,
    state,
    lease,
    records,
    request,
    service,
    git,
    checks: () => checks,
  };
}

for (const capabilities of [
  { scratch: true },
  { cache: true },
  { scratch: true, cache: true },
]) {
  test(`projects only declared transient storage: ${Object.keys(capabilities).join(", ")}`, async (t) => {
    const f = await fixture(t, capabilities);
    const service = f.service({
      async runCommand(command, { environment }) {
        const saved = await f.store.loadRun(f.state.runId);
        assert.equal(saved.executionResource.phase, "allocated");
        const base = join(f.storageRoot, saved.executionResource.id);
        assert.equal((await lstat(base)).mode & 0o777, 0o700);
        for (const name of ["scratch", "cache"]) {
          const source = join(base, name);
          if (capabilities[name]) {
            assert.equal((await lstat(source)).mode & 0o777, 0o700);
            const position = command.arguments.indexOf(source);
            assert.equal(command.arguments[position - 1], "--bind");
            assert.equal(
              command.arguments[position + 1],
              `/run/agent-runner/${name}`,
            );
            await writeFile(join(source, "output"), "transient");
          } else await assert.rejects(access(source), { code: "ENOENT" });
        }
        assert.equal(
          command.arguments.filter((value) => value === "--bind").length,
          Object.keys(capabilities).length,
        );
        assert.ok(command.arguments.includes("--unshare-net"));
        assert.ok(command.arguments.includes("--unshare-user"));
        const repository = command.arguments.indexOf(f.projectPath);
        assert.equal(command.arguments[repository - 1], "--ro-bind");
        assert.equal(environment.SECRET, undefined);
        assert.equal(environment.HTTPS_PROXY, undefined);
        assert.equal(environment.HOME, "/nonexistent");
        assert.equal(
          environment.AGENT_RUNNER_SCRATCH,
          capabilities.scratch ? "/run/agent-runner/scratch" : undefined,
        );
        assert.equal(
          environment.AGENT_RUNNER_CACHE,
          capabilities.cache ? "/run/agent-runner/cache" : undefined,
        );
        assert.equal(
          environment.TMPDIR,
          capabilities.scratch ? "/run/agent-runner/scratch" : "/tmp",
        );
        return passed;
      },
    });
    await service.preflight(f.request);
    await assert.rejects(access(f.storageRoot), { code: "ENOENT" });
    const result = await service.execute(f.request);
    assert.equal(result.status, "PASS", JSON.stringify(result));
    assert.deepEqual(
      f.records.map((record) => record?.phase ?? null),
      ["allocating", "allocated", null],
    );
    assert.deepEqual(await readdir(f.storageRoot), []);
    assert.equal(
      (await f.store.loadRun(f.state.runId)).executionResource,
      null,
    );
    assert.equal(f.checks(), 1);
    assert.doesNotMatch(
      JSON.stringify(result),
      /trusted-storage-|\/run\/agent-runner/u,
    );
  });
}

for (const outcome of ["failure", "timeout", "abort", "mutation"]) {
  test(`cleans owned storage and checks repository after ${outcome}`, async (t) => {
    const f = await fixture(t);
    const controller = new AbortController();
    const service = f.service({
      async runCommand() {
        if (outcome === "abort") {
          controller.abort(new Error("Canceled fixture"));
          throw controller.signal.reason;
        }
        if (outcome === "failure")
          return { ...passed, status: "FAIL", exitCode: 1 };
        if (outcome === "timeout")
          return {
            status: "BLOCKED",
            exitCode: null,
            signal: null,
            timedOut: true,
            reason: "timeout",
          };
        return passed;
      },
    });
    if (outcome === "mutation")
      f.git.assertUnchanged = async () => {
        throw new Error("Fixture mutation");
      };
    const executed = service.execute({
      ...f.request,
      signal: controller.signal,
    });
    if (["abort", "mutation"].includes(outcome)) await assert.rejects(executed);
    else
      assert.equal(
        (await executed).status,
        outcome === "failure" ? "FAIL" : "BLOCKED",
      );
    assert.deepEqual(await readdir(f.storageRoot), []);
    assert.equal(
      (await f.store.loadRun(f.state.runId)).executionResource,
      null,
    );
    if (outcome !== "mutation") assert.equal(f.checks(), 1);
  });
}

for (const phase of ["allocating", "allocated"]) {
  test(`recovers a journaled ${phase} allocation without launching a command`, async (t) => {
    const f = await fixture(t);
    let launches = 0;
    const service = f.service({
      async runCommand() {
        launches++;
        return passed;
      },
    });
    const interruption = new Error("Fixture publication interruption");
    await assert.rejects(
      service.execute({
        ...f.request,
        async onResource(record) {
          await f.request.onResource(record);
          if (record?.phase === phase) throw interruption;
        },
      }),
      (error) => error === interruption,
    );
    const saved = (await f.store.loadRun(f.state.runId)).executionResource;
    assert.equal(saved.phase, phase);
    assert.equal(launches, 0);
    await service.recoverResources({ ...f.request, resource: saved });
    await service.recoverResources({ ...f.request, resource: saved });
    assert.equal(
      (await f.store.loadRun(f.state.runId)).executionResource,
      null,
    );
    assert.deepEqual(await readdir(f.storageRoot), []);
  });
}

test("an unverified allocation retains evidence and is never deleted or reused", async (t) => {
  const f = await fixture(t);
  const service = f.service({
    runCommand: () => assert.fail("No launch before verified persistence"),
  });
  await assert.rejects(
    service.execute({
      ...f.request,
      async onResource(record) {
        if (record?.phase === "allocated")
          throw new Error("Interrupted before verified persistence");
        return f.request.onResource(record);
      },
    }),
  );
  const saved = (await f.store.loadRun(f.state.runId)).executionResource;
  assert.equal(saved.phase, "allocating");
  const path = join(saved.root.path, saved.id);
  await access(path);
  await assert.rejects(
    service.recoverResources({ ...f.request, resource: saved }),
    { code: "ERR_TRUSTED_VALIDATION_RESOURCE_UNVERIFIABLE" },
  );
  await access(path);
  assert.deepEqual(
    (await f.store.loadRun(f.state.runId)).executionResource,
    saved,
  );
});

for (const phase of ["allocation", "cleanup"]) {
  test(`retains storage ownership when ${phase} cannot be synchronized`, async (t) => {
    const f = await fixture(t);
    let commandRan = false;
    const service = f.service({
      async runCommand() {
        commandRan = true;
        return passed;
      },
    });
    const nativeOpen = filesystem.open;
    const mockedOpen = t.mock.method(
      filesystem,
      "open",
      async (path, ...args) => {
        const handle = await nativeOpen(path, ...args);
        if (path === f.storageRoot) {
          const nativeSync = handle.sync.bind(handle);
          t.mock.method(handle, "sync", async () => {
            if (phase === "allocation" || commandRan) {
              throw Object.assign(new Error("Storage synchronization failed"), {
                code: "EIO",
              });
            }
            await nativeSync();
          });
        }
        return handle;
      },
    );
    syncBuiltinESMExports();
    try {
      await assert.rejects(service.execute(f.request), {
        code: "ERR_TRUSTED_VALIDATION_RESOURCE_UNVERIFIABLE",
      });
    } finally {
      mockedOpen.mock.restore();
      syncBuiltinESMExports();
    }
    assert.equal(commandRan, phase === "cleanup");
    const saved = (await f.store.loadRun(f.state.runId)).executionResource;
    assert.equal(
      saved.phase,
      phase === "allocation" ? "allocating" : "allocated",
    );
    if (phase === "allocation") {
      await access(join(saved.root.path, saved.id));
      await assert.rejects(
        service.recoverResources({ ...f.request, resource: saved }),
        { code: "ERR_TRUSTED_VALIDATION_RESOURCE_UNVERIFIABLE" },
      );
    } else {
      assert.deepEqual(await readdir(f.storageRoot), []);
      await service.recoverResources({ ...f.request, resource: saved });
      assert.equal(
        (await f.store.loadRun(f.state.runId)).executionResource,
        null,
      );
    }
  });
}

test("cleanup removes internal symlinks without following them", async (t) => {
  const f = await fixture(t);
  const outside = join(f.root, "outside");
  await mkdir(outside);
  await writeFile(join(outside, "keep"), "safe");
  const service = f.service({
    async runCommand() {
      const record = (await f.store.loadRun(f.state.runId)).executionResource;
      await symlink(
        outside,
        join(record.root.path, record.id, "scratch", "link"),
      );
      return passed;
    },
  });
  await service.execute(f.request);
  assert.equal(await readFile(join(outside, "keep"), "utf8"), "safe");
});

test("recovery rejects replacement of the owned directory by a symlink", async (t) => {
  const f = await fixture(t);
  const service = f.service({ runCommand: () => assert.fail("No launch") });
  await assert.rejects(
    service.execute({
      ...f.request,
      async onResource(record) {
        await f.request.onResource(record);
        if (record?.phase === "allocated") throw new Error("Interrupted");
      },
    }),
  );
  const saved = (await f.store.loadRun(f.state.runId)).executionResource;
  const path = join(saved.root.path, saved.id);
  await rename(path, `${path}-original`);
  await symlink(f.projectPath, path);
  await assert.rejects(
    service.recoverResources({ ...f.request, resource: saved }),
    { code: "ERR_TRUSTED_VALIDATION_RESOURCE_UNVERIFIABLE" },
  );
  assert.ok((await lstat(path)).isSymbolicLink());
  assert.deepEqual(
    (await f.store.loadRun(f.state.runId)).executionResource,
    saved,
  );
});

test("storage roots cannot overlap protected paths or use permissive ownership", async (t) => {
  const f = await fixture(t);
  for (const storageRoot of [
    f.projectPath,
    join(f.projectPath, "scratch"),
    f.stateRoot,
    f.root,
  ]) {
    await assert.rejects(f.service({ storageRoot }).preflight(f.request), {
      code: "ERR_TRUSTED_VALIDATION_CAPABILITY_UNAVAILABLE",
    });
  }
  await mkdir(f.storageRoot, { mode: 0o755 });
  await chmod(f.storageRoot, 0o755);
  await assert.rejects(f.service().preflight(f.request), {
    code: "ERR_TRUSTED_VALIDATION_CAPABILITY_UNAVAILABLE",
  });
});

test("storage remains owned until registered processes retire", async (t) => {
  const f = await fixture(t);
  const service = f.service({
    async runCommand(_command, { onProcess }) {
      await onProcess(process.pid);
      const current = await f.store.loadRun(f.state.runId);
      await assert.rejects(f.store.recordExecutionResource(f.lease, null), {
        code: "ERR_EXECUTION_RESOURCE_ACTIVE",
      });
      await access(
        join(current.executionResource.root.path, current.executionResource.id),
      );
      await onProcess(null);
      return passed;
    },
  });
  const result = await service.execute({
    ...f.request,
    onProcess: (pid, proof) =>
      f.store.recordExecutionProcess(f.lease, pid, proof),
  });
  assert.equal(result.status, "PASS", JSON.stringify(result));
  assert.equal((await f.store.loadRun(f.state.runId)).executionResource, null);
});

test("allocation rejects a parent symlink replacement without writing outside owned storage", async (t) => {
  const f = await fixture(t);
  const outside = join(f.root, "outside");
  await mkdir(outside, { mode: 0o700 });
  const service = f.service({
    runCommand: () => assert.fail("No command after root replacement"),
  });
  await assert.rejects(
    service.execute({
      ...f.request,
      async onResource(record) {
        await f.request.onResource(record);
        if (record?.phase === "allocating") {
          await rename(f.storageRoot, `${f.storageRoot}-original`);
          await symlink(outside, f.storageRoot);
        }
      },
    }),
    { code: "ERR_TRUSTED_VALIDATION_RESOURCE_UNVERIFIABLE" },
  );
  assert.deepEqual(await readdir(outside), []);
  assert.equal(
    (await f.store.loadRun(f.state.runId)).executionResource.phase,
    "allocating",
  );
});

test("native storage sandbox confines builds and fails closed when namespaces are denied", async (t) => {
  const f = await fixture(t);
  const executeFile = promisify(execFile);
  // Probe namespace availability independently of the executor under test.
  // Only the system runtime is exposed, read-only; no project or host temp
  // storage is mounted and the probe has its own network namespace.
  let namespacesAvailable = true;
  try {
    await executeFile(
      "/usr/bin/bwrap",
      [
        "--unshare-user",
        "--unshare-pid",
        "--unshare-net",
        "--cap-drop",
        "ALL",
        ...["/usr", "/bin", "/lib", "/lib64"]
          .filter((path) => existsSync(path))
          .flatMap((path) => ["--ro-bind", path, path]),
        "--",
        "/bin/true",
      ],
      { timeout: 10_000, env: { LC_ALL: "C" } },
    );
  } catch (cause) {
    assert.equal(cause.code, 1);
    assert.match(
      cause.stderr,
      /bwrap: (?:No permissions to create a new namespace|Creating new namespace failed: Operation not permitted)/u,
    );
    namespacesAvailable = false;
  }
  for (const args of [
    ["init", "-q"],
    ["config", "user.name", "Test"],
    ["config", "user.email", "test@example.com"],
  ])
    await executeFile("git", ["-C", f.projectPath, ...args]);
  await writeFile(join(f.projectPath, "source.txt"), "protected");
  await executeFile("git", ["-C", f.projectPath, "add", "."]);
  await executeFile("git", [
    "-C",
    f.projectPath,
    "commit",
    "-qm",
    "test: fixture",
  ]);
  const script = `const fs = require('node:fs'); const assert = require('node:assert/strict');
fs.writeFileSync(process.env.AGENT_RUNNER_SCRATCH + '/build', 'output');
fs.writeFileSync(process.env.AGENT_RUNNER_CACHE + '/cache', 'cached');
assert.throws(() => fs.writeFileSync('source.txt', 'changed'));
assert.throws(() => fs.writeFileSync(${JSON.stringify(join(f.stateRoot, "host-write"))}, 'forbidden'));
assert.throws(() => fs.writeFileSync('/etc/agent-runner-write', 'forbidden'));`;
  const snapshot = createTrustedValidationSnapshot(
    {
      build: {
        command: "node offline-build",
        executable: process.execPath,
        arguments: ["--eval", script],
        capabilities: { scratch: true, cache: true },
      },
    },
    ["build"],
  );
  const git = createGitService();
  const before = await git.snapshot({ projectPath: f.projectPath });
  // Keep the fixture's fixed native launcher: an enclosing sandbox can have a
  // writable root, which production host-path discovery correctly rejects.
  const service = f.service({ git });
  const result = await service.execute({
    ...f.request,
    snapshot,
    commandIdentity: snapshot.commands[0].identity,
    onProcess: (pid, proof) =>
      f.store.recordExecutionProcess(f.lease, pid, proof),
    bindings: {
      ...f.request.bindings,
      contentFingerprint: before.contentFingerprint,
      commandFingerprint: snapshot.commandFingerprint,
      configurationFingerprint: snapshot.configurationFingerprint,
    },
  });
  assert.equal(
    result.status,
    namespacesAvailable ? "PASS" : "BLOCKED",
    JSON.stringify(result),
  );
  if (!namespacesAvailable) {
    assert.equal(result.exitCode, null);
    assert.deepEqual(result.evidence, [
      "Runner-trusted command build could not start in the required isolated executor.",
    ]);
  }
  assert.equal(
    await readFile(join(f.projectPath, "source.txt"), "utf8"),
    "protected",
  );
  await assert.rejects(access(join(f.stateRoot, "host-write")), {
    code: "ENOENT",
  });
  assert.deepEqual(await readdir(f.storageRoot), []);
  assert.equal((await f.store.loadRun(f.state.runId)).executionResource, null);
  assert.equal((await f.store.loadRun(f.state.runId)).executionProcess, null);
});

test("storage cannot launch without both durable ownership callbacks", async (t) => {
  const f = await fixture(t);
  const service = f.service({
    runCommand: () => assert.fail("Unowned launch"),
  });
  for (const field of ["onProcess", "onResource"]) {
    await assert.rejects(
      service.execute({ ...f.request, [field]: undefined }),
      {
        code: "ERR_TRUSTED_VALIDATION_RESOURCE_UNVERIFIABLE",
      },
    );
  }
  await assert.rejects(access(f.storageRoot), { code: "ENOENT" });
  assert.equal((await f.store.loadRun(f.state.runId)).executionResource, null);
});

test("unverified process retirement retains storage until recovery", async (t) => {
  const f = await fixture(t);
  const service = f.service({
    async runCommand(_command, { onProcess }) {
      await onProcess(process.pid);
      return passed;
    },
  });
  await assert.rejects(
    service.execute({
      ...f.request,
      onProcess: (pid, proof) =>
        f.store.recordExecutionProcess(f.lease, pid, proof),
    }),
    { code: "ERR_EXECUTION_PROCESS_ACTIVE" },
  );
  const saved = await f.store.loadRun(f.state.runId);
  assert.equal(saved.executionResource.phase, "allocated");
  await access(
    join(saved.executionResource.root.path, saved.executionResource.id),
  );
  assert.equal(f.checks(), 0);
  // The fake executor has no descendants; explicitly clear its test registration.
  await f.store.recordExecutionProcess(f.lease, null);
  await service.recoverResources({
    ...f.request,
    resource: saved.executionResource,
  });
  assert.deepEqual(await readdir(f.storageRoot), []);
});

test("preflight rejects protected paths overlapping declared fixed storage mounts", async (t) => {
  const f = await fixture(t);
  const service = f.service({
    runCommand: () => assert.fail("No launch during preflight"),
  });
  for (const path of [
    "/run/agent-runner",
    "/run/agent-runner/scratch",
    "/run/agent-runner/cache/repository",
  ]) {
    await assert.rejects(
      service.preflight({ ...f.request, projectPath: path }),
      {
        code: "ERR_TRUSTED_VALIDATION_CAPABILITY_UNAVAILABLE",
      },
    );
    await assert.rejects(
      service.preflight({ ...f.request, storageForbiddenPaths: [path] }),
      {
        code: "ERR_TRUSTED_VALIDATION_CAPABILITY_UNAVAILABLE",
      },
    );
  }
  // An undeclared mount does not shadow the repository.
  const cache = await fixture(t, { cache: true });
  await cache.service().preflight({
    ...cache.request,
    projectPath: "/run/agent-runner/scratch/repository",
  });
  await assert.rejects(access(f.storageRoot), { code: "ENOENT" });
  await assert.rejects(access(cache.storageRoot), { code: "ENOENT" });
});

test("preflight rejects an existing read-only storage root before allocation", async (t) => {
  const f = await fixture(t);
  await mkdir(f.storageRoot, { mode: 0o700 });
  const nativeAccess = filesystem.access;
  const mockedAccess = t.mock.method(
    filesystem,
    "access",
    async (path, mode) => {
      if (path === f.storageRoot)
        throw Object.assign(new Error("Read-only fixture mount"), {
          code: "EROFS",
        });
      return nativeAccess(path, mode);
    },
  );
  syncBuiltinESMExports();
  try {
    await assert.rejects(f.service().preflight(f.request), {
      code: "ERR_TRUSTED_VALIDATION_CAPABILITY_UNAVAILABLE",
    });
    assert.deepEqual(f.records, []);
    assert.deepEqual(await readdir(f.storageRoot), []);
  } finally {
    mockedAccess.mock.restore();
    syncBuiltinESMExports();
  }
  await f.service().preflight(f.request);
});

for (const kind of [
  "directory symlink",
  "gitdir pointer",
  "shared directory",
]) {
  test(`preflight protects Git metadata through a ${kind}`, async (t) => {
    const f = await fixture(t);
    await mkdir(f.storageRoot, { mode: 0o700 });
    await writeFile(join(f.storageRoot, "keep"), "Git metadata");
    const dotGit = join(f.projectPath, ".git");
    if (kind === "directory symlink") {
      await symlink(f.storageRoot, dotGit);
    } else if (kind === "gitdir pointer") {
      await writeFile(dotGit, `gitdir: ${f.storageRoot}\n`);
    } else {
      await mkdir(dotGit);
      await writeFile(join(dotGit, "commondir"), `${f.storageRoot}\n`);
    }
    const service = f.service({
      runCommand: () => assert.fail("No launch with overlapping Git storage"),
    });
    await assert.rejects(service.preflight(f.request), {
      code: "ERR_TRUSTED_VALIDATION_CAPABILITY_UNAVAILABLE",
    });
    const result = await service.execute(f.request);
    assert.equal(result.status, "BLOCKED");
    assert.deepEqual(f.records, []);
    assert.deepEqual(await readdir(f.storageRoot), ["keep"]);
    assert.equal(
      await readFile(join(f.storageRoot, "keep"), "utf8"),
      "Git metadata",
    );
  });
}
