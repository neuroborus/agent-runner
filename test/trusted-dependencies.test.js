import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import {
  access,
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
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import test from "node:test";
import { promisify } from "node:util";

import { createGitService } from "../src/git/index.js";
import { createRunStore } from "../src/state/index.js";
import {
  createTrustedValidationService,
  createTrustedValidationSnapshot,
} from "../src/trusted-validation/index.js";
import { sandboxTrustedCommand } from "../src/trusted-validation/execution.js";

const body = "verified dependency";
const hash = createHash("sha256").update(body).digest("hex");
const artifact = { url: "https://downloads.example.com/file", sha256: hash };
const passed = {
  status: "PASS",
  exitCode: 0,
  signal: null,
  timedOut: false,
  reason: "exit",
};
const ownershipError = { code: "ERR_TRUSTED_VALIDATION_RESOURCE_UNVERIFIABLE" };

async function fixture(
  t,
  { capabilities = { artifacts: [artifact] }, ...transport } = {},
) {
  const root = await mkdtemp(join(tmpdir(), "trusted-dependencies-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const projectPath = join(root, "project");
  const taskPath = join(root, "task");
  const stateRoot = join(root, "state");
  const storageRoot = join(root, "storage");
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
  const snapshot = createTrustedValidationSnapshot(
    {
      build: {
        command: "node offline-build",
        executable: process.execPath,
        arguments: ["--eval", ""],
        capabilities,
      },
    },
    ["build"],
  );
  const records = [];
  const events = [];
  const timers = new Map();
  const sockets = [];
  const started = Promise.withResolvers();
  let downloads = 0;
  let launches = 0;
  const saved = async () =>
    (await store.loadRun(state.runId)).executionResource;
  const request = {
    projectPath,
    snapshot,
    commandIdentity: snapshot.commands[0].identity,
    storageForbiddenPaths: [stateRoot, taskPath],
    bindings: {
      contentFingerprint: hash,
      validationInfrastructureFingerprint: hash,
      commandFingerprint: snapshot.commandFingerprint,
      configurationFingerprint: snapshot.configurationFingerprint,
    },
    async onResource(record) {
      await store.recordExecutionResource(lease, record);
      records.push(record);
      events.push(record?.phase ?? "cleaned");
    },
    onProcess: (pid, proof) => store.recordExecutionProcess(lease, pid, proof),
  };
  const acquisition = {
    schedule(callback, ms) {
      const token = {};
      timers.set(token, { callback, ms });
      return () => timers.delete(token);
    },
    async lookup() {
      downloads++;
      const record = await saved();
      assert.equal(record.phase, "acquiring");
      assert.equal(record.owner.pid, process.pid);
      assert.equal(record.commandIdentity, snapshot.commands[0].identity);
      assert.equal(launches, 0);
      events.push("download");
      await transport.beforeLookup?.(record);
      if (transport.dnsError)
        throw new Error("private URL and resolver details");
      return [{ address: "8.8.8.8", family: 4 }];
    },
    request(_settings, reply) {
      const resource = () => {
        const value = new EventEmitter();
        value.destroy = () => {
          if (!transport.stuck)
            queueMicrotask(() => {
              value.closed = true;
              value.emit("close");
            });
          return value;
        };
        sockets.push(value);
        return value;
      };
      const req = resource();
      req.end = () =>
        queueMicrotask(() => {
          const socket = resource();
          Object.assign(socket, {
            encrypted: true,
            authorized: true,
            remotePort: 443,
            remoteAddress: "8.8.8.8",
          });
          req.emit("socket", socket);
          socket.emit("secureConnect");
          const response = new PassThrough();
          Object.assign(response, {
            statusCode: transport.status ?? 200,
            headers: {},
            rawHeaders: [],
            complete: true,
          });
          reply(response);
          if (transport.pending) response.write("partial");
          else response.end(transport.body ?? body);
          started.resolve();
        });
      return req;
    },
  };
  const service = (options = {}) =>
    createTrustedValidationService({
      storageRoot,
      acquisition,
      git: {
        async snapshot() {
          return { projectPath, contentFingerprint: hash };
        },
        async assertUnchanged() {},
      },
      environment: {
        HOME: root,
        PATH: "/usr/bin:/bin",
        AGENT_RUNNER_DEPENDENCIES: "/untrusted",
        HTTPS_PROXY: "private",
      },
      sandboxCommand(command, settings) {
        return sandboxTrustedCommand(command, {
          ...settings,
          bubblewrapPath: "/usr/bin/bwrap",
        });
      },
      async runCommand() {
        launches++;
        return passed;
      },
      ...options,
    });
  return {
    root,
    projectPath,
    storageRoot,
    store,
    runId: state.runId,
    lease,
    request,
    service,
    saved,
    records,
    events,
    timers,
    sockets,
    started,
    downloads: () => downloads,
    launches: () => launches,
    repair() {
      Object.assign(transport, {
        dnsError: false,
        status: 200,
        body,
        pending: false,
      });
    },
  };
}

test("requirement inspection acquires frozen dependencies without executing the check and finalization reverifies", async (t) => {
  const f = await fixture(t);
  const vectors = [];
  const service = f.service({
    async runCommand(command) {
      vectors.push(command.arguments.slice(-3));
      return passed;
    },
  });
  const input = {
    ...f.request,
    inventory: [f.request.snapshot.commands[0].command],
  };
  assert.deepEqual(await service.inspectRequirements(input), {
    status: "READY",
    blockers: [],
  });
  assert.deepEqual(vectors, [[process.execPath, "--eval", ""]]);
  assert.equal(f.downloads(), 1);
  assert.equal(await f.saved(), null);
  assert.deepEqual(await readdir(f.storageRoot), []);
  assert.equal((await service.execute(f.request)).status, "PASS");
  assert.equal(f.downloads(), 2);
  assert.equal(await f.saved(), null);
  const allocations = f.records.filter(
    (record) => record?.phase === "allocating",
  );
  assert.notEqual(allocations[0].id, allocations[1].id);
});

test("unavailable dependencies block inspection with redacted evidence and retry the saved request", async (t) => {
  const f = await fixture(t, { dnsError: true });
  const service = f.service();
  const input = {
    ...f.request,
    inventory: [f.request.snapshot.commands[0].command],
  };
  const before = JSON.stringify(input.snapshot);
  const result = await service.inspectRequirements(input);
  assert.equal(result.status, "BLOCKED");
  assert.equal(result.blockers[0].reason, "unavailable");
  assert.ok(!JSON.stringify(result).includes("private URL"));
  assert.equal(f.launches(), 0);
  assert.equal(await f.saved(), null);
  f.repair();
  assert.equal((await service.inspectRequirements(input)).status, "READY");
  assert.equal(JSON.stringify(input.snapshot), before);
  assert.equal(f.downloads(), 2);
  assert.equal(await f.saved(), null);
});

test("inspection cancellation retires acquisition and clears durable ownership", async (t) => {
  const f = await fixture(t, { pending: true });
  const controller = new AbortController();
  const inspecting = f.service().inspectRequirements({
    ...f.request,
    inventory: [f.request.snapshot.commands[0].command],
    signal: controller.signal,
  });
  await f.started.promise;
  controller.abort();
  await assert.rejects(inspecting, { name: "AbortError" });
  assert.equal(f.launches(), 0);
  assert.equal(await f.saved(), null);
  assert.ok(f.sockets.every((socket) => socket.closed));
});

for (const scratch of [false, true]) {
  test(`verified dependency mount is read-only and artifact-only allocation works (scratch=${scratch})`, async (t) => {
    const f = await fixture(t, {
      capabilities: {
        artifacts: [artifact],
        ...(scratch ? { scratch: true, cache: true } : {}),
      },
    });
    const service = f.service({
      async runCommand(command, { environment }) {
        const record = await f.saved();
        const directory = join(f.storageRoot, record.id, "dependencies");
        assert.deepEqual(await readdir(directory), [hash]);
        assert.equal(await readFile(join(directory, hash), "utf8"), body);
        assert.equal((await lstat(join(directory, hash))).mode & 0o777, 0o444);
        const at = command.arguments.indexOf(directory);
        assert.equal(command.arguments[at - 1], "--ro-bind");
        assert.equal(
          command.arguments[at + 1],
          "/run/agent-runner/dependencies",
        );
        assert.ok(command.arguments.includes("--unshare-net"));
        assert.equal(
          environment.AGENT_RUNNER_DEPENDENCIES,
          "/run/agent-runner/dependencies",
        );
        assert.equal(environment.HTTPS_PROXY, undefined);
        assert.equal(
          environment.AGENT_RUNNER_SCRATCH,
          scratch ? "/run/agent-runner/scratch" : undefined,
        );
        assert.equal(command.arguments.includes(f.storageRoot), false);
        assert.deepEqual(f.events, [
          "allocating",
          "allocated",
          "acquiring",
          "download",
          "allocated",
        ]);
        assert.ok(f.sockets.every((socket) => socket.closed));
        return passed;
      },
    });
    await service.preflight(f.request);
    assert.equal(f.downloads(), 0);
    await assert.rejects(access(f.storageRoot), { code: "ENOENT" });
    assert.equal((await service.execute(f.request)).status, "PASS");
    assert.equal(await f.saved(), null);
    assert.deepEqual(await readdir(f.storageRoot), []);
    assert.equal(f.timers.size, 0);
  });
}

for (const transport of [
  { dnsError: true },
  { status: 302 },
  { body: "wrong digest" },
]) {
  test(`acquisition failure blocks command execution and cleans storage: ${JSON.stringify(transport)}`, async (t) => {
    const f = await fixture(t, transport);
    const result = await f.service().execute(f.request);
    assert.equal(result.status, "BLOCKED");
    assert.equal(result.exitCode, null);
    assert.match(
      result.evidence[0],
      /could not acquire its verified dependencies/u,
    );
    assert.doesNotMatch(
      JSON.stringify(result),
      /downloads\.example|private|trusted-dependencies-/u,
    );
    assert.equal(f.launches(), 0);
    assert.equal(await f.saved(), null);
    assert.deepEqual(await readdir(f.storageRoot), []);
    // Repair retries the frozen request with a fresh allocation and acquisition.
    f.repair();
    assert.equal((await f.service().execute(f.request)).status, "PASS");
    assert.equal(f.downloads(), 2);
    assert.equal(
      new Set(f.records.filter(Boolean).map(({ id }) => id)).size,
      2,
    );
  });
}

for (const phase of ["allocating", "allocated", "acquiring"]) {
  test(`interruption after ${phase} journal publication recovers before any download or process registration`, async (t) => {
    const f = await fixture(t);
    const service = f.service();
    const interruption = new Error("journal interruption");
    await assert.rejects(
      service.execute({
        ...f.request,
        async onResource(record) {
          await f.request.onResource(record);
          if (record?.phase === phase) throw interruption;
        },
      }),
      (cause) =>
        cause.code === ownershipError.code && cause.cause === interruption,
    );
    assert.equal(f.downloads(), 0);
    assert.equal(f.launches(), 0);
    const resource = await f.saved();
    await service.recoverResources({ ...f.request, resource });
    if (phase !== "acquiring")
      await service.recoverResources({ ...f.request, resource });
    assert.equal(await f.saved(), null);
    assert.equal((await service.execute(f.request)).status, "PASS");
    assert.equal(f.downloads(), 1);
  });
}

test("failed ownership publication never downloads and retains uncertain allocation", async (t) => {
  const f = await fixture(t);
  const service = f.service();
  await assert.rejects(
    service.execute({
      ...f.request,
      async onResource(record) {
        if (record?.phase === "allocated")
          throw new Error("journal unavailable");
        await f.request.onResource(record);
      },
    }),
  );
  const resource = await f.saved();
  assert.equal(resource.phase, "allocating");
  assert.equal(f.downloads(), 0);
  await assert.rejects(
    service.recoverResources({ ...f.request, resource }),
    ownershipError,
  );
  await access(join(f.storageRoot, resource.id));
});

for (const cancel of [false, true]) {
  test(`partial acquisition ${cancel ? "cancellation" : "deadline"} never launches or reuses a partial`, async (t) => {
    const f = await fixture(t, { pending: true });
    const controller = new AbortController();
    const service = f.service();
    const result = service.execute({ ...f.request, signal: controller.signal });
    await f.started.promise;
    const directory = join(f.storageRoot, (await f.saved()).id, "dependencies");
    assert.ok(
      (await readdir(directory)).every((name) => name.startsWith(".partial-")),
    );
    const cancellation = new Error("cancel fixture");
    if (cancel) controller.abort(cancellation);
    else [...f.timers.values()].find(({ ms }) => ms === 300_000).callback();
    if (cancel) await assert.rejects(result, (cause) => cause === cancellation);
    else assert.equal((await result).status, "BLOCKED");
    assert.equal(f.launches(), 0);
    assert.equal(await f.saved(), null);
    assert.deepEqual(await readdir(f.storageRoot), []);
    assert.ok(f.sockets.every((socket) => socket.closed));
  });
}

test(
  "unretired transports retain ownership and block recovery until closure",
  { timeout: 5_000 },
  async (t) => {
    const f = await fixture(t, { stuck: true });
    const service = f.service();
    const result = service.execute(f.request);
    await f.started.promise;
    // Allow stream hashing and asynchronous file writes to reach retirement.
    while (![...f.timers.values()].some(({ ms }) => ms === 1_000))
      await new Promise((resolve) => setImmediate(resolve));
    [...f.timers.values()].find(({ ms }) => ms === 1_000).callback();
    await assert.rejects(result, ownershipError);
    const resource = await f.saved();
    const directory = join(f.storageRoot, resource.id, "dependencies");
    assert.ok(
      (await readdir(directory)).some((name) => name.startsWith(".partial-")),
    );
    assert.equal(f.launches(), 0);
    await assert.rejects(
      service.recoverResources({ ...f.request, resource }),
      ownershipError,
    );
    await assert.rejects(
      f.service().recoverResources({ ...f.request, resource }),
      ownershipError,
    );
    for (const socket of f.sockets) {
      socket.closed = true;
      socket.emit("close");
    }
    await new Promise((resolve) => setImmediate(resolve));
    await service.recoverResources({ ...f.request, resource });
    assert.equal(await f.saved(), null);
  },
);

for (const substitute of ["root", "allocation", "dependencies"]) {
  test(`directory substitution during acquisition fails closed: ${substitute}`, async (t) => {
    let f;
    let original;
    let path;
    f = await fixture(t, {
      async beforeLookup(record) {
        path =
          substitute === "root"
            ? f.storageRoot
            : join(
                f.storageRoot,
                record.id,
                ...(substitute === "dependencies" ? ["dependencies"] : []),
              );
        original = `${path}-original`;
        await rename(path, original);
        await symlink(f.projectPath, path);
      },
    });
    await writeFile(join(f.projectPath, "keep"), "protected");
    const service = f.service();
    await assert.rejects(service.execute(f.request), ownershipError);
    assert.equal(f.launches(), 0);
    assert.deepEqual(await readdir(f.projectPath), ["keep"]);
    const resource = await f.saved();
    if (resource !== null) {
      await rm(path);
      await rename(original, path);
      await service.recoverResources({ ...f.request, resource });
    }
    assert.equal(await f.saved(), null);
  });
}

test("cleanup publication failure retries idempotently after removal", async (t) => {
  const f = await fixture(t);
  const service = f.service();
  await assert.rejects(
    service.execute({
      ...f.request,
      async onResource(record) {
        if (record === null)
          throw new Error("journal unavailable after deletion");
        await f.request.onResource(record);
      },
    }),
    ownershipError,
  );
  assert.equal(f.launches(), 1);
  const resource = await f.saved();
  assert.equal(resource.phase, "allocated");
  assert.deepEqual(await readdir(f.storageRoot), []);
  await service.recoverResources({ ...f.request, resource });
  assert.equal(await f.saved(), null);
});

test("artifact storage protects fixed mounts, private paths, and durable ownership callbacks", async (t) => {
  const f = await fixture(t);
  const service = f.service();
  for (const path of [
    "/run/agent-runner/dependencies",
    "/run/agent-runner/dependencies/repo",
    f.storageRoot,
  ]) {
    await assert.rejects(
      service.preflight({ ...f.request, storageForbiddenPaths: [path] }),
      { code: "ERR_TRUSTED_VALIDATION_CAPABILITY_UNAVAILABLE" },
    );
  }
  for (const name of ["onResource", "onProcess"])
    await assert.rejects(
      service.execute({ ...f.request, [name]: undefined }),
      ownershipError,
    );
  assert.equal(f.downloads(), 0);
  assert.deepEqual(f.records, []);
});

test("private storage cannot leak through PATH exposures", async (t) => {
  const f = await fixture(t);
  const service = f.service({
    environment: { HOME: "/nonexistent", PATH: `${f.root}:/usr/bin` },
  });
  await assert.rejects(service.preflight(f.request), {
    code: "ERR_TRUSTED_VALIDATION_CAPABILITY_UNAVAILABLE",
  });
  assert.equal(f.downloads(), 0);
  const result = await service.execute(f.request);
  assert.equal(result.status, "BLOCKED");
  assert.equal(f.launches(), 0);
  assert.equal(await f.saved(), null);
});

for (const outcome of ["failure", "timeout", "abort"]) {
  test(`verified dependencies are cleaned after command ${outcome}`, async (t) => {
    const f = await fixture(t);
    const controller = new AbortController();
    const service = f.service({
      async runCommand() {
        assert.equal(f.downloads(), 1);
        if (outcome === "abort") {
          controller.abort(new Error("cancel command"));
          throw controller.signal.reason;
        }
        return outcome === "failure"
          ? { ...passed, status: "FAIL", exitCode: 1 }
          : {
              ...passed,
              status: "BLOCKED",
              exitCode: null,
              timedOut: true,
              reason: "timeout",
            };
      },
    });
    const result = service.execute({ ...f.request, signal: controller.signal });
    if (outcome === "abort")
      await assert.rejects(
        result,
        (cause) => cause === controller.signal.reason,
      );
    else
      assert.equal(
        (await result).status,
        outcome === "failure" ? "FAIL" : "BLOCKED",
      );
    assert.equal(await f.saved(), null);
    assert.deepEqual(await readdir(f.storageRoot), []);
  });
}

test("an active command retains dependencies until process recovery", async (t) => {
  const f = await fixture(t);
  const service = f.service({
    async runCommand(_command, { onProcess }) {
      await onProcess(process.pid);
      return passed;
    },
  });
  await assert.rejects(service.execute(f.request), {
    code: "ERR_EXECUTION_PROCESS_ACTIVE",
  });
  const resource = await f.saved();
  assert.equal(
    await readFile(
      join(f.storageRoot, resource.id, "dependencies", hash),
      "utf8",
    ),
    body,
  );
  // Retire the fake process registration; no real command process was launched.
  await f.store.recordExecutionProcess(f.lease, null);
  await service.recoverResources({ ...f.request, resource });
  assert.equal(await f.saved(), null);
});

test("dependency acquisition preserves temporary repository content and Git controls", async (t) => {
  const f = await fixture(t);
  const runGit = async (...args) =>
    promisify(execFile)("git", ["-C", f.projectPath, ...args]);
  await runGit("init", "-q");
  await runGit("config", "user.name", "Fixture");
  await runGit("config", "user.email", "fixture@example.com");
  await writeFile(join(f.projectPath, "source.txt"), "protected source");
  await runGit("add", "source.txt");
  await runGit("commit", "-qm", "test: fixture");
  const git = createGitService();
  const before = await git.snapshot({ projectPath: f.projectPath });
  const result = await f.service({ git }).execute({
    ...f.request,
    bindings: {
      ...f.request.bindings,
      contentFingerprint: before.contentFingerprint,
    },
  });
  assert.equal(result.status, "PASS");
  await git.assertUnchanged(before);
  assert.equal(
    await readFile(join(f.projectPath, "source.txt"), "utf8"),
    "protected source",
  );
  assert.equal(await f.saved(), null);
});

test("interruption after verified download and before process registration recovers without reuse", async (t) => {
  const f = await fixture(t);
  const service = f.service({
    async runCommand(_command, { onProcess }) {
      await onProcess(process.pid);
      assert.fail("Registration must fail before the fake process launches");
    },
  });
  await assert.rejects(
    service.execute({
      ...f.request,
      async onProcess() {
        throw Object.assign(new Error("interrupted registration"), {
          code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
        });
      },
    }),
    { code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE" },
  );
  const resource = await f.saved();
  assert.equal((await f.store.loadRun(f.runId)).executionProcess, null);
  assert.equal(
    await readFile(
      join(f.storageRoot, resource.id, "dependencies", hash),
      "utf8",
    ),
    body,
  );
  // Reconstruct the service as resume would; the fake executor started no process.
  const resumed = f.service();
  await resumed.recoverResources({ ...f.request, resource });
  assert.equal((await resumed.execute(f.request)).status, "PASS");
  assert.equal(f.downloads(), 2);
  assert.equal(new Set(f.records.filter(Boolean).map(({ id }) => id)).size, 2);
  assert.equal(await f.saved(), null);
});

test("recovery verifies the journaled acquisition owner even after service reconstruction", async (t) => {
  const f = await fixture(t);
  const exited = promisify(execFile)(process.execPath, ["--eval", ""], {
    timeout: 5_000,
  });
  const deadPid = exited.child.pid;
  await exited;
  await assert.rejects(
    f.service().execute({
      ...f.request,
      async onResource(record) {
        if (record?.phase === "acquiring") {
          // Model a runner that persisted acquisition intent and then exited.
          await f.request.onResource({
            ...record,
            owner: { ...record.owner, pid: deadPid },
          });
          throw new Error("owner exited before download");
        }
        await f.request.onResource(record);
      },
    }),
    (cause) => {
      assert.equal(cause.code, ownershipError.code);
      assert.equal(cause.cause.message, "owner exited before download");
      return true;
    },
  );
  const resource = await f.saved();
  assert.equal(resource.phase, "acquiring");
  assert.equal(f.downloads(), 0);
  await f.service().recoverResources({ ...f.request, resource });
  assert.equal(await f.saved(), null);
});

test("acquisition journal rejects malformed owners and identity-changing settlement", async (t) => {
  const f = await fixture(t, {
    beforeLookup: async (resource) => {
      await assert.rejects(
        f.store.recordExecutionResource(f.lease, {
          ...resource,
          owner: { ...resource.owner, pid: 0 },
        }),
      );
      const { owner, ...allocated } = resource;
      await assert.rejects(
        f.store.recordExecutionResource(f.lease, {
          ...allocated,
          phase: "allocated",
          commandIdentity: "b".repeat(64),
        }),
        { code: "ERR_EXECUTION_RESOURCE_ACTIVE" },
      );
    },
  });
  assert.equal((await f.service().execute(f.request)).status, "PASS");
});

test("failure after an earlier verified file never exposes an incomplete dependency set", async (t) => {
  let f;
  let attempts = 0;
  f = await fixture(t, {
    capabilities: {
      artifacts: [
        artifact,
        { ...artifact, url: "https://downloads.example.com/second" },
      ],
    },
    async beforeLookup(record) {
      if (++attempts === 2) {
        assert.equal(
          await readFile(
            join(f.storageRoot, record.id, "dependencies", hash),
            "utf8",
          ),
          body,
        );
        throw new Error("second artifact unavailable");
      }
    },
  });
  assert.equal((await f.service().execute(f.request)).status, "BLOCKED");
  assert.equal(f.launches(), 0);
  assert.equal(await f.saved(), null);
  assert.deepEqual(await readdir(f.storageRoot), []);
});

for (const published of [false, true]) {
  test(`acquisition settlement journal failure remains a resumable ownership blocker (published=${published})`, async (t) => {
    const f = await fixture(t);
    const service = f.service();
    let allocations = 0;
    await assert.rejects(
      service.execute({
        ...f.request,
        async onResource(record) {
          if (record?.phase === "allocated" && ++allocations === 2) {
            if (published) await f.request.onResource(record);
            throw new Error("private journal failure");
          }
          await f.request.onResource(record);
        },
      }),
      ownershipError,
    );
    assert.equal(f.launches(), 0);
    const resource = await f.saved();
    assert.equal(resource.phase, published ? "allocated" : "acquiring");
    await access(join(f.storageRoot, resource.id));
    if (!published) {
      await assert.rejects(
        service.recoverResources({
          ...f.request,
          resource,
          async onResource() {
            throw new Error("retry journal failure");
          },
        }),
        ownershipError,
      );
      assert.equal((await f.saved()).phase, "acquiring");
    }
    await service.recoverResources({ ...f.request, resource });
    assert.equal(await f.saved(), null);
  });
}
