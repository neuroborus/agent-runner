import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { lstat, mkdir, rm, writeFile } from "node:fs/promises";
import { hostname } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { AgentBoundaryError } from "../src/agents/index.js";
import {
  parseRunnerConfiguration,
  loadProjectConfiguration,
  resolveRunStoragePolicy,
} from "../src/config/index.js";
import { createGitService } from "../src/git/index.js";
import { createMcpControlPlane } from "../src/mcp/index.js";
import { createRunner } from "../src/runner/index.js";
import {
  createRunStore,
  DEFAULT_MAX_EVENT_LOG_BYTES,
} from "../src/state/index.js";
import { createTrustedValidationService } from "../src/trusted-validation/index.js";
import {
  createAdapter,
  createExecutionAdapter,
  createFixture,
  PLAN,
} from "./support/index.js";

test("journal capacity wires current root policy through ordinary Runner and shared MCP without replacing workflow configuration", async (t) => {
  const fixture = await createFixture(t);
  const previous = process.env.XDG_STATE_HOME;
  process.env.XDG_STATE_HOME = join(fixture.workspace, "xdg");
  t.after(() => {
    if (previous === undefined) delete process.env.XDG_STATE_HOME;
    else process.env.XDG_STATE_HOME = previous;
  });
  let capacity = 1;
  let model = "current";
  const loadConfiguration = async () =>
    parseRunnerConfiguration(
      JSON.stringify({
        schemaVersion: 1,
        defaultBackend: "codex",
        defaultModel: model,
        maxEventLogBytes: capacity,
      }),
    );
  const runner = createRunner({
    adapters: { codex: createAdapter() },
    loadConfiguration,
  });
  const input = {
    pipelineId: "plan-authoring",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    proactiveClarification: false,
    sourceSession: null,
    settingOverrides: { mode: "lazy" },
  };
  await assert.rejects(runner.create(input), { code: "ERR_EVENT_LOG_LIMIT" });
  capacity = DEFAULT_MAX_EVENT_LOG_BYTES;
  const { run } = await runner.create(input);
  model = "changed-model";
  const observer = createRunStore({
    stateRoot: join(process.env.XDG_STATE_HOME, "agent-runner"),
  });
  const lease = await observer.acquireRunLease(run.runId);
  const control = createMcpControlPlane({
    loadConfiguration,
    launchRun: () => assert.fail("The live owner must exclude detached work"),
  });
  capacity = 1;
  const stop = {
    runId: run.runId,
    expectedRevision: run.revision,
    idempotencyKey: "journal-policy-stop",
  };
  await assert.rejects(control.runPause(stop), { code: "ERR_EVENT_LOG_LIMIT" });
  assert.deepEqual(await observer.loadRun(run.runId), run);
  capacity = DEFAULT_MAX_EVENT_LOG_BYTES;
  const receipt = await control.runPause(stop);
  const stopped = await observer.loadRun(run.runId);
  assert.deepEqual(stopped.roles, run.roles);
  assert.deepEqual(stopped.pipelineState, run.pipelineState);
  await observer.completeOperatorStop(lease, {
    requestId: receipt.requestId,
    patch: {
      pipelineState: {
        ...stopped.pipelineState,
        workflowState: "WAITING_FOR_USER",
      },
      pause: {
        reason: "operator_paused",
        operatorResume: {
          workflowState: "CLARIFY",
          pause: null,
          activeTurn: null,
        },
      },
      activeTurn: null,
    },
  });
  await lease.release();

  const git = createGitService();
  const overlayPath = join(
    fixture.projectPath,
    "LOCAL_ARTIFACTS",
    "agent-runner.json",
  );
  await writeFile(
    join(fixture.projectPath, ".gitignore"),
    "/LOCAL_ARTIFACTS/\n",
  );
  await mkdir(join(fixture.projectPath, "LOCAL_ARTIFACTS"));
  await writeFile(overlayPath, '{"schemaVersion":1,"maxEventLogBytes":8192}\n');
  const configuration = await loadConfiguration();
  const overlay = await loadProjectConfiguration({
    configurationPath: overlayPath,
    inspectPath: (options) => git.inspectPath(options),
    projectPath: fixture.projectPath,
    runnerConfiguration: configuration,
  });
  const policy = {
    configuration,
    inspectPath: (options) => git.inspectPath(options),
    projectPath: fixture.projectPath,
    protection: overlay.protection,
  };
  assert.equal(await resolveRunStoragePolicy(policy), 8192);
  assert.equal(
    await resolveRunStoragePolicy({ ...policy, protection: null }),
    DEFAULT_MAX_EVENT_LOG_BYTES,
  );
  await writeFile(
    overlayPath,
    '{"schemaVersion":1,"maxEventLogBytes":16384}\n',
  );
  await assert.rejects(resolveRunStoragePolicy(policy), {
    code: "ERR_PROJECT_CONFIGURATION_CHANGED",
  });
});

test("journal capacity preserves original trusted cleanup failure through both lease failures and permits exact same-Runner retry", async (t) => {
  const fixture = await createFixture(t);
  await writeFile(join(fixture.taskPath, "plan.md"), PLAN);
  const identity = (pid) => ({
    bootId: "11111111-1111-4111-8111-111111111111",
    startTicks: String(pid),
  });
  const options = { stateRoot: fixture.stateRoot, processIdentity: identity };
  const source = createRunStore({
    ...options,
    processId: 100,
    processIsAlive: () => true,
  });
  const loadConfiguration = async () =>
    parseRunnerConfiguration('{"schemaVersion":1,"defaultBackend":"codex"}');
  const creator = createRunner({
    runStore: source,
    adapters: { codex: createExecutionAdapter() },
    loadConfiguration,
  });
  const { run } = await creator.create({
    pipelineId: "plan-execution",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    proactiveClarification: false,
    sourceSession: null,
    settingOverrides: { mode: "lazy" },
  });
  const seed = await source.acquireRunLease(run.runId);
  const storagePath = join(fixture.workspace, "storage");
  await mkdir(storagePath, { mode: 0o700 });
  const metadata = await lstat(storagePath, { bigint: true });
  const resource = {
    id: randomUUID(),
    hostname: hostname(),
    commandIdentity: "a".repeat(64),
    phase: "allocating",
    root: {
      path: storagePath,
      device: String(metadata.dev),
      inode: String(metadata.ino),
    },
    directory: null,
  };
  await source.recordExecutionResource(seed, resource);
  const child = join(storagePath, resource.id);
  await mkdir(child, { mode: 0o700 });
  const childMetadata = await lstat(child, { bigint: true });
  const retained = {
    ...resource,
    phase: "allocated",
    directory: {
      device: String(childMetadata.dev),
      inode: String(childMetadata.ino),
    },
  };
  await source.recordExecutionResource(seed, retained);
  await rm(child, { recursive: true });
  let capacity = 1;
  const store = createRunStore({
    ...options,
    processId: 200,
    processIsAlive: (pid) => pid === 200,
    maxEventLogBytes: () => capacity,
  });
  const acquired = [];
  let worktreeAcquisitions = 0;
  const tracked = {
    ...store,
    async acquireRunLease(runId, handle) {
      const lease = await store.acquireRunLease(runId, handle);
      acquired.push({ lease, handle });
      return lease;
    },
    async acquireWorktreeLease(...args) {
      worktreeAcquisitions++;
      return store.acquireWorktreeLease(...args);
    },
  };
  const service = createTrustedValidationService();
  const failures = [];
  const trustedValidation = {
    ...service,
    async recoverResources(request) {
      try {
        await service.recoverResources(request);
      } catch (cause) {
        failures.push(cause);
        throw cause;
      }
    },
  };
  const afterCleanup = new AgentBoundaryError(
    { code: "ERR_FIXTURE_AFTER_CLEANUP" },
    {
      failureClass: "adapter_failure",
      checkpoint: "probe",
      outcome: "rejected",
      effect: "none",
      retry: "terminal",
    },
  );
  const adapter = createExecutionAdapter();
  // Stop at the next injected probe, after durable cleanup but before either
  // lease can release or another agent turn can begin.
  adapter.probe = async () => {
    assert.equal((await store.loadRun(run.runId)).executionResource, null);
    assert.equal(await store.runLeaseOwnerIsLive(run.runId), true);
    assert.equal(
      await store.worktreeLeaseOwner(fixture.projectPath, run.runId),
      run.runId,
    );
    throw afterCleanup;
  };
  const runner = createRunner({
    runStore: tracked,
    adapters: { codex: adapter },
    trustedValidation,
    loadConfiguration,
  });
  await assert.rejects(
    runner.resume({ runId: run.runId }),
    (cause) =>
      cause === failures[0] &&
      cause.code === "ERR_TRUSTED_VALIDATION_RESOURCE_UNVERIFIABLE" &&
      cause.cause?.code === "ERR_EVENT_LOG_LIMIT",
  );
  assert.deepEqual(
    (await store.loadRun(run.runId)).executionResource,
    retained,
  );
  assert.equal(await store.runLeaseOwnerIsLive(run.runId), true);
  assert.equal(
    await store.worktreeLeaseOwner(fixture.projectPath, run.runId),
    run.runId,
  );
  await assert.rejects(
    createRunner({ runStore: store, loadConfiguration }).resume({
      runId: run.runId,
    }),
    { code: "ERR_RUN_LEASED" },
  );
  await assert.rejects(
    store.acquireWorktreeLease(fixture.projectPath, randomUUID()),
    { code: "ERR_WORKTREE_LEASED" },
  );
  capacity = DEFAULT_MAX_EVENT_LOG_BYTES;
  await assert.rejects(
    runner.resume({ runId: run.runId }),
    (cause) => cause === afterCleanup,
  );
  assert.equal(acquired[1].handle, acquired[0].lease);
  assert.equal(worktreeAcquisitions, 1);
  assert.equal(failures.length, 1);
  assert.equal(await store.runLeaseOwnerIsLive(run.runId), false);
  assert.equal(
    await store.worktreeLeaseOwner(fixture.projectPath, run.runId),
    null,
  );
  assert.equal(adapter.calls.length, 0);
  const history = await store.loadRunHistory(run.runId);
  assert.equal(history.events.at(-1).activity.kind, "resource-cleaned");
});
