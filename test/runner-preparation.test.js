import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import * as filesystem from "node:fs/promises";
import {
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { auditPipeline } from "@agent-runner/audit";

import {
  createClaudeAdapter,
  createCodexAdapter,
} from "../src/agents/index.js";
import { parseRunnerConfiguration } from "../src/config/index.js";
import { main } from "../src/index.js";
import { createGitService } from "../src/git/index.js";
import { createMcpControlPlane } from "../src/mcp/index.js";
import { createRunner } from "../src/runner/index.js";
import { createRunStore } from "../src/state/index.js";
import { workspacePreparationInputFingerprint } from "../src/state/validation.js";
import { createWorkspaceService } from "../src/workspace/index.js";

const digest = (value) =>
  createHash("sha256").update(JSON.stringify(value)).digest("hex");
const execute = promisify(execFile);

function captureGate() {
  const entered = Promise.withResolvers();
  const released = Promise.withResolvers();
  return {
    entered: entered.promise,
    release: released.resolve,
    async hold(signal) {
      entered.resolve();
      const aborted = Promise.withResolvers();
      const abort = () => aborted.reject(signal.reason);
      signal.addEventListener("abort", abort, { once: true });
      try {
        signal.throwIfAborted();
        await Promise.race([released.promise, aborted.promise]);
      } finally {
        signal.removeEventListener("abort", abort);
      }
    },
  };
}

// Early completion/failure must fail the event wait instead of hanging a test.
function until(event, operation) {
  return Promise.race([
    event,
    operation.then(() =>
      assert.fail("Operation completed before its controlled event."),
    ),
  ]);
}

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), "runner-preparation-"));
  const projectPath = join(root, "project");
  const taskPath = join(root, "task");
  const stateRoot = join(root, "state");
  await Promise.all([mkdir(projectPath), mkdir(taskPath)]);
  await writeFile(join(projectPath, "source.txt"), "Original source\n");
  await writeFile(join(taskPath, "task.md"), "Audit the whole workspace.\n");
  t.after(() => rm(root, { recursive: true, force: true }));
  const store = createRunStore({ stateRoot });
  const workspace = createWorkspaceService();
  const f = {
    root,
    projectPath,
    taskPath,
    stateRoot,
    store,
    gate: null,
    scans: 0,
    probes: [],
    calls: [],
  };
  const adapter = {
    async probe(request) {
      f.probes.push(request);
      assert.equal(request.workspacePolicy.kind, "directory");
      return {
        version: "fixture",
        readOnly: true,
        structuredOutput: true,
        declaredWorkspace: true,
        remoteWriteBlocked: true,
        nativeSessionContinuation: true,
        policyReceipt: {
          schemaVersion: 1,
          fingerprint: digest(request),
          supportedAccess: ["read-only"],
        },
      };
    },
    async run(request) {
      f.calls.push(request);
      assert.equal(request.access, "read-only");
      const evidence = JSON.parse(request.prompt.split("\n").at(-1));
      return {
        sessionId: "audit-child",
        structured:
          f.calls.length === 1
            ? {
                status: "READY",
                questions: [],
                reason: "",
                inputs: {
                  scope: ["Whole workspace"],
                  references: [],
                  exclusions: [],
                  criteria: ["Established rules"],
                },
              }
            : {
                status: "COMPLETE",
                snapshotFingerprint: evidence.snapshotFingerprint,
                candidates: [],
                limitations: [],
                hypotheses: [],
                reportCorrections: [],
              },
      };
    },
  };
  f.runner = (options = {}) =>
    createRunner({
      runStore: store,
      git: new Proxy(
        {},
        {
          get: () =>
            assert.fail("Ordinary audit preparation must not invoke Git."),
        },
      ),
      adapters: { codex: adapter },
      loadConfiguration: async () =>
        parseRunnerConfiguration(
          JSON.stringify({ schemaVersion: 1, defaultBackend: "codex" }),
        ),
      workspace: {
        ...workspace,
        async inspect(declarations, traversal = {}) {
          f.scans++;
          const gate = f.gate;
          if (gate !== null) {
            f.gate = null;
            assert.ok(
              traversal.signal,
              "Preparation traversal must be cancellable.",
            );
          }
          return workspace.inspect(declarations, {
            ...traversal,
            ...(gate === null
              ? {}
              : { onProgress: () => gate.hold(traversal.signal) }),
          });
        },
      },
      ...options,
    });
  f.input = {
    pipelineId: "audit",
    projectPath,
    taskPath,
    settingOverrides: { mode: "lazy" },
  };
  return f;
}

test("admission applies the project overlay before source-scope relationships and retains strict final validation", async (t) => {
  const f = await fixture(t);
  await writeFile(
    join(f.projectPath, "runner.json"),
    JSON.stringify({
      schemaVersion: 1,
      pipelines: { audit: { sourceScope: "directory" } },
    }),
  );
  const runner = f.runner({
    loadConfiguration: async () =>
      parseRunnerConfiguration(
        JSON.stringify({
          schemaVersion: 1,
          defaultBackend: "codex",
          pipelines: { audit: { sourceScope: "git" } },
        }),
      ),
  });
  const input = {
    ...f.input,
    projectConfigurationPath: "runner.json",
    settingOverrides: {
      ...f.input.settingOverrides,
      excludePaths: ["generated"],
    },
  };
  assert.equal(
    (await runner.validateBoundary(input)).projectPath,
    f.projectPath,
  );
  const { run } = await runner.create(input);
  assert.equal(run.pipelineState.settings.sourceScope, "directory");
  assert.deepEqual(run.pipelineState.settings.excludePaths, ["generated"]);
  assert.deepEqual(run.workspacePreparation.policy.excludePaths, ["generated"]);
  for (const settings of [
    { sourceScope: "git", excludePaths: ["generated"] },
    { excludePaths: ["../outside"] },
  ])
    await assert.rejects(
      runner.create({ ...input, settingOverrides: settings }),
      { code: "ERR_INVALID_CONFIGURATION" },
    );
  assert.equal(f.scans, 0);
  assert.equal(f.probes.length, 0);
  assert.equal(f.calls.length, 0);
});

test("CLI exposes durable preparation and cancellation stops traversal before provider work", async (t) => {
  const f = await fixture(t);
  const gate = captureGate();
  f.gate = gate;
  let output = "";
  let runId;
  const runner = f.runner();
  // Forward creation activity through the CLI's normal runner factory.
  const running = main(
    [
      "run",
      "audit",
      "--project",
      f.projectPath,
      "--task",
      f.taskPath,
      "--mode",
      "lazy",
    ],
    {
      createCommandRunner(options) {
        return f.runner({
          ...options,
          onActivity(activity) {
            runId ??= activity.runId;
            return options.onActivity(activity);
          },
        });
      },
      stdout: {
        write: (value) => {
          output += value;
        },
      },
      stderr: { write: (value) => assert.fail(value) },
    },
  );
  try {
    await until(gate.entered, running);
    assert.ok(output.includes(`Run: ${runId}.`));
    assert.match(output, /Workspace preparation pending/u);
    assert.ok(output.includes(`agent-run pause --run ${runId}`));
    assert.ok(output.includes(`agent-run cancel --run ${runId}`));
    const { run } = await runner.status(runId);
    assert.equal(run.pipelineState.workflowState, "CLARIFY");
    assert.equal(run.workspace, null);
    assert.ok(run.workspacePreparation);
    await runner.requestOperatorStop({
      runId,
      kind: "cancel_requested",
      expectedRevision: run.revision,
      idempotencyKey: "cancel-capture",
    });
    await running;
    const canceled = (await runner.status(runId)).run;
    assert.equal(canceled.pipelineState.workflowState, "CANCELED");
    assert.deepEqual(canceled.workspacePreparation, run.workspacePreparation);
    assert.equal(canceled.workspace, null);
    assert.equal(canceled.stopRequest.settlement.kind, "quiescent");
    assert.equal(f.probes.length, 0);
    assert.equal(f.calls.length, 0);
    assert.equal(await f.store.runLeaseOwnerIsLive(runId), false);
    assert.equal(await f.store.worktreeLeaseOwner(f.projectPath, runId), null);
  } finally {
    gate.release();
    await running.catch(() => {});
  }
});

test("paused preparation resumes from frozen inputs and configuration in a replacement runner", async (t) => {
  const f = await fixture(t);
  const runner = f.runner();
  await runner.validateBoundary(f.input);
  const { run } = await runner.create(f.input);
  assert.equal(f.scans, 0);
  assert.equal(f.probes.length, 0);
  const gate = captureGate();
  f.gate = gate;
  const running = runner.resume({ runId: run.runId });
  try {
    await until(gate.entered, running);
    const inspected = (await runner.status(run.runId)).run;
    await runner.requestOperatorStop({
      runId: run.runId,
      kind: "pause_requested",
      expectedRevision: inspected.revision,
      idempotencyKey: "pause-capture",
    });
    const paused = (await running).run;
    assert.equal(paused.pause.reason, "operator_paused");
    assert.deepEqual(paused.workspacePreparation, run.workspacePreparation);
    const replacement = f.runner({
      runStore: createRunStore({ stateRoot: f.stateRoot }),
      loadConfiguration: () =>
        assert.fail("Resume must not resolve current configuration."),
      getPipeline: () => ({
        ...auditPipeline,
        resolveWorkspace: () =>
          assert.fail("Resume must not select preparation again."),
      }),
    });
    const resumed = await replacement.resume({ runId: run.runId });
    assert.equal(resumed.run.pipelineState.workflowState, "DONE");
    assert.equal(resumed.run.workspacePreparation, null);
    assert.deepEqual(
      resumed.run.workspace.policy,
      run.workspacePreparation.policy,
    );
    assert.deepEqual(resumed.run.roles, run.roles);
    assert.equal(resumed.run.pipelineState.settings.mode, "lazy");
    assert.match(
      await readFile(join(f.taskPath, "audit.md"), "utf8"),
      /complete/iu,
    );
    assert.equal(f.probes.length, 1);
  } finally {
    gate.release();
    await running.catch(() => {});
  }
});

test("interrupted capture recovers without adopting partial evidence and rejects substituted inputs", async (t) => {
  const f = await fixture(t);
  let interrupted = true;
  const workspace = createWorkspaceService();
  const runner = f.runner({
    workspace: {
      ...workspace,
      async snapshot(request) {
        const partial = await workspace.snapshot(request);
        if (interrupted) {
          interrupted = false;
          throw new Error("Capture interrupted.");
        }
        return partial;
      },
    },
  });
  const { run } = await runner.create(f.input);
  await assert.rejects(
    runner.resume({ runId: run.runId }),
    /Capture interrupted/u,
  );
  const saved = (await runner.status(run.runId)).run;
  assert.equal(saved.workspace, null);
  assert.deepEqual(saved.workspacePreparation, run.workspacePreparation);
  const resumed = await f
    .runner({
      runStore: createRunStore({ stateRoot: f.stateRoot }),
      loadConfiguration: () =>
        assert.fail("Frozen admission must survive reconstruction."),
    })
    .resume({ runId: run.runId });
  assert.equal(resumed.run.pipelineState.workflowState, "DONE");
  const other = await f.runner().create(f.input);
  const replacement = join(f.taskPath, "replacement.md");
  await writeFile(replacement, await readFile(join(f.taskPath, "task.md")));
  await rename(replacement, join(f.taskPath, "task.md"));
  const scans = f.scans;
  const calls = f.calls.length;
  const blocked = await f.runner().resume({ runId: other.run.runId });
  assert.equal(blocked.run.pause.reason, "workspace_changed");
  assert.equal(blocked.run.workspace, null);
  assert.equal(f.scans, scans);
  assert.equal(f.calls.length, calls);
});

test("MCP acknowledges owned preparation before capture and repairs a lost receipt after disconnect", async (t) => {
  const f = await fixture(t);
  const gate = captureGate();
  f.gate = gate;
  const receiptEntered = Promise.withResolvers();
  const releaseReceipt = Promise.withResolvers();
  const actionReleased = Promise.withResolvers();
  const continuationOutcome = Promise.withResolvers();
  let continuation;
  let launches = 0;
  const runner = f.runner();
  const store = {
    ...f.store,
    async beginAction(input) {
      const action = await f.store.beginAction(input);
      return {
        ...action,
        async complete() {
          receiptEntered.resolve();
          await releaseReceipt.promise;
          throw new Error("Receipt publication interrupted.");
        },
        async release() {
          try {
            await action.release();
          } finally {
            actionReleased.resolve();
          }
        },
      };
    },
  };
  const control = createMcpControlPlane({
    runner,
    runStore: store,
    launchRun(runId, _action, options) {
      launches++;
      continuation = runner.resume({
        runId,
        dispatch: options.dispatch,
        expectedRuntimeCompatibility: options.expectedRuntimeCompatibility,
      });
      continuation.then(
        (result) => {
          continuationOutcome.resolve(result);
          options.onExit(0, null);
        },
        (cause) => {
          continuationOutcome.reject(cause);
          options.onExit(1, null);
        },
      );
    },
  });
  const input = {
    pipelineId: "audit",
    projectPath: f.projectPath,
    taskPath: f.taskPath,
    mode: "lazy",
    proactiveClarification: false,
    idempotencyKey: "start-preparation",
  };
  const client = new AbortController();
  const starting = control.runStart(input, { signal: client.signal });
  const preparing = Promise.race([starting, continuationOutcome.promise]);
  try {
    await until(receiptEntered.promise, preparing);
    await until(gate.entered, preparing);
    const { idempotencyKey, ...argumentsWithoutKey } = input;
    const action = await f.store.readAction({
      key: idempotencyKey,
      tool: "run_start",
      arguments: argumentsWithoutKey,
    });
    const runId = action.context.runId;
    const status = await control.runStatus({ runId });
    assert.deepEqual(status.workspacePreparation, { status: "pending" });
    assert.equal(status.status, "CLARIFY");
    assert.equal(status.execution.state, "running");
    client.abort(new Error("Client disconnected."));
    await assert.rejects(starting, /Client disconnected/u);
    releaseReceipt.resolve();
    await actionReleased.promise;
    const recovered = createMcpControlPlane({
      runner: f.runner({
        loadConfiguration: () =>
          assert.fail("Receipt repair must not resolve configuration."),
      }),
      runStore: f.store,
      launchRun: () => assert.fail("Receipt repair must not dispatch again."),
    });
    assert.deepEqual(await recovered.runStart(input), { runId });
    assert.deepEqual(await recovered.runStart(input), { runId });
    assert.equal(launches, 1);
    assert.equal(f.probes.length, 0);
    const current = (await runner.status(runId)).run;
    await runner.requestOperatorStop({
      runId,
      kind: "cancel_requested",
      expectedRevision: current.revision,
      idempotencyKey: "stop-detached-preparation",
    });
    assert.equal(
      (await continuation).run.pipelineState.workflowState,
      "CANCELED",
    );
  } finally {
    releaseReceipt.resolve();
    gate.release();
    await starting.catch(() => {});
    await continuation?.catch(() => {});
  }
});

test("pending audit capture shares canonical and overlapping workspace exclusion", async (t) => {
  for (const git of [false, true]) {
    const f = await fixture(t);
    if (git) {
      await mkdir(join(f.projectPath, ".git", "objects"), { recursive: true });
      await mkdir(join(f.projectPath, ".git", "refs"));
      await writeFile(
        join(f.projectPath, ".git", "HEAD"),
        "ref: refs/heads/main\n",
      );
    }
    const child = join(f.projectPath, "content");
    await mkdir(child);
    const owner = "11111111-1111-4111-8111-111111111111";
    const held = await f.store.acquireWorktreeLease(f.projectPath, owner);
    const runner = f.runner();
    try {
      const { run } = await runner.create({ ...f.input, projectPath: child });
      assert.equal(
        run.workspacePreparation.leasePath,
        git ? f.projectPath : child,
      );
      await assert.rejects(runner.resume({ runId: run.runId }), {
        code: "ERR_WORKTREE_LEASED",
      });
      assert.equal(f.scans, 0);
      assert.equal(f.probes.length, 0);
      assert.equal(
        await f.store.worktreeLeaseOwner(f.projectPath, owner),
        owner,
      );
    } finally {
      await held.release();
    }
  }
});

test("excluded directory trees stay opaque through audit completion and deliberate issue capture", async (t) => {
  const f = await fixture(t);
  const opaque = join(f.projectPath, "generated");
  await mkdir(opaque);
  await writeFile(join(opaque, "unread.txt"), "Outside the selected scope\n");
  const touched = [];
  const fileSystem = { ...filesystem };
  for (const name of [
    "lstat",
    "open",
    "readdir",
    "readFile",
    "readlink",
    "realpath",
  ])
    fileSystem[name] = async (path, ...args) => {
      let actual = String(path);
      const descriptor = /^\/proc\/self\/fd\/\d+/u.exec(actual)?.[0];
      if (descriptor)
        actual =
          (await filesystem.realpath(descriptor)) +
          actual.slice(descriptor.length);
      if (actual === opaque || actual.startsWith(`${opaque}/`)) {
        touched.push(actual);
        assert.fail("Excluded descendants must stay opaque.");
      }
      return filesystem[name](path, ...args);
    };
  const runner = f.runner({
    workspace: createWorkspaceService({ fileSystem }),
  });
  const result = await runner.run({
    ...f.input,
    settingOverrides: { mode: "lazy", excludePaths: ["generated"] },
  });
  assert.equal(result.run.pipelineState.workflowState, "DONE");
  assert.match(
    await readFile(join(f.taskPath, "audit.md"), "utf8"),
    /Literal excluded paths\*\*\n\n- generated/u,
  );
  assert.deepEqual(touched, []);
  for (const request of [...f.probes, ...f.calls])
    assert.deepEqual(request.workspacePolicy.excludePaths, ["generated"]);
  assert.notEqual(process.cwd(), f.projectPath);
  const request = f.calls[0];
  assert.ok(request.storageForbiddenPaths.includes(f.projectPath));
  assert.ok(
    request.storageForbiddenPaths.every(
      (path) => isAbsolute(path) && resolve(path) === path,
    ),
  );
  // Real adapters must accept Runner's request before the controlled CLI blocker;
  // neither this normalization proof nor the audit fixture invokes a provider.
  for (const [createAdapter, code] of [
    [createCodexAdapter, "ERR_CODEX_UNAVAILABLE"],
    [createClaudeAdapter, "ERR_CLAUDE_UNAVAILABLE"],
  ]) {
    let inspections = 0;
    const adapter = createAdapter({
      env: {},
      execute: async () => {
        inspections++;
        throw new Error("Controlled CLI unavailability.");
      },
    });
    await assert.rejects(adapter.run(request), { code });
    assert.equal(inspections, 2);
  }
  assert.deepEqual(
    JSON.parse(f.calls[0].prompt.split("\n").at(-1)).sourceSelection,
    {
      sourceScope: "directory",
      excludePaths: ["generated"],
      fingerprint: null,
    },
  );
  const control = createMcpControlPlane({
    runner,
    runStore: f.store,
    reportingOptions: {
      platform: "linux",
      homeDirectory: join(f.root, "home"),
      env: {
        HOME: join(f.root, "home"),
        XDG_DATA_HOME: join(f.root, "data"),
        XDG_CONFIG_HOME: join(f.root, "config"),
        XDG_STATE_HOME: join(f.root, "runtime"),
      },
      git: {
        resolveProject: () =>
          assert.fail("Directory issue capture must not invoke Git."),
      },
    },
  });
  const status = await control.runStatus({ runId: result.run.runId });
  assert.deepEqual(status.auditSource, {
    sourceScope: "directory",
    excludePaths: ["generated"],
    selectionFingerprint: null,
  });
  await assert.rejects(filesystem.access(join(f.root, "data")), {
    code: "ENOENT",
  });
  const input = {
    idempotencyKey: "directory-issue",
    projectPath: f.projectPath,
    runId: result.run.runId,
    summary: "A caller observed a separate Runner inconsistency.",
    expectedBehavior: "The documented result remains available.",
    actualBehavior: "The result was unavailable.",
    occurrence: "Observed once by the caller.",
    unexpectedReason: "The result contradicted the documented contract.",
  };
  const receipt = await control.unexpectedIssueReport(input);
  assert.deepEqual(await control.unexpectedIssueReport(input), receipt);
  const issue = JSON.parse(await readFile(receipt.issuePath, "utf8"));
  assert.equal(issue.tracking.origin.path, f.projectPath);
  assert.equal(f.calls.length, 2);
  assert.equal(
    (await runner.status(result.run.runId)).run.pipelineState.workflowState,
    "DONE",
  );
});

test("Git source selection is visible and cancellable before membership or capture is published", async (t) => {
  const f = await fixture(t);
  const gate = captureGate();
  const runner = f.runner({
    git: {
      resolveProject: async () => f.projectPath,
      selectSources: ({ signal }) => gate.hold(signal),
    },
  });
  const { run } = await runner.create({
    ...f.input,
    settingOverrides: { mode: "lazy", sourceScope: "git" },
  });
  const running = runner.resume({ runId: run.runId });
  try {
    await until(gate.entered, running);
    const pending = (await runner.status(run.runId)).run;
    assert.equal(pending.workspace, null);
    assert.equal(
      pending.workspacePreparation.sourceSelection.fingerprint,
      null,
    );
    await runner.requestOperatorStop({
      runId: run.runId,
      kind: "cancel_requested",
      expectedRevision: pending.revision,
      idempotencyKey: "cancel-selection",
    });
    const canceled = (await running).run;
    assert.equal(canceled.pipelineState.workflowState, "CANCELED");
    assert.deepEqual(
      canceled.workspacePreparation,
      pending.workspacePreparation,
    );
    assert.equal(f.scans, 0);
    assert.equal(f.probes.length, 0);
    assert.equal(f.calls.length, 0);
    assert.equal(
      await f.store.worktreeLeaseOwner(f.projectPath, run.runId),
      null,
    );
  } finally {
    gate.release();
    await running.catch(() => {});
  }
});

test("Git audit journals complete source selection before cancellable capture and rechecks it on reconstruction", async (t) => {
  const f = await fixture(t);
  const env = {
    ...Object.fromEntries(
      Object.entries(process.env).filter(([name]) => !name.startsWith("GIT_")),
    ),
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_OPTIONAL_LOCKS: "0",
    HOME: f.root,
    XDG_CONFIG_HOME: f.root,
  };
  const git = (...args) =>
    execute("git", ["-C", f.projectPath, ...args], { env });
  await git("init", "--quiet");
  await mkdir(join(f.projectPath, "dependencies"));
  await writeFile(join(f.projectPath, ".gitignore"), "dependencies/\n");
  await writeFile(
    join(f.projectPath, "dependencies/tracked.txt"),
    "Tracked dependency\n",
  );
  for (const path of ["dirty.txt", "deleted.txt"])
    await writeFile(join(f.projectPath, path), "Original\n");
  await git("add", ".");
  await git("add", "-f", "dependencies/tracked.txt");
  await git(
    "-c",
    "user.name=Fixture",
    "-c",
    "user.email=fixture@example.invalid",
    "-c",
    "commit.gpgsign=false",
    "commit",
    "-qm",
    "fixture",
  );
  await writeFile(join(f.projectPath, "dirty.txt"), "Dirty worktree\n");
  await rm(join(f.projectPath, "deleted.txt"));
  await writeFile(join(f.projectPath, "new.txt"), "Untracked\n");
  await writeFile(join(f.projectPath, "dependencies/ignored.txt"), "Ignored\n");
  const service = createGitService({ env });
  let selections = 0;
  const scopedGit = {
    ...service,
    selectSources(options) {
      if (options.expectedSelectionFingerprint === undefined) selections++;
      return service.selectSources(options);
    },
  };
  const before = await service.snapshot({ projectPath: f.projectPath });
  const runner = f.runner({ git: scopedGit });
  const { run } = await runner.create({
    ...f.input,
    settingOverrides: { mode: "lazy", sourceScope: "git" },
  });
  assert.equal(selections, 0);
  assert.equal(run.workspacePreparation.sourceSelection.fingerprint, null);
  const gate = captureGate();
  f.gate = gate;
  const running = runner.resume({ runId: run.runId });
  try {
    await until(gate.entered, running);
    const selected = (await runner.status(run.runId)).run;
    const binding = selected.workspacePreparation;
    assert.match(binding.sourceSelection.fingerprint, /^[a-f0-9]{64}$/u);
    assert.equal(selected.workspace, null);
    assert.equal(binding.policy.inspectionFilesOnly, true);
    assert.deepEqual(
      binding.policy.inspectionPaths,
      [
        ".gitignore",
        "deleted.txt",
        "dependencies/tracked.txt",
        "dirty.txt",
        "new.txt",
        "source.txt",
      ].map((path) => join(f.projectPath, path)),
    );
    assert.equal(f.probes.length, 0);
    await runner.requestOperatorStop({
      runId: run.runId,
      kind: "pause_requested",
      expectedRevision: selected.revision,
      idempotencyKey: "pause-git-capture",
    });
    const paused = (await running).run;
    assert.deepEqual(paused.workspacePreparation, binding);
    const replacement = f.runner({
      git: scopedGit,
      runStore: createRunStore({ stateRoot: f.stateRoot }),
      loadConfiguration: () =>
        assert.fail("Frozen selection must not resolve configuration again."),
    });
    const completed = (await replacement.resume({ runId: run.runId })).run;
    assert.equal(completed.pipelineState.workflowState, "DONE");
    assert.deepEqual(
      completed.workspace.sourceSelection,
      binding.sourceSelection,
    );
    assert.equal(selections, 1);
    for (const request of [...f.probes, ...f.calls]) {
      assert.equal(request.access, "read-only");
      assert.deepEqual(
        request.workspacePolicy.inspectionPaths,
        binding.policy.inspectionPaths,
      );
      assert.equal(request.workspacePolicy.inspectionFilesOnly, true);
    }
    assert.equal(
      JSON.parse(f.calls[0].prompt.split("\n").at(-1)).sourceSelection
        .fingerprint,
      binding.sourceSelection.fingerprint,
    );
    assert.deepEqual(
      await service.snapshot({ projectPath: f.projectPath }),
      before,
    );
    await writeFile(join(f.projectPath, "later.txt"), "Membership changed\n");
    const blocked = (await replacement.resume({ runId: run.runId })).run;
    assert.equal(blocked.pause.reason, "workspace_changed");
    assert.equal(f.calls.length, 2);
    assert.equal(selections, 1);
  } finally {
    gate.release();
    await running.catch(() => {});
  }
});

test("legacy pending audit resumes whole-directory capture without changing frozen settings or budgets", async (t) => {
  const f = await fixture(t);
  const { run, directoryPath } = await f.runner().create(f.input);
  const event = JSON.parse(
    (await readFile(join(directoryPath, "events.jsonl"), "utf8")).trim(),
  );
  const legacy = event.state;
  event.schemaVersion =
    legacy.schemaVersion =
    legacy.runtimeCompatibility.runStateVersion =
      25;
  legacy.pipelineStateVersion = 6;
  delete legacy.pipelineState.settings.sourceScope;
  delete legacy.pipelineState.settings.excludePaths;
  legacy.workspacePreparation.inputFingerprint =
    workspacePreparationInputFingerprint(legacy);
  await writeFile(
    join(directoryPath, "events.jsonl"),
    `${JSON.stringify(event)}\n`,
  );
  await writeFile(join(directoryPath, "state.json"), JSON.stringify(legacy));
  const resumed = (
    await f
      .runner({
        runStore: createRunStore({ stateRoot: f.stateRoot }),
        loadConfiguration: () =>
          assert.fail("Legacy resume retains frozen configuration."),
      })
      .resume({ runId: run.runId })
  ).run;
  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.deepEqual(
    resumed.pipelineState.settings,
    legacy.pipelineState.settings,
  );
  assert.deepEqual(
    resumed.workspace.policy,
    legacy.workspacePreparation.policy,
  );
  assert.equal(resumed.workspace.sourceSelection, undefined);
  assert.equal(resumed.pipelineState.history.length, 1);
  assert.equal(resumed.pipelineState.recheckHistory.length, 0);
});
