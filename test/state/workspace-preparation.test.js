import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

import {
  loadProjectConfiguration,
  parseRunnerConfiguration,
} from "../../src/config/index.js";
import {
  bindWorkspace,
  captureWorkspacePreparation,
} from "../../src/runner/workspace.js";
import {
  createRunStore,
  RUN_STATE_SCHEMA_VERSION,
} from "../../src/state/index.js";
import { createWorkspaceService } from "../../src/workspace/index.js";

const hash = (value) => createHash("sha256").update(value).digest("hex");
const bootId = "00000000-0000-4000-8000-000000000001";

async function fixture(
  t,
  {
    onTransitionBoundary = () => {},
    configuration = false,
    contextFilename = "context.md",
    gitSelection = false,
  } = {},
) {
  const root = await mkdtemp(
    join(tmpdir(), "agent-runner-workspace-admission-"),
  );
  const projectPath = join(root, "project");
  const taskPath = join(root, "task");
  const stateRoot = join(root, "state");
  await Promise.all([mkdir(projectPath), mkdir(taskPath)]);
  await mkdir(dirname(join(taskPath, contextFilename)), { recursive: true });
  await writeFile(join(projectPath, "source.txt"), "source\n");
  await writeFile(join(taskPath, "task.md"), "Inspect the sources.\n");
  const workspace = createWorkspaceService();
  const policy = {
    kind: "directory",
    workspacePath: projectPath,
    taskPath,
    stateRoot,
    inputPaths: [join(taskPath, "task.md")],
    sourcePaths: [],
    outputPaths: [],
    configurationPaths: [],
    artifactPaths: [],
    infrastructurePaths: [],
  };
  const admission = {
    leasePath: projectPath,
    policy,
    inputs: [
      {
        path: join(taskPath, "task.md"),
        contentHash: hash("Inspect the sources.\n"),
      },
      { path: join(taskPath, contextFilename), contentHash: null },
    ],
    ...(gitSelection
      ? { sourceSelection: { kind: "git", fingerprint: null } }
      : {}),
  };
  let projectConfigurationProtection = null;
  if (configuration) {
    const path = join(projectPath, "runner.json");
    await writeFile(path, '{"schemaVersion":1}\n');
    const selected = await loadProjectConfiguration({
      configurationPath: path,
      projectPath,
      inspectPath: (request) => workspace.inspectPath(request),
      workspaceKind: "directory",
      runnerConfiguration: parseRunnerConfiguration('{"schemaVersion":1}'),
    });
    projectConfigurationProtection = selected.protection;
    policy.configurationPaths.push(path);
    admission.inputs.push({
      path,
      contentHash: selected.protection.contentHash,
    });
  }
  let alive = new Set([4001, 4002]);
  const options = {
    stateRoot,
    hostName: "fixture-host",
    processId: 4001,
    processIsAlive: (pid) => alive.has(pid),
    processIdentity: async (pid) => ({ bootId, startTicks: String(pid) }),
    onTransitionBoundary,
  };
  const store = createRunStore(options);
  const input = {
    pipelineId: "sample",
    pipelineStateVersion: 1,
    projectPath,
    taskPath,
    workspacePreparation: admission,
    projectConfigurationProtection,
    hashes: { task: hash("Inspect the sources.\n") },
    roles: { auditor: { backend: "codex", model: null } },
    pipelineState: {
      workflowState: "CLARIFY",
      settings: { mode: "independent" },
    },
  };
  const created = await store.createRun(input);
  const worktreeLease = await store.acquireWorktreeLease(
    projectPath,
    created.state.runId,
  );
  const handles = [worktreeLease, created.lease];
  t.after(async () => {
    for (const handle of handles) await handle.release().catch(() => {});
    await rm(root, { recursive: true, force: true });
  });
  async function capture(pending) {
    const {
      kind,
      workspacePath,
      stateRoot: _state,
      taskPath: _task,
      ...paths
    } = pending.policy;
    return bindWorkspace({
      selection: { kind, lease: "exclusive", ...paths },
      projectPath,
      taskPath,
      stateRoot,
      workspace,
      taskInputs: { context: { filename: contextFilename, optional: true } },
    });
  }
  return {
    store,
    created,
    worktreeLease,
    options,
    input,
    admission,
    root,
    projectPath,
    taskPath,
    capture,
    async prepare(overrides = {}) {
      return store.captureWorkspacePreparation(created.lease, {
        worktreeLease,
        expectedRevision: (await store.loadRun(created.state.runId)).revision,
        capture,
        ...overrides,
      });
    },
    async replaceOwner() {
      alive.delete(4001);
      const replacement = createRunStore({ ...options, processId: 4002 });
      const lease = await replacement.acquireRunLease(created.state.runId);
      const workspaceLease = await replacement.acquireWorktreeLease(
        projectPath,
        created.state.runId,
      );
      handles.unshift(workspaceLease, lease);
      return { store: replacement, lease, worktreeLease: workspaceLease };
    },
  };
}

test("admits frozen preparation before capture and publishes only the complete binding", async (t) => {
  const f = await fixture(t);
  const { state } = f.created;
  assert.equal(state.workspace, null);
  assert.equal(state.preparation, null);
  assert.equal(state.activeTurn, null);
  assert.ok(
    state.workspacePreparation.rootBindings.some(
      ({ path }) => path === f.options.stateRoot,
    ),
  );
  const saved = structuredClone(state.workspacePreparation);
  f.admission.policy.inputPaths.length = 0;
  f.admission.inputs[0].contentHash = hash("changed");
  assert.deepEqual(
    (await f.store.loadRun(state.runId)).workspacePreparation,
    saved,
  );
  for (const patch of [
    { pipelineState: { ...state.pipelineState, workflowState: "DISCOVER" } },
    { hashes: { task: hash("changed") } },
    { pipelineState: { ...state.pipelineState, settings: { mode: "lazy" } } },
    { workspacePreparation: null },
    { activeTurn: { role: "auditor", phase: "clarify" } },
  ])
    await assert.rejects(f.store.transitionRun(f.created.lease, patch));
  await assert.rejects(
    f.store.writeRunArtifact(f.created.lease, "report.md", "partial"),
    { code: "ERR_WORKSPACE_PREPARATION_PENDING" },
  );
  await assert.rejects(
    f.store.recordChildSession(f.created.lease, {
      role: "auditor",
      sessionId: "child",
    }),
    { code: "ERR_WORKSPACE_PREPARATION_PENDING" },
  );
  const prepared = await f.prepare({
    capture: async (pending) => {
      assert.deepEqual(pending, saved);
      assert.ok(Object.isFrozen(pending.policy.inputPaths));
      assert.equal((await f.store.loadRun(state.runId)).workspace, null);
      return f.capture(pending);
    },
  });
  assert.equal(prepared.workspacePreparation, null);
  assert.equal(prepared.workspace.kind, "directory");
  assert.deepEqual(prepared.workspace.policy, saved.policy);
  assert.deepEqual(prepared.workspace.absentInputPaths, [
    join(f.taskPath, "context.md"),
  ]);
  assert.deepEqual(prepared.hashes, state.hashes);
  assert.equal(prepared.pipelineState.workflowState, "CLARIFY");
  assert.deepEqual(
    (await f.store.loadRunHistory(state.runId)).events.map(
      ({ activity }) => activity.kind,
    ),
    ["created", "captured"],
  );
  await assert.rejects(f.prepare(), {
    code: "ERR_WORKSPACE_PREPARATION_CHANGED",
  });
});

test("rejects malformed admissions and complete bindings without changing the checkpoint", async (t) => {
  const f = await fixture(t);
  for (const change of [
    { authority: true },
    { leasePath: f.taskPath },
    {
      inputs: [
        { path: join(f.taskPath, "task.md"), contentHash: hash("wrong") },
      ],
    },
    { inputs: Array(257).fill(f.admission.inputs[0]) },
    {
      inputs: [
        {
          path: join(f.projectPath, "source.txt"),
          contentHash: hash("source\n"),
        },
      ],
    },
    { policy: { ...f.admission.policy, stateRoot: f.projectPath } },
    { policy: { ...f.admission.policy, excludePaths: ["../outside"] } },
  ])
    await assert.rejects(
      f.store.createRun({
        ...f.input,
        workspacePreparation: { ...f.admission, ...change },
      }),
    );
  const binding = await f.capture(f.created.state.workspacePreparation);
  for (const change of [
    { protectedFingerprint: null },
    { leasePath: f.taskPath },
    { absentInputPaths: [] },
    { policy: { ...binding.policy, inputPaths: [] } },
    { kind: "git", policy: null },
  ])
    await assert.rejects(
      f.prepare({ capture: async () => ({ ...binding, ...change }) }),
    );
  assert.deepEqual(
    await f.store.loadRun(f.created.state.runId),
    f.created.state,
  );
  await writeFile(join(f.taskPath, "task.md"), "x".repeat(1024 * 1024 + 1));
  await assert.rejects(
    f.store.createRun({
      ...f.input,
      workspacePreparation: {
        ...f.admission,
        inputs: [
          {
            path: join(f.taskPath, "task.md"),
            contentHash: hash("x".repeat(1024 * 1024 + 1)),
          },
        ],
      },
    }),
    { code: "ERR_WORKSPACE_PATH" },
  );
});

test("journal replay rejects invalid completion and changes to a frozen selection", async (t) => {
  for (const alteration of [
    "removal",
    "absent-inputs",
    "replacement",
    "late-admission",
  ]) {
    const f = await fixture(t);
    await f.prepare();
    const history = structuredClone(
      (await f.store.loadRunHistory(f.created.state.runId)).events,
    );
    if (alteration === "removal") history[1].activity.kind = "partial";
    else if (alteration === "absent-inputs")
      history[1].state.workspace.absentInputPaths = [];
    else {
      history[1].state.workspace = null;
      history[1].state.workspacePreparation = structuredClone(
        f.created.state.workspacePreparation,
      );
      history[1].activity.kind = "progress";
      if (alteration === "replacement")
        history[1].state.workspacePreparation.policy.excludePaths = ["opaque"];
      else history[0].state.workspacePreparation = null;
    }
    await writeFile(
      join(f.created.directoryPath, "events.jsonl"),
      history.map((event) => JSON.stringify(event)).join("\n") + "\n",
    );
    await writeFile(
      join(f.created.directoryPath, "state.json"),
      JSON.stringify(history[1].state),
    );
    const cold = createRunStore(f.options);
    await assert.rejects(cold.loadRun(f.created.state.runId), {
      code: "ERR_INVALID_EVENT_LOG",
    });
  }
});

test("interrupted capture is discarded and replacement ownership recaptures frozen declarations", async (t) => {
  const f = await fixture(t);
  let partial;
  await assert.rejects(
    f.prepare({
      capture: async (pending) => {
        partial = await f.capture(pending);
        throw new Error("Interrupted capture.");
      },
    }),
    /Interrupted capture/u,
  );
  assert.ok(partial.protectedFingerprint);
  assert.deepEqual(
    await f.store.loadRun(f.created.state.runId),
    f.created.state,
  );
  const replacement = await f.replaceOwner();
  let captures = 0;
  const recovered = await replacement.store.captureWorkspacePreparation(
    replacement.lease,
    {
      worktreeLease: replacement.worktreeLease,
      expectedRevision: 1,
      capture: async (pending) => {
        captures++;
        assert.deepEqual(pending, f.created.state.workspacePreparation);
        return f.capture(pending);
      },
    },
  );
  assert.equal(captures, 1);
  assert.equal(recovered.workspacePreparation, null);
  assert.equal(recovered.preparation, null);
});

test("selected configuration evidence is mandatory and rechecked after capture", async (t) => {
  const f = await fixture(t, { configuration: true });
  const configurationPath = f.input.projectConfigurationProtection.path;
  await assert.rejects(
    f.store.createRun({
      ...f.input,
      workspacePreparation: {
        ...f.admission,
        inputs: f.admission.inputs.filter(
          ({ path }) => path !== configurationPath,
        ),
      },
    }),
    { code: "ERR_WORKSPACE_PREPARATION_CHANGED" },
  );
  await assert.rejects(
    f.prepare({
      capture: async (pending) => {
        const binding = await f.capture(pending);
        await writeFile(configurationPath, '{"schemaVersion":1} \n');
        return binding;
      },
    }),
    { code: "ERR_WORKSPACE_PREPARATION_CHANGED" },
  );
  assert.equal((await f.store.loadRun(f.created.state.runId)).workspace, null);
});

test("journal recovery finishes an interrupted complete publication exactly once", async (t) => {
  let interrupt = false;
  const f = await fixture(t, {
    onTransitionBoundary: (point) => {
      if (interrupt && point === "event-appended") {
        interrupt = false;
        throw new Error("Interrupted publication.");
      }
    },
  });
  interrupt = true;
  await assert.rejects(f.prepare(), /Interrupted publication/u);
  const snapshot = JSON.parse(
    await readFile(join(f.created.directoryPath, "state.json"), "utf8"),
  );
  assert.ok(snapshot.workspacePreparation);
  assert.equal(snapshot.workspace, null);
  const replacement = await f.replaceOwner();
  const recovered = await replacement.store.recoverRun(replacement.lease);
  assert.equal(recovered.workspacePreparation, null);
  assert.equal(recovered.workspace.kind, "directory");
  assert.equal(recovered.revision, 2);
  assert.equal(
    (await replacement.store.loadRunHistory(recovered.runId)).events.filter(
      ({ activity }) => activity?.kind === "captured",
    ).length,
    1,
  );
});

test("source selection is journaled once before capture and survives interrupted publication without reselection", async (t) => {
  let interrupt = false;
  const f = await fixture(t, {
    gitSelection: true,
    onTransitionBoundary(point) {
      if (interrupt && point === "event-appended") {
        interrupt = false;
        throw new Error("Interrupted selection publication.");
      }
    },
  });
  const selection = {
    policy: {
      ...f.admission.policy,
      inspectionPaths: [join(f.projectPath, "source.txt")],
      inspectionFilesOnly: true,
    },
    sourceSelection: { kind: "git", fingerprint: hash("membership") },
  };
  for (const selected of [
    { ...selection, policy: { ...selection.policy, inputPaths: [] } },
    { ...selection, sourceSelection: { kind: "git", fingerprint: null } },
  ])
    await assert.rejects(
      f.prepare({
        select: async () => selected,
        capture: () => assert.fail("Malformed selection must not capture."),
      }),
    );
  assert.deepEqual(
    await f.store.loadRun(f.created.state.runId),
    f.created.state,
  );
  interrupt = true;
  await assert.rejects(
    f.prepare({
      select: async () => selection,
      capture: () => assert.fail("Interrupted selection must not capture."),
    }),
    /Interrupted selection publication/u,
  );
  const replacement = await f.replaceOwner();
  const recovered = await replacement.store.recoverRun(replacement.lease);
  assert.equal(recovered.workspace, null);
  assert.deepEqual(
    recovered.workspacePreparation.sourceSelection,
    selection.sourceSelection,
  );
  const completed = await replacement.store.captureWorkspacePreparation(
    replacement.lease,
    {
      worktreeLease: replacement.worktreeLease,
      expectedRevision: recovered.revision,
      select: () =>
        assert.fail("Reconstruction must not replace frozen membership."),
      capture: (pending) =>
        captureWorkspacePreparation(
          pending,
          createWorkspaceService(),
          undefined,
          {
            selectSources: async ({ expectedSelectionFingerprint }) => {
              assert.equal(
                expectedSelectionFingerprint,
                selection.sourceSelection.fingerprint,
              );
              return {
                projectPath: f.projectPath,
                inspection: {
                  inspectionPaths: selection.policy.inspectionPaths,
                  inspectionFilesOnly: true,
                },
              };
            },
          },
        ),
    },
  );
  assert.deepEqual(
    completed.workspace.sourceSelection,
    selection.sourceSelection,
  );
  const history = (await replacement.store.loadRunHistory(completed.runId))
    .events;
  assert.deepEqual(
    history.map(({ activity }) => activity.kind),
    ["created", "selected", "captured"],
  );
  const corrupted = structuredClone(history);
  corrupted[1].state.workspacePreparation.sourceSelection.fingerprint =
    hash("replacement");
  await writeFile(
    join(f.created.directoryPath, "events.jsonl"),
    corrupted.map((event) => JSON.stringify(event)).join("\n") + "\n",
  );
  await writeFile(
    join(f.created.directoryPath, "state.json"),
    JSON.stringify(completed),
  );
  await assert.rejects(createRunStore(f.options).loadRun(completed.runId), {
    code: "ERR_INVALID_EVENT_LOG",
  });
});

test("stale captures and a replaced execution owner cannot publish", async (t) => {
  const f = await fixture(t);
  await assert.rejects(
    f.prepare({
      capture: async (pending) => {
        const binding = await f.capture(pending);
        await f.store.transitionRun(
          f.created.lease,
          {},
          {
            activity: {
              actor: "runner",
              phase: "workspace-preparation",
              kind: "progress",
              message: "Capture in progress.",
            },
          },
        );
        return binding;
      },
    }),
    { code: "ERR_RUN_REVISION_CHANGED" },
  );
  assert.ok(
    (await f.store.loadRun(f.created.state.runId)).workspacePreparation,
  );
  let replacement;
  await assert.rejects(
    f.prepare({
      capture: async (pending) => {
        const binding = await f.capture(pending);
        replacement = await f.replaceOwner();
        return binding;
      },
    }),
    { code: "ERR_INVALID_RUN_LEASE" },
  );
  const recovered = await replacement.store.captureWorkspacePreparation(
    replacement.lease,
    {
      worktreeLease: replacement.worktreeLease,
      expectedRevision: 2,
      capture: f.capture,
    },
  );
  assert.equal(recovered.workspacePreparation, null);
});

test("input changes and substituted roots reject before capture", async (t) => {
  const f = await fixture(t);
  const capture = () =>
    assert.fail("Changed admission must not reach recursive capture.");
  await writeFile(join(f.taskPath, "context.md"), "new input\n");
  await assert.rejects(f.prepare({ capture }), {
    code: "ERR_WORKSPACE_PREPARATION_CHANGED",
  });
  await rm(join(f.taskPath, "context.md"));
  await writeFile(join(f.taskPath, "task.md"), "changed input\n");
  await assert.rejects(f.prepare({ capture }), {
    code: "ERR_WORKSPACE_PREPARATION_CHANGED",
  });
  await rename(f.projectPath, join(f.root, "retained-project"));
  await mkdir(f.projectPath);
  await assert.rejects(f.prepare({ capture }), {
    code: "ERR_WORKSPACE_PREPARATION_CHANGED",
  });
  assert.equal((await f.store.loadRun(f.created.state.runId)).workspace, null);
});

test("recovery requires the unchanged parent binding of an absent nested input", async (t) => {
  const f = await fixture(t, { contextFilename: "optional/context.md" });
  const parentPath = join(f.taskPath, "optional");
  assert.ok(
    f.created.state.workspacePreparation.rootBindings.some(
      ({ path }) => path === parentPath,
    ),
  );
  await rename(parentPath, join(f.taskPath, "retained-optional"));
  await mkdir(parentPath);
  const replacement = await f.replaceOwner();
  await assert.rejects(
    replacement.store.captureWorkspacePreparation(replacement.lease, {
      worktreeLease: replacement.worktreeLease,
      expectedRevision: 1,
      capture: () =>
        assert.fail("A substituted input parent grants no capture authority."),
    }),
    { code: "ERR_WORKSPACE_PREPARATION_CHANGED" },
  );
  assert.deepEqual(
    await replacement.store.loadRun(f.created.state.runId),
    f.created.state,
  );

  const event = JSON.parse(
    await readFile(join(f.created.directoryPath, "events.jsonl"), "utf8"),
  );
  event.state.workspacePreparation.rootBindings =
    event.state.workspacePreparation.rootBindings.filter(
      ({ path }) => path !== parentPath,
    );
  await writeFile(
    join(f.created.directoryPath, "events.jsonl"),
    JSON.stringify(event) + "\n",
  );
  await writeFile(
    join(f.created.directoryPath, "state.json"),
    JSON.stringify(event.state),
  );
  const cold = createRunStore(f.options);
  await assert.rejects(cold.loadRun(f.created.state.runId), {
    code: "ERR_INVALID_RUN_STATE",
  });
});

test("the canonical workspace lease must match and stay current before publication", async (t) => {
  const f = await fixture(t);
  const wrongLease = await f.store.acquireWorktreeLease(
    f.taskPath,
    f.created.state.runId,
  );
  try {
    await assert.rejects(
      f.prepare({
        worktreeLease: wrongLease,
        capture: () =>
          assert.fail("A different exclusion key grants no capture authority."),
      }),
      { code: "ERR_WORKSPACE_PREPARATION_CHANGED" },
    );
  } finally {
    await wrongLease.release();
  }
  const leasePath = join(
    f.options.stateRoot,
    "worktrees",
    hash(f.projectPath),
    ".lease",
  );
  const original = await readFile(leasePath, "utf8");
  try {
    await assert.rejects(
      f.prepare({
        capture: async (pending) => {
          const binding = await f.capture(pending);
          await writeFile(
            leasePath,
            JSON.stringify({ ...JSON.parse(original), token: randomUUID() }),
          );
          return binding;
        },
      }),
      { code: "ERR_INVALID_WORKTREE_LEASE" },
    );
    assert.deepEqual(
      await f.store.loadRun(f.created.state.runId),
      f.created.state,
    );
  } finally {
    await writeFile(leasePath, original);
  }
  assert.equal((await f.prepare()).workspacePreparation, null);
});

for (const kind of ["pause_requested", "cancel_requested"]) {
  test(`${kind} remains publishable during capture and preserves the pending selection`, async (t) => {
    const f = await fixture(t);
    const started = Promise.withResolvers();
    const release = Promise.withResolvers();
    const abort = new AbortController();
    const preparing = assert.rejects(
      f.prepare({
        signal: abort.signal,
        capture: async (pending) => {
          const result = await f.capture(pending);
          started.resolve();
          await release.promise;
          return result;
        },
      }),
      /Capture aborted/u,
    );
    await started.promise;
    await f.store.requestOperatorStop({
      runId: f.created.state.runId,
      kind,
      expectedRevision: 1,
      idempotencyKey: `workspace-${kind}`,
    });
    abort.abort(new Error("Capture aborted."));
    release.resolve();
    await preparing;
    const current = await f.store.loadRun(f.created.state.runId);
    const canceled = kind === "cancel_requested";
    const stopped = await f.store.completeOperatorStop(f.created.lease, {
      requestId: current.stopRequest.requestId,
      patch: {
        pipelineState: {
          ...current.pipelineState,
          workflowState: canceled ? "CANCELED" : "WAITING_FOR_USER",
        },
        pause: {
          reason: canceled ? "operator_canceled" : "operator_paused",
          operatorResume: {
            workflowState: "CLARIFY",
            pause: null,
            activeTurn: null,
          },
        },
      },
    });
    assert.deepEqual(
      stopped.workspacePreparation,
      f.created.state.workspacePreparation,
    );
    assert.equal(stopped.workspace, null);
    await f.worktreeLease.release();
    await f.created.lease.release();
    const replacement = await f.replaceOwner();
    if (canceled) {
      await assert.rejects(
        replacement.store.captureWorkspacePreparation(replacement.lease, {
          worktreeLease: replacement.worktreeLease,
          expectedRevision: stopped.revision,
          capture: f.capture,
        }),
        { code: "ERR_RUN_CANCELED" },
      );
    } else {
      const resumed = await replacement.store.transitionRun(replacement.lease, {
        pipelineState: { ...stopped.pipelineState, workflowState: "CLARIFY" },
        pause: null,
      });
      const prepared = await replacement.store.captureWorkspacePreparation(
        replacement.lease,
        {
          worktreeLease: replacement.worktreeLease,
          expectedRevision: resumed.revision,
          capture: f.capture,
        },
      );
      assert.equal(prepared.workspacePreparation, null);
    }
  });
}

test("legacy absence migrates without inventing preparation or changing completed bindings", async (t) => {
  const f = await fixture(t);
  const prepared = await f.prepare();
  await f.worktreeLease.release();
  await f.created.lease.release();
  const legacy = {
    ...prepared,
    schemaVersion: 24,
    revision: 1,
    updatedAt: prepared.createdAt,
    runtimeCompatibility: { runnerVersion: 1, runStateVersion: 24 },
  };
  delete legacy.workspacePreparation;
  const event = {
    schemaVersion: 24,
    revision: 1,
    runId: legacy.runId,
    recordedAt: legacy.createdAt,
    state: legacy,
    activity: {
      actor: "runner",
      phase: "run",
      kind: "created",
      message: "Run created.",
    },
  };
  await writeFile(
    join(f.created.directoryPath, "state.json"),
    JSON.stringify(legacy),
  );
  await writeFile(
    join(f.created.directoryPath, "events.jsonl"),
    JSON.stringify(event) + "\n",
  );
  const replacement = await f.replaceOwner();
  const loaded = await replacement.store.loadRun(legacy.runId);
  assert.equal(loaded.workspacePreparation, null);
  const migrated = await replacement.store.migrateRun(
    replacement.lease,
    {
      pipelineState: legacy.pipelineState,
      pipelineStateVersion: legacy.pipelineStateVersion,
    },
    {
      activity: {
        actor: "runner",
        phase: "runtime",
        kind: "migrated",
        message: "Migrated common envelope.",
      },
    },
  );
  assert.equal(migrated.schemaVersion, RUN_STATE_SCHEMA_VERSION);
  assert.equal(migrated.workspacePreparation, null);
  assert.deepEqual(migrated.workspace, prepared.workspace);
  assert.deepEqual(migrated.hashes, prepared.hashes);
  assert.equal(
    (await replacement.store.loadRunHistory(legacy.runId)).events[0]
      .schemaVersion,
    24,
  );
});
