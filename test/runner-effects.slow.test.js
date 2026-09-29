import assert from "node:assert/strict";
import { cp, mkdir, mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { after, before } from "node:test";

import {
  createGitService,
  createMcpControlPlane,
  createRunStore,
} from "../src/index.js";
import { resolveStopBoundary } from "../src/pipeline-registry.js";
import {
  createArbiterAdapter,
  createExecutionAdapter,
  createFixture,
  executeFile,
  PLAN,
  runnerFor,
  RUNNER_CONFIGURATION,
} from "./support/index.js";

const SECOND_PLAN = `${PLAN}

## Commit 2: fix(test): refine behavior

Refine the behavior.
`;
const checkpointWorkspaces = [];
let oneStepCheckpoint;
let twoStepCheckpoint;

async function removeCopiedLeases(directoryPath) {
  const entries = await readdir(directoryPath, { withFileTypes: true });
  await Promise.all(
    entries.map(async (entry) => {
      const path = join(directoryPath, entry.name);
      if (entry.isDirectory()) {
        await removeCopiedLeases(path);
      } else if ([".lease", ".lease-reclaiming"].includes(entry.name)) {
        await rm(path, { force: true });
      }
    }),
  );
}

async function createCommitCheckpoint(plan) {
  const workspace = await mkdtemp(
    join(tmpdir(), "agent-runner-effect-checkpoint-"),
  );
  checkpointWorkspaces.push(workspace);
  const fixture = {
    projectPath: join(workspace, "project"),
    stateRoot: join(workspace, "state"),
    taskPath: join(workspace, "task"),
    workspace,
  };
  const stateSnapshot = join(workspace, "prepared-state");
  const configPath = join(
    fixture.projectPath,
    "LOCAL_ARTIFACTS",
    "agent-runner.json",
  );
  await Promise.all([
    mkdir(join(fixture.projectPath, "LOCAL_ARTIFACTS"), { recursive: true }),
    mkdir(fixture.taskPath),
  ]);
  await executeFile("git", ["init", "-q", fixture.projectPath]);
  await Promise.all([
    writeFile(join(fixture.projectPath, ".gitignore"), "/LOCAL_ARTIFACTS/\n"),
    writeFile(
      join(fixture.projectPath, "source.js"),
      "export const value = 0;\n",
    ),
    writeFile(configPath, '{"schemaVersion":1}\n'),
    writeFile(join(fixture.taskPath, "task.md"), "Implement the behavior.\n"),
    writeFile(join(fixture.taskPath, "plan.md"), plan),
  ]);
  for (const args of [
    ["config", "user.name", "Test"],
    ["config", "user.email", "test@example.com"],
    ["add", ".gitignore", "source.js"],
    ["commit", "-qm", "chore(test): initialize"],
  ]) {
    await executeFile("git", ["-C", fixture.projectPath, ...args]);
  }
  const initialHead = (
    await executeFile("git", ["-C", fixture.projectPath, "rev-parse", "HEAD"])
  ).stdout.trim();
  const git = createGitService();
  const store = createRunStore({
    stateRoot: fixture.stateRoot,
    resolveStopBoundary,
  });
  let captured = false;
  const runner = runnerFor(
    fixture,
    { codex: createExecutionAdapter() },
    {
      runStore: store,
      git: {
        ...git,
        async prepareCommit(options) {
          return git.prepareCommit({
            ...options,
            persistPendingCommit: async (authorization) => {
              await options.persistPendingCommit(authorization);
              if (!captured) {
                captured = true;
                // Reuse the real workflow's durable commit boundary without
                // replaying its clarification, bootstrap, and review turns.
                await cp(fixture.stateRoot, stateSnapshot, {
                  recursive: true,
                });
                const current = await store.loadRun(runId);
                await store.requestOperatorStop({
                  runId,
                  kind: "pause_requested",
                  timing: "after-current-commit",
                  expectedRevision: current.revision,
                  idempotencyKey: "checkpoint-capture",
                });
              }
            },
          });
        },
      },
    },
  );
  const runId = (
    await runner.create({
      pipelineId: "plan-execution",
      projectPath: fixture.projectPath,
      taskPath: fixture.taskPath,
      proactiveClarification: false,
      roleOverrides: {},
      sourceSession: null,
    })
  ).run.runId;
  const completed = (await runner.resume({ runId, action: null })).run;
  assert.equal(completed.pause.reason, "operator_paused");
  assert.equal(completed.pipelineState.completedCommits.length, 1);
  assert.equal(captured, true);
  await removeCopiedLeases(stateSnapshot);

  return {
    async restore() {
      await executeFile("git", [
        "-C",
        fixture.projectPath,
        "reset",
        "--hard",
        initialHead,
      ]);
      await rm(join(fixture.projectPath, "feature.js"), { force: true });
      await writeFile(
        join(fixture.projectPath, "feature.js"),
        "export const value = 1;\n",
      );
      await rm(fixture.stateRoot, { recursive: true, force: true });
      await cp(stateSnapshot, fixture.stateRoot, { recursive: true });
      const restored = await createRunStore({
        stateRoot: fixture.stateRoot,
        resolveStopBoundary,
      }).loadRun(runId);
      assert.equal(restored.pipelineState.workflowState, "COMMIT");
      assert.equal(restored.pipelineState.pendingCommit.status, "prepared");
      assert.equal(restored.pipelineState.currentStep, 1);
      assert.deepEqual(restored.pipelineState.completedCommits, []);
      assert.equal(restored.stopRequest, null);
      assert.equal(restored.activeTurn, null);
      assert.equal(restored.executionProcess, null);
      assert.equal(restored.executionResource, null);
      return { ...fixture, configPath, runId };
    },
  };
}

before(async () => {
  oneStepCheckpoint = await createCommitCheckpoint(PLAN);
  twoStepCheckpoint = await createCommitCheckpoint(SECOND_PLAN);
});

after(async () => {
  await Promise.all(
    checkpointWorkspaces.map((workspace) =>
      rm(workspace, { recursive: true, force: true }),
    ),
  );
});

test("dispatches plan execution through the root Git and state services", async (t) => {
  const fixture = await createFixture(t);
  await Promise.all([
    writeFile(join(fixture.projectPath, ".gitignore"), "/LOCAL_ARTIFACTS/\n"),
    writeFile(
      join(fixture.projectPath, "source.js"),
      "export const value = 0;\n",
    ),
    writeFile(join(fixture.taskPath, "plan.md"), PLAN),
  ]);
  await executeFile("git", [
    "-C",
    fixture.projectPath,
    "config",
    "user.name",
    "Test User",
  ]);
  await executeFile("git", [
    "-C",
    fixture.projectPath,
    "config",
    "user.email",
    "test@example.com",
  ]);
  await executeFile("git", [
    "-C",
    fixture.projectPath,
    "add",
    ".gitignore",
    "source.js",
  ]);
  await executeFile("git", [
    "-C",
    fixture.projectPath,
    "commit",
    "-qm",
    "chore(test): initialize",
  ]);
  const adapter = createExecutionAdapter({ bootstrapDisagreement: true });
  const arbiter = createArbiterAdapter();
  const activities = [];
  const runner = runnerFor(
    fixture,
    { codex: adapter, claude: arbiter },
    {
      activities,
      configuration: {
        ...RUNNER_CONFIGURATION,
        profiles: {
          "codex-work": { backend: "codex", profile: "work" },
        },
        pipelines: {
          "plan-execution": {
            roles: { arbiter: { backend: "claude" } },
          },
        },
      },
    },
  );

  const result = await runner.run({
    pipelineId: "plan-execution",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    roleOverrides: { arbiter: { profile: "current" } },
    executionOverrides: {
      profile: "codex-work",
      model: "execution-model",
      contextSize: "200000",
    },
    sourceSession: null,
  });
  const { stdout } = await executeFile("git", [
    "-C",
    fixture.projectPath,
    "log",
    "-1",
    "--pretty=%s",
  ]);

  assert.equal(result.run.pipelineState.workflowState, "DONE");
  assert.equal(result.run.pipelineState.completedCommits.length, 1);
  assert.equal(stdout.trim(), "feat(test): add behavior");
  assert.equal(arbiter.probeCalls, 1);
  assert.equal(arbiter.calls.length, 1);
  assert.ok(adapter.calls.some(({ access }) => access === "local-commit"));
  assert.deepEqual(
    adapter.probes,
    Array.from({ length: 3 }, () => ({
      profile: "work",
      model: "execution-model",
      contextSize: "200000",
      effort: "current",
    })),
  );
  assert.ok(
    activities.some(
      ({ actor, phase, kind }) =>
        actor === "worker" && phase === "commit" && kind === "created",
    ),
  );
});

async function assertVerifiedCommitSettlement(t) {
  for (const drift of [false, true]) {
    await t.test(drift ? "configuration drift" : "next step", async () => {
      const checkpoint = drift ? oneStepCheckpoint : twoStepCheckpoint;
      const fixture = await checkpoint.restore();
      const store = createRunStore({
        stateRoot: fixture.stateRoot,
        resolveStopBoundary,
      });
      const git = createGitService();
      const delegate = createExecutionAdapter();
      let verifiedCalls = 0,
        commits = 0,
        callsAfterVerification = 0;
      let control, stopInput, receipt;
      const runner = runnerFor(
        fixture,
        {
          codex: {
            ...delegate,
            async run(request) {
              if (verifiedCalls > 0) callsAfterVerification += 1;
              if (request.access === "local-commit") {
                assert.equal(request.signal.aborted, false);
                commits += 1;
              }
              return delegate.run(request);
            },
          },
        },
        {
          runStore: store,
          git: {
            ...git,
            async consumeCommit(authorization, options) {
              const current = await store.loadRun(fixture.runId);
              stopInput = {
                runId: fixture.runId,
                timing: "after-current-commit",
                expectedRevision: current.revision,
                idempotencyKey: `deferred-stop-${drift}`,
              };
              receipt = await control.runPause(stopInput);
              return git.consumeCommit(authorization, options);
            },
            async verifyCommit(authorization) {
              const verified = await git.verifyCommit(authorization);
              verifiedCalls += 1;
              if (drift)
                await writeFile(
                  fixture.configPath,
                  '{"schemaVersion":1,"artifactRoot":"changed"}\n',
                );
              return verified;
            },
          },
        },
      );
      control = createMcpControlPlane({ runner, runStore: store });

      const stopped = (
        await runner.resume({ runId: fixture.runId, action: null })
      ).run;
      assert.deepEqual(await control.runPause(stopInput), receipt);
      assert.equal(stopped.pause.reason, "operator_paused");
      assert.equal(
        stopped.pause.operatorResume.workflowState,
        drift ? "WAITING_FOR_USER" : "IMPLEMENT",
      );
      if (drift)
        assert.equal(
          stopped.pause.operatorResume.pause.reason,
          "project_configuration_changed",
        );
      assert.equal(stopped.pipelineState.currentStep, drift ? null : 2);
      assert.equal(stopped.pipelineState.completedCommits.length, 1);
      assert.equal(
        stopped.pipelineState.repositoryBaseline.head,
        stopped.pipelineState.completedCommits[0],
      );
      assert.equal(stopped.pipelineState.pendingCommit, null);
      assert.equal(stopped.activeTurn, null);
      assert.equal(stopped.stopRequest.targetBoundary.step, 1);
      assert.equal(stopped.stopRequest.effectiveTiming, "after-current-commit");
      assert.equal(stopped.stopRequest.reconciledRevision, stopped.revision);
      assert.deepEqual(stopped.stopRequest.settlement, {
        kind: "commit",
        commit: stopped.pipelineState.completedCommits[0],
      });
      const status = await control.runStatus({ runId: fixture.runId });
      assert.equal(status.stop.state, "settled");
      assert.deepEqual(status.stop.settlement, stopped.stopRequest.settlement);
      const waited = await control.runWait({
        runId: fixture.runId,
        cursor: 0,
        timeoutMs: 0,
      });
      assert.deepEqual(waited.stop, status.stop);
      const activity = await control.runActivity({
        runId: fixture.runId,
        cursor: 0,
        limit: 100,
      });
      assert.ok(
        activity.activities.some((entry) => entry.stop?.state === "settled"),
      );
      assert.equal(verifiedCalls, 1);
      assert.equal(commits, 1);
      assert.equal(callsAfterVerification, 0);
      const history = await store.loadRunHistory(fixture.runId);
      const progress = history.events.filter(
        (event) => event.state.pipelineState.completedCommits.length > 0,
      );
      assert.ok(progress.length > 0);
      assert.equal(
        progress[0].state.stopRequest.reconciledRevision,
        progress[0].revision,
      );
    });
  }
}

test("interrupted verified checkpoint publication preserves progress without replaying the commit", async () => {
  const fixture = await oneStepCheckpoint.restore();
  let interrupt = true;
  const store = createRunStore({
    stateRoot: fixture.stateRoot,
    onTransitionBoundary: async (point) => {
      if (
        interrupt &&
        point === "event-appended" &&
        (await store.loadRun(fixture.runId)).pipelineState.completedCommits
          .length === 1
      ) {
        interrupt = false;
        throw new Error("verified publication interrupted");
      }
    },
  });
  const delegate = createExecutionAdapter();
  let commits = 0;
  const runner = runnerFor(
    fixture,
    {
      codex: {
        ...delegate,
        async run(request) {
          if (request.access === "local-commit") commits += 1;
          return delegate.run(request);
        },
      },
    },
    { runStore: store },
  );
  await assert.rejects(
    runner.resume({ runId: fixture.runId, action: null }),
    /verified publication interrupted/u,
  );
  const persisted = await store.loadRun(fixture.runId);
  assert.equal(persisted.pipelineState.workflowState, "DONE");
  assert.equal(persisted.pipelineState.completedCommits.length, 1);
  assert.equal(persisted.pipelineState.pendingCommit, null);
  assert.equal(
    (await runner.resume({ runId: fixture.runId, action: null })).run
      .pipelineState.workflowState,
    "DONE",
  );
  assert.equal(commits, 1);
});

test("commit-boundary capability requires a selected plan-execution step", async () => {
  // State-store coverage owns the stop kind, timing, rejection, and quiescent
  // matrix; runner stop coverage owns writable-content reconstruction.
  // Keep the pipeline-owned boundary policy at its direct deterministic seam.
  const fixture = await oneStepCheckpoint.restore();
  const run = await createRunStore({
    stateRoot: fixture.stateRoot,
    resolveStopBoundary,
  }).loadRun(fixture.runId);
  assert.deepEqual(resolveStopBoundary(run), {
    capability: "verified-commit-v1",
    step: 1,
    completedCommits: 0,
    baselineHead: run.pipelineState.repositoryBaseline.head,
  });
  assert.equal(
    resolveStopBoundary({
      ...run,
      pipelineState: { ...run.pipelineState, currentStep: null },
    }),
    null,
  );
  assert.equal(resolveStopBoundary({ ...run, pipelineId: "polishing" }), null);
});

test("deferred settlement publication recovers the final checkpoint without another commit", async () => {
  // The state-store suite owns the equivalent publication-boundary products.
  const fixture = await oneStepCheckpoint.restore();
  let interrupt = true;
  const store = createRunStore({
    stateRoot: fixture.stateRoot,
    resolveStopBoundary,
    onTransitionBoundary: async (point) => {
      if (
        interrupt &&
        point === "event-appended" &&
        (await store.loadRun(fixture.runId)).pipelineState.completedCommits
          .length === 1
      ) {
        interrupt = false;
        throw new Error("verified publication interrupted");
      }
    },
  });
  const git = createGitService();
  const delegate = createExecutionAdapter();
  let commits = 0,
    stopInput,
    receipt;
  const runner = runnerFor(
    fixture,
    {
      codex: {
        ...delegate,
        async run(request) {
          if (request.access === "local-commit") commits += 1;
          return delegate.run(request);
        },
      },
    },
    {
      runStore: store,
      git: {
        ...git,
        async consumeCommit(authorization, options) {
          const current = await store.loadRun(fixture.runId);
          stopInput = {
            runId: fixture.runId,
            kind: "pause_requested",
            timing: "after-current-commit",
            expectedRevision: current.revision,
            idempotencyKey: "publish-stop",
          };
          receipt = await store.requestOperatorStop(stopInput);
          return git.consumeCommit(authorization, options);
        },
      },
    },
  );
  await assert.rejects(
    runner.resume({ runId: fixture.runId, action: null }),
    /verified publication interrupted/u,
  );
  const persisted = await store.loadRun(fixture.runId);
  assert.deepEqual(await store.requestOperatorStop(stopInput), receipt);
  assert.equal(persisted.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(persisted.pause.operatorResume.workflowState, "DONE");
  assert.deepEqual(persisted.stopRequest.settlement, {
    kind: "commit",
    commit: persisted.pipelineState.completedCommits[0],
  });
  assert.equal(persisted.pipelineState.completedCommits.length, 1);
  assert.equal(persisted.pipelineState.pendingCommit, null);
  assert.equal(
    (await runner.resume({ runId: fixture.runId, action: null })).run
      .pipelineState.workflowState,
    "DONE",
  );
  assert.equal(commits, 1);
});

test("deferred cancellation recovers interrupted commit verification without invoking another effect", async () => {
  const fixture = await oneStepCheckpoint.restore();
  const store = createRunStore({
    stateRoot: fixture.stateRoot,
    resolveStopBoundary,
  });
  const git = createGitService();
  let verifications = 0;
  const delegate = createExecutionAdapter();
  let commits = 0;
  const runner = runnerFor(
    fixture,
    {
      codex: {
        ...delegate,
        async run(request) {
          if (request.access === "local-commit") commits += 1;
          return delegate.run(request);
        },
      },
    },
    {
      runStore: store,
      git: {
        ...git,
        async consumeCommit(authorization, options) {
          const current = await store.loadRun(fixture.runId);
          await store.requestOperatorStop({
            runId: fixture.runId,
            kind: "cancel_requested",
            timing: "after-current-commit",
            expectedRevision: current.revision,
            idempotencyKey: "cancel-commit",
          });
          return git.consumeCommit(authorization, options);
        },
        async verifyCommit(authorization) {
          verifications += 1;
          if (verifications === 1)
            throw new Error("Verification interrupted after effect");
          return git.verifyCommit(authorization);
        },
      },
    },
  );
  const stopped = (await runner.resume({ runId: fixture.runId, action: null }))
    .run;
  assert.equal(stopped.pipelineState.workflowState, "CANCELED");
  assert.equal(stopped.pipelineState.completedCommits.length, 1);
  assert.equal(stopped.pipelineState.pendingCommit, null);
  assert.equal(stopped.pause.operatorResume.workflowState, "DONE");
  assert.equal(
    (
      await executeFile("git", ["-C", fixture.projectPath, "rev-parse", "HEAD"])
    ).stdout.trim(),
    stopped.pipelineState.completedCommits[0],
  );
  await assert.rejects(runner.resume({ runId: fixture.runId, action: null }), {
    code: "ERR_RUN_CANCELED",
  });
  assert.equal(commits, 1);
  assert.equal(verifications, 2);
  assert.deepEqual(stopped.stopRequest.settlement, {
    kind: "commit",
    commit: stopped.pipelineState.completedCommits[0],
  });
});

test("deferred commit faults preserve authorization and account for effects exactly once", async (t) => {
  for (const [kind, fault] of [
    ["cancel_requested", "consumed"],
    ["pause_requested", "absent"],
    ["cancel_requested", "invalid"],
    ["pause_requested", "verification"],
  ]) {
    await t.test(`${kind}/${fault}`, async () => {
      const fixture = await oneStepCheckpoint.restore();
      const git = createGitService();
      const before = await git.snapshot({ projectPath: fixture.projectPath });
      let stopInput, receipt, retainedAuthorization;
      let publicationInterrupted = false,
        commits = 0,
        verifications = 0,
        forbidTurns = false;
      const store = createRunStore({
        stateRoot: fixture.stateRoot,
        resolveStopBoundary,
        async onTransitionBoundary(point) {
          if (
            publicationInterrupted ||
            point !== "event-appended" ||
            fault !== "consumed"
          )
            return;
          const current = await store.loadRun(fixture.runId);
          if (current.pipelineState.pendingCommit?.status === fault) {
            publicationInterrupted = true;
            retainedAuthorization =
              current.pipelineState.pendingCommit.authorization;
            throw new Error(`Interrupted ${fault} publication`);
          }
        },
      });
      const delegate = createExecutionAdapter();
      const adapter = {
        ...delegate,
        async run(request) {
          assert.equal(
            forbidTurns,
            false,
            "Recovery must not invoke another provider turn.",
          );
          if (request.access === "local-commit") {
            commits += 1;
            const current = await store.loadRun(fixture.runId);
            assert.equal(
              current.pipelineState.pendingCommit.status,
              "consumed",
            );
            if (fault === "absent")
              return {
                output: "No effect",
                structured: { ready: true },
                sessionId: request.session.id,
              };
            if (fault === "invalid")
              return delegate.run({
                ...request,
                commit: {
                  ...request.commit,
                  message: "fix(test): wrong authorized subject",
                },
              });
          }
          return delegate.run(request);
        },
      };
      const runtimeGit = {
        ...git,
        async consumeCommit(authorization, options) {
          if (stopInput === undefined) {
            const current = await store.loadRun(fixture.runId);
            stopInput = {
              runId: fixture.runId,
              kind,
              timing: "after-current-commit",
              expectedRevision: current.revision,
              idempotencyKey: "fault-stop",
            };
            receipt = await store.requestOperatorStop(stopInput);
          }
          return git.consumeCommit(authorization, options);
        },
        async verifyCommit(authorization) {
          verifications += 1;
          if (fault === "verification" && verifications === 1)
            throw new Error("Interrupted verification after effect");
          return git.verifyCommit(authorization);
        },
      };
      const openRunner = () =>
        runnerFor(
          fixture,
          { codex: adapter },
          {
            runStore: store,
            git: runtimeGit,
          },
        );
      const runner = openRunner();
      const stopped = (
        await runner.resume({ runId: fixture.runId, action: null })
      ).run;
      forbidTurns = true;
      const canceled = kind === "cancel_requested";
      assert.equal(
        stopped.pause.reason,
        canceled ? "operator_canceled" : "operator_paused",
      );
      assert.equal(stopped.stopRequest.reconciledRevision, stopped.revision);
      assert.deepEqual(await store.requestOperatorStop(stopInput), receipt);
      assert.equal(stopped.activeTurn, null);
      assert.equal(stopped.executionProcess, null);
      const after = await git.snapshot({ projectPath: fixture.projectPath });
      assert.equal(
        after.remoteConfigurationFingerprint,
        before.remoteConfigurationFingerprint,
      );
      assert.equal(after.identityFingerprint, before.identityFingerprint);
      if (fault === "consumed") {
        assert.equal(publicationInterrupted, true);
        assert.equal(commits, 0);
        assert.equal(after.head, before.head);
        assert.equal(stopped.pipelineState.pendingCommit.status, fault);
        assert.deepEqual(
          stopped.pipelineState.pendingCommit.authorization,
          retainedAuthorization,
        );
      } else {
        assert.equal(commits, 1);
        assert.equal(after.head === before.head, fault === "absent");
      }
      const verified = fault === "verification";
      assert.equal(
        stopped.pipelineState.completedCommits.length,
        verified ? 1 : 0,
      );
      assert.deepEqual(stopped.stopRequest.settlement, {
        kind: verified ? "commit" : "quiescent",
        commit: verified ? after.head : null,
      });
      if (verified) {
        assert.equal(verifications, 2);
        assert.equal(stopped.pipelineState.pendingCommit, null);
        assert.equal(stopped.pause.operatorResume.workflowState, "DONE");
      } else {
        assert.equal(stopped.pipelineState.pendingCommit.status, "consumed");
        assert.equal(
          stopped.pause.operatorResume.pause.reason,
          fault === "invalid" ? "commit_contract_violated" : "commit_failed",
        );
      }
      const history = await store.loadRunHistory(fixture.runId);
      const completed = history.events.filter(
        (event) => event.state.pipelineState.completedCommits.length > 0,
      );
      if (verified)
        assert.equal(
          completed[0].state.stopRequest.reconciledRevision,
          completed[0].revision,
        );
      const control = createMcpControlPlane({
        runner: openRunner(),
        runStore: store,
      });
      const publicState = await control.runStatus({ runId: fixture.runId });
      assert.doesNotMatch(
        JSON.stringify(publicState),
        /requestId|fault-stop|startTicks|bootId/u,
      );
      if (canceled) {
        await assert.rejects(
          openRunner().resume({ runId: fixture.runId, action: null }),
          {
            code: "ERR_RUN_CANCELED",
          },
        );
      } else {
        const restored = (
          await openRunner().resume({ runId: fixture.runId, action: null })
        ).run;
        if (verified)
          assert.equal(restored.pipelineState.workflowState, "DONE");
        else
          assert.deepEqual(restored.pause, stopped.pause.operatorResume.pause);
      }
      assert.equal(commits, fault === "consumed" ? 0 : 1);
    });
  }
});

// Configuration drift changes protected file identity, so this shared
// checkpoint is intentionally consumed only after every other restore.
test(
  "verified commit settlement stops before the next Worker and retains configuration blockers",
  assertVerifiedCommitSettlement,
);
