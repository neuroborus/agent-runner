import assert from "node:assert/strict";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import {
  createGitService,
  createMcpControlPlane,
  createRunStore,
  main,
} from "../src/index.js";
import { resolveStopBoundary } from "../src/pipeline-registry.js";
import {
  createArbiterAdapter,
  createExecutionAdapter,
  createFixture,
  executeFile,
  operatorFixture,
  PLAN,
  runnerFor,
  RUNNER_CONFIGURATION,
} from "./support/index.js";

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

test("verified commit settlement stops before the next Worker and retains configuration blockers", async (t) => {
  for (const [kind, steps, drift, timing = "immediate"] of [
    ["pause_requested", 1, false],
    ["cancel_requested", 2, false, "after-current-commit"],
    ["pause_requested", 1, true, "after-current-commit"],
  ]) {
    await t.test(`${kind}/${steps}/${drift}/${timing}`, async (t) => {
      const fixture = await operatorFixture(t, "plan-execution");
      if (steps === 2)
        await writeFile(
          join(fixture.taskPath, "plan.md"),
          `${PLAN}\n\n## Commit 2: fix(test): refine behavior\n\nRefine the behavior.\n`,
        );
      const configPath = join(
        fixture.projectPath,
        "LOCAL_ARTIFACTS",
        "agent-runner.json",
      );
      if (drift) {
        await mkdir(join(fixture.projectPath, "LOCAL_ARTIFACTS"));
        await writeFile(configPath, '{"schemaVersion":1}\n');
      }
      const store = createRunStore({
        stateRoot: fixture.stateRoot,
        resolveStopBoundary,
      });
      const git = createGitService();
      const delegate = createExecutionAdapter();
      let runId,
        verifiedCalls = 0,
        commits = 0,
        callsAfterVerification = 0;
      const runner = runnerFor(
        fixture,
        {
          codex: {
            ...delegate,
            async run(request) {
              if (
                timing === "after-current-commit" &&
                request.prompt.includes("Implement the changes described")
              ) {
                const current = await store.loadRun(runId);
                const control = createMcpControlPlane({
                  runner,
                  runStore: store,
                });
                const input = {
                  runId,
                  timing,
                  expectedRevision: current.revision,
                  idempotencyKey: "deferred-stop",
                };
                if (steps === 2) {
                  const stopRequest =
                    kind === "pause_requested"
                      ? control.runPause
                      : control.runCancel;
                  const receipt = await stopRequest(input);
                  assert.deepEqual(await stopRequest(input), receipt);
                } else {
                  let receiptOutput = "";
                  assert.equal(
                    await main(
                      [
                        kind === "pause_requested" ? "pause" : "cancel",
                        "--run",
                        runId,
                        "--timing",
                        timing,
                        "--expected-revision",
                        String(current.revision),
                        "--idempotency-key",
                        input.idempotencyKey,
                      ],
                      {
                        createCommandRunner: () => runner,
                        stdout: {
                          write: (text) => {
                            receiptOutput += text;
                          },
                        },
                        stderr: {
                          write: (text) => {
                            throw new Error(text);
                          },
                        },
                      },
                    ),
                    0,
                  );
                  assert.match(receiptOutput, /Stop target step: 1/u);
                }
                const pending = (await runner.status(runId)).run.stopRequest;
                assert.equal(pending.targetBoundary.step, 1);
                assert.equal(pending.effectiveTiming, timing);
                assert.deepEqual(
                  (await control.runStatus({ runId })).pendingStop,
                  {
                    kind,
                    revision: pending.acceptedRevision,
                    timing,
                    effectiveTiming: timing,
                    targetStep: 1,
                  },
                );
                let output = "";
                assert.equal(
                  await main(["status", "--run", runId], {
                    createCommandRunner: () => runner,
                    stdout: {
                      write: (text) => {
                        output += text;
                      },
                    },
                    stderr: {
                      write: (text) => {
                        throw new Error(text);
                      },
                    },
                  }),
                  0,
                );
                assert.match(output, /Stop timing: after-current-commit/u);
                assert.match(output, /Stop target step: 1/u);
                assert.equal(request.signal.aborted, false);
              }
              if (verifiedCalls > 0) callsAfterVerification += 1;
              if (request.access === "local-commit") commits += 1;
              return delegate.run(request);
            },
          },
        },
        {
          runStore: store,
          git: {
            ...git,
            async verifyCommit(authorization) {
              const verified = await git.verifyCommit(authorization);
              verifiedCalls += 1;
              const current = await store.loadRun(runId);
              if (timing === "immediate" && kind === "cancel_requested") {
                await store.requestOperatorStop({
                  runId,
                  kind: "pause_requested",
                  expectedRevision: current.revision,
                  idempotencyKey: "verified-pause",
                });
              }
              if (timing === "immediate")
                await store.requestOperatorStop({
                  runId,
                  kind,
                  expectedRevision: current.revision,
                  idempotencyKey: "verified-stop",
                });
              if (drift)
                await writeFile(
                  configPath,
                  '{"schemaVersion":1,"artifactRoot":"changed"}\n',
                );
              return verified;
            },
          },
        },
      );
      runId = (
        await runner.create({
          pipelineId: "plan-execution",
          projectPath: fixture.projectPath,
          taskPath: fixture.taskPath,
          proactiveClarification: false,
          roleOverrides: {},
          sourceSession: null,
        })
      ).run.runId;
      const stopped = (await runner.resume({ runId, action: null })).run;
      assert.equal(
        stopped.pause.reason,
        kind === "pause_requested" ? "operator_paused" : "operator_canceled",
      );
      assert.equal(
        stopped.pause.operatorResume.workflowState,
        drift ? "WAITING_FOR_USER" : steps === 1 ? "DONE" : "IMPLEMENT",
      );
      if (drift)
        assert.equal(
          stopped.pause.operatorResume.pause.reason,
          "project_configuration_changed",
        );
      assert.equal(stopped.pipelineState.currentStep, steps === 1 ? null : 2);
      assert.equal(stopped.pipelineState.completedCommits.length, 1);
      assert.equal(
        stopped.pipelineState.repositoryBaseline.head,
        stopped.pipelineState.completedCommits[0],
      );
      assert.equal(stopped.pipelineState.pendingCommit, null);
      assert.equal(stopped.activeTurn, null);
      assert.equal(stopped.stopRequest.reconciledRevision, stopped.revision);
      assert.deepEqual(stopped.stopRequest.settlement, {
        kind: "commit",
        commit: stopped.pipelineState.completedCommits[0],
      });
      const control = createMcpControlPlane({ runner, runStore: store });
      const status = await control.runStatus({ runId });
      assert.equal(status.stop.state, "settled");
      assert.deepEqual(status.stop.settlement, stopped.stopRequest.settlement);
      const waited = await control.runWait({ runId, cursor: 0, timeoutMs: 0 });
      assert.deepEqual(waited.stop, status.stop);
      const activity = await control.runActivity({
        runId,
        cursor: 0,
        limit: 100,
      });
      assert.ok(
        activity.activities.some((entry) => entry.stop?.state === "settled"),
      );
      assert.equal(verifiedCalls, 1);
      assert.equal(commits, 1);
      assert.equal(callsAfterVerification, 0);
      const history = await store.loadRunHistory(runId);
      const progress = history.events.filter(
        (event) => event.state.pipelineState.completedCommits.length > 0,
      );
      assert.ok(progress.length > 0);
      assert.equal(
        progress[0].state.stopRequest.reconciledRevision,
        progress[0].revision,
      );
      if (kind === "pause_requested" && steps === 1 && !drift) {
        assert.equal(
          (await runner.resume({ runId, action: null })).run.pipelineState
            .workflowState,
          "DONE",
        );
        assert.equal(callsAfterVerification, 0);
        const terminal = await store.loadRun(runId);
        await assert.rejects(
          runner.requestOperatorStop({
            runId,
            kind,
            timing: "after-current-commit",
            expectedRevision: terminal.revision,
            idempotencyKey: "after-done",
          }),
          { code: "ERR_RUN_TERMINAL" },
        );
      }
    });
  }
});

test("interrupted verified checkpoint publication preserves progress without replaying the commit", async (t) => {
  const fixture = await operatorFixture(t, "plan-execution");
  let interrupt = true;
  let runId;
  const store = createRunStore({
    stateRoot: fixture.stateRoot,
    onTransitionBoundary: async (point) => {
      if (
        interrupt &&
        point === "event-appended" &&
        runId !== undefined &&
        (await store.loadRun(runId)).pipelineState.completedCommits.length === 1
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
  runId = (
    await runner.create({
      pipelineId: "plan-execution",
      projectPath: fixture.projectPath,
      taskPath: fixture.taskPath,
      proactiveClarification: false,
      roleOverrides: {},
      sourceSession: null,
    })
  ).run.runId;
  await assert.rejects(
    runner.resume({ runId, action: null }),
    /verified publication interrupted/u,
  );
  const persisted = await store.loadRun(runId);
  assert.equal(persisted.pipelineState.workflowState, "DONE");
  assert.equal(persisted.pipelineState.completedCommits.length, 1);
  assert.equal(persisted.pipelineState.pendingCommit, null);
  assert.equal(
    (await runner.resume({ runId, action: null })).run.pipelineState
      .workflowState,
    "DONE",
  );
  assert.equal(commits, 1);
});

test("deferred stops settle quiescent failures and suspended steps without further turns", async (t) => {
  for (const [kind, outcome] of [
    ["pause_requested", "blocked"],
    ["cancel_requested", "failed"],
    ["pause_requested", "suspended"],
    ["pause_requested", "superseded"],
  ]) {
    await t.test(`${kind}/${outcome}`, async (t) => {
      const fixture = await operatorFixture(t, "plan-execution");
      const store = createRunStore({
        stateRoot: fixture.stateRoot,
        resolveStopBoundary,
      });
      const delegate = createExecutionAdapter();
      let runId,
        primaryTurns = 0,
        laterTurns = 0;
      const runner = runnerFor(
        fixture,
        {
          codex: {
            ...delegate,
            async run(request) {
              if (primaryTurns > 0) laterTurns += 1;
              if (!request.prompt.includes("Implement the changes described"))
                return delegate.run(request);
              primaryTurns += 1;
              if (outcome !== "suspended") {
                const current = await store.loadRun(runId);
                const control = createMcpControlPlane({
                  runner,
                  runStore: store,
                });
                await (
                  kind === "pause_requested"
                    ? control.runPause
                    : control.runCancel
                )({
                  runId,
                  timing: "after-current-commit",
                  expectedRevision: current.revision,
                  idempotencyKey: "deferred-fallback",
                });
                assert.equal(request.signal.aborted, false);
                if (outcome === "superseded") {
                  const aborted = new Promise((resolve) =>
                    request.signal.addEventListener("abort", resolve, {
                      once: true,
                    }),
                  );
                  await control.runCancel({
                    runId,
                    timing: "immediate",
                    expectedRevision: current.revision,
                    idempotencyKey: "immediate-cancel",
                  });
                  await aborted;
                  request.signal.throwIfAborted();
                }
              }
              await writeFile(
                join(request.cwd, "partial.js"),
                "export const partial = true;\n",
              );
              throw Object.assign(new Error("test checkpoint failure"), {
                code: "ERR_TEST_CHECKPOINT",
                recoverable: outcome !== "failed",
              });
            },
          },
        },
        { runStore: store },
      );
      runId = (
        await runner.create({
          pipelineId: "plan-execution",
          projectPath: fixture.projectPath,
          taskPath: fixture.taskPath,
          proactiveClarification: false,
          roleOverrides: {},
          sourceSession: null,
        })
      ).run.runId;
      let stopped = (await runner.resume({ runId })).run;
      if (outcome === "suspended") {
        assert.equal(stopped.pause.reason, "backend_unavailable");
        let output = "";
        assert.equal(
          await main(
            [
              kind === "pause_requested" ? "pause" : "cancel",
              "--run",
              runId,
              "--timing",
              "after-current-commit",
              "--expected-revision",
              String(stopped.revision),
              "--idempotency-key",
              "suspended-stop",
            ],
            {
              createCommandRunner: () => runner,
              stdout: {
                write: (text) => {
                  output += text;
                },
              },
              stderr: {
                write: (text) => {
                  throw new Error(text);
                },
              },
            },
          ),
          0,
        );
        assert.match(output, /Stop target step: 1/u);
        const control = createMcpControlPlane({ runner, runStore: store });
        assert.equal(
          (await control.runStatus({ runId })).stop.state,
          "applicable",
        );
        stopped = (await runner.resume({ runId })).run;
      }
      const canceled = kind === "cancel_requested" || outcome === "superseded";
      assert.equal(
        stopped.pipelineState.workflowState,
        canceled ? "CANCELED" : "WAITING_FOR_USER",
      );
      assert.equal(
        stopped.pause.reason,
        canceled ? "operator_canceled" : "operator_paused",
      );
      assert.deepEqual(stopped.stopRequest.settlement, {
        kind: "quiescent",
        commit: null,
      });
      assert.equal(stopped.pipelineState.completedCommits.length, 0);
      assert.equal(primaryTurns, 1);
      assert.equal(laterTurns, 0);
      if (outcome !== "superseded") {
        assert.equal(
          await readFile(join(fixture.projectPath, "partial.js"), "utf8"),
          "export const partial = true;\n",
        );
        assert.equal(
          stopped.pause.operatorResume.pause.code,
          "ERR_TEST_CHECKPOINT",
        );
        assert.equal(
          stopped.pause.operatorResume.pause.reason,
          outcome === "failed" ? "internal_failure" : "backend_unavailable",
        );
        assert.equal(
          stopped.pause.operatorResume.workflowState,
          outcome === "failed" ? "FAILED" : "WAITING_FOR_USER",
        );
      } else {
        assert.equal(stopped.stopRequest.effectiveTiming, "immediate");
      }
      if (!canceled) {
        const restored = (await runner.resume({ runId })).run;
        assert.equal(
          restored.pipelineState.workflowState,
          outcome === "failed" ? "FAILED" : "WAITING_FOR_USER",
        );
        assert.equal(laterTurns, 0);
      }
    });
  }
});

test("commit-boundary capability rejects unselected steps and an unsupported pipeline", async (t) => {
  for (const pipelineId of ["plan-execution", "polishing"]) {
    await t.test(pipelineId, async (t) => {
      const fixture = await operatorFixture(t, pipelineId);
      const store = createRunStore({
        stateRoot: fixture.stateRoot,
        resolveStopBoundary,
      });
      const delegate = createExecutionAdapter();
      const runner = runnerFor(
        fixture,
        {
          codex: {
            ...delegate,
            async run(request) {
              if (
                request.prompt.includes("Provide a concise bootstrap summary")
              ) {
                const current = await store.loadRun(run.runId);
                await assert.rejects(
                  runner.requestOperatorStop({
                    runId: run.runId,
                    kind: "pause_requested",
                    timing: "after-current-commit",
                    expectedRevision: current.revision,
                    idempotencyKey: "live-bootstrap",
                  }),
                  { code: "ERR_STOP_BOUNDARY_UNSUPPORTED" },
                );
                throw Object.assign(new Error("Bootstrap suspended"), {
                  recoverable: true,
                });
              }
              return delegate.run(request);
            },
          },
        },
        { runStore: store },
      );
      const { run } = await runner.create({
        pipelineId,
        projectPath: fixture.projectPath,
        taskPath: fixture.taskPath,
        proactiveClarification: false,
        roleOverrides: {},
        sourceSession: null,
      });
      await assert.rejects(
        runner.requestOperatorStop({
          runId: run.runId,
          kind: "pause_requested",
          timing: "after-current-commit",
          expectedRevision: run.revision,
          idempotencyKey: "no-step",
        }),
        { code: "ERR_STOP_BOUNDARY_UNSUPPORTED" },
      );
      assert.equal((await store.loadRun(run.runId)).stopRequest, null);
      if (pipelineId === "plan-execution") {
        const suspended = (await runner.resume({ runId: run.runId })).run;
        assert.equal(suspended.pause.reason, "backend_unavailable");
        assert.equal(suspended.pipelineState.currentStep, null);
        await assert.rejects(
          runner.requestOperatorStop({
            runId: run.runId,
            kind: "pause_requested",
            timing: "after-current-commit",
            expectedRevision: suspended.revision,
            idempotencyKey: "suspended-bootstrap",
          }),
          { code: "ERR_STOP_BOUNDARY_UNSUPPORTED" },
        );
      }
    });
  }
});

test("deferred settlement publication recovers the final checkpoint without another commit", async (t) => {
  for (const [kind, boundary] of [
    ["pause_requested", "event-appended"],
    ["cancel_requested", "state-replaced"],
    ["pause_requested", "progress-replaced"],
  ]) {
    await t.test(`${kind}/${boundary}`, async (t) => {
      const fixture = await operatorFixture(t, "plan-execution");
      let interrupt = true;
      let runId;
      const store = createRunStore({
        stateRoot: fixture.stateRoot,
        resolveStopBoundary,
        onTransitionBoundary: async (point) => {
          if (
            interrupt &&
            point === boundary &&
            runId !== undefined &&
            (await store.loadRun(runId)).pipelineState.completedCommits
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
              if (request.prompt.includes("Implement the changes described")) {
                const current = await store.loadRun(runId);
                await runner.requestOperatorStop({
                  runId,
                  kind,
                  timing: "after-current-commit",
                  expectedRevision: current.revision,
                  idempotencyKey: "publish-stop",
                });
              }
              if (request.access === "local-commit") commits += 1;
              return delegate.run(request);
            },
          },
        },
        { runStore: store },
      );
      runId = (
        await runner.create({
          pipelineId: "plan-execution",
          projectPath: fixture.projectPath,
          taskPath: fixture.taskPath,
          proactiveClarification: false,
          roleOverrides: {},
          sourceSession: null,
        })
      ).run.runId;
      await assert.rejects(
        runner.resume({ runId, action: null }),
        /verified publication interrupted/u,
      );
      const persisted = await store.loadRun(runId);
      assert.equal(
        persisted.pipelineState.workflowState,
        kind === "pause_requested" ? "WAITING_FOR_USER" : "CANCELED",
      );
      assert.equal(persisted.pause.operatorResume.workflowState, "DONE");
      assert.deepEqual(persisted.stopRequest.settlement, {
        kind: "commit",
        commit: persisted.pipelineState.completedCommits[0],
      });
      assert.equal(persisted.pipelineState.completedCommits.length, 1);
      assert.equal(persisted.pipelineState.pendingCommit, null);
      if (kind === "pause_requested") {
        assert.equal(
          (await runner.resume({ runId, action: null })).run.pipelineState
            .workflowState,
          "DONE",
        );
      } else {
        await assert.rejects(runner.resume({ runId, action: null }), {
          code: "ERR_RUN_CANCELED",
        });
      }
      assert.equal(commits, 1);
    });
  }
});

test("deferred cancellation recovers interrupted commit verification without invoking another effect", async (t) => {
  const fixture = await operatorFixture(t, "plan-execution");
  const store = createRunStore({
    stateRoot: fixture.stateRoot,
    resolveStopBoundary,
  });
  const git = createGitService();
  let verifications = 0;
  const delegate = createExecutionAdapter();
  let runner,
    runId,
    commits = 0;
  runner = runnerFor(
    fixture,
    {
      codex: {
        ...delegate,
        async run(request) {
          if (request.access === "local-commit") commits += 1;
          if (request.prompt.includes("Implement the changes described")) {
            const current = await store.loadRun(runId);
            await runner.requestOperatorStop({
              runId,
              kind: "cancel_requested",
              timing: "after-current-commit",
              expectedRevision: current.revision,
              idempotencyKey: "cancel-commit",
            });
          }
          return delegate.run(request);
        },
      },
    },
    {
      runStore: store,
      git: {
        ...git,
        async verifyCommit(authorization) {
          verifications += 1;
          if (verifications === 1)
            throw new Error("Verification interrupted after effect");
          return git.verifyCommit(authorization);
        },
      },
    },
  );
  runId = (
    await runner.create({
      pipelineId: "plan-execution",
      projectPath: fixture.projectPath,
      taskPath: fixture.taskPath,
      proactiveClarification: false,
      roleOverrides: {},
      sourceSession: null,
    })
  ).run.runId;
  const stopped = (await runner.resume({ runId, action: null })).run;
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
  await assert.rejects(runner.resume({ runId, action: null }), {
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
    ["pause_requested", "prepared"],
    ["cancel_requested", "consumed"],
    ["pause_requested", "absent"],
    ["cancel_requested", "invalid"],
    ["pause_requested", "verification"],
  ]) {
    await t.test(`${kind}/${fault}`, async (t) => {
      const fixture = await operatorFixture(t, "plan-execution");
      const git = createGitService();
      const before = await git.snapshot({ projectPath: fixture.projectPath });
      let runId, stopInput, receipt, interruptedAuthorization;
      let injected = false,
        commits = 0,
        verifications = 0,
        forbidTurns = false;
      const store = createRunStore({
        stateRoot: fixture.stateRoot,
        resolveStopBoundary,
        async onTransitionBoundary(point) {
          if (
            injected ||
            runId === undefined ||
            point !== "event-appended" ||
            !["prepared", "consumed"].includes(fault)
          )
            return;
          const current = await store.loadRun(runId);
          if (current.pipelineState.pendingCommit?.status === fault) {
            injected = true;
            interruptedAuthorization =
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
          if (request.prompt.includes("Implement the changes described")) {
            const current = await store.loadRun(runId);
            stopInput = {
              runId,
              kind,
              timing: "after-current-commit",
              expectedRevision: current.revision,
              idempotencyKey: "fault-stop",
            };
            receipt = await store.requestOperatorStop(stopInput);
            assert.equal(request.signal.aborted, false);
          }
          if (request.access === "local-commit") {
            commits += 1;
            const current = await store.loadRun(runId);
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
      runId = (
        await runner.create({
          pipelineId: "plan-execution",
          projectPath: fixture.projectPath,
          taskPath: fixture.taskPath,
          proactiveClarification: false,
          roleOverrides: {},
          sourceSession: null,
        })
      ).run.runId;
      const stopped = (await runner.resume({ runId, action: null })).run;
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
      if (["prepared", "consumed"].includes(fault)) {
        assert.equal(injected, true);
        assert.equal(commits, 0);
        assert.equal(after.head, before.head);
        assert.equal(stopped.pipelineState.pendingCommit.status, fault);
        assert.deepEqual(
          stopped.pipelineState.pendingCommit.authorization,
          interruptedAuthorization,
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
      } else if (fault !== "prepared") {
        assert.equal(stopped.pipelineState.pendingCommit.status, "consumed");
        assert.equal(
          stopped.pause.operatorResume.pause.reason,
          fault === "invalid" ? "commit_contract_violated" : "commit_failed",
        );
      }
      const history = await store.loadRunHistory(runId);
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
      const publicState = await control.runStatus({ runId });
      assert.doesNotMatch(
        JSON.stringify(publicState),
        /requestId|fault-stop|startTicks|bootId/u,
      );
      if (canceled) {
        await assert.rejects(openRunner().resume({ runId, action: null }), {
          code: "ERR_RUN_CANCELED",
        });
      } else if (verified || fault !== "prepared") {
        const restored = (await openRunner().resume({ runId, action: null }))
          .run;
        if (verified)
          assert.equal(restored.pipelineState.workflowState, "DONE");
        else
          assert.deepEqual(restored.pause, stopped.pause.operatorResume.pause);
      }
      assert.equal(commits, ["prepared", "consumed"].includes(fault) ? 0 : 1);
    });
  }
});
