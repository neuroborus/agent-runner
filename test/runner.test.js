import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  lstat,
  readdir,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { hostname, tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import {
  createClarificationService,
  createGitService,
  createMcpControlPlane,
  createRunner,
  createRunStore,
  createTrustedValidationService,
  DETACHED_RUNTIME_COMPATIBILITY_TOKEN,
  getPipeline,
  main,
  parseRunnerConfiguration,
  RUN_STATE_SCHEMA_VERSION,
  RunnerError,
} from "../src/index.js";
import { spawnOwnedProcess } from "../src/agents/index.js";
import { resolveStopBoundary } from "../src/pipeline-registry.js";
import { preparePipelineMigration } from "../src/runner/index.js";
import { createLegacyRecoveryFixture } from "../pipelines/plan-execution/test/support/index.js";

const executeFile = promisify(execFile);
const SOURCE_SESSION = "11111111-1111-4111-8111-111111111111";
const PLANNER_SESSION = "22222222-2222-4222-8222-222222222222";
const POST_CLARIFICATION_PLANNER_SESSION = `${PLANNER_SESSION}:1`;
const PLANNING_SESSION = `${PLANNER_SESSION}:2`;
const REVIEWER_SESSION = "33333333-3333-4333-8333-333333333333";
const ARBITER_SESSION = "44444444-4444-4444-8444-444444444444";
const PREPARED_RUN = "55555555-5555-4555-8555-555555555555";
const RUNNER_CONFIGURATION = { schemaVersion: 1, defaultBackend: "codex" };
const PLAN = `## Commit 1: feat(test): add behavior

Implement the requested behavior.`;

test("legacy recovery status is lock-free and resume retains run-then-worktree ownership", async (t) => {
  const fixture = await createLegacyRecoveryFixture(t, { steps: 1 });
  const before = await fixture.bytes();
  const lease = await fixture.store.acquireRunLease(fixture.runId);
  try {
    assert.deepEqual(await fixture.recoveryAction(), [
      { type: "resume", action: null },
    ]);
    await assert.rejects(
      fixture.openRunner().resume({ runId: fixture.runId }),
      { code: "ERR_RUN_LEASED" },
    );
  } finally {
    await lease.release();
  }
  const worktree = await fixture.store.acquireWorktreeLease(
    fixture.projectPath,
    PREPARED_RUN,
  );
  try {
    await assert.rejects(
      fixture.openRunner().resume({ runId: fixture.runId }),
      { code: "ERR_WORKTREE_LEASED" },
    );
    assert.equal(await fixture.store.runIsLeased(fixture.runId), false);
    assert.deepEqual(await fixture.bytes(), before);
  } finally {
    await worktree.release();
  }
  const status = await fixture.openRunner().status(fixture.runId);
  assert.equal(Object.hasOwn(status, "events"), false);
  assert.equal(Object.hasOwn(status.run, "events"), false);
  assert.equal(
    (await fixture.openRunner().resume({ runId: fixture.runId })).run
      .pipelineState.workflowState,
    "DONE",
  );
});

function questions() {
  return {
    status: "QUESTIONS",
    questions: [
      {
        question: "Which behavior is required?",
        whyItMatters: "The answer changes the commit plan.",
      },
    ],
  };
}

function ready() {
  return { status: "READY", questions: [] };
}

function draft() {
  return {
    status: "DRAFT",
    plan: PLAN,
    question: "",
    options: [],
    whyBlocked: "",
    evidence: [],
  };
}

function approved() {
  return {
    status: "APPROVED",
    findings: [],
    question: "",
    options: [],
    whyBlocked: "",
    evidence: [],
  };
}

function unchangedPlan() {
  return {
    status: "UNCHANGED",
    plan: "",
    question: "",
    options: [],
    whyBlocked: "",
    evidence: [],
  };
}

function cleanPlan() {
  return {
    status: "CLEAN",
    findings: [],
    question: "",
    options: [],
    whyBlocked: "",
    evidence: [],
  };
}

function createAdapter({ fork = true, questionFirst = false } = {}) {
  const calls = [];
  const probes = [];
  let clarificationCalls = 0;
  let freshPlannerSessions = 0;
  function plannerSession() {
    const sessionId =
      freshPlannerSessions === 0
        ? PLANNER_SESSION
        : `${PLANNER_SESSION}:${freshPlannerSessions}`;
    freshPlannerSessions += 1;
    return sessionId;
  }
  return {
    calls,
    probes,
    async probe(options) {
      probes.push(options);
      return {
        version: "fake-1.0.0",
        structuredOutput: true,
        readOnly: true,
        autonomousWrite: true,
        gitMetadataWriteBlocked: true,
        workspaceWrite: true,
        localCommit: true,
        remoteWriteBlocked: true,
        nativeSessionContinuation: true,
        nativeSessionFork: fork,
      };
    },
    async run(request) {
      calls.push(request);
      let structured;
      let sessionId =
        request.session?.mode === "continue" ? request.session.id : undefined;
      if (request.prompt.includes("Study the task, existing clarifications")) {
        clarificationCalls += 1;
        structured =
          questionFirst && clarificationCalls === 1 ? questions() : ready();
        sessionId ??= plannerSession();
      } else if (
        request.prompt.includes("Write a concise commit-by-commit plan")
      ) {
        structured = draft();
        sessionId ??= plannerSession();
      } else if (request.prompt.includes("Return CLEAN only")) {
        structured = cleanPlan();
        sessionId ??= plannerSession();
      } else if (
        request.prompt.includes(
          "If you find any problems, fix the plan idiomatically and minimally",
        )
      ) {
        structured = unchangedPlan();
        sessionId ??= plannerSession();
      } else if (
        request.prompt.includes("Review the plan and verify that it is correct")
      ) {
        structured = approved();
        sessionId =
          request.session?.mode === "continue"
            ? request.session.id
            : REVIEWER_SESSION;
      } else {
        throw new Error("Unexpected fake adapter turn.");
      }
      return { output: "structured", structured, sessionId };
    },
  };
}

function createExecutionAdapter({ bootstrapDisagreement = false } = {}) {
  const calls = [];
  const probes = [];
  let freshSessionCount = 0;
  function freshSession() {
    const index = freshSessionCount;
    freshSessionCount += 1;
    return index === 0 ? PLANNER_SESSION : `${PLANNER_SESSION}:${index}`;
  }
  return {
    calls,
    probes,
    async probe(options) {
      probes.push(options);
      return {
        version: "fake-1.0.0",
        structuredOutput: true,
        readOnly: true,
        autonomousWrite: true,
        gitMetadataWriteBlocked: true,
        workspaceWrite: true,
        localCommit: true,
        remoteWriteBlocked: true,
        nativeSessionContinuation: true,
        nativeSessionFork: true,
      };
    },
    async run(request) {
      calls.push(request);
      if (request.access === "local-commit") {
        await executeFile("git", ["-C", request.cwd, "add", "-A"]);
        await executeFile("git", [
          "-C",
          request.cwd,
          "commit",
          "-qm",
          request.commit.message,
        ]);
        return {
          output: "committed",
          structured: { ready: true },
          sessionId: request.session.id,
        };
      }
      let structured;
      let sessionId =
        request.session?.mode === "continue" ? request.session.id : undefined;
      if (
        request.prompt.includes("Study the task, validated plan") ||
        request.prompt.includes("Study the task, existing changes")
      ) {
        structured = {
          status: "READY",
          questions: [],
          reason: "",
          question: "",
          options: [],
          whyBlocked: "",
          evidence: [],
        };
      } else if (
        request.prompt.includes("Provide a concise bootstrap summary") ||
        request.prompt.includes("Return a concise bootstrap summary")
      ) {
        const reviewer = request.prompt.includes("As Reviewer");
        structured = {
          status: "READY",
          summary:
            `${reviewer ? "Reviewer" : "Worker"} understands the task, ` +
            "plan, risks, and finalization procedure.",
          requiredChecks: [{ id: "C1", command: "git diff --check HEAD" }],
          validationInfrastructure: [],
          ...(request.schema?.properties?.result?.anyOf?.[0]?.properties
            ?.capabilityRequirements
            ? { capabilityRequirements: [], environmentBlockers: [] }
            : {}),
          capacityField: "",
          capacityLimit: 0,
          reason: "",
          question: "",
          options: [],
          whyBlocked: "",
          evidence: [],
        };
      } else if (
        request.prompt.includes("Reconcile the independent Worker and Reviewer")
      ) {
        structured = bootstrapDisagreement
          ? {
              status: "DISAGREEMENT",
              summary: "",
              disagreement: "The roles selected different module boundaries.",
              reason: "",
              question: "",
              options: [],
              whyBlocked: "",
              evidence: ["The summaries name different owning modules."],
            }
          : {
              status: "RESOLVED",
              summary: "The roles agree on the minimal implementation.",
              disagreement: "",
              reason: "",
              question: "",
              options: [],
              whyBlocked: "",
              evidence: [],
            };
      } else if (
        request.prompt.includes("Implement the changes described") ||
        request.prompt.includes("Polish the existing local repository changes")
      ) {
        await writeFile(
          join(request.cwd, "feature.js"),
          "export const value = 1;\n",
        );
        structured = {
          status: "COMPLETED",
          summary: "Implemented and self-reviewed the planned change.",
          reason: "",
          question: "",
          options: [],
          whyBlocked: "",
          evidence: [],
        };
      } else if (
        request.prompt.includes(
          "Run the complete project finalization procedure",
        )
      ) {
        structured = {
          status: "PASS",
          skillPath: "",
          summary: "The repository finalization procedure passed.",
          issues: [],
          requiredChecks: [{ id: "C1", command: "git diff --check HEAD" }],
          validationInfrastructure: [],
          checks: [
            {
              checkId: "C1",
              command: "git diff --check HEAD",
              status: "PASS",
              evidence: ["git diff --check HEAD exited successfully."],
            },
          ],
          reason: "",
          question: "",
          options: [],
          whyBlocked: "",
          evidence: [],
        };
      } else if (request.prompt.includes("semantic candidate")) {
        structured = {
          status: "APPROVED",
          findings: [],
          question: "",
          options: [],
          whyBlocked: "",
          evidence: [],
        };
      } else if (
        request.prompt.includes("Confirm the finalized changes") ||
        request.prompt.includes("Confirm the finalized change set") ||
        request.prompt.includes("Review the complete current change set")
      ) {
        structured = {
          status: "APPROVED",
          findings: [],
          validationChange: "UNCHANGED",
          validationEvidence: [],
          ...(request.prompt.includes("Confirm the finalized changes") ||
          request.prompt.includes("Confirm the finalized change set")
            ? { finalizationFindingIds: [] }
            : {}),
          question: "",
          options: [],
          whyBlocked: "",
          evidence: [],
        };
      } else {
        throw new Error("Unexpected fake execution turn.");
      }
      sessionId ??= freshSession();
      return {
        output: "structured",
        structured:
          request.schema?.properties?.result?.anyOf === undefined
            ? structured
            : { result: structured },
        sessionId,
      };
    },
  };
}

function createArbiterAdapter() {
  let probeCalls = 0;
  const calls = [];
  return {
    calls,
    get probeCalls() {
      return probeCalls;
    },
    async probe() {
      probeCalls += 1;
      return {
        version: "fake-1.0.0",
        structuredOutput: true,
        readOnly: true,
        remoteWriteBlocked: true,
      };
    },
    async run(request) {
      assert.equal(probeCalls, 1);
      calls.push(request);
      assert.match(request.prompt, /^Resolve the bootstrap disagreement/u);
      return {
        output: "structured",
        structured: {
          result: {
            direction: "SYNTHESIZE",
            summary: "Use the existing minimal module boundary.",
            rationale: "Repository ownership supports that boundary.",
            reason: "",
            question: "",
            options: [],
            whyBlocked: "",
            evidence: [],
          },
        },
        sessionId: ARBITER_SESSION,
      };
    },
  };
}

async function createFixture(t) {
  const workspace = await mkdtemp(join(tmpdir(), "agent-runner-runtime-"));
  const projectPath = join(workspace, "project");
  const taskPath = join(workspace, "task");
  const stateRoot = join(workspace, "state");
  await Promise.all([mkdir(projectPath), mkdir(taskPath)]);
  await executeFile("git", ["init", "-q", projectPath]);
  await writeFile(
    join(taskPath, "task.md"),
    "Implement the requested behavior.\n",
  );
  t.after(() => rm(workspace, { recursive: true, force: true }));
  return { projectPath, stateRoot, taskPath, workspace };
}

function configurationLoader(configuration = RUNNER_CONFIGURATION) {
  return async () => parseRunnerConfiguration(JSON.stringify(configuration));
}

async function operatorFixture(t, pipelineId) {
  const fixture = await createFixture(t);
  await writeFile(
    join(fixture.projectPath, ".gitignore"),
    "/LOCAL_ARTIFACTS/\n",
  );
  await writeFile(
    join(fixture.projectPath, "source.js"),
    "export const value = 0;\n",
  );
  for (const args of [
    ["config", "user.name", "Test"],
    ["config", "user.email", "test@example.com"],
    ["add", "."],
    ["commit", "-qm", "chore(test): initialize"],
  ]) {
    await executeFile("git", ["-C", fixture.projectPath, ...args]);
  }
  if (pipelineId === "plan-execution")
    await writeFile(join(fixture.taskPath, "plan.md"), PLAN);
  if (pipelineId === "polishing")
    await writeFile(
      join(fixture.projectPath, "source.js"),
      "export const value = 1;\n",
    );
  return fixture;
}

test("operator stops abort active read-only turns and preserve their checkpoints in every pipeline", async (t) => {
  for (const pipelineId of ["plan-authoring", "plan-execution", "polishing"]) {
    for (const mode of ["independent", "lazy"]) {
      for (const kind of ["pause_requested", "cancel_requested"]) {
        await t.test(`${pipelineId} ${mode} ${kind}`, async (t) => {
          const fixture = await operatorFixture(t, pipelineId);
          const store = createRunStore({ stateRoot: fixture.stateRoot });
          const delegate =
            pipelineId === "plan-authoring"
              ? createAdapter()
              : createExecutionAdapter();
          const started = Promise.withResolvers();
          let requests = 0;
          const runner = runnerFor(
            fixture,
            {
              codex: {
                ...delegate,
                async run(request) {
                  requests += 1;
                  started.resolve();
                  return new Promise((resolve, reject) => {
                    request.signal.addEventListener(
                      "abort",
                      () => reject(request.signal.reason),
                      { once: true },
                    );
                  });
                },
              },
            },
            { runStore: store },
          );
          const prepared = await runner.create({
            pipelineId,
            settingOverrides: { mode },
            projectPath: fixture.projectPath,
            taskPath: fixture.taskPath,
            proactiveClarification: false,
            roleOverrides: {},
            sourceSession: null,
          });
          const runId = prepared.run.runId;
          const executing = runner.resume({ runId, action: null });
          await Promise.race([
            started.promise,
            executing.then(() => assert.fail("Turn did not start")),
          ]);
          const before = await store.loadRun(runId);
          const receipt = await runner.requestOperatorStop({
            runId,
            kind,
            expectedRevision: before.revision,
            idempotencyKey: kind,
          });
          const stopped = (await executing).run;
          assert.equal(requests, 1);
          assert.equal(
            stopped.pipelineState.workflowState,
            kind === "pause_requested" ? "WAITING_FOR_USER" : "CANCELED",
          );
          assert.deepEqual(
            stopped.pause.operatorResume.activeTurn,
            before.activeTurn,
          );
          assert.equal(stopped.pause.operatorResume.workflowState, "CLARIFY");
          assert.equal(stopped.pause.resumeAction, null);
          assert.equal(stopped.activeTurn, null);
          assert.deepEqual(stopped.roles, before.roles);
          assert.deepEqual(stopped.sessionLineage, before.sessionLineage);
          assert.deepEqual((await runner.status(runId)).run, stopped);
          assert.equal(await store.runIsLeased(runId), false);
          if (pipelineId !== "plan-authoring")
            assert.equal(
              await store.worktreeIsLeased(fixture.projectPath, runId),
              false,
            );
          assert.deepEqual(
            await runner.requestOperatorStop({
              runId,
              kind,
              expectedRevision: before.revision,
              idempotencyKey: kind,
            }),
            receipt,
          );
          if (kind === "cancel_requested")
            await assert.rejects(runner.resume({ runId, action: null }), {
              code: "ERR_RUN_CANCELED",
            });
        });
      }
    }
  }
});

test("operator pause resume restores active state only after worktree ownership", async (t) => {
  const fixture = await operatorFixture(t, "plan-execution");
  const store = createRunStore({ stateRoot: fixture.stateRoot });
  const delegate = createExecutionAdapter();
  const started = Promise.withResolvers();
  let first = true;
  const runner = runnerFor(
    fixture,
    {
      codex: {
        ...delegate,
        async run(request) {
          if (!first) return delegate.run(request);
          first = false;
          started.resolve();
          return new Promise((resolve, reject) => {
            request.signal.addEventListener(
              "abort",
              () => reject(request.signal.reason),
              { once: true },
            );
          });
        },
      },
    },
    { runStore: store },
  );
  const prepared = await runner.create({
    pipelineId: "plan-execution",
    settingOverrides: { mode: "lazy" },
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  });
  const runId = prepared.run.runId;
  const executing = runner.resume({ runId, action: null });
  await Promise.race([
    started.promise,
    executing.then(() => assert.fail("Turn did not start")),
  ]);
  const active = await store.loadRun(runId);
  await runner.requestOperatorStop({
    runId,
    kind: "pause_requested",
    expectedRevision: active.revision,
    idempotencyKey: "pause-before-competing-owner",
  });
  const paused = (await executing).run;
  const competing = await store.acquireWorktreeLease(
    fixture.projectPath,
    PREPARED_RUN,
  );
  try {
    await assert.rejects(runner.resume({ runId, action: null }), {
      code: "ERR_WORKTREE_LEASED",
    });
    assert.deepEqual(await store.loadRun(runId), paused);
  } finally {
    await competing.release();
  }
});

test("runner fails closed when operator stop monitoring fails", async (t) => {
  const fixture = await operatorFixture(t, "plan-authoring");
  const store = createRunStore({ stateRoot: fixture.stateRoot });
  const watchStarted = Promise.withResolvers();
  const operationStarted = Promise.withResolvers();
  const monitorAborted = Promise.withResolvers();
  const releaseOperation = Promise.withResolvers();
  const delegate = createAdapter();
  const prepared = await runnerFor(
    fixture,
    { codex: delegate },
    { runStore: store },
  ).create({
    pipelineId: "plan-authoring",
    settingOverrides: { mode: "lazy" },
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  });
  const runner = runnerFor(
    fixture,
    {
      codex: {
        ...delegate,
        async run(request) {
          request.signal.addEventListener(
            "abort",
            () => monitorAborted.resolve(),
            { once: true },
          );
          operationStarted.resolve();
          await releaseOperation.promise;
          return delegate.run(request);
        },
      },
    },
    {
      runStore: {
        ...store,
        async waitForRunChange() {
          watchStarted.resolve();
          await operationStarted.promise;
          throw new Error("watch failed");
        },
      },
    },
  );

  const executing = runner.resume({ runId: prepared.run.runId, action: null });
  await Promise.all([
    watchStarted.promise,
    operationStarted.promise,
    monitorAborted.promise,
  ]);
  releaseOperation.resolve();

  await assert.rejects(executing, { code: "ERR_STOP_MONITOR_FAILED" });
  assert.equal(await store.runIsLeased(prepared.run.runId), false);
});

test("operator stops reconcile native provider ownership before releasing leases", async (t) => {
  for (const access of ["read-only", "workspace-write"]) {
    await t.test(access, async (t) => {
      const fixture = await operatorFixture(t, "polishing");
      const store = createRunStore({ stateRoot: fixture.stateRoot });
      const delegate = createExecutionAdapter();
      const started = Promise.withResolvers();
      let child;
      const runner = runnerFor(
        fixture,
        {
          codex: {
            ...delegate,
            async run(request) {
              if (request.access !== access) return delegate.run(request);
              const source = `${access === "workspace-write" ? "require('node:fs').writeFileSync('partial.txt', 'preserved');" : ""}
          require('node:fs').writeSync(1, 'ready'); setInterval(() => {}, 1000);`;
              child = spawnOwnedProcess(process.execPath, ["-e", source], {
                cwd: request.cwd,
                env: process.env,
                signal: request.signal,
                onProcess: request.onProcess,
              });
              child.stdout.once("data", () => started.resolve());
              child.stderr.resume();
              child.stdin.end();
              await child.ownedCompletion;
              request.signal.throwIfAborted();
              assert.fail("The native turn must be interrupted");
            },
          },
        },
        { runStore: store },
      );
      t.after(() => child?.kill());
      const runId = (
        await runner.create({
          pipelineId: "polishing",
          projectPath: fixture.projectPath,
          taskPath: fixture.taskPath,
          proactiveClarification: false,
          roleOverrides: {},
          sourceSession: null,
        })
      ).run.runId;
      const executing = runner.resume({ runId, action: null });
      await Promise.race([
        started.promise,
        executing.then(() => assert.fail("Provider did not start")),
      ]);
      const before = await store.loadRun(runId);
      assert.equal(before.executionProcess.pid, child.ownedPid);
      assert.equal(await store.runIsLeased(runId), true);
      const kind =
        access === "read-only" ? "pause_requested" : "cancel_requested";
      await runner.requestOperatorStop({
        runId,
        kind,
        expectedRevision: before.revision,
        idempotencyKey: "native-stop",
      });
      const stopped = (await executing).run;
      assert.equal(
        stopped.pause.reason,
        access === "read-only" ? "operator_paused" : "operator_canceled",
      );
      assert.equal(stopped.executionProcess, null);
      assert.equal(await store.runIsLeased(runId), false);
      assert.equal(
        await store.worktreeIsLeased(fixture.projectPath, runId),
        false,
      );
      assert.throws(() => process.kill(-child.pid, 0), { code: "ESRCH" });
      if (access === "workspace-write")
        assert.equal(
          await readFile(join(fixture.projectPath, "partial.txt"), "utf8"),
          "preserved",
        );
    });
  }
});

test("operator pause preserves writable partial content and reconstructs the primary without reforking", async (t) => {
  for (const pipelineId of ["plan-execution", "polishing"]) {
    await t.test(pipelineId, async (t) => {
      const fixture = await operatorFixture(t, pipelineId);
      const store = createRunStore({ stateRoot: fixture.stateRoot });
      const delegate = createExecutionAdapter();
      let primaryTurns = 0;
      let runId;
      let runner;
      runner = runnerFor(
        fixture,
        {
          codex: {
            ...delegate,
            async run(request) {
              if (request.access !== "workspace-write")
                return delegate.run(request);
              primaryTurns += 1;
              if (primaryTurns === 2) assert.equal(request.session, undefined);
              await writeFile(
                join(fixture.projectPath, "partial.js"),
                "export const partial = true;\n",
              );
              const current = await store.loadRun(runId);
              await runner.requestOperatorStop({
                runId,
                expectedRevision: current.revision,
                kind:
                  primaryTurns === 1 ? "pause_requested" : "cancel_requested",
                idempotencyKey: `stop-${primaryTurns}`,
              });
              return delegate.run(request);
            },
          },
        },
        { runStore: store },
      );
      const prepared = await runner.create({
        pipelineId,
        projectPath: fixture.projectPath,
        taskPath: fixture.taskPath,
        proactiveClarification: false,
        roleOverrides: {},
        sourceSession: { backend: "codex", id: SOURCE_SESSION },
      });
      runId = prepared.run.runId;
      const paused = (await runner.resume({ runId, action: null })).run;
      assert.equal(paused.pause.reason, "operator_paused");
      assert.equal(
        paused.pause.operatorResume.workflowState,
        pipelineId === "plan-execution" ? "IMPLEMENT" : "POLISH",
      );
      assert.match(
        await readFile(join(fixture.projectPath, "partial.js"), "utf8"),
        /partial = true/u,
      );
      assert.equal(paused.pipelineState.finalizedFingerprint, null);
      const canceled = (await runner.resume({ runId, action: null })).run;
      assert.equal(canceled.pipelineState.workflowState, "CANCELED");
      assert.equal(primaryTurns, 2);
      assert.deepEqual(canceled.sessionLineage, paused.sessionLineage);
    });
  }
});

test("operator pause over existing pending input restores the blocker without consuming its authorization", async (t) => {
  const fixture = await operatorFixture(t, "plan-authoring");
  const store = createRunStore({ stateRoot: fixture.stateRoot });
  const delegate = createAdapter({ questionFirst: true });
  const runner = runnerFor(fixture, { codex: delegate }, { runStore: store });
  const original = (
    await runner.run({
      pipelineId: "plan-authoring",
      projectPath: fixture.projectPath,
      taskPath: fixture.taskPath,
      proactiveClarification: false,
      roleOverrides: {},
      sourceSession: null,
    })
  ).run;
  const runId = original.runId;
  await runner.requestOperatorStop({
    runId,
    kind: "pause_requested",
    expectedRevision: original.revision,
    idempotencyKey: "pause",
  });
  const paused = (await runner.resume({ runId, action: null })).run;
  assert.equal(paused.pause.reason, "operator_paused");
  assert.deepEqual(
    paused.pipelineState.pendingEdit,
    original.pipelineState.pendingEdit,
  );
  const calls = delegate.calls.length;
  const restored = (await runner.resume({ runId, action: null })).run;
  assert.deepEqual(restored.pause, original.pause);
  assert.deepEqual(
    restored.pipelineState.pendingEdit,
    original.pipelineState.pendingEdit,
  );
  assert.equal(delegate.calls.length, calls);
});

test("operator pause preserves authorized clarification edits in every pipeline", async (t) => {
  for (const pipelineId of ["plan-authoring", "plan-execution", "polishing"]) {
    await t.test(pipelineId, async (t) => {
      const fixture = await operatorFixture(t, pipelineId);
      const delegate =
        pipelineId === "plan-authoring"
          ? createAdapter()
          : createExecutionAdapter();
      const runner = runnerFor(fixture, { codex: delegate });
      const original = (
        await runner.run({
          pipelineId,
          projectPath: fixture.projectPath,
          taskPath: fixture.taskPath,
          proactiveClarification: true,
          roleOverrides: {},
          sourceSession: null,
        })
      ).run;
      const { runId } = original;
      const transcriptPath = original.pipelineState.pendingEdit.transcriptPath;
      const transcript = `${await readFile(transcriptPath, "utf8")}\nAuthorized operator clarification.\n`;
      await writeFile(transcriptPath, transcript);
      await runner.requestOperatorStop({
        runId,
        kind: "pause_requested",
        expectedRevision: original.revision,
        idempotencyKey: "pause",
      });
      const paused = (await runner.resume({ runId, action: null })).run;
      assert.equal(paused.pause.reason, "operator_paused");
      assert.deepEqual(paused.pause.operatorResume.pause, original.pause);
      assert.deepEqual(
        paused.pipelineState.pendingEdit,
        original.pipelineState.pendingEdit,
      );
      const restored = (await runner.resume({ runId, action: null })).run;
      assert.deepEqual(restored.pause, original.pause);
      assert.deepEqual(
        restored.pipelineState.pendingEdit,
        original.pipelineState.pendingEdit,
      );
      assert.deepEqual(restored.hashes, original.hashes);
      assert.equal(await readFile(transcriptPath, "utf8"), transcript);
      assert.equal(delegate.calls.length, 0);
    });
  }
});

test("operator stops retain read-only mutation findings even when task input also drifted", async (t) => {
  for (const pipelineId of ["plan-authoring", "plan-execution", "polishing"]) {
    const fixture = await operatorFixture(t, pipelineId);
    const store = createRunStore({ stateRoot: fixture.stateRoot });
    const delegate =
      pipelineId === "plan-authoring"
        ? createAdapter()
        : createExecutionAdapter();
    let runner, runId;
    runner = runnerFor(
      fixture,
      {
        codex: {
          ...delegate,
          async run(request) {
            await writeFile(
              join(fixture.projectPath, "contaminated.txt"),
              "retained for inspection\n",
            );
            await writeFile(
              join(fixture.taskPath, "task.md"),
              "Changed task input.\n",
            );
            const current = await store.loadRun(runId);
            await runner.requestOperatorStop({
              runId,
              kind: "pause_requested",
              expectedRevision: current.revision,
              idempotencyKey: "stop",
            });
            return delegate.run(request);
          },
        },
      },
      { runStore: store },
    );
    runId = (
      await runner.create({
        pipelineId,
        projectPath: fixture.projectPath,
        taskPath: fixture.taskPath,
        proactiveClarification: false,
        roleOverrides: {},
        sourceSession: null,
      })
    ).run.runId;
    const stopped = (await runner.resume({ runId, action: null })).run;
    assert.equal(stopped.pause.reason, "operator_paused");
    assert.equal(
      stopped.pause.operatorResume.pause.reason,
      pipelineId === "plan-authoring"
        ? "read_only_mutation"
        : "read_only_agent_mutated_repository",
    );
    assert.equal(
      await readFile(join(fixture.projectPath, "contaminated.txt"), "utf8"),
      "retained for inspection\n",
    );
    const restored = (await runner.resume({ runId, action: null })).run;
    assert.equal(restored.pipelineState.workflowState, "WAITING_FOR_USER");
    assert.equal(
      restored.pause.reason,
      stopped.pause.operatorResume.pause.reason,
    );
  }
});

test("operator cancellation racing a consumed commit verifies and records its effect exactly once", async (t) => {
  const fixture = await operatorFixture(t, "plan-execution");
  const store = createRunStore({ stateRoot: fixture.stateRoot });
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
          const response = await delegate.run(request);
          if (request.access === "local-commit") {
            commits += 1;
            const current = await store.loadRun(runId);
            await runner.requestOperatorStop({
              runId,
              kind: "cancel_requested",
              expectedRevision: current.revision,
              idempotencyKey: "cancel-commit",
            });
          }
          return response;
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
});

test("operator pause after commit consumption but before invocation retires only the unused authorization", async (t) => {
  const fixture = await operatorFixture(t, "plan-execution");
  const store = createRunStore({ stateRoot: fixture.stateRoot });
  const git = createGitService();
  const delegate = createExecutionAdapter();
  let runner,
    runId,
    consumptions = 0;
  runner = runnerFor(
    fixture,
    { codex: delegate },
    {
      runStore: store,
      git: {
        ...git,
        async consumeCommit(...args) {
          const request = await git.consumeCommit(...args);
          consumptions += 1;
          if (consumptions === 1) {
            const current = await store.loadRun(runId);
            await runner.requestOperatorStop({
              runId,
              kind: "pause_requested",
              expectedRevision: current.revision,
              idempotencyKey: "before-commit",
            });
          }
          return request;
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
  const paused = (await runner.resume({ runId, action: null })).run;
  assert.equal(paused.pause.reason, "operator_paused");
  assert.equal(paused.pause.operatorResume.workflowState, "COMMIT");
  assert.equal(paused.pause.operatorResume.pause, null);
  assert.equal(paused.pipelineState.pendingCommit, null);
  assert.equal(
    delegate.calls.filter((request) => request.access === "local-commit")
      .length,
    0,
  );
  const completed = (await runner.resume({ runId, action: null })).run;
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.pipelineState.completedCommits.length, 1);
  assert.equal(
    delegate.calls.filter((request) => request.access === "local-commit")
      .length,
    1,
  );
});

test("operator pauses preserve wrapped pre-effect abort proof without discarding unrelated failures", async (t) => {
  for (const aborted of [true, false]) {
    await t.test(
      aborted ? "wrapped abort" : "unrelated rejection",
      async (t) => {
        const fixture = await operatorFixture(t, "plan-execution");
        const store = createRunStore({ stateRoot: fixture.stateRoot });
        const delegate = createExecutionAdapter();
        let runner,
          runId,
          attempts = 0;
        runner = runnerFor(
          fixture,
          {
            codex: {
              ...delegate,
              async run(request) {
                if (request.access === "local-commit" && ++attempts === 1) {
                  const stopped = new Promise((resolve) => {
                    request.signal.addEventListener("abort", resolve, {
                      once: true,
                    });
                    if (request.signal.aborted) resolve();
                  });
                  const current = await store.loadRun(runId);
                  await runner.requestOperatorStop({
                    runId,
                    kind: "pause_requested",
                    expectedRevision: current.revision,
                    idempotencyKey: "during-commit-readiness",
                  });
                  await stopped;
                  const cause = aborted
                    ? request.signal.reason
                    : new Error("PRIVATE_NATIVE_FAILURE");
                  throw Object.assign(
                    new Error("PRIVATE_PROVIDER_WRAPPER", {
                      cause: new Error("PRIVATE_PROCESS_WRAPPER", { cause }),
                    }),
                    {
                      code: "ERR_CODEX_LOCAL_COMMIT_INTERRUPTED",
                      effectStarted: false,
                    },
                  );
                }
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
        const paused = (await runner.resume({ runId, action: null })).run;
        assert.equal(paused.pause.reason, "operator_paused");
        assert.equal(paused.pipelineState.completedCommits.length, 0);
        assert.doesNotMatch(JSON.stringify(paused), /PRIVATE_/u);
        if (aborted) {
          assert.equal(paused.pause.operatorResume.pause, null);
          assert.equal(paused.pipelineState.pendingCommit, null);
          const completed = (await runner.resume({ runId, action: null })).run;
          assert.equal(completed.pipelineState.workflowState, "DONE");
          assert.equal(completed.pipelineState.completedCommits.length, 1);
          assert.equal(attempts, 2);
        } else {
          assert.equal(
            paused.pause.operatorResume.pause.reason,
            "commit_failed",
          );
          assert.equal(paused.pipelineState.pendingCommit, null);
          assert.equal(
            paused.pause.operatorResume.pause.code,
            "ERR_CODEX_LOCAL_COMMIT_INTERRUPTED",
          );
          const restored = (await runner.resume({ runId, action: null })).run;
          assert.equal(restored.pause.reason, "commit_failed");
          assert.equal(attempts, 1);
        }
      },
    );
  }
});

test("operator pause racing handoff preserves staged content without staging again on resume", async (t) => {
  const fixture = await operatorFixture(t, "polishing");
  const store = createRunStore({ stateRoot: fixture.stateRoot });
  const git = createGitService();
  let runner,
    runId,
    handoffs = 0;
  runner = runnerFor(
    fixture,
    { codex: createExecutionAdapter() },
    {
      runStore: store,
      git: {
        ...git,
        async stagePolishingHandoff(options) {
          handoffs += 1;
          const inspected = await git.stagePolishingHandoff(options);
          const current = await store.loadRun(runId);
          await runner.requestOperatorStop({
            runId,
            kind: "pause_requested",
            expectedRevision: current.revision,
            idempotencyKey: "pause-handoff",
          });
          return inspected;
        },
      },
    },
  );
  runId = (
    await runner.create({
      pipelineId: "polishing",
      projectPath: fixture.projectPath,
      taskPath: fixture.taskPath,
      proactiveClarification: false,
      roleOverrides: {},
      sourceSession: null,
    })
  ).run.runId;
  const stopped = (await runner.resume({ runId, action: null })).run;
  assert.equal(stopped.pause.reason, "operator_paused");
  assert.equal(stopped.pause.operatorResume.workflowState, "DONE");
  assert.equal(
    (await runner.resume({ runId, action: null })).run.pipelineState
      .workflowState,
    "DONE",
  );
  assert.equal(handoffs, 1);
});

test("operator cancellation supersedes pause during trusted validation without accepting check evidence", async (t) => {
  const fixture = await operatorFixture(t, "polishing");
  const store = createRunStore({ stateRoot: fixture.stateRoot });
  const delegate = createExecutionAdapter();
  let runner,
    runId,
    executions = 0;
  const activities = [];
  runner = runnerFor(
    fixture,
    {
      codex: {
        ...delegate,
        async run(request) {
          const response = await delegate.run(request);
          if (
            request.prompt.includes(
              "Run the complete project finalization procedure",
            )
          ) {
            (
              response.structured.result ?? response.structured
            ).checks[0].status = "NOT_RUN";
          }
          return response;
        },
      },
    },
    {
      runStore: store,
      activities,
      configuration: {
        ...RUNNER_CONFIGURATION,
        trustedCommands: {
          hygiene: {
            command: "git diff --check HEAD",
            executable: "git",
            arguments: ["diff", "--check", "HEAD"],
          },
        },
        pipelines: { polishing: { trustedChecks: ["hygiene"] } },
      },
      trustedValidation: {
        async preflight() {},
        async execute(request) {
          executions += 1;
          assert.equal(typeof request.onProcess, "function");
          const current = await store.loadRun(runId);
          const stopped = new Promise((resolve, reject) =>
            request.signal.addEventListener(
              "abort",
              () => reject(request.signal.reason),
              { once: true },
            ),
          );
          // Attach rejection handling before asynchronously accepting both requests.
          stopped.catch(() => {});
          for (const kind of ["pause_requested", "cancel_requested"]) {
            await runner.requestOperatorStop({
              runId,
              kind,
              expectedRevision: current.revision,
              idempotencyKey: kind,
            });
          }
          return stopped;
        },
      },
    },
  );
  runId = (
    await runner.create({
      pipelineId: "polishing",
      projectPath: fixture.projectPath,
      taskPath: fixture.taskPath,
      proactiveClarification: false,
      roleOverrides: {},
      sourceSession: null,
    })
  ).run.runId;
  const canceled = (await runner.resume({ runId, action: null })).run;
  assert.equal(canceled.pipelineState.workflowState, "CANCELED");
  assert.equal(canceled.pipelineState.finalizedFingerprint, null);
  assert.equal(executions, 1);
  assert.equal(await store.runIsLeased(runId), false);
  assert.deepEqual(
    activities.filter((item) => item.phase === "stop").map((item) => item.kind),
    ["stopping", "reconciling", "reconciled"],
  );
});

test("operator stop after host loss reclaims ownership and reconciles before further provider work", async (t) => {
  for (const kind of ["pause_requested", "cancel_requested"]) {
    for (const timing of ["immediate", "after-current-commit"])
      await t.test(`${kind}/${timing}`, async (t) => {
        const fixture = await operatorFixture(t, "plan-execution");
        const BOOT_A = "11111111-1111-4111-8111-111111111111";
        const BOOT_B = "22222222-2222-4222-8222-222222222222";
        const options = {
          stateRoot: fixture.stateRoot,
          resolveStopBoundary,
          hostName: "recovery-host",
          processId: 100,
          processIsAlive: () => true,
          processIdentity: (pid) => ({
            bootId: BOOT_A,
            startTicks: String(pid),
          }),
          leaseStaleMs: 0,
        };
        const store = createRunStore(options);
        const delegate = createExecutionAdapter();
        const runner = runnerFor(
          fixture,
          {
            codex: {
              ...delegate,
              async run(request) {
                if (
                  timing === "after-current-commit" &&
                  !request.prompt.includes("Implement the changes described")
                )
                  return delegate.run(request);
                await request.onProcess(4242, {
                  processIdentity: { bootId: BOOT_A, startTicks: "4242" },
                  namespaceId: "pid:[4026533000]",
                });
                throw new Error("Simulated execution-owner loss");
              },
            },
          },
          { runStore: store },
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
        await assert.rejects(runner.resume({ runId, action: null }), {
          code: "ERR_EXECUTION_PROCESS_ACTIVE",
        });
        const checkpoint = await store.loadRun(runId);
        assert.equal(
          checkpoint.executionProcess.namespaceId,
          "pid:[4026533000]",
        );
        assert.deepEqual(checkpoint.executionProcess.processIdentity, {
          bootId: BOOT_A,
          startTicks: "4242",
        });
        const rebooted = createRunStore({
          ...options,
          processId: 200,
          processIdentity: (pid) => ({
            bootId: BOOT_B,
            startTicks: String(pid),
          }),
        });
        const recoveredRunner = runnerFor(
          fixture,
          {
            codex: {
              ...delegate,
              async run() {
                assert.fail("Stop recovery must not invoke a provider");
              },
            },
          },
          { runStore: rebooted },
        );
        await recoveredRunner.requestOperatorStop({
          runId,
          kind,
          expectedRevision: checkpoint.revision,
          idempotencyKey: "reboot-stop",
          timing,
        });
        const canceled = (await recoveredRunner.resume({ runId, action: null }))
          .run;
        assert.equal(
          canceled.pipelineState.workflowState,
          kind === "cancel_requested" ? "CANCELED" : "WAITING_FOR_USER",
        );
        assert.equal(canceled.executionProcess, null);
        assert.deepEqual(canceled.stopRequest.settlement, {
          kind: "quiescent",
          commit: null,
        });
        assert.equal(canceled.pipelineState.completedCommits.length, 0);
        assert.deepEqual(
          canceled.pause.operatorResume.activeTurn,
          checkpoint.activeTurn,
        );
        assert.equal(await rebooted.runIsLeased(runId), false);
        assert.equal(
          await rebooted.worktreeIsLeased(fixture.projectPath, runId),
          false,
        );
      });
  }
});

for (const recovery of ["resume", "cancel", "configuration pause"]) {
  test(`retired execution storage is cleaned before ${recovery} after owner loss`, async (t) => {
    const fixture = await operatorFixture(t, "plan-execution");
    if (recovery === "configuration pause") {
      await mkdir(join(fixture.projectPath, "LOCAL_ARTIFACTS"), {
        recursive: true,
      });
      await writeFile(
        join(fixture.projectPath, "LOCAL_ARTIFACTS", "agent-runner.json"),
        JSON.stringify({ schemaVersion: 1, defaultEffort: "current" }),
      );
    }
    const bootA = "11111111-1111-4111-8111-111111111111";
    const bootB = "22222222-2222-4222-8222-222222222222";
    const options = {
      stateRoot: fixture.stateRoot,
      resolveStopBoundary,
      hostName: "recovery-host",
      processId: 100,
      processIsAlive: () => true,
      processIdentity: (pid) => ({ bootId: bootA, startTicks: String(pid) }),
      leaseStaleMs: 0,
    };
    const store = createRunStore(options);
    const delegate = createExecutionAdapter();
    const runner = runnerFor(fixture, { codex: delegate }, { runStore: store });
    const { run } = await runner.create({
      pipelineId: "plan-execution",
      projectPath: fixture.projectPath,
      taskPath: fixture.taskPath,
      proactiveClarification: false,
      roleOverrides: {},
      sourceSession: null,
    });
    const lease = await store.acquireRunLease(run.runId);
    const root = join(fixture.stateRoot, "..", "execution-storage");
    await mkdir(root, { mode: 0o700 });
    const rootInfo = await lstat(root, { bigint: true });
    const intent = {
      id: "55555555-5555-4555-8555-555555555555",
      hostname: hostname(),
      commandIdentity: "a".repeat(64),
      phase: "allocating",
      root: {
        path: root,
        device: String(rootInfo.dev),
        inode: String(rootInfo.ino),
      },
      directory: null,
    };
    await store.recordExecutionResource(lease, intent);
    const path = join(root, intent.id);
    await mkdir(path, { mode: 0o700 });
    const directory = await lstat(path, { bigint: true });
    await store.recordExecutionResource(lease, {
      ...intent,
      phase: "allocated",
      directory: {
        device: String(directory.dev),
        inode: String(directory.ino),
      },
    });
    await writeFile(join(path, "interrupted-cache"), "must not be reused");
    // Simulate a supervised child recorded before its owner was lost.
    await store.recordExecutionProcess(lease, 4242, {
      processIdentity: { bootId: bootA, startTicks: "4242" },
      namespaceId: "pid:[4026533000]",
    });
    await assert.rejects(lease.release(), {
      code: "ERR_EXECUTION_PROCESS_ACTIVE",
    });
    const recoveredStore = createRunStore({
      ...options,
      processId: 200,
      processIdentity: (pid) => ({ bootId: bootB, startTicks: String(pid) }),
    });
    const interruption = new Error("Reached provider after recovery");
    let providerCalls = 0;
    const recoveredRunner = runnerFor(
      fixture,
      {
        codex: {
          ...delegate,
          async run() {
            providerCalls++;
            const saved = await recoveredStore.loadRun(run.runId);
            assert.equal(saved.executionProcess, null);
            assert.equal(saved.executionResource, null);
            assert.deepEqual(await readdir(root), []);
            throw interruption;
          },
        },
      },
      {
        runStore: recoveredStore,
        trustedValidation: createTrustedValidationService(),
      },
    );
    if (recovery === "cancel") {
      const current = await recoveredStore.loadRun(run.runId);
      await recoveredRunner.requestOperatorStop({
        runId: run.runId,
        kind: "cancel_requested",
        expectedRevision: current.revision,
        idempotencyKey: "storage-recovery-stop",
        timing: "immediate",
      });
      const canceled = (
        await recoveredRunner.resume({ runId: run.runId, action: null })
      ).run;
      assert.equal(canceled.pipelineState.workflowState, "CANCELED");
      assert.equal(providerCalls, 0);
    } else if (recovery === "configuration pause") {
      await mkdir(join(fixture.projectPath, "LOCAL_ARTIFACTS"), {
        recursive: true,
      });
      await writeFile(
        join(fixture.projectPath, "LOCAL_ARTIFACTS", "agent-runner.json"),
        JSON.stringify({ schemaVersion: 1, defaultEffort: "high" }),
      );
      const paused = (
        await recoveredRunner.resume({ runId: run.runId, action: null })
      ).run;
      assert.equal(paused.pause.reason, "project_configuration_changed");
      assert.equal(providerCalls, 0);
    } else {
      await assert.rejects(
        recoveredRunner.resume({ runId: run.runId, action: null }),
        { name: "AgentBoundaryError" },
      );
      assert.equal(providerCalls, 1);
    }
    const saved = await recoveredStore.loadRun(run.runId);
    assert.equal(saved.executionProcess, null);
    assert.equal(saved.executionResource, null);
    assert.deepEqual(await readdir(root), []);
    assert.equal(await recoveredStore.runIsLeased(run.runId), false);
  });
}

function runnerFor(
  fixture,
  adapters,
  {
    activities = [],
    configuration = RUNNER_CONFIGURATION,
    git = createGitService(),
    runStore = createRunStore({ stateRoot: fixture.stateRoot }),
    trustedValidation,
  } = {},
) {
  return createRunner({
    adapters,
    clarifications: createClarificationService({ interactive: false }),
    git,
    loadConfiguration: configurationLoader(configuration),
    onActivity(activity) {
      activities.push(activity);
    },
    runStore,
    ...(trustedValidation === undefined ? {} : { trustedValidation }),
  });
}

async function rewriteRunAsLegacy(directoryPath) {
  const statePath = join(directoryPath, "state.json");
  const eventsPath = join(directoryPath, "events.jsonl");
  const state = JSON.parse(await readFile(statePath, "utf8"));
  state.schemaVersion = 1;
  delete state.runtimeCompatibility;
  delete state.activeTurn;
  for (const role of Object.values(state.roles)) delete role.effort;
  const events = (await readFile(eventsPath, "utf8"))
    .trimEnd()
    .split("\n")
    .map((line) => JSON.parse(line));
  let previousActiveTurn = null;
  for (const event of events) {
    const activeTurn = event.state.activeTurn;
    if (
      event.activity === null &&
      activeTurn === null &&
      previousActiveTurn !== null
    ) {
      event.activity = {
        actor: previousActiveTurn.role,
        phase: previousActiveTurn.phase,
        kind: "turn-finished",
        message: `${previousActiveTurn.role} turn finished.`,
      };
    }
    previousActiveTurn = activeTurn;
    event.schemaVersion = 1;
    event.state.schemaVersion = 1;
    delete event.state.runtimeCompatibility;
    delete event.state.activeTurn;
    for (const role of Object.values(event.state.roles)) delete role.effort;
  }
  await Promise.all([
    writeFile(statePath, `${JSON.stringify(state, null, 2)}\n`),
    writeFile(
      eventsPath,
      `${events.map((event) => JSON.stringify(event)).join("\n")}\n`,
    ),
  ]);
}

test("validates the canonical Git root before creating external state", async (t) => {
  const fixture = await createFixture(t);
  const nestedProjectPath = join(fixture.projectPath, "nested");
  const unsafeStateRoot = join(fixture.projectPath, ".state");
  await mkdir(nestedProjectPath);
  const runner = runnerFor(
    fixture,
    { codex: createAdapter() },
    { runStore: createRunStore({ stateRoot: unsafeStateRoot }) },
  );

  await assert.rejects(
    runner.validateBoundary({
      projectPath: nestedProjectPath,
      taskPath: fixture.taskPath,
    }),
    (error) => error.code === "ERR_UNSAFE_STATE_ROOT",
  );
  await assert.rejects(readdir(unsafeStateRoot), /ENOENT/u);
});

test("serializes execution and polishing runs for one temporary worktree", async (t) => {
  const fixture = await createFixture(t);
  const runStore = createRunStore({ stateRoot: fixture.stateRoot });
  const runner = runnerFor(fixture, { codex: createAdapter() }, { runStore });
  const preparedRuns = await Promise.all(
    ["plan-execution", "polishing"].map((pipelineId) =>
      runner.create({
        pipelineId,
        projectPath: fixture.projectPath,
        taskPath: fixture.taskPath,
        proactiveClarification: false,
        roleOverrides: {},
        sourceSession: null,
      }),
    ),
  );
  const ownerLease = await runStore.acquireWorktreeLease(
    fixture.projectPath,
    PREPARED_RUN,
  );

  for (const prepared of preparedRuns) {
    await assert.rejects(
      runner.resume({ runId: prepared.run.runId, action: null }),
      (error) => error.code === "ERR_WORKTREE_LEASED",
    );
    assert.equal((await runner.status(prepared.run.runId)).run.revision, 1);
    const runLease = await runStore.acquireRunLease(prepared.run.runId);
    await runLease.release();
  }

  await ownerLease.release();
});

test("publishes blocking provider activity before every pipeline turn", async (t) => {
  for (const [pipelineId, expectedRole] of [
    ["plan-authoring", "planner"],
    ["plan-execution", "worker"],
    ["polishing", "worker"],
  ]) {
    await t.test(pipelineId, async (pipelineTest) => {
      const fixture = await createFixture(pipelineTest);
      if (pipelineId !== "plan-authoring") {
        await Promise.all([
          writeFile(
            join(fixture.projectPath, ".gitignore"),
            "/LOCAL_ARTIFACTS/\n",
          ),
          writeFile(
            join(fixture.projectPath, "source.js"),
            "export const value = 0;\n",
          ),
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
        if (pipelineId === "plan-execution") {
          await writeFile(join(fixture.taskPath, "plan.md"), PLAN);
        } else {
          await writeFile(
            join(fixture.projectPath, "source.js"),
            "export const value = 1;\n",
          );
        }
      }

      const delegate =
        pipelineId === "plan-authoring"
          ? createAdapter()
          : createExecutionAdapter();
      const started = Promise.withResolvers();
      const unblock = Promise.withResolvers();
      let blockFirstTurn = true;
      const runStore = createRunStore({ stateRoot: fixture.stateRoot });
      const adapter = {
        ...delegate,
        async run(request) {
          if (blockFirstTurn) {
            blockFirstTurn = false;
            const [runId] = await readdir(join(fixture.stateRoot, "runs"));
            const active = await runStore.loadRun(runId);
            assert.deepEqual(active.activeTurn, {
              role: expectedRole,
              phase: "clarify",
            });
            started.resolve(runId);
            await unblock.promise;
          }
          return delegate.run(request);
        },
      };
      const activities = [];
      const runner = runnerFor(
        fixture,
        { codex: adapter },
        { activities, runStore },
      );
      const executing = runner.run({
        pipelineId,
        projectPath: fixture.projectPath,
        taskPath: fixture.taskPath,
        proactiveClarification: false,
        roleOverrides: {},
        sourceSession: null,
      });
      const runId = await Promise.race([
        started.promise,
        executing.then(
          () =>
            assert.fail("Pipeline completed before its first provider turn."),
          (cause) => Promise.reject(cause),
        ),
      ]);
      assert.equal(await runStore.runIsLeased(runId), true);
      assert.deepEqual((await runner.status(runId)).run.activeTurn, {
        role: expectedRole,
        phase: "clarify",
      });

      unblock.resolve();
      const completed = await executing;
      assert.equal(completed.run.activeTurn, null);
      assert.equal(
        activities.filter(({ kind }) => kind === "turn-started").length,
        delegate.calls.length,
      );
    });
  }
});

test("runs and resumes a registered pipeline from persisted configuration", async (t) => {
  const fixture = await createFixture(t);
  const adapter = createAdapter({ questionFirst: true });
  const activities = [];
  const firstRunner = runnerFor(
    fixture,
    { codex: adapter },
    {
      activities,
      configuration: {
        ...RUNNER_CONFIGURATION,
        defaultEffort: "xhigh",
        pipelines: { "plan-authoring": { preferredCommitLineLimit: 650 } },
      },
    },
  );

  const paused = await firstRunner.run({
    pipelineId: "plan-authoring",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    proactiveClarification: false,
    roleOverrides: { planner: { model: "planner-model" } },
    sourceSession: { backend: "codex", id: SOURCE_SESSION },
  });

  assert.equal(paused.run.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(
    paused.run.pipelineState.pendingEdit.transcriptPath,
    join(fixture.taskPath, "clarifications.md"),
  );
  assert.equal(paused.run.pause.reason, "clarification_answers_required");
  assert.equal(paused.run.sessionLineage.source, SOURCE_SESSION);
  assert.equal(paused.run.sessionLineage.sourceProfile, null);
  assert.deepEqual(paused.run.roles.planner, {
    backend: "codex",
    profile: "current",
    model: "planner-model",
    contextSize: "current",
    effort: "xhigh",
  });
  assert.deepEqual(paused.run.pipelineState.settings, {
    maxRevisionRounds: 20,
    mode: "independent",
    preferredCommitLineLimit: 650,
    stagnationWindowRounds: 3,
  });
  assert.deepEqual(adapter.calls[0].session, {
    mode: "fork",
    id: SOURCE_SESSION,
  });

  const clarificationPath = join(fixture.taskPath, "clarifications.md");
  await writeFile(
    clarificationPath,
    `${await readFile(clarificationPath, "utf8")}\nUse behavior A.\n`,
  );
  const secondRunner = runnerFor(
    fixture,
    { codex: adapter },
    {
      activities,
      configuration: {
        schemaVersion: 1,
        defaultBackend: "claude",
        defaultEffort: "low",
        pipelines: { "plan-authoring": { preferredCommitLineLimit: 1200 } },
      },
    },
  );
  const beforeResume = await secondRunner.status(paused.run.runId);
  const completed = await secondRunner.resume({
    runId: paused.run.runId,
    action: null,
  });

  assert.equal(
    beforeResume.run.pipelineState.workflowState,
    "WAITING_FOR_USER",
  );
  assert.equal(completed.run.pipelineState.workflowState, "DONE");
  assert.equal(await readFile(join(fixture.taskPath, "plan.md"), "utf8"), PLAN);
  assert.deepEqual(completed.run.roles, paused.run.roles);
  assert.ok(adapter.calls.every(({ effort }) => effort === "xhigh"));
  assert.ok(adapter.probes.every(({ effort }) => effort === "xhigh"));
  assert.deepEqual(completed.run.pipelineState.settings, {
    maxRevisionRounds: 20,
    mode: "independent",
    preferredCommitLineLimit: 650,
    stagnationWindowRounds: 3,
  });
  assert.deepEqual(
    completed.run.sessionLineage.children.map(({ role, sessionId }) => ({
      role,
      sessionId,
    })),
    [
      { role: "planner", sessionId: PLANNER_SESSION },
      { role: "planner", sessionId: POST_CLARIFICATION_PLANNER_SESSION },
      { role: "planner", sessionId: PLANNING_SESSION },
      { role: "reviewer", sessionId: REVIEWER_SESSION },
    ],
  );
  assert.deepEqual(
    adapter.calls.find((call) =>
      call.prompt.includes("Review the plan and verify that it is correct"),
    ).session,
    { mode: "fork", id: SOURCE_SESSION },
  );
  assert.ok(activities.some(({ actor }) => actor === "planner"));
  assert.ok(activities.some(({ actor }) => actor === "reviewer"));
  assert.ok(activities.every(({ runId }) => runId === paused.run.runId));
});

test("migrates legacy authoring line targets under the lease without configuration reload", async (t) => {
  const fixture = await createFixture(t);
  const store = createRunStore({ stateRoot: fixture.stateRoot });
  const delegate = createAdapter();
  const initialRunner = runnerFor(
    fixture,
    { codex: delegate },
    { runStore: store },
  );
  const prepared = await initialRunner.create({
    pipelineId: "plan-authoring",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  });
  const statePath = join(prepared.directoryPath, "state.json");
  const eventsPath = join(prepared.directoryPath, "events.jsonl");
  const state = JSON.parse(await readFile(statePath, "utf8"));
  const events = (await readFile(eventsPath, "utf8"))
    .trimEnd()
    .split("\n")
    .map((line) => JSON.parse(line));
  for (const legacy of [state, ...events.map((event) => event.state)]) {
    legacy.pipelineStateVersion = 3;
    delete legacy.pipelineState.settings.preferredCommitLineLimit;
  }
  await writeFile(statePath, `${JSON.stringify(state)}\n`);
  await writeFile(
    eventsPath,
    `${events.map((event) => JSON.stringify(event)).join("\n")}\n`,
  );
  const before = await Promise.all([readFile(statePath), readFile(eventsPath)]);
  const runner = createRunner({
    adapters: {
      codex: {
        ...delegate,
        async run(request) {
          const saved = await store.loadRun(prepared.run.runId);
          assert.equal(await store.runIsLeased(prepared.run.runId), true);
          assert.equal(saved.pipelineStateVersion, 5);
          assert.equal(
            saved.pipelineState.settings.preferredCommitLineLimit,
            900,
          );
          return delegate.run(request);
        },
      },
    },
    clarifications: createClarificationService({ interactive: false }),
    git: createGitService(),
    runStore: store,
    async loadConfiguration() {
      throw new Error("Migration reloaded configuration.");
    },
  });
  const lease = await store.acquireRunLease(prepared.run.runId);
  try {
    const status = await runner.status(prepared.run.runId);
    assert.equal(
      status.run.pipelineState.settings.preferredCommitLineLimit,
      900,
    );
    await assert.rejects(runner.resume({ runId: prepared.run.runId }), {
      code: "ERR_RUN_LEASED",
    });
    assert.deepEqual(
      await Promise.all([readFile(statePath), readFile(eventsPath)]),
      before,
    );
  } finally {
    await lease.release();
  }
  const completed = await runner.resume({ runId: prepared.run.runId });
  assert.equal(completed.run.pipelineState.workflowState, "DONE");
  const persistedEvents = (await readFile(eventsPath, "utf8"))
    .trimEnd()
    .split("\n")
    .map((line) => JSON.parse(line));
  assert.equal(persistedEvents[1].activity.kind, "migrated");
  assert.equal(
    persistedEvents[1].state.pipelineState.settings.preferredCommitLineLimit,
    900,
  );
});

test("migrates a legacy runtime envelope under the run lease before resume", async (t) => {
  const fixture = await createFixture(t);
  const adapter = createAdapter();
  const activities = [];
  const runner = runnerFor(fixture, { codex: adapter }, { activities });
  const prepared = await runner.create({
    pipelineId: "plan-authoring",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  });
  await rewriteRunAsLegacy(prepared.directoryPath);

  const probeCount = adapter.probes.length;
  const callCount = adapter.calls.length;
  const legacyStatus = await runner.status(prepared.run.runId);
  assert.equal(adapter.probes.length, probeCount);
  assert.equal(adapter.calls.length, callCount);
  assert.ok(
    Object.values(legacyStatus.run.roles).every(
      ({ effort }) => effort === "current",
    ),
  );
  assert.equal(legacyStatus.run.schemaVersion, 1);
  assert.equal(legacyStatus.run.runtimeCompatibility, null);
  assert.equal(legacyStatus.run.revision, 1);

  const completed = await runner.resume({
    runId: prepared.run.runId,
    action: null,
  });
  assert.equal(completed.run.pipelineState.workflowState, "DONE");
  assert.equal(completed.run.schemaVersion, RUN_STATE_SCHEMA_VERSION);
  assert.equal(
    completed.run.runtimeCompatibility.runStateVersion,
    RUN_STATE_SCHEMA_VERSION,
  );
  assert.ok(
    activities.some(
      ({ actor, kind, phase }) =>
        actor === "runner" && kind === "migrated" && phase === "runtime",
    ),
  );
  const events = (
    await readFile(join(prepared.directoryPath, "events.jsonl"), "utf8")
  )
    .trimEnd()
    .split("\n")
    .map((line) => JSON.parse(line));
  assert.equal(events[0].schemaVersion, 1);
  assert.equal(events[1].activity.kind, "migrated");
});

test("rejects a detached runtime mismatch before touching a durable run", async (t) => {
  const fixture = await createFixture(t);
  const runner = runnerFor(fixture, { codex: createAdapter() });
  const prepared = await runner.create({
    pipelineId: "plan-authoring",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  });
  const statePath = join(prepared.directoryPath, "state.json");
  const eventsPath = join(prepared.directoryPath, "events.jsonl");
  const before = await Promise.all([
    readFile(statePath, "utf8"),
    readFile(eventsPath, "utf8"),
  ]);

  await assert.rejects(
    runner.resume({
      runId: prepared.run.runId,
      action: null,
      expectedRuntimeCompatibility: `${DETACHED_RUNTIME_COMPATIBILITY_TOKEN}-other`,
    }),
    (error) =>
      error instanceof RunnerError &&
      error.code === "ERR_RUNTIME_VERSION_SKEW" &&
      /restart the Agent Runner MCP server/u.test(error.message),
  );
  assert.deepEqual(
    await Promise.all([
      readFile(statePath, "utf8"),
      readFile(eventsPath, "utf8"),
    ]),
    before,
  );
});

test("applies explicit pipeline migrations in order without mutating input", () => {
  const run = Object.freeze({
    runId: PREPARED_RUN,
    pipelineId: "test-pipeline",
    pipelineStateVersion: 1,
    pipelineState: Object.freeze({ value: 1 }),
  });
  const versions = [];
  const pipeline = {
    id: "test-pipeline",
    stateVersion: 3,
    migrations: {
      1(current) {
        versions.push(current.pipelineStateVersion);
        return { ...current.pipelineState, value: 2 };
      },
      2(current) {
        versions.push(current.pipelineStateVersion);
        return { ...current.pipelineState, value: 3 };
      },
    },
    workflow: {
      validateRun(current) {
        assert.equal(current.pipelineStateVersion, 3);
        assert.equal(current.pipelineState.value, 3);
      },
    },
  };

  const migrated = preparePipelineMigration(run, pipeline);
  assert.deepEqual(versions, [1, 2]);
  assert.equal(migrated.pipelineStateVersion, 3);
  assert.deepEqual(run.pipelineState, { value: 1 });
  assert.throws(
    () =>
      preparePipelineMigration(run, {
        ...pipeline,
        migrations: {},
      }),
    (error) =>
      error instanceof RunnerError &&
      error.code === "ERR_PIPELINE_VERSION_SKEW",
  );
  assert.throws(
    () =>
      preparePipelineMigration(run, {
        ...pipeline,
        workflow: {
          validateRun() {
            throw new Error("Invalid migrated shape.");
          },
        },
      }),
    (error) =>
      error instanceof RunnerError &&
      error.code === "ERR_PIPELINE_MIGRATION_FAILED",
  );
});

test("prepares a durable run and submits identified input before continuation", async (t) => {
  const fixture = await createFixture(t);
  const adapter = createAdapter({ questionFirst: true });
  const runner = runnerFor(fixture, { codex: adapter });
  const input = {
    pipelineId: "plan-authoring",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  };

  const prepared = await runner.create(input, { runId: PREPARED_RUN });
  assert.equal(prepared.run.runId, PREPARED_RUN);
  assert.equal(prepared.run.pipelineState.workflowState, "CLARIFY");
  assert.equal(
    (await runner.status(PREPARED_RUN)).run.pipelineState.workflowState,
    "CLARIFY",
  );
  assert.equal(adapter.calls.length, 0);

  const paused = await runner.resume({ runId: PREPARED_RUN, action: null });
  assert.equal(paused.run.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.deepEqual(paused.run.pause.inputRequest.questions, [
    {
      id: "q1",
      question: "Which behavior is required?",
      options: [],
      rationale: "The answer changes the commit plan.",
    },
  ]);
  const response = {
    runId: PREPARED_RUN,
    requestId: paused.run.pause.inputRequest.id,
    expectedRevision: paused.run.revision,
    answers: [{ questionId: "q1", answer: "Use behavior A exactly." }],
  };
  const preview = await runner.previewInput(response);
  const submitted = await runner.submitInput({
    ...response,
    responseHash: preview.responseHash,
  });
  assert.equal(
    submitted.run.pause.inputResponse.transcriptHash,
    preview.responseHash,
  );

  const completed = await runner.resume({ runId: PREPARED_RUN, action: null });
  assert.equal(completed.run.pipelineState.workflowState, "DONE");
  assert.match(
    await readFile(join(fixture.taskPath, "clarifications.md"), "utf8"),
    /### A1\n\nUse behavior A exactly\./u,
  );
});

test("resumes plan execution from its durable trusted-command snapshot", async (t) => {
  const fixture = await createFixture(t);
  await writeFile(
    join(fixture.projectPath, ".gitignore"),
    "/LOCAL_ARTIFACTS/\n",
  );
  await writeFile(
    join(fixture.projectPath, "source.js"),
    "export const value = 1;\n",
  );
  await writeFile(join(fixture.taskPath, "plan.md"), PLAN);
  await executeFile("git", [
    "-C",
    fixture.projectPath,
    "config",
    "user.name",
    "Test",
  ]);
  await executeFile("git", [
    "-C",
    fixture.projectPath,
    "config",
    "user.email",
    "test@example.com",
  ]);
  await executeFile("git", ["-C", fixture.projectPath, "add", "."]);
  await executeFile("git", [
    "-C",
    fixture.projectPath,
    "commit",
    "-qm",
    "test: fixture",
  ]);
  const configuration = {
    schemaVersion: 1,
    defaultBackend: "codex",
    trustedCommands: {
      "service-check": {
        command: "npm run test:service",
        executable: "npm",
        arguments: ["run", "test:service"],
      },
    },
    pipelines: {
      "plan-execution": { trustedChecks: ["service-check"] },
    },
  };
  let configurationLoads = 0;
  const trustedPreflights = [];
  const trustedValidation = {
    async execute() {
      throw new Error("Trusted validation unexpectedly executed.");
    },
    async preflight(options) {
      trustedPreflights.push(options);
    },
  };
  const runStore = createRunStore({ stateRoot: fixture.stateRoot });
  const adapter = {
    async probe() {
      return {
        version: "fake-1.0.0",
        structuredOutput: true,
        readOnly: true,
        autonomousWrite: true,
        gitMetadataWriteBlocked: true,
        workspaceWrite: true,
        localCommit: true,
        remoteWriteBlocked: true,
        nativeSessionContinuation: true,
        nativeSessionFork: true,
      };
    },
    async run() {
      return {
        output: "structured",
        structured: {
          status: "PLAN_REVISION_REQUIRED",
          questions: [],
          reason: "The durable test intentionally stops before bootstrap.",
          question: "",
          options: [],
          whyBlocked: "",
          evidence: ["No provider continuation is required."],
        },
        sessionId: PLANNER_SESSION,
      };
    },
  };
  const firstRunner = createRunner({
    adapters: { codex: adapter },
    clarifications: createClarificationService({ interactive: false }),
    git: createGitService(),
    async loadConfiguration() {
      configurationLoads += 1;
      return parseRunnerConfiguration(JSON.stringify(configuration));
    },
    runStore,
    trustedValidation,
  });
  const prepared = await firstRunner.create(
    {
      pipelineId: "plan-execution",
      projectPath: fixture.projectPath,
      taskPath: fixture.taskPath,
      proactiveClarification: false,
      roleOverrides: {},
      sourceSession: null,
    },
    { runId: PREPARED_RUN },
  );
  const durableSnapshot = prepared.run.pipelineState.trustedValidation;
  assert.equal(configurationLoads, 1);

  const resumed = await createRunner({
    adapters: { codex: adapter },
    clarifications: createClarificationService({ interactive: false }),
    git: createGitService(),
    async loadConfiguration() {
      throw new Error("Resume reloaded runner configuration.");
    },
    runStore,
    trustedValidation,
  }).resume({ runId: PREPARED_RUN, action: null });

  assert.equal(resumed.run.pause.reason, "plan_revision_required");
  assert.deepEqual(
    resumed.run.pipelineState.trustedValidation,
    durableSnapshot,
  );
  assert.equal(configurationLoads, 1);
  assert.deepEqual(trustedPreflights, [
    {
      projectPath: fixture.projectPath,
      snapshot: durableSnapshot,
      storageForbiddenPaths: [
        fixture.projectPath,
        fixture.taskPath,
        runStore.rootPath,
      ],
    },
    {
      projectPath: fixture.projectPath,
      snapshot: durableSnapshot,
      storageForbiddenPaths: [
        fixture.projectPath,
        fixture.taskPath,
        runStore.rootPath,
      ],
    },
  ]);
});

test("unavailable trusted capabilities persist early pauses and retry frozen requests before providers", async (t) => {
  for (const pipelineId of ["plan-execution", "polishing"]) {
    await t.test(pipelineId, async (t) => {
      const fixture = await createFixture(t);
      await writeFile(
        join(fixture.projectPath, ".gitignore"),
        "/LOCAL_ARTIFACTS/\n",
      );
      await writeFile(
        join(fixture.projectPath, "source.js"),
        "export const value = 1;\n",
      );
      await writeFile(join(fixture.taskPath, "plan.md"), PLAN);
      await executeFile("git", [
        "-C",
        fixture.projectPath,
        "config",
        "user.name",
        "Test",
      ]);
      await executeFile("git", [
        "-C",
        fixture.projectPath,
        "config",
        "user.email",
        "test@example.com",
      ]);
      await executeFile("git", ["-C", fixture.projectPath, "add", "."]);
      await executeFile("git", [
        "-C",
        fixture.projectPath,
        "commit",
        "-qm",
        "test: fixture",
      ]);
      if (pipelineId === "polishing")
        await writeFile(
          join(fixture.projectPath, "source.js"),
          "export const value = 2;\n",
        );
      const configuration = {
        schemaVersion: 1,
        defaultBackend: "codex",
        trustedCommands: {
          build: {
            command: "npm run build",
            executable: "npm",
            arguments: ["run", "build"],
            capabilities: { scratch: true },
          },
        },
        pipelines: { [pipelineId]: { trustedChecks: ["build"] } },
      };
      let unavailable = true;
      let providerCalls = 0;
      let loads = 0;
      const requests = [];
      const adapter = {
        async probe() {
          providerCalls += 1;
          return {
            version: "fake-1.0.0",
            structuredOutput: true,
            readOnly: true,
            autonomousWrite: true,
            gitMetadataWriteBlocked: true,
            workspaceWrite: true,
            localCommit: true,
            remoteWriteBlocked: true,
            nativeSessionContinuation: true,
            nativeSessionFork: true,
          };
        },
        async run() {
          providerCalls += 1;
          return {
            output: "structured",
            sessionId: PLANNER_SESSION,
            structured: {
              status: "PRODUCT_DECISION_REQUIRED",
              questions: [],
              reason: "",
              question: "Which behavior should the fixture implement?",
              options: [],
              whyBlocked: "The fixture intentionally stops at clarification.",
              evidence: ["The fixture task leaves behavior unspecified."],
            },
          };
        },
      };
      const trustedValidation = {
        async preflight({ snapshot }) {
          requests.push(snapshot);
          if (unavailable)
            throw Object.assign(new Error("Unavailable fixture capability"), {
              code: "ERR_TRUSTED_VALIDATION_CAPABILITY_UNAVAILABLE",
            });
        },
        async execute() {
          assert.fail("Preflight must not execute checks.");
        },
      };
      const runStore = createRunStore({ stateRoot: fixture.stateRoot });
      const open = () =>
        createRunner({
          adapters: { codex: adapter },
          clarifications: createClarificationService({ interactive: false }),
          trustedValidation,
          runStore,
          async loadConfiguration() {
            loads += 1;
            assert.equal(loads, 1);
            return parseRunnerConfiguration(JSON.stringify(configuration));
          },
        });
      const runner = open();
      const input = {
        pipelineId,
        projectPath: fixture.projectPath,
        taskPath: fixture.taskPath,
        proactiveClarification: false,
        roleOverrides: {},
        sourceSession: null,
      };
      const blocked =
        pipelineId === "plan-execution"
          ? await runner.run(input)
          : await runner.create(input);
      assert.equal(blocked.run.pause.reason, "environment_blocked");
      assert.equal(blocked.run.pipelineState.preflightComplete, false);
      assert.equal(blocked.run.pipelineState.repositoryBaseline, null);
      assert.equal(blocked.run.pipelineState.backendVersions, null);
      assert.deepEqual(blocked.run.hashes, {});
      assert.equal(providerCalls, 0);
      const runId = blocked.run.runId;
      await runner.status(runId);
      assert.equal(requests.length, 1);
      const retried = await open().resume({ runId });
      assert.equal(retried.run.pause.reason, "environment_blocked");
      assert.equal(providerCalls, 0);
      assert.equal(requests.length, 2);
      configuration.trustedCommands.build.capabilities = { cache: true };
      unavailable = false;
      const resumed = await open().resume({ runId });
      assert.equal(resumed.run.pause.reason, "product_decision_required");
      assert.ok(providerCalls > 0);
      assert.equal(loads, 1);
      assert.equal(requests.length, 3);
      for (const request of requests)
        assert.deepEqual(request, blocked.run.pipelineState.trustedValidation);
      assert.deepEqual(
        resumed.run.pipelineState.trustedValidation,
        blocked.run.pipelineState.trustedValidation,
      );
    });
  }
});

test("submits input previewed from a compatible legacy run", async (t) => {
  const fixture = await createFixture(t);
  const runner = runnerFor(fixture, {
    codex: createAdapter({ questionFirst: true }),
  });
  const paused = await runner.run({
    pipelineId: "plan-authoring",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  });
  await rewriteRunAsLegacy(paused.directoryPath);

  const response = {
    runId: paused.run.runId,
    requestId: paused.run.pause.inputRequest.id,
    expectedRevision: paused.run.revision,
    answers: [{ questionId: "q1", answer: "Use behavior A exactly." }],
  };
  const preview = await runner.previewInput(response);
  await assert.rejects(
    runner.submitInput({
      ...response,
      expectedRevision: response.expectedRevision + 1,
      responseHash: preview.responseHash,
    }),
    (error) => error.code === "ERR_STALE_INPUT_REQUEST",
  );
  const unchanged = await runner.status(paused.run.runId);
  assert.equal(unchanged.run.schemaVersion, 1);
  assert.equal(unchanged.run.revision, paused.run.revision);

  const submitted = await runner.submitInput({
    ...response,
    responseHash: preview.responseHash,
  });

  assert.equal(submitted.run.schemaVersion, RUN_STATE_SCHEMA_VERSION);
  assert.equal(submitted.run.revision, paused.run.revision + 2);
  assert.equal(
    submitted.run.pause.inputResponse.transcriptHash,
    preview.responseHash,
  );
  const events = (
    await readFile(join(paused.directoryPath, "events.jsonl"), "utf8")
  )
    .trimEnd()
    .split("\n")
    .map((line) => JSON.parse(line));
  assert.equal(events.at(-2).activity.kind, "migrated");
  assert.equal(events.at(-1).activity.kind, "submitted");
});

test("rejects incompatible or unsupported source sessions before creating a run", async (t) => {
  const fixture = await createFixture(t);
  const adapter = createAdapter();
  const runner = runnerFor(fixture, { codex: adapter });

  await assert.rejects(
    runner.run({
      pipelineId: "plan-authoring",
      projectPath: fixture.projectPath,
      taskPath: fixture.taskPath,
      roleOverrides: {
        planner: { backend: "codex" },
        reviewer: { backend: "codex" },
      },
      sourceSession: { backend: "claude", id: SOURCE_SESSION },
    }),
    (error) =>
      error instanceof RunnerError &&
      error.code === "ERR_SOURCE_BACKEND_MISMATCH",
  );

  const noForkRunner = runnerFor(fixture, {
    codex: createAdapter({ fork: false }),
  });
  await assert.rejects(
    noForkRunner.run({
      pipelineId: "plan-authoring",
      projectPath: fixture.projectPath,
      taskPath: fixture.taskPath,
      roleOverrides: {},
      sourceSession: { backend: "codex", id: SOURCE_SESSION },
    }),
    (error) =>
      error instanceof RunnerError &&
      error.code === "ERR_UNSUPPORTED_SOURCE_SESSION",
  );

  assert.deepEqual(
    await readdir(join(fixture.stateRoot, "runs")).catch((error) => {
      if (error?.code === "ENOENT") {
        return [];
      }
      throw error;
    }),
    [],
  );
});

test("persists a trusted source profile and applies resolved turn preferences", async (t) => {
  const fixture = await createFixture(t);
  const adapter = createAdapter();
  const profileDirectory = join(fixture.workspace, "claude-profile");
  const runner = runnerFor(
    fixture,
    { claude: adapter },
    {
      configuration: {
        schemaVersion: 1,
        profiles: {
          "claude-primary": {
            backend: "claude",
            configDirectory: profileDirectory,
          },
        },
        pipelines: {
          "plan-authoring": {
            roles: { arbiter: { profile: "claude-primary" } },
          },
        },
      },
    },
  );

  const result = await runner.run({
    pipelineId: "plan-authoring",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    roleOverrides: {},
    executionOverrides: { model: "sonnet", contextSize: "200000" },
    sourceSession: {
      backend: "claude",
      id: SOURCE_SESSION,
      profile: "claude-primary",
    },
  });

  assert.equal(result.run.pipelineState.workflowState, "DONE");
  assert.equal(result.run.sessionLineage.sourceProfile, "claude-primary");
  assert.deepEqual(result.run.roles.planner, {
    backend: "claude",
    profile: profileDirectory,
    model: "sonnet",
    contextSize: "200000",
    effort: "current",
  });
  assert.deepEqual(adapter.probes, [
    {
      profile: profileDirectory,
      model: "sonnet",
      contextSize: "200000",
      effort: "current",
    },
  ]);
  assert.ok(
    adapter.calls.every(
      ({ profile, model, contextSize }) =>
        profile === profileDirectory &&
        model === "sonnet" &&
        contextSize === "200000",
    ),
  );
  assert.deepEqual(adapter.calls[0].session, {
    mode: "fork",
    id: SOURCE_SESSION,
  });
});

test("does not require an unused Arbiter backend", async (t) => {
  const fixture = await createFixture(t);
  const adapter = createAdapter();
  const runner = runnerFor(
    fixture,
    { codex: adapter },
    {
      configuration: {
        ...RUNNER_CONFIGURATION,
        pipelines: {
          "plan-authoring": {
            roles: { arbiter: { backend: "claude" } },
          },
        },
      },
    },
  );

  const result = await runner.run({
    pipelineId: "plan-authoring",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    roleOverrides: {},
    sourceSession: null,
  });

  assert.equal(result.run.pipelineState.workflowState, "DONE");
  assert.deepEqual(result.run.roles.arbiter, {
    backend: "claude",
    profile: "current",
    model: "current",
    contextSize: "current",
    effort: "current",
  });
});

test("persists descriptor-selected roles and probes only required roles", async (t) => {
  const fixture = await createFixture(t);
  const adapter = createAdapter();
  const runner = runnerFor(fixture, { codex: adapter });

  const prepared = await runner.create({
    pipelineId: "plan-authoring",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    roleOverrides: {
      planner: { model: "planner-model" },
      reviewer: { model: "reviewer-model" },
      arbiter: { backend: "claude" },
    },
    sourceSession: null,
  });
  const pipeline = getPipeline("plan-authoring");

  assert.deepEqual(
    Object.keys(prepared.run.roles),
    pipeline.resolveActiveRoles(prepared.run.pipelineState.settings),
  );
  assert.deepEqual(adapter.probes, [
    {
      profile: "current",
      model: "planner-model",
      contextSize: "current",
      effort: "current",
    },
    {
      profile: "current",
      model: "reviewer-model",
      contextSize: "current",
      effort: "current",
    },
  ]);
  assert.equal(prepared.run.roles.arbiter.backend, "claude");
});

test("runs lazy plan authoring with only one Planner fork", async (t) => {
  const fixture = await createFixture(t);
  const adapter = createAdapter();
  const runner = runnerFor(
    fixture,
    { codex: adapter },
    {
      configuration: {
        ...RUNNER_CONFIGURATION,
        defaultEffort: "xhigh",
        pipelines: {
          "plan-authoring": {
            mode: "independent",
            roles: {
              reviewer: {
                backend: "claude",
                model: "reviewer-model",
                effort: "low",
              },
              arbiter: {
                backend: "claude",
                model: "arbiter-model",
                effort: "medium",
              },
            },
          },
        },
      },
    },
  );

  const result = await runner.run({
    pipelineId: "plan-authoring",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    roleOverrides: {},
    settingOverrides: { mode: "lazy" },
    sourceSession: { backend: "codex", id: SOURCE_SESSION },
  });

  assert.equal(result.run.pipelineState.workflowState, "DONE");
  assert.deepEqual(Object.keys(result.run.roles), ["planner"]);
  assert.equal(result.run.pipelineState.settings.mode, "lazy");
  assert.equal(adapter.probes.length, 1);
  assert.equal(result.run.roles.planner.effort, "xhigh");
  assert.equal(adapter.probes[0].effort, "xhigh");
  assert.ok(adapter.calls.every(({ effort }) => effort === "xhigh"));
  assert.equal(
    adapter.calls.filter(({ session }) => session?.mode === "fork").length,
    1,
  );
  assert.deepEqual(
    result.run.sessionLineage.children.map(({ role }) => role),
    ["planner"],
  );
});

test("runs combined authoring with independent role probes and checkpoint forks", async (t) => {
  const fixture = await createFixture(t);
  const adapter = createAdapter();
  const runner = runnerFor(fixture, { codex: adapter });
  const result = await runner.run({
    pipelineId: "plan-authoring",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    roleOverrides: {
      planner: { model: "planner-model" },
      reviewer: { model: "reviewer-model" },
      arbiter: { backend: "claude" },
    },
    settingOverrides: { mode: "combined" },
    sourceSession: { backend: "codex", id: SOURCE_SESSION },
  });
  assert.equal(result.run.pipelineState.workflowState, "DONE");
  assert.equal(result.run.pipelineState.settings.mode, "combined");
  assert.deepEqual(Object.keys(result.run.roles), [
    "planner",
    "reviewer",
    "arbiter",
  ]);
  assert.deepEqual(
    adapter.probes.map(({ model }) => model),
    ["planner-model", "reviewer-model"],
  );
  assert.equal(adapter.calls.length, 5);
  assert.equal(
    adapter.calls.filter(({ session }) => session?.mode === "fork").length,
    3,
  );
  assert.deepEqual(
    result.run.sessionLineage.children.map(({ role }) => role),
    ["planner", "planner", "reviewer"],
  );
  assert.ok(adapter.calls.every(({ access }) => access === "read-only"));
  assert.equal(await readFile(join(fixture.taskPath, "plan.md"), "utf8"), PLAN);
});

test("persists project overrides and blocks later configuration changes", async (t) => {
  const fixture = await createFixture(t);
  const adapter = createAdapter({ questionFirst: true });
  const projectConfigurationDirectory = join(
    fixture.projectPath,
    "LOCAL_ARTIFACTS",
  );
  const projectConfigurationPath = join(
    projectConfigurationDirectory,
    "agent-runner.json",
  );
  await Promise.all([
    mkdir(projectConfigurationDirectory),
    writeFile(join(fixture.projectPath, ".gitignore"), "/LOCAL_ARTIFACTS/\n"),
  ]);
  await writeFile(
    projectConfigurationPath,
    JSON.stringify({
      schemaVersion: 1,
      artifactRoot: "project-artifacts",
      defaultProfile: "codex-work",
      defaultModel: "project-model",
      defaultEffort: "high",
      pipelines: {
        "plan-authoring": {
          mode: "lazy",
          maxRevisionRounds: 4,
          preferredCommitLineLimit: 450,
          roles: { reviewer: { contextSize: "200000" } },
        },
      },
    }),
  );
  const configuration = {
    schemaVersion: 1,
    defaultBackend: "claude",
    defaultModel: "runner-model",
    profiles: {
      "codex-work": { backend: "codex", profile: "native-work" },
    },
    pipelines: {
      "plan-authoring": {
        maxRevisionRounds: 9,
        preferredCommitLineLimit: 700,
        roles: { reviewer: { model: "runner-reviewer" } },
      },
    },
  };
  const runner = runnerFor(fixture, { codex: adapter }, { configuration });

  const paused = await runner.run({
    pipelineId: "plan-authoring",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    proactiveClarification: false,
    roleOverrides: { planner: { model: "cli-planner" } },
    settingOverrides: { mode: "independent" },
    sourceSession: null,
  });

  assert.equal(paused.run.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.deepEqual(paused.run.pipelineState.settings, {
    maxRevisionRounds: 4,
    mode: "independent",
    preferredCommitLineLimit: 450,
    stagnationWindowRounds: 3,
  });
  assert.equal(
    paused.run.pipelineState.pendingEdit.transcriptPath,
    join(fixture.taskPath, "clarifications.md"),
  );
  assert.deepEqual(paused.run.roles.planner, {
    backend: "codex",
    profile: "native-work",
    model: "cli-planner",
    contextSize: "current",
    effort: "high",
  });
  assert.deepEqual(paused.run.roles.reviewer, {
    backend: "codex",
    profile: "native-work",
    model: "project-model",
    contextSize: "200000",
    effort: "high",
  });
  assert.equal(
    paused.run.projectConfigurationProtection.path,
    projectConfigurationPath,
  );
  assert.match(
    paused.run.projectConfigurationProtection.contentHash,
    /^[a-f0-9]{64}$/u,
  );
  const preparedPolishing = await runner.create({
    pipelineId: "polishing",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  });
  assert.equal(
    preparedPolishing.run.pipelineState.artifactRoot,
    "project-artifacts",
  );

  await Promise.all([
    writeFile(
      projectConfigurationPath,
      '{"schemaVersion":1,"defaultEffort":"low"}\n',
    ),
    writeFile(
      join(fixture.taskPath, "clarifications.md"),
      `${await readFile(join(fixture.taskPath, "clarifications.md"), "utf8")}\nUse behavior A.\n`,
    ),
  ]);
  const completed = await runner.resume({
    runId: paused.run.runId,
    action: null,
  });

  assert.equal(completed.run.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.deepEqual(completed.run.pause, {
    reason: "project_configuration_changed",
    code: "ERR_PROJECT_CONFIGURATION_CHANGED",
  });
  assert.equal(
    (await runner.status(completed.run.runId)).run.pause.reason,
    "project_configuration_changed",
  );
  assert.deepEqual(completed.run.roles, paused.run.roles);
  assert.deepEqual(
    completed.run.pipelineState.settings,
    paused.run.pipelineState.settings,
  );
});

test("configuration drift cannot revive a canceled run", async (t) => {
  const fixture = await createFixture(t);
  const configurationDirectory = join(fixture.projectPath, "LOCAL_ARTIFACTS");
  const configurationPath = join(configurationDirectory, "agent-runner.json");
  await mkdir(configurationDirectory);
  await Promise.all([
    writeFile(join(fixture.projectPath, ".gitignore"), "/LOCAL_ARTIFACTS/\n"),
    writeFile(configurationPath, '{"schemaVersion":1}\n'),
  ]);
  const runner = runnerFor(fixture, { codex: createAdapter() });
  const created = await runner.create({
    pipelineId: "plan-authoring",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  });
  await runner.requestOperatorStop({
    runId: created.run.runId,
    kind: "cancel_requested",
    expectedRevision: created.run.revision,
    idempotencyKey: "cancel-before-configuration-drift",
  });
  const canceled = await runner.resume({
    runId: created.run.runId,
    action: null,
  });
  assert.equal(canceled.run.pipelineState.workflowState, "CANCELED");

  await writeFile(
    configurationPath,
    '{"schemaVersion":1,"artifactRoot":"changed"}\n',
  );
  await assert.rejects(
    runner.resume({ runId: created.run.runId, action: null }),
    { code: "ERR_RUN_CANCELED" },
  );
  const unchanged = await runner.status(created.run.runId);
  assert.equal(unchanged.run.pipelineState.workflowState, "CANCELED");
  assert.equal(unchanged.run.revision, canceled.run.revision);
});

test("guards project configuration after every pipeline provider turn", async (t) => {
  for (const pipelineId of ["plan-authoring", "plan-execution", "polishing"]) {
    await t.test(pipelineId, async (t) => {
      const fixture = await operatorFixture(t, pipelineId);
      const configurationDirectory = join(
        fixture.projectPath,
        "LOCAL_ARTIFACTS",
      );
      const configurationPath = join(
        configurationDirectory,
        "agent-runner.json",
      );
      await mkdir(configurationDirectory, { recursive: true });
      await writeFile(configurationPath, '{"schemaVersion":1}\n');
      const delegate =
        pipelineId === "plan-authoring"
          ? createAdapter()
          : createExecutionAdapter();
      let calls = 0;
      const runner = runnerFor(fixture, {
        codex: {
          ...delegate,
          async run(request) {
            calls += 1;
            const response = await delegate.run(request);
            await writeFile(
              configurationPath,
              '{"schemaVersion":1,"artifactRoot":"changed"}\n',
            );
            return response;
          },
        },
      });

      const result = await runner.run({
        pipelineId,
        projectPath: fixture.projectPath,
        taskPath: fixture.taskPath,
        proactiveClarification: false,
        roleOverrides: {},
        sourceSession: null,
      });

      assert.equal(calls, 1);
      assert.equal(result.run.pipelineState.workflowState, "WAITING_FOR_USER");
      assert.deepEqual(result.run.pause, {
        reason: "project_configuration_changed",
        code: "ERR_PROJECT_CONFIGURATION_CHANGED",
      });
    });
  }
});

test("retains protected-configuration drift through stop reconciliation", async (t) => {
  const fixture = await operatorFixture(t, "plan-authoring");
  const configurationDirectory = join(fixture.projectPath, "LOCAL_ARTIFACTS");
  const configurationPath = join(configurationDirectory, "agent-runner.json");
  await mkdir(configurationDirectory, { recursive: true });
  await writeFile(configurationPath, '{"schemaVersion":1}\n');
  const entered = Promise.withResolvers();
  const store = createRunStore({ stateRoot: fixture.stateRoot });
  const runner = runnerFor(
    fixture,
    {
      codex: {
        ...createAdapter(),
        async run(request) {
          entered.resolve();
          return new Promise((resolve, reject) => {
            request.signal.addEventListener(
              "abort",
              () => reject(request.signal.reason),
              { once: true },
            );
          });
        },
      },
    },
    { runStore: store },
  );
  const active = runner.run({
    pipelineId: "plan-authoring",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    proactiveClarification: false,
    roleOverrides: {},
    sourceSession: null,
  });
  await entered.promise;
  await writeFile(
    configurationPath,
    '{"schemaVersion":1,"artifactRoot":"changed"}\n',
  );
  const [runId] = await readdir(join(fixture.stateRoot, "runs"));
  const current = (await runner.status(runId)).run;
  await runner.requestOperatorStop({
    runId: current.runId,
    kind: "pause_requested",
    expectedRevision: current.revision,
    idempotencyKey: "configuration-stop",
  });

  const stopped = (await active).run;
  assert.equal(stopped.pause.reason, "operator_paused");
  assert.deepEqual(stopped.pause.operatorResume.pause, {
    reason: "project_configuration_changed",
    code: "ERR_PROJECT_CONFIGURATION_CHANGED",
  });
  assert.equal(stopped.pause.operatorResume.workflowState, "WAITING_FOR_USER");
  const resumed = await runner.resume({ runId: stopped.runId, action: null });
  assert.equal(resumed.run.pause.reason, "project_configuration_changed");
});

test("never reads an Agent Runner configuration file in the target repository", async (t) => {
  const fixture = await createFixture(t);
  await writeFile(
    join(fixture.projectPath, ".agent-runner.json"),
    '{"schemaVersion":99}\n',
  );
  const roleOverrides = {
    planner: { backend: "codex", model: "planner-model" },
    reviewer: { backend: "codex", model: "reviewer-model" },
    arbiter: { backend: "codex", model: "arbiter-model" },
  };
  const runner = createRunner({
    adapters: { codex: createAdapter() },
    clarifications: createClarificationService({ interactive: false }),
    git: createGitService(),
    loadConfiguration: configurationLoader(),
    runStore: createRunStore({ stateRoot: fixture.stateRoot }),
  });

  const result = await runner.run({
    pipelineId: "plan-authoring",
    projectPath: fixture.projectPath,
    taskPath: fixture.taskPath,
    roleOverrides,
    sourceSession: null,
  });

  assert.equal(result.run.pipelineState.workflowState, "DONE");
  assert.deepEqual(result.run.roles, {
    planner: {
      ...roleOverrides.planner,
      profile: "current",
      contextSize: "current",
      effort: "current",
    },
    reviewer: {
      ...roleOverrides.reviewer,
      profile: "current",
      contextSize: "current",
      effort: "current",
    },
    arbiter: {
      ...roleOverrides.arbiter,
      profile: "current",
      contextSize: "current",
      effort: "current",
    },
  });
});

test("releases a new run lease when activity delivery fails", async (t) => {
  const fixture = await createFixture(t);
  const runStore = createRunStore({ stateRoot: fixture.stateRoot });
  const deliveryError = new Error("Activity delivery failed.");
  const runner = createRunner({
    adapters: { codex: createAdapter() },
    clarifications: createClarificationService({ interactive: false }),
    git: createGitService(),
    loadConfiguration: configurationLoader(),
    onActivity() {
      throw deliveryError;
    },
    runStore,
  });

  await assert.rejects(
    runner.run({
      pipelineId: "plan-authoring",
      projectPath: fixture.projectPath,
      taskPath: fixture.taskPath,
      roleOverrides: {},
      sourceSession: null,
    }),
    (error) => error === deliveryError,
  );

  const [runId] = await readdir(join(fixture.stateRoot, "runs"));
  const lease = await runStore.acquireRunLease(runId);
  await lease.release();
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

for (const pauseReason of ["local_artifacts_not_ignored", "unsafe_git_state"]) {
  test(`resumes polishing after ${pauseReason} preflight is corrected`, async (t) => {
    const fixture = await createFixture(t);
    const ignoreArtifacts = pauseReason === "unsafe_git_state";
    await Promise.all([
      writeFile(
        join(fixture.projectPath, ".gitignore"),
        ignoreArtifacts ? "/LOCAL_ARTIFACTS/\n" : "/ignored/\n",
      ),
      writeFile(
        join(fixture.projectPath, "source.js"),
        "export const value = 0;\n",
      ),
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
    await writeFile(
      join(fixture.projectPath, "source.js"),
      "export const value = 1;\n",
    );

    const baseGit = createGitService();
    let preflightCalls = 0;
    const git =
      pauseReason === "unsafe_git_state"
        ? {
            ...baseGit,
            async preflight(options) {
              preflightCalls += 1;
              if (preflightCalls === 2) {
                const error = new Error(
                  "Git snapshot raced with another process.",
                );
                error.code = "ERR_GIT_SNAPSHOT_RACE";
                throw error;
              }
              return baseGit.preflight(options);
            },
          }
        : baseGit;
    const adapter = createExecutionAdapter();
    const runner = runnerFor(
      fixture,
      { codex: adapter },
      {
        git,
        configuration: {
          ...RUNNER_CONFIGURATION,
          profiles: {
            "codex-work": { backend: "codex", profile: "work" },
          },
        },
      },
    );

    const paused = await runner.run({
      pipelineId: "polishing",
      projectPath: fixture.projectPath,
      taskPath: fixture.taskPath,
      roleOverrides: {},
      executionOverrides: {
        profile: "codex-work",
        model: "polishing-model",
        contextSize: "200000",
      },
      sourceSession: null,
    });
    assert.equal(paused.run.pipelineState.workflowState, "WAITING_FOR_USER");
    assert.equal(paused.run.pipelineState.preflightComplete, false);
    assert.equal(paused.run.pause.reason, pauseReason);

    if (!ignoreArtifacts) {
      await writeFile(
        join(fixture.projectPath, ".gitignore"),
        "/ignored/\n/LOCAL_ARTIFACTS/\n",
      );
    }
    const completed = await runner.resume({
      runId: paused.run.runId,
      action: null,
    });

    assert.equal(completed.run.pipelineState.workflowState, "DONE");
    assert.equal(completed.run.pause, null);
    assert.deepEqual(
      adapter.probes,
      Array.from({ length: 3 }, () => ({
        profile: "work",
        model: "polishing-model",
        contextSize: "200000",
        effort: "current",
      })),
    );
  });
}

test("verified commit settlement stops before the next Worker and retains configuration blockers", async (t) => {
  for (const [kind, steps, drift, timing = "immediate"] of [
    ["pause_requested", 1, false],
    ["cancel_requested", 1, false],
    ["pause_requested", 2, false],
    ["cancel_requested", 2, false],
    ["pause_requested", 1, true],
    ["pause_requested", 1, false, "after-current-commit"],
    ["cancel_requested", 1, false, "after-current-commit"],
    ["pause_requested", 2, false, "after-current-commit"],
    ["cancel_requested", 2, false, "after-current-commit"],
    ["pause_requested", 1, true, "after-current-commit"],
    ["cancel_requested", 1, true, "after-current-commit"],
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
  for (const kind of ["pause_requested", "cancel_requested"]) {
    for (const outcome of kind === "pause_requested"
      ? ["blocked", "failed", "suspended", "superseded"]
      : ["blocked", "failed", "suspended"]) {
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
        const canceled =
          kind === "cancel_requested" || outcome === "superseded";
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
  }
});

test("commit-boundary capability rejects unselected steps and other pipelines", async (t) => {
  for (const pipelineId of ["plan-execution", "plan-authoring", "polishing"]) {
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
  for (const kind of ["pause_requested", "cancel_requested"]) {
    for (const boundary of [
      "event-appended",
      "state-replaced",
      "progress-replaced",
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
                if (
                  request.prompt.includes("Implement the changes described")
                ) {
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
  for (const kind of ["pause_requested", "cancel_requested"]) {
    for (const fault of [
      "prepared",
      "consumed",
      "absent",
      "invalid",
      "verification",
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
            assert.deepEqual(
              restored.pause,
              stopped.pause.operatorResume.pause,
            );
        }
        assert.equal(commits, ["prepared", "consumed"].includes(fault) ? 0 : 1);
      });
    }
  }
});
