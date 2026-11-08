import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import {
  integratedFinalizationContent,
  integratedFinalizationPath,
  integratedIgnoreContent,
  integratedIgnorePaths,
  externalFinalizationContent,
  externalFinalizationPath,
  initPipeline,
} from "@agent-runner/init";
import {
  ConfigurationError,
  parseRunnerConfiguration,
} from "../src/config/index.js";
import {
  AgentBoundaryError,
  CodexAdapterError,
  normalizeFailureRecord,
} from "../src/agents/index.js";
import {
  ClarificationError,
  createClarificationService,
} from "../src/clarifications/index.js";
import { main } from "../src/index.js";
import { createMcpControlPlane } from "../src/mcp/index.js";
import { createRunner } from "../src/runner/index.js";
import { createRunStore } from "../src/state/index.js";
import {
  createWorkspaceService,
  WorkspaceSafetyError,
} from "../src/workspace/index.js";
import { createGitService } from "../src/git/index.js";
import { createGuidanceService } from "../src/guidance/index.js";

const hash = (value) => createHash("sha256").update(value).digest("hex");
const execute = promisify(execFile);
async function fixture(
  t,
  placement,
  mode,
  {
    boundary = async () => {},
    beforeRun = async () => false,
    inactivityTimers,
    availabilityClock,
    availabilityWait,
    beforeFile = async () => {},
    afterFile = async () => {},
    beforeFinish = async () => {},
    beforeTransition = async () => {},
    beforeChild = async () => {},
    beforeInfrastructureRelease = async () => {},
    afterGuideReceipt = async () => {},
    beforeProof = () => {},
    afterSnapshot = async () => {},
    beforeInspect = async () => {},
    beforeInspectControls = async () => {},
    beforeInspectPath = async () => {},
    afterInspectPath = async () => {},
    beforeInspectInfrastructure = async () => {},
    beforeReadFile = async () => {},
    afterWorktreeLease = async () => {},
    onActivity = async () => {},
    probeVersion = () => "fixture",
    terminalFinding = false,
    repairChecks = false,
    enclosingWorktree = false,
    transformResult = async (result) => result,
    clarificationHooks = {},
    clarificationService = createClarificationService({ interactive: false }),
    maxRevisionRounds = 20,
  } = {},
) {
  const root = await fs.mkdtemp(join(tmpdir(), "init-runtime-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const workspacePath = enclosingWorktree ? join(root, "workspace") : root;
  if (enclosingWorktree) {
    await fs.mkdir(workspacePath);
    await execute("git", ["init", "--quiet", workspacePath]);
  }
  const projectPath = join(workspacePath, "project");
  const taskPath = join(root, "task");
  await fs.mkdir(projectPath);
  await fs.mkdir(taskPath);
  if (placement === "integrated" && !enclosingWorktree)
    await execute("git", ["init", "--quiet", projectPath]);
  await fs.writeFile(
    join(projectPath, "AGENTS.md"),
    "Validate from the project root with node --test.\n",
  );
  await fs.writeFile(
    join(taskPath, "task.md"),
    "Prepare reviewed infrastructure.\n",
  );
  const workspace = createWorkspaceService();
  const controlledWorkspace = {
    ...workspace,
    async inspect(request, ...options) {
      await beforeInspect(request);
      return workspace.inspect(request, ...options);
    },
    async inspectControls(request, ...options) {
      await beforeInspectControls(request);
      return workspace.inspectControls(request, ...options);
    },
    async inspectPath(request) {
      await beforeInspectPath(request);
      const inspected = await workspace.inspectPath(request);
      await afterInspectPath(request, inspected);
      return inspected;
    },
    async readFile(request) {
      await beforeReadFile(request);
      return workspace.readFile(request);
    },
    async inspectInfrastructure(request) {
      await beforeInspectInfrastructure(request);
      return workspace.inspectInfrastructure(request);
    },
    snapshotProof(request) {
      beforeProof(request);
      return workspace.snapshotProof(request);
    },
    async snapshot(request) {
      const snapshot = await workspace.snapshot(request);
      await afterSnapshot(request, snapshot);
      return snapshot;
    },
    async publishInfrastructureFile(request) {
      await beforeFile(request);
      const result = await workspace.publishInfrastructureFile(request);
      await afterFile(request, result);
      return result;
    },
    publishInfrastructureDirectory: (request) =>
      workspace.publishInfrastructureDirectory({
        ...request,
        // The workspace suite owns the native no-clobber primitive; this isolated
        // lifecycle fixture supplies controlled directory publication without processes.
        publishDirectory: async ({
          sourceParent,
          sourceName,
          destinationParent,
          destinationName,
        }) =>
          fs.rename(
            `/proc/self/fd/${sourceParent}/${sourceName}`,
            `/proc/self/fd/${destinationParent}/${destinationName}`,
          ),
      }),
  };
  const calls = [];
  let sequence = 0;
  let findingReturned = false;
  let proposalHash;
  const adapter = {
    async probe(request) {
      const bindings = [];
      for (const path of request?.workspacePolicy?.infrastructurePaths ?? [])
        bindings.push(
          await workspace.inspectPath({ projectPath: dirname(path), path }),
        );
      return {
        version: probeVersion(),
        readOnly: true,
        structuredOutput: true,
        declaredWorkspace: true,
        remoteWriteBlocked: true,
        nativeSessionContinuation: true,
        nativeSessionFork: true,
        policyReceipt: {
          schemaVersion: 1,
          fingerprint: hash(JSON.stringify({ request, bindings })),
          supportedAccess: ["read-only"],
        },
      };
    },
    async run(request) {
      assert.equal(request.access, "read-only");
      calls.push(request);
      const reconstructed = await beforeRun(request);
      const objects = request.prompt
        .split("\n")
        .filter((line) => line.startsWith("{"))
        .map((line) => JSON.parse(line));
      const evidence = objects.find((value) => value.inspection);
      let structured;
      if (request.schema.properties.resources) {
        const state = {
          inspection: evidence.inspection,
          selection: evidence.selection,
          createdFinalizationPath: evidence.createdFinalizationPath,
        };
        const { rootPath, configurationPath, artifactPath } = state.selection;
        const checks = [
          repairChecks && findingReturned
            ? "node --test --test-reporter=spec"
            : "node --test",
        ];
        const finalizationPath =
          placement === "external"
            ? externalFinalizationPath(state)
            : integratedFinalizationPath(state, checks);
        let config;
        try {
          config = JSON.parse(await fs.readFile(configurationPath, "utf8"));
        } catch (error) {
          if (error.code !== "ENOENT") throw error;
          config = { schemaVersion: 1 };
        }
        config.artifactRoot = relative(rootPath, artifactPath);
        config.infrastructure = {
          schemaVersion: 1,
          placement,
          projectPath,
          rootPath,
        };
        config.pipelines ??= {};
        for (const id of ["plan-execution", "polishing"])
          config.pipelines[id] = {
            ...config.pipelines[id],
            finalization: relative(rootPath, finalizationPath),
          };
        const resource = (path, kind, content) => {
          const before = state.inspection.entries.find(
            (entry) => entry.path === path,
          );
          const beforeHash =
            before?.kind === "directory"
              ? hash(JSON.stringify({ kind: "directory" }))
              : (before?.hash ?? null);
          return {
            path,
            kind,
            content,
            beforeHash,
            action:
              beforeHash === null
                ? "create"
                : kind === "artifacts" || hash(content) === beforeHash
                  ? "reuse"
                  : "replace",
          };
        };
        const guidePath = join(artifactPath, "agent-runner", "rules.md");
        let guide = "Preserve useful local instructions.\n";
        try {
          guide = await fs.readFile(guidePath, "utf8");
        } catch (error) {
          if (error.code !== "ENOENT") throw error;
        }
        structured = {
          summary: "Prepare reviewed infrastructure.",
          checks,
          resources: [
            resource(
              configurationPath,
              "configuration",
              JSON.stringify(config),
            ),
            resource(artifactPath, "artifacts", ""),
            resource(
              finalizationPath,
              "finalization",
              placement === "external"
                ? externalFinalizationContent(state, checks)
                : integratedFinalizationContent(state, checks),
            ),
            resource(guidePath, "guidance", guide),
          ],
        };
        if (placement === "integrated") {
          let original = "";
          try {
            original = await fs.readFile(
              join(projectPath, ".gitignore"),
              "utf8",
            );
          } catch (error) {
            if (error.code !== "ENOENT") throw error;
          }
          structured.resources.push(
            resource(join(projectPath, ".gitignore"), "ignore", original),
          );
          const paths = integratedIgnorePaths({
            ...state,
            proposal: structured,
          });
          const needed = [];
          const git = createGitService();
          for (const path of paths) {
            const inspected = await git.inspectPath({ projectPath, path });
            if (
              !inspected.ignored &&
              !needed.some(
                (parent) => path === parent || path.startsWith(`${parent}/`),
              )
            )
              needed.push(path);
          }
          structured.resources[structured.resources.length - 1] = resource(
            join(projectPath, ".gitignore"),
            "ignore",
            integratedIgnoreContent(original, projectPath, needed),
          );
        }
        proposalHash = hash(JSON.stringify(structured));
      } else if (request.schema.properties.status.enum.includes("READY"))
        structured = { status: "READY", questions: [], reason: "" };
      else {
        const terminal = request.prompt.includes(
          "Distinct terminal confirmation:",
        );
        if (terminal) {
          await boundary("terminal", { projectPath, taskPath });
          assert.ok(
            await fs.readFile(
              join(
                objects[0].selection.artifactPath,
                "agent-runner",
                "rules.md",
              ),
              "utf8",
            ),
          );
        }
        const finding = terminal && terminalFinding && !findingReturned;
        if (finding) findingReturned = true;
        structured = {
          status: finding ? "FINDINGS" : "CLEAN",
          proposalHash:
            evidence?.proposalHash ?? objects[0]?.proposalHash ?? proposalHash,
          findings: finding
            ? ["Review the prepared working-directory instruction again."]
            : [],
        };
      }
      if (!request.schema.properties.status.enum.includes("READY"))
        structured = {
          status: "PROPOSAL",
          question: "",
          options: [],
          whyBlocked: "",
          evidence: [],
          ...structured,
        };
      structured = await transformResult(structured, request, evidence);
      await boundary("response", {
        request,
        structured,
        projectPath,
        taskPath,
      });
      return {
        structured,
        sessionId:
          !reconstructed && request.session?.mode === "continue"
            ? request.session.id
            : `child-${++sequence}`,
      };
    },
  };
  const store = createRunStore({ stateRoot: join(root, "state") });
  const infrastructureLeases = new WeakMap();
  const runStore = {
    ...store,
    async recordChildSession(...args) {
      await beforeChild();
      return store.recordChildSession(...args);
    },
    async transitionRun(lease, patch, options) {
      await beforeTransition(patch, options);
      return store.transitionRun(lease, patch, options);
    },
    async acquireWorktreeLease(path, runId) {
      const lease = await store.acquireWorktreeLease(path, runId);
      await afterWorktreeLease({ path, runId });
      return lease;
    },
    async acquireInfrastructureLease(path, runId) {
      const lease = await store.acquireInfrastructureLease(path, runId);
      const controlled = {
        runId,
        async release() {
          await beforeInfrastructureRelease();
          return lease.release();
        },
      };
      infrastructureLeases.set(controlled, lease);
      return controlled;
    },
    assertWorkspaceLease(lease, workspaceLease, path) {
      return store.assertWorkspaceLease(
        lease,
        infrastructureLeases.get(workspaceLease) ?? workspaceLease,
        path,
      );
    },
    async finishAgentTurn(lease, active) {
      await beforeFinish(active);
      return store.finishAgentTurn(lease, active);
    },
    async beginAction(input) {
      const action = await store.beginAction(input);
      return {
        ...action,
        get record() {
          return action.record;
        },
        async complete(receipt) {
          const result = await action.complete(receipt);
          if (input.tool === "guidance_update")
            await afterGuideReceipt(receipt);
          return result;
        },
      };
    },
  };
  const runner = createRunner({
    workspace: controlledWorkspace,
    runStore,
    onActivity,
    adapters: { codex: adapter },
    inactivityTimers,
    availabilityClock,
    availabilityWait,
    clarifications: { ...clarificationService, ...clarificationHooks },
    loadConfiguration: async () =>
      parseRunnerConfiguration(
        JSON.stringify({
          schemaVersion: 1,
          defaultBackend: "codex",
          pipelines: { init: { mode, placement, maxRevisionRounds } },
        }),
      ),
  });
  return {
    root,
    workspacePath,
    projectPath,
    taskPath,
    workspace,
    calls,
    runner,
    runStore,
    start: (extra = {}) =>
      runner.run({ pipelineId: "init", projectPath, taskPath, ...extra }),
  };
}

test("init completes both placements in all modes, projects selectors and repeats without duplicate guidance", async (t) => {
  for (const placement of ["integrated", "external"])
    for (const mode of ["independent", "lazy", "combined"]) {
      await t.test(`${placement}/${mode}`, async (t) => {
        const f = await fixture(t, placement, mode);
        const context = "Preserve the existing project validation policy.\n";
        const clarifications = "# Clarifications\n\nUse the project root.\n";
        await fs.writeFile(join(f.taskPath, "context.md"), context);
        await fs.writeFile(
          join(f.taskPath, "clarifications.md"),
          clarifications,
        );
        const result = await f.start();
        assert.equal(
          result.run.pipelineState.workflowState,
          "DONE",
          JSON.stringify(result.run.pause),
        );
        const state = result.run.pipelineState;
        assert.equal(
          result.run.pipelineStateVersion,
          initPipeline.stateVersion,
        );
        assert.equal(state.inspection.schemaVersion, 2);
        assert.equal(state.publication.baseline.schemaVersion, 2);
        assert.deepEqual(
          (await f.runStore.loadRun(result.run.runId)).pipelineState
            .publication,
          state.publication,
        );
        assert.equal(state.completion.placement, placement);
        assert.equal(state.terminal.status, "CLEAN");
        assert.equal(
          f.calls.length,
          { independent: 4, lazy: 5, combined: 6 }[mode],
        );
        for (const request of f.calls)
          for (const prompt of [request.prompt, request.recoveryPrompt]) {
            const inputs = prompt
              .split("\n")
              .filter((line) => line.startsWith("{"))
              .map((line) => JSON.parse(line))
              .find((value) => Object.hasOwn(value, "task"));
            assert.deepEqual(inputs, {
              task: "Prepare reviewed infrastructure.\n",
              context,
              clarifications,
            });
          }
        assert.equal(
          result.run.sessionLineage.children.filter(
            ({ role }) => role === "reviewer",
          ).length > 0,
          mode !== "lazy",
        );
        const path = state.guidanceIntent.path;
        const guide = await fs.readFile(path, "utf8");
        assert.equal(guide.split("## Runner setup").length, 2);
        assert.ok(guide.includes("Preserve useful local instructions."));
        assert.ok(
          guide.includes(
            `Finalization: ${state.proposal.resources.find(({ kind }) => kind === "finalization").path}\n`,
          ),
        );
        if (placement === "external")
          assert.deepEqual(await fs.readdir(f.projectPath), ["AGENTS.md"]);
        const control = createMcpControlPlane({
          runner: f.runner,
          runStore: f.runStore,
        });
        const status = await control.runStatus({ runId: result.run.runId });
        assert.equal(
          status.setup.configurationPath,
          state.selection.configurationPath,
        );
        let output = "";
        assert.equal(
          await main(["status", "--run", result.run.runId], {
            runner: f.runner,
            stdout: {
              write: (text) => {
                output += text;
              },
            },
            stderr: { write: assert.fail },
          }),
          0,
        );
        assert.ok(output.includes(state.selection.configurationPath));
        // An explicit external selector reuses its bound root. Integrated reruns
        // retain conventional discovery and their existing selected procedure.
        // Publication replay is mode-independent; prove it once per placement.
        if (mode === "independent") {
          const repeated = await f.start({
            ...(placement === "external"
              ? { projectConfigurationPath: state.selection.configurationPath }
              : {}),
          });
          assert.equal(repeated.run.pipelineState.workflowState, "DONE");
          assert.equal(await fs.readFile(path, "utf8"), guide);
          assert.equal(
            repeated.run.pipelineState.guidanceReceipt.receipt.updated,
            false,
          );
          assert.ok(
            repeated.run.pipelineState.completion.resources.every(
              ({ status }) => status === "reused",
            ),
          );
          const guidance = await createGuidanceService({
            runStore: f.runStore,
            loadConfiguration: async () =>
              parseRunnerConfiguration('{"schemaVersion":1}'),
          }).read({
            projectPath: f.projectPath,
            projectConfigurationPath: state.selection.configurationPath,
          });
          assert.equal(guidance.localContent, guide);
          const consumer = await f.runner.create({
            pipelineId: "audit",
            projectPath: f.projectPath,
            taskPath: f.taskPath,
            projectConfigurationPath: state.selection.configurationPath,
          });
          assert.equal(
            consumer.run.projectConfigurationProtection.path,
            state.selection.configurationPath,
          );
        }
      });
    }
});

test("init publishes terminal adapter failures with exact retained bindings and no retry authority", async (t) => {
  for (const [placement, mode, phase, unknown, repaired] of [
    ["external", "independent", "clarify"],
    ["integrated", "lazy", "propose", true],
    ["external", "combined", "check-and-fix"],
    ["external", "lazy", "clean-confirm"],
    ["external", "independent", "review"],
    ["external", "combined", "propose", false, true],
    ["integrated", "independent", "confirm"],
  ]) {
    await t.test(`${placement}/${mode}/${phase}`, async (t) => {
      let before;
      let probeBlocked = false;
      const f = await fixture(t, placement, mode, {
        terminalFinding: repaired,
        probeVersion() {
          assert.equal(
            probeBlocked,
            false,
            "Terminal runs cannot probe a provider.",
          );
          return "fixture";
        },
        async beforeRun(request) {
          const current = await f.runStore.loadRun(runId);
          if (
            current.activeTurn.phase !== phase ||
            (repaired && current.pipelineState.createdFinalizationPath === null)
          )
            return false;
          if (phase === "clean-confirm") {
            assert.equal(await request.onFreshSession(), true);
            assert.equal(await request.onFreshSession(), false);
          }
          await request.onSessionCreated("failed-child");
          before = await f.runStore.loadRun(runId);
          throw unknown
            ? Object.assign(new Error("Private provider content"), {
                code: "private rejected code",
                diagnosticClass: "private_unregistered_class",
                payload: "Private provider content",
              })
            : new CodexAdapterError("Private provider content", {
                code: "ERR_CODEX_TURN_FAILED",
                diagnosticClass: "turn_bad_request",
              });
        },
      });
      const { run } = await f.runner.create({
        pipelineId: "init",
        projectPath: f.projectPath,
        taskPath: f.taskPath,
        sourceSession: { backend: "codex", id: "source-session" },
      });
      const runId = run.runId;
      const result = await f.runner.resume({ runId });
      const saved = await createRunStore({
        stateRoot: join(f.root, "state"),
      }).loadRun(runId);
      initPipeline.workflow.validateRun(saved);
      assert.deepEqual(saved.pipelineState, {
        ...before.pipelineState,
        workflowState: "FAILED",
        pendingTurn: null,
      });
      assert.deepEqual(saved.sessionLineage, before.sessionLineage);
      assert.deepEqual(saved.inactivityRecovery, before.inactivityRecovery);
      assert.equal(saved.pipelineState.revisionRounds, repaired ? 1 : 0);
      assert.deepEqual(saved.pipelineState, result.run.pipelineState);
      assert.equal(saved.activeTurn, null);
      assert.equal(saved.executionProcess, null);
      assert.equal(saved.executionResource, null);
      assert.equal(saved.preparation, null);
      assert.equal(await f.runStore.runLeaseOwnerIsLive(runId), false);
      assert.equal(
        await f.runStore.worktreeLeaseOwner(saved.workspace.leasePath, runId),
        null,
      );
      assert.equal(saved.pipelineState.completion, null);
      if (phase === "confirm") {
        assert.equal(saved.pipelineState.publication.prepared, true);
        assert.equal(saved.pipelineState.terminal.status, "PENDING");
        const guide = saved.pipelineState.guidanceIntent;
        assert.equal(
          hash(await fs.readFile(guide.path, "utf8")),
          guide.localContentHash,
        );
      } else assert.equal(saved.pipelineState.publication, null);
      if (repaired) assert.ok(saved.pipelineState.setupBaseline);
      const control = createMcpControlPlane({
        runner: f.runner,
        runStore: f.runStore,
      });
      const status = await control.runStatus({ runId });
      const waited = await control.runWait({
        runId,
        cursor: saved.revision,
        timeoutMs: 0,
      });
      assert.equal(status.status, "FAILED");
      assert.equal(waited.timedOut, false);
      assert.deepEqual(waited.pause, status.pause);
      assert.deepEqual(status.pause.nextActions, []);
      assert.equal(status.pause.resumeState, null);
      assert.deepEqual(
        status.pause.evidence,
        unknown ? [] : ["Adapter diagnostic: turn_bad_request."],
      );
      const activity = await control.runActivity({
        runId,
        cursor: before.revision,
        limit: 100,
      });
      assert.ok(activity.activities.some(({ kind }) => kind === "failed"));
      assert.doesNotMatch(
        JSON.stringify([saved, status, waited, activity]),
        /Private provider content|private_unregistered_class|private rejected code/u,
      );
      assert.equal((await f.runStore.loadRun(runId)).revision, saved.revision);
      const calls = f.calls.length;
      probeBlocked = true;
      assert.deepEqual(
        (await f.runner.resume({ runId })).run.pipelineState,
        saved.pipelineState,
      );
      assert.equal(f.calls.length, calls);
      // Reload validation owns registry membership and rejects misplaced fields.
      const lease = await f.runStore.acquireRunLease(runId);
      try {
        await assert.rejects(
          f.runStore.transitionRun(lease, {
            pause: { ...saved.pause, diagnosticClass: "unregistered_class" },
          }),
          /diagnosticClass/u,
        );
      } finally {
        await lease.release();
      }
    });
  }
});

test("foreground failure and already-held MCP wait observe the same durable init diagnosis", async (t) => {
  const entered = Promise.withResolvers();
  const release = Promise.withResolvers();
  const waiting = Promise.withResolvers();
  let runId;
  const f = await fixture(t, "external", "independent", {
    onActivity(activity) {
      if (activity.kind === "created") runId = activity.runId;
    },
    async beforeRun() {
      entered.resolve();
      await release.promise;
      throw new CodexAdapterError("Private provider content", {
        code: "ERR_CODEX_TURN_FAILED",
        diagnosticClass: "turn_bad_request",
      });
    },
  });
  let output = "";
  const foreground = main(
    ["run", "init", "--project", f.projectPath, "--task", f.taskPath],
    {
      runner: f.runner,
      stdout: {
        write(text) {
          output += text;
        },
      },
      stderr: { write: assert.fail },
    },
  );
  const abort = new AbortController();
  let held;
  try {
    await Promise.race([
      entered.promise,
      foreground.then(() => assert.fail("Provider was not invoked.")),
    ]);
    assert.ok(runId);
    const run = await f.runStore.loadRun(runId);
    const control = createMcpControlPlane({
      runner: f.runner,
      runStore: {
        ...f.runStore,
        waitForRunChange(...args) {
          waiting.resolve();
          return f.runStore.waitForRunChange(...args);
        },
      },
      launchRun: assert.fail,
    });
    held = control.runWait(
      { runId, cursor: run.revision, timeoutMs: 60_000 },
      { signal: abort.signal },
    );
    await Promise.race([
      waiting.promise,
      held.then(() => assert.fail("Wait ended before provider failure.")),
    ]);
    release.resolve();
    assert.equal(await foreground, 1);
    const status = await control.runStatus({ runId });
    const observed = await held;
    const fresh = await control.runWait({
      runId,
      cursor: status.revision,
      timeoutMs: 0,
    });
    for (const value of [observed, fresh]) {
      assert.equal(value.status, "FAILED");
      assert.equal(value.timedOut, false);
      assert.deepEqual(value.pause, status.pause);
    }
    assert.ok(output.includes(status.pause.explanation));
    assert.match(output, /ERR_CODEX_TURN_FAILED/u);
    assert.match(output, /Adapter diagnostic: turn_bad_request/u);
    assert.doesNotMatch(output, /Private provider content/u);
    assert.equal(await f.runStore.runLeaseOwnerIsLive(runId), false);
  } finally {
    release.resolve();
    abort.abort();
    await Promise.allSettled([foreground, held]);
  }
});

test("init keeps output, authentication and structured-result dispositions ahead of terminal failure", async (t) => {
  for (const reason of [
    "output_exhausted",
    "authentication_required",
    "invalid_result",
  ])
    await t.test(reason, async (t) => {
      let rejected = false;
      const f = await fixture(t, "external", "lazy", {
        beforeRun() {
          if (rejected) return false;
          rejected = true;
          if (reason === "invalid_result")
            throw new CodexAdapterError("Private provider content", {
              code: "ERR_CODEX_STRUCTURED_OUTPUT",
              failureClass: "structured-output",
            });
          throw new AgentBoundaryError(
            {},
            normalizeFailureRecord({
              failureClass: "adapter_failure",
              checkpoint: "turn",
              outcome: "rejected",
              effect: "none",
              retry: "terminal",
              disposition: reason,
            }),
          );
        },
      });
      const paused = (
        await f.start({
          sourceSession: { backend: "codex", id: "source-session" },
        })
      ).run;
      assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
      assert.equal(paused.pause.reason, reason);
      assert.equal(paused.pipelineState.publication, null);
      assert.equal(paused.pipelineState.sequence, 1);
      assert.equal(paused.pipelineState.revisionRounds, 0);
      assert.equal(
        paused.pipelineState.sourceForks.length,
        reason === "invalid_result" ? 1 : 0,
      );
      assert.equal(
        (await f.runner.resume({ runId: paused.runId })).run.pipelineState
          .workflowState,
        "DONE",
      );
    });
});

test("init never acknowledges terminal settlement when retirement or persistence fails", async (t) => {
  for (const failure of [
    "callback",
    "retirement",
    "persistence",
    "publication",
  ])
    await t.test(failure, async (t) => {
      const privateFailure = new Error("Owned operation failed");
      const f = await fixture(t, "external", "independent", {
        async beforeRun(request) {
          if (failure === "callback") {
            try {
              await request.onSessionCreated("failed-child");
            } catch {
              throw new CodexAdapterError("Private wrapped callback failure");
            }
          }
          throw new CodexAdapterError("Private provider content", {
            code: "ERR_CODEX_TURN_FAILED",
            diagnosticClass: "turn_bad_request",
          });
        },
        beforeFinish() {
          if (failure === "retirement") throw privateFailure;
        },
        beforeTransition(patch) {
          if (
            failure === "persistence" &&
            patch.pipelineState?.workflowState === "FAILED"
          )
            throw privateFailure;
        },
        beforeChild() {
          if (failure === "callback") throw privateFailure;
        },
        onActivity(activity) {
          if (failure === "publication" && activity.kind === "failed")
            throw privateFailure;
        },
      });
      const { run } = await f.runner.create({
        pipelineId: "init",
        projectPath: f.projectPath,
        taskPath: f.taskPath,
      });
      await assert.rejects(
        f.runner.resume({ runId: run.runId }),
        (error) => error === privateFailure,
      );
      const saved = await f.runStore.loadRun(run.runId);
      assert.equal(
        saved.pipelineState.workflowState,
        failure === "publication" ? "FAILED" : "CLARIFY",
      );
      assert.equal(
        saved.pause?.reason ?? null,
        failure === "publication" ? "internal_failure" : null,
      );
      if (failure !== "publication")
        assert.equal(saved.pipelineState.pendingTurn.phase, "CLARIFY");
    });
});

test("terminal refusal after availability backoff preserves accounting without another retry", async (t) => {
  let now = Date.now();
  let attempts = 0;
  let waits = 0;
  const f = await fixture(t, "external", "lazy", {
    availabilityClock: () => now,
    availabilityWait: async (duration) => {
      now += duration;
      waits++;
    },
    beforeRun() {
      attempts++;
      throw new CodexAdapterError(
        "Private provider content",
        attempts === 1
          ? {
              code: "ERR_CODEX_TURN_FAILED",
              diagnosticClass: "turn_server_overloaded",
              availabilityReason: "temporarily_overloaded",
              recoverable: true,
            }
          : {
              code: "ERR_CODEX_TURN_FAILED",
              diagnosticClass: "turn_bad_request",
            },
      );
    },
  });
  const run = (
    await f.start({
      sourceSession: { backend: "codex", id: "source-session" },
    })
  ).run;
  assert.equal(run.pipelineState.workflowState, "FAILED");
  assert.equal(run.pause.reason, "internal_failure");
  assert.equal(run.pause.diagnosticClass, "turn_bad_request");
  assert.equal(run.pipelineState.sourceForks.length, 1);
  assert.equal(run.pipelineState.sequence, 1);
  assert.equal(run.availabilityRetry.attempt, 1);
  assert.equal(attempts, 2);
  assert.equal(waits, 1);
  assert.deepEqual(initPipeline.projections.pause(run).nextActions, []);
});

function inactivityClock() {
  let fire;
  return {
    setTimeout(callback) {
      fire = callback;
      return callback;
    },
    clearTimeout(callback) {
      if (fire === callback) fire = undefined;
    },
    expire(request) {
      const result = new Promise((resolve, reject) => {
        request.signal.addEventListener(
          "abort",
          () => reject(request.signal.reason),
          { once: true },
        );
      });
      assert.equal(typeof fire, "function");
      fire();
      return result;
    },
  };
}

test("init settles successful reconstruction during proposal and terminal confirmation without reforking", async (t) => {
  for (const phase of ["proposal", "terminal"])
    for (const trigger of ["inactivity", "fresh-session"])
      await t.test(`${phase}/${trigger}`, async (t) => {
        const timers = inactivityClock();
        let f;
        let interrupted = false;
        let recovery;
        f = await fixture(t, "external", "combined", {
          inactivityTimers: timers,
          async beforeRun(request) {
            const selected =
              phase === "proposal"
                ? request.schema.properties.resources
                : request.prompt.includes("Distinct terminal confirmation:");
            if (!selected || recovery) return false;
            if (!interrupted) {
              interrupted = true;
              if (trigger === "inactivity") return timers.expire(request);
              assert.equal(await request.onFreshSession(), true);
              assert.equal(await request.onFreshSession(), false);
            } else assert.equal(request.session, undefined);
            recovery = (await f.runStore.loadRun(runId)).inactivityRecovery;
            return trigger === "fresh-session";
          },
        });
        const { run } = await f.runner.create({
          pipelineId: "init",
          projectPath: f.projectPath,
          taskPath: f.taskPath,
          sourceSession: { backend: "codex", id: "source-session" },
        });
        const runId = run.runId;
        const result = await f.runner.resume({ runId });
        assert.equal(result.run.pipelineState.workflowState, "DONE");
        assert.equal(recovery.attempt, 2);
        assert.equal(recovery.status, "reconstructing");
        assert.equal(result.run.inactivityRecovery, null);
        assert.equal(result.run.activeTurn, null);
        assert.equal(result.run.pipelineState.revisionRounds, 0);
        assert.equal(result.run.pipelineState.sourceForks.length, 6);
        assert.equal(
          f.calls.filter(({ session }) => session?.mode === "fork").length,
          6,
        );
        assert.equal(f.calls.length, trigger === "inactivity" ? 7 : 6);
      });
});

test("init persists reconstruction exhaustion after interruption and exposes a resumable CLI/MCP pause", async (t) => {
  for (const trigger of ["inactivity", "fresh-session"])
    await t.test(trigger, async (t) => {
      const timers = inactivityClock();
      let attempts = 0;
      let retirementInterrupted = false;
      const f = await fixture(t, "external", "lazy", {
        inactivityTimers: timers,
        beforeFinish(active) {
          if (
            active.phase === "propose" &&
            attempts === 2 &&
            !retirementInterrupted
          ) {
            retirementInterrupted = true;
            throw new Error("Interrupted reconstructed retirement");
          }
        },
        async beforeRun(request) {
          if (!request.schema.properties.resources || attempts > 1)
            return false;
          attempts++;
          if (trigger === "inactivity" && attempts === 1)
            return timers.expire(request);
          if (trigger === "fresh-session") {
            assert.equal(await request.onFreshSession(), true);
            attempts++;
          }
          throw new Error("Interrupted reconstructed proposal");
        },
      });
      const { run } = await f.runner.create({
        pipelineId: "init",
        projectPath: f.projectPath,
        taskPath: f.taskPath,
        sourceSession: { backend: "codex", id: "source-session" },
      });
      await assert.rejects(
        f.runner.resume({ runId: run.runId }),
        /Interrupted reconstructed retirement/u,
      );
      const saved = (await f.runner.status(run.runId)).run;
      assert.equal(saved.pause, null);
      assert.equal(saved.inactivityRecovery.attempt, 2);
      const calls = f.calls.length;
      const paused = (await f.runner.resume({ runId: run.runId })).run;
      assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
      assert.equal(paused.pause.reason, "provider_interrupted");
      assert.equal(paused.pause.resumeState, "PROPOSE");
      assert.deepEqual(paused.inactivityRecovery, saved.inactivityRecovery);
      assert.equal(paused.pipelineState.revisionRounds, 0);
      assert.deepEqual(
        paused.pipelineState.sourceForks,
        saved.pipelineState.sourceForks,
      );
      assert.equal(f.calls.length, calls);
      const control = createMcpControlPlane({
        runner: f.runner,
        runStore: f.runStore,
      });
      const status = await control.runStatus({ runId: run.runId });
      assert.deepEqual(status.pause.nextActions, [
        { type: "resume", action: null },
      ]);
      assert.equal(status.pause.resumeState, "PROPOSE");
      assert.equal(status.inactivityRecovery.attempt, 2);
      let output = "";
      assert.equal(
        await main(["status", "--run", run.runId], {
          runner: f.runner,
          stdout: {
            write: (text) => {
              output += text;
            },
          },
          stderr: { write: assert.fail },
        }),
        0,
      );
      assert.match(output, /provider_interrupted/u);
      assert.match(output, /attempt 2 of 2/u);
      const result = await f.runner.resume({ runId: run.runId });
      assert.equal(result.run.pipelineState.workflowState, "DONE");
      assert.equal(result.run.inactivityRecovery, null);
      assert.equal(result.run.pipelineState.revisionRounds, 0);
      assert.equal(
        f.calls.filter(({ session }) => session?.mode === "fork").length,
        1,
      );
    });
});

test("init restores only source forks proved unused by launch recovery", async (t) => {
  for (const [checkpoint, effect] of [
    ["spawn", "none"],
    ["initialize", "none"],
    ["initialize", "possible"],
  ])
    await t.test(`${checkpoint}/${effect}`, async (t) => {
      let interrupted = false;
      const f = await fixture(t, "external", "lazy", {
        boundary(phase) {
          if (phase !== "response" || interrupted) return;
          interrupted = true;
          throw new AgentBoundaryError(
            { code: "ERR_BACKEND_UNAVAILABLE" },
            normalizeFailureRecord({
              failureClass: "launch_process_exited",
              checkpoint,
              outcome: effect === "none" ? "exited" : "ambiguous",
              effect,
              retry: "transient",
            }),
          );
        },
      });
      const paused = await f.start({
        sourceSession: { backend: "codex", id: "source-session" },
      });
      assert.equal(paused.run.pause.reason, "provider_interrupted");
      assert.equal(paused.run.sessionLineage.children.length, 0);
      const unused = effect === "none";
      assert.equal(paused.run.pipelineState.sourceForks.length, unused ? 0 : 1);
      const result = await f.runner.resume({ runId: paused.run.runId });
      assert.equal(result.run.pipelineState.workflowState, "DONE");
      assert.deepEqual(f.calls[0].session, {
        mode: "fork",
        id: "source-session",
      });
      assert.deepEqual(
        f.calls[1].session,
        unused ? { mode: "fork", id: "source-session" } : undefined,
      );
      assert.ok(
        f.calls.slice(2).every(({ session }) => session?.mode === "continue"),
      );
      assert.equal(result.run.pipelineState.sourceForks.length, 1);
      assert.equal(result.run.pipelineState.revisionRounds, 0);
    });
});

test("external setup reuses its held enclosing-worktree exclusion without changing target controls", async (t) => {
  const f = await fixture(t, "external", "lazy", { enclosingWorktree: true });
  const inspection = await f.workspace.inspect({
    workspacePath: f.projectPath,
    stateRoot: f.runStore.rootPath,
  });
  const before = await f.workspace.snapshot({ inspection });
  const result = await f.start();
  assert.equal(result.run.pipelineState.workflowState, "DONE");
  assert.equal(result.run.workspace.leasePath, f.workspacePath);
  assert.equal(
    dirname(result.run.pipelineState.selection.rootPath),
    f.workspacePath,
  );
  f.workspace.assertUnchanged({
    before,
    after: await f.workspace.snapshot({ inspection }),
  });
});

test("invalid setup content pauses before publication and remains correctable on resume", async (t) => {
  for (const [placement, kind, content, proposalNumber] of [
    ["external", "guidance", "Unsafe control: \u0000\n", 1],
    ["external", "configuration", "{", 1],
    ["integrated", "finalization", "Omit the reviewed checks.\n", 2],
  ])
    await t.test(`${placement}/${kind}`, async (t) => {
      let proposals = 0;
      const f = await fixture(t, placement, "combined", {
        transformResult(result) {
          if (result.status === "PROPOSAL" && ++proposals === proposalNumber) {
            result.resources.find(
              (resource) => resource.kind === kind,
            ).content = content;
          }
          return result;
        },
      });
      const original = await fs.readdir(f.projectPath);
      const paused = await f.start();
      assert.equal(paused.run.pause.reason, "invalid_result");
      assert.equal(
        paused.run.pause.resumeState,
        proposalNumber === 1 ? "PROPOSE" : "CHECK_AND_FIX",
      );
      if (proposalNumber === 1)
        assert.equal(paused.run.pipelineState.proposal, null);
      else
        assert.notEqual(
          paused.run.pipelineState.proposal.resources.find(
            (resource) => resource.kind === kind,
          ).content,
          content,
        );
      assert.equal(paused.run.pipelineState.publication, null);
      assert.deepEqual(await fs.readdir(f.projectPath), original);
      const result = await f.runner.resume({ runId: paused.run.runId });
      assert.equal(result.run.pipelineState.workflowState, "DONE");
      assert.equal(result.run.pipelineState.revisionRounds, 0);
    });
});

test("init merges existing local guidance through its atomic publication", async (t) => {
  const f = await fixture(t, "integrated", "independent");
  const path = join(
    f.projectPath,
    "LOCAL_ARTIFACTS",
    "agent-runner",
    "rules.md",
  );
  await fs.mkdir(dirname(path), { recursive: true });
  const original = "Keep the project's existing validation instructions.\n";
  await fs.writeFile(path, original);
  const result = await f.start();
  assert.equal(result.run.pipelineState.workflowState, "DONE");
  assert.ok((await fs.readFile(path, "utf8")).startsWith(original));
  assert.equal(result.run.pipelineState.guidanceReceipt.receipt.updated, true);
});

test("terminal findings repair created procedures through renewed gates without renewing correction accounting", async (t) => {
  for (const placement of ["integrated", "external"])
    await t.test(placement, async (t) => {
      let terminalSeen = false;
      let interrupted = false;
      const f = await fixture(t, placement, "combined", {
        terminalFinding: true,
        repairChecks: true,
        boundary(phase) {
          if (phase === "terminal") terminalSeen = true;
        },
        beforeFinish(active) {
          if (terminalSeen && active.phase === "propose" && !interrupted) {
            interrupted = true;
            throw new Error("Interrupted proposal repair");
          }
        },
      });
      const { run } = await f.runner.create({
        pipelineId: "init",
        projectPath: f.projectPath,
        taskPath: f.taskPath,
      });
      await assert.rejects(
        f.runner.resume({ runId: run.runId }),
        /Interrupted proposal repair/u,
      );
      const saved = (await f.runner.status(run.runId)).run;
      assert.equal(saved.pipelineState.publication, null);
      assert.ok(saved.pipelineState.setupBaseline);
      assert.equal(saved.pipelineState.setupBaseline.snapshot.schemaVersion, 2);
      assert.ok(
        saved.pipelineState.setupBaseline.snapshot.entries.some(
          ({ path, kind }) =>
            path === saved.pipelineState.createdFinalizationPath &&
            kind === "file",
        ),
      );
      const result = await f.runner.resume({ runId: run.runId });
      assert.equal(result.run.pipelineState.workflowState, "DONE");
      assert.equal(result.run.pipelineState.revisionRounds, 1);
      assert.equal(
        f.calls.filter(({ prompt }) =>
          prompt.includes("Distinct terminal confirmation:"),
        ).length,
        2,
      );
      const procedure = result.run.pipelineState.proposal.resources.find(
        ({ kind }) => kind === "finalization",
      );
      assert.match(
        await fs.readFile(procedure.path, "utf8"),
        /node --test --test-reporter=spec/u,
      );
      assert.match(
        await fs.readFile(result.run.pipelineState.guidanceIntent.path, "utf8"),
        /node --test --test-reporter=spec/u,
      );
    });
});

test("root resume reconciles pending ignore publication before requiring its exclusions", async (t) => {
  let interrupted = false;
  const f = await fixture(t, "integrated", "independent", {
    beforeFile({ intent }) {
      if (!interrupted && intent.path.endsWith("/.gitignore")) {
        interrupted = true;
        throw new Error("Interrupted before ignore publication");
      }
    },
  });
  const { run } = await f.runner.create({
    pipelineId: "init",
    projectPath: f.projectPath,
    taskPath: f.taskPath,
  });
  await assert.rejects(
    f.runner.resume({ runId: run.runId }),
    /Interrupted before ignore publication/u,
  );
  const saved = (await f.runner.status(run.runId)).run;
  assert.equal(
    saved.pipelineState.publication.pending.path,
    join(f.projectPath, ".gitignore"),
  );
  await assert.rejects(fs.readFile(join(f.projectPath, ".gitignore")), {
    code: "ENOENT",
  });
  const calls = f.calls.length;
  const result = await f.runner.resume({ runId: run.runId });
  assert.equal(result.run.pipelineState.workflowState, "DONE");
  assert.equal(result.run.pipelineState.revisionRounds, 0);
  assert.equal(f.calls.length, calls + 1);
});

test("root resume reconciles a published prerequisite before continuing guidance and terminal confirmation", async (t) => {
  let interrupted = false;
  const f = await fixture(t, "external", "lazy", {
    afterFile(request) {
      if (!interrupted && request.intent.path.endsWith("/agent-runner.json")) {
        interrupted = true;
        throw new Error("Interrupted after configuration publication");
      }
    },
  });
  const { run } = await f.runner.create({
    pipelineId: "init",
    projectPath: f.projectPath,
    taskPath: f.taskPath,
  });
  await assert.rejects(
    f.runner.resume({ runId: run.runId }),
    /Interrupted after configuration publication/u,
  );
  const saved = (await f.runner.status(run.runId)).run;
  assert.equal(
    saved.pipelineState.publication.pending.path,
    saved.pipelineState.selection.configurationPath,
  );
  assert.equal(saved.pipelineState.guidanceIntent, null);
  const published = await fs.stat(
    saved.pipelineState.selection.configurationPath,
  );
  const result = await f.runner.resume({ runId: run.runId });
  assert.equal(result.run.pipelineState.workflowState, "DONE");
  assert.equal(
    (await fs.stat(saved.pipelineState.selection.configurationPath)).ino,
    published.ino,
  );
  assert.equal(result.run.pipelineState.revisionRounds, 0);
});

test("external setup retains failed infrastructure release for resume and stop settlement", async (t) => {
  for (const action of ["resume", "cancel"])
    await t.test(action, async (t) => {
      let interrupted = false;
      let releaseBlocked = true;
      const f = await fixture(t, "external", "lazy", {
        beforeFinish(active) {
          if (active.phase === "confirm" && !interrupted) {
            interrupted = true;
            throw new Error("Interrupted terminal retirement");
          }
        },
        beforeInfrastructureRelease() {
          if (releaseBlocked)
            throw Object.assign(new Error("Infrastructure release pending"), {
              code: "ERR_EXECUTION_PROCESS_ACTIVE",
            });
        },
      });
      const { run } = await f.runner.create({
        pipelineId: "init",
        projectPath: f.projectPath,
        taskPath: f.taskPath,
      });
      await assert.rejects(f.runner.resume({ runId: run.runId }), {
        code: "ERR_EXECUTION_PROCESS_ACTIVE",
      });
      const saved = await f.runStore.loadRun(run.runId);
      const infrastructurePath = saved.pipelineState.selection.rootPath;
      await assert.rejects(
        f.runStore.acquireInfrastructureLease(infrastructurePath, run.runId),
        { code: "ERR_WORKTREE_LEASED" },
      );
      releaseBlocked = false;
      if (action === "cancel")
        await f.runner.requestOperatorStop({
          runId: run.runId,
          kind: "cancel_requested",
          expectedRevision: saved.revision,
          idempotencyKey: "cancel-retained-setup",
          timing: "immediate",
        });
      const completed = await f.runner.resume({ runId: run.runId });
      assert.equal(
        completed.run.pipelineState.workflowState,
        action === "resume" ? "DONE" : "CANCELED",
      );
      const released = await f.runStore.acquireInfrastructureLease(
        infrastructurePath,
        run.runId,
      );
      await released.release();
    });
});

test("intervening prepared-file changes cannot be adopted during root resume", async (t) => {
  let interrupted = false;
  const f = await fixture(t, "external", "independent", {
    beforeFinish(active) {
      if (active.phase === "confirm" && !interrupted) {
        interrupted = true;
        throw new Error("Interrupted terminal confirmation");
      }
    },
  });
  const { run } = await f.runner.create({
    pipelineId: "init",
    projectPath: f.projectPath,
    taskPath: f.taskPath,
  });
  await assert.rejects(
    f.runner.resume({ runId: run.runId }),
    /Interrupted terminal confirmation/u,
  );
  const saved = (await f.runner.status(run.runId)).run;
  const path = saved.pipelineState.guidanceIntent.path;
  await fs.appendFile(path, "Intervening operator instructions.\n");
  const calls = f.calls.length;
  const rejected = await f.runner.resume({ runId: run.runId });
  assert.equal(rejected.run.pause.reason, "init_inspection_failed");
  assert.deepEqual(rejected.run.pause.inspectionFailure, {
    phase: "recovery",
    constraint: "workspace_changed",
  });
  assert.equal(f.calls.length, calls);
  assert.match(
    await fs.readFile(path, "utf8"),
    /Intervening operator instructions/u,
  );
});

test("authorized clarification can select bound external infrastructure before read scopes freeze", async (t) => {
  const f = await fixture(t, "external", "lazy");
  const selectedRoot = join(f.root, "selected-infrastructure");
  await fs.mkdir(selectedRoot);
  const configurationPath = join(selectedRoot, "agent-runner.json");
  await fs.writeFile(
    configurationPath,
    JSON.stringify({
      schemaVersion: 1,
      artifactRoot: "artifacts",
      infrastructure: {
        schemaVersion: 1,
        placement: "external",
        projectPath: f.projectPath,
        rootPath: selectedRoot,
      },
    }),
  );
  const guidePath = join(selectedRoot, "artifacts", "agent-runner", "rules.md");
  await fs.mkdir(dirname(guidePath), { recursive: true });
  await fs.writeFile(
    guidePath,
    "Preserve the selected setup's local instructions.\n",
  );
  const first = await f.start({
    proactiveClarification: true,
    settingOverrides: { placement: null },
  });
  assert.equal(first.run.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(f.calls.length, 0);
  assert.deepEqual(first.run.workspace.policy.infrastructurePaths, []);
  await fs.appendFile(
    first.run.pipelineState.pendingEdit.transcriptPath,
    `\nconfigurationPath: ${configurationPath}\n`,
  );
  const result = await f.runner.resume({ runId: first.run.runId });
  assert.equal(result.run.pipelineState.workflowState, "DONE");
  assert.equal(result.run.pipelineState.completion.placement, "external");
  assert.equal(result.run.pipelineState.selection.rootPath, selectedRoot);
  assert.deepEqual(result.run.workspace.policy.infrastructurePaths, [
    result.run.pipelineState.selection.rootPath,
  ]);
  assert.deepEqual(result.run.workspace.policy.outputPaths, []);
  assert.equal(result.run.pipelineState.clarificationRounds, 0);
  assert.match(
    await fs.readFile(guidePath, "utf8"),
    /Preserve the selected setup's local instructions/u,
  );
});

test("retired terminal interruption preserves its child while rebinding Runner-created read identities", async (t) => {
  let interrupted = false;
  let version = "fixture";
  const f = await fixture(t, "external", "lazy", {
    beforeFinish(active) {
      if (active.phase === "confirm" && !interrupted) {
        interrupted = true;
        throw new Error("Interrupted before terminal retirement receipt");
      }
    },
    probeVersion: () => version,
  });
  const { run } = await f.runner.create({
    pipelineId: "init",
    projectPath: f.projectPath,
    taskPath: f.taskPath,
  });
  await assert.rejects(
    f.runner.resume({ runId: run.runId }),
    /Interrupted before terminal retirement receipt/u,
  );
  const saved = (await f.runner.status(run.runId)).run;
  assert.equal(saved.activeTurn.phase, "confirm");
  const children = saved.sessionLineage.children;
  version = "changed-fixture";
  const calls = f.calls.length;
  await assert.rejects(f.runner.resume({ runId: run.runId }), {
    code: "ERR_PROVIDER_POLICY_CHANGED",
  });
  assert.equal(f.calls.length, calls);
  version = "fixture";
  const result = await f.runner.resume({ runId: run.runId });
  assert.equal(result.run.pipelineState.workflowState, "DONE");
  assert.deepEqual(result.run.sessionLineage.children, children);
  assert.equal(result.run.activeTurn, null);
  assert.equal(result.run.pipelineState.revisionRounds, 0);
});

test("lost guidance acknowledgement rejects a same-byte replacement without adopting its identity", async (t) => {
  let interrupted = false;
  const f = await fixture(t, "external", "lazy", {
    afterGuideReceipt() {
      if (!interrupted) {
        interrupted = true;
        throw new Error("Interrupted guidance acknowledgement");
      }
    },
  });
  const { run } = await f.runner.create({
    pipelineId: "init",
    projectPath: f.projectPath,
    taskPath: f.taskPath,
  });
  await assert.rejects(f.runner.resume({ runId: run.runId }), {
    code: "ERR_GUIDANCE_STORAGE",
  });
  const saved = (await f.runner.status(run.runId)).run;
  assert.equal(saved.pipelineState.guidanceReceipt, null);
  const path = saved.pipelineState.guidanceIntent.path;
  const content = await fs.readFile(path, "utf8");
  const replacement = join(f.root, "replacement.md");
  await fs.writeFile(replacement, content);
  const identity = await fs.stat(replacement);
  await fs.rename(replacement, path);
  const calls = f.calls.length;
  await assert.rejects(f.runner.resume({ runId: run.runId }), {
    code: "ERR_GUIDANCE_RECOVERY",
  });
  assert.equal(f.calls.length, calls);
  assert.equal((await fs.stat(path)).ino, identity.ino);
  assert.equal(
    (await f.runner.status(run.runId)).run.pipelineState.guidanceReceipt,
    null,
  );
});

test("init operator stops preserve reserved turns and authorized clarification windows", async (t) => {
  for (const checkpoint of ["proposal", "clarification"])
    for (const kind of ["pause_requested", "cancel_requested"]) {
      await t.test(`${checkpoint}/${kind}`, async (t) => {
        let f;
        let runId;
        let stopped = false;
        f = await fixture(t, "external", "combined", {
          async boundary(phase, { request } = {}) {
            if (
              checkpoint !== "proposal" ||
              stopped ||
              phase !== "response" ||
              !request.schema.properties.resources
            )
              return;
            stopped = true;
            const saved = await f.runStore.loadRun(runId);
            await f.runner.requestOperatorStop({
              runId,
              kind,
              expectedRevision: saved.revision,
              idempotencyKey: "setup-stop",
              timing: "immediate",
            });
            throw new Error("Interrupted reserved proposal");
          },
        });
        const created = await f.runner.create({
          pipelineId: "init",
          projectPath: f.projectPath,
          taskPath: f.taskPath,
          proactiveClarification: checkpoint === "clarification",
        });
        runId = created.run.runId;
        let result = await f.runner.resume({ runId });
        if (checkpoint === "clarification") {
          await f.runner.requestOperatorStop({
            runId,
            kind,
            expectedRevision: result.run.revision,
            idempotencyKey: "setup-stop",
            timing: "immediate",
          });
          result = await f.runner.resume({ runId });
        }
        assert.equal(
          result.run.pause.reason,
          kind === "pause_requested" ? "operator_paused" : "operator_canceled",
        );
        assert.notEqual(result.run.stopRequest.reconciledRevision, null);
        assert.equal(result.run.activeTurn, null);
        assert.equal(await f.runStore.runLeaseOwnerIsLive(runId), false);
        if (checkpoint === "proposal")
          assert.equal(result.run.pipelineState.pendingTurn.phase, "PROPOSE");
        else assert.ok(result.run.pipelineState.pendingEdit);
        if (kind === "pause_requested") {
          result = await f.runner.resume({ runId });
          if (checkpoint === "clarification") {
            assert.equal(
              result.run.pipelineState.workflowState,
              "WAITING_FOR_USER",
            );
            result = await f.runner.resume({ runId });
          }
          assert.equal(result.run.pipelineState.workflowState, "DONE");
        } else
          await assert.rejects(f.runner.resume({ runId }), {
            code: "ERR_RUN_CANCELED",
          });
      });
    }
});

test("init resumes exact question publication before append, after replacement and before editor authorization", async (t) => {
  for (const checkpoint of [
    "before-append",
    "after-replacement",
    "before-editor",
  ])
    await t.test(checkpoint, async (t) => {
      const service = createClarificationService({ interactive: false });
      let interrupted = false;
      let asked = false;
      const f = await fixture(t, "external", "lazy", {
        transformResult(result) {
          if (!asked && result.status === "READY") {
            asked = true;
            return {
              status: "QUESTIONS",
              questions: [
                {
                  question: "Which checks define acceptance?",
                  whyItMatters: "The setup must preserve the agreed checks.",
                },
              ],
              reason: "",
            };
          }
          return result;
        },
        clarificationService: service,
        clarificationHooks: {
          async appendQuestionRound(request) {
            if (checkpoint === "before-append" && !interrupted) {
              interrupted = true;
              throw new Error("Interrupted question publication");
            }
            const appended = await service.appendQuestionRound(request);
            if (checkpoint === "after-replacement" && !interrupted) {
              interrupted = true;
              throw new ClarificationError("Interrupted question publication", {
                code: "ERR_CLARIFICATION_WRITE",
              });
            }
            return appended;
          },
          async prepareEdit(request) {
            if (checkpoint === "before-editor" && !interrupted) {
              interrupted = true;
              throw new Error("Interrupted question publication");
            }
            return service.prepareEdit(request);
          },
        },
      });
      const { run } = await f.runner.create({
        pipelineId: "init",
        projectPath: f.projectPath,
        taskPath: f.taskPath,
      });
      await assert.rejects(
        f.runner.resume({ runId: run.runId }),
        /Interrupted question publication/u,
      );
      const calls = f.calls.length;
      const waiting = await f.runner.resume({ runId: run.runId });
      assert.ok(waiting.run.pipelineState.pendingEdit);
      assert.equal(f.calls.length, calls);
      const path = waiting.run.pipelineState.pendingEdit.transcriptPath;
      assert.equal(
        (await fs.readFile(path, "utf8")).split("## Round 1").length,
        2,
      );
      const submitted = await answer(f, waiting.run, "Preserve node --test.");
      assert.equal(
        (await f.runner.resume({ runId: submitted.runId })).run.pipelineState
          .workflowState,
        "DONE",
      );
      assert.equal(
        (await fs.readFile(path, "utf8")).split("## Round 1").length,
        2,
      );
    });
});

async function answer(f, run, text) {
  const request = {
    runId: run.runId,
    requestId: run.pause.inputRequest.id,
    expectedRevision: run.revision,
    answers: run.pause.inputRequest.questions.map(({ id }) => ({
      questionId: id,
      answer: text,
    })),
  };
  const preview = await f.runner.previewInput(request);
  return (
    await f.runner.submitInput({
      ...request,
      responseHash: preview.responseHash,
    })
  ).run;
}

const materialDecision = {
  question:
    "Should the setup retain the existing check or use the newly requested check?",
  options: ["Retain the existing check", "Use the newly requested check"],
  whyBlocked: "The task gives conflicting acceptance requirements.",
  evidence: [
    "The task requests a different check while the agreed requirements retain the existing check.",
  ],
};

test("init product decisions survive append interruption and renew complete gates without changing frozen selections", async (t) => {
  for (const phase of ["proposal", "terminal"])
    await t.test(phase, async (t) => {
      const service = createClarificationService({ interactive: false });
      let requested = false;
      let interrupted = false;
      const f = await fixture(t, "external", "combined", {
        transformResult(result, request) {
          if (
            !requested &&
            (phase === "proposal"
              ? result.status === "PROPOSAL"
              : request.prompt.includes("Distinct terminal confirmation:"))
          ) {
            requested = true;
            return {
              status: "PRODUCT_DECISION_REQUIRED",
              ...materialDecision,
              ...(phase === "proposal"
                ? { summary: "", checks: [], resources: [] }
                : { proposalHash: "", findings: [] }),
            };
          }
          return result;
        },
        clarificationService: service,
        clarificationHooks: {
          async appendProductDecision(request) {
            const appended = await service.appendProductDecision(request);
            if (!interrupted) {
              interrupted = true;
              throw new ClarificationError("Interrupted decision append", {
                code: "ERR_CLARIFICATION_WRITE",
              });
            }
            return appended;
          },
        },
      });
      const { run } = await f.runner.create({
        pipelineId: "init",
        projectPath: f.projectPath,
        taskPath: f.taskPath,
      });
      await assert.rejects(
        f.runner.resume({ runId: run.runId }),
        /Interrupted decision append/u,
      );
      const saved = await f.runStore.loadRun(run.runId);
      const waiting = (await f.runner.resume({ runId: run.runId })).run;
      assert.equal(waiting.pause.reason, "product_decision_required");
      assert.equal(waiting.pause.inputRequest.kind, "product-decision");
      assert.deepEqual(
        waiting.pipelineState.selection,
        saved.pipelineState.selection,
      );
      assert.equal(waiting.pipelineState.productDecisions, 1);
      assert.equal(waiting.pipelineState.revisionRounds, 0);
      const path = waiting.pipelineState.pendingEdit.transcriptPath;
      const unchanged = (await f.runner.resume({ runId: run.runId })).run;
      assert.ok(unchanged.pipelineState.pendingEdit);
      assert.equal(
        (await fs.readFile(path, "utf8")).split("## Product Decision 1").length,
        2,
      );
      const answered = await answer(
        f,
        unchanged,
        "Retain the existing check.\nplacement: integrated",
      );
      const calls = f.calls.length;
      const result = await f.runner.resume({ runId: answered.runId });
      assert.equal(result.run.pipelineState.workflowState, "DONE");
      assert.equal(result.run.pipelineState.selection.placement, "external");
      assert.equal(f.calls.length, calls + 5);
      assert.equal(result.run.pipelineState.productDecisions, 1);
      assert.equal(result.run.pipelineState.revisionRounds, 0);
      assert.equal(result.run.pipelineState.pendingEdit, null);
    });
});

test("init exposes concrete blocking and exhausted findings through CLI and MCP status", async (t) => {
  for (const outcome of ["blocked", "revision-limit"])
    await t.test(outcome, async (t) => {
      const explanation =
        "The required acceptance check is missing from the inspected setup.";
      let rejectRecovery = false;
      const f = await fixture(t, "external", "combined", {
        maxRevisionRounds: 1,
        async beforeInspect() {
          if (rejectRecovery)
            throw new WorkspaceSafetyError("Private rejected evidence", {
              code: "ERR_WORKSPACE_INSPECTION",
              cause: Object.assign(new Error(), { code: "EMFILE" }),
            });
        },
        transformResult(result) {
          if (outcome === "blocked" && result.status === "READY")
            return { status: "BLOCKED", questions: [], reason: explanation };
          return result.status === "CLEAN"
            ? { ...result, status: "FINDINGS", findings: [explanation] }
            : result;
        },
      });
      const result = await f.start();
      assert.equal(
        result.run.pause.reason,
        outcome === "blocked" ? "setup_blocked" : "revision_limit",
      );
      const control = createMcpControlPlane({
        runner: f.runner,
        runStore: f.runStore,
      });
      const status = await control.runStatus({ runId: result.run.runId });
      assert.equal(status.findings[0].summary, explanation);
      assert.deepEqual(status.pause.evidence, [explanation]);
      assert.notEqual(
        status.pause.explanation,
        "Init is paused at its saved setup checkpoint.",
      );
      let output = "";
      assert.equal(
        await main(["status", "--run", result.run.runId], {
          runner: f.runner,
          stdout: {
            write: (text) => {
              output += text;
            },
          },
          stderr: { write: assert.fail },
        }),
        0,
      );
      assert.ok(output.includes(explanation));
      const calls = f.calls.length;
      assert.deepEqual(status.pause.nextActions, []);
      rejectRecovery = true;
      await assert.rejects(f.runner.resume({ runId: result.run.runId }), {
        code: "ERR_WORKSPACE_INSPECTION",
      });
      const reloaded = await createRunStore({
        stateRoot: join(f.root, "state"),
      }).loadRun(result.run.runId);
      initPipeline.workflow.validateRun(reloaded);
      assert.deepEqual(reloaded.pause, result.run.pause);
      assert.deepEqual(reloaded.pipelineState, result.run.pipelineState);
      assert.deepEqual(
        (await control.runStatus({ runId: reloaded.runId })).pause,
        status.pause,
      );
      rejectRecovery = false;
      await assert.rejects(f.runner.resume({ runId: reloaded.runId }), {
        code: "ERR_INAPPLICABLE_RESUME_ACTION",
      });
      assert.equal(f.calls.length, calls);
    });
});

function capacityFailure() {
  return new WorkspaceSafetyError(
    "Private rejected evidence must not be retained.",
    {
      code: "ERR_WORKSPACE_PROOF_CAPACITY",
    },
  );
}

async function assertInspectionStop(f, runId, phase, constraint) {
  const saved = await f.runStore.loadRun(runId);
  assert.equal(saved.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(saved.pause.reason, "init_inspection_failed");
  assert.deepEqual(saved.pause.inspectionFailure, { phase, constraint });
  assert.equal(saved.activeTurn, null);
  assert.equal(saved.executionProcess, null);
  assert.equal(saved.pipelineState.pendingTurn, null);
  assert.equal(await f.runStore.runLeaseOwnerIsLive(runId), false);
  assert.equal(
    JSON.stringify(saved).includes("Private rejected evidence"),
    false,
  );
  const control = createMcpControlPlane({
    runner: f.runner,
    runStore: f.runStore,
  });
  const status = await control.runStatus({ runId });
  const waited = await control.runWait({ runId, cursor: 0, timeoutMs: 0 });
  assert.deepEqual(waited.pause, status.pause);
  assert.equal(status.status, "WAITING_FOR_USER");
  assert.ok(status.pause.explanation.includes(phase));
  let output = "";
  assert.equal(
    await main(["status", "--run", runId], {
      runner: f.runner,
      stdout: {
        write: (text) => {
          output += text;
        },
      },
      stderr: { write: assert.fail },
    }),
    0,
  );
  assert.ok(output.includes(status.pause.explanation));
  return { saved, status };
}

test("pre-provider inspection rejection is durable after start admission and exact receipt replay", async (t) => {
  for (const placement of ["external", "integrated"])
    await t.test(placement, async (t) => {
      const f = await fixture(t, placement, "independent", {
        beforeProof() {
          throw capacityFailure();
        },
      });
      const inspection = await f.workspace.inspect({
        workspacePath: f.projectPath,
        stateRoot: f.runStore.rootPath,
      });
      const before = await f.workspace.snapshot({ inspection });
      let launches = 0;
      const control = createMcpControlPlane({
        runner: f.runner,
        runStore: f.runStore,
        async launchRun(
          runId,
          action,
          { dispatch, expectedRuntimeCompatibility },
        ) {
          launches++;
          await f.runner.resume({
            runId,
            action,
            dispatch,
            expectedRuntimeCompatibility,
            expectedRevision: dispatch.expectedRevision,
          });
        },
      });
      const input = {
        idempotencyKey: "rejected-start",
        pipelineId: "init",
        projectPath: f.projectPath,
        taskPath: f.taskPath,
        proactiveClarification: false,
        roleOverrides: {},
        sourceSession: null,
      };
      const receipt = await control.runStart(input);
      assert.deepEqual(await control.runStart(input), receipt);
      assert.equal(launches, 1);
      const { saved, status } = await assertInspectionStop(
        f,
        receipt.runId,
        "inspection",
        "evidence_capacity",
      );
      assert.deepEqual(status.pause.nextActions, []);
      assert.match(status.pause.explanation, /fresh init run/u);
      assert.equal(saved.pipelineState.inspection, null);
      assert.equal(saved.pipelineState.sequence, 0);
      assert.equal(saved.pipelineState.publication, null);
      assert.equal(saved.observations, null);
      assert.equal(f.calls.length, 0);
      await assert.rejects(f.runner.resume({ runId: receipt.runId }), {
        code: "ERR_INAPPLICABLE_RESUME_ACTION",
      });
      f.workspace.assertUnchanged({
        before,
        after: await f.workspace.snapshot({ inspection }),
      });
    });
});

test("ownerless init recovery diagnoses inspection before any turn and replays only its exact key", async (t) => {
  const f = await fixture(t, "external", "independent", {
    beforeProof() {
      throw capacityFailure();
    },
  });
  const { run: created } = await f.runner.create({
    pipelineId: "init",
    projectPath: f.projectPath,
    taskPath: f.taskPath,
  });
  const lease = await f.runStore.acquireRunLease(created.runId);
  const run = await f.runStore.transitionRun(
    lease,
    {},
    {
      activity: {
        actor: "runner",
        phase: "inspection",
        kind: "prepared",
        message: "Initial setup checkpoint saved.",
      },
    },
  );
  let launches = 0;
  const control = createMcpControlPlane({
    runner: f.runner,
    runStore: f.runStore,
    async launchRun(runId, action, { dispatch, expectedRuntimeCompatibility }) {
      launches++;
      await f.runner.resume({
        runId,
        action,
        dispatch,
        expectedRuntimeCompatibility,
        expectedRevision: dispatch.expectedRevision,
      });
    },
  });
  const input = {
    runId: run.runId,
    expectedRevision: run.revision,
    action: null,
    idempotencyKey: "ownerless-inspection",
  };
  try {
    await assert.rejects(
      control.runResume({
        ...input,
        idempotencyKey: "stale-inspection",
        expectedRevision: created.revision,
      }),
      /revision is stale/u,
    );
    await assert.rejects(
      control.runResume({ ...input, idempotencyKey: "live-inspection" }),
      { code: "ERR_RUN_LEASED" },
    );
  } finally {
    await lease.release();
  }
  assert.deepEqual(await control.runResume(input), { runId: run.runId });
  assert.deepEqual(await control.runResume(input), { runId: run.runId });
  const { saved } = await assertInspectionStop(
    f,
    run.runId,
    "inspection",
    "evidence_capacity",
  );
  assert.equal(saved.pipelineState.revisionRounds, 0);
  assert.equal(saved.pipelineState.clarificationRounds, 0);
  assert.equal(f.calls.length, 0);
  assert.equal(launches, 1);
});

test("transient inspection resumes only with unchanged frozen inputs", async (t) => {
  for (const changed of [false, true])
    await t.test(String(changed), async (t) => {
      let unavailable = true;
      const f = await fixture(t, "external", "independent", {
        beforeProof() {
          if (unavailable)
            throw new WorkspaceSafetyError("Private rejected evidence", {
              code: "ERR_WORKSPACE_INSPECTION",
              cause: Object.assign(new Error(), { code: "EMFILE" }),
            });
        },
      });
      const first = await f.start();
      const { saved, status } = await assertInspectionStop(
        f,
        first.run.runId,
        "inspection",
        "inspection_unavailable",
      );
      assert.deepEqual(status.pause.nextActions, [
        { type: "resume", action: null },
      ]);
      unavailable = false;
      if (changed)
        await fs.appendFile(
          join(f.taskPath, "task.md"),
          "Changed frozen requirement.\n",
        );
      const result = await f.runner.resume({ runId: saved.runId });
      if (changed) {
        await assertInspectionStop(
          f,
          saved.runId,
          "recovery",
          "workspace_changed",
        );
        assert.equal(f.calls.length, 0);
        assert.equal(result.run.pipelineState.publication, null);
      } else assert.equal(result.run.pipelineState.workflowState, "DONE");
    });
});

test("post-turn and additive reinspection failures cannot approve or publish setup", async (t) => {
  for (const phase of ["post-turn", "reinspection"])
    await t.test(phase, async (t) => {
      let rejectProof = false;
      const f = await fixture(t, "external", "independent", {
        beforeProof() {
          if (rejectProof) throw capacityFailure();
        },
        async boundary(event) {
          if (event === "response") rejectProof = true;
        },
      });
      let result = await f.start(
        phase === "reinspection"
          ? {
              proactiveClarification: true,
              settingOverrides: { placement: null },
            }
          : {},
      );
      if (phase === "reinspection") {
        await fs.appendFile(
          result.run.pipelineState.pendingEdit.transcriptPath,
          "\nplacement: external\n",
        );
        rejectProof = true;
        result = await f.runner.resume({ runId: result.run.runId });
      }
      const { saved } = await assertInspectionStop(
        f,
        result.run.runId,
        phase,
        "evidence_capacity",
      );
      assert.equal(saved.pipelineState.publication, null);
      assert.equal(saved.pipelineState.primaryApproval, null);
      assert.equal(saved.pipelineState.reviewApproval, null);
      assert.equal(f.calls.length, phase === "post-turn" ? 1 : 0);
    });
});

test("inspection rejection settles concurrent stops before or during a reserved turn", async (t) => {
  for (const kind of ["pause_requested", "cancel_requested"])
    for (const checkpoint of ["before-turn", "reserved-turn"])
      await t.test(`${kind}/${checkpoint}`, async (t) => {
        let armed = false;
        let rejected;
        let f;
        let runId;
        f = await fixture(t, "external", "independent", {
          async afterSnapshot() {
            if (!armed) return;
            const saved = await f.runStore.loadRun(runId);
            if (checkpoint === "reserved-turn" && saved.activeTurn === null)
              return;
            armed = false;
            rejected = saved;
            await f.runner.requestOperatorStop({
              runId,
              kind,
              expectedRevision: saved.revision,
              idempotencyKey: "inspection-stop",
              timing: "immediate",
            });
            // Fail once: stop cleanup must retain this diagnosis, rather than
            // reproducing the failure to manufacture a replacement diagnosis.
            throw new WorkspaceSafetyError("Private rejected evidence", {
              code: "ERR_WORKSPACE_INSPECTION",
              cause: Object.assign(new Error(), { code: "EMFILE" }),
            });
          },
        });
        const { run } = await f.runner.create({
          pipelineId: "init",
          projectPath: f.projectPath,
          taskPath: f.taskPath,
        });
        runId = run.runId;
        armed = true;
        const result = await f.runner.resume({ runId });
        const saved = await f.runStore.loadRun(runId);
        assert.deepEqual(saved, result.run);
        assert.equal(
          saved.pause.reason,
          kind === "pause_requested" ? "operator_paused" : "operator_canceled",
        );
        const diagnosis = saved.pause.operatorResume.pause;
        assert.equal(diagnosis.reason, "init_inspection_failed");
        assert.deepEqual(diagnosis.inspectionFailure, {
          phase: checkpoint === "before-turn" ? "recovery" : "preparation",
          constraint: "inspection_unavailable",
        });
        assert.equal(saved.stopRequest.reconciledRevision, saved.revision);
        assert.equal(saved.activeTurn, null);
        assert.equal(saved.pipelineState.pendingTurn, null);
        assert.equal(
          saved.pipelineState.sequence,
          rejected.pipelineState.sequence,
        );
        assert.equal(
          saved.pipelineState.revisionRounds,
          rejected.pipelineState.revisionRounds,
        );
        assert.equal(await f.runStore.runLeaseOwnerIsLive(runId), false);
        assert.equal(
          await f.runStore.worktreeLeaseOwner(f.projectPath, runId),
          null,
        );
        assert.equal(f.calls.length, 0);
        assert.equal(saved.pipelineState.publication, null);
        if (kind === "pause_requested") {
          const restored = (await f.runner.resume({ runId })).run;
          assert.deepEqual(restored.pause, diagnosis);
          assert.equal(
            restored.pipelineState.sequence,
            saved.pipelineState.sequence,
          );
          assert.equal(f.calls.length, 0);
        }
      });
});

test("a recovery inspection stop acquires canonical ownership before stop settlement", async (t) => {
  let f;
  let runId;
  let armed = false;
  let reconciliations = 0;
  f = await fixture(t, "external", "independent", {
    async beforeInspect() {
      if (!armed) return;
      armed = false;
      const current = await f.runStore.loadRun(runId);
      await f.runner.requestOperatorStop({
        runId,
        kind: "pause_requested",
        expectedRevision: current.revision,
        idempotencyKey: "recovery-inspection-stop",
      });
      throw capacityFailure();
    },
    async onActivity(activity) {
      if (activity.phase !== "stop" || activity.kind !== "reconciled") return;
      reconciliations++;
      assert.equal(await f.runStore.runLeaseOwnerIsLive(runId), true);
      assert.equal(
        await f.runStore.worktreeLeaseOwner(f.projectPath, runId),
        runId,
      );
    },
  });
  const { run } = await f.runner.create({
    pipelineId: "init",
    projectPath: f.projectPath,
    taskPath: f.taskPath,
  });
  runId = run.runId;
  armed = true;
  const stopped = (await f.runner.resume({ runId })).run;
  assert.ok(reconciliations > 0);
  assert.equal(stopped.pause.reason, "operator_paused");
  assert.deepEqual(stopped.pause.operatorResume.pause.inspectionFailure, {
    phase: "recovery",
    constraint: "evidence_capacity",
  });
  assert.notEqual(stopped.stopRequest.reconciledRevision, null);
  assert.equal(await f.runStore.runLeaseOwnerIsLive(runId), false);
  assert.equal(await f.runStore.worktreeLeaseOwner(f.projectPath, runId), null);
  assert.equal(f.calls.length, 0);
  assert.equal(stopped.pipelineState.publication, null);
});

test("editor and adapter inspection failures settle their registered preparation checkpoints", async (t) => {
  for (const checkpoint of [
    "prepare-edit",
    "editor-close",
    "adapter-preparation",
    "adapter-verification",
  ])
    await t.test(checkpoint, async (t) => {
      let f;
      let runId;
      let armed = true;
      const unavailable = () =>
        Object.assign(new Error("Private rejected evidence"), {
          code: "EMFILE",
        });
      const providerCalls = checkpoint === "adapter-verification" ? 1 : 0;
      f = await fixture(t, "external", "independent", {
        clarificationHooks: ["prepare-edit", "editor-close"].includes(
          checkpoint,
        )
          ? {
              async [checkpoint === "prepare-edit"
                ? "prepareEdit"
                : "openEditor"]() {
                throw new ClarificationError("Private rejected evidence", {
                  code: "ERR_CLARIFICATION_READ",
                  cause: unavailable(),
                });
              },
            }
          : {},
        async afterSnapshot() {
          if (
            !runId ||
            !armed ||
            !checkpoint.startsWith("adapter-") ||
            f.calls.length !== providerCalls
          )
            return;
          const current = await f.runStore.loadRun(runId);
          if (current.activeTurn === null) return;
          armed = false;
          throw new WorkspaceSafetyError("Private rejected evidence", {
            code: "ERR_WORKSPACE_INSPECTION",
            cause: unavailable(),
          });
        },
      });
      const inspection = await f.workspace.inspect({
        workspacePath: f.projectPath,
        stateRoot: f.runStore.rootPath,
      });
      const before = await f.workspace.snapshot({ inspection });
      const { run } = await f.runner.create({
        pipelineId: "init",
        projectPath: f.projectPath,
        taskPath: f.taskPath,
        proactiveClarification: ["prepare-edit", "editor-close"].includes(
          checkpoint,
        ),
      });
      runId = run.runId;
      await f.runner.resume({ runId });
      const phase =
        checkpoint === "adapter-verification" ? "post-turn" : "preparation";
      const { saved, status } = await assertInspectionStop(
        f,
        runId,
        phase,
        "inspection_unavailable",
      );
      assert.deepEqual(status.pause.nextActions, [
        { type: "resume", action: null },
      ]);
      assert.equal(
        saved.pipelineState.pendingEdit === null,
        checkpoint !== "editor-close",
      );
      assert.equal(saved.pipelineState.publication, null);
      assert.equal(saved.pipelineState.revisionRounds, 0);
      assert.equal(saved.pipelineState.clarificationRounds, 0);
      assert.equal(f.calls.length, providerCalls);
      f.workspace.assertUnchanged({
        before,
        after: await f.workspace.snapshot({ inspection }),
      });
    });
});

test("an oversized initial transcript pauses without a provider or editor authorization", async (t) => {
  const f = await fixture(t, "external", "independent");
  const transcriptPath = join(f.taskPath, "clarifications.md");
  await fs.writeFile(transcriptPath, Buffer.alloc(1024 * 1024 + 1));
  const result = await f.start();
  const { saved, status } = await assertInspectionStop(
    f,
    result.run.runId,
    "preparation",
    "evidence_capacity",
  );
  assert.deepEqual(status.pause.nextActions, []);
  assert.equal(saved.pipelineState.inspection, null);
  assert.equal(saved.pipelineState.pendingEdit, null);
  assert.equal(saved.pipelineState.publication, null);
  assert.equal(saved.observations, null);
  assert.equal(f.calls.length, 0);
  assert.equal((await fs.stat(transcriptPath)).size, 1024 * 1024 + 1);
});

test("configuration file constraints during additive reinspection persist without accepting partial evidence", async (t) => {
  for (const shape of ["oversized", "directory"])
    await t.test(shape, async (t) => {
      const f = await fixture(t, "external", "independent");
      const first = await f.start({
        proactiveClarification: true,
        settingOverrides: { placement: null },
      });
      const originalInspection = first.run.pipelineState.inspection;
      const rootPath = join(f.root, "selected-infrastructure");
      await fs.mkdir(rootPath);
      const configurationPath = join(rootPath, "agent-runner.json");
      if (shape === "directory") await fs.mkdir(configurationPath);
      else await fs.writeFile(configurationPath, Buffer.alloc(1024 * 1024 + 1));
      await fs.appendFile(
        first.run.pipelineState.pendingEdit.transcriptPath,
        `\nplacement: external\nconfigurationPath: ${configurationPath}\n`,
      );
      await f.runner.resume({ runId: first.run.runId });
      const { saved, status } = await assertInspectionStop(
        f,
        first.run.runId,
        "reinspection",
        shape === "oversized" ? "evidence_capacity" : "unsafe_path",
      );
      assert.deepEqual(status.pause.nextActions, []);
      assert.deepEqual(saved.pipelineState.inspection, originalInspection);
      assert.equal(saved.pipelineState.reinspectionRequired, true);
      assert.equal(saved.pipelineState.selection, null);
      assert.equal(saved.pipelineState.publication, null);
      assert.equal(saved.pipelineState.pendingEdit, null);
      assert.equal(saved.pipelineState.clarificationRounds, 0);
      assert.equal(f.calls.length, 0);
    });
});

test("a selected integrated configuration vanishing after discovery leaves a non-resumable diagnosis", async (t) => {
  let f;
  let selectedPath;
  let armed = false;
  let disappeared = false;
  f = await fixture(t, "integrated", "independent", {
    async afterInspectPath(request, inspected) {
      if (
        !armed ||
        request.path !== selectedPath ||
        request.projectPath !== dirname(selectedPath)
      )
        return;
      assert.equal(inspected.exists, true);
      armed = false;
      disappeared = true;
      await fs.rm(selectedPath);
    },
  });
  selectedPath = join(f.projectPath, "configuration", "selected.json");
  await fs.mkdir(dirname(selectedPath));
  await fs.writeFile(selectedPath, '{"schemaVersion":1}\n');
  await fs.writeFile(join(f.projectPath, ".gitignore"), "/configuration/\n");
  const first = (await f.start({ proactiveClarification: true })).run;
  const previousInspection = first.pipelineState.inspection;
  await fs.appendFile(
    first.pipelineState.pendingEdit.transcriptPath,
    `\nplacement: integrated\nconfigurationPath: ${selectedPath}\n`,
  );
  armed = true;
  await f.runner.resume({ runId: first.runId });
  const { saved, status } = await assertInspectionStop(
    f,
    first.runId,
    "reinspection",
    "workspace_changed",
  );
  assert.equal(disappeared, true);
  assert.deepEqual(status.pause.nextActions, []);
  assert.deepEqual(saved.pipelineState.inspection, previousInspection);
  assert.equal(saved.pipelineState.reinspectionRequired, true);
  assert.equal(saved.pipelineState.publication, null);
  assert.equal(saved.pipelineState.primaryApproval, null);
  assert.equal(saved.pipelineState.reviewApproval, null);
  assert.equal(f.calls.length, 0);
  await assert.rejects(f.runner.resume({ runId: first.runId }), {
    code: "ERR_INAPPLICABLE_RESUME_ACTION",
  });
});

test("pre-append read rejection is diagnosed and resumes the same question or decision", async (t) => {
  for (const kind of ["questions", "decision"])
    await t.test(kind, async (t) => {
      const service = createClarificationService({ interactive: false });
      const method =
        kind === "questions" ? "appendQuestionRound" : "appendProductDecision";
      let requested = false;
      let appendCalls = 0;
      const f = await fixture(t, "external", "independent", {
        transformResult(result) {
          if (
            requested ||
            result.status !== (kind === "questions" ? "READY" : "PROPOSAL")
          )
            return result;
          requested = true;
          return kind === "questions"
            ? {
                status: "QUESTIONS",
                questions: [
                  {
                    question: "Which checks define acceptance?",
                    whyItMatters: "The setup must preserve the agreed checks.",
                  },
                ],
                reason: "",
              }
            : {
                status: "PRODUCT_DECISION_REQUIRED",
                ...materialDecision,
                summary: "",
                checks: [],
                resources: [],
              };
        },
        clarificationService: service,
        clarificationHooks: {
          async [method](request) {
            appendCalls++;
            if (appendCalls === 1)
              throw new ClarificationError("Private rejected evidence", {
                code: "ERR_CLARIFICATION_READ",
                cause: Object.assign(new Error(), { code: "EMFILE" }),
              });
            return service[method](request);
          },
        },
      });
      const first = await f.start();
      const { saved, status } = await assertInspectionStop(
        f,
        first.run.runId,
        "preparation",
        "inspection_unavailable",
      );
      const transcriptPath = join(f.taskPath, "clarifications.md");
      const marker =
        kind === "questions" ? "## Round 1" : "## Product Decision 1";
      assert.equal(
        (await fs.readFile(transcriptPath, "utf8")).includes(marker),
        false,
      );
      assert.equal(
        hash(await fs.readFile(transcriptPath, "utf8")),
        saved.pipelineState.transcriptHash,
      );
      assert.equal(saved.pipelineState.transcriptAppendHash, null);
      assert.equal(saved.pipelineState.pendingEdit, null);
      assert.equal(saved.pipelineState.publication, null);
      assert.equal(saved.pause.inputRequest, undefined);
      assert.deepEqual(status.pause.nextActions, [
        { type: "resume", action: null },
      ]);
      const calls = f.calls.length;
      const waiting = (await f.runner.resume({ runId: saved.runId })).run;
      assert.equal(appendCalls, 2);
      assert.equal(f.calls.length, calls);
      assert.equal(
        waiting.pipelineState.pendingEdit.action,
        kind === "questions" ? "clarification-answers" : "product-decision",
      );
      assert.equal(
        waiting.pause.inputRequest.id,
        waiting.pipelineState.pendingEdit.id,
      );
      assert.equal(
        (await fs.readFile(transcriptPath, "utf8")).split(marker).length,
        2,
      );
      assert.equal(waiting.pipelineState.transcriptAppendHash, null);
      assert.equal(
        waiting.pipelineState.clarificationRounds,
        saved.pipelineState.clarificationRounds,
      );
      assert.equal(
        waiting.pipelineState.productDecisions,
        saved.pipelineState.productDecisions,
      );
      assert.equal(
        waiting.pipelineState.revisionRounds,
        saved.pipelineState.revisionRounds,
      );
      assert.deepEqual(
        waiting.pipelineState.inspection,
        saved.pipelineState.inspection,
      );
      assert.deepEqual(
        waiting.pipelineState.selection,
        saved.pipelineState.selection,
      );
      assert.equal(waiting.pipelineState.publication, null);
    });
});

test("transient proactive preparation retries authorization before any provider work", async (t) => {
  const service = createClarificationService({ interactive: false });
  let preparations = 0;
  let runId;
  let f;
  f = await fixture(t, "external", "independent", {
    clarificationService: service,
    clarificationHooks: {
      async prepareEdit(request) {
        preparations++;
        const before = await f.runStore.loadRun(runId);
        assert.equal(
          before.pipelineState.proactiveClarificationComplete,
          false,
        );
        assert.equal(before.pipelineState.pendingEdit, null);
        if (preparations === 1)
          throw new ClarificationError("Private rejected evidence", {
            code: "ERR_CLARIFICATION_READ",
            cause: Object.assign(new Error(), { code: "EMFILE" }),
          });
        const authorization = await service.prepareEdit(request);
        const after = await f.runStore.loadRun(runId);
        assert.equal(after.pipelineState.proactiveClarificationComplete, true);
        assert.equal(after.pipelineState.pendingEdit.id, authorization.id);
        assert.equal(after.pause.inputRequest.id, authorization.id);
        assert.equal(await f.runStore.runLeaseOwnerIsLive(runId), true);
        return authorization;
      },
    },
    async beforeRun() {
      assert.equal(preparations, 2);
      const current = await f.runStore.loadRun(runId);
      assert.equal(current.pipelineState.pendingEdit, null);
      assert.equal(current.pipelineState.proactiveClarificationComplete, true);
      return false;
    },
  });
  const { run } = await f.runner.create({
    pipelineId: "init",
    projectPath: f.projectPath,
    taskPath: f.taskPath,
    proactiveClarification: true,
  });
  runId = run.runId;
  await f.runner.resume({ runId });
  const { saved } = await assertInspectionStop(
    f,
    runId,
    "preparation",
    "inspection_unavailable",
  );
  assert.equal(saved.pipelineState.proactiveClarificationComplete, false);
  assert.equal(saved.pipelineState.pendingEdit, null);
  assert.equal(f.calls.length, 0);
  const waiting = (await f.runner.resume({ runId })).run;
  assert.equal(preparations, 2);
  assert.equal(waiting.pause.reason, "proactive_clarification");
  assert.equal(
    waiting.pipelineState.pendingEdit.action,
    "proactive-clarification",
  );
  assert.equal(waiting.pipelineState.proactiveClarificationComplete, true);
  assert.equal(
    waiting.pipelineState.transcriptHash,
    saved.pipelineState.transcriptHash,
  );
  assert.equal(f.calls.length, 0);
  // An unchanged close consumes this authorization before normal provider work.
  const completed = (await f.runner.resume({ runId })).run;
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(preparations, 2);
  assert.equal(completed.pipelineState.pendingEdit, null);
  assert.equal(
    completed.pipelineState.clarificationHash,
    saved.pipelineState.transcriptHash,
  );
  assert.equal(completed.pipelineState.clarificationRounds, 0);
  assert.equal(completed.pipelineState.revisionRounds, 0);
  assert.ok(f.calls.length > 0);
});

test("initial task and context hashing failures pause before provider work and capture inputs once on resume", async (t) => {
  for (const rejectedInput of ["task.md", "context.md"])
    await t.test(rejectedInput, async (t) => {
      const service = createClarificationService({ interactive: false });
      const reads = { "task.md": 0, "context.md": 0 };
      let capturing = false;
      let rejected = false;
      let f;
      f = await fixture(t, "external", "independent", {
        clarificationService: service,
        clarificationHooks: {
          async ensureTranscript(request) {
            const result = await service.ensureTranscript(request);
            capturing = true;
            return result;
          },
        },
        async beforeReadFile({ path }) {
          if (!capturing) return;
          for (const input of Object.keys(reads)) {
            if (path !== join(f.taskPath, input)) continue;
            reads[input]++;
            if (!rejected && input === rejectedInput) {
              rejected = true;
              throw new WorkspaceSafetyError("Private rejected evidence", {
                code: "ERR_WORKSPACE_INSPECTION",
                cause: Object.assign(new Error(), { code: "EMFILE" }),
              });
            }
          }
        },
        async beforeRun() {
          // One initial capture plus the separate first-turn input read.
          assert.deepEqual(reads, { "task.md": 2, "context.md": 2 });
          capturing = false;
          return false;
        },
      });
      await fs.writeFile(
        join(f.taskPath, "context.md"),
        "Preserve the agreed setup checks.\n",
      );
      const first = await f.start();
      const { saved } = await assertInspectionStop(
        f,
        first.run.runId,
        "preparation",
        "inspection_unavailable",
      );
      assert.equal(saved.pipelineState.transcriptHash, null);
      assert.equal(saved.pipelineState.inspection, null);
      assert.equal(saved.pipelineState.publication, null);
      assert.equal(saved.observations, null);
      assert.equal(f.calls.length, 0);
      reads["task.md"] = reads["context.md"] = 0;
      const completed = (await f.runner.resume({ runId: saved.runId })).run;
      assert.equal(completed.pipelineState.workflowState, "DONE");
      assert.equal(
        completed.hashes.task,
        hash(await fs.readFile(join(f.taskPath, "task.md"), "utf8")),
      );
      assert.equal(
        completed.hashes.context,
        hash(await fs.readFile(join(f.taskPath, "context.md"), "utf8")),
      );
    });
});

test("prepared configuration read failure preserves verified publication and resumes before guidance", async (t) => {
  let rejected = false;
  let runId;
  let f;
  f = await fixture(t, "external", "independent", {
    async beforeInspectPath({ path }) {
      if (!runId || rejected || path !== join(f.projectPath, ".git")) return;
      const current = await f.runStore.loadRun(runId);
      if (!current.pipelineState.publication?.prepared) return;
      rejected = true;
      throw new ConfigurationError("Private rejected evidence", {
        code: "ERR_PROJECT_CONFIGURATION_READ",
        cause: Object.assign(new Error(), { code: "EMFILE" }),
      });
    },
  });
  const { run } = await f.runner.create({
    pipelineId: "init",
    projectPath: f.projectPath,
    taskPath: f.taskPath,
  });
  runId = run.runId;
  await f.runner.resume({ runId });
  const { saved, status } = await assertInspectionStop(
    f,
    runId,
    "preparation",
    "inspection_unavailable",
  );
  assert.equal(rejected, true);
  assert.equal(saved.pause.resumeState, "PROPOSAL_ACCEPTED");
  assert.equal(saved.pipelineState.publication.prepared, true);
  assert.equal(saved.pipelineState.publication.pending, null);
  assert.ok(saved.pipelineState.publication.receipts.length > 0);
  assert.equal(saved.pipelineState.guidanceIntent, null);
  assert.equal(saved.pipelineState.guidanceReceipt, null);
  assert.deepEqual(status.pause.nextActions, [
    { type: "resume", action: null },
  ]);
  const calls = f.calls.length;
  const completed = (await f.runner.resume({ runId })).run;
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.deepEqual(
    completed.pipelineState.publication,
    saved.pipelineState.publication,
  );
  assert.deepEqual(
    completed.pipelineState.selection,
    saved.pipelineState.selection,
  );
  assert.equal(
    completed.pipelineState.reviewApproval,
    saved.pipelineState.reviewApproval,
  );
  assert.equal(
    completed.pipelineState.revisionRounds,
    saved.pipelineState.revisionRounds,
  );
  assert.equal(f.calls.length, calls + 1);
  assert.match(f.calls.at(-1).prompt, /Distinct terminal confirmation:/u);
});

test("foreground init diagnoses pre-dispatch validation while both execution owners remain held", async (t) => {
  let armed = false;
  let rejected = false;
  let runId;
  let leasePath;
  let diagnoses = 0;
  let f;
  f = await fixture(t, "external", "independent", {
    async afterWorktreeLease(ownership) {
      runId = ownership.runId;
      leasePath = ownership.path;
      if (!rejected) armed = true;
    },
    async beforeInspect() {
      if (!armed) return;
      armed = false;
      rejected = true;
      throw new WorkspaceSafetyError("Private rejected evidence", {
        code: "ERR_WORKSPACE_INSPECTION",
        cause: Object.assign(new Error(), { code: "EMFILE" }),
      });
    },
    async onActivity(activity) {
      if (activity.phase !== "inspection" || activity.kind !== "blocked")
        return;
      diagnoses++;
      assert.equal(await f.runStore.runLeaseOwnerIsLive(activity.runId), true);
      assert.equal(
        await f.runStore.worktreeLeaseOwner(leasePath, activity.runId),
        activity.runId,
      );
      assert.equal(
        (await f.runStore.loadRun(activity.runId)).pause.reason,
        "init_inspection_failed",
      );
    },
  });
  const first = await f.start();
  assert.equal(first.run.runId, runId);
  assert.equal(diagnoses, 1);
  const { saved } = await assertInspectionStop(
    f,
    runId,
    "preparation",
    "inspection_unavailable",
  );
  assert.equal(saved.pipelineState.transcriptHash, null);
  assert.equal(saved.pipelineState.sequence, 0);
  assert.equal(saved.pipelineState.inspection, null);
  assert.equal(saved.pipelineState.publication, null);
  assert.equal(saved.observations, null);
  assert.equal(f.calls.length, 0);
  assert.equal(await f.runStore.worktreeLeaseOwner(leasePath, runId), null);
  assert.equal(
    (await f.runner.resume({ runId })).run.pipelineState.workflowState,
    "DONE",
  );
  assert.equal(diagnoses, 1);
});

test("proposal policy source reads diagnose inspection without rejecting provider content", async (t) => {
  let f;
  let rejected = false;
  f = await fixture(t, "integrated", "independent", {
    async beforeReadFile({ path }) {
      if (
        !f ||
        rejected ||
        f.calls.length < 2 ||
        !path.endsWith("/agent-runner.json")
      )
        return;
      rejected = true;
      throw new WorkspaceSafetyError("Private rejected evidence", {
        code: "ERR_WORKSPACE_INSPECTION",
        cause: Object.assign(new Error(), { code: "EMFILE" }),
      });
    },
  });
  const first = await f.start();
  const { saved } = await assertInspectionStop(
    f,
    first.run.runId,
    "post-turn",
    "inspection_unavailable",
  );
  assert.equal(rejected, true);
  assert.equal(saved.pause.resumeState, "PROPOSE");
  assert.equal(saved.pipelineState.proposal, null);
  assert.equal(saved.pipelineState.reviewApproval, null);
  assert.equal(saved.pipelineState.publication, null);
  assert.equal(saved.pipelineState.revisionRounds, 0);
  const completed = (await f.runner.resume({ runId: saved.runId })).run;
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.pipelineState.revisionRounds, 0);
});

test("publication preparation read rejection retains approvals without reserving an effect", async (t) => {
  let f;
  let runId;
  let rejected = false;
  f = await fixture(t, "external", "independent", {
    async beforeInspectInfrastructure() {
      if (!runId || rejected) return;
      const { pipelineState: state } = await f.runStore.loadRun(runId);
      if (state.publication === null) return;
      assert.equal(state.publication.pending, null);
      assert.deepEqual(state.publication.receipts, []);
      rejected = true;
      throw new WorkspaceSafetyError("Private rejected evidence", {
        code: "ERR_WORKSPACE_INSPECTION",
        cause: Object.assign(new Error(), { code: "EMFILE" }),
      });
    },
  });
  const { run } = await f.runner.create({
    pipelineId: "init",
    projectPath: f.projectPath,
    taskPath: f.taskPath,
  });
  runId = run.runId;
  await f.runner.resume({ runId });
  const { saved } = await assertInspectionStop(
    f,
    runId,
    "publication-preparation",
    "inspection_unavailable",
  );
  assert.equal(rejected, true);
  assert.equal(saved.pause.resumeState, "PROPOSAL_ACCEPTED");
  assert.equal(saved.pipelineState.publication.pending, null);
  assert.deepEqual(saved.pipelineState.publication.receipts, []);
  assert.notEqual(saved.pipelineState.reviewApproval, null);
  await assert.rejects(fs.lstat(saved.pipelineState.selection.rootPath), {
    code: "ENOENT",
  });
  const calls = f.calls.length;
  const completed = (await f.runner.resume({ runId })).run;
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(
    completed.pipelineState.reviewApproval,
    saved.pipelineState.reviewApproval,
  );
  assert.equal(f.calls.length, calls + 1);
});

test("input inspection rejection cannot acknowledge unapplied clarification input", async (t) => {
  for (const checkpoint of ["canonical", "source-proof", "clarification-read"])
    await t.test(checkpoint, async (t) => {
      let rejectOnLease = false;
      let armed = false;
      let writingAnswers = false;
      const service = createClarificationService({ interactive: false });
      const f = await fixture(t, "external", "independent", {
        clarificationService: service,
        clarificationHooks: {
          async writeEditAnswers(...args) {
            writingAnswers = true;
            try {
              return await service.writeEditAnswers(...args);
            } finally {
              writingAnswers = false;
            }
          },
        },
        async afterWorktreeLease() {
          armed = rejectOnLease;
        },
        async afterSnapshot() {
          if (!armed || checkpoint !== "source-proof") return;
          armed = false;
          throw new WorkspaceSafetyError("Private rejected evidence", {
            code: "ERR_WORKSPACE_INSPECTION",
            cause: Object.assign(new Error(), { code: "EMFILE" }),
          });
        },
        async beforeInspect() {
          if (!armed || checkpoint !== "canonical") return;
          armed = false;
          throw new WorkspaceSafetyError("Private rejected evidence", {
            code: "ERR_WORKSPACE_INSPECTION",
            cause: Object.assign(new Error(), { code: "EMFILE" }),
          });
        },
      });
      const waiting = (await f.start({ proactiveClarification: true })).run;
      const pending = waiting.pipelineState.pendingEdit;
      const before = await fs.readFile(pending.transcriptPath, "utf8");
      const input = {
        runId: waiting.runId,
        requestId: pending.id,
        expectedRevision: waiting.revision,
        answers: [],
      };
      const preview = await f.runner.previewInput(input);
      if (checkpoint === "clarification-read") {
        const nativeOpen = fs.open;
        const mocked = t.mock.method(fs, "open", async (path, ...args) => {
          if (writingAnswers && path === pending.transcriptPath)
            throw Object.assign(new Error("Private rejected evidence"), {
              code: "EMFILE",
            });
          return nativeOpen(path, ...args);
        });
        syncBuiltinESMExports();
        t.after(() => {
          mocked.mock.restore();
          syncBuiltinESMExports();
        });
      }
      rejectOnLease = true;
      await assert.rejects(
        f.runner.submitInput({ ...input, responseHash: preview.responseHash }),
        { code: "ERR_INIT_INSPECTION" },
      );
      const { saved } = await assertInspectionStop(
        f,
        waiting.runId,
        "preparation",
        "inspection_unavailable",
      );
      assert.equal(saved.pause.inputResponse, undefined);
      assert.deepEqual(saved.pipelineState.pendingEdit, pending);
      assert.equal(
        await f.runStore.worktreeLeaseOwner(f.projectPath, saved.runId),
        null,
      );
      assert.equal(await fs.readFile(pending.transcriptPath, "utf8"), before);
      assert.equal(f.calls.length, 0);
    });
});

test("normalized guidance inspection failure diagnoses prepared init without changing accepted receipts", async (t) => {
  for (const origin of ["controls", "directory-open", "directory-verification"])
    await t.test(origin, async (t) => {
      let rejected = false;
      let directoryToReject;
      let verifyArmed = false;
      let runId;
      let f;
      f = await fixture(
        t,
        origin === "directory-verification" ? "integrated" : "external",
        "independent",
        {
          async beforeInspectControls({ paths }) {
            if (!runId || rejected || paths.length !== 1) return;
            const current = await f.runStore.loadRun(runId);
            const state = current.pipelineState;
            if (
              !state.publication?.prepared ||
              state.guidanceIntent !== null ||
              !state.proposal.resources.some(
                ({ kind, path }) => kind === "guidance" && path === paths[0],
              )
            )
              return;
            if (origin !== "controls") {
              directoryToReject = state.selection.rootPath;
              return;
            }
            rejected = true;
            throw new WorkspaceSafetyError("Private rejected evidence", {
              code: "ERR_WORKSPACE_INSPECTION",
              cause: Object.assign(new Error("Private rejected evidence"), {
                code: "EMFILE",
              }),
            });
          },
        },
      );
      const original = "Preserve the local validation policy.\n";
      if (origin === "directory-verification") {
        const guide = join(
          f.projectPath,
          "LOCAL_ARTIFACTS",
          "agent-runner",
          "rules.md",
        );
        await fs.mkdir(dirname(guide), { recursive: true });
        await fs.writeFile(guide, original);
      }
      if (origin !== "controls") {
        const nativeOpen = fs.open;
        const nativeRealpath = fs.realpath;
        const mockedOpen = t.mock.method(fs, "open", async (path, ...args) => {
          if (
            origin === "directory-open" &&
            path === directoryToReject &&
            !rejected
          ) {
            rejected = true;
            throw Object.assign(new Error("Private rejected evidence"), {
              code: "EMFILE",
              syscall: "open",
            });
          }
          const handle = await nativeOpen(path, ...args);
          if (
            origin === "directory-verification" &&
            directoryToReject &&
            typeof path === "string" &&
            path.endsWith("/rules.md")
          )
            verifyArmed = true;
          return handle;
        });
        const mockedRealpath = t.mock.method(
          fs,
          "realpath",
          async (path, ...args) => {
            if (
              origin === "directory-verification" &&
              verifyArmed &&
              !rejected &&
              path === directoryToReject
            ) {
              rejected = true;
              throw Object.assign(new Error("Private rejected evidence"), {
                code: "EMFILE",
              });
            }
            return nativeRealpath(path, ...args);
          },
        );
        syncBuiltinESMExports();
        t.after(() => {
          mockedOpen.mock.restore();
          mockedRealpath.mock.restore();
          syncBuiltinESMExports();
        });
      }
      const { run } = await f.runner.create({
        pipelineId: "init",
        projectPath: f.projectPath,
        taskPath: f.taskPath,
      });
      runId = run.runId;
      await f.runner.resume({ runId });
      const { saved, status } = await assertInspectionStop(
        f,
        runId,
        "preparation",
        "inspection_unavailable",
      );
      assert.equal(rejected, true);
      assert.equal(saved.pause.resumeState, "PROPOSAL_ACCEPTED");
      assert.equal(saved.pipelineState.publication.prepared, true);
      assert.equal(saved.pipelineState.publication.pending, null);
      assert.ok(saved.pipelineState.publication.receipts.length > 0);
      assert.equal(saved.pipelineState.guidanceIntent, null);
      assert.equal(saved.pipelineState.guidanceReceipt, null);
      const guide = saved.pipelineState.proposal.resources.find(
        ({ kind }) => kind === "guidance",
      );
      if (origin === "directory-verification")
        assert.equal(await fs.readFile(guide.path, "utf8"), original);
      else await assert.rejects(fs.lstat(guide.path), { code: "ENOENT" });
      assert.deepEqual(status.pause.nextActions, [
        { type: "resume", action: null },
      ]);
      const calls = f.calls.length;
      const completed = (await f.runner.resume({ runId })).run;
      assert.equal(completed.pipelineState.workflowState, "DONE");
      assert.deepEqual(
        completed.pipelineState.publication,
        saved.pipelineState.publication,
      );
      assert.deepEqual(
        completed.pipelineState.inspection,
        saved.pipelineState.inspection,
      );
      assert.deepEqual(
        completed.pipelineState.selection,
        saved.pipelineState.selection,
      );
      assert.equal(
        completed.pipelineState.reviewApproval,
        saved.pipelineState.reviewApproval,
      );
      assert.equal(
        completed.pipelineState.revisionRounds,
        saved.pipelineState.revisionRounds,
      );
      assert.equal(f.calls.length, calls + 1);
      assert.match(f.calls.at(-1).prompt, /Distinct terminal confirmation:/u);
    });
});
