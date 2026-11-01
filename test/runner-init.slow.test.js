import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import * as fs from "node:fs/promises";
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
} from "@agent-runner/init";
import { parseRunnerConfiguration } from "../src/config/index.js";
import {
  AgentBoundaryError,
  normalizeFailureRecord,
} from "../src/agents/index.js";
import { createClarificationService } from "../src/clarifications/index.js";
import { main } from "../src/index.js";
import { createMcpControlPlane } from "../src/mcp/index.js";
import { createRunner } from "../src/runner/index.js";
import { createRunStore } from "../src/state/index.js";
import { createWorkspaceService } from "../src/workspace/index.js";
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
    beforeFile = async () => {},
    afterFile = async () => {},
    beforeFinish = async () => {},
    beforeInfrastructureRelease = async () => {},
    afterGuideReceipt = async () => {},
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
    adapters: { codex: adapter },
    inactivityTimers,
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
      const f = await fixture(t, "external", "lazy", {
        inactivityTimers: timers,
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
      await assert.rejects(f.runner.resume({ runId: run.runId }), {
        name: "AgentBoundaryError",
      });
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
    boundary(phase) {
      if (phase === "terminal" && !interrupted) {
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
  await assert.rejects(f.runner.resume({ runId: run.runId }), {
    name: "AgentBoundaryError",
  });
  const saved = (await f.runner.status(run.runId)).run;
  const path = saved.pipelineState.guidanceIntent.path;
  await fs.appendFile(path, "Intervening operator instructions.\n");
  const calls = f.calls.length;
  await assert.rejects(
    f.runner.resume({ runId: run.runId }),
    /guidance changed|snapshot changed/u,
  );
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
              throw new Error("Interrupted question publication");
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
              throw new Error("Interrupted decision append");
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
      const f = await fixture(t, "external", "combined", {
        maxRevisionRounds: 1,
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
    });
});
