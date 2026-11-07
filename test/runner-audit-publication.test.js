import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import * as filesystem from "node:fs/promises";
import {
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { CodexAdapterError } from "../src/agents/index.js";
import { parseRunnerConfiguration } from "../src/config/index.js";
import { main } from "../src/index.js";
import { createMcpControlPlane } from "../src/mcp/index.js";
import { createRunner } from "../src/runner/index.js";
import { createRunStore } from "../src/state/index.js";
import { createWorkspaceService } from "../src/workspace/index.js";
import {
  READY,
  complete,
  fixture,
} from "../pipelines/audit/test/support/index.js";

const execute = promisify(execFile);

test("public audit preserves confined reports and terminal provider diagnoses", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "audit-public-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  for (const [git, mode, diagnosticClass] of [
    [false, "independent"],
    [true, "combined"],
    [false, "lazy", "isolation_workspace_policy"],
  ]) {
    await t.test(`${git ? "Git" : "directory"}: ${mode}`, async () => {
      const projectPath = join(root, `${git}-${mode}`);
      const taskPath = join(projectPath, "artifacts");
      await mkdir(taskPath, { recursive: true });
      await writeFile(join(projectPath, "source.txt"), "Original source\n");
      await writeFile(
        join(taskPath, "task.md"),
        "Audit the whole workspace.\n",
      );
      if (git) {
        await execute("git", ["init", "--quiet", projectPath]);
        await writeFile(join(projectPath, ".gitignore"), "artifacts/\n");
      }
      const projectConfigurationPath = join(projectPath, "project.json");
      if (diagnosticClass)
        await writeFile(projectConfigurationPath, '{"schemaVersion":1}\n');
      const calls = [];
      const probes = [];
      let rejectProviderCalls = false;
      const adapter = {
        async probe(request) {
          probes.push(request);
          assert.equal(rejectProviderCalls, false, "Unexpected provider probe");
          return {
            version: "fixture",
            readOnly: true,
            structuredOutput: true,
            declaredWorkspace: true,
            remoteWriteBlocked: true,
            nativeSessionContinuation: true,
            policyReceipt: {
              schemaVersion: 1,
              fingerprint: createHash("sha256")
                .update(JSON.stringify(request))
                .digest("hex"),
              supportedAccess: ["read-only"],
            },
          };
        },
        async run(request) {
          calls.push(request);
          assert.equal(rejectProviderCalls, false, "Unexpected provider turn");
          assert.equal(request.access, "read-only");
          if (diagnosticClass && calls.length === 2)
            throw new CodexAdapterError("PRIVATE_PROVIDER_MESSAGE", {
              code: "ERR_CODEX_ISOLATION",
              diagnosticClass,
              cause: new Error("PRIVATE_CAUSE"),
            });
          const evidence = JSON.parse(request.prompt.split("\n").at(-1));
          return {
            structured:
              calls.length === 1
                ? {
                    status: "READY",
                    inputs: {
                      scope: ["Whole workspace"],
                      references: [],
                      exclusions: [],
                      criteria: ["Established rules"],
                    },
                    questions: [],
                    reason: "",
                  }
                : {
                    status: "COMPLETE",
                    snapshotFingerprint: evidence.snapshotFingerprint,
                    candidates: [],
                    limitations: [],
                    hypotheses: [],
                    reportCorrections: [],
                  },
            sessionId:
              request.session?.mode === "continue"
                ? request.session.id
                : `child-${calls.length}`,
          };
        },
      };
      const stateRoot = join(root, `state-${git}-${mode}`);
      const runStore = createRunStore({ stateRoot });
      const activities = [];
      const publications = [];
      const workspace = createWorkspaceService();
      const createObserver = (store = runStore) =>
        createRunner({
          adapters: { codex: adapter },
          runStore: store,
          onActivity: (activity) => activities.push(activity),
          workspace: {
            ...workspace,
            reportArtifact: (...args) => {
              publications.push(args);
              return workspace.reportArtifact(...args);
            },
          },
          loadConfiguration: async () =>
            parseRunnerConfiguration(
              JSON.stringify({
                schemaVersion: 1,
                defaultBackend: "codex",
                pipelines: { audit: { mode } },
              }),
            ),
        });
      const runner = createObserver();
      if (diagnosticClass) {
        await assert.rejects(
          runner.run({
            pipelineId: "audit",
            projectPath,
            taskPath,
            projectConfigurationPath,
          }),
          { code: "ERR_CODEX_ISOLATION", diagnosticClass },
        );
        rejectProviderCalls = true;
        const probeCount = probes.length;
        const runId = activities[0].runId;
        const observationStore = createRunStore({ stateRoot });
        const reconstructed = createObserver(observationStore);
        const failed = (await reconstructed.status(runId)).run;
        assert.equal(failed.pipelineState.workflowState, "FAILED");
        assert.equal(failed.pause.diagnosticClass, diagnosticClass);
        assert.equal(failed.pipelineState.history[0].outcome, "interrupted");
        const publicationCount = publications.length;
        const control = createMcpControlPlane({
          runner: reconstructed,
          runStore: observationStore,
        });
        const status = await control.runStatus({ runId });
        assert.deepEqual(status.pause.evidence, [
          `Adapter diagnostic: ${diagnosticClass}.`,
        ]);
        assert.match(
          status.pause.explanation,
          /could not enforce the declared workspace policy/u,
        );
        assert.deepEqual(status.pause.nextActions, []);
        assert.equal(status.pause.resumeState, null);
        const notifications = [];
        const waited = await control.runWait(
          { runId, cursor: 0, timeoutMs: 0, progress: true },
          {
            progressToken: "audit-observer",
            notify: (notification) => notifications.push(notification),
          },
        );
        assert.equal(waited.status, "FAILED");
        assert.equal(waited.timedOut, false);
        assert.deepEqual(waited.pause, status.pause);
        const page = await control.runActivity({
          runId,
          cursor: 0,
          limit: 100,
        });
        const terminalActivity = page.activities.find(
          ({ actor, phase, kind }) =>
            actor === "runner" && phase === "audit" && kind === "failed",
        );
        assert.equal(
          terminalActivity.message,
          `Audit failed: ERR_CODEX_ISOLATION (${diagnosticClass}).`,
        );
        assert.ok(
          activities.some(
            ({ message }) => message === terminalActivity.message,
          ),
        );
        assert.ok(
          notifications.some(({ params }) =>
            params.message.includes(terminalActivity.message),
          ),
        );
        let output = "";
        assert.equal(
          await main(["status", "--run", runId], {
            runner: reconstructed,
            stdout: {
              write: (value) => {
                output += value;
              },
            },
            stderr: { write: (value) => assert.fail(value) },
          }),
          0,
        );
        assert.ok(output.includes(status.pause.explanation));
        assert.ok(output.includes(status.pause.evidence[0]));
        const resumed = await reconstructed.resume({ runId, action: null });
        assert.deepEqual(resumed.run.pipelineState, failed.pipelineState);
        assert.deepEqual(resumed.run.pause, failed.pause);
        assert.equal(
          failed.projectConfigurationProtection.path,
          projectConfigurationPath,
        );
        for (const drift of ["changed", "missing"]) {
          if (drift === "changed")
            await writeFile(
              projectConfigurationPath,
              '{"schemaVersion":1,"defaultModel":"changed"}\n',
            );
          else await rm(projectConfigurationPath);
          const continued = await reconstructed.resume({ runId, action: null });
          assert.deepEqual(continued.run, failed);
          assert.deepEqual(
            (await control.runStatus({ runId })).pause,
            status.pause,
          );
        }
        assert.equal(calls.length, 2);
        assert.equal(probes.length, probeCount);
        assert.equal(publications.length, publicationCount);
        assert.deepEqual(
          (await reconstructed.status(runId)).run.pipelineState,
          failed.pipelineState,
        );
        assert.doesNotMatch(
          JSON.stringify({
            failed,
            status,
            waited,
            page,
            notifications,
            activities,
            output,
          }),
          /PRIVATE_/u,
        );
        assert.equal(
          await readFile(join(projectPath, "source.txt"), "utf8"),
          "Original source\n",
        );
        return;
      }
      const result = await runner.run({
        pipelineId: "audit",
        projectPath,
        taskPath,
      });
      assert.equal(result.run.pipelineState.workflowState, "DONE");
      assert.equal(calls.length, mode === "combined" ? 3 : 2);
      assert.deepEqual(result.run.workspace.policy.outputPaths, []);
      assert.equal(
        await readFile(join(projectPath, "source.txt"), "utf8"),
        "Original source\n",
      );
      assert.match(
        await readFile(join(taskPath, "audit.md"), "utf8"),
        /\*\*Status:\*\* Complete/u,
      );
      const control = createMcpControlPlane({ runner, runStore });
      const status = await control.runStatus({ runId: result.run.runId });
      assert.equal(status.auditReport.status, "complete");
      assert.equal(status.auditReport.path, join(taskPath, "audit.md"));
      assert.equal(status.auditReport.confirmedFindings, 0);
      assert.equal(status.planPath, null);
      let output = "";
      assert.equal(
        await main(["status", "--run", result.run.runId], {
          runner,
          stdout: {
            write: (value) => {
              output += value;
            },
          },
          stderr: { write: (value) => assert.fail(value) },
        }),
        0,
      );
      assert.ok(
        output.includes(
          `Audit report: ${join(taskPath, "audit.md")} (complete)`,
        ),
      );
      if (git) {
        assert.equal(
          (await execute("git", ["-C", projectPath, "status", "--porcelain"]))
            .stdout,
          "?? .gitignore\n?? source.txt\n",
        );
      }
    });
  }
});

test("artifact publication recovers exact bytes and rejects intervening edits and aliases", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "audit-artifact-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const projectPath = join(root, "project");
  await mkdir(projectPath);
  const path = join(projectPath, "audit.md");
  const temporaryPath = join(projectPath, ".audit.md.tmp");
  const workspace = createWorkspaceService();
  const inspect = () =>
    workspace.inspect({
      workspacePath: projectPath,
      artifactPaths: [path, temporaryPath],
      stateRoot: join(root, "state"),
    });
  const content = "# Audit report\n";
  const options = { recordTemporary: async () => {} };
  // A crash after temporary completion but before rename retains the intended bytes.
  await writeFile(temporaryPath, content);
  const first = await workspace.reportArtifact(
    {
      inspection: await inspect(),
      path,
      temporaryPath,
      content,
      expectedHash: null,
    },
    options,
  );
  assert.equal(await readFile(path, "utf8"), content);
  const replay = await workspace.reportArtifact(
    {
      inspection: await inspect(),
      path,
      temporaryPath,
      content,
      expectedHash: null,
    },
    options,
  );
  assert.deepEqual(replay, first);
  await writeFile(path, "User edit\n");
  await assert.rejects(
    workspace.reportArtifact(
      {
        inspection: await inspect(),
        path,
        temporaryPath,
        content: "New report\n",
        expectedHash: first.contentHash,
      },
      options,
    ),
    { code: "ERR_WORKSPACE_REPORT_CHANGED" },
  );
  await rm(path);
  const outside = join(root, "outside.md");
  await writeFile(outside, "Unrelated content\n");
  await symlink(outside, path);
  await assert.rejects(inspect());
  assert.equal(await readFile(outside, "utf8"), "Unrelated content\n");
});

test("interrupted report writes resume accepted discovery and preserve substituted temporaries", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "audit-write-recovery-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  for (const substituted of [false, true]) {
    await t.test(
      substituted ? "substituted temporary" : "owned partial write",
      async () => {
        const projectPath = join(root, String(substituted));
        await mkdir(projectPath);
        const path = join(projectPath, "audit.md");
        const temporaryPath = join(projectPath, ".audit.md.tmp");
        const f = fixture([READY, complete()]);
        f.run().taskPath = projectPath;
        let writes = 0;
        const workspace = createWorkspaceService({
          fileSystem: {
            ...filesystem,
            async open(candidate, flags, ...args) {
              const handle = await filesystem.open(candidate, flags, ...args);
              if (
                !candidate.endsWith("/.audit.md.tmp") ||
                !(
                  flags === "wx" ||
                  (typeof flags === "number" && flags & constants.O_WRONLY)
                )
              )
                return handle;
              return {
                stat: (...values) => handle.stat(...values),
                truncate: (...values) => handle.truncate(...values),
                sync: () => handle.sync(),
                close: () => handle.close(),
                async writeFile(content) {
                  assert.equal(
                    f.run().pipelineState.publication.temporary.phase,
                    "writing",
                  );
                  if (++writes === 2) {
                    await handle.writeFile(content.slice(0, 12));
                    throw new Error("Interrupted temporary write");
                  }
                  return handle.writeFile(content);
                },
              };
            },
          },
        });
        f.runtime.workspace.reportArtifact = async (request, options) =>
          workspace.reportArtifact(
            {
              inspection: await workspace.inspect({
                workspacePath: projectPath,
                artifactPaths: [path, temporaryPath],
                stateRoot: join(root, "state"),
              }),
              ...request,
            },
            options,
          );
        await assert.rejects(f.executePublic(), {
          code: "ERR_WORKSPACE_INSPECTION",
        });
        const saved = structuredClone(f.run());
        assert.equal(saved.pipelineState.history.length, 1);
        assert.equal(saved.pipelineState.history[0].outcome, "clean");
        assert.equal(
          saved.pipelineState.publication.temporary.phase,
          "writing",
        );
        assert.equal(saved.pipelineState.publication.pending.complete, true);
        const partial = await readFile(temporaryPath, "utf8");
        const original = await readFile(path, "utf8");
        assert.match(original, /In progress/u);
        if (substituted) {
          const replacement = join(projectPath, "replacement.md");
          await writeFile(replacement, partial);
          await rename(replacement, temporaryPath);
        }
        const result = await f.executePublic();
        assert.equal(f.calls.length, 2, "Accepted model work must not replay");
        if (substituted) {
          assert.equal(result.pause.reason, "audit_report_changed");
          assert.equal(await readFile(temporaryPath, "utf8"), partial);
          assert.equal(await readFile(path, "utf8"), original);
        } else {
          assert.equal(result.pipelineState.workflowState, "DONE");
          assert.equal(result.pipelineState.publication.temporary, null);
          assert.match(
            await readFile(path, "utf8"),
            /\*\*Status:\*\* Complete/u,
          );
          await assert.rejects(filesystem.stat(temporaryPath), {
            code: "ENOENT",
          });
        }
      },
    );
  }
});

test("artifact inspection rejects special-file substitution and growing reads before publication", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "audit-artifact-read-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const projectPath = join(root, "project");
  await mkdir(projectPath);
  const path = join(projectPath, "audit.md");
  const temporaryPath = join(projectPath, ".audit.md.tmp");
  for (const regular of [false, true]) {
    let opened = false;
    const workspace = createWorkspaceService({
      fileSystem: {
        ...filesystem,
        async open(candidate, flags, ...args) {
          // The absent report has no snapshot read; substitution occurs at publication inspection.
          if (!candidate.endsWith("/audit.md"))
            return filesystem.open(candidate, flags, ...args);
          opened = true;
          assert.ok(flags & constants.O_NONBLOCK);
          return {
            stat: async () => ({ isFile: () => regular, nlink: 1n, size: 0n }),
            read: async (buffer) => {
              assert.ok(regular, "Special files must never be read");
              buffer[0] = 120;
              return { bytesRead: 1 };
            },
            readFile: async () => Buffer.from("x"),
            close: async () => {},
          };
        },
      },
    });
    const inspection = await workspace.inspect({
      workspacePath: projectPath,
      artifactPaths: [path, temporaryPath],
      stateRoot: join(root, "state"),
    });
    await assert.rejects(
      workspace.reportArtifact(
        {
          inspection,
          path,
          temporaryPath,
          content: "x",
          expectedHash: null,
        },
        { recordTemporary: async () => {} },
      ),
      { code: regular ? "ERR_WORKSPACE_REPORT_CHANGED" : "ERR_WORKSPACE_PATH" },
    );
    assert.equal(opened, true);
    await assert.rejects(filesystem.stat(path), { code: "ENOENT" });
    await assert.rejects(filesystem.stat(temporaryPath), { code: "ENOENT" });
  }
});
