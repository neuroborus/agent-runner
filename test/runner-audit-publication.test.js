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
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import workerThreads from "node:worker_threads";

import { auditPipeline } from "@agent-runner/audit";

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

test("artifact publication reconciles only proven custody and preserves refused files", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "audit-artifact-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const projectPath = join(root, "project");
  await mkdir(projectPath);
  const path = join(projectPath, "audit.md");
  const temporaryPath = join(projectPath, ".audit.md.tmp");
  const effects = [];
  let beforeCreate = null;
  let beforeRead = null;
  let afterOpen = null;
  let afterReopen = null;
  let duringRead = null;
  let beforeTargetRead = null;
  let afterTargetOpen = null;
  let targetLookup = null;
  let beforeClosingOpen = null;
  let beforeClosingRead = null;
  let descriptorFailureAt = null;
  // Frozen stat times model entry changes within one timestamp tick.
  let frozen = false;
  const freeze = (stat) =>
    frozen
      ? Object.assign(Object.create(Object.getPrototypeOf(stat)), stat, {
          mtimeNs: 0n,
          ctimeNs: 0n,
        })
      : stat;
  const frozenHandle = (handle) =>
    frozen
      ? new Proxy(handle, {
          get(target, key) {
            if (key === "stat")
              return async (...values) => freeze(await target.stat(...values));
            const value = Reflect.get(target, key);
            return typeof value === "function" ? value.bind(target) : value;
          },
        })
      : handle;
  const workspace = createWorkspaceService({
    fileSystem: {
      ...filesystem,
      async lstat(candidate, ...args) {
        const lookup = async () =>
          freeze(await filesystem.lstat(candidate, ...args));
        return targetLookup && candidate.endsWith("/audit.md")
          ? targetLookup(lookup)
          : lookup();
      },
      async opendir(candidate, options) {
        if (beforeClosingOpen !== null) {
          const before = beforeClosingOpen;
          beforeClosingOpen = null;
          await before();
        }
        const directory = await filesystem.opendir(candidate, options);
        if (beforeClosingRead === null) return directory;
        return {
          async read() {
            const before = beforeClosingRead;
            beforeClosingRead = null;
            assert.equal(await filesystem.readlink(candidate), projectPath);
            await before();
            return directory.read();
          },
          close: () => directory.close(),
        };
      },
      async open(candidate, flags, ...args) {
        const owned = candidate.endsWith("/.audit.md.tmp");
        if (owned && flags === "wx") await beforeCreate?.();
        const reading =
          typeof flags === "number" && !(flags & constants.O_WRONLY);
        const readingTemporary = owned && reading;
        const readingTarget = candidate.endsWith("/audit.md") && reading;
        if (readingTarget) await beforeTargetRead?.();
        if (readingTemporary) await beforeRead?.();
        const handle = frozenHandle(
          await filesystem.open(candidate, flags, ...args),
        );
        try {
          if (readingTarget) await afterTargetOpen?.();
          if (readingTemporary) await afterOpen?.();
          if (owned && typeof flags === "number" && flags & constants.O_WRONLY)
            await afterReopen?.();
        } catch (cause) {
          await handle.close();
          throw cause;
        }
        if (readingTemporary && duringRead !== null)
          return {
            stat: (...values) => handle.stat(...values),
            close: () => handle.close(),
            async read(...values) {
              await duringRead?.();
              duringRead = null;
              return handle.read(...values);
            },
          };
        if (
          descriptorFailureAt === null ||
          !candidate.endsWith(descriptorFailureAt)
        )
          return handle;
        return {
          stat: (...values) => handle.stat(...values),
          close: () => handle.close(),
          async read() {
            throw Object.assign(new Error("Synthetic descriptor failure"), {
              code: "ENOENT",
            });
          },
        };
      },
      async rename(...args) {
        effects.push("rename");
        return filesystem.rename(...args);
      },
      async unlink(...args) {
        effects.push("unlink");
        return filesystem.unlink(...args);
      },
    },
  });
  const custody = async (file) => {
    const stat = await filesystem.stat(file, { bigint: true });
    return {
      device: String(stat.dev),
      inode: String(stat.ino),
      mode: String(stat.mode),
      birthtimeNs: String(stat.birthtimeNs),
    };
  };
  const inspect = () =>
    workspace.inspect({
      workspacePath: projectPath,
      artifactPaths: [path, temporaryPath],
      stateRoot: join(root, "state"),
    });
  const inspection = await inspect();
  const publish = (content, expectedHash, options = {}) =>
    workspace.reportArtifact(
      {
        inspection,
        path,
        temporaryPath,
        content,
        expectedHash,
      },
      {
        recordTemporary: async () => assert.fail("Unexpected custody write"),
        ...options,
      },
    );
  const conflict = { code: "ERR_WORKSPACE_REPORT_TEMPORARY_CONFLICT" };
  const content = "# Audit report\n";
  // A crash after the prepared record but before rename retains the intended bytes.
  await writeFile(temporaryPath, content);
  const prepared = {
    phase: "prepared",
    identity: await custody(temporaryPath),
  };
  const first = await publish(content, null, { temporary: prepared });
  assert.equal(await readFile(path, "utf8"), content);
  assert.deepEqual(await custody(path), prepared.identity);
  // A lost receipt reconciles only from the renamed prepared inode.
  assert.deepEqual(
    await publish(content, null, { temporary: prepared }),
    first,
  );
  await assert.rejects(publish(content, null), conflict);
  assert.deepEqual(await publish(content, first.contentHash), first);
  // A temporary reappearing during the first destination reread is unproven.
  await assert.rejects(
    publish(content, first.contentHash, {
      assertCurrent: () => {
        let reads = 0;
        beforeTargetRead = async () => {
          if (++reads !== 2) return;
          beforeTargetRead = null;
          await writeFile(temporaryPath, content);
        };
      },
    }),
    conflict,
  );
  assert.equal(await readFile(path, "utf8"), content);
  await rm(temporaryPath);
  // A same-byte destination substituted before the first temporary recheck.
  const replacement = join(projectPath, "replacement.md");
  let lookups = 0;
  beforeRead = async () => {
    if (++lookups !== 2) return;
    await writeFile(replacement, content);
    await rename(replacement, path);
  };
  await assert.rejects(publish(content, first.contentHash), {
    code: "ERR_WORKSPACE_REPORT_CHANGED",
  });
  // A same-byte destination substituted before the last temporary recheck.
  lookups = 0;
  beforeRead = async () => {
    if (++lookups !== 3) return;
    await writeFile(replacement, content);
    await rename(replacement, path);
  };
  await assert.rejects(publish(content, first.contentHash), {
    code: "ERR_WORKSPACE_REPORT_CHANGED",
  });
  // Parent drift keeps precedence over a destination substituted with it.
  const driftMove = join(root, "drift-move");
  lookups = 0;
  beforeRead = async () => {
    if (++lookups !== 3) return;
    await rename(projectPath, driftMove);
    await writeFile(join(driftMove, "replacement.md"), content);
    await rename(
      join(driftMove, "replacement.md"),
      join(driftMove, "audit.md"),
    );
  };
  await assert.rejects(publish(content, first.contentHash), {
    code: "ERR_WORKSPACE_DRIFT",
  });
  await rename(driftMove, projectPath);
  // Same-tick entry changes inside the readback interval leave every stat
  // sample equal; only parent notifications refuse them.
  const movedAside = join(projectPath, "aside.md");
  const accepted = await custody(path);
  frozen = true;
  lookups = 0;
  beforeRead = async () => {
    if (++lookups !== 3) return;
    beforeRead = null;
    // The last temporary recheck sees absence beside a same-byte substitute.
    await rename(path, movedAside);
    await writeFile(replacement, content);
    await rename(replacement, path);
    beforeTargetRead = async () => {
      beforeTargetRead = null;
      // The last destination lookup sees the accepted inode beside a temporary.
      await rename(path, temporaryPath);
      await rename(movedAside, path);
    };
  };
  await assert.rejects(publish(content, first.contentHash), conflict);
  assert.deepEqual(await custody(path), accepted);
  assert.equal(await readFile(temporaryPath, "utf8"), content);
  await rm(temporaryPath);
  // The accepted inode moved aside and restored before the last recheck.
  lookups = 0;
  beforeRead = async () => {
    if (++lookups !== 3) return;
    beforeRead = null;
    await rename(path, movedAside);
    await rename(movedAside, path);
  };
  await assert.rejects(publish(content, first.contentHash), {
    code: "ERR_WORKSPACE_REPORT_CHANGED",
  });
  assert.deepEqual(await custody(path), accepted);
  await assert.rejects(filesystem.stat(temporaryPath), { code: "ENOENT" });
  // A separate in-process watcher, like the run store's, receives its own
  // events without sharing or hiding the readback observer's queue.
  const separate = new AbortController();
  const separateWatch = (async () => {
    for await (const { filename } of filesystem.watch(projectPath, {
      signal: AbortSignal.any([separate.signal, AbortSignal.timeout(5_000)]),
    })) {
      if (filename === "audit.md") return;
    }
    assert.fail("Separate watcher closed before observing audit.md");
  })();
  separateWatch.catch(() => {});
  try {
    lookups = 0;
    beforeRead = async () => {
      if (++lookups !== 3) return;
      beforeRead = null;
      await rename(path, movedAside);
      await writeFile(replacement, content);
      await rename(replacement, path);
      beforeTargetRead = async () => {
        beforeTargetRead = null;
        await rename(path, temporaryPath);
        await rename(movedAside, path);
      };
    };
    await assert.rejects(publish(content, first.contentHash), conflict);
    await separateWatch;
  } finally {
    separate.abort();
    await separateWatch.catch(() => {});
  }
  assert.deepEqual(await custody(path), accepted);
  assert.equal(await readFile(temporaryPath, "utf8"), content);
  await rm(temporaryPath);
  // A temporary notified alone stays custody even after it disappears.
  lookups = 0;
  beforeRead = async () => {
    if (++lookups !== 3) return;
    beforeRead = null;
    await writeFile(temporaryPath, content);
    await rm(temporaryPath);
  };
  await assert.rejects(publish(content, first.contentHash), conflict);
  assert.deepEqual(await custody(path), accepted);
  await assert.rejects(filesystem.stat(temporaryPath), { code: "ENOENT" });
  // Overlapping readbacks observe through separate queues and both verify.
  let nested = null;
  lookups = 0;
  beforeRead = async () => {
    if (++lookups !== 3) return;
    beforeRead = null;
    nested = await publish(content, first.contentHash);
  };
  assert.deepEqual(await publish(content, first.contentHash), first);
  assert.deepEqual(nested, first);
  assert.deepEqual(await custody(path), accepted);
  await assert.rejects(filesystem.stat(temporaryPath), { code: "ENOENT" });
  await t.test(
    "ignores an unrelated watch on the same inode number",
    async (t) => {
      // Supply a separate inotify fdinfo record with the marker inode on a
      // different device while leaving the real observer queue intact.
      const foreignWatch = String.raw`
      {
        const fs = require("node:fs");
        const { readdirSync, readlinkSync, readFileSync } = fs;
        const inode = fs.statSync("/proc/thread-self", { bigint: true }).ino;
        const fd = "2147483647";
        fs.readdirSync = (path, ...args) => path === "/proc/self/fd"
          ? [...readdirSync(path, ...args), fd] : readdirSync(path, ...args);
        fs.readlinkSync = (path, ...args) => path === "/proc/self/fd/" + fd
          ? "anon_inode:inotify" : readlinkSync(path, ...args);
        fs.readFileSync = (path, ...args) => path === "/proc/self/fdinfo/" + fd
          ? "inotify wd:1 ino:" + inode.toString(16) + " sdev:12300045 mask:2 ignored_mask:0\n"
          : readFileSync(path, ...args);
      }
    `;
      const { Worker } = workerThreads;
      const mock = t.mock.method(
        workerThreads,
        "Worker",
        class extends Worker {
          constructor(source, options) {
            super(foreignWatch + source, options);
          }
        },
      );
      syncBuiltinESMExports();
      try {
        assert.deepEqual(await publish(content, first.contentHash), first);
      } finally {
        mock.mock.restore();
        syncBuiltinESMExports();
      }
    },
  );
  beforeRead = null;
  let substitute = await custody(path);
  const atLastLookup = (observe) => ({
    assertCurrent: () => {
      let lookups = 0;
      targetLookup = (lookup) => {
        if (++lookups !== 3) return lookup();
        targetLookup = null;
        return observe(lookup);
      };
    },
  });
  const afterLastLookup = (change) =>
    atLastLookup(async (lookup) => {
      const stat = await lookup();
      await change();
      return stat;
    });
  // Model delayed notification from an entry change after the final lookup.
  // Release the native rename events only when the closing directory read
  // waits for the modeled writer. The round trip leaves sampled stats equal.
  await assert.rejects(
    publish(
      content,
      first.contentHash,
      afterLastLookup(() => {
        targetLookup = () => {
          throw Object.assign(
            new Error("Destination moved before notification"),
            { code: "ENOENT" },
          );
        };
        beforeClosingRead = async () => {
          await rename(path, temporaryPath);
          await rename(temporaryPath, path);
          targetLookup = null;
        };
      }),
    ),
    { code: "ERR_WORKSPACE_REPORT_CHANGED" },
  );
  assert.equal(await readFile(path, "utf8"), content);
  assert.deepEqual(await custody(path), substitute);
  await assert.rejects(filesystem.stat(temporaryPath), { code: "ENOENT" });
  await t.test("rechecks drift on closing directory failures", async () => {
    const mode = (await filesystem.stat(projectPath)).mode & 0o777;
    for (const operation of ["open", "read"]) {
      for (const drift of [false, true]) {
        const failure = Object.assign(new Error("Synthetic directory error"), {
          code: "EACCES",
        });
        const fail = async () => {
          if (drift) await filesystem.chmod(projectPath, mode ^ 0o400);
          throw failure;
        };
        if (operation === "open") beforeClosingOpen = fail;
        else beforeClosingRead = fail;
        try {
          await assert.rejects(
            publish(content, first.contentHash),
            drift
              ? { code: "ERR_WORKSPACE_DRIFT" }
              : (error) =>
                  error.code === "ERR_WORKSPACE_INSPECTION" &&
                  error.cause === failure,
          );
        } finally {
          if (drift) await filesystem.chmod(projectPath, mode);
        }
      }
    }
  });
  await assert.rejects(
    publish(
      content,
      first.contentHash,
      afterLastLookup(async () => {
        await writeFile(temporaryPath, content);
        await rm(temporaryPath);
      }),
    ),
    conflict,
  );
  await assert.rejects(filesystem.stat(temporaryPath), { code: "ENOENT" });
  frozen = false;
  const lastMove = join(root, "last-move");
  await assert.rejects(
    publish(
      content,
      first.contentHash,
      afterLastLookup(() => rename(projectPath, lastMove)),
    ),
    { code: "ERR_WORKSPACE_DRIFT" },
  );
  await rename(lastMove, projectPath);
  assert.deepEqual(await custody(path), substitute);
  for (const drift of [false, true]) {
    await assert.rejects(
      publish(
        content,
        first.contentHash,
        atLastLookup(async (lookup) => {
          await rename(path, movedAside);
          if (drift) await rename(projectPath, lastMove);
          return lookup();
        }),
      ),
      drift
        ? { code: "ERR_WORKSPACE_DRIFT" }
        : (error) =>
            error.code === "ERR_WORKSPACE_REPORT_CHANGED" &&
            error.cause.code === "ENOENT",
    );
    if (drift) await rename(lastMove, projectPath);
    await rename(movedAside, path);
    assert.deepEqual(await custody(path), substitute);
  }
  // Unlink after the final open, before the first descriptor stat sees it.
  for (const drift of [false, true]) {
    await assert.rejects(
      publish(content, first.contentHash, {
        assertCurrent: () => {
          let reads = 0;
          afterTargetOpen = async () => {
            if (++reads !== 3) return;
            afterTargetOpen = null;
            await filesystem.unlink(path);
            if (drift) await rename(projectPath, lastMove);
          };
        },
      }),
      drift
        ? { code: "ERR_WORKSPACE_DRIFT" }
        : (error) =>
            error.code === "ERR_WORKSPACE_REPORT_CHANGED" &&
            error.cause.code === "ENOENT",
    );
    if (drift) await rename(lastMove, projectPath);
    await assert.rejects(filesystem.stat(path), { code: "ENOENT" });
    await writeFile(path, content);
    substitute = await custody(path);
  }
  await assert.rejects(
    publish(content, first.contentHash, {
      assertCurrent: () => {
        let reads = 0;
        beforeTargetRead = () => {
          if (++reads !== 3) return;
          beforeTargetRead = null;
          descriptorFailureAt = "/audit.md";
        };
      },
    }),
    (error) =>
      error.code === "ERR_WORKSPACE_INSPECTION" &&
      error.cause.code === "ENOENT",
  );
  descriptorFailureAt = null;
  await assert.rejects(
    publish(
      content,
      first.contentHash,
      afterLastLookup(async () => {
        await writeFile(replacement, content);
        await rename(replacement, path);
      }),
    ),
    { code: "ERR_WORKSPACE_REPORT_CHANGED" },
  );
  assert.equal(await readFile(path, "utf8"), content);
  assert.notDeepEqual(await custody(path), substitute);
  substitute = await custody(path);
  await assert.rejects(filesystem.stat(temporaryPath), { code: "ENOENT" });
  assert.notDeepEqual(substitute, prepared.identity);
  await assert.rejects(
    publish(content, null, { temporary: prepared }),
    conflict,
  );
  assert.deepEqual(await custody(path), substitute);

  const next = "New report\n";
  const preserved = async (bytes) => {
    assert.equal(await readFile(path, "utf8"), content);
    assert.deepEqual(await custody(path), substitute);
    if (bytes === null)
      await assert.rejects(filesystem.stat(temporaryPath), { code: "ENOENT" });
    else assert.equal(await readFile(temporaryPath, "utf8"), bytes);
  };
  await writeFile(temporaryPath, next);
  await assert.rejects(publish(next, first.contentHash), conflict);
  const foreign = await custody(temporaryPath);
  // A descriptor ENOENT while the path still holds the file is not custody.
  // Arm it after the service snapshot, before the publisher reads the file.
  await assert.rejects(
    publish(next, first.contentHash, {
      assertCurrent: () => {
        descriptorFailureAt = "/.audit.md.tmp";
      },
    }),
    (error) =>
      error.code === "ERR_WORKSPACE_INSPECTION" &&
      error.cause.code === "ENOENT",
  );
  descriptorFailureAt = null;
  await assert.rejects(
    publish("Other report\n", first.contentHash, {
      temporary: { phase: "prepared", identity: foreign },
    }),
    conflict,
  );
  await preserved(next);
  assert.deepEqual(await custody(temporaryPath), foreign);
  // A temporary unlinked after open but before its first descriptor stat.
  await assert.rejects(
    publish(next, first.contentHash, {
      assertCurrent: () => {
        afterOpen = async () => {
          afterOpen = null;
          await filesystem.unlink(temporaryPath);
        };
      },
    }),
    (error) => error.code === conflict.code && error.cause.code === "ENOENT",
  );
  await preserved(null);
  // Parent drift takes precedence over a temporary unlinked during its read.
  await writeFile(temporaryPath, next);
  const movedProject = join(root, "moved-project");
  await assert.rejects(
    publish(next, first.contentHash, {
      assertCurrent: () => {
        duringRead = async () => {
          await filesystem.unlink(temporaryPath);
          await rename(projectPath, movedProject);
          await mkdir(projectPath);
        };
      },
    }),
    { code: "ERR_WORKSPACE_DRIFT" },
  );
  await rm(projectPath, { recursive: true });
  await rename(movedProject, projectPath);
  await preserved(null);
  // Parent drift takes precedence over an owned temporary unlinked after its
  // writable reopen but before the first descriptor stat.
  await writeFile(temporaryPath, next);
  const writing = { phase: "writing", identity: await custody(temporaryPath) };
  await assert.rejects(
    publish(next, first.contentHash, {
      temporary: writing,
      assertCurrent: () => {
        afterReopen = async () => {
          afterReopen = null;
          await filesystem.unlink(temporaryPath);
          await rename(projectPath, movedProject);
          await mkdir(projectPath);
        };
      },
    }),
    { code: "ERR_WORKSPACE_DRIFT" },
  );
  await rm(projectPath, { recursive: true });
  await rename(movedProject, projectPath);
  await preserved(null);

  let collision;
  beforeCreate = async () => {
    await writeFile(temporaryPath, next);
    collision = await custody(temporaryPath);
  };
  await assert.rejects(publish(next, first.contentHash), conflict);
  await preserved(next);
  assert.deepEqual(await custody(temporaryPath), collision);
  await rm(temporaryPath);
  // An interruption before ownership is journaled leaves an unowned allocation.
  beforeCreate = null;
  let recorded;
  await assert.rejects(
    publish(next, first.contentHash, {
      async recordTemporary(temporary) {
        recorded = temporary;
        throw new Error("Custody journal interrupted");
      },
    }),
    { code: "ERR_WORKSPACE_INSPECTION" },
  );
  await preserved("");
  assert.deepEqual(await custody(temporaryPath), recorded.identity);
  await rm(temporaryPath);
  const aside = join(projectPath, "aside.tmp");
  await assert.rejects(
    publish(next, first.contentHash, {
      async recordTemporary(temporary) {
        recorded = temporary;
        await rename(temporaryPath, aside);
      },
    }),
    conflict,
  );
  await preserved(null);
  assert.deepEqual(await custody(aside), recorded.identity);
  assert.equal(await readFile(aside, "utf8"), "");
  beforeCreate = () => {
    throw Object.assign(new Error("Synthetic device failure"), { code: "EIO" });
  };
  await assert.rejects(
    publish(next, first.contentHash),
    (error) =>
      error.code === "ERR_WORKSPACE_INSPECTION" && error.cause.code === "EIO",
  );
  await preserved(null);
  assert.deepEqual(effects, ["rename"]);

  beforeCreate = null;
  await writeFile(path, "User edit\n");
  await assert.rejects(publish(next, first.contentHash), {
    code: "ERR_WORKSPACE_REPORT_CHANGED",
  });
  await rm(path);
  const outside = join(root, "outside.md");
  await writeFile(outside, "Unrelated content\n");
  await symlink(outside, path);
  await assert.rejects(inspect());
  assert.equal(await readFile(outside, "utf8"), "Unrelated content\n");
});

test("report readback observer ignores adverse parent runtime options", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "audit-artifact-observer-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const projectPath = join(root, "project");
  await mkdir(projectPath);
  const content = "# Audit report\n";
  await writeFile(join(projectPath, "audit.md"), content);
  // Any preload reaching the observer thread could share its native queue.
  const preload = join(root, "preload.cjs");
  await writeFile(
    preload,
    'if (!require("node:worker_threads").isMainThread)\n' +
      '  throw new Error("Preload reached the readback observer.");\n',
  );
  const script = `
    const [, service, projectPath, stateRoot, expectedHash] = process.argv;
    const { createWorkspaceService } = await import(service);
    const workspace = createWorkspaceService();
    const path = projectPath + "/audit.md";
    const temporaryPath = projectPath + "/.audit.md.tmp";
    const inspection = await workspace.inspect({
      workspacePath: projectPath,
      artifactPaths: [path, temporaryPath],
      stateRoot,
    });
    const receipt = await workspace.reportArtifact(
      { inspection, path, temporaryPath, content: ${JSON.stringify(content)}, expectedHash },
      { recordTemporary: () => { throw new Error("Unexpected custody write"); } },
    );
    process.stdout.write(JSON.stringify(receipt));
  `;
  const contentHash = createHash("sha256").update(content).digest("hex");
  const { stdout } = await execute(
    process.execPath,
    [
      "--input-type=module",
      "--require",
      preload,
      "--eval",
      script,
      new URL("../src/workspace/index.js", import.meta.url).href,
      projectPath,
      join(root, "state"),
      contentHash,
    ],
    {
      env: {
        ...process.env,
        NODE_OPTIONS: `--require ${JSON.stringify(preload)}`,
      },
    },
  );
  assert.deepEqual(JSON.parse(stdout), {
    path: join(projectPath, "audit.md"),
    contentHash,
  });
});

test("interrupted report writes resume accepted discovery and preserve unproven custody", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "audit-write-recovery-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  for (const variant of [
    "owned partial write",
    "substituted temporary",
    "missing writing custody",
    "prepared destination substitute",
  ]) {
    await t.test(variant, async () => {
      const projectPath = join(root, variant.replaceAll(" ", "-"));
      await mkdir(projectPath);
      const path = join(projectPath, "audit.md");
      const temporaryPath = join(projectPath, ".audit.md.tmp");
      const f = fixture([READY, complete()]);
      f.run().taskPath = projectPath;
      const prepared = variant === "prepared destination substitute";
      let writes = 0;
      let renames = 0;
      const workspace = createWorkspaceService({
        fileSystem: {
          ...filesystem,
          async rename(...args) {
            if (prepared && ++renames === 2)
              throw new Error("Interrupted report rename");
            return filesystem.rename(...args);
          },
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
                if (!prepared && ++writes === 2) {
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
        prepared ? "prepared" : "writing",
      );
      assert.equal(saved.pipelineState.publication.pending.complete, true);
      const partial = await readFile(temporaryPath, "utf8");
      const original = await readFile(path, "utf8");
      assert.match(original, /In progress/u);
      if (variant === "substituted temporary") {
        const replacement = join(projectPath, "replacement.md");
        await writeFile(replacement, partial);
        await rename(replacement, temporaryPath);
      } else if (variant === "missing writing custody") {
        await rm(temporaryPath);
      } else if (prepared) {
        const replacement = join(projectPath, "replacement.md");
        await writeFile(replacement, partial);
        await rename(replacement, path);
      }
      const destination = await readFile(path, "utf8");
      const result = await f.executePublic();
      assert.equal(f.calls.length, 2, "Accepted model work must not replay");
      if (variant === "owned partial write") {
        assert.equal(result.pipelineState.workflowState, "DONE");
        assert.equal(result.pipelineState.publication.temporary, null);
        assert.match(await readFile(path, "utf8"), /\*\*Status:\*\* Complete/u);
        await assert.rejects(filesystem.stat(temporaryPath), {
          code: "ENOENT",
        });
        return;
      }
      assert.equal(result.pause.reason, "audit_report_temporary_conflict");
      assert.equal(result.pause.resumeState, saved.pipelineState.workflowState);
      assert.deepEqual(
        result.pipelineState.publication,
        saved.pipelineState.publication,
      );
      assert.equal(await readFile(path, "utf8"), destination);
      if (variant === "missing writing custody")
        await assert.rejects(filesystem.stat(temporaryPath), {
          code: "ENOENT",
        });
      else assert.equal(await readFile(temporaryPath, "utf8"), partial);
      assert.deepEqual(auditPipeline.projections.pause(result).nextActions, []);
      assert.throws(
        () => auditPipeline.validateResumeAction(result, null),
        /temporary custody cannot be verified/u,
      );
    });
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
