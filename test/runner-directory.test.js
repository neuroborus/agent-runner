import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import * as filesystem from "node:fs/promises";
import {
  mkdir,
  mkdtemp,
  lstat,
  readFile,
  readlink,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { hostname, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

import { planAuthoringPipeline } from "@agent-runner/plan-authoring";

import { createCodexAdapter } from "../src/agents/codex/index.js";
import {
  CLAUDE_STORAGE_IDENTITY,
  recoverClaudeStorage,
} from "../src/agents/claude/index.js";
import { createRunner } from "../src/runner/index.js";
import { publishOutputDirectory } from "../src/runner/workspace.js";
import { createMcpControlPlane } from "../src/mcp/index.js";
import { createRunStore } from "../src/state/index.js";
import { normalizeRunState } from "../src/state/validation.js";
import { createWorkspaceService } from "../src/workspace/index.js";
import {
  createTrustedValidationService,
  createTrustedValidationSnapshot,
} from "../src/trusted-validation/index.js";
import { createClarificationService } from "../src/clarifications/index.js";
import { parseRunnerConfiguration } from "../src/config/index.js";
import { createGitService } from "../src/git/index.js";

const digest = (value) =>
  createHash("sha256").update(JSON.stringify(value)).digest("hex");
const noGit = new Proxy(
  {},
  {
    get() {
      throw new Error("Git must not be invoked.");
    },
  },
);

async function fixture(t, { contained = false, storeOptions = {} } = {}) {
  const root = await mkdtemp(join(tmpdir(), "runner-directory-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const repository = join(root, "project");
  const projectPath = contained ? join(repository, "content") : repository;
  const taskPath = join(root, "task");
  const stateRoot = join(root, "state");
  await mkdir(projectPath, { recursive: true });
  await mkdir(taskPath);
  await writeFile(join(taskPath, "task.md"), "Produce the agreed report.\n");
  await writeFile(join(projectPath, "input.txt"), "frozen input\n");
  const probes = [];
  const calls = [];
  const adapter = {
    async probe(options) {
      probes.push(options);
      const access = options.access;
      return {
        version: "fixture-1",
        structuredOutput: true,
        declaredWorkspace: true,
        readOnly: access === "read-only",
        workspaceWrite: access === "workspace-write",
        autonomousWrite: access === "workspace-write",
        gitMetadataWriteBlocked: true,
        remoteWriteBlocked: true,
        nativeSessionContinuation: true,
        policyReceipt: {
          schemaVersion: 1,
          fingerprint: digest(options),
          supportedAccess: [access],
        },
      };
    },
    async run(request) {
      calls.push(request);
      return { structured: {}, sessionId: "opaque-child" };
    },
  };
  const store = createRunStore({ stateRoot, ...storeOptions });
  function runner(
    workflow,
    { selection, loadConfiguration, assertOutputPreparation, ...options } = {},
  ) {
    const pipeline = {
      ...planAuthoringPipeline,
      stateVersion: 1,
      migrations: {},
      workspace: {
        kind: "directory",
        lease: "exclusive",
        inputPaths: ["input.txt"],
        outputPaths: ["out"],
        artifactPaths: [join(taskPath, "clarifications.md")],
      },
      resolveWorkspace: selection,
      assertOutputPreparation,
      resolveTaskInputs: undefined,
      roleAccess: { planner: ["read-only", "workspace-write"] },
      projections: { status: () => ({}), pause: () => null },
      validateResumeAction() {},
      workflow: {
        createState: ({ settings }) => ({
          workflowState: "CLARIFY",
          settings,
          repositoryBaseline: null,
        }),
        validateRun() {},
        run: workflow,
      },
    };
    return createRunner({
      getPipeline: (id) => (id === pipeline.id ? pipeline : undefined),
      adapters: { codex: adapter },
      git: noGit,
      runStore: store,
      clarifications: createClarificationService({ interactive: false }),
      loadConfiguration:
        loadConfiguration ??
        (async () =>
          parseRunnerConfiguration(
            JSON.stringify({
              schemaVersion: 1,
              defaultBackend: "codex",
              pipelines: { "plan-authoring": { mode: "lazy" } },
            }),
          )),
      ...options,
    });
  }
  return {
    root,
    repository,
    projectPath,
    taskPath,
    stateRoot,
    store,
    adapter,
    calls,
    probes,
    runner,
    input: { pipelineId: "plan-authoring", projectPath, taskPath },
  };
}

async function turn(runtime, run, access, phase) {
  const repository = await runtime.workspace.snapshot();
  await runtime.inactivity.before({
    role: "planner",
    checkpoint: phase,
    repository,
  });
  await runtime.startAgentTurn({ role: "planner", phase });
  await runtime.adapters.planner.run({
    cwd: run.projectPath,
    access,
    prompt: "Inspect the declared workspace.",
    schema: {
      type: "object",
      properties: {},
      required: [],
      additionalProperties: false,
    },
  });
  await runtime.finishAgentTurn({ role: "planner", phase });
}

test("directory creation rejects unsafe task inputs before reading or probing", async (t) => {
  for (const kind of ["symlink", "directory", "special", "missing"]) {
    await t.test(kind, async (t) => {
      const f = await fixture(t);
      const path = join(f.taskPath, "task.md");
      if (kind !== "special") await rm(path);
      if (kind === "symlink")
        await symlink(join(f.root, "undeclared.md"), path);
      if (kind === "directory") await mkdir(path);
      let openedInput = false;
      const workspace = createWorkspaceService({
        fileSystem: {
          ...filesystem,
          async lstat(candidate, options) {
            const stat = await lstat(candidate, options);
            if (kind === "special" && candidate === path)
              return {
                isFile: () => false,
                isDirectory: () => false,
              };
            return stat;
          },
          async open(candidate, flags) {
            if (
              candidate.endsWith("/task.md") &&
              !(flags & constants.O_DIRECTORY)
            )
              openedInput = true;
            return filesystem.open(candidate, flags);
          },
        },
      });
      const runner = f.runner(() => assert.fail("No workflow expected."), {
        workspace,
      });
      await assert.rejects(runner.create(f.input), {
        code: "ERR_WORKSPACE_PATH",
      });
      assert.equal(openedInput, false);
      assert.equal(f.probes.length, 0);
      await assert.rejects(lstat(f.stateRoot), { code: "ENOENT" });
    });
  }
});

test("near-limit directory declarations preserve compact storage exclusions at the adapter boundary", async (t) => {
  const f = await fixture(t);
  const inputPaths = Array.from({ length: 253 }, (_, index) =>
    join(f.projectPath, `input-${index}.txt`),
  );
  const artifactPaths = Array.from({ length: 128 }, (_, index) =>
    join(f.root, `artifact-${index}`),
  );
  const infrastructurePaths = Array.from({ length: 128 }, (_, index) =>
    join(f.root, `infrastructure-${index}`),
  );
  // This case owns path forwarding and request limits. Adjacent real-service
  // cases own filesystem confinement, identity drift and recovery.
  const workspace = {
    ...createWorkspaceService(),
    async inspect({ workspacePath, taskPath, stateRoot, ...declarations }) {
      return {
        schemaVersion: 1,
        workspacePath,
        taskPath,
        stateRoot,
        ...Object.fromEntries(
          [
            "inputPaths",
            "sourcePaths",
            "outputPaths",
            "configurationPaths",
            "artifactPaths",
            "infrastructurePaths",
          ].map((name) => [
            name,
            (declarations[name] ?? [])
              .map((path) => resolve(workspacePath, path))
              .sort(),
          ]),
        ),
        controlPaths: [],
        bindings: [],
      };
    },
    async exclusionPath({ workspacePath }) {
      return workspacePath;
    },
    async snapshot({ inspection }) {
      return {
        schemaVersion: 1,
        workspacePath: inspection.workspacePath,
        outputPaths: inspection.outputPaths,
        entries: [],
        contentFingerprint: digest([]),
        identityFingerprint: digest([]),
      };
    },
  };
  let executions = 0;
  const adapter = createCodexAdapter({
    async execute() {
      executions += 1;
      assert.fail("Request-boundary coverage must not invoke a provider.");
    },
  });
  f.adapter.run = async (request) => {
    f.calls.push(request);
    assert.equal(
      request.workspacePolicy.inputPaths.length,
      inputPaths.length + 1,
    );
    assert.equal(request.storageForbiddenPaths.length, 259);
    assert.deepEqual(
      new Set(request.storageForbiddenPaths),
      new Set([
        f.projectPath,
        f.taskPath,
        f.stateRoot,
        ...artifactPaths,
        ...infrastructurePaths,
      ]),
    );
    // This access rejection follows complete request normalization and precedes
    // filesystem/provider work. An exclusion-count rejection cannot satisfy it.
    await assert.rejects(
      adapter.run({
        ...request,
        authorizationId: "11111111-1111-4111-8111-111111111111",
      }),
      {
        code: "ERR_INVALID_CODEX_OPTIONS",
        message: "Commit constraints require local-commit access.",
      },
    );
    return { structured: {}, sessionId: "opaque-child" };
  };
  const result = await f
    .runner(
      async ({ run, runtime }) => {
        await turn(runtime, run, "read-only", "inspect");
        return runtime.transition({
          pipelineState: { ...run.pipelineState, workflowState: "COMPLETED" },
        });
      },
      {
        workspace,
        selection: () => ({
          kind: "directory",
          lease: "exclusive",
          inputPaths,
          outputPaths: ["out"],
          artifactPaths,
          infrastructurePaths,
        }),
      },
    )
    .run(f.input);
  assert.equal(result.run.pause, null);
  assert.equal(f.calls.length, 1);
  assert.equal(executions, 0);
});

test("directory lifecycle reconstructs interrupted output work without Git or configuration reload", async (t) => {
  const f = await fixture(t);
  const output = join(f.projectPath, "out", "report.txt");
  f.adapter.run = async (request) => {
    f.calls.push(request);
    assert.equal(request.workspacePolicy.kind, "directory");
    assert.deepEqual(request.workspacePolicy.outputPaths, [
      join(f.projectPath, "out"),
    ]);
    if (request.access === "workspace-write") {
      await mkdir(join(f.projectPath, "out"));
      await writeFile(output, "accepted partial result\n");
    }
    return { structured: {}, sessionId: "opaque-child" };
  };
  let runId;
  await assert.rejects(
    f
      .runner(async ({ run, runtime }) => {
        runId = run.runId;
        assert.equal(runtime.git, undefined);
        assert.equal(runtime.preservation, undefined);
        const inputs = await runtime.readInputs({ taskPath: run.taskPath });
        assert.equal(inputs.task.content, "Produce the agreed report.\n");
        assert.equal(inputs.context, null);
        assert.equal(
          (await runtime.adapters.planner.probe()).nativeSessionContinuation,
          true,
        );
        await runtime.clarifications.ensureTranscript({
          artifactRoot: f.taskPath,
          transcriptPath: join(f.taskPath, "clarifications.md"),
        });
        await turn(runtime, run, "read-only", "clarify");
        const repository = await runtime.workspace.snapshot();
        await runtime.inactivity.before({
          role: "planner",
          checkpoint: "implement",
          repository,
        });
        await runtime.startAgentTurn({ role: "planner", phase: "implement" });
        await runtime.adapters.planner.run({
          cwd: run.projectPath,
          access: "workspace-write",
          prompt: "Produce the report.",
          schema: { type: "object" },
        });
        throw new Error("interrupted after response");
      })
      .run(f.input),
    /interrupted after response/u,
  );
  const before = await f.store.loadRun(runId);
  assert.equal(before.activeTurn.phase, "implement");
  assert.deepEqual(before.workspace.retrievalPermissions, []);
  assert.deepEqual(before.providerPolicies.planner.supportedAccess, [
    "read-only",
    "workspace-write",
  ]);
  const resumed = await f
    .runner(
      async ({ run, runtime }) => {
        assert.equal(
          await readFile(output, "utf8"),
          "accepted partial result\n",
        );
        await runtime.finishAgentTurn(run.activeTurn);
        await turn(runtime, run, "read-only", "confirm");
        return runtime.transition({
          pipelineState: { ...run.pipelineState, workflowState: "COMPLETED" },
        });
      },
      {
        selection() {
          throw new Error("Resume must use the frozen selection.");
        },
        loadConfiguration() {
          throw new Error("Resume must use frozen configuration.");
        },
      },
    )
    .resume({ runId });
  assert.equal(resumed.run.pipelineState.workflowState, "COMPLETED");
  assert.deepEqual(resumed.run.workspace, before.workspace);
  assert.equal(
    f.calls.filter(({ access }) => access === "workspace-write").length,
    1,
  );
  assert.deepEqual(
    f.probes.map(({ access }) => access),
    [
      "read-only",
      "workspace-write",
      "read-only",
      "workspace-write",
      "read-only",
      "workspace-write",
    ],
  );
});

test("directory recovery rejects replaced inputs, controls and substituted policy authority", async (t) => {
  const f = await fixture(t);
  const runner = f.runner(async () => {
    throw new Error("No provider work expected.");
  });
  const { run } = await runner.create(f.input);
  const substitute = join(f.projectPath, "replacement.txt");
  await writeFile(substitute, "frozen input\n");
  await rename(substitute, join(f.projectPath, "input.txt"));
  const paused = (await runner.resume({ runId: run.runId })).run;
  assert.equal(paused.pause.reason, "workspace_changed");
  assert.equal(paused.pause.code, "ERR_WORKSPACE_DRIFT");
  assert.equal(f.calls.length, 0);
  for (const mutate of [
    (copy) => {
      copy.workspace.policy.extraRead = f.root;
    },
    (copy) => {
      copy.workspace.retrievalPermissions = ["https://example.test/source"];
    },
    (copy) => {
      copy.schemaVersion = 23;
      copy.runtimeCompatibility.runStateVersion = 23;
    },
  ]) {
    const copy = structuredClone(run);
    mutate(copy);
    assert.throws(() => normalizeRunState(copy), /workspace|Directory/u);
  }
  const lease = await f.store.acquireRunLease(run.runId);
  try {
    await assert.rejects(
      f.store.transitionRun(lease, {
        workspace: { ...run.workspace, lease: "none" },
      }),
      /workspace/u,
    );
  } finally {
    await lease.release();
  }
});

test("directory recovery freezes project content when the task root equals or contains the workspace", async (t) => {
  for (const placement of ["coincident", "ancestor"]) {
    await t.test(placement, async (t) => {
      const f = await fixture(t);
      const projectPath =
        placement === "coincident" ? f.taskPath : join(f.taskPath, "project");
      await mkdir(projectPath, { recursive: true });
      const sourcePath = join(projectPath, "source.js");
      await writeFile(sourcePath, "export const value = 1;\n");
      const transcriptPath = join(f.taskPath, "clarifications.md");
      const runner = f.runner(
        async ({ run, runtime }) => {
          await runtime.clarifications.ensureTranscript({
            artifactRoot: f.taskPath,
            transcriptPath,
          });
          await runtime.workspace.snapshot();
          return run;
        },
        {
          selection: () => ({
            kind: "directory",
            lease: "exclusive",
            artifactPaths: [transcriptPath],
          }),
        },
      );
      const { run } = await runner.run({ ...f.input, projectPath });
      assert.equal(run.pause, null);
      const resumed = await runner.resume({ runId: run.runId });
      assert.equal(resumed.run.pause, null);

      await writeFile(sourcePath, "export const value = 2;\n");
      const probes = f.probes.length;
      const paused = await runner.resume({ runId: run.runId });
      assert.equal(paused.run.pause?.reason, "workspace_changed");
      assert.equal(f.probes.length, probes);
      assert.equal(f.calls.length, 0);
    });
  }
});

test("directory provider turns reject read-only and undeclared mutations including failure paths", async (t) => {
  for (const access of ["read-only", "workspace-write"]) {
    await t.test(access, async (t) => {
      const f = await fixture(t);
      f.adapter.run = async () => {
        await writeFile(join(f.projectPath, "unrelated.txt"), "unauthorized\n");
        throw new Error("provider failed");
      };
      await assert.rejects(
        f
          .runner(async ({ run, runtime }) =>
            turn(runtime, run, access, "inspect"),
          )
          .run(f.input),
        { code: "ERR_WORKSPACE_DRIFT" },
      );
      assert.equal(
        await readFile(join(f.projectPath, "unrelated.txt"), "utf8"),
        "unauthorized\n",
      );
    });
  }
});

test("directory workspace inside a repository contends on the Git workflow's canonical lease", async (t) => {
  const f = await fixture(t, { contained: true });
  // A filesystem marker is sufficient; Git itself remains unavailable to the runner.
  await mkdir(join(f.repository, ".git"));
  await mkdir(join(f.repository, ".git", "objects"));
  await mkdir(join(f.repository, ".git", "refs"));
  await writeFile(join(f.repository, ".git", "HEAD"), "ref: refs/heads/main\n");
  const otherRunId = "11111111-1111-4111-8111-111111111111";
  const held = await f.store.acquireWorktreeLease(f.repository, otherRunId);
  const runner = f.runner(async ({ run, runtime }) =>
    runtime.transition({
      pipelineState: { ...run.pipelineState, workflowState: "COMPLETED" },
    }),
  );
  const { run } = await runner.create(f.input);
  assert.equal(run.projectPath, f.projectPath);
  assert.equal(run.workspace.leasePath, f.repository);
  await assert.rejects(runner.resume({ runId: run.runId }), {
    code: "ERR_WORKTREE_LEASED",
  });
  await held.release();
  assert.equal(
    (await runner.resume({ runId: run.runId })).run.pipelineState.workflowState,
    "COMPLETED",
  );
});

test("directory creation rejects state inside its enclosing repository before probing or writing", async (t) => {
  for (const discovery of ["initial", "configuration"]) {
    await t.test(discovery, async (t) => {
      const f = await fixture(t, { contained: true });
      async function createControls() {
        await mkdir(join(f.repository, ".git"));
        await mkdir(join(f.repository, ".git", "objects"));
        await mkdir(join(f.repository, ".git", "refs"));
        await writeFile(
          join(f.repository, ".git", "HEAD"),
          "ref: refs/heads/main\n",
        );
      }
      if (discovery === "initial") await createControls();
      const stateRoot = join(f.repository, "run-state");
      const runner = f.runner(
        () => assert.fail("Unsafe state must prevent execution."),
        {
          runStore: createRunStore({ stateRoot }),
          async loadConfiguration() {
            assert.equal(discovery, "configuration");
            await createControls();
            return parseRunnerConfiguration(
              JSON.stringify({ schemaVersion: 1, defaultBackend: "codex" }),
            );
          },
        },
      );

      await assert.rejects(runner.create(f.input), {
        code: "ERR_UNSAFE_STATE_ROOT",
      });
      assert.equal(f.probes.length, 0);
      assert.equal(f.calls.length, 0);
      await assert.rejects(lstat(stateRoot), { code: "ENOENT" });
    });
  }
});

test("confined Git control aliases retain exact-key exclusion against a legacy root lease", async (t) => {
  for (const alias of ["HEAD", "objects", "refs"]) {
    await t.test(alias, async (t) => {
      const f = await fixture(t, { contained: true });
      const metadata = join(f.repository, ".git");
      await mkdir(metadata);
      for (const name of ["objects", "refs"]) {
        const target = name === alias ? `${name}-data` : name;
        await mkdir(join(metadata, target));
        if (name === alias) await symlink(target, join(metadata, name));
      }
      await mkdir(join(metadata, "refs", "heads"));
      await writeFile(
        join(metadata, "refs", "heads", "main"),
        `${"a".repeat(40)}\n`,
      );
      if (alias === "HEAD")
        await symlink("refs/heads/main", join(metadata, "HEAD"));
      else await writeFile(join(metadata, "HEAD"), "ref: refs/heads/main\n");

      // Pre-scope leases have only their canonical key and owner record.
      const key = createHash("sha256").update(f.repository).digest("hex");
      const leaseDirectory = join(f.stateRoot, "worktrees", key);
      await mkdir(leaseDirectory, { recursive: true });
      await writeFile(
        join(leaseDirectory, ".lease"),
        JSON.stringify({
          runId: "11111111-1111-4111-8111-111111111111",
          token: "22222222-2222-4222-8222-222222222222",
          pid: process.pid,
          hostname: hostname(),
          acquiredAt: "2026-01-01T00:00:00.000Z",
        }),
      );
      await assert.rejects(readFile(join(leaseDirectory, "scope.json")), {
        code: "ENOENT",
      });
      const runner = f.runner(() =>
        assert.fail(
          "A held root lease must prevent directory workflow execution.",
        ),
      );
      const { run } = await runner.create(f.input);
      assert.equal(run.workspace.leasePath, f.repository);
      await assert.rejects(runner.resume({ runId: run.runId }), {
        code: "ERR_WORKTREE_LEASED",
      });
      assert.equal(f.calls.length, 0);
    });
  }
});

test("parent and child directory lifecycles cannot own the same declared output concurrently", async (t) => {
  const f = await fixture(t);
  const child = join(f.projectPath, "child");
  await mkdir(child);
  const output = join(child, "result.txt");
  const runner = f.runner(
    async ({ run, runtime }) =>
      runtime.transition({
        pipelineState: { ...run.pipelineState, workflowState: "COMPLETED" },
      }),
    {
      selection: () => ({
        kind: "directory",
        lease: "exclusive",
        outputPaths: [output],
      }),
    },
  );
  const parentRun = (await runner.create(f.input)).run;
  const childRun = (await runner.create({ ...f.input, projectPath: child }))
    .run;
  const held = await f.store.acquireWorktreeLease(
    f.projectPath,
    parentRun.runId,
  );
  try {
    assert.equal(
      await f.store.worktreeLeaseOwner(child, childRun.runId),
      parentRun.runId,
    );
    await assert.rejects(runner.resume({ runId: childRun.runId }), {
      code: "ERR_WORKTREE_LEASED",
    });
    assert.equal(f.calls.length, 0);
  } finally {
    await held.release();
  }
  assert.equal(
    (await runner.resume({ runId: childRun.runId })).run.pipelineState
      .workflowState,
    "COMPLETED",
  );

  // Separate service instances share admission; simultaneous attempts cannot
  // both pass an overlap check before either publishes its lease.
  const other = createRunStore({ stateRoot: f.stateRoot });
  const admitted = await Promise.allSettled([
    f.store.acquireWorktreeLease(f.projectPath, parentRun.runId),
    other.acquireWorktreeLease(child, childRun.runId),
  ]);
  try {
    assert.equal(
      admitted.filter(({ status }) => status === "fulfilled").length,
      1,
    );
    assert.equal(
      admitted.find(({ status }) => status === "rejected").reason.code,
      "ERR_WORKTREE_LEASED",
    );
  } finally {
    for (const result of admitted)
      if (result.status === "fulfilled") await result.value.release();
  }

  const bootId = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
  const oldStore = createRunStore({
    stateRoot: f.stateRoot,
    processId: 100,
    processIsAlive: (pid) => pid === 100,
    processIdentity: (pid) => ({ bootId, startTicks: String(pid) }),
  });
  await oldStore.acquireWorktreeLease(f.projectPath, parentRun.runId);
  const replacement = createRunStore({
    stateRoot: f.stateRoot,
    processId: 200,
    processIsAlive: (pid) => pid === 200,
    processIdentity: (pid) => ({ bootId, startTicks: String(pid) }),
  });
  // Dead reservations remain barriers to a different scope until ordinary
  // same-key recovery reconciles and releases them.
  await assert.rejects(
    replacement.acquireWorktreeLease(child, childRun.runId),
    {
      code: "ERR_WORKTREE_LEASED",
    },
  );
  const recovered = await replacement.acquireWorktreeLease(
    f.projectPath,
    parentRun.runId,
  );
  await recovered.release();
  const releasedChild = await replacement.acquireWorktreeLease(
    child,
    childRun.runId,
  );
  await releasedChild.release();
});

test("directory outputs cannot enter nested worktrees with a different exclusion key", async (t) => {
  for (const layout of ["ordinary", "linked"]) {
    await t.test(layout, async (t) => {
      const f = await fixture(t);
      const nested = join(f.projectPath, "nested");
      await mkdir(join(nested, "reports"), { recursive: true });
      await writeFile(join(nested, "result.txt"), "keep\n");
      const metadata =
        layout === "ordinary" ? join(nested, ".git") : join(f.root, "metadata");
      await mkdir(join(metadata, "objects"), { recursive: true });
      await mkdir(join(metadata, "refs"));
      await writeFile(join(metadata, "HEAD"), "ref: refs/heads/main\n");
      if (layout === "linked")
        await writeFile(join(nested, ".git"), `gitdir: ${metadata}\n`);
      const held = await f.store.acquireWorktreeLease(
        nested,
        "11111111-1111-4111-8111-111111111111",
      );
      try {
        for (const output of [
          "nested/result.txt",
          "nested/missing/result.txt",
          "nested/reports",
        ]) {
          const runner = f.runner(
            async () => {
              assert.fail(
                "Nested worktree outputs must fail before workflow execution.",
              );
            },
            {
              selection: () => ({
                kind: "directory",
                lease: "exclusive",
                outputPaths: ["a-safe.txt", output],
              }),
            },
          );
          await assert.rejects(runner.run(f.input), {
            code: "ERR_WORKSPACE_PATH",
            message:
              "Outputs cannot enter a nested Git worktree with a different exclusion key.",
          });
        }
        assert.equal(f.calls.length, 0);
        assert.equal(f.probes.length, 0);
        assert.equal(
          await readFile(join(nested, "result.txt"), "utf8"),
          "keep\n",
        );
        // A read-only nested worktree does not prevent outputs elsewhere.
        const { run } = await f.runner(async () => {}).create(f.input);
        assert.equal(run.workspace.leasePath, f.projectPath);
      } finally {
        await held.release();
      }
    });
  }
});

test("directory stop reconciliation preserves the checkpoint and resumes without Git", async (t) => {
  const f = await fixture(t);
  let reconciliations = 0;
  const runner = f.runner(async ({ run, runtime, operatorStop }) => {
    if (operatorStop) {
      reconciliations += 1;
      return run;
    }
    return runtime.transition({
      pipelineState: { ...run.pipelineState, workflowState: "COMPLETED" },
    });
  });
  const { run } = await runner.create(f.input);
  await f.store.requestOperatorStop({
    runId: run.runId,
    kind: "pause_requested",
    expectedRevision: run.revision,
    idempotencyKey: "pause-directory",
  });
  const paused = (await runner.resume({ runId: run.runId })).run;
  assert.equal(paused.pause.reason, "operator_paused");
  assert.equal(reconciliations, 1);
  assert.equal(
    (await runner.resume({ runId: run.runId })).run.pipelineState.workflowState,
    "COMPLETED",
  );
});

test("a stop accepted during output preflight prevents allocation and publication", async (t) => {
  const f = await fixture(t);
  let stopping = false;
  let runId;
  let creations = 0;
  const workspace = createWorkspaceService({
    fileSystem: {
      ...filesystem,
      async lstat(path, options) {
        const stat = await lstat(path, options);
        if (stopping && path === f.projectPath) {
          stopping = false;
          const current = await f.store.loadRun(runId);
          await f.store.requestOperatorStop({
            runId,
            kind: "pause_requested",
            expectedRevision: current.revision,
            idempotencyKey: "stop-output-preflight",
          });
        }
        return stat;
      },
      async mkdir(...args) {
        creations += 1;
        return mkdir(...args);
      },
    },
  });
  const runner = f.runner(
    async ({ run, runtime, operatorStop }) => {
      if (operatorStop) return run;
      runId = run.runId;
      const intent = await runtime.workspace.inspectOutputDirectory(
        join(f.projectPath, "out"),
      );
      stopping = true;
      await runtime.workspace.prepareOutputDirectory(intent);
      assert.fail("Preparation must observe the accepted stop.");
    },
    { workspace, assertOutputPreparation() {} },
  );
  const { run } = await runner.run(f.input);
  assert.equal(run.pause.reason, "operator_paused");
  assert.equal(creations, 0);
  await assert.rejects(lstat(join(f.projectPath, "out")), { code: "ENOENT" });
  assert.equal(f.calls.length, 0);
});

test("output publication uses owned no-clobber moves without copying or retaining output", async () => {
  const signal = new AbortController().signal;
  const onProcess = async () => {};
  for (const exitCode of [0, 1]) {
    const result = publishOutputDirectory(
      {
        sourceParent: 7,
        sourceName: "allocation",
        destinationParent: 8,
        destinationName: "reports",
      },
      {
        signal,
        onProcess,
        cwd: "/project",
        spawn(file, args, options) {
          assert.equal(file, "/usr/bin/mv");
          assert.deepEqual(args, [
            "--no-clobber",
            "--no-copy",
            "--no-target-directory",
            "--",
            "/proc/self/fd/3/allocation",
            "/proc/self/fd/4/reports",
          ]);
          assert.equal(options.signal, signal);
          assert.equal(options.onProcess, onProcess);
          assert.deepEqual(options.stdio, ["ignore", "ignore", "ignore", 7, 8]);
          return {
            ownedCompletion: Promise.resolve({
              outcome: { type: "close", exitCode },
            }),
          };
        },
      },
    );
    if (exitCode === 0) await result;
    else
      await assert.rejects(result, { code: "ERR_WORKSPACE_OUTPUT_AMBIGUOUS" });
  }
});

test("directory output publication returns retired process revisions and preserves arriving roots", async (t) => {
  for (const arriving of [false, true]) {
    await t.test(
      arriving ? "arriving empty root" : "absent root",
      async (t) => {
        const f = await fixture(t);
        const path = join(f.projectPath, "out");
        let inode;
        let runId;
        let intent;
        let registrations = 0;
        const store = {
          ...f.store,
          async recordExecutionProcess(lease, pid, proof) {
            const next = await f.store.recordExecutionProcess(
              lease,
              pid,
              proof,
            );
            if (pid !== null) {
              registrations += 1;
              assert.deepEqual(next.pipelineState.outputIntent, intent);
              await assert.rejects(lstat(path), { code: "ENOENT" });
              inode = (await lstat(intent.staging.path)).ino;
              if (arriving) {
                await mkdir(path);
                inode = (await lstat(path)).ino;
              }
            }
            return next;
          },
        };
        const runner = f.runner(
          async ({ run, runtime }) => {
            runId = run.runId;
            intent = await runtime.workspace.inspectOutputDirectory(path);
            const journaled = await runtime.transition({
              pipelineState: { ...run.pipelineState, outputIntent: intent },
            });
            const response =
              await runtime.workspace.prepareOutputDirectory(intent);
            assert.equal(response.run.executionProcess, null);
            assert.ok(response.run.revision > journaled.revision);
            assert.equal(response.prepared.identity.inode, String(inode));
            return runtime.transition(
              {
                pipelineState: {
                  ...response.run.pipelineState,
                  workflowState: "COMPLETED",
                },
              },
              { expectedRevision: response.run.revision },
            );
          },
          {
            runStore: store,
            assertOutputPreparation(run, supplied) {
              assert.deepEqual(run.pipelineState.outputIntent, supplied);
            },
          },
        );
        if (arriving) {
          await assert.rejects(runner.run(f.input), {
            code: "ERR_WORKSPACE_OUTPUT_AMBIGUOUS",
          });
          assert.equal((await lstat(intent.staging.path)).isDirectory(), true);
        } else {
          assert.equal(
            (await runner.run(f.input)).run.pipelineState.workflowState,
            "COMPLETED",
          );
          await assert.rejects(lstat(intent.staging.path), { code: "ENOENT" });
        }
        assert.equal(registrations, 1);
        assert.equal((await lstat(path)).ino, inode);
        assert.equal((await f.store.loadRun(runId)).executionProcess, null);
        assert.equal(f.calls.length, 0);
      },
    );
  }
});

test("directory project configuration is protected without an ignore prerequisite", async (t) => {
  const f = await fixture(t);
  const configurationPath = join(f.projectPath, "project.json");
  await writeFile(configurationPath, JSON.stringify({ schemaVersion: 1 }));
  const runner = f.runner(async () => {
    throw new Error("Changed configuration must block work.");
  });
  const { run } = await runner.create({
    ...f.input,
    projectConfigurationPath: configurationPath,
  });
  assert.equal(run.projectConfigurationProtection.path, configurationPath);
  await writeFile(
    configurationPath,
    JSON.stringify({ schemaVersion: 1, defaultModel: "changed" }),
  );
  const resumed = await runner.resume({ runId: run.runId });
  assert.equal(resumed.run.pause.reason, "project_configuration_changed");
  assert.equal(f.calls.length, 0);
});

test("directory input submission rejects frozen-input drift without consuming its edit authorization", async (t) => {
  const f = await fixture(t);
  const runner = f.runner(async ({ run, runtime }) => {
    const transcriptPath = join(f.taskPath, "clarifications.md");
    const initial = await runtime.clarifications.ensureTranscript({
      artifactRoot: f.taskPath,
      transcriptPath,
    });
    const question = "Which report format is required?";
    const rationale = "The format determines the report output.";
    const transcript = await runtime.clarifications.appendQuestionRound({
      artifactRoot: f.taskPath,
      transcriptPath,
      expectedHash: initial.hash,
      round: 1,
      questions: [{ question, whyItMatters: rationale }],
    });
    let paused;
    await runtime.clarifications.prepareEdit({
      artifactRoot: f.taskPath,
      transcriptPath,
      expectedHash: transcript.hash,
      suspendedState: "CLARIFY",
      action: "clarification-answers",
      async persistPendingEdit(pendingEdit) {
        paused = await runtime.transition({
          pipelineState: {
            ...run.pipelineState,
            workflowState: "WAITING_FOR_USER",
            pendingEdit,
          },
          pause: {
            reason: "clarification_required",
            inputRequest: {
              id: pendingEdit.id,
              kind: "clarification",
              artifactPath: transcriptPath,
              rationale,
              questions: [{ id: "q1", question, options: [] }],
            },
          },
        });
      },
    });
    return paused;
  });
  const unchanged = (await runner.run(f.input)).run;
  const response = {
    runId: unchanged.runId,
    requestId: unchanged.pause.inputRequest.id,
    expectedRevision: unchanged.revision,
    answers: [{ questionId: "q1", answer: "Markdown." }],
  };
  const acceptedPreview = await runner.previewInput(response);
  const submitted = await runner.submitInput({
    ...response,
    responseHash: acceptedPreview.responseHash,
  });
  assert.equal(
    submitted.run.pause.inputResponse.transcriptHash,
    acceptedPreview.responseHash,
  );

  for (const drift of ["changed-input", "new-context"]) {
    await t.test(drift, async () => {
      const { run } = await runner.run(f.input);
      const input = {
        runId: run.runId,
        requestId: run.pause.inputRequest.id,
        expectedRevision: run.revision,
        answers: [{ questionId: "q1", answer: "Markdown." }],
      };
      const preview = await runner.previewInput(input);
      const transcriptPath = run.pipelineState.pendingEdit.transcriptPath;
      const before = await readFile(transcriptPath, "utf8");
      const probes = f.probes.length;
      await writeFile(
        drift === "new-context"
          ? join(f.taskPath, "context.md")
          : join(f.projectPath, "input.txt"),
        "changed input\n",
      );

      await assert.rejects(
        runner.submitInput({ ...input, responseHash: preview.responseHash }),
        { code: "ERR_WORKSPACE_DRIFT" },
      );
      assert.equal(await readFile(transcriptPath, "utf8"), before);
      assert.deepEqual(await f.store.loadRun(run.runId), run);
      const resumed = (await runner.resume({ runId: run.runId })).run;
      assert.equal(resumed.pause.reason, "workspace_changed");
      assert.equal(f.probes.length, probes);
      assert.equal(await readFile(transcriptPath, "utf8"), before);
      assert.deepEqual(
        resumed.pipelineState.pendingEdit,
        run.pipelineState.pendingEdit,
      );
    });
  }
  assert.equal(f.calls.length, 0);
});

test("directory drift retires interrupted execution before durably blocking further work", async (t) => {
  for (const drift of [
    "configuration",
    "input",
    "missing-input",
    "stopping-configuration",
  ]) {
    await t.test(drift, async (t) => {
      const bootA = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
      const bootB = "bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee";
      const f = await fixture(t, {
        storeOptions: {
          hostName: "fixture-host",
          processId: 100,
          processIsAlive: (pid) => pid === 100,
          processIdentity: (pid) => ({
            bootId: bootA,
            startTicks: String(pid),
          }),
        },
      });
      const configurationPath = join(f.projectPath, "project.json");
      await writeFile(configurationPath, JSON.stringify({ schemaVersion: 1 }));
      const workflow = () =>
        assert.fail("Drift must block workflow and provider work.");
      const { run } = await f.runner(workflow).create({
        ...f.input,
        projectConfigurationPath: configurationPath,
      });
      const lease = await f.store.acquireRunLease(run.runId);
      await f.store.acquireWorktreeLease(f.projectPath, run.runId);
      await f.store.transitionRun(lease, {
        activeTurn: { role: "planner", phase: "implement" },
      });
      const storagePath = join(f.root, "storage");
      const id = "11111111-1111-4111-8111-111111111111";
      await mkdir(storagePath, { mode: 0o700 });
      const root = await lstat(storagePath, { bigint: true });
      const intent = {
        id,
        hostname: hostname(),
        commandIdentity: "a".repeat(64),
        phase: "allocating",
        root: {
          path: storagePath,
          device: String(root.dev),
          inode: String(root.ino),
        },
        directory: null,
      };
      await f.store.recordExecutionResource(lease, intent);
      await mkdir(join(storagePath, id), { mode: 0o700 });
      const directory = await lstat(join(storagePath, id), { bigint: true });
      const resource = {
        ...intent,
        phase: "allocated",
        directory: {
          device: String(directory.dev),
          inode: String(directory.ino),
        },
      };
      await f.store.recordExecutionResource(lease, resource);
      await f.store.recordExecutionProcess(lease, 300, {
        processIdentity: { bootId: bootA, startTicks: "300" },
        namespaceId: "pid:[1234]",
      });
      await assert.rejects(lease.release(), {
        code: "ERR_EXECUTION_PROCESS_ACTIVE",
      });
      const configurationDrift = drift.includes("configuration");
      const stopping =
        drift === "missing-input" || drift === "stopping-configuration";
      if (stopping)
        await f.store.requestOperatorStop({
          runId: run.runId,
          kind: "pause_requested",
          idempotencyKey: "pause-drift",
          expectedRevision: (await f.store.loadRun(run.runId)).revision,
        });
      if (drift === "missing-input") await rm(join(f.projectPath, "input.txt"));
      else
        await writeFile(
          configurationDrift
            ? configurationPath
            : join(f.projectPath, "input.txt"),
          "changed\n",
        );
      const recoveredStore = createRunStore({
        stateRoot: f.stateRoot,
        hostName: "fixture-host",
        processId: 200,
        processIsAlive: (pid) => pid === 200,
        processIdentity: (pid) => ({ bootId: bootB, startTicks: String(pid) }),
      });
      let cleanups = 0;
      const probes = f.probes.length;
      const trustedValidation = createTrustedValidationService({ git: noGit });
      const runner = f.runner(workflow, {
        runStore: recoveredStore,
        trustedValidation: {
          ...trustedValidation,
          async recoverResources(request) {
            assert.deepEqual(request.resource, resource);
            assert.equal(
              (await recoveredStore.loadRun(run.runId)).executionProcess,
              null,
            );
            cleanups += 1;
            await trustedValidation.recoverResources(request);
          },
        },
      });
      const paused = (await runner.resume({ runId: run.runId })).run;
      assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
      const blocker = configurationDrift
        ? "project_configuration_changed"
        : "workspace_changed";
      assert.equal(paused.pause.reason, stopping ? "operator_paused" : blocker);
      if (stopping) {
        assert.equal(paused.pause.operatorResume.pause.reason, blocker);
        assert.equal(paused.stopRequest.reconciledRevision, paused.revision);
      }
      assert.equal(paused.executionProcess, null);
      assert.equal(paused.executionResource, null);
      assert.equal(paused.activeTurn, null);
      await assert.rejects(lstat(join(storagePath, id)), { code: "ENOENT" });
      assert.equal(cleanups, 1);
      assert.equal(f.calls.length, 0);
      assert.equal(f.probes.length, probes);
      const resumed = (await runner.resume({ runId: run.runId })).run;
      assert.equal(resumed.pause.reason, blocker);
      assert.equal(cleanups, 1);
      const releasedRun = await recoveredStore.acquireRunLease(run.runId);
      const releasedWorkspace = await recoveredStore.acquireWorktreeLease(
        f.projectPath,
        run.runId,
      );
      await releasedWorkspace.release();
      await releasedRun.release();
    });
  }
});

test("initial directory execution retains process-only ownership for same-instance resume", async (t) => {
  const bootId = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
  let executionAlive = true;
  const f = await fixture(t, {
    storeOptions: {
      hostName: "fixture-host",
      processId: 100,
      processIsAlive: (pid) => pid === 100 || (pid === 300 && executionAlive),
      processIdentity: (pid) => ({ bootId, startTicks: String(pid) }),
    },
  });
  const namespaceId = await readlink("/proc/self/ns/pid");
  const failure = Object.assign(new Error("Fixture process ownership lost."), {
    code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
  });
  f.adapter.run = async (request) => {
    f.calls.push(request);
    await request.onProcess(300, {
      processIdentity: { bootId, startTicks: "300" },
      namespaceId,
      ancestryBaseline: [{ bootId, pid: 100, startTicks: "100" }],
    });
    throw failure;
  };
  let runId;
  let recoveries = 0;
  const runner = f.runner(
    async ({ run, runtime }) => {
      if (runId === undefined) {
        runId = run.runId;
        await turn(runtime, run, "workspace-write", "implement");
        assert.fail("Unresolved ownership must reject the initial turn.");
      }
      assert.equal(run.executionProcess, null);
      assert.equal(run.activeTurn.phase, "implement");
      await runtime.finishAgentTurn(run.activeTurn);
      return runtime.transition({
        pipelineState: { ...run.pipelineState, workflowState: "COMPLETED" },
      });
    },
    {
      inspectSessionProcesses(pid) {
        assert.equal(pid, 300);
        recoveries += 1;
        return [];
      },
    },
  );
  await assert.rejects(runner.run(f.input), {
    code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
  });
  const retained = await f.store.loadRun(runId);
  assert.equal(retained.executionProcess.pid, 300);
  assert.equal(retained.executionResource, null);
  assert.equal(retained.preparation, null);
  await assert.rejects(f.store.acquireRunLease(runId), {
    code: "ERR_RUN_LEASED",
  });

  executionAlive = false;
  const resumed = (await runner.resume({ runId })).run;
  assert.equal(resumed.pipelineState.workflowState, "COMPLETED");
  assert.equal(resumed.executionProcess, null);
  assert.equal(resumed.activeTurn, null);
  assert.equal(recoveries, 1);
  assert.equal(f.calls.length, 1);
  const releasedRun = await f.store.acquireRunLease(runId);
  const releasedWorkspace = await f.store.acquireWorktreeLease(
    f.projectPath,
    runId,
  );
  await releasedWorkspace.release();
  await releasedRun.release();
});

test("directory inspection failure retains process-only ownership for same-instance recovery", async (t) => {
  const bootA = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
  const bootB = "bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee";
  const f = await fixture(t, {
    storeOptions: {
      hostName: "fixture-host",
      processId: 100,
      processIsAlive: (pid) => pid === 100,
      processIdentity: (pid) => ({ bootId: bootA, startTicks: String(pid) }),
    },
  });
  const controls = join(f.root, "metadata");
  const pointer = join(f.projectPath, ".git");
  await mkdir(controls);
  const original = `gitdir: ${controls}\n`;
  await writeFile(pointer, original);
  const workflow = () => assert.fail("Recovery must not invoke the workflow.");
  const { run } = await f.runner(workflow).create(f.input);
  const lease = await f.store.acquireRunLease(run.runId);
  await f.store.transitionRun(lease, {
    activeTurn: { role: "planner", phase: "implement" },
  });
  await f.store.recordExecutionProcess(lease, 300, {
    processIdentity: { bootId: bootA, startTicks: "300" },
    namespaceId: "pid:[1234]",
  });
  await assert.rejects(lease.release(), {
    code: "ERR_EXECUTION_PROCESS_ACTIVE",
  });
  const recoveredStore = createRunStore({
    stateRoot: f.stateRoot,
    hostName: "fixture-host",
    processId: 200,
    processIsAlive: (pid) => pid === 200,
    processIdentity: (pid) => ({ bootId: bootB, startTicks: String(pid) }),
  });
  const runner = f.runner(workflow, { runStore: recoveredStore });
  const probes = f.probes.length;
  await writeFile(pointer, "invalid\n");
  await assert.rejects(runner.resume({ runId: run.runId }), {
    code: "ERR_WORKSPACE_PATH",
  });
  const retained = await recoveredStore.loadRun(run.runId);
  assert.equal(retained.executionProcess.pid, 300);
  assert.equal(retained.executionResource, null);
  await assert.rejects(recoveredStore.acquireRunLease(run.runId), {
    code: "ERR_RUN_LEASED",
  });

  await writeFile(pointer, original);
  await rm(join(f.projectPath, "input.txt"));
  const paused = (await runner.resume({ runId: run.runId })).run;
  assert.equal(paused.pause.reason, "workspace_changed");
  assert.equal(paused.executionProcess, null);
  assert.equal(paused.executionResource, null);
  assert.equal(paused.activeTurn, null);
  assert.equal(f.probes.length, probes);
  assert.equal(f.calls.length, 0);
  const released = await recoveredStore.acquireRunLease(run.runId);
  await released.release();
});

test("live directory storage cleanup retains Runner ownership for same-instance recovery", async (t) => {
  const f = await fixture(t);
  const metadata = join(f.root, "metadata");
  const pointer = join(f.projectPath, ".git");
  await mkdir(metadata);
  const original = `gitdir: ${metadata}\n`;
  await writeFile(pointer, original);
  const storagePath = join(f.root, `agent-runner-claude-${process.getuid()}`);
  const id = "11111111-1111-4111-8111-111111111111";
  await mkdir(storagePath, { mode: 0o700 });
  const root = await lstat(storagePath, { bigint: true });
  const allocation = join(storagePath, id);
  let resource;
  f.adapter.run = async (request) => {
    f.calls.push(request);
    const intent = {
      id,
      hostname: hostname(),
      commandIdentity: CLAUDE_STORAGE_IDENTITY,
      phase: "allocating",
      root: {
        path: storagePath,
        device: String(root.dev),
        inode: String(root.ino),
      },
      directory: null,
    };
    await request.onResource(intent);
    await mkdir(allocation, { mode: 0o700 });
    const directory = await lstat(allocation, { bigint: true });
    resource = {
      ...intent,
      phase: "allocated",
      directory: {
        device: String(directory.dev),
        inode: String(directory.ino),
      },
    };
    await request.onResource(resource);
    await writeFile(join(allocation, "protected.txt"), "Preserve.\n");
    await writeFile(pointer, `gitdir: ${allocation}\n`);
    await recoverClaudeStorage({ ...request, resource });
    assert.fail("Changed controls must prevent live storage cleanup.");
  };
  let runId;
  const runner = f.runner(
    async ({ run, runtime }) => {
      runId = run.runId;
      await turn(runtime, run, "workspace-write", "implement");
    },
    {
      adapters: { claude: f.adapter },
      loadConfiguration: async () =>
        parseRunnerConfiguration(
          JSON.stringify({
            schemaVersion: 1,
            defaultBackend: "claude",
            pipelines: { "plan-authoring": { mode: "lazy" } },
          }),
        ),
    },
  );
  await assert.rejects(runner.run(f.input), {
    code: "ERR_EXECUTION_RESOURCE_UNVERIFIABLE",
  });
  const retained = await f.store.loadRun(runId);
  assert.deepEqual(retained.executionResource, resource);
  assert.equal(retained.executionProcess, null);
  assert.equal(retained.activeTurn.phase, "implement");
  assert.equal(
    await readFile(join(allocation, "protected.txt"), "utf8"),
    "Preserve.\n",
  );
  await assert.rejects(f.store.acquireRunLease(runId), {
    code: "ERR_RUN_LEASED",
  });
  await assert.rejects(f.store.acquireWorktreeLease(f.projectPath, runId), {
    code: "ERR_WORKTREE_LEASED",
  });
  const probes = f.probes.length;
  await assert.rejects(runner.resume({ runId }), {
    code: "ERR_EXECUTION_RESOURCE_UNVERIFIABLE",
  });

  await writeFile(pointer, original);
  await rm(join(f.projectPath, "input.txt"));
  const paused = (await runner.resume({ runId })).run;
  assert.equal(paused.pause.reason, "workspace_changed");
  assert.equal(paused.executionResource, null);
  assert.equal(paused.activeTurn, null);
  await assert.rejects(lstat(allocation), { code: "ENOENT" });
  assert.equal(f.calls.length, 1);
  assert.equal(f.probes.length, probes);
  const runLease = await f.store.acquireRunLease(runId);
  const workspaceLease = await f.store.acquireWorktreeLease(
    f.projectPath,
    runId,
  );
  await workspaceLease.release();
  await runLease.release();
});

test("interrupted Claude recovery retains allocations referenced by changed directory controls", async (t) => {
  const bootA = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
  const bootB = "bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee";
  const f = await fixture(t, {
    storeOptions: {
      hostName: "fixture-host",
      processId: 100,
      processIsAlive: (pid) => pid === 100,
      processIdentity: (pid) => ({ bootId: bootA, startTicks: String(pid) }),
    },
  });
  const controls = join(f.root, "metadata");
  const pointer = join(f.projectPath, ".git");
  await mkdir(controls);
  await writeFile(pointer, `gitdir: ${controls}\n`);
  const workflow = () => assert.fail("Recovery must not invoke the workflow.");
  const { run } = await f.runner(workflow).create(f.input);
  const lease = await f.store.acquireRunLease(run.runId);
  await f.store.acquireWorktreeLease(run.workspace.leasePath, run.runId);
  await f.store.transitionRun(lease, {
    activeTurn: { role: "planner", phase: "implement" },
  });
  const storagePath = join(f.root, `agent-runner-claude-${process.getuid()}`);
  const id = "11111111-1111-4111-8111-111111111111";
  await mkdir(storagePath, { mode: 0o700 });
  const root = await lstat(storagePath, { bigint: true });
  const intent = {
    id,
    hostname: hostname(),
    commandIdentity: CLAUDE_STORAGE_IDENTITY,
    phase: "allocating",
    root: {
      path: storagePath,
      device: String(root.dev),
      inode: String(root.ino),
    },
    directory: null,
  };
  await f.store.recordExecutionResource(lease, intent);
  const allocation = join(storagePath, id);
  await mkdir(allocation, { mode: 0o700 });
  const directory = await lstat(allocation, { bigint: true });
  const resource = {
    ...intent,
    phase: "allocated",
    directory: { device: String(directory.dev), inode: String(directory.ino) },
  };
  await f.store.recordExecutionResource(lease, resource);
  await writeFile(
    join(allocation, "protected.txt"),
    "retain control content\n",
  );
  await assert.rejects(lease.release(), {
    code: "ERR_EXECUTION_PROCESS_ACTIVE",
  });
  await writeFile(pointer, `gitdir: ${allocation}\n`);
  assert.equal(
    await createWorkspaceService().exclusionPath({
      workspacePath: f.projectPath,
    }),
    run.workspace.leasePath,
  );
  const recoveredStore = createRunStore({
    stateRoot: f.stateRoot,
    hostName: "fixture-host",
    processId: 200,
    processIsAlive: (pid) => pid === 200,
    processIdentity: (pid) => ({ bootId: bootB, startTicks: String(pid) }),
  });
  const runner = f.runner(workflow, { runStore: recoveredStore });
  const probes = f.probes.length;
  // Boundary inspection can fail before resource cleanup is reached. Retain
  // the same owner's lease handle so repairing the pointer permits recovery.
  await writeFile(pointer, "invalid\n");
  await assert.rejects(runner.resume({ runId: run.runId }), {
    code: "ERR_WORKSPACE_PATH",
  });
  assert.deepEqual(
    (await recoveredStore.loadRun(run.runId)).executionResource,
    resource,
  );
  await writeFile(pointer, `gitdir: ${allocation}\n`);
  await assert.rejects(runner.resume({ runId: run.runId }), {
    code: "ERR_EXECUTION_RESOURCE_UNVERIFIABLE",
  });
  assert.equal(
    await readFile(join(allocation, "protected.txt"), "utf8"),
    "retain control content\n",
  );
  const retained = await recoveredStore.loadRun(run.runId);
  assert.deepEqual(retained.executionResource, resource);
  assert.deepEqual(retained.activeTurn, {
    role: "planner",
    phase: "implement",
  });
  assert.equal(f.probes.length, probes);
  assert.equal(f.calls.length, 0);

  // Restoring the pointer permits cleanup, even if a frozen input was deleted.
  await writeFile(pointer, `gitdir: ${controls}\n`);
  await rm(join(f.projectPath, "input.txt"));
  const paused = (await runner.resume({ runId: run.runId })).run;
  assert.equal(paused.pause.reason, "workspace_changed");
  assert.equal(paused.executionResource, null);
  await assert.rejects(lstat(allocation), { code: "ENOENT" });
  assert.equal(f.probes.length, probes);
  assert.equal(f.calls.length, 0);
});

test("new control trees invalidate a saved directory binding before provider work", async (t) => {
  const f = await fixture(t);
  const runner = f.runner(async () => {
    throw new Error("Control drift must block work.");
  });
  const { run } = await runner.create(f.input);
  await mkdir(join(f.projectPath, ".codex"));
  assert.equal(
    (await runner.resume({ runId: run.runId })).run.pause.reason,
    "workspace_changed",
  );
  assert.equal(f.calls.length, 0);
});

test("directory recovery pins existing output ancestors", async (t) => {
  const f = await fixture(t);
  const parent = join(f.projectPath, "reports");
  await mkdir(parent);
  const runner = f.runner(
    async () => {
      throw new Error("Ancestor substitution must block work.");
    },
    {
      selection: () => ({
        kind: "directory",
        lease: "exclusive",
        outputPaths: ["reports/report.txt"],
      }),
    },
  );
  const { run } = await runner.create(f.input);
  await rename(parent, join(f.root, "original-reports"));
  await mkdir(parent);
  assert.equal(
    (await runner.resume({ runId: run.runId })).run.pause.reason,
    "workspace_changed",
  );
  assert.equal(f.calls.length, 0);
});

test("trusted directory validation binds filesystem content, read mounts and mutation guards", async (t) => {
  const f = await fixture(t);
  const source = join(f.root, "reference.txt");
  await writeFile(source, "read-only reference\n");
  const workspacePolicy = {
    kind: "directory",
    workspacePath: f.projectPath,
    stateRoot: f.stateRoot,
    taskPath: f.taskPath,
    sourcePaths: [source],
    outputPaths: [join(f.projectPath, "out")],
  };
  const { kind: _kind, ...declarations } = workspacePolicy;
  const workspace = createWorkspaceService();
  const before = await workspace.snapshot({
    inspection: await workspace.inspect(declarations),
  });
  const snapshot = createTrustedValidationSnapshot(
    {
      verify: {
        command: "node verify.js",
        executable: "node",
        arguments: ["verify.js"],
      },
    },
    ["verify"],
  );
  const bindings = {
    contentFingerprint: before.contentFingerprint,
    validationInfrastructureFingerprint: digest("infrastructure"),
    commandFingerprint: snapshot.commandFingerprint,
    configurationFingerprint: snapshot.configurationFingerprint,
  };
  let mutations = false;
  let executions = 0;
  const service = createTrustedValidationService({
    git: noGit,
    sandboxCommand(command, scope) {
      assert.equal(command.identity, snapshot.commands[0].identity);
      assert.ok(scope.workspacePaths.includes(source));
      assert.ok(scope.protectedPaths.includes(source));
      return { command, environment: {} };
    },
    async runCommand() {
      executions += 1;
      if (mutations) await writeFile(source, "mutated\n");
      return {
        status: "PASS",
        exitCode: 0,
        signal: null,
        timedOut: false,
        reason: "exit",
      };
    },
  });
  const request = {
    projectPath: f.projectPath,
    workspacePolicy,
    snapshot,
    bindings,
    commandIdentity: snapshot.commands[0].identity,
  };
  await service.preflight(request);
  assert.equal((await service.execute(request)).status, "PASS");
  mutations = true;
  await assert.rejects(service.execute(request), {
    code: "ERR_TRUSTED_VALIDATION_MUTATED_REPOSITORY",
  });
  await assert.rejects(service.execute(request), {
    code: "ERR_TRUSTED_VALIDATION_BINDING_CHANGED",
  });
  assert.equal(executions, 2);
});

test("trusted directory cleanup retains Runner leases across control and configuration drift", async (t) => {
  for (const [operation, entry] of [
    ["execute", "run"],
    ["inspectRequirements", "resume"],
  ]) {
    for (const [target, configurationDrift] of [
      ["allocation", false],
      ["malformed", false],
      ["allocation", true],
      ["malformed", true],
    ]) {
      const name = `${entry}/${operation}: ${target}, configuration drift: ${configurationDrift}`;
      await t.test(name, async (t) => {
        const f = await fixture(t);
        const configurationPath = join(f.projectPath, "project.json");
        const configuration = JSON.stringify({ schemaVersion: 1 });
        if (configurationDrift)
          await writeFile(configurationPath, configuration);
        const metadata = join(f.root, "metadata");
        await mkdir(metadata);
        const pointer = join(f.projectPath, ".git");
        const original = `gitdir: ${metadata}\n`;
        await writeFile(pointer, original);
        const snapshot = createTrustedValidationSnapshot(
          {
            verify: {
              command: "node verify.js",
              executable: "node",
              arguments: ["verify.js"],
              capabilities: { scratch: true },
            },
          },
          ["verify"],
        );
        let runId;
        let allocation;
        let executions = 0;
        let workflows = 0;
        const service = createTrustedValidationService({
          git: noGit,
          environment: {},
          storageRoot: join(f.root, "validation-storage"),
          sandboxCommand: (command) => ({ command, environment: {} }),
          async runCommand(_command, { onNoLaunch }) {
            executions += 1;
            // The preparation fixture launches no process; settle its real custody.
            await onNoLaunch?.();
            const { executionResource: resource } =
              await f.store.loadRun(runId);
            allocation = join(resource.root.path, resource.id);
            await writeFile(
              join(allocation, "scratch", "retained.txt"),
              "owned\n",
            );
            await writeFile(
              pointer,
              target === "allocation" ? `gitdir: ${allocation}\n` : "invalid\n",
            );
            if (configurationDrift)
              await writeFile(configurationPath, `${configuration}\n`);
            return {
              status: "PASS",
              exitCode: 0,
              signal: null,
              timedOut: false,
              reason: "exit",
            };
          },
        });
        const runner = f.runner(
          async ({ run, runtime }) => {
            runId = run.runId;
            workflows += 1;
            await runtime.transition({
              pipelineState: {
                ...run.pipelineState,
                trustedValidation: snapshot,
              },
            });
            const before = await runtime.workspace.snapshot();
            return runtime.trustedValidation[operation](
              operation === "execute"
                ? {
                    snapshot,
                    commandIdentity: snapshot.commands[0].identity,
                    bindings: {
                      contentFingerprint: before.contentFingerprint,
                      validationInfrastructureFingerprint:
                        digest("infrastructure"),
                      commandFingerprint: snapshot.commandFingerprint,
                      configurationFingerprint:
                        snapshot.configurationFingerprint,
                    },
                  }
                : { inventory: [snapshot.commands[0].command] },
            );
          },
          { trustedValidation: service },
        );
        const createInput = {
          ...f.input,
          ...(configurationDrift
            ? { projectConfigurationPath: configurationPath }
            : {}),
        };
        const input =
          entry === "run"
            ? createInput
            : { runId: (await runner.create(createInput)).run.runId };
        let failure;
        await assert.rejects(runner[entry](input), (cause) => {
          failure = cause;
          return true;
        });
        const retained = await f.store.loadRun(runId);
        assert.equal(retained.executionResource.phase, "allocated");
        assert.equal(retained.executionProcess, null);
        assert.equal(retained.preparation, null);
        await assert.rejects(f.store.acquireRunLease(runId), {
          code: "ERR_RUN_LEASED",
        });
        await assert.rejects(
          f.store.acquireWorktreeLease(f.projectPath, runId),
          {
            code: "ERR_WORKTREE_LEASED",
          },
        );
        assert.equal(
          await readFile(join(allocation, "scratch", "retained.txt"), "utf8"),
          "owned\n",
        );
        const probes = f.probes.length;
        if (configurationDrift) {
          assert.equal(failure.code, "ERR_EXECUTION_PROCESS_ACTIVE");
          assert.equal(retained.pause.reason, "project_configuration_changed");
          // A saved safety pause must still attempt cleanup, retaining its
          // exact leases while current controls make removal unsafe.
          await assert.rejects(runner.resume({ runId }), {
            code:
              target === "allocation"
                ? "ERR_EXECUTION_PROCESS_ACTIVE"
                : "ERR_WORKSPACE_PATH",
          });
          assert.deepEqual(await f.store.loadRun(runId), retained);
          assert.equal(
            await readFile(join(allocation, "scratch", "retained.txt"), "utf8"),
            "owned\n",
          );
        }
        await writeFile(pointer, original);
        // Exercise cleanup with configuration both still changed and restored;
        // neither permits replay of the suspended workflow.
        if (configurationDrift && target === "malformed")
          await writeFile(configurationPath, configuration);
        const recovered = (await runner.resume({ runId })).run;
        assert.equal(
          recovered.pause.reason,
          configurationDrift
            ? "project_configuration_changed"
            : "workspace_changed",
        );
        assert.equal(recovered.executionResource, null);
        await assert.rejects(lstat(allocation), { code: "ENOENT" });
        if (!configurationDrift) {
          assert.equal(failure.executionResourceRetained, true);
          assert.ok(failure.code.startsWith("ERR_WORKSPACE_"));
        }
        if (configurationDrift)
          await writeFile(configurationPath, configuration);
        assert.deepEqual((await runner.resume({ runId })).run, recovered);
        assert.equal(executions, 1);
        assert.equal(workflows, 1);
        assert.equal(f.calls.length, 0);
        assert.equal(f.probes.length, probes);
        const runLease = await f.store.acquireRunLease(runId);
        const workspaceLease = await f.store.acquireWorktreeLease(
          f.projectPath,
          runId,
        );
        await workspaceLease.release();
        await runLease.release();
      });
    }
  }
});

test("directory drift blocks trusted execution and preparation before service invocation", async (t) => {
  for (const operation of ["execute", "inspectRequirements"]) {
    await t.test(operation, async (t) => {
      const f = await fixture(t);
      let invocations = 0;
      const runner = f.runner(
        async ({ runtime }) => {
          const input = join(f.projectPath, "input.txt");
          const replacement = join(f.projectPath, "replacement.txt");
          await writeFile(replacement, await readFile(input));
          await rename(replacement, input);
          await runtime.trustedValidation[operation]({});
        },
        {
          trustedValidation: {
            async preflight() {},
            async execute() {},
            async [operation]() {
              invocations += 1;
              return {};
            },
          },
        },
      );
      await assert.rejects(runner.run(f.input), {
        code: "ERR_WORKSPACE_DRIFT",
      });
      assert.equal(invocations, 0);
    });
  }
});

test("public commit pipelines still reject ordinary directories before probing", async (t) => {
  const f = await fixture(t);
  const runner = createRunner({
    adapters: { codex: f.adapter },
    git: createGitService(),
    runStore: f.store,
  });
  await assert.rejects(runner.create(f.input));
  assert.equal(f.probes.length, 0);
});

test("MCP workspace preflight and creation use the same resolved selection settings", async (t) => {
  const f = await fixture(t);
  const configurationPath = join(f.projectPath, "project.json");
  await writeFile(configurationPath, JSON.stringify({ schemaVersion: 1 }));
  const expectedSettings = {
    ...Object.fromEntries(
      Object.entries(planAuthoringPipeline.settings).map(
        ([name, definition]) => [name, definition.defaultValue],
      ),
    ),
    mode: "lazy",
  };
  let selections = 0;
  const runner = f.runner(async () => {}, {
    selection(input) {
      selections += 1;
      assert.equal(input.projectConfigurationPath, configurationPath);
      assert.deepEqual(input.settingOverrides, expectedSettings);
      assert.equal(input.proactiveClarification, false);
      assert.equal(input.sourceSession, null);
      return { kind: "directory", lease: "exclusive" };
    },
  });
  const prepared = new Error("Preflight completed before durable dispatch.");
  const control = createMcpControlPlane({
    runner,
    runStore: {
      readAction: async () => null,
      async beginAction() {
        throw prepared;
      },
    },
  });
  await assert.rejects(
    control.runStart({
      ...f.input,
      projectConfigurationPath: configurationPath,
      mode: "lazy",
      idempotencyKey: "directory-start",
    }),
    (cause) => cause === prepared,
  );
  const preflightSelections = selections;
  assert.ok(preflightSelections > 0);
  const { run } = await runner.create({
    ...f.input,
    projectConfigurationPath: configurationPath,
    settingOverrides: { mode: "lazy" },
  });
  assert.equal(run.workspace.kind, "directory");
  assert.deepEqual(run.pipelineState.settings, expectedSettings);
  assert.ok(selections > preflightSelections);
});
