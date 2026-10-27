import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { serializeCustomPlan } from "@agent-runner/custom-plan";
import { createClarificationService } from "../src/clarifications/index.js";
import { parseRunnerConfiguration } from "../src/config/index.js";
import { createGitService } from "../src/git/index.js";
import { createMcpControlPlane } from "../src/mcp/index.js";
import { createRunner } from "../src/runner/index.js";
import { createRunStore } from "../src/state/index.js";

const criteria = [
  {
    id: "traceability",
    condition: "Trace each conclusion to the supplied evidence.",
  },
];
const emptyDecision = {
  question: "",
  options: [],
  whyBlocked: "",
  evidence: [],
};

async function fixture(t, settings = {}, { git } = {}) {
  const root = await mkdtemp(join(tmpdir(), "runner-custom-authoring-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const projectPath = join(root, "workspace");
  const taskPath = join(projectPath, "task");
  await mkdir(taskPath, { recursive: true });
  await writeFile(
    join(taskPath, "task.md"),
    "Plan an evidence-based summary.\n",
  );
  await writeFile(
    join(projectPath, "criteria.md"),
    "Trace each conclusion to supplied evidence.\n",
  );
  const source = join(root, "source.md");
  await writeFile(source, "Supplied evidence.\n");
  const calls = [];
  const probes = [];
  const runStore = createRunStore({ stateRoot: join(root, "state") });
  let configuration = {
    schemaVersion: 1,
    defaultBackend: "codex",
    pipelines: { "plan-authoring": settings },
  };
  const queue = [];
  const adapter = {
    async probe(request) {
      probes.push(request);
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
      assert.ok(queue.length > 0, "Unexpected model turn");
      const next = queue.shift();
      return {
        output: "structured",
        structured: typeof next === "function" ? await next(request) : next,
        sessionId:
          request.session?.mode === "continue"
            ? request.session.id
            : `child-${calls.length}`,
      };
    },
  };
  const runner = createRunner({
    adapters: { codex: adapter },
    runStore,
    clarifications: createClarificationService({ interactive: false }),
    git:
      git ??
      new Proxy(
        {},
        {
          get() {
            throw new Error(
              "Commit selection requires Git; custom selection must not inspect Git.",
            );
          },
        },
      ),
    loadConfiguration: async () =>
      parseRunnerConfiguration(JSON.stringify(configuration)),
  });
  return {
    projectPath,
    taskPath,
    root,
    source,
    calls,
    probes,
    queue,
    runner,
    runStore,
    setConfiguration(value) {
      configuration = value;
    },
    input: { pipelineId: "plan-authoring", projectPath, taskPath },
  };
}

test("configured custom authoring freezes declarations and publishes only its plan in an ordinary directory", async (t) => {
  const f = await fixture(t);
  await mkdir(join(f.projectPath, "LOCAL_ARTIFACTS"));
  await writeFile(
    join(f.projectPath, "LOCAL_ARTIFACTS", "agent-runner.json"),
    JSON.stringify({
      schemaVersion: 1,
      pipelines: {
        "plan-authoring": {
          planKind: "custom",
          mode: "combined",
          criteriaPath: "criteria.md",
        },
      },
    }),
  );
  const sourceReferences = [f.source, "https://example.invalid/evidence"];
  const outputPaths = ["reports/summary.md"];
  const plan = serializeCustomPlan({
    kind: "custom",
    criteria,
    inputs: sourceReferences,
    outputs: outputPaths,
    steps: [
      {
        number: 1,
        title: "Summarize evidence",
        work: "Read the supplied source and record unavailable references.",
        expectedResults: "A traceable summary with explicit evidence gaps.",
        criterionRefs: ["traceability"],
      },
    ],
  });
  f.queue.push(
    { status: "READY", questions: [], criteria },
    { status: "DRAFT", plan, ...emptyDecision },
    { status: "UNCHANGED", plan: "", ...emptyDecision },
    { status: "CLEAN", findings: [], ...emptyDecision },
    { status: "APPROVED", findings: [], ...emptyDecision },
  );
  assert.equal(
    (
      await f.runner.validateBoundary({
        ...f.input,
        settingOverrides: { sourceReferences, outputPaths },
      })
    ).projectPath,
    f.projectPath,
  );
  const { run } = await f.runner.run({
    ...f.input,
    settingOverrides: { sourceReferences, outputPaths },
  });
  assert.equal(run.pipelineState.workflowState, "DONE");
  assert.equal(run.workspace.kind, "directory");
  assert.deepEqual(run.workspace.policy.outputPaths, []);
  assert.deepEqual(run.workspace.retrievalPermissions, []);
  assert.ok(
    run.workspace.policy.inputPaths.includes(
      join(f.projectPath, "criteria.md"),
    ),
  );
  assert.deepEqual(run.workspace.policy.sourcePaths, [f.source]);
  assert.equal(await readFile(join(f.taskPath, "plan.md"), "utf8"), plan);
  await assert.rejects(readFile(join(f.projectPath, outputPaths[0])), {
    code: "ENOENT",
  });
  assert.ok(
    f.calls.every(
      (request) =>
        request.access === "read-only" &&
        request.workspacePolicy.kind === "directory",
    ),
  );
  assert.ok(f.probes.every((request) => request.access === "read-only"));
});

test("custom resume uses frozen selections and rejects source drift before another model turn", async (t) => {
  const f = await fixture(t, {
    planKind: "custom",
    mode: "lazy",
    criteriaPath: "criteria.md",
  });
  f.queue.push({
    status: "QUESTIONS",
    questions: [
      {
        question: "Which evidence is in scope?",
        whyItMatters: "It determines result coverage.",
      },
    ],
    criteria: [],
  });
  const { run } = await f.runner.run({
    ...f.input,
    settingOverrides: { sourceReferences: [f.source] },
  });
  assert.equal(run.pause.reason, "clarification_answers_required");
  f.setConfiguration({ schemaVersion: 1, defaultBackend: "codex" });
  await writeFile(f.source, "Changed evidence.\n");
  const transcript = await readFile(
    join(f.taskPath, "clarifications.md"),
    "utf8",
  );
  const resumed = await f.runner.resume({ runId: run.runId });
  assert.equal(resumed.run.pause.reason, "workspace_changed");
  assert.equal(resumed.run.pipelineState.settings.planKind, "custom");
  assert.equal(
    await readFile(join(f.taskPath, "clarifications.md"), "utf8"),
    transcript,
  );
  assert.equal(f.calls.length, 1);
});

test("criteria alone never select custom, and invalid kinds fail before provider work", async (t) => {
  const f = await fixture(t);
  await assert.rejects(
    f.runner.create({
      ...f.input,
      settingOverrides: { criteriaPath: "criteria.md" },
    }),
    /requires Git/u,
  );
  await assert.rejects(
    f.runner.create({ ...f.input, settingOverrides: { planKind: "unknown" } }),
    /planKind/u,
  );
  assert.deepEqual(f.probes, []);
  assert.deepEqual(f.calls, []);
});

test("artifact separation uses the effective project overrides", async (t) => {
  const f = await fixture(t, {
    planKind: "custom",
    criteriaPath: "task/plan.md",
    sourceReferences: ["task/clarifications.md"],
  });
  await mkdir(join(f.projectPath, "LOCAL_ARTIFACTS"));
  await writeFile(
    join(f.projectPath, "LOCAL_ARTIFACTS", "agent-runner.json"),
    JSON.stringify({
      schemaVersion: 1,
      pipelines: {
        "plan-authoring": {
          criteriaPath: "criteria.md",
          sourceReferences: [f.source],
        },
      },
    }),
  );
  assert.equal(
    (await f.runner.validateBoundary(f.input)).projectPath,
    f.projectPath,
  );
  const { run } = await f.runner.create(f.input);
  assert.equal(run.pipelineState.settings.criteriaPath, "criteria.md");
  assert.deepEqual(
    run.workspace.policy.inputPaths,
    [join(f.projectPath, "criteria.md"), join(f.taskPath, "task.md")].sort(),
  );
  assert.deepEqual(run.workspace.policy.sourcePaths, [f.source]);
  assert.deepEqual(f.calls, []);
});

test("planning artifacts cannot overwrite declared criteria or source inputs", async (t) => {
  const f = await fixture(t, { planKind: "custom" });
  await writeFile(join(f.taskPath, "plan.md"), "Existing source evidence.\n");
  await assert.rejects(
    f.runner.create({
      ...f.input,
      settingOverrides: { sourceReferences: [join(f.taskPath, "plan.md")] },
    }),
    /must not overlap/u,
  );
  await assert.rejects(
    f.runner.create({
      ...f.input,
      settingOverrides: { criteriaPath: join(f.taskPath, "plan.md") },
    }),
    /must not overlap/u,
  );
  assert.equal(
    await readFile(join(f.taskPath, "plan.md"), "utf8"),
    "Existing source evidence.\n",
  );
  assert.deepEqual(f.probes, []);
});

test("authoring rejects configuration collisions before replacing either artifact", async (t) => {
  for (const filename of ["clarifications.md", "plan.md"]) {
    await t.test(filename, async (t) => {
      const f = await fixture(t, { planKind: "custom" });
      const configurationPath = join(f.taskPath, filename);
      const content = '{"schemaVersion":1}\n';
      await writeFile(configurationPath, content);
      await assert.rejects(
        f.runner.create({
          ...f.input,
          projectConfigurationPath: configurationPath,
        }),
        { code: "ERR_UNSAFE_WORKSPACE_ACCESS" },
      );
      assert.equal(await readFile(configurationPath, "utf8"), content);
      assert.deepEqual(f.probes, []);
      assert.deepEqual(f.calls, []);
    });
  }
});

test("authoring artifacts cannot be published inside provider controls", async (t) => {
  const f = await fixture(t, { planKind: "custom" });
  const taskPath = join(f.projectPath, ".agents", "task");
  await mkdir(taskPath, { recursive: true });
  await writeFile(join(taskPath, "task.md"), "Plan a traceable summary.\n");
  await assert.rejects(f.runner.create({ ...f.input, taskPath }), {
    code: "ERR_UNSAFE_WORKSPACE_ACCESS",
  });
  for (const filename of ["clarifications.md", "plan.md"])
    await assert.rejects(readFile(join(taskPath, filename)), {
      code: "ENOENT",
    });
  assert.deepEqual(f.probes, []);
});

test("commit authoring from a subdirectory resolves repository-root configuration", async (t) => {
  const f = await fixture(t, {}, { git: createGitService() });
  await promisify(execFile)("git", ["init", "-q", f.projectPath]);
  const nestedPath = join(f.projectPath, "nested");
  const configurationPath = join(
    f.projectPath,
    "LOCAL_ARTIFACTS",
    "agent-runner.json",
  );
  await mkdir(nestedPath);
  await mkdir(join(f.projectPath, "LOCAL_ARTIFACTS"));
  await writeFile(join(f.projectPath, ".gitignore"), "/LOCAL_ARTIFACTS/\n");
  await writeFile(
    configurationPath,
    JSON.stringify({
      schemaVersion: 1,
      pipelines: { "plan-authoring": { mode: "lazy" } },
    }),
  );
  for (const projectConfigurationPath of [
    undefined,
    configurationPath,
    "LOCAL_ARTIFACTS/agent-runner.json",
  ]) {
    const input = {
      ...f.input,
      projectPath: nestedPath,
      projectConfigurationPath,
    };
    assert.equal(
      (await f.runner.validateBoundary(input)).projectPath,
      f.projectPath,
    );
    const { run } = await f.runner.create(input);
    assert.equal(run.projectPath, f.projectPath);
    assert.equal(run.workspace.kind, "git");
    assert.equal(run.pipelineState.settings.mode, "lazy");
    assert.equal(run.pipelineState.settings.planKind, "commit");
    assert.equal(run.projectConfigurationProtection.path, configurationPath);
    assert.equal(run.projectConfigurationProtection.projectPath, f.projectPath);
  }
  assert.deepEqual(f.calls, []);
});

test("custom authoring retains its selected subdirectory configuration scope", async (t) => {
  for (const configured of [false, true]) {
    await t.test(
      configured ? "configured kind" : "explicit kind",
      async (t) => {
        const f = await fixture(t, configured ? { planKind: "custom" } : {});
        await promisify(execFile)("git", ["init", "-q", f.projectPath]);
        const nestedPath = join(f.projectPath, "nested");
        await mkdir(nestedPath);
        await mkdir(join(f.projectPath, "LOCAL_ARTIFACTS"));
        await writeFile(
          join(f.projectPath, "LOCAL_ARTIFACTS", "agent-runner.json"),
          "Unselected repository-root configuration.\n",
        );
        const input = {
          ...f.input,
          projectPath: nestedPath,
          settingOverrides: configured ? {} : { planKind: "custom" },
        };
        assert.equal(
          (await f.runner.validateBoundary(input)).projectPath,
          nestedPath,
        );
        const { run } = await f.runner.create(input);
        assert.equal(run.projectPath, nestedPath);
        assert.equal(run.workspace.kind, "directory");
        assert.equal(run.workspace.leasePath, f.projectPath);
        assert.equal(run.projectConfigurationProtection, null);
        assert.deepEqual(f.calls, []);
      },
    );
  }
});

test("MCP start recovery retains a reserved custom workspace after configured kind changes", async (t) => {
  const f = await fixture(
    t,
    { planKind: "custom" },
    { git: createGitService() },
  );
  await promisify(execFile)("git", ["init", "-q", f.projectPath]);
  const projectPath = join(f.projectPath, "nested");
  await mkdir(projectPath);
  const input = {
    ...f.input,
    projectPath,
    proactiveClarification: false,
    sourceSession: null,
    idempotencyKey: "reserved-custom-start",
  };
  const { idempotencyKey, ...argumentsWithoutKey } = input;
  const runId = "11111111-1111-4111-8111-111111111111";
  const intent = await f.runStore.beginAction({
    key: idempotencyKey,
    tool: "run_start",
    arguments: argumentsWithoutKey,
    context: { runId },
  });
  let reserved;
  try {
    ({ run: reserved } = await f.runner.create(argumentsWithoutKey, {
      runId,
    }));
  } finally {
    await intent.release();
  }
  assert.equal(reserved.workspace.kind, "directory");
  assert.equal(reserved.projectPath, projectPath);

  f.setConfiguration({ schemaVersion: 1, defaultBackend: "codex" });
  assert.equal(
    (await f.runner.validateBoundary(argumentsWithoutKey)).projectPath,
    f.projectPath,
  );
  const launches = [];
  const control = createMcpControlPlane({
    runner: f.runner,
    runStore: f.runStore,
    async launchRun(id, _action, { dispatch }) {
      launches.push(id);
      const lease = await f.runStore.acquireRunLease(id);
      try {
        await f.runStore.recoverRun(lease);
        await f.runStore.recordRecoveryDispatch(lease, dispatch);
        await f.runStore.recordRecoveryDispatch(lease, dispatch, true);
      } finally {
        await lease.release();
      }
    },
  });
  assert.deepEqual(await control.runStart(input), { runId });
  assert.deepEqual(await control.runStart(input), { runId });
  await assert.rejects(control.runStart({ ...input, planKind: "commit" }), {
    code: "ERR_MCP_IDEMPOTENCY_CONFLICT",
  });
  const recovered = await f.runStore.loadRun(runId);
  assert.deepEqual(recovered.workspace, reserved.workspace);
  assert.equal(recovered.pipelineState.settings.planKind, "custom");
  assert.deepEqual(launches, [runId]);
  assert.deepEqual(f.calls, []);
});

test("project-selected custom authoring keeps the requested repository subdirectory", async (t) => {
  for (const selector of ["implicit", "absolute", "relative"]) {
    await t.test(selector, async (t) => {
      const f = await fixture(t);
      await promisify(execFile)("git", ["init", "-q", f.projectPath]);
      const projectPath = join(f.projectPath, "nested");
      const relativeConfigurationPath = "LOCAL_ARTIFACTS/agent-runner.json";
      const configurationPath = join(projectPath, relativeConfigurationPath);
      await mkdir(join(projectPath, "LOCAL_ARTIFACTS"), { recursive: true });
      await writeFile(
        join(projectPath, "criteria.md"),
        "Use supplied evidence.\n",
      );
      await writeFile(join(projectPath, "evidence.md"), "Local evidence.\n");
      await writeFile(
        configurationPath,
        JSON.stringify({
          schemaVersion: 1,
          pipelines: {
            "plan-authoring": {
              planKind: "custom",
              criteriaPath: "criteria.md",
              sourceReferences: ["evidence.md"],
            },
          },
        }),
      );
      const input = {
        ...f.input,
        projectPath,
        ...(selector === "implicit"
          ? {}
          : {
              projectConfigurationPath:
                selector === "absolute"
                  ? configurationPath
                  : relativeConfigurationPath,
            }),
      };
      assert.equal(
        (await f.runner.validateBoundary(input)).projectPath,
        projectPath,
      );
      const { run } = await f.runner.create(input);
      assert.equal(run.projectPath, projectPath);
      assert.equal(run.workspace.kind, "directory");
      assert.equal(run.workspace.leasePath, f.projectPath);
      assert.ok(
        run.workspace.policy.inputPaths.includes(
          join(projectPath, "criteria.md"),
        ),
      );
      assert.deepEqual(run.workspace.policy.sourcePaths, [
        join(projectPath, "evidence.md"),
      ]);
      assert.equal(run.projectConfigurationProtection.projectPath, projectPath);
      assert.equal(run.projectConfigurationProtection.path, configurationPath);
      assert.deepEqual(f.calls, []);
    });
  }
});

test("custom project configuration cannot widen the requested directory to its parent", async (t) => {
  const f = await fixture(t);
  await promisify(execFile)("git", ["init", "-q", f.projectPath]);
  const projectPath = join(f.projectPath, "nested");
  await mkdir(projectPath);
  await mkdir(join(f.projectPath, "LOCAL_ARTIFACTS"));
  const projectConfigurationPath = join(
    f.projectPath,
    "LOCAL_ARTIFACTS",
    "agent-runner.json",
  );
  await writeFile(
    projectConfigurationPath,
    JSON.stringify({
      schemaVersion: 1,
      pipelines: { "plan-authoring": { planKind: "custom" } },
    }),
  );
  await assert.rejects(
    f.runner.create({ ...f.input, projectPath, projectConfigurationPath }),
    { code: "ERR_WORKSPACE_PATH" },
  );
  assert.deepEqual(f.probes, []);
  assert.deepEqual(f.calls, []);
});

test("commit supplemental reads tolerate unrelated ignored links and reject declared source drift", async (t) => {
  const f = await fixture(t, {}, { git: createGitService() });
  await promisify(execFile)("git", ["init", "-q", f.projectPath]);
  await mkdir(join(f.projectPath, "node_modules"));
  const sourcePath = join(f.root, "evidence");
  await mkdir(sourcePath);
  const sourceFile = join(sourcePath, "source.md");
  await writeFile(sourceFile, "Original evidence.\n");
  await symlink(sourcePath, join(f.projectPath, "node_modules", "linked"));
  await writeFile(
    join(f.projectPath, ".gitignore"),
    "/node_modules/\n/task/clarifications.md\n",
  );
  f.queue.push(async () => {
    await writeFile(sourceFile, "Changed evidence.\n");
    return { status: "READY", questions: [] };
  });
  const { run } = await f.runner.run({
    ...f.input,
    settingOverrides: {
      criteriaPath: "criteria.md",
      sourceReferences: [sourcePath],
    },
  });
  assert.equal(run.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(run.pause.reason, "input_changed");
  assert.equal(run.workspace.kind, "git");
  assert.equal(f.calls.length, 1);
  await assert.rejects(readFile(join(f.taskPath, "plan.md")), {
    code: "ENOENT",
  });
});

test("repository-contained custom authoring requires an ignored clarification artifact", async (t) => {
  const f = await fixture(
    t,
    { planKind: "custom" },
    { git: createGitService() },
  );
  await promisify(execFile)("git", ["init", "-q", f.projectPath]);
  await assert.rejects(f.runner.run(f.input), {
    code: "ERR_REPOSITORY_ARTIFACT_NOT_IGNORED",
  });
  await assert.rejects(readFile(join(f.taskPath, "clarifications.md")), {
    code: "ENOENT",
  });
  assert.deepEqual(f.calls, []);

  await writeFile(
    join(f.projectPath, ".gitignore"),
    "/task/clarifications.md\n",
  );
  const plan = serializeCustomPlan({
    kind: "custom",
    criteria,
    inputs: [],
    outputs: [],
    steps: [
      {
        number: 1,
        title: "Analyze the evidence",
        work: "Identify the supplied evidence.",
        expectedResults: "A traceable analysis with explicit evidence gaps.",
        criterionRefs: ["traceability"],
      },
    ],
  });
  f.queue.push(
    { status: "READY", questions: [], criteria },
    { status: "DRAFT", plan, ...emptyDecision },
    { status: "APPROVED", findings: [], ...emptyDecision },
  );
  const { run } = await f.runner.run(f.input);
  assert.equal(run.pipelineState.workflowState, "DONE");
  assert.equal(run.workspace.kind, "directory");
  assert.equal(await readFile(join(f.taskPath, "plan.md"), "utf8"), plan);
});
