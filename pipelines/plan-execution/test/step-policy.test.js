import assert from "node:assert/strict";
import test from "node:test";

import { serializeCustomPlan } from "@agent-runner/custom-plan";
import {
  createPlanExecutionState,
  migratePlanExecutionStateV32,
  planExecutionPipeline,
  runPlanExecution,
} from "../src/index.js";
import {
  canonicalExecutionPlan,
  MAX_PLAN_LENGTH,
  planKindPolicy,
} from "../src/step-policy.js";
import {
  assertRuntime,
  normalizeAdapterCapabilities,
  normalizePipelineState,
} from "../src/workflow-contract.js";
import {
  checkAndFix,
  createFixture,
  finalizationPassed,
  implementationCompleted,
} from "./support/index.js";

const commitPlan = "## Commit 1: feat(example): add behavior\n\nAdd behavior.";
const customPlan = serializeCustomPlan({
  kind: "custom",
  criteria: [
    { id: "source-coverage", condition: "Identify every supplied source." },
  ],
  inputs: ["sources/catalog.md", "https://example.invalid/reference"],
  outputs: [],
  steps: [
    {
      number: 1,
      title: "Analyze the evidence",
      work: "Read the supplied catalog.",
      expectedResults: "An analysis identifying sources and evidence gaps.",
      criterionRefs: ["source-coverage"],
    },
  ],
});

test("execution parsing selects the explicit contract and preserves exact subjects", () => {
  const commit = planKindPolicy("commit");
  const custom = planKindPolicy("custom");
  const source = canonicalExecutionPlan(commitPlan);
  const step = commit.parse(source).steps[0];
  assert.equal(step.subject, "feat(example): add behavior");
  assert.equal(
    commit.stepContext(source, step),
    `Current planned commit:\n## Commit 1: ${step.subject}\n\n${step.body}`,
  );
  assert.equal(canonicalExecutionPlan(customPlan, "custom"), customPlan);
  assert.equal(custom.parse(customPlan).steps[0].title, "Analyze the evidence");
  for (const [source, kind] of [
    [customPlan, "commit"],
    [commitPlan, "custom"],
    [customPlan, undefined],
  ]) {
    assert.throws(() => canonicalExecutionPlan(source, kind), {
      code: "ERR_INVALID_EXECUTION_PLAN",
    });
  }
  for (const kind of [null, "inferred", "Commit"]) {
    assert.throws(() => planKindPolicy(kind), {
      code: "ERR_INVALID_PLAN_EXECUTION_STATE",
    });
  }
  for (const kind of ["commit", "custom"]) {
    assert.throws(
      () => canonicalExecutionPlan("x".repeat(MAX_PLAN_LENGTH + 1), kind),
      { code: "ERR_INVALID_EXECUTION_PLAN" },
    );
  }
});

test("custom context carries agreed conditions and declarations without commit requirements", () => {
  const policy = planKindPolicy("custom");
  const step = policy.parse(customPlan).steps[0];
  const context = policy.stepContext(customPlan, step);
  assert.ok(context.includes(`## Step 1: ${step.title}`));
  assert.ok(context.includes(step.work));
  assert.ok(context.includes(step.expectedResults));
  assert.ok(context.includes('"id":"source-coverage"'));
  assert.ok(context.includes('"condition":"Identify every supplied source."'));
  assert.ok(context.includes('"outputs":[]'));
  assert.ok(context.includes("https://example.invalid/reference"));
  assert.equal(context.includes("Current planned commit"), false);

  const before = "a".repeat(64);
  assert.equal(policy.acceptsInitialResult(before, before), true);
  assert.equal(
    planKindPolicy("commit").acceptsInitialResult(before, before),
    false,
  );
  assert.equal(
    planKindPolicy("commit").acceptsInitialResult(before, "b".repeat(64)),
    true,
  );
});

test("custom inspection uses the bound directory snapshot and cannot obtain Git effects", async () => {
  const policy = planKindPolicy("custom");
  const snapshot = {
    workspacePath: "/workspace",
    contentFingerprint: "snapshot",
  };
  let snapshots = 0;
  const safety = new Proxy(
    {
      async snapshot() {
        snapshots += 1;
        return snapshot;
      },
    },
    {
      get(target, key) {
        assert.equal(
          key,
          "snapshot",
          "custom inspection attempted a Git operation",
        );
        return target[key];
      },
    },
  );
  assert.deepEqual(await policy.inspectWorkspace({ git: safety }), {
    snapshot,
  });
  assert.equal(await policy.inspectPlanPosition({ git: safety }), null);
  assert.equal(snapshots, 1);
  // Even a fully capable supplied Git service cannot grant this policy effects.
  const runtime = new Proxy(
    {},
    {
      get() {
        assert.fail("read Git authority");
      },
    },
  );
  assert.throws(() => policy.commitService(runtime), {
    code: "ERR_PLAN_KIND_EFFECT_FORBIDDEN",
  });
  assert.deepEqual(policy.workspace, { kind: "directory", lease: "exclusive" });
  assert.equal(policy.terminalState, null);
  assert.deepEqual(policy.roleAccess.worker, ["read-only", "workspace-write"]);
  for (const role of ["reviewer", "arbiter"])
    assert.deepEqual(policy.roleAccess[role], ["read-only"]);
  assert.deepEqual(planExecutionPipeline.workspace, {
    kind: "git",
    lease: "exclusive",
  });
  assert.ok(planExecutionPipeline.roleAccess.worker.includes("local-commit"));
});

test("kind-specific runtime and provider requirements do not demand custom commit authority", () => {
  const noop = () => {};
  const runtime = {
    adapters: { worker: { probe: noop, run: noop } },
    clarifications: Object.fromEntries(
      [
        "acceptEdit",
        "appendProductDecision",
        "appendQuestionRound",
        "ensureTranscript",
        "freezeTranscript",
        "inspectTranscript",
        "openEditor",
        "prepareEdit",
      ].map((name) => [name, noop]),
    ),
    git: { assertUnchanged: noop, inspectPath: noop, snapshot: noop },
    trustedValidation: { execute: noop, preflight: noop },
    finishAgentTurn: noop,
    readInputs: noop,
    recordChildSession: noop,
    startAgentTurn: noop,
    transition: noop,
    writeRunArtifact: noop,
  };
  assert.doesNotThrow(() => assertRuntime(runtime, ["worker"], "custom"));
  assert.throws(
    () => assertRuntime(runtime, ["worker"], "commit"),
    /settleVerifiedCommit/u,
  );
  const capabilities = {
    version: "fixture",
    structuredOutput: true,
    readOnly: true,
    autonomousWrite: true,
    workspaceWrite: true,
    remoteWriteBlocked: true,
    declaredWorkspace: true,
  };
  assert.deepEqual(
    normalizeAdapterCapabilities(capabilities, "worker", null, "custom"),
    {
      version: "fixture",
    },
  );
  assert.throws(
    () => normalizeAdapterCapabilities(capabilities, "worker", null, "commit"),
    {
      code: "ERR_UNSUPPORTED_PLAN_EXECUTION_BACKEND",
    },
  );
  assert.throws(
    () =>
      normalizeAdapterCapabilities(
        { ...capabilities, declaredWorkspace: false },
        "worker",
        null,
        "custom",
      ),
    {
      code: "ERR_UNSUPPORTED_PLAN_EXECUTION_BACKEND",
    },
  );
});

test("persisted kind is explicit and custom execution cannot start through internal entry points", async (t) => {
  const initial = createPlanExecutionState();
  assert.equal(initial.planKind, "commit");
  const { planKind: _kind, ...legacy } = initial;
  assert.throws(() => normalizePipelineState(legacy), {
    code: "ERR_INVALID_PLAN_EXECUTION_STATE",
  });
  for (const planKind of [null, undefined, "unknown"]) {
    assert.throws(() => normalizePipelineState({ ...initial, planKind }), {
      code: "ERR_INVALID_PLAN_EXECUTION_STATE",
    });
  }
  assert.equal(
    Object.hasOwn(planExecutionPipeline.settings, "planKind"),
    false,
  );
  assert.equal(planExecutionPipeline.runOptions.includes("planKind"), false);
  assert.throws(() => createPlanExecutionState({ planKind: "custom" }), {
    code: "ERR_CUSTOM_EXECUTION_INACTIVE",
  });
  const fixture = await createFixture(t);
  await assert.rejects(
    runPlanExecution({
      run: {
        ...fixture.currentRun,
        pipelineState: { ...initial, planKind: "custom" },
      },
      runtime: new Proxy(
        {},
        {
          get() {
            assert.fail("custom runtime was accessed");
          },
        },
      ),
    }),
    { code: "ERR_CUSTOM_EXECUTION_INACTIVE" },
  );
});

for (const mode of ["independent", "lazy", "combined"]) {
  test(`${mode} kind migration preserves a consumed commit for verification-only recovery`, async (t) => {
    let interrupted = false;
    const fixture = await createFixture(t, {
      mode,
      workWorker: [
        implementationCompleted(),
        ...(mode === "independent" ? [] : [checkAndFix()]),
        finalizationPassed(),
      ],
      onCommitVerify() {
        if (!interrupted) {
          interrupted = true;
          throw new Error("Verification interrupted");
        }
      },
    });
    const paused = await fixture.run();
    assert.equal(paused.pipelineState.pendingCommit.status, "consumed");
    const calls = Object.values(fixture.calls).flat().length;
    const { planKind: _kind, ...legacy } = paused.pipelineState;
    const saved = structuredClone(legacy);
    const migrated = migratePlanExecutionStateV32({ pipelineState: legacy });
    assert.deepEqual(legacy, saved);
    assert.deepEqual(migrated, { ...saved, planKind: "commit" });
    assert.ok(Object.isFrozen(migrated));
    assert.doesNotThrow(() => normalizePipelineState(migrated));
    fixture.persistPipelineState(migrated);
    const done = await fixture.run();
    assert.equal(
      done.pipelineState.workflowState,
      "DONE",
      JSON.stringify(done.pause),
    );
    assert.equal(done.pipelineState.completedCommits.length, 1);
    assert.equal(Object.values(fixture.calls).flat().length, calls);
    assert.deepEqual(done.counters, paused.counters);
    assert.equal(
      done.pipelineState.commitSizeAssessment.eligible,
      paused.pipelineState.commitSizeAssessment.eligible,
    );
  });
}
