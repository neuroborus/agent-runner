import assert from "node:assert/strict";
import test from "node:test";

import { serializeCustomPlan } from "@agent-runner/custom-plan";
import {
  createPlanExecutionState,
  migratePlanExecutionStateV32,
  planExecutionPipeline,
} from "../src/index.js";
import {
  canonicalExecutionPlan,
  MAX_PLAN_LENGTH,
  planKindPolicy,
} from "../src/step-policy.js";
import {
  customExecutionPrompt,
  APPLICABILITY_INSTRUCTIONS,
  BOOTSTRAP_INSTRUCTIONS,
  CHECK_AND_FIX_INSTRUCTIONS,
  FINALIZATION_INSTRUCTIONS,
  IMPLEMENTATION_INSTRUCTIONS,
} from "../src/prompts.js";
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

test("custom instructions preserve frozen task, criteria and evidence text verbatim", () => {
  const context =
    "\n\nTask data: preserve the literal COMMIT token and planned commit wording.\nCriteria: Staging, index inspection belong only to COMMIT.\nEvidence: authorized commit.";
  for (const instructions of [
    IMPLEMENTATION_INSTRUCTIONS,
    FINALIZATION_INSTRUCTIONS,
  ]) {
    const prompt = customExecutionPrompt(instructions + context);
    assert.ok(prompt.endsWith(context));
    assert.notEqual(prompt, instructions + context);
    assert.equal(
      prompt.slice(0, -context.length).includes("executor alone runs git add"),
      false,
    );
  }
});

test("custom bootstrap derives checks from criteria without a mandatory coding gate", () => {
  for (const instructions of [
    BOOTSTRAP_INSTRUCTIONS,
    APPLICABILITY_INSTRUCTIONS,
  ]) {
    const context =
      "\n\nCriterion data: preserve the ordinary fast gate wording.";
    const prompt = customExecutionPrompt(instructions + context);
    assert.ok(prompt.endsWith(context));
    assert.equal(
      prompt.slice(0, -context.length).includes("ordinary fast gate"),
      false,
    );
    assert.ok(
      prompt.includes("semantic-only steps may have no executable checks"),
    );
    assert.equal(
      prompt.includes("commit preparation belongs only to ACCEPT"),
      false,
    );
    assert.equal(prompt.includes("against HEAD or explicit trees"), false);
    assert.ok(instructions.includes("ordinary fast gate"));
  }
});

test("custom check/fix status accounts for result-only repairs without rewriting task data", () => {
  const changed = "For CHANGED, use only when you changed repository content;";
  const unchanged =
    "For UNCHANGED, use only when you found no problem and changed no repository content;";
  const context = `\n\nTask data: ${changed}\n${unchanged}`;
  const prompt = customExecutionPrompt(CHECK_AND_FIX_INSTRUCTIONS + context);
  const instructions = prompt.slice(0, -context.length);
  assert.ok(prompt.endsWith(context));
  assert.equal(instructions.includes(changed), false);
  assert.equal(instructions.includes(unchanged), false);
  assert.ok(instructions.includes("changed workspace content or result data"));
  assert.ok(
    instructions.includes("changed neither workspace content nor result data"),
  );
  assert.ok(CHECK_AND_FIX_INSTRUCTIONS.includes(changed));
  assert.ok(CHECK_AND_FIX_INSTRUCTIONS.includes(unchanged));
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
  assert.deepEqual(
    await policy.inspectWorkspace({
      git: safety,
      projectPath: "/workspace",
      artifactRoot: "LOCAL_ARTIFACTS",
      runId: "run-1",
    }),
    {
      snapshot,
      clarificationPath:
        "/workspace/LOCAL_ARTIFACTS/agent-runner/run-1/clarifications.md",
    },
  );
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
  assert.equal(policy.terminalState, "ACCEPT");
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
    workspace: { assertUnchanged: noop, inspectPath: noop, snapshot: noop },
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

test("persisted kind stays explicit and public custom selection grants no commit access", () => {
  const initial = createPlanExecutionState();
  assert.equal(initial.planKind, "commit");
  const { planKind: _kind, ...legacy } = initial;
  assert.throws(() => normalizePipelineState(legacy));
  for (const planKind of [null, undefined, "unknown"])
    assert.throws(() => normalizePipelineState({ ...initial, planKind }));
  assert.equal(planExecutionPipeline.settings.planKind.defaultValue, "commit");
  assert.ok(planExecutionPipeline.runOptions.includes("plan-kind"));
  const custom = createPlanExecutionState({ planKind: "custom" });
  assert.equal(custom.planKind, "custom");
  assert.equal(custom.commitSizeAssessment.eligible, false);
  assert.throws(() =>
    planExecutionPipeline.migrations[34]({ pipelineState: custom }),
  );
  for (const change of [
    { workflowState: "COMMIT" },
    { pendingCommit: {} },
    { completedCommits: ["a".repeat(40)] },
  ])
    assert.throws(() => normalizePipelineState({ ...custom, ...change }));
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
    for (const missing of ["finalization", "trustedChecks"]) {
      const legacySettings = structuredClone(migrated);
      delete legacySettings.customCandidate;
      delete legacySettings.settings.planKind;
      delete legacySettings.settings[missing];
      const upgraded = planExecutionPipeline.migrations[34]({
        pipelineState: legacySettings,
      });
      assert.deepEqual(normalizePipelineState(upgraded), migrated);
    }
    const legacy34 = structuredClone(migrated);
    delete legacy34.customCandidate;
    delete legacy34.settings.planKind;
    const upgraded = planExecutionPipeline.migrations[34]({
      pipelineState: legacy34,
    });
    fixture.persistPipelineState(normalizePipelineState(upgraded));
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
