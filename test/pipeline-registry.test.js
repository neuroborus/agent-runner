import assert from "node:assert/strict";
import test from "node:test";

import * as planAuthoringApi from "@agent-runner/plan-authoring";
import * as planExecutionApi from "@agent-runner/plan-execution";
import * as polishingApi from "@agent-runner/polishing";

import {
  createDetachedRuntimeCompatibilityToken,
  DETACHED_RUNTIME_COMPATIBILITY_TOKEN,
  getPipeline,
  listPipelines,
  RUNTIME_COMPATIBILITY,
} from "../src/index.js";

test("detached compatibility canonically binds every pipeline state version", () => {
  const pipelines = listPipelines();
  assert.equal(
    createDetachedRuntimeCompatibilityToken({
      pipelines: [...pipelines].reverse(),
    }),
    DETACHED_RUNTIME_COMPATIBILITY_TOKEN,
  );

  const previousExecutionVersion = pipelines.map((pipeline) =>
    pipeline.id === "plan-execution"
      ? { ...pipeline, stateVersion: pipeline.stateVersion - 1 }
      : pipeline,
  );
  assert.notEqual(
    createDetachedRuntimeCompatibilityToken({
      pipelines: previousExecutionVersion,
    }),
    DETACHED_RUNTIME_COMPATIBILITY_TOKEN,
  );
  assert.notEqual(
    createDetachedRuntimeCompatibilityToken({
      runtimeCompatibility: {
        ...RUNTIME_COMPATIBILITY,
        runStateVersion: RUNTIME_COMPATIBILITY.runStateVersion + 1,
      },
    }),
    DETACHED_RUNTIME_COMPATIBILITY_TOKEN,
  );
});

test("registry exposes explicit immutable pipeline descriptors", () => {
  const pipelines = listPipelines();

  assert.deepEqual(
    pipelines.map((pipeline) => pipeline.id),
    ["plan-authoring", "plan-execution", "polishing"],
  );

  for (const pipeline of pipelines) {
    assert.equal(getPipeline(pipeline.id), pipeline);
    assert.ok(Number.isSafeInteger(pipeline.stateVersion));
    assert.ok(pipeline.stateVersion > 0);
    assert.ok(Object.isFrozen(pipeline.migrations));
    assert.ok(
      Object.entries(pipeline.migrations).every(
        ([version, migration]) =>
          /^[1-9][0-9]*$/u.test(version) &&
          Number(version) < pipeline.stateVersion &&
          typeof migration === "function",
      ),
    );
    assert.ok(Object.isFrozen(pipeline));
    assert.ok(Object.isFrozen(pipeline.roles));
    assert.ok(Object.isFrozen(pipeline.settings));
    assert.ok(Object.isFrozen(pipeline.taskInputs));
    assert.ok(Object.isFrozen(pipeline.projections));
    assert.ok(Object.isFrozen(pipeline.runOptions));
    assert.ok(Object.isFrozen(pipeline.requiredRunOptions));
    assert.equal(typeof pipeline.projections.clarification, "function");
    assert.equal(typeof pipeline.projections.pause, "function");
    assert.equal(typeof pipeline.projections.status, "function");
    assert.equal(typeof pipeline.validateResumeAction, "function");
    for (const definition of Object.values(pipeline.taskInputs)) {
      assert.ok(Object.isFrozen(definition));
      assert.equal(typeof definition.filename, "string");
      assert.equal(typeof definition.optional, "boolean");
    }
    for (const role of pipeline.roles) {
      assert.ok(pipeline.runOptions.includes(role));
    }
    for (const setting of Object.values(pipeline.settings)) {
      assert.ok(Object.isFrozen(setting));
      assert.equal(typeof setting.errorMessage, "string");
      assert.ok(setting.validate(setting.defaultValue));
    }
    for (const option of pipeline.requiredRunOptions) {
      assert.ok(pipeline.runOptions.includes(option));
    }
  }
});

function pausedRun(pause, pipelineState = {}) {
  return {
    pause,
    pipelineState: {
      workflowState: "WAITING_FOR_USER",
      pendingEdit: null,
      preflightComplete: true,
      ...pipelineState,
    },
  };
}

test("pipeline pause projections preserve bounded details and redact private fields", () => {
  const pipeline = getPipeline("plan-execution");
  const projected = pipeline.projections.pause(
    pausedRun({
      reason: "environment_blocked",
      code: "ERR_LOOPBACK_UNAVAILABLE",
      explanation: "Check C2 cannot bind a loopback listener.",
      evidence: ["C2: listener creation was denied."],
      resumeState: "IMPLEMENT",
      prompt: "private prompt",
      transcript: "private transcript",
      credentials: "private credentials",
      nativeResponse: "private native response",
      rawStderr: "private stderr",
    }),
  );

  assert.deepEqual(projected, {
    reason: "environment_blocked",
    code: "ERR_LOOPBACK_UNAVAILABLE",
    explanation: "Check C2 cannot bind a loopback listener.",
    evidence: ["C2: listener creation was denied."],
    resumeState: "IMPLEMENT",
    nextActions: [{ type: "resume", action: null }],
  });
  const serialized = JSON.stringify(projected);
  for (const privateValue of [
    "private prompt",
    "private transcript",
    "private credentials",
    "private native response",
    "private stderr",
  ]) {
    assert.doesNotMatch(serialized, new RegExp(privateValue, "u"));
  }
  assert.ok(Object.isFrozen(projected));
  assert.ok(Object.isFrozen(projected.evidence));
  assert.ok(Object.isFrozen(projected.nextActions));

  for (const pipelineId of [
    "plan-authoring",
    "plan-execution",
    "polishing",
  ]) {
    assert.deepEqual(
      getPipeline(pipelineId).projections.pause(
        pausedRun({
          reason: "__proto__",
          code: "ERR_PRIVATE_PROVIDER_DETAIL",
          explanation: "private unknown explanation",
          evidence: ["private unknown evidence"],
          resumeState: "private unknown state",
        }),
      ),
      {
        reason: "unknown_pause",
        code: null,
        explanation: "No public diagnostic is available for this pause.",
        evidence: [],
        resumeState: null,
        nextActions: [],
      },
    );
  }
});

test("every pipeline projects bounded adapter diagnostics", () => {
  for (const [pipelineId, explanation] of [
    ["plan-authoring", "Plan authoring failed."],
    ["plan-execution", "Plan execution failed."],
    ["polishing", "Polishing failed."],
  ]) {
    assert.deepEqual(
      getPipeline(pipelineId).projections.pause(
        pausedRun(
          {
            reason: "internal_failure",
            code: "ERR_CODEX_ISOLATION",
            diagnosticClass: "operation_multi_agent",
          },
          { workflowState: "FAILED" },
        ),
      ),
      {
        reason: "internal_failure",
        code: "ERR_CODEX_ISOLATION",
        explanation:
          `${explanation} Adapter diagnostic: operation_multi_agent.`,
        evidence: [],
        resumeState: null,
        nextActions: [],
      },
    );
  }
});

test("plan-execution pause projection distinguishes fresh-run requirements", () => {
  const projectPause = getPipeline("plan-execution").projections.pause;

  assert.deepEqual(
    projectPause(
      pausedRun({
        reason: "plan_revision_required",
        explanation: "Commit 2 conflicts with the accepted clarification.",
        evidence: ["The plan requires the opposite behavior."],
      }),
    ),
    {
      reason: "plan_revision_required",
      code: null,
      explanation: "Commit 2 conflicts with the accepted clarification.",
      evidence: ["The plan requires the opposite behavior."],
      resumeState: null,
      nextActions: [
        { type: "start-new-run", requirement: "revised-plan" },
      ],
    },
  );

  assert.deepEqual(
    projectPause(
      pausedRun({
        reason: "read_only_agent_mutated_repository",
        code: "ERR_READ_ONLY_REPOSITORY_CHANGED",
      }),
    ),
    {
      reason: "read_only_agent_mutated_repository",
      code: "ERR_READ_ONLY_REPOSITORY_CHANGED",
      explanation:
        "A read-only turn contaminated the repository; abandon this run and restart from an uncontaminated worktree.",
      evidence: [],
      resumeState: null,
      nextActions: [
        {
          type: "start-new-run",
          requirement: "uncontaminated-worktree",
        },
      ],
    },
  );
});

test("pipeline pause projections expose only applicable response and resume actions", () => {
  const executionPause = getPipeline("plan-execution").projections.pause;
  const polishingPause = getPipeline("polishing").projections.pause;
  const authoringPause = getPipeline("plan-authoring").projections.pause;

  assert.deepEqual(
    authoringPause(
      pausedRun(
        {
          reason: "clarification_answers_required",
          inputRequest: { id: "edit-1" },
        },
        { pendingEdit: { id: "edit-1" } },
      ),
    ).nextActions,
    [{ type: "respond", requestId: "edit-1" }],
  );

  const findingState = {
    additionalFixRounds: 0,
    settings: { maxFixRoundsPerStep: 5 },
    finalizationResult: { status: "PASS" },
    reviewedFingerprint: "a".repeat(64),
    findings: [{ id: "R1" }, { id: "R2" }],
    findingOverrides: [],
  };
  assert.deepEqual(
    executionPause(
      pausedRun(
        { reason: "fix_limit_reached", resumeState: "IMPLEMENT" },
        findingState,
      ),
    ).nextActions,
    [
      {
        type: "resume",
        action: { type: "extra-fix-rounds", amount: 1 },
      },
      {
        type: "resume",
        action: { type: "override-finding", findingId: "R1" },
      },
      {
        type: "resume",
        action: { type: "override-finding", findingId: "R2" },
      },
    ],
  );

  assert.deepEqual(
    polishingPause(
      pausedRun(
        { reason: "backend_unavailable", resumeState: "POLISH" },
        { findings: [] },
      ),
    ).nextActions,
    [{ type: "resume", action: null }],
  );

  assert.deepEqual(
    executionPause(
      pausedRun(
        {
          reason: "clarification_answers_required",
          inputRequest: { id: "edit-2" },
          inputResponse: { requestId: "edit-2" },
        },
        { pendingEdit: { id: "edit-2" } },
      ),
    ).nextActions,
    [],
  );
});

test("pipelines own their pipeline-specific run options", () => {
  assert.deepEqual(getPipeline("plan-authoring").roles, [
    "planner",
    "reviewer",
    "arbiter",
  ]);
  assert.deepEqual(getPipeline("plan-execution").roles, [
    "worker",
    "reviewer",
    "arbiter",
  ]);
  assert.deepEqual(getPipeline("polishing").roles, [
    "worker",
    "reviewer",
    "arbiter",
  ]);
  assert.deepEqual(getPipeline("plan-authoring").runOptions, [
    "project",
    "task",
    "planner",
    "reviewer",
    "arbiter",
  ]);
  assert.deepEqual(getPipeline("plan-execution").runOptions, [
    "project",
    "task",
    "worker",
    "reviewer",
    "arbiter",
  ]);
  assert.deepEqual(getPipeline("polishing").runOptions, [
    "project",
    "task",
    "worker",
    "reviewer",
    "arbiter",
  ]);
  assert.deepEqual(getPipeline("plan-authoring").requiredRunOptions, [
    "project",
    "task",
  ]);
  assert.equal(
    typeof getPipeline("plan-authoring").workflow.createState,
    "function",
  );
  assert.equal(typeof getPipeline("plan-authoring").workflow.run, "function");
  assert.equal(
    typeof getPipeline("plan-authoring").workflow.validateRun,
    "function",
  );
  assert.ok(Object.isFrozen(getPipeline("plan-authoring").workflow));
  assert.deepEqual(getPipeline("plan-execution").requiredRunOptions, [
    "project",
    "task",
  ]);
  assert.equal(
    typeof getPipeline("plan-execution").workflow.createState,
    "function",
  );
  assert.equal(typeof getPipeline("plan-execution").workflow.run, "function");
  assert.equal(
    typeof getPipeline("plan-execution").workflow.validateRun,
    "function",
  );
  assert.ok(Object.isFrozen(getPipeline("plan-execution").workflow));
  assert.deepEqual(getPipeline("polishing").requiredRunOptions, [
    "project",
    "task",
  ]);
  assert.equal(typeof getPipeline("polishing").workflow.createState, "function");
  assert.equal(typeof getPipeline("polishing").workflow.run, "function");
  assert.equal(
    typeof getPipeline("polishing").workflow.validateRun,
    "function",
  );
  assert.ok(Object.isFrozen(getPipeline("polishing").workflow));
  assert.equal(getPipeline("unknown"), undefined);
});

test("pipelines do not duplicate the shared validation API", () => {
  assert.equal("assertCommitSubject" in planAuthoringApi, false);
  assert.equal("assertCommitSubject" in planExecutionApi, false);
  assert.equal("assertCommitSubject" in polishingApi, false);
});
