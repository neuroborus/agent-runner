import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import {
  bootstrapReady,
  checkAndFix,
  clarificationReady,
  createFixture,
  environmentBlocked,
  finalizationWithTrustedCheck,
  implementationCompleted,
  reconciliationResolved,
  trustedValidationSnapshot,
} from "./support/index.js";

async function retryFixture(
  t,
  { mode = "lazy", outcomes = ["FAIL", "FAIL", "PASS"], mixed = false } = {},
) {
  const trustedValidation = trustedValidationSnapshot();
  const finalization = finalizationWithTrustedCheck(trustedValidation);
  if (mixed) {
    finalization.status = "FAIL";
    finalization.checks[0].status = "FAIL";
    finalization.issues = [
      {
        id: "F1",
        // Even an agent issue naming the trusted command must remain a blocker.
        command: trustedValidation.commands[0].command,
        problem: "The Worker identified a concrete content defect.",
        evidence: ["The implementation does not handle missing input."],
      },
    ];
  }
  const bootstrap = (role) => ({
    ...bootstrapReady(role),
    requiredChecks: finalization.requiredChecks,
  });
  const blocked = () =>
    environmentBlocked(
      "The available evidence does not identify a safe content repair.",
      "Trusted native output is unavailable; complete finalization is required.",
    );
  const executions = [];
  const turns = [];
  const fixture = await createFixture(t, {
    mode,
    modeSettings: { trustedChecks: ["service-check"] },
    trustedValidation,
    worker: [
      clarificationReady(),
      bootstrap("Worker"),
      ...(mode === "lazy" ? [] : [reconciliationResolved()]),
    ],
    reviewer: [bootstrap("Reviewer")],
    workWorker: [
      implementationCompleted(),
      checkAndFix(),
      ...outcomes.flatMap(() => [structuredClone(finalization), blocked()]),
      blocked(),
    ],
    onRoleRun(role, request) {
      turns.push([role, fixture.currentRun.activeTurn.phase, request.access]);
    },
    onTrustedValidation(options) {
      const status = outcomes[executions.length];
      assert.notEqual(status, undefined, "Unexpected trusted retry.");
      executions.push(options);
      return {
        status,
        commandIdentity: options.commandIdentity,
        exitCode: status === "FAIL" ? 7 : 0,
        signal: null,
        timedOut: false,
        evidence: [
          `Runner-trusted command exited with code ${status === "FAIL" ? 7 : 0}.`,
        ],
        ...options.bindings,
      };
    },
  });
  return { fixture, executions, turns };
}

for (const mode of ["lazy", "independent", "combined"]) {
  test(`${mode} opaque trusted failures need one explicit resume per complete finalization retry`, async (t) => {
    const { fixture, executions, turns } = await retryFixture(t, { mode });
    const first = await fixture.run({ trustedChecks: ["service-check"] });
    assert.equal(first.pause.reason, "environment_blocked");
    assert.equal(first.pause.resumeState, "RESOLVE_FINDINGS");
    assert.equal(executions.length, 1);
    const before = turns.length;

    const repeated = await fixture.run({}, null);
    assert.equal(repeated.pause.reason, "environment_blocked");
    assert.equal(repeated.pause.resumeState, "RESOLVE_FINDINGS");
    assert.equal(executions.length, 2);
    assert.deepEqual(turns.slice(before), [
      ["worker", "finalize", "workspace-write"],
      ["worker", "resolve-findings", "workspace-write"],
    ]);
    assert.deepEqual(repeated.counters, first.counters);
    assert.deepEqual(
      repeated.pipelineState.correctionHistory,
      first.pipelineState.correctionHistory,
    );
    assert.deepEqual(
      repeated.pipelineState.candidateReviewResult,
      first.pipelineState.candidateReviewResult,
    );
    assert.equal(repeated.pipelineState.finalizedFingerprint, null);
    assert.equal(repeated.pipelineState.reviewResult, null);

    const retryStart = turns.length;
    const completed = await fixture.run({}, null);
    assert.equal(completed.pipelineState.workflowState, "DONE");
    assert.equal(executions.length, 3);
    assert.deepEqual(
      executions.map(({ bindings }) => bindings),
      [executions[0].bindings, executions[0].bindings, executions[0].bindings],
    );
    assert.deepEqual(turns.slice(retryStart), [
      ["worker", "finalize", "workspace-write"],
      [mode === "lazy" ? "worker" : "reviewer", "confirm", "read-only"],
      ["worker", "commit", "local-commit"],
    ]);
    assert.deepEqual(completed.counters, first.counters);
    assert.equal(fixture.calls.arbiter.length, 0);
    if (mode === "lazy") assert.equal(fixture.calls.reviewer.length, 0);
  });
}

for (const trustedOutcome of ["FAIL", "PASS"]) {
  test(`agent blockers with trusted ${trustedOutcome} resume resolution without executing finalization`, async (t) => {
    const { fixture, executions, turns } = await retryFixture(t, {
      mixed: true,
      outcomes: [trustedOutcome],
    });
    const first = await fixture.run();
    assert.equal(first.pause.reason, "environment_blocked");
    assert.equal(
      first.pipelineState.finalizationResult.issues.length,
      trustedOutcome === "FAIL" ? 2 : 1,
    );
    const before = turns.length;
    const resumed = await fixture.run({}, null);
    assert.equal(resumed.pause.resumeState, "RESOLVE_FINDINGS");
    assert.equal(executions.length, 1);
    assert.deepEqual(turns.slice(before), [
      ["worker", "resolve-findings", "workspace-write"],
    ]);
    assert.deepEqual(
      resumed.pipelineState.finalizationResult,
      first.pipelineState.finalizationResult,
    );
    assert.deepEqual(resumed.counters, first.counters);
  });
}

test("an additional persisted issue on the failed trusted command excludes retry", async (t) => {
  const { fixture, executions, turns } = await retryFixture(t, {
    outcomes: ["FAIL"],
  });
  const first = await fixture.run();
  const finalization = first.pipelineState.finalizationResult;
  fixture.persistPipelineState({
    ...first.pipelineState,
    finalizationResult: {
      ...finalization,
      issues: [
        ...finalization.issues,
        {
          ...finalization.issues[0],
          id: "F2",
          problem:
            "An agent-authored issue on the same command remains unresolved.",
        },
      ],
    },
  });
  const before = turns.length;
  const resumed = await fixture.run({}, null);
  assert.equal(resumed.pause.resumeState, "RESOLVE_FINDINGS");
  assert.equal(resumed.pipelineState.finalizationResult.issues.length, 2);
  assert.equal(executions.length, 1);
  assert.deepEqual(turns.slice(before), [
    ["worker", "resolve-findings", "workspace-write"],
  ]);
});

test("opaque trusted retry rejects external content changes before any agent or check runs", async (t) => {
  const { fixture, executions, turns } = await retryFixture(t);
  await fixture.run();
  const before = turns.length;
  await writeFile(join(fixture.projectPath, "external.txt"), "changed\n");
  const resumed = await fixture.run({}, null);
  assert.equal(resumed.pause.reason, "unsafe_git_state");
  assert.equal(turns.length, before);
  assert.equal(executions.length, 1);
});

test("opaque trusted retry rejects validation-infrastructure drift on unchanged content", async (t) => {
  const { fixture, executions, turns } = await retryFixture(t);
  const first = await fixture.run();
  const before = turns.length;
  const fingerprint = fixture.runtime.git.validationInfrastructureFingerprint;
  fixture.runtime.git.validationInfrastructureFingerprint = async (options) =>
    options.paths.includes("package.json")
      ? "f".repeat(64)
      : fingerprint(options);
  const resumed = await fixture.run({}, null);
  assert.equal(resumed.pause.reason, "unsafe_git_state");
  assert.equal(resumed.pause.code, "ERR_TRUSTED_VALIDATION_BINDING_CHANGED");
  assert.equal(
    resumed.pipelineState.repositoryBaseline.contentFingerprint,
    first.pipelineState.repositoryBaseline.contentFingerprint,
  );
  assert.equal(turns.length, before);
  assert.equal(executions.length, 1);
});
