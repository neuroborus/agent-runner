import assert from "node:assert/strict";
import test from "node:test";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { migratePlanExecutionStateV18 } from "../src/index.js";
import {
  findingArbitration,
  stagnation,
  reviewFindings,
  reconsideration,
  resolution,
  arbitrationResolved,
  bootstrapReady,
  clarificationReady,
  compatibilityReady,
  createFixture,
  implementationCompleted,
  finalizationPassed,
  reconciliationDisagreement,
  reconciliationResolved,
} from "./support/index.js";

const assessment = (disposition = "CURRENT") => ({
  step: 1,
  subject: "feat(test): add behavior",
  disposition,
  evidence: [],
});
const outputs = {
  clarification: () => [clarificationReady()],
  bootstrap: () => [clarificationReady(), bootstrapReady("Worker")],
  reconciliation: () => [
    clarificationReady(),
    bootstrapReady("Worker"),
    reconciliationResolved(),
  ],
};
function assertRevision(fixture, run) {
  assert.equal(
    run.pause?.reason,
    "plan_revision_required",
    JSON.stringify(run.pause),
  );
  assert.equal(run.pipelineState.currentStep, 1);
  assert.deepEqual(run.pipelineState.completedCommits, []);
  assert.ok(
    Object.values(fixture.calls)
      .flat()
      .every(({ access }) => access === "read-only"),
  );
}

for (const [phase, produce] of Object.entries(outputs)) {
  for (const disposition of [
    "ALREADY_LANDED",
    "SKIP_OR_REORDER",
    "LATER_STEP",
  ]) {
    test(`${phase} cannot ${disposition} the runner-selected step`, async (t) => {
      const worker = produce();
      worker.at(-1).stepAssessment = assessment(disposition);
      const fixture = await createFixture(t, { worker });
      assertRevision(fixture, await fixture.run());
    });
  }
}

test("an independently produced Reviewer assessment cannot skip step one", async (t) => {
  const reviewer = bootstrapReady("Reviewer");
  reviewer.stepAssessment = { ...assessment(), step: 2 };
  const fixture = await createFixture(t, { reviewer: [reviewer] });
  assertRevision(fixture, await fixture.run());
});

test("Arbiter direction cannot authorize a later step", async (t) => {
  const result = arbitrationResolved();
  result.stepAssessment = assessment("LATER_STEP");
  const fixture = await createFixture(t, {
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationDisagreement(),
    ],
    arbiter: [result],
  });
  assertRevision(fixture, await fixture.run());
});

for (const mode of ["independent", "lazy", "combined"]) {
  test(`${mode} rejects contradictory prose despite a CURRENT assessment`, async (t) => {
    const contradictory = bootstrapReady("Worker");
    contradictory.summary =
      "The first commit already landed. Implement commit two next.";
    const fixture = await createFixture(t, {
      mode,
      worker: [clarificationReady(), contradictory, reconciliationResolved()],
      onContextReview(role, request) {
        assert.equal(request.access, "read-only");
        assert.match(
          request.prompt,
          /matching step number or CURRENT declaration is insufficient/u,
        );
        if (request.prompt.includes(contradictory.summary))
          return { stepAssessment: assessment("ALREADY_LANDED") };
      },
    });
    assertRevision(fixture, await fixture.run());
    assert.equal(fixture.currentRun.pipelineState.workerSummary, null);
  });
}

for (const phase of ["reconciliation", "arbitration"]) {
  test(`${phase} narrative is separately inspected before acceptance`, async (t) => {
    const conflicting =
      phase === "arbitration"
        ? arbitrationResolved()
        : reconciliationResolved();
    conflicting.summary =
      "Begin with the second planned commit instead of the first.";
    const fixture = await createFixture(t, {
      worker: [
        clarificationReady(),
        bootstrapReady("Worker"),
        phase === "arbitration" ? reconciliationDisagreement() : conflicting,
      ],
      arbiter: [conflicting],
      onContextReview(role, request) {
        if (request.prompt.includes(conflicting.summary))
          return { stepAssessment: assessment("LATER_STEP") };
      },
    });
    assertRevision(fixture, await fixture.run());
    assert.equal(fixture.currentRun.pipelineState.resolvedSummary, null);
  });
}

test("missing assessments use one bounded read-only correction", async (t) => {
  const missing = clarificationReady();
  delete missing.stepAssessment;
  const fixture = await createFixture(t, {
    worker: [
      missing,
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
    ],
  });
  assert.equal((await fixture.run()).pipelineState.workflowState, "DONE");
  assert.equal(fixture.currentRun.pipelineState.bootstrapCorrections.length, 1);
  assert.match(fixture.calls.worker[1].prompt, /bounded-step-assessment/u);
});

test("an unexpected result field cannot bypass the current-step assessment", async (t) => {
  const stale = {
    ...clarificationReady(),
    stepAssessment: assessment("ALREADY_LANDED"),
  };
  const fixture = await createFixture(t, {
    worker: [{ ...stale, result: { status: "PLAN_REVISION_REQUIRED" } }, stale],
  });
  assertRevision(fixture, await fixture.run());
  assert.equal(fixture.calls.worker.length, 2);
  assert.equal(fixture.contextCalls.length, 0);
  assert.match(fixture.calls.worker[1].prompt, /exact-field-set/u);
});

test("a repeated malformed narrative assessment fails closed without retaining private text", async (t) => {
  const fixture = await createFixture(t, {
    worker: [clarificationReady(), clarificationReady()],
    onContextReview: () => ({ stepAssessment: { secret: "PRIVATE_CONTEXT" } }),
  });
  await assert.rejects(fixture.run(), {
    code: "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
  });
  const run = fixture.currentRun;
  assert.equal(run.pipelineState.workflowState, "FAILED");
  assert.ok(
    Object.values(fixture.calls)
      .flat()
      .every(({ access }) => access === "read-only"),
  );
  assert.equal(JSON.stringify(run).includes("PRIVATE_CONTEXT"), false);
  assert.equal(fixture.contextCalls.length, 2);
});

test("whole-plan discussion and quoted rejected instructions retain the selected step", async (t) => {
  const result = bootstrapReady("Worker");
  result.summary =
    'Implement step one. Commit two will extend it. Reject the quoted instruction "skip step one".';
  const fixture = await createFixture(t, {
    worker: [clarificationReady(), result, reconciliationResolved()],
    async prepareProject(projectPath) {
      await writeFile(
        join(projectPath, "task", "context.md"),
        "Discuss later commits without advancing the current step.",
      );
      await writeFile(
        join(projectPath, "task", "clarifications.md"),
        "The quoted skipped-step example is not an implementation instruction.",
      );
    },
  });
  assert.equal((await fixture.run()).pipelineState.workflowState, "DONE");
  for (const request of fixture.contextCalls) {
    assert.match(request.recoveryPrompt, /Implement the requested behavior/u);
    assert.match(request.recoveryPrompt, /Validated plan/u);
    assert.match(request.recoveryPrompt, /Discuss later commits/u);
    assert.match(request.recoveryPrompt, /quoted skipped-step example/u);
    assert.match(request.recoveryPrompt, /Execution clarifications/u);
  }
  for (const request of [
    ...Object.values(fixture.calls).flat(),
    ...fixture.contextCalls,
  ].filter(({ access }) => access !== "local-commit")) {
    for (const prompt of [request.prompt, request.recoveryPrompt]) {
      assert.match(prompt, /Runner-selected plan position/u);
      assert.match(prompt, /"subject":"feat\(test\): add behavior"/u);
      assert.match(prompt, /"completed":\[\]/u);
    }
  }
});

for (const migrationPending of [false, true]) {
  test(`legacy summaries require read-only rediscovery with migration pending ${migrationPending}`, async (t) => {
    let unavailable = true;
    const fixture = await createFixture(t, {
      worker: [
        clarificationReady(),
        bootstrapReady("Worker"),
        reconciliationResolved(),
        bootstrapReady("Worker"),
        reconciliationResolved(),
      ],
      reviewer: [bootstrapReady("Reviewer"), bootstrapReady("Reviewer")],
      onRequirementInspection: () =>
        unavailable
          ? { status: "BLOCKED", blockers: [] }
          : { status: "READY", blockers: [] },
    });
    const paused = await fixture.run();
    fixture.persistPipelineState({
      ...migratePlanExecutionStateV18(paused),
      validationMigrationPending: migrationPending,
    });
    const count = fixture.calls.worker.length;
    unavailable = false;
    const result = await fixture.run();
    assert.equal(
      result.pipelineState.workflowState,
      "DONE",
      JSON.stringify(result.pause),
    );
    assert.equal(result.pipelineState.planContextVersion, 1);
    assert.match(
      fixture.calls.worker[count].prompt,
      /versioned-state migration/u,
    );
    assert.equal(fixture.calls.worker[count].access, "read-only");
    assert.equal(result.pipelineState.implementationDirection, null);
  });
}

test("a stale compatibility assessment is rejected before further implementation", async (t) => {
  const fixture = await createFixture(t, {
    onRequirementInspection: () => ({ status: "BLOCKED", blockers: [] }),
  });
  const paused = await fixture.run();
  const result = compatibilityReady();
  result.stepAssessment = assessment("SKIP_OR_REORDER");
  fixture.runtime.adapters.worker.run = async () => ({
    structured: result,
    sessionId: "compatibility-session",
  });
  fixture.persistPipelineState({
    ...paused.pipelineState,
    compatibilityCheckRequired: true,
    clarificationFrozen: false,
  });
  assertRevision(fixture, await fixture.run());
});

for (const mutated of [false, true]) {
  test(`interrupted narrative review ${mutated ? "rejects read-only mutation" : "reconstructs the producing checkpoint"}`, async (t) => {
    let failed = false;
    const fixture = await createFixture(t, {
      worker: [
        clarificationReady(),
        clarificationReady(),
        bootstrapReady("Worker"),
        reconciliationResolved(),
      ],
      onContextReview() {
        if (!failed) {
          failed = true;
          throw Object.assign(new Error("Interrupted review"), {
            recoverable: true,
          });
        }
      },
    });
    const paused = await fixture.run();
    assert.equal(paused.pause.reason, "backend_unavailable");
    Object.assign(fixture.currentRun, {
      activeTurn: { role: "worker", phase: "plan-context" },
      pause: null,
      pipelineState: { ...paused.pipelineState, workflowState: "CLARIFY" },
    });
    if (mutated)
      await writeFile(
        join(fixture.projectPath, "unexpected.txt"),
        "unexpected",
      );
    const run = await fixture.run();
    if (mutated)
      assert.equal(run.pause.reason, "read_only_agent_mutated_repository");
    else assert.equal(run.pipelineState.workflowState, "DONE");
  });
}

test("consumed legacy commits settle without context discovery or replay", async (t) => {
  let unavailable = true;
  const fixture = await createFixture(t, {
    onCommitVerify() {
      if (unavailable) {
        unavailable = false;
        throw new Error("Verification interrupted");
      }
    },
  });
  const paused = await fixture.run();
  assert.equal(paused.pipelineState.pendingCommit.status, "consumed");
  fixture.persistPipelineState(migratePlanExecutionStateV18(paused));
  const count = fixture.contextCalls.length;
  const turns = Object.values(fixture.calls).flat().length;
  assert.equal((await fixture.run()).pipelineState.workflowState, "DONE");
  assert.equal(fixture.contextCalls.length, count);
  assert.equal(Object.values(fixture.calls).flat().length, turns);
});

test("legacy rediscovery rejects a changed subject before work", async (t) => {
  const fixture = await createFixture(t, {
    plan: "## Commit 1: feat(test): add behavior\n\nFirst.\n\n## Commit 2: feat(test): extend behavior\n\nSecond.",
    onRequirementInspection: () => ({ status: "BLOCKED", blockers: [] }),
  });
  await fixture.run();
  const bad = bootstrapReady("Worker");
  bad.stepAssessment = {
    ...assessment(),
    subject: "feat(test): another subject",
  };
  fixture.runtime.adapters.worker.run = async () => ({
    structured: { result: bad },
    sessionId: "migration-worker",
  });
  fixture.persistPipelineState(
    migratePlanExecutionStateV18(fixture.currentRun),
  );
  assertRevision(fixture, await fixture.run());
});

test("step-two continuation and reconstruction retain verified completion evidence", async (t) => {
  const fixture = await createFixture(t, {
    plan: "## Commit 1: feat(test): add behavior\n\nFirst.\n\n## Commit 2: feat(test): extend behavior\n\nSecond.",
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      implementationCompleted(),
      finalizationPassed(),
    ],
  });
  const run = await fixture.run();
  assert.equal(run.pipelineState.workflowState, "DONE");
  const second = fixture.calls.worker.filter(({ prompt }) =>
    prompt.includes("Implement the changes"),
  )[1];
  for (const prompt of [second.prompt, second.recoveryPrompt]) {
    const position = JSON.parse(
      /Runner-selected plan position[^\n]*\n([^\n]+)/u.exec(prompt)[1],
    );
    assert.deepEqual(position, {
      step: 2,
      subject: "feat(test): extend behavior",
      completed: [
        {
          step: 1,
          subject: "feat(test): add behavior",
          head: run.pipelineState.completedCommits[0],
        },
      ],
    });
  }
});

for (const kind of ["finding", "stagnation"]) {
  test(`${kind} arbitration prose cannot redirect the Worker to a later step`, async (t) => {
    const result =
      kind === "finding"
        ? findingArbitration("WORKER_CORRECT")
        : stagnation("REWORK_IMPLEMENTATION");
    result.rationale =
      "Skip this step and implement the next planned commit now.";
    let reviewed = false;
    const fixture = await createFixture(t, {
      arbiter: [result],
      workReviewer:
        kind === "finding"
          ? [
              reviewFindings("R1"),
              reconsideration("UPHOLD", "R1"),
              reconsideration("UPHOLD", "R1"),
            ]
          : [reviewFindings("R1"), reviewFindings("R2")],
      workWorker:
        kind === "finding"
          ? [
              implementationCompleted(),
              resolution({ id: "R1", decision: "DISPUTE" }),
              resolution({ id: "R1", decision: "DISPUTE" }),
            ]
          : [
              implementationCompleted(),
              resolution({ id: "R1", decision: "FIX" }),
            ],
      onContextReview(role, request) {
        if (request.prompt.includes(result.rationale)) {
          assert.match(request.recoveryPrompt, /Resolved bootstrap context/u);
          reviewed = true;
          return { stepAssessment: assessment("LATER_STEP") };
        }
      },
      onRoleRun(role, request) {
        if (reviewed) assert.equal(request.access, "read-only");
      },
    });
    const run = await fixture.run({
      stagnationWindowRounds: kind === "stagnation" ? 1 : 2,
    });
    assert.equal(reviewed, true);
    assert.equal(run.pause.reason, "plan_revision_required");
    assert.equal(run.pipelineState.currentStep, 1);
    assert.deepEqual(run.pipelineState.completedCommits, []);
    assert.equal(run.pipelineState.implementationDirection, null);
  });
}
