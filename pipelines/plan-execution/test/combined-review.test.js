import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import {
  planExecutionPipeline,
  migratePlanExecutionStateV16,
} from "../src/index.js";
import { normalizePipelineState } from "../src/workflow-contract.js";
import { candidateGatePassed, commitGatePassed } from "../src/gate-evidence.js";
import {
  CANDIDATE_CLEAN_CONFIRM_SCHEMA,
  CANDIDATE_REVIEW_SCHEMA,
  CHECK_AND_FIX_SCHEMA,
  FINDING_RESOLUTION_SCHEMA,
  FINALIZATION_SCHEMA,
} from "../src/schemas.js";
import {
  createLegacyRecoveryFixture,
  findingArbitration,
  reconsideration,
  terminalConfirmation,
  SOURCE_SESSION,
  bootstrapReady,
  clarificationReady,
  checkAndFix,
  cleanConfirmation,
  cleanConfirmationFindings,
  createFixture,
  finalizationPassed,
  implementationCompleted,
  reconciliationDisagreement,
  reconciliationResolved,
  resolution,
  reviewFindings,
} from "./support/index.js";

const work = () => [
  implementationCompleted(),
  checkAndFix(),
  finalizationPassed(),
];

test("combined binds both candidate gates before formatting and Reviewer terminal confirmation", async (t) => {
  const turns = [];
  const fixture = await createFixture(t, {
    mode: "combined",
    sourceSession: SOURCE_SESSION,
    workWorker: work(),
    async onRoleRun(role, request) {
      turns.push([role, fixture.currentRun.activeTurn.phase, request.access]);
      if (request.schema === FINALIZATION_SCHEMA)
        await writeFile(join(request.cwd, "formatted.txt"), "formatted\n");
    },
  });
  const result = await fixture.run();
  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.deepEqual(
    turns.slice(turns.findIndex(([, phase]) => phase === "implement")),
    [
      ["worker", "implement", "workspace-write"],
      ["worker", "check-and-fix", "workspace-write"],
      ["worker", "clean-confirm", "read-only"],
      ["reviewer", "review", "read-only"],
      ["worker", "finalize", "workspace-write"],
      ["reviewer", "confirm", "read-only"],
      ["worker", "commit", "local-commit"],
    ],
  );
  const primary = fixture.transitions.find(
    ({ patch }) => patch?.pipelineState.workflowState === "REVIEW",
  ).patch.pipelineState;
  assert.equal(primary.candidateReviewResult, null);
  assert.equal(candidateGatePassed(primary), false);
  const finalized = fixture.transitions.find(
    ({ patch }) => patch?.pipelineState.workflowState === "CONFIRM",
  ).patch.pipelineState;
  assert.equal(candidateGatePassed(finalized), true);
  assert.equal(
    finalized.candidateConfirmationFingerprint,
    finalized.candidateReviewedFingerprint,
  );
  assert.notEqual(
    finalized.finalizedFingerprint,
    finalized.candidateReviewedFingerprint,
  );
  assert.equal(commitGatePassed(finalized), false);
  const authorized = fixture.transitions.find(
    ({ patch }) => patch?.pipelineState.workflowState === "COMMIT",
  ).patch.pipelineState;
  assert.equal(commitGatePassed(authorized), true);
  for (const field of [
    "candidateReviewResult",
    "candidateReviewedFingerprint",
    "candidateConfirmationFingerprint",
  ]) {
    assert.equal(
      commitGatePassed({ ...authorized, [field]: null }),
      false,
      field,
    );
    assert.throws(() =>
      normalizePipelineState({ ...authorized, [field]: null }),
    );
  }
  assert.equal(fixture.calls.arbiter.length, 0);
  const workerForks = fixture.calls.worker.filter(
    ({ session }) => session?.mode === "fork",
  );
  assert.ok(workerForks.length >= 3);
  assert.equal(
    fixture.calls.reviewer.filter(({ session }) => session?.mode === "fork")
      .length,
    2,
  );
  assert.equal(fixture.calls.reviewer.at(-1).session.mode, "continue");
});

test("combined self findings go directly to fixing; independent repairs reconverge both gates", async (t) => {
  let fixes = 0;
  const fixture = await createFixture(t, {
    mode: "combined",
    workWorker: [
      implementationCompleted(),
      checkAndFix(),
      cleanConfirmationFindings("R1"),
      checkAndFix("CHANGED"),
      checkAndFix(),
      cleanConfirmation(),
      resolution({ id: "R2", decision: "FIX" }),
      checkAndFix(),
      finalizationPassed(),
    ],
    workReviewer: [reviewFindings("R2")],
    async onRoleRun(role, request) {
      if (
        request.schema === CHECK_AND_FIX_SCHEMA &&
        fixture.currentRun.pipelineState.primaryFindings.length > 0
      ) {
        assert.deepEqual(fixture.currentRun.pipelineState.findings, []);
        await writeFile(join(request.cwd, "self-fix.txt"), "fixed\n");
        fixes++;
      }
      if (request.schema === FINDING_RESOLUTION_SCHEMA) {
        assert.match(request.prompt, /R2/u);
        await writeFile(join(request.cwd, "review-fix.txt"), "fixed\n");
      }
    },
  });
  const result = await fixture.run();
  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(fixes, 1);
  assert.equal(
    fixture.calls.worker.filter(
      ({ schema }) => schema === FINDING_RESOLUTION_SCHEMA,
    ).length,
    1,
  );
  assert.equal(
    fixture.calls.reviewer.filter(
      ({ schema }) => schema === CANDIDATE_REVIEW_SCHEMA,
    ).length,
    2,
  );
  assert.equal(fixture.calls.arbiter.length, 0);
  const repair = fixture.transitions.find(
    ({ patch }) =>
      patch?.pipelineState.previousFindings.some(({ id }) => id === "R2") &&
      patch.pipelineState.workflowState === "CHECK_AND_FIX",
  ).patch.pipelineState;
  assert.equal(repair.candidateConfirmationFingerprint, null);
  assert.equal(repair.candidateReviewResult, null);
  assert.equal(repair.finalizationResult, null);
});

test("combined bootstrap disagreement blocks without arbitration and resumes reconciliation", async (t) => {
  const fixture = await createFixture(t, {
    mode: "combined",
    workWorker: work(),
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationDisagreement(),
      reconciliationResolved(),
    ],
  });
  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "bootstrap_disagreement");
  assert.equal(paused.pause.resumeState, "BOOTSTRAP");
  assert.doesNotThrow(() =>
    planExecutionPipeline.validateResumeAction(paused, null),
  );
  assert.deepEqual(
    planExecutionPipeline.projections.pause(paused).nextActions,
    [{ type: "resume", action: null }],
  );
  assert.equal(fixture.calls.arbiter.length, 0);
  assert.equal(
    fixture.calls.worker.some(({ access }) => access === "workspace-write"),
    false,
  );
  const completed = await fixture.run();
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(fixture.calls.arbiter.length, 0);
});

test("combined primary exhaustion cannot be overridden or arbitrated", async (t) => {
  const fixture = await createFixture(t, {
    mode: "combined",
    modeSettings: { maxFixRoundsPerStep: 1 },
    workWorker: [
      implementationCompleted(),
      checkAndFix(),
      cleanConfirmationFindings("R1"),
    ],
  });
  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "fix_limit_reached");
  assert.equal(paused.pause.resumeState, "CHECK_AND_FIX");
  assert.equal(fixture.calls.arbiter.length, 0);
  assert.equal(
    fixture.calls.reviewer.filter(
      ({ schema }) => schema === CANDIDATE_REVIEW_SCHEMA,
    ).length,
    0,
  );
  assert.throws(() =>
    planExecutionPipeline.validateResumeAction(paused, {
      type: "override-finding",
      findingId: "R1",
    }),
  );
});

for (const schema of [
  CANDIDATE_CLEAN_CONFIRM_SCHEMA,
  CANDIDATE_REVIEW_SCHEMA,
]) {
  test(`combined rejects repository mutation during ${schema === CANDIDATE_REVIEW_SCHEMA ? "Reviewer" : "Worker"} confirmation`, async (t) => {
    const fixture = await createFixture(t, {
      mode: "combined",
      workWorker: work(),
      async onRoleRun(role, request) {
        if (request.schema === schema)
          await writeFile(join(request.cwd, "forbidden.txt"), "mutation\n");
      },
    });
    const result = await fixture.run();
    assert.notEqual(result.pipelineState.workflowState, "DONE");
    assert.equal(
      fixture.calls.worker.some(({ access }) => access === "local-commit"),
      false,
    );
  });
}

test("version sixteen migration preserves saved mode, counters and consumed authorization", async (t) => {
  const fixture = await createFixture(t, {
    workWorker: [implementationCompleted(), finalizationPassed()],
    onCommitVerify() {
      throw new Error("interrupted verification");
    },
  });
  const paused = await fixture.run();
  const { primaryFindings, ...legacy } = paused.pipelineState;
  const migrated = migratePlanExecutionStateV16({
    ...paused,
    pipelineStateVersion: 16,
    pipelineState: legacy,
  });
  assert.deepEqual(migrated, { ...legacy, primaryFindings: [] });
  assert.equal(migrated.settings.mode, "independent");
  assert.equal(migrated.pendingCommit.status, "consumed");
  assert.doesNotThrow(() => normalizePipelineState(migrated));
});

test("combined retains mixed disputes across primary reconvergence and uses fresh finding arbitration", async (t) => {
  const fixture = await createFixture(t, {
    mode: "combined",
    sourceSession: SOURCE_SESSION,
    modeSettings: { maxDisputesPerFinding: 1 },
    workWorker: [
      implementationCompleted(),
      checkAndFix(),
      resolution(
        { id: "R1", decision: "FIX" },
        { id: "R2", decision: "DISPUTE" },
      ),
      checkAndFix(),
      checkAndFix(),
      finalizationPassed(),
    ],
    workReviewer: [
      reviewFindings("R1", "R2"),
      reviewFindings("R2"),
      reconsideration("UPHOLD", "R2"),
    ],
    arbiter: [findingArbitration("WORKER_CORRECT")],
    async onRoleRun(role, request) {
      if (request.schema === FINDING_RESOLUTION_SCHEMA)
        await writeFile(join(request.cwd, "mixed-repair.txt"), "fixed R1\n");
    },
  });
  const result = await fixture.run();
  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.disputeCounts.R2, 1);
  assert.equal(result.pipelineState.findingArbitrations.at(-1).findingId, "R2");
  assert.equal(fixture.calls.arbiter.length, 1);
  assert.equal(fixture.calls.arbiter[0].session, undefined);
  assert.ok(
    fixture.transitions.some(
      ({ patch }) =>
        patch?.pipelineState.workflowState === "CHECK_AND_FIX" &&
        patch.pipelineState.pendingDisputes.some(
          ({ findingId }) => findingId === "R2",
        ),
    ),
  );
});

test("combined unchanged terminal repair reuses finalization only after both candidate gates", async (t) => {
  const fixture = await createFixture(t, {
    mode: "combined",
    workWorker: [
      implementationCompleted(),
      checkAndFix(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      checkAndFix(),
    ],
    workReviewer: [terminalConfirmation(reviewFindings("R1"))],
  });
  const result = await fixture.run();
  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(
    fixture.calls.worker.filter(({ schema }) => schema === FINALIZATION_SCHEMA)
      .length,
    1,
  );
  assert.equal(
    fixture.calls.worker.filter(
      ({ schema }) => schema === CANDIDATE_CLEAN_CONFIRM_SCHEMA,
    ).length,
    2,
  );
  assert.equal(
    fixture.calls.reviewer.filter(
      ({ schema }) => schema === CANDIDATE_REVIEW_SCHEMA,
    ).length,
    2,
  );
});

test("combined journal-proven confirmation recovery retains both candidate approvals", async (t) => {
  const fixture = await createLegacyRecoveryFixture(t, {
    mode: "combined",
    steps: 1,
    pendingCorrection: true,
    source: true,
    format: true,
  });
  const failed = fixture.failed;
  assert.equal(candidateGatePassed(failed.pipelineState), true);
  assert.deepEqual(await fixture.recoveryAction(), [
    { type: "resume", action: null },
  ]);
  const before = fixture.calls.length;
  const { run } = await fixture.openRunner().resume({ runId: fixture.runId });
  assert.equal(run.pipelineState.workflowState, "DONE");
  assert.equal(run.pipelineState.settings.mode, "combined");
  assert.equal(fixture.calls.length - before, 2);
  assert.equal(fixture.calls[before].access, "read-only");
  assert.equal(fixture.calls[before].session, undefined);
  assert.equal(fixture.calls[before + 1].access, "local-commit");
});

test("combined exact finding override still requires both candidate gates", async (t) => {
  const fixture = await createFixture(t, {
    mode: "combined",
    modeSettings: { maxSameFindingRounds: 1 },
    workWorker: [
      implementationCompleted(),
      checkAndFix(),
      resolution({ id: "R1", decision: "FIX" }),
      checkAndFix(),
      checkAndFix(),
      finalizationPassed(),
    ],
    workReviewer: [
      reviewFindings("R1"),
      reviewFindings("R1"),
      reviewFindings("R1"),
    ],
  });
  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "no_progress");
  const counters = structuredClone(paused.counters);
  const result = await fixture.run(
    {},
    { type: "override-finding", findingId: "R1" },
  );
  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.deepEqual(result.pipelineState.findingOverrides, [
    { findingId: "R1", fingerprint: result.pipelineState.reviewedFingerprint },
  ]);
  assert.equal(result.pipelineState.candidateReviewResult.status, "FINDINGS");
  assert.equal(candidateGatePassed(result.pipelineState), true);
  assert.ok(result.counters.fixRounds >= counters.fixRounds);
  assert.equal(
    fixture.calls.worker.filter(
      ({ schema }) => schema === CANDIDATE_CLEAN_CONFIRM_SCHEMA,
    ).length,
    3,
  );
});
