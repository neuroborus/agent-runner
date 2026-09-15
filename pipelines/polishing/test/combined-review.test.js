import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { migratePolishingStateV12, polishingPipeline } from "../src/index.js";
import { normalizePipelineState } from "../src/workflow-contract.js";
import {
  SOURCE_SESSION,
  bootstrapReady,
  candidateApproved,
  candidateClean,
  candidateFindings,
  checkAndFix,
  clarificationReady,
  cleanConfirmation,
  createFixture,
  createRealGitFixture,
  finalizationPassed,
  findingArbitration,
  reconsideration,
  polishingCompleted,
  reconciliationDisagreement,
  reconciliationResolved,
  resolution,
  reviewApproved,
  reviewFindings,
  runGit,
  stagnationDirection,
} from "./support/index.js";

const bootstrap = () => [
  clarificationReady(),
  bootstrapReady("Worker"),
  reconciliationResolved(),
];
const converge = () => [checkAndFix(), candidateClean()];

async function combinedFixture(t, options = {}) {
  return createFixture(t, {
    mode: "combined",
    worker: [
      ...bootstrap(),
      polishingCompleted(),
      ...converge(),
      finalizationPassed(),
    ],
    reviewer: [
      bootstrapReady("Reviewer"),
      candidateApproved(),
      reviewApproved(),
    ],
    ...options,
  });
}

test("combined polishing converges both candidate gates before independent terminal confirmation", async (t) => {
  const turns = [];
  const fixture = await combinedFixture(t, {
    sourceSession: SOURCE_SESSION,
    onRoleRun(role, request) {
      turns.push([role, fixture.currentRun.activeTurn.phase, request.access]);
    },
  });
  const completed = await fixture.run();
  assert.equal(
    completed.pipelineState.workflowState,
    "DONE",
    JSON.stringify(completed.pause),
  );
  assert.deepEqual(turns, [
    ["worker", "clarify", "read-only"],
    ["worker", "bootstrap", "read-only"],
    ["reviewer", "bootstrap", "read-only"],
    ["worker", "bootstrap", "read-only"],
    ["worker", "polish", "workspace-write"],
    ["worker", "check-and-fix", "workspace-write"],
    ["worker", "clean-confirm", "read-only"],
    ["reviewer", "review", "read-only"],
    ["worker", "finalize", "workspace-write"],
    ["reviewer", "confirm", "read-only"],
  ]);
  const state = completed.pipelineState;
  assert.equal(state.settings.mode, "combined");
  assert.equal(
    state.candidateConfirmationFingerprint,
    state.candidateReviewedFingerprint,
  );
  assert.equal(state.reviewedFingerprint, state.finalizedFingerprint);
  assert.equal(state.cleanConfirmationFingerprint, null);
  assert.equal(state.lazySourceForkConsumed, false);
  assert.deepEqual(fixture.calls.arbiter, []);
  for (const role of ["worker", "reviewer"]) {
    assert.ok(
      fixture.calls[role].some(({ session }) => session?.mode === "fork"),
    );
  }
  for (const index of [4, 5, 6, 8]) {
    const roleIndex =
      turns.slice(0, index + 1).filter(([role]) => role === "worker").length -
      1;
    assert.equal(fixture.calls.worker[roleIndex].session.mode, "fork");
  }
  assert.doesNotThrow(() => normalizePipelineState(state));
});

test("combined self-findings go directly to fixing before any independent review", async (t) => {
  const fixture = await combinedFixture(t, {
    worker: [
      ...bootstrap(),
      polishingCompleted(),
      checkAndFix(),
      candidateFindings("R1"),
      ...converge(),
      finalizationPassed(),
    ],
  });
  const completed = await fixture.run();
  assert.equal(
    completed.pipelineState.workflowState,
    "DONE",
    JSON.stringify(completed.pause),
  );
  assert.deepEqual(fixture.calls.arbiter, []);
  assert.match(fixture.calls.worker[6].prompt, /R1/u);
  const repair = fixture.transitions.find(
    ({ patch }) => patch.pipelineState.primaryFindings?.length > 0,
  )?.patch.pipelineState;
  assert.equal(repair.workflowState, "CHECK_AND_FIX");
  assert.deepEqual(repair.findings, []);
  assert.equal(repair.candidateReviewResult, null);
});

test("combined unresolved bootstrap pauses without Arbiter and resumes reconciliation", async (t) => {
  const fixture = await combinedFixture(t, {
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationDisagreement(),
      reconciliationResolved(),
      polishingCompleted(),
      ...converge(),
      finalizationPassed(),
    ],
  });
  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "bootstrap_disagreement");
  assert.deepEqual(fixture.calls.arbiter, []);
  polishingPipeline.validateResumeAction(paused, null);
  const completed = await fixture.run();
  assert.equal(
    completed.pipelineState.workflowState,
    "DONE",
    JSON.stringify(completed.pause),
  );
});

for (const changed of [false, true]) {
  test(`combined independent repairs ${changed ? "invalidate" : "reuse"} finalization after reconvergence`, async (t) => {
    let repaired = false;
    const fixture = await combinedFixture(t, {
      worker: [
        ...bootstrap(),
        polishingCompleted(),
        ...converge(),
        finalizationPassed(),
        resolution("FIX", "R1"),
        ...converge(),
        ...(changed ? [finalizationPassed()] : []),
      ],
      reviewer: [
        bootstrapReady("Reviewer"),
        candidateApproved(),
        reviewFindings("R1"),
        candidateApproved(),
        reviewApproved(),
      ],
      async onRoleRun() {
        if (
          changed &&
          !repaired &&
          fixture.currentRun.activeTurn.phase === "resolve-findings"
        ) {
          repaired = true;
          await writeFile(join(fixture.projectPath, "repair.txt"), "fixed\n");
        }
      },
    });
    const completed = await fixture.run();
    assert.equal(
      completed.pipelineState.workflowState,
      "DONE",
      JSON.stringify(completed.pause),
    );
    assert.equal(
      fixture.calls.worker.filter(({ prompt }) =>
        /Run the complete project finalization procedure/u.test(prompt),
      ).length,
      changed ? 2 : 1,
    );
    assert.equal(
      fixture.calls.worker.filter(({ prompt }) =>
        /Concrete findings from the preceding clean confirmation/u.test(prompt),
      ).length,
      2,
    );
    assert.equal(fixture.calls.reviewer.length, 5);
  });
}

test("version-12 migration preserves saved modes and completed handoff evidence", async (t) => {
  for (const mode of ["independent", "lazy", "combined"]) {
    const fixture = await combinedFixture(t, {
      mode,
      ...(mode === "independent"
        ? {
            worker: [
              ...bootstrap(),
              polishingCompleted(),
              finalizationPassed(),
            ],
          }
        : {}),
      ...(mode === "lazy"
        ? {
            worker: [
              clarificationReady(),
              bootstrapReady("Worker"),
              polishingCompleted(),
              ...converge(),
              finalizationPassed(),
              cleanConfirmation(),
            ],
          }
        : {}),
    });
    const completed = await fixture.run();
    const { primaryFindings: _primary, ...legacy } = completed.pipelineState;
    const migrated = migratePolishingStateV12({ pipelineState: legacy });
    assert.deepEqual(migrated, { ...legacy, primaryFindings: [] });
    assert.equal(migrated.settings.mode, mode);
    assert.doesNotThrow(() => normalizePipelineState(migrated));
    const calls = Object.values(fixture.calls).flat().length;
    fixture.persistPipelineState(migrated);
    await fixture.run();
    assert.equal(Object.values(fixture.calls).flat().length, calls);
  }
});

for (const phase of ["clean-confirm", "confirm"]) {
  test(`combined ${phase} rejects content mutation without handoff`, async (t) => {
    const fixture = await combinedFixture(t, {
      async onRoleRun() {
        if (fixture.currentRun.activeTurn.phase === phase) {
          await writeFile(
            join(fixture.projectPath, "contaminated.txt"),
            "unexpected\n",
          );
        }
      },
    });
    const paused = await fixture.run();
    assert.equal(paused.pause.reason, "read_only_agent_mutated_repository");
    assert.equal(paused.pipelineState.reviewedFingerprint, null);
    assert.ok(
      !fixture.transitions.some(
        ({ patch }) => patch.pipelineState.workflowState === "HANDOFF",
      ),
    );
  });
}

test("combined check/fix never has index authority", async (t) => {
  const fixture = await createRealGitFixture(t, {
    mode: "combined",
    worker: [
      ...bootstrap(),
      polishingCompleted(),
      ...converge(),
      finalizationPassed(),
    ],
    async onRoleRun() {
      if (fixture.currentRun.activeTurn.phase === "check-and-fix") {
        await runGit(fixture.projectPath, "add", "-A");
      }
    },
  });
  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "unexpected_git_index_change");
  assert.ok(
    fixture.calls.worker.every(({ access }) => access !== "local-commit"),
  );
  assert.equal(fixture.calls.reviewer.length, 1);
});

test("combined self-review exhaustion cannot invoke Arbiter or override a primary finding", async (t) => {
  const fixture = await combinedFixture(t, {
    modeSettings: { maxFixRounds: 1 },
    worker: [
      ...bootstrap(),
      polishingCompleted(),
      checkAndFix(),
      candidateFindings("R1"),
    ],
  });
  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "fix_limit_reached");
  assert.equal(paused.pause.resumeState, "CHECK_AND_FIX");
  assert.deepEqual(fixture.calls.arbiter, []);
  assert.equal(fixture.calls.reviewer.length, 1);
  assert.throws(() =>
    polishingPipeline.validateResumeAction(paused, {
      type: "override-finding",
      findingId: "R1",
    }),
  );
  assert.deepEqual(
    polishingPipeline.projections.status(paused).findings.map(({ id }) => id),
    ["R1"],
  );
});

test("combined bounded output correction does not double-charge a changed primary turn", async (t) => {
  let changed = false;
  const fixture = await combinedFixture(t, {
    modeSettings: { maxFixRounds: 2 },
    worker: [
      ...bootstrap(),
      polishingCompleted(),
      { status: "INVALID" },
      checkAndFix(),
      candidateClean(),
      finalizationPassed(),
    ],
    async onRoleRun() {
      if (!changed && fixture.currentRun.activeTurn.phase === "check-and-fix") {
        changed = true;
        await writeFile(
          join(fixture.projectPath, "corrected.txt"),
          "changed\n",
        );
      }
    },
  });
  const completed = await fixture.run();
  assert.equal(
    completed.pipelineState.workflowState,
    "DONE",
    JSON.stringify(completed.pause),
  );
  assert.equal(completed.counters.fixRounds, 1);
  const corrected = fixture.calls.worker.find(({ prompt }) =>
    /previous structured primary checkpoint/u.test(prompt),
  );
  assert.equal(corrected.session, undefined);
});

test("combined independent dispute arbitration stays fresh and returns through primary convergence", async (t) => {
  const fixture = await combinedFixture(t, {
    sourceSession: SOURCE_SESSION,
    modeSettings: { maxDisputesPerFinding: 1 },
    worker: [
      ...bootstrap(),
      polishingCompleted(),
      ...converge(),
      resolution("DISPUTE", "R1"),
      ...converge(),
      finalizationPassed(),
    ],
    reviewer: [
      bootstrapReady("Reviewer"),
      candidateFindings("R1"),
      reconsideration("UPHOLD", "R1"),
      candidateApproved(),
      reviewApproved(),
    ],
    arbiter: [findingArbitration("WORKER_CORRECT")],
  });
  const completed = await fixture.run();
  assert.equal(
    completed.pipelineState.workflowState,
    "DONE",
    JSON.stringify(completed.pause),
  );
  assert.equal(fixture.calls.arbiter.length, 1);
  assert.equal(fixture.calls.arbiter[0].access, "read-only");
  assert.equal(fixture.calls.arbiter[0].session, undefined);
  assert.equal(
    completed.pipelineState.findingArbitrations[0].direction,
    "WORKER_CORRECT",
  );
  assert.equal(
    fixture.calls.worker.filter(({ prompt }) =>
      /Concrete findings from the preceding clean confirmation/u.test(prompt),
    ).length,
    2,
  );
});

test("combined interrupted terminal confirmation reuses both candidate gates and finalization", async (t) => {
  const fixture = await combinedFixture(t);
  const lost = new Error("Process stopped before terminal confirmation.");
  const transition = fixture.runtime.transition;
  const start = fixture.runtime.startAgentTurn;
  let stopped = false;
  fixture.runtime.transition = async (patch, options) => {
    if (stopped) throw lost;
    const next = await transition(patch, options);
    if (patch.pipelineState.workflowState === "CONFIRM") stopped = true;
    return next;
  };
  fixture.runtime.startAgentTurn = async (...args) => {
    if (stopped) throw lost;
    return start(...args);
  };
  await assert.rejects(fixture.run(), (error) => error === lost);
  const accepted = fixture.currentRun.pipelineState;
  stopped = false;
  fixture.runtime.transition = transition;
  fixture.runtime.startAgentTurn = start;
  await fixture.recover();
  const completed = await fixture.run();
  assert.equal(
    completed.pipelineState.workflowState,
    "DONE",
    JSON.stringify(completed.pause),
  );
  assert.deepEqual(
    completed.pipelineState.candidateReviewResult,
    accepted.candidateReviewResult,
  );
  assert.deepEqual(
    completed.pipelineState.finalizationResult,
    accepted.finalizationResult,
  );
  assert.equal(fixture.calls.worker.length, 7);
  assert.equal(fixture.calls.reviewer.length, 3);
});

test("combined handoff rejects missing or mismatched primary and independent evidence", async (t) => {
  const fixture = await combinedFixture(t);
  const completed = await fixture.run();
  const state = completed.pipelineState;
  for (const patch of [
    { candidateConfirmationFingerprint: null },
    { candidateConfirmationFingerprint: "f".repeat(64) },
    { candidateReviewResult: null, candidateReviewedFingerprint: null },
    { reviewedFingerprint: null, reviewResult: null },
  ]) {
    assert.throws(() => normalizePipelineState({ ...state, ...patch }));
  }
});

test("combined terminal review binds formatter output separately from the candidate", async (t) => {
  const fixture = await combinedFixture(t, {
    async onRoleRun() {
      if (fixture.currentRun.activeTurn.phase === "finalize") {
        await writeFile(
          join(fixture.projectPath, "formatted.txt"),
          "formatted\n",
        );
      }
    },
  });
  const completed = await fixture.run();
  const state = completed.pipelineState;
  assert.equal(state.workflowState, "DONE");
  assert.equal(
    state.candidateConfirmationFingerprint,
    state.candidateReviewedFingerprint,
  );
  assert.notEqual(
    state.finalizedFingerprint,
    state.candidateReviewedFingerprint,
  );
  assert.equal(state.reviewedFingerprint, state.finalizedFingerprint);
  assert.match(
    fixture.calls.reviewer.at(-1).prompt,
    new RegExp(state.finalizedFingerprint, "u"),
  );
});

test("combined evidence rejection reruns finalization without repeating candidate gates", async (t) => {
  const fixture = await combinedFixture(t, {
    worker: [
      ...bootstrap(),
      polishingCompleted(),
      ...converge(),
      finalizationPassed(),
      finalizationPassed(),
    ],
    reviewer: [
      bootstrapReady("Reviewer"),
      candidateApproved(),
      {
        ...reviewFindings("R1"),
        validationChange: "REJECTED",
        validationEvidence: ["Required check evidence is insufficient."],
        finalizationFindingIds: ["R1"],
      },
      reviewApproved(),
    ],
  });
  const completed = await fixture.run();
  assert.equal(
    completed.pipelineState.workflowState,
    "DONE",
    JSON.stringify(completed.pause),
  );
  assert.equal(fixture.calls.worker.length, 8);
  assert.equal(fixture.calls.reviewer.length, 4);
  assert.deepEqual(fixture.calls.arbiter, []);
});

test("combined independent withdrawal restarts primary convergence", async (t) => {
  const fixture = await combinedFixture(t, {
    worker: [
      ...bootstrap(),
      polishingCompleted(),
      ...converge(),
      resolution("DISPUTE", "R1"),
      ...converge(),
      finalizationPassed(),
    ],
    reviewer: [
      bootstrapReady("Reviewer"),
      candidateFindings("R1"),
      reconsideration("WITHDRAW", "R1"),
      candidateApproved(),
      reviewApproved(),
    ],
  });
  const completed = await fixture.run();
  assert.equal(
    completed.pipelineState.workflowState,
    "DONE",
    JSON.stringify(completed.pause),
  );
  assert.equal(
    completed.pipelineState.disputeHistory.at(-1).direction,
    "WITHDRAW",
  );
  assert.equal(
    fixture.calls.worker.filter(({ prompt }) =>
      /Concrete findings from the preceding clean confirmation/u.test(prompt),
    ).length,
    2,
  );
  assert.deepEqual(fixture.calls.arbiter, []);
});

test("combined independent overrides remain fingerprint-bound after primary reconvergence", async (t) => {
  const fixture = await combinedFixture(t, {
    modeSettings: { maxSameFindingRounds: 1 },
    worker: [
      ...bootstrap(),
      polishingCompleted(),
      ...converge(),
      resolution("FIX", "R1"),
      ...converge(),
      ...converge(),
      finalizationPassed(),
    ],
    reviewer: [
      bootstrapReady("Reviewer"),
      candidateFindings("R1"),
      candidateFindings("R1"),
      candidateFindings("R1"),
      reviewApproved(),
    ],
  });
  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "no_progress");
  const fingerprint = paused.pipelineState.candidateReviewedFingerprint;
  const completed = await fixture.run({
    type: "override-finding",
    findingId: "R1",
  });
  assert.equal(
    completed.pipelineState.workflowState,
    "DONE",
    JSON.stringify(completed.pause),
  );
  assert.deepEqual(completed.pipelineState.findingOverrides, [
    { findingId: "R1", fingerprint },
  ]);
  assert.equal(
    fixture.calls.worker.filter(({ prompt }) =>
      /Concrete findings from the preceding clean confirmation/u.test(prompt),
    ).length,
    3,
  );
});

test("combined independent stagnation reconsideration preserves findings through primary checkpoints", async (t) => {
  const fixture = await combinedFixture(t, {
    modeSettings: { stagnationWindowRounds: 1, maxSameFindingRounds: 5 },
    worker: [
      ...bootstrap(),
      polishingCompleted(),
      ...converge(),
      resolution("FIX", "R1"),
      ...converge(),
      ...converge(),
      finalizationPassed(),
    ],
    reviewer: [
      bootstrapReady("Reviewer"),
      candidateFindings("R1"),
      candidateFindings("R1"),
      candidateApproved(),
      reviewApproved(),
    ],
    arbiter: [
      { ...stagnationDirection("RECONSIDER_FINDINGS"), findingIds: ["R1"] },
    ],
  });
  const completed = await fixture.run();
  assert.equal(
    completed.pipelineState.workflowState,
    "DONE",
    JSON.stringify(completed.pause),
  );
  assert.equal(fixture.calls.arbiter.length, 1);
  assert.equal(fixture.calls.arbiter[0].session, undefined);
  assert.match(fixture.calls.reviewer.at(-2).prompt, /R1/u);
});
