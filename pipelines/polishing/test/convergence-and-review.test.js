import assert from "node:assert/strict";
import { mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { polishingPipeline } from "../src/index.js";
import {
  CANDIDATE_CLEAN_CONFIRM_SCHEMA,
  CANDIDATE_REVIEW_SCHEMA,
  CHECK_AND_FIX_SCHEMA,
  CLEAN_CONFIRM_SCHEMA,
  FINALIZATION_SCHEMA,
  FINDING_RESOLUTION_SCHEMA,
  REVIEW_SCHEMA,
} from "../src/schemas.js";
import {
  assertRun,
  MAX_DISPUTE_HISTORY_BYTES,
  normalizeFinalizationResult,
  normalizePipelineState,
} from "../src/workflow-contract.js";
import {
  SETTINGS,
  REQUIRED_CHECKS,
  bootstrapReady,
  candidateApproved,
  candidateClean,
  candidateFindings,
  checkAndFix,
  checkResults,
  clarificationReady,
  cleanConfirmation,
  cleanConfirmationFindings,
  createFixture,
  createRealGitFixture,
  finalizationBlocked,
  finalizationFailed,
  finalizationPassed,
  finalizationUnavailable,
  findingArbitration,
  invalidProductionFinalization,
  polishingCompleted,
  reconciliationResolved,
  reconsideration,
  resolution,
  resolutionBatch,
  reviewApproved,
  reviewFindingBatch,
  reviewFindings,
  runGit,
  stagnationDirection,
  trustedValidationSnapshot,
  verboseReconsiderationBatch,
  verboseResolutionBatch,
} from "./support/index.js";

test("finalizes only after a content-changing lazy candidate converges", async (t) => {
  let checkRound = 0;
  const fixture = await createFixture(t, {
    mode: "lazy",
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      polishingCompleted(),
      checkAndFix("CHANGED"),
      checkAndFix(),
      candidateClean(),
      finalizationPassed(),
      cleanConfirmation(),
    ],
    async onRoleRun(role, request, _turn, { projectPath }) {
      if (role === "worker" && request.schema === CHECK_AND_FIX_SCHEMA) {
        checkRound += 1;
        if (checkRound === 1) {
          await writeFile(join(projectPath, "lazy-fix.txt"), "fixed\n");
        }
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(
    fixture.calls.worker.filter(({ schema }) => schema === FINALIZATION_SCHEMA)
      .length,
    1,
  );
  assert.equal(
    fixture.calls.worker.filter(({ schema }) => schema === CHECK_AND_FIX_SCHEMA)
      .length,
    2,
  );
  assert.equal(result.counters.fixRounds, 2);
});

test("routes lazy candidate findings directly back to Worker fixing", async (t) => {
  let checkRound = 0;
  const fixture = await createFixture(t, {
    mode: "lazy",
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      polishingCompleted(),
      checkAndFix(),
      candidateFindings("R1"),
      checkAndFix("CHANGED"),
      checkAndFix(),
      candidateClean(),
      finalizationPassed(),
      cleanConfirmation(),
    ],
    async onRoleRun(role, request, _turn, { projectPath }) {
      if (role === "worker" && request.schema === CHECK_AND_FIX_SCHEMA) {
        checkRound += 1;
        if (checkRound === 2) {
          await writeFile(join(projectPath, "confirmation-fix.txt"), "fixed\n");
        }
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(fixture.calls.reviewer.length, 0);
  assert.equal(fixture.calls.arbiter.length, 0);
  assert.equal(
    fixture.calls.worker.filter(({ schema }) => schema === CHECK_AND_FIX_SCHEMA)
      .length,
    3,
  );
  assert.equal(
    fixture.calls.worker.filter(({ schema }) => schema === FINALIZATION_SCHEMA)
      .length,
    1,
  );
});

test("routes lazy terminal findings through candidate convergence and finalization", async (t) => {
  let checkRound = 0;
  let finalizationRound = 0;
  const fixture = await createFixture(t, {
    mode: "lazy",
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      polishingCompleted(),
      checkAndFix(),
      candidateClean(),
      finalizationPassed(),
      cleanConfirmationFindings("R1"),
      checkAndFix("CHANGED"),
      checkAndFix(),
      candidateClean(),
      finalizationPassed(),
      cleanConfirmation(),
    ],
    async onRoleRun(role, request, _turn, { projectPath }) {
      if (role === "worker" && request.schema === CHECK_AND_FIX_SCHEMA) {
        checkRound += 1;
        if (checkRound === 2) {
          await writeFile(join(projectPath, "terminal-fix.txt"), "fixed\n");
        }
      }
      if (role === "worker" && request.schema === FINALIZATION_SCHEMA) {
        finalizationRound += 1;
        if (finalizationRound === 1) {
          await writeFile(join(projectPath, "formatted.txt"), "formatted\n");
        }
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(
    fixture.calls.worker.filter(({ schema }) => schema === FINALIZATION_SCHEMA)
      .length,
    2,
  );
  assert.equal(
    fixture.calls.worker.filter(
      ({ schema }) => schema === CANDIDATE_CLEAN_CONFIRM_SCHEMA,
    ).length,
    2,
  );
  assert.equal(
    fixture.calls.worker.filter(({ schema }) => schema === CLEAN_CONFIRM_SCHEMA)
      .length,
    2,
  );
  assert.equal(result.pipelineState.findings.length, 0);
});

test("corrects one invalid lazy candidate check before finalization", async (t) => {
  const fixture = await createFixture(t, {
    mode: "lazy",
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      polishingCompleted(),
      { ...checkAndFix(), status: "INVALID" },
      checkAndFix(),
      candidateClean(),
      finalizationPassed(),
      cleanConfirmation(),
    ],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.lazyCorrections.length, 1);
  assert.equal(result.pipelineState.pendingLazyCorrection, null);
  assert.equal(
    fixture.calls.worker.filter(
      ({ schema }) => schema === CANDIDATE_CLEAN_CONFIRM_SCHEMA,
    ).length,
    1,
  );
  const correctionCall = fixture.calls.worker.filter(
    ({ schema }) => schema === CHECK_AND_FIX_SCHEMA,
  )[1];
  assert.equal(correctionCall.session, undefined);
  assert.match(correctionCall.prompt, /Pending correction diagnostic batch/u);
  assert.equal(fixture.calls.reviewer.length, 0);
  assert.equal(fixture.calls.arbiter.length, 0);
});

test("rejects repository mutation during lazy clean confirmation", async (t) => {
  const fixture = await createFixture(t, {
    mode: "lazy",
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      polishingCompleted(),
      finalizationPassed(),
      checkAndFix(),
      cleanConfirmation(),
    ],
    async onRoleRun(role, request, _turn, { projectPath }) {
      if (role === "worker" && request.schema === CLEAN_CONFIRM_SCHEMA) {
        await writeFile(
          join(projectPath, "illegal-confirmation.txt"),
          "changed\n",
        );
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "read_only_agent_mutated_repository");
  assert.equal(result.pipelineState.cleanConfirmationFingerprint, null);
  assert.equal(fixture.calls.reviewer.length, 0);
  assert.equal(fixture.calls.arbiter.length, 0);
});

test("reconciles a content-changing invalid lazy check exactly once", async (t) => {
  let checkTurns = 0;
  const fixture = await createFixture(t, {
    mode: "lazy",
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      polishingCompleted(),
      checkAndFix(),
      checkAndFix(),
      candidateClean(),
      finalizationPassed(),
      cleanConfirmation(),
    ],
    async onRoleRun(role, request, _turn, { projectPath }) {
      if (role === "worker" && request.schema === CHECK_AND_FIX_SCHEMA) {
        checkTurns += 1;
        if (checkTurns === 1) {
          await writeFile(
            join(projectPath, "misreported-lazy-fix.txt"),
            "changed\n",
          );
        }
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.fixRounds, 1);
  assert.equal(result.pipelineState.lazyCorrections.length, 1);
  assert.equal(result.pipelineState.lazyCorrections[0].fixRoundCharged, true);
  assert.equal(
    fixture.calls.worker.filter(({ schema }) => schema === FINALIZATION_SCHEMA)
      .length,
    1,
  );
});

test("corrects a provider-classified lazy check in a fresh redacted session", async (t) => {
  const sensitiveMarker = "DO_NOT_PERSIST_LAZY_PROVIDER_OUTPUT";
  let rejected = false;
  const fixture = await createFixture(t, {
    mode: "lazy",
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      polishingCompleted(),
      finalizationPassed(),
      checkAndFix(),
      cleanConfirmation(),
    ],
    onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.schema === CHECK_AND_FIX_SCHEMA &&
        !rejected
      ) {
        rejected = true;
        const error = new Error(sensitiveMarker);
        error.failureClass = "structured-output";
        error.stderr = sensitiveMarker;
        throw error;
      }
    },
  });

  const result = await fixture.run();
  const checkCalls = fixture.calls.worker.filter(
    ({ schema }) => schema === CHECK_AND_FIX_SCHEMA,
  );

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(checkCalls.length, 2);
  assert.equal(checkCalls[1].session, undefined);
  assert.match(checkCalls[1].prompt, /provider-structured-output/u);
  assert.doesNotMatch(JSON.stringify(result), new RegExp(sensitiveMarker, "u"));
});

test("corrects a lazy candidate confirmation without accepting evidence early", async (t) => {
  const fixture = await createFixture(t, {
    mode: "lazy",
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      polishingCompleted(),
      checkAndFix(),
      { ...candidateClean(), unexpected: "field" },
      candidateClean(),
      finalizationPassed(),
      cleanConfirmation(),
    ],
  });

  const result = await fixture.run();
  const cleanCalls = fixture.calls.worker.filter(
    ({ schema }) => schema === CANDIDATE_CLEAN_CONFIRM_SCHEMA,
  );

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(cleanCalls.length, 2);
  assert.equal(cleanCalls[1].session, undefined);
  assert.match(cleanCalls[1].prompt, /Pending correction diagnostic batch/u);
  assert.deepEqual(
    result.pipelineState.lazyCorrections.map(({ phase }) => phase),
    ["CLEAN_CONFIRM"],
  );
  assert.equal(
    result.pipelineState.cleanConfirmationFingerprint,
    result.pipelineState.finalizedFingerprint,
  );
});

test("pauses a repeated invalid lazy checkpoint and resumes its null retry", async (t) => {
  const fixture = await createFixture(t, {
    mode: "lazy",
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      polishingCompleted(),
      { ...checkAndFix(), status: "INVALID" },
      { ...checkAndFix(), status: "INVALID" },
      checkAndFix(),
      candidateClean(),
      finalizationPassed(),
      cleanConfirmation(),
    ],
  });

  const paused = await fixture.run();
  const projected = polishingPipeline.projections.pause(paused);

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "lazy_output_invalid");
  assert.equal(paused.pause.resumeState, "CHECK_AND_FIX");
  assert.equal(paused.counters.fixRounds, 0);
  assert.equal(paused.pipelineState.lazyCorrections.length, 1);
  assert.notEqual(paused.pipelineState.pendingLazyCorrection, null);
  assert.deepEqual(projected.nextActions, [{ type: "resume", action: null }]);
  assert.deepEqual(projected.evidence, [
    "Worker field status violated supported-status.",
  ]);

  await fixture.recover();
  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.pipelineState.lazyCorrections.length, 1);
  assert.equal(completed.pipelineState.pendingLazyCorrection, null);
  assert.equal(completed.counters.fixRounds, 1);
});

test("bounds repeated lazy confirmation findings without arbitration", async (t) => {
  const fixture = await createFixture(t, {
    mode: "lazy",
    modeSettings: { maxSameFindingRounds: 1 },
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      polishingCompleted(),
      checkAndFix(),
      candidateFindings("R1"),
      checkAndFix(),
      candidateFindings("R1"),
    ],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "no_progress");
  assert.equal(result.pause.resumeState, "CHECK_AND_FIX");
  assert.deepEqual(result.pause.findingIds, ["R1"]);
  assert.equal(fixture.calls.reviewer.length, 0);
  assert.equal(fixture.calls.arbiter.length, 0);
});

test("applies additional lazy fix rounds without arbitration", async (t) => {
  let checkRound = 0;
  const fixture = await createFixture(t, {
    mode: "lazy",
    modeSettings: { maxFixRounds: 1 },
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      polishingCompleted(),
      finalizationPassed(),
      checkAndFix(),
      cleanConfirmationFindings("R1"),
      checkAndFix("CHANGED"),
      finalizationPassed(),
      checkAndFix(),
      cleanConfirmation(),
    ],
    async onRoleRun(role, request, _turn, { projectPath }) {
      if (role === "worker" && request.schema === CHECK_AND_FIX_SCHEMA) {
        checkRound += 1;
        if (checkRound === 2) {
          await writeFile(join(projectPath, "extra-lazy-fix.txt"), "fixed\n");
        }
      }
    },
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "fix_limit_reached");
  assert.equal(paused.pause.resumeState, "CHECK_AND_FIX");

  const result = await fixture.run({ type: "extra-fix-rounds", amount: 2 });

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.additionalFixRounds, 2);
  assert.equal(fixture.calls.reviewer.length, 0);
  assert.equal(fixture.calls.arbiter.length, 0);
});

test("runs the dedicated finalization gate without skill guidance", async (t) => {
  const fixture = await createFixture(t, {
    settings: { ...SETTINGS, finalization: "none" },
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(""),
    ],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.finalizationResult.skillPath, null);
  assert.equal(
    result.pipelineState.finalizedFingerprint,
    result.pipelineState.reviewedFingerprint,
  );
  assert.match(
    fixture.calls.worker.find(({ prompt }) =>
      prompt.includes("Run the complete project finalization procedure"),
    ).prompt,
    /No finalization skill guidance is available/u,
  );
});

test("corrects an invalid finalization inventory into an environment pause", async (t) => {
  const fixture = await createFixture(t, {
    reviewer: [bootstrapReady("Reviewer")],
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      invalidProductionFinalization(),
      finalizationBlocked(
        "The required process-isolation facility is unavailable.",
        "The validation process could not start in the sandbox.",
      ),
    ],
  });

  const paused = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "environment_blocked");
  assert.equal(paused.pause.resumeState, "FINALIZE");
  const correction = paused.pipelineState.finalizationCorrection;
  assert.deepEqual(correction, {
    attempt: 1,
    guidance: "resolved",
    contentFingerprint:
      paused.pipelineState.repositoryBaseline.contentFingerprint,
    role: "worker",
    phase: "finalization",
    contract: "finalization",
    field: "requiredChecks[2].command",
    constraint: "staging-independent-validation-command",
  });
  assert.equal(paused.pipelineState.pendingFinalizationCorrection, null);
  const finalizationCalls = fixture.calls.worker.filter(
    ({ schema }) => schema === FINALIZATION_SCHEMA,
  );
  assert.equal(finalizationCalls.length, 2);
  assert.equal(finalizationCalls[0].access, "workspace-write");
  assert.equal(finalizationCalls[1].access, "read-only");
  assert.equal(finalizationCalls[0].schema, finalizationCalls[1].schema);
  assert.match(finalizationCalls[1].prompt, /one read-only correction/u);
  assert.equal(finalizationCalls[1].session, undefined);
  assert.match(
    finalizationCalls[1].recoveryPrompt,
    /Resolved bootstrap context/u,
  );
  assert.doesNotMatch(finalizationCalls[1].prompt, /git status/u);
  const correctionActivity = fixture.transitions.find(
    ({ options }) => options.activity?.kind === "finalization-correction",
  )?.options.activity;
  assert.deepEqual(correctionActivity, {
    actor: "worker",
    phase: "finalization",
    kind: "finalization-correction",
    message:
      "worker must correct finalization field requiredChecks[2].command (staging-independent-validation-command).",
  });
  for (const persisted of [paused, fixture.transitions, correctionActivity]) {
    assert.doesNotMatch(JSON.stringify(persisted), /DO_NOT_PERSIST/u);
  }
  assert.throws(
    () =>
      normalizePipelineState({
        ...paused.pipelineState,
        finalizationCorrection: {
          ...correction,
          rawOutput: "DO_NOT_PERSIST",
        },
      }),
    /finalization correction is invalid/u,
  );
});

test("routes corrected finalization PASS and FAIL through the existing gates", async (t) => {
  await t.test("PASS", async (t) => {
    const fixture = await createFixture(t, {
      worker: [
        clarificationReady(),
        bootstrapReady("Worker"),
        reconciliationResolved(),
        polishingCompleted(),
        invalidProductionFinalization(),
        finalizationPassed(),
      ],
    });

    const completed = await fixture.run();

    assert.equal(completed.pipelineState.workflowState, "DONE");
    assert.equal(completed.pipelineState.finalizationResult.status, "PASS");
    assert.equal(completed.pipelineState.finalizationCorrection, null);
  });

  await t.test("FAIL", async (t) => {
    const fixture = await createFixture(t, {
      worker: [
        clarificationReady(),
        bootstrapReady("Worker"),
        reconciliationResolved(),
        polishingCompleted(),
        invalidProductionFinalization(),
        finalizationFailed(),
        resolution("FIX"),
        finalizationPassed(),
      ],
    });

    const completed = await fixture.run();

    assert.equal(completed.pipelineState.workflowState, "DONE");
    assert.ok(
      fixture.transitions.some(
        ({ patch }) =>
          patch.pipelineState.workflowState === "RESOLVE_FINDINGS" &&
          patch.pipelineState.finalizationResult?.status === "FAIL",
      ),
    );
    assert.equal(completed.pipelineState.finalizationResult.status, "PASS");
  });
});

test("uses resolved and fallback guidance for bounded finalization correction", async (t) => {
  await t.test("corrects availability without selected guidance", async (t) => {
    const fixture = await createFixture(t, {
      settings: { ...SETTINGS, finalization: "none" },
      worker: [
        clarificationReady(),
        bootstrapReady("Worker"),
        reconciliationResolved(),
        polishingCompleted(),
        { ...finalizationUnavailable("SKILL_MISSING"), skillPath: "" },
        finalizationPassed(""),
      ],
    });

    const completed = await fixture.run();
    const correction = fixture.transitions.find(
      ({ options }) => options.activity?.kind === "finalization-correction",
    ).patch.pipelineState.finalizationCorrection;

    assert.equal(completed.pipelineState.workflowState, "DONE");
    assert.equal(correction.guidance, "resolved");
    assert.equal(correction.field, "status");
    assert.equal(correction.constraint, "selected-finalization-guidance");
  });

  await t.test("reconstructs fallback guidance", async (t) => {
    const fixture = await createFixture(t, {
      worker: [
        clarificationReady(),
        bootstrapReady("Worker"),
        reconciliationResolved(),
        polishingCompleted(),
        finalizationUnavailable("SKILL_INVALID"),
        invalidProductionFinalization(),
        finalizationPassed(""),
      ],
    });

    const completed = await fixture.run();
    const correctionCall = fixture.calls.worker.find(({ prompt }) =>
      prompt.includes("one read-only correction"),
    );
    const correction = fixture.transitions.find(
      ({ options }) => options.activity?.kind === "finalization-correction",
    ).patch.pipelineState.finalizationCorrection;

    assert.equal(completed.pipelineState.workflowState, "DONE");
    assert.equal(correction.guidance, "fallback");
    assert.match(
      correctionCall.prompt,
      /No finalization skill guidance is available/u,
    );
  });
});

test("fails closed after a repeated invalid finalization result", async (t) => {
  const fixture = await createFixture(t, {
    reviewer: [bootstrapReady("Reviewer")],
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      invalidProductionFinalization(),
      invalidProductionFinalization(),
    ],
  });

  await assert.rejects(
    fixture.run(),
    (error) => error.code === "ERR_INVALID_POLISHING_OUTPUT",
  );

  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
  assert.deepEqual(fixture.currentRun.pause.diagnostic, {
    role: "worker",
    phase: "finalization",
    contract: "finalization",
    field: "requiredChecks[2].command",
    constraint: "staging-independent-validation-command",
  });
  assert.deepEqual(
    fixture.currentRun.pipelineState.pendingFinalizationCorrection,
    fixture.currentRun.pipelineState.finalizationCorrection,
  );
  assert.doesNotMatch(JSON.stringify(fixture.currentRun), /DO_NOT_PERSIST/u);
  assert.doesNotMatch(JSON.stringify(fixture.transitions), /DO_NOT_PERSIST/u);
});

test("corrects a finalization structured-output failure without provider text", async (t) => {
  const sensitiveMarker = "DO_NOT_PERSIST_FINALIZATION_PROVIDER_OUTPUT";
  let rejected = false;
  const fixture = await createFixture(t, {
    onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes(
          "Run the complete project finalization procedure",
        ) &&
        !request.prompt.includes("one read-only correction") &&
        !rejected
      ) {
        rejected = true;
        const error = new Error(sensitiveMarker);
        error.failureClass = "structured-output";
        error.nativeResponse = { message: sensitiveMarker };
        error.stderr = sensitiveMarker;
        throw error;
      }
    },
  });

  const completed = await fixture.run();
  const correction = fixture.transitions.find(
    ({ options }) => options.activity?.kind === "finalization-correction",
  ).patch.pipelineState.finalizationCorrection;

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(correction.field, "result");
  assert.equal(correction.constraint, "semantic-contract");
  assert.doesNotMatch(
    JSON.stringify(completed),
    new RegExp(sensitiveMarker, "u"),
  );
  assert.doesNotMatch(
    JSON.stringify(fixture.transitions),
    new RegExp(sensitiveMarker, "u"),
  );
});

test("scopes finalization correction attempts to the current content fingerprint", async (t) => {
  let changed = false;
  const fixture = await createFixture(t, {
    async onRoleRun(role, request, _turn, { projectPath }) {
      if (
        role === "worker" &&
        request.prompt.includes("Resolve every current blocker") &&
        !changed
      ) {
        changed = true;
        await writeFile(join(projectPath, "tracked.txt"), "corrected\n");
      }
    },
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      invalidProductionFinalization(),
      finalizationFailed(),
      resolution("FIX"),
      invalidProductionFinalization(),
      finalizationPassed(),
    ],
  });

  const completed = await fixture.run();
  const corrections = fixture.transitions
    .filter(
      ({ options }) => options.activity?.kind === "finalization-correction",
    )
    .map(
      ({ patch }) =>
        patch.pipelineState.finalizationCorrection.contentFingerprint,
    );

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(corrections.length, 2);
  assert.notEqual(corrections[0], corrections[1]);
});

test("scopes correction after an invalid finalization turn changes content", async (t) => {
  let changed = false;
  const fixture = await createFixture(t, {
    async onRoleRun(role, request, _turn, { projectPath }) {
      if (
        role === "worker" &&
        request.prompt.includes(
          "Run the complete project finalization procedure",
        ) &&
        !request.prompt.includes("one read-only correction") &&
        !changed
      ) {
        changed = true;
        await writeFile(join(projectPath, "tracked.txt"), "finalized\n");
      }
    },
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      invalidProductionFinalization(),
      finalizationPassed(),
    ],
  });

  const completed = await fixture.run();
  const correctionState = fixture.transitions.find(
    ({ options }) => options.activity?.kind === "finalization-correction",
  ).patch.pipelineState;

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(
    correctionState.finalizationCorrection.contentFingerprint,
    correctionState.repositoryBaseline.contentFingerprint,
  );
});

for (const backend of ["codex", "claude"]) {
  test(`keeps the ${backend} finalization correction turn index-read-only`, async (t) => {
    const fixture = await createRealGitFixture(t, {
      roleBackends: {
        worker: backend,
        reviewer: backend === "codex" ? "claude" : "codex",
        arbiter: backend,
      },
      async onRoleRun(role, request, _turn, { projectPath }) {
        if (
          role === "worker" &&
          request.prompt.includes("one read-only correction")
        ) {
          assert.equal(request.access, "read-only");
          assert.equal(
            (await runGit(projectPath, "diff", "--cached", "--name-only"))
              .stdout,
            "",
          );
        }
      },
      worker: [
        clarificationReady(),
        bootstrapReady("Worker"),
        reconciliationResolved(),
        polishingCompleted(),
        invalidProductionFinalization(),
        finalizationPassed(),
      ],
    });

    const completed = await fixture.run();

    assert.equal(completed.pipelineState.workflowState, "DONE");
  });
}

test("falls back when automatic finalization discovery finds no skill", async (t) => {
  const withoutSkill = (result) => ({
    ...result,
    validationInfrastructure: [],
  });
  const fixture = await createFixture(t, {
    finalizationSkill: false,
    reviewer: [withoutSkill(bootstrapReady("Reviewer")), reviewApproved()],
    worker: [
      clarificationReady(),
      withoutSkill(bootstrapReady("Worker")),
      reconciliationResolved(),
      polishingCompleted(),
      withoutSkill(finalizationPassed("")),
    ],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.settings.finalization, "auto");
  assert.equal(result.pipelineState.finalizationResult.skillPath, null);
  assert.match(
    fixture.calls.worker.find(({ prompt }) =>
      prompt.includes("Run the complete project finalization procedure"),
    ).prompt,
    /repository instructions and project-defined checks/u,
  );
});

test("uses an explicitly configured finalization skill", async (t) => {
  const skillPath = ".agents/skills/finalization/SKILL.md";
  const fixture = await createFixture(t, {
    settings: { ...SETTINGS, finalization: skillPath },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.settings.finalization, skillPath);
  assert.match(
    fixture.calls.worker.find(({ prompt }) =>
      prompt.includes("Run the complete project finalization procedure"),
    ).prompt,
    /explicitly configured/u,
  );
});

test("pauses before invoking a missing explicit finalization skill", async (t) => {
  const skillPath = "checks/finalization/SKILL.md";
  const fixture = await createFixture(t, {
    settings: { ...SETTINGS, finalization: skillPath },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "finalization_skill_missing");
  assert.equal(result.pause.resumeState, "FINALIZE");
  assert.equal(result.pause.skillPath, skillPath);
  assert.equal(
    fixture.calls.worker.some(({ prompt }) =>
      prompt.includes("Run the complete project finalization procedure"),
    ),
    false,
  );
});

test("blocks an explicit finalization skill that escapes through a symlink", async (t) => {
  const skillPath = "linked/SKILL.md";
  const fixture = await createFixture(t, {
    settings: { ...SETTINGS, finalization: skillPath },
  });
  await symlink(fixture.taskPath, join(fixture.projectPath, "linked"), "dir");

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "finalization_skill_invalid");
  assert.equal(result.pause.resumeState, "FINALIZE");
  assert.equal(result.pause.skillPath, skillPath);
  assert.equal(
    fixture.calls.worker.some(({ prompt }) =>
      prompt.includes("Run the complete project finalization procedure"),
    ),
    false,
  );
});

test("resumes finalization after an explicit skill is corrected", async (t) => {
  for (const kind of ["missing", "symlink-invalid"]) {
    await t.test(kind, async (t) => {
      const skillPath = `LOCAL_ARTIFACTS/skills/${kind}/SKILL.md`;
      const fixture = await createFixture(t, {
        settings: { ...SETTINGS, finalization: skillPath },
        worker: [
          clarificationReady(),
          bootstrapReady("Worker"),
          reconciliationResolved(),
          polishingCompleted(),
          finalizationPassed(skillPath),
        ],
      });
      const skillDirectory = join(
        fixture.projectPath,
        "LOCAL_ARTIFACTS",
        "skills",
        kind,
      );
      if (kind === "symlink-invalid") {
        await mkdir(join(fixture.projectPath, "LOCAL_ARTIFACTS", "skills"), {
          recursive: true,
        });
        await symlink(fixture.taskPath, skillDirectory, "dir");
      }

      const paused = await fixture.run();

      assert.equal(
        paused.pause.reason,
        kind === "missing"
          ? "finalization_skill_missing"
          : "finalization_skill_invalid",
      );
      assert.doesNotThrow(() =>
        polishingPipeline.validateResumeAction(paused, null),
      );
      await rm(skillDirectory, { recursive: true, force: true });
      await mkdir(skillDirectory, { recursive: true });
      await writeFile(
        join(skillDirectory, "SKILL.md"),
        "---\nname: finalization\ndescription: Test validation.\n---\n\nRun tests.\n",
      );

      const resumed = await fixture.run();

      assert.equal(resumed.pipelineState.workflowState, "DONE");
      assert.equal(resumed.pause, null);
      assert.equal(
        resumed.pipelineState.finalizationResult.skillPath,
        skillPath,
      );
    });
  }
});

test("rejects a skill availability status without selected guidance", async (t) => {
  const fixture = await createFixture(t, {
    settings: { ...SETTINGS, finalization: "none" },
    reviewer: [bootstrapReady("Reviewer")],
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      { ...finalizationUnavailable("SKILL_MISSING"), skillPath: "" },
      { ...finalizationUnavailable("SKILL_MISSING"), skillPath: "" },
    ],
  });

  await assert.rejects(
    fixture.run(),
    (error) =>
      error.code === "ERR_INVALID_POLISHING_OUTPUT" &&
      error.diagnostic?.field === "status" &&
      error.diagnostic?.constraint === "selected-finalization-guidance",
  );
  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
});

for (const [name, mutate] of [
  [
    "content",
    async ({ projectPath }) =>
      writeFile(join(projectPath, "mutated.txt"), "mutated\n"),
  ],
  ["refs", async ({ projectPath }) => runGit(projectPath, "tag", "unexpected")],
  [
    "remotes",
    async ({ projectPath }) =>
      runGit(
        projectPath,
        "remote",
        "add",
        "origin",
        "https://example.invalid/repository.git",
      ),
  ],
  [
    "identity",
    async ({ projectPath }) =>
      runGit(projectPath, "config", "user.name", "Changed Identity"),
  ],
]) {
  test(`detects read-only ${name} mutation`, async (t) => {
    let mutated = false;
    const fixture = await createRealGitFixture(t, {
      async onRoleRun(role, _request, _turn, paths) {
        if (role === "worker" && !mutated) {
          mutated = true;
          await mutate(paths);
        }
      },
    });

    const result = await fixture.run();

    assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
    assert.equal(result.pause.reason, "read_only_agent_mutated_repository");
  });
}

test("resumes and completes runner-trusted polishing validation", async (t) => {
  const trustedValidation = trustedValidationSnapshot();
  const requiredChecks = [
    ...REQUIRED_CHECKS,
    { id: "C2", command: trustedValidation.commands[0].command },
  ];
  const bootstrap = (result) => ({ ...result, requiredChecks });
  const finalization = {
    ...finalizationPassed(),
    requiredChecks,
    checks: [
      ...checkResults("PASS"),
      {
        checkId: "C2",
        command: trustedValidation.commands[0].command,
        status: "NOT_RUN",
        evidence: ["Reserved for the runner-trusted executor."],
      },
    ],
  };
  const trustedCalls = [];
  const fixture = await createFixture(t, {
    settings: { ...SETTINGS, trustedChecks: ["service-check"] },
    trustedValidation,
    reviewer: [bootstrap(bootstrapReady("Reviewer")), reviewApproved()],
    worker: [
      clarificationReady(),
      bootstrap(bootstrapReady("Worker")),
      reconciliationResolved(),
      polishingCompleted(),
      finalization,
      finalization,
    ],
    onTrustedValidation(options) {
      trustedCalls.push(options);
      return {
        status: trustedCalls.length === 1 ? "BLOCKED" : "PASS",
        commandIdentity: options.commandIdentity,
        exitCode: trustedCalls.length === 1 ? null : 0,
        signal: null,
        timedOut: trustedCalls.length === 1,
        evidence: [
          trustedCalls.length === 1
            ? "The isolated temporary service is unavailable."
            : "The isolated temporary service check passed.",
        ],
        ...options.bindings,
      };
    },
  });

  const paused = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "environment_blocked");
  assert.equal(paused.pause.code, "ERR_TRUSTED_VALIDATION_BLOCKED");
  assert.equal(paused.pause.resumeState, "FINALIZE");
  assert.equal(paused.pipelineState.finalizationResult, null);

  const recovered = await fixture.recover();
  assert.deepEqual(
    recovered.pipelineState.trustedValidation,
    trustedValidation,
  );
  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(trustedCalls.length, 2);
  assert.deepEqual(
    result.pipelineState.finalizationResult.checks.map(
      ({ checkId, executor, commandIdentity }) => ({
        checkId,
        executor,
        commandIdentity,
      }),
    ),
    [
      { checkId: "C1", executor: "agent", commandIdentity: null },
      {
        checkId: "C2",
        executor: "runner",
        commandIdentity: trustedValidation.commands[0].identity,
      },
    ],
  );
  assert.equal(
    result.pipelineState.finalizationResult.trustedCommandFingerprint,
    trustedValidation.commandFingerprint,
  );
  assert.match(fixture.calls.worker[1].prompt, /service-check/u);
  assert.match(
    fixture.calls.worker.find(({ prompt }) =>
      prompt.includes("Run the complete project finalization procedure"),
    ).prompt,
    /return NOT_RUN/u,
  );
});

test("rejects non-allowlisted polishing finalization placeholders", () => {
  const trustedValidation = trustedValidationSnapshot();
  const requiredChecks = [
    ...REQUIRED_CHECKS,
    { id: "C2", command: trustedValidation.commands[0].command },
  ];
  const result = {
    ...finalizationPassed(),
    requiredChecks,
    checks: [
      { ...checkResults("PASS")[0], status: "NOT_RUN" },
      {
        checkId: "C2",
        command: trustedValidation.commands[0].command,
        status: "PASS",
        evidence: ["The agent substituted a host result."],
      },
    ],
  };

  assert.throws(
    () =>
      normalizeFinalizationResult(result, {
        trustedCommands: [trustedValidation.commands[0].command],
      }),
    /substituted/u,
  );
});

test("turns a runner-trusted polishing failure into a bounded issue", async (t) => {
  const trustedValidation = trustedValidationSnapshot();
  const requiredChecks = [
    ...REQUIRED_CHECKS,
    { id: "C2", command: trustedValidation.commands[0].command },
  ];
  const finalization = {
    ...finalizationPassed(),
    requiredChecks,
    checks: [
      ...checkResults("PASS"),
      {
        checkId: "C2",
        command: trustedValidation.commands[0].command,
        status: "NOT_RUN",
        evidence: ["Reserved for the runner-trusted executor."],
      },
    ],
  };
  let trustedCalls = 0;
  const fixture = await createFixture(t, {
    settings: { ...SETTINGS, trustedChecks: ["service-check"] },
    trustedValidation,
    reviewer: [
      { ...bootstrapReady("Reviewer"), requiredChecks },
      reviewApproved(),
    ],
    worker: [
      clarificationReady(),
      { ...bootstrapReady("Worker"), requiredChecks },
      reconciliationResolved(),
      polishingCompleted(),
      finalization,
      resolution("FIX", "F1"),
      finalization,
    ],
    async onRoleRun(role, request, _turn, { projectPath }) {
      if (
        role === "worker" &&
        /Resolve every current blocker/u.test(request.prompt)
      ) {
        await writeFile(
          join(projectPath, "tracked.txt"),
          "fixed service input\n",
        );
      }
    },
    onTrustedValidation(options) {
      trustedCalls += 1;
      return {
        status: trustedCalls === 1 ? "FAIL" : "PASS",
        commandIdentity: options.commandIdentity,
        exitCode: trustedCalls === 1 ? 7 : 0,
        signal: null,
        timedOut: false,
        evidence: [
          trustedCalls === 1
            ? "Runner-trusted command service-check exited with code 7."
            : "Runner-trusted command service-check exited with code 0.",
        ],
        ...options.bindings,
      };
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(trustedCalls, 2);
  assert.equal(result.counters.fixRounds, 1);
  assert.ok(
    fixture.calls.worker.some(({ prompt }) =>
      prompt.includes("A runner-trusted validation command failed."),
    ),
  );
});

for (const [name, code] of [
  ["binding drift", "ERR_TRUSTED_VALIDATION_BINDING_CHANGED"],
  ["repository mutation", "ERR_TRUSTED_VALIDATION_MUTATED_REPOSITORY"],
]) {
  test(`rejects trusted polishing validation ${name}`, async (t) => {
    const trustedValidation = trustedValidationSnapshot();
    const requiredChecks = [
      ...REQUIRED_CHECKS,
      { id: "C2", command: trustedValidation.commands[0].command },
    ];
    const finalization = {
      ...finalizationPassed(),
      requiredChecks,
      checks: [
        ...checkResults("PASS"),
        {
          checkId: "C2",
          command: trustedValidation.commands[0].command,
          status: "NOT_RUN",
          evidence: ["Reserved for the runner-trusted executor."],
        },
      ],
    };
    const fixture = await createFixture(t, {
      settings: { ...SETTINGS, trustedChecks: ["service-check"] },
      trustedValidation,
      reviewer: [{ ...bootstrapReady("Reviewer"), requiredChecks }],
      worker: [
        clarificationReady(),
        { ...bootstrapReady("Worker"), requiredChecks },
        reconciliationResolved(),
        polishingCompleted(),
        finalization,
      ],
      onTrustedValidation() {
        const error = new Error(`Trusted executor ${name}.`);
        error.code = code;
        throw error;
      },
    });

    const result = await fixture.run();

    assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
    assert.equal(result.pause.reason, "unsafe_git_state");
    assert.equal(result.pause.code, code);
  });
}

test("rejects validation-infrastructure drift after trusted polishing execution", async (t) => {
  const trustedValidation = trustedValidationSnapshot();
  const infrastructurePath = "LOCAL_ARTIFACTS/validation.json";
  const validationInfrastructure = [infrastructurePath];
  const requiredChecks = [
    ...REQUIRED_CHECKS,
    { id: "C2", command: trustedValidation.commands[0].command },
  ];
  const fixture = await createFixture(t, {
    async prepareProject(projectPath) {
      await mkdir(join(projectPath, "LOCAL_ARTIFACTS"), { recursive: true });
      await writeFile(join(projectPath, infrastructurePath), '{"version":1}\n');
    },
    settings: { ...SETTINGS, trustedChecks: ["service-check"] },
    trustedValidation,
    reviewer: [
      {
        ...bootstrapReady("Reviewer"),
        requiredChecks,
        validationInfrastructure,
      },
    ],
    worker: [
      clarificationReady(),
      {
        ...bootstrapReady("Worker"),
        requiredChecks,
        validationInfrastructure,
      },
      reconciliationResolved(),
      polishingCompleted(),
      {
        ...finalizationPassed(),
        requiredChecks,
        validationInfrastructure,
        checks: [
          ...checkResults("PASS"),
          {
            checkId: "C2",
            command: trustedValidation.commands[0].command,
            status: "NOT_RUN",
            evidence: ["Reserved for the runner-trusted executor."],
          },
        ],
      },
    ],
    async onTrustedValidation(options) {
      await writeFile(
        join(fixture.projectPath, infrastructurePath),
        '{"version":2}\n',
      );
      return {
        status: "PASS",
        commandIdentity: options.commandIdentity,
        exitCode: 0,
        signal: null,
        timedOut: false,
        evidence: ["The runner-trusted check passed."],
        ...options.bindings,
      };
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "unsafe_git_state");
  assert.equal(
    result.pause.code,
    "ERR_TRUSTED_VALIDATION_INFRASTRUCTURE_CHANGED",
  );
  assert.equal(result.pipelineState.finalizationResult, null);
});

test("corrects candidate Reviewer output before terminal finalization", async (t) => {
  const fixture = await createFixture(t, {
    reviewer: [
      bootstrapReady("Reviewer"),
      { ...candidateApproved(), unexpected: "field" },
      candidateApproved(),
      reviewApproved(),
    ],
  });

  const result = await fixture.run();
  const candidateCalls = fixture.calls.reviewer.filter(
    ({ schema }) => schema === CANDIDATE_REVIEW_SCHEMA,
  );

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(candidateCalls.length, 2);
  assert.equal(candidateCalls[1].session, undefined);
  assert.match(
    candidateCalls[1].prompt,
    /Pending correction diagnostic batch/u,
  );
  assert.ok(
    fixture.transitions.some(
      ({ patch }) => patch.pipelineState.reviewCorrection !== null,
    ),
  );
  assert.equal(result.pipelineState.pendingReviewCorrection, null);
  assert.equal(
    fixture.calls.worker.filter(({ schema }) => schema === FINALIZATION_SCHEMA)
      .length,
    1,
  );
});

test("projects candidate and terminal gate activity in order", async (t) => {
  const fixture = await createFixture(t);

  const result = await fixture.run();
  const gateActivity = fixture.transitions
    .map(({ options }) => options.activity)
    .filter(({ phase }) =>
      ["review", "finalization", "confirmation"].includes(phase),
    )
    .map(({ actor, phase, kind }) => ({ actor, phase, kind }));

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.deepEqual(gateActivity, [
    { actor: "reviewer", phase: "review", kind: "approved" },
    { actor: "worker", phase: "finalization", kind: "passed" },
    { actor: "reviewer", phase: "confirmation", kind: "approved" },
  ]);
});

test("routes independent terminal findings through candidate review and finalization", async (t) => {
  const fixture = await createFixture(t, {
    reviewer: [
      bootstrapReady("Reviewer"),
      candidateApproved(),
      reviewFindings("R1"),
      candidateApproved(),
      reviewApproved(),
    ],
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
      resolution("FIX", "R1"),
      finalizationPassed(),
    ],
    async onRoleRun(role, request, _turn, { projectPath }) {
      if (role === "worker" && request.schema === FINDING_RESOLUTION_SCHEMA) {
        await writeFile(join(projectPath, "terminal-fix.txt"), "fixed\n");
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(
    fixture.calls.reviewer.filter(
      ({ schema }) => schema === CANDIDATE_REVIEW_SCHEMA,
    ).length,
    2,
  );
  assert.equal(
    fixture.calls.reviewer.filter(({ schema }) => schema === REVIEW_SCHEMA)
      .length,
    2,
  );
  assert.equal(
    fixture.calls.worker.filter(({ schema }) => schema === FINALIZATION_SCHEMA)
      .length,
    2,
  );
  assert.equal(result.pipelineState.findings.length, 0);
});

test("corrects terminal Reviewer output without rerunning finalization", async (t) => {
  const fixture = await createFixture(t, {
    reviewer: [
      bootstrapReady("Reviewer"),
      candidateApproved(),
      { ...reviewApproved(), unexpected: "field" },
      reviewApproved(),
    ],
  });

  const result = await fixture.run();
  const confirmationCalls = fixture.calls.reviewer.filter(
    ({ schema }) => schema === REVIEW_SCHEMA,
  );

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(confirmationCalls.length, 2);
  assert.equal(confirmationCalls[1].session, undefined);
  assert.match(
    confirmationCalls[1].prompt,
    /Pending correction diagnostic batch/u,
  );
  assert.ok(
    fixture.transitions.some(
      ({ patch }) => patch.pipelineState.confirmationCorrection !== null,
    ),
  );
  assert.equal(result.pipelineState.pendingConfirmationCorrection, null);
  assert.equal(
    fixture.calls.worker.filter(({ schema }) => schema === FINALIZATION_SCHEMA)
      .length,
    1,
  );
});

test("fixes finalization failures in one batch and reruns the complete gate", async (t) => {
  const fixture = await createFixture(t, {
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationFailed(),
      resolution("FIX"),
      finalizationPassed(),
    ],
    async onRoleRun(role, request, _turn, { projectPath }) {
      if (
        role === "worker" &&
        /Resolve every current blocker/u.test(request.prompt)
      ) {
        await writeFile(join(projectPath, "tracked.txt"), "fixed validation\n");
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.fixRounds, 1);
  assert.equal(
    fixture.calls.worker.filter(({ prompt }) =>
      /Run the complete project finalization procedure/u.test(prompt),
    ).length,
    2,
  );
});

test("fixes stable review findings and invalidates prior fingerprints", async (t) => {
  const fixture = await createFixture(t, {
    reviewer: [bootstrapReady("Reviewer"), reviewFindings(), reviewApproved()],
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
      resolution("FIX", "R1"),
      finalizationPassed(),
    ],
    async onRoleRun(role, request, _turn, { projectPath }) {
      if (
        role === "worker" &&
        /Resolve every current blocker/u.test(request.prompt)
      ) {
        await writeFile(join(projectPath, "tracked.txt"), "minimal\n");
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.fixRounds, 1);
  assert.equal(result.pipelineState.findings.length, 0);
  assert.equal(result.pipelineState.correctionHistory.length, 0);
  assert.equal(
    fixture.calls.reviewer.filter(({ prompt }) =>
      /Review the complete/u.test(prompt),
    ).length,
    2,
  );
});

test("withdraws an evidence-based dispute after Reviewer reconsideration", async (t) => {
  const fixture = await createFixture(t, {
    reviewer: [
      bootstrapReady("Reviewer"),
      reviewFindings(),
      reconsideration("WITHDRAW"),
    ],
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
      resolution("DISPUTE"),
    ],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.disputeHistory[0].direction, "WITHDRAW");
  assert.equal(result.counters.fixRounds, 0);
});

test("arbitrates a repeatedly upheld dispute in a fresh read-only turn", async (t) => {
  const fixture = await createFixture(t, {
    arbiter: [findingArbitration("WORKER_CORRECT")],
    reviewer: [
      bootstrapReady("Reviewer"),
      reviewFindings(),
      reconsideration("UPHOLD"),
      reconsideration("UPHOLD"),
    ],
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
      resolution("DISPUTE"),
      resolution("DISPUTE"),
    ],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.deepEqual(result.pipelineState.findingArbitrations, [
    {
      findingId: "R1",
      direction: "WORKER_CORRECT",
      rationale: "The recorded repository evidence determines the finding.",
    },
  ]);
  assert.equal(fixture.calls.arbiter.at(-1).access, "read-only");
  assert.equal(fixture.calls.arbiter.at(-1).session, undefined);
  assert.match(fixture.calls.arbiter.at(-1).prompt, /"attempt": 1/u);
  assert.match(fixture.calls.arbiter.at(-1).prompt, /"attempt": 2/u);
  assert.deepEqual(
    result.pipelineState.disputeHistory.map(({ attempt }) => attempt),
    [1, 2],
  );

  const recovered = await fixture.recover();
  assert.deepEqual(
    recovered.pipelineState.disputeHistory.map(({ attempt }) => attempt),
    [1, 2],
  );
});

test("rejects oversized Worker dispute evidence before persisting it", async (t) => {
  const findingIds = Array.from({ length: 32 }, (_, index) => `R${index + 1}`);
  assert.ok(
    Buffer.byteLength(JSON.stringify(verboseResolutionBatch(findingIds))) >
      MAX_DISPUTE_HISTORY_BYTES,
  );
  const fixture = await createFixture(t, {
    reviewer: [bootstrapReady("Reviewer"), reviewFindingBatch(findingIds)],
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
      verboseResolutionBatch(findingIds),
    ],
  });

  await assert.rejects(fixture.run(), (cause) => {
    assert.equal(cause.code, "ERR_INVALID_POLISHING_OUTPUT");
    assert.match(cause.message, /durable history limit/u);
    return true;
  });
  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
  assert.deepEqual(fixture.currentRun.pipelineState.pendingDisputes, []);
  assert.deepEqual(fixture.currentRun.pipelineState.disputeHistory, []);
});

test("rejects oversized Reviewer evidence without losing pending disputes", async (t) => {
  const findingIds = Array.from({ length: 32 }, (_, index) => `R${index + 1}`);
  assert.ok(
    Buffer.byteLength(JSON.stringify(verboseReconsiderationBatch(findingIds))) >
      MAX_DISPUTE_HISTORY_BYTES,
  );
  const fixture = await createFixture(t, {
    reviewer: [
      bootstrapReady("Reviewer"),
      reviewFindingBatch(findingIds),
      verboseReconsiderationBatch(findingIds),
    ],
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
      resolutionBatch(findingIds.map((id) => ({ id, decision: "DISPUTE" }))),
    ],
  });

  await assert.rejects(fixture.run(), (cause) => {
    assert.equal(cause.code, "ERR_INVALID_POLISHING_OUTPUT");
    assert.match(cause.message, /durable history limit/u);
    return true;
  });
  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
  assert.equal(fixture.currentRun.pipelineState.pendingDisputes.length, 32);
  assert.deepEqual(fixture.currentRun.pipelineState.disputeHistory, []);
  assert.equal(
    fixture.currentRun.pipelineState.pendingDisputes[0].evidence[0],
    "The current test covers the reported behavior.",
  );
});

test("compacts correlated decision records for a thirty-third disputed finding", async (t) => {
  let interrupted = false;
  const fixture = await createFixture(t, {
    reviewer: [
      bootstrapReady("Reviewer"),
      reviewFindings("R33"),
      reconsideration("WITHDRAW", "R33"),
    ],
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
      resolution("DISPUTE", "R33"),
    ],
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        /Resolve every current blocker/u.test(request.prompt) &&
        !interrupted
      ) {
        interrupted = true;
        const error = new Error("Claude provider is unavailable.");
        error.code = "ERR_CLAUDE_PROVIDER_UNAVAILABLE";
        error.recoverable = true;
        throw error;
      }
    },
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "backend_unavailable");
  const disputeCounts = {};
  const disputeHistory = [];
  for (let number = 1; number <= 32; number += 1) {
    const findingId = `R${number}`;
    const arbitrated = number === 1;
    disputeCounts[findingId] = arbitrated ? 2 : 1;
    disputeHistory.push({
      findingId,
      attempt: 1,
      direction: arbitrated ? "UPHOLD" : "WITHDRAW",
      workerReason: "Repository evidence disputed the historical finding.",
      workerEvidence: ["Historical Worker evidence."],
      reviewerReason: "The historical finding was reconsidered.",
      reviewerEvidence: [],
    });
    if (arbitrated) {
      disputeHistory.push({
        ...disputeHistory.at(-1),
        attempt: 2,
      });
    }
  }
  await fixture.persistPipelineState({
    ...paused.pipelineState,
    disputeCounts,
    disputeHistory,
    findingArbitrations: [
      {
        findingId: "R1",
        direction: "WORKER_CORRECT",
        rationale: "Historical arbitration resolved the first finding.",
      },
    ],
  });

  const result = await fixture.run();
  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(Object.keys(result.pipelineState.disputeCounts).length, 32);
  assert.equal(result.pipelineState.disputeCounts.R1, undefined);
  assert.equal(result.pipelineState.disputeCounts.R33, 1);
  assert.equal(
    result.pipelineState.disputeHistory.some(
      ({ findingId }) => findingId === "R1",
    ),
    false,
  );
  assert.equal(
    result.pipelineState.disputeHistory.some(
      ({ findingId }) => findingId === "R33",
    ),
    true,
  );
  assert.deepEqual(result.pipelineState.findingArbitrations, []);
});

test("pauses at the fix budget and resumes with persisted additional rounds", async (t) => {
  let fix = 0;
  const fixture = await createFixture(t, {
    settings: { ...SETTINGS, maxFixRounds: 1 },
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationFailed(),
      resolution("FIX"),
      finalizationFailed(),
      resolution("FIX"),
      finalizationPassed(),
    ],
    async onRoleRun(role, request, _turn, { projectPath }) {
      if (
        role === "worker" &&
        /Resolve every current blocker/u.test(request.prompt)
      ) {
        fix += 1;
        await writeFile(join(projectPath, "tracked.txt"), `fix ${fix}\n`);
      }
    },
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "fix_limit_reached");
  assert.equal(paused.counters.fixRounds, 1);

  await assert.rejects(
    fixture.run({
      type: "extra-fix-rounds",
      amount: Number.MAX_SAFE_INTEGER,
    }),
    /fix-round budget is too large/u,
  );
  assert.equal(fixture.currentRun.revision, paused.revision);
  assert.equal(fixture.currentRun.pipelineState.additionalFixRounds, 0);

  const result = await fixture.run({ type: "extra-fix-rounds", amount: 1 });
  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.additionalFixRounds, 1);
  assert.equal(result.counters.fixRounds, 2);
});

test("persists mixed exhausted-budget disputes and fixes a reappearing exhausted finding", async (t) => {
  let fix = 0;
  const fixture = await createFixture(t, {
    settings: {
      ...SETTINGS,
      maxFixRounds: 1,
      maxDisputesPerFinding: 1,
    },
    reviewer: [
      bootstrapReady("Reviewer"),
      reviewFindingBatch(["R1", "R2"]),
      reviewFindingBatch(["R1", "R2"]),
      reconsideration("WITHDRAW", "R2"),
      reviewFindings("R2"),
      reviewApproved(),
    ],
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
      resolutionBatch([
        { id: "R1", decision: "FIX" },
        { id: "R2", decision: "FIX" },
      ]),
      finalizationPassed(),
      resolutionBatch([
        { id: "R1", decision: "FIX" },
        { id: "R2", decision: "DISPUTE" },
      ]),
      resolution("FIX", "R1"),
      finalizationPassed(),
      resolution("FIX", "R2"),
      finalizationPassed(),
    ],
    async onRoleRun(role, request, _turn, { projectPath }) {
      if (
        role === "worker" &&
        request.access === "workspace-write" &&
        /Resolve every current blocker/u.test(request.prompt)
      ) {
        fix += 1;
        await writeFile(
          join(projectPath, "tracked.txt"),
          `budget fix ${fix}\n`,
        );
      }
    },
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "fix_limit_reached");
  assert.deepEqual(paused.pipelineState.pendingDisputes, [
    {
      findingId: "R2",
      reason: "Repository evidence shows the finding is incorrect.",
      evidence: ["The current test covers the reported behavior."],
    },
  ]);
  assert.equal(paused.pipelineState.disputeCounts.R2, 1);

  const result = await fixture.run({ type: "extra-fix-rounds", amount: 2 });
  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.fixRounds, 3);
  assert.equal(result.pipelineState.disputeCounts.R2, 1);
  assert.equal(
    result.pipelineState.disputeHistory.at(-1).direction,
    "WITHDRAW",
  );
  assert.ok(
    fixture.calls.worker.some(({ prompt }) =>
      /cannot be disputed and must be fixed:[\s\S]*R2/u.test(prompt),
    ),
  );
  const laterReviews = fixture.calls.reviewer.filter(({ prompt }) =>
    /Review the complete current change set independently/u.test(prompt),
  );
  assert.ok(
    laterReviews
      .slice(2)
      .some(({ prompt }) =>
        /Prior decisions:[\s\S]*"findingId": "R2"[\s\S]*"direction": "WITHDRAW"/u.test(
          prompt,
        ),
      ),
  );
});

test("defers invalidated disputes until review re-establishes the finding", async (t) => {
  let fix = 0;
  const fixture = await createFixture(t, {
    settings: { ...SETTINGS, maxDisputesPerFinding: 1 },
    reviewer: [
      bootstrapReady("Reviewer"),
      reviewFindingBatch(["R1", "R2"]),
      reviewFindings("R2"),
      reconsideration("WITHDRAW", "R2"),
    ],
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
      resolutionBatch([
        { id: "R1", decision: "FIX" },
        { id: "R2", decision: "DISPUTE" },
      ]),
      finalizationFailed(),
      resolution("FIX", "F1"),
      finalizationPassed(),
    ],
    async onRoleRun(role, request, _turn, { projectPath }) {
      if (
        role === "worker" &&
        request.access === "workspace-write" &&
        /Resolve every current blocker/u.test(request.prompt)
      ) {
        fix += 1;
        await writeFile(
          join(projectPath, "tracked.txt"),
          `deferred fix ${fix}\n`,
        );
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.disputeCounts.R2, 1);
  assert.equal(
    result.pipelineState.disputeHistory.at(-1).direction,
    "WITHDRAW",
  );
  assert.equal(fixture.calls.arbiter.length, 0);
  const reconsiderationCalls = fixture.calls.reviewer.filter(({ prompt }) =>
    /Reconsider each disputed finding/u.test(prompt),
  );
  assert.equal(reconsiderationCalls.length, 1);
  assert.match(
    reconsiderationCalls[0].prompt,
    /Current findings:[\s\S]*"id": "R2"/u,
  );
});

test("records an exact-fingerprint override only after a stable finding pause", async (t) => {
  const fixture = await createFixture(t, {
    settings: { ...SETTINGS, maxSameFindingRounds: 1 },
    reviewer: [bootstrapReady("Reviewer"), reviewFindings(), reviewFindings()],
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
      resolution("FIX", "R1"),
      finalizationPassed(),
    ],
    async onRoleRun(role, request, _turn, { projectPath }) {
      if (
        role === "worker" &&
        /Resolve every current blocker/u.test(request.prompt)
      ) {
        await writeFile(
          join(projectPath, "tracked.txt"),
          "reviewed correction\n",
        );
      }
    },
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "no_progress");
  const fingerprint = paused.pipelineState.candidateReviewedFingerprint;

  assert.throws(
    () =>
      assertRun({
        ...paused,
        pause: { ...paused.pause, resumeState: "REVIEW" },
      }),
    /pause resume state is invalid/u,
  );
  await assert.rejects(
    fixture.run({ type: "extra-fix-rounds", amount: 1 }),
    /Additional fix rounds are not applicable/u,
  );
  assert.equal(fixture.currentRun.revision, paused.revision);

  const result = await fixture.run({
    type: "override-finding",
    findingId: "R1",
  });
  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.deepEqual(result.pipelineState.findingOverrides, [
    { findingId: "R1", fingerprint },
  ]);
});

test("uses one bounded stagnation arbitration before continuing fixes", async (t) => {
  let fix = 0;
  const fixture = await createFixture(t, {
    settings: {
      ...SETTINGS,
      maxSameFindingRounds: 5,
      stagnationWindowRounds: 1,
    },
    arbiter: [stagnationDirection()],
    reviewer: [
      bootstrapReady("Reviewer"),
      reviewFindings(),
      reviewFindings(),
      reviewApproved(),
    ],
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
      resolution("FIX", "R1"),
      finalizationPassed(),
      resolution("FIX", "R1"),
      finalizationPassed(),
    ],
    async onRoleRun(role, request, _turn, { projectPath }) {
      if (
        role === "worker" &&
        /Resolve every current blocker/u.test(request.prompt)
      ) {
        fix += 1;
        await writeFile(
          join(projectPath, "tracked.txt"),
          `stagnation fix ${fix}\n`,
        );
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.stagnationArbitrationUsed, true);
  assert.equal(
    result.pipelineState.stagnationDirection.direction,
    "CONTINUE_FIXES",
  );
  assert.equal(fixture.calls.arbiter.at(-1).access, "read-only");
});

test("requires Reviewer acceptance for task-authorized validation changes", async (t) => {
  const fixture = await createFixture(t, {
    onRoleRun: async (role, request) => {
      if (role === "worker" && request.prompt.includes("Polish the existing")) {
        await writeFile(
          join(request.cwd, ".agents", "skills", "finalization", "SKILL.md"),
          "---\nname: finalization\ndescription: Updated checks.\n---\n\nRun every required check.\n",
        );
      }
    },
    reviewer: [bootstrapReady("Reviewer"), reviewApproved("ACCEPTED")],
  });
  const completed = await fixture.run();
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(
    completed.pipelineState.reviewResult.validationChange,
    "ACCEPTED",
  );
  const reviewPrompt = fixture.calls.reviewer.find(({ prompt }) =>
    prompt.includes("Confirm the finalized change set"),
  ).prompt;
  assert.match(
    reviewPrompt,
    /Established validation tuple:[\s\S]*Candidate validation tuple and finalization evidence:/u,
  );
  assert.match(
    reviewPrompt,
    /"validationInfrastructureFingerprint": "[a-f0-9]{64}"/u,
  );
});
