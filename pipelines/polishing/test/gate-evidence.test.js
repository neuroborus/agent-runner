import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { migratePolishingStateV9, runPolishing } from "../src/index.js";
import {
  candidateGatePassed,
  finalizationGatePassed,
  handoffGatePassed,
} from "../src/gate-evidence.js";
import { normalizePipelineState } from "../src/workflow-contract.js";
import {
  bootstrapReady,
  candidateApproved,
  candidateClean,
  checkAndFix,
  clarificationReady,
  cleanConfirmation,
  cleanConfirmationFindings,
  createFixture,
  finalizationPassed,
  hash,
  polishingCompleted,
  reconciliationResolved,
  resolution,
  reviewApproved,
  reviewFindings,
  versionNineState,
} from "./support/index.js";

for (const mode of ["independent", "lazy"]) {
  const bootstrap = () => [
    clarificationReady(),
    bootstrapReady("Worker"),
    ...(mode === "independent" ? [reconciliationResolved()] : []),
  ];
  const candidate = () =>
    mode === "lazy" ? [checkAndFix(), candidateClean()] : [];

  test(`${mode} binds candidate approval separately from formatted handoff content`, async (t) => {
    const fixture = await createFixture(t, {
      mode,
      worker: [
        ...bootstrap(),
        polishingCompleted(),
        ...candidate(),
        finalizationPassed(),
        ...(mode === "lazy" ? [cleanConfirmation()] : []),
      ],
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
    assert.notEqual(
      state.candidateReviewedFingerprint,
      state.finalizedFingerprint,
    );
    assert.equal(candidateGatePassed(state), true);
    assert.equal(candidateGatePassed(state, state.finalizedFingerprint), false);
    assert.equal(finalizationGatePassed(state), true);
    assert.equal(handoffGatePassed(state), true);
    assert.doesNotThrow(() => normalizePipelineState(state));

    if (mode === "independent") {
      const accepted = {
        ...state,
        candidateReviewResult: {
          ...state.candidateReviewResult,
          status: "FINDINGS",
          findingIds: ["R1"],
        },
        findingOverrides: [
          { findingId: "R1", fingerprint: state.candidateReviewedFingerprint },
        ],
      };
      assert.equal(handoffGatePassed(accepted), true);
      assert.equal(
        handoffGatePassed({
          ...accepted,
          findingOverrides: [
            { findingId: "R1", fingerprint: state.finalizedFingerprint },
          ],
        }),
        false,
      );
      const rejectedValidation = {
        ...state,
        reviewResult: {
          ...state.reviewResult,
          status: "FINDINGS",
          validationChange: "REJECTED",
        },
        previousFindings: reviewFindings("R1").findings,
        findingOverrides: [
          { findingId: "R1", fingerprint: state.finalizedFingerprint },
        ],
      };
      assert.equal(handoffGatePassed(rejectedValidation), true);
      assert.equal(
        handoffGatePassed({
          ...rejectedValidation,
          findingOverrides: [
            {
              findingId: "R1",
              fingerprint: state.candidateReviewedFingerprint,
            },
          ],
        }),
        false,
      );
    }

    const cases = [
      [
        "absent candidate",
        {
          candidateReviewResult: null,
          candidateReviewedFingerprint: null,
          candidateConfirmationFingerprint: null,
        },
      ],
      [
        "forged candidate record",
        {
          candidateReviewResult: {
            ...state.candidateReviewResult,
            fingerprint: hash("forged"),
          },
        },
      ],
      [
        "empty finding acceptance",
        {
          candidateReviewResult: {
            ...state.candidateReviewResult,
            status: "FINDINGS",
            findingIds: [],
          },
        },
      ],
      [
        "unresolved candidate finding",
        {
          candidateReviewResult: {
            ...state.candidateReviewResult,
            status: "FINDINGS",
            findingIds: ["R1"],
          },
        },
      ],
      [
        "absent finalization",
        { finalizationResult: null, finalizedFingerprint: null },
      ],
      [
        "forged finalization record",
        {
          finalizationResult: {
            ...state.finalizationResult,
            fingerprint: hash("forged"),
          },
        },
      ],
      [
        "absent terminal confirmation",
        { reviewResult: null, reviewedFingerprint: null },
      ],
      [
        "stale terminal confirmation",
        {
          reviewResult: {
            ...state.reviewResult,
            fingerprint: state.candidateReviewedFingerprint,
          },
          reviewedFingerprint: state.candidateReviewedFingerprint,
        },
      ],
      [
        "unresolved terminal findings",
        {
          reviewResult: { ...state.reviewResult, status: "FINDINGS" },
          previousFindings: reviewFindings("R1").findings,
        },
      ],
      ...(mode === "lazy"
        ? [
            [
              "absent primary clean",
              { candidateConfirmationFingerprint: null },
            ],
            [
              "forged primary clean",
              { candidateConfirmationFingerprint: state.finalizedFingerprint },
            ],
            ["absent terminal clean", { cleanConfirmationFingerprint: null }],
          ]
        : []),
    ];
    const callsBefore = Object.values(fixture.calls).flat().length;
    fixture.runtime.git.stagePolishingHandoff = () =>
      assert.fail("Invalid evidence must not stage.");
    for (const [name, patch] of cases) {
      await t.test(name, async () => {
        const invalid = { ...state, ...patch, workflowState: "HANDOFF" };
        assert.equal(handoffGatePassed(invalid), false);
        assert.throws(() => normalizePipelineState(invalid));
        await assert.rejects(
          runPolishing({
            run: { ...completed, pipelineState: invalid },
            runtime: fixture.runtime,
          }),
        );
      });
    }
    assert.equal(Object.values(fixture.calls).flat().length, callsBefore);
  });

  test(`${mode} unchanged repair reconverges while retaining valid finalization`, async (t) => {
    const fixture = await createFixture(t, {
      mode,
      worker: [
        ...bootstrap(),
        polishingCompleted(),
        ...candidate(),
        finalizationPassed(),
        ...(mode === "lazy"
          ? [
              cleanConfirmationFindings("R1"),
              checkAndFix(),
              candidateClean(),
              cleanConfirmation(),
            ]
          : [resolution("FIX", "R1")]),
      ],
      reviewer: [
        bootstrapReady("Reviewer"),
        candidateApproved(),
        reviewFindings("R1"),
        candidateApproved(),
        reviewApproved(),
      ],
    });
    const completed = await fixture.run();
    assert.equal(completed.pipelineState.workflowState, "DONE");
    const retained = fixture.transitions
      .map(({ patch }) => patch.pipelineState)
      .filter(
        (state) =>
          state.finalizationResult?.status === "PASS" &&
          state.candidateReviewResult === null,
      );
    assert.ok(retained.length > 0);
    for (const state of retained) {
      assert.equal(finalizationGatePassed(state), true);
      assert.equal(candidateGatePassed(state), false);
      assert.equal(handoffGatePassed(state), false);
      assert.equal(state.reviewedFingerprint, null);
      assert.equal(state.cleanConfirmationFingerprint, null);
    }
    assert.equal(
      fixture.calls.worker.filter(({ prompt }) =>
        /Run the complete project finalization procedure/u.test(prompt),
      ).length,
      1,
    );
  });

  test(`${mode} legacy handoff preserves accepted proof without inventing missing confirmation`, async (t) => {
    const fixture = await createFixture(t, {
      mode,
      worker: [
        ...bootstrap(),
        polishingCompleted(),
        ...candidate(),
        finalizationPassed(),
        ...(mode === "lazy" ? [cleanConfirmation()] : []),
      ],
    });
    const completed = await fixture.run();
    const legacy = versionNineState({
      ...completed.pipelineState,
      workflowState: "HANDOFF",
    });
    const migrated = migratePolishingStateV9({ pipelineState: legacy });
    assert.equal(handoffGatePassed(migrated), true);
    assert.doesNotThrow(() => normalizePipelineState(migrated));
    const missing = migratePolishingStateV9({
      pipelineState: {
        ...legacy,
        reviewResult: null,
        reviewedFingerprint: null,
      },
    });
    assert.equal(missing.candidateReviewResult, null);
    assert.equal(handoffGatePassed(missing), false);
    assert.throws(() => normalizePipelineState(missing));
    const callsBefore = Object.values(fixture.calls).flat().length;
    fixture.persistPipelineState({ ...migrated, workflowState: "DONE" });
    await fixture.run();
    assert.equal(Object.values(fixture.calls).flat().length, callsBefore);
  });
}
