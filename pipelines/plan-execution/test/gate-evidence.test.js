import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { normalizePipelineState } from "../src/workflow-contract.js";
import { FINALIZATION_SCHEMA } from "../src/schemas.js";
import {
  bootstrapReady,
  checkAndFix,
  clarificationReady,
  createFixture,
  finalizationPassed,
  implementationCompleted,
  reconciliationResolved,
} from "./support/index.js";

function modeOptions(mode) {
  return {
    mode,
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      ...(mode === "independent" ? [reconciliationResolved()] : []),
    ],
    workWorker: [
      implementationCompleted(),
      checkAndFix(),
      finalizationPassed(),
    ],
  };
}

for (const mode of ["independent", "lazy"]) {
  test(`${mode} binds each gate to its own evidence across finalization formatting`, async (t) => {
    let candidate;
    let finalized;
    let authorized;
    const fixture = await createFixture(t, {
      ...modeOptions(mode),
      async onRoleRun(_role, request) {
        if (request.schema === FINALIZATION_SCHEMA) {
          candidate = structuredClone(fixture.currentRun.pipelineState);
          await writeFile(join(request.cwd, "formatted.js"), "export {};\n");
        }
        if (request.access === "local-commit") {
          authorized = structuredClone(fixture.currentRun.pipelineState);
        }
      },
      onTransition(run) {
        if (run.pipelineState.workflowState === "CONFIRM") {
          finalized = structuredClone(run.pipelineState);
        }
      },
    });
    const completed = await fixture.run();
    assert.equal(completed.pipelineState.workflowState, "DONE");
    assert.equal(candidate.finalizationResult, null);
    assert.equal(candidate.reviewResult, null);
    assert.equal(finalized.reviewResult, null);
    assert.notEqual(
      finalized.finalizedFingerprint,
      candidate.candidateReviewedFingerprint,
    );
    assert.deepEqual(
      finalized.candidateReviewResult,
      candidate.candidateReviewResult,
    );
    assert.equal(
      authorized.reviewResult.fingerprint,
      finalized.finalizedFingerprint,
    );
    assert.equal(
      authorized.pendingCommit.authorization.expectedContentFingerprint,
      finalized.finalizedFingerprint,
    );
    assert.equal(
      authorized.candidateConfirmationFingerprint,
      mode === "lazy" ? candidate.candidateReviewedFingerprint : null,
    );
    assert.equal(
      authorized.cleanConfirmationFingerprint,
      mode === "lazy" ? finalized.finalizedFingerprint : null,
    );
    assert.doesNotThrow(() => normalizePipelineState(authorized));

    const corruptions = [
      [
        "missing candidate",
        (state) => {
          state.candidateReviewResult = null;
          state.candidateReviewedFingerprint = null;
          state.candidateConfirmationFingerprint = null;
        },
      ],
      [
        "candidate record bound to different content",
        (state) => {
          state.candidateReviewResult.fingerprint = "0".repeat(64);
        },
      ],
      [
        "unresolved candidate findings",
        (state) => {
          state.candidateReviewResult.status = "FINDINGS";
          state.candidateReviewResult.findingIds = ["R1"];
        },
      ],
      [
        "missing finalization",
        (state) => {
          state.finalizationResult = null;
          state.finalizedFingerprint = null;
        },
      ],
      [
        "finalization record bound to different content",
        (state) => {
          state.finalizationResult.fingerprint = "0".repeat(64);
        },
      ],
      [
        "missing terminal confirmation",
        (state) => {
          state.reviewResult = null;
          state.reviewedFingerprint = null;
          state.cleanConfirmationFingerprint = null;
        },
      ],
      [
        "terminal confirmation of pre-format content",
        (state) => {
          state.reviewResult.fingerprint =
            candidate.candidateReviewedFingerprint;
          state.reviewedFingerprint = candidate.candidateReviewedFingerprint;
          // Isolate gate validation from the already-bound effect contract.
          state.pendingCommit = null;
          if (mode === "lazy") {
            state.cleanConfirmationFingerprint =
              candidate.candidateReviewedFingerprint;
          }
        },
      ],
      ...(mode === "lazy"
        ? [
            [
              "missing primary clean confirmation",
              (state) => {
                state.candidateConfirmationFingerprint = null;
              },
            ],
            [
              "missing terminal clean confirmation",
              (state) => {
                state.cleanConfirmationFingerprint = null;
              },
            ],
          ]
        : []),
    ];
    if (mode === "independent") {
      const overridden = structuredClone(authorized);
      overridden.candidateReviewResult.status = "FINDINGS";
      overridden.candidateReviewResult.findingIds = ["R1"];
      overridden.findingOverrides = [
        {
          findingId: "R1",
          fingerprint: candidate.candidateReviewedFingerprint,
        },
      ];
      assert.doesNotThrow(() => normalizePipelineState(overridden));
      overridden.findingOverrides[0].fingerprint =
        finalized.finalizedFingerprint;
      assert.throws(() => normalizePipelineState(overridden), {
        code: "ERR_INVALID_PLAN_EXECUTION_STATE",
      });
    }
    for (const [description, corrupt] of corruptions) {
      await t.test(description, () => {
        const forged = structuredClone(authorized);
        corrupt(forged);
        assert.throws(() => normalizePipelineState(forged), {
          code: "ERR_INVALID_PLAN_EXECUTION_STATE",
        });
      });
    }
  });

  test(`${mode} verifies a consumed formatted commit without renewing any gate or effect`, async (t) => {
    let interrupted = true;
    let verifications = 0;
    const fixture = await createFixture(t, {
      ...modeOptions(mode),
      async onRoleRun(_role, request) {
        if (request.schema === FINALIZATION_SCHEMA) {
          await writeFile(join(request.cwd, "formatted.js"), "export {};\n");
        }
      },
      onCommitVerify() {
        verifications += 1;
        if (interrupted) {
          interrupted = false;
          throw new Error("Verification interrupted after effect consumption.");
        }
      },
    });
    const paused = await fixture.run();
    assert.equal(paused.pause.reason, "commit_failed");
    assert.equal(paused.pipelineState.pendingCommit.status, "consumed");
    const calls = Object.values(fixture.calls).flat().length;
    const resumed = await fixture.run();
    assert.equal(resumed.pipelineState.workflowState, "DONE");
    assert.equal(resumed.pipelineState.completedCommits.length, 1);
    assert.equal(verifications, 2);
    assert.equal(Object.values(fixture.calls).flat().length, calls);
    for (const field of [
      "candidateReviewResult",
      "candidateReviewedFingerprint",
      "candidateConfirmationFingerprint",
      "finalizationResult",
      "finalizedFingerprint",
      "reviewResult",
      "reviewedFingerprint",
      "cleanConfirmationFingerprint",
    ]) {
      assert.deepEqual(
        resumed.pipelineState[field],
        paused.pipelineState[field],
      );
    }
  });
}
