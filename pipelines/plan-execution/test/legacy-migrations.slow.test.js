import assert from "node:assert/strict";
import test from "node:test";

import {
  migratePlanExecutionStateV13,
  planExecutionPipeline,
} from "../src/index.js";
import {
  createLegacyRecoveryFixture,
  removeUnchangedEvents,
} from "./support/index.js";

test("legacy confirmation proof crosses authentic persisted migration history", async (t) => {
  const fixture = await createLegacyRecoveryFixture(t, {
    format: true,
    pendingCorrection: false,
    steps: 1,
  });
  await fixture.rewrite(({ events }) => {
    const accepted = events.findIndex(
      ({ activity }) =>
        activity?.phase === "clean-confirm" && activity.kind === "clean",
    );
    // A migration marks old context provisional; it cannot synthesize a review.
    for (const event of events) {
      event.state.pipelineState.planContextVersion = 0;
      event.state.pipelineState.stepImplementation = null;
      event.state.pipelineState.implementationEvidenceLegacy = true;
    }
    const migration = structuredClone(events[accepted]);
    delete migration.state.pipelineState.finalizationGuidance;
    migration.state.pipelineStateVersion = 21;
    migration.activity = {
      actor: "runner",
      phase: "runtime",
      kind: "migrated",
      message: "Migrated fixture state.",
    };
    for (const event of events.slice(0, accepted + 1)) {
      event.state.pipelineStateVersion = 14;
      delete event.state.pipelineState.finalizationRecovery;
      delete event.state.pipelineState.finalizationGuidance;
    }
    for (const event of events.slice(accepted + 1)) {
      event.state.pipelineStateVersion = 21;
      delete event.state.pipelineState.finalizationGuidance;
    }
    events.splice(accepted + 1, 0, migration);
    events.forEach((event, index) => {
      event.revision = index + 1;
      event.state.revision = index + 1;
    });
    removeUnchangedEvents(events);
  });
  assert.deepEqual(await fixture.recoveryAction(), [
    { type: "resume", action: null },
  ]);
  await fixture.rewrite(({ events }) => {
    events.find(
      ({ activity }) => activity?.kind === "migrated",
    ).state.counters.fixRounds += 1;
  });
  assert.deepEqual(await fixture.recoveryAction(), []);
  await fixture.rewrite(({ events }) => {
    events.find(
      ({ activity }) => activity?.kind === "migrated",
    ).state.counters.fixRounds -= 1;
  });
  assert.equal(
    (await fixture.openRunner().resume({ runId: fixture.runId })).run
      .pipelineState.workflowState,
    "DONE",
  );

  const unproven = structuredClone(fixture.failed);
  unproven.pipelineStateVersion = 13;
  for (const field of [
    "candidateReviewResult",
    "candidateReviewedFingerprint",
    "candidateConfirmationFingerprint",
    "candidateMigrationPending",
    "confirmationCorrection",
    "pendingConfirmationCorrection",
    "finalizationRecovery",
  ])
    delete unproven.pipelineState[field];
  unproven.revision = 1;
  unproven.updatedAt = unproven.createdAt;
  const projected = {
    ...unproven,
    pipelineStateVersion: 21,
    pipelineState: {
      ...migratePlanExecutionStateV13(unproven),
      finalizationRecovery: {
        attempts: 0,
        additionalAttempts: 0,
        required: false,
        pending: false,
        feedback: null,
      },
    },
  };
  assert.equal(
    projected.pipelineState.candidateReviewResult.status,
    "APPROVED",
  );
  planExecutionPipeline.prepareRecovery(projected, {
    run: unproven,
    events: [
      {
        runId: unproven.runId,
        revision: 1,
        state: unproven,
        activity: null,
      },
    ],
  });
  assert.throws(() =>
    planExecutionPipeline.validateResumeAction(projected, null),
  );
});
