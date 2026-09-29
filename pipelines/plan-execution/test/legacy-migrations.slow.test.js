import assert from "node:assert/strict";
import test from "node:test";
import {
  planExecutionPipeline,
  migratePlanExecutionStateV13,
} from "../src/index.js";
import { candidateGatePassed } from "../src/gate-evidence.js";
import { BOOTSTRAP_SCHEMA, FINALIZATION_SCHEMA } from "../src/schemas.js";
import {
  createLegacyRecoveryFixture,
  removeUnchangedEvents,
} from "./support/index.js";

test("version-22 terminal history remains readable and scoped discovery precedes recovery work", async (t) => {
  const fixture = await createLegacyRecoveryFixture(t, {
    mode: "combined",
    steps: 2,
  });
  await fixture.rewrite(({ events }) => {
    for (const event of events) {
      event.state.pipelineStateVersion = 22;
      const state = event.state.pipelineState;
      delete state.validationSchedule;
      delete state.validationAmendment;
      delete state.validationScopeLegacy;
      if (state.finalizationResult) delete state.finalizationResult.step;
      if (state.reviewResult)
        delete state.reviewResult.validationTupleFingerprint;
      for (const role of ["worker", "reviewer"]) {
        for (const check of state[`${role}Validation`]?.requiredChecks ?? [])
          delete check.steps;
      }
    }
  });
  const before = await fixture.bytes();
  assert.deepEqual(await fixture.recoveryAction(), [
    { type: "resume", action: null },
  ]);
  assert.deepEqual(await fixture.bytes(), before);
  const offset = fixture.calls.length;
  const { run } = await fixture.openRunner().resume({ runId: fixture.runId });
  assert.equal(run.pipelineState.workflowState, "DONE");
  assert.equal(run.pipelineStateVersion, 24);
  assert.equal(
    run.pipelineState.completedCommits[0],
    fixture.failed.pipelineState.completedCommits[0],
  );
  const resumed = fixture.calls.slice(offset);
  const discoveries = resumed.filter(
    ({ schema }) => schema === BOOTSTRAP_SCHEMA,
  );
  assert.equal(discoveries.length, 2);
  assert.ok(
    discoveries.every(
      ({ access, prompt }) =>
        access === "read-only" && prompt.includes("versioned-state migration"),
    ),
  );
  const firstWrite = resumed.findIndex(({ access }) => access !== "read-only");
  assert.ok(
    discoveries.every((request) => resumed.indexOf(request) < firstWrite),
  );
  assert.equal(
    resumed.filter(({ schema }) => schema === FINALIZATION_SCHEMA).length,
    1,
  );
  assert.equal(run.pipelineState.validationScopeLegacy, false);
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

test("legacy terminal proof survives requirement migration and rediscovery precedes new work", async (t) => {
  const fixture = await createLegacyRecoveryFixture(t, { steps: 1 });
  await fixture.rewrite(({ events }) => {
    for (const event of events) {
      event.state.pipelineStateVersion = 17;
      for (const role of ["worker", "reviewer"]) {
        const value = event.state.pipelineState[`${role}Validation`];
        if (value) {
          delete value.capabilityRequirements;
          delete value.environmentBlockers;
        }
      }
    }
  });
  const before = await fixture.bytes();
  assert.deepEqual(await fixture.recoveryAction(), [
    { type: "resume", action: null },
  ]);
  assert.deepEqual(await fixture.bytes(), before);
  const calls = fixture.calls.length;
  const { run } = await fixture.openRunner().resume({ runId: fixture.runId });
  assert.equal(run.pipelineState.workflowState, "DONE");
  const resumed = fixture.calls.slice(calls);
  assert.match(resumed[0].prompt, /versioned-state migration checkpoint/u);
  assert.equal(resumed[0].access, "read-only");
  assert.deepEqual(
    run.pipelineState.workerValidation.capabilityRequirements,
    [],
  );
});

test("runner migrates version-15 execution under a lease and rediscovers context before finalization", async (t) => {
  const fixture = await createLegacyRecoveryFixture(t, { steps: 1 });
  await fixture.rewrite(({ events }) => {
    for (const event of events) event.state.pipelineStateVersion = 15;
  });
  const before = await fixture.bytes();
  await fixture.recoveryAction();
  assert.deepEqual(await fixture.bytes(), before);
  const calls = fixture.calls.length;
  const { run } = await fixture.openRunner().resume({ runId: fixture.runId });
  assert.equal(run.pipelineStateVersion, planExecutionPipeline.stateVersion);
  assert.equal(run.pipelineState.workflowState, "DONE");
  const resumedCalls = fixture.calls.slice(calls);
  assert.equal(resumedCalls[0].access, "read-only");
  assert.equal(resumedCalls[0].schema, BOOTSTRAP_SCHEMA);
  assert.match(resumedCalls[0].prompt, /versioned-state migration/u);
  assert.equal(
    resumedCalls.filter(({ access }) => access === "local-commit").length,
    1,
  );
  assert.equal(
    resumedCalls.filter(({ schema }) => schema === FINALIZATION_SCHEMA).length,
    1,
  );
  const history = await fixture.history();
  assert.equal(
    history.events.filter(({ activity }) => activity?.kind === "migrated")
      .length,
    1,
  );
});

test("authentic legacy journal restores evidence before a new commit effect", async (t) => {
  const fixture = await createLegacyRecoveryFixture(t, { steps: 1 });
  await fixture.rewrite(({ events }) => {
    for (const event of events) {
      event.state.pipelineStateVersion = 19;
      delete event.state.pipelineState.stepImplementation;
      delete event.state.pipelineState.implementationEvidenceLegacy;
    }
    removeUnchangedEvents(events);
  });
  const before = await fixture.bytes();
  assert.deepEqual(await fixture.recoveryAction(), [
    { type: "resume", action: null },
  ]);
  assert.deepEqual(await fixture.bytes(), before);
  const { run } = await fixture.openRunner().resume({ runId: fixture.runId });
  assert.equal(
    run.pipelineState.workflowState,
    "DONE",
    JSON.stringify(run.pause),
  );
  const history = await fixture.history();
  const restored = history.events.find(
    ({ state }) => state.pipelineState.stepImplementation?.accepted,
  );
  assert.ok(restored);
  assert.equal(restored.state.pipelineState.stepImplementation.step, 1);
  assert.equal(run.pipelineState.completedCommits.length, 1);
});

test("legacy confirmation migrations preserve journal proof but cannot synthesize acceptance", async (t) => {
  const fixture = await createLegacyRecoveryFixture(t, { steps: 1 });
  await fixture.rewrite(({ events }) => {
    for (const event of events) {
      event.state.pipelineStateVersion = 14;
      delete event.state.pipelineState.finalizationRecovery;
      delete event.state.pipelineState.finalizationGuidance;
    }
  });
  const oldBytes = await fixture.bytes();
  assert.deepEqual(await fixture.recoveryAction(), [
    { type: "resume", action: null },
  ]);
  assert.deepEqual(await fixture.bytes(), oldBytes);
  fixture.failAgain();
  const { run } = await fixture.openRunner().resume({ runId: fixture.runId });
  assert.equal(run.pause.reason, "backend_unavailable");
  const history = await fixture.history();
  assert.equal(
    history.events.filter(({ activity }) => activity?.kind === "migrated")
      .length,
    1,
  );
  assert.equal(history.events[0].state.pipelineStateVersion, 14);
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
  ]) {
    delete unproven.pipelineState[field];
  }
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

test("legacy confirmation proof crosses an authentic intervening migration and rejects hidden changes", async (t) => {
  const fixture = await createLegacyRecoveryFixture(t, {
    steps: 1,
    format: true,
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
});
