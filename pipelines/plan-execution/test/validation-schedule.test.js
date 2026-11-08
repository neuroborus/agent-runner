import assert from "node:assert/strict";
import test from "node:test";

import { createTrustedValidationSnapshot } from "../../../src/trusted-validation/index.js";

import { REPOSITORY_DISCOVERY_SCHEMA } from "../src/bootstrap-unit-schemas.js";
import {
  migratePlanExecutionStateV22,
  migratePlanExecutionStateV26,
} from "../src/index.js";
import {
  CANDIDATE_REVIEW_SCHEMA,
  CHECK_AND_FIX_SCHEMA,
  FINALIZATION_SCHEMA,
  REVIEW_SCHEMA,
} from "../src/schemas.js";
import {
  normalizeBootstrapResult,
  normalizeFinalizationResult,
  normalizePipelineState,
} from "../src/workflow-contract.js";
import {
  deriveValidationSchedule,
  scheduledChecks,
  validationEvidenceFingerprint,
} from "../src/validation-schedule.js";
import {
  bootstrapReady,
  checkAndFix,
  clarificationReady,
  cleanConfirmation,
  createFixture,
  finalizationPassed,
  implementationCompleted,
  reconciliationResolved,
  resolution,
  trustedValidationSnapshot,
  reviewApproved,
  reviewFindings,
  stagnation,
  terminalConfirmation,
} from "./support/index.js";

const plan =
  "## Commit 1: feat(test): add first behavior\n\nFirst.\n\n## Commit 2: feat(test): add second behavior\n\nSecond.\n";
const fast = "npm test";
const slow = "npm run test:service";
const reviewerOnly = "npm run reviewer-check";
const check = (id, command, steps) => ({ id, command, steps });

function migrateUnscopedState(state) {
  const legacy = structuredClone(state);
  for (const field of [
    "validationSchedule",
    "validationAmendment",
    "validationScopeLegacy",
  ])
    delete legacy[field];
  if (legacy.finalizationResult) delete legacy.finalizationResult.step;
  if (legacy.reviewResult)
    delete legacy.reviewResult.validationTupleFingerprint;
  for (const role of ["worker", "reviewer"]) {
    for (const check of legacy[`${role}Validation`]?.requiredChecks ?? [])
      delete check.steps;
  }
  return migratePlanExecutionStateV22({ pipelineState: legacy });
}

test("scoped discovery rejects missing, unordered, and out-of-plan applicability and incomplete coverage", () => {
  for (const steps of [
    undefined,
    [],
    [0],
    [1, 1],
    [2, 1],
    [1, 3],
    [1.5],
    [1],
  ]) {
    const result = bootstrapReady("Worker");
    result.requiredChecks = [check("C1", fast, steps)];
    if (steps === undefined) delete result.requiredChecks[0].steps;
    assert.throws(() => normalizeBootstrapResult(result, "Worker", 2), {
      code: "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
    });
  }
  const worker = {
    requiredChecks: [check("C9", fast, [1, 2]), check("C2", slow, [2])],
  };
  const reviewer = {
    requiredChecks: [check("C1", slow, [1]), check("C9", reviewerOnly, [2])],
  };
  assert.deepEqual(deriveValidationSchedule([worker, reviewer], 2), {
    commands: [fast, slow, reviewerOnly],
    steps: [
      { step: 1, commandIndexes: [0, 1] },
      { step: 2, commandIndexes: [0, 1, 2] },
    ],
  });
});

function discovery(role, independent, trustedValidation) {
  const trusted = trustedValidation.commands[0];
  return {
    ...bootstrapReady(role),
    requiredChecks: [
      check("C1", fast, [1, 2]),
      check("C2", slow, [2]),
      ...(role === "Reviewer" && independent
        ? [check("C3", reviewerOnly, [2])]
        : []),
    ],
    capabilityRequirements: [
      {
        command: slow,
        commandIdentity: trusted.identity,
        capabilities: {
          scratch: false,
          cache: false,
          sourceProjection: true,
          artifacts: [],
        },
        unsupported: [],
      },
    ],
  };
}

function finalized(commands, trustedCommands = [slow]) {
  return {
    ...finalizationPassed(),
    requiredChecks: commands.map((command, index) => ({
      id: `C${index + 1}`,
      command,
    })),
    checks: commands.map((command, index) => ({
      checkId: `C${index + 1}`,
      command,
      status: trustedCommands.includes(command) ? "NOT_RUN" : "PASS",
      evidence: [
        trustedCommands.includes(command)
          ? "Reserved for the runner."
          : "Injected check passed.",
      ],
    })),
  };
}

for (const mode of ["independent", "lazy", "combined"]) {
  test(`${mode} persists per-step selection and reuses unchanged confirmation evidence`, async (t) => {
    const independent = mode !== "lazy";
    const trustedValidation = trustedValidationSnapshot("service-check", slow, {
      sourceProjection: true,
    });
    const trustedSteps = [];
    const trustedBindings = [];
    const agentChecks = [];
    const preparation = [];
    const stop = Object.assign(new Error("persist and reload checkpoint"), {
      code: "ERR_RUN_REVISION_CHANGED",
    });
    let checkpoint = 0;
    const fixture = await createFixture(t, {
      plan,
      mode,
      trustedValidation,
      modeSettings: { trustedChecks: ["service-check"] },
      worker: [
        clarificationReady(),
        discovery("Worker", independent, trustedValidation),
        ...(independent ? [reconciliationResolved()] : []),
      ],
      reviewer: independent
        ? [discovery("Reviewer", true, trustedValidation)]
        : [],
      workWorker: [
        implementationCompleted(),
        ...(mode === "independent" ? [] : [checkAndFix()]),
        finalized([fast]),
        implementationCompleted(),
        ...(mode === "independent" ? [] : [checkAndFix()]),
        finalized([fast, slow, ...(independent ? [reviewerOnly] : [])]),
      ],
      onRequirementInspection(request) {
        preparation.push(structuredClone(request));
        return { status: "READY", blockers: [] };
      },
      onRoleRun(_role, request) {
        if (request.schema !== FINALIZATION_SCHEMA) return;
        const state = fixture.currentRun.pipelineState;
        agentChecks.push([
          state.currentStep,
          state.requiredChecks.map(({ command }) => command),
        ]);
        const tuple = JSON.parse(
          /Established validation tuple:\n([\s\S]+?)\n\n/.exec(
            request.prompt,
          )[1],
        );
        assert.deepEqual(tuple.requiredChecks, state.requiredChecks);
        assert.equal(tuple.step, state.currentStep);
        for (const prompt of [request.prompt, request.recoveryPrompt]) {
          const reservations = JSON.parse(
            /Runner-trusted validation commands selected before agent work:\n(\[[\s\S]*?\n\])/u.exec(
              prompt,
            )[1],
          );
          assert.deepEqual(
            reservations,
            trustedValidation.commands.map(({ alias, command, identity }) => ({
              alias,
              command,
              identity,
            })),
          );
        }
      },
      onTrustedValidation(request) {
        const state = fixture.currentRun.pipelineState;
        trustedSteps.push(state.currentStep);
        trustedBindings.push(request.bindings);
        assert.deepEqual(request.snapshot, trustedValidation);
        assert.equal(request.sourceHead, state.repositoryBaseline.head);
        assert.equal(
          request.bindings.contentFingerprint,
          state.repositoryBaseline.contentFingerprint,
        );
        return {
          status: "PASS",
          commandIdentity: request.commandIdentity,
          exitCode: 0,
          signal: null,
          timedOut: false,
          evidence: ["Injected trusted check passed."],
          ...request.bindings,
        };
      },
      onTransition(run) {
        const state = run.pipelineState;
        if (
          (checkpoint === 0 &&
            state.currentStep === 2 &&
            state.workflowState === "IMPLEMENT") ||
          (checkpoint === 1 &&
            state.currentStep === 2 &&
            state.workflowState === "CONFIRM")
        ) {
          checkpoint += 1;
          throw stop;
        }
      },
    });
    const settings = { mode, trustedChecks: ["service-check"] };
    await assert.rejects(fixture.run(settings), (error) => error === stop);
    const between = JSON.parse(
      JSON.stringify(fixture.currentRun.pipelineState),
    );
    assert.equal(between.completedCommits.length, 1);
    assert.equal(between.finalizationResult, null);
    assert.equal(between.reviewResult, null);
    assert.deepEqual(trustedSteps, []);
    assert.deepEqual(
      between.requiredChecks.map(({ command }) => command),
      [fast, slow, ...(independent ? [reviewerOnly] : [])],
    );
    fixture.persistPipelineState(between);
    await assert.rejects(fixture.run(settings), (error) => error === stop);
    const confirmation = JSON.parse(
      JSON.stringify(fixture.currentRun.pipelineState),
    );
    const evidence = structuredClone(confirmation.finalizationResult);
    assert.equal(evidence.step, 2);
    fixture.persistPipelineState(confirmation);
    const completed = await fixture.run(settings);
    assert.equal(completed.pipelineState.workflowState, "DONE");
    assert.equal(completed.pipelineState.completedCommits.length, 2);
    assert.deepEqual(completed.pipelineState.finalizationResult, evidence);
    assert.deepEqual(trustedSteps, [2]);
    assert.equal(trustedBindings[0].contentFingerprint, evidence.fingerprint);
    assert.deepEqual(agentChecks, [
      [1, [fast]],
      [2, [fast, slow, ...(independent ? [reviewerOnly] : [])]],
    ]);
    assert.ok(preparation.length > 0);
    assert.ok(preparation.every(({ inventory }) => inventory.includes(slow)));
    assert.ok(
      preparation.every(({ requirements }) =>
        requirements.some(
          (requirement) =>
            requirement.command === slow &&
            requirement.capabilities.sourceProjection === true,
        ),
      ),
    );
    if (independent)
      assert.ok(
        preparation.every(({ inventory }) => inventory.includes(reviewerOnly)),
      );
    assert.deepEqual(
      completed.pipelineState.trustedValidation,
      trustedValidation,
    );

    for (const corrupt of [
      (state) => {
        state.validationSchedule.steps[1].commandIndexes.pop();
      },
      (state) => {
        state.requiredChecks = scheduledChecks(state, 1);
      },
      (state) => {
        state.finalizationResult.step = 1;
      },
      (state) => {
        state.finalizationResult.checks[0].evidence = ["Different evidence."];
      },
      (state) => {
        state.workerValidation.requiredChecks[0].steps = [2];
      },
    ]) {
      const invalid = structuredClone(completed.pipelineState);
      corrupt(invalid);
      assert.throws(() => normalizePipelineState(invalid), {
        code: "ERR_INVALID_PLAN_EXECUTION_STATE",
      });
    }
    if (mode === "combined") {
      const consumed = fixture.transitions.find(
        ({ patch }) =>
          patch?.pipelineState?.pendingCommit?.status === "consumed",
      ).patch.pipelineState;
      for (const compact of [completed.pipelineState, consumed]) {
        const legacy = {
          ...compact,
          validationSchedule: compact.validationSchedule.steps.map(
            ({ step }) => ({
              step,
              requiredChecks: scheduledChecks(compact, step),
            }),
          ),
        };
        assert.deepEqual(
          migratePlanExecutionStateV26({ pipelineState: legacy }),
          compact,
        );
        legacy.validationSchedule[1].requiredChecks.pop();
        assert.throws(
          () => migratePlanExecutionStateV26({ pipelineState: legacy }),
          { code: "ERR_INVALID_PLAN_EXECUTION_STATE" },
        );
      }
      const unestablished = {
        ...completed.pipelineState,
        validationSchedule: null,
      };
      assert.deepEqual(
        migratePlanExecutionStateV26({ pipelineState: unestablished }),
        unestablished,
      );
    }
  });
}

test("version-22 discovery survives interruption and preserves consumed-effect verification", async (t) => {
  const stop = Object.assign(new Error("captured legacy checkpoint"), {
    code: "ERR_RUN_REVISION_CHANGED",
  });
  let saved;
  let rediscoveredCorrections;
  const fixture = await createFixture(t, {
    workWorker: [
      implementationCompleted(),
      { ...finalizationPassed(), summary: "" },
      finalizationPassed(),
      bootstrapReady("Migrating Worker"),
      reconciliationResolved(),
      finalizationPassed(),
    ],
    workReviewer: [bootstrapReady("Migrating Reviewer")],
    onRoleRun(_role, request) {
      if (saved && request.schema === FINALIZATION_SCHEMA) {
        rediscoveredCorrections =
          fixture.currentRun.pipelineState.finalizationCorrections;
      }
    },
    onTransition(run) {
      if (!saved && run.pipelineState.pendingCommit?.status === "consumed") {
        saved = JSON.parse(JSON.stringify(run.pipelineState));
      }
      if (run.pipelineState.workflowState === "CONFIRM" && !saved) {
        // Capture before a commit exists; the second run exercises discovery.
        saved = JSON.parse(JSON.stringify(run.pipelineState));
        throw stop;
      }
    },
  });
  await assert.rejects(fixture.run(), (error) => error === stop);
  const migrated = migratePlanExecutionStateV22({ pipelineState: saved });
  assert.equal(migrated.validationScopeLegacy, true);
  assert.equal(migrated.validationSchedule, null);
  assert.equal(migrated.finalizationResult.step, null);
  assert.equal(migrated.finalizationCorrections.length, 1);
  fixture.persistPipelineState(migrated);
  let interrupted = false;
  const transition = fixture.runtime.transition;
  fixture.runtime.transition = async (...args) => {
    const run = await transition(...args);
    if (
      !interrupted &&
      run.pipelineState.validationMigrationPending &&
      run.pipelineState.workerValidation !== null
    ) {
      interrupted = true;
      throw stop;
    }
    return run;
  };
  await assert.rejects(fixture.run(), (error) => error === stop);
  fixture.persistPipelineState(
    JSON.parse(JSON.stringify(fixture.currentRun.pipelineState)),
  );
  const completed = await fixture.run();
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.pipelineState.validationScopeLegacy, false);
  assert.deepEqual(rediscoveredCorrections, migrated.finalizationCorrections);
  for (const role of ["worker", "reviewer"]) {
    const turns = fixture.calls[role].filter(
      (request) =>
        request.schema === REPOSITORY_DISCOVERY_SCHEMA &&
        request.prompt.includes("versioned-state migration"),
    );
    assert.equal(turns.length, 1);
    assert.equal(turns[0].access, "read-only");
  }
  const consumed = fixture.transitions.find(
    ({ patch }) => patch?.pipelineState?.pendingCommit?.status === "consumed",
  ).patch.pipelineState;
  const legacyConsumed = migratePlanExecutionStateV22({
    pipelineState: consumed,
  });
  assert.deepEqual(legacyConsumed.pendingCommit, consumed.pendingCommit);
  assert.equal(legacyConsumed.validationScopeLegacy, true);
  assert.doesNotThrow(() => normalizePipelineState(legacyConsumed));
});

test("confirmed inventory amendments do not change the next persisted step", async (t) => {
  const inventories = [];
  const fixture = await createFixture(t, {
    plan,
    workWorker: [
      implementationCompleted(),
      finalized([fast, reviewerOnly]),
      implementationCompleted(),
      finalized([fast]),
    ],
    workReviewer: [
      reviewApproved(),
      terminalConfirmation(reviewApproved("ACCEPTED")),
    ],
    onRoleRun(_role, request) {
      if (request.schema === FINALIZATION_SCHEMA) {
        inventories.push(
          fixture.currentRun.pipelineState.requiredChecks.map(
            ({ command }) => command,
          ),
        );
      }
    },
  });
  const completed = await fixture.run();
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.deepEqual(inventories, [[fast], [fast]]);
  assert.equal(completed.pipelineState.validationAmendment, null);
  assert.ok(
    completed.pipelineState.validationSchedule.steps.every(
      ({ commandIndexes }) => commandIndexes.length === 1,
    ),
  );
  const accepted = fixture.transitions.find(
    ({ patch }) =>
      patch?.pipelineState?.validationAmendment !== null &&
      patch?.pipelineState?.validationAmendment !== undefined,
  ).patch.pipelineState;
  assert.equal(accepted.validationAmendment.step, 1);
  assert.deepEqual(
    accepted.requiredChecks.map(({ command }) => command),
    [fast, reviewerOnly],
  );
  for (const amendment of [
    { ...accepted.validationAmendment, step: 2 },
    {
      ...accepted.validationAmendment,
      confirmationFingerprint: "0".repeat(64),
    },
  ]) {
    assert.throws(
      () =>
        normalizePipelineState({
          ...accepted,
          validationAmendment: amendment,
        }),
      { code: "ERR_INVALID_PLAN_EXECUTION_STATE" },
    );
  }
});

test("terminal rejection admits a selected future check only in the amended step inventory", async (t) => {
  const future = "npm run test:future";
  const trustedValidation = createTrustedValidationSnapshot(
    {
      "service-check": {
        command: slow,
        executable: "npm",
        arguments: ["run", "test:service"],
        capabilities: { sourceProjection: true },
      },
      "future-check": {
        command: future,
        executable: "npm",
        arguments: ["run", "test:future"],
      },
    },
    ["service-check", "future-check"],
  );
  const bootstrap = (role) => ({
    ...discovery(role, false, trustedValidation),
    requiredChecks: [
      check("C1", fast, [1, 2]),
      check("C2", slow, [2]),
      check("C3", future, [2]),
    ],
  });
  const rejection = {
    ...reviewFindings("R1"),
    findings: [
      {
        ...reviewFindings("R1").findings[0],
        file: "package.json",
        problem:
          "The current metadata change requires the selected service check.",
        reason: "Its original applicability covers only the next step.",
        suggestedAction:
          "Add the selected check to this step's finalization inventory without editing content.",
      },
    ],
    validationChange: "REJECTED",
    finalizationFindingIds: ["R1"],
    validationEvidence: [
      "The current step has incomplete validation evidence.",
    ],
  };
  const attested = finalized([fast, slow]);
  attested.checks[1].status = "PASS";
  const executions = [];
  const finalizations = [];
  const settings = { trustedChecks: ["service-check", "future-check"] };
  const stop = Object.assign(new Error("reload amendment checkpoint"), {
    code: "ERR_RUN_REVISION_CHANGED",
  });
  let checkpoint = 0;
  let candidate;
  const fixture = await createFixture(t, {
    plan,
    trustedValidation,
    worker: [
      clarificationReady(),
      bootstrap("Worker"),
      reconciliationResolved(),
    ],
    reviewer: [bootstrap("Reviewer")],
    workWorker: [
      implementationCompleted(),
      finalized([fast]),
      attested,
      finalized([fast, slow]),
      implementationCompleted(),
      finalized([fast, slow, future], [slow, future]),
    ],
    workReviewer: [
      reviewApproved(),
      terminalConfirmation(rejection),
      terminalConfirmation(reviewApproved("ACCEPTED")),
    ],
    onRoleRun(_role, request) {
      if ([FINALIZATION_SCHEMA, REVIEW_SCHEMA].includes(request.schema)) {
        for (const prompt of [request.prompt, request.recoveryPrompt]) {
          for (const command of [slow, future])
            assert.ok(prompt.includes(JSON.stringify(command)));
        }
      }
      if (request.schema === FINALIZATION_SCHEMA) {
        finalizations.push(request);
        candidate ??= structuredClone(
          fixture.currentRun.pipelineState.candidateReviewResult,
        );
        if ([2, 3].includes(finalizations.length))
          assert.match(request.prompt, /requires the selected service check/u);
        if (finalizations.length === 3) {
          assert.equal(request.access, "read-only");
          assert.deepEqual(executions, []);
        }
      }
    },
    onTrustedValidation(request) {
      const state = fixture.currentRun.pipelineState;
      const selected = trustedValidation.commands.find(
        ({ identity }) => identity === request.commandIdentity,
      );
      assert.ok(selected);
      assert.equal(fixture.currentRun.activeTurn, null);
      assert.deepEqual(request.snapshot, trustedValidation);
      assert.equal(
        request.bindings.contentFingerprint,
        state.repositoryBaseline.contentFingerprint,
      );
      if (selected.capabilities.sourceProjection === true)
        assert.equal(request.sourceHead, state.repositoryBaseline.head);
      executions.push([state.currentStep, selected.command]);
      return {
        status: "PASS",
        commandIdentity: request.commandIdentity,
        exitCode: 0,
        signal: null,
        timedOut: false,
        evidence: ["The controlled runner check passed."],
        ...request.bindings,
      };
    },
    onTransition(run) {
      const state = run.pipelineState;
      if (
        (checkpoint === 0 &&
          state.workflowState === "FINALIZE" &&
          state.finalizationRecovery.required) ||
        (checkpoint === 1 &&
          state.workflowState === "COMMIT" &&
          state.validationAmendment !== null) ||
        (checkpoint === 2 &&
          state.currentStep === 2 &&
          state.workflowState === "IMPLEMENT")
      ) {
        checkpoint += 1;
        throw stop;
      }
    },
  });
  await assert.rejects(fixture.run(settings), (error) => error === stop);
  const rejected = structuredClone(fixture.currentRun.pipelineState);
  assert.equal(rejected.finalizationResult, null);
  assert.deepEqual(rejected.candidateReviewResult, candidate);
  assert.deepEqual(
    rejected.requiredChecks.map(({ command }) => command),
    [fast],
  );
  assert.deepEqual(executions, []);
  const schedule = structuredClone(rejected.validationSchedule);
  fixture.persistPipelineState(JSON.parse(JSON.stringify(rejected)));

  await assert.rejects(fixture.run(), (error) => error === stop);
  const accepted = structuredClone(fixture.currentRun.pipelineState);
  assert.equal(accepted.validationAmendment.step, 1);
  assert.equal(accepted.reviewResult.validationChange, "ACCEPTED");
  assert.deepEqual(
    accepted.finalizationResult.checks.map(
      ({ command, executor, commandIdentity }) => [
        command,
        executor,
        commandIdentity,
      ],
    ),
    [
      [fast, "agent", null],
      [slow, "runner", trustedValidation.commands[0].identity],
    ],
  );
  assert.deepEqual(
    accepted.requiredChecks.map(({ command }) => command),
    [fast, slow],
  );
  assert.deepEqual(accepted.candidateReviewResult, candidate);
  assert.deepEqual(accepted.validationSchedule, schedule);
  assert.deepEqual(accepted.workerValidation, rejected.workerValidation);
  assert.deepEqual(accepted.reviewerValidation, rejected.reviewerValidation);
  assert.deepEqual(
    fixture.currentRun.counters,
    fixture.transitions.find(
      ({ options }) => options.activity?.kind === "evidence-rejected",
    ).patch.counters,
  );
  assert.deepEqual(executions, [[1, slow]]);
  assert.equal(accepted.finalizationCorrections.length, 1);
  assert.equal(accepted.finalizationRecovery.attempts, 1);
  assert.equal(
    accepted.reviewResult.validationTupleFingerprint,
    validationEvidenceFingerprint(accepted.finalizationResult),
  );
  fixture.persistPipelineState(JSON.parse(JSON.stringify(accepted)));

  await assert.rejects(fixture.run(), (error) => error === stop);
  const next = fixture.currentRun.pipelineState;
  assert.equal(next.validationAmendment, null);
  assert.equal(next.finalizationResult, null);
  assert.deepEqual(next.requiredChecks, scheduledChecks(accepted, 2));
  assert.deepEqual(next.validationSchedule, schedule);
  assert.deepEqual(executions, [[1, slow]]);
  fixture.persistPipelineState(JSON.parse(JSON.stringify(next)));
  const completed = await fixture.run();
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.deepEqual(executions, [
    [1, slow],
    [2, slow],
    [2, future],
  ]);
  assert.equal(
    fixture.calls.reviewer.filter(
      ({ schema }) => schema === CANDIDATE_REVIEW_SCHEMA,
    ).length,
    2,
  );
  assert.equal(
    fixture.calls.reviewer.filter(({ schema }) => schema === REVIEW_SCHEMA)
      .length,
    3,
  );

  for (const corrupt of [
    (checks) => {
      checks[1].commandIdentity = trustedValidation.commands[1].identity;
    },
    (checks) => {
      Object.assign(checks[1], {
        executor: "agent",
        commandIdentity: null,
        exitCode: null,
      });
    },
    (checks) => {
      Object.assign(checks[0], {
        executor: "runner",
        commandIdentity: trustedValidation.commands[0].identity,
        exitCode: 0,
      });
    },
  ]) {
    const invalid = structuredClone(accepted);
    corrupt(invalid.finalizationResult.checks);
    const fingerprint = validationEvidenceFingerprint(
      invalid.finalizationResult,
    );
    invalid.reviewResult.validationTupleFingerprint = fingerprint;
    invalid.validationAmendment.confirmationFingerprint = fingerprint;
    assert.throws(
      () => normalizePipelineState(invalid),
      /trusted finalization evidence is inconsistent/u,
    );
  }
});

test("new unselected checks cannot claim NOT_RUN under another command's selection", () => {
  assert.throws(
    () =>
      normalizeFinalizationResult(finalized([fast, slow]), {
        trustedCommands: [reviewerOnly],
      }),
    /check evidence was substituted/u,
  );
});

test("consumed legacy commit verifies before scoped discovery for the following step", async (t) => {
  let migrated = false;
  let unavailable = false;
  const events = [];
  const fixture = await createFixture(t, {
    plan,
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      bootstrapReady("Migrating Worker", [1, 2]),
      reconciliationResolved(),
      implementationCompleted(),
      finalizationPassed(),
    ],
    workReviewer: [bootstrapReady("Migrating Reviewer", [1, 2])],
    onCommitVerify() {
      events.push("verify");
      if (!unavailable) {
        unavailable = true;
        throw new Error("verification interrupted after the commit effect");
      }
    },
    onRoleRun(_role, request) {
      if (migrated && request.schema === REPOSITORY_DISCOVERY_SCHEMA)
        events.push("discover");
    },
  });
  const paused = await fixture.run();
  assert.equal(paused.pipelineState.pendingCommit.status, "consumed");
  fixture.persistPipelineState(
    migratePlanExecutionStateV22({ pipelineState: paused.pipelineState }),
  );
  migrated = true;
  events.length = 0;
  const completed = await fixture.run();
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.deepEqual(events.slice(0, 3), ["verify", "discover", "discover"]);
  assert.equal(
    fixture.calls.worker.filter(({ access }) => access === "local-commit")
      .length,
    2,
  );
  assert.equal(completed.pipelineState.completedCommits.length, 2);
});

for (const paused of [false, true]) {
  test(`version-22 ${paused ? "paused" : "active"} rework retains arbitration and fix accounting`, async (t) => {
    const stop = Object.assign(new Error("interrupted before rework"), {
      code: "ERR_RUN_REVISION_CHANGED",
    });
    let captured = false;
    let migrated = false;
    let rework;
    const fixture = await createFixture(t, {
      arbiter: [stagnation("REWORK_IMPLEMENTATION")],
      workReviewer: [
        reviewFindings("R1"),
        reviewFindings("R2"),
        bootstrapReady("Migrating Reviewer"),
        reviewApproved(),
      ],
      workWorker: [
        implementationCompleted(),
        resolution({ id: "R1", decision: "FIX" }),
        bootstrapReady("Migrating Worker"),
        reconciliationResolved(),
        implementationCompleted(),
        finalizationPassed(),
      ],
      onTransition(run) {
        if (
          !paused &&
          !captured &&
          run.pipelineState.workflowState === "IMPLEMENT" &&
          run.pipelineState.implementationDirection !== null
        ) {
          captured = true;
          throw stop;
        }
      },
      onRoleRun(_role, request) {
        if (
          migrated &&
          rework === undefined &&
          request.access === "workspace-write"
        ) {
          rework = request;
          assert.match(request.prompt, /Required rework direction/u);
          assert.equal(fixture.currentRun.counters.fixRounds, 1);
        }
      },
    });
    const settings = {
      maxFixRoundsPerStep: paused ? 1 : 2,
      maxSameFindingRounds: 10,
      stagnationWindowRounds: 1,
    };
    if (paused) {
      const run = await fixture.run(settings);
      assert.equal(run.pause.reason, "fix_limit_reached");
      assert.equal(run.pause.resumeState, "IMPLEMENT");
    } else {
      await assert.rejects(fixture.run(settings), (error) => error === stop);
    }
    const before = fixture.currentRun.pipelineState;
    fixture.persistPipelineState(migrateUnscopedState(before));
    migrated = true;
    const completed = await fixture.run(
      {},
      paused ? { type: "extra-fix-rounds", amount: 1 } : undefined,
    );
    assert.equal(completed.pipelineState.workflowState, "DONE");
    assert.ok(rework);
    assert.equal(completed.counters.fixRounds, 2);
    assert.equal(fixture.calls.arbiter.length, 1);
    assert.equal(completed.pipelineState.stagnationArbitrationUsed, true);
    assert.deepEqual(
      completed.pipelineState.stagnationDirection,
      before.stagnationDirection,
    );
    assert.equal(completed.pipelineState.additionalFixRounds, paused ? 1 : 0);
  });
}

for (const mode of ["lazy", "combined"]) {
  test(`version-22 ${mode} confirmation correction restarts convergence without replenishing its ledger`, async (t) => {
    const interrupted = mode === "lazy";
    const stop = Object.assign(
      new Error("interrupted confirmation correction"),
      { code: "ERR_RUN_REVISION_CHANGED" },
    );
    const invalid = () => ({ ...cleanConfirmation(), unexpected: true });
    let captured = false;
    let migrated = false;
    let ledger;
    let resumedCheck = false;
    const fixture = await createFixture(t, {
      mode,
      workReviewer:
        mode === "combined" ? [bootstrapReady("Migrating Reviewer")] : [],
      workWorker: [
        implementationCompleted(),
        checkAndFix(),
        invalid(),
        ...(interrupted ? [] : [invalid()]),
        bootstrapReady("Migrating Worker"),
        ...(mode === "combined" ? [reconciliationResolved()] : []),
        checkAndFix(),
        invalid(),
        cleanConfirmation(),
        finalizationPassed(),
      ],
      onTransition(run) {
        if (
          interrupted &&
          !captured &&
          run.pipelineState.pendingLazyCorrection?.phase === "CLEAN_CONFIRM"
        ) {
          captured = true;
          throw stop;
        }
      },
      onRoleRun(_role, request) {
        if (migrated && request.schema === CHECK_AND_FIX_SCHEMA) {
          resumedCheck = true;
          assert.equal(
            fixture.currentRun.pipelineState.pendingLazyCorrection,
            null,
          );
          assert.deepEqual(
            fixture.currentRun.pipelineState.lazyCorrections,
            ledger,
          );
          assert.equal(fixture.currentRun.counters.fixRounds, 1);
        }
      },
    });
    if (interrupted) {
      await assert.rejects(fixture.run(), (error) => error === stop);
    } else {
      assert.equal((await fixture.run()).pause.reason, "lazy_output_invalid");
    }
    ledger = structuredClone(fixture.currentRun.pipelineState.lazyCorrections);
    assert.equal(ledger.length, 1);
    fixture.persistPipelineState(
      migrateUnscopedState(fixture.currentRun.pipelineState),
    );
    migrated = true;
    const paused = await fixture.run();
    assert.ok(resumedCheck);
    assert.equal(paused.pause.reason, "lazy_output_invalid");
    assert.deepEqual(paused.pipelineState.lazyCorrections, ledger);
    assert.equal(paused.counters.fixRounds, 2);
    assert.equal((await fixture.run()).pipelineState.workflowState, "DONE");
  });
}
