import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import {
  createPolishingState,
  migratePolishingStateV2,
  migratePolishingStateV3,
  migratePolishingStateV4,
  migratePolishingStateV5,
  migratePolishingStateV6,
  migratePolishingStateV7,
  migratePolishingStateV8,
  migratePolishingStateV9,
  polishingPipeline,
  runPolishing,
} from "../src/index.js";
import {
  CANDIDATE_CLEAN_CONFIRM_SCHEMA,
  CANDIDATE_REVIEW_SCHEMA,
  CHECK_AND_FIX_SCHEMA,
  CLEAN_CONFIRM_SCHEMA,
  FINALIZATION_SCHEMA,
} from "../src/schemas.js";
import {
  assertRun,
  assertSettings,
  MAX_BOOTSTRAP_ITEMS,
  MAX_DURABLE_RUN_BYTES,
  MAX_DISPUTES_PER_FINDING,
  normalizeBootstrapResult,
  normalizeCandidateReviewResult,
  normalizeCheckAndFixResult,
  normalizeCleanConfirmationResult,
  normalizeFinalizationResult,
  normalizePipelineState,
} from "../src/workflow-contract.js";
import {
  SETTINGS,
  REQUIRED_CHECKS,
  VALIDATION_INFRASTRUCTURE,
  arbitrationResolved,
  bootstrapCapacityExhausted,
  bootstrapReady,
  candidateApproved,
  candidateClean,
  candidateFindings,
  checkAndFix,
  clarificationReady,
  cleanConfirmation,
  createFixture,
  createRealStoreFixture,
  finalizationBlocked,
  finalizationFailed,
  finalizationPassed,
  findingArbitration,
  hash,
  migrateVersionOneState,
  polishingCompleted,
  reconciliationDisagreement,
  reconciliationResolved,
  resolution,
  reviewApproved,
  reviewFindings,
  versionEightState,
  versionNineState,
  versionOneState,
  versionSevenState,
  versionThreeState,
  versionTwoFailedFinalizationState,
  versionTwoState,
} from "./support/index.js";

test("rejects incomplete or substituted finalization PASS evidence", () => {
  const valid = finalizationPassed();
  assert.throws(
    () => normalizeFinalizationResult({ ...valid, checks: [] }),
    /incomplete/u,
  );
  assert.throws(
    () =>
      normalizeFinalizationResult({
        ...valid,
        checks: [{ ...valid.checks[0], command: "npm test -- --exclude slow" }],
      }),
    /substituted/u,
  );
  assert.throws(
    () =>
      normalizeFinalizationResult({
        ...valid,
        checks: [{ ...valid.checks[0], status: "NOT_RUN" }],
      }),
    /substituted|status does not match/u,
  );
  const blocked = finalizationBlocked(
    "The sandbox blocked the required check.",
    "The subprocess was denied before validation could complete.",
  );
  assert.throws(
    () =>
      normalizeFinalizationResult({
        ...blocked,
        checks: [{ ...blocked.checks[0], status: "FAIL" }],
      }),
    /invalid check evidence/u,
  );
  const exactCommand = `node -e 'process.stdout.write("a  b")'`;
  const exactPath = "config/checks  strict.json";
  const exact = normalizeFinalizationResult({
    ...valid,
    requiredChecks: [{ id: "C1", command: exactCommand }],
    validationInfrastructure: [exactPath],
    checks: [
      {
        checkId: "C1",
        command: exactCommand,
        status: "PASS",
        evidence: ["The exact command passed."],
      },
    ],
  });
  assert.equal(exact.requiredChecks[0].command, exactCommand);
  assert.equal(exact.checks[0].command, exactCommand);
  assert.equal(exact.validationInfrastructure[0], exactPath);
});

test("rejects mixed failed and blocked finalization before persistence", async (t) => {
  const requiredChecks = Object.freeze([
    ...REQUIRED_CHECKS,
    Object.freeze({ id: "C2", command: "npm run lint" }),
  ]);
  const failed = finalizationFailed();
  const mixedFinalization = {
    ...failed,
    requiredChecks,
    checks: [
      ...failed.checks,
      {
        checkId: "C2",
        command: "npm run lint",
        status: "BLOCKED",
        evidence: ["The lint check could not start."],
      },
    ],
  };
  const fixture = await createFixture(t, {
    reviewer: [{ ...bootstrapReady("Reviewer"), requiredChecks }],
    worker: [
      clarificationReady(),
      { ...bootstrapReady("Worker"), requiredChecks },
      reconciliationResolved(),
      polishingCompleted(),
      mixedFinalization,
      mixedFinalization,
    ],
  });

  await assert.rejects(fixture.run(), (error) => {
    assert.equal(error.code, "ERR_INVALID_POLISHING_OUTPUT");
    assert.deepEqual(error.diagnostic, {
      role: "worker",
      phase: "finalization",
      contract: "finalization",
      field: "result",
      constraint: "semantic-contract",
    });
    return true;
  });
  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
  assert.equal(fixture.currentRun.pipelineState.finalizationResult, null);
});

test("rejects staging-dependent validation commands while allowing content checks", () => {
  const unsafeCommands = [
    "git add -A",
    "git -C . add -A",
    "GIT_INDEX_FILE=.alternate-index git add -A",
    "git diff --cached --check",
    "git diff --cached --raw | sha256sum",
    "git diff --exit-code",
    "git status --short",
    "git ls-files --error-unmatch source.js",
    "git apply --index change.patch",
    "git show :source.js",
    "git rev-parse --git-path index",
    "sha256sum .git/index",
    "npm run prepare-commit-message",
  ];
  for (const command of unsafeCommands) {
    assert.throws(
      () =>
        normalizeBootstrapResult(
          {
            ...bootstrapReady("Worker"),
            requiredChecks: [{ id: "C1", command }],
          },
          "Worker",
        ),
      (cause) => {
        assert.deepEqual(cause.diagnostic, {
          field: "requiredChecks[0].command",
          constraint: "staging-independent-validation-command",
        });
        return true;
      },
    );
  }

  for (const command of [
    "npm test",
    "git diff --check HEAD",
    "git diff HEAD --exit-code",
    "git diff-tree --check HEAD",
    "git apply --check change.patch",
  ]) {
    assert.doesNotThrow(() =>
      normalizeBootstrapResult(
        {
          ...bootstrapReady("Worker"),
          requiredChecks: [{ id: "C1", command }],
        },
        "Worker",
      ),
    );
  }

  const command = "git diff --cached --check";
  assert.throws(
    () =>
      normalizeFinalizationResult({
        ...finalizationPassed(),
        requiredChecks: [{ id: "C1", command }],
        checks: [
          {
            checkId: "C1",
            command,
            status: "PASS",
            evidence: ["The staged diff passed."],
          },
        ],
      }),
    (cause) => {
      assert.deepEqual(cause.diagnostic, {
        field: "requiredChecks[0].command",
        constraint: "staging-independent-validation-command",
      });
      return true;
    },
  );
});

test("migrates version-1 polishing state to the fail-closed shape", () => {
  const legacy = versionOneState(createPolishingState());
  const migrated = migrateVersionOneState(legacy);
  assert.doesNotThrow(() => normalizePipelineState(migrated));
  assert.equal(migrated.finalizationResult, null);
  assert.equal(migrated.reviewResult, null);
});

test("migrates version-2 state with empty trust and invalidates its active gate", async (t) => {
  const fixture = await createFixture(t);
  const completed = await fixture.run();
  const legacy = versionTwoState({
    ...completed.pipelineState,
    workflowState: "REVIEW",
  });
  const versionThree = migratePolishingStateV2({ pipelineState: legacy });
  const migrated = migratePolishingStateV3({ pipelineState: versionThree });

  assert.equal(migrated.workflowState, "FINALIZE");
  assert.equal(migrated.polishSummary, completed.pipelineState.polishSummary);
  assert.equal(migrated.finalizationResult, null);
  assert.equal(migrated.reviewResult, null);
  assert.equal(migrated.validationMigrationPending, true);
  assert.deepEqual(migrated.settings.trustedChecks, []);
  assert.deepEqual(migrated.trustedValidation.commands, []);
  assert.doesNotThrow(() => normalizePipelineState(migrated));
  assert.equal(polishingPipeline.stateVersion, 10);
});

test("migrates version-3 state with no consumed bootstrap corrections", () => {
  const current = createPolishingState();
  const migrated = migratePolishingStateV3({
    pipelineState: versionThreeState(current),
  });

  assert.deepEqual(migrated.bootstrapCorrections, []);
  assert.equal(migrated.pendingBootstrapCorrection, null);
  assert.equal(migrated.validationMigrationDisagreement, null);
  assert.doesNotThrow(() => normalizePipelineState(migrated));
});

test("migrates version-4 runs through the content-only handoff boundary", async (t) => {
  const fixture = await createFixture(t);
  const completed = await fixture.run();
  const active = {
    ...completed.pipelineState,
    workflowState: "REVIEW",
    reviewResult: null,
    reviewedFingerprint: null,
  };

  const migrated = migratePolishingStateV4({
    pause: null,
    pipelineState: active,
  });
  const terminal = migratePolishingStateV4({
    pause: null,
    pipelineState: completed.pipelineState,
  });

  assert.equal(migrated.workflowState, "FINALIZE");
  assert.equal(migrated.workerValidation, null);
  assert.equal(migrated.reviewerValidation, null);
  assert.equal(migrated.validationMigrationPending, true);
  assert.equal(migrated.finalizationResult, null);
  assert.equal(migrated.finalizedFingerprint, null);
  assert.equal(migrated.reviewResult, null);
  assert.equal(migrated.reviewedFingerprint, null);
  assert.doesNotThrow(() => normalizePipelineState(migrated));
  assert.deepEqual(terminal, completed.pipelineState);
});

test("migrates active version-5 validation through an independent checkpoint", async (t) => {
  const initial = createPolishingState();
  assert.deepEqual(
    migratePolishingStateV5({ pipelineState: initial }),
    initial,
  );

  const fixture = await createFixture(t);
  const completed = await fixture.run();
  const unsafeCommand = "git diff --cached --check";
  const unsafeValidation = {
    requiredChecks: [{ id: "C1", command: unsafeCommand }],
    validationInfrastructure: VALIDATION_INFRASTRUCTURE,
  };
  const unsafeFinalization = {
    ...completed.pipelineState.finalizationResult,
    requiredChecks: unsafeValidation.requiredChecks,
    checks: completed.pipelineState.finalizationResult.checks.map((check) => ({
      ...check,
      command: unsafeCommand,
    })),
  };
  const active = versionNineState({
    ...completed.pipelineState,
    workflowState: "REVIEW",
    workerValidation: unsafeValidation,
    reviewerValidation: unsafeValidation,
    requiredChecks: unsafeValidation.requiredChecks,
    finalizationResult: unsafeFinalization,
    reviewResult: null,
    reviewedFingerprint: null,
  });

  const versionSix = migratePolishingStateV5({
    pause: null,
    pipelineState: active,
  });
  const migrated = migratePolishingStateV9({
    pause: null,
    pipelineState: versionSix,
  });

  assert.equal(migrated.workflowState, "REVIEW");
  assert.equal(migrated.workerValidation, null);
  assert.equal(migrated.reviewerValidation, null);
  assert.equal(migrated.validationMigrationPending, true);
  assert.equal(migrated.finalizationResult, null);
  assert.equal(migrated.reviewResult, null);
  assert.deepEqual(migrated.requiredChecks, active.requiredChecks);
  assert.deepEqual(migrated.repositoryBaseline, active.repositoryBaseline);
  assert.doesNotThrow(() => normalizePipelineState(migrated));

  const terminal = {
    ...completed.pipelineState,
    workerValidation: unsafeValidation,
    reviewerValidation: unsafeValidation,
    requiredChecks: unsafeValidation.requiredChecks,
    finalizationResult: unsafeFinalization,
  };
  assert.doesNotThrow(() => normalizePipelineState(terminal));
  assert.deepEqual(
    migratePolishingStateV5({ pipelineState: terminal }),
    terminal,
  );
});

test("migrates version-6 state without changing workflow evidence", async (t) => {
  const fixture = await createFixture(t);
  const completed = await fixture.run();
  const legacy = { ...completed.pipelineState };
  delete legacy.finalizationCorrection;
  delete legacy.pendingFinalizationCorrection;

  const migrated = migratePolishingStateV6({ pipelineState: legacy });

  assert.deepEqual(migrated, {
    ...legacy,
    finalizationCorrection: null,
    pendingFinalizationCorrection: null,
  });
  assert.doesNotThrow(() => normalizePipelineState(migrated));
});

test("selects Worker-only lazy mode and migrates version 7 to independent", () => {
  assert.deepEqual(
    polishingPipeline.resolveActiveRoles({ mode: "independent" }),
    ["worker", "reviewer", "arbiter"],
  );
  assert.deepEqual(polishingPipeline.resolveActiveRoles({ mode: "lazy" }), [
    "worker",
  ]);
  assert.equal(polishingPipeline.settings.mode.defaultValue, "independent");
  assert.equal(polishingPipeline.settings.mode.validate("lazy"), true);
  assert.equal(polishingPipeline.settings.mode.validate("automatic"), false);

  const legacy = versionSevenState(
    createPolishingState({ settings: SETTINGS }),
  );
  const migrated = migratePolishingStateV7({
    pipelineState: legacy,
  });

  assert.equal(migrated.settings.mode, "independent");
  assert.equal(migrated.cleanConfirmationFingerprint, null);
  assert.equal(migrated.lazySourceForkConsumed, false);
  assert.doesNotThrow(() => normalizePipelineState(migrated));
});

test("migrates version-9 active and terminal states through candidate convergence", async (t) => {
  const fixture = await createFixture(t);
  const completed = await fixture.run();
  const cases = [
    {
      name: "active",
      state: {
        ...completed.pipelineState,
        workflowState: "REVIEW",
        reviewResult: null,
        reviewedFingerprint: null,
      },
    },
    {
      name: "HANDOFF",
      state: { ...completed.pipelineState, workflowState: "HANDOFF" },
    },
    { name: "DONE", state: completed.pipelineState },
    {
      name: "FAILED",
      state: { ...completed.pipelineState, workflowState: "FAILED" },
    },
  ];

  for (const migrationCase of cases) {
    await t.test(migrationCase.name, () => {
      const legacy = versionEightState(versionNineState(migrationCase.state));
      const versionNine = migratePolishingStateV8({ pipelineState: legacy });
      const migrated = migratePolishingStateV9({
        pipelineState: versionNine,
      });

      assert.deepEqual(versionNine, {
        ...legacy,
        lazyCorrections: [],
        pendingLazyCorrection: null,
      });
      assert.equal(
        migrated.workflowState,
        migrationCase.name === "active" ? "REVIEW" : legacy.workflowState,
      );
      assert.deepEqual(migrated.repositoryBaseline, legacy.repositoryBaseline);
      assert.deepEqual(
        migrated.finalizationResult,
        migrationCase.name === "active" ? null : legacy.finalizationResult,
      );
      assert.equal(
        migrated.candidateReviewResult?.status ?? null,
        migrationCase.name === "active" ? null : "APPROVED",
      );
      assert.doesNotThrow(() => normalizePipelineState(migrated));
    });
  }
});

test("defers a paused version-9 gate migration until safe resume", async (t) => {
  const fixture = await createFixture(t);
  const completed = await fixture.run();
  const pause = { reason: "no_progress", resumeState: "RESOLVE_FINDINGS" };
  const legacy = versionNineState({
    ...completed.pipelineState,
    workflowState: "WAITING_FOR_USER",
  });

  const migrated = migratePolishingStateV9({
    pause,
    pipelineState: legacy,
  });

  assert.equal(migrated.workflowState, "WAITING_FOR_USER");
  assert.equal(migrated.candidateMigrationPending, true);
  assert.equal(migrated.candidateReviewResult, null);
  assert.equal(migrated.finalizationResult, null);
  assert.equal(migrated.reviewResult, null);
  assert.doesNotThrow(() => normalizePipelineState(migrated));
  assert.doesNotThrow(() =>
    polishingPipeline.validateResumeAction(
      { pause, pipelineState: migrated },
      null,
    ),
  );
  assert.deepEqual(
    polishingPipeline.projections.pause({ pause, pipelineState: migrated })
      .nextActions,
    [{ type: "resume", action: null }],
  );
});

test("resumes a paused version-9 gate migration through candidate convergence", async (t) => {
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
      checkAndFix(),
      candidateClean(),
      finalizationPassed(),
      cleanConfirmation(),
    ],
  });

  const paused = await fixture.run();
  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "no_progress");

  const migrated = migratePolishingStateV9({
    pause: paused.pause,
    pipelineState: versionNineState(paused.pipelineState),
  });
  await fixture.persistPipelineState(migrated, paused.counters, paused.pause);

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.candidateMigrationPending, false);
  assert.equal(
    fixture.calls.worker.filter(({ schema }) => schema === FINALIZATION_SCHEMA)
      .length,
    1,
  );
  assert.equal(
    fixture.calls.worker.filter(({ schema }) => schema === CLEAN_CONFIRM_SCHEMA)
      .length,
    1,
  );
});

test("normalizes strict lazy polishing convergence results", () => {
  assert.deepEqual(normalizeCheckAndFixResult(checkAndFix()), {
    status: "UNCHANGED",
    summary: "The complete change set is clean.",
  });
  assert.deepEqual(normalizeCleanConfirmationResult(cleanConfirmation()), {
    status: "CLEAN",
    findings: [],
    validationChange: "UNCHANGED",
    validationEvidence: [],
  });
  assert.deepEqual(
    normalizeCandidateReviewResult(candidateClean(), [], {
      clean: true,
    }),
    {
      status: "CLEAN",
      findings: [],
    },
  );
  assert.equal(CHECK_AND_FIX_SCHEMA.additionalProperties, false);
  assert.equal(CANDIDATE_CLEAN_CONFIRM_SCHEMA.additionalProperties, false);
  assert.equal(CANDIDATE_REVIEW_SCHEMA.additionalProperties, false);
  assert.equal(CLEAN_CONFIRM_SCHEMA.additionalProperties, false);
});

test("clears partial bootstrap evidence across polishing migrations", async (t) => {
  let unavailable = false;
  const fixture = await createFixture(t, {
    onRoleRun(role, request) {
      if (
        role === "reviewer" &&
        /concise bootstrap summary/u.test(request.prompt) &&
        !unavailable
      ) {
        unavailable = true;
        const error = new Error("Reviewer unavailable.");
        error.recoverable = true;
        throw error;
      }
    },
  });
  const paused = await fixture.run();
  assert.notEqual(paused.pipelineState.workerSummary, null);

  const migrated = migratePolishingStateV4(paused);
  const stagingIndependent = migratePolishingStateV5(paused);

  assert.equal(migrated.workerSummary, null);
  assert.equal(migrated.reviewerSummary, null);
  assert.equal(migrated.workerValidation, null);
  assert.equal(migrated.requiredChecks, null);
  assert.equal(migrated.validationMigrationPending, false);
  assert.deepEqual(migrated.bootstrapCorrections, []);
  assert.doesNotThrow(() => normalizePipelineState(migrated));
  assert.equal(stagingIndependent.workerSummary, null);
  assert.equal(stagingIndependent.reviewerSummary, null);
  assert.equal(stagingIndependent.workerValidation, null);
  assert.equal(stagingIndependent.requiredChecks, null);
  assert.equal(stagingIndependent.validationMigrationPending, false);
  assert.doesNotThrow(() => normalizePipelineState(stagingIndependent));
});

test("rejects pending bootstrap correction without matching history", () => {
  const current = createPolishingState();
  assert.throws(
    () =>
      normalizePipelineState({
        ...current,
        pendingBootstrapCorrection: {
          attempt: 1,
          role: "worker",
          phase: "bootstrap",
          contract: "bootstrap",
          field: "result",
          constraint: "semantic-contract",
        },
      }),
    /pending bootstrap correction is inconsistent/u,
  );
});

test("rejects unoverridden terminal findings as completion evidence", async (t) => {
  const fixture = await createFixture(t);
  const completed = await fixture.run();
  const fingerprint = completed.pipelineState.reviewedFingerprint;

  assert.throws(
    () =>
      normalizePipelineState({
        ...completed.pipelineState,
        reviewResult: {
          ...completed.pipelineState.reviewResult,
          status: "FINDINGS",
        },
        previousFindings: reviewFindings("R1").findings,
        findingOverrides: [],
        reviewedFingerprint: fingerprint,
      }),
    /Completed polishing state is inconsistent/u,
  );
});

test("migrates incomplete paused and terminal version-2 checks fail closed", async (t) => {
  const fixture = await createFixture(t);
  const completed = await fixture.run();
  const cases = [
    {
      name: "paused BLOCKED check",
      workflowState: "WAITING_FOR_USER",
      incompleteStatus: "BLOCKED",
      migrationPending: true,
    },
    {
      name: "immutable terminal NOT_RUN check",
      workflowState: "FAILED",
      incompleteStatus: "NOT_RUN",
      migrationPending: false,
    },
  ];

  for (const migrationCase of cases) {
    await t.test(migrationCase.name, () => {
      const legacy = versionTwoFailedFinalizationState(
        completed.pipelineState,
        migrationCase,
      );
      const versionThree = migratePolishingStateV2({ pipelineState: legacy });
      const migrated = migratePolishingStateV3({
        pipelineState: versionThree,
      });

      assert.deepEqual(
        migrated.finalizationResult.checks.map(({ status }) => status),
        ["FAIL", "FAIL"],
      );
      assert.deepEqual(migrated.finalizationResult.checks[1].evidence, [
        "The legacy check did not complete.",
      ]);
      assert.equal(
        migrated.validationMigrationPending,
        migrationCase.migrationPending,
      );
      assert.doesNotThrow(() => normalizePipelineState(migrated));
    });
  }
});

test("invalidates version-1 validation evidence before completed polishing resumes", async (t) => {
  const fixture = await createFixture(t, {
    reviewer: [
      bootstrapReady("Reviewer"),
      candidateApproved(),
      reviewApproved(),
      bootstrapReady("Migrating Reviewer"),
      candidateApproved(),
      reviewApproved(),
    ],
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
      {
        ...bootstrapReady("Invalid Migrating Worker"),
        requiredChecks: [
          { id: "C1", command: "npm test" },
          { id: "C2", command: "npm test" },
        ],
      },
      bootstrapReady("Migrating Worker"),
      reconciliationResolved(),
      finalizationPassed(),
    ],
  });
  const completed = await fixture.run();
  const migrated = migrateVersionOneState(
    versionOneState(completed.pipelineState),
  );

  assert.doesNotThrow(() => normalizePipelineState(migrated));
  assert.equal(migrated.workflowState, "REVIEW");
  assert.equal(migrated.finalizationResult, null);
  assert.equal(migrated.finalizedFingerprint, null);
  assert.equal(migrated.reviewResult, null);
  assert.equal(migrated.reviewedFingerprint, null);
  assert.equal(migrated.validationMigrationPending, true);

  await fixture.persistPipelineState(migrated);
  const revalidated = await fixture.run();
  assert.equal(revalidated.pipelineState.workflowState, "DONE");
  assert.equal(revalidated.pipelineState.validationMigrationPending, false);
  assert.deepEqual(revalidated.pipelineState.bootstrapCorrections, [
    {
      attempt: 1,
      role: "worker",
      phase: "validation-migration",
      contract: "bootstrap",
      field: "requiredChecks",
      constraint: "unique-ids-and-commands",
    },
  ]);
  assert.ok(
    fixture.calls.worker.some(({ prompt }) =>
      prompt.includes("versioned-state migration checkpoint"),
    ),
  );
  assert.ok(
    fixture.calls.reviewer.some(({ prompt }) =>
      prompt.includes("versioned-state migration checkpoint"),
    ),
  );
});

test("corrects staging-dependent validation-migration checks", async (t) => {
  const unsafeCommand = "git diff --cached --raw | sha256sum";
  const fixture = await createFixture(t, {
    reviewer: [
      bootstrapReady("Reviewer"),
      reviewApproved(),
      bootstrapReady("Migrating Reviewer"),
      reviewApproved(),
    ],
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
      {
        ...bootstrapReady("Invalid Migrating Worker"),
        requiredChecks: [{ id: "C1", command: unsafeCommand }],
      },
      bootstrapReady("Corrected Migrating Worker"),
      reconciliationResolved(),
      finalizationPassed(),
    ],
  });
  const completed = await fixture.run();
  const active = {
    ...completed.pipelineState,
    workflowState: "FINALIZE",
    finalizationResult: null,
    finalizedFingerprint: null,
    reviewResult: null,
    reviewedFingerprint: null,
  };
  const migrated = migratePolishingStateV5({
    pause: null,
    pipelineState: active,
  });
  await fixture.persistPipelineState(migrated);

  const revalidated = await fixture.run();

  assert.equal(revalidated.pipelineState.workflowState, "DONE");
  assert.deepEqual(revalidated.pipelineState.bootstrapCorrections, [
    {
      attempt: 1,
      role: "worker",
      phase: "validation-migration",
      contract: "bootstrap",
      field: "requiredChecks[0].command",
      constraint: "staging-independent-validation-command",
    },
  ]);
  assert.doesNotMatch(JSON.stringify(revalidated), /git diff --cached/u);
});

test("pauses on capacity exhaustion during validation migration", async (t) => {
  const capacityField = "validationInfrastructure";
  const fixture = await createFixture(t, {
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
      bootstrapCapacityExhausted(capacityField),
    ],
  });
  const completed = await fixture.run();
  const migrated = migrateVersionOneState(
    versionOneState(completed.pipelineState),
  );
  await fixture.persistPipelineState(migrated);

  const paused = await fixture.run();
  const projected = polishingPipeline.projections.pause(paused);

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pipelineState.validationMigrationPending, true);
  assert.equal(paused.pipelineState.workerValidation, null);
  assert.deepEqual(paused.pipelineState.bootstrapCorrections, []);
  assert.equal(paused.pipelineState.pendingBootstrapCorrection, null);
  assert.equal(
    fixture.calls.worker.filter(({ prompt }) =>
      prompt.includes("versioned-state migration checkpoint"),
    ).length,
    1,
  );
  assert.deepEqual(projected, {
    reason: "bootstrap_inventory_capacity_exhausted",
    code: "ERR_BOOTSTRAP_INVENTORY_CAPACITY_EXHAUSTED",
    explanation: `The worker bootstrap reported that the complete ${capacityField} inventory exceeds the supported per-role limit of ${MAX_BOOTSTRAP_ITEMS} items. Increase the bounded Runner contract or reduce the validation-controlling surface, then start a new run.`,
    evidence: [
      "Bootstrap role: worker.",
      `Inventory field: ${capacityField}.`,
      `Per-role item limit: ${MAX_BOOTSTRAP_ITEMS}.`,
    ],
    resumeState: null,
    nextActions: [],
  });
});

test("persists repeated invalid validation-migration output as terminal", async (t) => {
  const unsafeCommand = "git diff --cached --check";
  const rejected = {
    ...bootstrapReady("Invalid Migrating Worker"),
    requiredChecks: [{ id: "C1", command: unsafeCommand }],
  };
  const fixture = await createFixture(t, {
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
      rejected,
      rejected,
    ],
  });
  const completed = await fixture.run();
  const migrated = migrateVersionOneState(
    versionOneState(completed.pipelineState),
  );
  assert.throws(
    () => normalizePipelineState({ ...migrated, workflowState: "DONE" }),
    /validation migration is inapplicable/u,
  );
  await fixture.persistPipelineState(migrated);

  await assert.rejects(
    fixture.run(),
    (cause) => cause.code === "ERR_INVALID_POLISHING_OUTPUT",
  );
  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
  assert.equal(
    fixture.currentRun.pipelineState.validationMigrationPending,
    true,
  );
  assert.deepEqual(fixture.currentRun.pause.diagnostic, {
    role: "worker",
    phase: "validation-migration",
    contract: "bootstrap",
    field: "requiredChecks[0].command",
    constraint: "staging-independent-validation-command",
  });
  assert.equal(fixture.currentRun.pipelineState.bootstrapCorrections.length, 1);
  assert.deepEqual(
    fixture.currentRun.pipelineState.pendingBootstrapCorrection,
    fixture.currentRun.pipelineState.bootstrapCorrections[0],
  );
  assert.doesNotMatch(
    JSON.stringify(fixture.currentRun),
    new RegExp(unsafeCommand, "u"),
  );

  const workerCalls = fixture.calls.worker.length;
  await fixture.recover();
  const terminal = await fixture.run();
  assert.equal(terminal.pipelineState.workflowState, "FAILED");
  assert.equal(fixture.calls.worker.length, workerCalls);
});

test("resumes an interrupted validation-migration Arbiter correction directly", async (t) => {
  let interrupted = false;
  const fixture = await createFixture(t, {
    onRoleRun(role, request) {
      if (
        role === "arbiter" &&
        request.prompt.includes("Make one read-only correction") &&
        !interrupted
      ) {
        interrupted = true;
        const error = new Error("Transient provider interruption.");
        error.code = "ERR_TEST_PROVIDER_INTERRUPTED";
        error.recoverable = true;
        throw error;
      }
    },
    reviewer: [
      bootstrapReady("Reviewer"),
      reviewApproved(),
      bootstrapReady("Migrating Reviewer"),
    ],
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
      bootstrapReady("Migrating Worker"),
      reconciliationDisagreement(),
      reconciliationResolved(),
    ],
    arbiter: [{}, arbitrationResolved()],
  });
  const completed = await fixture.run();
  const migrated = {
    ...migrateVersionOneState(versionOneState(completed.pipelineState)),
    settings: {
      ...completed.pipelineState.settings,
      finalization: ".agents/skills/missing/SKILL.md",
    },
  };
  await fixture.persistPipelineState(migrated);

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.deepEqual(paused.pipelineState.validationMigrationDisagreement, {
    description: "The roles selected different owning modules.",
    evidence: ["The summaries identify different existing boundaries."],
  });
  assert.deepEqual(
    paused.pipelineState.pendingBootstrapCorrection,
    paused.pipelineState.bootstrapCorrections[0],
  );

  await fixture.recover();
  const resumed = await fixture.run();
  assert.equal(resumed.pause.reason, "finalization_skill_missing");
  assert.equal(resumed.pipelineState.validationMigrationPending, false);
  assert.equal(resumed.pipelineState.validationMigrationDisagreement, null);
  assert.equal(resumed.pipelineState.pendingBootstrapCorrection, null);
  assert.equal(fixture.calls.arbiter.length, 3);
  assert.equal(
    fixture.calls.worker.filter(({ prompt }) =>
      prompt.includes(
        "Reconcile only the independently rediscovered validation requirements.",
      ),
    ).length,
    1,
  );
});

test("re-establishes validation before retrying a migrated finalization pause", async (t) => {
  const fixture = await createFixture(t, {
    reviewer: [
      bootstrapReady("Reviewer"),
      candidateApproved(),
      bootstrapReady("Migrating Reviewer"),
      candidateApproved(),
      reviewApproved(),
    ],
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationBlocked(
        "The validation service is unavailable.",
        "The service endpoint refused the local connection.",
      ),
      bootstrapReady("Migrating Worker"),
      reconciliationResolved(),
      finalizationPassed(),
    ],
  });
  const paused = await fixture.run();
  const migrated = migrateVersionOneState(
    versionOneState(paused.pipelineState),
  );
  await fixture.persistPipelineState(migrated);

  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.pipelineState.validationMigrationPending, false);
  assert.ok(
    fixture.calls.worker.some(({ prompt }) =>
      prompt.includes("versioned-state migration checkpoint"),
    ),
  );
});

test("invalidates migrated findings before applying an override", async (t) => {
  const fixture = await createFixture(t, {
    settings: { ...SETTINGS, maxSameFindingRounds: 1 },
    reviewer: [
      bootstrapReady("Reviewer"),
      reviewFindings(),
      reviewFindings(),
      bootstrapReady("Migrating Reviewer"),
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
      bootstrapReady("Migrating Worker"),
      reconciliationResolved(),
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
  const migrated = migrateVersionOneState(
    versionOneState(paused.pipelineState),
  );
  await fixture.persistPipelineState(migrated);

  const completed = await fixture.run({
    type: "override-finding",
    findingId: "R1",
  });

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.deepEqual(completed.pipelineState.findingOverrides, []);
  assert.equal(completed.pipelineState.validationMigrationPending, false);
});

test("rejects dispute settings that cannot fit bounded durable history", () => {
  const maximumSettings = {
    ...SETTINGS,
    maxDisputesPerFinding: MAX_DISPUTES_PER_FINDING,
  };
  assert.doesNotThrow(() => assertSettings(maximumSettings));
  assert.equal(
    polishingPipeline.settings.maxDisputesPerFinding.validate(
      MAX_DISPUTES_PER_FINDING,
    ),
    true,
  );

  const unrepresentable = MAX_DISPUTES_PER_FINDING + 1;
  assert.throws(
    () =>
      assertSettings({
        ...SETTINGS,
        maxDisputesPerFinding: unrepresentable,
      }),
    /must not exceed/u,
  );
  assert.equal(
    polishingPipeline.settings.maxDisputesPerFinding.validate(unrepresentable),
    false,
  );
});

test("rejects and refuses to recover inconsistent correction progress", async (t) => {
  const oversizedSessionId = "a".repeat(1_024);
  const fixture = await createRealStoreFixture(t, {
    arbiter: [findingArbitration("WORKER_CORRECT")],
    sessionIdForRole: (role) =>
      role === "arbiter" ? oversizedSessionId : undefined,
  });
  const initial = fixture.currentRun;

  for (const pipelineState of [
    { ...initial.pipelineState, pendingCorrection: true },
    { ...initial.pipelineState, additionalFixRounds: 1 },
    {
      ...initial.pipelineState,
      stagnationArbitrationUsed: true,
    },
  ]) {
    assert.throws(
      () => assertRun({ ...initial, pipelineState }),
      /Polishing (pending correction|preflight|stagnation arbitration)/u,
    );
  }

  const completed = await fixture.run();
  assert.throws(
    () =>
      assertRun({
        ...completed,
        counters: {
          ...completed.counters,
          fixRounds: 1,
          correctionRounds: 1,
        },
      }),
    /persisted progress is invalid/u,
  );
  assert.throws(
    () =>
      assertRun({
        ...completed,
        pipelineState: {
          ...completed.pipelineState,
          correctionHistory: [
            {
              round: 1,
              fingerprint: completed.pipelineState.reviewedFingerprint,
              finalizationIssueIds: [],
              findingIds: [],
            },
          ],
        },
      }),
    /correction history entry is invalid/u,
  );

  const inconsistentState = {
    ...completed.pipelineState,
    workflowState: "RESOLVE_FINDINGS",
    reviewedFingerprint: hash("different reviewed content"),
  };
  assert.throws(
    () => assertRun({ ...completed, pipelineState: inconsistentState }),
    /finalization progress is inconsistent/u,
  );

  const differentFingerprint = hash("different completed content");
  const mismatchedCompletion = {
    ...completed.pipelineState,
    finalizationResult: {
      ...completed.pipelineState.finalizationResult,
      fingerprint: differentFingerprint,
    },
    finalizedFingerprint: differentFingerprint,
    reviewResult: {
      ...completed.pipelineState.reviewResult,
      fingerprint: differentFingerprint,
    },
    reviewedFingerprint: differentFingerprint,
  };
  assert.throws(
    () => assertRun({ ...completed, pipelineState: mismatchedCompletion }),
    /content fingerprints are inconsistent/u,
  );

  const pausedState = {
    ...completed.pipelineState,
    workflowState: "WAITING_FOR_USER",
  };
  const pause = {
    reason: "fix_limit_reached",
    fixRounds: completed.counters.fixRounds,
    resumeState: "RESOLVE_FINDINGS",
  };
  assert.throws(
    () => assertRun({ ...completed, pause, pipelineState: pausedState }),
    /persisted progress is invalid|finding resolution has no blockers/u,
  );

  const finding = reviewFindings().findings[0];
  const pendingDispute = {
    findingId: finding.id,
    reason: "Repository evidence still disputes the finding.",
    evidence: ["The complete evidence must survive recovery."],
  };
  const baseState = {
    ...completed.pipelineState,
    workflowState: "RESOLVE_FINDINGS",
    reviewResult: {
      ...completed.pipelineState.reviewResult,
      status: "FINDINGS",
    },
    findings: [finding],
    pendingDisputes: [pendingDispute],
    disputeCounts: { [finding.id]: 2 },
    disputeHistory: [],
  };

  assert.throws(
    () => assertRun({ ...completed, pipelineState: baseState }),
    /dispute progress is invalid/u,
  );

  const firstAttempt = {
    findingId: finding.id,
    attempt: 1,
    direction: "UPHOLD",
    workerReason: pendingDispute.reason,
    workerEvidence: pendingDispute.evidence,
    reviewerReason: "The finding remains valid.",
    reviewerEvidence: [],
  };
  const secondAttempt = {
    ...firstAttempt,
    attempt: 2,
  };
  const exhaustedDisputeState = {
    ...baseState,
    pendingDisputes: [],
    disputeHistory: [firstAttempt, secondAttempt],
  };
  const contradictoryDisputeState = {
    ...exhaustedDisputeState,
    pendingDisputes: [
      {
        ...pendingDispute,
        reason: "Contradictory Worker evidence.",
      },
    ],
  };

  for (const pipelineState of [
    exhaustedDisputeState,
    contradictoryDisputeState,
  ]) {
    assert.throws(
      () => assertRun({ ...completed, pipelineState }),
      /dispute progress is invalid/u,
    );
    await fixture.persistPipelineState(pipelineState);
    await fixture.recover();
    await assert.rejects(fixture.run(), /dispute progress is invalid/u);
  }

  assert.throws(
    () =>
      assertRun({
        ...completed,
        pipelineState: {
          ...baseState,
          pendingDisputes: [],
          disputeCounts: { [finding.id]: 1 },
          disputeHistory: [firstAttempt],
          findingArbitrations: [
            {
              findingId: finding.id,
              direction: "REVIEWER_CORRECT",
              rationale: "The finding is supported by repository evidence.",
            },
          ],
        },
      }),
    /arbitration history is incomplete/u,
  );

  const detail = "x".repeat(3_900);
  const findings = Array.from({ length: 32 }, (_, index) => ({
    id: `R${index + 1}`,
    file: `src/${"f".repeat(3_900)}-${index + 1}.js`,
    problem: detail,
    reason: detail,
    suggestedAction: detail,
  }));
  const disputeCounts = Object.fromEntries(findings.map(({ id }) => [id, 2]));
  const disputeHistory = findings.flatMap(({ id }) =>
    [1, 2].map((attempt) => ({
      findingId: id,
      attempt,
      direction: "UPHOLD",
      workerReason: "The Worker disputed the finding.",
      workerEvidence: ["Worker evidence."],
      reviewerReason: "The Reviewer upheld the finding.",
      reviewerEvidence: [],
    })),
  );
  const pipelineState = {
    ...completed.pipelineState,
    workflowState: "RESOLVE_FINDINGS",
    reviewResult: {
      ...completed.pipelineState.reviewResult,
      status: "FINDINGS",
    },
    findings,
    previousFindings: findings,
    disputeCounts,
    disputeHistory,
    findingArbitrations: findings.map(({ id }) => ({
      findingId: id,
      direction: "REVIEWER_CORRECT",
      rationale: detail,
    })),
  };
  const oversizedRun = { ...completed, pipelineState };

  assert.ok(Buffer.byteLength(JSON.stringify(oversizedRun)) > 1024 * 1024);
  assert.throws(() => assertRun(oversizedRun), /durable size budget/u);

  const nearCapacityDetail = "n".repeat(3_500);
  const nearCapacityEvidence = "e".repeat(3_900);
  const nearCapacityFindings = Array.from({ length: 32 }, (_, index) => ({
    id: `R${index + 1}`,
    file: `src/${"f".repeat(3_500)}-${index + 1}.js`,
    problem: nearCapacityDetail,
    reason: nearCapacityDetail,
    suggestedAction: nearCapacityDetail,
  }));
  const nearCapacityDispute = {
    findingId: "R1",
    reason: nearCapacityEvidence,
    evidence: [nearCapacityEvidence, nearCapacityEvidence],
  };
  const nearCapacityHistory = [1, 2].map((attempt) => ({
    findingId: "R1",
    attempt,
    direction: "UPHOLD",
    workerReason: nearCapacityDispute.reason,
    workerEvidence: nearCapacityDispute.evidence,
    reviewerReason: nearCapacityEvidence,
    reviewerEvidence: [nearCapacityEvidence, nearCapacityEvidence],
  }));
  const nearCapacityBase = {
    ...completed.pipelineState,
    workflowState: "RESOLVE_FINDINGS",
    reviewResult: {
      ...completed.pipelineState.reviewResult,
      status: "FINDINGS",
    },
    backendVersions: {
      ...completed.pipelineState.backendVersions,
      arbiter: "fake-1.0.0",
    },
    findings: nearCapacityFindings,
    previousFindings: nearCapacityFindings,
    pendingDisputes: [nearCapacityDispute],
    disputeCounts: { R1: 2 },
    disputeHistory: nearCapacityHistory,
    findingArbitrations: [],
    workerSummary: "",
  };
  const targetBytes = MAX_DURABLE_RUN_BYTES - 256;
  const baseBytes = Buffer.byteLength(
    JSON.stringify({ ...fixture.currentRun, pipelineState: nearCapacityBase }),
  );
  const paddingLength = targetBytes - baseBytes;
  assert.ok(paddingLength > 0 && paddingLength <= 20_000);
  const nearCapacityState = {
    ...nearCapacityBase,
    workerSummary: "w".repeat(paddingLength),
  };
  const nearCapacityRun = {
    ...fixture.currentRun,
    pipelineState: nearCapacityState,
  };
  assert.doesNotThrow(() => assertRun(nearCapacityRun));
  assert.throws(
    () =>
      assertRun({
        ...nearCapacityRun,
        revision: nearCapacityRun.revision + 1,
        sessionLineage: {
          ...nearCapacityRun.sessionLineage,
          children: [
            ...nearCapacityRun.sessionLineage.children,
            { role: "arbiter", sessionId: oversizedSessionId },
          ],
        },
      }),
    /durable size budget/u,
  );

  await fixture.persistPipelineState(nearCapacityState);
  const childrenBeforeArbitration = fixture.currentRun.sessionLineage.children;
  await assert.rejects(fixture.run(), /durable size budget/u);
  assert.deepEqual(
    fixture.currentRun.sessionLineage.children,
    childrenBeforeArbitration,
  );
});

test("preflights digit-boundary transition growth before persistence", async (t) => {
  const fixture = await createFixture(t, {
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
      { ...polishingCompleted(), summary: "." },
    ],
  });
  const completed = await fixture.run();
  const pipelineState = {
    ...completed.pipelineState,
    workflowState: "POLISH",
    resolvedSummary: ".",
    polishSummary: null,
    finalizationResult: null,
    finalizedFingerprint: null,
    reviewResult: null,
    reviewedFingerprint: null,
  };
  const targetPipelineState = {
    ...pipelineState,
    workflowState: "FINALIZE",
    polishSummary: ".",
  };
  const paddingChildren = [];
  const buildTargetRun = (resolvedSummary) => ({
    ...completed,
    revision: 9,
    sessionLineage: {
      ...completed.sessionLineage,
      children: [...completed.sessionLineage.children, ...paddingChildren],
    },
    pipelineState: {
      ...targetPipelineState,
      resolvedSummary,
    },
  });

  let targetRun = buildTargetRun(".");
  while (
    MAX_DURABLE_RUN_BYTES - Buffer.byteLength(JSON.stringify(targetRun)) >
    19_000
  ) {
    const prefix = `padding-${paddingChildren.length}-`;
    paddingChildren.push({
      role: "reviewer",
      sessionId: `${prefix}${"s".repeat(1_024 - prefix.length)}`,
    });
    targetRun = buildTargetRun(".");
  }
  const remainingBytes =
    MAX_DURABLE_RUN_BYTES - Buffer.byteLength(JSON.stringify(targetRun));
  const resolvedSummary = "r".repeat(remainingBytes + 1);
  targetRun = buildTargetRun(resolvedSummary);

  assert.equal(
    Buffer.byteLength(JSON.stringify(targetRun)),
    MAX_DURABLE_RUN_BYTES,
  );
  assert.doesNotThrow(() => assertRun(targetRun));
  assert.throws(
    () => assertRun({ ...targetRun, revision: 10 }),
    /durable size budget/u,
  );

  const nearCapacityRun = {
    ...targetRun,
    pipelineState: {
      ...pipelineState,
      resolvedSummary,
    },
  };
  assert.doesNotThrow(() => assertRun(nearCapacityRun));
  const attemptedTransitions = [];
  await assert.rejects(
    runPolishing({
      run: nearCapacityRun,
      runtime: {
        ...fixture.runtime,
        async startAgentTurn(activeTurn) {
          return {
            ...nearCapacityRun,
            activeTurn,
            revision: nearCapacityRun.revision + 1,
          };
        },
        async transition(patch) {
          attemptedTransitions.push(patch);
          return {
            ...nearCapacityRun,
            ...patch,
            revision: nearCapacityRun.revision + 1,
          };
        },
      },
      settings: SETTINGS,
    }),
    /durable size budget/u,
  );
  assert.deepEqual(attemptedTransitions, []);
  assert.equal(fixture.currentRun, completed);
});

test("normalizes legacy polishing state to the default artifact root", () => {
  const legacySettings = { ...SETTINGS };
  delete legacySettings.finalization;
  const state = {
    ...createPolishingState({ settings: SETTINGS }),
    settings: legacySettings,
  };
  delete state.artifactRoot;

  const normalized = normalizePipelineState(state);
  assert.equal(normalized.artifactRoot, "LOCAL_ARTIFACTS");
  assert.equal(normalized.settings.finalization, "auto");
});
