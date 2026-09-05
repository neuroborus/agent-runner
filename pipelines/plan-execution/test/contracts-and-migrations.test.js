import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { join, relative } from "node:path";
import test from "node:test";

import {
  createPlanExecutionState,
  migratePlanExecutionStateV3,
  migratePlanExecutionStateV4,
  migratePlanExecutionStateV5,
  migratePlanExecutionStateV6,
  migratePlanExecutionStateV7,
  migratePlanExecutionStateV8,
  migratePlanExecutionStateV9,
  migratePlanExecutionStateV10,
  migratePlanExecutionStateV11,
  migratePlanExecutionStateV12,
  migratePlanExecutionStateV13,
  planExecutionPipeline,
} from "../src/index.js";
import {
  BOOTSTRAP_ARBITRATION_SCHEMA,
  BOOTSTRAP_RECONCILIATION_SCHEMA,
  BOOTSTRAP_SCHEMA,
  CHECK_AND_FIX_SCHEMA,
  CLEAN_CONFIRM_SCHEMA,
  FINALIZATION_SCHEMA,
} from "../src/schemas.js";
import {
  MAX_BOOTSTRAP_ITEMS,
  normalizeBootstrapArbitration,
  normalizeBootstrapResult,
  normalizeCheckAndFixResult,
  normalizeCleanConfirmationResult,
  normalizeFinalizationResult,
  normalizePipelineState,
  normalizeReconciliationResult,
} from "../src/workflow-contract.js";
import {
  REQUIRED_CHECKS,
  SETTINGS,
  VALIDATION_INFRASTRUCTURE,
  arbitrationProductDecision,
  arbitrationResolved,
  assertArraySchemasDeclareItems,
  bootstrapCapacityExhausted,
  bootstrapCorrection,
  bootstrapProductDecision,
  bootstrapReady,
  checkAndFix,
  clarificationReady,
  cleanConfirmation,
  createFixture,
  finalizationBlocked,
  finalizationFailed,
  finalizationPassed,
  hash,
  implementationBlocked,
  implementationCompleted,
  matchesSchemaSubset,
  migrateVersionOneState,
  persistedFinalizationCorrection,
  persistedReviewCorrection,
  prepareValidationMigration,
  reconciliationDisagreement,
  reconciliationProductDecision,
  reconciliationResolved,
  resolution,
  reviewApproved,
  reviewFindings,
  schemaPatterns,
  stagnation,
  versionFourState,
  versionOneState,
  versionThirteenState,
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

test("enforces exact bootstrap field sets without retaining unexpected values", () => {
  const sensitiveField = "DO_NOT_PERSIST_UNEXPECTED_FIELD";
  const sensitiveValue = "DO_NOT_PERSIST_UNEXPECTED_VALUE";
  const cases = [
    {
      normalize: (value) => normalizeBootstrapResult(value, "Worker"),
      value: bootstrapReady("Worker"),
    },
    {
      normalize: normalizeReconciliationResult,
      value: reconciliationResolved(),
    },
    {
      normalize: normalizeBootstrapArbitration,
      value: arbitrationResolved(),
    },
  ];

  for (const { normalize, value } of cases) {
    assert.throws(
      () => normalize({ ...value, [sensitiveField]: sensitiveValue }),
      (cause) => {
        assert.equal(cause.code, "ERR_INVALID_PLAN_EXECUTION_OUTPUT");
        assert.deepEqual(cause.diagnostic, {
          field: "result",
          constraint: "exact-field-set",
        });
        assert.doesNotMatch(String(cause), /DO_NOT_PERSIST/u);
        assert.doesNotMatch(JSON.stringify(cause), /DO_NOT_PERSIST/u);
        return true;
      },
    );
  }

  assert.throws(
    () =>
      normalizeBootstrapResult(
        {
          ...bootstrapReady("Worker"),
          requiredChecks: [
            {
              ...REQUIRED_CHECKS[0],
              [sensitiveField]: sensitiveValue,
            },
          ],
        },
        "Worker",
      ),
    (cause) => {
      assert.deepEqual(cause.diagnostic, {
        field: "requiredChecks[0]",
        constraint: "exact-field-set",
      });
      assert.doesNotMatch(String(cause), /DO_NOT_PERSIST/u);
      assert.doesNotMatch(JSON.stringify(cause), /DO_NOT_PERSIST/u);
      return true;
    },
  );
});

test("rejects reconciliation and arbitration inventory invention", () => {
  const inventedValue = "Review the implementation and then decide the path.";
  for (const [normalize, value] of [
    [
      normalizeReconciliationResult,
      {
        ...reconciliationResolved(),
        validationInfrastructure: [inventedValue],
      },
    ],
    [
      normalizeBootstrapArbitration,
      { ...arbitrationResolved(), requiredChecks: REQUIRED_CHECKS },
    ],
  ]) {
    assert.throws(
      () => normalize(value),
      (cause) => {
        assert.equal(cause.code, "ERR_INVALID_PLAN_EXECUTION_OUTPUT");
        assert.deepEqual(cause.diagnostic, {
          field: "result",
          constraint: "exact-field-set",
        });
        assert.doesNotMatch(
          JSON.stringify(cause),
          /Review the implementation/u,
        );
        return true;
      },
    );
  }
});

test("bootstrap schemas match conditional deterministic normalization", () => {
  const bootstrapPlanRevision = {
    ...bootstrapReady("Worker"),
    status: "PLAN_REVISION_REQUIRED",
    summary: "",
    requiredChecks: [],
    validationInfrastructure: [],
    reason: "The validated plan does not cover the required behavior.",
    evidence: ["The repository requires another planned commit."],
  };
  const reconciliationPlanRevision = {
    ...reconciliationResolved(),
    status: "PLAN_REVISION_REQUIRED",
    summary: "",
    reason: "The summaries expose a conflict with the validated plan.",
    evidence: ["The required behavior changes a planned commit boundary."],
  };
  const arbitrationPlanRevision = {
    ...arbitrationResolved(),
    direction: "PLAN_REVISION_REQUIRED",
    summary: "",
    reason: "The disagreement cannot be resolved within the validated plan.",
    evidence: ["Both reports require a different commit boundary."],
  };
  const arbitrationDirections = ["USE_WORKER", "USE_REVIEWER", "SYNTHESIZE"];
  const contracts = [
    {
      name: "bootstrap",
      schema: BOOTSTRAP_SCHEMA,
      normalize: (value) => normalizeBootstrapResult(value, "Worker"),
      valid: [
        bootstrapReady("Worker"),
        bootstrapCapacityExhausted("validationInfrastructure"),
        bootstrapPlanRevision,
        bootstrapProductDecision(),
      ],
      invalid: [
        { ...bootstrapReady("Worker"), summary: "" },
        { ...bootstrapReady("Worker"), requiredChecks: [] },
        {
          ...bootstrapCapacityExhausted("requiredChecks"),
          capacityLimit: MAX_BOOTSTRAP_ITEMS - 1,
        },
        {
          ...bootstrapCapacityExhausted("validationInfrastructure"),
          validationInfrastructure: VALIDATION_INFRASTRUCTURE,
        },
        { ...bootstrapPlanRevision, summary: "Unexpected summary." },
        { ...bootstrapPlanRevision, requiredChecks: REQUIRED_CHECKS },
        {
          ...bootstrapPlanRevision,
          validationInfrastructure: VALIDATION_INFRASTRUCTURE,
        },
        { ...bootstrapProductDecision(), question: "" },
      ],
    },
    {
      name: "reconciliation",
      schema: BOOTSTRAP_RECONCILIATION_SCHEMA,
      normalize: normalizeReconciliationResult,
      valid: [
        reconciliationResolved(),
        reconciliationDisagreement(),
        reconciliationPlanRevision,
        reconciliationProductDecision(),
      ],
      invalid: [
        { ...reconciliationResolved(), summary: "" },
        {
          ...reconciliationResolved(),
          validationInfrastructure: ["not a repository path from a model"],
        },
        { ...reconciliationDisagreement(), disagreement: "" },
        { ...reconciliationDisagreement(), evidence: [] },
        { ...reconciliationPlanRevision, summary: "Unexpected summary." },
        { ...reconciliationProductDecision(), reason: "Unexpected reason." },
      ],
    },
    {
      name: "arbitration",
      schema: BOOTSTRAP_ARBITRATION_SCHEMA,
      normalize: normalizeBootstrapArbitration,
      valid: [
        ...arbitrationDirections.map((direction) => ({
          ...arbitrationResolved(),
          direction,
        })),
        arbitrationPlanRevision,
        arbitrationProductDecision(),
      ],
      invalid: [
        ...arbitrationDirections.map((direction) => ({
          ...arbitrationResolved(),
          direction,
          rationale: "",
        })),
        { ...arbitrationResolved(), summary: "" },
        { ...arbitrationResolved(), requiredChecks: REQUIRED_CHECKS },
        { ...arbitrationPlanRevision, reason: "" },
        { ...arbitrationProductDecision(), whyBlocked: "" },
      ],
    },
  ];

  for (const contract of contracts) {
    assert.equal(contract.schema.type, "object");
    assert.equal(contract.schema.anyOf, undefined);
    assert.ok(contract.schema.properties.result.anyOf.length > 0);
    assertArraySchemasDeclareItems(contract.schema);
    for (const value of contract.valid) {
      assert.equal(matchesSchemaSubset(contract.schema, value), false);
      assert.equal(
        matchesSchemaSubset(contract.schema, { result: value }),
        true,
        `${contract.name} schema rejected ${value.status ?? value.direction}`,
      );
      assert.doesNotThrow(() => contract.normalize(value));
    }
    for (const value of contract.invalid) {
      assert.equal(
        matchesSchemaSubset(contract.schema, { result: value }),
        false,
        `${contract.name} schema accepted invalid ${value.status ?? value.direction}`,
      );
      assert.throws(() => contract.normalize(value));
    }
  }
});

test("bootstrap schemas use portable patterns with authoritative normalization", () => {
  const contracts = [
    {
      name: "bootstrap",
      schema: BOOTSTRAP_SCHEMA,
      normalize: (value) => normalizeBootstrapResult(value, "Worker"),
      valid: bootstrapReady("Worker"),
      whitespaceText: { ...bootstrapProductDecision(), question: "   " },
    },
    {
      name: "reconciliation",
      schema: BOOTSTRAP_RECONCILIATION_SCHEMA,
      normalize: normalizeReconciliationResult,
      valid: reconciliationResolved(),
      whitespaceText: {
        ...reconciliationDisagreement(),
        disagreement: "   ",
      },
    },
    {
      name: "arbitration",
      schema: BOOTSTRAP_ARBITRATION_SCHEMA,
      normalize: normalizeBootstrapArbitration,
      valid: arbitrationResolved(),
      whitespaceText: { ...arbitrationResolved(), rationale: "   " },
    },
  ];

  for (const schema of [
    ...contracts.map(({ schema }) => schema),
    FINALIZATION_SCHEMA,
  ]) {
    for (const pattern of schemaPatterns(schema)) {
      assert.doesNotMatch(pattern, /\(\?(?:[=!]|<[=!])/u);
    }
  }

  for (const contract of contracts) {
    const invalid = [
      { ...contract.valid, summary: "   " },
      contract.whitespaceText,
    ];
    if (contract.name === "bootstrap") {
      invalid.push(
        {
          ...contract.valid,
          requiredChecks: [{ ...REQUIRED_CHECKS[0], command: " npm test" }],
        },
        {
          ...contract.valid,
          validationInfrastructure: ["../outside.js"],
        },
      );
    }
    for (const value of invalid) {
      assert.equal(
        matchesSchemaSubset(contract.schema, { result: value }),
        true,
        `${contract.name} schema did not preserve its portable approximation`,
      );
      assert.throws(() => contract.normalize(value));
    }
  }
});

test("rejects validation-infrastructure directory paths", () => {
  for (const path of ["config/", "./"]) {
    assert.throws(
      () =>
        normalizeBootstrapResult(
          {
            ...bootstrapReady("Worker"),
            validationInfrastructure: [path],
          },
          "Worker",
        ),
      (cause) => {
        assert.deepEqual(cause.diagnostic, {
          field: "validationInfrastructure[0]",
          constraint: "exact-repository-relative-path-up-to-4000-characters",
        });
        return true;
      },
    );
  }
  assert.doesNotThrow(() =>
    normalizeBootstrapResult(
      {
        ...bootstrapReady("Worker"),
        validationInfrastructure: ["config/checks.json"],
      },
      "Worker",
    ),
  );
});

test("requires unique bootstrap check IDs, exact commands, and paths", () => {
  const duplicateCases = [
    {
      requiredChecks: [
        REQUIRED_CHECKS[0],
        { id: "C1", command: "npm run check" },
      ],
      diagnostic: {
        field: "requiredChecks",
        constraint: "unique-ids-and-commands",
      },
    },
    {
      requiredChecks: [
        REQUIRED_CHECKS[0],
        { id: "C2", command: REQUIRED_CHECKS[0].command },
      ],
      diagnostic: {
        field: "requiredChecks",
        constraint: "unique-ids-and-commands",
      },
    },
    {
      validationInfrastructure: ["source.js", "source.js"],
      diagnostic: {
        field: "validationInfrastructure",
        constraint: "unique-paths",
      },
    },
  ];

  for (const { diagnostic, ...inventory } of duplicateCases) {
    assert.throws(
      () =>
        normalizeBootstrapResult(
          { ...bootstrapReady("Worker"), ...inventory },
          "Worker",
        ),
      (cause) => {
        assert.deepEqual(cause.diagnostic, diagnostic);
        return true;
      },
    );
  }
});

test("rejects staging-dependent validation commands while allowing HEAD checks", () => {
  const unsafeCommands = [
    "git add -A",
    "git -C . add -A",
    "GIT_INDEX_FILE=.alternate-index git add -A",
    "git diff --cached --check",
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

  const commands = ["git diff --cached --check", "git status --short"];
  assert.throws(
    () =>
      normalizeFinalizationResult({
        ...finalizationPassed(),
        requiredChecks: commands.map((command, index) => ({
          id: `C${index + 1}`,
          command,
        })),
        checks: commands.map((command, index) => ({
          checkId: `C${index + 1}`,
          command,
          status: "PASS",
          evidence: ["The staged diff passed."],
        })),
      }),
    (cause) => {
      assert.deepEqual(cause.diagnostic, {
        field: "requiredChecks[0].command",
        constraint: "staging-independent-validation-command",
      });
      assert.deepEqual(cause.diagnostics, [
        {
          field: "requiredChecks[0].command",
          constraint: "staging-independent-validation-command",
        },
        {
          field: "requiredChecks[1].command",
          constraint: "staging-independent-validation-command",
        },
      ]);
      return true;
    },
  );
});

test("classifies oversized and unserializable bootstrap contracts", () => {
  const largePaths = Array.from(
    { length: 32 },
    (_, index) => `${"😀".repeat(3_990)}-${index}`,
  );
  const cases = [
    {
      normalize: (value) => normalizeBootstrapResult(value, "Worker"),
      value: {
        ...bootstrapReady("Worker"),
        validationInfrastructure: largePaths,
      },
    },
  ];

  for (const { normalize, value } of cases) {
    assert.throws(
      () => normalize(value),
      (cause) => {
        assert.deepEqual(cause.diagnostic, {
          field: "result",
          constraint: "maximum-256-kibibytes",
        });
        return true;
      },
    );
  }

  const cyclic = bootstrapReady("Worker");
  cyclic.evidence.push(cyclic);
  assert.throws(
    () => normalizeBootstrapResult(cyclic, "Worker"),
    (cause) => {
      assert.deepEqual(cause.diagnostic, {
        field: "result",
        constraint: "serializable-json",
      });
      return true;
    },
  );

  const sensitiveCause = "DO_NOT_RETAIN_SERIALIZATION_CAUSE";
  assert.throws(
    () =>
      normalizeBootstrapResult(
        {
          ...bootstrapReady("Worker"),
          toJSON() {
            throw new Error(sensitiveCause);
          },
        },
        "Worker",
      ),
    (cause) => {
      assert.deepEqual(cause.diagnostic, {
        field: "result",
        constraint: "serializable-json",
      });
      assert.equal(Object.hasOwn(cause, "cause"), false);
      assert.doesNotMatch(String(cause), /DO_NOT_RETAIN/u);
      return true;
    },
  );
});

test("migrates version-1 execution state to the fail-closed shape", () => {
  const legacy = versionOneState(createPlanExecutionState());
  const migrated = migrateVersionOneState(legacy);
  assert.doesNotThrow(() => normalizePipelineState(migrated));
  assert.equal(migrated.pendingCommit, null);
  assert.equal(migrated.finalizationResult, null);
  assert.equal(migrated.reviewResult, null);
});

test("migrates version-3 execution state with no consumed bootstrap corrections", () => {
  const current = createPlanExecutionState();
  const legacy = { ...current };
  delete legacy.bootstrapCorrections;
  delete legacy.pendingBootstrapCorrection;

  const migrated = migratePlanExecutionStateV3({ pipelineState: legacy });

  assert.deepEqual(migrated.bootstrapCorrections, []);
  assert.equal(migrated.pendingBootstrapCorrection, null);
  assert.doesNotThrow(() => normalizePipelineState(migrated));
  assert.equal(planExecutionPipeline.stateVersion, 14);
});

test("selects Worker-only lazy mode and migrates version 11 to independent", () => {
  assert.deepEqual(planExecutionPipeline.resolveActiveRoles(), [
    "worker",
    "reviewer",
    "arbiter",
  ]);
  assert.deepEqual(
    planExecutionPipeline.resolveActiveRoles({ mode: "independent" }),
    ["worker", "reviewer", "arbiter"],
  );
  assert.deepEqual(planExecutionPipeline.resolveActiveRoles({ mode: "lazy" }), [
    "worker",
  ]);
  assert.equal(planExecutionPipeline.settings.mode.defaultValue, "independent");
  assert.equal(planExecutionPipeline.settings.mode.validate("lazy"), true);
  assert.equal(
    planExecutionPipeline.settings.mode.validate("automatic"),
    false,
  );

  const current = createPlanExecutionState({ settings: SETTINGS });
  const {
    cleanConfirmationFingerprint: _confirmation,
    lazySourceForkConsumed: _sourceFork,
    ...legacy
  } = current;
  const { mode: _mode, ...legacySettings } = legacy.settings;
  const migrated = migratePlanExecutionStateV11({
    pipelineState: { ...legacy, settings: legacySettings },
  });

  assert.equal(migrated.workflowState, current.workflowState);
  assert.equal(migrated.settings.mode, "independent");
  assert.equal(migrated.cleanConfirmationFingerprint, null);
  assert.equal(migrated.lazySourceForkConsumed, false);
  assert.doesNotThrow(() => normalizePipelineState(migrated));
});

test("version 12 migration initializes lazy correction state in place", () => {
  const current = createPlanExecutionState({
    settings: { ...SETTINGS, mode: "lazy" },
  });
  const legacy = { ...current };
  delete legacy.lazyCorrections;
  delete legacy.pendingLazyCorrection;

  const migrated = migratePlanExecutionStateV12({ pipelineState: legacy });

  assert.equal(migrated.workflowState, current.workflowState);
  assert.deepEqual(migrated.lazyCorrections, []);
  assert.equal(migrated.pendingLazyCorrection, null);
  assert.doesNotThrow(() => normalizePipelineState(migrated));
});

test("version 13 migration invalidates active gates and preserves terminal proof", async (t) => {
  const stop = new Error("captured terminal confirmation");
  let confirming;
  const fixture = await createFixture(t, {
    onTransition(run) {
      if (
        confirming === undefined &&
        run.pipelineState.workflowState === "CONFIRM"
      ) {
        confirming = run.pipelineState;
        throw stop;
      }
    },
  });
  await assert.rejects(fixture.run(), (cause) => cause === stop);

  const active = migratePlanExecutionStateV13({
    pipelineState: versionThirteenState({
      ...confirming,
      workflowState: "REVIEW",
    }),
  });
  assert.equal(active.workflowState, "REVIEW");
  assert.equal(active.finalizationResult, null);
  assert.equal(active.reviewResult, null);
  assert.equal(active.candidateReviewedFingerprint, null);
  assert.doesNotThrow(() => normalizePipelineState(active));

  const paused = migratePlanExecutionStateV13({
    pipelineState: versionThirteenState({
      ...confirming,
      workflowState: "WAITING_FOR_USER",
    }),
  });
  assert.equal(paused.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.candidateMigrationPending, true);
  assert.equal(paused.finalizationResult, null);
  assert.doesNotThrow(() => normalizePipelineState(paused));

  const pausedImplementation = migratePlanExecutionStateV13({
    pipelineState: versionThirteenState({
      ...confirming,
      workflowState: "WAITING_FOR_USER",
      reviewerStep: null,
      finalizationResult: null,
      finalizedFingerprint: null,
      reviewResult: null,
      reviewedFingerprint: null,
    }),
    pause: {
      reason: "environment_blocked",
      resumeState: "IMPLEMENT",
    },
  });
  assert.equal(pausedImplementation.workflowState, "WAITING_FOR_USER");
  assert.equal(pausedImplementation.candidateMigrationPending, false);
  assert.doesNotThrow(() => normalizePipelineState(pausedImplementation));

  const legacyReviewCorrection = {
    attempt: 1,
    step: confirming.currentStep,
    contentFingerprint: confirming.finalizedFingerprint,
    validationInfrastructureFingerprint:
      confirming.finalizationResult.validationInfrastructureFingerprint,
    diagnostics: [
      {
        role: "reviewer",
        phase: "review",
        contract: "review",
        field: "result",
        constraint: "semantic-contract",
      },
    ],
  };
  const failed = migratePlanExecutionStateV13({
    pipelineState: versionThirteenState({
      ...confirming,
      workflowState: "FAILED",
      reviewCorrection: legacyReviewCorrection,
      pendingReviewCorrection: null,
    }),
  });
  assert.equal(failed.reviewCorrection, null);
  assert.deepEqual(failed.confirmationCorrection.diagnostics, [
    {
      role: "reviewer",
      phase: "confirmation",
      contract: "confirmation",
      field: "result",
      constraint: "semantic-contract",
    },
  ]);
  assert.doesNotThrow(() => normalizePipelineState(failed));

  const terminalFixture = await createFixture(t);
  const completed = await terminalFixture.run();
  const terminal = migratePlanExecutionStateV13({
    pipelineState: versionThirteenState(completed.pipelineState),
  });
  assert.equal(terminal.workflowState, "DONE");
  assert.deepEqual(
    terminal.completedCommits,
    completed.pipelineState.completedCommits,
  );
  assert.equal(
    terminal.candidateReviewedFingerprint,
    completed.pipelineState.reviewedFingerprint,
  );
  assert.doesNotThrow(() => normalizePipelineState(terminal));

  let consumed;
  const consumedFixture = await createFixture(t, {
    onCommitRun() {
      throw new Error("commit result was interrupted");
    },
    onTransition(run) {
      if (
        consumed === undefined &&
        run.pipelineState.pendingCommit?.status === "consumed"
      ) {
        consumed = run.pipelineState;
      }
    },
  });
  await consumedFixture.run();
  const verificationOnly = migratePlanExecutionStateV13({
    pipelineState: versionThirteenState(consumed),
  });
  assert.equal(verificationOnly.workflowState, "COMMIT");
  assert.equal(verificationOnly.pendingCommit.status, "consumed");
  assert.deepEqual(verificationOnly.pendingCommit, consumed.pendingCommit);
  assert.equal(
    verificationOnly.candidateReviewedFingerprint,
    consumed.reviewedFingerprint,
  );
  assert.doesNotThrow(() => normalizePipelineState(verificationOnly));
});

test("normalizes strict lazy convergence results", () => {
  assert.deepEqual(normalizeCheckAndFixResult(checkAndFix("UNCHANGED")), {
    status: "UNCHANGED",
    summary: "The complete check found no problem.",
  });
  assert.throws(() => normalizeCheckAndFixResult(checkAndFix("REFINALIZE")));
  assert.deepEqual(normalizeCleanConfirmationResult(cleanConfirmation()), {
    status: "CLEAN",
    findings: [],
    validationChange: "UNCHANGED",
    validationEvidence: [],
  });
  assert.equal(CHECK_AND_FIX_SCHEMA.additionalProperties, false);
  assert.equal(CLEAN_CONFIRM_SCHEMA.additionalProperties, false);
  assert.throws(() =>
    normalizeCheckAndFixResult({
      ...checkAndFix("UNCHANGED"),
      unexpected: "rejected",
    }),
  );
});

test("version 11 migration preserves terminal commits and effects", async (t) => {
  const fixture = await createFixture(t);
  const completed = await fixture.run();
  const {
    cleanConfirmationFingerprint: _confirmation,
    lazySourceForkConsumed: _sourceFork,
    ...legacy
  } = completed.pipelineState;
  const { mode: _mode, ...legacySettings } = legacy.settings;

  const migrated = migratePlanExecutionStateV11({
    pipelineState: { ...legacy, settings: legacySettings },
  });

  assert.equal(migrated.workflowState, "DONE");
  assert.deepEqual(
    migrated.completedCommits,
    completed.pipelineState.completedCommits,
  );
  assert.equal(migrated.pendingCommit, null);
  assert.deepEqual(
    migrated.finalizationResult,
    completed.pipelineState.finalizationResult,
  );
  assert.deepEqual(migrated.reviewResult, completed.pipelineState.reviewResult);
  assert.doesNotThrow(() => normalizePipelineState(migrated));

  const versionTwelve = { ...completed.pipelineState };
  delete versionTwelve.lazyCorrections;
  delete versionTwelve.pendingLazyCorrection;
  const current = migratePlanExecutionStateV12({
    pipelineState: versionTwelve,
  });
  assert.equal(current.workflowState, "DONE");
  assert.deepEqual(
    current.completedCommits,
    completed.pipelineState.completedCommits,
  );
  assert.deepEqual(
    current.finalizationResult,
    completed.pipelineState.finalizationResult,
  );
  assert.deepEqual(current.reviewResult, completed.pipelineState.reviewResult);
  assert.doesNotThrow(() => normalizePipelineState(current));
});

test("migrates a consumed version-9 bootstrap diagnostic losslessly", async (t) => {
  const fixture = await createFixture(t, {
    worker: [
      clarificationReady(),
      {
        ...bootstrapReady("Worker"),
        requiredChecks: [{ ...REQUIRED_CHECKS[0], unexpected: "rejected" }],
      },
      bootstrapReady("Corrected Worker"),
      reconciliationResolved(),
    ],
  });
  const completed = await fixture.run();
  const [currentCorrection] = completed.pipelineState.bootstrapCorrections;
  const [diagnostic] = currentCorrection.diagnostics;
  const legacyCorrection = {
    attempt: currentCorrection.attempt,
    ...diagnostic,
  };
  const legacy = {
    ...completed.pipelineState,
    bootstrapCorrections: [legacyCorrection],
  };

  const migrated = migratePlanExecutionStateV9({ pipelineState: legacy });

  assert.deepEqual(migrated, completed.pipelineState);
  assert.doesNotThrow(() => normalizePipelineState(migrated));
});

test("migrates version-10 review state without reconstructing rejected output", async (t) => {
  const fixture = await createFixture(t);
  const completed = await fixture.run();
  const active = fixture.transitions.findLast(
    ({ patch }) => patch?.pipelineState?.workflowState === "COMMIT",
  ).patch.pipelineState;
  const activeLegacy = { ...active };
  delete activeLegacy.reviewCorrection;
  delete activeLegacy.pendingReviewCorrection;
  const activeMigrated = migratePlanExecutionStateV10({
    pipelineState: activeLegacy,
  });
  const legacy = { ...completed.pipelineState };
  delete legacy.reviewCorrection;
  delete legacy.pendingReviewCorrection;

  const migrated = migratePlanExecutionStateV10({ pipelineState: legacy });
  const failedMigrated = migratePlanExecutionStateV10({
    pipelineState: { ...legacy, workflowState: "FAILED" },
  });

  assert.equal(activeMigrated.workflowState, "COMMIT");
  assert.deepEqual(
    activeMigrated.finalizationResult,
    active.finalizationResult,
  );
  assert.deepEqual(activeMigrated.reviewResult, active.reviewResult);
  assert.equal(activeMigrated.reviewCorrection, null);
  assert.equal(activeMigrated.pendingReviewCorrection, null);
  assert.doesNotThrow(() => normalizePipelineState(activeMigrated));
  assert.equal(migrated.workflowState, "DONE");
  assert.equal(migrated.reviewCorrection, null);
  assert.equal(migrated.pendingReviewCorrection, null);
  assert.deepEqual(
    migrated.finalizationResult,
    completed.pipelineState.finalizationResult,
  );
  assert.deepEqual(migrated.reviewResult, completed.pipelineState.reviewResult);
  assert.doesNotThrow(() => normalizePipelineState(migrated));
  assert.equal(failedMigrated.workflowState, "FAILED");
  assert.equal(failedMigrated.reviewCorrection, null);
  assert.equal(failedMigrated.pendingReviewCorrection, null);
  assert.doesNotThrow(() => normalizePipelineState(failedMigrated));
});

test("migrates version-6 execution state with no finalization correction", () => {
  const current = createPlanExecutionState();
  const legacy = { ...current };
  delete legacy.finalizationCorrections;
  delete legacy.pendingFinalizationCorrection;

  const versionSeven = migratePlanExecutionStateV6({ pipelineState: legacy });

  assert.deepEqual(versionSeven, {
    ...legacy,
    finalizationCorrection: null,
    pendingFinalizationCorrection: null,
  });
  const migrated = migratePlanExecutionStateV7({
    pipelineState: versionSeven,
  });
  assert.deepEqual(migrated, {
    ...legacy,
    finalizationCorrections: [],
    pendingFinalizationCorrection: null,
  });
  assert.doesNotThrow(() => normalizePipelineState(migrated));
});

test("migrates consumed and pending version-7 finalization correction state losslessly", () => {
  const legacyCorrection = {
    attempt: 1,
    step: 2,
    guidance: "fallback",
    contentFingerprint: "a".repeat(64),
    role: "worker",
    phase: "finalization",
    contract: "finalization",
    field: "requiredChecks[3].command",
    constraint: "staging-independent-validation-command",
  };
  const migrated = migratePlanExecutionStateV7({
    pipelineState: {
      preserved: "value",
      finalizationCorrection: legacyCorrection,
      pendingFinalizationCorrection: legacyCorrection,
    },
  });

  const upgraded = {
    attempt: 1,
    step: 2,
    guidance: "fallback",
    contentFingerprint: "a".repeat(64),
    diagnostics: [
      {
        role: "worker",
        phase: "finalization",
        contract: "finalization",
        field: "requiredChecks[3].command",
        constraint: "staging-independent-validation-command",
      },
    ],
  };
  assert.deepEqual(migrated, {
    preserved: "value",
    finalizationCorrections: [upgraded],
    pendingFinalizationCorrection: upgraded,
  });
});

test("migrates version-4 state with empty trust and invalidates its active gate", async (t) => {
  const stop = new Error("captured version-4 state");
  let legacy;
  const fixture = await createFixture(t, {
    onTransition(run) {
      if (
        legacy === undefined &&
        run.pipelineState.workflowState === "REVIEW"
      ) {
        legacy = versionFourState(run.pipelineState);
        throw stop;
      }
    },
  });

  await assert.rejects(fixture.run(), (cause) => cause === stop);
  const migrated = migratePlanExecutionStateV4({ pipelineState: legacy });

  assert.equal(migrated.workflowState, "FINALIZE");
  assert.equal(migrated.finalizationResult, null);
  assert.equal(migrated.reviewResult, null);
  assert.equal(migrated.validationMigrationPending, true);
  assert.deepEqual(migrated.settings.trustedChecks, []);
  assert.deepEqual(migrated.trustedValidation.commands, []);
  const current = migratePlanExecutionStateV13({ pipelineState: migrated });
  assert.equal(current.workflowState, "REVIEW");
  assert.doesNotThrow(() => normalizePipelineState(current));
});

test("preserves version-4 consumed commit authority for verification", async (t) => {
  let legacy;
  const interrupted = new Error("commit adapter interrupted");
  const fixture = await createFixture(t, {
    onTransition(run) {
      if (
        legacy === undefined &&
        run.pipelineState.pendingCommit?.status === "consumed"
      ) {
        legacy = versionFourState(run.pipelineState);
      }
    },
    onCommitRun() {
      throw interrupted;
    },
  });

  await fixture.run();
  assert.notEqual(legacy, undefined);
  const migrated = migratePlanExecutionStateV4({ pipelineState: legacy });

  assert.equal(migrated.workflowState, "COMMIT");
  assert.equal(migrated.pendingCommit.status, "consumed");
  assert.equal(migrated.validationMigrationPending, true);
  assert.equal(migrated.finalizationResult.status, "PASS");
  assert.deepEqual(migrated.trustedValidation.commands, []);
  assert.doesNotThrow(() => normalizePipelineState(migrated));
});

test("migrates version-5 states according to their safe checkpoint", async (t) => {
  const initial = createPlanExecutionState();
  assert.deepEqual(
    migratePlanExecutionStateV5({ pipelineState: initial }),
    initial,
  );

  const stop = new Error("captured partial bootstrap");
  let partialBootstrap;
  const bootstrapFixture = await createFixture(t, {
    onTransition(run) {
      if (
        partialBootstrap === undefined &&
        run.pipelineState.workflowState === "BOOTSTRAP" &&
        run.pipelineState.workerSummary !== null
      ) {
        partialBootstrap = run.pipelineState;
        throw stop;
      }
    },
  });
  await assert.rejects(bootstrapFixture.run(), (cause) => cause === stop);
  const resetBootstrap = migratePlanExecutionStateV5({
    pipelineState: partialBootstrap,
  });
  assert.equal(resetBootstrap.workflowState, "BOOTSTRAP");
  assert.equal(resetBootstrap.workerSummary, null);
  assert.equal(resetBootstrap.reviewerSummary, null);
  assert.equal(resetBootstrap.workerValidation, null);
  assert.equal(resetBootstrap.resolvedSummary, null);
  assert.equal(resetBootstrap.requiredChecks, null);
  assert.equal(resetBootstrap.validationMigrationPending, false);
  assert.doesNotThrow(() => normalizePipelineState(resetBootstrap));

  const phaseStates = new Map();
  const completedFixture = await createFixture(t, {
    onTransition(run) {
      const state = run.pipelineState;
      if (
        (state.workflowState !== "CLARIFY" || state.preflightComplete) &&
        ["CLARIFY", "IMPLEMENT", "FINALIZE", "REVIEW", "COMMIT"].includes(
          state.workflowState,
        ) &&
        !phaseStates.has(state.workflowState)
      ) {
        phaseStates.set(state.workflowState, state);
      }
    },
  });
  const completed = await completedFixture.run();
  assert.deepEqual(
    migratePlanExecutionStateV5({
      pipelineState: phaseStates.get("CLARIFY"),
    }),
    phaseStates.get("CLARIFY"),
  );
  for (const [workflowState, expectedState] of [
    ["IMPLEMENT", "IMPLEMENT"],
    ["FINALIZE", "FINALIZE"],
    ["REVIEW", "FINALIZE"],
    ["COMMIT", "FINALIZE"],
  ]) {
    const current = phaseStates.get(workflowState);
    const migrated = migratePlanExecutionStateV5({ pipelineState: current });
    assert.equal(migrated.workflowState, expectedState);
    assert.equal(migrated.validationMigrationPending, true);
    assert.equal(migrated.workerValidation, null);
    assert.equal(migrated.reviewerValidation, null);
    assert.equal(migrated.finalizationResult, null);
    assert.equal(migrated.reviewResult, null);
    assert.deepEqual(migrated.requiredChecks, current.requiredChecks);
    assert.deepEqual(migrated.repositoryBaseline, current.repositoryBaseline);
    const upgraded = migratePlanExecutionStateV13({
      pipelineState: migrated,
    });
    assert.equal(
      upgraded.workflowState,
      expectedState === "IMPLEMENT" ? "IMPLEMENT" : "REVIEW",
    );
    assert.doesNotThrow(() => normalizePipelineState(upgraded));
  }

  let resolving;
  const resolvingFixture = await createFixture(t, {
    workWorker: [
      implementationCompleted(),
      finalizationFailed("F1"),
      resolution({ id: "F1", decision: "FIX" }),
      finalizationPassed(),
    ],
    onTransition(run) {
      if (
        resolving === undefined &&
        run.pipelineState.workflowState === "RESOLVE_FINDINGS"
      ) {
        resolving = run.pipelineState;
      }
    },
  });
  await resolvingFixture.run();
  const migratedResolution = migratePlanExecutionStateV5({
    pipelineState: resolving,
  });
  assert.equal(migratedResolution.workflowState, "FINALIZE");
  assert.equal(migratedResolution.validationMigrationPending, true);
  assert.equal(migratedResolution.finalizationResult, null);
  assert.deepEqual(migratedResolution.findings, []);
  assert.deepEqual(migratedResolution.previousFindings, resolving.findings);
  assert.doesNotThrow(() => normalizePipelineState(migratedResolution));

  for (const workflowState of ["DONE", "FAILED"]) {
    const immutable = {
      ...completed.pipelineState,
      workflowState,
      workerSummary: "Historical summary requires a staged handoff.",
      reviewerSummary: "Historical summary requires a staged handoff.",
      resolvedSummary: "Historical summary requires a staged handoff.",
      workerValidation: {
        requiredChecks: [{ id: "C1", command: "git diff --cached --check" }],
        validationInfrastructure: VALIDATION_INFRASTRUCTURE,
      },
      reviewerValidation: {
        requiredChecks: [{ id: "C1", command: "git diff --cached --check" }],
        validationInfrastructure: VALIDATION_INFRASTRUCTURE,
      },
      requiredChecks: [{ id: "C1", command: "git diff --cached --check" }],
      finalizationResult: {
        ...completed.pipelineState.finalizationResult,
        requiredChecks: [{ id: "C1", command: "git diff --cached --check" }],
        checks: completed.pipelineState.finalizationResult.checks.map(
          (check) => ({ ...check, command: "git diff --cached --check" }),
        ),
      },
    };
    assert.doesNotThrow(() => normalizePipelineState(immutable));
    assert.deepEqual(
      migratePlanExecutionStateV5({ pipelineState: immutable }),
      immutable,
    );
  }
});

test("preserves consumed version-5 commit authorization for verification", async (t) => {
  let consumed;
  const interrupted = new Error("commit adapter interrupted");
  const fixture = await createFixture(t, {
    onTransition(run) {
      if (
        consumed === undefined &&
        run.pipelineState.pendingCommit?.status === "consumed"
      ) {
        consumed = run.pipelineState;
      }
    },
    onCommitRun() {
      throw interrupted;
    },
  });

  await fixture.run();
  const migrated = migratePlanExecutionStateV5({ pipelineState: consumed });

  assert.equal(migrated.workflowState, "COMMIT");
  assert.equal(migrated.pendingCommit.status, "consumed");
  assert.deepEqual(migrated.pendingCommit, consumed.pendingCommit);
  assert.deepEqual(migrated.finalizationResult, consumed.finalizationResult);
  assert.equal(migrated.finalizedFingerprint, consumed.finalizedFingerprint);
  assert.equal(migrated.reviewedFingerprint, consumed.reviewedFingerprint);
  assert.equal(migrated.validationMigrationPending, true);
  assert.doesNotThrow(() => normalizePipelineState(migrated));
});

test("invalidates version-1 validation evidence before active execution resumes", async (t) => {
  const stop = new Error("captured active legacy state");
  let legacy;
  let captured = false;
  const fixture = await createFixture(t, {
    workReviewer: [bootstrapReady("Migrating Reviewer"), reviewApproved()],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      bootstrapReady("Migrating Worker"),
      reconciliationResolved(),
      finalizationPassed(),
    ],
    onTransition(run) {
      if (!captured && run.pipelineState.workflowState === "REVIEW") {
        captured = true;
        legacy = versionOneState(run.pipelineState);
        throw stop;
      }
    },
  });

  await assert.rejects(fixture.run(), (cause) => cause === stop);
  const migrated = migrateVersionOneState(legacy);

  assert.doesNotThrow(() => normalizePipelineState(migrated));
  assert.equal(migrated.workflowState, "REVIEW");
  assert.equal(migrated.finalizationResult, null);
  assert.equal(migrated.finalizedFingerprint, null);
  assert.equal(migrated.reviewResult, null);
  assert.equal(migrated.reviewedFingerprint, null);
  assert.equal(migrated.validationMigrationPending, true);

  fixture.persistPipelineState(migrated, { pause: null });
  const completed = await fixture.run();
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.pipelineState.validationMigrationPending, false);
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

test("pauses on capacity exhaustion during validation migration", async (t) => {
  const capacityField = "validationInfrastructure";
  const fixture = await prepareValidationMigration(t, {
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      bootstrapCapacityExhausted(capacityField),
    ],
  });

  const paused = await fixture.run();
  const projected = planExecutionPipeline.projections.pause(paused);

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

test("batches staging-dependent validation-migration checks", async (t) => {
  const unsafeCommands = ["git diff --cached --check", "git status --short"];
  const fixture = await prepareValidationMigration(t, {
    workReviewer: [bootstrapReady("Migrating Reviewer"), reviewApproved()],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      {
        ...bootstrapReady("Migrating Worker"),
        requiredChecks: unsafeCommands.map((command, index) => ({
          id: `C${index + 1}`,
          command,
        })),
      },
      bootstrapReady("Corrected Migrating Worker"),
      reconciliationResolved(),
      finalizationPassed(),
    ],
  });

  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.deepEqual(completed.pipelineState.bootstrapCorrections, [
    {
      attempt: 1,
      diagnostics: unsafeCommands.map((_, index) => ({
        role: "worker",
        phase: "validation-migration",
        contract: "bootstrap",
        field: `requiredChecks[${index}].command`,
        constraint: "staging-independent-validation-command",
      })),
    },
  ]);
  assert.doesNotMatch(
    completed.pipelineState.resolvedSummary,
    /staged|cached/iu,
  );
});

test("redacts precise diagnostics across validation-migration contracts", async (t) => {
  const sensitiveSummary = "DO_NOT_PERSIST_MIGRATION_SUMMARY".repeat(1_000);
  const cases = [
    {
      name: "bootstrap",
      fixture: {
        workReviewer: [bootstrapReady("Migrating Reviewer"), reviewApproved()],
        workWorker: [
          implementationCompleted(),
          finalizationPassed(),
          { ...bootstrapReady("Migrating Worker"), summary: sensitiveSummary },
          bootstrapReady("Migrating Worker"),
          reconciliationResolved(),
          finalizationPassed(),
        ],
      },
      diagnostic: {
        role: "worker",
        phase: "validation-migration",
        contract: "bootstrap",
        field: "summary",
        constraint: "concise-markdown-up-to-20000-characters",
      },
    },
    {
      name: "reconciliation",
      fixture: {
        workReviewer: [bootstrapReady("Migrating Reviewer"), reviewApproved()],
        workWorker: [
          implementationCompleted(),
          finalizationPassed(),
          bootstrapReady("Migrating Worker"),
          { ...reconciliationResolved(), summary: sensitiveSummary },
          reconciliationResolved(),
          finalizationPassed(),
        ],
      },
      diagnostic: {
        role: "worker",
        phase: "validation-migration",
        contract: "bootstrap-reconciliation",
        field: "summary",
        constraint: "concise-markdown-up-to-20000-characters",
      },
    },
    {
      name: "arbitration",
      fixture: {
        arbiter: [
          { ...arbitrationResolved(), summary: sensitiveSummary },
          arbitrationResolved(),
        ],
        workReviewer: [bootstrapReady("Migrating Reviewer"), reviewApproved()],
        workWorker: [
          implementationCompleted(),
          finalizationPassed(),
          bootstrapReady("Migrating Worker"),
          reconciliationDisagreement(),
          finalizationPassed(),
        ],
      },
      diagnostic: {
        role: "arbiter",
        phase: "validation-migration",
        contract: "bootstrap-arbitration",
        field: "summary",
        constraint: "concise-markdown-up-to-20000-characters",
      },
    },
  ];

  for (const testCase of cases) {
    await t.test(testCase.name, async (t) => {
      const fixture = await prepareValidationMigration(t, testCase.fixture);

      const completed = await fixture.run();

      assert.equal(completed.pipelineState.workflowState, "DONE");
      assert.deepEqual(completed.pipelineState.bootstrapCorrections, [
        bootstrapCorrection(testCase.diagnostic),
      ]);
      assert.doesNotMatch(
        JSON.stringify(fixture.transitions),
        /DO_NOT_PERSIST/u,
      );
    });
  }
});

test("re-establishes validation before retrying a migrated finalization pause", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [bootstrapReady("Migrating Reviewer"), reviewApproved()],
    workWorker: [
      implementationCompleted(),
      finalizationBlocked(
        "The validation IPC endpoint is unavailable.",
        "The test runner could not open its required IPC channel.",
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
  fixture.persistPipelineState(migrated, { pause: paused.pause });

  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.pipelineState.validationMigrationPending, false);
  assert.ok(
    fixture.calls.worker.some(({ prompt }) =>
      prompt.includes("versioned-state migration checkpoint"),
    ),
  );
});

test("resumes a pre-fix paused implementation through phase-safe validation", async (t) => {
  const unsafeCommand = "git add -A && git diff --cached --check";
  let implementationTurns = 0;
  const fixture = await createFixture(t, {
    workReviewer: [bootstrapReady("Migrating Reviewer"), reviewApproved()],
    workWorker: [
      implementationBlocked(),
      bootstrapReady("Migrating Worker"),
      reconciliationResolved(),
      implementationCompleted(),
      finalizationPassed(),
    ],
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("Implement the changes")
      ) {
        implementationTurns += 1;
        if (implementationTurns === 1) {
          await writeFile(
            join(fixture.projectPath, "safe-partial-implementation.txt"),
            "safe partial implementation\n",
          );
        }
      }
    },
  });
  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "environment_blocked");
  assert.equal(paused.pause.resumeState, "IMPLEMENT");

  const unsafeValidation = {
    requiredChecks: [{ id: "C1", command: unsafeCommand }],
    validationInfrastructure: VALIDATION_INFRASTRUCTURE,
  };
  const legacy = {
    ...paused.pipelineState,
    workerSummary: "A staged handoff is mandatory.",
    reviewerSummary: "A staged handoff is mandatory.",
    resolvedSummary: "A staged handoff is mandatory.",
    workerValidation: unsafeValidation,
    reviewerValidation: unsafeValidation,
    requiredChecks: unsafeValidation.requiredChecks,
  };
  assert.doesNotThrow(() => normalizePipelineState(legacy));
  const migrated = migratePlanExecutionStateV5({
    pipelineState: legacy,
    pause: paused.pause,
  });
  assert.equal(migrated.validationMigrationPending, true);
  fixture.persistPipelineState(migrated, { pause: paused.pause });

  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.pipelineState.validationMigrationPending, false);
  assert.equal(
    completed.pipelineState.workerSummary.includes("Migrating"),
    true,
  );
  assert.equal(
    completed.pipelineState.reviewerSummary.includes("Migrating"),
    true,
  );
  assert.equal(
    completed.pipelineState.resolvedSummary.includes("staged"),
    false,
  );
  assert.equal(completed.pipelineState.completedCommits.length, 1);
  assert.equal(
    fixture.calls.worker.filter(({ access }) => access === "local-commit")
      .length,
    1,
  );
  assert.equal(
    await readFile(
      join(fixture.projectPath, "safe-partial-implementation.txt"),
      "utf8",
    ),
    "safe partial implementation\n",
  );
  for (const request of fixture.calls.worker.filter(({ prompt }) =>
    prompt.includes("Implement the changes"),
  )) {
    assert.doesNotMatch(
      request.prompt,
      /Established required-check inventory/u,
    );
    assert.doesNotMatch(request.recoveryPrompt, new RegExp(unsafeCommand, "u"));
  }
});

test("invalidates migrated findings before applying an override", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [
      reviewFindings("R1"),
      reviewFindings("R1"),
      bootstrapReady("Migrating Reviewer"),
      reviewApproved(),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      bootstrapReady("Migrating Worker"),
      reconciliationResolved(),
      finalizationPassed(),
    ],
  });
  const paused = await fixture.run({
    maxFixRoundsPerStep: 1,
    maxSameFindingRounds: 10,
    stagnationWindowRounds: 10,
  });
  const migrated = migrateVersionOneState(
    versionOneState(paused.pipelineState),
  );
  fixture.persistPipelineState(migrated, { pause: paused.pause });

  const completed = await fixture.run(
    {},
    { type: "override-finding", findingId: "R1" },
  );

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.deepEqual(completed.pipelineState.findingOverrides, []);
  assert.equal(completed.pipelineState.validationMigrationPending, false);
});

test("migrates duplicate overrides into fresh validation discovery", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [
      reviewFindings("R1"),
      reviewFindings("R1"),
      bootstrapReady("Migrating Reviewer"),
      reviewApproved(),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      bootstrapReady("Migrating Worker"),
      reconciliationResolved(),
      finalizationPassed(),
    ],
  });
  const paused = await fixture.run({
    maxFixRoundsPerStep: 1,
    maxSameFindingRounds: 10,
    stagnationWindowRounds: 10,
  });
  const override = {
    findingId: "R1",
    fingerprint:
      paused.pipelineState.reviewedFingerprint ??
      paused.pipelineState.candidateReviewedFingerprint,
  };
  const legacy = {
    ...paused.pipelineState,
    findingOverrides: [override, override, override],
  };
  assert.throws(
    () => normalizePipelineState(legacy),
    /overrides must be unique/u,
  );

  const migrated = migratePlanExecutionStateV8({
    pipelineState: legacy,
    pause: paused.pause,
  });
  assert.doesNotThrow(() => normalizePipelineState(migrated));
  assert.deepEqual(migrated.findingOverrides, [override]);
  assert.equal(migrated.validationMigrationPending, true);
  fixture.persistPipelineState(migrated, { pause: paused.pause });
  const projection = planExecutionPipeline.projections.pause(
    fixture.currentRun,
  );
  assert.ok(projection.nextActions.some(({ action }) => action === null));
  assert.equal(
    projection.nextActions.some(
      ({ action }) => action?.type === "override-finding",
    ),
    false,
  );

  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.pipelineState.validationMigrationPending, false);
  assert.deepEqual(completed.pipelineState.findingOverrides, [override]);
  assert.ok(
    fixture.calls.worker.some(({ prompt }) =>
      prompt.includes("versioned-state migration checkpoint"),
    ),
  );
});

test("migrates invalid narrative infrastructure without losing completed work", async (t) => {
  const plan = `## Commit 1: feat(test): add first behavior

Implement the first behavior.

## Commit 2: fix(test): add second behavior

Implement the second behavior.`;
  let implementationTurns = 0;
  const safePath = "safe-current-step-content.txt";
  const fixture = await createFixture(t, {
    plan,
    workReviewer: [
      reviewApproved(),
      reviewFindings("R1"),
      reviewFindings("R1"),
      bootstrapReady("Migrating Reviewer"),
      reviewApproved(),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      bootstrapReady("Migrating Worker"),
      reconciliationResolved(),
      finalizationPassed(),
    ],
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("Implement the changes")
      ) {
        implementationTurns += 1;
        if (implementationTurns === 2) {
          await writeFile(join(request.cwd, safePath), "safe partial work\n");
        }
      }
    },
  });
  const paused = await fixture.run({
    maxFixRoundsPerStep: 1,
    maxSameFindingRounds: 10,
    stagnationWindowRounds: 10,
  });
  assert.equal(paused.pause.reason, "fix_limit_reached");
  assert.equal(paused.pause.resumeState, "RESOLVE_FINDINGS");
  assert.equal(paused.pipelineState.completedCommits.length, 1);
  assert.equal(paused.pipelineState.finalizationResult, null);
  assert.equal(paused.pipelineState.candidateReviewResult.status, "FINDINGS");
  const completedHead = paused.pipelineState.completedCommits[0];
  const narrativePath =
    "TMPDIR, bound HEAD, and worktree fingerprint from a prior turn";
  const invalidInfrastructure = [narrativePath];
  const invalidInfrastructureFingerprint = hash(
    JSON.stringify([[narrativePath, null]]),
  );
  const legacy = {
    ...paused.pipelineState,
    workerValidation: {
      ...paused.pipelineState.workerValidation,
      validationInfrastructure: invalidInfrastructure,
    },
    reviewerValidation: {
      ...paused.pipelineState.reviewerValidation,
      validationInfrastructure: invalidInfrastructure,
    },
    validationInfrastructure: invalidInfrastructure,
    validationInfrastructureFingerprint: invalidInfrastructureFingerprint,
  };
  assert.doesNotThrow(() => normalizePipelineState(legacy));

  const migrated = migratePlanExecutionStateV8({
    pipelineState: legacy,
    pause: paused.pause,
  });
  assert.equal(migrated.validationMigrationPending, true);
  assert.deepEqual(migrated.completedCommits, [completedHead]);
  assert.equal(migrated.finalizationResult, null);
  assert.equal(migrated.candidateReviewResult.status, "FINDINGS");
  fixture.persistPipelineState(migrated, { pause: paused.pause });
  const resumedCallOffsets = Object.fromEntries(
    Object.entries(fixture.calls).map(([role, calls]) => [role, calls.length]),
  );
  const resumedTransitionOffset = fixture.transitions.length;

  const completed = await fixture.run();

  const invalidation = fixture.transitions
    .slice(resumedTransitionOffset)
    .find(({ options }) => options.activity?.kind === "validation-invalidated")
    .patch.pipelineState;
  assert.equal(invalidation.finalizationResult, null);
  assert.equal(invalidation.reviewResult, null);
  assert.equal(invalidation.candidateReviewResult, null);
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.pipelineState.validationMigrationPending, false);
  assert.equal(completed.pipelineState.completedCommits.length, 2);
  assert.equal(completed.pipelineState.completedCommits[0], completedHead);
  assert.deepEqual(
    completed.pipelineState.validationInfrastructure,
    VALIDATION_INFRASTRUCTURE,
  );
  assert.deepEqual(
    completed.pipelineState.finalizationResult.validationInfrastructure,
    VALIDATION_INFRASTRUCTURE,
  );
  assert.deepEqual(
    completed.pipelineState.workerValidation.validationInfrastructure,
    VALIDATION_INFRASTRUCTURE,
  );
  assert.deepEqual(
    completed.pipelineState.reviewerValidation.validationInfrastructure,
    VALIDATION_INFRASTRUCTURE,
  );
  assert.equal(
    await readFile(join(fixture.projectPath, safePath), "utf8"),
    "safe partial work\n",
  );
  assert.equal(implementationTurns, 2);
  for (const [role, calls] of Object.entries(fixture.calls)) {
    for (const request of calls.slice(resumedCallOffsets[role])) {
      assert.equal(request.prompt.includes(narrativePath), false);
      assert.equal(
        (request.recoveryPrompt ?? "").includes(narrativePath),
        false,
      );
    }
  }
  assert.equal(
    JSON.stringify(completed.pipelineState).includes(narrativePath),
    false,
  );
});

test("rejects inconsistent persisted workflow state", async (t) => {
  async function rejectsState(name, mutate) {
    await t.test(name, async (t) => {
      const fixture = await createFixture(t);
      await fixture.run();
      const commitTransition = fixture.transitions.findLast(
        ({ patch }) => patch?.pipelineState?.workflowState === "COMMIT",
      );
      assert.notEqual(commitTransition, undefined);
      Object.assign(fixture.currentRun, commitTransition.patch);
      mutate(fixture.currentRun);

      await assert.rejects(
        fixture.run(),
        (error) => error.code === "ERR_INVALID_PLAN_EXECUTION_STATE",
      );
    });
  }

  await rejectsState("unresolved used arbitration", (run) => {
    Object.assign(run.pipelineState, {
      workflowState: "BOOTSTRAP",
      currentStep: null,
      resolvedSummary: null,
      bootstrapDisagreement: {
        description: "The roles still disagree.",
        evidence: ["The repository evidence supports different boundaries."],
      },
      bootstrapArbitrationUsed: true,
    });
  });

  await rejectsState("arbitration without backend metadata", (run) => {
    run.pipelineState.bootstrapArbitrationUsed = true;
  });

  await rejectsState("pending bootstrap correction without history", (run) => {
    run.pipelineState.pendingBootstrapCorrection = bootstrapCorrection({
      role: "worker",
      phase: "bootstrap",
      contract: "bootstrap",
      field: "result",
      constraint: "semantic-contract",
    });
  });

  await rejectsState("duplicate bootstrap correction diagnostic", (run) => {
    const diagnostic = {
      role: "worker",
      phase: "bootstrap",
      contract: "bootstrap",
      field: "result",
      constraint: "semantic-contract",
    };
    run.pipelineState.bootstrapCorrections = [
      { attempt: 1, diagnostics: [diagnostic, diagnostic] },
    ];
  });

  await rejectsState("bootstrap correction with retained raw output", (run) => {
    run.pipelineState.bootstrapCorrections = [
      {
        attempt: 1,
        diagnostics: [
          {
            role: "worker",
            phase: "bootstrap",
            contract: "bootstrap",
            field: "result",
            constraint: "semantic-contract",
            rejectedValue: "DO_NOT_PERSIST_REJECTED_BOOTSTRAP_OUTPUT",
          },
        ],
      },
    ];
  });

  await rejectsState(
    "pending finalization correction without history",
    (run) => {
      run.pipelineState.pendingFinalizationCorrection = {
        attempt: 1,
        step: 1,
        guidance: "resolved",
        contentFingerprint: "a".repeat(64),
        diagnostics: [
          {
            role: "worker",
            phase: "finalization",
            contract: "finalization",
            field: "result",
            constraint: "semantic-contract",
          },
        ],
      };
    },
  );

  await rejectsState("finalization correction for another step", (run) => {
    run.pipelineState.finalizationCorrections = [
      {
        attempt: 1,
        step: 2,
        guidance: "resolved",
        contentFingerprint: "a".repeat(64),
        diagnostics: [
          {
            role: "worker",
            phase: "finalization",
            contract: "finalization",
            field: "result",
            constraint: "semantic-contract",
          },
        ],
      },
    ];
  });

  await rejectsState(
    "finalization correction with retained raw output",
    (run) => {
      run.pipelineState.finalizationCorrections = [
        {
          attempt: 1,
          step: 1,
          guidance: "resolved",
          contentFingerprint: "a".repeat(64),
          diagnostics: [
            {
              role: "worker",
              phase: "finalization",
              contract: "finalization",
              field: "result",
              constraint: "semantic-contract",
            },
          ],
          rawOutput: "must not be persisted",
        },
      ];
    },
  );

  await rejectsState("repeated finalization correction diagnostic", (run) => {
    run.pipelineState.finalizationCorrections = [
      persistedFinalizationCorrection(1, "requiredChecks[1].command"),
      persistedFinalizationCorrection(2, "requiredChecks[1].command"),
    ];
  });

  await rejectsState("pending finalization correction is not latest", (run) => {
    const first = persistedFinalizationCorrection(
      1,
      "requiredChecks[1].command",
    );
    const second = persistedFinalizationCorrection(
      2,
      "requiredChecks[2].command",
    );
    run.pipelineState.finalizationCorrections = [first, second];
    run.pipelineState.pendingFinalizationCorrection = first;
  });

  await rejectsState("pending review correction without history", (run) => {
    const correction = persistedReviewCorrection("result", {
      contentFingerprint: run.pipelineState.finalizedFingerprint,
      validationInfrastructureFingerprint:
        run.pipelineState.finalizationResult
          .validationInfrastructureFingerprint,
    });
    run.pipelineState.pendingReviewCorrection = correction;
  });

  await rejectsState(
    "review correction with retained rejected output",
    (run) => {
      run.pipelineState.reviewCorrection = {
        ...persistedReviewCorrection("result", {
          contentFingerprint: run.pipelineState.finalizedFingerprint,
          validationInfrastructureFingerprint:
            run.pipelineState.finalizationResult
              .validationInfrastructureFingerprint,
        }),
        rejectedOutput: "DO_NOT_PERSIST_REJECTED_REVIEW_OUTPUT",
      };
    },
  );

  await rejectsState("pending review correction with another scope", (run) => {
    const correction = persistedReviewCorrection("result", {
      contentFingerprint: run.pipelineState.finalizedFingerprint,
      validationInfrastructureFingerprint:
        run.pipelineState.finalizationResult
          .validationInfrastructureFingerprint,
    });
    run.pipelineState.reviewCorrection = correction;
    run.pipelineState.pendingReviewCorrection = {
      ...correction,
      validationInfrastructureFingerprint: "c".repeat(64),
    };
  });

  await rejectsState("lazy correction with an invalid diagnostic", (run) => {
    run.pipelineState.lazyCorrections = [
      {
        attempt: 1,
        fixRoundCharged: false,
        step: 1,
        phase: "CHECK_AND_FIX",
        contentFingerprint: run.pipelineState.finalizedFingerprint,
        validationInfrastructureFingerprint:
          run.pipelineState.finalizationResult
            .validationInfrastructureFingerprint,
        diagnostics: [null],
      },
    ];
  });

  await rejectsState("frozen compatibility re-entry", (run) => {
    Object.assign(run.pipelineState, {
      workflowState: "BOOTSTRAP",
      currentStep: null,
      clarificationFrozen: true,
      workerSummary: null,
      reviewerSummary: null,
      resolvedSummary: null,
      compatibilityCheckRequired: true,
    });
  });

  await rejectsState("edit pause without authorization", (run) => {
    run.pipelineState.workflowState = "WAITING_FOR_USER";
    run.pause = { reason: "product_decision_required" };
  });

  await rejectsState("retry pause with an invalid target", (run) => {
    run.pipelineState.workflowState = "WAITING_FOR_USER";
    run.pause = {
      reason: "environment_blocked",
      resumeState: "REVIEW",
    };
  });

  await rejectsState("retry pause without its target", (run) => {
    run.pipelineState.workflowState = "WAITING_FOR_USER";
    run.pause = { reason: "backend_unavailable" };
  });

  await rejectsState("retry pause with an inconsistent target state", (run) => {
    run.pipelineState.workflowState = "WAITING_FOR_USER";
    run.pause = {
      reason: "backend_unavailable",
      resumeState: "IMPLEMENT",
    };
  });

  await rejectsState("non-retryable pause with a target", (run) => {
    run.pipelineState.workflowState = "WAITING_FOR_USER";
    run.pause = {
      reason: "constructor",
      resumeState: "IMPLEMENT",
    };
  });

  await rejectsState("invalid output diagnostic", (run) => {
    run.pipelineState.workflowState = "FAILED";
    run.pause = {
      reason: "internal_failure",
      code: "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
      diagnostic: {
        role: "worker",
        phase: "bootstrap",
        contract: "bootstrap",
        field: "result",
        constraint: "x".repeat(129),
      },
    };
  });

  await rejectsState("invalid adapter diagnostic", (run) => {
    run.pipelineState.workflowState = "FAILED";
    run.pause = {
      reason: "internal_failure",
      code: "ERR_CODEX_TURN_FAILED",
      diagnosticClass: "native provider value",
    };
  });

  await rejectsState("retained raw terminal turn data", (run) => {
    run.pipelineState.workflowState = "FAILED";
    run.pause = {
      reason: "internal_failure",
      code: "ERR_CODEX_TURN_FAILED",
      diagnosticClass: "turn_bad_request",
      nativeResponse: "must not be persisted",
    };
  });

  for (const [name, diagnostic] of [
    ["legacy output failure", {}],
    [
      "diagnosed output failure",
      {
        diagnostic: {
          role: "worker",
          phase: "bootstrap",
          contract: "bootstrap",
          field: "result",
          constraint: "semantic-contract",
        },
      },
    ],
  ]) {
    await rejectsState(`retained raw output in ${name}`, (run) => {
      run.pipelineState.workflowState = "FAILED";
      run.pause = {
        reason: "internal_failure",
        code: "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
        ...diagnostic,
        rawOutput: "must not be persisted",
      };
    });
  }

  await rejectsState("duplicate child session", (run) => {
    run.sessionLineage.children.push({ ...run.sessionLineage.children[0] });
  });

  await rejectsState("same-finding count without a correction", (run) => {
    run.pipelineState.sameFindingRounds = { R1: 1 };
  });

  await rejectsState("pending correction at the commit gate", (run) => {
    run.pipelineState.pendingCorrection = true;
  });

  await rejectsState("stagnation use without a direction", (run) => {
    run.pipelineState.stagnationArbitrationUsed = true;
  });

  await rejectsState("stagnation direction without recorded use", (run) => {
    run.pipelineState.stagnationDirection = {
      direction: "CONTINUE_FIXES",
      rationale: "Continue the current correction strategy.",
    };
  });

  await rejectsState("implementation rework without arbitration", (run) => {
    Object.assign(run.pipelineState, {
      workflowState: "IMPLEMENT",
      implementationDirection: {
        direction: "REWORK_IMPLEMENTATION",
        rationale: "Rework the current implementation.",
      },
      finalizationResult: null,
      finalizedFingerprint: null,
      reviewedFingerprint: null,
    });
  });

  await t.test("bootstrap context before preflight", async (t) => {
    const fixture = await createFixture(t);
    fixture.currentRun.pipelineState = {
      ...fixture.currentRun.pipelineState,
      workflowState: "FAILED",
      clarificationFrozen: true,
      workerSummary: "Worker summary.",
      reviewerSummary: "Reviewer summary.",
      resolvedSummary: "Resolved summary.",
      currentStep: 1,
    };
    fixture.currentRun.pause = { reason: "internal_failure" };

    await assert.rejects(
      fixture.run(),
      (error) => error.code === "ERR_INVALID_PLAN_EXECUTION_STATE",
    );
  });
});
