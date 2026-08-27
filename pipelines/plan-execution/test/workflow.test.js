import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readlink,
  realpath,
  readdir,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, sep } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

import {
  createPlanExecutionState,
  migratePlanExecutionStateV1,
  migratePlanExecutionStateV2,
  migratePlanExecutionStateV3,
  migratePlanExecutionStateV4,
  migratePlanExecutionStateV5,
  migratePlanExecutionStateV6,
  planExecutionPipeline,
  runPlanExecution,
} from "../src/index.js";
import {
  BOOTSTRAP_ARBITRATION_SCHEMA,
  BOOTSTRAP_RECONCILIATION_SCHEMA,
  BOOTSTRAP_SCHEMA,
  FINALIZATION_SCHEMA,
} from "../src/schemas.js";
import {
  assertRun,
  MAX_BOOTSTRAP_ITEMS,
  MAX_VALIDATION_ITEMS,
  normalizeBootstrapArbitration,
  normalizeBootstrapResult,
  normalizeFinalizationResult,
  normalizePipelineState,
  normalizeReconciliationResult,
} from "../src/workflow-contract.js";

const executeFile = promisify(execFile);
const SOURCE_SESSION = "11111111-1111-4111-8111-111111111111";
const ROLE_SESSIONS = Object.freeze({
  worker: "22222222-2222-4222-8222-222222222222",
  reviewer: "33333333-3333-4333-8333-333333333333",
  arbiter: "44444444-4444-4444-8444-444444444444",
});
const RESTARTED_ROLE_SESSIONS = Object.freeze({
  worker: "55555555-5555-4555-8555-555555555555",
  reviewer: "66666666-6666-4666-8666-666666666666",
});
const REBOOTSTRAPPED_WORKER_SESSION =
  "88888888-8888-4888-8888-888888888888";
const MISSING_BOOTSTRAP_RESPONSE = Symbol("missing-bootstrap-response");
const PLAN = `## Commit 1: feat(test): add behavior

Implement the requested behavior.`;
const SETTINGS = Object.freeze({
  finalization: "auto",
  maxFixRoundsPerStep: 5,
  maxDisputesPerFinding: 2,
  maxSameFindingRounds: 3,
  stagnationWindowRounds: 3,
  trustedChecks: Object.freeze([]),
});
const REQUIRED_CHECKS = Object.freeze([
  Object.freeze({ id: "C1", command: "npm test" }),
]);
const VALIDATION_INFRASTRUCTURE = Object.freeze([
  "package.json",
]);
const WRAPPED_BOOTSTRAP_SCHEMAS = new Set([
  BOOTSTRAP_SCHEMA,
  BOOTSTRAP_RECONCILIATION_SCHEMA,
  BOOTSTRAP_ARBITRATION_SCHEMA,
]);

function checkResults(status, evidence = "The fixture check completed.") {
  return REQUIRED_CHECKS.map(({ id, command }) => ({
    checkId: id,
    command,
    status,
    evidence: [evidence],
  }));
}

function versionOneState(state) {
  const legacy = { ...state };
  for (const field of [
    "workerValidation",
    "reviewerValidation",
    "requiredChecks",
    "validationInfrastructure",
    "validationInfrastructureFingerprint",
    "validationMigrationPending",
    "reviewResult",
    "bootstrapCorrections",
    "pendingBootstrapCorrection",
    "finalizationCorrection",
    "pendingFinalizationCorrection",
    "trustedValidation",
  ]) {
    delete legacy[field];
  }
  if (legacy.settings !== null) {
    const { trustedChecks: _trustedChecks, ...settings } = legacy.settings;
    legacy.settings = settings;
  }
  if (legacy.pendingCommit !== null) {
    legacy.pendingCommit = {
      status: legacy.pendingCommit.status,
      authorization: legacy.pendingCommit.authorization,
    };
  }
  return legacy;
}

function versionFourState(state) {
  const legacy = { ...state };
  delete legacy.trustedValidation;
  if (legacy.settings !== null) {
    const { trustedChecks: _trustedChecks, ...settings } = legacy.settings;
    legacy.settings = settings;
  }
  if (legacy.finalizationResult !== null) {
    const {
      trustedCommandFingerprint: _trustedCommandFingerprint,
      trustedConfigurationFingerprint: _trustedConfigurationFingerprint,
      ...finalizationResult
    } = legacy.finalizationResult;
    legacy.finalizationResult = {
      ...finalizationResult,
      checks: finalizationResult.checks.map(
        ({
          executor: _executor,
          commandIdentity: _commandIdentity,
          exitCode: _exitCode,
          signal: _signal,
          timedOut: _timedOut,
          ...check
        }) => check,
      ),
    };
  }
  return legacy;
}

function migrateVersionOneState(state) {
  const versionTwo = migratePlanExecutionStateV1({ pipelineState: state });
  const versionThree = migratePlanExecutionStateV2({
    pipelineState: versionTwo,
  });
  const versionFour = migratePlanExecutionStateV3({
    pipelineState: versionThree,
  });
  const versionFive = migratePlanExecutionStateV4({
    pipelineState: versionFour,
  });
  const versionSix = migratePlanExecutionStateV5({
    pipelineState: versionFive,
  });
  return migratePlanExecutionStateV6({ pipelineState: versionSix });
}

async function prepareValidationMigration(t, fixtureOptions) {
  const stop = new Error("captured active legacy state");
  let legacy;
  const fixture = await createFixture(t, {
    ...fixtureOptions,
    onTransition(run) {
      if (legacy === undefined && run.pipelineState.workflowState === "REVIEW") {
        legacy = versionOneState(run.pipelineState);
        throw stop;
      }
    },
  });

  await assert.rejects(fixture.run(), (cause) => cause === stop);
  assert.notEqual(legacy, undefined);
  fixture.persistPipelineState(migrateVersionOneState(legacy), { pause: null });
  return fixture;
}

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
    assert.throws(() => normalize(value), (cause) => {
      assert.equal(cause.code, "ERR_INVALID_PLAN_EXECUTION_OUTPUT");
      assert.deepEqual(cause.diagnostic, {
        field: "result",
        constraint: "exact-field-set",
      });
      assert.doesNotMatch(JSON.stringify(cause), /Review the implementation/u);
      return true;
    });
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
          constraint:
            "exact-repository-relative-path-up-to-4000-characters",
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
  assert.equal(planExecutionPipeline.stateVersion, 7);
});

test("migrates version-6 execution state with no finalization correction", () => {
  const current = createPlanExecutionState();
  const legacy = { ...current };
  delete legacy.finalizationCorrection;
  delete legacy.pendingFinalizationCorrection;

  const migrated = migratePlanExecutionStateV6({ pipelineState: legacy });

  assert.deepEqual(migrated, {
    ...legacy,
    finalizationCorrection: null,
    pendingFinalizationCorrection: null,
  });
  assert.doesNotThrow(() => normalizePipelineState(migrated));
});

test("migrates version-4 state with empty trust and invalidates its active gate", async (t) => {
  const stop = new Error("captured version-4 state");
  let legacy;
  const fixture = await createFixture(t, {
    onTransition(run) {
      if (legacy === undefined && run.pipelineState.workflowState === "REVIEW") {
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
  assert.doesNotThrow(() => normalizePipelineState(migrated));
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
    assert.doesNotThrow(() => normalizePipelineState(migrated));
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
        requiredChecks: [
          { id: "C1", command: "git diff --cached --check" },
        ],
        validationInfrastructure: VALIDATION_INFRASTRUCTURE,
      },
      reviewerValidation: {
        requiredChecks: [
          { id: "C1", command: "git diff --cached --check" },
        ],
        validationInfrastructure: VALIDATION_INFRASTRUCTURE,
      },
      requiredChecks: [
        { id: "C1", command: "git diff --cached --check" },
      ],
      finalizationResult: {
        ...completed.pipelineState.finalizationResult,
        requiredChecks: [
          { id: "C1", command: "git diff --cached --check" },
        ],
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
  assert.equal(migrated.workflowState, "FINALIZE");
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

test("corrects staging-dependent validation-migration checks", async (t) => {
  const unsafeCommand = "git diff --cached --check";
  const fixture = await prepareValidationMigration(t, {
    workReviewer: [bootstrapReady("Migrating Reviewer"), reviewApproved()],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      {
        ...bootstrapReady("Migrating Worker"),
        requiredChecks: [{ id: "C1", command: unsafeCommand }],
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
      role: "worker",
      phase: "validation-migration",
      contract: "bootstrap",
      field: "requiredChecks[0].command",
      constraint: "staging-independent-validation-command",
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
        workReviewer: [
          bootstrapReady("Migrating Reviewer"),
          reviewApproved(),
        ],
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
        workReviewer: [
          bootstrapReady("Migrating Reviewer"),
          reviewApproved(),
        ],
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
        workReviewer: [
          bootstrapReady("Migrating Reviewer"),
          reviewApproved(),
        ],
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
        { attempt: 1, ...testCase.diagnostic },
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
      if (role === "worker" && request.prompt.includes("Implement the changes")) {
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
  assert.equal(completed.pipelineState.workerSummary.includes("Migrating"), true);
  assert.equal(completed.pipelineState.reviewerSummary.includes("Migrating"), true);
  assert.equal(completed.pipelineState.resolvedSummary.includes("staged"), false);
  assert.equal(completed.pipelineState.completedCommits.length, 1);
  assert.equal(
    fixture.calls.worker.filter(({ access }) => access === "local-commit").length,
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
    assert.doesNotMatch(request.prompt, /Established required-check inventory/u);
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

function hash(value) {
  return createHash("sha256").update(value).digest("hex");
}

function trustedValidationSnapshot(
  alias = "service-check",
  command = "npm run test:service",
) {
  const vector = {
    alias,
    command,
    executable: "npm",
    arguments: ["run", "test:service"],
  };
  const identity = hash(JSON.stringify(vector));
  const commands = [{ ...vector, identity }];
  return Object.freeze({
    schemaVersion: 1,
    commands: Object.freeze(commands.map(Object.freeze)),
    commandFingerprint: hash(JSON.stringify([identity])),
    configurationFingerprint: hash(
      JSON.stringify({ schemaVersion: 1, commands: [vector] }),
    ),
  });
}

function emptyDecision() {
  return { question: "", options: [], whyBlocked: "", evidence: [] };
}

function clarificationReady() {
  return {
    status: "READY",
    questions: [],
    reason: "",
    ...emptyDecision(),
  };
}

function clarificationQuestions() {
  return {
    status: "QUESTIONS",
    questions: [
      {
        question: "Which externally visible behavior is required?",
        whyItMatters: "The answer changes implementation of the plan.",
      },
    ],
    reason: "",
    ...emptyDecision(),
  };
}

function clarificationPlanRevision() {
  return {
    status: "PLAN_REVISION_REQUIRED",
    questions: [],
    reason: "The requested behavior conflicts with the validated plan.",
    question: "",
    options: [],
    whyBlocked: "",
    evidence: ["The plan excludes the required public behavior."],
  };
}

function bootstrapReady(role) {
  return {
    status: "READY",
    summary: `${role} understands the task, architecture, plan, risks, and finalization procedure.`,
    requiredChecks: REQUIRED_CHECKS,
    validationInfrastructure: VALIDATION_INFRASTRUCTURE,
    capacityField: "",
    capacityLimit: 0,
    reason: "",
    ...emptyDecision(),
  };
}

function bootstrapProductDecision() {
  return {
    status: "PRODUCT_DECISION_REQUIRED",
    summary: "",
    requiredChecks: [],
    validationInfrastructure: [],
    capacityField: "",
    capacityLimit: 0,
    reason: "",
    question: "Which public behavior should be implemented?",
    options: ["Behavior A", "Behavior B"],
    whyBlocked: "Both behaviors are valid but incompatible.",
    evidence: ["The task and plan do not choose a behavior."],
  };
}

function bootstrapCapacityExhausted(capacityField) {
  return {
    status: "CAPACITY_EXHAUSTED",
    summary: "",
    requiredChecks: [],
    validationInfrastructure: [],
    capacityField,
    capacityLimit: MAX_BOOTSTRAP_ITEMS,
    reason: "",
    ...emptyDecision(),
  };
}

function compatibilityReady() {
  return { status: "READY", reason: "", evidence: [] };
}

function compatibilityPlanRevision() {
  return {
    status: "PLAN_REVISION_REQUIRED",
    reason: "The product decision changes a planned commit boundary.",
    evidence: ["The selected behavior requires another commit."],
  };
}

function reconciliationResolved() {
  return {
    status: "RESOLVED",
    summary: "The roles agree on the minimal implementation and finalization procedure.",
    disagreement: "",
    reason: "",
    ...emptyDecision(),
  };
}

function reconciliationDisagreement() {
  return {
    status: "DISAGREEMENT",
    summary: "",
    disagreement: "The roles disagree about the required repository boundary.",
    reason: "",
    question: "",
    options: [],
    whyBlocked: "",
    evidence: ["Worker and Reviewer identify different owning modules."],
  };
}

function reconciliationProductDecision() {
  return {
    status: "PRODUCT_DECISION_REQUIRED",
    summary: "",
    disagreement: "",
    reason: "",
    question: "Which public behavior should be implemented?",
    options: ["Behavior A", "Behavior B"],
    whyBlocked: "Both behaviors are valid but incompatible.",
    evidence: ["The independent summaries expose an unresolved requirement."],
  };
}

function arbitrationResolved() {
  return {
    direction: "SYNTHESIZE",
    summary: "Use the existing repository boundary and keep the change local.",
    rationale: "Repository ownership evidence supports the existing boundary.",
    reason: "",
    ...emptyDecision(),
  };
}

function arbitrationProductDecision() {
  return {
    direction: "PRODUCT_DECISION_REQUIRED",
    summary: "",
    rationale: "The repository evidence cannot select a product behavior.",
    reason: "",
    question: "Which public behavior should be implemented?",
    options: ["Behavior A", "Behavior B"],
    whyBlocked: "Both behaviors are valid but incompatible.",
    evidence: ["The task and plan do not choose a behavior."],
  };
}

function implementationCompleted() {
  return {
    status: "COMPLETED",
    summary: "Implemented and self-reviewed the planned change.",
    reason: "",
    ...emptyDecision(),
  };
}

function implementationBlocked() {
  return {
    status: "BLOCKED",
    summary: "",
    reason: "A required local service is temporarily unavailable.",
    question: "",
    options: [],
    whyBlocked: "",
    evidence: ["The local service health check failed."],
  };
}

function environmentBlocked(reason, evidence) {
  return {
    status: "BLOCKED",
    decisions: [],
    reason,
    question: "",
    options: [],
    whyBlocked: "",
    evidence: [evidence],
  };
}

function finalizationPassed(
  skillPath = ".agents/skills/finalization/SKILL.md",
) {
  return {
    status: "PASS",
    skillPath,
    summary: "The repository finalization procedure passed.",
    issues: [],
    requiredChecks: REQUIRED_CHECKS,
    validationInfrastructure: VALIDATION_INFRASTRUCTURE,
    checks: checkResults("PASS"),
    reason: "",
    ...emptyDecision(),
  };
}

function reviewApproved(validationChange = "UNCHANGED") {
  return {
    status: "APPROVED",
    findings: [],
    validationChange,
    validationEvidence:
      validationChange === "UNCHANGED"
        ? []
        : ["The planned commit authorizes the complete validation change."],
    ...emptyDecision(),
  };
}

function implementationProductDecision() {
  return {
    status: "PRODUCT_DECISION_REQUIRED",
    summary: "",
    reason: "",
    question: "Which public behavior should the implementation expose?",
    options: ["Behavior A", "Behavior B"],
    whyBlocked: "Both behaviors are valid but incompatible.",
    evidence: ["The validated inputs do not choose one."],
  };
}

function finalizationFailed(...ids) {
  return {
    status: "FAIL",
    skillPath: ".agents/skills/finalization/SKILL.md",
    summary: "The repository finalization procedure found blocking failures.",
    issues: ids.map((id) => ({
      id,
      command: "npm test",
      problem: `Validation failed for ${id}.`,
      evidence: [`${id} failed in the test output.`],
    })),
    requiredChecks: REQUIRED_CHECKS,
    validationInfrastructure: VALIDATION_INFRASTRUCTURE,
    checks: checkResults("FAIL", "The fixture check failed."),
    reason: "",
    ...emptyDecision(),
  };
}

function finalizationUnavailable(status) {
  return {
    status,
    skillPath: ".agents/skills/finalization/SKILL.md",
    summary: "",
    issues: [],
    requiredChecks: [],
    validationInfrastructure: [],
    checks: [],
    reason: "The finalization skill cannot be used safely.",
    question: "",
    options: [],
    whyBlocked: "",
    evidence: ["The repository instructions do not provide a valid procedure."],
  };
}

function finalizationBlocked(reason, evidence) {
  return {
    status: "BLOCKED",
    skillPath: ".agents/skills/finalization/SKILL.md",
    summary: "",
    issues: [],
    requiredChecks: REQUIRED_CHECKS,
    validationInfrastructure: VALIDATION_INFRASTRUCTURE,
    checks: checkResults("BLOCKED", evidence),
    reason,
    question: "",
    options: [],
    whyBlocked: "",
    evidence: [evidence],
  };
}

function invalidProductionFinalization() {
  const requiredChecks = [
    REQUIRED_CHECKS[0],
    { id: "C2", command: "git diff --check HEAD" },
    { id: "C3", command: "git status" },
  ];
  return {
    status: "BLOCKED",
    skillPath: ".agents/skills/finalization/SKILL.md",
    summary: "",
    issues: [],
    requiredChecks,
    validationInfrastructure: [
      ...VALIDATION_INFRASTRUCTURE,
      "DO_NOT_PERSIST_REJECTED_PATH",
    ],
    checks: requiredChecks.map(({ id, command }, index) => ({
      checkId: id,
      command,
      status: index === 2 ? "BLOCKED" : "PASS",
      evidence: ["DO_NOT_PERSIST_REJECTED_PROVIDER_TEXT"],
    })),
    reason: "DO_NOT_PERSIST_REJECTED_BLOCKER",
    question: "",
    options: [],
    whyBlocked: "",
    evidence: ["DO_NOT_PERSIST_REJECTED_EVIDENCE"],
  };
}

function reviewFindings(...ids) {
  return {
    status: "FINDINGS",
    findings: ids.map((id) => ({
      id,
      file: "source.js",
      problem: `Problem ${id} remains.`,
      reason: `The current implementation still exhibits ${id}.`,
      suggestedAction: `Fix ${id}.`,
    })),
    validationChange: "UNCHANGED",
    validationEvidence: [],
    ...emptyDecision(),
  };
}

function reviewProductDecision() {
  return {
    status: "PRODUCT_DECISION_REQUIRED",
    findings: [],
    validationChange: "UNCHANGED",
    validationEvidence: [],
    question: "Which public behavior should the review require?",
    options: ["Behavior A", "Behavior B"],
    whyBlocked: "Both behaviors are valid but incompatible.",
    evidence: ["The validated inputs do not select either behavior."],
  };
}

function resolution(...decisions) {
  return {
    status: "RESOLVED",
    decisions: decisions.map(({ decision, id }) => ({
      id,
      decision,
      reason:
        decision === "FIX"
          ? `Applied the correction for ${id}.`
          : `The implementation already satisfies ${id}.`,
      evidence:
        decision === "FIX" ? [] : [`source.js demonstrates why ${id} is invalid.`],
    })),
    reason: "",
    ...emptyDecision(),
  };
}

function reconsideration(direction, ...ids) {
  return {
    status: "RESOLVED",
    decisions: ids.map((id) => ({
      id,
      direction,
      reason: `${direction} is supported for ${id}.`,
      evidence: [`The current repository evidence supports ${direction}.`],
    })),
    ...emptyDecision(),
  };
}

function reconsiderationProductDecision() {
  return {
    status: "PRODUCT_DECISION_REQUIRED",
    decisions: [],
    question: "Which public behavior should resolve the disputed finding?",
    options: ["Behavior A", "Behavior B"],
    whyBlocked: "Both interpretations remain valid and incompatible.",
    evidence: ["The plan and repository do not resolve the dispute."],
  };
}

function findingArbitration(direction) {
  return {
    direction,
    rationale: `Repository evidence supports ${direction}.`,
    ...emptyDecision(),
  };
}

function stagnation(direction, findingIds = []) {
  return {
    direction,
    rationale: `The minimal next direction is ${direction}.`,
    findingIds,
    reason: "",
    ...emptyDecision(),
  };
}

function matchesSchemaSubset(schema, value) {
  const objectValue =
    value !== null && typeof value === "object" && !Array.isArray(value);
  if (schema.type === "string" && typeof value !== "string") {
    return false;
  }
  if (schema.type === "array" && !Array.isArray(value)) {
    return false;
  }
  if (schema.type === "object" && !objectValue) {
    return false;
  }
  if (schema.enum !== undefined && !schema.enum.includes(value)) {
    return false;
  }
  if (typeof value === "string") {
    const length = [...value].length;
    if (
      (schema.minLength !== undefined && length < schema.minLength) ||
      (schema.maxLength !== undefined && length > schema.maxLength) ||
      (schema.pattern !== undefined &&
        !new RegExp(schema.pattern, "u").test(value))
    ) {
      return false;
    }
  }
  if (Array.isArray(value)) {
    if (
      (schema.minItems !== undefined && value.length < schema.minItems) ||
      (schema.maxItems !== undefined && value.length > schema.maxItems) ||
      (schema.items !== undefined &&
        value.some((item) => !matchesSchemaSubset(schema.items, item)))
    ) {
      return false;
    }
  }
  if (objectValue) {
    if (
      schema.required?.some((field) => !Object.hasOwn(value, field)) ||
      (schema.additionalProperties === false &&
        Object.keys(value).some(
          (field) => !Object.hasOwn(schema.properties, field),
        )) ||
      Object.entries(schema.properties ?? {}).some(
        ([field, propertySchema]) =>
          Object.hasOwn(value, field) &&
          !matchesSchemaSubset(propertySchema, value[field]),
      )
    ) {
      return false;
    }
  }
  if (
    schema.anyOf !== undefined &&
    !schema.anyOf.some((branch) => matchesSchemaSubset(branch, value))
  ) {
    return false;
  }
  return true;
}

function schemaPatterns(schema) {
  if (schema === null || typeof schema !== "object") {
    return [];
  }
  return [
    ...(typeof schema.pattern === "string" ? [schema.pattern] : []),
    ...Object.values(schema).flatMap(schemaPatterns),
  ];
}

function assertStrictSchema(schema) {
  if (schema === null || typeof schema !== "object") {
    return;
  }
  if (
    !Array.isArray(schema) &&
    (schema.type === "object" || schema.properties !== undefined)
  ) {
    assert.equal(schema.additionalProperties, false);
    assert.deepEqual(
      new Set(schema.required),
      new Set(Object.keys(schema.properties)),
    );
  }
  for (const child of Object.values(schema)) {
    assertStrictSchema(child);
  }
}

function assertArraySchemasDeclareItems(schema) {
  if (schema === null || typeof schema !== "object") {
    return;
  }
  if (!Array.isArray(schema) && schema.type === "array") {
    assert.notEqual(schema.items, undefined);
  }
  for (const child of Object.values(schema)) {
    assertArraySchemasDeclareItems(child);
  }
}

async function repositoryFingerprint(root) {
  const entries = [];

  async function visit(directory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      if (entry.name === ".git") {
        continue;
      }
      const path = join(directory, entry.name);
      const pathFromRoot = relative(root, path);
      if (
        pathFromRoot === "LOCAL_ARTIFACTS" ||
        pathFromRoot.startsWith("LOCAL_ARTIFACTS/")
      ) {
        continue;
      }
      if (entry.isDirectory()) {
        await visit(path);
      } else if (entry.isSymbolicLink()) {
        entries.push([pathFromRoot, hash(await readlink(path))]);
      } else {
        entries.push([pathFromRoot, hash(await readFile(path))]);
      }
    }
  }

  await visit(root);
  entries.sort(([left], [right]) => left.localeCompare(right));
  return hash(JSON.stringify(entries));
}

function createClarificationService({
  interactive = false,
  onEdit,
  onFreeze,
} = {}) {
  let authorizationIndex = 0;

  async function inspectTranscript({ artifactRoot, transcriptPath }) {
    const content = await readFile(transcriptPath, "utf8");
    return Object.freeze({
      artifactRoot,
      transcriptPath,
      content,
      hash: hash(content),
    });
  }

  function assertExpectedHash(snapshot, expectedHash) {
    if (snapshot.hash !== expectedHash) {
      const error = new Error("Clarifications changed.");
      error.code = "ERR_CLARIFICATIONS_CHANGED";
      throw error;
    }
  }

  async function ensureTranscript(options) {
    await mkdir(dirname(options.transcriptPath), { recursive: true });
    await writeFile(options.transcriptPath, "", { flag: "a" });
    return inspectTranscript(options);
  }

  async function append(options, section) {
    const snapshot = await inspectTranscript(options);
    assertExpectedHash(snapshot, options.expectedHash);
    const separator = snapshot.content.length === 0 ? "" : "\n\n";
    await writeFile(
      options.transcriptPath,
      `${snapshot.content}${separator}${section}\n`,
    );
    return inspectTranscript(options);
  }

  async function appendQuestionRound(options) {
    return append(
      options,
      `## Round ${options.round}\n\n${options.questions[0].question}\n\n<!-- answer -->`,
    );
  }

  async function appendProductDecision(options) {
    return append(
      options,
      `## Product Decision ${options.number}\n\n${options.question}\n\n<!-- decision -->`,
    );
  }

  async function prepareEdit(options) {
    const snapshot = await inspectTranscript(options);
    assertExpectedHash(snapshot, options.expectedHash);
    const authorization = Object.freeze({
      schemaVersion: 1,
      id: `edit-${++authorizationIndex}`,
      artifactRoot: options.artifactRoot,
      transcriptPath: options.transcriptPath,
      suspendedState: options.suspendedState,
      action: options.action,
      preEditorHash: snapshot.hash,
    });
    await options.persistPendingEdit(authorization);
    return authorization;
  }

  async function acceptEdit(authorization, { consumePendingEdit }) {
    const snapshot = await inspectTranscript(authorization);
    const result = Object.freeze({
      authorizationId: authorization.id,
      suspendedState: authorization.suspendedState,
      action: authorization.action,
      transcriptPath: authorization.transcriptPath,
      preEditorHash: authorization.preEditorHash,
      hash: snapshot.hash,
      changed: snapshot.hash !== authorization.preEditorHash,
    });
    await consumePendingEdit(result);
    return result;
  }

  async function openEditor(authorization, options) {
    if (!interactive) {
      return Object.freeze({ status: "WAITING_FOR_USER", authorization });
    }
    await onEdit?.(authorization);
    return Object.freeze({
      status: "COMPLETED",
      result: await acceptEdit(authorization, options),
    });
  }

  return Object.freeze({
    acceptEdit,
    appendProductDecision,
    appendQuestionRound,
    ensureTranscript,
    freezeTranscript: async (options) => {
      const snapshot = await inspectTranscript(options);
      assertExpectedHash(snapshot, options.expectedHash);
      return (await onFreeze?.(snapshot)) ?? snapshot;
    },
    inspectTranscript,
    openEditor,
    prepareEdit,
  });
}

async function optionalInput(path) {
  try {
    const content = await readFile(path, "utf8");
    return { path, content, hash: hash(content) };
  } catch (cause) {
    if (cause?.code === "ENOENT") {
      return null;
    }
    throw cause;
  }
}

async function createFixture(
  t,
  {
    artifactRoot = "LOCAL_ARTIFACTS",
    arbiter = [],
    capabilities = {},
    clarificationIgnored = true,
    dirty = false,
    finalizationSkill = true,
    interactive = false,
    models = {},
    onEdit,
    onFreeze,
    onCommitRun,
    onCommitVerify,
    onRoleRun,
    onTrustedValidation,
    onTransition,
    plan = PLAN,
    prepareProject,
    proactiveClarification = false,
    reviewer = [bootstrapReady("Reviewer")],
    sessionIds = ROLE_SESSIONS,
    sourceSession = null,
    trustedValidation,
    workReviewer = [reviewApproved()],
    workWorker = [implementationCompleted(), finalizationPassed()],
    worker = [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
    ],
  } = {},
) {
  const projectPath = await mkdtemp(join(tmpdir(), "agent-runner-execution-"));
  const statePath = await mkdtemp(join(tmpdir(), "agent-runner-state-"));
  const taskPath = join(projectPath, "task");
  const runId = "run-1";
  const clarificationPath = join(
    projectPath,
    artifactRoot,
    "agent-runner",
    runId,
    "clarifications.md",
  );
  await executeFile("git", ["init", "-q", projectPath]);
  await executeFile("git", ["-C", projectPath, "config", "user.name", "Test"]);
  await executeFile("git", ["-C", projectPath, "config", "user.email", "test@example.com"]);
  await mkdir(taskPath);
  await writeFile(join(taskPath, "task.md"), "Implement the requested behavior.\n");
  await writeFile(join(taskPath, "plan.md"), plan);
  if (finalizationSkill) {
    await mkdir(join(projectPath, ".agents", "skills", "finalization"), {
      recursive: true,
    });
    await writeFile(
      join(projectPath, ".agents", "skills", "finalization", "SKILL.md"),
      "---\nname: finalization\ndescription: Test validation.\n---\n\nRun tests.\n",
    );
  }
  await writeFile(
    join(projectPath, ".gitignore"),
    clarificationIgnored ? `/${artifactRoot}/\n` : "",
  );
  await writeFile(join(projectPath, "source.js"), "export const value = 1;\n");
  await writeFile(
    join(projectPath, "package.json"),
    '{"scripts":{"test":"node --test"}}\n',
  );
  await prepareProject?.(projectPath);
  await executeFile("git", ["-C", projectPath, "add", "."]);
  await executeFile("git", ["-C", projectPath, "commit", "-qm", "test: fixture"]);
  if (dirty) {
    await writeFile(join(projectPath, "dirty.txt"), "dirty\n");
  }
  t.after(() => rm(projectPath, { recursive: true, force: true }));
  t.after(() => rm(statePath, { recursive: true, force: true }));

  const queues = {
    worker: [...worker, ...workWorker],
    reviewer: [...reviewer, ...workReviewer],
    arbiter: [...arbiter],
  };
  const calls = { worker: [], reviewer: [], arbiter: [] };
  const probeCalls = { worker: 0, reviewer: 0, arbiter: 0 };
  const freshSessionIndexes = { worker: 0, reviewer: 0, arbiter: 0 };

  function nextFreshSessionId(role) {
    const configured = sessionIds[role];
    if (!Array.isArray(configured)) {
      const index = freshSessionIndexes[role]++;
      return index === 0 ? configured : `${configured}-${index + 1}`;
    }
    const sessionId = configured[freshSessionIndexes[role]++];
    assert.notEqual(sessionId, undefined, `Missing fresh ${role} session ID.`);
    return sessionId;
  }

  const defaultCapabilities = {
    version: "fake-1.0.0",
    structuredOutput: true,
    readOnly: true,
    autonomousWrite: true,
    workspaceWrite: true,
    localCommit: true,
    remoteWriteBlocked: true,
    nativeSessionContinuation: true,
    nativeSessionFork: true,
  };
  const adapters = Object.fromEntries(
    Object.keys(queues).map((role) => [
      role,
      {
        async probe() {
          probeCalls[role] += 1;
          return { ...defaultCapabilities, ...capabilities[role] };
        },
        async run(request) {
          calls[role].push(request);
          assert.match(request.prompt, /Do not delegate/u);
          assert.match(
            request.recoveryPrompt ?? request.prompt,
            /Do not delegate/u,
          );
          await onRoleRun?.(role, request, calls[role].length);
          if (request.access === "local-commit") {
            if (onCommitRun === undefined) {
              await executeFile("git", ["-C", projectPath, "add", "-A"]);
              await executeFile("git", [
                "-C",
                projectPath,
                "commit",
                "-qm",
                request.commit.message,
              ]);
            } else {
              await onCommitRun(request);
            }
            return {
              output: "committed",
              sessionId: request.session?.id ?? nextFreshSessionId(role),
            };
          }
          assert.ok(queues[role].length > 0, `Unexpected ${role} turn.`);
          const structured = queues[role].shift();
          if (structured === MISSING_BOOTSTRAP_RESPONSE) {
            return null;
          }
          if (
            role === "worker" &&
            structured.status === "COMPLETED" &&
            request.prompt.includes("Implement the changes")
          ) {
            const step =
              /Current planned commit:\n## Commit ([1-9][0-9]*):/u.exec(
                request.prompt,
              )?.[1];
            assert.notEqual(step, undefined);
            await writeFile(
              join(projectPath, `implementation-${step}.txt`),
              `implemented step ${step}\n`,
            );
          }
          return {
            output: "structured",
            structured: WRAPPED_BOOTSTRAP_SCHEMAS.has(request.schema)
              ? { result: structured }
              : structured,
            sessionId:
              request.session?.mode === "continue"
                ? request.session.id
                : nextFreshSessionId(role),
          };
        },
      },
    ]),
  );

  async function gitSnapshot({ allowedPaths = [] } = {}) {
    const [head, branch, refs, status, index, remotes, identity] = await Promise.all([
      executeFile("git", ["-C", projectPath, "rev-parse", "HEAD"]),
      executeFile("git", ["-C", projectPath, "rev-parse", "--abbrev-ref", "HEAD"]),
      executeFile("git", ["-C", projectPath, "for-each-ref"]),
      executeFile("git", [
        "-C",
        projectPath,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
      ]),
      executeFile("git", ["-C", projectPath, "diff", "--cached", "--binary"]),
      executeFile("git", ["-C", projectPath, "config", "--get-regexp", "^(remote|url)\\."]).catch(
        () => ({ stdout: "" }),
      ),
      executeFile("git", [
        "-C",
        projectPath,
        "config",
        "--get-regexp",
        "^user\\.(name|email)$",
      ]),
    ]);
    const content = await repositoryFingerprint(projectPath);
    const normalizedAllowedPaths = allowedPaths
      .map((path) => (isAbsolute(path) ? relative(projectPath, path) : path))
      .sort();
    const snapshot = {
      schemaVersion: 1,
      projectPath,
      allowedPaths: normalizedAllowedPaths,
      head: head.stdout.trim(),
      branch: branch.stdout.trim() === "HEAD" ? null : `refs/heads/${branch.stdout.trim()}`,
      detached: branch.stdout.trim() === "HEAD",
      clean: status.stdout.trim().length === 0,
      refsFingerprint: hash(refs.stdout),
      trackedContentFingerprint: content,
      untrackedContentFingerprint: hash(status.stdout),
      contentFingerprint: content,
      indexFingerprint: hash(index.stdout),
      remoteConfigurationFingerprint: hash(remotes.stdout),
      identityAvailable: true,
      identityFingerprint: hash(identity.stdout),
    };
    return {
      ...snapshot,
      fingerprint: hash(JSON.stringify(snapshot)),
    };
  }

  let currentRun = {
    revision: 1,
    runId,
    pipelineId: "plan-execution",
    pipelineStateVersion: 7,
    projectPath,
    taskPath,
    roles: {
      worker: { backend: "codex", model: models.worker ?? null },
      reviewer: { backend: "codex", model: models.reviewer ?? null },
      arbiter: { backend: "codex", model: models.arbiter ?? null },
    },
    counters: {},
    hashes: {},
    pause: null,
    activeTurn: null,
    sessionLineage: { source: sourceSession, children: [] },
    pipelineState: createPlanExecutionState({
      artifactRoot,
      proactiveClarification,
      ...(trustedValidation === undefined ? {} : { trustedValidation }),
    }),
  };
  const preflights = [];
  const transitions = [];
  const artifacts = new Map();
  let commitAuthorizationIndex = 0;
  const runtime = {
    adapters,
    clarifications: createClarificationService({
      interactive,
      onEdit,
      onFreeze,
    }),
    trustedValidation: {
      async execute(options) {
        assert.notEqual(onTrustedValidation, undefined);
        return onTrustedValidation(options);
      },
    },
    git: {
      async inspectPath({ path }) {
        const absolutePath = isAbsolute(path) ? path : join(projectPath, path);
        let canonicalPath;
        try {
          canonicalPath = await realpath(absolutePath);
        } catch (cause) {
          if (cause?.code !== "ENOENT") {
            throw cause;
          }
          return {
            exists: false,
            kind: null,
            relativePath: relative(projectPath, absolutePath),
          };
        }
        const relativePath = relative(projectPath, canonicalPath);
        if (
          relativePath === ".." ||
          relativePath.startsWith(`..${sep}`) ||
          isAbsolute(relativePath)
        ) {
          const error = new Error("Repository path escapes through a symlink.");
          error.code = "ERR_UNSAFE_REPOSITORY_PATH";
          throw error;
        }
        const metadata = await lstat(canonicalPath);
        return {
          exists: true,
          kind: metadata.isFile()
            ? "file"
            : metadata.isDirectory()
              ? "directory"
              : "other",
          relativePath,
        };
      },
      async prepareCommit({ expectedSnapshot, subject, persistPendingCommit }) {
        const authorization = Object.freeze({
          schemaVersion: 1,
          id: `commit-${++commitAuthorizationIndex}`,
          projectPath,
          expectedHead: expectedSnapshot.head,
          expectedBranch: expectedSnapshot.branch,
          expectedRefsFingerprint: expectedSnapshot.refsFingerprint,
          expectedOtherRefsFingerprint: expectedSnapshot.refsFingerprint,
          expectedContentFingerprint: expectedSnapshot.contentFingerprint,
          expectedIndexFingerprint: expectedSnapshot.indexFingerprint,
          expectedRemoteConfigurationFingerprint:
            expectedSnapshot.remoteConfigurationFingerprint,
          expectedIdentityFingerprint: expectedSnapshot.identityFingerprint,
          expectedAuthorIdentityFingerprint: hash("author"),
          expectedCommitterIdentityFingerprint: hash("committer"),
          subject,
        });
        const current = await gitSnapshot({
          allowedPaths: expectedSnapshot.allowedPaths,
        });
        if (current.fingerprint !== expectedSnapshot.fingerprint) {
          const error = new Error("Commit gate changed.");
          error.code = "ERR_COMMIT_GATE_CHANGED";
          throw error;
        }
        await persistPendingCommit(authorization);
        return authorization;
      },
      async consumeCommit(authorization, { consumePendingCommit }) {
        await consumePendingCommit();
        return Object.freeze({
          authorizationId: authorization.id,
          cwd: authorization.projectPath,
          access: "local-commit",
          commit: Object.freeze({
            expectedHead: authorization.expectedHead,
            message: authorization.subject,
          }),
        });
      },
      async verifyCommit(authorization) {
        await onCommitVerify?.(authorization);
        const snapshot = await gitSnapshot();
        if (snapshot.head === authorization.expectedHead) {
          const error = new Error("Authorized commit was not created.");
          error.code = "ERR_COMMIT_NOT_CREATED";
          throw error;
        }
        const [{ stdout: parents }, { stdout: message }] = await Promise.all([
          executeFile("git", [
            "-C",
            projectPath,
            "show",
            "-s",
            "--format=%P",
            snapshot.head,
          ]),
          executeFile("git", [
            "-C",
            projectPath,
            "show",
            "-s",
            "--format=%B",
            snapshot.head,
          ]),
        ]);
        const changes = [];
        if (parents.trim() !== authorization.expectedHead) {
          changes.push("parent");
        }
        if (message.trimEnd() !== authorization.subject) {
          changes.push("message");
        }
        if (/(?:^|\n)co-authored-by[ \t]*:/iu.test(message)) {
          changes.push("co-author");
        }
        if (!snapshot.clean) {
          changes.push("worktree-or-index");
        }
        if (
          (await repositoryFingerprint(projectPath)) !==
          authorization.expectedContentFingerprint
        ) {
          changes.push("content");
        }
        if (changes.length > 0) {
          const error = new Error("Authorized commit violates its contract.");
          error.code = "ERR_COMMIT_CONTRACT_VIOLATED";
          error.changes = changes;
          throw error;
        }
        return Object.freeze({
          authorizationId: authorization.id,
          head: snapshot.head,
          subject: authorization.subject,
          contentFingerprint: authorization.expectedContentFingerprint,
        });
      },
      async contentFingerprint() {
        return repositoryFingerprint(projectPath);
      },
      async validationInfrastructureFingerprint({ paths }) {
        const entries = await Promise.all(
          paths.map(async (path) => {
            try {
              return [path, await readFile(join(projectPath, path), "utf8")];
            } catch (cause) {
              if (cause?.code === "ENOENT") {
                return [path, null];
              }
              throw cause;
            }
          }),
        );
        return hash(JSON.stringify(entries));
      },
      async preflight(options) {
        preflights.push(options);
        if (options.requireClean) {
          const { stdout } = await executeFile("git", [
            "-C",
            projectPath,
            "status",
            "--porcelain",
            "--untracked-files=all",
          ]);
          if (stdout.trim().length > 0) {
            const error = new Error("Repository is not clean.");
            error.code = "ERR_REPOSITORY_NOT_CLEAN";
            throw error;
          }
        }
        for (const path of options.requiredIgnoredPaths) {
          try {
            await executeFile("git", [
              "-C",
              projectPath,
              "check-ignore",
              "-q",
              "--",
              path,
            ]);
          } catch (cause) {
            const error = new Error("Artifact is not ignored.");
            error.code = "ERR_REPOSITORY_ARTIFACT_NOT_IGNORED";
            error.cause = cause;
            throw error;
          }
        }
        return { snapshot: await gitSnapshot(options) };
      },
      snapshot: gitSnapshot,
      async assertUnchanged(snapshot) {
        const current = await gitSnapshot({ allowedPaths: snapshot.allowedPaths });
        if (snapshot.fingerprint !== current.fingerprint) {
          const error = new Error("Read-only repository changed.");
          error.code = "ERR_READ_ONLY_REPOSITORY_CHANGED";
          throw error;
        }
      },
      async reconcileInterrupted(snapshot, { allowWorkspaceChanges }) {
        const current = await gitSnapshot({
          allowedPaths: snapshot.allowedPaths,
        });
        if (!allowWorkspaceChanges) {
          await this.assertUnchanged(snapshot);
          return current;
        }
        const changes = [];
        for (const [field, name] of [
          ["head", "head"],
          ["branch", "branch"],
          ["detached", "detached-head"],
          ["refsFingerprint", "refs"],
          ["remoteConfigurationFingerprint", "remote-configuration"],
          ["identityFingerprint", "identity"],
        ]) {
          if (snapshot[field] !== current[field]) {
            changes.push(name);
          }
        }
        if (changes.length > 0) {
          const error = new Error("Interrupted repository controls changed.");
          error.code = "ERR_INTERRUPTED_REPOSITORY_CONTROL_CHANGED";
          error.changes = changes;
          throw error;
        }
        return current;
      },
    },
    async readInputs() {
      const task = await optionalInput(join(taskPath, "task.md"));
      const planInput = await optionalInput(join(taskPath, "plan.md"));
      if (task === null || planInput === null) {
        const error = new Error("Required task input is missing.");
        error.code = "ENOENT";
        error.path = task === null ? join(taskPath, "task.md") : join(taskPath, "plan.md");
        throw error;
      }
      return {
        task,
        plan: planInput,
        taskClarifications: await optionalInput(join(taskPath, "clarifications.md")),
        context: await optionalInput(join(taskPath, "context.md")),
      };
    },
    async transition(patch, options) {
      currentRun = { ...currentRun, ...patch, revision: currentRun.revision + 1 };
      transitions.push({ patch, options });
      await onTransition?.(currentRun, patch, options);
      return currentRun;
    },
    async startAgentTurn(activeTurn) {
      currentRun = {
        ...currentRun,
        activeTurn,
        revision: currentRun.revision + 1,
      };
      transitions.push({ activeTurn, kind: "turn-started", options: {} });
      return currentRun;
    },
    async finishAgentTurn(activeTurn) {
      assert.deepEqual(currentRun.activeTurn, activeTurn);
      currentRun = {
        ...currentRun,
        activeTurn: null,
        revision: currentRun.revision + 1,
      };
      transitions.push({ activeTurn, kind: "turn-finished", options: {} });
      return currentRun;
    },
    async recordChildSession(child, options) {
      currentRun = {
        ...currentRun,
        revision: currentRun.revision + 1,
        sessionLineage: {
          ...currentRun.sessionLineage,
          children: [...currentRun.sessionLineage.children, child],
        },
      };
      transitions.push({ child, options });
      return currentRun;
    },
    async writeRunArtifact({ path, content }) {
      const artifactPath = join(statePath, path);
      await mkdir(dirname(artifactPath), { recursive: true });
      await writeFile(artifactPath, content);
      artifacts.set(path, content);
      return artifactPath;
    },
  };

  async function run(settings = {}, action) {
    currentRun = await runPlanExecution({
      action,
      run: currentRun,
      runtime,
      settings: { ...SETTINGS, ...settings },
    });
    return currentRun;
  }

  function persistPipelineState(
    pipelineState,
    { pause = currentRun.pause } = {},
  ) {
    currentRun = {
      ...currentRun,
      pipelineStateVersion: 7,
      pipelineState,
      pause,
      revision: currentRun.revision + 1,
    };
    assertRun(currentRun);
    return currentRun;
  }

  return {
    artifacts,
    calls,
    clarificationPath,
    get currentRun() {
      return currentRun;
    },
    preflights,
    probeCalls,
    projectPath,
    persistPipelineState,
    run,
    runtime,
    taskPath,
    transitions,
  };
}

test("clarifies and bootstraps through independent source-session forks", async (t) => {
  const fixture = await createFixture(t, {
    models: {
      worker: "worker-model",
      reviewer: "reviewer-model",
      arbiter: "arbiter-model",
    },
    sourceSession: SOURCE_SESSION,
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.currentStep, null);
  assert.equal(result.pipelineState.completedCommits.length, 1);
  assert.equal(result.pipelineState.canonicalPlan, PLAN);
  assert.equal(result.pipelineState.clarificationPath, fixture.clarificationPath);
  assert.equal(result.pipelineState.clarificationFrozen, true);
  assert.deepEqual(result.pipelineState.backendVersions, {
    worker: "fake-1.0.0",
    reviewer: "fake-1.0.0",
    arbiter: null,
  });
  assert.equal(fixture.preflights.length, 2);
  assert.deepEqual(fixture.preflights[1].requiredIgnoredPaths, [
    fixture.clarificationPath,
  ]);
  assert.equal(fixture.preflights[1].requireClean, true);
  assert.equal(fixture.preflights[1].requireIdentity, true);
  assert.deepEqual(
    result.sessionLineage.children.map(({ role }) => role),
    ["worker", "worker", "reviewer", "worker", "reviewer"],
  );
  assert.deepEqual(fixture.calls.worker[0].session, {
    mode: "fork",
    id: SOURCE_SESSION,
  });
  assert.deepEqual(fixture.calls.worker[1].session, {
    mode: "fork",
    id: SOURCE_SESSION,
  });
  for (const heading of [
    /Task \(/u,
    /Validated plan \(/u,
    /Plan-authoring clarifications \(/u,
    /Context \(/u,
    /Execution clarifications \(/u,
  ]) {
    assert.match(fixture.calls.worker[1].prompt, heading);
    assert.match(fixture.calls.worker[2].recoveryPrompt, heading);
    assert.doesNotMatch(fixture.calls.worker[2].prompt, heading);
  }
  assert.deepEqual(fixture.calls.worker[2].session, {
    mode: "continue",
    id: result.sessionLineage.children[1].sessionId,
  });
  assert.deepEqual(fixture.calls.reviewer[0].session, {
    mode: "fork",
    id: SOURCE_SESSION,
  });
  assert.deepEqual(fixture.calls.worker[3].session, {
    mode: "fork",
    id: SOURCE_SESSION,
  });
  assert.deepEqual(fixture.calls.reviewer[1].session, {
    mode: "fork",
    id: SOURCE_SESSION,
  });
  assert.doesNotMatch(fixture.calls.reviewer[0].prompt, /Worker understands/u);
  assert.doesNotMatch(fixture.calls.worker[1].prompt, /Reviewer understands/u);
  assert.match(
    fixture.calls.reviewer[0].prompt,
    /As Reviewer, also state what you intend to verify\./u,
  );
  assert.doesNotMatch(
    fixture.calls.worker[1].prompt,
    /As Reviewer, also state what you intend to verify\./u,
  );
  assert.match(fixture.calls.worker[2].prompt, /Worker bootstrap summary/u);
  assert.match(fixture.calls.worker[2].prompt, /Reviewer bootstrap summary/u);
  const finalizationCall = fixture.calls.worker.find(({ prompt }) =>
    prompt.includes("Run the complete project finalization procedure"),
  );
  assert.ok(finalizationCall);
  assert.deepEqual(finalizationCall.session, {
    mode: "continue",
    id: result.sessionLineage.children[3].sessionId,
  });
  assert.doesNotMatch(finalizationCall.prompt, /Resolved bootstrap context:/u);
  assert.match(finalizationCall.recoveryPrompt, /Resolved bootstrap context:/u);
  assert.match(fixture.calls.reviewer[1].prompt, /Resolved bootstrap context:/u);
  assert.equal(
    fixture.calls.reviewer[1].prompt,
    fixture.calls.reviewer[1].recoveryPrompt,
  );
  assert.equal(fixture.calls.worker[0].model, "worker-model");
  assert.equal(fixture.calls.reviewer[0].model, "reviewer-model");
  for (const child of result.sessionLineage.children) {
    assert.match(child.contextKey, /^[a-f0-9]{64}$/u);
  }
  const workerKeys = result.sessionLineage.children
    .filter(({ role }) => role === "worker")
    .map(({ contextKey }) => contextKey);
  const reviewerKeys = result.sessionLineage.children
    .filter(({ role }) => role === "reviewer")
    .map(({ contextKey }) => contextKey);
  assert.equal(new Set(workerKeys).size, 3);
  assert.equal(new Set(reviewerKeys).size, 2);
  for (const call of [...fixture.calls.worker, ...fixture.calls.reviewer]) {
    assertStrictSchema(call.schema);
  }
  const bootstrapSchema = fixture.calls.worker[1].schema;
  const readySchema = bootstrapSchema.properties.result.anyOf[0];
  assert.equal(readySchema.properties.summary.maxLength, 20_000);
  assert.equal(
    readySchema.properties.requiredChecks.maxItems,
    MAX_BOOTSTRAP_ITEMS,
  );
  assert.equal(
    readySchema.properties.requiredChecks.items.properties.command.maxLength,
    4_000,
  );
  assert.equal(
    new RegExp(
      readySchema.properties.requiredChecks.items.properties.command.pattern,
      "u",
    ).test("npm test\nnode bypass.js"),
    false,
  );
  assert.equal(
    readySchema.properties.validationInfrastructure.maxItems,
    MAX_BOOTSTRAP_ITEMS,
  );
  const validationPathPattern = new RegExp(
    readySchema.properties.validationInfrastructure.items.pattern,
    "u",
  );
  assert.equal(validationPathPattern.test("config/checks.json"), true);
  assert.equal(validationPathPattern.test("config/"), false);
  assert.equal(validationPathPattern.test("./"), false);
  assert.equal(validationPathPattern.test("../outside.js"), true);
  assert.equal(
    FINALIZATION_SCHEMA.properties.requiredChecks.maxItems,
    MAX_VALIDATION_ITEMS,
  );
  assert.equal(
    FINALIZATION_SCHEMA.properties.validationInfrastructure.maxItems,
    MAX_VALIDATION_ITEMS,
  );
  assert.equal(
    FINALIZATION_SCHEMA.properties.checks.maxItems,
    MAX_VALIDATION_ITEMS,
  );
  for (const call of fixture.calls.worker.slice(0, 3)) {
    assert.equal(call.access, "read-only");
  }
  for (const call of fixture.calls.worker.filter(
    ({ access }) => access !== "local-commit",
  ).slice(3)) {
    assert.equal(call.access, "workspace-write");
  }
  assert.equal(fixture.calls.worker.at(-1).access, "local-commit");
  for (const call of fixture.calls.reviewer) {
    assert.equal(call.access, "read-only");
  }
  assert.match(fixture.artifacts.get("context/worker.md"), /Worker understands/u);
  assert.match(fixture.artifacts.get("context/reviewer.md"), /Reviewer understands/u);
  assert.match(fixture.artifacts.get("context/resolved.md"), /roles agree/u);
});

test("accepts the advertised maximum bootstrap inventory", async (t) => {
  const maximumSummary = "😀".repeat(20_000);
  const requiredChecks = Array.from({ length: MAX_BOOTSTRAP_ITEMS }, (_, index) => ({
    id: `C${index + 1}`,
    command: `node --test test/check-${index + 1}.test.js`,
  }));
  const validationInfrastructure = Array.from(
    { length: MAX_BOOTSTRAP_ITEMS },
    (_, index) => `test/check-${index + 1}.test.js`,
  );
  const ready = (role) => ({
    ...bootstrapReady(role),
    ...(role === "Worker" ? { summary: maximumSummary } : {}),
    requiredChecks,
    validationInfrastructure,
  });
  const stop = new Error("implementation turn reached");
  let implementationStarted = false;
  const fixture = await createFixture(t, {
    async prepareProject(projectPath) {
      await mkdir(join(projectPath, "test"));
      await Promise.all(
        validationInfrastructure.map((path) =>
          writeFile(join(projectPath, path), "// validation fixture\n"),
        ),
      );
    },
    reviewer: [ready("Reviewer")],
    worker: [clarificationReady(), ready("Worker"), reconciliationResolved()],
    onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("Implement the changes")
      ) {
        implementationStarted = true;
        throw stop;
      }
    },
  });

  await assert.rejects(fixture.run(), (cause) => cause === stop);

  assert.equal(implementationStarted, true);
});

test("persists and finalizes a disjoint maximum role-derived inventory", async (t) => {
  const roleInventory = (role) => ({
    requiredChecks: Array.from(
      { length: MAX_BOOTSTRAP_ITEMS },
      (_, index) => ({
        id: `C${index + 1}`,
        command: `node --test validation/${role}-${index + 1}.test.js`,
      }),
    ),
    validationInfrastructure: Array.from(
      { length: MAX_BOOTSTRAP_ITEMS },
      (_, index) => `validation/${role}-${index + 1}.test.js`,
    ),
  });
  const workerInventory = roleInventory("worker");
  const reviewerInventory = roleInventory("reviewer");
  const derivedCommands = [
    ...workerInventory.requiredChecks,
    ...reviewerInventory.requiredChecks,
  ].map(({ command }, index) => ({ id: `C${index + 1}`, command }));
  const derivedPaths = [
    ...workerInventory.validationInfrastructure,
    ...reviewerInventory.validationInfrastructure,
  ];
  const fixture = await createFixture(t, {
    async prepareProject(projectPath) {
      await mkdir(join(projectPath, "validation"));
      await Promise.all(
        derivedPaths.map((path) =>
          writeFile(join(projectPath, path), `// ${path}\n`),
        ),
      );
    },
    reviewer: [
      { ...bootstrapReady("Reviewer"), ...reviewerInventory },
    ],
    worker: [
      clarificationReady(),
      { ...bootstrapReady("Worker"), ...workerInventory },
      reconciliationResolved(),
    ],
    workWorker: [
      implementationCompleted(),
      {
        ...finalizationPassed(),
        requiredChecks: derivedCommands,
        validationInfrastructure: derivedPaths,
        checks: derivedCommands.map(({ id, command }) => ({
          checkId: id,
          command,
          status: "PASS",
          evidence: ["The derived inventory check passed."],
        })),
      },
    ],
  });

  const completed = await fixture.run();
  const state = completed.pipelineState;

  assert.equal(state.workerValidation.requiredChecks.length, MAX_BOOTSTRAP_ITEMS);
  assert.equal(
    state.reviewerValidation.validationInfrastructure.length,
    MAX_BOOTSTRAP_ITEMS,
  );
  assert.equal(state.requiredChecks.length, MAX_VALIDATION_ITEMS);
  assert.equal(state.validationInfrastructure.length, MAX_VALIDATION_ITEMS);
  assert.equal(
    state.finalizationResult.requiredChecks.length,
    MAX_VALIDATION_ITEMS,
  );
  assert.equal(state.finalizationResult.checks.length, MAX_VALIDATION_ITEMS);
  assert.equal(
    state.validationInfrastructureFingerprint,
    hash(JSON.stringify(derivedPaths.map((path) => [path, `// ${path}\n`]))),
  );
  assert.equal(
    state.finalizationResult.validationInfrastructureFingerprint,
    state.validationInfrastructureFingerprint,
  );
});

test("pauses deterministically when a bootstrap inventory exceeds capacity", async (t) => {
  for (const capacityField of [
    "requiredChecks",
    "validationInfrastructure",
  ]) {
    await t.test(capacityField, async (t) => {
      const fixture = await createFixture(t, {
        worker: [
          clarificationReady(),
          bootstrapCapacityExhausted(capacityField),
        ],
      });

      const paused = await fixture.run();
      const projected = planExecutionPipeline.projections.pause(paused);

      assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
      assert.deepEqual(paused.pipelineState.bootstrapCorrections, []);
      assert.equal(fixture.calls.worker.length, 2);
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
  }
});

test("derives one stable complete inventory from independent role evidence", async (t) => {
  const workerPath = "validation/worker.js";
  const reviewerPath = "validation/reviewer.js";
  const worker = {
    ...bootstrapReady("Worker"),
    requiredChecks: [
      { id: "C7", command: "npm test" },
      { id: "C2", command: "npm run lint" },
    ],
    validationInfrastructure: ["package.json", workerPath],
  };
  const reviewer = {
    ...bootstrapReady("Reviewer"),
    requiredChecks: [
      { id: "C1", command: "npm test" },
      { id: "C7", command: "npm run docs" },
    ],
    validationInfrastructure: ["package.json", reviewerPath],
  };
  const stop = new Error("implementation turn reached");
  const fixture = await createFixture(t, {
    async prepareProject(projectPath) {
      await mkdir(join(projectPath, "validation"));
      await Promise.all([
        writeFile(join(projectPath, workerPath), "// worker validation\n"),
        writeFile(join(projectPath, reviewerPath), "// reviewer validation\n"),
      ]);
    },
    reviewer: [reviewer],
    worker: [clarificationReady(), worker, reconciliationResolved()],
    onRoleRun(role, request) {
      if (role === "worker" && request.prompt.includes("Implement the changes")) {
        throw stop;
      }
    },
  });

  await assert.rejects(fixture.run(), (cause) => cause === stop);
  assert.deepEqual(fixture.currentRun.pipelineState.requiredChecks, [
    { id: "C1", command: "npm test" },
    { id: "C2", command: "npm run lint" },
    { id: "C3", command: "npm run docs" },
  ]);
  assert.deepEqual(fixture.currentRun.pipelineState.validationInfrastructure, [
    "package.json",
    workerPath,
    reviewerPath,
  ]);
});

test("corrects staging-dependent bootstrap checks before implementation", async (t) => {
  const unsafeCommand = "git add -A && git diff --cached --check";
  const unsafeBootstrap = {
    ...bootstrapReady("Worker"),
    summary: "Worker incorrectly requires a staged handoff.",
    requiredChecks: [{ id: "C1", command: unsafeCommand }],
  };
  const fixture = await createFixture(t, {
    worker: [
      clarificationReady(),
      unsafeBootstrap,
      bootstrapReady("Corrected Worker"),
      reconciliationResolved(),
    ],
    onRoleRun(role, request) {
      if (role === "worker" && request.prompt.includes("Implement the changes")) {
        assert.doesNotMatch(request.prompt, /Established required-check inventory/u);
        assert.doesNotMatch(request.prompt, new RegExp(unsafeCommand, "u"));
      }
    },
  });

  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.deepEqual(completed.pipelineState.bootstrapCorrections, [
    {
      attempt: 1,
      role: "worker",
      phase: "bootstrap",
      contract: "bootstrap",
      field: "requiredChecks[0].command",
      constraint: "staging-independent-validation-command",
    },
  ]);
  const correctionCall = fixture.calls.worker.find(({ prompt }) =>
    prompt.includes("Correction diagnostic"),
  );
  assert.ok(correctionCall);
  assert.doesNotMatch(correctionCall.prompt, new RegExp(unsafeCommand, "u"));
});

test("fails closed when corrected bootstrap checks still depend on staging", async (t) => {
  const unsafeBootstrap = {
    ...bootstrapReady("Worker"),
    requiredChecks: [{ id: "C1", command: "git diff --exit-code" }],
  };
  const fixture = await createFixture(t, {
    worker: [clarificationReady(), unsafeBootstrap, unsafeBootstrap],
  });

  await assert.rejects(
    fixture.run(),
    (cause) =>
      cause.code === "ERR_INVALID_PLAN_EXECUTION_OUTPUT" &&
      cause.diagnostic?.constraint ===
        "staging-independent-validation-command",
  );
  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
  assert.equal(fixture.currentRun.pipelineState.bootstrapCorrections.length, 1);
});

test("persists a forbidden-delegation class for a terminal bootstrap failure", async (
  t,
) => {
  const sensitiveMarker = "DO_NOT_PERSIST_TERMINAL_TURN_DATA";
  const fixture = await createFixture(t, {
    onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("Provide a concise bootstrap summary")
      ) {
        const error = new Error(sensitiveMarker);
        error.code = "ERR_CODEX_ISOLATION";
        error.diagnosticClass = "operation_multi_agent";
        error.nativeResponse = { message: sensitiveMarker };
        error.prompt = sensitiveMarker;
        error.transcript = sensitiveMarker;
        throw error;
      }
    },
  });

  await assert.rejects(
    fixture.run(),
    (cause) => cause.code === "ERR_CODEX_ISOLATION",
  );

  assert.deepEqual(fixture.currentRun.pause, {
    reason: "internal_failure",
    code: "ERR_CODEX_ISOLATION",
    diagnosticClass: "operation_multi_agent",
  });
  const failureActivity = fixture.transitions.find(
    ({ options }) => options.activity?.kind === "failed",
  )?.options.activity;
  assert.match(failureActivity.message, /operation_multi_agent/u);
  assert.doesNotMatch(JSON.stringify(fixture.currentRun), /DO_NOT_PERSIST/u);
  assert.doesNotMatch(JSON.stringify(fixture.transitions), /DO_NOT_PERSIST/u);
});

test(
  "corrects a classified adapter structured-output failure without retaining provider text",
  async (t) => {
    const sensitiveMarker = "DO_NOT_PERSIST_CLASSIFIED_OUTPUT_FAILURE";
    let rejected = false;
    const fixture = await createFixture(t, {
      onRoleRun(role, request) {
        if (
          role === "worker" &&
          request.prompt.includes("Provide a concise bootstrap summary") &&
          !rejected
        ) {
          rejected = true;
          const error = new Error(sensitiveMarker);
          error.code = "ERR_TEST_ADAPTER_OUTPUT";
          error.failureClass = "structured-output";
          error.nativeResponse = { message: sensitiveMarker };
          error.stderr = sensitiveMarker;
          throw error;
        }
      },
    });

    const completed = await fixture.run();

    assert.equal(completed.pipelineState.workflowState, "DONE");
    assert.deepEqual(completed.pipelineState.bootstrapCorrections, [
      {
        attempt: 1,
        role: "worker",
        phase: "bootstrap",
        contract: "bootstrap",
        field: "result",
        constraint: "semantic-contract",
      },
    ]);
    assert.equal(completed.pipelineState.pendingBootstrapCorrection, null);
    assert.match(fixture.calls.worker[2].prompt, /Correction diagnostic/u);
    assert.equal(fixture.calls.worker[2].session, undefined);
    assert.doesNotMatch(JSON.stringify(fixture.currentRun), /DO_NOT_PERSIST/u);
    assert.doesNotMatch(JSON.stringify(fixture.transitions), /DO_NOT_PERSIST/u);
  },
);

test(
  "fails closed when a classified structured-output correction is also invalid",
  async (t) => {
    const sensitiveMarker = "DO_NOT_PERSIST_REPEATED_CLASSIFIED_OUTPUT";
    const fixture = await createFixture(t, {
      onRoleRun(role, request) {
        if (
          role === "worker" &&
          request.prompt.includes("Provide a concise bootstrap summary")
        ) {
          const error = new Error(sensitiveMarker);
          error.code = "ERR_TEST_ADAPTER_OUTPUT";
          error.failureClass = "structured-output";
          error.nativeResponse = { message: sensitiveMarker };
          throw error;
        }
      },
    });

    await assert.rejects(
      fixture.run(),
      (cause) => cause.code === "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
    );

    assert.deepEqual(fixture.currentRun.pause.diagnostic, {
      role: "worker",
      phase: "bootstrap",
      contract: "bootstrap",
      field: "result",
      constraint: "semantic-contract",
    });
    assert.equal(
      fixture.currentRun.pipelineState.bootstrapCorrections.length,
      1,
    );
    assert.equal(
      fixture.calls.worker.filter(({ prompt }) =>
        prompt.includes("Provide a concise bootstrap summary"),
      ).length,
      2,
    );
    assert.doesNotMatch(JSON.stringify(fixture.currentRun), /DO_NOT_PERSIST/u);
    assert.doesNotMatch(JSON.stringify(fixture.transitions), /DO_NOT_PERSIST/u);
  },
);

test("corrects one invalid Worker bootstrap result without retaining raw values", async (t) => {
  const sensitiveField = "DO_NOT_PERSIST_THIS_FIELD";
  const sensitiveValue = "DO_NOT_PERSIST_THIS_VALUE";
  const fixture = await createFixture(t, {
    worker: [
      clarificationReady(),
      {
        ...bootstrapReady("Worker"),
        requiredChecks: [
          {
            ...REQUIRED_CHECKS[0],
            [sensitiveField]: sensitiveValue,
          },
        ],
      },
      bootstrapReady("Corrected Worker"),
      reconciliationResolved(),
    ],
  });

  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.deepEqual(completed.pipelineState.bootstrapCorrections, [
    {
      attempt: 1,
      role: "worker",
      phase: "bootstrap",
      contract: "bootstrap",
      field: "requiredChecks[0]",
      constraint: "exact-field-set",
    },
  ]);
  const correctionActivity = fixture.transitions.find(
    ({ options }) => options.activity?.kind === "bootstrap-correction",
  )?.options.activity;
  assert.match(
    correctionActivity.message,
    /bootstrap field requiredChecks\[0\]/u,
  );
  assert.match(
    fixture.calls.worker[2].prompt,
    /Make one read-only correction/u,
  );
  assert.doesNotMatch(JSON.stringify(fixture.currentRun), /DO_NOT_PERSIST/u);
  assert.doesNotMatch(JSON.stringify(correctionActivity), /DO_NOT_PERSIST/u);
  assert.doesNotMatch(JSON.stringify(fixture.transitions), /DO_NOT_PERSIST/u);
});

test("gives the independent Reviewer one bounded bootstrap correction", async (t) => {
  const sensitiveSummary = "DO_NOT_PERSIST_REVIEWER_SUMMARY".repeat(1_000);
  const fixture = await createFixture(t, {
    reviewer: [
      { ...bootstrapReady("Reviewer"), summary: sensitiveSummary },
      bootstrapReady("Corrected Reviewer"),
    ],
  });

  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.deepEqual(completed.pipelineState.bootstrapCorrections, [
    {
      attempt: 1,
      role: "reviewer",
      phase: "bootstrap",
      contract: "bootstrap",
      field: "summary",
      constraint: "concise-markdown-up-to-20000-characters",
    },
  ]);
  assert.match(fixture.calls.reviewer[1].prompt, /Correction diagnostic/u);
  assert.doesNotMatch(JSON.stringify(fixture.transitions), /DO_NOT_PERSIST/u);
});

test("corrects a symlink alias and preserves the canonical role-only path", async (t) => {
  const aliasPath = ".claude/skills/finalization/SKILL.md";
  const canonicalPath = ".agents/skills/finalization/SKILL.md";
  const validationInfrastructure = [canonicalPath, ...VALIDATION_INFRASTRUCTURE];
  const fixture = await createFixture(t, {
    async prepareProject(projectPath) {
      await symlink(".agents", join(projectPath, ".claude"));
    },
    worker: [
      clarificationReady(),
      {
        ...bootstrapReady("Worker"),
        validationInfrastructure: [aliasPath],
      },
      {
        ...bootstrapReady("Corrected Worker"),
        validationInfrastructure: [canonicalPath],
      },
      reconciliationResolved(),
    ],
    reviewer: [bootstrapReady("Reviewer")],
    workWorker: [
      implementationCompleted(),
      { ...finalizationPassed(), validationInfrastructure },
    ],
  });

  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.deepEqual(completed.pipelineState.bootstrapCorrections, [
    {
      attempt: 1,
      role: "worker",
      phase: "bootstrap",
      contract: "bootstrap",
      field: "validationInfrastructure[0]",
      constraint: "existing-canonical-repository-file",
    },
  ]);
  assert.match(fixture.calls.worker[2].prompt, /validationInfrastructure\[0\]/u);
  assert.deepEqual(
    completed.pipelineState.validationInfrastructure,
    validationInfrastructure,
  );
  assert.doesNotMatch(
    JSON.stringify(fixture.currentRun),
    /ERR_UNSAFE_REPOSITORY_PATH/u,
  );
});

test("corrects missing and directory validation-infrastructure paths", async (t) => {
  for (const kind of ["missing", "directory"]) {
    await t.test(kind, async (t) => {
      const invalidPath = `validation/${kind}`;
      const fixture = await createFixture(t, {
        async prepareProject(projectPath) {
          if (kind === "directory") {
            await mkdir(join(projectPath, invalidPath), { recursive: true });
          }
        },
        worker: [
          clarificationReady(),
          {
            ...bootstrapReady("Worker"),
            validationInfrastructure: [invalidPath],
          },
          bootstrapReady("Corrected Worker"),
          reconciliationResolved(),
        ],
      });

      const completed = await fixture.run();

      assert.equal(completed.pipelineState.workflowState, "DONE");
      assert.deepEqual(completed.pipelineState.bootstrapCorrections, [
        {
          attempt: 1,
          role: "worker",
          phase: "bootstrap",
          contract: "bootstrap",
          field: "validationInfrastructure[0]",
          constraint: "existing-canonical-repository-file",
        },
      ]);
    });
  }
});

test("reconstructs a persisted correction after a harmless provider interruption", async (t) => {
  let interrupted = false;
  const invalid = {
    ...bootstrapReady("Worker"),
    requiredChecks: [
      { ...REQUIRED_CHECKS[0], unexpected: "DO_NOT_PERSIST_REJECTED_VALUE" },
    ],
  };
  const fixture = await createFixture(t, {
    onRoleRun(role, request) {
      if (
        role === "worker" &&
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
    worker: [
      clarificationReady(),
      invalid,
      bootstrapReady("Corrected Worker"),
      reconciliationResolved(),
    ],
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pause.resumeState, "BOOTSTRAP");
  assert.equal(paused.pipelineState.bootstrapCorrections.length, 1);
  assert.deepEqual(
    paused.pipelineState.pendingBootstrapCorrection,
    paused.pipelineState.bootstrapCorrections[0],
  );

  const completed = await fixture.run();
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.pipelineState.bootstrapCorrections.length, 1);
  assert.equal(completed.pipelineState.pendingBootstrapCorrection, null);
  assert.match(fixture.calls.worker[3].prompt, /Correction diagnostic/u);
  assert.doesNotMatch(JSON.stringify(fixture.transitions), /DO_NOT_PERSIST/u);
});

test("fails closed after a repeated invalid bootstrap result", async (t) => {
  const fixture = await createFixture(t, {
    worker: [
      clarificationReady(),
      "DO_NOT_PERSIST_RAW_OUTPUT",
      "DO_NOT_PERSIST_REPEATED_OUTPUT",
    ],
  });

  await assert.rejects(
    fixture.run(),
    (cause) => cause.code === "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
  );

  assert.deepEqual(fixture.currentRun.pause.diagnostic, {
    role: "worker",
    phase: "bootstrap",
    contract: "bootstrap",
    field: "result",
    constraint: "single-object-wrapper",
  });
  assert.deepEqual(fixture.currentRun.pipelineState.bootstrapCorrections, [
    {
      attempt: 1,
      ...fixture.currentRun.pause.diagnostic,
    },
  ]);
  assert.doesNotMatch(JSON.stringify(fixture.transitions), /DO_NOT_PERSIST/u);
});

test("corrects a missing structured bootstrap response once", async (t) => {
  const fixture = await createFixture(t, {
    worker: [
      clarificationReady(),
      MISSING_BOOTSTRAP_RESPONSE,
      bootstrapReady("Corrected Worker"),
      reconciliationResolved(),
    ],
  });

  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.deepEqual(completed.pipelineState.bootstrapCorrections, [
    {
      attempt: 1,
      role: "worker",
      phase: "bootstrap",
      contract: "bootstrap",
      field: "result",
      constraint: "semantic-contract",
    },
  ]);
});

test("does not retain bootstrap serialization errors in the workflow cause", async (t) => {
  const sensitiveCause = "DO_NOT_RETAIN_WORKFLOW_SERIALIZATION_CAUSE";
  const unserializable = () => ({
    ...bootstrapReady("Worker"),
    toJSON() {
      throw new Error(sensitiveCause);
    },
  });
  const fixture = await createFixture(t, {
    worker: [
      clarificationReady(),
      unserializable(),
      unserializable(),
    ],
  });

  await assert.rejects(fixture.run(), (cause) => {
    assert.equal(cause.code, "ERR_INVALID_PLAN_EXECUTION_OUTPUT");
    assert.equal(Object.hasOwn(cause, "cause"), false);
    assert.doesNotMatch(String(cause), /DO_NOT_RETAIN/u);
    return true;
  });

  assert.deepEqual(fixture.currentRun.pause.diagnostic, {
    role: "worker",
    phase: "bootstrap",
    contract: "bootstrap",
    field: "result",
    constraint: "serializable-json",
  });
  assert.doesNotMatch(JSON.stringify(fixture.transitions), /DO_NOT_RETAIN/u);
});

test("redacts precise reconciliation and arbitration diagnostics", async (t) => {
  const sensitiveSummary = "DO_NOT_PERSIST_SUMMARY".repeat(1_000);
  const cases = [
    {
      name: "reconciliation",
      fixture: {
        worker: [
          clarificationReady(),
          bootstrapReady("Worker"),
          { ...reconciliationResolved(), summary: sensitiveSummary },
          reconciliationResolved(),
        ],
      },
      diagnostic: {
        role: "worker",
        phase: "bootstrap",
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
        worker: [
          clarificationReady(),
          bootstrapReady("Worker"),
          reconciliationDisagreement(),
        ],
      },
      diagnostic: {
        role: "arbiter",
        phase: "bootstrap",
        contract: "bootstrap-arbitration",
        field: "summary",
        constraint: "concise-markdown-up-to-20000-characters",
      },
    },
  ];

  for (const testCase of cases) {
    await t.test(testCase.name, async (t) => {
      const fixture = await createFixture(t, testCase.fixture);

      const completed = await fixture.run();

      assert.equal(completed.pipelineState.workflowState, "DONE");
      assert.deepEqual(completed.pipelineState.bootstrapCorrections, [
        { attempt: 1, ...testCase.diagnostic },
      ]);
      assert.doesNotMatch(
        JSON.stringify(fixture.transitions),
        /DO_NOT_PERSIST/u,
      );
    });
  }
});

test("uses and persists a configured runner artifact root", async (t) => {
  const fixture = await createFixture(t, {
    artifactRoot: "IGNORED_RUNS",
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.artifactRoot, "IGNORED_RUNS");
  assert.equal(
    result.pipelineState.clarificationPath,
    join(
      fixture.projectPath,
      "IGNORED_RUNS",
      "agent-runner",
      "run-1",
      "clarifications.md",
    ),
  );
});

test("runs the dedicated finalization gate without skill guidance", async (t) => {
  const fixture = await createFixture(t, {
    workWorker: [implementationCompleted(), finalizationPassed("")],
  });

  const result = await fixture.run({ finalization: "none" });

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.settings.finalization, "none");
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

test("corrects the production git status finalization inventory into an environment pause", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [],
    workWorker: [
      implementationCompleted(),
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
  assert.match(correction.contentFingerprint, /^[a-f0-9]{64}$/u);
  assert.deepEqual(correction, {
    attempt: 1,
    step: 1,
    guidance: "resolved",
    contentFingerprint: correction.contentFingerprint,
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
  assert.match(finalizationCalls[1].recoveryPrompt, /Current planned commit/u);
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
  for (const persisted of [
    fixture.currentRun,
    fixture.transitions,
    correctionActivity,
  ]) {
    assert.doesNotMatch(JSON.stringify(persisted), /DO_NOT_PERSIST/u);
  }
});

test("routes corrected finalization PASS and FAIL through the existing gate", async (t) => {
  await t.test("PASS", async (t) => {
    const fixture = await createFixture(t, {
      workWorker: [
        implementationCompleted(),
        invalidProductionFinalization(),
        finalizationPassed(),
      ],
    });

    const completed = await fixture.run();

    assert.equal(completed.pipelineState.workflowState, "DONE");
    assert.equal(completed.pipelineState.finalizationResult.status, "PASS");
    assert.equal(completed.pipelineState.finalizationCorrection, null);
    assert.equal(
      fixture.transitions.filter(
        ({ options }) => options.activity?.kind === "finalization-correction",
      ).length,
      1,
    );
  });

  await t.test("FAIL", async (t) => {
    const fixture = await createFixture(t, {
      workWorker: [
        implementationCompleted(),
        invalidProductionFinalization(),
        finalizationFailed("F1"),
        resolution({ id: "F1", decision: "FIX" }),
        finalizationPassed(),
      ],
    });

    const completed = await fixture.run();

    assert.equal(completed.pipelineState.workflowState, "DONE");
    assert.ok(
      fixture.transitions.some(
        ({ patch }) =>
          patch?.pipelineState?.workflowState === "RESOLVE_FINDINGS" &&
          patch.pipelineState.finalizationResult?.status === "FAIL",
      ),
    );
    assert.equal(completed.pipelineState.finalizationResult.status, "PASS");
  });
});

test("reconstructs finalization correction before and during interruption", async (t) => {
  await t.test("before correction", async (t) => {
    const processLoss = new Error("Process stopped before correction.");
    const fixture = await createFixture(t, {
      workWorker: [
        implementationCompleted(),
        finalizationUnavailable("SKILL_INVALID"),
        invalidProductionFinalization(),
        finalizationPassed(""),
      ],
    });
    const transition = fixture.runtime.transition;
    const startAgentTurn = fixture.runtime.startAgentTurn;
    let stopped = false;
    fixture.runtime.transition = async (patch, options) => {
      if (stopped) {
        throw processLoss;
      }
      const next = await transition(patch, options);
      if (options.activity?.kind === "finalization-correction") {
        stopped = true;
      }
      return next;
    };
    fixture.runtime.startAgentTurn = async (turn) => {
      if (stopped) {
        throw processLoss;
      }
      return startAgentTurn(turn);
    };

    await assert.rejects(fixture.run(), (error) => error === processLoss);
    assert.equal(fixture.currentRun.activeTurn, null);
    assert.notEqual(
      fixture.currentRun.pipelineState.pendingFinalizationCorrection,
      null,
    );
    assert.equal(
      fixture.currentRun.pipelineState.pendingFinalizationCorrection.guidance,
      "fallback",
    );

    stopped = false;
    fixture.runtime.transition = transition;
    fixture.runtime.startAgentTurn = startAgentTurn;
    const completed = await fixture.run();

    assert.equal(completed.pipelineState.workflowState, "DONE");
    const correctionCall = fixture.calls.worker.find(
      ({ prompt }) => prompt.includes("one read-only correction"),
    );
    assert.equal(correctionCall.access, "read-only");
    assert.match(
      correctionCall.prompt,
      /No finalization skill guidance is available/u,
    );
    assert.match(correctionCall.recoveryPrompt, /Resolved bootstrap context/u);
    assert.equal(correctionCall.session, undefined);
  });

  await t.test("during correction", async (t) => {
    const processLoss = new Error("Process stopped during correction.");
    let interruptionTriggered = false;
    let processStopped = false;
    const fixture = await createFixture(t, {
      onRoleRun(role, request) {
        if (
          role === "worker" &&
          request.prompt.includes("one read-only correction") &&
          !interruptionTriggered
        ) {
          interruptionTriggered = true;
          processStopped = true;
          throw processLoss;
        }
      },
      workWorker: [
        implementationCompleted(),
        invalidProductionFinalization(),
        finalizationPassed(),
      ],
    });
    const transition = fixture.runtime.transition;
    const finishAgentTurn = fixture.runtime.finishAgentTurn;
    fixture.runtime.transition = async (patch, options) => {
      if (processStopped) {
        throw processLoss;
      }
      return transition(patch, options);
    };
    fixture.runtime.finishAgentTurn = async (turn) => {
      if (processStopped) {
        throw processLoss;
      }
      return finishAgentTurn(turn);
    };

    await assert.rejects(fixture.run(), (error) => error === processLoss);
    assert.deepEqual(fixture.currentRun.activeTurn, {
      role: "worker",
      phase: "finalize",
    });
    assert.notEqual(
      fixture.currentRun.pipelineState.pendingFinalizationCorrection,
      null,
    );
    const reconcileInterrupted = fixture.runtime.git.reconcileInterrupted;
    const reconciliation = [];
    fixture.runtime.git.reconcileInterrupted = (snapshot, options) => {
      reconciliation.push(options);
      return reconcileInterrupted.call(fixture.runtime.git, snapshot, options);
    };
    processStopped = false;
    fixture.runtime.transition = transition;
    fixture.runtime.finishAgentTurn = finishAgentTurn;

    const completed = await fixture.run();

    assert.equal(completed.pipelineState.workflowState, "DONE");
    assert.deepEqual(reconciliation, [{ allowWorkspaceChanges: false }]);
    const correctionCalls = fixture.calls.worker.filter(({ prompt }) =>
      prompt.includes("one read-only correction"),
    );
    assert.equal(correctionCalls.length, 2);
    assert.ok(correctionCalls.every(({ session }) => session === undefined));
  });
});

test("fails closed after a repeated invalid finalization result", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [],
    workWorker: [
      implementationCompleted(),
      invalidProductionFinalization(),
      invalidProductionFinalization(),
    ],
  });

  await assert.rejects(
    fixture.run(),
    (error) => error.code === "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
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

test("scopes finalization correction attempts to the current commit step", async (t) => {
  const plan = `${PLAN}\n\n## Commit 2: fix(test): finish behavior\n\nFinish the requested behavior.`;
  const fixture = await createFixture(t, {
    plan,
    workReviewer: [reviewApproved(), reviewApproved()],
    workWorker: [
      implementationCompleted(),
      invalidProductionFinalization(),
      finalizationPassed(),
      implementationCompleted(),
      invalidProductionFinalization(),
      finalizationPassed(),
    ],
  });

  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  const corrections = fixture.transitions
    .filter(
      ({ options }) => options.activity?.kind === "finalization-correction",
    )
    .map(({ patch }) => patch.pipelineState.finalizationCorrection.step);
  assert.deepEqual(corrections, [1, 2]);
});

test("corrects, blocks, and completes runner-trusted validation", async (t) => {
  const trustedValidation = trustedValidationSnapshot();
  const requiredChecks = [
    ...REQUIRED_CHECKS,
    { id: "C2", command: trustedValidation.commands[0].command },
  ];
  const bootstrap = (role) => ({
    ...bootstrapReady(role),
    requiredChecks,
  });
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
    trustedValidation,
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      bootstrap("Worker"),
      reconciliationResolved(),
    ],
    reviewer: [bootstrap("Reviewer")],
    workWorker: [implementationCompleted(), finalization, finalization],
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
            ? "The selected host service is unavailable."
            : "The temporary runner service check passed.",
        ],
        ...options.bindings,
      };
    },
  });

  const paused = await fixture.run({ trustedChecks: ["service-check"] });

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "environment_blocked");
  assert.equal(paused.pause.code, "ERR_TRUSTED_VALIDATION_BLOCKED");
  assert.equal(paused.pause.resumeState, "FINALIZE");
  assert.equal(paused.pipelineState.finalizationResult, null);
  assert.deepEqual(paused.pipelineState.bootstrapCorrections, [
    {
      attempt: 1,
      role: "worker",
      phase: "bootstrap",
      contract: "bootstrap",
      field: "requiredChecks",
      constraint: "includes-runner-trusted-commands",
    },
  ]);

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

test("turns a runner-trusted check failure into a bounded finalization issue", async (t) => {
  const trustedValidation = trustedValidationSnapshot();
  const requiredChecks = [
    ...REQUIRED_CHECKS,
    { id: "C2", command: trustedValidation.commands[0].command },
  ];
  const captured = new Error("captured trusted validation failure");
  let failedState;
  const fixture = await createFixture(t, {
    trustedValidation,
    worker: [
      clarificationReady(),
      { ...bootstrapReady("Worker"), requiredChecks },
      reconciliationResolved(),
    ],
    reviewer: [{ ...bootstrapReady("Reviewer"), requiredChecks }],
    workWorker: [
      implementationCompleted(),
      {
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
      },
    ],
    onTrustedValidation(options) {
      return {
        status: "FAIL",
        commandIdentity: options.commandIdentity,
        exitCode: 7,
        signal: null,
        timedOut: false,
        evidence: ["Runner-trusted command service-check exited with code 7."],
        ...options.bindings,
      };
    },
    onTransition(run) {
      if (run.pipelineState.workflowState === "RESOLVE_FINDINGS") {
        failedState = run.pipelineState;
        throw captured;
      }
    },
  });

  await assert.rejects(
    fixture.run({ trustedChecks: ["service-check"] }),
    (cause) => cause === captured,
  );

  assert.equal(failedState.finalizationResult.status, "FAIL");
  assert.equal(failedState.finalizationResult.checks[1].executor, "runner");
  assert.deepEqual(failedState.finalizationResult.issues, [
    {
      id: "F1",
      command: trustedValidation.commands[0].command,
      problem: "A runner-trusted validation command failed.",
      evidence: ["Runner-trusted command service-check exited with code 7."],
    },
  ]);
});

test("rejects trusted validation binding drift and repository mutation", async (t) => {
  for (const [name, code] of [
    ["binding drift", "ERR_TRUSTED_VALIDATION_BINDING_CHANGED"],
    ["repository mutation", "ERR_TRUSTED_VALIDATION_MUTATED_REPOSITORY"],
    [
      "unterminated process tree",
      "ERR_TRUSTED_VALIDATION_PROCESS_TREE_ACTIVE",
    ],
  ]) {
    await t.test(name, async (t) => {
      const trustedValidation = trustedValidationSnapshot();
      const requiredChecks = [
        ...REQUIRED_CHECKS,
        { id: "C2", command: trustedValidation.commands[0].command },
      ];
      const fixture = await createFixture(t, {
        trustedValidation,
        worker: [
          clarificationReady(),
          { ...bootstrapReady("Worker"), requiredChecks },
          reconciliationResolved(),
        ],
        reviewer: [{ ...bootstrapReady("Reviewer"), requiredChecks }],
        workWorker: [
          implementationCompleted(),
          {
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
          },
        ],
        onTrustedValidation() {
          const error = new Error(`Trusted executor ${name}.`);
          error.code = code;
          throw error;
        },
      });

      const result = await fixture.run({
        trustedChecks: ["service-check"],
      });

      assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
      assert.equal(result.pause.reason, "unsafe_git_state");
      assert.equal(result.pause.code, code);
    });
  }
});

test("rejects ignored validation-infrastructure drift after trusted execution", async (t) => {
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
      await writeFile(
        join(projectPath, infrastructurePath),
        '{"version":1}\n',
      );
    },
    trustedValidation,
    worker: [
      clarificationReady(),
      {
        ...bootstrapReady("Worker"),
        requiredChecks,
        validationInfrastructure,
      },
      reconciliationResolved(),
    ],
    reviewer: [
      {
        ...bootstrapReady("Reviewer"),
        requiredChecks,
        validationInfrastructure,
      },
    ],
    workWorker: [
      implementationCompleted(),
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

  const result = await fixture.run({ trustedChecks: ["service-check"] });

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "unsafe_git_state");
  assert.equal(
    result.pause.code,
    "ERR_TRUSTED_VALIDATION_INFRASTRUCTURE_CHANGED",
  );
  assert.equal(result.pipelineState.finalizationResult, null);
});

test("falls back when automatic finalization discovery finds no skill", async (t) => {
  const fixture = await createFixture(t, {
    finalizationSkill: false,
    workWorker: [implementationCompleted(), finalizationPassed("")],
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
  const fixture = await createFixture(t);

  const result = await fixture.run({ finalization: skillPath });

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.settings.finalization, skillPath);
  assert.match(
    fixture.calls.worker.find(({ prompt }) =>
      prompt.includes("Run the complete project finalization procedure"),
    ).prompt,
    /explicitly configured/u,
  );
});

test("defers skill-guided commit preparation to the constrained commit turn", async (t) => {
  const skillPath = ".agents/skills/finalization/SKILL.md";
  const fixture = await createFixture(t, {
    async prepareProject(projectPath) {
      await writeFile(
        join(projectPath, skillPath),
        `---
name: finalization
description: Test validation and handoff.
---

Run tests and formatting, then stage changes, inspect the cached diff, and draft a commit message.
`,
      );
    },
    workWorker: [
      implementationCompleted(),
      finalizationFailed("F1"),
      resolution({ id: "F1", decision: "FIX" }),
      finalizationPassed(),
    ],
  });

  const result = await fixture.run({ finalization: skillPath });

  assert.equal(result.pipelineState.workflowState, "DONE");
  const implementationCall = fixture.calls.worker.find(({ prompt }) =>
    prompt.includes("Implement the changes"),
  );
  const resolutionCall = fixture.calls.worker.find(({ prompt }) =>
    prompt.includes("For each finding below"),
  );
  const finalizationCalls = fixture.calls.worker.filter(({ prompt }) =>
    prompt.includes("Run the complete project finalization procedure"),
  );
  const commitCall = fixture.calls.worker.find(
    ({ access }) => access === "local-commit",
  );
  assert.ok(implementationCall);
  assert.ok(resolutionCall);
  assert.equal(finalizationCalls.length, 2);
  assert.ok(commitCall);
  for (const call of [implementationCall, resolutionCall]) {
    assert.match(call.prompt, /Do not run the project finalization procedure/u);
    assert.match(call.prompt, /generic commit preparation/u);
    assert.match(call.prompt, /required-check inventory is input only/u);
    assert.doesNotMatch(call.prompt, /Established required-check inventory:/u);
  }
  for (const call of finalizationCalls) {
    assert.match(call.prompt, /Follow every substantive instruction/u);
    assert.match(call.prompt, /staged\/index-relative inspection/u);
    assert.match(call.prompt, /against HEAD or explicit trees/u);
    assert.match(call.prompt, /neither a validation blocker nor a skipped required check/u);
    assert.match(call.prompt, /constrained COMMIT executor alone runs git add -A/u);
  }
  assert.match(commitCall.prompt, /exact supplied subject/u);
  assert.match(commitCall.prompt, /constrained executor alone stages/u);
  assert.match(commitCall.prompt, /Authorized planned commit:\nfeat\(test\): add behavior/u);
});

test("pauses before invoking a missing explicit finalization skill", async (t) => {
  const fixture = await createFixture(t);

  const result = await fixture.run({
    finalization: "checks/finalization/SKILL.md",
  });

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "finalization_skill_missing");
  assert.equal(result.pause.resumeState, "FINALIZE");
  assert.equal(result.pause.skillPath, "checks/finalization/SKILL.md");
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
        workWorker: [
          implementationCompleted(),
          finalizationPassed(skillPath),
        ],
      });
      const skillDirectory = dirname(join(fixture.projectPath, skillPath));
      if (kind === "symlink-invalid") {
        const externalSkillDirectory = await mkdtemp(
          join(tmpdir(), "agent-runner-external-skill-"),
        );
        t.after(() =>
          rm(externalSkillDirectory, { recursive: true, force: true }),
        );
        await writeFile(
          join(externalSkillDirectory, "SKILL.md"),
          "---\nname: finalization\ndescription: External validation.\n---\n",
        );
        await mkdir(dirname(skillDirectory), { recursive: true });
        await symlink(externalSkillDirectory, skillDirectory, "dir");
      }

      const paused = await fixture.run({ finalization: skillPath });

      assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
      assert.equal(
        paused.pause.reason,
        kind === "missing"
          ? "finalization_skill_missing"
          : "finalization_skill_invalid",
      );
      assert.doesNotThrow(() =>
        planExecutionPipeline.validateResumeAction(paused, null),
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
      assert.equal(resumed.pipelineState.finalizationResult.skillPath, skillPath);
    });
  }
});

test("corrects a skill availability status without selected guidance", async (t) => {
  const fixture = await createFixture(t, {
    workWorker: [
      implementationCompleted(),
      { ...finalizationUnavailable("SKILL_MISSING"), skillPath: "" },
      finalizationPassed(""),
    ],
  });

  const completed = await fixture.run({ finalization: "none" });

  assert.equal(completed.pipelineState.workflowState, "DONE");
  const correction = fixture.transitions.find(
    ({ options }) => options.activity?.kind === "finalization-correction",
  ).patch.pipelineState.finalizationCorrection;
  assert.equal(correction.field, "status");
  assert.equal(correction.constraint, "selected-finalization-guidance");
});

test("normalizes legacy execution state to the default artifact root", () => {
  const legacySettings = { ...SETTINGS };
  delete legacySettings.finalization;
  const state = {
    ...createPlanExecutionState({ settings: SETTINGS }),
    settings: legacySettings,
  };
  delete state.artifactRoot;

  const normalized = normalizePipelineState(state);
  assert.equal(normalized.artifactRoot, "LOCAL_ARTIFACTS");
  assert.equal(normalized.settings.finalization, "auto");
});

test("accepts an unchanged proactive clarification and uses fresh role sessions", async (t) => {
  const fixture = await createFixture(t, {
    interactive: true,
    proactiveClarification: true,
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.proactiveClarificationComplete, true);
  assert.equal(await readFile(fixture.clarificationPath, "utf8"), "");
  assert.equal(fixture.calls.worker[0].session, undefined);
  assert.equal(fixture.calls.worker[1].session, undefined);
  assert.notEqual(
    result.sessionLineage.children[0].contextKey,
    result.sessionLineage.children[1].contextKey,
  );
  assert.equal(fixture.calls.reviewer[0].session, undefined);
  assert.equal(result.counters.clarificationRounds, 0);
});

test("pauses for clarification answers and resumes through the authorization", async (t) => {
  const fixture = await createFixture(t, {
    worker: [
      clarificationQuestions(),
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
    ],
  });

  const paused = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "clarification_answers_required");
  assert.equal(paused.counters.clarificationRounds, 1);
  await writeFile(
    fixture.clarificationPath,
    `${await readFile(fixture.clarificationPath, "utf8")}Use behavior A.\n`,
  );

  const resumed = await fixture.run();

  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.equal(resumed.pipelineState.pendingEdit, null);
  assert.equal(resumed.pipelineState.clarificationFrozen, true);
  assert.equal(fixture.calls.worker[1].session, undefined);
  assert.match(fixture.calls.worker[1].prompt, /Task \(/u);
  assert.notEqual(
    resumed.sessionLineage.children[0].contextKey,
    resumed.sessionLineage.children[1].contextKey,
  );
});

test("rejects malformed persisted structured input", async (t) => {
  const fixture = await createFixture(t, {
    worker: [clarificationQuestions()],
  });
  await fixture.run();
  fixture.currentRun.pause.inputRequest.questions[0].id = "q2";

  await assert.rejects(fixture.run(), /input request is invalid/u);
});

test("reconstructs an allowlisted failed Claude read-only turn", async (t) => {
  let interruptClarification = true;
  const fixture = await createFixture(t, {
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("Study the task, validated plan") &&
        interruptClarification
      ) {
        interruptClarification = false;
        const error = new Error("provider-native secret text");
        error.code = "ERR_CLAUDE_READ_ONLY_TURN_FAILED";
        error.recoverable = true;
        throw error;
      }
    },
  });

  const paused = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pause.code, "ERR_CLAUDE_READ_ONLY_TURN_FAILED");
  assert.equal(paused.pause.resumeState, "CLARIFY");
  assert.doesNotMatch(JSON.stringify(fixture.transitions), /provider-native/u);

  const resumed = await fixture.run();
  const resumedRequest = fixture.calls.worker[1];

  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.equal(resumedRequest.session, undefined);
  assert.equal(resumedRequest.prompt, resumedRequest.recoveryPrompt);
});

test("pauses before bootstrap when clarification requires a revised plan", async (t) => {
  const fixture = await createFixture(t, {
    reviewer: [],
    worker: [clarificationPlanRevision()],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "plan_revision_required");
  assert.match(result.pause.explanation, /conflicts with the validated plan/u);
  assert.equal(result.pipelineState.workerSummary, null);
  assert.equal(fixture.calls.reviewer.length, 0);
});

test("rejects an invalid plan before Git preflight or artifact creation", async (t) => {
  const fixture = await createFixture(t, {
    plan: "## Commit 2: invalid",
    reviewer: [],
    worker: [],
  });

  await assert.rejects(
    fixture.run(),
    (error) => error.code === "ERR_INVALID_EXECUTION_PLAN",
  );
  assert.equal(fixture.preflights.length, 0);
  assert.equal(fixture.calls.worker.length, 0);
  await assert.rejects(readFile(fixture.clarificationPath), { code: "ENOENT" });
  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
});

test("rejects an oversized plan before Git preflight or artifact creation", async (t) => {
  const fixture = await createFixture(t, {
    plan: "x".repeat(100_001),
    reviewer: [],
    worker: [],
  });

  await assert.rejects(
    fixture.run(),
    (error) =>
      error.code === "ERR_INVALID_EXECUTION_PLAN" &&
      /must not exceed/u.test(error.message),
  );
  assert.equal(fixture.preflights.length, 0);
  await assert.rejects(readFile(fixture.clarificationPath), { code: "ENOENT" });
  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
});

test("validates the next pipeline state before persisting it", async (t) => {
  const invalidHash = "invalid-hash";
  const fixture = await createFixture(t, {
    onFreeze(snapshot) {
      return { ...snapshot, hash: invalidHash };
    },
  });

  await assert.rejects(
    fixture.run(),
    (error) => error.code === "ERR_INVALID_PLAN_EXECUTION_STATE",
  );
  assert.equal(
    fixture.transitions.some(
      ({ patch }) => patch?.hashes?.executionClarifications === invalidHash,
    ),
    false,
  );
  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
});

test("requires a clean repository and an ignored execution transcript", async (t) => {
  await t.test("dirty repository", async (t) => {
    const fixture = await createFixture(t, { dirty: true });

    const result = await fixture.run();

    assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
    assert.equal(result.pause.reason, "unsafe_git_state");
    assert.equal(result.pipelineState.preflightComplete, false);
    assert.equal(fixture.calls.worker.length, 0);
  });

  await t.test("unignored transcript", async (t) => {
    const fixture = await createFixture(t, { clarificationIgnored: false });

    const result = await fixture.run();

    assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
    assert.equal(result.pause.reason, "local_artifacts_not_ignored");
    assert.equal(result.pipelineState.preflightComplete, false);
    await assert.rejects(readFile(fixture.clarificationPath), { code: "ENOENT" });
    assert.equal(fixture.calls.worker.length, 0);
  });
});

test("pauses when an accepted task input changes between bootstrap turns", async (t) => {
  let changed = false;
  const fixture = await createFixture(t, {
    onTransition: async (run) => {
      if (!changed && run.pipelineState.workerSummary !== null) {
        changed = true;
        await writeFile(join(run.taskPath, "task.md"), "Changed task.\n");
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "task_input_changed");
  assert.equal(result.pipelineState.workerSummary, null);
  assert.equal(fixture.calls.reviewer.length, 0);
});

test("invalidates correction counters when accepted task input changes", async (t) => {
  let changed = false;
  const fixture = await createFixture(t, {
    onTransition: async (run) => {
      if (!changed && run.counters.correctionRounds === 1) {
        changed = true;
        await writeFile(join(run.taskPath, "task.md"), "Changed task.\n");
      }
    },
    workReviewer: [reviewFindings("R1"), reviewFindings("R1")],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
    ],
  });

  const result = await fixture.run({
    maxSameFindingRounds: 10,
    stagnationWindowRounds: 10,
  });

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "task_input_changed");
  assert.equal(result.counters.fixRounds, 0);
  assert.equal(result.counters.correctionRounds, 0);
  assert.deepEqual(result.pipelineState.correctionHistory, []);
});

test("pauses when the repository changes between bootstrap turns", async (t) => {
  let changed = false;
  const fixture = await createFixture(t, {
    onTransition: async (run) => {
      if (!changed && run.pipelineState.workerSummary !== null) {
        changed = true;
        await writeFile(join(run.projectPath, "source.js"), "externally changed\n");
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "unsafe_git_state");
  assert.equal(result.pause.code, "ERR_READ_ONLY_REPOSITORY_CHANGED");
  assert.notEqual(result.pipelineState.workerSummary, null);
  assert.equal(fixture.calls.reviewer.length, 0);
});

test("invalidates bootstrap after a read-only role mutates the repository", async (t) => {
  const fixture = await createFixture(t, {
    onRoleRun: async (role) => {
      if (role === "reviewer") {
        await writeFile(join(fixture.projectPath, "source.js"), "mutated\n");
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "read_only_agent_mutated_repository");
  assert.equal(result.pipelineState.workerSummary, null);
  assert.equal(result.pipelineState.reviewerSummary, null);
});

test("detects an ignored transcript mutation during a read-only turn", async (t) => {
  const fixture = await createFixture(t, {
    onRoleRun: async (role, _request, turn) => {
      if (role === "worker" && turn === 2) {
        await writeFile(fixture.clarificationPath, "agent mutation\n");
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "clarifications_changed");
  assert.equal(result.pipelineState.workerSummary, null);
  assert.equal(fixture.calls.reviewer.length, 0);
});

test("enforces the bounded clarification round limit", async (t) => {
  const fixture = await createFixture(t, {
    interactive: true,
    onEdit: async (authorization) => {
      await writeFile(
        authorization.transcriptPath,
        `${await readFile(authorization.transcriptPath, "utf8")}Answer.\n`,
      );
    },
    reviewer: [],
    worker: [
      clarificationQuestions(),
      clarificationQuestions(),
      clarificationQuestions(),
      clarificationQuestions(),
    ],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "clarification_limit_reached");
  assert.equal(result.counters.clarificationRounds, 3);
  assert.equal(fixture.calls.worker.length, 4);
  assert.equal(fixture.calls.reviewer.length, 0);
});

test("uses a fresh Arbiter only for a recorded bootstrap disagreement", async (t) => {
  const fixture = await createFixture(t, {
    arbiter: [arbitrationResolved()],
    capabilities: { arbiter: { nativeSessionFork: false } },
    models: { arbiter: "arbiter-model" },
    sourceSession: SOURCE_SESSION,
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationDisagreement(),
    ],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.bootstrapArbitrationUsed, true);
  assert.equal(result.pipelineState.bootstrapDisagreement, null);
  assert.equal(result.pipelineState.backendVersions.arbiter, "fake-1.0.0");
  assert.equal(fixture.calls.arbiter.length, 1);
  assert.equal(fixture.calls.arbiter[0].session, undefined);
  assert.equal(fixture.calls.arbiter[0].model, "arbiter-model");
  assert.match(
    fixture.calls.arbiter[0].prompt,
    /Resolve the bootstrap disagreement from the task, plan, repository, and evidence, choosing the minimal valid direction using the provided schema\./u,
  );
  assert.deepEqual(
    result.sessionLineage.children.map(({ role }) => role),
    ["worker", "worker", "reviewer", "arbiter", "worker", "reviewer"],
  );
});

test("starts a fresh Arbiter for a new bootstrap dispute", async (t) => {
  const secondArbiterSession = "77777777-7777-4777-8777-777777777777";
  const fixture = await createFixture(t, {
    arbiter: [arbitrationProductDecision(), arbitrationResolved()],
    reviewer: [bootstrapReady("Reviewer"), bootstrapReady("Reviewer")],
    sessionIds: {
      ...ROLE_SESSIONS,
      arbiter: [ROLE_SESSIONS.arbiter, secondArbiterSession],
    },
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationDisagreement(),
      compatibilityReady(),
      bootstrapReady("Worker"),
      reconciliationDisagreement(),
    ],
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "product_decision_required");
  assert.deepEqual(paused.pause.inputRequest, {
    id: paused.pipelineState.pendingEdit.id,
    kind: "product-decision",
    questions: [
      {
        id: "decision",
        question: "Which public behavior should be implemented?",
        options: ["Behavior A", "Behavior B"],
      },
    ],
    rationale: "Both behaviors are valid but incompatible.",
    artifactPath: fixture.clarificationPath,
  });
  await writeFile(
    fixture.clarificationPath,
    `${await readFile(fixture.clarificationPath, "utf8")}Behavior A.\n`,
  );

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(fixture.calls.arbiter.length, 2);
  assert.equal(fixture.calls.arbiter[0].session, undefined);
  assert.equal(fixture.calls.arbiter[1].session, undefined);
  assert.deepEqual(
    result.sessionLineage.children
      .filter(({ role }) => role === "arbiter")
      .map(({ sessionId }) => sessionId),
    [ROLE_SESSIONS.arbiter, secondArbiterSession],
  );
});

test("checks plan compatibility after a bootstrap product decision", async (t) => {
  const fixture = await createFixture(t, {
    worker: [
      clarificationReady(),
      bootstrapProductDecision(),
      compatibilityReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
    ],
  });

  const paused = await fixture.run();

  assert.equal(paused.pause.reason, "product_decision_required");
  assert.equal(paused.pipelineState.pendingEdit.suspendedState, "BOOTSTRAP");
  await writeFile(
    fixture.clarificationPath,
    `${await readFile(fixture.clarificationPath, "utf8")}Behavior A.\n`,
  );

  const resumed = await fixture.run();

  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.equal(resumed.counters.productDecisions, 1);
  assert.match(fixture.calls.worker[2].prompt, /Review the updated clarifications/u);
  assert.equal(resumed.pipelineState.compatibilityCheckRequired, false);
});

test(
  "retires a corrected product decision before restarting bootstrap",
  async (t) => {
    const fixture = await createFixture(t, {
      worker: [
        clarificationReady(),
        { ...bootstrapProductDecision(), question: "" },
        bootstrapProductDecision(),
        compatibilityReady(),
        bootstrapReady("Worker"),
        reconciliationResolved(),
      ],
    });

    const paused = await fixture.run();

    assert.equal(paused.pause.reason, "product_decision_required");
    assert.deepEqual(paused.pipelineState.bootstrapCorrections, [
      {
        attempt: 1,
        role: "worker",
        phase: "bootstrap",
        contract: "bootstrap",
        field: "question",
        constraint: "nonempty-plain-text-up-to-4000-characters",
      },
    ]);
    assert.equal(paused.pipelineState.pendingBootstrapCorrection, null);
    assert.match(
      fixture.calls.worker[2].prompt,
      /Preserve the exceptional PRODUCT_DECISION_REQUIRED outcome/u,
    );
    await writeFile(
      fixture.clarificationPath,
      `${await readFile(fixture.clarificationPath, "utf8")}Behavior A.\n`,
    );

    const resumed = await fixture.run();

    assert.equal(resumed.pipelineState.workflowState, "DONE");
    assert.equal(resumed.pipelineState.bootstrapCorrections.length, 1);
    assert.equal(resumed.pipelineState.pendingBootstrapCorrection, null);
    assert.match(
      fixture.calls.worker[3].prompt,
      /Review the updated clarifications/u,
    );
    assert.doesNotMatch(
      fixture.calls.worker[4].prompt,
      /Make one read-only correction/u,
    );
  },
);

test("restarts independent bootstrap after a reconciliation product decision", async (t) => {
  const fixture = await createFixture(t, {
    reviewer: [bootstrapReady("Reviewer"), bootstrapReady("Reviewer")],
    sourceSession: SOURCE_SESSION,
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationProductDecision(),
      compatibilityReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
    ],
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "product_decision_required");
  await writeFile(
    fixture.clarificationPath,
    `${await readFile(fixture.clarificationPath, "utf8")}Behavior A.\n`,
  );

  const resumed = await fixture.run();

  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.deepEqual(fixture.calls.worker[4].session, {
    mode: "fork",
    id: SOURCE_SESSION,
  });
  assert.deepEqual(fixture.calls.reviewer[1].session, {
    mode: "fork",
    id: SOURCE_SESSION,
  });
  assert.deepEqual(fixture.calls.worker[5].session, {
    mode: "continue",
    id: resumed.sessionLineage.children.filter(
      ({ role }) => role === "worker",
    )[3].sessionId,
  });
});

test("keeps the run paused when a product answer invalidates the plan", async (t) => {
  const fixture = await createFixture(t, {
    reviewer: [],
    worker: [
      clarificationReady(),
      bootstrapProductDecision(),
      compatibilityPlanRevision(),
    ],
  });

  await fixture.run();
  await writeFile(
    fixture.clarificationPath,
    `${await readFile(fixture.clarificationPath, "utf8")}Behavior B.\n`,
  );
  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "plan_revision_required");
  assert.match(result.pause.explanation, /changes a planned commit boundary/u);
  assert.equal(result.pipelineState.resolvedSummary, null);
  assert.equal(fixture.calls.reviewer.length, 0);
});

test("rejects a fork response that reuses the source session", async (t) => {
  const fixture = await createFixture(t, {
    sessionIds: { ...ROLE_SESSIONS, worker: SOURCE_SESSION },
    sourceSession: SOURCE_SESSION,
  });

  await assert.rejects(
    fixture.run(),
    (error) => error.code === "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
  );
  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
});

test("pauses before agent work when the selected backend is unsafe", async (t) => {
  const fixture = await createFixture(t, {
    capabilities: { worker: { localCommit: false } },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "backend_unavailable");
  assert.equal(result.pipelineState.preflightComplete, false);
  assert.equal(fixture.calls.worker.length, 0);
  await assert.rejects(readFile(fixture.clarificationPath), { code: "ENOENT" });
});

test("preserves settings while retrying a preflight pause", async (t) => {
  const fixture = await createFixture(t, { dirty: true });

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "unsafe_git_state");
  assert.deepEqual(paused.pipelineState.settings, SETTINGS);
  await rm(join(fixture.projectPath, "dirty.txt"));

  const resumed = await fixture.run({ maxFixRoundsPerStep: 99 });

  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.deepEqual(resumed.pipelineState.settings, SETTINGS);
});

test("verifies frozen inputs at the implementation boundary", async (t) => {
  let changed = false;
  const fixture = await createFixture(t, {
    async onTransition(run) {
      if (!changed && run.pipelineState.workflowState === "IMPLEMENT") {
        changed = true;
        await writeFile(
          join(run.taskPath, "plan.md"),
          `${PLAN}\n\nChanged after bootstrap.`,
        );
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "task_input_changed");
  assert.equal(result.pipelineState.currentStep, null);
  assert.equal(result.pipelineState.resolvedSummary, null);
});

test("reconstructs an interrupted writable turn with partial content and staging", async (t) => {
  let interrupt = true;
  let recovering = false;
  const fixture = await createFixture(t, {
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("Implement the changes")
      ) {
        if (interrupt) {
          interrupt = false;
          const error = new Error("Provider interrupted.");
          error.recoverable = true;
          throw error;
        }
        if (recovering) {
          assert.equal(request.session, undefined);
          assert.equal(request.prompt, request.recoveryPrompt);
          assert.equal(
            await readFile(join(fixture.projectPath, "partial.txt"), "utf8"),
            "partial implementation\n",
          );
          const { stdout } = await executeFile("git", [
            "-C",
            fixture.projectPath,
            "diff",
            "--cached",
            "--name-only",
          ]);
          assert.match(stdout, /^partial\.txt$/mu);
          recovering = false;
        }
      }
    },
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.resumeState, "IMPLEMENT");
  await writeFile(
    join(fixture.projectPath, "partial.txt"),
    "partial implementation\n",
  );
  await executeFile("git", ["-C", fixture.projectPath, "add", "partial.txt"]);
  Object.assign(fixture.currentRun, {
    activeTurn: { role: "worker", phase: "implement" },
    pause: null,
    pipelineState: { ...paused.pipelineState, workflowState: "IMPLEMENT" },
  });
  recovering = true;

  const completed = await fixture.run();
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.activeTurn, null);
});

test("rejects task and Git-control drift before interrupted writable recovery", async (t) => {
  for (const drift of ["plan", "identity"]) {
    await t.test(drift, async (t) => {
      let interrupt = true;
      const fixture = await createFixture(t, {
        onRoleRun(role, request) {
          if (
            role === "worker" &&
            request.prompt.includes("Implement the changes") &&
            interrupt
          ) {
            interrupt = false;
            const error = new Error("Provider interrupted.");
            error.recoverable = true;
            throw error;
          }
        },
      });
      const paused = await fixture.run();
      Object.assign(fixture.currentRun, {
        activeTurn: { role: "worker", phase: "implement" },
        pause: null,
        pipelineState: {
          ...paused.pipelineState,
          workflowState: "IMPLEMENT",
        },
      });
      if (drift === "plan") {
        await writeFile(join(fixture.taskPath, "plan.md"), `${PLAN}\nDrift.\n`);
      } else {
        await executeFile("git", [
          "-C",
          fixture.projectPath,
          "config",
          "user.name",
          "Changed Identity",
        ]);
      }

      const rejected = await fixture.run();
      assert.equal(
        rejected.pause.reason,
        drift === "plan" ? "task_input_changed" : "unexpected_git_identity_change",
      );
      assert.deepEqual(rejected.activeTurn, {
        role: "worker",
        phase: "implement",
      });
    });
  }
});

test("counts a recovered correction that removes partial content", async (t) => {
  let interrupt = true;
  const fixture = await createFixture(t, {
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("For each finding below") &&
        interrupt
      ) {
        interrupt = false;
        const error = new Error("Provider interrupted.");
        error.recoverable = true;
        throw error;
      }
      if (
        role === "worker" &&
        request.prompt.includes("For each finding below")
      ) {
        await rm(join(request.cwd, "partial-fix.txt"));
      }
    },
    workReviewer: [reviewFindings("R1"), reviewApproved()],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
    ],
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.resumeState, "RESOLVE_FINDINGS");
  await writeFile(join(fixture.projectPath, "partial-fix.txt"), "partial fix\n");
  Object.assign(fixture.currentRun, {
    activeTurn: { role: "worker", phase: "resolve-findings" },
    pause: null,
    pipelineState: {
      ...paused.pipelineState,
      workflowState: "RESOLVE_FINDINGS",
    },
  });

  const completed = await fixture.run();
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.counters.fixRounds, 1);
  await assert.rejects(
    readFile(join(fixture.projectPath, "partial-fix.txt")),
    { code: "ENOENT" },
  );
});

test("clears a reconciled correction marker without replaying the turn", async (t) => {
  const processLoss = new Error(
    "Process stopped after correction reconciliation.",
  );
  const fixture = await createFixture(t, {
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("For each finding below")
      ) {
        await writeFile(
          join(fixture.projectPath, "reconciled-fix.txt"),
          "reconciled fix\n",
        );
      }
    },
    workReviewer: [reviewFindings("R1"), reviewApproved()],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
    ],
  });
  const transition = fixture.runtime.transition;
  const finishAgentTurn = fixture.runtime.finishAgentTurn;
  let processStopped = false;
  fixture.runtime.transition = async (patch, options) => {
    if (processStopped) {
      throw processLoss;
    }
    const next = await transition(patch, options);
    if (
      next.activeTurn?.phase === "resolve-findings" &&
      next.pipelineState.workflowState === "FINALIZE" &&
      next.pipelineState.pendingCorrection
    ) {
      processStopped = true;
    }
    return next;
  };
  fixture.runtime.finishAgentTurn = async (turn) => {
    if (processStopped) {
      throw processLoss;
    }
    return finishAgentTurn(turn);
  };

  await assert.rejects(fixture.run(), (error) => error === processLoss);
  assert.deepEqual(fixture.currentRun.activeTurn, {
    role: "worker",
    phase: "resolve-findings",
  });
  assert.equal(fixture.currentRun.pipelineState.workflowState, "FINALIZE");
  assert.equal(fixture.currentRun.pipelineState.pendingCorrection, true);
  assert.equal(fixture.currentRun.counters.fixRounds, 1);
  const resolutionTurns = fixture.calls.worker.filter(({ prompt }) =>
    prompt.includes("For each finding below"),
  ).length;

  processStopped = false;
  fixture.runtime.transition = transition;
  fixture.runtime.finishAgentTurn = finishAgentTurn;
  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.activeTurn, null);
  assert.equal(completed.counters.fixRounds, 1);
  assert.equal(
    fixture.calls.worker.filter(({ prompt }) =>
      prompt.includes("For each finding below"),
    ).length,
    resolutionTurns,
  );
});

test("treats emptied required inputs as drift on resume", async (t) => {
  for (const file of ["task.md", "plan.md"]) {
    await t.test(file, async (t) => {
      let changed = false;
      const fixture = await createFixture(t, {
        async onTransition(run) {
          if (!changed && run.pipelineState.workflowState === "IMPLEMENT") {
            changed = true;
            await writeFile(join(run.taskPath, file), "");
          }
        },
      });

      const result = await fixture.run();

      assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
      assert.equal(result.pause.reason, "task_input_changed");
      assert.equal(result.pipelineState.currentStep, null);
      assert.equal(result.pipelineState.resolvedSummary, null);
    });
  }
});

test("pauses when the repository changes at the implementation boundary", async (t) => {
  let changed = false;
  const fixture = await createFixture(t, {
    async onTransition(run) {
      if (!changed && run.pipelineState.workflowState === "IMPLEMENT") {
        changed = true;
        await writeFile(join(run.projectPath, "source.js"), "externally changed\n");
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "unsafe_git_state");
  assert.equal(result.pause.code, "ERR_READ_ONLY_REPOSITORY_CHANGED");
  assert.notEqual(result.pipelineState.resolvedSummary, null);
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
    run.pipelineState.pendingBootstrapCorrection = {
      attempt: 1,
      role: "worker",
      phase: "bootstrap",
      contract: "bootstrap",
      field: "result",
      constraint: "semantic-contract",
    };
  });

  await rejectsState("pending finalization correction without history", (run) => {
    run.pipelineState.pendingFinalizationCorrection = {
      attempt: 1,
      step: 1,
      guidance: "resolved",
      contentFingerprint: "a".repeat(64),
      role: "worker",
      phase: "finalization",
      contract: "finalization",
      field: "result",
      constraint: "semantic-contract",
    };
  });

  await rejectsState("finalization correction for another step", (run) => {
    run.pipelineState.finalizationCorrection = {
      attempt: 1,
      step: 2,
      guidance: "resolved",
      contentFingerprint: "a".repeat(64),
      role: "worker",
      phase: "finalization",
      contract: "finalization",
      field: "result",
      constraint: "semantic-contract",
    };
  });

  await rejectsState("finalization correction with retained raw output", (run) => {
    run.pipelineState.finalizationCorrection = {
      attempt: 1,
      step: 1,
      guidance: "resolved",
      contentFingerprint: "a".repeat(64),
      role: "worker",
      phase: "finalization",
      contract: "finalization",
      field: "result",
      constraint: "semantic-contract",
      rawOutput: "must not be persisted",
    };
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

test("rejects a child session shared by Worker and Reviewer", async (t) => {
  const fixture = await createFixture(t, {
    sessionIds: {
      ...ROLE_SESSIONS,
      reviewer: ROLE_SESSIONS.worker,
    },
  });

  await assert.rejects(
    fixture.run(),
    (error) => error.code === "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
  );
  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
});

test("rejects a fresh role turn that reuses its previous session", async (t) => {
  const fixture = await createFixture(t, {
    sessionIds: {
      ...ROLE_SESSIONS,
      worker: [
        ROLE_SESSIONS.worker,
        RESTARTED_ROLE_SESSIONS.worker,
        REBOOTSTRAPPED_WORKER_SESSION,
        REBOOTSTRAPPED_WORKER_SESSION,
      ],
    },
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationProductDecision(),
      compatibilityReady(),
      bootstrapReady("Worker"),
    ],
  });

  await fixture.run();
  await writeFile(
    fixture.clarificationPath,
    `${await readFile(fixture.clarificationPath, "utf8")}Behavior A.\n`,
  );

  await assert.rejects(
    fixture.run(),
    (error) => error.code === "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
  );
  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
});

test("retries an unavailable bootstrap Arbiter without repeating bootstrap", async (t) => {
  const arbiterCapabilities = { readOnly: false };
  const fixture = await createFixture(t, {
    arbiter: [arbitrationResolved()],
    capabilities: { arbiter: arbiterCapabilities },
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationDisagreement(),
    ],
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pause.resumeState, "BOOTSTRAP");
  assert.equal(paused.pipelineState.bootstrapDisagreement.description.length > 0, true);
  assert.equal(fixture.calls.worker.length, 3);
  arbiterCapabilities.readOnly = true;

  const resumed = await fixture.run();

  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.equal(fixture.calls.worker.length, 6);
  assert.equal(fixture.calls.reviewer.length, 2);
  assert.equal(fixture.calls.arbiter.length, 1);
  assert.equal(fixture.probeCalls.arbiter, 2);
  assert.equal(
    fixture.calls.worker.filter(({ prompt }) =>
      prompt.includes("Provide a concise bootstrap summary"),
    ).length,
    1,
  );
});

test("implements, finalizes, reviews, and commits one step", async (t) => {
  let initialHead;
  const fixture = await createFixture(t, {
    async onRoleRun(role, request) {
      if (role === "worker" && request.prompt.includes("Implement the changes")) {
        initialHead ??= (
          await executeFile("git", ["-C", request.cwd, "rev-parse", "HEAD"])
        ).stdout.trim();
        await writeFile(join(request.cwd, "source.js"), "export const value = 2;\n");
      }
      if (
        role === "worker" &&
        request.prompt.includes("Run the complete project finalization procedure")
      ) {
        await writeFile(join(request.cwd, "generated.js"), "export const generated = true;\n");
      }
    },
  });

  const result = await fixture.run();
  const head = (
    await executeFile("git", ["-C", fixture.projectPath, "rev-parse", "HEAD"])
  ).stdout.trim();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.finalizationResult.status, "PASS");
  assert.equal(
    result.pipelineState.finalizedFingerprint,
    result.pipelineState.reviewedFingerprint,
  );
  assert.notEqual(head, initialHead);
  assert.equal(result.pipelineState.completedCommits[0], head);
  assert.equal(fixture.calls.worker.at(-3).access, "workspace-write");
  assert.equal(fixture.calls.worker.at(-2).access, "workspace-write");
  assert.equal(fixture.calls.worker.at(-1).access, "local-commit");
  assert.equal(fixture.calls.reviewer.at(-1).access, "read-only");
});

test("creates one verified local commit for every plan step", async (t) => {
  const plan = `## Commit 1: feat(test): add first behavior

Implement the first behavior.

## Commit 2: fix(test): add second behavior

Implement the second behavior.`;
  const fixture = await createFixture(t, {
    plan,
    sourceSession: SOURCE_SESSION,
    workReviewer: [reviewApproved(), reviewApproved()],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      implementationCompleted(),
      finalizationPassed(),
    ],
  });

  const result = await fixture.run();
  const { stdout } = await executeFile("git", [
    "-C",
    fixture.projectPath,
    "log",
    "-2",
    "--pretty=%s",
  ]);

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.currentStep, null);
  assert.equal(result.pipelineState.completedCommits.length, 2);
  assert.deepEqual(stdout.trim().split("\n"), [
    "fix(test): add second behavior",
    "feat(test): add first behavior",
  ]);
  assert.deepEqual(
    fixture.calls.worker
      .filter(({ access }) => access === "local-commit")
      .map(({ commit }) => commit.message),
    ["feat(test): add first behavior", "fix(test): add second behavior"],
  );
  const implementationCalls = fixture.calls.worker.filter(({ prompt }) =>
    prompt.includes("Implement the changes described"),
  );
  const reviewCalls = fixture.calls.reviewer.filter(({ prompt }) =>
    prompt.includes("Review the changes and verify"),
  );
  assert.equal(implementationCalls.length, 2);
  assert.equal(reviewCalls.length, 2);
  for (const request of [...implementationCalls, ...reviewCalls]) {
    assert.deepEqual(request.session, { mode: "fork", id: SOURCE_SESSION });
    assert.equal(request.prompt, request.recoveryPrompt);
  }
  const workerCheckpointKeys = result.sessionLineage.children
    .filter(({ role }) => role === "worker")
    .slice(-2)
    .map(({ contextKey }) => contextKey);
  const reviewerCheckpointKeys = result.sessionLineage.children
    .filter(({ role }) => role === "reviewer")
    .slice(-2)
    .map(({ contextKey }) => contextKey);
  assert.notEqual(workerCheckpointKeys[0], workerCheckpointKeys[1]);
  assert.notEqual(reviewerCheckpointKeys[0], reviewerCheckpointKeys[1]);
  assert.deepEqual(fixture.calls.reviewer.at(-1).session, {
    mode: "fork",
    id: SOURCE_SESSION,
  });
});

test("accepts a verified commit after an interrupted adapter result", async (t) => {
  const fixture = await createFixture(t, {
    async onCommitRun(request) {
      await executeFile("git", ["-C", request.cwd, "add", "-A"]);
      await executeFile("git", [
        "-C",
        request.cwd,
        "commit",
        "-qm",
        request.commit.message,
      ]);
      const error = new Error("Commit result was lost.");
      error.code = "ERR_FAKE_LOCAL_COMMIT_INTERRUPTED";
      error.ambiguous = true;
      throw error;
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.completedCommits.length, 1);
  assert.equal(
    fixture.calls.worker.filter(({ access }) => access === "local-commit")
      .length,
    1,
  );
});

test("renews a policy-rejected commit authorization after Git proves no effect", async (t) => {
  let rejectCommit = true;
  const fixture = await createFixture(t, {
    async onRoleRun(_role, request) {
      if (request.access === "local-commit" && rejectCommit) {
        rejectCommit = false;
        const error = new Error("The adapter rejected the commit request.");
        error.code = "ERR_FAKE_LOCAL_COMMIT_POLICY";
        error.effectStarted = false;
        throw error;
      }
    },
  });

  const paused = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "commit_failed");
  assert.equal(paused.pause.code, "ERR_FAKE_LOCAL_COMMIT_POLICY");
  assert.equal(paused.pause.resumeState, "COMMIT");
  assert.equal(paused.pipelineState.pendingCommit, null);
  assert.equal(
    fixture.transitions.findLast(
      ({ options }) => options?.activity?.kind === "authorization-retired",
    ).patch.pipelineState.pendingCommit,
    null,
  );

  const resumed = await fixture.run();
  const commitRequests = fixture.calls.worker.filter(
    ({ access }) => access === "local-commit",
  );

  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.deepEqual(
    commitRequests.map(({ authorizationId }) => authorizationId),
    ["commit-1", "commit-2"],
  );
});

test("preserves pre-effect proof across interrupted Git verification", async (t) => {
  let rejectCommit = true;
  let interruptVerification = true;
  const fixture = await createFixture(t, {
    onCommitVerify() {
      if (interruptVerification) {
        interruptVerification = false;
        const error = new Error("Git verification was interrupted.");
        error.code = "ERR_FAKE_COMMIT_VERIFICATION";
        throw error;
      }
    },
    onRoleRun(_role, request) {
      if (request.access === "local-commit" && rejectCommit) {
        rejectCommit = false;
        const error = new Error("The adapter rejected the commit request.");
        error.code = "ERR_FAKE_LOCAL_COMMIT_POLICY";
        error.effectStarted = false;
        throw error;
      }
    },
  });

  const verificationPaused = await fixture.run();

  assert.equal(verificationPaused.pause.reason, "commit_failed");
  assert.equal(verificationPaused.pause.code, "ERR_FAKE_COMMIT_VERIFICATION");
  assert.deepEqual(
    verificationPaused.pipelineState.pendingCommit.preEffectRejection,
    {
      code: "ERR_FAKE_LOCAL_COMMIT_POLICY",
      recoverable: false,
    },
  );

  const rejectionPaused = await fixture.run();

  assert.equal(rejectionPaused.pause.reason, "commit_failed");
  assert.equal(rejectionPaused.pause.code, "ERR_FAKE_LOCAL_COMMIT_POLICY");
  assert.equal(rejectionPaused.pipelineState.pendingCommit, null);

  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.deepEqual(
    fixture.calls.worker
      .filter(({ access }) => access === "local-commit")
      .map(({ authorizationId }) => authorizationId),
    ["commit-1", "commit-2"],
  );
});

test("re-authorizes after a proven pre-effect provider rejection", async (t) => {
  let backendUnavailable = true;
  const fixture = await createFixture(t, {
    workReviewer: [
      reviewApproved(),
      bootstrapReady("Migrating Reviewer"),
      reviewApproved(),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      bootstrapReady("Migrating Worker"),
      reconciliationResolved(),
      finalizationPassed(),
    ],
    async onRoleRun(_role, request) {
      if (request.access === "local-commit" && backendUnavailable) {
        backendUnavailable = false;
        const error = new Error("Provider capacity is unavailable.");
        error.code = "ERR_FAKE_PROVIDER_LIMIT";
        error.recoverable = true;
        error.ambiguous = false;
        error.effectStarted = false;
        throw error;
      }
    },
  });

  const paused = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pause.code, "ERR_FAKE_PROVIDER_LIMIT");
  assert.equal(paused.pause.resumeState, "COMMIT");
  assert.equal(paused.pipelineState.pendingCommit, null);
  const rejectedRequest = fixture.calls.worker.findLast(
    ({ access }) => access === "local-commit",
  );
  assert.equal(rejectedRequest.authorizationId, "commit-1");

  const migrated = migrateVersionOneState(
    versionOneState(paused.pipelineState),
  );
  assert.equal(migrated.validationMigrationPending, true);
  assert.equal(migrated.pendingCommit, null);
  fixture.persistPipelineState(migrated, { pause: paused.pause });
  const resumed = await fixture.run();
  const commitRequests = fixture.calls.worker.filter(
    ({ access }) => access === "local-commit",
  );

  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.equal(resumed.pipelineState.completedCommits.length, 1);
  assert.deepEqual(
    commitRequests.map(({ authorizationId }) => authorizationId),
    ["commit-1", "commit-2"],
  );
});

test("does not renew an unmarked provider rejection", async (t) => {
  const fixture = await createFixture(t, {
    onRoleRun(_role, request) {
      if (request.access === "local-commit") {
        const error = new Error("Provider capacity is unavailable.");
        error.code = "ERR_FAKE_PROVIDER_LIMIT";
        error.recoverable = true;
        error.ambiguous = false;
        throw error;
      }
    },
  });

  const paused = await fixture.run();
  const resumed = await fixture.run();

  assert.equal(paused.pause.reason, "commit_failed");
  assert.equal(paused.pipelineState.pendingCommit.status, "consumed");
  assert.equal(resumed.pause.reason, "commit_failed");
  assert.equal(resumed.pipelineState.pendingCommit.status, "consumed");
  assert.equal(
    fixture.calls.worker.filter(({ access }) => access === "local-commit")
      .length,
    1,
  );
});

test("resumes commit verification without replaying the Worker", async (t) => {
  let verificationUnavailable = true;
  const fixture = await createFixture(t, {
    onCommitVerify() {
      if (verificationUnavailable) {
        verificationUnavailable = false;
        const error = new Error("Git verification was interrupted.");
        error.code = "ERR_FAKE_COMMIT_VERIFICATION";
        throw error;
      }
    },
  });

  const paused = await fixture.run();
  const resumed = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "commit_failed");
  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.equal(resumed.pipelineState.completedCommits.length, 1);
  assert.equal(
    fixture.calls.worker.filter(({ access }) => access === "local-commit")
      .length,
    1,
  );
});

test("verifies a consumed version-5 authorization before validation migration", async (t) => {
  let verificationUnavailable = true;
  const fixture = await createFixture(t, {
    onCommitVerify() {
      if (verificationUnavailable) {
        verificationUnavailable = false;
        const error = new Error("Git verification was interrupted.");
        error.code = "ERR_FAKE_COMMIT_VERIFICATION";
        throw error;
      }
    },
  });
  const paused = await fixture.run();
  const roleCallCount = Object.values(fixture.calls).flat().length;
  const migrated = migratePlanExecutionStateV5({
    pipelineState: paused.pipelineState,
    pause: paused.pause,
  });
  assert.equal(migrated.pendingCommit.status, "consumed");
  assert.equal(migrated.validationMigrationPending, true);
  fixture.persistPipelineState(migrated, { pause: paused.pause });

  const resumed = await fixture.run();

  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.equal(resumed.pipelineState.validationMigrationPending, false);
  assert.equal(Object.values(fixture.calls).flat().length, roleCallCount);
  assert.equal(
    fixture.calls.worker.filter(({ access }) => access === "local-commit").length,
    1,
  );
});

test("never replays a consumed authorization when no commit was created", async (t) => {
  const fixture = await createFixture(t, {
    onCommitRun() {
      const error = new Error("Commit process was interrupted.");
      error.code = "ERR_FAKE_LOCAL_COMMIT_INTERRUPTED";
      error.ambiguous = true;
      throw error;
    },
  });

  const paused = await fixture.run();
  const migrated = migrateVersionOneState(
    versionOneState(paused.pipelineState),
  );
  assert.equal(migrated.validationMigrationPending, true);
  assert.equal(migrated.pendingCommit.status, "consumed");
  assert.equal(migrated.pendingCommit.preEffectRejection, null);
  fixture.persistPipelineState(migrated, { pause: paused.pause });
  const resumed = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "commit_failed");
  assert.equal(paused.pipelineState.pendingCommit.status, "consumed");
  assert.equal(resumed.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(resumed.pause.reason, "commit_failed");
  assert.ok(resumed.revision > paused.revision);
  assert.equal(
    fixture.calls.worker.filter(({ access }) => access === "local-commit")
      .length,
    1,
  );
});

test("pauses without rewriting a commit that violates its authorization", async (t) => {
  const fixture = await createFixture(t, {
    async onCommitRun(request) {
      await executeFile("git", ["-C", request.cwd, "add", "-A"]);
      await executeFile("git", [
        "-C",
        request.cwd,
        "commit",
        "-qm",
        `${request.commit.message}\n\nCo-authored-by: Other <other@example.com>`,
      ]);
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "commit_contract_violated");
  assert.ok(result.pause.changes.includes("co-author"));
  assert.deepEqual(result.pipelineState.completedCommits, []);
  assert.equal(result.pipelineState.pendingCommit.status, "consumed");
});

test("preserves workspace changes after a Claude usage rejection", async (t) => {
  let interruptImplementation = true;
  const fixture = await createFixture(t, {
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("Implement the changes") &&
        interruptImplementation
      ) {
        interruptImplementation = false;
        await writeFile(
          join(request.cwd, "source.js"),
          "export const value = 2;\n",
        );
        const error = new Error("Claude usage capacity is unavailable.");
        error.code = "ERR_CLAUDE_USAGE_LIMIT";
        error.recoverable = true;
        throw error;
      }
    },
  });

  const paused = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pause.code, "ERR_CLAUDE_USAGE_LIMIT");
  assert.equal(paused.pause.resumeState, "IMPLEMENT");

  const resumed = await fixture.run();

  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.equal(
    await readFile(join(fixture.projectPath, "source.js"), "utf8"),
    "export const value = 2;\n",
  );
});

test("does not let Claude provider recovery mask a control mutation", async (t) => {
  const fixture = await createFixture(t, {
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("Implement the changes")
      ) {
        await executeFile("git", [
          "-C",
          request.cwd,
          "remote",
          "add",
          "unexpected",
          "https://example.invalid/repository.git",
        ]);
        const error = new Error("Claude provider is unavailable.");
        error.code = "ERR_CLAUDE_PROVIDER_UNAVAILABLE";
        error.recoverable = true;
        throw error;
      }
    },
  });

  const paused = await fixture.run();

  assert.equal(paused.pause.reason, "unexpected_remote_configuration_change");
  assert.notEqual(paused.pause.reason, "backend_unavailable");
});

test("re-finalizes a partial correction after provider unavailability", async (t) => {
  let interruptResolution = true;
  const fixture = await createFixture(t, {
    workReviewer: [reviewFindings("R1"), reviewApproved()],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      finalizationPassed(),
    ],
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("For each finding below") &&
        interruptResolution
      ) {
        interruptResolution = false;
        await writeFile(
          join(request.cwd, "source.js"),
          "export const value = 2;\n",
        );
        const error = new Error("Claude provider is unavailable.");
        error.code = "ERR_CLAUDE_PROVIDER_UNAVAILABLE";
        error.recoverable = true;
        throw error;
      }
    },
  });

  const paused = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pause.code, "ERR_CLAUDE_PROVIDER_UNAVAILABLE");
  assert.equal(paused.pause.resumeState, "FINALIZE");
  assert.equal(paused.pipelineState.finalizationResult, null);
  assert.equal(paused.pipelineState.finalizedFingerprint, null);
  assert.equal(paused.pipelineState.reviewedFingerprint, null);
  assert.deepEqual(paused.pipelineState.findings, []);
  assert.equal(paused.pipelineState.previousFindings[0].id, "R1");
  assert.equal(paused.counters.fixRounds, 1);

  const resumed = await fixture.run();

  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.match(
    fixture.calls.worker.findLast(({ prompt }) =>
      prompt.includes("Run the complete project finalization procedure"),
    ).prompt,
    /Run the complete project finalization procedure/u,
  );
  assert.match(
    fixture.calls.reviewer.at(-1).prompt,
    /Previous findings for this step:[\s\S]*"id": "R1"/u,
  );
});

test("fails closed after an ambiguous writable Claude process failure", async (t) => {
  let interrupted = false;
  const fixture = await createFixture(t, {
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("Implement the changes") &&
        !interrupted
      ) {
        interrupted = true;
        await writeFile(
          join(request.cwd, "source.js"),
          "export const value = 2;\n",
        );
        const error = new Error("provider-native secret text");
        error.code = "ERR_CLAUDE_PROCESS_INTERRUPTED";
        error.ambiguous = true;
        throw error;
      }
    },
  });

  await assert.rejects(
    fixture.run(),
    (error) => error.code === "ERR_CLAUDE_PROCESS_INTERRUPTED",
  );

  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
  assert.equal(fixture.currentRun.pause.reason, "internal_failure");
  assert.equal(fixture.currentRun.pause.code, "ERR_CLAUDE_PROCESS_INTERRUPTED");
  assert.equal(
    await readFile(join(fixture.projectPath, "source.js"), "utf8"),
    "export const value = 2;\n",
  );
  assert.doesNotMatch(JSON.stringify(fixture.transitions), /provider-native/u);
});

test("retries implementation after an environment blocker clears", async (t) => {
  const fixture = await createFixture(t, {
    workWorker: [
      implementationBlocked(),
      implementationCompleted(),
      finalizationPassed(),
    ],
  });

  const paused = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "environment_blocked");
  assert.equal(paused.pause.resumeState, "IMPLEMENT");

  const resumed = await fixture.run();

  assert.equal(resumed.pipelineState.workflowState, "DONE");
});

test("retries unchanged loopback-blocked finding resolution", async (t) => {
  const fixture = await createFixture(t, {
    workWorker: [
      implementationCompleted(),
      finalizationFailed("F1"),
      environmentBlocked(
        "The required loopback endpoint is unavailable.",
        "The validation client could not connect to its loopback service.",
      ),
      resolution({ id: "F1", decision: "FIX" }),
      finalizationPassed(),
    ],
  });

  const paused = await fixture.run();

  assert.equal(paused.pause.reason, "environment_blocked");
  assert.equal(paused.pause.resumeState, "RESOLVE_FINDINGS");
  assert.equal(paused.pipelineState.finalizationResult.status, "FAIL");
  assert.deepEqual(paused.pause.evidence, [
    "The validation client could not connect to its loopback service.",
  ]);

  const resumed = await fixture.run();
  assert.equal(resumed.pipelineState.workflowState, "DONE");
});

test("preserves a partial fix before sandbox-blocked validation", async (t) => {
  const fixture = await createFixture(t, {
    workWorker: [
      implementationCompleted(),
      finalizationFailed("F1"),
      environmentBlocked(
        "The validation sandbox rejected a required operation.",
        "The sandbox denied the validation subprocess before it could run.",
      ),
      finalizationPassed(),
    ],
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("For each finding below")
      ) {
        await writeFile(join(request.cwd, "source.js"), "export const value = 2;\n");
      }
    },
  });

  const paused = await fixture.run();

  assert.equal(paused.pause.reason, "environment_blocked");
  assert.equal(paused.pause.resumeState, "FINALIZE");
  assert.equal(paused.pipelineState.finalizationResult, null);
  assert.equal(paused.pipelineState.finalizedFingerprint, null);
  assert.equal(paused.pipelineState.reviewedFingerprint, null);
  assert.equal(
    await readFile(join(fixture.projectPath, "source.js"), "utf8"),
    "export const value = 2;\n",
  );

  const resumed = await fixture.run();
  assert.equal(resumed.pipelineState.workflowState, "DONE");
});

test("routes finalization failures through a fix and the complete gate", async (t) => {
  const fixture = await createFixture(t, {
    workWorker: [
      implementationCompleted(),
      finalizationFailed("F1"),
      resolution({ id: "F1", decision: "FIX" }),
      finalizationPassed(),
    ],
    async onRoleRun(role, request) {
      if (role === "worker" && request.prompt.includes("For each finding below")) {
        await writeFile(join(request.cwd, "source.js"), "export const value = 2;\n");
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.fixRounds, 1);
  assert.equal(result.counters.correctionRounds, 0);
  assert.equal(result.pipelineState.finalizationResult.status, "PASS");
  assert.equal(fixture.calls.reviewer.length, 2);
});

test("invalidates finalization and review after fixing a review finding", async (t) => {
  const validationStates = [];
  const fixture = await createFixture(t, {
    workReviewer: [reviewFindings("R1"), reviewApproved()],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
    ],
    async onRoleRun(role, request) {
      if (role === "worker" && request.prompt.includes("For each finding below")) {
        await writeFile(join(request.cwd, "source.js"), "export const value = 2;\n");
      }
    },
    onTransition(run) {
      if (run.pipelineState.workflowState === "FINALIZE") {
        validationStates.push({
          finalizationResult: run.pipelineState.finalizationResult,
          finalizedFingerprint: run.pipelineState.finalizedFingerprint,
          reviewedFingerprint: run.pipelineState.reviewedFingerprint,
        });
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.fixRounds, 1);
  assert.ok(
    validationStates.every(
      (entry) =>
        entry.finalizationResult === null &&
        entry.finalizedFingerprint === null &&
        entry.reviewedFingerprint === null,
    ),
  );
  assert.equal(fixture.calls.reviewer.length, 3);
});

test("preserves disputes while accepted findings are fixed", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [
      reviewFindings("R1", "R2"),
      reconsideration("WITHDRAW", "R2"),
      reviewApproved(),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution(
        { id: "R1", decision: "FIX" },
        { id: "R2", decision: "DISPUTE" },
      ),
      finalizationPassed(),
    ],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.fixRounds, 1);
  assert.equal(result.pipelineState.disputeCounts.R2, 1);
  assert.equal(result.pipelineState.disputeHistory.at(-1).findingId, "R2");
  assert.equal(result.pipelineState.disputeHistory.at(-1).direction, "WITHDRAW");
  assert.match(fixture.calls.reviewer[2].prompt, /Worker disputes[\s\S]*R2/u);
  assert.match(
    fixture.calls.reviewer[3].prompt,
    /Review the changes[\s\S]*Prior decisions for this step[\s\S]*R2/u,
  );
});

test("resumes the complete review after reconsidering a deferred dispute", async (t) => {
  let interruptReview = true;
  let reviewTurns = 0;
  const fixture = await createFixture(t, {
    workReviewer: [
      reviewFindings("R1", "R2"),
      reconsideration("WITHDRAW", "R2"),
      reviewApproved(),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution(
        { id: "R1", decision: "FIX" },
        { id: "R2", decision: "DISPUTE" },
      ),
      finalizationPassed(),
    ],
    async onRoleRun(role, request) {
      if (
        role === "reviewer" &&
        request.prompt.includes("Review the changes")
      ) {
        reviewTurns += 1;
        if (reviewTurns === 2 && interruptReview) {
          interruptReview = false;
          const error = new Error(
            "Reviewer backend is temporarily unavailable.",
          );
          error.code = "ERR_PLAN_EXECUTION_BACKEND_UNAVAILABLE";
          throw error;
        }
      }
    },
  });

  const paused = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pause.resumeState, "REVIEW");
  assert.equal(paused.pipelineState.pendingDisputes.length, 0);
  assert.equal(paused.pipelineState.disputeHistory.at(-1).findingId, "R2");
  assert.equal(paused.pipelineState.reviewedFingerprint, null);

  const resumed = await fixture.run();

  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.equal(resumed.pipelineState.disputeHistory.at(-1).direction, "WITHDRAW");
  assert.match(
    fixture.calls.reviewer.at(-1).prompt,
    /Prior decisions for this step[\s\S]*"findingId": "R2"/u,
  );
});

test("preserves a mixed dispute when finalization pauses", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [reviewFindings("R1", "R2")],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution(
        { id: "R1", decision: "FIX" },
        { id: "R2", decision: "DISPUTE" },
      ),
      finalizationUnavailable("SKILL_MISSING"),
    ],
  });

  const result = await fixture.run({
    finalization: ".agents/skills/finalization/SKILL.md",
  });

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "finalization_skill_missing");
  assert.equal(result.pipelineState.pendingDisputes[0].findingId, "R2");
  assert.equal(result.pipelineState.disputeCounts.R2, 1);
});

test("preserves a mixed dispute through a finalization fix", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [
      reviewFindings("R1", "R2"),
      reconsideration("WITHDRAW", "R2"),
      reviewApproved(),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution(
        { id: "R1", decision: "FIX" },
        { id: "R2", decision: "DISPUTE" },
      ),
      finalizationFailed("F1"),
      resolution({ id: "F1", decision: "FIX" }),
      finalizationPassed(),
    ],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.fixRounds, 2);
  assert.equal(result.counters.correctionRounds, 1);
  assert.equal(result.pipelineState.disputeHistory.at(-1).findingId, "R2");
  assert.equal(result.pipelineState.disputeHistory.at(-1).direction, "WITHDRAW");
});

test("preserves a mixed dispute through stagnation rework", async (t) => {
  const fixture = await createFixture(t, {
    arbiter: [stagnation("REWORK_IMPLEMENTATION")],
    workReviewer: [
      reviewFindings("R1", "R2"),
      reconsideration("WITHDRAW", "R2"),
      reviewApproved(),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution(
        { id: "R1", decision: "FIX" },
        { id: "R2", decision: "DISPUTE" },
      ),
      finalizationFailed("F1"),
      implementationCompleted(),
      finalizationPassed(),
    ],
  });

  const result = await fixture.run({
    maxSameFindingRounds: 10,
    stagnationWindowRounds: 1,
  });

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.fixRounds, 2);
  assert.equal(result.pipelineState.disputeHistory.at(-1).findingId, "R2");
  assert.equal(result.pipelineState.disputeHistory.at(-1).direction, "WITHDRAW");
  assert.equal(fixture.calls.arbiter.length, 1);
  assert.match(
    fixture.calls.worker[7].prompt,
    /Persisted correction context[\s\S]*pendingDisputes[\s\S]*R2/u,
  );
});

test("arbitrates an upheld mixed dispute after the complete re-review", async (t) => {
  const fixture = await createFixture(t, {
    arbiter: [findingArbitration("WORKER_CORRECT")],
    workReviewer: [
      reviewFindings("R1", "R2"),
      reconsideration("UPHOLD", "R2"),
      reviewFindings("R2"),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution(
        { id: "R1", decision: "FIX" },
        { id: "R2", decision: "DISPUTE" },
      ),
      finalizationPassed(),
    ],
  });

  const result = await fixture.run({ maxDisputesPerFinding: 1 });

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.disputeCounts.R2, 1);
  assert.equal(result.pipelineState.disputeHistory.at(-1).direction, "UPHOLD");
  assert.equal(result.pipelineState.findingArbitrations.at(-1).findingId, "R2");
  assert.equal(fixture.calls.arbiter.length, 1);
});

test("lets the Reviewer withdraw an evidenced Worker dispute", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [reviewFindings("R1"), reconsideration("WITHDRAW", "R1")],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "DISPUTE" }),
    ],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.fixRounds, 0);
  assert.equal(result.pipelineState.disputeCounts.R1, 1);
  assert.equal(result.pipelineState.disputeHistory.at(-1).direction, "WITHDRAW");
  assert.equal(result.pipelineState.findings.length, 0);
});

test("arbitrates an upheld finding only after its dispute budget", async (t) => {
  const fixture = await createFixture(t, {
    arbiter: [findingArbitration("WORKER_CORRECT")],
    workReviewer: [
      reviewFindings("R1"),
      reconsideration("UPHOLD", "R1"),
      reconsideration("UPHOLD", "R1"),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "DISPUTE" }),
      resolution({ id: "R1", decision: "DISPUTE" }),
    ],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.disputeCounts.R1, 2);
  assert.equal(result.pipelineState.findingArbitrations[0].direction, "WORKER_CORRECT");
  assert.equal(fixture.calls.arbiter.length, 1);
  assert.match(
    fixture.calls.arbiter[0].prompt,
    /Resolve the disputed finding from the task, plan, repository, diff, and evidence, choosing the correct outcome using the provided schema\./u,
  );
  assert.match(
    fixture.calls.arbiter[0].prompt,
    /Do not ask questions after clarification closes\./u,
  );
  assert.match(
    fixture.calls.arbiter[0].prompt,
    /Prior decisions for this finding[\s\S]*"findingId": "R1"/u,
  );
});

test("requires a fix after the Arbiter upholds the Reviewer", async (t) => {
  const fixture = await createFixture(t, {
    arbiter: [findingArbitration("REVIEWER_CORRECT")],
    workReviewer: [
      reviewFindings("R1"),
      reconsideration("UPHOLD", "R1"),
      reconsideration("UPHOLD", "R1"),
      reviewApproved(),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "DISPUTE" }),
      resolution({ id: "R1", decision: "DISPUTE" }),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
    ],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.fixRounds, 1);
  assert.equal(
    result.pipelineState.findingArbitrations[0].direction,
    "REVIEWER_CORRECT",
  );
  const requiredFix = fixture.calls.worker
    .filter(({ prompt }) => prompt.includes("For each finding below"))
    .at(-1);
  assert.match(requiredFix.prompt, /"direction": "REVIEWER_CORRECT"/u);
  assert.match(requiredFix.prompt, /"findingId": "R1"/u);
});

test("pauses when the same finding survives the configured correction rounds", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [
      reviewFindings("R1"),
      reviewFindings("R1"),
      reviewFindings("R1"),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
    ],
  });

  const result = await fixture.run({
    maxSameFindingRounds: 2,
    stagnationWindowRounds: 10,
  });

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "no_progress");
  assert.deepEqual(result.pause.findingIds, ["R1"]);
  assert.equal(result.counters.fixRounds, 2);
  assert.equal(result.counters.correctionRounds, 2);
});

test("tracks stable findings beyond the bounded diagnostic history", async (t) => {
  const correctionRounds = 33;
  const fixture = await createFixture(t, {
    workReviewer: Array.from(
      { length: correctionRounds + 1 },
      () => reviewFindings("R1"),
    ),
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      ...Array.from({ length: correctionRounds }, () => [
        resolution({ id: "R1", decision: "FIX" }),
        finalizationPassed(),
      ]).flat(),
    ],
  });

  const result = await fixture.run({
    maxFixRoundsPerStep: correctionRounds,
    maxSameFindingRounds: correctionRounds,
    stagnationWindowRounds: correctionRounds + 1,
  });

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "no_progress");
  assert.equal(result.pipelineState.correctionHistory.length, 32);
  assert.equal(result.pipelineState.sameFindingRounds.R1, correctionRounds);
});

test("uses one stagnation arbitration for finding churn", async (t) => {
  const fixture = await createFixture(t, {
    arbiter: [stagnation("RECONSIDER_FINDINGS", ["R3"])],
    workReviewer: [
      reviewFindings("R1"),
      reviewFindings("R2"),
      reviewFindings("R3"),
      reviewApproved(),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
      resolution({ id: "R2", decision: "FIX" }),
      finalizationPassed(),
    ],
  });

  const result = await fixture.run({
    maxSameFindingRounds: 10,
    stagnationWindowRounds: 2,
  });

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.stagnationArbitrationUsed, true);
  assert.equal(
    result.pipelineState.stagnationDirection.direction,
    "RECONSIDER_FINDINGS",
  );
  assert.match(
    fixture.calls.arbiter[0].prompt,
    /Diagnose why the implementation correction loop is not converging and choose the minimal valid next direction using the provided schema\./u,
  );
});

test("routes stagnation rework through Worker, finalization, and review", async (t) => {
  const fixture = await createFixture(t, {
    arbiter: [stagnation("REWORK_IMPLEMENTATION")],
    workReviewer: [
      reviewFindings("R1"),
      reviewFindings("R2"),
      reviewApproved(),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
      implementationCompleted(),
      finalizationPassed(),
    ],
  });

  const result = await fixture.run({
    maxSameFindingRounds: 10,
    stagnationWindowRounds: 1,
  });

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.fixRounds, 2);
  assert.equal(
    result.pipelineState.stagnationDirection.direction,
    "REWORK_IMPLEMENTATION",
  );
  assert.match(
    fixture.calls.worker.findLast(({ prompt }) =>
      prompt.includes("Required rework direction"),
    ).prompt,
    /Required rework direction/u,
  );
});

test("preserves stagnation rework while waiting for fix budget", async (t) => {
  const fixture = await createFixture(t, {
    arbiter: [stagnation("REWORK_IMPLEMENTATION")],
    workReviewer: [
      reviewFindings("R1"),
      reviewFindings("R2"),
      reviewApproved(),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
      implementationCompleted(),
      finalizationPassed(),
    ],
  });

  const paused = await fixture.run({
    maxFixRoundsPerStep: 1,
    maxSameFindingRounds: 10,
    stagnationWindowRounds: 1,
  });

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "fix_limit_reached");
  assert.equal(paused.pause.resumeState, "IMPLEMENT");
  assert.equal(
    paused.pipelineState.implementationDirection.direction,
    "REWORK_IMPLEMENTATION",
  );
  assert.equal(paused.pipelineState.stagnationArbitrationUsed, true);
  assert.equal(fixture.calls.arbiter.length, 1);

  const result = await fixture.run(
    {},
    { type: "extra-fix-rounds", amount: 1 },
  );

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.fixRounds, 2);
  assert.equal(fixture.calls.arbiter.length, 1);
});

test("pauses after stagnation recurs following its one arbitration", async (t) => {
  const fixture = await createFixture(t, {
    arbiter: [stagnation("CONTINUE_FIXES")],
    workReviewer: [
      reviewFindings("R1"),
      reviewFindings("R2"),
      reviewFindings("R3"),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
      resolution({ id: "R2", decision: "FIX" }),
      finalizationPassed(),
    ],
  });

  const result = await fixture.run({
    maxSameFindingRounds: 10,
    stagnationWindowRounds: 1,
  });

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "no_progress");
  assert.equal(result.pause.resumeState, "RESOLVE_FINDINGS");
  assert.equal(fixture.calls.arbiter.length, 1);
});

test("accepts a finite extra fix budget only after exhaustion", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [reviewFindings("R1"), reviewFindings("R2"), reviewApproved()],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
      resolution({ id: "R2", decision: "FIX" }),
      resolution({ id: "R2", decision: "FIX" }),
      finalizationPassed(),
    ],
  });

  const paused = await fixture.run({
    maxFixRoundsPerStep: 1,
    maxSameFindingRounds: 10,
    stagnationWindowRounds: 10,
  });
  assert.equal(paused.pause.reason, "fix_limit_reached");

  const result = await fixture.run({}, { type: "extra-fix-rounds", amount: 1 });

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.additionalFixRounds, 1);
  assert.equal(result.counters.fixRounds, 2);
});

test("overrides one current finding only for its reviewed fingerprint", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [reviewFindings("R1"), reviewFindings("R1")],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
    ],
  });

  const paused = await fixture.run({
    maxFixRoundsPerStep: 1,
    maxSameFindingRounds: 10,
    stagnationWindowRounds: 10,
  });
  assert.equal(paused.pause.reason, "fix_limit_reached");

  const result = await fixture.run(
    {},
    { type: "override-finding", findingId: "R1" },
  );

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.deepEqual(result.pipelineState.findingOverrides, [
    {
      findingId: "R1",
      fingerprint: result.pipelineState.reviewedFingerprint,
    },
  ]);
});

test("preserves an unresolved dispute count when its finding is overridden", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [
      reviewFindings("R1", "R2"),
      reviewFindings("R1", "R2"),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution(
        { id: "R1", decision: "FIX" },
        { id: "R2", decision: "FIX" },
      ),
      finalizationPassed(),
      resolution(
        { id: "R1", decision: "FIX" },
        { id: "R2", decision: "DISPUTE" },
      ),
      resolution({ id: "R1", decision: "FIX" }),
    ],
  });

  const paused = await fixture.run({
    maxFixRoundsPerStep: 1,
    maxSameFindingRounds: 10,
    stagnationWindowRounds: 10,
  });
  assert.equal(paused.pause.reason, "fix_limit_reached");
  assert.equal(paused.pipelineState.disputeCounts.R2, 1);
  assert.deepEqual(paused.pipelineState.disputeHistory, []);

  const result = await fixture.run(
    {},
    { type: "override-finding", findingId: "R2" },
  );

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "fix_limit_reached");
  assert.equal(result.pipelineState.disputeCounts.R2, 1);
  assert.deepEqual(result.pipelineState.findingOverrides, [
    {
      findingId: "R2",
      fingerprint: result.pipelineState.reviewedFingerprint,
    },
  ]);
});

test("checks plan compatibility after a post-start product decision", async (t) => {
  const fixture = await createFixture(t, {
    workWorker: [
      implementationProductDecision(),
      compatibilityReady(),
      implementationCompleted(),
      finalizationPassed(),
    ],
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "product_decision_required");
  assert.equal(paused.pipelineState.pendingEdit.suspendedState, "IMPLEMENT");
  assert.equal(paused.pipelineState.currentStep, 1);
  assert.notEqual(paused.pipelineState.resolvedSummary, null);
  const initialImplementationKey = paused.sessionLineage.children
    .filter(({ role }) => role === "worker")
    .at(-1).contextKey;
  await writeFile(
    fixture.clarificationPath,
    `${await readFile(fixture.clarificationPath, "utf8")}Behavior A.\n`,
  );

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.productDecisions, 1);
  assert.match(fixture.calls.worker[4].prompt, /Review the updated clarifications/u);
  const resumedImplementation = fixture.calls.worker
    .filter(({ prompt }) => prompt.includes("Implement the changes described"))
    .at(-1);
  assert.equal(resumedImplementation.session, undefined);
  assert.equal(
    resumedImplementation.prompt,
    resumedImplementation.recoveryPrompt,
  );
  const resumedImplementationKey = result.sessionLineage.children
    .filter(({ role }) => role === "worker")
    .at(-1).contextKey;
  assert.notEqual(initialImplementationKey, resumedImplementationKey);
});

test("preserves previous findings across a review product decision", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [
      reviewFindings("R1"),
      reviewProductDecision(),
      reviewApproved(),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
      compatibilityReady(),
      implementationCompleted(),
      finalizationPassed(),
    ],
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "product_decision_required");
  assert.deepEqual(paused.pipelineState.previousFindings, [
    reviewFindings("R1").findings[0],
  ]);
  await writeFile(
    fixture.clarificationPath,
    `${await readFile(fixture.clarificationPath, "utf8")}Behavior A.\n`,
  );

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.match(fixture.calls.reviewer[3].prompt, /Previous findings[\s\S]*"id": "R1"/u);
});

test("starts a new dispute episode after a product decision", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [
      reviewFindings("R1"),
      reconsideration("UPHOLD", "R1"),
      reconsiderationProductDecision(),
      reviewFindings("R1"),
      reconsideration("WITHDRAW", "R1"),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "DISPUTE" }),
      resolution({ id: "R1", decision: "DISPUTE" }),
      compatibilityReady(),
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "DISPUTE" }),
    ],
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "product_decision_required");
  assert.deepEqual(paused.pipelineState.disputeCounts, {});
  assert.deepEqual(paused.pipelineState.disputeHistory, []);
  await writeFile(
    fixture.clarificationPath,
    `${await readFile(fixture.clarificationPath, "utf8")}Behavior A.\n`,
  );

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.disputeCounts.R1, 1);
  assert.equal(result.pipelineState.disputeHistory.length, 1);
  assert.equal(result.pipelineState.disputeHistory[0].attempt, 1);
});

test("requires a revised plan when a post-start decision is incompatible", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [],
    workWorker: [implementationProductDecision(), compatibilityPlanRevision()],
  });

  await fixture.run();
  await writeFile(
    fixture.clarificationPath,
    `${await readFile(fixture.clarificationPath, "utf8")}Behavior B.\n`,
  );
  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "plan_revision_required");
  assert.equal(result.pipelineState.currentStep, 1);
  assert.notEqual(result.pipelineState.resolvedSummary, null);
});

test("records a blocking correction when finalization still fails", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [reviewFindings("R1")],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationFailed("F1"),
    ],
  });

  const result = await fixture.run({
    maxFixRoundsPerStep: 1,
    maxSameFindingRounds: 10,
    stagnationWindowRounds: 10,
  });

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "fix_limit_reached");
  assert.equal(result.counters.correctionRounds, 1);
  assert.deepEqual(result.pipelineState.correctionHistory.at(-1), {
    round: 1,
    fingerprint: result.pipelineState.finalizationResult.fingerprint,
    finalizationIssueIds: ["F1"],
    findingIds: [],
  });
  assert.deepEqual(result.pipelineState.sameFindingRounds, {});
});

test("pauses before finalization advances when its skill is unavailable", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [],
    workWorker: [
      implementationCompleted(),
      finalizationUnavailable("SKILL_MISSING"),
    ],
  });

  const result = await fixture.run({
    finalization: ".agents/skills/finalization/SKILL.md",
  });

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "finalization_skill_missing");
  assert.equal(result.pipelineState.finalizationResult, null);
  assert.equal(fixture.calls.reviewer.length, 1);
});

test("retries finalization after its environment blocker clears", async (t) => {
  const fixture = await createFixture(t, {
    workWorker: [
      implementationCompleted(),
      finalizationBlocked(
        "The validation IPC endpoint is unavailable.",
        "The test runner could not open its required IPC channel.",
      ),
      finalizationPassed(),
    ],
  });

  const paused = await fixture.run({
    finalization: ".agents/skills/finalization/SKILL.md",
  });

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "environment_blocked");
  assert.equal(paused.pause.resumeState, "FINALIZE");

  const resumed = await fixture.run({ finalization: "none" });

  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.equal(
    resumed.pipelineState.settings.finalization,
    ".agents/skills/finalization/SKILL.md",
  );
});

test("falls back after an automatically discovered skill is invalid", async (t) => {
  const fixture = await createFixture(t, {
    workWorker: [
      implementationCompleted(),
      finalizationUnavailable("SKILL_INVALID"),
      finalizationPassed(""),
    ],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.finalizationResult.skillPath, null);
  assert.equal(
    fixture.calls.worker.filter(({ prompt }) =>
      prompt.includes("Run the complete project finalization procedure"),
    ).length,
    2,
  );
});

test("rejects finalization changes made before skill validation", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [],
    workWorker: [
      implementationCompleted(),
      finalizationUnavailable("SKILL_MISSING"),
    ],
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes(
          "Run the complete project finalization procedure",
        )
      ) {
        await writeFile(
          join(request.cwd, "source.js"),
          "export const value = 2;\n",
        );
      }
    },
  });

  const result = await fixture.run({
    finalization: ".agents/skills/finalization/SKILL.md",
  });

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "finalization_cannot_pass");
  assert.equal(
    result.pause.code,
    "ERR_FINALIZATION_MODIFIED_BEFORE_VALIDATION",
  );
  assert.equal(result.pipelineState.finalizationResult, null);
  assert.equal(fixture.calls.reviewer.length, 1);
});

test("allows project changes before finalization becomes blocked", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [],
    workWorker: [
      implementationCompleted(),
      finalizationBlocked(
        "The validation process cannot be isolated on this host.",
        "The required process-isolation facility is unavailable.",
      ),
    ],
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes(
          "Run the complete project finalization procedure",
        )
      ) {
        await writeFile(
          join(request.cwd, "source.js"),
          "export const value = 2;\n",
        );
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "environment_blocked");
  assert.equal(result.pause.resumeState, "FINALIZE");
  assert.equal(result.pause.code, undefined);
  assert.equal(result.pipelineState.finalizationResult, null);
  assert.equal(fixture.calls.reviewer.length, 1);
});

test("corrects a missing resolved skill path when finalization is blocked", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [],
    workWorker: [
      implementationCompleted(),
      {
        ...finalizationBlocked(
          "The validation process is externally blocked.",
          "The required validation service is unavailable.",
        ),
        skillPath: "",
      },
      finalizationBlocked(
        "The validation process is externally blocked.",
        "The required validation service is unavailable.",
      ),
    ],
  });

  const paused = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "environment_blocked");
  assert.equal(paused.pipelineState.finalizationCorrection.field, "skillPath");
  assert.equal(
    paused.pipelineState.finalizationCorrection.constraint,
    "resolved-finalization-skill",
  );
});

test("pauses when a Worker changes Git history outside COMMIT", async (t) => {
  const fixture = await createFixture(t, {
    async onRoleRun(role, request) {
      if (role === "worker" && request.prompt.includes("Implement the changes")) {
        await executeFile("git", [
          "-C",
          request.cwd,
          "commit",
          "--allow-empty",
          "-qm",
          "test: unauthorized",
        ]);
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "unexpected_git_ref_change");
  assert.equal(result.pipelineState.finalizationResult, null);
});

test("pauses when a Worker changes remote configuration", async (t) => {
  const fixture = await createFixture(t, {
    async onRoleRun(role, request) {
      if (role === "worker" && request.prompt.includes("Implement the changes")) {
        await executeFile("git", [
          "-C",
          request.cwd,
          "remote",
          "add",
          "origin",
          "https://example.invalid/repository.git",
        ]);
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "unexpected_remote_configuration_change");
});

test("invalidates work when the Reviewer mutates the repository", async (t) => {
  const fixture = await createFixture(t, {
    async onRoleRun(role, request) {
      if (role === "reviewer" && request.prompt.includes("Review the changes")) {
        await writeFile(join(request.cwd, "source.js"), "reviewer mutation\n");
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "read_only_agent_mutated_repository");
  assert.equal(result.pipelineState.currentStep, null);
});

test("requires Reviewer acceptance for planned validation-infrastructure changes", async (t) => {
  const infrastructurePath = "package.json";
  const accepted = await createFixture(t, {
    onRoleRun: async (role, request) => {
      if (
        role === "worker" &&
        request.prompt.includes("Implement the changes")
      ) {
        await writeFile(
          join(request.cwd, infrastructurePath),
          '{"scripts":{"test":"node --test --test-reporter=spec"}}\n',
        );
      }
    },
    workReviewer: [reviewApproved("ACCEPTED")],
  });
  const completed = await accepted.run();
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(
    completed.pipelineState.reviewResult.validationChange,
    "ACCEPTED",
  );
  const reviewPrompt = accepted.calls.reviewer.find(({ prompt }) =>
    prompt.includes("Review the changes"),
  ).prompt;
  assert.match(
    reviewPrompt,
    /Established validation tuple:[\s\S]*Candidate validation tuple and finalization evidence:/u,
  );
  assert.match(
    reviewPrompt,
    /"validationInfrastructureFingerprint": "[a-f0-9]{64}"/u,
  );

  const rejected = await createFixture(t, {
    onRoleRun: async (role, request) => {
      if (
        role === "worker" &&
        request.prompt.includes("Implement the changes")
      ) {
        await writeFile(
          join(request.cwd, infrastructurePath),
          '{"scripts":{"test":"true"}}\n',
        );
      }
    },
  });
  await assert.rejects(
    rejected.run(),
    /inconsistent validation-change decision/u,
  );
});
