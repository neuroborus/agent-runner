import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  appendFile,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

import { createClarificationService } from "../../../src/clarifications.js";
import { createGitService } from "../../../src/git.js";
import { createRunStore } from "../../../src/state.js";
import {
  createPolishingState,
  migratePolishingStateV1,
  migratePolishingStateV2,
  migratePolishingStateV3,
  polishingPipeline,
  runPolishing,
} from "../src/index.js";
import {
  assertRun,
  assertSettings,
  MAX_DURABLE_RUN_BYTES,
  MAX_DISPUTE_HISTORY_BYTES,
  MAX_DISPUTES_PER_FINDING,
  normalizeFinalizationResult,
  normalizePipelineState,
} from "../src/workflow-contract.js";

const executeFile = promisify(execFile);
const SOURCE_SESSION = "source-session";
const SETTINGS = Object.freeze({
  finalization: "auto",
  maxFixRounds: 5,
  maxDisputesPerFinding: 2,
  maxSameFindingRounds: 3,
  stagnationWindowRounds: 3,
  trustedChecks: Object.freeze([]),
});
const REQUIRED_CHECKS = Object.freeze([
  Object.freeze({ id: "C1", command: "npm test" }),
]);
const VALIDATION_INFRASTRUCTURE = Object.freeze([
  ".agents/skills/finalization/SKILL.md",
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
    "trustedValidation",
  ]) {
    delete legacy[field];
  }
  if (legacy.settings !== null) {
    const { trustedChecks: _trustedChecks, ...settings } = legacy.settings;
    legacy.settings = settings;
  }
  return legacy;
}

function versionTwoState(state) {
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

function versionThreeState(state) {
  const legacy = { ...state };
  delete legacy.bootstrapCorrections;
  delete legacy.pendingBootstrapCorrection;
  delete legacy.validationMigrationDisagreement;
  return legacy;
}

function versionTwoFailedFinalizationState(
  state,
  { incompleteStatus, workflowState },
) {
  const requiredChecks = Object.freeze([
    ...REQUIRED_CHECKS,
    Object.freeze({ id: "C2", command: "npm run service:test" }),
  ]);
  const finalizationResult = {
    ...state.finalizationResult,
    status: "FAIL",
    summary: "Legacy finalization retained incomplete validation evidence.",
    issues: [
      {
        id: "F1",
        command: "npm test",
        problem: "A required validation check did not pass.",
        evidence: ["The legacy validation gate remained incomplete."],
      },
    ],
    requiredChecks,
    checks: [
      {
        ...state.finalizationResult.checks[0],
        status: "FAIL",
        evidence: ["The legacy check failed."],
      },
      {
        checkId: "C2",
        command: "npm run service:test",
        status: incompleteStatus,
        evidence: ["The legacy check did not complete."],
        executor: "agent",
        commandIdentity: null,
        exitCode: null,
        signal: null,
        timedOut: false,
      },
    ],
    validationChanged: false,
  };
  return versionTwoState({
    ...state,
    workflowState,
    workerValidation: {
      ...state.workerValidation,
      requiredChecks,
    },
    reviewerValidation: {
      ...state.reviewerValidation,
      requiredChecks,
    },
    requiredChecks,
    finalizationResult,
    finalizedFingerprint: null,
    reviewResult: null,
    reviewedFingerprint: null,
    findings: [],
  });
}

function migrateVersionOneState(state) {
  const versionTwo = migratePolishingStateV1({ pipelineState: state });
  const versionThree = migratePolishingStateV2({ pipelineState: versionTwo });
  return migratePolishingStateV3({ pipelineState: versionThree });
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
    reviewer: [
      { ...bootstrapReady("Reviewer"), requiredChecks },
    ],
    worker: [
      clarificationReady(),
      { ...bootstrapReady("Worker"), requiredChecks },
      reconciliationResolved(),
      polishingCompleted(),
      mixedFinalization,
    ],
  });

  await assert.rejects(fixture.run(), (error) => {
    assert.equal(error.code, "ERR_INVALID_POLISHING_OUTPUT");
    assert.match(error.message, /status does not match/u);
    return true;
  });
  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
  assert.equal(fixture.currentRun.pipelineState.finalizationResult, null);
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
    validationInfrastructure: [
      ".agents/skills/finalization/SKILL.md",
      workerPath,
    ],
  };
  const reviewer = {
    ...bootstrapReady("Reviewer"),
    requiredChecks: [
      { id: "C1", command: "npm test" },
      { id: "C7", command: "npm run docs" },
    ],
    validationInfrastructure: [
      ".agents/skills/finalization/SKILL.md",
      reviewerPath,
    ],
  };
  const stop = new Error("polishing turn reached");
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
      if (role === "worker" && /Polish the existing local/u.test(request.prompt)) {
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
    ".agents/skills/finalization/SKILL.md",
    workerPath,
    reviewerPath,
  ]);
});

test("corrects duplicate Worker bootstrap commands once without retaining them", async (t) => {
  const rejectedCommand = "DO_NOT_PERSIST_DUPLICATE_COMMAND";
  const fixture = await createFixture(t, {
    worker: [
      clarificationReady(),
      {
        ...bootstrapReady("Worker"),
        requiredChecks: [
          { id: "C1", command: rejectedCommand },
          { id: "C2", command: rejectedCommand },
        ],
      },
      bootstrapReady("Corrected Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
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
      field: "requiredChecks",
      constraint: "unique-ids-and-commands",
    },
  ]);
  assert.equal(completed.pipelineState.pendingBootstrapCorrection, null);
  assert.match(fixture.calls.worker[2].prompt, /Correction diagnostic/u);
  assert.doesNotMatch(JSON.stringify(completed), /DO_NOT_PERSIST/u);
});

test("corrects a multiline Reviewer bootstrap command once", async (t) => {
  const fixture = await createFixture(t, {
    reviewer: [
      {
        ...bootstrapReady("Reviewer"),
        requiredChecks: [{ id: "C1", command: "npm test\nnpm run lint" }],
      },
      bootstrapReady("Corrected Reviewer"),
      reviewApproved(),
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
      field: "requiredChecks[0].command",
      constraint: "exact-single-line-command-up-to-4000-characters",
    },
  ]);
  assert.match(fixture.calls.reviewer[1].prompt, /one read-only correction/u);
});

test("corrects missing and symlinked validation-infrastructure paths", async (t) => {
  const cases = [
    { name: "missing", invalidPath: "validation/missing.js" },
    {
      name: "symlink alias",
      invalidPath: ".claude/skills/finalization/SKILL.md",
      prepareProject: (projectPath) =>
        symlink(".agents", join(projectPath, ".claude")),
    },
  ];

  for (const testCase of cases) {
    await t.test(testCase.name, async (t) => {
      const fixture = await createFixture(t, {
        prepareProject: testCase.prepareProject,
        worker: [
          clarificationReady(),
          {
            ...bootstrapReady("Worker"),
            validationInfrastructure: [testCase.invalidPath],
          },
          bootstrapReady("Corrected Worker"),
          reconciliationResolved(),
          polishingCompleted(),
          finalizationPassed(),
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

test("reconstructs a persisted bootstrap correction after interruption", async (t) => {
  let interrupted = false;
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
      {
        ...bootstrapReady("Worker"),
        requiredChecks: [
          { id: "C1", command: "npm test" },
          { id: "C2", command: "npm test" },
        ],
      },
      bootstrapReady("Corrected Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
    ],
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pause.resumeState, "BOOTSTRAP");
  assert.deepEqual(
    paused.pipelineState.pendingBootstrapCorrection,
    paused.pipelineState.bootstrapCorrections[0],
  );

  await fixture.recover();
  const completed = await fixture.run();
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.pipelineState.pendingBootstrapCorrection, null);
  assert.match(fixture.calls.worker[3].prompt, /Correction diagnostic/u);
});

test("fails closed after a repeated invalid bootstrap result", async (t) => {
  const rejected = {
    ...bootstrapReady("Worker"),
    requiredChecks: [
      { id: "C1", command: "npm test" },
      { id: "C2", command: "npm test" },
    ],
  };
  const fixture = await createFixture(t, {
    worker: [clarificationReady(), rejected, rejected],
  });

  await assert.rejects(
    fixture.run(),
    (cause) => cause.code === "ERR_INVALID_POLISHING_OUTPUT",
  );

  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
  assert.deepEqual(fixture.currentRun.pause.diagnostic, {
    role: "worker",
    phase: "bootstrap",
    contract: "bootstrap",
    field: "requiredChecks",
    constraint: "unique-ids-and-commands",
  });
  assert.equal(fixture.currentRun.pipelineState.bootstrapCorrections.length, 1);
  assert.equal(fixture.calls.worker.length, 3);
});

test("corrects a classified structured-output failure without provider text", async (t) => {
  const sensitiveMarker = "DO_NOT_PERSIST_PROVIDER_OUTPUT";
  let rejected = false;
  const fixture = await createFixture(t, {
    onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("concise bootstrap summary") &&
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
  assert.doesNotMatch(JSON.stringify(completed), /DO_NOT_PERSIST/u);
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
  assert.equal(polishingPipeline.stateVersion, 4);
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
  assert.equal(migrated.workflowState, "FINALIZE");
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

test("persists repeated invalid validation-migration output as terminal", async (t) => {
  const rejected = {
    ...bootstrapReady("Invalid Migrating Worker"),
    requiredChecks: [
      { id: "C1", command: "npm test" },
      { id: "C2", command: "npm test" },
    ],
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
  assert.equal(fixture.currentRun.pipelineState.validationMigrationPending, true);
  assert.deepEqual(fixture.currentRun.pause.diagnostic, {
    role: "worker",
    phase: "validation-migration",
    contract: "bootstrap",
    field: "requiredChecks",
    constraint: "unique-ids-and-commands",
  });
  assert.equal(fixture.currentRun.pipelineState.bootstrapCorrections.length, 1);
  assert.deepEqual(
    fixture.currentRun.pipelineState.pendingBootstrapCorrection,
    fixture.currentRun.pipelineState.bootstrapCorrections[0],
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
      bootstrapReady("Migrating Reviewer"),
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
      if (role === "worker" && /Resolve every current blocker/u.test(request.prompt)) {
        await writeFile(join(projectPath, "tracked.txt"), "reviewed correction\n");
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
        question: "Which public behavior should the existing changes preserve?",
        whyItMatters: "The answer changes how the dirty implementation is polished.",
      },
    ],
    reason: "",
    ...emptyDecision(),
  };
}

function bootstrapReady(role) {
  return {
    status: "READY",
    summary: `${role} independently understands the dirty change set and finalization procedure.`,
    requiredChecks: REQUIRED_CHECKS,
    validationInfrastructure: VALIDATION_INFRASTRUCTURE,
    reason: "",
    ...emptyDecision(),
  };
}

function reconciliationResolved() {
  return {
    status: "RESOLVED",
    summary:
      "Polish the existing change set within the established repository boundaries.",
    disagreement: "",
    reason: "",
    ...emptyDecision(),
  };
}

function reconciliationDisagreement() {
  return {
    status: "DISAGREEMENT",
    summary: "",
    disagreement: "The roles selected different owning modules.",
    reason: "",
    question: "",
    options: [],
    whyBlocked: "",
    evidence: ["The summaries identify different existing boundaries."],
  };
}

function arbitrationResolved() {
  return {
    direction: "SYNTHESIZE",
    summary: "Use the existing narrow module boundary and preserve the public behavior.",
    rationale: "Repository ownership and tests support the combined interpretation.",
    reason: "",
    ...emptyDecision(),
  };
}

function polishingCompleted() {
  return {
    status: "COMPLETED",
    summary: "Polished the existing changes and completed a concise self-review.",
    reason: "",
    ...emptyDecision(),
  };
}

function polishingBlocked() {
  return {
    status: "BLOCKED",
    summary: "",
    reason: "The required local compiler is temporarily unavailable.",
    question: "",
    options: [],
    whyBlocked: "",
    evidence: [
      "The compiler executable returned a transient availability error.",
    ],
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
    summary: "The complete project validation procedure passed.",
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
        : ["The task authorizes the complete validation change."],
    ...emptyDecision(),
  };
}

function finalizationFailed(id = "F1") {
  return {
    status: "FAIL",
    skillPath: ".agents/skills/finalization/SKILL.md",
    summary: "The validation procedure found a scoped failure.",
    issues: [
      {
        id,
        command: "npm test",
        problem: "A scoped validation failed.",
        evidence: ["The fixture check failed."],
      },
    ],
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

function reviewFindings(id = "R1") {
  return reviewFindingBatch([id]);
}

function reviewFindingBatch(ids) {
  return {
    status: "FINDINGS",
    findings: ids.map((id) => ({
      id,
      file: "tracked.txt",
      problem: `The dirty change is not minimal for ${id}.`,
      reason: "An unnecessary line remains.",
      suggestedAction: "Remove the unnecessary line.",
    })),
    validationChange: "UNCHANGED",
    validationEvidence: [],
    ...emptyDecision(),
  };
}

function resolution(decision, id = decision === "FIX" ? "F1" : "R1") {
  return resolutionBatch([{ id, decision }]);
}

function resolutionBatch(decisions) {
  return {
    status: "RESOLVED",
    decisions: decisions.map(({ id, decision }) => ({
        id,
        decision,
        reason:
          decision === "FIX"
            ? "Applied the minimal scoped correction."
            : "Repository evidence shows the finding is incorrect.",
        evidence:
          decision === "DISPUTE"
            ? ["The current test covers the reported behavior."]
            : [],
      })),
    reason: "",
    ...emptyDecision(),
  };
}

function verboseResolutionBatch(ids) {
  const detail = "worker-evidence".repeat(125);
  return {
    status: "RESOLVED",
    decisions: ids.map((id) => ({
      id,
      decision: "DISPUTE",
      reason: detail,
      evidence: [detail, detail],
    })),
    reason: "",
    ...emptyDecision(),
  };
}

function reconsiderationBatch(direction, ids) {
  return {
    status: "RESOLVED",
    decisions: ids.map((id) => ({
      id,
      direction,
      reason:
        direction === "WITHDRAW"
          ? "The Worker evidence resolves the concern."
          : "The current repository evidence still supports the finding.",
      evidence: [],
    })),
    ...emptyDecision(),
  };
}

function verboseReconsiderationBatch(ids) {
  const detail = "reviewer-evidence".repeat(110);
  return {
    status: "RESOLVED",
    decisions: ids.map((id) => ({
      id,
      direction: "UPHOLD",
      reason: detail,
      evidence: [detail, detail],
    })),
    ...emptyDecision(),
  };
}

function reconsideration(direction = "WITHDRAW", id = "R1") {
  return reconsiderationBatch(direction, [id]);
}

function findingArbitration(direction = "WORKER_CORRECT") {
  return {
    direction,
    rationale: "The recorded repository evidence determines the finding.",
    ...emptyDecision(),
  };
}

function stagnationDirection(direction = "CONTINUE_FIXES") {
  return {
    direction,
    rationale: "The loop is progressing and one more focused fix is warranted.",
    findingIds: [],
    ...emptyDecision(),
  };
}

function productDecision(statusShape) {
  return {
    ...statusShape,
    question: "Should the polished behavior use variant A or variant B?",
    options: ["Variant A", "Variant B"],
    whyBlocked: "The task and repository leave both product behaviors valid.",
    evidence: ["No existing test or convention chooses between the variants."],
  };
}

function capabilities() {
  return {
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
}

async function runGit(repositoryPath, ...argumentsList) {
  return executeFile("git", ["-C", repositoryPath, ...argumentsList]);
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
    dirty = true,
    finalizationSkill = true,
    ignoreArtifacts = true,
    interactive = false,
    onEdit,
    onRoleRun,
    onTrustedValidation,
    prepareProject,
    proactiveClarification = false,
    reviewer = [bootstrapReady("Reviewer"), reviewApproved()],
    sessionIdForRole,
    settings = SETTINGS,
    sourceSession = null,
    taskLocation = "external",
    trustedValidation,
    worker = [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
    ],
    arbiter = [],
  } = {},
) {
  const workspace = await mkdtemp(join(tmpdir(), "agent-runner-polishing-"));
  const projectPath = join(workspace, "project");
  const externalTaskPath = join(workspace, "task");
  const stateRoot = join(workspace, "state");
  await mkdir(projectPath, { recursive: true });
  await runGit(projectPath, "init", "-q");
  await runGit(projectPath, "config", "user.name", "Polishing Test");
  await runGit(projectPath, "config", "user.email", "polishing@example.test");
  await writeFile(
    join(projectPath, ".gitignore"),
    `${ignoreArtifacts ? `${artifactRoot}/\n` : ""}ignored-task/\n`,
  );
  await writeFile(join(projectPath, "tracked.txt"), "base\n");
  await writeFile(join(projectPath, "deleted.txt"), "delete me\n");
  if (finalizationSkill) {
    await mkdir(join(projectPath, ".agents", "skills", "finalization"), {
      recursive: true,
    });
    await writeFile(
      join(projectPath, ".agents", "skills", "finalization", "SKILL.md"),
      "---\nname: finalization\ndescription: Test validation.\n---\n\nRun tests.\n",
    );
  }
  await prepareProject?.(projectPath);

  const taskPath =
    taskLocation === "external" || taskLocation === "symlinked-untracked"
      ? externalTaskPath
      : taskLocation === "ignored"
        ? join(projectPath, "ignored-task")
        : join(projectPath, "task");
  if (taskLocation === "symlinked-untracked") {
    const repositoryTaskPath = join(projectPath, "task");
    await mkdir(repositoryTaskPath, { recursive: true });
    await symlink(repositoryTaskPath, taskPath, "dir");
  } else {
    await mkdir(taskPath, { recursive: true });
  }
  await writeFile(join(taskPath, "task.md"), "# Polish fixture\n");
  if (taskLocation === "tracked" || taskLocation === "dirty-tracked") {
    await runGit(
      projectPath,
      "add",
      ".gitignore",
      "deleted.txt",
      "tracked.txt",
      "task/task.md",
    );
  } else {
    await runGit(
      projectPath,
      "add",
      ".gitignore",
      "deleted.txt",
      "tracked.txt",
    );
  }
  if (finalizationSkill) {
    await runGit(
      projectPath,
      "add",
      ".agents/skills/finalization/SKILL.md",
    );
  }
  await runGit(projectPath, "commit", "-qm", "initialize fixture");
  if (taskLocation === "dirty-tracked") {
    await appendFile(join(taskPath, "task.md"), "Changed input.\n");
  }
  if (dirty) {
    await writeFile(join(projectPath, "change.txt"), "dirty change\n");
  }
  t.after(() => rm(workspace, { recursive: true, force: true }));

  const queues = {
    worker: [...worker],
    reviewer: [...reviewer],
    arbiter: [...arbiter],
  };
  const calls = { worker: [], reviewer: [], arbiter: [] };
  const probes = { worker: 0, reviewer: 0, arbiter: 0 };
  let sessionIndex = 0;
  const adapters = Object.fromEntries(
    Object.keys(queues).map((role) => [
      role,
      {
        async probe() {
          probes[role] += 1;
          return capabilities();
        },
        async run(request) {
          calls[role].push(request);
          await onRoleRun?.(role, request, calls[role].length, { projectPath });
          assert.ok(queues[role].length > 0, `Unexpected ${role} turn.`);
          const structured = queues[role].shift();
          sessionIndex += 1;
          return {
            output: "structured",
            structured,
            sessionId:
              request.session?.mode === "continue"
                ? request.session.id
                : (sessionIdForRole?.(role, sessionIndex) ??
                  `${role}-session-${sessionIndex}`),
          };
        },
      },
    ]),
  );

  const store = createRunStore({ stateRoot });
  let created = await store.createRun({
    pipelineId: "polishing",
    pipelineStateVersion: 4,
    projectPath,
    taskPath,
    roles: {
      worker: { backend: "codex", model: "worker-model" },
      reviewer: { backend: "codex", model: "reviewer-model" },
      arbiter: { backend: "codex", model: "arbiter-model" },
    },
    sourceSession,
    pipelineState: createPolishingState({
      artifactRoot,
      proactiveClarification,
      settings,
      ...(trustedValidation === undefined ? {} : { trustedValidation }),
    }),
    activity: {
      actor: "runner",
      phase: "run",
      kind: "created",
      message: "Polishing test run created.",
    },
  });
  let lease = created.lease;
  let currentRun = created.state;
  t.after(() => lease?.release().catch(() => {}));

  const git = createGitService();
  const clarifications = createClarificationService({
    env: { EDITOR: "fixture-editor" },
    interactive,
    launchEditor: async (_command, transcriptPath) =>
      onEdit?.({ transcriptPath }),
  });
  const runtime = {
    adapters,
    clarifications,
    git,
    trustedValidation: {
      async execute(options) {
        assert.notEqual(onTrustedValidation, undefined);
        return onTrustedValidation(options);
      },
    },
    async readInputs({ taskPath: requestedTaskPath }) {
      const task = await optionalInput(join(requestedTaskPath, "task.md"));
      if (task === null) {
        const error = new Error("task.md is missing.");
        error.code = "ENOENT";
        error.path = join(requestedTaskPath, "task.md");
        throw error;
      }
      return {
        task,
        taskClarifications: await optionalInput(
          join(requestedTaskPath, "clarifications.md"),
        ),
        context: await optionalInput(join(requestedTaskPath, "context.md")),
      };
    },
    async transition(patch, options) {
      currentRun = await store.transitionRun(lease, patch, options);
      return currentRun;
    },
    async startAgentTurn(activeTurn) {
      currentRun = await store.startAgentTurn(lease, activeTurn, {
        activity: {
          actor: activeTurn.role,
          phase: activeTurn.phase,
          kind: "turn-started",
          message: `${activeTurn.role} ${activeTurn.phase} turn started.`,
        },
      });
      return currentRun;
    },
    async finishAgentTurn(activeTurn) {
      currentRun = await store.finishAgentTurn(lease, activeTurn);
      return currentRun;
    },
    async recordChildSession(child, options) {
      currentRun = await store.recordChildSession(lease, child, options);
      return currentRun;
    },
    writeRunArtifact({ path, content }) {
      return store.writeRunArtifact(lease, path, content);
    },
  };

  async function run(action = null) {
    currentRun = await runPolishing({
      action,
      run: currentRun,
      runtime,
      settings,
    });
    return currentRun;
  }

  async function recover() {
    await lease.release();
    const reopened = createRunStore({ stateRoot });
    lease = await reopened.acquireRunLease(currentRun.runId);
    currentRun = await reopened.recoverRun(lease);
    runtime.transition = async (patch, options) => {
      currentRun = await reopened.transitionRun(lease, patch, options);
      return currentRun;
    };
    runtime.startAgentTurn = async (activeTurn) => {
      currentRun = await reopened.startAgentTurn(lease, activeTurn, {
        activity: {
          actor: activeTurn.role,
          phase: activeTurn.phase,
          kind: "turn-started",
          message: `${activeTurn.role} ${activeTurn.phase} turn started.`,
        },
      });
      return currentRun;
    };
    runtime.finishAgentTurn = async (activeTurn) => {
      currentRun = await reopened.finishAgentTurn(lease, activeTurn);
      return currentRun;
    };
    runtime.recordChildSession = async (child, options) => {
      currentRun = await reopened.recordChildSession(lease, child, options);
      return currentRun;
    };
    runtime.writeRunArtifact = ({ path, content }) =>
      reopened.writeRunArtifact(lease, path, content);
    return currentRun;
  }

  async function persistPipelineState(
    pipelineState,
    counters = currentRun.counters,
  ) {
    currentRun = await runtime.transition(
      {
        counters,
        hashes: currentRun.hashes,
        pause: currentRun.pause,
        pipelineState,
      },
      {
        activity: {
          actor: "runner",
          phase: "test",
          kind: "persisted",
          message: "Persisted a recovery test state.",
        },
      },
    );
    return currentRun;
  }

  return {
    calls,
    get currentRun() {
      return currentRun;
    },
    directoryPath: created.directoryPath,
    probes,
    projectPath,
    persistPipelineState,
    recover,
    run,
    runtime,
    taskPath,
  };
}

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
    polishingPipeline.settings.maxDisputesPerFinding.validate(
      unrepresentable,
    ),
    false,
  );
});

test("rejects and refuses to recover inconsistent correction progress", async (t) => {
  const oversizedSessionId = "a".repeat(1_024);
  const fixture = await createFixture(t, {
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
    /persisted progress is invalid/u,
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
  const disputeCounts = Object.fromEntries(
    findings.map(({ id }) => [id, 2]),
  );
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
  assert.throws(
    () => assertRun(oversizedRun),
    /durable size budget/u,
  );

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
      children: [
        ...completed.sessionLineage.children,
        ...paddingChildren,
      ],
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

test("prepares a dirty worktree through independent source-session bootstraps", async (t) => {
  const fixture = await createFixture(t, { sourceSession: SOURCE_SESSION });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.clarificationFrozen, true);
  assert.equal(result.pipelineState.repositoryBaseline.clean, false);
  assert.deepEqual(result.pipelineState.backendVersions, {
    worker: "fake-1.0.0",
    reviewer: "fake-1.0.0",
    arbiter: null,
  });
  assert.deepEqual(
    result.sessionLineage.children.map(({ role }) => role),
    ["worker", "worker", "reviewer", "worker", "reviewer"],
  );
  assert.deepEqual(fixture.calls.worker[0].session, {
    mode: "fork",
    id: SOURCE_SESSION,
  });
  assert.deepEqual(fixture.calls.reviewer[0].session, {
    mode: "fork",
    id: SOURCE_SESSION,
  });
  assert.deepEqual(fixture.calls.worker[1].session, {
    mode: "fork",
    id: SOURCE_SESSION,
  });
  assert.deepEqual(fixture.calls.worker[2].session, {
    mode: "continue",
    id: result.sessionLineage.children[1].sessionId,
  });
  assert.deepEqual(fixture.calls.worker[3].session, {
    mode: "fork",
    id: SOURCE_SESSION,
  });
  assert.deepEqual(fixture.calls.reviewer[1].session, {
    mode: "fork",
    id: SOURCE_SESSION,
  });
  for (const heading of [
    /Task \(/u,
    /Task-level clarifications:/u,
    /Context:/u,
    /Execution clarifications \(/u,
  ]) {
    assert.match(fixture.calls.worker[1].prompt, heading);
    assert.doesNotMatch(fixture.calls.worker[2].prompt, heading);
    assert.match(fixture.calls.worker[2].recoveryPrompt, heading);
  }
  assert.match(
    fixture.calls.worker[3].prompt,
    /Change-set fingerprint before this turn:/u,
  );
  assert.match(fixture.calls.worker[3].prompt, /Resolved bootstrap context:/u);
  assert.doesNotMatch(fixture.calls.reviewer[0].prompt, /Worker independently/u);
  assert.doesNotMatch(fixture.calls.worker[1].prompt, /Reviewer independently/u);
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
  assert.doesNotMatch(finalizationCall.prompt, /Worker polishing summary:/u);
  assert.match(finalizationCall.recoveryPrompt, /Resolved bootstrap context:/u);
  assert.match(finalizationCall.recoveryPrompt, /Worker polishing summary:/u);
  assert.match(fixture.calls.reviewer[1].prompt, /Resolved bootstrap context:/u);
  assert.match(fixture.calls.reviewer[1].prompt, /Worker polishing summary:/u);
  assert.equal(
    fixture.calls.reviewer[1].prompt,
    fixture.calls.reviewer[1].recoveryPrompt,
  );
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
  for (const call of [
    ...fixture.calls.worker.slice(0, 3),
    ...fixture.calls.reviewer,
  ]) {
    assert.equal(call.access, "read-only");
    assert.equal(call.schema.additionalProperties, false);
  }
  for (const call of fixture.calls.worker.slice(3)) {
    assert.equal(call.access, "workspace-write");
    assert.equal(call.schema.additionalProperties, false);
  }
  assert.match(
    await readFile(join(fixture.directoryPath, "context", "resolved.md"), "utf8"),
    /existing change set/u,
  );
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
      result.runId,
      "clarifications.md",
    ),
  );
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
      assert.equal(resumed.pipelineState.finalizationResult.skillPath, skillPath);
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
    ],
  });

  await assert.rejects(
    fixture.run(),
    (error) =>
      error.code === "ERR_INVALID_POLISHING_OUTPUT" &&
      /without selected finalization skill guidance/u.test(error.message),
  );
  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
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

test("accepts staged, unstaged, deleted, and untracked changes as one set", async (t) => {
  const fixture = await createFixture(t, { dirty: false });
  await writeFile(join(fixture.projectPath, "tracked.txt"), "staged change\n");
  await runGit(fixture.projectPath, "add", "tracked.txt");
  await rm(join(fixture.projectPath, "deleted.txt"));
  await writeFile(join(fixture.projectPath, "untracked.txt"), "untracked\n");

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.repositoryBaseline.clean, false);
});

test("pauses clean repositories before creating a clarification artifact", async (t) => {
  const fixture = await createFixture(t, {
    dirty: false,
    reviewer: [],
    worker: [],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "no_changes");
  assert.equal(fixture.calls.worker.length, 0);
  assert.equal(fixture.calls.reviewer.length, 0);
  assert.equal(result.pipelineState.clarificationPath, null);
});

test("resumes preflight after the clarification path becomes ignored", async (t) => {
  const fixture = await createFixture(t, {
    ignoreArtifacts: false,
  });

  const paused = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "local_artifacts_not_ignored");
  assert.equal(paused.pipelineState.clarificationPath, null);

  await appendFile(join(fixture.projectPath, ".gitignore"), "LOCAL_ARTIFACTS/\n");
  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.pause, null);
});

test("resumes preflight after a transient unsafe Git state", async (t) => {
  const fixture = await createFixture(t);
  const git = fixture.runtime.git;
  let preflightCalls = 0;
  fixture.runtime.git = {
    ...git,
    async preflight(options) {
      preflightCalls += 1;
      if (preflightCalls === 1) {
        const error = new Error("Git snapshot raced with another process.");
        error.code = "ERR_GIT_SNAPSHOT_RACE";
        throw error;
      }
      return git.preflight(options);
    },
  };

  const paused = await fixture.run();
  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "unsafe_git_state");
  assert.equal(paused.pipelineState.preflightComplete, false);

  const completed = await fixture.run();
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.pause, null);
});

for (const taskLocation of [
  "dirty-tracked",
  "untracked",
  "symlinked-untracked",
]) {
  test(`rejects ${taskLocation} repository-local task input overlap`, async (t) => {
    const fixture = await createFixture(t, {
      taskLocation,
      reviewer: [],
      worker: [],
    });

    const result = await fixture.run();

    assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
    assert.equal(result.pause.reason, "task_input_overlaps_changes");
    assert.match(result.pause.path, /task\.md$/u);
    assert.equal(fixture.calls.worker.length, 0);
  });
}

test("rejects a tracked task input with an index-only change", async (t) => {
  const fixture = await createFixture(t, {
    taskLocation: "tracked",
    reviewer: [],
    worker: [],
  });
  const taskFile = join(fixture.taskPath, "task.md");
  await appendFile(taskFile, "Staged input change.\n");
  await runGit(fixture.projectPath, "add", "task/task.md");
  await writeFile(taskFile, "# Polish fixture\n");

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "task_input_overlaps_changes");
  assert.match(result.pause.path, /task\.md$/u);
  assert.equal(fixture.calls.worker.length, 0);
});

for (const [name, flag] of [
  ["assume-unchanged", "--assume-unchanged"],
  ["skip-worktree", "--skip-worktree"],
]) {
  test(`rejects tracked task input hidden by ${name}`, async (t) => {
    const fixture = await createFixture(t, {
      dirty: false,
      taskLocation: "tracked",
      reviewer: [],
      worker: [],
    });
    await runGit(fixture.projectPath, "update-index", flag, "task/task.md");
    await appendFile(join(fixture.taskPath, "task.md"), "Hidden change.\n");

    const result = await fixture.run();

    assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
    assert.equal(result.pause.reason, "task_input_overlaps_changes");
    assert.match(result.pause.path, /task\.md$/u);
    assert.equal(fixture.calls.worker.length, 0);
  });

  test(`accepts a hidden-only ${name} worktree change`, async (t) => {
    const fixture = await createFixture(t, { dirty: false });
    await runGit(fixture.projectPath, "update-index", flag, "tracked.txt");
    await writeFile(join(fixture.projectPath, "tracked.txt"), "hidden change\n");

    const result = await fixture.run();

    assert.equal(result.pipelineState.workflowState, "DONE");
    assert.equal(result.pipelineState.repositoryBaseline.clean, false);
  });
}

for (const taskLocation of ["ignored", "tracked"]) {
  test(`accepts ${taskLocation} repository-local immutable task input`, async (t) => {
    const fixture = await createFixture(t, { taskLocation });

    const result = await fixture.run();

    assert.equal(result.pipelineState.workflowState, "DONE");
  });
}

test("pauses for clarification answers and resumes without consuming an extra round", async (t) => {
  const fixture = await createFixture(t, {
    worker: [
      clarificationQuestions(),
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
    ],
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "clarification_answers_required");
  assert.equal(paused.counters.clarificationRounds, 1);
  await appendFile(
    paused.pipelineState.clarificationPath,
    "Use the existing public behavior.\n",
  );

  await fixture.recover();
  const resumed = await fixture.run();

  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.equal(resumed.counters.clarificationRounds, 1);
  assert.equal(resumed.pipelineState.pendingEdit, null);
  assert.equal(fixture.calls.worker[1].session, undefined);
  assert.match(fixture.calls.worker[1].prompt, /Task \(/u);
  assert.notEqual(
    resumed.sessionLineage.children[0].contextKey,
    resumed.sessionLineage.children[1].contextKey,
  );
});

test("accepts an unchanged proactive clarification without consuming a round", async (t) => {
  const fixture = await createFixture(t, {
    interactive: true,
    onEdit: async () => {},
    proactiveClarification: true,
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.proactiveClarificationComplete, true);
  assert.equal(result.counters.clarificationRounds, 0);
});

test("stops after the bounded clarification question rounds", async (t) => {
  const fixture = await createFixture(t, {
    worker: [
      clarificationQuestions(),
      clarificationQuestions(),
      clarificationQuestions(),
      clarificationQuestions(),
    ],
    reviewer: [],
  });

  for (let round = 1; round <= 3; round += 1) {
    const paused = await fixture.run();
    assert.equal(paused.pause.reason, "clarification_answers_required");
    assert.equal(paused.counters.clarificationRounds, round);
    await appendFile(paused.pipelineState.clarificationPath, `Answer ${round}.\n`);
  }

  const exhausted = await fixture.run();
  assert.equal(exhausted.pause.reason, "clarification_limit_reached");
  assert.equal(exhausted.counters.clarificationRounds, 3);
});

test("detects immutable task-input drift during a read-only turn", async (t) => {
  let changed = false;
  const fixture = await createFixture(t, {
    async onRoleRun(role) {
      if (role === "worker" && !changed) {
        changed = true;
        await appendFile(join(fixture.taskPath, "task.md"), "Unexpected drift.\n");
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "task_input_changed");
});

test("detects unauthorized clarification drift during a read-only turn", async (t) => {
  let changed = false;
  const fixture = await createFixture(t, {
    async onRoleRun(role) {
      if (role === "worker" && !changed) {
        changed = true;
        await appendFile(
          fixture.currentRun.pipelineState.clarificationPath,
          "Unexpected clarification drift.\n",
        );
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "clarifications_changed");
});

test("arbitrates a material bootstrap disagreement in a fresh read-only context", async (t) => {
  const fixture = await createFixture(t, {
    arbiter: [arbitrationResolved()],
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationDisagreement(),
      polishingCompleted(),
      finalizationPassed(),
    ],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.bootstrapArbitrationUsed, true);
  assert.equal(fixture.calls.arbiter.length, 1);
  assert.equal(fixture.calls.arbiter[0].access, "read-only");
  assert.equal(fixture.calls.arbiter[0].session, undefined);
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
    const fixture = await createFixture(t, {
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

test("persists and reconstructs an allowlisted failed Claude read-only turn", async (t) => {
  let interrupted = false;
  const fixture = await createFixture(t, {
    async onRoleRun(role) {
      if (role === "worker" && !interrupted) {
        interrupted = true;
        const error = new Error("provider-native secret text");
        error.code = "ERR_CLAUDE_READ_ONLY_TURN_FAILED";
        error.recoverable = true;
        throw error;
      }
    },
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pause.code, "ERR_CLAUDE_READ_ONLY_TURN_FAILED");
  assert.equal(paused.pause.resumeState, "CLARIFY");
  const events = await readFile(
    join(fixture.directoryPath, "events.jsonl"),
    "utf8",
  );
  const eventCount = events
    .trimEnd()
    .split("\n").length;
  assert.ok(eventCount > 1);
  assert.doesNotMatch(events, /provider-native/u);

  const recovered = await fixture.recover();
  assert.equal(recovered.revision, paused.revision);
  const resumed = await fixture.run();
  const resumedRequest = fixture.calls.worker[1];

  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.ok(resumed.revision > recovered.revision);
  assert.equal(resumedRequest.session, undefined);
  assert.equal(resumedRequest.prompt, resumedRequest.recoveryPrompt);
});

test("preserves Worker changes when a valid environment blocker pauses polishing", async (t) => {
  let polishTurns = 0;
  const fixture = await createFixture(t, {
    reviewer: [
      bootstrapReady("Reviewer"),
      reviewApproved(),
      reviewApproved(),
    ],
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
      polishingBlocked(),
      polishingCompleted(),
      finalizationPassed(),
    ],
    async onRoleRun(role, request, _turn, { projectPath }) {
      if (
        role === "worker" &&
        /Polish the existing local/u.test(request.prompt)
      ) {
        polishTurns += 1;
        if (polishTurns === 2) {
          await writeFile(join(projectPath, "tracked.txt"), "safe blocked work\n");
        }
      }
    },
  });

  const completed = await fixture.run();
  const staleFingerprint = completed.pipelineState.finalizedFingerprint;
  await fixture.persistPipelineState({
    ...completed.pipelineState,
    workflowState: "POLISH",
    pendingCorrection: true,
  });

  const paused = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "environment_blocked");
  assert.equal(paused.pause.resumeState, "POLISH");
  assert.equal(paused.pipelineState.finalizationResult, null);
  assert.equal(paused.pipelineState.finalizedFingerprint, null);
  assert.equal(paused.pipelineState.reviewedFingerprint, null);
  assert.notEqual(
    paused.pipelineState.repositoryBaseline.contentFingerprint,
    staleFingerprint,
  );
  assert.equal(
    await readFile(join(fixture.projectPath, "tracked.txt"), "utf8"),
    "safe blocked work\n",
  );

  const recovered = await fixture.recover();
  assert.equal(recovered.revision, paused.revision);
  const resumed = await fixture.run();

  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.equal(resumed.pause, null);
  assert.equal(
    await readFile(join(fixture.projectPath, "tracked.txt"), "utf8"),
    "safe blocked work\n",
  );
});

test("retries permission-blocked finalization", async (t) => {
  const fixture = await createFixture(t, {
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationBlocked(
        "The validation process lacks a required permission.",
        "The required validation resource rejected access.",
      ),
      finalizationPassed(),
    ],
  });

  const paused = await fixture.run();

  assert.equal(paused.pause.reason, "environment_blocked");
  assert.equal(paused.pause.resumeState, "FINALIZE");
  assert.deepEqual(paused.pause.evidence, [
    "The required validation resource rejected access.",
  ]);

  const resumed = await fixture.run();
  assert.equal(resumed.pipelineState.workflowState, "DONE");
});

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
      if (role === "worker" && /Resolve every current blocker/u.test(request.prompt)) {
        await writeFile(join(projectPath, "tracked.txt"), "fixed service input\n");
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
      reviewer: [
        { ...bootstrapReady("Reviewer"), requiredChecks },
      ],
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
      await writeFile(
        join(projectPath, infrastructurePath),
        '{"version":1}\n',
      );
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

test("retries unchanged process-isolation-blocked finding resolution", async (t) => {
  const fixture = await createFixture(t, {
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationFailed(),
      environmentBlocked(
        "The required process isolation is unavailable.",
        "The validation subprocess could not enter its required isolation profile.",
      ),
      resolution("FIX"),
      finalizationPassed(),
    ],
  });

  const paused = await fixture.run();

  assert.equal(paused.pause.reason, "environment_blocked");
  assert.equal(paused.pause.resumeState, "RESOLVE_FINDINGS");
  assert.equal(paused.pipelineState.finalizationResult.status, "FAIL");

  const resumed = await fixture.run();
  assert.equal(resumed.pipelineState.workflowState, "DONE");
});

test("preserves a partial fix before missing-service validation", async (t) => {
  const fixture = await createFixture(t, {
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationFailed(),
      environmentBlocked(
        "A required local validation service is unavailable.",
        "The service health check reported no available endpoint.",
      ),
      finalizationPassed(),
    ],
    async onRoleRun(role, request, _turn, { projectPath }) {
      if (
        role === "worker" &&
        /Resolve every current blocker/u.test(request.prompt)
      ) {
        await writeFile(join(projectPath, "tracked.txt"), "safe partial fix\n");
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
    await readFile(join(fixture.projectPath, "tracked.txt"), "utf8"),
    "safe partial fix\n",
  );

  const recovered = await fixture.recover();
  assert.equal(recovered.pause.reason, "environment_blocked");
  const resumed = await fixture.run();
  assert.equal(resumed.pipelineState.workflowState, "DONE");
});

test("binds finalization changes and review to one fingerprint without committing", async (t) => {
  let beforeFinalizationFingerprint;
  let beforePolishFingerprint;
  const fixture = await createFixture(t, {
    async onRoleRun(role, request, _turn, { projectPath }) {
      if (role === "worker" && /Polish the existing local/u.test(request.prompt)) {
        beforePolishFingerprint = await createGitService().contentFingerprint({
          allowedPaths: [],
          projectPath,
        });
        await writeFile(join(projectPath, "tracked.txt"), "polished\n");
      }
      if (
        role === "worker" &&
        /Run the complete project finalization procedure/u.test(request.prompt)
      ) {
        beforeFinalizationFingerprint =
          await createGitService().contentFingerprint({
            allowedPaths: [],
            projectPath,
          });
        await writeFile(join(projectPath, "generated.txt"), "generated\n");
      }
    },
  });
  const beforeHead = (await runGit(fixture.projectPath, "rev-parse", "HEAD")).stdout.trim();

  const result = await fixture.run();

  const afterHead = (await runGit(fixture.projectPath, "rev-parse", "HEAD")).stdout.trim();
  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(
    result.pipelineState.finalizedFingerprint,
    result.pipelineState.reviewedFingerprint,
  );
  assert.equal(result.pipelineState.finalizationResult.status, "PASS");
  assert.equal(beforeHead, afterHead);
  assert.equal(await readFile(join(fixture.projectPath, "generated.txt"), "utf8"), "generated\n");
  assert.notEqual(beforePolishFingerprint, beforeFinalizationFingerprint);
  const polishCall = fixture.calls.worker.find(({ prompt }) =>
    /Polish the existing local/u.test(prompt),
  );
  const finalizationCall = fixture.calls.worker.find(({ prompt }) =>
    /Run the complete project finalization procedure/u.test(prompt),
  );
  assert.match(polishCall.prompt, new RegExp(beforePolishFingerprint, "u"));
  assert.match(
    finalizationCall.recoveryPrompt,
    new RegExp(beforeFinalizationFingerprint, "u"),
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
      if (role === "worker" && /Resolve every current blocker/u.test(request.prompt)) {
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
      if (role === "worker" && /Resolve every current blocker/u.test(request.prompt)) {
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
    fixture.calls.reviewer.filter(({ prompt }) => /Review the complete/u.test(prompt)).length,
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

test("preserves maximum concurrent dispute attempts through recovery", async (t) => {
  const findingIds = Array.from({ length: 32 }, (_, index) => `R${index + 1}`);
  const fixture = await createFixture(t, {
    arbiter: findingIds.map(() => findingArbitration("WORKER_CORRECT")),
    reviewer: [
      bootstrapReady("Reviewer"),
      reviewFindingBatch(findingIds),
      reconsiderationBatch("UPHOLD", findingIds),
      reconsiderationBatch("UPHOLD", findingIds),
    ],
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
      resolutionBatch(
        findingIds.map((id) => ({ id, decision: "DISPUTE" })),
      ),
      resolutionBatch(
        findingIds.map((id) => ({ id, decision: "DISPUTE" })),
      ),
    ],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.disputeHistory.length, 64);
  assert.equal(result.pipelineState.findingArbitrations.length, 32);
  assert.ok(
    Buffer.byteLength(JSON.stringify(result.pipelineState.disputeHistory)) <=
      MAX_DISPUTE_HISTORY_BYTES,
  );
  assert.ok(
    result.pipelineState.disputeHistory.every(
      ({ workerReason, workerEvidence, reviewerReason }) =>
        workerReason ===
          "Repository evidence shows the finding is incorrect." &&
        workerEvidence[0] ===
          "The current test covers the reported behavior." &&
        reviewerReason ===
          "The current repository evidence still supports the finding.",
    ),
  );
  assert.ok(Buffer.byteLength(JSON.stringify(result)) < 1024 * 1024);
  for (const findingId of findingIds) {
    assert.deepEqual(
      result.pipelineState.disputeHistory
        .filter((entry) => entry.findingId === findingId)
        .map(({ attempt }) => attempt),
      [1, 2],
    );
  }

  const recovered = await fixture.recover();
  assert.equal(recovered.pipelineState.disputeHistory.length, 64);
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
      resolutionBatch(
        findingIds.map((id) => ({ id, decision: "DISPUTE" })),
      ),
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
      if (role === "worker" && /Resolve every current blocker/u.test(request.prompt)) {
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
        await writeFile(join(projectPath, "tracked.txt"), `budget fix ${fix}\n`);
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
  assert.equal(result.pipelineState.disputeHistory.at(-1).direction, "WITHDRAW");
  assert.ok(
    fixture.calls.worker.some(
      ({ prompt }) =>
        /cannot be disputed and must be fixed:[\s\S]*R2/u.test(prompt),
    ),
  );
  const laterReviews = fixture.calls.reviewer.filter(({ prompt }) =>
    /Review the complete current change set independently/u.test(prompt),
  );
  assert.ok(
    laterReviews.slice(2).some(({ prompt }) =>
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
        await writeFile(join(projectPath, "tracked.txt"), `deferred fix ${fix}\n`);
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.disputeCounts.R2, 1);
  assert.equal(result.pipelineState.disputeHistory.at(-1).direction, "WITHDRAW");
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
    reviewer: [
      bootstrapReady("Reviewer"),
      reviewFindings(),
      reviewFindings(),
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
      if (role === "worker" && /Resolve every current blocker/u.test(request.prompt)) {
        await writeFile(join(projectPath, "tracked.txt"), "reviewed correction\n");
      }
    },
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "no_progress");
  const fingerprint = paused.pipelineState.reviewedFingerprint;

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

  const result = await fixture.run({ type: "override-finding", findingId: "R1" });
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
      if (role === "worker" && /Resolve every current blocker/u.test(request.prompt)) {
        fix += 1;
        await writeFile(join(projectPath, "tracked.txt"), `stagnation fix ${fix}\n`);
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

test("invalidates dependent work before product-decision bootstrap re-entry", async (t) => {
  const fixture = await createFixture(t, {
    reviewer: [
      bootstrapReady("Reviewer"),
      productDecision({
        status: "PRODUCT_DECISION_REQUIRED",
        findings: [],
        validationChange: "UNCHANGED",
        validationEvidence: [],
      }),
      bootstrapReady("Reviewer"),
      reviewApproved(),
    ],
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
    ],
  });

  const waiting = await fixture.run();

  assert.equal(waiting.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(waiting.pause.reason, "product_decision_required");
  assert.equal(waiting.pipelineState.pendingEdit.suspendedState, "BOOTSTRAP");
  assert.equal(waiting.pipelineState.polishSummary, null);
  assert.equal(waiting.pipelineState.finalizationResult, null);
  assert.equal(waiting.pipelineState.resolvedSummary, null);
  const { clarificationPath } = waiting.pipelineState;
  const previousWorkerKey = waiting.sessionLineage.children
    .filter(({ role }) => role === "worker")
    .at(-1).contextKey;
  const previousReviewerKey = waiting.sessionLineage.children
    .filter(({ role }) => role === "reviewer")
    .at(-1).contextKey;
  await writeFile(
    clarificationPath,
    `${await readFile(clarificationPath, "utf8")}Behavior A.\n`,
  );

  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  const resumedWork = [
    fixture.calls.worker
      .filter(({ prompt }) => /Polish the existing local/u.test(prompt))
      .at(-1),
    fixture.calls.reviewer
      .filter(({ prompt }) => /Review the complete current/u.test(prompt))
      .at(-1),
  ];
  for (const request of resumedWork) {
    assert.equal(request.session, undefined);
    assert.equal(request.prompt, request.recoveryPrompt);
  }
  assert.notEqual(
    previousWorkerKey,
    completed.sessionLineage.children
      .filter(({ role }) => role === "worker")
      .at(-1).contextKey,
  );
  assert.notEqual(
    previousReviewerKey,
    completed.sessionLineage.children
      .filter(({ role }) => role === "reviewer")
      .at(-1).contextKey,
  );
});

test("preserves safe writable changes across a Claude usage rejection", async (t) => {
  let interrupted = false;
  const fixture = await createFixture(t, {
    async onRoleRun(role, request, _turn, { projectPath }) {
      if (
        role === "worker" &&
        /Polish the existing local/u.test(request.prompt) &&
        !interrupted
      ) {
        interrupted = true;
        await writeFile(join(projectPath, "tracked.txt"), "interrupted polish\n");
        const error = new Error("Claude usage capacity is unavailable.");
        error.code = "ERR_CLAUDE_USAGE_LIMIT";
        error.recoverable = true;
        throw error;
      }
    },
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pause.code, "ERR_CLAUDE_USAGE_LIMIT");
  assert.equal(paused.pause.resumeState, "POLISH");

  await fixture.recover();
  const result = await fixture.run();
  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(
    await readFile(join(fixture.projectPath, "tracked.txt"), "utf8"),
    "interrupted polish\n",
  );
});

test("does not let Claude provider recovery mask a control mutation", async (t) => {
  const fixture = await createFixture(t, {
    async onRoleRun(role, request, _turn, { projectPath }) {
      if (role === "worker" && /Polish the existing local/u.test(request.prompt)) {
        await runGit(
          projectPath,
          "remote",
          "add",
          "unexpected",
          "https://example.invalid/repository.git",
        );
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

test("fails closed after an ambiguous writable Claude process failure", async (t) => {
  let interrupted = false;
  const fixture = await createFixture(t, {
    async onRoleRun(role, request, _turn, { projectPath }) {
      if (
        role === "worker" &&
        /Polish the existing local/u.test(request.prompt) &&
        !interrupted
      ) {
        interrupted = true;
        await writeFile(join(projectPath, "tracked.txt"), "interrupted polish\n");
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
    await readFile(join(fixture.projectPath, "tracked.txt"), "utf8"),
    "interrupted polish\n",
  );
  assert.doesNotMatch(
    await readFile(join(fixture.directoryPath, "events.jsonl"), "utf8"),
    /provider-native/u,
  );
});

test("accounts for a content-changing interrupted correction before recovery", async (t) => {
  let interrupted = false;
  const fixture = await createFixture(t, {
    settings: { ...SETTINGS, maxSameFindingRounds: 1 },
    reviewer: [
      bootstrapReady("Reviewer"),
      reviewFindings(),
      reviewFindings(),
    ],
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
      finalizationPassed(),
    ],
    async onRoleRun(role, request, _turn, { projectPath }) {
      if (
        role === "worker" &&
        /Resolve every current blocker/u.test(request.prompt) &&
        !interrupted
      ) {
        interrupted = true;
        await writeFile(join(projectPath, "tracked.txt"), "interrupted fix\n");
        const error = new Error("Claude provider is unavailable.");
        error.code = "ERR_CLAUDE_PROVIDER_UNAVAILABLE";
        error.recoverable = true;
        throw error;
      }
    },
  });

  const interruptedRun = await fixture.run();
  assert.equal(interruptedRun.pause.reason, "backend_unavailable");
  assert.equal(interruptedRun.pause.resumeState, "FINALIZE");
  assert.equal(interruptedRun.counters.fixRounds, 1);
  assert.equal(interruptedRun.pipelineState.pendingCorrection, true);

  await fixture.recover();
  const resumed = await fixture.run();
  assert.equal(resumed.pause.reason, "no_progress");
  assert.equal(resumed.counters.fixRounds, 1);
  assert.equal(resumed.counters.correctionRounds, 1);
});

test("does not charge an interrupted staging-only correction as a fix", async (t) => {
  let interrupted = false;
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
    async onRoleRun(role, request, _turn, { projectPath }) {
      if (
        role === "worker" &&
        /Resolve every current blocker/u.test(request.prompt) &&
        !interrupted
      ) {
        interrupted = true;
        await runGit(projectPath, "add", "change.txt");
        const error = new Error("Claude provider is unavailable.");
        error.code = "ERR_CLAUDE_PROVIDER_UNAVAILABLE";
        error.recoverable = true;
        throw error;
      }
    },
  });

  const interruptedRun = await fixture.run();
  assert.equal(interruptedRun.pause.reason, "backend_unavailable");
  assert.equal(interruptedRun.pause.resumeState, "RESOLVE_FINDINGS");
  assert.equal(interruptedRun.counters.fixRounds, 0);
  assert.equal(interruptedRun.pipelineState.pendingCorrection, false);

  await fixture.recover();
  const resumed = await fixture.run();
  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.equal(resumed.counters.fixRounds, 0);
});

for (const [name, expectedReason, mutate] of [
  [
    "HEAD",
    "unexpected_git_ref_change",
    async ({ projectPath }) => {
      await runGit(projectPath, "add", "-A");
      await runGit(projectPath, "commit", "-qm", "unauthorized");
    },
  ],
  [
    "refs",
    "unexpected_git_ref_change",
    async ({ projectPath }) => runGit(projectPath, "tag", "unauthorized"),
  ],
  [
    "remotes",
    "unexpected_remote_configuration_change",
    async ({ projectPath }) =>
      runGit(
        projectPath,
        "remote",
        "add",
        "origin",
        "https://example.invalid/polishing.git",
      ),
  ],
  [
    "identity",
    "unexpected_git_identity_change",
    async ({ projectPath }) =>
      runGit(projectPath, "config", "user.name", "Unauthorized Identity"),
  ],
]) {
  test(`rejects writable Worker ${name} mutations`, async (t) => {
    let mutated = false;
    const fixture = await createFixture(t, {
      async onRoleRun(role, request, _turn, paths) {
        if (
          role === "worker" &&
          /Polish the existing local/u.test(request.prompt) &&
          !mutated
        ) {
          mutated = true;
          await mutate(paths);
        }
      },
    });

    const result = await fixture.run();

    assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
    assert.equal(result.pause.reason, expectedReason);
  });
}

test("requires Reviewer acceptance for task-authorized validation changes", async (t) => {
  const fixture = await createFixture(t, {
    onRoleRun: async (role, request) => {
      if (role === "worker" && request.prompt.includes("Polish the existing")) {
        await writeFile(
          join(
            request.cwd,
            ".agents",
            "skills",
            "finalization",
            "SKILL.md",
          ),
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
    prompt.includes("Review the complete current change set"),
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
