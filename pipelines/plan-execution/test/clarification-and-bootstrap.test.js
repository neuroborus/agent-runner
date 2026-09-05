import assert from "node:assert/strict";
import { mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import {
  createPlanExecutionState,
  migratePlanExecutionStateV9,
  planExecutionPipeline,
} from "../src/index.js";
import { FINALIZATION_SCHEMA } from "../src/schemas.js";
import {
  MAX_BOOTSTRAP_ITEMS,
  MAX_VALIDATION_ITEMS,
  normalizePipelineState,
} from "../src/workflow-contract.js";
import {
  MISSING_BOOTSTRAP_RESPONSE,
  PLAN,
  REQUIRED_CHECKS,
  ROLE_SESSIONS,
  SETTINGS,
  SOURCE_SESSION,
  VALIDATION_INFRASTRUCTURE,
  arbitrationProductDecision,
  arbitrationResolved,
  assertStrictSchema,
  bootstrapCapacityExhausted,
  bootstrapCorrection,
  bootstrapProductDecision,
  bootstrapReady,
  clarificationPlanRevision,
  clarificationQuestions,
  clarificationReady,
  compatibilityPlanRevision,
  compatibilityReady,
  createFixture,
  finalizationPassed,
  hash,
  implementationCompleted,
  reconciliationDisagreement,
  reconciliationProductDecision,
  reconciliationResolved,
  resolution,
  reviewFindings,
} from "./support/index.js";

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
  assert.equal(
    result.pipelineState.clarificationPath,
    fixture.clarificationPath,
  );
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
  assert.match(
    fixture.calls.worker[1].prompt,
    /\.agents.*current plan step explicitly require them.*not a user question/u,
  );
  assert.doesNotMatch(fixture.calls.worker[2].prompt, /\.agents/u);
  assert.match(
    fixture.calls.worker[2].recoveryPrompt,
    /\.agents.*current plan step explicitly require them.*not a user question/u,
  );
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
  assert.match(
    fixture.calls.reviewer[1].prompt,
    /\.agents.*current plan step explicitly require them.*not a user question/u,
  );
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
  assert.match(
    fixture.calls.reviewer[1].prompt,
    /Resolved bootstrap context:/u,
  );
  assert.equal(
    fixture.calls.reviewer[1].prompt,
    fixture.calls.reviewer[1].recoveryPrompt,
  );
  assert.deepEqual(fixture.calls.reviewer[2].session, {
    mode: "continue",
    id: result.sessionLineage.children[4].sessionId,
  });
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
  for (const call of fixture.calls.worker
    .filter(({ access }) => access !== "local-commit")
    .slice(3)) {
    assert.equal(call.access, "workspace-write");
  }
  assert.equal(fixture.calls.worker.at(-1).access, "local-commit");
  for (const call of fixture.calls.reviewer) {
    assert.equal(call.access, "read-only");
  }
  assert.match(
    fixture.artifacts.get("context/worker.md"),
    /Worker understands/u,
  );
  assert.match(
    fixture.artifacts.get("context/reviewer.md"),
    /Reviewer understands/u,
  );
  assert.match(fixture.artifacts.get("context/resolved.md"), /roles agree/u);
});

test("accepts the advertised maximum bootstrap inventory", async (t) => {
  const maximumSummary = "😀".repeat(20_000);
  const requiredChecks = Array.from(
    { length: MAX_BOOTSTRAP_ITEMS },
    (_, index) => ({
      id: `C${index + 1}`,
      command: `node --test test/check-${index + 1}.test.js`,
    }),
  );
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
    requiredChecks: Array.from({ length: MAX_BOOTSTRAP_ITEMS }, (_, index) => ({
      id: `C${index + 1}`,
      command: `node --test validation/${role}-${index + 1}.test.js`,
    })),
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
    reviewer: [{ ...bootstrapReady("Reviewer"), ...reviewerInventory }],
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

  assert.equal(
    state.workerValidation.requiredChecks.length,
    MAX_BOOTSTRAP_ITEMS,
  );
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
  for (const capacityField of ["requiredChecks", "validationInfrastructure"]) {
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
      if (
        role === "worker" &&
        request.prompt.includes("Implement the changes")
      ) {
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

test("batches adjacent staging-dependent bootstrap checks", async (t) => {
  const unsafeCommands = [
    "git add -A && git diff --cached --check",
    "git status --short",
  ];
  const unsafeBootstrap = {
    ...bootstrapReady("Worker"),
    summary: "Worker incorrectly requires a staged handoff.",
    requiredChecks: Array.from({ length: 17 }, (_, index) => ({
      id: `C${index + 1}`,
      command:
        index < 15
          ? `node --test test/focused-${index + 1}.test.js`
          : unsafeCommands[index - 15],
    })),
  };
  const fixture = await createFixture(t, {
    worker: [
      clarificationReady(),
      unsafeBootstrap,
      bootstrapReady("Corrected Worker"),
      reconciliationResolved(),
    ],
    onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("Implement the changes")
      ) {
        assert.doesNotMatch(
          request.prompt,
          /Established required-check inventory/u,
        );
        for (const command of unsafeCommands) {
          assert.doesNotMatch(request.prompt, new RegExp(command, "u"));
        }
      }
    },
  });

  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.deepEqual(completed.pipelineState.bootstrapCorrections, [
    {
      attempt: 1,
      diagnostics: unsafeCommands.map((_, index) => ({
        role: "worker",
        phase: "bootstrap",
        contract: "bootstrap",
        field: `requiredChecks[${index + 15}].command`,
        constraint: "staging-independent-validation-command",
      })),
    },
  ]);
  const correctionActivity = fixture.transitions.find(
    ({ options }) => options.activity?.kind === "bootstrap-correction",
  )?.options.activity;
  assert.equal(
    correctionActivity.message,
    "worker must correct 2 bootstrap contract violations.",
  );
  const correctionCall = fixture.calls.worker.find(({ prompt }) =>
    prompt.includes("Correction diagnostic batch"),
  );
  assert.ok(correctionCall);
  for (const command of unsafeCommands) {
    assert.doesNotMatch(correctionCall.prompt, new RegExp(command, "u"));
  }
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
      cause.diagnostic?.constraint === "staging-independent-validation-command",
  );
  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
  assert.equal(fixture.currentRun.pipelineState.bootstrapCorrections.length, 1);
});

test("persists a forbidden-delegation class for a terminal bootstrap failure", async (t) => {
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

test("corrects a classified adapter structured-output failure without retaining provider text", async (t) => {
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
    bootstrapCorrection({
      role: "worker",
      phase: "bootstrap",
      contract: "bootstrap",
      field: "result",
      constraint: "semantic-contract",
    }),
  ]);
  assert.equal(completed.pipelineState.pendingBootstrapCorrection, null);
  assert.match(fixture.calls.worker[2].prompt, /Correction diagnostic/u);
  assert.equal(fixture.calls.worker[2].session, undefined);
  assert.doesNotMatch(JSON.stringify(fixture.currentRun), /DO_NOT_PERSIST/u);
  assert.doesNotMatch(JSON.stringify(fixture.transitions), /DO_NOT_PERSIST/u);
});

test("fails closed when a classified structured-output correction is also invalid", async (t) => {
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
  assert.equal(fixture.currentRun.pipelineState.bootstrapCorrections.length, 1);
  assert.equal(
    fixture.calls.worker.filter(({ prompt }) =>
      prompt.includes("Provide a concise bootstrap summary"),
    ).length,
    2,
  );
  assert.doesNotMatch(JSON.stringify(fixture.currentRun), /DO_NOT_PERSIST/u);
  assert.doesNotMatch(JSON.stringify(fixture.transitions), /DO_NOT_PERSIST/u);
});

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
    bootstrapCorrection({
      role: "worker",
      phase: "bootstrap",
      contract: "bootstrap",
      field: "requiredChecks[0]",
      constraint: "exact-field-set",
    }),
  ]);
  const correctionActivity = fixture.transitions.find(
    ({ options }) => options.activity?.kind === "bootstrap-correction",
  )?.options.activity;
  assert.match(
    correctionActivity.message,
    /correct 1 bootstrap contract violation/u,
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
    bootstrapCorrection({
      role: "reviewer",
      phase: "bootstrap",
      contract: "bootstrap",
      field: "summary",
      constraint: "concise-markdown-up-to-20000-characters",
    }),
  ]);
  assert.match(fixture.calls.reviewer[1].prompt, /Correction diagnostic/u);
  assert.doesNotMatch(JSON.stringify(fixture.transitions), /DO_NOT_PERSIST/u);
});

test("corrects a symlink alias and preserves the canonical role-only path", async (t) => {
  const aliasPath = ".claude/skills/finalization/SKILL.md";
  const canonicalPath = ".agents/skills/finalization/SKILL.md";
  const validationInfrastructure = [
    canonicalPath,
    ...VALIDATION_INFRASTRUCTURE,
  ];
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
    bootstrapCorrection({
      role: "worker",
      phase: "bootstrap",
      contract: "bootstrap",
      field: "validationInfrastructure[0]",
      constraint: "existing-canonical-repository-file",
    }),
  ]);
  assert.match(
    fixture.calls.worker[2].prompt,
    /validationInfrastructure\[0\]/u,
  );
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
        bootstrapCorrection({
          role: "worker",
          phase: "bootstrap",
          contract: "bootstrap",
          field: "validationInfrastructure[0]",
          constraint: "existing-canonical-repository-file",
        }),
      ]);
    });
  }
});

test("batches staging and inspectable bootstrap path violations without rejected values", async (t) => {
  const sensitiveMarker = "DO_NOT_PERSIST_BOOTSTRAP_BATCH_VALUES";
  const rejectedCommands = [
    `git status --short ${sensitiveMarker}`,
    `git diff --cached --check ${sensitiveMarker}`,
  ];
  const rejectedPaths = [
    `validation/${sensitiveMarker}-one.js`,
    `validation/${sensitiveMarker}-two.js`,
  ];
  const fixture = await createFixture(t, {
    worker: [
      clarificationReady(),
      {
        ...bootstrapReady("Worker"),
        requiredChecks: rejectedCommands.map((command, index) => ({
          id: `C${index + 1}`,
          command,
        })),
        validationInfrastructure: rejectedPaths,
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
      diagnostics: [
        ...rejectedCommands.map((_, index) => ({
          role: "worker",
          phase: "bootstrap",
          contract: "bootstrap",
          field: `requiredChecks[${index}].command`,
          constraint: "staging-independent-validation-command",
        })),
        ...rejectedPaths.map((_, index) => ({
          role: "worker",
          phase: "bootstrap",
          contract: "bootstrap",
          field: `validationInfrastructure[${index}]`,
          constraint: "existing-canonical-repository-file",
        })),
      ],
    },
  ]);
  const correctionCall = fixture.calls.worker.find(({ prompt }) =>
    prompt.includes("Correction diagnostic batch"),
  );
  assert.doesNotMatch(correctionCall.prompt, new RegExp(sensitiveMarker, "u"));
  assert.doesNotMatch(
    JSON.stringify(fixture.transitions),
    new RegExp(sensitiveMarker, "u"),
  );
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

  const [currentCorrection] = paused.pipelineState.bootstrapCorrections;
  const [diagnostic] = currentCorrection.diagnostics;
  const legacyCorrection = {
    attempt: currentCorrection.attempt,
    ...diagnostic,
  };
  const migrated = migratePlanExecutionStateV9({
    pipelineState: {
      ...paused.pipelineState,
      bootstrapCorrections: [legacyCorrection],
      pendingBootstrapCorrection: legacyCorrection,
    },
  });
  assert.deepEqual(migrated.bootstrapCorrections, [currentCorrection]);
  assert.deepEqual(migrated.pendingBootstrapCorrection, currentCorrection);
  assert.doesNotThrow(() => normalizePipelineState(migrated));
  fixture.persistPipelineState(migrated, { pause: paused.pause });

  const completed = await fixture.run();
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.pipelineState.bootstrapCorrections.length, 1);
  assert.equal(completed.pipelineState.pendingBootstrapCorrection, null);
  assert.match(fixture.calls.worker[3].prompt, /Correction diagnostic/u);
  assert.doesNotMatch(JSON.stringify(fixture.transitions), /DO_NOT_PERSIST/u);
});

test("resumes one pending multi-diagnostic bootstrap batch without recounting", async (t) => {
  const sensitiveMarker = "DO_NOT_PERSIST_PENDING_BOOTSTRAP_BATCH";
  let interrupted = false;
  const rejectedCommands = [
    `git status --short ${sensitiveMarker}`,
    `git diff --cached --check ${sensitiveMarker}`,
  ];
  const fixture = await createFixture(t, {
    onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("Correction diagnostic batch") &&
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
        requiredChecks: rejectedCommands.map((command, index) => ({
          id: `C${index + 1}`,
          command,
        })),
      },
      bootstrapReady("Corrected Worker"),
      reconciliationResolved(),
    ],
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pipelineState.bootstrapCorrections.length, 1);
  assert.equal(
    paused.pipelineState.pendingBootstrapCorrection.diagnostics.length,
    2,
  );
  assert.deepEqual(
    paused.pipelineState.pendingBootstrapCorrection,
    paused.pipelineState.bootstrapCorrections[0],
  );

  const completed = await fixture.run();
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.pipelineState.bootstrapCorrections.length, 1);
  assert.equal(completed.pipelineState.pendingBootstrapCorrection, null);
  assert.equal(
    fixture.calls.worker.filter(({ prompt }) =>
      prompt.includes("Correction diagnostic batch"),
    ).length,
    2,
  );
  assert.doesNotMatch(
    JSON.stringify(fixture.transitions),
    new RegExp(sensitiveMarker, "u"),
  );
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
    bootstrapCorrection(fixture.currentRun.pause.diagnostic),
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
    bootstrapCorrection({
      role: "worker",
      phase: "bootstrap",
      contract: "bootstrap",
      field: "result",
      constraint: "semantic-contract",
    }),
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
    worker: [clarificationReady(), unserializable(), unserializable()],
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
        bootstrapCorrection(testCase.diagnostic),
      ]);
      assert.doesNotMatch(
        JSON.stringify(fixture.transitions),
        /DO_NOT_PERSIST/u,
      );
    });
  }
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
  assert.equal(fixture.readClarification(), "");
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
  fixture.writeClarification(`${fixture.readClarification()}Use behavior A.\n`);

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
  assert.equal(fixture.hasClarification(), false);
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
  assert.equal(fixture.hasClarification(), false);
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
    assert.equal(fixture.hasClarification(), false);
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
        await writeFile(
          join(run.projectPath, "source.js"),
          "externally changed\n",
        );
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
        fixture.writeClarification("agent mutation\n");
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
    onEdit: async (_authorization, transcript) => {
      transcript.write(`${transcript.read()}Answer.\n`);
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
  fixture.writeClarification(`${fixture.readClarification()}Behavior A.\n`);

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
  fixture.writeClarification(`${fixture.readClarification()}Behavior A.\n`);

  const resumed = await fixture.run();

  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.equal(resumed.counters.productDecisions, 1);
  assert.match(
    fixture.calls.worker[2].prompt,
    /Review the updated clarifications/u,
  );
  assert.equal(resumed.pipelineState.compatibilityCheckRequired, false);
});

test("retires a corrected product decision before restarting bootstrap", async (t) => {
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
    bootstrapCorrection({
      role: "worker",
      phase: "bootstrap",
      contract: "bootstrap",
      field: "question",
      constraint: "nonempty-plain-text-up-to-4000-characters",
    }),
  ]);
  assert.equal(paused.pipelineState.pendingBootstrapCorrection, null);
  assert.match(
    fixture.calls.worker[2].prompt,
    /Preserve the exceptional PRODUCT_DECISION_REQUIRED outcome/u,
  );
  fixture.writeClarification(`${fixture.readClarification()}Behavior A.\n`);

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
});

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
  fixture.writeClarification(`${fixture.readClarification()}Behavior A.\n`);

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
  fixture.writeClarification(`${fixture.readClarification()}Behavior B.\n`);
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
  assert.equal(fixture.hasClarification(), false);
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
