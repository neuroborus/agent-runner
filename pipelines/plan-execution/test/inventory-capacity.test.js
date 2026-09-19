import assert from "node:assert/strict";
import test from "node:test";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import {
  migratePlanExecutionStateV15,
  planExecutionPipeline,
} from "../src/index.js";
import { BOOTSTRAP_SCHEMA, FINALIZATION_SCHEMA } from "../src/schemas.js";
import {
  MAX_BOOTSTRAP_ITEMS,
  MAX_VALIDATION_ITEMS,
  normalizeBootstrapResult,
  normalizeFinalizationResult,
  normalizePipelineState,
} from "../src/workflow-contract.js";
import {
  bootstrapReady,
  bootstrapCapacityExhausted,
  finalizationPassed,
  createFixture,
  clarificationReady,
  reconciliationResolved,
  implementationCompleted,
  createLegacyRecoveryFixture,
  matchesSchemaSubset,
} from "./support/index.js";

function inventory(count, prefix = "check") {
  return {
    requiredChecks: Array.from({ length: count }, (_, index) => ({
      id: `C${index + 1}`,
      command: `node validation/${prefix}-${index}.js`,
    })),
    validationInfrastructure: Array.from(
      { length: count },
      (_, index) => `validation/${prefix}-${index}.js`,
    ),
  };
}

function finalization(count) {
  const fields = inventory(count);
  return {
    ...finalizationPassed(),
    ...fields,
    checks: fields.requiredChecks.map(({ id, command }) => ({
      checkId: id,
      command,
      status: "PASS",
      evidence: ["Check passed."],
    })),
  };
}

test("execution accepts 256 role items and rejects 257 with check overflow priority", () => {
  assert.equal(MAX_BOOTSTRAP_ITEMS, 256);
  assert.equal(MAX_VALIDATION_ITEMS, 512);
  const ready = { ...bootstrapReady("Worker"), ...inventory(256) };
  assert.ok(matchesSchemaSubset(BOOTSTRAP_SCHEMA, { result: ready }));
  assert.equal(
    normalizeBootstrapResult(ready, "Worker").requiredChecks.length,
    256,
  );
  for (const field of ["requiredChecks", "validationInfrastructure"]) {
    const oversized = { ...ready, [field]: inventory(257)[field] };
    assert.equal(
      matchesSchemaSubset(BOOTSTRAP_SCHEMA, { result: oversized }),
      false,
    );
    assert.throws(
      () => normalizeBootstrapResult(oversized, "Worker"),
      (error) => {
        assert.equal(error.diagnostic.field, field);
        assert.match(error.diagnostic.constraint, /257|256/u);
        return true;
      },
    );
  }
  assert.throws(
    () => normalizeBootstrapResult({ ...ready, ...inventory(257) }, "Worker"),
    (error) => error.diagnostic.field === "requiredChecks",
  );
  const exhausted = bootstrapCapacityExhausted("requiredChecks");
  assert.equal(exhausted.capacityLimit, 256);
  assert.equal(
    normalizeBootstrapResult(exhausted, "Worker").capacityLimit,
    256,
  );
  for (const field of ["requiredChecks", "validationInfrastructure"]) {
    assert.throws(() =>
      normalizeBootstrapResult(
        { ...exhausted, [field]: ready[field] },
        "Worker",
      ),
    );
  }
  assert.throws(() =>
    normalizeBootstrapResult({ ...exhausted, capacityLimit: 64 }, "Worker"),
  );
});

test("execution finalization accepts 512 items and rejects 513 without truncation", () => {
  const valid = finalization(512);
  assert.ok(matchesSchemaSubset(FINALIZATION_SCHEMA, valid));
  const normalized = normalizeFinalizationResult(valid);
  assert.equal(normalized.requiredChecks.length, 512);
  assert.equal(normalized.validationInfrastructure.length, 512);
  assert.equal(normalized.checks.length, 512);
  for (const field of [
    "requiredChecks",
    "validationInfrastructure",
    "checks",
  ]) {
    const oversized = { ...valid, [field]: finalization(513)[field] };
    assert.equal(matchesSchemaSubset(FINALIZATION_SCHEMA, oversized), false);
    assert.throws(() => normalizeFinalizationResult(oversized));
  }
});

test("expanded execution inventories retain structured-output and per-item byte bounds", () => {
  const ready = { ...bootstrapReady("Worker"), ...inventory(256) };
  ready.requiredChecks = ready.requiredChecks.map((check) => ({
    ...check,
    command: `${check.command} ${"x".repeat(1100)}`,
  }));
  assert.throws(
    () => normalizeBootstrapResult(ready, "Worker"),
    (error) => error.diagnostic.constraint === "maximum-256-kibibytes",
  );
  const result = finalization(512);
  result.checks = result.checks.map((check) => ({
    ...check,
    evidence: ["x".repeat(1000)],
  }));
  assert.throws(() => normalizeFinalizationResult(result), /too large/u);
  const tooLong = {
    ...bootstrapReady("Worker"),
    requiredChecks: [{ id: "C1", command: "x".repeat(4001) }],
  };
  assert.throws(() => normalizeBootstrapResult(tooLong, "Worker"));
});

test("version-15 capacity migration preserves legacy 64/128 inventories and completed effects", async (t) => {
  const worker = inventory(64, "worker");
  const reviewer = inventory(64, "reviewer");
  const merged = {
    requiredChecks: [...worker.requiredChecks, ...reviewer.requiredChecks].map(
      ({ command }, index) => ({ id: `C${index + 1}`, command }),
    ),
    validationInfrastructure: [
      ...worker.validationInfrastructure,
      ...reviewer.validationInfrastructure,
    ],
  };
  const fixture = await createFixture(t, {
    worker: [
      clarificationReady(),
      { ...bootstrapReady("Worker"), ...worker },
      reconciliationResolved(),
    ],
    reviewer: [{ ...bootstrapReady("Reviewer"), ...reviewer }],
    workWorker: [
      implementationCompleted(),
      {
        ...finalizationPassed(),
        ...merged,
        checks: merged.requiredChecks.map(({ id, command }) => ({
          checkId: id,
          command,
          status: "PASS",
          evidence: ["Passed."],
        })),
      },
    ],
    async prepareProject(projectPath) {
      await mkdir(join(projectPath, "validation"));
      await Promise.all(
        merged.validationInfrastructure.map((path) =>
          writeFile(join(projectPath, path), "// runner\n"),
        ),
      );
    },
  });
  const completed = await fixture.run();
  assert.ok(completed.pipelineState.completedCommits.length > 0);
  const migrated = migratePlanExecutionStateV15({
    ...completed,
    pipelineStateVersion: 15,
  });
  assert.deepEqual(migrated, completed.pipelineState);
  assert.doesNotThrow(() => normalizePipelineState(migrated));
  assert.equal(migrated.requiredChecks.length, 128);
  assert.equal(migrated.workerValidation.requiredChecks.length, 64);
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
