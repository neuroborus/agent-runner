import assert from "node:assert/strict";
import test from "node:test";

import { BOOTSTRAP_SCHEMA, FINALIZATION_SCHEMA } from "../src/schemas.js";
import {
  MAX_BOOTSTRAP_ITEMS,
  MAX_VALIDATION_ITEMS,
  normalizeBootstrapResult,
  normalizeFinalizationResult,
} from "../src/workflow-contract.js";
import {
  bootstrapReady,
  bootstrapCapacityExhausted,
  finalizationPassed,
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

test("polishing accepts 256 role items and rejects 257 with check overflow priority", () => {
  assert.equal(MAX_BOOTSTRAP_ITEMS, 256);
  assert.equal(MAX_VALIDATION_ITEMS, 512);
  const ready = { ...bootstrapReady("Worker"), ...inventory(256) };
  for (const field of ["requiredChecks", "validationInfrastructure"]) {
    assert.equal(BOOTSTRAP_SCHEMA.properties[field].maxItems, 256);
  }
  assert.equal(
    normalizeBootstrapResult(ready, "Worker").requiredChecks.length,
    256,
  );
  for (const field of ["requiredChecks", "validationInfrastructure"]) {
    const oversized = { ...ready, [field]: inventory(257)[field] };
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

test("polishing finalization accepts 512 items and rejects 513 without truncation", () => {
  const valid = finalization(512);
  for (const field of [
    "requiredChecks",
    "validationInfrastructure",
    "checks",
  ]) {
    assert.equal(FINALIZATION_SCHEMA.properties[field].maxItems, 512);
  }
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
    assert.throws(() => normalizeFinalizationResult(oversized));
  }
});

test("expanded polishing inventories retain structured-output and per-item byte bounds", () => {
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

test("polishing inventory paths stay canonical and checks stay staging-independent", () => {
  for (const path of [
    "./package.json",
    "a/../package.json",
    "/package.json",
    "a\\b",
    "a//b",
  ]) {
    assert.throws(() =>
      normalizeBootstrapResult(
        { ...bootstrapReady("Worker"), validationInfrastructure: [path] },
        "Worker",
      ),
    );
    assert.throws(() =>
      normalizeFinalizationResult({
        ...finalization(1),
        validationInfrastructure: [path],
      }),
    );
  }
  for (const command of [
    "git diff --cached --check",
    "git add -A",
    "git diff --check",
  ]) {
    assert.throws(() =>
      normalizeBootstrapResult(
        {
          ...bootstrapReady("Worker"),
          requiredChecks: [{ id: "C1", command }],
        },
        "Worker",
      ),
    );
  }
});
