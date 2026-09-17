import assert from "node:assert/strict";
import test from "node:test";

import {
  BOOTSTRAP_ARBITRATION_INSTRUCTIONS,
  BOOTSTRAP_CORRECTION_INSTRUCTIONS,
  BOOTSTRAP_INSTRUCTIONS,
  BOOTSTRAP_RECONCILIATION_INSTRUCTIONS,
  CANDIDATE_CLEAN_CONFIRM_INSTRUCTIONS,
  CANDIDATE_REVIEW_INSTRUCTIONS,
  CHECK_AND_FIX_INSTRUCTIONS,
  CLARIFICATION_INSTRUCTIONS,
  CLEAN_CONFIRM_INSTRUCTIONS,
  CONFIRMATION_CORRECTION_INSTRUCTIONS,
  DISPUTE_RECONSIDERATION_INSTRUCTIONS,
  FINALIZATION_CORRECTION_INSTRUCTIONS,
  FINALIZATION_INSTRUCTIONS,
  FINALIZATION_RECOVERY_INSTRUCTIONS,
  finalizationBootstrapInstructions,
  finalizationGuidanceInstructions,
  FINDING_ARBITRATION_INSTRUCTIONS,
  FINDING_RESOLUTION_INSTRUCTIONS,
  LAZY_CHECKPOINT_CORRECTION_INSTRUCTIONS,
  POLISH_INSTRUCTIONS,
  PRODUCT_DECISION_INSTRUCTIONS,
  REVIEW_INSTRUCTIONS,
  REVIEW_CORRECTION_INSTRUCTIONS,
  STAGNATION_INSTRUCTIONS,
} from "../src/index.js";
import {
  BOOTSTRAP_ARBITRATION_SCHEMA,
  BOOTSTRAP_RECONCILIATION_SCHEMA,
  BOOTSTRAP_SCHEMA,
  CANDIDATE_CLEAN_CONFIRM_SCHEMA,
  CANDIDATE_REVIEW_SCHEMA,
  CHECK_AND_FIX_SCHEMA,
  CLARIFICATION_SCHEMA,
  CLEAN_CONFIRM_SCHEMA,
  DISPUTE_RECONSIDERATION_SCHEMA,
  FINALIZATION_SCHEMA,
  FINDING_ARBITRATION_SCHEMA,
  FINDING_RESOLUTION_SCHEMA,
  POLISH_SCHEMA,
  REVIEW_SCHEMA,
  STAGNATION_SCHEMA,
} from "../src/schemas.js";
import {
  MAX_BOOTSTRAP_ITEMS,
  MAX_ITEMS,
  MAX_OPTIONS,
  MAX_SUMMARY_LENGTH,
  MAX_TEXT_LENGTH,
  MAX_VALIDATION_ITEMS,
} from "../src/workflow-contract.js";

function assertStrictSchema(schema) {
  assert.equal(schema.type, "object");
  assert.equal(schema.additionalProperties, false);
  assert.deepEqual(
    [...schema.required].sort(),
    Object.keys(schema.properties).sort(),
  );
  assert.ok(Object.isFrozen(schema));
}

function assertSchemaBounds(schema, propertyName = null, parentName = null) {
  if (schema.type === "object") {
    assertStrictSchema(schema);
    for (const [name, property] of Object.entries(schema.properties)) {
      assertSchemaBounds(property, name, propertyName);
    }
    return;
  }
  if (schema.type === "array") {
    const reportBound =
      parentName === "environmentBlockers" && propertyName === "evidence"
        ? 8
        : { artifacts: 32, unsupported: 16 }[propertyName];
    assert.ok(
      propertyName === "options"
        ? schema.maxItems === MAX_OPTIONS
        : reportBound !== undefined
          ? schema.maxItems === reportBound
          : [MAX_ITEMS, MAX_BOOTSTRAP_ITEMS, MAX_VALIDATION_ITEMS].includes(
              schema.maxItems,
            ),
      `${propertyName} must have a deterministic collection bound`,
    );
    assertSchemaBounds(schema.items, propertyName, parentName);
    return;
  }
  if (
    schema.type === "string" &&
    schema.enum === undefined &&
    schema.pattern === undefined
  ) {
    assert.equal(
      schema.maxLength,
      propertyName === "summary" ? MAX_SUMMARY_LENGTH : MAX_TEXT_LENGTH,
      `${propertyName} must have the deterministic text bound`,
    );
  }
}

test("polishing prompts preserve role and product-decision boundaries", () => {
  assert.match(CLARIFICATION_INSTRUCTIONS, /Do not modify the repository/u);
  assert.match(CLARIFICATION_INSTRUCTIONS, /existing changes/u);
  assert.match(BOOTSTRAP_INSTRUCTIONS, /independently/u);
  assert.match(BOOTSTRAP_INSTRUCTIONS, /finalization guidance/u);
  assert.match(BOOTSTRAP_INSTRUCTIONS, /IDs must be unique/u);
  assert.match(BOOTSTRAP_INSTRUCTIONS, /unique, single-line/u);
  assert.match(BOOTSTRAP_INSTRUCTIONS, /canonical repository-relative/u);
  assert.match(BOOTSTRAP_INSTRUCTIONS, /symlink alias/u);
  assert.match(BOOTSTRAP_INSTRUCTIONS, /capacity of 256 items/u);
  assert.match(BOOTSTRAP_INSTRUCTIONS, /CAPACITY_EXHAUSTED/u);
  assert.match(BOOTSTRAP_INSTRUCTIONS, /staging-independent/u);
  assert.match(BOOTSTRAP_INSTRUCTIONS, /HEAD or explicit trees/u);
  assert.match(BOOTSTRAP_INSTRUCTIONS, /only to HANDOFF/u);
  assert.match(BOOTSTRAP_CORRECTION_INSTRUCTIONS, /one read-only correction/u);
  assert.match(BOOTSTRAP_CORRECTION_INSTRUCTIONS, /rejected command/u);
  assert.match(BOOTSTRAP_CORRECTION_INSTRUCTIONS, /staging-dependent/u);
  assert.match(BOOTSTRAP_CORRECTION_INSTRUCTIONS, /rejected result/u);
  assert.match(BOOTSTRAP_CORRECTION_INSTRUCTIONS, /fails closed/u);
  assert.match(
    FINALIZATION_CORRECTION_INSTRUCTIONS,
    /one read-only correction/u,
  );
  assert.match(
    FINALIZATION_CORRECTION_INSTRUCTIONS,
    /same finalization schema/u,
  );
  assert.match(
    FINALIZATION_CORRECTION_INSTRUCTIONS,
    /Re-execute only corrected staging-independent checks/u,
  );
  assert.match(
    FINALIZATION_CORRECTION_INSTRUCTIONS,
    /Do not execute the rejected command/u,
  );
  assert.match(
    FINALIZATION_CORRECTION_INSTRUCTIONS,
    /modify repository content, staging, history, refs, remotes, or Git identity/u,
  );
  assert.match(FINALIZATION_CORRECTION_INSTRUCTIONS, /fails closed/u);
  assert.match(
    BOOTSTRAP_RECONCILIATION_INSTRUCTIONS,
    /Do not force agreement/u,
  );
  assert.match(BOOTSTRAP_ARBITRATION_INSTRUCTIONS, /Do not modify/u);
  for (const instructions of [
    BOOTSTRAP_RECONCILIATION_INSTRUCTIONS,
    BOOTSTRAP_ARBITRATION_INSTRUCTIONS,
  ]) {
    assert.match(instructions, /staging-independent/u);
    assert.match(instructions, /input only to the dedicated FINALIZE/u);
    assert.match(instructions, /runner derives the final required-check/u);
    assert.match(instructions, /Do not propose, select, or repeat commands/u);
    assert.doesNotMatch(instructions, /provide .*requiredChecks/iu);
  }
  for (const schema of [
    BOOTSTRAP_RECONCILIATION_SCHEMA,
    BOOTSTRAP_ARBITRATION_SCHEMA,
  ]) {
    assert.equal(Object.hasOwn(schema.properties, "requiredChecks"), false);
    assert.equal(
      Object.hasOwn(schema.properties, "validationInfrastructure"),
      false,
    );
  }
  assert.match(PRODUCT_DECISION_INSTRUCTIONS, /Do not ask questions/u);
  assert.match(PRODUCT_DECISION_INSTRUCTIONS, /materially different product/u);
  assert.match(POLISH_INSTRUCTIONS, /Do not create a commit/u);
  assert.match(POLISH_INSTRUCTIONS, /runner alone stages/u);
  assert.match(POLISH_INSTRUCTIONS, /Do not stage or unstage/u);
  assert.match(POLISH_INSTRUCTIONS, /self-review/u);
  assert.match(POLISH_INSTRUCTIONS, /external environment constraints/u);
  assert.match(POLISH_INSTRUCTIONS, /required-check inventory is input only/u);
  assert.match(FINALIZATION_INSTRUCTIONS, /finalization procedure/u);
  assert.match(FINALIZATION_INSTRUCTIONS, /Do not.*stage/u);
  assert.match(FINALIZATION_INSTRUCTIONS, /staged\/index-relative inspection/u);
  assert.match(FINALIZATION_INSTRUCTIONS, /HEAD or explicit trees/u);
  assert.match(FINALIZATION_INSTRUCTIONS, /HANDOFF alone stages/u);
  assert.match(FINALIZATION_INSTRUCTIONS, /external constraints/u);
  assert.match(FINALIZATION_INSTRUCTIONS, /Do not weaken sandboxing/u);
  assert.match(REVIEW_INSTRUCTIONS, /Do not modify/u);
  assert.match(REVIEW_INSTRUCTIONS, /stable IDs/u);
  assert.match(CANDIDATE_REVIEW_INSTRUCTIONS, /semantic candidate/u);
  assert.match(CANDIDATE_REVIEW_INSTRUCTIONS, /Do not run.*finalization/u);
  assert.match(REVIEW_CORRECTION_INSTRUCTIONS, /candidate-review/u);
  assert.match(CONFIRMATION_CORRECTION_INSTRUCTIONS, /terminal-confirmation/u);
  assert.match(
    CHECK_AND_FIX_INSTRUCTIONS,
    /correct, idiomatic, minimal, and consistent/u,
  );
  assert.match(CHECK_AND_FIX_INSTRUCTIONS, /For CHANGED, use only/u);
  assert.match(
    CHECK_AND_FIX_INSTRUCTIONS,
    /no supplied candidate-confirmation finding remains/u,
  );
  assert.match(CHECK_AND_FIX_INSTRUCTIONS, /Do not stage, unstage, or commit/u);
  assert.match(
    CLEAN_CONFIRM_INSTRUCTIONS,
    /correct, idiomatic, minimal, and consistent/u,
  );
  assert.match(CLEAN_CONFIRM_INSTRUCTIONS, /Do not modify the repository/u);
  assert.match(
    LAZY_CHECKPOINT_CORRECTION_INSTRUCTIONS,
    /same checkpoint schema/u,
  );
  assert.match(
    LAZY_CHECKPOINT_CORRECTION_INSTRUCTIONS,
    /CHECK_AND_FIX correction remains workspace-writable/u,
  );
  assert.match(
    LAZY_CHECKPOINT_CORRECTION_INSTRUCTIONS,
    /CLEAN_CONFIRM correction remains repository-read-only/u,
  );
  assert.match(
    LAZY_CHECKPOINT_CORRECTION_INSTRUCTIONS,
    /must not change the index/u,
  );
  assert.match(
    LAZY_CHECKPOINT_CORRECTION_INSTRUCTIONS,
    /handoff evidence early/u,
  );
  assert.match(CLEAN_CONFIRM_INSTRUCTIONS, /Return CLEAN only/u);
  assert.match(CANDIDATE_CLEAN_CONFIRM_INSTRUCTIONS, /Return CLEAN only/u);
  assert.match(
    CANDIDATE_CLEAN_CONFIRM_INSTRUCTIONS,
    /Do not run the project finalization procedure/u,
  );
  assert.match(FINDING_RESOLUTION_INSTRUCTIONS, /one batch/u);
  assert.match(FINDING_RESOLUTION_INSTRUCTIONS, /runner owns final staging/u);
  assert.match(
    FINDING_RESOLUTION_INSTRUCTIONS,
    /established required-check inventory/u,
  );
  assert.match(FINDING_RESOLUTION_INSTRUCTIONS, /For BLOCKED/u);
  assert.match(DISPUTE_RECONSIDERATION_INSTRUCTIONS, /Withdraw/u);
  assert.match(FINDING_ARBITRATION_INSTRUCTIONS, /WORKER_CORRECT/u);
  assert.match(STAGNATION_INSTRUCTIONS, /cannot approve/u);
  assert.match(finalizationBootstrapInstructions("auto"), /conventional/u);
  assert.match(finalizationBootstrapInstructions("none"), /do not skip/u);
  assert.match(
    finalizationGuidanceInstructions({
      required: false,
      skillPath: null,
    }),
    /repository instructions and project-defined checks/u,
  );
  assert.match(
    finalizationGuidanceInstructions({
      required: true,
      skillPath: "checks/finalize/SKILL.md",
    }),
    /missing, escaping, or invalid skill is blocking/u,
  );
});

test("polishing schemas are strict, bounded, and deeply frozen", () => {
  for (const schema of [
    CLARIFICATION_SCHEMA,
    BOOTSTRAP_SCHEMA,
    BOOTSTRAP_RECONCILIATION_SCHEMA,
    BOOTSTRAP_ARBITRATION_SCHEMA,
    POLISH_SCHEMA,
    CANDIDATE_REVIEW_SCHEMA,
    CANDIDATE_CLEAN_CONFIRM_SCHEMA,
    FINALIZATION_SCHEMA,
    CHECK_AND_FIX_SCHEMA,
    CLEAN_CONFIRM_SCHEMA,
    REVIEW_SCHEMA,
    FINDING_RESOLUTION_SCHEMA,
    DISPUTE_RECONSIDERATION_SCHEMA,
    FINDING_ARBITRATION_SCHEMA,
    STAGNATION_SCHEMA,
  ]) {
    assertSchemaBounds(schema);
  }
});

test("terminal recovery instructions distinguish evidence from content without weakening the gate", () => {
  for (const prompt of [REVIEW_INSTRUCTIONS, CLEAN_CONFIRM_INSTRUCTIONS]) {
    assert.match(prompt, /finalizationFindingIds as the unique subset/u);
    assert.match(prompt, /requiring no repository edit/u);
    assert.match(prompt, /Split mixed evidence and content concerns/u);
    assert.match(
      prompt,
      /Evidence rejection is valid even when inventories are unchanged/u,
    );
  }
  for (const schema of [REVIEW_SCHEMA, CLEAN_CONFIRM_SCHEMA]) {
    assert.ok(schema.required.includes("finalizationFindingIds"));
    assert.equal(schema.properties.finalizationFindingIds.maxItems, MAX_ITEMS);
  }
  for (const schema of [
    CANDIDATE_REVIEW_SCHEMA,
    CANDIDATE_CLEAN_CONFIRM_SCHEMA,
  ]) {
    assert.equal(
      Object.hasOwn(schema.properties, "finalizationFindingIds"),
      false,
    );
  }
  assert.match(
    FINALIZATION_RECOVERY_INSTRUCTIONS,
    /complete project finalization procedure again/u,
  );
  assert.match(
    FINALIZATION_RECOVERY_INSTRUCTIONS,
    /never authorize omitting, substituting, removing, or weakening/u,
  );
  assert.match(
    FINALIZATION_RECOVERY_INSTRUCTIONS,
    /do not reuse the rejected PASS/u,
  );
});

test("writable candidate instructions defer checks without suppressing unrelated blockers", () => {
  for (const instructions of [
    POLISH_INSTRUCTIONS,
    CHECK_AND_FIX_INSTRUCTIONS,
    FINDING_RESOLUTION_INSTRUCTIONS,
  ]) {
    assert.match(instructions, /Do not execute or attest it in this turn/u);
    assert.match(instructions, /must never execute inside an agent turn/u);
    assert.match(instructions, /must not cause BLOCKED/u);
    assert.match(
      instructions,
      /applicable content repairs and semantic review/u,
    );
    assert.match(
      instructions,
      /work not delegated to a selected runner-trusted command/u,
    );
    assert.doesNotMatch(
      instructions,
      /NOT_RUN|requiredChecks|validationInfrastructure/u,
    );
  }
});

test("polishing discovery and finalization classify infrastructure by responsibility", () => {
  for (const instructions of [
    BOOTSTRAP_INSTRUCTIONS,
    FINALIZATION_INSTRUCTIONS,
  ]) {
    assert.match(
      instructions,
      /own validation commands, discovery, runners, configuration, or mandatory finalization guidance/u,
    );
    assert.match(
      instructions,
      /Exclude ordinary source, individual tests, fixtures, and generated output merely consumed by checks/u,
    );
    assert.match(instructions, /responsibility, not its name or extension/u);
  }
  assert.match(
    BOOTSTRAP_INSTRUCTIONS,
    /Check requiredChecks first, then validationInfrastructure/u,
  );
});
