import assert from "node:assert/strict";
import test from "node:test";

import {
  BOOTSTRAP_ARBITRATION_INSTRUCTIONS,
  BOOTSTRAP_INSTRUCTIONS,
  BOOTSTRAP_RECONCILIATION_INSTRUCTIONS,
  CLARIFICATION_INSTRUCTIONS,
  PRODUCT_DECISION_INSTRUCTIONS,
} from "../src/index.js";
import {
  BOOTSTRAP_ARBITRATION_SCHEMA,
  BOOTSTRAP_RECONCILIATION_SCHEMA,
  BOOTSTRAP_SCHEMA,
  CLARIFICATION_SCHEMA,
} from "../src/schemas.js";

function assertStrictSchema(schema) {
  assert.equal(schema.type, "object");
  assert.equal(schema.additionalProperties, false);
  assert.deepEqual([...schema.required].sort(), Object.keys(schema.properties).sort());
  assert.ok(Object.isFrozen(schema));
}

test("polishing prompts preserve role and product-decision boundaries", () => {
  assert.match(CLARIFICATION_INSTRUCTIONS, /Do not modify the repository/u);
  assert.match(CLARIFICATION_INSTRUCTIONS, /existing changes/u);
  assert.match(BOOTSTRAP_INSTRUCTIONS, /independently/u);
  assert.match(BOOTSTRAP_INSTRUCTIONS, /finalization skill/u);
  assert.match(BOOTSTRAP_RECONCILIATION_INSTRUCTIONS, /Do not force agreement/u);
  assert.match(BOOTSTRAP_ARBITRATION_INSTRUCTIONS, /Do not modify/u);
  assert.match(PRODUCT_DECISION_INSTRUCTIONS, /Do not ask questions/u);
  assert.match(PRODUCT_DECISION_INSTRUCTIONS, /materially different product/u);
});

test("polishing preparation schemas are strict and deeply frozen", () => {
  for (const schema of [
    CLARIFICATION_SCHEMA,
    BOOTSTRAP_SCHEMA,
    BOOTSTRAP_RECONCILIATION_SCHEMA,
    BOOTSTRAP_ARBITRATION_SCHEMA,
  ]) {
    assertStrictSchema(schema);
  }
  assert.equal(CLARIFICATION_SCHEMA.properties.questions.items.additionalProperties, false);
});
