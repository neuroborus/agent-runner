import assert from "node:assert/strict";
import test from "node:test";

import { MAX_CLARIFICATION_ROUNDS, WORKFLOW_STATES } from "../src/index.js";

test("plan-authoring exposes its explicit persisted states", () => {
  assert.equal(MAX_CLARIFICATION_ROUNDS, 3);
  assert.deepEqual(WORKFLOW_STATES, [
    "CLARIFY",
    "ANALYZE",
    "DRAFT",
    "REVIEW",
    "REVISE",
    "VALIDATE",
    "WRITE_PLAN",
    "WAITING_FOR_USER",
    "DONE",
    "FAILED",
  ]);
});
