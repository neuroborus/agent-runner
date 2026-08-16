import assert from "node:assert/strict";
import test from "node:test";

import { MAX_CLARIFICATION_ROUNDS, WORKFLOW_STATES } from "../src/index.js";

test("plan-execution states match the pipeline specification", () => {
  assert.equal(MAX_CLARIFICATION_ROUNDS, 3);
  assert.deepEqual(WORKFLOW_STATES, [
    "CLARIFY",
    "BOOTSTRAP",
    "IMPLEMENT",
    "FINALIZE",
    "REVIEW",
    "RESOLVE_FINDINGS",
    "COMMIT",
    "WAITING_FOR_USER",
    "DONE",
    "FAILED",
  ]);
});
