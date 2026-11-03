import assert from "node:assert/strict";
import test from "node:test";

import { normalizeReviewResult } from "../pipelines/plan-authoring/src/workflow-contract.js";
import { normalizeFinalizationResult as executionResult } from "../pipelines/plan-execution/src/workflow-contract.js";
import { normalizeFinalizationResult as polishingResult } from "../pipelines/polishing/src/workflow-contract.js";
import {
  largeFinalizationResult,
  sizeEvidenceResult,
  STRUCTURED_RESULT_BYTES,
} from "./support/index.js";

function authoringResult(character) {
  const result = {
    status: "FINDINGS",
    findings: Array.from({ length: 32 }, (_, index) => ({
      id: `finding-${index}`,
      description: "Synthetic repository finding.",
      evidence: Array(32).fill("e"),
    })),
    question: "",
    options: [],
    whyBlocked: "",
    evidence: [],
  };
  return sizeEvidenceResult(
    result,
    result.findings.map(({ evidence }) => evidence),
    character,
  );
}

for (const [pipeline, create, normalize, items] of [
  ["authoring", authoringResult, normalizeReviewResult, "findings"],
  ["execution", largeFinalizationResult, executionResult, "checks"],
  ["polishing", largeFinalizationResult, polishingResult, "checks"],
]) {
  test(`${pipeline} accepts exactly two mebibytes of UTF-8 and rejects one extra byte`, () => {
    for (const character of ["x", "é"]) {
      const result = create(character);
      assert.equal(
        Buffer.byteLength(JSON.stringify(result)),
        STRUCTURED_RESULT_BYTES,
      );
      const accepted = normalize(result);
      assert.deepEqual(accepted[items], result[items]);
      result[items][0].evidence[0] += "x";
      // This slot has room within the existing 4,000-character semantic bound.
      assert.ok(result[items][0].evidence[0].length <= 4000);
      assert.equal(
        Buffer.byteLength(JSON.stringify(result)),
        STRUCTURED_RESULT_BYTES + 1,
      );
      assert.throws(
        () => normalize(result),
        (error) => {
          assert.match(error.message, /too large/u);
          assert.equal(error.diagnostic.constraint, "maximum-2-mebibytes");
          return true;
        },
      );
    }
  });
}
