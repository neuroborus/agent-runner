import assert from "node:assert/strict";
import test from "node:test";

import {
  CLARIFICATION_INSTRUCTIONS,
  DRAFT_INSTRUCTIONS,
  FINDING_RESOLUTION_INSTRUCTIONS,
  PRODUCT_DECISION_INSTRUCTIONS,
  REVIEW_INSTRUCTIONS,
  STAGNATION_INSTRUCTIONS,
} from "../src/index.js";

test("clarification instructions keep questions before planning", () => {
  assert.equal(
    CLARIFICATION_INSTRUCTIONS,
    `Study the task, existing clarifications, and repository before planning. Ask only questions whose answers could materially change the required behavior, scope, or commit plan. If the available evidence resolves them, return READY without questions.

Do not modify the repository.
Return only READY or actionable clarification questions using the provided schema.`,
  );
});

test("work questions require a blocking product decision", () => {
  assert.equal(
    PRODUCT_DECISION_INSTRUCTIONS,
    `Do not ask questions after clarification closes.
Return PRODUCT_DECISION_REQUIRED using the provided schema only when the task, repository, conventions, and prior clarifications leave a choice between materially different product requirements or behaviors unresolved and progress is otherwise impossible.
Do not use it for technical choices, implementation difficulty, naming, or ordinary review findings.`,
  );
});

test("draft instructions require a minimal idiomatic commit plan", () => {
  assert.equal(
    DRAFT_INSTRUCTIONS,
    `Write a concise commit-by-commit plan for the requested changes. Keep the plan idiomatic and minimal, follow the project's conventions, and ensure it contains no contradictions.

Use contiguous \`## Commit N: type(scope)[!]: imperative summary\` sections starting at 1, with no preamble. Use feat, fix, refactor, perf, test, docs, build, ci, chore, or revert; each heading contains the exact one-line subject-only commit message, at most 72 Unicode code points and without a trailing period. Put implementation details below it.
Do not modify the repository or artifact files.
${PRODUCT_DECISION_INSTRUCTIONS}
Otherwise, return only the draft plan.`,
  );
});

test("review instructions require a correct and consistent plan", () => {
  assert.equal(
    REVIEW_INSTRUCTIONS,
    `Review the plan and verify that it is correct, idiomatic, minimal, consistent with the project's conventions, and free of contradictions.

Use contiguous \`## Commit N: type(scope)[!]: imperative summary\` sections starting at 1, with no preamble. Use feat, fix, refactor, perf, test, docs, build, ci, chore, or revert; each heading contains the exact one-line subject-only commit message, at most 72 Unicode code points and without a trailing period. Put implementation details below it.
Do not modify the repository or artifact files.
${PRODUCT_DECISION_INSTRUCTIONS}
Otherwise, return only the approval decision and actionable findings using the provided schema.`,
  );
});

test("finding resolution instructions preserve the required core", () => {
  assert.equal(
    FINDING_RESOLUTION_INSTRUCTIONS,
    `For each finding below, fix the plan idiomatically and minimally, following the project's conventions.

Use contiguous \`## Commit N: type(scope)[!]: imperative summary\` sections starting at 1, with no preamble. Use feat, fix, refactor, perf, test, docs, build, ci, chore, or revert; each heading contains the exact one-line subject-only commit message, at most 72 Unicode code points and without a trailing period. Put implementation details below it.
Do not modify the repository or artifact files.
${PRODUCT_DECISION_INSTRUCTIONS}
Otherwise, return only the revised plan.`,
  );
});

test("stagnation instructions preserve the required core", () => {
  assert.equal(
    STAGNATION_INSTRUCTIONS,
    "Diagnose why the plan revision loop is not converging and choose the " +
      "minimal valid next direction using the provided schema.",
  );
});
