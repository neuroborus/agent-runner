import assert from "node:assert/strict";
import test from "node:test";

import {
  CHECK_AND_FIX_INSTRUCTIONS,
  CLARIFICATION_INSTRUCTIONS,
  CLEAN_CONFIRM_INSTRUCTIONS,
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
For READY, set questions to [].
For QUESTIONS, provide one or more actionable questions with question and whyItMatters.`,
  );
});

test("work questions require a blocking product decision", () => {
  assert.equal(
    PRODUCT_DECISION_INSTRUCTIONS,
    `Do not ask questions after clarification closes.
A blocking product-decision outcome is allowed only when the task, repository, conventions, and prior clarifications leave a choice between materially different product requirements or behaviors unresolved and progress is otherwise impossible.
Do not use it for technical choices, implementation difficulty, naming, or ordinary review findings.
For that outcome, provide question, whyBlocked, and evidence; options may be [].`,
  );
});

test("draft instructions require a minimal idiomatic commit plan", () => {
  assert.equal(
    DRAFT_INSTRUCTIONS,
    `Write a concise commit-by-commit plan for the requested changes. Keep the plan idiomatic and minimal, follow the project's conventions, and ensure it contains no contradictions.

Use contiguous \`## Commit N: type(scope)[!]: imperative summary\` sections starting at 1, with no preamble. Use feat, fix, refactor, perf, test, docs, build, ci, chore, or revert; each heading contains the exact one-line subject-only commit message, at most 72 Unicode code points and without a trailing period. Put implementation details below it.
Do not modify the repository or artifact files.
${PRODUCT_DECISION_INSTRUCTIONS}
For DRAFT, provide plan; set question and whyBlocked to "", and options and evidence to [].
For PRODUCT_DECISION_REQUIRED, set plan to ""; use the product-decision fields.`,
  );
});

test("review instructions require a correct and consistent plan", () => {
  assert.equal(
    REVIEW_INSTRUCTIONS,
    `Review the plan and verify that it is correct, idiomatic, minimal, consistent with the project's conventions, and free of contradictions.

Use contiguous \`## Commit N: type(scope)[!]: imperative summary\` sections starting at 1, with no preamble. Use feat, fix, refactor, perf, test, docs, build, ci, chore, or revert; each heading contains the exact one-line subject-only commit message, at most 72 Unicode code points and without a trailing period. Put implementation details below it.
Do not modify the repository or artifact files.
${PRODUCT_DECISION_INSTRUCTIONS}
For APPROVED, set findings, options, and evidence to [], and question and whyBlocked to "".
For FINDINGS, provide one or more findings with unique stable lowercase kebab-case IDs, descriptions, and evidence; set question and whyBlocked to "", and options and evidence to [].
For PRODUCT_DECISION_REQUIRED, set findings to []; use the product-decision fields.
Otherwise, return only the approval decision and actionable findings using the provided schema.`,
  );
});

test("lazy convergence preserves the plan review core", () => {
  assert.match(
    CHECK_AND_FIX_INSTRUCTIONS,
    /^Review the plan and verify that it is correct, idiomatic, minimal, consistent with the project's conventions, and free of contradictions\. If you find any problems, fix the plan idiomatically and minimally, following the project's conventions\./u,
  );
  assert.match(CHECK_AND_FIX_INSTRUCTIONS, /For CHANGED, provide/u);
  assert.match(
    CLEAN_CONFIRM_INSTRUCTIONS,
    /^Review the plan and verify that it is correct, idiomatic, minimal, consistent with the project's conventions, and free of contradictions\./u,
  );
  assert.match(CLEAN_CONFIRM_INSTRUCTIONS, /Do not modify/u);
  assert.match(CLEAN_CONFIRM_INSTRUCTIONS, /Return CLEAN only/u);
});

test("finding resolution instructions preserve the required core", () => {
  assert.equal(
    FINDING_RESOLUTION_INSTRUCTIONS,
    `For each finding below, fix the plan idiomatically and minimally, following the project's conventions.

Use contiguous \`## Commit N: type(scope)[!]: imperative summary\` sections starting at 1, with no preamble. Use feat, fix, refactor, perf, test, docs, build, ci, chore, or revert; each heading contains the exact one-line subject-only commit message, at most 72 Unicode code points and without a trailing period. Put implementation details below it.
Do not modify the repository or artifact files.
${PRODUCT_DECISION_INSTRUCTIONS}
For DRAFT, provide plan; set question and whyBlocked to "", and options and evidence to [].
For PRODUCT_DECISION_REQUIRED, set plan to ""; use the product-decision fields.`,
  );
});

test("stagnation instructions preserve the required core", () => {
  assert.equal(
    STAGNATION_INSTRUCTIONS,
    `Diagnose why the plan revision loop is not converging and choose the minimal valid next direction using the provided schema.
Always provide rationale.
For CONTINUE_REVISION or RESTRUCTURE_PLAN, set findingIds, options, and evidence to [], and question and whyBlocked to "".
For RECONSIDER_FINDINGS, provide exactly the current finding IDs; set question and whyBlocked to "", and options and evidence to [].
For PRODUCT_DECISION_REQUIRED, set findingIds to []; use the product-decision fields.`,
  );
});
