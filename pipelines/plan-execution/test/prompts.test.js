import assert from "node:assert/strict";
import test from "node:test";

import {
  BOOTSTRAP_ARBITRATION_INSTRUCTIONS,
  BOOTSTRAP_INSTRUCTIONS,
  BOOTSTRAP_RECONCILIATION_INSTRUCTIONS,
  CLARIFICATION_INSTRUCTIONS,
  FINDING_RESOLUTION_INSTRUCTIONS,
  IMPLEMENTATION_INSTRUCTIONS,
  PLAN_COMPATIBILITY_INSTRUCTIONS,
  PRODUCT_DECISION_INSTRUCTIONS,
  REVIEW_INSTRUCTIONS,
} from "../src/index.js";

test("bootstrap instructions preserve independent evidence and arbitration", () => {
  assert.equal(
    BOOTSTRAP_INSTRUCTIONS,
    `Study the repository, task, validated plan, clarifications, project instructions, the project's finalization skill, other relevant skills, tests, and Git history independently and without modifying the repository.
Return a concise bootstrap summary covering the task, relevant architecture and files, invariants, planned commits, risks, and the project's finalization procedure using the provided schema.`,
  );
  assert.equal(
    BOOTSTRAP_RECONCILIATION_INSTRUCTIONS,
    `Reconcile the independent Worker and Reviewer bootstrap summaries using the task, validated plan, repository, and evidence.
Do not force agreement or modify the repository. Return a concise resolved summary, or the remaining material disagreement, using the provided schema.`,
  );
  assert.equal(
    BOOTSTRAP_ARBITRATION_INSTRUCTIONS,
    `Resolve the bootstrap disagreement from the task, plan, repository, and evidence, choosing the minimal valid direction using the provided schema.

Do not modify the repository. Resolve only the recorded disagreement and do not rewrite requirements.`,
  );
});

test("clarification instructions keep questions before implementation", () => {
  assert.equal(
    CLARIFICATION_INSTRUCTIONS,
    `Study the task, validated plan, existing clarifications, and repository before implementation. Ask only questions whose answers could materially change the required behavior, scope, or implementation of the plan.

Do not modify the repository.
If existing clarifications conflict with the validated plan, return PLAN_REVISION_REQUIRED using the provided schema.
Otherwise, return only READY or actionable clarification questions using the provided schema.`,
  );
});

test("work questions require a blocking product decision", () => {
  assert.equal(
    PRODUCT_DECISION_INSTRUCTIONS,
    `Do not ask questions after clarification closes.
Return PRODUCT_DECISION_REQUIRED using the provided schema only when the task, plan, repository, conventions, and prior clarifications leave a choice between materially different product requirements or behaviors unresolved and progress is otherwise impossible.
Do not use it for technical choices, implementation difficulty, naming, or ordinary review findings.`,
  );
});

test("plan compatibility is checked without reopening questions", () => {
  assert.equal(
    PLAN_COMPATIBILITY_INSTRUCTIONS,
    `Review the updated clarifications against the task, validated plan, completed commits, and repository.
Do not ask questions or modify the repository.
Using the provided schema, return READY when compatible; otherwise return PLAN_REVISION_REQUIRED with concise evidence.`,
  );
});

test("work instructions preserve their concise mandatory cores", () => {
  assert.equal(
    IMPLEMENTATION_INSTRUCTIONS,
    `Implement the changes described in the following planned commit. Keep the implementation idiomatic and minimal, and follow the project's conventions.

Work only on this planned commit.
Do not create a commit in this turn.
Before returning, perform a concise self-review.

Do not ask questions after clarification closes.
Return PRODUCT_DECISION_REQUIRED using the provided schema only when the task, plan, repository, conventions, and prior clarifications leave a choice between materially different product requirements or behaviors unresolved and progress is otherwise impossible.
Do not use it for technical choices, implementation difficulty, naming, or ordinary review findings.`,
  );
  assert.equal(
    REVIEW_INSTRUCTIONS,
    `Review the changes and verify that they are correct, idiomatic, minimal, and consistent with the project's conventions.

Do not modify the repository.
Do not ask questions after clarification closes.
Return PRODUCT_DECISION_REQUIRED using the provided schema only when the task, plan, repository, conventions, and prior clarifications leave a choice between materially different product requirements or behaviors unresolved and progress is otherwise impossible.
Do not use it for technical choices, implementation difficulty, naming, or ordinary review findings.
Otherwise, return only the approval decision and actionable findings using the provided schema.`,
  );
  assert.equal(
    FINDING_RESOLUTION_INSTRUCTIONS,
    `For each finding below, fix it idiomatically and minimally, following the project's conventions.
If a finding is incorrect, dispute it with concise evidence instead of changing the code.

Do not create a commit in this turn.
Do not ask questions after clarification closes.
Return PRODUCT_DECISION_REQUIRED using the provided schema only when the task, plan, repository, conventions, and prior clarifications leave a choice between materially different product requirements or behaviors unresolved and progress is otherwise impossible.
Do not use it for technical choices, implementation difficulty, naming, or ordinary review findings.
Otherwise, return each FIX or DISPUTE decision using the provided schema.`,
  );
});
