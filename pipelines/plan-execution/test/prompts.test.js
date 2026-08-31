import assert from "node:assert/strict";
import test from "node:test";

import {
  BOOTSTRAP_ARBITRATION_INSTRUCTIONS,
  BOOTSTRAP_CORRECTION_INSTRUCTIONS,
  BOOTSTRAP_INSTRUCTIONS,
  BOOTSTRAP_RECONCILIATION_INSTRUCTIONS,
  CLARIFICATION_INSTRUCTIONS,
  COMMIT_INSTRUCTIONS,
  DISPUTE_RECONSIDERATION_INSTRUCTIONS,
  FINALIZATION_CORRECTION_INSTRUCTIONS,
  FINALIZATION_INSTRUCTIONS,
  finalizationBootstrapInstructions,
  finalizationGuidanceInstructions,
  FINDING_ARBITRATION_INSTRUCTIONS,
  FINDING_RESOLUTION_INSTRUCTIONS,
  IMPLEMENTATION_INSTRUCTIONS,
  PLAN_COMPATIBILITY_INSTRUCTIONS,
  PRODUCT_DECISION_INSTRUCTIONS,
  REVIEW_INSTRUCTIONS,
  STAGNATION_INSTRUCTIONS,
} from "../src/index.js";

test("bootstrap instructions preserve independent evidence and arbitration", () => {
  assert.match(BOOTSTRAP_INSTRUCTIONS, /schema's result object/u);
  assert.match(BOOTSTRAP_INSTRUCTIONS, /Required-check IDs must be unique/u);
  assert.match(BOOTSTRAP_INSTRUCTIONS, /Exact commands must be unique/u);
  assert.match(BOOTSTRAP_INSTRUCTIONS, /canonical repository-relative file paths/u);
  assert.match(BOOTSTRAP_INSTRUCTIONS, /symlink alias/u);
  assert.match(BOOTSTRAP_INSTRUCTIONS, /independently identify every required check/iu);
  assert.match(BOOTSTRAP_INSTRUCTIONS, /validationInfrastructure/u);
  assert.match(BOOTSTRAP_INSTRUCTIONS, /capacity of 64 items/u);
  assert.match(BOOTSTRAP_INSTRUCTIONS, /CAPACITY_EXHAUSTED/u);
  assert.match(BOOTSTRAP_INSTRUCTIONS, /keep the summary and required-check inventory staging-independent/u);
  assert.match(BOOTSTRAP_INSTRUCTIONS, /against HEAD or explicit trees/u);
  assert.match(
    BOOTSTRAP_RECONCILIATION_INSTRUCTIONS,
    /runner derives the final required-check/u,
  );
  assert.match(
    BOOTSTRAP_ARBITRATION_INSTRUCTIONS,
    /runner derives the final required-check/u,
  );
  for (const instructions of [
    BOOTSTRAP_RECONCILIATION_INSTRUCTIONS,
    BOOTSTRAP_ARBITRATION_INSTRUCTIONS,
  ]) {
    assert.match(instructions, /Do not propose, select, or repeat commands/u);
    assert.match(instructions, /belong only to COMMIT/u);
    assert.doesNotMatch(instructions, /provide .*requiredChecks/iu);
  }
  assert.match(BOOTSTRAP_CORRECTION_INSTRUCTIONS, /one read-only correction/u);
  assert.match(BOOTSTRAP_CORRECTION_INSTRUCTIONS, /complete replacement/u);
  assert.match(BOOTSTRAP_CORRECTION_INSTRUCTIONS, /ordinary clarification question/u);
  assert.match(BOOTSTRAP_CORRECTION_INSTRUCTIONS, /PRODUCT_DECISION_REQUIRED/u);
  assert.match(BOOTSTRAP_CORRECTION_INSTRUCTIONS, /repeated invalid result fails closed/u);
  assert.match(
    FINALIZATION_CORRECTION_INSTRUCTIONS,
    /bounded read-only correction/u,
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
    /Do not execute a rejected command/u,
  );
  assert.match(
    FINALIZATION_CORRECTION_INSTRUCTIONS,
    /modify repository content, staging, history, refs, remotes, or Git identity/u,
  );
  assert.match(
    FINALIZATION_CORRECTION_INSTRUCTIONS,
    /wholly new diagnostic batch/u,
  );
  assert.match(
    FINALIZATION_CORRECTION_INSTRUCTIONS,
    /repeated diagnostic or another invalid result after that finite allowance fails closed/u,
  );
});

test("clarification instructions keep questions before implementation", () => {
  assert.equal(
    CLARIFICATION_INSTRUCTIONS,
    `Study the task, validated plan, existing clarifications, and repository before implementation. Ask only questions whose answers could materially change the required behavior, scope, or implementation of the plan.

Do not modify the repository.
If existing clarifications conflict with the validated plan, use PLAN_REVISION_REQUIRED.
For READY, return exactly {"status":"READY","questions":[],"reason":"","question":"","options":[],"whyBlocked":"","evidence":[]}.
For QUESTIONS, provide one or more actionable questions with question and whyItMatters; set reason, question, and whyBlocked to "", and options and evidence to [].
For PLAN_REVISION_REQUIRED, set questions and options to []; provide reason and evidence; set question and whyBlocked to "".
For PRODUCT_DECISION_REQUIRED, set questions to [] and reason to ""; use the product-decision fields.`,
  );
});

test("work questions require a blocking product decision", () => {
  assert.equal(
    PRODUCT_DECISION_INSTRUCTIONS,
    `Do not ask questions after clarification closes.
A blocking product-decision outcome is allowed only when the task, plan, repository, conventions, and prior clarifications leave a choice between materially different product requirements or behaviors unresolved and progress is otherwise impossible.
Do not use it for technical choices, implementation difficulty, naming, or ordinary review findings.
For that outcome, provide question, whyBlocked, and evidence; options may be [].`,
  );
});

test("plan compatibility is checked without reopening questions", () => {
  assert.equal(
    PLAN_COMPATIBILITY_INSTRUCTIONS,
    `Review the updated clarifications against the task, validated plan, completed commits, and repository.
Do not ask questions or modify the repository.
Using the provided schema, return READY when compatible; otherwise return PLAN_REVISION_REQUIRED with concise evidence.
For READY, set reason to "" and evidence to [].
For PLAN_REVISION_REQUIRED, provide reason and evidence.`,
  );
});

test("work instructions preserve their concise mandatory cores", () => {
  assert.equal(
    IMPLEMENTATION_INSTRUCTIONS,
    `Implement the changes described in the following planned commit. Keep the implementation idiomatic and minimal, and follow the project's conventions.

Work only on this planned commit.
Do not run the project finalization procedure or perform generic commit preparation in this turn. Those belong to the dedicated FINALIZE and COMMIT phases.
The established required-check inventory is input only to the dedicated FINALIZE gate. Do not execute it in this turn.
Do not create a commit in this turn.
Before returning, perform a concise self-review.
For COMPLETED, put all results in summary; set reason, question, and whyBlocked to "", and options and evidence to [].
For BLOCKED, use only when required validation cannot run because of sandbox, IPC, loopback, process-isolation, missing-service, permission, or comparable external constraints. Set summary, question, and whyBlocked to "", and options to []; provide reason and evidence.
For PRODUCT_DECISION_REQUIRED, set summary and reason to ""; use the product-decision fields.

Do not weaken sandboxing or grant network or host temporary-directory access to make validation pass.

Do not ask questions after clarification closes.
A blocking product-decision outcome is allowed only when the task, plan, repository, conventions, and prior clarifications leave a choice between materially different product requirements or behaviors unresolved and progress is otherwise impossible.
Do not use it for technical choices, implementation difficulty, naming, or ordinary review findings.
For that outcome, provide question, whyBlocked, and evidence; options may be [].`,
  );
  assert.match(REVIEW_INSTRUCTIONS, /Do not modify the repository/u);
  assert.match(REVIEW_INSTRUCTIONS, /reject omissions, skips, substitutions/u);
  assert.match(REVIEW_INSTRUCTIONS, /validationChange UNCHANGED/u);
  assert.match(REVIEW_INSTRUCTIONS, /ACCEPTED with validationEvidence/u);
  assert.equal(
    FINDING_RESOLUTION_INSTRUCTIONS,
    `For each finding below, fix it idiomatically and minimally, following the project's conventions.
If a finding is incorrect, dispute it with concise evidence instead of changing the code.

Do not run the project finalization procedure or perform generic commit preparation in this turn. Those belong to the dedicated FINALIZE and COMMIT phases.
The established required-check inventory is input only to the dedicated FINALIZE gate. Do not execute it in this turn.
Do not create a commit in this turn.
For RESOLVED, return exactly one decision per blocker; every decision requires reason; DISPUTE requires evidence, while FIX evidence may be []. Set top-level reason, question, and whyBlocked to "", and options and evidence to [].
For BLOCKED, use only when required validation cannot run because of sandbox, IPC, loopback, process-isolation, missing-service, permission, or comparable external constraints. Set decisions and options to []; provide reason and evidence; set question and whyBlocked to "".
For PRODUCT_DECISION_REQUIRED, set decisions to [] and reason to ""; use the product-decision fields.
Do not weaken sandboxing or grant network or host temporary-directory access to make validation pass.
Do not ask questions after clarification closes.
A blocking product-decision outcome is allowed only when the task, plan, repository, conventions, and prior clarifications leave a choice between materially different product requirements or behaviors unresolved and progress is otherwise impossible.
Do not use it for technical choices, implementation difficulty, naming, or ordinary review findings.
For that outcome, provide question, whyBlocked, and evidence; options may be [].
Otherwise, return each FIX or DISPUTE decision using the provided schema.`,
  );
});

test("finalization and dispute prompts preserve their narrow roles", () => {
  assert.match(
    FINALIZATION_INSTRUCTIONS,
    /^Run the complete project finalization procedure in this dedicated turn/u,
  );
  assert.match(
    FINALIZATION_INSTRUCTIONS,
    /Follow every substantive instruction in the applicable project guidance/u,
  );
  assert.match(
    FINALIZATION_INSTRUCTIONS,
    /defer staging, staged\/index-relative inspection, alternate-index workarounds/u,
  );
  assert.match(
    FINALIZATION_INSTRUCTIONS,
    /against HEAD or explicit trees/u,
  );
  assert.match(
    FINALIZATION_INSTRUCTIONS,
    /neither a validation blocker nor a skipped required check/u,
  );
  assert.match(
    FINALIZATION_INSTRUCTIONS,
    /constrained COMMIT executor alone runs git add -A, performs fixed runner-owned staged-diff hygiene/u,
  );
  assert.match(
    FINALIZATION_INSTRUCTIONS,
    /Use PASS only after every agent-executed required check succeeds/u,
  );
  assert.match(
    FINALIZATION_INSTRUCTIONS,
    /Return NOT_RUN only for a command explicitly listed as runner-trusted/u,
  );
  assert.match(FINALIZATION_INSTRUCTIONS, /sandbox, IPC, loopback/u);
  assert.match(FINALIZATION_INSTRUCTIONS, /Do not weaken sandboxing/u);
  assert.match(
    FINALIZATION_INSTRUCTIONS,
    /For PASS, provide summary; set issues, options, and evidence to \[\]; set reason, question, and whyBlocked to ""\./u,
  );
  assert.match(
    FINALIZATION_INSTRUCTIONS,
    /For FAIL, provide summary and one or more issues with unique stable F-prefixed numeric IDs, each with command, problem, and evidence;/u,
  );
  assert.match(
    FINALIZATION_INSTRUCTIONS,
    /For SKILL_MISSING or SKILL_INVALID, provide the attempted repository-relative skillPath and reason/u,
  );
  assert.match(
    FINALIZATION_INSTRUCTIONS,
    /requiredChecks, validationInfrastructure, checks/u,
  );
  assert.match(FINALIZATION_INSTRUCTIONS, /For BLOCKED, use only/u);
  assert.match(
    FINALIZATION_INSTRUCTIONS,
    /For PRODUCT_DECISION_REQUIRED, set skillPath, summary, and reason to ""/u,
  );
  assert.match(finalizationBootstrapInstructions("auto"), /conventional/u);
  assert.match(finalizationBootstrapInstructions("none"), /do not skip/u);
  assert.match(
    finalizationBootstrapInstructions("checks/finalize/SKILL.md"),
    /explicitly configured/u,
  );
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
  assert.equal(
    DISPUTE_RECONSIDERATION_INSTRUCTIONS,
    `Reconsider the disputed findings against the task, plan, repository, diff, and Worker evidence.

Do not modify the repository. Return WITHDRAW or UPHOLD with a concise reason for every disputed finding using the provided schema.
For RESOLVED, return exactly one decision per dispute; every decision requires reason, while evidence may be []. Set question and whyBlocked to "", and options and evidence to [].
For PRODUCT_DECISION_REQUIRED, set decisions to []; use the product-decision fields.
${PRODUCT_DECISION_INSTRUCTIONS}`,
  );
});

test("commit instructions preserve the one-shot local boundary", () => {
  assert.equal(
    COMMIT_INSTRUCTIONS,
    `Validate readiness for the authorized local commit using the exact supplied subject. The constrained executor alone stages the exact finalized and reviewed workspace with git add -A, performs fixed staged-diff hygiene, and creates the subject-only commit.
Do not stage changes yourself, modify project content, amend history, bypass hooks, change Git identity or configuration, create other refs, or perform any remote write.`,
  );
});

test("arbitration prompts preserve the mandatory cores", () => {
  assert.equal(
    FINDING_ARBITRATION_INSTRUCTIONS,
    `Resolve the disputed finding from the task, plan, repository, diff, and evidence, choosing the correct outcome using the provided schema.

Do not modify the repository or rewrite requirements. Always provide rationale.
For WORKER_CORRECT or REVIEWER_CORRECT, set question and whyBlocked to "", and options and evidence to [].
For REQUIREMENT_AMBIGUOUS, use the product-decision fields.`,
  );
  assert.equal(
    STAGNATION_INSTRUCTIONS,
    `Diagnose why the implementation correction loop is not converging and choose the minimal valid next direction using the provided schema.
Always provide rationale.
For CONTINUE_FIXES or REWORK_IMPLEMENTATION, set findingIds, options, and evidence to [], and reason, question, and whyBlocked to "".
For RECONSIDER_FINDINGS, provide one or more unique current Reviewer findingIds; set reason, question, and whyBlocked to "", and options and evidence to [].
For PLAN_REVISION_REQUIRED, set findingIds and options to [], and question and whyBlocked to ""; provide reason and evidence.
For PRODUCT_DECISION_REQUIRED, set findingIds to [] and reason to ""; use the product-decision fields.`,
  );
});
