export const CLARIFICATION_INSTRUCTIONS = `Study the task, validated plan, existing clarifications, and repository before implementation. Ask only questions whose answers could materially change the required behavior, scope, or implementation of the plan.

Do not modify the repository.
If existing clarifications conflict with the validated plan, return PLAN_REVISION_REQUIRED using the provided schema.
For READY, return exactly {"status":"READY","questions":[],"reason":"","question":"","options":[],"whyBlocked":"","evidence":[]}.
Otherwise, return only actionable clarification questions using the provided schema.`;

export const PRODUCT_DECISION_INSTRUCTIONS = `Do not ask questions after clarification closes.
Return PRODUCT_DECISION_REQUIRED using the provided schema only when the task, plan, repository, conventions, and prior clarifications leave a choice between materially different product requirements or behaviors unresolved and progress is otherwise impossible.
Do not use it for technical choices, implementation difficulty, naming, or ordinary review findings.`;

export const PLAN_COMPATIBILITY_INSTRUCTIONS = `Review the updated clarifications against the task, validated plan, completed commits, and repository.
Do not ask questions or modify the repository.
Using the provided schema, return READY when compatible; otherwise return PLAN_REVISION_REQUIRED with concise evidence.`;

export const BOOTSTRAP_INSTRUCTIONS = `Study the repository, task, validated plan, clarifications, project instructions, the project's finalization skill, other relevant skills, tests, and Git history independently and without modifying the repository.
Return a concise bootstrap summary covering the task, relevant architecture and files, invariants, planned commits, risks, and the project's finalization procedure using the provided schema.
For READY, put all analysis in summary; set reason, question, and whyBlocked to "", and options and evidence to [].`;

export const BOOTSTRAP_RECONCILIATION_INSTRUCTIONS = `Reconcile the independent Worker and Reviewer bootstrap summaries using the task, validated plan, repository, and evidence.
Do not force agreement or modify the repository. Return a concise resolved summary, or the remaining material disagreement, using the provided schema.`;

export const BOOTSTRAP_ARBITRATION_INSTRUCTIONS = `Resolve the bootstrap disagreement from the task, plan, repository, and evidence, choosing the minimal valid direction using the provided schema.

Do not modify the repository. Resolve only the recorded disagreement and do not rewrite requirements.`;

export const IMPLEMENTATION_INSTRUCTIONS = `Implement the changes described in the following planned commit. Keep the implementation idiomatic and minimal, and follow the project's conventions.

Work only on this planned commit.
Do not create a commit in this turn.
Before returning, perform a concise self-review.

${PRODUCT_DECISION_INSTRUCTIONS}`;

export const REVIEW_INSTRUCTIONS = `Review the changes and verify that they are correct, idiomatic, minimal, and consistent with the project's conventions.

Do not modify the repository.
${PRODUCT_DECISION_INSTRUCTIONS}
Otherwise, return only the approval decision and actionable findings using the provided schema.`;

export const FINDING_RESOLUTION_INSTRUCTIONS = `For each finding below, fix it idiomatically and minimally, following the project's conventions.
If a finding is incorrect, dispute it with concise evidence instead of changing the code.

Do not create a commit in this turn.
${PRODUCT_DECISION_INSTRUCTIONS}
Otherwise, return each FIX or DISPUTE decision using the provided schema.`;

export const FINALIZATION_INSTRUCTIONS = `Locate and validate the project's finalization skill before following it in this dedicated turn.
Run only that finalization procedure, including project-required formatting or generated output, and report its result using the provided schema.

Do not perform unrelated fixes or create a commit.
${PRODUCT_DECISION_INSTRUCTIONS}`;

export const COMMIT_INSTRUCTIONS = `Complete the authorized local commit using the exact supplied subject.
Do not modify project content, amend history, bypass hooks, change Git identity or configuration, create other refs, or perform any remote write.`;

export const DISPUTE_RECONSIDERATION_INSTRUCTIONS = `Reconsider the disputed findings against the task, plan, repository, diff, and Worker evidence.

Do not modify the repository. Return WITHDRAW or UPHOLD with a concise reason for every disputed finding using the provided schema.
${PRODUCT_DECISION_INSTRUCTIONS}`;

export const FINDING_ARBITRATION_INSTRUCTIONS = `Resolve the disputed finding from the task, plan, repository, diff, and evidence, choosing the correct outcome using the provided schema.

Do not modify the repository or rewrite requirements.`;

export const STAGNATION_INSTRUCTIONS =
  "Diagnose why the implementation correction loop is not converging and " +
  "choose the minimal valid next direction using the provided schema.";
