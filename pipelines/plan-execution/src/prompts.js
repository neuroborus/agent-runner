export const CLARIFICATION_INSTRUCTIONS = `Study the task, validated plan, existing clarifications, and repository before implementation. Ask only questions whose answers could materially change the required behavior, scope, or implementation of the plan.

Do not modify the repository.
If existing clarifications conflict with the validated plan, use PLAN_REVISION_REQUIRED.
For READY, return exactly {"status":"READY","questions":[],"reason":"","question":"","options":[],"whyBlocked":"","evidence":[]}.
For QUESTIONS, provide one or more actionable questions with question and whyItMatters; set reason, question, and whyBlocked to "", and options and evidence to [].
For PLAN_REVISION_REQUIRED, set questions and options to []; provide reason and evidence; set question and whyBlocked to "".
For PRODUCT_DECISION_REQUIRED, set questions to [] and reason to ""; use the product-decision fields.`;

export const PRODUCT_DECISION_INSTRUCTIONS = `Do not ask questions after clarification closes.
A blocking product-decision outcome is allowed only when the task, plan, repository, conventions, and prior clarifications leave a choice between materially different product requirements or behaviors unresolved and progress is otherwise impossible.
Do not use it for technical choices, implementation difficulty, naming, or ordinary review findings.
For that outcome, provide question, whyBlocked, and evidence; options may be [].`;

export const PLAN_COMPATIBILITY_INSTRUCTIONS = `Review the updated clarifications against the task, validated plan, completed commits, and repository.
Do not ask questions or modify the repository.
Using the provided schema, return READY when compatible; otherwise return PLAN_REVISION_REQUIRED with concise evidence.
For READY, set reason to "" and evidence to [].
For PLAN_REVISION_REQUIRED, provide reason and evidence.`;

export const BOOTSTRAP_INSTRUCTIONS = `Study the repository, task, validated plan, clarifications, project instructions, relevant finalization guidance, other relevant skills, project checks, tests, and Git history independently and without modifying the repository.
Return a concise bootstrap summary covering the task, relevant architecture and files, invariants, planned commits, risks, and the complete project finalization procedure using the provided schema.
For READY, provide summary; set reason, question, and whyBlocked to "", and options and evidence to [].
For PLAN_REVISION_REQUIRED, set summary, question, and whyBlocked to "", and options to []; provide reason and evidence.
For PRODUCT_DECISION_REQUIRED, set summary and reason to ""; use the product-decision fields.`;

export const BOOTSTRAP_RECONCILIATION_INSTRUCTIONS = `Reconcile the independent Worker and Reviewer bootstrap summaries using the task, validated plan, repository, and evidence.
Do not force agreement or modify the repository. Return a concise resolved summary, or the remaining material disagreement, using the provided schema.
For RESOLVED, provide summary; set disagreement, reason, question, and whyBlocked to "", and options and evidence to [].
For DISAGREEMENT, provide disagreement and evidence; set summary, reason, question, and whyBlocked to "", and options to [].
For PLAN_REVISION_REQUIRED, provide reason and evidence; set summary, disagreement, question, and whyBlocked to "", and options to [].
For PRODUCT_DECISION_REQUIRED, set summary, disagreement, and reason to ""; use the product-decision fields.`;

export const BOOTSTRAP_ARBITRATION_INSTRUCTIONS = `Resolve the bootstrap disagreement from the task, plan, repository, and evidence, choosing the minimal valid direction using the provided schema.

Do not modify the repository. Resolve only the recorded disagreement and do not rewrite requirements.
Always provide rationale.
Choose USE_WORKER or USE_REVIEWER only when that summary is correct, and SYNTHESIZE when the evidence supports a combined summary.
For USE_WORKER, USE_REVIEWER, or SYNTHESIZE, provide summary; set reason, question, and whyBlocked to "", and options and evidence to [].
For PLAN_REVISION_REQUIRED, set summary, question, and whyBlocked to "", and options to []; provide reason and evidence.
For PRODUCT_DECISION_REQUIRED, set summary and reason to ""; use the product-decision fields.`;

export const IMPLEMENTATION_INSTRUCTIONS = `Implement the changes described in the following planned commit. Keep the implementation idiomatic and minimal, and follow the project's conventions.

Work only on this planned commit.
Do not create a commit in this turn.
Before returning, perform a concise self-review.
For COMPLETED, put all results in summary; set reason, question, and whyBlocked to "", and options and evidence to [].
For BLOCKED, use only when required validation cannot run because of sandbox, IPC, loopback, process-isolation, missing-service, permission, or comparable external constraints. Set summary, question, and whyBlocked to "", and options to []; provide reason and evidence.
For PRODUCT_DECISION_REQUIRED, set summary and reason to ""; use the product-decision fields.

Do not weaken sandboxing or grant network or host temporary-directory access to make validation pass.

${PRODUCT_DECISION_INSTRUCTIONS}`;

export const REVIEW_INSTRUCTIONS = `Review the changes and verify that they are correct, idiomatic, minimal, and consistent with the project's conventions.

Do not modify the repository.
For APPROVED, set question and whyBlocked to "", and findings, options, and evidence to [].
For FINDINGS, provide one or more findings with unique stable R-prefixed numeric IDs, a repository-relative file, and populated problem, reason, and suggestedAction fields; set question and whyBlocked to "", and options and evidence to [].
For PRODUCT_DECISION_REQUIRED, set findings to []; use the product-decision fields.
${PRODUCT_DECISION_INSTRUCTIONS}
Otherwise, return only the approval decision and actionable findings using the provided schema.`;

export const FINDING_RESOLUTION_INSTRUCTIONS = `For each finding below, fix it idiomatically and minimally, following the project's conventions.
If a finding is incorrect, dispute it with concise evidence instead of changing the code.

Do not create a commit in this turn.
For RESOLVED, return exactly one decision per blocker; every decision requires reason; DISPUTE requires evidence, while FIX evidence may be []. Set top-level reason, question, and whyBlocked to "", and options and evidence to [].
For BLOCKED, use only when required validation cannot run because of sandbox, IPC, loopback, process-isolation, missing-service, permission, or comparable external constraints. Set decisions and options to []; provide reason and evidence; set question and whyBlocked to "".
For PRODUCT_DECISION_REQUIRED, set decisions to [] and reason to ""; use the product-decision fields.
Do not weaken sandboxing or grant network or host temporary-directory access to make validation pass.
${PRODUCT_DECISION_INSTRUCTIONS}
Otherwise, return each FIX or DISPUTE decision using the provided schema.`;

export const FINALIZATION_INSTRUCTIONS = `Run the complete project finalization procedure in this dedicated turn, including project-required formatting or generated output, and report its result using the provided schema.

Do not perform unrelated fixes, stage changes, or create a commit.
Use PASS only after the complete validation procedure succeeds.
Do not weaken sandboxing or grant network or host temporary-directory access to make validation pass.
For PASS, provide summary; set issues, options, and evidence to []; set reason, question, and whyBlocked to "".
For FAIL, provide summary and one or more issues with unique stable F-prefixed numeric IDs, each with command, problem, and evidence; set options and evidence to []; set reason, question, and whyBlocked to "".
For SKILL_MISSING, provide the attempted repository-relative skillPath and reason; set summary, question, and whyBlocked to "", and issues and options to []; evidence may be [].
For SKILL_INVALID, provide a repository-relative skillPath and reason; set summary, question, and whyBlocked to "", and issues and options to []; evidence may be [].
For BLOCKED, use only when required validation cannot run because of sandbox, IPC, loopback, process-isolation, missing-service, permission, or comparable external constraints. Use the selected skillPath or "" when no skill is selected; set summary, question, and whyBlocked to "", and issues and options to []; provide reason and evidence.
For PRODUCT_DECISION_REQUIRED, set skillPath, summary, and reason to "", and issues to []; use the product-decision fields.
${PRODUCT_DECISION_INSTRUCTIONS}`;

export function finalizationBootstrapInstructions(policy) {
  if (policy === "none") {
    return "No finalization skill guidance is selected. Derive the complete finalization gate from repository instructions and project-defined checks; do not skip validation.";
  }
  if (policy === "auto") {
    return "Use a conventional repository finalization skill when one is available. Otherwise derive the complete finalization gate from repository instructions and project-defined checks; missing optional guidance must not skip validation.";
  }
  return `Use only the explicitly configured finalization skill at ${policy}. Treat a missing, escaping, or invalid configured skill as blocking.`;
}

export function finalizationGuidanceInstructions({ required, skillPath }) {
  if (skillPath === null) {
    return `No finalization skill guidance is available for this turn. Derive and run the complete gate from repository instructions and project-defined checks; inspect relevant scripts and established validation commands instead of skipping validation.
For PASS, FAIL, or BLOCKED, set skillPath to "". Do not use SKILL_MISSING or SKILL_INVALID when no skill is selected.`;
  }
  return `The resolved finalization skill is ${skillPath}. Validate that exact confined repository-relative skill before following it; do not substitute another path.
${required ? "This skill is explicitly configured, so a missing, escaping, or invalid skill is blocking." : "This skill was discovered automatically; report SKILL_MISSING or SKILL_INVALID before invoking it so the runner can fall back to repository instructions and project checks."}
For PASS, FAIL, SKILL_MISSING, SKILL_INVALID, or BLOCKED, set skillPath to ${JSON.stringify(skillPath)}.`;
}

export const COMMIT_INSTRUCTIONS = `Validate the authorized local commit using the exact supplied subject.
Do not modify project content, amend history, bypass hooks, change Git identity or configuration, create other refs, or perform any remote write.`;

export const DISPUTE_RECONSIDERATION_INSTRUCTIONS = `Reconsider the disputed findings against the task, plan, repository, diff, and Worker evidence.

Do not modify the repository. Return WITHDRAW or UPHOLD with a concise reason for every disputed finding using the provided schema.
For RESOLVED, return exactly one decision per dispute; every decision requires reason, while evidence may be []. Set question and whyBlocked to "", and options and evidence to [].
For PRODUCT_DECISION_REQUIRED, set decisions to []; use the product-decision fields.
${PRODUCT_DECISION_INSTRUCTIONS}`;

export const FINDING_ARBITRATION_INSTRUCTIONS = `Resolve the disputed finding from the task, plan, repository, diff, and evidence, choosing the correct outcome using the provided schema.

Do not modify the repository or rewrite requirements. Always provide rationale.
For WORKER_CORRECT or REVIEWER_CORRECT, set question and whyBlocked to "", and options and evidence to [].
For REQUIREMENT_AMBIGUOUS, use the product-decision fields.`;

export const STAGNATION_INSTRUCTIONS = `Diagnose why the implementation correction loop is not converging and choose the minimal valid next direction using the provided schema.
Always provide rationale.
For CONTINUE_FIXES or REWORK_IMPLEMENTATION, set findingIds, options, and evidence to [], and reason, question, and whyBlocked to "".
For RECONSIDER_FINDINGS, provide one or more unique current Reviewer findingIds; set reason, question, and whyBlocked to "", and options and evidence to [].
For PLAN_REVISION_REQUIRED, set findingIds and options to [], and question and whyBlocked to ""; provide reason and evidence.
For PRODUCT_DECISION_REQUIRED, set findingIds to [] and reason to ""; use the product-decision fields.`;
