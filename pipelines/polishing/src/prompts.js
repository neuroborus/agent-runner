export const PRODUCT_DECISION_INSTRUCTIONS = `Do not ask questions after clarification closes.
A blocking product-decision outcome is allowed only when the task, existing changes, repository conventions, and prior clarifications leave a choice between materially different product requirements or behaviors unresolved and progress is otherwise impossible.
Do not use it for technical choices, implementation difficulty, naming, or ordinary review findings.
For that outcome, provide question, whyBlocked, and evidence; options may be [].`;

export const CLARIFICATION_INSTRUCTIONS = `Study the task, existing changes, task-level clarifications, execution clarifications, and repository before polishing begins. Ask only questions whose answers could materially change the required behavior, scope, or treatment of the existing changes.

Do not modify the repository.
For READY, return exactly {"status":"READY","questions":[],"reason":"","question":"","options":[],"whyBlocked":"","evidence":[]}.
For QUESTIONS, provide one or more actionable questions with question and whyItMatters; set reason, question, and whyBlocked to "", and options and evidence to [].
For PRODUCT_DECISION_REQUIRED, set questions to [] and reason to ""; use the product-decision fields.`;

export const BOOTSTRAP_INSTRUCTIONS = `Study the repository, task, existing changes, clarifications, project instructions, the project's finalization skill, other relevant skills, tests, and Git history independently and without modifying the repository.
Return a concise bootstrap summary covering the task, current change set, relevant architecture and files, invariants, risks, and the project's finalization procedure using the provided schema.
For READY, provide summary; set reason, question, and whyBlocked to "", and options and evidence to [].
For PRODUCT_DECISION_REQUIRED, set summary and reason to ""; use the product-decision fields.`;

export const BOOTSTRAP_RECONCILIATION_INSTRUCTIONS = `Reconcile the independent Worker and Reviewer bootstrap summaries using the task, existing changes, repository, clarifications, and evidence.
Do not force agreement or modify the repository. Return a concise resolved summary, or the remaining material disagreement, using the provided schema.
For RESOLVED, provide summary; set disagreement, reason, question, and whyBlocked to "", and options and evidence to [].
For DISAGREEMENT, provide disagreement and evidence; set summary, reason, question, and whyBlocked to "", and options to [].
For PRODUCT_DECISION_REQUIRED, set summary, disagreement, and reason to ""; use the product-decision fields.`;

export const BOOTSTRAP_ARBITRATION_INSTRUCTIONS = `Resolve the bootstrap disagreement from the task, existing changes, repository, clarifications, and evidence, choosing the minimal valid direction using the provided schema.

Do not modify the repository or rewrite requirements. Always provide rationale.
Choose USE_WORKER or USE_REVIEWER only when that summary is correct, and SYNTHESIZE when the evidence supports a combined summary.
For USE_WORKER, USE_REVIEWER, or SYNTHESIZE, provide summary; set reason, question, and whyBlocked to "", and options and evidence to [].
For PRODUCT_DECISION_REQUIRED, set summary and reason to ""; use the product-decision fields.`;

export const POLISH_INSTRUCTIONS = `Polish the existing local repository changes into a correct, idiomatic, minimal result that satisfies the task and follows the target project's conventions.

You may modify workspace content and staging placement when correctness requires it. Preserve unrelated work. Do not create a commit, change HEAD or refs, alter remotes or Git identity, or perform a remote write. Before returning, perform a concise self-review.
For COMPLETED, provide summary; set reason, question, and whyBlocked to "", and options and evidence to [].
For BLOCKED, use only an external environment blocker; set summary, question, and whyBlocked to "", and options to []; provide reason and evidence.
For PRODUCT_DECISION_REQUIRED, set summary and reason to ""; use the product-decision fields.`;

export const FINALIZATION_INSTRUCTIONS = `Locate and validate the target project's finalization skill before following it in this dedicated turn.
Run only the validation procedure defined by that skill, including project-required formatting or generated output. Do not perform unrelated fixes, stage changes as a discretionary handoff action, or create a commit.
Use PASS only after the complete validation procedure succeeds.
For PASS, provide a repository-relative skillPath and summary; set issues, options, and evidence to []; set reason, question, and whyBlocked to "".
For FAIL, provide a repository-relative skillPath, summary, and one or more issues with unique stable F-prefixed numeric IDs, each with command, problem, and evidence; set options and evidence to []; set reason, question, and whyBlocked to "".
For SKILL_MISSING, provide reason; set skillPath, summary, question, and whyBlocked to "", and issues and options to []; evidence may be [].
For SKILL_INVALID or BLOCKED, provide a repository-relative skillPath and reason; set summary, question, and whyBlocked to "", and issues and options to []; evidence may be [].
For PRODUCT_DECISION_REQUIRED, set skillPath, summary, and reason to "", and issues to []; use the product-decision fields.`;

export const REVIEW_INSTRUCTIONS = `Review the complete current change set independently against the task, resolved context, architecture, tests, edge cases, minimality, and project conventions.

Do not modify the repository. Reuse an existing R-prefixed ID for an unchanged finding. Report every actionable blocker, but do not report preferences or already-resolved issues.
For APPROVED, set findings, options, and evidence to []; set question and whyBlocked to "".
For FINDINGS, provide one or more findings with stable IDs, repository-relative file, problem, reason, and suggestedAction; set question and whyBlocked to "", and options and evidence to [].
For PRODUCT_DECISION_REQUIRED, set findings to []; use the product-decision fields.`;

export const FINDING_RESOLUTION_INSTRUCTIONS = `Resolve every current blocker in one batch. Fix each valid blocker idiomatically and minimally. Dispute an incorrect Reviewer finding only with concise evidence.

Do not create a commit. Finalization failures must be fixed and cannot be disputed. A finding already upheld by the Arbiter must be fixed.
For RESOLVED, return exactly one decision per blocker; every decision requires reason; DISPUTE requires evidence, while FIX evidence may be []. Set question and whyBlocked to "", and options and evidence to [].
For PRODUCT_DECISION_REQUIRED, set decisions to []; use the product-decision fields.`;

export const DISPUTE_RECONSIDERATION_INSTRUCTIONS = `Reconsider each disputed finding from the current repository evidence and the Worker's evidence.

Do not modify the repository. Withdraw an incorrect finding; uphold a valid one. Return exactly one decision for every dispute with reason and optional evidence.
For RESOLVED, set question and whyBlocked to "", and options and evidence to [].
For PRODUCT_DECISION_REQUIRED, set decisions to []; use the product-decision fields.`;

export const FINDING_ARBITRATION_INSTRUCTIONS = `Resolve the disputed finding from the task, repository, current changes, and recorded evidence.

Do not modify the repository. Choose WORKER_CORRECT when the finding should be withdrawn, REVIEWER_CORRECT when it must be fixed, or REQUIREMENT_AMBIGUOUS only for a genuinely blocking unresolved product requirement. Always provide rationale.`;

export const STAGNATION_INSTRUCTIONS = `Resolve a stalled polishing correction loop from the current blockers and compact correction history.

Do not modify the repository. This result cannot approve the changes or satisfy review. Choose CONTINUE_FIXES, REWORK_IMPLEMENTATION, or RECONSIDER_FINDINGS. Name only current Reviewer finding IDs for RECONSIDER_FINDINGS. Use PRODUCT_DECISION_REQUIRED only for a genuinely blocking unresolved product requirement. Always provide rationale.`;
