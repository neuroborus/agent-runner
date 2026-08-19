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
