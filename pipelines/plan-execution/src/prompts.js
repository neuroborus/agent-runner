export const CLARIFICATION_INSTRUCTIONS = `Study the task, validated plan, existing clarifications, and repository before implementation. Ask only questions whose answers could materially change the required behavior, scope, or implementation of the plan.

Do not modify the repository.
If existing clarifications conflict with the validated plan, return PLAN_REVISION_REQUIRED using the provided schema.
Otherwise, return only READY or actionable clarification questions using the provided schema.`;

export const PRODUCT_DECISION_INSTRUCTIONS = `Do not ask questions after clarification closes.
Return PRODUCT_DECISION_REQUIRED using the provided schema only when the task, plan, repository, conventions, and prior clarifications leave a choice between materially different product requirements or behaviors unresolved and progress is otherwise impossible.
Do not use it for technical choices, implementation difficulty, naming, or ordinary review findings.`;

export const PLAN_COMPATIBILITY_INSTRUCTIONS = `Review the updated clarifications against the task, validated plan, completed commits, and repository.
Do not ask questions or modify the repository.
Using the provided schema, return READY when compatible; otherwise return PLAN_REVISION_REQUIRED with concise evidence.`;

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
