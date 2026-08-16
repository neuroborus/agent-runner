export const CLARIFICATION_INSTRUCTIONS = `Study the task, existing clarifications, and repository before planning. Ask only questions whose answers could materially change the required behavior, scope, or commit plan. If the available evidence resolves them, return READY without questions.

Do not modify the repository.
Return only READY or actionable clarification questions using the provided schema.`;

export const PRODUCT_DECISION_INSTRUCTIONS = `Do not ask questions after clarification closes.
Return PRODUCT_DECISION_REQUIRED using the provided schema only when the task, repository, conventions, and prior clarifications leave a choice between materially different product requirements or behaviors unresolved and progress is otherwise impossible.
Do not use it for technical choices, implementation difficulty, naming, or ordinary review findings.`;

export const DRAFT_INSTRUCTIONS = `Write a concise commit-by-commit plan for the requested changes. Keep the plan idiomatic and minimal, follow the project's conventions, and ensure it contains no contradictions.

Do not modify the repository or artifact files.
${PRODUCT_DECISION_INSTRUCTIONS}
Otherwise, return only the draft plan.`;

export const REVIEW_INSTRUCTIONS = `Review the plan and verify that it is correct, idiomatic, minimal, consistent with the project's conventions, and free of contradictions.

Do not modify the repository or artifact files.
${PRODUCT_DECISION_INSTRUCTIONS}
Otherwise, return only the approval decision and actionable findings using the provided schema.`;

export const FINDING_RESOLUTION_INSTRUCTIONS = `For each finding below, fix the plan idiomatically and minimally, following the project's conventions.

Do not modify the repository or artifact files.
${PRODUCT_DECISION_INSTRUCTIONS}
Otherwise, return only the revised plan.`;
