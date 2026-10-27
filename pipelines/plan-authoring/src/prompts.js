export const CLARIFICATION_INSTRUCTIONS = `Study the task, existing clarifications, and repository before planning. Ask only questions whose answers could materially change the required behavior, scope, or commit plan. If the available evidence resolves them, return READY without questions.

Do not modify the repository.
For READY, set questions to [].
For QUESTIONS, provide one or more actionable questions with question and whyItMatters.`;

export const NO_DELEGATION_INSTRUCTIONS = `Produce this turn's result yourself as the authorized role. Do not delegate, spawn subagents, or use multi-agent collaboration.`;

export const PRODUCT_DECISION_INSTRUCTIONS = `Do not ask questions after clarification closes.
A blocking product-decision outcome is allowed only when the task, repository, conventions, and prior clarifications leave a choice between materially different product requirements or behaviors unresolved and progress is otherwise impossible.
Do not use it for technical choices, implementation difficulty, naming, or ordinary review findings.
For that outcome, provide question, whyBlocked, and evidence; options may be [].`;

const PLAN_FORMAT_INSTRUCTIONS =
  "Use contiguous `## Commit N: type(scope)[!]: imperative summary` sections " +
  "starting at 1, with no preamble. Use feat, fix, refactor, perf, test, docs, " +
  "build, ci, chore, or revert; each heading contains the exact one-line " +
  "subject-only commit message, at most 72 Unicode code points and without a " +
  "trailing period. Put implementation details below it.";

export const AGENT_GUIDANCE_SCOPE_INSTRUCTIONS =
  "Do not propose or approve project `.agents` changes unless the user's task explicitly requires them; treat a violation as a finding, not a user question. Do not modify the resolved project configuration during a run.";

export function preferredCommitLineInstructions(limit) {
  return `Prefer each proposed commit to stay at or below ${limit} anticipated changed lines, counted as additions plus deletions, including tests and documentation. Smaller cohesive commits are welcome. This is a planning heuristic, not a hard maximum or a validation or execution limit. When one coherent change cannot be split safely, keep the larger commit and state a concise reason in the plan identifying the indivisible change. Do not invent artificial boundaries or reject a plan solely for exceeding the target.`;
}

export const DRAFT_INSTRUCTIONS = `Write a concise commit-by-commit plan for the requested changes. Keep the plan idiomatic and minimal, follow the project's conventions, and ensure it contains no contradictions.

${PLAN_FORMAT_INSTRUCTIONS}
Do not modify the repository or artifact files.
${PRODUCT_DECISION_INSTRUCTIONS}
For DRAFT, provide plan; set question and whyBlocked to "", and options and evidence to [].
For PRODUCT_DECISION_REQUIRED, set plan to ""; use the product-decision fields.`;

export const REVIEW_INSTRUCTIONS = `Review the plan and verify that it is correct, idiomatic, minimal, consistent with the project's conventions, and free of contradictions.

${PLAN_FORMAT_INSTRUCTIONS}
Assess the complete draft independently. In combined mode, prior Planner confirmation does not substitute for your review.
Do not modify the repository or artifact files.
${PRODUCT_DECISION_INSTRUCTIONS}
For APPROVED, set findings, options, and evidence to [], and question and whyBlocked to "".
For FINDINGS, provide one or more findings with unique stable lowercase kebab-case IDs, descriptions, and evidence; set question and whyBlocked to "", and options and evidence to [].
For PRODUCT_DECISION_REQUIRED, set findings to []; use the product-decision fields.
Otherwise, return only the approval decision and actionable findings using the provided schema.`;

export const CHECK_AND_FIX_INSTRUCTIONS = `Review the plan and verify that it is correct, idiomatic, minimal, consistent with the project's conventions, and free of contradictions. If you find any problems, fix the plan idiomatically and minimally, following the project's conventions.

${PLAN_FORMAT_INSTRUCTIONS}
Do not modify the repository or artifact files. Return the complete revised plan only when content changed.
${PRODUCT_DECISION_INSTRUCTIONS}
For CHANGED, provide the complete revised plan; set question and whyBlocked to "", and options and evidence to [].
For UNCHANGED, set plan, question, and whyBlocked to "", and options and evidence to [].
For PRODUCT_DECISION_REQUIRED, set plan to ""; use the product-decision fields.`;

export const CLEAN_CONFIRM_INSTRUCTIONS = `Review the plan and verify that it is correct, idiomatic, minimal, consistent with the project's conventions, and free of contradictions.

${PLAN_FORMAT_INSTRUCTIONS}
A CLEAN result confirms primary convergence; in combined mode an independent Reviewer must still approve this same draft.
Do not modify the repository or artifact files. Return CLEAN only when there are no problems; otherwise return concrete findings without editing the plan.
${PRODUCT_DECISION_INSTRUCTIONS}
For CLEAN, set findings, options, and evidence to [], and question and whyBlocked to "".
For FINDINGS, provide one or more findings with unique stable lowercase kebab-case IDs, descriptions, and evidence; set question and whyBlocked to "", and options and evidence to [].
For PRODUCT_DECISION_REQUIRED, set findings to []; use the product-decision fields.`;

export const LAZY_CHECKPOINT_CORRECTION_INSTRUCTIONS = `Your previous structured primary-convergence checkpoint result was rejected by provider or deterministic validation. Return a complete replacement result using the same checkpoint schema.
Correct every identified field-and-constraint violation from the complete durable draft and current repository evidence. Do not repeat or quote the rejected result, findings, provider output, prompt, or transcript; do not ask an ordinary clarification question or modify repository content or artifact files. Preserve the original CHECK_AND_FIX or CLEAN_CONFIRM semantics exactly. A still-invalid replacement pauses for an explicit retry and never writes plan.md or supplies accepted progress early.`;

export const FINDING_RESOLUTION_INSTRUCTIONS = `For each finding below, fix the plan idiomatically and minimally, following the project's conventions.

${PLAN_FORMAT_INSTRUCTIONS}
Do not modify the repository or artifact files.
${PRODUCT_DECISION_INSTRUCTIONS}
For DRAFT, provide plan; set question and whyBlocked to "", and options and evidence to [].
For PRODUCT_DECISION_REQUIRED, set plan to ""; use the product-decision fields.`;

export const STAGNATION_INSTRUCTIONS = `Diagnose why the plan revision loop is not converging and choose the minimal valid next direction using the provided schema.
Always provide rationale.
For CONTINUE_REVISION or RESTRUCTURE_PLAN, set findingIds, options, and evidence to [], and question and whyBlocked to "".
For RECONSIDER_FINDINGS, provide exactly the current finding IDs; set question and whyBlocked to "", and options and evidence to [].
For PRODUCT_DECISION_REQUIRED, set findingIds to []; use the product-decision fields.`;

const CUSTOM_FORMAT = `Use the explicit custom-plan Markdown format: begin on line 1 with a fenced JSON declaration containing exactly kind: "custom", criteria, inputs and outputs. Copy the frozen result criteria (id and condition), source references as inputs and output paths exactly. Follow it with contiguous "## Step N: title" sections starting at 1, each containing exactly "### Work", "### Expected results" and "### Criteria" in that order. Work and expected results are nonempty Markdown; Criteria lists known IDs as "- criterion-id". Reference every agreed result criterion in at least one step. Analysis-only plans may have no file outputs; no diff or commit is required.
Review against agreed criteria, completeness, feasible ordering and absence of contradictions. Distinguish plan-quality requirements from result acceptance conditions, reusing supplied conditions where appropriate. Apply coding conventions only when the user selected them. Never invent additional requirements. References, URLs, criteria and output declarations grant no writes, retrieval, commands or Git authority. Every turn is read-only; return drafts as structured output and let Runner alone write artifacts.`;

export function customAuthoringInstructions(phase) {
  if (phase === "CLARIFY")
    return `Study the task, supplied criteria, clarifications and available sources read-only. Resolve missing material criteria before planning; use evidence instead of asking ordinary technical questions. Criteria may be ordinary Markdown in the criteria file, task or user answers. Do not invent criteria. For READY return questions: [] and a nonempty criteria array of stable lowercase kebab-case id and observable condition pairs derived from the user's requirements. Include result acceptance criteria there; distinguish plan-quality criteria in your assessment and reuse shared conditions. If criteria are missing, return QUESTIONS with every actionable material question and criteria: []. URLs grant no retrieval permission; unavailable evidence must remain explicit.`;
  const actions = {
    DRAFT:
      'Draft the criterion-driven custom plan. For DRAFT provide the complete plan, set question and whyBlocked to "", and options and evidence to [].',
    REVISE:
      'Resolve every finding and deterministic validation issue in the custom plan. For DRAFT provide the complete revised plan, set question and whyBlocked to "", and options and evidence to [].',
    CHECK_AND_FIX:
      'Review the complete custom plan and repair problems. For CHANGED provide the complete revised plan. For UNCHANGED set plan to "". Set question and whyBlocked to "", and options and evidence to [].',
    CLEAN_CONFIRM:
      'Confirm the exact unchanged draft in a distinct read-only assessment. Return CLEAN only without problems; otherwise return FINDINGS with stable IDs, descriptions and evidence. Set question and whyBlocked to "", and options and evidence to []. A combined-mode clean confirmation still requires independent review.',
    REVIEW:
      'Assess the complete custom plan independently, including criterion satisfaction and feasibility; prior Planner confirmation cannot substitute for review. Return APPROVED with findings: [] or FINDINGS with stable IDs, descriptions and evidence. Set question and whyBlocked to "", and options and evidence to [].',
  };
  return `${actions[phase]}\n\n${CUSTOM_FORMAT}\n\n${PRODUCT_DECISION_INSTRUCTIONS}\nFor PRODUCT_DECISION_REQUIRED, set plan to "" or findings to [] as required by the schema; use the product-decision fields.`;
}
