import { MAX_BOOTSTRAP_ITEMS } from "./workflow-contract.js";

export const AGENT_GUIDANCE_SCOPE_INSTRUCTIONS =
  "Do not make or approve project `.agents` changes unless the user's task explicitly requires them; treat a violation as a finding, not a user question.";

export const NO_DELEGATION_INSTRUCTIONS = `Produce this turn's result yourself as the authorized role. Do not delegate, spawn subagents, or use multi-agent collaboration.`;

export const PRODUCT_DECISION_INSTRUCTIONS = `Do not ask questions after clarification closes.
A blocking product-decision outcome is allowed only when the task, existing changes, repository conventions, and prior clarifications leave a choice between materially different product requirements or behaviors unresolved and progress is otherwise impossible.
Do not use it for technical choices, implementation difficulty, naming, or ordinary review findings.
For that outcome, provide question, whyBlocked, and evidence; options may be [].`;

export const CLARIFICATION_INSTRUCTIONS = `Study the task, existing changes, task-level clarifications, execution clarifications, and repository before polishing begins. Ask only questions whose answers could materially change the required behavior, scope, or treatment of the existing changes.

Do not modify the repository.
For READY, return exactly {"status":"READY","questions":[],"reason":"","question":"","options":[],"whyBlocked":"","evidence":[]}.
For QUESTIONS, provide one or more actionable questions with question and whyItMatters; set reason, question, and whyBlocked to "", and options and evidence to [].
For PRODUCT_DECISION_REQUIRED, set questions to [] and reason to ""; use the product-decision fields.`;

export const BOOTSTRAP_INSTRUCTIONS = `Study the repository, task, existing changes, clarifications, project instructions, relevant finalization guidance, other relevant skills, project checks, tests, and Git history independently and without modifying the repository.
Return a concise bootstrap summary covering the task, current change set, relevant architecture and files, invariants, risks, and the complete project finalization procedure using the provided schema. Independently identify every required check as a stable C-prefixed ID and exact command, plus every repository-relative file that controls those checks, package scripts, test discovery, test runners, or validation configuration.
Cover every substantive validation requirement, but keep the summary and required-check inventory staging-independent. Do not require staging, a staged handoff, index mutation or inspection, an implicit worktree-versus-index assertion, an alternate index, or commit preparation. Staging and staged-handoff inspection belong only to HANDOFF. Express an applicable content check against HEAD or explicit trees instead of the index.
Required-check IDs must be unique. Exact commands must be unique, single-line, and already normalized without leading or trailing whitespace. Validation-infrastructure paths must be unique, existing, canonical repository-relative regular files; never return a symlink or a path through a symlink, including a symlink alias of a canonical path.
Each inventory field has a per-role capacity of ${MAX_BOOTSTRAP_ITEMS} items. If the complete requiredChecks or validationInfrastructure inventory would exceed that capacity, do not truncate it or invent a placeholder. Check requiredChecks first, then validationInfrastructure, and return CAPACITY_EXHAUSTED for the first over-capacity field with capacityField set to its exact field name and capacityLimit set to ${MAX_BOOTSTRAP_ITEMS}.
For READY, provide summary, requiredChecks, and validationInfrastructure; set capacityField, reason, question, and whyBlocked to "", capacityLimit to 0, and options and evidence to [].
For CAPACITY_EXHAUSTED, set summary, reason, question, and whyBlocked to "", requiredChecks, validationInfrastructure, options, and evidence to [], and provide capacityField and capacityLimit as described above.
For PRODUCT_DECISION_REQUIRED, set summary, capacityField, and reason to "", capacityLimit to 0, and requiredChecks and validationInfrastructure to []; use the product-decision fields.`;

export const BOOTSTRAP_RECONCILIATION_INSTRUCTIONS = `Reconcile the independent Worker and Reviewer bootstrap summaries using the task, existing changes, repository, clarifications, and evidence.
Do not force agreement or modify the repository. Keep every resolved summary staging-independent. Staging, staged handoff, and index-relative checks belong only to HANDOFF; alternate-index workarounds and commit preparation are prohibited. Established checks are input only to the dedicated FINALIZE gate.
The runner derives the final required-check and validation-infrastructure inventories from the independently accepted role evidence. Do not propose, select, or repeat commands or repository paths.
For RESOLVED, provide summary; set disagreement, reason, question, and whyBlocked to "", and options and evidence to [].
For DISAGREEMENT, provide disagreement and evidence; set summary, reason, question, and whyBlocked to "", and options to [].
For PRODUCT_DECISION_REQUIRED, set summary, disagreement, and reason to ""; use the product-decision fields.`;

export const BOOTSTRAP_ARBITRATION_INSTRUCTIONS = `Resolve the bootstrap disagreement from the task, existing changes, repository, clarifications, and evidence, choosing the minimal valid direction using the provided schema.

Do not modify the repository or rewrite requirements. Always provide rationale.
Choose USE_WORKER or USE_REVIEWER only when that summary is correct, and SYNTHESIZE when the evidence supports a combined summary.
Keep the selected or synthesized summary staging-independent. Staging, staged handoff, and index-relative checks belong only to HANDOFF; alternate-index workarounds and commit preparation are prohibited. Established checks are input only to the dedicated FINALIZE gate.
The runner derives the final required-check and validation-infrastructure inventories from the independently accepted role evidence. Do not propose, select, or repeat commands or repository paths.
For USE_WORKER, USE_REVIEWER, or SYNTHESIZE, provide summary; set reason, question, and whyBlocked to "", and options and evidence to [].
For PRODUCT_DECISION_REQUIRED, set summary and reason to ""; use the product-decision fields.`;

export const BOOTSTRAP_CORRECTION_INSTRUCTIONS = `Your previous structured bootstrap result was rejected by deterministic validation. Make one read-only correction and return a complete replacement result using the same schema.
Correct only the identified contract violation using current repository evidence. Do not execute the rejected command, run staging-dependent validation, repeat or quote the rejected result, ask an ordinary clarification question, or modify the repository. Preserve the exceptional PRODUCT_DECISION_REQUIRED outcome and its required product-decision fields when its existing criteria are met. Preserve the CAPACITY_EXHAUSTED outcome and its capacity fields on the same basis. A repeated invalid result fails closed.`;

export const FINALIZATION_CORRECTION_INSTRUCTIONS = `Your previous structured finalization result was rejected by deterministic validation. Make one read-only correction and return a complete replacement result using the same finalization schema.
Correct only the identified contract violation using current repository evidence. Re-execute only corrected staging-independent checks as needed to produce complete direct evidence. Do not execute the rejected command, run staging-dependent validation, repeat or quote the rejected result, ask an ordinary clarification question, or modify repository content, staging, history, refs, remotes, or Git identity. Preserve the exceptional PRODUCT_DECISION_REQUIRED outcome and its required product-decision fields when its existing criteria are met. A repeated invalid result fails closed.`;

export const POLISH_INSTRUCTIONS = `Polish the existing local repository changes into a correct, idiomatic, minimal result that satisfies the task and follows the target project's conventions.

You may modify safe workspace content when correctness requires it. Do not stage or unstage changes or alter the Git index or other Git metadata. Do not create a commit, change HEAD or refs, alter remotes or Git identity, or perform a remote write. The runner alone stages the finalized and reviewed content during handoff. Preserve unrelated work. Before returning, perform a concise self-review.
The established required-check inventory is input only to the dedicated FINALIZE gate. Do not execute it in this turn or perform generic commit preparation.
For COMPLETED, provide summary; set reason, question, and whyBlocked to "", and options and evidence to [].
For BLOCKED, use only when required validation cannot run because of sandbox, IPC, loopback, process-isolation, missing-service, permission, or comparable external constraints. Set summary, question, and whyBlocked to "", and options to []; provide reason and evidence.
For PRODUCT_DECISION_REQUIRED, set summary and reason to ""; use the product-decision fields.
Do not weaken sandboxing or grant network or host temporary-directory access to make validation pass.`;

export const FINALIZATION_INSTRUCTIONS = `Run the complete project finalization procedure in this dedicated turn, including project-required formatting or generated output and staging-independent content review. Do not perform unrelated fixes, stage or unstage changes, alter the Git index or other Git metadata, or create a commit.
Keep the finalization inventory staging-independent. When project finalization guidance includes staging or generic commit preparation, defer staging, staged/index-relative inspection, and staged handoff to the runner-owned HANDOFF; omit alternate-index workarounds and commit preparation because polishing prohibits them. Do not run git add or inspect the staged diff in this turn. Express each applicable content check against HEAD or explicit trees. This phase-owned deferral is neither a validation blocker nor a skipped required check and must not prevent PASS. After candidate convergence and the fingerprint-bound finalization and terminal-confirmation gate pass, HANDOFF alone stages and performs fixed runner-owned staged-handoff hygiene; it never creates a commit.
Use PASS only after every agent-executed required check succeeds without being skipped, excluded, substituted, replaced, or weakened. Return the complete requiredChecks and validationInfrastructure actually used, and exactly one ordered checks entry for every required check with bounded direct evidence. Return NOT_RUN only for a command explicitly listed as runner-trusted in the turn context; the runner executes that persisted vector before it accepts the gate. Do not use any other host-reported or user-attested results.
Changes to package scripts, test discovery, test runners, validation configuration, the check inventory, or its infrastructure paths are allowed only when the task requires them; never make them merely to evade an environmental blocker.
Do not weaken sandboxing or grant network or host temporary-directory access to make validation pass.
For PASS, provide summary; set issues, options, and evidence to []; set reason, question, and whyBlocked to "".
For FAIL, provide summary and one or more issues with unique stable F-prefixed numeric IDs, each with command, problem, and evidence; set options and evidence to []; set reason, question, and whyBlocked to "".
For SKILL_MISSING or SKILL_INVALID, provide the attempted repository-relative skillPath and reason; set summary, question, and whyBlocked to "", and issues, requiredChecks, validationInfrastructure, checks, and options to []; evidence may be [].
For BLOCKED, use only when required validation cannot run because of sandbox, IPC, loopback, process-isolation, missing-service, permission, or comparable external constraints. Use the selected skillPath or "" when no skill is selected; preserve the complete inventory, report every check as PASS, BLOCKED, or NOT_RUN, set summary, question, and whyBlocked to "", and issues and options to []; provide reason and evidence.
For PRODUCT_DECISION_REQUIRED, set skillPath, summary, and reason to "", and issues, requiredChecks, validationInfrastructure, and checks to []; use the product-decision fields.`;

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

export const CANDIDATE_REVIEW_INSTRUCTIONS = `Review the complete current change set independently against the task, resolved context, architecture, tests, edge cases, minimality, and project conventions.

Do not modify the repository. Review the complete result as a semantic candidate. Do not run the project finalization procedure, attest finalization evidence, or perform generic handoff preparation; those remain owned by FINALIZE, CONFIRM, and HANDOFF.
Reuse an existing R-prefixed ID for an unchanged finding. Report every actionable blocker, but do not report preferences or already-resolved issues.
For APPROVED, set findings, options, and evidence to []; set question and whyBlocked to "".
For FINDINGS, provide one or more findings with stable IDs, repository-relative file, problem, reason, and suggestedAction; set question and whyBlocked to "", and options and evidence to [].
For PRODUCT_DECISION_REQUIRED, set findings to []; use the product-decision fields.`;

export const REVIEW_INSTRUCTIONS = `Confirm the finalized change set is correct, idiomatic, minimal, consistent with the project's conventions, and ready for runner-owned handoff.

Do not modify the repository. This is the distinct terminal confirmation over finalized content and evidence, not candidate review or generic handoff preparation. Reuse an existing R-prefixed ID for an unchanged finding. Report every actionable blocker, but do not report preferences or already-resolved issues.
Verify the exact required-check evidence and reject omissions, skips, substitutions, weakening, fingerprint mismatch, or validation-infrastructure changes that the task does not authorize.
Use validationChange UNCHANGED when no change occurred, ACCEPTED with validationEvidence when an authorized change remains complete, or REJECTED with validationEvidence and a finding when it is evasive or unauthorized.
For APPROVED, set findings, options, and evidence to []; set question and whyBlocked to "".
For FINDINGS, provide one or more findings with stable IDs, repository-relative file, problem, reason, and suggestedAction; set question and whyBlocked to "", and options and evidence to [].
For PRODUCT_DECISION_REQUIRED, set findings and validationEvidence to [], and validationChange to UNCHANGED; use the product-decision fields.`;

export const CHECK_AND_FIX_INSTRUCTIONS = `Review the changes and verify that they are correct, idiomatic, minimal, and consistent with the project's conventions. If you find any problems, fix them idiomatically and minimally, following the project's conventions.

Review the complete current result as a semantic candidate. Do not run the project finalization procedure, attest finalization evidence, or perform generic handoff preparation; those remain owned by FINALIZE, CONFIRM, and HANDOFF. Do not stage, unstage, or commit.
When candidate-confirmation findings are supplied, resolve them before reporting UNCHANGED; use UNCHANGED only when no supplied candidate-confirmation finding remains.
For CHANGED, use only when you changed repository content; provide summary and set reason, question, and whyBlocked to "", and options and evidence to [].
For UNCHANGED, use only when you found no problem and changed no repository content; provide summary and set reason, question, and whyBlocked to "", and options and evidence to [].
For BLOCKED, use only when required validation cannot run because of sandbox, IPC, loopback, process-isolation, missing-service, permission, or a comparable external constraint. Set summary, question, and whyBlocked to "", and options to []; provide reason and evidence.
For PRODUCT_DECISION_REQUIRED, set summary and reason to ""; use the product-decision fields.
Do not weaken sandboxing or grant network or host temporary-directory access to make validation pass.
${PRODUCT_DECISION_INSTRUCTIONS}`;

export const CANDIDATE_CLEAN_CONFIRM_INSTRUCTIONS = `Review the candidate changes and verify that they are correct, idiomatic, minimal, and consistent with the project's conventions.

Do not modify the repository. Return CLEAN only when there are no problems; otherwise return concrete findings without editing the content.
Do not run the project finalization procedure, attest finalization, validate terminal evidence, or perform generic handoff preparation; those remain owned by FINALIZE, CONFIRM, and HANDOFF.
For CLEAN, set question and whyBlocked to "", and findings, options, and evidence to [].
For FINDINGS, provide one or more findings with unique stable R-prefixed numeric IDs, a repository-relative file, and populated problem, reason, and suggestedAction fields; set question and whyBlocked to "", and options and evidence to [].
For PRODUCT_DECISION_REQUIRED, set findings to []; use the product-decision fields.
${PRODUCT_DECISION_INSTRUCTIONS}`;

export const CLEAN_CONFIRM_INSTRUCTIONS = `Confirm the finalized changes are correct, idiomatic, minimal, and consistent with the project's conventions, and ready for runner-owned handoff.

Do not modify the repository. This is the distinct terminal confirmation over finalized content and evidence. Return CLEAN only when there are no problems; otherwise return concrete findings without editing the content.
Verify the exact required-check evidence and reject omissions, skips, substitutions, weakening, fingerprint mismatch, or validation-infrastructure changes that the task does not authorize.
Use validationChange UNCHANGED when no change occurred, ACCEPTED with validationEvidence when an authorized change remains complete, or REJECTED with validationEvidence and a finding when it is evasive or unauthorized.
For CLEAN, set question and whyBlocked to "", and findings, options, and evidence to [].
For FINDINGS, provide one or more findings with unique stable R-prefixed numeric IDs, a repository-relative file, and populated problem, reason, and suggestedAction fields; set question and whyBlocked to "", and options and evidence to [].
For PRODUCT_DECISION_REQUIRED, set findings and validationEvidence to [], and validationChange to UNCHANGED; use the product-decision fields.
${PRODUCT_DECISION_INSTRUCTIONS}`;

export const LAZY_CHECKPOINT_CORRECTION_INSTRUCTIONS = `Your previous structured lazy checkpoint result was rejected by provider or deterministic validation. Return one complete replacement result using the same checkpoint schema.
Correct every identified field-and-constraint violation from current repository evidence and the complete durable checkpoint context. Do not quote or retain the rejected result, disclose provider diagnostics, ask an ordinary clarification question, or provide finalization, confirmation, review, approval, staging, or handoff evidence early. A CHECK_AND_FIX correction remains workspace-writable but must not change the index; report actual safe content mutation exactly. A CLEAN_CONFIRM correction remains repository-read-only. Preserve the original checkpoint semantics exactly. A repeated invalid result pauses the pipeline.`;

export const REVIEW_CORRECTION_INSTRUCTIONS = `Your previous structured candidate-review result was rejected by deterministic validation. Make the pending read-only correction and return a complete replacement result using the same candidate-review schema.
Correct every identified field-and-constraint violation from current repository evidence and the candidate-review context. Do not repeat or quote the rejected result, findings, provider output, prompt, or transcript; do not ask an ordinary clarification question or modify repository content, staging, history, refs, remotes, or Git identity. Preserve APPROVED, FINDINGS, and PRODUCT_DECISION_REQUIRED semantics exactly. A still-invalid replacement pauses for an explicit retry and never accepts the candidate.`;

export const CONFIRMATION_CORRECTION_INSTRUCTIONS = `Your previous structured terminal-confirmation result was rejected by deterministic validation. Make the pending read-only correction and return a complete replacement result using the same confirmation schema.
Correct every identified field-and-constraint violation from current repository and finalized evidence. Do not repeat or quote the rejected result, findings, commands, paths, provider output, prompt, or transcript; do not ask an ordinary clarification question or modify repository content, staging, history, refs, remotes, or Git identity. Preserve clean or approved, findings, validation-change, and PRODUCT_DECISION_REQUIRED semantics exactly as required by the unchanged confirmation contract. A still-invalid replacement pauses for an explicit retry and never confirms the work.`;

export const FINDING_RESOLUTION_INSTRUCTIONS = `Resolve every current blocker in one batch. Fix each valid blocker idiomatically and minimally. Dispute an incorrect Reviewer finding only with concise evidence. Modify safe workspace content only; do not stage or unstage changes or alter the Git index. The runner owns final staging after finalization and review.

Do not run the project finalization procedure, execute the established required-check inventory, perform generic commit preparation, or create a commit. Those actions remain owned by FINALIZE or HANDOFF as applicable. Finalization failures must be fixed and cannot be disputed. A finding already upheld by the Arbiter must be fixed.
For RESOLVED, return exactly one decision per blocker; every decision requires reason; DISPUTE requires evidence, while FIX evidence may be []. Set top-level reason, question, and whyBlocked to "", and options and evidence to [].
For BLOCKED, use only when required validation cannot run because of sandbox, IPC, loopback, process-isolation, missing-service, permission, or comparable external constraints. Set decisions and options to []; provide reason and evidence; set question and whyBlocked to "".
For PRODUCT_DECISION_REQUIRED, set decisions to [] and reason to ""; use the product-decision fields.
Do not weaken sandboxing or grant network or host temporary-directory access to make validation pass.`;

export const DISPUTE_RECONSIDERATION_INSTRUCTIONS = `Reconsider each disputed finding from the current repository evidence and the Worker's evidence.

Do not modify the repository. Withdraw an incorrect finding; uphold a valid one. Return exactly one decision for every dispute with reason and optional evidence.
For RESOLVED, set question and whyBlocked to "", and options and evidence to [].
For PRODUCT_DECISION_REQUIRED, set decisions to []; use the product-decision fields.`;

export const FINDING_ARBITRATION_INSTRUCTIONS = `Resolve the disputed finding from the task, repository, current changes, and recorded evidence.

Do not modify the repository. Choose WORKER_CORRECT when the finding should be withdrawn, REVIEWER_CORRECT when it must be fixed, or REQUIREMENT_AMBIGUOUS only for a genuinely blocking unresolved product requirement. Always provide rationale.`;

export const STAGNATION_INSTRUCTIONS = `Resolve a stalled polishing correction loop from the current blockers and compact correction history.

Do not modify the repository. This result cannot approve the changes or satisfy review. Choose CONTINUE_FIXES, REWORK_IMPLEMENTATION, or RECONSIDER_FINDINGS. Name only current Reviewer finding IDs for RECONSIDER_FINDINGS. Use PRODUCT_DECISION_REQUIRED only for a genuinely blocking unresolved product requirement. Always provide rationale.`;
