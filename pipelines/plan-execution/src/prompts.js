import { MAX_BOOTSTRAP_ITEMS } from "./workflow-contract.js";

export const AGENT_GUIDANCE_SCOPE_INSTRUCTIONS =
  "Do not make or approve project `.agents` changes unless both the user's task and the current plan step explicitly require them; treat a violation as a finding, not a user question. Do not modify the resolved project configuration during a run.";

export const CLARIFICATION_INSTRUCTIONS = `Study the task, validated plan, existing clarifications, and repository before implementation. Ask only questions whose answers could materially change the required behavior, scope, or implementation of the plan.

Do not modify the repository.
If existing clarifications conflict with the validated plan, use PLAN_REVISION_REQUIRED.
For READY, provide stepAssessment; set questions, options, and evidence to [], and reason, question, and whyBlocked to "".
For QUESTIONS, provide one or more actionable questions with question and whyItMatters; set reason, question, and whyBlocked to "", and options and evidence to [].
For PLAN_REVISION_REQUIRED, set questions and options to []; provide reason and evidence; set question and whyBlocked to "".
For PRODUCT_DECISION_REQUIRED, set questions to [] and reason to ""; use the product-decision fields.`;

export const NO_DELEGATION_INSTRUCTIONS = `Produce this turn's result yourself as the authorized role. Do not delegate, spawn subagents, or use multi-agent collaboration.`;

export const PRODUCT_DECISION_INSTRUCTIONS = `Do not ask questions after clarification closes.
A blocking product-decision outcome is allowed only when the task, plan, repository, conventions, and prior clarifications leave a choice between materially different product requirements or behaviors unresolved and progress is otherwise impossible.
Do not use it for technical choices, implementation difficulty, naming, or ordinary review findings.
For that outcome, provide question, whyBlocked, and evidence; options may be [].`;

export const PLAN_COMPATIBILITY_INSTRUCTIONS = `Review the updated clarifications against the task, validated plan, completed commits, and repository.
Do not ask questions or modify the repository.
Using the provided schema, return READY when compatible; otherwise return PLAN_REVISION_REQUIRED with concise evidence.
For READY, set reason to "" and evidence to [].
For PLAN_REVISION_REQUIRED, provide reason and evidence.`;

const VALIDATION_INFRASTRUCTURE_INSTRUCTIONS = `Validation infrastructure means files that own validation commands, discovery, runners, configuration, or mandatory finalization guidance. Exclude ordinary source, individual tests, fixtures, and generated output merely consumed by checks. Classify by the file's responsibility, not its name or extension.`;

const CHECK_OWNERSHIP_INSTRUCTIONS = `Before putting any command in requiredChecks, determine the owner and checkpoint that the task, clarifications, repository instructions, and applicable skills assign to each validation obligation. requiredChecks contains only checks owned by this pipeline's finalization: ordinary checks run by the Worker FINALIZE turn, and selected Runner-trusted commands, which remain pipeline-owned with their frozen identities and capabilities even though Runner executes them on the host. A check that the task or clarifications explicitly assign to the supervising operator or another owner only after this run completes is mandatory external acceptance, not a pipeline check: record its owner, timing, and pending status in the summary, never run it, and never report it as run or passed. An operator-owned witness expected to fail never becomes a PASS-required command; negative assertions inside in-scope test commands remain required. A task's command list never drops other genuine in-scope requirements from repository conventions or applicable skills. Neither a label alone nor the machine that physically runs a check decides ownership; resolve a genuine conflict only through the existing bounded outcomes.`;

const EXTERNAL_ACCEPTANCE_SUMMARY_INSTRUCTIONS = `Keep post-completion acceptance that the task or clarifications explicitly assign to the supervising operator or another owner in the resolved summary as pending external work with its owner and timing; it is never a pipeline check, and this turn still cannot add, select, or remove commands, paths, or reports.`;

const VALIDATION_WORK_OWNERSHIP_INSTRUCTIONS = `Owner and timing assignments that the task or clarifications make explicit bind validation work for the whole run. Classify the work by its actual purpose, scope, and evidence against explicit task authority, never by its label. Executing a check reserved for another owner or a later checkpoint, its full equivalent, or a subset that the task or clarifications explicitly reserve is reserved work under any name or entrypoint; that never transfers its owner or permits early execution. Reading or inspecting source and focused development tests that the task and phase permit stay development work even when they overlap a reserved check: overlap is neither a violation nor completion, and the reserved check still runs in full under its owner. Explicit task restrictions on development work still apply.`;

const VALIDATION_WORK_REVIEW_INSTRUCTIONS = `${VALIDATION_WORK_OWNERSHIP_INSTRUCTIONS} Report a finding when evidence shows that reserved work actually ran early or under another owner, or that development evidence is claimed as reserved-check coverage, even when final acceptance is also left pending; calling the work inspection does not excuse it. Source observation or overlap alone is not a violation. When the evidence cannot establish what ran, do not invent command facts or report a confirmed violation; such work provides no reserved coverage. Keep honestly reported facts, useful content, and pending coverage; never approve early reserved execution or assert that it was undone.`;

const VALIDATION_WORK_ADJUDICATION_INSTRUCTIONS = `${VALIDATION_WORK_OWNERSHIP_INSTRUCTIONS} Decide each validation-work finding by the allegation it makes. Uphold an allegation that reserved work ran early or under another owner (UPHOLD or REVIEWER_CORRECT) when evidence shows that execution, whether or not anyone claimed coverage; withdraw it (WITHDRAW or WORKER_CORRECT) only when it rests solely on source observation, overlap, or unsupported inference, or when evidence shows the work was permitted development work. Uphold an allegation that development evidence was presented as reserved coverage when evidence shows that claim, even if the underlying work was permitted development work; withdraw it only when evidence shows no such claim was made. Relabeling or still-pending final acceptance never makes either allegation incorrect.`;

const EXTERNAL_ACCEPTANCE_CONFIRMATION_INSTRUCTIONS = `Leaving out post-completion acceptance that the task or clarifications explicitly assign to the supervising operator or another owner is not an omission. Reject evidence or summaries claiming that such acceptance ran or passed, and reject a finalization that adds it to the inventory. A missing genuine pipeline-owned check remains an omission. ${VALIDATION_WORK_REVIEW_INSTRUCTIONS}`;

const CAPABILITY_EXECUTOR_INSTRUCTIONS = `Describe needs and blockers for each command's actual future executor at its assigned checkpoint: the ordinary Worker FINALIZE turn under its existing declared workspace-write access, or Runner-trusted execution of a selected frozen exact command; never describe the current read-only discovery, migration, or Reviewer turn. An ordinary agent-executed command that writes only safe workspace output under that existing Worker access needs no report: no scratch, cache, projection, or unsupported need. Selected trusted commands remain reserved from agent execution; report every capability their trusted executor actually requires. sourceProjection is separate frozen authority, not a synonym for workspace-write; set it to true only when supported evidence shows the actual executor must write beside the staging-independent source the command validates. Report a genuine command-specific blocker, including a nondelegated one, only with evidence; never run an unpermitted probe or claim that no blockers exist without evidence.`;

export const BOOTSTRAP_INSTRUCTIONS = `Study the repository, task, validated plan, clarifications, project instructions, relevant finalization guidance, other relevant skills, project checks, tests, and Git history independently and without modifying the repository.
Return the following fields inside the schema's result object. Provide a concise bootstrap summary covering the task, relevant architecture and files, invariants, planned commits, risks, and the complete project finalization procedure. Independently identify every required check as a stable C-prefixed ID, exact command, and steps array of applicable canonical plan step numbers, plus every repository-relative file that controls those checks, package scripts, test discovery, test runners, or validation configuration.
Each check's steps must be a nonempty ascending list without duplicates or references outside the canonical plan. Independently provide a complete procedure for every plan step: the repository's ordinary fast gate for each step plus only slow checks whose documented guarantees that exact step affects. Include all selected trusted commands in the complete catalog, with their actual step applicability; selection alone does not make a check applicable to every step. Do not execute future-step checks during earlier finalization. The runner preserves each role's accepted assignments and derives stable Worker-first per-step inventories, unioning applicability of identical commands. Reconciliation and arbitration cannot discard or reassign requirements.
${VALIDATION_INFRASTRUCTURE_INSTRUCTIONS}
Cover every substantive validation requirement, but keep the summary and required-check inventory staging-independent. Do not require staging, a staged handoff, index mutation or inspection, an implicit worktree-versus-index assertion, an alternate index, or commit-message drafting. Generic commit preparation belongs only to COMMIT. Express an applicable content check against HEAD or explicit trees instead of the index.
${CHECK_OWNERSHIP_INSTRUCTIONS}
Required-check IDs must be unique. Exact commands must be unique, single-line, and already normalized without leading or trailing whitespace. Validation-infrastructure paths must be unique, existing, canonical repository-relative regular files, except for the exact declared label of selected external finalization guidance when supplied; never return a symlink or a path through a symlink, including a symlink alias of a canonical path.
Each inventory field has a per-role capacity of ${MAX_BOOTSTRAP_ITEMS} items. If the complete requiredChecks or validationInfrastructure inventory would exceed that capacity, do not truncate it or invent a placeholder. Check requiredChecks first, then validationInfrastructure, and return CAPACITY_EXHAUSTED for the first over-capacity field with capacityField set to its exact field name and capacityLimit set to ${MAX_BOOTSTRAP_ITEMS}.
Report capabilityRequirements and environmentBlockers as bounded arrays (up to 256 each), tied to exact commands in your requiredChecks inventory; use [] when none. Each capability requirement must identify at least one actual need: scratch, cache, a writable source projection, one or more artifacts, or one or more unsupported capabilities. Omit the report instead of returning an entry with no needs. Each requirement has command, commandIdentity (the supplied frozen identity or null), capabilities {scratch: boolean, cache: boolean, sourceProjection: boolean, artifacts: [{url, sha256}]}, and unsupported (up to 16 short capability identifiers). ${CAPABILITY_EXECUTOR_INSTRUCTIONS} Any non-null identity must exactly match the selected command's frozen identity; never invent or substitute one. Artifact URLs and SHA-256 must match the canonical HTTPS declaration contract; at most 32 artifacts per report. Do not request projection paths, credentials, or broader authority. Each environment blocker has command, source ("agent-sandbox" or "runner"), and evidence (1–8 concise single-line strings). Report missing runner selection or authority as needs, not as permission to grant them. The runner preserves every role's reports, evaluates the frozen declarations and actual availability, and pauses before writable work when unsatisfied. An agent-sandbox limitation is resolved only for that exact delegated command when runner inspection succeeds; a limitation of another command remains blocking. Do not execute required checks during discovery. Set both arrays to [] for every non-READY outcome.
For READY, provide summary, requiredChecks, and validationInfrastructure; set capacityField, reason, question, and whyBlocked to "", capacityLimit to 0, and options and evidence to [].
For CAPACITY_EXHAUSTED, set summary, reason, question, and whyBlocked to "", requiredChecks, validationInfrastructure, options, and evidence to [], and provide capacityField and capacityLimit as described above.
For PLAN_REVISION_REQUIRED, set summary, capacityField, question, and whyBlocked to "", capacityLimit to 0, and requiredChecks, validationInfrastructure, and options to []; provide reason and evidence.
For PRODUCT_DECISION_REQUIRED, set summary, capacityField, and reason to "", capacityLimit to 0, and requiredChecks and validationInfrastructure to []; use the product-decision fields.`;

export const REPOSITORY_DISCOVERY_INSTRUCTIONS = `Study the repository, task, complete validated plan, clarifications, project instructions, relevant skills, checks, tests, and Git history independently and without modifying the repository.
Provide a concise bootstrap summary covering architecture, relevant files, invariants, planned commits, risks, and the complete staging-independent finalization procedure. This discovery is a repository catalog, not a plan applicability matrix. Return the six discovery fields inside result: stepAssessment, summary, requiredChecks, validationInfrastructure, capabilityRequirements, environmentBlockers. Each required check has only id and exact command, without steps. Later focused batches assign applicability.
${VALIDATION_INFRASTRUCTURE_INSTRUCTIONS}
Keep commands unique, normalized, single-line and staging-independent. Use existing canonical regular repository files for infrastructure, plus the exact declared label of selected external finalization guidance when supplied. Include every frozen runner-trusted command. Do not execute required checks, modify content or Git state, or perform commit preparation. Staging, index-relative inspection, and commit-message drafting belong only to COMMIT.
${CHECK_OWNERSHIP_INSTRUCTIONS}
Report exact-command capability needs and environment blockers using the supplied schema and frozen command identities, or [] when none. ${CAPABILITY_EXECUTOR_INSTRUCTIONS} Never invent authority, omit requirements, truncate inventories, or persist provider messages. The per-role catalog limit is ${MAX_BOOTSTRAP_ITEMS}; report CAPACITY_EXHAUSTED using the exceptional schema if exceeded, checking requiredChecks before infrastructure.
For an incompatible plan or an unresolved material product decision, use the corresponding exceptional result schema with empty inventories and summary; technical choices are not product decisions.
${PRODUCT_DECISION_INSTRUCTIONS}`;

export const APPLICABILITY_INSTRUCTIONS = `Assess only the supplied contiguous canonical plan range against your own accepted repository discovery. Keep the repository and Git state read-only. Do not execute checks, perform finalization, or prepare a commit.
Return READY with the exact unitId and catalog-order assignments of checkId to ascending canonical steps within this unit. Every step must have its complete applicable procedure: the ordinary fast gate and only slow checks whose documented guarantees that step affects. A selected trusted command is not automatically applicable to every step. Omit a check assignment only when it applies to no step in this range. The complete plan must eventually assign every discovered check.
If commands, infrastructure, capability needs, or environment blockers are missing from discovery, return CATALOG_CORRECTION_REQUIRED, no assignments, and only new requirements. Do not silently change or drop accepted requirements. Catalog correction never adds post-completion acceptance that the task or clarifications explicitly assign to the supervising operator or another owner. READY has empty correction arrays. Use frozen input files if needed; normally continue from accepted discovery without repeating broad repository discovery. Return only the supplied schema's result object.`;

export const BOOTSTRAP_RECONCILIATION_INSTRUCTIONS = `Reconcile the independent Worker and Reviewer bootstrap summaries using the task, validated plan, repository, and evidence.
Do not force agreement or modify the repository. Return the following fields inside the schema's result object, with a concise resolved summary or the remaining material disagreement.
Keep every resolved summary staging-independent. Staging, staged handoff, index-relative checks, alternate-index workarounds, and commit-message drafting belong only to COMMIT; established checks are input only to the dedicated FINALIZE gate.
The runner derives each plan step's required-check inventory and the shared validation infrastructure from independently accepted role evidence. Reconciliation and arbitration cannot discard or reassign accepted check applicability. Do not propose, select, or repeat commands or repository paths. Every accepted role capability requirement and environment blocker is retained independently of this summary; reconciliation or arbitration cannot omit them or replace frozen authority.
${EXTERNAL_ACCEPTANCE_SUMMARY_INSTRUCTIONS}
For RESOLVED, provide summary; set disagreement, reason, question, and whyBlocked to "", and options and evidence to [].
For DISAGREEMENT, provide disagreement and evidence; set summary, reason, question, and whyBlocked to "", and options to [].
For PLAN_REVISION_REQUIRED, provide reason and evidence; set summary, disagreement, question, and whyBlocked to "", and options to [].
For PRODUCT_DECISION_REQUIRED, set summary, disagreement, and reason to ""; use the product-decision fields.`;

export const BOOTSTRAP_ARBITRATION_INSTRUCTIONS = `Resolve the bootstrap disagreement from the task, plan, repository, and evidence, choosing the minimal valid direction using the provided schema.
Return the following fields inside the schema's result object.

Do not modify the repository. Resolve only the recorded disagreement and do not rewrite requirements.
Always provide rationale.
Choose USE_WORKER or USE_REVIEWER only when that summary is correct, and SYNTHESIZE when the evidence supports a combined summary.
Keep the selected or synthesized summary staging-independent. Staging, staged handoff, index-relative checks, alternate-index workarounds, and commit-message drafting belong only to COMMIT; established checks are input only to the dedicated FINALIZE gate.
The runner derives each plan step's required-check inventory and the shared validation infrastructure from independently accepted role evidence. Reconciliation and arbitration cannot discard or reassign accepted check applicability. Do not propose, select, or repeat commands or repository paths. Every accepted role capability requirement and environment blocker is retained independently of this summary; reconciliation or arbitration cannot omit them or replace frozen authority.
${EXTERNAL_ACCEPTANCE_SUMMARY_INSTRUCTIONS}
For USE_WORKER, USE_REVIEWER, or SYNTHESIZE, provide summary; set reason, question, and whyBlocked to "", and options and evidence to [].
For PLAN_REVISION_REQUIRED, set summary, question, and whyBlocked to "", and options to []; provide reason and evidence.
For PRODUCT_DECISION_REQUIRED, set summary and reason to ""; use the product-decision fields.`;

export const BOOTSTRAP_CORRECTION_INSTRUCTIONS = `Your previous structured bootstrap result was rejected by deterministic validation. Make one read-only correction and return a complete replacement result using the same schema.
Correct every violation in the identified diagnostic batch using current repository evidence. Do not repeat or quote the rejected result, ask an ordinary clarification question, or modify the repository. Preserve the exceptional PRODUCT_DECISION_REQUIRED outcome and its required product-decision fields when its existing criteria are met. Preserve the CAPACITY_EXHAUSTED outcome and its capacity fields on the same basis. A repeated or still-invalid result fails closed.`;

export const FINALIZATION_RECOVERY_INSTRUCTIONS = `Terminal confirmation rejected the previous finalization evidence. Run the complete project finalization procedure again and return fresh evidence under the unchanged full contract.
Use only the bounded accepted findings below as correction feedback. They never authorize omitting, substituting, removing, or weakening an established check or infrastructure entry. Reinspect the repository and both inventories; do not reuse the rejected PASS or infer its native output. Apply only project-required formatting or generation, preserving ordinary finalization permissions. Content concerns have their own repair route; this turn is not discretionary code fixing.`;

export const FINALIZATION_CORRECTION_INSTRUCTIONS = `Your previous structured finalization result was rejected by deterministic validation. Make the requested bounded read-only correction and return a complete replacement result using the same finalization schema.
Diagnostic fields identify schema names and zero-based positions, never rejected values. Correct every member of the batch; unavailable provider field details remain unknown. A mixed batch containing any repeated violation cannot authorize another correction.
Correct every violation in the identified diagnostic batch using current repository evidence. Re-execute only corrected staging-independent checks as needed to produce complete direct evidence. Do not execute a rejected command, run staging-dependent validation, repeat or quote the rejected result, ask an ordinary clarification question, or modify repository content, staging, history, refs, remotes, or Git identity. Preserve the exceptional PRODUCT_DECISION_REQUIRED outcome and its required product-decision fields when its existing criteria are met. A second correction is available only for a wholly new diagnostic batch; a repeated diagnostic or another invalid result after that finite allowance fails closed.`;

const PREFINALIZATION_VALIDATION_INSTRUCTIONS = `The established required-check inventory is input only to the dedicated FINALIZE gate. Do not execute or attest it in this turn.
Selected runner-trusted commands must never execute inside an agent turn. Their agent-sandbox limitations must not cause BLOCKED or prevent applicable content repairs and semantic review; the runner executes their persisted exact vectors during FINALIZE.
${VALIDATION_WORK_OWNERSHIP_INSTRUCTIONS} Do not run reserved work in this turn or claim that it ran. Report development work only as development evidence, never as reserved-check coverage, and leave reserved checks pending with their owner and timing. The reservations above and selected commands' capabilities are unchanged.`;

export const IMPLEMENTATION_INSTRUCTIONS = `Implement the changes described in the following planned commit. Keep the implementation idiomatic and minimal, and follow the project's conventions.

Work only on this planned commit.
Do not run the project finalization procedure or perform generic commit preparation in this turn. Those belong to the dedicated FINALIZE and COMMIT phases.
${PREFINALIZATION_VALIDATION_INSTRUCTIONS}
Do not create a commit in this turn.
Before returning, perform a concise self-review.
Return the status fields inside the schema's result object.
For COMPLETED, put all results in summary; set reason, question, and whyBlocked to "", and options and evidence to [].
For BLOCKED, use only for external environment constraints affecting work not delegated to a selected runner-trusted command. Set summary, question, and whyBlocked to "", and options to []; provide reason and evidence.
For PRODUCT_DECISION_REQUIRED, set summary and reason to ""; use the product-decision fields.

Do not weaken sandboxing or grant network or host temporary-directory access to make validation pass.

${PRODUCT_DECISION_INSTRUCTIONS}`;

export const CANDIDATE_REVIEW_INSTRUCTIONS = `Review the changes and verify that they are correct, idiomatic, minimal, and consistent with the project's conventions.

Do not modify the repository.
Review the complete current result as a semantic candidate. Do not run the project finalization procedure, attest finalization evidence, or perform generic commit preparation; those remain owned by FINALIZE, CONFIRM, and COMMIT.
${VALIDATION_WORK_REVIEW_INSTRUCTIONS}
For APPROVED, set question and whyBlocked to "", and findings, options, and evidence to [].
For FINDINGS, provide one or more findings with unique stable R-prefixed numeric IDs, a repository-relative file, and populated problem, reason, and suggestedAction fields; set question and whyBlocked to "", and options and evidence to [].
For PRODUCT_DECISION_REQUIRED, set findings to []; use the product-decision fields.
${PRODUCT_DECISION_INSTRUCTIONS}
Otherwise, return only the candidate decision and actionable findings using the provided schema.`;

const TRUSTED_TIMING_INSTRUCTIONS = `Runner-trusted elapsed evidence measures the admitted attempt including preparation, retirement, cleanup and safety checks, not child runtime alone. Use only the persisted Runner measurement; unavailable legacy/controller timing stays unknown. Never measure a reserved command yourself, invent historical timing or rerun solely for missing telemetry.`;

export const REVIEW_INSTRUCTIONS = `Confirm the finalized changes are correct, idiomatic, minimal, consistent with the project's conventions, and ready for the authorized commit.

Do not modify the repository. This is the distinct terminal confirmation over the finalized content and evidence, not candidate review or generic commit preparation.
${TRUSTED_TIMING_INSTRUCTIONS}
Verify the exact required-check evidence and reject omissions, skips, substitutions, weakening, fingerprint mismatch, or validation-infrastructure changes that this planned commit does not authorize.
${EXTERNAL_ACCEPTANCE_CONFIRMATION_INSTRUCTIONS}
Return finalizationFindingIds as the unique subset of finding IDs concerning only finalization evidence and requiring no repository edit. It must be empty unless validationChange is REJECTED. Split mixed evidence and content concerns into separate findings; content findings must never appear in this subset. Pure evidence rejection reruns the complete finalization procedure; content findings follow ordinary repair.
Use validationChange UNCHANGED when no inventory or infrastructure change occurred and validation evidence is sufficient, ACCEPTED with validationEvidence when an authorized change remains complete, or REJECTED with validationEvidence and a finding when evidence is insufficient or a change is evasive or unauthorized. Evidence rejection is valid even when inventories are unchanged.
For APPROVED, set finalizationFindingIds to []; set question and whyBlocked to "", and findings, options, and evidence to [].
For FINDINGS, provide one or more findings with unique stable R-prefixed numeric IDs, a repository-relative file, and populated problem, reason, and suggestedAction fields; set question and whyBlocked to "", and options and evidence to [].
For PRODUCT_DECISION_REQUIRED, set findings, finalizationFindingIds, and validationEvidence to [], and validationChange to UNCHANGED; use the product-decision fields.
${PRODUCT_DECISION_INSTRUCTIONS}
Otherwise, return only the approval decision and actionable findings using the provided schema.`;

export const CHECK_AND_FIX_INSTRUCTIONS = `Review the changes and verify that they are correct, idiomatic, minimal, and consistent with the project's conventions. If you find any problems, fix them idiomatically and minimally, following the project's conventions.

Self-confirmation findings require fixing and cannot be disputed or arbitrated. In combined mode, primary convergence is followed by the complete independent Reviewer gate.
Review the complete current result as a semantic candidate. Do not run the project finalization procedure, attest finalization evidence, or perform generic commit preparation; those remain owned by FINALIZE, CONFIRM, and COMMIT. Do not create a commit.
${PREFINALIZATION_VALIDATION_INSTRUCTIONS}
For CHANGED, use only when you changed repository content; provide summary and set reason, question, and whyBlocked to "", and options and evidence to [].
For UNCHANGED, use only when you found no problem and changed no repository content; provide summary and set reason, question, and whyBlocked to "", and options and evidence to [].
For BLOCKED, use only for external environment constraints affecting work not delegated to a selected runner-trusted command. Set summary, question, and whyBlocked to "", and options to []; provide reason and evidence.
For PRODUCT_DECISION_REQUIRED, set summary and reason to ""; use the product-decision fields.
Do not weaken sandboxing or grant network or host temporary-directory access to make validation pass.
${PRODUCT_DECISION_INSTRUCTIONS}`;

export const CANDIDATE_CLEAN_CONFIRM_INSTRUCTIONS = `Review the candidate changes and verify that they are correct, idiomatic, minimal, and consistent with the project's conventions.

This primary confirmation does not replace independent candidate review when the selected mode requires it.
Do not modify the repository. Return CLEAN only when there are no problems; otherwise return concrete findings without editing the content.
Do not run or attest project finalization, validate terminal evidence, or perform generic commit preparation; those remain owned by FINALIZE, CONFIRM, and COMMIT.
${VALIDATION_WORK_REVIEW_INSTRUCTIONS}
For CLEAN, set question and whyBlocked to "", and findings, options, and evidence to [].
For FINDINGS, provide one or more findings with unique stable R-prefixed numeric IDs, a repository-relative file, and populated problem, reason, and suggestedAction fields; set question and whyBlocked to "", and options and evidence to [].
For PRODUCT_DECISION_REQUIRED, set findings to []; use the product-decision fields.
${PRODUCT_DECISION_INSTRUCTIONS}`;

export const CLEAN_CONFIRM_INSTRUCTIONS = `Confirm the finalized changes are correct, idiomatic, minimal, consistent with the project's conventions, and ready for the authorized commit.

Do not modify the repository. This is the distinct terminal confirmation over the finalized content and evidence. Return CLEAN only when there are no problems; otherwise return concrete findings without editing the content.
${TRUSTED_TIMING_INSTRUCTIONS}
Verify the exact required-check evidence and reject omissions, skips, substitutions, weakening, fingerprint mismatch, or validation-infrastructure changes that this planned commit does not authorize.
${EXTERNAL_ACCEPTANCE_CONFIRMATION_INSTRUCTIONS}
Return finalizationFindingIds as the unique subset of finding IDs concerning only finalization evidence and requiring no repository edit. It must be empty unless validationChange is REJECTED. Split mixed evidence and content concerns into separate findings; content findings must never appear in this subset. Pure evidence rejection reruns the complete finalization procedure; content findings follow ordinary repair.
Use validationChange UNCHANGED when no inventory or infrastructure change occurred and validation evidence is sufficient, ACCEPTED with validationEvidence when an authorized change remains complete, or REJECTED with validationEvidence and a finding when evidence is insufficient or a change is evasive or unauthorized. Evidence rejection is valid even when inventories are unchanged.
For CLEAN, set finalizationFindingIds to []; set question and whyBlocked to "", and findings, options, and evidence to [].
For FINDINGS, provide one or more findings with unique stable R-prefixed numeric IDs, a repository-relative file, and populated problem, reason, and suggestedAction fields; set question and whyBlocked to "", and options and evidence to [].
For PRODUCT_DECISION_REQUIRED, set findings, finalizationFindingIds, and validationEvidence to [], and validationChange to UNCHANGED; use the product-decision fields.
${PRODUCT_DECISION_INSTRUCTIONS}`;

export const LAZY_CHECKPOINT_CORRECTION_INSTRUCTIONS = `Your previous structured lazy checkpoint result was rejected by provider or deterministic validation. Return a complete replacement result using the same checkpoint schema.
Correct every identified field-and-constraint violation from the current repository and durable checkpoint evidence. Do not repeat or quote the rejected result, findings, commands, paths, provider output, prompt, or transcript; do not ask an ordinary clarification question. During CHECK_AND_FIX, reconcile only safe workspace content and report its actual mutation status. During CLEAN_CONFIRM, keep the repository read-only. Preserve the original checkpoint semantics exactly. A still-invalid replacement pauses for an explicit retry and never supplies finalization, confirmation, review, or commit evidence early.`;

export const REVIEW_CORRECTION_INSTRUCTIONS = `Your previous structured candidate-review result was rejected by deterministic validation. Make the pending read-only correction and return a complete replacement result using the same candidate-review schema.
Correct every identified field-and-constraint violation from the current repository and candidate-review context. Do not repeat or quote the rejected result, findings, provider output, prompt, or transcript; do not ask an ordinary clarification question or modify repository content, staging, history, refs, remotes, or Git identity. Preserve APPROVED, FINDINGS, and PRODUCT_DECISION_REQUIRED semantics exactly. A still-invalid replacement pauses for an explicit retry and never accepts the candidate.`;

export const CONFIRMATION_CORRECTION_INSTRUCTIONS = `Your previous structured terminal-confirmation result was rejected by deterministic validation. Make the pending read-only correction and return a complete replacement result using the same confirmation schema.
Correct every identified field-and-constraint violation from current repository and finalized evidence. Do not repeat or quote the rejected result, findings, commands, paths, provider output, prompt, or transcript; do not ask an ordinary clarification question or modify repository content, staging, history, refs, remotes, or Git identity. Preserve clean or approved, findings, validation-change, and PRODUCT_DECISION_REQUIRED semantics exactly as required by the unchanged confirmation contract. A still-invalid replacement pauses for an explicit retry and never confirms the work.`;

export const FINDING_RESOLUTION_INSTRUCTIONS = `For each finding below, fix it idiomatically and minimally, following the project's conventions.
If a finding is incorrect, dispute it with concise evidence instead of changing the code.

Do not run the project finalization procedure or perform generic commit preparation in this turn. Those belong to the dedicated FINALIZE and COMMIT phases.
${PREFINALIZATION_VALIDATION_INSTRUCTIONS}
Do not create a commit in this turn.
Return the status fields and finding decisions inside the schema's result object.
For RESOLVED, return exactly one decision per blocker; every decision requires reason; DISPUTE requires evidence, while FIX evidence may be []. Set reason, question, and whyBlocked to "", and options and evidence to [].
For BLOCKED, use only for external environment constraints affecting work not delegated to a selected runner-trusted command. Set decisions and options to []; provide reason and evidence; set question and whyBlocked to "".
For PRODUCT_DECISION_REQUIRED, set decisions to [] and reason to ""; use the product-decision fields.
Do not weaken sandboxing or grant network or host temporary-directory access to make validation pass.
${PRODUCT_DECISION_INSTRUCTIONS}
Otherwise, return each FIX or DISPUTE decision using the provided schema.`;

const FINALIZATION_RESULT_INSTRUCTIONS = `Use PASS only after every agent-executed required check succeeds without being skipped, excluded, substituted, replaced, or weakened. Return the complete requiredChecks and validationInfrastructure actually used, and exactly one ordered checks entry for every required check with bounded direct evidence. Return NOT_RUN only for a command explicitly listed as runner-trusted in the turn context; the runner executes that persisted vector before it accepts the gate. Do not use any other host-reported or user-attested results.
Each checks entry has exactly checkId, command, status and evidence. Match checkId and command exactly to requiredChecks at the same position. Each check's evidence array is nonempty, at most 32 items, each concise plain text up to 4000 characters. A Worker PASS may include reserved NOT_RUN placeholders; only Runner replacement can supply their execution evidence.
Post-completion acceptance that the task or clarifications explicitly assign to the supervising operator or another owner is not part of this inventory: do not add or run it. PASS covers only the pipeline-owned inventory; list that acceptance in the summary as pending external work with its owner and timing, never as run or passed. This never permits removing or weakening an established check.
${TRUSTED_TIMING_INSTRUCTIONS}
Changes to package scripts, test discovery, test runners, validation configuration, the check inventory, or its infrastructure paths are allowed only when this planned commit requires them; never make them merely to evade an environmental blocker.
Do not weaken sandboxing or grant network or host temporary-directory access to make validation pass.
For PASS, provide summary; set issues, options, and evidence to []; set reason, question, and whyBlocked to "".
For FAIL, provide summary and one or more issues with unique stable F-prefixed numeric IDs, each with command, problem, and evidence; set options and evidence to []; set reason, question, and whyBlocked to "". Commit-plan FAIL requires a failing check; custom criterion failures may retain passing or empty checks. A FAIL result cannot contain BLOCKED checks.
For SKILL_MISSING or SKILL_INVALID, provide the attempted selected guidance label in skillPath and reason; set summary, question, and whyBlocked to "", and issues, requiredChecks, validationInfrastructure, checks, and options to []; evidence may be [].
For BLOCKED, use only when required validation cannot run because of sandbox, IPC, loopback, process-isolation, missing-service, permission, or comparable external constraints. Use the selected skillPath or "" when no skill is selected; preserve the complete inventory, report every check as PASS, BLOCKED, or reserved NOT_RUN, including at least one BLOCKED agent-executed check. Set summary, question, and whyBlocked to "", and issues and options to []; provide reason and evidence. A selected Runner check's sandbox limitations never justify Worker BLOCKED.
For PRODUCT_DECISION_REQUIRED, set skillPath, summary, and reason to "", and issues, requiredChecks, validationInfrastructure, and checks to []; use the product-decision fields.
${PRODUCT_DECISION_INSTRUCTIONS}`;

export const FINALIZATION_INSTRUCTIONS = `Start with the established active-step inventory and preserve its required checks. The complete persisted schedule retains future requirements; do not add future-step checks unless the current planned change requires them. A justified current-step amendment may include an exact already selected runner-trusted command originally scheduled for another step. Return every selected command in the proposed inventory as NOT_RUN, including newly proposed checks; never execute any selected command in an agent turn. Selection reserves commands without requiring all of them in this step. Inventory amendments apply only to the current step and require distinct fingerprint-bound terminal confirmation. Any shared infrastructure change must remain valid for future requirements and receive explicit terminal confirmation.

Run the complete project finalization procedure in this dedicated turn and report its result using the provided schema. Follow every substantive instruction in the applicable project guidance, including required checks, project-required formatting or generated output, and staging-independent content review.

${VALIDATION_INFRASTRUCTURE_INSTRUCTIONS}
Do not perform unrelated fixes or create a commit.
Keep the finalization inventory staging-independent. When project finalization guidance includes generic commit preparation, defer staging, staged/index-relative inspection, alternate-index workarounds, staged handoff, and commit-message drafting to the authorized COMMIT turn. Do not run git add, inspect the staged diff, or draft a commit message in this turn. Express each applicable content check against HEAD or explicit trees. This phase-owned deferral is neither a validation blocker nor a skipped required check and must not prevent PASS.
The validated plan subject remains authoritative. After candidate convergence and the fingerprint-bound finalization and terminal-confirmation gate pass, the constrained COMMIT executor alone runs git add -A, performs fixed runner-owned staged-diff hygiene, and creates the subject-only commit.
${FINALIZATION_RESULT_INSTRUCTIONS}`;

const CUSTOM_FINALIZATION_INSTRUCTIONS = `Finalize only the current custom result against its agreed observable criteria and established active-step inventory. Review the analysis, criterion evidence and exact inspected outputs, using explicitly selected frozen guidance when present. Coding checks apply only when the user selected applicable coding requirements. A semantic-only inventory may be empty; every required candidate and terminal review still applies.
Report unmet criteria as FAIL with concrete issues even when no executable check fails. For a criterion issue, identify the criterion in its command field (for example, criterion:traceability); do not invent an executable check or misreport a passing check as failed.
Run applicable agent-executed checks in this dedicated turn. Preserve established checks; a justified current-step amendment may add an exact already selected command originally scheduled elsewhere and requires distinct fingerprint-bound terminal confirmation. Keep every selected command reserved from agent execution, including newly proposed checks; return included selected entries as ordered NOT_RUN. Selection does not require all future checks in this step. The runner executes only selected entries in the resulting inventory using their frozen exact vectors. Preserve their identities, capability declarations, later applicability and provenance.
Never stage, inspect an index-relative diff, prepare a commit, create a commit or change Git controls. No custom phase has commit authority. Do not perform unrelated repairs or change the accepted analysis/evidence during finalization; content repairs require fresh convergence.
${VALIDATION_INFRASTRUCTURE_INSTRUCTIONS}
${FINALIZATION_RESULT_INSTRUCTIONS}`;

export function finalizationBootstrapInstructions({
  selection,
  skillPath,
  planKind = "commit",
}) {
  if (selection === "fallback" && planKind === "custom")
    return "No finalization guidance is selected. Discover only criterion-dependent checks; never invent automatic coding gates.";
  if (selection === "fallback") {
    return "No finalization skill guidance is selected. Derive the complete finalization gate from repository instructions and project-defined checks; do not skip validation.";
  }
  return `The frozen finalization skill or Markdown procedure is ${skillPath}. Read only that exact confined Markdown file, do not substitute another path, and include it in validationInfrastructure.`;
}

export function finalizationGuidanceInstructions({
  skillPath,
  planKind = "commit",
}) {
  if (skillPath === null && planKind === "custom")
    return 'No finalization guidance is selected. Derive the gate from agreed custom criteria, preserving explicitly selected coding requirements. For PASS, FAIL or BLOCKED set skillPath to ""; never report SKILL_MISSING or SKILL_INVALID without a selected skill.';
  if (skillPath === null) {
    return `No finalization skill guidance is available for this turn. Derive and run the complete gate from repository instructions and project-defined checks; inspect relevant scripts and established validation commands instead of skipping validation.
For PASS, FAIL, or BLOCKED, set skillPath to "". Do not use SKILL_MISSING or SKILL_INVALID when no skill is selected.`;
  }
  return `The frozen finalization skill or Markdown procedure is ${skillPath}. Validate that exact confined Markdown file before following it; do not substitute another path or fall back to different guidance.
This frozen skill must remain present in validationInfrastructure. If it is missing or invalid, report SKILL_MISSING or SKILL_INVALID; repairing guidance requires a new run.
For PASS, FAIL, SKILL_MISSING, SKILL_INVALID, or BLOCKED, set skillPath to ${JSON.stringify(skillPath)}.`;
}

export const COMMIT_INSTRUCTIONS = `Validate readiness for the authorized local commit using the exact supplied subject. The constrained executor alone stages the exact finalized and reviewed workspace with git add -A, performs fixed staged-diff hygiene, and creates the subject-only commit.
Follow the adapter's readiness output contract exactly. If it requests a ready boolean, return only { "ready": true } when ready or { "ready": false } otherwise, with no other fields. A readiness refusal preserves the candidate for separately authorized follow-up; COMMIT has no durable readiness-output correction checkpoint.
Do not stage changes yourself, modify project content, amend history, bypass hooks, change Git identity or configuration, create other refs, or perform any remote write.`;

export const DISPUTE_RECONSIDERATION_INSTRUCTIONS = `Reconsider the disputed findings against the task, plan, repository, diff, and Worker evidence.

Do not modify the repository. Return WITHDRAW or UPHOLD with a concise reason for every disputed finding using the provided schema.
${VALIDATION_WORK_ADJUDICATION_INSTRUCTIONS}
For RESOLVED, return exactly one decision per dispute; every decision requires reason, while evidence may be []. Set question and whyBlocked to "", and options and evidence to [].
For PRODUCT_DECISION_REQUIRED, set decisions to []; use the product-decision fields.
${PRODUCT_DECISION_INSTRUCTIONS}`;

export const FINDING_ARBITRATION_INSTRUCTIONS = `Resolve the disputed finding from the task, plan, repository, diff, and evidence, choosing the correct outcome using the provided schema.

Do not modify the repository or rewrite requirements. Always provide rationale.
${VALIDATION_WORK_ADJUDICATION_INSTRUCTIONS}
For WORKER_CORRECT or REVIEWER_CORRECT, set question and whyBlocked to "", and options and evidence to [].
For REQUIREMENT_AMBIGUOUS, use the product-decision fields.`;

export const STAGNATION_INSTRUCTIONS = `Diagnose why the implementation correction loop is not converging and choose the minimal valid next direction using the provided schema.
Always provide rationale.
For CONTINUE_FIXES or REWORK_IMPLEMENTATION, set findingIds, options, and evidence to [], and reason, question, and whyBlocked to "".
For RECONSIDER_FINDINGS, provide one or more unique current Reviewer findingIds; set reason, question, and whyBlocked to "", and options and evidence to [].
For PLAN_REVISION_REQUIRED, set findingIds and options to [], and question and whyBlocked to ""; provide reason and evidence.
For PRODUCT_DECISION_REQUIRED, set findingIds to [] and reason to ""; use the product-decision fields.`;

// Adapt only a source-controlled instruction prefix. Frozen task/plan text,
// criterion conditions and evidence in the remaining context stay byte-for-byte.
export function customExecutionPrompt(prompt) {
  const bases = [
    CLARIFICATION_INSTRUCTIONS,
    PLAN_COMPATIBILITY_INSTRUCTIONS,
    REPOSITORY_DISCOVERY_INSTRUCTIONS,
    APPLICABILITY_INSTRUCTIONS,
    BOOTSTRAP_INSTRUCTIONS,
    BOOTSTRAP_RECONCILIATION_INSTRUCTIONS,
    BOOTSTRAP_ARBITRATION_INSTRUCTIONS,
    BOOTSTRAP_CORRECTION_INSTRUCTIONS,
    IMPLEMENTATION_INSTRUCTIONS,
    CHECK_AND_FIX_INSTRUCTIONS,
    CANDIDATE_CLEAN_CONFIRM_INSTRUCTIONS,
    CANDIDATE_REVIEW_INSTRUCTIONS,
    FINALIZATION_INSTRUCTIONS,
    CLEAN_CONFIRM_INSTRUCTIONS,
    REVIEW_INSTRUCTIONS,
    FINDING_RESOLUTION_INSTRUCTIONS,
    FINDING_ARBITRATION_INSTRUCTIONS,
    DISPUTE_RECONSIDERATION_INSTRUCTIONS,
    STAGNATION_INSTRUCTIONS,
  ];
  const base = bases.find((value) => prompt.startsWith(value));
  if (base === undefined) return prompt;
  const instructions =
    base === FINALIZATION_INSTRUCTIONS
      ? CUSTOM_FINALIZATION_INSTRUCTIONS
      : base
          .replace(
            "the repository's ordinary fast gate for each step plus only slow checks whose documented guarantees that exact step affects",
            "only checks required by that step's agreed criteria and explicitly selected coding requirements; semantic-only steps may have no executable checks",
          )
          .replace(
            "the ordinary fast gate and only slow checks whose documented guarantees that step affects",
            "only checks required by the agreed criteria and explicitly selected coding requirements; semantic-only steps may have no executable checks",
          )
          .replace(
            /Staging, [^\n]*?belong only to COMMIT\./gu,
            "Staging and commit preparation are forbidden throughout custom execution.",
          )
          .replace(
            "Generic commit preparation belongs only to COMMIT.",
            "No custom phase permits generic commit preparation.",
          )
          .replace(
            "Express an applicable content check against HEAD or explicit trees instead of the index.",
            "Validate the inspected custom inputs and outputs without staging or requiring Git.",
          )
          .replace(
            "For CHANGED, use only when you changed repository content;",
            "For CHANGED, use only when you changed workspace content or result data;",
          )
          .replace(
            "For UNCHANGED, use only when you found no problem and changed no repository content;",
            "For UNCHANGED, use only when you found no problem and changed neither workspace content nor result data;",
          )
          .replaceAll(", and Git history", "")
          .replaceAll("planned commit", "planned step")
          .replaceAll("authorized commit", "accepted-result checkpoint")
          .replaceAll("COMMIT", "ACCEPT");
  return instructions + prompt.slice(base.length);
}

export const WRITABLE_RESULT_RESTATEMENT_INSTRUCTIONS = `Restate the result of the retired Worker turn using the exact advertised schema.
Selected runner-trusted commands must never execute inside an agent turn. Their sandbox limitations must not cause BLOCKED; use BLOCKED only for external environment constraints affecting work not delegated to a selected runner-trusted command.
This is a read-only result correction, not another implementation or finding-resolution effect. Do not modify, stage, commit, finalize, execute validation commands, or replay any work. Inspect the preserved candidate and original turn facts below. The original task and plan are context, not authorization to implement them again.
Return only claims supported by inspected unchanged content and the original blockers. Never invent a FIX or DISPUTE disposition, withdraw a blocker, or infer completion from a malformed or missing response. If the result cannot be established safely, return BLOCKED with the missing proof. Preserve a current environment blocker or genuinely required product decision. Keep custom criterion evidence separate from the status envelope.
A valid result still requires every original convergence, review, finalization, confirmation and effect gate. Do not run the required-check inventory; it belongs to FINALIZE. Rejected responses are unavailable and must not be reconstructed from provider-private storage.`;
