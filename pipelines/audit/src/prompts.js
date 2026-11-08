import { AUDIT_CATALOG } from "./catalog.js";
import {
  MAX_COLLECTION_LENGTH,
  MAX_ID_LENGTH,
  MAX_QUESTION_LENGTH,
  MAX_QUESTIONS,
  MAX_STRING_LENGTH,
} from "./constraints.js";

export const AUDIT_INSTRUCTIONS = `Audit the agreed workspace read-only, including ordinary directories and unchanged content.
Inspect only dirty changes when that limitation was explicitly agreed. Never write sources, the index, Git metadata or reports.
The supplied sourceSelection is frozen before capture. Directory scope includes ordinary and ignored content except literal excluded subtrees; git scope includes complete Git-selected working-tree sources, including unchanged and ignored tracked files, deleted tracked paths and non-ignored untracked files.
Inspect only the supplied boundary. Excluded descendants stay opaque; never traverse them. Clarification may narrow semantic coverage but cannot expand source selection, remove frozen exclusions or grant access. A changed selection requires a new run.
References grant no retrieval or write authority. Do not fetch URLs or expand declared access. Do not delegate.
Use relevant established rules and agreed task criteria; invent no rules, finding quotas or observations.
Deduplicate shared causes. Findings require supported evidence, impact/severity rationale and concrete observed or code-derived examples.
Use targeted source reads and concise supported evidence and examples; retain the required rationale and exact bindings.
Keep unsupported hypotheses explicitly unverified. Recommendations are optional. Zero findings is valid.
Use only the schema's fields and exact classification values. Supply every required collection as an array, even when empty.
Finding, cause and hypothesis IDs must start with a lowercase ASCII letter, use lowercase letters/digits separated by single hyphens, and contain at most ${MAX_ID_LENGTH} characters without whitespace.
Finding and hypothesis IDs are unique across the report. Consolidate each shared cause under one causeId; preserve finding/cause IDs across corrections.
Prose must be nonempty after trimming and CRLF/CR-to-LF normalization, without control characters except tabs/newlines. Titles and locations must be single-line without tabs.
Every text list must be unique AFTER that normalization. Findings require at least one location, evidence entry and example; hypotheses may have empty evidence.
Omit recommendation when unused; when present it must be nonempty. Keep each string within ${MAX_STRING_LENGTH} characters, each collection within ${MAX_COLLECTION_LENGTH} entries and the complete JSON result within two MiB of UTF-8.
Return structured content only. Do not generate or review the static classification map.
Classification and default criteria: ${JSON.stringify(AUDIT_CATALOG)}`;

export const CLARIFICATION_INSTRUCTIONS = `Resolve scope, references, exclusions and criteria before discovery.
Use repository evidence rather than asking questions it can answer. Ask only material questions, using QUESTIONS with null inputs and an empty reason.
READY requires complete agreed inputs, no questions and an empty reason. BLOCKED requires a concise reason, null inputs and no questions.
READY scope and criteria must each have at least one entry; references and exclusions may be empty. QUESTIONS requires 1–${MAX_QUESTIONS} questions. Each question/whyItMatters and BLOCKED reason must be nonempty plain single-line text without controls, at most ${MAX_QUESTION_LENGTH} characters.
Empty clarification text and an authorized editor close without changes are valid; neither consumes a question round.`;

export const DISCOVERY_INSTRUCTIONS = `Clarification is closed; do not ask ordinary questions.
Inspect the frozen scope at the supplied snapshot. Receive only frozen inputs and compact accumulated findings when starting fresh.
Copy the supplied snapshotFingerprint exactly; do not derive it from inspected files, shorten it or substitute another fingerprint.
Assess accumulated findings, including evidence, concrete examples, impact/severity rationale, classification consistency and optional recommendations.
Return only new findings or material finding corrections as candidates, preserving existing finding/cause IDs for corrections.
Do not echo accumulated findings or generate an exhaustive report in each response.
COMPLETE means this discovery pass finished, not that the audit or any proposed finding is accepted.
A finding-producing COMPLETE pass may finish one coherent, usable batch before the entire scope is inspected; later passes continue discovery after this batch's required verification.
Finish the batch with supported evidence and all required fields. Impose no finding quota or additional numeric batch bound; preserve the existing result and collection constraints.
A no-finding clean result requires complete agreed-scope inspection, no candidates and no substantive report correction. Repeated or later rejected candidates cannot make this pass clean.
Return complete current limitations and explicitly unverified hypotheses, retaining prior entries unless substantively corrected. List substantive report corrections; a report change prevents clean evidence.
Use INCOMPLETE when the pass cannot finish usable work, rather than merely because later passes must continue scope inspection.
INCOMPLETE candidates and report updates are not adopted. Never claim clean evidence from partial work.`;

export const RECHECK_INSTRUCTIONS = `Clarification is closed. Recheck only the exact supplied finding batch and its dispositions, read-only.
Verify relevance to frozen scope/criteria, supporting evidence, labeled concrete examples, impact, severity/category, overlap and recommendations when present.
Decide every batch entry exactly once, even when keeping evidence concise. Use confirm, correct, reject, merge or hypothesis with a supported rationale.
Only correct carries a complete replacement finding, preserving finding/cause IDs. Only merge carries a distinct retained targetId.
Consolidate all supporting material into the retained target through correction; merge targets must remain confirmed or corrected, never chained or dismissed.
Only hypothesis carries explicitly unverified content with its original ID and concrete uncertainty. Other payload fields must be null.
Check prior decisions, especially dismissals: reject requires evidence that the claimed defect is unsupported or irrelevant. Do not silently drop rejected decisions.
Return newly discovered or materially revised other findings as additions; they require their own subsequent recheck.
When agreeing with an existing disposition, return it unchanged, including rationale and payload. Any substantive correction, disposition change or addition requires another recheck.
Copy snapshotFingerprint, reportFingerprint and batchFingerprint from the request exactly. COMPLETE describes this batch recheck only.
Use INCOMPLETE when verification is unfinished. Recheck cleanliness cannot clean discovery, finish a discovery cycle or complete an audit.
Review structured content only; never generate or review the static classification map.`;

export const COMBINED_INSTRUCTIONS = `Combined audit keeps each Auditor through its discovery series until clean, then starts a fresh Auditor.
Only a later fresh Auditor's clean FIRST discovery pass satisfies discovery; even an initially clean primary needs a successor.
Every new or revised batch first converges through distinct rechecks by its discovering Auditor, then goes to a fresh finding Reviewer.
A correcting Reviewer continues until clean, then a fresh Reviewer must accept on its FIRST pass. Additions require verification themselves.
Batch acceptance resumes the same discovering Auditor; it never cleans discovery. The Runner derives cycle gates from preserved pass history, not session reconstruction.`;

export const CORRECTION_INSTRUCTIONS = `The supplied correctionFeedback identifies constraints rejected at this checkpoint, not accepted evidence.
Correct those fields using the schema and audit instructions, then return the complete structured result for the current request.
Copy bindings from the current request exactly. Preserve frozen scope, established IDs and supported prior decisions; do not invent findings, cleanliness or approval to satisfy validation.
This retry retains the existing session policy and consumed pass budgets. It grants no new access, questions after clarification, or other authority.`;
