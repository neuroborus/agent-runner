import { AUDIT_CATALOG } from "./catalog.js";

export const AUDIT_INSTRUCTIONS = `Audit the agreed workspace read-only, including ordinary directories and unchanged content.
Inspect only dirty changes when that limitation was explicitly agreed. Never write sources, the index, Git metadata or reports.
References grant no retrieval or write authority. Do not fetch URLs or expand declared access. Do not delegate.
Use relevant established rules and agreed task criteria; invent no rules, finding quotas or observations.
Deduplicate shared causes. Findings require supported evidence, impact/severity rationale and concrete observed or code-derived examples.
Keep unsupported hypotheses explicitly unverified. Recommendations are optional. Zero findings is valid.
Return structured content only. Do not generate or review the static classification map.
Classification and default criteria: ${JSON.stringify(AUDIT_CATALOG)}`;

export const CLARIFICATION_INSTRUCTIONS = `Resolve scope, references, exclusions and criteria before discovery.
Use repository evidence rather than asking questions it can answer. Ask only material questions, using QUESTIONS with null inputs and an empty reason.
READY requires complete agreed inputs, no questions and an empty reason. BLOCKED requires a concise reason, null inputs and no questions.
Empty clarification text and an authorized editor close without changes are valid; neither consumes a question round.`;

export const DISCOVERY_INSTRUCTIONS = `Clarification is closed; do not ask ordinary questions.
Inspect the frozen scope at the supplied snapshot. Receive only frozen inputs and compact accumulated findings when starting fresh.
Assess accumulated findings, including evidence, concrete examples, impact/severity rationale, classification consistency and optional recommendations.
Return material finding corrections as candidates with their existing finding/cause IDs.
COMPLETE means this discovery pass finished, not that the audit or any proposed finding is accepted.
A clean discovery proposes no candidates and needs no substantive report correction. Repeated or later rejected candidates cannot make this pass clean.
Return complete limitations and explicitly unverified hypotheses. List substantive report corrections; a report change prevents clean evidence.
Use stable finding/cause IDs across revisions. Return INCOMPLETE when inspection is unfinished; never claim clean evidence from partial work.`;

export const RECHECK_INSTRUCTIONS = `Clarification is closed. Recheck only the exact supplied finding batch and its dispositions, read-only.
Verify relevance to frozen scope/criteria, supporting evidence, labeled concrete examples, impact, severity/category, overlap and recommendations when present.
Decide every batch entry exactly once. Use confirm, correct, reject, merge or hypothesis with a supported rationale.
Only correct carries a complete replacement finding, preserving finding/cause IDs. Only merge carries a distinct retained targetId.
Consolidate all supporting material into the retained target through correction; merge targets must remain confirmed or corrected, never chained or dismissed.
Only hypothesis carries explicitly unverified content with its original ID and concrete uncertainty. Other payload fields must be null.
Check prior decisions, especially dismissals: reject requires evidence that the claimed defect is unsupported or irrelevant. Do not silently drop rejected decisions.
Return newly discovered or materially revised other findings as additions; they require their own subsequent recheck.
When agreeing with an existing disposition, return it unchanged, including rationale and payload. Any substantive correction, disposition change or addition requires another recheck.
Copy snapshotFingerprint, reportFingerprint and batchFingerprint from the request exactly. COMPLETE describes this batch recheck only.
Use INCOMPLETE when verification is unfinished. Recheck cleanliness cannot clean discovery, finish a discovery cycle or complete an audit.
Review structured content only; never generate or review the static classification map.`;
