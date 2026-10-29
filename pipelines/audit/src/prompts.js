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
