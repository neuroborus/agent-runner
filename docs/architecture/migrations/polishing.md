# Polishing Migrations

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

Polishing state version 3 adopts the same resolved trusted-validation snapshot,
per-check executor provenance, and fingerprint-bound evidence tuple. Its
version-2 migration selects empty legacy trust, preserves safe workspace
content, and invalidates active finalization and review evidence through the
existing independent validation-migration checkpoint before advancement.
Retained `BLOCKED` and `NOT_RUN` entries in paused or immutable failed evidence
become `FAIL` without losing their bounded diagnostics. Immutable terminal
evidence is shape-upgraded without replaying work.

Polishing state version 4 adds its bounded bootstrap-correction ledger and
pending one-shot diagnostic. Its version-3 migration initializes both without
changing accepted bootstrap context, validation evidence, workspace content,
or workflow position. Each producing role, bootstrap or validation-migration
phase, and contract may consume one read-only correction;
only attempt `1` and the bounded role, phase, contract, field, and constraint
are durable. A valid replacement clears the pending copy, an interrupted turn
reconstructs it from state, and a second invalid result fails closed without
retaining rejected values or provider output. Validation migration also
persists its accepted bounded disagreement before arbitration, resumes that
checkpoint directly, and clears it when the migration completes.

Polishing state version 5 adds the durable runner-owned `HANDOFF` boundary.
Its version-4 migration preserves immutable terminal history and untouched
preflight state, clears partial bootstrap evidence, and routes applicable
prepared nonterminal runs through fresh independent staging-free validation
before they can advance. Legacy paused evidence remains provisional until
resume invalidates it through that checkpoint.

Polishing state version 6 makes bootstrap, validation-migration, and
finalization inventories staging-independent. Its version-5 migration preserves
immutable terminal history, frozen inputs, safe content, counters, Git controls,
and trusted-validation state; clears incompatible partial bootstrap evidence;
invalidates stale active finalization and review gates; and routes prepared
nonterminal work through fresh independent inventory discovery. A legacy
`HANDOFF` is reconciled first: a complete verified effect becomes immutable
completion, an untouched pre-effect state enters discovery without staging, and
an incomplete or contaminated index fails closed.

Polishing state version 7 adds one finalization-correction record and a
matching pending marker scoped to the current content fingerprint. Its
version-6 migration initializes both to `null` without changing workflow
position or evidence. The first invalid Worker finalization result records only
attempt `1`, bounded resolved-or-fallback guidance and content-fingerprint
scope, and the role, phase, contract, field, and constraint diagnostic. The
runner reconstructs the complete finalization request from durable state and
uses the same schema for one fresh-session, read-only correction turn. A valid
replacement clears the pending marker and rejoins the existing gate; a second
invalid result for the same content fails closed. Content changes clear stale
correction scope. Rejected values, commands, paths, provider text, and
transcripts never enter state or public activity. Interrupted correction
recovery remains read-only and does not require a native session. `HANDOFF`
remains the sole Git-index owner for both Codex and Claude turns.

Recognized semantic finalization rejections retain source-defined field and
constraint diagnostics through normalization, durable feedback and terminal
failure. The polishing descriptor projects the latest terminal violation into
shared CLI/MCP pause evidence without resume authority. Unknown diagnostic-like
identities reduce to a generic semantic-contract diagnostic before corrective
requests or projection; accepted legacy shapes and terminal history remain
unchanged. The [polishing specification](../../../pipelines/polishing/docs/SPEC.md#finalize)
owns the exact rejection and correction rules.

Polishing state version 8 adds the resolved mode, the fingerprint accepted by
lazy clean confirmation, and the one-time lazy source-fork marker. Its
version-7 migration selects `independent` without moving active or terminal
workflow positions, changing safe workspace content, or replaying a pending or
completed `HANDOFF` effect.

Polishing state version 9 adds a pipeline-owned lazy-checkpoint correction
ledger and pending marker scoped to the checkpoint phase, finalized content
fingerprint, and validation-infrastructure fingerprint. Its version-8
migration initializes both fields empty without moving active or terminal
workflow positions, changing safe workspace content, or replaying a pending or
completed `HANDOFF` effect.

Polishing state version 10 separates semantic candidate convergence from the
terminal gate. Independent `REVIEW`, or lazy `CHECK_AND_FIX` plus candidate
`CLEAN_CONFIRM`, precedes `FINALIZE`; passing finalization enters the new
read-only `CONFIRM` checkpoint before `HANDOFF`. Candidate and terminal results,
fingerprints, and bounded correction diagnostics are distinct. The version-9
migration invalidates unprovable active gate evidence and routes it through safe
mode-specific candidate convergence, defers the same repair for paused runs,
and preserves `HANDOFF`, `DONE`, and `FAILED` without replaying staging.

Polishing state version 13 enables combined review with independent roles,
bootstrap, and isolated checkpoint sessions. Worker check/fix and separate
read-only clean confirmation precede independent candidate review of the same
fingerprint; independent terminal confirmation covers finalized content before
runner-only handoff. Durable `primaryFindings` keep self-findings separate from
independent findings. Content repairs clear both gates; unchanged resolutions
retain only current finalization. Only independent finding resolution permits
fresh arbitration; unresolved bootstrap and primary exhaustion pause. Version-12
migration adds an empty primary-findings record without changing saved mode,
correction budgets, or consumed handoff evidence.

Polishing state version 11 adds the same bounded semantic finalization recovery
as plan execution, with two automatic attempts per polishing run. Both terminal
roles share deterministic pure/mixed rejection routing within polishing. Exact
terminal-fingerprint overrides are checked first; otherwise rejected evidence is
invalidated immediately and replacement finalization plus fresh confirmation
must pass before runner-owned `HANDOFF`. Pending attempts survive interruption
and environment/provider blockage without recounting. Scope drift clears feedback
without restoring allowance; explicit retry after exhaustion grants one additional
attempt. The version-10 migration initializes metadata without moving checkpoints,
inferring old rejection output, or replaying pending or completed staging effects.
The existing polishing malformed-output correction budget and index restrictions
remain unchanged.
