# Plan-Execution Migrations

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Commit-effect compatibility

Plan execution persists each prepared or consumed one-shot commit authorization
and every verified commit SHA. After an ambiguous commit turn, resume verifies
the recorded authorization against Git state and never replays the effect.
An adapter may record `commitExecutor: "not_started"` only at the `commit`
checkpoint, with `none` or `possible` effect evidence, when it proves that its
isolated commit executor was never invoked. The boundary derives
`effectStarted: false` from that validated record. The pipeline durably records
that bounded proof on the consumed authorization before Git verification. After
Git independently confirms that no commit was created and controls, accepted
content and the original semantic index are unchanged, the pipeline retires the
authorization before an eligible later resume can issue a fresh ID. An absent
marker or executor failure keeps the consumed authorization on the verification-only
path, while interrupted verification retains any recorded proof for resume.
For unchanged HEAD, the Git capability also recognizes exact authorized full
staging as `ERR_COMMIT_NOT_CREATED` with bounded `changes: ["index"]` evidence.
Private content helpers use the shared [compatible-domain staging proof](../git-conversion.md) and reject semantic flags and resolve-undo state;
controls, content and index stability are rechecked without writing. Incomplete,
mismatched, hidden or unsafe index effects remain contract violations. The
execution pipeline retains the original consumed authorization, bindings and
staged effect and pauses `commit_failed`; repeated or reconstructed resume only
verifies, without readiness, restaging, commit replay or inferred completion.
Observed staging contradicting a pre-executor refusal is instead a contract
violation and cannot retire authorization. Existing successful-commit checks,
nested-repository rejection and durable state versions remain unchanged. This
does not retroactively recover historical rejected pauses.
Claude validates the exact boolean readiness shape before its value and emits
only the finite provider-neutral [readiness diagnostics](../../product/PROVIDER_MODEL.md#isolation-and-effects).
Execution carries the class through the consumed rejection and retired
`commit_failed` pause. Classified readiness refusals preserve the reviewed
candidate and offer separately authorized follow-up, with no same-run COMMIT
retry or readiness-output correction. CLI and MCP share the fixed constraint,
class evidence and null public resume state; legacy classless recovery remains
unchanged. An interrupted verification still reconciles the consumed effect
before applying that disposition, never reinvoking readiness or the executor.
Polishing has no commit authorization and preserves the initial `HEAD`, refs,
remotes, and Git identity through completion.

## Step-scoped validation and bounded bootstrap

Plan execution state version 23 scopes validation to canonical plan steps. Its
private `validation-schedule.js` derives per-step inventories from immutable
Worker-first accepted role assignments, unioning applicability of identical
commands. Independent and combined retain both roles; lazy retains Worker only.
Each role must cover every step with its complete applicable procedure. Shared
infrastructure stays globally fingerprinted. The persisted schedule must match
its role evidence; only a confirmed current-step amendment may overlay the
active inventory. Verified advancement clears that amendment and prior gates
and selects the next schedule entry.

An amendment can add an exact selected trusted command originally assigned
elsewhere. Finalization normalizes against the full frozen selected catalog,
requiring `NOT_RUN` even for newly proposed entries. Its normal, correction and
reconstruction prompts retain that complete reservation list, as does terminal
confirmation. `validation-schedule.js` intersects the resulting explicit
candidate inventory with the frozen selection for execution; it never runs all
future checks automatically. Original vectors, capabilities and bindings remain
authoritative; persisted selected results require runner provenance and the exact
command identity.
Only the existing distinct terminal confirmation accepts the step-local amendment;
role inventories, later schedules, state shape and version remain unchanged.

State version 27 stores that schedule as one ordered `commands` catalog and
per-step zero-based `commandIndexes`, expanding contiguous local check IDs only
for the selected step. This prevents long commands from multiplying by the
number of plan steps inside state and recovery prompts. The leased version-26
migration verifies the complete legacy schedule against its immutable role
assignments before replacing only its representation. It preserves amendments,
gate evidence, counters, and prepared or consumed commit effects.

Plan execution also owns private pure repository-discovery and bounded
applicability-unit contracts in `bootstrap-units.js` and
`bootstrap-unit-schemas.js`, with shared inventory fragments isolated in
`validation-schema-fragments.js` from complete response-schema exports. They
reuse its inventory validators and bind ordered complete coverage and shared
correction accounting to frozen inputs, role, catalog, and repository evidence.
They expose no runtime capability or public package API. Private
`bounded-bootstrap.js` activates discovery followed by focused applicability
turns for both bootstrap and validation migration; `bootstrap-progress.js`
validates the durable work and independent output-subdivision allowance.
Accepted discovery and each complete unit pass through the existing write-ahead
transition before advancement. Exhaustion can subdivide only the unfinished
read-only applicability unit, with its allowance consumed in the same durable
transition. Discovery and indivisible exhaustion pause; semantic corrections
remain a separate shared producing-role allowance. Catalog corrections and
unexpected drift invalidate dependent proof without replenishing allowances.

Execution state version 28 adds per-role nullable bound work and consumed split
counts. Its ordered version-27 migration preserves compatible complete
inventories, schedules, amendments, correction accounting, completed commits,
and historical confirmation proof without inventing batch evidence. Unfinished
roles use discovery; consumed effects settle first. Frozen inputs, accepted
catalogs, and pending units reconstruct requests without a native session or
routinely repeating the applicability matrix. Migration bootstrap turns retain
a distinct read-only identity across interruption and operator stops; repository
drift pauses and invalidates stale work without renewing allowances. Saved
version-27 availability and inactivity records keep their exact checkpoint for
the same role and suspended phase's read-only migration until successful
reconciliation, preserving consumed recovery accounting alongside the new turn
identity. The
[execution specification](../../../pipelines/plan-execution/docs/SPEC.md#durable-bounded-bootstrap)
owns exact bounds, state, acceptance, and recovery rules.

Finalization records its active step and exact ordered checks; terminal
confirmation hashes the complete canonical evidence tuple. Resume validates
both bindings before reuse. Confirmation also sees future requirements when
assessing shared infrastructure changes. Trusted capability inspection uses the
complete catalog and both roles' additive reports. Finalization reserves the full
selection and executes only selected entries in the explicit current candidate
inventory, including justified amendments. The frozen snapshot, vectors, identities,
and command/configuration fingerprints stay intact.

Both coding pipelines deliver the frozen `finalizationGuidance` decision beside
the established validation tuple. Their finalization and terminal instructions
explain the fingerprint domains and Runner-owned persisted additions:
`fingerprint`, `validationInfrastructureFingerprint`, `trustedCommandFingerprint`,
`trustedConfigurationFingerprint`, `validationChanged`, execution's `step`, and
per-check `executor`, `commandIdentity`, `exitCode`, `signal`, and `timedOut`.
Execution additionally binds confirmation with `validationTupleFingerprint`.
These are not role output fields. The closed role schemas remain authoritative,
and Worker check output still contains only `checkId`, `command`, `status`, and
`evidence`. Fresh, continued, reconstructed, corrective, and evidence-recovery
requests preserve this contract. Roles independently assess content, complete
checks, authorized inventory changes and exact evidence bindings; a different
raw digest alone is no finding, while actual drift or insufficient evidence
remains blocking. Reviewing evidence never authorizes reserved-check execution
or Runner CLI/admission management.

Each pipeline's prompt module also owns procedure-order guidance, composed into
bootstrap discovery, finalization and both terminal-confirmation variants.
Bootstrap discovers known applicable supplemental validators early. Workers
retain established check identities and exact commands while positioning
amendments to preserve project-defined first, final and relative-order
constraints in the declared inventory and ordered evidence. Reordering the
current inventory never rewrites original discovery or future assignments.
Inventory order proves no physical execution sequence: Worker completes its
agent-owned checks and returns reserved `NOT_RUN` placeholders; Runner later
executes frozen selected vectors and replaces those entries in inventory
positions under existing unchanged-content and infrastructure guards. No later
Worker phase is required. The only order exception is a controller fact: each
pipeline's workflow is the sole producer of `executor: "runner"` entries and,
after Worker returns, awaits one selected trusted execution at a time in
inventory order. Each attempt resolves only after verified retirement and
cleanup, infrastructure is rechecked before the next attempt, a failure does
not skip later entries, and a pause, block, guard failure or crash persists no
partial finalization evidence. Within one persisted record, Runner-attributed
entries therefore establish their relative physical order after that
`FINALIZE` turn's agent-owned work. No witness, hash, schema field or state
version records this; legacy migrated entries stay agent-attributed and
order-unknown. Separately explicit physical sequencing requirements remain
binding; incompatibility with existing ownership/checkpoints uses existing
blocking outcomes without new permissions or an invented product decision.
Terminal roles never reject evidence solely for absent telemetry or for
established Runner order; insufficient proof of a mandatory sequence uses
bounded evidence rejection, while proven uncorrectable violation keeps the
`VALIDATION_POLICY_BLOCKED` route.
`COMMIT`/`HANDOFF` retains separate fixed staged hygiene.
Terminal roles read the actual selected guidance and mandatory references and
assess the complete resulting procedure, including additions;
passing checks alone cannot establish procedural compliance. The same owners
feed continued, reconstructed, corrective and evidence-recovery requests.
This strengthens semantic delivery without parsing project prose, changing the
first-seen bootstrap union or evidence domains, guaranteeing model compliance,
or automatically repairing historical runs. Existing bounded evidence-only
recovery can repair ordering without changing content.

The explicit version-22 migration retains historical unscoped evidence under a
provisional legacy marker. It never infers applicability. Before unfinished
work advances, a read-only barrier invalidates active gates and requires scoped
discovery by every mode-required role. Accepted partial discovery survives
restart. Completed effects, pauses, configuration, and correction accounting
are preserved; terminal history remains readable. Consumed stagnation arbitration
and pending rework survive discovery; incompatible pending correction markers
retire without resetting their ledgers or fix accounting. Consumed commit
verification precedes discovery and capability preparation, with any subsequent
unfinished step subject to the same barrier. Older historical inventory contracts below
remain relevant to their migration chain.

## Historical gate and correction migrations

Plan execution state version 3 adds the nullable bounded pre-effect rejection
record to each pending commit. Its version-2 migration sets that record to
`null`; it never infers proof for a legacy consumed authorization.

Plan execution state version 4 adds a bounded bootstrap-correction ledger. Its
version-3 migration initializes an empty ledger without changing accepted
bootstrap context, validation evidence, workspace content, commit authority, or
workflow position. Each producing role, phase, and contract may consume at most
one read-only correction attempt. The durable entry contains only attempt `1`
and the existing bounded role, phase, contract, field, and constraint
diagnostic; rejected values and provider output are never persisted. A bounded
pending copy distinguishes a correction that still must run from consumed
history and is cleared as soon as a valid replacement is accepted. Each adapter
maps its native structured-output failure to the shared bounded
`structured-output` failure class. Pipelines consume only that backend-neutral
class, and plan execution turns it into the bounded semantic diagnostic only
after read-only mutation checks complete.

Plan execution state version 5 adds the resolved trusted-validation snapshot
and executor provenance to every accepted per-check result. Its version-4
migration selects empty legacy trust and invalidates active finalization and
review gates through the existing independent validation-migration checkpoint.
Immutable terminal evidence is shape-upgraded, and a consumed one-shot commit
authorization remains on its verification-only path; migration never makes it
replayable.

Plan execution state version 6 makes validation inventories staging-independent
and assigns the Git index exclusively to `COMMIT`. Its version-5 migration
shape-upgrades clarification, preflight, and immutable terminal states without
rediscovery; clears partial bootstrap evidence at an unfinished bootstrap; and
routes every other prepared nonterminal run through fresh independent summaries,
resolved context, and validation before advancement. A consumed commit
authorization and its gate evidence stay on the verification-only path. Git
verification runs before reconciliation, migration discovery, or another role
turn, and any still-pending migration resumes only after that effect is resolved.

Plan execution state version 7 adds one finalization-correction record and a
matching pending marker scoped to the current commit step. Its version-6
migration initializes both to `null` without changing workflow position or
evidence. The first invalid Worker finalization result records only attempt `1`,
the step, bounded guidance and content-fingerprint scope, and the role, phase,
contract, field, and constraint diagnostic. The runner then reconstructs the
complete finalization request from durable state and uses the same schema for
one fresh-session, read-only correction turn. A valid replacement clears the
pending marker and rejoins the existing gate; a second invalid result fails
closed. Rejected values, commands, paths, provider text, and transcripts never
enter state or public activity. Interrupted correction recovery remains
read-only and does not require a native session.

Plan execution state version 8 replaces that single record with a two-entry
finalization-correction ledger and one pending attempt. Its version-7 migration
preserves a consumed or pending attempt as the first one-entry diagnostic batch
without changing workflow position, evidence, or correction scope.
Deterministic finalization validation batches independently detectable
violations where practical and always includes every staging-dependent required
command. The first batch may authorize attempt `1`; one wholly new batch may
authorize attempt `2`. Any repeated diagnostic, mixed repeated/new batch, or
invalid result after attempt `2` fails closed. Guidance identifies how to
reconstruct a pending request and never creates another budget. The ledger is
scoped to the current step and request content fingerprint and is cleared when
that content scope changes. Rejected commands, paths, values, provider text,
and transcripts remain outside state and public activity, while interruption
preserves the pending attempt without replaying or recounting it.

Finalization normalizers attach fixed constraint identifiers to schema fields
and trusted zero-based check/issue positions. Independent violations are collected
within the existing 512-diagnostic bound; invalid inventories suppress dependent
identity comparisons. Reserved checks require Worker `NOT_RUN` and Runner
replacement before persisted acceptance. CLI and MCP share the pipeline pause
projection, which exposes the validated first terminal finalization diagnostic
through its existing evidence list without new recovery authority. Unknown
provider fields retain the semantic fallback; no rejected values or exception
prose enter diagnostic identities, and no state migration or allowance changes.

Plan execution state version 9 makes user finding overrides unique by exact
finding ID and reviewed content fingerprint and requires every finalization
validation-infrastructure candidate to pass the same existing canonical-file
inspection as bootstrap evidence before fingerprinting or review. Its version-8
migration deduplicates legacy override audit entries, preserves completed
commits, safe current-step content, counters, Git controls, and one-shot commit
effect safety, and marks active validation evidence provisional. Before
advancement, the existing validation-migration checkpoint independently
rediscovers the complete stable inventory and invalidates provisional
finalization and review evidence. Immutable terminal history is shape-upgraded
without replaying work.

Plan execution state version 10 replaces each consumed or pending bootstrap
correction's single field diagnostic with one bounded, deduplicated diagnostic
batch. Its version-9 migration losslessly wraps every existing diagnostic in a
one-entry batch without changing workflow position, accepted context, safe
content, gates, counters, or commit authority. Deterministic bootstrap and
validation-migration validation collects all independently detectable
violations from one candidate where practical, including every
staging-dependent required command and every lexically valid
validation-infrastructure path that canonical-file inspection rejects. The
producing role still receives exactly one correction attempt for its phase and
contract; a pending batch survives interruption and is cleared only after a
valid complete replacement is accepted. Repeated or still-invalid output fails
closed. Durable state and public activity contain only bounded diagnostic
identities, never rejected values, commands, paths, provider output, or
transcripts.

Plan execution state version 11 adds one final-Reviewer correction record and
a pending marker scoped to the current step, finalized content fingerprint,
and validation-infrastructure fingerprint. Its version-10 migration initializes
both to `null` without moving the workflow, altering accepted finalization or
review evidence, reviving terminal runs, or inferring rejected output that was
never retained. The first provider structured-output, normalization, or
validation-change consistency failure records attempt `1` and only bounded
Reviewer/review field-and-constraint diagnostics, then reconstructs the full
unchanged review request for a fresh-session, read-only correction with the
same schema. Interruption and backend unavailability preserve that pending
attempt without replay or recounting. A still-invalid replacement pauses at
the deliberately retryable `review_output_invalid` REVIEW checkpoint; an
explicit retry reruns the pending correction without approving content or
bypassing finalization, findings, fingerprints, Git guards, or commit
authorization. Rejected values, findings, commands, paths, provider output,
prompts, and transcripts never enter durable state or public activity.

Plan execution state version 12 adds the resolved mode, the fingerprint
accepted by lazy clean confirmation, and the one-time lazy source-fork marker.
Its version-11 migration selects `independent` without moving active or terminal
workflow positions, changing completed commits, or replaying a pending or
consumed one-shot commit effect.

Plan execution state version 13 adds a pipeline-owned lazy-checkpoint
correction ledger and pending marker. Each record is scoped to the current
step, `CHECK_AND_FIX` or `CLEAN_CONFIRM` phase, finalized content fingerprint,
and validation-infrastructure fingerprint and retains only attempt `1`, whether
actual fix work was already charged, and bounded Worker field-and-constraint
diagnostics. The version-12 migration
initializes both fields empty without moving active or terminal workflow
positions, changing accepted gates or completed commits, reviving terminal
runs, or replaying agent or commit effects.

Plan execution state version 14 separates semantic candidate convergence from
the terminal gate. Independent `REVIEW`, or lazy `CHECK_AND_FIX` plus candidate
`CLEAN_CONFIRM`, now precedes `FINALIZE`; passing finalization enters the new
read-only `CONFIRM` checkpoint before `COMMIT`. Candidate and terminal results,
fingerprints, correction diagnostics, and public activity are distinct. The
version-13 migration preserves terminal runs and consumed commit authorization
on verification-only paths and retains an unfinished `IMPLEMENT` checkpoint.
Evidence at every later active checkpoint that cannot prove the new ordering is
invalidated and routed to safe mode-specific candidate convergence. Retained
legacy terminal-Reviewer correction diagnostics are translated into the new
terminal-confirmation namespace on immutable paths.

Plan execution state version 15 adds bounded semantic finalization recovery.
Terminal roles share rejection routing: after the exact whole-result override
gate, `REJECTED` invalidates finalization immediately. The structured
`finalizationFindingIds` subset separates evidence-only findings from content
repairs. Pure rejection preserves candidate approval and re-enters `FINALIZE`
without code-fix accounting; mixed rejection resolves content first and still
requires replacement finalization. The complete deterministic gate preserves
established check IDs/commands and infrastructure entries, and fresh confirmation
binds the resulting fingerprint. Ordinary non-rejection reuse is unchanged.
Evidence rejection remains valid when inventories are unchanged; equality of
the inventory cannot substitute for sufficient check evidence.

The version-14 migration initializes metadata without interpreting missing
provider output or replaying workflow/effect history. Two semantic retries per
step are reserved durably before invocation. Pending attempts survive
interruption and unavailable providers without recounting; fingerprint drift
clears feedback without restoring allowance. Exhaustion exposes
`finalization_evidence_rejected` at `FINALIZE` with one explicit additional
attempt per null retry. Independent overrides use the saved terminal content
fingerprint; closing recovery feedback still requires replacement finalization
and fresh confirmation. Only bounded validated findings and control metadata
are retained. Each pipeline owns its recovery policy independently; polishing
adopts the same contract with a per-run allowance in state version 11.
