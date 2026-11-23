# Execution Clarification And Bootstrap

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## 12. Clarification And Bootstrap

### Clarification

No implementation or bootstrap work may begin before `CLARIFY` closes. After
the ignore check, the runner ensures the execution clarification artifact exists
without overwriting a resumed transcript. The Worker then studies the task,
validated plan, optional plan-authoring
clarifications, existing execution transcript, repository instructions,
relevant architecture, tests, and Git history in read-only mode.

It returns structured `READY` or all currently actionable questions whose
answers could materially change required behavior, scope, or implementation of
the validated plan. It must use available evidence instead of asking about
ordinary technical choices.

```json
{
  "status": "READY",
  "questions": []
}
```

or:

```json
{
  "status": "QUESTIONS",
  "questions": [
    {
      "question": "Which externally visible behavior is required?",
      "whyItMatters": "The answer changes implementation of the validated step."
    }
  ]
}
```

or, when the clarification input conflicts with the validated plan:

```json
{
  "status": "PLAN_REVISION_REQUIRED",
  "reason": "Existing clarifications conflict with the validated plan.",
  "evidence": ["The requested behavior is outside the validated commit scope."]
}
```

An empty clarification artifact and closing the proactive editor without
changes are valid and do not consume an agent question round. The Worker still
runs and may return `READY`; only unanswered questions appended by the Worker
require user input.

State version 43 adds closed nullable `pendingClarificationAppend` for question
rounds and supported product decisions outside `writableResult.productDecision`.
The version-42 migration accepts only legacy absence and initializes `null`;
it infers no append authority and preserves completed provenance, prepared or
consumed commits, frozen plans, validation inventories and stop-recovery markers.

The clarification service's `persistAppend` callback journals exact normalized
questions or decision data, number, prior/result hashes and settlement checkpoint
before replacing transcript bytes. The checkpoint binds the complete producing
state, counters, input hashes and session lineage, and retains the inspected
validation-infrastructure fingerprint, suspended state, lineage-preservation choice and any accepted arbitration work report.
Append intent and editor authorization are separate and cannot compete with a
writable-result settlement or commit effect.

Before replay, verify the checkpoint, protected non-transcript inputs and
workspace/control ownership, frozen guidance and inspected validation
infrastructure, including custom accepted-output bindings where applicable. Only the prior hash or exact journaled result may precede ordinary
transcript-drift rejection. Replay supplies `resultHash`; it never adopts a
guessed hash, reruns the producing role or renews a budget. After verified
readback and repeated input/workspace guards, one atomic publication retires
intent, publishes the new hash and once-only round/decision count, applies the
established product-decision invalidations and retained reports, and creates the
pending editor authorization and structured input request. Only then may the
editor open. Material answers retain compatibility/replanning re-entry;
unchanged answers renew only the existing editor window.

Terminal `CONFIRM` product decisions suspend to `IMPLEMENT` through this same
append owner while retaining `finalizationResult` until publication. Before
intent creation or replay, and again before editor authorization, measure the
deduplicated union of established validation infrastructure and any inventory in
retained finalization evidence. This includes ignored finalized-only files that
ordinary content snapshots omit. Use the existing
`validationInfrastructureFingerprint` owner, preserving selected-file composition
and ordinary/legacy fingerprint domains; the finalization evidence tuple remains
separate. Missing or changed infrastructure rejects replay against the original
intent with `unsafe_git_state` / `ERR_REVIEW_VALIDATION_INFRASTRUCTURE_CHANGED`,
retaining its hashes, checkpoint, accounting and unsettled work. Never rebind an
old intent to current bytes. The existing strict state shape needs no migration;
an older intent whose fingerprint omits retained infrastructure fails closed.

Replacement, readback or publication interruption retains the original intent
and checkpoint. Bounded read/write failures pause as
`clarification_append_interrupted`, with only an allowlisted code and null-action
resume; unknown publication failures propagate without overwriting possible
journal progress. Unauthorized transcript bytes or changed protected inputs and
controls remain non-resumable and retain rejected proof. Operator-stop
reconciliation verifies prior-or-result bytes and controls only: it retains
intent without appending, preparing/opening an editor or accepting an answer.
Existing consumed-commit and writable-result reconciliation keep their owners.

A service-readback hash different from the durable intent's `resultHash`
persists `clarifications_changed` before publication or editor preparation.
Retain the complete intent, prior hashes, checkpoint, accounting and unsettled
work. Reconstruction and verification-only stop settlement preserve this
rejection even when later transcript bytes match the prior or result hash;
neither match restores replay authority.

Append each question round to the execution clarification artifact, open the
editor for answers, then let the Worker reread the complete transcript. The
fixed clarification protocol permits at most three agent question rounds; it
is not a configurable workflow budget. If the editor cannot be opened, the run
is non-interactive, answers remain missing, or the round limit is reached,
persist `WAITING_FOR_USER` instead of advancing.

Before opening the editor or entering `WAITING_FOR_USER`, persist the suspended
state, pending editor action, and last accepted artifact hash. An edit made
through that authorized editor window is accepted as new clarification input
and invalidates dependent work; any edit outside an authorized window pauses
with `clarifications_changed`.

The root runtime applies immutable runtime admission to CLI/MCP lifetimes and
new-run/resume effects.
Associated live users defer activation, while unknown owned identity blocks it;
admission cannot migrate, resume or expand authority for a legacy run. The root
runtime contract owns this boundary and retains all existing pipeline gates.

Through MCP, the root runtime never opens an editor. It projects the same
pending authorization with identified questions and accepts an empty response
for optional proactive clarification or one exact answer per Worker question
through `run_respond`. A product decision requires explicit user context; the
controlling agent asks the user when that context is absent. An external edit
followed by `run_resume` remains an equivalent path. Detached continuation does
not change this pipeline's lease, compatibility, Git, or commit gates. An MCP
dispatch that encounters another run's canonical-worktree lease leaves its
durable run and incomplete idempotency intent available for exact retry instead
of launching a conflicting child. After a mutating child is spawned, MCP does
not complete the intent until the run advances or that child owns the worktree;
a child that loses a concurrent acquisition race leaves the intent retryable.
The launcher's correlated exit acknowledgement preserves that result when the
winning lease is released between MCP polls. At MCP startup, the dispatcher
freezes one canonical detached-compatibility token over the root run-envelope
tuple and every loaded pipeline descriptor's ID and state version, sorted by
ID. The child loads its registry and independently recomputes that token before
run-lease acquisition, recovery, or migration. A mismatch takes the distinct
version-skew exit path and leaves the durable run, journal, leases, and
incomplete intent exactly unchanged for an exact-key retry after the MCP
process is restarted.
Detached stop reconciliation is checkpoint-correlated rather than
lease-correlated. Once MCP launches that child, it follows the exact stop until
durable settlement or correlated child exit and never treats transient run-lease
ownership as completion. Exit before settlement leaves the request applicable
and reports a retryable detached-start or runtime-version-skew result. A later
action-free `run_resume` uses the exact inspected revision and a new durable
idempotency intent; it does not require the original stop key. The delayed child
also carries the private stop-checkpoint revision, so settlement makes it a
no-op instead of allowing a pause to resume or cancellation to revive.
The additive MCP start fields leave `sourceSession` unset by default and pass it
only after the user deliberately selects a fork; native IDs remain opaque and
an unknown source profile offers only `current` inheritance.
`run_start.mode` has the same precedence as CLI `--mode`. MCP guidance must
recommend `independent` for genuine semantic independence, disclose its higher
context/token use, describe `lazy` as an opt-in lower-consumption choice without
independent review, and prohibit automatic lazy selection. Registry, status,
wait, and activity projections expose descriptor metadata or the resolved mode
without inactive roles or provider-private values.

When the Worker returns `READY`, persist and freeze the artifact hash. `READY`
is valid only when the clarification input is compatible with the validated
plan. Both the execution transcript and optional plan-authoring clarifications
become inputs to every later role. After this transition, normal prompts
prohibit questions.

`PLAN_REVISION_REQUIRED` enters `WAITING_FOR_USER` with
`plan_revision_required` before bootstrap. The current run remains paused until
a revised plan is validated and a new execution run starts with the transcript
carried forward; never reinterpret the stale plan.

An agent may instead return structured `PRODUCT_DECISION_REQUIRED` only when
all of these are true:

- the answer changes observable behavior, a business rule, data, security, or material scope;
- multiple incompatible choices are reasonable;
- the task, validated plan, repository, conventions, and prior clarifications do not resolve the choice;
- continuing would invent a requirement or create substantial rework risk.

```json
{
  "status": "PRODUCT_DECISION_REQUIRED",
  "question": "Which behavior should the product expose?",
  "options": ["Option A", "Option B"],
  "whyBlocked": "Both behaviors are valid but incompatible.",
  "evidence": ["The task and plan do not select either behavior."]
}
```

That outcome enters `WAITING_FOR_USER` and appends the question, options, and
evidence to the execution transcript. The user edits the transcript in the
authorized editor window. The runner persists the updated artifact hash, and
the edit invalidates all dependent context, finalization, and review. Before
re-entry, a read-only Worker compatibility check returns `READY` or
`PLAN_REVISION_REQUIRED` without asking questions. Resume at `BOOTSTRAP` if the
question arose there; otherwise resume the current step at `IMPLEMENT`, but only
when the answer leaves completed commits and the validated plan intact. If it
affects completed work, plan scope, or commit boundaries, pause with
`plan_revision_required`; do not reinterpret the plan or rewrite completed
commits. The current run remains paused: create a revised validated plan and
start a new execution run, carrying forward the recorded decision as task
context.

### Bootstrap

No implementation changes may occur before bootstrap completes.

In independent and combined modes, run Worker bootstrap and Reviewer bootstrap independently
and in read-only mode. Clarification and bootstrap use distinct role
checkpoints. Reconciliation may continue the Worker bootstrap session, but
implementation and review never do. In lazy mode, run only Worker bootstrap,
accept its complete summary and validation inventory as resolved context after
the same deterministic validation, capacity, correction,
staging-independence, trusted-check, canonical-path, and infrastructure-
fingerprint rules, and never invoke Reviewer reconciliation or Arbiter.

Every active bootstrap role studies:

- repository structure;
- relevant source code and architecture;
- `task.md`;
- the complete `plan.md`;
- plan-authoring and execution clarifications;
- optional `context.md`;
- repository agent instructions;
- relevant repository skills;
- the frozen finalization path or fallback decision, and repository
  instructions and project checks for fallback validation;
- relevant tests;
- relevant Git history where useful;
- project conventions related to the task.

In independent mode, the roles must not receive each other's interpretation
until both analyses finish.

Persist concise summaries:

```text
context/worker.md
context/reviewer.md  # independent and combined modes only
```

Each summary should cover:

- task understanding;
- relevant architecture/files;
- important invariants;
- interpretation of planned commits;
- risks/ambiguities;
- finalization procedure.

Each active bootstrap role establishes an independently discovered ordered inventory
through discovery and accepted applicability batches. The final role inventory has stable `C`-prefixed IDs, exact commands, and `steps`: a nonempty ascending
array of unique canonical plan step numbers. Missing applicability, invalid
references, and missing step coverage are rejected. Every role discovers a
complete procedure for every step, including the repository's ordinary fast
gate and only slow checks whose documented guarantees that exact step affects.
It also reports every canonical repository-relative validation-infrastructure
file and the exact declared label of selected external finalization guidance.
Independent and combined modes preserve accepted Worker evidence followed
by Reviewer evidence; lazy mode uses Worker evidence alone. The runner unions
applicability for identical commands, preserves first-seen command order, and
assigns contiguous `C1`-through-`Cn` IDs within each step. Reconciliation and
arbitration cannot discard or reassign requirements. Infrastructure paths are
deduplicated globally and fingerprinted by the runner.

Discovery, correction and validation migration catalogue only checks owned by
this pipeline's finalization, including selected Runner-trusted commands.
Acceptance explicitly assigned to the supervising operator or another owner
after the run completes stays pending external work in the summaries,
with its owner and timing; applicability catalog correction never adds it. This
semantic rule follows the
[validation ownership guarantee](../../../docs/product/VALIDATION_AND_REVIEW.md#bootstrap-inventory);
the runner does not parse task prose for ownership or remove a misclassified
accepted command.

`validationSchedule` persists one ordered `commands` catalog and a `steps` array
of `{step, commandIndexes}` entries. Indexes are zero-based references into that
catalog, so command text is retained once rather than repeated for every step.
The schedule must equal the deterministic derivation from accepted role
assignments. `requiredChecks` expands the selected step's inventory with its
contiguous local check IDs. A confirmed
`validationAmendment` records only that step, its amended inventory, and the
confirming evidence fingerprint. It does not rewrite original role assignments
or another step's schedule. Verified advancement clears the amendment and prior
gates before selecting the next persisted inventory.

A justified amendment may add an exact operator-selected command originally
assigned to another step. Selection reserves that command from agent execution;
it does not make every selected command applicable. The resulting candidate
inventory, rather than the original applicability alone, selects which frozen
commands the runner executes. The amendment still requires the existing distinct,
fingerprint-bound terminal confirmation before becoming active authority.

Each bootstrap role discovers all known applicable checks, including available
supplemental validators. In finalization, the Worker preserves project-defined
first, final and relative-order constraints in the declared inventory and ordered
evidence; amendments position additions accordingly rather than automatically appending
them, retaining every established identity and exact command. Current-inventory
reordering never changes original discovery or future assignments. Array order
proves no physical execution sequence: Worker runs agent-owned checks during
`FINALIZE` and returns reserved `NOT_RUN` entries; Runner subsequently executes
their frozen vectors and replaces those entries in inventory positions under
existing unchanged-content and infrastructure guards. No later Worker turn is
required; `COMMIT` retains its separate fixed staged hygiene. The only exception
is Runner's serial loop, identical for commit and custom execution: it awaits
one selected entry at a time in inventory order, each attempt retires before the
next starts under unchanged bindings, and no stop persists partial finalization
evidence. Within one persisted record, entries whose Runner-owned `executor` is
`runner` therefore establish their relative physical order after that
`FINALIZE` turn's agent-owned work; agent-owned and legacy entries establish no
Runner order. A separately explicit physical sequencing requirement remains
binding and uses existing blocking outcomes if incompatible with
ownership/checkpoints, without new permissions or an invented product decision.
Terminal roles never reject evidence for order this guarantee establishes or
for missing telemetry. Insufficient proof that a mandatory sequence was met is
never approved: evidence-only rejection uses the bounded recovery and
[exhaustion pause](finalization.md#candidate-convergence-and-phase-ownership), while
proven uncorrectable violation keeps the
[policy stop](validation-history.md#historical-validation-noncompliance). Independent terminal
Reviewer confirmation and lazy terminal clean confirmation read the
actual selected guidance and mandatory references and assess the complete
resulting procedure, including additions and their positions, even when all
checks pass. The owning prompt instructions reach fresh, continued,
reconstructed, corrective and evidence-recovery requests. This semantic
obligation changes neither bootstrap union nor future assignments, schemas,
bindings or budgets. It cannot guarantee model compliance or automatically
repair historical runs; existing evidence-only recovery can correct ordering
without content changes.

State version 27 replaces the expanded schedule representation. Its leased
version-26 migration verifies the old schedule against accepted role assignments
before converting it, preserving all other evidence, amendments, correction
accounting, and prepared or consumed effects. A null legacy schedule stays null.

Each summary and inventory covers every substantive validation requirement but
must not require staging, staged handoff, index mutation or inspection, an
implicit worktree-versus-index assertion, an alternate index, or commit-message
drafting. Generic commit preparation belongs only to `COMMIT`; an applicable
content check uses `HEAD` or explicit trees. Deterministic validation collects
every unsafe command and every inspectable invalid validation-infrastructure
path from one candidate into a bounded, deduplicated field-diagnostic batch,
consumes the producing role's one bounded read-only correction, and fails
closed if the replacement remains invalid. Validation-migration discovery uses
the same policy, and finalization candidate inventories are rejected by their
owning batched correction policy as well.
Validation infrastructure consists of files owning commands, discovery, runners,
configuration, or mandatory finalization guidance. Exclude ordinary source,
individual tests, fixtures, and generated output merely consumed by checks.
Classification is semantic, not a filename or extension heuristic.
The runner deterministically includes a frozen selected finalization skill in
the established infrastructure before fingerprinting it, even when a role
omits that already resolved mandatory path. If that addition would exceed the
aggregate bound, the producing role receives its bounded correction instead of
creating an oversized persisted inventory.
Each role may return at most 256 `requiredChecks` and 256
`validationInfrastructure` entries. The independently derived, persisted,
finalization, and fingerprint-input inventories each allow at most 512 entries,
so two disjoint maximum role inventories remain representable. Current-step
amendments must also keep the complete retained command catalog within 512;
overflow receives the existing bounded finalization correction. If a complete
role field would exceed 256 items, the role must return the strict
`CAPACITY_EXHAUSTED` result with empty inventory and ordinary result fields,
`capacityField` equal to `requiredChecks` or `validationInfrastructure`, and
`capacityLimit: 256`. It checks `requiredChecks` first when both fields are over
capacity. The runner pauses immediately with
`bootstrap_inventory_capacity_exhausted` and the bounded public code
`ERR_BOOTSTRAP_INVENTORY_CAPACITY_EXHAUSTED`; it does not consume a correction
turn, accept truncation, or persist a placeholder.
Exact commands and paths retain interior whitespace; validation rejects unsafe,
non-normalized, multiline, or boundary-whitespace values rather than rewriting
them.
Every inventory-producing bootstrap prompt, including validation-migration
discovery, requires unique check IDs, unique exact single-line commands already
normalized without boundary whitespace, and unique existing canonical
repository-relative validation files, with the sole exception of the exact
declared label of selected external finalization guidance. A symlink or path
through a symlink is an invalid alias even when its target is confined to the
repository.
Provider-facing structured-output schemas are portable approximations limited
to the common backend Structured Outputs subset and do not use regex
lookaround. They retain strict objects, bounds, safe lexical patterns, and
status-specific variants. Deterministic pipeline normalization remains
authoritative for exact nonempty text, commands, uniqueness, and safe
repository-relative paths. Each bootstrap schema keeps a strict object root
and places its outcome variants in a nested `result` union. A rejected
bootstrap result persists and publishes only its bounded, deduplicated role,
phase, contract, field, and violated-constraint diagnostic batch; it never
retains a rejected value, command, path, or raw role output.

The producing Worker or Reviewer and each summary-producing reconciliation
Worker or Arbiter receives one read-only correction turn for an invalid
bootstrap contract. The runner first persists attempt `1` and the bounded
diagnostic batch, then reconstructs the complete request from durable state and
asks for a complete replacement result. A
provider interruption does not consume another correction or require the
native session. Each adapter maps its native structured-output failure to the
shared bounded `structured-output` failure class. The pipeline maps only that
class to the bounded `result` semantic diagnostic after the read-only mutation
guard completes; provider text is discarded. A valid replacement retires the
pending batch before any product-decision pause, while its history remains
consumed. Repeated or still-invalid output fails closed.

Before any inventory is accepted or fingerprinted, the runner asks the root
Git or directory boundary to inspect each repository validation path, and the
configuration capability to inspect a new selected finalization file. Each path
must exist as a regular file and the returned canonical repository-relative path
must exactly equal the proposed value; external guidance uses its frozen
namespaced inventory label instead. Every inspectable missing file,
directory, symlink, and symlink-traversing path returns to the producing role in
the same bounded `existing-canonical-repository-file` diagnostic batch; these
violations do not surface later as generic unsafe-path failures and are never
followed or silently rewritten.

In independent mode, the Reviewer summary additionally states what it intends
to verify. Lazy mode creates no Reviewer summary.

### Durable bounded bootstrap

`bootstrap-unit-schemas.js` and `bootstrap-units.js` define completed
repository-discovery and applicability reports and pure work-record transitions.
Both initial `BOOTSTRAP` and validation-migration discovery use them. Each
mode-required role normally performs broad read-only repository discovery once,
including a distinct semantic plan-context review, then supplies focused
applicability batches. Worker and Reviewer discovery remain independent in
independent and combined modes; lazy uses only Worker. No writable effect may
begin until every required role has complete canonical coverage, the stable
Worker-first union is established, and capability preparation succeeds.

Shared inventory fragments live in `validation-schema-fragments.js`, keeping
`schemas.js` exports limited to complete object-root response schemas.

Discovery contains the producing role's repository summary, selected-step
assessment, ordered command catalog without `steps`, canonical infrastructure
paths, capability requirements, and environment blockers. Its validators reuse
the existing exact-command, staging-independence, path, capability, structured
result size, and inventory bounds. Root-owned inspection of existing canonical
regular files and semantic plan-position review remain separate obligations;
pure validation cannot establish either from an agent assertion.

A work record binds contract version 1, role, frozen-input and canonical-plan
fingerprints, repository and infrastructure fingerprints, frozen trusted-command
authority, selected position, and accepted discovery. Applicability requests
contain this binding, the discovery catalog and its fingerprint, a deterministic
unit ID, and a contiguous canonical plan range. The workflow persists fixed
limits of four canonical steps and 262,144 supplied JSON bytes per unit,
partitioning the plan in order. Oversized
ranges bisect deterministically through single-step units; an oversized
single-step request raises `ERR_BOOTSTRAP_UNIT_CAPACITY_EXHAUSTED`. The byte
measurement covers exactly the supplied request JSON, excluding referenced-file
reads and provider framing; it implies no native output-token limit.

Each accepted batch identifies its exact unit and supplies unique catalog-order
check IDs with ascending steps inside that range. Every step needs coverage.
Reload rejects gaps, overlaps, noncanonical subdivisions, reordered, duplicate,
foreign, stale, or cross-role evidence. Assembly requires complete ordered
coverage, every discovered command assigned, and the original aggregate bounds;
only then does the existing bootstrap normalizer produce a ready role inventory.
Final-batch acceptance also validates that assembled inventory. A failed final
batch remains unaccepted so it can use the remaining shared role correction
allowance without discarding earlier accepted batches.
Accepted assignments, applicability unions, capability reports, and blockers
remain available to the existing schedule and inspection contracts.

A batch may instead request catalog correction with no accepted assignments,
reporting missing commands, infrastructure paths, capability requirements, or
environment blockers. Before a correction invocation, the caller must persist
`consumeBootstrapCorrection` and charge the existing producing-role bootstrap
ledger. Catalog and invalid-unit repairs share its single attempt. Corrected
discovery must retain accepted commands and reports and include every new
requirement; it invalidates all dependent units and coverage. Reload takes the
saved role attempt as a lower bound. Rebinding a corrected catalog to newly
fingerprinted infrastructure, subdivision, rediscovery, reconstruction, and
resume must retain the consumed attempt. Pending correction authorization permits reconstruction of that same
attempt, never a new allowance. Subdivision replaces only an unaccepted leaf,
so each catalog admits at most plan-step-count minus one splits. The workflow
additionally retains at most 16 output-triggered subdivisions per role for the
entire run, separately from semantic correction accounting. Accepted discovery
and each accepted unit are journaled before advancement. Output exhaustion can
split only the unfinished read-only applicability unit; the split and consumed
allowance persist atomically with the exhaustion record before continuation.
Discovery exhaustion, an exhausted single-step unit, or exhaustion after that
allowance is consumed pauses without accepting partial output. A supplied
single-step request exceeding the byte limit pauses for capacity instead.

Pipeline state version 28 adds strict `bootstrapProgress` records for Worker and
Reviewer, each containing nullable bound work and a consumed subdivision count.
After a role inventory is published, its temporary work is retired but consumed
allowances remain. A compatible native session receives focused instructions;
reconstruction receives frozen input-file references and hashes, its accepted
catalog and exact current unit, without routinely repeating broad discovery or
the entire applicability matrix. Native session survival is never required.
Reload validates partitions, ordered accepted units, role bindings, the exact
selected plan position, and the shared correction ledger. Live reuse also checks
input, repository, infrastructure, and trusted-command fingerprints. Unexpected
drift invalidates affected proof under the existing input and Git guards;
rediscovery and catalog correction never replenish either allowance.
Migration bootstrap turns persist the read-only `validation-migration` identity
instead of inheriting their suspended workflow phase. Interrupted recovery and
operator stops therefore retain read-only reconciliation even when the workflow
is suspended at `IMPLEMENT` or `FINALIZE`. Exhaustion pauses retain that migration
checkpoint and the suspended workflow's resume state. Repository drift pauses
and clears stale bootstrap work atomically while preserving consumed allowances.
Saved version-27 availability and inactivity retries retain their exact legacy
checkpoint only for the same role and suspended phase's read-only migration.
Retry accounting remains consumed while new turns use `validation-migration`;
successful provider reconciliation retires the saved recovery record normally.
Journal-proven confirmation recovery accepts this identity only behind the
pending migration barrier with unchanged workflow, input, and repository
bindings and no pending consumed commit effect. Later candidate acceptance and
passing finalization still require their complete journal provenance.

The ordered version-27 migration initializes empty work and zero subdivision
counts because older states contain no such proof or consumed output allowance.
Compatible complete legacy role inventories, schedules, current-step amendments,
completed commits, corrections, and historical confirmation evidence remain
unchanged. Unfinished roles perform discovery without fabricated batch evidence;
older incompatible inventories retain their existing migration barrier. A
consumed commit settles by verification before discovery or another writable
effect. No contract truncates an oversized inventory or treats partial coverage
as ready.

### Reconciliation

The remaining reconciliation requirements apply only in independent mode. After
both summaries exist, compare material differences. Lazy mode skips
reconciliation because the accepted Worker summary is already the resolved
summary and the same logical agent cannot form an independent disagreement with
itself.

Resolve differences from task/plan/repository evidence.

Reconciliation and any arbitration resolve only the summary and a remaining
material disagreement. The runner independently derives the established
validation inventory from the two already accepted role inventories regardless
of which summary direction is selected. The resolved summary keeps explicitly
assigned post-completion acceptance as pending external work with its owner and
timing.

Persist the agreed context:

```text
context/resolved.md
```

Do not force agreement.

If a material disagreement remains, use the Arbiter.

If arbitration determines that progress requires an unresolved material product
decision meeting the clarification criteria:

```text
WAITING_FOR_USER
reason: product_decision_required
```

---
