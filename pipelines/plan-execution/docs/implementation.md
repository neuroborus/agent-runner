# Execution Implementation and Size Assessment

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Initial implementation must change step content

Before registering the first writable implementation turn, the runner persists
`stepImplementation`: the deterministic step number, runner-observed starting
HEAD, staging-independent content fingerprint, and `accepted: false`. This
record is distinct from the mutable repository baseline. Interrupted turns,
partial implementation, stop recovery, environment retries, and baseline updates
retain the original record. It is cleared only by verified COMMIT settlement.

A `COMPLETED` initial implementation is accepted only when the observed content
differs from that original fingerprint. Otherwise execution pauses with
`plan_revision_required` before candidate convergence or finalization, retaining
the current step and unchanged `completedCommits`. An implementation summary
cannot authorize an empty step, including when its content already exists under
a different commit subject. Repair requires a revised plan and new run.

Once initial implementation is accepted, unchanged correction, finding-resolution,
check/fix, review, and confirmation turns remain valid under their existing gates.
The comparison does not depend on staging placement, and it does not authorize
index changes. Only consumed runner-authorized commit verification advances steps.

State version 20 marks legacy evidence as unresolved, except when preflight has
never begun and no implementation could have run. Before new writable work
or an unconsumed commit effect, recovery uses the complete validated journal to
find the original implementation entry and its saved HEAD/content baseline.
A prior acceptance must show a content change; a never-started step may use its
journal-proven clean baseline. Missing, truncated, inconsistent, or already-no-op
history cannot be replaced with the current workspace fingerprint or agent claims:
it pauses for plan revision. Status performs no effects. Consumed commit settlement
and operator stop/cancel reconciliation precede evidence acquisition for new work.

## Worker implementation

Start or continue the current commit's Worker checkpoint.

Before editing, the Worker refreshes:

- current commit section;
- relevant resolved context;
- relevant decisions/findings from previous work;
- current affected code.

The Worker then:

1. implements only the current planned commit;
2. performs a concise self-review;
3. returns control to the runner.

Implementation and finding resolution advertise strict object roots containing
a `result` union of status-specific strict objects, following the bootstrap
schema convention. `COMPLETED` requires a nonempty summary and empty reason,
question, options, whyBlocked and root evidence. `RESOLVED` requires empty
inapplicable root fields and one decision per current blocker. Each `FIX` or
`DISPUTE` decision requires a bounded nonempty reason; `FIX` evidence may be
empty, while `DISPUTE` requires evidence and an R-prefixed finding ID.
`BLOCKED` requires nonempty reason and evidence, with other outcome fields
empty. `PRODUCT_DECISION_REQUIRED` requires question, whyBlocked and evidence,
permits empty options, and leaves ordinary outcome fields empty. Inactive
finding-resolution outcomes require no decisions.

These schemas encode expressible status/disposition constraints without
relaxing deterministic validation. Normalization additionally enforces exact
field sets, text rules, the overall byte limit, current blocker ownership,
exactly-once decisions and dispute restrictions, including already upheld
findings. Every implementation or resolution normalization failure supplies a
bounded diagnostic: Worker role, implementation or finding-resolution phase
and contract, and allowlisted field and constraint identities. Decision and
list positions are bounded by the 32-item limits; rejected values, blocker IDs,
commands, arbitrary messages and raw output never enter diagnostics. Existing
valid historical diagnostics remain readable without migration.

Synthetic nonempty root reason/evidence cases establish schema/normalizer
agreement regressions. The exact rejected fields in the reported real turns
remain unknown; these cases do not establish what those turns returned.

Implementation does not invoke the project finalization procedure, stage
changes, inspect a post-staging cached diff, or draft a commit message. Those
actions belong to the dedicated `FINALIZE` and `COMMIT` phases.
The established required-check inventory is input only to `FINALIZE`; it is not
included as phase-local implementation work.

Implementation, lazy `CHECK_AND_FIX`, and finding-resolution prompts receive
only the exact command text selected in persisted `trustedValidation.commands`.
This bounded projection is present in complete, continued, reconstructed, and
correction requests, including an empty array when no commands are selected.
It neither reloads configuration nor repeats executable vectors, provider
settings, or the complete validation inventory. Bootstrap inventory-reporting
and finalization `NOT_RUN` instructions remain in their owning contexts.

Established required-check execution and attestation belong exclusively to
`FINALIZE`. Selected runner-trusted commands never execute inside an agent
turn. Their agent-sandbox limitations must not cause `BLOCKED` or prevent
applicable content repairs and semantic review; the runner executes the
persisted exact vectors during `FINALIZE`. Explicit owner and timing
assignments bind validation work by its actual purpose, scope and evidence
rather than its label, so these turns neither run nor claim work reserved for
another owner or later checkpoint. Permitted source inspection and focused
development tests stay development evidence even when they overlap a reserved
check, which still runs in full under its owner.

External environment constraints affecting work not delegated to an exact
selected command still produce `BLOCKED` with bounded reason and evidence,
even when another command is selected. The runner preserves safe implementation
content and pauses with `environment_blocked` at `IMPLEMENT`.

The Worker must not create a Git commit during implementation, finalization, or
finding resolution. Commit creation is allowed only in the dedicated,
runner-authorized `COMMIT` turn after the gate passes.

### Commit-size assessment foundation

The descriptor owns `preferredCommitLineLimit = 900` and
`commitSizeAssessmentMultiplier = 3`. Both accept only positive safe integers;
their product must also be a safe integer after root/project resolution. Project
values take precedence per setting. The resolved pair is persisted at creation
and reused on resume without configuration reload. This execution policy is
separate from authoring's anticipated additions-plus-deletions heuristic.

The descriptor also owns the strict boolean `automaticCommitSplitting = true`,
resolved through the same root/project precedence without coercion or a CLI/MCP
run option. Creation persists it in frozen settings; a commit-plan run is
eligible only when it is `true`, and custom runs are always ineligible. A
disabled run never measures size, reserves or invokes an assessment, or
proposes, reviews or separates replacements: it executes the predefined plan
unchanged through every ordinary gate, and large planned commits remain valid.
Both size settings and their safe product are validated even when disabled.
Persisted eligibility must equal the frozen switch for commit runs; contradictory
records are rejected. A legacy run with null settings adopts runtime settings
with the switch limited to its saved eligibility.

The private `commit-size-assessment.js` contract prepares assessment only for
eligible commit-plan work at a reconciled boundary after implementation or
content-changing repairs, before another convergence/review loop. Pending commit
effects exclude assessment until settlement. Text additions plus deletions must
be strictly above the product: 2,700 does not qualify; 2,701 does. Binary and
gitlink counts remain separate. Size alone cannot fail a step or require an
override, including when the bounded assessment allowance is exhausted.

| Mode          | Read-only assessment checkpoint                                               |
| ------------- | ----------------------------------------------------------------------------- |
| `lazy`        | Distinct turn in the continuing logical Worker session                        |
| `independent` | Distinct configured Reviewer checkpoint, independent of Worker                |
| `combined`    | Same independent Reviewer checkpoint, without waiting for primary convergence |

Existing session selection and reconstruction rules apply; assessment introduces
no role, provider branch, write permission or source-fork exception. Its focused
instructions request a concrete atomic justification or a cohesive ordered
replacement plan. Replacement subjects and contiguous numbering use the shared
commit-plan parser. Structural validity grants no semantic scope approval.
The proposal must preserve requirements, dependencies, findings, checks and later
steps, with independently valid intermediate states rather than arbitrary patch
chunks. Assessment grants no revision, preservation, materialization or commit
authority; acceptance and separation have distinct persisted gates.

The runner-controlled binding records the original-step lineage, frozen plan
and input fingerprints, assessed implementation scope and dependencies, baseline
HEAD, content fingerprint, measured text size, separate binary/gitlink counts,
target and threshold. Results echo its deterministic fingerprint. Scope and
dependency fingerprints describe implementation within frozen requirements;
changed frozen inputs are rejected, never accepted as new requirements.

Each original step and all eventual replacements share at most three reserved
assessments, including split proposals. Publish a newly reserved ledger before
invocation. A durable matching pending reservation continues directly at its
existing read-only role/checkpoint without republishing the unchanged ledger or
consuming another attempt. Provider completion without a persisted decision
supplies no decision evidence: reinvoke that checkpoint, then normalize and
persist its matching result before atomic continuation or split publication.
Recovery after decision publication still reuses the exact saved decision.
Unresolved changed reservations require reconciliation. Later content repairs
alone do not repeat an atomic assessment.
Reassessment requires changed implementation scope/dependencies or growth of
strictly more than one further preferred target over the last assessment. Neither
refinement nor reconstruction resets this lineage allowance or correction budgets.

State version 29 adds `commitSizeAssessment`, initially ineligible with no
lineages. The ordered version-28 migration adds that same disabled record and
default settings without reloading configuration or changing workflow, bootstrap,
findings, correction accounting, approvals or pending effects. Version 32 activates assessment only at creation of new commit-plan runs.
Intermediate and legacy runs cannot acquire eligibility by resuming; changing
these settings does not activate refinement for those runs.

State version 39 adds `automaticCommitSplitting` to non-null settings. The
ordered version-38 migration copies it from saved eligibility, never from
configuration or the new default, and preserves lineages, accepted or pending
revisions, separations, pending effects, inventories, progress, counters and
native sessions. Historically ineligible runs stay disabled; null legacy settings
stay null. No operator action switches an existing run.
