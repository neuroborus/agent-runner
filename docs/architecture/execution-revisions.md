# Execution Revision Integration

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Step Selection and Context

Plan execution owns bounded step assessments and semantic context validation in
its private `plan-position.js` contract. Every context-producing phase receives
the runner-selected subject and verified completion evidence. A separate
read-only review checks narrative directions before acceptance; matching fields
cannot override contradictory prose. Its `plan-context` interruption marker
requires read-only reconciliation before replaying the producing checkpoint.
Version-19 migration invalidates legacy context before writable work while
preserving verification-only settlement of consumed commits. Root Git remains
the observation authority; agents and summaries never select the next step.

## Initial Implementation Evidence

Plan execution also owns durable initial-implementation evidence. Its
`implementation-evidence.js` contract separates the original step/HEAD/content
baseline from mutable repository snapshots and reconstructs legacy evidence only
from the state-owned validated journal. State version 20 persists that evidence
before writable implementation and rejects unchanged initial results before
candidate convergence. Corrections retain their existing unchanged-result semantics;
verified commit settlement alone resets the record for the next step. Consumed
effects and stop recovery remain ahead of preparation for new writable work.

## Commit-size Assessment

Execution's private `commit-size-assessment.js` owns safe threshold arithmetic,
fingerprint-bound atomic/split decisions and a three-attempt original-step
lineage ledger. Read-only assessment uses the continuing Worker in lazy mode
and a distinct configured Reviewer checkpoint in independent/combined modes,
before further convergence. Only scope/dependency expansion or more than one
additional preferred target renews assessment of an atomic exception. The
replacement coordinator publishes new reservations before invocation. A matching
durable null-result reservation continues its existing read-only role/checkpoint
without an unchanged transition or another attempt. Missing durable output
requires reinvocation; the matching normalized decision is persisted before
atomic continuation or split-proposal publication. A saved decision survives
interruption before proposal publication without another assessment. Proposal
and assessment allowances survive reconstruction and future replacement steps;
they grant no execution approval or effect authority. State version 29 persists
the resolved size settings and disabled eligibility, with a default-only
version-28 migration preserving existing progress. Version 32 activates dispatch
only for new commit-plan runs; migrations keep historical eligibility disabled.
State version 39 freezes `automaticCommitSplitting` in settings: new commit runs
are eligible only when it is `true`, disabled runs skip measurement and
assessment before any model call, and the version-38 migration derives the
switch from saved eligibility. See the
[owning contract](../../pipelines/plan-execution/docs/SPEC.md#commit-size-assessment-foundation).

## Effective Revision Authority

Execution's private `effective-plan.js` owns the reviewed-revision
contract. State version 30 persists proposals, exact flat plans, original-step
correspondence, completed-prefix provenance, complete versioned finding payloads
and ownership, and fingerprint-bound mode gates. The version-29 migration adds
empty authority without changing eligibility or progress. Lazy requires distinct
Worker plan convergence/confirmation; independent requires Reviewer approval; combined
requires both. Accepted authority must be journaled before boundary selection,
invalidates dependent content gates and retains consumed allowances.
Proposal bindings retain historical additional-round grants; reload enforces
cumulative lineage consumption, and any binding change requires fresh reports.
Deferred targets map to logical original work. Pending commits remain
verification-only.
Production routing selects only accepted effective authority while preserving
the unchanged canonical plan. See the
[revision contract](../../pipelines/plan-execution/docs/SPEC.md#reviewed-effective-revision-foundation).

## Revision-bound Validation

Execution's private `revision-validation.js` binds bounded discovery, complete
role inventories and compact schedules to accepted revision authority and exact
replacement positions. The public persisted validator composes this contract
with bootstrap progress. State version 31 retains separate additive revision
receipts without rewriting frozen-plan inventories. Validated splice
correspondence preserves unchanged assignments and future obligations; affected
applicability requires fresh read-only discovery from every active role. Only
complete roles produce the Worker-first schedule. Receipts bind confirmed
amendment commands, mapped applicability and infrastructure, enforcing them on
acceptance and reload independently of the active amendment's lifetime.
Capability preparation remains root-owned, and no receipt supplies check evidence
or materialization authority.
The version-30 migration adds empty receipts without inventing legacy proof,
preserving consumed effects and allowances. Revised implementation evidence
cannot be rebound by ordinal. See the
[validation foundation](../../pipelines/plan-execution/docs/SPEC.md#revision-bound-validation-foundation).

## Derived Progress

Execution's private `plan-progress.js` derives refinement status and Markdown
from frozen plan text, assessment/revision ledgers, separation readiness and
verified completed commits. Its descriptor exposes the artifact projection and
`status.refinementProgress`; CLI and MCP use that same projection. Root Runner's
private `plan-progress.js` confines atomic publication to `plan.progress.md`
beside the frozen plan after state publication, with run ownership, regular-file,
canonical-parent and repository ignore checks. Reads, temporary writes,
replacement, synchronization and cleanup stay anchored to a validated open
directory descriptor. Runner defers publication throughout a consumed commit
until verification and durable settlement, so artifact failure cannot strand an
unattempted effect. Pending operator stops also defer publication until durable
reconciliation. Publication failure after settlement still permits state-checked
lease release, including reconciliation initiated during release.
A per-run publication queue serializes concurrent activity
producers and discards older snapshots after observing a newer state revision.
Publication failure preserves durable authority for leased
resume/regeneration; status remains read-only.
The artifact is never a workflow input. See the
[derived progress contract](../../pipelines/plan-execution/docs/SPEC.md#derived-refinement-progress).

## Replacement Execution

Execution's private `replacement-execution.js` coordinates assessment, reviewed
revision acceptance, complete role rediscovery and preservation through injected
capabilities. Version 32 persists separation IDs, the inspected snapshot,
capture revision and capture/restore/ready phases plus consumed lineage output
corrections. Root `runtimeFor` supplies the held run/worktree leases to the
state-owned preservation service; its capture binding uses the latest serialized
revision, including capability-preparation publications. After verifying every
saved byte, the state service supplies exact manifest/hash and content-addressed
blob references for read-only reconstruction. Complete file bytes stay external;
the cumulative reference context is bounded to 65,536 UTF-8 bytes. Before
restoration, the complete first reconstruction request must also fit the existing
32 MiB adapter limit. The Worker's provider-owned `canReadFiles` admission checks
every exact manifest and before/after blob path against its proved command
policy and host readability. Claude's runner-boundary masks make external
sources under `/tmp` or `/run` unavailable; native Read is not byte-exact binary
recovery. Missing admission support or inaccessible sources pauses as
`environment_blocked` before restoration, retaining the candidate and capture
for a fresh access check on resume without widening the sandbox.
References permit neither storage writes nor unrelated
state access and contain no native transcripts.

The complete unfinished candidate is captured before any removal. Restoration
reuses one journaled operation to restore all saved paths to their accepted
baseline. Its receipt reconciles before generic workspace-drift handling; ready
publication pins the clean baseline and retires completed bootstrap units while
retaining receipts and consumed subdivision/correction totals. It also retires
the former candidate's phase-local pending correction marker before `IMPLEMENT`.
Each replacement
then uses ordinary initial-implementation evidence, mode gates, finalization,
terminal confirmation and one-shot commit settlement. Saved future work remains
external, and earlier child commits are never overwritten by a later restore.
Sibling replacements retain correction budgets and semantic finalization retry
allowances within their original refinement lineage. Private
`replacement-findings.js` preserves finding-specific consumption and decisions
by reviewed version and ownership; sibling-local IDs cannot inherit an unrelated
finding's arbitration, dispute counts or exact override. Active version changes
retain the original version's decisions and pending requests separately, without
relabeling them or renewing lineage budgets. Owned pending disputes, their counts
and reconsideration requests stay in the ledger during reconstruction and return
at candidate convergence. Dispositions retain their final history even when
they remove the last active payload.
Revision discovery
routes capacity, product-decision and plan-revision outcomes through their owning
workflow handlers without discarding structured details or suspended authority.
Private `replacement-inputs.js` journals authorized clarification binding changes,
retains the suspended content checkpoint separately from the `IMPLEMENT`
compatibility route, preserves historical plan approval and role receipts, and requires fresh mode
approval and additive discovery before reuse. Assessment bindings follow only
that authorized chain without replacing history or renewing lineage allowances.
Rediscovery preserves parent amendment correspondence and exact replacement
targets for amendments accepted within the current revision.
Review normalization includes owned sibling payloads when enforcing stable IDs.
Deferred stops resolve the
original logical work and settle only when all its children verify. Consumed
commits reconcile before refinement. Read-only refinement violations persist
the ordinary contamination stop before preservation or new effects.
Input invalidation retains the historical role inventories and revision receipts
needed to validate that stop, while retiring active selection and approvals.
Pending separation records remain recoverable without reactivating invalid inputs.
The version-31 migration adds empty preparation records and keeps legacy and
intermediate runs disabled; it supplies no revision approval or preserved bytes.
Output-exhaustion pauses validate the exact pending refinement checkpoint rather
than treating its read-only phase as the suspended content phase. Reconstruction
retains assessment reservations and correction accounting.
An unchanged repair of a rejected plan preserves its report and offers an
explicit read-only repair retry through the shared CLI/MCP pause projection.
