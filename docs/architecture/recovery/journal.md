# Journal replay and recovery

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## History and pipeline recovery proofs

The state service's internal `loadRunHistory` operation returns the run and
complete validated events from one authoritative snapshot. Runtime callers use
`stream: true` to replay that prefix as a repeatable asynchronous iterable;
existing materialized inspection remains available for bounded histories.
Replay shares journal continuity, size, migration-envelope, and
snapshot-consistency checks with ordinary reads and preserves lock-free,
non-repairing status semantics.
Recovery still repairs incomplete tails and lagging snapshots only under the
run lease. Optional expected-revision transitions reject stale evidence before
appending anything.

The runner supplies this private history to a pipeline's optional
asynchronous `prepareRecovery` descriptor operation. Proofs consume events
incrementally and require the final replayed state to match the inspected run.
When operator-stop recovery needs journal history, Runner prepares it against
the certified stop snapshot, which can include a cancellation accepted during
reconciliation activity publication.
Plan execution binds legacy terminal confirmation eligibility to the inspected
run object and revision; no history or recovery authorization is serialized
into public run data. Status may project supported migrations in memory, while
execution first persists the existing migration chain and obtains fresh history
under both execution leases. Plan-execution resume revalidates canonical project and task boundaries
inside the worktree lease, including restart after a durable recovery transition.
Pipeline policy validates actual candidate/finalization transitions and their
intervening fingerprint lineage. A migrated terminal snapshot alone
cannot establish acceptance. The exact legacy opaque failure can then enter
`CONFIRM` through a revision-checked write-ahead transition carrying the
read-only active request. Existing interrupted-turn reconstruction handles a
crash at any persistence boundary without repeating a source fork or earlier
work. Non-actionable `pendingCorrection` accounting is retained with its
counters; concrete pending work and effects remain disqualifying.

The descriptor shares that eligibility with CLI/MCP projections and resume
action validation. MCP's detached launcher admits the proven failed state
without changing stale-revision, ownership, compatibility, or receipt rules.
The owning [execution specification](../../../pipelines/plan-execution/docs/SPEC.md)
defines eligibility and revalidation; the state layer owns all journal I/O.

## Write-ahead publication and certified replay

Each state transition is a small write-ahead transaction:

1. append and sync a complete journal record containing the next state;
2. atomically replace `state.json` using a temporary file and rename;
3. atomically regenerate the derived `progress.md` projection.

Revisions start at `1` and remain contiguous. Recovery ignores and removes only
an incomplete final event fragment, rejects malformed durable records, advances
a lagging `state.json` from the last complete event, and regenerates stale or
missing progress. Valid event history is never discarded.

Each journal segment has the same 64 MiB writer and reader ceiling. The initial
segment remains `events.jsonl`; before an append would exceed its ceiling, the
writer atomically publishes a complete first event in the next contiguous
`events-000001.jsonl` segment (then `000002`, and so on). State replacement and
progress publication follow that event, including at rollover. At most 1,024
segments (64 GiB total headroom) are permitted; exhaustion rejects publication
with `ERR_EVENT_LOG_LIMIT` while retaining the readable accepted history. No
segment is compacted, overwritten during rollover, or discarded. The state cap
leaves enough room for one complete event and metadata within a segment.
Active waits observe segment publication as well as current-state replacement,
including interruption between those two durable boundaries. Replay retains
one bounded segment source, adjacent states, and the current stop's compact
checkpoint/acceptance proof, rather than all historical snapshots. Public
activity and recovery proofs use the same validated prefix; derived progress
is atomically streamed to disk. Replay memory therefore does not grow with the
number of segments, and no authoritative record is removed to save memory.

Each store instance may retain at most eight validated journal checkpoints with
a combined 16 MiB serialized footprint (counting shared references conservatively).
A checkpoint contains only the last two adjacent events, the current stop's
continuity proof, segment bindings, snapshot metadata, and bounded public
projection records. Each stable validated scan produces an operation-local prefix
certificate independently of optional checkpoint admission. It binds the run,
first and last revisions, directory identity, ordered contiguous segment names,
and each segment's revision endpoints, file identity, and exact `[0, length)`
byte range and digest. Before reuse, safely opened files stream fresh SHA-256
digests over every certified byte prefix and compare them to the original bindings.
The scan re-lists the recognized journal namespace before certifying its result.
Directory device/inode, mode, and ownership must remain stable; unrelated
choosing/ready claims and derived/control publications may change directory
timestamps or size without changing journal history. Certification requires
stable full before/after file handle and path observations, including link count
and change time, while reading the byte prefix bound to semantic validation. Timestamps alone
grant no reuse. A full scan retains bounded operation-local capture bindings
for the exact complete bytes read even when append or rotation prevents these
stable closing observations. Capture is not certification: canonical validation
must prove the original digests, file and directory identities, ordered segment
prefix and captured endpoint event while validating the complete observed history.
A later self-consistent history or equal state endpoint cannot substitute for
that proof. Changed bytes, replacement or unavailable proof invalidate reuse
conservatively without extra retry allowances.
Only appended records then need normalization and continuity validation. Every
read still rereads and validates `state.json` and proves its exact event match;
snapshots older than the retained adjacent pair require complete replay.
Cold reads, cache overflow, and eviction retain complete validation; missing
optional cache evidence is not a corruption diagnosis. Partial
tails are never cached, and failed publication discards retained checkpoints,
including any populated by publication callbacks. No checkpoint is authoritative
or persisted. Certificates retain no historical state sequence. Full history
and recovery-proof APIs continue canonical replay.

Cold validation and validated suffixes collect public activities with their
revision, timestamp, redacted dispatch message, event-specific public stop
summary, and the event's own capability diagnostic and check associations.
Each checkpoint retains at
most 1,024 activities and 1 MiB of serialized activity data, also counted
within the combined checkpoint cap. Overflow evicts the oldest activities and
retains their last revision as a coverage boundary. Authoritative events stay
in the journal. Activity pagination uses the retained range only when it covers
the requested cursor. Older requests stream one byte-certified record at a time
and normalize only the activity, legacy stop, and capability diagnostic for
public projection. They do not revalidate unchanged historical states. A page
drains and verifies the entire original prefix even after reaching its limit;
no partial page escapes a failed digest, identity, or namespace observation.
Cursors still advance across revisions without activity and stop at the last
returned activity when a page is full. Stream observations cannot distinguish
an owner's append or rotation from an edit, so they stay unchanged. When a
lock-free page's drain fails with `ERR_INVALID_EVENT_LOG`, the journal's
`extendSnapshot` reloads through the original certificate as publication proof:
every original binding's digest, identity, link count and stable observation,
the recognized namespace, and continuity of the appended records. If append races
this reload itself, observation alone may retain the complete consumed-byte
capture under unchanged file identities and controls with a growing active
segment. It must then drain a separate stable exact-prefix verification of all
those bytes, binding the semantic validation to that same endpoint. This final
verification requires the exact captured segment namespace; unvalidated rollover,
including a newly sealed partial tail, cannot certify the raced scan. Changed
bytes or unavailable or unstable final proof still fail strictly. No raced
capture becomes a reusable checkpoint, and the finite continuation limit remains
unchanged. Only a certified snapshot with a strictly later revision, passing the
same custody and state-root checks, permits another drain under the same cursor
and limit rules.
If fully published custody appears after extension capture, authorization may
extend that same snapshot once more before reapplying its checks. This reload
must prove all preceding bindings and validated history through its own endpoint;
an unconstrained cold load cannot replace the original operation's proof.
Concurrent settlement uses the same bound. If the reloaded snapshot still lacks
preparation authority while custody is observed, authorization fails without
another reload.
A page permits two such continuations (three drains). Each extension uses the
preceding operation-local certificate, preserving the original run identity and
every original byte binding transitively; optional checkpoint replacement or
eviction grants no new proof. If the third drain fails, the same extension proof
and authorization are still required before returning the typed
`RunObservationBusyError` (`ERR_RUN_OBSERVATION_BUSY`, `retryable: true`). No
partial page or cursor escapes, and only a new explicit observation starts a
new bound. Proof is unavailable only for `CheckpointInvalid`, which includes
a certificate-bound segment that can no longer be opened safely; then the
original error is rethrown. Every other extension failure, such as runtime
version skew, invalid or unsafe state, a filesystem or programming error, and
any authorization failure propagates. Changed bytes, rollback, substitution or
unavailable proof never receive the retryable classification. The extension
writes nothing, takes no lease and populates no checkpoint.

When the first drain instead lacks certification because its full scan raced
with publication, extension uses that scan's original capture bindings and
endpoint. It repeats complete semantic validation rather than treating the
capture as a reusable checkpoint. Only a certified strictly later revision
enters the same continuation loop; certification adds no retry allowance.
Append during cold capture, canonical recertification and extension can therefore
continue through the same bound. The final stable byte proof may certify a
consumed endpoint preceding the latest publication; its activities and cursor
remain bound to that endpoint, with later activity available to a subsequent read.
Canonical certification at an unchanged endpoint also requires the original
capture proof. A returned page always pairs its activities and cursor with the
same snapshot; certification never silently replaces it with newer activities.

Progress publication uses retained records when they cover the complete run;
overflow uses the same certified record stream with identical text. An
operation-local certificate survives cache eviction or oversized checkpoint
rejection. Missing certification requires one bounded canonical scan through
the original capture to certify the same snapshot before projection streaming;
missing capture evidence rejects publication. Publication and recovery cannot
adopt a later endpoint through observation continuation.
Certificates cover only complete consumed records, so partial tails stay
uncached while their complete prefix can still serve a verified projection.
Publication certifies the appended event before callbacks, then checks its
original prefix after every callback, including failures. Snapshot rollback or
callback-populated checkpoints cannot substitute different history. Canonical
matching of a lagging snapshot retains the original prefix's byte proof through
the same scan. Progress replacement occurs only after the complete stream's
proof; publication failure rechecks the original certificate without masking an
existing safety error.
Post-publication snapshot verification remains bound to that certificate and
never passes null evidence as a reusable checkpoint. Recovery repairs partial
tails and lagging snapshots before atomically regenerating progress from the
same certified prefix. Tail repair retains bounded filesystem observations
separately from the immutable semantic certificate. Before truncation it proves
the original consumed ranges and digests, exact recognized namespace, directory
identity and captured file observations through safe file access. It truncates
and syncs only the incomplete active tail, then proves that same prefix and
namespace with stable handle/path observations and the exact repaired size.
Only successful verification returns an immutable snapshot with post-truncation
observations and `hasPartialTail: false`; the original capture, certificate,
state and revision endpoint remain unchanged. The journal recovery wrapper
returns this value to `recoverRun`, which uses it for ownership checks and
observation retirement through `persistObservations` and `appendTransition`.
Independent appends also consume their own repair result. No latest-history
reload or callback-populated checkpoint substitutes for the original proof,
and read-only observers never authorize repair. Failed publication or recovery
discards retained evidence, including callback reads.
Runner monitoring and MCP activity/wait consumers continue using the state
capability; they own no projection cache or additional polling.

Lock-free readers discover an ordered segment prefix after reading current
state, prove every revision and cross-segment transition, and reject missing,
misnamed, oversized, or incomplete sealed segments. Only the last segment may
have an incomplete tail; leased recovery truncates that tail and republishes
lagging state and derived progress. Existing single-file journals load without
migration of their records on read. Common-envelope version 21 and detached
compatibility token `1:21` established the segmented format. New runs use
version 28 (`1:28`); legacy runs require an explicit leased migration publishing
a version-21-or-newer record in the original journal before rollover is permitted.
Even if state replacement is interrupted, older readers reject that original
journal instead of ignoring later segments and appending conflicting revisions.
If the original segment lacks space for the migration record, publication fails
with `ERR_EVENT_LOG_LIMIT` and retains the legacy history; migration cannot
silently publish its barrier in a new segment. Readers reject segmented history
without the original-segment barrier. Segment paths are reserved from
run-artifact writes.

A coding pipeline's required-check `environment_blocked` pause with
`ERR_REQUIRED_CHECK_CAPABILITY_UNAVAILABLE` may carry an optional
`capabilityDiagnostic`. Root pause validation, including pauses retained by
operator stops, accepts it only on that reason and code for plan execution and
polishing and validates it through trusted validation's public
`normalizeCapabilityMismatchDiagnostic`. Generic pause cloning reads only
the ordinary fields and the checkpoint structure. Invalid diagnostics fail
state validation with a fixed message. Operator stop restoration returns the
value unchanged. The additive field preserves existing state versions.
Historical absence means unknown. Evidence prose and other records cannot supply
the missing diagnostic. Activity derives `capabilityDiagnostic` from each event's
own top-level pause. Eligible coding pauses project the diagnostic or `null`
when it is absent. Other events omit the field. Byte-certified projection reads
the pause from each event and retains only its normalized public diagnostic
plus its `capabilityChecks` projection, empty when the diagnostic is null, and
its revalidated `ownershipDiagnostics`, including when the diagnostic is null.
Detached recovery-failure sidecars remain separate allowlisted error records
and never carry it.

Events may carry an optional bounded public activity record containing only
`actor`, `phase`, `kind`, and a concise one-line `message`. Pipelines derive
these messages from validated structured results; the state service validates
only their generic form. Cursor-based readers expose this projection without
returning private pipeline state, model output, credentials, or unhashed remote
and identity values. Persist concise structured decisions and summaries, never
raw model transcripts or chain-of-thought.

## Explicit-model catalog recovery

Provider [catalog-miss classification](../providers/failures.md#explicit-model-catalog-misses)
and [model attestation](../providers/requests.md#explicit-model-attestation)
supply this contract's inputs. Common envelope version 28 journals at most one
private completion receipt per frozen role, bound to the role, provider,
profile, explicit model and effort; its
[migration](../migrations/common-envelope.md#catalog-recovery-evidence) starts
with empty receipts. The run store requires a runner-recorded completed attempt
that started after the current turn opened, with provider custody retired.
Child creation, compaction and provider observations alone confer no model
proof. Replay verifies the same attempt binding and append-only receipt
history. If receipt publication loses its acknowledgement, Runner verifies the
receipt against the certified journal. An unconfirmed receipt leaves the active
turn for normal checkpoint reconciliation, including read-only restatement of
completed workspace writes.

After policy, configuration and stop checks, the Runner reads the latest durable
receipt and checks the normalized no-effect record. A source-fork request
cannot use the receipt. The owning workflow verifies its snapshots and pauses
at the bound checkpoint for explicit resume with the same selection. The
journal carries that binding from resume acceptance to the matching turn-start
transition, including a retryable environment pause or a temporary init
inspection failure at the same workflow state.
If clearing a retry pause loses its acknowledgement, the coding workflows leave
the journaled checkpoint for recovery.
The resume transition must publish the binding before any new turn starts.
Admission and replay reject redirects to a different workflow phase, including
when the run returns to a catalog pause before dispatch. They also reject
replacements of the frozen input hashes while the retry is pending.
The turn-start event records the logical checkpoint so replay can verify the
exact binding and the actual turn's role and phase. The registry supplies
descriptor-owned reservation checks for plan authoring, plan execution,
polishing, audit and init to the run store for both admission and journal replay.
First publication requires the owning descriptor to recognize the role, access
and exact checkpoint, including ordinary direct turns. The public `src/index.js`
guidance factory defaults to the registry-composed run store and accepts an
injected store; CLI, MCP, and Runner setup supply their composed store, so
reclaiming a prior run's lease verifies its journal with the owning pipeline's
reservation and stop rules. Pipeline checkpoint validation stays at the
composition boundary.

Plan authoring preserves the saved draft and counters through dispatch.
Init preserves the frozen settings, spent revisions and proposal evidence
while rebuilding its read-only turn reservation from the saved facts.
Coding restatements preserve their stage and attempt. A `CHECK_AND_FIX` or
polishing `POLISH` catalog retry keeps the frozen input hashes, candidate,
pending correction and fix budget from the first pause through dispatch. A
writable `FINALIZE` retry keeps the frozen input hashes, candidate, validation
inventory, correction scope, spent counters and authorized limit from the first
pause through acceptance and dispatch. Both coding pipelines journal the live
validation-infrastructure fingerprint with catalog pauses at candidate review
and candidate clean confirmation, including initial turns with no pending
correction. A first read-only candidate review, clean confirmation or terminal
confirmation catalog pause must retire that gate phase's current invocation and
its sole failed attempt at that checkpoint with its recorded no-effect
rejection. It keeps the frozen input hashes, reservation and counters and may
only add an absent infrastructure fingerprint. Every other first read-only
catalog pause, including audit, init, plan authoring and validation migration
in both coding pipelines, likewise needs that sole failed attempt at the
pipeline's observed checkpoint; without it the Runner grants no retry. Plan
execution narrative reviews observe `plan-context` and bind retries to their
producing turns. Polishing migration checkpoints keep the suspended phase
prefix and use the migration reservation. A captured fingerprint, accepted
work reports and prior finding decisions stay unchanged through later misses.
The reservation also preserves finalization guidance, any
correction scope and, in plan execution, the selected step. A candidate-review
retry preserves its complete saved state, including custom criterion results,
spent counters and configured and additional fix rounds, through the matching
Reviewer turn start. Audit preserves its saved state,
including both pass budgets, through the matching catalog retry turn start.
In combined mode, successful Worker clean confirmation retires its retry
scope when advancing to the independent Reviewer, which inspects its own scope.
Both coding pipelines preserve the saved finalization evidence and correction
allowance until a bound `CONFIRM` turn starts. Before dispatch, confirmation
scope drift clears the stale terminal evidence and retires the binding through an
`unsafe_git_state` pause. Admission and replay still reject a direct redirect
to `FINALIZE`.

Plan execution state version 46 persists the validation-migration disagreement
and resumes its Arbiter from that record and the existing correction ledger.
The first migration pause preserves the suspended role and workflow state,
frozen inputs, reservation, disagreement, correction ledger and spent counters.
Admission and journal replay enforce that preservation for both direct and
narrative pauses and their subsequent retries.
Older checkpoints migrate without inventing a disagreement or offering a retry
for an unbound Arbiter catalog pause.
The version-43 through version-45 migrations verify any pending clarification
append against its checkpoint before changing the bound pipeline state.
Replay verifies the same rebinding and preserves the exact append intent and
both transcript hashes.
Polishing resumes validation migration in the saved phase and role, preserving
its recorded disagreement and correction ledger through the retry.
Candidate review and candidate clean confirmation compare the saved scope
before dispatch and through result settlement, including after recovery of an
interrupted retry.
Infrastructure drift pauses the run with any pending correction intact and
without accepting a response. An older initial candidate pause without an
inspected scope cannot establish that retry binding.

COMMIT consumes the authorization it prepared for the selected step, and
audit retains its unsettled pass. Initial IMPLEMENT journals the verified
no-effect and unchanged-workspace result when it retires the matching active
invocation into the paused reservation. Publishing a `workspace-write` catalog
retry requires the retirement event to repeat the redacted no-effect rejection
recorded on the sole Runner-recorded attempt after the turn started. Admission
and replay require a failed status, the same role, the exact checkpoint and
matching rejection evidence. A catalog pause that sends a reconciled original
invocation to read-only restatement needs the original invocation's matching
failed attempt and rejection. A catalog pause for an already-consumed
restatement can retire only the active turn whose own failed attempt records a
read-only no-effect rejection. The attempt uses the restatement's checkpoint or
its retained provider episode's checkpoint. Publication, acceptance, and
dispatch preserve the frozen inputs, reconciled candidate, reservation and
spent counters.
If a stop is accepted after that rejection is journaled, operator-pause
settlement verifies the same attempt against the saved inputs, candidate and
validation scope. The operator pause keeps the retry for explicit resume and
does not dispatch or charge the restatement again.
Plan execution captures the reconciled candidate's validation scope at the
first read-only turn start for each restatement attempt. The saved scope binds
provider continuations across backoff and Runner restart. Runner rechecks it
before publishing a continuation, after turn-start publication and before
accepting the result. The established validation fingerprint still records
the scope used for later validation-change review. Cancellation accepted
before stop settlement retires the invocation and retains its rejection and
accounting without publishing a new restatement retry.

The COMMIT catalog pause
must retire a consumed authorization with qualifying rejection proof in the
preceding journal state, including during operator-stop settlement. Admission
and replay accept that proof only from the latest failed Worker attempt at the
same `commit:<step>` checkpoint, started after the consumed COMMIT turn opened.
When that attempt fails, the Runner records its own normalized `commit`/`none`/
`not_started` catalog rejection on it; the recording event must repeat exactly
that attempt-bound rejection. A generic failure, a later independent claim or
an earlier completion receipt proves nothing about that invocation. The stop
monitor binds any reduced pre-executor rejection to the specific authorization
and clears it before a new attempt. A coding restatement records its invocation
boundary from the journal predecessor inside the turn-start transaction. The
predecessor must show that the earlier invocation has retired. Ordinary
reconstruction can replace a stale activity marker without establishing
restatement proof. A deferred stop accepted during preparation can advance that
predecessor without invalidating the invocation. If plan execution must rebuild a
narrative review's prerequisite, the catalog binding names that prerequisite's
phase while provider recovery retains the narrative checkpoint.

Workspace drift during a proven no-effect writable turn blocks reconciliation
without becoming part of the candidate. Runner binds the proof to the turn
before checking configuration and stop. After owner loss, ordinary resume and
stop reconciliation recover the guard from certified history. The active turn
must have exactly one attempt, which failed at the matching role and writable
checkpoint.
This guard preserves the baseline without granting retry authority.
If configuration drift takes precedence,
the configuration pause retains the original candidate baseline, reservation
and accounting without authorizing a catalog retry. Catalog recovery adds no
backoff episode, reconstruction allowance or source refork. Retained
[availability episodes](availability.md#catalog-restatement-episodes) and
[inactivity continuations](inactivity.md#catalog-restatement-continuations)
keep their existing owners.
