# Durable availability episodes

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

Common envelope version 16 adds the immutable normalized client attribution and
its matching fingerprint. Version 1 through version 15 runs normalize only to
the generic default; a leased runtime migration journals that value without
loading current configuration. Legacy state cannot claim a custom identity.

Common envelope version 15 adds immutable `availabilityPolicy` and nullable
`availabilityRetry`. Runtime compatibility includes this envelope version.
Legacy versions project the documented default policy and no pending episode;
the leased runtime migration journals those values without replacing saved
roles, checkpoints, modes, corrections, session lineage, or provider receipts.
Current configuration never replaces a frozen policy on resume. Legacy records
cannot claim a custom policy or pending episode.

The state service's `scheduleAvailabilityRetry` accepts an inspected revision,
active role, bounded logical checkpoint, finite provider-neutral reason, and
reconciled content fingerprint. It requires retired process and resource
ownership and the existing exclusive mutation lease. Scheduling ordinarily
requires the turn to have retired. A reconciled coding-pipeline restatement can
retire its exact turn and record its read-only continuation in the same event
as the next backoff. Admission and replay verify the owning pipeline's
consumed reservation and the reconciled candidate fingerprint against the
recorded turn start. They require the latest provider attempt to have started
after that turn start and failed at the backoff's role and checkpoint. The
service appends the complete event before replacing state and returning. The
episode stores a UUID, role, checkpoint, reason, attempt, delay, scheduling
time, retry deadline, content fingerprint, and reconciled revision. The caller
owns repository reconciliation. A hash-shaped value alone does not prove Git
safety.

Delays are `min(maxDelayMs, 5000 * 2^(attempt - 1))`: at the default ceiling,
5, 10, 20, 40, 80, 160, 320, 640, 1280, 1800 seconds, then 1800 repeatedly.
The attempt has no policy quota; its numeric representation saturates at the
largest safe integer without stopping capped retries. Journal validation rejects
policy drift, changed episode identity/role/checkpoint, skipped attempts,
inconsistent deadlines, and progression before the prior deadline. Deadlines
are calculated from the current scheduling time, so overdue recovery cannot
produce a catch-up schedule. Unrelated transitions and restart retain the episode;
clearing it is reserved for the successful-provider-turn coordinator path.

The runner injects one availability coordinator into all registered pipelines.
Logical checkpoints bind the original access mode as well as role and phase;
read-only dispute recovery cannot regain write access through an availability
episode when its correction budget is exhausted.
Each pipeline first reconciles repository controls, safe partial content, and
turn/process retirement, then requests scheduling. Correction accounting and
pending correction diagnostics remain bound to the same logical turn; partial
writes invalidate dependent approvals without charging that correction twice.
After restart the pipeline reconstructs the same role/checkpoint from durable
state, preserving lineage without reforking the source. Deadline waits retain
the execution/worktree leases and are abortable by immediate or deferred stops.
An overdue deadline permits one attempt, never a catch-up burst.

Scheduling and retry start are journaled before waiting or dispatch and immediately
published to CLI/MCP activity with bounded role, checkpoint, normalized reason,
attempt, delay, and deadline. Status projects the same fields in `availabilityRetry`.
A successfully returned provider response clears the episode at repository
reconciliation, before deterministic output validation; rejected output can
therefore still mark provider progress. Reconstructing plan context for a
pending narrative review preserves the review's episode until that review
settles. A normalized authentication-required
response retires the superseded availability episode as part of settling its
distinct operator pause. Coding-pipeline restatements retain the consumed
attempt and any spent inactivity allowance after authentication, and retain
their provider recovery episodes through output exhaustion. Polishing journals
acceptance of a restatement's provider retry when clearing its pause, then
consumes that continuation with the next read-only turn start. Reconciled
content and correction accounting are persisted atomically with either pause.
Check/fix mutation claims are compared against the attempt's starting
fingerprint, including any safe content retained from earlier failed attempts.
Other availability errors, tool activity, partial output,
session replacement, operator resume, and restart do not reset it. Persistence or
wait failures retain the checkpoint and propagate without inventing a terminal
pipeline failure.

Plan-execution state version 24 permits a bounded availability reason and
`commitExecutor: "not_started"` in a persisted pre-effect rejection. Version 23
migrates without inventing that proof. Version 25 makes the plan-execution
source-projection need explicit and defaults version-24 reports to false without
changing frozen authority, workflow evidence, correction accounting, or effects.
Consumed authorization remains verification-only until Git proves no commit and
unchanged state; only then can one atomic journal transition retire it and
schedule a fresh authorization.
Potentially executed commit/handoff effects never enter availability replay.
Polishing state version 16 preserves charged partial resolutions at their original
checkpoint. Both writable pipelines persist whether the current provider-recovery
continuation has charged a check/fix round; authentication recovery also retains
the charge for a partially completed finding-resolution round. An earlier
pending correction does not exempt a new round, and availability reset or
authentication pause cannot erase an unfinished charge.
Legacy pipeline migration initializes that marker to false. Both retain unresolved blockers and historical
negative validation evidence during recovery; no stale passing evidence or
approval can authorize the changed content.
Polishing state version 17 makes its independently owned source-projection need
explicit and defaults version-16 reports to false without changing frozen
authority, workflow position, review or correction evidence, or handoff state.
Null provisional reports retain the existing read-only discovery barrier.
Foreground CLI owner loss requires resume; detached MCP ownership outlives a
client timeout or disconnect.

## Catalog restatement episodes

[Explicit-model catalog recovery](journal.md#explicit-model-catalog-recovery)
adds no backoff episode. Before read-only restatement, the owning pipeline
durably settles or rebinds any existing availability or inactivity episode to
the consumed reservation and its continuation. A coding restatement retains
any original recovery episode under its original reservation identity,
including its reconciliation evidence and spent allowance, across restart. It
resumes only through the bound checkpoint, and a later provider retry draws on
the remaining allowance without a new backoff from the catalog pause.
Polishing applies the same freshness rule as
[inactivity continuations](inactivity.md#catalog-restatement-continuations) to
the reconciled revision of availability backoff after turn retirement. Without
an invocation marker, certified polishing history must tie the backoff to the
latest retired restatement or the watchdog expiry to the latest restatement's
active provider attempt, under the same checkpoint and content.
A successful reconciled response retires the episode through its existing owner.
