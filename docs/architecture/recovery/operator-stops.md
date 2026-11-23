# State-owned operator stop protocol

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

The common envelope version 7 extends the nullable bounded `stopRequest` with
requested and effective timing, immutable target evidence, and settlement
accounting. The state service's `requestOperatorStop` accepts a run ID,
`pause_requested` or `cancel_requested`, an inspected `expectedRevision`, an
`idempotencyKey`, and optional `timing` (`immediate` by default).
It persists a version-3 action intent, appends the complete acceptance event,
and publishes an acceptance receipt before returning. This capability does not
signal processes, reconcile Git, or expose CLI/MCP commands; those operations
belong to runner and transport integration.

Short, recoverable `.mutation-<uuid>` claims serialize requests with
execution-owned journal writes and lease release. Each contender durably
publishes a choosing claim before selecting its ordered ticket; it waits for
choosing peers and lower ticket/identity pairs. Dead claims have unique paths,
so recovery cannot unlink a newer owner at a reused lock pathname. Claims and
contention are observed at most 500 times with 10 milliseconds between blocked
observations, about five seconds plus filesystem work. Exhaustion returns the
retryable mutation-busy outcome, and unverifiable owners continue to exclude
mutation. Action-lease reclamation uses the same boundary, which does not grant
another execution lease. Worktree owners without a pipeline run, such as
guidance publishers, use claims in the worktree lease directory. Status and
activity reads remain lock-free.
The acceptance record contains the hashed request identity, request kind,
inspected and accepted revisions, request time, nullable reconciled revision,
and a suspended checkpoint. That checkpoint records the workflow state, active
turn, null resume action, and the exact earlier journal revision. Reading that
revision recovers the complete frozen state, including existing pause blockers
and pending input, without duplicating a potentially large pipeline payload.

Only nonterminal runs accept fresh requests. A cancellation may supersede a
pending pause using either its original inspected revision or the current
revision; it retains the original checkpoint. Other stale requests fail, as do
new competing requests that cannot supersede the pending stop. Exact retries
return their original receipt. If receipt publication was interrupted, the
acceptance event reconstructs it even after cancellation superseded a pause or
the run terminated. Receipt replay neither advances the run nor executes work.
Version-1 and version-2 action records remain readable; incomplete actions
upgrade when written, and completed receipts replay without migration writes.

Execution propagates commit-authorization preparation and consumption publication
failures without overwriting the journal with a stale local checkpoint. Deferred
stop recovery preserves the durable authorization, never invokes a prepared
effect to obtain a commit, and only verifies a consumed effect. Fault-injection
coverage includes acceptance versus advancement/completion, lost receipts,
lease transfer, and verified settlement publication for both stop actions.

New stop argument identities include timing and canonicalize omitted and explicit
`immediate`. Legacy timing-less identities accept those same immediate arguments
and retain their original receipt shape; a timing change conflicts. Legacy stop
records normalize to immediate timing without read-side writes. New receipts
include requested/effective timing and bounded target evidence. Target evidence
permits a null baseline HEAD only with no preceding completed commits, preserving
an unborn logical step's boundary across child commits. CLI `--timing` and MCP's
optional `timing` field expose the same two values; omission stays immediate.
Transport validation never refreshes an inspected revision or changes
retry arguments. MCP keeps `pendingStop` for pending requests and adds the
state-owned bounded `projectOperatorStop` summary as `stop` for current and settled
requests. CLI status uses the same summary; public activity derives it from each
event's state, and waits reuse status. It excludes identities and private
checkpoints, exposing kind, accepted revision, requested/effective timing,
target step, state, and nullable settlement. `applicable` denotes immediate
requests or suspended/failed checkpoints awaiting reconciliation; other pending
requests remain `pending`, including interrupted owners awaiting recovery.
`settled` denotes completed accounting, with `quiescent` or a verified commit
SHA when available. These projections do not decide ownership or enforcement.

Plan execution's descriptor classifies one stop checkpoint as `pre-work` only
when the applicable request is immediate, its saved journal revision matches
the unchanged current pipeline state, and both snapshots remain at initial
`CLARIFY` with incomplete preflight, empty input hashes, no repository baseline,
backend versions, clarification path, frozen artifact, pending edit, canonical
plan, selected step, pending commit, or completed commit, and no pause, active
turn, execution process, or execution resource. The runner holds the run lease and
uses the existing atomic stop settlement without acquiring a canonical lease
recorded for another run. Cancellation becomes terminal; pause preserves that
same resumable `CLARIFY` checkpoint. Any failed predicate retains the ordinary
worktree-lease requirement and full repository/effect reconciliation. Plan
execution state version 21 is an identity migration that rotates detached
runtime compatibility for this settlement-aware contract. Plan execution state
version 22 adds its frozen finalization-guidance decision. Terminal states and
consumed commits retain verification-only recovery. Other unfinished legacy
states establish the decision before more provider work and use the existing
read-only validation migration before writable work when their prior inventory
cannot prove the new contract.

The private `src/state/stop-policy.js` owns three distinct decisions: whether a
request awaits reconciliation, whether that request blocks execution, and
whether unresolved stop accounting or a recorded execution process retains
ownership. Immediate requests block execution. Deferred requests retain ownership
while allowing progress within their immutable target. The runner monitor keeps
watching for immediate cancellation supersession without aborting deferred work.
Envelope validation owns
shape; the stop service owns acceptance, supersession, and receipt accounting.

State accepts `after-current-commit` only with a trusted synchronous
`resolveStopBoundary` capability supplied to `createRunStore` by composition.
It resolves a frozen authoritative snapshot inside acceptance serialization.
The bounded `verified-commit-v1` evidence contains the positive step number,
completed-commit count, and baseline SHA; no provider data or free text is stored.
Ordinary writes cannot change that boundary; only leased atomic settlement can
record progress together with the stop outcome. Unsupported resolver results or
persisted capabilities fail closed, including during history reads. The root
pipeline registry supplies execution's boundary resolver to the runner
and MCP stores. Execution accepts a selected step, including suspended
checkpoints; clarification, bootstrap, absent steps, and the other pipelines
reject deferred requests. Direct state stores without that capability still
fail closed. Deferred CLI/MCP request inputs remain unavailable.

Cancellation supersession retains the original suspended checkpoint and cannot
delay an earlier immediate stop. Requested timing remains visible when effective
timing is immediate; a still-deferred cancellation retains the earlier target.
Settlement records either a verified commit SHA or a quiescent fallback, and
becomes immutable with the reconciliation revision. Workflow meaning and commit
verification remain the pipeline/runner's responsibility. Execution supplies the
verified SHA to both ordinary checkpoint settlement and verification-only recovery.
The state mutation records progress and the latest requested outcome together.
If the target pauses, fails, or loses its owner before verification, recovery
reconciles effects and applies the request at the quiescent checkpoint without
invoking another role. Underlying failures, blockers, and consumed authorization
evidence remain in the operator checkpoint. A final-commit pause suspends `DONE`;
resume reaches `DONE` without agent work. Final-commit cancellation retains all
completed commits in `CANCELED`.

The common advancement guard applies inside the mutation boundary to workflow
transitions, provider-turn records, session/artifact writes, and execution
registration. Pending stop enforcement takes precedence over process accounting,
then terminal cancellation blocks any further advancement. Retiring a recorded
process remains allowed while a stop is pending so reconciliation can finish.

Lease release, worktree reclamation, and durable `runIsLeased` exclusion consult
the separate ownership-retention policy. A reconciled cancellation remains
terminal without retaining ownership; a reconciled pause permits ordinary
resumption once other blockers are resolved. A pending stop prevents release
of held run/worktree ownership even after its process record has been retired.
A dead owner's existing worktree lease remains excluded from other runs while
the request is pending; only recovery of the same run can reclaim it.
Reclamation, including reclaim-marker recovery, rechecks the stop under the
original run's mutation boundary before replacing ownership. A crash leaving
only a reclaiming record retains that reservation until a replacement lease
exists, restricted to the same run while a stop is pending; failed
replacement publication restores the previous lease when possible.
The recorded lease owner and the run currently requesting reconciliation are
separate identities: diagnostics name both when they differ. Operators never
manually delete, rewrite, or bypass a lease record to make progress; recovery
uses the state-owned settlement and normal lease acquisition/reclamation rules.
`inspectRunLeaseOwner` exposes private identity and finite
live/dead/replaced/unverifiable classification for runner use; unverifiable
owners are not eligible signalling targets.

The runner separately tracks an in-process canonical-worktree lease handle,
durable same-run recovery responsibility, and the persisted execution-process
record. Stop reconciliation reuses a handle it already owns and releases it
only after durable settlement. If process retirement cannot be proved, the
same-run reservation remains for retry and the containment error escapes
unchanged; release recovery never reacquires that handle and cannot replace the
failure with a self-conflict. After owner loss, normal age, process-identity,
and competing-owner checks govern same-run stale reclamation before the same
retirement and settlement path runs.

Only the execution lease holder can call `completeOperatorStop`, after the
runner has reconciled the interrupted access contract and any begun effects.
That operation atomically records `WAITING_FOR_USER`/`operator_paused` or
`CANCELED`, clears active-turn activity, and marks reconciliation complete.
It does no repository work. The journal retains the suspended checkpoint and
prohibits cancellation downgrade or revival. Identical completion retries do
not add another transition. Lease release becomes possible only after this
durable accounting. Version-1 through version-3 run envelopes project a null
request without read-side writes; stop acceptance can upgrade only the common
envelope in its acceptance event while preserving pipeline state and history.

Verified commit settlement uses the leased `settleCheckpoint` state operation.
Its synchronous resolver reads the latest authoritative snapshot inside the
mutation boundary; the runner supplies workflow patches and the pipeline
validator checks the fully normalized result before journal publication. A
recorded execution process prevents settlement. A pending stop must settle to
its requested outcome, including a cancellation that superseded a pause during
verification. No provider, Git, or artifact effects run inside the resolver.

Execution's private `commit-checkpoint.js` constructs the verified SHA, clean
repository baseline, completed-commit list, next step or `DONE`, evidence resets,
and counters. Normal execution and verification-only stop recovery use that same
construction. The runner wraps the checkpoint in an operator pause or cancellation
when applicable and retains protected-configuration blockers beneath the stop.
Successful settlement clears the active commit turn and consumed authorization
in the same event as progress. Publication errors escape without writing failure
state from an older local snapshot; journal recovery preserves an already
published checkpoint without replaying the commit. Deferred requests use the
same settlement path and retain explicit commit or quiescent accounting.
