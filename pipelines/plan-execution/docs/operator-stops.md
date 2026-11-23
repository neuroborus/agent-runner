# Execution Operator Stops

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Operator Pause And Cancellation

The runner's durable stop protocol applies to every role, checkpoint, and mode.
An immediate request aborts only registered execution. The runner contains
ordinary owned processes in private PID namespaces. Explicit native-sandbox
provider processes prefer that mode after a complete nested capability probe
and alone may fall back to session/token ownership on the initial host
namespace when nesting is unavailable. A runner nested inside the runner-trusted
validation namespace retains an owned session when that sandbox denies another
PID namespace, without widening the enclosing sandbox. It waits
for owned containment teardown, including detached descendants, before repository
reconciliation. The runner keeps its
execution lease and any held worktree lease until the pipeline's read-only
reconciliation path has accounted for the interrupted turn. That path cannot
invoke providers, trusted checks, or artifact writes. It revalidates frozen
inputs and the original access contract, preserves existing artifacts and safe
partial content, and retains unsafe input or repository changes as blockers.
It never rolls back content or changes Git controls.
The current runner reuses its already-held worktree lease during this path.
After owner loss, replacement ownership may safely reclaim only the stale
same-run lease. It rejects a replaced, live, unverifiable, or
descendant-bearing recorded process, clears a retired record under the
replacement execution lease, and makes process retirement plus checkpoint
settlement independently retryable across interruption.

Shared-host supervision and owner-loss recovery associate processes through
owned-session membership, a matching launch token or observed owned ancestry.
Available parent links continue through inaccessible environments, and observed
association survives later evidence loss. Unassociated processes neither block
progress nor receive signals because metadata is unreadable, their session is
newer or their cgroup is shared. Historical ancestry and control-group fields
remain strictly validated but optional; new launches store null values. Required
supervisor identity and namespace, live-owner exclusion, bounded inspection and
journaled retirement remain mandatory. Recovery never signals persisted host
PIDs. Shared-host discovery cannot prove absence against arbitrary same-user
processes hiding all ancestry and token evidence; see the
[safety contract](../../../docs/product/SAFETY_MODEL.md#inputs-artifacts-and-state).

The descriptor owns one fail-closed `pre-work` classification for an applicable
immediate stop saved against the untouched initial `CLARIFY` checkpoint. The
saved revision must match the stop checkpoint and the current pipeline state;
preflight is incomplete, hashes are empty, and neither snapshot has a persisted
repository baseline, backend versions, clarification artifact or frozen hash,
pending edit, canonical plan, selected step, pending commit, completed commit,
pause, active turn, execution process, or execution resource. Under the run
lease, the runner may settle only this checkpoint through the state-owned atomic
operation without acquiring an unrelated canonical-worktree lease. Cancellation
becomes terminal `CANCELED`; pause preserves resumable initial `CLARIFY`. Every
other checkpoint retains the worktree lease and full repository/effect
reconciliation. State version 21 is an identity migration that rotates detached
compatibility for this contract without synthesizing checkpoint evidence.
State version 22 adds the frozen finalization-guidance decision. Terminal runs
and consumed commit effects remain verification-only. Unfinished legacy work
resolves and freezes guidance before another provider turn; when its prior
evidence cannot prove the new contract, the existing read-only validation
migration re-establishes the inventory before writable work.

Pipeline state version 23 introduces scoped discovery and evidence. Its explicit
version-22 migration preserves legacy tuples with null step/confirmation
bindings, a null schedule/amendment, and `validationScopeLegacy: true` when
accepted discovery exists. This marker makes the old gates provisional; it
never infers applicability from the union. Before unfinished work advances, the
workflow clears unscoped active gates and rediscovers independently with every
mode-required bootstrap role. Partial accepted scoped discovery survives
interruption without replaying a completed role. Historical tuples remain in
the journal, completed commits and correction accounting remain intact, and
paused runs retain their required resume authorization. Terminal history stays
readable. Consumed stagnation arbitration and pending implementation rework
survive discovery, including fix-budget pauses. Restarting candidate convergence
retires a pending correction from an incompatible checkpoint but preserves its
consumed ledger and fix accounting; migration grants no new correction attempt.
Consumed commit recovery verifies its existing effect before any
preparation or discovery; unfinished subsequent work then crosses the same
rediscovery barrier. Journal-proven terminal-confirmation recovery also crosses
that barrier before new work when its retained tuple is unscoped.

A completed operator pause uses `WAITING_FOR_USER`, `operator_paused`, and a
null resume action. Its private checkpoint preserves the reconciled workflow
position, logical turn, and preceding pause. Resuming an already paused
checkpoint restores its blockers and pending editor authorization without
consuming them. Session reconstruction uses frozen roles, mode, settings, and
source lineage; an interrupted role does not refork its source. `CANCELED` is
terminal and inspectable, and every resume path rejects it. A settled pause
accepts only a fresh cancellation at its current revision; until reconciliation
validation accepts that pending cancellation over the preserved pause checkpoint,
which reconciliation wraps once as `operator_canceled` without provider work.

Writable partial changes advance the baseline only after index, history/ref,
remote, identity, and input checks pass. They invalidate dependent candidate,
finalization, and confirmation evidence and charge actual correction work once.
A consumed commit remains verification-only during reconciliation, even when
its effect races the request. A verified commit SHA and step advancement are
recorded atomically with the stop outcome; resume never reinvokes that consumed
effect. An uncreated or invalid commit retains its ordinary blocker, including
available pre-effect proof. If the runner proves that the operator stop
prevented invocation and Git verification confirms no effect, it retires the
unused authorization and preserves `COMMIT` for a newly authorized attempt on
resume. Cancellation winning during reconciliation changes only the requested
terminal outcome.

A stop that races a model catalog miss settles under the same proof rules. A
consumed COMMIT authorization retires for a fresh one-shot attempt only with
the journaled [catalog rejection proof](commit.md#commit), a matching receipt
and unchanged Git verification; a reduced stop record from before that proof
was journaled keeps the authorization verification-only. An operator pause
accepted after a read-only restatement's catalog rejection preserves the
consumed restatement for explicit retry after rechecking the frozen inputs,
repository, guidance and validation scope. Stop settlement retires the
invocation without replaying it or renewing the allowance, and retains a
watchdog continuation for explicit resume when its matching expiry predates
stop acceptance.

The runner service also accepts `timing: "after-current-commit"` when a step is
selected, including its suspended checkpoints. It rejects this timing during
clarification/bootstrap and when no current step exists. The target is resolved
from the authoritative state inside acceptance serialization and cannot move.
CLI pause/cancel exposes `--timing immediate|after-current-commit`; MCP stop
tools expose the equivalent optional `timing` field. Omission is immediate and
canonicalizes with explicit immediate timing for replay. Both transports retain
the exact inspected revision and idempotency key and reject changed arguments.
Status and waits expose bounded requested/effective timing, target step, pending
or applicable state, and retained settlement; activity uses event-time evidence.
Receipts remain immutable acceptance evidence, including across supersession
and settlement. A disconnected caller can retry the same request without
creating another owner, and wait cancellation affects only the wait.

An ownerless applicable stop is also a public continuation target. CLI
`agent-run resume --run <run-id>` performs action-free same-run reconciliation.
MCP `run_resume` requires `action: null`, the exact latest revision, and a new
idempotency key; its intent stores the private stop-checkpoint revision before
dispatch, so the original stop key is unnecessary. Fresh stale-revision,
non-null-action, live-owner, and duplicate-owner requests fail closed. MCP waits
for settlement or the correlated child's exit before completing the recovery
receipt. If another run owns the canonical worktree needed by a non-pre-work
checkpoint, diagnostics identify that recorded owner separately from the
ownerless pending run. Operators never manually delete or bypass a lease record;
supported recovery uses the state-owned lease protocol.

Deferred acceptance reserves ownership while the target step continues through
its ordinary gates. Monitoring remains active for immediate cancellation
supersession. Successful verification records the SHA, baseline, next checkpoint,
and operator outcome in one leased state mutation before any next-step Worker.
A final-step pause preserves `DONE` as its resume checkpoint and resume invokes
no agent; a final-step cancellation retains all commits in terminal `CANCELED`.
If terminal completion wins before acceptance, the request is rejected normally.

A pause, failure, or interruption before verified settlement applies the request
at the quiescent checkpoint after owned execution and effects are reconciled.
Recovery never performs extra work to obtain a commit. It preserves underlying
blockers and terminal failures, protected-input evidence, and consumed effect
and authorization records. Settlement accounts for either the verified commit
or the quiescent fallback; publication interruption cannot replay an effect.
Preparation and consumption publication failures propagate without persisting
an older in-memory checkpoint. Recovery reloads the durable authorization:
prepared effects remain uninvoked during stop reconciliation, and consumed
effects remain verification-only even when invocation never began.
Successful verification resolves a provisional commit-verification failure;
its earlier diagnostic remains in history while unrelated blockers stay intact.
