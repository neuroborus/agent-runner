# MCP Actions and Detached Dispatch

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Durable actions and start recovery

Mutating MCP calls require an opaque idempotency key. The state layer hashes the
key, binds it to the tool and canonical arguments, and durably records an action
intent before mutation and a receipt before returning. An exact retry returns
the receipt; reuse with different arguments fails. An incomplete run intent is
reconciled against the reserved run ID, current revision, submitted transcript
hash, and execution lease before work is launched again.

`run_start` persists the run before spawning `agent-run resume` as a detached
child with no inherited standard streams. An incomplete start first loads its
reserved run and validates the request paths against that run's frozen workspace
selection. Current configuration is resolved only when creating a new run;
changed defaults cannot change a reserved run's workspace or plan kind.
`run_respond` atomically writes the
identified answers, records their transcript hash in run state, then launches
the same detached continuation. `run_resume` normally accepts only an action
applicable to the persisted pause. Two exact-revision, action-free recovery
paths are additional: a nonterminal checkpoint with no pause or live owner, and
an ownerless applicable stop. Stop recovery persists its own idempotency intent
and private stop-checkpoint revision, so it uses a new key and does not require
the original stop key. A non-null action, stale revision, live owner, or
duplicate ownership race is rejected without weakening ordinary pause-action
validation.

## Ownership and stop reconciliation

An ordinary continuation child owns the existing per-run execution lease and,
for plan execution or polishing, the canonical-worktree lease. Before ordinary
detached dispatch, MCP rejects an already-owned worktree without completing the
idempotency intent, leaving the reserved durable run available for an exact
retry. After spawning an ordinary mutating continuation, MCP withholds the
receipt until journaled readiness correlates that dispatch with process retirement
and checkpoint continuation under the required leases. A child that loses a
concurrent ownership race leaves the intent incomplete and exactly retryable.
Child-exit and ownership notifications wake bounded inspection; unrelated
revision changes and transient lease ownership cannot acknowledge a launch.

Detached stop reconciliation has the stronger completion condition. MCP binds
the launched child to the exact stop checkpoint and follows it until that stop
is durably settled or that child exits; transient acquisition of the run lease
is not progress. Exit before settlement leaves the recovery intent retryable
and reports detached-start failure or the distinct runtime-version-skew error.
A delayed child carries the checkpoint revision and becomes a no-op after that
stop settles, so it cannot resume a reconciled pause or revive cancellation.
An MCP disconnect, tool timeout, worktree conflict, or duplicate recovery
launch cannot create a second workflow owner.

`run_pause` and `run_cancel` delegate directly to the state-owned stop action,
so the acceptance event and receipt are durable before either tool returns.
Both require the caller's exact inspected revision and idempotency key. An
exact retry replays the receipt; a stale or conflicting request never refreshes
itself. A live execution owner observes the durable request through the runner
monitor. If ownership was already lost, MCP launches a detached action-free
resume to perform the same-run reconciliation. If the child exits first, the
diagnostic identifies a conflicting canonical lease by its recorded owner run
ID, distinct from the ownerless run whose stop remains applicable. Execution
and worktree leases still exclude a second owner. Client cancellation stops
only the tool's wait and does not retract the request or terminate the detached
child.

At MCP startup, the root freezes one bounded detached-compatibility token
derived canonically from the detached protocol version, root run-envelope
compatibility tuple, and the sorted ID/state-version pairs of every loaded pipeline descriptor. Detached
launch passes that token in an internal environment field. After loading its
own registry, the child independently recomputes and compares the token before
acquiring a run lease, recovering state, or evaluating a migration. A mismatch
uses a distinct exit status that the parent converts to an actionable
version-skew error; `state.json`, the journal, leases, the durable run, and the
incomplete idempotency intent remain exactly at their pre-dispatch state for an
exact-key retry after the MCP process is restarted. Client disconnect and wait
cancellation still affect only the client-side operation.

For a bootstrapped installation this protocol runs inside the already pinned
payload. Payload and Node-identity admission happen before child application
imports; compatibility and dispatch admission still happen before run effects.
Replacing the outer npm path cannot redirect either the current server or its
detached continuation to another application tree.
