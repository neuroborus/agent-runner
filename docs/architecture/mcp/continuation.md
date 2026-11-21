# Bounded Action-Free Continuation

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Admission and readiness

CLI resume accepts an optional `--expected-revision`; MCP resume always binds
its inspected revision. Both enter the same runner resume path. Admission
checks the revision under the execution lease before recovery. An ownerless
nonterminal checkpoint with no pause also accepts action-free continuation,
including a crash between admission and the first provider turn. Retained
process/resource reservations are exclusion evidence, not proof of a live
runner: only same-host owner inspection decides whether to dispatch a replacement.
Same-run worktree reclamation retains exact process identity, mutation, and
reclaim-marker checks, and recovery reuses an already-held worktree handle.

MCP action-lease contention returns `ERR_MCP_ACTION_IN_PROGRESS` immediately.
Detached dispatch uses revision/lease notifications and the correlated child's
exit, with at most 64 inspections within 30 seconds. Exhaustion returns
`ERR_DETACHED_OWNERSHIP_PENDING`; it does not clear ownership or cancel the child.
The client can retry the identical key. Client cancellation and disconnect affect
only observation; reconciliation and receipt publication keep their action lease.

Before IPC admission, the action intent saves a dispatch UUID, exact revision,
and the child's hostname/boot/PID/start identity. The inert child waits up to ten
seconds for admission and cannot execute after a pre-admission disconnect.
Under the execution lease it journals a correlated `dispatch-started` event
before potentially long recovery. After process/resource retirement and acquiring
the required worktree lease, `dispatch-ready` marks checkpoint continuation;
short input/configuration paths can acknowledge their durable return; stop
recovery uses its existing checkpoint-bound settlement without appending another
acknowledgement revision.
These events do not approve content or attest workflow completion. Public activity
and progress output omit the private correlation UUID. Legacy confirmation
proof accepts these events only when the complete state is unchanged apart
from revision and timestamp; it is rebuilt for the acknowledged snapshot. The detached compatibility token versions
this admission protocol independently of the run envelope.

A restarted control plane adopts only matching journal evidence, never arbitrary
revision movement or transient lease ownership. A live or unverifiable recorded
child prevents redispatch. A dead/replaced child without a ready event permits
same-key recovery only at its unchanged revision or while its admission is
followed exclusively by root reconciliation. Another admission or workflow turn
makes that request stale. A durable ready event permits receipt repair even after
later pauses or input changes. Stop receipts additionally require settlement of
the specific saved stop checkpoint. A different worktree owner remains identified
in the retryable diagnostic.

## Correlated recovery diagnostics

The state capability exposes `recordRecoveryFailure(runId, dispatch, { stage,
error })` and `readRecoveryFailure(runId, { id, expectedRevision, owner })` for
detached recovery diagnostics. Each dispatch has an immutable, exclusively and
atomically published `.recovery-failure-<uuid>.json` beside the run state, bounded
to 4 KiB on publication and reads, and reserved from ordinary run-artifact writes.
Publication derives hostname/PID/boot/start identity from the publishing child.
Reading requires the exact run UUID, dispatch UUID, expected revision and child
identity already recorded in the action intent; mismatches and missing historical
records return no cause. A late child cannot replace a later dispatch's record.
Identical writes are idempotent; conflicting records are rejected.

These sidecars use the existing durable exclusive-file publication protocol,
without acquiring the execution or action lease or reading the workflow journal.
They can therefore retain failures before execution-lease acquisition or durable
readiness. The closed record stores a finite recovery stage, recognized Runner
error code and fixed allowlisted explanation; unrecognized errors retain a null
code and an unavailable explanation. Error messages, causes, stacks, provider
output and transcripts are discarded. Exit codes and signals are separate
observations and are never inferred from a diagnostic. A diagnostic cannot
acknowledge dispatch, complete an action receipt, change acceptance or workflow
state, or release uncertain ownership.

The CLI resume boundary publishes this diagnostic after a failed admitted
dispatch, using the actual recovery stage reported by the runner. Runtime
compatibility and execution-lease failures can therefore be retained before
admission is journaled. Diagnostic publication failure preserves the original
failure and its exit status. CLI recovery explanations use the same allowlist;
native messages, causes and stacks never supply detached diagnostics.

The launcher forwards both child exit arguments. MCP dispatch errors expose
`dispatchFailure: { exitCode, signal }` separately from the nullable
`recoveryCause: { stage, code, explanation, ownershipDiagnostic }`. Tool errors return `isError: true`
with these fields, the dispatch error `code` and safe `message` in both text JSON
and `structuredContent`. Only exact state-owned correlation admits a cause;
missing, invalid or mismatched diagnostics explicitly leave it unavailable.
Failed journal, status or ownership inspection for a recorded dispatch uses
the same safe projection, including identical-key retries after restart.
Stop recovery loads its saved action context before status or lease inspection,
including the original checkpoint retained by a superseding cancellation.
Inspection failure grants neither receipt completion nor replacement authority.
An unobserved exit has null facts, including after control-plane replacement;
neither a signal nor an exit code establishes a recovery cause. Version-skew
exit handling retains its distinct restart instruction. Admission errors also
discard arbitrary native error text. Bounded event-driven inspection, runtime
compatibility, readiness, stop settlement and exact-key retry rules are unchanged.
Failed dispatches retain incomplete intents and ownership exclusion. Retrying
does not repair the reported blocker or acknowledge workflow success.

## Interrupted provider ownership

Action-free provider process-proof failures leave the active turn and exact
pipeline checkpoint durable, including a finalization failure after command
execution. They do not become terminal `internal_failure` or accept output,
fingerprints, or checks while ownership is uncertain. Resume retires retained
processes first, then performs the pipeline's ordinary interrupted-turn Git/input
reconciliation. Consumed effects retain verification-only recovery.
