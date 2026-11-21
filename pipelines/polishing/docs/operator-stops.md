# Polishing Operator Stops

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Operator Pause And Cancellation

The runner's durable stop protocol applies to every role, checkpoint, and mode.
An accepted request aborts only registered execution. The runner contains
owned processes in private PID namespaces. A runner nested inside the
runner-trusted validation namespace uses an owned session when that sandbox
denies another PID namespace, without widening the enclosing sandbox. It waits
for owned containment teardown, including detached descendants, before repository
reconciliation. The runner keeps its
execution lease and any held worktree lease until the pipeline's read-only
reconciliation path has accounted for the interrupted turn. That path cannot
invoke providers, trusted checks, or artifact writes. It revalidates frozen
inputs and the original access contract, preserves existing artifacts and safe
partial content, and retains unsafe input or repository changes as blockers.
It never rolls back content or changes Git controls.

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

Writable partial changes advance the baseline only after the unchanged-index
and Git-control checks pass. They invalidate candidate, finalization, and
confirmation evidence and charge actual correction work once. A request racing
`HANDOFF` performs inspection only: a fully staged accepted result is accounted
as completed, a fully staged result that fails the late staged hygiene check
takes the terminal `handoff_whitespace_rejected` disposition, an untouched
handoff remains pending, and an ambiguous index
retains a safety blocker. Stop reconciliation never stages or commits; resume
never restages an already verified handoff.
