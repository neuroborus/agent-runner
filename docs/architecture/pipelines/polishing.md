# Polishing Ownership

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Mode and Session Policy

Polishing's private `mode-policy.js` separates active roles, bootstrap
independence, primary convergence, independent review, terminal confirmer,
arbitration eligibility, and primary session scope. Its workflow, persisted
validator, resume checks, and legacy migrations share those decisions. Ordinary
and interrupted repairs return through the same candidate checkpoint. Lazy keeps
one run-wide Worker source fork; independent checkpoints remain isolated and
Arbiter and correction contexts remain fresh. Persisted correction shapes and
budgets do not change. No policy grants index authority: staging remains the
runner-owned handoff effect. Polishing accepts independent, lazy, and combined.

## Gate Evidence and Handoff

Polishing's private `gate-evidence.js` composes primary clean, independent
candidate, finalization, terminal-confirmation, and handoff predicates. Routing,
persisted validation, legacy migration, and handoff authorization share these
checks. Candidate approval binds its inspected fingerprint; finalization can
format it into a different fingerprint that needs distinct terminal approval.
Content repair clears dependent evidence. Unchanged resolution retains only
fingerprint-bound passing finalization, subject to live content and infrastructure
rechecks after reconvergence. Legacy active evidence reconverges under the lease;
accepted handoff evidence survives migration and completed effects remain
verification-only. No persisted shape, mode, correction budget, or index permission
changes.

## Finding-Resolution Result Recovery

Polishing owns finding-resolution report recovery in its own workflow and
contract without importing execution internals. Polishing state version 20 adds
nullable `resolutionCorrection`; the version-19 migration initializes absence
without inferring recovery evidence or changing terminal history. In independent
and combined modes, each original `RESOLVE_FINDINGS` turn reserves the
checkpoint atomically with its active turn. A returned report first publishes
the reconciled candidate binding, approval invalidation and any single fix
charge, keeping its blockers at `RESOLVE_FINDINGS`, before the turn retires.
Invalid, lost or interrupted reports receive one durably consumed fresh
read-only restatement; repeated invalid or lost output pauses
`resolution_output_invalid`, and explicit null resume authorizes exactly one
further read-only attempt. Lazy mode keeps its existing resolution contract. The
owning [polishing specification](../../../pipelines/polishing/docs/SPEC.md#finding-resolution-result-recovery)
defines the checkpoint and pause contract.

Polishing state version 25 adds its own recovery-only UNFINISHED and
`repair-required` / `repair-authorized` continuation through existing null resume
and narrowly eligible extra-fix-rounds actions. Schema-2 resolution checkpoints
bind frozen facts, original blockers, candidate/controls/infrastructure and
predecessor work reports. New repair invocations preserve consumed attempts and
pending once-only correction accounting; invoked effects return through read-only
recovery, including authentication and output-exhaustion pauses. Uncertain repair
checkpoint, invocation, retirement or child-session publication, including
read-only restatement startup, propagates without overwriting durable authority
with stale failure or pause state; reconstruction uses the journal.
Version-24 migration upgrades shape only and grants no writes or renewed
allowances. Lazy resolution, candidate/terminal gates and runner-owned HANDOFF
remain unchanged.

## Lazy Structured-Output Recovery

Polishing owns the corresponding lazy structured-output recovery before its
runner-owned handoff. A writable check/fix correction reconciles safe content
and charges actual fix work once, invalidates stale gate evidence, and returns
through candidate convergence. A candidate clean-confirmation correction
remains read-only and retains the index, content, and
validation-infrastructure guards. Terminal Reviewer and Worker corrections are
separately scoped to finalized evidence; scope drift invalidates that evidence
and returns through finalization. Repeated
invalid output pauses with bounded redacted diagnostics and an explicit null
retry; neither a correction nor its recovery can stage, approve, or enter
`HANDOFF` early.
