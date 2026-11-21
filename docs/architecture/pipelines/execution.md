# Execution Ownership

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Mode and Session Policy

Execution's private `mode-policy.js` separates active roles, independent
bootstrap, primary convergence, independent review, terminal confirmer,
arbitration, and primary session scope. The workflow, persisted-state validator,
resume-action checks, migrations, and journal-proven confirmation recovery use
those decisions. Ordinary and stop-reconciled content repairs rejoin the same
candidate checkpoint. Session selection preserves one run-wide Worker source
fork in lazy mode, checkpoint forks in independent and combined modes, and fresh arbitration
and output-correction contexts. Permissions, one-shot commit verification, and bounded
correction accounting remain with their existing workflow operations; policy
selection grants no additional repository authority.

## Combined Candidate and Terminal Gates

Combined execution runs Worker check/fix and a separate read-only clean
confirmation before the complete independent candidate Reviewer gate. Both
candidate approvals bind the same content fingerprint. Finalization may format
that content; a distinct Reviewer terminal confirmation approves its resulting
fingerprint and validation evidence before one-shot commit authorization.
Content repairs restart primary convergence. Self-findings go directly to fixing;
independent findings retain disputes, withdrawals, exact recorded overrides, and
fresh on-demand arbitration. Unresolved bootstrap disagreements and primary
exhaustion pause without arbitration. Corrections remain bounded and interrupted
work is charged once; resume preserves the saved mode and consumed commits remain
verification-only.

## Gate Evidence and Recovery

Execution's private `gate-evidence.js` composes primary clean evidence,
independent candidate approval, passing finalization, and terminal confirmation.
Persisted validation, normal routing, migration invalidation, journal-proven
recovery, stop reconciliation, and new commit authorization share these predicates
and resets. Candidate approval stays bound to the inspected content; finalization
may format it, so its resulting fingerprint requires distinct terminal approval.
Content repairs clear dependent evidence. Unchanged resolutions reconverge the
candidate and retain passing finalization only subject to fresh content and
infrastructure checks. Correction ledgers keep their existing bounded accounting.
Execution state version 17 adds bounded `primaryFindings` without renaming the
persisted lazy correction ledger. Leased version-16 migration adds an empty list
and preserves saved mode, counters, gate evidence, and pending effects. Combined
primary proof and independent approval remain distinct, including journal-proven
confirmation recovery.
Consumed effects still bypass new authorization and use verification-only recovery;
the shared predicates neither replace journal provenance nor grant Git authority.

## Writable-Result Recovery

Plan execution owns durable implementation/finding-resolution result recovery
in private `writable-result.js` and its workflow integration. State version 38
adds nullable `writableResult`; the version-37 migration initializes absence
without inferring recovery evidence or changing terminal history, accepted work
or consumed effects. Before invocation, the pipeline binds original phase,
step, content, blocker ownership, restrictions, inventories and accounting.
Reconciliation atomically publishes the inspected candidate, approval
invalidation and any fix charge before retiring the writable turn. Only
allowlisted normalization diagnostics are retained, never rejected output.
Unstarted prepared reservations resume under their existing authority after
unchanged-state checks; published invocations require result restatement.
Legacy writable continuations bind their reconciled baseline and retained fix
accounting before checkpoint creation, preserving original implementation proof.
Validated product decisions remain journaled settlement intents until the
transcript append and product-decision suspension complete. The existing
clarification service binds append replacement to a persisted result hash;
recovery reuses those exact bytes before input checks or another role turn.
The checkpoint retires atomically with the suspension and editor authorization.

One durably reserved read-only Worker restatement uses its recovery schema and
facts under unchanged content, frozen inputs, native policy and filesystem
permissions. Custom result data and output authority remain independently
validated and settle with the valid gate transition. Interrupted attempts remain
consumed; lost acceptance responses use the published state. Repeated invalid
output pauses with `writable_output_invalid`; explicit null-action resume
journals one additional read-only retry without renewing the automatic allowance.
Output-exhausted restatements require their exact read-only checkpoint bound to
Worker, the original implementation/resolution phase, step and consumed attempt.
Validated blockers remain blocking. Recovery precedes ordinary dispatch and
never repeats writable work, invents dispositions, duplicates fix charges or
commits, or replaces a mode-required gate. The owning
[execution specification](../../../pipelines/plan-execution/docs/SPEC.md#writable-result-recovery)
defines the checkpoint and pause contract.

Execution state version 45 adds recovery-only `UNFINISHED` and a distinct
`repair-required` checkpoint. Explicit null resume journals a new repair
invocation; unavailable uncharged budget instead requires the existing
`extra-fix-rounds` grant. Schema-2 checkpoints carry consumed restatement
allowances and pending fix accounting forward; bounded historical work reports
link predecessor checkpoints and retain uncertainty independently of native
sessions. Published invocations require reconciliation, retirement and read-only
recovery; only proven unstarted reservations are reusable. Migration upgrades
legacy checkpoints without granting writes or renewing budgets. Original blockers,
frozen authority and every mode-specific gate remain binding.
The [unfinished repair continuation](../../../pipelines/plan-execution/docs/recovery.md#unfinished-repair-continuation)
section defines the authorization and recovery gates.

## Lazy Structured-Output Recovery

Plan execution also owns lazy structured-output recovery. Provider and
deterministic checkpoint failures are reduced to bounded diagnostics, then one
fresh Worker session receives the complete durable checkpoint request with its
original schema. A writable check/fix correction may reconcile safe content
exactly once, invalidates dependent evidence, charges actual fix work once,
and must pass complete finalization before the pending checkpoint resumes. A
clean-confirmation correction is read-only and requires unchanged content and
validation-infrastructure fingerprints. Repeated invalid output pauses at the
exact checkpoint with a redacted explicit null retry; retry reconstructs the
pending attempt without recounting its automatic attempt or fix budget. No
correction result can act as early finalization, confirmation, review, or
commit evidence.
