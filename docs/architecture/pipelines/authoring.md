# Authoring Convergence and Output Recovery

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Primary and Independent Review Policy

Plan authoring separates primary convergence, independent review, session scope,
correction accounting, and arbitration eligibility in its private
`review-policy.js`. The workflow and persisted-state contract share these pure
decisions. Turn implementations, effect guards, persistence, and plan writing
remain in the workflow. Combined mode enables both primary convergence and
independent review, retaining checkpoint-isolated sessions and the existing
durable lazy-checkpoint field names. Draft review invalidation
retains correction scopes so returning to an earlier fingerprint cannot reset
an automatic correction allowance.

Combined authoring records primary confirmation separately from Reviewer
approval. A revised draft clears both and restarts primary convergence; Reviewer
reconsideration of an unchanged draft can retain primary confirmation. Self
findings and structural failures return to check/fix, without arbitration on
exhaustion. Only independent finding resolution may request the fresh Arbiter.
Each accepted check/fix or revision consumes one bounded revision round; invalid
output and recovery cannot duplicate accepted work. Version 5 adds combined
mode while migrating saved version-4 independent/lazy state unchanged under
the lease; missing mode remains independent and unsupported old values reject.

## Structured-Output Recovery

Plan authoring owns primary-convergence structured-output recovery at both checkpoints.
Provider and deterministic contract failures become bounded diagnostics, then
one fresh repository-read-only Planner session receives the complete durable
draft-bound request and original schema. Only a valid replacement under the
unchanged draft fingerprint rejoins the ordinary route. Repeated invalid output
pauses at the exact checkpoint with a redacted explicit null retry; interruption
and resume preserve the pending marker without retaining rejected output,
replaying accepted progress, consuming revision or correction budgets, or
writing `plan.md` early.
