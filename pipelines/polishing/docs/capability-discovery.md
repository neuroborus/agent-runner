# Polishing Capability Discovery

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Required Capability Discovery

Bootstrap and read-only validation migration persist `capabilityRequirements`
and `environmentBlockers` with each active role's exact inventory. The private
`capability-requirements.js` owns their bounded syntax; only the root
`inspectRequirements` capability evaluates authority, support, and availability.
There are at most 256 reports of each kind per role. Each need names an exact
inventory command, an optional frozen identity (`commandIdentity`, otherwise
null), `capabilities` with boolean `scratch`/`cache`, a required boolean
`sourceProjection` need, up to 32 exact `{url, sha256}` artifacts, and up to 16
unique `unsupported` identifiers. Each need and blocker also carries a closed
`basis`. `assigned-executor` entries describe the command's assigned executor
and checkpoint, either the ordinary Worker `FINALIZE` turn under its existing
workspace-write access or Runner-trusted execution of a selected command, never
the current read-only discovery, migration, or Reviewer turn. They require
static task, repository, or declaration evidence, or saved evidence from that
executor running the exact command at its checkpoint. A restriction seen only
through the current turn's read-only access may be recorded only as
`read-only-turn`; it is never upgraded. Ordinary safe Worker workspace output
needs no report. `sourceProjection`
is separate frozen authority, not a synonym for workspace-write, and may be true
only when evidence shows the actual executor must write beside the
staging-independent source it checks; agents cannot name a projection path or
grant broader authority.
Each blocker names an inventory command, `source` (`agent-sandbox` or `runner`),
and 1–8 bounded single-line evidence strings. Non-READY outcomes use empty arrays.
Every capability report must contain at least one scratch, cache,
source-projection, artifact, or unsupported need. A non-null `commandIdentity`
must exactly equal the frozen identity supplied for that selected command; the
field may remain null. Both `basis` values keep every structural rule.
Zero-need reports, substituted identities, missing or unknown `basis`, and
malformed reports use the
existing bounded read-only bootstrap correction path. A corrected empty array
leaves the ordinary inventory command agent-runnable and creates no delegated
requirement for root inspection.

Accepted reports from every active role remain saved and additive regardless
of the reconciled or arbitrated summary. Reports cannot grant permissions, omit
another role's needs, or replace frozen declarations. Root inspection receives
only `assigned-executor` reports and legacy reports without `basis`, never the
field itself. `read-only-turn` observations stay unproved for review and never
become requirements, so their ordinary check stays with Worker `FINALIZE`, where
an actual failure keeps its existing blocker semantics. Frozen trusted
declarations remain requirements without any report. Before every writable POLISH,
CHECK_AND_FIX, RESOLVE_FINDINGS, or FINALIZE invocation, inspect the saved request
again; cached declaration preflight cannot bypass this gate. Unsatisfied needs
pause as `environment_blocked` before content or index mutation, preserving the
checkpoint and bounded runner-derived evidence. Repairing the environment permits
retry; changing trusted selection or declarations requires a new run.
A blocked inspection saves the comparison's optional shared diagnostic as
`capabilityDiagnostic` and binds each published inventory index to the ID of
its required check in `capabilityChecks`; a command listed under several IDs
binds null. Saved evidence keeps each blocker
reason and validated ownership envelopes but no command text. Caught
availability failures and legacy pauses save no diagnostic, so their mismatch
details are unknown. Public status, wait and activity for this pause,
including historical records, use a fixed explanation and project evidence only
from the validated diagnostic, allowlisted check IDs and revalidated ownership
envelopes through the root-injected trusted-validation projector. Unsafe,
missing, ambiguous or unbound labels, including an ID saved for more than one
published blocker index, project as unknown and never change the blocker.

An agent-sandbox limitation is satisfied only for the exact delegated command
when runner inspection succeeds. A limitation on another command remains a
blocker. Preparation may acquire verified dependencies and probe isolation, but
never executes or attests required checks. Those checks execute only in FINALIZE,
which reacquires and reverifies dependencies. Configuration guards, cancellation,
leases, and resource ownership remain enforced by the root capability.

State version 14 marks legacy missing discovery with paired null report fields.
Passive migration preserves historical gate proof. Active legacy runs rediscover
requirements read-only before new writable work, using only Worker in lazy mode.
Pending migration cannot bypass safety or capacity-exhaustion pauses; only
retryable pauses and applicable explicit resume actions permit discovery.
Interrupted content corrections are reconciled and charged once before continuing. Completed and
failed historical states remain inert. HANDOFF first inspects whether staging
already completed: complete staging settles verification-only without providers
or capability preparation; untouched legacy staging returns to discovery and
candidate convergence. Current untouched handoffs recheck availability before
runner-owned staging. Stop reconciliation starts no new effects.

State version 15 adds the independently owned frozen finalization-guidance
decision. Completed handoffs and terminal history remain verification-only.
Other unfinished legacy runs resolve guidance before provider work and repeat
the existing read-only validation migration before writable work when their
prior evidence cannot prove the new contract.

State version 16 permits a charged partial resolution to retain its blockers at
`RESOLVE_FINDINGS` during availability recovery. Obsolete failed validation remains
negative diagnostic evidence only; stale approvals and passing evidence are
invalidated. Version 15 migrates without changing saved checkpoints or counters.

State version 17 requires every polishing capability report to carry the
boolean `sourceProjection` need. The ordered version-16 migration sets it to
`false` without changing the trusted snapshot, workflow position, correction
accounting, review evidence, or handoff state. It does not infer authority from
current configuration. Null provisional reports stay null and continue through
the existing read-only discovery barrier.

State version 18 admits the fixed `authentication_required` pause. The ordered
version-17 migration initializes the nullable provider-neutral source-fork
recovery marker to `null` while preserving workflow position, session lineage,
fingerprints, correction accounting, and handoff state. It does not infer a
native child or reload configuration, and it prevents older readers from
accepting the expanded durable vocabulary as version 17.

State version 21 requires `basis` on every new provider capability report. The
version-20 migration is the identity: it never edits saved or frozen reports,
selections, accounting, or workflow position. Saved reports without `basis`
stay byte-identical and keep the admission they were accepted under, and null
provisional reports stay null for the existing discovery barrier. Only
persisted-state validation accepts a report without `basis`; a recovered
provider result without it receives bounded correction, never an inferred
`basis`. The version bump prevents older readers from accepting reports that
carry `basis`.
