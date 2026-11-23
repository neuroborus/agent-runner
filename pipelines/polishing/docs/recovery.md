# Polishing Checkpoint And Provider Recovery

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

### Action-free ownership recovery

The common Runner attempt/recovery surfaces retain nullable platform-validated
`ownershipDiagnostic` evidence independently of native sessions. The shared
[ownership diagnostic contract](../../../docs/ARCHITECTURE.md#bounded-ownership-failure-diagnostics)
owns its vocabulary, persistence compatibility and CLI/MCP projections. This
pipeline adds no diagnostic policy, retry, checkpoint or effect authority.
Capability pauses retain the trusted service's bounded blocker evidence. Caught
preflight, inspection and cleanup refusals use its pure `failureEvidence`
projection without changing pause codes or resume checkpoints.

A provider turn that returns `ERR_EXECUTION_PROCESS_UNVERIFIABLE` or
`ERR_EXECUTION_PROCESS_ACTIVE` retains its active-turn marker and checkpoint.
Do not reconcile or accept its output while process ownership is unresolved,
or turn that action-free failure into terminal `internal_failure`. Shared runner
resume proves process retirement under exclusive run/worktree ownership before
the ordinary interrupted-turn input and Git reconciliation. Finalization then
repeats at its saved checkpoint with fresh evidence. Begun handoff effects
remain governed by their existing verification-only recovery rules.

CLI exact-revision resume and MCP action-free resume use that same recovery path.
MCP journals child-correlated admission and readiness, waits through bounded
state/ownership notifications, and retains retryable intents across disconnect
or server restart. These acknowledgements confer no workflow or content approval.

## Adapter environment recovery

The root supplies adapter-owned resource journaling and cleanup. Unresolved
cleanup uncertainty (`ERR_EXECUTION_RESOURCE_UNVERIFIABLE`) preserves the exact
active checkpoint without accepting a provider result or fingerprint. The root
retires owned processes and verifies/removes the allocation before another
turn or trusted check. Fully cleaned pre-launch preparation failures use the
existing safe provider pause and not-started launch proof, including source-fork
recovery. Pipeline recovery then performs its existing repository
and effect reconciliation. A stronger provider failure retains its class;
retained-resource evidence prevents turn settlement over unfinished cleanup.
Terminal provider failures remain durably failed after cleanup; only safe
ownership uncertainty permits checkpoint continuation.
No agent receives cleanup authority and no ignore/fingerprint exception hides
scaffolding. Read-only mutation, containment failure, and ambiguous consumed
effects keep their existing precedence. Only bounded environment class/stage
and trusted command identity/outcome evidence may be retained, not diagnostics.

## Output-exhausted checkpoints

The pipeline consumes only the normalized `output_exhausted` disposition after
process/resource retirement and repository reconciliation. It enters
`WAITING_FOR_USER` with the exact closed pause `{ reason: "output_exhausted",
code: "ERR_OUTPUT_EXHAUSTED", resumeState, role, checkpoint }`. The checkpoint
is the complete logical phase/access/checkpoint key, not a native identifier.
CLI/MCP expose a bounded explanation, suspended-role/checkpoint evidence, and
one explicit null resume action. Repeated exhaustion pauses again; it never
starts writable replay, backoff, compaction, or malformed-output correction.
An operator may explicitly retry the saved checkpoint or start a new run with
smaller work units; retry does not replenish automatic recovery allowances.

Accepted progress, findings, pending correction attempts, and session lineage
survive. Possible source-fork effects retain the existing compatibility-named
`authenticationSourceForkRecovery` role/context marker; only no-effect evidence
may restore an unused lazy fork. Safety, ownership, authentication, review,
and ordinary availability policies retain their separate precedence.

Safe partial writes, affected gate invalidation, correction accounting, active-
turn retirement, and the exhaustion pause are persisted together. Content-changing
check/fix and finding-resolution work is charged once across explicit retries;
repairs require candidate convergence and fresh dependent gate evidence. A failed
finalization preserves its safe content without accepting a finalization result;
terminal confirmation remains distinct and read-only.

## Provider inactivity recovery

The common [inactivity contract](../../../docs/ARCHITECTURE.md#provider-inactivity-deadlines)
applies to every role turn. The frozen root/project
`providerInactivityTimeoutMs` defaults to 1800000 milliseconds, validates the
strict range 1–2147483647, and has no CLI/MCP override. Legacy common state
migrates to that default without configuration reload; pipeline versions and
saved settings are unchanged. Only validated semantic progress resets the
watchdog; an aggregate owned-command count suspends it until all commands
complete. Keepalives and process liveness are ignored.

The runner journals an expiry and role/checkpoint/attempt/configuration/content
marker before aborting the invocation. This pipeline reconciles its repository
boundary before requesting a fresh reconstruction. It retains the same logical
checkpoint and complete durable prompt, never reforks the source, and preserves
partial-content correction accounting while invalidating stale approvals.
Native fresh fallback and inactivity share one durably consumed allowance.
Common-envelope version 20 distinguishes `reconstructionRevision` from proven
`expiryRevision`. Generic and legacy reconstruction markers consume the same
allowance but establish no timeout proof and cannot relax correction budgets.
Public recovery adds `expiryProven`; unproven reconstruction is labeled as such.
An interrupted consumed reconstruction without expiry proof pauses with
`ERR_PROVIDER_RECONSTRUCTION_EXHAUSTED`, rather than claiming inactivity.
Repeated expiry pauses as `backend_unavailable` / `ERR_PROVIDER_INACTIVE`.
Restart preserves the allowance; an offered explicit resume attempts the same
checkpoint once without replenishing automatic recovery. A returned provider
response clears recovery only with matching repository reconciliation, atomically
with any safe content/counter update and before structured-output validation.

Availability backoff, authentication, usage limits, operator stops, and trusted
command deadlines remain separate. Commit readiness may retry only with existing
pre-executor proof and Git verification; the constrained executor and runner-owned
handoff are excluded. Ambiguous effects retain precedence. CLI/MCP publish the
same bounded expiry/reconstruction/recovery activity and status; a client
disconnect changes observation only.

## Explicit-model catalog recovery

The common [catalog recovery contract](../../../docs/ARCHITECTURE.md#explicit-model-catalog-recovery)
applies after configuration, policy and stop checks. A qualifying miss,
including one at candidate review, pauses as `backend_unavailable` with
`ERR_MODEL_CATALOG_RETRY` at the bound role and checkpoint. Explicit resume
retries the frozen selection without automatic backoff, adapter fallback or
source refork. A `POLISH` or `CHECK_AND_FIX` catalog retry preserves the frozen
input hashes, candidate, pending correction and fix-round accounting from the
first pause through the matching turn start. Workspace drift during any proven
no-effect lookup pauses as `unsafe_git_state` with the saved baseline and
findings intact, on cold resume and during operator-stop settlement. Possible
prior work instead reconciles into the read-only
[finding-resolution result recovery](review.md#finding-resolution-result-recovery),
which also owns restatement and gate retry bindings; validation-migration
retries keep the [persisted](persistence.md#persistence-and-resume) phase,
role and disagreement.
