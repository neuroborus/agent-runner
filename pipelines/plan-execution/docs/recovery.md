# Execution Checkpoint Recovery

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Legacy terminal-confirmation recovery

A legacy `FAILED` run with the exact `internal_failure` pause,
`ERR_CODEX_TURN_FAILED` code, and `turn_other` diagnostic may expose one
action-free retry. Eligibility requires the authoritative, continuous
write-ahead journal, not merely the terminal snapshot. The journal must prove
an actual mode-specific candidate transition: independent candidate review
acceptance, or an unchanged lazy `CHECK_AND_FIX` followed by accepted candidate
`CLEAN_CONFIRM`; combined requires both primary and independent edges. It must also prove passing finalization and the failed
read-only terminal `CONFIRM` turn for the same step. Complete current state,
check, trust, override, accounting, and effect contracts still apply.
This compatibility gate is intentionally exact: historical
`turn_server_overloaded` failures remain immutable `FAILED` runs, and no
migration reopens them.

Explicit supported migrations may preserve this proof, including across
restart, but cannot create it. In particular, the version-13 migration's
preserved terminal candidate tuple is not evidence of candidate acceptance.
Missing, discontinuous, inconsistent, altered, or migration-only provenance
grants no retry. Candidate repairs invalidate proof; permitted formatting
inside finalization establishes its resulting fingerprint. An otherwise
unchanged passing finalization record may retain its original provenance
through the existing candidate-reconvergence and evidence-reuse route.

`pendingCorrection: true` can be an accounting marker: a content-changing fix
has already been charged, and unchanged check/fix, candidate acceptance, and
finalization preserve that marker to avoid charging it twice. Recovery permits
that proven marker, without clearing it or changing counters, only when no
findings, disputes, directions, concrete correction payloads, migration
obligations, pending effects, or other conflicting work remain. The same gates
apply when the marker is false.

Status projects eligibility without acquiring execution ownership or rewriting
state. Execution recomputes proof under the normal run-then-worktree leases,
revalidates canonical inputs and artifact confinement, frozen hashes and plan,
repository/Git controls, finalized content, and canonical validation
infrastructure, and checks the complete retained finalization evidence.
Rejected recovery invokes no provider and uses existing safety outcomes.
An exact-revision write-ahead transition enters `CONFIRM` with a retained
read-only request, making interruption reconstructible without reforking the
source. It preserves completed commits, counters, settings, trust selection,
lineage, and valid evidence. Neither implementation nor finalization nor a
consumed commit effect is replayed. Repeated recoverable provider failure pauses
at `backend_unavailable` with `CONFIRM` as its resume target; successful fresh
confirmation reaches the ordinary one-shot commit gate.

CLI and MCP use the same descriptor eligibility and bounded projection. MCP
also dispatches eligible failed runs with a null action, retaining exact
revisions, compatibility checks, durable intents and receipts, idempotent
retries, detached ownership, and wait-only cancellation. Private journal
history and provider diagnostics never enter that projection.

## Writable result recovery

Pipeline state version 38 adds nullable `writableResult`. The explicit version-37
migration initializes it to `null`, preserving valid historical diagnostics,
terminal outcomes, accepted commits, counters and consumed effects. It does not
infer recovery authority for a historical rejected response. Unsupported forward
versions remain rejected; the legacy version-27 repair is unchanged.

Before an implementation or finding-resolution invocation, Runner journals the
original phase, step, content/result baseline, rework facts, validated blocker
ownership and dispute restrictions, fix accounting, and a binding to the frozen
plan, inventories, implementation evidence and earlier accepted work. It publishes
`invoking` with the active turn. After the provider finishes, one transition binds the safely
reconciled candidate, invalidates dependent approvals and charges changed rework
or resolution once. Existing blocker records remain authoritative; failed
finalization evidence is retained as a blocker, never an approval. No rejected
response is stored. Custom criterion data is normalized separately and adopted
only with a valid status result and original gate transition.

A still-prepared reservation with no published active turn proves invocation
never began. After unchanged-input, content and authority checks, resume uses
that same original reservation without consuming result-correction allowance.
Once invocation is published, recovery cannot infer that native work was absent
and uses read-only restatement. Legacy interrupted writable turns retain their
existing continuation contract: persist the safely reconciled baseline and any
pending fix charge before creating a new result checkpoint, keeping the original
step-start implementation evidence and blocker ownership unchanged.

Normalization failures and the established provider `structured-output` class
receive one automatically authorized read-only Worker result restatement, using
the recovery schema, inspected candidate and saved turn facts. Pending recovery
precedes ordinary dispatch, refinement and another writable turn. It never
replays implementation or resolution. The dedicated prompt prohibits repair,
validation execution and invented finding dispositions. Fresh reconstruction
uses no new source-session fork; lazy source-fork accounting remains consumed.
Inputs, native read-only policy, filesystem authority, original blockers,
initial implementation evidence, custom output/accepted-result bindings and
unchanged candidate fingerprints are rechecked. A valid completion enters the
original mode-required convergence route; no review, finalization, confirmation,
custom acceptance or commit gate is replaced by result correction.

Runner durably consumes the attempt before invoking it. Interruption during
reservation or invocation consumes that attempt, even without a response.
Reconciliation precedes retirement of interrupted original writable turns, and
lost acceptance responses preserve the published gate transition. Invalid or
lost correction results pause in `WAITING_FOR_USER` with
`writable_output_invalid`, the original resume phase and an allowlisted
role/phase/contract/field/constraint diagnostic. Decision and list indices are
bounded; unknown diagnostic identities become `result`/`semantic-contract`.
Rejected values, IDs, commands, exception messages, prompts, native output and
provider-private storage are never diagnostic sources.

An exhausted restatement publishes the exact
`writable-result:read-only:commit:<step>` checkpoint, bound to Worker, its
original `IMPLEMENT` or `RESOLVE_FINDINGS` resume phase and the consumed attempt.
Reconstruction retains that allowance consumption; it cannot reinterpret the
checkpoint as writable work or another step's retry.

`agent-run resume --run <run-id>` (MCP null-action resume at the inspected
revision) explicitly authorizes exactly one additional read-only restatement of
this same checkpoint. That authorization and consumption are persisted
separately from the single automatic allowance. A validated environment blocker
after correction, or after charged implementation rework, retains a read-only checkpoint
and requires explicit resume after resolving that blocker. A validated product
decision is journaled in the result checkpoint with its original clarification
hash and question number before transcript mutation. The clarification service
persists the exact resulting hash before replacement and reuses only that
verified append on reconstruction. Recovery settles this intent before ordinary
input inspection or role dispatch. Checkpoint retirement, decision counting,
the new transcript hash and pending editor authorization publish together with
the durable product-decision suspension; lost acknowledgements cannot replay
writable work or lose the question. Answers retain the existing
compatibility/replanning flow. Unsafe drift pauses without
adopting edits; read-only contamination requires an uncontaminated new run.
Publication failures preserve recovery authority. Resume and operator-stop
reconciliation preserve candidate bytes, prior accepted commits and receipts,
fix/dispute accounting and consumed effect authority; they never renew a budget,
transfer an approval, skip a blocker or duplicate a commit.

## Unfinished repair continuation

State version 45 upgrades existing result checkpoints to schema version 2 with
`repair: null`; legacy blocked/exhausted facts and allowances are unchanged.
Migration authorizes no repair. Only the read-only finding-recovery schema admits
`UNFINISHED`: empty decisions and inactive question/options/whyBlocked, bounded
reason and nonempty current-blocker evidence, and null customResult when present.
It establishes an observable still-required repair permitted by frozen authority,
never historical completion, FIX/DISPUTE, containment or validation credit.
Ordinary resolution and implementation reject it. Environment prerequisites and
proven unsatisfiable validation-policy stops retain their existing contracts;
missing provenance cannot justify an identical retry without a valid next step.

UNFINISHED preserves every original blocker and publishes `repair-required`.
`finding_repair_required` null-action resume authorizes one new finding-resolution
invocation, not replay or another restatement. Runner rechecks inputs/configuration,
content/controls, original finding ownership, validation and plan-kind/output
bindings and permissions after owner retirement/reconciliation. It journals
`repair-authorized` before reserving/invoking the new turn. Only a proven unstarted
reservation is reusable; published invocations recover read-only, including a lost
continuation result. Lost publication acknowledgement uses the durable checkpoint.
Consumed restatement attempts and additional allowances carry forward unchanged;
a new invocation grants no automatic restatement replenishment.

Bounded UNFINISHED work reports retain reason/evidence, predecessor references,
checkpoint/candidate/facts/blocker hashes, diagnostics and consumed accounting.
The journal retains each complete checkpoint. Reconstruction includes this history
without native sessions. A pending already charged correction continues once;
a new uncharged round still needs available fix budget. If unavailable, preserve
the continuation at `fix_limit_reached`; only the existing explicit
`extra-fix-rounds` grant authorizes it, rebinding that allowance without resetting
stagnation, disputes or any other budget. An exhausted read-only turn gains no
write permission without that grant. Repairs still return through independent
review or combined/lazy convergence and every original terminal/effect gate.
Polishing supports its own [unfinished finding repair](../../polishing/docs/review.md#unfinished-repair-continuation).
Replacement-proposal
pauses, clarification reconsideration retirement and stale polishing finalization
markers remain separate pending scope.

## Resume

`agent-run resume --run <run-id>` must reconstruct the workflow from persisted
state.

An ownerless persisted active turn or applicable stop is a continuation target
even though the run is not ordinarily resumable. CLI resume reconstructs it
with a null action. Exact-revision MCP `run_resume` does the same with its own
idempotency intent; for a stop, the original stop key is not required. MCP
rejects a non-null action, stale revision, live execution owner, or duplicate
ownership race. A stop recovery completes only after durable settlement, while
paused runs otherwise continue to use their descriptor-owned action validator
unchanged.

Before continuing:

1. resolve the run ID, load its state, and verify the canonical task path;
2. verify current hashes of `task.md`, `plan.md`, optional task `clarifications.md`, and `context.md`;
3. verify the execution clarification path, hash, and whether its current change was explicitly authorized;
4. verify project path;
5. verify current HEAD;
6. verify current working-tree content/state against persisted expectations.

Reject a persisted resume target unless the exact pause reason permits it and
the suspended pipeline state is valid for that target in the current preflight
phase.

If task inputs changed while paused:

```text
WAITING_FOR_USER
reason: task_input_changed
```

If repository state changed externally and deterministic reconciliation is unsafe:

```text
WAITING_FOR_USER
reason: unsafe_git_state
```

Do not assume a native agent session survived.

Native Codex/Claude resume may be used as an optimization only.

---

### Action-free ownership recovery

A provider turn that returns `ERR_EXECUTION_PROCESS_UNVERIFIABLE` or
`ERR_EXECUTION_PROCESS_ACTIVE` retains its active-turn marker and checkpoint.
Do not reconcile or accept its output while process ownership is unresolved,
or turn that action-free failure into terminal `internal_failure`. Shared runner
resume proves process retirement under exclusive run/worktree ownership before
the ordinary interrupted-turn input and Git reconciliation. Finalization then
repeats at its saved checkpoint with fresh evidence. Begun commit effects
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

An exhausted read-only narrative review retains its `plan-context` checkpoint.
Resume reconstructs the unaccepted producing result read-only and reviews it
again under the same recovery allowance; no provider result is retained merely
to reconstruct that turn. Prerequisite reconstruction and narrative review
share one reserved recovery attempt only for the immediate transition from a
successful prerequisite to its review. Failed prerequisite or review retries
reserve the normal bounded allowance. The prerequisite response does not clear
the consumed allowance; only a returned narrative-review response with matching
repository reconciliation clears it.

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

At `COMMIT`, a validated not-started executor proof is persisted as
`preEffectRejection.outputExhaustion: { disposition: "output_exhausted",
commitExecutor: "not_started" }` with the fixed code before Git verification.
Only unchanged verification proving no commit retires that authorization and
exposes explicit retry at `commit:<step>`. Interruption retains both authorization
and proof for verification-only recovery. Without proof, the consumed authorization
survives the exhaustion pause and resume performs verification only. A completed
valid commit settles normally; contract violations retain their blocking policy.

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
