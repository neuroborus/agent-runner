# CLI recovery

Read this topic when inspecting run state or status, or when resuming, pausing,
cancelling or recovering a run from the command line. The [CLI reference](cli.md)
owns starting and configuring runs. Use the [user documentation map](README.md)
for other topics.

Runner state uses `$XDG_STATE_HOME/agent-runner/` with
`~/.local/state/agent-runner/` as the fallback. Every run records its pipeline
ID, pipeline state-schema version, and an explicit runtime compatibility tuple
independent from the package version. Compatible legacy state is migrated by
the owning pipeline under the per-run lease; incompatible readers return a
specific version-skew error while preserving the run. Common envelope version 8
persists active-role effort; legacy missing values migrate to `current` without
provider activity or changes to saved progress and session evidence. Version 11
adds the supervisor's boot/start launch cutoff for durable shared-host recovery.
Versions 12 and 14 added ancestry and control-group proof fields. Historical
values remain strictly validated, but recovery uses positive ownership with or
without those proofs. New launches store null values for both obsolete fields;
required supervisor identity and namespace evidence remain unchanged.
Version 20 separates generic reconstruction provenance from proven inactivity
expiry. Legacy markers grant no timeout proof or additional recovery allowance;
CLI/MCP expose `expiryProven` alongside recovery status.
Version 17 adds the frozen provider inactivity timeout, its fingerprint, and a
nullable durable recovery allowance. Legacy runs use 30 minutes without
configuration reload. Version 15 adds frozen availability policy and nullable retry episodes, with
default-only legacy migration that preserves saved workflow and session evidence.
Historical mode-aware compatibility generations include plan-authoring version 5,
plan-execution version 35 and polishing version 16. These are historical migration
steps, not the current descriptor or package versions; the pipeline descriptors
and root [`agentRunnerCompatibility`](../../package.json) declaration own current
versions. Existing execution runs retain explicit commit semantics and a null
custom-result ledger; that historical execution version added custom-result data
without granting legacy custom authority. Ordered migrations resolve missing
legacy modes to `independent` and preserve explicitly saved modes without moving
terminal workflows or replaying role turns, commits or handoffs. Complete write-ahead events precede atomic state
replacement; recovery repairs a lagging state file and derived progress.
Mutating runs require one per-run execution lease. Plan execution and polishing
also serialize ownership with an external lease keyed by the canonical Git
worktree, granting mutation ownership to one run ID at a time. Both leases
support safe same-host stale recovery;
status and bounded public activity reads remain lock-free. `run` and `resume`
print concise labeled activity as it is persisted; `status` prints the resolved
mode, current state, pause, artifact paths, findings, fingerprints, commit SHAs,
and a bounded public activity summary.

## State and status

Status also shows the latest observed attempt's role, exact checkpoint, outcome,
accounting completeness, native turns, command completions, and compactions.
UTF-8 byte measurements for the supplied prompt, reconstruction prompt, schema,
output, and structured-result JSON stay separate from provider token snapshots.
Prompt bytes include directly supplied text; referenced-file contents and reads
remain unknown. These measurements exclude native wrappers and existing session
context and do not establish an output limit or a byte-to-token conversion.
Failed or interrupted results and unavailable usage remain unknown or incomplete.
No prompt, reasoning, transcript, tool output, secret, native identifier, or
arbitrary provider error is retained in these diagnostics.

## Output exhaustion

Codex response incompleteness with the recognized native `max_output_tokens`
reason pauses as `output_exhausted` after repository reconciliation, retaining
the suspended role/checkpoint, safe partial progress, and correction accounting.
Use the offered explicit resume or start a new run with smaller work units if
exhaustion repeats. Consumed commit effects recover through verification only;
replacing an unused authorization requires validated not-started proof and Git
verification. It triggers no automatic
fresh replay, availability or quota recovery, or output correction. That reason
alone establishes neither a numeric output ceiling nor context utilization.
See the provider model (`docs/product/PROVIDER_MODEL.md#normalized-failures-and-recovery`)
for the recognition and safety boundaries.

## Model catalog pauses

A [model catalog pause](provider-recovery.md#model-catalog-misses) shows
`ERR_MODEL_CATALOG_RETRY` with reason `backend_unavailable`, or
`provider_interrupted` for init, plus the saved resume state and any offered
action. When status offers the null resume action, run
`agent-run resume --run <run-id>` after the model is available again; the run
retries the frozen selection at its saved checkpoint. A legacy plan execution
validation-migration Arbiter pause without its saved disagreement keeps the
code but shows no resume state and rejects resume; start a new run. A plan
execution `commit_failed` pause recorded for a catalog miss without journaled
pre-executor proof, including one from an older run, offers no fresh COMMIT
authorization in status, resume validation or workflow dispatch. When no
authorization remains, it shows no resume state. When a consumed authorization
survives, resume only verifies whether its commit occurred and cannot renew it.

## Audit reconstruction

For audit, explicit resume reconstructs the same suspended checkpoint in fresh
native context, retiring the exhausted child without another source fork.
Acknowledged replacements can continue after response loss. Frozen scope,
accepted receipts, pending versions and dispositions, correction feedback and
both finite budgets survive; replacement cannot establish clean coverage or
confirm findings. Discovery may finish one coherent usable batch, and each exact
batch still requires the complete selected verification gate before more discovery.

## Bootstrap recovery

Execution bootstrap separates repository discovery from bounded contiguous
applicability units. Restart preserves accepted work; only unfinished units may
subdivide on recognized output exhaustion, without renewing correction budgets.
Combined execution requires complete independent Worker and Reviewer inventories
before writable work. Keep every journal segment and use the offered resume
action; never edit durable evidence or repeat a consumed commit effect.

The [operator verification record](../OPERATOR_GUIDE.md#output-budget-verification-record)
separates historical per-commit checks, supplied bytes, public usage, commands,
compactions, and missing observations. The five earlier native cases prove
compatibility and one-step discovery. A subsequent operator-supervised diagnostic
using accepted8 (`c0d6d7b0`), fresh independent Worker and Reviewer roles,
gpt-6.1-sol/xhigh, and combined mode completed production discovery, semantic
position confirmation, all ten applicability units, normalization, and full READY
assembly for each role across forty canonical steps. Earlier nested App Server
startup failures remain environment-specific evidence; earlier host discovery
timeouts remain incomplete attempts. This diagnostic supplies no current
execution approval, causal speedup, effective native output ceiling, or
byte-to-token conversion.
Codex 0.163.0's generated `turn/start` contract exposes no numeric
`max_output_tokens` control; two MiB is serialized-result headroom.
Native model tests remain opt-in. The later deferred launch requires the verified
corrected implementation loaded in a fresh runtime and a new combined run;
existing frozen runtimes and old approvals cannot supply that acceptance.

## Action-free recovery

An action-free resume also recovers a nonterminal, nonpaused persisted active
turn after its execution owner is lost. Recovery retains the active marker
through input and repository reconciliation, replaces it when the complete
request restarts, and clears it only after normal post-turn reconciliation. If
correction reconciliation advanced the checkpoint before the marker could be
cleared, resume clears that completed marker after the same safety checks and
continues from the advanced checkpoint without replaying the correction.
Lazy check/fix and clean-confirm checkpoints persist their intent, accepted
fingerprint, and round accounting so resume reconciles partial writable content
or read-only mutation without replaying an accepted effect or counting a round
twice. The one-time source-fork marker prevents reconstruction from forking the
source again.

## Legacy confirmation recovery

Legacy plan-execution failures at terminal `CONFIRM` can also offer action-free
resume in either mode. Status shows that action only when the durable journal
proves candidate acceptance, passing finalization, and the exact opaque
`ERR_CODEX_TURN_FAILED` / `turn_other` failure. Run
`agent-run resume --run <run-id>`, or submit MCP `run_resume` with the current
revision, a null action, and an idempotency key. Recovery revalidates inputs,
Git safety, content, infrastructure, and retained check evidence before
confirmation; it preserves completed commits and counters and replays no
implementation, finalization, or consumed commit effect. A proven
`pendingCorrection: true` accounting marker is retained. Missing or inconsistent
history, migration-only acceptance, and genuinely pending work fail closed.
This compatibility exception remains limited to historical `turn_other`;
historical `turn_server_overloaded` failures remain immutable `FAILED` runs and
are not reopened by migration.
See the [operator guide](../OPERATOR_GUIDE.md) for recovery boundaries.

## Resume actions

Plan execution and polishing accept one applicable resume action at a time:

```bash
agent-run resume --run <run-id> --extra-fix-rounds 3
agent-run resume --run <run-id> --override-finding R7
```

## Pause and cancel

An operator can also request a durable pause or terminal cancellation. The
short CLI form reads the run once, binds that revision to a fresh idempotency
key, and submits the request:

```bash
agent-run pause --run <run-id>
agent-run cancel --run <run-id>
```

Timing defaults to `immediate`. To let the selected execution step finish:

```bash
agent-run pause --run <run-id> --timing after-current-commit
agent-run cancel --run <run-id> --timing after-current-commit
```

This timing also accepts suspended execution steps, but rejects clarification,
bootstrap, missing steps, authoring, and polishing. The stop settles at the
verified commit before the next step, or at the reconciled checkpoint if the
step pauses, fails, or is interrupted; it never does extra work to obtain a
commit. A final-step pause resumes through `DONE` without agent work; cancel
retains completed commits in terminal `CANCELED`. Status shows requested and
effective timing, target step, and settlement. See
[operator guidance](../OPERATOR_GUIDE.md) for recovery semantics.

## Stop and lease recovery

If CLI status shows `Stop state: applicable`,
`agent-run resume --run <run-id>` is a safe action-free recovery attempt: lease
enforcement rejects a live execution owner. MCP `run_status` identifies the
ownerless case when `stop.state` is `applicable` and `execution.state` is not
`running`; `execution.leaseOwner` distinguishes live, dead, replaced, and
unverifiable lease evidence, while `execution.processRecord` reports retained
durable process ownership without exposing its identity. Recover it through
`run_resume` through [MCP supervision](mcp-supervision.md). Neither path
requires the original pause or cancel idempotency key. Initial plan-execution
`CLARIFY` stops that have no preflight, repository/artifact checkpoint, active
turn, process, or resource settle under the run lease without waiting for a
canonical-worktree lease owned by another run. Every later or otherwise
non-quiescent checkpoint still requires normal worktree exclusion and effect
reconciliation. A lease-conflict diagnostic names the recorded owner run
separately from the ownerless pending run. Never manually delete, rewrite, or
bypass lease records; recover the recorded owner or retry the offered action
after normal release or state-owned reclamation.
Recovery reuses a same-run worktree lease already held by the runner. After
owner loss it may immediately reclaim a current same-host execution or worktree
lease only when the recorded boot/PID/start identity proves the exact owner dead
or replaced; acquisition age is not a delay or proof. Legacy, identity-free,
foreign-host, live, invalid, and unverifiable lease records remain blocking.
The runner clears a process record only after validating the recorded supervisor
identity and namespace, proving its death, and completing bounded discovery
without surviving positively associated descendants. Both live supervision and
recovery associate processes through owned-session membership, a matching launch
token, or observed owned ancestry. They follow available parent links through
inaccessible environments and retain observed association through later evidence
loss. Unassociated processes neither block progress nor receive signals because
metadata is unreadable, a session is newer, or a cgroup is shared. Historical
ancestry and control-group proofs are optional and confer no exclusion authority.
Shared-host discovery cannot prove absence against arbitrary same-user processes
hiding all ancestry and token evidence. Private PID namespaces retain their
kernel-enforced containment guarantee. Live, replaced or unverifiable recorded
owners, namespace mismatches, uncertain known descendants and inspection-budget
exhaustion remain blocking. Recovery never signals a persisted host PID.

## Repeatable automation

For repeatable automation, supply both captured values explicitly. Retry an
uncertain request with exactly the same revision, key, and timing; never refresh a stale
request silently:

```bash
agent-run pause --run <run-id> --expected-revision 42 --idempotency-key <key>
agent-run cancel --run <run-id> --expected-revision 42 --idempotency-key <key>
```

`run` and `resume` exit with status `2` when they return a persisted pause.
Accepted `pause` and `cancel` requests and readable `status` calls exit
successfully. Invalid input and startup or execution failures exit with status
`1`.

## Clarification resume

Resume after editing the reported clarification artifact or resolving a
reported retryable blocker. After clarification closes, only a
blocking material product decision may ask another question. An answer that
invalidates the validated plan or completed execution scope requires a revised
plan and a new execution run, preserving existing history.

### Plan authoring

Plan authoring keeps its independent Planner/Reviewer/Arbiter flow by default.
In lazy mode, the Planner drafts and performs state-held `CHECK_AND_FIX` rounds,
then separately confirms the exact draft read-only. Only an unchanged
structured `CLEAN` result can reach deterministic shared plan validation and
atomic `plan.md` writing; drafts never become repository writes or commits. An
invalid lazy checkpoint receives one fresh read-only correction with the same
schema and exact draft scope before an explicit retry is required.

### Plan execution

For every execution step, the Worker implements the change before candidate
convergence. Independent mode uses Reviewer passes; lazy mode alternates a
writable Worker `CHECK_AND_FIX` turn with a separate read-only candidate
`CLEAN_CONFIRM`. The stable candidate then runs the dedicated finalization gate
using the configured guidance policy and one distinct read-only terminal
confirmation over the resulting content and validation fingerprints. Content
findings return through candidate convergence. Terminal rejection of validation
evidence invalidates finalization immediately; pure evidence findings rerun
complete finalization directly without code fixing. Mixed findings resolve
content first, then require replacement finalization. Two automatic semantic
retries per step are durable across interruption and provider unavailability;
exhaustion pauses as `finalization_evidence_rejected` at `FINALIZE`, where an
explicit retry grants one additional attempt. Matching successful evidence from
ordinary non-rejection findings remains reusable for a fresh confirmation;
content or validation-infrastructure drift reruns the complete gate. Lazy
mode has no review dispute or Arbiter path. Remote state remains read-only.
If an unexpected runner-owned invariant rejects a finalization transition,
status retains a resumable `FINALIZE` checkpoint and exposes only a bounded
diagnostic through both the CLI and MCP.

When plan execution is environment-blocked in finding resolution solely by
opaque runner-trusted check failures, an explicit resume retries complete
finalization on the unchanged content. A repeated failure returns to resolution
and needs another explicit resume if blocked again. Mixed blockers retain their
ordinary resolution path; host check results never replace runner evidence.

### Polishing

Polishing follows the same mode-specific, fingerprint-bound ordering and
terminal evidence-rejection recovery, with two automatic semantic retries per
run. Pure evidence rejection preserves candidate acceptance; mixed findings
converge content before replacement finalization. Exhaustion exposes the same
explicit additional-attempt action, and recovery never grants an agent index
access or replays a completed handoff.
Independent candidate review, or lazy check/fix plus candidate clean
confirmation, converges before full finalization. Finalization may format the
accepted candidate; one distinct read-only Reviewer or Worker confirmation then
binds the resulting content and exact validation evidence before `HANDOFF`.
Confirmation findings return through candidate convergence; matching
successful finalization evidence is reused for a fresh confirmation, while a
content or validation-infrastructure change reruns the complete finalization
gate. Agent turns change content only; the runner then stages the complete
confirmed change set and leaves it uncommitted for a separate commit workflow.
Invalid lazy polishing checkpoints receive one fresh correction with the same
schema and exact content and validation-infrastructure scope. Check/fix
corrections remain content-writable and are reconciled and charged once;
clean-confirmation corrections remain read-only. A repeated invalid result
pauses at the persisted checkpoint for an explicit null retry without allowing
early handoff evidence.
Its dedicated `FINALIZE` turn runs the target project's complete validation
procedure, including required formatting or generated output, with configured
skill guidance when available. Its scope ends with fingerprint-bound validation
and review. Bootstrap, validation migration, and finalization translate
applicable tracked-content checks to `HEAD` or explicit trees and reject index
mutation, index-relative inspection, alternate-index workarounds, and commit
preparation. Staging and staged inspection in selected guidance are deferred to
the runner-owned handoff.

## Pipeline recovery

Read the [current contract](#cli-recovery).
