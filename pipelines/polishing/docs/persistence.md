# Polishing Persistence And Resume

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Persistence And Resume

Each structured role result permits exactly 2 MiB (2,097,152 bytes) of
serialized UTF-8 JSON; one-byte overflow is rejected. This is byte headroom,
not a token budget. Semantic text, item, path, inventory, dispute, and correction
bounds remain unchanged. New size diagnostics use `maximum-2-mebibytes` while
historical `maximum-256-kibibytes` records remain valid. Rejected output is never
retained. The root owns larger state/recovery containers and complete segmented
journal recovery; see [the enclosing budgets](../../../docs/ARCHITECTURE.md#structured-result-headroom).

State lives outside both the target repository and task directory under the
common external run store. Pipeline state includes resolved settings, baseline,
input hashes, clarification status, backend versions, bootstrap summaries,
findings, disputes, arbitration, budgets, fingerprints, overrides, and pause
details, including distinct candidate and terminal review records and
fingerprints, candidate and terminal correction markers, the resolved mode,
one-time lazy source-fork marker, candidate lazy-correction ledger, and the
configured finalization policy, selected path or fallback, selected-file
fingerprint, and complete decision fingerprint. The
common versioned envelope also records an
explicit runtime
compatibility tuple maintained independently from the package version and, in
version 3, nullable bounded active provider role and phase. Version-1 and
version-2 envelopes project null activity without rewriting until the next
mutating continuation persists the explicit runtime migration.

Persist concise structured decisions and public summaries, never raw model
transcripts, chain-of-thought, credentials, or unhashed remote and identity
values.
Terminal failures may retain only the root-normalized finite adapter diagnostic
class, which the descriptor renders as a deterministic CLI/MCP explanation.

The descriptor projects each pause through one bounded public contract shared
by CLI status, MCP status, and MCP wait. It contains the finite reason, optional
validated bounded diagnostic code, concise explanation, bounded evidence,
validated resume checkpoint, and only applicable next actions. Prompts,
transcripts, credentials, native responses, raw standard error, rejected
values, internal diagnostics, pause-only paths, and counters remain private;
identified questions stay in the root pending-input projection. Input response,
safe null retry, one concrete valid extra-fix round, and exact finding overrides
continue to use the existing resume validation. A read-only repository mutation
instead instructs the user to abandon the contaminated run and start fresh from
an uncontaminated worktree. That `read_only_agent_mutated_repository` pause
retains the Git-classified changed snapshot domains as `snapshotChanges` and its
activity and single evidence line name them, for example `Changed snapshot
domains: untracked-content.`; legacy, unclassified, or unknown labels report
`unavailable`. The pause keeps existing pipeline state, including persisted
finalization evidence, and grants no approval, staging, or resume.
`environment_blocked` retains why nondelegated work
or finalization is blocked and the precise `POLISH`, `REVIEW`, `FINALIZE`, `CHECK_AND_FIX`, or
`RESOLVE_FINDINGS` retry checkpoint. `resolution_output_invalid` exposes its
bounded field-and-constraint evidence, `RESOLVE_FINDINGS`, and only the null
retry; a blocked finding-resolution restatement offers only the same retry.
`finding_repair_required` explains and offers one new repair invocation.
If the [unfinished repair](review.md#unfinished-repair-continuation) needs an
uncharged round at `fix_limit_reached`, the only action is the eligible explicit
fix-budget grant.
This read-only projection does not itself change the pipeline state version.
The runner-owned handoff is represented by pipeline state version 5.
Missing, invalid, or changed frozen guidance exposes only a `start-new-run`
action with the `resolved-finalization-guidance` requirement; it is not an
environment-recovery retry.
Bootstrap capacity exhaustion instead has no retry action: its bounded public
diagnostic identifies the producing role, full inventory field, and 256-item
limit so the validation surface or Runner capacity can be addressed before a
new run.

CLI status and MCP status, wait, and activity also expose the persisted resolved
mode. `pipelines_list` exposes descriptor-owned values, default, and
recommendation. None of these projections exposes inactive role configuration
or provider-private data.

Each transition is a complete write-ahead event appended and synchronized
before atomic state replacement. `progress.md` is derived public activity.
Immediately before every Worker, Reviewer, or Arbiter provider call, the root
persists a complete `turn-started` transition. It clears the active turn only
after the pipeline reconciles read-only guards or safely snapshots and persists
writable workspace effects. If the process stops first, MCP status and timed-out
wait combine the retained role/phase with the absence of a live execution owner
to report `interrupted`, even before stale lease recovery; a live detached owner
reports `running`, and no owner or retained
turn reports `idle`. Same-host reads check owner process liveness immediately
without changing acquisition or stale-recovery thresholds. Resume reconstructs
the request from durable state and does not require polling, a heartbeat,
daemon, or surviving native session.
Mutating run/resume operations acquire the per-run execution lease first and an
external lease keyed by the canonical Git worktree second, then release them in
reverse order. Separate run IDs therefore cannot mutate one worktree
concurrently. Both leases use owner-checked release and permit stale recovery
only after the age threshold when the recorded same-host process is
demonstrably dead. Status reads acquire neither lease and remain lock-free.
Recovery accepts only an incomplete final journal fragment, advances lagging
state from complete events, and never depends on a native Codex or Claude
session surviving interruption.

Candidate `REVIEW`, lazy `CHECK_AND_FIX` and `CLEAN_CONFIRM`, terminal `CONFIRM`,
and `HANDOFF` are durable checkpoints. Their turn-start or effect-intent events
precede invocation, and accepted content, findings, fingerprints, round
accounting, and confirmation are persisted atomically before advancement.
Resume reconstructs an unfinished turn exactly once, reconciles a writable
partial change before returning through `REVIEW` or `CHECK_AND_FIX`, rejects any
mutation from read-only confirmation, and continues from an already advanced
checkpoint without replaying finalization, confirmation, staging, or round
accounting. The one-time fork marker is persisted before the first lazy source
fork, so reconstructed sessions never
fork the source again.

An exact-revision MCP continuation may resume a nonterminal, nonpaused
persisted active turn with a null action only when no live execution owner
remains; ordinary paused-run action validation is unchanged. Before replay,
resume revalidates the canonical project and task paths and every task, context,
task-clarification, and execution-clarification hash. The root Git boundary
requires an unchanged workspace and index for read-only phases. For an interrupted
Worker phase that had workspace-write authority, it may instead preserve
content drift, but any index drift is rejected after proving that `HEAD`,
branch/detached state,
refs, remotes, Git identity, canonical root, and allowed runner paths did not
change. The pipeline then advances its baseline, invalidates stale
fingerprint-bound candidate, finalization, and terminal evidence, and counts
interrupted correction content once. The reconstructed turn uses its complete
request in a fresh native session; the new `turn-started` event replaces the stale marker,
which clears only after normal workspace reconciliation. If correction
reconciliation already advanced the state to `REVIEW` or `CHECK_AND_FIX`,
resume instead clears the retained `worker`/`resolve-findings` marker after the
same safety checks and continues from candidate convergence without replaying
or recounting the correction.

Claude read-only recovery uses the common run envelope. A valid but otherwise
unclassified read-only result or process failure
may pause only after the read-only mutation guard succeeds. Resume rebuilds the
complete role request from the persisted inputs and checkpoint. No denied tool
input, native provider text, raw standard error, or new recovery field is
persisted. Writable usage/provider recovery first preserves safe content and
invalidates stale fingerprint-bound evidence; ambiguous writable failures fail
closed.

The descriptor owns one explicit ordered migration for every supported prior
pipeline state version. Lock-free status may project a compatible migration in
memory, but only a mutating continuation may persist it. Before workflow
execution the root evaluates the complete chain, validates the current
pipeline shape, and appends one atomic migration event under the per-run lease.
Unsupported forward versions, missing migrations, and incompatible runtime
tuples return a specific actionable version-skew error; invalid migration
output returns a specific migration failure. Neither changes the durable run.

Pipeline state version 2 adds the required-check and validation-infrastructure
evidence. Its version-1 migration preserves safe workspace content, invalidates
active aggregate finalization and review evidence, and marks paused legacy
evidence provisional. Before retry, override, finalization, or review advances,
fresh independent Worker and Reviewer checkpoints re-establish the inventory
and the runner fingerprints it again. Completed active work returns through
`FINALIZE`; immutable failed history is upgraded without replaying an effect.

Pipeline state version 3 adds the resolved trusted-validation snapshot and
executor provenance to every accepted per-check result. Its version-2 migration
selects empty legacy trust, preserves safe workspace content, and invalidates
active finalization and review evidence through the existing independent
validation-migration checkpoint before advancement. Paused legacy evidence
remains provisional until that checkpoint runs. Retained `BLOCKED` and
`NOT_RUN` entries in paused or immutable failed evidence become `FAIL` without
losing their bounded diagnostics. Immutable `DONE` and `FAILED` evidence is
shape-upgraded without replaying workspace work.

Pipeline state version 4 adds the bounded bootstrap-correction ledger and
pending diagnostic. Its version-3 migration initializes them empty without
changing accepted context, validation evidence, workspace content, or workflow
position. A correction is unique by producing role, bootstrap or
validation-migration phase, and contract; only its attempt and finite
field/constraint diagnostic are durable. Resume reconstructs a pending
read-only correction, acceptance clears it, and a repeated invalid result is
terminal. When validation migration requires arbitration, its accepted bounded
disagreement is persisted before the Arbiter turn, resumed directly after an
interruption, and cleared atomically with successful migration completion.
A catalog retry resumes the saved validation-migration role and workflow phase
with the same disagreement and correction allowance. Resume acceptance
retains this binding through owner loss before dispatch.

Pipeline state version 5 adds the durable `HANDOFF` boundary and makes every
ordinary polishing Worker turn content-only. Its version-4 migration preserves
immutable `DONE` and `FAILED` history and preflight-only state, clears unfinished
bootstrap evidence, and sends applicable prepared nonterminal runs through
fresh independent staging-free validation before advancement. Paused legacy
gate evidence remains provisional until resume invalidates it through that
checkpoint. A version-5 `HANDOFF` resume lets the Git boundary accept a proven
complete effect, retry an unchanged pre-effect state, or fail closed; it never
replays an ambiguous partial effect.

Pipeline state version 6 makes every accepted validation inventory
staging-independent while preserving `HANDOFF` as the sole Git-index owner. Its
version-5 migration shape-upgrades `CLARIFY`, incomplete preflight, `DONE`, and
`FAILED` without role work; clears incompatible partial bootstrap evidence;
and routes other prepared nonterminal work through fresh independent inventory
discovery before finalization can advance. Safe content, frozen inputs,
counters, Git controls, and trusted-validation state remain unchanged. A legacy
`HANDOFF` is inspected before any role turn: a complete verified effect enters
`DONE`, an untouched pre-effect state invalidates stale gate evidence and enters
discovery without staging, and any incomplete or contaminated index fails
closed.

Pipeline state version 7 adds a nullable consumed finalization correction and a
matching nullable pending marker scoped to the current content fingerprint.
The version-6 migration initializes both to `null` without changing safe
content, workflow position, validation evidence, counters, or handoff state. A
record contains only attempt `1`, resolved-or-fallback guidance scope, the
content fingerprint, and the bounded Worker/finalization contract field and
constraint diagnostic. It never contains rejected values, commands, paths,
prompts, provider text, transcripts, credentials, or raw structured output.
The pending marker is cleared only after a valid replacement; the consumed
record remains applicable while the fingerprint is unchanged so a later
invalid finalization result fails closed. A content change clears both records,
and completed `HANDOFF` clears the exhausted scope.

Pipeline state version 8 adds the resolved mode, the fingerprint accepted by
lazy clean confirmation, and the one-time lazy source-fork marker. Its
version-7 migration selects `independent` and initializes the new fields
without moving an active or terminal workflow position, changing safe workspace
content, or replaying a pending or completed `HANDOFF`. Every earlier supported
version reaches the same independent default through the ordered chain; no
migration replays role turns or repository effects.

Pipeline state version 9 adds the bounded lazy-correction ledger and nullable
pending marker scoped to phase, finalized content fingerprint, and
validation-infrastructure fingerprint. Its version-8 migration initializes the
ledger empty and the marker to `null` without moving active, paused, `HANDOFF`,
`DONE`, or `FAILED` workflows, changing safe workspace content, or replaying
role, finalization, or handoff effects. Pending writable reconciliation remains
subject to the ordinary Git controls and exact-once fix accounting; a migrated
`HANDOFF` is never routed back through a role checkpoint.

Pipeline state version 10 separates semantic candidate convergence from the
terminal gate. It adds `CONFIRM`, distinct candidate and terminal review
results and fingerprints, and independent bounded correction records for
candidate Reviewer and terminal-confirmation output. The version-9 migration
preserves safe content, inputs, counters, and control fingerprints; invalidates
unprovable active finalization and review evidence; and routes active work to
`REVIEW` or `CHECK_AND_FIX`. Paused work records that the same repair must occur
on safe resume. Existing `HANDOFF`, `DONE`, and `FAILED` gates are shape-upgraded
without replaying role turns, finalization, staging, or a completed handoff.

Pipeline state version 11 adds the bounded `finalizationRecovery` record described
in [review recovery](review.md). The version-10 migration initializes empty recovery metadata without
moving active or terminal checkpoints, changing mode or counters, inferring
missing rejection output, or replaying role turns or pending/completed handoff
effects. Recovery-state validation rejects unknown fields, inconsistent attempt
allowances and pending markers, malformed feedback, and retained finalization
or confirmation evidence while replacement finalization is required.

Pipeline state version 12 expands inventory capacities to 256 per role and 512
for aggregate, persisted, finalization, and fingerprint evidence. Its leased
version-11 migration preserves legacy 64/128 inventories, counters, terminal
history, and pending or completed handoff effects without replaying role work
or reloading configuration. Per-item, structured-output, and durable byte limits
were unchanged by that migration; count-valid output can still exceed the
structured-result byte ceiling.
Expanded schemas retain strict Claude preflight and existing sandbox restrictions,
without enabling `allowAllUnixSockets: true` or broader host access.

Pipeline state version 20 adds the nullable `resolutionCorrection` checkpoint
of finding-resolution result recovery. The version-19 migration only
initializes it to `null`; it never moves a workflow, changes counters, revives
`DONE` or `FAILED` runs, or infers a historical rejection. Legacy interrupted
resolution turns without a checkpoint keep their existing continuation and
operator-stop contracts. Validation requires independent or combined mode, a
`RESOLVE_FINDINGS`, `WAITING_FOR_USER`, `FAILED`, or `CANCELED` position,
blockers equal to the current findings or failed finalization, fix rounds equal
to the pre-turn count plus the single charge, consistent stage and attempt
arithmetic, a binding equal to the persisted baseline, matching pauses, and
allowlisted diagnostics; unknown diagnostics reduce to
`result`/`semantic-contract`.

Pipeline state version 25 upgrades version-24 resolution checkpoints to schema 2
with a null repair predecessor and a current facts binding. Blocked/exhausted
positions, original blockers, consumption and accounting remain unchanged; migration
grants no repair authorization, infers no historical disposition and replays no effect.
New read-only restatement starts record the preceding revision on that same
checkpoint. Older checkpoints can omit it. An availability schedule or
watchdog expiry must follow that revision and match the checkpoint's content
and provider binding to authorize another invocation, live or after restart.
For a legacy checkpoint without the marker, the certified journal must show
the matching restatement start with no later invocation. Compare schema-1
corrections using the version-24 migration and each event's saved facts so a
simultaneous envelope and pipeline migration preserves valid evidence. Backoff
also requires retirement before scheduling and keeps the saved attempt and
deadline. A watchdog expiry requires the matching active provider attempt at
the expiry event and keeps the existing reconstruction allowance on cold
resume and operator-stop settlement.
If Runner journals a reconstruction for that expiry before losing its owner,
recovery uses the saved authorization only until the bound read-only turn starts.

MCP uses the common STDIO tools, persists idempotency intents before mutation
and receipts before returning, and launches detached continuation under the
same lease rules. A worktree conflict leaves the durable run and incomplete
intent available for an exact retry instead of launching a conflicting child.
After spawn, the receipt remains incomplete until the run advances or that
child owns the worktree, so losing a concurrent acquisition race remains
retryable. A correlated child exit acknowledgement makes this deterministic
when the winning lease is released between MCP polls. A disconnected client
cannot create a second workflow owner. The dispatcher passes its runtime tuple
to the detached child, which rejects a mismatch before taking the run lease.
Its distinct skew exit becomes an actionable restart-and-retry error while the
incomplete idempotency intent and run remain durable.
Its additive start fields leave `sourceSession` unset until the user
deliberately selects a fork; native IDs remain opaque and an unknown source
profile permits only `current` inheritance.
`run_start.mode` has the same precedence as CLI `--mode`. MCP guidance
recommends `independent` for genuine semantic independence, discloses its higher
context/token cost, identifies `lazy` as an opt-in lower-consumption choice
without independent review, and prohibits automatic lazy selection. Registry,
status, wait, and activity projections expose descriptor metadata or the
resolved mode without inactive role or provider-private values.

On resume, verify the canonical paths, task hashes, accepted clarification hash,
repository baseline, `HEAD`, refs, remotes, identity, and current content.
Unsafe or ambiguous reconciliation pauses rather than discarding user work.
