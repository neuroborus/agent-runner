# MCP supervision

Read this topic when waiting for, responding to, stopping or recovering a run
through MCP. The [MCP reference](mcp.md) owns server configuration and starting
runs. [CLI recovery](cli-recovery.md) owns shared state, lifecycle and recovery
procedures; use the [user documentation map](README.md) for other topics.

Call `run_wait` once for the desired interval. Its `timeoutMs` accepts up to 24
hours; configure the MCP client's tool timeout above the requested wait.
[Codex](https://developers.openai.com/codex/config-reference) currently defaults
`tool_timeout_sec` to 60 seconds, which is too short for long runs, so size the
[client setting](mcp.md#mcp) to the operator's longest expected wait. A client timeout or
cancelled wait affects the wait call while the pipeline continues. Recover with
`run_status` and another explicit wait. A wait also returns promptly with
`execution.state: "interrupted"` when the execution owner is positively
observed dead or replaced at a checkpoint requiring continuation, including
between turns with no execution records or revision change. Recover that run
with an explicit `run_resume` using `action: null`, the inspected revision,
and a new idempotency key. Use `run_activity` for deliberate inspection and
`run_wait` for long event-driven waits.

## Waits and observation recovery

Concurrent journal publication permits bounded, byte-proved activity rereads.
Cold reads and optional-cache overflow retain the original consumed-byte proof
through append or rotation; later valid history alone cannot certify it.
If publication exhausts that bound, `run_activity` and `run_wait` return a
structured tool error with `code: "ERR_RUN_OBSERVATION_BUSY"` and
`retryable: true`. A later explicit observation is safe; the run is unchanged.
Corruption or unavailable proof receives no such classification.

## Pending input and responses

MCP represents paused clarification and product decisions as structured
`pendingInput`. `run_respond` requires the request ID,
run revision, an answer for every identified question, and a new idempotency
key; optional proactive clarification accepts an empty answer array. The
controlling agent answers from explicit user context or asks the user. Answers
are appended verbatim to the durable clarification transcript before detached
execution continues. Editing the artifact and using `run_resume` remains
supported.

## Writable-result recovery

Execution also preserves candidate work after malformed implementation or
finding-resolution output. One automatic read-only result restatement precedes
`writable_output_invalid`; explicit resume of that same checkpoint authorizes
one additional read-only retry. It preserves earlier accepted work, blockers and
fix accounting and still requires every original review and commit/result gate.

Recovery-only `UNFINISHED` preserves the original blockers at
`finding_repair_required`: null-action resume authorizes one new repair invocation
against the verified candidate. If uncharged fix budget is unavailable, only the
existing explicit `extra-fix-rounds` action at `fix_limit_reached` authorizes it.
Consumed attempts, historical uncertainty and every original gate remain binding.
For the exact execution contract, open
`pipelines/plan-execution/docs/recovery.md` in the matching source checkout and
read **Writable result recovery**.

Polishing likewise preserves reconciled finding-resolution work after a
malformed or lost report in independent and combined modes. One automatic
read-only report restatement precedes `resolution_output_invalid`; explicit
resume of that checkpoint authorizes one additional read-only retry without
writable replay, additional fix budget or approval. Recovery-only UNFINISHED
instead pauses at `finding_repair_required` for one explicitly authorized new
repair, retaining original blockers, uncertainty and consumed accounting. An
uncharged exhausted round requires the eligible existing fix-budget grant.
See [recover a pause](../OPERATOR_GUIDE.md#5-recover-a-pause-without-taking-over-the-work)
for the operator procedure. For the exact polishing contract, open
`pipelines/polishing/docs/review.md` in the matching source checkout and read
**Finding-resolution result recovery**.

When status offers the null action, a
[model catalog pause](provider-recovery.md#model-catalog-misses) resumes
through `run_resume` with a null action, the current revision and an
idempotency key, at its saved checkpoint. MCP projects the same pause and
actions as [CLI recovery](cli-recovery.md#model-catalog-pauses): a plan
execution `commit_failed` catalog pause without journaled pre-executor proof
offers no fresh COMMIT authorization. It has no resume state when no
authorization remains; a retained consumed authorization resumes for
verification only.

## Action-free resume

Action-free recovery uses the same leased runner path through CLI and MCP.
CLI `resume --run <run-id> --expected-revision <revision>` can bind an inspected
revision explicitly. An action-free process-proof failure retains its checkpoint,
including `FINALIZE`, until retirement and repository reconciliation succeed.
MCP dispatch is bounded and event-driven; ownership contention or an incomplete
acknowledgement leaves a retryable intent. Retry the same idempotency key after
`ERR_MCP_ACTION_IN_PROGRESS` or `ERR_DETACHED_OWNERSHIP_PENDING`. Disconnecting
cancels only the client's wait; durable reconciliation and receipt completion
continue. Neither retained reservations nor unrelated revision changes prove
that a detached continuation started.

`run_resume` requires `expectedRevision` from the latest status or wait result,
a unique idempotency key, and only an action valid for the persisted pause. A
null action at the exact revision also recovers a nonterminal checkpoint with
no pause, or an applicable stop, when no execution owner is live. Stop recovery
uses a new `run_resume` key and does not require the original pause/cancel key;
stale revisions, non-null actions, live owners, and concurrent ownership races
are rejected.

## Pause and cancel

Use `run_pause` or `run_cancel` with `expectedRevision` from the inspected
status or wait result and a unique `idempotencyKey`. A pause preserves the
reconciled checkpoint for an action-free resume; cancellation reaches terminal
`CANCELED` and cannot be revived. Exact retries use the same arguments and key.
Older or conflicting requests fail instead of silently adopting a newer
revision. The optional `timing` field accepts `immediate` (the default) or
`after-current-commit` under the same execution-only rules as the CLI. Omitted
and explicit immediate timing identify the same request. An immediate cancel
can supersede a deferred pause; supersession cannot delay an earlier stop.
Receipts retain their acceptance timing and target even on later replay.
Status and waits retain `pendingStop` and add `stop`, which includes requested
and effective timing, target step, `state` (`pending`, `applicable`, or `settled`),
and nullable settlement (`quiescent` or `commit`, with the verified SHA).
Activity entries carry the stop summary at that event's revision. Waits treat
`CANCELED` as terminal and canceling a wait does not cancel the run.

## Durable intents and detached continuations

Mutating tools persist an action intent before mutation and a receipt before
returning. Exact retries return the original result, while reusing a key with
different arguments is rejected. Issue reporting uses that contract for its
single global document creation. Accepted stop requests notify the live execution
owner or start detached same-run reconciliation when ownership was lost. Runs
continue in detached local children, so MCP disconnects and wait cancellation
affect only the client call. Ordinary detached start or resume rejects active
canonical-worktree ownership before launch and withholds its receipt after
launch until journaled readiness binds that dispatch to process retirement and
checkpoint continuation under the required leases. Detached stop
reconciliation instead follows the exact launched child until the stop is
durably settled or that child exits; acquiring the run lease is not completion.
An exit before settlement leaves recovery retryable and preserves the applicable
stop. Losing a concurrent ownership race keeps the durable idempotency intent
available for an exact retry, including when the competing lease is released
before the next MCP observation because child exit is acknowledged directly.
Detached tool errors expose `dispatchFailure: { exitCode, signal }` and a
separate nullable `recoveryCause: { stage, code, explanation }`, together with
the dispatch error `code` and safe `message` in text JSON and structured content.
CLI resume uses the same fixed recovery explanations. Causes require exact
dispatch/child correlation; absent causes are explicitly unavailable. Unknown
exit facts stay null, including after restart, and a signal or exit does not
explain why recovery failed. These diagnostics contain no native output or
transcripts. Failed requests remain incomplete: address the reported blocker
and retry the identical key and arguments; retry alone promises no repair.
The MCP process freezes a detached-compatibility token over the root
detached protocol version, run-envelope tuple, and every sorted loaded pipeline
ID/state version. The child
independently recomputes it before acquiring the run lease, recovering state,
or migrating a run. Version skew leaves the durable run, journal, leases, and
incomplete intent unchanged and returns an actionable restart-and-retry error.
The existing execution leases, Git safety checks, local-only policy, and
one-shot commit authorization remain authoritative.

## Public projections

CLI output and MCP progress events label public activity by role. `run_status`,
`run_wait`, and `run_activity` expose the resolved mode; `pipelines_list`
projects descriptor-owned setting values, defaults, and recommendations.
`run_status` returns a concise current snapshot; `run_activity` returns bounded
history after a cursor and a next cursor. Use activity for explicit inspection
or recovery. `run_wait` can emit the same bounded events as progress
notifications while the model sleeps; live rendering depends on the MCP host.
Execution's `refinementProgress` includes the current derived plan view;
activity identifies that snapshot with `refinementProgressRevision`, independent
of its historical page cursor.
Public projections contain no inactive role configuration or provider-private
data. When present, `launchRecovery` is the same strict checkpoint/class value
shown by CLI status.
`run_status` and `run_wait` return `observations` with the latest 32 runner
attempts and `omittedAttempts`; legacy absence is `null`. Each attempt includes
its runner-owned ID, role, checkpoint, status, accounting, nullable measurements,
and bounded native observations with their original cumulative scope and token
inclusion rules. Earlier attempts can lack measurements. Snapshots are never
summed into consumption totals. `run_activity` and live progress include concise
observation events at attempt start, changed fallback batches, and settlement.
They do not grant progress, retry, or effect authority.

Failed/interrupted attempts also project nullable `ownershipDiagnostic` evidence:
a validated raising site, applicable supervisor branch, pre-cleanup flags and
bounded inspection sample. CLI status/direct failures and correlated recovery
errors expose the same evidence; unavailable legacy facts stay null. These facts
change no recovery, retry, acceptance or ownership authority. See
[start, clarify, and observe](../OPERATOR_GUIDE.md#4-start-clarify-and-observe)
for guidance on interpreting the evidence. In the matching source checkout,
open `docs/architecture/recovery/ownership-diagnostics.md` for the contract and
`docs/testing/native-acceptance.md` under **Ownership diagnostic acceptance**
for the separate operator procedure.
