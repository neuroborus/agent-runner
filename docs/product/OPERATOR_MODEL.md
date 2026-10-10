# Operator Model

Agent Runner is a local CLI with an asynchronous STDIO MCP boundary over the
same durable runner. Operators start a named pipeline, observe its run ID and
public activity, answer bounded pending input, and resume explicit pauses. The
product does not require a daemon or network service.

The shared [operator guide](../OPERATOR_GUIDE.md) owns the practical procedure
for preparing, supervising, recovering, and completing work through either
transport, including optional observation, reporting ongoing launches, and
recovery within Runner workflows.

## Configuration

`maxEventLogBytes` is a storage-only setting in root and safe project
configuration: numeric integers `1` through `2147483647` bytes, default
`536870912` (512 MiB), with project precedence. Unlike workflow selections,
current root capacity applies to subsequent appends. The originally selected
protected project overlay must remain unchanged and identity-verified; legacy
runs never discover an overlay. Saved roles, settings, commands, and inputs
remain frozen, with no CLI, MCP, or environment capacity override.

On `ERR_EVENT_LOG_LIMIT`, increase effective root capacity within the validated
range and resume the same run. An unchanged protected project override may be
superseded only by explicitly injected public `createRunStore` policy, composed
with `createRunner({ runStore })`; an injected callback supports same-Runner
increases. A replacement Runner cannot take over a live owner: restart requires
proof that the exact former owner is dead or replaced. Preserve all project
configuration, journal, state, lease, and resource records. If no permitted
increase exists, remain blocked. Lower policy does not make valid history
corrupt or prevent observation and leased recovery within the fixed read ceiling.

Runner-root configuration is the only source of trusted profile
implementations. Root and safe ignored project configuration may define exact
trusted command vectors. Catalogs merge root then project, deduplicate identical
same-name definitions, and reject conflicts even when unselected. The merged
catalog permits 256 definitions; each pipeline may select at most 32 root or
project aliases. Project configuration may also select role preferences,
pipeline settings, and an artifact root, but cannot add provider binaries,
credentials, environment values, or new host authority. CLI and MCP overrides
have the documented highest precedence.

Only runner-root configuration accepts `clientAttribution`, an exact
`{ name, title }` provider-visible identity. It defaults to
`agent_runner` / `Agent Runner`; project configuration, CLI, MCP, pipelines,
prompts, and repository content cannot override it. A custom value must be
supported by every active role provider before work begins. Each new run saves
the normalized value and fingerprint, resume never reloads it, and legacy runs
migrate to the generic default. Public status, activity, and diagnostics do not
expose the value.

The top-level `trustedCommandTimeoutMs` sets the per-command runner-trusted
execution deadline in milliseconds. It is a strict integer from `1` through
`2147483647`, defaults to `3600000` (60 minutes), and may be set in either
configuration layer; the project value wins over the root value. Unlike role
and pipeline selections, it has no CLI or MCP override. A new run saves the
resolved value in its fingerprinted trusted-validation snapshot, and resume
reuses it unchanged. This permits concurrent projects to use distinct deadlines
without shared service state. For example, `"trustedCommandTimeoutMs": 7200000`
selects two hours. Legacy snapshot versions use the one-hour fallback, while
capability preparation remains capped at 10 seconds.

Root and project configuration accept `providerInactivityTimeoutMs`, a strict
integer from 1 through 2147483647 milliseconds with a 30-minute default and
project precedence. The run freezes and fingerprints it; neither resume nor
legacy migration reloads configuration. There is no CLI or MCP override.
An inactive provider records bounded recovery activity before termination,
reconciles safe partial work, and may reconstruct the same role once without
reforking a source. Native fresh fallback shares that durable allowance. A
second expiry pauses as `backend_unavailable` / `ERR_PROVIDER_INACTIVE`.
Follow the offered resume action for one invocation without renewed automatic
retries. CLI and MCP show the role, checkpoint, attempt, and recovery status;
client disconnect does not affect execution. Owned local commands suspend the
deadline, while keepalives do not. See the [provider contract](PROVIDER_MODEL.md#provider-inactivity).

Root and project configuration also accept `availabilityRetryMaxDelayMs`, a
strict integer from `5000` through `2147483647` milliseconds with a `1800000`
(30-minute) default. The project value wins, without CLI/MCP or role overrides.
Each run freezes the ceiling with a five-second initial delay. Resume preserves
it, and legacy migration supplies the documented default with no pending retry.
All three pipelines retry eligible explicit provider availability failures after
repository reconciliation. Delays double to the ceiling and repeat there without
an attempt quota. A successful provider response resets the episode, even when
subsequent output validation rejects that response. A normalized authentication-
required response instead retires the superseded episode before its distinct
operator pause. CLI/MCP activity and
status expose the saved role, checkpoint, normalized reason, attempt, delay, and
deadline. Stops interrupt the wait under the same exclusive owner. Foreground
CLI owner loss needs resume; detached MCP work survives client wait cancellation,
timeout, and disconnect. Resuming an overdue deadline permits one attempt.

The separate `authentication_required` disposition never enters that retry
policy. After repository reconciliation, every pipeline pauses durably at its
exact logical checkpoint with the fixed `ERR_AUTHENTICATION_REQUIRED` code.
Any active availability episode superseded by that response is retired first.
CLI and MCP expose one redacted explanation and one null resume action. The
operator reauthenticates the selected provider and resumes the same run; saved
roles, session lineage, fingerprints, findings, and correction accounting are
preserved. A source fork is retried only with no-effect proof; possible-effect
evidence resumes the same logical role fresh without risking a duplicate native
child. Commit readiness still requires pre-effect proof and Git verification
before a consumed authorization is replaced.

Both configuration layers accept portable `defaultEffort` and role `effort`
values: `current`, `low`, `medium`, `high`, and `xhigh`. Effort stays separate
from model selection and follows shared execution-preference precedence through
CLI/MCP overrides. CLI `--effort` and MCP `run_start.effort` select run-wide
effort; `--<role>-effort` and `roleOverrides.<role>.effort` win for one role.
Start retries must retain both values under the same idempotency key; detached
execution reuses the saved selection. Inactive role vocabulary is validated
without
resolving or exposing those roles. Legacy runs receive `current` without
provider activity; public status and activity never expose saved role effort.

Resolved active roles, settings, artifact root, trusted commands, and optional
source-session lineage are frozen into a new run. Resume uses that snapshot and
does not silently adopt later configuration changes. `independent` is the
default mode; choosing `lazy` or `combined` is always an explicit
operator decision. Combined adds primary convergence before independent review.
All three descriptors expose these modes through CLI/MCP discovery. Resume preserves the saved mode, approvals, and budgets.

Plan execution and polishing save exact-command capability needs and blocker evidence from
bootstrap and legacy read-only discovery. If the runner cannot satisfy them, it
pauses as `environment_blocked` before writable work. Repairing storage,
isolation, or dependency availability permits retry of that saved request;
changing selection or declarations requires a new run. Availability is checked
again at every writable entry, even within one invocation. Agents cannot grant
capabilities by reporting a need. An agent's sandbox limitation for an exactly
delegated check is resolved only when runner inspection succeeds. Required checks
remain exclusive to finalization, and consumed commit and completed handoff verification precede new
preparation effects.

Plan execution and polishing each independently require a boolean
source-projection need in every capability report. A role may identify only the
frozen exact command; it cannot choose a path or broaden authority. Ordered
legacy migration defaults that need to false without adopting current
configuration or changing saved progress, review evidence, correction
accounting, or effect recovery.

A trusted command that must write beside its inputs may declare
`"sourceProjection": true` in its closed capabilities object. The runner then
runs it from a private writable materialization of the accepted source rather
than the checkout. The projection contains the frozen HEAD plus tracked and
non-ignored untracked workspace content, but no index, Git metadata, ignored
dependency tree, project configuration, task/state artifacts, credentials, or
other undeclared host paths. Writes are discarded after verified process
retirement. Operators must declare scratch/cache or pinned artifacts separately
when the build needs them; source projection does not grant raw network, host
cache, or arbitrary mount authority. Legacy runs never gain it from current
configuration.

Execution pauses as `plan_revision_required` when runner-observed HEAD already
contains the current planned subject or moved outside verified commit settlement.
The operator must revise the plan and start a new run; external commits are never
adopted into progress. A reported first-step position can precede completed
bootstrap. Completed runner-owned effects retain verification-only recovery.

Plan authoring's `preferredCommitLineLimit` is a positive-integer planning
target, default 900, configured through runner settings or the safe project
overlay. It is persisted for the run; legacy runs receive 900 without adopting
current configuration. CLI pipeline listing and MCP pipeline metadata expose
the descriptor-owned default. It does not restrict execution diff size.

Pinned dependency declarations freeze canonical public HTTPS URLs and SHA-256
digests alongside command vectors. During finalization, the runner downloads
verified files into private storage and exposes a fixed read-only dependency
mount to the network-isolated check. Acquisition failures pause for environment
repair; resume cleans prior resources and retries the saved declarations. Changing
a URL or digest requires a new run. Checks perform any extraction in declared
scratch; the runner does not install host tools.

## CLI and MCP control

The CLI provides run, resume, pause, cancel, status, pipeline discovery, and
MCP server commands. MCP exposes matching `run_pause` and `run_cancel` actions
alongside the same static pipeline registry through STDIO and keeps standard
output exclusively for protocol traffic. It never launches an editor;
pending clarification and product-decision input is represented as a structured
request with a revision and stable request ID.

Mutating MCP calls require idempotency keys. Intent is persisted before
mutation and a receipt before return. Work continues in a detached process, so
a client disconnect or wait cancellation ends only that client's wait and does
not create a second execution owner. A compatibility token prevents an old MCP
process from dispatching a newer or otherwise incompatible workflow. An
ownerless applicable stop may be recovered by exact-revision, action-free
`run_resume` with a new key; that separate durable intent makes the original
pause/cancel key unnecessary without replaying its acceptance receipt.

## Durable state and local artifacts

Run state lives under the user's OS state directory, outside both the target
repository and task directory. Each transition is a complete write-ahead event
followed by atomic current-state replacement. The human-readable progress file
is derived and can be regenerated; the event journal remains authoritative.
The common run envelope also holds one bounded provider-policy receipt slot per
resolved role. Legacy state migrates before provider work and pins a role's
first current receipt when that role is required; resume rejects policy drift
instead of re-resolving isolation.
The receipt exposes only a fingerprint and common supported access modes, never
provider flags, credentials, native output, prompts, or session storage.

Plan authoring writes its declared task artifacts. Plan execution and polishing
may place runner-owned clarification artifacts below the configured repository
artifact root only after Git proves the path is already ignored. The runner
does not edit target ignore rules.

One execution lease protects a mutating run. Plan execution and polishing also
hold a canonical-worktree lease so independently identified runs cannot mutate
the same checkout concurrently. Plan execution's descriptor-proven untouched
initial `CLARIFY` stop is the narrow state-only exception: it retains the run
lease and settles without acquiring a canonical lease recorded for an unrelated
run. Every checkpoint that may require repository reconciliation or effect
verification keeps normal worktree exclusion. Status and activity reads remain
lock-free.
An abandoned current same-host execution or canonical-worktree lease becomes
eligible for immediate recovery only when its complete boot/PID/start identity
proves the exact owner dead or replaced. Acquisition age is neither a delay nor
ownership proof. Legacy, identity-free, foreign-host, live, invalid, and
otherwise unverifiable records remain exclusion barriers. Short state
mutations observe competing claims at most 500 times with 10 milliseconds
between observations (about five seconds plus file system work), then return a
retryable busy result rather than risking two writers. The smaller fixed
publication and collision retry counts are correctness mechanics, not
operator-configurable workflow budgets.

Lease ownership, same-run recovery responsibility, and a persisted execution
process are independent facts. A current owner reuses its existing worktree
lease while stopping; after owner loss, the replacement execution owner may
reclaim only the exact same-run lease and must prove the recorded process and
all owned descendants absent before clearing the process record. Live,
replaced, unverifiable, or descendant-bearing process evidence remains a
blocking ownership condition. Retirement and stop settlement are separate
journaled transitions so an interruption safely retries either boundary.
For shared-host sessions, the persisted frozen boot/PID/start baseline lets
recovery exclude a new unrelated process only when every stabilized ancestry
hop reaches an unchanged pre-launch identity, or when inaccessible current
environment metadata is paired with a stable control-group identity different
from the recorded owner. Observed session and token ownership always wins over
an anchor. PID reuse, a stale or missing anchor, boot or namespace mismatch,
cycles, missing or matching control-group evidence, or incomplete evidence
remain conservative; a recorded previous boot remains independent absence
proof. A process or ancestor that exits or reparents during
inspection receives only the fixed per-entry retry bound; recovery ignores it
only after a fresh read proves the snapshot PID absent. Reuse, surviving
ownership, malformed evidence, and exhausted churn remain blocking. Legacy
records gain no baseline authority, and public projections never expose the
baseline or retry evidence.

## Pauses, resume, and observability

The runner service distinguishes an operator pause from cancellation. A pause
retains the frozen run and its reconciled checkpoint; its null resume action
restores any existing blocker before ordinary work can continue. Cancellation
produces inspectable terminal `CANCELED` state and cannot be resumed. Safe
partial workspace changes and task artifacts remain available in either case.
CLI shorthand captures one status revision and key, while explicit CLI and MCP
requests require both values for repeatable automation. Exact retries replay
their durable receipt; stale requests are never refreshed implicitly.

The runner service supports `after-current-commit` for a selected execution
step, including suspended steps; other pipelines and pre-step checkpoints reject
it. CLI pause/cancel accepts `--timing`; MCP stop tools accept `timing`, both
with `immediate` and `after-current-commit` and omission equivalent to immediate.
Exact retries preserve timing as well as revision and key. A deferred request lets that target
finish normally while retaining ownership. An immediate cancellation can
supersede it. Verification records the commit and stop outcome before the next
step; a pause, failure, or interruption instead settles at the reconciled
quiescent checkpoint without extra work. Existing blockers and failure evidence
remain available. After the final commit, pause resumes through `DONE` without
agent work; cancellation retains completed history in `CANCELED`.

Stop requests are durable before immediate owned execution is interrupted. Activity
reports stopping, repository reconciliation, and the resulting state, while
leases remain held until accounting completes. If a commit or handoff already
began, verification records the observed effect without undoing or replaying it.
Retained safety blockers remain visible through the bounded pause projection.
An ownerless accepted request starts detached same-run reconciliation, and a
client disconnect cancels only its wait. Public status and waits expose the
pending kind, accepted revision, requested/effective timing, and target step
without the request identity or private checkpoint. The bounded `stop` summary
also remains after settlement. Its state is `pending` while awaiting the target,
`applicable` for immediate requests or suspended/failed checkpoints awaiting
reconciliation, and `settled` after accounting. Ownership loss still requires
reconciliation even when the durable summary is pending. Settlement is nullable
for pending or legacy records, otherwise `quiescent` or `commit` with the verified
SHA. Activity projects the summary from each historical event, while receipts
replay immutable acceptance evidence. Cancellation is a terminal wait result
and older intents cannot revive it.

MCP supervises a stop child through durable settlement or that correlated
child's exit; transient run-lease ownership is never reported as reconciliation.
Exit first leaves the stop applicable and the recovery intent retryable, with a
distinct version-skew outcome when applicable. Fresh public recovery rejects a
stale revision, non-null action, live owner, or duplicate-owner race. When a
non-quiescent stop is blocked by a canonical lease, diagnostics distinguish the
ownerless pending run from the different run recorded as lease owner. Operators
must use supported recovery and reclamation rather than manually deleting or
bypassing lease records.

Legacy opaque plan-execution failures during terminal confirmation can expose
an action-free retry in either mode when durable history proves acceptance and
finalization. CLI and MCP share that eligibility; status remains lock-free and
does not reopen the run. Execution rechecks proof and safety under the normal
leases before resuming confirmation. It preserves completed commits, settings,
lineage, evidence, and accounting. A true correction marker may represent an
already charged fix rather than pending work; operators must not edit it.
Absent or inconsistent provenance grants no retry, and MCP retains its exact
revision, durable receipt, idempotency, and detached ownership guarantees.

Newly diagnosed lazy Worker check/fix acquisition failures can offer a null
resume action targeting `CHECK_AND_FIX`. Eligibility requires closed completed-
turn evidence, safe reconciliation/retirement and a continuous matching journal,
then fresh safety checks under execution/worktree leases. Reconstruction retains
commits, content, frozen inputs and accounting, including charged corrections,
and requires fresh convergence and acceptance gates. Protocol errors remain
terminal to automatic retry. An opaque legacy protocol failure lacking that
provenance offers no action; use the reconciled polishing/revised-plan fallback
in the operator guide. Existing legacy terminal-confirmation eligibility is
separate and unchanged.

Normal work is autonomous. The runner pauses for identified clarification or a
material product decision, required provider authentication, provider
unavailability, an external validation
blocker, exhausted correction budgets, version skew, unsafe Git state, or an
ambiguous effect. Each public pause exposes a finite reason, bounded evidence,
the safe resume checkpoint when one exists, and concrete next actions. It does
not expose prompts, transcripts, credentials, rejected provider output, or raw
diagnostics.

A proven pre-effect COMMIT readiness rejection exposes the same fixed
explanation and recovery action through CLI and MCP: reported workspace change,
forbidden Git operation, or invalid readiness object. The explanation identifies
the category without retaining the operation or provider data. Git must verify
that no commit was created before the consumed authorization is retired and an
action-free COMMIT resume can prepare a fresh one. Interrupted verification
retains the category privately until settlement. Legacy or unknown category
evidence keeps the generic commit-failure explanation; missing evidence is
never reconstructed. A reported file-change item does not prove that content
changed. Preserve resumable workspace content and use supported runner
reconciliation; repair the installed adapter before retrying. Recovery
explanations never invite manual restoration or edits to frozen inputs,
configuration, finalization guidance, or an active readiness response. Unsafe
reconciliation requires a new run.

An eligible pre-effect transient launch failure adds the same strict
`launchRecovery` value to CLI and MCP status: only its normalized failure class
and launch checkpoint. An operator pause preserves that projection with the
underlying availability blocker so action-free restoration shows the same
state. Accepted resume clears it with the pause, and cancellation removes it
from the retained private checkpoint. It never authorizes a second source fork
or a commit effect.

If an unexpected runner-owned invariant rejects a plan-execution finalization
transition, both CLI and MCP status expose the same bounded diagnostic and an
explicit retry from the retained `FINALIZE` checkpoint. Rejected finalization
evidence and native process output do not enter the pause record.

Increasing the trusted-command deadline does not change isolation or restore
historical discarded stdout/stderr. Trusted-check failures can expose finite
normalized error classes/stages through existing CLI/MCP pause evidence, bound
to the frozen failed runner check and its matching generated issue IDs.
For the supported repository-check launcher, that evidence can also identify a
canonical selected failing test file and include Runner-measured elapsed
milliseconds. Membership remains bound to the inspected content after reload;
it is not reconstructed from current files. Timing also survives successful
checks into terminal confirmation, even though successful output is discarded.
Preflight and unstarted checks omit timing; old records retain their absence.
General agent issue prose/commands and raw logs remain private. Unsupported,
unsafe or malformed output produces a bounded omission explanation; successful
output is discarded. Diagnostics change no next actions, retry eligibility or
budgets. Historical opaque records remain opaque until an authorized normal
retry generates fresh evidence. A host pass may still fail closed in isolation;
timeout configuration is not a sandbox or diagnostics remedy.
Runner-generated blocked finalization retains applicable safe fragments in its
existing pause evidence without generated failure issue IDs.
Executed timeout/retirement blockers may include validated Runner timing, but
blocked outcomes do not expose unbound file identities. When changing the
executing Runner's own implementation, settle a public pause and resume through
a fresh process before finalization if necessary. Do not hot-reload an active
owner or edit durable state, frozen configuration or inputs.

Plan execution and polishing pause as `finalization_evidence_rejected` at
`FINALIZE` after two automatic semantic retries per execution step or polishing
run. CLI and MCP expose bounded finding identities and an explicit null retry
for exactly one additional complete finalization attempt. Applicable
independent-mode finding overrides remain tied
to the terminal content fingerprint; closing feedback still requires replacement
finalization and fresh confirmation. Provider availability or interruption
resumes an already pending attempt without charging another retry.

Public activity records the actor, phase, event kind, and concise message. The
active role and phase combine with lease ownership to distinguish running,
interrupted, and idle work without polling a provider or depending on a
heartbeat. MCP status and wait additionally report the finite lease-owner
classification and whether a process record is persisted, without exposing a
PID or process identity. An interrupted owner reconstructs work from durable
state after revalidating inputs and the repository.

Unexpected-issue reporting is an optional MCP-only operator action for behavior
that contradicts the documented runner contract. Expected pauses, invalid
input, configured limits, and environmental blockers are not unexpected
issues. Reports contain only caller-supplied bounded Markdown; the runner does
not attach logs or secrets automatically.

## Local issue index

`LOCAL_ARTIFACTS/agent-runner/issues/index.json` is an optional, repository-relative
operator artifact for tracking deliberate processing of local issue reports.
Issue Markdown files remain authoritative; the index contains only their order
and a cursor, never copied report content or a second issue-status model. This
convention adds no CLI command, MCP tool, prompt input, public run projection,
or automatic backlog loading. Existing issue reporting does not maintain the
index. The literal path does not override `artifactRoot` or relocate reports
published under another configured root.

Before creating or replacing the index, require `git check-ignore` to confirm
that its resolved repository-relative path is ignored and verify that it is
untracked. Never change ignore rules to make it eligible. The index and issue
paths must stay inside the repository, with real directory parents and no
symbolic-link components. An existing index and present issue files must be
regular files with a single hard link.

The JSON object has exactly these fields:

```json
{
  "schemaVersion": 1,
  "entries": [
    "LOCAL_ARTIFACTS/agent-runner/issues/issue_2026-09-30_090000.000Z.md",
    "LOCAL_ARTIFACTS/agent-runner/issues/issue_2026-09-30_090000.000Z_001.md"
  ],
  "lastProcessed": null
}
```

`schemaVersion` is the integer `1`. `entries` is an ordered array of unique
normalized issue Markdown paths. `lastProcessed` is either `null` or exactly
one of those strings. Null means no entry has been processed; otherwise every
entry through that cursor, inclusive, is processed and the suffix is pending.
An empty list requires a null cursor. A missing index starts from an empty list
and null cursor; it does not imply that any discovered report was processed.
Reject malformed JSON, duplicate object fields, unknown fields or versions,
invalid entries, duplicate stored entries, and a cursor absent from the list.
Do not silently repair, reorder, or reset an invalid stored index.

Normalized entries use the exact repository-relative prefix
`LOCAL_ARTIFACTS/agent-runner/issues/` and one report basename, separated by
forward slashes. Report names have the existing form
`issue_YYYY-MM-DD_HHMMSS.sssZ.md`, optionally inserting `_NNN` (three digits) or
`_<token>` (12 lowercase hexadecimal characters) before `.md`.
The encoded timestamp must be a valid UTC date and time. Reject absolute,
drive-qualified, backslash, empty-component, `.` or `..` paths, symbolic links,
directories, and non-issue files. Never resolve traversal, follow links, strip
an absolute prefix, or reinterpret another Markdown file as an issue. Discovery
produces the same normalized form; repeated discoveries of one path do not
create additional entries.

Maintenance first validates the complete stored index and the confined paths.
Preserve every existing entry in its existing position as an unchanged ordered
prefix. Discover regular issue Markdown files in that directory, collapse
duplicate discoveries, and exclude paths already in the prefix. Sort only the
new paths by their filename's UTC timestamp ascending, then by the complete
normalized path in bytewise ascending order, and append that batch. Do not use
filesystem modification times, locale ordering, or a global resort; even a
newly discovered older report goes after the existing prefix.

A missing unprocessed issue blocks cursor advancement: never skip it or delete
its entry to reach later work. Discovery may append entries without moving the
cursor. A missing already processed file may remain in the preserved prefix
only as historical evidence anchoring the cursor, including when it is the
`lastProcessed` entry itself. It supplies no report content or authority to
reprocess a different path. Cursor membership is determined by the validated
list, not by searching for a replacement file. The historical exception never
permits a symbolic link, path escape, or replacement non-issue file.

Process pending entries in order. Advance `lastProcessed` to the next entry
only after that issue has been successfully processed; failed or incomplete
processing grants no advancement. Serialize maintenance and do not overwrite
a concurrent index change. Publish each update as the complete validated JSON:
write an exclusive temporary regular file in the same confined, ignored
directory, sync that file, atomically replace `index.json`, then sync the parent
directory. Never patch the cursor in place. Do not claim a durable advancement
until publication and syncing succeed; after an uncertain publication, reread
and validate the complete index before continuing.

## Project-local operating guidance

The shared guidance capability composes the installed operator guide and the
entire optional `<artifactRoot>/agent-runner/rules.md`, using current new-run
configuration resolution. Clear boundaries state that local additions may
specialize project operation but cannot weaken common safety or product
contracts. Missing local content is valid and reading never creates it.

Local guidance is a complete, bounded, non-sensitive Markdown document. Whole
replacement uses an expected content hash, an idempotency key, atomic
publication, and the canonical-worktree lease. Stale concurrent edits fail;
completed retries return their original receipt even after subsequent edits.
Empty content means no additions. The common guide is never replaced.

CLI operators use `agent-run guidance --project <repo>` to read both documents
and `agent-run guidance edit --project <repo>` to edit the entire local document.
Both accept `--project-config <path>`. Editing uses a private external copy in
`$VISUAL` or `$EDITOR`; failed or signalled closes preserve local guidance.
Unchanged closes still recheck safety and concurrency, and leave a missing
local document absent. No pipeline run is constructed for either command.

MCP supervisors call `guidance_read` once before first managing a run for each
project, including when issue reporting is disabled. It returns the complete
combined guide, separate common and local documents, resolved paths, and
`localHash`. Both guidance tools accept `projectPath` and optional
`projectConfigurationPath`. `guidance_update` replaces the whole local document
using full `localContent`, nullable `expectedHash`, and an `idempotencyKey`.
Null requires an absent file; an existing empty file has a hash. MCP never
opens an editor. Replacement is local, potentially destructive, and idempotent;
its bounded receipt contains paths, the resulting hash, and an `updated` flag.
Retry the same logical mutation with identical arguments and key after a lost
response. Completed receipt replay preserves later edits and is not a fresh
read. A stale edit requires rereading, reconciliation, and a new mutation key.

Record stable project operating lessons here after execution releases ownership.
Task requirements belong in task context or tracked project documents, universal
rules in the common guide, and genuine Runner defects in deliberate issue
reports. Guidance belongs only to the supervisor: pipeline roles do not receive
it, and runs neither persist nor reload it.

Valid dirty work left by a genuinely non-resumable run may be recovered through
polishing after ownership is gone and inputs are reconciled. Plan execution
still requires a clean worktree; polishing still stages without committing.
Contaminated or unsafe mixed content requires an uncontaminated worktree,
not adoption by a different pipeline.

Action-free continuation is shared by CLI and MCP, including a finalization turn
whose process-retirement proof is temporarily unverifiable. The saved turn stays
resumable while ownership remains safety-blocking; successful retirement precedes
ordinary checkpoint reconstruction. CLI may bind `--expected-revision`; MCP
always requires the exact revision. Action contention and bounded detached
observation return retryable ownership results with the original intent intact.
Identical-key retries use correlated durable dispatch evidence and cannot create
a second live owner. Cancellation, timeout, and disconnect end only the observing
wait, not reconciliation or receipt publication. A receipt acknowledges accepted
continuation or the particular stop's settlement, never content approval.
