# Agent Runner Operator Guide

Use this procedure when supervising Agent Runner through the CLI or its local
STDIO MCP server. The [product documents](README.md) own the current guarantees;
the pipeline specifications own exact workflow and recovery contracts.

| Mode          | Quality | Speed | Token consumption | Meaning                                                         |
| ------------- | ------- | ----- | ----------------- | --------------------------------------------------------------- |
| `lazy`        | ★★★☆☆   | ★★★★★ | ★★☆☆☆             | Lower-consumption self-review without an independent Reviewer.  |
| `independent` | ★★★★☆   | ★★★☆☆ | ★★★★☆             | Recommended default with genuinely independent semantic review. |
| `combined`    | ★★★★★   | ★★☆☆☆ | ★★★★★             | Primary self-convergence followed by the full independent gate. |

## 1. Choose the work and its owner

Choose one pipeline for the intended outcome:

| Pipeline         | Starting point                             | Successful result                                                    |
| ---------------- | ------------------------------------------ | -------------------------------------------------------------------- |
| `plan-authoring` | A task and optional context                | A reviewed, validated `plan.md`; no implementation or commit         |
| `plan-execution` | A clean worktree and validated commit plan | One verified local commit per planned step                           |
| `polishing`      | An existing non-empty local change set     | The complete finalized and reviewed changes staged, without a commit |

`independent` is the default and recommended mode: separate primary and review
roles provide independent semantic review, using more provider context and
tokens. `lazy` is an explicit opt-in choice with lower consumption and no
independent review. It uses the primary role's bounded check/fix and separate
read-only clean confirmations. Never choose lazy automatically to save tokens.

Every pipeline supports all three modes. Combined adds primary check/fix and a
separate read-only clean confirmation before the full independent Reviewer gate.
Candidate approvals bind the same
fingerprint; content repairs restart primary convergence. Self-findings return
directly to fixing. Only independent finding resolution may invoke a fresh
Arbiter; unresolved bootstrap disagreements and primary or structural exhaustion
pause without arbitration. Resume preserves mode, bounded correction accounting,
and accepted evidence; interrupted corrections are charged once.

All planning turns remain repository-read-only, with runner-owned artifact writes.
Execution and polishing additionally require finalization and a distinct read-only
terminal confirmation over the resulting fingerprint and validation evidence:
Worker in lazy mode, Reviewer otherwise.
Execution then authorizes one Worker commit; consumed commits recover by
verification only. Polishing ends with runner-owned staging without a commit.
See the [mode contract](product/PIPELINE_MODEL.md#review-modes) and the owning
[authoring](../pipelines/plan-authoring/docs/SPEC.md),
[execution](../pipelines/plan-execution/docs/SPEC.md), and
[polishing](../pipelines/polishing/docs/SPEC.md) specifications.

Give a worktree one owner. Plan execution and polishing enforce a canonical
worktree lease, including across CLI and MCP. While a run owns execution, do
not mutate its repository, Git state, frozen inputs, configuration, local
guidance, or finalization guidance. Do not switch branches, stash, reset,
rewrite history, edit checks, or run another mutating workflow there. Read-only
inspection is appropriate; inspect another base without changing this checkout.
An execution lease ending does not authorize interference with resumable work.

## 2. Prepare against the actual base

Read the project's instructions, owning specifications, and relevant code.
Verify that the intended base contains the files, symbols, and behavior named
in the task. Recompute baselines, checksums, inventories, and acceptance
assumptions against that base. Do not copy measurements from a previous task,
another checkout, or a stale branch. Prefer explicit behavior and invariants
to incidental counts; verify any required counts and path lists locally.

Use pipeline discovery (`agent-run pipelines` or `pipelines_list`) to confirm
inputs and settings. Reconcile the task, context, plan, and existing
clarifications before starting. Put requirements and acceptance criteria in
task inputs or tracked project documentation, with commands clearly identified
as required checks or background examples. Ambiguous commands in prose can
produce a different inventory from the one you intended.

Plan execution consumes the validated subjects and commit boundaries unchanged.
A decision that conflicts with the plan requires a revised plan and a new
execution run. Do not edit a frozen clarification transcript to override it,
rewrite completed commits, or reuse a plan whose steps are already implemented.
Prepare a new plan for the remaining work when required.

Plan authoring's `preferredCommitLineLimit` defaults to 900 anticipated additions
plus deletions per commit, including tests and documentation. Set this positive
integer under `pipelines.plan-authoring` in runner or safe project configuration;
project values take precedence. Prefer cohesive commits within the target. An
indivisible larger change remains valid with a rationale in the plan. This is a
planning preference, not an execution limit. Resume retains the saved target;
legacy runs receive 900.

Runner-root configuration defines trusted profile implementations. Both root
and ignored, untracked project configuration may define exact trusted command
vectors; project configuration may select these aliases and safe settings.
The default project configuration is
`LOCAL_ARTIFACTS/agent-runner.json`; an explicit project configuration must be
confined to the project. `artifactRoot` defaults to `LOCAL_ARTIFACTS`.
Repository-local artifacts must already be ignored. The runner never changes
ignore rules automatically. Keep authoritative state in a separate tree from
the project and task directories; neither may contain the other.

Configure provider-visible `clientAttribution: { "name": "...", "title": "..." }`
only at runner root. It defaults to `agent_runner` / `Agent Runner`, requires
every active backend's support (Claude does not support custom attribution),
and is absent from public projections and prompts. Project files and CLI/MCP
cannot override it. Resume retains the fingerprinted selection; legacy runs
use the generic default. See [client attribution](product/PROVIDER_MODEL.md#client-attribution).

Select effort separately from model: `current`, `low`, `medium`, `high`, or
`xhigh`. Use configuration `defaultEffort`/role `effort`, CLI `--effort`/
`--<role>-effort`, or MCP `run_start.effort`/`roleOverrides.<role>.effort`.
Precedence is role override, run override, project role/default, runner
role/default, then `current` (the provider default). Unsupported selections fail
without downgrading. Resume retains private saved role settings; MCP retries
retain effort and the original key. Changing attribution or effort requires a
new run; see [configuration](product/OPERATOR_MODEL.md#configuration).

Select compatible role backends and profiles before starting. Leave the source
session unset unless the user deliberately chooses to fork a compatible current
session after being offered a fresh start. Use only a known trusted source
profile, or `current` inheritance if it is unknown. Keep session IDs opaque;
never inspect provider-private storage or invent an ID. Prefer a fresh start
for long, mixed-topic, or uncertain context. Independent and combined modes fork source
context separately into primary and review checkpoints; lazy mode forks it
once into the primary role. Durable recovery does not require native sessions
to survive.

## 3. Establish executable validation

Before starting, verify each required command in its owning environment and in
the exact form that will be executed. Its exit status must express the intended
pass/fail rule. Check availability of dependencies, generated prerequisites,
services, and any expected baseline failures. A check must detect a regression,
not merely pass the existing base. Distinguish checks applicable throughout the
plan from step-specific acceptance criteria.

Establish complete staging-independent inventories: execution bootstrap owns
one per canonical step (the fast gate plus affected slow checks), and polishing
owns one for the workspace. Execute only the active inventory. Preserve exact
commands, stable IDs, order, and infrastructure paths; retain future checks for
their owning steps. Do not create competing lists, renumber, omit, or substitute
checks. Infrastructure means files controlling commands, discovery, runners,
configuration, or mandatory finalization guidance, rather than every source,
test, fixture, or generated input. Classify by responsibility, not filename.

Use checks over workspace content, `HEAD`, or explicit trees where applicable.
Staged/index-relative checks and staging completeness belong to the runner's
commit or handoff boundary. Do not build an alternate index or hide a dependency
on staging or changing commit history inside a script. Git inspection is not
universally forbidden: the relevant distinction is which content and boundary
the command actually checks.

Bootstrap supports 256 checks and 256 infrastructure files per role, up to 512
entries per merged or finalization field. Report complete inventories; if both
overflow, report `requiredChecks` first. Never omit entries or weaken checks.
Execution discovers each active role's catalog once, then assigns contiguous
units of at most four steps and 256 KiB of supplied JSON. Accepted units survive
restart; only recognized output exhaustion may subdivide unfinished applicability,
with a persisted limit of sixteen subdivisions per role. Indivisible work,
exhausted discovery, or exhausted allowances pause at that checkpoint. Resume
renews no allowance. Both independent inventories must be complete before
combined writable work.
Drift invalidates affected evidence; native sessions prove no reusable coverage.
Legacy migrations preserve evidence and completed work, but unfinished execution
requires fresh scoped read-only discovery, not applicability inferred from an old
union. See [bootstrap inventory](product/VALIDATION_AND_REVIEW.md#bootstrap-inventory).

Commands requiring capabilities unavailable to agents may need runner-trusted
execution. Select `trustedCommands` aliases separately for each pipeline; the
default is empty and project selection replaces root selection. Catalogs merge
root then project, deduplicate identical same-name vectors, and reject conflicts
even when unselected. Limits are 256 definitions and 32 selected aliases per
pipeline. Exact vectors, identities, and fingerprints freeze before work and
survive resume; later project edits trigger the protected-input guard.
Declarations grant no environment, credentials, shell-string substitutes, or
broader host authority. Isolation and mutation guards still apply; user-attested
results cannot replace execution. See [configuration](product/OPERATOR_MODEL.md#configuration).

For a check that must write beside its inputs, declare
`"sourceProjection": true` in that command's capabilities. The runner creates
an owned writable projection of frozen HEAD plus the exact tracked and non-
ignored untracked workspace content. It does not copy the index, `.git`, ignored
dependency trees, project configuration, task/state artifacts, credentials, or
other host paths. Writes are disposable; the original checkout remains absent
from the check. Declare scratch, cache, and pinned artifacts independently.

Set top-level `trustedCommandTimeoutMs` in root or safe project configuration:
strict integer milliseconds `1`–`2147483647`, default `3600000` (60 minutes),
with no CLI/MCP override. The project value wins over the root value. The
fingerprinted value is per-run; resume never reloads it. Legacy snapshots retain
60 minutes. Capability preparation uses the smaller of that deadline and 10 seconds.

For availability recovery, `availabilityRetryMaxDelayMs` accepts `5000`–
`2147483647` milliseconds, default `1800000` (30 minutes), with project
precedence. Runs freeze the policy; legacy migration uses the default without
a pending episode. Explicit transient failures reconcile the repository, then
retry from five seconds, doubling to the ceiling and repeating without a quota.
Follow `availabilityRetry` and schedule/start activity instead of polling.
Successful provider responses reset the episode; partial work, session changes,
and restart do not. Stops interrupt waits. Never edit configuration or state to
reset one. See [durable availability episodes](ARCHITECTURE.md#durable-availability-episodes).

`authentication_required` / `ERR_AUTHENTICATION_REQUIRED` retires a superseded
availability episode and pauses at the saved checkpoint with one null resume
action, no retry delay or native details. Reauthenticate the selected provider
outside the runner, then resume the same run without switching providers or
editing state. Preserve partial content, fingerprints, lineage, and accounting.
Commit readiness first proves the
executor never started and Git created no commit. A possibly effective source
fork reconstructs the logical role fresh rather than risking another child.
See [authentication pauses](ARCHITECTURE.md#durable-authentication-required-pauses).

Writable implementation, polishing, lazy or combined check/fix, and finding-resolution turns
receive only the persisted exact selected command text, including after resume
or reconstruction. Established required-check execution and attestation belong
to `FINALIZE`; selected trusted commands must never execute inside agent turns.
Their agent-sandbox limitations alone must not pause repairs or semantic review.
A constraint affecting nondelegated work still uses the environment-blocker
recovery path, even when another command is selected. Runner-trusted execution
can itself report an environment blocker during `FINALIZE`.

Never weaken tests, assertions, discovery, scripts, formatter/linter settings,
or validation infrastructure merely to make a check pass. Fix the in-scope
implementation. A legitimate infrastructure change must be explicitly within
the task and current planned step and accepted by terminal confirmation.
An environment blocker requires the permitted recovery action, not relaxed
sandboxing, an invented command, a new baseline, or fabricated success.

Use the [trusted build examples](../README.md#configuration) to declare exact
vectors with `scratch`, `cache`, or `sourceProjection` capabilities in root or
safe project configuration. Supply tools/dependencies in accepted source or as
pinned artifacts, not ignored host dependency trees.
Scratch binds `AGENT_RUNNER_SCRATCH`/`TMPDIR`; cache binds
`AGENT_RUNNER_CACHE`, `XDG_CACHE_HOME`, and npm's cache. Paths are runner-fixed;
exact arguments do not expand variables. Storage is private and disposable,
including projected writes; original repository and network access remain
prohibited. Cleanup follows verified process retirement. Uncertain cleanup
retains ownership evidence and resumes before new work; interrupted contents
are never reused.

Increasing the deadline does not repair sandbox incompatibility or reveal
discarded diagnostics. Trusted execution retains no command stdout or stderr;
a check may pass on the host yet fail closed in isolation with only a generic
exit code. Preserve that boundary and investigate the isolated environment
rather than using the timeout as a containment or diagnostics workaround.

For public downloads, declare `capabilities.artifacts` entries with canonical
HTTPS `url` and verified SHA-256 `sha256`; see the
[configuration examples](../README.md#configuration). The runner acquires them
before the network-isolated check and mounts verified files read-only at
`/run/agent-runner/dependencies/<sha256>` (`AGENT_RUNNER_DEPENDENCIES`). Public
DNS/HTTPS and built-in TLS trust are required; redirects, proxies, credentials,
and custom trust are unsupported. Limits remain 64 MiB per file, 256 MiB total,
five minutes overall, one A and one AAAA lookup in a five-second DNS phase with
one resolver try each, connection establishment bounded to 10 seconds, and
header/body inactivity bounded to 15 seconds. Retirement has a separate
one-second safety bound. The command handles extraction in declared scratch;
read-only artifact use needs no scratch/cache. Downloads are never reused.
Acquisition failure pauses finalization without executing the check. Repair and
resume; changed declarations require a new run. Never delete uncertain resources
without verified ownership and transport/process retirement. See
[resource safety](product/SAFETY_MODEL.md#inputs-artifacts-and-state).

Before each writable execution/polishing checkpoint, including resume, the runner
prepares every active role's saved exact-command requirements. Unavailable
storage, isolation, or dependencies pause as `environment_blocked`; repair the
environment and retry the saved request. Runner inspection resolves an agent
sandbox limitation only for the exact delegated check. Preparation supplies no
check evidence; finalization verifies dependencies again.

## 4. Start, clarify, and observe

Start the selected pipeline with its project and task directory, for example:

```bash
agent-run run plan-execution --project /path/to/project --task /path/to/task
agent-run status --run <run-id>
```

Every pipeline starts with read-only `CLARIFY`. The fixed protocol limit is
three agent question rounds; empty clarification artifacts and authorized
editor closes without changes consume no round. Exhaustion pauses rather than
silently extending the dialogue, and the limit is not a configurable workflow
budget. Answer material questions from
explicit user context; otherwise obtain the user's decision. An empty
clarification document and an authorized editor close without changes are
valid. CLI uses a persisted editor authorization; MCP uses structured pending
input and never opens an editor. Only the identified authorization permits
clarification changes. Once clarification closes, inputs are frozen and hashed;
ordinary follow-up questions are prohibited. A later product decision is an
exception only when progress is impossible without a genuinely unresolved
material requirement, not an implementation preference or review finding.

Retain the run ID and each MCP mutation's original idempotency key. Retry
uncertain mutations with identical arguments and key; a new key cannot recover
the original receipt. Ownerless applicable-stop recovery is a separate
`run_resume` mutation with a new key, not a recreated pause/cancel receipt.
Use `run_wait` for event-driven waiting and cursor-based `run_activity` for
deliberate inspection; never poll at a fixed cadence. Omitted
`run_wait.timeoutMs` waits 30 seconds, with a 24-hour maximum.

Use CLI status or MCP `observations` to inspect output pressure by attempt, role,
and checkpoint. Compare byte measurements and token snapshots separately;
unknown referenced-file reads, missing results, incomplete accounting, and
omitted attempts are evidence limits. Never infer a service output limit, sum
cumulative snapshots, or collect private provider content to fill those gaps.

A timeout, wait cancellation, or MCP disconnect ends only that wait. Detached
work continues. Inspect `execution.leaseOwner` (live/dead/replaced/unverifiable)
and `execution.processRecord` (durable ownership present, without identity).
An ownerless nonterminal unpaused checkpoint or `applicable` stop may accept
action-free recovery through
`agent-run resume --run <run-id>`, or MCP `run_resume` with `action: null`, the
exact current revision, and a new idempotency key. MCP rejects stale revisions,
non-null actions, live owners, and ownership races. Follow the current public
state and actions; this never authorizes a second owner.

CLI can bind recovery with
`agent-run resume --run <run-id> --expected-revision <revision>`. An action-free `ERR_EXECUTION_PROCESS_UNVERIFIABLE`
keeps its saved checkpoint, including `FINALIZE`; first resolve ownership through
supported resume, then let the runner reconcile inputs and repository controls.
Do not interpret finished validation commands as accepted finalization evidence.
MCP `ERR_MCP_ACTION_IN_PROGRESS` and `ERR_DETACHED_OWNERSHIP_PENDING` are bounded,
retryable ownership outcomes. Retry the identical key and arguments; neither
client timeout nor disconnect cancels the durable continuation or its receipt.
Unrelated revision movement and retained lease reservations are not launch proof.
Inspection-budget exhaustion preserves exclusion just like incomplete evidence.

For detached failures, inspect `dispatchFailure` (known exit code/signal) and
the separate nullable `recoveryCause` (safe stage, Runner code and explanation).
CLI resume uses the same fixed explanations. Missing causes are explicitly
unavailable; an exit or signal never establishes why the owner disappeared.
Restart can retain a correlated cause without known exit facts. Address the
reported blocker, then retry the identical key and arguments. Retry alone
does not repair it, complete the intent or release uncertain ownership. Never
collect raw child streams, provider output or transcripts to fill this gap.

Shared-host recovery requires frozen pre-launch boot/PID/start evidence and
stable complete ancestry. Observed ownership takes precedence. Inaccessible
candidates need positive control-group, fully exited, or separate live-custody
proof; `Z`, baseline ancestry, a different session, or permission denial alone
does not suffice. Every descendant is independently inspected. Missing, reused,
unstable, incomplete, mismatched, or exhausted evidence blocks; legacy records
gain no retroactive proof. Never delete process/lease records. The
[safety contract](product/SAFETY_MODEL.md#inputs-artifacts-and-state)
owns exact exclusion and bounded retry rules.

After both fixes pass review and commit gates, follow the operator-owned
[operational acceptance procedure](product/SAFETY_MODEL.md#ownership-repair-operational-acceptance)
before dependent work.

Stop with `agent-run pause --run <run-id>` or `agent-run cancel --run <run-id>`.
The shorthand reads status once and binds its revision to a fresh key.
Automation supplies both `--expected-revision` and `--idempotency-key`; MCP uses
`run_pause`/`run_cancel` with the same rule. Retry exact values without silently
refreshing stale requests. Pause is resumable; cancellation is terminal and
older intents cannot revive it. Requests survive disconnect/owner loss. Follow
status/wait while the owner or detached same-run continuation reconciles them.
MCP waits for durable settlement or correlated child exit, not transient lease
acquisition. Exit before settlement retains applicable, retryable recovery,
including the distinct runtime-version-skew restart path.

Add `--timing after-current-commit` to CLI pause/cancel, or
`timing: "after-current-commit"` to MCP `run_pause`/`run_cancel`, to stop after
the selected execution step. Omission and explicit `immediate` are equivalent.
Retry with unchanged timing, revision, and key. Authoring, polishing,
clarification/bootstrap, and checkpoints without a selected step reject deferred
timing; terminal runs reject new stops. Suspended execution steps are eligible.
For a deferred request, supervise its durable target rather than starting another owner. A
successful target commit and stop outcome are recorded together; a blocked or
interrupted target stops at its reconciled checkpoint without extra work. Resume
restores any underlying blocker. A pause after the final commit resumes directly
to `DONE`; cancellation preserves all completed commits and cannot resume.

An immediate cancel can supersede a pending deferred pause. A deferred cancel
cannot postpone an earlier immediate pause: inspect effective timing as well as
requested timing. Acceptance receipts are immutable, so replay does not report
a later settlement. Read status/wait `stop` for the latest outcome, or activity
for the summary at an event's revision. `pending` awaits the target; `applicable`
means immediate enforcement or a suspended/failed checkpoint awaiting
reconciliation; `settled` records completion of stop accounting. An interrupted
owner can still need reconciliation while the durable summary is `pending`.
Settlement is either `quiescent` or `commit` with its verified SHA. Legacy
settled stops may have no settlement details. None of these fields authorize
another execution owner or extra work.

Only a descriptor-proved untouched initial execution `CLARIFY` stop may settle
under the run lease without an unrelated worktree lease; all other checkpoints
retain normal exclusion and effect reconciliation. A lease conflict names the
recorded owner, distinct from an ownerless run awaiting stop settlement. Recover
that owner through supported actions or await normal release/identity-proved
reclamation; never edit or bypass leases. See
[operator stops](ARCHITECTURE.md#state-owned-operator-stop-protocol).

Structured role results allow exactly 2 MiB of serialized UTF-8 JSON. Semantic
field and inventory limits still apply. This is byte headroom, not a token
budget or a native model output setting. Run journals may span contiguous
bounded segments; preserve every segment when inspecting or recovering a run.
Do not prune history to reclaim capacity. See
[the storage contract](ARCHITECTURE.md#structured-result-headroom).

### Output-budget verification record

The eight accepted prerequisites supplied 67 passing finalization entries;
29 have exact normalized runner-monotonic durations. These historical outcomes
do not approve current content. All entries are **PASS**: numbers are milliseconds,
`?` means timing unknown, and `—` means no recorded entry. Absence says nothing
about applicability; never rerun old commits to manufacture timings. Slow rows
abbreviate `npm run test:slow -- <path>.slow.test.js`: root rows omit `test/`,
`execution/` means `pipelines/plan-execution/test/`, and `polishing/` means
`pipelines/polishing/test/`.

| Prerequisite                             | 1          | 2          | 3          | 4          | 5          | 6          | 7          | 8          |
| ---------------------------------------- | ---------- | ---------- | ---------- | ---------- | ---------- | ---------- | ---------- | ---------- |
| Commit                                   | `78b6ffc7` | `8c2f13ef` | `d1991d11` | `a9c6c12a` | `301db035` | `b9f4ebe0` | `d3d958f4` | `c0d6d7b0` |
| `npm run format`                         | ?          | ?          | ?          | ?          | ?          | ?          | ?          | ?          |
| `npm run check`                          | 57447      | 58561      | 60220      | 55925      | 58321      | ?          | ?          | ?          |
| `git diff --check HEAD`                  | ?          | ?          | ?          | ?          | ?          | ?          | ?          | ?          |
| `runner-operator-stops`                  | 25033      | —          | 31020      | —          | 34321      | ?          | —          | ?          |
| `state/operator-stops`                   | —          | 4046       | 5160       | —          | 9091       | ?          | —          | —          |
| `runner-orchestration`                   | —          | 15284      | 15680      | —          | 18646      | ?          | —          | ?          |
| `integration/mcp-workflows`              | —          | 5966       | 6398       | —          | 8145       | ?          | —          | ?          |
| `execution/legacy-confirmation-recovery` | —          | 32328      | 33336      | —          | 36443      | ?          | —          | ?          |
| `execution/legacy-migrations`            | —          | 9551       | —          | —          | 12067      | ?          | —          | ?          |
| `mcp/control-plane`                      | —          | ?          | 6414       | —          | 7545       | ?          | —          | ?          |
| `integration/cli-workflows`              | —          | —          | 13642      | —          | 16058      | ?          | —          | ?          |
| `runner-effects`                         | —          | —          | 39112      | —          | 42876      | ?          | —          | ?          |
| `polishing/handoff-recovery`             | —          | —          | —          | —          | 8994       | ?          | —          | —          |

Current FINALIZE uses its established inventory and records fresh outcomes and
elapsed times for finalized content. Historical rows do not assign current slow
checks; use [affected-check ownership](TESTING.md#slow-gate). Process-churn
regressions protect inspection work/time bounds but explain no earlier opaque
fast-gate failure or queued custody redesign. Earlier CLI/MCP legacy fake-backend
bootstrap blockers were repaired; preserve assertions and investigate new failures.

Five earlier gpt-6.1-sol/xhigh native cases establish old-schema READY compatibility
and one-step independent discovery, without representative long-plan acceptance.
The four discovery cases measured the following bytes. In both byte tables,
`Prompt/Recon` is the size of each equal prompt/reconstruction, not their sum;
schema, output, and structured JSON are separate measurements.

| Case     | Role     | Prompt/Recon | Schema | Output | JSON  |
| -------- | -------- | ------------ | ------ | ------ | ----- |
| Observed | Worker   | 18340        | 13496  | 12007  | 9894  |
| Observed | Reviewer | 18391        | 13496  | 12026  | 9913  |
| Envelope | Worker   | 17285        | 13496  | 12789  | 10658 |
| Envelope | Reviewer | 17336        | 13496  | 11769  | 9654  |

Thread-cumulative token snapshots, completed commands, and compactions:

| Case     | Role     | Input   | Cached input | Output | Reasoning output | Commands | Compactions |
| -------- | -------- | ------- | ------------ | ------ | ---------------- | -------- | ----------- |
| Observed | Worker   | 1012648 | 886400       | 13017  | 5606             | 30       | 0           |
| Observed | Reviewer | 1628878 | 1486848      | 12248  | 4459             | 61       | 0           |
| Envelope | Worker   | 1782008 | 1632512      | 16601  | 7597             | 46       | 0           |
| Envelope | Reviewer | 1850213 | 1686272      | 15285  | 6680             | 45       | 0           |

The compatibility case reported 12948 input and 1243 output tokens (43
reasoning), no commands/compactions, unknown prompt/reconstruction sizes,
13496-byte schema, 2593-byte fixture/output, and 20221 ms elapsed. All five
reported 475000-token context capacity and incomplete accounting. The common
accounting limitations below apply to every native measurement here.

Nested forty-step attempts on 2026-10-21 used production bounded bootstrap,
separate Worker/Reviewer, gpt-6.1-sol/xhigh, and combined mode. Bounds were twelve
requests, 120 seconds/request, 900 seconds/role. Both stopped before model work
with `ERR_CODEX_PROCESS_EXITED`; a public model-free initialization probe confirmed
read-only-filesystem startup failure, exit 1. Worker/Reviewer supplied
prompt/reconstruction/schema bytes were 17936/17936/12844 and 17986/17986/12844;
442/415 ms are startup timings, not bootstrap performance. Native usage, commands,
compactions, results, and READY were unavailable, never zero or acceptance.

An earlier operator-supervised host diagnostic retained the adapter read-only
sandbox, combined mode, gpt-6.1-sol/xhigh, and forty-step plan. Bounds were sixteen
requests per role, 300000 ms per request, and 1800000 ms per role. Worker discovery
was interrupted after 300059 ms (role: 300111 ms), with 60 commands; Reviewer after
300052 ms (role: 300106 ms), with 55 commands. Neither reached READY.
Prompt and reconstruction each measured 40251 bytes for Worker and 40301 for
Reviewer; schema was 12844 bytes, results unknown. Final thread-cumulative
input/cached/output/reasoning snapshots were 1601428/1426944/9694/5927 and
1571948/1423104/12809/8902, respectively. Accounting was incomplete, context
capacity 475000, compactions zero, and both roles reported unchanged repository
reconciliation. These are timeouts, not output exhaustion, startup failures, or
completed bootstrap measurements.

The admitted 2026-10-21 operator-supervised report completed forty-step
`runBoundedBootstrap` on accepted8 (`c0d6d7b04b5f005c39d1b3b665dd00e287287025`).
Fresh independent Worker/Reviewer retained gpt-6.1-sol/xhigh, combined mode, and
the unchanged public read-only sandbox, without configuration/network expansion.
Bounds were sixteen requests/role, 900000 ms/request, 3600000 ms/role. Both
completed discovery/catalog validation, distinct semantic position confirmation,
ten contiguous four-step units, production normalization, and full READY:

| Role     | Steps | Requests | Units | Checks | Infra paths | Corrections | Elapsed ms |
| -------- | ----- | -------- | ----- | ------ | ----------- | ----------- | ---------- |
| Worker   | 40    | 12       | 10    | 14     | 18          | 0           | 1228019    |
| Reviewer | 40    | 12       | 10    | 13     | 58          | 0           | 1468496    |

Byte sizes and elapsed times below are per request; applicability ranges show
minima–maxima across ten requests, not totals.

| Role     | Request               | Prompt/Recon | Schema | Output  | JSON    | Elapsed ms   |
| -------- | --------------------- | ------------ | ------ | ------- | ------- | ------------ |
| Worker   | Discovery             | 40251        | 12844  | 9203    | 8449    | 382372       |
| Reviewer | Discovery             | 40301        | 12844  | 13950   | 12166   | 531325       |
| Worker   | Position confirmation | 9410         | 517    | 451     | 451     | 14826        |
| Reviewer | Position confirmation | 13127        | 517    | 558     | 558     | 14145        |
| Worker   | Applicability         | 14102–16522  | 4788   | 449–609 | 449–609 | 53261–110207 |
| Reviewer | Applicability         | 17821–20241  | 4788   | 445–596 | 445–596 | 54634–158583 |

Final thread-cumulative tokens remain separate per role. Commands below are
discovery counts or later per-request counts; compactions are per request.

| Role     | Input   | Cached  | Output | Reasoning | Discovery cmds | Later cmds | Compactions |
| -------- | ------- | ------- | ------ | --------- | -------------- | ---------- | ----------- |
| Worker   | 3331432 | 2755712 | 32878  | 26106     | 26             | 0          | 0           |
| Reviewer | 3799238 | 3249024 | 41409  | 32112     | 35             | 0          | 0           |

Every completed request reported incomplete accounting, 475000-token context
capacity, and unchanged repository reconciliation. Throughout this record,
cached input is included in input and reasoning in output: never add subsets
again, sum cumulative snapshots, or treat thread totals as live context occupancy.
Referenced-file counts/bytes, prior exhausted usage, and effective native output
limits remain unknown. Supplied bytes exclude separately read files, native wrappers,
and prior context; reconstruction size proves no delivery. Different workloads,
discovery, and bounds establish no causal speedup. See
[observation semantics](product/OPERATOR_MODEL.md#durable-state-and-local-artifacts).

Diagnostic READY proves neither current execution approval nor inventory
reconciliation; all current convergence, independent review, finalization,
terminal confirmation, and commit gates remain required. Small schemas or
CAPACITY_EXHAUSTED alone prove no representative acceptance. Keep native tests
opt-in; never repeat nested probes or expand sandbox/network access. Retain
only admitted facts and bounded measurements, excluding prompts, transcripts,
tool output, reasoning, native IDs, credentials, and arbitrary provider messages.

Codex 0.163.0's generated `turn/start` contract had no numeric `max_output_tokens`
field; no output control was added. The documented 128000-token API ceiling is
separate from an effective Codex turn limit; the incomplete reason proves no
numeric ceiling. The 2 MiB allowance is structured-result byte headroom. Durable
recovery and bounded requests are verified independently of unmeasured native
budget improvements.

Later deferred launch requires the verified corrected implementation in a fresh
runtime and new combined run; frozen runtimes do not acquire target-checkout
repairs. Preserve histories, frozen evidence, other checkouts, configuration, and
skills. Deferred features remain queued; native acceptance proves neither the
original native-platform proof of concept nor those later implementations.

## 5. Recover a pause without taking over the work

Some short runner bounds deliberately remain fixed. Each model-free subprocess
used to prove CLI availability, sandbox support, commit-executor isolation, or
process containment has a 10-second deadline. A local-commit probe has a
one-second network-denial observation deadline inside that outer bound; a
silent socket is not accepted as isolation proof. Both providers' pre-effect
local-commit Git metadata lookups also use the 10-second bound; this preparation
deadline does not cap the authorized commit effect after it begins. Codex MCP
configuration discovery gets at most two attempts with a 30-second subprocess
deadline apiece. An ordinary non-commit turn with native context exhaustion may
receive at most one in-session compaction retry when it has a usable native
session. Outside source forks, persistent pressure and other ordinary
recoverable provider work get one fresh reconstruction before the run pauses.

For Claude on a capability-restricted Linux host, do not grant `CAP_SYS_ADMIN`,
change user-namespace policy, or disable sandboxing. The adapter prefers full
native isolation; only a proved nested-user-namespace denial permits its
authenticated, access-specific Runner launcher. Model-issued commands remain
isolated from host network, sockets, credentials, Git mutation, and outside
writes; provider connectivity stays separate. Unsupported architecture, invalid
arguments/filter, incomplete proof, launch, or cleanup failure leaves that access
mode unavailable as `ERR_UNSUPPORTED_BACKEND`. Resume must reproduce the saved
receipt. Repair Claude, bubblewrap, or the environment rather than weakening
settings or editing state. Exact launcher/filter mechanics belong to
[provider isolation](product/SAFETY_MODEL.md#redaction-and-provider-isolation).

Claude's HOME/config projections and temporary scaffolding stay outside project
and task trees. Missing optional tooling must not appear in project Git status;
do not add ignores or ask agents to remove sandbox placeholders.

A pre-launch `ERR_AGENT_ENVIRONMENT_PREPARATION` pauses safely; turn-time
`ERR_EXECUTION_RESOURCE_UNVERIFIABLE` retains its checkpoint and storage
reservation. Restore the environment and resume the same run for process
retirement, identity-verified cleanup, and effect reconciliation. Never replace
ownership records. Cleanup cannot weaken containment, resolve ambiguous effects,
or retry terminal provider failures. Bounded failure classes and exact trusted
command exit/signal/timeout outcomes remain distinct without raw output. Policy
changes require fresh runs; existing receipts remain immutable.

Claude read-only/local-commit readiness permits autonomous compound inspection
only inside the proved sandbox; workspace-write retains its tool restrictions.
After installing access-policy changes, require a fresh real Claude lazy
plan-authoring run with advertised read-only, workspace-write, and local-commit
access plus a provider response before dependent work. Fake tests do not replace
this [post-install acceptance](TESTING.md#finalization).

A current same-host execution or worktree lease is immediately recoverable only
when recorded boot/PID/start identity proves its exact owner dead or replaced.
Age neither delays nor authorizes recovery. Legacy, identity-free, foreign-host,
live, invalid, and unverifiable records block.
State-mutation contention returns retryable busy after roughly five seconds.
Supported same-run recovery then proves the persisted process and
descendants absent before settling stops; a replaced, live, unverifiable, or
descendant-bearing process still blocks. Do not kill recorded PIDs or remove
lease files. These safety bounds are not workflow budgets or trusted-command
timeouts; follow the offered action and [ownership contract](product/SAFETY_MODEL.md#inputs-artifacts-and-state).

Execution requires plan revision for unchanged initial implementation or missing
trustworthy original step-start evidence. Already-present content under another
subject does not satisfy a step. Partial work survives interruption; continuing
it or correcting accepted implementation need not produce additional edits.
`plan_revision_required` also covers the current subject already at HEAD,
external HEAD movement, or context directing a skip/reorder or claiming the step
landed. Matching structured fields cannot override that contradiction; quoted
examples and future discussion alone do not redirect work. The runner preserves
position/history and never adopts external commits. Step one may appear before
bootstrap completes. Revise the plan and start a new run, without moving HEAD or
editing frozen inputs. Consumed runner commits settle by verification first.
See [initial implementation evidence](product/VALIDATION_AND_REVIEW.md).

**A pause is not completion.** Read its reason, bounded evidence, pending input,
and current `nextActions`. When the run is resumable, resolve only the permitted
cause and resume that same run. Do not manually finish, validate, rewrite,
discard, or commit its resumable work. Do not mutate frozen inputs or
configuration to change what a resumed run will do; resume uses its durable
snapshot.

| Current action  | Operator procedure                                                                             |
| --------------- | ---------------------------------------------------------------------------------------------- |
| `respond`       | Answer the exact pending revision/request, or use the authorized CLI edit. Never answer twice. |
| `resume`        | Apply only the offered retry/action to the same run; preserve counters and decisions.          |
| `start-new-run` | Meet its stated prerequisite. The stopped workflow and its changes gain no acceptance.         |

Offered resume actions may cover provider reauthentication/availability, extra
fix budget, or one applicable finding override. New-run prerequisites may require
a revised plan, reconciled finalization blockers, or an uncontaminated worktree.

For an ordinary CLI retry, use `agent-run resume --run <run-id>` only when the
current action permits it. MCP responses and resumes require the current
revision and an idempotency key. An override applies only to its named finding
and exact reviewed content, not to other findings or future repairs. Lazy
confirmation findings return to fixing and are not arbitrated.

A legacy execution `FAILED` run after opaque `ERR_CODEX_TURN_FAILED` /
`turn_other` may offer null `resume` targeting `CONFIRM`. Use only that offered
action. Durable candidate/finalization proof and current input, content,
infrastructure, and Git checks precede confirmation retry. Completed commits,
accounting, and proven non-actionable `pendingCorrection` survive. Never clear
markers or edit journals; a matching error or migrated snapshot alone proves
no eligibility. Explicit availability failures back off at the same checkpoint.
See [confirmation provenance](product/VALIDATION_AND_REVIEW.md#evidence-and-fingerprints).

Classify by current actions rather than an error-name shortcut. Provider usage
exhaustion and environment limitations may be resumable; exhausted budgets,
unsafe reconciliation, changed inputs, or ambiguous effects have their own
bounded recovery rules. Do not erase locks, patch state files, reset stagnation
history, or assume every `no_progress` pause has the same recovery path.

For `backend_unavailable` / `ERR_PROVIDER_INACTIVE`, inspect `Provider inactivity`
or MCP `inactivityRecovery` for role, checkpoint, attempt, and status. The frozen
`providerInactivityTimeoutMs` defaults to 30 minutes without meaningful progress;
owned commands suspend it, keepalives do not. Safe partial work and counters
survive one fresh reconstruction without reforking. After a second expiry,
restore the provider and use the offered resume for one invocation without new
automatic allowance. Never edit markers/configuration. Trusted deadlines and
ambiguous effects retain separate rules; see
[provider inactivity](product/PROVIDER_MODEL.md#provider-inactivity).

For a launch failure without explicit availability evidence, CLI status prints
`Launch recovery: <checkpoint> (<failureClass>)` and MCP status returns the
equivalent two-field `launchRecovery` object. Restore availability and use only
the offered resume action. An operator pause preserves this diagnosis; resuming
the underlying pause clears it before retry, while cancellation clears it
permanently. A lazy source fork failed at `spawn` or `initialize` is still the
run's unconsumed single fork. Later fork checkpoints are not offered this
recovery and fail closed because a provider child may already exist.

Owned execution requires Linux PID namespaces and system-installed bubblewrap.
The runner-trusted executor may reuse its already-private PID namespace for a
nested runner test when its sandbox correctly denies another namespace; it does
not relax that sandbox. Otherwise, unavailable containment fails before provider
work begins. Stops retain exclusion until the recorded supervisor and descendants,
including detached services, have stopped. Unknown ownership and older
group-only records remain conservative recovery barriers; an empty process
group alone does not authorize clearing them.

Codex `ERR_INVALID_CODEX_SCHEMA` (local) and `ERR_CODEX_TURN_FAILED` /
`turn_bad_request` (provider) are terminal request errors, including recognized
structured HTTP 400 schema rejection labeled `other`. Correct the defect before
starting again; availability/output correction does not apply. Opaque `turn_other`
keeps one eligible ordinary non-commit reconstruction outside source forks, then
`backend_unavailable`. Explicit overload/transport failures use durable backoff;
policy, protocol, and isolation violations take precedence. Commit readiness
instead requires pre-effect Git verification. Never collect native error payloads
or transcripts; see [failure classification](product/PROVIDER_MODEL.md#normalized-failures-and-recovery).

If a genuinely non-resumable run leaves valid dirty work, first establish that
execution ownership is gone and reconcile inputs and the stopped run's
requirements. Then use **polishing** to finalize and review that existing
change set. Do not start plan execution on a dirty tree or discard useful work
merely to pass its clean-tree preflight. Polishing stages the accepted result
and never commits; any subsequent operator commit requires separate authority.
If further planned implementation remains, prepare the appropriate clean base
and revised remaining plan before starting execution.

This fallback never legitimizes contamination. A read-only role mutation or
unsafe mixed change set requires an uncontaminated worktree and explicit
reconciliation, not adoption through another pipeline. Preserve unexpected
user work; the runner does not roll it back automatically.

## 6. Recognize the actual completion boundary

Candidate convergence precedes finalization. Finalization follows the selected
repository skill or the complete repository-derived fallback, runs writable
formatting before the established non-mutating checks, and records direct
evidence for every check. A separate read-only terminal confirmation inspects
the resulting content and validation evidence. Formatter output is part of
what must be confirmed.

In plan execution and polishing, terminal validation-evidence rejection
invalidates the finalization result. Pure evidence findings return directly to
complete finalization; mixed findings require content convergence first. After two
automatic semantic retries per execution step or polishing run,
`finalization_evidence_rejected` exposes an explicit retry at `FINALIZE` for one
additional attempt. Pending attempts survive interruption without another charge.
Follow the projected action; neither
feedback nor an override can restore rejected evidence or weaken the inventory.

Content-changing repairs invalidate earlier acceptance evidence and require
the complete gate again. An unchanged successful finalization may be reused
only under the runner's exact content and infrastructure fingerprint rules;
there must still be a fresh successful terminal confirmation. An operator's
manual validation result does not replace this evidence.

For plan execution, only the runner-authorized Worker commit effect stages,
checks staged hygiene, and creates the exact subject-only planned local commit.
No body, footer, authorship trailer, identity change, or remote write is allowed.
For polishing, only the runner's `HANDOFF` stages and verifies the complete
accepted change set; `HEAD` stays unchanged. Wait for `DONE` and its verified
outcome, not merely a successful agent message or passing tests. Never replay
an ambiguous commit or handoff manually.

## 7. Report defects and maintain useful local guidance

Keep these outcomes separate:

- **Expected runner pause or invalid input:** follow its current actions and
  correct only the permitted cause. Limits and environmental blockers are not
  automatically Runner defects.
- **Genuine unexpected Runner defect:** deliberately use the optional MCP
  `unexpected_issue_report` only after concluding that behavior contradicts
  the documented contract. Supply bounded English Markdown describing the
  expected and actual behavior and why it is unexpected. Do not attach raw
  logs, provider output, prompts, credentials, or transcripts. The server does
  not gather them automatically. Retry an uncertain report with its original
  key; reporting does not resume or repair the run.
- **Stable project operating lesson:** consolidate it into local guidance when
  no execution owns the project. A universal product rule belongs in the common
  guide; a task or product requirement belongs in task context or tracked
  project documentation.

For deliberate local issue processing, follow the
[local issue index contract](product/OPERATOR_MODEL.md#local-issue-index) for
`LOCAL_ARTIFACTS/agent-runner/issues/index.json`. It defines append order, safe
paths, missing-file handling, and durable cursor advancement. Issue Markdown
remains authoritative; the runner does not load or maintain this backlog.

The shipped common guide and optional `<artifactRoot>/agent-runner/rules.md`
are returned complete with explicit boundaries, using current new-run
configuration. Local additions specialize operation but cannot weaken common safety
or product contracts. They guide only the supervisor, never pipeline-role
prompts or active runs. See [guidance ownership](product/OPERATOR_MODEL.md#project-local-operating-guidance).

Keep local additions short, non-sensitive, and operator-authored. Exclude
secrets, credentials, raw provider output, transcripts, and chain-of-thought.
Reads do not create missing files or directories. Unsafe, linked, tracked,
non-ignored, overlapping, malformed, or oversized targets are rejected.
Each document is bounded to 64 KiB of valid UTF-8 with safe text characters.
Recognizable credential and transcript formats are rejected; this is not a
guarantee that arbitrary prose is free of secrets.

Replace local additions as a whole document, consolidating obsolete lessons.
Empty content means no additions; missing files have null hashes, existing empty
files have SHA-256 hashes. Atomic replacement compares the previously read hash
at publication. Stale edits require rereading/reconciling the whole document.
Local updates never replace the common guide. Completed retries return their
original receipt, preserving later edits; they are not fresh guidance reads.

Read and edit through the CLI:

```bash
agent-run guidance --project /path/to/project
agent-run guidance edit --project /path/to/project
agent-run guidance edit --project /path/to/project --project-config LOCAL_ARTIFACTS/custom.json
```

Editing opens a private temporary copy outside the project in `$VISUAL`, with
`$EDITOR` as fallback only when the preferred editor cannot launch. Configure
a graphical editor's wait option so it closes only after the edit is complete.
A failed or signalled editor cannot publish. A successful close still checks
the original destination, configuration, local hash, content safety, and
execution ownership before atomic replacement. An unchanged close is a checked
no-op and leaves a missing local file absent. If a concurrent update makes the
edit stale, reread and reconcile the document before editing again. Temporary
copies are cleaned up after the command.

Through MCP, call `guidance_read` once before first managing a run for each
project, even when issue reporting is disabled. Supply `projectPath` and, when
needed, `projectConfigurationPath`. Read the returned `combinedContent`; retain
`localContent`, `localHash`, and the resolved paths when preparing an edit.
MCP never opens an editor. After execution releases ownership, send the complete
replacement to `guidance_update`, for example when the local file was absent:

```json
{
  "projectPath": "/path/to/project",
  "localContent": "# Local additions\n\nRun service checks in the documented development container.\n",
  "expectedHash": null,
  "idempotencyKey": "<unique-opaque-key>"
}
```

For existing content, pass exact `localHash` as `expectedHash` with the original
configuration selector. Empty `localContent` publishes no additions. Retry a
lost response with identical arguments/key. Receipts contain `projectPath`,
`localPath`, `localHash`, and `updated`. A stale edit requires a reconciled whole
document and a new mutation/key. Keep only stable project lessons here.
