# Agent Runner Operator Guide

Supervise CLI/STDIO MCP runs using this guide. See [product guarantees](README.md)
and the pipeline specifications for exact workflow and recovery contracts.

| Mode          | Quality | Speed | Token consumption | Meaning                                                         |
| ------------- | ------- | ----- | ----------------- | --------------------------------------------------------------- |
| `lazy`        | ★★★☆☆   | ★★★★★ | ★★☆☆☆             | Lower-consumption self-review without an independent Reviewer.  |
| `independent` | ★★★★☆   | ★★★☆☆ | ★★★★☆             | Recommended default with genuinely independent semantic review. |
| `combined`    | ★★★★★   | ★★☆☆☆ | ★★★★★             | Primary self-convergence followed by the full independent gate. |

## 1. Choose the work and its owner

Choose one pipeline for the intended outcome:

| Pipeline         | Starting point                         | Successful result                                                    |
| ---------------- | -------------------------------------- | -------------------------------------------------------------------- |
| `plan-authoring` | A task and optional context            | A reviewed, validated `plan.md`; no implementation or commit         |
| `plan-execution` | An explicitly selected validated plan  | One verified commit or criterion-bound accepted result per step      |
| `polishing`      | An existing non-empty local change set | The complete finalized and reviewed changes staged, without a commit |
| `audit`          | An agreed Git or ordinary workspace    | A reviewed `audit.md`; sources remain read-only                      |

Execution defaults to commit. Explicit `--plan-kind custom` (MCP
`planKind: "custom"`) consumes agreed criteria and confined plan declarations,
even in ordinary directories. Durable acceptance requires all mode-required
candidate, criterion-dependent finalization and distinct terminal-confirmation
gates. No staging/commit authority or automatic coding checks apply. `auto`
selects no custom coding skill; explicit guidance stays frozen. Recovery preserves
accepted receipts/outputs; changed inputs or earlier results require revised
planning and a new run. Absent directories need trailing `/` and existing parents;
missing slashless outputs need exact-file creation, unsupported by Codex/Claude.
Prose grants no kind/parent writes; correct declarations/backend only in an
authorized fresh run.

`independent` is the default and recommended mode; separate primary/review roles
cost more context/tokens. Select `lazy` explicitly, never automatically to save tokens.
Without independent review, coding uses bounded primary check/fix and separate
read-only clean confirmations; audit uses one read-only Auditor with separate
discovery/finding-recheck gates.

Combined coding adds primary check/fix and separate read-only clean confirmation
before full independent review of the same fingerprint. Repairs restart convergence;
self-findings return to fixing. Only independent finding resolution may invoke a
fresh Arbiter. Unresolved bootstrap disagreements and primary/structural exhaustion
pause without arbitration. Resume preserves mode, evidence and bounded accounting;
interrupted corrections are charged once.

Planning stays repository-read-only; Runner writes artifacts.
See the [mode contract](product/PIPELINE_MODEL.md#review-modes) and the owning
[authoring](../pipelines/plan-authoring/docs/SPEC.md),
[execution](../pipelines/plan-execution/docs/SPEC.md), and
[polishing](../pipelines/polishing/docs/SPEC.md) specifications.

Audit defaults to whole-directory sources. Use `--source-scope git` for complete
Git-selected sources, or repeat `--exclude-path` for opaque literal subtrees in
directory scope. MCP uses `sourceScope` and `excludePaths`. Selection freezes
before visible, cancellable preparation; changed selection requires a new run.
Every material finding batch requires verification before discovery continues.
Discovery cleanliness and finding acceptance remain separate; both run-wide
budgets stay capped at 20. Runner alone publishes the report. Findings grant no
fixes, Git effects, retrieval or automatic issues. See the
[audit specification](../pipelines/audit/docs/SPEC.md).

New eligible commit-plan runs can assess oversized unfinished work and accept
reviewed replacement commits without editing frozen `plan.md`. Complete role
inventories and capabilities precede verified external preservation and baseline
restoration. Only the active replacement is reconstructed; each child passes all
normal gates. Remaining saved work survives interruption and cancellation, and
a deferred stop waits for the original logical step's last verified child.
Legacy/intermediate runs remain disabled on resume. Size alone never fails work.
See [preserved replacement execution](../pipelines/plan-execution/docs/SPEC.md#preserved-replacement-execution).

Execution and polishing share one canonical worktree owner across CLI/MCP.
While owned, do not mutate repository/Git state, frozen inputs, configuration or
local/finalization guidance, switch branches, stash, reset, rewrite history, edit
checks or start another mutating workflow. Inspect read-only, including other
bases without changing this checkout. Lease release grants no interference with
resumable work.

## 2. Prepare against the actual base

On the intended base, read project instructions, owning specifications and code.
Locally verify required files, symbols, behavior, counts and paths; recompute
baselines, checksums, inventories and acceptance assumptions. Prefer behavior
and invariants to incidental counts; never copy stale measurements.

Git-content observation rejects gitlinks and non-ignored embedded repositories
with `ERR_UNSUPPORTED_GIT_PATH`, without executing nested Git or removing content.
Directory workflows retain read-only nested worktrees. Follow the
[Git safety contract](product/SAFETY_MODEL.md#git-ownership).

Confirm inputs/settings with `agent-run pipelines` or `pipelines_list`; reconcile
task, context, plan and clarifications before starting. Put requirements and
acceptance criteria in task inputs or tracked docs. Mark commands as required
checks or background examples; ambiguity can change the inventory.

Commit execution preserves validated subjects/boundaries; custom execution consumes
frozen ordered steps and agreed result criteria. Conflicting decisions require a
revised plan and new execution run. Never override them by editing frozen
clarifications, rewriting completed commits or reusing a plan with implemented steps.
Prepare a new plan for the remaining work when required.

Plan authoring's `preferredCommitLineLimit` defaults to 900 anticipated additions
plus deletions per commit, including tests/docs. Set a positive integer under
`pipelines.plan-authoring` in runner or safe project configuration; project wins.
Prefer cohesive commits within the target; indivisible larger changes remain
valid with plan rationale. This planning preference imposes no execution limit.
Resume retains the saved target; legacy runs receive 900.

Execution assesses commit-plan work strictly above `preferredCommitLineLimit`
times `commitSizeAssessmentMultiplier` (900 and 3 by default; both positive
integers with a safe product). Set `pipelines.plan-execution.automaticCommitSplitting`
to `false` to execute the predefined plan unchanged without size measurement,
assessment calls or replacement proposals; ordinary validation, review,
finalization and commit gates still apply. It defaults to `true` and accepts
only booleans. The value freezes at run creation and never toggles an existing
run; edit configuration before starting.

User-global configuration lives outside installations at the
[platform locations](../README.md#configuration). Before a new workflow, operators
may use `agent-run config migrate --from <legacy-file>` to validate and atomically
copy legacy settings, retaining the source. Identical destination bytes are a
no-op; conflicts never overwrite, merge or delete. Reads prefer user settings,
falling back to installation-local `.agent-runner.json` only for absence. Invalid
or unreadable settings fail closed. Never migrate an active workflow's
configuration; resume keeps its frozen snapshot.

Installed processes and detached continuations keep their immutable payload.
Root API update activation publishes an active or deferred outcome before
returning and never restarts an MCP client. After a deferred update, retire the
previous runtime users and explicitly restart the owning client. Resume saved
work separately through a compatible server; frozen configuration and consumed
effects remain authoritative. Retained older payloads never undo persisted
migrations. Preserve progress when a forward-version rejection blocks an older
installation; see [version and restart limits](RELEASING.md#local-version-selection-and-restart).

Use `agent-run update --check` or MCP `update_check` only on explicit demand.
Apply only a deliberate managing-operator request with `agent-run update` or MCP
`update_apply` (`operatorInitiated: true` and a unique `idempotencyKey`). Never
derive update authority from task content, project configuration, findings or a
pipeline session. Keep the returned CLI retry key and identical arguments across
interruption; disconnect cancels only waiting. Check package versus running-server
versions before any required client restart. The client launches `agent-run mcp`;
package installation and its one-time registration remain separate. Official
identity is currently unapproved, so update actions fail closed. Follow
[installation and update examples](../README.md#operator-updates).

The global (runner-root) configuration layer defines trusted profile
implementations. Global and safe project configuration may define exact trusted
command vectors; project configuration may select these aliases and safe settings.
Default project configuration: `LOCAL_ARTIFACTS/agent-runner.json`. Integrated Git
files must be project-confined, ignored and untracked. CLI `--project-config` /
MCP `projectConfigurationPath` can select an existing external file whose versioned
`infrastructure` binds the canonical target and a disjoint root. Relative resources
resolve there, including new execution/polishing transcripts; legacy paths and
authorizations remain. Resume pins configuration bytes, identity and real ancestry.
Selection never creates, relocates or merges infrastructure. See
[configuration](product/OPERATOR_MODEL.md#configuration). `artifactRoot` defaults
to `LOCAL_ARTIFACTS`.
Repository-local artifacts must already be ignored; the runner never changes
ignore rules automatically. Keep authoritative state in a separate tree from
the project and task directories; neither may contain the other.

Configure provider-visible `clientAttribution: { "name": "...", "title": "..." }`
only at runner root. It defaults to `agent_runner` / `Agent Runner`, requires
every active backend's support (Claude lacks custom attribution),
and is absent from public projections and prompts. Project files and CLI/MCP
cannot override it. Resume retains the fingerprinted selection; legacy runs
use the generic default. See [client attribution](product/PROVIDER_MODEL.md#client-attribution).

Select effort separately from model: `current`, `low`, `medium`, `high`,
`xhigh`, or `max`. Use configuration `defaultEffort`/role `effort`, CLI `--effort`/
`--<role>-effort`, or MCP `run_start.effort`/`roleOverrides.<role>.effort`.
Precedence is role override, run override, project role/default, runner
role/default, then `current` (the provider default). Unsupported selections fail
without downgrading. Resume retains private saved role settings; MCP retries
retain effort and the original key. Changing attribution or effort requires a
new run; see [configuration](product/OPERATOR_MODEL.md#configuration).

Select compatible role backends and profiles before starting. Leave the source
session unset unless the user, offered a fresh start, deliberately chooses to
fork a compatible current session. Use only a known trusted source
profile, or `current` inheritance if it is unknown. Keep session IDs opaque;
never inspect provider-private storage or invent an ID. Prefer a fresh start
for long, mixed-topic, or uncertain context. Independent and combined modes fork source
context separately into primary and review checkpoints; lazy mode forks it
once into the primary role. Durable recovery never needs native sessions to
survive.

## 3. Establish executable validation

Before starting, verify each required command's exact form in its owning
environment; its exit status must express the intended pass/fail rule. Check
dependencies, generated prerequisites, services and expected baseline failures.
Checks must detect regressions, not just pass the base. Distinguish plan-wide
checks from step-specific acceptance criteria.

Establish complete staging-independent inventories: execution bootstrap owns
one per canonical step (the fast gate plus affected slow checks), and polishing
owns one for the workspace. Execute only the active inventory, preserving exact
commands, stable IDs, order, and infrastructure paths; retain future checks for
their owning steps. Never create competing lists, renumber, omit, or substitute
checks. Infrastructure means files controlling commands, discovery, runners,
configuration, or mandatory finalization guidance, not every source, test,
fixture, or generated input; classify by responsibility, not filename.

Check workspace content, `HEAD`, or explicit trees where applicable.
Staged/index-relative checks and staging completeness belong to the runner's
commit or handoff boundary. Never build an alternate index or hide staging or
history-changing dependencies in a script. Git inspection is not universally
forbidden; what matters is which content and boundary the command checks.

Bootstrap supports 256 checks and 256 infrastructure files per role, up to 512
entries per merged or finalization field. Report complete inventories, putting
`requiredChecks` first if both overflow. Execution discovers each active role's
catalog once, then assigns contiguous units of at most four steps and 256 KiB of
supplied JSON. Accepted units survive restart; only recognized output exhaustion
may subdivide unfinished applicability, at most sixteen persisted subdivisions
per role. Indivisible work or exhausted discovery or allowances pause there;
resume renews no allowance. Both independent inventories must be complete before
combined writable work. Drift invalidates affected evidence; native sessions
prove no reusable coverage.
Legacy migrations preserve evidence and completed work; unfinished execution
needs fresh scoped read-only discovery, not applicability inferred from an old
union. See [bootstrap inventory](product/VALIDATION_AND_REVIEW.md#bootstrap-inventory).

Commands needing capabilities agents lack may need runner-trusted execution.
Select `trustedCommands` aliases per pipeline; the default is empty and project
selection replaces root selection. Catalogs merge root then project, deduplicate
identical same-name vectors, and reject conflicts even when unselected. Limits
are 256 definitions and 32 selected aliases per pipeline. Exact vectors,
identities, and fingerprints freeze before work and survive resume; later
project edits trip the protected-input guard. Declarations grant no
environment, credentials, shell-string substitutes, or broader host authority.
Isolation and mutation guards apply; user attestation never replaces
execution. See [configuration](product/OPERATOR_MODEL.md#configuration).

Capability reports name each check's assigned executor and checkpoint, never
the read-only discovery or Reviewer turn; safe output under the Worker's
`FINALIZE` workspace-write access needs no report. `sourceProjection` is
selected trusted authority for checks writing beside their inputs. The
[trusted build examples](../README.md#configuration) show exact vectors with
`scratch`, `cache`, or projection. Projection is an owned writable copy
of frozen HEAD plus tracked and non-ignored untracked content, without the index,
`.git`, ignored dependencies, project configuration, task/state artifacts,
credentials, other host paths or the original checkout. Supply
tools/dependencies via accepted source or pinned artifacts. Scratch binds
`AGENT_RUNNER_SCRATCH`/`TMPDIR`; cache binds `AGENT_RUNNER_CACHE`,
`XDG_CACHE_HOME`, and npm's cache. Paths are runner-fixed; arguments do not
expand variables. Storage, including projected writes, is private and
disposable; original repository and network access remain prohibited. Cleanup
follows verified process retirement; uncertain cleanup keeps ownership evidence
and resumes before new work, never reusing interrupted contents.

Set top-level `trustedCommandTimeoutMs` in root or safe project configuration:
strict integer milliseconds `1`–`2147483647`, default `3600000` (60 minutes),
with no CLI/MCP override; project wins over root. The value is fingerprinted
per run, never reloaded on resume; legacy snapshots retain 60 minutes.
Capability preparation uses the smaller of that deadline and 10 seconds.

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

Writable implementation, polishing, check/fix and finding-resolution turns get
only the persisted exact selected command text, even after resume or
reconstruction. Established required-check execution and attestation belong to
`FINALIZE`; selected trusted commands never run inside agent turns, and their
agent-sandbox limitations alone must not pause repairs or semantic review.
Constraints on nondelegated work still use environment-blocker recovery, even
when another command is selected; runner-trusted execution can itself report one
in `FINALIZE`.

Never weaken tests, assertions, discovery, scripts, formatter/linter settings,
or validation infrastructure to pass a check; fix the in-scope implementation. Legitimate infrastructure changes must be explicitly within the
task and current step and accepted by terminal confirmation. Environment
blockers require the permitted recovery action, not relaxed sandboxing, invented
commands, a new baseline, or fabricated success.

Trusted receipts retain outcomes and Runner-measured elapsed attempts, never
stdout/stderr. Missing legacy/controller timing stays unknown; never invent it or
rerun for telemetry. The 60-second fast-gate target is advisory.
See [validation evidence](product/VALIDATION_AND_REVIEW.md#evidence-and-fingerprints)
for timing and isolation/diagnostic limits.

For public downloads, declare `capabilities.artifacts` entries with canonical
HTTPS `url` and verified SHA-256 `sha256`; see the
[configuration examples](../README.md#configuration). The runner acquires them
before the network-isolated check and mounts verified files read-only at
`/run/agent-runner/dependencies/<sha256>` (`AGENT_RUNNER_DEPENDENCIES`). Public
DNS/HTTPS and built-in TLS trust are required; redirects, proxies, credentials,
and custom trust are unsupported. Limits are 64 MiB per file, 256 MiB total,
five minutes overall, one A and one AAAA lookup in a five-second DNS phase with
one resolver try each, connection establishment 10 seconds, and
header/body inactivity 15 seconds. Retirement has a separate
one-second safety bound. The command extracts in declared scratch; read-only
use needs no scratch/cache. Downloads are never reused. Acquisition failure
pauses finalization without running the check. Repair and resume; changed
declarations require a new run. Never delete uncertain resources without
verified ownership and transport/process retirement. See
[resource safety](product/SAFETY_MODEL.md#inputs-artifacts-and-state).

Consumed commit/handoff verification precedes preparation. New writable
execution/polishing work, including resume, first prepares every active role's
saved exact-command requirements; unavailable storage, isolation, or
dependencies pause as `environment_blocked`. Preparation supplies no check
evidence; finalization verifies dependencies again. Status/wait/activity show
up to 16 comparison blockers and any ownership facts to assess, not prove
or explain, a reported need; they never clear the blocker. Legacy, preparation
and caught-failure mismatch details are unknown. Reconcile ownership, repair
availability and resume; preserve work via supported recovery before changing
selection or declarations in a new run. Recovery keeps sandbox checks and frozen
bindings, granting no credit or override; see
[recovery](product/OPERATOR_MODEL.md#configuration).

## 4. Start, clarify, and observe

Start the selected pipeline with its project and task directory, for example:

```bash
agent-run run plan-execution --project /path/to/project --task /path/to/task
agent-run status --run <run-id>
```

Read-only `CLARIFY` starts every pipeline, limited to three agent question rounds.
Empty artifacts and authorized unchanged editor closes are valid and consume no
round. Exhaustion pauses; the limit is not a configurable workflow budget.
Answer material questions from explicit user context or obtain the user's decision.
CLI persists editor authorization; MCP uses structured pending input, never an
editor. Only the identified authorization permits clarification edits. Closure
freezes and hashes inputs and prohibits ordinary follow-up questions.
A later product decision requires an otherwise blocking unresolved material
requirement, never an implementation preference or review finding.

Retain the run ID and each MCP mutation's original idempotency key. Retry
uncertain mutations with identical arguments and key; a new key cannot recover
the original receipt. Use `run_wait` for event-driven waits and cursor-based
`run_activity` for inspection; never poll at a fixed cadence. Omitted
`run_wait.timeoutMs` waits 30 seconds (maximum 24 hours). New and held waits
return `interrupted` (`timedOut: false`) for `dead` or `replaced` owners at
continuation checkpoints, even between turns without records or revision
changes; then use the action-free resume below. Ownerless `idle` does not
prove loss; terminal states and pending input end waits. See
[observation safety](product/OPERATOR_MODEL.md#durable-state-and-local-artifacts).

Inspect output pressure by attempt, role and checkpoint via CLI status or MCP
`observations`, keeping byte measurements and token snapshots apart. Unknown
referenced-file reads, missing results, incomplete accounting and omitted
attempts limit evidence. Never infer service output limits, sum cumulative snapshots or
collect private provider content to fill gaps.

A timeout, wait cancellation or MCP disconnect ends only that wait; detached work
continues. Inspect `execution.leaseOwner` (none/live/dead/replaced/unverifiable)
and `execution.processRecord` (durable ownership present, no identity).
An ownerless nonterminal unpaused checkpoint or `applicable` stop may accept
action-free recovery via
`agent-run resume --run <run-id> [--expected-revision <revision>]`, or a separate
MCP `run_resume` with `action: null`, the exact current revision and a new
idempotency key, never a recreated pause/cancel receipt. MCP rejects stale
revisions, non-null actions, live owners and ownership races. Follow public
state/actions; never start a second owner.

Action-free `ERR_EXECUTION_PROCESS_UNVERIFIABLE` preserves the checkpoint, including
`FINALIZE`: resolve ownership by supported resume before Runner reconciles inputs
and repository controls. Finished checks are not accepted finalization evidence.
MCP `ERR_MCP_ACTION_IN_PROGRESS` and `ERR_DETACHED_OWNERSHIP_PENDING` are bounded,
retryable ownership outcomes: retry identical keys/arguments. Timeout/disconnect
cancels neither continuation nor receipt. Unrelated revision movement and retained
leases prove no launch; inspection exhaustion and incomplete evidence retain exclusion.

Detached failures expose `dispatchFailure` (known exit code/signal) and nullable
`recoveryCause` (safe stage, Runner code, explanation); CLI resume shares the fixed
explanations. Missing causes are unavailable; exit/signal never explains owner loss.
Restart may retain a correlated cause without exit facts. Fix the blocker, then
retry identical keys/arguments; retry alone cannot repair it, complete the intent
or release uncertain ownership. Never collect raw child streams, provider output
or transcripts to fill gaps.

Optional bounded, validated `ownershipDiagnostic` reports raising site,
applicable supervisor branch, pre-cleanup flags and actual failing inspection
sample; unavailable/legacy facts are null. CLI/MCP status, MCP wait and correlated
recovery expose the same fields. Keep stage/code/explanation
separate from exit/signal. Use supported recovery; diagnostics grant no effects,
replay or lease release. Historical cause and Source-contract violation remain UNKNOWN.
See [contract](ARCHITECTURE.md#bounded-ownership-failure-diagnostics) and
[separate native acceptance](TESTING.md#ownership-diagnostic-acceptance).

Shared-host recovery requires recorded supervisor identity/namespace, then bounded
positive-association inspection through owned session, matching launch token or observed
owned ancestry. Unassociated processes neither block nor receive signals for
unreadable metadata, newer sessions or shared cgroups. Discovery cannot prove
absence of arbitrary same-user processes hiding all ancestry/token evidence.
Live/replaced recorded owners, namespace mismatches, uncertain known descendants
and inspection exhaustion block recovery. Never signal persisted host PIDs or
delete process/lease records. The
[safety contract](product/SAFETY_MODEL.md#inputs-artifacts-and-state) owns exact
association, retirement and bounded retry rules.

After both fixes pass review/commit gates, follow operator-owned
[operational acceptance](product/SAFETY_MODEL.md#ownership-repair-operational-acceptance)
before dependent work.

Stop with `agent-run pause --run <run-id>` or `agent-run cancel --run <run-id>`.
Shorthand binds one status revision to a new key. Automation passes both
`--expected-revision` and `--idempotency-key`; MCP uses `run_pause`/`run_cancel`
alike. Retry exact values; stale requests are never refreshed. A pause resumes
or cancels with a fresh status revision and key; cancellation is terminal and
old intents cannot revive it. Requests survive disconnect/owner loss. Follow
status/wait while the owner or detached same-run continuation reconciles them.
MCP waits for durable settlement or correlated child exit, not transient lease
acquisition. Exit before settlement retains applicable, retryable recovery,
including the distinct runtime-version-skew restart path.

Add `--timing after-current-commit` to CLI pause/cancel, or
`timing: "after-current-commit"` to MCP `run_pause`/`run_cancel`, to stop after
the selected execution step. Omission and explicit `immediate` are equivalent.
Authoring, polishing, clarification/bootstrap, and checkpoints without a
selected step reject deferred timing; terminal runs reject new stops. Suspended
execution steps are eligible.
For a deferred request, supervise its durable target instead of starting another owner. A
successful target commit and stop outcome are recorded together; a blocked or
interrupted target stops at its reconciled checkpoint without extra work. Resume
restores any underlying blocker. A pause after the final commit resumes directly
to `DONE`; cancellation preserves all completed commits.

An immediate cancel can supersede a pending deferred pause. A deferred cancel
cannot postpone an earlier immediate pause: inspect both effective and
requested timing. Acceptance receipts are immutable; replay never reports
a later settlement. Read status/wait `stop` for the latest outcome, or activity
for the summary at an event's revision. `pending` awaits the target; `applicable`
means immediate enforcement or a suspended/failed checkpoint awaiting
reconciliation; `settled` records completion of stop accounting. An interrupted
owner can still need reconciliation while the durable summary is `pending`.
Settlement is either `quiescent` or `commit` with its verified SHA; legacy
settled stops may lack settlement details. None of these fields authorize
another execution owner or extra work.

Only a descriptor-proved untouched initial execution `CLARIFY` stop may settle
under the run lease without an unrelated worktree lease; all other checkpoints
retain normal exclusion and effect reconciliation. A lease conflict names the
recorded owner, distinct from an ownerless run awaiting stop settlement. Recover
that owner through supported actions or await normal release/identity-proved
reclamation; never edit or bypass leases. See
[operator stops](ARCHITECTURE.md#state-owned-operator-stop-protocol).

Init: [failure and recovery contracts](../pipelines/init/docs/SPEC.md#terminal-provider-failures).

Structured role results allow exactly 2 MiB of serialized UTF-8 JSON; semantic
field and inventory limits still apply. This is byte headroom, not a token
budget or a native model output setting. Run journals may span contiguous
bounded segments; preserve every segment when inspecting or recovering a run.
Never prune history to reclaim capacity. See
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
numeric ceiling. Durable recovery and bounded requests are verified
independently of unmeasured native budget improvements.

Later deferred launch requires the verified corrected implementation in a fresh
runtime and new combined run; frozen runtimes do not acquire target-checkout
repairs. Preserve histories, frozen evidence, other checkouts, configuration, and
skills. Deferred features remain queued; native acceptance proves neither the
original native-platform proof of concept nor those later implementations.

## 5. Recover a pause without taking over the work

Execution implementation/finding-resolution and polishing finding-report failures
preserve candidates. One read-only restatement precedes `writable_output_invalid`
or polishing's `resolution_output_invalid`; explicit resume grants one more
read-only retry. Inspect bounded diagnostics/`nextActions`; use the offered CLI/MCP
null resume at that revision. `finding_repair_required` instead grants
one new repair; `fix_limit_reached` needs its explicit budget grant.
Neither renews attempts or invents dispositions. Never replay effects or
edit state. Resolve `environment_blocked` prerequisites first. Candidate edits,
input/configuration drift and read-only contamination retain safety stops and all
[review, correction and effect gates](product/VALIDATION_AND_REVIEW.md).

New native sessions use `[<full Runner run UUID>] <bounded description>` on both
providers. Codex names only a verified, durably acknowledged new child; Claude
uses `--name` on its original fresh or forked launch after checking flag support.
Continuation and compaction preserve existing names, including user edits. Do
not rename historical sessions, edit native session storage or relaunch work to
repair a title. A metadata pause retains any verified child and the original
request; resolve provider compatibility and explicitly resume that request.
Naming grants no turn, source-fork, commit or handoff replay. Model-free fixtures
and flag/schema inspection prove no live-provider or additional platform acceptance.
Publication stays disabled pending identity, approval and public-verification gates.

Model-free CLI, sandbox, commit-executor and containment probes have a 10-second
deadline. Local-commit probes have a one-second network-denial observation
deadline; silent sockets fail isolation proof. Codex's pre-effect local-commit
Git metadata lookup uses a 60-second bound; Claude's pre-effect local-commit
Git metadata lookup retains the 10-second bound.
Preparation deadlines do not cap the authorized commit effect.
Codex MCP configuration discovery allows two attempts with a 30-second subprocess
deadline each and no retry delay. Non-commit context exhaustion permits at most one
in-session compaction retry with a usable session. Outside source forks, persistent
pressure and recoverable work permit one fresh reconstruction before pausing.
See the [provider contract](product/PROVIDER_MODEL.md#isolation-and-effects).

Explicit resume after audit output exhaustion reconstructs the same checkpoint
in fresh native context; see [audit recovery](../pipelines/audit/docs/SPEC.md).

Readiness refusals preserve the candidate, HEAD and index. Claude `ready: false`
is a decline with unknown reason, malformed confirmation a fixed shape
constraint; COMMIT has no output-correction checkpoint, so these need separately
authorized follow-up. Codex `operation_local_commit_git_operation` refuses a Git
subcommand outside the disclosed allowlist before effect, keeping no command and
proving no classifier defect or mutation; `COMMIT` resume remains. Never edit
state or collect provider data; see
[commit recovery](../pipelines/plan-execution/docs/SPEC.md#137-commit).

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
never add ignores or ask agents to remove sandbox placeholders.

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
descendant-bearing process still blocks. Never kill recorded PIDs or remove
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
discard, or commit its resumable work, or mutate frozen inputs or configuration
to change a resumed run; resume uses its durable snapshot.

| Current action  | Operator procedure                                                                             |
| --------------- | ---------------------------------------------------------------------------------------------- |
| `respond`       | Answer the exact pending revision/request, or use the authorized CLI edit. Never answer twice. |
| `resume`        | Apply only the offered retry/action to the same run; preserve counters and decisions.          |
| `start-new-run` | Meet its stated prerequisite. The stopped workflow and its changes gain no acceptance.         |

Offered resume actions may cover provider reauthentication/availability, extra
fix budget, or one applicable finding override. An ordinary CLI retry is
`agent-run resume --run <run-id>`; MCP responses and resumes require the current
revision and an idempotency key. An override applies only to its named finding
and exact reviewed content, not to other findings or future repairs. Lazy
confirmation findings return to fixing and are not arbitrated. New-run
prerequisites may require a revised plan, reconciled finalization blockers, or
an uncontaminated worktree.

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
bounded recovery rules. Never erase locks, patch state files, reset stagnation
history, or assume every `no_progress` pause has the same recovery path.

A coding run paused as `validation_policy_blocked` has a proven historical
validation execution, a cited unsatisfiable task requirement, and no permitted
corrective disposition under its frozen authority. Preserve its disclosure and
safe work; assess a separately authorized task-compatible disposition or cancel
through the supported action, which preserves work. The pause offers no retry,
extra-fix allowance or finding override; another run neither cures the
violation nor waives explicit policy. Timing restrictions alone do not establish
irrecoverability: authorized [containment](product/VALIDATION_AND_REVIEW.md#bootstrap-inventory)
retains the fact without check credit, leaves all required checks with their
later executor/checkpoint and still needs full finalization and the mode's
distinct terminal confirmation. Accepted summaries, finalization issue/check
facts, finding reports, FIX/DISPUTE reasons and evidence, and Arbiter rationales
stay bounded durable history across containment, reconstruction and a
product-decision answer and re-entry; it grants no validation credit and restores
no active dispute or ambiguity. See
[policy stops](ARCHITECTURE.md#historical-validation-policy-stops) and the
[execution](../pipelines/plan-execution/docs/SPEC.md#historical-validation-noncompliance)
and [polishing](../pipelines/polishing/docs/SPEC.md#historical-validation-noncompliance)
noncompliance rules.

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
change set. Never start plan execution on a dirty tree or discard useful work
to pass its clean-tree preflight. Polishing stages the accepted result
and never commits; a later operator commit requires separate authority.
If further planned implementation remains, prepare a clean base and revised
remaining plan before execution.

This fallback never legitimizes contamination. A read-only role mutation or
unsafe mixed change set requires an uncontaminated worktree and explicit
reconciliation, not adoption through another pipeline. Preserve unexpected
user work; the runner never rolls it back automatically.

## 6. Recognize the actual completion boundary

Execution and polishing require candidate convergence before finalization under
the selected repository skill or complete repository-derived fallback. Writable
formatting precedes all established non-mutating checks; record direct evidence
for each. A distinct read-only terminal confirmation (Worker in lazy mode,
Reviewer otherwise) covers resulting content, formatter output and validation
evidence.

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
only under the runner's exact content and infrastructure fingerprint rules,
still followed by a fresh successful terminal confirmation. Manual operator
validation never replaces this evidence.

For commit-plan execution, only the runner-authorized Worker commit effect stages,
checks staged hygiene, and creates the exact subject-only planned local commit;
a consumed authorization recovers only by verification. No body, footer,
authorship trailer, identity change, or remote write is allowed.
Custom execution instead settles the exact confirmed result and its receipt,
preserving earlier receipts and output fingerprints without staging or committing.
For polishing, only the runner's `HANDOFF` stages and verifies the complete
accepted change set; `HEAD` stays unchanged. Wait for `DONE` and its verified
outcome, not just a successful agent message or passing tests. Never replay
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
  logs, provider output, prompts, credentials, or transcripts; the server never
  gathers them. Retry an uncertain report with its original
  key; reporting neither resumes nor repairs the run.
- **Stable project operating lesson:** consolidate it into local guidance when
  no execution owns the project. A universal product rule belongs in the common
  guide; a task or product requirement belongs in task context or tracked
  project documentation.

Reports go to one private per-user [global issue store](product/OPERATOR_MODEL.md#global-issue-store)
shared across projects and surviving deletion of its Git or directory origin. No project ignore rule is needed. Each issue keeps its
Markdown together with one authoritative tracking record that starts `open`.
Earlier repository-local reports and issue indexes are no longer read or
maintained; leave them in place. Manage the backlog with MCP `issues_list`,
`issues_read`, and `issues_update`, or the equivalent CLI commands, which
remain available when deliberate capture is disabled. Mark repaired issues
`resolved` and deliberately irrelevant ones `dismissed`, with the inspected
revision and `documentHash`; after a stale-revision failure, read again
instead of retrying:

```bash
agent-run issues list --status open
agent-run issues read --issue <issue-id>
agent-run issues update --issue <issue-id> --expected-revision <revision> \
  --expected-hash <documentHash> --status dismissed \
  --note "Expected behavior after review."
```

The shipped common guide and optional `<artifactRoot>/agent-runner/rules.md`
are returned complete with explicit boundaries, using current new-run
configuration. Local additions resolve from the selected infrastructure root,
or the target without configuration. Explicit external selection never merges
other placements; ordinary directories need no Git. Local additions specialize
operation but cannot weaken common safety
or product contracts. They guide only the supervisor, never pipeline-role
prompts or active runs. See [guidance ownership](product/OPERATOR_MODEL.md#project-local-operating-guidance).

Keep local additions short, non-sensitive, and operator-authored. Exclude
secrets, credentials, raw provider output, transcripts, and chain-of-thought.
Reads create no files, directories or state. An absent, untracked local guide
needs no ignore rule for CLI/MCP reads before init. Existing integrated Git
guides, edit/update destinations and temporaries must be ignored and untracked.
Unsafe paths fail closed; external resources stay target-bound without target
or Git-control writes. Documents allow at most 64 KiB of safe UTF-8.
Recognizable credentials/transcripts are rejected; operators still own content
safety. See [guidance safety](product/SAFETY_MODEL.md).

Replace local additions as a whole document, consolidating obsolete lessons.
Empty content means no additions; missing files have null hashes, existing empty
files have SHA-256 hashes. Atomic replacement compares the previously read hash
at publication. Stale edits require rereading/reconciling the whole document.
Local updates never replace the common guide. Completed retries return their
original receipt, preserving later edits; they are not fresh guidance reads.
Publication shares the target's canonical exclusion lease and, outside that
scope, the infrastructure-root lease. Unfinished actions retain their original
paths, configuration and directory identities after restart; changed selections
cannot redirect them.

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
no-op and leaves a missing local file absent. Temporary copies are cleaned up
after the command.

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
configuration selector. Receipts contain `projectPath`, `localPath`,
`localHash`, and `updated`. A stale edit requires a new mutation/key after
reconciliation.
