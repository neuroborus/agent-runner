# Agent Runner Operator Guide

Use this procedure when supervising Agent Runner through the CLI or its local
STDIO MCP server. The [product documents](README.md) own the current guarantees;
the pipeline specifications own exact workflow and recovery contracts.

| Mode          | Quality | Speed | Token consumption | Meaning                                                         |
| ------------- | ------- | ----- | ----------------- | --------------------------------------------------------------- |
| `lazy`        | ★★★☆☆   | ★★★★★ | ★★☆☆☆             | Lower-consumption self-review without an independent Reviewer.  |
| `independent` | ★★★★☆   | ★★★☆☆ | ★★★★☆             | Recommended default with genuinely independent semantic review. |
| `combined`    | ★★★★★   | ★★☆☆☆ | ★★★★★             | Primary self-convergence followed by the full independent gate. |

More token stars mean greater consumption. Ratings are relative guidance, not
measured provider guarantees.

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

In combined plan authoring, Planner check/fix and clean confirmation precede
independent Reviewer approval. Revisions restart
primary convergence. Self findings and structural exhaustion never trigger
arbitration. All planning turns remain repository-read-only and artifact writes
remain runner-owned. Every pipeline supports all three modes; resume retains
the saved mode and correction budgets.

Combined polishing uses independent bootstrap, Worker check/fix and read-only
clean confirmation, independent candidate review, finalization, and a distinct
Reviewer terminal confirmation. Content repairs restart primary convergence;
unchanged resolutions reuse only fingerprint-current finalization. Self-findings
return directly to fixing; only independent finding resolution may invoke Arbiter.
Unresolved bootstrap and exhausted primary budgets pause. Handoff remains
runner-owned staging without a commit, and resume preserves accepted evidence
and correction accounting.

Combined execution runs Worker check/fix and a separate read-only clean
confirmation before the complete independent candidate Reviewer gate. Both
candidate approvals bind the same content fingerprint. Finalization may format
that content; a distinct Reviewer terminal confirmation approves its resulting
fingerprint and validation evidence before one-shot commit authorization.
Content repairs restart primary convergence. Self-findings go directly to fixing;
independent findings retain disputes, withdrawals, exact recorded overrides, and
fresh on-demand arbitration. Unresolved bootstrap disagreements and primary
exhaustion pause without arbitration. Corrections remain bounded and interrupted
work is charged once; resume preserves the saved mode and consumed commits remain
verification-only.

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

Set portable effort with `defaultEffort` or role `effort` in runner/project
configuration, CLI `--effort` and `--<role>-effort`, or MCP `run_start.effort`
and `roleOverrides.<role>.effort`. Values are `current`, `low`, `medium`,
`high`, and `xhigh`; keep effort separate from the model ID. A role override
wins over a run-wide override, then project role/default, runner role/default,
and finally `current`. Explicit `current` retains the effective provider
default. Unsupported provider/model selections fail without downgrading.
Resume and detached execution reuse saved effort; status, wait, and activity
keep role configuration private. Retrying an MCP start requires the same effort
values and idempotency key. To select different effort, start a new run.

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

Bootstrap establishes one complete, staging-independent inventory. Keep its
exact commands, stable check IDs, order, and validation-infrastructure paths.
Do not duplicate it in competing lists, renumber it, omit checks, substitute an
equivalent command, or add infrastructure paths because they seem relevant.
Infrastructure describes what controls validation; it is not a second list of
acceptance criteria or every file whose contents are being checked.

Use checks over workspace content, `HEAD`, or explicit trees where applicable.
Staged/index-relative checks and staging completeness belong to the runner's
commit or handoff boundary. Do not build an alternate index or hide a dependency
on staging or changing commit history inside a script. Git inspection is not
universally forbidden: the relevant distinction is which content and boundary
the command actually checks.

Execution and polishing bootstrap each support 256 checks and 256 infrastructure
files per role, with up to 512 entries per merged or finalization field.
Infrastructure means files owning commands, discovery, runners,
configuration, or mandatory finalization guidance, rather than every source,
individual test, fixture, or generated file consumed by a check. Classify by
responsibility, not filename. Report complete inventories; when capacity is
exhausted, report `requiredChecks` first if both fields overflow. Do not omit
entries or weaken checks. Byte limits remain unchanged, and legacy execution
and polishing runs retain their saved evidence and completed work on migration.

Commands requiring unavailable sandbox capabilities, IPC, sockets, or host
services may need runner-trusted execution. Root and safe project
`trustedCommands` catalogs merge in root-then-project order. Identical same-name
vectors deduplicate; conflicts reject configuration even when unselected.
The merged catalog is limited to 256 definitions and each pipeline selection
to 32 aliases. Select root or project aliases separately
for every applicable pipeline; selecting it for plan execution does not select
it for polishing. The selection defaults to empty; a project selection replaces
the root selection. Exact vectors, identities, and fingerprints are frozen
before agent work and reused on resume. Later project configuration edits
trigger the protected-input guard. Definitions cannot add environment,
credentials, shell-string substitutes, or broader host authority.
Trusted checks retain isolation and mutation guards; they do not grant broader
agent permissions or accept user-attested results.

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

For an offline build whose project-provided `build.js` supports `--out-dir`, a
trusted declaration can request transient output and cache storage:

```json
{
  "schemaVersion": 1,
  "trustedCommands": {
    "offline-build": {
      "command": "node build.js --out-dir /run/agent-runner/scratch/build",
      "executable": "node",
      "arguments": ["build.js", "--out-dir", "/run/agent-runner/scratch/build"],
      "capabilities": { "scratch": true, "cache": true }
    }
  },
  "pipelines": { "polishing": { "trustedChecks": ["offline-build"] } }
}
```

This fragment works in runner configuration or its safe project overlay. The
project must already have the build tool and dependencies. Scratch provides
`AGENT_RUNNER_SCRATCH` and `TMPDIR`; cache provides `AGENT_RUNNER_CACHE`,
`XDG_CACHE_HOME`, and npm's cache binding. Paths are fixed by the runner; exact
argument vectors do not expand environment variables. Both directories are
private to one execution and removed after its process tree retires. Repository
writes and network access remain prohibited. Interrupted cache contents are not
reused. An uncertain cleanup keeps ownership evidence for operator recovery;
resume retries cleanup before new work.

When a build needs a pinned public download, extend that command's `capabilities`
with `artifacts`. For example (replace the illustrative URL and digest with the
canonical HTTPS URL and verified SHA-256 of your file):

```json
{
  "scratch": true,
  "cache": true,
  "artifacts": [
    {
      "url": "https://downloads.example.com/tool.tar.gz",
      "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }
  ]
}
```

The build driver reads the verified file at
`/run/agent-runner/dependencies/<sha256>` or uses `AGENT_RUNNER_DEPENDENCIES`.
The mount is read-only. The runner acquires files before launching the exact
check, which remains network-isolated. Acquisition requires public DNS and HTTPS
with built-in TLS trust; redirects, proxies, credentials, and custom trust are
unsupported. Limits are 64 MiB per file, 256 MiB total, and five minutes overall,
with shorter DNS, connection, and inactivity deadlines. No automatic extraction
or host setup occurs: the declared command must extract or prepare inputs in
its declared scratch directory. Artifact-only commands need no scratch or cache
if they only read verified files. Downloads are never reused across executions.
Acquisition failures pause finalization as an environment blocker without running
the check. Repair the environment and resume; changing declarations requires a
new run. Do not delete uncertain resources until their ownership and transport
or process retirement have been independently verified.

Plan execution and polishing also prepare required capabilities before each writable
checkpoint, including on resume. Bootstrap and legacy read-only discovery save
exact-command requirements from every active role; unavailable storage,
isolation, or dependencies pause as `environment_blocked` before writable work.
Repair the environment to retry the saved request. A reported agent-sandbox
limitation is satisfied only for that exact delegated command when runner
inspection succeeds. Preparation does not execute required checks or provide
check evidence; dependencies are verified again during finalization.

## 4. Start, clarify, and observe

Start the selected pipeline with its project and task directory, for example:

```bash
agent-run run plan-execution --project /path/to/project --task /path/to/task
agent-run status --run <run-id>
```

Every pipeline starts with read-only `CLARIFY`. Answer material questions from
explicit user context; otherwise obtain the user's decision. An empty
clarification document and an authorized editor close without changes are
valid. CLI uses a persisted editor authorization; MCP uses structured pending
input and never opens an editor. Only the identified authorization permits
clarification changes. Once clarification closes, inputs are frozen and hashed;
ordinary follow-up questions are prohibited. A later product decision is an
exception only when progress is impossible without a genuinely unresolved
material requirement, not an implementation preference or review finding.

Through MCP, retain the durable run ID and the original idempotency key for
each mutation. Retry an uncertain mutation with the same arguments and key.
A new key represents a new mutation and cannot recover the original receipt.
Use `run_wait` for one event-driven wait over the desired interval. Use
`run_activity` only for deliberate current or historical inspection, with its
cursor. Do not poll status, activity, or waits at a fixed cadence.

A timeout, wait cancellation, or MCP disconnect ends only that wait. Detached
work continues. Inspect the returned execution state to distinguish a live
owner, an interrupted turn, and idle work. An ownerless interrupted turn may
accept action-free resume at the exact revision; it is not permission to start
a second owner. Follow the current public state and actions.

To stop active work, use `agent-run pause --run <run-id>` or
`agent-run cancel --run <run-id>`. The shorthand reads status once and binds
that revision to one fresh key. Automation may instead provide both
`--expected-revision` and `--idempotency-key`; retry with those exact values
and never refresh a stale request silently. MCP supervisors use `run_pause` or
`run_cancel` with the same explicit revision-and-key rule. Pause preserves a
resumable checkpoint. Cancellation is terminal and older intents cannot revive
it. A pending request is durable across disconnect or owner loss; status and
wait expose its bounded kind, revision, timing, and target step while the live owner or a detached
same-run continuation reconciles it.

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

## 5. Recover a pause without taking over the work

Execution reports `plan_revision_required` when the current planned subject is
already at HEAD or an external commit moved HEAD from the saved baseline. The
same pause applies when context claims the current step landed or directs work
to skip, reorder, or move to a later step. Matching structured step fields do not
override contradictory instructions; quoted examples and future-plan discussion
remain valid when they do not redirect current work. The
runner retains the selected step and completed-commit history; it does not count
external work as a completed step. Step one can be visible before bootstrap is
complete. Revise the plan and start a new run; do not move HEAD or edit frozen
inputs to force the old run forward. Runner-owned consumed commits retain
verification-only recovery before this guard.

**A pause is not completion.** Read its reason, bounded evidence, pending input,
and current `nextActions`. When the run is resumable, resolve only the permitted
cause and resume that same run. Do not manually finish, validate, rewrite,
discard, or commit its resumable work. Do not mutate frozen inputs or
configuration to change what a resumed run will do; resume uses its durable
snapshot.

| Current action  | Operator procedure                                                                                                                                                                                                                                |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `respond`       | Answer the identified pending request with its exact revision and request ID through MCP, or use the runner-authorized clarification edit and CLI resume. Do not answer a consumed request again.                                                 |
| `resume`        | Apply only the offered retry or explicit action: for example restore provider/service availability, grant the offered extra fix budget, or authorize one applicable finding override. Resume the same run; preserve prior counters and decisions. |
| `start-new-run` | Follow the stated prerequisite: revise the plan, reconcile finalization blockers, or obtain an uncontaminated worktree. This action does not authorize retrying the stopped workflow or silently accepting its changes.                           |

For an ordinary CLI retry, use `agent-run resume --run <run-id>` only when the
current action permits it. MCP responses and resumes require the current
revision and an idempotency key. An override applies only to its named finding
and exact reviewed content, not to other findings or future repairs. Lazy
confirmation findings return to fixing and are not arbitrated.

A legacy plan-execution `FAILED` run may now offer a null `resume` action with
`CONFIRM` as its target after an opaque `ERR_CODEX_TURN_FAILED` / `turn_other`
failure. Follow that offered action through CLI or MCP. The runner proves the
accepted candidate and passing finalization from durable history and rechecks
inputs, content, validation infrastructure, and Git safety before retrying
confirmation. It preserves completed commits and accounting, including a
proven non-actionable `pendingCorrection` marker. Do not clear the marker or
edit the journal. Missing provenance or conflicting work grants no recovery
action; a matching error name or migrated snapshot alone is insufficient.
Repeated provider unavailability pauses at the same confirmation checkpoint.

Classify by current actions rather than an error-name shortcut. Provider usage
exhaustion and environment limitations may be resumable; exhausted budgets,
unsafe reconciliation, changed inputs, or ambiguous effects have their own
bounded recovery rules. Do not erase locks, patch state files, reset stagnation
history, or assume every `no_progress` pause has the same recovery path.

Owned execution requires Linux PID namespaces and system-installed bubblewrap.
The runner-trusted executor may reuse its already-private PID namespace for a
nested runner test when its sandbox correctly denies another namespace; it does
not relax that sandbox. Otherwise, unavailable containment fails before provider
work begins. Stops retain exclusion until the recorded supervisor and descendants,
including detached services, have stopped. Unknown ownership and older
group-only records remain conservative recovery barriers; an empty process
group alone does not authorize clearing them.

Codex `ERR_INVALID_CODEX_SCHEMA` is a terminal local request error, and
`ERR_CODEX_TURN_FAILED` with `turn_bad_request` is a terminal provider request
rejection. A recognized structured HTTP 400 schema rejection has the latter
classification even if Codex labels it `other`. These failures do not enter
provider-availability or output-correction recovery; follow the stopped run's
actions and correct the request defect before starting again. A genuinely
opaque `turn_other` retains one fresh reconstruction for eligible non-commit
turns and then the existing `backend_unavailable` pause. Native error payloads
and transcripts are not diagnostic evidence to collect or attach.

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

The canonical common guide is shipped with Agent Runner. Optional project-local
Markdown lives at `<artifactRoot>/agent-runner/rules.md`, using the same current
configuration resolution as a new run. The shared guidance capability returns
both complete documents with explicit boundaries and precedence. Local
additions may specialize project operation but cannot weaken common safety or
product contracts. They guide the supervising operator only: they are not
injected into Planner, Worker, Reviewer, or Arbiter prompts, persisted in run
state, or reloaded by active runs.

Keep local additions short, non-sensitive, and operator-authored. Exclude
secrets, credentials, raw provider output, transcripts, and chain-of-thought.
Reads do not create missing files or directories. Unsafe, linked, tracked,
non-ignored, overlapping, malformed, or oversized targets are rejected.
Each document is bounded to 64 KiB of valid UTF-8 with safe text characters.
Recognizable credential and transcript formats are rejected; this is not a
guarantee that arbitrary prose is free of secrets.

Edit additions as a whole document: rewrite, consolidate, or remove obsolete
lessons. Empty content means no local additions. A missing file has a null
hash; an existing empty file has its own SHA-256 hash. Replacement compares
the previously read hash inside the publication boundary and is atomic.
A stale edit requires rereading and reconciling the entire current document.
The common guide is never replaced by a local update. Completed idempotent
retries return their recorded receipt even after later edits; that receipt
describes the earlier operation, not a fresh read of current guidance.

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

For an existing document, pass its exact `localHash` as `expectedHash` and keep
the same configuration selector used to read it. Empty `localContent` removes
all additions by publishing an empty document. Keep the key and arguments for
retry after a disconnect or interrupted response; never give the same logical
mutation a new key. The bounded receipt contains `projectPath`, `localPath`,
`localHash`, and `updated`. If the edit is stale, reread and reconcile the whole
document, then submit that new mutation with a new key. Keep only stable project
lessons; task requirements, universal product rules, and defect reports belong
in their respective sources described above.
