# Plan Authoring Pipeline — Specification

## Goal

Create a deterministic, reviewable `plan.md` that the `plan-execution` pipeline
can consume without reinterpretation.

## Inputs And Artifacts

The pipeline receives a local Git repository, `task.md`, and optional
`context.md`. It manages two declared artifacts in the task directory:

```text
task/
├── clarifications.md
└── plan.md
```

`clarifications.md` is the durable user/agent question-and-answer transcript in
the common Markdown format defined by the root runtime. `plan.md` is the final
validated commit plan. Drafts and review state live under the runner's external
state directory.

Project content remains read-only except for these two resolved artifact paths,
even when the task directory is inside the target repository. Agents never
write either artifact directly: the runner creates or appends clarification
rounds, the user answers through a text editor, and the runner writes the final
plan atomically. No other tracked or untracked file, index entry, commit, or ref
may change.

## Configuration

The pipeline descriptor declares the `planner`, `reviewer`, and on-demand
`arbiter` roles and owns these settings:

```text
mode = independent
maxRevisionRounds = 15
stagnationWindowRounds = 3
```

`mode` accepts exactly `independent` and `lazy`. Missing values resolve to
`independent`, which remains the default and recommended mode because the
separate Plan Reviewer provides genuinely independent semantic review, at the
cost of more provider context and tokens. `lazy` is an explicit
lower-consumption choice that uses only the Planner and does not provide
independent review. It is never selected automatically.

Values may be overridden under `pipelines.plan-authoring` in the runner's
versioned `.agent-runner.json` contract or its safe project overlay. Role
objects live under
`pipelines.plan-authoring.roles` and may contain optional string `backend`,
trusted `profile`, backend-specific `model`, and decimal `contextSize`
selections. The root runtime applies the shared precedence rules
documented in [`docs/ARCHITECTURE.md`](../../../docs/ARCHITECTURE.md); this
pipeline owns only its roles, setting validation, and defaults. The root loads
an optional ignored `LOCAL_ARTIFACTS/agent-runner.json`, or an explicitly
selected confined project file, and permits it to select only runner-trusted
profiles and safe execution and pipeline values. CLI/MCP values win over the
project overlay, which wins over runner-root values. Explicit `--mode` or MCP
`run_start.mode` wins over both configuration sources. All configured role
objects are validated, but lazy mode resolves, probes, persists, and invokes
only the Planner. Reviewer and Arbiter configuration remains untouched for a
later independent run and is not exposed through lazy-run state. Resolved roles
and settings are persisted and not reloaded on resume.

On Linux, every Claude role that performs a read-only turn requires the
adapter's fixed, model-free exact-policy proof in addition to its CLI and native
sandbox dependencies. Through fixed no-shell bubblewrap arguments, the probe
runs an inert command through the resolved Claude executable's embedded
`apply-seccomp` helper and the outer user-namespace shape required by
`allowAllUnixSockets: false`. It uses the credential-filtered environment,
bounded time and output, no selected profile, authentication, or model call,
and retains no host diagnostic. It remains independent from the Runner-owned
local-commit executor probe, which this read-only pipeline does not require;
native session and structured-output capabilities retain their existing
CLI-based semantics.

A configured runner artifact root does not affect this pipeline. Its task-owned
`clarifications.md` and `plan.md` remain beside `task.md`.

CLI overrides use `--planner`, `--reviewer`, and `--arbiter`, with corresponding
derived profile, model, and context-size flags. Run-wide `--profile`, `--model`,
and `--context-size` defaults apply below role-specific CLI values. `--mode`
selects the descriptor setting. A new run may also use
`--fork-from <backend>:<session-id>` and optional separate
`--fork-profile <trusted-alias>` when the Planner and, in independent mode,
Reviewer match the source. Known source profiles supply those roles' `current`
profile; unknown source profiles require `current` and omit the native
override. In independent mode, each Planner and
Reviewer checkpoint's first eligible turn forks the source independently and
every Arbiter remains fresh. In lazy mode, the source is forked exactly once
into the logical Planner for the entire run. Later checkpoints continue that
child when compatible or reconstruct the Planner without another source fork.
`resume` uses the persisted lineage and one-time marker without another flag.
MCP leaves the source unset unless the user deliberately selects a compatible
current session after being offered a fresh start. It includes the known
trusted profile with that choice, or offers only `current` inheritance when the
profile is unknown. Prefer a fresh start for a long, multi-topic, or uncertain
session, especially when independent mode would fork its complete context more
than once.

## Persistent Run State

The root run store persists this pipeline outside the project and task
directories using the common contract in
[`docs/ARCHITECTURE.md`](../../../docs/ARCHITECTURE.md). Its versioned envelope
records canonical inputs, resolved active-role configuration, resolved pipeline
settings including mode, the initial repository baseline, hashes, revision
and clarification counters, pause state, optional source-session reference and
resolved profile, direct child role/session IDs with accepted-input and
pipeline-checkpoint context keys, and opaque plan-authoring state.
Drafts, findings, correction-round snapshots, stagnation evidence, the lazy
clean-confirmation fingerprint, one-time lazy source-fork marker, and bounded
lazy-checkpoint correction ledger and pending marker remain pipeline-owned
structured data in the external run state rather than task artifacts. A lazy
correction record contains only attempt `1`, its `CHECK_AND_FIX` or
`CLEAN_CONFIRM` phase, the exact draft fingerprint, and bounded Planner
field-and-constraint diagnostics; rejected output is never persisted.
For a terminal role failure, the pause may also retain the finite adapter
diagnostic class normalized by the root agent boundary. It retains no native
message, provider response, prompt, command, transcript, credential, or process
cause, and CLI/MCP status derives its explanation from the class
deterministically.

Every transition appends and syncs its complete write-ahead event before
atomically replacing `state.json`; `progress.md` is a derived public projection.
Recovery advances lagging state from the last complete event, removes only an
incomplete final fragment, and regenerates progress. A mutating run or resume
must hold the per-run execution lease, while status remains read-only and
lock-free. The pipeline creates concise public activity messages only from
validated structured role results and deterministic runner outcomes. Never
persist raw model transcripts, chain-of-thought, credentials, or unhashed
remote or identity data.

Common run-envelope version 3 adds nullable bounded active provider role and
phase. The runner persists a `turn-started` write-ahead transition immediately
before each Planner, Reviewer, or Arbiter invocation and clears it only after
the read-only repository guard reconciles the turn. Version-1 and version-2
envelopes project null activity until the next mutating continuation persists
the explicit runtime migration. If execution stops first, lock-free MCP status
and timed-out wait combine the retained activity with the absence of a live
execution owner to report interruption, even before stale lease recovery;
resume reconstructs the same checkpoint request
from durable inputs without depending on the native session. Same-host status
reads check owner process liveness immediately without changing the lease
staleness threshold used for exclusive acquisition and recovery.
Before replaying an ownerless interrupted turn, resume revalidates the canonical
project and task paths, `task.md`, optional `context.md`, the accepted
clarification hash, and the persisted repository baseline. Because every
provider turn is read-only, any content, index, history/ref, remote, or Git
identity drift is rejected before a new turn starts. A safe recovery uses the
complete reconstructed prompt in a fresh native session; its `turn-started`
transition replaces the retained marker, which remains durable until the normal
post-turn read-only reconciliation completes.

`CHECK_AND_FIX` and `CLEAN_CONFIRM` are durable checkpoints, not transient
prompt labels. A turn-start event is persisted before invocation; its accepted
result, revised draft or findings, fingerprint, and round accounting are
committed in one transition. Resume either reconstructs an unfinished request
exactly once or continues from an already advanced checkpoint without replaying
the effect or counting the round twice. Provider structured-output failures and
deterministic checkpoint-contract failures first persist one pending correction
attempt, then reconstruct the complete draft-bound request in a fresh read-only
Planner session with the original schema. Interruption preserves that marker.
A claimed clean confirmation that mutates the repository is rejected by the
read-only guard, and a correction or confirmation whose draft fingerprint no
longer matches its inspected candidate cannot advance.

The descriptor projects each pause as bounded public data for both CLI and MCP:
its finite reason, optional validated bounded error code, a deterministic
explanation, empty evidence except for redacted lazy-correction
field-and-constraint violations, a validated retry state when present, and only
the applicable input-response or null-resume action. It
never projects the stored input request itself, authorization metadata,
question snapshots, revision counters, prompts, transcripts, native output, or
raw standard error; the root's separate pending-input projection owns the
identified questions. It does not expose inactive role configuration or
provider-private data.
CLI status and MCP status, wait, and activity expose the persisted resolved
mode, while `pipelines_list` exposes the descriptor-owned values, default, and
recommendation.

Pipeline state version 2 adds the resolved mode, the fingerprint accepted by a
lazy clean confirmation, and the one-time lazy source-fork marker. Its ordered
version-1 migration sets mode to `independent` and initializes both checkpoint
fields without moving any active or terminal workflow position, replaying a
role turn, rewriting a draft, or writing `plan.md`. Lock-free status may project
the migration in memory; only a mutating continuation persists it under the
per-run lease.

Pipeline state version 3 adds the lazy-correction ledger and nullable pending
marker. Its ordered version-2 migration initializes both fields empty without
moving active or terminal workflow positions, reviving a terminal run,
rewriting the draft, replaying an accepted checkpoint, consuming a revision or
correction round, or writing `plan.md`.

## Clarification

Before the first Planner turn in `CLARIFY`, the runner ensures the clarification
artifact exists without overwriting an existing transcript. The Planner studies
the task, existing clarifications, repository instructions, relevant
architecture, tests, and Git history in read-only mode.
It returns structured `READY` or all currently actionable questions whose
answers could materially change required behavior, scope, or commit boundaries.
It must use repository evidence instead of asking about ordinary technical
choices.

```json
{
  "status": "READY",
  "questions": []
}
```

or:

```json
{
  "status": "QUESTIONS",
  "questions": [
    {
      "question": "Which externally visible behavior is required?",
      "whyItMatters": "The answer changes the commit boundaries."
    }
  ]
}
```

`--clarify` opens `$VISUAL`, falling back to `$EDITOR`, before the first Planner
turn so the user can add context proactively. Without the flag, the phase still
runs and opens the editor only when questions exist. If no editor can be opened
or the process is non-interactive, persist `WAITING_FOR_USER` with
`clarification_answers_required` and print the artifact path.

An empty clarification artifact and closing the proactive editor without
changes are valid and do not consume an agent question round. The Planner still
runs and may return `READY`; only unanswered questions appended by the Planner
require user input.

Append each question round to `clarifications.md`, open the editor for answers,
then let the Planner reread the complete transcript. Default to at most three
agent question rounds; reaching the limit pauses with
`clarification_limit_reached` rather than starting with unresolved questions.
When the Planner returns `READY`, persist the artifact path and hash and close
clarification. The hash becomes a run input checked on resume.

Before opening the editor or entering `WAITING_FOR_USER`, persist the suspended
state, pending editor action, and last accepted artifact hash. An edit made
through that authorized editor window is accepted as new clarification input
and invalidates dependent work; any edit outside an authorized window pauses
with `clarifications_changed`.

Through MCP, the root runtime never opens an editor. It exposes the same pending
authorization as a structured request with identified questions and accepts an
empty response for optional proactive clarification or one exact answer per
Planner question through `run_respond`. The controlling agent may answer from
explicit user context and otherwise asks the user. A material product decision
must come from explicit user context. An external artifact edit followed by
`run_resume` uses the same authorization and remains valid.

After `CLARIFY`, agents must not ask questions during normal work. They may
return structured `PRODUCT_DECISION_REQUIRED` only when all of these are true:

- the answer changes observable behavior, a business rule, data, security, or material scope;
- multiple incompatible choices are reasonable;
- the task, repository, conventions, and prior clarifications do not resolve the choice;
- continuing would invent a requirement or create substantial rework risk.

```json
{
  "status": "PRODUCT_DECISION_REQUIRED",
  "question": "Which behavior should the product expose?",
  "options": ["Option A", "Option B"],
  "whyBlocked": "Both behaviors are valid but incompatible.",
  "evidence": ["task.md does not select either behavior"]
}
```

That outcome enters `WAITING_FOR_USER` and appends the question, options, and
evidence to the same artifact. The user edits the transcript in the authorized
editor window. The runner persists the updated artifact hash, and the edit
invalidates dependent analysis, drafts, and reviews; resume returns to
`ANALYZE`. It also starts a new consecutive-stagnation window and discards
diagnostic evidence tied to the prior inputs without resetting cumulative
revision counters or allowing a second Arbiter.

## Workflow

```text
independent:
CLARIFY → ANALYZE → DRAFT → REVIEW → VALIDATE → WRITE_PLAN → DONE
                         │
                         ▼
                       REVISE ────────────┘

lazy:
CLARIFY → ANALYZE → DRAFT → CHECK_AND_FIX
CHECK_AND_FIX ── changed ──▶ CHECK_AND_FIX
CHECK_AND_FIX ── unchanged ──▶ CLEAN_CONFIRM
CLEAN_CONFIRM ── findings ──▶ CHECK_AND_FIX
CLEAN_CONFIRM ── CLEAN ──▶ VALIDATE → WRITE_PLAN → DONE
invalid lazy result ── first failure ──▶ fresh correction at same checkpoint
invalid correction ──▶ WAITING_FOR_USER ── null retry ──▶ same checkpoint

Questions before work remain in CLARIFY.
Blocking product decisions after work starts → WAITING_FOR_USER → ANALYZE
Unsafe, ambiguous, or exhausted paths       → WAITING_FOR_USER
Unrecoverable internal failure              → FAILED
```

Independent mode is unchanged: the Planner and Plan Reviewer study the
finalized inputs, repository instructions, relevant architecture, tests, and
Git history independently, and the Reviewer checks scope, ordering, atomic
commit boundaries, dependencies, acceptance criteria, and commit-subject
validity. Planner clarification and planning are separate checkpoints;
correction turns reuse the planning checkpoint. The first eligible turn of each
checkpoint forks a compatible supplied source directly, neither role continues
the source in place or forks from the other role, and every on-demand Arbiter
starts fresh.

Lazy mode uses the Planner alone for clarification, analysis, drafting, fixing,
and confirmation. It never resolves or invokes Reviewer or Arbiter. A supplied
source session is forked once on the first eligible Planner turn for the entire
run. The durable one-time marker prevents reforking after interruption or
context reconstruction; a compatible child may continue, otherwise a fresh
native session reconstructs the same logical Planner from durable state. All
agent turns remain repository-read-only. Draft changes occur only in external
runner state and the runner remains the sole writer of the final artifact.

Keep role prompts short. Their mandatory English cores are:

```text
Planner draft:
Write a concise commit-by-commit plan for the requested changes. Keep the plan idiomatic and minimal, follow the project's conventions, and ensure it contains no contradictions.

Plan Reviewer:
Review the plan and verify that it is correct, idiomatic, minimal, consistent with the project's conventions, and free of contradictions.

Lazy check/fix:
Review the plan and verify that it is correct, idiomatic, minimal, consistent with the project's conventions, and free of contradictions. If you find any problems, fix the plan idiomatically and minimally, following the project's conventions.

Lazy clean confirmation:
Review the plan using the same criteria without editing it. Return CLEAN only when there are no problems; otherwise return concrete findings.

Planner finding resolution:
For each finding below, fix the plan idiomatically and minimally, following the project's conventions.

Stagnation Arbiter:
Diagnose why the plan revision loop is not converging and choose the minimal valid next direction using the provided schema.

Every role:
Produce this turn's result yourself as the authorized role. Do not delegate, spawn subagents, or use multi-agent collaboration.
```

The pipeline may append finalized inputs, access restrictions, output schemas,
the concise shared plan format, and the common product-decision instructions.
First, forked, fresh, and context-invalidated turns receive that complete
durable context. A compatible role continuation receives only its current
instruction and state delta; the complete prompt remains attached for adapter
recovery after unavailable continuation or failed compaction.
Claude classifies structured permission, HTTP status, result subtype, and
terminal-reason fields before bounded native-text matching. Only finite
allowlisted backend, capability, configuration, usage, provider, expected-tool
permission, and harmless read-only execution failures are resumable. A Bash
denial is an expected-tool capability failure only for a positively recognized
safe repository inspection; all other Bash denials fail closed. Provider
recovery requires an explicit transient HTTP status, while non-transient client
statuses and an unqualified structured `api_error` are terminal. An
unclassified valid read-only result or process failure may use this path only
after the repository guard proves the turn remained read-only. Authentication,
forbidden-operation permission denials, protocol failures, and isolation
failures remain terminal. Denied input and native provider text are discarded.
The root agent boundary normalizes those finite adapter-owned classes before
workflow code sees the failure. In particular, Codex collaboration activity
despite disabled multi-agent support remains terminal
`operation_multi_agent`; it is not an environment blocker and is not retried.
An explicit rate, quota, credit, or spend-limit rejection is not retried through
compaction, a fresh session, or provider fallback. Persist
`backend_unavailable` with the current authoring state and resume by
reconstructing the complete durable request after availability returns; do not
require the failed native session. This uses the current pipeline state and
common run envelope without an additional migration.
The planning checkpoint is seeded from the validated inputs and its current
draft, blockers, and bounded correction history. A product-decision edit
invalidates it before planning resumes.
In independent mode, the Reviewer returns structured actionable findings
instead of editing the draft. When findings exist, the pipeline sends them to
the Planner together with the finding-resolution core. The Planner returns a
revised draft, and the independent Reviewer checks it again. Neither role
writes repository or artifact files directly.

In lazy mode, every draft enters a writable-to-state `CHECK_AND_FIX` Planner
turn using the complete review core. A `CHANGED` result must contain the revised
draft and loops through another check/fix pass. An unchanged result is not
sufficient: it enters a separate repository-read-only `CLEAN_CONFIRM` Planner
turn over the exact draft fingerprint. That strict result is `CLEAN`, concrete
findings, or the narrowly allowed product-decision outcome. Findings return to
`CHECK_AND_FIX`; there is no dispute or arbitration path. Only a mutation-free
`CLEAN` result with the unchanged draft fingerprint advances to deterministic
shared plan validation and atomic writing. Deterministic validation issues also
return to `CHECK_AND_FIX`, and any draft change clears confirmation evidence.

An invalid provider or deterministic `CHECK_AND_FIX` or `CLEAN_CONFIRM` result
does not consume revision or correction budgets, retain the rejected result, or
advance accepted progress. The pipeline reduces the failure to bounded
field-and-constraint diagnostics and permits one automatic fresh-session,
repository-read-only replacement using the same schema and the complete durable
draft context. Only a replacement that passes the original contract and exact
draft-fingerprint guard rejoins the ordinary route. A repeated invalid result
pauses with the pending phase and draft scope intact, redacted diagnostics, and
an explicit null retry. Resume reconstructs the same correction without
recounting its automatic attempt, replaying accepted progress, or writing
`plan.md` early.

The pipeline owns strict schemas for clarification readiness, Planner drafts or
blocking product decisions, Reviewer approval or stable-ID findings, and
stagnation directions. Fields that do not apply to the selected status remain
present and empty so every object schema is strict and deterministic. The
pipeline validates status-specific invariants after adapter validation.

Only the Planner proposes the exact subject in each commit heading. The shared
`@agent-runner/commit-plan` package parses and validates every proposed subject
and plan deterministically; neither the Reviewer, Arbiter, runner, nor execution
pipeline generates or rewrites a subject.

The initial draft does not consume the revision budget. In independent mode,
each completed Planner revision followed by review, and when approved
deterministic validation, that returns to revision is one blocked correction
round. In lazy mode, each valid completed `CHECK_AND_FIX` turn consumes one
revision round, while a valid confirmation finding or deterministic validation
rejection after that turn records one blocked correction round. Invalid
checkpoint output and its one automatic correction consume neither counter.
Persist exact finding IDs,
validation issues, and the draft fingerprint as bounded diagnostic evidence.
Finding-ID changes are evidence rather than a reason to reset the counter; do
not use fuzzy matching or heuristic progress scores.

In independent mode, after `stagnationWindowRounds` consecutive blocked
correction rounds, invoke the fresh read-only Arbiter once. Give it only the
current draft, compact correction history, current blockers, finalized inputs,
and repository evidence. Its strict result may continue revision, request a
plan restructure, require Reviewer reconsideration of the current findings, or
require a product decision. It can never approve a plan, waive deterministic
validation, edit a draft, or reset a budget. Reject a finding-reconsideration
direction unless it names exactly the currently open finding IDs. A second full
blocked window pauses with `plan_revision_not_converging`; a second stagnation
arbitration is forbidden. Lazy mode has no Arbiter and pauses at the first full
blocked window with the same non-convergence reason.

`maxRevisionRounds` defaults to `15`. When no further revision is authorized,
pause with `plan_revision_limit_reached` and do not write `plan.md`. Arbitration
does not reset or bypass this limit, and lazy mode never treats budget
exhaustion as a clean result.

The final artifact must pass
[`@agent-runner/commit-plan`](../../../packages/commit-plan/README.md) validation
before it is written atomically. This pipeline never changes Git history,
creates a commit, pushes, or changes remote configuration or Git identity.
Immediately before every agent turn and the final write, re-read and compare the
persisted hashes of `task.md`, optional `context.md`, and accepted
`clarifications.md`. Unauthorized drift pauses and invalidates dependent drafts
and reviews. Preserve the preflight repository snapshot as the run baseline,
compare it before and after every agent turn and around the final write, and
also wrap each turn in its own full snapshot check. Any other repository
mutation pauses instead of advancing. Before creating a repository-local
clarification transcript, require `git check-ignore` evidence that its resolved
path is ignored and untracked.

## V1 Boundaries

- Use explicit JavaScript workflow logic, not a workflow DSL.
- Keep Planner and Plan Reviewer prompts pipeline-specific.
- Preserve independent Planner/Reviewer/Arbiter behavior when mode is omitted,
  and keep lazy mode primary-only with bounded check/fix and clean-confirm
  checkpoints.
- Keep target-repository agent turns read-only.
- Keep clarification and revision budgets finite, apply the resolved
  `maxRevisionRounds`, and pause rather than accepting unresolved input or an
  invalid plan.
- Apply safe project role and setting overrides without relocating task-owned
  artifacts under the runner artifact root.
- Keep MCP source-session fields additive and unset until the user deliberately
  selects a fork.
- Do not turn clarifications into an open-ended chat after work begins.
- Do not automatically start plan execution after authoring completes.
- Keep MCP start, wait, response, and detached-process behavior in the root
  runtime; this pipeline continues to own the same states and transitions.
- Cover mode validation and precedence, active-role probes, exactly one lazy
  source fork across checkpoints and resume, a changed pass followed by a
  genuinely clean confirmation, confirmation findings, mutation and fingerprint
  rejection, deterministic-validation return, budget exhaustion, version-1
  migration to `independent`, and version-2 lazy-correction initialization
  without reviving terminal runs.
- Cover provider and deterministic lazy-checkpoint correction, exhaustion,
  interruption and explicit retry, repository mutation, draft-fingerprint
  drift, counter accounting, artifact gating, and public redaction.
- Cover blocked provider activity, interrupted-owner projection, and resumed
  request reconstruction with fake adapters and external temporary state,
  including input drift, read-only mutation rejection, fresh recovery context,
  and retained activity until reconciliation.
- Cover finite redacted Claude classification, durable reconstruction of a
  failed read-only request, and terminal authentication and forbidden-operation
  boundaries without retaining native provider text.
- Cover redacted terminal adapter diagnostics, including forbidden delegated
  turns, through durable state and the shared CLI/MCP pause projection.
