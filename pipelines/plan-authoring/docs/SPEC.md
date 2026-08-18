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
`arbiter` roles and owns these positive-integer repository settings:

```text
maxRevisionRounds = 15
stagnationWindowRounds = 3
```

Values may be overridden under `pipelines.plan-authoring` in the repository's
versioned `.agent-runner.json` contract. Role objects live under
`pipelines.plan-authoring.roles` and may contain an optional `backend` and
backend-specific `model`. The root runtime applies the shared precedence rules
documented in [`docs/ARCHITECTURE.md`](../../../docs/ARCHITECTURE.md); this
pipeline owns only its roles, setting validation, and defaults.

CLI overrides use `--planner`, `--reviewer`, and `--arbiter`, with corresponding
`--planner-model`, `--reviewer-model`, and `--arbiter-model` flags. A new run may
also use `--fork-from <backend>:<session-id>` when Planner and Plan Reviewer both
use that backend. Their first turns fork the source independently; the Arbiter
remains fresh and `resume` uses the persisted lineage without another flag.

## Persistent Run State

The root run store persists this pipeline outside the project and task
directories using the common contract in
[`docs/ARCHITECTURE.md`](../../../docs/ARCHITECTURE.md). Its versioned envelope
records canonical inputs, resolved Planner, Reviewer, and Arbiter configuration,
resolved pipeline settings, the initial repository baseline, hashes, revision
and clarification counters, pause state, optional source-session reference,
direct child role/session IDs, and opaque plan-authoring state.
Drafts, findings, correction-round snapshots, and stagnation evidence remain
pipeline-owned structured data in the external run state rather than task
artifacts.

Every transition appends and syncs its complete write-ahead event before
atomically replacing `state.json`; `progress.md` is a derived public projection.
Recovery advances lagging state from the last complete event, removes only an
incomplete final fragment, and regenerates progress. A mutating run or resume
must hold the per-run execution lease, while status remains read-only and
lock-free. The pipeline creates concise public activity messages only from
validated structured role results and deterministic runner outcomes. Never
persist raw model transcripts, chain-of-thought, credentials, or unhashed
remote or identity data.

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
CLARIFY → ANALYZE → DRAFT → REVIEW → VALIDATE → WRITE_PLAN → DONE
                         │
                         ▼
                       REVISE ────────────┘

Questions before work remain in CLARIFY.
Blocking product decisions after work starts → WAITING_FOR_USER → ANALYZE
Unsafe, ambiguous, or exhausted paths       → WAITING_FOR_USER
Unrecoverable internal failure              → FAILED
```

The Planner and Plan Reviewer study the finalized inputs, repository
instructions, relevant architecture, tests, and Git history independently. If
a compatible source session was supplied, their first turns are separate direct
forks of that source and only the returned child IDs are persisted. Neither role
ever continues the source in place or forks from the other role. The on-demand
Arbiter always starts fresh. The Reviewer checks scope, ordering, atomic commit
boundaries, dependencies, acceptance criteria, and commit-subject validity.

Keep role prompts short. Their mandatory English cores are:

```text
Planner draft:
Write a concise commit-by-commit plan for the requested changes. Keep the plan idiomatic and minimal, follow the project's conventions, and ensure it contains no contradictions.

Plan Reviewer:
Review the plan and verify that it is correct, idiomatic, minimal, consistent with the project's conventions, and free of contradictions.

Planner finding resolution:
For each finding below, fix the plan idiomatically and minimally, following the project's conventions.

Stagnation Arbiter:
Diagnose why the plan revision loop is not converging and choose the minimal valid next direction using the provided schema.
```

The pipeline may append finalized inputs, access restrictions, output schemas,
the concise shared plan format, and the common product-decision instructions.
The Reviewer returns structured actionable findings instead of editing the
draft. When findings exist, the pipeline sends them to the Planner together
with the finding-resolution core. The Planner returns a revised draft, and the
independent Reviewer checks it again. Neither role writes repository or
artifact files directly.

The pipeline owns strict schemas for clarification readiness, Planner drafts or
blocking product decisions, Reviewer approval or stable-ID findings, and
stagnation directions. Fields that do not apply to the selected status remain
present and empty so every object schema is strict and deterministic. The
pipeline validates status-specific invariants after adapter validation.

Only the Planner proposes the exact subject in each commit heading. The shared
`@agent-runner/commit-plan` package parses and validates every proposed subject
and plan deterministically; neither the Reviewer, Arbiter, runner, nor execution
pipeline generates or rewrites a subject.

The initial draft and review do not consume the revision budget. Each completed
Planner revision followed by review, and when approved deterministic validation,
that returns to revision is one blocked correction round. Persist its exact
finding IDs, validation issues, and draft fingerprint as bounded diagnostic
evidence. Finding-ID changes are evidence rather than a reason to reset the
counter; do not use fuzzy matching or heuristic progress scores.

After `stagnationWindowRounds` consecutive blocked correction rounds, invoke the
fresh read-only Arbiter once. Give it only the current draft, compact correction
history, current blockers, finalized inputs, and repository evidence. Its strict
result may continue revision, request a plan restructure, require Reviewer
reconsideration of the current findings, or require a product decision. It can
never approve a plan, waive deterministic validation, edit a draft, or reset a
budget. Reject a finding-reconsideration direction unless it names exactly the
currently open finding IDs. A second full blocked window pauses with
`plan_revision_not_converging`; a second stagnation arbitration is forbidden.

`maxRevisionRounds` defaults to `15`. When no further revision is authorized,
pause with `plan_revision_limit_reached` and do not write `plan.md`. Arbitration
does not reset or bypass this limit.

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
- Keep target-repository agent turns read-only.
- Keep clarification and revision budgets finite, apply the resolved
  `maxRevisionRounds`, and pause rather than accepting unresolved input or an
  invalid plan.
- Do not turn clarifications into an open-ended chat after work begins.
- Do not automatically start plan execution after authoring completes.
- Keep MCP start, wait, response, and detached-process behavior in the root
  runtime; this pipeline continues to own the same states and transitions.
