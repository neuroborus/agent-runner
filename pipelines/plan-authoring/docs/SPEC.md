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

## Clarification

The runner ensures the clarification artifact exists without overwriting an
existing transcript before the pipeline enters `CLARIFY`. The Planner studies
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
`ANALYZE`.

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
instructions, relevant architecture, tests, and Git history independently. The
Reviewer checks scope, ordering, atomic commit boundaries, dependencies,
acceptance criteria, and commit-subject validity.

Keep role prompts short. Their mandatory English cores are:

```text
Planner draft:
Write a concise commit-by-commit plan for the requested changes. Keep the plan idiomatic and minimal, follow the project's conventions, and ensure it contains no contradictions.

Plan Reviewer:
Review the plan and verify that it is correct, idiomatic, minimal, consistent with the project's conventions, and free of contradictions.

Planner finding resolution:
For each finding below, fix the plan idiomatically and minimally, following the project's conventions.
```

The pipeline may append finalized inputs, access restrictions, output schemas,
and the common product-decision instructions. The Reviewer returns structured
actionable findings instead of editing the draft. When findings exist, the
pipeline sends them to the Planner together with the finding-resolution core.
The Planner returns a revised draft, and the independent Reviewer checks it
again. Neither role writes repository or artifact files directly.

The final artifact must pass
[`@agent-runner/commit-plan`](../../../packages/commit-plan/README.md) validation
before it is written atomically. This pipeline never changes Git history,
creates a commit, pushes, or changes remote configuration or Git identity.

## V1 Boundaries

- Use explicit JavaScript workflow logic, not a workflow DSL.
- Keep Planner and Plan Reviewer prompts pipeline-specific.
- Keep target-repository agent turns read-only.
- Keep clarification and revision budgets finite and pause rather than accepting unresolved input or an invalid plan.
- Do not turn clarifications into an open-ended chat after work begins.
- Do not automatically start plan execution after authoring completes.
