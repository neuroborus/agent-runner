# Task-Scoped Role Selection

These selections apply to the user's repair and skill tasks, subordinate to
explicit task selections. They change neither descriptor defaults nor unrelated
settings. The default and recommended mode remains `independent`; never select
`lazy` automatically.

## Planning and execution

- Use actual Runner `combined` planning and execution with the user-selected
  primary and a distinct independent Codex `gpt-6.1-sol` Reviewer, unless the
  task explicitly selects otherwise.
- The standing primary choice is Claude Opus. The user authorizes Codex
  `gpt-6.1-sol` as primary after Opus reaches its usage limit, retaining a
  separate independent Sol Reviewer and the combined gate. Preserve an
  explicit task-selected primary instead of replacing it with this preference.
- Never silently substitute models, providers or modes on errors, quota or
  delays. Diagnose the configured route using bounded evidence without
  requesting secrets, changing authentication or enabling paid credits.
- Role bindings are immutable within a run. A selection change requires a
  supported replacement/new run preserving work, completed effects and
  histories. Never edit frozen state or replay a consumed effect.

## Audits

- Preserve the user's standing Claude Fable Auditor and independent Sol review
  choice unless the user authorizes a change. Coordinators record the authorized
  selection at run creation; model selection grants no override authority.
  Infer no audit mode from the coding selection.
- Fable's plan and allowance are separate from ordinary Claude or Opus limits.
  An Opus limit establishes neither Fable availability nor exhaustion; a
  generic provider usage-limit code does not prove Fable allowance exhaustion.
  Diagnose the actual configured route under the same restrictions above;
  never silently replace the audit model.
