# Task-Scoped Role Selection

These selections apply to the user's repair and skill tasks, subordinate to
explicit task selections. They change neither descriptor defaults nor unrelated
settings. The default and recommended mode remains `independent`; never select
`lazy` automatically.

## Planning and execution

- Use actual Runner `combined` planning and execution with the user-selected
  primary and a distinct independent Codex `gpt-6.2-sol` Reviewer and any
  Arbiter, unless the task explicitly selects otherwise.
- The standing primary choice is Claude Opus. The user authorizes Codex
  `gpt-6.2-sol` as primary only after Opus reaches an actual usage limit and
  only where the backend supports the role's access, retaining a separate
  independent Sol Reviewer and the combined gate. Preserve an explicit
  task-selected primary instead of replacing it with this preference.
- Never silently substitute models, providers or modes on errors, quota or
  delays. Diagnose the configured route using bounded evidence without
  requesting secrets, changing authentication or enabling paid credits.
- Role bindings are immutable within a run. A selection change requires a
  supported replacement/new run preserving work, completed effects and
  histories. Never edit frozen state or replay a consumed effect.

## Audits

- The user's standing pairing is a Claude Fable 5.2 Auditor
  (`claude-fable-5-2`, `high`) with a distinct independent Codex `gpt-6.2-sol`
  Reviewer in `independent` mode. It stays subordinate to any audit mode or
  roles the task explicitly authorizes; other audits keep their mode
  selection. Coordinators record the authorized selection at run creation;
  model selection grants no override authority. Infer no audit mode from the
  coding selection.
- When the selected overlay already resolves to the standing pairing, pass no
  role, execution or mode overrides, whether it is the default-discovered
  `LOCAL_ARTIFACTS/agent-runner.json` or one selected explicitly with
  `--project-config` or `projectConfigurationPath`. Otherwise bind
  `independent` mode and both roles explicitly; an inherited `lazy` mode drops
  the Reviewer. Each role needs a backend-compatible profile; otherwise
  resolution fails with `ERR_PROFILE_BACKEND_MISMATCH`. Existing runs keep
  their immutable bindings.
- Fable's plan and allowance are separate from ordinary Claude or Opus limits.
  An Opus limit establishes neither Fable availability nor exhaustion; a
  generic provider usage-limit code does not prove Fable allowance exhaustion.
  Diagnose the actual configured route under the same restrictions above;
  never silently replace the audit model.
