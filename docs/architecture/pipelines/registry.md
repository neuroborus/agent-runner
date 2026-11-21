# Pipeline Registry and Descriptors

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Pipeline Ownership

Each pipeline owns its input interpretation, roles, configuration settings and
defaults, accepted `run` options, prompts, structured-output schemas, explicit
JavaScript state machine, retry policy, and completion criteria. Roles, settings,
accepted and required options, task-input definitions, clarification and status
projections, resume-action validation, and persisted-run validation are exposed
through its static descriptor. The descriptor also selects the active roles
from its resolved settings, including all mode semantics; pipeline states remain
workspace-owned rather than becoming root runtime policy.

The root CLI owns `--clarify` as a common run-lifecycle option. Role and
pipeline-specific options remain in pipeline descriptors.

V1 registers:

- `plan-authoring`: produces a validated commit or explicitly selected custom
  `plan.md` without changing project content or Git history outside its declared
  task-owned artifacts.
- `plan-execution`: consumes `plan.md` and implements one reviewed local commit per commit-plan step, or a durable criterion-bound accepted result per explicitly selected custom step.
- `polishing`: polishes, finalizes, and reviews an existing dirty worktree, then
  stages the complete result while leaving it uncommitted.
- `audit`: inspects an agreed Git or ordinary workspace read-only and publishes
  a resumable reviewed `audit.md` through Runner-owned artifact effects.
- `init`: prepares reviewed integrated or external infrastructure, publishes
  merged guidance last and confirms the complete setup without Git effects.

The pipeline registry is static. V1 has no dynamic plugins, workflow DSL, or
generic DAG executor.
