# Task inputs

## Task Inputs

Plan authoring accepts:

```text
task/
├── task.md
└── context.md  # optional
```

It creates or extends `clarifications.md` and atomically writes `plan.md` in the
same directory. Plan execution accepts:

```text
task/
├── task.md
├── plan.md
├── clarifications.md  # optional authoring transcript
└── context.md          # optional
```

Polishing accepts the existing dirty worktree plus:

```text
task/
├── task.md
├── clarifications.md  # optional authoring transcript
└── context.md          # optional
```

Audit accepts `task.md` and optional `context.md` in the task directory. Runner
creates or extends `clarifications.md` and publishes `audit.md` there; it grants
no source writes. Repository-local artifacts must already be ignored and untracked.

Commit-plan steps use `## Commit N:` headings with the exact commit subject:

```markdown
## Commit 1: feat(market): add repository

### Goal

Introduce a repository abstraction.

### Acceptance Criteria

- Existing behavior remains unchanged.
- Repository has tests.
```

The commit-plan contract owns numbering, structure, and the exact subject-only
Conventional Commit format. Agents consume the validated commit subject verbatim.
Custom plans use `## Step N:` headings. See [Pipelines](pipelines.md#pipelines) for
both contracts' locations in the source checkout and standalone installation.
