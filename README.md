# Agent Runner

Agent Runner is a local CLI and npm-workspaces monorepo for explicit agent
pipelines. It is designed to orchestrate local Codex CLI and Claude Code
processes while keeping persistence, Git safety, and backend execution in one
small runner.

> **Status:** the public command shape, module boundaries, versioned repository
> configuration, deterministic commit-plan contract, external run store,
> clarification and Git-safety services, Codex and Claude adapters, the complete
> plan-authoring state machine, plan-execution preflight, clarification, and
> independent bootstrap, two pipeline descriptors, tests, and agent guidance
> are present. The `run`, `resume`, and `status` workflows are not wired yet and
> deliberately return a non-zero exit code.

Architecture is documented in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
Each pipeline owns its specification under its workspace.

## Core Guarantees

- Pipelines own their roles, inputs, prompts, state machines, and output policy.
- The root runner owns lifecycle, persistence, backend execution, and Git safety.
- Every pipeline starts with a bounded `CLARIFY` phase whose agent turns are read-only.
- After clarification closes, only a blocking material product decision may ask the user another question through `PRODUCT_DECISION_REQUIRED`.
- Codex and Claude can be selected independently for each pipeline role.
- Read-only agent turns are checked for repository mutations.
- `plan-authoring` keeps project content read-only except for its resolved `clarifications.md` and `plan.md` artifact paths, even when the task directory is inside the target repository.
- In `plan-execution`, only the Worker may create the exact planned local commit, and only after runner authorization and successful finalization/review gates.
- Commit messages never contain a `Co-authored-by` trailer or replace the repository's configured Git identity.
- Retry exhaustion and unsafe states pause for the user instead of accepting unresolved work.
- Persistent state lives outside both the target repository and task directory.
- V1 never pushes, changes `origin` or another remote's configuration, or performs any other remote-repository mutation.

## Requirements

- Node.js 24 LTS: `>=24 <25`
- Git
- Codex CLI 0.147.0 or newer stable and/or Claude Code 2.1.233 or newer stable,
  depending on the selected role backends
- `bubblewrap` and `socat` for the V1 Claude backend on Linux

The project uses native ES modules and currently has no runtime npm
dependencies outside the local workspaces. Adapter tests use process fakes;
set `AGENT_RUNNER_LIVE_CODEX=1` or `AGENT_RUNNER_LIVE_CLAUDE=1` to include the
corresponding real smoke turn. Workflow tests use fakes and temporary Git
repositories by default.

## Pipelines

| Pipeline | Purpose | Specification |
| --- | --- | --- |
| `plan-authoring` | Analyze a task, review a draft, and atomically write `plan.md` | [`pipelines/plan-authoring/docs/SPEC.md`](pipelines/plan-authoring/docs/SPEC.md) |
| `plan-execution` | Implement, finalize, review, and locally commit every plan step | [`pipelines/plan-execution/docs/SPEC.md`](pipelines/plan-execution/docs/SPEC.md) |

Both pipelines share the deterministic
[`@agent-runner/commit-plan`](packages/commit-plan/README.md) contract. The
authoring pipeline produces that artifact; the execution pipeline consumes it.

Repository defaults may be stored in an ignored `.agent-runner.json` copied
from the tracked [example](.agent-runner.example.json). The V1 loader validates
the schema and pipeline-owned settings, rejects unsupported role backends and
malformed model fields, and never rewrites the local file. Git preflight
requires its path to remain ignored and untracked even when the file is absent.

A task directory has this shape:

```text
task/
├── task.md
├── clarifications.md  # plan-authoring transcript
├── plan.md
└── context.md  # optional
```

`plan-authoring` needs `task.md` and optional `context.md`; it creates or extends
`clarifications.md` beside `plan.md`. `plan-execution` also requires `plan.md`
and reads the authoring clarifications when present. Each plan step begins with:

```markdown
## Commit 1: feat(market): add repository

### Goal

Introduce a repository abstraction.

### Acceptance Criteria

- Existing behavior remains unchanged.
- Repository has tests.
```

The common contract owns numbering, structure, and the exact subject-only
Conventional Commit format. Agents never reinterpret or rewrite the validated
commit subject.

## Intended CLI

```bash
agent-run run plan-authoring --project /path/to/repository --task /path/to/task
agent-run run plan-execution --project /path/to/repository --task /path/to/task
agent-run resume --run <run-id>
agent-run status --run <run-id>
agent-run pipelines
```

Add `--clarify` to either `run` command to open `$VISUAL` or `$EDITOR` before
the primary agent checks whether more information is needed. Without the flag,
the clarification phase still runs but opens the editor only when the agent asks
a material question. In a non-interactive environment, the run pauses and
prints the clarification path instead. An empty clarification artifact and
closing the proactive editor without changes are valid; neither consumes an
agent question round. Unanswered agent questions still pause the run.

Authoring uses `<task-dir>/clarifications.md`. Execution keeps its run-specific
transcript under
`<project>/LOCAL_ARTIFACTS/agent-runner/<run-id>/clarifications.md`. Preflight
requires the target repository to ignore that resolved path; the runner never
edits ignore rules automatically. The artifact is hashed separately and is
never included in a planned commit. Execution pauses for a revised plan and a
new run if clarification input conflicts with the validated plan.

Role backends are configured independently:

```bash
agent-run run plan-execution \
  --project /path/to/repository \
  --task /path/to/task \
  --worker codex \
  --reviewer claude \
  --arbiter codex
```

Runner state uses `$XDG_STATE_HOME/agent-runner/` with
`~/.local/state/agent-runner/` as the fallback. Every run records its pipeline
ID and state-schema version and is addressed by an opaque run ID. Complete
write-ahead events precede atomic state replacement; recovery repairs a lagging
state file and derived progress. Mutating runs require one execution lease,
while status and bounded public activity reads remain lock-free.

## Pipeline Boundary

The registry is static in V1. A pipeline descriptor exports an ID, a state
version, roles, configuration settings and defaults, pipeline-specific accepted
and required `run` options, and a description; the root CLI owns the common
`--clarify` lifecycle option. Each workspace owns its explicit JavaScript
workflow. The runner provides state, events, agents, and Git services; it does
not provide a workflow DSL or duplicate pipeline-owned policy.

## Repository Layout

```text
.
├── bin/
│   └── agent-run.js
├── src/
│   ├── agents/
│   │   ├── adapter-contract.js
│   │   ├── claude.js
│   │   ├── claude-local-commit.js
│   │   ├── codex-app-server.js
│   │   ├── codex-local-commit.js
│   │   ├── codex.js
│   │   └── index.js
│   ├── cli.js
│   ├── config.js
│   ├── clarification-editor.js
│   ├── clarification-files.js
│   ├── clarifications.js
│   ├── git-commit.js
│   ├── git-command.js
│   ├── git-content.js
│   ├── git.js
│   ├── index.js
│   ├── pipeline-registry.js
│   ├── runner.js
│   ├── state-files.js
│   ├── state-journal.js
│   ├── state-lease.js
│   ├── state-validation.js
│   └── state.js
├── packages/
│   └── commit-plan/
├── pipelines/
│   ├── plan-authoring/
│   └── plan-execution/
├── test/
├── docs/
│   └── ARCHITECTURE.md
├── .agents/skills/
├── AGENTS.md
└── CLAUDE.md
```

`.agents/skills/` is the canonical shared skill directory.
`.claude/skills` points to it so Codex and Claude use the same project
instructions.

## Development

Create the local workspace links from the committed lockfile:

```bash
npm ci
```

Run the unit tests:

```bash
npm test
```

Run the complete repository gate:

```bash
npm run check
git diff --check
git diff --cached --check
```

Inspect the current scaffold CLI:

```bash
node bin/agent-run.js --help
```

Use the repository's `finalization` skill before handing off a completed
change. It validates and stages the relevant change set and drafts a Conventional
Commit message, but it never commits or pushes. Creating a commit is a separate
action that requires an explicit request; pushing remains prohibited in V1.

## V1 Non-Goals

V1 intentionally excludes TypeScript, a build step, web or server components,
databases, cloud execution, dynamic plugin loading, a declarative workflow DSL,
PR automation, and all automatic pushing.
