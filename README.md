# Agent Runner

Agent Runner is a local CLI and npm-workspaces monorepo for explicit agent
pipelines. It is designed to orchestrate local Codex CLI and Claude Code
processes while keeping persistence, Git safety, and backend execution in one
small runner.

All registered pipelines are runnable through the CLI and the local STDIO MCP
control plane.

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
- `polishing` finalizes and independently reviews existing workspace changes
  while preserving `HEAD` and leaving those changes uncommitted.
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

The project uses native ES modules. Its only external runtime dependencies are
the official Node MCP server SDK and its schema library.

## Installation

Install the pinned workspace dependencies and expose the local executable:

```bash
npm ci
npm link
agent-run --help
```

For repository development, use `node bin/agent-run.js` instead of creating the
global link.

## Pipelines

| Pipeline | Purpose | Specification |
| --- | --- | --- |
| `plan-authoring` | Analyze a task, review a draft, and atomically write `plan.md` | [`pipelines/plan-authoring/docs/SPEC.md`](pipelines/plan-authoring/docs/SPEC.md) |
| `plan-execution` | Implement, finalize, review, and locally commit every plan step | [`pipelines/plan-execution/docs/SPEC.md`](pipelines/plan-execution/docs/SPEC.md) |
| `polishing` | Polish, finalize, and independently review existing dirty-worktree changes without committing | [`pipelines/polishing/docs/SPEC.md`](pipelines/polishing/docs/SPEC.md) |

Plan authoring and execution share the deterministic
[`@agent-runner/commit-plan`](packages/commit-plan/README.md) contract. The
authoring pipeline produces that artifact; the execution pipeline consumes it.
Polishing is independently owned and does not consume a commit plan.

## Configuration

Trusted provider-profile implementations and runner defaults belong to the
installed runner. Copy the
tracked [example](.agent-runner.example.json) to an ignored, untracked
`.agent-runner.json` beside it at the Agent Runner repository root. The runner
never rewrites this local file.

When present, the file requires `"schemaVersion": 1`; unknown versions, fields,
pipelines, roles, profiles, and settings are errors. `profiles` defines trusted
aliases pinned to one backend: Codex aliases map to native profile names and
Claude aliases map to absolute isolated configuration directories. The schema
does not accept profile-supplied credentials, binaries, or arbitrary
environment variables. A selected alias supplies its backend; a conflicting
explicit backend is invalid.

A target repository may optionally provide an ignored, untracked
`LOCAL_ARTIFACTS/agent-runner.json`, or a new run may select another confined
ignored path with `--project-config`. A project file may select aliases already
trusted by the runner, set backend/model/context defaults, override pipeline
roles and limits, and select a normalized repository-relative `artifactRoot`.
It cannot define profiles, credentials, binaries, or environment variables.
Traversal, symbolic-link escapes, tracked files, and non-ignored files are
rejected; Agent Runner never creates the file or changes ignore rules.

For execution preferences, CLI/MCP role values win over CLI/MCP run-wide
values, then project-role and project-wide values, runner-role and runner-wide
values, and finally built-in `current`. Project pipeline settings override
runner settings. The resolved roles, settings, and artifact root are persisted,
so `resume` never reloads either configuration file.

Every role accepts string `profile`, `model`, and `contextSize` selections.
`defaultBackend` remains optional and is used only when no profile supplies the
backend; a missing backend is a preflight error. Explicit decimal context sizes
are validated by the chosen adapter and map to Codex's context window or
Claude's auto-compaction token window.

| Backend | `model: "current"` | `profile: "current"` |
| --- | --- | --- |
| Codex | Omit the model override and use the effective native Codex default | Omit `--profile` and inherit the current process/profile |
| Claude | Omit `--model` and use the effective Claude configuration/account default | Omit `CLAUDE_CONFIG_DIR` and inherit the current process configuration |

Agent Runner intentionally does not hard-code either backend's changing native
model ID. The tracked [example](.agent-runner.example.json) makes these native
defaults explicit and shows `claude-primary` and `claude-secondary` aliases.
`artifactRoot` defaults to `LOCAL_ARTIFACTS`.

Pipeline settings use these defaults:

| Pipeline | Setting | Default |
| --- | --- | ---: |
| `plan-authoring` | `maxRevisionRounds` | 15 |
| `plan-authoring` | `stagnationWindowRounds` | 3 |
| `plan-execution` | `maxFixRoundsPerStep` | 5 |
| `plan-execution` | `finalization` | `auto` |
| `plan-execution` | `maxDisputesPerFinding` | 2 |
| `plan-execution` | `maxSameFindingRounds` | 3 |
| `plan-execution` | `stagnationWindowRounds` | 3 |
| `polishing` | `maxFixRounds` | 5 |
| `polishing` | `finalization` | `auto` |
| `polishing` | `maxDisputesPerFinding` | 2 |
| `polishing` | `maxSameFindingRounds` | 3 |
| `polishing` | `stagnationWindowRounds` | 3 |

The stagnation window detects consecutive blocked correction rounds. Unless a
harder limit preempts it, the first full window invokes one fresh Arbiter; a
second full window pauses for the user instead of continuing an architectural
correction loop indefinitely.

For plan execution and polishing, `finalization: "auto"` uses a conventional
confined repository `finalization` skill when present and otherwise derives the
complete gate from repository instructions and project-defined checks. Use
`"none"` to select that fallback deliberately, or a normalized
repository-relative path ending in `SKILL.md` to require that exact skill. A
missing, escaping, or invalid explicit skill blocks the run; absent optional
guidance never skips the dedicated fingerprint-bound finalization turn.

Backend sessions are disposable. When a native context is full, the adapter
compacts it and retries once; if the context remains full, ordinary turns can
continue in a fresh session reconstructed from durable run state, artifacts,
and the current workspace. An explicitly supplied source session is never
silently replaced, and an interrupted local-commit turn is verified from Git
state rather than replayed. An explicit Claude rate, quota, credit, or spend
limit rejection is not retried through compaction, a fresh session, or another
provider. The run pauses as `backend_unavailable` after the one rejected turn,
with durable workflow state and safe workspace changes preserved for resume.

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

Each plan step begins with:

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

## CLI

```bash
agent-run run plan-authoring --project /path/to/repository --task /path/to/task
agent-run run plan-execution --project /path/to/repository --task /path/to/task
agent-run run polishing --project /path/to/repository --task /path/to/task
agent-run resume --run <run-id>
agent-run status --run <run-id>
agent-run pipelines
agent-run mcp
```

Run-wide preferences use `--profile`, `--model`, and `--context-size`.
Role-specific values use derived flags such as `--worker-profile`,
`--reviewer-model`, or `--planner-context-size`; role-specific values win. Use
the trusted alias, backend-native model ID, and decimal token string
respectively:

```bash
agent-run run polishing \
  --project /path/to/repository \
  --task /path/to/task \
  --profile claude-primary \
  --model sonnet \
  --worker-context-size 200000
```

Use `--project-config <path>` to select an explicit project configuration for
the new run. Relative paths are confined to the canonical project; the file
must already exist and be ignored and untracked. The flag is not accepted by
`resume` because the resolved configuration is durable run state.

A run may seed its primary and review roles from one existing backend session:

```bash
agent-run run plan-execution \
  --project /path/to/repository \
  --task /path/to/task \
  --worker codex \
  --reviewer codex \
  --fork-from codex:<session-id> \
  --fork-profile codex-work
```

`--fork-profile` is separate so the text after the first separator in
`--fork-from` remains an opaque native ID. The primary and review backends must
match the source backend. A known source profile supplies `current` for those
roles and every explicit role profile must match it. If the source profile is
unknown, those roles must remain `current` and no native profile override is
guessed. The first
eligible turn in each pipeline-owned primary or review checkpoint forks the
source independently. Checkpoints separate clarification, bootstrap, and work;
plan execution also isolates every commit's Worker and Reviewer contexts. The
source may intentionally contain context shared before the fork, but its
children are direct siblings and do not share later turns. The source is never
resumed in place, and every arbitration uses a fresh Arbiter that is not
constrained by the source backend. The runner persists the resolved source
reference, resolved source profile, and child lineage, so recovery uses durable
run state and `resume` needs no source flag. The Arbiter remains independent.
An unavailable or backend/profile-incompatible source fails instead of falling
back to a fresh session. Because primary and review roles each receive the
complete source context, a fork can consume that provider context and quota
independently. Prefer a fresh start for a long, multi-topic, or uncertain source
session.

Add `--clarify` to any `run` command to open `$VISUAL` or `$EDITOR` before
the primary agent checks whether more information is needed. Without the flag,
the clarification phase still runs but opens the editor only when the agent asks
a material question. In a non-interactive environment, the run pauses and
prints the clarification path instead. An empty clarification artifact and
closing the proactive editor without changes are valid; neither consumes an
agent question round. Unanswered agent questions still pause the run.

Authoring uses `<task-dir>/clarifications.md`. Execution and polishing keep
their run-specific transcript under
`<project>/<artifactRoot>/agent-runner/<run-id>/clarifications.md`, where
`artifactRoot` defaults to `LOCAL_ARTIFACTS`. Preflight
requires the target repository to ignore that resolved path; the runner never
edits ignore rules automatically. The artifact is hashed separately and is
never included in a planned commit. Execution pauses for a revised plan and a
new run if clarification input conflicts with the validated plan. Plan
authoring's task-owned `clarifications.md` and `plan.md` always remain beside
`task.md` and do not move under the configured runner artifact root.

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
while status and bounded public activity reads remain lock-free. `run` and
`resume` print concise labeled activity as it is persisted; `status` prints the
current state, pause, artifact paths, findings, fingerprints, commit SHAs, and
state directory without exposing model transcripts.

Plan execution and polishing accept one applicable resume action at a time:

```bash
agent-run resume --run <run-id> --extra-fix-rounds 3
agent-run resume --run <run-id> --override-finding R7
```

`run` and `resume` exit with status `2` when they return a persisted pause.
Invalid input and startup or execution failures exit with status `1`; `status`
exits successfully when it can read the requested run.

Resume without an action flag after editing the reported clarification artifact
or resolving a reported retryable blocker. After clarification closes, only a
blocking material product decision may ask another question. If its answer
invalidates the validated plan or completed execution scope, revise the plan
and start a new execution run rather than rewriting history.

For every execution step, the Worker implements the change, runs a dedicated
finalization gate using the configured guidance policy, and passes an
independent review of the same content fingerprint before receiving one-shot
authorization to create the exact planned local commit. Commits are not pushed,
no remote is changed, and remote writes remain permanently prohibited.

Polishing follows the same fingerprint-bound finalization and independent
review gate, but it has no commit turn or commit authorization. Successful
polishing leaves the reviewed workspace content and staging state uncommitted.
Its dedicated `FINALIZE` turn runs the target project's complete validation
procedure, including required formatting or generated output, with configured
skill guidance when available. It does not perform handoff staging or draft a
commit.

## MCP

Configure the installed command in Codex's `~/.codex/config.toml`:

```toml
[mcp_servers.agent_runner]
command = "agent-run"
args = ["mcp"]
tool_timeout_sec = 90000 # 25 hours; longer than the maximum 24-hour run_wait
```

For development without `npm link`, point Codex at the repository executable:

```toml
[mcp_servers.agent_runner]
command = "node"
args = ["/absolute/path/to/agent-task-runner/bin/agent-run.js", "mcp"]
tool_timeout_sec = 90000
```

The MCP process starts from the pinned local installation; startup performs no
`uvx` or unpinned network install. No network service or daemon is required.
The server uses STDIO only, and stdout is reserved for protocol messages. It
exposes:

- `pipelines_list`
- `run_start`
- `run_status`
- `run_activity`
- `run_wait`
- `run_respond`
- `run_resume`

Use `pipelines_list` to discover the registry, then start with `run_start` and a
unique opaque idempotency key. It persists the run, returns a durable `runId`,
and launches detached execution. Its additive `projectConfigurationPath`
selects the same confined project file as `--project-config`; `profile`,
`model`, and `contextSize` set run-wide selections; the same fields inside a
`roleOverrides` entry take precedence. `sourceSession.profile` carries a known
trusted source alias while its `id` remains opaque. These optional fields are
additive, so a fresh-start request remains valid without them:

```json
{
  "idempotencyKey": "<unique-opaque-key>",
  "pipelineId": "plan-execution",
  "projectPath": "/path/to/repository",
  "taskPath": "/path/to/task"
}
```

When a compatible current Codex or Claude session is available, offer the user
a fresh start and a deliberate fork choice. Include the known trusted profile
with that choice. If its profile is unknown, offer only `current` inheritance;
never guess an alias or inspect provider-private storage. Leave `sourceSession`
unset unless the user chooses the fork. A deliberate fork adds:

```json
{
  "sourceSession": {
    "backend": "codex",
    "id": "<opaque-session-id>",
    "profile": "codex-work"
  }
}
```

Primary and review roles then fork the complete source context independently,
so each child can consume the provider context and quota. Recommend a fresh
start for a long, multi-topic, or uncertain current session. The configured
artifact root applies only to runner-owned execution and polishing artifacts;
plan-authoring artifacts remain beside `task.md`.

Call `run_wait` once for the desired interval. Its `timeoutMs` accepts up to 24
hours; the MCP client's tool timeout must be longer than the requested wait.
[Codex](https://developers.openai.com/codex/config-reference) currently defaults
`tool_timeout_sec` to 60 seconds, which is too short for long runs, so size the
setting above to the operator's longest expected wait. A client timeout or
cancelled wait does not stop the pipeline; recover it later with `run_status`
and another explicit wait. Do not make the model poll `run_status`,
`run_activity`, or `run_wait` at a fixed cadence.

MCP never opens a text editor. A paused clarification or product decision is
returned as structured `pendingInput`. `run_respond` requires the request ID,
run revision, an answer for every identified question, and a new idempotency
key; optional proactive clarification accepts an empty answer array. The
controlling agent answers from explicit user context or asks the user, and must
not invent a material product decision. Answers are appended without
paraphrasing to the durable clarification transcript before detached execution
continues. Editing the artifact and using `run_resume` remains supported;
`run_resume` requires `expectedRevision` from the latest status or wait result,
a unique idempotency key, and only an action valid for the persisted pause.

Mutating tools persist an action intent before mutation and a receipt before
returning. Exact retries return the original result, while reusing a key with
different arguments is rejected. Runs continue in detached local children, so
MCP disconnects and wait cancellation affect only the client call. The existing
execution lease, Git safety checks, local-only policy, and one-shot commit
authorization remain authoritative. V1 does not require MCP Tasks.

CLI output and MCP progress events label public activity by role. `run_status`
returns a concise current snapshot; `run_activity` returns bounded history
after a cursor and a next cursor. Use activity for explicit inspection or
recovery, not polling. `run_wait` can emit the same bounded events as progress
notifications without waking the model, but live rendering depends on the MCP
host. Public activity excludes raw prompts, reasoning, private state, and
complete model transcripts.

## Pipeline Boundary

The registry is static in V1. A pipeline descriptor exports an ID, a state
version, roles, configuration settings and defaults, pipeline-specific accepted
and required `run` options, task-input definitions, clarification and status
projections, resume-action validation, persisted-run validation, and a
description; the root CLI owns the common `--clarify` lifecycle option. Each
workspace owns its explicit JavaScript workflow. The runner provides state,
events, agents, and Git services; it does not provide a workflow DSL or
duplicate pipeline-owned policy.

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
│   ├── mcp.js
│   ├── pipeline-registry.js
│   ├── runner.js
│   ├── state-files.js
│   ├── state-actions.js
│   ├── state-journal.js
│   ├── state-lease.js
│   ├── state-validation.js
│   └── state.js
├── packages/
│   └── commit-plan/
├── pipelines/
│   ├── plan-authoring/
│   ├── plan-execution/
│   └── polishing/
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

Real-backend smoke turns are opt-in and are excluded from that gate:

```bash
AGENT_RUNNER_LIVE_CODEX=1 npm test -- test/codex.test.js
AGENT_RUNNER_LIVE_CLAUDE=1 npm test -- test/claude.test.js
```

Inspect the CLI:

```bash
node bin/agent-run.js --help
```

Use the repository's `finalization` skill before handing off a completed
change. It validates the current change; when explicitly asked to finalize, it
also stages the relevant files and drafts a Conventional Commit message. It
never commits or pushes. Creating a commit is a separate action that requires
an explicit request; pushing remains prohibited in V1.

## V1 Non-Goals

V1 intentionally excludes TypeScript, a build step, network services and
daemons, databases, cloud execution, dynamic plugin loading, a declarative
workflow DSL, PR automation, and all automatic pushing.
