# Agent Runner

Agent Runner is a local CLI and STDIO MCP server for durable agent pipelines.
The npm-workspaces monorepo orchestrates Codex CLI and Claude Code while keeping
persistence, Git safety, and backend execution in one small runner.

All registered pipelines are runnable through the CLI and the local STDIO MCP
control plane.

Start with the [`docs` map and change gate](docs/README.md). Architecture is
documented in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), and each pipeline
owns its specification under its workspace.

## Core Guarantees

- Pipelines own their roles, inputs, prompts, state machines, and output policy.
- The root runner owns lifecycle, persistence, backend execution, and Git safety.
- Every pipeline starts with a bounded, read-only `CLARIFY` phase.
- After clarification closes, a blocking material product decision pauses the
  pipeline through `PRODUCT_DECISION_REQUIRED`.
- Every built-in pipeline supports `independent` and `lazy` execution modes.
  `independent` is the default and recommended choice because it provides
  genuinely independent semantic review, at the cost of more provider context
  and tokens. `lazy` is an explicit lower-consumption choice that uses only the
  primary agent and does not provide independent review; it is never selected
  automatically.
- Codex and Claude can be selected independently for each pipeline role.
- Read-only agent turns include repository-mutation verification.
- Codex writable turns expose an existing real project `.agents` directory,
  while role prompts permit changing it only for an explicit task requirement
  and, during plan execution, an explicit current plan step. A symlinked
  `.agents`, `.git`, and `.codex` stay protected.
- `plan-authoring` confines writes to its resolved `clarifications.md` and
  `plan.md` artifact paths, including task directories inside the target
  repository.
- In `plan-execution`, the Worker receives one-shot authorization for the exact
  planned local commit after successful finalization and review gates.
- `polishing` finalizes and applies the selected review gate to existing
  workspace changes while preserving `HEAD` for a later commit workflow.
- Commit creation uses the repository's configured Git identity and the exact
  subject-only Conventional Commit message; validation includes
  `Co-authored-by` in its trailer denylist.
- Retry exhaustion and unsafe states pause with unresolved work preserved.
- Persistent state lives outside both the target repository and task directory.
- Remote repositories and their configuration remain read-only in V1.

## Requirements

- Node.js 24 LTS: `>=24 <25`
- Git
- Codex CLI 0.147.0 or newer stable and/or Claude Code 2.1.233 or newer stable,
  depending on the selected role backends
- `bubblewrap` for trusted validation and the V1 Claude backend on Linux, plus
  `socat` for the Claude backend

The project uses native ES modules. External runtime dependencies comprise the
official Node MCP server SDK and its schema library.

## Installation

Install the pinned workspace dependencies and expose the local executable:

```bash
npm ci
npm link
agent-run --help
```

For repository development, run `node bin/agent-run.js` directly.

## Pipelines

| Pipeline         | Purpose                                                                                         | Specification                                                                    |
| ---------------- | ----------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| `plan-authoring` | Analyze a task, review a draft, and atomically write `plan.md`                                  | [`pipelines/plan-authoring/docs/SPEC.md`](pipelines/plan-authoring/docs/SPEC.md) |
| `plan-execution` | Implement, finalize, review, and locally commit every plan step                                 | [`pipelines/plan-execution/docs/SPEC.md`](pipelines/plan-execution/docs/SPEC.md) |
| `polishing`      | Polish, finalize, review, and stage existing dirty-worktree changes for a later commit workflow | [`pipelines/polishing/docs/SPEC.md`](pipelines/polishing/docs/SPEC.md)           |

Plan authoring and execution share the deterministic
[`@agent-runner/commit-plan`](packages/commit-plan/README.md) contract. The
authoring pipeline produces that artifact; the execution pipeline consumes it.
Polishing is independently owned and operates directly on the current workspace
change set.

## Configuration

Trusted provider-profile implementations and runner defaults belong to the
installed runner. Copy the
tracked [example](.agent-runner.example.json) to an ignored, untracked
`.agent-runner.json` beside it at the Agent Runner repository root. The runner
treats this local file as operator-managed input.

When present, the file requires `"schemaVersion": 1`; unknown versions, fields,
pipelines, roles, profiles, and settings are errors. `profiles` defines trusted
aliases pinned to one backend: Codex aliases map to native profile names and
Claude aliases map to absolute isolated configuration directories. Profile
entries contain provider selectors and execution preferences. A selected alias
supplies its backend; a conflicting explicit backend is invalid.

`issueReporting` is a runner-local boolean and defaults to `true`. It controls
the MCP-only unexpected-issue tool described below. Set it to `false` and
restart the MCP server to remove the tool, its schema, and all related server
instructions from discovery. This discovery switch is restart-scoped; each
fresh report reloads the current runner configuration. Its scope is the
runner-local configuration.

A target repository may optionally provide an ignored, untracked
`LOCAL_ARTIFACTS/agent-runner.json`, or a new run may select another confined
ignored path with `--project-config`. A project file may select aliases already
trusted by the runner, set backend/model/context defaults, override pipeline
roles and limits, and select a normalized repository-relative `artifactRoot`.
Its accepted fields select runner-trusted aliases, execution preferences,
pipeline settings, and the artifact root. Agent Runner expects an existing
ignored, untracked, confined regular file.

For execution preferences, CLI/MCP role values win over CLI/MCP run-wide
values, then project-role and project-wide values, runner-role and runner-wide
values, and finally built-in `current`. Explicit CLI/MCP pipeline-setting
overrides win over project pipeline settings, which win over runner settings
and descriptor defaults. `resume` uses the persisted roles, settings, and
artifact root and never reloads the mode.

Every role accepts string `profile`, `model`, and `contextSize` selections.
A selected profile supplies its backend; `defaultBackend` provides the fallback.
Explicit decimal context sizes are validated by the chosen adapter and map to
Codex's context window or Claude's auto-compaction token window.

| Backend | `model: "current"`                                                        | `profile: "current"`                                                   |
| ------- | ------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| Codex   | Omit the model override and use the effective native Codex default        | Omit `--profile` and inherit the current process/profile               |
| Claude  | Omit `--model` and use the effective Claude configuration/account default | Omit `CLAUDE_CONFIG_DIR` and inherit the current process configuration |

The `current` selection delegates changing native model IDs to each backend.
The tracked [example](.agent-runner.example.json) makes these native defaults
explicit and shows `claude-primary` and `claude-secondary` aliases.
`artifactRoot` defaults to `LOCAL_ARTIFACTS`.

Pipeline settings use these defaults:

| Pipeline         | Setting                  |       Default |
| ---------------- | ------------------------ | ------------: |
| `plan-authoring` | `mode`                   | `independent` |
| `plan-authoring` | `maxRevisionRounds`      |            15 |
| `plan-authoring` | `stagnationWindowRounds` |             3 |
| `plan-execution` | `mode`                   | `independent` |
| `plan-execution` | `maxFixRoundsPerStep`    |             5 |
| `plan-execution` | `finalization`           |        `auto` |
| `plan-execution` | `maxDisputesPerFinding`  |             2 |
| `plan-execution` | `maxSameFindingRounds`   |             3 |
| `plan-execution` | `stagnationWindowRounds` |             3 |
| `plan-execution` | `trustedChecks`          |          `[]` |
| `polishing`      | `mode`                   | `independent` |
| `polishing`      | `maxFixRounds`           |             5 |
| `polishing`      | `finalization`           |        `auto` |
| `polishing`      | `maxDisputesPerFinding`  |             2 |
| `polishing`      | `maxSameFindingRounds`   |             3 |
| `polishing`      | `stagnationWindowRounds` |             3 |
| `polishing`      | `trustedChecks`          |          `[]` |

`mode` accepts exactly `independent` and `lazy`. A missing value resolves to
`independent`. The tracked [example](.agent-runner.example.json) selects
`independent` explicitly for every pipeline. Runner and ignored project
configuration may select either value, and `--mode` or MCP `run_start.mode`
has highest precedence. Configuration remains strictly validated for every
declared role, but a lazy run resolves, probes, persists, and invokes only its
Planner or Worker. Reviewer and Arbiter configuration stays available in the
configuration files for a later independent run without being resolved or
exposed by the lazy run.

The stagnation window detects consecutive blocked correction rounds. In
independent mode the first full window invokes one fresh Arbiter and a second
full window pauses for the user. Lazy mode has no Arbiter and pauses at the
first full window. Harder configured limits take precedence.

For plan execution and polishing, `finalization: "auto"` uses a conventional
confined repository `finalization` skill when present. The fallback derives the
complete gate from repository instructions and project-defined checks. Use
`"none"` to select that fallback deliberately, or a normalized
repository-relative path ending in `SKILL.md` to require that exact skill. A
missing, escaping, or invalid explicit skill blocks the run. Every path retains
the dedicated fingerprint-bound finalization turn.

Required checks that need loopback listeners, Docker, a local database, or a
comparable host service may be delegated to the runner's trusted validation
executor. The runner-root catalog accepts at most 256 aliases; each pipeline
run may select at most 32 of them. Exact direct arguments may contain line
feeds for multiline scripts; other control characters remain invalid. Only the
runner-root configuration may define an alias, its exact inventory command, and
its executable/argument vector:

```json
{
  "schemaVersion": 1,
  "trustedCommands": {
    "service-tests": {
      "command": "npm run test:service",
      "executable": "npm",
      "arguments": ["run", "test:service"]
    }
  },
  "pipelines": {
    "polishing": {
      "trustedChecks": ["service-tests"]
    }
  }
}
```

An ignored project configuration may select `service-tests` through the same
pipeline setting. Runner configuration owns its command, vector, environment,
and executable. Selection resolves to a durable fingerprinted snapshot before
agent work, and resume uses that snapshot. The runner executes the vector
directly. Before agent work, it resolves bubblewrap from fixed system locations
to a canonical absolute executable protected by system-owned file and parent
permissions. The pinned path is reverified on resume and execution. Its network
namespace has a minimal read-only system and repository view, private runtime
and temporary storage, a hidden user home, and a finite non-credential
environment. Rootless Docker and command-owned services run inside the same
mount, network, and PID namespaces. A private PID namespace and an outer
process group retire that complete service tree before reconciliation. A
readiness signal classifies isolation setup failures separately from executed
check failures. Workspace, Git, ref, remote, identity,
and validation-infrastructure snapshots must remain stable. Isolation or
process-tree retirement failures block or fail closed. Agent and runner results
form one complete ordered gate for the same content,
validation-infrastructure, command, and trusted-configuration fingerprints.

Backend sessions are disposable. When a native context is full, the adapter
compacts it and retries once; persistent pressure moves ordinary turns to a
fresh session reconstructed from durable run state, artifacts, and the current
workspace. Explicit source sessions retain strict identity and lineage.
Interrupted ordinary turns revalidate canonical paths, durable task inputs, and
Git controls before restarting from the complete request in a fresh native
session. Read-only turns still require an unchanged repository. Polishing
Worker turns may preserve partial content, but index drift is rejected; the
runner owns the later staging handoff. Plan-execution recovery retains its
pipeline-specific one-shot commit reconciliation.
Interrupted local-commit turns are reconciled from Git state and never replayed.
An explicit Claude rate, quota, credit, or spend-limit rejection pauses as
`backend_unavailable`, with durable workflow state and safe workspace changes
preserved for resume.

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
Conventional Commit format. Agents consume the validated commit subject
verbatim.

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
  --mode independent \
  --profile claude-primary \
  --model sonnet \
  --worker-context-size 200000
```

Use `--project-config <path>` to select an existing ignored and untracked
project configuration confined to the canonical project. New runs accept the
flag; resume uses the resolved durable configuration.

A run may seed the mode's primary and review roles from one existing backend
session:

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
`--fork-from` remains an opaque native ID. Participating primary and review
roles must match the source backend. A known source profile supplies `current`
for those roles and every explicit participating-role profile must match it; an
unknown source profile requires `current` inheritance. In independent mode,
the first eligible turn in each pipeline-owned primary or review checkpoint
forks the source independently.
Those children are direct siblings with independent later histories, and every
Arbiter starts fresh. In lazy mode, the source is forked exactly once into the
logical Planner or Worker for the whole run. Later checkpoints continue that
child when compatible or reconstruct the same logical role without forking the
source again. The source always stays immutable, and correctness never depends
on a native session surviving interruption. The runner persists the source,
resolved profile, lineage, and the one-time lazy-fork marker for recovery and
resume. Prefer a fresh start for a long, multi-topic, or uncertain source
session; independent forks can consume its provider context and quota more than
once.

Add `--clarify` to any `run` command to open `$VISUAL` or `$EDITOR` before
the primary agent checks whether more information is needed. The default
clarification phase opens the editor when the agent asks a material question.
In a non-interactive environment, the run pauses and prints the clarification
path. An empty clarification artifact and closing the proactive editor without
changes complete the round with zero agent questions. Unanswered agent
questions pause the run.

Authoring uses `<task-dir>/clarifications.md`. Execution and polishing keep
their run-specific transcript under
`<project>/<artifactRoot>/agent-runner/<run-id>/clarifications.md`, where
`artifactRoot` defaults to `LOCAL_ARTIFACTS`. Preflight requires the target
repository to ignore that resolved path. Ignore rules remain operator-managed.
The artifact has an independent hash and stays outside planned commits.
Execution pauses for a revised plan and a
new run if clarification input conflicts with the validated plan. Plan
authoring's task-owned `clarifications.md` and `plan.md` remain beside `task.md`.

Independent-mode role backends are configured independently:

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
ID, pipeline state-schema version, and an explicit runtime compatibility tuple
independent from the package version. Compatible legacy state is migrated by
the owning pipeline under the per-run lease; incompatible readers return a
specific version-skew error while preserving the run. The mode-aware pipeline
versions are plan-authoring version 3, plan-execution version 13, and polishing
version 9. Their ordered migrations resolve every supported legacy run to
`independent` without moving terminal workflows or replaying role turns,
commits, or handoffs. Complete write-ahead events precede atomic state
replacement; recovery repairs a lagging state file and derived progress.
Mutating runs require one per-run execution lease. Plan execution and polishing
also serialize ownership with an external lease keyed by the canonical Git
worktree, granting mutation ownership to one run ID at a time. Both leases
support safe same-host stale recovery;
status and bounded public activity reads remain lock-free. `run` and `resume`
print concise labeled activity as it is persisted; `status` prints the resolved
mode, current state, pause, artifact paths, findings, fingerprints, commit SHAs,
and a bounded public activity summary.

An action-free resume also recovers a nonterminal, nonpaused persisted active
turn after its execution owner is lost. Recovery retains the active marker
through input and repository reconciliation, replaces it when the complete
request restarts, and clears it only after normal post-turn reconciliation. If
correction reconciliation advanced the checkpoint before the marker could be
cleared, resume clears that completed marker after the same safety checks and
continues from the advanced checkpoint without replaying the correction.
Lazy check/fix and clean-confirm checkpoints persist their intent, accepted
fingerprint, and round accounting so resume reconciles partial writable content
or read-only mutation without replaying an accepted effect or counting a round
twice. The one-time source-fork marker prevents reconstruction from forking the
source again.

Plan execution and polishing accept one applicable resume action at a time:

```bash
agent-run resume --run <run-id> --extra-fix-rounds 3
agent-run resume --run <run-id> --override-finding R7
```

`run` and `resume` exit with status `2` when they return a persisted pause.
Invalid input and startup or execution failures exit with status `1`; `status`
exits successfully when it can read the requested run.

Resume after editing the reported clarification artifact or resolving a
reported retryable blocker. After clarification closes, only a
blocking material product decision may ask another question. An answer that
invalidates the validated plan or completed execution scope requires a revised
plan and a new execution run, preserving existing history.

Plan authoring keeps its independent Planner/Reviewer/Arbiter flow by default.
In lazy mode, the Planner drafts and performs state-held `CHECK_AND_FIX` rounds,
then separately confirms the exact draft read-only. Only an unchanged
structured `CLEAN` result can reach deterministic shared plan validation and
atomic `plan.md` writing; drafts never become repository writes or commits. An
invalid lazy checkpoint receives one fresh read-only correction with the same
schema and exact draft scope before an explicit retry is required.

For every execution step, the Worker implements the change and runs a dedicated
finalization gate using the configured guidance policy. Independent mode then
requires a separate Reviewer over that fingerprint. Lazy mode instead runs a
writable Worker `CHECK_AND_FIX` turn with the established review criteria;
changes return through full finalization, while an unchanged result requires a
separate read-only `CLEAN_CONFIRM`. Only a structured clean confirmation with
no repository mutation and unchanged content and validation fingerprints may
reach the same runner-owned one-shot exact-subject commit boundary.
Confirmation findings return directly to `CHECK_AND_FIX`; lazy mode has no
review dispute or Arbiter path. Remote state remains read-only.
If an unexpected runner-owned invariant rejects a finalization transition,
status retains a resumable `FINALIZE` checkpoint and exposes only a bounded
diagnostic through both the CLI and MCP.

Polishing follows the same mode-specific, fingerprint-bound gate. In lazy mode,
Worker changes after finalization require the complete finalization gate again,
and only an unchanged clean confirmation can reach `HANDOFF`. Agent turns
change content only; the runner then stages the complete confirmed change set
and leaves it uncommitted for a separate commit workflow.
Invalid lazy polishing checkpoints receive one fresh correction with the same
schema and exact content and validation-infrastructure scope. Check/fix
corrections remain content-writable and are reconciled and charged once;
clean-confirmation corrections remain read-only. A repeated invalid result
pauses at the persisted checkpoint for an explicit null retry without allowing
early handoff evidence.
Its dedicated `FINALIZE` turn runs the target project's complete validation
procedure, including required formatting or generated output, with configured
skill guidance when available. Its scope ends with fingerprint-bound validation
and review. Bootstrap, validation migration, and finalization translate
applicable tracked-content checks to `HEAD` or explicit trees and reject index
mutation, index-relative inspection, alternate-index workarounds, and commit
preparation. Staging and staged inspection in selected guidance are deferred to
the runner-owned handoff.

## MCP

Configure the installed command in Codex's `~/.codex/config.toml`:

```toml
[mcp_servers.agent_runner]
command = "agent-run"
args = ["mcp"]
tool_timeout_sec = 90000 # 25 hours; longer than the maximum 24-hour run_wait
```

For a repository-direct development setup, point Codex at the executable:

```toml
[mcp_servers.agent_runner]
command = "node"
args = ["/absolute/path/to/agent-runner/bin/agent-run.js", "mcp"]
tool_timeout_sec = 90000
```

The MCP process starts from the pinned local installation. The server uses a
local STDIO transport with stdout reserved for protocol messages. It
exposes:

- `pipelines_list`
- `run_start`
- `run_status`
- `run_activity`
- `run_wait`
- `run_respond`
- `run_resume`
- `unexpected_issue_report` when runner-local issue reporting is enabled

Use `pipelines_list` to discover the registry, then start with `run_start` and a
unique opaque idempotency key. It persists the run, returns a durable `runId`,
and launches detached execution. Its additive `projectConfigurationPath`
selects the same confined project file as `--project-config`; `profile`,
`model`, and `contextSize` set run-wide selections; the same fields inside a
`roleOverrides` entry take precedence. Optional `mode` accepts only
`independent` and `lazy` and overrides project and runner configuration.
`independent` is the default and recommended option for genuinely independent
semantic review, but it consumes more provider context and tokens. `lazy` is
opt-in for lower consumption and does not provide independent review; a
controlling agent must never select it automatically. `sourceSession.profile`
carries a known trusted source alias while its `id` remains opaque. These
optional fields are additive; the minimal fresh-start request is:

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
with that choice. An unknown profile offers `current` inheritance. Add
`sourceSession` after the user chooses the fork:

```json
{
  "sourceSession": {
    "backend": "codex",
    "id": "<opaque-session-id>",
    "profile": "codex-work"
  }
}
```

Independent mode then forks the complete source context into primary and review
roles, so each child can consume provider context and quota. Lazy mode forks it
once into the primary role and never invokes Reviewer or Arbiter. Recommend a
fresh start for a long, multi-topic, or uncertain current session. The
configured artifact root applies to runner-owned execution, polishing, and
issue-report artifacts; plan-authoring artifacts remain beside `task.md`.

`unexpected_issue_report` is deliberately separate from pipeline execution.
Use it after the supervising client agent explicitly concludes that Agent Runner
behaved genuinely unexpectedly or contrary to its documented contract.
Reportable issues are limited to unexpected runner behavior; expected
completion, configured budget exhaustion, provider usage limits, user pauses,
documented environment blockers, and invalid input follow their normal pipeline
outcomes. The supervising MCP client owns this tool surface.

The caller supplies concise English Markdown for the summary, expected and
actual behavior, occurrence, and reason the behavior was unexpected, with
optional details, run ID, and error code. Reports contain caller-supplied
bounded fields. The same runner and optional project
configuration rules resolve `artifactRoot`; the report is created under
`<artifactRoot>/agent-runner/issues/` when that destination is ignored,
untracked, confined, and link-safe. Ignore rules remain operator-managed.
The canonical project and external-state boundary are validated before its
idempotency intent reserves the collision-safe UTC filename. Publication
records durable ownership while the temporary hard link still proves it, so an
exact retry or interrupted receipt recovery returns its previously owned path.

Call `run_wait` once for the desired interval. Its `timeoutMs` accepts up to 24
hours; configure the MCP client's tool timeout above the requested wait.
[Codex](https://developers.openai.com/codex/config-reference) currently defaults
`tool_timeout_sec` to 60 seconds, which is too short for long runs, so size the
setting above to the operator's longest expected wait. A client timeout or
cancelled wait affects the wait call while the pipeline continues. Recover with
`run_status` and another explicit wait. Use `run_activity` for deliberate
inspection and `run_wait` for long event-driven waits.

MCP represents paused clarification and product decisions as structured
`pendingInput`. `run_respond` requires the request ID,
run revision, an answer for every identified question, and a new idempotency
key; optional proactive clarification accepts an empty answer array. The
controlling agent answers from explicit user context or asks the user. Answers
are appended verbatim to the durable clarification transcript before detached
execution continues. Editing the artifact and using `run_resume` remains
supported;
`run_resume` requires `expectedRevision` from the latest status or wait result,
a unique idempotency key, and only an action valid for the persisted pause. The
only non-pause exception is a null action at the exact revision of a nonterminal
persisted active turn with no live execution owner; stale revisions, non-null
actions, and concurrent owners are rejected.

Mutating tools persist an action intent before mutation and a receipt before
returning. Exact retries return the original result, while reusing a key with
different arguments is rejected. Issue reporting uses that contract for its
single local file creation. Runs continue in detached local children, so
MCP disconnects and wait cancellation affect only the client call. A detached
start or resume rejects active canonical-worktree ownership before launch and
withholds its receipt after launch until the run advances or the child owns the
worktree. Losing a concurrent ownership race keeps the durable idempotency
intent available for an exact retry, including when the competing lease is
released before the next MCP poll because child exit is acknowledged directly.
The MCP process freezes a detached-compatibility token over the root
run-envelope tuple and every sorted loaded pipeline ID/state version. The child
independently recomputes it before acquiring the run lease, recovering state,
or migrating a run. Version skew leaves the durable run, journal, leases, and
incomplete intent unchanged and returns an actionable restart-and-retry error.
The existing execution leases, Git safety checks, local-only policy, and
one-shot commit authorization remain authoritative.

CLI output and MCP progress events label public activity by role. `run_status`,
`run_wait`, and `run_activity` expose the resolved mode; `pipelines_list`
projects descriptor-owned setting values, defaults, and recommendations.
`run_status` returns a concise current snapshot; `run_activity` returns bounded
history after a cursor and a next cursor. Use activity for explicit inspection
or recovery. `run_wait` can emit the same bounded events as progress
notifications while the model sleeps; live rendering depends on the MCP host.
Public projections contain no inactive role configuration or provider-private
data.

## Pipeline Boundary

The registry is static in V1. A pipeline descriptor exports an ID, a state
version, roles, configuration settings and defaults, setting allowed values and
recommendations, descriptor-owned active-role selection, ordered migrations
from supported prior versions, pipeline-specific accepted and required `run`
options, task-input definitions, clarification and status projections,
resume-action validation, persisted-run validation, and a description; the root
CLI owns the common `--clarify` lifecycle option. Each workspace owns its
explicit JavaScript workflow. The runner provides state, events, agents, and
Git services; pipeline workspaces own mode and workflow policy.

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
│   ├── git-handoff.js
│   ├── git.js
│   ├── index.js
│   ├── mcp.js
│   ├── mcp-reporting.js
│   ├── pipeline-registry.js
│   ├── runner.js
│   ├── state-files.js
│   ├── state-actions.js
│   ├── state-journal.js
│   ├── state-lease.js
│   ├── state-validation.js
│   ├── state.js
│   ├── trusted-validation-execution.js
│   └── trusted-validation.js
├── packages/
│   └── commit-plan/
├── pipelines/
│   ├── plan-authoring/
│   ├── plan-execution/
│   └── polishing/
├── test/
├── docs/
│   ├── product/
│   ├── ARCHITECTURE.md
│   ├── CONVENTIONS.md
│   └── README.md
├── .agents/skills/
├── AGENTS.md
├── CLAUDE.md
└── RHYTHM.md
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

Format every supported tracked or non-ignored repository file:

```bash
npm run format
```

Verify formatting without changing files:

```bash
npm run format:check
```

Run the complete repository gate:

```bash
npm run check
git diff --check HEAD
git diff --cached --check
```

Run the opt-in real-backend smoke turns explicitly:

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
also stages the relevant files and drafts a Conventional Commit message.
Inside the polishing pipeline, that skill remains staging-independent and the
runner stages and inspects the complete finalized and reviewed change set
instead. Its producing roles use `HEAD`-relative or explicit-tree content checks
and never persist a staged/index-relative required check.
Finalization stops at the staged handoff boundary. Commit creation requires a
separate explicit request, and remote state remains read-only in V1.
