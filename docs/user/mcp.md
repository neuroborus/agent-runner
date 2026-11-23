# MCP

Read this topic before configuring an MCP client, starting runs, updating local
guidance or managing the issue backlog. [MCP supervision](mcp-supervision.md) owns
waits, responses, stops and recovery. The [CLI reference](cli.md) covers the shared
command-line procedures; use the [user documentation map](README.md) for other topics.

## Server configuration

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

## Tool catalog

The MCP process starts from the pinned local installation. The server uses a
local STDIO transport with stdout reserved for protocol messages. It
exposes:

- `guidance_read`
- `guidance_update`
- `update_check`
- `update_apply`
- `pipelines_list`
- `run_start`
- `run_status`
- `run_activity`
- `run_cancel`
- `run_pause`
- `run_wait`
- `run_respond`
- `run_resume`
- `issues_list`
- `issues_read`
- `issues_update`
- `unexpected_issue_report` when runner-local issue reporting is enabled

## Guidance tools

Call `guidance_read` once before first managing a run for each project, using
`projectPath` and optional `projectConfigurationPath`. It returns the complete
`commonContent`, `localContent`, and `combinedContent`, plus the resolved paths
and `localHash` needed for editing. The startup reminder remains present when
issue reporting is disabled. This read also works before init when the local
guide is absent and untracked, without creating setup or requiring an ignore rule.

After execution releases ownership, use `guidance_update` to replace the entire
local Markdown with a stable project operating lesson. Supply the same project
selectors, full `localContent`, `expectedHash` from the read's `localHash`, and
a unique `idempotencyKey`. A null hash requires an absent file; empty content
means no local additions. MCP never opens an editor or replaces the common
guide. Keep task requirements in task context or tracked project documentation
and secrets, transcripts, and raw provider output out of local guidance.

Retry an interrupted update with the same key and arguments. A completed retry
returns its recorded `projectPath`, `localPath`, `localHash`, and `updated`
receipt without overwriting later CLI or MCP edits. For a stale edit, reread,
reconcile the entire document, and submit a new mutation with a new key. See
the [operator guide](../OPERATOR_GUIDE.md#7-report-defects-and-maintain-useful-local-guidance)
for a complete replacement example and common safety precedence.

## Starting runs, modes and source sessions

Use `pipelines_list` to discover the registry, then start with `run_start` and a
unique opaque idempotency key. It persists the run, returns a durable `runId`,
and launches detached execution. Its additive `projectConfigurationPath`
selects the same integrated or bound external project file as `--project-config`;
`profile`, `model`, `contextSize`, and `effort` set run-wide selections; the same fields
inside a
`roleOverrides` entry take precedence. Effort uses the [portable enum](configuration.md) documented with role preferences;
`current` overrides lower-precedence values with the native default. Retry a
start with the same effort values and idempotency key. Detached execution and
resume use persisted effort, while status, wait, and activity keep role
configuration private. Optional `mode` overrides project and
runner configuration and is validated by the selected descriptor. All pipelines
accept `independent`, `lazy`, and `combined`.
`independent` is the default and recommended option for genuinely independent
semantic review, but it consumes more provider context and tokens. `lazy` is
opt-in for lower consumption and does not provide independent review; a
controlling agent must never select it automatically. `combined` adds primary
convergence before the full independent review gate. `sourceSession.profile`
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

Independent and combined modes then fork the complete source context into
primary and review roles, so each child can consume provider context and quota. Lazy mode forks it
once into the primary role and never invokes Reviewer or Arbiter. Recommend a
fresh start for a long, multi-topic, or uncertain current session. The
configured artifact root applies to runner-owned execution and polishing
artifacts; plan-authoring artifacts remain beside `task.md`.

## Unexpected-issue reporting

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
bounded fields. Each new issue is published once in one cross-project,
private per-user issue store: `$XDG_DATA_HOME/agent-runner/issues/` on Linux,
falling back to `~/.local/share/agent-runner/issues/`. The location maps to
user Application Support on macOS and local application data on Windows
without extending execution-platform support. The store is user data,
separate from settings, installed payloads, run state, and caches, and it
survives deletion of the originating checkout. Publication needs no project
ignore rule and never writes to the project. `projectPath` accepts a Git
worktree or an ordinary directory: Git origins use the canonical worktree root,
while non-Git origins use the canonical selected directory. Unsafe controls and
failed Git inspection are rejected. `projectConfigurationPath` stays part of
the request identity but does not load configuration or select storage.

The result is `{ "issueId", "issuePath" }`. `<issueId>.json` is one versioned
document holding the immutable rendered Markdown with its hash and the
authoritative tracking record: revision `1`, status `open`, origin project
name and canonical path, creation and update times, optional run ID and error
code, and empty plan references, resolving commit references, and note. The
statuses are `open`, `queued`, `in_progress`, `resolved`, and `dismissed`. An
exact retry returns the original receipt before origin or store resolution, so
it still succeeds after the checkout is deleted. Interrupted publication
recovers the reserved issue ID in the reserved store without duplication.
Repository-local reports from earlier versions are neither discovered nor
imported and remain untouched; an incomplete historical local publication
fails explicitly and needs a new key.

## Issue backlog

The global backlog is managed with `issues_list`, `issues_read`, and
`issues_update`, which stay registered when deliberate capture is disabled.
They read only the issue store, never the origin project, and take no
worktree lease, so they work after the checkout is deleted and while unrelated
runs own their worktrees. `issues_list` covers all projects and statuses by
default; optional `projectPath` matches the recorded origin path exactly and
`statuses` selects one or more statuses. Results are ordered by creation time,
then ID, with `limit` from 1 to 100 (default 50) and an opaque `nextCursor`
bound to the store and filters. Each entry holds `issueId`, `documentHash`, and
the tracking record. `issues_read` returns the preserved `markdown`, the
tracking record, `documentHash`, and `issuePath`.

`issues_update` requires `issueId`, the inspected `expectedRevision` and
`expectedHash` (its `documentHash`), and an `idempotencyKey`. It changes only
`status`, `planReferences`, `commitReferences`, or `note`; omitted fields stay
unchanged, while empty arrays and `null` clear them. Any status may follow any
other, including reopening. References are caller-supplied text that is never
retrieved or validated. The receipt is `{ "issueId", "revision",
"documentHash" }`. A stale revision fails without change; read again and use a
new key. An exact retry returns its receipt even after newer updates and never
overwrites them.
