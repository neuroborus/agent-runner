# Configuration

Read this topic before creating or migrating user settings, selecting project
infrastructure, or overriding role preferences. The [user documentation map](README.md)
routes [pipeline settings](pipeline-settings.md), [trusted validation](trusted-validation.md)
and [provider recovery](provider-recovery.md).

## User settings and migration

Trusted provider-profile implementations and runner defaults belong to the
user-global configuration, outside the installation:

| Platform | Configuration file                                                                                                            |
| -------- | ----------------------------------------------------------------------------------------------------------------------------- |
| Linux    | `$XDG_CONFIG_HOME/agent-runner/config.json`, or `$HOME/.config/agent-runner/config.json` when XDG is unset, empty or relative |
| macOS    | `$HOME/Library/Application Support/agent-runner/config.json`                                                                  |
| Windows  | `%APPDATA%\agent-runner\config.json` (APPDATA must include its drive or UNC share)                                            |

Create the parent directory and copy the tracked
[example](configuration.example.json) there for new settings. These location
conventions do not expand the supported execution platforms. Settings, native
credentials and durable state remain separate from application payloads.
The global layer is also called runner-root or runner-local configuration below;
it retains the same schema and authority.

For an existing installation or linked checkout, explicitly migrate its legacy
file before ordinary configuration resolution:

```bash
agent-run config migrate --from /path/to/legacy/.agent-runner.json
```

Migration validates the source and atomically copies its exact bytes only to an
absent user file, using private directories and a mode-0600 file. Identical
bytes are a no-op; conflicts, including formatting differences, never merge,
overwrite or delete either file. The source stays in place. Private temporary
files left by interruption are never adopted or removed by a later invocation.
If interruption leaves the destination linked to its temporary file, loading
and migration fail closed while preserving both names and the source. A
completed publication can be retried as an identical no-op.

The user file takes precedence over the installation-local `.agent-runner.json`;
the latter remains a compatibility fallback only when the user file is absent.
An invalid, unreadable or unsafe user file fails instead of falling back. Global
files must be bounded UTF-8 regular files without symbolic/hard links or linked
ancestors. Ordinary reads create nothing. User settings survive installation
replacement and linked development. Migration is an explicit managing-operator
action for future work; never use it to alter a running workflow's configuration.
Existing runs continue with their frozen snapshots and never reload these files.

When present, the file requires `"schemaVersion": 1`; unknown versions, fields,
pipelines, roles, profiles, and settings are errors. `profiles` defines trusted
aliases pinned to one backend: Codex aliases map to native profile names and
Claude aliases map to absolute isolated configuration directories. Profile
entries contain provider selectors and execution preferences. A selected alias
supplies its backend; a conflicting explicit backend is invalid.

`issueReporting` is a runner-local boolean and defaults to `true`. It controls
deliberate capture through the MCP-only [unexpected-issue tool](mcp.md#mcp).
Set it to `false` and restart the MCP server to remove the tool, its schema,
and all related server instructions from discovery. This discovery switch is
restart-scoped and does not select issue storage. Backlog management through
`issues_list`, `issues_read`, `issues_update`, and `agent-run issues` stays
available when capture is disabled. Its scope is the runner-local configuration.

`clientAttribution` is a runner-root-only exact `{ "name", "title" }` object
for provider-visible client identity. It defaults to
`{ "name": "agent_runner", "title": "Agent Runner" }`. Both strings must be
non-empty, trimmed, at most 256 characters, and free of unsafe control or
bidirectional formatting characters. Project configuration, CLI, MCP,
pipelines, prompts, and repository content cannot override it. Custom identity
requires support from every active role provider; Codex supports it and Claude
does not. New runs persist its normalized value and fingerprint, resume ignores
later root-configuration changes, and legacy runs use the generic default.
Public prompts, status, activity, and diagnostics do not expose it.

A target repository may optionally provide an ignored, untracked
`LOCAL_ARTIFACTS/agent-runner.json`, or a new run may select another confined
ignored path with `--project-config`. An explicitly selected external file may
instead declare an exact target-bound infrastructure root. A project file may
select aliases already trusted by the runner, set backend/model/context defaults, override pipeline
roles and limits, and select a normalized infrastructure-relative `artifactRoot`.
It may also define exact `trustedCommands` vectors under the same contract as
the runner catalog; profile implementations remain runner-owned. Agent Runner
expects an existing confined regular file; integrated Git files must also be
ignored and untracked.

## Project configuration

For an existing external setup, select its configuration explicitly with
`--project-config /workspace/infrastructure/agent-runner.json` (MCP:
`projectConfigurationPath`). Include this project-only binding in that file:

```json
{
  "schemaVersion": 1,
  "infrastructure": {
    "schemaVersion": 1,
    "placement": "external",
    "projectPath": "/workspace/project",
    "rootPath": "/workspace/infrastructure"
  },
  "artifactRoot": "artifacts"
}
```

Both binding paths must be canonical absolute paths to existing real directories.
The selected file must be below its infrastructure root, which must be disjoint
from the target. Relative infrastructure resources resolve from that root;
here the artifact path is `/workspace/infrastructure/artifacts`. The configuration
loader exposes this resolved path. Local operator guidance uses
`/workspace/infrastructure/artifacts/agent-runner/rules.md`; individual workflow
artifact publication contracts still govern where they write. External selection creates
no target files, ignore rules, pointer files or global registration. It never
discovers sibling setups automatically or merges them with integrated settings.
An explicit integrated binding uses `placement: "integrated"` and the canonical
project path for both paths; existing integrated files need no binding.
Git workflows resolve a supplied project subdirectory to the canonical worktree
target. Relative external configuration selectors resolve from the supplied
directory before that rebasing, including in polishing. Custom directory
workflows keep their supplied directory scope.

For a run that uses this file, Agent Runner persists its canonical path,
content hash, file identity, and real-directory ancestry before agent work.
External records also pin the infrastructure root and target directory identity.
The runner checks that record around provider turns and before recovery,
trusted validation, commit, handoff, and stop reconciliation. Removal, content
drift, replacement, hard links, symbolic links, or redirected ancestors pause
the run as `project_configuration_changed`; restoring similar content does not
authorize that run to continue. Legacy runs with no protection record remain
compatible and do not infer one from current files.

## Precedence and role preferences

For execution preferences, CLI/MCP role values win over CLI/MCP run-wide
values, then project-role and project-wide values, runner-role and runner-wide
values, and finally built-in `current`. Explicit CLI/MCP pipeline-setting
overrides win over project pipeline settings, which win over runner settings
and descriptor defaults. `resume` uses the persisted roles, settings, and
artifact root and never reloads the mode.

Every role accepts string `profile`, `model`, `contextSize`, and `effort`
selections.
Root and safe ignored project configuration accept `defaultEffort`, with role
`effort` values taking precedence within each layer. Portable effort values are
`current`, `low`, `medium`, `high`, `xhigh`, and `max`; `current` retains the provider
default. Use `--effort` or MCP `run_start.effort` for a run-wide override, and
`--<role>-effort` or `roleOverrides.<role>.effort` for a role override. Only
active roles persist the resolved selection, and resume reuses it without
reloading configuration.
A selected profile supplies its backend; `defaultBackend` provides the fallback.
Explicit decimal context sizes are validated by the chosen adapter and map to
Codex's context window or Claude's auto-compaction token window.

The supported backend IDs and their trusted-profile and execution rules come
from one frozen, source-controlled provider registry. The same registry builds
runner adapters, validates source-session selections, and supplies MCP backend
enums. It is an explicit extension seam for repository development, not a
runtime plugin or configuration surface.

| Backend | `model: "current"`                                                        | `profile: "current"`                                                   |
| ------- | ------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| Codex   | Omit the model override and use the effective native Codex default        | Omit `--profile` and inherit the current process/profile               |
| Claude  | Omit `--model` and use the effective Claude configuration/account default | Omit `CLAUDE_CONFIG_DIR` and inherit the current process configuration |

The `current` selection delegates changing native model IDs to each backend.
The tracked [example](configuration.example.json) selects Claude `opus` with
`high` effort for Planner/Worker roles, Codex `gpt-6.2-sol` with `xhigh`
effort for every Reviewer and Arbiter, and Claude `claude-fable-5-2` with
`high` effort for Auditor.
It also shows `claude-primary` and `claude-secondary` profile aliases alongside
the native defaults.
`artifactRoot` defaults to `LOCAL_ARTIFACTS`.

The [canonical configuration example](configuration.example.json) is packaged as a
regular resource. The root `.agent-runner.example.json` is its confined alias.
