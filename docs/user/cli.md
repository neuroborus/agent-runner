# CLI

Read this topic when starting, configuring or forking runs from the command
line, or when managing local guidance and the issue backlog. [CLI recovery](cli-recovery.md)
owns state, status, resume, stop and recovery commands. Use the
[user documentation map](README.md) for other topics.

## Commands

```bash
agent-run run plan-authoring --project /path/to/repository --task /path/to/task
agent-run run plan-execution --project /path/to/repository --task /path/to/task
agent-run run polishing --project /path/to/repository --task /path/to/task
agent-run resume --run <run-id>
agent-run status --run <run-id>
agent-run guidance --project /path/to/repository
agent-run guidance edit --project /path/to/repository
agent-run issues list [--origin /path/to/repository] [--status open]
agent-run issues read --issue <issue-id>
agent-run issues update --issue <issue-id> --expected-revision <revision> --expected-hash <hash> --status resolved
agent-run pipelines
agent-run mcp
```

## Custom plans

Author criterion-driven custom plans explicitly, including in an ordinary directory:

```bash
agent-run run plan-authoring --project /path/to/workspace --task /path/to/task \
  --plan-kind custom --criteria criteria.md \
  --source sources/catalog.md --source https://example.invalid/reference \
  --output reports/
```

Criteria may be ordinary Markdown in the selected file, task or clarification
answers; missing material criteria are resolved before drafting. Relative paths
resolve from the workspace. Sources remain read-only; URLs grant no retrieval,
and unavailable evidence stays explicit. Intended outputs are plan declarations
and receive no authoring write permission. Analysis-only plans may omit
`--output`. All three review modes retain their gates; custom plans inherit
coding requirements only when selected. Only Runner writes `clarifications.md`
and the validated `plan.md`.

Execute the reviewed custom plan with its frozen criteria and declarations:

```bash
agent-run run plan-execution --project /path/to/workspace --task /path/to/task \
  --plan-kind custom --mode combined
```

MCP `run_start` uses `pipelineId: "plan-execution"` and `planKind: "custom"`;
configuration uses `pipelines.plan-execution.planKind`. Execution takes sources,
outputs and agreed criteria from `plan.md`; authoring-only selectors cannot
replace them. Existing output files or directories can be writable. To create
new files, prefer a declared output directory; a trailing `/` explicitly
requests directory preparation under an existing real parent. Missing slashless
outputs require proved exact-file creation, unsupported by Codex's named-profile
route and Claude's exact mounts. Codex also refuses existing regular-file roots;
Claude requires an existing exact file or directory mount root. Admission checks
every output before new preparation or writable work. Prose grants no kind or
parent writes. Correct declarations or select a supported backend only in an
authorized fresh run; frozen selectors remain unchanged.

All three modes retain candidate convergence, criterion-dependent finalization
and distinct read-only terminal confirmation. `finalization: auto` selects no
coding skill for custom work; explicit selected guidance remains frozen. A
semantic-only step may need no executable checks, but it still requires its
review gates. Selected trusted commands keep their exact provenance. Each
settled result records bounded analysis, criterion evidence and exact output
fingerprints; status exposes accepted-step receipts. Interruptions reconcile
pending acceptance before advancing. Earlier accepted outputs remain immutable.
Custom execution never stages, commits or gains automatic coding gates, including
inside a repository. Commit execution retains exact subjects, observed initial
changes and one-shot commit authorization.

Clarification artifacts inside a Git repository must already be ignored and
untracked, including custom authoring; the runner never changes ignore rules.

MCP `run_start` uses `planKind: "custom"`, `criteriaPath: "criteria.md"`,
`sourceReferences: ["sources/catalog.md"]` and
`outputPaths: ["reports/"]`. The same fields belong under
`pipelines.plan-authoring` in global/project configuration. CLI/MCP overrides
win; selections and read bindings freeze for resume. Omitted and legacy kinds
remain `commit`, including with supplemental criteria. Unknown or mismatched
kinds fail closed; absent Git never selects custom.

## Guidance

`guidance` prints the complete common operator guide and local additions.
`guidance edit` opens the entire local Markdown in `$VISUAL`, then `$EDITOR`
if the preferred editor cannot launch. Both commands accept
`--project-config <path>` using the same configuration rules as a new run.
Local additions resolve as `<artifactRoot>/agent-runner/rules.md` from the selected
infrastructure root, or from the target without configuration. For example:

```bash
agent-run guidance --project /workspace/project --project-config /workspace/infrastructure/agent-runner.json
```

Guidance supports ordinary directories without Git. Git selectors use the
worktree target, including explicit configurations selected from subdirectories.
An explicit configuration bound to the supplied directory retains that scope
and shares the enclosing worktree's exclusion lease when present.
An absent, untracked local guide can be read before init without an ignore rule;
the result includes the complete common guide, empty local content, a null local
hash and the resolved paths. Existing integrated Git guides, edit/update
destinations and temporary files must already be ignored and untracked. Explicit
external selection reads and updates only the bound infrastructure; it creates
no target files, ignore rules, pointers or Git-control changes and never merges
local additions from another placement. Reads create neither files nor state.
For editors that launch a separate window, configure their wait flag so the
command remains open until editing is complete.

Edits use a private temporary copy outside the project. A successful editor
exit validates and atomically publishes the result only if the original local
hash, destination, configuration, and execution ownership still permit it.
External publication also leases the infrastructure tree, excluding publishers
from other targets that select the same destination.
Interrupted publication also retains its original infrastructure and directory
identities across restart. Changed settings cannot redirect an old intent, and
completed retries return their original receipt without publishing again.
An unchanged close is a checked no-op, including when no local file exists.
An empty edited document removes all additions. Editor failure, unsafe content,
or a concurrent change preserves the local document; reread and reconcile a
stale edit. These commands do not create a pipeline run.

## Issue backlog

`issues list`, `issues read`, and `issues update` manage the
[global issue backlog](mcp.md#mcp) through the same shared capability as
`issues_list`, `issues_read`, and `issues_update`, with the same records,
validation, and conflicts. They need no configuration, ignore `issueReporting`,
construct no run, and never inspect the origin project, so they work after the
checkout is deleted. Each prints one JSON result. `--origin` matches the
recorded origin path exactly; repeat `--status` to select several statuses, and
continue with `--limit` and the returned `nextCursor` as `--cursor`. For
example, record a repair from the inspected `tracking.revision` and
`documentHash`:

```bash
agent-run issues update --issue <issue-id> \
  --expected-revision 1 --expected-hash <documentHash> --status resolved \
  --plan-reference plan.md#commit-2 --commit-reference 0123456789abcdef \
  --note "Repaired by the referenced commit." --idempotency-key repair-1
```

Update changes only the supplied tracking fields. Repeated `--plan-reference`
or `--commit-reference` values replace that list, and `--clear-plan-references`,
`--clear-commit-references`, and `--clear-note` clear it. Without
`--idempotency-key`, the generated retry key is printed on stderr before the
update and included in its JSON receipt; retry an uncertain update with that
key and the same arguments. After a stale-revision failure, read again and use
a new key. Deliberate new reports remain MCP-only.

## Role preferences

Run-wide preferences use `--profile`, `--model`, `--context-size`, and `--effort`.
Role-specific values use derived flags such as `--worker-profile`,
`--reviewer-model`, `--planner-context-size`, or `--worker-effort`; role-specific
values win. Use a trusted alias, backend-native model ID, decimal token string,
or portable effort value respectively. Effort accepts only
`current|low|medium|high|xhigh|max`; select it separately from the model ID:

```bash
agent-run run polishing \
  --project /path/to/repository \
  --task /path/to/task \
  --mode independent \
  --profile claude-primary \
  --model sonnet \
  --effort high \
  --worker-context-size 200000
```

## Project configuration

Use `--project-config <path>` to select an existing integrated or explicitly
target-bound external project configuration. Integrated Git files must be
ignored and untracked. New runs accept the flag; resume uses the resolved durable
configuration.

## Source-session forks

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
unknown source profile requires `current` inheritance. In independent and
combined modes, the first eligible turn in each pipeline-owned primary or review checkpoint
forks the source independently.
Those children are direct siblings with independent later histories, and every
Arbiter starts fresh. In lazy mode, the source is forked exactly once into the
logical Planner, Worker or Auditor for the whole run. Later checkpoints continue that
child when compatible or reconstruct the same logical role without forking the
source again. The source always stays immutable, and correctness never depends
on a native session surviving interruption. The runner persists the source,
resolved profile, lineage, and the one-time lazy-fork marker for recovery and
resume. Prefer a fresh start for a long, multi-topic, or uncertain source
session; independent forks can consume its provider context and quota more than
once.

## Clarification

Add `--clarify` to any `run` command to open `$VISUAL` or `$EDITOR` before
the primary agent checks whether more information is needed. The default
clarification phase opens the editor when the agent asks a material question.
In a non-interactive environment, the run pauses and prints the clarification
path. An empty clarification artifact and closing the proactive editor without
changes complete the round with zero agent questions. Unanswered agent
questions pause the run.

Authoring uses `<task-dir>/clarifications.md`. Execution and polishing keep
their run-specific transcript under
`<infrastructure-root>/<artifactRoot>/agent-runner/<run-id>/clarifications.md`.
The selected configuration owns that root; without configuration it is the target.
`artifactRoot` defaults to `LOCAL_ARTIFACTS`. New runs freeze this ownership;
legacy runs keep their exact repository-owned paths, including pending edits.
Any enclosing repository must already ignore the untracked transcript.
Ignore rules remain operator-managed.
The artifact has an independent hash and stays outside planned commits.
Execution pauses for a revised plan and a
new run if clarification input conflicts with the validated plan. Plan
authoring's task-owned `clarifications.md` and `plan.md` remain beside `task.md`.

## Role backends

Independent-mode role backends are configured independently:

```bash
agent-run run plan-execution \
  --project /path/to/repository \
  --task /path/to/task \
  --worker codex \
  --reviewer claude \
  --arbiter codex
```

## Exit statuses

The [CLI dispatcher](../../src/cli.js) owns command and workflow exit statuses.
Read [run recovery](cli-recovery.md) for paused and failed outcomes.
