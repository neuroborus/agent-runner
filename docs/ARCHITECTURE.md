# Architecture

Agent Runner is an npm-workspaces monorepo with one root CLI/runtime, one shared
commit-plan contract, and independently owned pipeline workspaces.

## Dependency Direction

```text
root CLI/runtime ──static registry──▶ pipeline workspaces
                                           ┊
                                           └┄ when consumed ┄▶ @agent-runner/commit-plan
```

The root runner imports registered pipelines. Pipelines do not import the root
application; the runner supplies state, event, agent, and Git services through a
runtime context. Both pipelines may depend on `@agent-runner/commit-plan` once
their implementation imports it, but they never depend on each other. Do not
declare an internal runtime dependency before an actual import needs it.

## Root Runner Ownership

- CLI parsing, pipeline selection, and concise terminal output.
- Local STDIO MCP tool schemas, projections, and detached-run dispatch.
- Versioned repository configuration loading, validation, and role resolution.
- Run IDs, atomic state, append-only events, resume, and status.
- Clarification files, editor invocation, transcript updates, and input hashes.
- Codex and Claude adapter execution and access-mode enforcement.
- Git snapshots, content fingerprints, read-only guards, remote/identity guards,
  and constrained local-commit verification.
- Static pipeline registration.

The root is one application, so these modules are not separate workspace
packages. Extract one only after it gains an independent consumer, release
lifecycle, or dependency boundary.

Each JavaScript source directory exposes outward-facing dependencies through
its `index.js`. Imports between modules in the same directory remain direct to
keep ownership visible and avoid barrel cycles.

## Pipeline Ownership

Each pipeline owns its input interpretation, roles, configuration settings and
defaults, accepted `run` options, prompts, structured-output schemas, explicit
JavaScript state machine, retry policy, and completion criteria. Roles, settings,
accepted and required options, and persisted-run validation are exposed through
its static descriptor; pipeline states remain workspace-owned rather than
becoming root runtime policy.

The root CLI owns `--clarify` as a common run-lifecycle option. Role and
pipeline-specific options remain in pipeline descriptors.

V1 registers:

- `plan-authoring`: produces a validated `plan.md` without changing target Git
  history.
- `plan-execution`: consumes `plan.md` and implements one reviewed local commit
  per step.

The registry is static. V1 has no dynamic plugins, workflow DSL, or generic DAG
executor.

## Repository Configuration

The root runtime reads an optional `.agent-runner.json` from the canonical
target repository root. The file requires `schemaVersion: 1`; unknown versions,
pipelines, roles, settings, and fields are errors. The loader never rewrites it.
A tracked `.agent-runner.example.json` documents the contract, while the local
runtime file must remain ignored and untracked. Git preflight enforces that
repository boundary before a workflow starts.

The V1 shape is:

```json
{
  "schemaVersion": 1,
  "defaultBackend": "codex",
  "pipelines": {
    "plan-execution": {
      "maxFixRoundsPerStep": 5,
      "roles": {
        "worker": {
          "backend": "claude",
          "model": "sonnet"
        }
      }
    }
  }
}
```

`defaultBackend` is optional. A role backend resolves from its CLI override,
pipeline-role repository value, then `defaultBackend`; absence after those
steps is a preflight error. A role model resolves from its CLI override, then
its pipeline-role repository value, otherwise the selected backend uses its
native default. There is no repository-wide model because model identifiers are
backend-specific. The selected adapter validates every explicit model before
that role's first agent turn.

Pipeline descriptors validate their own settings and supply built-in defaults.
The root loader owns only the versioned envelope, strict field validation, and
resolution precedence; it does not duplicate pipeline-specific role or setting
lists.

## Run Lifecycle

The root runner resolves the canonical Git root, loads repository configuration,
applies CLI role and model overrides, and persists the resolved roles, settings,
and optional source-session reference before pipeline work begins. `run` then
holds the new run's lease while invoking its statically registered workflow;
`resume` recovers the durable event history and reconstructs the same runtime
from persisted state without reloading role configuration or requiring a live
native session. `status` remains lock-free.

`--fork-from <backend>:<session-id>` is accepted only on a new run. The session
ID remains opaque after the first separator. The pipeline's primary and review
roles must use that backend and support native forking; their first turns fork
the source independently, while the Arbiter is not constrained by it. Resume
uses the persisted source and child lineage and never asks for the flag again.

The CLI renders only persisted public activity and a concise current-state
projection. A user-action pause has a distinct exit status from an internal
failure; neither status output nor activity rendering exposes raw prompts or
model transcripts.

## MCP Control Plane

`agent-run mcp` exposes the same static registry and runner through the official
Node MCP SDK over STDIO only. `src/mcp.js` owns the seven tools:
`pipelines_list`, `run_start`, `run_status`, `run_activity`, `run_wait`,
`run_respond`, and `run_resume`. It contains transport schemas and concise
projections, not a second workflow implementation. Standard output belongs
exclusively to MCP; bounded protocol diagnostics go to standard error without
prompts or model transcripts.

Mutating MCP calls require an opaque idempotency key. The state layer hashes the
key, binds it to the tool and canonical arguments, and durably records an action
intent before mutation and a receipt before returning. An exact retry returns
the receipt; reuse with different arguments fails. An incomplete intent is
reconciled against the reserved run ID, current revision, submitted transcript
hash, and execution lease before work is launched again.

`run_start` persists the run before spawning `agent-run resume` as a detached
child with no inherited standard streams. `run_respond` atomically writes the
identified answers, records their transcript hash in run state, then launches
the same detached continuation. `run_resume` accepts only an action applicable
to the persisted pause. The child owns the existing per-run execution lease, so
an MCP disconnect, tool timeout, or duplicate recovery launch cannot create a
second workflow owner.

`run_wait` is one revision-driven server-side wait that ends at an unresolved
`WAITING_FOR_USER`, `DONE`, `FAILED`, or its caller-selected timeout. Optional
MCP progress notifications carry only bounded public activity with role labels;
they do not wake a model or alter the run. Cancellation cancels only that wait.
`run_activity` remains an explicit cursor-based history read rather than a
polling primitive. V1 does not require the MCP Tasks extension, a network
transport, authentication, or a daemon.

## External Run State

The root runtime persists runs under `$XDG_STATE_HOME/agent-runner/`, falling
back to `~/.local/state/agent-runner/`. A run is addressed by an opaque ID and
stored beneath `runs/<run-id>/`; preflight rejects a state root inside the
canonical project or task directory.

MCP action intents and receipts live under `actions/<hashed-key>/` in the same
external root. The opaque key itself is not persisted. Action records are
atomically replaced and protected by a same-host process lease; they never live
inside the target or task directory.

`state.json` contains the common versioned envelope: monotonic revision,
pipeline ID and state version, canonical paths, resolved roles, counters,
hashes, pause state, session lineage, timestamps, and opaque pipeline-owned
state, including its resolved settings from the initial revision. The root
validates JSON shape and size without interpreting workflow roles or outcomes.
Session lineage records an optional source-session reference and every direct
child role/session ID, but native session resume remains an optimization rather
than a correctness dependency.

Plan execution persists each prepared or consumed one-shot commit authorization
and every verified commit SHA. After an ambiguous commit turn, resume verifies
the recorded authorization against Git state and never replays the effect.

## Agent Context Recovery

Backend sessions are disposable execution context, not durable workflow state.
Every retryable prompt can be reconstructed from validated run state, durable
artifacts, and the observed workspace. When a native context is full, an adapter
may compact it and retry once; if continuation still fails, writable and
read-only work can resume in a fresh session with a concise recovery preface.

An explicitly supplied source session is different: the adapter must create a
direct child and return its ID without resuming or mutating the source. If the
source cannot be forked, the turn fails before agent work rather than silently
losing lineage.

Interrupted one-shot effects are also different. In particular, a
`local-commit` turn is never replayed; control returns to the runner for pending
authorization and Git-state verification.

Each state transition is a small write-ahead transaction:

1. append and sync a complete `events.jsonl` record containing the next state;
2. atomically replace `state.json` using a temporary file and rename;
3. atomically regenerate the derived `progress.md` projection.

Revisions start at `1` and remain contiguous. Recovery ignores and removes only
an incomplete final event fragment, rejects malformed durable records, advances
a lagging `state.json` from the last complete event, and regenerates stale or
missing progress. Valid event history is never discarded.

Events may carry an optional bounded public activity record containing only
`actor`, `phase`, `kind`, and a concise one-line `message`. Pipelines derive
these messages from validated structured results; the state service validates
only their generic form. Cursor-based readers expose this projection without
returning private pipeline state, model output, credentials, or unhashed remote
and identity values. Persist concise structured decisions and summaries, never
raw model transcripts or chain-of-thought.

Every mutating run or resume holds one atomic per-run execution lease. Status
and public activity reads remain lock-free. A competing owner is rejected; a
lease is recoverable only after its age threshold when its same-host process is
demonstrably dead. Pipeline-declared run artifacts are atomically replaced
beneath the run directory, with absolute paths, traversal, reserved state files,
and symlink escapes rejected. Managed state and lease paths must be isolated
regular files rather than symbolic or hard links.

## Clarification Lifecycle

Every pipeline starts with an explicit, pipeline-owned `CLARIFY` state. Its
primary agent studies the task and repository read-only, then returns `READY`,
structured questions whose answers could materially change the required
behavior, scope, or planned work, or a pipeline-owned blocking outcome.
`--clarify` opens the text editor before that turn so the user can add context
proactively; otherwise the editor opens only when the agent asks a question.

The root runtime owns the common mechanics in `src/clarifications.js`: creating
the `clarifications.md` artifact, invoking `$VISUAL` or `$EDITOR`, appending
question rounds, and hashing the result. Pipelines own the artifact location,
prompt, round limit, transition out of `CLARIFY`, and safe re-entry after an
exceptional product decision. This is a bounded preparation protocol, not a
general chat or dialogue engine.

Before the first clarification turn, the runner creates the Markdown artifact
when missing and otherwise preserves its existing transcript. Keep the format
intentionally simple: the runner appends questions without rewriting prior
content. An existing empty clarification artifact is valid and must not be
replaced with a template. Closing an authorized editor without changes is also
valid. Both cases require no user text and do not consume an agent question
round. Unanswered questions already appended by an agent still require a
response.

During an authorized editor window, the resulting user edit is accepted as new
clarification input and invalidates every dependent result. Changes outside an
authorized editor window remain unexpected input changes.

MCP never launches `$VISUAL` or `$EDITOR`. It projects a pending edit as a
structured request with a stable ID, kind, identified questions and options,
rationale, artifact path, and run revision. An empty answer set is valid only
for optional proactive clarification. `run_respond` requires exactly one
non-empty answer for every identified question, preserves the supplied text,
and rejects stale or already answered requests. Editing the artifact externally
and calling `run_resume` remains available. A controlling agent answers from
explicit user context or asks the user; it must not invent a material product
decision.

```markdown
# Clarifications

## Context

<!-- Optional user context. -->

## Round 1

### Q1

Question text.

Why it matters: concise impact on scope, behavior, or planned work.

### A1

<!-- Write the answer here. -->
```

Product-decision pauses append a separate `## Product Decision N` section with
the question, concrete options when available, blocking evidence, and a user
decision field. After the authorized editor closes, the runner persists the new
artifact hash before re-entry. Store no model chain-of-thought or full agent
transcript.

Before opening the editor or pausing for an answer, persist the suspended
pipeline state, pending editor action, and last accepted artifact hash. Resume
accepts an edit only for that pending action and returns to the pipeline-owned
safe re-entry state. The authorization is one-shot and is consumed when the
editor closes or a resumed edit is accepted.

Repository-local clarification artifacts may be created only after
`git check-ignore` confirms the target repository ignores their resolved paths.
The runner never edits target ignore rules automatically.

When clarification closes, the runner freezes the artifact hash. Normal work
prompts prohibit further questions. An agent may return the structured
`PRODUCT_DECISION_REQUIRED` outcome only when progress is impossible without a
material product decision that existing task, plan, repository, conventions,
and clarification evidence cannot resolve. The runner pauses for the user and
invalidates dependent work after the answer; it never invents the requirement.
If the decision invalidates completed commits or the validated plan, the runner
requires a revised plan and a new execution run instead of rewriting history.

## Shared Commit-Plan Contract

`@agent-runner/commit-plan` is the only extracted shared domain package. It owns
the deterministic `plan.md` representation and validation rules needed by both
authoring and execution. It does not own prompts, agent roles, review behavior,
or workflow transitions.

## Global Safety Policy

Every pipeline inherits non-negotiable runner controls:

- no remote writes, pushes, or hosting-service mutations;
- no remote configuration or Git identity changes;
- no `Co-authored-by` trailers;
- active mutation checks around read-only turns;
- no repository-local clarification artifact outside an already ignored path;
- state outside target and task repositories;
- explicit pause on unsafe or unrecoverable state.
