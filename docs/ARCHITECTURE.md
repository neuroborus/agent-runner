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
runtime context. Plan authoring and execution consume
`@agent-runner/commit-plan`; polishing has no shared-package dependency, and
pipelines never depend on each other. Do not declare an internal runtime
dependency before an actual import needs it.

## Root Runner Ownership

- CLI parsing, pipeline selection, and concise terminal output.
- Local STDIO MCP tool schemas, projections, and detached-run dispatch.
- Versioned runner configuration loading, validation, and role resolution.
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
accepted and required options, task-input definitions, clarification and status
projections, resume-action validation, and persisted-run validation are exposed
through its static descriptor; pipeline states remain workspace-owned rather
than becoming root runtime policy.

The root CLI owns `--clarify` as a common run-lifecycle option. Role and
pipeline-specific options remain in pipeline descriptors.

V1 registers:

- `plan-authoring`: produces a validated `plan.md` without changing target Git
  history.
- `plan-execution`: consumes `plan.md` and implements one reviewed local commit
  per step.
- `polishing`: polishes, finalizes, and independently reviews an existing dirty
  worktree while leaving its changes uncommitted.

The registry is static. V1 has no dynamic plugins, workflow DSL, or generic DAG
executor.

## Runner Configuration

The root runtime reads an optional `.agent-runner.json` from the Agent Runner
repository root, beside its tracked `.agent-runner.example.json`. That file is
the only source of trusted profile implementations. It may also supply runner
defaults for backends, execution preferences, pipeline limits, and the
repository-relative artifact root. The loader never rewrites it, and the local
runtime file remains ignored and untracked.

For a new run, the root also discovers an optional ignored and untracked
`<project>/LOCAL_ARTIFACTS/agent-runner.json`, or uses an explicitly selected
confined project path from CLI/MCP. Both files require `schemaVersion: 1`;
unknown versions, pipelines, roles, settings, and fields are errors. Project
configuration may select runner-trusted aliases, override execution defaults,
pipeline roles and settings, and select a normalized repository-relative
artifact root. It cannot define profiles, credentials, binaries, or arbitrary
environment values. Tracked, non-ignored, missing explicit, traversing, and
symbolic-link paths are rejected without creating a file or changing ignore
rules.

The V1 shape is:

```json
{
  "schemaVersion": 1,
  "artifactRoot": "LOCAL_ARTIFACTS",
  "defaultBackend": "codex",
  "defaultProfile": "current",
  "defaultModel": "current",
  "defaultContextSize": "current",
  "profiles": {
    "codex-work": {
      "backend": "codex",
      "profile": "work"
    },
    "claude-primary": {
      "backend": "claude",
      "configDirectory": "/profiles/claude-primary"
    }
  },
  "pipelines": {
    "plan-execution": {
      "finalization": "auto",
      "maxFixRoundsPerStep": 5,
      "roles": {
        "worker": {
          "backend": "claude",
          "profile": "claude-primary",
          "model": "sonnet",
          "contextSize": "200000"
        }
      }
    }
  }
}
```

`defaultBackend` is optional. A role's `profile`, `model`, and `contextSize`
resolve from its role-specific CLI/MCP override, the run-wide override, its
project-role value, the corresponding project-wide default, its pipeline-role
runner value, the corresponding runner-wide default, then the built-in string
`current`; a role-specific CLI override has highest precedence. Project
pipeline settings override runner settings.
A profile alias is trusted runner configuration, pins one backend, and maps
only to a native Codex profile name or an isolated Claude configuration
directory. A conflicting explicit backend is invalid; profile configuration
cannot inject credentials, binaries, or arbitrary environment variables.
Without a selected profile, the backend resolves from the role override,
pipeline-role value, then `defaultBackend`; absence is a preflight error.

`current` omits that native override. For models this means both Codex and
Claude use the model selected by their effective native profile, process, or
backend native default; Agent Runner does not hard-code a backend model ID. An
explicit context size is a decimal token string validated by the selected
adapter and mapped to Codex's context-window setting or Claude's
auto-compaction token window. These controls are not treated as otherwise
equivalent.

Pipeline descriptors validate their own settings and supply built-in defaults.
The root loader owns only the versioned envelope, strict field validation, and
resolution precedence; it does not duplicate pipeline-specific role or setting
lists.

Plan execution and polishing own a string `finalization` setting. `auto`, the
default, discovers a conventional confined repository skill and otherwise
falls back to repository instructions and project-defined checks. `none`
selects that fallback directly. Any other accepted value is a normalized
repository-relative `SKILL.md` path; a missing or unsafe explicit path blocks
the run. Runner configuration supplies the base value and a safe project
overlay may replace it. The resolved selection is persisted with the other
pipeline settings and is not reloaded on resume.

## Run Lifecycle

The root runner resolves the canonical Git root, safely loads runner and
project configuration, applies run-wide and role-specific execution overrides,
and persists the resolved roles, settings, artifact root, and optional
source-session reference and profile before pipeline work begins. `run` then
holds the new run's per-run lease while invoking its statically registered
workflow. Plan execution and polishing additionally hold one external lease
keyed by the canonical Git worktree before any workflow-owned mutation. The
runner always acquires the per-run lease first and releases the worktree lease
first. `resume` recovers the durable event history and reconstructs the same
runtime from persisted state without reloading either configuration source or
requiring a live native session. `status` remains lock-free.

`artifactRoot` defaults to `LOCAL_ARTIFACTS`. Plan execution and polishing use
it only for runner-owned repository-local artifacts beneath
`<artifactRoot>/agent-runner/<run-id>/`; ignored-path, traversal, symlink,
overlap, and fingerprint guards apply to the resolved path. Legacy runs with no
persisted selection retain `LOCAL_ARTIFACTS`. Plan authoring continues to keep
its task-owned `clarifications.md` and `plan.md` beside `task.md`.

`--fork-from <backend>:<session-id>` is accepted only on a new run. The session
ID remains opaque after the first separator; `--fork-profile <alias>` supplies
its optional trusted profile without changing that syntax. The pipeline's
primary and review roles must use the source backend and support native forking.
When the source profile is known, their `current` profile selections inherit it
and every explicit selection must match. When it is unknown, they must remain
`current`, no native profile override is supplied, and unavailable native
forking fails closed. Each checkpoint's first eligible role turns fork the
source independently, while the Arbiter remains unconstrained. Resume uses the
persisted source, resolved source profile, and child lineage and never asks for
the flags again.

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
to the persisted pause. The child owns the existing per-run execution lease
and, for plan execution or polishing, the canonical-worktree lease. Before
detached dispatch, MCP rejects an already-owned worktree without completing the
idempotency intent, leaving the reserved durable run available for an exact
retry. After spawning a mutating continuation, MCP withholds the receipt until
the run advances or that child owns the worktree lease. A child that loses a
concurrent ownership race therefore leaves the intent incomplete and exactly
retryable. The launcher reports a causally correlated child exit so this
remains deterministic when the competing lease is released between MCP polls.
An MCP disconnect, tool timeout, worktree conflict, or duplicate recovery
launch cannot create a second workflow owner.

MCP start fields remain additive, and `sourceSession` defaults to unset. When a
compatible current native session is available, the controlling agent offers a
fresh start and a deliberate fork choice, including its trusted source profile
when known. An unknown profile permits only `current` inheritance; the agent
never guesses an alias, inspects provider-private storage, or interprets the
opaque native ID. The field is passed only after the user selects the fork.
Primary and review roles then fork the complete source context independently,
so a fresh start is recommended for a long, multi-topic, or uncertain source
session to avoid unnecessary provider context and quota use.

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

Canonical-worktree leases live under
`worktrees/<sha256(canonical-worktree-path)>/` in that external root. The hash
keeps filesystem-safe bounded keys while the owner record contains only the
run ID, an opaque token, process ID, hostname, and acquisition time. Empty key
directories may remain after release; ownership exists only while `.lease` is
present.

`state.json` contains the common versioned envelope: monotonic revision,
pipeline ID and state version, an explicit runtime-compatibility tuple,
canonical paths, resolved roles, counters, hashes, pause state, session
lineage, timestamps, and opaque pipeline-owned state, including its resolved
settings from the initial revision. The compatibility generation is maintained
independently from the package version, which is not a persistence contract.
The root validates JSON shape and size without interpreting workflow roles or
outcomes.
Session lineage records an optional source-session reference, its resolved
trusted profile when known, and every direct child role/session ID with its
accepted-input and pipeline-checkpoint context key. Legacy role records missing
`profile` or `contextSize`, and missing or nullable `model`, normalize to
`current` in memory without rewriting state or event history. Native session
resume remains an optimization rather than a correctness dependency.

Lock-free readers reject unsupported envelope, runtime, or pipeline versions
with an actionable version-skew error and never rewrite durable state. A
supported legacy envelope may be projected through the pipeline's explicit,
ordered migrations for status. Before workflow execution, the runner evaluates
the complete migration chain, validates the current pipeline shape, and appends
one complete migration event while holding the per-run execution lease. The
event upgrades the envelope and pipeline state atomically without rewriting
earlier history. Missing, failing, or forward-version migrations fail closed.

Plan execution persists each prepared or consumed one-shot commit authorization
and every verified commit SHA. After an ambiguous commit turn, resume verifies
the recorded authorization against Git state and never replays the effect.
Polishing has no commit authorization and preserves the initial `HEAD`, refs,
remotes, and Git identity through completion.

## Agent Context Recovery

Backend sessions are disposable execution context, not durable workflow state.
Every retryable request carries a turn prompt and a complete recovery prompt
reconstructed from validated run state, durable artifacts, and the observed
workspace. A role session is continued only when its persisted key matches the
accepted inputs, role, and pipeline-owned checkpoint. Clarification and normal
work use distinct checkpoints; plan execution also isolates Worker and Reviewer
by planned commit, while polishing isolates bootstrap from Worker and Reviewer
work. Compatible continuations receive only the current instruction and state
delta; first, forked, fresh, and context-invalidated turns receive the complete
prompt. Arbiters remain fresh.

A checkpoint's complete prompt is reconstructed from validated inputs, durable
resolved summaries, its current plan step or change-set fingerprint, active
blockers, and the pipeline's bounded decision history. These inputs remain
durable even when the native session is gone.

When a native context is full, an adapter may compact it and retry the complete
recovery prompt once. If continuation still fails, writable and read-only work
can resume in a fresh session with the same complete prompt and a concise
recovery preface.

An explicit Claude rate, quota, credit, or spend-limit rejection bypasses that
context-recovery path and all provider fallback. The rejected turn is invoked
once, then the owning pipeline persists `backend_unavailable`, its resumable
workflow state, reconciled one-shot authorization state, and any safe workspace
changes before entering `WAITING_FOR_USER`. Resume reconstructs the same
durable request after capacity returns.

An explicitly supplied source session is different: the first eligible turn of
each new primary or review checkpoint creates a direct child and returns its ID
without resuming or mutating the source. If the source cannot be forked, the
turn fails before agent work rather than silently losing lineage.

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

Every mutating run or resume holds one atomic per-run execution lease. Plan
execution and polishing also hold one atomic lease for the canonical Git
worktree throughout workflow execution and runner-authorized clarification
writes, preventing independently identified runs from mutating the same
worktree concurrently. Status and public activity reads acquire neither lease.
A competing owner is rejected; either lease is recoverable only after its age
threshold when its same-host process is demonstrably dead. Release verifies the
opaque owner token before removing a lease. Pipeline-declared run artifacts are
atomically replaced beneath the run directory, with absolute paths, traversal,
reserved state files, and symlink escapes rejected. Managed state and lease
paths must be isolated regular files rather than symbolic or hard links.

Detached MCP launch also carries the dispatching process's runtime tuple in a
bounded internal environment field. The child compares it with its loaded code
before acquiring a run lease or recovering the run. A mismatch uses a distinct
exit status that the parent converts to an actionable version-skew error; the
run and incomplete idempotency intent remain durable for retry after the MCP
process is restarted. Client disconnect and wait cancellation still affect
only the client-side operation.

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
