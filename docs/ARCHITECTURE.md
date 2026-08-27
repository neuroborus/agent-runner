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
- Runner-trusted exact-vector validation outside agent turns, with bounded
  results and repository mutation guards.
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
  "issueReporting": true,
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
  "trustedCommands": {
    "service-tests": {
      "command": "npm run test:service",
      "executable": "npm",
      "arguments": ["run", "test:service"]
    }
  },
  "pipelines": {
    "plan-execution": {
      "finalization": "auto",
      "trustedChecks": ["service-tests"],
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

`issueReporting` is runner-local, defaults to `true`, and is not accepted in a
project configuration. The MCP process loads it once at startup; applying a
change requires a restart. A disabled server omits the reporting tool, schema,
and related instructions from discovery. Other runner settings are reloaded
for each fresh report and persisted through its resolved reservation.

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

`trustedCommands` is runner-only configuration. Each lowercase alias binds one
exact inventory command to one executable and argument vector; definitions
cannot carry environment values. Plan execution and polishing each own a
`trustedChecks` setting that may select aliases, and an ignored project
configuration may replace that pipeline's selection, but project configuration
cannot define an alias, binary, argument, environment value, or new host
command. The default selection is empty. Before agent work, the root resolves
it into an immutable snapshot containing every selected vector, deterministic
command identities, an ordered command fingerprint, and a
trusted-configuration fingerprint. Resume uses that durable snapshot without
reloading either configuration source.

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

Each descriptor also owns a bounded public pause projection. CLI status, MCP
status, and MCP wait render that same projection as `null` or an object with
the finite public `reason`, an optional validated bounded diagnostic `code`, a
concise `explanation`, bounded `evidence`, the validated `resumeState` when one
exists, and `nextActions`. No other persisted pause field crosses this boundary:
in particular prompts, transcripts, credentials, native responses, raw
standard error, rejected values, internal diagnostics, and counters remain private.
Unknown pause reasons fail closed to `unknown_pause` without their persisted
text.

Public next actions are concrete descriptor-owned operations. `respond`
identifies the exact pending request; `resume` carries either the validated
null retry or one valid extra-round or finding-override payload; and
`start-new-run` identifies either a revised-plan or uncontaminated-worktree
requirement. A submitted input awaiting detached continuation exposes no second
action. Plan revision never projects resume of the stale run, and a read-only
repository mutation never projects acceptance of contaminated or hybrid
changes. This is a read-only projection of existing durable state and does not
change the root or pipeline state versions.

## MCP Control Plane

`agent-run mcp` exposes the same static registry and runner through the official
Node MCP SDK over STDIO only. `src/mcp.js` owns the seven pipeline-control
tools: `pipelines_list`, `run_start`, `run_status`, `run_activity`, `run_wait`,
`run_respond`, and `run_resume`, plus the conditionally registered MCP-only
`unexpected_issue_report`. It contains transport schemas and concise
projections, not a second workflow implementation. `src/mcp-reporting.js` owns
the narrow local publication service. Standard output belongs exclusively to
MCP; bounded protocol diagnostics go to standard error without prompts or model
transcripts.

Unexpected-issue reporting remains deliberate and caller-initiated. Its tool
description and server instructions limit it to a supervising client agent
that has explicitly concluded Agent Runner behaved genuinely unexpectedly or
contrary to its documented contract. Expected completion, exhausted configured
budgets, usage limits, expected user pauses, documented environment blockers,
and invalid user or configuration input are not reportable. Runner error paths
never invoke it, and backend role sessions are not exposed to the MCP server.

The caller supplies bounded English Markdown for every diagnostic section and
optional bounded details, run ID, and error code. The service never gathers or
attaches logs, transcripts, prompts, environment values, credentials, secrets,
or other diagnostic data automatically. It canonicalizes the Git project,
validates the external-state boundary before action persistence, loads the same
current runner and optional confined project configuration used for a new run,
and resolves `<artifactRoot>/agent-runner/issues/`. Git and filesystem guards
require that destination to be ignored, untracked, confined, and free of
symbolic- or hard-link escapes. Publication uses a sortable colon-free UTC name,
an exclusive atomic link, and collision retries without changing ignore rules
or overwriting an existing path.

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
to the persisted pause, except that an exact-revision, nonterminal, nonpaused
run with a persisted active turn and no live execution owner accepts one null
action to recover that interruption. A non-null action, stale revision, live
owner, or persisted pause is rejected without weakening ordinary pause-action
validation. The child owns
the existing per-run execution lease
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
MCP status and wait also project one bounded `execution` object. Its finite
`state` is `running` while the per-run execution lease has a live owner,
`interrupted` when persisted provider activity has lost its owner, and `idle`
otherwise; nullable `role` and `phase` come only from the common run envelope.
A read checks same-host process liveness immediately without changing the
stale threshold used for exclusive acquisition; an owner on another host
remains live because its process liveness cannot be established locally.
A timeout therefore distinguishes a live detached continuation from an
interrupted process without polling or a heartbeat.
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

An unexpected-issue action persists its intent and reserved report path before
publication. It records a published phase while the temporary hard link still
proves ownership, then removes that link and persists the path receipt before
returning. Recovery adopts a report-only path only with that durable ownership
proof; otherwise a matching file is a collision. An exact retry returns the
same path, while key reuse with different arguments fails.

Canonical-worktree leases live under
`worktrees/<sha256(canonical-worktree-path)>/` in that external root. The hash
keeps filesystem-safe bounded keys while the owner record contains only the
run ID, an opaque token, process ID, hostname, and acquisition time. Empty key
directories may remain after release; ownership exists only while `.lease` is
present.

Run, canonical-worktree, reclaiming, and MCP action leases share one durable
no-replace publication primitive. It writes and syncs the complete JSON record
to an isolated in-directory temporary file, atomically links that inode at the
lease path only when the path is absent, removes the temporary link, and syncs
the directory before acquisition returns. A lock-free reader therefore treats
an unpublished lease as absent and parses only a complete record. If it meets
the bounded internal link between publication and cleanup, including after an
interrupted publisher, it removes only the matching same-directory temporary
link to restore the isolated final file; unrecognized or persistent hard links
remain unsafe. Exclusive contention, stale-owner recovery, and release all use
the published record and continue to verify its opaque owner token.

`state.json` contains the common versioned envelope: monotonic revision,
pipeline ID and state version, an explicit runtime-compatibility tuple,
canonical paths, resolved roles, counters, hashes, pause state, session
lineage, nullable bounded active provider role/phase, timestamps, and opaque
pipeline-owned state, including its resolved settings from the initial
revision. The compatibility generation is maintained independently from the
package version, which is not a persistence contract.
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
An adapter may attach `effectStarted: false` only when it proves that its
isolated commit executor was never invoked. The pipeline durably records that
bounded proof on the consumed authorization before Git verification. After Git
independently confirms that no commit was created, the pipeline retires the
authorization before a later resume can issue a fresh ID. An absent marker or
executor failure keeps the consumed authorization on the verification-only
path, while interrupted verification retains any recorded proof for resume.
Polishing has no commit authorization and preserves the initial `HEAD`, refs,
remotes, and Git identity through completion.

Plan execution and polishing state version 2 persist the independently
bootstrapped required-check inventory, the repository-relative files that own
validation infrastructure, and a runner-computed fingerprint of those files.
Each pipeline owns a 64-item limit for each inventory field returned by one
bootstrap role and a separate 128-item limit for each runner-derived inventory
field, including persisted, finalization, and fingerprint inputs. A role that
cannot return a complete field within 64 items reports the strict
`CAPACITY_EXHAUSTED` result with that `capacityField` and `capacityLimit: 64`;
the pipeline pauses with `bootstrap_inventory_capacity_exhausted` and a bounded
public diagnostic without consuming a structured-output correction or
accepting truncated evidence.
The runner establishes that inventory from accepted Worker evidence followed by
accepted Reviewer evidence. It deduplicates exact commands and paths in stable
first-seen order and assigns contiguous `C1`-through-`Cn` IDs; reconciliation
and arbitration resolve only summaries and material disagreements and cannot
add commands or paths. Validation-migration discovery uses the same derivation.
The version-1 migration preserves safe workspace content while invalidating
active aggregate finalization and review evidence. Paused legacy evidence is
explicitly provisional: before a retry, override, finalization, or review can
advance, fresh independent Worker and Reviewer checkpoints re-establish the
inventory and the runner fingerprints it again. A consumed plan-execution
commit authorization remains on the verification path until Git resolves its
effect; migration never converts it into a replayable authorization. Immutable
terminal history is shape-upgraded without replaying an effect.

Plan execution state version 3 adds the nullable bounded pre-effect rejection
record to each pending commit. Its version-2 migration sets that record to
`null`; it never infers proof for a legacy consumed authorization.

Plan execution state version 4 adds a bounded bootstrap-correction ledger. Its
version-3 migration initializes an empty ledger without changing accepted
bootstrap context, validation evidence, workspace content, commit authority, or
workflow position. Each producing role, phase, and contract may consume at most
one read-only correction attempt. The durable entry contains only attempt `1`
and the existing bounded role, phase, contract, field, and constraint
diagnostic; rejected values and provider output are never persisted. A bounded
pending copy distinguishes a correction that still must run from consumed
history and is cleared as soon as a valid replacement is accepted. Each adapter
maps its native structured-output failure to the shared bounded
`structured-output` failure class. Pipelines consume only that backend-neutral
class, and plan execution turns it into the bounded semantic diagnostic only
after read-only mutation checks complete.

Plan execution state version 5 adds the resolved trusted-validation snapshot
and executor provenance to every accepted per-check result. Its version-4
migration selects empty legacy trust and invalidates active finalization and
review gates through the existing independent validation-migration checkpoint.
Immutable terminal evidence is shape-upgraded, and a consumed one-shot commit
authorization remains on its verification-only path; migration never makes it
replayable.

Plan execution state version 6 makes validation inventories staging-independent
and assigns the Git index exclusively to `COMMIT`. Its version-5 migration
shape-upgrades clarification, preflight, and immutable terminal states without
rediscovery; clears partial bootstrap evidence at an unfinished bootstrap; and
routes every other prepared nonterminal run through fresh independent summaries,
resolved context, and validation before advancement. A consumed commit
authorization and its gate evidence stay on the verification-only path. Git
verification runs before reconciliation, migration discovery, or another role
turn, and any still-pending migration resumes only after that effect is resolved.

Polishing state version 3 adopts the same resolved trusted-validation snapshot,
per-check executor provenance, and fingerprint-bound evidence tuple. Its
version-2 migration selects empty legacy trust, preserves safe workspace
content, and invalidates active finalization and review evidence through the
existing independent validation-migration checkpoint before advancement.
Retained `BLOCKED` and `NOT_RUN` entries in paused or immutable failed evidence
become `FAIL` without losing their bounded diagnostics. Immutable terminal
evidence is shape-upgraded without replaying work.

Polishing state version 4 adds its bounded bootstrap-correction ledger and
pending one-shot diagnostic. Its version-3 migration initializes both without
changing accepted bootstrap context, validation evidence, workspace content,
or workflow position. As in plan execution, each producing role, bootstrap or
validation-migration phase, and contract may consume one read-only correction;
only attempt `1` and the bounded role, phase, contract, field, and constraint
are durable. A valid replacement clears the pending copy, an interrupted turn
reconstructs it from state, and a second invalid result fails closed without
retaining rejected values or provider output. Validation migration also
persists its accepted bounded disagreement before arbitration, resumes that
checkpoint directly, and clears it when the migration completes.

Common run-envelope version 3 adds `activeTurn`, either `null` or the current
bounded `{ role, phase }`. Version-1 and version-2 runs project it as `null`
without rewriting state or history; the next mutating continuation persists the
explicit ordered runtime migration under the execution lease.

## Agent Context Recovery

Backend sessions are disposable execution context, not durable workflow state.
Adapter capability probes inspect the installed CLI and enforceable local
isolation only. They do not apply a selected native profile and do not claim
that its authentication or provider is usable; that is established by the
first real turn under the effective profile.
Claude derives its advertised read-only capability and turn arguments from one
plan-mode access envelope. It exposes only repository-inspection tools, allows
Bash without prompting only when the required native sandbox is active, denies
workspace and Git-metadata writes, closes command network access, and forbids
unsandboxed fallback. Workspace-write turns retain Claude's separate `auto`
permission policy and background classifier.
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
Every pipeline role turn also states that the authorized role must produce the
result itself without delegation, subagents, or multi-agent collaboration.
Prompt compliance supplements rather than replaces the adapters' fail-closed
collaboration audit.

When a native context is full, an adapter may compact it and retry the complete
recovery prompt once. If continuation still fails, writable and read-only work
can resume in a fresh session with the same complete prompt and a concise
recovery preface.

Claude turn failures use a finite adapter-owned diagnostic allowlist. Structured
`permission_denials`, `api_error_status`, result subtype, and `terminal_reason`
take precedence over bounded message matching. The adapter discards denied tool
input, native result text, raw standard error, and process causes; only its
fixed code, fixed message, allowlisted class, and safety fields cross the
boundary. Authentication remains terminal. A denial that identifies an
unexposed tool or a Bash command outside the narrow positive repository-
inspection allowlist is also terminal. Only an expected non-Bash tool or a
positively recognized safe Bash inspection may be a recoverable capability or
configuration failure. Structured provider recovery accepts only explicit
transient HTTP statuses; non-transient client statuses and an `api_error`
without a transient status fail closed with a fixed request-rejected error.

An explicit Claude rate, quota, credit, or spend-limit rejection bypasses
context recovery and provider fallback. Other allowlisted backend, capability,
configuration, usage, and provider failures use the same durable pause path.
An otherwise unclassified valid read-only result or process failure is
recoverable only because the enforced read-only envelope and the pipeline's
post-turn repository guard prove that it could not mutate the repository.
Unknown writable process outcomes remain terminal after reconciliation;
classified usage and provider failures may pause only after safe workspace
changes and control state have been reconciled. The rejected turn is invoked
once, then the owning pipeline persists `backend_unavailable`, its resumable
workflow state, reconciled one-shot authorization state, and any safe workspace
changes before entering `WAITING_FOR_USER`. Resume reconstructs the same
durable request after availability returns. No new persisted field or state
version is required.

A Worker that cannot execute required validation because of sandbox, IPC,
loopback, process-isolation, missing-service, permission, or comparable external
constraints returns a bounded structured blocker. Plan execution and polishing
persist `environment_blocked` rather than treating that condition as a code
failure, preserve safe workspace content, and invalidate any stale
fingerprint-bound finalization and review evidence. A content-changing finding
resolution resumes at `FINALIZE`; an unchanged turn resumes at its original
checkpoint. Finalization always resumes at `FINALIZE`. The workflow does not
weaken isolation or grant network or host temporary-directory access to bypass
the unavailable validation.

Finalization is fail closed. A `PASS` contains exactly one ordered result with
bounded direct evidence for every persisted required check; omitted, skipped,
substituted, replaced, or weakened checks are invalid output. The runner hashes
the identified package scripts, test-discovery and runner files, skill guidance,
and validation configuration rather than trusting an agent-supplied hash.
Changing that inventory, its file set, or its fingerprint is provisional until
the independent read-only Reviewer accepts that the task or current plan step
authorizes the complete change for the same content fingerprint. Reviewer
receives both the established and candidate tuples, so its acceptance cannot
depend on a prior session. Reviewer rejection remains a finding. Commands and
repository-relative infrastructure paths are validated and compared without
rewriting interior whitespace. Host-reported results and user attestations are
outside this trust boundary.

Plan execution gives each preparation phase one owner. Implementation and
finding-resolution turns do not invoke project finalization or perform generic
commit preparation. The dedicated finalization turn follows every substantive
instruction in the selected guidance, including checks, formatting, generation,
and staging-independent content review. Bootstrap, validation-migration, and
finalization inventories deterministically reject index mutation, staged or
index-relative inspection, implicit worktree-versus-index assertions,
alternate-index workarounds, and commit preparation; applicable content checks
use `HEAD` or explicit trees. Established checks are input only to `FINALIZE`.
After finalization and independent review bind the same content and
validation-infrastructure fingerprints, the constrained local-commit executor
alone runs `git add -A`, fixed unstaged-clean, staged-diff whitespace, and
nonempty-diff hygiene, and the subject-only commit with the validated plan
subject. The contract is
identical for Codex and Claude and does not broaden ordinary Worker access to
Git metadata.

A selected runner-trusted command is the only exception to agent-side check
execution. The runner-derived bootstrap inventory must contain its exact
configured command.
The finalization agent returns `NOT_RUN` only for those selected entries; after
the agent turn reconciles, the root executor replaces each placeholder by
running the exact persisted executable/argument vector directly without a
shell. On Linux it requires bubblewrap and runs with a private network
namespace. Before agent work, the root resolves bubblewrap only from fixed
system locations to a canonical absolute executable whose file and ancestor
directories are not writable by the runner identity. Project-relative or
project-writable `PATH` entries never participate, and resume and execution
reverify the pinned path. The namespace contains minimal read-only system and
repository mounts, private temporary storage, a hidden ambient home, private
runtime storage, and a finite non-credential environment. Isolated loopback
listeners remain available inside the command namespace, but raw host Unix
daemon and control sockets are masked.
A Docker daemon must be rootless, and every service must be command-owned inside
the same mount, network, and PID namespaces, so it cannot gain host mounts or
networking and is retired with the complete process tree. Remote network and
filesystem writes, hosting credentials, Git credential helpers, and ambient
authentication variables are unavailable. A private PID namespace and an outer
process group provide bounded TERM/KILL retirement before reconciliation. A
one-byte readiness signal emitted inside the completed isolation profile
distinguishes setup denial from an executed check failure without exposing
native output. The runner retains no stdout or stderr and records only bounded
status, exit/signal/timeout data, command identity, and fixed evidence. A full
Git snapshot before and after each command rejects workspace, index,
history/ref, remote-configuration, or identity mutation, and the complete
validation-infrastructure fingerprint is recomputed after trusted execution.
Missing isolation, an unterminated process tree, skipped, changed,
non-allowlisted, substituted, unmatched, or fingerprint-drifting checks fail
closed. The final evidence tuple binds agent and runner results to the same
content, validation-infrastructure, ordered-command, and trusted-configuration
fingerprints. This service does not broaden any agent turn's sandbox and
introduces no daemon or shell DSL.

Before plan execution or polishing accepts a producing role's bootstrap or
legacy validation-migration inventory, the root Git boundary verifies every
validation-infrastructure entry is an existing regular file whose canonical
repository-relative path exactly matches the proposed path. Missing files,
directories, symlinks, and paths traversing a symlink are field-specific
bootstrap violations; the runner does not follow or silently canonicalize
them. The producing role receives the bounded diagnostic on its one correction
turn, and a second invalid result fails closed. The deterministic aggregate is
therefore derived only from independently accepted canonical role evidence.
Plan execution additionally rejects each staging-dependent required command
with a bounded field-specific diagnostic before accepting that producing result;
the same policy rejects a finalization candidate inventory without delegating
index ownership to an ordinary Worker turn.

An explicitly supplied source session is different: the first eligible turn of
each new primary or review checkpoint creates a direct child and returns its ID
without resuming or mutating the source. If the source cannot be forked, the
turn fails before agent work rather than silently losing lineage.

Adapter failures retain only bounded diagnostics. Codex capability, isolation,
prohibited-operation, and recognized App Server failures carry one allowlisted
diagnostic class rather than a command or native response. Claude classifies
unavailable sessions, effective-profile, authentication, backend, capability,
configuration, usage, provider, permission, and process failures and derives
recoverability only from its finite class allowlist. The root agent boundary
uses those adapter-owned allowlists to normalize every thrown turn failure into
a fixed message and safe control fields; it does not duplicate backend class
lists. Every pipeline may persist the normalized class for a terminal failure
and projects it only through a deterministic CLI/MCP explanation. Native
messages, additional details, denied input, provider responses, prompts,
commands, credentials, transcripts, and process causes never cross that
boundary or enter durable state.

Codex `subAgentActivity` or another collaboration audit signal remains a
terminal `operation_multi_agent` isolation failure even though collaboration is
disabled at launch. A backend that ignores that disabled capability cannot be
accepted, reclassified as an environment blocker, or transparently retried.
Context exhaustion and interruption retain their dedicated recovery paths.

Interrupted one-shot effects are also different. In particular, a
`local-commit` turn is never replayed; control returns to the runner for pending
authorization and Git-state verification. Backend policy, profile, provider,
or turn rejection before the isolated executor may prove `effectStarted:
false`; that proof permits authorization renewal only after Git verifies that
the effect did not occur. It never makes the consumed authorization replayable.

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

Immediately before every provider invocation, the runner appends and syncs a
complete `turn-started` transition whose next state contains the bounded active
role and pipeline phase. The active turn remains durable while the provider is
blocked and through repository or one-shot-effect reconciliation, then a
second write-ahead transition clears it. If the process stops first, the stale
activity remains without a live execution owner, even while its lease record
awaits stale recovery. A resumed owner
reconstructs the request from durable pipeline state, replaces ordinary stale
activity when it starts the reconstructed turn, and clears a one-shot commit
activity only after Git verification deterministically resolves the consumed
authorization. Native sessions, polling, model-token heartbeats, and daemons
are not part of this correctness path.

Before an ordinary interrupted turn is reconstructed, the runner revalidates
the canonical project and task directories and the owning pipeline revalidates
every durable task, context, plan, and accepted clarification input. The root
Git boundary then compares the persisted snapshot with the current repository.
Read-only turns still require an unchanged workspace and index. An interrupted
plan-execution or polishing Worker may retain content and staging drift only
for a phase that originally had workspace-write authority; `HEAD`, branch and
detached state, local refs, remotes, Git identity, canonical root, and allowed
runner paths must remain unchanged. The pipeline advances its baseline only
after those checks, invalidates fingerprint-bound finalization and review
evidence when content changed, and charges interrupted correction work once.
The reconstructed request uses the complete recovery prompt in a fresh native
session, and its `turn-started` event replaces the stale marker before normal
post-turn reconciliation clears it. If a correction transition was already
persisted before process loss, recovery clears its retained marker after the
same input and Git checks and continues from the advanced checkpoint without
replaying or recounting the correction. Consumed one-shot commit turns remain
on their verification-only path and are never reconstructed or replayed.

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
