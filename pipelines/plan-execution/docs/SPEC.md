# Plan Execution Pipeline — Implementation Specification

## 1. Goal

Define the `plan-execution` pipeline that executes a predefined coding plan
autonomously, one planned commit at a time, using local coding agents through
the shared Agent Runner CLI/runtime.

The runner must:

- support both Codex CLI and Claude Code in V1;
- allow Worker, Reviewer, and Arbiter to use different backends;
- complete a bounded clarification phase before implementation begins;
- let the Worker operate unattended during normal execution;
- validate each implementation through a dedicated, optionally skill-guided finalization gate;
- independently review each planned commit by default, or run bounded
  primary-only convergence when lazy mode is explicitly selected;
- allow the Worker to fix findings and, in independent mode, dispute Reviewer
  findings;
- advance only when the exact current workspace has passed finalization and
  its mode-specific review gate with no unresolved findings;
- pause for the user when a material product decision is genuinely blocking, automated resolution reaches its limits, or execution cannot proceed safely;
- persist enough state to resume after interruption.

Core principle:

> Clarify before work. Stay autonomous afterward except for a genuinely blocking product decision or another explicit escalation.

This is a local orchestration CLI, not a general agent framework.

---

## 2. Technology Baseline

Implement the runner as plain modern JavaScript on Node.js with native ES modules.

Verified baseline as of **2026-08-16**:

- Node.js: **24.x LTS**
- latest npm release: **12.0.2**
- npm: use the version bundled with the selected Node.js 24.x release
- Codex CLI stable release used as the V1 compatibility baseline: **0.147.0**
- Claude Code current release used as the V1 compatibility baseline: **2.1.233**
- Git: required external executable

Use Node.js 24.x LTS. The supported range is **`>=24 <25`**. Do not target the Current Node.js line.

`package.json` should be minimal:

```json
{
  "type": "module",
  "engines": {
    "node": ">=24 <25"
  }
}
```

Do not pin npm in `package.json`: the runner should not depend on a specific npm version.

### Dependency policy

V1 should have **no external runtime npm dependencies unless implementation
proves one is necessary**. Internal npm-workspace dependencies are explicit
repository boundaries, not third-party runtime dependencies.

The local MCP boundary is that demonstrated exception: use the exact locked
official Node MCP server SDK and its Zod peer for protocol schemas. Do not use
them to replace deterministic pipeline or commit-plan validation.

Prefer the Node.js standard library:

- `node:child_process`
- `node:fs/promises`
- `node:path`
- `node:os`
- `node:crypto`
- `node:util`
- `node:readline/promises`
- `node:test`
- `node:assert`

Use `util.parseArgs()` for CLI parsing.

Do not add:

- TypeScript;
- a transpilation/build step;
- a CLI framework;
- a state-machine library;
- a general application validation framework;
- a logging framework;
- a database;
- a network service or daemon;
- a DI container.

Codex CLI and Claude Code are external prerequisites, not npm dependencies; the
official MCP packages are the narrow protocol-boundary exception above.

Do not hard-pin their versions in workflow logic. Detect and log installed versions during preflight. The adapters should target the current stable capabilities described below and fail clearly if the installed CLI cannot provide a required capability.

---

## 3. Inputs

The runner receives:

1. a local Git repository;
2. a task directory.

```bash
agent-run run plan-execution \
  --project /path/to/repository \
  --task /path/to/task
```

Task directory:

```text
task/
├── task.md
├── clarifications.md  # optional plan-authoring transcript
├── plan.md
└── context.md      # optional
```

- `task.md`: task/problem statement.
- `clarifications.md`: optional product decisions captured during plan authoring.
- `plan.md`: ordered commit-by-commit implementation plan.
- `context.md`: optional extra context supplied by the user.

The execution run keeps its own clarification transcript at:

```text
<project>/<artifactRoot>/agent-runner/<run-id>/clarifications.md
```

This local artifact uses the common Markdown transcript format and contains
execution-specific questions and answers. Before creating it, preflight must
use `git check-ignore` to verify that the target
repository ignores the resolved path. `artifactRoot` is a persisted normalized
repository-relative selection and defaults to `LOCAL_ARTIFACTS`. If the path is
not ignored, pause
with `local_artifacts_not_ignored`; never edit `.gitignore` or
`.git/info/exclude` automatically. The artifact is not runner state and must
never enter a planned commit. The task directory may be located inside or
outside the target repository. Runner state must therefore **never** be stored
inside the task directory or target repository.

---

## 4. Plan Format

The authoritative shared contract lives in
[`@agent-runner/commit-plan`](../../../packages/commit-plan/README.md). Before
bootstrap, this pipeline must parse and validate the plan with that deterministic
contract rather than an LLM.

The Worker must use the validated subject exactly as returned by the parser. The
runner must never ask an agent to generate or rewrite it, and multiple planned
commits must never be merged into one implementation step.

---

## 5. CLI

Required commands:

```bash
agent-run run plan-execution --project <repo> --task <task-dir>
agent-run resume --run <run-id>
agent-run status --run <run-id>
```

Use `--clarify` on `run` to open `$VISUAL`, falling back to `$EDITOR`, before
the Worker's clarification turn:

```bash
agent-run run plan-execution \
  --project /path/to/repo \
  --task /path/to/task \
  --clarify
```

Without the flag, `CLARIFY` still runs but opens the editor only if the Worker
returns questions. In a non-interactive environment, persist the pause and print
the clarification artifact path instead of attempting terminal dialogue.

Use run-wide or role-specific execution flags when native overrides are
required:

```bash
agent-run run plan-execution \
  --project /path/to/repo \
  --task /path/to/task \
  --worker codex \
  --worker-profile codex-work \
  --worker-model <codex-model-id> \
  --worker-context-size 200000 \
  --reviewer claude \
  --reviewer-profile claude-primary \
  --reviewer-model <claude-model-id> \
  --reviewer-context-size 200000
```

`--mode` accepts exactly `independent` and `lazy`. `independent` is the default
and recommended mode because it provides genuinely independent semantic review,
although its separate roles use more provider context and tokens. `lazy` is an
explicit lower-consumption choice that uses only the Worker and does not provide
independent review. The runner never selects it automatically.

An independent run may seed Worker and Reviewer from one existing session only
when both use its backend. A lazy run applies that requirement only to its
active Worker:

```bash
agent-run run plan-execution \
  --project /path/to/repo \
  --task /path/to/task \
  --worker codex \
  --reviewer codex \
  --fork-from codex:<session-id> \
  --fork-profile codex-work
```

The runner splits only the backend prefix, keeps the session ID opaque, probes
native fork support, and persists the resolved source and known trusted
profile. A known source profile supplies `current` for the Worker and, in
independent mode, Reviewer and requires every explicit participating
backend/profile selection to match. An unknown source profile requires those
profiles to remain `current` and omits the native
profile override. In independent mode, Worker and Reviewer checkpoints fork it
independently and every Arbiter remains fresh. In lazy mode, it is forked
exactly once into the logical Worker across clarification, bootstrap, all
planned commits, and every convergence checkpoint. Later checkpoints continue
that child when compatible or reconstruct the same Worker without reforking the
source. `resume` uses the persisted lineage and one-time marker. MCP leaves the
source unset unless the user deliberately selects a compatible current session
after being offered a fresh start. It includes a known trusted profile with the
fork choice, or offers only `current` inheritance when the profile is unknown.
Recommend a fresh start for a long, multi-topic, or uncertain session,
especially when independent mode would fork its complete context more than
once.

Role backends must be independently configurable:

```bash
agent-run run plan-execution \
  --project /path/to/repo \
  --task /path/to/task \
  --worker codex \
  --reviewer claude \
  --arbiter codex
```

Supported V1 backend values:

```text
codex
claude
```

The following must work:

```text
Codex worker  + Codex reviewer
Claude worker + Claude reviewer
Codex worker  + Claude reviewer
Claude worker + Codex reviewer
```

The Arbiter must also support either backend.

The pipeline descriptor declares the `worker`, `reviewer`, and `arbiter` roles
and owns active-role selection. Independent mode activates all three, with the
Arbiter still probed on demand; lazy mode activates only the Worker.
Role objects under `pipelines.plan-execution.roles` in the runner's
`.agent-runner.json` or its safe project overlay may provide optional string
`backend`, trusted `profile`, backend-specific `model`, and decimal
`contextSize` selections. The project file may only select aliases defined by
runner-root configuration; it cannot define profile implementations,
credentials, binaries, or environment values. Role-specific CLI/MCP values
take precedence over run-wide values, project values, runner values, and
built-in `current`. A trusted profile pins
its backend; conflicting explicit backend selection is invalid. `current`
omits the corresponding native override and uses the effective source-session,
process, profile, or backend default. Do not hard-code model names into
workflow logic.

The descriptor also owns the positive-integer settings and built-in defaults
listed under [Retry Limits and No-Progress Detection](#14-retry-limits-and-no-progress-detection),
plus `mode` with default and recommended value `independent`. It additionally
owns the string `finalization` setting. Its default `auto`
discovers a conventional confined repository `finalization` skill and otherwise
falls back to repository instructions and project-defined checks. `none`
selects that fallback directly; any other valid value is a normalized
repository-relative path ending in `SKILL.md` and requires that exact skill.
Runner overrides live directly under `pipelines.plan-execution`. The root
loader strictly validates both versioned envelopes and delegates these values
to the descriptor rather than duplicating pipeline policy. It discovers only
the ignored `LOCAL_ARTIFACTS/agent-runner.json` project file unless CLI/MCP
explicitly selects another confined ignored path. It never creates the file or
changes ignore rules. All configured role objects are validated
deterministically. CLI/MCP pipeline-setting overrides then win over the project
overlay, runner values, and descriptor defaults. Only active roles are
resolved, probed, persisted, source-session checked, or invoked. Inactive
configured values remain in the configuration source for a later independent
run and are not exposed through lazy state. Resolved roles, settings, and
`artifactRoot` are persisted and never reloaded on resume.

The descriptor also owns `trustedChecks`, an ordered list of unique lowercase
aliases that defaults to `[]`. Only runner-root `trustedCommands`
configuration may define an alias, its exact inventory command, and its
executable/argument vector. A safe project overlay may select runner-defined
aliases through `trustedChecks`, but cannot define or alter binaries,
arguments, environment values, aliases, or host commands. Before agent work,
the root persists every resolved vector and alias, deterministic command
identities, an ordered command fingerprint, and a trusted-configuration
fingerprint. Resume uses that durable snapshot without reloading configuration.

Codex and Claude do **not** both need to be installed for every run. Independent
mode preflight validates the selected Worker and Reviewer; the Arbiter backend
may be validated when arbitration is first needed. Lazy mode validates only the
Worker and never probes Reviewer or Arbiter.

---

## 6. Persistent State

Runner state must live outside both the task directory and target repository.

Use an OS/user state directory, for example:

```text
$XDG_STATE_HOME/agent-runner/
```

with fallback:

```text
~/.local/state/agent-runner/
```

Assign every run an opaque run ID. Persist the canonical task-directory path in
state, but do not use a mutable filesystem path as the public run identity.

`agent-run status --run <run-id>` must print the resolved state directory.

State layout:

```text
<state-root>/runs/<run-id>/
├── .lease            # present only while a mutating owner is active
├── state.json
├── events.jsonl
├── progress.md
└── context/
    ├── worker.md
    ├── reviewer.md
    └── resolved.md
```

Worktree ownership is separate from run identity:

```text
<state-root>/worktrees/<sha256(canonical-worktree-path)>/
└── .lease            # present only while one run owns this worktree
```

A mutating `run` or `resume` must acquire the atomic per-run execution lease
before recovery or workflow advancement, then acquire the canonical-worktree
lease before pipeline mutation. Release occurs in reverse order. A competing
run ID cannot own the same canonical Git worktree. Each release verifies its
opaque owner token. Stale recovery for either lease requires both the configured
age threshold and proof that the recorded same-host process is no longer alive;
age alone or a foreign host is insufficient. `status` and public activity reads
are lock-free and acquire neither lease.

### `state.json`

Machine-readable current state.

Persist at least:

- run ID;
- pipeline ID and pipeline state-schema version;
- root run-envelope schema and runtime-compatibility tuple;
- canonical project path;
- canonical task path;
- hashes of `task.md`, `plan.md`, and optional task `clarifications.md` and `context.md`;
- execution clarification path, hash, status, and question-round count;
- suspended workflow state, pending editor action, and pre-editor clarification
  hash while an editor action is pending;
- selected backends;
- detected backend versions;
- current workflow state;
- resolved pipeline mode;
- current plan step;
- expected Git HEAD;
- expected branch/ref context and local-ref fingerprint;
- expected effective remote-configuration fingerprint;
- expected effective Git-identity fingerprint;
- prepared or consumed one-shot commit authorization while `COMMIT` is pending;
- completed commit SHAs;
- current findings;
- unique user finding-override audit decisions bound to exact reviewed content
  fingerprints;
- fix/dispute counters;
- latest finalized content fingerprint;
- complete required-check inventory, validation-infrastructure file list, and
  runner-computed infrastructure fingerprint;
- bounded bootstrap-correction attempts containing only attempt number and
  deduplicated role, phase, contract, field, and constraint diagnostic batches;
- the current step's bounded finalization-correction ledger and optional
  pending attempt, containing only attempt number, step, bounded guidance and
  content-fingerprint scope, and bounded role, phase, contract, field, and
  constraint diagnostic batches;
- the current step's bounded final-Reviewer correction record and optional
  pending attempt, scoped to the finalized content and validation-
  infrastructure fingerprints and containing only attempt number, step, and
  bounded Reviewer/review field-and-constraint diagnostics;
- the current step's lazy-checkpoint correction ledger and optional pending
  attempt, scoped to `CHECK_AND_FIX` or `CLEAN_CONFIRM`, finalized content,
  and validation-infrastructure fingerprints and containing only attempt `1`,
  whether actual fix work was already charged, and bounded Worker
  field-and-constraint diagnostics;
- exact per-check finalization evidence and the fingerprint-bound
  mode-specific validation-change decision;
- the resolved runner-trusted command snapshot, command/configuration
  fingerprints, and bounded executor provenance for accepted check evidence;
- latest reviewed content fingerprint;
- the lazy clean-confirmation fingerprint and one-time source-fork marker;
- escalation reason when paused;
- an optional finite adapter diagnostic class normalized by the root boundary
  for any terminal role turn, without native provider data.

The common envelope also persists an optional opaque source-session reference,
its resolved trusted profile when known, and every direct Worker, Reviewer, or
Arbiter child session ID with its
accepted-input and pipeline-checkpoint context key, monotonic revision and
timestamps, a nullable bounded active provider role/phase, and an opaque
pipeline-owned state object. Store
correction-round snapshots and arbitration episodes there without asking the
root runtime to interpret them. Native backend session resume is optional; the
persisted task, plan, decisions, summaries, and lineage must be sufficient to
continue with a new native session.

Validate the complete next pipeline state before handing a transition to the
root state service. Write state atomically using temporary-file + rename.
The descriptor exposes an ordered migration for every supported prior pipeline
state version. Status may evaluate those migrations in memory without rewriting
history. Before execution resumes, the root evaluates the complete chain,
validates the resulting current shape, and persists one complete migration
event under the per-run execution lease. An unsupported forward version or a
missing migration returns an actionable version-skew error; invalid migration
output returns a specific migration failure instead of treating the run as
generically invalid.

Pipeline state version 2 adds the required-check and validation-infrastructure
evidence. Its version-1 migration preserves safe content and commit history,
marks resumable legacy evidence provisional, and routes active validated work
back through independent validation discovery and `FINALIZE`. A paused retry or
finding override cannot advance until that discovery completes. A consumed
commit authorization remains in `COMMIT` for Git verification and is never
cleared into a replayable effect. Immutable terminal history is upgraded without
replaying an effect.

Pipeline state version 3 adds a nullable pre-effect rejection record to a
pending commit. The record contains only a bounded diagnostic code and whether
the rejection is recoverable. Its version-2 migration sets the record to
`null`, retaining every legacy consumed authorization on the verification-only
path rather than inventing proof.

Pipeline state version 4 adds the bounded bootstrap-correction ledger. Its
version-3 migration initializes an empty ledger without changing accepted
bootstrap context, validation evidence, workflow position, safe workspace
content, or commit authority. A ledger entry records only attempt `1` plus the
producing role, phase, contract, field, and violated constraint. It never
contains the rejected value, raw structured output, or provider text. A
matching bounded pending record is cleared when the replacement is accepted;
the retained history still enforces the one-attempt limit if bootstrap later
restarts after authorized product input.

Pipeline state version 5 adds the resolved trusted-validation snapshot and
runner/agent executor provenance to accepted per-check evidence. The version-4
migration defaults legacy runs to empty trust and invalidates active
finalization and review evidence through the existing independent validation-
migration checkpoint. Immutable terminal evidence is shape-upgraded. A
consumed one-shot commit authorization remains on the verification-only path,
and migration never creates a replayable authorization.

Pipeline state version 6 makes every accepted validation inventory
staging-independent and gives the Git index one owner in `COMMIT`. Its version-5
migration shape-upgrades `CLARIFY`, incomplete preflight, `DONE`, and `FAILED`
states without role work; clears incompatible partial bootstrap evidence before
an unfinished `BOOTSTRAP` continues; and routes every other prepared
nonterminal run through fresh independent summaries, resolved context, and
validation. Safe content, frozen inputs, completed commits, counters, Git
controls, and trusted-validation state remain unchanged. A consumed commit
authorization retains its gate evidence and active verification state; Git
verification occurs before repository reconciliation, validation rediscovery,
or another role turn, and any pending validation migration continues only after
the effect is resolved.

Pipeline state version 7 adds a nullable consumed finalization correction and a
matching nullable pending marker scoped to the current commit step. The
version-6 migration initializes both to `null` without changing safe content,
workflow position, gate evidence, or commit authority. A record contains only
attempt `1`, the step, resolved-or-fallback guidance scope, the request's
content fingerprint, and the bounded Worker/finalization contract field and
constraint diagnostic. It never contains rejected values, commands, paths,
provider text, or raw structured output. The pending marker is cleared after a
valid replacement; the consumed record remains until the step commits so a
later invalid finalization result in the same step fails closed. Starting the
next step clears both records.

Pipeline state version 8 replaces the consumed record with a ledger of at most
two correction attempts. The version-7 migration losslessly wraps a consumed
or pending field diagnostic in the first batch without changing safe content,
workflow position, gate evidence, guidance, fingerprint scope, or commit
authority. Deterministic validation reports all independently detectable
violations from one finalization candidate together where practical, including
every staging-dependent required command. Attempt `1` is authorized by the
first batch. Attempt `2` is authorized only when every diagnostic in the next
batch is new; a repeated diagnostic, a mixed repeated/new batch, or any invalid
result after attempt `2` fails closed. Guidance is reconstruction metadata, not
a separate retry budget. The ledger remains scoped to the current step and
request content fingerprint and clears when that content scope changes.
Rejected values, commands, paths, provider text, and raw structured output
remain outside state and public activity. The pending copy is always the latest
ledger entry, so interruption reconstructs the same read-only attempt without
replaying or recounting consumed work.

Pipeline state version 9 makes finding overrides unique by exact finding ID and
reviewed content fingerprint and requires finalization validation
infrastructure to contain only existing canonical repository-relative regular
files. Its version-8 migration deduplicates legacy override audit entries,
preserves completed commits, safe current-step content, counters, Git controls,
and consumed one-shot effect safety, invalidates provisional finalization and
review evidence, and routes every prepared active run through fresh independent
validation discovery before advancement. A consumed commit authorization stays
on its verification-only path. Immutable terminal history is shape-upgraded
without replaying work.

Pipeline state version 10 replaces each consumed or pending bootstrap
correction's single field diagnostic with one bounded, deduplicated diagnostic
batch. The version-9 migration losslessly wraps every existing diagnostic in a
one-entry batch without changing workflow position, accepted context, safe
content, gates, counters, or commit authority. Bootstrap and validation-
migration validation collects all independently detectable violations from one
candidate where practical, including every staging-dependent command and every
lexically valid validation-infrastructure path rejected by canonical-file
inspection. The producing role still receives exactly one correction attempt
per phase and contract. A pending batch survives interruption and is cleared
only after a valid complete replacement is accepted; repeated or still-invalid
output fails closed. Rejected values, commands, paths, provider output, and
transcripts remain outside durable state and public activity.

Pipeline state version 11 adds a nullable final-Reviewer correction record and
a matching nullable pending marker. The version-10 migration initializes both
to `null` without moving workflow position, changing accepted finalization or
review evidence, reviving terminal runs, or inferring rejected output that was
never persisted. A record contains only attempt `1`, the current step, the
finalized content fingerprint, the validation-infrastructure fingerprint, and
bounded Reviewer/review field-and-constraint diagnostics. It contains no
rejected values, findings, commands, paths, provider output, prompts, or
transcripts. The pending marker survives interruption and backend
unavailability and is cleared only after a valid replacement is routed. A
still-invalid replacement retains the latest bounded pending diagnostic for an
explicit read-only retry without creating another automatic attempt.

Pipeline state version 12 adds the resolved mode, the fingerprint accepted by
lazy clean confirmation, and the one-time lazy source-fork marker. Its
version-11 migration selects `independent` and initializes the new fields
without moving an active or terminal workflow position, changing completed
commits, altering accepted gates, or replaying a pending or consumed one-shot
commit effect. Every earlier supported version migrates through this ordered
chain and therefore also resolves to `independent`; no migration replays role
turns or repository effects.

Pipeline state version 13 adds the lazy-checkpoint correction ledger and
pending marker. Its version-12 migration initializes them empty without moving
active or terminal workflow positions, changing completed commits or accepted
gate evidence, reviving terminal runs, or replaying role or commit effects.
Every earlier supported version migrates through version 12 before this
ordered initialization.

Common run-envelope version 3 independently adds nullable bounded active
provider role and phase. Version-1 and version-2 envelopes project it as `null`
without rewriting; the next mutating continuation persists the explicit runtime
migration under the per-run lease.
MCP status and timed-out wait combine that field with the live execution lease:
`running` identifies a current execution owner, including a detached
continuation; `interrupted` identifies retained provider activity with no owner,
and `idle` identifies neither. This projection uses no polling, daemon, or
heartbeat. Same-host reads check owner process liveness immediately while
exclusive acquisition and stale recovery retain their existing age threshold.

### `events.jsonl`

Append-only machine-readable event history.

Never rewrite previous events.

A partially written final line after a crash may be ignored during recovery; earlier valid lines remain authoritative history.

Every complete event contains the entire next state and its monotonic revision.
For each transition, append and sync that write-ahead event before atomically
replacing `state.json`. Recovery removes only an incomplete final fragment,
rejects malformed durable records, and advances a lagging state file from the
last valid event. Revisions are the stable cursor for resume and activity
consumers.

An event may include a bounded public activity record with `actor`, `phase`,
`kind`, and a concise one-line `message`. The pipeline derives normalized role
summaries, findings, and decisions only from validated structured results. The
state service validates generic shape and size limits without interpreting
roles or outcomes, and cursor readers expose only this safe projection rather
than private pipeline state.

Immediately before every Worker, Reviewer, or Arbiter provider call, append and
sync a `turn-started` transition containing the bounded active role and current
pipeline phase. Clear it only after read-only or writable repository
reconciliation. For the one-shot commit turn, retain it until independent Git
verification resolves the consumed authorization; an interrupted verification
never clears it or replays the Worker. A stopped ordinary turn retains its
activity without a live execution owner, even while its lease record awaits
stale recovery, and resume reconstructs the request from
the persisted checkpoint before replacing and eventually clearing that
activity.
For an ordinary interrupted turn, resume first revalidates canonical project
and task paths plus every persisted task, plan, context, task-clarification, and
execution-clarification hash. The root Git boundary then reconciles the stored
snapshot. Read-only phases require a completely unchanged workspace and index;
an interrupted Worker phase retains content and staging drift only when that
phase had workspace-write authority and only while `HEAD`, branch/detached
state, refs, remotes, Git identity, canonical root, and runner-allowed paths
remain unchanged. Safe partial changes advance the repository baseline,
invalidate dependent fingerprint-bound evidence, and count correction work
exactly once. Recovery uses the complete request in a fresh native session, and
the new `turn-started` transition replaces the stale marker before ordinary
post-turn reconciliation clears it. If correction reconciliation already
advanced the state to `FINALIZE`, resume clears the retained
`worker`/`resolve-findings` marker after those safety checks and continues from
`FINALIZE` without replaying or recounting the correction. A consumed `COMMIT`
turn is excluded: its marker remains through verification and the Worker effect
is never replayed.

Lazy `CHECK_AND_FIX` and `CLEAN_CONFIRM` are durable checkpoints. The
turn-start transition is written before invocation, and accepted content,
findings, fingerprints, and round accounting are persisted atomically before
advancement. Resume reconstructs an unfinished turn exactly once, reconciles a
writable partial change before returning through `FINALIZE`, rejects mutation
from read-only confirmation, and continues from an already advanced checkpoint
without replaying or double-counting it. The one-time source-fork marker is
persisted before the first lazy forked turn starts, so reconstruction can never
fork the source again.

Provider structured-output failure and deterministic lazy-result contract
failure are normalized to bounded Worker, phase, contract, field, and
constraint diagnostics. The first failure for an exact step, phase, finalized
content fingerprint, and validation-infrastructure fingerprint records
automatic attempt `1` and reconstructs the complete checkpoint with its
original schema in a fresh Worker session. Rejected values and provider text
are never durable or public. A pending `CHECK_AND_FIX` correction remains
workspace-writable; safe content mutation is reconciled and marked as charged
once, invalidates the gate, and returns through complete `FINALIZE` before the
correction resumes. A pending `CLEAN_CONFIRM` correction remains read-only and
requires both fingerprints to stay unchanged. A still-invalid correction
pauses at `lazy_output_invalid` with its exact resume checkpoint and an
explicit null retry. Retry reconstructs the pending attempt without allocating
another automatic attempt or charging fix work before actual work occurs.

### `progress.md`

Human-readable summary of:

- completed steps;
- important implementation changes;
- clarification questions, answers, and product-decision pauses by reference to the durable artifact;
- finalization results;
- review findings;
- fixes;
- disputes and evidence;
- arbitration outcomes;
- user overrides;
- significant decisions;
- created commit SHAs;
- pause reasons.

Do not store raw model transcripts or agent chain-of-thought.

Regenerate `progress.md` after state recovery when it is missing or stale. Write
pipeline-declared run artifacts such as `context/*.md` atomically beneath the
run directory, rejecting absolute paths, traversal, reserved state filenames,
and symlink escapes. Reject symbolic or hard links for managed state and lease
files.

---

## 7. Agent Adapter Contract

Keep the backend abstraction small and functional.

Conceptually:

```js
const backend = {
  id: "codex",

  async probe() {
    return {
      version: "...",
      structuredOutput: true,
      readOnly: true,
      autonomousWrite: true,
      gitMetadataWriteBlocked: true,
      workspaceWrite: true,
      localCommit: true,
      remoteWriteBlocked: true,
      nativeSessionContinuation: true,
      nativeSessionFork: true
    };
  },

  async run(request) {
    return {
      output: "...",
      structured: {},
      sessionId: "optional"
    };
  }
};
```

A request should contain only runner-level concepts such as:

```js
{
  cwd,
  access: "read-only" | "workspace-write" | "local-commit",
  prompt,
  recoveryPrompt, // optional; defaults to prompt
  schema,
  session: { mode: "fork" | "continue", id }, // optional
  authorizationId, // local-commit only
  commit: { expectedHead, message } // local-commit only
}
```

Backend-specific CLI flags belong only inside the adapter.

`probe()` validates installed CLI features and enforceable local isolation. It
does not apply a selected native profile or attest that the profile's
authentication and provider are usable. The first real `run()` request uses the
effective profile and reports a bounded classified failure when it cannot be
used.

For non-commit turns, an adapter error may set `recoverable: true` only when
reconstructing and retrying the durable request is safe. Safety, protocol, and
isolation failures are not recoverable; an ambiguous `local-commit` outcome is
never retried and must instead return to Git-state verification.

The root agent boundary normalizes thrown failures through the selected
adapter's own finite diagnostic-class validator. It exposes only a fixed
message, bounded code, safe effect/recovery flags, the shared structured-output
class, and the validated adapter diagnostic class. Pipelines never duplicate
backend allowlists or receive native messages, denied inputs, prompts,
commands, responses, transcripts, credentials, or process causes.

When a requested structured result cannot be produced, each adapter retains
its backend-specific bounded error code and additionally exposes only the
shared `failureClass: "structured-output"` classification. Pipeline workflow
logic consumes that class rather than backend IDs or native error codes.

A `local-commit` adapter error may additionally set `effectStarted: false`
only when the adapter proves that its isolated commit executor was never
invoked. This marker is independent of `recoverable`: policy rejection may be
non-recoverable while provider unavailability is recoverable. The absent
marker is the safe default for executor failures and every other outcome that
could have started the effect. The runner never renews an authorization from
the marker alone. It first persists the bounded code and recoverable
classification on the consumed authorization, then Git must verify that no
commit was created. An interrupted verification retains that durable proof for
resume.

Claude recoverability is derived from a finite adapter-owned diagnostic-class
allowlist. Structured permission denials, HTTP status, result subtype, and
terminal reason take precedence over bounded message matching. Backend,
capability, configuration, usage, provider, and expected-tool permission
failures may be recoverable, but Bash permission recovery requires a positively
recognized safe repository inspection. Authentication, every other Bash
denial, and permission denials proving a forbidden operation remain terminal.
Provider recovery requires an explicit transient HTTP status; non-transient
client statuses and an unqualified structured `api_error` fail closed. An
otherwise unclassified valid result or process failure is recoverable only for
a read-only turn. Denied tool input,
native result text, raw standard error, and process causes are discarded.

An explicit Claude rate, quota, credit, or spend-limit rejection is recoverable
backend unavailability, but the rejected turn itself is never retried through
compaction, a fresh session, or provider fallback. Persist
`backend_unavailable` with the resumable pipeline state, reconcile any prepared
one-shot commit authorization, preserve safe workspace changes, and enter
`WAITING_FOR_USER` after the single rejected invocation. Classified usage and
provider failures from non-commit writable turns use the same path only after
workspace and repository-control reconciliation. Unknown writable process
outcomes remain terminal. Resume reconstructs the complete request from durable
state rather than requiring the failed native session. These rules add no new
pipeline-state field or migration.

When a writable Worker turn cannot execute required validation because of
sandbox, IPC, loopback, process-isolation, missing-service, permission, or a
comparable external constraint, it returns structured `BLOCKED` with bounded
reason and evidence. The pipeline persists `environment_blocked`; it does not
turn the external constraint into a code finding or weaken the sandbox,
network, process, or host temporary-directory boundary. Safe content remains in
the workspace. A content-changing finding-resolution turn invalidates stale
fingerprint-bound evidence and resumes at `FINALIZE`; an unchanged turn resumes
at `RESOLVE_FINDINGS`. Initial implementation and finalization resume at their
original `IMPLEMENT` and `FINALIZE` checkpoints respectively.

`local-commit` is a one-turn capability used only after the runner's commit gate
and requires the `commit` constraint. It allows the Worker to stage and create
one ordinary local commit with the exact supplied message while the adapter
continues to block any other history/ref mutation, pushes, hosting-service
writes, and remote configuration changes. Fail preflight if the selected Worker
backend cannot provide that boundary; do not rely on prompt compliance alone.

Native session continuation is optional. Runner correctness must not depend on
it. `prompt` is the compact instruction and state delta for a compatible
continuation. `recoveryPrompt` is the complete durable request used for first,
forked, fresh, context-invalidated, compacted, or reconstructed turns. Continue
a persisted child only when its context key matches the accepted inputs, role,
and pipeline-owned checkpoint. The first eligible turn of each new primary or
review checkpoint forks a supplied source directly; never resume it or silently
replace an unavailable source.

Use structured output for all machine-actionable decisions:

- clarification readiness and questions;
- plan-revision requirements;
- blocking product-decision requests;
- review findings;
- Worker FIX/DISPUTE decisions;
- dispute reconsideration;
- arbitration;
- finalization pass/fail result.

Plain Markdown is acceptable for bootstrap/context summaries.

---

## 8. Backend Behavior

### Codex

Use the non-interactive Codex app-server JSONL protocol. Probe the installed
`codex-cli` version and required app-server flags before the first role turn.
Start each process with strict configuration and hosted search, browser,
computer-use, image-generation, artifact, Code Mode, JS REPL, memory,
automatic-goal, guardian-review, multi-agent, external app, plugin,
lifecycle-hook, notification, MCP, shell-environment snapshot, and skill-driven
MCP dependency installation capabilities disabled. Route no native approval to
a subagent or interactive reviewer.
Resolve and disable every configured MCP server individually, then verify the
effective configuration before starting a thread; fail closed when isolation
cannot be proven. The Codex process retains its own provider connectivity, but
command tools receive no network access, workspace-write excludes implicit
temporary-directory roots, Git metadata remains read-only, and reported
activity is rejected if it uses a disabled or unknown tool or attempts a push,
hosting-service mutation, or remote reconfiguration. Each workspace-write
app-server attempt receives one runner-created canonical owner-only private
root beneath the fixed platform temporary location. Add exactly the repository
and that root to native writable roots, keep host `/tmp` excluded, and project
only its validated temporary, cache, and runtime children as `TMPDIR`,
`XDG_CACHE_HOME`, and `XDG_RUNTIME_DIR` through the effective command shell
policy. Do not change the provider process environment. Retain the root across
in-session compaction, but validate and remove it after every success, failure,
or fresh recovery before starting another attempt with a distinct root. Unsafe
preparation or cleanup fails closed and never reports success. Read-only and
local-commit storage remain unchanged. Strip ambient Git
repository redirection and identity overrides from every Codex process
environment, and expose only Codex's filtered core environment plus those three
private paths, without shell-profile loading, to agent commands. Remove key-,
secret-, and token-named variables from the isolated local-commit executor
while retaining the ordinary environment needed by Git and hooks.
Capability, isolation, and prohibited-operation failures expose only one
bounded allowlisted diagnostic class identifying the rejected capability or
operation class. Do not retain the reported command, native error response,
credentials, or transcript as diagnostic evidence.
Reported `subAgentActivity` or any other collaboration use remains a terminal
`operation_multi_agent` isolation failure. Disabled multi-agent launch
configuration does not authorize accepting or transparently retrying a backend
that ignores the restriction.
For `ERR_CODEX_TURN_FAILED`, map only recognized App Server
`codexErrorInfo` variants to finite allowlisted terminal classes. Persist the
validated class in plan-execution failure state, but discard the native error
message, HTTP status and other variant data, additional details, provider
response, prompt, and transcript. Unknown variants add no diagnostic class.
Keep context-exhaustion compaction and interruption handling on their existing
dedicated paths.

Worker:

```text
sandbox: workspace-write
approval policy: never
```

Reviewer and Arbiter:

```text
sandbox: read-only
approval policy: never
```

Use Codex structured output / JSON Schema support for machine-actionable responses.

Validate every explicit model with `model/list` and reject any reported model
reroute. Fresh turns use `thread/start`; continuation uses `thread/resume`; and
a supplied source session uses `thread/fork`, with the returned child thread ID
persisted as role lineage. Unavailable continuation may fall back to a fresh
reconstructed turn, while an unavailable fork source is an error.

Map a trusted Codex alias only to its configured native profile name and pass
it with `--profile`. Map an explicit decimal context size to
`model_context_window`. Omit both controls for `current`; do not derive them
from native session storage.

On native context exhaustion, request thread compaction and retry the turn once.
If the context remains full, start a fresh turn reconstructed from durable
runner input and the current workspace. Never replay an interrupted
`local-commit` turn: return an ambiguous outcome so the runner consumes no
second authorization and verifies Git state before deciding how to proceed.

`local-commit` additionally supplies an opaque authorization ID, expected HEAD,
and exact subject. Its agent turn is read-only and may only confirm readiness
through the adapter's strict schema; it cannot modify files, stage changes, or
write Git metadata itself. After confirmation, the Worker adapter runs the
exact HEAD check, `git add -A`, fixed unstaged-clean, staged-diff whitespace,
and nonempty-diff hygiene, and the ordinary subject-only commit in a dedicated
Codex permission profile. That profile grants write access only to the
workspace and resolved Git directory, denies command network access, preserves
Git hooks and configured Git identity, and receives no ambient Git overrides.

Probe this isolated commit profile by verifying outside-workspace write denial,
Git-metadata writes, and network denial. Report `localCommit: false` and fail
preflight if any boundary cannot be enforced. Any interrupted or failed commit
executor returns an ambiguous outcome for the runner's one-shot authorization
and final Git-state verification; it is never replayed. Policy, capability,
provider, or confirmation-turn rejection before executor invocation carries
`effectStarted: false`, including `ERR_CODEX_LOCAL_COMMIT_POLICY`. The adapter
preserves the original bounded error code and recoverable classification.

### Claude Code

Use non-interactive print mode with JSON output. Start in safe mode, expose only
the built-in repository tools needed by the role, disable Chrome and prompt
suggestions, and load an explicitly empty MCP configuration. Supply
invocation-local settings that
disable bypass mode and commit attribution, disable model fallback, require the
native command sandbox to start successfully, deny its network access, forbid
unsandboxed command retries, and deny writes to the resolved Git metadata
directories. Use native sandbox credential-deny entries so Bash commands cannot
inherit provider credentials without enabling subprocess hardening that
downgrades `auto` to Manual mode, and reject any reported permission-mode
fallback. Fail preflight when the host cannot enforce those settings. Plan-mode
turns derive their advertised read-only capability and invocation arguments
from the same access envelope. They do not expose editing tools, deny command
writes to the workspace and Git metadata, and set
`sandbox.autoAllowBashIfSandboxed: true` so repository inspection proceeds
without a prompt only inside the required native sandbox. Unsandboxed fallback
and command network access remain disabled. On Linux, advertise read-only,
workspace-write, Git-metadata-blocking, and remote-write-blocking capabilities
only after a fixed, model-free exact-policy probe proves the Unix-socket denial
required by that native sandbox. Invoke bubblewrap directly with fixed
arguments for the outer user, PID, mount, and network namespaces, and run
`/usr/bin/true` through the resolved Claude executable's embedded
`apply-seccomp` helper. Use the credential-filtered command environment,
bounded output and time, and no shell, selected profile, authentication, or
model call; reduce failures to a boolean without retaining host diagnostics. A
generic user-namespace check is not evidence for this policy. The opt-in real
Claude smoke test must exercise a representative repository-inspection command
through this exact envelope.

Worker default:

```text
permission mode: auto
```

This is the preferred unattended mode because it removes routine user permission prompts while retaining Claude Code's background safety classifier.

If `auto` mode is unavailable for the installed Claude Code/account/model/provider combination, the adapter must **not silently fall back to Manual mode**.

For V1:

- fail preflight for a Claude Worker when autonomous execution cannot be provided safely;
- do not silently use unrestricted `bypassPermissions` on the host.

Reviewer and Arbiter:

```text
permission mode: plan
```

Do not enable bypass permissions in Reviewer or Arbiter sessions.

Use `--output-format json` and `--json-schema` for machine-actionable output.
Reject permission denials from a non-interactive turn instead of treating a
partial response as success. Pass an explicit model without a fallback chain
and reject a full model ID when the result's model usage reports a different
model.

Classify `permission_denials`, `api_error_status`, result subtype, and
`terminal_reason` before consulting at most one bounded native-text slice.
Expose only fixed error codes and messages plus a finite non-sensitive
diagnostic class. Never attach denied `tool_input`, provider result text, raw
standard error, or the native process error. A denial of an unexposed tool or a
Bash command outside the positive repository-inspection allowlist is a terminal
safety failure. An exposed non-Bash tool or a positively recognized safe Bash
inspection may be a recoverable capability/configuration failure. Treat only
explicit transient HTTP statuses as provider unavailability; fail closed on
non-transient client statuses and `api_error` without such a status. Unknown
valid read-only result failures and unclassified read-only process exits are
recoverable; the same unknown outcomes during workspace-write or one-shot
commit work are not.

Map a trusted Claude alias only to its configured absolute isolated
configuration directory through `CLAUDE_CONFIG_DIR`. Map an explicit decimal
context size to the native `--autocompact` token window. Omit both controls for
`current`, and never accept profile-provided arbitrary environment or
credential material.

Fresh turns omit resume flags. Continuation uses `--resume <session-id>`, and a
supplied source session uses `--resume <session-id> --fork-session`; persist the
returned child ID and reject the source ID as invalid fork lineage. An
unavailable continuation may reconstruct a fresh turn, but an unavailable fork
source is an error. Classify source-session and continuation-session failures
from the attempted session mode. On a fresh turn, distinguish effective-profile,
authentication, and provider failures instead of reporting a generic missing
session, and retain no native error text.

Enable native auto-compaction for every turn. On an explicit context-exhaustion
result, retry the durable request once in the same session with compaction
instructions, then reconstruct it in a fresh session if the context remains
full. Never replay an interrupted `local-commit` turn.

On Linux, the isolated local-commit executor uses a probed `bubblewrap` profile
with a read-only host filesystem, writable workspace and resolved Git
directories, private temporary and runtime directories, and no network. The
Runner-owned executor proof is independent from the native Claude turn proof,
and `localCommit` requires both while native session and structured-output
capabilities remain CLI-derived. The agent confirmation turn remains in `plan`
mode; after confirmation the executor checks the expected HEAD, runs
`git add -A`, rechecks HEAD, applies fixed
unstaged-clean, staged-diff whitespace, and nonempty-diff hygiene, and creates
one subject-only commit with the exact supplied message. It preserves Git hooks and configured
identity, strips ambient Git redirection and sensitive command environment
values, and never adds Claude attribution. Report
`localCommit: false` when either applicable proof or Claude's required Linux
sandbox dependencies fail. Policy, capability, provider, or confirmation-
turn rejection before executor invocation carries `effectStarted: false`,
including `ERR_CLAUDE_LOCAL_COMMIT_POLICY`, while preserving the classified
profile, authentication, provider, continuation, or process error and its
recoverability; an executor failure does not carry the marker.

### Backend-neutral finalization guidance

Finalization is a dedicated pipeline gate, not a Codex-only or Claude-only
feature. A repository-defined skill may guide it, but the gate does not depend
on optional guidance being present.

During bootstrap, the agent follows the persisted policy: use an explicitly
selected confined skill, discover a conventional skill in `auto`, or derive the
complete procedure from repository instructions and project-defined checks when
no skill is selected or discovered.

When the selected backend supports a resolved skill natively, it may invoke it
natively. Otherwise it reads and follows the instructions directly. An
explicitly selected missing, escaping, or invalid skill blocks; an unavailable
automatically discovered skill falls back without skipping finalization.

The same repository finalization procedure must therefore work with either
Worker backend and without skill-specific guidance.

Phase ownership is also backend-neutral. Implementation and finding-resolution
turns reserve project finalization and generic commit preparation for their
dedicated phases. The finalization turn follows all substantive guidance but
keeps its inventory staging-independent. Staging, staged/index-relative
inspection, alternate-index workarounds, staged handoff, and commit-message
drafting belong to the constrained `COMMIT` executor. Applicable content checks
use `HEAD` or explicit trees. This deferral is not a validation blocker or a
skipped required check.

---

## 9. Repository Safety Guards

A fresh `run` requires a clean Git working tree, including untracked non-ignored files.

Before any implementation work:

- verify the project is a Git repository;
- record the initial HEAD;
- record the current branch when available;
- record deterministic local-ref, effective remote-configuration, and effective
  Git-identity fingerprints;
- verify an existing Git identity can create local commits without changing
  repository, global, or system configuration;
- verify the working tree is clean;
- verify the execution clarification path is ignored by the target repository;
- hash the task input files, including task-level clarifications when present;
- detect selected agent CLIs and versions.

### Git history/ref and configuration guard

Outside a dedicated, one-shot Worker turn authorized by the runner in `COMMIT`,
**no agent is allowed to change Git history or refs**.

Before and after every agent turn, compare at least:

- `HEAD` commit;
- symbolic branch/detached-HEAD state;
- a deterministic snapshot of local refs (`git for-each-ref` is sufficient);
- a fingerprint of effective remote configuration, including remote names, fetch
  and push URLs, and repository-local `remote.*` / `url.*` configuration;
- a fingerprint of the effective configured Git author/committer identity.

Hash remote configuration and Git identity for comparison without persisting
credential-bearing URLs or personal identity values in runner state or logs.

This catches unexpected commits, branch switches, rebases, resets, stashes,
tag/ref creation, remote renames or URL changes, and similar repository-control
mutations.

If the snapshot changes unexpectedly:

```text
WAITING_FOR_USER
reason: unexpected_git_ref_change
```

Use `unexpected_remote_configuration_change` instead when history/refs are
unchanged but effective remote configuration changed.

Use `unexpected_git_identity_change` when configured author/committer identity
changed.

Do not attempt an automatic destructive recovery.

The authorized `COMMIT` turn has a narrower expected mutation. Accept it only
when the current branch advances by exactly one non-merge commit whose parent is
the expected HEAD, every other ref and the effective remote configuration and
Git identity remain unchanged, and the commit passes the checks in section 13.7.

Staging/index changes do not change repository history, so the generic
workspace-write mutation guard can reconcile them. That capability does not
authorize generic commit preparation: plan-execution prompts reserve staging
for the constrained `COMMIT` executor. Read-only roles are handled more
strictly by the mutation guard below.

### Read-only mutation guard

Worker clarification and plan-compatibility turns, every active bootstrap turn,
lazy `CLEAN_CONFIRM`, and every Reviewer and Arbiter turn are read-only.

For these turns, capture a repository snapshot before and after execution.

The snapshot must detect:

- HEAD changes;
- tracked content changes;
- untracked content changes;
- index/staging changes;
- effective remote-configuration changes;
- effective Git-identity changes.

If a supposedly read-only turn mutates repository state:

```text
WAITING_FOR_USER
reason: read_only_agent_mutated_repository
```

Do not silently revert it.

The runner may create or update only the resolved execution clarification
artifact while `CLARIFY` is active or while handling a persisted
`product_decision_required` pause. The user edits it through the configured text
editor; agents never write it directly. Hash that ignored artifact separately
before and after every agent turn. Any change outside an authorized editor
window pauses with `clarifications_changed`.

---

## 10. Content Fingerprint

Finalization and review must be tied to the exact content that would be committed.

The fingerprint must represent **repository content**, not whether a change is currently staged or unstaged.

It must include:

- current content of changed tracked files relative to HEAD;
- deletions;
- non-ignored untracked files and their content.

It must ignore staging placement itself.

This is important because `git add` before commit must not invalidate an already finalized/reviewed content fingerprint.

A practical implementation may hash:

1. a deterministic binary diff from `HEAD` to the current working-tree content;
2. sorted untracked non-ignored paths plus their file contents.

Do not modify the Git index to compute the fingerprint.

The ignored configured-root clarification transcript is not commit content and
must not affect this fingerprint. Its independently persisted hash protects it
as a run input.

---

## 11. Workflow

Persisted workflow states:

```text
CLARIFY
BOOTSTRAP
IMPLEMENT
FINALIZE
CHECK_AND_FIX
CLEAN_CONFIRM
REVIEW
RESOLVE_FINDINGS
COMMIT
WAITING_FOR_USER
DONE
FAILED
```

`CHECK_AND_FIX` and `CLEAN_CONFIRM` are used only in lazy mode. `FIX`,
`DISPUTE`, `ARBITRATE`, implementation self-review, and per-step context refresh
remain actions within the owning independent-mode states rather than separate
persisted states.

Only the runner controls transitions.

---

## 12. Clarification And Bootstrap

### Clarification

No implementation or bootstrap work may begin before `CLARIFY` closes. After
the ignore check, the runner ensures the execution clarification artifact exists
without overwriting a resumed transcript. The Worker then studies the task,
validated plan, optional plan-authoring
clarifications, existing execution transcript, repository instructions,
relevant architecture, tests, and Git history in read-only mode.

It returns structured `READY` or all currently actionable questions whose
answers could materially change required behavior, scope, or implementation of
the validated plan. It must use available evidence instead of asking about
ordinary technical choices.

```json
{
  "status": "READY",
  "questions": []
}
```

or:

```json
{
  "status": "QUESTIONS",
  "questions": [
    {
      "question": "Which externally visible behavior is required?",
      "whyItMatters": "The answer changes implementation of the validated step."
    }
  ]
}
```

or, when the clarification input conflicts with the validated plan:

```json
{
  "status": "PLAN_REVISION_REQUIRED",
  "reason": "Existing clarifications conflict with the validated plan.",
  "evidence": ["The requested behavior is outside the validated commit scope."]
}
```

An empty clarification artifact and closing the proactive editor without
changes are valid and do not consume an agent question round. The Worker still
runs and may return `READY`; only unanswered questions appended by the Worker
require user input.

Append each question round to the execution clarification artifact, open the
editor for answers, then let the Worker reread the complete transcript. Default
to at most three agent question rounds. If the editor cannot be opened, the run
is non-interactive, answers remain missing, or the round limit is reached,
persist `WAITING_FOR_USER` instead of advancing.

Before opening the editor or entering `WAITING_FOR_USER`, persist the suspended
state, pending editor action, and last accepted artifact hash. An edit made
through that authorized editor window is accepted as new clarification input
and invalidates dependent work; any edit outside an authorized window pauses
with `clarifications_changed`.

Through MCP, the root runtime never opens an editor. It projects the same
pending authorization with identified questions and accepts an empty response
for optional proactive clarification or one exact answer per Worker question
through `run_respond`. A product decision requires explicit user context; the
controlling agent asks the user when that context is absent. An external edit
followed by `run_resume` remains an equivalent path. Detached continuation does
not change this pipeline's lease, compatibility, Git, or commit gates. An MCP
dispatch that encounters another run's canonical-worktree lease leaves its
durable run and incomplete idempotency intent available for exact retry instead
of launching a conflicting child. After a mutating child is spawned, MCP does
not complete the intent until the run advances or that child owns the worktree;
a child that loses a concurrent acquisition race leaves the intent retryable.
The launcher's correlated exit acknowledgement preserves that result when the
winning lease is released between MCP polls. At MCP startup, the dispatcher
freezes one canonical detached-compatibility token over the root run-envelope
tuple and every loaded pipeline descriptor's ID and state version, sorted by
ID. The child loads its registry and independently recomputes that token before
run-lease acquisition, recovery, or migration. A mismatch takes the distinct
version-skew exit path and leaves the durable run, journal, leases, and
incomplete intent exactly unchanged for an exact-key retry after the MCP
process is restarted.
The additive MCP start fields leave `sourceSession` unset by default and pass it
only after the user deliberately selects a fork; native IDs remain opaque and
an unknown source profile offers only `current` inheritance.
`run_start.mode` has the same precedence as CLI `--mode`. MCP guidance must
recommend `independent` for genuine semantic independence, disclose its higher
context/token use, describe `lazy` as an opt-in lower-consumption choice without
independent review, and prohibit automatic lazy selection. Registry, status,
wait, and activity projections expose descriptor metadata or the resolved mode
without inactive roles or provider-private values.

When the Worker returns `READY`, persist and freeze the artifact hash. `READY`
is valid only when the clarification input is compatible with the validated
plan. Both the execution transcript and optional plan-authoring clarifications
become inputs to every later role. After this transition, normal prompts
prohibit questions.

`PLAN_REVISION_REQUIRED` enters `WAITING_FOR_USER` with
`plan_revision_required` before bootstrap. The current run remains paused until
a revised plan is validated and a new execution run starts with the transcript
carried forward; never reinterpret the stale plan.

An agent may instead return structured `PRODUCT_DECISION_REQUIRED` only when
all of these are true:

- the answer changes observable behavior, a business rule, data, security, or material scope;
- multiple incompatible choices are reasonable;
- the task, validated plan, repository, conventions, and prior clarifications do not resolve the choice;
- continuing would invent a requirement or create substantial rework risk.

```json
{
  "status": "PRODUCT_DECISION_REQUIRED",
  "question": "Which behavior should the product expose?",
  "options": ["Option A", "Option B"],
  "whyBlocked": "Both behaviors are valid but incompatible.",
  "evidence": ["The task and plan do not select either behavior."]
}
```

That outcome enters `WAITING_FOR_USER` and appends the question, options, and
evidence to the execution transcript. The user edits the transcript in the
authorized editor window. The runner persists the updated artifact hash, and
the edit invalidates all dependent context, finalization, and review. Before
re-entry, a read-only Worker compatibility check returns `READY` or
`PLAN_REVISION_REQUIRED` without asking questions. Resume at `BOOTSTRAP` if the
question arose there; otherwise resume the current step at `IMPLEMENT`, but only
when the answer leaves completed commits and the validated plan intact. If it
affects completed work, plan scope, or commit boundaries, pause with
`plan_revision_required`; do not reinterpret the plan or rewrite completed
commits. The current run remains paused: create a revised validated plan and
start a new execution run, carrying forward the recorded decision as task
context.

### Bootstrap

No implementation changes may occur before bootstrap completes.

In independent mode, run Worker bootstrap and Reviewer bootstrap independently
and in read-only mode. Clarification and bootstrap use distinct role
checkpoints. Reconciliation may continue the Worker bootstrap session, but
implementation and review never do. In lazy mode, run only Worker bootstrap,
accept its complete summary and validation inventory as resolved context after
the same deterministic validation, capacity, correction,
staging-independence, trusted-check, canonical-path, and infrastructure-
fingerprint rules, and never invoke Reviewer reconciliation or Arbiter.

Every active bootstrap role studies:

- repository structure;
- relevant source code and architecture;
- `task.md`;
- the complete `plan.md`;
- plan-authoring and execution clarifications;
- optional `context.md`;
- repository agent instructions;
- relevant repository skills;
- the persisted finalization policy, its resolved guidance when present, and
  repository instructions and project checks for fallback validation;
- relevant tests;
- relevant Git history where useful;
- project conventions related to the task.

In independent mode, the roles must not receive each other's interpretation
until both analyses finish.

Persist concise summaries:

```text
context/worker.md
context/reviewer.md  # independent mode only
```

Each summary should cover:

- task understanding;
- relevant architecture/files;
- important invariants;
- interpretation of planned commits;
- risks/ambiguities;
- finalization procedure.

Each active bootstrap role also returns an independently discovered ordered
inventory of stable `C`-prefixed check IDs and exact commands, plus every repository-relative file
that controls package scripts, test discovery, test runners, skill guidance, or
validation configuration. In independent mode, the runner establishes the
complete inventory from accepted Worker evidence followed by accepted Reviewer
evidence. In lazy mode, the complete inventory is accepted Worker evidence. It
deduplicates exact commands and paths in stable first-seen order, ignores conflicting role
IDs, and assigns the final contiguous `C1`-through-`Cn` IDs. Every command and
path found by any active role is preserved. Reconciliation and arbitration
return no inventory fields and cannot invent, select, or omit commands or repository
paths. The runner fingerprints the derived file list; an agent-supplied digest
is never trusted.
Each summary and inventory covers every substantive validation requirement but
must not require staging, staged handoff, index mutation or inspection, an
implicit worktree-versus-index assertion, an alternate index, or commit-message
drafting. Generic commit preparation belongs only to `COMMIT`; an applicable
content check uses `HEAD` or explicit trees. Deterministic validation collects
every unsafe command and every inspectable invalid validation-infrastructure
path from one candidate into a bounded, deduplicated field-diagnostic batch,
consumes the producing role's one bounded read-only correction, and fails
closed if the replacement remains invalid. Validation-migration discovery uses
the same policy, and finalization candidate inventories are rejected by their
owning batched correction policy as well.
Each role may return at most 64 `requiredChecks` and 64
`validationInfrastructure` entries. The independently derived, persisted,
finalization, and fingerprint-input inventories each allow at most 128 entries,
so two disjoint maximum role inventories remain representable. If a complete
role field would exceed 64 items, the role must return the strict
`CAPACITY_EXHAUSTED` result with empty inventory and ordinary result fields,
`capacityField` equal to `requiredChecks` or `validationInfrastructure`, and
`capacityLimit: 64`. It checks `requiredChecks` first when both fields are over
capacity. The runner pauses immediately with
`bootstrap_inventory_capacity_exhausted` and the bounded public code
`ERR_BOOTSTRAP_INVENTORY_CAPACITY_EXHAUSTED`; it does not consume a correction
turn, accept truncation, or persist a placeholder.
Exact commands and paths retain interior whitespace; validation rejects unsafe,
non-normalized, multiline, or boundary-whitespace values rather than rewriting
them.
Every inventory-producing bootstrap prompt, including validation-migration
discovery, requires unique check IDs, unique exact single-line commands already
normalized without boundary whitespace, and unique existing canonical
repository-relative validation files. A symlink or path through a symlink is an
invalid alias even when its target is confined to the repository.
Provider-facing structured-output schemas are portable approximations limited
to the common backend Structured Outputs subset and do not use regex
lookaround. They retain strict objects, bounds, safe lexical patterns, and
status-specific variants. Deterministic pipeline normalization remains
authoritative for exact nonempty text, commands, uniqueness, and safe
repository-relative paths. Each bootstrap schema keeps a strict object root
and places its discriminated variants in a nested `result` union. A rejected
bootstrap result persists and publishes only its bounded, deduplicated role,
phase, contract, field, and violated-constraint diagnostic batch; it never
retains a rejected value, command, path, or raw role output.

The producing Worker or Reviewer and each summary-producing reconciliation
Worker or Arbiter receives one read-only correction turn for an invalid
bootstrap contract. The runner first persists attempt `1` and the bounded
diagnostic batch, then reconstructs the complete request from durable state and
asks for a complete replacement result. A
provider interruption does not consume another correction or require the
native session. Each adapter maps its native structured-output failure to the
shared bounded `structured-output` failure class. The pipeline maps only that
class to the bounded `result` semantic diagnostic after the read-only mutation
guard completes; provider text is discarded. A valid replacement retires the
pending batch before any product-decision pause, while its history remains
consumed. Repeated or still-invalid output fails closed.

Before any inventory is accepted or fingerprinted, the runner asks the root
Git boundary to inspect each validation-infrastructure path. The path must
exist as a regular file and the returned canonical repository-relative path
must exactly equal the proposed value. Every inspectable missing file,
directory, symlink, and symlink-traversing path returns to the producing role in
the same bounded `existing-canonical-repository-file` diagnostic batch; these
violations do not surface later as generic unsafe-path failures and are never
followed or silently rewritten.

In independent mode, the Reviewer summary additionally states what it intends
to verify. Lazy mode creates no Reviewer summary.

### Reconciliation

The remaining reconciliation requirements apply only in independent mode. After
both summaries exist, compare material differences. Lazy mode skips
reconciliation because the accepted Worker summary is already the resolved
summary and the same logical agent cannot form an independent disagreement with
itself.

Resolve differences from task/plan/repository evidence.

Reconciliation and any arbitration resolve only the summary and a remaining
material disagreement. The runner independently derives the established
validation inventory from the two already accepted role inventories regardless
of which summary direction is selected.

Persist the agreed context:

```text
context/resolved.md
```

Do not force agreement.

If a material disagreement remains, use the Arbiter.

If arbitration determines that progress requires an unresolved material product
decision meeting the clarification criteria:

```text
WAITING_FOR_USER
reason: product_decision_required
```

---

## 13. Per-Commit Workflow

In independent mode, start one fresh Worker checkpoint and one fresh Reviewer
checkpoint for every planned commit. Reuse those role sessions for
implementation, finalization, finding resolution, complete re-review, and
dispute reconsideration within that commit. Never carry either work checkpoint
into the next commit, and keep every Arbiter turn fresh. In lazy mode, the one
logical Worker uses a durable per-commit convergence checkpoint while retaining
the single source-fork lineage across commits; a reconstructed native session
does not become a new logical role.

Reconstruct each checkpoint from the validated inputs, resolved bootstrap
summary, current plan step, active blockers, and bounded prior decisions. A
product-decision edit invalidates the affected work checkpoint before execution
resumes. Native continuation remains optional.

For each plan step:

Keep role prompts short. Their mandatory English cores are:

```text
Worker: Implement the changes described in the following planned commit. Keep the implementation idiomatic and minimal, and follow the project's conventions.
Reviewer: Review the changes and verify that they are correct, idiomatic, minimal, and consistent with the project's conventions.
Lazy check/fix: Review the changes and verify that they are correct, idiomatic, minimal, and consistent with the project's conventions. If you find any problems, fix them idiomatically and minimally, following the project's conventions.
Lazy clean confirmation: Review the changes using the same criteria without editing. Return CLEAN only when there are no problems; otherwise return concrete findings.
Finding resolution: For each finding below, fix it idiomatically and minimally, following the project's conventions.
Every role: Produce this turn's result yourself as the authorized role. Do not delegate, spawn subagents, or use multi-agent collaboration.
```

The pipeline may append turn-specific context, access restrictions, and output
requirements. The Reviewer returns structured findings rather than a free-form
handoff prompt; the pipeline attaches the canonical finding-resolution
instruction before sending those findings to the Worker.

After an authorized product-decision edit, the compatibility check uses this
minimal contract:

```text
Review the updated clarifications against the task, validated plan, completed commits, and repository.
Do not ask questions or modify the repository.
Using the provided schema, return READY when compatible; otherwise return PLAN_REVISION_REQUIRED with concise evidence.
```

After `CLARIFY` closes, every role prompt prohibits questions and permits only
the narrowly defined `PRODUCT_DECISION_REQUIRED` exception. Technical
uncertainty, naming preferences, implementation difficulty, and ordinary review
findings do not qualify.

### 13.1 Worker implementation

Start or continue the current commit's Worker checkpoint.

Before editing, the Worker refreshes:

- current commit section;
- relevant resolved context;
- relevant decisions/findings from previous work;
- current affected code.

The Worker then:

1. implements only the current planned commit;
2. performs a concise self-review;
3. returns control to the runner.

Implementation does not invoke the project finalization procedure, stage
changes, inspect a post-staging cached diff, or draft a commit message. Those
actions belong to the dedicated `FINALIZE` and `COMMIT` phases.
The established required-check inventory is input only to `FINALIZE`; it is not
included as phase-local implementation work.

If required validation cannot run because of an external environment
constraint, the Worker returns `BLOCKED` with bounded reason and evidence. The
runner preserves safe implementation content and pauses with
`environment_blocked` at the `IMPLEMENT` checkpoint.

The Worker must not create a Git commit during implementation, finalization, or
finding resolution. Commit creation is allowed only in the dedicated,
runner-authorized `COMMIT` turn after the gate passes.

### 13.2 Finalization

Run the complete project finalization procedure in a dedicated Worker turn for
every policy mode. Follow every substantive instruction in the applicable
project guidance, including required checks, project-required formatting or
generation, hygiene, and staging-independent review of the exact content.

The finalization turn should execute the validation procedure and report its
result. It should not perform unrelated discretionary fixes in the same turn.
When guidance includes generic commit preparation, defer staging,
staged/index-relative inspection, alternate-index workarounds, staged handoff,
and commit-message drafting to `COMMIT`. Every finalization inventory remains
staging-independent and expresses an applicable content check against `HEAD` or
explicit trees. This phase-owned deferral is neither a validation blocker nor a
skipped required check and must not prevent `PASS`.

Every non-availability result carries the complete inventory actually used and
exactly one ordered result for each required check. `PASS` requires every result
to be `PASS` after the runner replaces the exact selected trusted-command
placeholders described below; every other omission, `NOT_RUN`, skip, exclusion,
substitution, replacement, or weakening is invalid structured output. Evidence is bounded and direct;
external host results and user attestations do not satisfy the gate.

Every selected runner-trusted command must appear exactly once in the inventory
using its persisted exact command text. The Worker does not execute it and
returns `NOT_RUN` only for that selected entry. After the Worker turn completes
and repository changes are reconciled, the root runs the exact persisted
executable/argument vector directly without a shell and replaces the
placeholder with bounded runner evidence. It retains no process stdout or
stderr and accepts no configuration-supplied environment values. The Linux
executor requires bubblewrap. Before agent work, the root resolves it only from
fixed system locations to a canonical absolute executable whose file and
ancestor directories are not writable by the runner identity. Project-relative
or project-writable `PATH` entries never participate, and resume and execution
reverify that pinned path. Its private network namespace contains minimal
read-only system and repository mounts, private runtime and temporary storage,
a hidden ambient home, and a finite non-credential environment.
Command-owned loopback listeners remain possible inside that namespace, but raw
host Unix daemon and control sockets are masked. A Docker daemon must be
rootless, and every service must run as part of the exact command inside the
same mount, network, and PID namespaces; it cannot acquire host mounts or
networking and is retired with the complete process tree. Remote network and
filesystem writes, hosting credentials, Git credential helpers, and ambient
authentication variables remain unavailable. The runner supervises the
complete process tree with a private PID namespace and outer process group.
Every completed, readiness-confirmed command gives remaining descendants one
bounded grace period to retire naturally regardless of exit code before bounded
TERM/KILL cleanup; timeout cleanup starts immediately. A one-byte signal from
inside the completed isolation profile distinguishes setup denial from a
nonzero validation-command exit
without retaining stderr or other native output. A repository snapshot
before and after every trusted command
rejects workspace, index, history/ref, remote-configuration, or Git-identity
mutation, and the complete validation-infrastructure fingerprint is recomputed
after trusted execution. Missing isolation, an unterminated process tree,
blocked, skipped, changed, substituted, non-allowlisted, unmatched, or
fingerprint-drifting commands fail closed. Agent and runner results form one
ordered evidence tuple bound to the same content, validation-infrastructure,
ordered-command, and trusted-configuration fingerprints. The executor runs
outside agent turns and does not grant an agent loopback, Docker, database,
network, host temporary-directory, or another host-service capability.

The Worker must not change package scripts, test discovery, test runners,
validation configuration, or the inventory merely to evade an environment
blocker. A change required by the current planned commit remains possible, but
the finalization result records the candidate inventory and current
infrastructure fingerprint for the mode-specific review gate.

Before invocation, the Worker reports a missing or invalid resolved skill and
does not execute it. An explicitly configured unavailable skill pauses. An
unavailable automatically discovered skill switches to the same dedicated gate
using repository instructions and project-defined checks. A safe structured
result is one of `PASS`, `FAIL`,
`SKILL_MISSING`, `SKILL_INVALID`, `BLOCKED`, or the narrowly permitted
`PRODUCT_DECISION_REQUIRED`. `FAIL` supplies stable `F`-prefixed issue IDs for
the current procedure output. Skill-guided results identify the resolved
repository-relative skill path; skill-less `PASS`, `FAIL`, and `BLOCKED`
results carry no path. A blocked procedure or unavailable explicit skill pauses
without advancing.

`BLOCKED` is reserved for a required check that cannot execute because of an
external environment constraint and carries bounded reason and evidence. It
pauses with `environment_blocked` and resumes at `FINALIZE`; it is not
`finalization_cannot_pass` and does not become a code failure. A legitimate
check failure remains `FAIL`.

The finalization procedure may legitimately modify files when the project itself requires this, for example formatting or generated output.

Therefore:

1. run finalization;
2. let project-required modifications finish;
3. compute the content fingerprint afterward;
4. associate the finalization result with that fingerprint.

If finalization fails, enter `RESOLVE_FINDINGS` with the reported validation
failures. In lazy mode those failures must be fixed rather than disputed, and
stagnation never invokes an Arbiter.

Any later content change invalidates the previous finalization result.

If deterministic normalization rejects a Worker finalization result, collect
all independently detectable violations from that candidate where practical,
including every staging-dependent required command. Persist the version-8
bounded diagnostic batch and publish one redacted `finalization-correction`
activity without rejected content. Reconstruct the complete request from
durable inputs and ask the Worker for a complete replacement with the same
finalization schema in a fresh-session, read-only turn. The correction may
re-execute corrected staging-independent checks needed for complete direct
evidence, but it does not execute a rejected command or staging-dependent
validation and cannot modify repository content, staging, history, refs,
remotes, or Git identity.

Allow at most two such attempts for the current step and request content
fingerprint. The first diagnostic batch authorizes attempt `1`; a correction
that produces a wholly new batch may authorize attempt `2`. Any repeated
diagnostic, any batch mixing repeated and new diagnostics, or another invalid
result after attempt `2` fails closed. Resolved versus fallback guidance is
durable request-reconstruction metadata and does not create a separate budget.
A later content change starts a new fingerprint scope. Interruption before or
during an attempt preserves its pending ledger entry, reconciles it as
read-only, and resumes that same attempt without replay, recounting, or a
required native session. A valid corrected `BLOCKED` result uses
`environment_blocked`; corrected `PASS` and `FAIL` results rejoin the existing
fingerprint, trusted-validation, review, and commit paths unchanged. Rejected
values, commands, paths, provider output, and transcripts are never persisted
or published. This bounded ledger is independent of bootstrap and validation-
migration correction ledgers.

Before any finalization candidate, including `BLOCKED`, is fingerprinted,
trusted, or reviewed, inspect every validation-infrastructure entry through the
root Git boundary. Each entry must exist as a regular file and its canonical
repository-relative path must exactly equal the proposed value. Missing files,
directories, symlinks, symlink traversal, and narrative per-turn values enter
the same bounded redacted finalization-correction path; they never become a
candidate fingerprint or Reviewer finding.

### 13.3 Mode-Specific Review

#### Independent review

In independent mode, after finalization passes, use an independent Reviewer
context for the current commit.

Use one Reviewer checkpoint per planned commit, reused for complete re-review
and dispute handling within that commit.

The Reviewer receives:

- task;
- current plan step;
- resolved bootstrap context;
- relevant prior decisions;
- previous findings for this step, if any;
- current repository state/diff;
- finalization result.

It reviews:

- correctness;
- completeness;
- plan compliance;
- regression risk;
- architecture consistency;
- tests;
- edge cases;
- unintended scope expansion;
- project conventions.

It also compares the established and candidate check inventories,
infrastructure file sets, runner-computed fingerprints, and exact per-check
evidence. The fresh review request carries both complete tuples rather than
depending on earlier session context. An unchanged gate is recorded as
`UNCHANGED`. Any change must be
explicitly `ACCEPTED` as authorized by the current plan step or `REJECTED` with
a finding. The decision and its bounded evidence are bound to the same content
fingerprint as the review.

The Reviewer must not receive the Worker's private implementation reasoning.

Machine-actionable review output:

```json
{
  "status": "FINDINGS",
  "findings": [
    {
      "id": "R3",
      "file": "src/example.js",
      "problem": "Cache invalidation is missing on one path.",
      "reason": "...",
      "suggestedAction": "..."
    }
  ],
  "question": "",
  "options": [],
  "whyBlocked": "",
  "evidence": []
}
```

All findings are blocking until resolved. Severity is unnecessary for V1 workflow logic.

Finding IDs must remain stable across re-review:

- reuse an existing ID when the same finding remains;
- assign a new ID only to a genuinely new finding.

The runner must not implement fuzzy semantic matching of findings in V1.

When review finishes successfully, persist the reviewed content fingerprint.

If the final `REVIEW_SCHEMA` provider reports the shared structured-output
failure class, deterministic normalization rejects the result, or the
validation-change decision conflicts with accepted finalization evidence, map
the failure to bounded Reviewer/review field-and-constraint diagnostics. After
the first invalid result, durably record automatic attempt `1` and publish only
one redacted `review-correction` activity. Reconstruct the complete review
request from durable task, plan, context, prior-decision, finalization, and
fingerprint state, then invoke a fresh read-only Reviewer session with the
unchanged schema. Never rely on or continue the rejected native session.

Before accepting the replacement, reapply input, repository, read-only, Git-
control, content-fingerprint, validation-infrastructure-fingerprint, and
finalization-evidence guards. Preserve accepted finalization evidence while
that complete scope is unchanged. Content or control drift invalidates the
correction scope and follows the existing safe reconciliation path. A valid
replacement rejoins the ordinary approval, findings, validation-change, and
product-decision routes.

If the corrected result remains invalid, pause at `review_output_invalid` with
resume state `REVIEW`, bounded public field-and-constraint evidence, and one
explicit null retry action. That retry reconstructs and reruns the pending
fresh-session, read-only correction without incrementing attempt `1`; another
invalid result pauses again. It cannot approve work, accept findings, alter
finalization evidence, or bypass fingerprint, Git, finding-resolution, or
commit-authorization gates. Interruption or backend unavailability before or
during correction retains the pending attempt for the same reconstruction and
does not replay accepted progress or require a native session. Rejected values,
findings, commands, paths, provider output, prompts, and transcripts are never
persisted or published.

#### Lazy check/fix and clean confirmation

In lazy mode, successful finalization enters `CHECK_AND_FIX`, never `REVIEW`.
The Worker receives the whole current commit result, the established and
candidate validation tuples, exact finalization evidence, prior confirmation
findings, and the mandatory review core. This is a workspace-write turn: every
problem it identifies must be fixed immediately, idiomatically, minimally, and
within the current planned commit. Its strict result reports whether content
changed, remained unchanged, requires corrected finalization evidence, is
externally blocked, or reaches the narrowly valid product-decision outcome.
The runner compares that claim with the actual content fingerprint.

Any content change clears finalization and confirmation evidence and returns to
the complete `FINALIZE` gate before another check/fix pass. An unchanged pass is
not approval; it enters the separate read-only `CLEAN_CONFIRM` state over the
exact finalized content and validation-infrastructure fingerprints. That turn
uses the same review criteria, forbids edits, and returns only structured
`CLEAN`, concrete findings, or the narrow product-decision outcome together
with the same validation-change decision required from an independent review.
A status/content mismatch is invalid output, actual read-only mutation is
rejected, and fingerprint drift pauses without advancing.

Invalid provider or deterministic checkpoint output follows the durable lazy
correction policy above. A valid replacement rejoins the ordinary checkpoint
route and cannot itself accept finalization, confirmation, review, or commit
evidence. Content-changing invalid or interrupted check/fix work is reconciled
exactly once, retains the pending marker through full finalization, and resumes
only at the original check/fix checkpoint. Clean-confirmation correction never
receives workspace-write authority.

Concrete confirmation findings return directly to `CHECK_AND_FIX`; they are
not disputes and cannot invoke Reviewer or Arbiter. Only a mutation-free
`CLEAN` result with unchanged fingerprints and `UNCHANGED` or task-authorized
`ACCEPTED` validation change records the reviewed and clean-confirmation
fingerprints and enters `COMMIT`. The loop consumes the existing fix, stable-
finding, stagnation, and additional-fix-round budgets. Exhaustion pauses at the
applicable checkpoint and never treats a non-clean result as accepted.

### 13.4 Resolve findings

The Worker receives all currently open blockers together. Independent review
findings may be fixed or disputed. Finalization failures use this path in both
modes and must be fixed; lazy mode has no review-finding dispute or arbitration
path.

Finding resolution fixes or disputes the current blockers and then returns
control. It does not invoke project finalization or perform generic commit
preparation; a content-changing fix returns to the dedicated `FINALIZE` gate.
The established required-check inventory remains input to that gate and is not
phase-local finding-resolution work.

For each finding it returns:

```text
FIX
```

or:

```text
DISPUTE
```

If required validation is externally unavailable during the resolution turn,
the Worker may instead return `BLOCKED` with no decisions and bounded reason and
evidence. When the turn changed content, the runner preserves the partial fix,
invalidates prior finalization and review evidence, and resumes at `FINALIZE`.
When content is unchanged, it preserves the current blockers and resumes at
`RESOLVE_FINDINGS`.

#### FIX

If the Worker agrees:

1. fix all accepted findings in one fix round;
2. return control;
3. run finalization again;
4. run a complete re-review.

When one resolution batch mixes `FIX` and `DISPUTE`, preserve the disputes
through finalization, let the Reviewer reconsider them after finalization
passes, then run the complete re-review.

#### DISPUTE

A dispute must contain concise evidence.

Example:

```text
Finding: R3
Decision: DISPUTE

Reason:
updateMarketConfig() delegates to saveMarket(), which performs invalidation
after persistence succeeds.

Evidence:
- src/market/service.js:142
- src/market/repository.js:88
- existing invalidation test
```

Valid evidence includes:

- source code;
- tests;
- task/plan wording;
- project documentation;
- prior accepted decisions;
- concrete execution paths.

A bare disagreement is invalid.

The Reviewer must reconsider the dispute and return:

```text
WITHDRAW
```

or:

```text
UPHOLD
```

with a concise reason.

### 13.5 Arbiter

Lazy mode never invokes the Arbiter. In independent mode, use the Arbiter only
when:

- a material bootstrap disagreement remains; or
- a Worker/Reviewer dispute remains unresolved after the configured dispute budget.

Give the Arbiter only:

- relevant task/plan requirement;
- finding;
- Worker evidence;
- Reviewer response;
- relevant code/diff;
- relevant established decisions.

Possible outcomes:

```text
WORKER_CORRECT
REVIEWER_CORRECT
REQUIREMENT_AMBIGUOUS
```

The Arbiter never rewrites requirements.

Per-finding arbitration preserves this mandatory core:

```text
Resolve the disputed finding from the task, plan, repository, diff, and evidence, choosing the correct outcome using the provided schema.
```

Correction-loop stagnation is a separate arbitration episode for correction
churn that has not already reached the stable-finding limit. After the first
`stagnationWindowRounds` consecutive blocked correction rounds, invoke one
fresh read-only Arbiter with compact persisted history and this mandatory core:

```text
Diagnose why the implementation correction loop is not converging and choose the minimal valid next direction using the provided schema.
```

Its structured directions are `CONTINUE_FIXES`, `REWORK_IMPLEMENTATION`,
`RECONSIDER_FINDINGS`, `PLAN_REVISION_REQUIRED`, and
`PRODUCT_DECISION_REQUIRED`. The result cannot approve work, resolve a finding,
reset a budget, or satisfy the commit gate. Content changes remain Worker-only,
and finding reconsideration remains Reviewer-only. If another complete blocked
window accumulates after this arbitration, pause instead of invoking it again.

### 13.6 Commit gate

The runner may authorize the Worker commit turn only when all are true:

```text
finalization == PASS
open findings == 0
current content fingerprint == finalized fingerprint
current content fingerprint == reviewed fingerprint
review validation change == UNCHANGED or ACCEPTED
independent: unresolved disputes == 0 and pending arbitration == false
lazy: clean confirmation fingerprint == current content fingerprint
HEAD == expected HEAD
current branch/ref context == expected branch/ref context
```

### 13.7 Commit

Only the Worker creates the planned commit, and only in a dedicated one-shot
turn explicitly authorized by the runner after the commit gate passes. The
runner controls the transition and verifies the result; it does not run
`git commit` itself. The Worker's confirmation turn remains read-only. Only the
adapter's constrained local-commit executor stages content and creates the
commit.

Once the gate passes:

1. use the validated commit subject extracted from the plan heading without
   generating, rewriting, or extending it;
2. reject a message containing a `Co-authored-by` trailer, case-insensitively;
3. record the expected HEAD, branch/ref context, local refs, effective remote
   configuration and Git-identity fingerprints, and finalized/reviewed content
   fingerprint;
4. start or continue the Worker with a narrow readiness instruction, then have
   its constrained executor stage the current non-ignored workspace
   (`git add -A`), run fixed runner-owned unstaged-clean, staged-diff whitespace,
   and nonempty-diff hygiene, and create exactly one local commit using the
   exact supplied message;
5. require the Worker to use the repository's existing Git identity and prohibit
   changing `user.name`, `user.email`, author/committer metadata, commit-message
   hooks, remotes, branches, tags, or unrelated Git configuration;
6. verify the new commit is a direct, single-parent child of the expected HEAD
   on the expected branch and no other refs changed;
7. verify the committed tree exactly matches the finalized/reviewed content and
   that staging did not change its fingerprint;
8. verify the effective remote configuration and Git identity are unchanged and
   the commit's author/committer identity matches that baseline;
9. verify the final commit message exactly matches the supplied message with no
   `Co-authored-by` trailer;
10. verify no unexpected non-ignored working-tree or index changes remain;
11. persist the new SHA, mark the step completed, and continue to the next step.

The authorization permits one ordinary local commit only. It does not permit
`commit --amend`, merge commits, rebases, resets, branch switches, tag creation,
or any other history/ref mutation.

If no commit is created, pause with `commit_failed`. If the adapter also proved
`effectStarted: false`, persist its bounded rejection metadata before Git
verification and durably retire the consumed authorization only after that
verification reports no commit. A non-recoverable policy rejection remains
`commit_failed`; a recoverable provider rejection remains
`backend_unavailable`. Either resumes at `COMMIT` by preparing a fresh
authorization with a new ID. If verification is interrupted, retain both the
consumed authorization and its proof, then resume verification without invoking
the Worker again. Without the explicit marker, retain the consumed
authorization on that verification-only path. If a commit is created but
violates the authorization contract, pause with `commit_contract_violated`.
Never amend, reset, or otherwise rewrite the unexpected commit automatically.

Do not create separate "review fix" commits.

Do not perform a second full review after commit. The exact content was already finalized and reviewed.

Remote mutation is strictly forbidden in V1.

Neither the runner nor any agent may:

- run `git push`;
- run `git push --force` / `--force-with-lease`;
- create, update, delete, or otherwise mutate remote refs;
- push tags;
- create or update pull requests;
- call GitHub/GitLab/Bitbucket APIs or CLIs in a way that writes to the remote repository;
- change remote repository settings;
- add, remove, rename, or change the URL/configuration of `origin` or another
  configured remote;
- perform any other operation that modifies a Git remote.

Remote access, when available, is read-only and may be used only for inspection.
Agent adapters must block remote-write operations at the execution boundary;
prompt instructions alone are not a sufficient safety control. The runner must
also compare the effective remote-configuration fingerprint before and after
every agent turn.

Also never automatically:

- `git reset --hard`;
- discard user work;
- bypass a failing Git hook.

The workflow ends with verified local commits only. Publishing those commits is always a separate explicit user action outside the autonomous V1 workflow.

A commit hook failure or unexpected post-commit repository state must pause the run.

---

## 14. Retry Limits and No-Progress Detection

Defaults:

```text
maxFixRoundsPerStep = 5
maxDisputesPerFinding = 2
maxSameFindingRounds = 3
stagnationWindowRounds = 3
```

A fix round is one Worker fix or lazy check/fix response followed by the
required finalization and mode-specific review cycle.

Finalization failures that require code changes consume fix rounds too.

A blocked correction round is recorded after a completed fix when finalization
fails, or when finalization passes and the mode-specific review gate returns
findings to its correction state. Persist its content fingerprint and exact
finalization issue or review finding IDs. This diagnostic history is bounded and uses exact IDs;
do not add fuzzy or semantic finding matching. Track consecutive exact-ID
counts separately so the configured stable-finding limit remains enforceable
beyond the retained diagnostic-history window.

No-progress detection in V1 is intentionally simple:

- if the same stable finding ID remains open for `maxSameFindingRounds` consecutive rounds, pause;
- do not implement fuzzy/semantic similarity detection.

Independent-mode disputes do not consume fix rounds. After `maxDisputesPerFinding` upheld
disputes, invoke one read-only per-finding arbitration. An Arbiter decision in
the Reviewer's favor leaves the finding blocking and requires a fix or explicit
user override; it does not permit another dispute of the same reviewed finding.

Lazy mode never invokes Reviewer or Arbiter and therefore has no dispute
budget. Confirmation findings return to `CHECK_AND_FIX`; the existing fix,
stable-finding, and stagnation counters remain bounded, and
`--extra-fix-rounds` extends only the fix allowance without resetting history.

Reaching any limit **never** means accept-and-continue.

It always means:

```text
WAITING_FOR_USER
```

---

## 15. User Escalation

Typical reasons:

```text
clarification_answers_required
clarification_limit_reached
clarifications_changed
bootstrap_inventory_capacity_exhausted
local_artifacts_not_ignored
product_decision_required
plan_revision_required
fix_limit_reached
dispute_limit_reached
no_progress
finalization_skill_missing
finalization_skill_invalid
finalization_cannot_pass
lazy_output_invalid
review_output_invalid
read_only_agent_mutated_repository
unexpected_git_ref_change
unexpected_remote_configuration_change
unexpected_git_identity_change
unsafe_git_state
backend_unavailable
environment_blocked
arbiter_cannot_resolve
commit_failed
commit_contract_violated
```

When paused:

1. persist state;
2. append an event;
3. project and print the same bounded public pause used by MCP status and wait;
4. do not advance.

The descriptor-owned public pause contains only its finite reason, an optional
validated bounded diagnostic code, concise explanation, bounded evidence,
validated resume checkpoint, and applicable next actions. It omits prompts,
transcripts, credentials, native responses, raw standard error, rejected
structured values, internal diagnostics, and private counters. The root
separately projects a pending input request without copying it into the pause.
An input awaiting detached continuation has no second action.

Next actions preserve the existing validation contract: an identified input
uses `respond`; a safe retry carries a null resume action; an exhausted fix
budget carries one concrete valid additional round; and each currently
overridable finding receives its exact ID. `plan_revision_required` preserves
the validated rationale and evidence but offers only revision of `plan.md` and
a fresh execution run. `read_only_agent_mutated_repository` explains that the
run is contaminated and offers only a fresh run from an uncontaminated
worktree; it never accepts hybrid changes. `environment_blocked` preserves why
validation is blocked, its bounded evidence, and the exact retry checkpoint.
This read-only projection does not itself change the pipeline state version.
CLI status and MCP status, wait, and activity also expose the persisted resolved
mode, while `pipelines_list` exposes descriptor-owned values, default, and
recommendation. None exposes inactive role configuration or provider-private
data.

Example:

```text
Run paused.

Step:
Commit 3: feat(market): add cache

Reason:
Fix limit reached after 5 rounds.

Open finding:
R7 — Cache invalidation may be missing on updateMarketConfig().

Available actions:
- grant additional fix rounds;
- send/re-send to Arbiter;
- re-run review;
- explicitly override/close a finding;
- abort.
```

Support finite additional fix budget:

```bash
agent-run resume \
  --run <run-id> \
  --extra-fix-rounds 3
```

Do not reset previous counters/history.

Also support one explicit override of a currently open finding for the exact
current reviewed fingerprint:

```bash
agent-run resume \
  --run <run-id> \
  --override-finding R7
```

Both resume actions are valid only for an applicable paused run. The override
removes only the named finding, does not approve any other finding, and becomes
stale as soon as the reviewed content fingerprint changes.

Override audit entries are unique by finding ID and reviewed fingerprint. A
complete re-review deterministically suppresses only an exact applicable
override; unrelated findings remain blocking. When a rejected validation
change is represented only by overridden findings for that same fingerprint,
the override resolves that blocker without changing the persisted Reviewer
decision to `ACCEPTED`. The same applicable override is neither offered nor
stored again.

A user override must be explicitly recorded in `events.jsonl` and `progress.md`.

---

## 16. Resume

`agent-run resume --run <run-id>` must reconstruct the workflow from persisted
state.

An ownerless persisted active turn is a continuation target even though the
run is not paused. CLI resume and exact-revision MCP `run_resume` reconstruct it
with a null action; MCP rejects a non-null action, stale revision, or live
execution owner. Paused runs continue to use their descriptor-owned action
validator unchanged.

Before continuing:

1. resolve the run ID, load its state, and verify the canonical task path;
2. verify current hashes of `task.md`, `plan.md`, optional task `clarifications.md`, and `context.md`;
3. verify the execution clarification path, hash, and whether its current change was explicitly authorized;
4. verify project path;
5. verify current HEAD;
6. verify current working-tree content/state against persisted expectations.

Reject a persisted resume target unless the exact pause reason permits it and
the suspended pipeline state is valid for that target in the current preflight
phase.

If task inputs changed while paused:

```text
WAITING_FOR_USER
reason: task_input_changed
```

If repository state changed externally and deterministic reconciliation is unsafe:

```text
WAITING_FOR_USER
reason: unsafe_git_state
```

Do not assume a native agent session survived.

Native Codex/Claude resume may be used as an optimization only.

---

## 17. Terminal UX

Keep normal output concise and state-oriented:

```text
[3/7] Add market cache

Implementation    done
Finalization      pass
Review            1 finding

R7                 dispute
Reviewer           withdraw

Finalization      pass
Review            pass
Commit             2ac1d38

Proceeding to step 4.
```

Do not stream full model transcripts by default.

A debug mode may expose backend stdout/stderr.

`status` should show:

- resolved mode;
- current step/state;
- clarification status, round count, and artifact path;
- open findings;
- fix/dispute counters;
- expected/current HEAD;
- last finalized/reviewed fingerprint;
- state directory;
- bounded pause reason, explanation, evidence, retry checkpoint, and applicable
  next actions when present.

---

## 18. Testing

Use built-in `node:test`.

Do not add Jest/Vitest solely for this project.

Most tests must use fake agent adapters and temporary Git repositories. Normal tests must not consume model usage.

At minimum cover:

1. deterministic plan parsing and exact commit-subject extraction;
2. invalid/non-sequential plan numbering and invalid commit-subject rejection;
3. clean-repository preflight;
4. task directory located inside the repository without state pollution;
5. independent read-only bootstrap;
6. bootstrap mutation detection;
7. successful implementation -> finalization -> review -> commit;
8. finalization failure -> fix -> retry;
9. review finding -> fix -> re-finalize -> re-review;
10. dispute -> Reviewer withdraw;
11. dispute -> Reviewer uphold -> Arbiter;
12. fix/dispute/no-progress limits -> `WAITING_FOR_USER`;
13. additional fix budget after resume;
14. content fingerprint is independent of staging state;
15. content changes invalidate previous finalization/review;
16. read-only clarification, plan-compatibility, Reviewer, and Arbiter mutation detection;
17. unexpected Worker Git history/ref change outside the authorized `COMMIT` turn;
18. commit gate rejects unresolved findings;
19. commit staging does not invalidate the reviewed fingerprint;
20. authorized Worker turn creates exactly one direct, non-merge local commit;
21. commit messages containing `Co-authored-by` are rejected;
22. remote configuration changes by any agent are detected;
23. successful one-commit-per-plan-step progression;
24. interrupted run resumes from persisted state;
25. changed task/plan inputs are detected;
26. external repository changes while paused are detected;
27. Codex adapter command/result normalization;
28. Claude adapter command/result normalization;
29. `--clarify` opens the editor before the first Worker clarification turn;
30. `READY` closes clarification without opening the editor when `--clarify` is absent;
31. structured questions append to the transcript and remain read-only to the agent;
32. clarification round exhaustion and missing answers pause before bootstrap;
33. the frozen clarification hash is verified on agent turns and resume;
34. clarification input that conflicts with the validated plan pauses before bootstrap;
35. ordinary questions after `CLARIFY` are rejected;
36. a valid `PRODUCT_DECISION_REQUIRED` pause records the answer and invalidates dependent results;
37. a product answer that changes plan scope pauses with `plan_revision_required`;
38. the configured ignored artifact root remains outside the commit-content fingerprint;
39. preflight rejects a clarification path that the target repository does not ignore.
40. MCP input uses the same one-shot authorization and preserves exact answers;
41. MCP continuation cannot bypass the per-run lease or any local-commit gate.
42. automatic, explicit, and skill-less finalization modes preserve the
    dedicated gate, resume policy, and matching finalization/review fingerprints.
43. MCP offers fresh start and compatible current-session fork choices while
    leaving the source unset unless the user deliberately selects the fork.
44. independently identified plan-execution or polishing runs cannot own the
    same canonical Git worktree concurrently, including through detached MCP
    dispatch, and a demonstrably stale same-host owner is recoverable.
45. compatible legacy state migrates under the execution lease; the real
    canonical root-and-sorted-pipeline compatibility calculation rejects an
    old-parent/new-child descriptor skew before lease acquisition or migration;
    and a fresh MCP process can retry the unchanged durable run and incomplete
    intent with the exact idempotency key.
46. sandbox, IPC, loopback, process-isolation, missing-service, and permission
    validation blockers pause as `environment_blocked`, preserve safe content,
    and resume from the correct fingerprint-aware checkpoint.
47. pre-effect local-commit policy and provider rejections renew only after the
    adapter proof and no-commit Git verification, while executor ambiguity and
    interrupted verification never replay the consumed authorization.
48. a pre-effect rejection followed by interrupted Git verification persists
    its bounded proof, resumes verification without replay, and renews only
    after the resumed verification confirms no commit.
49. blocked provider turns publish bounded role/phase before invocation;
    owner loss, timed-out MCP wait, ordinary resume, and interrupted one-shot
    verification preserve the lease-aware activity contract.
50. invalid Worker, Reviewer, reconciliation, arbitration, and validation-
    migration bootstrap results receive one durable read-only diagnostic-batch
    correction and repeated or still-invalid output fails closed without
    persisted rejected values.
51. all inspectable missing, directory, symlink, and symlink-traversing
    validation-infrastructure paths are batched before inventory acceptance
    with every producing field identified, while canonical existing files are
    accepted.
52. Claude structured status and permission classification is finite and
    redacted; allowlisted read-only failures reconstruct from durable state,
    classified writable usage/provider failures preserve reconciled changes,
    and forbidden, authentication, ambiguous writable, and one-shot outcomes
    remain fail closed.
53. runner-only trusted command definitions, project alias selection, durable
    snapshot resume, exact-vector execution, bounded redaction, fingerprint
    drift, exact lexical round trips, and non-allowlisted substitutions fail
    closed.
54. service-backed runner checks combine with agent checks only for one exact
    fingerprint tuple, while blocked checks pause and workspace, Git, ref,
    remote, identity, ignored validation-infrastructure, leaked process-tree,
    remote-write, or ambient-credential effects are rejected.
55. conflicting role IDs, cross-role repeated commands and paths, role-only
    entries, runner-trusted commands, and attempted reconciliation inventory
    invention produce one stable complete runner-derived inventory.
56. every role prompt prohibits delegation, and a backend-reported delegated
    turn remains terminal while its finite class is redacted, durable, and
    projected consistently through CLI and MCP status.
57. 64-item role inventories, disjoint 128-item derived inventories,
    persistence, finalization round trips, infrastructure fingerprinting, and
    strict capacity exhaustion remain bounded and consistent.
58. ownerless interrupted read-only and writable turns revalidate all durable
    inputs and Git controls, preserve only authorized partial content and index
    changes, invalidate dependent evidence, replace and clear activity in
    order, and never replay a consumed commit authorization.
59. skill-guided implementation, finding-resolution, finalization, and commit
    prompts preserve phase ownership: all substantive finalization work runs,
    commit preparation is deferred without blocking validation, and only the
    constrained commit executor stages the finalized and reviewed content.
60. staging-dependent bootstrap and validation-migration inventories batch
    every independently detectable unsafe command and inspectable invalid path
    into their one field-specific correction and then fail closed;
    finalization candidate inventories obey the same deterministic policy, and
    a paused version-5 implementation run re-establishes phase-safe context
    before finalization, review, and one authorized commit.
61. finalization validation batches every independently detectable staging-
    dependent command; permits only one wholly new second diagnostic batch;
    fails closed on repetition, mixed novelty, or exhausted allowance; and
    keeps corrected BLOCKED, PASS, and FAIL outcomes on their existing routes.
62. pending first and second finalization corrections survive interruption
    without replay or recounting, prompts and public activity retain no rejected
    content, and version-7 consumed and pending state migrates losslessly to the
    version-8 ledger.
63. exact finding overrides remain unique and fingerprint-bound, suppress only
    the named same-content finding, resolve a solely represented validation
    rejection without claiming Reviewer acceptance, and become inapplicable
    after content drift.
64. finalization candidates accept only existing canonical repository-relative
    regular validation files before fingerprinting or review, and version-8
    active runs migrate through fresh independent discovery without losing
    completed commits or safe current-step content.
65. version-9 consumed and pending bootstrap diagnostics migrate losslessly to
    one-entry batches, adjacent staging-dependent commands share one correction,
    and a pending multi-diagnostic batch resumes without replay or rejected
    content retention.
66. final Reviewer provider, normalization, and validation-change consistency
    failures receive one durable fresh-session read-only correction; valid
    approval, findings, validation-change, and product-decision replacements
    rejoin their existing routes; and repeated invalid output pauses for an
    explicit retry with no rejected-content retention.
67. pending final Reviewer correction survives interruption and backend
    unavailability without recounting, rejects read-only mutation and content
    or validation-infrastructure fingerprint drift, and version-10 active and
    terminal runs migrate without reconstructing unavailable output.
68. omitted mode preserves independent role probes, source forks, bootstrap,
    review, disputes, arbitration, and completion gates.
69. lazy mode probes, resolves, forks, and invokes only Worker, including one
    source fork across multiple commits and resume, and never invokes Reviewer
    or Arbiter.
70. a content-changing check/fix pass requires full re-finalization, an
    unchanged pass requires a genuinely empty read-only clean confirmation, and
    confirmation findings return to fixing.
71. claimed-clean mutation, actual read-only mutation, content drift, and
    validation-infrastructure drift cannot advance.
72. interruption at check/fix and clean-confirm checkpoints neither replays
    workspace effects nor double-counts rounds, while provider reconstruction
    never reforks the source.
73. lazy no-progress, stable-finding, fix, and additional-round behavior remains
    bounded without weakening exact commits, trusted checks, fingerprints, Git
    controls, product decisions, or no-coauthor/no-push rules.
74. every supported legacy version migrates through state version 13 to
    `independent` without reviving terminal runs or replaying completed or
    pending commit effects.
75. lazy provider and deterministic contract failures receive one scoped
    fresh-session correction; writable mutation re-finalizes and is counted
    once, clean correction remains read-only and fingerprint-bound, pending
    work survives interruption, and repeated invalid output resumes only by an
    explicit null retry with redacted diagnostics.

Real Codex/Claude smoke tests should be opt-in integration tests.

---

## 19. Monorepo Placement

Keep execution-specific behavior inside its pipeline workspace:

```text
pipelines/plan-execution/
├── package.json
├── docs/
│   └── SPEC.md
├── src/
│   ├── index.js
│   ├── prompts.js
│   ├── schemas.js
│   ├── workflow-contract.js
│   └── workflow.js
└── test/
```

Shared plan parsing and validation belong in `packages/commit-plan/`. CLI,
clarification artifacts/editor handling, state, Git, and backend-adapter
services remain in the root runtime because both pipelines consume them there.

Split modules only when they gain a distinct responsibility or become
meaningfully large. Avoid speculative abstractions.

---

## 20. Non-Goals for V1

Do not build:

- TypeScript;
- a build step;
- a web UI;
- a network service or daemon;
- a database;
- cloud execution;
- multi-user support;
- GitHub/PR automation;
- distributed workers;
- a generic workflow engine;
- a plugin framework;
- vector memory;
- parallel reviewers;
- semantic/fuzzy finding matching;
- an open-ended agent/user dialogue after clarification closes;
- automatic pushing;
- any write operation against `origin` or another Git remote;
- PR creation/update or other remote-repository mutation.

---

## 21. Mandatory Invariants

1. In independent mode, Worker and Reviewer independently study
   project/task/plan before implementation; lazy mode uses Worker alone under
   the same deterministic bootstrap rules.
2. Clarification, plan-compatibility, bootstrap, independent review, lazy clean-
   confirmation, and arbitration turns are read-only.
3. A dedicated finalization turn always defines the project validation gate.
4. Finalization is backend-neutral and must work through either Worker adapter,
   with an explicit skill, automatic discovery, or no skill guidance.
5. Skill-less finalization derives checks from repository evidence; the runner
   never substitutes generic hard-coded test commands.
6. The Worker is autonomous during normal implementation.
7. Only the Worker creates planned commits, one at a time, in a dedicated turn
   authorized by the runner after the commit gate passes.
8. Git history/refs must not change outside that authorized `COMMIT` turn.
9. Reviewer, Arbiter, and lazy clean-confirmation turns never modify repository state.
10. In independent mode, Worker may dispute Reviewer findings with evidence.
11. Every independent Reviewer finding must be fixed, withdrawn, arbitrated, or
    explicitly overridden by the user; every lazy confirmation finding returns
    directly to fixing.
12. Any content change invalidates finalization/review for the previous content fingerprint.
13. Staging alone does not invalidate the content fingerprint.
14. Only the runner may advance to the next planned commit.
15. Retry exhaustion always pauses; it never accepts unresolved work.
16. Runner correctness does not depend on native agent-session resume.
17. Codex and Claude Code are both first-class V1 backends.
18. Independent-mode Worker, Reviewer, and Arbiter backend choices are
    independent; lazy mode resolves only Worker.
19. Workflow logic is backend-agnostic.
20. State survives process termination and never pollutes the target repository.
21. The runner and all agents are strictly local-only for writes: they must never
    push, change remote configuration, or otherwise mutate `origin` or another
    remote repository.
22. Planned commit messages never contain `Co-authored-by` trailers, and the
    Worker does not change the repository's configured Git identity.
23. `CLARIFY` completes before bootstrap or implementation and keeps its agent turn read-only.
24. Clarification questions are material, structured, bounded, and persisted in the declared artifact.
25. The clarification artifact is frozen and hashed before normal work begins.
26. Questions after clarification closes are prohibited except for a blocking `PRODUCT_DECISION_REQUIRED` outcome.
27. `CLARIFY` never closes while clarification input conflicts with the validated plan.
28. A product decision invalidates dependent work, and a plan-changing answer requires a revised validated plan.
29. The runner never creates a repository-local clarification artifact unless its resolved path is ignored.
30. External validation constraints pause as `environment_blocked`; they never
    become code failures or justify weakening the execution boundary.
31. Bootstrap role inventories use unique check IDs, unique normalized exact
    commands, and unique existing canonical repository-relative validation
    files; the runner derives the final stable union and assigns contiguous IDs,
    while invalid output receives at most one read-only diagnostic-batch
    correction per producing role, phase, and contract.
32. Claude recovery persists no denied input or native provider text, retries
    only finite allowlisted failures, and reconstructs the request from durable
    runner state without making a native session authoritative.
33. Only runner-root configuration defines trusted host commands; selected
    commands execute outside agent turns as exact persisted vectors, and their
    bounded evidence cannot pass unless every fingerprint and repository guard
    remains unchanged. The isolated executor denies remote writes and ambient
    credentials and retires the complete process tree before reconciliation.
34. Every role produces its own result without delegation; adapter collaboration
    auditing remains fail closed and a violation is never an environment pause
    or transparent retry.
35. Plan-execution implementation and finding-resolution turns do not perform
    project finalization, established checks, or generic commit preparation;
    bootstrap, migration, and finalization inventories are staging-independent,
    and the constrained `COMMIT` executor alone stages, applies fixed staged
    hygiene, and creates the exact validated subject-only commit.
36. An invalid Worker finalization result receives at most two read-only
    corrections for the current step and content-fingerprint scope, with the
    second available only for a wholly new field-diagnostic batch. Repeated,
    mixed, and exhausted invalid results fail closed; only bounded diagnostics
    are durable or public, and corrected evidence must still pass every existing
    trusted-validation, Git, and fingerprint gate.
37. User finding overrides are unique durable audit decisions and suppress only
    the exact finding on the exact reviewed content; they never record Reviewer
    acceptance or weaken another finding or validation gate.
38. Every finalization validation-infrastructure candidate is an ordered set of
    existing canonical repository-relative regular files before it can be
    fingerprinted, trusted, or reviewed.
39. Detached MCP compatibility binds the root run-envelope tuple and every
    loaded pipeline ID/state version, is frozen at server startup, and fails
    before lease acquisition, recovery, or migration without changing durable
    run or idempotency state.
40. An invalid final Reviewer contract consumes only one automatic read-only
    correction for its exact finalized scope. A still-invalid result pauses for
    explicit retry, only bounded field-and-constraint diagnostics are durable
    or public, and no correction path weakens finalization, independent review,
    findings, fingerprints, Git safety, or commit authorization.
41. `independent` is the persisted default and recommended mode; `lazy` is
    explicit, primary-only, never automatic, and never invokes Reviewer or
    Arbiter.
42. Lazy advancement requires full finalization, a writable check/fix pass, and
    a separate mutation-free `CLEAN` confirmation over unchanged content and
    validation fingerprints. Every change returns through full finalization,
    and bounded-loop exhaustion pauses.
43. Each exact lazy checkpoint scope receives one automatic fresh-session
    structured-output correction. Repeated invalid output pauses for explicit
    null retry with only redacted field-and-constraint diagnostics; mutation,
    interruption, resume, budget, fingerprint, finalization, confirmation,
    review, Git, and commit gates remain unchanged.
44. A deliberately supplied source forks independently by checkpoint in
    independent mode and exactly once into the logical Worker in lazy mode;
    native-session reconstruction never changes that lineage.

---

## 22. Acceptance Criteria

V1 is complete when:

- it runs as a plain Node.js 24 LTS ESM CLI with no unnecessary runtime dependencies;
- `run`, `resume`, and `status` work;
- Codex and Claude adapters both work;
- `independent` remains the default and recommended reviewed path, while
  explicit `lazy` completes with one logical Worker through bounded check/fix
  and clean-confirm checkpoints;
- Codex-only, Claude-only, and mixed Worker/Reviewer configurations work;
- independent-mode Worker and Reviewer bootstrap independently, while lazy
  mode bootstraps with Worker alone;
- a bounded clarification phase with read-only agent turns completes before bootstrap;
- `--clarify` and agent-generated questions use the declared Markdown artifact and configured text editor;
- execution does not start when clarification input conflicts with the validated plan;
- clarification input changes are detected and post-start questions require a blocking product decision;
- preflight refuses to create the configured artifact path when the target repository does not ignore it;
- read-only agent-turn guarantees are actively checked;
- task/plan input changes are detected;
- each plan step is implemented separately;
- project finalization is the validation gate;
- finalization follows all substantive project guidance while commit preparation
  remains owned by the constrained `COMMIT` executor;
- finalization and the mode-specific review gate are tied to the same
  staging-independent content fingerprint;
- in independent mode, Worker can fix or dispute Reviewer findings and
  unresolved disputes can be arbitrated;
- in lazy mode, confirmation findings return directly to fixing without dispute
  or arbitration;
- retry/no-progress limits pause for the user;
- only a zero-finding finalized/reviewed workspace can be committed;
- only the Worker creates one local commit per plan step, after explicit runner
  authorization and successful gate verification;
- planned commit messages contain no `Co-authored-by` trailers;
- unexpected agent Git history/ref changes are detected;
- no workflow path can push commits, change remote configuration, or mutate a
  remote repository;
- detached MCP launches reject root or loaded-pipeline version skew before
  recovery and remain exactly retryable after a fresh control-plane start;
- interruption and resume are safe;
- tests cover workflow behavior using fake agents and temporary Git repositories;
- the implementation remains a small local CLI rather than growing into a framework.

Implementation priority:

1. workflow correctness;
2. Git safety;
3. persistence/resume correctness;
4. backend isolation;
5. review/fix/dispute behavior;
6. minimal code/dependencies;
7. terminal UX.
