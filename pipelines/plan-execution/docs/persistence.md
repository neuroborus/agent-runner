# Execution Persistence

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Persistent state

Each structured role result permits exactly 2 MiB (2,097,152 bytes) of
serialized UTF-8 JSON; one-byte overflow is rejected. This is byte headroom,
not a token budget. Semantic text, item, path, inventory, dispute, and correction
bounds remain unchanged. New size diagnostics use `maximum-2-mebibytes` while
historical `maximum-256-kibibytes` records remain valid. Rejected output is never
retained. The root owns larger state/recovery containers and complete segmented
journal recovery; see [the enclosing budgets](../../../docs/ARCHITECTURE.md#structured-result-headroom).

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
├── events-000001.jsonl # present after journal rollover; retain every segment
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
- unique user finding-override audit decisions bound to exact candidate-reviewed or
  terminal-confirmed content
  fingerprints;
- fix/dispute counters;
- latest candidate-review result and finding IDs, plus candidate-reviewed,
  primary-clean-confirmed, finalized, and terminal-confirmed content
  fingerprints;
- complete per-step validation schedule, active required-check inventory,
  optional current-step amendment, legacy-scope marker, validation-infrastructure
  file list, and runner-computed infrastructure fingerprint;
- per-role durable discovery/applicability work and consumed output-subdivision allowances;
- bounded bootstrap-correction attempts containing only attempt number and
  deduplicated role, phase, contract, field, and constraint diagnostic batches;
- the current step's bounded finalization-correction ledger and optional
  pending attempt, containing only attempt number, step, bounded guidance and
  content-fingerprint scope, and bounded role, phase, contract, field, and
  constraint diagnostic batches;
- separate bounded candidate-Reviewer and terminal-confirmation correction
  records with optional pending attempts, each scoped to its exact content and
  validation-infrastructure fingerprints and containing only attempt number,
  step, and bounded role, phase, contract, field, and constraint diagnostics;
  a candidate-Reviewer record binds the Runner's live inspection of the
  established inventory, and an accepted terminal validation change neither
  invalidates nor renews it;
- the current step's lazy-checkpoint correction ledger and optional pending
  attempt, scoped to `CHECK_AND_FIX` or `CLEAN_CONFIRM`, candidate content,
  and validation-infrastructure fingerprints and containing only attempt `1`,
  whether actual fix work was already charged, and bounded Worker
  field-and-constraint diagnostics; a `CLEAN_CONFIRM` record binds the
  Runner's live inspection of the established inventory, and an accepted
  terminal validation change neither invalidates nor renews it;
- exact per-check finalization evidence and the fingerprint-bound terminal
  validation-change decision;
- the resolved runner-trusted command snapshot, command/configuration
  fingerprints, and bounded executor provenance for accepted check evidence;
- the lazy candidate- and terminal-clean-confirmation fingerprints and one-time
  source-fork marker;
- escalation reason when paused;
- an optional finite adapter diagnostic class normalized by the root boundary
  for any terminal role turn or retired pre-effect `commit_failed` pause,
  without native provider data.

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

Pipeline state version 37 lets that record carry an optional bounded adapter
`diagnosticClass` when no availability, authentication, or output-exhaustion
proof applies; the class and a proof are mutually exclusive. A retired
`commit_failed` pause resuming at `COMMIT` may carry the same class. Its
version-36 identity migration keeps records without a class valid and never
infers one; older runtimes refuse version-37 state rather than drop the class.

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
infrastructure to contain existing canonical repository-relative regular files
(extended in version 36 only for the exact selected external finalization-file
label). Its version-8 migration deduplicates legacy override audit entries,
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

Pipeline state version 14 moves semantic convergence before the terminal gate
and adds distinct candidate-review and terminal-confirmation evidence. Its
version-13 migration preserves immutable terminal runs and consumed commit
authorizations on their verification-only paths. An unfinished `IMPLEMENT`
checkpoint remains there. Every later prepared active run invalidates
unprovable legacy gate evidence and resumes at `REVIEW` in independent mode or
`CHECK_AND_FIX` in lazy mode. A paused later checkpoint retains its public pause
and records a migration marker so resume first enters the same safe
candidate-convergence path. Safe content, completed commits, counters, frozen
inputs, Git controls, and source-session lineage remain unchanged. A retained
legacy terminal-Reviewer correction on an immutable path is translated to the
new terminal-confirmation correction namespace.

Common run-envelope version 3 independently adds nullable bounded active
provider role and phase. Version-1 and version-2 envelopes project it as `null`
without rewriting; the next mutating continuation persists the explicit runtime
migration under the per-run lease.
MCP status and timed-out wait combine that field with the live execution lease:
`running` identifies a live or conservatively unverifiable execution owner,
including a detached continuation; `interrupted` identifies a persisted active
turn or execution-process record with no exclusionary owner, and `idle`
identifies neither. The bounded object separately reports `leaseOwner` as
`none`, `live`, `dead`, `replaced`, or `unverifiable`, plus `processRecord` as
`none` or `persisted`, without exposing identity. This projection uses no
polling, daemon, or heartbeat. Same-host reads check owner process liveness
immediately while exclusive acquisition and stale recovery retain their
existing age threshold.

### Event journal

Append-only machine-readable event history starts in `events.jsonl` and rolls
over into contiguous segments under the root
[journal contract](../../../docs/architecture/recovery/journal.md#write-ahead-publication-and-certified-replay).

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
advanced the state to `REVIEW` or `CHECK_AND_FIX`, resume clears the retained
`worker`/`resolve-findings` marker after those safety checks and continues from
that candidate checkpoint without replaying or recounting the correction. A consumed `COMMIT`
turn is excluded: its marker remains through verification and the Worker effect
is never replayed.

Lazy `CHECK_AND_FIX` and `CLEAN_CONFIRM` are durable checkpoints. The
turn-start transition is written before invocation, and accepted content,
findings, fingerprints, and round accounting are persisted atomically before
advancement. Resume reconstructs an unfinished turn exactly once, reconciles a
writable partial change before returning through candidate convergence, rejects mutation
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
once, invalidates the gate, and returns through the same candidate checkpoint
before the correction resumes. A pending candidate `CLEAN_CONFIRM` correction remains read-only and
requires both fingerprints to stay unchanged. Its validation-infrastructure
binding is the Runner's live inspection of the established inventory before
the rejected turn, rechecked before and after the correction; drift pauses as
`unsafe_git_state`. A still-invalid correction
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
