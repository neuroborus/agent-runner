# Polishing Pipeline — Specification

## Goal

The `polishing` pipeline takes an existing non-empty set of local repository
changes and brings it to a correct, idiomatic, minimal state that follows the
target project's conventions. It finalizes and independently reviews the exact
result, then leaves every change uncommitted.

The pipeline is independently owned. It reuses the root Agent Runner services
for Git inspection, clarification files, agent adapters, external state,
execution leases, public activity, CLI dispatch, and MCP control. It does not
depend on another pipeline or on `@agent-runner/commit-plan`, and it does not
introduce a workflow DSL or generic workflow engine.

## Technology And Ownership

Use plain JavaScript, native ES modules, Node.js `>=24 <25`, the standard
library, and `node:test`. Normal tests use fake adapters and temporary Git
repositories; live model calls remain opt-in.

Pipeline-owned files live under `pipelines/polishing/`:

```text
pipelines/polishing/
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

The workspace owns its roles, settings, input interpretation, prompts, strict
schemas, persisted-state validation, explicit JavaScript state machine, retry
policy, and completion criteria. Root modules retain their documented
ownership; pipeline registration remains static.

## Inputs And Change Set

The task directory contains:

```text
task/
├── task.md
├── clarifications.md  # optional task-level transcript
└── context.md         # optional
```

`task.md` is required and non-empty. `clarifications.md` and `context.md` are
optional immutable inputs. The pipeline does not accept or parse `plan.md`.

The initial change set is all repository content represented by:

- staged, unstaged, or deleted tracked paths relative to `HEAD`;
- non-ignored untracked paths and their content.

Staging placement does not define content membership. Ignored untracked files
are outside the change set. Preflight requires at least one change.

Task inputs may be outside the repository or may be ignored untracked files
inside it. A repository-local task input is rejected when it is a dirty tracked
path regardless of ignore rules, or a non-ignored untracked path. This prevents
immutable hashed input from overlapping the writable change set. A clean
tracked input is allowed and remains protected by input-drift checks.

## Roles And Configuration

The descriptor declares independently configurable `worker`, `reviewer`, and
on-demand `arbiter` roles. CLI and runner configuration use the common backend
and execution-preference precedence rules. Each role accepts string trusted
`profile`, backend-native `model`, and decimal `contextSize` selections;
role-specific CLI/MCP values win over run-wide and runner values, with
`current` omitting the native override. Worker and Reviewer may use any
Codex/Claude combination; Arbiter supports either backend.

The pipeline owns these positive-integer settings and defaults:

```text
maxFixRounds = 5
maxDisputesPerFinding = 2
maxSameFindingRounds = 3
stagnationWindowRounds = 3
```

It also owns `finalization`, a string setting whose default `auto` discovers a
conventional confined repository `finalization` skill and otherwise falls back
to repository instructions and project-defined checks. `none` selects that
fallback directly. Any other valid value is a normalized repository-relative
path ending in `SKILL.md` and requires that exact skill.

Settings are stored in pipeline state at run creation and are not reloaded on
resume. The root may load safe project overrides from an ignored
`LOCAL_ARTIFACTS/agent-runner.json` or an explicitly selected confined ignored
path. CLI/MCP execution selections win over project values, which win over
runner-root values. A project file may select only runner-trusted profile
aliases and safe role, setting, and repository-relative artifact-root values;
it cannot define profile implementations, credentials, binaries, or environment
values. The resolved roles, settings, and artifact root are persisted. The
Arbiter backend is probed lazily when first needed.

## Clarification

Every run begins in a pipeline-owned `CLARIFY` state. The Worker studies the
task, current changes, task-level and execution clarifications, repository
instructions, relevant architecture, tests, skills, and Git history in
read-only mode. It returns strict structured `READY`, all currently actionable
material questions, or a narrowly valid `PRODUCT_DECISION_REQUIRED` outcome.

The run-specific transcript is:

```text
<repository>/<artifactRoot>/agent-runner/<run-id>/clarifications.md
```

`artifactRoot` is a normalized repository-relative selection that defaults to
`LOCAL_ARTIFACTS`; a legacy run without that persisted field keeps the default.
Before creating the transcript, preflight requires `git check-ignore` evidence
that the resolved path is ignored and untracked. The runner never changes
ignore rules.
The transcript is excluded from the repository content fingerprint and hashed
separately as immutable workflow input.

`--clarify` opens the authorized editor before the first agent turn. Otherwise
the editor opens only when questions exist. MCP never opens an editor and uses
the common structured pending-input projection.

An empty clarification artifact is valid. Closing an authorized editor without
changes is also valid. Neither case requires user text.
They do not consume an agent question
round. Unanswered agent questions still require a response.
Question rounds are bounded to three; exhaustion pauses rather than advancing.

The runner persists the suspended workflow state, one-shot pending editor
authorization, and accepted transcript hash before opening an editor or waiting
for input. Authorized edits update the accepted hash. Edits outside that window
pause as unexpected input changes. The transcript is frozen and hashed before
leaving `CLARIFY`.

After clarification closes, agents must not ask questions. A later
`PRODUCT_DECISION_REQUIRED` is valid only when progress is impossible without
choosing between materially different product requirements that the task,
changes, repository, conventions, and prior clarifications do not resolve. The
answer invalidates dependent bootstrap, finalization, and review results and
returns through a pipeline-owned safe re-entry path.

## Preflight And Bootstrap

Preflight:

1. resolves the canonical Git root without requiring a clean worktree;
2. reads and hashes the declared task inputs;
3. rejects task-input/change-set overlap;
4. verifies the ignored run clarification path;
5. records the dirty repository snapshot and requires at least one change;
6. probes Worker and Reviewer capabilities independently;
7. creates or preserves the run clarification transcript;
8. stores the artifact root, settings, hashes, backend versions, and the repository baseline.

Worker and Reviewer bootstrap independently and read-only. Both study the
repository, task, complete current changes, clarifications, instructions,
relevant skills and finalization guidance, repository-defined project checks,
tests, and useful Git history. They
must not see each other's interpretation before both summaries exist. A source
session supplied with `--fork-from` and optional separate `--fork-profile` is
forked directly and independently for the first eligible turn of each Worker
and Reviewer checkpoint. A known source profile supplies their `current`
selection and every explicit backend/profile must match; an unknown source
profile requires `current` and omits a native override. The Arbiter remains
fresh and independent. MCP leaves the source unset unless the user deliberately
selects a compatible current session after being offered a fresh start. It
includes a known trusted profile with the fork choice, or offers only `current`
inheritance when the profile is unknown. Worker and Reviewer each fork the
complete source context, so prefer a fresh start for a long, multi-topic, or
uncertain session.

Each direct child session is persisted with a key over its accepted inputs and
pipeline-owned role checkpoint. Clarification, bootstrap, Worker work, and
Reviewer work are distinct checkpoints. Reconciliation may continue the Worker
bootstrap session, but polishing and review never continue bootstrap sessions.
First, forked, fresh, and context-invalidated turns receive the complete durable
request. Compatible continuations receive only the current instruction and
state delta while retaining the complete request for adapter recovery after
unavailable continuation or failed compaction.
An explicit Claude rate, quota, credit, or spend-limit rejection is not retried
through compaction, a fresh session, or provider fallback. Persist
`backend_unavailable`, safe Worker workspace changes, and invalidation of stale
fingerprint-bound results before pausing so the durable request can resume after
capacity returns.

A writable Worker turn that cannot execute required validation because of
sandbox, IPC, loopback, process-isolation, missing-service, permission, or a
comparable external constraint returns structured `BLOCKED` with bounded reason
and evidence. The pipeline persists `environment_blocked`, preserves safe
workspace content, and never weakens sandbox, network, process, or host
temporary-directory boundaries to make validation pass.

The pipeline stores concise summaries as external run artifacts:

```text
context/worker.md
context/reviewer.md
context/resolved.md
```

The Worker reconciles both summaries from repository evidence without forcing
agreement. A material disagreement invokes one fresh, read-only Arbiter, which
may select the Worker summary, select the Reviewer summary, synthesize an
evidence-supported result, or require a genuine product decision. Only a
resolved context permits the workflow to enter `POLISH`.

Each bootstrap role independently returns the complete ordered inventory of
stable `C`-prefixed required-check IDs and exact commands, plus every
repository-relative file that controls package scripts, test discovery, test
runners, skill guidance, or validation configuration. Reconciliation or
arbitration establishes the inventory from both reports, and the runner—not an
agent—fingerprints those files.
Commands and paths retain interior whitespace exactly; unsafe, non-normalized,
multiline, or boundary-whitespace values are rejected instead of rewritten.

## Workflow

The explicit persisted states are:

```text
CLARIFY
BOOTSTRAP
POLISH
FINALIZE
REVIEW
RESOLVE_FINDINGS
WAITING_FOR_USER
DONE
FAILED
```

Only runner-owned transition code advances the workflow. The first
implementation increment prepares a validated run through `POLISH`; subsequent
behavior follows the remaining sections of this specification.

### Polish

The Worker starts a fresh work checkpoint with the validated inputs, current
change-set fingerprint, resolved context, active blockers, and bounded decision
history. It receives workspace-write access and brings the whole existing
change set to a correct, idiomatic, minimal result, follows the task and project
conventions, and performs a concise self-review. Finalization and finding fixes
reuse this checkpoint. The Worker may add or remove content when correctness
requires it. It must not create a commit, change `HEAD` or refs, reconfigure
remotes or Git identity, or perform a remote write.

An external validation blocker pauses at `POLISH` without discarding safe
Worker changes. Any stale fingerprint-bound finalization and review results are
invalidated before the pause.

### Finalize

Run the target repository's complete finalization procedure in a dedicated
Worker turn in every policy mode. Locate and validate resolved skill guidance
first. When no skill is selected or automatic discovery finds none, derive the
same complete gate from repository instructions and project-defined checks;
never skip validation. Execute required formatting or generated output, but do
not stage or commit as a discretionary handoff action. Report strict `PASS`, `FAIL`,
`SKILL_MISSING`, `SKILL_INVALID`, `BLOCKED`, or the narrowly allowed product
decision outcome.

An explicitly selected missing, escaping, or invalid skill pauses. An
unavailable automatically discovered skill falls back to the skill-less gate.
Skill-less `PASS`, `FAIL`, and `BLOCKED` results carry no skill path.
Finalization-generated content changes are permitted. Compute the content
fingerprint after the procedure and bind the result to it. A failure becomes
blocking findings for Worker resolution. Unavailable explicit guidance or a
blocked finalization procedure pauses.

Every non-availability result repeats the complete inventory actually used and
contains exactly one ordered result with bounded direct evidence for every
required check. `PASS` requires all of them to pass; omissions, `NOT_RUN`,
skips, exclusions, substitutions, replacements, or weakening are invalid
output. Host-reported results and user attestations are not trusted. The Worker
must not weaken package scripts, test discovery, test runners, validation
configuration, the inventory, or its file set to evade an environment blocker.

`BLOCKED` is reserved for required validation that cannot execute because of an
external environment constraint. It carries bounded reason and evidence,
pauses as `environment_blocked`, and resumes at `FINALIZE`; an executable check
that reports a legitimate failure remains `FAIL`.

### Review And Findings

After finalization passes, an independent read-only Reviewer checks the task,
resolved context, entire current diff, tests, architecture, edge cases,
minimality, and conventions. Its first review starts a separate work checkpoint
seeded from the same durable evidence; re-review and dispute reconsideration
reuse it. Findings use stable `R`-prefixed IDs and remain blocking.

The Reviewer compares the established and candidate inventories,
infrastructure file sets and runner-computed fingerprints, and the exact
per-check evidence. The fresh review request includes both complete tuples and
does not depend on a prior session. It records `UNCHANGED`, explicitly
`ACCEPTED` for a complete task-authorized change, or `REJECTED` with a finding.
This decision and evidence are bound to the reviewed content fingerprint.

The Worker resolves all current blockers in one batch by `FIX` or evidence-based
`DISPUTE`. Fixes rerun complete finalization and review. The Reviewer reconsiders
disputes as `WITHDRAW` or `UPHOLD`. An unresolved dispute reaches a fresh
read-only Arbiter after the configured budget. Every finding must be fixed,
withdrawn, arbitrated, or explicitly overridden by the user for the exact
reviewed fingerprint.

If required validation is externally blocked during finding resolution, the
Worker returns `BLOCKED` with no decisions and bounded reason and evidence. A
content-changing partial fix is preserved, invalidates stale finalization and
review evidence, and resumes at `FINALIZE`; an unchanged turn retains its
blockers and resumes at `RESOLVE_FINDINGS`.

Exact finding IDs drive no-progress detection; fuzzy semantic matching is out
of scope. Exhausted fix, dispute, stable-finding, or stagnation budgets always
pause. Additional fix rounds do not reset history. One stagnation arbitration
may direct further fixes, implementation rework, or Reviewer reconsideration;
another complete blocked window pauses.

### Completion Gate

Completion requires:

```text
finalization == PASS
open findings == 0
unresolved disputes == 0
pending arbitration == false
current content fingerprint == finalized fingerprint
current content fingerprint == reviewed fingerprint
review validation change == UNCHANGED or ACCEPTED
HEAD and repository control fingerprints == recorded baseline
```

The pipeline enters `DONE` with the polished workspace still uncommitted. It
never invokes `local-commit` access and never stages or creates a commit as a
completion effect.

## Safety Guards

The repository baseline records `HEAD`, branch/detached state, local refs,
tracked and untracked content, index state, effective remote configuration, and
effective Git identity. Remote and identity values are fingerprinted without
persisting credentials or personal data.

Clarification, bootstrap, compatibility, Reviewer, reconsideration, and Arbiter
turns are read-only. Snapshot comparison before and after every such turn must
detect tracked or untracked content changes, deletions, index changes, `HEAD`,
refs, remotes, and identity. Mutation pauses without automatic rollback.

Writable Worker turns may change repository content and staging placement, but
the runner actively rejects any `HEAD`, branch, ref, remote-configuration, or
Git-identity change. No role may push, mutate a remote ref, use a hosting API to
write, alter a remote, change Git identity, create a commit, amend, reset,
rebase, stash, switch branches, or create tags. `HEAD` must remain unchanged for
the entire run.

The staging-independent content fingerprint includes current changed tracked
content, deletions, and non-ignored untracked content. It ignores whether
content is staged and excludes the ignored execution transcript. Every content
change invalidates finalization and review.

## Persistence And Resume

State lives outside both the target repository and task directory under the
common external run store. Pipeline state includes resolved settings, baseline,
input hashes, clarification status, backend versions, bootstrap summaries,
findings, disputes, arbitration, budgets, fingerprints, overrides, and pause
details. The common versioned envelope also records an explicit runtime
compatibility tuple maintained independently from the package version and, in
version 3, nullable bounded active provider role and phase. Version-1 and
version-2 envelopes project null activity without rewriting until the next
mutating continuation persists the explicit runtime migration.

Persist concise structured decisions and public summaries, never raw model
transcripts, chain-of-thought, credentials, or unhashed remote and identity
values.

The descriptor projects each pause through one bounded public contract shared
by CLI status, MCP status, and MCP wait. It contains the finite reason, optional
validated bounded diagnostic code, concise explanation, bounded evidence,
validated resume checkpoint, and only applicable next actions. Prompts,
transcripts, credentials, native responses, raw standard error, rejected
values, internal diagnostics, pause-only paths, and counters remain private;
identified questions stay in the root pending-input projection. Input response,
safe null retry, one concrete valid extra-fix round, and exact finding overrides
continue to use the existing resume validation. A read-only repository mutation
instead instructs the user to abandon the contaminated run and start fresh from
an uncontaminated worktree. `environment_blocked` retains why validation is
blocked and the precise `POLISH`, `FINALIZE`, or `RESOLVE_FINDINGS` retry
checkpoint. This read-only projection leaves pipeline state version 2 unchanged.

Each transition is a complete write-ahead event appended and synchronized
before atomic state replacement. `progress.md` is derived public activity.
Immediately before every Worker, Reviewer, or Arbiter provider call, the root
persists a complete `turn-started` transition. It clears the active turn only
after the pipeline reconciles read-only guards or safely snapshots and persists
writable workspace effects. If the process stops first, MCP status and timed-out
wait combine the retained role/phase with the absence of a live execution owner
to report `interrupted`, even before stale lease recovery; a live detached owner
reports `running`, and no owner or retained
turn reports `idle`. Same-host reads check owner process liveness immediately
without changing acquisition or stale-recovery thresholds. Resume reconstructs
the request from durable state and does not require polling, a heartbeat,
daemon, or surviving native session.
Mutating run/resume operations acquire the per-run execution lease first and an
external lease keyed by the canonical Git worktree second, then release them in
reverse order. Separate run IDs therefore cannot mutate one worktree
concurrently. Both leases use owner-checked release and permit stale recovery
only after the age threshold when the recorded same-host process is
demonstrably dead. Status reads acquire neither lease and remain lock-free.
Recovery accepts only an incomplete final journal fragment, advances lagging
state from complete events, and never depends on a native Codex or Claude
session surviving interruption.

The descriptor owns one explicit ordered migration for every supported prior
pipeline state version. Lock-free status may project a compatible migration in
memory, but only a mutating continuation may persist it. Before workflow
execution the root evaluates the complete chain, validates the current
pipeline shape, and appends one atomic migration event under the per-run lease.
Unsupported forward versions, missing migrations, and incompatible runtime
tuples return a specific actionable version-skew error; invalid migration
output returns a specific migration failure. Neither changes the durable run.

Pipeline state version 2 adds the required-check and validation-infrastructure
evidence. Its version-1 migration preserves safe workspace content, invalidates
active aggregate finalization and review evidence, and marks paused legacy
evidence provisional. Before retry, override, finalization, or review advances,
fresh independent Worker and Reviewer checkpoints re-establish the inventory
and the runner fingerprints it again. Completed active work returns through
`FINALIZE`; immutable failed history is upgraded without replaying an effect.

MCP uses the common STDIO tools, persists idempotency intents before mutation
and receipts before returning, and launches detached continuation under the
same lease rules. A worktree conflict leaves the durable run and incomplete
intent available for an exact retry instead of launching a conflicting child.
After spawn, the receipt remains incomplete until the run advances or that
child owns the worktree, so losing a concurrent acquisition race remains
retryable. A correlated child exit acknowledgement makes this deterministic
when the winning lease is released between MCP polls. A disconnected client
cannot create a second workflow owner. The dispatcher passes its runtime tuple
to the detached child, which rejects a mismatch before taking the run lease.
Its distinct skew exit becomes an actionable restart-and-retry error while the
incomplete idempotency intent and run remain durable.
Its additive start fields leave `sourceSession` unset until the user
deliberately selects a fork; native IDs remain opaque and an unknown source
profile permits only `current` inheritance.

On resume, verify the canonical paths, task hashes, accepted clarification hash,
repository baseline, `HEAD`, refs, remotes, identity, and current content.
Unsafe or ambiguous reconciliation pauses rather than discarding user work.

## Testing

Pipeline tests use fake adapters and temporary repositories. Cover at least:

- dirty and clean preflight;
- staged, unstaged, deleted, and non-ignored untracked change membership;
- dirty tracked, non-ignored untracked, ignored untracked, and clean tracked
  task-input paths;
- default, configured, and legacy artifact roots plus ignored clarification
  creation and unauthorized clarification changes;
- empty and unchanged proactive clarification behavior;
- bounded questions and answer resume;
- independent Worker/Reviewer bootstrap and deliberate MCP source-session
  forks;
- reconciliation, arbitration, and product-decision pauses;
- read-only mutation plus ref, remote, and identity guards;
- durable transitions, interrupted turns, and journal recovery;
- blocked provider activity plus lease-aware running, interrupted, and idle MCP
  projection;
- successful polishing, finalization changes/failures, findings, fixes,
  disputes, arbitration, stagnation, budgets, overrides, and fingerprint
  invalidation;
- automatic discovery, explicit skill selection, skill-less fallback, invalid
  explicit paths, resume, and matching finalization/review fingerprints;
- canonical-worktree conflicts across independently identified polishing or
  plan-execution runs, detached MCP retry, and same-host stale recovery;
- compatible legacy migration, incompatible reader and detached-child
  rejection, and disconnects that leave durable state unchanged;
- sandbox, IPC, loopback, process-isolation, missing-service, and permission
  validation blockers across polishing, finalization, and finding resolution,
  including fingerprint-aware preservation and resume;
- the invariant that `HEAD` never changes and completion never commits.

Root tests cover workspace imports and metadata, static registration,
configuration, runner behavior, CLI/MCP projections, applicable resume actions,
idempotent detached continuation, and regressions for existing pipelines.

## Non-Goals

Do not add a workflow framework, dynamic plugins, pipeline-to-pipeline imports,
commit-plan parsing, fuzzy finding matching, parallel reviewers, network
transport, daemon, remote mutation, automatic commits, or open-ended dialogue
after clarification closes.
