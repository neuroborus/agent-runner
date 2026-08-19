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
and model precedence rules. Worker and Reviewer may use any Codex/Claude
combination; Arbiter supports either backend.

The pipeline owns these positive-integer settings and defaults:

```text
maxFixRounds = 5
maxDisputesPerFinding = 2
maxSameFindingRounds = 3
stagnationWindowRounds = 3
```

Settings are stored in pipeline state at run creation and are not reloaded on
resume. The Arbiter backend is probed lazily when first needed.

## Clarification

Every run begins in a pipeline-owned `CLARIFY` state. The Worker studies the
task, current changes, task-level and execution clarifications, repository
instructions, relevant architecture, tests, skills, and Git history in
read-only mode. It returns strict structured `READY`, all currently actionable
material questions, or a narrowly valid `PRODUCT_DECISION_REQUIRED` outcome.

The run-specific transcript is:

```text
<repository>/LOCAL_ARTIFACTS/agent-runner/<run-id>/clarifications.md
```

Before creating it, preflight requires `git check-ignore` evidence that the
resolved path is ignored and untracked. The runner never changes ignore rules.
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
8. stores settings, hashes, backend versions, and the repository baseline.

Worker and Reviewer bootstrap independently and read-only. Both study the
repository, task, complete current changes, clarifications, instructions,
relevant skills including `finalization`, tests, and useful Git history. They
must not see each other's interpretation before both summaries exist. A source
session supplied with `--fork-from` is forked directly and independently for
the first Worker and Reviewer contexts; the Arbiter remains fresh.

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

The Worker receives workspace-write access and the resolved context. It brings
the whole existing change set to a correct, idiomatic, minimal result, follows
the task and project conventions, and performs a concise self-review. It may
add or remove content when correctness requires it. It must not create a commit,
change `HEAD` or refs, reconfigure remotes or Git identity, or perform a remote
write.

### Finalize

Run the target repository's `finalization` skill in a dedicated Worker turn.
Locate and validate the skill first. Execute its validation procedure,
including project-required formatting or generated output, but do not stage or
commit as a discretionary handoff action. Report strict `PASS`, `FAIL`,
`SKILL_MISSING`, `SKILL_INVALID`, `BLOCKED`, or the narrowly allowed product
decision outcome.

Finalization-generated content changes are permitted. Compute the content
fingerprint after the procedure and bind the result to it. A failure becomes
blocking findings for Worker resolution. Missing, invalid, or blocked
finalization pauses.

### Review And Findings

After finalization passes, an independent read-only Reviewer checks the task,
resolved context, entire current diff, tests, architecture, edge cases,
minimality, and conventions. Findings use stable `R`-prefixed IDs and remain
blocking.

The Worker resolves all current blockers in one batch by `FIX` or evidence-based
`DISPUTE`. Fixes rerun complete finalization and review. The Reviewer reconsiders
disputes as `WITHDRAW` or `UPHOLD`. An unresolved dispute reaches a fresh
read-only Arbiter after the configured budget. Every finding must be fixed,
withdrawn, arbitrated, or explicitly overridden by the user for the exact
reviewed fingerprint.

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
details.

Persist concise structured decisions and public summaries, never raw model
transcripts, chain-of-thought, credentials, or unhashed remote and identity
values.

Each transition is a complete write-ahead event appended and synchronized
before atomic state replacement. `progress.md` is derived public activity.
Mutating run/resume operations require one recoverable execution lease; status
reads remain lock-free. Recovery accepts only an incomplete final journal
fragment, advances lagging state from complete events, and never depends on a
native Codex or Claude session surviving interruption.

MCP uses the common STDIO tools, persists idempotency intents before mutation
and receipts before returning, and launches detached continuation under the
same lease rules. A disconnected client cannot create a second workflow owner.

On resume, verify the canonical paths, task hashes, accepted clarification hash,
repository baseline, `HEAD`, refs, remotes, identity, and current content.
Unsafe or ambiguous reconciliation pauses rather than discarding user work.

## Testing

Pipeline tests use fake adapters and temporary repositories. Cover at least:

- dirty and clean preflight;
- staged, unstaged, deleted, and non-ignored untracked change membership;
- dirty tracked, non-ignored untracked, ignored untracked, and clean tracked
  task-input paths;
- ignored clarification creation and unauthorized clarification changes;
- empty and unchanged proactive clarification behavior;
- bounded questions and answer resume;
- independent Worker/Reviewer bootstrap and source-session forks;
- reconciliation, arbitration, and product-decision pauses;
- read-only mutation plus ref, remote, and identity guards;
- durable transitions, interrupted turns, and journal recovery;
- successful polishing, finalization changes/failures, findings, fixes,
  disputes, arbitration, stagnation, budgets, overrides, and fingerprint
  invalidation;
- the invariant that `HEAD` never changes and completion never commits.

Root tests cover workspace imports and metadata, static registration,
configuration, runner behavior, CLI/MCP projections, applicable resume actions,
idempotent detached continuation, and regressions for existing pipelines.

## Non-Goals

Do not add a workflow framework, dynamic plugins, pipeline-to-pipeline imports,
commit-plan parsing, fuzzy finding matching, parallel reviewers, network
transport, daemon, remote mutation, automatic commits, or open-ended dialogue
after clarification closes.
