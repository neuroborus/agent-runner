# Polishing Pipeline — Specification

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Goal

The `polishing` pipeline takes an existing non-empty set of local repository
changes and brings it to a correct, idiomatic, minimal state that follows the
target project's conventions. It finalizes and reviews the exact result, then
stages the complete change set while leaving every change uncommitted.

The pipeline is independently owned. It reuses the root Agent Runner services
for Git inspection, clarification files, agent adapters, external state,
execution leases, public activity, CLI dispatch, and MCP control. It does not
depend on another pipeline or on `@agent-runner/commit-plan`, and it does not
introduce a workflow DSL or generic workflow engine.

The descriptor explicitly selects a Git workspace and an exclusive canonical-worktree lease.
The root resolves that selection before Git-specific inspection; a missing Git
repository never selects a directory workflow. Role access, ignored artifacts
and this pipeline's completion contract retain their existing guarantees.

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
│   ├── capability-requirements.js
│   ├── gate-evidence.js
│   ├── index.js
│   ├── mode-policy.js
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

The private `mode-policy.js` separates active roles, independent bootstrap,
primary convergence, independent review, terminal confirmer, arbitration, and
primary session scope. The workflow, persisted validator, resume-action checks,
and legacy migration use these decisions for the supported
`independent`, `lazy`, and `combined` modes.

The private `gate-evidence.js` composes primary clean evidence, independent
candidate approval, passing finalization, terminal confirmation, and handoff
readiness. Workflow routing, persisted validation, and legacy migration use the
same predicates. Candidate acceptance binds its result to the inspected
fingerprint; formatting may produce a different finalized fingerprint, which
requires its own terminal confirmation. Findings require exact fingerprint
scoped overrides where the existing independent review rules permit them.

Shared invalidation clears dependent approvals after content repairs. Unchanged
resolutions clear candidate and terminal approval but retain only fingerprint-bound
passing finalization; reuse still requires live content and infrastructure checks.
Correction budgets and durable ledgers retain their existing reset rules. Legacy
active evidence reconverges under the lease, while accepted handoff evidence is
preserved for recovery without rerunning agents or completed staging effects.
The existing evidence fields retain their persisted meaning.

Content repairs, interrupted repairs, and migration re-entry share candidate
routing: `REVIEW` for independent mode and `CHECK_AND_FIX` for lazy and combined modes.
Terminal content findings use independent finding resolution or direct primary
fixing; pure evidence rejection still repeats finalization. Policy selection
never grants permissions: agent turns remain unable to change the index, and
handoff staging remains runner-owned.

Session selection retains a single run-wide Worker source fork in lazy mode and
separate primary/review checkpoint forks in independent and combined modes. Recovery and output
correction can reconstruct fresh sessions; Arbiter contexts are always fresh.
The existing `lazyCorrections`, `pendingLazyCorrection`, and
`lazySourceForkConsumed` fields and bounded accounting remain unchanged. Large turn implementations and Git reconciliation stay in the workflow.

## Safety Guards

The repository baseline records `HEAD`, branch/detached state, local refs,
tracked and untracked content, index state, effective remote configuration, and
effective Git identity. Remote and identity values are fingerprinted without
persisting credentials or personal data.

Clarification, bootstrap, compatibility, candidate and terminal lazy clean
confirmation, candidate and terminal Reviewer, reconsideration, and Arbiter
turns are read-only. Snapshot comparison before and after every such turn must
detect tracked or untracked content changes, deletions, index changes, `HEAD`,
refs, remotes, and identity. Mutation pauses without automatic rollback.

Writable Worker turns may change safe repository content only. The runner
rejects index drift as well as any `HEAD`, branch, ref, remote-configuration,
or Git-identity change. The persisted `HANDOFF` transition is the only
polishing owner allowed to stage; its pre-add and late staged whitespace checks
never reset or restage, and a rejection is terminal. No role may push, mutate a
remote ref, use a hosting API to write, alter a remote, change Git identity,
create a commit, amend, reset,
rebase, stash, switch branches, or create tags. `HEAD` must remain unchanged for
the entire run.

The staging-independent content fingerprint includes current changed tracked
content, deletions, and non-ignored untracked content. It ignores whether
content is staged and excludes the ignored execution transcript. Every ordinary
content change invalidates candidate, finalization, and terminal-confirmation
evidence. A formatter change during `FINALIZE` preserves the accepted candidate
record but invalidates any prior terminal evidence.

## Non-Goals

Do not add a workflow framework, dynamic plugins, pipeline-to-pipeline imports,
commit-plan parsing, fuzzy finding matching, parallel reviewers, network
transport, daemon, remote mutation, automatic commits, or open-ended dialogue
after clarification closes.

### Historical validation noncompliance

Read [Historical validation noncompliance](validation-history.md#historical-validation-noncompliance).

## Required Capability Discovery

Read [Required Capability Discovery](capability-discovery.md#required-capability-discovery).

## Combined Review

Read [Combined Review](workflow.md#combined-review).

## Inputs And Change Set

Read [Inputs And Change Set](admission.md#inputs-and-change-set).

## Roles And Configuration

Read [Roles And Configuration](admission.md#roles-and-configuration).

## Clarification

Read [Clarification](bootstrap.md#clarification).

## Preflight And Bootstrap

Read [Preflight And Bootstrap](bootstrap.md#preflight-and-bootstrap).

## Workflow

Read [Workflow](workflow.md#workflow).

### Polish

Read [Polish](workflow.md#polish).

### Finalize

Read [Finalize](finalization.md#finalize).

### Transient validation storage ownership

Read [Transient validation storage ownership](finalization.md#transient-validation-storage-ownership).

### Review And Findings

Read [Review And Findings](review.md#review-and-findings).

#### Independent review and findings

Read [Independent review and findings](review.md#independent-review-and-findings).

#### Finding-resolution result recovery

Read [Finding-resolution result recovery](review.md#finding-resolution-result-recovery).

#### Lazy check/fix and clean confirmation

Read [Lazy check/fix and clean confirmation](review.md#lazy-checkfix-and-clean-confirmation).

### Handoff And Completion Gate

Read [Handoff And Completion Gate](handoff.md#handoff-and-completion-gate).

## Operator Pause And Cancellation

Read [Operator Pause And Cancellation](operator-stops.md#operator-pause-and-cancellation).

## Persistence And Resume

Read [Persistence And Resume](persistence.md#persistence-and-resume).

### Action-free ownership recovery

Read [Action-free ownership recovery](recovery.md#action-free-ownership-recovery).

## Testing

Read [Testing](testing.md#testing).

## Adapter environment recovery

Read [Adapter environment recovery](recovery.md#adapter-environment-recovery).

## Output-exhausted checkpoints

Read [Output-exhausted checkpoints](recovery.md#output-exhausted-checkpoints).

## Provider inactivity recovery

Read [Provider inactivity recovery](recovery.md#provider-inactivity-recovery).
