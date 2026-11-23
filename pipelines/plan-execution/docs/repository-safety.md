# Execution Repository Safety

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Initial implementation must change step content

Read the [initial implementation contract](implementation.md#initial-implementation-must-change-step-content).

## Context cannot change plan position

Clarification, plan compatibility, each independent bootstrap, reconciliation,
bootstrap/finding/stagnation arbitration, and validation migration require
`stepAssessment` in every result. It contains `step` (positive integer),
`subject` (at most 256 characters),
`disposition` (`CURRENT`, `ALREADY_LANDED`, `SKIP_OR_REORDER`, or `LATER_STEP`),
and at most eight evidence strings of 512 characters each. The runner supplies
its selected step, exact validated subject, and verified completed subjects and
commit IDs in both continuation and reconstructed prompts. Reports cannot
change that position or grant commit authority.

A well-formed mismatching step/subject or non-`CURRENT` assessment pauses for
plan revision. Each otherwise acceptable context result also receives a separate
read-only semantic review before acceptance. That review examines the entire
proposed narrative, not just its numeric fields: assertions that the current
step landed, directions to skip/reorder it, or instructions to implement a later
step are incompatible. Quoted rejected examples, hypothetical discussion, and
ordinary whole-plan descriptions remain valid when they do not redirect work.
The semantic review uses the producing logical role and continues its checkpoint
session, including an Arbiter's existing session rather than starting another
arbitration. It cannot modify the repository or execute required checks.
Reconstructed review prompts retain the original inputs, clarification evidence,
and applicable resolved context as well as the proposed result.

Malformed assessments or semantic-review responses use the existing one-correction
ledger, extended to clarification, compatibility, and finding/stagnation arbitration.
Diagnostics stay bounded and exclude rejected narrative. The original producing checkpoint is replayed
after interruption of the `plan-context` read-only turn; its output is not yet
accepted. Recovery first verifies that no read-only mutation occurred.

State version 19 marks prior context provisional with `planContextVersion: 0`.
Before further writable work it invalidates dependent gates and active legacy
rework directions and performs read-only validation rediscovery, preserving the
existing correction ledger. Already pending migration also discards old accepted
role inventories before rediscovery.
A run that has not resolved bootstrap discards provisional role summaries and
restarts discovery. Only current context has version 1. Consumed COMMIT effects
settle verification-only before this migration; completed runs need no new work.
Neither legacy summaries, reconciliation, nor arbitration advances completed
commits. Stale context requires a revised plan and a new run.

## Stale plans and externally committed steps

Before invoking a new role, and before ordinary or interrupted repository
reconciliation can classify HEAD drift, the runner inspects HEAD through the
root Git capability. The leading step is the validated plan entry at
`completedCommits.length + 1`, independent of agent summaries. If HEAD already
has that exact subject, or HEAD moved from the saved baseline outside verified
runner commit settlement, pause as `plan_revision_required` with bounded
runner-derived evidence. Do not adopt the external commit, advance the step,
change `completedCommits`, or invoke writable work.

This guard applies before bootstrap completes. A paused run may expose
`currentStep: 1` while `resolvedSummary` and the established inventories remain
null. This is a deterministic plan position, not evidence of completed
bootstrap, and does not authorize a deferred commit stop. The persisted shape
is unchanged; state validation accepts this suspended first-step position and
still rejects unresolved bootstrap at later steps or writable checkpoints.

Consumed COMMIT authorization remains verification-only and is settled before
stale-plan inspection. Verified settlement alone records the commit and chooses
the next step; recovery retires the previous in-memory turn as well as its
durable marker. An ordinary runner-owned commit therefore does not appear as
external HEAD movement. Stop/cancel reconciliation starts no providers,
capability preparation, or stale-plan inspection. Independent branch, ref,
remote, identity, index, and workspace violations retain their Git-safety
checks and diagnostics. Plan revision requires a revised plan and a new run.

A fresh commit-plan `run` requires a clean Git working tree, including untracked non-ignored files.

Before commit-plan implementation work:

- verify the project is a Git repository;
- record the initial HEAD;
- record the current branch when available;
- record deterministic local-ref, effective remote-configuration, and effective
  Git-identity fingerprints;
- verify an existing Git identity can create local commits without changing
  repository, global, or system configuration;
- evaluate that identity in the constrained commit executor's isolated
  environment: ambient author, committer and `EMAIL` values and
  configuration-source overrides neither satisfy availability nor enter the
  baseline;
- verify the working tree is clean;
- verify the execution clarification path is ignored by the target repository;
- hash the task input files, including task-level clarifications when present;
- detect selected agent CLIs and versions.

## Git history/ref and configuration guard

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
The identity fingerprint is evaluated in the same isolated environment as the
constrained commit executor. Existing baselines or commit authorizations
captured under ambient identity or configuration-source overrides no longer
match; they pause through the identity guards and are never silently rebound.

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

## Read-only mutation guard

Worker clarification and plan-compatibility turns, every active bootstrap turn,
lazy `CLEAN_CONFIRM` and terminal `CONFIRM`, and every Reviewer and Arbiter turn
are read-only.

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

## Content Fingerprint

Candidate convergence, finalization, and terminal confirmation each require
fingerprint-bound evidence. Finalization and terminal confirmation must bind
the same post-format content that would be committed.

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
