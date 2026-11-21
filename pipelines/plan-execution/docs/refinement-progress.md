# Execution Refinement Progress

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

### Derived refinement progress

Runner publishes `plan.progress.md` beside the frozen `plan.md` after durable
state publication. The pipeline's deterministic projection retains every original
`## Commit N: <exact subject>` heading and body, adding size-decision footnotes
and original/replacement progress. Assessment measurements report changed text
lines, binary-file and gitlink counts separately, with the structured decision
and reason. Before an assessment exists, measurement and decision are unavailable.
The advisory planning target (default 900 lines) differs from the strict
execution assessment threshold (default **more than** 2,700); neither rejects
work solely for size.

Atomic decisions retain their indivisibility justification. Split progress is
proposed until mode-specific approval publishes accepted authority, accepted
while validation/separation prepares, executing after preparation, and completed
only when every mapped replacement has a verified SHA. Proposed replacements
are explicitly pending and cannot supersede accepted work. Each accepted
replacement shows its exact subject, pending/active/completed state and verified
SHA, when available. Decimal original/replacement labels appear only in the
Markdown footnotes and are display-only;
effective integer positions and exact subjects remain the execution contract.

The root Runner confines publication to that one task-relative path, under its
existing mutation ownership. An identifying comment binds the file to the run;
unowned files, another run's file, symbolic/hard links, special files and aliased
parents are rejected. Repository-local output and publication temporaries must
already be ignored and untracked; Runner never edits ignore rules. Atomic
replacement follows synced temporary writing and renewed path/identity checks.
All file operations, including cleanup after ancestor substitution, use a
validated open directory descriptor.
Concurrent activity producers publish through one per-run queue; older state
snapshots cannot replace progress from a newer observed revision. A failed
publication leaves the queue available for regeneration of that same revision.
Publication failure reports `ERR_PLAN_PROGRESS_PUBLICATION` without replacing
already published authority with a stale failure state. Resume regenerates a
missing or stale owned artifact, including after verified commit settlement.
Runner defers publication from commit consumption through verification and
durable settlement, including executor admission, so artifact failure cannot strand an
unattempted commit. Consumed commit reconciliation remains verification-only.
Pending operator stops likewise defer artifact publication until durable stop
settlement. A subsequent artifact failure is reported after settlement without
preventing safe run/worktree lease release, including release-time reconciliation.
Lock-free status reads never write the artifact. Manual Markdown edits cannot
accept a revision, complete a step or authorize/replay an effect. Keep the
ownership comment to allow automatic regeneration; an ownership conflict must be
resolved externally.

CLI status and live activity expose the same `refinementProgress` projection as
MCP status/wait and activity: artifact path, accepted effective revision, advisory
target, threshold, each original step's decision/measurement/reason, and mapped
replacement states/subjects/SHAs. MCP activity's progress describes its current
snapshot, identified by `refinementProgressRevision`, separately from historical
event pagination. These projections consume durable state without reading the
Markdown. Safety activity published before legacy size settings migrate carries
no refinement progress until the existing migration supplies those settings.
No new persisted authority, state migration or provider checkpoint is needed.
