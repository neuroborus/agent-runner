# Shared Plan Integration

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Shared Plan Contracts

`@agent-runner/commit-plan` owns the deterministic commit `plan.md`
representation and subject validation consumed by authoring and execution.
`@agent-runner/custom-plan` separately owns an explicit `custom` kind, agreed
criterion IDs/conditions, input/output declarations and contiguous titled steps
with scoped work, expected results and criterion references. It validates closed
shapes and reference coverage, parses readable Markdown with a JSON declaration
and serializes canonically; analysis-only plans may declare no file outputs.
Its [package contract](../../packages/custom-plan/README.md) owns the exact syntax.
Neither package owns prompts, roles, permissions, result acceptance or workflow
transitions. Declarations grant no filesystem, retrieval or Git authority.
Plan authoring consumes both contracts with an explicit descriptor-owned
`planKind` defaulting to `commit`. `criteriaPath`, `sourceReferences` and
`outputPaths` resolve through the same precedence and freeze in authoring state.
Dynamic workspace selection reads confined configuration through filesystem
inspection before Git preflight, then enforces Git ignored/untracked rules for
commit selection. Filesystem discovery checks configuration in the requested
directory before using the repository-root fallback for preliminary commit
selection. A local project configuration may select custom while retaining
that directory and its relative declarations; the enclosing repository supplies
only its canonical exclusion key. Commit selection canonicalizes the workspace
and retains the exact selected configuration file. The configuration boundary
resolves preliminary settings without requiring project-supplied role backends.
It validates individual values without applying relationships to an incomplete
runner/override combination; effective settings are validated after the project
overlay and overrides are merged, before binding, capture or provider work.
Artifact binding checks the final merged declarations for overlap with inputs,
sources and configuration; preliminary discovery cannot reject declarations
superseded by project overrides. Directory bindings also protect inputs,
infrastructure and controls before publication.
The descriptor's optional `resolveTaskInputs` supplies exact
additional read files; declared local sources bind content, identity and ancestors.
Custom selection uses the directory capability, exclusively read-only roles and
only task-owned artifact exclusions in long-lived baselines. Per-turn snapshots
still permit no artifact mutation. Output declarations confer no write paths and
retrieval permissions remain empty. Before creating a clarification transcript,
the runner discovers any enclosing Git worktree and requires its resolved path
to be ignored and untracked; ordinary-directory artifacts need no Git command.
The bounded clarification output adds agreed result criteria, normalized through
the shared contract before freezing. Canonical declarations and required step
scaffolding must leave 4,000 characters for step content within the unchanged
100,000-character draft budget before clarification can close. Deterministic
publication matches the complete custom header to
that frozen catalog and source/output selection. Authoring state version 7
migrates legacy runs to commit-only defaults without changing authority or
progress. Unchanged default commit inputs preserve existing session-context and
pending source-fork recovery keys. Authoring state version 8 captures custom
`repositoryBaseline` through `runtime.workspace.baseline` with exactly the
clarification and plan artifact exemptions, so preflight persists bounded
evidence for any directory size. The run contract accepts the legacy full
snapshot under its existing checks or the closed compact form; unknown, scope
and link-resolution fields fail closed. The identity version-7 migration keeps
legacy full baselines and their exact comparison, all guards use the same
`assertUnchanged`, and a version-7 runtime refuses compact baselines as skew.

Plan execution's private `step-policy.js` consumes both deterministic contracts
and isolates parsing, step/criterion context, workspace inspection, initial
content-change requirements, role access/capabilities and terminal effects from
its existing mode and review policies. `commit-workspace.js` retains two-pass
Git preflight, ignored artifacts and stale-plan inspection; the one-shot commit
route obtains Git effects only through the commit policy. Custom analysis needs
no artificial diff, uses only the already bound directory snapshot capability,
and cannot obtain commit authority. Explicit CLI/MCP/configuration selection enables custom execution through the same mode and finding loops. Execution state version 33
requires `planKind`; version-32 migration adds `commit` without changing any
gate, consumed effect, accounting or refinement eligibility. Legacy execution retains commit semantics and its existing session context.

Execution state version 34 adds nullable `customResults`; version-33 migration
sets it to `null` without inventing acceptance or output authority. Commit runs
reject non-null custom ledgers. The pipeline-owned checkpoint validates a
bounded, receipt-chained ledger over frozen criteria/inputs/permissions,
analysis/evidence and exact output fingerprints, including link resolution hops
and readable target trees. It consumes the shared mode-specific gate predicate
but never obtains Git effects or advances workflow
progress from a provider success claim. Revision-bound state transitions journal
pending acceptance before verifying and settling the same record on recovery.

The workspace capability owns exact output-directory inspection and preparation.
The runner's bound directory facade checks frozen controls and configuration,
and the existing stop monitor guards effects. The pipeline descriptor authorizes
creation only against the exact persisted root and private-state allocation
intent. Preparation pins the new directory in private durable state before
publishing it through an owned, no-clobber move. Missing roots require state
storage on the same filesystem and `/usr/bin/mv` supporting GNU coreutils 9.4's
`--no-clobber --no-copy --no-target-directory`; unsupported moves fail closed,
without copying or replacing an arriving directory. Existing roots need no move.
The directory descriptor stays open through identity verification and parent
synchronization. The execution workflow atomically saves the prepared identity
with a baseline allowing only that exact empty-root creation; intervening output
edits cannot be adopted. `custom-workspace.js` obtains both forms from one
`runtime.workspace.outputBaseline` inspection and compares only scope and
filtered-entry evidence: equal entry, remainder and output records for an
existing root, or an equal remainder and other records while the root's
missing record becomes the prepared empty directory. The artifact-sensitive
identity fingerprint is never compared, so an authorized clarification edit
cannot block preparation. No workspace siblings or parents are created, and provider
mount authority stays unchanged. The runner returns refreshed state after
process retirement so the identity transition retains revision checking.
Cancellation is checked immediately before allocation and publication. Lost
creation proof, substitutions, drift and pending
stops preserve unfinished evidence and fail closed. Earlier accepted outputs
are verified on reconstruction; invalidated acceptance requires a revised plan
and new run. The [execution specification](../../pipelines/plan-execution/docs/SPEC.md)
owns ledger bounds and the accepted-result completion contract.

Execution state version 35 adds nullable current custom-result data, a separately
pinned writable provider-policy receipt and a commit-default `planKind` setting;
migration creates neither custom authority
nor acceptance. `custom-workspace.js` adapts directory inspection without Git
effects; filesystem identity never masquerades as Git identity. Result
fingerprints include bounded analysis/evidence and workspace content. Custom
result fingerprints also bind the active authorized clarification version,
advanced only after read-only plan compatibility; earlier receipt versions and
immutable input/permission bindings remain unchanged. Custom
bootstrap supports criterion-dependent empty command schedules, retaining exact
trusted catalog provenance. Explicit guidance is optional and `auto` supplies
no automatic coding gate. All mode-required candidate gates precede finalization
and distinct terminal confirmation; only journaled `ACCEPT` settlement advances
the custom cursor. Result-only repairs clear dependent evidence. Interrupted
publication reconciles its exact receipt without replaying a model effect.
The runner supplies descriptor-selected role access. Custom startup proves
read-only access, then exact writable access is probed after journaled output
preparation and before use. Execution persists that separate receipt before the
first writable turn and reproduces it before later writes, including on resume;
policy drift fails closed without replacing the frozen startup receipt.
Missing directory roots require explicit trailing-slash declarations. Existing
file outputs grant no parent write. Legacy and commit execution retain their
Git effects, exact subjects, nonempty initial implementation and one-shot recovery.

Execution state version 42 persists new custom `repositoryBaseline` values as the
closed output-partitioned projection, adding `outputBaseline` to the custom
workspace methods. The facade fixes each run's representation from its persisted
baseline: a legacy full snapshot stays full, and null or compact selects compact.
Complete snapshots stay transient for runner output allowances, the custom-result
checkpoint, content and validation-infrastructure fingerprints, so receipts and
their formulas are unchanged. The run contract accepts the legacy full shape
under its existing checks or the closed compact shape. The identity version-41
migration rewrites no state; a version-41 runtime refuses compact baselines as
skew. A legacy baseline that would exceed the 10,000-entry state capacity raises
`ERR_CUSTOM_BASELINE_CAPACITY`, mapped to the public `plan_revision_required`
pause instead of an internal state-limit failure.
