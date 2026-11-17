---
name: delegation
description: Route repository implementation through Runner and supervise repair or skill tasks, task-scoped roles, isolated audits, and authorized delivery.
---

# Runner-Owned Delegation

Use Runner for implementation authorship by default. Before supervising work,
read [AGENTS.md](../../../AGENTS.md), the [document map](../../../docs/README.md)
and the [operator guide](../../../docs/OPERATOR_GUIDE.md). Owning pipeline
specifications retain role permissions, frozen-input, review, recovery and
effect boundaries; this skill grants no additional access or operational authority.

## Authorship and operator work

- Route source, tests, fixtures, helpers, tracked documentation, prompts and
  instruction edits through Runner. Use `plan-authoring` and `plan-execution`
  for planned implementation, or `polishing` for an existing change set.
- Already-assigned Runner agents perform only their authorized role. Operators
  own pipeline invocation and supervision; do not create nested role pairs or
  substitute provider subagents for actual Runner roles.
- Operators may prepare requirements, investigate read-only, run existing
  tools/checks within their assigned phase, supervise pipelines and perform
  already authorized operations, including commit and installation. These
  activities grant no implementation authority. Coordinators must not
  preauthor changes for rubber-stamp approval by Runner roles.
- Unavoidable authorized manual implementation edits require Runner polishing
  and independent review of the entire resulting change set. This requirement
  grants no manual-edit exception. Reuse existing user authorization for
  already authorized operations.
- Before selecting repair/skill or audit roles, read
  [role selection](references/role-selection.md). Keep Worker commands
  foreground and awaited; preserve the owning backend's foreground policy.
- Preserve user configuration, durable runs, unrelated changes, Git identity
  and remote boundaries. Never push, use hosting-service write APIs or add
  coauthor trailers. Do not edit resolved configuration during a run.

## Safe supervision

- Prioritize registered repairs. Inspect the global issue backlog at meaningful
  safe boundaries, such as before new work or after verified completion;
  never interrupt an owned effect merely to poll it.
- Deliberately register newly established unexpected Runner defects through
  supported issue tools, then queue repairs. Expected pauses, exhausted
  budgets, environment restrictions and invalid user input do not automatically
  establish engine defects; compare evidence with the owning contract.
- Respect issue-origin ownership. Backlog visibility grants no control over
  foreign workspaces, runs or configuration. Never weaken guards, alter frozen
  plans or unsafely interrupt effects to advance another task.
- Follow supported stop/resume/new-run actions and preserve stopped bindings.
  Start fresh when required. Never clean or rebind a source directory to hide
  unexpected bookkeeping, or edit durable run state.

## Audit and artifact isolation

- Use isolated audit snapshots with exact source-commit provenance and no
  mutable Git-control sharing with the repair workspace. Keep audit task,
  durable state and snapshot storage disjoint. Every audit turn, including
  corrections and finding review, remains read-only.
- Keep operator receipts, progress and traces in separate operator storage
  outside source workspaces, frozen task trees and durable run stores. Never
  add operator files to a task tree after Runner freezes it.
- Agent mappings and helper artifacts stay within existing assigned writable
  workspace authority, or return as structured output for Runner to persist.
  Task ownership grants no write access. Never alter ignore rules to make a
  path writable or hide drift.

## Acceptance and delivery

Read [completion](references/completion.md) when authoring skills, approaching
finalization, delivering a repaired build or integrating reviewed changes.
Keep implementation, review, finalization, commit and operational acceptance
distinct; a successful agent response alone is not Runner completion.
