# Plan-Authoring Migrations

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

Plan authoring state version 2 adds the resolved mode, the fingerprint accepted
by lazy clean confirmation, and the one-time lazy source-fork marker. Its
version-1 migration selects `independent` and initializes the new checkpoint
fields without moving the workflow, replaying a role turn, rewriting a draft or
artifact, or reviving a terminal run.

Plan authoring state version 3 adds a pipeline-owned lazy-checkpoint correction
ledger and nullable pending marker scoped to `CHECK_AND_FIX` or
`CLEAN_CONFIRM` and the exact draft fingerprint. Each record retains only
attempt `1` and bounded Planner field-and-constraint diagnostics. Its ordered
version-2 migration initializes both fields empty without moving active or
terminal workflow positions, reviving terminal work, replaying an accepted
checkpoint, consuming revision or correction budgets, or writing `plan.md`.
