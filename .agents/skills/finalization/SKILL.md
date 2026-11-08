---
name: finalization
description: Post-change validation, staging, and handoff gate for Agent Runner. Use after implementing, fixing, refactoring, testing, documenting, or restructuring this repository, and before asking for review, drafting a commit, or declaring work complete.
---

# Finalization — Agent Runner

Validate the exact current workspace. Fix failures that belong to the current
change set, then rerun the affected checks. Preserve unrelated user work and
report only failures that cannot be resolved safely within the current scope.

Follow sections 1–7 in order. Before performing the terminal gate, read the
three linked procedures in full; they contain the mandatory checklists and
commands. This entry point does not replace them or grant additional authority.

## 1. Review Scope

Read [scope review](references/scope-and-safety.md#1-review-scope).

### Check operator-facing consistency

Apply the complete [operator-surface checklist](references/scope-and-safety.md#check-operator-facing-consistency)
as part of scope review.

## 2. Review Safety Boundaries

Apply [all safety checks](references/scope-and-safety.md#2-review-safety-boundaries)
before validating or handing off the change.

## 3. Format And Run Checks

Follow the [formatting and validation procedure](references/validation.md#3-format-and-run-checks),
including phase-owned trusted execution and the complete established inventory.

## 4. Check Change Hygiene

Apply the [change-hygiene checklist](references/validation.md#4-check-change-hygiene)
to the complete resulting change set.

## 5. Staging And Commit Boundary

Read the [phase-owned staging and commit boundary](references/handoff.md#5-staging-and-commit-boundary)
and defer actions that belong to `COMMIT` or `HANDOFF`. Finalization never creates a commit.

## 6. Commit Message Draft

Follow the [commit-message rules](references/handoff.md#6-commit-message-draft)
only at the authorized handoff boundary.

## 7. Report Result

Report the [required outcome and evidence](references/handoff.md#7-report-result)
with the exact current staging and commit status.
