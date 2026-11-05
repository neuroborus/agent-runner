# Staging, Commit Message, And Result Handoff

## 5. Staging And Commit Boundary

**Finalization never creates a Git commit.**

Inside an Agent Runner pipeline finalization turn, keep this gate
staging-independent. Follow every substantive validation, formatting,
generation, and content-review instruction, but defer staging, unstaging,
index-relative handoff inspection, and commit-message drafting to the owning
runner phase. Plan execution assigns that work to `COMMIT`; polishing assigns
it to its runner-owned `HANDOFF`. This phase-owned deferral is not a skipped
check or a validation blocker.

Return only staging-independent required checks to the pipeline. Translate an
applicable staged or worktree-versus-index check into an equivalent `HEAD`-relative
or explicit-tree content check; leave staging completeness and staged-diff
hygiene to the owning runner phase. Never retain a deferred index check as a
required check that would make the content gate impossible to pass.

Outside an Agent Runner pipeline, when the user asks to finalize, finish the
checks, then stage only the files that belong to the current change set. Stop
there.

After staging, verify the exact staged change:

```bash
git diff --cached --check
git status --short
```

- Do not run `git commit`, `git commit --amend`, or an equivalent command.
- Do not treat finalization, handoff, or staging as permission to commit.
- Create a commit only when the user explicitly asks for one.
- Preserve unrelated user work and never stage it with the current change.

## 6. Commit Message Draft

Draft a Conventional Commit message for the staged set:

```text
type(scope)[!]: imperative summary
```

- Use one subject line only; do not add a body or footer.
- Use `feat`, `fix`, `refactor`, `perf`, `test`, `docs`, `build`, `ci`, `chore`,
  or `revert` as the lowercase type, plus a short, required kebab-case scope.
- Use `!` only for a breaking change.
- Keep the subject imperative, focused, without a trailing period, and at most 72 Unicode code points.
- Match recent repository history and reuse established scopes when available.
- Never add a `Co-authored-by` or another authorship trailer.

## 7. Report Result

Conclude with `Result: PASS` or `Result: FAIL`, then report:

1. Commands run and their outcomes.
2. Relevant checklist sections completed or skipped with a reason.
3. Important files changed.
4. Remaining risks, failures, or intentionally deferred work.
5. Current staged, unstaged, and untracked status.
6. The draft commit message for the staged set.

Remind the user that the changes are staged only and that no commit was created.
