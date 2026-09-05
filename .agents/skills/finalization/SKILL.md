---
name: finalization
description: Post-change validation, staging, and handoff gate for Agent Runner. Use after implementing, fixing, refactoring, testing, documenting, or restructuring this repository, and before asking for review, drafting a commit, or declaring work complete.
---

# Finalization — Agent Runner

Validate the exact current workspace. Fix failures that belong to the current
change set, then rerun the affected checks. Preserve unrelated user work and
report only failures that cannot be resolved safely within the current scope.

## 1. Review Scope

- Use the change gate in `docs/README.md` to identify every owning document
  affected by the change.
- Compare the change with the intended architecture and repository-wide rules
  in `docs/CONVENTIONS.md`, the detailed runtime contract in
  `docs/ARCHITECTURE.md`, the affected pipeline specifications, the shared plan
  contract, and the current request.
- Keep the monorepo within its stated non-goals and avoid speculative abstractions.
- Preserve unrelated user work and call out any overlap or uncertainty.
- Verify that README, `AGENTS.md`, and project skills still match actual behavior.
- Keep every tracked `docs/product/*.md` document represented exactly once in
  `docs/README.md`, with a concise description of what it owns and when to read
  it. Update the owning product document when its behavior changes, without
  duplicating detailed pipeline or runtime contracts.
- Add a newest-first `RHYTHM.md` entry when the change creates or revises a
  durable product, convention, safety, provider, workflow-ownership, or
  architectural decision. Mechanical moves and corrections need no entry.
- Verify that the complete `docs/README.md` map and its links still match the
  repository.
- Verify that workspace dependencies point from the root runtime to pipelines and
  from pipelines to shared packages, never between pipelines.

## 2. Review Safety Boundaries

- Verify that `plan-authoring` keeps project content read-only except for the
  resolved clarification and plan artifact paths, even when the task directory
  is inside the target repository, and never commits.
- Verify that every pipeline freezes its clarification artifact before work and
  asks later questions only through a blocking `PRODUCT_DECISION_REQUIRED` pause.
- Verify that any clarification or product decision conflicting with the
  validated plan requires a revised plan and new execution run without history
  rewriting.
- Verify that repository-local clarification artifacts are created only under a
  resolved path already ignored by the target repository.
- Verify that read-only turns cannot mutate tracked files, untracked files, the index, HEAD, or refs.
- Verify that only a runner-authorized `plan-execution` Worker turn can create one planned local commit and that no other turn can change history or refs.
- Verify that no path can push, change `origin` or another remote's configuration, or otherwise mutate a remote.
- Verify that planned commit messages contain no `Co-authored-by` trailer and use the existing Git identity.
- Verify that state remains outside the task and target repositories and is written atomically.
- Verify that content fingerprints include changed tracked content, deletions, and non-ignored untracked content while ignoring staging placement.
- Verify that ordinary content changes invalidate candidate, finalization, and
  terminal-confirmation evidence, while terminal formatting is covered by the
  final confirmation over its resulting fingerprint.
- Verify that unresolved findings, disputes, exhausted budgets, or unsafe Git state pause instead of advancing.

## 3. Format And Run Checks

Run the writable repository formatter as the first operation of the terminal
gate:

```bash
npm run format
```

Review its output as the content being finalized and subsequently confirmed.
Then run the non-mutating repository gate and staging-independent Git
whitespace check:

```bash
npm run check
git diff --check HEAD
```

Add or update tests in the same change when behavior changes. Prefer fake adapters
and temporary Git repositories. Keep live Codex/Claude calls opt-in and report
them as skipped unless the task specifically requires them.

Use the repository tests to import every root and workspace source module and to
validate every local skill's frontmatter and interface metadata. If the current
agent environment exposes an official skill validator, run it as an additional
check; do not make finalization depend on a backend-specific installation path.

## 4. Check Change Hygiene

- Inspect the diff for secrets, credentials, prompts, raw model transcripts, or local paths that do not belong in versioned content.
- Keep complete model transcripts and chain-of-thought out of state and documentation.
- Ensure generated output, coverage, dependencies, and local settings remain ignored.

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

When the user asks to finalize, finish the checks, then stage only the files that
belong to the current change set. Stop there.

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
