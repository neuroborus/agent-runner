# Commit Plan Contract

`@agent-runner/commit-plan` is the shared boundary between pipelines that write
and consume commit-by-commit plans. It owns deterministic parsing,
serialization, and validation of `plan.md`; pipeline prompts and workflow states
remain outside this package.

The initial scaffold implements the shared commit-subject validator. Plan
parsing and serialization will be added here rather than duplicated between
pipelines.

## Step Structure

A plan contains at least one step. Steps are numbered contiguously from `1` and
start with this delimiter:

```markdown
## Commit 1: feat(market): add repository
```

The general form is `## Commit N: <commit-subject>`. Everything until the next
step delimiter is that step's Markdown body. The shared parser treats the body
as opaque content; pipeline-specific semantic review remains with the owning
pipeline.

## Commit Subject

`<commit-subject>` is the exact subject used for the local commit:

```text
type(scope)[!]: imperative summary
```

Its structural pattern is:

```regex
^(feat|fix|refactor|perf|test|docs|build|ci|chore|revert)\([a-z0-9]+(?:-[a-z0-9]+)*\)!?: \S(?:.*\S)?$
```

- Allowed types: `feat`, `fix`, `refactor`, `perf`, `test`, `docs`, `build`,
  `ci`, `chore`, and `revert`.
- Scope is required, lowercase, and kebab-case.
- `!` is optional and marks a breaking change.
- The subject is one line, has no trailing period, and is at most 72 Unicode
  code points.
- The commit message has no body or footer.
- `Co-authored-by` and other authorship trailers are forbidden.

Structural validation is deterministic and must not use an LLM. Imperative
wording is checked by `plan-authoring` review because grammar cannot be validated
reliably by the shared parser.
