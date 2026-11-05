# Validation And Change Hygiene

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

Inside a pipeline, use the established required-check inventory. A command
explicitly selected for runner-trusted execution must never execute in an agent
turn: report it as `NOT_RUN` with its reserved runner identity. Only the runner
executes its persisted exact vector and records the result. Keep every required
check exactly once and in order; do not substitute, weaken, or omit checks or
accept user-attested results. An agent-sandbox limitation of a selected command
does not block agent content work. Fresh evidence after interruption or repair
may require trusted checks to rerun; do not promise exactly-once execution.

When mandatory skill references define commands or gate behavior, classify them
as validation infrastructure under the owning workflow's inventory and drift
rules. Reading a reference alone does not add unrelated documents to that inventory.

Review test necessity, coverage, determinism, and cost using the canonical
[`test-authoring` skill](../../test-authoring/SKILL.md). Follow `docs/TESTING.md`
for fast and slow gate selection. Keep live Codex/Claude calls opt-in and report
them as skipped unless the task specifically requires them.

Use the repository tests to import every root and workspace source module and to
validate every local skill's frontmatter and content without requiring local
provider interface metadata. If the current agent environment exposes an
official skill validator, run it as an additional check; do not make finalization depend on a backend-specific installation path.

## 4. Check Change Hygiene

- Inspect the diff for secrets, credentials, prompts, raw model transcripts, or local paths that do not belong in versioned content.
- Verify that tracked content is self-contained. Reject names, paths,
  identifiers, domain details, or other context from unrelated projects,
  including in examples, fixtures, deny lists, and regression tests; require
  neutral synthetic values when a contract needs representative external
  data.
- Keep complete model transcripts and chain-of-thought out of state and documentation.
- Ensure generated output, coverage, dependencies, and local settings remain ignored.
