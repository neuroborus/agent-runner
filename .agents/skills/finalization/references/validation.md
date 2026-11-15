# Validation And Change Hygiene

## 3. Format And Run Checks

Run the writable repository formatter as the first operation of the terminal
gate:

```bash
npm run format
```

Review its output as the content being finalized and subsequently confirmed.
Then run the non-mutating repository gate:

```bash
npm run check
```

Inside a pipeline, use the established required-check inventory. A command
explicitly selected for runner-trusted execution must never execute in an agent
turn: report it as `NOT_RUN` with its reserved runner identity. Only the runner
executes its persisted exact vector and records the result. Keep every required
check exactly once in the declared inventory and ordered evidence;
do not substitute, weaken, or omit checks or
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

Discover applicable supplemental checks during bootstrap, including canonical-skill
physical-line validation and an available general skill validator for skill edits.
Keep every applicable addition, including selected slow checks, in the declared
inventory before the final HEAD-relative check. Amendments may reorder the current
inventory while retaining established identities, exact commands and obligations.
Formatting remains the first operation; this content check is last in the declared
inventory and ordered evidence:

```bash
git diff --check HEAD
```

Inventory and evidence order do not define a global physical command timeline.
Inside this repository's pipelines, Worker runs the formatter first and its
agent-owned checks during `FINALIZE`, returning reserved checks as `NOT_RUN`.
Runner then executes their frozen vectors and replaces those placeholders in
inventory positions under unchanged-content and infrastructure guards. No later
Worker turn is required. `COMMIT`/`HANDOFF` keeps its separate staged hygiene.
Outside a pipeline, an operator runs the standalone procedure in the stated
sequence. Any separately explicit physical sequencing requirement remains binding;
if incompatible with existing owners/checkpoints, use the existing blocking
outcome without granting permissions or inventing a phase or product decision.

## 4. Check Change Hygiene

- Inspect the diff for secrets, credentials, prompts, raw model transcripts, or local paths that do not belong in versioned content.
- Verify that tracked content is self-contained. Reject names, paths,
  identifiers, domain details, or other context from unrelated projects,
  including in examples, fixtures, deny lists, and regression tests; require
  neutral synthetic values when a contract needs representative external
  data.
- Keep complete model transcripts and chain-of-thought out of state and documentation.
- Ensure generated output, coverage, dependencies, and local settings remain ignored.
