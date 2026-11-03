# Custom Plan Contract

`@agent-runner/custom-plan` owns deterministic parsing, validation and
serialization of criterion-driven plans. It is a pure contract for authoring
and execution, separate from the commit-specific `@agent-runner/commit-plan`.
Plan authoring consumes this contract only after explicit custom selection.
Execution consumes it after explicit custom selection to bind criterion-driven context, analysis and declared outputs through the directory lifecycle. Declarations alone grant no runtime authority; the runner separately confines and freezes permissions.

## Representation

A custom plan starts on line 1 with a fenced JSON declaration containing exactly
`kind`, `criteria`, `inputs` and `outputs`. Explicit `kind: "custom"` is required;
missing or incompatible kinds are rejected. The declaration is followed by at
least one contiguous `## Step N: title` section, numbered from `1`.

Each step has exactly three level-three sections in order: `Work`,
`Expected results`, and `Criteria`. Work and expected results contain nonempty
Markdown; criteria contain one `- <criterion-id>` reference per line. Blank
lines may surround sections. Other level-two or level-three headings are
reserved and rejected, including inside code examples. Deeper headings remain
ordinary content. Preambles, extra sections and commit delimiters are rejected.
Titles are ordinary single-line text; Conventional Commit syntax is not required.

````markdown
```json
{
  "kind": "custom",
  "criteria": [
    {
      "id": "source-coverage",
      "condition": "Identify every supplied source and label missing evidence."
    },
    {
      "id": "editable-result",
      "condition": "Deliver an editable summary with source references."
    }
  ],
  "inputs": ["sources/catalog.md"],
  "outputs": ["reports/summary.md"]
}
```

## Step 1: Analyze the supplied evidence

### Work

Read the supplied catalog and compare the source descriptions.

### Expected results

An analysis identifying the supplied sources and evidence gaps.

### Criteria

- source-coverage

## Step 2: Write the summary

### Work

Write reports/summary.md using the preceding analysis.

### Expected results

An editable summary with references and explicit evidence gaps.

### Criteria

- source-coverage
- editable-result
````

Criteria contain only `id` and `condition`. IDs are unique stable references
matching `[a-z][a-z0-9]*(?:-[a-z0-9]+)*`. Conditions express the agreed observable
completion requirements in nonempty text. Every criterion must be referenced by
at least one step; every step must reference at least one known criterion without
duplicates. Reusing a criterion across steps does not duplicate its definition.
Semantic review owns whether conditions are observable, work is feasible and
results satisfy those conditions. Structural validation cannot prove those facts.
This is the reviewed normalized representation; it does not require users to
supply original task criteria as JSON or author a workflow language.

`inputs` and `outputs` are required arrays of distinct, nonempty, trimmed
single-line strings. Inputs identify local paths or source references, including
URLs. Outputs identify intended local output paths. An analysis-only plan may
declare `outputs: []`; it still describes the required result and evidence in
its steps. The contract requires no file diff, Git repository or commit.
These declarations are data: they grant no reading, retrieval, writing, command
or Git authority. The owning runner must separately resolve, confine, authorize
and freeze actual paths and permissions before using them.

## Public API

- `parseCustomPlan(source)` returns a deeply frozen plan.
- `normalizeCustomCriteria(criteria)` validates the same closed criterion catalog
  before a draft exists and returns deeply frozen criteria with canonical line
  endings and surrounding blank lines removed, as in plan serialization.
- `validateCustomPlan(plan)` returns a frozen array of structural issues.
- `assertCustomPlan(plan)` returns the supplied plan or throws
  `CustomPlanValidationError` (`ERR_INVALID_CUSTOM_PLAN`) with frozen `issues`.
- `serializeCustomPlan(plan)` validates and emits canonical Markdown without
  changing the supplied object. It uses fixed declaration/section ordering,
  `LF` line endings, no surrounding blank lines in Markdown fields and one
  terminal newline; internal Markdown and indentation are preserved.

The object representation contains exactly `kind`, `criteria`, `inputs`,
`outputs` and `steps`. Each step contains exactly `number`, `title`, `work`,
`expectedResults` and `criterionRefs`. All fields are required; unknown fields
are rejected at each level. Numbers must be safe positive integers contiguous
from `1`. Parsing and serialization round-trip this shape with normalized line
endings and surrounding blank lines. No workflow transitions, provider behavior,
publication, validation execution or result acceptance belong to this package.
