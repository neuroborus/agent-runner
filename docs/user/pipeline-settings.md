# Pipeline settings

Read this topic when selecting modes, correction limits, commit-size settings or
finalization guidance. [Configuration](configuration.md) owns file placement and
precedence; [trusted validation](trusted-validation.md) owns command declarations
and execution capabilities. Use the [user documentation map](README.md) for other topics.

## Defaults

| Pipeline         | Setting                          |       Default |
| ---------------- | -------------------------------- | ------------: |
| `plan-authoring` | `planKind`                       |      `commit` |
| `plan-authoring` | `criteriaPath`                   |        `null` |
| `plan-authoring` | `sourceReferences`               |          `[]` |
| `plan-authoring` | `outputPaths`                    |          `[]` |
| `plan-authoring` | `mode`                           | `independent` |
| `plan-authoring` | `maxRevisionRounds`              |            20 |
| `plan-authoring` | `preferredCommitLineLimit`       |           900 |
| `plan-authoring` | `stagnationWindowRounds`         |             3 |
| `plan-execution` | `planKind`                       |      `commit` |
| `plan-execution` | `mode`                           | `independent` |
| `plan-execution` | `automaticCommitSplitting`       |        `true` |
| `plan-execution` | `preferredCommitLineLimit`       |           900 |
| `plan-execution` | `commitSizeAssessmentMultiplier` |             3 |
| `plan-execution` | `maxFixRoundsPerStep`            |            20 |
| `plan-execution` | `finalization`                   |        `auto` |
| `plan-execution` | `maxDisputesPerFinding`          |             5 |
| `plan-execution` | `maxSameFindingRounds`           |             5 |
| `plan-execution` | `stagnationWindowRounds`         |             3 |
| `plan-execution` | `trustedChecks`                  |          `[]` |
| `polishing`      | `mode`                           | `independent` |
| `polishing`      | `maxFixRounds`                   |            20 |
| `polishing`      | `finalization`                   |        `auto` |
| `polishing`      | `maxDisputesPerFinding`          |             5 |
| `polishing`      | `maxSameFindingRounds`           |             5 |
| `polishing`      | `stagnationWindowRounds`         |             3 |
| `init`           | `mode`                           | `independent` |
| `init`           | `placement`                      |        `null` |
| `init`           | `maxRevisionRounds`              |          `20` |
| `audit`          | `mode`                           | `independent` |
| `audit`          | `sourceScope`                    |   `directory` |
| `audit`          | `excludePaths`                   |          `[]` |
| `audit`          | `maxDiscoveryPasses`             |          `20` |
| `audit`          | `maxFindingRecheckPasses`        |          `20` |
| `polishing`      | `trustedChecks`                  |          `[]` |

## Modes

`mode` accepts `independent`, `lazy`, and `combined` in every pipeline. A missing value
resolves to `independent`. The tracked [example](configuration.example.json) selects
`independent` explicitly for every pipeline. Runner and ignored project
configuration may select a descriptor-supported value, and `--mode` or MCP
`run_start.mode` has highest precedence. Configuration remains strictly validated for every
declared role, but a lazy run resolves, probes, persists, and invokes only its
Planner, Worker or Auditor. Inactive review-role configuration stays available in the
configuration files for a later independent run without being resolved or
exposed by the lazy run.

## Combined mode

Combined authoring adds Planner check/fix and a separate clean confirmation
before the complete independent Reviewer gate. Reviewer revisions restart
primary convergence; self findings return directly to fixing. Only independent
finding resolution can use a fresh Arbiter. All agent turns remain read-only;
the runner writes the validated plan. For example:

Combined execution runs Worker check/fix and a separate read-only clean
confirmation before the complete independent candidate Reviewer gate. Both
candidate approvals bind the same content fingerprint. Finalization may format
that content; a distinct Reviewer terminal confirmation approves its resulting
fingerprint and validation evidence before one-shot commit authorization.
Content repairs restart primary convergence. Self-findings go directly to fixing;
independent findings retain disputes, withdrawals, exact recorded overrides, and
fresh on-demand arbitration. Unresolved bootstrap disagreements and primary
exhaustion pause without arbitration. Corrections remain bounded and interrupted
work is charged once; resume preserves the saved mode and consumed commits remain
verification-only.

Combined polishing uses independent bootstrap, Worker check/fix and read-only
clean confirmation, independent candidate review, finalization, and a distinct
Reviewer terminal confirmation. Content repairs restart primary convergence;
unchanged resolutions reuse only fingerprint-current finalization. Self-findings
return directly to fixing; only independent finding resolution may invoke Arbiter.
Unresolved bootstrap and exhausted primary budgets pause. Handoff remains
runner-owned staging without a commit, and resume preserves accepted evidence
and correction accounting.

```bash
agent-run run plan-authoring --project /path/to/repository --task /path/to/task --mode combined
agent-run run plan-execution --project /path/to/repository --task /path/to/task --mode combined
agent-run run polishing --project /path/to/repository --task /path/to/task --mode combined
```

The equivalent MCP `run_start` request uses the selected `pipelineId`
(`plan-authoring`, `plan-execution`, or `polishing`) and `"mode": "combined"`. Saved mode and bounded correction progress survive
resume; changing configuration does not switch an existing run.

## Commit size and progress

`preferredCommitLineLimit` is a positive-integer planning target for anticipated
additions plus deletions per commit, including tests and documentation. Set it
under `pipelines.plan-authoring` in runner configuration or the safe project
overlay; project values take precedence. Planner and Plan Reviewer prefer
cohesive commits within the target, with smaller commits welcome. A larger
indivisible change remains valid when the plan explains why it cannot be split
safely. This heuristic changes neither the plan format nor execution validation.
The resolved value is persisted and reused on resume; legacy runs receive 900.
`agent-run pipelines` lists descriptor-owned setting defaults, and MCP
`pipelines_list` exposes the same defaults.

Execution separately owns `preferredCommitLineLimit: 900` and
`commitSizeAssessmentMultiplier: 3` under `pipelines.plan-execution`, with the
same project precedence and persisted resolution. Both are positive safe
integers, and their product must be a safe integer. New commit-plan runs assess reconciled work strictly above the threshold
(2,701, not 2,700, at the defaults). An atomic exception remains valid; a split
requires mode-specific plan approval and complete replacement validation. The
runner preserves all unfinished bytes externally before restoring the accepted
baseline. Worker reconstructs only the active replacement; every replacement
passes its own complete gates and exact-subject commit. Frozen plans stay
unchanged, and legacy/intermediate runs remain ineligible on resume. See the
assessment contract (`pipelines/plan-execution/docs/SPEC.md#commit-size-assessment-foundation`).

`automaticCommitSplitting` is a strict boolean under `pipelines.plan-execution`
and defaults to `true`, which keeps the assessment above. Root configuration and
the safe project overlay resolve it with the same precedence; there is no CLI or
MCP run override. With `false`, a new commit-plan run never measures size,
requests an assessment or proposes replacements; it executes the predefined
plan unchanged through every ordinary validation, review, finalization,
terminal-confirmation and commit gate, and large planned commits remain valid.
Both size settings stay validated as positive integers with a safe product while
disabled. For example:

```json
{
  "pipelines": {
    "plan-execution": {
      "automaticCommitSplitting": false,
      "commitSizeAssessmentMultiplier": 4
    }
  }
}
```

Re-enabling it with that multiplier assesses strictly above 3,600 lines. The
resolved switch is frozen at creation, so changing configuration never toggles
an existing run; migrated runs keep their saved eligibility. Custom runs are
never assessed, and plan authoring's advisory target is unaffected.

Execution publishes `plan.progress.md` beside unchanged `plan.md`, retaining its
exact headings and adding size-decision footnotes, original/replacement states,
exact subjects and verified SHAs. Decimal labels are for display only. CLI status
and live activity plus MCP status/wait/activity expose the same state-derived
progress, including the artifact path and accepted effective revision. The 900-line
planning target is advisory; execution assessment starts strictly above 2,700
lines at the defaults. Editing the progress file grants no authority. Resume
regenerates missing/stale owned output; preserve its run ownership comment.
Runner refuses unrelated files, links and repository-local paths that are not
already ignored. See the
progress contract (`pipelines/plan-execution/docs/SPEC.md#derived-refinement-progress`).

## Correction limits

The stagnation window detects consecutive blocked correction rounds. In
independent mode the first full window invokes one fresh Arbiter and a second
full window pauses for the user. Lazy mode has no Arbiter and pauses at the
first full window. Harder configured limits take precedence.
For authoring, only independent Reviewer findings are eligible for arbitration;
self-review and deterministic structural exhaustion pause without it.

## Finalization guidance

For plan execution and polishing, `finalization: "auto"` uses a conventional
confined repository `finalization` skill when present. The fallback derives the
complete gate from repository instructions and project-defined checks. Use
`"none"` to select that fallback deliberately, or a normalized
infrastructure-relative Markdown path to require that exact procedure, such as
`.agents/skills/finalization/RUNNER.md` beside an existing skill, or
`finalization/SKILL.md` under a selected external infrastructure root. Explicit
paths resolve from that bound root (the target itself for integrated setups);
auto discovery remains repository-local. The original skill is preserved. A
missing, escaping, linked, or invalid explicit file blocks the run. Every path retains
the dedicated fingerprint-bound finalization turn. Both workflows freeze the
effective path or fallback decision before bootstrap; automatic discovery never
switches later. New selections fingerprint file bytes, identity and real ancestry; even
an identical-byte replacement requires a new run. Selection grants only the
exact file read, never access to its parent. Custom execution keeps guidance
optional: `auto` selects none, while an explicit file supplies criterion-dependent
guidance without Git authority.
