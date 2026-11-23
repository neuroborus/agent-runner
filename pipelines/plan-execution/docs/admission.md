# Execution Inputs And Plan Kinds

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Inputs

The runner receives:

1. a local Git repository for commit plans, or a directory for custom plans;
2. a task directory.

```bash
agent-run run plan-execution \
  --project /path/to/repository \
  --task /path/to/task
```

Task directory:

```text
task/
├── task.md
├── clarifications.md  # optional plan-authoring transcript
├── plan.md
└── context.md      # optional
```

- `task.md`: task/problem statement.
- `clarifications.md`: optional product decisions captured during plan authoring.
- `plan.md`: ordered plan of the explicitly selected kind.
- `context.md`: optional extra context supplied by the user.

The execution run keeps its own clarification transcript at:

```text
<infrastructure-root>/<artifactRoot>/agent-runner/<run-id>/clarifications.md
```

The selected configuration supplies the infrastructure root and resolved artifact
path; without configuration the root is the target. New state version 44 freezes
`clarificationRoot` and uses it for all transcript operations, pending edits,
append recovery, compatibility and product decisions. `artifactRoot` remains a
normalized infrastructure-relative selection, defaulting to `LOCAL_ARTIFACTS`.
Explicit version-43 migration preserves legacy repository ownership, exact paths,
workspace policy, hashes, receipts, pending edits/appends and consumed allowances.
Preflight-paused legacy runs resolve only their original repository root, never
current configuration. No artifact is relocated on resume.

Any enclosing repository must already ignore the untracked resolved path. Failure
pauses with `local_artifacts_not_ignored`; never edit ignore rules automatically.
External transcripts add no target Git baseline exemption or provider output
permission. Runner retains confined real parents, protected configuration,
control/task/state separation and target/infrastructure leases. Custom workspace
selection declares only this exact Runner artifact, never an output root.
The artifact is not runner state and must
never enter a planned commit. The task directory may be located inside or
outside the target repository. Runner state must therefore **never** be stored
inside the task directory or target repository.

---

## Plan Format

Commit plans use the authoritative shared
[`@agent-runner/commit-plan`](../../../packages/commit-plan/README.md) contract;
custom plans use
[`@agent-runner/custom-plan`](../../../packages/custom-plan/README.md). Before
bootstrap, this pipeline must parse and validate the explicitly selected kind
with its deterministic contract rather than an LLM.

For commit plans, the Worker must use the validated subject exactly as returned
by the parser. The runner must never ask an agent to generate or rewrite it,
and multiple planned commits must never be merged into one implementation step.

### Plan-kind step policies

Private `step-policy.js` owns the differences between commit and custom steps:
deterministic parsing/serialization, step context and agreed criteria, workspace
inspection, initial content-change requirements, role capabilities/access and
the terminal effect. `commit-workspace.js` owns the existing two-pass Git
preflight and stale-plan inspection. Commit steps retain clean-worktree and
identity requirements, ignored clarification artifacts, exact subjects and
runner-observed nonempty initial implementation. A matching HEAD subject never
counts as completed work. Consumed commit verification and operator-stop
reconciliation still precede stale-plan inspection or new implementation proof.

The private custom policy consumes `@agent-runner/custom-plan`, carries each
step's referenced observable conditions, work, expected results and frozen
declarations, and permits analysis without an artificial file diff. It selects
directory inspection through the root-supplied bound capability, grants neither
retrieval nor paths from plan declarations, and has no `local-commit` access or
Git effect service. Analysis eligibility is not result acceptance. `custom-results.js` supplies accepted-result checkpoints. CLI `--plan-kind custom`, MCP `planKind: "custom"` and configuration `pipelines.plan-execution.planKind` explicitly select this route. Omitted and legacy kinds stay commit; plan syntax or absent Git never infers a kind. Execution consumes criteria and input/output declarations from the frozen plan, rather than accepting authoring-only criteria/source/output overrides.

The existing mode policy, finding/correction loops, availability handling,
output-exhaustion recovery and fingerprint-bound gate evidence remain shared
within this pipeline. Commit-specific effective revisions, validation rebinding,
replacement execution and derived progress retain their existing contracts and
eligibility rules. There is no second runner or cross-pipeline dependency.
