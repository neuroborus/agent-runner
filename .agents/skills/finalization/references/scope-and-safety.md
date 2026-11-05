# Scope And Safety Review

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

### Check operator-facing consistency

Review these surfaces against the implemented descriptor and workflow contracts;
update only the owners affected by the current change:

- `README.md` and `docs/OPERATOR_GUIDE.md`: identical mode comparison tables,
  with the same row order; supported modes, independent
  default/recommendation, and resume behavior.
- `.agent-runner.example.json`: valid configuration, descriptor defaults,
  `preferredCommitLineLimit`, and exact trusted command catalogs and selections.
- CLI help (`agent-run --help` and `agent-run pipelines`) and MCP descriptions
  (`pipelines_list`, `run_start`, `run_pause`, and `run_cancel`): supported
  settings, role projections, and immediate/deferred stop availability agree
  with the operator guide. Deferred stops require a selected execution step.
- `docs/ARCHITECTURE.md`, owning `docs/product/` documents, and affected
  `pipelines/*/docs/SPEC.md`: gate ordering, recovery, correction accounting,
  source-session isolation, and commit/handoff authority remain consistent.
- For changed role or public contracts, apply [contract-review](../../contract-review/SKILL.md)
  across schemas, prompts, semantic validators, and public pause/error details. Constraints must be discoverable and
  failures actionable without exposing rejected payloads.
- `docs/README.md`: map links and ownership cover the current documents;
  `RHYTHM.md` records meaningful implemented decisions and their rationale.

Keep this checklist in the canonical `.agents/skills/finalization/` tree and
follow its `SKILL.md` entry point.
Do not copy it into phase prompts or create a Claude-specific skill copy.
Review coverage does not automatically add every referenced document to the
validation-infrastructure inventory; classify paths by their actual ownership.

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

- For changed read-only backends, inspect initialization and incidental writes as
  well as tool permissions; source/control drift remains meaningful evidence.
  Use [effect-review](../../effect-review/SKILL.md) when effects or lifecycle ownership change.
- Check workspace and scope selection before expensive traversal, retaining all
  supported Git and ordinary-directory consumers and the owning preparation visibility/cancellation contract.
- For changed concurrent observations, require proof of benign extension before
  retrying; preserve corruption detection and keep reads free of execution authority.
