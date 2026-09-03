# Documentation

This directory is the entry point for Agent Runner's engineering contracts.
Use the change gate below before editing tracked content; read the documents
owned by the affected boundary, and update them in the same change when their
contract changes.

## Document map

| Document | Owns |
| --- | --- |
| [`AGENTS.md`](../AGENTS.md) | Mandatory project goals, working agreements, safety invariants, repository ownership, and required checks |
| [`RHYTHM.md`](../RHYTHM.md) | Newest-first record of meaningful implemented repository decisions; read when a change creates or revises a durable decision |
| [`docs/CONVENTIONS.md`](CONVENTIONS.md) | Intended architecture and repository-wide code, module, test, documentation, and formatting conventions |
| [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) | Detailed current runtime design, dependency direction, configuration, persistence, recovery, MCP, Git, and clarification contracts |
| [`docs/product/PIPELINE_MODEL.md`](product/PIPELINE_MODEL.md) | Pipeline purposes, relationships, modes, and clarification boundaries; read before changing workflow meaning |
| [`docs/product/VALIDATION_AND_REVIEW.md`](product/VALIDATION_AND_REVIEW.md) | Validation, review, fingerprint, and effect-gate guarantees; read before changing how work becomes acceptable |
| [`docs/product/PROVIDER_MODEL.md`](product/PROVIDER_MODEL.md) | Provider capabilities, execution selection, sessions, and normalized failures; read before changing backend semantics |
| [`docs/product/OPERATOR_MODEL.md`](product/OPERATOR_MODEL.md) | Configuration, CLI/MCP control, durable state, pauses, and observability; read before changing operator behavior |
| [`docs/product/SAFETY_MODEL.md`](product/SAFETY_MODEL.md) | Repository permissions, Git ownership, redaction, and effect reconciliation; read before changing a safety boundary |
| [`README.md`](../README.md) | User-facing installation, configuration, CLI, MCP, and pipeline usage |
| [`packages/commit-plan/README.md`](../packages/commit-plan/README.md) | Shared commit-plan syntax, parsing, validation, and Conventional Commit subject contract |
| [`pipelines/plan-authoring/docs/SPEC.md`](../pipelines/plan-authoring/docs/SPEC.md) | Plan-authoring roles, prompts, states, corrections, artifacts, and completion rules |
| [`pipelines/plan-execution/docs/SPEC.md`](../pipelines/plan-execution/docs/SPEC.md) | Plan-execution roles, prompts, validation, review, commit, recovery, and completion rules |
| [`pipelines/polishing/docs/SPEC.md`](../pipelines/polishing/docs/SPEC.md) | Polishing roles, prompts, validation, review, handoff, recovery, and completion rules |
| [`project-structure` skill](../.agents/skills/project-structure/SKILL.md) | Operational ownership guidance for placing, moving, or splitting repository code |
| [`finalization` skill](../.agents/skills/finalization/SKILL.md) | Post-change review, validation, staging, and commit-message handoff gate |

## Change gate

`AGENTS.md` and `docs/CONVENTIONS.md` apply to every tracked change. Then use
the narrowest matching row; more than one row may apply.

| Change | Read before editing | Update when the contract changes |
| --- | --- | --- |
| Product behavior, business rule, accepted nuance, or operator guarantee | The owning product document and its implementation/specification owner | Owning product document; architecture or specification for exact technical contracts; `RHYTHM.md` for a new durable decision |
| Repository boundaries, dependency direction, capability layout, or public indexes | `docs/CONVENTIONS.md`, `docs/ARCHITECTURE.md`, `project-structure` skill | `docs/ARCHITECTURE.md`, repository maps, and `README.md` when visible to users |
| Root runner, configuration, state, Git, clarification, trusted validation, provider adapters, or recovery | `docs/ARCHITECTURE.md` and the nearest tests | `docs/ARCHITECTURE.md`; `README.md` for visible configuration or behavior |
| Pipeline workflow, roles, prompts, schemas, settings, retry policy, pause actions, or completion | Owning pipeline `SPEC.md` and `docs/ARCHITECTURE.md` for shared runtime interaction | Owning pipeline `SPEC.md`; architecture and README only when their contracts change |
| Commit-plan syntax, serialization, validation, or planned subject rules | `packages/commit-plan/README.md` and both consuming pipeline specifications | Shared package README and every affected consuming specification |
| CLI or MCP command, schema, projection, activity, or wait behavior | `README.md`, `docs/ARCHITECTURE.md`, and affected pipeline specifications | `README.md` and every changed owning contract |
| Finalization discovery, validation inventory, review gate, staging, or commit handoff | `finalization` skill, owning pipeline specification, and `docs/ARCHITECTURE.md` | Skill, specification, and architecture wherever semantics changed |
| Node version, dependencies, formatting, naming, imports, or test conventions | `docs/CONVENTIONS.md` and root package metadata | Conventions, package metadata, and README when setup changes |
| User-facing installation, configuration, examples, or workflow | `README.md` plus the owning implementation contract | `README.md` in the same change |

## Ownership and precedence

- Safety invariants in `AGENTS.md` cannot be weakened by another document.
- The closest owning specification defines behavior for its package or
  pipeline.
- `docs/CONVENTIONS.md` defines intended structure and engineering practice.
- `docs/ARCHITECTURE.md` describes the implemented cross-cutting runtime
  contract; update it rather than using stale placement as precedent.
- Product documents describe current guarantees, business meaning, and accepted
  nuances without replacing exact state-machine or schema contracts.
- `RHYTHM.md` records why meaningful implemented decisions were made; it is not
  a substitute for the current owning document.
- `README.md` explains supported user behavior and must agree with the owning
  technical contract.
- Skills define agent procedures. They do not replace product or architecture
  specifications.

When documents disagree, do not silently choose one. Preserve mandatory safety,
resolve the owning contract, and align every affected tracked document in the
same change.

## Documentation rules

- Keep one owner for each rule. Link to the owner instead of copying detailed
  behavior into several documents.
- Keep normative tracked documentation in English and free of machine-local
  paths, personal profiles, credentials, and session artifacts.
- Keep every tracked product Markdown file represented exactly once in the
  document map with a concise ownership and reading description.
- Describe implemented behavior in architecture, package, pipeline, and user
  documentation. Keep speculative work in ignored local artifacts.
- Add a newest-first `RHYTHM.md` entry when a change creates or revises a
  durable product, convention, safety, provider, workflow-ownership, or
  architectural decision. Mechanical moves and corrections need no entry.
- Update examples and commands when their accepted input or output changes.
- Run the `finalization` skill after documentation-only changes as well as code
  changes.
