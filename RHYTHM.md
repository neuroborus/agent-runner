# RHYTHM.md

Chronological record of meaningful implemented repository decisions. New dated
sections are added immediately below this introduction. Entries describe the
resulting behavior, rationale, and important consequences; current contracts
remain in the owning documentation.

## 2026-09-13

- **Codex rejects incompatible response schemas before provider activity.**
  A Codex-owned keyword and structural compatibility gate now validates the
  effective schema, including local-commit readiness, before probing or starting
  a turn. Invalid declarations fail terminally without provider recovery or
  output correction. Plan-execution terminal schemas no longer use unsupported
  `uniqueItems`; both runtime normalizers retain deterministic uniqueness,
  bounds, membership, and rejected-result validation. Schema traversal preserves
  literal data and property names, and provider restrictions stay inside Codex.

- **Opaque Codex turn failures use bounded provider recovery.** `turn_other`
  now enters the existing single fresh reconstruction for non-commit requests
  outside source forks. The complete durable request preserves valid workspace
  progress; a repeated failure pauses at the safe checkpoint as
  `backend_unavailable` after repository reconciliation. Only fixed diagnostics
  and safe control fields survive. Local-commit readiness failures retain their
  pre-effect exit, and uncertain commit effects remain verification-only.
  Explicit policy, protocol, and model-selection violations still fail closed
  before recovery.

## 2026-09-12

- **Plan execution and polishing repair rejected finalization evidence.**
  Terminal evidence-only findings now return directly to complete finalization,
  preserving candidate acceptance and avoiding unchanged code-fix cycles. Mixed
  findings immediately invalidate evidence and converge content before a fresh
  gate. Two durable semantic retries per execution step or polishing run are
  separate from malformed-output and code-fix budgets; pending attempts survive
  interruption, and exhaustion offers an explicit finalization retry.
  Terminal-fingerprint overrides cannot
  revive an invalidated PASS. Unchanged inventories still require sufficient
  evidence and do not prevent semantic rejection. The new state migration retains
  only bounded validated findings and control metadata while preserving
  commit-effect and runner-owned handoff safety. Polishing retains its existing
  malformed-output correction budget and keeps all agent turns index-read-only.

- **MCP supervision shares guidance and publication with the CLI.** Two thin
  tools read the complete common and local guide or replace the local document
  with an expected hash and idempotency key. The shared capability owns safety,
  concurrency, and interruption recovery, so receipt retries preserve later
  edits from either transport. A single startup reminder applies even when
  issue reporting is disabled; guidance remains supervisor context only.

- **CLI guidance editing shares launch mechanics without sharing exit policy.**
  The CLI reads combined guidance or edits the complete local Markdown through
  a private external copy. Publication retains the original destination,
  configuration, and content hash, so even an unchanged close rejects stale
  edits. Shell-free editor selection and launch now have one root owner;
  guidance requires a successful close while clarification still consumes
  authorization whenever a launched editor closes.

- **Operator guidance has one common owner and a confined local extension.**
  The installed operator guide covers preparation, supervision, recovery,
  validation, and completion across CLI and MCP. The shared root capability
  composes it with the complete optional project-local document, preserving
  common safety precedence and keeping additions outside pipeline roles and
  durable runs. Hash-checked replacement holds canonical-worktree ownership
  and uses atomic publication with durable temporary-file provenance. This
  prevents stale edits, duplicate effects, and incorrect adoption of another
  writer's identical content after interruption.

## 2026-09-05

- **Unchanged terminal repairs retain fingerprint-bound finalization.** Plan
  execution and polishing now clear candidate and confirmation attestations for
  terminal findings while retaining a successful finalization record whose
  content and validation-infrastructure fingerprints remain current. After
  independent or lazy candidate convergence, an exact match retries the distinct
  terminal confirmation directly; actual content or infrastructure changes,
  correction-scope drift, content-changing recovery, and a new commit step still
  force the complete gate to rerun. This removes redundant full-suite work
  without weakening the fresh confirmation required immediately before commit
  or handoff.
- **Compact test output retains complete failure diagnostics.** The normal root
  test command uses Node's built-in `dot` reporter while preserving automatic
  discovery and the bounded concurrency of 4. Passing records no longer flood
  finalization context, while failed-test names, assertion diagnostics, and
  stacks remain available from the same run without a reporting dependency or
  a diagnostic-only rerun.
- **Workflow policy fixtures are lightweight while capability proofs stay
  real.** Plan-execution and polishing state-machine suites inject
  pipeline-owned in-memory effects, split along cohesive behavioral boundaries,
  and expose cross-directory builders only through `test/support/index.js`.
  Focused Git and store integration cases remain serial within their files,
  while root capability and cross-capability suites prove atomic state,
  journals, leases, recovery, filesystem durability, snapshots, commits, and
  handoffs. The root `node:test` command caps file concurrency at 4 to leave
  headroom on the 16-CPU baseline machine after higher bounds exposed
  intermittent contention; isolated suites still overlap without making the
  complete gate depend on maximum host parallelism.
- **Default convergence budgets favor completing difficult corrections.** Plan
  authoring permits 20 revisions, while plan execution and polishing permit 20
  fix rounds, five repeated-finding rounds, and five disputes per finding by
  default. The three-round stagnation window remains unchanged so architectural
  non-convergence is still detected early; every budget remains configurable
  and frozen into each new run.

## 2026-09-04

- **Polishing finalizes only stable semantic candidates.** Independent Reviewer
  convergence, or lazy Worker check/fix plus read-only candidate confirmation,
  now precedes the writable finalization gate. A distinct read-only terminal
  confirmation binds the resulting content and exact validation evidence before
  the runner-owned `HANDOFF`, so formatter changes are reviewed and every repair
  returns through convergence without duplicating staging.
- **Plan execution finalizes only stable semantic candidates.** Independent
  Reviewer convergence, or lazy Worker check/fix plus read-only candidate
  confirmation, now completes before the writable terminal finalization gate.
  One distinct read-only confirmation then binds the resulting content and
  exact validation evidence immediately before `COMMIT`, so intermediate
  candidate corrections do not prematurely run finalization and stale evidence
  cannot authorize a commit.
- **Provider registration is one static, testable composition seam.** A frozen
  descriptor registry under [`src/agents/`](src/agents/) supplies backend IDs,
  adapter factories, native option and profile rules, source-session support,
  and failure classification to root runtime consumers. A fake descriptor and
  source-boundary regression prove that adding a provider does not require
  pipeline branches or private cross-capability imports, while production
  remains source-controlled rather than dynamically extensible.
- **Repository formatting is one root-owned terminal-gate concern.** The exact
  stable Prettier 3 release is pinned once at the root, and the root scripts
  format the Git-visible supported file set while preserving repository and
  local ignore rules. Finalization runs the writable formatter first, then the
  non-mutating repository and whitespace gates, so accepted evidence describes
  the formatted candidate without adding per-workspace tools or configuration.

## 2026-09-03

- **Existing project agent guidance participates in writable turns.** Codex
  protects project-root `.agents` by default, but Agent Runner reopens an
  existing real directory during workspace-write turns so planned guidance
  changes are possible. Complete and recovery role prompts keep that capability
  outside normal maintenance without repeating the rule in compatible
  continuation turns: the task must explicitly request the change, and plan
  execution additionally requires it in the current plan step. A symlinked
  `.agents`, `.git`, and `.codex` retain their provider protection, preserving
  the narrow content-versus-control boundary.
- **Current product meaning and repository decisions have explicit owners.**
  [`docs/README.md`](docs/README.md) is the single document map and change gate,
  while the focused documents under [`docs/product/`](docs/product/) explain
  current guarantees without reproducing pipeline state machines.
  [`docs/CONVENTIONS.md`](docs/CONVENTIONS.md) owns intended engineering rules,
  [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) records the implemented runtime,
  and this file retains the rationale for durable decisions. Reviewers can now
  find business meaning without reconstructing it from code while each exact
  contract keeps one normative owner.
- **Canonical skill instructions are versioned, provider interface metadata is
  local.** [`test/scaffold.test.js`](test/scaffold.test.js) validates each
  canonical `SKILL.md`, and [`.gitignore`](.gitignore) excludes only YAML files
  beneath `.agents/**/agents/`. Codex and Claude continue to share the canonical
  [`.agents/skills/`](.agents/skills/) tree, but an installed agent may create
  its own ignored interface metadata without dirtying the repository or making
  a clean checkout depend on one provider's installation format.
- **Repository placement follows ownership rather than the historical flat
  layout.** [`docs/CONVENTIONS.md`](docs/CONVENTIONS.md) defines capabilities,
  provider slices, intentional public indexes, and present-need promotion as
  the target architecture. [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) remains
  a description of the current implementation and must move with it, so an
  accidental file layout cannot justify new dependency violations.

## 2026-09-02

- **Independent execution remains the default; lazy execution is an explicit
  consumption tradeoff.** The three pipeline descriptors under
  [`pipelines/`](pipelines/) own the same `independent` and `lazy` setting.
  Independent mode retains distinct primary and review contexts for genuine
  semantic review. Lazy mode resolves only the primary role and requires a
  separate read-only clean confirmation, reducing provider use without
  presenting self-review as independent review.
- **Writable provider turns use provider-specific isolation behind one shared
  role contract.** The adapters under [`src/agents/`](src/agents/) block Git
  metadata and remote writes while allowing only phase-authorized content
  changes. Codex receives a runner-owned private temporary root and Claude must
  prove its native sandbox policy before advertising writable capability. This
  keeps provider mechanics private while making the pipeline safety guarantee
  backend-neutral.

## 2026-08-27

- **The Git index has one effect owner per content-producing pipeline.**
  [`pipelines/plan-execution/docs/SPEC.md`](pipelines/plan-execution/docs/SPEC.md)
  assigns staging and commit hygiene to the constrained `COMMIT` effect, while
  [`pipelines/polishing/docs/SPEC.md`](pipelines/polishing/docs/SPEC.md) assigns
  final staging to the runner-owned `HANDOFF`. Bootstrap, finalization, and
  semantic review remain staging-independent, preventing ordinary agent turns
  from turning index state into evidence they control themselves.

## 2026-08-18

- **Pipeline registration is static and the MCP boundary projects the same
  durable runner.** [`src/pipeline-registry.js`](src/pipeline-registry.js)
  explicitly registers independently owned pipelines, and
  [`src/mcp/index.js`](src/mcp/index.js) exposes their control operations over
  STDIO rather than implementing a second workflow engine. Persisted
  idempotency intent, detached continuation, and reconnectable status let long
  runs outlive a client call without introducing dynamic plugins, a network
  service, or a daemon.
