# RHYTHM.md

Chronological record of meaningful implemented repository decisions. New dated
sections are added immediately below this introduction. Entries describe the
resulting behavior, rationale, and important consequences; current contracts
remain in the owning documentation.

## 2026-09-15

- **Execution gate evidence composes independently of mode routing.** Shared
  private predicates bind candidate approval to inspected content and terminal
  confirmation to the formatter's result. Repairs and unchanged resolutions use
  explicit invalidation rules across normal execution, migration, and recovery;
  consumed commit effects retain verification-only semantics.

- **Execution mode responsibilities are private pipeline policy.** Active roles,
  bootstrap, convergence, terminal confirmation, arbitration, and session scope
  now have distinct decisions shared by workflow, validation, and recovery.
  The two accepted modes, persisted correction evidence, bounded accounting,
  and repository authorization boundaries retain their existing behavior.

- **Combined authoring converges before independent review.** Authoring alone
  exposes an explicit combined mode, reusing primary check/fix and clean
  confirmation before the complete Reviewer gate. Revisions invalidate both
  approvals, and only independent finding resolution permits arbitration.
  Checkpoint-isolated sessions, read-only turns, durable correction accounting,
  and runner-owned artifact writes retain their existing boundaries. Mode
  availability comes from descriptors; saved modes survive leased migration.

- **Authoring review policy is independent of turn execution.** Private pure
  decisions now separate primary convergence, independent review, session scope,
  correction accounting, and arbitration eligibility. Workflow and state
  validation share those decisions while retaining the two supported modes,
  durable lazy fields, guards, and existing turn implementations.

- **Authorization publication failures preserve durable effect accounting.**
  Deferred-stop fault injection exposed stale workflow failure writes after
  preparation or consumption was already journaled. Execution now propagates
  those failures to existing recovery, preserving prepared authorization and
  verification-only consumed effects. Coverage exercises both stop actions,
  acceptance races, receipt replay, owner loss, and settlement publication.

- **Stop timing is an explicit transport choice.** CLI and MCP expose immediate
  or after-current-commit timing without refreshing inspected revisions.
  Immutable receipts retain acceptance evidence; shared bounded status and
  historical activity summaries retain settlement. Deferred requests use the
  existing quiescent fallback and detached reconciliation, so a disconnected
  caller or canceled wait never grants another owner or asks for extra work.

- **Deferred stops settle at the selected execution boundary.** Execution owns
  target selection; root composition supplies it to state, which serializes
  acceptance and settlement. The monitor permits the target step while still
  observing immediate cancellation. Verification supplies one SHA to the
  existing checkpoint path, including recovery; quiescent fallback preserves
  blockers and consumed-effect evidence without extra work. Final-step pause
  retains `DONE` for an agent-free resume. CLI/MCP status shows timing and target
  while request inputs remain immediate.

- **Deferred stop targets belong to durable state.** A trusted injected resolver
  binds requests to immutable commit-boundary evidence under acceptance
  serialization. Target-step work retains ownership, and crossing requires atomic
  settlement. Timing participates in new identities while historical immediate
  receipts remain replayable. Supersession cannot postpone an earlier stop;
  unsupported capabilities fail closed. Production registration is deferred to
  the runner integration step.

- **Verified commits settle progress and stops together.** Execution owns the
  successful checkpoint construction; state owns its atomic leased publication.
  The runner resolves the latest operator outcome while preserving the verified
  SHA, next checkpoint, and protected-input blockers. Publication failure cannot
  replace journaled progress with stale failure state, and consumed effects
  remain verification-only during recovery.

- **Stop enforcement and ownership accounting have separate policies.** State's
  private stop policy distinguishes pending requests, blocked advancement, and
  retained ownership. Every immediate pending stop still blocks ordinary writes;
  process retirement can complete without releasing unresolved stop accounting.
  Reconciled cancellation remains terminal but does not retain a worktree.
  Mutation serialization, receipt replay, and same-run recovery stay unchanged;
  deferred timing is not yet accepted.

## 2026-09-14

- **Polishing inventories match complete validation ownership.** Polishing now
  accepts 256 entries per bootstrap role and 512 per derived or finalization
  field, with the same responsibility-based infrastructure definition as
  execution. State version 12 preserves saved 64/128 evidence and handoff
  effects under leased migration. Index authority remains runner-owned; byte
  limits and strict Claude preflight and sandbox restrictions remain unchanged.

- **Execution inventories cover complete validation ownership.** Bootstrap roles
  can each report 256 checks and infrastructure files; derived and finalization
  inventories accept 512. Infrastructure is defined by ownership of commands,
  discovery, runners, configuration, or mandatory finalization guidance, not
  by files merely consumed by checks. The shared Git fingerprint input accepts
  512 paths while other path lists and byte limits remain unchanged. State
  version 16 migrates saved evidence without resetting budgets or replaying
  completed effects; polishing retains its existing limits for now.

- **Trusted command catalogs can be project-local.** Safe project configuration
  uses the existing exact-vector validator. Normalized catalogs merge root then
  project, deduplicate identical same-name definitions, and reject conflicts
  even when unselected. The merged catalog retains the 256-definition bound and
  each selection the 32-command bound. Project-only selections use the existing
  immutable snapshot before agent work, with unchanged identities, resume, and
  protected-input guards. Profile implementations and execution sandbox policy
  remain runner-owned; command definitions grant no additional host authority.

- **Commit size is an authoring heuristic.** The persisted
  `preferredCommitLineLimit` defaults to 900 anticipated additions plus deletions,
  including tests and documentation. Planner and review prompts prefer cohesive
  boundaries within that target and require concise explanations for indivisible
  exceptions. Descriptor-driven configuration, CLI discovery, and MCP metadata
  share the default; leased legacy migration supplies it without reloading
  configuration or replaying work. The shared plan format and execution gate
  remain unchanged.

- **Codex shell commands retain the owned-process proof through a narrow
  allowlist.** The provider process keeps its full isolated parent environment,
  while command construction applies Codex's automatic secret exclusions,
  explicit workspace values, and an exact allowlist of standard core names,
  `AGENT_RUNNER_OWNED_PROCESS`, and supplied workspace names. This preserves
  ownership evidence across provider-native PID sessions without exposing
  unrelated parent variables or weakening filesystem, network, MCP, or Git
  isolation.

- **Transient ownership inspection has one bounded recovery window.** A
  completion-time incomplete descendant observation retries against one
  non-resetting descendant-grace deadline before retaining the existing
  fail-closed error and durable exclusion. Once persistent containment failure
  is reported, the parent closes provider protocol resources and unreferences
  the detached supervisor and IPC channel without disconnecting containment,
  signalling unverified work, or clearing ownership, so the run owner can exit
  while deterministic recovery remains possible.

- **Owned-process failure is independent of provider protocol completion.**
  Codex races only owned-completion rejection against the complete App Server
  operation. A supervisor retaining containment and open protocol pipes can no
  longer leave a durable turn falsely running: the original ownership failure
  starts bounded cleanup and remains primary. Successful process completion
  does not substitute for a required protocol result.

- **Owned supervision preserves provider-native sandbox nesting.** Ordinary
  commands retain private PID namespace ownership. Provider adapters explicitly
  identify only executions that create their mandatory native sandbox; after a
  cached full nesting probe fails, those executions alone may use token-backed
  session ownership on the initial host namespace. Live ancestry and a token
  derived from the persisted PID/boot/start proof find provider descendants
  across sessions and nested namespaces, including after owner loss. Complete
  unrelated ancestry remains an independent exclusion proof. A stable
  pre-launch PID/boot/start baseline is the narrower fallback for an unchanged
  inaccessible host process whose ancestry is inconclusive; new, reused,
  changed, owned, and otherwise unproven processes and bounded-cleanup failures
  remain fail closed.

- **Resolved project configuration is protected input.** The same confined
  read that parses a project file now pins its canonical location, content,
  file identity, and real ancestor identities in the durable run envelope.
  Runner-owned checks surround provider turns and guard recovery, trusted
  validation, commit, handoff, and stop reconciliation. Any drift produces one
  bounded non-resumable safety pause without restoring the file or fabricating
  evidence for legacy runs; begun irreversible effects remain
  verification-only.

- **Pause and cancellation are durable controls across CLI and MCP.** CLI
  shorthand captures one inspected revision and fresh idempotency key, while
  repeatable CLI automation and the `run_pause` and `run_cancel` MCP tools bind
  both values explicitly. Exact retries replay state-owned receipts and stale
  requests never refresh silently. A live runner observes the durable stop;
  owner loss starts a detached same-run reconciliation without granting a
  second execution owner. Bounded status and wait projections expose pending
  intent without request identity or checkpoints, wait cancellation remains
  local to the caller, and terminal `CANCELED` work cannot be revived by an
  older continuation.

## 2026-09-13

- **Operator stops reconcile under the execution owner's leases.** The runner
  watches durable stop requests and aborts only its registered provider or
  trusted-command PID namespace. A supervisor waits for registration before
  launching work and starts cleanup when its owner's inherited IPC channel closes.
  System-protected bubblewrap establishes the namespace; its PID 1 lifetime
  contains detached sessions and double forks that process groups cannot retain.
  Envelope version 5 records host PID, boot/start, and namespace identity before
  launch, and retains exclusion until namespace teardown. Live signalling uses
  the original child handle/control channel; recovery never signals recycled
  numeric host PIDs. A nested runner test uses a distinct owned session only
  when the enclosing runner-trusted PID namespace denies another namespace;
  that existing namespace remains the detached-descendant containment boundary
  without added authority. Unsupported isolation otherwise fails closed without
  a group-only fallback. It retains conservative owner-loss recovery. Pipelines reconcile
  frozen inputs and Git permissions without provider work, preserve safe partial
  content, and invalidate affected gates. Consumed commits and begun handoffs are
  verified without replay; observed progress and the requested pause or terminal
  cancellation are recorded together. Null resume restores existing blockers
  before proceeding.

- **Writable turns defer selected trusted checks without deferring repairs.**
  Plan execution and polishing project only persisted exact command text into
  implementation, polishing, lazy check/fix, and finding-resolution requests,
  including continuation, reconstruction, and correction. Established check
  execution and attestation remain exclusive to finalization. Selected-command
  sandbox limitations cannot block applicable repairs or semantic review;
  nondelegated environment blockers preserve the existing safe-content and
  resume paths. No configuration reload, external attestation, or broader
  agent permission is introduced.

- **Legacy confirmation recovery requires journal provenance.** Failed opaque
  terminal confirmations can resume directly after mode-specific candidate
  acceptance, passing finalization, and complete safety revalidation are
  proven under the normal leases. State owns continuous history; the pipeline
  owns proof and shares revision-bound eligibility across CLI and MCP.
  Migration-derived terminal tuples cannot manufacture acceptance. A true
  correction marker survives an already charged fix through unchanged lazy
  checking and finalization, so recovery preserves it when no concrete work
  remains. Durable reconstruction, unchanged evidence, completed commits,
  idempotent receipts, and detached ownership prevent replay or recounting.

- **Structured Codex client errors are terminal even under `other`.** Bounded
  recognition of a native HTTP wrapper and JSON error envelope distinguishes
  non-transient request rejection, including HTTP 400 `invalid_json_schema`,
  from opaque provider failure. Only the fixed `turn_bad_request` diagnostic
  survives; the request is not compacted, retried, or sent to output correction.
  Malformed, ambiguous, oversized, and transient evidence retains existing
  bounded opaque recovery. Item auditing, model selection, source-fork and
  local-commit exclusions, and redaction remain intact without new pipeline
  branches or state migrations.

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

- **Operator stops have durable state ownership before process control.**
  The common envelope records bounded pause/cancel requests, immutable
  acceptance receipts, and references to exact suspended journal checkpoints.
  A short mutation boundary serializes acceptance with execution-owned writes and
  release without creating another execution owner or locking status reads.
  Cancellation wins competing requests from the same inspected revision, and
  recovery can reconstruct a lost receipt after a later cancellation or
  terminal transition. Pending stops retain held worktree exclusion across
  owner loss until same-run reconciliation. Lease identities now include boot
  and process-start evidence where available; legacy or inaccessible identities
  remain conservative. These state capabilities separate request durability
  from runner-owned signalling and Git reconciliation.

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
