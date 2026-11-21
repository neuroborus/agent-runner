# Polishing Testing Coverage

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Testing

Workflow policy tests use fake adapters with injected in-memory run-state and
repository effects. Their repository double models content fingerprints,
Git-control state, and handoff transitions deterministically while keeping task
inputs and validation-path fixtures confined to isolated temporary directories.
Shared builders are exposed only through `test/support/index.js`, and the
workflow suite is split by contracts and migrations, bootstrap, convergence and
review, recovery, and handoff.

Real run-store and Git services remain mandatory where persistence or repository
behavior is the subject. Keep focused cases for journals, interrupted recovery,
index ownership, staging, and handoff serial within their integration files.
Root state, Git, and cross-capability integration suites continue to own proof
of atomic files, journals, leases, recovery, filesystem durability, snapshot
semantics, and handoff behavior. Cover at least:

- dirty and clean preflight;
- staged, unstaged, deleted, and non-ignored untracked change membership;
- dirty tracked, non-ignored untracked, ignored untracked, and clean tracked
  task-input paths;
- default, configured, and legacy artifact roots plus ignored clarification
  creation and unauthorized clarification changes;
- empty and unchanged proactive clarification behavior;
- bounded questions and answer resume;
- independent Worker/Reviewer bootstrap and deliberate MCP source-session
  forks;
- omitted-mode preservation of independent probes, forks, review, disputes,
  arbitration, and completion gates;
- lazy primary-only probes and turns, exactly one Worker source fork across
  clarification, bootstrap, work, convergence, and resume, and no Reviewer or
  Arbiter invocation;
- reconciliation, arbitration, and product-decision pauses;
- stable runner derivation across conflicting role IDs, cross-role repeated
  commands and paths, role-only entries, trusted commands, and attempted
  reconciliation inventory invention;
- 256/257-item role boundaries, disjoint 512-item derived inventories and
  513-item rejection, semantic infrastructure classification, unchanged byte bounds,
  persistence, finalization round trips, infrastructure fingerprinting, and
  strict bounded capacity exhaustion;
- duplicate IDs or commands, multiline commands, missing files, directories,
  symlink aliases, successful bounded correction, interrupted reconstruction,
  validation-migration correction including interrupted Arbiter recovery, and
  repeated invalid bootstrap output;
- cached-diff fingerprints, index mutation and inspection, implicit
  worktree-versus-index checks, alternate indexes, and commit preparation in
  bootstrap, validation migration, and finalization, including corrected and
  repeated-invalid producing-role results;
- frozen explicit, automatic, none, and fallback finalization guidance,
  first-safe automatic selection, early explicit blockers, stable-content
  resume, drift rejection without correction accounting, no added provider
  turn, mandatory inventory capacity and omission correction, `BLOCKED`,
  `PASS`, and `FAIL` routes, interruption before and during the
  read-only correction, strict redaction, content-fingerprint reset, and
  repeated-invalid terminal behavior;
- read-only mutation plus ref, remote, and identity guards;
- durable transitions, interrupted turns, and journal recovery;
- action-free owner-loss continuation, input and Git-control drift rejection,
  read-only replay guards, preserved partial Worker content with rejected index drift,
  evidence invalidation, exact-once correction accounting, and activity-marker
  continuity;
- blocked provider activity plus lease-aware running, interrupted, and idle MCP
  projection;
- successful polishing, independent candidate review before finalization,
  formatter fingerprint changes, terminal Reviewer approval and findings,
  finalization failures, fixes, disputes, arbitration, stagnation, budgets,
  overrides, and complete gate invalidation;
- lazy changed and unchanged check/fix passes, candidate clean confirmation
  before finalization, distinct terminal clean confirmation, findings from both
  confirmations routed to fixing, required full reconvergence, matching-
  evidence reuse, change-triggered re-finalization, mutation and fingerprint
  rejection, bounded no-progress, and additional fix rounds;
- provider and deterministic lazy-checkpoint correction, repeated-invalid
  exhaustion and null retry, public redaction, fresh sessions, writable content
  and index reconciliation, exact-once budgets, fingerprint drift, gate and
  handoff preservation;
- interruption at candidate review, both lazy candidate checkpoints,
  finalization, terminal confirmation, and handoff without replay, double
  counting, duplicate staging, or a second source fork;
- automatic discovery, explicit skill selection, skill-less fallback, invalid
  explicit paths requiring a new run, and matching finalization/review
  fingerprints;
- canonical-worktree conflicts across independently identified polishing or
  plan-execution runs, detached MCP retry, and same-host stale recovery;
- compatible legacy migration, incompatible reader and detached-child
  rejection, and disconnects that leave durable state unchanged;
- every supported legacy version migrating through state version 18 to safe
  candidate convergence while preserving paused and terminal runs without
  replaying `HANDOFF`;
- finding-resolution report restatement in both independent-review modes:
  invalid and lost reports, interrupted publication, operator stops, blocked
  and product-decision outcomes, drift, exhaustion, explicit retry, and
  once-only fix charges;
- [cold repair continuation](../../../docs/testing/runner.md#interrupted-finding-repair-continuation)
  for unfinished finding-resolution reports and journaled repair authorization;
- sandbox, IPC, loopback, process-isolation, missing-service, and permission
  blockers for nondelegated work, including fingerprint-aware preservation
  and resume while another command is selected for trusted execution;
- delegated repairs and candidate convergence in both modes, with persisted
  exact command text in every affected writable checkpoint, continued and
  reconstructed requests, and lazy corrections; empty selections and exact
  matching without unrelated configuration or repeated inventories; trusted
  execution only during `FINALIZE`;
- successful, blocked, failed, non-allowlisted, fingerprint-drifting, mutating,
  and resumed runner-trusted checks with the durable selected snapshot;
- source-projection discovery, correction, migration, execution in every mode,
  content-change invalidation, evidence recovery, and matching handoff binding
  without duplicating root sandbox or Git-materialization proofs;
- finite redacted Claude failure classification, durable read-only request
  reconstruction, writable usage/provider reconciliation, and terminal
  authentication, unexposed-tool, unclassified-Bash, and ambiguous writable
  boundaries;
- non-delegating role prompts plus terminal, redacted, durable, and publicly
  projected forbidden-collaboration diagnostics;
- actual Codex workspace-write and Claude Git-directory/`git add` access
  envelopes, content-only added and updated files, successful and recovered
  runner handoffs, version-5 complete, untouched, and contaminated handoff
  migration, correction turns that leave the index unchanged for both
  backends, and every staging postcondition;
- the invariant that `HEAD` never changes and completion never commits.

Root tests cover workspace imports and metadata, static registration,
configuration, runner behavior, CLI/MCP projections, applicable resume actions,
idempotent detached continuation, and regressions for existing pipelines.

Additional terminal-recovery coverage includes both modes, evidence-only and
mixed rejection, unchanged-inventory insufficiency, exact replacement inventory,
separate malformed-output budgets, durable retry reservation and exhaustion,
provider and interruption recovery, scope drift, formatter-bound whole and
partial overrides, safe CLI/MCP projections, strict version-10 migration, and
handoff blocked until replacement finalization and fresh confirmation pass.
