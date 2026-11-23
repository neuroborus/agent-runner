# Custom Execution

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

### Custom execution and accepted results

The custom checkpoint uses the existing leased, revision-bound,
write-ahead pipeline transition capability. Its ledger binds the canonical plan,
agreed criteria, immutable input hashes, protected workspace fingerprint and
exact frozen permissions. References grant neither retrieval nor writes.
Each contiguous accepted record chains its predecessor receipt and contains
bounded analysis, criterion observations, exact selected output fingerprints,
the inspected snapshot and candidate/finalization/terminal-confirmation bindings.
Analysis is limited to 32 KiB, each observation to 4,000 bytes, each result to
128 KiB and the complete ledger to 1 MiB. Unknown fields, missing/unknown
criteria, unbound outputs and inconsistent receipts are rejected.
Selected output fingerprints also bind each symlink's inspected resolution
hops and readable target tree, recursively including links reached through
directories. Unrelated output siblings remain available to subsequent steps.

Worker success cannot accept a result. The runner must observe every
mode-required candidate gate, passing finalization and distinct terminal
confirmation for the result fingerprint, which includes analysis and evidence
as well as workspace content. Pending acceptance is journaled before settlement.
Reconstruction verifies the exact inspected content, output identities and gate
bindings before accepting that same record; it never asks a provider to replay
publication. The checkpoint alone advances no workflow cursor and invokes no
Git operation. Earlier accepted outputs remain immutable; changed frozen
criteria/inputs or invalidated earlier results require revised planning and a
new execution run.

Authorized product-decision answers still require the read-only plan-compatibility
gate and fresh candidate/finalization/confirmation evidence. Execution clarification
versions are bound in active result fingerprints and per result receipt,
separately from the immutable ledger binding. Only successful compatibility
and refreezing advance the active version. Compatible answers require fresh
convergence without rewriting earlier receipts or changing frozen input/output
authority. Unauthorized transcript edits remain input drift.

Before any new preparation, Runner applies backend-owned readiness to every
active role with eventual workspace-write access, including a custom Worker's
read-only startup. Codex's named-profile route refuses existing regular-file
output roots, including dotfiles, before writable implementation or native work.
Directory outputs and read-only file declarations retain exact permissions;
syntax remains backend-neutral and parents never gain write authority. Current
root shapes are rechecked before invocation despite cached capabilities. Pending
effects and owned process retirement retain their existing recovery order before
new writes; startup read-only and separate writable receipts, accepted results,
frozen declarations/source/control bindings and budgets remain unchanged.
Unsupported shapes use existing unsupported-backend/policy-drift paths with
bounded CLI/MCP diagnostics. Changing output or backend selection requires an
authorized fresh run, not a resume override. No durable shape migration is added.

Pending preparation and acceptance reconcile before new output admission.
Directory intent comes from the unchanged canonical declarations before path
normalization removes trailing `/`. Existing directories and explicit slash
directories use the owned preparation checkpoint; missing slashless paths never
implicitly become directories. Before preparing any new root, every output must
satisfy the selected descriptor's shape requirements, allowing only explicitly
preparable missing directories or enforceable exact-file creation. Codex rejects
missing unprepared roots (`capability_missing_output`); Claude rejects missing
exact mount roots (`output_root_missing`). After preparation, readiness permits
no missing roots for either backend, and the writable probe proves exact access
before invocation. Startup receipts and the separately pinned writable receipt
remain unchanged by recovery; cached proofs cannot approve changed shapes.
Workspace-owned directory inspection verifies every preparable root's current
shape and existing real parent before any new root is published.
Backend readiness also applies native literal-path restrictions before
preparation, including absent explicitly preparable directories.
Prose supplies no output kind or parent writes. See the
[custom-plan contract](../../../packages/custom-plan/README.md).

Output-directory preparation journals the exact declared root, its prior state,
real parent and a unique allocation path in private durable state before
creation. It pins the empty allocation with a no-follow descriptor before
publication, then journals the prepared identity before settlement. An owned
GNU no-clobber, no-copy move refuses even an empty concurrently appearing root;
no workspace siblings are allocated. Missing roots require private state storage
on the same filesystem and `/usr/bin/mv` with GNU coreutils 9.4's
`--no-clobber --no-copy --no-target-directory` support. Unsupported publication
fails closed without a copy fallback; existing roots need no utility.
The descriptor remains open through synchronization and final identity checks,
rejecting empty replacements before the first public-path identity read.
The workflow saves that verified prepared identity and its workspace baseline in
one transition, accepting only the exact empty-root creation. Recovery cannot
mistake a journaled preparation for unrelated drift or adopt intervening output edits.
Custom runs persist a bounded projection of each complete directory inspection
instead of a per-entry array: the entry count and digest, both fingerprints, an
immutable-remainder digest and one record per declared output root with its
entry and descendant digest. An absent root is a derived missing record proven by
complete capture; file or link ancestors fail closed. Complete snapshots stay
transient for output allowances, accepted-result receipts and validation
infrastructure, so their formulas are unchanged. Preparation compares only scope
and filtered-entry evidence, never the identity fingerprint that also covers
authorized artifacts such as an edited clarification transcript. An existing
root requires equal entry, remainder and output records. A missing root
requires an equal remainder and other output records while its own record changes
from missing to the prepared empty directory identity. Interrupted
reconciliation without allowed changes requires an equal entry digest.
Resume checks every required directory's settled preparation record, including
interruptions after ledger initialization or between separate root preparations.
An interrupted allocation or publication without a recorded identity stays
ambiguous; its exact journaled allocation and root are preserved. Only an explicitly
authorized output directory can be published; its parent must already exist.
A file output never grants its parent as a
writable mount. This preserves Claude's existing-root requirement without
broadening authority. Descriptor-anchored effects reject aliases, substitutions
and protected overlaps. Recovery verifies a published directory identity;
an existing directory after an absent intent without that proof is ambiguous
and remains preserved. Stops admit no new preparation or acceptance; pending
intent survives for reconciliation after authorized resume. The monitor's signal
and a fresh stop check guard allocation and publication after preflight. Owned
process retirement returns the current run revision before identity publication.
There is no cleanup
or rollback of unrelated content.

Pipeline state version 33 persists required `planKind`. New execution states use
`commit`; the ordered version-32 migration assigns explicit legacy commit
semantics without changing counters, sessions, saved mode, refinement eligibility,
validation evidence, completed commits or pending one-shot authorizations.
Prepared and consumed commits keep their original recovery contract; migration
never manufactures new effect authority.

State version 34 adds `customResults`, initially `null`. Its version-33
migration initializes no acceptance or preparation evidence and changes no
existing gates, counters, effects or eligibility. Commit runs reject a non-null
custom ledger. Version 35 adds nullable `customCandidate`, a nullable
`customWritePolicy` receipt and explicit setting defaults. Its version-34 migration
preserves commit semantics, gates, counters and consumed effects without granting
custom access or a writable policy receipt.

State version 42 persists new custom `repositoryBaseline` values in the closed
compact form: the snapshot-baseline fields, `remainderCount`, `remainderHash`,
`outputs`, `allowedPaths` and `projectPath`. Workspace and project paths equal the
run project, output paths equal the frozen policy, and each output record is a
closed path, captured or missing entry, descendant count and digest. Unknown,
scope or malformed fields fail closed. The identity version-41 migration rewrites
no state: legacy full baselines keep their representation, reconciliation and
bootstrap-scope fingerprint, and a version-41 runtime refuses compact baselines
as skew. A legacy run whose complete entries or link resolutions would exceed the
10,000-entry state capacity stops with `plan_revision_required` and
`ERR_CUSTOM_BASELINE_CAPACITY` before persisting the oversized baseline; the
operator preserves the work and starts a fresh custom run for the remaining
steps. Accepted provenance, frozen inputs, budgets and allowances are never
rebound.

Custom execution uses the existing sequential state machine. `IMPLEMENT` produces
bounded `customResult` data: analysis, observations in exact current criterion-reference
order, and absolute inspected output paths. Writable check/fix and finding
resolution return the complete result; inactive outcomes use `customResult: null`.
This field is a sibling of the status contract, separate from the strict
`result` status envelope used by implementation and finding resolution. Root
status evidence never carries custom criterion observations. Criterion-reference
order, result bounds and inspected output authority remain independently validated.
Analysis/evidence changes invalidate dependent gates just like output changes.
Every role sees the current and earlier accepted results, the current step's
work/expected results and agreed criteria. Coding requirements apply only when
selected by the user; unrelated repository coding gates are never automatic.

Independent candidate review, lazy check/fix plus distinct read-only clean
confirmation, and combined convergence followed by independent review retain
their ordinary bounded finding and correction contracts. Validation inventories
and schedules may be empty for semantic-only criteria, but discovery still covers
every step and retains every selected trusted command with its exact provenance.
Custom `finalization: auto` selects no coding skill; `none` also selects none,
while an explicit confined skill remains frozen and verified. Criterion-dependent
finalization and distinct read-only terminal confirmation bind the result,
content and exact validation evidence before `ACCEPT` journals and settles it.
Unmet criteria produce `FAIL` with concrete `F`-prefixed issues even when the
inventory is empty or all executable checks pass. Each semantic issue identifies
its criterion in `command`, without adding a fictitious check. These failures
must be fixed and return through fresh mode-required candidate convergence,
finalization and terminal confirmation before acceptance.
Only settled receipts advance the cursor; interruption reconciles pending
acceptance before another step. No custom state can enter `COMMIT`, carry a
pending commit, record completed commits or activate commit refinement.

Preliminary boundary discovery selects the workspace policy without reading
the plan. After project configuration and run overrides resolve, workspace
selection reads the explicit custom contract through a confined task reader
before Git inspection, binds local inputs and exact output authority and
grants no URL retrieval. Existing files or directories can be outputs; a trailing
`/` explicitly requests a directory root and permits journaled preparation under
an existing parent. An absent file never grants parent writes. Claude writable
mounts still require existing roots, so use an existing file or a declared
output directory for new files. Startup proves read-only access; after output
preparation the runner proves the exact writable access. Execution pins its
separate receipt before the first writable turn and requires the same proof
before subsequent writes, including reconstruction. Policy drift fails closed
without replacing the frozen startup receipt or broadening the workspace.
Repository-contained execution shares canonical exclusion and protects Git
controls. Its local clarification path must already be ignored and untracked.
Outputs remain unstaged, and completion exposes accepted-step receipts and
bounded results rather than commit SHAs. Source or accepted-output drift requires
revised planning and a new execution run.

---
