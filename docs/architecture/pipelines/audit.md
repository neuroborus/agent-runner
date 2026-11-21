# Audit Ownership

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Source Scope and Discovery

The registered audit workspace owns report, discovery and finding-verification contracts behind
`pipelines/audit/src/index.js`: its canonical classification/criterion catalog,
strict immutable structured content and deterministic English renderer. One
catalog supplies classification validation, severity ordering and map text.
Confirmed findings require evidence, impact/severity rationale and labeled
concrete examples; unsupported claims remain separate hypotheses, and repeated
cause keys require consolidation. The renderer returns `audit.md` text without
filesystem or provider effects. Audit schemas share portable constraints with
semantic normalization; instructions cover normalized uniqueness and exact-copy
bindings. Recognized validation errors expose one immutable finite-code diagnostic
at a schema-owned, bounded field location, retaining existing error identities
and excluding rejected keys/values and native causes. Audit-owned correction
feedback retains only those constraints and exact checkpoint bindings for supported
resume; it grants no acceptance or additional retry allowance. The audit
specification owns the exact contract.
Its descriptor selects read-only
directory inspection and an exclusive canonical workspace lease. It freezes
`sourceScope` (`directory` by default, or explicit `git`) and literal `excludePaths`
(directory only) before preparation. Git scope resolves the worktree root without
gaining Git effects. Runner journals membership before capture and verifies it
around capture and reconstruction. Directory scope prunes exclusions before
traversal and never invokes Git. Filesystem declarations bind provider receipts;
Runner additionally binds Git provenance into snapshot fingerprints and role
context. Report/finding bindings consume that same snapshot. New report bytes
and report fingerprints also bind frozen source settings. Audit state version 9
preserves legacy missing settings as whole-directory scope without altering
evidence or historical report bytes. The discovery
lifecycle uses injected workspace, clarification, adapter, session and durable
transition capabilities; it grants no new root authority. Frozen scope,
references, exclusions, criteria and snapshot/report bindings precede discovery.
Lazy retains one logical Auditor, while independent creates a fresh Auditor per
pass. A write-ahead pass history preserves the frozen run-wide budget capped at 20,
including interrupted reservations. New/revised candidates block discovery at
pending verification; clean discovery is separate from finding acceptance and
requires verified report publication before public completion. A finding-producing
complete pass may finish one coherent batch before full-scope inspection, with
verification before the next discovery pass. A no-finding clean result still
requires complete agreed-scope inspection; incomplete work adopts no candidate
or report update. Logical turns establish existing inactivity/availability checkpoints
and use the common `repositoryBaseline` for recovery settlement. Distinct provider
dispositions survive pauses, terminal failures stay failed, and result acceptance
enforces enclosing persistent field/collection limits as well as aggregate bytes.
Terminal audit failures retain the boundary-normalized optional `diagnosticClass`
in the existing common pause contract, without a state-version change. The common
envelope owns registry membership; audit owns strict terminal shape/disposition
and fixed evidence/guidance. A same-transition safe failure activity survives the
public publication wrapper. CLI/MCP status, activity and wait retain the diagnosis
after reconstruction; absent legacy classes remain absent. Neither diagnosis nor
terminal continuation permits another agent turn or report publication; see the
[audit failure contract](../../../pipelines/audit/docs/SPEC.md#read-only-discovery-lifecycle).
Report/ledger updates must also fit the escaped Markdown publisher's 32-MiB bound
before acceptance; overflow preserves the prior ledger and pauses resumably
without an impossible publication intent or a renewed pass budget.
The separate batch gate rechecks every new/material version before more discovery.
Lazy continues the discovering Auditor; independent creates a fresh read-only
finding Reviewer after each correction. Versioned entries/dispositions, retained
rejections, snapshot/report bindings, write-ahead recheck reservations and exact
accepted-batch receipts preserve a second finite run-wide budget capped at 20.
Corrections and review additions invalidate batch approval without changing
historical discovery cleanliness. State version 2 initializes these records from
version 1 through the descriptor migration without inventing acceptance.
Auditor-only legacy roles remain frozen: lazy can recheck, while independent
verification pauses before reserving work and requires a new run with a Reviewer.
State version 3 adds combined per-owner source-fork consumption without changing
earlier roles, histories, budgets or approvals. Combined derives discovery and
recheck cycle positions from preserved history; only clean closes a logical
owner's series, and reconstruction never grants another first-pass opportunity.
The initial Auditor continues from clarification until clean, then a fresh
successor must be clean on its first discovery pass. A finding-producing or
report-correcting successor finishes its own series before replacement. Each
batch first converges with that discovering Auditor, then passes to fresh finding
Reviewers. A correcting Reviewer finishes its own series before replacement;
only a fresh Reviewer's clean first pass accepts the exact batch. Intermediate
clean rechecks retain pending verification without acceptance receipts.
Batch acceptance resumes the same discovering owner. Both run-wide budgets and
all non-clean history survive reconstruction and replacement. State version 4
adds pending/published report bindings and temporary ownership without changing
earlier evidence or roles.
State version 5 persists proactive clarification and defaults legacy runs to no
proactive request. Audit uses the common one-shot editor and identified MCP input
requests before its first Auditor turn and for material clarification questions;
unanswered material requests remain pending without spending another round.
State version 6 adds nullable checkpoint correction feedback; its version-5
migration initializes absence without changing saved evidence. Rejection saves
feedback, invalid accounting and the pause together. Only the matching role
checkpoint receives canonical diagnostics with fixed correction instructions;
validation replaces or clears feedback without changing session or budget rules.
The descriptor exposes the same bounded constraint evidence through CLI/MCP pause
projections, excluding native messages and rejected content.
Audit state version 8 adds private nullable output-recovery intent: phase,
round/pass ordinal, logical context and a retired prefix length in common child
lineage. Exhaustion saves it atomically with the operator pause before native
replacement. Explicit resume reconstructs that checkpoint without reforking a
source; acknowledged replacements can continue after response loss, while retired
children cannot supply results. Histories, exact finding/batch versions,
dispositions, receipt references and correction feedback reconstruct the request;
concise output guidance changes no verification gate or finite budget. The intent
survives pause clearing, cold interruption and classified availability/inactivity
recovery until its durable outcome settles it. Repeated exhaustion advances
retirement and pauses again. The leased version-7 migration creates intent only
for a genuine matching legacy exhaustion pause; unrelated absence becomes null.
No native ID is duplicated and no common-envelope change is required. See the
[audit recovery contract](../../../pipelines/audit/docs/SPEC.md#explicit-output-exhaustion-reconstruction).
Audit state version 9 captures `repositoryBaseline` through
`runtime.workspace.baseline`, so CLARIFY transitions persist bounded evidence for
any protected control-tree size. Its identity version-8 migration keeps null and
legacy full baselines; all guards use the same `assertUnchanged`.
The public lifecycle projects confirmed findings only from current exact accepted
versions, retaining pending candidates and hypotheses as unverified. It persists a
rendered-content intent, invokes the Runner workspace artifact publisher, verifies
readback and unchanged frozen inputs/source, then saves its receipt. Publication
recovery precedes further discovery; `DONE` requires the selected clean gate,
no pending batch and the exact complete report receipt. CLI/MCP metadata and
`auditReport` projections remain descriptor-owned. Reports live at task-owned
`audit.md`; `.audit.md.tmp` and the report are declared exact Runner artifacts,
excluded from long-lived source guards but protected during every agent turn.
The workspace publisher anchors its atomic rename to a verified real parent and
journals temporary identity and writing/prepared phases before their effects.
Ownership is mandatory: it allocates exclusively only without a temporary or
record, rewrites only its exact `writing` temporary, renames only exact matching
`prepared` bytes and never unlinks. Desired destination bytes off the expected
baseline reconcile only at the recorded `prepared` identity with no temporary;
equal expected/desired hashes without custody give a verified no-write receipt.
Readback verifies bytes, identity and temporary absence within an unchanged
parent directory observation. After the final lookup and parent stat, one
bounded directory read on the pinned parent serializes with entry mutations
before a worker samples its isolated native watch queue directly. The worker
inherits no parent runtime options or preloads. Only an empty queue permits a
receipt after binding revalidation. Custody failures and proven `EEXIST`/`ENOENT`
temporary races, classified after parent and ancestor guards, use
`ERR_WORKSPACE_REPORT_TEMPORARY_CONFLICT`. Destination conflicts including
post-open path disappearance use `ERR_WORKSPACE_REPORT_CHANGED` after the same
drift checks. Unsafe paths, drift and unrelated I/O keep their own outcomes.
Report conflicts remain distinct from immutable source drift. Init keeps its
separate destination-identity check. Before a new intent,
an unchanged projection whose rendered hash differs pauses as
`audit_report_rendering_changed`. Publication pauses keep the active state, or
the suspended checkpoint on resume, as durable `resumeState` while projecting
no continuation. Root dispatch confines it to the descriptor's
filename and requires ignored, untracked repository-local paths. It grants no
source, index, Git, retrieval or automatic issue authority. Critical findings do
not block successful completion. Conflicting partial temporaries remain preserved.
See the [audit specification](../../../pipelines/audit/docs/SPEC.md).

## Finding Verification and Combined Gates

Read the [current contract](#audit-ownership).

## Clarification and Checkpoint Recovery

Read the [current contract](#audit-ownership).

## Report Publication and Completion

Read the [current contract](#audit-ownership).
