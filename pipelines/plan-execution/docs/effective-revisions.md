# Execution Effective Revisions and Validation

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

### Reviewed effective revision foundation

The private `effective-plan.js` policy persists proposed and accepted flat
revisions separately from frozen `canonicalPlan` and `plan.md`. Eligible
execution consumes accepted authority; proposals alone cannot select
replacements, materialize work or authorize effects.

A proposal replaces only the current unfinished effective step with two to
sixteen commits validated by `packages/commit-plan`. The runner copies all other
subjects and bodies unchanged, renumbers contiguously and records every effective
step's original step and replacement ordinal. Completed-prefix records bind
exact subjects, mapping and verified commit SHAs. Further splits remain flat;
accepted ancestry and completed provenance cannot be rewritten. Later revisions
cannot split an ancestor's already completed prefix, even when their proposal
and review fingerprints match. Logical deferred stop targets resolve through
their accepted revision to the original step and all its current replacements,
retaining the original target receipt.
Finding ownership outside the replaced step follows the unchanged step through
renumbering; only ownership on the replaced step may move to its new children.
Each revision retains complete finding payloads keyed by ID and payload
fingerprint. Different versions sharing an ID remain separately owned through
acceptance and reload; later revisions cannot omit inherited owners.

Each proposal binds a reserved SPLIT assessment, frozen plan/input/scope and
dependency fingerprints, inspected content and baseline HEAD, mode, complete
validation declarations and infrastructure, and finding versions with explicit
replacement ownership. Live drift prevents review or acceptance. Assessment
alone supplies no approval. Semantic reports must explicitly preserve
requirements, dependencies, later-step meaning, checks and findings; a negative
preservation judgment cannot be CLEAN.

Lazy acceptance requires Worker `CHECK_AND_FIX` followed by a distinct read-only
`CLEAN_CONFIRM`; independent requires independent Reviewer `REVIEW`; combined
requires both primary checkpoints before independent review. All these plan
turns are repository-read-only and have distinct revision/phase checkpoint keys.
Findings block acceptance; a corrected draft retains its predecessor and clears
dependent plan approvals. Every gate binds the exact proposal fingerprint.
Repeated identical proposals and published review receipts are idempotent.
Proposal identity includes the complete binding; changed validation or consumed
allowances require fresh reports even when the replacement text is unchanged.

Publish accepted authority through the existing leased write-ahead transition
before any boundary change. Acceptance retires candidate, implementation,
finalization and terminal-confirmation proof without clearing finding ownership,
correction history, finalization recovery or assessment allowances. Draft
corrections remain bounded across the original lineage by the saved correction
allowance plus its three assessment proposals; accepted attempts cannot be
reused. Each proposal binds the lineage's nondecreasing additional-round grant;
reload validates cumulative proposal consumption against that saved allowance.
Step advancement cannot discard historical grants or renew consumed proposals.
Any pending, consumed or ambiguous COMMIT excludes revision operations
until reconciliation. No revision operation stages, commits or rewrites history.

Acceptance retains the latest bounded batch as previous findings and combined
primary self-findings for fixing. The complete versioned payloads and ownership
remain in revision authority, without merging batches into the bounded,
ID-unique legacy field. Deferred finding references remain valid against that
authority at the acceptance boundary. Replacement execution must restore
applicable owned blockers, including lazy self-findings,
before invoking its content gates. Pending content corrections select
mode-specific candidate convergence. Acceptance retires pending
protocol markers with their invalidated proof, retaining the lazy and finalization
correction ledgers and recovery counts. Consumed candidate-review and terminal-
confirmation corrections are bound to each proposal and inherited across the
original lineage even after their scoped proof is retired; replacement
execution preserves those consumed allowances.

Pipeline state version 30 adds `effectivePlanRevisions`. The version-29 migration
adds only an empty ledger, preserving eligibility, frozen inputs, inventories,
approvals, findings, budgets and pending effects. Historical assessments never
become fabricated revision approval. Validation rebinding and replacement
execution retain their separate preparation and effect gates.

### Revision-bound validation foundation

`revision-validation.js` composes the existing bounded bootstrap with accepted
effective authority. Pipeline state version 31 adds `effectiveValidation`, an
ordered set of revision-specific role receipts and nullable merged schedules.
Frozen-plan inventories remain unchanged. These receipts alone grant no
writable, materialization or commit authority.

Each role independently rediscovers the complete catalog and applicability
read-only. Scope and unit IDs bind accepted revision number and fingerprint,
effective plan hash, exact selected replacement and step hash, prior inventory,
frozen inputs, repository, infrastructure and trusted commands. Requests include
the accepted flat steps and original/replacement correspondence. Proposed plans
cannot select work. Interrupted units retain their exact bindings; stale work
is retired without renewing correction or subdivision allowances. Acceptance of
a new plan retires pending units while preserving their consumed ledgers.

Rebinding preserves each role's ordered command catalog, infrastructure,
capability reports and blockers additively. Correspondence follows every accepted
splice, checking unchanged subject/body and origin before carrying assignments
forward. Every prior assignment survives on its unchanged step or at least one
descendant of a split step. Replacement applicability is rediscovered, never
copied by ordinal. New checks can supplement that minimum. Later-step coverage,
Reviewer-only obligations and requirements added by earlier revision discovery
survive further splits. Revision receipts retain the confirmed current-step
amendment, including its infrastructure and confirmation fingerprint. Scope and
unit bindings include that complete amendment; its commands, mapped applicability
and infrastructure must survive in the replacement Worker's inventory on
acceptance and reload, even after the active amendment clears. Discovery rejects
omitted amendment commands or infrastructure. Applicability rejects a dropped
assignment as soon as its last possible descendant has been inspected, leaving
the responsible unit unaccepted under the existing role correction allowance.
An amendment inherited from the split parent retains its descendant mapping
across clarification rediscovery. An amendment confirmed later in the accepted
revision remains assigned to its exact replacement, including later siblings;
it is not remapped as another parent amendment.

Only complete bounded coverage can publish a role receipt. Lazy requires Worker;
independent and combined require both separately accepted roles. The compact
schedule remains absent until all required roles finish, keeps Worker-first
union order, and binds the accepted revision. Capability preparation must still
consume every role's complete reports before materialization; a ready schedule
is not capability readiness or validation evidence. Selected trusted identities,
vectors and capabilities remain frozen, and checks execute only in FINALIZE.
Old schedules cannot select checks under newer authority. Revised implementation
evidence and selected plan context name the exact accepted replacement; an old
step ordinal or approval cannot become valid by renumbering.

The compatible version-30 migration initializes no revision-validation receipts.
It retains frozen-plan inventories, trusted authority, historical gates, consumed
effects and accounting. If accepted revisions exist, unbound pending units and
implementation evidence are retired, retaining subdivision totals. It never
fabricates applicability, approval, or legacy refinement eligibility. Pending
commits still settle by verification before discovery or new effects.
