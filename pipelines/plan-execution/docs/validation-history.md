# Historical Validation Noncompliance

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

### Historical validation noncompliance

Apply the [historical validation disposition](../../../docs/product/VALIDATION_AND_REVIEW.md#bootstrap-inventory)
in every applicable role request, including continuation, reconstruction,
correction and terminal confirmation. Containment preserves proven truth and
pending checks without requiring cosmetic edits or premature finalization.
FIX may close an ongoing blocker without denying its historical allegation;
unchanged content remains UNCHANGED. Durable `workReports` retain accepted
Worker implementation, check/fix and finalization summaries plus accepted finding
reports and normalized finding-resolution decisions before current blockers are
cleared. Reports are context, never check credit or active blockers; complete,
continued and reconstructed role requests
receive them independently of provider sessions. Exact duplicate reports are
retained once; retaining a duplicate alone publishes no transition. Each closed report has `phase` and either a nonempty bounded
`summary`, nonempty bounded `findings`, nonempty bounded `decisions`, terminal
`validationEvidence`, or normalized `arbitration`;
execution also records its plan `step`, nullable only for the pre-step arbitration
described below. Summary phases are `IMPLEMENT`, `CHECK_AND_FIX` and `FINALIZE`;
finding reports use `CLEAN_CONFIRM`, `REVIEW` or `CONFIRM`.
`CONFIRM` reports retain nonempty normalized `validationEvidence` independently
of findings, including semantic evidence rejection, ordinary content findings,
and successful confirmation. They use the terminal result's existing plain-text
and item bounds; findings-only legacy reports remain valid. No validation
decision, fingerprint or approval is stored in this historical shape. Publication
accompanies the accepting transition before recovery clears terminal evidence;
content repairs and step advancement preserve the facts without preserving check
credit. The common request boundary supplies this history even during validation
migration, independently of the resolved summary and native session.
Accepted `BLOCKED` results at `IMPLEMENT`, `CHECK_AND_FIX` and
`RESOLVE_FINDINGS` instead retain the closed shape `step`, `phase`, `status`
(`BLOCKED`), `reason` and `evidence`, under the existing blocked-result text/item
bounds and normalization. These reports publish atomically with the environment
pause, including read-only restatement, and survive retry clearing or replacing
that pause. At `CHECK_AND_FIX`, the role attempt has already persisted any
changed-content baseline, invalidated dependent gates and charged the repair.
The caller uses that live reconciled state without repeating its publication;
remaining pending-output-correction cleanup and the accepted blocked report
publish together in `environment_blocked`, resuming at `CHECK_AND_FIX`.
Earlier accepted commits, current candidate and finding history remain intact.
The historical blocker grants neither check credit nor a current
finding; the retry still must satisfy its checkpoint normally.
`FINALIZE` reports may additionally retain nonempty normalized `issues` under
the existing finalization-issue contract (`id`, `command`, `problem`, `evidence`)
and nonempty normalized Worker `checks` (`checkId`, `command`, `status`, `evidence`).
Check reports use the existing check-ID, exact-command, status and text/item
bounds, with unique IDs/commands and strict closed fields. Reported `NOT_RUN`
records a reservation only; reported statuses confer no executor authority or
check credit. Retain reports before Runner replaces trusted placeholders, an
execution blocks, or content repairs invalidate finalization. Accepted blocked
finalization uses its normalized reason as the report summary and retains its
nonempty normalized blocker `evidence` alongside check reports before pausing.
Summary-only and issue-only records remain valid; migration does not infer
missing facts. These private records use the same history bounds and state
diagnostics and do not change public validation projections or required checks.
`RESOLVE_FINDINGS` decision reports retain every accepted decision's `id`, `decision`
(`FIX` or `DISPUTE`), normalized `reason` and `evidence`, under the existing
resolution text/item bounds and strict closed fields. They publish atomically
with acceptance, including unchanged containment, mixed decisions, exhausted
fix budgets and read-only report restatement. Reconciled content repairs,
including lazy resolution, cannot bypass retention. Resolved findings remain
inactive; these decisions give no check or gate credit and renew no allowance.
`RECONSIDER_DISPUTES` reports retain normalized Reviewer decisions (`findingId`,
`direction`, `reason`, `evidence`), including withdrawals and upheld concerns.
`ARBITRATE_FINDING` retains an `arbitration` with `findingId`, `direction` and
`rationale`; `ARBITRATE_STAGNATION` retains `direction` and `rationale` in the
same field. Historical finding arbitration also admits `REQUIREMENT_AMBIGUOUS`,
with its finding ID; historical stagnation arbitration also admits
`PRODUCT_DECISION_REQUIRED`. Retain only their normalized direction and separate
rationale (plus the finding ID where applicable), atomically with the authorized
product-decision pause, before active ledgers clear. Product-decision questions,
options, blocking evidence and editor authorization retain their existing owners.
The separate rationale survives the authorized answer, bootstrap or compatibility
re-entry and later requests; it cannot recreate an active ambiguity or dispute.
These historical directions do not widen active arbitration ledgers.
Execution-only `PLAN_REVISION_REQUIRED` stagnation outcomes likewise retain their
separate rationale atomically with the terminal plan-revision pause; they still
require a revised plan and a new execution run.
`ARBITRATE_BOOTSTRAP` and `ARBITRATE_VALIDATION_MIGRATION` reports likewise
retain only normalized `direction` and `rationale` in `arbitration`. Bootstrap
uses `step: null`; validation migration records its positive current step or
`null` when no step is active. Other report phases still require a positive
step. Both phases admit `USE_WORKER`, `USE_REVIEWER`, `SYNTHESIZE` and
`PLAN_REVISION_REQUIRED`; only bootstrap admits `PRODUCT_DECISION_REQUIRED`.
Resolved outcomes publish with the accepting context/inventory transition,
product decisions with the authorized pause, and plan-revision outcomes with
their terminal pause. Answer/re-entry preserves the rationale without granting
approval, check credit, active disputes or plan-revision resume authority.
Bootstrap/migration arbitration remains restricted to independent mode.
Existing decision, identifier and text/item bounds apply. These closed records
publish with the accepting transition in each checkpoint's permitted mode,
before containment or repair can clear active ledgers. Common request
context preserves them through continuation, reconstruction and later plan
steps; neither compacting dispute history nor step advancement drops them.
They preserve reported facts without retaining an active dispute, approval,
validation credit or renewed budget. Lazy mode gains no adjudication role.
Existing summary/finding bounds apply, with at most 256 reports and 2 MiB of serialized UTF-8 history. Capacity exhaustion
fails closed without truncation or completion credit. Existing previous findings
remain available alongside this history; current blockers retain their separate
fields. Accepted finalization summaries are retained before Runner-trusted checks
and survive repairs or replacement of finalization evidence without retaining
check credit. These records preserve allegations as reported, including uncertainty;
semantic review determines their truth and remaining consequences. Self-findings
still route directly to fixing; fresh arbitration remains restricted to independent disputes.

Worker may return `VALIDATION_POLICY_BLOCKED` only for proven execution leaving a
cited task requirement unsatisfiable under frozen authority, including explicit
irrecoverability. Uncertainty, difficulty, environment constraints and pending
later checks do not qualify. Its existing bounded reason and evidence fields
carry exactly three nonempty plain-text entries, in order: execution proof,
governing task requirement, and why no corrective disposition is permitted.
All other fields are inactive empty strings/arrays, including finalization's
skillPath, inventories and checks; customResult, when present, is null.
Normalizers enforce shape and bounds; semantic review establishes the evidence's
meaning. Reviewers use ordinary findings directing Worker to this truthful stop,
not impossible content repairs or evidence-only finalization rejection.

After normal effect reconciliation, the runner journals `WAITING_FOR_USER` with
reason `validation_policy_blocked`, code `ERR_VALIDATION_POLICY_BLOCKED`, the
Worker reason as explanation, the three evidence entries and the originating
Worker checkpoint. It accepts no new gate or check evidence and starts no further
trusted checks. Safe content, historical facts, completed provenance, inventories,
frozen guidance/bindings and consumed allowances remain intact. CLI and MCP
project the same bounded explanation/evidence and no retry or finding override.
The supported next action is operator assessment of a separately authorized,
task-compatible disposition, or cancellation preserving work. Starting another
run cannot waive explicit policy or cure a historical violation.

Publication uses the existing complete write-ahead transition and atomic state
replacement. Publication failure propagates without replacing the policy stop
with a generic failure. Existing writable-report restatement can publish a valid stop after
reconciliation without replaying effects or charging a fix twice; rejected
reports remain unavailable. A settled stop cannot resume under frozen authority.
Migration preserves legacy records without inferring stop evidence or moving old
runs. No historical run is automatically repaired or resumed.

Pipeline contract version 41 admits this outcome at `IMPLEMENT`, `CHECK_AND_FIX`,
`RESOLVE_FINDINGS` and `FINALIZE` in each applicable mode. Its version-40
migration initializes missing `workReports` to an empty array without inventing
historical disclosures; existing reports, completed effects, counters, pending
correction allowances, inventories and bindings retain their meaning. Reports
publish with the accepting transition and survive content repairs and later
steps; report restatement and duplicate publication grant no new credit or
allowance.
If publication changes report history but its acknowledgement fails, propagate
the failure without further pipeline transitions from the stale local snapshot.
Recovery uses the authoritative journal checkpoint, preserving reports,
bindings, counters and consumed allowances without replaying accepted work.
