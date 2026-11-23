# Polishing Review, Findings And Clean Confirmation

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

### Review And Findings

Finalization failures enter finding resolution in both modes. They must be
fixed, never disputed; in lazy mode their no-progress path cannot invoke an
Arbiter. A content-changing fix invalidates candidate, finalization, and
terminal-confirmation evidence and returns through mode-specific candidate
convergence before the complete finalization gate runs again.

Ordinary terminal findings without validation-evidence rejection clear candidate
and terminal-confirmation attestations while retaining a successful finalization
record provisionally. After mode-specific
candidate convergence, the runner recomputes the finalized content and
validation-infrastructure fingerprints. Exact matches return directly to
`CONFIRM`; a mismatch invalidates the record and re-enters `FINALIZE`. A
declared fix without a proven repository mutation does not invalidate evidence.
Actual content or infrastructure changes, provider correction-scope drift, and
content-changing interruption reconciliation always do. One fresh successful
terminal confirmation remains required immediately before `HANDOFF`.

Terminal confirmation does not treat leaving out explicit post-completion
operator acceptance as an omission. It rejects evidence or summaries claiming
that such acceptance ran or passed and a finalization that adds it, while a
missing genuine pipeline-owned check remains an omission. Candidate review,
Worker self-review and terminal confirmation also report evidence that reserved
work actually ran early or that development evidence is claimed as reserved
coverage, even when final acceptance stays pending; source observation, overlap
or undecidable evidence alone is not a confirmed violation. Dispute
reconsideration and arbitration decide such a finding by the allegation it
makes, never by the label. This semantic rule follows the
[validation ownership guarantee](../../../docs/product/VALIDATION_AND_REVIEW.md#bootstrap-inventory).

Terminal `validationChange: REJECTED` has a separate recovery route shared by
both terminal roles. First honor the existing whole-result override gate for
all findings at the exact terminal content fingerprint. Otherwise immediately
invalidate finalization and confirmation evidence, including mixed rejections.
The required `finalizationFindingIds` array is a unique subset of at most 32
reported finding IDs identifying evidence-only concerns requiring no repository
edit. It must be empty outside a rejected terminal result; mixed concerns must
be separate findings. Candidate-review schemas do not carry this field, and
routing never classifies prose.
Evidence may be rejected even when the inventories and infrastructure are
unchanged. Such a rejection uses semantic recovery, not malformed-output
correction; inventory equality alone does not establish sufficient check evidence.

After exact applicable overrides, a pure evidence rejection preserves candidate
acceptance and returns directly to `FINALIZE` with bounded accepted findings.
It does not run candidate convergence or code check/fix, charge fix/correction
rounds, or update stable-finding/stagnation history. A mixed rejection routes
only content findings through ordinary mode-specific resolution and candidate
convergence, then requires fresh finalization even if content stays unchanged.
Neither withdrawal nor a later override can restore the invalidated PASS.
Ordinary non-rejection findings retain the existing reuse rule above.

Recovery invokes the complete finalization procedure with its ordinary
formatting permissions, canonical infrastructure inspection, ordered check
results, runner-trusted execution, and final evidence construction. A replacement
must retain every established exact check ID/command and infrastructure entry;
feedback cannot authorize an omission, substitution, removal, or weakening.
Every finalization request includes the saved established validation tuple,
including session-independent reconstruction after interruption.
Malformed replacement output follows the existing separate read-only correction
budget. A valid replacement and one fresh terminal confirmation must bind the
same resulting content and validation fingerprints before `HANDOFF`.

Pipeline state version 11 adds `finalizationRecovery`, containing consumed
`attempts`, explicit `additionalAttempts`, `required` and `pending` flags, and
nullable bounded `feedback`. Feedback retains only normalized findings, their
evidence-only ID subset, the terminal content fingerprint, and the current
established-infrastructure fingerprint. It never retains a rejected finalization
record, provider output, or transcript. The version-10 migration initializes
empty metadata without inferring lost rejection output, moving the workflow,
changing persisted mode, or replaying pending or completed handoff effects.

Two automatic semantic retries are available per polishing run, independently of
malformed-output and code-fix budgets. Before invocation, persist the consumed
attempt and pending marker. Interruption, provider unavailability, and external
validation blockage resume that pending attempt without recounting it. Content
or infrastructure scope drift discards stale feedback without replenishing the
run allowance. Content repair still returns through candidate convergence;
formatting within finalization retains its usual permissions and fingerprint
rules. Accepted replacement finalization clears pending recovery and feedback,
while the consumed allowance remains until the run ends.
A blocking product decision retires the pending attempt and its feedback before
returning through bootstrap and polishing; it does not restore
consumed allowance or remove the replacement-finalization requirement.
An operator stop that adopts changed content from an interrupted recovery
finalization likewise retires the pending marker when it returns to candidate
convergence. The consumed allowance and the replacement requirement remain, and
the replacement finalization reserves its next attempt before invocation.

Exhaustion pauses as `finalization_evidence_rejected`, with `FINALIZE` as the
resume checkpoint, bounded actionable CLI/MCP evidence, and an explicit null
retry granting exactly one additional attempt. Independent-mode overrides use
the saved terminal content fingerprint, which may differ from candidate
approval after formatting. Partial overrides leave other feedback blocking;
resolving all recovery feedback authorizes one replacement attempt and still
requires complete finalization and fresh confirmation. Lazy mode exposes no
finding overrides. No retry grants index-write or commit authority; runner-owned
`HANDOFF` alone stages the accepted content.

#### Independent review and findings

In independent mode, an independent read-only Reviewer first checks the stable
candidate before `FINALIZE`. It reviews the task, resolved context, entire
current diff, tests, architecture, edge cases, minimality, and conventions, but
does not attest finalization or validation evidence. Its first candidate review
starts a separate checkpoint seeded from durable evidence; re-review and dispute
reconsideration reuse it. Findings use stable `R`-prefixed IDs and remain
blocking. Only an accepted candidate fingerprint may enter `FINALIZE`.

After finalization passes, `CONFIRM` runs one distinct read-only Reviewer turn
over the finalized content, established and candidate validation inventories,
runner-computed infrastructure fingerprints, and exact per-check evidence. The
request is reconstructed from durable state rather than depending on the
candidate-review session. It records `UNCHANGED`, explicitly `ACCEPTED` for a
complete task-authorized validation change, or `REJECTED` with a finding, all
bound to the finalized content fingerprint. Approval enters `HANDOFF` directly;
ordinary findings return to resolution, while evidence rejection follows the
shared terminal recovery route above.

The Worker resolves all current blockers in one batch by `FIX` or evidence-based
`DISPUTE`. Fixes return through candidate review and then either reuse matching
successful finalization evidence or rerun the complete finalization gate before
terminal confirmation. The Reviewer reconsiders disputes as `WITHDRAW` or
`UPHOLD`. An unresolved dispute reaches a fresh read-only Arbiter after the
configured budget. Every finding must be fixed, withdrawn, arbitrated, or
explicitly overridden by the user for the exact candidate or terminal
fingerprint that reported it.

Each decision `reason` is nonempty single-line plain text of at most 4000 UTF-16
code units, without control characters or line or paragraph separators. The
resolution instructions state this rule, and the nested schema field carries the
supported `minLength` and pattern subset; top-level `reason`, `question`, and
`whyBlocked` stay generic bounded text because inactive outcomes require `""`.
The strict normalizer remains authoritative and also rejects whitespace-only
text. Each rejection carries one bounded diagnostic with a fixed field and
constraint, never a rejected value or finding ID: `result`/`exact-field-set`,
`status`/`resolution-status`, `empty-array` or `empty-string` for the first
inapplicable field in schema order, `reason`, `evidence`, and `evidence[j]` for
a blocked outcome, and positional `decisions[i]`, `decisions[i].id`,
`decisions[i].decision`, `decisions[i].reason`, `decisions[i].evidence`, and
`decisions[i].evidence[j]` identities. A non-array batch and positions of 32 or
more report `decisions`/`array-up-to-32-items`; a batch that does not resolve
every current blocker exactly once reports
`decisions`/`every-current-blocker-exactly-once`.

If an external environment constraint blocks nondelegated work during finding
resolution, the Worker returns `BLOCKED` with no decisions and bounded reason
and evidence. A selected trusted command's agent-sandbox limitation alone
cannot block repairs; execution remains owned by `FINALIZE`. A
content-changing partial fix is preserved, invalidates all three gates, and
resumes at `REVIEW`; an unchanged turn retains its blockers and resumes at
`RESOLVE_FINDINGS`.

Exact finding IDs drive no-progress detection; fuzzy semantic matching is out
of scope. Exhausted fix, dispute, stable-finding, or stagnation budgets always
pause. Additional fix rounds do not reset history. One stagnation arbitration
may direct further fixes, implementation rework, or Reviewer reconsideration;
another complete blocked window pauses.

#### Finding-resolution result recovery

In independent and combined modes, every original `RESOLVE_FINDINGS` Worker
turn, writable or read-only after budget exhaustion, publishes a strict
`resolutionCorrection` checkpoint atomically with its active turn. It holds the
validated blockers, non-disputable IDs, budget flag, original access, pre-turn
content fingerprint, fix accounting, attempts, bounded diagnostics, and an
optional product-decision intent. Schema 2 also binds frozen resolution facts
and a predecessor repair report; never a rejected value, exception text, or
native output. Lazy mode creates no checkpoint and keeps its existing contract.

A returned report, including a provider structured-output failure, is
reconciled in one transition before its turn retires: the reconciled baseline;
a `ready` checkpoint bound to that snapshot's content and Git controls and the
established validation-infrastructure fingerprint; and, for changed content, the
single fix charge, `pendingCorrection`, and invalidation of every dependent
approval. The workflow stays at `RESOLVE_FINDINGS` with its blockers; the
candidate move waits for settlement. If acknowledgement of publication or turn
retirement is lost, Runner recovers from the authoritative journal. A pure
classifier retains only the strict normalizer's bounded diagnostic. Availability
backoff, inactivity
reconstruction, authentication, and output exhaustion keep their existing
reconciliation, charging, and retry contracts for ordinary resolution and retire
that checkpoint with their first transition. Only an inactivity expiry proven
during that invocation counts. Terminal failures keep
their existing failure. Any other recoverable failure lost the report: the same
transition publishes `ready` with the fixed `result`/`interrupted-response`
diagnostic, and `backend_unavailable` resumes into the restatement. An
in-process classified retry reserves again from the round's pre-turn content,
so an earlier charged partial write still settles as changed content.

One helper settles original and restated reports with the existing routing: a
required FIX after budget exhaustion pauses `fix_limit_reached`; changed content
enters the mode's candidate checkpoint with recorded disputes and no further
charge; an unchanged FIX enters it through the existing gate invalidation and is
charged once unless already recorded; an unchanged dispute-only report records
disputes at `RESOLVE_FINDINGS`. An original `BLOCKED` pauses
`environment_blocked` at the candidate checkpoint when content changed,
otherwise at `RESOLVE_FINDINGS`. Settlement clears the checkpoint, and
convergence, review, finalization, terminal confirmation, and handoff are
unchanged.

An invalid or lost report is restated, never replayed. The runner persists the
consumed `correcting` attempt, then invokes one fresh read-only Worker session
at `resolve-findings:read-only:finding-resolution-correction` with the original
request rebuilt from checkpoint facts, the restatement instructions, and the
diagnostic batch. It may not edit, stage, validate, test, finalize, or repair;
it preserves the original claims and uncertainty and returns supported FIX
or DISPUTE dispositions, or the recovery-only unfinished outcome below.
Content, control, or validation-infrastructure drift
from the candidate binding pauses `unsafe_git_state` before invocation and
retains the checkpoint; frozen guidance and that binding are verified again
before a returned report settles. Protected-input drift keeps its existing
`task_input_changed` or `clarifications_changed` stop, and frozen-guidance
drift keeps its new-run guidance stop; while a checkpoint exists, both retain
it with the blockers, bindings, attempts, and counters. Guidance drift found
while reconciling an unreported original turn retains its `invoking`
checkpoint and original baseline without charging; an operator stop or a later
recovery reconciles that turn as an interrupted original. Read-only
contamination keeps `read_only_agent_mutated_repository`.

Recovery handles a checkpoint before stagnation, budget, and legacy
interrupted-turn rules. Only an inactivity expiry proven during the reserved
ordinary original keeps its reconstruction contract. An explicitly continued
repair never replays an invoked effect. Any other ownerless `invoking`
original may have consumed provider work: it is reconciled with workspace
changes allowed only for its writable access, charged once, and published as
`ready` with the fixed `result`/`interrupted-response` diagnostic. Until a
returned response retires them, the restatement uses the original's unfinished
availability or inactivity checkpoint, so owner loss never renews either
allowance; a backoff pending there or at the restatement checkpoint before
invocation resumes the consumed restatement. On catalog resume a fresh-session
request can use the remaining reconstruction under the same read-only
reservation after the adapter retires its native work. A transient availability
failure during restatement publishes the next backoff and retires that turn in
one journal event. Admission and replay bind retirement to the active read-only
restatement's recorded start, consumed reservation, reconciled content, and a
failed provider attempt recorded after that start at the backoff's checkpoint.
Runner retires the earlier invocation before recording a start that can prove
read-only restatement. If publication is interrupted, recovery uses the journal
to determine whether the next backoff was scheduled. A catalog miss during a
continued repair with a spent restatement allowance pauses with
`resolution_output_invalid` after reconciliation. Explicit resume authorizes one
more read-only attempt with the saved blockers and counters. A watchdog expiry
with the reconstruction allowance spent publishes `backend_unavailable`
together with turn retirement, during live settlement or cold recovery.
Explicit resume runs that consumed restatement. A diagnostic-free `ready`
checkpoint, a valid report whose settlement was lost, receives the same
diagnostic and is restated. A
restatement whose turn is still recorded was invoked: unless that attempt's own
first expiry was proven, it is lost and publishes `exhausted` before its turn
retires, so retained availability evidence never reauthorizes it. Without a
pending retry, an uncategorized `correcting` attempt is also lost. Operator
stops reconcile without invoking an agent: a stopped original becomes `ready`
at `RESOLVE_FINDINGS`, and other stages verify the binding. An interrupted
restatement remains eligible for continuation on explicit resume when its
matching watchdog expiry predates stop acceptance. Cold and stop recovery both
verify the checkpoint of the provider attempt recorded after restatement start,
including a retained original episode when that was the dispatched checkpoint.
Without that proof the interrupted restatement is lost.

A restated `BLOCKED` keeps the consumed `blocked` checkpoint and pauses
`environment_blocked` with `RESOLVE_FINDINGS`; this is the supported stop when
the original dispositions cannot be established. `PRODUCT_DECISION_REQUIRED`
first persists the validated decision, number, and expected transcript hash.
The append journals its exact resulting hash before replacement; recovery
settles a pending intent from that hash before input inspection or role dispatch.
Settlement first verifies the inputs, the repository, the candidate's
validation-infrastructure binding, and frozen guidance; drift pauses and retains
the intent and checkpoint without transcript mutation.
Checkpoint retirement, counters, transcript hash, and editor authorization
publish with the existing product-decision suspension.

An invalid or lost restatement publishes `exhausted` with the
`resolution_output_invalid` pause: `ERR_INVALID_POLISHING_OUTPUT`, a fixed
explanation, `Worker field <field> violated <constraint>.` evidence, and
`RESOLVE_FINDINGS`. Availability backoff, the shared inactivity allowance,
authentication, and output exhaustion retry the same consumed attempt without
recharging it. Clearing an authentication, output-exhaustion or inactivity
pause records `retry-ready` for the bound restatement. The next read-only turn
changes it to `correcting` as part of turn start, so restart before dispatch
preserves the continuation. Output exhaustion retains the restatement's
existing provider episode. Authentication retires superseded availability
backoff. An explicit null resume of `resolution_output_invalid` or a blocked
restatement's `environment_blocked` pause persists one more consumed attempt
before exactly one further read-only restatement. Both retries preserve the
automatic allowance and run read-only.

##### Unfinished repair continuation

Recovery-only `UNFINISHED` establishes an observable still-required repair under
frozen authority. It requires empty decisions, options, question and whyBlocked,
a bounded reason and nonempty current-blocker evidence. Ordinary resolution and
polishing turns reject it. It establishes no historical completion, disposition,
containment or validation credit; missing provenance that prevents safe
continuation remains a bounded stop, and genuine environment and unsatisfiable
validation-policy stops retain their existing contracts.

The runner retains every original blocker and publishes `repair-required` with
`finding_repair_required`. Null-action resume explicitly authorizes one new
repair, after owner retirement and verification of inputs, configuration,
candidate/content/controls, frozen guidance, infrastructure and permissions.
Authorization is journaled as `repair-authorized` before atomic turn publication.
An uncertain repair checkpoint, invocation, retirement or child-session publication
acknowledgement, including read-only restatement startup, propagates without a
stale failure or pause transition; recovery uses the authoritative journal.
Only that proven unstarted authorization is reusable; a published invocation
requires reconciliation, retirement and read-only recovery. This also applies
to provider failures during the new repair, including authentication and output
exhaustion pauses, preserving consumed recovery allowances.

Bounded UNFINISHED work reports retain checkpoint/candidate/facts/blocker hashes,
consumed attempts, diagnostics, pending correction, fix accounting and predecessor
lineage independently of native sessions. New invocations carry consumed attempts
forward without renewing the automatic restatement allowance. A previously charged
logical repair remains pending and is charged only once; an additional uncharged
round needs available fix budget. Without it, retain the binding at the existing
`fix_limit_reached` pause: only its narrowly eligible `extra-fix-rounds` grant can
authorize the repair, including one originally inspected read-only. No action
resets stagnation/dispute limits, grants staging/commit authority or replaces
mode-specific convergence, candidate review, FINALIZE or terminal confirmation.
CLI/MCP expose the bounded pause and only its applicable existing resume action.
Related replacement-proposal, clarification-retirement and stale-finalization-marker
repairs remain separate pending scope with their original histories and budgets.

#### Lazy check/fix and clean confirmation

In lazy mode, polishing enters writable `CHECK_AND_FIX` before finalization and
never invokes Reviewer or Arbiter. The Worker receives the entire current
result, the bounded trusted-command projection specified for polishing, prior
candidate or terminal findings, and this mandatory review core:

```text
Review the changes and verify that they are correct, idiomatic, minimal, and consistent with the project's conventions. If you find any problems, fix them idiomatically and minimally, following the project's conventions.
```

This is a workspace-write turn. Its strict result reports changed or unchanged
content, an external blocker, or the narrow product-decision outcome, and the
runner compares that claim with the actual content fingerprint. Every change
clears candidate, finalization, and terminal-confirmation evidence and requires
another check/fix pass. After that validation, an accepted `CHANGED` or
`UNCHANGED` summary replaces the stored Worker polishing summary, so every later
role context, including reconstructed requests, carries the latest accepted
primary report. The separate `workReports` context also preserves earlier
accepted summaries and finding reports, including through content repairs.
Invalid, blocked, and product-decision results leave the latest summary
unchanged. A replaced summary is neither a content change nor approval and
renews no budget.

An unchanged pass is not approval. It enters a separate read-only
candidate `CLEAN_CONFIRM` over the exact current content and
validation-infrastructure fingerprints, using the same criteria while
explicitly forbidding edits and requiring structured `CLEAN` or concrete
findings. A status/content mismatch is invalid output, repository mutation is
rejected, and fingerprint drift pauses without advancing. Findings return
directly to `CHECK_AND_FIX`; they are not disputes and cannot invoke Reviewer or
Arbiter. Mutation-free `CLEAN` accepts the candidate and enters `FINALIZE`, or
returns directly to `CONFIRM` when retained finalization evidence still matches
the recomputed fingerprints.

After finalization passes, `CONFIRM` runs one distinct read-only Worker clean
confirmation over the finalized content and exact validation evidence. This
terminal result supplies the same validation-change decision required from the
independent terminal Reviewer. Only mutation-free `CLEAN` with unchanged
fingerprints and `UNCHANGED` or task-authorized `ACCEPTED` validation change
records the reviewed and terminal clean-confirmation fingerprints and enters
`HANDOFF`. Ordinary terminal findings return directly to `CHECK_AND_FIX` and require
candidate confirmation plus a fresh terminal confirmation; finalization reruns
only when the retained evidence no longer matches. Existing
fix, stable-finding, stagnation, and additional-round budgets bound the loop;
exhaustion never accepts a non-clean result.

Provider structured-output failure and deterministic candidate check/fix or
clean-confirmation contract failure are reduced to a bounded batch of Worker,
phase, contract, field, and constraint diagnostics. Candidate-review
normalization identifies shape and status, inactive decision fields,
status/findings consistency, finding identity, content, uniqueness and stability
at `findings[i]` positions, and product-decision fields by fixed schema field
names, never by values or IDs; unknown and historical causes stay
`result`/`semantic-contract`. The first invalid result
for the exact phase, candidate content fingerprint, and
validation-infrastructure fingerprint persists attempt `1` and a pending
marker, then reconstructs the complete durable request with the original schema
in one fresh Worker session. Rejected output, provider text, prompts, commands,
paths, transcripts, and credentials are not retained.

A check/fix correction remains workspace-writable and index-read-only. Safe
content from an invalid or interrupted turn is reconciled once, stale gate
evidence is invalidated, and actual fix work is charged once. A candidate
clean-confirmation correction remains repository-read-only and requires the
unchanged content and validation-infrastructure fingerprints. Its
validation-infrastructure binding is the Runner's live inspection of the
established inventory before the rejected turn, rechecked before and after the
correction; drift pauses as `unsafe_git_state`. A valid replacement rejoins
only its original route and cannot provide finalization, confirmation, review,
approval, or handoff evidence early. A repeated invalid
result pauses as `lazy_output_invalid` with bounded redacted diagnostics, the
exact resume checkpoint, and one explicit null retry. Resume reconstructs the
pending correction without adding another automatic attempt, replaying an
effect, recounting work, staging, or advancing to `HANDOFF`.

Independent candidate review and both terminal-confirmation variants own
separate one-attempt correction records scoped to their candidate or finalized
fingerprints. Candidate corrections cannot accept validation evidence, and
terminal corrections cannot themselves provide finalization or reuse a
candidate approval. Candidate-review and candidate clean-confirmation
corrections bind the Runner's live inspection of the established inventory,
which may differ from the established fingerprint after an authorized
infrastructure edit. An accepted terminal validation change replaces the
established tuple without invalidating or renewing a consumed candidate
correction. Correction-scope drift invalidates the retained
finalization record and routes through `FINALIZE`. A writable `FINALIZE`
catalog retry preserves the frozen input hashes, candidate, validation
inventory, correction scope, spent rounds and authorized limit from the first
pause through dispatch. A catalog retry at `CONFIRM` preserves frozen inputs,
finalization evidence, and the correction allowance through turn start. Scope
drift before dispatch clears terminal evidence and pauses with
`unsafe_git_state`. If an accepted catalog retry still owns the candidate
review, infrastructure drift pauses as `unsafe_git_state` before dispatch and
preserves the pending correction and its consumed allowance. Admission and
journal replay preserve that review scope until the matching turn starts.
Candidate Reviewer rejections carry the same candidate-review field and
constraint identities as lazy clean confirmation. Terminal confirmation shares
their finding count, identity, content, uniqueness and product-decision field
identities.
Repeated invalid output pauses at the exact `REVIEW` or `CONFIRM` checkpoint
with bounded diagnostics and an explicit null retry.
