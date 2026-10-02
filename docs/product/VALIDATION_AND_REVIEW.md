# Validation And Review

Validation and semantic review are separate sources of evidence. Deterministic
checks prove executable repository properties; agents assess correctness,
scope, architecture, and edge cases. Neither substitutes for the other.

Plan execution requires an observed content change for initial implementation of
each step. Worker completion claims do not suffice. The runner preserves the
original step-start evidence across partial work and resume; an unchanged step
requires plan revision before convergence or finalization. Unchanged corrections
and confirmations remain valid. Legacy runs without reconstructable original
evidence pause before further writable work; already-consumed commits still
settle through verification.

## Authoring review

Combined authoring requires two distinct approvals over the same durable draft:
a mutation-free Planner clean confirmation after check/fix, then independent
Reviewer approval. Deterministic plan validation and runner-owned artifact
writing follow both gates. Revisions clear dependent approvals and restart
primary convergence. Self findings return directly to fixing; only independent
finding resolution can use arbitration. Invalid output and interrupted recovery
do not duplicate accepted correction work or reset bounded budgets. These turns
remain repository-read-only.
In every authoring mode, exhaustion on deterministic structural failures pauses
without arbitration; an Arbiter cannot resolve those failures.

## Execution and polishing review

Combined execution runs Worker check/fix and a separate read-only clean
confirmation before the complete independent candidate Reviewer gate. Both
candidate approvals bind the same content fingerprint. Finalization may format
that content; a distinct Reviewer terminal confirmation approves its resulting
fingerprint and validation evidence before one-shot commit authorization.
Content repairs restart primary convergence. Self-findings go directly to fixing;
independent findings retain disputes, withdrawals, exact recorded overrides, and
fresh on-demand arbitration. Unresolved bootstrap disagreements and primary
exhaustion pause without arbitration. Corrections remain bounded and interrupted
work is charged once; resume preserves the saved mode and consumed commits remain
verification-only.

Combined polishing uses independent bootstrap, Worker check/fix and read-only
clean confirmation, independent candidate review, finalization, and a distinct
Reviewer terminal confirmation. Content repairs restart primary convergence;
unchanged resolutions reuse only fingerprint-current finalization. Self-findings
return directly to fixing; only independent finding resolution may invoke Arbiter.
Unresolved bootstrap and exhausted primary budgets pause. Handoff remains
runner-owned staging without a commit, and resume preserves accepted evidence
and correction accounting.

## Bootstrap inventory

Before writable work, plan execution and polishing establish the complete
staging-independent validation inventory and the repository files that control
it. Independent and combined modes combine separately accepted Worker and Reviewer
inventories. Lazy mode accepts one complete Worker inventory under the same
deterministic rules. Reconciliation may resolve summaries, but cannot add, select, or remove
checks. Only independent mode permits bootstrap arbitration; unresolved combined
bootstrap disagreements remain blocking.

Execution inventories are scoped to canonical plan steps. Every active role
discovers a complete procedure for every step: the ordinary fast gate and only
slow checks whose documented guarantees that step affects. The runner preserves
the accepted role assignments, merges commands in Worker-first order, and unions
their applicability. A Reviewer-only requirement survives reconciliation.
Later requirements remain persisted without executing during earlier finalization.
Polishing continues to use one workspace inventory.

Execution finalization and terminal confirmation bind the active step and its
exact ordered evidence. A confirmed inventory amendment affects only that
step; advancing clears its amendment and gate evidence and selects the next
persisted inventory. Shared infrastructure remains fingerprinted for the run,
and confirmation must explicitly assess authorized changes against future
requirements. Trusted capability preparation retains the complete catalog and
both roles' reports, while finalization reserves and executes only active
trusted commands. The frozen command vectors and identities never change.

Legacy execution inventories have no reliable applicability. Version-22 state
migrates explicitly to version 23 with provisional historical evidence; fresh
read-only discovery by every mode-required role precedes unfinished work.
Migration does not infer assignments from the old union, reset correction
accounting, adopt mutable configuration, or replay consumed commits. Terminal
history remains readable and consumed effects settle by verification first.

Commands, paths, capacity limits, and selected runner-trusted commands are
validated before acceptance. Validation-infrastructure paths must identify
canonical regular files. The runner fingerprints those files instead of
trusting an agent-provided digest. Resume uses the persisted inventory and
trusted-command snapshot rather than reloading mutable configuration.

## Finalization and semantic review

Plan execution and polishing first converge a stable semantic candidate, then
run their dedicated full finalization turn, and finally apply a distinct
read-only confirmation immediately before `COMMIT` or `HANDOFF`. Finalization
follows applicable repository guidance, runs required writable formatting
before generation and every established non-mutating check, and accepts no
omission or substitution. A project-required content change is fingerprinted
after it finishes.

Both workflows freeze their effective finalization-guidance path or fallback
decision before bootstrap. A selected skill remains mandatory fingerprinted
validation infrastructure for the run; automatic discovery does not switch or
fall back later. Missing, invalid, or changed frozen guidance requires a new
run rather than consuming correction or review budgets.

In independent mode, the Reviewer first checks the complete candidate without
attesting finalization. All findings remain blocking until fixed, withdrawn,
arbitrated, or explicitly overridden for the exact candidate fingerprint.
After finalization passes, a separate Reviewer confirmation checks the finalized
content and exact validation evidence. Content confirmation findings return through
candidate convergence. If the successful finalization record still matches the
recomputed content and validation-infrastructure fingerprints, the workflow
retries confirmation directly; otherwise it reruns finalization first.

In lazy mode, writable check-and-fix and read-only candidate clean-confirmation
turns converge before finalization. A passing finalization enters a distinct
read-only terminal clean confirmation over the exact validation evidence. Only
a clean result over unchanged fingerprints advances; ordinary findings return directly
to the next check-and-fix pass and the same fingerprint-bound reuse decision.

## Evidence and fingerprints

Recovery of a legacy failed terminal confirmation requires durable provenance
for actual mode-specific candidate acceptance and passing finalization.
Migration may preserve that provenance but cannot create acceptance from a
terminal snapshot. The runner validates intervening transitions and fingerprint
lineage, including finalization formatting and legitimate unchanged evidence
reuse. Recovery resumes only confirmation after revalidating the retained
gate; it neither replays finalization nor treats its result as candidate
approval. A fresh successful read-only confirmation remains mandatory.

Accepted finalization records one ordered result for every required check and
binds it to the staging-independent content, validation-infrastructure,
ordered-command, and trusted-configuration fingerprints. Skipped, weakened,
replaced, unmatched, or stale evidence fails closed. Host attestations and user
claims do not satisfy the gate.

Ordinary terminal findings invalidate candidate and confirmation attestations,
not an otherwise current successful finalization record. A declared fix does not prove
that content changed. After candidate convergence, exact content and validation-
infrastructure fingerprint matches permit a direct confirmation retry. Actual
content or infrastructure changes, provider correction-scope drift, content-
changing interruption recovery, and a new plan-execution commit step invalidate
the record and require the complete finalization gate again. Every path still
requires one fresh successful terminal confirmation immediately before commit
or handoff.

Plan execution and polishing treat terminal rejection of validation evidence
separately.
Unless every reported finding already has an applicable exact-terminal-fingerprint
user override, rejection immediately invalidates finalization and confirmation.
A bounded structured finding-ID subset identifies evidence-only concerns; prose
does not decide routing. Pure evidence rejection preserves candidate acceptance
and reruns complete finalization without code-fix or no-progress accounting.
Unchanged validation inventories do not prevent evidence rejection; insufficient
check evidence still requires replacement finalization under the same retry budget.
Mixed rejection resolves content through normal convergence before replacement
finalization. Recovery cannot omit, substitute, remove, or weaken established
checks or infrastructure entries, and always requires fresh terminal confirmation.
Ordinary non-rejection evidence reuse remains as specified above.

Malformed structured output has separate fixed protocol bounds. Plan authoring
allows one automatic correction at each draft-bound primary checkpoint. Plan
execution and polishing allow one at each bootstrap, validation-migration,
candidate-review, terminal-confirmation, or lazy checkpoint scope; polishing
also allows one for malformed Worker finalization output. Plan execution alone
allows up to two Worker finalization corrections, and the second is available
only for a wholly new bounded diagnostic batch. Repetition or further invalid
output pauses for explicit recovery. These limits prevent rejected provider
output from becoming an unbounded hidden retry loop and do not consume the
separate code-fix or semantic-evidence budgets.

Two automatic semantic retries per execution step or polishing run are durable
and separate from malformed-output and code-fix budgets. Pending retries survive
interruption or provider unavailability without recounting. Scope drift clears feedback without
restoring allowance. Exhaustion pauses specifically for rejected finalization
evidence; an explicit retry authorizes one additional attempt. Independent
recovery overrides bind the saved terminal fingerprint, including formatter
changes, and cannot revive invalidated evidence. Only validated bounded findings
and control metadata are retained.

Plan execution constructs both passing and failing persisted evidence through
one deterministic pipeline contract. The contract normalizes the Worker and
runner-trusted portions together, derives the aggregate status, and validates
the complete fingerprint-bound record before either finalization transition is
attempted.

If a planned change legitimately alters scripts, test discovery, validation
configuration, or the inventory, terminal confirmation must explicitly accept
that complete change. An evasive or unauthorized change is a finding.

Runner-trusted checks are a narrow exception for commands that an agent sandbox
cannot safely execute. Root and safe project catalogs use the same exact-vector
validation, merge root then project, deduplicate identical same-name definitions,
and reject conflicts. The merged catalog is bounded to 256 definitions and each
selection to 32 aliases. Project selections may use project-only aliases.
Vectors, identities, and fingerprints are frozen before agent work and reused
unchanged on resume; later project configuration edits retain the protected-input
guard. Profile implementations and sandbox policy remain runner-owned.
Declarations may request the closed scratch/cache, writable source-projection,
and pinned-HTTPS-artifact capability vocabulary owned by the trusted-validation
architecture. Parameters are frozen into command identities and snapshot
fingerprints. Version-4 snapshots carry the resolved per-command `timeoutMs` in
the trusted-configuration fingerprint and may grant `sourceProjection: true`.
Version 3 retains its frozen deadline but cannot acquire that new authority;
version 1 and version 2 preserve their original policy and evidence bindings
and use the deterministic 60-minute fallback. Resume never grants newly
configured capabilities or adopts a new deadline.

The public root/project setting is `trustedCommandTimeoutMs`, in milliseconds.
It accepts strict integers from `1` through `2147483647`, defaults to `3600000`
(60 minutes), and resolves project over root without CLI or MCP overrides. A
new run persists the resolved value once, so resumes and concurrent runs use
their own unchanged snapshots. For example, `"trustedCommandTimeoutMs":
7200000` selects two hours. Capability preparation remains limited to the
smaller of the resolved value and 10 seconds.

A valid but unavailable frozen request pauses durably as `environment_blocked`
before provider work, including at creation before any preflight evidence exists.
Resume retries the saved request after environment repair. Changing declarations
requires a new run; repository changes must not bypass or weaken required checks.
Scratch and cache capabilities provide per-execution transient storage; pinned
artifacts are acquired by the runner into durably owned private storage before
finalization command execution. Only complete SHA-256-verified files appear in
the fixed read-only dependency mount. Checks remain network-isolated. Acquisition
failures are resumable environment blockers, never check passes or permission to
change the declaration; retries acquire fresh files after cleanup. Preflight
checks storage and isolation without downloading. Capability inspection is not
check execution or validation evidence. Verification-only recovery of a consumed
commit or completed handoff remains available without those capabilities.

Source projection is configuration-frozen boolean authority, never an agent-
chosen path. After journaling the private allocation, the Git boundary
materializes the frozen HEAD plus the exact tracked and non-ignored untracked
content represented by the accepted staging-independent fingerprint. It ignores
staged blob content, ignored untracked files, and Git metadata. The isolated
executor mounts only that owned copy writable at the canonical project path;
original repository, index, state, task paths, credentials, and undeclared host
storage stay absent.
Projected build effects are disposable. Allocation identity and the original
repository snapshot are rechecked before launch and after process retirement;
stale source, substituted storage, external repository drift, or incomplete
cleanup cannot produce accepted evidence. The bounded result remains tied to
the source content fingerprint and accepted HEAD, exact command identity,
resolved authority, ordered-command and trusted-configuration fingerprints,
and validation-infrastructure binding.

Plan execution and polishing also discover exact-command capability needs and
environment blockers read-only during bootstrap or legacy validation migration.
Accepted active-role reports are preserved together; reconciliation cannot
discard a role's needs. Plan execution and polishing independently require a
boolean `sourceProjection` need in every report alongside scratch, cache,
artifacts, and unsupported needs. They can identify only the frozen exact
command: no report can choose a projection path or broader authority. Their
ordered migrations default historical reports to no projection without
reloading configuration or changing workflow, evidence, correction, or effect
state. Every capability report must identify an actual
scratch, cache, source-projection, artifact, or unsupported need. A reported
non-null command identity must match the frozen selected-command identity
exactly. Zero-need reports, substituted identities, and other invalid reports
receive bounded contract correction; a corrected empty report array leaves the
ordinary check agent-runnable rather than turning it into an unselected trusted
requirement.
Valid needs without trusted selection, sufficient frozen authority, runner
support, or actual availability pause before any writable checkpoint, with no
content or index mutation. Every writable entry and resume rechecks the saved
request. A sandbox limitation on an exactly delegated command is satisfied only
by successful runner inspection; another command's limitation remains a blocker.
Inspection never executes or attests the required check, changes authority, or
reloads configuration.

Before finalization, writable roles receive the exact
selected command text from the persisted run, including on continuation,
reconstruction, and correction. They defer established required-check execution
and attestation to `FINALIZE`, continue applicable content repairs and semantic
review, and never execute selected commands inside agent turns. Selected-command
sandbox limitations alone cannot block that work. The context is bounded and
does not repeat the complete inventory or expose unrelated configuration.

During `FINALIZE`, the runner executes only the exact persisted executable
and argument vector in its isolated service, retains bounded outcomes and safe
normalized failure classes/stages while discarding raw output, and rejects
repository or control-state mutation. Diagnostic fragments are revalidated
before entering existing check and generated-issue evidence, survive reload and
reach finding resolution without becoming validation authority. Applicable
safe fragments also survive in Runner-blocked pause evidence; signal termination
remains distinct from a nonzero exit. This mechanism does not broaden an agent
turn's permissions. Increasing the deadline cannot
fix sandbox incompatibility or restore historical discarded stdout/stderr. A check may
pass on the host yet fail closed in isolation with only a generic outcome and
bounded omission explanation when no supported safe detail is available;
the timeout must not be presented as a diagnostics remedy.

Execution and polishing validation infrastructure consists of files that own
commands, discovery, runners, configuration, or mandatory finalization guidance. Ordinary
source, individual tests, fixtures, and generated output merely consumed by
checks are excluded; ownership is semantic rather than inferred from filenames.
Both pipelines permit 256 entries per role field and 512 per merged, persisted,
or finalization field. Inventories are complete and never truncated; `requiredChecks` overflow has priority over infrastructure overflow.
Existing byte limits still apply. Legacy evidence in both pipelines migrates
under the lease without losing completed effects or resetting budgets.

## Failure and blocking behavior

A legitimate nonzero check result is a finalization failure and returns to
Worker correction. In plan execution, an explicit resume of an unchanged
environment-blocked resolution may repeat complete finalization when every
blocker is solely a runner-trusted failure with its matching generated issue.
Normalized diagnostics do not change that existing eligibility or budgets;
historical opaque results receive no synthesized detail. Mixed or agent-authored
failures remain on the ordinary resolution path.
This does not accept host evidence or enable automatic retries: another failure
returns to resolution and requires another explicit resume if blocked again.
Mode-specific terminal confirmation and correction accounting remain intact.
An external sandbox, process, service, IPC, loopback, or
permission limitation affecting nondelegated work is an environment blocker,
even when another command is selected for trusted execution. The trusted
executor's own environment constraints can still block `FINALIZE`. The workflow
preserves safe content and pauses at the precise resumable checkpoint; it does not weaken a
check or grant broader access to manufacture a pass.

Candidate-review and terminal-confirmation corrections are distinct, bounded,
and resumable without retaining rejected provider output. Correction and
dispute budgets are bounded. Exhaustion, repeated invalid
structured output, unsafe reconciliation, or a non-converging loop pauses
rather than accepting incomplete evidence.
An unexpected runner-owned finalization-state invariant retains the last valid
`FINALIZE` checkpoint with a bounded explicit retry instead of turning the run
into an opaque terminal failure.

Provider environment preparation is distinct from a repository-check failure.
Claude projections and scaffolding stay outside the validation tree while an
agent runs and are retired before the runner accepts its fingerprints or
executes trusted commands. Setup/cleanup uncertainty retains the precise
checkpoint and ownership record for safe reconciliation; it does not become a
finding asking the agent to delete protected files. Ignore rules and fingerprint
exclusions cannot hide pollution.

Preparation/cleanup failures expose a finite class and checkpoint. Trusted
validation continues to retain the exact command identity and bounded outcome,
including exit status, signal, and timeout, without storing raw diagnostics.
A successful environment preparation does not attest a check, and a check's
nonzero exit is still a finalization failure requiring correction.

## Commit and handoff gates

Finalization is staging-independent. Agent turns do not stage, inspect the
index as evidence, use an alternate index, or perform generic commit
preparation. Plan execution's constrained `COMMIT` effect alone stages the
accepted content, performs fixed staged hygiene, and creates the exact planned
commit. Polishing's runner-owned `HANDOFF` effect alone stages and verifies the
complete accepted change set without committing.

The content and validation fingerprints must remain unchanged from the
accepted gate through the effect. Recovery verifies a pending or possibly
completed effect before deciding what remains; it never reruns an ambiguous
commit or duplicates a completed handoff.

Provider availability waits preserve the exact validation/review checkpoint and
pending correction diagnostics. Safe partial content is reconciled and stale
approvals invalidated before scheduling; the same correction is not charged
again after retry or restart. A successful provider response resets availability
backoff before deterministic output validation. A normalized authentication-
required response instead retires the superseded episode before its distinct
operator pause. Neither path relaxes deterministic output validation or its
separate bounded correction budget.
