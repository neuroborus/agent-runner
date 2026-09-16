# Validation And Review

Validation and semantic review are separate sources of evidence. Deterministic
checks prove executable repository properties; agents assess correctness,
scope, architecture, and edge cases. Neither substitutes for the other.

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
Declarations may request the closed scratch/cache and pinned-HTTPS-artifact
capability vocabulary owned by the trusted-validation architecture. Parameters
are frozen into command identities and version-2 snapshot fingerprints. Legacy
version-1 snapshots preserve their original restricted policy and evidence
bindings; resume never grants newly configured capabilities.

A valid but unavailable frozen request pauses durably as `environment_blocked`
before provider work, including at creation before any preflight evidence exists.
Resume retries the saved request after environment repair. Changing declarations
requires a new run; repository changes must not bypass or weaken required checks.
Declared scratch, cache, and artifact capabilities currently fail closed while
their implementations are unavailable. Capability inspection is not check
execution or validation evidence. Verification-only recovery of a consumed
commit or completed handoff remains available without those capabilities.

Before finalization, writable roles receive the exact
selected command text from the persisted run, including on continuation,
reconstruction, and correction. They defer established required-check execution
and attestation to `FINALIZE`, continue applicable content repairs and semantic
review, and never execute selected commands inside agent turns. Selected-command
sandbox limitations alone cannot block that work. The context is bounded and
does not repeat the complete inventory or expose unrelated configuration.

During `FINALIZE`, the runner executes only the exact persisted executable
and argument vector in its isolated service, retains bounded status rather than
native output, and rejects repository or control-state mutation. This mechanism
does not broaden an agent turn's permissions.

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
Worker correction. An external sandbox, process, service, IPC, loopback, or
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
