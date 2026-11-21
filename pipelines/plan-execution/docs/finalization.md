# Candidate Convergence and Finalization

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Candidate convergence and phase ownership

Semantic candidate convergence precedes the terminal gate. In independent
mode, `REVIEW` examines the complete current step without running or attesting
finalization; every finding is resolved, withdrawn, arbitrated, or explicitly
overridden before advancement. In lazy mode, writable `CHECK_AND_FIX` passes
alternate with read-only candidate `CLEAN_CONFIRM` turns until one unchanged
clean pass accepts the candidate fingerprint. Candidate turns cannot provide
finalization, terminal-confirmation, or commit evidence.

Run the active step's complete project finalization procedure in a dedicated
Worker turn for every policy mode only after candidate convergence. Follow
every substantive instruction in the applicable project guidance, including
required checks, project-required formatting or generation, hygiene, and
staging-independent review of the exact content.

The finalization turn should execute the validation procedure and report its
result. It should not perform unrelated discretionary fixes in the same turn.
When guidance includes generic commit preparation, defer staging,
staged/index-relative inspection, alternate-index workarounds, staged handoff,
and commit-message drafting to `COMMIT`. Every finalization inventory remains
staging-independent and expresses an applicable content check against `HEAD` or
explicit trees. This phase-owned deferral is neither a validation blocker nor a
skipped required check and must not prevent `PASS`.

Commit and custom finalization neither add nor run explicit post-completion
operator acceptance. `PASS` covers only the pipeline inventory, and the summary
lists that acceptance as pending without claiming success. This never permits
removing or weakening an established check.

Every non-availability result carries the complete inventory actually used and
exactly one ordered result for each required check. `PASS` requires every result
to be `PASS` after the runner replaces the exact selected trusted-command
[placeholders](trusted-validation.md); every other omission, `NOT_RUN`, skip, exclusion,
substitution, replacement, or weakening is invalid structured output. Evidence is bounded and direct;
external host results and user attestations do not satisfy the gate.

## Finalization evidence and outcomes

Before either the passing or failing finalization transition is attempted, one
pipeline-owned deterministic contract constructs and validates the exact
persisted evidence record from the normalized Worker result and bounded
runner-trusted results. It derives the aggregate status, normalizes every issue
and ordered check with its executor provenance, and binds the complete record
to the current content and validation fingerprints. Agent or runner evidence is
not accepted merely because its producing boundary returned it.

Persisted finalization carries the runner-selected `step` and exact ordered
check results. Terminal confirmation records `validationTupleFingerprint`, a
canonical digest of that complete finalization evidence, in addition to its
content fingerprint. Step or tuple mismatches fail closed, including on resume.
Confirmation receives the complete schedule and explicitly evaluates shared
infrastructure changes against future requirements. Frozen command identities,
vectors, and command/configuration fingerprints remain unchanged.

Finalization and confirmation requests also carry the persisted
`finalizationGuidance` decision. Shared instructions explain that Runner adds
`step`, `fingerprint`, `validationInfrastructureFingerprint`,
`trustedCommandFingerprint`, `trustedConfigurationFingerprint`, `validationChanged`
and per-check `executor`, `commandIdentity`, `exitCode`, `signal`, `timedOut`;
Runner binds terminal confirmation with `validationTupleFingerprint`.
Roles return only the closed output schemas, never these persisted additions.
Worker checks still have exactly `checkId`, `command`, `status`, `evidence`.

When selection is `file` and its label is in the inventory, the existing workflow
fingerprint owner computes `SHA256(JSON.stringify({infrastructure, finalizationFile}))`:
`infrastructure` is the repository digest excluding the selected label;
`finalizationFile` is the verified identity-bound selected-file fingerprint.
Legacy `skill` and fallback algorithms remain unchanged. A different raw
all-path digest alone cannot justify evidence rejection. Content, complete
ordered checks, authorized inventory changes and exact content, infrastructure,
guidance, command and configuration bindings still require independent semantic
review; genuine mismatches and insufficient evidence remain blocking. Roles
neither rerun reserved checks nor manage Runner CLI/admission. The same contract
is delivered in fresh, continued, reconstructed, corrective and evidence-recovery
requests without changing hashing, schemas or recovery authority.

If that validated record or the runner-owned transition still encounters the
unexpected `ERR_INVALID_PLAN_EXECUTION_STATE` invariant, retain the last valid
`FINALIZE` checkpoint and persist `finalization_transition_invalid` with the
fixed `ERR_FINALIZATION_TRANSITION_INVALID` code and `FINALIZE` resume state.
CLI status, MCP status, and MCP wait expose the same bounded explanation,
evidence, and explicit null retry. The diagnostic never retains the rejected
finalization record, provider output, prompts, transcripts, runner-trusted
process output, or detached-process logs. Resume reconstructs and reruns the
bounded finalization checkpoint instead of trusting the rejected transition.

The Worker must not change package scripts, test discovery, test runners,
validation configuration, or the inventory merely to evade an environment
blocker. A change required by the current planned commit remains possible, but
the finalization result records the proposed inventory and current
infrastructure fingerprint for terminal confirmation.

Before invocation, the runner verifies the frozen selected skill and does not
invoke the Worker when it is missing, invalid, or changed. The Worker reports
the same conditions if they arise inside finalization. Either outcome pauses
non-resumably and requires a new run after repair; automatic selection never
switches guidance late. A safe structured result is one of `PASS`, `FAIL`,
`SKILL_MISSING`, `SKILL_INVALID`, `BLOCKED`, `VALIDATION_POLICY_BLOCKED`, or the narrowly permitted
`PRODUCT_DECISION_REQUIRED`. `FAIL` supplies stable `F`-prefixed issue IDs for
the current procedure output. Guided results identify the frozen
guidance label in `skillPath`; skill-less `PASS`, `FAIL`, and `BLOCKED`
results carry no path. A blocked procedure retains resumable environment
recovery; unavailable frozen guidance requires a new run.

`BLOCKED` is reserved for a required check that cannot execute because of an
external environment constraint and carries bounded reason and evidence. It
pauses with `environment_blocked` and resumes at `FINALIZE`; it is not
`finalization_cannot_pass` and does not become a code failure. A legitimate
check failure remains `FAIL`.

The finalization procedure may legitimately modify files when the project itself requires this, for example formatting or generated output.

Therefore:

1. run finalization;
2. let project-required modifications finish;
3. compute the content fingerprint afterward;
4. associate the finalization result with that fingerprint.

If finalization fails, enter `RESOLVE_FINDINGS` with the reported validation
failures. In lazy mode those failures must be fixed rather than disputed, and
stagnation never invokes an Arbiter. A fix returns through candidate convergence
before finalization runs again.

## Fingerprint invalidation and reuse

Any later content-changing repair invalidates candidate, finalization, and
terminal-confirmation evidence. Formatting inside a newly entered `FINALIZE`
turn instead establishes the content fingerprint that finalization and terminal
confirmation must share.

An ordinary terminal finding without validation-evidence rejection clears the
candidate and terminal-confirmation attestations,
but a successful finalization record remains provisionally reusable while its
finalized content and validation-infrastructure fingerprints stay current. A
declared `FIX` is not evidence of a repository mutation. After independent or
lazy candidate convergence, the runner recomputes both fingerprints and enters
`CONFIRM` directly only when they still match the retained record; otherwise it
clears that record and re-enters `FINALIZE`. Actual content or infrastructure
changes, provider correction-scope drift, content-changing interruption
reconciliation, and advancement to the next commit step always invalidate the
record. A fresh successful `CONFIRM` remains mandatory immediately before every
`COMMIT`.

## Validation-evidence rejection and recovery

Terminal `validationChange: REJECTED` has a separate recovery route shared by
both terminal roles. First honor the existing whole-result override gate for
all findings at the exact terminal content fingerprint. Otherwise immediately
invalidate finalization and confirmation evidence, including mixed rejections.
The required `finalizationFindingIds` array is a unique subset of at most 32
reported finding IDs identifying evidence-only concerns requiring no repository
edit. It must be empty outside a rejected terminal result; mixed concerns must
be separate findings. Candidate-review schemas do not carry this field, and
routing never classifies prose.
Both terminal response schemas omit the provider-unsupported `uniqueItems`
keyword. Deterministic Reviewer and Worker terminal normalizers enforce
uniqueness, bounds, membership, and the rejected-result restriction unchanged.
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
same resulting content and validation fingerprints before `COMMIT`.

Pipeline state version 16 expands inventory capacities to 256 per role and 512
for aggregate evidence. Its leased version-15 migration preserves accepted
64/128 inventories, finalization and review evidence, counters, terminal history,
and consumed commit authorization without replaying effects or reloading
configuration. Per-item and structured-output byte limits were unchanged by
that migration; a count-valid result can still exceed the structured-result byte ceiling.

Pipeline state version 15 adds `finalizationRecovery`, containing consumed
`attempts`, explicit `additionalAttempts`, `required` and `pending` flags, and
nullable bounded `feedback`. Feedback retains only normalized findings, their
evidence-only ID subset, the terminal content fingerprint, and the current
established-infrastructure fingerprint. It never retains a rejected finalization
record, provider output, or transcript. The version-14 migration initializes
empty metadata without inferring lost rejection output, moving the workflow,
changing persisted mode, or replaying completed or consumed commit effects.

Two automatic semantic retries are available per step, independently of
malformed-output and code-fix budgets. Before invocation, persist the consumed
attempt and pending marker. Interruption, provider unavailability, and external
validation blockage resume that pending attempt without recounting it. Content
or infrastructure scope drift discards stale feedback without replenishing the
step allowance. When operator-stop reconciliation adopts changed content, it
retires pending recovery before returning through candidate convergence,
retains the consumed step allowance and replacement-finalization requirement,
and durably reserves the next attempt before replacement invocation.
Content repair still returns through candidate convergence;
formatting within finalization retains its usual permissions and fingerprint
rules. Accepted replacement finalization clears pending recovery and feedback,
while the consumed allowance remains until the step ends.
A blocking product decision retires the pending attempt and its feedback before
returning through plan compatibility and implementation; it does not restore
consumed allowance or remove the replacement-finalization requirement.

Exhaustion pauses as `finalization_evidence_rejected`, with `FINALIZE` as the
resume checkpoint, bounded actionable CLI/MCP evidence, and an explicit null
retry granting exactly one additional attempt. Independent-mode overrides use
the saved terminal content fingerprint, which may differ from candidate
approval after formatting. Partial overrides leave other feedback blocking;
resolving all recovery feedback authorizes one replacement attempt and still
requires complete finalization and fresh confirmation. Lazy mode exposes no
finding overrides. No retry grants commit authority.

## Structured-output correction

If deterministic normalization rejects a Worker finalization result, collect
all independently detectable violations from that candidate where practical,
including every staging-dependent required command. Persist the version-8
bounded diagnostic batch and publish one redacted `finalization-correction`
activity without rejected content. Reconstruct the complete request from
durable inputs and ask the Worker for a complete replacement with the same
finalization schema in a fresh-session, read-only turn. The correction may
re-execute corrected staging-independent checks needed for complete direct
evidence, but it does not execute a rejected command or staging-dependent
validation and cannot modify repository content, staging, history, refs,
remotes, or Git identity.

Allow at most two such attempts for the current step and request content
fingerprint. The first diagnostic batch authorizes attempt `1`; a correction
that produces a wholly new batch may authorize attempt `2`. Any repeated
diagnostic, any batch mixing repeated and new diagnostics, or another invalid
result after attempt `2` fails closed. Resolved versus fallback guidance is
durable request-reconstruction metadata and does not create a separate budget.
A later content change starts a new fingerprint scope. Interruption before or
during an attempt preserves its pending ledger entry, reconciles it as
read-only, and resumes that same attempt without replay, recounting, or a
required native session. A valid corrected `BLOCKED` result uses
`environment_blocked`; corrected `PASS` and `FAIL` results rejoin the existing
fingerprint, trusted-validation, review, and commit paths unchanged. Rejected
values, commands, paths, provider output, and transcripts are never persisted
or published. This bounded ledger is independent of bootstrap and validation-
migration correction ledgers.

Finalization normalization identifies root/object and exact-field-set failures,
closed status values, each inapplicable field, ordered check completeness and
identity, exact commands, reserved `NOT_RUN` rules, bounded evidence, issues and
status consistency at their owning validators. Paths use schema field names and
zero-based trusted positions, never proposed IDs, commands, values or exception
prose. Independent field/check violations share a batch capped at 512 diagnostics;
invalid prerequisite inventories suppress dependent check comparisons. Worker
`PASS` may contain reserved placeholders, which Runner replaces before persisted
acceptance. Custom criterion failures retain their existing empty-inventory semantics.
The same bounded first diagnostic appears in terminal CLI/MCP failure evidence;
it grants no resume action. Provider failures lacking field information retain
`result` / `semantic-contract`. Historical unknown fields stay unknown, and the
existing ledger and persisted evidence shapes require no migration.

Before any finalization candidate, including `BLOCKED`, is fingerprinted,
trusted, or reviewed, inspect every validation-infrastructure entry through the
root Git boundary. Each entry must exist as a regular file and its canonical
repository-relative path must exactly equal the proposed value. Missing files,
directories, symlinks, symlink traversal, and narrative per-turn values enter
the same bounded redacted finalization-correction path; they never become a
candidate fingerprint or Reviewer finding.

## Runner-trusted checks

Read the [current contract](#candidate-convergence-and-finalization).
