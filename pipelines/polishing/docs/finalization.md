# Polishing Finalization And Evidence Recovery

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

### Finalize

After mode-specific candidate convergence, run the target repository's complete
finalization procedure in a dedicated Worker turn in every policy mode. Reverify
the frozen guidance path and fingerprint first. When the frozen decision selects
no skill, derive the same complete gate from repository
instructions and project-defined checks; never skip validation. Execute required
formatting first and then any other generated output, but do not stage, unstage,
or commit. When selected guidance requests staging,
index-relative handoff inspection, an alternate-index workaround, or commit
preparation, defer staging and staged inspection to `HANDOFF`, omit prohibited
commit preparation, and complete the staging-independent content gate. Express
an applicable tracked-content check against `HEAD` or explicit trees. This
deferral is neither a skipped check nor a validation blocker. Report strict
`PASS`, `FAIL`, `SKILL_MISSING`, `SKILL_INVALID`, `BLOCKED`,
`VALIDATION_POLICY_BLOCKED`, or the narrowly
allowed product decision outcome. Finalization neither adds nor runs explicit
post-completion operator acceptance; `PASS` covers only the pipeline inventory,
and the summary lists that acceptance as pending without claiming success. This
never permits removing or weakening an established check.

Missing, escaping, invalid, or changed frozen guidance pauses without a retry
checkpoint and requires a new run; automatic guidance never switches or falls
back after pre-bootstrap selection. Guidance is reverified before bootstrap,
validation migration, finalization, every bounded correction, and resumed work.
After a writable turn, the runner rechecks guidance against the safe resulting
snapshot before reconciling output or charging a correction round. Drift
persists that snapshot, invalidates stale gate evidence, and consumes no budget,
except that a finding-resolution checkpoint retains its original baseline.
Skill-less `PASS`, `FAIL`, and `BLOCKED` results carry no skill path.
Finalization-generated content changes are permitted without invalidating the
already accepted semantic candidate. Compute the content fingerprint after the
procedure and bind the result to it. A passing result enters `CONFIRM`; it cannot
enter `HANDOFF` directly. A failure becomes blocking findings for Worker
resolution. Unavailable explicit guidance or a blocked finalization procedure
pauses.

Before evidence is fingerprinted, the runner inspects every candidate
validation-infrastructure path as an existing canonical regular repository file,
or the exact selected external guidance label through confined file inspection.
An invalid path uses the existing bounded read-only finalization correction.
Every non-availability result repeats the complete inventory actually used and
contains exactly one ordered result with bounded direct evidence for every
required check. Agent-executed checks must pass; omissions, skips, exclusions,
substitutions, replacements, or weakening are invalid output. `NOT_RUN` is
valid only for an exact selected runner-trusted command. After the Worker turn
is reconciled, the root executor replaces each such placeholder by running the
persisted executable/argument vector directly without a shell or expanding the
agent turn's capabilities. Other host-reported results and user attestations
are not trusted. The Worker must not weaken package scripts, test discovery,
test runners, validation configuration, the inventory, or its file set to
evade an environment blocker.

Each runner result retains only bounded status, exit/signal/timeout data,
command identity, and fixed evidence; raw process output is discarded. Every
completed, readiness-confirmed command gives remaining descendants one bounded
grace period to retire naturally regardless of exit code before bounded
TERM/KILL cleanup; timeout cleanup starts immediately. Before and after
execution, the shared root service rejects workspace, index, history, ref,
remote, or identity mutation and recomputes validation-infrastructure
fingerprints. Missing isolation, an unterminated process tree, a changed
binding, a non-allowlisted command, infrastructure drift, or mutation fails
closed. A bounded environment failure pauses at `FINALIZE`; resume reuses the
durable command snapshot. The accepted ordered evidence tuple binds both agent
and runner results to the same content, validation-infrastructure,
ordered-command, and trusted-configuration fingerprints.

When agent and runner results otherwise pass, the Runner also proves
staging-independent whitespace hygiene through the Git capability before
accepting `PASS`. The inspection is bound to the persisted controls and index
and to the computed finalization content fingerprint. It runs hook-free
`git diff --check` against `HEAD` for tracked content, skipped in an unborn
repository, and checks every non-ignored untracked regular file, plus every
indexed regular file when `HEAD` is unborn, with
`git diff --no-index --check` against `/dev/null`. The repository-relative
operand stays literal so repository whitespace configuration, attributes and
check-in conversion apply; a root path named exactly `-` is passed as `./-`
because Git reads a bare `-` as stdin. Allowed artifact paths are excluded;
directories, nested repositories and symlinks are left to the staged check. The
inspection writes neither the index nor objects. Snapshots before and after
must match every Git control, the content and the index; drift pauses as
`unsafe_git_state` with `ERR_POLISHING_HANDOFF_CONTAMINATED`. A hygiene failure
appends one runner-owned issue with the next free `F<n>` ID, command
`Runner staging-independent whitespace hygiene`, a fixed problem and bounded
evidence: an optional tracked-change line, up to 30 new-file paths and an
omitted-path count. It then takes the ordinary `FAIL` route to Worker
resolution and renewed mode-specific convergence. A persisted `FAIL` whose
checks all pass is valid only with that issue; agent `FAIL` output still
requires a failed check.

Finalization and terminal-confirmation requests carry the persisted
`finalizationGuidance` decision and explain Runner-owned additions:
`fingerprint`, `validationInfrastructureFingerprint`, `trustedCommandFingerprint`,
`trustedConfigurationFingerprint`, `validationChanged` and per-check `executor`,
`commandIdentity`, `exitCode`, `signal`, `timedOut`. These are not role output
fields; roles return only their closed schemas, with Worker check entries limited
to `checkId`, `command`, `status`, `evidence`.

When selection is `file` and its label is in the inventory, the existing workflow
owner computes `SHA256(JSON.stringify({infrastructure, finalizationFile}))`:
`infrastructure` is the repository digest excluding the selected label;
`finalizationFile` is the verified identity-bound selected-file fingerprint.
Legacy `skill` and fallback algorithms remain unchanged. A different raw
all-path digest alone is no evidence of drift. Roles independently review
content, complete checks, authorized inventory changes and exact content,
infrastructure, guidance, command and configuration bindings, rejecting genuine
mismatches and insufficient evidence. They never rerun reserved checks or manage
Runner CLI/admission. Fresh, continued, reconstructed, corrective and
evidence-recovery requests all preserve this contract without new hashing,
schemas or recovery authority.

Each bootstrap role discovers all known applicable checks, including available
supplemental validators. In finalization, the Worker preserves project-defined
first, final and relative-order constraints in the declared inventory and ordered
evidence; amendments position additions accordingly rather than automatically appending
them, retaining every established identity and exact command. Current-inventory
reordering never changes original discovery. Array order proves no physical
execution sequence: Worker runs agent-owned checks during `FINALIZE` and returns
reserved `NOT_RUN` entries; Runner subsequently executes their frozen vectors
and replaces those entries in inventory positions under existing unchanged-content
and infrastructure guards. No later Worker turn is required; `HANDOFF` retains
its separate fixed staged hygiene. The only exception is Runner's serial loop:
it awaits one selected entry at a time in inventory order, each attempt retires
before the next starts under unchanged bindings, and no stop persists partial
finalization evidence. Within one persisted record, entries whose Runner-owned
`executor` is `runner` therefore establish their relative physical order after
that `FINALIZE` turn's agent-owned work; agent-owned and legacy entries
establish no Runner order. A separately explicit physical sequencing
requirement remains binding and uses existing blocking outcomes if incompatible
with ownership/checkpoints, without new permissions or an invented product
decision. Terminal roles never reject evidence for order this guarantee
establishes or for missing telemetry. Insufficient proof that a mandatory
sequence was met is never approved: evidence-only rejection uses the bounded
recovery and [exhaustion pause](review.md#review-and-findings), while proven
uncorrectable violation keeps the
[policy stop](validation-history.md#historical-validation-noncompliance). Independent terminal
Reviewer confirmation and lazy terminal clean confirmation read the
actual selected guidance and mandatory references and assess the complete
resulting procedure, including additions and their positions, even when all
checks pass. The owning prompt instructions reach fresh, continued,
reconstructed, corrective and evidence-recovery requests. This semantic
obligation changes neither first-seen bootstrap union nor schemas, bindings or
budgets. It cannot guarantee model compliance or automatically repair historical
runs; existing evidence-only recovery can correct ordering without content changes.

Increasing the deadline cannot repair sandbox incompatibility or restore raw
stdout/stderr. A full repository check may pass on the host while trusted
isolation fails closed with only a generic exit code; the timeout is not a
diagnostics or containment workaround.

The shared service appends Runner-monotonic elapsed milliseconds for the admitted
attempt, including preparation, verified retirement, cleanup and safety checks;
see the [shared execution interval](../../../docs/ARCHITECTURE.md). Timing marks
pre-invocation blockage separately from executor invocation, which alone cannot
attest payload admission. Availability probes and uncertain/unsafe attempts
produce no completed-check timing evidence. Existing check evidence lists carry
the receipt unchanged through persistence and terminal confirmation. Legacy or
older-controller receipts remain timing-unknown without migration; roles keep
reserved placeholders `NOT_RUN`, never estimate Runner timing and never rerun
or reject evidence solely for absent telemetry.

`BLOCKED` is reserved for required validation that cannot execute because of an
external environment constraint. It carries bounded reason and evidence,
pauses as `environment_blocked`, and resumes at `FINALIZE`; an executable check
that reports a legitimate failure remains `FAIL`.

If deterministic normalization rejects the first Worker finalization result
for the current content fingerprint, persist the version-7 bounded diagnostic
and publish one `finalization-correction` activity without rejected content.
Recognized rejections identify the first violated field and source-defined
constraint, including status/issue/check consistency, inactive and unavailable
fields, complete ordered check identities and exact commands, selected trusted
`NOT_RUN` ownership, and bounded shape, text and evidence requirements. Fields
use fixed names and bounded list positions, never rejected IDs, values or keys.
Normalization preserves these diagnostics through correction feedback and
terminal errors; arbitrary exception prose is never parsed for a diagnosis.
Unknown diagnostic-like identities reduce to `result / semantic-contract`.
Reconstruct the complete request from durable inputs and ask the Worker for one
complete replacement with the same finalization schema in a fresh-session,
read-only turn. The correction may re-execute corrected staging-independent
checks needed for complete direct evidence, but it does not execute the
rejected command or staging-dependent validation and cannot modify repository
content, staging, history, refs, remotes, or Git identity. Interruption before
or during that turn preserves the pending attempt, reconciles it as read-only,
and resumes without another attempt or a required native session. A valid
corrected availability or product-decision result uses its existing route;
corrected `BLOCKED`, `PASS`, and `FAIL` results rejoin the existing environment,
fingerprint, trusted-validation, review, and handoff gates. A repeated invalid
result for the same content fails closed without retaining either rejected
result. Shared CLI/MCP pause evidence projects only recognized finalization
diagnostics from the latest rejected replacement, independently of the first
consumed correction record, and offers no resume action for this terminal
failure. Legacy valid diagnostic shapes remain loadable; reconstruction reduces
unknown identities before including them in a corrective request, without
renewing its allowance or reviving terminal history.
Content changes clear the consumed scope and permit one correction for
the new fingerprint. This attempt is independent of the bootstrap and
validation-migration correction ledger.

### Transient validation storage ownership

Common envelope version 9 records trusted storage allocation intent and verified
identity separately from process ownership. Version 10 adds the acquiring runner
identity and changes the runtime compatibility token. Leased migration preserves
version-9 allocation records without new resource effects. The root retires owned processes and
cleans recorded resources before resuming pipeline work or settling an operator
stop. Legacy envelopes migrate to null storage ownership without allocation or
provider activity. Only declared scratch/cache directories and a declared
writable source projection are writable through bindings owned by the trusted-
validation architecture. Projected build output is discarded; without that
authority required output must stay in scratch and outside the repository.

Cleanup uncertainty preserves the resource record and pauses finalization as
`environment_blocked` at `FINALIZE`; neither the check nor subsequent work is
accepted until ownership is verified and cleanup finishes. Interrupted mutable
cache contents and partial downloads are never reused. Pinned artifact requests
share this durable allocation lifecycle, including artifact-only commands. The
root journals verified directory ownership and the acquiring runner process
identity before downloading. Journal failures preserve a resumable ownership
blocker and the saved allocation. Recovery cannot delete its storage while that owner
is live or unverifiable without service-observed transport retirement. It exposes only
complete digest-verified files at `/run/agent-runner/dependencies`, read-only.
The exact check remains network-isolated; extraction or setup belongs to its
declared vector and must use declared scratch. Acquisition failures block
`FINALIZE` before command launch with bounded redacted evidence; repaired
environments retry the frozen request after cleanup. Status remains observational.

## Terminal Findings And Evidence Recovery

Read the [current contract](review.md#polishing-review-findings-and-clean-confirmation).
