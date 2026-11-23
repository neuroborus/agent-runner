# Finalization and Validation Evidence

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Evidence acceptance

Finalization is fail closed. A `PASS` contains exactly one ordered result with
bounded direct evidence for every persisted required check; omitted, skipped,
substituted, replaced, or weakened checks are invalid output. The runner hashes
the identified package scripts, test-discovery and runner files, skill guidance,
and validation configuration rather than trusting an agent-supplied hash.
Changing that inventory, its file set, or its fingerprint is provisional until
the read-only terminal Reviewer in independent and combined modes, or the lazy
read-only terminal clean confirmation, accepts that the task or current plan
step authorizes the complete change for
the same content fingerprint. The confirming turn receives both the established
and candidate tuples, so acceptance cannot depend on a prior native session.
Both pipelines invalidate rejected evidence and use their independently owned
bounded semantic recovery routes. Commands and repository-relative infrastructure
paths are validated and compared without rewriting interior whitespace.
Host-reported results and user attestations are outside this trust boundary.
Plan execution builds both passing and failing persisted finalization evidence
through one deterministic pipeline contract before attempting advancement.
That contract normalizes the Worker and runner portions together, derives the
aggregate status, validates ordered executor provenance, and binds the result
to the content, validation-infrastructure, ordered-command, and trusted-
configuration fingerprints. An unexpected persisted-state invariant therefore
leaves the prior valid `FINALIZE` checkpoint available for the bounded public
retry instead of turning the run into an opaque terminal failure.

## Phase ownership

Plan execution gives each preparation phase one owner. Independent semantic
review, or lazy check/fix and candidate clean confirmation, converges first.
Implementation, finding-resolution, and lazy check/fix turns do not invoke project finalization
or perform generic commit preparation. The dedicated finalization turn follows
every substantive instruction in the pre-bootstrap frozen guidance. A selected
skill remains in the established validation-infrastructure inventory and must
match its frozen path and fingerprint through finalization and terminal
confirmation. Guidance repair or drift starts a new run rather than consuming
correction or review budgets. The finalization turn runs the writable
repository formatter first, treats its output as the content under finalization, then runs
generation, the non-mutating repository gate, Git whitespace checks, and
staging-independent content review. Bootstrap,
validation-migration, and finalization inventories deterministically reject
index mutation, staged or index-relative inspection, implicit
worktree-versus-index assertions, alternate-index workarounds, and commit
preparation; applicable content checks use `HEAD` or explicit trees.
Established checks are input only to `FINALIZE`.
After finalization and the distinct mode-specific terminal confirmation bind
the same content and validation-infrastructure fingerprints, the constrained local-commit executor
alone runs `git add -A`, fixed unstaged-clean, staged-diff whitespace, and
nonempty-diff hygiene, and the subject-only commit with the validated plan
subject. The contract is
identical for Codex and Claude and does not broaden ordinary Worker access to
Git metadata.

Polishing uses the same ownership rule without requesting `local-commit`.
Worker polishing, finalization, finding-resolution, and lazy or combined check/fix turns
are content-only, including when selected finalization guidance normally
requests staging. Its independently persisted pre-bootstrap decision supplies
only the frozen skill path or fallback to bootstrap and validation migration.
Any selected skill remains in established infrastructure and must retain its
path and fingerprint through correction, finalization, confirmation, and
resume; repair or drift requires a new run without consuming fix or review
rounds. Bootstrap, validation-migration, and finalization inventories
use the same deterministic staging-independence policy as plan execution;
applicable tracked content checks use `HEAD` or explicit trees, and established
checks are input only to `FINALIZE`. Once candidate convergence has completed
and finalization plus the distinct mode-specific terminal confirmation bind the
same staging-independent content and validation-infrastructure fingerprints,
the pipeline persists `HANDOFF`. Before accepting `PASS`, `FINALIZE` also runs
the Git capability's read-only `inspectContentHygiene`. It checks tracked
content against `HEAD` and each non-ignored untracked regular file, or each
indexed one in an unborn repository, against `/dev/null` with literal operands.
Before and after snapshots bind every control, the content and the index. A
failure becomes a runner-owned finalization issue on the ordinary repair path.
The root Git boundary then accepts either an unchanged pre-effect state or an
already-complete recovered effect, repeats that hygiene inspection and runs
`git add -A` only for the former, and verifies unchanged content and Git
controls, a nonempty complete staged set, no unstaged or non-ignored untracked
remnants, and staged whitespace hygiene before the pipeline can enter `DONE`.
A pre-add or staged whitespace rejection makes the run terminal `FAILED` with
`handoff_whitespace_rejected`. The pipeline keeps any index effect and never
resets, restages or reopens a role checkpoint.

## Reserved commands

Both pipelines project only exact command text from persisted
`trustedValidation.commands` into implementation or polishing, lazy or combined
`CHECK_AND_FIX`, and finding-resolution prompts. The existing snapshot bounds
limit the projection; an empty selection produces an empty array. Complete,
continued, reconstructed, and correction requests all carry it without
configuration reloads, provider settings, executable vectors, or a repeated
validation inventory. Established required-check execution and attestation
remain exclusive to `FINALIZE`. Selected trusted commands never execute inside
agent turns, and their agent-sandbox limitations do not prevent applicable
repairs and semantic review. Bootstrap inventory-reporting and finalization
`NOT_RUN` instructions stay in their existing contexts.

A selected runner-trusted command is the only exception to agent-side check
execution during finalization. The runner-derived bootstrap inventory must
contain its exact configured command.

## Opaque failure recovery

Plan execution can retry these opaque failures through an explicit resume from
an `environment_blocked` finding-resolution pause. Pipeline policy recognizes
only a complete persisted match between failed runner checks and their generated
issues, with no agent failure or other unresolved work. After input, repository,
and failure-fingerprint revalidation, one write-ahead transition clears terminal
evidence and enters complete `FINALIZE`, retaining candidate acceptance and
correction accounting. A repeated failure rejoins resolution and does not retry
automatically. The trusted executor's authority, output-retention policy, and
mode-specific confirmation gates remain unchanged; the
[execution specification](../../../pipelines/plan-execution/docs/SPEC.md) owns eligibility.

## Canonical inventory entries

Before plan execution or polishing accepts a producing role's bootstrap or
legacy validation-migration inventory, and before either pipeline fingerprints
finalization evidence, the root Git or directory boundary verifies repository
validation entries are existing regular files whose canonical repository-relative
paths exactly match the proposed paths. The configuration capability inspects
the exact selected finalization-file label against its frozen root; external
labels retain their distinct `finalization://` namespace. Missing files,
directories, symlinks, and paths traversing a symlink are field-specific
violations; the runner does not follow or silently canonicalize them. Plan
execution collects every inspectable violation from the candidate into the
owning bounded bootstrap or finalization diagnostic batch, and a repeated
invalid result fails closed. The deterministic aggregate is therefore derived
only from independently accepted canonical role evidence.
Plan execution and polishing additionally reject each staging-dependent
required command with bounded field-specific diagnostics before accepting that
producing result; plan execution batches all such independently detectable
violations, and the same policy rejects a finalization candidate inventory
without delegating index ownership to an ordinary Worker turn.

Read [Git stored-content and staging verification](../git-conversion.md) before
changing compatible-domain proof, hashing isolation, hook suppression or
verification-only recovery at commit and handoff boundaries.
