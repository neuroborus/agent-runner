# Validation And Review

Validation and semantic review are separate sources of evidence. Deterministic
checks prove executable repository properties; agents assess correctness,
scope, architecture, and edge cases. Neither substitutes for the other.

## Bootstrap inventory

Before writable work, plan execution and polishing establish the complete
staging-independent validation inventory and the repository files that control
it. Independent mode combines separately accepted Worker and Reviewer
inventories. Lazy mode accepts one complete Worker inventory under the same
deterministic rules. Reconciliation and arbitration may resolve summaries, but
they cannot add, select, or remove checks.

Commands, paths, capacity limits, and selected runner-trusted commands are
validated before acceptance. Validation-infrastructure paths must identify
canonical regular files. The runner fingerprints those files instead of
trusting an agent-provided digest. Resume uses the persisted inventory and
trusted-command snapshot rather than reloading mutable configuration.

## Finalization and semantic review

Plan execution implements a step, runs its dedicated full finalization turn,
and then applies the mode-specific review gate. Polishing follows the same
shape for its complete change set. Finalization follows applicable repository
guidance, performs required formatting or generation, and executes every
established check without omission or substitution. A project-required content
change is fingerprinted after it finishes.

In independent mode, the Reviewer checks the complete current result and the
finalization evidence. All findings remain blocking until fixed, withdrawn,
arbitrated, or explicitly overridden for the exact reviewed fingerprint. A
content-changing resolution invalidates the old evidence and requires complete
finalization and review again.

In lazy mode, successful finalization enters a writable check-and-fix pass. Any
change invalidates the evidence and returns through complete finalization. An
unchanged pass requires a separate read-only clean confirmation. Only a clean
result over unchanged fingerprints advances; findings return directly to the
next check-and-fix pass.

## Evidence and fingerprints

Accepted finalization records one ordered result for every required check and
binds it to the staging-independent content, validation-infrastructure,
ordered-command, and trusted-configuration fingerprints. Skipped, weakened,
replaced, unmatched, or stale evidence fails closed. Host attestations and user
claims do not satisfy the gate.

If a planned change legitimately alters scripts, test discovery, validation
configuration, or the inventory, the review gate must explicitly accept that
complete change. An evasive or unauthorized change is a finding.

Runner-trusted checks are a narrow exception for commands that an agent sandbox
cannot safely execute. The runner executes only the exact persisted executable
and argument vector in its isolated service, retains bounded status rather than
native output, and rejects repository or control-state mutation. This mechanism
does not broaden an agent turn's permissions.

## Failure and blocking behavior

A legitimate nonzero check result is a finalization failure and returns to
Worker correction. An external sandbox, process, service, IPC, loopback, or
permission limitation is an environment blocker. The workflow preserves safe
content and pauses at the precise resumable checkpoint; it does not weaken a
check or grant broader access to manufacture a pass.

Correction and dispute budgets are bounded. Exhaustion, repeated invalid
structured output, unsafe reconciliation, or a non-converging loop pauses
rather than accepting incomplete evidence.

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
