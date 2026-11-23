# Durable Lease Bindings

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Canonical Scope and Owner Records

Canonical-worktree leases live under
`worktrees/<sha256(canonical-worktree-path)>/` in that external root. The hash
keeps filesystem-safe bounded keys while the owner record contains only the
run ID, an opaque token, process ID, hostname, acquisition time, and nullable
process identity. Version-2 lease records pin Linux boot identity and process
start ticks when available. A live reused PID is a replaced owner, not proof
that the recorded execution survives. Foreign-host, legacy, identity-free, and
otherwise unverifiable owners remain conservative exclusion barriers. Legacy
records are read without rewriting them; new acquisitions publish the current
lease format. New acquisitions pin the canonical scope in an immutable
`scope.json` beside the lease. The existing mutation boundary serializes scope
inspection and admission across keys; parent/child scopes cannot both acquire
exclusive ownership. A different overlapping key treats even dead lease or
reclaiming records as barriers until exact-key recovery reconciles them. Legacy
Git records retain exact-key exclusion without rewriting their owner format.
Scope records and key directories may remain after release. Ownership uses
`.lease`; a pending stop also retains an interrupted `.lease-reclaiming`
reservation until reconciliation permits its release.

## Atomic Lease Publication

Run, canonical-worktree, reclaiming, and MCP action leases share one durable
no-replace publication primitive. It writes and syncs the complete JSON record
to an isolated in-directory temporary file, atomically links that inode at the
lease path only when the path is absent, removes the temporary link, and syncs
the directory before acquisition returns. A lock-free reader therefore treats
an unpublished lease as absent and parses only a complete record. If it meets
the bounded internal link between publication and cleanup, including after an
interrupted publisher, it removes only the matching same-directory temporary
link to restore the isolated final file. Bounded retries cover replacement
publication between inspection and opening; each read still requires an
isolated regular file, and unrecognized or persistent hard links remain unsafe.
Exclusive contention, dead-owner recovery, and release all use the published
record and continue to verify its opaque owner token. A current same-host run
or worktree lease with a complete boot/PID/start identity is reclaimable
immediately only when that exact owner is dead or replaced. Acquisition time is
neither a delay nor ownership proof. Legacy, identity-free, foreign-host, live,
invalid, and otherwise unverifiable records remain exclusion barriers.

## Fixed Correctness Guards

These state retry counts are fixed correctness guards rather than workflow
budgets. Managed-state reads make at most five attempts across an atomic
replacement; lease acquisition, including reclaim-marker and owner
reconciliation, makes at most five passes. Runner release of either an
execution or canonical-worktree lease makes at most five stop-aware attempts;
exhaustion leaves stop reconciliation pending. Generated run IDs try at most
ten candidates. None of these loops
waits for user work or makes an external service more available, so exposing
their counts as configuration would weaken the persistence proof without
creating a useful operator control.

## Execution and Recovery

Every mutating run or resume holds one atomic per-run execution lease. Plan
execution and polishing also hold one atomic lease for the canonical Git
worktree throughout workflow execution and runner-authorized clarification
writes, preventing independently identified runs from mutating the same
worktree concurrently. Status and public activity reads acquire neither lease.
A competing owner is rejected. A current same-host lease is recoverable
immediately only when its complete boot/PID/start identity proves the exact
owner dead or replaced; the reclaim marker and mutation boundary recheck that
identity and the opaque token before atomic replacement. Acquisition age does
not delay recovery and never proves that ownership ended. Legacy,
identity-free, foreign-host, live, invalid, and unverifiable records remain
non-reclaimable. Release verifies the opaque owner token before removing a
lease. Pipeline-declared run artifacts are
atomically replaced beneath the run directory, with absolute paths, traversal,
reserved state files, and symlink escapes rejected. Managed state and lease
paths must be isolated regular files rather than symbolic or hard links.
