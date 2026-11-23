# Interrupted Turns and One-Shot Effects

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## One-Shot Effect Verification

Interrupted one-shot effects are also different. In particular, a
`local-commit` turn is never replayed; control returns to the runner for pending
authorization and Git-state verification. Backend policy, profile, provider,
or turn rejection before the isolated executor may record
`commitExecutor: "not_started"`; the derived `effectStarted: false` proof
permits authorization renewal only after Git verifies that the effect did not
occur. It never makes the consumed authorization replayable.

## Durable Invocation and Reconciliation

Immediately before every provider invocation, the runner appends and syncs a
complete `turn-started` transition whose next state contains the bounded active
role and pipeline phase. The active turn remains durable while the provider is
blocked and through repository or one-shot-effect reconciliation, then a
second write-ahead transition clears it. If the process stops first, the stale
activity remains without a live execution owner, even while its lease record
awaits stale recovery. A resumed owner
reconstructs the request from durable pipeline state, replaces ordinary stale
activity when it starts the reconstructed turn, and clears a one-shot commit
activity only after Git verification deterministically resolves the consumed
authorization. Native sessions, polling, model-token heartbeats, and daemons
are not part of this correctness path.

Before an ordinary interrupted turn is reconstructed, the runner revalidates
the canonical project and task directories and the owning pipeline revalidates
every durable task, context, plan, and accepted clarification input. The root
Git boundary then compares the persisted snapshot with the current repository.
Read-only turns still require an unchanged workspace and index. An interrupted
polishing Worker may retain content drift only for a phase that originally had
workspace-write authority; any index drift is rejected. Plan execution retains
its owning pipeline's one-shot commit reconciliation rules. `HEAD`, branch and
detached state, local refs, remotes, Git identity, canonical root, and allowed
runner paths must remain unchanged. The pipeline advances its baseline only
after those checks, invalidates its fingerprint-bound gate evidence when
content changed, and charges interrupted correction work once.
The reconstructed request uses the complete recovery prompt in a fresh native
session, and its `turn-started` event replaces the stale marker before normal
post-turn reconciliation clears it. If a correction transition was already
persisted before process loss, recovery clears its retained marker after the
same input and Git checks and continues from the advanced checkpoint without
replaying or recounting the correction. Consumed one-shot commit turns remain
on their verification-only path and are never reconstructed or replayed.
