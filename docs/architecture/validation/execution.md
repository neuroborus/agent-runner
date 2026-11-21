# Trusted Command Execution

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Capability boundary

The trusted-validation capability lives under `src/trusted-validation/` behind
its public `index.js`. The index exposes only the contracts consumed by the
root runtime and capability tests; private service and execution modules keep
snapshot validation, exact command vectors, sandbox policy, bounded evidence, and
repository mutation guards within the capability. Trusted validation owns
exposure, storage, environment, and authorization policy and passes an ordered
mount program to the platform boundary, which owns launcher discovery and
verification and renders the fixed Linux isolation profile.

## Exact invocation and sandbox

The finalization agent returns `NOT_RUN` only for those selected entries; after
the agent turn reconciles, the root executor replaces each placeholder by
running the exact persisted executable/argument vector directly without a
shell. On Linux it requires bubblewrap and runs with a private network
namespace. The trusted sandbox selects `native-sandbox-provider` ownership;
the service and exact-command executor forward that mode to the owned-process
launcher so it probes the complete nested isolation shape. The trusted sandbox
explicitly creates its own user namespace, matching the nested probe rather than
relying on Bubblewrap's host-dependent implicit user-namespace selection. Executions whose
sandbox does not select a mode retain ordinary ownership. The trusted command's
isolation profile and process-containment requirements remain unchanged.
Before agent work, the root resolves bubblewrap only from fixed
system locations to a canonical absolute executable whose file and ancestor
directories are not writable by the runner identity. Project-relative or
project-writable `PATH` entries never participate, and resume and execution
reverify the pinned path. The namespace contains minimal read-only system mounts
and either the read-only repository view or the declared writable source
projection, private temporary storage, a hidden ambient home, private runtime
storage, and a finite non-credential environment. Isolated loopback
listeners remain available inside the command namespace, but raw host Unix
daemon and control sockets are masked.
A Docker daemon must be rootless, and every service must be command-owned inside
the same mount, network, and PID namespaces, so it cannot gain host mounts or
networking and is retired with the complete process tree. Remote network and
filesystem writes, hosting credentials, Git credential helpers, and ambient
authentication variables are unavailable. A private PID namespace and an outer
process group give every completed, readiness-confirmed command one fixed
one-second grace period for remaining descendants to retire naturally
regardless of exit code, then provide bounded TERM/KILL retirement when the
group remains active.
Timeout cleanup begins immediately. A one-byte readiness signal emitted inside
the completed isolation profile
distinguishes setup denial from an executed check failure without exposing
native output. The runner retains no stdout or stderr and records only bounded
status, exit/signal/timeout data, command identity, and fixed evidence.
The selected workspace snapshot before and after each command rejects mutation.
Directory checks use filesystem snapshots and exact read-only declared mounts,
including external references and controls, without invoking Git. They reject
Git source projection rather than granting repository or copy authority.
Normal and recovery cleanup rediscover current directory controls before
deleting owned storage. Changed pointers into an allocation or unverifiable
confinement retain both the allocation and its ownership record.
Preparation, execution and subsequent boundary-check errors preserve that
retention status so the live runner keeps its private lease handles for a
same-instance cleanup retry before any new work.
Persisted allocation ownership also preserves the run handle when configuration
drift replaces the cleanup error with a safety pause. Saved configuration and
workspace blockers reconcile owned execution and storage before returning;
restoring controls permits cleanup but never replays the blocked checkpoint.
Git snapshots reject workspace, index,
history/ref, remote-configuration, or identity mutation, and the complete
validation-infrastructure fingerprint is recomputed after trusted execution.
Missing isolation, an unterminated process tree, skipped, changed,
non-allowlisted, substituted, unmatched, or fingerprint-drifting checks fail
closed. The final evidence tuple binds agent and runner results to the same
content, validation-infrastructure, ordered-command, and trusted-configuration
fingerprints. This service does not broaden any agent turn's sandbox and
introduces no daemon or shell DSL.

## Deadline and diagnostic limits

The deadline changes only timeout behavior. It cannot make an incompatible
sandbox succeed or recover diagnostics discarded by the output-retention
boundary. Consequently, a full repository check may pass on the host yet fail
closed in trusted isolation with only a generic nonzero exit code; increasing
`trustedCommandTimeoutMs` neither explains nor fixes that difference.
