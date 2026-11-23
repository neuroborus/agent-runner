# Runner-Trusted Validation

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Selected commands and isolated execution

Every selected runner-trusted command must appear in each role's complete
bootstrap catalog with its actual applicability; selection alone does not
make it applicable to every step. Capability preparation uses the complete
catalog and both active roles' reports without executing checks. Normal,
correction and reconstruction finalization prompts reserve the complete selected
catalog, including commands assigned to later steps. Terminal confirmation also
receives that reservation list. Every established active runner-trusted command
must remain exactly once in the candidate inventory using its persisted exact
command text. A justified current-step amendment may add another selected
command without changing the frozen role inventories or later schedules; future
requirements are not added automatically. The Worker returns `NOT_RUN` for every
selected candidate entry, including newly proposed checks. An agent attestation
for a selected command, or `NOT_RUN` for an unselected command, is invalid.
After the Worker turn completes and repository changes are reconciled, the root
runs the exact persisted executable/argument vector only for selected commands
explicitly present in the resulting candidate inventory, directly without a
shell, and replaces the placeholder with bounded runner evidence. It retains no
process stdout or stderr and accepts no configuration-supplied environment values. The Linux
executor requires bubblewrap. Before agent work, the root resolves it only from
fixed system locations to a canonical absolute executable whose file and
ancestor directories are not writable by the runner identity. Project-relative
or project-writable `PATH` entries never participate, and resume and execution
reverify that pinned path. Its private network namespace contains minimal
read-only system mounts and either the read-only repository view or the
declared writable source projection, private runtime and temporary storage, a
hidden ambient home, and a finite non-credential environment.
Command-owned loopback listeners remain possible inside that namespace, but raw
host Unix daemon and control sockets are masked. A Docker daemon must be
rootless, and every service must run as part of the exact command inside the
same mount, network, and PID namespaces; it cannot acquire host mounts or
networking and is retired with the complete process tree. Remote network and
filesystem writes, hosting credentials, Git credential helpers, and ambient
authentication variables remain unavailable. The runner supervises the
complete process tree with a private PID namespace and outer process group.
Every completed, readiness-confirmed command gives remaining descendants one
bounded grace period to retire naturally regardless of exit code before bounded
TERM/KILL cleanup; timeout cleanup starts immediately. A one-byte signal from
inside the completed isolation profile distinguishes setup denial from a
nonzero validation-command exit
without retaining stderr or other native output. A repository snapshot
before and after every trusted command
rejects workspace, index, history/ref, remote-configuration, or Git-identity
mutation, and the complete validation-infrastructure fingerprint is recomputed
after trusted execution. Missing isolation, an unterminated process tree,
blocked, skipped, changed, substituted, non-allowlisted, unmatched, or
fingerprint-drifting commands fail closed. Agent and runner results form one
ordered evidence tuple bound to the same content, validation-infrastructure,
ordered-command, and trusted-configuration fingerprints. The executor runs
with the original frozen capabilities and bindings. Persisted selected-check
evidence requires executor `runner` and the exact frozen command identity;
unselected entries require agent evidence and gain no runner authority.
Execution remains outside agent turns and does not grant an agent loopback,
Docker, database, network, host temporary-directory, or another host-service
capability.
Increasing the deadline cannot repair sandbox incompatibility or recover the
discarded output. A full repository check can pass on the host while trusted
isolation fails closed with only a generic exit code; timeout configuration is
not a diagnostics or containment remedy.

## Receipt timing

Runner receipts append monotonic elapsed milliseconds for the admitted attempt,
including preparation, invocation, verified retirement, cleanup and safety checks;
see the [shared execution interval](../../../docs/ARCHITECTURE.md). The evidence
distinguishes pre-invocation blockage from an invoked executor, without asserting
payload admission. Availability preparation is never check evidence. Cancellation,
uncertain ownership/cleanup and safety failures publish no completed receipt.
The existing check evidence list retains timing through persistence/reload and
the terminal confirmation's exact validation tuple. No schema migration is
needed; authentic unmeasured receipts remain valid with timing unknown. Worker
placeholders stay `NOT_RUN`; finalization and terminal roles never estimate
Runner duration or rerun or reject evidence solely for missing legacy/controller
telemetry.
