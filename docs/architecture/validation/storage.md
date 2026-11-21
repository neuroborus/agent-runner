# Trusted Validation Execution Storage

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Durable resource ownership

Common run-envelope version 9 adds private `executionResource` ownership next to
`executionProcess`. Legacy envelopes normalize it to null and migrate through the
existing leased journal transition without filesystem allocation, provider work,
or changes to session/progress evidence. Status reads never allocate or clean
resources. The resource record carries a random execution ID, host, command
identity, private root device/inode, and allocation phase; the allocated phase
also records the execution directory device/inode. Common run-envelope version
10 adds the `acquiring` phase, which journals the runner PID and boot/start
identity before transport activity. Version-9 state and journal records retain
their original closed allocation contract and load without writes; leased
migration preserves ownership, command identities, and progress without new
resource effects. The runtime compatibility token changes with this version.
Verified retirement restores `allocated` before launch or cleanup; only those
exact identity-preserving transitions are accepted. Acquisition journal failures
retain ownership and report the bounded resumable ownership blocker. Resource ownership is never publicly projected.

## Allocation and storage isolation

The trusted executor creates a runner-owned mode-0700 parent under the runner's
temporary directory, disjoint from project, task, Git metadata, and runner state.
A journaled allocation intent precedes exclusive per-execution directory creation;
verified identity is journaled before downloading, materializing source,
exposing mounts, or launching a process. The execution directory owns its
dependency and optional source subdirectories as well as scratch/cache; the
acquisition phase records transport ownership separately from command process
registration.
Directory creation is synchronized before publishing allocation identity, and
declared storage entries are synchronized before acquisition or launch. Cleanup
synchronizes removal before clearing journaled ownership, including retries
after removal.
Descriptor-anchored directory operations and identity checks reject symlink
substitution. Only declared scratch/cache subdirectories and the exact declared
source projection are mounted writable.
No mutable cache is reused across executions, including after interruption.

## Retirement and cleanup recovery

Command completion, failure, timeout, and cancellation retire descendants before
confined cleanup and repository mutation checks. Resume and operator-stop recovery
retire any recorded process before cleaning saved resources, even when interruption
preceded process registration. Cleanup uses the recorded root, not a newly selected
temporary directory. A missing child can be cleared idempotently. An existing child
without a journaled verified identity, a replaced directory/root, or uncertain
process ownership retains evidence and ownership for explicit recovery; the runner
never guesses which directory to remove. Checkpoint settlement and releasing
ownership remain closed until cleanup succeeds. After an operator restores the
recorded directory or removes an independently verified orphan, resume retries
cleanup before any new work. Acquisition failures return bounded, redacted
`BLOCKED` check evidence without launching the command. They and resource cleanup
uncertainty preserve an `environment_blocked` FINALIZE checkpoint and never attest the check. Cancellation
preserves the abort outcome after safe cleanup; uncertain retirement retains
ownership and blocks settlement.
