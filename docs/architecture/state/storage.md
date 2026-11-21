# External State Storage

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Capability Boundary

The state capability lives under `src/state/` behind its public `index.js`.
The index exposes only the run-store and runtime contracts used outside the
capability; its private service composes confined file operations, the
write-ahead journal, durable actions, execution leases, and state validation.

## Preservation References

Common envelope version 23 adds `preservationRecords`: at most 1,024 compact
references to immutable external capture/restoration records. Each reference
binds an operation UUID to an exact record UUID, SHA-256 and file identity.
Only state-owned preservation transitions may append or replace one reference;
they preserve pipeline state and all other authority. Records, manifests and
payload bytes stay outside bounded state JSON. Legacy absence normalizes to an
empty list, and the ordinary leased runtime migration persists that absence
without inventing preservation authority or rewriting historical events.
Version-22 preparation recovery settles and clears custody under its issued
envelope before the ordinary migration; its certificate and custody history
remain unchanged.
Execution's version-29 eligibility remains disabled.

## Locations and Actions

The root runtime persists runs under `$XDG_STATE_HOME/agent-runner/`, falling
back to `~/.local/state/agent-runner/`. A run is addressed by an opaque ID and
stored beneath `runs/<run-id>/`. Preflight requires the canonical state tree
to be disjoint from both the project and task trees: neither may contain the
other.

MCP action intents and receipts live under `actions/<hashed-key>/` in the same
external root. The opaque key itself is not persisted. Action records are
atomically replaced and protected by a same-host process lease; they never live
inside the target or task directory. Read-only `readAction` accepts exact
arguments or a synchronous resolver over frozen saved context; both forms
require the same tool and canonical argument hash before returning the record.
