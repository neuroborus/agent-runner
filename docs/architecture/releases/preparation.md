# Exact candidate preparation

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

The same update capability exposes `prepare({ operationId, version })`; both
fields are exact, bounded selections, not storage/source/role authority. The
official identity gate and development-managed exclusion precede mutation.
State-owned `update_prepare` actions persist the UUID, original arguments,
selection intent, exact metadata/integrity, storage identities, phases and owned
process proof. The existing recoverable action lease serializes each operation.
Completed receipts are reusable only while the pinned candidate still verifies.
A current version is a successful no-op. These actions do not create a run or
change any pipeline's compatibility or execution authority.
Preparation context version 2 records downloaded and installed versions separately
after their respective verification boundaries. Version-1 intents upgrade only
under their action lease; completed historical receipts retain their exact shape.

Default storage is private `updates/` under the user runtime root, disjoint from
the application, controls and authoritative state. Each of at most three fresh
attempts has an exclusive directory and persisted device/inode/owner identity.
Shell-free npm vectors select `name@exact-version` at the approved registry,
disable scripts/retries and bind anonymous settings/cache to owned storage.
The runtime-owned archive parser is shared with release tooling: actual SHA-512,
canonical complete manifest, resource bytes, paths and modes must agree before
offline installation from a retained read-only archive descriptor. Installed
metadata, manifest, dependency/resource closure and Node/configuration/state
contracts are verified again, then standard startup materializes and pins the
candidate's immutable payload.

Native commands use existing owned-process supervision plus bubblewrap with a
read-only filesystem and only the descriptor-bound attempt writable. Offline
installation and smoke have no network; the selected archive and smoke payload
are mounted read-only through retained descriptors. Private smoke settings/state
stay outside the payload. CLI help and MCP initialize/list-tools/transport-EOF
shutdown must complete before recording `validated`; no live provider, client
registration, target project or global link is involved. Output is capped at
two MiB and each native command has a 120-second launch-to-retirement deadline.
Process ownership is persisted before payload release, and children are awaited
before identity-checked smoke teardown. Unsupported containment fails closed.

Recovery inspects only the recorded owner/namespace and positively associated
session/token members; unavailable identity remains blocking and no recorded PID
is signaled. After owner retirement, a reused session number alone cannot
associate new members; token or verified ancestry evidence is required.
A fully installed interrupted attempt is reverified rather than
reinstalled. Partial/failed attempts remain quarantined, with bounded fresh
attempts and no deletion of unproved storage. A lost creation receipt or
substituted path blocks adoption. Validation/permission/network failures retain
the previous usable payload; no native effect overwrites it. Public receipts
contain only bounded IDs, versions, outcomes and redacted blockers. Preparation
changes no selector, restarts no client and migrates/resumes no settings or run.
