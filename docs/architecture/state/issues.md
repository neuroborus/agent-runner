# Issue Storage and Publication

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Capability Boundary

The issue capability lives under `src/issues/` behind its public `index.js`,
which exposes `createIssueService()` and the pure `resolveIssueStorePath()`
location mapping. Its private service owns the deliberate-report action
lifecycle and the list, read, and revisioned update operations over the run
store's durable action primitives and narrow per-issue lease. Private contract,
location, and store modules own the issue document schema, the per-user store
location, descriptor-bound filesystem guards, and interrupted-publication
recovery. MCP and the `agent-run issues` CLI project its operations without
duplicating action wrappers or effects.

## Publication and Exact Retry

An unexpected-issue action keeps the existing tool namespace and canonical
argument binding. Its intent reserves the request selector and canonical
origin, store path and directory identity, issue ID, creation time, document
hash, and a private temporary name before publication. A saved selector maps an
exact retry, including one naming a project subdirectory, to its verified
canonical arguments without consulting a deleted origin. Bound pending
publications also retain their canonical origin for storage separation without
resolving it again; replacement or deletion cannot redirect recovery. The
temporary file is created exclusively with mode `0600`, its device, inode, and birth time are
bound in the intent before content is written, and it is synced and hard-linked to its final
name, which never replaces an existing file. The directory is synced and its
identity and private ownership are rechecked before the action records a
published phase, while the temporary link still proves ownership; it then
removes that link, verifies the published bytes, and persists the
`{ issueId, issuePath }` receipt before returning. Only the bound temporary
file is ever removed; an unbound or substituted entry is preserved and fails
with `ERR_ISSUE_REPORT_OWNERSHIP`. Recovery republishes
only in the reserved store with the reserved ID and bytes: a relocated or
replaced store directory fails with `ERR_ISSUE_STORE_CHANGED`, and an identity
collision or extra hard link fails without adoption. An exact retry returns the receipt, while key
reuse with different arguments fails. Historical completed receipts, including
repository-local `{ reportPath }` receipts, replay unchanged before any origin
inspection; an intent that
never reserved a local destination is rebound to the global store, and any
other incomplete local intent fails with
`ERR_ISSUE_REPORT_LEGACY_PUBLICATION` without touching its files.

## Mutation Coordination

Issue mutations are serialized by the state layer's same-host lease in the
store's private `.coordination/<issueId>/` directory, created with mode `0700`
through the descriptor-bound store and held after the action lease. Both
levels are opened without following links and used only through their
descriptors, and each level's parent is synced before the lease admits a
mutation; every store verification during the mutation also proves their
identities, so a replaced or linked directory fails with
`ERR_UNSAFE_ISSUE_STORE` before any destructive step. Because
it lives in the shared store, every writer to that store coordinates there,
whatever its state root; listing ignores the directory. Creation holds it from publication through its
receipt, so no update observes a half-published document; recovery then
compares only immutable report, origin, and creation fields, tolerating later
tracking updates. An `issues_update` action replays a completed receipt before
store resolution and binds the store path and identity in its intent; a moved,
replaced, or missing store fails with `ERR_ISSUE_STORE_CHANGED`. Under the
issue lease it checks the expected revision and hash, persists the next
document hash and update time in the intent, records that hash in the lease
directory's ledger for the next revision, and writes the previous bytes to a
private bound backup and the new bytes to a private synced temporary file. It
rechecks the exact document it read and the temporary file's bound identity,
isolation, and bytes immediately before atomically renaming it over the
document; the backup is removed only after the published identity and bytes
are verified and remains otherwise. Recovery syncs and reverifies the store before completing the
receipt when the current hash or that ledger entry matches its prepared hash,
reapplies identical bytes when the document is still at the expected revision,
and otherwise fails as stale. A later writer at the same revision overwrites the
ledger entry before replacing, so ledger entries prove which document each
published revision held. Only bound temporary and backup files are removed
after a failed replacement, and the backup only while the previous document is
still in place.
