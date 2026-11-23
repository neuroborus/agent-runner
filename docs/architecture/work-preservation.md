# Unfinished-work Preservation

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Capture and Restoration

Unfinished-work preservation is a separate Git/state capability consumed by
execution replacement preparation. `capturePreservation` requires run and worktree leases at a
reconciled checkpoint. The state journal publishes an intent bound to the exact
run, revision and inspected snapshot before storage allocation. Git's
`captureChanges` reuses guarded source inspection and immutable baseline reads
to capture baseline/current bytes, deletions, executable modes and unfollowed
link targets for changed paths. Payloads and manifests remain in confined
external run storage under reserved `.preservation-*` names. State reads back
every blob and pins directory, manifest and blob identities before publishing
capture completion. Interrupted attempts remain retained and are never adopted
as verified payloads.

`restorePreservation` journals the exact authorized paths, accepted current
snapshot, restoration plan and identities of prepared files and their parents
before destructive effects. Git's `prepareRestoration` and `applyRestoration`
require selected paths to match their saved baseline or current content and their
current HEAD baseline to match the saved baseline. Later child commits on other
paths remain intact. Recovery verifies unrelated content, index, history, refs,
remotes, identity, repository/control identities and surviving parent directories,
including those created during restoration. Confined parent descriptors,
exclusive temporaries and atomic replacement prevent following aliases or
adopting substituted writes. Explicitly selected file or link ancestors hide
descendants without following links and are removed before descendants are
created. Unselected aliases remain forbidden. Selected directory identities are
pinned even when they have no saved children. Only empty directories may be
removed for checked file/directory or link/directory replacements; uninspected
children survive.
Each restoration blob read rechecks the journal-bound capture record's identity
and hash, ownership of the capture directory and stable manifest evidence,
including after prepared-file publication and before replacement. Completion
revalidates that capture authority. Final saved-blob reads precede the last
repository/control, ancestor and destination checks; destination content is
inspected through its pinned parent immediately before deletion or replacement.
Prepared and applied writes reconcile without replaying completed operations.
`reconcilePreservation` can settle only an existing restoration intent during
operator-stop recovery, under the same run/worktree leases and byte/control
guards. It returns no receipt for an unstarted operation and cannot start
capture or grant new restoration authority.
Recovery syncs the verified surviving parent before accepting an already-applied
write, completing durability even when interruption followed rename or unlink.
Temporary creation has its own journaled intent and parent bindings. Before
identity publication, recovery accepts only an empty regular file or the exact
saved link target; regular bytes are written only after identity publication.
Missing parents have a separate creation intent and a durable identity binding
before descendant work. Recovery rejects an existing parent whose creation
was interrupted before identity publication rather than adopting it.
Interrupted writes resume only on that inode with a saved-byte prefix. A ready
record binds the complete bytes and mode before atomic replacement.
Cancellation and transient `executionResource` cleanup never dispose of saved
work; no deletion API is exposed.
