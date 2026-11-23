# Operator Guidance

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

`docs/OPERATOR_GUIDE.md` is the installed, canonical CLI/MCP operating procedure.
It distinguishes expected pauses, genuine unexpected defects, and stable
project lessons. Operators follow current actions and resume resumable work
without taking it over. Valid dirty work from a genuinely non-resumable run may
enter polishing after ownership ends and inputs are reconciled, preserving
contamination safeguards and the uncommitted outcome.

The guidance capability lives under `src/guidance/` behind its public `index.js`.
Private content, contract, file, selection, and service modules own composition, configuration
selection, confined access, and durable replacement. Its factory is deliberately
exported from `src/index.js`; transports consume the same capability rather
than duplicating policy. No pipeline depends on it.

`createGuidanceService().read({ projectPath, projectConfigurationPath? })` loads
the common guide from the installed runner and uses public configuration,
workspace and Git services to resolve `<artifactRoot>/agent-runner/rules.md` from the
selected infrastructure root, or the target when no configuration is selected.
Ordinary directories need no Git prerequisite. Git discovery keeps the worktree
target, including explicit integrated and external configuration selected from
subdirectories. Relative external selectors resolve from the originally supplied
directory before worktree rebasing; selection rechecks and durable action identities
retain that exact path. Integrated selectors retain worktree-relative recovery.
Only an explicit configuration bound to the supplied directory
retains that scope, with the enclosing worktree supplying the canonical exclusion key.
Explicit external selection uses the configuration capability's target-bound root
and never merges integrated guidance or discovers sibling infrastructure. Its result
contains canonical project/local/configuration paths, complete `commonContent`
and `localContent`, `combinedContent`, and `localHash`. Rendering separates the
documents and states that local additions cannot weaken common safety or
product contracts. Missing local content is an empty string with a null hash;
an existing document, including an empty one, has a SHA-256 hash. A positively
verified absent, untracked local guide needs no ignore rule for reads, including
before init in an unconfigured Git checkout. The existing selectors and resolved
metadata remain unchanged; absence never triggers discovery of another placement.
Reading creates neither local artifacts nor external state.

Both documents have a 64 KiB UTF-8 byte limit. Reads and replacements reject
invalid encoding, unsafe control characters, and recognizable credential or
provider-transcript formats without echoing or partially redacting content.
Operators remain responsible for excluding sensitive material that cannot be
recognized deterministically. Existing integrated guides, edit/update destinations
and temporary files in a Git worktree must be ignored and untracked. External paths
use exact target-bound confinement without target Git inspection or writes.
All paths must be disjoint from project configuration
and protected control paths. The workspace capability's `inspectControls` reuses
control discovery along the exact target/destination ancestry, including Git
pointers, shared metadata and canonical ancestor provider alias targets containing
selected destinations. Resolved internal provider-control alias targets are
protected like the links themselves. Control-discovery failures use their own
controls diagnostic under the same `ERR_UNSAFE_GUIDANCE_PATH` code, while a
destination inside any control or resolved target still fails as an unsafe
guidance path. The query traverses discovered protected control trees and their
metadata dependencies, including nested Git pointers, without traversing unrelated
project content. Metadata reached only through state ancestors also protects
selected destinations; this query grants no snapshot reads. Missing
destinations receive the same safety inspection. Symlinks, hard links,
non-regular files, and unsafe ancestors fail closed. The private selection boundary
allows the read-only ignore exception only when both workspace and Git inspections
prove absence; tracked paths reject even when missing from the worktree. Reads,
including init's identity-bearing read, repeat selection and verify pinned
directories after the document read. Any returned existing content requires
strict ignore validation even if it disappears before reinspection. Edit/update
selection and every publication recheck retain strict destination validation.

The `read` and `readWithIdentity` entry points preserve trusted inspection
categories through guidance error normalization with optional finite
`readFailure` metadata: `inspection_unavailable`, `workspace_changed`,
`unsafe_path` or `evidence_capacity`. Existing normalized error codes remain
unchanged. Only recognized workspace/configuration errors and direct native
read causes under the selection/file-helper control/path wrapper are classified;
returned pinned-directory verification retains private read provenance without
changing normalized codes. Init also consumes that finite `readFailure` metadata
when verification normalizes to `ERR_GUIDANCE_STORAGE`; the storage code alone
grants no classification. Descriptor cleanup and storage/recovery cause chains
are not classified or searched. Unknown native codes and corruption remain
unclassified. Edit/update and publication errors gain no read
classification. Init consumes this metadata only at scoped inspection boundaries,
retaining pending-effect and ownership guards before any resume. Metadata alone
grants no continuation or effect authority.

The public `update` method accepts the same selectors plus complete
`localContent`, nullable `expectedHash`, and `idempotencyKey`. It validates the
external-state boundary before intent or lease writes, rejecting state and
project trees that contain one another. It binds the key to
canonical arguments and a content hash, and reserves the destination and a hash
of resolved configuration. Versioned selection evidence also pins the infrastructure
base, target exclusion key and existing real directory ancestry; newly prepared
publication ancestors are persisted before temporary-file writes. State storage
must be disjoint from the target, enclosing exclusion tree and infrastructure.
The existing action store accepts the narrow
`guidance_update` kind. Context and receipts contain paths, hashes, publication
phases, and filesystem identity, never document bodies. The state service's
`withGuidanceLease` holds the canonical-worktree lease with an opaque operation
owner, excluding mutating execution and other guidance writers across processes.
External publication also holds an infrastructure-root lease unless the target
lease already encloses that root. Overlapping infrastructure selections from
different targets therefore cannot publish concurrently; both leases are checked
before publication and released together.
A contender receives a conflict and may retry its same incomplete intent after
ownership is released.

Filesystem access is relative to pinned directory descriptors using
`/proc/self/fd` or `/dev/fd`; unavailable descriptor access fails closed.
Directory identities and lexical confinement are rechecked around effects so
ancestor replacement cannot redirect reads, writes, publication, or cleanup.
Atomic rename publishes an owner-only, synchronized temporary file in the
destination directory; integrated Git temporary paths must also be ignored. Publication
rechecks configuration, path safety, execution ownership, the expected hash,
and inspected file identities.

An intent records reserved, writing, prepared, and published phases. Temporary
inode provenance is persisted before writing, and complete file identity before
rename. Recovery removes a proven partial temporary write or recognizes its
own renamed inode. It never adopts another writer's identical bytes or
overwrites an intervening edit. An unproven temporary file left before
provenance was recorded is neither adopted nor deleted; retry reserves a fresh
name. Changed configuration or substituted bound ancestors cannot redirect
incomplete publication, including after restart. Legacy integrated intents retain
their original worktree-relative arguments, destination and configuration hash,
including for configuration selectors retried from Git subdirectories.
Compatibility lookup applies only to binding-free legacy actions and grants no
external authority. Current actions retain their exact selector identity. A durable
published record completes its receipt without replaying the effect. Completed
retries return the recorded bounded receipt (`projectPath`, `localPath`,
`localHash`, `updated`) without reapplying the old hash comparison or reloading
configuration. Receipts describe their operation, not the current document.

The CLI dispatches `guidance` and `guidance edit` directly to this capability
with project/configuration selectors; it never constructs a pipeline runner.
The capability's `edit` method reads and pins the complete original selection,
opens an owner-only temporary document outside the project, and validates the
entire result after the editor closes. It uses the same confined file access
and shared writer, retaining the original destination and configuration hash
through the publication boundary. Even unchanged content must pass current
path, hash, configuration, and execution-ownership checks. A missing document
left unchanged remains absent, with a null-hash no-op receipt; explicit empty
replacement still creates an empty document. Temporary copies are removed
through their pinned parent directory, without following substituted links.

`src/editor.js` owns shared shell-free command parsing, `$VISUAL`/`$EDITOR`
selection, launch fallback, and exit/signal outcomes. Only an unavailable or
unparseable editor command permits fallback. Guidance rejects a nonzero or
signalled close and never publishes that edit. Clarification retains its
existing policy: any launched editor close consumes its one-shot authorization,
even after a nonzero exit or signal. Authorization, document safety, and
publication remain in their owning capabilities. MCP never opens an editor.

Local guidance supplies instructions only to the supervisor. Ordinary pipeline
prompts, run state and resume configuration do not include it. Init retains and
reviews proposed local content as setup data, including its guidance publication
intent; that content grants no role instructions or permissions. Guidance never constructs a pipeline run,
changes ignore rules, replaces the common guide, mutates Git control state,
or performs finalization or commit work.
