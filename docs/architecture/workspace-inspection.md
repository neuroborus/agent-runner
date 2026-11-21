# Workspace Inspection

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Capability Boundary

The filesystem-only workspace capability lives under `src/workspace/` behind
`createWorkspaceService` and `WorkspaceSafetyError` in its public `index.js`.
Private `paths.js`, `scope.js`, `controls.js` and `snapshot.js` own confinement,
inspection selection, filesystem control discovery and guarded capture;
`traversal.js` owns cancellation/progress checkpoints and `service.js` composes
inspection and mutation guards.

## Snapshot Proofs and Baselines

Private `proof.js` projects complete whole-directory snapshots into bounded
exact-path evidence plus hashes of the complete immutable remainder and link
resolutions. `snapshotProof` derives missing leaves only from complete captured
coverage and retains file/link ancestors as blockers. It refuses selected or
excluded snapshots as absence evidence. `assertSnapshotProof` permits only its
caller's exact journaled effect paths to differ, while preserving the remainder,
scope and link proof. Deferred new temporaries can be removed from the current
remainder only if the original hash proves their absence. These methods grant
no traversal, write or publication authority and leave capture unchanged.
`snapshotBaseline` projects a complete snapshot into a bounded durable baseline:
its scope (`workspacePath`, `outputPaths` and any `inspectionPaths`,
`inspectionFilesOnly` and `excludePaths`), both fingerprints, `entryCount` and
`entriesHash`, the ordered-entry digest shared with proofs through private
`digest.js`. It omits `entries` and `linkResolutions`, so protected control
trees cannot grow persisted state beyond its limits.
`outputBaseline` adds output partitions for writable consumers, accepting only
complete whole-directory snapshots like `snapshotProof`. `remainderCount` and
`remainderHash` digest every captured entry outside all `outputPaths` roots;
`outputs` holds one `{path, entry, descendantCount, descendantsHash}` record per
compacted, sorted output root over its captured strict descendants. Compacted
capture records no absent output beneath the workspace, so the projection
derives a missing `entry` only when the nearest captured ancestor inside the
workspace is a directory. File or link ancestors and uncaptured coverage are
blockers that fail closed. Derived records exist only in the projection; capture,
entries, `entryCount`, `entriesHash` and both fingerprints stay as captured.
Records are bounded by frozen output declarations rather than tree size.

## Lifecycle Selection

The runner's private `workspace.js` selects descriptor-owned workspace/lease
requirements before Git inspection and binds directory policies through this
capability. Authoring explicitly selects Git for commit plans or the directory
lifecycle for custom plans. Execution selects the same lifecycle explicitly.
Preliminary boundary discovery selects only the workspace policy; execution
parses declarations through a confined task-input capability after project
configuration and run overrides resolve, before Git inspection.
It is the directory inspection foundation for custom planning/execution, audit
and init. Custom authoring, execution and audit consume it; init publishes reviewed setup. Git snapshots remain Git-owned.
`inspect` accepts an existing `workspacePath`, external `stateRoot`, optional
`taskPath`, and arrays of `inputPaths`, `sourcePaths`, `outputPaths`,
`configurationPaths`, `artifactPaths` and `infrastructurePaths`. Relative paths
resolve from the workspace. Reads require existing paths; outputs, artifacts,
infrastructure and state may name missing destinations. Duplicate/descendant
read declarations collapse to their declared parent without granting writes.
Outputs must be proper workspace descendants disjoint from all protected
declarations and control trees. State is disjoint from workspace, task,
infrastructure, declared read trees and discovered controls. Inspection grants
no provider access, retrieval, publication, Git effect or write authority.

## Declarations and Selection

Optional `inspectionPaths` selects literal workspace-confined file or directory
roots, including missing paths; `[]` selects no ordinary source content. Omission
selects the whole workspace. Optional `excludePaths` prunes literal
workspace-relative subtrees; duplicate/descendant declarations collapse, dot-dot
components and absolute exclusions fail, and no glob expansion occurs. Both
declarations are normalized before recursive discovery and frozen with the
inspection. Selected roots become absolute; exclusions remain workspace-relative
for reconstruction. Real routing ancestors remain pinned. Selected leaf links
are captured only when their resolution stays in selected or protected trees.
Optional boolean `inspectionFilesOnly` requires explicit `inspectionPaths` and,
when true, restricts every selected root to a regular file, leaf link or missing
path. Directory replacements fail before descendant reads at admission, control
discovery, link resolution and capture, including after reconstruction. The
constraint remains frozen with the declarations and binds snapshot fingerprints
and unchanged checks; omission retains the existing directory-root behavior.

Excluded leaves and descendants receive no metadata/content reads or traversal.
Their routing ancestors must be real directories or missing, and exclusions
cannot hide exact selected roots, required input/source/configuration/task/
artifact/infrastructure declarations, authorized outputs, reserved control
components, discovered control boundaries or required link dependencies.
Controls in selected trees, their routing ancestors, explicit protected trees
and output roots retain discovery and protection. Excluded trees are opaque;
undiscovered controls inside them grant no authority. No selection grants reads,
outputs or state storage there, and state remains disjoint from the entire
workspace. Omitted declarations retain the previous whole-directory behavior.

## Controls and Link Confinement

Filesystem discovery protects `.git`, `.codex`, `.claude`, `.agents` and
`.claude.json`, including nested controls and enclosing repository controls for
the workspace and declared external paths. Discovery also inspects protected
control directories for nested Git pointers and their external metadata,
including dependencies reached through other metadata directories.
Bare Git layouts are recognized by `HEAD`, `objects` and `refs`; their entire
metadata directory is protected and cannot contain the workspace.
Bounded regular-file reads resolve Git `gitdir:` and `commondir` pointers to
their real metadata directories without executing Git, rejecting aliases before
normalizing pointer dot segments. Arbitrary ancestor home
directories grant no provider-storage reads; their existing provider controls
still exclude overlapping state storage, including resolved alias targets.
Canonical provider-control targets overlapping the workspace are protected
against output authority; unrelated external provider storage is not captured.
Ancestor provider aliases resolve component by component and reject writable
output or state dependencies, including hops erased by later dot segments.
At the workspace root, its descendants and enclosing-repository ancestors, a
symlinked `.codex`, `.claude`, `.agents` or `.claude.json` is an internal
provider-control alias resolved by the same component-wise resolver. Its
canonical target must be a real directory with real ancestors strictly inside
the link's parent, outside Git metadata, not containing the workspace and
disjoint from state storage. Discovery then protects both the link and that
target and traverses the target for nested controls; the alias grants no reads,
outputs or mutable roots. Escaping, parent-equal, dangling, cyclic, file,
special-file and Git-metadata targets fail with control-specific diagnostics,
and a symlinked `.git` remains rejected as a non-ordinary Git control. Full
`inspect` still rejects any alias among its control bindings, because those
bindings feed directory workflows and provider projections; only the
controls-only `inspectControls` query accepts them.
That query reserves every control-name component in exact infrastructure
destinations, including nested components whose parents do not yet exist.
Routing directories remain pinned by identity and mode, while links and files
retain full metadata checks. Unrelated sibling creation outside inspected trees
does not invalidate alias resolution; inspected trees retain their complete
listing and metadata race checks.
The state location's existing ancestors are also inspected for control overlap.
Git and shared metadata targets inside the workspace remain protected; unrelated
external state-ancestor metadata is traversed for nested Git pointers without
adding read or snapshot scope. This traversal preserves state-only scope through
pointer dependencies and terminates cycles.
Reserved output components stay
forbidden even before their control paths exist. Workspace roots cannot be
inside reserved control components, including outside Git repositories. All
declared ancestors must be real directories; aliases in declarations/ancestors,
multiply linked regular files, undecodable names and special files fail closed.
Snapshots hash link text without reading linked file bytes and confine
resolution to the declared tree or explicitly bound protected trees. Real
ancestors may connect those trees without granting reads of their other
children, supporting `.claude/skills` links to protected `.agents/skills`.
Unbound intermediate hops, escaping, dangling and cyclic links fail.
Absolute targets re-enter their selected root through the same component checks
before processing any suffix, preserving file-only constraints and root dependency evidence.
Resolution dependencies participate in snapshot
race checks; snapshots return sorted `linkResolutions` alongside entries so
output consumers can bind readable dependencies outside a selected subtree.
Omitted-scope entry and input fingerprints remain unchanged.
Links cannot cross writable boundaries in either direction, including
through intermediate resolution hops.

`snapshot({inspection, signal, onProgress})` rechecks pinned ancestors and control
bindings and captures the selected workspace roots plus protected declarations
and authorized outputs, pruning exclusions before descent or hashing. On the
current Linux runtime, pinned directory descriptors through `/proc/self/fd`
anchor enumeration and regular-file reads; unavailable descriptor access fails
closed. Handle/path metadata and directory listings are checked around reads
and again before completing capture, including missing-path ancestor bindings.
Workspace and protected-path identities remain pinned throughout capture.
Results contain sorted metadata and hashes, never file bytes. Content
fingerprints bind paths, kinds, modes, sizes and content; separate identity
fingerprints also bind inodes and file timestamps. Explicit scope declarations
participate in both fingerprints and the unchanged guard, even for an empty
selection; legacy omitted-scope fingerprint construction stays unchanged.
`inspect(declarations, {signal, onProgress})` and snapshot accept an optional
AbortSignal and awaited progress hook. Control descent, per-entry capture,
regular-file read chunks and final verification check cancellation, closing owned
handles on interruption without writing source content. Progress contains only
`phase` (`controls`, `capture` or `verify`) and an increasing `completed` operation
counter, emitted at phase changes and every 128 checkpoints. Hooks grant no
filesystem authority; cancellation preserves the signal's reason. These options
remain transient and never enter frozen declarations.
`snapshotInputs({paths, stateRoot})` captures only explicitly declared read trees
with the same confined, race-checked reads and ancestor bindings. It rejects
state overlap and grants no reads of unrelated workspace content. Supplemental
commit-authoring criteria and sources use this narrower capture while Git owns
the repository snapshot and mutation guards.
`assertUnchanged({before, after})` rejects content or identity drift; explicit
`allowOutputs: true` permits only declared outputs and newly required parent
directories, preserving unrelated files and all protected inputs. A compact
`before` baseline is compared against a complete `after` snapshot by
recomputing the same digest over its entries, the complete equality applied to
legacy full baselines. Compact baselines reject `allowOutputs` and malformed
counts, digests, fingerprints or retained link evidence. Output partitions, when
present, require well-formed counts and digests and records whose paths equal
`outputPaths`; they never grant output changes, which stay with complete
transient snapshots and the bound protected fingerprint. Filesystem
injection supports deterministic race tests without Git or providers.

## Capture and Mutation Guards

Directory lifecycle protected fingerprints exempt only declared outputs and
artifacts. A task root coinciding with or containing the workspace never exempts
other project content; runner-owned task artifacts must be declared explicitly.

## Confined Text Reads

`readFile({path, projectPath, optional, maxBytes})` confines text input reads to a real
regular file beneath the supplied root, reusing descriptor-anchored snapshot
reads with no-follow, nonblocking opens and read-race checks. Only an absent
optional file returns null; aliases and special files fail before content reads.
Optional `maxBytes` bounds the descriptor-anchored read, including growth races;
omission retains the existing safe-integer maximum.
