# Git Inspection and Measurement

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Capability Boundary

The Git capability lives under `src/git/` behind its public `index.js`. The
small index exposes only the service factory, the read-only snapshot-change
normalizer, the shared safety error, and the Git-owned `isolateGitEnvironment`
rule; its private service composes command execution, content and snapshot
inspection, change measurement, complete source selection, exact source
materialization, commit verification, and polishing handoff modules without
exposing their implementation contracts to root consumers. The isolation rule
removes `EMAIL` and every case-insensitive `GIT_*` name and disables terminal
prompts. Snapshot identity queries and both provider local-commit executors
share it, so identity availability, fingerprints, commit authorization and
verification follow the configured identity that the executor actually uses.
Other Git queries keep stripping only repository redirection, and check-in
hashing keeps its existing dedicated isolation unchanged. Legacy evidence
captured under ambient identity or configuration-source overrides fails closed
through the existing identity guards.

Git-content observation never invokes Git inside a content-selected nested
directory. The command boundary disables submodule recursion, and observational
status/diff commands ignore submodule worktrees. Independently, literal HEAD
and index metadata reject gitlinks, including unchanged, deleted, ignored,
index-hidden and allowed paths; an explicit measurement/source baseline is
checked as well. Suppressing submodule inspection cannot establish cleanliness.
Metadata-only checks reject `.git` markers and bare `HEAD`/`objects`/`refs`
layouts in selected source ancestors and directory candidates. Ignored untracked
trees remain pruned by Git. Descriptor-anchored directory probes never interpret
nested configuration or follow Git pointers; handle/path identity and metadata
are rechecked after content reads. A missing marker grants no later execution
authority. Substitution races fail with `ERR_GIT_SNAPSHOT_RACE`.

Gitlinks and embedded repositories fail closed with bounded
`ERR_UNSUPPORTED_GIT_PATH` diagnostics in snapshots, content/path fingerprints,
measurement and source projection/selection. Their rejection also blocks
post-turn acceptance, preservation, commit verification and polishing handoff;
it grants no cleanup, recovery or Git authority. Ordinary file/directory
replacements, unfollowed leaf links, immutable object reads and staging-independent
content hashes retain their supported behavior. Supported snapshot, selection
and measurement shapes and fingerprint construction remain unchanged, so no
durable migration is needed. Historical gitlink measurements, completed
provenance and consumed effects remain historical evidence; they cannot approve
a currently unsupported workspace or authorize replay.

## Complete Source Selection

`git.selectSources({projectPath, expectedSelectionFingerprint?, signal?})` resolves an
existing worktree and enumerates complete current sources independently of the
changed-path snapshot. `trackedPaths` is the sorted union of the literal HEAD
tree and index entries, retaining staged-deletion names and ignored tracked
files. `untrackedPaths` adds only non-ignored untracked files. Git's
`ls-files --others --exclude-standard` prunes ignored untracked trees; Node does
not recursively enumerate source directories. HEAD tree enumeration disables
replacement objects. Strict UTF-8 decoding preserves literal names, including
leading U+FEFF. Unchanged, assume-unchanged and skip-worktree files are selected
and read from the working tree by subsequent workspace capture, never from
staged blobs.

The immutable result includes canonical `projectPath`, `head`, the existing Git
`indexFingerprint`, relative tracked/untracked/deleted path lists and an
`inspection` declaration containing absolute `inspectionPaths` together with
`inspectionFilesOnly: true`. Consumers pass this complete declaration to
workspace inspection; file paths alone lose the leaf constraint. Missing tracked
files and missing tracked ancestors remain explicit missing inspection roots. The
`selectionFingerprint` binds these declarations and provenance, not file bytes
or content approval. Selection checks membership/provenance and file kinds
twice; callers reselect with the saved fingerprint around confined capture and
on reconstruction to reject membership, deletion or index/HEAD drift with
`ERR_GIT_SOURCE_SELECTION_CHANGED`. Workspace capture separately owns content,
identity, routing/control bindings and link resolution; a frozen file list alone
cannot detect newly appearing untracked sources.

Leaf symlinks remain links and grant no target reads at selection. Routing
aliases, special files, file/directory replacements, unresolved index entries,
gitlinks and embedded repositories fail closed rather than becoming recursive
inspection roots. Git snapshots and measurement also reject gitlinks and
embedded repository candidates. Selection neither
initializes Git nor writes source, index, refs, remotes or identity, and grants
no provider, staging or commit authority. Ordinary-directory consumers remain
Git-independent. Cancellation interrupts path classification and Git commands;
selection waits for child closure, including all concurrent index reads.
Audit activates this selector through its descriptor-owned source settings.

## Change Measurement

`measureChanges({projectPath, baseHead, expectedContentFingerprint})` measures
the final worktree against the caller-verified immutable step-start commit
(or null for an unborn baseline). Existing staging-independent source inspection
discovers changed paths and verifies the candidate fingerprint before and after
measurement. Only discovered change candidates and index-hidden paths are read;
the latter retain the existing content checks. Each changed path is counted
once, including new non-ignored files, regardless of partial staging or
index-only bytes. Replacement refs cannot reinterpret the baseline. Guarded
reads supply raw baseline and worktree bytes to deterministic shortest-edit
line counting using Myers' algorithm, without temporary files, external diff
helpers or text conversion.
LF terminates a line; raw bytes, CR and missing final newlines remain significant.
Text additions and deletions sum to `changedLines`; a NUL in either side's first
8,000 bytes marks a binary path, reported separately in `binaryPaths` without
invented line counts. Symlinks contribute their target text without following
it. Gitlinks and embedded repositories reject measurement with
`ERR_UNSUPPORTED_GIT_PATH`; `gitlinkPaths` remains in the result shape as an empty
array for supported new measurements. Saved nonempty historical measurements
retain their meaning. The sorted `changedPaths` bind assessed scope
without reading unrelated files. Content drift rejects the measurement. This
capability does not stage, invoke agents or validation, assess thresholds, or
change workflow eligibility.

## HEAD Observation

`inspectHead` reads the current commit object ID and that immutable object's
subject, including unborn HEAD as `{head: null, subject: null}`. Plan execution
uses this observation before writable entry and ahead of generic resume or
interruption drift handling. An exact leading-plan subject already at HEAD, or
external HEAD movement from the saved baseline, requires plan revision without
adopting the commit. Consumed runner-authorized commits settle verification-only
first; only that verified settlement changes plan progress.

## Read-only Change Diagnostics

The Git capability alone defines the read-only snapshot change domains, in
comparison order: `head`, `branch`, `refs`, `tracked-content`,
`untracked-content`, `index`, `remote-configuration`, and `identity`. Its pure
normalizer accepts only one to eight unique known labels and returns them in
canonical order, otherwise `null`; the service's `readOnlyChanges(cause)`
applies it only to `ERR_READ_ONLY_REPOSITORY_CHANGED` and runs no Git command.
Polishing and plan execution persist the result as the optional
`pause.snapshotChanges` of `read_only_agent_mutated_repository` only when their
safety facade offers that accessor. Root pause validation, including pauses
retained by operator stops, rejects any value the normalizer would change, and
pipeline validation accepts it only on that reason and code. Absent labels mean
the diagnosis is unavailable, so state versions are unchanged.
