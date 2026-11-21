# Workspace and Git Coverage

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

Fast `test/git/polishing-handoff.test.js` uses isolated real-Git fixtures with
preconfigured ignored hooks and a harmless `post-index-change` receipt outside
the repository. Assertions cover ordinary hook activation, unchanged accepted
fingerprints and configuration, hook-free exact staging of additions,
modifications and deletions, unchanged/no-op incomplete classification, and
inspection/completed recovery without `add` through a fixture-local Git recorder.
Existing authorized commit-hook refusal coverage remains in
`test/git/local-commit.test.js`. Slow polishing handoff recovery additionally
covers configured hooks for complete, untouched
and partial effects: no role/staging replay for complete recovery, validation
rediscovery before an untouched legacy effect, and no repair of a partial effect.
These fixtures require no live provider, network, paid service or live-project
hook execution; they do not replace the full slow gate or operator acceptance.

## Directory inspection

The fast `test/workspace/inspection.test.js` suite owns the filesystem-only
directory boundary: non-Git snapshots, enclosing and nested controls for the
workspace and external reads, Git pointer/shared and bare metadata, pointer
dependencies nested in protected controls, aliases hidden by dot segments,
redundant reads, protected output overlap, state-control exclusion through
workspace and unrelated state ancestors (including workspace metadata targets) and
provider aliases without added reads, nested state-only metadata pointers and
cycles, canonical workspace targets and writable intermediary dependencies of
ancestor provider aliases, protected cross-control skill links, content/identity drift,
unrelated sibling creation during alias resolution and routing-directory replacement,
escaping intermediate links, mutable hops across writable boundaries, hard links,
special files, exact UTF-8 filenames, undecodable names and deterministic
read/ancestor races. It also owns bounded internal provider-control directory
aliases: canonical target protection, full-inspection alias-binding rejection,
control-specific escaping, dangling, cyclic, file, FIFO, parent, Git-metadata,
Git-link and state-overlap rejections, and target replacement during resolution.
Scoped fixtures reject reads of excluded/unselected trees through both ordinary
and descriptor paths, preserve protected inputs/controls and required link
dependencies, bind reconstructed selections and routing identities, and cancel
discovery/file hashing with verified handle closure and bounded anonymous progress.
Real captures prove compact baselines detect source and control drift and that
output baselines derive absent roots only from covered directory ancestors,
reject blocking file ancestors, uncovered roots and selected or excluded
snapshots, keep remainder digests across output-only changes and reject
`allowOutputs` or malformed partitions in the compact guard.
`test/workspace/output-directory.test.js` retains ordinary output preparation and
scoped output authority independently of source selection.
Temporary directories and injected filesystem effects need neither Git nor live
providers. Workflow/provider integration remains separately owned as those
consumers land. Fast `test/agents/codex.test.js` owns the public adapter's
directory request/probe contract, access-specific receipts without Git or commit
preparation, native output-only permissions, protected-write rejection, effective
policy substitution, literal-path rejection for glob syntax, reconstruction,
observations and attempt retirement. Codex 0.167.0-style `config/read` fixtures
carry explicit nullable permission defaults through launch, selection,
continuation, fork and reconstruction, retaining legacy omitted defaults and
rejecting unknown fields, non-null overrides, inheritance, changed grants and
scope. It uses ordinary temporary directories and model-free transport fixtures; live
provider/platform acceptance remains separate. Fast `test/agents/claude.test.js`
also owns Git-free directory proofs, access-specific immutable receipts, native
and fallback output-only command projection, protected external read mounts,
execution of the fallback probe payload against its emitted mount topology,
rejected write mounts, output substitution during allocation and admission,
missing nested artifact/state exclusions, post-failure mutation guards,
reconstruction and unsupported isolation. Controlled launchers preserve deterministic coverage;
the operator-owned [post-install Claude acceptance](native-acceptance.md) remains separate.
Retiring completed and failed turns retain Claude allocations when changed
control pointers reference storage or cannot be inspected, then permit the same
owner to clean up after restoring controls without replaying the turn.
Controlled 2.1.317-style initialization runs through the adapter's actual launch
options before the tool launcher, proving unchanged ordinary-directory sources,
controls and selected inputs, private mode-0700 atomic staging, separate command
cwd, continuation and retained allocations pending process retirement. It covers
missing controls and existing user bookkeeping without reading native provider
storage. This is model-free regression coverage, not live-provider acceptance;
version/help output does not prove native read-only behavior.

Scoped public-adapter fixtures use malformed control pointers and dangling links
inside excluded and unselected trees to reject unrestricted preparation or
verification. They bind receipts to inspection roots and exclusions, preserve
frozen scope through reconstruction despite caller mutation, reject selected
source/control drift and protected exclusions, and exercise Claude cleanup with
missing inputs under the same scope. Scoped mount preparation uses the verified
workspace binding even when capture omits that root. Omitted-scope fixtures retain
the existing native initialization and whole-directory contracts.

## Repository boundaries

Fast `test/source-boundaries.test.js` owns source index, dependency-direction
and provider-isolation boundaries. Its source walks cover the root runtime and
exactly the root manifest's `workspaces` declarations. A synthetic temporary
root proves that an undeclared hidden directory is not walked, declared regular
workspaces still are, and an explicitly declared hidden workspace is discovered
and strictly validated; run it when changing workspace layout or declarations.

## Change measurement

The fast Git `change-measurement.test.js` suite owns staging-independent text
counts and separate binary paths, mixed staging, ignored files, index-hidden
changes, raw newline handling, link confinement, path replacements, exact size
inputs and stale-candidate rejection. It uses isolated repositories through the
public Git service; measurement itself runs no tests or agents and changes no
index or history. Adding this unused capability does not change workflow,
migration or effect ownership and requires no durable slow workflow matrix.

## Git source selection

The fast Git `source-selection.test.js` suite owns complete HEAD/index and
non-ignored untracked membership, missing tracked paths, index-hidden worktree
content, ignored-tree non-visitation through workspace capture, unchanged Git
controls/index bytes, literal names, links, unsupported recursive boundaries,
unborn/non-Git directories and controlled membership publication races. It uses
isolated repositories and the public Git/workspace services without providers.
Controlled file and missing-leaf replacements at handoff, discovery and capture
assert zero descendant reads, including reconstructed declarations and absolute
links entering a selected missing root replaced during capture. Valid absolute
file links retain root dependency evidence. Provider
receipt fixtures separately bind the optional file-only constraint and reject
malformed declarations before activity.
This capability does not activate pipeline scope selection or change run state;
workflow and durable preparation coverage remains with their owning changes.

## Read-only change diagnostics

Read the [current contract](runner.md#runner-composition-coverage).

## Setup proofs

Read the [current contract](runner.md#runner-composition-coverage).

## Output directory preparation

Read the [current contract](finalization.md#finalization-applicability).
