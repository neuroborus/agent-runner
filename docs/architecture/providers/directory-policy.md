# Provider Directory Policy

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Request Declarations

The strict provider-neutral turn contract also accepts an optional
`workspacePolicy` with `kind: "directory"`, canonical absolute `workspacePath`
and `stateRoot`, optional `taskPath`, and the workspace service's six path arrays:
`inputPaths`, `sourcePaths`, `outputPaths`, `configurationPaths`, `artifactPaths`
and `infrastructurePaths`. Omitted arrays are empty. The workspace must equal
`cwd`. Optional `inspectionPaths` contains confined canonical absolute inspection
roots; optional `excludePaths` contains literal workspace-relative subtrees.
Both lists are normalized, copied and frozen. Inspection roots accept up to
10,000 entries, matching the persisted directory policy; exclusions retain their
256-entry limit. The file-only constraint applies to every selected root.
Optional boolean `inspectionFilesOnly` requires explicit inspection roots and
preserves their file/link/missing restriction through both providers' workspace
checks, receipts and reconstruction without granting new native permissions.
Omitting both retains whole-directory inspection and the existing policy receipt.
The workspace capability validates scope before discovery, preserving required
reads, outputs, controls and link dependencies. The same selection binds provider
receipts and every pre-launch/post-retirement snapshot, including reconstruction;
neither provider derives Git membership. Exclusions narrow inspection without
widening native read/write permissions or storage placement.
Each ordinary path array accepts at most 256 paths. Runner storage exclusions
contain only canonical absolute protection roots, removing duplicates and
descendants already covered by a parent. Relative inspection exclusions are
covered by the workspace root and never become storage declarations. Directory requests allow
up to 1,539 exclusions for all six arrays plus workspace, task and state roots.
Every declared read/output root remains protected. Unknown fields, noncanonical
inspection/read/output roots and directory `local-commit` requests are invalid.
Execution-option validation remains separate: `probe` additionally
accepts `access` and this policy, requiring explicit read-only or workspace-write
access for directory proofs. Unsupported adapters reject it before provider work.

Codex directory access requires stable CLI 0.164.0 or newer. Its readiness
rejects existing regular-file output roots on the named-profile route,
including dotfiles (`capability_existing_file_output`), without extrapolating a
blanket unsupported version range from the reported 0.167.2 failure. The frozen
backend descriptor optionally supplies `assertWorkspaceReady({ access,
workspacePolicy })`; registration rejects a non-function value. Runner calls it
for active roles whose full role access includes workspace-write before initial
probes, new output preparation and turns, including initially read-only custom
Workers. Explicit writable probes and direct Codex probes/requests repeat current
shape inspection before native work; storage, thread and turn admission recheck
as well. Cached capability proofs do not approve a substituted file root.
Read-only authoring/Reviewer roles and lazy inactive roles remain unaffected.
Read-only recovery probes retain their existing receipt checks; owned process
retirement and pending effect reconciliation precede new writable work. Refusal
uses `ERR_UNSUPPORTED_BACKEND` at Runner admission or the existing provider
capability diagnostic boundary. CLI/MCP errors direct an authorized fresh run
with supported outputs/backend; frozen selections, receipts, accepted outputs and
budgets are unchanged. No public or persisted shape changes or migration are
needed. File declarations remain valid in the shared custom-plan contract.

For custom execution, pending preparation/acceptance reconciles first. The
workflow derives directory intent from trailing `/` in the unchanged canonical
plan, then compares normalized absolute roots. Its configured Worker adapter
exposes descriptor-backed `assertWorkspaceReady({ preparableOutputPaths })`:
before new preparation the list contains only existing directories or explicit
directory declarations; afterward it is empty. Omitted lists retain read-only
startup discovery of missing roots without granting writes. Codex rejects absent
unprepared roots with `capability_missing_output`; Claude's descriptor rejects
them with `output_root_missing`, because exact bind targets must exist. Direct
writable probes and native policy admission recheck actual shapes without a
preparation allowance. Other backends may prove exact-file creation under their
exact frozen policy; no parent permission or output-kind schema is added.
Both descriptors apply their native literal-path restrictions to output roots
before preparation, including absent explicitly preparable directories.
Writable capability proof follows preparation and precedes provider work, retaining
the startup receipt and separate pinned writable receipt. Frozen declaration or
backend corrections require an authorized fresh run.

## Codex Capability Receipt

Its access-specific probe inspects bindings and snapshot safety without Git, an artificial repository,
or a local-commit executor probe. Frozen policy receipts bind the version,
access, declared paths and immutable input/control bindings; authorized output
and state creation do not change a receipt. `declaredWorkspace`
distinguishes this proof from legacy repository capabilities. Directory analysis
advertises read-only access; directory output advertises workspace-write access.
Neither advertises commit authority. Legacy requests and full capability probes
retain their existing behavior.

## Claude Capability Receipt

Claude directory access uses the existing stable CLI baseline and Linux isolation
requirements. Separate cached probes for each directory access mode use ordinary
directories, read-only controls and confined output roots; they never run Git,
initialize a repository or probe local-commit readiness. Repository proofs keep
their own policy selection. Immutable directory receipts bind the installed
version, isolation/tool policy, requested access and filesystem-owned declarations
and immutable bindings. Authorized output changes do not change those receipts.
Only the requested access is advertised, with no local-commit capability.
Restricted-host directory probes check write denial on the mounted reference file
and a separate host-root path; a reference's parent under private `/tmp` may be
writable namespace-local scratch.
