# Claude Native Initialization and Storage

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Native Initialization

Native turns start in a mode-0700 `native` directory within their journaled
adapter allocation, rather than in the task workspace. The public CLI's atomic
staging initialization can create `.claude/.cc-writes` there before any sandboxed
tool starts; a command-only projection cannot contain that earlier effect.
`--add-dir` declares the real workspace, and fixed system instructions require
absolute workspace paths for file tools and reading the applicable workspace
instructions. Before each sandboxed command Claude prepares staging under its
session cwd. Without cwd retention it adopts a command's projected workspace cwd
inside the declared root, so a later command creates an empty mode-0700
`.claude/.cc-writes` in the workspace. Launches force
`CLAUDE_BASH_MAINTAIN_PROJECT_WORKING_DIR=1` in both the isolated process
environment and inline settings, overriding inherited values, to return Claude
to its private native startup directory after every command. The installed-CLI
differential described in `docs/TESTING.md` proves this sequence and its
prevention; a lone command does not reproduce it.
Launches also force `CLAUDE_CODE_DISABLE_BACKGROUND_TASKS=1` in both the
isolated process environment and inline settings so tool work completes in
the foreground before the result. Conflicting inherited values are discarded;
inline settings override ordinary user/project settings without editing them.
Native managed-policy precedence remains intact, and strict stream rejection
remains the backstop for post-result traffic or duplicate results. Long commands
may stop at the native Bash timeout instead of becoming background tasks.
Unfinished or timed-out required checks cannot pass finalization; a result alone
does not establish completion. Runner-trusted execution retains its separate
authority. The operator-owned native differential in `docs/TESTING.md` compares
the same policy with background execution enabled, releasing an owned FIFO only
after the first result and requiring actual late effects and rejected traffic.
Repaired turns require successful effects before the sole result; unsupported
background and started-but-timed-out requests cannot create late effects. This
proof supplements the source-shaped cwd differential and does not identify the
cause of historical protocol failures.
Native profiles, authentication and session storage stay in their
existing locations; continuation and forks still select the exact native session
ID. Native startup and workspace roots both receive read-only command-preparation
reservations. Projections discard self-mounts of owned startup content and
incidental provider write mounts, including the selected configuration directory's
`.cc-writes`. Commands retain the real workspace cwd and the original exact
workspace, output, input and control mounts. No source placeholder, control
filter, additional writable mount or source cleanup is introduced. Both isolation
probes exercise separate native/workspace cwd projection.

## Private Command Storage

Commands receive an empty, read-only HOME/config projection with private
namespace-local temporary, cache, and runtime directories. The real provider
HOME, authentication environment, selected config directory, and session store
remain separate and unchanged. Provider temporary scaffolding and the fallback
filter's temporary files belong to the same allocation. New allocations live
beneath the fixed platform temporary location without consulting ambient
temporary variables, as Codex workspace storage does. This keeps the provider
`TMPDIR` short enough for the Unix sockets Claude binds there: Linux socket
paths hold at most 108 bytes including the terminator, and a nested ambient
temporary root left no room for a bridge socket name. Recorded allocation
roots, including earlier ambient ones, still recover and clean up unchanged.
Probes exercise the projection launcher too; the contract revisions are
`claude-isolation-v6` and `claude-command-boundary-v13`. These identities bind
the complete policy including cwd retention and foreground lifecycle enforcement;
old receipts cannot authorize it. Existing runs retain immutable receipts and
budgets; adopting the new policy requires a fresh run rather than rebinding evidence.

## Journaled Allocation

Before a turn launches, the adapter journals allocation intent and then the
private directory's device/inode identity through the optional `onResource`
request callback. The stop monitor serializes that callback with process and
stop-activity writes; cancellation does not cancel cleanup persistence.
`storageForbiddenPaths` supplies the task/state exclusions in
addition to cwd. The existing execution-resource slot holds the frozen adapter
preparation identity in `commandIdentity`; this identity never selects or
attests a trusted validation command. A provider descriptor may register one
unique resource identity and recovery hook. The runner dispatches retirement
cleanup through this hook without provider branches or changes to Codex.
Live directory cleanup and recovery add current filesystem-discovered controls
to the cleanup exclusions using the same inspection selection and subtree
exclusions, even when frozen input files are missing. Cleanup never falls back
to an unrestricted workspace traversal. An allocation newly referenced by a
control pointer remains retained until that overlap is resolved.

## Cleanup and Recovery

Cleanup verifies the host, canonical private root, owner, permissions, and child
identity, pins the root descriptor, removes only the recorded child, syncs the
parent, and journals removal. Missing children permit interrupted-removal
recovery; replaced or unverifiable storage remains blocking. Cleanup occurs
only after process and descendant retirement, before a response, fingerprint,
trusted validation, or commit executor can be accepted. Owner-loss resume and
operator stops use the same adapter cleanup under exclusive leases. A still-live
runner retains its private run/worktree lease handles after resource cleanup
failure; a sequential retry revalidates the run token through the state mutation
boundary before reuse, retaining the handle if inspection itself fails.
Concurrent resumes and other owners remain excluded, and stale revisions remain
errors. Restart uses normal identity-based owner reclamation.
`ERR_EXECUTION_RESOURCE_UNVERIFIABLE` preserves the active checkpoint for
repository/effect reconciliation on resume. A fully cleaned pre-launch failure
uses `ERR_AGENT_ENVIRONMENT_PREPARATION` and the existing safe provider pause,
including proven not-started source-fork recovery. Errors retain only finite
`environment_preparation` or `environment_cleanup` class/checkpoint evidence.
A journaled `environment/cleanup-pending` activity distinguishes unfinished
adapter cleanup from a repository check without retaining raw diagnostics.
A stronger provider or containment failure is preserved; the root marks retained
resource ownership so pipelines cannot accept content or finish the turn over
it. Terminal provider failures are persisted as failed checkpoints while their
cleanup reservations remain owned; subsequent cleanup cannot replay the turn.
Process-proof uncertainty stays resumable. Consumed commit effects remain
verification-only.
