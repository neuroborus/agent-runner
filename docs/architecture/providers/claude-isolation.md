# Claude Isolation

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Directory Turns

Directory turns replace Git metadata preparation with workspace-service inspection
of all declared reads and discovered filesystem controls. Claude's mount
preparation stays read-only with no configured writable paths. Both authenticated
launchers keep the workspace read-only and bind only declared existing output
roots writable; a write turn needs the exact read-only preparation reservation,
and a whole-workspace grant adds no write access.
Missing output roots fail closed rather than being materialized
or widening access to their parents; new descendants can be created inside an
existing output directory. Mount identities come from a fresh filesystem-owned
snapshot after storage allocation. Both launchers recheck canonical paths,
device/inode identity, ordinary file types and single-link files before admission.
When scoped capture omits the workspace root, its separately verified inspection
binding supplies that read-only mount identity without capturing unselected
content.
Controls and external reads receive exact read-only mounts, including references
otherwise hidden by private temporary/runtime filesystems.
Incidental host write mounts are discarded. Provider-native Edit/Write are omitted
for directory requests: only sandboxed Bash can write, with the existing tool,
credential, network, socket, seccomp and no-fallback restrictions. Provider
authentication/connectivity and session storage remain separate.

Private turn storage excludes the declared state and protected trees in addition
to workspace/task exclusions. Missing exclusion suffixes resolve through their
nearest existing directory without creating declared paths. The workspace's
output-only snapshot guard runs before each attempt and after process retirement
and storage cleanup, including
failed attempts before compaction or fresh reconstruction. Uncertain retirement
retains its ownership failure and cannot authorize replay. Continuation, forks
and reconstructed sessions reinstall the same policy without manufacturing Git
or commit authority. This adapter capability does not expose directory workflows.

## Linux Policy Selection

On Linux, Claude selects an isolation policy independently for read-only,
workspace-write, and local-commit access. The selector first uses the fixed,
model-free provider/child probe around Claude's embedded `apply-seccomp` helper
for the full native sandbox. Only a positively recognized
nested-user-namespace denial may try the fallback. A bounded model-free version
invocation first proves that Claude accepts the spawning-parent policy option.
The isolation proofs invoke no model or provider transport. The native proof
invokes Claude's local embedded seccomp helper. The fallback proof supplies
representative effective arguments without that automatic dispatch through
the same provider-private command launcher, validation grammar, and
access-aware topology installed for model commands.
Fallback turns launch the Claude CLI directly so authentication and provider
transport retain the host environment and network path. The invocation-local
spawning-parent policy names the short-lived launcher as `bwrapPath`. Claude
honors that value only when its policy tier admits that source and otherwise
resolves `bwrap` through `PATH`, so the turn environment also places the
launcher's directory first on the provider's `PATH`. Either selection reaches
the same authenticated launcher; without it, Claude's own bubblewrap would
apply the read-only preparation reservation to every command. Administrator
managed settings outrank both selections because Claude takes their first
`bwrapPath`. Before any proof, the selector therefore reads the documented
Linux `/etc/claude-code/managed-settings.json` and its non-hidden `.json`
drop-ins; a `sandbox.bwrapPath`, a policy helper whose tier cannot be
inspected, or an unreadable or invalid document leaves every access mode
unavailable. Server-managed settings live in provider-private storage and are
not read, so selection is also enforced per command. The turn environment names
a generated Runner shell through `CLAUDE_CODE_SHELL`; it runs the pinned bash or
zsh only when `AGENT_RUNNER_CLAUDE_COMMAND_SHELL_PROOF` carries the launcher's
per-turn value and otherwise exits 125. Claude's credential denial removes that
variable inside every sandbox it starts, while its unsandboxed shell use keeps
it. Only the authenticated launchers set it again, after Claude's removal and
beside the read-only HOME projection that holds the shell, so a command started
through any other selected bubblewrap never runs. Probes require that refusal
and run their commands through the same shell. The launcher pins
the canonical host `bwrap` executable from the unchanged environment before the
turn instead of resolving it through a potentially workspace-writable path. The
launcher file is non-writable.
Its owner-only allocation is outside the project, task, and state trees, and
command namespaces cannot write the allocation except for an existing,
validated, owner-only directory Claude selects strictly inside its private
temporary directory. In every access mode commands may use that directory for
shell bookkeeping, its exported TMPDIR and the cwd receipt the parent reads, and
for scratch writes. The launcher executable and token, the provider cwd, and
other allocation content stay hidden, and the tool HOME remains the read-only
projection with private namespace-local scratch directories. The adapter
retains directory authority for teardown.

## Authenticated Launcher Grammar

The authenticated launcher accepts one closed Claude bubblewrap grammar: the
session and parent-lifetime flags; unique environment removals or non-protected
assignments; network unsharing, optionally followed by same-path proxy-bridge
binds strictly inside the private runtime trees and environment operations; a
read-only root followed by supported bind, read-only-bind, or tmpfs operations;
the synthetic device mount; PID and required user unsharing; an optional empty
capability set; Claude's weaker host `/proc` bind; trailing environment
operations; and exactly one absolute shell, `-c`, and opaque command payload
after `--`. Assignments after network unsharing point at Claude's discarded
proxy bridge, so each becomes a removal; a variable Claude already removed stays
removed. The
launcher translates the required user-unshare argument into exactly one
bubblewrap user namespace. Claude's fixed
incidental write binds for its temporary, npm-log, and debug paths are
recognized exactly but discarded rather than exposing their host paths.
Except for the private temporary self-bind below, which grants no write to the
workspace, Git metadata, outside paths, or allocation controls, all other
writable binds must resolve inside the canonical workspace, must not resolve
inside Git metadata, and are accepted only for workspace-write access.
Read-only binds must preserve their source path except for Claude's `/dev/null`
or verified owner-only empty-directory masks, both limited to strict workspace
descendants. Turn masks must lie beneath the allocation's canonical private
temporary directory that Claude receives as `TMPDIR`; directory-free probes
use the canonical runtime temporary root. Empty-directory masks are replaced
by private read-only tmpfs mounts rather than exposing their host temporary
sources.
Exact workspace mounts of either kind and Git mounts, including redundant Git
descendants, are replaced by Runner-owned mounts. Claude's same-path writable
bind strictly inside the allocation's private temporary directory, overlapping
neither the workspace nor Git metadata, is retained after the private tmpfs
mounts when it names an existing canonical non-symlink directory owned by the
current user beneath that canonical owner-only directory; any other existing
target fails closed and a missing one is discarded. The launcher opens that
directory without following symlinks, verifies the descriptor's owner, kind and
canonical path, and binds the pinned descriptor with `--bind-fd`, so later path
substitution cannot redirect the mount. Claude's other mounts
strictly inside `/tmp`, `/run`, or the hidden allocation, without overlapping
the workspace or Git metadata, are discarded because the launcher's private
mounts replace those trees. Other same-path read-only workspace descendants and masks
preserve Claude's command-protection policy for every access; outside the
workspace, Claude may also mask an existing file with `/dev/null`. Every
remaining read-only bind must not overlap the writable workspace or any part of
the Runner-private device, process, runtime, or launcher trees. A tmpfs
destination is either `/tmp` or `/run`, replaced by the launcher's private
mounts, or an existing directory mask that overlaps none of the workspace, Git
metadata, or those private trees. A later writable bind may not overlap an established
read-only workspace restriction, and no later mount may re-expose a path hidden
by a private workspace mask.
Duplicate environment operations, assignments to `ARGV0`, credentials, or the
launcher token, writable roots, unsupported options, malformed namespace
arguments, malformed option arity or ordering, and extra payload arguments exit
before bubblewrap or the command starts.

Current Claude versions also pass `--sync-fd` and `--info-fd`: a descriptor
whose end Claude awaits before it removes its write-denied placeholders, and
one from which it reads bubblewrap's first `child-pid` record to wait for or
kill the sandbox. The shared projection used by both launchers accepts each
option at most once, anywhere before `--`, only with a canonical descriptor
number naming Claude's producer-assigned slot (`5` for end, `6` for info) and
an inherited unnamed, connected, non-listening Unix stream socket that is
neither standard I/O nor the other role's socket.
Socket shape alone cannot prove that Claude owns a descriptor. The launcher
token authenticates the invocation, and both roles must arrive together and
account for every inherited socket beyond standard I/O, with no Node control
channel in the launcher. The current producer's other inherited descriptors
are files, so its own pair passes this census; a producer that adds another
socket fails closed. The launcher then reads the kernel's Unix socket table
through `ss`, resolved from the turn's `PATH` at launcher creation and never
from a protected root, to find each role's peer socket. Walking the launcher's
ancestors, the first process that holds either peer must hold both and carry
the invocation's exact private shell proof in its launch environment. That
process must also match the configured Claude executable's pinned device/inode;
a shebang CLI requires both the pinned interpreter executable and the pinned
script as its first argument, verifying both current identities. Direct
interpreter shebangs and `/usr/bin/env` with one command are resolved at launcher
creation; unsupported argument forms fail closed for descriptor-bearing programs.
A foreign executable naming the script or a script path supplied as ordinary
data after `--eval` cannot authenticate that process.
The interpreter or inherited environment alone cannot authenticate a supervisor.
Claude keeps the other end of each pair it creates, even when a shell sits
between it and the launcher. An enclosing supervisor's unrelated control peers
cannot acquire producer provenance through a relay, and the fixed slots prevent
role substitution. A foreign peer or an ancestor without those bindings fails.
Without a usable `ss` or producer identity, either
option fails closed; a producer that passes neither needs none. Closed, forged,
malformed, repeated, shared, unpaired, file, named, listening, control-channel,
foreign-peer and non-Unix descriptors, a pair beside another inherited socket,
and every other bubblewrap descriptor option, exit before bubblewrap starts.
Neither descriptor reaches the command. Both launchers remove both options
and keep the end descriptor, never reading or writing it, until bubblewrap has
exited. They pass only the info descriptor to bubblewrap: as child descriptor
`3` under native policy, and after the seccomp filter and any retained bind
descriptors under the fallback. Bubblewrap writes the record from outside the
sandbox and closes the descriptor in its child before the command starts. Both launchers
close both descriptors after bubblewrap returns; refusal or interruption closes
them at launcher exit, so Claude observes the end either way. A producer that
passes neither option keeps its unchanged program. Accepting this producer form
changes no command authority, so the policy identities below are unchanged;
receipts already bind the CLI version that emits it.

## Namespace and Direct Filter

After validation the launcher drops Claude's host `/proc` bind and strengthens
the same invocation with PID-1 behavior, an empty capability set, private
procfs, private `/tmp` and `/run`, a private `/tmp/claude`, a hidden launcher
path, the retained private temporary self-bind, the exact workspace authority, read-only resolved Git metadata, missing
protected-environment removals, and the requested working directory. A private
Claude module serializes a classic seccomp BPF for little-endian x64 or arm64.
The program validates `seccomp_data.arch`, kills an architecture mismatch,
returns `EPERM` for `socket(AF_UNIX, ...)`, `io_uring_setup`,
`io_uring_enter`, and `io_uring_register`, and allows other syscalls. X64
covers both native and x32 syscall numbers. Unsupported architectures and
malformed programs fail before launch.

On every invocation the authenticated launcher decodes and hashes the exact
filter bytes, writes and syncs an owner-only no-follow file, reopens it
read-only, and unlinks it before verifying the link-free descriptor's owner,
mode, size, identity, and complete contents with positioned reads that leave
its offset at zero. It then removes its authorization token, `ARGV0`, and
provider credentials and invokes the pinned real `bwrap` directly once,
passing that sealed resource as inherited child descriptor `3` with
`--seccomp 3`. Filter creation, tampering, descriptor inheritance, bubblewrap
setup or execution, close, and resource cleanup errors all fail closed. The
fallback's `allowAllUnixSockets: true` setting suppresses Claude's automatic
helper dispatch so the Runner-owned filter is the only fallback socket policy.
The command crosses one user, PID, mount, and network namespace boundary; the
fallback never invokes Claude's seccomp helper or creates a nested user
namespace.

## Capability Proofs

The direct fallback probe supplies Claude's producer-ordered arguments for the
same read-only preparation settings to that same validator and execution path:
credential removals, a private proxy-bridge bind with proxy rewrites, the
default workspace write, a private temporary bind, the final workspace
reservation without the masks it covers, the capability drop, and a trailing
removal. Native probes use the same workspace order. Both probes first prove
that the probe environment resolves `bwrap` to the generated launcher. For
repository access, native and
fallback child probes use a disposable committed repository to require compound
repository inspection and, for read-only access, reject workspace, Git, and local
remote-ref mutations. Workspace-write proofs create a source directory and
create, rename, and unlink a file there; read-only proofs require each change
to be denied. Repository proofs also reject writing a nested `.mcp.json`
control or renaming its pinned parent, and both policies reject writes beneath
`.claude`. They also check access-specific workspace writes, outside-write
denial, private temporary storage, IP isolation, inability to reach live host
abstract and pathname Unix sockets, credential and `ARGV0` removal, and host
provider-proc secrecy. The selected fallback sets
Claude's required weaker-nesting option and `allowAllUnixSockets: true`, so no
second automatic helper is added to the opaque command payload. Native policy
retains `allowAllUnixSockets: false` and its existing stricter topology.
Arbitrary native failures, launcher construction or execution failure,
incomplete proof, or cleanup failure do not enable the fallback.
Both policies keep model-command network, host Unix sockets, credentials, Git
metadata, remotes, and outside writes denied. Probes use fixed representative
arguments and a fixed validated shell payload, the credential-filtered command
environment, and bounded time and output; they retain no host diagnostic and
never apply a profile, authenticate, or invoke a model.
The local-commit executor proof remains independent and `localCommit` requires
both the local-commit turn policy and executor proof.
Both policies now install an authenticated adapter-owned projection launcher.
The native launcher preserves the native namespace/seccomp invocation; only the
restricted-host launcher replaces its known weaker topology. Both preserve
existing descendant masks. Claude prepares its filesystem arguments with an
explicit read-only project reservation and no extra configured write paths;
this prevents it from registering absent project targets for creation or later
cleanup. The authenticated launcher replaces only that exact reservation with
the runner-authorized workspace access. Git writable access requires both the
original workspace bind and the preparation reservation. Declared-directory
writable and native access requires the reservation and derives writes only
from validated declared outputs; a whole-workspace bind grants nothing.

## Workspace Protections

Because the reservation covers workspace Git metadata, selected `readPaths`
inputs, and Claude's built-in shell, tool, and settings controls (`.gitconfig`,
`.gitmodules`, shell profiles, `.ripgreprc`, `.mcp.json`, `.claude.json`,
editor directories, and `.claude`), Claude omits their masks. For Git
workspace-write access both projections therefore normalize the complete
validated mount program before bubblewrap starts. Each destination is
classified canonically. Mounts away from the workspace keep their order, while
a later mount that encloses or replaces the workspace grant, an earlier
descendant tmpfs, a writable alias of workspace content, and a later writable
descendant overlapping an established restriction are rejected. The grant
hides earlier descendant mounts: earlier writable descendants are subsumed by
it, and earlier read-only restrictions are reapplied after it with their own
source and destination. The output order is the grant, ancestor pins
shallowest first, and then Git and selected-input protections, restored
controls, and Claude's descendant restrictions together, shallowest first, with
a restriction after a protection at the same destination. Restrictions with
different operations or sources at one destination are rejected, as is a mask
or tmpfs that would enclose a protection or another restriction, or a tmpfs at
one, because it replaces host content; a read-only mask may still cover a
protection at its destination. Before bubblewrap starts, the
normalized program is replayed with each later mount hiding every earlier mount
at or beneath its destination; every protection and restriction must remain
effective and read-only, and none may keep a movable ancestor. Like Claude's producer, discovery finds controls and nested `.git`
entries by name in the workspace and up to three non-symlinked directory levels
below it, outside `node_modules`. Only existing paths are mounted. A
symlinked control, a protected path behind an inner symlink, or a link whose
target encloses the workspace fails closed; a linked settings, commands,
agents, skills, or plugins entry inside a protected `.claude` directory also
protects its in-workspace target. Immutability is decided only from read-only
mounts in the final tree. Every other ancestor of a protected path or
restriction becomes a writable self-bind: its contents stay editable, but as a
mount point it cannot be renamed, removed, and recreated around the
protection. The restricted-host launcher keeps its final Runner-owned Git and
selected-input mounts after those pins. Directory projection admits Claude's
same-path binds strictly inside the turn's private temporary directory and
still rejects every other undeclared write. All project bind,
directory, tmpfs, device, and proc targets must resolve before bubblewrap starts.
Missing `.bashrc`, `.gitconfig`, `.mcp.json`, editor directories, and `.claude`
tooling paths must never be materialized inside a writable project bind. No project file is
ignored, filtered from a fingerprint, or cleaned by an agent.

## Policy Identity and Access Envelope

The provider-private policy identity binds the installed CLI version, selected
isolation policy, complete effective permission, tool, deny, and sandbox policy,
and, for fallback access, the direct-filter contract, architecture, and exact
byte hash. A receipt created for the superseded helper-based fallback, another
architecture, or a prior permission policy cannot authorize later provider
work.
Claude derives its advertised read-only capability and turn arguments from one
autonomous access envelope shared by read-only and local-commit readiness
turns. It exposes only repository-inspection tools and omits broad shell-command
denials that would reject compound inspection, while retaining collaboration,
editing, and web restrictions. Autonomous Bash is available only inside the
proved sandbox, which denies workspace and Git-metadata writes, closes command
network and Unix-socket access, and forbids unsandboxed fallback.
Git workspace-write turns share that envelope, adding only the Edit and Write
tools and the launcher-granted workspace write; no Git-subcommand rule rejects
ordinary inspection before sandbox auto-allow. Under every access policy the
sandbox enforces, and the effective access proof shows, that one compound Git
inspection succeeds while index, branch, tag, remote, configuration,
identity-bearing commit and push mutations fail, outside writes stay denied,
and network and Unix-socket access stay closed. File tools run outside that
sandbox, so their Git-metadata denials name each resolved absolute protected
directory in Claude's `//` rule form; a root-relative rule would resolve against
the native startup directory. A protected path containing a rule, glob or
control character fails with the workspace-policy error before launch.
Declared-directory turns keep their Git-subcommand denials. The policy identity
serializes these settings and the path-independent rule template, so a receipt
pinned under the prior policy fails closed on resume or reconstruction without
migration.
