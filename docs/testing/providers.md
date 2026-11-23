# Provider Coverage

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Session naming

Fast `test/session-naming.test.js` owns strict Runner naming context, the full
existing run UUID across providers/pipelines/modes, inactive roles and creation
acknowledgement ordering. Provider fixtures prove native child acknowledgement
without live model calls. Codex fixtures additionally cover exact UUID prefixes,
bounded Unicode descriptions, acknowledgement/naming/turn ordering, direct fork
lineage, inherited titles, unchanged continuation, fresh reconstruction, redacted
metadata rejection and transport loss before model or commit effects. Runner
coverage retains the known child and full request through a backend pause without
retry accounting. The installed Codex 0.164.0 stable generated protocol schema
confirmed `ThreadSetNameParams`, `ThreadSetNameResponse` and `thread/name/set`;
this model-free schema inspection is not live naming acceptance. The opt-in Codex
smoke verifies naming only when explicitly enabled. Focused durable
authoring/audit cases cover bounded journaled diagnoses, unchanged retry/usage
accounting and known-child recovery without another source fork or owner cycle.
Coverage retains acknowledged children through authentication/output dispositions,
excludes commit-readiness children from Worker reuse and bounds concurrent diagnoses.
These checks add no retrospective naming or native acceptance claim. Existing
common and custom-execution slow assignments remain unchanged.

Claude's model-free fixtures cover the same full UUID and Unicode bound, exact
`--name` support, fresh/fork/continuation arguments, fresh reconstruction,
unchanged compaction and source lineage, acknowledgement before bounded receipts,
and metadata rejection with either a validated result or stream initialization.
They reject replacement launches and constrained commit effects after metadata
failure, and preserve permission, interruption and accounting boundaries.
Installed Claude Code 2.1.316 help advertises `-n, --name <name>`; help inspection
is not a live naming acceptance claim. Both provider smoke tests remain opt-in.
The shared context matrix retains every registered pipeline/mode and active role
on both providers, excluding inactive roles. Common slow coverage, exact package
installation and Agent custom-execution assignments remain required; no predecessor
gate evidence satisfies the final feature's current validation.

## Terminal failure classification

Fast `test/agents/claude.test.js` owns the exact terminal `protocol_*` class,
failure record, retry and single turn call for each malformed-stream, failed-exit,
observer and lineage rejection, including unchanged local-commit `not_started`
proof, while replayed completed-session init and accepted streams stay accepted.
`test/agents/registry.test.js` owns bounded boundary messages and rejection of
unregistered classes and native text; `test/cli.test.js` owns the printed line.
`pipelines/polishing/test/recovery.test.js` owns cold persisted FINALIZE
diagnosis, status and activity, classified and unclassified, without
finalization acceptance, fingerprints, staging, retry or resume.

## Permission failure classification

The Claude test also owns factual permission classes through completed and
failed processes, order-independent mixed batches and local-commit
`not_started` proof; the registry, persistence, polishing recovery and CLI
tests own their terminal registration, legacy loading, redaction, cold pause
and printed line.

## Explicit-model catalog misses

Focused adapter and COMMIT policy tests distinguish malformed RPC envelopes,
invalid and capped catalog pages, and unsupported effort from unrelated
pre-executor rejections. Repeated or unmatched catalog replies and malformed
shutdown output cannot establish catalog absence. The adapter rejects reroutes
with request IDs and reroutes during App Server shutdown before attestation or
commit execution. It also rejects thread model conflicts while accepting catalog
aliases. Shutdown reroutes invalidate provisional misses and prevent native
fresh-thread recovery while preserving provider availability classification.
An unsuccessful provider exit prevents catalog retry, attestation, and commit
execution, even when stdout drains successfully. An interrupted drain,
unsuccessful exit, or exit before the next catalog page keeps the lookup
terminal as `model_catalog_invalid`. [Runner coverage](runner.md#explicit-model-catalog-recovery)
owns composed retry and pause regressions.

## Restricted-host launchers

Claude restricted-host launcher changes use deterministic public-adapter tests
with controlled bubblewrap processes for the commit gate. That coverage must
compare every x64 and arm64 BPF instruction, reject unsupported architectures
and filter tampering or setup failure, prove direct bubblewrap execution with
one user namespace and no fallback Claude helper, and retain provider
connectivity, environment scrubbing, argument rejection before payload
execution, and the complete command-isolation argument contract.
Access-policy coverage also proves that one compound `git status`,
`git branch --show-current`, `git branch -a`, `git remote -v`, `git tag --list`,
`git log`, `git cat-file`, `git diff --check HEAD`, and `ls` inspection succeeds
under every access policy while index, branch, tag, remote, configuration,
identity-bearing commit, and push mutations fail; the read-only sandbox also
denies workspace writes, and local-commit readiness uses that policy.
Workspace-write settings share the autonomous envelope with no `Bash(...)` rule
or root-relative `Edit(/.git…)` entry and exactly the absolute protected-directory
Edit denials; declared-directory workspace-write keeps its Git-subcommand
denials, and a protected Git path with a rule metacharacter fails before any
turn starts.
Git workspace-write coverage resolves each generated native and fallback
launcher through the turn's `PATH`, feeds it Claude's producer-ordered
arguments for the read-only preparation settings, and replays the resulting
bubblewrap vector through an independent test model in which a later mount
hides earlier mounts at or beneath its destination and a mount point cannot be
renamed or unlinked. Ordinary source files must stay creatable, renamable, and
removable only for workspace-write, while Git metadata, a selected input beside
a nested control, restored controls, and external paths stay unwritable and
irreplaceable. The model first rejects both earlier failure compositions: an
earlier nested restriction hidden by the grant and an ancestor pin after a
selected-file protection. An earlier file mask survives a later read-only
ancestor. Enclosing or hidden unsupported mounts, a tmpfs hiding protections, a
same-destination bind removing a mask,
weakened restrictions, and symlinked controls must exit before bubblewrap
starts. A temporary managed-settings directory proves that an administrator
`bwrapPath`, policy helper, or invalid drop-in leaves every access unavailable
before any isolation proof starts. A non-file override is modeled by Claude's
credential denial removing the shell proof: the generated shell must refuse that
command, run Claude's unsandboxed use, and run the same command through the
authenticated launcher. Probes require the same refusal with real execution.
Directory-probe simulations execute the generated probe script against the
same mount view. A read-only fallback turn proves that Claude's existing
owner-only temporary self-bind follows the private `/tmp` and `/run` mounts
while no other allocation path is bound, and that the descriptor bind keeps
the validated directory when the path is substituted afterward; a substituted
symlink and a regular file at that destination exit before bubblewrap starts.
A separate authenticated producer stand-in runs both generated launchers
against controlled bubblewrap with Claude's end and info sockets as descriptors
5 and 6. Bubblewrap must receive only the info socket, as descriptor 3 natively and after the filter
and retained bind descriptors under the fallback, with no `--sync-fd`; its
record must reach the producer, and the end must arrive only after bubblewrap
has exited. Killing the launcher while bubblewrap still runs must still close
the end descriptor. The still-running bubblewrap is registered before that
kill and, even after a failure, signaled only under its recorded identity;
after its standard error ends, its process state must show it exiting or gone
before the launcher and fixtures are removed; uncertain retirement retains
those fixtures. Producer completion and stderr EOF waits have deadlines. The
supervisor also records producer and launcher identities, and kills all verified
owners before awaiting their shared stderr during failure cleanup. An injected
event regression proves bounded stalled-producer and EOF failure while retaining
unverified owners. Older programs omitting both options still run without
forwarding any socket. A closed, standard, non-canonical, swapped, shared,
repeated or unpaired descriptor, an unsupported descriptor option, a regular file, the launcher's own Node control channel or
an unrelated process's live control channel relayed as the info descriptor,
a relay of both endpoints whose peers belong to an enclosing supervisor
without the producer proof, a proof-bearing process that does not match the
configured producer file, a copied foreign interpreter running the pinned script,
an interpreter evaluating code with that script path as ordinary argument data,
and a pair beside a control channel or another
inherited socket must exit before bubblewrap starts while the producer descriptors end. Named,
listening and non-Unix sockets fail through the same socket-table rule; they
are not constructed because host socket policy may forbid it.
Running the pinned shebang script through its pinned interpreter must still
pass the producer gate, covering both direct and `/usr/bin/env` shebangs.
Two bounded capability-gated Linux process regressions exercise the installed
bubblewrap direct-filter boundary without a model request, sleep, retry loop,
or slow-tier promotion. In the first, read-only and workspace-write fallback
probes run for real, confirming source changes and pinned-control denial with
actual syscalls. The second runs both generated launchers with a literal
Claude TMPDIR and requires a parent-readable cwd receipt, unchanged project
content, and a hidden restricted-host launcher. They do not replace post-install acceptance: after the
finalized commit is installed, the supervising agent starts a fresh real Claude
lazy plan-authoring run and requires preflight to advertise read-only,
workspace-write, and local-commit access plus a provider response before
dependent provider work continues.

## Directory policies and scoped adapters

Read the [current contract](workspace-git.md#workspace-and-git-coverage).

## Exact-file admission

Read the [current contract](runner.md#runner-composition-coverage).

## Runner callback failures

Read the [current contract](#provider-coverage).
