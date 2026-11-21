# Trusted Validation Source Projection

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Declared mounts and environment

Scratch and cache mount only at `/run/agent-runner/scratch` and
`/run/agent-runner/cache`. They provide `AGENT_RUNNER_SCRATCH`/`TMPDIR` and
`AGENT_RUNNER_CACHE`/`XDG_CACHE_HOME`/`npm_config_cache` respectively (npm uses
`/run/agent-runner/cache/npm`). These bindings are runner-defined; project
configuration chooses only the capability booleans. Without source projection,
build output must explicitly target scratch. Dependencies mount only at the read-only
`/run/agent-runner/dependencies`, with `AGENT_RUNNER_DEPENDENCIES` bound to that
path. Files use their declared lowercase SHA-256 digest as their name. No partial
file is exposed. Artifact-only requests allocate storage even without scratch or
cache. Extraction or setup must be part of the exact declared command and target
declared scratch; the runner does not extract archives or install host tools.
Without source projection the repository mount remains read-only; system mounts
are always read-only and networking remains private.
These capabilities do not change the agent sandbox.

## Source materialization and guards

`sourceProjection: true` makes the Git boundary materialize the immutable HEAD
selected by the pre-execution repository snapshot plus the exact current
tracked and non-ignored untracked content represented by its staging-independent
content fingerprint. It neither materializes staged blob content from the
mutable index nor carries ignored untracked files, and it never copies `.git`.
The owned allocation is journaled before its destination exists, and the source
directory must match its allocated device/inode before any source write.
Descriptor-anchored writes and a final kind, mode, size, and content-hash
comparison verify the complete owned tree before execution. Its root and
source-directory identities are also verified before and after materialization.
The executor rechecks the original repository snapshot before launch, mounts
only that source directory writable at the canonical project path inside the
namespace, and uses it as the command's working directory. Original worktree,
index, Git metadata, state, task paths, credentials, and undeclared host storage
are absent. The check may create or rewrite projected files, but those effects
are discarded with the owned allocation after the complete process tree
retires. A final repository guard rejects external or original-repository drift,
and accepted evidence retains the source content, HEAD, command-identity,
ordered-command, trusted-configuration, and validation-infrastructure bindings.
Stale content or HEAD, substituted directory identities, incomplete
materialization, projected entries overlapping protected control paths, runtime
mounts that would expose an external protected path, and uncertain cleanup fail
closed without reusable output.
Preflight checks storage-root writability and rejects fixed mount targets that
overlap protected paths before provider work; allocation rechecks that policy.
Private storage also cannot overlap system, executable, or PATH exposures;
the sandbox rechecks this before mounting. Protected Git paths include canonical
directory-symlink targets and shared metadata reached through Git directory
pointers or `commondir` files.
