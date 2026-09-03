# Provider Model

Agent Runner supports Codex CLI and Claude Code as independent role backends.
The pipelines consume one small normalized turn contract; provider-native
processes, flags, profiles, protocols, sandbox behavior, sessions, and parsing
remain adapter concerns.

## Selection and capabilities

Each active role resolves a backend plus optional trusted profile, native model,
and context-size selection. `current` means the provider's effective native
selection rather than a model ID chosen by Agent Runner. A trusted profile is
defined only in runner-local configuration and pins one backend. Project
configuration may select its alias but cannot define credentials, binaries, or
arbitrary environment values.

Configured inactive roles are validated, but lazy mode neither resolves nor
probes them and does not persist or publicly expose their provider-private
values.

Before work, an adapter proves the capabilities required by the role: structured
output, read-only inspection, safe workspace writes when applicable, remote
write blocking, native session behavior, and constrained local commit when the
pipeline needs it. A capability probe does not prove authentication or provider
availability; the first real turn under the selected profile establishes that.

## Sessions and context

Native sessions are disposable execution context, never durable workflow
state. Every turn has a complete recovery prompt reconstructed from persisted
inputs, summaries, decisions, fingerprints, and repository evidence. A
compatible session may be continued as an optimization, but interruption and
context exhaustion can recover in a fresh session without changing correctness.

An operator may deliberately provide a source session. Independent mode forks
it separately into primary and review checkpoints so the Reviewer does not
inherit the primary agent's reasoning. Lazy mode forks it exactly once into the
logical primary role for the entire run. The source ID remains opaque, profile
compatibility is checked before work, and a failed fork never silently becomes
an unrelated fresh context.

## Isolation and effects

Read-only turns cannot change repository content or Git control state.
Workspace-write turns may change safe content but cannot write Git metadata.
Codex uses a runner-owned private temporary root for writable attempts; Claude
advertises writable capability only after its native sandbox policy is proven.
Remote writes remain blocked in every access mode.

Plan execution's local commit is a separate constrained adapter capability. It
is available only for the Worker's one-shot authorized `COMMIT` turn and does
not widen ordinary workspace-write access. Polishing never requests it.

## Normalized failures and recovery

Adapters classify native failures into a finite provider-neutral control
surface. Authentication, unsafe permissions, forbidden collaboration,
isolation failure, invalid contracts, and ambiguous writable outcomes fail
closed. Allowlisted backend, capability, configuration, usage, provider, and
source-session availability failures may enter a durable pause only after the
runner proves the repository is safe.

Explicit rate, quota, credit, or spend-limit failures are not hidden behind
context compaction or provider fallback. A resumable failure records only its
bounded normalized class and checkpoint. Resume reconstructs the same logical
request after the operator restores availability; it does not depend on raw
native output or a surviving provider session.

Provider messages, responses, prompts, denied tool input, standard error,
credentials, and process causes do not enter public activity or durable state.
Adding another backend is a source-controlled runtime decision, not dynamic
plugin loading, and must preserve these shared semantics without adding
provider branches to pipeline policy.
