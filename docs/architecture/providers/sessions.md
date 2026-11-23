# Disposable Sessions and Source Lineage

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Agent Context Recovery

Backend sessions are disposable execution context, not durable workflow state.
Adapter capability probes inspect the installed CLI and enforceable local
isolation only. Codex additionally validates a selected named profile once per
adapter with the model-free
`--profile <name> app-server --strict-config --print-startup-config` startup
path, which `app-server --help` must advertise. Its output is discarded; a
missing flag or non-zero exit fails before any App Server launch as
`ERR_UNSUPPORTED_CODEX_CAPABILITY` / `capability_native_profile`, without the
profile name or native text, and the profile is never ignored or substituted.
Probes do not claim that authentication or the provider is usable; that is
established by the first real turn under the effective profile.

Every retryable request carries a turn prompt and a complete recovery prompt
reconstructed from validated run state, durable artifacts, and the observed
workspace. A role session is continued only when its persisted key matches the
accepted inputs, role, and pipeline-owned checkpoint. Clarification and normal
work use distinct checkpoints. In independent mode, plan execution also
isolates Worker and Reviewer by planned commit, while polishing isolates
bootstrap from Worker and Reviewer work. Compatible continuations receive only
the current instruction and state delta; first, forked, fresh, and
context-invalidated turns receive the complete prompt. Arbiters remain fresh.

## Durable Reconstruction

A checkpoint's complete prompt is reconstructed from validated inputs, durable
resolved summaries, its current plan step or change-set fingerprint, active
blockers, and the pipeline's bounded decision history. These inputs remain
durable even when the native session is gone.
Every pipeline role turn also states that the authorized role must produce the
result itself without delegation, subagents, or multi-agent collaboration.
Prompt compliance supplements rather than replaces the adapters' fail-closed
collaboration audit.

## Mode Topology

Independent mode retains the original role topology: primary and review roles
have separate contexts and any required Arbiter starts fresh. Lazy mode has one
logical primary role and never resolves, probes, forks, invokes, or charges a
Reviewer or Arbiter. Plan authoring uses the Planner; plan execution and
polishing use the Worker. A reconstructed native session is still that same
logical role, and all clarification, no-delegation, provider recovery,
redaction, product-decision, durable-state, lease, and repository guards remain
unchanged.

## Context Exhaustion

When a native context is full, an adapter may compact it and retry the complete
recovery prompt once. If continuation still fails, writable and read-only work
can resume in a fresh session with the same complete prompt and a concise
recovery preface.

## Source-Session Consumption

An explicitly supplied source session is different. In independent and combined
modes, the
first eligible turn of each new primary or review checkpoint creates a direct
child and returns its ID without resuming or mutating the source. In lazy mode,
only the first eligible primary turn may create that child, and the durable
one-time marker forbids later source forks even when a native session must be
reconstructed. For failures without availability evidence, if an eligible `spawn` or `initialize` launch failure occurs
before a lazy fork can create a child, the same atomic availability-pause
transition restores the one-time marker. Resume then makes the run's single
fork for the same logical role. Recovery at `session` or `turn_start` is removed
from a fork request and the request becomes non-resumable because a native child
may already exist without durable lineage; recorded children are continued or
reconstructed and never reforked.
If the source cannot otherwise be forked, the turn fails before agent work
rather than silently losing lineage.
