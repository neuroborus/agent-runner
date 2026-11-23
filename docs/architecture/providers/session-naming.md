# Provider Session Naming

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Naming and Creation Acknowledgement

`runner/session-naming.js` derives bounded display context from the existing run
UUID, workspace basename, pipeline and active role at invocation. It overrides
any request-supplied context, preserves the full UUID and never changes client
attribution. The shared strict adapter request carries `sessionNaming`, awaited
`onSessionCreated` and optional `onSessionNaming` observers. Provider-native
naming effects remain adapter-owned and are not implemented by this context.

Codex's actual selection path acknowledges verified new start/fork children, then
calls `thread/name/set` before the first model turn. The full UUID prefix and a
128-code-point description are built from Runner context, never an inherited
title. Ordinary resume does not name; reconstruction names its newly acknowledged
child. The private App Server transport exposes whether it remains usable so an
RPC metadata rejection can continue once while transport/protocol loss emits a
bounded diagnosis and pauses without adapter reconstruction. This failure carries
no availability retry reason or unused source-fork proof, and commit readiness
still proves its executor has not started. Existing pipeline recovery owns resume.

Both adapters build the same bounded title through the private adapter contract.
Claude's native `--name` belongs to its original fresh/forked CLI launch, after
an exact installed-help flag check, and is omitted for ordinary continuation or
compaction. Unsupported naming before the first launch carries proof that
initialization did not start; later recovery retains any earlier effect
uncertainty. Native metadata rejection retains a positively correlated
stream initialization identity or validated child result before surfacing its
bounded diagnosis; it cannot trigger fallback launch, reconstruction or a Git
effect. The stream exposes only the verified identity, never a transcript or
title. This adds no persistent schema, migration, provider bound or session-store
inspection. Codex's acknowledgement-before-RPC ordering remains unchanged.

Every pipeline supplies the creation acknowledgement at its existing logical
session key, including audit cycles and commit readiness. It records the child
before a naming diagnosis or metadata failure reaches the workflow, then accepts
the same acknowledged response without recording it twice. Existing source-fork, continuation and reconstruction
selection remains authoritative. Old sessions are never enrolled by continuation.
Acknowledged children retain consumed source-fork authority across no-turn-effect
and ambiguous failures. The first continued request after authentication,
output exhaustion or a backend pause includes the complete recovery prompt because acknowledgement
does not prove that the child received its original request.
Fresh commit-readiness children remain recorded in a
separate, non-reusable context so they cannot replace a fully reconstructed Worker.
Naming diagnoses use existing immutable journaled activity, with only a closed
status and role; child records and envelope schemas remain unchanged. No metadata
receipt rewrites lineage or settles workflow, effects, retry or usage accounting.
See the [provider contract](../../product/PROVIDER_MODEL.md#sessions-and-context).
