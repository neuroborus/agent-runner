# Provider Permission Boundaries

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Git Metadata and Project Guidance Authority

Read-only and local-commit storage remain independently isolated. Both adapters
advertise `gitMetadataWriteBlocked`; the runner, not an agent turn, owns effects
that require the index.
Each pipeline's complete and recovery role-prompt envelope provides the
semantic boundary for eligible project `.agents` content: plan authoring
requires an explicit user task, polishing requires the same, and plan execution
additionally requires the current planned commit to authorize the guidance
change. The responsible roles must not propose, make, or approve a change
outside that scope. A compatible continuation inherits the boundary from its
native session, while every fresh or reconstructed context receives it again.
Violations use the owning pipeline's ordinary finding-and-fix route and do not
open a user question.

## Capability Probes

Read the [current contract](sessions.md#disposable-sessions-and-source-lineage).

Capability probe semantics and selected-profile validation are owned by
[disposable sessions](sessions.md); native enforcement is selected through the
[provider map](README.md).
