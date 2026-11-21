# Provider Contracts

Read the matching topic before changing its contract. The [document map](../../README.md)
owns the change gate. Read only the affected owners and their required references.

| Topic                                                         | Read when                                                                                                                                                     |
| ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Claude Isolation](claude-isolation.md)                       | Native/fallback selection, authenticated launcher grammar, mount protections and access proofs; read before changing Claude enforcement.                      |
| [Claude Native Initialization and Storage](claude-storage.md) | Native startup effects, private storage, journaled allocation and cleanup recovery; read before changing Claude resource custody.                             |
| [Codex Isolation](codex-isolation.md)                         | Directory permission profiles, named-profile validation, private command storage and App Server retirement; read before changing Codex enforcement.           |
| [Provider Directory Policy](directory-policy.md)              | Strict path declarations, inspection bounds and access-specific receipts; read before changing directory request selection or capability proofs.              |
| [Normalized Provider Failures and Recovery](failures.md)      | Closed failure/effect proofs, native precedence, output exhaustion and bounded pause eligibility; read before changing classification or retry policy.        |
| [Provider Observations](observations.md)                      | Normalized token snapshots, bounded facts, lineage and accounting uncertainty; read before changing diagnostic observation mapping.                           |
| [Provider Permission Boundaries](permissions.md)              | Capability-probe limits, Git-metadata authority and project-guidance scope; read before changing shared permission boundaries.                                |
| [Provider Turn Progress](progress.md)                         | Payload-free progress, native stream correlation, parser bounds and failure precedence; read before changing progress or stream validation.                   |
| [Provider Capability Internals](registry.md)                  | Changing provider capability internals.                                                                                                                       |
| [Provider Requests](requests.md)                              | Model-free deadlines, bounded discovery, portable effort and diagnostic inventory attribution; read before changing request limits, selection or attribution. |
| [Provider Session Naming](session-naming.md)                  | Display context, native naming order, child acknowledgement and bounded metadata failure; read before changing naming or its consumers.                       |
| [Disposable Sessions and Source Lineage](sessions.md)         | Durable reconstruction, mode topology, context recovery and source-session consumption; read before changing session continuation or lineage.                 |
