# Durable State Contracts

Read the matching topic before changing its contract. The [document map](../../README.md)
owns the change gate. Read only the affected owners and their required references.

| Topic                                                     | Read when                                                                                                                                               |
| --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Issue Storage and Publication](issues.md)                | Issue capability, publication intents, exact retries and revisioned replacement; read before changing deliberate-report storage or effects.             |
| [Durable Lease Bindings](leases.md)                       | Canonical keys, overlapping scopes, owner identities, atomic publication and fixed correctness guards; read before changing exclusion or lease storage. |
| [Durable Observations and Measurements](observations.md)  | Retained attempts, batching, byte measurements and public projection; read before changing diagnostic persistence or consumers.                         |
| [External State Storage](storage.md)                      | State capability, run/action locations and preservation references; read before changing placement or storage bindings.                                 |
| [Durable Workspace Preparation](workspace-preparation.md) | Frozen admission, capture, source selection, deferred audit preparation and completed workspace bindings; read before changing preparation or recovery. |
