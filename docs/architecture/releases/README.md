# Release Lifecycle

Read the matching topic before changing its contract. The [document map](../../README.md)
owns the change gate. Read only the affected owners and their required references.

| Topic                                               | Read when                                                                                                                                                   |
| --------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Candidate activation and restart](activation.md)   | Apply/status operations, activation intents, consumed-selection recovery and restart requirements; read before changing candidate selection or activation.  |
| [On-demand release compatibility](compatibility.md) | Official identity, on-demand checks, version selection and contract comparison; read before changing approval or compatibility policy.                      |
| [Local application packaging](packaging.md)         | Standalone assembly, production closure, manifests, archive inspection and delivery acceptance; read before changing packaged resources or release tooling. |
| [Exact candidate preparation](preparation.md)       | Exact construction, confined native effects, smoke proof and interrupted recovery; read before changing candidate preparation or verification.              |
