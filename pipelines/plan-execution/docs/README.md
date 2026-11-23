# Plan Execution Contracts

Read the matching topic before changing its contract. The [document map](../../../docs/README.md)
owns the change gate. Read only the affected owners and their required references.

| Topic                                                                  | Read when                                                                                                                                           |
| ---------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Plan Execution Pipeline — Implementation Specification](SPEC.md)      | Goals, technology baseline, per-commit role cores, terminal UX, testing, mandatory invariants and acceptance                                        |
| [Execution Agent Adapter Contract](adapters.md)                        | Provider-neutral requests, capability probing, session lineage, failure normalization and one-shot effect proofs                                    |
| [Execution Inputs And Plan Kinds](admission.md)                        | Task files, clarification artifact placement, deterministic parsing, exact subjects and explicit commit/custom authority                            |
| [Execution Backend Behavior](backends.md)                              | Native Codex/Claude invocation, permissions, session recovery, isolated commit execution and backend-neutral guidance                               |
| [Execution Clarification And Bootstrap](bootstrap.md)                  | Clarification and plan compatibility, mode-specific bootstrap, per-step validation inventories, bounded discovery/correction and reconciliation     |
| [Execution Commit Authorization And Verification](commit.md)           | Gate prerequisites, one-shot executor authority, exact subjects, Git verification and consumed-effect settlement                                    |
| [Execution CLI And Configuration](configuration.md)                    | Commands, modes and combined admission, roles, source sessions, settings, frozen guidance, trusted commands or capability discovery                 |
| [Custom Execution](custom-execution.md)                                | Criteria/declarations, result receipts, output preparation, directory access and custom state compatibility                                         |
| [Execution Effective Revisions and Validation](effective-revisions.md) | Proposal/approval authority, completed provenance, finding ownership, consumed budgets and additive validation rebinding                            |
| [Execution Retry And Escalation](escalation.md)                        | Fix/dispute limits, no-progress accounting, public pauses and additional rounds                                                                     |
| [Candidate Convergence and Finalization](finalization.md)              | Phase ordering, required checks, evidence acceptance, fingerprint invalidation, semantic recovery and bounded output correction                     |
| [Execution Finding Resolution](findings.md)                            | Fixes, disputes, reconsideration, mode-specific arbitration and exact fingerprint-bound user overrides                                              |
| [Execution Implementation and Size Assessment](implementation.md)      | Worker outcomes, initial implementation evidence, eligibility, size thresholds and read-only assessment allowances                                  |
| [Execution Operator Stops](operator-stops.md)                          | Immediate/deferred pause and cancellation, process retirement, owner loss and atomic consumed-effect settlement                                     |
| [Execution Persistence](persistence.md)                                | Storage and leases, state fields and migrations, write-ahead journals, progress and managed artifacts                                               |
| [Execution Checkpoint Recovery](recovery.md)                           | Resume, legacy terminal proof, writable-result restatement, unfinished repair continuation, ownership uncertainty, output exhaustion and inactivity |
| [Execution Refinement Progress](refinement-progress.md)                | Derived original/replacement status, confined progress-artifact publication and CLI/MCP projections                                                 |
| [Preserved Replacement Execution](replacement-execution.md)            | Durable capture/restoration, activation and legacy eligibility, separation, reconstruction and replacement effect gates                             |
| [Execution Repository Safety](repository-safety.md)                    | Plan-position evidence, Git/ref/remote/identity protection, read-only mutation guards and content fingerprints                                      |
| [Execution Review And Confirmation](review.md)                         | Independent candidate review, primary clean confirmation, terminal evidence acceptance and bounded output correction                                |
| [Plan Execution Testing](testing.md)                                   | Execution-suite ownership, invocation conditions, slow dependencies and evidence limits                                                             |
| [Runner-Trusted Validation](trusted-validation.md)                     | Selected-check applicability, assigned executors, frozen vectors, isolation, receipt timing and evidence custody                                    |
| [Historical Validation Noncompliance](validation-history.md)           | Changing historical validation noncompliance.                                                                                                       |
| [Transient Validation Storage](validation-storage.md)                  | Allocation and acquisition ownership, process retirement, cleanup uncertainty and frozen-request recovery                                           |
| [Execution Workflow And Gate Evidence](workflow.md)                    | Persisted states, mode-specific routing, evidence predicates, invalidation and session topology                                                     |
