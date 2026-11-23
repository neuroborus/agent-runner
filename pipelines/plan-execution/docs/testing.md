# Plan Execution Testing

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## 18. Testing

Use built-in `node:test`.

Do not add Jest/Vitest solely for this project.

Workflow policy tests use injected in-memory run-state, clarification, and
repository effects. Their repository double models fingerprints and Git-control
state deterministically while keeping task inputs and validation-path fixtures
confined to isolated temporary directories. Shared builders are exposed only
through `test/support/index.js`, and the workflow suite is split by contracts
and migrations, clarification and bootstrap, convergence and finalization,
recovery, and commit safety.

Real Git remains mandatory where Git behavior is the subject. Keep those cases
grouped in the commit-safety suite and the interrupted-staging recovery case;
`node:test` runs their top-level cases serially within each file. Root state,
Git, and cross-capability integration suites continue to own
proof of atomic files, journals, leases, recovery, filesystem durability,
snapshot semantics, commit verification, and handoff behavior. Normal tests
must not consume model usage.

At minimum cover:

1. deterministic plan parsing and exact commit-subject extraction;
2. invalid/non-sequential plan numbering and invalid commit-subject rejection;
3. clean-repository preflight;
4. task directory located inside the repository without state pollution;
5. independent read-only bootstrap;
6. bootstrap mutation detection;
7. successful implementation -> candidate review -> finalization -> terminal
   confirmation -> commit;
8. finalization failure -> fix -> retry;
9. candidate or terminal finding -> fix -> candidate reconvergence -> matching
   finalization reuse or changed-fingerprint re-finalization -> terminal
   confirmation;
10. dispute -> Reviewer withdraw;
11. dispute -> Reviewer uphold -> Arbiter;
12. fix/dispute/no-progress limits -> `WAITING_FOR_USER`;
13. additional fix budget after resume;
14. content fingerprint is independent of staging state;
15. content changes invalidate previous finalization/review;
16. read-only clarification, plan-compatibility, Reviewer, and Arbiter mutation detection;
17. unexpected Worker Git history/ref change outside the authorized `COMMIT` turn;
18. commit gate rejects unresolved findings;
19. commit staging does not invalidate the reviewed fingerprint;
20. authorized Worker turn creates exactly one direct, non-merge local commit;
21. commit messages containing `Co-authored-by` are rejected;
22. remote configuration changes by any agent are detected;
23. successful one-commit-per-plan-step progression;
24. interrupted run resumes from persisted state;
25. changed task/plan inputs are detected;
26. external repository changes while paused are detected;
27. Codex adapter command/result normalization;
28. Claude adapter command/result normalization;
29. `--clarify` opens the editor before the first Worker clarification turn;
30. `READY` closes clarification without opening the editor when `--clarify` is absent;
31. structured questions append to the transcript and remain read-only to the agent;
32. clarification round exhaustion and missing answers pause before bootstrap;
33. the frozen clarification hash is verified on agent turns and resume;
34. clarification input that conflicts with the validated plan pauses before bootstrap;
35. ordinary questions after `CLARIFY` are rejected;
36. a valid `PRODUCT_DECISION_REQUIRED` pause records the answer and invalidates dependent results;
37. a product answer that changes plan scope pauses with `plan_revision_required`;
38. the configured ignored artifact root remains outside the commit-content fingerprint;
39. preflight rejects a clarification path that the target repository does not ignore.
40. MCP input uses the same one-shot authorization and preserves exact answers;
41. MCP continuation cannot bypass the per-run lease or any local-commit gate.
42. frozen automatic, explicit, and skill-less finalization decisions preserve
    the dedicated gate and matching finalization/review fingerprints; selected
    guidance drift requires a fresh run.
43. MCP offers fresh start and compatible current-session fork choices while
    leaving the source unset unless the user deliberately selects the fork.
44. independently identified plan-execution or polishing runs cannot own the
    same canonical Git worktree concurrently, including through detached MCP
    dispatch, and a demonstrably stale same-host owner is recoverable.
45. compatible legacy state migrates under the execution lease; the real
    canonical root-and-sorted-pipeline compatibility calculation rejects an
    old-parent/new-child descriptor skew before lease acquisition or migration;
    and a fresh MCP process can retry the unchanged durable run and incomplete
    intent with the exact idempotency key.
46. sandbox, IPC, loopback, process-isolation, missing-service, and permission
    blockers affecting nondelegated work pause as `environment_blocked`, preserve
    safe content, and resume from the correct fingerprint-aware checkpoint.
    Selected-command limitations do not block repairs or candidate convergence
    in either mode. Every affected writable checkpoint, continued/reconstructed
    request, and lazy correction carries only persisted exact command text,
    including empty selections, while trusted execution remains in `FINALIZE`.
47. pre-effect local-commit policy and provider rejections renew only after the
    adapter proof and no-commit Git verification, while executor ambiguity and
    interrupted verification never replay the consumed authorization.
48. a pre-effect rejection followed by interrupted Git verification persists
    its bounded proof, resumes verification without replay, and renews only
    after the resumed verification confirms no commit.
49. blocked provider turns publish bounded role/phase before invocation;
    owner loss, timed-out MCP wait, ordinary resume, and interrupted one-shot
    verification preserve the lease-aware activity contract.
50. invalid Worker, Reviewer, reconciliation, arbitration, and validation-
    migration bootstrap results receive one durable read-only diagnostic-batch
    correction and repeated or still-invalid output fails closed without
    persisted rejected values.
51. all inspectable missing, directory, symlink, and symlink-traversing
    validation-infrastructure paths are batched before inventory acceptance
    with every producing field identified, while canonical existing files are
    accepted.
52. Codex `usageLimitExceeded`, `serverOverloaded`, and Claude structured status
    and permission classification are finite and redacted; explicit usage
    exhaustion and allowlisted Claude read-only failures reconstruct from
    durable state, eligible Codex overload receives the shared durable availability
    backoff without an immediate adapter retry, classified writable usage/provider failures preserve
    reconciled changes, and forbidden, authentication, ambiguous writable, and
    one-shot outcomes remain fail closed.
53. merged root/project trusted catalogs, deduplication, conflicts, 256-definition
    and 32-selection bounds, project-only alias selection, durable
    snapshot resume, exact-vector execution, bounded redaction, fingerprint
    drift, exact lexical round trips, and non-allowlisted substitutions fail
    closed.
54. service-backed runner checks combine with agent checks only for one exact
    fingerprint tuple, while blocked checks pause and workspace, Git, ref,
    remote, identity, ignored validation-infrastructure, leaked process-tree,
    remote-write, or ambient-credential effects are rejected.
55. conflicting role IDs, cross-role repeated commands and paths, role-only
    entries, runner-trusted commands, and attempted reconciliation inventory
    invention produce one stable complete runner-derived inventory.
56. every role prompt prohibits delegation, and a backend-reported delegated
    turn remains terminal while its finite class is redacted, durable, and
    projected consistently through CLI and MCP status.
57. 256/257-item role boundaries, disjoint 512-item derived inventories and
    513-item rejection, semantic infrastructure classification, unchanged byte bounds,
    persistence, finalization round trips, infrastructure fingerprinting, and
    strict capacity exhaustion remain bounded and consistent.
58. ownerless interrupted read-only and writable turns revalidate all durable
    inputs and Git controls, preserve only authorized partial content and index
    changes, invalidate dependent evidence, replace and clear activity in
    order, and never replay a consumed commit authorization.
59. skill-guided implementation, finding-resolution, finalization, and commit
    prompts preserve phase ownership: all substantive finalization work runs,
    commit preparation is deferred without blocking validation, and only the
    constrained commit executor stages the finalized and reviewed content.
60. staging-dependent bootstrap and validation-migration inventories batch
    every independently detectable unsafe command and inspectable invalid path
    into their one field-specific correction and then fail closed;
    finalization candidate inventories obey the same deterministic policy, and
    a paused version-5 implementation run re-establishes phase-safe context
    before finalization, review, and one authorized commit.
61. finalization validation batches every independently detectable staging-
    dependent command; permits only one wholly new second diagnostic batch;
    fails closed on repetition, mixed novelty, or exhausted allowance; and
    keeps corrected BLOCKED, PASS, and FAIL outcomes on their existing routes.
62. pending first and second finalization corrections survive interruption
    without replay or recounting, prompts and public activity retain no rejected
    content, and version-7 consumed and pending state migrates losslessly to the
    version-8 ledger.
63. exact finding overrides remain unique and fingerprint-bound, suppress only
    the named same-content finding, resolve a solely represented validation
    rejection without claiming Reviewer acceptance, and become inapplicable
    after content drift.
64. finalization candidates accept only existing canonical repository-relative
    regular validation files or the exact selected finalization-file label
    before fingerprinting or review, and version-8
    active runs migrate through fresh independent discovery without losing
    completed commits or safe current-step content.
65. version-9 consumed and pending bootstrap diagnostics migrate losslessly to
    one-entry batches, adjacent staging-dependent commands share one correction,
    and a pending multi-diagnostic batch resumes without replay or rejected
    content retention.
66. final Reviewer provider, normalization, and validation-change consistency
    failures receive one durable fresh-session read-only correction; valid
    approval, findings, validation-change, and product-decision replacements
    rejoin their existing routes; and repeated invalid output pauses for an
    explicit retry with no rejected-content retention.
67. pending final Reviewer correction survives interruption and backend
    unavailability without recounting, rejects read-only mutation and content
    or validation-infrastructure fingerprint drift, and version-10 active and
    terminal runs migrate without reconstructing unavailable output.
68. omitted mode preserves independent role probes, source forks, bootstrap,
    review, disputes, arbitration, and completion gates.
69. lazy mode probes, resolves, forks, and invokes only Worker, including one
    source fork across multiple commits and resume, and never invokes Reviewer
    or Arbiter.
70. a content-changing check/fix pass requires candidate convergence before
    full finalization, an unchanged pass requires a genuinely empty read-only
    candidate clean confirmation, and terminal-confirmation findings return to
    fixing.
71. claimed-clean mutation, actual read-only mutation, content drift, and
    validation-infrastructure drift cannot advance.
72. interruption at check/fix and clean-confirm checkpoints neither replays
    workspace effects nor double-counts rounds, while provider reconstruction
    never reforks the source.
73. lazy no-progress, stable-finding, fix, and additional-round behavior remains
    bounded without weakening exact commits, trusted checks, fingerprints, Git
    controls, product decisions, or no-coauthor/no-push rules.
74. every supported legacy version migrates through state version 35, preserving
    its saved mode and defaulting missing modes to `independent`, without
    fabricating effective-revision approval, reviving terminal runs or replaying
    completed or pending commit effects; unfinished work freezes guidance and repeats
    read-only validation discovery when prior evidence is provisional.
75. lazy provider and deterministic contract failures receive one scoped
    fresh-session correction; writable mutation re-finalizes and is counted
    once, clean correction remains read-only and fingerprint-bound, pending
    work survives interruption, and repeated invalid output resumes only by an
    explicit null retry with redacted diagnostics.

76. pure and mixed validation-evidence rejection in both modes invalidates stale
    finalization, preserves exact inventory checks and effect gating, and uses
    bounded durable semantic retries without code-fix accounting for pure recovery.
77. terminal-fingerprint overrides, including formatter drift and partial
    overrides, never restore invalidated evidence; interruption and unavailable
    providers preserve pending attempts, while explicit retries grant only one.
78. initial pre-work pause/cancellation settles under the run lease without an
    unrelated worktree lease, while every non-quiescent checkpoint retains
    worktree exclusion; detached stop supervision waits for settlement or the
    correlated child exit, and exact-revision action-free recovery with a new
    key preserves receipt replay, version skew, and single-owner safety.
79. [explicit-model catalog recovery](recovery.md#explicit-model-catalog-recovery)
    preserves the initial `IMPLEMENT` reservation, read-only restatement
    attempts, gate retries, validation-migration arbitration and COMMIT proof
    with their frozen inputs, scopes and counters; a generic, completed,
    stale or mismatched attempt, possible effects, a legacy `commit_failed`
    catalog pause and workspace drift grant no retry. Root suite ownership is
    in the [runner testing map](../../../docs/testing/runner.md#explicit-model-catalog-recovery).

Real Codex/Claude smoke tests should be opt-in integration tests. The owned
Codex smoke registers its supervised process and must read and validate the
repository `package.json` through a model-issued read-only command.
Provider smoke tests are not required finalization checks or runner-trusted
validation commands because both agent and trusted-validation sandboxes deny
provider network access. After the finalized commit is installed, the operator
runs the applicable opt-in smoke once on the host as separate integration
verification.

---

## Writable-result recovery

Read the [current contract](#plan-execution-testing).

## Trusted timing

Read the [current contract](#plan-execution-testing).

## Custom clarification compatibility

Read the [current contract](#plan-execution-testing).

## Effective revisions and progress

Read the [current contract](#plan-execution-testing).

## Revision validation

Read the [current contract](#plan-execution-testing).

## Replacement execution

Read the [current contract](#plan-execution-testing).

## Validation scheduling and diagnostics

Read the [current contract](#plan-execution-testing).

## Plan-kind policy

Read the [current contract](#plan-execution-testing).

## Custom accepted results

Read the [current contract](#plan-execution-testing).

## Bounded bootstrap

Read the [current contract](#plan-execution-testing).

## Legacy recovery

Read the [current contract](#plan-execution-testing).
