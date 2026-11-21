# Polishing Workflow And Candidate Convergence

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Combined Review

Combined mode uses independent Worker/Reviewer bootstrap discovery and
reconciliation, all active roles, and independent source checkpoint forks.
Unresolved bootstrap or validation-migration disagreement pauses for explicit
retry without Arbiter. Independent remains the default and recommended mode.

After `POLISH`, Worker `CHECK_AND_FIX` and a separate read-only `CLEAN_CONFIRM`
must converge before independent `REVIEW`. Durable `primaryFindings` retain
self-findings for direct fixing; they never replace independent findings or
enter dispute/override/arbitration routes. Candidate confirmation and independent
approval bind the same fingerprint. `FINALIZE` follows, then independent Reviewer
`CONFIRM` covers the formatter's result and validation evidence before `HANDOFF`.

Independent findings retain the full fix, dispute, withdrawal, exact override,
and fresh finding-arbitration workflow. Content-changing repairs restart primary
convergence and invalidate dependent approval; unchanged resolution can reuse
current finalization only after both candidate gates reconverge. Neither primary
exhaustion nor non-finding failures permit arbitration. Corrections use existing
bounded ledgers and counters, including exact-once interrupted correction charging.
Every agent still lacks index authority. The runner alone stages the accepted
handoff and never creates a polishing commit.

State version 13 adds `primaryFindings`. The version-12 leased migration initializes
it empty and preserves saved mode, budgets, approvals, and completed handoff
recovery. Missing legacy mode remains independent.

## Workflow

The explicit persisted states are:

```text
CLARIFY
BOOTSTRAP
POLISH
REVIEW
CHECK_AND_FIX
CLEAN_CONFIRM
FINALIZE
CONFIRM
RESOLVE_FINDINGS
HANDOFF
WAITING_FOR_USER
DONE
FAILED
```

`CHECK_AND_FIX` and `CLEAN_CONFIRM` are lazy and combined primary-convergence states.
`REVIEW` is the independent candidate-review state, while `CONFIRM` owns
the mode-specific terminal read-only confirmation. Only runner-owned transition
code advances the workflow.

### Polish

The Worker starts a fresh work checkpoint with the validated inputs, current
change-set fingerprint, resolved context, active blockers, and bounded decision
history. It receives workspace-write access and brings the whole existing
change set to a correct, idiomatic, minimal result, follows the task and project
conventions, and performs a concise self-review. Finding fixes reuse this
checkpoint. The Worker may add or remove safe workspace content when
correctness requires it. It must not stage or unstage changes, alter the index
or other Git metadata, create a commit, change `HEAD` or refs, reconfigure
remotes or Git identity, or perform a remote write. The runner owns final
staging after candidate convergence, finalization, and the distinct terminal
confirmation pass.
The complete and recovery prompt for each Worker and Reviewer checkpoint treats
project `.agents` changes as authorized only when the user's task explicitly
requires them; otherwise the role neither makes nor approves those changes.
Compatible continuation turns inherit this responsibility from their native
session without repeating it. A violation follows the ordinary finding-and-fix
path and never reopens user questions.

Polishing, lazy or combined `CHECK_AND_FIX`, and finding-resolution prompts
receive only the exact command text selected in persisted `trustedValidation.commands`.
The bounded projection accompanies complete, continued, reconstructed, and
correction requests and is an empty array for an empty selection. It does not
reload configuration, expose executable vectors or provider settings, or repeat
the complete validation inventory. Inventory-reporting and `NOT_RUN`
instructions remain in their existing bootstrap and finalization contexts.

Established required-check execution and attestation belong exclusively to
`FINALIZE`. Selected runner-trusted commands never execute inside agent turns.
Their agent-sandbox limitations must not cause `BLOCKED` or prevent applicable
content repairs and semantic review; the runner executes the persisted exact
vectors during `FINALIZE`. Explicit owner and timing assignments bind
validation work by its actual purpose, scope and evidence rather than its
label, so these turns neither run nor claim work reserved for another owner or
later checkpoint. Permitted source inspection and focused development tests
stay development evidence even when they overlap a reserved check, which still
runs in full under its owner.

An external environment constraint affecting nondelegated work pauses at
`POLISH` without discarding safe Worker changes. Any stale candidate,
finalization, and terminal-confirmation results are invalidated before the pause.
