# Execution Finding Resolution

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Resolve findings

The Worker receives all currently open blockers together. Independent review
findings may be fixed or disputed. Finalization failures use this path in both
modes and must be fixed; lazy mode has no review-finding dispute or arbitration
path.

Finding resolution fixes or disputes the current blockers and then returns
control. It does not invoke project finalization or perform generic commit
preparation; a content-changing fix returns to independent `REVIEW` or lazy/combined
`CHECK_AND_FIX` candidate convergence before the dedicated `FINALIZE` gate.
The established required-check inventory remains input to that gate and is not
phase-local finding-resolution work.

For each finding it returns:

```text
FIX
```

or:

```text
DISPUTE
```

If an external environment constraint prevents nondelegated work during
resolution, the Worker may instead return `BLOCKED` with no decisions and
bounded reason and evidence. A selected trusted command's agent-sandbox
limitation alone cannot block repairs; execution remains owned by `FINALIZE`.
When the turn changed content, the runner preserves the partial fix,
invalidates prior candidate, finalization, and confirmation evidence, and
resumes at `REVIEW` or `CHECK_AND_FIX` according to mode.
When content is unchanged, it preserves the current blockers and resumes at
`RESOLVE_FINDINGS`.

An explicit null-action resume from `environment_blocked` at
`RESOLVE_FINDINGS` instead retries complete `FINALIZE` when the persisted failure
contains only opaque runner-trusted failures. Every failed check must have
runner provenance, and the complete ordered issue list must match the issues
the runner generates from those checks, including IDs, commands, fixed problem
text, and bounded evidence. An agent-authored issue, an agent-executed failure,
or any pending finding, dispute, or reconsideration excludes this retry.
Candidate acceptance must remain valid. Revalidate frozen inputs, repository
safety, and the failed content and validation-infrastructure fingerprints before
atomically clearing terminal evidence and entering `FINALIZE`.

This path works in independent, lazy, and combined modes and repeats the whole
Worker finalization procedure followed by the runner's own exact trusted checks.
It preserves candidate evidence and correction accounting; it neither grants a
fix round nor resets a budget. Success still requires the mode's distinct
terminal confirmation over fresh evidence. Another failure returns to ordinary
finding resolution; another unchanged `environment_blocked` pause requires
another explicit resume. No automatic retry, retained native output, host
attestation, or broader execution authority is introduced. Ordinary and mixed
failure sets keep the existing resolution path.

### FIX

If the Worker agrees:

1. fix all accepted findings in one fix round;
2. return control;
3. run complete candidate convergence again;
4. rerun finalization when content or validation infrastructure changed;
5. otherwise reuse matching, non-rejected successful finalization evidence;
6. run one fresh terminal confirmation.

When one resolution batch mixes `FIX` and `DISPUTE`, preserve the disputes
through complete candidate re-review, then let the Reviewer reconsider them
before finalization can begin.

### DISPUTE

A dispute must contain concise evidence.

Example:

```text
Finding: R3
Decision: DISPUTE

Reason:
updateMarketConfig() delegates to saveMarket(), which performs invalidation
after persistence succeeds.

Evidence:
- src/market/service.js:142
- src/market/repository.js:88
- existing invalidation test
```

Valid evidence includes:

- source code;
- tests;
- task/plan wording;
- project documentation;
- prior accepted decisions;
- concrete execution paths.

A bare disagreement is invalid.

The Reviewer must reconsider the dispute and return:

```text
WITHDRAW
```

or:

```text
UPHOLD
```

with a concise reason.

## Arbiter

Lazy mode never invokes the Arbiter. In independent mode, use the Arbiter only
when:

- a material bootstrap disagreement remains; or
- a Worker/Reviewer dispute remains unresolved after the configured dispute budget.

Combined permits only independent finding resolution arbitration, including
finding-based stagnation. Bootstrap disagreement and primary exhaustion pause
without invoking an Arbiter.

Give the Arbiter only:

- relevant task/plan requirement;
- finding;
- Worker evidence;
- Reviewer response;
- relevant code/diff;
- relevant established decisions.

Possible outcomes:

```text
WORKER_CORRECT
REVIEWER_CORRECT
REQUIREMENT_AMBIGUOUS
```

The Arbiter never rewrites requirements.

Per-finding arbitration preserves this mandatory core:

```text
Resolve the disputed finding from the task, plan, repository, diff, and evidence, choosing the correct outcome using the provided schema.
```

Correction-loop stagnation is a separate arbitration episode for correction
churn that has not already reached the stable-finding limit. After the first
`stagnationWindowRounds` consecutive blocked correction rounds, invoke one
fresh read-only Arbiter with compact persisted history and this mandatory core:

```text
Diagnose why the implementation correction loop is not converging and choose the minimal valid next direction using the provided schema.
```

Its structured directions are `CONTINUE_FIXES`, `REWORK_IMPLEMENTATION`,
`RECONSIDER_FINDINGS`, `PLAN_REVISION_REQUIRED`, and
`PRODUCT_DECISION_REQUIRED`. The result cannot approve work, resolve a finding,
reset a budget, or satisfy the commit gate. Content changes remain Worker-only,
and finding reconsideration remains Reviewer-only. If another complete blocked
window accumulates after this arbitration, pause instead of invoking it again.

## Exact finding overrides

Also support one explicit override of a currently open finding for the exact
current reviewed fingerprint:

```bash
agent-run resume \
  --run <run-id> \
  --override-finding R7
```

Both resume actions are valid only for an applicable paused run. The override
removes only the named finding, does not approve any other finding, and becomes
stale as soon as the reviewed content fingerprint changes.

Override audit entries are unique by finding ID and reviewed fingerprint. A
complete re-review deterministically suppresses only an exact applicable
override; unrelated findings remain blocking. When a rejected validation
change is represented only by overridden findings for that same fingerprint,
the override resolves that blocker without changing the persisted Reviewer
decision to `ACCEPTED`. The same applicable override is neither offered nor
stored again.

A user override must be explicitly recorded in the event journal and `progress.md`.

---
