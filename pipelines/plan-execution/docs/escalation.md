# Execution Retry And Escalation

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Retry Limits and No-Progress Detection

Defaults:

```text
maxFixRoundsPerStep = 20
maxDisputesPerFinding = 5
maxSameFindingRounds = 5
stagnationWindowRounds = 3
```

A fix round is one Worker fix or lazy check/fix response followed by the
required candidate convergence and, once stable, the terminal gate.

Finalization failures that require code changes consume fix rounds too.

A blocked correction round is recorded after a completed fix when candidate
review or finalization fails, or when terminal confirmation returns
findings to its correction state. Persist its content fingerprint and exact
finalization issue or review finding IDs. This diagnostic history is bounded and uses exact IDs;
do not add fuzzy or semantic finding matching. Track consecutive exact-ID
counts separately so the configured stable-finding limit remains enforceable
beyond the retained diagnostic-history window.

No-progress detection in V1 is intentionally simple:

- if the same stable finding ID remains open for `maxSameFindingRounds` consecutive rounds, pause;
- do not implement fuzzy/semantic similarity detection.

Independent-mode disputes do not consume fix rounds. After `maxDisputesPerFinding` upheld
disputes, invoke one read-only per-finding arbitration. An Arbiter decision in
the Reviewer's favor leaves the finding blocking and requires a fix or explicit
user override; it does not permit another dispute of the same reviewed finding.

Lazy mode never invokes Reviewer or Arbiter and therefore has no dispute
budget. Content confirmation findings return to `CHECK_AND_FIX`; the existing fix,
stable-finding, and stagnation counters remain bounded, and
`--extra-fix-rounds` extends only the fix allowance without resetting history.

Reaching any limit **never** means accept-and-continue.

It always means:

```text
WAITING_FOR_USER
```

---

## User Escalation

Typical reasons:

```text
clarification_answers_required
clarification_append_interrupted
clarification_limit_reached
clarifications_changed
bootstrap_inventory_capacity_exhausted
local_artifacts_not_ignored
product_decision_required
plan_revision_required
finding_repair_required
fix_limit_reached
dispute_limit_reached
no_progress
finalization_skill_missing
finalization_skill_invalid
finalization_cannot_pass
finalization_evidence_rejected
lazy_output_invalid
review_output_invalid
effective_plan_output_invalid
read_only_agent_mutated_repository
unexpected_git_ref_change
unexpected_remote_configuration_change
unexpected_git_identity_change
unsafe_git_state
backend_unavailable
environment_blocked
arbiter_cannot_resolve
commit_failed
commit_contract_violated
```

When paused:

1. persist state;
2. append an event;
3. project and print the same bounded public pause used by MCP status and wait;
4. do not advance.

The descriptor-owned public pause contains only its finite reason, an optional
validated bounded diagnostic code, concise explanation, bounded evidence,
validated resume checkpoint, and applicable next actions. It omits prompts,
transcripts, credentials, native responses, raw standard error, rejected
structured values, internal diagnostics, and private counters. The root
separately projects a pending input request without copying it into the pause.
An input awaiting detached continuation has no second action.

Next actions preserve the existing validation contract: an identified input
uses `respond`; a safe retry carries a null resume action; an exhausted fix
budget carries one concrete valid additional round; and each currently
overridable finding receives its exact ID. `plan_revision_required` preserves
the validated rationale and evidence but offers only revision of `plan.md` and
a fresh execution run. `read_only_agent_mutated_repository` explains that the
run is contaminated and offers only a fresh run from an uncontaminated
worktree; it never accepts hybrid changes. Its one evidence line names the
Git-classified changed snapshot domains retained as `snapshotChanges`, for
example `Changed snapshot domains: head, index.`, and the activity message adds
the same sentence. Custom and directory workspaces, legacy pauses, and
unclassified or unknown labels report `unavailable`; input invalidation still
clears approvals and grants no retry, commit, or resume. `environment_blocked` preserves why
nondelegated work or finalization is blocked, its bounded evidence, and the
exact retry checkpoint.
For a finalization-backed `no_progress` pause, the descriptor derives immutable
bounded evidence solely from the active validated `F`-prefixed finalization
issue IDs. Commands, problems, issue evidence, paths, raw provider output,
pause internals, and clarification data remain private; Reviewer finding data
remain outside this finalization-backed projection. Any validator-approved
recovery, including a pending validation-migration retry, remains the only
projected action. Otherwise the sole action is
`{ type: "start-new-run", requirement: "resolved-finalization-blockers" }`,
which requires resolving the reported blockers, restoring a clean baseline,
and preparing a plan for the remaining work before starting a fresh execution
run. It grants no extra correction round, finding override, or stagnation-history
reset. Reviewer-backed `no_progress` continues to expose only public Reviewer
findings and exact actions accepted by resume validation, including applicable
fingerprint-bound overrides in independent mode.
This read-only projection does not itself change the pipeline state version.
CLI status and MCP status, wait, and activity also expose the persisted resolved
mode, while `pipelines_list` exposes descriptor-owned values, default, and
recommendation. None exposes inactive role configuration or provider-private
data.

Example:

```text
Run paused.

Step:
Commit 3: feat(market): add cache

Reason:
Fix limit reached after 5 rounds.

Open finding:
R7 — Cache invalidation may be missing on updateMarketConfig().

Available actions:
- grant additional fix rounds;
- send/re-send to Arbiter;
- re-run review;
- explicitly override/close a finding;
- abort.
```

Support finite additional fix budget:

```bash
agent-run resume \
  --run <run-id> \
  --extra-fix-rounds 3
```

Do not reset previous counters/history.
