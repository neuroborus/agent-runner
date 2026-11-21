# Core guarantees

## Core Guarantees

Plan execution pauses for plan revision when initial implementation leaves the
selected step's content unchanged. Runner-observed step-start evidence survives
partial work and resume; missing legacy evidence must be reconstructed from the
validated journal before new writable work. Unchanged corrective turns remain
valid after initial acceptance. See the execution specification (`pipelines/plan-execution/docs/SPEC.md`).

- Pipelines own their roles, inputs, prompts, state machines, and output policy.
- The root runner owns lifecycle, persistence, backend execution, and Git safety.
- Every pipeline starts with a bounded, read-only `CLARIFY` phase.
- After clarification closes, a blocking material product decision pauses the
  pipeline through `PRODUCT_DECISION_REQUIRED`.
- Every built-in pipeline supports `independent`, `lazy`, and `combined` modes.
  `independent` is the default and recommended choice because it provides
  genuinely independent semantic review, at the cost of more provider context
  and tokens. `lazy` is an explicit lower-consumption choice that uses only the
  primary agent and does not provide independent review; it is never selected
  automatically. `combined` adds primary
  convergence followed by independent review.
- Codex and Claude can be selected independently for each pipeline role.
- Read-only agent turns include repository-mutation verification.
- Codex repository writable turns expose an existing real project `.agents` directory,
  while role prompts permit changing it only for an explicit task requirement
  and, during plan execution, an explicit current plan step. A symlinked
  `.agents`, `.git`, and `.codex` stay protected.
- The adapter foundation also supports declared directory reads and output-only
  writes in Codex 0.164.0 or newer and Claude Code 2.1.233 or newer on Linux,
  without Git or commit readiness. Claude writes through sandboxed Bash to
  existing declared output roots. Explicit custom execution uses these directory permissions; see the provider contract (`docs/product/PROVIDER_MODEL.md`).
  Codex's named-profile route refuses existing regular-file output roots,
  including dotfiles, before writable preparation or native execution. Use
  directory outputs or select a supported backend in an authorized fresh run;
  no parent write grant or automatic backend substitution is applied. Read-only
  file declarations remain supported. This is a route limitation, not a blanket
  unsupported Codex version range.
- The runner lifecycle foundation selects workspace and lease requirements from
  pipeline descriptors before Git inspection. Directory bindings, protected
  inputs and output permissions survive recovery; repository-contained directory
  work shares the enclosing worktree lease. Explicit custom authoring uses that
  directory lifecycle, as does explicitly selected custom execution; commit authoring, commit execution and polishing require Git. Missing Git never selects another completion contract.
- `plan-authoring` confines writes to its resolved `clarifications.md` and
  `plan.md` artifact paths, including task directories inside the target
  repository.
- In `plan-execution`, the Worker receives one-shot authorization for the exact
  planned local commit after candidate convergence, successful finalization,
  and a distinct read-only terminal confirmation.
- `polishing` finalizes and applies the selected review gate to existing
  workspace changes while preserving `HEAD` for a later commit workflow.
- Commit creation uses the repository's configured Git identity and the exact
  subject-only Conventional Commit message; validation includes
  `Co-authored-by` in its trailer denylist.
- Retry exhaustion and unsafe states pause with unresolved work preserved.
- Persistent state lives outside both the target repository and task directory.
- Remote repositories and their configuration remain read-only in V1.
