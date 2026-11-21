# Execution Workflow And Gate Evidence

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Workflow

Persisted workflow states:

```text
CLARIFY
BOOTSTRAP
IMPLEMENT
REVIEW
CHECK_AND_FIX
CLEAN_CONFIRM
FINALIZE
CONFIRM
RESOLVE_FINDINGS
COMMIT
WAITING_FOR_USER
DONE
FAILED
```

`CHECK_AND_FIX` and `CLEAN_CONFIRM` are used in lazy and combined modes. `FIX`,
`DISPUTE`, `ARBITRATE`, implementation self-review, and per-step context refresh
remain actions within the owning independent-mode states rather than separate
persisted states.

The private `mode-policy.js` owns the separate decisions for active roles,
independent bootstrap, primary convergence, independent review, terminal
confirmer, bootstrap versus finding arbitration eligibility, and session lineage.
The accepted modes are `independent`, `lazy`, and `combined`. The descriptor and persisted settings contract
validate modes; policy selection does not introduce another configuration API.

Implementation, content-changing finding resolution, migration re-entry, and
stop reconciliation share candidate routing: `REVIEW` for independent mode,
`CHECK_AND_FIX` for lazy and combined modes. Content findings from terminal evidence rejection
use independent finding resolution or direct primary fixing; pure evidence
rejection still repeats finalization without code-fix accounting. The terminal
confirmer and journal recovery use the same role decision.

The private `gate-evidence.js` owns composable evidence predicates and
invalidation. A candidate record must name its inspected fingerprint; independent
approval requires approval or exact fingerprint-bound finding overrides, while
lazy approval requires the primary clean confirmation. Combined requires both
primary confirmation and independent approval for the same candidate. Passing finalization has
its own resulting fingerprint, and terminal confirmation must match that result
with no unresolved findings or disputes before new commit authorization. A
formatter may change the candidate fingerprint without rewriting candidate proof.

Persisted validation and workflow routing use the same predicates. Content repairs,
including interrupted repairs reconciled for a stop, clear dependent approvals;
unchanged finding resolutions clear candidate and confirmation approval but may
retain passing finalization. Reuse still requires fresh content and infrastructure
fingerprint checks after candidate convergence. Existing correction scopes and
budgets are preserved. Migration uses the same invalidation rules without
reopening consumed commits, and legacy confirmation recovery additionally requires
its validated journal proof. Successful settlement clears evidence for the next
step and retains the final step's evidence at `DONE`.

Session selection is independent of routing: lazy's logical Worker consumes
its source fork once across all checkpoints, independent and combined Worker and Reviewer
contexts fork by checkpoint, and recovery or explicit output correction reconstructs
freshly. Arbiters never inherit a source or prior child. Existing persisted
`lazyCorrections`, `pendingLazyCorrection`, and `lazySourceForkConsumed` shapes
remain unchanged. Accepted or reconciled repair work is charged once; invalid
output replacement does not renew budgets. Worker access, read-only guards,
protected-input checks, and commit authorization remain in the owning turn and
reconciliation paths, independent of mode selection.

Only the runner controls transitions.

---
