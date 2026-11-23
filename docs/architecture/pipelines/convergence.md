# Primary Convergence

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

Lazy convergence is a bounded pipeline-owned loop. A writable
`CHECK_AND_FIX` turn reviews the complete current result with the established
pipeline review criteria and fixes any problem immediately. An unchanged
result enters a separate read-only `CLEAN_CONFIRM` turn with the same criteria,
an explicit edit prohibition, and a strict `CLEAN` or concrete-findings result.
Advancement requires `CLEAN`, no repository mutation, and the exact inspected
content fingerprint. In plan execution and polishing this first converges the
candidate; `FINALIZE` follows, then a distinct read-only `CONFIRM` applies the
validation-change decision to the finalized evidence.
Content findings return directly to `CHECK_AND_FIX`, never to dispute or arbitration.
Ordinary terminal findings clear candidate and confirmation attestations but retain a
successful finalization record while its content and validation-infrastructure
fingerprints remain current. After candidate convergence, the runner recomputes
both fingerprints and retries `CONFIRM` directly on an exact match; otherwise it
invalidates the record and returns to `FINALIZE`. Declared fixes do not stand in
for observed repository mutation. Every actual content or validation-
infrastructure change, provider correction-scope drift, content-changing
interruption reconciliation, and plan-execution commit-step advancement
invalidates finalization evidence. Plan-authoring drafts stay
in external state and are deterministically validated only after confirmation.
Plan execution and polishing route pure validation-evidence rejection directly
to bounded replacement finalization; mixed rejection returns through candidate
convergence before fresh finalization. Both require a fresh terminal confirmation.
Existing fix/revision, stable-finding, stagnation, and additional-round budgets
bound the loop and never silently accept an unconfirmed result.
