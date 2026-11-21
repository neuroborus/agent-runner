# Execution Review And Confirmation

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Independent review

In independent mode, use an independent Reviewer context first to converge the
semantic candidate and again, after finalization passes, to confirm the
finalized content and evidence. These are distinct prompts, schemas, persisted
results, and public activities.

Use one Reviewer checkpoint per planned commit, reused for complete re-review
and dispute handling within that commit.

Candidate review receives:

- task;
- current plan step;
- resolved bootstrap context;
- relevant prior decisions;
- previous findings for this step, if any;
- current repository state/diff;
- no finalization result or terminal-attestation request.

It reviews:

- correctness;
- completeness;
- plan compliance;
- regression risk;
- architecture consistency;
- tests;
- edge cases;
- unintended scope expansion;
- project conventions.

After the candidate is accepted, `FINALIZE` runs the complete procedure for
that stable content; semantic evidence recovery may require replacement runs.
The separate read-only `CONFIRM` turn then compares the established and candidate check inventories,
infrastructure file sets, runner-computed fingerprints, and exact per-check
evidence. The fresh review request carries both complete tuples rather than
depending on earlier session context. An unchanged gate with sufficient evidence
is recorded as `UNCHANGED`; insufficient evidence requires `REJECTED` even when
the gate inventory is unchanged. Any change must be
explicitly `ACCEPTED` as authorized by the current plan step or `REJECTED` with
a finding. The decision and its bounded evidence are bound to the same content
fingerprint as terminal confirmation. Exactly one successful confirmation
advances directly to `COMMIT`.

Reviewer and lazy terminal confirmation do not treat leaving out explicit
post-completion operator acceptance as an omission. They reject evidence or
summaries claiming that such acceptance ran or passed and a finalization that
adds it, while a missing genuine pipeline-owned check remains an omission.
Candidate review, lazy self-review and terminal confirmation also report
evidence that reserved work actually ran early or that development evidence is
claimed as reserved coverage, even when final acceptance stays pending; source
observation, overlap or undecidable evidence alone is not a confirmed
violation. Dispute reconsideration and arbitration decide such a finding by the
allegation it makes, never by the label. This semantic rule follows the
[validation ownership guarantee](../../../docs/product/VALIDATION_AND_REVIEW.md#bootstrap-inventory).

The Reviewer must not receive the Worker's private implementation reasoning.

Machine-actionable review output:

```json
{
  "status": "FINDINGS",
  "findings": [
    {
      "id": "R3",
      "file": "src/example.js",
      "problem": "Cache invalidation is missing on one path.",
      "reason": "...",
      "suggestedAction": "..."
    }
  ],
  "question": "",
  "options": [],
  "whyBlocked": "",
  "evidence": []
}
```

All findings are blocking until resolved. Severity is unnecessary for V1 workflow logic.

Finding IDs must remain stable across re-review:

- reuse an existing ID when the same finding remains;
- assign a new ID only to a genuinely new finding.

The runner must not implement fuzzy semantic matching of findings in V1.

When candidate review finishes successfully, persist its fingerprint and enter
`FINALIZE`, except that a still-current retained finalization record returns
directly to `CONFIRM`. When terminal confirmation finishes successfully,
persist its separate reviewed fingerprint and enter `COMMIT`.

If the candidate schema or final `REVIEW_SCHEMA` provider reports the shared structured-output
failure class, deterministic normalization rejects the result, or the
validation-change decision conflicts with accepted finalization evidence, map
the failure to bounded candidate-review or confirmation field-and-constraint diagnostics.
Candidate-review normalization, shared by Reviewer candidate review and lazy or
combined `CLEAN_CONFIRM`, identifies shape and status, inactive decision fields,
status/findings consistency, finding identity, content, uniqueness and stability
at `findings[i]` positions, and product-decision fields by fixed schema field
names, never by values or IDs. Final review and confirmation share the same
finding count, identity, content and uniqueness identities. Unknown and
historical causes stay `result`/`semantic-contract`. After
the first invalid result, durably record automatic attempt `1` and publish only
one redacted `review-correction` activity. Reconstruct the complete review
request from durable task, plan, context, prior-decision, and the applicable
candidate or finalization fingerprint state, then invoke a fresh read-only Reviewer session with the
unchanged schema. Never rely on or continue the rejected native session.

Before accepting the replacement, reapply input, repository, read-only, Git-
control, content-fingerprint, validation-infrastructure-fingerprint, and
applicable evidence guards. Preserve accepted finalization evidence only while
the applicable provider-correction scope is unchanged. Validation-
infrastructure or correction-scope drift invalidates the finalization record
and re-enters `FINALIZE`; content or control drift invalidates all dependent
evidence and follows the existing safe reconciliation path. A valid replacement
rejoins the ordinary approval, findings, validation-change, and product-decision
routes. Candidate-review and candidate clean-confirmation corrections bind the
Runner's live inspection of the established inventory, which may differ from
the established fingerprint after an authorized infrastructure edit. An
accepted terminal validation change replaces the established tuple without
invalidating or renewing a consumed candidate correction.

If a corrected candidate result remains invalid, pause at
`review_output_invalid` with resume state `REVIEW`. If a corrected terminal
result remains invalid, pause at `confirmation_output_invalid` with resume
state `CONFIRM`. Both expose bounded public field-and-constraint evidence and one
explicit null retry action. That retry reconstructs and reruns the pending
fresh-session, read-only correction without incrementing attempt `1`; another
invalid result pauses again. It cannot approve work, accept findings, alter
finalization evidence, or bypass fingerprint, Git, finding-resolution, or
commit-authorization gates. Interruption or backend unavailability before or
during correction retains the pending attempt for the same reconstruction and
does not replay accepted progress or require a native session. Rejected values,
findings, commands, paths, provider output, prompts, and transcripts are never
persisted or published.

## Lazy check/fix and clean confirmation

In lazy mode, implementation enters `CHECK_AND_FIX`, never `REVIEW`. The Worker
receives the whole current commit result, the bounded trusted-command projection
specified for implementation, and mandatory candidate-review core without
finalization evidence. This is a workspace-write turn: every
problem it identifies must be fixed immediately, idiomatically, minimally, and
within the current planned commit. Its strict result reports whether content
changed, remained unchanged, is externally blocked, or reaches the narrowly
valid product-decision outcome.
The runner compares that claim with the actual content fingerprint.

Any content change clears candidate, finalization, and confirmation evidence
and returns to another `CHECK_AND_FIX` pass. An unchanged pass is not approval;
it enters the separate read-only candidate `CLEAN_CONFIRM` state over the exact
candidate fingerprint. That turn uses the same semantic criteria, forbids
edits, and returns only structured `CLEAN`, concrete findings, or the narrow
product-decision outcome.
A status/content mismatch is invalid output, actual read-only mutation is
rejected, and fingerprint drift pauses without advancing.

Invalid provider or deterministic checkpoint output follows the durable lazy
correction policy above. A valid replacement rejoins the ordinary checkpoint
route and cannot itself accept finalization, confirmation, review, or commit
evidence. Content-changing invalid or interrupted check/fix work is reconciled
exactly once and resumes only at the original check/fix checkpoint. Candidate
clean-confirmation correction never
receives workspace-write authority.

Concrete confirmation findings return directly to `CHECK_AND_FIX`; they are
not disputes and cannot invoke Reviewer or Arbiter. A mutation-free candidate
`CLEAN` result with an unchanged fingerprint enters `FINALIZE`, or returns
directly to `CONFIRM` when retained finalization evidence still matches the
recomputed content and validation-infrastructure fingerprints. A passing
finalization enters the distinct read-only `CONFIRM` state, where
the Worker receives the established and finalized validation tuples and
returns `CLEAN`, findings, or the narrow product-decision outcome together with
`UNCHANGED` or task-authorized `ACCEPTED` validation change. Ordinary terminal findings
return to `CHECK_AND_FIX`; pure evidence rejection uses the separate finalization
recovery route, and mixed rejection sends only content findings to fixing; exactly one successful terminal clean confirmation
records the reviewed and terminal-clean fingerprints and enters `COMMIT`. The loop consumes the existing fix, stable-
finding, stagnation, and additional-fix-round budgets. Exhaustion pauses at the
applicable checkpoint and never treats a non-clean result as accepted.
