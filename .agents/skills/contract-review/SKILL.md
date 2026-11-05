---
name: contract-review
description: Review a changed structured agent-role or public contract across its specification, schema, instructions, semantic validation, persistence, diagnostics, and recovery. Use for contract changes or contract-failure investigations, not unrelated source edits.
---

# Contract Review — Agent Runner

Review one identified contract through its actual consumers, within the current
task's assigned role and gate. This procedure does not authorize additional
reviewers or pipeline roles, invocation, mutation, retrieval, or recovery.

## Establish the review target

- Identify the owning capability or pipeline, changed producer/consumer boundary,
  applicable specification, supported versions, and requested behavior.
- Read the actual request/result definitions, role instructions, normalizer,
  semantic validator, persisted shape, public projection, and recovery handler.
  Follow the real call path; unrelated contracts are outside this review.
- Use the owning definitions as the authority. Do not create a parallel schema,
  allowlist, diagnostic vocabulary, or migration policy merely to review them.

## Trace acceptance and rejection

1. Select one concrete accepted flow and one meaningful rejected flow through the
   changed boundary. Use existing evidence or the smallest model-free fixture;
   add coverage only for a distinct uncovered contract.
2. Trace the supplied request into the producer's schema and applicable
   instructions or help.
   Check required/optional/null fields, status-dependent shapes, and exact source,
   snapshot, result, or approval bindings relevant to that flow.
3. Compare the role-facing contract with semantic normalization and validation.
   Account for normalized text, identifiers, uniqueness, limits, and closed values
   where required by the owner. Restrictions unsupported by a backend schema
   must still be discoverable in the instructions; do not guess provider support.
4. Follow the accepted value through normalization before policy or persistence.
   Where public or durable representations exist, confirm the same meaning and
   bindings; a well-shaped response alone proves neither compatibility nor acceptance.
5. Follow the rejected value to the exact failing field/constraint and disposition.
   Verify strict rejection and bounded, sanitized, machine-actionable diagnostics
   derived from trusted validation rather than arbitrary provider text or values.
   Do not expose or retain the raw rejected response to explain the failure.
6. Check corrective feedback for the producing role, caller, or operator. Affected
   instructions and public projections must identify the same constraint.
   A normal invalid response is expected;
   losing every actionable reason is a separate diagnostic/recovery defect.
   Keep the actual offending field unknown when the evidence cannot establish it.

## Check durable and recovery consequences

- For a persisted-shape change, verify version/migration ownership and compatibility
  with real saved shapes. Retain frozen settings, completed provenance, pending
  effects, inventories, bindings, and consumed allowances required by the owner.
- Inspect the offered action, checkpoint, correction scope, and stopping condition.
  Supported correction must preserve strict validation and existing authorization;
  never invent an override, renew a budget, or edit frozen inputs as a workaround.
- Check whether rejection consumes an attempt or invalidates dependent evidence,
  and whether interruption can charge or accept it twice. Follow the owning rule,
  including an explicit non-resumable outcome when correction is unsupported.
- Compare CLI and MCP projections when both are affected. Do not equate a generic
  error string, schema success, or later healthy status with proof of the failed field.

## Evidence and handoff

- Record the owning definitions and the accepted/rejected paths actually inspected
  or exercised, including the field, binding, diagnostic, and offered action.
- Report actionable findings at their owning files with the violated contract,
  evidence, consequence, and required correction. Keep optional alternatives separate.
- State untested consumers, missing historical evidence, and unknown causes.
  Return through the current role's review protocol; this skill does not replace
  its validation, correction accounting, or final acceptance gate.
