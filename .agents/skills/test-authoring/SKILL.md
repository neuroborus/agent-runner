---
name: test-authoring
description: Design, change, and review Agent Runner tests for necessary coverage, deterministic behavior, and fast execution. Use when adding tests, changing fixtures, removing redundant cases, or reviewing test cost during finalization.
---

# Test Authoring — Agent Runner

These are requirements for writing and reviewing tests:

- Every test MUST catch a concrete regression or protect a distinct observable
  contract. If its necessity cannot be explained, remove it. Do not add tests
  for reassurance, coverage counts, copied wording, or implementation shape.
- Test inputs and assertions MUST be self-contained. Never use names, paths,
  identifiers, or contextual details from unrelated projects, including as
  deny-list entries or regression fixtures. Use minimal, neutral synthetic
  values that exercise only the owned contract.
- Keep fixtures sanitized and valid. Synthetic nested data must satisfy the
  real nested parser's required fields; an enclosing object does not supply
  them. Fix a malformed fixture instead of loosening production parsing;
  intentional rejection tests remain valid.
- Add regression tests for reproduced defects and known fragile boundaries;
  prove the failure and the fix. Elsewhere, add a test only for an important
  uncovered contract. A change alone does not justify another test.
- Use the smallest sufficient test with `node:test`. Test policy with pure
  functions or injected effects. Use real processes and durable storage only
  when their interaction is the behavior being proved. Do not duplicate that
  proof across layers or multiply equivalent scenarios.
- Tests MUST be deterministic. Synchronize with events, promises, or controlled
  clocks. Artificial sleeps, timing-based ordering, retry-until-green, and
  unnecessary polling are prohibited. Await teardown of every owned resource.
  Release manually owned resources with failure-safe cleanup before any
  boundary that verifies their release; never disable invariants or
  assertions to tolerate late cleanup.
- Preserve distinct safety, recovery, and failure-path guarantees. Before
  deleting a redundant test, identify its retained replacement. Never weaken
  assertions, skip failures, or lower concurrency to hide a race.
- After changing shared fixtures, helpers, or defaults, trace affected
  integration callers beyond the edited files and keep their distinct
  guarantees instead of blindly rewriting expectations.
- The complete ordinary `npm run check` gate has a 60-second development
  budget. Measure it and remove avoidable cost before handoff. Do not impose a
  flaky wall-clock assertion in a unit test to enforce this budget.
- Keep an expensive test only when its necessary guarantee cannot be proved
  cheaply. Give it explicit slow-tier ownership and invocation rules in
  `docs/TESTING.md`; ordinary finalization must not run it repeatedly. An unrun
  slow check is not a pass. Live provider tests remain opt-in.
- Run the affected coverage and every required gate; required gates stay
  mandatory. Repeat broad or expensive runs, including during finalization,
  only for a concrete unresolved risk. Report actual outcomes and elapsed times.
- A run that was actually interrupted, including one terminated at its
  deadline, stays interrupted even if its controller or tool exits zero.
  Report it so and verify that the owned process retired. A bounded run that
  completes within its limit is reported by its actual result.
- For changed structured role contracts, exercise semantic restrictions and
  bounded field-level rejection details together, without retaining raw replies.
- Exercise relevant native initialization or incidental-write effects at the
  read-only snapshot boundary; keep real provider smoke tests opt-in.
- For journal and wait changes, control the publication interleaving and retain
  distinct proofs for benign extension and changed-prefix rejection.
- For workspace-scope changes, cover supported Git and ordinary-directory
  consumers and exclusions before traversal. Preserve control/input protection
  and test expensive-preparation visibility or cancellation where that contract changes.
