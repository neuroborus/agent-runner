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
- Preserve distinct safety, recovery, and failure-path guarantees. Before
  deleting a redundant test, identify its retained replacement. Never weaken
  assertions, skip failures, or lower concurrency to hide a race.
- The complete ordinary `npm run check` gate has a 60-second development
  budget. Measure it and remove avoidable cost before handoff. Do not impose a
  flaky wall-clock assertion in a unit test to enforce this budget.
- Keep an expensive test only when its necessary guarantee cannot be proved
  cheaply. Give it explicit slow-tier ownership and invocation rules in
  `docs/TESTING.md`; ordinary finalization must not run it repeatedly. An unrun
  slow check is not a pass. Live provider tests remain opt-in.
- Run the affected coverage and required gate; repeat broad runs only for a
  concrete unresolved risk. Report actual outcomes and elapsed times.
