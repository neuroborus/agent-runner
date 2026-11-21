# Testing

The [test-authoring skill](../.agents/skills/test-authoring/SKILL.md) owns test
necessity, minimalism, and determinism. Regressions belong around reproduced
defects and fragile boundaries, not around every edit.

Use the [testing map](testing/README.md) for affected suite ownership and
procedures, including writable-result recovery policy and its slow dependencies.

## Ordinary gate

Read the [coverage map](testing/README.md) when changing a capability,
pipeline, shared contract or repository boundary; follow its affected owners
for suite guarantees, invocation conditions and remaining slow obligations.

`npm run check` runs formatting verification, the fast test tier, and CLI help.
Its development budget is approximately 60 seconds. The fast tier retains
contract, policy, provider, Git, state, and focused integration checks.
`npm test -- path/to/file.test.js` runs selected coverage.

Read [harness and storage](testing/harness.md) when changing temporary storage,
concurrency, reporters, interruption reporting or scratch-request reporting.

## Slow gate

`npm run test:slow` runs every `*.slow.test.js` file. Both tiers together cover
all test files; neither silently excludes a failed test. Use
`npm run test:slow -- path/to/file.slow.test.js` to run an affected file, or
pass multiple paths for one affected batch; selected files retain the same
bounded runner and per-file timing output.

Read [slow and release gates](testing/slow-gates.md) before selecting affected
slow coverage or the full release gate, including exact-artifact package-install
acceptance. Follow its pipeline-owner routes for pipeline-local slow records.

## Finalization

Read [finalization applicability](testing/finalization.md) before assigning
per-step checks, executors, slow batches or unchanged-fingerprint evidence reuse.
Read [native and live-provider acceptance](testing/native-acceptance.md) when
provider, launcher or installation changes require opt-in host or post-install
acceptance. Ordinary or slow results do not establish native acceptance.

## Operator-owned Codex file-output acceptance

Read the [native output acceptance](testing/native-acceptance.md#operator-owned-codex-file-output-acceptance)
for its separate operator ownership and evidence limits.

## Ownership diagnostic acceptance

Read [ownership diagnostic acceptance](testing/native-acceptance.md#ownership-diagnostic-acceptance)
for Source/Installed model-free delivery acceptance.
