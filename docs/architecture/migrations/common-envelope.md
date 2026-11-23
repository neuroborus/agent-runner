# Common Run-Envelope Migrations

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Envelope shape and migration publication

`state.json` contains the common versioned envelope: monotonic revision,
pipeline ID and state version, an explicit runtime-compatibility tuple,
canonical paths, resolved roles, counters, hashes, pause state, session
lineage, nullable bounded active provider role/phase, timestamps, and opaque
pipeline-owned state, including its resolved settings from the initial
revision. The compatibility generation is maintained independently from the
package version, which is not a persistence contract.
The root validates JSON shape, size, and the common terminal/stop lifecycle;
pipeline-specific roles and outcomes remain opaque to the state capability.
Session lineage records an optional source-session reference, its resolved
trusted profile when known, and every direct child role/session ID with its
accepted-input and pipeline-checkpoint context key. Legacy role records missing
`profile` or `contextSize`, and missing or nullable `model`, normalize to
`current` in memory without rewriting state or event history. Envelope versions
1–7 also normalize absent active-role `effort` to `current`; version 8 requires
a portable effort value on every saved role. The leased runtime migration
persists those defaults without provider activity or configuration reload,
preserving prior journal records, progress, leases, and session evidence.
Changing runner configuration never re-resolves saved effort; changing protected
project configuration retains the safety pause without changing saved roles.
Native session resume remains an optimization rather than a correctness dependency.

Lock-free readers reject unsupported envelope, runtime, or pipeline versions
with an actionable version-skew error and never rewrite durable state. A
supported legacy envelope may be projected through the pipeline's explicit,
ordered migrations for status. Before workflow execution, the runner evaluates
the complete migration chain, validates the current pipeline shape, and appends
one complete migration event while holding the per-run execution lease. The
event upgrades the envelope and pipeline state atomically without rewriting
earlier history. Missing, failing, or forward-version migrations fail closed.

## Active-turn compatibility

Common run-envelope version 3 adds `activeTurn`, either `null` or the current
bounded `{ role, phase }`. Version-1 and version-2 runs project it as `null`
without rewriting state or history; the next mutating continuation persists the
explicit ordered runtime migration under the execution lease.

## Process ownership versions

Common envelope version 5 adds nullable `executionProcess` ownership. Version
11 adds the supervisor's bounded boot/start launch cutoff and changes the
runtime compatibility token. Version 12 adds a nullable, ordered launch-time
ancestry baseline bounded to 4,096 entries, each containing the boot ID, PID,
and start tick observed immediately before supervisor launch. Version 14 adds
the nullable SHA-256 identity of the supervisor's exact Linux control-group
membership. Versions 5 through 10 derive the cutoff from a valid recorded
supervisor identity during normalization. Versions 5 through 11 normalize the
baseline to null; versions 5 through 13 normalize the control-group identity to
null. Neither migration rescans the host or synthesizes recovery authority.
Historical ancestry and control-group fields remain strictly validated, including
ordering, size, boot identity and digest shape, but neither supplies recovery
authority. New launches retain the same persisted shape with null ancestry and
control-group fields; no global pre-launch process census is required. Valid old
records with or without those optional proofs use the same ownership policy.

## Catalog recovery evidence

Common envelope version 28 adds the private per-role completion receipts of
[explicit-model catalog recovery](../recovery/journal.md#explicit-model-catalog-recovery).
Migration starts with empty receipts and retains terminal workflow states.
Current release compatibility metadata uses envelope 28, and the derived
detached token `1:28` rejects mixed runtimes.

Common run-envelope version 28 with version-2 observations adds optional
rejection evidence on failed attempts. At terminal settlement, Runner derives
it from that invocation's normalized adapter failure. `writableRejection`
requires a `workspace-write` checkpoint and the exact `model_unavailable`/
`turn`/`rejected`/`none`/`terminal` record. Runner adds `writableRetryEligible`
only for a non-fork request. Reconciliation may use the no-effect record on
its own, but writable retry and catalog-triggered restatement require the
eligibility marker. `commitRejection` requires a
`commit:<step>` checkpoint and the exact `model_unavailable`/`commit`/
`rejected`/`none`/`terminal`/`not_started` record. Validation rejects any other
value, status or checkpoint. The evidence stays private and older envelopes
omit it.
