# Bounded Ownership-Failure Diagnostics

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

### Bounded ownership-failure diagnostics

`src/platform/ownership-diagnostic.js`, exposed by `src/platform/index.js`, owns
one closed version-1 `ownershipDiagnostic` envelope. Identifiers are assigned at
the actual raising site, never inferred from an error code, message or session.
Launcher/setup, registration, parent supervision, recovery, state custody and
adapter/trusted resource refusals remain distinguishable. Parent sites separate
session signalling, completion inspection, containment relay, incomplete/active
outcomes, invalid frames/observations and missing descendant/supervision proof.
A containment relay additionally retains the supervisor's exact
`finish-inspection-deadline`, `finish-retirement-deadline`, `terminate-signal` or
`terminate-check` branch; no other site admits a branch.

The exact envelope fields are `schemaVersion`, `site`, `branch`, `phase`,
`startRequested`, `terminationRequested`, `ownershipHandedOff` and `inspection`.
Parent flags are nullable booleans captured before cleanup changes them; other
owners leave them null. Registration can also capture the parent flags.
`inspection` is null or a closed sample with `work`, `elapsedMs`, `maxWork`,
`maxElapsedMs` and `maxAttempts`. Its phase is `session-inspection`, otherwise
null. Numeric measurements are finite, nonnegative and bounded by the safe
integer range; work is integral. Invalid or unavailable measurements stay null.
Applicable limits retain the existing 65,536 work, 250 milliseconds and three
classification attempts (injected inspection fixtures may select smaller work
or time bounds). Namespace-only inspections have no session-budget sample.
The budget snapshots existing checks, including post-read checks; it retains
measured overruns and the first exhausted sample within a scan. Later cleanup
cannot replace evidence attached to the original refusal. Reporting adds no
scan, read, signal, wait, retry or grace extension, and the inspector still
returns an array or null to existing injected consumers.

Native frames validate their outcome/observation shapes before forwarding
facts. A strictly shaped preparation-expiry frame remains valid after the parent
requests start: the supervisor checks the absolute deadline before target spawn.
Expiry records no target effect and still requires verified supervisor close
before deregistration. Malformed supplemental evidence becomes unavailable without establishing
an outcome, replacing the original refusal or relaxing retirement. Both adapters,
`AgentBoundaryError`, Runner invocation and trusted-validation wrappers carry
only the validated envelope; normalized failure, effect and retry policy are
unchanged. Trusted-validation receipts expose the nullable envelope, including
synchronous and asynchronous no-launch refusals. Their bounded evidence and
capability-preparation blockers retain its validated JSON for existing workflow
pause projections.
Both coding pipelines preserve bounded capability-blocker evidence in pauses.
For caught preflight, inspection and resource-cleanup refusals, the injected
trusted-validation `failureEvidence` projection serializes only platform-validated
ownership facts, excluding error messages and arbitrary error evidence. Existing
pause codes, resume checkpoints and recovery authority remain unchanged.
No command, argument vector, process list, environment value, path,
credential, raw stream or private session identifier enters the envelope.

Common envelope version 27 permits observation format version 2. A new attempt
uses version 2; historical version-1 records and attempts remain unchanged.
Only failed/interrupted terminal attempts may carry `ownershipDiagnostic`;
legacy absence projects null. Existing leased migration, 32-attempt retention,
revision/role/checkpoint identity, sealed terminal records, continuity checks
and write-ahead publication still apply. Migration preserves newer clarification
journal contracts, frozen inputs, provenance, budgets, effects and checkpoints.
Recovery sidecar version 2 adds the same nullable envelope; version 1 is read
strictly without backfilling evidence or rewriting immutable bytes. Exact
run/dispatch/revision/child correlation and the 4-KiB bound remain mandatory,
including pre-lease, reconstructed and operator-stop recovery failures.
Publication failure never replaces the original error. Release compatibility
metadata uses envelope 27, and the derived detached token rejects mixed runtimes.

Runner results, CLI status/direct failures/recovery output and MCP status/wait
or detached errors expose the same validated evidence. MCP tool errors preserve
text JSON/structured-content parity; recovery stage/code/explanation and
separate exit/signal observations keep their meanings. All five pipelines,
including init, consume the common attempt publication without their own
diagnostic vocabulary or workflow policy. Diagnostics grant no readiness,
acceptance, replay, ownership release or foreign-run recovery authority.
Historical cause, raising site and Source-contract violation remain UNKNOWN;
this deployment improves future discrimination only, without proving a
historical fix or reproduction. Operator native acceptance is separate from
injected development evidence; see [testing](../../TESTING.md#ownership-diagnostic-acceptance).
