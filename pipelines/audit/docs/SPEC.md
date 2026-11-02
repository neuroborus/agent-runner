# Audit — Discovery, Finding Verification and Report Contract

## Status and ownership

`pipelines/audit/` owns strict structured findings, the canonical classification
and default criterion catalog, deterministic English Markdown rendering, and a
descriptor-owned read-only discovery and finding-verification lifecycle. It
is registered for CLI and STDIO MCP use. All three modes retain their separate
discovery and finding-batch gates; only Runner publishes reports. Independent
is the default and recommended mode, and lazy is explicit opt-in.

The private workspace uses native ESM, Node.js `>=24 <25`, the standard library,
and `node:test`. Its public `src/index.js` exposes `AUDIT_CATALOG`,
`normalizeAuditReport`, `AuditReportValidationError`, `renderAuditReport`, and
the discovery/verification descriptor, state and workflow contracts described
below.
It imports neither root runtime capabilities nor another pipeline. Report
semantics belong here; filesystem publication and snapshot inspection remain
Runner-owned. Rendering returns text without reading sources, writing files,
invoking providers, or granting Git or retrieval authority.

## Read-only discovery lifecycle

The exported `auditPipeline` descriptor is a root dependency in the static
registry. It selects a directory workspace and
exclusive canonical workspace lease, allowing the same filesystem inspection
capability for Git repositories and ordinary directories. Auditor and finding
Reviewer access is read-only; lazy resolves and invokes only the Auditor. The
descriptor owns `mode` (default and recommended `independent`; explicit `lazy`
or `combined`) and `maxDiscoveryPasses` (default 20, positive integer
capped at 20 and frozen at creation). The separate
`maxFindingRecheckPasses` setting has the same default and finite cap.
The lifecycle imports no root capability or other pipeline.

`runAuditDiscovery` consumes existing injected runner workspace, clarification,
adapter, session-lineage and state-transition capabilities. The runner owns
confinement, ignored repository-local artifacts, external atomic/journaled state,
leases, provider enforcement and retirement. The lifecycle writes no files or
Git state directly. The public `runAudit` lifecycle coordinates report publication
through a confined Runner effect. The descriptor declares task-owned
`clarifications.md`, `audit.md` and `.audit.md.tmp` as exact mutable Runner
artifacts. Long-lived snapshots exclude those paths; task/context and source
content remain protected, while explicit transcript hashes reject edits outside
an authorized window. Per-turn provider enforcement remains read-only.

Active role turns carry the Runner-owned [session naming context](../../../docs/product/PROVIDER_MODEL.md#sessions-and-context).
The creation acknowledgement records a verified new child at this pipeline's
existing logical context key before a naming diagnosis or metadata failure is
returned; the eventual response does not record it twice. Naming diagnoses grant
no retry, source fork, replacement,
owner cycle or workflow/effect authority. Continuation preserves historical sessions.

Every new run starts in `CLARIFY`. The Auditor resolves complete `scope`,
`references`, `exclusions` and `criteria` lists from the task, context and
clarification artifact. Scope and criteria are nonempty; references/exclusions
may be empty. Inspect the agreed workspace, including unchanged content, unless
dirty-only inspection was explicitly requested. References authorize neither
retrieval nor writes nor access outside the runner's declared read boundary.
Structured `READY` freezes these declarations and the clarification hash;
`QUESTIONS` uses the common three-question-round limit; `BLOCKED` suspends scope
resolution. Use repository evidence for questions it can answer and ask only
material questions. Empty
artifacts and authorized editor closes without changes are valid. Question
rounds charge only actual question batches, and a one-shot edit authorization
is persisted before waiting and consumed on accepted resume. Unexpected input
or clarification changes block discovery; ordinary questions end at freeze.

State version 5 retains the workspace baseline, frozen declarations and their
hash, clarification hash/rounds/pending edit, logical source-fork consumption
and unrecorded fork context, structured report/fingerprint, versioned finding
ledger, versioned pending batch, discovery/recheck histories and accepted-batch
receipts. The descriptor migration from version 1 initializes the recheck
budget/history and pending-batch version without manufacturing acceptance or
changing discovery provenance. Version-1 snapshots retain their Auditor-only
frozen role configuration. Lazy verification continues that Auditor; independent
runs without a frozen Reviewer pause at `VERIFY_FINDINGS` with
`audit_reviewer_required` before reserving or invoking any recheck. Their pending
evidence remains intact across resume; independently reviewed findings require
a new run, without resolving or adding roles to the old snapshot. The migration
is consumed through the existing leased Runner migration boundary, never by
writing state directly. The ordered version-2 migration adds an empty
`sourceForkContexts` list for combined logical-owner fork consumption; it changes
no existing history, roles, budgets, batch versions or approval. Combined had no
invocable lifecycle in prior versions. Task/context hashes remain in the common envelope.
Report and pending-batch bindings pin the inspected content snapshot. Each
history entry retains its ordinal, logical session context, outcome, report
binding and candidate IDs. Actual opaque child identities/lineage use the
runner's session records; no provider conversations or native diagnostics enter
audit state.
Session context keys use the run store's SHA-256 format and bind task/context
hashes, the source snapshot and logical checkpoint. Independent discovery also
binds frozen declarations; lazy retains one key across clarification and passes.
Combined derives cycle ordinals and passes within each cycle from preserved
history prefixes: only `clean` closes a series. Thus reservations, interruptions,
invalid output, findings and report corrections remain part of the same cycle.
These histories are the durable cycle record, rather than independently mutable
freshness counters. Session keys bind that logical owner; a new native child
cannot reset its first-pass opportunity.

Lazy uses one logical Auditor across clarification and discovery. A deliberately
supplied source is forked at most once, with consumption persisted before
invocation. Continue a known child, or reconstruct the same logical owner from
frozen inputs and accumulated findings without reforking. Independent gives
every discovery pass a fresh Auditor (and its own source fork when deliberately
supplied), receiving frozen task/context/clarification text, resolved declarations,
structured report context and compact accumulated findings rather than preceding
conversations. Reconstruction never
manufactures a completed pass or freshness proof.
Accumulated findings retain evidence, concrete examples, impact/severity rationale,
classification and optional recommendations so fresh Auditors can assess their
consistency and return material corrections under the existing finding/cause IDs.

Every clarification/discovery/recheck invocation first establishes its logical checkpoint
with the existing Runner inactivity coordinator. Classified availability uses
the existing durable backoff, while inactivity retains its shared reconstruction
allowance; both recover the same reserved pass without renewing its budget.
Authentication and output exhaustion persist their distinct operator pauses
atomically with turn retirement. A possibly created source child is never forked
again at that checkpoint; only validated no-effect evidence restores an unused
fork. Provider-neutral structured-output failures pause as invalid output after
read-only reconciliation; discovery records an invalid pass before resuming at
a new ordinal. Terminal provider safety failures propagate after reconciliation and
persist `FAILED`, which cannot resume discovery or verification. A pending batch
and its interrupted recheck remain valid preserved evidence in this terminal state.
No native diagnostics are saved.
The baseline uses the common `repositoryBaseline` binding so successful recovery
can retire its evidence against the same unchanged workspace.

`DISCOVER` reserves a numbered `running` pass durably before invocation.
Reservations, interrupted launches, invalid outputs and incomplete passes all
consume the same finite run-wide budget. An interrupted reservation becomes
`interrupted` on reconstruction without a classified recovery checkpoint, and the
next invocation reserves a new ordinal; no new cycle or child can reset the count.
Exhaustion remains durably paused in
`WAITING_FOR_USER` with `discovery_limit_reached`; inspection/resume preserves
that checkpoint without additional provider work or allowance.

A complete pass proposes structured `candidates`, complete `limitations` and
`hypotheses`, plus substantive `reportCorrections`, bound to the exact snapshot.
A clean pass has no candidates, no substantive correction and unchanged report
content. New report content requires another pass even if corrections were
omitted. Malformed, interrupted, incomplete or stale-snapshot output never
supplies clean evidence. Partial results are not adopted. Source or frozen-input
drift rejects the result and remains blocking.

Clarification, discovery and recheck role results share the two-MiB serialized UTF-8
limit, independently of the enclosing store's 100,000-character string and
10,000-item collection limits. Clarification questions additionally retain the
shared service's 32-item and 4,000-character text limits. Oversized,
unserializable or malformed output is invalid and cannot enter frozen inputs,
report content or the finding ledger. Proposed report/ledger updates also preserve
collection limits, the complete run's 32-MiB ceiling and the escaped report's
32-MiB publication bound before acceptance. Overflow records an invalid pass and
pauses resumably with the prior ledger/report intact, without publishing an
impossible intent; retries retain both consumed pass budgets.
Unsettled execution-process or storage ownership propagates to Runner
reconciliation without retiring the
active turn or reclassifying its reserved pass as an ordinary interruption.

Exact normalized duplicate candidates share one ledger entry; conflicting IDs
or causes are invalid rather than silently merged. Material revisions preserve
finding/cause IDs and increment the ledger version. Exact previously recorded
duplicates create no new pending batch, but their discovery pass remains
finding-producing. A later rejection likewise cannot retrospectively change
discovery history. New or revised entries enter a snapshot/report-bound pending
batch at `VERIFY_FINDINGS`, which blocks all further discovery across resume.
Only confirmed dispositions in accepted batches may later supply report
findings. Discovery retains structured report context and a versioned ledger;
the public lifecycle projects only current accepted versions into confirmed sections.

`DISCOVERY_CLEAN` records clean discovery evidence only: it is not public audit
completion, finding acceptance or permission to publish. The lifecycle returns
at that checkpoint without a redundant unchanged-response turn. The separate
finding gate and public mode-specific completion/publication consume
these bindings without changing historical outcomes or renewing either budget.

## Combined discovery cycles

Combined continues the initial Auditor from clarification through its discovery
series. A clean primary always starts a fresh Auditor, including when the primary
was clean on its first pass. Each successor inspects the same frozen scope with
compact accumulated findings and accepted dispositions, without preceding
conversations. If its first discovery pass is clean, it supplies the combined
`DISCOVERY_CLEAN` gate. Otherwise, keep that Auditor until its own series is clean,
then create another fresh Auditor. Later cleanliness closes only that series.

Finding-producing passes, exact duplicates, report-only corrections and invalid,
incomplete or interrupted reservations all retain their non-clean provenance.
Rejected candidates never retrospectively clean discovery. Every new/material
batch suspends discovery for the separate verification policy below; accepting
it resumes the discovering Auditor, without closing or replacing that owner.

Combined source forks are isolated per logical Auditor or finding Reviewer.
Persist consumption in `sourceForkContexts` before invocation, even before a
child is known. Continue or reconstruct the same owner without reforking; only
existing validated no-effect recovery can restore that key's unused fork.
Reconstruction, replacement and new batches never reset either run-wide budget.
Discovery and finding review share only the pure history-derived cycle-position
rule; their distinct starting owners and acceptance rules remain audit-owned.

## Finding-batch verification

`VERIFY_FINDINGS` requires a distinct read-only recheck of every new or materially
revised batch, in every supported mode. Exact unchanged duplicate candidates
create no batch. A pending batch binds its discovery pass, source snapshot,
structured report fingerprint, monotonically increasing batch version, exact
ledger entry versions and proposed dispositions. Recheck requests include frozen
inputs, compact accumulated findings and prior decisions, including rejected
claims. Responses echo the exact snapshot, report and batch fingerprints;
stale responses cannot approve a later version.

A complete recheck decides every current batch entry exactly once. Each closed
decision contains `id`, `kind`, nonempty supported `rationale`, `finding`,
`targetId` and `hypothesis`. Unused payloads must be null:

- `confirm` retains the finding unchanged.
- `correct` carries a complete corrected finding, preserving finding/cause IDs.
  Material content changes increment its ledger version.
- `reject` retains an evidence-based dismissal in decision history, without
  deleting the candidate or rewriting discovery cleanliness. Subsequent rechecks
  assess unsupported dismissals as well as supported findings.
- `merge` names a distinct retained finding. Correct the target to consolidate
  supporting locations, evidence and examples. Targets enter the batch if needed
  and must remain confirmed or corrected; chains and dismissed targets fail.
- `hypothesis` carries the original ID, title, evidence and explicit uncertainty
  in the report's unverified hypothesis shape; it is never a confirmed finding.

Rechecks assess scope/criterion relevance, evidence, concrete examples, impact,
severity/category, overlap and recommendations when present. `additions` can
introduce new findings or material revisions to other ledger findings; exact
unchanged repeats are ignored. Added/revised entries themselves require recheck.
No response can silently remove a batch member. All updates are adopted together,
and partial, malformed or interrupted output cannot approve a batch.

Lazy continues the discovering Auditor's logical session until the exact batch
and dispositions are unchanged. Reconstruction reuses frozen evidence and never
reforks its consumed source. Independent starts a fresh finding Reviewer for
each recheck, including every pass after a substantive correction. Each fresh
Reviewer receives complete structured evidence without prior conversations;
its own source fork is isolated from discovery. Changes to entries, dispositions
or their rationale increment the batch version and require another distinct
recheck. Agreeing with a disposition preserves its exact text/payload. A first
review with only confirmations is clean immediately, as is unchanged review of
previously added entries; neither requires a redundant confirmation turn.
Combined first rechecks with the discovering Auditor until the exact batch and
dispositions are unchanged, then starts a fresh finding Reviewer. A clean first
Reviewer pass accepts that batch immediately. If a Reviewer corrects anything,
adds findings, or returns invalid/incomplete output, retain it through its own
series until clean, then replace it. Acceptance requires a later fresh Reviewer's
clean first pass. An interrupted reservation also consumes that first-pass
opportunity. Neither the Auditor's clean recheck nor a correcting Reviewer's later
clean recheck creates an acceptance receipt or releases pending verification.
Rechecks resume the same exact batch/version after interruption; changes still
invalidate approval and require verification themselves, including additions.

A write-ahead recheck reservation records ordinal, logical session key,
discovery pass, batch version/fingerprint, snapshot/report bindings and outcome.
Complete decisions remain in history even after rejection is reversed. The
finite run-wide `maxFindingRecheckPasses` budget charges reservations,
interruptions, invalid and incomplete responses, across all batches, cycles and
sessions. Classified provider recovery retries the original reservation using
existing policies; unclassified interruption charges it and reserves a new pass.
`finding_recheck_limit_reached` preserves the pending batch and exhausted history
on resume, without provider work or renewed allowances. Invalid/incomplete
rechecks pause resumably at verification rather than discovering more findings.
Source/input drift remains blocking and unsettled execution ownership propagates.

Only a mode-eligible clean distinct recheck creates an accepted-batch receipt bound to its exact
entries, dispositions and recheck evidence, then releases `DISCOVER`. A material
later revision leaves historical receipts intact but requires a new pending
version; earlier acceptance cannot approve it. Discovery receives accepted
dispositions with version references so rejected and uncertain claims remain
visible. Recheck cleanliness accepts only that batch: it cannot clean a discovery
pass, complete a discovery cycle or finish the audit. Recheck cleanliness alone cannot publish complete status. The public lifecycle
projects exact acceptance into the report as described below.

## Criteria and classification

`src/catalog.js` is the single classification source. Its ordered severity and
category entries supply allowed values, validation, sorting, and the compact
report map. Severity describes impact and realistic likelihood; one primary
category describes the dominant problem. Neither determines the other.
Consumers use this catalog for classification reference text instead of
maintaining another copy of its definitions.

The catalog also supplies default criteria: correctness; established conventions
and minimalism; architecture; homogeneity; security; reliability; validation and
documentation; and demonstrated performance/resource cost. Apply only relevant
criteria and include agreed task-specific criteria without inventing project
rules. Equivalent interfaces should provide compatible guarantees; different
contracts may justify different implementations. Require concrete coverage needs
for test/documentation findings and demonstrated resource problems for performance
findings. Subjective style, speculative optimization, gratuitous refactoring, and
finding quotas are invalid. No findings is a valid result and proves no universal
security guarantee.

Homogeneity is classified as Consistency and structural minimalism as
Architecture. Nit is reserved for minor defects grounded in an established
convention; it cannot disguise a behavioral or safety defect. A Security finding
is not automatically Critical. Structural validation accepts severity and category
independently; relevance, supporting evidence, and realistic severity assignment
remain semantic obligations.

## Structured report

All records are closed plain objects. Required fields cannot be omitted or null.
Lists are arrays, including when empty. Text must be nonempty and free of control
characters except tabs and line breaks in prose. Normalization trims prose edges
and converts CRLF/CR to LF; titles and locations must be single-line. Text lists
reject duplicate normalized entries. No raw transcripts, credentials, invented
observations, or unrelated private context belong in a report.

| Field         | Contract                                                                                            |
| ------------- | --------------------------------------------------------------------------------------------------- |
| `scope`       | Nonempty list describing the agreed inspected scope and exclusions                                  |
| `snapshot`    | Exact `{fingerprint, description}`; fingerprint is a lowercase 64-character SHA-256 content binding |
| `criteria`    | Nonempty list of the relevant criteria actually applied, including agreed task-specific rules       |
| `findings`    | Confirmed findings only, possibly empty                                                             |
| `limitations` | Coverage limitations, unavailable checks, and other evidence gaps, possibly empty                   |
| `hypotheses`  | Explicitly unverified claims, possibly empty                                                        |

The snapshot fingerprint is supplied by the caller's inspection capability.
Validation checks its syntax, not the existence or freshness of that evidence.
The caller must bind content to its inspected snapshot and enforce acceptance
before presenting findings as confirmed. Rendering does not establish audit
completion or turn unsupported content into verified evidence.

Each finding requires:

- `id`: stable report-local lowercase kebab-case ID, starting with a letter,
  at most 64 characters. Keep it across title, classification, and evidence
  corrections; sorting never renumbers it.
- `causeId`: a stable key with the same syntax identifying the underlying cause.
  Consolidate shared causes into one finding retaining all affected `locations`,
  supporting `evidence`, and applicable `examples`. Duplicate cause keys are
  rejected rather than silently choosing between conflicting accounts. Semantic
  review must also detect shared causes assigned different keys.
- `title`, one catalog `severity`, one catalog `category`, nonempty `locations`
  and `evidence` lists, `impact`, and `severityRationale`. Evidence supports the
  claim; the rationale explains impact and realistic likelihood.
- A nonempty `examples` list. Every example labels its `basis` exactly
  `observed` or `code-derived`. Unexecuted scenarios must use code-derived;
  never invent reproduction results or error messages.

A behavioral example has `kind: "behavioral"`, `basis`, `conditions`, `action`,
`expected`, and `actual`. It identifies concrete conditions/input, the relevant
action, and expected versus observed or derived behavior. A non-behavioral example
has `kind: "non-behavioral"`, `basis`, `material`, `rule`, and `violation`: cite
specific structure, a fragment, or a document and the established rule it
violates, without inventing a runtime failure. Mixed or incomplete shapes fail.

`recommendation` is optional nonempty text. Omit it when no supported useful
guidance is needed; no placeholder or explanation is required. When present it
is subject to the same evidence and relevance obligations as the finding.

A hypothesis contains exactly `id`, `title`, `evidence` (which may be empty),
and nonempty `uncertainty`. It has no severity/category or confirmed-finding
shape. IDs are unique across confirmed findings and hypotheses. A claim lacking
a supported concrete example stays unverified. Do not run unsafe or costly
checks merely to manufacture an example.

`normalizeAuditReport` validates and returns a detached, deeply frozen content
copy. Invalid input throws `AuditReportValidationError` with code
`ERR_INVALID_AUDIT_REPORT` and a path-based `issues` list without raw input
values. It grants no durable state or publication authority.

## Rendering

`renderAuditReport` validates its input and returns the English `audit.md`
content with a trailing LF. The report contains a finding-count summary, scope,
snapshot binding, applied criteria, one compact classification map, confirmed
findings, and separate limitations/unverified hypotheses. Zero findings retains
all sections and explicitly says there are no confirmed findings.

Findings sort by catalog severity order, then report-local ID using code-unit
comparison independent of locale. Locations and hypothesis IDs use the same
locale-independent ordering; scope, criteria, evidence, examples, and limitations
retain supplied order. IDs and source arrays are never mutated. The renderer
uses no clock, randomness, filesystem, or environment-dependent collation.
Plain source text is escaped against Markdown/HTML injection; prose line breaks
become `<br>` without creating report sections or active links.

Agents consume and review structured content with necessary classification
context. They neither generate the static map nor review its prose as a report
correction. Map generation requires no provider turn and remains independently
testable from the catalog. A rendered report is not permission to publish it,
change audited sources, stage, commit, create issues, or retrieve references.

## Public completion and publication

Use `agent-run run audit --project <workspace> --task <task-dir>` or MCP
`run_start` with `pipelineId: "audit"`. The descriptor exposes Auditor and finding
Reviewer configuration, mode and finite budgets through pipeline metadata;
lazy resolves only the Auditor. Every agent turn remains read-only. No Arbiter,
commit, staging, source repair, retrieval or automatic issue creation is authorized.

CLI `--clarify` and MCP `proactiveClarification` persist an optional editor window
before the first Auditor turn. An unchanged optional close or empty MCP answer set
is valid and consumes no question round. Material questions persist identified
`q1` through `qN` requests and their one-shot edit authorization before opening the
CLI editor or waiting in MCP. MCP never opens an editor. Answers are accepted
through the shared response boundary or an authorized external edit and resume;
unchanged material answers retain the pending request without another model turn
or question round. Closing clarification freezes its accepted transcript hash.

Runner publishes `<task-dir>/audit.md` atomically after accepted structured report,
ledger or disposition updates. An initial report is marked **In progress**.
Only current ledger versions with exact accepted-batch receipts and confirm/correct
dispositions appear as confirmed. Pending revisions remove the earlier confirmed
version until accepted; pending candidates and hypotheses are explicitly unverified.
Rejected and merged decisions remain in durable state. Limitations and unavailable
checks remain visible; neither zero nor Critical findings prevent completion.
Report-quality corrections alter structured report content and never audited sources.

State version 4 adds `publication: {pending, published, temporary}` through the leased
version-3 migration, preserving all earlier roles, history and budgets. Each
publication binding carries source snapshot, projected report fingerprint, rendered
content hash and completion flag. Persist the exact intent before writing; verify
readback and unchanged frozen inputs/source before the receipt. Resume settles a
pending publication before any further discovery. Exact desired bytes reconcile a
lost acknowledgement without a provider turn. Unexpected report edits, unsafe
paths, substituted ancestors or conflicting temporaries fail closed and remain
preserved. Legacy bindings lacking declared report paths gain no new write authority.
State version 5 adds the selected proactive-clarification boolean and its completion
flag. The version-4 migration defaults to no proactive request, preserving existing
clarification progress, discovery history, roles, publication and both budgets.
Legacy material edits without structured requests retain external edit/resume support.

The Runner anchors replacement to the bound real parent directory, journals the
temporary's identity and `writing` phase before writing `.audit.md.tmp`, syncs its
bytes, journals `prepared`, renames it atomically, syncs the parent and verifies bytes.
Both paths must already be ignored and untracked when repository-local; the
Runner never edits ignore rules. The publisher accepts only exact declared
artifacts and bounded report text (32 MiB); agents cannot call it. Recovery may
rewrite an incomplete `writing` temporary only after verifying its recorded file
identity, single-link ownership and unchanged destination. Unowned partial files,
substituted temporaries and changed prepared bytes remain preserved and block report
publication, independently of immutable source drift. Source snapshots exclude only the declared
artifacts; per-turn read-only guards still include every artifact.

Complete publication requires the selected clean-discovery gate, no pending
verification, and unchanged source, task, clarification and report bindings. Lazy
and independent finish on an eligible clean discovery pass; independent requires
no redundant unchanged-response turn. Combined requires a fresh successor's clean
first pass. Only a verified complete report receipt advances to `DONE`.
Interrupted publication remains a resumable checkpoint. A completed resume verifies
content and report bytes without model work or replaying publication. CLI status
and MCP `auditReport` expose the path, publication status/hash, counts and consumed
pass totals without provider-private content.

Optional checks run only within their existing authorized isolated read boundary,
with the same snapshot guards; this workflow invokes no arbitrary check or extra
permission based on a finding. Missing evidence is a report limitation, never an
invented pass. Findings require a separately authorized workflow for fixes. Critical
project findings are successful audit results, not unexpected Runner issues.
