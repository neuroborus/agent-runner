# Audit — Discovery, Finding and Report Contract

## Status and ownership

`pipelines/audit/` owns strict structured findings, the canonical classification
and default criterion catalog, deterministic English Markdown rendering, and a
descriptor-owned read-only discovery lifecycle. It remains unfinished and
unregistered: there is no audit CLI command, MCP route, finding-verification
gate or publication capability. The root runtime still exposes its three
existing pipelines. Combined audit cycles are unavailable at this stage.

The private workspace uses native ESM, Node.js `>=24 <25`, the standard library,
and `node:test`. Its public `src/index.js` exposes `AUDIT_CATALOG`,
`normalizeAuditReport`, `AuditReportValidationError`, `renderAuditReport`, and
the discovery descriptor/state/workflow contracts described below.
It imports neither root runtime capabilities nor another pipeline. Report
semantics belong here; filesystem publication and snapshot inspection remain
Runner-owned. Rendering returns text without reading sources, writing files,
invoking providers, or granting Git or retrieval authority.

## Read-only discovery lifecycle

The exported `auditPipeline` descriptor is intentionally absent from root
dependencies and the static registry. It selects a directory workspace and
exclusive canonical workspace lease, allowing the same filesystem inspection
capability for Git repositories and ordinary directories. Auditor access is
read-only. The descriptor owns `mode` (default and recommended `independent`;
explicit `lazy`; reserved `combined`) and `maxDiscoveryPasses` (default 20,
positive integer capped at 20 and frozen at creation).
Combined invocation fails before effects until its audit-specific cycle gate
is implemented. The lifecycle imports no root capability or other pipeline.

`runAuditDiscovery` consumes existing injected runner workspace, clarification,
adapter, session-lineage and state-transition capabilities. The runner owns
confinement, ignored repository-local artifacts, external atomic/journaled state,
leases, provider enforcement and retirement. The lifecycle writes no files or
Git state directly and never publishes `audit.md`.
The descriptor declares only task-owned `clarifications.md` as a mutable Runner
artifact. Long-lived snapshots exclude that exact path; task/context and source
content remain protected, while explicit transcript hashes reject edits outside
an authorized window. Per-turn provider enforcement remains read-only.

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

State version 1 retains the workspace baseline, frozen declarations and their
hash, clarification hash/rounds/pending edit, logical source-fork consumption
and unrecorded fork context, structured report/fingerprint, versioned finding
ledger, pending batch and full discovery-pass history. Task/context hashes remain
in the common envelope.
Report and pending-batch bindings pin the inspected content snapshot. Each
history entry retains its ordinal, logical session context, outcome, report
binding and candidate IDs. Actual opaque child identities/lineage use the
runner's session records; no provider conversations or native diagnostics enter
audit state.
Session context keys use the run store's SHA-256 format and bind task/context
hashes, the source snapshot and logical checkpoint. Independent discovery also
binds frozen declarations; lazy retains one key across clarification and passes.

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

Every clarification/discovery invocation first establishes its logical checkpoint
with the existing Runner inactivity coordinator. Classified availability uses
the existing durable backoff, while inactivity retains its shared reconstruction
allowance; both recover the same reserved pass without renewing its budget.
Authentication and output exhaustion persist their distinct operator pauses
atomically with turn retirement. A possibly created source child is never forked
again at that checkpoint; only validated no-effect evidence restores an unused
fork. Provider-neutral structured-output failures pause as invalid output after
read-only reconciliation; discovery records an invalid pass before resuming at
a new ordinal. Terminal provider safety failures propagate after reconciliation and
persist `FAILED`, which cannot resume discovery. No native diagnostics are saved.
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

Clarification and discovery role results share the two-MiB serialized UTF-8
limit, independently of the enclosing store's 100,000-character string and
10,000-item collection limits. Clarification questions additionally retain the
shared service's 32-item and 4,000-character text limits. Oversized,
unserializable or malformed output is invalid and cannot enter frozen inputs,
report content or the finding ledger. Proposed ledger updates also preserve
collection limits and the complete run's 32-MiB ceiling before persistence.
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
They are not confirmed report findings. Finding dispositions and verification
are a separate, still unavailable gate.

`DISCOVERY_CLEAN` records clean discovery evidence only: it is not public audit
completion, finding acceptance or permission to publish. The lifecycle returns
at that checkpoint without a redundant unchanged-response turn. The separate
finding gate and eventual mode-specific completion/publication must consume
these bindings without changing historical outcomes or renewing either budget.

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
