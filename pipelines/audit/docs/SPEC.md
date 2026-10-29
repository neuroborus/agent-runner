# Audit — Finding and Report Contract

## Status and ownership

`pipelines/audit/` owns strict structured findings, the canonical classification
and default criterion catalog, and deterministic English Markdown rendering.
It is an unfinished, unregistered pipeline: there is no audit descriptor,
workflow, CLI command, MCP route, discovery gate, or publication capability yet.
The root runtime still exposes its three existing pipelines.

The private workspace uses native ESM, Node.js `>=24 <25`, the standard library,
and `node:test`. Its public `src/index.js` exposes `AUDIT_CATALOG`,
`normalizeAuditReport`, `AuditReportValidationError`, and `renderAuditReport`.
It imports neither root runtime capabilities nor another pipeline. Report
semantics belong here; filesystem publication and snapshot inspection remain
Runner-owned. Rendering returns text without reading sources, writing files,
invoking providers, or granting Git or retrieval authority.

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
