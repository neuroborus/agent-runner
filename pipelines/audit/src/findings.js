import { AUDIT_CATALOG } from "./catalog.js";
import { HASH_PATTERN, ID_PATTERN, MAX_ID_LENGTH } from "./constraints.js";
import { auditDiagnostic, diagnosticIssues } from "./diagnostics.js";

const ID = new RegExp(ID_PATTERN, "u");
const HASH = new RegExp(HASH_PATTERN, "u");
const SEVERITIES = AUDIT_CATALOG.severities.map(({ name }) => name);
const CATEGORIES = AUDIT_CATALOG.categories.map(({ name }) => name);
const FINDING_FIELDS = [
  "id",
  "causeId",
  "title",
  "severity",
  "category",
  "locations",
  "evidence",
  "impact",
  "severityRationale",
  "examples",
];

export class AuditReportValidationError extends Error {
  constructor(field = "report", code = "invalid-result") {
    super("Invalid audit report.");
    this.name = "AuditReportValidationError";
    this.code = "ERR_INVALID_AUDIT_REPORT";
    const diagnostic = auditDiagnostic(field, code);
    this.diagnostics = Object.freeze([diagnostic]);
    this.issues = diagnosticIssues(diagnostic);
  }
}

function invalid(path, code) {
  throw new AuditReportValidationError(path, code);
}

function record(value, path, required, optional = []) {
  if (
    value === null ||
    typeof value !== "object" ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  ) {
    invalid(path, "invalid-record");
  }
  if (
    Object.keys(value).some((key) => ![...required, ...optional].includes(key))
  ) {
    invalid(path, "unsupported-fields");
  }
  if (required.some((key) => !Object.hasOwn(value, key))) {
    invalid(path, "required-fields");
  }
}

export function text(value, path, singleLine = false) {
  if (typeof value !== "string") invalid(path, "invalid-text");
  const normalized = value.replace(/\r\n?/gu, "\n");
  if (
    normalized.trim().length === 0 ||
    /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u2028\u2029]/u.test(normalized) ||
    (singleLine && /[\n\t]/u.test(normalized))
  ) {
    invalid(path, "invalid-text");
  }
  return normalized.trim();
}

function identifier(value, path) {
  if (
    typeof value !== "string" ||
    value.length > MAX_ID_LENGTH ||
    value !== value.trim() ||
    !ID.test(value)
  ) {
    invalid(path, "invalid-id");
  }
  return value;
}

function choice(value, path, allowed) {
  if (!allowed.includes(value)) invalid(path, "unsupported-value");
  return value;
}

function list(value, path, normalize, minimum = 0) {
  if (!Array.isArray(value) || value.length < minimum) {
    invalid(path, "required-items");
  }
  return Object.freeze(
    Array.from(value, (item, index) => normalize(item, `${path}[${index}]`)),
  );
}

export function texts(value, path, minimum = 0, singleLine = false) {
  const result = list(
    value,
    path,
    (item, at) => text(item, at, singleLine),
    minimum,
  );
  if (new Set(result).size !== result.length) {
    invalid(path, "duplicate-items");
  }
  return result;
}

function example(value, path) {
  const behavioral = value?.kind === "behavioral";
  const fields = behavioral
    ? ["conditions", "action", "expected", "actual"]
    : ["material", "rule", "violation"];
  record(value, path, ["kind", "basis", ...fields]);
  return Object.freeze({
    kind: choice(value.kind, `${path}.kind`, ["behavioral", "non-behavioral"]),
    basis: choice(value.basis, `${path}.basis`, ["observed", "code-derived"]),
    ...Object.fromEntries(
      fields.map((key) => [key, text(value[key], `${path}.${key}`)]),
    ),
  });
}

export function normalizeFinding(value, path = "report.findings[0]") {
  record(value, path, FINDING_FIELDS, ["recommendation"]);
  return Object.freeze({
    id: identifier(value.id, `${path}.id`),
    causeId: identifier(value.causeId, `${path}.causeId`),
    title: text(value.title, `${path}.title`, true),
    severity: choice(value.severity, `${path}.severity`, SEVERITIES),
    category: choice(value.category, `${path}.category`, CATEGORIES),
    locations: Object.freeze(
      [...texts(value.locations, `${path}.locations`, 1, true)].sort(
        compareText,
      ),
    ),
    evidence: texts(value.evidence, `${path}.evidence`, 1),
    impact: text(value.impact, `${path}.impact`),
    severityRationale: text(
      value.severityRationale,
      `${path}.severityRationale`,
    ),
    examples: list(value.examples, `${path}.examples`, example, 1),
    ...(Object.hasOwn(value, "recommendation")
      ? { recommendation: text(value.recommendation, `${path}.recommendation`) }
      : {}),
  });
}

export function normalizeHypothesis(value, path) {
  record(value, path, ["id", "title", "evidence", "uncertainty"]);
  return Object.freeze({
    id: identifier(value.id, `${path}.id`),
    title: text(value.title, `${path}.title`, true),
    evidence: texts(value.evidence, `${path}.evidence`),
    uncertainty: text(value.uncertainty, `${path}.uncertainty`),
  });
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

/** Validate and copy structured content; IDs survive sorting without renumbering. */
export function normalizeAuditReport(value, fields = {}) {
  const at = (field) => fields[field] ?? `report.${field}`;
  record(value, "report", [
    "scope",
    "snapshot",
    "criteria",
    "findings",
    "limitations",
    "hypotheses",
  ]);
  record(value.snapshot, "report.snapshot", ["fingerprint", "description"]);
  if (
    typeof value.snapshot.fingerprint !== "string" ||
    value.snapshot.fingerprint.length !== 64 ||
    !HASH.test(value.snapshot.fingerprint)
  ) {
    invalid("report.snapshot.fingerprint", "invalid-fingerprint");
  }
  const findings = list(value.findings, at("findings"), normalizeFinding);
  const hypotheses = list(
    value.hypotheses,
    at("hypotheses"),
    normalizeHypothesis,
  );
  const ids = [...findings, ...hypotheses].map(({ id }) => id);
  if (new Set(ids).size !== ids.length) {
    invalid(fields.ids ?? "report", "duplicate-ids");
  }
  const causes = findings.map(({ causeId }) => causeId);
  if (new Set(causes).size !== causes.length) {
    invalid(at("findings"), "shared-cause");
  }
  return Object.freeze({
    scope: texts(value.scope, "report.scope", 1),
    snapshot: Object.freeze({
      fingerprint: value.snapshot.fingerprint,
      description: text(
        value.snapshot.description,
        "report.snapshot.description",
      ),
    }),
    criteria: texts(value.criteria, "report.criteria", 1),
    findings: Object.freeze(
      [...findings].sort(
        (left, right) =>
          SEVERITIES.indexOf(left.severity) -
            SEVERITIES.indexOf(right.severity) ||
          compareText(left.id, right.id),
      ),
    ),
    limitations: texts(value.limitations, at("limitations")),
    hypotheses: Object.freeze(
      [...hypotheses].sort((left, right) => compareText(left.id, right.id)),
    ),
  });
}
