import { AUDIT_CATALOG } from "./catalog.js";

const ID = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/u;
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
  constructor(issue) {
    super("Invalid audit report.");
    this.name = "AuditReportValidationError";
    this.code = "ERR_INVALID_AUDIT_REPORT";
    this.issues = Object.freeze([issue]);
  }
}

function invalid(path, message) {
  throw new AuditReportValidationError(`${path} ${message}`);
}

function record(value, path, required, optional = []) {
  if (
    value === null ||
    typeof value !== "object" ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  ) {
    invalid(path, "must be an object.");
  }
  if (
    Object.keys(value).some((key) => ![...required, ...optional].includes(key))
  ) {
    invalid(path, "contains unsupported fields.");
  }
  if (required.some((key) => !Object.hasOwn(value, key))) {
    invalid(path, "is missing required fields.");
  }
}

function text(value, path, singleLine = false) {
  if (typeof value !== "string") invalid(path, "must be text.");
  const normalized = value.replace(/\r\n?/gu, "\n");
  if (
    normalized.trim().length === 0 ||
    /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u2028\u2029]/u.test(normalized) ||
    (singleLine && /[\n\t]/u.test(normalized))
  ) {
    invalid(
      path,
      "must be nonempty text without control characters or unsupported line breaks.",
    );
  }
  return normalized.trim();
}

function identifier(value, path) {
  if (
    typeof value !== "string" ||
    value.length > 64 ||
    value !== value.trim() ||
    !ID.test(value)
  ) {
    invalid(
      path,
      "must be a lowercase kebab-case ID of at most 64 characters.",
    );
  }
  return value;
}

function choice(value, path, allowed) {
  if (!allowed.includes(value)) invalid(path, "must be a supported value.");
  return value;
}

function list(value, path, normalize, minimum = 0) {
  if (!Array.isArray(value) || value.length < minimum) {
    invalid(path, `must be an array with at least ${minimum} entries.`);
  }
  return Object.freeze(
    Array.from(value, (item, index) => normalize(item, `${path}[${index}]`)),
  );
}

function texts(value, path, minimum = 0, singleLine = false) {
  const result = list(
    value,
    path,
    (item, at) => text(item, at, singleLine),
    minimum,
  );
  if (new Set(result).size !== result.length) {
    invalid(path, "must not contain duplicates.");
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

function finding(value, path) {
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

function hypothesis(value, path) {
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
export function normalizeAuditReport(value) {
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
    !/^[a-f0-9]{64}$/u.test(value.snapshot.fingerprint)
  ) {
    invalid(
      "report.snapshot.fingerprint",
      "must be a SHA-256 content fingerprint.",
    );
  }
  const findings = list(value.findings, "report.findings", finding);
  const hypotheses = list(value.hypotheses, "report.hypotheses", hypothesis);
  const ids = [...findings, ...hypotheses].map(({ id }) => id);
  if (new Set(ids).size !== ids.length) {
    invalid("report", "must have unique report-local IDs.");
  }
  const causes = findings.map(({ causeId }) => causeId);
  if (new Set(causes).size !== causes.length) {
    invalid(
      "report.findings",
      "must consolidate each shared cause into one finding retaining all locations.",
    );
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
    limitations: texts(value.limitations, "report.limitations"),
    hypotheses: Object.freeze(
      [...hypotheses].sort((left, right) => compareText(left.id, right.id)),
    ),
  });
}
