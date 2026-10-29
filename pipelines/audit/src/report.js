import { AUDIT_CATALOG } from "./catalog.js";
import { normalizeAuditReport } from "./findings.js";

// Report fields are plain text, including source fragments and untrusted paths.
function markdown(value) {
  return value
    .replace(/&/gu, "&amp;")
    .replace(/</gu, "&lt;")
    .replace(/>/gu, "&gt;")
    .replace(/[\\`*_[\]{}()#+\-.!|~]/gu, "\\$&")
    .replace(/\n/gu, "<br>");
}

function bullets(values) {
  return values.map((value) => `- ${markdown(value)}`).join("\n");
}

function classificationMap() {
  return [
    "## Classification map",
    "Severity describes impact and realistic likelihood; category describes the primary problem. They are independent.",
    "| Severity | Meaning |\n| --- | --- |\n" +
      AUDIT_CATALOG.severities
        .map(({ name, description }) => `| ${name} | ${description} |`)
        .join("\n"),
    "| Category | Primary concern |\n| --- | --- |\n" +
      AUDIT_CATALOG.categories
        .map(({ name, description }) => `| ${name} | ${description} |`)
        .join("\n"),
  ].join("\n\n");
}

function renderExample(example, index) {
  const fields =
    example.kind === "behavioral"
      ? [
          ["Conditions/input", example.conditions],
          ["Action", example.action],
          ["Expected", example.expected],
          [
            example.basis === "observed" ? "Observed" : "Derived",
            example.actual,
          ],
        ]
      : [
          ["Specific material", example.material],
          ["Established rule", example.rule],
          ["Violation", example.violation],
        ];
  return [
    `**Concrete failure example ${index + 1} (${example.basis}; ${example.kind})**`,
    fields
      .map(([label, value]) => `- **${label}:** ${markdown(value)}`)
      .join("\n"),
  ].join("\n\n");
}

function renderFinding(finding) {
  return [
    `### ${finding.id}: ${markdown(finding.title)}`,
    `**Severity:** ${finding.severity} · **Category:** ${finding.category}`,
    `**Locations**\n\n${bullets(finding.locations)}`,
    `**Evidence**\n\n${bullets(finding.evidence)}`,
    `**Impact:** ${markdown(finding.impact)}`,
    `**Severity rationale:** ${markdown(finding.severityRationale)}`,
    ...finding.examples.map(renderExample),
    ...(finding.recommendation === undefined
      ? []
      : [`**Recommendation:** ${markdown(finding.recommendation)}`]),
  ].join("\n\n");
}

function renderHypothesis(hypothesis) {
  return [
    `#### ${hypothesis.id}: ${markdown(hypothesis.title)} (unverified)`,
    `**Uncertainty:** ${markdown(hypothesis.uncertainty)}`,
    ...(hypothesis.evidence.length === 0
      ? []
      : [`**Available evidence**\n\n${bullets(hypothesis.evidence)}`]),
  ].join("\n\n");
}

/** Render audit.md bytes only. The caller owns review gates and publication. */
export function renderAuditReport(value) {
  const report = normalizeAuditReport(value);
  const count = report.findings.length;
  return (
    [
      "# Audit report",
      count === 0
        ? "No confirmed findings."
        : `${count} confirmed finding${count === 1 ? "" : "s"}.`,
      "## Scope",
      bullets(report.scope),
      "## Snapshot",
      markdown(report.snapshot.description),
      `**Content fingerprint:** ${report.snapshot.fingerprint}`,
      "## Criteria used",
      bullets(report.criteria),
      classificationMap(),
      "## Confirmed findings",
      count === 0 ? "None." : report.findings.map(renderFinding).join("\n\n"),
      "## Limitations and uncertainty",
      "### Coverage limitations and unavailable checks",
      report.limitations.length === 0
        ? "None recorded."
        : bullets(report.limitations),
      "### Unverified hypotheses",
      report.hypotheses.length === 0
        ? "None recorded."
        : report.hypotheses.map(renderHypothesis).join("\n\n"),
    ].join("\n\n") + "\n"
  );
}
