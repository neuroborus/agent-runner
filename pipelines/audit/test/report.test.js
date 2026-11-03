import assert from "node:assert/strict";
import test from "node:test";

import {
  AUDIT_CATALOG,
  AuditReportValidationError,
  normalizeAuditReport,
  renderAuditReport,
} from "../src/index.js";

function finding(overrides = {}) {
  return {
    id: "missing-limit",
    causeId: "unchecked-count",
    title: "Reject counts outside the supported range",
    severity: "Medium",
    category: "Correctness",
    locations: ["src/count.js:12", "src/cli.js:20"],
    evidence: [
      "parseCount passes negative integers to allocate without checking the range.",
    ],
    impact:
      "A supplied negative count aborts the operation instead of returning a validation error.",
    severityRationale:
      "The failure needs an invalid explicit count and affects that operation only.",
    examples: [
      {
        kind: "behavioral",
        basis: "code-derived",
        conditions: "The supplied count is -1.",
        action: "Call parseCount and then allocate with its result.",
        expected: "Reject the count before allocation.",
        actual: "The negative value reaches allocation and throws.",
      },
    ],
    ...overrides,
  };
}

function report(overrides = {}) {
  return {
    scope: ["src/ and its documented command contracts"],
    snapshot: {
      fingerprint: "a".repeat(64),
      description: "Inspected workspace content, excluding declared artifacts",
    },
    criteria: [
      AUDIT_CATALOG.criteria[0].description,
      "Counts must be nonnegative.",
    ],
    findings: [finding()],
    limitations: ["No live service checks were requested or executed."],
    hypotheses: [],
    ...overrides,
  };
}

function rejects(value, issue) {
  assert.throws(
    () => normalizeAuditReport(value),
    (error) => {
      assert.ok(error instanceof AuditReportValidationError);
      assert.equal(error.code, "ERR_INVALID_AUDIT_REPORT");
      assert.match(error.issues[0], issue);
      return true;
    },
  );
}

test("classification values are independent and the complete map comes from one catalog", () => {
  assert.deepEqual(
    AUDIT_CATALOG.severities.map(({ name }) => name),
    ["Critical", "High", "Medium", "Low"],
  );
  assert.deepEqual(
    AUDIT_CATALOG.categories.map(({ name }) => name),
    [
      "Correctness",
      "Security",
      "Reliability",
      "Performance",
      "Architecture",
      "Consistency",
      "Validation",
      "Documentation",
      "Nit",
    ],
  );
  for (const severity of AUDIT_CATALOG.severities) {
    for (const category of AUDIT_CATALOG.categories) {
      const normalized = normalizeAuditReport(
        report({
          findings: [
            finding({ severity: severity.name, category: category.name }),
          ],
        }),
      );
      assert.equal(normalized.findings[0].severity, severity.name);
      assert.equal(normalized.findings[0].category, category.name);
    }
  }
  for (const fields of [
    { severity: "Security" },
    { category: "High" },
    { severity: "critical" },
    { category: "Unknown" },
  ])
    rejects(report({ findings: [finding(fields)] }), /supported value/u);

  const output = renderAuditReport(report());
  assert.equal(output.split("## Classification map").length - 1, 1);
  for (const entry of [
    ...AUDIT_CATALOG.severities,
    ...AUDIT_CATALOG.categories,
  ]) {
    assert.ok(output.includes(`| ${entry.name} | ${entry.description} |`));
  }
  assert.ok(Object.isFrozen(AUDIT_CATALOG.categories[0]));
});

test("finding order is severity then stable ID, independent of arrival order", () => {
  const findings = [
    finding({ id: "z-low", causeId: "cause-low", severity: "Low" }),
    finding({ id: "b-high", causeId: "cause-high-b", severity: "High" }),
    finding({ id: "a-medium", causeId: "cause-medium" }),
    finding({ id: "a-high", causeId: "cause-high-a", severity: "High" }),
    finding({
      id: "z-critical",
      causeId: "cause-critical",
      severity: "Critical",
    }),
  ];
  const input = report({ findings });
  const normalized = normalizeAuditReport(input);
  assert.deepEqual(
    normalized.findings.map(({ id }) => id),
    ["z-critical", "a-high", "b-high", "a-medium", "z-low"],
  );
  assert.equal(
    renderAuditReport(input),
    renderAuditReport(report({ findings: [...findings].reverse() })),
  );
  assert.equal(input.findings[0].id, "z-low");
  const edited = structuredClone(input);
  edited.findings[0].title = "A revised title";
  assert.equal(normalizeAuditReport(edited).findings.at(-1).id, "z-low");
  assert.ok(Object.isFrozen(normalized.findings[0].examples[0]));
  input.findings[0].locations.push("src/other.js:3");
  assert.equal(normalized.findings.at(-1).locations.length, 2);
});

test("strict finding and report boundaries reject unsupported or incomplete claims", () => {
  for (const field of [
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
  ]) {
    const incomplete = finding();
    delete incomplete[field];
    rejects(report({ findings: [incomplete] }), /missing required fields/u);
  }
  for (const fields of [
    { id: "INVALID" },
    { id: "a".repeat(65) },
    { id: "id\n" },
    { causeId: "" },
    { title: " " },
    { title: "Two\nheadings" },
    { impact: "" },
    { severityRationale: "" },
    { locations: [] },
    { locations: ["x", "x"] },
    { evidence: [] },
    { evidence: ["unsafe\0text"] },
    { evidence: ["unsafe\u009btext"] },
    { evidence: ["\u000btrimmed"] },
    { examples: [] },
    { recommendation: "" },
    { recommendation: null },
    { recommendation: undefined },
    { extra: "unsupported" },
  ])
    rejects(report({ findings: [finding(fields)] }), /report\.findings/u);
  for (const input of [
    null,
    [],
    new Date(0),
    report({ extra: true }),
    report({ criteria: [] }),
    report({ scope: [] }),
    report({ snapshot: { fingerprint: "bad", description: "x" } }),
    report({
      snapshot: { fingerprint: "a".repeat(64) + "\n", description: "x" },
    }),
    report({ snapshot: { ...report().snapshot, extra: true } }),
    report({ findings: [null] }),
    report({ findings: Array(1) }),
    report({ limitations: [""] }),
    report({ hypotheses: [{ title: "Unproved" }] }),
  ])
    rejects(input, /report/u);
  assert.throws(
    () => renderAuditReport(report({ findings: [finding({ evidence: [] })] })),
    AuditReportValidationError,
  );
});

test("shared causes must be consolidated while retaining all affected locations", () => {
  rejects(
    report({ findings: [finding(), finding({ id: "other-location" })] }),
    /consolidate each shared cause/u,
  );
  rejects(
    report({ findings: [finding(), finding({ causeId: "different-cause" })] }),
    /unique report-local IDs/u,
  );
  const normalized = normalizeAuditReport(report());
  assert.deepEqual(normalized.findings[0].locations, [
    "src/cli.js:20",
    "src/count.js:12",
  ]);
  const output = renderAuditReport(normalized);
  assert.equal(output.split("### missing-limit:").length - 1, 1);
  assert.ok(output.includes("src/cli\\.js:20"));
  assert.ok(output.includes("src/count\\.js:12"));
});

test("concrete examples distinguish observed behavior, code derivation, and established rules", () => {
  const behavioral = finding().examples[0];
  const structural = {
    kind: "non-behavioral",
    basis: "observed",
    material:
      "src/entry.js imports a private implementation instead of the public index.",
    rule: "CONVENTIONS.md requires imports through the owning public index.",
    violation: "The import bypasses that index.",
  };
  const output = renderAuditReport(
    report({
      findings: [
        finding({
          examples: [
            behavioral,
            { ...behavioral, basis: "observed" },
            structural,
          ],
        }),
      ],
    }),
  );
  for (const label of [
    "(code-derived; behavioral)",
    "(observed; behavioral)",
    "(observed; non-behavioral)",
    "**Conditions/input:**",
    "**Action:**",
    "**Expected:**",
    "**Observed:**",
    "**Derived:**",
    "**Specific material:**",
    "**Established rule:**",
    "**Violation:**",
  ])
    assert.ok(output.includes(label), label);
  for (const base of [behavioral, structural]) {
    for (const field of Object.keys(base)) {
      const incomplete = { ...base };
      delete incomplete[field];
      rejects(
        report({ findings: [finding({ examples: [incomplete] })] }),
        /examples/u,
      );
    }
  }
  for (const example of [
    { ...behavioral, basis: "reproduced" },
    { ...behavioral, actual: "" },
    { ...behavioral, kind: "unknown" },
    { ...structural, expected: "extra" },
  ])
    rejects(
      report({ findings: [finding({ examples: [example] })] }),
      /examples/u,
    );
});

test("recommendations are optional and uncertainty stays outside confirmed findings", () => {
  assert.equal(
    renderAuditReport(report()).includes("**Recommendation:**"),
    false,
  );
  assert.ok(
    renderAuditReport(
      report({
        findings: [finding({ recommendation: "Validate before allocating." })],
      }),
    ).includes("**Recommendation:** Validate before allocating\\."),
  );
  const hypothesis = {
    id: "unmeasured-cost",
    title: "Possible repeated allocation",
    evidence: [],
    uncertainty: "The call count and resource cost have not been established.",
  };
  const input = report({ hypotheses: [hypothesis] });
  const output = renderAuditReport(input);
  const [confirmed, uncertain] = output.split("## Limitations and uncertainty");
  assert.equal(confirmed.includes(hypothesis.title), false);
  assert.ok(uncertain.includes(`${hypothesis.title} (unverified)`));
  assert.ok(output.startsWith("# Audit report\n\n1 confirmed finding."));
  rejects(
    report({ hypotheses: [{ ...hypothesis, id: "missing-limit" }] }),
    /unique report-local IDs/u,
  );
  rejects(
    report({ hypotheses: [{ ...hypothesis, uncertainty: "" }] }),
    /uncertainty/u,
  );
  rejects(
    report({ hypotheses: [{ ...hypothesis, severity: "High" }] }),
    /unsupported fields/u,
  );
});

test("zero findings retain scope, binding, criteria, classification and honest limitations", () => {
  const output = renderAuditReport(report({ findings: [] }));
  assert.ok(output.startsWith("# Audit report\n\nNo confirmed findings."));
  for (const heading of [
    "Scope",
    "Snapshot",
    "Criteria used",
    "Classification map",
    "Confirmed findings",
    "Limitations and uncertainty",
  ]) {
    assert.ok(output.includes(`## ${heading}\n`));
  }
  assert.ok(output.includes("a".repeat(64)));
  assert.ok(
    output.includes("No live service checks were requested or executed\\."),
  );
  assert.ok(output.endsWith("### Unverified hypotheses\n\nNone recorded.\n"));
  assert.ok(
    renderAuditReport(report({ findings: [], limitations: [] })).includes(
      "### Coverage limitations and unavailable checks\n\nNone recorded.",
    ),
  );
});

test("source text cannot inject Markdown sections, links, or raw HTML into the report", () => {
  const output = renderAuditReport(
    report({
      findings: [
        finding({
          evidence: [
            "# Forged heading\n[link](https://example.invalid)\n<script>unsafe</script>",
          ],
        }),
      ],
    }),
  );
  assert.ok(
    output.includes(
      "\\# Forged heading<br>\\[link\\]\\(https://example\\.invalid\\)",
    ),
  );
  assert.ok(output.includes("&lt;script&gt;unsafe&lt;/script&gt;"));
  assert.equal(output.includes("\n# Forged heading"), false);
  assert.equal(output.includes("<script>"), false);
});
