import assert from "node:assert/strict";
import test from "node:test";

import {
  aggregateNativeEvidence,
  CHECK_IDS,
  normalizeNativeResult,
  PLATFORMS,
  PROVIDER_CHECK_IDS,
  renderNativeReport,
  SOURCE_FINDING_IDS,
} from "./index.js";

const CANDIDATE = "a".repeat(40);
const DIGEST = "b".repeat(64);
const passedPhase = () => ({
  status: "PASS",
  elapsedMs: 1,
  deadlineMs: 100,
  reason: null,
});

// Synthetic controller inputs only. A GO here tests the evidence predicate;
// it is never a native observation or an attestation of the real candidate.
function completeEvidence() {
  const source = {
    candidateSha: CANDIDATE,
    inspected: SOURCE_FINDING_IDS.map((id) => ({
      id,
      kind: "implementation",
      url: "https://example.org/source.js",
      revision: CANDIDATE,
      sha256: DIGEST,
      binding: "VERIFIED",
      complete: true,
      summary: "Synthetic reviewed implementation binding.",
    })),
    hypotheses: [],
    missingInputs: [],
    findings: SOURCE_FINDING_IDS.map((id) => ({
      id,
      status: "CLOSED",
      sourceIds: [id],
    })),
  };
  const results = [];
  const bindings = [];
  for (const [index, platform] of PLATFORMS.entries()) {
    for (const [offset, tier] of ["system", "provider"].entries()) {
      const provenance = {
        repository: "example/native-proof",
        workflow: "native-poc.yml",
        runId: "101",
        runAttempt: 1,
        jobId: String(1 + 2 * index + offset),
      };
      bindings.push({
        artifactId: String(101 + 2 * index + offset),
        candidateSha: CANDIDATE,
        platform: platform.os,
        tier,
        provenance: { ...provenance },
        conclusion: "success",
        authority: tier === "provider" ? "operator-protected" : "ordinary",
      });
      for (const checkId of CHECK_IDS.filter(
        (id) => PROVIDER_CHECK_IDS.includes(id) === (tier === "provider"),
      )) {
        const profile = checkId.startsWith("profile.")
          ? checkId.slice(8)
          : checkId === "git.fixed-commit"
            ? "commit"
            : "fixture";
        results.push({
          schemaVersion: 1,
          candidateSha: CANDIDATE,
          checkoutSha: CANDIDATE,
          platform: platform.os,
          declaredImage: platform.image,
          observed: {
            os: platform.os,
            image: platform.image,
            build: "synthetic-build",
            architecture: platform.architecture,
          },
          provenance: { ...provenance },
          checkId,
          profile,
          tier,
          dispatch: tier === "provider" ? "protected" : "native",
          implemented: true,
          versions: [{ name: "fixture", version: "1.0.0", sha256: DIGEST }],
          policy: { id: "fixture", sha256: DIGEST },
          phases: {
            setup: passedPhase(),
            probe: passedPhase(),
            cleanup: passedPhase(),
          },
          observations: [
            {
              expected: "permitted positive control and denied attempt",
              observed: "synthetic matching observation",
              matched: true,
              positiveControl: true,
              attempted: true,
              sentinelsUnchanged: true,
            },
          ],
          settlement: {
            status: "RETIRED",
            independent: true,
            emergencyCleanup: false,
          },
          status: "PASS",
          reason: null,
        });
      }
    }
  }
  return { candidateSha: CANDIDATE, source, results, bindings };
}

test("synthetic complete same-revision evidence passes the predicate independent of input order", () => {
  const input = completeEvidence();
  const before = structuredClone(input);
  const expected = aggregateNativeEvidence(input);
  assert.equal(expected.decision, "GO");
  assert.deepEqual(input, before);
  input.results.reverse();
  input.bindings.reverse();
  input.source.inspected.reverse();
  input.source.findings.reverse();
  assert.deepEqual(aggregateNativeEvidence(input), expected);
});

test("reporting alone cannot pass missing native or source evidence", () => {
  const input = completeEvidence();
  input.results = [];
  input.bindings = [];
  input.source.inspected = [];
  input.source.findings = [];
  const { report, summary, annotations } = renderNativeReport(input);
  assert.equal(report.decision, "BLOCKED");
  assert.equal(
    report.issues.filter(({ code }) => code === "MISSING").length,
    PLATFORMS.length * CHECK_IDS.length,
  );
  assert.equal(
    report.issues.filter(({ code }) => code === "SOURCE").length,
    SOURCE_FINDING_IDS.length,
  );
  assert.ok(summary.length < 8192);
  assert.equal(annotations.length, 32);
  assert.match(summary, /additional findings remain/u);
});

test("strict result validation rejects incomplete, inconsistent, and unretired PASS records", () => {
  for (const repair of [
    (r) => {
      delete r.phases.cleanup;
    },
    (r) => {
      r.rawOutput = "token=private-value";
    },
    (r) => {
      r.checkId = "unrecognized.check";
    },
    (r) => {
      r.versions.push({ ...r.versions[0] });
    },
    (r) => {
      r.observations = [];
    },
    (r) => {
      r.observations = Array(1);
    },
    (r) => {
      r.phases.probe.elapsedMs = 101;
    },
    (r) => {
      r.phases.setup.status = "FAIL";
      r.phases.setup.reason = "setup-failed";
    },
    (r) => {
      r.settlement.status = "RETAINED";
    },
    (r) => {
      r.settlement.independent = false;
    },
    (r) => {
      r.settlement.emergencyCleanup = true;
    },
    (r) => {
      r.observations[0].positiveControl = false;
    },
    (r) => {
      r.observations[0].attempted = false;
    },
    (r) => {
      r.observations[0].sentinelsUnchanged = false;
    },
    (r) => {
      r.implemented = false;
    },
    (r) => {
      r.phases.cleanup.elapsedMs = null;
    },
    (r) => {
      r.checkoutSha = "c".repeat(40);
    },
    (r) => {
      r.provenance.jobId = null;
    },
    (r) => {
      r.observed.build = "/private/fixture";
    },
    (r) => {
      r.versions[0].version = "x".repeat(513);
    },
  ]) {
    const input = completeEvidence();
    repair(input.results[0]);
    assert.throws(() => normalizeNativeResult(input.results[0]), {
      code: "ERR_INVALID_NATIVE_EVIDENCE",
    });
    const report = aggregateNativeEvidence(input);
    assert.equal(report.decision, "BLOCKED");
    assert.ok(report.issues.some(({ code }) => code === "INVALID"));
  }
});

test("duplicate, absent, unknown-platform, wrong-image, and mixed-revision evidence cannot yield GO", () => {
  for (const alter of [
    (i) => {
      i.results.push(structuredClone(i.results[0]));
    },
    (i) => {
      i.results.pop();
    },
    (i) => {
      i.bindings.push(structuredClone(i.bindings[0]));
    },
    (i) => {
      i.results[0].platform = "unknown";
    },
    (i) => {
      i.results[0].observed.architecture = "arm64";
    },
    (i) => {
      i.results[0].declaredImage = i.results[0].observed.image =
        "substituted-image";
    },
    (i) => {
      i.results[0].candidateSha = i.results[0].checkoutSha = "c".repeat(40);
    },
    (i) => {
      i.source.candidateSha = "c".repeat(40);
    },
    (i) => {
      i.bindings[0].candidateSha = "c".repeat(40);
    },
    (i) => {
      i.bindings[0].provenance.jobId = "901";
    },
    (i) => {
      i.bindings[0].conclusion = "cancelled";
    },
    (i) => {
      i.bindings.find(({ tier }) => tier === "provider").authority = "ordinary";
    },
    (i) => {
      i.results[0].observed.build = "different-build";
    },
    (i) => {
      i.results[0].policy.sha256 = "c".repeat(64);
    },
    (i) => {
      i.results[0].versions[0].version = "different-version";
    },
    (i) => {
      i.bindings = [];
    },
  ]) {
    const input = completeEvidence();
    alter(input);
    assert.equal(aggregateNativeEvidence(input).decision, "BLOCKED");
  }
});

test("revision text or publication bytes alone cannot close source findings", () => {
  for (const alter of [
    (i) => {
      i.source.inspected[0].complete = false;
    },
    (i) => {
      i.source.inspected[0].binding = "UNPROVED";
    },
    (i) => {
      i.source.inspected[0].kind = "publication";
    },
    (i) => {
      i.source.inspected[0].revision = null;
    },
    (i) => {
      i.source.findings[0].status = "BLOCKED";
    },
    (i) => {
      i.source.missingInputs.push({
        findingId: SOURCE_FINDING_IDS[0],
        summary: "Missing release/build binding.",
      });
    },
    (i) => {
      i.source.hypotheses.push({
        findingId: SOURCE_FINDING_IDS[0],
        summary: "Unproved ownership mechanism.",
      });
    },
  ]) {
    const input = completeEvidence();
    alter(input);
    assert.equal(aggregateNativeEvidence(input).decision, "BLOCKED");
  }
});

test("skipped and cancelled phases stay distinct from real probe or cleanup failure", () => {
  for (const status of ["SKIPPED", "CANCELLED", "FAIL"]) {
    const input = completeEvidence();
    const result = input.results[0];
    result.phases.probe = {
      status,
      elapsedMs: status === "FAIL" ? 100 : null,
      deadlineMs: 100,
      reason: status === "FAIL" ? "deadline" : status.toLowerCase(),
    };
    result.observations = [];
    result.status = status === "FAIL" ? "FAIL" : "BLOCKED";
    result.reason = result.phases.probe.reason;
    const report = aggregateNativeEvidence(input);
    assert.equal(report.decision, status === "FAIL" ? "NO_GO" : "BLOCKED");
    assert.ok(report.issues.some(({ code }) => code === "PROBE"));
    assert.equal(
      report.results.find(
        ({ checkId, platform }) =>
          checkId === result.checkId && platform === result.platform,
      ).phases.probe.status,
      status,
    );
  }
  const input = completeEvidence();
  input.results[0].status = "FAIL";
  input.results[0].reason = "unretired";
  input.results[0].settlement.emergencyCleanup = true;
  assert.equal(aggregateNativeEvidence(input).decision, "NO_GO");
  input.results[0].status = "BLOCKED";
  input.results[0].phases.cleanup = {
    status: "FAIL",
    elapsedMs: 100,
    deadlineMs: 100,
    reason: "cleanup-failed",
  };
  const report = aggregateNativeEvidence(input);
  assert.equal(report.decision, "NO_GO");
  assert.ok(report.issues.some(({ code }) => code === "INCONSISTENT"));
});

test("protected dispatch is required by default and cannot be replaced by a transport claim", () => {
  const input = completeEvidence();
  const result = input.results.find(({ tier }) => tier === "provider");
  result.tier = "system";
  result.dispatch = "model-free";
  const report = aggregateNativeEvidence(input);
  assert.equal(report.decision, "BLOCKED");
  assert.ok(report.issues.some(({ code }) => code === "DISPATCH"));
});

test("unimplemented checks retain explicit BLOCKED records and profile checks cannot borrow another profile", () => {
  const input = completeEvidence();
  const result = input.results[0];
  result.implemented = false;
  result.status = "BLOCKED";
  result.reason = "unimplemented";
  result.provenance.jobId = null;
  result.observations = [];
  for (const name of ["setup", "probe", "cleanup"])
    result.phases[name] = {
      status: "NOT_RUN",
      elapsedMs: null,
      deadlineMs: 100,
      reason: "unimplemented",
    };
  result.settlement = {
    status: "RETAINED",
    independent: false,
    emergencyCleanup: false,
  };
  const report = aggregateNativeEvidence(input);
  assert.equal(report.decision, "BLOCKED");
  assert.ok(
    report.results.some(
      (entry) => !entry.implemented && entry.reason === "unimplemented",
    ),
  );
  assert.ok(
    report.results.some(
      (entry) =>
        entry.provenance.jobId === null &&
        entry.phases.probe.status === "NOT_RUN",
    ),
  );
  const wrongProfile = completeEvidence().results.find(
    ({ checkId }) => checkId === "profile.read-only",
  );
  wrongProfile.profile = "workspace-write";
  assert.throws(() => normalizeNativeResult(wrongProfile), {
    code: "ERR_INVALID_NATIVE_EVIDENCE",
  });
});

test("diagnostic prose is bounded and never becomes Markdown or annotation instructions", () => {
  const input = completeEvidence();
  const diagnostic =
    'token=private-value password="private-password" Bearer private-bearer https://example.org/?key=private-query /private/fixture C:\\private\\fixture\n::error title=injected::private-instruction\u001b[31m\u202e';
  input.results[0].observations[0].observed = diagnostic;
  input.source.inspected[0].summary = diagnostic;
  input.source.missingInputs = [
    { findingId: SOURCE_FINDING_IDS[0], summary: diagnostic },
  ];
  const { report, summary, annotations } = renderNativeReport(input);
  const serialized = JSON.stringify(report);
  for (const value of [
    "private-value",
    "private-password",
    "private-bearer",
    "private-query",
    "/private/fixture",
    "C:\\private\\fixture",
  ])
    assert.ok(!serialized.includes(value));
  assert.ok(!summary.includes("private-instruction"));
  assert.ok(!annotations.join("\n").includes("injected"));
  const result = structuredClone(input.results[0]);
  result.observations[0].observed = "x".repeat(4096);
  assert.equal(
    normalizeNativeResult(result).observations[0].observed.length,
    512,
  );
  assert.ok(
    !/[\p{Cc}\p{Cf}]/u.test(
      normalizeNativeResult(input.results[0]).observations[0].observed,
    ),
  );
});

test("redaction covers isolated credentials, paths, and control-obfuscated assignments", () => {
  for (const diagnostic of [
    'password="private-value"',
    'token="private-value\nprivate-value"',
    "access_token=private-value",
    "refresh_token=private-value",
    "client_secret=private-value",
    "to\u001b[31mken=private-value",
    "to\u202eken=private-value",
    "Bearer private-value",
    "Basic private-value",
    "sk-private-value",
    "https://example.org/private-value",
    "/private-value/fixture",
    "C:\\private-value\\fixture",
    "::error title=private-value::injected",
  ]) {
    const result = completeEvidence().results[0];
    result.observations[0].observed = diagnostic;
    const normalized = normalizeNativeResult(result);
    assert.ok(!JSON.stringify(normalized).includes("private-value"));
  }
});
