import assert from "node:assert/strict";
import test from "node:test";

import {
  aggregateNativeEvidence,
  CHECK_IDS,
  initializeNativeJob,
  joinNativeArtifacts,
  nativeArtifactName,
  normalizeNativeResult,
  PLATFORMS,
  PROVIDER_CHECK_IDS,
  recordNativeStage,
  renderNativeJob,
  renderNativeReport,
  resolveNativeDispatch,
  selectNativeArtifacts,
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

const ciContext = () => ({
  candidateSha: CANDIDATE,
  repository: "example/native-proof",
  runId: "101",
  runAttempt: 1,
  workflowSha: "c".repeat(40),
});

function reportingJob(platform = PLATFORMS[0], jobId = "1") {
  const { workflowSha, ...context } = ciContext();
  let job = initializeNativeJob({ ...context, platform: platform.os });
  job = recordNativeStage(job, "setup", passedPhase(), {
    checkoutSha: CANDIDATE,
    observed: {
      os: platform.os,
      image: platform.image,
      build: "synthetic-build",
      architecture: "x64",
    },
    provenance: { ...job.provenance, jobId },
    versions: [{ name: "node", version: "v24.21.0", sha256: DIGEST }],
  });
  job = recordNativeStage(job, "probe", passedPhase());
  return recordNativeStage(job, "cleanup", passedPhase());
}

test("system dispatch is closed and cannot activate protected provider execution", () => {
  assert.deepEqual(resolveNativeDispatch(["--tier", "system"]), {
    tier: "system",
    stage: "all",
  });
  assert.equal(
    resolveNativeDispatch(["--tier", "system", "--stage", "cleanup"]).stage,
    "cleanup",
  );
  for (const args of [
    [],
    ["--tier", "provider"],
    ["--tier", "system", "--stage"],
    ["--tier", "system", "--stage", "unknown"],
    ["--tier", "system", "--retry", "all"],
  ])
    assert.throws(() => resolveNativeDispatch(args), {
      code: "ERR_INVALID_NATIVE_EVIDENCE",
    });
  const report = renderNativeJob(reportingJob()).report;
  assert.equal(report.decision, "BLOCKED");
  assert.equal(report.ciStatus, "PASS");
  assert.ok(
    report.results.every(
      ({ implemented, status, observations, settlement }) =>
        !implemented &&
        status === "BLOCKED" &&
        observations.length === 0 &&
        settlement.status === "RETAINED",
    ),
  );
});

test("CI stage failures remain distinct, cleanup is attempted, and probe cannot precede admission", () => {
  const { workflowSha, ...context } = ciContext();
  const initial = initializeNativeJob({ ...context, platform: "linux" });
  assert.throws(() => recordNativeStage(initial, "probe", passedPhase()), {
    code: "ERR_INVALID_NATIVE_EVIDENCE",
  });
  assert.equal(initial.stages.setup.status, "NOT_RUN");
  const ready = reportingJob();
  const setup = {
    checkoutSha: ready.checkoutSha,
    observed: ready.observed,
    provenance: ready.provenance,
    versions: ready.versions,
  };
  for (const stage of ["setup", "probe", "cleanup"]) {
    let job = initial;
    for (const name of ["setup", "probe", "cleanup"])
      job = recordNativeStage(
        job,
        name,
        name === stage
          ? { ...passedPhase(), status: "FAIL", reason: `${name}-failed` }
          : name === "probe" && stage === "setup"
            ? { ...passedPhase(), status: "NOT_RUN", reason: "setup-failed" }
            : passedPhase(),
        name === "setup" ? setup : {},
      );
    const { report, summary } = renderNativeJob(job);
    assert.equal(report.decision, "BLOCKED");
    assert.equal(report.ciStatus, "FAIL");
    assert.equal(report.ciStages[stage].status, "FAIL");
    assert.ok(
      report.results.every(
        (result) =>
          !result.implemented &&
          result.status === "BLOCKED" &&
          Object.values(result.phases).every(
            ({ status, reason }) =>
              status === "NOT_RUN" && reason === "unimplemented",
          ),
      ),
    );
    assert.match(summary, new RegExp(`${stage}: FAIL`, "u"));
    assert.equal(
      job.stages.cleanup.status,
      stage === "cleanup" ? "FAIL" : "PASS",
    );
    assert.throws(() => recordNativeStage(job, "setup", passedPhase()), {
      code: "ERR_INVALID_NATIVE_EVIDENCE",
    });
  }
});

function ciMetadata() {
  const context = ciContext();
  const run = {
    id: 101,
    run_attempt: 1,
    repository: { full_name: context.repository },
    path: ".github/workflows/native-poc.yml",
    event: "pull_request",
    head_sha: context.workflowSha,
  };
  const jobs = PLATFORMS.map(({ os }, index) => ({
    id: index + 1,
    name: `native-system-${os}`,
    run_id: 101,
    run_attempt: 1,
    status: "completed",
    conclusion: "success",
    started_at: "2026-01-01T00:00:00Z",
    completed_at: "2026-01-01T00:01:00Z",
    steps: [
      { name: `Bind native artifact ${201 + index}`, conclusion: "success" },
      ...[
        "Setup",
        "Probe reporting harness",
        "Cleanup",
        "Report per-OS evidence",
      ].map((name) => ({ name, conclusion: "success" })),
    ],
  }));
  const artifacts = PLATFORMS.map(({ os }, index) => ({
    id: 201 + index,
    name: nativeArtifactName(context, os),
    expired: false,
    size_in_bytes: 1000,
    digest: `sha256:${DIGEST}`,
    workflow_run: { id: 101, head_sha: context.workflowSha },
    created_at: "2026-01-01T00:00:30Z",
  }));
  const payloads = Object.fromEntries(
    PLATFORMS.map((platform, index) => [
      nativeArtifactName(context, platform.os),
      reportingJob(platform, String(index + 1)),
    ]),
  );
  return { context, run, jobs, artifacts, payloads };
}

test("artifact joining uses actual run/job upload receipts and rejects missing or mixed-revision payloads", () => {
  const input = ciMetadata();
  const before = structuredClone(input);
  const selection = selectNativeArtifacts(
    input.context,
    input.run,
    input.jobs,
    input.artifacts,
  );
  assert.equal(selection.entries.length, 3);
  assert.deepEqual(selection.issues, []);
  const rendered = joinNativeArtifacts(
    input.context,
    selection,
    input.payloads,
  );
  assert.deepEqual(rendered.report.ciIssues, []);
  assert.equal(rendered.report.bindings.length, 3);
  assert.equal(rendered.report.decision, "BLOCKED");
  assert.equal(rendered.report.ciStatus, "PASS");
  assert.deepEqual(input, before);
  const reordered = structuredClone(selection);
  reordered.entries.reverse();
  reordered.jobs.reverse();
  for (const entry of reordered.entries)
    entry.stages = Object.fromEntries(Object.entries(entry.stages).reverse());
  assert.deepEqual(
    joinNativeArtifacts(input.context, reordered, input.payloads),
    rendered,
  );
  assert.throws(
    () =>
      joinNativeArtifacts(
        input.context,
        {
          entries: [],
          issues: [{ code: "token=private-value", platform: null }],
          jobs: [],
        },
        {},
      ),
    { code: "ERR_INVALID_NATIVE_EVIDENCE" },
  );
  const unsafe = structuredClone(selection);
  unsafe.entries[0].name = "../private-control";
  assert.throws(() => joinNativeArtifacts(input.context, unsafe, {}), {
    code: "ERR_INVALID_NATIVE_EVIDENCE",
  });
  const missingSelection = { ...selection, entries: [] };
  const missingReport = joinNativeArtifacts(
    input.context,
    missingSelection,
    {},
  ).report;
  assert.equal(missingReport.ciStatus, "BLOCKED");
  assert.deepEqual(
    missingReport.ciIssues,
    PLATFORMS.map(({ os }) => ({ code: "missing", platform: os })),
  );
  for (const alter of [
    (i) => {
      i.run.run_attempt = 2;
    },
    (i) => {
      i.artifacts.pop();
    },
    (i) => {
      i.artifacts.push(structuredClone(i.artifacts[0]));
    },
    (i) => {
      i.artifacts[0].workflow_run.head_sha = "d".repeat(40);
    },
    (i) => {
      i.jobs[0].steps[0].name = "Bind native artifact 999";
    },
    (i) => {
      i.jobs[0].steps[0].conclusion = "skipped";
    },
    (i) => {
      delete i.payloads[i.artifacts[0].name];
    },
    (i) => {
      i.payloads[i.artifacts[0].name].candidateSha = "d".repeat(40);
    },
    (i) => {
      i.payloads[i.artifacts[0].name].provenance.jobId = "999";
    },
  ]) {
    const changed = ciMetadata();
    alter(changed);
    const selected = selectNativeArtifacts(
      changed.context,
      changed.run,
      changed.jobs,
      changed.artifacts,
    );
    const report = joinNativeArtifacts(
      changed.context,
      selected,
      changed.payloads,
    ).report;
    assert.equal(report.decision, "BLOCKED");
    assert.ok(report.ciIssues.length > 0);
  }
  const cancelled = ciMetadata();
  cancelled.jobs[0].conclusion = "cancelled";
  const cancelledReport = joinNativeArtifacts(
    cancelled.context,
    selectNativeArtifacts(
      cancelled.context,
      cancelled.run,
      cancelled.jobs,
      cancelled.artifacts,
    ),
    cancelled.payloads,
  ).report;
  assert.equal(
    cancelledReport.bindings.find(({ platform }) => platform === "linux")
      .conclusion,
    "cancelled",
  );
  assert.equal(cancelledReport.decision, "BLOCKED");
  assert.equal(cancelledReport.ciStatus, "BLOCKED");
  cancelled.artifacts = [];
  const absent = joinNativeArtifacts(
    cancelled.context,
    selectNativeArtifacts(
      cancelled.context,
      cancelled.run,
      cancelled.jobs,
      cancelled.artifacts,
    ),
    {},
  ).report;
  assert.equal(
    absent.ciJobs.find(({ platform }) => platform === "linux").conclusion,
    "cancelled",
  );
  assert.equal(
    absent.ciJobs.find(({ platform }) => platform === "linux").artifactId,
    null,
  );
  assert.ok(absent.ciIssues.some(({ code }) => code === "missing"));
  const partial = ciMetadata();
  partial.artifacts.pop();
  const partialSelection = selectNativeArtifacts(
    partial.context,
    partial.run,
    partial.jobs,
    partial.artifacts,
  );
  partialSelection.issues.push({ code: "download", platform: null });
  const incomplete = joinNativeArtifacts(
    partial.context,
    partialSelection,
    partial.payloads,
  ).report;
  assert.equal(incomplete.ciStatus, "BLOCKED");
  assert.ok(incomplete.ciIssues.some(({ code }) => code === "download"));
  const failed = ciMetadata();
  failed.jobs[0].conclusion = "failure";
  failed.jobs[0].steps.find(
    ({ name }) => name === "Probe reporting harness",
  ).conclusion = "failure";
  failed.payloads[failed.artifacts[0].name].stages.probe = {
    ...passedPhase(),
    status: "FAIL",
    reason: "probe-failed",
  };
  const failedReport = joinNativeArtifacts(
    failed.context,
    selectNativeArtifacts(
      failed.context,
      failed.run,
      failed.jobs,
      failed.artifacts,
    ),
    failed.payloads,
  ).report;
  assert.equal(failedReport.decision, "BLOCKED");
  assert.equal(failedReport.ciStatus, "FAIL");
  assert.equal(
    failedReport.ciJobs.find(({ platform }) => platform === "linux").stages
      .probe,
    "failure",
  );
});
