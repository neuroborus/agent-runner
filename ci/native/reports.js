import {
  CHECK_IDS,
  PLATFORMS,
  PROVIDER_CHECK_IDS,
  SOURCE_FINDING_IDS,
} from "./catalog.js";
import {
  normalizeBinding,
  normalizeNativeResult,
  normalizeRequest,
  normalizeSourceEvidence,
} from "./evidence.js";
import { verifyPreparedPublicInputs } from "./public-inputs.js";

const ACTIONS = Object.freeze({
  INVALID: "Repair the closed evidence shape; raw diagnostics are omitted.",
  DUPLICATE:
    "Supply exactly one record per platform/check and one artifact per job.",
  SOURCE:
    "Close the source finding with complete release-bound implementation review.",
  REVISION: "Collect fresh evidence for the exact candidate checkout SHA.",
  PLATFORM:
    "Use the declared image and record its actual OS, build, and x64 architecture.",
  MISSING:
    "Implement and run the missing native check; retain BLOCKED until then.",
  PROVENANCE:
    "Bind the artifact to independently read workflow/run/job metadata and required protected authority.",
  INCONSISTENT:
    "Reconcile phase/result status, observed job image/build, component versions, and effective profile policy; rerun after repair.",
  DISPATCH:
    "Exercise the required real tool dispatch in the approved acceptance environment.",
  SETUP:
    "Repair setup and rerun the case with a ready permitted positive control.",
  PROBE:
    "Investigate the attempted operation and rerun after repair; timeouts are not denials.",
  CLEANUP:
    "Independently establish bounded retirement and sentinel preservation.",
  SETTLEMENT:
    "Retain exclusion until independent retirement is proved; emergency cleanup preserves failure.",
  RESULT:
    "Resolve the recorded failure or missing input and collect fresh native evidence.",
});

function jobKey(value) {
  const { repository, workflow, runId, runAttempt, jobId } = value.provenance;
  return JSON.stringify([repository, workflow, runId, runAttempt, jobId]);
}

function compare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

/** Bind only metadata supplied independently by the CI controller, never a
 * binding copied from the payload. This pure join cannot authenticate CI APIs. */
export function aggregateNativeEvidence(input) {
  const request = normalizeRequest(input);
  const issues = [];
  const add = (code, platform = null, checkId = null) =>
    issues.push({ code, platform, checkId, message: ACTIONS[code] });
  let source = null;
  try {
    source = normalizeSourceEvidence(request.source);
  } catch {
    add("INVALID");
  }
  if (source?.candidateSha !== request.candidateSha) add("REVISION");
  for (const id of SOURCE_FINDING_IDS) {
    const finding = source?.findings.find((entry) => entry.id === id);
    const facts =
      finding?.sourceIds.map((sourceId) =>
        source.inspected.find((fact) => fact.id === sourceId),
      ) ?? [];
    const complete =
      facts.length > 0 &&
      facts.every(
        (fact) =>
          fact.complete &&
          fact.binding === "VERIFIED" &&
          fact.summary &&
          (fact.kind === "publication" || fact.revision !== null),
      ) &&
      facts.some((fact) => fact.kind === "implementation");
    if (
      finding?.status !== "CLOSED" ||
      !complete ||
      source.hypotheses.some(({ findingId }) => findingId === id) ||
      source.missingInputs.some(({ findingId }) => findingId === id)
    )
      add("SOURCE", null, id);
  }

  const bindings = new Map();
  const bindingRecords = [];
  const artifactIds = new Map();
  const duplicateJobs = new Set();
  for (const raw of request.bindings) {
    let binding;
    try {
      binding = normalizeBinding(raw);
    } catch {
      add("INVALID");
      continue;
    }
    const key = jobKey(binding);
    bindingRecords.push(binding);
    if (bindings.has(key) || artifactIds.has(binding.artifactId)) {
      add("DUPLICATE");
      duplicateJobs.add(key);
      if (artifactIds.has(binding.artifactId))
        duplicateJobs.add(artifactIds.get(binding.artifactId));
    }
    if (!bindings.has(key)) bindings.set(key, binding);
    artifactIds.set(binding.artifactId, key);
    if (binding.candidateSha !== request.candidateSha) add("REVISION");
    if (!PLATFORMS.some(({ os }) => os === binding.platform)) add("PLATFORM");
    if (binding.conclusion !== "success") add("PROVENANCE");
    if (
      binding.tier === "provider" &&
      binding.authority !== "operator-protected"
    )
      add("PROVENANCE");
  }

  const results = [];
  const records = new Map();
  const usedJobs = new Set();
  for (const raw of request.results) {
    let result;
    try {
      result = normalizeNativeResult(raw);
    } catch {
      add("INVALID");
      continue;
    }
    results.push(result);
    const platform = PLATFORMS.find(({ os }) => os === result.platform);
    const os = platform?.os ?? null;
    const check = result.checkId;
    const key = `${result.platform}:${check}`;
    if (records.has(key)) add("DUPLICATE", os, check);
    records.set(key, result);
    if (
      result.candidateSha !== request.candidateSha ||
      result.checkoutSha !== request.candidateSha
    )
      add("REVISION", os, check);
    if (
      !platform ||
      result.declaredImage !== platform.image ||
      result.observed.image !== platform.image ||
      result.observed.os !== os ||
      result.observed.architecture !== platform.architecture ||
      !result.observed.build
    )
      add("PLATFORM", os, check);
    const job = jobKey(result);
    const binding = bindings.get(job);
    usedJobs.add(job);
    if (
      !binding ||
      duplicateJobs.has(job) ||
      binding.platform !== result.platform ||
      binding.tier !== result.tier ||
      binding.conclusion !== "success" ||
      binding.candidateSha !== request.candidateSha
    )
      add("PROVENANCE", os, check);
    if (
      result.tier === "provider" &&
      binding?.authority !== "operator-protected"
    )
      add("PROVENANCE", os, check);
    if (
      PROVIDER_CHECK_IDS.includes(check) &&
      result.dispatch !== request.providerModes[check]
    )
      add("DISPATCH", os, check);
    for (const phase of ["setup", "probe", "cleanup"]) {
      if (result.phases[phase].status !== "PASS")
        add(phase.toUpperCase(), os, check);
    }
    if (
      result.status === "BLOCKED" &&
      Object.values(result.phases).some(({ status }) => status === "FAIL")
    )
      add("INCONSISTENT", os, check);
    if (
      result.settlement.status !== "RETIRED" ||
      !result.settlement.independent ||
      result.settlement.emergencyCleanup
    )
      add("SETTLEMENT", os, check);
    if (result.status !== "PASS") add("RESULT", os, check);
  }
  for (const job of usedJobs) {
    const entries = results.filter((result) => jobKey(result) === job);
    const contexts = new Set(
      entries.map(
        ({ candidateSha, checkoutSha, platform, declaredImage, observed }) =>
          JSON.stringify([
            candidateSha,
            checkoutSha,
            platform,
            declaredImage,
            observed,
          ]),
      ),
    );
    const policies = new Map();
    const versions = new Map();
    for (const entry of entries) {
      const profilePolicies = policies.get(entry.profile) ?? new Set();
      profilePolicies.add(JSON.stringify(entry.policy));
      policies.set(entry.profile, profilePolicies);
      for (const component of entry.versions) {
        const observedVersions = versions.get(component.name) ?? new Set();
        observedVersions.add(JSON.stringify(component));
        versions.set(component.name, observedVersions);
      }
    }
    if (
      contexts.size > 1 ||
      [...policies.values(), ...versions.values()].some(
        (values) => values.size > 1,
      )
    ) {
      for (const entry of entries)
        add(
          "INCONSISTENT",
          PLATFORMS.some(({ os }) => os === entry.platform)
            ? entry.platform
            : null,
          entry.checkId,
        );
    }
  }
  for (const job of bindings.keys()) if (!usedJobs.has(job)) add("PROVENANCE");
  for (const { os } of PLATFORMS) {
    for (const id of CHECK_IDS)
      if (!records.has(`${os}:${id}`)) add("MISSING", os, id);
  }
  const uniqueIssues = [
    ...new Map(issues.map((issue) => [JSON.stringify(issue), issue])).values(),
  ].sort((left, right) => compare(JSON.stringify(left), JSON.stringify(right)));
  results.sort((left, right) =>
    compare(JSON.stringify(left), JSON.stringify(right)),
  );
  return {
    schemaVersion: 1,
    candidateSha: request.candidateSha,
    decision:
      uniqueIssues.length === 0
        ? "GO"
        : results.some(
              (result) =>
                result.status === "FAIL" ||
                Object.values(result.phases).some(
                  ({ status }) => status === "FAIL",
                ),
            )
          ? "NO_GO"
          : "BLOCKED",
    source,
    results,
    bindings: bindingRecords.sort((left, right) =>
      compare(JSON.stringify(left), JSON.stringify(right)),
    ),
    issues: uniqueIssues,
  };
}

/** Render only fixed messages and closed IDs. Never echo diagnostic prose into
 * Markdown or workflow commands. Explicit artifact/summary I/O stays in CI. */
export function renderNativeReport(input) {
  const report = aggregateNativeEvidence(input);
  const lines = [
    `## Native proof: ${report.decision}`,
    `Candidate: ${report.candidateSha}`,
    "",
    "| Platform | Accepted native checks | Required checks |",
    "| --- | ---: | ---: |",
  ];
  for (const { os } of PLATFORMS) {
    const passed = new Set(
      report.results
        .filter(
          (result) =>
            result.platform === os &&
            result.status === "PASS" &&
            !report.issues.some(
              (issue) =>
                issue.platform === os && issue.checkId === result.checkId,
            ),
        )
        .map(({ checkId }) => checkId),
    );
    lines.push(`| ${os} | ${passed.size} | ${CHECK_IDS.length} |`);
  }
  lines.push(
    "",
    "Reporting success is not native acceptance. Unproved checks retain BLOCKED.",
  );
  for (const issue of report.issues.slice(0, 32))
    lines.push(
      `- ${issue.code} ${issue.platform ?? "source/CI"} ${issue.checkId ?? "evidence"}: ${issue.message}`,
    );
  if (report.issues.length > 32)
    lines.push(
      `- ${report.issues.length - 32} additional findings remain in the structured report.`,
    );
  return {
    report,
    summary: lines.join("\n") + "\n",
    annotations: report.issues
      .slice(0, 32)
      .map(
        (issue) =>
          `::error title=Native proof ${issue.code}::${issue.platform ?? "source/CI"} ${issue.checkId ?? "evidence"}: ${issue.message}`,
      ),
  };
}

/** Offline publication/source reporting cannot substitute for native results or
 * independently reviewed release/build equivalence. Raw member bytes never enter
 * reports; exact public provenance is retained only in structured evidence. */
export function renderPublicInputReport(input) {
  const publicInputs = verifyPreparedPublicInputs(input);
  const rendered = renderNativeReport({
    candidateSha: publicInputs.candidateSha,
    source: publicInputs.source,
    results: [],
    bindings: [],
  });
  const lines = [
    `## Prepared public inputs: ${publicInputs.status}`,
    "",
    "| Bundle | Matching members | Required members | Byte status | Release binding |",
    "| --- | ---: | ---: | --- | --- |",
  ];
  for (const bundle of publicInputs.bundles)
    lines.push(
      `| ${bundle.id} | ${bundle.files.filter((entry) => entry.status === "PASS").length} | ${bundle.files.length} | ${bundle.byteStatus} | UNPROVED |`,
    );
  lines.push(
    "",
    "Prepare missing material separately; matching bytes authorize neither installation nor admission.",
    "",
  );
  return {
    report: { ...rendered.report, publicInputs },
    summary: lines.join("\n") + rendered.summary,
    annotations: [
      publicInputs.status === "FAIL"
        ? "::error title=Public input integrity::Reject altered members and prepare fresh immutable bundles against reviewed provenance."
        : "::error title=Public input closure::Prepare reviewed release/build bindings and complete reached source; byte checks cannot close native findings.",
      ...rendered.annotations,
    ].slice(0, 32),
  };
}
