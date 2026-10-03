import {
  CHECK_IDS,
  PLATFORMS,
  PROVIDER_CHECK_IDS,
  SOURCE_FINDING_IDS,
  linuxNativeGroup,
} from "./catalog.js";
import {
  normalizeBinding,
  normalizeNativeResult,
  normalizeRequest,
  normalizeSourceEvidence,
  hasNativeProcessEffects,
  NativeEvidenceError,
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
const FAILED_JOB_ACTION =
  "Repair the recorded CI setup/probe/cleanup/report failure and collect fresh same-revision evidence; artifact selection alone does not make the producing job successful.";

function jobKey(value) {
  const { repository, workflow, runId, runAttempt, jobId } = value.provenance;
  return JSON.stringify([repository, workflow, runId, runAttempt, jobId]);
}

function compare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

const SYSTEM_CHECK_IDS = CHECK_IDS.filter(
  (id) => !PROVIDER_CHECK_IDS.includes(id),
);
const ISSUE_ORDER = [
  "INVALID",
  "DUPLICATE",
  "REVISION",
  "PLATFORM",
  "INCONSISTENT",
  "SETUP",
  "PROBE",
  "CLEANUP",
  "SETTLEMENT",
  "SOURCE",
  "PROVENANCE",
  "DISPATCH",
  "RESULT",
  "MISSING",
];

function requiredAction(platform, checkId) {
  if (PROVIDER_CHECK_IDS.includes(checkId))
    return "Recover release-bound enabled-tool enforcement and collect operator-protected provider evidence; CI harness health supplies none.";
  if (checkId === "audit.release")
    return "Close exact release/build, dependency, licensing, ABI and privilege bindings before native admission.";
  if (platform === "darwin" || platform === "win32") {
    if (checkId.startsWith("files."))
      return "Supply reviewed native held-parent/handle identity, alias rejection, publication/replacement and interrupted cleanup proof; no file helper is admitted.";
    if (platform === "darwin")
      return "Supply callable build-matched protected domain membership, acknowledged literal launch and recovered retirement, including delegated Mach/service and proxy work.";
    return "Supply complete release-bound helper source, fail-closed suspended two-hop admission, protected process/Job handles and independent setup/delegation and holder-loss recovery.";
  }
  return ACTIONS.MISSING;
}

function isSourceApplicable(id, platform) {
  return (
    !(id === "A-MAC-OWNERSHIP" && platform !== "darwin") &&
    !(id === "A-WIN-ADMISSION" && platform !== "win32")
  );
}

/** Bind only metadata supplied independently by the CI controller, never a
 * binding copied from the payload. This pure join cannot authenticate CI APIs. */
export function aggregateNativeEvidence(input) {
  const request = normalizeRequest(input);
  const issues = [];
  const add = (
    code,
    platform = null,
    checkId = null,
    message = ACTIONS[code],
  ) =>
    issues.push({
      code,
      platform,
      checkId,
      message: code === "MISSING" ? requiredAction(platform, checkId) : message,
    });
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
    if (binding.conclusion !== "success")
      add(
        "PROVENANCE",
        PLATFORMS.some(({ os }) => os === binding.platform)
          ? binding.platform
          : null,
        null,
        FAILED_JOB_ACTION,
      );
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
    const attempted = hasNativeProcessEffects(result);
    const key = `${result.platform}:${check}`;
    if (records.has(key)) add("DUPLICATE", os, check);
    records.set(key, result);
    if (
      result.candidateSha !== request.candidateSha ||
      ((attempted || result.checkoutSha !== null) &&
        result.checkoutSha !== request.candidateSha)
    )
      add("REVISION", os, check);
    if (
      !platform ||
      result.declaredImage !== platform.image ||
      ((attempted || result.observed.image !== null) &&
        result.observed.image !== platform.image) ||
      ((attempted || result.observed.os !== null) &&
        result.observed.os !== os) ||
      ((attempted || result.observed.architecture !== null) &&
        result.observed.architecture !== platform.architecture) ||
      (attempted && !result.observed.build)
    )
      add("PLATFORM", os, check);
    const job = jobKey(result);
    const binding = bindings.get(job);
    usedJobs.add(job);
    if (
      (attempted && !binding) ||
      duplicateJobs.has(job) ||
      (binding &&
        (binding.platform !== result.platform ||
          binding.tier !== result.tier ||
          binding.candidateSha !== request.candidateSha))
    )
      add("PROVENANCE", os, check);
    if (attempted && binding && binding.conclusion !== "success")
      add("PROVENANCE", os, check, FAILED_JOB_ACTION);
    if (
      attempted &&
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
      if (
        result.phases[phase].status !== "PASS" &&
        (attempted || result.phases[phase].status !== "NOT_RUN")
      )
        add(phase.toUpperCase(), os, check);
    }
    if (result.admission === "not-started" && attempted)
      add("INCONSISTENT", os, check);
    if (
      result.status === "BLOCKED" &&
      Object.values(result.phases).some(({ status }) => status === "FAIL")
    )
      add("INCONSISTENT", os, check);
    if (
      attempted &&
      (result.settlement.status !== "RETIRED" ||
        !result.settlement.independent ||
        result.settlement.emergencyCleanup)
    )
      add("SETTLEMENT", os, check);
    if (result.status !== "PASS")
      add(
        "RESULT",
        os,
        check,
        result.reason === "unimplemented"
          ? requiredAction(os, check)
          : ACTIONS.RESULT,
      );
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
      if (entry.policy !== null) {
        // Files and release policies are distinct even when legacy labels agree.
        const group =
          entry.platform === "linux" ? linuxNativeGroup(entry.checkId) : null;
        const policyGroup = ["files", "release"].includes(group)
          ? JSON.stringify([group])
          : entry.profile;
        const profilePolicies = policies.get(policyGroup) ?? new Set();
        profilePolicies.add(JSON.stringify(entry.policy));
        policies.set(policyGroup, profilePolicies);
      }
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
  ].sort(
    (left, right) =>
      ISSUE_ORDER.indexOf(left.code) - ISSUE_ORDER.indexOf(right.code) ||
      compare(JSON.stringify(left), JSON.stringify(right)),
  );
  results.sort((left, right) =>
    compare(JSON.stringify(left), JSON.stringify(right)),
  );
  return {
    schemaVersion: 1,
    candidateSha: request.candidateSha,
    scope: "aggregate",
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
export function renderNativeReport(input, { platform = null } = {}) {
  if (platform !== null && !PLATFORMS.some(({ os }) => os === platform))
    throw new NativeEvidenceError();
  const report = aggregateNativeEvidence(input);
  const platforms = PLATFORMS.filter(
    ({ os }) => platform === null || os === platform,
  );
  if (platform !== null) {
    report.scope = platform;
    report.results = report.results.filter(
      (result) => result.platform === platform,
    );
    report.bindings = report.bindings.filter(
      (binding) => binding.platform === platform,
    );
    report.issues = report.issues.filter(
      (issue) =>
        issue.platform === platform ||
        (issue.platform === null &&
          (issue.code !== "SOURCE" ||
            isSourceApplicable(issue.checkId, platform))),
    );
    if (report.source) {
      const findings = report.source.findings.filter((finding) =>
        isSourceApplicable(finding.id, platform),
      );
      const ids = new Set(findings.flatMap((finding) => finding.sourceIds));
      report.source = {
        ...report.source,
        findings,
        inspected: report.source.inspected.filter((fact) => ids.has(fact.id)),
        hypotheses: report.source.hypotheses.filter((entry) =>
          isSourceApplicable(entry.findingId, platform),
        ),
        missingInputs: report.source.missingInputs.filter((entry) =>
          isSourceApplicable(entry.findingId, platform),
        ),
      };
    }
    report.decision = report.results.some(
      (result) =>
        result.status === "FAIL" ||
        Object.values(result.phases).some((phase) => phase.status === "FAIL"),
    )
      ? "NO_GO"
      : "BLOCKED";
  }
  const lines = [
    `## Native proof: ${report.decision}`,
    `Candidate: ${report.candidateSha}`,
    "",
    "| Platform | Accepted system cases | Required system cases |",
    "| --- | ---: | ---: |",
  ];
  const accepted = (os) =>
    new Set(
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
        .map((result) => result.checkId),
    );
  for (const { os } of platforms) {
    const passed = accepted(os);
    lines.push(
      `| ${os} | ${[...passed].filter((id) => SYSTEM_CHECK_IDS.includes(id)).length} | ${SYSTEM_CHECK_IDS.length} |`,
    );
  }
  lines.push(
    "",
    `Source closure: ${
      report.source?.findings.filter(
        (finding) =>
          finding.status === "CLOSED" &&
          !report.issues.some(
            (issue) => issue.code === "SOURCE" && issue.checkId === finding.id,
          ),
      ).length ?? 0
    }/${SOURCE_FINDING_IDS.filter((id) => platform === null || isSourceApplicable(id, platform)).length} applicable findings closed.`,
  );
  lines.push(
    "",
    "Provider dispatch is a separate prerequisite; protected evidence is operator-owned.",
  );
  for (const { os } of platforms)
    lines.push(
      `- ${os}: accepted provider checks ${[...accepted(os)].filter((id) => PROVIDER_CHECK_IDS.includes(id)).length}/${PROVIDER_CHECK_IDS.length}; absent provider records ${PROVIDER_CHECK_IDS.filter((id) => !report.results.some((result) => result.platform === os && result.checkId === id)).length}.`,
    );
  if (platform !== null)
    lines.push(
      "",
      "This platform-scoped report cannot establish aggregate GO.",
    );
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
