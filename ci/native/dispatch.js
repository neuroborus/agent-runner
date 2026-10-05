import {
  initialCompositionJob,
  normalizeCompositionJob,
  compositionResults,
  compositionCleanupFailure,
} from "./composition.js";
import {
  CHECK_IDS,
  LINUX_OWNERSHIP_CHECK_IDS,
  LINUX_POLICY_ID,
  LINUX_ACCESS_CHECK_IDS,
  LINUX_ACCESS_POLICY_ID,
  PLATFORMS,
  PROVIDER_CHECK_IDS,
  SOURCE_FINDING_IDS,
  LINUX_NATIVE_GROUPS,
  linuxNativeGroup,
  NATIVE_JOB_STEPS,
} from "./catalog.js";
import {
  NativeEvidenceError,
  normalizeBinding,
  normalizeNativeResult,
  hasNativeProcessEffects,
  normalizeNativeAdmission,
  normalizeNativeSupportingEvidence,
} from "./evidence.js";
import { renderNativeReport } from "./reports.js";
import {
  normalizeLinuxPrerequisites,
  linuxPrerequisiteEvidence,
} from "./linux-prerequisites.js";

const STAGES = ["setup", "probe", "cleanup"];
const REPORTED_STAGES = [...STAGES, "report"];
const SYSTEM_CHECK_IDS = CHECK_IDS.filter(
  (id) => !PROVIDER_CHECK_IDS.includes(id),
);
const EFFECT_IDS = Object.values(LINUX_NATIVE_GROUPS).flatMap(
  ({ effects }) => effects,
);
const retainedSettlement = () => ({
  status: "RETAINED",
  independent: false,
  emergencyCleanup: false,
});
const CI_ACTIONS = Object.freeze({
  setup:
    "Verify exact checkout, declared image/build, x64, pinned Node and job identity; repair setup and rerun it.",
  probe:
    "Resolve preceding setup failures; inspect the reporting harness or recorded native setup/probe failure and rerun the affected probe.",
  cleanup:
    "Inspect reporting cleanup and preserve attempted-case exclusion until independent retirement is proved; cleanup cannot repair native failure.",
  report:
    "Repair per-OS report generation while preserving the original setup/probe/cleanup evidence.",
  metadata:
    "Repair independent artifact/run/job selection metadata and collect a fresh matching artifact.",
  duplicate:
    "Select exactly one independently bound artifact and producing job per declared platform.",
  missing:
    "Recover the missing producing job or independently bound artifact; collect fresh same-revision evidence.",
  download:
    "Repair the selected artifact download and verify its bounded bytes and digest.",
  payload:
    "Repair the closed artifact payload or its binding to independently selected job/stage evidence.",
});
const SHA = /^[a-f0-9]{40}$/u;
const ID = /^[1-9][0-9]{0,19}$/u;
const absentPhase = () => ({
  status: "NOT_RUN",
  elapsedMs: null,
  deadlineMs: 120000,
  reason: "missing-input",
});

function ciAction(code, platform) {
  return code === "setup" && platform === "linux"
    ? `${CI_ACTIONS.setup} Inspect the candidate-bound Linux preparation receipt and workflow outcome; absent, failed or interrupted preparation cannot release probes.`
    : CI_ACTIONS[code];
}

function stagesInOrder(stages) {
  return Object.fromEntries(
    REPORTED_STAGES.map((name) => [name, stages[name]]),
  );
}

function platformOrder(left, right) {
  const platform = (value) => value.platform ?? value.binding?.platform ?? null;
  return (
    PLATFORMS.findIndex(({ os }) => os === platform(left)) -
    PLATFORMS.findIndex(({ os }) => os === platform(right))
  );
}

function orderedCiIssues(issues) {
  const order = Object.keys(CI_ACTIONS);
  const unique = new Map(
    issues.map(({ code, platform }) => {
      const issue = { code, platform };
      return [JSON.stringify(issue), issue];
    }),
  );
  return [...unique.values()].sort(
    (left, right) =>
      order.indexOf(left.code) - order.indexOf(right.code) ||
      platformOrder(left, right),
  );
}

function prerequisiteAction(id) {
  if (id.startsWith("bubblewrap-") && id !== "bubblewrap-version")
    return "Inspect the Linux preparation receipt and first discovery, identity or protection failure in fresh external CI; preserve verified package bytes and protection without host-policy changes.";
  if (["ordinary-namespace", "nested-namespaces"].includes(id))
    return "Fresh external CI must retain the reached production namespace probe outcome; do not infer host policy or substitute non-isolated/host-session execution.";
  return "Fresh external CI must identify the first failed procfs, storage, ABI or version prerequisite; dependent native checks remain NOT_RUN.";
}

/** Primary stages and reached prerequisites precede derivative proof findings. */
function renderCiFindings(rendered, heading, details, issues) {
  rendered.report.ciIssues = orderedCiIssues(issues);
  rendered.report.prerequisiteIssues = rendered.report.linuxPrerequisites.map(
    ({ diagnosis }) => {
      const failed = diagnosis.checks.find(
        (check) => check.id === diagnosis.failedPrerequisite,
      );
      return {
        code: "LINUX_PREREQUISITE",
        platform: "linux",
        checkId: failed.id,
        diagnosis: failed.diagnosis,
        message: prerequisiteAction(failed.id),
      };
    },
  );
  const ciLines = rendered.report.ciIssues.map(
    ({ code, platform }) =>
      `- ${platform ?? "all"}: ${code}; ${ciAction(code, platform)}`,
  );
  const prerequisiteLines = rendered.report.linuxPrerequisites.flatMap(
    ({ diagnosis }) => {
      const failed = diagnosis.checks.find(
        (check) => check.id === diagnosis.failedPrerequisite,
      );
      const observation = Object.entries(failed.observation)
        .filter(([, value]) => value !== null)
        .map(([name, value]) => `${name}=${value}`)
        .join(", ");
      return [
        "",
        `### Linux prerequisite: ${failed.id} (${failed.diagnosis})`,
        prerequisiteAction(failed.id),
        ...(observation ? [`Observed: ${observation}.`] : []),
        ...diagnosis.checks.map((check) => `- ${check.id}: ${check.status}`),
      ];
    },
  );
  rendered.summary = [
    heading,
    "",
    details,
    ...ciLines,
    ...prerequisiteLines,
    "",
    "CI harness health supplies no system or protected provider acceptance.",
    "",
    rendered.summary,
  ].join("\n");
  rendered.annotations = [
    ...rendered.report.ciIssues.map(
      ({ code, platform }) =>
        `::error title=Native CI ${code}::${platform ?? "all"}: ${ciAction(code, platform)}`,
    ),
    ...rendered.report.prerequisiteIssues.map(
      (issue) =>
        `::error title=Native Linux prerequisite::linux ${issue.checkId} (${issue.diagnosis}): ${issue.message}`,
    ),
    ...rendered.annotations,
  ].slice(0, 32);
  return rendered;
}

function requireValue(condition) {
  if (!condition) throw new NativeEvidenceError();
}

function closed(value, keys) {
  requireValue(
    value !== null &&
      typeof value === "object" &&
      Object.getPrototypeOf(value) === Object.prototype,
  );
  requireValue(
    Reflect.ownKeys(value).length === keys.length &&
      keys.every(
        (key) =>
          Object.hasOwn(value, key) &&
          Object.getOwnPropertyDescriptor(value, key).enumerable &&
          Object.hasOwn(Object.getOwnPropertyDescriptor(value, key), "value"),
      ),
  );
}

function list(value, maximum) {
  requireValue(
    Array.isArray(value) &&
      Object.getPrototypeOf(value) === Array.prototype &&
      value.length <= maximum &&
      Reflect.ownKeys(value).length === value.length + 1,
  );
  for (let index = 0; index < value.length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    requireValue(descriptor?.enumerable && Object.hasOwn(descriptor, "value"));
  }
  return Array.from(value);
}

/** Recognize reviewed hosted images without attesting setup or native proof. */
export function isWindows2025Image({ build, imageOS, imageVersion }) {
  return (
    typeof build === "string" &&
    /^10\.0\.26100(?:\.[0-9]+)?$/u.test(build) &&
    (imageOS === "win25" || imageOS === "win25-vs2026") &&
    typeof imageVersion === "string" &&
    /^[a-zA-Z0-9._-]{1,128}$/u.test(imageVersion)
  );
}

/** Selecting a tier grants no authority; protected review admission is separate. */
export function resolveNativeDispatch(args) {
  args = list(args, 4);
  requireValue(
    args.length >= 2 &&
      args[0] === "--tier" &&
      ["system", "provider"].includes(args[1]),
  );
  const stage = args.length === 2 ? "all" : args[3];
  requireValue(
    args.length === 2 ||
      (args[2] === "--stage" &&
        [
          "initialize",
          "verify-revision",
          "verify-system",
          "prepare-linux",
          "prepare-inputs",
          "prepare",
          "deadlines",
          ...STAGES,
          "report",
          "collect",
          "aggregate",
        ].includes(stage)),
  );
  requireValue(
    args[1] === "provider" ||
      !["verify-revision", "verify-system"].includes(stage),
  );
  return { tier: args[1], stage };
}

export function initializeNativeJob(context, options = { schemaVersion: 4 }) {
  if (options.schemaVersion === 6) {
    closed(
      options,
      Object.hasOwn(options, "tier")
        ? ["schemaVersion", "tier"]
        : ["schemaVersion"],
    );
    return initialCompositionJob(context, options.tier ?? "system");
  }
  closed(options, ["schemaVersion"]);
  requireValue([4, 5].includes(options.schemaVersion));
  closed(context, [
    "candidateSha",
    "platform",
    "repository",
    "runId",
    "runAttempt",
  ]);
  const platform = PLATFORMS.find(({ os }) => os === context.platform);
  requireValue(
    platform &&
      SHA.test(context.candidateSha) &&
      ID.test(context.runId) &&
      Number.isSafeInteger(context.runAttempt) &&
      context.runAttempt > 0,
  );
  const job = {
    schemaVersion: options.schemaVersion,
    ...(options.schemaVersion === 4
      ? { unrecordedAdmission: "not-started" }
      : {
          admissions: Object.fromEntries(
            EFFECT_IDS.map((id) => [
              id,
              {
                admission: "not-started",
                settlement: retainedSettlement(),
              },
            ]),
          ),
          supportingEvidence: [],
        }),
    candidateSha: context.candidateSha,
    checkoutSha: null,
    platform: platform.os,
    declaredImage: platform.image,
    observed: { os: null, image: null, build: null, architecture: null },
    provenance: {
      repository: context.repository,
      workflow: "native-poc.yml",
      runId: context.runId,
      runAttempt: context.runAttempt,
      jobId: null,
    },
    versions: [],
    stages: Object.fromEntries(STAGES.map((name) => [name, absentPhase()])),
    results: [],
    linuxPrerequisites: null,
  };
  return normalizeNativeJob(job);
}

function nativeResult(job, checkId) {
  const group = linuxNativeGroup(checkId);
  const implemented =
    job.platform === "linux" &&
    (job.schemaVersion === 5
      ? group !== null
      : [...LINUX_OWNERSHIP_CHECK_IDS, ...LINUX_ACCESS_CHECK_IDS].includes(
          checkId,
        ));
  const uncertain =
    (job.schemaVersion === 5
      ? group !== null &&
        job.admissions[LINUX_NATIVE_GROUPS[group].admission].admission ===
          "possible"
      : job.schemaVersion === 4 && job.unrecordedAdmission === "possible") &&
    implemented;
  const reason =
    uncertain || (job.schemaVersion === 5 && implemented)
      ? "missing-input"
      : "unimplemented";
  return {
    schemaVersion: 2,
    admission: (
      job.schemaVersion === 5
        ? !uncertain
        : job.schemaVersion === 4 &&
          (job.unrecordedAdmission === "not-started" ||
            (job.platform === "linux" && !implemented))
    )
      ? "not-started"
      : "possible",
    candidateSha: job.candidateSha,
    checkoutSha: job.checkoutSha,
    platform: job.platform,
    declaredImage: job.declaredImage,
    observed: job.observed,
    provenance: job.provenance,
    checkId,
    profile: checkId.startsWith("profile.")
      ? checkId.slice(8)
      : checkId === "git.fixed-commit"
        ? "commit"
        : job.schemaVersion === 5
          ? group
          : "fixture",
    tier: "system",
    dispatch: "native",
    implemented: job.schemaVersion === 5 ? implemented : uncertain,
    versions: job.versions,
    policy: null,
    phases: Object.fromEntries(
      STAGES.map((name) => [name, { ...absentPhase(), reason }]),
    ),
    observations: [],
    settlement: {
      status: "RETAINED",
      independent: false,
      emergencyCleanup: false,
    },
    status: "BLOCKED",
    reason,
  };
}

function nativeResults(job) {
  if (job.schemaVersion === 6) return compositionResults(job);
  // Recorded process effects contradict a claim that the proof never started.
  // Explicitly unadmitted records remain usable; absent records stay uncertain.
  const fallback =
    job.schemaVersion === 4 && job.results.some(hasNativeProcessEffects)
      ? { ...job, unrecordedAdmission: "possible" }
      : job;
  return SYSTEM_CHECK_IDS.map(
    (checkId) =>
      job.results.find((result) => result.checkId === checkId) ??
      normalizeNativeResult(nativeResult(fallback, checkId)),
  );
}

export function normalizeNativeJob(value) {
  if (
    Object.getOwnPropertyDescriptor(value ?? {}, "schemaVersion")?.value === 6
  )
    return normalizeCompositionJob(value);
  const version =
    value && typeof value === "object"
      ? Object.getOwnPropertyDescriptor(value, "schemaVersion")?.value
      : null;
  closed(value, [
    "schemaVersion",
    "candidateSha",
    "checkoutSha",
    "platform",
    "declaredImage",
    "observed",
    "provenance",
    "versions",
    "stages",
    ...(version >= 2 ? ["results"] : []),
    ...(version >= 3 ? ["linuxPrerequisites"] : []),
    ...(version === 4 ? ["unrecordedAdmission"] : []),
    ...(version === 5 ? ["admissions", "supportingEvidence"] : []),
  ]);
  closed(value.stages, STAGES);
  requireValue(
    [1, 2, 3, 4, 5].includes(value.schemaVersion) &&
      PLATFORMS.some(
        ({ os, image }) =>
          value.platform === os && value.declaredImage === image,
      ),
  );
  if (version === 4)
    requireValue(
      ["not-started", "possible"].includes(value.unrecordedAdmission),
    );
  let admissions, supportingEvidence;
  if (version === 5) {
    closed(value.admissions, EFFECT_IDS);
    admissions = Object.fromEntries(
      EFFECT_IDS.map((id) => [
        id,
        normalizeNativeAdmission(value.admissions[id]),
      ]),
    );
    supportingEvidence = normalizeNativeSupportingEvidence(
      value.supportingEvidence,
    );
    if (value.platform !== "linux")
      requireValue(
        EFFECT_IDS.every((id) => admissions[id].admission === "not-started") &&
          supportingEvidence.length === 0,
      );
    if (admissions["file-helper"].admission === "possible")
      requireValue(
        admissions["file-build"].admission === "possible" &&
          admissions["file-build"].settlement.status === "RETIRED" &&
          !admissions["file-build"].settlement.emergencyCleanup,
      );
    for (const record of supportingEvidence) {
      const group = LINUX_NATIVE_GROUPS[linuxNativeGroup(record.checkId)];
      const effect = record.kind === "build" ? "file-build" : group.admission;
      requireValue(admissions[effect].admission === "possible");
    }
    value = { ...value, admissions };
  }
  // Reuse the evidence validator for all identity, version, and phase fields.
  const validated = normalizeNativeResult({
    ...nativeResult(value, CHECK_IDS[0]),
    phases: value.stages,
  });
  if (validated.phases.setup.status === "PASS")
    requireValue(
      validated.checkoutSha === validated.candidateSha &&
        validated.observed.os === validated.platform &&
        validated.observed.image === validated.declaredImage &&
        validated.observed.architecture === "x64" &&
        validated.observed.build &&
        Object.values(validated.provenance).every((field) => field !== null) &&
        validated.versions.some(
          ({ name, version }) => name === "node" && version === "v24.21.0",
        ),
    );
  if (validated.phases.probe.status === "PASS")
    requireValue(validated.phases.setup.status === "PASS");
  const results =
    value.schemaVersion >= 2
      ? list(
          value.results,
          version === 5
            ? SYSTEM_CHECK_IDS.length
            : LINUX_OWNERSHIP_CHECK_IDS.length + LINUX_ACCESS_CHECK_IDS.length,
        ).map(normalizeNativeResult)
      : [];
  requireValue(
    new Set(results.map(({ checkId }) => checkId)).size === results.length,
  );
  for (const result of results) {
    requireValue(
      validated.phases.setup.status === "PASS" &&
        result.platform === "linux" &&
        (version === 5
          ? linuxNativeGroup(result.checkId) !== null
          : [...LINUX_OWNERSHIP_CHECK_IDS, ...LINUX_ACCESS_CHECK_IDS].includes(
              result.checkId,
            )),
    );
    for (const key of [
      "candidateSha",
      "checkoutSha",
      "platform",
      "declaredImage",
      "observed",
      "provenance",
    ])
      requireValue(
        JSON.stringify(result[key]) === JSON.stringify(validated[key]),
      );
    requireValue(
      result.implemented &&
        result.tier === "system" &&
        result.dispatch === "native",
    );
    for (const version of validated.versions)
      requireValue(
        result.versions.some(
          (entry) => JSON.stringify(entry) === JSON.stringify(version),
        ),
      );
    if (version === 5) {
      const groupId = linuxNativeGroup(result.checkId);
      const group = LINUX_NATIVE_GROUPS[groupId];
      requireValue(
        result.profile ===
          (result.checkId.startsWith("profile.")
            ? result.checkId.slice(8)
            : result.checkId === "git.fixed-commit"
              ? "commit"
              : groupId),
      );
      if (hasNativeProcessEffects(result))
        requireValue(admissions[group.admission].admission === "possible");
      if (result.policy !== null)
        requireValue(result.policy.id === group.policyId);
      if (result.status === "PASS" && ["files", "release"].includes(groupId))
        requireValue(
          supportingEvidence.some(
            (entry) =>
              entry.checkId === result.checkId &&
              entry.kind === (groupId === "files" ? "receipt" : "release"),
          ),
        );
    } else if (result.status === "PASS")
      requireValue(
        result.policy?.id ===
          (LINUX_ACCESS_CHECK_IDS.includes(result.checkId)
            ? LINUX_ACCESS_POLICY_ID
            : LINUX_POLICY_ID),
      );
  }
  if (validated.phases.probe.status === "PASS")
    requireValue(results.every((result) => result.status !== "FAIL"));
  if (validated.phases.cleanup.status === "PASS") {
    // Historical reporting cleanup did not validate incomplete native records.
    // Preserve readable inputs; their native settlement findings stay strict.
    requireValue(
      version >= 4
        ? nativeCleanupFailure({ ...value, results }) === null
        : results.every(
            (result) =>
              result.status !== "FAIL" ||
              (result.phases.cleanup.status === "PASS" &&
                result.settlement.status === "RETIRED" &&
                result.settlement.independent),
          ),
    );
  }
  results.sort(
    (a, b) => CHECK_IDS.indexOf(a.checkId) - CHECK_IDS.indexOf(b.checkId),
  );
  const linuxPrerequisites =
    version >= 3 && value.linuxPrerequisites !== null
      ? normalizeLinuxPrerequisites(value.linuxPrerequisites)
      : null;
  if (linuxPrerequisites)
    requireValue(
      validated.platform === "linux" &&
        validated.phases.setup.status === "PASS" &&
        results.length ===
          LINUX_OWNERSHIP_CHECK_IDS.length + LINUX_ACCESS_CHECK_IDS.length &&
        results.every(
          (result) =>
            result.status === "BLOCKED" &&
            result.reason === "missing-input" &&
            result.policy === null &&
            result.observations.length === 0 &&
            JSON.stringify(result.versions) ===
              JSON.stringify(validated.versions) &&
            result.settlement.status === "RETAINED" &&
            !result.settlement.independent &&
            !result.settlement.emergencyCleanup &&
            Object.values(result.phases).every(
              (phase) =>
                phase.status === "NOT_RUN" && phase.reason === "missing-input",
            ),
        ),
    );
  return {
    schemaVersion: version >= 4 ? version : 3,
    ...(version === 4
      ? { unrecordedAdmission: value.unrecordedAdmission }
      : {}),
    ...(version === 5 ? { admissions, supportingEvidence } : {}),
    candidateSha: validated.candidateSha,
    checkoutSha: validated.checkoutSha,
    platform: validated.platform,
    declaredImage: validated.declaredImage,
    observed: validated.observed,
    provenance: validated.provenance,
    versions: validated.versions,
    stages: validated.phases,
    results,
    linuxPrerequisites,
  };
}

export function recordNativeResults(input, results, linuxPrerequisites = null) {
  const job = normalizeNativeJob(input);
  requireValue(
    (job.schemaVersion === 5 || job.results.length === 0) &&
      job.stages.setup.status === "PASS" &&
      job.stages.probe.status === "NOT_RUN",
  );
  if (job.schemaVersion === 5)
    requireValue(
      job.stages.cleanup.status === "NOT_RUN" &&
        job.linuxPrerequisites === null,
    );
  return normalizeNativeJob({
    ...job,
    results:
      job.schemaVersion === 5
        ? [...job.results, ...list(results, SYSTEM_CHECK_IDS.length)]
        : results,
    linuxPrerequisites,
  });
}

/** Persist before the producer can start a controller, even without a receipt. */
export function recordNativeAdmission(input, effectId) {
  const job = normalizeNativeJob(input);
  if (job.schemaVersion === 5) {
    requireValue(
      EFFECT_IDS.includes(effectId) &&
        job.platform === "linux" &&
        job.stages.setup.status === "PASS" &&
        job.stages.probe.status === "NOT_RUN" &&
        job.stages.cleanup.status === "NOT_RUN" &&
        job.admissions[effectId].admission === "not-started",
    );
    return normalizeNativeJob({
      ...job,
      admissions: {
        ...job.admissions,
        [effectId]: { admission: "possible", settlement: retainedSettlement() },
      },
    });
  }
  requireValue(
    effectId === undefined &&
      job.schemaVersion === 4 &&
      job.platform === "linux" &&
      job.stages.setup.status === "PASS" &&
      job.stages.probe.status === "NOT_RUN" &&
      job.results.length === 0 &&
      job.unrecordedAdmission === "not-started",
  );
  return normalizeNativeJob({ ...job, unrecordedAdmission: "possible" });
}

/** Only independently supplied effect retirement can settle an admitted group. */
export function recordNativeSettlement(input, effectId, settlement) {
  const job = normalizeNativeJob(input);
  requireValue(
    job.schemaVersion === 5 &&
      EFFECT_IDS.includes(effectId) &&
      job.platform === "linux" &&
      job.stages.setup.status === "PASS" &&
      job.stages.probe.status === "NOT_RUN" &&
      job.stages.cleanup.status === "NOT_RUN",
  );
  const current = job.admissions[effectId];
  requireValue(
    current.admission === "possible" &&
      current.settlement.status === "RETAINED" &&
      !current.settlement.emergencyCleanup,
  );
  return normalizeNativeJob({
    ...job,
    admissions: {
      ...job.admissions,
      [effectId]: { admission: "possible", settlement },
    },
  });
}

export function recordNativeSupportingEvidence(input, records) {
  const job = normalizeNativeJob(input);
  requireValue(
    job.schemaVersion === 5 &&
      job.stages.setup.status === "PASS" &&
      job.stages.probe.status === "NOT_RUN" &&
      job.stages.cleanup.status === "NOT_RUN",
  );
  return normalizeNativeJob({
    ...job,
    supportingEvidence: [...job.supportingEvidence, ...list(records, 32)],
  });
}

/** Reporting cleanup cannot repair attempted or unrecorded possible effects. */
export function nativeCleanupFailure(job) {
  if (job.schemaVersion === 6) return compositionCleanupFailure(job);
  if (
    job.schemaVersion === 5 &&
    EFFECT_IDS.some((id) => {
      const record = job.admissions[id];
      return (
        record.admission === "possible" &&
        (record.settlement.status !== "RETIRED" ||
          !record.settlement.independent ||
          record.settlement.emergencyCleanup)
      );
    })
  )
    return "unretired";
  const failures = nativeResults({ ...job, results: job.results ?? [] }).filter(
    hasNativeProcessEffects,
  );
  if (
    failures.some(
      (result) =>
        result.settlement.status !== "RETIRED" ||
        !result.settlement.independent ||
        (job.schemaVersion === 5 && result.settlement.emergencyCleanup),
    )
  )
    return "unretired";
  return failures.some((result) => result.phases.cleanup.status !== "PASS")
    ? "cleanup-failed"
    : null;
}

export function recordNativeStage(input, name, phase, setup = {}) {
  requireValue(STAGES.includes(name));
  const job = normalizeNativeJob(input);
  requireValue(
    job.stages[name].status === "NOT_RUN" &&
      job.stages[name].elapsedMs === null,
  );
  requireValue(name === "setup" || Object.keys(setup).length === 0);
  for (const key of Object.keys(setup))
    requireValue(
      ["checkoutSha", "observed", "provenance", "versions"].includes(key),
    );
  // Read historical completed cleanup under its original contract, but never
  // publish a fresh PASS that the current cleanup evaluator would reject.
  if (
    name === "cleanup" &&
    phase &&
    Object.getOwnPropertyDescriptor(phase, "status")?.value === "PASS"
  )
    requireValue(nativeCleanupFailure(job) === null);
  return normalizeNativeJob({
    ...job,
    ...setup,
    stages: { ...job.stages, [name]: phase },
  });
}

function source(candidateSha) {
  const missing = {
    "A-MAC-OWNERSHIP":
      "Missing build-matched callable protected membership, stable identity, and recovered retirement source and CI proof.",
    "A-WIN-ADMISSION":
      "Missing complete Windows helper source and build binding and independently settled two-hop admission proof.",
    "A-PROVIDER-MEDIATION":
      "Missing release-bound enabled-tool enforcement review and approved same-revision protected dispatch evidence.",
    "A-RELEASE-CLOSURE":
      "Missing complete dependencies, licensing, ABI assumptions, and packaged-binary build provenance closure.",
  };
  return {
    candidateSha,
    inspected: [],
    hypotheses: [],
    missingInputs: SOURCE_FINDING_IDS.map((findingId) => ({
      findingId,
      summary: missing[findingId],
    })),
    findings: SOURCE_FINDING_IDS.map((id) => ({
      id,
      status: "BLOCKED",
      sourceIds: [],
    })),
  };
}

function nativeEffectEvidence(job) {
  if (job.schemaVersion === 6)
    return {
      candidateSha: job.candidateSha,
      platform: job.platform,
      provenance: job.provenance,
      executions: job.executions,
      reviews: job.reviews,
      closure: job.closure,
    };
  return {
    candidateSha: job.candidateSha,
    platform: job.platform,
    provenance: job.provenance,
    admissions: job.admissions,
    supportingEvidence: job.supportingEvidence,
  };
}

export function renderNativeJob(input) {
  const job = normalizeNativeJob(input);
  const rendered = renderNativeReport(
    {
      candidateSha: job.candidateSha,
      source: source(job.candidateSha),
      results: nativeResults(job),
      bindings: [],
    },
    { platform: job.platform },
  );
  rendered.report.ciStatus = STAGES.some(
    (name) => job.stages[name].status === "FAIL",
  )
    ? "FAIL"
    : STAGES.every((name) => job.stages[name].status === "PASS")
      ? "PASS"
      : "BLOCKED";
  rendered.report.ciStages = job.stages;
  rendered.report.nativeEffects =
    job.schemaVersion >= 5 ? [nativeEffectEvidence(job)] : [];
  rendered.report.linuxPrerequisites = job.linuxPrerequisites
    ? [linuxPrerequisiteEvidence(job, job.linuxPrerequisites)]
    : [];
  return renderCiFindings(
    rendered,
    `## CI stages (${job.platform}): ${rendered.report.ciStatus}`,
    STAGES.map(
      (name) =>
        `- ${name}: ${job.stages[name].status} (${job.stages[name].reason ?? "reporting-only"})`,
    ).join("\n"),
    STAGES.filter((name) => job.stages[name].status !== "PASS").map((code) => ({
      code,
      platform: job.platform,
    })),
  );
}

export function nativeArtifactName(context, platform, tier = "system") {
  requireValue(
    ["system", "provider"].includes(tier) &&
      SHA.test(context.candidateSha) &&
      Number.isSafeInteger(context.runAttempt) &&
      context.runAttempt > 0 &&
      PLATFORMS.some(({ os }) => os === platform),
  );
  return `native-${tier}-${platform}-${context.runAttempt}-${context.candidateSha}`;
}

/** Only the controller's read-only API responses select artifacts and jobs.
 * Artifact names alone are insufficient: run, attempt, timing, digest and job
 * identity must agree. There is no artifact.job_id field in the GitHub API. */
export function selectNativeArtifacts(context, run, jobs, artifacts) {
  closed(context, [
    "candidateSha",
    "repository",
    "runId",
    "runAttempt",
    "workflowSha",
  ]);
  initializeNativeJob({
    candidateSha: context.candidateSha,
    platform: "linux",
    repository: context.repository,
    runId: context.runId,
    runAttempt: context.runAttempt,
  });
  return selectArtifacts(context, run, jobs, artifacts);
}

export function selectProviderArtifacts(context, run, jobs, artifacts) {
  return selectArtifacts(context, run, jobs, artifacts, "provider");
}

function selectArtifacts(context, run, jobs, artifacts, tier = "system") {
  const entries = [];
  const issues = [];
  const observedJobs = [];
  const issue = (code, platform = null) => issues.push({ code, platform });
  if (
    !SHA.test(context.workflowSha) ||
    String(run.id) !== context.runId ||
    run.run_attempt !== context.runAttempt ||
    run.repository?.full_name !== context.repository ||
    typeof run.path !== "string" ||
    run.path.split("@")[0] !==
      `.github/workflows/${tier === "system" ? "native-poc.yml" : "native-poc-acceptance.yml"}` ||
    !["pull_request", "workflow_dispatch"].includes(run.event) ||
    ![context.candidateSha, context.workflowSha].includes(run.head_sha)
  ) {
    issue("metadata");
    return { entries, issues, jobs: observedJobs };
  }
  requireValue(
    Array.isArray(jobs) &&
      jobs.length <= 400 &&
      Array.isArray(artifacts) &&
      artifacts.length <= 400,
  );
  for (const { os } of PLATFORMS) {
    const matchedJobs = jobs.filter(
      (job) =>
        job.name === `native-${tier}-${os}` &&
        String(job.run_id) === context.runId &&
        job.run_attempt === context.runAttempt,
    );
    const name = nativeArtifactName(context, os, tier);
    const matchedArtifacts = artifacts.filter(
      (artifact) => artifact.name === name,
    );
    let observedJob;
    if (
      matchedJobs.length === 1 &&
      Number.isSafeInteger(matchedJobs[0].id) &&
      ID.test(String(matchedJobs[0].id))
    ) {
      const job = matchedJobs[0];
      const stages = Object.fromEntries(
        Object.entries({
          ...NATIVE_JOB_STEPS[6],
          ...(tier === "provider"
            ? { probe: "Probe protected real providers" }
            : {}),
        }).map(([stage, name]) => {
          const matches = Array.isArray(job.steps)
            ? job.steps.filter(
                (step) =>
                  step.name === name ||
                  (tier === "system" &&
                    stage === "probe" &&
                    step.name === "Probe reporting harness"),
              )
            : [];
          return [
            stage,
            matches.length === 1 &&
            ["success", "failure", "cancelled", "skipped"].includes(
              matches[0].conclusion,
            )
              ? matches[0].conclusion
              : "missing",
          ];
        }),
      );
      observedJob = {
        platform: os,
        jobId: String(job.id),
        artifactId: null,
        conclusion: ["success", "cancelled", "skipped"].includes(job.conclusion)
          ? job.conclusion
          : job.status === "completed"
            ? "failure"
            : "in_progress",
        stages,
      };
      observedJobs.push(observedJob);
    }
    if (matchedJobs.length !== 1 || matchedArtifacts.length !== 1) {
      issue(
        matchedJobs.length > 1 || matchedArtifacts.length > 1
          ? "duplicate"
          : "missing",
        os,
      );
      continue;
    }
    const job = matchedJobs[0];
    const artifact = matchedArtifacts[0];
    const created = Date.parse(artifact.created_at);
    const started = Date.parse(job.started_at);
    const completed = Date.parse(job.completed_at);
    const receipts = Array.isArray(job.steps)
      ? job.steps.filter(
          (step) => step.name === `Bind native artifact ${artifact.id}`,
        )
      : [];
    if (
      !Number.isSafeInteger(job.id) ||
      !Number.isSafeInteger(artifact.id) ||
      !ID.test(String(job.id)) ||
      !ID.test(String(artifact.id)) ||
      job.status !== "completed" ||
      ![
        "success",
        "failure",
        "cancelled",
        "skipped",
        "timed_out",
        "action_required",
        "neutral",
        "stale",
      ].includes(job.conclusion) ||
      receipts.length !== 1 ||
      receipts[0].conclusion !== "success" ||
      artifact.expired !== false ||
      !Number.isSafeInteger(artifact.size_in_bytes) ||
      artifact.size_in_bytes < 1 ||
      artifact.size_in_bytes > 2097152 ||
      !/^sha256:[a-f0-9]{64}$/u.test(artifact.digest) ||
      String(artifact.workflow_run?.id) !== context.runId ||
      artifact.workflow_run?.head_sha !== run.head_sha ||
      !Number.isFinite(created) ||
      !Number.isFinite(started) ||
      !Number.isFinite(completed) ||
      created < started ||
      created > completed
    ) {
      issue("metadata", os);
      continue;
    }
    observedJob.artifactId = String(artifact.id);
    entries.push({
      name,
      digest: artifact.digest,
      stages: observedJob.stages,
      binding: {
        artifactId: String(artifact.id),
        candidateSha: context.candidateSha,
        platform: os,
        tier,
        provenance: {
          repository: context.repository,
          workflow:
            tier === "system" ? "native-poc.yml" : "native-poc-acceptance.yml",
          runId: context.runId,
          runAttempt: context.runAttempt,
          jobId: String(job.id),
        },
        conclusion: observedJob.conclusion,
        authority: tier === "system" ? "ordinary" : "operator-protected",
      },
    });
  }
  return { entries, issues, jobs: observedJobs };
}

export function normalizeNativeArtifactSelection(
  context,
  input,
  tier = "system",
) {
  requireValue(["system", "provider"].includes(tier));
  closed(context, [
    "candidateSha",
    "repository",
    "runId",
    "runAttempt",
    "workflowSha",
  ]);
  initializeNativeJob({
    candidateSha: context.candidateSha,
    repository: context.repository,
    runId: context.runId,
    runAttempt: context.runAttempt,
    platform: "linux",
  });
  requireValue(SHA.test(context.workflowSha));
  closed(input, ["entries", "issues", "jobs"]);
  const jobs = list(input.jobs, 3)
    .map((job) => {
      closed(job, ["platform", "jobId", "artifactId", "conclusion", "stages"]);
      closed(job.stages, REPORTED_STAGES);
      requireValue(
        PLATFORMS.some(({ os }) => os === job.platform) &&
          typeof job.jobId === "string" &&
          ID.test(job.jobId) &&
          (job.artifactId === null ||
            (typeof job.artifactId === "string" && ID.test(job.artifactId))) &&
          [
            "success",
            "failure",
            "cancelled",
            "skipped",
            "in_progress",
          ].includes(job.conclusion) &&
          Object.values(job.stages).every((status) =>
            ["success", "failure", "cancelled", "skipped", "missing"].includes(
              status,
            ),
          ),
      );
      return {
        platform: job.platform,
        jobId: job.jobId,
        artifactId: job.artifactId,
        conclusion: job.conclusion,
        stages: stagesInOrder(job.stages),
      };
    })
    .sort(platformOrder);
  requireValue(
    new Set(jobs.map(({ jobId }) => jobId)).size === jobs.length &&
      new Set(jobs.map(({ platform }) => platform)).size === jobs.length,
  );
  const issues = list(input.issues, 4).map((issue) => {
    closed(issue, ["code", "platform"]);
    requireValue(
      ["metadata", "duplicate", "missing", "download"].includes(issue.code) &&
        (issue.platform === null ||
          PLATFORMS.some(({ os }) => os === issue.platform)),
    );
    return { code: issue.code, platform: issue.platform };
  });
  const entries = list(input.entries, 3)
    .map((entry) => {
      closed(entry, ["name", "digest", "stages", "binding"]);
      closed(entry.stages, REPORTED_STAGES);
      requireValue(
        Object.values(entry.stages).every((status) =>
          ["success", "failure", "cancelled", "skipped", "missing"].includes(
            status,
          ),
        ),
      );
      const binding = normalizeBinding(entry.binding);
      requireValue(
        binding.candidateSha === context.candidateSha &&
          binding.tier === tier &&
          binding.authority ===
            (tier === "system" ? "ordinary" : "operator-protected") &&
          binding.provenance.repository === context.repository &&
          binding.provenance.runId === context.runId &&
          binding.provenance.runAttempt === context.runAttempt &&
          binding.provenance.workflow ===
            (tier === "system"
              ? "native-poc.yml"
              : "native-poc-acceptance.yml") &&
          entry.name === nativeArtifactName(context, binding.platform, tier) &&
          /^sha256:[a-f0-9]{64}$/u.test(entry.digest),
      );
      const job = jobs.find(({ jobId }) => jobId === binding.provenance.jobId);
      requireValue(
        job &&
          job.platform === binding.platform &&
          job.artifactId === binding.artifactId &&
          job.conclusion === binding.conclusion &&
          REPORTED_STAGES.every(
            (name) => job.stages[name] === entry.stages[name],
          ),
      );
      return {
        name: entry.name,
        digest: entry.digest,
        stages: stagesInOrder(entry.stages),
        binding,
      };
    })
    .sort(platformOrder);
  for (const key of ["name", "artifactId", "jobId"])
    requireValue(
      new Set(
        entries.map((entry) =>
          key === "name"
            ? entry.name
            : key === "artifactId"
              ? entry.binding.artifactId
              : entry.binding.provenance.jobId,
        ),
      ).size === entries.length,
    );
  issues.sort(
    (left, right) =>
      platformOrder(left, right) ||
      (left.code < right.code ? -1 : left.code > right.code ? 1 : 0),
  );
  return { entries, issues, jobs };
}

export function joinNativeArtifacts(context, input, payloads) {
  const selection = normalizeNativeArtifactSelection(context, input);
  const issues = [...selection.issues];
  const results = [];
  const bindings = [];
  const linuxPrerequisites = [];
  const nativeEffects = [];
  for (const job of selection.jobs)
    for (const code of REPORTED_STAGES)
      if (job.stages[code] !== "success")
        issues.push({ code, platform: job.platform });
  for (const { os } of PLATFORMS) {
    if (
      !selection.entries.some(({ binding }) => binding.platform === os) &&
      !selection.issues.some(({ platform }) => platform === os)
    )
      issues.push({ code: "missing", platform: os });
  }
  for (const entry of selection.entries) {
    try {
      const job = normalizeNativeJob(payloads[entry.name]);
      requireValue(
        job.candidateSha === context.candidateSha &&
          job.checkoutSha === context.candidateSha &&
          job.platform === entry.binding.platform &&
          JSON.stringify(job.provenance) ===
            JSON.stringify(entry.binding.provenance),
      );
      for (const stage of STAGES)
        requireValue(
          (entry.stages[stage] === "success") ===
            (job.stages[stage].status === "PASS"),
        );
      results.push(...nativeResults(job));
      bindings.push(entry.binding);
      if (job.schemaVersion >= 5) nativeEffects.push(nativeEffectEvidence(job));
      if (job.linuxPrerequisites)
        linuxPrerequisites.push(
          linuxPrerequisiteEvidence(job, job.linuxPrerequisites),
        );
    } catch {
      issues.push({ code: "payload", platform: entry.binding.platform });
    }
  }
  const rendered = renderNativeReport({
    candidateSha: context.candidateSha,
    source: source(context.candidateSha),
    results,
    bindings,
  });
  rendered.report.linuxPrerequisites = linuxPrerequisites;
  rendered.report.nativeEffects = nativeEffects;
  rendered.report.ciContext = { ...context };
  rendered.report.ciJobs = selection.jobs;
  rendered.report.ciStatus = selection.jobs.some(
    ({ conclusion, stages }) =>
      conclusion === "failure" || Object.values(stages).includes("failure"),
  )
    ? "FAIL"
    : issues.length ||
        selection.jobs.length !== PLATFORMS.length ||
        selection.jobs.some(
          ({ conclusion, stages }) =>
            conclusion !== "success" ||
            Object.values(stages).some((status) => status !== "success"),
        )
      ? "BLOCKED"
      : "PASS";
  return renderCiFindings(
    rendered,
    `## CI artifact join: ${rendered.report.ciStatus}`,
    issues.length
      ? "Primary CI stages and artifact defects are reported separately."
      : "All declared system artifacts were joined using read-only CI metadata.",
    issues,
  );
}
