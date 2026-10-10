import path from "node:path";
import {
  observationList,
  observationObject,
  observationDigest,
  requireObservation,
} from "./observation.js";

const STAGES = [
  "prepare-inputs",
  "prepare-linux",
  "prepare",
  "setup",
  "probe",
  "cleanup",
];
const DIAGNOSES = [
  "prerequisite",
  "acquisition",
  "review",
  "metadata",
  "installation",
  "native-bootstrap",
  "bootstrap-assets",
  "packages",
  "toolchain",
  "build",
  "verification",
  "namespace-policy",
  "deadline",
  "stage-failed",
];
const INPUTS = {
  CI: (value) => value === "true",
  GITHUB_ACTIONS: (value) => value === "true",
  RUNNER_TEMP: (value) => path.isAbsolute(value) && !/[\x00-\x1f]/u.test(value),
  NATIVE_SYSTEM_INPUT_REPOSITORY: (value) =>
    /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(value),
  NATIVE_SYSTEM_INPUT_REVISION: (value) => /^[a-f0-9]{40}$/u.test(value),
  NATIVE_SYSTEM_REVIEW_SHA256: (value) => /^[a-f0-9]{64}$/u.test(value),
  NATIVE_LINUX_REVIEW_SHA256: (value) => /^[a-f0-9]{64}$/u.test(value),
  NATIVE_PROVIDER_REVIEW_SHA256: (value) => /^[a-f0-9]{64}$/u.test(value),
};
const INPUT_IDS = [
  ...Object.keys(INPUTS),
  "system-inputs.json",
  "native-effects.mjs",
  "linux-review.json",
  "provider-inputs.json",
  "provider-effects.mjs",
];
// Only errors produced by this owner may carry diagnostic metadata. Arbitrary
// thrown objects, including objects imitating this contract, never cross it.
const failures = new WeakMap();
export function nativePreparationError(diagnosis, inputs = []) {
  requireObservation(DIAGNOSES.includes(diagnosis));
  const error = new Error(`Native CI preparation failed: ${diagnosis}`);
  failures.set(error, { diagnosis, inputs: structuredClone(inputs) });
  return error;
}
export function nativeFailureDetails(error, fallback = "stage-failed") {
  requireObservation(DIAGNOSES.includes(fallback));
  return structuredClone(
    failures.get(error) ?? { diagnosis: fallback, inputs: [] },
  );
}
export function assertNativePreparationInputs(job, env) {
  const inputs = Object.entries(INPUTS).flatMap(([id, validate]) => {
    if (id === "NATIVE_LINUX_REVIEW_SHA256" && job.platform !== "linux")
      return [];
    if (id === "NATIVE_PROVIDER_REVIEW_SHA256" && job.tier !== "provider")
      return [];
    const value = Object.getOwnPropertyDescriptor(env, id)?.value;
    const diagnosis =
      value === undefined || value === null || value === ""
        ? "missing"
        : typeof value !== "string" || !validate(value)
          ? "malformed"
          : null;
    return diagnosis ? [{ id, diagnosis }] : [];
  });
  if (inputs.length) throw nativePreparationError("prerequisite", inputs);
}

export function normalizeNativeFirstFailure(value, job) {
  observationObject(value, [
    "schemaVersion",
    "candidateSha",
    "platform",
    "tier",
    "runId",
    "runAttempt",
    "stage",
    "diagnosis",
    "inputs",
    "admission",
  ]);
  requireObservation(
    value.schemaVersion === 1 &&
      typeof value.candidateSha === "string" &&
      /^[a-f0-9]{40}$/u.test(value.candidateSha) &&
      ["linux", "darwin", "win32"].includes(value.platform) &&
      ["system", "provider"].includes(value.tier) &&
      typeof value.runId === "string" &&
      /^[1-9][0-9]{0,19}$/u.test(value.runId) &&
      Number.isSafeInteger(value.runAttempt) &&
      value.runAttempt > 0 &&
      STAGES.includes(value.stage) &&
      DIAGNOSES.includes(value.diagnosis) &&
      ["not-started", "possible"].includes(value.admission),
  );
  for (const key of ["candidateSha", "platform", "tier"])
    requireObservation(value[key] === job[key]);
  requireObservation(
    value.diagnosis !== "namespace-policy" || value.platform === "linux",
  );
  for (const key of ["runId", "runAttempt"])
    requireObservation(value[key] === job.provenance[key]);
  const inputs = observationList(value.inputs, INPUT_IDS.length);
  requireObservation(
    new Set(inputs.map(({ id }) => id)).size === inputs.length,
  );
  for (const input of inputs) {
    observationObject(input, ["id", "diagnosis"]);
    requireObservation(
      INPUT_IDS.includes(input.id) &&
        ["missing", "malformed"].includes(input.diagnosis),
    );
    requireObservation(
      input.id !== "NATIVE_LINUX_REVIEW_SHA256" || value.platform === "linux",
    );
    requireObservation(
      input.id !== "NATIVE_PROVIDER_REVIEW_SHA256" || value.tier === "provider",
    );
  }
  requireObservation(value.diagnosis !== "prerequisite" || inputs.length > 0);
  requireObservation(
    inputs.length === 0 ||
      ["prerequisite", "acquisition", "review"].includes(value.diagnosis),
  );
  return structuredClone(value);
}

export function nativeJobHasPossibleEffects(job) {
  return (
    job.preparationEffects?.admission !== "not-started" ||
    job.executions?.some((entry) =>
      Object.values(entry.effects).some(
        ({ admission }) => admission === "possible",
      ),
    )
  );
}
export function captureNativeFirstFailure(job, stage, details) {
  if (job.firstFailure)
    return normalizeNativeFirstFailure(job.firstFailure, job);
  return normalizeNativeFirstFailure(
    {
      schemaVersion: 1,
      candidateSha: job.candidateSha,
      platform: job.platform,
      tier: job.tier,
      runId: job.provenance.runId,
      runAttempt: job.provenance.runAttempt,
      stage,
      ...details,
      admission: nativeJobHasPossibleEffects(job) ? "possible" : "not-started",
    },
    job,
  );
}

export function rejoinNativeFirstFailure(job, receipt) {
  const firstFailure = normalizeNativeFirstFailure(receipt, job);
  if (job.firstFailure)
    requireObservation(
      observationDigest(firstFailure) === observationDigest(job.firstFailure),
    );
  return { ...job, firstFailure };
}

/** Rejoin independently uploaded write-ahead custody without changing it.
 * Only an absent receipt is optional; malformed or substituted custody fails. */
export async function loadNativeFirstFailure(job, read) {
  let receipt;
  try {
    receipt = await read();
  } catch (error) {
    if (error?.code === "ENOENT") return job;
    throw error;
  }
  return rejoinNativeFirstFailure(job, receipt);
}

/** Receipt publication precedes the atomic job replacement. A resumed stage
 * rejoins that receipt instead of replacing the cause with its own failure. */
export async function persistNativeFirstFailure(
  job,
  stage,
  details,
  { read, persist, persistJob },
) {
  const previous = await read();
  const receipt =
    previous === null
      ? captureNativeFirstFailure(job, stage, details)
      : normalizeNativeFirstFailure(previous, job);
  const updated = rejoinNativeFirstFailure(job, receipt);
  if (previous === null) await persist(receipt);
  await persistJob(updated);
  return updated;
}

export function nativeFailureEvidence(jobs) {
  jobs = [...jobs].sort(
    (left, right) =>
      ["linux", "darwin", "win32"].indexOf(left.platform) -
        ["linux", "darwin", "win32"].indexOf(right.platform) ||
      left.tier.localeCompare(right.tier),
  );
  return {
    firstFailures: jobs
      .filter((job) => job.firstFailure)
      .map((job) => normalizeNativeFirstFailure(job.firstFailure, job)),
    preparationRecovery: jobs
      .filter(
        (job) =>
          job.preparationEffects || job.firstFailure?.admission === "possible",
      )
      .map((job) => ({
        candidateSha: job.candidateSha,
        platform: job.platform,
        tier: job.tier,
        runId: job.provenance.runId,
        runAttempt: job.provenance.runAttempt,
        admission: job.preparationEffects?.admission ?? "possible",
        status:
          job.preparationEffects?.admission === "not-started"
            ? "NOT_ADMITTED"
            : job.preparationEffects?.settlement.status === "RETIRED" &&
                job.preparationEffects.settlement.independent &&
                !job.preparationEffects.settlement.emergencyCleanup
              ? "RETIRED"
              : "UNCERTAIN",
      })),
  };
}
export function renderNativeFailures(rendered, jobs = null) {
  if (jobs) Object.assign(rendered.report, nativeFailureEvidence(jobs));
  const causes = rendered.report.firstFailures ?? [];
  const uncertain = (rendered.report.preparationRecovery ?? []).filter(
    ({ status }) => status === "UNCERTAIN",
  );
  if (!causes.length && !uncertain.length) return rendered;
  const prerequisites = [],
    failures = [];
  for (const cause of causes) {
    const message = `${cause.platform}/${cause.tier}: ${cause.stage}, ${cause.diagnosis}, admission ${cause.admission}${cause.inputs.map(({ id, diagnosis }) => `; ${id} ${diagnosis}`).join("")}.`;
    // Only retained non-admission evidence can classify a prerequisite stop.
    // A stage name or missing input alone does not exclude possible effects.
    if (cause.diagnosis === "prerequisite" && cause.admission === "not-started")
      prerequisites.push(message);
    else failures.push(message);
  }
  const recovery = uncertain.map(
    ({ platform, tier }) =>
      `${platform}/${tier}: preparation retirement is uncertain; retain exclusion and independently recover possible effects.`,
  );
  rendered.summary = [
    ...(prerequisites.length
      ? [
          "## Unmet native CI prerequisites",
          ...prerequisites,
          "Supply the identified CI inputs and independently reviewed, immutable candidate-bound manifests. Native admission has not started for these records; full acceptance remains blocked and the job remains unsuccessful.",
          "",
        ]
      : []),
    ...(failures.length || recovery.length
      ? [
          "## First native CI failures and preparation recovery",
          ...failures,
          ...recovery,
          "",
        ]
      : []),
    rendered.summary,
  ].join("\n");
  rendered.annotations = [
    ...prerequisites.map(
      (message) => `::error title=Native CI prerequisite::${message}`,
    ),
    ...[...failures, ...recovery].map(
      (message) => `::error title=Native preparation::${message}`,
    ),
    ...rendered.annotations,
  ].slice(0, 32);
  return rendered;
}
