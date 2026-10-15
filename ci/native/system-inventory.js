import { CHECK_IDS, PROVIDER_CHECK_IDS, PLATFORMS } from "./catalog.js";
import {
  normalizeNativeJob,
  normalizeNativeArtifactSelection,
} from "./dispatch.js";
import {
  darwinSystemRecipes,
  darwinSystemPreparationInventory,
  DARWIN_SYSTEM_PREPARATION_MS,
} from "./darwin/index.js";
import {
  windowsSystemRecipes,
  windowsSystemPreparationInventory,
  WINDOWS_SYSTEM_PREPARATION_MS,
} from "./win32/index.js";
import {
  linuxSystemRecipes,
  linuxSystemPreparationInventory,
  LINUX_SYSTEM_PROBE_MS,
  LINUX_SYSTEM_PREPARATION_MS,
} from "./linux/index.js";
import { requireObservation, observationDigest } from "./observation.js";
import { normalizeExperimentJob } from "./experiment.js";
import { compositionEffectRetired } from "./composition.js";

const recipesFor = (platform) =>
  ({
    linux: linuxSystemRecipes,
    darwin: darwinSystemRecipes,
    win32: windowsSystemRecipes,
  })[platform]?.();

/** Ordinary experiments use the same fixed cases and candidate build inventory. */
export function nativeExperimentInventory(platform) {
  requireObservation(PLATFORMS.some(({ os }) => os === platform));
  const preparation = {
    linux: linuxSystemPreparationInventory,
    darwin: darwinSystemPreparationInventory,
    win32: windowsSystemPreparationInventory,
  }[platform];
  requireObservation(preparation);
  return { ...preparation(), cases: recipesFor(platform) };
}

export const SYSTEM_CHECK_IDS = Object.freeze(
  CHECK_IDS.filter((id) => !PROVIDER_CHECK_IDS.includes(id)),
);

/** Reduction of validated native observations, never a substitute for them. */
export function experimentSystemInventory(input) {
  const job = normalizeExperimentJob(input),
    recipes = nativeExperimentInventory(job.platform).cases,
    effects = [
      job.preparationEffects,
      ...job.cases.flatMap((entry) => Object.values(entry.effects)),
    ],
    possible = effects.filter((effect) => effect.admission === "possible"),
    cleanupStatus = possible.some((effect) => !compositionEffectRetired(effect))
      ? "FAIL"
      : possible.length
        ? "PASS"
        : "BLOCKED";
  const results = SYSTEM_CHECK_IDS.map((checkId) => {
    const required = recipes.filter((recipe) =>
        recipe.checkIds.includes(checkId),
      ),
      reached = job.cases.filter((entry) =>
        required.some((recipe) => recipe.id === entry.id),
      );
    return {
      purpose: "experiment",
      checkId,
      status: reached.some((entry) => entry.status === "FAIL")
        ? "FAIL"
        : reached.length === required.length &&
            reached.every((entry) => entry.status === "PASS")
          ? "PASS"
          : "BLOCKED",
    };
  });
  const failed =
      job.failure !== null ||
      cleanupStatus === "FAIL" ||
      job.cases.some((entry) => entry.status === "FAIL"),
    complete =
      job.preparation &&
      compositionEffectRetired(job.preparationEffects) &&
      job.cases.length === recipes.length &&
      job.cases.every((entry) => entry.status === "PASS") &&
      results.every((result) => result.status === "PASS");
  return {
    job,
    status: failed ? "FAIL" : complete ? "PASS" : "BLOCKED",
    cleanupStatus,
    results,
  };
}

/** Experimental custody uses top-level run context and observed preparation job
 * identity. Missing preparation can retain diagnostics, never successful proof. */
export function selectedExperimentInventory(context, input, payloads) {
  const selection = normalizeNativeArtifactSelection(
      context,
      input,
      "system",
      "experiment",
    ),
    issues = [...selection.issues],
    jobs = [];
  for (const job of selection.jobs)
    for (const [code, outcome] of Object.entries(job.stages))
      if (outcome !== "success") issues.push({ code, platform: job.platform });
  for (const { os } of PLATFORMS) {
    const entry = selection.entries.find(
      (entry) => entry.binding.platform === os,
    );
    if (!entry) {
      if (
        !issues.some(
          (issue) =>
            issue.platform === os &&
            ["missing", "duplicate", "metadata"].includes(issue.code),
        )
      )
        issues.push({ code: "missing", platform: os });
      continue;
    }
    try {
      const job = normalizeExperimentJob(payloads[entry.name]),
        provenance = entry.binding.provenance;
      requireObservation(
        job.candidateSha === context.candidateSha &&
          job.platform === os &&
          job.repository === provenance.repository &&
          job.runId === provenance.runId &&
          job.runAttempt === provenance.runAttempt,
      );
      if (job.preparation) {
        const binding = job.preparation.expected.binding;
        requireObservation(
          binding.checkoutSha === context.candidateSha &&
            binding.jobId === provenance.jobId &&
            binding.workflow + ".yml" === provenance.workflow,
        );
      }
      jobs.push(job);
    } catch {
      issues.push({ code: "payload", platform: os });
    }
  }
  const outcomes = jobs.map(experimentSystemInventory),
    failed =
      outcomes.some((outcome) => outcome.status === "FAIL") ||
      selection.jobs.some(
        (job) =>
          job.conclusion === "failure" ||
          Object.values(job.stages).includes("failure"),
      ),
    complete =
      !issues.length &&
      jobs.length === PLATFORMS.length &&
      selection.jobs.length === PLATFORMS.length &&
      selection.jobs.every((job) => job.conclusion === "success") &&
      outcomes.every((outcome) => outcome.status === "PASS");
  return {
    purpose: "experiment",
    status: failed ? "FAIL" : complete ? "PASS" : "BLOCKED",
    records: outcomes.reduce(
      (sum, outcome) =>
        sum +
        outcome.results.filter((result) => result.status === "PASS").length,
      0,
    ),
    issues,
    jobs,
    ciJobs: selection.jobs,
    bindings: selection.entries.map((entry) => entry.binding),
  };
}

/** Independently inspect the checkout and runtime before acquisition or native
 * preparation. An image label alone cannot admit privileged bootstrap. */
export function assertSystemPreparationEnvelope(job, observed) {
  requireObservation(
    (job.tier ?? "system") === "system" &&
      job.stages.setup.elapsedMs === null &&
      observed.checkoutSha === job.candidateSha &&
      observed.nodeVersion === "v24.21.0" &&
      observed.image.os === job.platform &&
      observed.image.image === job.declaredImage &&
      observed.image.architecture === "x64",
  );
}

/** Bounds follow the fixed native inventory, including separate settlement and
 * final receipt writes. Workflow limits add reserve; none narrows a case. */
export function systemJobBounds(platform, schemaVersion = 6) {
  const recipes = recipesFor(platform);
  requireObservation(
    recipes &&
      [5, 6].includes(schemaVersion) &&
      (schemaVersion === 6 || platform === "linux"),
  );
  const preparationMs = {
    linux: LINUX_SYSTEM_PREPARATION_MS,
    darwin: DARWIN_SYSTEM_PREPARATION_MS,
    win32: WINDOWS_SYSTEM_PREPARATION_MS,
  }[platform];
  // Harness, capability loading, plan/closure writes and final reduction each
  // have a separate 30-second allowance before case settlement.
  const probeMs =
    schemaVersion === 5
      ? LINUX_SYSTEM_PROBE_MS
      : 5 * 30000 +
        recipes.reduce((sum, { deadlineMs }) => sum + deadlineMs + 60000, 0);
  const cleanupMs = 120000;
  const minutes = (ms) => Math.ceil(ms / 60000) + 1;
  return {
    preparationMs,
    probeMs,
    cleanupMs,
    preparationMinutes: minutes(preparationMs),
    probeMinutes: minutes(probeMs),
    cleanupMinutes: minutes(cleanupMs),
    bootstrapMinutes: platform === "linux" ? 4 : 0,
    jobMinutes:
      minutes(preparationMs) +
      minutes(probeMs) +
      minutes(cleanupMs) +
      16 +
      (platform === "linux" ? 4 : 0),
  };
}

/** A labelled 23-record result is useful to the protected collector, but is
 * never full acceptance. Independent selection still owns run/job/artifact
 * identity, digest, upload receipt and lifetime; run conclusion is not a bypass. */
export function selectedSystemInventory(context, selection, payloads) {
  selection = normalizeNativeArtifactSelection(context, selection);
  const issues = [...selection.issues];
  const jobs = [];
  for (const { os } of PLATFORMS) {
    const entry = selection.entries.find(
      ({ binding }) => binding.platform === os,
    );
    try {
      requireObservation(
        entry &&
          entry.binding.conclusion === "success" &&
          Object.values(entry.stages).every((status) => status === "success"),
      );
      const job = normalizeNativeJob(payloads[entry.name]);
      const recipes = recipesFor(os);
      requireObservation(
        job.schemaVersion === 6 &&
          job.plan?.cases.length === recipes.length &&
          recipes.every((recipe, index) => {
            const item = job.plan.cases[index];
            return (
              job.executions[index]?.id === recipe.id &&
              Object.keys(recipe).every(
                (key) =>
                  observationDigest(item[key]) ===
                  observationDigest(recipe[key]),
              )
            );
          }),
      );
      requireObservation(
        job.candidateSha === context.candidateSha &&
          job.checkoutSha === context.candidateSha &&
          job.platform === os &&
          job.tier === "system" &&
          JSON.stringify(job.provenance) ===
            JSON.stringify(entry.binding.provenance) &&
          Object.values(job.stages).every(({ status }) => status === "PASS") &&
          job.results.length === SYSTEM_CHECK_IDS.length &&
          SYSTEM_CHECK_IDS.every((id) =>
            job.results.some(
              ({ checkId, tier, dispatch, status, phases, settlement }) =>
                checkId === id &&
                tier === "system" &&
                dispatch === "native" &&
                status === "PASS" &&
                Object.values(phases).every(
                  ({ status }) => status === "PASS",
                ) &&
                settlement.status === "RETIRED" &&
                settlement.independent &&
                !settlement.emergencyCleanup,
            ),
          ),
      );
      jobs.push(job);
    } catch {
      issues.push({ code: "system-inventory", platform: os });
    }
  }
  return {
    schemaVersion: 1,
    candidateSha: context.candidateSha,
    scope: "system-inventory-only",
    fullAcceptance: false,
    status:
      issues.length === 0 && jobs.length === PLATFORMS.length
        ? "PASS"
        : "BLOCKED",
    records: jobs.reduce((sum, job) => sum + job.results.length, 0),
    issues,
    jobs,
  };
}
