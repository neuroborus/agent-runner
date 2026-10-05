import { CHECK_IDS, PROVIDER_CHECK_IDS, PLATFORMS } from "./catalog.js";
import {
  normalizeNativeJob,
  normalizeNativeArtifactSelection,
} from "./dispatch.js";
import {
  darwinSystemRecipes,
  DARWIN_SYSTEM_PREPARATION_MS,
} from "./darwin/index.js";
import {
  windowsSystemRecipes,
  WINDOWS_SYSTEM_PREPARATION_MS,
} from "./win32/index.js";
import {
  linuxSystemRecipes,
  LINUX_SYSTEM_PROBE_MS,
  LINUX_SYSTEM_PREPARATION_MS,
} from "./linux/index.js";
import { requireObservation, observationDigest } from "./observation.js";

const recipesFor = (platform) =>
  ({
    linux: linuxSystemRecipes,
    darwin: darwinSystemRecipes,
    win32: windowsSystemRecipes,
  })[platform]?.();

export const SYSTEM_CHECK_IDS = Object.freeze(
  CHECK_IDS.filter((id) => !PROVIDER_CHECK_IDS.includes(id)),
);

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
