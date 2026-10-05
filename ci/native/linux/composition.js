import { initializeNativeJob, recordNativeStage } from "../dispatch.js";
import {
  NATIVE_GROUPS,
  runCompositionExecution,
  admitCompositionPlan,
  composeNativeRecords,
  normalizeCompositionJob,
  observationDigest,
  requireObservation,
} from "../index.js";
import { runLinuxSystemProofs, LINUX_SYSTEM_PROBE_MS } from "./system.js";
import { observeLinuxCandidateClosure } from "./candidate-release.js";

export function linuxSystemRecipes() {
  return [
    {
      id: "linux.reference",
      group: "reference",
      profile: "reference",
      checkIds: Object.values(NATIVE_GROUPS.linux)
        .flatMap(({ checkIds }) => checkIds)
        .filter(
          (id, index, all) =>
            !id.startsWith("provider.") &&
            !id.startsWith("codex.") &&
            !id.startsWith("claude.") &&
            id !== "audit.release" &&
            all.indexOf(id) === index,
        ),
      deadlineMs: LINUX_SYSTEM_PROBE_MS,
    },
    {
      id: "candidate.release",
      group: "release",
      profile: "release",
      checkIds: ["audit.release"],
      deadlineMs: 120000,
    },
  ];
}

/** The v5 Linux reference engine and its unresolved-source semantics remain
 * intact. New candidate/package closure is a distinct, reviewed observation. */
export async function runLinuxComposedSystemProofs(
  input,
  directory,
  options = {},
) {
  let job = normalizeCompositionJob(input);
  requireObservation(
    job.platform === "linux" &&
      job.tier === "system" &&
      job.executions.length === 0 &&
      typeof options.persist === "function",
  );
  if (
    !options.sourceManifest ||
    !options.manifest ||
    !options.authority ||
    !options.releaseManifest ||
    typeof options.effects?.prepare !== "function" ||
    typeof options.effects?.settle !== "function"
  )
    return job;
  const { recipes } = admitCompositionPlan(
    job,
    linuxSystemRecipes(),
    options.manifest,
    options.authority,
    options.sourceManifest,
  );
  const persist = async (value) => {
    await options.persist(value);
    job = value;
  };
  job = normalizeCompositionJob({
    ...job,
    reviews: { ...job.reviews, execution: options.authority },
    plan: { ...options.manifest, cases: recipes },
  });
  await persist(job);
  for (const recipe of recipes) {
    let prepared;
    const owner = {
      execute: async ({ admit, signal, diagnostic }) => {
        for (const effectClass of NATIVE_GROUPS.linux[recipe.group].effects)
          await admit(effectClass);
        prepared = await options.effects.prepare(recipe, { signal });
        requireObservation(!signal.aborted);
        requireObservation(
          prepared?.independent === true &&
            prepared.reviewSha256 === recipe.reviewSha256 &&
            prepared.policySha256 === recipe.policySha256,
        );
        if (recipe.group === "reference") {
          let reference = initializeNativeJob(
            {
              candidateSha: job.candidateSha,
              platform: job.platform,
              repository: job.provenance.repository,
              runId: job.provenance.runId,
              runAttempt: job.provenance.runAttempt,
            },
            { schemaVersion: 5 },
          );
          reference = recordNativeStage(reference, "setup", job.stages.setup, {
            checkoutSha: job.checkoutSha,
            observed: job.observed,
            provenance: job.provenance,
            // The historical release engine owns its component version names.
            // Dedicated preparation banners remain in the enclosing v6 job.
            versions: job.versions.filter(
              ({ name }) =>
                !["build.compiler", "build.sdk", "build.signer"].includes(name),
            ),
          });
          reference = await runLinuxSystemProofs(
            reference,
            options.referenceDirectory ?? directory,
            {
              ...prepared.options,
              persist: async (value) => {
                // Preserve the reference engine's write-ahead group receipts too.
                requireObservation(
                  typeof options.effects.persistReference === "function",
                );
                await options.effects.persistReference(value);
              },
              diagnostic,
            },
          );
          requireObservation(
            reference.results.length === 23 &&
              reference.results.every(({ status }) => status === "PASS") &&
              Object.values(reference.admissions).every(
                ({ admission, settlement }) =>
                  admission === "possible" &&
                  settlement.status === "RETIRED" &&
                  settlement.independent &&
                  !settlement.emergencyCleanup,
              ),
          );
          return {
            status: "OBSERVED",
            evidenceSha256: observationDigest(reference),
          };
        }
        const record = await observeLinuxCandidateClosure(
          options.releaseManifest,
          job.reviews.release,
          prepared.effects,
        );
        return {
          status: "OBSERVED",
          evidenceSha256: observationDigest(record),
          closure: record.closure,
        };
      },
      settle: ({ signal }) =>
        options.effects.settle(recipe, prepared, { signal }),
    };
    const outcome = await runCompositionExecution(job, recipe, owner, {
      persist,
      diagnostic: options.diagnostic,
    });
    job = outcome.job;
    if (!outcome.result) break;
    if (outcome.result.closure) {
      job = normalizeCompositionJob({
        ...job,
        closure: {
          ...outcome.result.closure,
          sourceReviewSha256: job.reviews.source.manifestSha256,
        },
      });
      await persist(job);
    }
  }
  if (job.closure) {
    job = composeNativeRecords(job, recipes);
    await persist(job);
  }
  return job;
}
