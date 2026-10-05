import {
  runCompositionExecution,
  admitCompositionPlan,
  composeNativeRecords,
  normalizeCompositionJob,
  NATIVE_GROUPS,
  observationDigest,
  requireObservation,
} from "../index.js";
import {
  WINDOWS_OWNERSHIP_CASES,
  runWindowsOwnershipCase,
} from "./ownership.js";
import { runWindowsAccessCase } from "./access.js";
import { runWindowsFileCase } from "./files-cases.js";
import { runWindowsGitCase } from "./git.js";
import { observeWindowsRelease } from "./release.js";
import { admitWindowsLaunch } from "./launch.js";
import { assertWindowsLiteralObservation } from "./literal.js";
import {
  normalizeWindowsLaunch,
  WINDOWS_LITERAL_ARGUMENTS,
} from "./protocol.js";

const profiles = ["read-only", "workspace-write", "trusted-command"];
export function windowsSystemRecipes() {
  const recipe = (id, group, profile, checkIds, deadlineMs = 120000) => ({
    id,
    group,
    profile,
    checkIds,
    deadlineMs,
  });
  const groups = NATIVE_GROUPS.win32;
  return [
    recipe("build", "build", "fixture", []),
    recipe("release", "release", "release", groups.release.checkIds),
    ...["literal", "storage", ...WINDOWS_OWNERSHIP_CASES].map((id) =>
      recipe(
        `ownership.${id}`,
        "ownership",
        "ownership",
        groups.ownership.checkIds,
      ),
    ),
    ...profiles.flatMap((profile) =>
      ["none", "owner-loss", "helper-loss"].map((fault) =>
        recipe(
          `access.${profile}.${fault}`,
          "access",
          profile,
          groups.access.checkIds.filter(
            (id) =>
              !id.startsWith("git.") &&
              (!id.startsWith("profile.") || id === `profile.${profile}`),
          ),
        ),
      ),
    ),
    ...groups.files.checkIds.map((id) => recipe(id, "files", "files", [id])),
    recipe("git.ordinary", "access", "fixture", ["git.ordinary-denial"]),
    recipe("git.fixed", "access", "commit", ["git.fixed-commit"]),
  ];
}

/** External native preparation supplies private verifier capabilities; the
 * indexed controller fixes every dispatched case and its reviewed recipe. */
export async function runWindowsSystemProofs(input, options = {}) {
  let job = normalizeCompositionJob(input);
  requireObservation(
    job.platform === "win32" &&
      job.tier === "system" &&
      job.stages.setup.status === "PASS" &&
      job.executions.length === 0 &&
      typeof options.persist === "function",
  );
  const effects = options.effects;
  // Missing native installation/readers cannot become a reporting PASS.
  if (
    !effects ||
    !options.sourceManifest ||
    !options.manifest ||
    !options.authority ||
    !options.releaseManifest ||
    ["build", "prepare", "settle", "literal"].some(
      (key) => typeof effects[key] !== "function",
    )
  )
    return job;
  const { recipes } = admitCompositionPlan(
    job,
    windowsSystemRecipes(),
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
      execute: async ({ admit, signal }) => {
        const classes =
          recipe.group === "build"
            ? ["builds"]
            : NATIVE_GROUPS.win32[recipe.group].effects;
        for (const effectClass of classes) await admit(effectClass);
        if (recipe.group === "build") {
          const built = await effects.build({
            candidateSha: job.candidateSha,
            signal,
            reviewSha256: recipe.reviewSha256,
          });
          requireObservation(
            built?.independent === true &&
              built.status === "OBSERVED" &&
              built.reviewSha256 === recipe.reviewSha256,
          );
          return {
            status: "OBSERVED",
            evidenceSha256: observationDigest(built),
          };
        }
        prepared = await effects.prepare(recipe, { signal });
        requireObservation(!signal.aborted);
        requireObservation(
          prepared?.independent === true &&
            prepared.reviewSha256 === recipe.reviewSha256 &&
            prepared.policySha256 === recipe.policySha256,
        );
        let record;
        if (recipe.group === "release") {
          record = await observeWindowsRelease(
            options.releaseManifest,
            job.reviews.release,
            prepared.effects,
          );
          record = { closure: record.closure, status: "OBSERVED" };
        } else if (
          recipe.id === "ownership.literal" ||
          recipe.id === "ownership.storage"
        ) {
          // Both records need a real immutable executable below sealed private
          // storage. The same fixed corpus reaches the payload without a shell.
          const request = normalizeWindowsLaunch(
            prepared.input?.request ?? prepared.input,
          );
          requireObservation(
            request.schemaVersion === 1 &&
              request.candidateSha === job.candidateSha &&
              request.bindings.policy === recipe.policySha256 &&
              typeof prepared.effects?.persist === "function",
          );
          prepared.admitted = await admitWindowsLaunch(
            request,
            WINDOWS_LITERAL_ARGUMENTS,
            recipe.reviewSha256,
            prepared.effects,
          );
          requireObservation(
            !signal.aborted && prepared.admitted.record.status === "ADMITTED",
          );
          const observed = await effects.literal(prepared, { signal });
          record = assertWindowsLiteralObservation(
            request,
            WINDOWS_LITERAL_ARGUMENTS,
            prepared.admitted.record,
            observed,
          );
        } else {
          requireObservation(
            prepared.input?.request?.candidateSha === job.candidateSha ||
              prepared.input?.candidateSha === job.candidateSha,
          );
          if (recipe.id.startsWith("access."))
            requireObservation(prepared.input.profile === recipe.profile);
          requireObservation(typeof prepared.effects?.persist === "function");
          const nativeEffects = {
            ...prepared.effects,
            persist: async (value) => {
              await prepared.effects.persist(value);
              // Complete protected recovery receipts stay in their native owner;
              // only bounded receipt digests leave that custody.
              await effects.persistReceipt?.(
                recipe.id,
                observationDigest(value),
              );
            },
          };
          if (recipe.group === "ownership")
            record = await runWindowsOwnershipCase(
              recipe.id.slice(10),
              prepared.input,
              nativeEffects,
            );
          else if (recipe.id.startsWith("access."))
            record = await runWindowsAccessCase(prepared.input, nativeEffects, {
              fault: recipe.id.split(".").at(-1),
            });
          else if (recipe.group === "files")
            record = await runWindowsFileCase(
              recipe.id,
              prepared.input,
              nativeEffects,
            );
          else
            record = await runWindowsGitCase(
              recipe.id === "git.fixed"
                ? "git.fixed-commit"
                : "git.ordinary-denial",
              prepared.input,
              nativeEffects,
            );
        }
        requireObservation(record?.status === "OBSERVED");
        if (recipe.id.startsWith("access."))
          requireObservation(record.compositionSha256 === recipe.policySha256);
        return {
          status: "OBSERVED",
          evidenceSha256: observationDigest(record),
          ...(recipe.group === "release" ? { closure: record.closure } : {}),
        };
      },
      settle: ({ signal }) => effects.settle(recipe, prepared, { signal }),
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
