import {
  runCompositionExecution,
  compositionPolicyBinding,
  verifyCompositionPolicy,
  admitCompositionPlan,
  composeNativeRecords,
  normalizeCompositionJob,
  NATIVE_GROUPS,
  observationDigest,
  requireObservation,
} from "../index.js";
import { DARWIN_OWNERSHIP_CASES, runDarwinOwnershipCase } from "./ownership.js";
import { runDarwinAccessCase } from "./access.js";
import { runDarwinFileCase } from "./files-cases.js";
import { runDarwinGitCase } from "./git.js";
import { observeDarwinRelease } from "./release.js";
import { admitDarwinLaunch } from "./launch.js";
import { assertDarwinLiteralObservation } from "./literal.js";
import { normalizeDarwinLaunch, DARWIN_LITERAL_ARGUMENTS } from "./protocol.js";

const profiles = ["read-only", "workspace-write", "trusted-command"];
export function darwinSystemRecipes() {
  const recipe = (id, group, profile, checkIds, deadlineMs = 120000) => ({
    id,
    group,
    profile,
    checkIds,
    deadlineMs,
  });
  const groups = NATIVE_GROUPS.darwin;
  return [
    recipe("build", "build", "fixture", []),
    recipe("release", "release", "release", groups.release.checkIds),
    ...["literal", "storage", ...DARWIN_OWNERSHIP_CASES].map((id) =>
      recipe(
        `ownership.${id}`,
        "ownership",
        "ownership",
        groups.ownership.checkIds,
      ),
    ),
    ...profiles.map((profile) =>
      recipe(
        `access.${profile}`,
        "access",
        profile,
        groups.access.checkIds.filter(
          (id) =>
            !id.startsWith("git.") &&
            (!id.startsWith("profile.") || id === `profile.${profile}`),
        ),
      ),
    ),
    ...groups.files.checkIds.map((id) =>
      recipe(
        id,
        "files",
        "files",
        [id],
        id === "files.aliases"
          ? 360000
          : id === "files.substitution"
            ? 240000
            : 180000,
      ),
    ),
    recipe("git.ordinary", "access", "fixture", ["git.ordinary-denial"]),
    recipe("git.fixed", "access", "commit", ["git.fixed-commit"]),
  ];
}

/** External native preparation supplies private verifier capabilities; the
 * indexed controller fixes every dispatched case and its reviewed recipe. */
export async function runDarwinSystemProofs(input, options = {}) {
  let job = normalizeCompositionJob(input);
  requireObservation(
    job.platform === "darwin" &&
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
    darwinSystemRecipes(),
    options.manifest,
    options.authority,
    options.sourceManifest,
    options.templateReviews ?? [],
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
      execute: async ({ admit, recordPolicy, signal }) => {
        const policy =
          job.plan.schemaVersion === 2
            ? {
                policyBinding: compositionPolicyBinding(job, recipe.id),
                recordPolicy: async (proof) =>
                  recordPolicy(verifyCompositionPolicy(job, recipe.id, proof)),
              }
            : {};
        if (policy.policyBinding) await admit("policy");
        const classes =
          recipe.group === "build"
            ? ["builds"]
            : NATIVE_GROUPS.darwin[recipe.group].effects;
        for (const effectClass of classes)
          if (!policy.policyBinding || effectClass !== "policy")
            await admit(effectClass);
        if (recipe.group === "build") {
          const built = await effects.build({
            candidateSha: job.candidateSha,
            signal,
            reviewSha256: recipe.reviewSha256,
            ...policy,
          });
          requireObservation(
            built?.independent === true &&
              built.status === "OBSERVED" &&
              built.reviewSha256 === recipe.reviewSha256,
          );
          if (policy.policyBinding) {
            if (built.policyProof) await policy.recordPolicy(built.policyProof);
            requireObservation(job.executions.at(-1).policyReceipt !== null);
          }
          return {
            status: "OBSERVED",
            evidenceSha256: observationDigest(built),
          };
        }
        prepared = await effects.prepare(recipe, { signal, ...policy });
        requireObservation(!signal.aborted);
        requireObservation(
          prepared?.independent === true &&
            prepared.reviewSha256 === recipe.reviewSha256 &&
            (policy.policyBinding
              ? prepared.templateSha256 === recipe.templateSha256
              : prepared.policySha256 === recipe.policySha256),
        );
        if (policy.policyBinding) {
          if (prepared.policyProof)
            await policy.recordPolicy(prepared.policyProof);
          if (!["ownership.literal", "ownership.storage"].includes(recipe.id))
            requireObservation(job.executions.at(-1).policyReceipt !== null);
        }
        return executeDarwinSystemCase(
          job,
          recipe,
          prepared,
          effects,
          {
            ...policy,
            hasReceipt: () => job.executions.at(-1).policyReceipt !== null,
          },
          options,
          signal,
        );
      },
      settle: ({ signal }) =>
        effects.settle(recipe, prepared, {
          signal,
          execution: structuredClone(job.executions.at(-1)),
        }),
    };
    const outcome = await runCompositionExecution(job, recipe, owner, {
      persist,
      diagnostic: options.diagnostic,
    });
    job = outcome.job;
    if (!outcome.result) break;
    if (outcome.result.closure && job.plan.schemaVersion === 2) {
      const { observationSha256: freshObservation, ...fresh } =
        outcome.result.closure;
      const {
        observationSha256: selectedObservation,
        sourceReviewSha256,
        ...selected
      } = job.closure;
      requireObservation(
        /^[a-f0-9]{64}$/u.test(freshObservation) &&
          /^[a-f0-9]{64}$/u.test(selectedObservation),
      );
      requireObservation(
        observationDigest(fresh) === observationDigest(selected),
      );
    } else if (outcome.result.closure) {
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

async function executeDarwinSystemCase(
  job,
  recipe,
  prepared,
  effects,
  policy,
  options,
  signal,
) {
  let record;
  if (recipe.group === "release") {
    if (job.purpose === "experiment") {
      record = await prepared.effects.observe();
      requireObservation(
        record?.purpose === "experiment" &&
          /^[a-f0-9]{64}$/u.test(record.evidenceSha256),
      );
    } else {
      record = await observeDarwinRelease(
        options.releaseManifest,
        job.reviews.release,
        prepared.effects,
      );
      record = { closure: record.closure, status: "OBSERVED" };
    }
  } else if (
    recipe.id === "ownership.literal" ||
    recipe.id === "ownership.storage"
  ) {
    // Both records need a real immutable executable below sealed private
    // storage. The same fixed corpus reaches the payload without a shell.
    const request = normalizeDarwinLaunch(
      prepared.input?.request ?? prepared.input,
      job.purpose ?? "reviewed",
    );
    requireObservation(
      request.schemaVersion === 1 &&
        request.candidateSha === job.candidateSha &&
        (policy.policyBinding ||
          request.bindings.policy === recipe.policySha256) &&
        typeof prepared.effects?.persist === "function",
    );
    prepared.admitted = prepared.admit
      ? await prepared.admit()
      : await admitDarwinLaunch(
          request,
          DARWIN_LITERAL_ARGUMENTS,
          policy.policyBinding ?? recipe.reviewSha256,
          policy.policyBinding
            ? {
                ...prepared.effects,
                async readPolicy(request, record) {
                  const observed = await prepared.effects.readPolicy(
                    request,
                    record,
                  );
                  await policy.recordPolicy({
                    provisioning: record.provisioning,
                    requestSha256: record.requestSha256,
                    observed,
                  });
                  return observed;
                },
              }
            : prepared.effects,
        );
    requireObservation(
      !signal.aborted && prepared.admitted.record.status === "ADMITTED",
    );
    if (policy.policyBinding) requireObservation(policy.hasReceipt());
    const observed = await effects.literal(prepared, { signal });
    record = assertDarwinLiteralObservation(
      request,
      DARWIN_LITERAL_ARGUMENTS,
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
        await effects.persistReceipt?.(recipe.id, observationDigest(value));
      },
    };
    if (recipe.group === "ownership")
      record = await runDarwinOwnershipCase(
        recipe.id.slice(10),
        prepared.input,
        nativeEffects,
      );
    else if (recipe.id.startsWith("access."))
      record = await runDarwinAccessCase(prepared.input, nativeEffects);
    else if (recipe.group === "files")
      record = await runDarwinFileCase(
        recipe.id,
        prepared.input,
        nativeEffects,
      );
    else
      record = await runDarwinGitCase(
        recipe.id === "git.fixed" ? "git.fixed-commit" : "git.ordinary-denial",
        prepared.input,
        nativeEffects,
      );
  }
  requireObservation(record?.status === "OBSERVED");
  if (recipe.id.startsWith("access."))
    requireObservation(
      record.compositionSha256 ===
        (policy.policyBinding ? prepared.policySha256 : recipe.policySha256),
    );
  return {
    status: "OBSERVED",
    evidenceSha256: observationDigest(record),
    ...(recipe.group === "release" && job.purpose !== "experiment"
      ? { closure: record.closure }
      : {}),
  };
}

/** Ordinary v7 evidence uses the same fixed native assertions as reviewed CI. */
export async function runDarwinExperimentProofs(
  input,
  directory,
  options = {},
) {
  requireObservation(input.platform === "darwin");
  const { runSystemExperimentProofs } = await import("../system-experiment.js");
  const {
    loadDarwinExperiment,
    createDarwinExperimentSystemEffects,
    darwinExperimentBuildBinding,
  } = await import("./experiment-preparation.js");
  return runSystemExperimentProofs(
    input,
    directory,
    darwinSystemRecipes(),
    {
      load: options.load ?? loadDarwinExperiment,
      createEffects:
        options.createEffects ?? createDarwinExperimentSystemEffects,
      binding: (preparation, id) =>
        id === "build"
          ? darwinExperimentBuildBinding(preparation)
          : preparation.system.policyBindings.find(
              (value) => value.context.executionId === id,
            ),
      execute: executeDarwinSystemCase,
    },
    options,
  );
}
