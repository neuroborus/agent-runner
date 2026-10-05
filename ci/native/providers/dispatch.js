import {
  normalizeCompositionJob,
  runCompositionExecution,
  admitCompositionPlan,
  composeNativeRecords,
  normalizeReleaseClosure,
  releaseClosureDigest,
  nativePackageReviewDigest,
  observationDigest,
  requireObservation,
  normalizeBinding,
  NATIVE_GROUPS,
} from "../index.js";
import { linuxProviderOwner } from "../linux/index.js";
import { darwinProviderOwner } from "../darwin/index.js";
import { windowsProviderOwner } from "../win32/index.js";
import { normalizeProviderSpec } from "./contract.js";
import { runCodexMediation } from "./codex-cases.js";
import { CLAUDE_TOOL_CASES, runClaudeMediationCase } from "./claude-cases.js";

const profiles = ["read-only", "workspace-write", "trusted-command"];
const owners = {
  linux: linuxProviderOwner,
  darwin: darwinProviderOwner,
  win32: windowsProviderOwner,
};
export function protectedProviderRecipes(platform) {
  const groups = NATIVE_GROUPS[platform];
  requireObservation(groups);
  return profiles.flatMap((profile) => [
    {
      id: `codex.${profile}`,
      group: "codex",
      profile,
      checkIds: groups.codex.checkIds,
      deadlineMs: 180000,
    },
    ...Object.keys(CLAUDE_TOOL_CASES).map((id) => ({
      id: `claude.${profile}.${id}`,
      group: "claude",
      profile,
      checkIds: groups.claude.checkIds,
      deadlineMs: 180000,
    })),
  ]);
}

/** Protected controller authority and system closure are independent inputs.
 * Selecting --tier provider, supplying a payload flag, or provider text grants
 * no authority. All real model and native observation owners remain required. */
export async function runProtectedProviderProofs(input, options = {}) {
  let job = normalizeCompositionJob(input);
  requireObservation(
    job.tier === "provider" &&
      job.stages.setup.status === "PASS" &&
      job.executions.length === 0 &&
      typeof options.persist === "function",
  );
  const effects = options.effects;
  if (
    !job.reviews.provider ||
    !job.closure ||
    !options.sourceManifest ||
    !options.manifest ||
    !options.authority ||
    !options.releaseManifest ||
    !effects ||
    ["prepare", "settle"].some((key) => typeof effects[key] !== "function")
  )
    return job;
  const release = normalizeReleaseClosure(options.releaseManifest);
  requireObservation(
    releaseClosureDigest(release) === job.closure.manifestSha256 &&
      release.platform === job.platform &&
      release.candidateSha === job.candidateSha,
  );
  const { recipes } = admitCompositionPlan(
    job,
    protectedProviderRecipes(job.platform),
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
        for (const effectClass of NATIVE_GROUPS[job.platform][recipe.group]
          .effects)
          await admit(effectClass);
        prepared = await effects.prepare(recipe, { signal });
        requireObservation(!signal.aborted);
        requireObservation(
          prepared?.independent === true &&
            prepared.reviewSha256 === recipe.reviewSha256 &&
            prepared.policySha256 === recipe.policySha256,
        );
        const spec = normalizeProviderSpec(prepared.specification),
          provider = recipe.group;
        requireObservation(
          spec.provider === provider &&
            spec.platform === job.platform &&
            spec.candidateSha === job.candidateSha &&
            spec.profile === recipe.profile &&
            spec.closureSha256 === release.providers[provider].closureSha256 &&
            nativePackageReviewDigest(spec.review) ===
              release.providers[provider].reviewSha256,
        );
        const checkedCases = (value) => {
          requireObservation(
            value?.plan?.policySha256 === recipe.policySha256 &&
              value.plan.reviewSha256 === recipe.reviewSha256,
          );
          return value;
        };
        const cases =
          typeof prepared.cases === "function"
            ? async (...args) => checkedCases(await prepared.cases(...args))
            : checkedCases(prepared.cases);
        requireObservation(
          typeof prepared.effects?.persist === "function" &&
            typeof prepared.launchEffects?.persist === "function",
        );
        const nativeEffects = {
          ...prepared.effects,
          persist: async (value) => {
            await prepared.effects.persist(value);
            // Provider controllers redact their receipts; composition retains only
            // digests. No prompts, sessions, raw model text or request bodies.
            await effects.persistReceipt?.(recipe.id, observationDigest(value));
          },
        };
        const platformOwner = owners[job.platform](
          prepared.launch,
          prepared.approvedSha256,
          prepared.launchEffects,
          prepared.launchOptions,
        );
        const record =
          provider === "codex"
            ? await runCodexMediation(
                spec,
                cases,
                prepared.relayPolicy,
                platformOwner,
                nativeEffects,
              )
            : await runClaudeMediationCase(
                spec,
                cases,
                recipe.id.split(".").at(-1),
                prepared.relayPolicy,
                platformOwner,
                nativeEffects,
              );
        requireObservation(
          record?.status ===
            (provider === "codex"
              ? "MEDIATION_OBSERVED"
              : "CASE_MEDIATION_OBSERVED") &&
            record.phase === "settled" &&
            record.nativeObservation?.status === "OBSERVED" &&
            /^[a-f0-9]{64}$/u.test(record.liveBindingSha256),
        );
        // The controller rechecks images, dependency/build/ABI, policy and tool
        // routes before and after the model turn. Bind that live receipt to the
        // system's independently held package closure, retaining opacity.
        return {
          status: "OBSERVED",
          evidenceSha256: observationDigest({
            releaseReviewSha256: job.closure.manifestSha256,
            systemBindingSha256: job.closure.providerBindings[provider],
            liveBindingSha256: record.liveBindingSha256,
            receiptSha256: observationDigest(record),
          }),
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
  }
  job = composeNativeRecords(job, recipes);
  await persist(job);
  return job;
}

/** Pure join of externally selected metadata and the settled system payload.
 * API authentication/protected-environment approval belongs to the CI caller. */
export function admitProtectedProviderJob(
  input,
  systemInput,
  binding,
  reviews,
) {
  const job = normalizeCompositionJob(input),
    system = normalizeCompositionJob(systemInput);
  requireObservation(
    job.tier === "provider" &&
      system.tier === "system" &&
      job.platform === system.platform &&
      job.candidateSha === system.candidateSha &&
      system.closure !== null &&
      Object.values(system.stages).every(({ status }) => status === "PASS") &&
      system.results.every(({ status }) => status === "PASS"),
  );
  const selected = normalizeBinding(binding);
  requireObservation(
    selected.candidateSha === job.candidateSha &&
      selected.platform === job.platform &&
      selected.tier === "system" &&
      selected.conclusion === "success" &&
      observationDigest(selected.provenance) ===
        observationDigest(system.provenance),
  );
  requireObservation(
    reviews.source?.manifestSha256 === system.reviews.source?.manifestSha256 &&
      reviews.release?.manifestSha256 ===
        system.reviews.release?.manifestSha256,
  );
  return normalizeCompositionJob({
    ...job,
    reviews: {
      source: reviews.source,
      release: reviews.release,
      provider: reviews.provider,
      execution: null,
    },
    closure: system.closure,
  });
}
