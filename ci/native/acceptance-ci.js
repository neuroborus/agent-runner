import { appendFile, lstat } from "node:fs/promises";
import path from "node:path";
import { PLATFORMS, PROVIDER_CHECK_IDS } from "./catalog.js";
import { admitNativeSourceReview, sourceReviewDigest } from "./evidence.js";
import { observationDigest, requireObservation } from "./observation.js";
import { initializeNativeJob } from "./dispatch.js";
import { admitCompositionPlan } from "./composition-plan.js";
import { aggregateNativeEvidence } from "./reports.js";
import { selectedSystemInventory } from "./system-inventory.js";
import {
  normalizeAcceptanceRequest,
  selectAcceptanceArtifacts,
  joinAcceptanceArtifacts,
  providerEnvironmentName,
} from "./acceptance.js";
import {
  fetchAcceptanceInput,
  admitProviderCIManifest,
} from "./providers/index.js";
import { linuxSystemRecipes } from "./linux/index.js";
import { darwinSystemRecipes } from "./darwin/index.js";
import { windowsSystemRecipes } from "./win32/index.js";

export function acceptanceRequest(env) {
  return normalizeAcceptanceRequest({
    candidateSha: env.NATIVE_CANDIDATE_SHA,
    repository: env.GITHUB_REPOSITORY,
    runId: env.GITHUB_RUN_ID,
    runAttempt: Number(env.GITHUB_RUN_ATTEMPT),
    workflowSha: env.GITHUB_WORKFLOW_SHA,
    systemRunId: env.NATIVE_SYSTEM_RUN_ID,
    systemRunAttempt: Number(env.NATIVE_SYSTEM_RUN_ATTEMPT),
    sourceReviewSha256: env.NATIVE_SOURCE_REVIEW_SHA256,
  });
}

/** Bounded, read-only API collection is separate from artifact assertions and
 * never trusts head_sha as a PR checkout or accepts artifact-supplied authority. */
export async function collectAcceptance(env, directory, io) {
  const request = acceptanceRequest(env);
  const repository = await io.github(env, "", { repositoryRoute: true });
  const bundles = {};
  for (const tier of ["system", "provider"]) {
    const runId = tier === "system" ? request.systemRunId : request.runId;
    const attempt =
      tier === "system" ? request.systemRunAttempt : request.runAttempt;
    const file =
      tier === "system" ? "native-poc.yml" : "native-poc-acceptance.yml";
    const run = await io.github(env, `runs/${runId}/attempts/${attempt}`);
    const workflow = await io.github(env, `workflows/${file}`);
    const selectedEnv = {
      ...env,
      GITHUB_RUN_ID: runId,
      GITHUB_RUN_ATTEMPT: String(attempt),
    };
    const bundle = {
      run,
      workflow,
      repository,
      jobs: await io.listMetadata(selectedEnv, "jobs"),
      artifacts: await io.listMetadata(selectedEnv, "artifacts"),
    };
    if (tier === "system" && run.event === "pull_request") {
      requireObservation(/^[a-f0-9]{40}$/u.test(run.head_sha));
      bundle.merge = await io.github(env, `git/commits/${run.head_sha}`, {
        repositoryRoute: true,
      });
      for (const [key, sha] of [
        ["candidateWorkflow", request.candidateSha],
        ["runWorkflow", run.head_sha],
      ])
        bundle[key] = await io.github(
          env,
          `contents/.github/workflows/native-poc.yml?ref=${sha}`,
          { repositoryRoute: true },
        );
    }
    if (tier === "provider") {
      bundle.environments = [];
      for (const { os } of PLATFORMS)
        bundle.environments.push(
          await io.github(env, `environments/${providerEnvironmentName(os)}`, {
            repositoryRoute: true,
          }),
        );
    }
    bundles[tier] = bundle;
  }
  const selection = selectAcceptanceArtifacts(request, bundles, Date.now(), {
    systemOnly: env.NATIVE_REPORT_NAME === "native-provider",
  });
  await io.persistJSON(path.join(directory, "selection.json"), selection);
  if (env.GITHUB_OUTPUT)
    await appendFile(
      env.GITHUB_OUTPUT,
      `system_artifact_ids=${selection.system.entries.map(({ binding }) => binding.artifactId).join(",")}\n` +
        `provider_artifact_ids=${selection.provider.entries.map(({ binding }) => binding.artifactId).join(",")}\n`,
    );
}

async function downloadedPayloads(env, selection, io) {
  const payloads = {};
  const root = path.resolve(env.RUNNER_TEMP, "native-artifacts");
  for (const [tier, entries] of [
    ["system", selection.system.entries],
    ["provider", selection.provider.entries],
  ]) {
    requireObservation(
      entries.length === 0 ||
        env[`NATIVE_${tier.toUpperCase()}_DOWNLOAD_OUTCOME`] === "success",
    );
    for (const { name } of entries) {
      for (const dir of [root, path.join(root, name)]) {
        const stat = await lstat(dir);
        requireObservation(stat.isDirectory() && !stat.isSymbolicLink());
      }
      payloads[name] = await io.readJSON(
        path.join(root, name, "native-job.json"),
      );
    }
  }
  return payloads;
}

async function reviewedSelection(env, directory, io) {
  const request = acceptanceRequest(env);
  const selection = await io.readJSON(path.join(directory, "selection.json"));
  requireObservation(
    observationDigest(selection.request) === observationDigest(request),
  );
  const payloads = await downloadedPayloads(env, selection, io);
  const inventory = selectedSystemInventory(
    selection.systemContext,
    selection.system,
    payloads,
  );
  requireObservation(inventory.status === "PASS");
  const source = JSON.parse(
    await fetchAcceptanceInput(
      env,
      request.candidateSha,
      "source-manifest.json",
    ),
  );
  const sourceReview = {
    candidateSha: request.candidateSha,
    platform: null,
    manifestSha256: request.sourceReviewSha256,
    authority: "operator-protected",
  };
  admitNativeSourceReview(source, sourceReview);
  const reviews = [];
  for (const { os } of PLATFORMS) {
    const job = inventory.jobs.find((entry) => entry.platform === os);
    const prefix = { linux: "LINUX", darwin: "DARWIN", win32: "WINDOWS" }[os];
    const system = JSON.parse(
      await fetchAcceptanceInput(
        env,
        request.candidateSha,
        `${os}/system-inputs.json`,
      ),
    );
    requireObservation(
      observationDigest(system) ===
        env[`NATIVE_${prefix}_SYSTEM_REVIEW_SHA256`] &&
        system.candidateSha === request.candidateSha &&
        system.platform === os &&
        sourceReviewDigest(system.source) === request.sourceReviewSha256,
    );
    const provider = JSON.parse(
      await fetchAcceptanceInput(
        env,
        request.candidateSha,
        `${os}/provider-inputs.json`,
      ),
    );
    const initialized = initializeNativeJob(
      {
        candidateSha: request.candidateSha,
        platform: os,
        repository: request.repository,
        runId: request.runId,
        runAttempt: request.runAttempt,
      },
      { schemaVersion: 6, tier: "provider" },
    );
    const admitted = admitProviderCIManifest(
      { ...initialized, closure: job.closure },
      provider,
      env[`NATIVE_${prefix}_PROVIDER_REVIEW_SHA256`],
      request.sourceReviewSha256,
    );
    requireObservation(
      observationDigest(system.release) ===
        observationDigest(provider.release) &&
        admitted.release.manifestSha256 === job.closure.manifestSha256 &&
        job.reviews.source?.manifestSha256 === request.sourceReviewSha256 &&
        observationDigest(job.reviews.release) ===
          observationDigest(admitted.release),
    );
    const execution = {
      ...admitted.release,
      manifestSha256: observationDigest(system.execution),
    };
    requireObservation(
      observationDigest(execution) === observationDigest(job.reviews.execution),
    );
    const recipes = {
      linux: linuxSystemRecipes,
      darwin: darwinSystemRecipes,
      win32: windowsSystemRecipes,
    }[os]();
    admitCompositionPlan(job, recipes, system.execution, execution, source);
    reviews.push({
      platform: os,
      system: execution,
      release: admitted.release,
      provider: admitted.provider,
    });
  }
  // With independently approved review now available, every selected system
  // record must already satisfy the full predicate. Only absent provider
  // records may remain; unrelated system/reporting failures cannot be reused.
  const partial = aggregateNativeEvidence({
    candidateSha: request.candidateSha,
    source,
    sourceReview,
    results: inventory.jobs.flatMap((job) => job.results),
    compositions: inventory.jobs,
    bindings: selection.system.entries.map(({ binding }) => binding),
    releaseReviews: reviews.map(({ release }) => release),
    executionReviews: reviews.map(({ system }) => ({
      tier: "system",
      review: system,
    })),
  });
  requireObservation(
    partial.issues.every(
      (issue) =>
        issue.code === "MISSING" && PROVIDER_CHECK_IDS.includes(issue.checkId),
    ),
  );
  return { request, selection, payloads, inventory, source, reviews };
}

export async function verifySelectedSystem(env, directory, io) {
  const reviewed = await reviewedSelection(env, directory, io);
  const system = reviewed.inventory.jobs.find(
    (job) => job.platform === env.NATIVE_PLATFORM,
  );
  const entry = reviewed.selection.system.entries.find(
    ({ binding }) => binding.platform === env.NATIVE_PLATFORM,
  );
  requireObservation(
    system && entry && reviewed.selection.provider.entries.length === 0,
  );
  await io.persistJSON(path.join(directory, "system-admission.json"), {
    request: reviewed.request,
    system,
    binding: entry.binding,
    reviews: reviewed.reviews,
  });
}

/** A failed collection still publishes a bounded failure artifact; it never
 * downgrades the strict 87-record/four-finding predicate into a system result. */
export async function aggregateAcceptance(env, directory, io) {
  let rendered;
  try {
    const reviewed = await reviewedSelection(env, directory, io);
    rendered = joinAcceptanceArtifacts(
      reviewed.selection,
      reviewed.payloads,
      reviewed.source,
      reviewed.reviews,
    );
  } catch {
    rendered = {
      report: {
        schemaVersion: 1,
        candidateSha: env.NATIVE_CANDIDATE_SHA,
        scope: "aggregate",
        decision: "BLOCKED",
        issues: [
          {
            code: "PROVENANCE",
            platform: null,
            checkId: null,
            message:
              "Repair candidate, protected review or independent run/job/artifact collection and obtain fresh proof.",
          },
        ],
      },
      summary:
        "## Native acceptance: BLOCKED\n\nIndependent same-candidate evidence is incomplete. No GO is established.",
      annotations: [
        "::error title=Native acceptance::Independent same-candidate collection or proof is incomplete.",
      ],
    };
  }
  await io.publish(env, directory, rendered);
  if (rendered.report.decision !== "GO") process.exitCode = 1;
}
