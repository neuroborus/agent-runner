import { PLATFORMS, PROVIDER_CHECK_IDS } from "./catalog.js";
import {
  normalizeNativeJob,
  normalizeNativeArtifactSelection,
  selectNativeArtifacts,
  selectProviderArtifacts,
} from "./dispatch.js";
import { selectedSystemInventory } from "./system-inventory.js";
import { admitNativeSourceReview } from "./evidence.js";
import { renderNativeReport } from "./reports.js";
import { protectedProviderRecipes } from "./providers/index.js";
import {
  observationObject,
  observationDigest,
  requireObservation,
} from "./observation.js";

const sha = (v) => typeof v === "string" && /^[a-f0-9]{40}$/u.test(v);
const id = (v) => typeof v === "string" && /^[1-9][0-9]{0,19}$/u.test(v);
const same = (a, b) => observationDigest(a) === observationDigest(b);
const lifetime = 7 * 24 * 60 * 60 * 1000;
export const providerEnvironmentName = (os) => `native-poc-provider-${os}`;

export function normalizeAcceptanceRequest(input) {
  observationObject(input, [
    "candidateSha",
    "repository",
    "runId",
    "runAttempt",
    "workflowSha",
    "systemRunId",
    "systemRunAttempt",
    "sourceReviewSha256",
  ]);
  requireObservation(
    sha(input.candidateSha) &&
      input.workflowSha === input.candidateSha &&
      /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(input.repository) &&
      id(input.runId) &&
      id(input.systemRunId) &&
      input.runId !== input.systemRunId &&
      [input.runAttempt, input.systemRunAttempt].every(
        (v) => Number.isSafeInteger(v) && v > 0,
      ) &&
      /^[a-f0-9]{64}$/u.test(input.sourceReviewSha256),
  );
  return { ...input };
}

/** The workflow revision, dispatch SHA and checkout are independent controls.
 * This gate precedes input preparation and the step that injects credentials. */
export function assertAcceptanceRevision(input, observed) {
  const request = normalizeAcceptanceRequest(input);
  requireObservation(
    observed.event === "workflow_dispatch" &&
      observed.workflowSha === request.candidateSha &&
      observed.dispatchSha === request.candidateSha &&
      observed.checkoutSha === request.candidateSha,
  );
  return request;
}

function verifyRun(request, bundle, tier, now) {
  const { run, workflow, repository } = bundle;
  const file =
    tier === "system" ? "native-poc.yml" : "native-poc-acceptance.yml";
  const runId = tier === "system" ? request.systemRunId : request.runId;
  const attempt =
    tier === "system" ? request.systemRunAttempt : request.runAttempt;
  const created = Date.parse(run.created_at),
    started = Date.parse(run.run_started_at),
    updated = Date.parse(run.updated_at);
  requireObservation(
    String(run.id) === runId &&
      run.run_attempt === attempt &&
      Number.isSafeInteger(repository.id) &&
      repository.id > 0 &&
      repository.full_name === request.repository &&
      run.repository?.id === repository.id &&
      run.repository.full_name === request.repository &&
      Number.isSafeInteger(workflow.id) &&
      workflow.id > 0 &&
      run.workflow_id === workflow.id &&
      workflow.path === `.github/workflows/${file}` &&
      run.path?.split("@")[0] === workflow.path &&
      Number.isFinite(now) &&
      Number.isFinite(created) &&
      Number.isFinite(started) &&
      Number.isFinite(updated) &&
      created <= started &&
      started <= updated &&
      updated <= now &&
      now - started <= lifetime,
  );
  if (tier === "provider") {
    requireObservation(
      run.event === "workflow_dispatch" &&
        run.head_sha === request.candidateSha &&
        ["in_progress", "completed"].includes(run.status),
    );
    for (const { os } of PLATFORMS) {
      const environment = bundle.environments?.find(
        (value) => value.name === providerEnvironmentName(os),
      );
      requireObservation(
        environment &&
          environment.protection_rules?.some(
            (rule) =>
              rule.type === "required_reviewers" &&
              rule.prevent_self_review === true &&
              Array.isArray(rule.reviewers) &&
              rule.reviewers.length > 0,
          ),
      );
    }
  } else {
    requireObservation(
      run.status === "completed" &&
        ["success", "failure"].includes(run.conclusion),
    );
    const candidate = bundle.jobs.filter((job) => job.name === "candidate");
    const aggregate = bundle.jobs.filter((job) => job.name === "aggregate");
    requireObservation(
      candidate.length === 1 &&
        aggregate.length === 1 &&
        candidate[0].status === "completed" &&
        candidate[0].conclusion === "success" &&
        aggregate[0].status === "completed" &&
        aggregate[0].conclusion === run.conclusion &&
        [candidate[0], aggregate[0]].every(
          (job) => String(job.run_id) === runId && job.run_attempt === attempt,
        ),
    );
    if (run.conclusion === "failure") {
      const failures = aggregate[0].steps?.filter(
        (step) => step.conclusion === "failure",
      );
      requireObservation(
        failures?.length === 1 &&
          failures[0].name === "Report aggregate and enforce acceptance" &&
          aggregate[0].steps.every((step) =>
            step.name === "Report aggregate and enforce acceptance"
              ? step.conclusion === "failure"
              : step.conclusion === "success",
          ) &&
          [
            "Collect read-only run/job/artifact metadata",
            "Upload aggregate failures and summary",
          ].every(
            (name) =>
              aggregate[0].steps.filter(
                (step) => step.name === name && step.conclusion === "success",
              ).length === 1,
          ),
      );
    }
    if (run.event === "pull_request") {
      // GitHub's head_sha is the immutable synthetic merge, not the checkout.
      // Read the merge commit and both workflow blobs independently from API.
      const pulls = run.pull_requests;
      requireObservation(
        Array.isArray(pulls) &&
          pulls.length === 1 &&
          pulls[0].head?.sha === request.candidateSha &&
          pulls[0].base?.repo?.id === repository.id &&
          bundle.merge?.sha === run.head_sha &&
          run.head_sha !== request.candidateSha &&
          bundle.merge.parents?.length === 2 &&
          bundle.merge.parents[0].sha === pulls[0].base.sha &&
          bundle.merge.parents[1].sha === request.candidateSha &&
          /^[a-f0-9]{40}$/u.test(bundle.candidateWorkflow?.sha) &&
          bundle.candidateWorkflow.sha === bundle.runWorkflow?.sha,
      );
    } else
      requireObservation(
        run.event === "workflow_dispatch" &&
          run.head_sha === request.candidateSha,
      );
  }
  return {
    candidateSha: request.candidateSha,
    repository: request.repository,
    runId,
    runAttempt: attempt,
    workflowSha: run.head_sha,
  };
}

/** All inputs are independent bounded API reads. Payloads cannot supply this
 * authority. A failed full system aggregate never overrides selected jobs. */
export function selectAcceptanceArtifacts(
  input,
  bundles,
  now,
  { systemOnly = false, diagnosticsOnly = false } = {},
) {
  requireObservation(!diagnosticsOnly || !systemOnly);
  const request = normalizeAcceptanceRequest(input);
  const systemContext = verifyRun(request, bundles.system, "system", now);
  const providerContext = verifyRun(request, bundles.provider, "provider", now);
  requireObservation(
    Date.parse(bundles.system.run.updated_at) <=
      Date.parse(bundles.provider.run.run_started_at),
  );
  const system = normalizeNativeArtifactSelection(
    systemContext,
    selectNativeArtifacts(
      systemContext,
      bundles.system.run,
      bundles.system.jobs,
      bundles.system.artifacts,
    ),
  );
  const provider = systemOnly
    ? { entries: [], issues: [], jobs: [] }
    : normalizeNativeArtifactSelection(
        providerContext,
        selectProviderArtifacts(
          providerContext,
          bundles.provider.run,
          bundles.provider.jobs,
          bundles.provider.artifacts,
        ),
        "provider",
      );
  for (const [selection, bundle] of [
    [system, bundles.system],
    [provider, bundles.provider],
  ]) {
    for (const entry of selection.entries) {
      const job = bundle.jobs.find(
        (value) => String(value.id) === entry.binding.provenance.jobId,
      );
      const artifact = bundle.artifacts.find(
        (value) => String(value.id) === entry.binding.artifactId,
      );
      const receipt = job.steps.find(
        (step) => step.name === `Bind native artifact ${artifact.id}`,
      );
      const upload = job.steps.filter(
        (step) => step.name === "Upload native evidence",
      );
      requireObservation(
        (diagnosticsOnly ||
          (job.conclusion === "success" &&
            Object.values(entry.stages).every((s) => s === "success"))) &&
          Date.parse(job.started_at) >= Date.parse(bundle.run.run_started_at) &&
          Date.parse(job.completed_at) <= now &&
          Date.parse(artifact.expires_at) > now &&
          upload.length === 1 &&
          upload[0].conclusion === "success" &&
          Date.parse(upload[0].started_at) <= Date.parse(artifact.created_at) &&
          Date.parse(artifact.created_at) <=
            Date.parse(upload[0].completed_at) &&
          Date.parse(receipt.started_at) >=
            Date.parse(upload[0].completed_at) &&
          Date.parse(receipt.completed_at) <= Date.parse(job.completed_at),
      );
    }
    if (!diagnosticsOnly)
      requireObservation(
        selection.issues.length === 0 &&
          ((selection === provider && systemOnly) ||
            selection.entries.length === 3),
      );
  }
  const entries = [...system.entries, ...provider.entries];
  requireObservation(
    ["artifactId", "jobId"].every(
      (key) =>
        new Set(
          entries.map(({ binding }) =>
            key === "artifactId"
              ? binding.artifactId
              : binding.provenance.jobId,
          ),
        ).size === entries.length,
    ),
  );
  return {
    request,
    systemContext,
    providerContext,
    system,
    provider,
    ...(diagnosticsOnly ? { diagnosticsOnly: true } : {}),
  };
}

/** Recheck the downloaded payloads against independent metadata. Require exact
 * fixed recipes and independent review digests; full reporting keeps all IDs. */
export function joinAcceptanceArtifacts(selection, payloads, source, reviews) {
  requireObservation(selection.diagnosticsOnly !== true);
  const request = normalizeAcceptanceRequest(selection.request);
  const sourceReview = {
    candidateSha: request.candidateSha,
    platform: null,
    manifestSha256: request.sourceReviewSha256,
    authority: "operator-protected",
  };
  admitNativeSourceReview(source, sourceReview);
  const inventory = selectedSystemInventory(
    selection.systemContext,
    selection.system,
    payloads,
  );
  requireObservation(inventory.status === "PASS");
  const providers = normalizeNativeArtifactSelection(
    selection.providerContext,
    selection.provider,
    "provider",
  );
  requireObservation(
    providers.entries.length === 3 && providers.issues.length === 0,
  );
  const jobs = [...inventory.jobs];
  const executionReviews = [];
  const releaseReviews = [];
  const templateReviews = [];
  for (const { os } of PLATFORMS) {
    const system = inventory.jobs.find((job) => job.platform === os);
    const entry = providers.entries.find(
      ({ binding }) => binding.platform === os,
    );
    const provider = normalizeNativeJob(payloads[entry.name]);
    const admitted = reviews.find((review) => review.platform === os);
    requireObservation(
      admitted &&
        provider.schemaVersion === 6 &&
        provider.tier === "provider" &&
        provider.platform === os &&
        provider.candidateSha === request.candidateSha &&
        provider.checkoutSha === request.candidateSha &&
        same(provider.provenance, entry.binding.provenance) &&
        entry.binding.conclusion === "success" &&
        Object.values(entry.stages).every((s) => s === "success") &&
        Object.values(provider.stages).every(
          ({ status }) => status === "PASS",
        ) &&
        provider.results.length === PROVIDER_CHECK_IDS.length &&
        PROVIDER_CHECK_IDS.every((id) =>
          provider.results.some(
            ({ checkId, tier, dispatch, status }) =>
              checkId === id &&
              tier === "provider" &&
              dispatch === "protected" &&
              status === "PASS",
          ),
        ) &&
        same(provider.closure, system.closure) &&
        [provider, system].every(
          (job) =>
            job.reviews.source?.manifestSha256 === request.sourceReviewSha256 &&
            same(job.reviews.release, admitted.release),
        ) &&
        same(provider.reviews.provider, admitted.provider) &&
        same(provider.reviews.execution, admitted.provider) &&
        same(system.reviews.execution, admitted.system),
    );
    const recipes = protectedProviderRecipes(os);
    requireObservation(
      provider.plan?.cases.length === recipes.length &&
        provider.executions.length === recipes.length &&
        recipes.every(
          (recipe, index) =>
            provider.executions[index].id === recipe.id &&
            Object.keys(recipe).every((key) =>
              same(recipe[key], provider.plan.cases[index][key]),
            ),
        ),
    );
    jobs.push(provider);
    executionReviews.push(
      { tier: "system", review: admitted.system },
      { tier: "provider", review: admitted.provider },
    );
    releaseReviews.push(admitted.release);
    templateReviews.push(...(admitted.templateReviews ?? []));
  }
  return renderNativeReport({
    candidateSha: request.candidateSha,
    source,
    sourceReview,
    results: jobs.flatMap((job) => job.results),
    compositions: jobs,
    bindings: [...selection.system.entries, ...providers.entries].map(
      ({ binding }) => binding,
    ),
    executionReviews,
    releaseReviews,
    templateReviews,
  });
}
