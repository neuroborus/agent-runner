import { CHECK_IDS, PROVIDER_CHECK_IDS, NATIVE_GROUPS } from "./catalog.js";
import { normalizeNativeResult, admitNativeSourceReview } from "./evidence.js";
import { normalizeReviewAuthority } from "./closure.js";
import { normalizeCompositionJob, compositionFallback } from "./composition.js";
import { normalizePolicyTemplateApprovals } from "./policy-template.js";
import {
  observationDigest,
  observationObject as closed,
  observationList as list,
  requireObservation as requireValue,
} from "./observation.js";

/** Fixed recipes come from the indexed controller. The protected manifest
 * binds their complete inventory and reviewed effective policy, never CLI flags. */
export function admitCompositionPlan(
  job,
  recipes,
  manifest,
  authority,
  sourceManifest,
  templateReviews = [],
) {
  job = normalizeCompositionJob(job);
  const version = Object.getOwnPropertyDescriptor(
    manifest ?? {},
    "schemaVersion",
  )?.value;
  closed(manifest, [
    "schemaVersion",
    "candidateSha",
    "platform",
    "tier",
    "sourceReviewSha256",
    "releaseReviewSha256",
    ...(version === 2 ? ["policyTemplates"] : []),
    "cases",
  ]);
  normalizeReviewAuthority(authority, job.candidateSha, job.platform);
  requireValue(job.reviews.source !== null && job.reviews.release !== null);
  requireValue(
    [1, 2].includes(version) &&
      manifest.candidateSha === job.candidateSha &&
      manifest.platform === job.platform &&
      manifest.tier === job.tier &&
      manifest.sourceReviewSha256 === job.reviews.source?.manifestSha256 &&
      manifest.releaseReviewSha256 === job.reviews.release?.manifestSha256,
  );
  admitNativeSourceReview(sourceManifest, job.reviews.source);
  const policyTemplates =
    version === 2
      ? normalizePolicyTemplateApprovals(manifest.policyTemplates, job)
      : null;
  if (version === 2) {
    const approved = list(templateReviews, 256).map((review) =>
      normalizeReviewAuthority(review, job.candidateSha, job.platform),
    );
    requireValue(
      policyTemplates.every(({ approval }) =>
        approved.some(
          (review) => review.manifestSha256 === approval.manifestSha256,
        ),
      ),
    );
  }
  const cases = list(manifest.cases, 256);
  requireValue(
    cases.length === recipes.length &&
      new Set(cases.map(({ id }) => id)).size === cases.length,
  );
  const normalized = recipes.map((recipe) => {
    const item = cases.find(({ id }) => id === recipe.id);
    closed(item, [
      "id",
      "group",
      "profile",
      "checkIds",
      "deadlineMs",
      ...(version === 2 ? ["templateSha256"] : ["policySha256"]),
      "reviewSha256",
    ]);
    for (const key of ["id", "group", "profile", "checkIds", "deadlineMs"])
      requireValue(
        observationDigest(item[key]) === observationDigest(recipe[key]),
      );
    requireValue(
      [
        version === 2 ? item.templateSha256 : item.policySha256,
        item.reviewSha256,
      ].every(
        (value) => typeof value === "string" && /^[a-f0-9]{64}$/u.test(value),
      ),
    );
    if (version === 2)
      requireValue(
        policyTemplates.some(
          ({ approval }) => approval.manifestSha256 === item.templateSha256,
        ),
      );
    return { ...item, checkIds: [...item.checkIds] };
  });
  const canonical = {
    ...manifest,
    ...(policyTemplates ? { policyTemplates } : {}),
    cases: normalized,
  };
  requireValue(authority.manifestSha256 === observationDigest(canonical));
  if (job.tier === "provider")
    requireValue(
      job.reviews.provider?.manifestSha256 === authority.manifestSha256 &&
        job.closure !== null &&
        (version !== 2 || job.selectedSystem),
    );
  return { manifest: canonical, recipes: normalized };
}

/** Reduce only a complete, independently settled fixed inventory. A controller
 * status alone cannot compensate for an absent, failed or simulated case. */
export function composeNativeRecords(input, recipes) {
  const job = normalizeCompositionJob(input);
  requireValue(job.closure !== null);
  const required = CHECK_IDS.filter(
    (id) => PROVIDER_CHECK_IDS.includes(id) === (job.tier === "provider"),
  );
  const results = required.map((checkId) => {
    const expected = recipes.filter((recipe) =>
      recipe.checkIds.includes(checkId),
    );
    requireValue(expected.length > 0);
    const executions = job.executions.filter((entry) =>
      entry.checkIds.includes(checkId),
    );
    const complete =
      expected.length === executions.length &&
      expected.every((recipe) =>
        executions.some(
          (entry) =>
            entry.id === recipe.id &&
            entry.group === recipe.group &&
            entry.status === "PASS",
        ),
      );
    if (!complete)
      return normalizeNativeResult(compositionFallback(job, checkId));
    const group =
      NATIVE_GROUPS[job.platform][
        checkId === "provider.no-fallback"
          ? "fallback"
          : checkId === "provider.transport"
            ? "transport"
            : expected[0].group
      ];
    const policySha256 = observationDigest(
      recipes.map((recipe) => ({
        id: recipe.id,
        ...(job.plan.schemaVersion === 2
          ? { templateSha256: recipe.templateSha256 }
          : { policySha256: recipe.policySha256 }),
        reviewSha256: recipe.reviewSha256,
      })),
    );
    const result = {
      ...compositionFallback(job, checkId),
      admission: "possible",
      policy: { id: group.policyId, sha256: policySha256 },
      effectsSha256: observationDigest(executions),
      phases: {
        setup: { ...job.stages.setup },
        probe: {
          status: "PASS",
          elapsedMs: executions.reduce(
            (sum, entry) => sum + entry.elapsedMs,
            0,
          ),
          deadlineMs: executions.reduce(
            (sum, entry) => sum + entry.deadlineMs,
            0,
          ),
          reason: null,
        },
        cleanup: {
          status: "PASS",
          elapsedMs: executions.reduce(
            (sum, entry) => sum + entry.cleanupMs,
            0,
          ),
          deadlineMs: 30000 * executions.length,
          reason: null,
        },
      },
      observations: [
        {
          expected: "complete admitted native case inventory",
          observed: "independently observed and settled fixed cases",
          matched: true,
          positiveControl: true,
          attempted: true,
          sentinelsUnchanged: true,
        },
      ],
      settlement: {
        status: "RETIRED",
        independent: true,
        emergencyCleanup: false,
      },
      status: "PASS",
      reason: null,
    };
    return normalizeNativeResult(result);
  });
  return normalizeCompositionJob({ ...job, results });
}
