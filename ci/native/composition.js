import {
  CHECK_IDS,
  PLATFORMS,
  PROVIDER_CHECK_IDS,
  NATIVE_EFFECT_CLASSES,
  NATIVE_GROUPS,
  nativeGroup,
} from "./catalog.js";
import { normalizeNativeAdmission, normalizeNativeResult } from "./evidence.js";
import {
  normalizeClosureReference,
  normalizeReviewAuthority,
} from "./closure.js";
import {
  observationDigest,
  observationObject as closed,
  observationList as list,
  requireObservation as requireValue,
} from "./observation.js";

const hash = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
const label = (value) =>
  typeof value === "string" && /^[a-z][a-z0-9.-]{0,95}$/u.test(value);
const stages = ["setup", "probe", "cleanup"];
const phase = () => ({
  status: "NOT_RUN",
  elapsedMs: null,
  deadlineMs: 120000,
  reason: "missing-input",
});
const retained = () => ({
  status: "RETAINED",
  independent: false,
  emergencyCleanup: false,
});
const checks = (tier) =>
  CHECK_IDS.filter(
    (id) => PROVIDER_CHECK_IDS.includes(id) === (tier === "provider"),
  );
export const compositionEffectRetired = (effect) =>
  effect.admission === "not-started" ||
  (effect.settlement.status === "RETIRED" &&
    effect.settlement.independent &&
    !effect.settlement.emergencyCleanup &&
    hash(effect.receiptSha256));
const settled = (execution) =>
  execution.status !== "NOT_RUN" &&
  Object.values(execution.effects).every(compositionEffectRetired);

export function initialCompositionJob(context, tier = "system") {
  closed(context, [
    "candidateSha",
    "platform",
    "repository",
    "runId",
    "runAttempt",
  ]);
  requireValue(["system", "provider"].includes(tier));
  const platform = PLATFORMS.find(({ os }) => os === context.platform);
  requireValue(platform);
  return normalizeCompositionJob(
    {
      schemaVersion: 6,
      ...context,
      tier,
      checkoutSha: null,
      declaredImage: platform.image,
      observed: { os: null, image: null, build: null, architecture: null },
      provenance: {
        repository: context.repository,
        workflow:
          tier === "system" ? "native-poc.yml" : "native-acceptance.yml",
        runId: context.runId,
        runAttempt: context.runAttempt,
        jobId: null,
      },
      versions: [],
      stages: Object.fromEntries(stages.map((name) => [name, phase()])),
      results: [],
      reviews: { source: null, release: null, provider: null, execution: null },
      plan: null,
      closure: null,
      executions: [],
    },
    true,
  );
}

export function compositionFallback(job, checkId) {
  const group = nativeGroup(job.platform, checkId);
  const related = job.executions.filter((entry) =>
    entry.checkIds.includes(checkId),
  );
  const attempted = related.some((entry) =>
    Object.values(entry.effects).some(
      ({ admission }) => admission === "possible",
    ),
  );
  const resultPhases = Object.fromEntries(
    stages.map((name) => [name, phase()]),
  );
  let status = "BLOCKED",
    reason = "missing-input",
    settlement = retained();
  const setupFailure =
    Object.getOwnPropertyDescriptor(job.stages.setup, "status")?.value ===
    "FAIL";
  if (!attempted && setupFailure) {
    resultPhases.setup = job.stages.setup;
    status = "FAIL";
    reason = Object.getOwnPropertyDescriptor(job.stages.setup, "reason")?.value;
  } else if (attempted && related.some((entry) => entry.status === "FAIL")) {
    const elapsed = (key) =>
      related.every((entry) => entry[key] !== null)
        ? related.reduce((sum, entry) => sum + entry[key], 0)
        : null;
    const retired = related.every(settled);
    const clean =
      retired &&
      related.every(
        (entry) => entry.cleanupMs !== null && entry.cleanupMs <= 30000,
      );
    reason = related.some((entry) => entry.elapsedMs > entry.deadlineMs)
      ? "deadline"
      : "probe-failed";
    status = "FAIL";
    resultPhases.setup = job.stages.setup;
    resultPhases.probe = {
      status,
      reason,
      elapsedMs: elapsed("elapsedMs"),
      deadlineMs: related.reduce((sum, entry) => sum + entry.deadlineMs, 0),
    };
    resultPhases.cleanup = {
      status: clean ? "PASS" : "FAIL",
      reason: clean
        ? null
        : !retired
          ? "unretired"
          : related.some((entry) => entry.cleanupMs === null)
            ? "missing-input"
            : "deadline",
      elapsedMs: elapsed("cleanupMs"),
      deadlineMs: related.length * 30000,
    };
    if (retired)
      settlement = {
        status: "RETIRED",
        independent: true,
        emergencyCleanup: false,
      };
  }
  return {
    schemaVersion: 3,
    candidateSha: job.candidateSha,
    checkoutSha: job.checkoutSha,
    platform: job.platform,
    declaredImage: job.declaredImage,
    observed: job.observed,
    provenance: job.provenance,
    checkId,
    profile: checkId.startsWith("profile.")
      ? checkId.slice(8)
      : checkId === "git.fixed-commit"
        ? "commit"
        : group,
    tier: job.tier,
    dispatch: job.tier === "provider" ? "protected" : "native",
    implemented: true,
    admission: attempted ? "possible" : "not-started",
    versions: job.versions,
    policy: null,
    phases: resultPhases,
    observations: [],
    settlement,
    status,
    reason,
    closure: job.closure,
    effectsSha256:
      status === "FAIL" && attempted ? observationDigest(related) : null,
  };
}
export const compositionResults = (job) =>
  checks(job.tier).map(
    (id) =>
      job.results.find(({ checkId }) => checkId === id) ??
      normalizeNativeResult(compositionFallback(job, id)),
  );

export function normalizeCompositionJob(value, initializing = false) {
  // Context is copied into provenance, never persisted twice.
  if (initializing) {
    value = { ...value };
    delete value.repository;
    delete value.runId;
    delete value.runAttempt;
  }
  closed(value, [
    "schemaVersion",
    "candidateSha",
    "checkoutSha",
    "platform",
    "declaredImage",
    "observed",
    "provenance",
    "versions",
    "stages",
    "results",
    "tier",
    "reviews",
    "plan",
    "closure",
    "executions",
  ]);
  requireValue(
    value.schemaVersion === 6 && ["system", "provider"].includes(value.tier),
  );
  closed(value.stages, stages);
  const platform = PLATFORMS.find(({ os }) => os === value.platform);
  requireValue(platform?.image === value.declaredImage);
  closed(value.reviews, ["source", "release", "provider", "execution"]);
  for (const key of ["source", "release", "provider", "execution"])
    if (value.reviews[key] !== null)
      normalizeReviewAuthority(
        value.reviews[key],
        value.candidateSha,
        key === "source" ? null : value.platform,
      );
  if (value.tier === "system") requireValue(value.reviews.provider === null);
  const closure =
    value.closure === null ? null : normalizeClosureReference(value.closure);
  if (closure)
    requireValue(
      closure.manifestSha256 === value.reviews.release?.manifestSha256 &&
        closure.sourceReviewSha256 === value.reviews.source?.manifestSha256,
    );
  if (value.plan !== null) {
    closed(value.plan, [
      "schemaVersion",
      "candidateSha",
      "platform",
      "tier",
      "sourceReviewSha256",
      "releaseReviewSha256",
      "cases",
    ]);
    requireValue(
      value.plan.schemaVersion === 1 &&
        value.plan.candidateSha === value.candidateSha &&
        value.plan.platform === value.platform &&
        value.plan.tier === value.tier &&
        value.plan.sourceReviewSha256 ===
          value.reviews.source?.manifestSha256 &&
        value.plan.releaseReviewSha256 ===
          value.reviews.release?.manifestSha256 &&
        observationDigest(value.plan) ===
          value.reviews.execution?.manifestSha256,
    );
    const recipes = list(value.plan.cases, 256);
    requireValue(new Set(recipes.map(({ id }) => id)).size === recipes.length);
    for (const recipe of recipes) {
      closed(recipe, [
        "id",
        "group",
        "profile",
        "checkIds",
        "deadlineMs",
        "policySha256",
        "reviewSha256",
      ]);
      requireValue(
        label(recipe.id) &&
          label(recipe.profile) &&
          ["build", ...Object.keys(NATIVE_GROUPS[value.platform])].includes(
            recipe.group,
          ) &&
          hash(recipe.policySha256) &&
          hash(recipe.reviewSha256) &&
          Number.isSafeInteger(recipe.deadlineMs) &&
          recipe.deadlineMs > 0 &&
          recipe.deadlineMs <= 3600000,
      );
      requireValue(
        list(recipe.checkIds, 23).every((id) =>
          checks(value.tier).includes(id),
        ),
      );
    }
    requireValue(
      checks(value.tier).every((id) =>
        recipes.some(({ checkIds }) => checkIds.includes(id)),
      ),
    );
  } else requireValue(value.reviews.execution === null);
  const executions = list(value.executions, 256).map((entry, index) => {
    closed(entry, [
      "id",
      "group",
      "checkIds",
      "effects",
      "status",
      "evidenceSha256",
      "elapsedMs",
      "deadlineMs",
      "cleanupMs",
    ]);
    requireValue(
      label(entry.id) &&
        ["build", ...Object.keys(NATIVE_GROUPS[value.platform])].includes(
          entry.group,
        ),
    );
    const checkIds = list(entry.checkIds, 23);
    requireValue(
      new Set(checkIds).size === checkIds.length &&
        checkIds.every(
          (id) =>
            checks(value.tier).includes(id) &&
            (entry.group === "build" ||
              NATIVE_GROUPS[value.platform][entry.group].checkIds.includes(id)),
        ),
    );
    closed(entry.effects, NATIVE_EFFECT_CLASSES);
    const effects = Object.fromEntries(
      NATIVE_EFFECT_CLASSES.map((id) => {
        const effect = entry.effects[id];
        closed(effect, ["admission", "settlement", "receiptSha256"]);
        const normalized = normalizeNativeAdmission({
          admission: effect.admission,
          settlement: effect.settlement,
        });
        requireValue(
          effect.receiptSha256 === null || hash(effect.receiptSha256),
        );
        if (effect.admission === "not-started")
          requireValue(effect.receiptSha256 === null);
        if (effect.settlement.status === "RETIRED")
          requireValue(hash(effect.receiptSha256));
        return [id, { ...normalized, receiptSha256: effect.receiptSha256 }];
      }),
    );
    requireValue(
      ["NOT_RUN", "PASS", "FAIL", "BLOCKED"].includes(entry.status) &&
        (entry.evidenceSha256 === null || hash(entry.evidenceSha256)),
    );
    for (const key of ["elapsedMs", "cleanupMs"])
      requireValue(
        entry[key] === null ||
          (Number.isSafeInteger(entry[key]) &&
            entry[key] >= 0 &&
            entry[key] <= 2147483647),
      );
    requireValue(
      Number.isSafeInteger(entry.deadlineMs) &&
        entry.deadlineMs > 0 &&
        entry.deadlineMs <= 3600000,
    );
    const recipe = value.plan?.cases.find(({ id }) => id === entry.id);
    requireValue(
      recipe &&
        recipe.group === entry.group &&
        recipe.deadlineMs === entry.deadlineMs &&
        observationDigest(recipe.checkIds) ===
          observationDigest(entry.checkIds),
    );
    const result = { ...entry, checkIds: [...checkIds], effects };
    if (entry.status === "PASS") {
      const required =
        entry.group === "build"
          ? ["builds"]
          : NATIVE_GROUPS[value.platform][entry.group].effects;
      requireValue(
        entry.elapsedMs !== null &&
          entry.elapsedMs <= entry.deadlineMs &&
          entry.cleanupMs !== null &&
          entry.cleanupMs <= 30000 &&
          hash(entry.evidenceSha256) &&
          required.every((id) => effects[id].admission === "possible") &&
          settled(result),
      );
    }
    if (
      value.tier === "provider" &&
      Object.values(effects).some(({ admission }) => admission === "possible")
    )
      requireValue(value.reviews.provider !== null && closure !== null);
    if (index < value.executions.length - 1) requireValue(settled(result));
    return result;
  });
  requireValue(
    new Set(executions.map(({ id }) => id)).size === executions.length,
  );
  // Reuse the strict identity/version/phase contract without promoting status.
  const context = normalizeNativeResult({
    ...compositionFallback({ ...value, executions }, checks(value.tier)[0]),
    phases: value.stages,
  });
  if (value.stages.setup.status === "PASS")
    requireValue(
      value.checkoutSha === value.candidateSha &&
        value.observed.os === value.platform &&
        value.observed.image === value.declaredImage &&
        value.observed.architecture === "x64" &&
        value.observed.build &&
        Object.values(value.provenance).every((field) => field !== null) &&
        value.versions.some(
          ({ name, version }) => name === "node" && version === "v24.21.0",
        ),
    );
  const results = list(value.results, checks(value.tier).length).map(
    normalizeNativeResult,
  );
  requireValue(
    new Set(results.map(({ checkId }) => checkId)).size === results.length,
  );
  for (const result of results) {
    requireValue(
      result.schemaVersion === 3 &&
        checks(value.tier).includes(result.checkId) &&
        result.tier === value.tier &&
        result.dispatch ===
          (value.tier === "provider" ? "protected" : "native"),
    );
    for (const key of [
      "candidateSha",
      "checkoutSha",
      "platform",
      "declaredImage",
      "observed",
      "provenance",
      "versions",
    ])
      requireValue(
        observationDigest(result[key]) === observationDigest(context[key]),
      );
    const possible = executions.some(
      (entry) =>
        entry.checkIds.includes(result.checkId) &&
        Object.values(entry.effects).some(
          ({ admission }) => admission === "possible",
        ),
    );
    requireValue(result.admission === (possible ? "possible" : "not-started"));
    if (result.status === "PASS")
      requireValue(
        closure &&
          observationDigest(result.closure) === observationDigest(closure) &&
          result.effectsSha256 ===
            observationDigest(
              executions.filter(({ checkIds }) =>
                checkIds.includes(result.checkId),
              ),
            ) &&
          executions.some(
            (entry) =>
              entry.status === "PASS" &&
              entry.checkIds.includes(result.checkId),
          ) &&
          executions
            .filter((entry) => entry.checkIds.includes(result.checkId))
            .every((entry) => entry.status === "PASS"),
      );
  }
  if (value.stages.probe.status === "PASS")
    requireValue(
      value.stages.setup.status === "PASS" &&
        results.length === checks(value.tier).length &&
        results.every(({ status }) => status === "PASS") &&
        value.plan !== null &&
        executions.length === value.plan.cases.length &&
        value.plan.cases.every((recipe) =>
          executions.some(
            (entry) => entry.id === recipe.id && entry.status === "PASS",
          ),
        ),
    );
  if (value.stages.cleanup.status === "PASS")
    requireValue(
      executions.every(settled) &&
        results.every(
          (result) =>
            result.admission === "not-started" ||
            (result.settlement.independent &&
              result.settlement.status === "RETIRED" &&
              !result.settlement.emergencyCleanup &&
              result.phases.cleanup.status === "PASS"),
        ),
    );
  return {
    ...value,
    observed: context.observed,
    provenance: context.provenance,
    versions: context.versions,
    stages: context.phases,
    closure,
    executions,
    results,
  };
}
export function compositionCleanupFailure(job) {
  return job.executions.every(settled) ? null : "unretired";
}
export function beginCompositionExecution(input, id, group, checkIds) {
  const job = normalizeCompositionJob(input);
  requireValue(
    job.stages.setup.status === "PASS" &&
      job.stages.probe.status === "NOT_RUN" &&
      job.stages.cleanup.status === "NOT_RUN" &&
      job.executions.every(settled),
  );
  const recipe = job.plan?.cases.find((entry) => entry.id === id);
  requireValue(recipe);
  return normalizeCompositionJob({
    ...job,
    executions: [
      ...job.executions,
      {
        id,
        group,
        checkIds,
        status: "NOT_RUN",
        evidenceSha256: null,
        elapsedMs: null,
        cleanupMs: null,
        deadlineMs: recipe.deadlineMs,
        effects: Object.fromEntries(
          NATIVE_EFFECT_CLASSES.map((name) => [
            name,
            {
              admission: "not-started",
              settlement: retained(),
              receiptSha256: null,
            },
          ]),
        ),
      },
    ],
  });
}
export function recordCompositionEffect(
  input,
  id,
  effectClass,
  settlement = null,
  receiptSha256 = null,
) {
  const job = normalizeCompositionJob(input),
    execution = job.executions.at(-1);
  requireValue(
    execution?.id === id &&
      execution.status === "NOT_RUN" &&
      NATIVE_EFFECT_CLASSES.includes(effectClass),
  );
  const allowed =
    execution.group === "build"
      ? ["builds"]
      : NATIVE_GROUPS[job.platform][execution.group].effects;
  requireValue(allowed.includes(effectClass));
  const before = execution.effects[effectClass];
  requireValue(
    before.settlement.status === "RETAINED" &&
      (settlement
        ? before.admission === "possible"
        : before.admission === "not-started"),
  );
  return normalizeCompositionJob({
    ...job,
    executions: [
      ...job.executions.slice(0, -1),
      {
        ...execution,
        effects: {
          ...execution.effects,
          [effectClass]: {
            admission: "possible",
            settlement: settlement ?? retained(),
            receiptSha256,
          },
        },
      },
    ],
  });
}
export function finishCompositionExecution(
  input,
  id,
  status,
  evidenceSha256,
  elapsedMs,
  cleanupMs,
) {
  const job = normalizeCompositionJob(input),
    execution = job.executions.at(-1);
  requireValue(
    execution?.id === id &&
      execution.status === "NOT_RUN" &&
      status !== "NOT_RUN",
  );
  return normalizeCompositionJob({
    ...job,
    executions: [
      ...job.executions.slice(0, -1),
      { ...execution, status, evidenceSha256, elapsedMs, cleanupMs },
    ],
  });
}
