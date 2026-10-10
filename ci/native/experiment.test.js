import assert from "node:assert/strict";
import test from "node:test";
import {
  initializeNativeJob,
  normalizeNativeJob,
  normalizeNativeResult,
  renderNativeJob,
  nativeExperimentInventory,
  recordExperimentPreparationEffect,
  recordExperimentPreparation,
  recordExperimentCase,
  observationDigest,
  normalizeReleaseClosure,
  normalizeReviewAuthority,
  NATIVE_EFFECT_CLASSES,
  NATIVE_GROUPS,
  PLATFORMS,
  SYSTEM_CHECK_IDS,
} from "./index.js";

const C = "a".repeat(40),
  H = "b".repeat(64),
  OTHER = "c".repeat(64);
const effect = (admission = "not-started", retired = false) => ({
  admission,
  settlement: {
    status: retired ? "RETIRED" : "RETAINED",
    independent: retired,
    emergencyCleanup: false,
  },
  receiptSha256: retired ? H : null,
});
function reverseKeys(value) {
  if (Array.isArray(value)) return value.map(reverseKeys);
  return value && typeof value === "object"
    ? Object.fromEntries(
        Object.entries(value)
          .reverse()
          .map(([key, entry]) => [key, reverseKeys(entry)]),
      )
    : value;
}

// Synthetic reads exercise only the pure contract; no native execution is claimed.
function fixture(platform = "linux") {
  const jobContext = {
    candidateSha: C,
    platform,
    repository: "example/native",
    runId: "1",
    runAttempt: 1,
  };
  const inventory = nativeExperimentInventory(platform);
  const expected = {
    binding: {
      ...jobContext,
      checkoutSha: C,
      image: PLATFORMS.find(({ os }) => os === platform).image,
      osBuild: "synthetic-build",
      architecture: "x64",
      nodeVersion: "v24.21.0",
      workflow: "native-poc",
      jobId: "2",
    },
    sources: inventory.helpers.map((id) => ({ id, sha256: H })),
    tools: inventory.tools.map((id) => ({
      id,
      sha256: H,
      version: "synthetic-version",
    })),
    sdk: { build: "synthetic-sdk", sha256: H },
    components: inventory.helpers.map((id) => ({
      id,
      role: "helper",
      sha256: H,
      format: { linux: "elf-x64", darwin: "macho-x64", win32: "pe-x64" }[
        platform
      ],
      loader: [],
      bindings: { source: H, build: H, abi: H },
    })),
  };
  const observed = {
    ...structuredClone(expected),
    components: expected.components.map(({ role, ...entry }) => ({
      ...entry,
      identityBefore: H,
      identityAfter: H,
      held: true,
      independent: true,
    })),
    independent: true,
    readSha256: H,
  };
  let job = initializeNativeJob(jobContext, {
    schemaVersion: 7,
    purpose: "experiment",
  });
  job = recordExperimentPreparationEffect(job, effect("possible"));
  job = recordExperimentPreparation(job, expected, observed);
  return { job, expected, observed, inventory };
}

function complete(platform) {
  let { job, observed, inventory } = fixture(platform);
  for (const recipe of inventory.cases) {
    const intent = {
      purpose: "experiment",
      id: recipe.id,
      preparationSha256: observationDigest(job.preparation),
      status: "NOT_RUN",
      elapsedMs: null,
      cleanupMs: null,
      policy: {
        expectedSha256: H,
        observedSha256: null,
        independent: false,
        effective: false,
      },
      components: null,
      observations: [],
      effects: Object.fromEntries(
        NATIVE_EFFECT_CLASSES.map((id) => [id, effect()]),
      ),
    };
    job = recordExperimentCase(job, intent);
    const required =
      recipe.group === "build"
        ? ["builds"]
        : NATIVE_GROUPS[platform][recipe.group].effects;
    const admitted = {
      ...intent,
      effects: Object.fromEntries(
        NATIVE_EFFECT_CLASSES.map((id) => [
          id,
          effect(required.includes(id) ? "possible" : "not-started"),
        ]),
      ),
    };
    job = recordExperimentCase(job, admitted);
    job = recordExperimentCase(job, {
      ...admitted,
      status: "PASS",
      elapsedMs: 1,
      cleanupMs: 1,
      policy: {
        expectedSha256: H,
        observedSha256: H,
        independent: true,
        effective: true,
      },
      components: observed.components,
      observations: recipe.checkIds.map((checkId) => ({
        checkId,
        observation: {
          expected: "verified",
          observed: "verified",
          matched: true,
          positiveControl: true,
          attempted: true,
          sentinelsUnchanged: true,
        },
      })),
      effects: Object.fromEntries(
        NATIVE_EFFECT_CLASSES.map((id) => [
          id,
          effect(
            required.includes(id) ? "possible" : "not-started",
            required.includes(id),
          ),
        ]),
      ),
    });
  }
  return recordExperimentPreparationEffect(job, effect("possible", true));
}

test("complete experiment recipes pass ordinary reporting on each platform without production approval", () => {
  for (const { os } of PLATFORMS) {
    const job = complete(os);
    assert.deepEqual(normalizeNativeJob(reverseKeys(job)), job);
    const report = renderNativeJob(job).report;
    assert.equal(report.ciStatus, "PASS");
    assert.deepEqual(
      report.results.map(({ checkId }) => checkId),
      SYSTEM_CHECK_IDS,
    );
    assert.ok(
      report.results.every(
        ({ purpose, status }) => purpose === "experiment" && status === "PASS",
      ),
    );
    assert.equal(report.decision, "BLOCKED");
    assert.equal(report.sourceClosure, "UNESTABLISHED");
    assert.equal(report.protectedAcceptance, "UNESTABLISHED");
    assert.equal(report.productionGO, "UNESTABLISHED");
  }
});

test("experiment preparation rejects substituted checkout, run, SDK, tool, source, loader and held image bindings", () => {
  const { job } = fixture();
  for (const change of [
    (value) => {
      value.preparation.observed.binding.checkoutSha = "d".repeat(40);
    },
    (value) => {
      value.preparation.expected.binding.runAttempt =
        value.preparation.observed.binding.runAttempt = 2;
    },
    (value) => {
      value.preparation.observed.sdk.sha256 = OTHER;
    },
    (value) => {
      value.preparation.observed.tools[0].sha256 = OTHER;
    },
    (value) => {
      value.preparation.observed.sources[0].sha256 = OTHER;
    },
    (value) => {
      value.preparation.observed.components[0].sha256 = OTHER;
    },
    (value) => {
      value.preparation.observed.components[0].loader.push("undeclared");
    },
    (value) => {
      value.preparation.observed.components[0].identityAfter = OTHER;
    },
    (value) => {
      value.preparation.expected.components = [];
      value.preparation.observed.components = [];
    },
  ]) {
    const changed = structuredClone(job);
    change(changed);
    assert.throws(() => normalizeNativeJob(changed));
  }
});

test("missing recipes, uncertain retirement, policy substitution and failed controls cannot pass", () => {
  const job = complete("linux");
  assert.equal(
    renderNativeJob({ ...job, cases: job.cases.slice(0, -1) }).report.ciStatus,
    "BLOCKED",
  );
  for (const change of [
    (value) => {
      value.cases.at(-1).preparationSha256 = OTHER;
    },
    (value) => {
      value.cases.at(-1).components[0].identityAfter = OTHER;
    },
    (value) => {
      value.cases.at(-1).effects.helpers.settlement.emergencyCleanup = true;
    },
    (value) => {
      value.cases.at(-1).effects.helpers = effect("possible");
    },
    (value) => {
      value.cases.at(-1).policy.observedSha256 = OTHER;
    },
    (value) => {
      value.cases.at(-1).observations[0].observation.sentinelsUnchanged = false;
    },
    (value) => {
      value.cases.at(-1).observations[0].observation.observed = "different";
    },
    (value) => {
      value.cases.at(-1).effects.providers = effect("possible", true);
    },
  ]) {
    const changed = structuredClone(job);
    change(changed);
    assert.throws(() => normalizeNativeJob(changed));
  }
  const uncertain = structuredClone(job);
  uncertain.cases.at(-1).status = "FAIL";
  uncertain.cases.at(-1).effects.helpers = effect("possible");
  assert.equal(renderNativeJob(uncertain).report.ciStatus, "FAIL");
  assert.throws(() => recordExperimentCase(uncertain, job.cases.at(-1)));
  assert.equal(
    renderNativeJob({ ...job, preparationEffects: effect("possible") }).report
      .ciStatus,
    "FAIL",
  );
  const emergency = {
    ...job,
    preparationEffects: {
      ...effect("possible", true),
      settlement: {
        status: "RETIRED",
        independent: true,
        emergencyCleanup: true,
      },
    },
  };
  assert.equal(renderNativeJob(emergency).report.ciStatus, "FAIL");
  assert.throws(() =>
    recordExperimentPreparationEffect(emergency, effect("possible", true)),
  );
});

test("effects require prior intent and failed or settled cases cannot be overwritten", () => {
  const { job } = fixture();
  const finished = complete("linux");
  assert.throws(() => recordExperimentCase(job, finished.cases[0]));
  assert.throws(() => recordExperimentCase(finished, finished.cases.at(-1)));
  const interrupted = {
    ...job,
    cases: [
      {
        ...finished.cases[0],
        status: "FAIL",
        effects: { ...finished.cases[0].effects, helpers: effect("possible") },
      },
    ],
  };
  assert.throws(() => recordExperimentCase(interrupted, finished.cases[1]));
  assert.throws(() =>
    recordExperimentCase(interrupted, {
      ...interrupted.cases[0],
      observations: [],
    }),
  );
  const recovered = recordExperimentCase(
    { ...interrupted, failure: "probe-failed" },
    { ...interrupted.cases[0], effects: finished.cases[0].effects },
  );
  assert.equal(recovered.cases[0].effects.helpers.settlement.status, "RETIRED");
  assert.equal(recovered.failure, "probe-failed");
  assert.deepEqual(
    recovered.cases[0].observations,
    interrupted.cases[0].observations,
  );
  assert.equal(renderNativeJob(recovered).report.ciStatus, "FAIL");
  assert.throws(() =>
    recordExperimentPreparationEffect(
      initializeNativeJob(
        {
          candidateSha: C,
          platform: "linux",
          repository: "example/native",
          runId: "1",
          runAttempt: 1,
        },
        { schemaVersion: 7, purpose: "experiment" },
      ),
      effect("possible", true),
    ),
  );
});

test("experiment purpose and build observations cannot be promoted into reviewed or protected evidence", () => {
  const job = complete("linux"),
    report = renderNativeJob(job).report;
  for (const changed of [
    { ...job, purpose: "reviewed" },
    { ...job, schemaVersion: 6 },
    { ...job, reviews: {} },
  ])
    assert.throws(() => normalizeNativeJob(changed));
  assert.throws(() => normalizeNativeResult(report.results[0]));
  assert.throws(() => normalizeReleaseClosure(job.preparation.expected));
  assert.throws(() =>
    normalizeReviewAuthority(
      {
        candidateSha: C,
        platform: "linux",
        manifestSha256: observationDigest(job.preparation),
        authority: "experiment",
      },
      C,
      "linux",
    ),
  );
});
