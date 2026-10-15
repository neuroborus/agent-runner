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
  nativeArtifactName,
  selectNativeArtifacts,
  joinNativeArtifacts,
  selectedSystemInventory,
} from "./index.js";
import { NATIVE_JOB_STEPS } from "./catalog.js";
import { normalizeNativeArtifactSelection } from "./dispatch.js";

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
function fixture(platform = "linux", jobId = "2") {
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
      jobId,
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

function complete(platform, jobId) {
  let { job, observed, inventory } = fixture(platform, jobId);
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

function artifacts() {
  const context = {
      candidateSha: C,
      repository: "example/native",
      runId: "1",
      runAttempt: 1,
      workflowSha: C,
    },
    stamp = (seconds) =>
      new Date(Date.UTC(2026, 0, 1, 0, 0, seconds)).toISOString(),
    now = Date.parse(stamp(90)),
    run = {
      id: 1,
      run_attempt: 1,
      repository: { full_name: context.repository },
      path: ".github/workflows/native-poc.yml",
      event: "pull_request",
      head_sha: C,
      run_started_at: stamp(0),
    },
    jobs = PLATFORMS.map(({ os }, index) => ({
      id: index + 2,
      name: `native-system-${os}`,
      run_id: 1,
      run_attempt: 1,
      status: "completed",
      conclusion: "success",
      started_at: stamp(1),
      completed_at: stamp(60),
      steps: [
        ...Object.values(NATIVE_JOB_STEPS[7]),
        ...(os === "linux"
          ? [
              "Prepare experiment Linux prerequisites and namespace policy",
              "Recover only settled owned Linux namespace policy",
            ]
          : []),
        `Bind native artifact ${index + 10}`,
      ].map((name) => ({
        name,
        conclusion: "success",
        started_at: stamp(name.startsWith("Bind") ? 40 : 2),
        completed_at: stamp(name.startsWith("Bind") ? 50 : 35),
      })),
    })),
    records = PLATFORMS.map(({ os }, index) => ({
      id: index + 10,
      name: nativeArtifactName(context, os),
      expired: false,
      size_in_bytes: 1000,
      digest: `sha256:${H}`,
      workflow_run: { id: 1, head_sha: C },
      created_at: stamp(30),
      expires_at: stamp(86400),
    })),
    payloads = Object.fromEntries(
      PLATFORMS.map(({ os }, index) => [
        nativeArtifactName(context, os),
        complete(os, String(index + 2)),
      ]),
    );
  return { context, run, jobs, records, payloads, now };
}

const select = (f) =>
  selectNativeArtifacts(
    f.context,
    f.run,
    f.jobs,
    f.records,
    "experiment",
    f.now,
  );

test("same-candidate experiment artifacts join all 69 checks without reviewed or production approval", () => {
  const f = artifacts(),
    selection = select(f),
    before = structuredClone(f.payloads),
    rendered = joinNativeArtifacts(f.context, selection, f.payloads),
    report = rendered.report;
  assert.equal(report.ciStatus, "PASS");
  assert.equal(report.experimentStatus, "PASS");
  assert.equal(report.systemInventory.records, 69);
  assert.equal(report.results.length, 69);
  assert.deepEqual(report.ciIssues, []);
  assert.ok(report.results.every((result) => result.status === "PASS"));
  assert.equal(report.decision, "BLOCKED");
  for (const key of ["sourceClosure", "protectedAcceptance", "productionGO"])
    assert.equal(report[key], "UNESTABLISHED");
  assert.deepEqual(f.payloads, before);
  const reordered = reverseKeys(selection);
  reordered.entries.reverse();
  reordered.jobs.reverse();
  assert.deepEqual(
    joinNativeArtifacts(f.context, reordered, reverseKeys(f.payloads)),
    rendered,
  );
  assert.throws(() => normalizeNativeArtifactSelection(f.context, selection));
  assert.throws(() =>
    joinNativeArtifacts(f.context, selection, f.payloads, "provider"),
  );
  const reviewed = selectNativeArtifacts(f.context, f.run, f.jobs, f.records);
  assert.equal(
    selectedSystemInventory(f.context, reviewed, f.payloads).status,
    "BLOCKED",
  );
});

test("experiment joins reject substituted metadata, purpose and incomplete native or CI inventories", () => {
  const original = artifacts();
  const substitute = (f, key, value) => {
    const job = f.payloads[f.records[0].name];
    if (key !== "jobId") job[key] = value;
    for (const side of ["expected", "observed"]) {
      job.preparation[side].binding[key] = value;
      if (key === "candidateSha")
        job.preparation[side].binding.checkoutSha = value;
    }
    for (const entry of job.cases)
      entry.preparationSha256 = observationDigest(job.preparation);
    assert.doesNotThrow(() => normalizeNativeJob(job));
  };
  for (const change of [
    (f) => f.records.pop(),
    (f) => f.records.push(structuredClone(f.records[0])),
    (f) => {
      f.records[0].expired = true;
    },
    (f) => {
      f.records[0].digest = "sha256:invalid";
    },
    (f) => {
      f.records[0].expires_at = "2025-01-01T00:00:00Z";
    },
    (f) => {
      f.jobs[0].steps.at(-1).started_at = f.jobs[0].started_at;
    },
    (f) => {
      f.jobs[0].steps.at(-1).started_at = f.records[0].expires_at;
    },
    (f) => {
      f.jobs[0].steps.find(
        (step) => step.name === "Upload native evidence",
      ).started_at = f.run.run_started_at;
    },
    (f) => {
      f.jobs[0].steps.at(-1).conclusion = "skipped";
    },
    (f) => {
      f.jobs[0].steps.find(
        (step) => step.name === "Build and prepare experiment platform helpers",
      ).conclusion = "skipped";
    },
    (f) => {
      f.jobs[0].steps.find(
        (step) => step.name === "Probe complete system inventory",
      ).name = "Probe reporting harness";
    },
    (f) => {
      delete f.payloads[f.records[0].name];
    },
    (f) => {
      f.payloads[f.records[0].name].purpose = "reviewed";
    },
    (f) => substitute(f, "candidateSha", "d".repeat(40)),
    (f) => substitute(f, "repository", "other/native"),
    (f) => substitute(f, "runId", "2"),
    (f) => substitute(f, "runAttempt", 2),
    (f) => substitute(f, "jobId", "99"),
    (f) => {
      f.payloads[f.records[0].name].cases.pop();
    },
    (f) => {
      f.payloads[f.records[1].name] = f.payloads[f.records[0].name];
    },
  ]) {
    const f = structuredClone(original);
    change(f);
    const report = joinNativeArtifacts(f.context, select(f), f.payloads).report;
    assert.notEqual(report.ciStatus, "PASS");
    assert.notEqual(report.experimentStatus, "PASS");
    assert.equal(report.decision, "BLOCKED");
  }
});

test("experiment joining preserves native failure independently of later cleanup and failed CI steps", () => {
  const f = artifacts(),
    name = f.records[0].name,
    job = f.payloads[name];
  job.failure = "probe-failed";
  job.cases.at(-1).status = "FAIL";
  job.cases.at(-1).effects.helpers = effect("possible");
  f.jobs[0].conclusion = "failure";
  f.jobs[0].steps.find((step) => step.name === "Cleanup").conclusion =
    "failure";
  const report = joinNativeArtifacts(f.context, select(f), f.payloads).report;
  assert.equal(report.ciStatus, "FAIL");
  assert.equal(report.platforms[0].failure, "probe-failed");
  assert.equal(report.platforms[0].cleanupStatus, "FAIL");
  job.cases.at(-1).effects.helpers = effect("possible", true);
  const recovered = joinNativeArtifacts(
    f.context,
    select(f),
    f.payloads,
  ).report;
  assert.equal(recovered.platforms[0].cleanupStatus, "PASS");
  assert.equal(recovered.platforms[0].failure, "probe-failed");
  assert.equal(recovered.experimentStatus, "FAIL");
  const missing = initializeNativeJob(
    {
      candidateSha: C,
      platform: "linux",
      repository: "example/native",
      runId: "1",
      runAttempt: 1,
    },
    { schemaVersion: 7, purpose: "experiment" },
  );
  f.payloads[name] = { ...missing, failure: "preparation-failed" };
  const early = joinNativeArtifacts(f.context, select(f), f.payloads).report;
  assert.equal(early.platforms[0].failure, "preparation-failed");
  assert.equal(early.platforms[0].cleanupStatus, "BLOCKED");
  assert.ok(!early.ciIssues.some((issue) => issue.code === "payload"));
});

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
