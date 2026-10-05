import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import {
  aggregateNativeEvidence,
  CHECK_IDS,
  PLATFORMS,
  PROVIDER_CHECK_IDS,
  SOURCE_FINDING_IDS,
  initializeNativeJob,
  recordNativeStage,
  normalizeNativeJob,
  renderNativeJob,
  sourceReviewDigest,
  releaseClosureDigest,
  verifyReleaseClosure,
  observationDigest,
  beginCompositionExecution,
  recordCompositionEffect,
  finishCompositionExecution,
  runCompositionExecution,
  admitCompositionPlan,
  composeNativeRecords,
  NATIVE_EFFECT_CLASSES,
  normalizeNativeResult,
  resolveNativeDispatch,
  selectedSystemInventory,
  systemJobBounds,
  SYSTEM_CHECK_IDS,
  nativeArtifactName,
  selectNativeArtifacts,
  joinNativeArtifacts,
  normalizeNativePolicyTemplate,
  nativePolicyTemplateDigest,
  admitNativePolicyTemplate,
  materializeNativePolicy,
  verifyNativePolicy,
  nativePolicyContext,
  recordCompositionPolicy,
  NATIVE_GROUPS,
  nativePackageInput,
  CODEX_RELEASE_REFERENCE,
  nativePolicyLaunchData,
} from "./index.js";
import { joinAcceptanceArtifacts } from "./acceptance.js";
import {
  protectedProviderRecipes,
  runProtectedProviderProofs,
  admitProtectedProviderJob,
  admitProviderCIManifest,
  normalizeProviderSpec,
} from "./providers/index.js";
import {
  darwinSystemRecipes,
  assertDarwinLiteralObservation,
  darwinLaunchDigest,
  DARWIN_LITERAL_ARGUMENTS,
  runDarwinSystemProofs,
  darwinProviderLaunch,
} from "./darwin/index.js";
import { windowsSystemRecipes, runWindowsSystemProofs } from "./win32/index.js";
import {
  observeLinuxCandidateClosure,
  linuxSystemRecipes,
  runLinuxComposedSystemProofs,
} from "./linux/index.js";

const C = "a".repeat(40),
  H = "b".repeat(64);
const pass = { status: "PASS", elapsedMs: 1, deadlineMs: 120000, reason: null };
const retired = {
  status: "RETIRED",
  independent: true,
  emergencyCleanup: false,
};
const approval = (platform, manifestSha256) => ({
  candidateSha: C,
  platform,
  manifestSha256,
  authority: "operator-protected",
});
function reviewedSource() {
  const value = {
    schemaVersion: 2,
    candidateSha: C,
    inspected: SOURCE_FINDING_IDS.map((id) => ({
      id,
      kind: "implementation",
      url: `https://example.org/${C}/fixture.c`,
      revision: C,
      sha256: H,
      binding: "VERIFIED",
      complete: true,
      summary: "Synthetic source and API review.",
    })),
    findings: SOURCE_FINDING_IDS.map((id) => ({
      id,
      status: "CLOSED",
      sourceIds: [id],
    })),
    hypotheses: [],
    missingInputs: [],
    citations: SOURCE_FINDING_IDS.flatMap((id) =>
      ["reached-code", "api-contract"].map((kind) => ({
        findingId: id,
        sourceId: id,
        kind,
        member: "fixture.c",
        firstLine: 1,
        lastLine: 2,
        sha256: H,
      })),
    ),
  };
  return { value, authority: approval(null, sourceReviewDigest(value)) };
}
function release(platform = "darwin", template = null) {
  const manifest = {
    schemaVersion: template ? 2 : 1,
    candidateSha: C,
    platform,
    image: PLATFORMS.find(({ os }) => os === platform).image,
    osBuild: "synthetic",
    sdkBuild: "synthetic-sdk",
    ...(template
      ? { policyTemplates: [nativePolicyTemplateDigest(template)] }
      : { policySha256: H }),
    privileges: ["private-owner"],
    components: ["helper", "codex", "claude"].map((id) => ({
      id,
      role: id === "helper" ? "helper" : "executable",
      sha256: H,
      format: { linux: "elf-x64", darwin: "macho-x64", win32: "pe-x64" }[
        platform
      ],
      loader: [],
      bindings: Object.fromEntries(
        ["publication", "source", "build", "license", "abi"].map((key) => [
          key,
          H,
        ]),
      ),
    })),
    providers: Object.fromEntries(
      ["codex", "claude"].map((name) => [
        name,
        { reviewSha256: H, closureSha256: H, members: [name] },
      ]),
    ),
  };
  const observed = {
    ...structuredClone(manifest),
    independent: true,
    settlementSha256: H,
    components: manifest.components.map(({ role, ...item }) => ({
      ...item,
      identityBefore: H,
      identityAfter: H,
      held: true,
      independent: true,
    })),
    providers: Object.fromEntries(
      ["codex", "claude"].map((name) => [
        name,
        {
          ...manifest.providers[name],
          liveBindingSha256: H,
          independent: true,
        },
      ]),
    ),
  };
  return {
    manifest,
    observed,
    authority: approval(platform, releaseClosureDigest(manifest)),
  };
}
function preparedJob(platform = "darwin", tier = "system", template = null) {
  let job = initializeNativeJob(
    {
      candidateSha: C,
      platform,
      repository: "example/native",
      runId: template && tier === "provider" ? "2" : "1",
      runAttempt: 1,
    },
    { schemaVersion: 6, tier },
  );
  job = recordNativeStage(job, "setup", pass, {
    checkoutSha: C,
    observed: {
      os: platform,
      image: job.declaredImage,
      build: "synthetic",
      architecture: "x64",
    },
    provenance: {
      ...job.provenance,
      jobId: String(
        2 * PLATFORMS.findIndex(({ os }) => os === platform) +
          (tier === "system" ? 1 : 2),
      ),
    },
    versions: [{ name: "node", version: "v24.21.0", sha256: H }],
  });
  const source = reviewedSource(),
    rel = release(platform, template);
  job.reviews.source = source.authority;
  job.reviews.release = rel.authority;
  job.closure = {
    ...verifyReleaseClosure(rel.manifest, rel.observed, rel.authority),
    sourceReviewSha256: source.authority.manifestSha256,
  };
  return job;
}
function withPlan(job, recipes, template = null) {
  const manifest = {
    schemaVersion: template ? 2 : 1,
    candidateSha: C,
    platform: job.platform,
    tier: job.tier,
    sourceReviewSha256: job.reviews.source.manifestSha256,
    releaseReviewSha256: job.reviews.release.manifestSha256,
    ...(template
      ? {
          policyTemplates: [
            {
              template,
              approval: approval(
                job.platform,
                nativePolicyTemplateDigest(template),
              ),
            },
          ],
        }
      : {}),
    cases: recipes.map((recipe) => ({
      ...recipe,
      ...(template
        ? { templateSha256: nativePolicyTemplateDigest(template) }
        : { policySha256: H }),
      reviewSha256: H,
    })),
  };
  const authority = approval(job.platform, observationDigest(manifest));
  if (job.tier === "provider") job.reviews.provider = authority;
  if (template)
    assert.throws(() =>
      admitCompositionPlan(
        job,
        recipes,
        manifest,
        authority,
        reviewedSource().value,
      ),
    );
  admitCompositionPlan(
    job,
    recipes,
    manifest,
    authority,
    reviewedSource().value,
    template
      ? [
          Object.fromEntries(
            Object.entries(manifest.policyTemplates[0].approval).reverse(),
          ),
        ]
      : [],
  );
  job.plan = manifest;
  job.reviews.execution = authority;
  return normalizeNativeJob(job);
}
function syntheticRecipeJob() {
  const checkIds = CHECK_IDS.filter((id) => !PROVIDER_CHECK_IDS.includes(id));
  // Linux's reference record covers the existing engine; release is separate.
  const recipes = [
    {
      id: "reference",
      group: "reference",
      profile: "reference",
      checkIds: checkIds.filter((id) => id !== "audit.release"),
      deadlineMs: 120000,
    },
    {
      id: "release",
      group: "release",
      profile: "release",
      checkIds: ["audit.release"],
      deadlineMs: 120000,
    },
  ];
  return { job: withPlan(preparedJob("linux"), recipes), recipes };
}

test("literal evidence rejects unrelated process, cwd, image and argument bytes", () => {
  const request = {
    schemaVersion: 1,
    candidateSha: C,
    nonce: "c".repeat(32),
    uid: 90001,
    gid: 90002,
    custody: "/fixture/custody",
    storage: "/fixture/storage",
    workspace: "/fixture/storage/work",
    launcher: { path: "/fixture/custody/launcher", sha256: H },
    executable: { path: "/fixture/storage/argv", sha256: H, cdhash: C },
    policy: { path: "/fixture/custody/policy", sha256: H },
    bindings: { system: H, source: H, closure: H, policy: H },
  };
  const identity = (pid, uid, gid, asid) => ({
    pid,
    pidVersion: 1,
    asid,
    auid: uid,
    uid,
    gid,
    ruid: uid,
    rgid: gid,
    svuid: uid,
    svgid: gid,
    startSeconds: 100,
    startMicroseconds: 1,
  });
  const payload = identity(100, request.uid, request.gid, 99),
    verifier = identity(101, 0, 0, 0),
    requestSha256 = darwinLaunchDigest(request, DARWIN_LITERAL_ARGUMENTS);
  const record = {
    status: "ADMITTED",
    requestSha256,
    payload,
    authority: { cwd: { dev: "1", ino: "2" } },
    helpers: [{ role: "verifier", identity: verifier }],
  };
  const observed = {
    independent: true,
    verifier,
    requestSha256,
    payload,
    cwdIdentity: { dev: "1", ino: "2" },
    imageSha256: H,
    output: JSON.stringify(DARWIN_LITERAL_ARGUMENTS) + "\n",
    exitCode: 0,
    timedOut: false,
    complete: true,
    nativeEventSha256: H,
  };
  const check = (value) =>
    assertDarwinLiteralObservation(
      request,
      DARWIN_LITERAL_ARGUMENTS,
      record,
      value,
    );
  assert.equal(check(observed).status, "OBSERVED");
  for (const patch of [
    { output: observed.output + observed.output },
    { output: observed.output.replace('["",', "[") },
    { payload: { ...payload, pidVersion: 2 } },
    { verifier: { ...verifier, pid: 102 } },
    { cwdIdentity: { dev: "1", ino: "3" } },
    { imageSha256: "d".repeat(64) },
    { timedOut: true },
    { complete: false },
  ])
    assert.throws(() => check({ ...observed, ...patch }));
});

test("versioned dispatch preserves legacy jobs and provider selection supplies no authority", async () => {
  const context = {
      candidateSha: C,
      platform: "darwin",
      repository: "example/native",
      runId: "1",
      runAttempt: 1,
    },
    old = initializeNativeJob(context, { schemaVersion: 5 });
  assert.equal(normalizeNativeJob(old).schemaVersion, 5);
  assert.deepEqual(normalizeNativeJob(old).admissions, old.admissions);
  assert.equal(renderNativeJob(old).report.decision, "BLOCKED");
  const failedSetup = recordNativeStage(
    initializeNativeJob(context, { schemaVersion: 6 }),
    "setup",
    { ...pass, status: "FAIL", reason: "setup-failed" },
  );
  const failedReport = renderNativeJob(failedSetup).report;
  assert.equal(failedReport.decision, "NO_GO");
  assert.ok(
    failedReport.results.every(
      (result) =>
        result.status === "FAIL" &&
        result.admission === "not-started" &&
        result.phases.setup.status === "FAIL",
    ),
  );
  assert.equal(resolveNativeDispatch(["--tier", "provider"]).tier, "provider");
  let effects = 0;
  const job = preparedJob("darwin", "provider");
  assert.deepEqual(
    await runProtectedProviderProofs(job, {
      persist: async () => {
        effects++;
      },
    }),
    job,
  );
  assert.equal(effects, 0);
  for (const recipes of [darwinSystemRecipes(), windowsSystemRecipes()])
    assert.deepEqual(
      [...new Set(recipes.flatMap(({ checkIds }) => checkIds))].sort(),
      CHECK_IDS.filter((id) => !PROVIDER_CHECK_IDS.includes(id)).sort(),
    );
  assert.equal(protectedProviderRecipes("win32").length, 60);
});

test("source closure requires protected digest and both reached code and API citations", () => {
  const source = reviewedSource();
  const input = {
    candidateSha: C,
    source: source.value,
    sourceReview: source.authority,
    results: [],
    bindings: [],
  };
  assert.equal(
    aggregateNativeEvidence(input).issues.some(({ code }) => code === "SOURCE"),
    false,
  );
  for (const mutate of [
    (x) => {
      delete x.sourceReview;
    },
    (x) => {
      x.sourceReview.manifestSha256 = H;
    },
    (x) => {
      x.source.citations = x.source.citations.filter(
        ({ kind }) => kind !== "api-contract",
      );
      x.sourceReview.manifestSha256 = sourceReviewDigest(x.source);
    },
    (x) => {
      delete x.source.schemaVersion;
      delete x.source.citations;
    },
  ]) {
    const value = structuredClone(input);
    mutate(value);
    assert.ok(
      aggregateNativeEvidence(value).issues.some(
        ({ code }) => code === "SOURCE",
      ),
    );
  }
});

test("held identity, loader, build and both provider bindings cannot be substituted", () => {
  const rel = release();
  assert.equal(
    verifyReleaseClosure(rel.manifest, rel.observed, rel.authority)
      .manifestSha256,
    rel.authority.manifestSha256,
  );
  for (const mutate of [
    (x) => {
      x.components[0].identityAfter = "c".repeat(64);
    },
    (x) => {
      x.components[0].held = false;
    },
    (x) => {
      x.components[0].loader = ["unreviewed"];
    },
    (x) => {
      x.components[0].bindings.build = "c".repeat(64);
    },
    (x) => {
      x.providers.claude.closureSha256 = "c".repeat(64);
    },
    (x) => {
      x.policySha256 = "c".repeat(64);
    },
  ]) {
    const value = structuredClone(rel.observed);
    mutate(value);
    assert.throws(() =>
      verifyReleaseClosure(rel.manifest, value, rel.authority),
    );
  }
  assert.throws(() =>
    verifyReleaseClosure(rel.manifest, rel.observed, approval("darwin", H)),
  );
  const incomplete = structuredClone(rel.manifest);
  incomplete.components.find(({ id }) => id === "codex").loader = ["helper"];
  assert.throws(() => releaseClosureDigest(incomplete));
});

test("a failed package reader leaves no inspection running when held images close", async () => {
  const { manifest, observed } = release("linux"),
    image = Buffer.alloc(64);
  image.set([0x7f, 0x45, 0x4c, 0x46, 2, 1]);
  image.writeUInt16LE(2, 16);
  image.writeUInt16LE(62, 18);
  for (const component of manifest.components)
    component.sha256 = createHash("sha256").update(image).digest("hex");
  let activeReader = false,
    closedDuringRead = false,
    closed = 0,
    releaseReader,
    reader;
  const effects = {
    openHeld: async (id) => id,
    inspectHeld: async (id) => ({
      independent: true,
      held: true,
      reparse: false,
      regular: true,
      identity: `1:${manifest.components.findIndex((item) => item.id === id) + 1}`,
    }),
    readHeld: async () => image,
    loaderClosure: async () => ({
      independent: true,
      complete: true,
      ambiguous: false,
      nativeSha256: H,
      components: [],
    }),
    buildBindings: async () => ({
      independent: true,
      complete: true,
      bindings: manifest.components[0].bindings,
    }),
    observeAuthority: async () => ({
      ...manifest,
      independent: true,
      ownedChangesOnly: true,
    }),
    inspectProvider: async (name) => {
      if (name === "codex") throw new Error("Synthetic reader failure");
      activeReader = true;
      reader = new Promise((resolve) => {
        releaseReader = resolve;
      });
      try {
        await reader;
        return observed.providers[name];
      } finally {
        activeReader = false;
      }
    },
    closeHeld: async () => {
      closedDuringRead ||= activeReader;
      closed++;
    },
    verifyClosed: async () => ({
      independent: true,
      closed: true,
      nativeSha256: H,
    }),
  };
  try {
    await assert.rejects(
      observeLinuxCandidateClosure(
        manifest,
        approval("linux", releaseClosureDigest(manifest)),
        effects,
      ),
    );
  } finally {
    releaseReader?.();
    await reader;
  }
  assert.equal(closedDuringRead, false);
  assert.equal(closed, manifest.components.length);
});

test("write-ahead effects retain exclusion across a lost case and block another execution", () => {
  let { job } = syntheticRecipeJob();
  job = beginCompositionExecution(
    job,
    "reference",
    "reference",
    job.plan.cases[0].checkIds,
  );
  job = recordCompositionEffect(job, "reference", "helpers");
  assert.throws(() =>
    beginCompositionExecution(job, "release", "release", ["audit.release"]),
  );
  assert.throws(() => recordNativeStage(job, "cleanup", pass));
  assert.throws(() =>
    finishCompositionExecution(job, "reference", "PASS", H, 1, 1),
  );
  const result = renderNativeJob(job).report.results.find(
    ({ checkId }) => checkId === "launch.argv",
  );
  assert.equal(result.admission, "possible");
  assert.equal(result.status, "BLOCKED");
});

test("composition persists each effect before execution and independently settles before continuation", async () => {
  let { job, recipes } = syntheticRecipeJob();
  const writes = [],
    order = [];
  for (const recipe of recipes) {
    const classes =
      recipe.group === "reference"
        ? ["builds", "helpers", "policy"]
        : ["helpers"];
    const outcome = await runCompositionExecution(
      job,
      recipe,
      {
        execute: async ({ admit }) => {
          for (const id of classes) {
            await admit(id);
            assert.equal(
              writes.at(-1).executions.at(-1).effects[id].admission,
              "possible",
            );
            order.push(id);
          }
          return { status: "OBSERVED", evidenceSha256: H };
        },
        settle: async () =>
          Object.fromEntries(
            NATIVE_EFFECT_CLASSES.map((id) => [
              id,
              classes.includes(id)
                ? {
                    candidateSha: C,
                    executionId: recipe.id,
                    effectClass: id,
                    settlement: retired,
                    sha256: H,
                  }
                : null,
            ]),
          ),
      },
      { persist: async (value) => writes.push(value), now: () => 10 },
    );
    job = outcome.job;
    assert.ok(outcome.result);
  }
  const composed = composeNativeRecords(job, recipes);
  assert.equal(composed.results.length, 23);
  assert.ok(
    composed.results.every(
      ({ status, schemaVersion, effectsSha256 }) =>
        status === "PASS" &&
        schemaVersion === 3 &&
        /^[a-f0-9]{64}$/u.test(effectsSha256),
    ),
  );
  const broken = structuredClone(job);
  broken.executions.pop();
  assert.equal(
    composeNativeRecords(broken, recipes).results.find(
      ({ checkId }) => checkId === "audit.release",
    ).status,
    "BLOCKED",
  );
  assert.deepEqual(order, ["builds", "helpers", "policy", "helpers"]);
});

test("diagnostic failure preserves failure receipts and still independently settles effects", async () => {
  const { job, recipes } = syntheticRecipeJob(),
    classes = ["builds", "helpers", "policy"];
  for (const failedPhase of ["observed", "settlement", "complete"]) {
    const writes = [];
    let settled = false;
    const outcome = await runCompositionExecution(
      job,
      recipes[0],
      {
        execute: async ({ admit, diagnostic }) => {
          for (const name of classes) await admit(name);
          diagnostic("reference", "observed");
          return { status: "OBSERVED", evidenceSha256: H };
        },
        settle: async () => {
          settled = true;
          return Object.fromEntries(
            NATIVE_EFFECT_CLASSES.map((effectClass) => [
              effectClass,
              classes.includes(effectClass)
                ? {
                    candidateSha: C,
                    executionId: recipes[0].id,
                    effectClass,
                    settlement: retired,
                    sha256: H,
                  }
                : null,
            ]),
          );
        },
      },
      {
        persist: async (value) => writes.push(value),
        now: () => 1,
        diagnostic: ({ phase }) => {
          if (phase === failedPhase) throw new Error("Closed diagnostic pipe");
        },
      },
    );
    assert.equal(settled, true);
    assert.equal(outcome.result, null);
    assert.equal(writes.at(-1).executions[0].status, "FAIL");
    for (const name of classes)
      assert.equal(
        outcome.job.executions[0].effects[name].settlement.status,
        "RETIRED",
      );
    const report = renderNativeJob(outcome.job).report;
    assert.equal(report.decision, "NO_GO");
    const result = report.results.find(
      ({ checkId }) => checkId === "launch.argv",
    );
    assert.equal(result.status, "FAIL");
    assert.equal(result.phases.cleanup.status, "PASS");
  }
});

test("new PASS records require their independently bound composition and release review", async () => {
  const { job } = syntheticRecipeJob(),
    source = reviewedSource();
  const record = { ...job, results: [] };
  const raw = {
    ...renderNativeJob(record).report.results[0],
    status: "PASS",
    reason: null,
    admission: "possible",
    closure: job.closure,
    effectsSha256: H,
    policy: { id: "fixture", sha256: H },
    phases: { setup: pass, probe: pass, cleanup: pass },
    settlement: retired,
    observations: [
      {
        expected: "control",
        observed: "control",
        matched: true,
        positiveControl: true,
        attempted: true,
        sentinelsUnchanged: true,
      },
    ],
  };
  normalizeNativeResult(raw);
  const report = aggregateNativeEvidence({
    candidateSha: C,
    source: source.value,
    sourceReview: source.authority,
    results: [raw],
    bindings: [],
    releaseReviews: [job.reviews.release],
  });
  assert.equal(report.decision, "BLOCKED");
  assert.ok(report.issues.some(({ code }) => code === "INCONSISTENT"));
});

test("complete versioned aggregation rejects loss of independent review, receipt or package closure", () => {
  const source = reviewedSource(),
    results = [],
    bindings = [],
    compositions = [],
    releaseReviews = [],
    executionReviews = [];
  for (const { os } of PLATFORMS) {
    for (const tier of ["system", "provider"]) {
      let job = preparedJob(os, tier);
      const recipes =
        tier === "provider"
          ? protectedProviderRecipes(os)
          : os === "linux"
            ? linuxSystemRecipes()
            : os === "darwin"
              ? darwinSystemRecipes()
              : windowsSystemRecipes();
      job = withPlan(job, recipes);
      // Synthetic completed receipts only; never native observations or CI authority.
      job.executions = recipes.map((recipe) => ({
        id: recipe.id,
        group: recipe.group,
        checkIds: recipe.checkIds,
        status: "PASS",
        evidenceSha256: H,
        elapsedMs: 1,
        deadlineMs: recipe.deadlineMs,
        cleanupMs: 1,
        effects: Object.fromEntries(
          NATIVE_EFFECT_CLASSES.map((effectClass) => {
            const classes =
              recipe.group === "build"
                ? ["builds"]
                : recipe.group === "reference"
                  ? ["builds", "helpers", "policy"]
                  : ["access", "ownership"].includes(recipe.group)
                    ? ["helpers", "policy"]
                    : ["codex", "claude"].includes(recipe.group)
                      ? [
                          "helpers",
                          "policy",
                          "observers",
                          "transport",
                          "providers",
                        ]
                      : ["helpers"];
            return [
              effectClass,
              classes.includes(effectClass)
                ? {
                    admission: "possible",
                    settlement: retired,
                    receiptSha256: H,
                  }
                : {
                    admission: "not-started",
                    settlement: {
                      status: "RETAINED",
                      independent: false,
                      emergencyCleanup: false,
                    },
                    receiptSha256: null,
                  },
            ];
          }),
        ),
      }));
      job = composeNativeRecords(job, recipes);
      job = recordNativeStage(job, "probe", pass);
      job = recordNativeStage(job, "cleanup", pass);
      results.push(...job.results);
      compositions.push(job);
      bindings.push({
        artifactId: String(bindings.length + 1),
        candidateSha: C,
        platform: os,
        tier,
        provenance: job.provenance,
        conclusion: "success",
        authority: tier === "provider" ? "operator-protected" : "ordinary",
      });
      executionReviews.push({ tier, review: job.reviews.execution });
      if (tier === "system") releaseReviews.push(job.reviews.release);
    }
  }
  const input = {
    candidateSha: C,
    source: source.value,
    sourceReview: source.authority,
    results,
    bindings,
    compositions,
    releaseReviews,
    executionReviews,
  };
  const good = aggregateNativeEvidence(input);
  // The ordinary collector verifies every system job even when the full run
  // failed for absent protected evidence. It cannot import that run's failure
  // as native failure, or turn this labelled result into full acceptance.
  const context = {
    candidateSha: C,
    repository: "example/native",
    runId: "1",
    runAttempt: 1,
    workflowSha: C,
  };
  const run = {
    id: 1,
    run_attempt: 1,
    repository: { full_name: context.repository },
    path: ".github/workflows/native-poc.yml",
    event: "workflow_dispatch",
    head_sha: C,
    conclusion: "failure",
  };
  const systemJobs = compositions.filter(({ tier }) => tier === "system");
  const apiJobs = systemJobs.map((job) => ({
    id: Number(job.provenance.jobId),
    run_id: 1,
    run_attempt: 1,
    name: `native-system-${job.platform}`,
    status: "completed",
    conclusion: "success",
    started_at: "2026-01-01T00:00:00Z",
    completed_at: "2026-01-01T00:02:00Z",
    steps: [
      "Setup",
      "Probe complete system inventory",
      "Cleanup",
      "Report per-OS evidence",
      `Bind native artifact ${job.provenance.jobId}`,
    ].map((name) => ({ name, conclusion: "success" })),
  }));
  const artifacts = systemJobs.map((job) => ({
    id: Number(job.provenance.jobId),
    name: nativeArtifactName(context, job.platform),
    digest: `sha256:${H}`,
    expired: false,
    size_in_bytes: 1024,
    created_at: "2026-01-01T00:01:00Z",
    workflow_run: { id: 1, head_sha: C },
  }));
  const payloads = Object.fromEntries(
    systemJobs.map((job) => [nativeArtifactName(context, job.platform), job]),
  );
  const selection = selectNativeArtifacts(context, run, apiJobs, artifacts);
  const inventory = selectedSystemInventory(context, selection, payloads);
  assert.equal(inventory.status, "PASS");
  assert.equal(inventory.records, 69);
  assert.equal(inventory.fullAcceptance, false);
  assert.equal(inventory.scope, "system-inventory-only");
  // The protected collector supplies a distinct run and independently approved
  // digests. Complete synthetic records test the join, never native GO.
  const providerContext = { ...context, runId: "2" };
  const providerJobs = compositions
    .filter(({ tier }) => tier === "provider")
    .map((job) => {
      const value = structuredClone(job);
      value.provenance.runId = "2";
      for (const record of value.results) record.provenance.runId = "2";
      return normalizeNativeJob(value);
    });
  const providerEntries = providerJobs.map((job) => ({
    name: nativeArtifactName(providerContext, job.platform, "provider"),
    digest: `sha256:${H}`,
    stages: {
      setup: "success",
      probe: "success",
      cleanup: "success",
      report: "success",
    },
    binding: {
      artifactId: job.provenance.jobId,
      candidateSha: C,
      platform: job.platform,
      tier: "provider",
      provenance: job.provenance,
      conclusion: "success",
      authority: "operator-protected",
    },
  }));
  const acceptance = {
    request: {
      ...providerContext,
      systemRunId: "1",
      systemRunAttempt: 1,
      sourceReviewSha256: source.authority.manifestSha256,
    },
    systemContext: context,
    providerContext,
    system: selection,
    provider: {
      entries: providerEntries,
      issues: [],
      jobs: providerEntries.map(({ binding, stages }) => ({
        platform: binding.platform,
        jobId: binding.provenance.jobId,
        artifactId: binding.artifactId,
        conclusion: "success",
        stages,
      })),
    },
  };
  const allPayloads = {
    ...payloads,
    ...Object.fromEntries(
      providerJobs.map((job) => [
        nativeArtifactName(providerContext, job.platform, "provider"),
        job,
      ]),
    ),
  };
  const approved = systemJobs.map((job) => ({
    platform: job.platform,
    system: job.reviews.execution,
    release: job.reviews.release,
    provider: providerJobs.find((value) => value.platform === job.platform)
      .reviews.provider,
  }));
  const collected = joinAcceptanceArtifacts(
    acceptance,
    allPayloads,
    source.value,
    approved,
  ).report;
  assert.equal(collected.decision, "GO");
  assert.equal(collected.results.length, 87);
  assert.equal(collected.source.findings.length, 4);
  const recovered = admitProtectedProviderJob(
    providerJobs[0],
    systemJobs[0],
    selection.entries[0].binding,
    {
      source: source.authority,
      release: approved[0].release,
      provider: approved[0].provider,
    },
  );
  assert.deepEqual(recovered, providerJobs[0]);
  assert.throws(() =>
    admitProtectedProviderJob(
      providerJobs[0],
      systemJobs[0],
      selection.entries[0].binding,
      {
        source: source.authority,
        release: approved[0].release,
        provider: { ...approved[0].provider, manifestSha256: H },
      },
    ),
  );
  for (const mutate of [
    (v) => {
      v.approved[0].provider.manifestSha256 = H;
    },
    (v) => {
      v.approved[0].system.manifestSha256 = H;
    },
    (v) => {
      v.acceptance.request.sourceReviewSha256 = H;
    },
    (v) => {
      delete v.payloads[providerEntries[0].name];
    },
    (v) => {
      v.payloads[providerEntries[0].name].executions.pop();
    },
    (v) => {
      v.payloads[providerEntries[0].name].closure.observationSha256 =
        "c".repeat(64);
    },
    (v) => {
      v.payloads[providerEntries[0].name].checkoutSha = "c".repeat(40);
    },
  ]) {
    const value = structuredClone({
      acceptance,
      payloads: allPayloads,
      approved,
    });
    mutate(value);
    let decision = "BLOCKED";
    try {
      decision = joinAcceptanceArtifacts(
        value.acceptance,
        value.payloads,
        source.value,
        value.approved,
      ).report.decision;
    } catch {
      /* Invalid joins remain non-GO. */
    }
    assert.notEqual(decision, "GO");
  }
  assert.notEqual(
    joinNativeArtifacts(context, selection, payloads).report.decision,
    "GO",
  );
  for (const mutate of [
    ({ jobs }) => {
      jobs[0].conclusion = "failure";
    },
    ({ jobs }) => {
      jobs[1].steps[1].conclusion = "skipped";
    },
    ({ jobs }) => {
      jobs[2].steps.pop();
    },
    ({ artifacts }) => {
      artifacts[0].digest = null;
    },
    ({ artifacts }) => {
      artifacts[1].expired = true;
    },
    ({ payloads }) => {
      delete payloads[Object.keys(payloads)[0]];
    },
    ({ payloads }) => {
      Object.values(payloads)[0].results.pop();
    },
    ({ payloads }) => {
      Object.values(payloads)[1].executions[0].effects.builds.receiptSha256 =
        null;
    },
    ({ payloads }) => {
      const job = Object.values(payloads)[0];
      job.plan.cases.reverse();
      job.reviews.execution.manifestSha256 = observationDigest(job.plan);
    },
  ]) {
    const changed = structuredClone({ jobs: apiJobs, artifacts, payloads });
    mutate(changed);
    const selected = selectNativeArtifacts(
      context,
      run,
      changed.jobs,
      changed.artifacts,
    );
    assert.equal(
      selectedSystemInventory(context, selected, changed.payloads).status,
      "BLOCKED",
    );
  }
  assert.ok(
    input.results
      .filter(({ checkId }) => checkId === "provider.transport")
      .every(
        ({ platform, policy }) =>
          policy.id === `${platform}-transport-composition-v1`,
      ),
  );
  assert.equal(
    good.decision,
    "GO",
    JSON.stringify(
      good.issues.map(({ code, platform, checkId }) => ({
        code,
        platform,
        checkId,
      })),
    ),
  );
  for (const mutate of [
    (x) => {
      x.executionReviews.pop();
    },
    (x) => {
      x.releaseReviews[0].manifestSha256 = H;
    },
    (x) => {
      x.compositions[0].executions[0].effects.helpers.receiptSha256 = null;
    },
    (x) => {
      x.results[0].closure.providerBindings.claude = "c".repeat(64);
    },
    ...["observationSha256", "providerBindings"].map((key) => (x) => {
      const job = x.compositions.find(
        ({ platform, tier }) => platform === "darwin" && tier === "provider",
      );
      if (key === "providerBindings")
        job.closure.providerBindings.claude = "c".repeat(64);
      else job.closure[key] = "c".repeat(64);
      for (const result of [...job.results, ...x.results])
        if (result.platform === "darwin" && result.tier === "provider")
          result.closure = structuredClone(job.closure);
    }),
    (x) => {
      x.compositions.pop();
    },
    (x) => {
      x.compositions.find(
        ({ platform, tier }) => platform === "darwin" && tier === "system",
      ).executions[0].status = "FAIL";
    },
    (x) => {
      const ownership = x.compositions
        .find(({ platform, tier }) => platform === "win32" && tier === "system")
        .executions.find(({ group }) => group === "ownership");
      ownership.effects.policy = {
        admission: "not-started",
        settlement: {
          status: "RETAINED",
          independent: false,
          emergencyCleanup: false,
        },
        receiptSha256: null,
      };
    },
  ]) {
    const value = structuredClone(input);
    mutate(value);
    assert.equal(aggregateNativeEvidence(value).decision, "BLOCKED");
  }
});

test("system deadlines include every fixed case and its separate settlement", () => {
  for (const [platform, recipes] of [
    ["linux", linuxSystemRecipes()],
    ["darwin", darwinSystemRecipes()],
    ["win32", windowsSystemRecipes()],
  ]) {
    assert.deepEqual(
      [...new Set(recipes.flatMap(({ checkIds }) => checkIds))].sort(),
      [...SYSTEM_CHECK_IDS].sort(),
    );
    const bounds = systemJobBounds(platform);
    assert.equal(
      bounds.probeMs,
      5 * 30000 +
        recipes.reduce((sum, recipe) => sum + recipe.deadlineMs + 60000, 0),
    );
    assert.ok(bounds.preparationMinutes * 60000 > bounds.preparationMs);
    assert.ok(bounds.probeMinutes * 60000 > bounds.probeMs);
    assert.ok(
      bounds.jobMinutes >
        bounds.preparationMinutes + bounds.probeMinutes + bounds.cleanupMinutes,
    );
  }
  assert.throws(() => systemJobBounds("darwin", 5));
});

test("a timed-out pending controller cannot settle its ledger or admit late effects", async () => {
  const { job, recipes } = syntheticRecipeJob();
  const rejectedCalls = [];
  await assert.rejects(
    runCompositionExecution(
      job,
      { ...recipes[0], deadlineMs: recipes[0].deadlineMs + 1 },
      {
        execute: async () => {
          rejectedCalls.push("execute");
        },
        settle: async () => {
          rejectedCalls.push("settle");
        },
      },
      {
        persist: async () => {
          rejectedCalls.push("persist");
        },
      },
    ),
  );
  assert.deepEqual(rejectedCalls, []);
  const callbacks = new Map();
  let counter = 0,
    release,
    lateAdmission;
  const pending = new Promise((resolve) => {
    release = resolve;
  });
  const result = await runCompositionExecution(
    job,
    recipes[0],
    {
      execute: async ({ admit }) => {
        await admit("helpers");
        callbacks.get(1)();
        await pending;
        lateAdmission = admit("policy");
        await assert.rejects(lateAdmission);
        return { status: "OBSERVED", evidenceSha256: H };
      },
      settle: async () =>
        Object.fromEntries(
          NATIVE_EFFECT_CLASSES.map((effectClass) => [
            effectClass,
            effectClass === "helpers"
              ? {
                  candidateSha: C,
                  executionId: recipes[0].id,
                  effectClass,
                  settlement: retired,
                  sha256: H,
                }
              : null,
          ]),
        ),
    },
    {
      persist: async () => {},
      now: () => 1,
      schedule: (callback) => {
        const id = ++counter;
        callbacks.set(id, callback);
        return id;
      },
      cancel: (id) => callbacks.delete(id),
    },
  );
  assert.equal(result.result, null);
  assert.equal(result.job.executions[0].status, "FAIL");
  assert.equal(
    result.job.executions[0].effects.helpers.settlement.status,
    "RETAINED",
  );
  const failedReport = renderNativeJob(result.job).report;
  assert.equal(failedReport.decision, "NO_GO");
  assert.equal(
    failedReport.results.find(({ checkId }) => checkId === "launch.argv").phases
      .cleanup.reason,
    "unretired",
  );
  release();
  await pending;
  await lateAdmission?.catch(() => {});
  assert.throws(() =>
    beginCompositionExecution(result.job, "release", "release", [
      "audit.release",
    ]),
  );
});

test("provider review admission parses Windows paths portably and rejects unapproved or aliased inputs", () => {
  const source = reviewedSource();
  for (const citation of source.value.citations)
    citation.member = "provider-effects.mjs";
  const sourceSha256 = sourceReviewDigest(source.value);
  const job = preparedJob("win32", "provider");
  job.reviews.source = approval(null, sourceSha256);
  job.closure.sourceReviewSha256 = sourceSha256;
  const execution = {
    schemaVersion: 1,
    candidateSha: C,
    platform: "win32",
    tier: "provider",
    sourceReviewSha256: sourceSha256,
    releaseReviewSha256: job.reviews.release.manifestSha256,
    cases: protectedProviderRecipes("win32").map((recipe) => ({
      ...recipe,
      policySha256: H,
      reviewSha256: H,
    })),
  };
  const manifest = {
    schemaVersion: 1,
    candidateSha: C,
    platform: "win32",
    source: source.value,
    release: release("win32").manifest,
    execution,
    capabilitySha256: H,
    helpers: [],
    inputs: [
      { id: "codex", path: "C:\\synthetic\\package.exe", sha256: H, bytes: 1 },
    ],
  };
  assert.doesNotThrow(() =>
    admitProviderCIManifest(
      job,
      manifest,
      observationDigest(manifest),
      sourceSha256,
    ),
  );
  assert.throws(() => admitProviderCIManifest(job, manifest, H, sourceSha256));
  assert.throws(() =>
    admitProviderCIManifest(job, manifest, observationDigest(manifest), H),
  );
  for (const path of [
    "/synthetic/package.exe",
    "C:\\synthetic\\package.exe:stream",
    "\\\\server\\share\\package.exe",
    "C:\\synthetic\\..\\package.exe",
  ]) {
    const value = structuredClone(manifest);
    value.inputs[0].path = path;
    assert.throws(() =>
      admitProviderCIManifest(
        job,
        value,
        observationDigest(value),
        sourceSha256,
      ),
    );
  }
});

const K = "c".repeat(64);
function template(platform = "win32") {
  return normalizeNativePolicyTemplate({
    schemaVersion: 1,
    candidateSha: C,
    platform,
    sourceReviewSha256: reviewedSource().authority.manifestSha256,
    provisioningReviewSha256: H,
    policy: {
      principal: { accountSid: { binding: "account" } },
      command: ["fixture", "literal"],
      authority: ["private-workspace"],
      toolSha256: H,
      endpoint: {
        address: "127.0.0.1",
        owned: true,
        port: { binding: "endpoint" },
      },
    },
    bindings: [
      {
        id: "account",
        kind: "sid",
        paths: [["principal", "accountSid"]],
        minimum: null,
        maximum: null,
      },
      {
        id: "endpoint",
        kind: "loopback-port",
        paths: [["endpoint", "port"]],
        minimum: 20000,
        maximum: 30000,
      },
    ],
  });
}
function policyEvidence(
  value = template(),
  context = {
    candidateSha: C,
    platform: value.platform,
    tier: "system",
    runId: "1",
    runAttempt: 1,
    jobBindingSha256: H,
    executionId: "fixture",
    closureSha256: H,
    selectedSystemSha256: null,
  },
  rid = 1001,
) {
  const reviewed = approval(value.platform, nativePolicyTemplateDigest(value));
  const provisioning = {
    schemaVersion: 1,
    context,
    authoritySha256: H,
    bindings: [
      { id: "account", kind: "sid", value: `S-1-5-21-1-2-3-${rid}` },
      { id: "endpoint", kind: "loopback-port", value: 24000 },
    ],
    held: true,
    independent: true,
    verifierSha256: H,
    nativeEventSha256: H,
  };
  const expected = materializeNativePolicy(
    value,
    reviewed,
    provisioning,
    context,
  );
  const observed = {
    schemaVersion: 1,
    context,
    templateSha256: expected.templateSha256,
    provisioningSha256: expected.provisioningSha256,
    requestSha256: K,
    policySha256: expected.expectedPolicySha256,
    policy: expected.policy,
    held: true,
    complete: true,
    independent: true,
    verifierSha256: K,
    nativeEventSha256: K,
  };
  return {
    value,
    reviewed,
    provisioning,
    context,
    expected,
    observed,
    receipt: verifyNativePolicy(
      value,
      reviewed,
      provisioning,
      context,
      K,
      observed,
    ),
  };
}
const verify = (f) =>
  verifyNativePolicy(
    f.value,
    f.reviewed,
    f.provisioning,
    f.context,
    K,
    f.observed,
  );

test("platform preparation receives approved bindings and persists policy proof before dependent cases", async () => {
  for (const platform of ["linux", "darwin", "win32"]) {
    let policy = template(platform);
    policy.policy = {
      launch: { request: {}, arguments: ["fixed"] },
      policy: policy.policy,
    };
    for (const rule of policy.bindings)
      rule.paths = rule.paths.map((path) => ["policy", ...path]);
    policy = normalizeNativePolicyTemplate(policy);
    const recipes =
      platform === "linux"
        ? linuxSystemRecipes()
        : platform === "darwin"
          ? darwinSystemRecipes()
          : windowsSystemRecipes();
    let job = withPlan(
        preparedJob(platform, "system", policy),
        recipes,
        policy,
      ),
      writes = [],
      called = false;
    const observe = async ({ policyBinding, recordPolicy }) => {
      called = true;
      assert.equal(job.executions.at(-1).effects.policy.admission, "possible");
      assert.equal(
        policyBinding.approval.manifestSha256,
        nativePolicyTemplateDigest(policy),
      );
      const evidence = policyEvidence(policy, policyBinding.context);
      await recordPolicy({
        provisioning: evidence.provisioning,
        requestSha256: K,
        observed: evidence.observed,
      });
      assert.deepEqual(
        writes.at(-1).executions.at(-1).policyReceipt,
        evidence.receipt,
      );
      return { status: "OBSERVED", independent: true, reviewSha256: H };
    };
    const options = {
      manifest: job.plan,
      authority: job.reviews.execution,
      sourceManifest: reviewedSource().value,
      releaseManifest: release(platform, policy).manifest,
      templateReviews: [approval(platform, nativePolicyTemplateDigest(policy))],
      persist: async (value) => {
        job = value;
        writes.push(value);
      },
      effects: {
        build: observe,
        literal: async () => {
          throw new Error("No native literal effects in this regression");
        },
        prepare: async (_, value) => {
          if (platform === "linux") await observe(value);
          throw new Error(
            "Dependent native cases are intentionally unavailable",
          );
        },
        settle: async () =>
          Object.fromEntries(
            NATIVE_EFFECT_CLASSES.map((effectClass) => [
              effectClass,
              job.executions.at(-1).effects[effectClass].admission ===
              "possible"
                ? {
                    candidateSha: C,
                    executionId: job.executions.at(-1).id,
                    effectClass,
                    settlement: retired,
                    sha256: H,
                  }
                : null,
            ]),
          ),
      },
    };
    const result =
      platform === "linux"
        ? await runLinuxComposedSystemProofs(job, "/fixture", options)
        : platform === "darwin"
          ? await runDarwinSystemProofs(job, options)
          : await runWindowsSystemProofs(job, options);
    assert.equal(called, true);
    assert.notEqual(result.executions[0].policyReceipt, null);
    assert.equal(
      result.executions[0].status,
      platform === "linux" ? "FAIL" : "PASS",
    );
    assert.equal(result.executions.at(-1).status, "FAIL");
  }
});

test("protected provider dispatch withholds relay effects when native policy prerequisites are missing", async () => {
  const input = nativePackageInput("codex-darwin"),
    reference = {
      url: "https://example.org/review",
      revision: null,
      sha256: H,
    };
  const spec = normalizeProviderSpec({
    candidateSha: C,
    nonce: "c".repeat(32),
    provider: "codex",
    platform: "darwin",
    profile: "read-only",
    review: {
      schemaVersion: 1,
      candidateSha: C,
      packageId: input.id,
      archiveBytes: input.bytes,
      bindings: Object.fromEntries(
        [
          "publication",
          "source",
          "build",
          "dependencies",
          "license",
          "abi",
          "transport",
          "extraction",
        ].map((key) => [
          key,
          key === "source"
            ? {
                ...reference,
                url: CODEX_RELEASE_REFERENCE.sourceUrl,
                revision: CODEX_RELEASE_REFERENCE.revision,
              }
            : reference,
        ]),
      ),
      files: [
        { path: input.entrypoint, bytes: 100, sha256: H, executable: true },
      ],
    },
    home: "/fixture/storage/home",
    cache: "/fixture/storage/cache",
    path: "/runtime/bin",
    endpoint: "http://127.0.0.1:24000",
    model: "fixture-model",
  });
  const launch = {
    schemaVersion: 1,
    candidateSha: C,
    nonce: spec.nonce,
    uid: 90001,
    gid: 90002,
    custody: "/fixture/custody",
    storage: "/fixture/storage",
    workspace: "/fixture/storage/work",
    launcher: { path: "/fixture/custody/launcher", sha256: H },
    executable: { path: "/fixture/storage/payload", sha256: H, cdhash: C },
    policy: { path: "/fixture/custody/policy", sha256: H },
    bindings: { system: H, source: H, closure: spec.closureSha256, policy: H },
  };
  const concrete = darwinProviderLaunch(spec, launch);
  const policy = normalizeNativePolicyTemplate({
    ...template("darwin"),
    policy: {
      launch: nativePolicyLaunchData(concrete.request, concrete.arguments),
      policy: {},
    },
    bindings: [],
  });
  const rel = release("darwin", policy);
  rel.manifest.providers.codex.reviewSha256 =
    rel.manifest.providers.codex.closureSha256 = spec.closureSha256;
  Object.assign(rel.observed.providers.codex, rel.manifest.providers.codex);
  rel.authority = approval("darwin", releaseClosureDigest(rel.manifest));
  let job = preparedJob("darwin", "provider", policy);
  job.reviews.release = rel.authority;
  job.closure = {
    ...verifyReleaseClosure(rel.manifest, rel.observed, rel.authority),
    sourceReviewSha256: job.reviews.source.manifestSha256,
  };
  job.selectedSystem = {
    schemaVersion: 1,
    jobSha256: H,
    binding: binding(preparedJob("darwin", "system", policy)),
    closure: structuredClone(job.closure),
  };
  job = withPlan(job, protectedProviderRecipes("darwin"), policy);
  let reviewed = false,
    relayEffects = 0;
  const unavailable = async () => {
    throw new Error("Unexpected native effect");
  };
  const relayPolicy = {
    provider: "codex",
    nonce: spec.nonce,
    model: spec.model,
    requests: 32,
    outputTokens: 10,
    budgetMicros: 100000,
    inputMicros: 1,
    outputMicros: 1,
    beta: [],
  };
  const result = await runProtectedProviderProofs(job, {
    manifest: job.plan,
    authority: job.reviews.provider,
    sourceManifest: reviewedSource().value,
    releaseManifest: rel.manifest,
    templateReviews: [approval("darwin", nativePolicyTemplateDigest(policy))],
    persist: async (value) => {
      job = value;
    },
    effects: {
      prepare: async () => ({
        independent: true,
        reviewSha256: H,
        templateSha256: nativePolicyTemplateDigest(policy),
        specification: spec,
        launch,
        relayPolicy,
        launchOptions: {
          platform: "darwin",
          architecture: "x64",
          uid: 0,
          now: () => 0,
          env: { CI: "true", GITHUB_ACTIONS: "true", ImageOS: "macos15" },
        },
        launchEffects: {
          persist: async () => {},
          verifyInputs: async () => {
            reviewed = true;
            return { missingInputs: ["native-policy-provisioning"] };
          },
          ...Object.fromEntries(
            [
              "inspect",
              "verifyAuthority",
              "verifyReceipt",
              "retire",
              "readProvisioning",
              "readPolicy",
            ].map((key) => [key, unavailable]),
          ),
        },
        effects: {
          persist: async () => {},
          review: async ({ configurationSha256 }) => ({
            independent: true,
            candidateSha: C,
            nonce: spec.nonce,
            configurationSha256,
            status: "MATCHED",
            packageSha256: spec.closureSha256,
          }),
          admitTransport: async () => {
            relayEffects++;
            return unavailable();
          },
          ...Object.fromEntries(
            [
              "inspect",
              "observe",
              "modelReceipts",
              "verifyTransport",
              "controls",
              "closeTransport",
              "retire",
              "verifySettlement",
            ].map((key) => [key, unavailable]),
          ),
        },
      }),
      settle: async (recipe) =>
        Object.fromEntries(
          NATIVE_EFFECT_CLASSES.map((id) => [
            id,
            job.executions.at(-1).effects[id].admission === "possible"
              ? {
                  candidateSha: C,
                  executionId: recipe.id,
                  effectClass: id,
                  settlement: retired,
                  sha256: H,
                }
              : null,
          ]),
        ),
    },
  });
  assert.equal(reviewed, true);
  assert.equal(relayEffects, 0);
  const execution = result.executions[0];
  assert.equal(execution.status, "FAIL");
  assert.equal(execution.policyReceipt, null);
  assert.equal(execution.effects.transport.admission, "not-started");
  assert.equal(execution.effects.providers.admission, "not-started");
});

test("approved templates bind fresh provisioning and independent complete concrete-policy reads", () => {
  const first = policyEvidence(),
    second = policyEvidence(template(), undefined, 1002);
  assert.equal(first.receipt.templateSha256, second.receipt.templateSha256);
  assert.notEqual(
    first.receipt.expectedPolicySha256,
    second.receipt.expectedPolicySha256,
  );
  assert.notEqual(
    first.receipt.provisioningSha256,
    second.receipt.provisioningSha256,
  );
  assert.notEqual(
    first.receipt.observationSha256,
    second.receipt.observationSha256,
  );
  assert.notEqual(
    first.receipt.templateReviewSha256,
    first.receipt.requestSha256,
  );
  const reordered = structuredClone(first);
  reordered.observed.context = Object.fromEntries(
    Object.entries(reordered.observed.context).reverse(),
  );
  assert.doesNotThrow(() => verify(reordered));
  assert.equal(
    first.expected.policy.principal.accountSid,
    "S-1-5-21-1-2-3-1001",
  );
  assert.deepEqual(first.expected.policy.command, ["fixture", "literal"]);
  assert.ok(!JSON.stringify(first.receipt).includes("S-1-5-21"));
  assert.ok(!JSON.stringify(first.receipt).includes("private-workspace"));
  for (const [kind, field, identity] of [
    ["uid", "uid", 65537],
    ["gid", "gid", 65538],
    ["session", "auditSessionId", 0],
    ["custody", "nonce", "d".repeat(32)],
  ]) {
    const value = template("darwin"),
      provisioning = structuredClone(first.provisioning);
    value.policy.principal = { [field]: { binding: "account" } };
    value.bindings[0] = {
      id: "account",
      kind,
      paths: [["principal", field]],
      minimum: kind === "custody" ? null : kind === "session" ? 0 : 65536,
      maximum: kind === "custody" ? null : 65599,
    };
    provisioning.context.platform = "darwin";
    provisioning.bindings[0] = { id: "account", kind, value: identity };
    const reviewed = approval("darwin", nativePolicyTemplateDigest(value));
    assert.equal(
      materializeNativePolicy(
        value,
        reviewed,
        provisioning,
        provisioning.context,
      ).policy.principal[field],
      identity,
    );
    provisioning.bindings[0].value =
      kind === "custody" ? "/fixture/custody" : -1;
    assert.throws(() =>
      materializeNativePolicy(
        value,
        reviewed,
        provisioning,
        provisioning.context,
      ),
    );
  }
  const extra = structuredClone(first.observed);
  extra.raw = "synthetic-secret";
  assert.throws(
    () =>
      verifyNativePolicy(
        first.value,
        first.reviewed,
        first.provisioning,
        first.context,
        K,
        extra,
      ),
    (error) => !error.message.includes("synthetic-secret"),
  );
});

test("template admission rejects authority interpolation, unowned endpoints and invented approvals", () => {
  for (const alter of [
    (v) => {
      v.bindings[0].paths = [["command", 0]];
    },
    (v) => {
      v.bindings[1].paths = [["toolSha256"]];
    },
    (v) => {
      v.policy.endpoint.address = "192.0.2.1";
    },
    (v) => {
      v.policy.endpoint.owned = false;
    },
    (v) => {
      v.policy.other = { binding: "undeclared" };
    },
    (v) => {
      v.bindings.push(v.bindings[0]);
    },
  ]) {
    const value = template();
    alter(value);
    assert.throws(() => normalizeNativePolicyTemplate(value));
  }
  assert.throws(() =>
    admitNativePolicyTemplate(template(), approval("win32", K)),
  );
  assert.throws(() =>
    admitNativePolicyTemplate(template(), {
      ...approval("win32", nativePolicyTemplateDigest(template())),
      authority: "ordinary",
    }),
  );
});

test("concrete admission rejects substitutions, unexpected identities and missing independent evidence", () => {
  for (const alter of [
    (f) => {
      f.provisioning.bindings[0].value = "S-1-5-18";
    },
    (f) => {
      f.provisioning.bindings.push({
        id: "extra",
        kind: "sid",
        value: "S-1-5-21-1-2-3-1002",
      });
    },
    (f) => {
      f.provisioning.bindings[1].value = 80;
    },
    (f) => {
      f.provisioning.authoritySha256 = K;
    },
    (f) => {
      f.provisioning.independent = false;
    },
    (f) => {
      f.observed.policy.authority.push("outside-workspace");
    },
    (f) => {
      f.observed.policy.principal.accountSid = "S-1-5-21-1-2-3-1002";
    },
    (f) => {
      f.observed.requestSha256 = H;
    },
    (f) => {
      f.observed.policySha256 = f.receipt.templateSha256;
    },
    (f) => {
      f.observed.context = { ...f.context, runAttempt: 2 };
    },
    (f) => {
      f.observed.held = false;
    },
    (f) => {
      f.observed.complete = false;
    },
    (f) => {
      f.observed.independent = false;
    },
    (f) => {
      delete f.observed.nativeEventSha256;
    },
    (f) => {
      f.observed = null;
    },
  ]) {
    const fixture = policyEvidence();
    alter(fixture);
    assert.throws(() => verify(fixture));
  }
});

const classes = (platform, recipe) => [
  ...new Set([
    ...(recipe.group === "build"
      ? ["builds"]
      : NATIVE_GROUPS[platform][recipe.group].effects),
    "policy",
  ]),
];
const binding = (job) => ({
  artifactId: job.provenance.jobId,
  candidateSha: C,
  platform: job.platform,
  tier: job.tier,
  provenance: job.provenance,
  conclusion: "success",
  authority: job.tier === "system" ? "ordinary" : "operator-protected",
});
function completed(job, policy) {
  job.executions = job.plan.cases.map((recipe) => ({
    schemaVersion: 2,
    policyReceipt: policyEvidence(policy, nativePolicyContext(job, recipe.id))
      .receipt,
    id: recipe.id,
    group: recipe.group,
    checkIds: recipe.checkIds,
    status: "PASS",
    evidenceSha256: H,
    elapsedMs: 1,
    deadlineMs: recipe.deadlineMs,
    cleanupMs: 1,
    effects: Object.fromEntries(
      NATIVE_EFFECT_CLASSES.map((id) => [
        id,
        classes(job.platform, recipe).includes(id)
          ? { admission: "possible", settlement: retired, receiptSha256: H }
          : {
              admission: "not-started",
              settlement: {
                status: "RETAINED",
                independent: false,
                emergencyCleanup: false,
              },
              receiptSha256: null,
            },
      ]),
    ),
  }));
  job = composeNativeRecords(job, job.plan.cases);
  job = recordNativeStage(job, "probe", pass);
  return recordNativeStage(job, "cleanup", pass);
}

test("versioned execution persists concrete policy before payload admission and rejects historical promotion", async () => {
  const policy = template("linux");
  const recipes = [
    {
      id: "reference",
      group: "reference",
      profile: "reference",
      checkIds: SYSTEM_CHECK_IDS.filter((id) => id !== "audit.release"),
      deadlineMs: 120000,
    },
    {
      id: "release",
      group: "release",
      profile: "release",
      checkIds: ["audit.release"],
      deadlineMs: 120000,
    },
  ];
  let job = withPlan(preparedJob("linux", "system", policy), recipes, policy);
  const writes = [],
    recipe = job.plan.cases[0];
  const receipt = policyEvidence(
    policy,
    nativePolicyContext(job, recipe.id),
  ).receipt;
  const outcome = await runCompositionExecution(
    job,
    recipe,
    {
      execute: async ({ admit, recordPolicy }) => {
        for (const id of classes(job.platform, recipe)) await admit(id);
        assert.throws(() =>
          finishCompositionExecution(writes.at(-1), recipe.id, "PASS", H, 1, 1),
        );
        await recordPolicy(receipt);
        assert.deepEqual(
          writes.at(-1).executions.at(-1).policyReceipt,
          receipt,
        );
        return { status: "OBSERVED", evidenceSha256: H };
      },
      settle: async () =>
        Object.fromEntries(
          NATIVE_EFFECT_CLASSES.map((id) => [
            id,
            classes(job.platform, recipe).includes(id)
              ? {
                  candidateSha: C,
                  executionId: recipe.id,
                  effectClass: id,
                  settlement: retired,
                  sha256: H,
                }
              : null,
          ]),
        ),
    },
    { persist: async (value) => writes.push(value), now: () => 1 },
  );
  assert.equal(outcome.job.executions[0].status, "PASS");
  job = beginCompositionExecution(
    job,
    recipe.id,
    recipe.group,
    recipe.checkIds,
  );
  job = recordCompositionEffect(job, recipe.id, "policy");
  for (const [field, value] of [
    ["repository", "example/other"],
    ["jobId", "99"],
  ]) {
    const other = { ...job, provenance: { ...job.provenance, [field]: value } };
    assert.throws(() => recordCompositionPolicy(other, recipe.id, receipt));
  }
  for (const key of [
    "candidateSha",
    "platform",
    "runId",
    "runAttempt",
    "jobBindingSha256",
    "executionId",
    "closureSha256",
  ]) {
    const bad = structuredClone(receipt);
    bad.context[key] =
      key === "runAttempt"
        ? 2
        : key === "platform"
          ? "win32"
          : key.endsWith("Sha")
            ? "d".repeat(40)
            : key.endsWith("Sha256")
              ? K
              : "other";
    assert.throws(() => recordCompositionPolicy(job, recipe.id, bad));
  }
  job = recordCompositionPolicy(job, recipe.id, receipt);
  assert.throws(() =>
    recordCompositionPolicy(job, recipe.id, {
      ...receipt,
      expectedPolicySha256: H,
    }),
  );
  const legacy = structuredClone(job);
  legacy.plan.schemaVersion = 1;
  delete legacy.plan.policyTemplates;
  for (const item of legacy.plan.cases) {
    item.policySha256 = item.templateSha256;
    delete item.templateSha256;
  }
  legacy.reviews.execution.manifestSha256 = observationDigest(legacy.plan);
  assert.throws(() => normalizeNativeJob(legacy));
  const missing = structuredClone(outcome.job);
  missing.executions[0].policyReceipt = null;
  assert.throws(() => normalizeNativeJob(missing));
});

test("template-backed full aggregation retains the complete independently selected system closure", () => {
  const jobs = [],
    bindings = [],
    releaseReviews = [],
    executionReviews = [];
  for (const { os } of PLATFORMS) {
    const policy = template(os),
      recipes = {
        linux: linuxSystemRecipes,
        darwin: darwinSystemRecipes,
        win32: windowsSystemRecipes,
      }[os]();
    const system = completed(
      withPlan(preparedJob(os, "system", policy), recipes, policy),
      policy,
    );
    const selected = binding(system),
      providerRecipes = protectedProviderRecipes(os);
    let provider = admitProtectedProviderJob(
      preparedJob(os, "provider", policy),
      system,
      selected,
      {
        source: system.reviews.source,
        release: system.reviews.release,
        provider: approval(os, H),
      },
    );
    assert.deepEqual(provider.selectedSystem.closure, system.closure);
    assert.equal(provider.selectedSystem.jobSha256, observationDigest(system));
    provider = completed(withPlan(provider, providerRecipes, policy), policy);
    const pending = beginCompositionExecution(
      withPlan(
        admitProtectedProviderJob(
          preparedJob(os, "provider", policy),
          system,
          selected,
          {
            source: system.reviews.source,
            release: system.reviews.release,
            provider: approval(os, H),
          },
        ),
        providerRecipes,
        policy,
      ),
      provider.plan.cases[0].id,
      "codex",
      provider.plan.cases[0].checkIds,
    );
    assert.throws(() =>
      recordCompositionEffect(pending, provider.plan.cases[0].id, "transport"),
    );
    assert.throws(() =>
      normalizeNativeJob({
        ...provider,
        selectedSystem: {
          ...provider.selectedSystem,
          closure: { ...system.closure, observationSha256: K },
        },
      }),
    );
    const replay = structuredClone(provider);
    replay.executions[0].policyReceipt.context.selectedSystemSha256 = H;
    assert.throws(() => normalizeNativeJob(replay));
    jobs.push(system, provider);
    bindings.push(selected, binding(provider));
    releaseReviews.push(system.reviews.release);
    executionReviews.push(
      ...[system, provider].map((job) => ({
        tier: job.tier,
        review: job.reviews.execution,
      })),
    );
  }
  const templateReviews = PLATFORMS.map(({ os }) =>
    approval(os, nativePolicyTemplateDigest(template(os))),
  );
  const input = {
    candidateSha: C,
    source: reviewedSource().value,
    sourceReview: reviewedSource().authority,
    results: jobs.flatMap((job) => job.results),
    compositions: jobs,
    bindings,
    releaseReviews,
    executionReviews,
    templateReviews,
  };
  const report = aggregateNativeEvidence(input);
  assert.equal(report.decision, "GO"); // Synthetic join regression, never native proof.
  const reordered = structuredClone(input);
  reordered.templateReviews = reordered.templateReviews.map((review) =>
    Object.fromEntries(Object.entries(review).reverse()),
  );
  reordered.results[0].closure = Object.fromEntries(
    Object.entries(reordered.results[0].closure).reverse(),
  );
  const providerSelection = reordered.compositions[1].selectedSystem;
  providerSelection.binding = Object.fromEntries(
    Object.entries(providerSelection.binding).reverse(),
  );
  providerSelection.closure = Object.fromEntries(
    Object.entries(providerSelection.closure).reverse(),
  );
  reordered.compositions[1].selectedSystem = Object.fromEntries(
    Object.entries(providerSelection).reverse(),
  );
  assert.equal(aggregateNativeEvidence(reordered).decision, "GO");
  assert.equal(report.results.length, 87);
  assert.equal(report.source.findings.length, 4);
  const changed = structuredClone(input);
  changed.bindings[0].artifactId = "99";
  assert.ok(
    aggregateNativeEvidence(changed).issues.some(
      ({ code }) => code === "PROVENANCE",
    ),
  );
  const alteredSystem = structuredClone(input);
  alteredSystem.compositions[0].versions.push({
    name: "fixture",
    version: "1",
    sha256: H,
  });
  for (const result of alteredSystem.compositions[0].results)
    result.versions = alteredSystem.compositions[0].versions;
  alteredSystem.results = alteredSystem.compositions.flatMap(
    (job) => job.results,
  );
  assert.ok(
    aggregateNativeEvidence(alteredSystem).issues.some(
      ({ code }) => code === "PROVENANCE",
    ),
  );
  assert.notEqual(
    aggregateNativeEvidence({ ...input, compositions: jobs.slice(1) }).decision,
    "GO",
  );
  assert.notEqual(
    aggregateNativeEvidence({ ...input, templateReviews: [] }).decision,
    "GO",
  );
});
