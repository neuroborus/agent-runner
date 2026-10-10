import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import path from "node:path";
import test from "node:test";
import {
  initializeNativeJob,
  normalizeNativeJob,
  nativeCleanupFailure,
  renderNativeJob,
  aggregateNativeEvidence,
} from "./index.js";
import {
  assertNativePreparationInputs,
  captureNativeFirstFailure,
  nativeFailureDetails,
  nativePreparationError,
  nativeJobHasPossibleEffects,
  normalizeNativeFirstFailure,
  persistNativeFirstFailure,
  rejoinNativeFirstFailure,
  loadNativeFirstFailure,
  renderNativeFailures,
} from "./first-failure.js";
import { acquireSystemCIInputs } from "./system-ci.js";
import { observationDigest } from "./observation.js";

const job = (platform = "linux", tier = "system") =>
  initializeNativeJob(
    {
      candidateSha: "a".repeat(40),
      platform,
      repository: "example/native",
      runId: "1",
      runAttempt: 1,
    },
    { schemaVersion: 6, tier },
  );
const env = {
  CI: "true",
  GITHUB_ACTIONS: "true",
  RUNNER_TEMP: path.resolve("/synthetic/temp"),
  NATIVE_SYSTEM_INPUT_REPOSITORY: "example/reviews",
  NATIVE_SYSTEM_INPUT_REVISION: "b".repeat(40),
  NATIVE_SYSTEM_REVIEW_SHA256: "c".repeat(64),
  NATIVE_LINUX_REVIEW_SHA256: "d".repeat(64),
};
const inputIds = [
  "NATIVE_SYSTEM_INPUT_REPOSITORY",
  "NATIVE_SYSTEM_INPUT_REVISION",
  "NATIVE_SYSTEM_REVIEW_SHA256",
  "NATIVE_LINUX_REVIEW_SHA256",
];
function rejectedInputs(candidate, values) {
  try {
    assertNativePreparationInputs(candidate, values);
  } catch (error) {
    return nativeFailureDetails(error);
  }
  assert.fail("Malformed prerequisites must fail");
}

test("namespace policy refusal stays a Linux-only first preparation cause through later recovery failure", () => {
  const candidate = job(),
    details = nativeFailureDetails(nativePreparationError("namespace-policy"));
  const first = captureNativeFirstFailure(candidate, "prepare-linux", details);
  assert.equal(first.diagnosis, "namespace-policy");
  assert.equal(first.admission, "not-started");
  assert.deepEqual(
    captureNativeFirstFailure(
      { ...candidate, firstFailure: first },
      "cleanup",
      { diagnosis: "stage-failed", inputs: [] },
    ),
    first,
  );
  assert.throws(() =>
    captureNativeFirstFailure(job("darwin"), "prepare", details),
  );
});

test("each empty or malformed prerequisite is identified before any acquisition", async () => {
  for (const platform of ["linux", "darwin", "win32"]) {
    const candidate = job(platform);
    const values = {
      ...env,
      ...Object.fromEntries(inputIds.map((id) => [id, ""])),
    };
    const expected = inputIds.filter(
      (id) => platform === "linux" || id !== "NATIVE_LINUX_REVIEW_SHA256",
    );
    assert.deepEqual(
      rejectedInputs(candidate, values).inputs,
      expected.map((id) => ({ id, diagnosis: "missing" })),
    );
    let effects = 0;
    await assert.rejects(
      acquireSystemCIInputs(
        candidate,
        {},
        path.join(env.RUNNER_TEMP, `native-${platform}-reviewed`),
        {
          env: values,
          fetchInput: async () => {
            effects++;
          },
          fs: {
            mkdir: async () => {
              effects++;
            },
            writeFile: async () => {
              effects++;
            },
          },
        },
      ),
    );
    assert.equal(effects, 0);
    for (const id of expected)
      assert.deepEqual(
        rejectedInputs(candidate, {
          ...env,
          [id]: "invalid private-data /synthetic/private",
        }).inputs,
        [{ id, diagnosis: "malformed" }],
      );
  }
  assert.deepEqual(rejectedInputs(job("darwin", "provider"), env).inputs, [
    { id: "NATIVE_PROVIDER_REVIEW_SHA256", diagnosis: "missing" },
  ]);
});

test("acquired missing and malformed members retain closed input identifiers", async () => {
  const capability = Buffer.from("synthetic capability bytes");
  for (const [platform, name, content, diagnosis, inputDiagnosis] of [
    ["darwin", "system-inputs.json", null, "acquisition", "missing"],
    [
      "darwin",
      "system-inputs.json",
      "private-output /synthetic/private",
      "review",
      "malformed",
    ],
    [
      "darwin",
      "native-effects.mjs",
      "substituted bytes",
      "review",
      "malformed",
    ],
    [
      "linux",
      "linux-review.json",
      "private-output /synthetic/private",
      "review",
      "malformed",
    ],
  ]) {
    const candidate = job(platform);
    const manifest = {
      candidateSha: candidate.candidateSha,
      platform,
      capabilitySha256: createHash("sha256").update(capability).digest("hex"),
    };
    const values = {
      ...env,
      NATIVE_SYSTEM_REVIEW_SHA256: observationDigest(manifest),
    };
    await assert.rejects(
      acquireSystemCIInputs(
        candidate,
        { verifyLegacy: () => {} },
        path.join(env.RUNNER_TEMP, `native-${platform}-reviewed`),
        {
          env: values,
          fetchInput: async (url) => ({
            ok: !url.endsWith(name) || content !== null,
            body: [
              url.endsWith(name)
                ? Buffer.from(content ?? "")
                : url.endsWith("system-inputs.json")
                  ? Buffer.from(JSON.stringify(manifest))
                  : capability,
            ],
          }),
          fs: { mkdir: async () => {}, writeFile: async () => {} },
          verify: async () => {},
        },
      ),
      (error) => {
        const details = nativeFailureDetails(error);
        assert.deepEqual(details, {
          diagnosis,
          inputs: [{ id: name, diagnosis: inputDiagnosis }],
        });
        assert.doesNotMatch(
          JSON.stringify(details),
          /private-output|synthetic\/private/u,
        );
        return true;
      },
    );
  }
});

test("published first cause survives interrupted job replacement and later failures without raw diagnostics", async () => {
  let receipt = null,
    saved = job(),
    writes = 0,
    interrupted = true;
  const storage = {
    read: async () => receipt,
    persist: async (value) => {
      receipt = structuredClone(value);
      writes++;
    },
    persistJob: async (value) => {
      if (interrupted) throw new Error("synthetic interruption");
      saved = normalizeNativeJob(value);
    },
  };
  const details = rejectedInputs(saved, {
    ...env,
    NATIVE_SYSTEM_INPUT_REVISION: "",
  });
  await assert.rejects(
    persistNativeFirstFailure(saved, "prepare-inputs", details, storage),
  );
  const original = structuredClone(receipt);
  assert.deepEqual(
    normalizeNativeJob(await loadNativeFirstFailure(saved, async () => receipt))
      .firstFailure,
    original,
  );
  assert.throws(() =>
    rejoinNativeFirstFailure(saved, { ...receipt, runAttempt: 2 }),
  );
  await assert.rejects(loadNativeFirstFailure(saved, async () => null));
  assert.equal(
    await loadNativeFirstFailure(saved, async () => {
      throw Object.assign(new Error("Absent receipt"), { code: "ENOENT" });
    }),
    saved,
  );
  interrupted = false;
  for (const stage of ["prepare", "setup", "probe", "cleanup"])
    saved = await persistNativeFirstFailure(
      saved,
      stage,
      nativeFailureDetails({
        diagnosis: "build",
        inputs: [{ id: "token=private-value", diagnosis: "missing" }],
        stdout: "private-output",
        cause: "/synthetic/private",
      }),
      storage,
    );
  assert.equal(writes, 1);
  assert.deepEqual(saved.firstFailure, original);
  assert.deepEqual(receipt, original);
  const rendered = renderNativeJob(saved);
  assert.equal(rendered.report.ciStatus, "FAIL");
  assert.match(rendered.summary, /prepare-inputs.*prerequisite/u);
  assert.doesNotMatch(
    JSON.stringify(rendered),
    /private-value|private-output|synthetic\/private/u,
  );
  for (const change of [
    { candidateSha: "b".repeat(40) },
    { runId: "2" },
    { runAttempt: 2 },
    { tier: "provider" },
    { stage: "unknown" },
    { diagnosis: "private-output" },
    { extra: "private-value" },
  ])
    assert.throws(() =>
      normalizeNativeFirstFailure({ ...original, ...change }, saved),
    );
  assert.throws(() =>
    normalizeNativeFirstFailure(
      {
        ...original,
        inputs: [{ id: "token=private-value", diagnosis: "missing" }],
      },
      saved,
    ),
  );
});

test("aggregation retains a uniquely bound cause without setup job identity and never promotes it to proof", () => {
  const candidate = job();
  candidate.firstFailure = captureNativeFirstFailure(
    candidate,
    "prepare-inputs",
    {
      diagnosis: "prerequisite",
      inputs: [{ id: "NATIVE_SYSTEM_INPUT_REVISION", diagnosis: "missing" }],
    },
  );
  const binding = {
    candidateSha: candidate.candidateSha,
    platform: candidate.platform,
    tier: candidate.tier,
    artifactId: "1",
    provenance: { ...candidate.provenance, jobId: "1" },
    conclusion: "failure",
    authority: "ordinary",
  };
  const report = (bindings) =>
    aggregateNativeEvidence({
      candidateSha: candidate.candidateSha,
      source: renderNativeJob(candidate).report.source,
      results: [],
      compositions: [candidate],
      bindings,
    });
  assert.deepEqual(report([binding]).firstFailures, [candidate.firstFailure]);
  assert.notEqual(report([binding]).decision, "GO");
  for (const change of [
    { runId: "2" },
    { runAttempt: 2 },
    { workflow: "other.yml" },
    { repository: "example/other" },
  ])
    assert.deepEqual(
      report([{ ...binding, provenance: { ...binding.provenance, ...change } }])
        .firstFailures,
      [],
    );
  assert.deepEqual(
    report([
      binding,
      {
        ...binding,
        artifactId: "2",
        provenance: { ...binding.provenance, jobId: "2" },
      },
    ]).firstFailures,
    [],
  );
});

test("missing reviewed inputs are unsuccessful prerequisites, separate from possible native effects", () => {
  for (const platform of ["linux", "darwin", "win32"]) {
    const candidate = job(platform);
    candidate.firstFailure = captureNativeFirstFailure(
      candidate,
      "prepare-inputs",
      rejectedInputs(candidate, {
        ...env,
        ...Object.fromEntries(inputIds.map((id) => [id, ""])),
      }),
    );
    const before = structuredClone(candidate);
    const rendered = renderNativeJob(candidate);
    assert.deepEqual(candidate, before);
    assert.deepEqual(rendered.report.firstFailures, [candidate.firstFailure]);
    assert.equal(rendered.report.ciStatus, "FAIL");
    assert.equal(rendered.report.decision, "BLOCKED");
    assert.equal(rendered.report.preparationRecovery[0].status, "NOT_ADMITTED");
    assert.match(rendered.summary, /^## Unmet native CI prerequisites/mu);
    assert.match(rendered.summary, /admission not-started/u);
    assert.match(rendered.summary, /full acceptance remains blocked/u);
    assert.doesNotMatch(rendered.summary, /^## First native CI failures/mu);
    assert.match(
      rendered.annotations[0],
      /^::error title=Native CI prerequisite::/u,
    );
    for (const input of candidate.firstFailure.inputs)
      assert.ok(rendered.summary.includes(`${input.id} missing`));

    const possible = job(platform);
    possible.preparationEffects.admission = "possible";
    // A prerequisite label alone must never claim that no effects occurred.
    possible.firstFailure = captureNativeFirstFailure(
      possible,
      "prepare-inputs",
      {
        diagnosis: "prerequisite",
        inputs: [{ id: "NATIVE_SYSTEM_REVIEW_SHA256", diagnosis: "missing" }],
      },
    );
    const mixed = renderNativeFailures(
      {
        report: {},
        summary: "Full acceptance remains BLOCKED.",
        annotations: [],
      },
      [candidate, possible],
    );
    assert.match(mixed.summary, /^## Unmet native CI prerequisites/mu);
    assert.match(
      mixed.summary,
      /^## First native CI failures and preparation recovery/mu,
    );
    assert.match(mixed.summary, /admission possible/u);
    assert.match(mixed.summary, /preparation retirement is uncertain/u);
    assert.deepEqual(mixed.report.firstFailures, [
      candidate.firstFailure,
      possible.firstFailure,
    ]);
    assert.deepEqual(
      mixed.report.preparationRecovery.map(({ status }) => status),
      ["NOT_ADMITTED", "UNCERTAIN"],
    );
    assert.match(mixed.annotations[1], /^::error title=Native preparation::/u);
  }
});

test("non-admission never invents retirement and possible preparation remains independently recoverable", () => {
  const unstarted = job();
  assert.equal(nativeJobHasPossibleEffects(unstarted), false);
  assert.equal(
    renderNativeJob(unstarted).report.preparationRecovery[0].status,
    "NOT_ADMITTED",
  );
  const historical = { ...unstarted };
  delete historical.preparationEffects;
  assert.equal(
    nativeJobHasPossibleEffects(normalizeNativeJob(historical)),
    true,
  );
  const historicalCause = captureNativeFirstFailure(historical, "prepare", {
    diagnosis: "build",
    inputs: [],
  });
  assert.equal(
    renderNativeJob({ ...historical, firstFailure: historicalCause }).report
      .preparationRecovery[0].status,
    "UNCERTAIN",
  );
  assert.throws(() =>
    normalizeNativeJob({
      ...historical,
      firstFailure: { ...historicalCause, admission: "not-started" },
    }),
  );
  const possible = normalizeNativeJob({
    ...unstarted,
    preparationEffects: {
      ...unstarted.preparationEffects,
      admission: "possible",
    },
  });
  possible.firstFailure = captureNativeFirstFailure(possible, "prepare", {
    diagnosis: "build",
    inputs: [],
  });
  assert.equal(possible.firstFailure.admission, "possible");
  assert.equal(nativeCleanupFailure(possible), "unretired");
  const rendered = renderNativeJob(possible);
  assert.equal(rendered.report.preparationRecovery[0].status, "UNCERTAIN");
  assert.match(rendered.summary, /independently recover possible effects/u);
  assert.throws(() =>
    normalizeNativeJob({
      ...possible,
      stages: {
        ...possible.stages,
        cleanup: {
          status: "PASS",
          elapsedMs: 1,
          deadlineMs: 120000,
          reason: null,
        },
      },
    }),
  );
  const retired = normalizeNativeJob({
    ...possible,
    preparationEffects: {
      ...possible.preparationEffects,
      settlement: {
        status: "RETIRED",
        independent: true,
        emergencyCleanup: false,
      },
      receiptSha256: "e".repeat(64),
    },
  });
  assert.equal(
    renderNativeJob(retired).report.preparationRecovery[0].status,
    "RETIRED",
  );
  assert.deepEqual(retired.firstFailure, possible.firstFailure);
  assert.equal(
    renderNativeJob({
      ...historical,
      firstFailure: historicalCause,
      preparationEffects: retired.preparationEffects,
    }).report.preparationRecovery[0].status,
    "RETIRED",
  );
});
