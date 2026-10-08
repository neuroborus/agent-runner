import assert from "node:assert/strict";
import test from "node:test";

import {
  assessFeasibilityReport,
  feasibilityCapabilities,
  FeasibilityError,
  LITERAL_ARGUMENTS,
  resolveFeasibilityDispatch,
  resolvePayloadRequest,
  runFeasibilityExperiment,
  unavailableFeasibilityResults,
} from "../ci/native/feasibility/index.js";
import {
  linuxFeasibilityResult,
  linuxFeasibilityCause,
  linuxFeasibilityBuildArguments,
  canContinueLinuxFeasibility,
  observeLinuxFeasibilityRetirement,
} from "../ci/native/linux/index.js";

const SHA = "a".repeat(40),
  DIGEST = "b".repeat(64);
const host = {
  ci: true,
  githubActions: true,
  runnerEnvironment: "github-hosted",
  runnerOs: "Linux",
  platform: "linux",
  architecture: "x64",
};
const args = ["--platform", "linux", "--expected-sha", SHA];

// Synthetic records exercise the contract only; they establish no native proof.
function report() {
  return {
    schemaVersion: 1,
    expectedSha: SHA,
    checkoutSha: SHA,
    platform: "linux",
    os: "linux",
    build: "synthetic-build",
    architecture: "x64",
    results: feasibilityCapabilities("linux").map(({ id, tier, outcome }) => {
      if (tier === "protected")
        return unavailableFeasibilityResults("linux").find(
          (entry) => entry.capability === id,
        );
      return {
        capability: id,
        status: "PASS",
        cause: null,
        elapsedMs: 10,
        components: ["tool", "helper"].map((role) => ({
          role,
          name: "fixture",
          version: "1",
          sha256: DIGEST,
        })),
        evidence: {
          ready: true,
          positiveControl: true,
          attemptAcknowledged: true,
          independent: true,
          outcome,
          observationSha256: DIGEST,
          sentinelsBeforeSha256: DIGEST,
          sentinelsAfterSha256: DIGEST,
        },
        cleanup: {
          status: "PASS",
          independent: true,
          emergency: false,
          elapsedMs: 5,
          witnessSha256: DIGEST,
          cause: null,
        },
      };
    }),
  };
}

test("experiment gate separates protected absence and fails mismatched or missing records", () => {
  const input = report();
  assert.equal(assessFeasibilityReport(input).status, "PASS");
  assert.equal(
    assessFeasibilityReport(input, { protectedAcceptance: true }).status,
    "BLOCKED",
  );
  const mismatch = assessFeasibilityReport({
    ...input,
    checkoutSha: "c".repeat(40),
  });
  assert.equal(mismatch.status, "FAIL");
  assert.equal(mismatch.issues[0].code, "checkout-mismatch");
  const missing = assessFeasibilityReport({
    ...input,
    results: input.results.slice(1),
  });
  assert.equal(missing.status, "FAIL");
  assert.equal(missing.report.results[0].cause.code, "missing-record");
  assert.throws(
    () =>
      assessFeasibilityReport({
        ...input,
        results: input.results.map(() => input.results[0]),
      }),
    FeasibilityError,
  );
  assert.throws(
    () => assessFeasibilityReport({ ...input, status: "PASS" }),
    FeasibilityError,
  );
  for (const changed of [
    { os: "darwin" },
    { build: null },
    { architecture: "arm64" },
  ])
    assert.equal(
      assessFeasibilityReport({ ...input, ...changed }).status,
      "FAIL",
    );
});

test("denial success needs every control, acknowledged attempt, independent witness and unchanged sentinel", () => {
  const cases = [
    ...["ready", "positiveControl", "attemptAcknowledged", "independent"].map(
      (key) => ["evidence", key, false],
    ),
    ["evidence", "outcome", "PERMITTED"],
    ["evidence", "observationSha256", null],
    ["evidence", "sentinelsBeforeSha256", null],
    ["evidence", "sentinelsAfterSha256", "d".repeat(64)],
    ["cleanup", "independent", false],
    ["cleanup", "witnessSha256", null],
    ["cleanup", "elapsedMs", 30001],
    ["cleanup", "emergency", true],
  ];
  for (const [section, key, value] of cases) {
    const input = report(),
      entry = input.results.find(
        ({ capability }) => capability === "network.tcp-denial",
      );
    entry[section][key] = value;
    assert.equal(
      assessFeasibilityReport(input).status,
      "FAIL",
      `${section}.${key}`,
    );
    assert.equal(
      entry.status,
      "PASS",
      "Assessment must not mutate submitted evidence",
    );
  }
  for (const change of [
    { evidence: null },
    { components: [] },
    { elapsedMs: null },
    { elapsedMs: 120001 },
  ]) {
    const input = report();
    Object.assign(input.results[0], change);
    assert.equal(assessFeasibilityReport(input).status, "FAIL");
  }
});

test("cleanup failure retains the original first cause and cannot repair crashes or deadlines", () => {
  for (const code of ["setup-failed", "crash", "deadline", "observed-escape"]) {
    const input = report(),
      entry = input.results[0];
    entry.status = "FAIL";
    entry.cause = {
      code,
      detail: "The fixed fixture failed before completion.",
    };
    entry.cleanup.status = "FAIL";
    entry.cleanup.cause = {
      code: "cleanup-failed",
      detail: "The independent observer found a surviving owned fixture.",
    };
    const assessed = assessFeasibilityReport(input);
    assert.equal(assessed.status, "FAIL");
    assert.equal(assessed.report.results[0].cause.code, code);
    assert.equal(
      assessed.report.results[0].cleanup.cause.code,
      "cleanup-failed",
    );
    entry.status = "BLOCKED";
    assert.throws(() => assessFeasibilityReport(input), FeasibilityError);
  }
  for (const change of [
    { independent: false },
    { witnessSha256: null },
    { elapsedMs: 30001 },
    { emergency: true },
    {
      status: "NOT_RUN",
      independent: false,
      elapsedMs: null,
      witnessSha256: null,
    },
  ]) {
    const input = report(),
      entry = input.results[0];
    entry.status = "FAIL";
    entry.cause = { code: "crash", detail: "The fixed fixture crashed." };
    Object.assign(entry.cleanup, change);
    const submittedCleanupStatus = entry.cleanup.status;
    const assessed = assessFeasibilityReport(input),
      result = assessed.report.results[0];
    assert.equal(result.cause.code, "crash");
    assert.equal(result.cleanup.status, "UNCERTAIN");
    assert.equal(result.cleanup.cause.code, "cleanup-unobserved");
    assert.equal(entry.cleanup.status, submittedCleanupStatus);
    assert.deepEqual(assessFeasibilityReport(assessed.report), assessed);
  }
  const missingCleanup = report();
  missingCleanup.results[0].evidence.independent = false;
  missingCleanup.results[0].cleanup =
    unavailableFeasibilityResults("linux")[0].cleanup;
  const missing = assessFeasibilityReport(missingCleanup).report.results[0];
  assert.equal(missing.cause.code, "missing-observation");
  assert.equal(missing.cleanup.status, "UNCERTAIN");
  assert.equal(missing.cleanup.cause.code, "cleanup-unobserved");
  const input = report();
  input.results[0].cleanup.status = "UNCERTAIN";
  input.results[0].cleanup.cause = {
    code: "cleanup-unobserved",
    detail: "The fresh cleanup witness is unavailable.",
  };
  assert.equal(
    assessFeasibilityReport(input).report.results[0].cause.code,
    "cleanup-unobserved",
  );
  input.results[0].cleanup.cause.detail = "authorization=private-value";
  assert.throws(() => assessFeasibilityReport(input), FeasibilityError);
});

test("dispatch refuses host, foreign-worker and arbitrary selectors before observing checkout", async () => {
  let observed = 0;
  let dispatched = 0;
  const runNative = async (dispatch, observation) => {
    dispatched += 1;
    assert.equal(dispatch.platform, "linux");
    assert.equal(dispatch.expectedSha, observation.checkoutSha);
    return unavailableFeasibilityResults("linux").filter(({ capability }) =>
      feasibilityCapabilities("linux").some(
        ({ id, tier }) => id === capability && tier === "native",
      ),
    );
  };
  const observe = async () => {
    observed += 1;
    return {
      checkoutSha: SHA,
      os: "linux",
      build: "synthetic-build",
      architecture: "x64",
    };
  };
  for (const change of [
    { ci: false },
    { githubActions: false },
    { runnerEnvironment: "self-hosted" },
    { runnerOs: "macOS" },
    { platform: "darwin" },
    { architecture: "arm64" },
  ])
    await assert.rejects(
      runFeasibilityExperiment(args, {
        host: { ...host, ...change },
        observe,
        runNative,
      }),
      FeasibilityError,
    );
  assert.equal(observed, 0);
  for (const extra of [
    ["--module", "fixture.js"],
    ["--platform", "linux"],
    ["--protected", "--protected"],
  ])
    assert.throws(
      () => resolveFeasibilityDispatch([...args, ...extra], host),
      FeasibilityError,
    );
  assert.equal(
    resolveFeasibilityDispatch([...args, "--protected"], host)
      .protectedAcceptance,
    true,
  );
  const initial = await runFeasibilityExperiment(args, {
    host,
    observe,
    runNative,
  });
  assert.equal(observed, 1);
  assert.equal(initial.status, "BLOCKED");
  assert.ok(
    initial.report.results.every(
      ({ cause, cleanup }) =>
        cause.code === "unimplemented" && cleanup.status === "NOT_RUN",
    ),
  );
  const failed = await runFeasibilityExperiment(args, {
    host,
    runNative,
    observe: async () => {
      throw { code: "ENOENT" };
    },
  });
  assert.equal(failed.status, "FAIL");
  assert.equal(
    failed.report.results[0].cause.detail,
    "Checkout observation failed: ENOENT.",
  );
  const forged = await runFeasibilityExperiment(args, {
    host,
    runNative,
    observe: async () => ({
      ...(await observe()),
      expectedSha: "c".repeat(40),
      checkoutSha: "c".repeat(40),
    }),
  });
  assert.equal(forged.report.expectedSha, SHA);
  assert.equal(forged.status, "FAIL");
  assert.equal(
    dispatched,
    1,
    "revision/observation failures must precede native dispatch",
  );
  await assert.rejects(
    runFeasibilityExperiment(args, {
      host,
      observe,
      runNative: async () => [
        report().results.find(
          ({ capability }) => capability === "codex.command-tools",
        ),
      ],
    }),
    FeasibilityError,
  );
  const interrupted = await runFeasibilityExperiment(args, {
    host,
    observe,
    runNative: async () => {
      throw new Error("Native owner interrupted");
    },
  });
  assert.equal(interrupted.report.results[0].status, "FAIL");
  assert.equal(interrupted.report.results[0].cleanup.status, "UNCERTAIN");
  const missing = await runFeasibilityExperiment(args, {
    host,
    observe,
    runNative: async () => [],
  });
  assert.equal(missing.report.results[0].cause.code, "missing-record");
});

test("Linux evidence joins retain uncertainty and emergency cleanup across both bundles", () => {
  const template = report();
  const input = template.results.find(
    ({ capability }) => capability === "git.denial",
  );
  const entry = {
    caseId: "read-only",
    status: "PASS",
    cause: null,
    elapsedMs: 10,
    ready: true,
    positiveControl: true,
    attemptAcknowledged: true,
    observationSha256: DIGEST,
    sentinelsBeforeSha256: DIGEST,
    sentinelsAfterSha256: DIGEST,
    cleanup: input.cleanup,
  };
  const assess = (changed) => {
    const joined = linuxFeasibilityResult(
      "git.denial",
      [entry, { ...changed, caseId: "workspace-write" }],
      input.components,
    );
    return assessFeasibilityReport({
      ...template,
      results: template.results.map((value) =>
        value.capability === joined.capability ? joined : value,
      ),
    }).report.results.find(({ capability }) => capability === "git.denial");
  };
  assert.equal(assess(entry).status, "PASS");
  assert.equal(canContinueLinuxFeasibility(entry), true);
  assert.equal(
    linuxFeasibilityResult("git.denial", [entry], input.components).status,
    "FAIL",
  );
  assert.equal(
    linuxFeasibilityResult("git.denial", [entry, entry], input.components)
      .status,
    "FAIL",
  );
  for (const changed of [
    { positiveControl: false },
    { attemptAcknowledged: false },
    { observationSha256: null },
    { sentinelsAfterSha256: "c".repeat(64) },
    { sentinelsBeforeSha256: "unobserved", sentinelsAfterSha256: "unobserved" },
    { cleanup: { ...entry.cleanup, witnessSha256: "unobserved" } },
    { cleanup: { ...entry.cleanup, emergency: true } },
  ]) {
    assert.equal(assess({ ...entry, ...changed }).status, "FAIL");
    assert.equal(canContinueLinuxFeasibility({ ...entry, ...changed }), false);
  }
  const cause = {
    code: "observed-escape",
    detail: "The fixture wrote outside its workspace.",
  };
  const failed = assess({
    ...entry,
    status: "FAIL",
    cause,
    cleanup: {
      ...entry.cleanup,
      status: "UNCERTAIN",
      cause: {
        code: "cleanup-unobserved",
        detail: "No independent retirement witness was available.",
      },
    },
  });
  assert.deepEqual(failed.cause, cause);
  assert.equal(failed.cleanup.status, "UNCERTAIN");
});

test("Linux prerequisite refusal separates unsupported namespaces from setup defects and fixes compiler inputs", () => {
  const unavailable = {
    prerequisites: {
      checks: [
        {
          id: "nested-namespaces",
          status: "BLOCKED",
          diagnosis: "probe-failed",
          observation: { exitCode: 1, signal: null, timedOut: false },
        },
      ],
    },
  };
  assert.equal(
    linuxFeasibilityCause("fixture", unavailable).code,
    "prerequisite-unavailable",
  );
  for (const observation of [
    { exitCode: null, signal: "SIGKILL", timedOut: false },
    { exitCode: null, signal: null, timedOut: true },
  ]) {
    const defective = structuredClone(unavailable);
    defective.prerequisites.checks[0].observation = observation;
    assert.equal(
      linuxFeasibilityCause("fixture", defective).code,
      observation.timedOut ? "deadline" : "crash",
    );
  }
  assert.equal(
    linuxFeasibilityCause("receipt", { code: "ENOENT" }).code,
    "setup-failed",
  );
  const argumentsList = linuxFeasibilityBuildArguments(
    "/fixture/file-helper.c",
    "/fixture/build",
  );
  assert.deepEqual(argumentsList.slice(-3), [
    "-o",
    "/fixture/build/file-helper",
    "/fixture/file-helper.c",
  ]);
  assert.ok(argumentsList.includes("-static"));
  assert.throws(() =>
    linuxFeasibilityBuildArguments("/fixture/../other.c", "/fixture/build"),
  );
});

test("Linux retirement requires a resolved, stable same-revision receipt before fresh verification", async () => {
  const binding = { file: "/fixture/owner-loss.json", sha256: DIGEST };
  const receipt = {
    candidateSha: SHA,
    caseId: "owner-loss",
    hostSession: false,
    isolatedNamespace: true,
  };
  const calls = [];
  const effects = {
    async readReceipt(file, sha256) {
      calls.push("receipt");
      assert.equal(file, binding.file);
      assert.equal(sha256, binding.sha256);
      return receipt;
    },
    async verify() {
      calls.push("verify");
      return { status: "RETIRED", independent: true, emergencyCleanup: false };
    },
  };
  await assert.rejects(
    observeLinuxFeasibilityRetirement(
      () => binding,
      SHA,
      "owner-loss",
      effects,
    ),
    /binding/,
  );
  assert.deepEqual(calls, []);
  const observed = await observeLinuxFeasibilityRetirement(
    binding,
    SHA,
    "owner-loss",
    effects,
  );
  assert.equal(observed.settlement.status, "RETIRED");
  assert.deepEqual(calls, ["receipt", "verify", "receipt"]);
  for (const change of [
    { candidateSha: "c".repeat(40) },
    { hostSession: true },
    { hostSession: undefined },
    { isolatedNamespace: false },
    { caseId: "cancel" },
  ]) {
    calls.length = 0;
    await assert.rejects(
      observeLinuxFeasibilityRetirement(binding, SHA, "owner-loss", {
        ...effects,
        readReceipt: async () => ({ ...receipt, ...change }),
      }),
      /mismatch/,
    );
    assert.deepEqual(calls, []);
  }
  let reads = 0;
  await assert.rejects(
    observeLinuxFeasibilityRetirement(binding, SHA, "owner-loss", {
      ...effects,
      readReceipt: async () =>
        ++reads === 1 ? receipt : { ...receipt, nonce: "changed" },
    }),
    /changed/,
  );
});

test("payload requests admit only fixed operations and literal argument vectors without running them", () => {
  const prefix = ["--platform", "linux", "--case"];
  assert.equal(resolvePayloadRequest([...prefix, "inspect"]).caseId, "inspect");
  assert.equal(
    resolvePayloadRequest([...prefix, "argv", "--", ...LITERAL_ARGUMENTS])
      .caseId,
    "argv",
  );
  for (const values of [
    [...prefix, "exec"],
    [...prefix, "inspect", "extra"],
    [...prefix, "argv", "--", "replacement"],
  ])
    assert.throws(() => resolvePayloadRequest(values));
});
