import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { Writable, PassThrough } from "node:stream";
import { gzipSync } from "node:zlib";
import { resolveOwnedProcessLauncher } from "../src/agents/index.js";
import {
  preflightNativeTar,
  materializeReviewedTar,
  observationDigest,
  NATIVE_PACKAGE_LIMITS,
  assertProtectedNativeEnvironment,
} from "../ci/native/index.js";
import {
  feasibilityCommandParameters,
  feasibilityCommandError,
  openFeasibilityCommand,
  protectedFeasibilityReadiness,
  assertFeasibilityToolEvidence,
  assertProtectedFeasibilityCleanup,
  feasibilityRuntimeMembers,
} from "../ci/native/providers/index.js";

import {
  assessFeasibilityReport,
  feasibilityCapabilities,
  FeasibilityError,
  LITERAL_ARGUMENTS,
  resolveFeasibilityDispatch,
  resolvePayloadRequest,
  runFeasibilityExperiment as runExperiment,
  unavailableFeasibilityResults,
  assertFeasibilityRevision,
  feasibilityModelAuthorization,
  assessUnavailableProtectedFeasibility,
  assessFeasibilityCompletion,
  renderFeasibilitySummary,
} from "../ci/native/feasibility/index.js";
import {
  linuxFeasibilityResult,
  linuxFeasibilityCause,
  linuxFeasibilityBuildArguments,
  canContinueLinuxFeasibility,
  observeLinuxFeasibilityRetirement,
  resolveLinuxDiagnosticLauncher,
  linuxDiagnosticError,
  linuxControllerFailure,
  normalizeLinuxControllerFailure,
  prepareLinuxFixture,
} from "../ci/native/linux/index.js";
import {
  assessDarwinFeasibilityDomain,
  assertDarwinFeasibilityTranscript,
  darwinFeasibilityIdentityArguments,
  darwinFeasibilityPolicy,
  runDarwinFeasibility,
  prepareDarwinFeasibility,
  darwinFeasibilityCause,
} from "../ci/native/darwin/index.js";
import {
  runWindowsFeasibility,
  windowsFeasibilityProfileName,
  windowsFeasibilityCallerEnvironment,
  windowsFeasibilityToolEnvironment,
  windowsFeasibilityImports,
  windowsFeasibilityCause,
  windowsFeasibilityDiagnostics,
  windowsFeasibilityHelperSession,
  WINDOWS_LITERAL_ARGUMENTS,
  quoteWindowsArgument,
  assertWindowsFeasibilityWitness,
} from "../ci/native/win32/index.js";

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

test("CI revision admission rejects foreign workflow/dispatch/checkout bindings", () => {
  const dispatch = { expectedSha: SHA, protectedAcceptance: true };
  const env = {
    NATIVE_CANDIDATE_SHA: SHA,
    GITHUB_EVENT_NAME: "workflow_dispatch",
    GITHUB_SHA: SHA,
    GITHUB_WORKFLOW_SHA: SHA,
  };
  assert.doesNotThrow(() =>
    assertFeasibilityRevision(dispatch, env, { checkoutSha: SHA }),
  );
  for (const key of [
    "NATIVE_CANDIDATE_SHA",
    "GITHUB_SHA",
    "GITHUB_WORKFLOW_SHA",
  ])
    assert.throws(
      () =>
        assertFeasibilityRevision(
          dispatch,
          { ...env, [key]: "b".repeat(40) },
          { checkoutSha: SHA },
        ),
      FeasibilityError,
    );
  assert.throws(
    () =>
      assertFeasibilityRevision(dispatch, env, { checkoutSha: "b".repeat(40) }),
    FeasibilityError,
  );
  // PR checks deliberately inspect the event head, rather than its merge SHA.
  assert.doesNotThrow(() =>
    assertFeasibilityRevision(
      { ...dispatch, protectedAcceptance: false },
      { ...env, GITHUB_EVENT_NAME: "pull_request", GITHUB_SHA: "b".repeat(40) },
      { checkoutSha: SHA },
    ),
  );
});

test("CI model authorization requires protected independent review and explicit bounded policies", () => {
  const dispatch = {
    platform: "linux",
    expectedSha: SHA,
    protectedAcceptance: true,
  };
  const environment = {
    name: "native-feasibility-provider-linux",
    protection_rules: [
      {
        type: "required_reviewers",
        prevent_self_review: true,
        reviewers: [{ type: "Team", reviewer: { id: 1 } }],
      },
    ],
  };
  const policy = JSON.stringify({
    model: "fixture-model",
    requests: 4,
    outputTokens: 128,
    budgetMicros: 1000000,
    inputMicros: 1,
    outputMicros: 1,
    beta: [],
  });
  const env = {
    NATIVE_FEASIBILITY_REVIEWED_SHA: SHA,
    NATIVE_FEASIBILITY_MODEL_USE_AUTHORIZED: "true",
    NATIVE_FEASIBILITY_CODEX_POLICY: policy,
    NATIVE_FEASIBILITY_CLAUDE_POLICY: policy,
  };
  const authorization = feasibilityModelAuthorization(
    dispatch,
    env,
    environment,
  );
  assert.equal(authorization.codex.requests, 4);
  assert.equal(authorization.candidateSha, SHA);
  assert.throws(() =>
    assertProtectedNativeEnvironment(
      { ...environment, name: "other-environment" },
      environment.name,
    ),
  );
  for (const protection_rules of [
    [],
    [{ ...environment.protection_rules[0], prevent_self_review: false }],
    [{ ...environment.protection_rules[0], reviewers: [] }],
  ])
    assert.throws(() =>
      feasibilityModelAuthorization(dispatch, env, {
        ...environment,
        protection_rules,
      }),
    );
  for (const change of [
    { NATIVE_FEASIBILITY_REVIEWED_SHA: "b".repeat(40) },
    { NATIVE_FEASIBILITY_MODEL_USE_AUTHORIZED: "false" },
    { NATIVE_FEASIBILITY_CODEX_POLICY: "{}" },
  ])
    assert.throws(() =>
      feasibilityModelAuthorization(
        dispatch,
        { ...env, ...change },
        environment,
      ),
    );
  assert.equal(
    typeof protectedFeasibilityReadiness(dispatch, authorization, null),
    "string",
  );
});

// Ordinary coverage stays portable even on matching hosted workers. Overrides
// below exercise provider dispatch without ever acquiring or starting a binary.
const runFeasibilityExperiment = (argumentsList, options) =>
  runExperiment(argumentsList, {
    runProviders: async ({ platform }) =>
      unavailableFeasibilityResults(platform).filter(({ capability }) =>
        feasibilityCapabilities(platform).some(
          ({ id, tier }) => id === capability && tier !== "native",
        ),
      ),
    ...options,
  });

// Synthetic records exercise the contract only; they establish no native proof.
function report(platform = "linux") {
  return {
    schemaVersion: 1,
    expectedSha: SHA,
    checkoutSha: SHA,
    platform,
    os: platform,
    build: "synthetic-build",
    architecture: "x64",
    results: feasibilityCapabilities(platform).map(({ id, tier, outcome }) => {
      if (tier === "protected")
        return unavailableFeasibilityResults(platform).find(
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

test("CI completion rejects inconsistent envelopes while preserving protected admission", () => {
  const input = assessFeasibilityReport(report());
  const dispatch = {
    platform: "linux",
    expectedSha: SHA,
    protectedAcceptance: false,
  };
  const observed = input.report;
  assert.equal(
    assessFeasibilityCompletion(input, dispatch, observed).status,
    "PASS",
  );
  assert.equal(
    assessFeasibilityCompletion(
      input,
      { ...dispatch, protectedAcceptance: true },
      observed,
    ).status,
    "BLOCKED",
  );
  for (const changed of [
    { ...input, status: "UNKNOWN" },
    { ...input, status: "FAIL" },
    { ...input, issues: null },
    {
      ...input,
      issues: [
        { code: "checkout-mismatch", detail: "Synthetic inconsistent issue." },
      ],
    },
    { ...input, extra: true },
    {
      ...input,
      report: { ...input.report, results: input.report.results.slice(1) },
    },
  ])
    assert.throws(
      () => assessFeasibilityCompletion(changed, dispatch, observed),
      FeasibilityError,
    );
  assert.throws(
    () =>
      assessFeasibilityCompletion(input, dispatch, {
        ...observed,
        build: "other-build",
      }),
    FeasibilityError,
  );
});

test("unavailable protected custody rejects prior success and retains original failure", () => {
  const input = report();
  input.results = feasibilityCapabilities("linux").map(({ id, outcome }) => ({
    ...input.results[0],
    capability: id,
    evidence: { ...input.results[0].evidence, outcome },
  }));
  assert.equal(
    assessFeasibilityReport(input, { protectedAcceptance: true }).status,
    "PASS",
  );
  const cause = {
    code: "observed-escape",
    detail: "Synthetic outside write observed.",
  };
  const failed = input.results.find(
    ({ capability }) => capability === "codex.file-tools",
  );
  failed.status = "FAIL";
  failed.cause = cause;
  const assessment = assessUnavailableProtectedFeasibility(
    input,
    "Private transport is not admitted.",
  );
  assert.equal(assessment.status, "FAIL");
  assert.deepEqual(
    assessment.report.results.find(
      ({ capability }) => capability === failed.capability,
    ).cause,
    cause,
  );
  assert.equal(
    assessment.report.results.find(
      ({ capability }) => capability === "provider.transport",
    ).status,
    "BLOCKED",
  );
  assert.equal(assessment.report.results[0].status, "PASS");
});

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
  assert.match(
    failed.report.results[0].cause.detail,
    /^observe checkout: exit=unknown, signal=unknown, timeout=unknown; .*not found\./u,
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

test("provider dispatch cannot substitute command evidence for protected routes or native records", async () => {
  const input = report(),
    options = {
      host,
      observe: async () => ({
        checkoutSha: SHA,
        os: "linux",
        build: "synthetic",
        architecture: "x64",
      }),
      runNative: async () =>
        input.results.filter(({ capability }) =>
          feasibilityCapabilities("linux").some(
            ({ id, tier }) => id === capability && tier === "native",
          ),
        ),
    };
  const result = await runFeasibilityExperiment(args, {
    ...options,
    runProviders: async () =>
      input.results.filter(({ capability }) =>
        feasibilityCapabilities("linux").some(
          ({ id, tier }) => id === capability && tier !== "native",
        ),
      ),
  });
  assert.equal(result.status, "PASS");
  assert.equal(
    result.report.results.find(
      ({ capability }) => capability === "codex.file-tools",
    ).status,
    "BLOCKED",
  );
  const missing = await runFeasibilityExperiment(args, {
    ...options,
    runProviders: async () => [],
  });
  assert.equal(
    missing.report.results.find(
      ({ capability }) => capability === "codex.command-exec",
    ).cause.code,
    "missing-record",
  );
  await assert.rejects(
    runFeasibilityExperiment(args, {
      ...options,
      runProviders: async () => [input.results[0]],
    }),
    FeasibilityError,
  );
  let calls = 0;
  const cleanup = input.results[0].cleanup;
  for (const change of [
    {
      status: "UNCERTAIN",
      cause: {
        code: "cleanup-unobserved",
        detail: "Synthetic cleanup is unsettled.",
      },
    },
    { emergency: true },
    { witnessSha256: null },
    { independent: false },
    { elapsedMs: 30001 },
  ]) {
    input.results[0].cleanup = { ...cleanup, ...change };
    await runFeasibilityExperiment(args, {
      ...options,
      runProviders: async () => {
        calls++;
        return [];
      },
    });
  }
  assert.equal(calls, 0);
  input.results[0].cleanup = cleanup;
  const interrupted = await runFeasibilityExperiment(args, {
    ...options,
    runProviders: async () => {
      throw new Error("Synthetic interrupted owner");
    },
  });
  assert.equal(
    interrupted.report.results.find(
      ({ capability }) => capability === "codex.command-exec",
    ).cleanup.status,
    "UNCERTAIN",
  );
});

test("Darwin and Windows command reports keep required native/protected records, components and independent cleanup", async () => {
  for (const platform of ["darwin", "win32"]) {
    const input = report(platform),
      capabilities = feasibilityCapabilities(platform),
      native = input.results.filter((entry) =>
        capabilities.some(
          (spec) => spec.id === entry.capability && spec.tier === "native",
        ),
      ),
      providers = input.results.filter((entry) => !native.includes(entry)),
      command = providers.find(
        (entry) => entry.capability === "codex.command-exec",
      ),
      options = {
        host: {
          ...host,
          platform,
          runnerOs: platform === "darwin" ? "macOS" : "Windows",
        },
        observe: async () => input,
        runNative: async () => native,
        runProviders: async () => providers,
      },
      argumentsList = ["--platform", platform, "--expected-sha", SHA];
    const completed = await runFeasibilityExperiment(argumentsList, options);
    assert.equal(completed.status, "PASS");
    assert.equal(completed.report.results.length, capabilities.length);
    const protectedRecords = completed.report.results.filter((entry) =>
      capabilities.some(
        (spec) => spec.id === entry.capability && spec.tier === "protected",
      ),
    );
    assert.equal(protectedRecords.length, 5);
    assert.ok(protectedRecords.every((entry) => entry.status === "BLOCKED"));
    assert.deepEqual(
      completed.report.results.find(
        (entry) => entry.capability === command.capability,
      ),
      command,
    );
    const summary = renderFeasibilitySummary(
      completed,
      {
        expectedSha: SHA,
        platform,
        protectedAcceptance: false,
        runId: "7",
        runAttempt: "2",
      },
      {
        NATIVE_CANDIDATE_SHA: SHA,
        NATIVE_PLATFORM: platform,
        GITHUB_RUN_ID: "7",
        GITHUB_RUN_ATTEMPT: "2",
        NATIVE_PREPARATION_CONCLUSION: "success",
        NATIVE_PROBE_CONCLUSION: "success",
        NATIVE_CLEANUP_CONCLUSION: "failure",
      },
    );
    assert.match(summary, /model-free=1\/1, protected=0\/5/u);
    assert.ok(summary.includes(`tool:fixture@1 sha256=${DIGEST}`));
    assert.ok(
      summary.includes(`independent=true, emergency=false, sha256=${DIGEST}`),
    );
    assert.match(
      summary,
      /step conclusion is an assessment, not a native cleanup witness/u,
    );
    for (const status of ["BLOCKED", "FAIL"]) {
      const cause = {
        code:
          status === "BLOCKED"
            ? "prerequisite-unavailable"
            : "missing-observation",
        detail: "Synthetic native command observation unavailable.",
      };
      Object.assign(command, { status, cause, evidence: null });
      const result = await runFeasibilityExperiment(argumentsList, options),
        record = result.report.results.find(
          (entry) => entry.capability === command.capability,
        );
      assert.equal(result.status, status);
      assert.deepEqual(record.cause, cause);
      assert.deepEqual(record.components, command.components);
      assert.equal(record.cleanup.status, "PASS");
    }
    Object.assign(
      command,
      completed.report.results.find(
        (entry) => entry.capability === command.capability,
      ),
    );
    native[0].status = "FAIL";
    native[0].cause = {
      code: "setup-failed",
      detail: "Observed fixture setup failed.",
    };
    const failedNative = await runFeasibilityExperiment(argumentsList, options);
    assert.equal(failedNative.status, "FAIL");
    assert.deepEqual(failedNative.report.results[0].cause, native[0].cause);
    assert.deepEqual(
      failedNative.report.results[0].components,
      native[0].components,
    );
    assert.equal(
      failedNative.report.results.find(
        (entry) => entry.capability === command.capability,
      ).status,
      "PASS",
    );
    native[0].status = "PASS";
    native[0].cause = null;
    for (const cleanup of [
      {
        ...native[0].cleanup,
        status: "UNCERTAIN",
        cause: {
          code: "cleanup-unobserved",
          detail: "Synthetic native cleanup remains unsettled.",
        },
      },
      { ...native[0].cleanup, emergency: true },
    ]) {
      native[0].cleanup = cleanup;
      const result = await runFeasibilityExperiment(argumentsList, {
        ...options,
        runProviders: async () =>
          assert.fail(
            "Uncertain or emergency native cleanup must prevent provider admission.",
          ),
      });
      assert.equal(result.status, "FAIL");
      assert.equal(
        result.report.results.find(
          (entry) => entry.capability === command.capability,
        ).cause.code,
        "prerequisite-unavailable",
      );
    }
  }
});

test("model-free client fixes authority and reports unsupported routes without model RPCs", async () => {
  const output = new PassThrough(),
    errorOutput = new PassThrough(),
    methods = [];
  const input = new Writable({
    write(chunk, encoding, done) {
      const value = JSON.parse(chunk.toString());
      methods.push(value.method);
      if (value.id)
        output.write(
          JSON.stringify({
            id: value.id,
            ...(value.method === "initialize"
              ? { result: {} }
              : { error: { code: -32601 } }),
          }) + "\n",
        );
      done();
    },
    final(done) {
      output.end();
      errorOutput.end();
      done();
    },
  });
  const client = openFeasibilityCommand({ input, output, errorOutput });
  await client.initialize();
  const parameters = feasibilityCommandParameters(
    ["fixture"],
    "/synthetic/workspace",
    "workspace-write",
  );
  assert.equal(parameters.sandboxPolicy.networkAccess, false);
  assert.equal(parameters.sandboxPolicy.excludeSlashTmp, true);
  assert.throws(
    () =>
      feasibilityCommandParameters(
        ["fixture"],
        "/synthetic",
        "externalSandbox",
      ),
    FeasibilityError,
  );
  await assert.rejects(client.exec(parameters), (error) => {
    assert.equal(error.code, "ERR_FEASIBILITY_ROUTE_UNAVAILABLE");
    const failure = feasibilityCommandError(
      "command",
      "command-execution",
      error,
    );
    assert.equal(
      unavailableFeasibilityResults("linux", failure.feasibilityCause)[0]
        .status,
      "BLOCKED",
    );
    return true;
  });
  await client.close();
  assert.deepEqual(methods, ["initialize", "initialized", "command/exec"]);
  const controller = new AbortController(),
    abortedOutput = new PassThrough(),
    abortedErrors = new PassThrough();
  const waitingInput = new Writable({
    write(chunk, encoding, done) {
      const value = JSON.parse(chunk.toString());
      if (value.method === "initialize")
        abortedOutput.write(
          JSON.stringify({ id: value.id, result: {} }) + "\n",
        );
      done();
    },
    final(done) {
      abortedOutput.end();
      abortedErrors.end();
      done();
    },
  });
  const waiting = openFeasibilityCommand(
    { input: waitingInput, output: abortedOutput, errorOutput: abortedErrors },
    controller.signal,
  );
  await waiting.initialize();
  const pending = waiting.exec(parameters);
  controller.abort();
  await assert.rejects(pending, { code: "ERR_FEASIBILITY_DEADLINE" });
  await assert.rejects(waiting.close());
});

test("command diagnostics preserve unavailable prerequisites without masking admission failures", () => {
  const missing = feasibilityCommandError("command", "tool-version", {
    code: "ENOENT",
  });
  assert.equal(
    unavailableFeasibilityResults("linux", missing.feasibilityCause)[0].status,
    "BLOCKED",
  );
  const rejected = feasibilityCommandError(
    "admission",
    "command-receipt-registration",
    { code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE" },
  );
  assert.equal(
    unavailableFeasibilityResults("linux", rejected.feasibilityCause)[0].status,
    "FAIL",
  );
  assert.match(
    rejected.feasibilityCause.detail,
    /^admission command-receipt-registration: exit=unknown/u,
  );
  assert.deepEqual(
    feasibilityCommandError("command", "command-execution", rejected)
      .feasibilityCause,
    rejected.feasibilityCause,
  );
});

test("protected prerequisites and actual tool/native joins cannot be replaced by transport success", () => {
  const dispatch = {
      platform: "linux",
      expectedSha: SHA,
      protectedAcceptance: true,
    },
    authorization = {
      candidateSha: SHA,
      reviewedCandidate: true,
      environmentProtected: true,
      modelUseAuthorized: true,
      codex: {},
      claude: {},
    },
    admission = {
      candidateSha: SHA,
      independent: true,
      nativeSha256: DIGEST,
      privateTransport: true,
      credentialCustody: true,
      authorityProtected: true,
      cleanupDemonstrated: true,
      positiveControls: true,
      disabledIntegrations: true,
    };
  assert.equal(
    protectedFeasibilityReadiness(dispatch, authorization, admission),
    null,
  );
  for (const name of [
    "privateTransport",
    "credentialCustody",
    "authorityProtected",
    "cleanupDemonstrated",
  ])
    assert.equal(
      typeof protectedFeasibilityReadiness(dispatch, authorization, {
        ...admission,
        [name]: false,
      }),
      "string",
    );
  assert.equal(
    typeof protectedFeasibilityReadiness(
      { ...dispatch, platform: "win32" },
      authorization,
      { ...admission, transport: "http-loopback" },
    ),
    "string",
  );
  const recipe = {
    id: "outside-command",
    permit: false,
    operation: "write",
    tool: { type: "commandExecution", command: "fixed attempt" },
  };
  assert.throws(
    () =>
      assertFeasibilityToolEvidence(
        "codex",
        recipe,
        { items: [] },
        { independent: true },
        [],
      ),
    FeasibilityError,
  );
  assert.equal(feasibilityRuntimeMembers("claude", "win32").length, 1);
});

test("protected tool evidence joins the actual tool ID/input to native denial and protected upstream receipts", () => {
  const input = { file_path: "/synthetic/outside", content: "denied" };
  const recipe = {
    id: "outside-file",
    permit: false,
    operation: "write",
    tool: { name: "Write", input },
  };
  const turn = {
    tools: [
      {
        id: "tool-1",
        messageId: "msg-1",
        name: "Write",
        input,
        result: { isError: true },
      },
    ],
  };
  const observed = {
    caseId: recipe.id,
    toolId: "tool-1",
    independent: true,
    positiveControl: true,
    attemptAcknowledged: true,
    nativeSha256: DIGEST,
    outcome: "DENIED",
    sentinelsBeforeSha256: DIGEST,
    sentinelsAfterSha256: DIGEST,
  };
  const receipts = [
    {
      completed: true,
      requestSha256: DIGEST,
      responseSha256: DIGEST,
      messageId: "msg-1",
      toolUses: [
        {
          id: "tool-1",
          name: "Write",
          inputSha256: observationDigest({
            content: input.content,
            file_path: input.file_path,
          }),
        },
      ],
    },
  ];
  assert.doesNotThrow(() =>
    assertFeasibilityToolEvidence("claude", recipe, turn, observed, receipts),
  );
  for (const change of [
    { toolId: "other-tool" },
    { attemptAcknowledged: false },
    { sentinelsAfterSha256: "c".repeat(64) },
  ])
    assert.throws(
      () =>
        assertFeasibilityToolEvidence(
          "claude",
          recipe,
          turn,
          { ...observed, ...change },
          receipts,
        ),
      FeasibilityError,
    );
  const substituted = structuredClone(receipts);
  substituted[0].toolUses[0].inputSha256 = "c".repeat(64);
  assert.throws(
    () =>
      assertFeasibilityToolEvidence(
        "claude",
        recipe,
        turn,
        observed,
        substituted,
      ),
    FeasibilityError,
  );
});

test("protected cleanup requires fresh bound retirement and preserves unsettled or changed sentinels", () => {
  const dispatch = {
      expectedSha: SHA,
      provider: "codex",
      profile: "read-only",
    },
    nonce = "c".repeat(32);
  const retired = {
    status: "RETIRED",
    candidateSha: SHA,
    nonce,
    independent: true,
    emergency: false,
    provider: dispatch.provider,
    profile: dispatch.profile,
    nativeSha256: DIGEST,
    sentinelsBeforeSha256: DIGEST,
    sentinelsAfterSha256: DIGEST,
  };
  const cleanup = {
    status: "PASS",
    candidateSha: SHA,
    nonce,
    provider: dispatch.provider,
    profile: dispatch.profile,
    independent: true,
    emergency: false,
    witnessSha256: DIGEST,
  };
  assert.doesNotThrow(() =>
    assertProtectedFeasibilityCleanup(dispatch, nonce, retired, cleanup),
  );
  for (const change of [
    { status: "ACTIVE" },
    { candidateSha: "d".repeat(40) },
    { nonce: "d".repeat(32) },
    { provider: "claude" },
    { profile: "workspace-write" },
    { independent: false },
    { emergency: true },
    { sentinelsAfterSha256: "d".repeat(64) },
  ])
    assert.throws(
      () =>
        assertProtectedFeasibilityCleanup(
          dispatch,
          nonce,
          { ...retired, ...change },
          cleanup,
        ),
      FeasibilityError,
    );
  for (const change of [
    { status: "FAIL" },
    { status: "UNCERTAIN" },
    { nonce: "d".repeat(32) },
    { provider: "claude" },
    { profile: "workspace-write" },
    { emergency: true },
    { witnessSha256: null },
  ])
    assert.throws(
      () =>
        assertProtectedFeasibilityCleanup(dispatch, nonce, retired, {
          ...cleanup,
          ...change,
        }),
      FeasibilityError,
    );
});

test("Codex command items join native literal scripts separately from rendered shell argv", () => {
  const command = "cat '/synthetic/workspace/inspection.txt'",
    cwd = "/synthetic/workspace";
  const recipe = {
    id: "inspect",
    permit: true,
    operation: "read",
    contents: "fixture-nonce",
    tool: { type: "commandExecution", command, cwd },
  };
  const item = {
    id: "tool-1",
    type: "commandExecution",
    cwd,
    source: "unifiedExecStartup",
    command: "/bin/sh -c \"cat '/synthetic/workspace/inspection.txt'\"",
    status: "completed",
    exitCode: 0,
  };
  // The native owner hashes raw script/display bytes, rather than serialized JSON.
  const bytesDigest = (value) =>
    createHash("sha256").update(value).digest("hex");
  const observed = {
    caseId: recipe.id,
    toolId: item.id,
    independent: true,
    positiveControl: true,
    attemptAcknowledged: true,
    nativeSha256: DIGEST,
    outcome: "PERMITTED",
    sentinelsBeforeSha256: DIGEST,
    sentinelsAfterSha256: DIGEST,
    commandSha256: bytesDigest(item.command),
    scriptSha256: bytesDigest(command),
    contentsSha256: bytesDigest(recipe.contents),
  };
  const turn = { threadId: "thread-1", turnId: "turn-1", items: [item] };
  const receipts = [
    {
      threadId: turn.threadId,
      turnId: turn.turnId,
      completed: true,
      requestSha256: DIGEST,
      responseSha256: DIGEST,
    },
  ];
  assert.doesNotThrow(() =>
    assertFeasibilityToolEvidence("codex", recipe, turn, observed, receipts),
  );
  for (const change of [
    { scriptSha256: "d".repeat(64) },
    { commandSha256: "d".repeat(64) },
  ])
    assert.throws(
      () =>
        assertFeasibilityToolEvidence(
          "codex",
          recipe,
          turn,
          { ...observed, ...change },
          receipts,
        ),
      FeasibilityError,
    );
  for (const change of [
    { threadId: "other-thread" },
    { turnId: "other-turn" },
    { threadId: null },
    { turnId: null },
  ])
    assert.throws(
      () =>
        assertFeasibilityToolEvidence("codex", recipe, turn, observed, [
          { ...receipts[0], ...change },
        ]),
      FeasibilityError,
    );
});

test("data-only feasibility preflight rejects traversal, links and duplicate members before extraction", async () => {
  const archive = (name, type = "0", duplicate = false) => {
    const header = Buffer.alloc(512);
    header.write(name);
    header.write("0000644\0", 100);
    header.write("00000000003\0", 124);
    header.fill(32, 148, 156);
    header.write(type, 156);
    header.write("ustar\0", 257);
    const sum = header.reduce((total, byte) => total + byte, 0);
    header.write(sum.toString(8).padStart(6, "0") + "\0 ", 148);
    const member = Buffer.concat([
      header,
      Buffer.from("abc"),
      Buffer.alloc(509),
    ]);
    return gzipSync(
      Buffer.concat([
        member,
        ...(duplicate ? [member] : []),
        Buffer.alloc(1024),
      ]),
    );
  };
  const files = await preflightNativeTar([archive("package/runtime")]);
  assert.equal(files[0].bytes, 3);
  await assert.rejects(
    materializeReviewedTar(
      [archive("package/runtime")],
      files,
      async () => null,
    ),
  );
  for (const bytes of [
    archive("../runtime"),
    archive("package/runtime", "2"),
    archive("package/runtime", "0", true),
  ])
    await assert.rejects(preflightNativeTar([bytes]));
  const members = Array.from(
    { length: NATIVE_PACKAGE_LIMITS.members + 1 },
    (_, index) => {
      const header = Buffer.alloc(512);
      header.write(`runtime-${index}`);
      header.write("0000644\0", 100);
      header.write("00000000000\0", 124);
      header.fill(32, 148, 156);
      header.write("0", 156);
      header.write("ustar\0", 257);
      header.write(
        header
          .reduce((sum, byte) => sum + byte, 0)
          .toString(8)
          .padStart(6, "0") + "\0 ",
        148,
      );
      return header;
    },
  );
  await assert.rejects(
    preflightNativeTar([
      gzipSync(Buffer.concat([...members, Buffer.alloc(1024)])),
    ]),
  );
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

test("Linux namespace diagnostics retain actual outcomes without changing public isolation probes", () => {
  for (const ownershipMode of ["ordinary", "native-sandbox-provider"]) {
    for (const [result, code, outcome, explanation] of [
      [
        {
          status: 1,
          signal: null,
          stderr:
            "bwrap: Creating new namespace failed: Operation not permitted\npassword=private",
        },
        "prerequisite-unavailable",
        "exit=1, signal=none, timeout=false",
        /namespace creation failure/u,
      ],
      [
        { status: 1, signal: null },
        "prerequisite-unavailable",
        "exit=1, signal=none, timeout=false",
        /output=absent; No native output was captured/u,
      ],
      [
        { status: 1, signal: null, stderr: "private unrecognized output" },
        "prerequisite-unavailable",
        "exit=1, signal=none, timeout=false",
        /output=unrecognized; Native output was captured/u,
      ],
      [
        { status: null, signal: null, error: { code: "ENOBUFS" } },
        "setup-failed",
        "exit=unknown, signal=none, timeout=unknown",
        /native=ENOBUFS; The native operation reported insufficient buffer space/u,
      ],
      [
        { status: null, signal: "SIGSEGV" },
        "crash",
        "exit=unknown, signal=SIGSEGV, timeout=false",
      ],
      [
        { status: null, signal: "SIGTERM", error: { code: "ETIMEDOUT" } },
        "deadline",
        "exit=unknown, signal=SIGTERM, timeout=true",
      ],
    ]) {
      assert.throws(
        () =>
          resolveLinuxDiagnosticLauncher("/fixture/workspace", {
            bubblewrap: "/fixture/bwrap",
            namespaceId: "pid:[4026531836]",
            ownershipMode,
            protect: () => {},
            probe(file, vector, options) {
              assert.equal(file, "/fixture/bwrap");
              assert.equal(options.timeout, 10000);
              assert.equal(options.maxBuffer, 65536);
              assert.deepEqual(options.stdio, ["ignore", "pipe", "pipe"]);
              assert.equal(options.encoding, "utf8");
              assert.deepEqual(options.env, {
                PATH: "/usr/bin:/bin",
                LANG: "C",
              });
              assert.deepEqual(vector, [
                "--die-with-parent",
                "--unshare-pid",
                "--as-pid-1",
                ownershipMode === "ordinary" ? "--ro-bind" : "--bind",
                "/",
                "/",
                "--dev",
                "/dev",
                "--proc",
                "/proc",
                "--chdir",
                "/",
                "--",
                ...(ownershipMode === "ordinary"
                  ? []
                  : [
                      file,
                      "--new-session",
                      "--die-with-parent",
                      "--unshare-user",
                      "--unshare-pid",
                      "--unshare-net",
                      "--as-pid-1",
                      "--cap-drop",
                      "ALL",
                      "--ro-bind",
                      "/",
                      "/",
                      "--dev",
                      "/dev",
                      "--proc",
                      "/proc",
                      "--",
                    ]),
                "/bin/true",
              ]);
              return result;
            },
          }),
        (error) => {
          assert.equal(error.code, "ERR_EXECUTION_PROCESS_UNVERIFIABLE");
          assert.equal(error.feasibilityCause.code, code);
          assert.ok(error.feasibilityCause.detail.includes(outcome));
          assert.ok(
            error.feasibilityCause.detail.startsWith(
              `admission ${ownershipMode === "ordinary" ? "ordinary-namespace" : "nested-namespaces"}:`,
            ),
          );
          if (explanation)
            assert.match(error.feasibilityCause.detail, explanation);
          assert.doesNotMatch(
            JSON.stringify(error.feasibilityCause),
            /password|private|\/fixture/u,
          );
          return true;
        },
      );
    }
  }
  for (const operation of [
    "launcher-discovery-protection",
    "launcher-protection",
  ]) {
    assert.throws(
      () =>
        resolveLinuxDiagnosticLauncher("/fixture/workspace", {
          resolve: () => {
            if (operation === "launcher-discovery-protection")
              throw { code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE" };
            return {
              file: "/fixture/bwrap",
              isolatedNamespace: true,
              hostSession: false,
            };
          },
          protect: () => {
            throw { code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE" };
          },
        }),
      (error) => {
        assert.match(
          error.feasibilityCause.detail,
          new RegExp(
            `^admission ${operation}: exit=unknown, signal=unknown, timeout=unknown;`,
            "u",
          ),
        );
        return true;
      },
    );
  }
});

test("Linux fixed resolver failures preserve native preparation, controller and model-free first causes", async () => {
  const nonce = "11111111-1111-4111-8111-111111111111";
  const cleanup = {
    code: "cleanup-unobserved",
    detail: "No independent retirement witness was available.",
  };
  for (const [diagnostic, code, native] of [
    [
      "setting up uid map: Permission denied",
      "prerequisite-unavailable",
      "EACCES",
    ],
    [
      "Failed to make / slave: Permission denied",
      "prerequisite-unavailable",
      "EACCES",
    ],
    [
      "Creating new namespace failed: Invalid argument",
      "prerequisite-unavailable",
      "EINVAL",
    ],
    ["setting up gid map: Invalid argument", "setup-failed", "EINVAL"],
    [
      "Can't mount tmpfs on /fixture/private: Invalid argument",
      "setup-failed",
      "EINVAL",
    ],
    ["execvp /fixture/private: Exec format error", "setup-failed", "ENOEXEC"],
    ["Unknown option --synthetic", "setup-failed", null],
    ["--ro-bind takes two arguments", "setup-failed", null],
  ]) {
    for (const phase of ["prepare", "admission"]) {
      let probes = 0,
        failure;
      const probe = (file, vector, options) => {
        probes++;
        assert.equal(file, "/fixture/bwrap");
        assert.deepEqual(vector, [
          "--die-with-parent",
          "--unshare-pid",
          "--as-pid-1",
          "--ro-bind",
          "/",
          "/",
          "--dev",
          "/dev",
          "--proc",
          "/proc",
          "--chdir",
          "/",
          "--",
          "/bin/true",
        ]);
        assert.equal(options.timeout, 10000);
        assert.equal(options.maxBuffer, 65536);
        assert.deepEqual(options.stdio, ["ignore", "pipe", "pipe"]);
        assert.deepEqual(options.env, { PATH: "/usr/bin:/bin", LANG: "C" });
        // Recognition must fall through the first unrecognized stream.
        return {
          status: 1,
          signal: null,
          stderr: "private output",
          stdout: `bwrap: ${diagnostic}`,
        };
      };
      const inspectFailure = (error) => {
        failure = error;
        assert.equal(error.feasibilityCause.code, code);
        assert.ok(
          error.feasibilityCause.detail.startsWith(
            `${phase} ordinary-namespace:`,
          ),
        );
        assert.match(
          error.feasibilityCause.detail,
          /exit=1, signal=none, timeout=false; output=recognized/u,
        );
        if (native)
          assert.ok(
            error.feasibilityCause.detail.includes(`native=${native};`),
          );
        if (code === "prerequisite-unavailable")
          assert.match(
            error.feasibilityCause.detail,
            /compatible Ubuntu 24\.04 x64 hosted worker for ordinary and nested probes\./u,
          );
        else
          assert.doesNotMatch(
            error.feasibilityCause.detail,
            /Require a compatible/u,
          );
        assert.ok(Buffer.byteLength(error.feasibilityCause.detail) <= 256);
        return true;
      };
      if (phase === "prepare") {
        await assert.rejects(
          prepareLinuxFixture("/fixture/workspace", {
            fs: {
              realpath: async (file) =>
                file.endsWith("bwrap") ? "/fixture/bwrap" : file,
              lstat: async () => ({ isFile: () => true, nlink: 1 }),
              access: async () => {},
            },
            protect: () => {},
            resolveLauncher: (cwd, options) =>
              resolveOwnedProcessLauncher(cwd, {
                ...options,
                namespaceId: "pid:[4026531836]",
              }),
            probe,
            procVisibility: () =>
              assert.fail(
                "A failed namespace probe cannot reach procfs or fixture effects.",
              ),
          }),
          inspectFailure,
        );
        assert.equal(
          failure.prerequisites.failedPrerequisite,
          "ordinary-namespace",
        );
        assert.equal(
          failure.prerequisites.checks[3].diagnosis,
          code === "prerequisite-unavailable" ? "probe-failed" : "unverifiable",
        );
        assert.ok(
          failure.prerequisites.checks
            .slice(4)
            .every(({ status }) => status === "NOT_RUN"),
        );
      } else {
        assert.throws(
          () =>
            resolveLinuxDiagnosticLauncher("/fixture/workspace", {
              bubblewrap: "/fixture/bwrap",
              namespaceId: "pid:[4026531836]",
              protect: () =>
                assert.fail(
                  "Refused namespace admission cannot reach protection or payload execution.",
                ),
              probe,
            }),
          inspectFailure,
        );
      }
      assert.equal(probes, 1);
      const received = normalizeLinuxControllerFailure(
        JSON.parse(
          JSON.stringify(linuxControllerFailure(SHA, nonce, failure, cleanup)),
        ),
        SHA,
        nonce,
      );
      const command = feasibilityCommandError("command", "tool-version", {
        feasibilityCause: received.cause,
        feasibilityCleanupCause: received.cleanupCause,
      });
      assert.deepEqual(command.feasibilityCause, failure.feasibilityCause);
      assert.deepEqual(command.feasibilityCleanupCause, cleanup);
      assert.deepEqual(
        linuxFeasibilityCause("controller", command),
        failure.feasibilityCause,
      );
      assert.equal(
        unavailableFeasibilityResults("linux", command.feasibilityCause)[0]
          .status,
        code === "setup-failed" ? "FAIL" : "BLOCKED",
      );
      assert.doesNotMatch(
        JSON.stringify(received),
        /\/fixture|private|synthetic|kernel|AppArmor/u,
      );
    }
  }
});

test("a successful fixed Linux probe cannot mask a subsequent launcher protection failure", () => {
  assert.throws(
    () =>
      resolveLinuxDiagnosticLauncher("/fixture/workspace", {
        bubblewrap: "/fixture/bwrap",
        namespaceId: "pid:[4026531836]",
        probe: () => ({ status: 0, signal: null, stdout: "private output" }),
        protect: () => {
          throw Object.assign(new Error("private failure"), { code: "EACCES" });
        },
      }),
    (error) => {
      assert.equal(error.feasibilityCause.code, "setup-failed");
      assert.match(
        error.feasibilityCause.detail,
        /^admission launcher-protection: exit=unknown, signal=unknown, timeout=unknown; output=absent, native=EACCES/u,
      );
      return true;
    },
  );
});

test("Linux fixture resolver failures before probing retain construction attribution and native classes", async () => {
  for (const failedMode of ["ordinary", "native-sandbox-provider"]) {
    for (const code of ["EACCES", "ERR_EXECUTION_PROCESS_UNVERIFIABLE"]) {
      let probes = 0;
      await assert.rejects(
        prepareLinuxFixture("/fixture/workspace", {
          captureDiagnostics: true,
          fs: {
            realpath: async (file) => file,
            lstat: async () => ({ isFile: () => true, nlink: 1 }),
            access: async () => {},
            readFile: async () => Buffer.from("synthetic launcher bytes"),
          },
          protect: () => {},
          executeFile: async () => ({ stdout: "bubblewrap 0.11.0\n" }),
          procVisibility: async () => {},
          resolveLauncher(cwd, options) {
            if (options.ownershipMode === failedMode)
              throw Object.assign(new Error("private resolver exception"), {
                code,
                exitCode: 7,
                signal: "SIGKILL",
                timedOut: true,
                stderr:
                  "bwrap: Creating new namespace failed: Operation not permitted",
              });
            return resolveLinuxDiagnosticLauncher(cwd, {
              ...options,
              namespaceId: null,
              protect: () => {},
            });
          },
          probe: () => {
            probes++;
            return { status: 0, signal: null };
          },
        }),
        (error) => {
          const ordinary = failedMode === "ordinary";
          const prerequisite = ordinary
            ? "ordinary-namespace"
            : "nested-namespaces";
          const check = error.prerequisites.checks.find(
            ({ id }) => id === prerequisite,
          );
          assert.equal(error.prerequisites.failedPrerequisite, prerequisite);
          assert.deepEqual(check.observation, {
            errno: code === "EACCES" ? code : null,
            exitCode: null,
            signal: null,
            timedOut: null,
          });
          assert.equal(probes, ordinary ? 0 : 1);
          assert.equal(error.feasibilityCause.code, "setup-failed");
          assert.match(
            error.feasibilityCause.detail,
            /exit=unknown, signal=unknown, timeout=unknown; output=absent/u,
          );
          assert.ok(
            error.feasibilityCause.detail.startsWith(
              `prepare ${ordinary ? "ordinary" : "nested"}-launcher-construction:`,
            ),
          );
          assert.ok(error.feasibilityCause.detail.includes(`native=${code};`));
          assert.equal(error.feasibilityComponents[0].name, "bubblewrap");
          assert.ok(
            error.prerequisites.checks
              .slice(ordinary ? 4 : 6)
              .every(({ status }) => status === "NOT_RUN"),
          );
          assert.doesNotMatch(
            JSON.stringify(error.feasibilityCause),
            /private|\/fixture/u,
          );
          return true;
        },
      );
    }
  }
});

test("Linux failed fixture diagnostics retain installed identity without extending acceptance prerequisites", async () => {
  const bytes = Buffer.from("synthetic launcher bytes");
  const component = {
    role: "tool",
    name: "bubblewrap",
    version: "bubblewrap 0.9.0",
    sha256: createHash("sha256").update(bytes).digest("hex"),
  };
  for (const [version, components, stderr, explanation] of [
    [
      component.version,
      [component],
      "bwrap: setting up uid map: Permission denied",
      /native=EACCES; Bubblewrap reported a UID or GID mapping failure\./u,
    ],
    [
      component.version,
      [component],
      "bwrap: Creating new namespace failed: Operation not permitted",
      /native=EPERM; Bubblewrap reported a namespace creation failure\./u,
    ],
    [
      `bubblewrap ${"1".repeat(120)}.1.1`,
      [],
      "bwrap: Creating new namespace failed: Operation not permitted",
      /namespace creation failure/u,
    ],
  ]) {
    await assert.rejects(
      prepareLinuxFixture("/fixture/workspace", {
        captureDiagnostics: true,
        fs: {
          realpath: async (file) => file,
          lstat: async () => ({ isFile: () => true, nlink: 1 }),
          access: async () => {},
          readFile: async () => bytes,
        },
        protect: () => {},
        resolveLauncher: (cwd, options) =>
          resolveLinuxDiagnosticLauncher(cwd, {
            ...options,
            namespaceId: null,
            protect: () => {},
          }),
        executeFile: async () => ({ stdout: version + "\n" }),
        probe: () => ({
          status: 1,
          signal: null,
          stderr,
        }),
      }),
      (error) => {
        assert.deepEqual(Object.keys(error.prerequisites).sort(), [
          "checks",
          "failedPrerequisite",
          "schemaVersion",
          "status",
        ]);
        assert.equal(
          error.prerequisites.failedPrerequisite,
          "ordinary-namespace",
        );
        assert.ok(
          error.prerequisites.checks
            .slice(4)
            .every((check) => check.status === "NOT_RUN"),
        );
        assert.match(
          error.feasibilityCause.detail,
          /^prepare ordinary-namespace: exit=1/u,
        );
        assert.equal(error.feasibilityCause.code, "prerequisite-unavailable");
        assert.match(error.feasibilityCause.detail, explanation);
        assert.deepEqual(error.prerequisites.checks[3].observation, {
          errno: null,
          exitCode: 1,
          signal: null,
          timedOut: false,
        });
        assert.deepEqual(error.feasibilityComponents, components);
        return true;
      },
    );
  }
});

test("Linux controller failures bind safe first and cleanup causes to the candidate and nonce", () => {
  const nonce = "11111111-1111-4111-8111-111111111111";
  const first = linuxDiagnosticError("admission", "receipt-registration", {
    code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
    killed: true,
    message: "private transcript",
  });
  const cleanup = {
    code: "cleanup-unobserved",
    detail: "No independent retirement witness was available.",
  };
  const message = linuxControllerFailure(SHA, nonce, first, cleanup);
  const received = normalizeLinuxControllerFailure(
    JSON.parse(JSON.stringify(message)),
    SHA,
    nonce,
  );
  assert.deepEqual(received.cause, first.feasibilityCause);
  assert.deepEqual(received.cleanupCause, cleanup);
  assert.deepEqual(
    linuxFeasibilityCause("settle", { feasibilityCause: received.cause }),
    first.feasibilityCause,
  );
  assert.match(
    received.cause.detail,
    /exit=unknown, signal=unknown, timeout=unknown/u,
  );
  assert.doesNotMatch(JSON.stringify(received), /transcript|private/u);
  for (const changed of [
    { candidateSha: "c".repeat(40) },
    { nonce: "22222222-2222-4222-8222-222222222222" },
    { stdout: "unowned output" },
    {
      cleanupCause: {
        code: "setup-failed",
        detail: "Foreign cleanup classification.",
      },
    },
    {
      cause: {
        code: "setup-failed",
        detail: "https://example.invalid/private",
      },
    },
  ])
    assert.throws(() =>
      normalizeLinuxControllerFailure({ ...message, ...changed }, SHA, nonce),
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

test("Darwin experiment policy confines grants and literal quoting without activating native effects", async () => {
  const root = '/fixture/quote"value';
  const readOnly = darwinFeasibilityPolicy(root);
  const editing = darwinFeasibilityPolicy(root, true);
  assert.ok(readOnly.includes("(deny default)"));
  assert.ok(readOnly.includes('quote\\"value/workspace'));
  assert.ok(!readOnly.includes("workspace/edited.txt"));
  assert.ok(editing.includes("workspace/edited.txt"));
  for (const privateName of [
    "control",
    "outside",
    "evidence",
    "storage-private",
    "storage-substitution",
  ])
    assert.ok(!editing.includes(`${privateName}/`));
  assert.ok(!editing.includes("network-outbound"));
  for (const invalid of [
    "/",
    "/fixture/../other",
    "/fixture\nother",
    "/usr/lib/fixture",
    "/System/Library/fixture",
    "/fixture\ud800",
  ])
    assert.throws(() => darwinFeasibilityPolicy(invalid));
  if (process.platform !== "darwin")
    await assert.rejects(
      runDarwinFeasibility({ expectedSha: SHA, checkoutSha: SHA }),
      { code: "ERR_NATIVE_FEASIBILITY_WORKER_UNAVAILABLE" },
    );
});

test("Darwin fault assessment never promotes recorded process retirement into domain recovery", () => {
  const identity = {
    pid: 42,
    pidVersion: 7,
    asid: 2,
    auid: 501,
    uid: 501,
    gid: 20,
    ruid: 501,
    rgid: 20,
    svuid: 501,
    svgid: 20,
    startSeconds: 100,
    startMicroseconds: 9,
  };
  assert.deepEqual(darwinFeasibilityIdentityArguments(identity), [
    "501",
    "501",
    "20",
    "501",
    "20",
    "42",
    "2",
    "7",
    "100",
    "9",
    "501",
    "20",
  ]);
  assert.throws(() =>
    darwinFeasibilityIdentityArguments({ ...identity, pidVersion: 0 }),
  );
  const retired = { status: "RETIRED" };
  assert.equal(
    assessDarwinFeasibilityDomain([retired, retired]).status,
    "BLOCKED",
  );
  assert.equal(
    assessDarwinFeasibilityDomain([retired, { status: "LIVE" }]).cause.code,
    "observed-escape",
  );
  for (const observations of [[], [retired], [retired, { status: "EXITED" }]])
    assert.throws(() => assessDarwinFeasibilityDomain(observations));
  const input = report(),
    entry = input.results.find(
      ({ capability }) => capability === "ownership.cancel",
    );
  entry.status = "BLOCKED";
  entry.cause = {
    code: "prerequisite-unavailable",
    detail: "The required native observation interface is unavailable.",
  };
  entry.evidence = null;
  entry.cleanup.status = "UNCERTAIN";
  entry.cleanup.cause = {
    code: "cleanup-unobserved",
    detail: "Recorded fixture cleanup did not settle.",
  };
  const assessed = assessFeasibilityReport(input).report.results.find(
    ({ capability }) => capability === entry.capability,
  );
  assert.equal(assessed.status, "FAIL");
  assert.equal(assessed.cause.code, "prerequisite-unavailable");
  assert.equal(assessed.cleanup.cause.code, "cleanup-unobserved");
});

test("Darwin dispatch requires a matching worker and a complete native owner report", async () => {
  const darwinArgs = ["--platform", "darwin", "--expected-sha", SHA];
  const darwinHost = { ...host, platform: "darwin", runnerOs: "macOS" };
  let dispatched = false;
  const options = {
    host: darwinHost,
    observe: async () => ({
      checkoutSha: SHA,
      os: "darwin",
      build: "synthetic-build",
      architecture: "x64",
    }),
    runNative: async (request) => {
      dispatched = true;
      assert.equal(request.platform, "darwin");
      return [];
    },
  };
  await assert.rejects(
    runFeasibilityExperiment(darwinArgs, { ...options, host }),
    FeasibilityError,
  );
  assert.equal(dispatched, false);
  const missing = await runFeasibilityExperiment(darwinArgs, options);
  assert.equal(dispatched, true);
  assert.equal(missing.report.results[0].cause.code, "missing-record");
  assert.ok(
    missing.report.results
      .filter(({ capability }) => capability.startsWith("codex."))
      .every(({ status }) => status === "BLOCKED"),
  );
});

test("Darwin native transcripts reject trailing, extra, malformed and oversized evidence", () => {
  const ready = '{"event":"ready"}\n';
  assert.doesNotThrow(() => assertDarwinFeasibilityTranscript(ready, 1));
  for (const transcript of [
    ready + "unfinished",
    ready + ready,
    ready + "invalid\n",
    ready + '"' + "x".repeat(65536) + '"\n',
  ])
    assert.throws(() => assertDarwinFeasibilityTranscript(transcript, 1));
  assert.throws(() =>
    assertDarwinFeasibilityTranscript(ready + "invalid\n", 2),
  );
});

test("Windows feasibility separates surviving Job custody from final-handle retirement", () => {
  const identity = (pid) => ({
    pid,
    creationTime: "100",
    sessionId: 1,
    userSid: "S-1-5-21-101",
  });
  const expected = [identity(42), identity(43)];
  const holder = {
    event: "witness-ready",
    owner: identity(44),
    child: expected[0],
    process: "16",
    members: expected,
    jobHeld: true,
    job: "12",
  };
  const final = { ...holder, jobHeld: false, job: "0" };
  assert.doesNotThrow(() =>
    assertWindowsFeasibilityWitness("holder", holder, expected, {
      retired: true,
      jobEmpty: true,
    }),
  );
  assert.doesNotThrow(() =>
    assertWindowsFeasibilityWitness("final", final, expected, {
      retired: true,
      jobHeld: false,
    }),
  );
  assert.doesNotThrow(() =>
    assertWindowsFeasibilityWitness("holder", holder, expected),
  );
  for (const [kind, ready, identities, settled] of [
    ["holder", holder, expected, { retired: false, jobEmpty: true }],
    ["holder", holder, expected, { retired: true }],
    ["final", holder, expected, { retired: true, jobHeld: true }],
    [
      "final",
      { ...final, job: "12" },
      expected,
      { retired: true, jobHeld: false },
    ],
    [
      "final",
      final,
      [identity(42), { ...identity(43), creationTime: "101" }],
      { retired: true, jobHeld: false },
    ],
    [
      "final",
      { ...final, owner: identity(42) },
      expected,
      { retired: true, jobHeld: false },
    ],
    [
      "final",
      { ...final, members: [identity(42), identity(42)] },
      expected,
      { retired: true, jobHeld: false },
    ],
    ["holder", { ...holder, child: identity(43) }, expected, undefined],
    ["holder", { ...holder, process: "0" }, expected, undefined],
    ["holder", { ...holder, job: holder.process }, expected, undefined],
    [
      "holder",
      { ...holder, members: [...expected, identity(45)] },
      expected,
      undefined,
    ],
  ])
    assert.throws(() =>
      assertWindowsFeasibilityWitness(kind, ready, identities, settled),
    );
});

test("Windows experiment loader rejects non-x64, escaping, truncated and delayed imports", () => {
  const pe = Buffer.alloc(1024),
    optional = 88,
    section = 328;
  pe.writeUInt16LE(0x5a4d);
  pe.writeUInt32LE(64, 60);
  pe.writeUInt32LE(0x4550, 64);
  pe.writeUInt16LE(0x8664, 68);
  pe.writeUInt16LE(1, 70);
  pe.writeUInt16LE(240, 84);
  pe.writeUInt16LE(0x20b, optional);
  pe.writeUInt32LE(16, optional + 108);
  pe.writeUInt32LE(4096, optional + 120);
  pe.writeUInt32LE(40, optional + 124);
  pe.writeUInt32LE(4096, section + 12);
  pe.writeUInt32LE(512, section + 16);
  pe.writeUInt32LE(512, section + 20);
  pe.writeUInt32LE(4160, 524);
  pe.write("fixture.dll\0", 576, "ascii");
  assert.deepEqual(windowsFeasibilityImports(pe), ["fixture.dll"]);
  for (const mutate of [
    (bytes) => bytes.writeUInt16LE(0xaa64, 68),
    (bytes) => bytes.write("../outside.dll\0", 576, "ascii"),
    (bytes) => bytes.writeUInt32LE(9000, 524),
    (bytes) => bytes.writeUInt32LE(1, optional + 112 + 13 * 8),
    (bytes) => bytes.writeUInt32LE(4160, 544),
    (bytes) => bytes.writeUInt32LE(75, section + 16),
  ]) {
    const changed = Buffer.from(pe);
    mutate(changed);
    assert.throws(() => windowsFeasibilityImports(changed));
  }
  assert.throws(() => windowsFeasibilityImports(pe.subarray(0, 600)));
});

test("Windows fixture tools exclude ambient Git authority while retaining native SDK setup", () => {
  const ambient = {
    Path: "native-tools",
    INCLUDE: "sdk-headers",
    LIB: "sdk-libraries",
    GIT_DIR: "foreign-repository",
    git_work_tree: "foreign-workspace",
    GIT_INDEX_FILE: "foreign-index",
    GIT_CONFIG_COUNT: "1",
    GIT_CONFIG_KEY_0: "core.hooksPath",
    GIT_CONFIG_VALUE_0: "foreign-hooks",
    GIT_EXEC_PATH: "foreign-tools",
    GIT_CONFIG_GLOBAL: "foreign-config",
  };
  assert.deepEqual(windowsFeasibilityToolEnvironment(ambient), {
    Path: "native-tools",
    INCLUDE: "sdk-headers",
    LIB: "sdk-libraries",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "NUL",
    GIT_OPTIONAL_LOCKS: "0",
    GIT_TERMINAL_PROMPT: "0",
  });
  assert.equal(ambient.GIT_DIR, "foreign-repository");
  for (const key of ["SystemRoot", "SYSTEMROOT", "systemroot"]) {
    const source = { ...ambient, [key]: "C:\\Windows" };
    const copied = windowsFeasibilityToolEnvironment(source);
    assert.equal(copied.SystemRoot, "C:\\Windows");
    assert.deepEqual(
      Object.keys(copied).filter((name) => /^systemroot$/iu.test(name)),
      ["SystemRoot"],
    );
    assert.equal(source[key], "C:\\Windows");
  }
  assert.equal(
    windowsFeasibilityToolEnvironment({
      SystemRoot: "C:\\Windows",
      SYSTEMROOT: "C:\\Windows",
    }).SystemRoot,
    "C:\\Windows",
  );
  assert.throws(() =>
    windowsFeasibilityToolEnvironment({
      SystemRoot: "C:\\Windows",
      SYSTEMROOT: "D:\\Other",
    }),
  );
});

const windowsCallerEnvironment = {
  SystemRoot: "C:\\Windows",
  LOCALAPPDATA: "C:\\Users\\Fixture User\\AppData\\Local",
};

test("Windows AppContainer helpers receive only validated caller prerequisites and fixed controls", async () => {
  const ambient = {
    ...windowsCallerEnvironment,
    CI: "false",
    GITHUB_ACTIONS: "false",
    RUNNER_ENVIRONMENT: "other-worker",
    RUNNER_OS: "other-os",
    PATH: "ambient-tools",
    USERPROFILE: "private-profile",
    APPDATA: "private-roaming",
    HOME: "private-home",
    TEMP: "private-temp",
    GIT_DIR: "private-repository",
    NATIVE_POC_TOKEN: "private-token",
  };
  const expected = {
    CI: "true",
    GITHUB_ACTIONS: "true",
    RUNNER_ENVIRONMENT: "github-hosted",
    RUNNER_OS: "Windows",
    SystemRoot: "C:\\Windows",
    PATH: "C:\\Windows\\System32",
    LOCALAPPDATA: windowsCallerEnvironment.LOCALAPPDATA,
  };
  assert.deepEqual(windowsFeasibilityCallerEnvironment(ambient), expected);
  const f = windowsSessionFixture(ambient);
  assert.deepEqual(f.options.env, expected);
  assert.equal(ambient.PATH, "ambient-tools");
  assert.equal(ambient.CI, "false");
  f.close(0);
  await f.session.finish(0);
  for (const value of [
    "d:\\Users\\Fixture User\\AppData\\Local",
    "C:\\Users\\Fixture \u03a9\\AppData\\Local",
    "C:\\Users\\Fixture \u{1f600}\\AppData\\Local",
  ]) {
    const caller = windowsFeasibilityCallerEnvironment({
      ...windowsCallerEnvironment,
      LOCALAPPDATA: value,
    });
    assert.equal(caller.LOCALAPPDATA, value);
  }
});

test("Missing or invalid Windows caller directories refuse profile and launch effects with path-free causes", () => {
  const invalid = [
    undefined,
    null,
    42,
    "",
    "private-caller-value",
    "C:private-caller-value",
    "\\private-caller-value",
    "\\\\server\\private-caller-value",
    "\\\\?\\C:\\private-caller-value",
    "C:\\",
    "C:\\private-caller-value\\..\\Local",
    "C:/private-caller-value",
    "C:\\private-caller-value\\",
    "C:\\private-caller-value ",
    "C:\\private-caller-value.",
    "C:\\private-caller-value:stream",
    "C:\\private-caller-value\\NUL",
    "C:\\private-caller-value\0suffix",
    "C:\\private-caller-value\nsuffix",
    "C:\\private-caller-value\u2028suffix",
    "C:\\private-caller-value\ud800suffix",
    'C:\\private-caller-value"suffix',
    "C:\\private-caller-value|suffix",
    "C:\\private-caller-value" + "x".repeat(4096),
  ];
  for (const key of ["LOCALAPPDATA", "SystemRoot"]) {
    for (const value of invalid) {
      for (const role of ["profile-create", "launch"]) {
        let launches = 0;
        const environment = { ...windowsCallerEnvironment, [key]: value };
        assert.throws(
          () =>
            windowsFeasibilityHelperSession(
              "C:\\fixture\\helper.exe",
              "C:\\fixture",
              "a".repeat(32),
              environment,
              role,
              [],
              { spawnProcess: () => launches++ },
            ),
          (error) => {
            const cause = windowsFeasibilityCause(
              "caller-prerequisites",
              error,
            );
            assert.equal(cause.code, "prerequisite-unavailable");
            assert.ok(cause.detail.includes(key));
            assert.match(
              cause.detail,
              /Restore the hosted worker's caller environment/u,
            );
            assert.doesNotMatch(
              JSON.stringify({ message: error.message, cause }),
              /private-caller-value|Fixture User|C:\\|private-token/u,
            );
            assert.ok(cause.detail.length <= 256);
            return true;
          },
        );
        assert.equal(launches, 0);
      }
    }
  }
});

function windowsSessionFixture(environment = windowsCallerEnvironment) {
  const child = Object.assign(new EventEmitter(), {
    pid: 42,
    stdin: new Writable({ write: (_, __, done) => done() }),
    stdout: new PassThrough(),
    stderr: new PassThrough(),
  });
  let capturedOptions;
  const session = windowsFeasibilityHelperSession(
    "C:\\fixture\\helper.exe",
    "C:\\fixture",
    "a".repeat(32),
    environment,
    "launch",
    WINDOWS_LITERAL_ARGUMENTS,
    {
      spawnProcess: (image, args, options) => {
        capturedOptions = options;
        assert.equal(image, "C:\\fixture\\helper.exe");
        assert.deepEqual(
          args.slice(3),
          WINDOWS_LITERAL_ARGUMENTS.map(quoteWindowsArgument),
        );
        assert.equal(options.windowsVerbatimArguments, true);
        assert.deepEqual(options.stdio, ["pipe", "pipe", "pipe"]);
        return child;
      },
    },
  );
  return {
    child,
    session,
    options: capturedOptions,
    close: (code = 126) => {
      child.stdout.end();
      child.stderr.end();
      child.emit("close", code, null);
    },
  };
}
const windowsDiagnostic = (operation, domain, value) =>
  `native-windows: operation=${operation} domain=${domain} value=${value}\n`;

test("Windows relayed payload failure survives owner loss without becoming a JSON stream error", async () => {
  for (const line of [
    windowsDiagnostic("git-null-input", "win32", 5),
    windowsDiagnostic("git-process-exit", "exit", 128).replace("\n", "\r\n"),
    windowsDiagnostic("git-dubious-owner", "exit", 128),
  ]) {
    const f = windowsSessionFixture();
    f.child.stdout.write('{"event":"attempt","operation":"git-status"}\n');
    assert.equal((await f.session.next()).operation, "git-status");
    const waiting = f.session.next();
    f.child.stdout.write(line.slice(0, 11));
    f.child.stdout.write(line.slice(11));
    await assert.rejects(waiting, (error) => {
      assert.equal(error.nativeStreamInvalid, undefined);
      assert.equal(error.stderr, line);
      return true;
    });
    f.child.stderr.write(
      windowsDiagnostic("helper-invariant", "invariant", 0) +
        "native-windows-cleanup: operation=job-close domain=win32 value=6\n",
    );
    f.close();
    await assert.rejects(f.session.finish(1), (error) => {
      const diagnosis = windowsFeasibilityDiagnostics(error.stderr);
      assert.equal(error.nativeStreamInvalid, undefined);
      assert.equal(error.exitCode, 126);
      assert.equal(
        diagnosis.failure.operation,
        windowsFeasibilityDiagnostics(line).failure.operation,
      );
      assert.equal(diagnosis.cleanup.operation, "job-close");
      return true;
    });
  }
  const invalid = windowsSessionFixture();
  const waiting = invalid.session.next();
  invalid.child.stdout.write("native-windows: private unrecognized payload\n");
  await assert.rejects(waiting, { nativeStreamInvalid: true });
  invalid.close();
});

test("Windows helper failures before the first record retain their operation through pending reads and completion", async () => {
  for (const [operation, domain, value, code] of [
    ["acl-read", "win32", 5, 126],
    ["acl-entries", "invariant", 0, 126],
    ["hash-create", "ntstatus", 0xc000000d, 126],
    ["profile-derive", "hresult", 0x80004001, 78],
    ["thread-query", "ntstatus", 0xc0000003, 78],
    ["local-appdata", "win32", 203, 78],
    ["local-appdata", "invariant", 0, 78],
    ["git-null-input", "win32", 5, 126],
    ["git-process-create", "win32", 203, 126],
    ["git-process-exit", "exit", 128, 126],
  ]) {
    const f = windowsSessionFixture(),
      waiting = f.session.next();
    f.child.stderr.write(windowsDiagnostic(operation, domain, value));
    f.close(code);
    let failure;
    await assert.rejects(waiting, (error) => {
      failure = error;
      assert.equal(error.exitCode, code);
      assert.equal(error.signal, null);
      const cause = windowsFeasibilityCause("literal-argv", {
        ...error,
        nativeError: 203,
      });
      assert.equal(
        cause.code,
        code === 78 ? "prerequisite-unavailable" : "setup-failed",
      );
      assert.ok(
        cause.detail.includes(
          `Native ${operation} failed (${domain}=${value}).`,
        ),
      );
      assert.doesNotMatch(cause.detail, /Win32=203/u);
      if (operation === "local-appdata") {
        assert.match(
          cause.detail,
          /Restore the hosted worker's LOCALAPPDATA before launch/u,
        );
        assert.doesNotMatch(cause.detail, /Fixture User|C:\\/u);
        assert.ok(cause.detail.length <= 256);
      }
      return true;
    });
    await assert.rejects(f.session.next(), (error) => error === failure);
    await assert.rejects(f.session.finish(0), (error) => error === failure);
    assert.equal(f.session.exited, true);
  }
});

test("Windows completed native failure keeps independent cleanup failure separate from the original diagnosis", async () => {
  const f = windowsSessionFixture(),
    row = f.session.next();
  f.child.stdout.write('{"event":"suspended"}\n');
  assert.deepEqual(await row, { event: "suspended" });
  const primary = windowsDiagnostic("process-create", "win32", 5),
    cleanup =
      "native-windows-cleanup: operation=job-close domain=win32 value=6\n";
  f.child.stderr.write(primary.slice(0, 20));
  f.child.stderr.write(primary.slice(20) + cleanup);
  f.close();
  await assert.rejects(f.session.finish(1), (error) => {
    const cause = windowsFeasibilityCause("literal-argv", error),
      parsed = windowsFeasibilityDiagnostics(error.stderr);
    assert.match(cause.detail, /Native process-create failed \(win32=5\)/u);
    assert.doesNotMatch(cause.detail, /job-close/u);
    assert.deepEqual(parsed.cleanup, {
      operation: "job-close",
      domain: "win32",
      value: 6,
    });
    return true;
  });
});

test("Windows diagnostic grammar rejects malformed, tainted and oversized streams without adopting stale errors", async () => {
  for (const stderr of [
    windowsDiagnostic("foreign-operation", "win32", 5),
    windowsDiagnostic("acl-read", "errno", 5),
    windowsDiagnostic("acl-read", "win32", 0x100000000),
    windowsDiagnostic("acl-entries", "invariant", 203),
    windowsDiagnostic("hash-create", "ntstatus", 5),
    windowsDiagnostic("git-process-exit", "exit", 0),
    windowsDiagnostic("git-process-exit", "win32", 128),
    windowsDiagnostic("acl-read", "exit", 128),
    windowsDiagnostic("acl-read", "win32", 5).trimEnd(),
    windowsDiagnostic("acl-read", "win32", 5).replace("\n", "\r\r\n"),
    windowsDiagnostic("acl-read", "win32", 5) +
      "C:\\private\\fixture S-1-5-21-101\n",
    windowsDiagnostic("acl-read", "win32", 5) + "x".repeat(4096),
    Buffer.from([0xff, 10]),
  ]) {
    assert.equal(windowsFeasibilityDiagnostics(stderr), null);
    const f = windowsSessionFixture(),
      waiting = f.session.next();
    f.child.stderr.write(stderr);
    f.close(
      typeof stderr === "string" && stderr.includes("foreign-operation")
        ? 78
        : 126,
    );
    await assert.rejects(waiting, (error) => {
      assert.equal(error.nativeDiagnosticInvalid, true);
      assert.ok(Buffer.byteLength(error.stderr) <= 4096);
      const cause = windowsFeasibilityCause("literal-argv", {
        ...error,
        nativeError: 203,
      });
      assert.equal(cause.code, "setup-failed");
      assert.match(cause.detail, /diagnostic rejected/u);
      assert.doesNotMatch(cause.detail, /Win32=203|private|S-1-/u);
      return true;
    });
    await assert.rejects(f.session.finish(0));
  }
});

test("Windows native stdout remains strict while successful sessions retain literal arguments", async () => {
  const ready = '{"event":"ready"}\n';
  for (const stdout of [
    ready,
    ready + "unfinished",
    ready + ready,
    "invalid\n",
    ready.replace("\n", "\r\n"),
    "x".repeat(65537),
  ]) {
    const f = windowsSessionFixture();
    f.child.stdout.write(stdout);
    f.close(0);
    if (stdout === ready) {
      assert.deepEqual(await f.session.next(), { event: "ready" });
      assert.deepEqual(await f.session.finish(1), [{ event: "ready" }]);
    } else {
      try {
        await f.session.next();
      } catch {
        /* Completion must also reject. */
      }
      await assert.rejects(f.session.finish(1), (error) => {
        assert.equal(error.nativeStreamInvalid, true);
        assert.equal(
          windowsFeasibilityCause("literal-argv", error).code,
          "setup-failed",
        );
        return true;
      });
    }
  }
  for (const code of [78, 126]) {
    const f = windowsSessionFixture(),
      waiting = f.session.next();
    f.child.stdout.write('{"event":"suspended"');
    f.child.stderr.write(
      windowsDiagnostic("thread-query", "ntstatus", 0xc0000003),
    );
    f.close(code);
    await assert.rejects(waiting, (error) => {
      assert.equal(error.nativeStreamInvalid, true);
      assert.equal(error.exitCode, code);
      const cause = windowsFeasibilityCause("literal-argv", error);
      assert.equal(cause.code, "setup-failed");
      assert.match(cause.detail, /stream rejected/u);
      assert.match(
        cause.detail,
        /Native thread-query failed \(ntstatus=3221225475\)/u,
      );
      return true;
    });
    await assert.rejects(f.session.finish(1));
  }
});

test("Windows first-launch source guards distinguish API statuses, held objects and pre-cleanup failure capture", async () => {
  const source = await readFile(
      new URL("../ci/native/win32/feasibility-helper.c", import.meta.url),
      "utf8",
    ),
    launch = source.slice(
      source.indexOf("static void launch("),
      source.indexOf("static void observe("),
    ),
    admission = source.slice(
      source.indexOf("static void observe("),
      source.indexOf("static int connection("),
    );
  // Fragile native forms only; no Windows compiler, process or SDK runs.
  assert.match(source, /status_check\(GetSecurityInfo\([^\n]*"acl-read"\)/u);
  assert.match(source, /nt_check\(BCryptCreateHash\([^\n]*"hash-create"\)/u);
  assert.match(source, /hresult_check\(hr, "profile-derive"\)/u);
  assert.match(
    source,
    /static void need\(BOOL ok\) \{ invariant\(ok, "helper-invariant"\); \}/u,
  );
  assert.match(launch, /sizeError != ERROR_INSUFFICIENT_BUFFER/u);
  assert.match(launch, /PROC_THREAD_ATTRIBUTE_JOB_LIST/u);
  assert.match(launch, /PROC_THREAD_ATTRIBUTE_HANDLE_LIST/u);
  assert.match(
    launch,
    /FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT/u,
  );
  assert.match(
    launch,
    /invariant\(!\(tag.FileAttributes & \(FILE_ATTRIBUTE_REPARSE_POINT \| FILE_ATTRIBUTE_DIRECTORY\)\), "executable-tag"\)/u,
  );
  assert.match(
    launch,
    /remember\("process-create", "win32", error\);[\s\S]*?QueryInformationJobObject/u,
  );
  assert.doesNotMatch(launch, /SetLastError\(error\)/u);
  assert.match(
    source,
    /fprintf\(stderr, "native-windows:[\s\S]*?close_job\(TRUE\)/u,
  );
  assert.match(source, /native-windows-cleanup:/u);
  assert.match(
    source,
    /win32_check\(DuplicateHandle\([^\n]*"handle-duplicate"\)/u,
  );
  assert.match(
    admission,
    /nt_check\(status, "thread-query"\); invariant\(status == 0 && count == 1, "thread-state"\)/u,
  );
  assert.match(
    admission,
    /remember\("thread-query", "ntstatus", \(DWORD\)status\); failure\(78\)/u,
  );
  assert.match(
    admission,
    /win32_check\(IsProcessInJob\(child, job, &member\), "process-job"\); invariant\(member, "process-job"\)/u,
  );
});

test("Windows AppContainer launch constructs only the bounded sorted Unicode child prerequisites before effects", async () => {
  const source = await readFile(
    new URL("../ci/native/win32/feasibility-helper.c", import.meta.url),
    "utf8",
  );
  const environment = source.slice(
      source.indexOf("static void child_environment("),
      source.indexOf("static void launch("),
    ),
    launch = source.slice(
      source.indexOf("static void launch("),
      source.indexOf("static void observe("),
    );
  assert.deepEqual(
    [...environment.matchAll(/L"([A-Za-z][A-Za-z0-9_]*)=[^"]+"/gu)].map(
      (match) => match[1],
    ),
    [
      "GIT_CONFIG_GLOBAL",
      "GIT_CONFIG_NOSYSTEM",
      "GIT_OPTIONAL_LOCKS",
      "GIT_TERMINAL_PROMPT",
      "LOCALAPPDATA",
      "SystemRoot",
    ],
  );
  assert.match(environment, /L"GIT_CONFIG_GLOBAL=\.git\/runner-global\.conf"/u);
  assert.match(
    environment,
    /GetEnvironmentVariableW\(L"LOCALAPPDATA", local, 4096\)/u,
  );
  assert.match(
    environment,
    /if \(!localSize\) \{ DWORD error = GetLastError\(\); remember\("local-appdata", "win32", error\); failure\(78\); \}/u,
  );
  assert.match(
    environment,
    /if \(!caller_directory\(local, localSize\)\)[^\n]*failure\(78\)/u,
  );
  assert.match(environment, /GetWindowsDirectoryW\(windows, 4096\)/u);
  assert.match(environment, /L"LOCALAPPDATA=%ls", local/u);
  assert.match(environment, /L"SystemRoot=%ls", windows/u);
  assert.match(
    environment,
    /wcslen\(L"LOCALAPPDATA="\) \+ localSize \+ 2 <= 8192 - at/u,
  );
  assert.match(
    environment,
    /wcslen\(L"SystemRoot="\) \+ windowsSize \+ 2 <= 8192 - at/u,
  );
  assert.match(
    environment,
    /invariant\(at < 8192, "environment-bound"\); environment\[at\] = 0/u,
  );
  assert.doesNotMatch(
    environment,
    /\b(?:USERPROFILE|APPDATA|PATH|TEMP|TMP|GetEnvironmentStringsW)\b/u,
  );
  assert.doesNotMatch(
    launch,
    /GetEnvironmentVariableW|GetEnvironmentStringsW/u,
  );
  const prepared = launch.indexOf("child_environment(environment);");
  assert.ok(prepared >= 0);
  for (const effect of [
    "owned_profile();",
    "CreateFileW(",
    "CreateJobObjectW(",
    "CreatePipe(",
    "recordio(",
    "CreateProcessW(",
  ])
    assert.ok(prepared < launch.indexOf(effect));
  assert.match(launch, /CREATE_UNICODE_ENVIRONMENT/u);
  assert.match(
    launch,
    /environment, workspace, &startup\.StartupInfo, &child/u,
  );
});

test("Windows feasibility confines profile names and requires complete matching-worker records", async () => {
  assert.equal(
    windowsFeasibilityProfileName("a".repeat(32)),
    `native.feasibility.${"a".repeat(32)}`,
  );
  for (const nonce of [
    "existing",
    "../profile",
    "A".repeat(32),
    "a".repeat(33),
  ])
    assert.throws(() => windowsFeasibilityProfileName(nonce));
  if (process.platform !== "win32") {
    const unavailable = await runWindowsFeasibility({}, {});
    assert.equal(unavailable.length, 11);
    assert.ok(
      unavailable.every(
        (entry) =>
          entry.status === "BLOCKED" &&
          entry.cause.code === "prerequisite-unavailable" &&
          entry.cleanup.status === "NOT_RUN",
      ),
    );
  }
  const args = ["--platform", "win32", "--expected-sha", SHA],
    windowsHost = { ...host, platform: "win32", runnerOs: "Windows" };
  let called = false;
  const options = {
    host: windowsHost,
    observe: async () => ({
      checkoutSha: SHA,
      os: "win32",
      build: "synthetic-build",
      architecture: "x64",
    }),
    runNative: async () => {
      called = true;
      return [];
    },
  };
  await assert.rejects(
    runFeasibilityExperiment(args, { ...options, host }),
    FeasibilityError,
  );
  assert.equal(called, false);
  const missing = await runFeasibilityExperiment(args, options);
  assert.equal(called, true);
  assert.equal(missing.status, "FAIL");
  assert.ok(
    missing.report.results
      .filter(({ capability }) =>
        feasibilityCapabilities("win32").some(
          ({ id, tier }) => id === capability && tier === "native",
        ),
      )
      .every(({ cause }) => cause.code === "missing-record"),
  );
});

// Portable effects exercise acquisition and failure settlement only. No native
// compiler, helper, Mach API, ACL read or process signal runs in these tests.
function darwinPreparationEffects({
  failure,
  replaceRoot = false,
  replaceLeaf = false,
  unknownOutput = false,
  removeFailure = false,
  canonicalFailure = false,
} = {}) {
  const root = "/fixture/nf-owned",
    entries = new Map(),
    calls = [];
  let sequence = 1;
  const missing = () =>
    Object.assign(new Error("Synthetic missing entry"), { code: "ENOENT" });
  const add = (file, directory = false, gid = 20) =>
    entries.set(file, {
      dev: 1,
      ino: sequence++,
      birthtimeMs: 1,
      uid: 501,
      gid,
      mode: directory ? 0o40700 : 0o100500,
      nlink: 1,
      isDirectory: () => directory,
      isFile: () => !directory,
      isSymbolicLink: () => false,
    });
  const options = {
    uid: 501,
    gid: 20,
    fs: {
      realpath: async (file) => {
        calls.push(["canonical", file]);
        if (file === root && canonicalFailure)
          throw new Error("Synthetic canonicalization failure");
        return file;
      },
      mkdtemp: async () => {
        calls.push(["acquire", root]);
        add(root, true, 0);
        return root;
      },
      lstat: async (file) => {
        if (!entries.has(file)) throw missing();
        return { ...entries.get(file) };
      },
      chown: async (file, uid, gid) => {
        calls.push(["group", file, uid, gid]);
        entries.get(file).gid = gid;
      },
      mkdir: async (file) => {
        calls.push(["mkdir", file]);
        add(file, true, entries.get(root).gid);
      },
      unlink: async (file) => {
        calls.push(["unlink", file]);
        if (removeFailure && file.endsWith("/helper"))
          throw Object.assign(new Error("Synthetic removal failure"), {
            code: "EPERM",
          });
        entries.delete(file);
      },
      rmdir: async (file) => {
        calls.push(["rmdir", file]);
        if ([...entries.keys()].some((entry) => entry.startsWith(`${file}/`)))
          throw Object.assign(new Error("Synthetic nonempty directory"), {
            code: "ENOTEMPTY",
          });
        entries.delete(file);
      },
    },
    build: async (_root, _components, { recordResource }) => {
      calls.push(["build"]);
      assert.equal(entries.get(root).gid, 20);
      for (const name of ["helper", "argv-fixture", "git"]) {
        add(`${root}/build/${name}`);
        await recordResource(`${root}/build/${name}`);
      }
      add(`${root}/evidence/build.json`);
      await recordResource(`${root}/evidence/build.json`);
    },
    readNative: async (file, operation, directory) => {
      calls.push(["native", operation]);
      assert.deepEqual(
        [file, operation, directory],
        [root, "prerequisites", root],
      );
      if (replaceRoot) entries.get(root).ino++;
      if (replaceLeaf) entries.get(`${root}/build/helper`).ino++;
      if (unknownOutput) add(`${root}/build/unclaimed`);
      if (failure) throw failure;
      return { identitySafeSignal: true, sandboxCheckBinding: true };
    },
    save: async () => {
      calls.push(["save"]);
      add(`${root}/evidence/prerequisites.json`);
    },
  };
  return { root, entries, calls, options };
}

const darwinPrerequisiteFailure = (fields = {}) =>
  Object.assign(new Error("Synthetic private diagnostic"), {
    code: 78,
    signal: null,
    timedOut: false,
    stderr:
      "native-darwin: operation=task-audit domain=mach value=5 effects=none settlement=settled\n",
    ...fields,
  });

test("Darwin preparation normalizes only the acquired private root before inherited-group checks", async () => {
  const injected = darwinPreparationEffects();
  assert.equal(
    await prepareDarwinFeasibility("/fixture", [], injected.options),
    injected.root,
  );
  assert.deepEqual(injected.calls.slice(0, 4), [
    ["canonical", "/fixture"],
    ["acquire", injected.root],
    ["canonical", injected.root],
    ["group", injected.root, -1, 20],
  ]);
  assert.ok(
    injected.calls.findIndex(([operation]) => operation === "group") <
      injected.calls.findIndex(([operation]) => operation === "build"),
  );
  assert.equal(
    injected.calls.some(([operation]) => operation === "unlink"),
    false,
  );
});

test("Darwin partial prerequisites require explicit child settlement independently of temporary-resource removal", async () => {
  for (const [fields, expectedCleanup, expectedCause] of [
    [{}, "PASS", "prerequisite-unavailable"],
    [{ code: 126 }, "PASS", "setup-failed"],
    [{ stderr: "" }, "UNCERTAIN", "prerequisite-unavailable"],
    [
      {
        stderr:
          "native-darwin: operation=task-audit domain=mach value=5 effects=none settlement=unsettled\n",
      },
      "UNCERTAIN",
      "prerequisite-unavailable",
    ],
    [
      {
        stderr:
          "native-darwin: operation=task-audit domain=mach value=5 effects=none settlement=settled\nnative-darwin-cleanup: operation=task-release domain=mach value=15 effects=none settlement=unsettled\n",
      },
      "UNCERTAIN",
      "prerequisite-unavailable",
    ],
    [
      {
        stderr:
          "native-darwin: operation=task-audit domain=mach value=5 effects=possible settlement=settled\n",
      },
      "UNCERTAIN",
      "prerequisite-unavailable",
    ],
    [
      { timedOut: true, signal: "SIGALRM", code: null },
      "UNCERTAIN",
      "deadline",
    ],
  ]) {
    const injected = darwinPreparationEffects({
      failure: darwinPrerequisiteFailure(fields),
    });
    await assert.rejects(
      prepareDarwinFeasibility("/fixture", [], injected.options),
      (error) => {
        assert.equal(error.feasibilityCause.code, expectedCause);
        assert.equal(error.feasibilityCleanup.status, expectedCleanup);
        assert.equal(error.feasibilityCleanup.emergency, false);
        if (expectedCleanup === "PASS")
          assert.equal(error.feasibilityCleanup.independent, true);
        return true;
      },
    );
    assert.equal(injected.entries.size, 0);
    assert.equal(
      injected.calls.some(([operation]) => operation === "save"),
      false,
    );
  }
});

test("Darwin prerequisite backstop and unexpected child exits cannot pass cleanup", async () => {
  for (const [operation, value, emergency] of [
    ["prerequisite-backstop", 14, true],
    ["prerequisite-child-status", 9, false],
  ]) {
    const injected = darwinPreparationEffects({
      failure: darwinPrerequisiteFailure({
        stderr: `native-darwin: operation=task-audit domain=mach value=5 effects=none settlement=unsettled\nnative-darwin-cleanup: operation=${operation} domain=invariant value=${value} effects=none settlement=unsettled\n`,
      }),
    });
    await assert.rejects(
      prepareDarwinFeasibility("/fixture", [], injected.options),
      (error) => {
        assert.match(
          error.feasibilityCause.detail,
          /Native task-audit failed \(mach=5\)/u,
        );
        assert.equal(error.feasibilityCleanup.status, "UNCERTAIN");
        assert.equal(error.feasibilityCleanup.emergency, emergency);
        assert.ok(error.feasibilityCleanup.cause.detail.includes(operation));
        return true;
      },
    );
    assert.equal(injected.entries.size, 0);
  }
});

test("Darwin held ACL inspection failures refuse preparation and retain their original diagnosis", async () => {
  for (const [operation, domain, value, code] of [
    ["filesec-init", "errno", 12, 126],
    ["filesec-stat", "errno", 2, 126],
    ["filesec-stat", "errno", 45, 78],
    ["acl-query", "errno", 5, 126],
    // Historical presence diagnoses remain parseable after the bitmask repair.
    ["acl-presence", "invariant", -1, 126],
    ["acl-read", "errno", 2, 126],
    ["acl-valid", "errno", 22, 126],
    ["acl-empty", "invariant", 0, 126],
    ["acl-empty", "errno", 5, 126],
    ["file-stat-again", "errno", 9, 126],
    ["file-stable", "invariant", 0, 126],
  ]) {
    const injected = darwinPreparationEffects({
      failure: darwinPrerequisiteFailure({
        code,
        stderr: `native-darwin: operation=${operation} domain=${domain} value=${value} effects=none settlement=settled\n`,
      }),
    });
    await assert.rejects(
      prepareDarwinFeasibility("/fixture", [], injected.options),
      (error) => {
        assert.equal(
          error.feasibilityCause.code,
          code === 78 ? "prerequisite-unavailable" : "setup-failed",
        );
        assert.ok(
          error.feasibilityCause.detail.includes(
            `Native ${operation} failed (${domain}=${value}).`,
          ),
        );
        assert.equal(error.feasibilityCleanup.status, "PASS");
        assert.equal(error.feasibilityCleanup.independent, true);
        return true;
      },
    );
    assert.equal(injected.entries.size, 0);
    assert.equal(
      injected.calls.some(([operation]) => operation === "save"),
      false,
    );
  }
});

test("Darwin ACL release failure remains separate from entry rejection and changed held identity", async () => {
  for (const operation of ["acl-empty", "file-stable"]) {
    const injected = darwinPreparationEffects({
      failure: darwinPrerequisiteFailure({
        code: 126,
        stderr: `native-darwin: operation=${operation} domain=invariant value=0 effects=none settlement=unsettled\nnative-darwin-cleanup: operation=acl-release domain=errno value=22 effects=none settlement=unsettled\n`,
      }),
    });
    await assert.rejects(
      prepareDarwinFeasibility("/fixture", [], injected.options),
      (error) => {
        assert.ok(
          error.feasibilityCause.detail.includes(
            `Native ${operation} failed (invariant=0).`,
          ),
        );
        assert.equal(error.feasibilityCleanup.status, "UNCERTAIN");
        assert.equal(error.feasibilityCleanup.emergency, false);
        assert.match(
          error.feasibilityCleanup.cause.detail,
          /Native cleanup acl-release failed \(errno=22\)/u,
        );
        return true;
      },
    );
    // Independent owned-file removal cannot settle a failed native release.
    assert.equal(injected.entries.size, 0);
  }
});

test("Darwin preparation preserves the first native cause while attempting independent owned removals", async () => {
  const failure = darwinPrerequisiteFailure({
    stderr:
      "native-darwin: operation=bsd-identity domain=errno value=3 effects=none settlement=unsettled\nnative-darwin-cleanup: operation=task-release domain=mach value=15 effects=none settlement=unsettled\n",
  });
  for (const variation of [
    { removeFailure: true },
    { replaceRoot: true },
    { replaceLeaf: true },
    { unknownOutput: true },
    { canonicalFailure: true },
  ]) {
    const injected = darwinPreparationEffects({ failure, ...variation });
    await assert.rejects(
      prepareDarwinFeasibility("/fixture", [], injected.options),
      (error) => {
        if (variation.canonicalFailure) {
          assert.match(
            error.feasibilityCause.detail,
            /fixture-root-canonical/u,
          );
          assert.equal(error.feasibilityCleanup.status, "PASS");
        } else {
          assert.match(
            error.feasibilityCause.detail,
            /Native bsd-identity failed \(errno=3\)/u,
          );
          assert.match(
            error.feasibilityCleanup.cause.detail,
            /Native cleanup task-release failed \(mach=15\)/u,
          );
          assert.equal(error.feasibilityCleanup.status, "UNCERTAIN");
        }
        return true;
      },
    );
    if (variation.removeFailure || variation.replaceLeaf) {
      assert.ok(injected.entries.has(`${injected.root}/build/helper`));
      assert.equal(injected.entries.has(`${injected.root}/build/git`), false);
      assert.ok(
        injected.calls.some(
          ([operation, file]) =>
            operation === "rmdir" && file === `${injected.root}/evidence`,
        ),
      );
    }
    if (variation.replaceRoot)
      assert.equal(
        injected.calls.some(
          ([operation]) => operation === "unlink" || operation === "rmdir",
        ),
        false,
      );
    if (variation.canonicalFailure) assert.equal(injected.entries.size, 0);
    if (variation.unknownOutput)
      assert.ok(injected.entries.has(`${injected.root}/build/unclaimed`));
  }
});

test("Darwin native diagnostics retain bounded operation and error domains without arbitrary output", () => {
  for (const stream of ["stdout", "stderr"]) {
    const operation = stream === "stdout" ? "acl-empty" : "helper-output";
    const cause = darwinFeasibilityCause(
      "identity-prerequisites",
      darwinPrerequisiteFailure({
        stderr: "",
        [stream]: `error: incompatible declarations\nnative-darwin: operation=${operation} domain=invariant value=0 effects=none settlement=settled\npassword=private\n`,
      }),
    );
    assert.ok(
      cause.detail.includes(
        `output=recognized; Native ${operation} failed (invariant=0)`,
      ),
    );
    assert.doesNotMatch(cause.detail, /private|password/u);
  }
  for (const stderr of [
    "native-darwin: operation=foreign-operation domain=mach value=5 effects=none settlement=settled\n",
    "native-darwin: operation=task-audit domain=errno value=2147483648 effects=none settlement=settled\n",
    "native-darwin: operation=task-audit domain=mach value=5 effects=none settlement=settled /private/fixture\n",
    "x".repeat(65536) +
      "\nnative-darwin: operation=task-audit domain=mach value=5 effects=none settlement=settled\n",
  ])
    assert.match(
      darwinFeasibilityCause(
        "identity-prerequisites",
        darwinPrerequisiteFailure({ stderr }),
      ).detail,
      /output=unrecognized/u,
    );
});

test("Darwin provider gating retains bounded native origins separately from derivative blocks and cleanup", async () => {
  const cleanupCause = {
    code: "cleanup-unobserved",
    detail: "Native cleanup task-release failed (mach=15).",
  };
  for (const cause of [
    darwinFeasibilityCause(
      "identity-prerequisites",
      darwinPrerequisiteFailure({ code: 126 }),
    ),
    {
      code: "setup-failed",
      detail: "darwin identity-prerequisites: " + "é".repeat(100),
    },
  ]) {
    const native = unavailableFeasibilityResults("darwin", cause).filter(
      ({ capability }) =>
        feasibilityCapabilities("darwin").some(
          ({ id, tier }) => id === capability && tier === "native",
        ),
    );
    native[0].cleanup = {
      status: "UNCERTAIN",
      independent: false,
      emergency: false,
      elapsedMs: 1,
      witnessSha256: null,
      cause: cleanupCause,
    };
    const assessment = await runFeasibilityExperiment(
      ["--platform", "darwin", "--expected-sha", SHA],
      {
        host: { ...host, platform: "darwin", runnerOs: "macOS" },
        observe: async () => report("darwin"),
        runNative: async () => native,
        runProviders: async () =>
          assert.fail(
            "Unsettled native resources cannot admit provider effects",
          ),
      },
    );
    assert.deepEqual(assessment.report.results[0].cause, cause);
    assert.deepEqual(assessment.report.results[0].cleanup.cause, cleanupCause);
    for (const entry of assessment.report.results.filter(({ capability }) =>
      feasibilityCapabilities("darwin").some(
        ({ id, tier }) => id === capability && tier !== "native",
      ),
    )) {
      assert.equal(entry.status, "BLOCKED");
      assert.equal(entry.cause.code, "prerequisite-unavailable");
      assert.match(
        entry.cause.detail,
        /origin=setup-failed; darwin identity-prerequisites/u,
      );
      if (cause.detail.includes("task-audit"))
        assert.match(
          entry.cause.detail,
          /Native task-audit failed \(mach=5\)/u,
        );
      assert.ok(Buffer.byteLength(entry.cause.detail) <= 256);
      assert.equal(entry.cause.detail.isWellFormed(), true);
      assert.equal(entry.cleanup.status, "NOT_RUN");
    }
  }
});

test("Darwin failed builds settle fixed preparation outputs without promoting crashed compiler cleanup", async () => {
  for (const [code, expected] of [
    ["setup-failed", "PASS"],
    ["deadline", "UNCERTAIN"],
    ["crash", "UNCERTAIN"],
  ]) {
    const injected = darwinPreparationEffects(),
      build = injected.options.build;
    const first = {
      code,
      detail: "build helper-compile-link: fixed synthetic failure.",
    };
    injected.options.build = async (...args) => {
      await build(...args);
      throw Object.assign(new Error("Synthetic build failure"), {
        feasibilityCause: first,
      });
    };
    await assert.rejects(
      prepareDarwinFeasibility("/fixture", [], injected.options),
      (error) => {
        assert.deepEqual(error.feasibilityCause, first);
        assert.equal(error.feasibilityCleanup.status, expected);
        return true;
      },
    );
    assert.equal(injected.entries.size, 0);
    assert.equal(
      injected.calls.some(([operation]) => operation === "native"),
      false,
    );
  }
});
