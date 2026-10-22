import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { EventEmitter, once } from "node:events";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { Writable, PassThrough } from "node:stream";
import { gzipSync } from "node:zlib";
import { Script } from "node:vm";
import { resolveOwnedProcessLauncher } from "../src/agents/index.js";
import { attemptNativeBuilds } from "../ci/native/diagnostics.js";
import {
  preflightNativeTar,
  materializeReviewedTar,
  observationDigest,
  NATIVE_PACKAGE_LIMITS,
  assertProtectedNativeEnvironment,
  createNativeDiagnosticWriter,
  withNativeDiagnostics,
} from "../ci/native/index.js";
import {
  feasibilityCommandParameters,
  feasibilityCommandError,
  openFeasibilityCommand,
  observeFeasibilityCompletion,
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
  runWindowsNullDiagnostic,
  renderWindowsNullDiagnostic,
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
  verifyLinuxCommandControllers,
} from "../ci/native/linux/index.js";
import {
  assessDarwinFeasibilityDomain,
  assertDarwinFeasibilityTranscript,
  darwinFeasibilityIdentityArguments,
  darwinFeasibilityPolicy,
  runDarwinFeasibility,
  prepareDarwinFeasibility,
  darwinFeasibilityCause,
  openDarwinFeasibilitySession,
  openDarwinFaultDomain,
  runDarwinFeasibilityBundle,
  runDarwinFeasibilityFault,
} from "../ci/native/darwin/index.js";
import {
  runWindowsFeasibility,
  validateWindowsFeasibilityGitStart,
  sameWindowsIdentity,
  normalizeWindowsIdentity,
  windowsFeasibilityProfileName,
  windowsFeasibilityAdmissionName,
  windowsFeasibilityCallerEnvironment,
  windowsFeasibilityToolEnvironment,
  windowsFeasibilityImports,
  windowsFeasibilityCause,
  windowsFeasibilityDiagnostics,
  windowsFeasibilityHelperSession,
  observeWindowsFeasibilityWfp,
  assertWindowsFeasibilityTcpObserver,
  assertWindowsFeasibilityTcpTransfer,
  assertWindowsFeasibilityTcpDenial,
  WINDOWS_LITERAL_ARGUMENTS,
  quoteWindowsArgument,
  assertWindowsFeasibilityWitness,
  observeWindowsGitNullProbe,
} from "../ci/native/win32/index.js";

import {
  createWindowsFeasibilityWorkspace,
  windowsFeasibilityWorkspaceLaunch,
} from "../ci/native/win32/feasibility-workspace.js";

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
              : { error: { code: -32601, message: "Unavailable." } }),
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

function modelFreeFailureFixture(signal, rejection) {
  const output = new PassThrough(),
    errorOutput = new PassThrough();
  const completion = Promise.withResolvers();
  const input = new Writable({
    write(chunk, encoding, done) {
      const value = JSON.parse(chunk.toString());
      if (value.method === "initialize" || (value.id && rejection))
        output.write(
          JSON.stringify({
            id: value.id,
            ...(value.method === "initialize"
              ? { result: {} }
              : { error: rejection }),
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
  const client = openFeasibilityCommand(
    { input, output, errorOutput, completion: completion.promise },
    signal,
    "linux",
  );
  const parameters = feasibilityCommandParameters(
    ["fixture"],
    "/synthetic/workspace",
    "read-only",
  );
  return {
    output,
    errorOutput,
    completion,
    client,
    exec: () => client.exec(parameters),
    inject: (value) =>
      Buffer.isBuffer(value)
        ? errorOutput.write(value)
        : output.write(
            (typeof value === "string" ? value : JSON.stringify(value)) + "\n",
          ),
  };
}

function disabledRemoteStatus(environmentId = null) {
  return {
    method: "remoteControl/status/changed",
    params: {
      status: "disabled",
      serverName: "private-server",
      installationId: "private-installation",
      environmentId,
    },
  };
}

test("model-free informational startup notifications never settle replies and all four controls complete", async (t) => {
  const output = new PassThrough(),
    errorOutput = new PassThrough(),
    methods = [];
  const send = (value, done) =>
    output.write(JSON.stringify(value) + "\n", done);
  const minimal = {
    method: "configWarning",
    params: { summary: "private-summary", details: null },
  };
  const full = {
    method: "configWarning",
    params: {
      summary: "private-summary",
      details: "private-details",
      path: "/synthetic/private.toml",
      range: { start: { line: 1, column: 1 }, end: { line: 2, column: 3 } },
    },
  };
  const remote = disabledRemoteStatus(),
    withEnvironment = disabledRemoteStatus("private-environment");
  const notifications = [
    minimal,
    full,
    remote,
    withEnvironment,
    { ...minimal, emittedAtMs: 1000 },
    { ...full, emittedAtMs: Number.MIN_SAFE_INTEGER },
    { ...remote, emittedAtMs: 0 },
    { ...withEnvironment, emittedAtMs: Number.MAX_SAFE_INTEGER },
  ];
  const input = new Writable({
    write(chunk, encoding, done) {
      const request = JSON.parse(chunk.toString());
      methods.push(request.method);
      const reply =
        request.method === "initialize"
          ? { fixture: "initialized" }
          : { exitCode: 0, stdout: `control-${request.id}`, stderr: "" };
      for (const notification of notifications) send(notification);
      if (request.id) send({ id: request.id, result: reply });
      for (const notification of notifications) send(notification);
      done();
    },
    final(done) {
      output.end();
      errorOutput.end();
      done();
    },
  });
  const client = openFeasibilityCommand({ input, output, errorOutput });
  t.after(() => client.close().catch(() => {}));
  for (const notification of notifications)
    await new Promise((resolve) => send(notification, resolve));
  assert.deepEqual(await client.initialize(), { fixture: "initialized" });
  for (let index = 0; index < 4; index++) {
    const params = feasibilityCommandParameters(
      ["fixture", String(index)],
      "/synthetic/workspace",
      index < 2 ? "read-only" : "workspace-write",
    );
    assert.deepEqual(await client.exec(params), {
      exitCode: 0,
      stdout: `control-${index + 2}`,
      stderr: "",
    });
  }
  await client.close();
  assert.deepEqual(methods, [
    "initialize",
    "initialized",
    ...Array(4).fill("command/exec"),
  ]);
});

test("model-free malformed JSON and strict notification/reply envelopes retain the first redacted failure", async () => {
  const warning = {
    method: "configWarning",
    params: { summary: "private-summary", details: null },
  };
  const remote = disabledRemoteStatus("private-environment");
  const overLine = " ".repeat(65537),
    overTotal = " ".repeat(1048577),
    overErrors = Buffer.alloc(1048577);
  const guardCases = new Map([
    [null, ["reply-envelope", "non-object"]],
    [{}, ["reply-envelope", "other-object"]],
    [
      { ...warning, method: "private-method" },
      ["reply-envelope", "notification"],
    ],
    [
      { id: 2, method: "private-method", params: {} },
      ["reply-envelope", "request"],
    ],
    [{ ...warning, id: 2 }, ["config-warning"]],
    [{ ...remote, id: 2 }, ["remote-status", null, "envelope"]],
    [{ method: remote.method }, ["remote-status", null, "envelope"]],
    ...[
      0.5,
      Number.MIN_SAFE_INTEGER - 1,
      Number.MAX_SAFE_INTEGER + 1,
      null,
      "private-timestamp",
      true,
      {},
      [],
    ].flatMap((emittedAtMs) => [
      [{ ...warning, emittedAtMs }, ["config-warning"]],
      [{ ...remote, emittedAtMs }, ["remote-status", null, "envelope"]],
    ]),
    ...[warning, remote].map((value) => [
      { ...value, emittedAtMs: 1000, authority: true },
      value === warning
        ? ["config-warning"]
        : ["remote-status", null, "envelope"],
    ]),
    [
      { ...warning, emittedAtMs: 1000, method: "private-method" },
      ["reply-envelope", "notification"],
    ],
    [
      { ...remote, emittedAtMs: 1000, id: 2 },
      ["remote-status", null, "envelope"],
    ],
    [
      { id: 2, result: {}, emittedAtMs: 1000 },
      ["reply-envelope", "reply-number"],
    ],
    [
      {
        id: 2,
        error: { code: -32603, message: "private-error" },
        emittedAtMs: 1000,
      },
      ["reply-envelope", "reply-number"],
    ],
    ...[
      ["status", "connecting", "status"],
      ["status", "connected", "status"],
      ["status", "errored", "status"],
      ["serverName", 1, "server-name-type"],
      ["installationId", null, "installation-id-type"],
      ["environmentId", false, "environment-id-type"],
      ["environmentId", undefined, "payload"],
      ["authority", true, "payload"],
    ].map(([field, input, subreason]) => [
      { ...remote, params: { ...remote.params, [field]: input } },
      ["remote-status", null, subreason],
    ]),
    [{ id: 3, result: {} }, ["pending-id", "reply-number"]],
    [{ id: "private-id", result: {} }, ["pending-id", "reply-string"]],
    [{ id: null, result: {} }, ["pending-id", "reply-null"]],
    [{ id: true, result: {} }, ["pending-id", "reply-other"]],
    [{ id: 2, error: null }, ["error-payload"]],
    [overLine, ["line-bound"]],
    [overTotal, ["total-bound"]],
    [overErrors, ["total-bound"]],
  ]);
  for (const value of [
    '{"private-json":',
    { ...warning, params: { summary: "private-summary" } },
    { ...warning, params: { summary: 1, details: null } },
    { ...warning, params: { ...warning.params, details: 1 } },
    { ...warning, params: { ...warning.params, path: null } },
    {
      ...warning,
      params: {
        ...warning.params,
        range: { start: { line: 0, column: 1 }, end: { line: 1, column: 2 } },
      },
    },
    { ...warning, params: { ...warning.params, authority: true } },
    { id: 2, result: {}, error: { code: -32603, message: "private-error" } },
    { id: 2, result: {}, method: "" },
    { id: 2, error: { code: -32603 } },
    ...guardCases.keys(),
  ]) {
    const controller = new AbortController(),
      fixture = modelFreeFailureFixture(controller.signal);
    await fixture.client.initialize();
    let first;
    const readerStage =
      value === overTotal
        ? null
        : value === overErrors
          ? "stream"
          : value === overLine
            ? "envelope"
            : typeof value === "string"
              ? "json"
              : "envelope";
    const failure =
      value === overTotal ? "transport-failure" : "reader-failure";
    const [readerReason, readerShape = null, readerSubreason = null] =
      guardCases.get(value) ?? [];
    const rejected = assert.rejects(fixture.exec(), (error) => {
      first = error;
      assert.equal(
        error.code,
        value === overTotal
          ? "ERR_FEASIBILITY_TRANSPORT_FAILED"
          : "ERR_FEASIBILITY_READER_FAILED",
      );
      assert.equal(error.readerStage ?? null, readerStage);
      assert.equal(error.readerSubreason ?? null, readerSubreason);
      if (readerReason) {
        assert.equal(error.readerReason, readerReason);
        assert.equal(error.readerShape ?? null, readerShape);
      }
      return true;
    });
    fixture.inject(value);
    await rejected;
    if (value !== overTotal)
      fixture.output.write(
        JSON.stringify({
          id: 2,
          result: { exitCode: 0, stdout: "late", stderr: "" },
        }) + "\n",
      );
    fixture.completion.resolve(
      feasibilityCommandError("command", "later-close", { signal: "SIGABRT" }),
    );
    controller.abort();
    await assert.rejects(fixture.client.close(), (error) => error === first);
    await assert.rejects(fixture.exec(), (error) => error === first);
    const wrapped = feasibilityCommandError("command", "inspection", first);
    assert.equal(wrapped.cause, first);
    assert.match(
      wrapped.feasibilityCause.detail,
      new RegExp(
        `timeout=unknown; failure=${failure}, rpc=command-exec#2${readerStage ? `, reader=${readerStage}` : ""}(?:,|;)`,
      ),
    );
    if (readerReason)
      assert.match(
        wrapped.feasibilityCause.detail,
        new RegExp(
          `, reason=${readerReason}${readerShape ? `, shape=${readerShape}` : ""}(?:,|;)`,
        ),
      );
    if (readerSubreason)
      assert.match(
        wrapped.feasibilityCause.detail,
        new RegExp(`, subreason=${readerSubreason}(?:,|;)`),
      );
    else assert.doesNotMatch(wrapped.feasibilityCause.detail, /subreason=/u);
    assert.ok(Buffer.byteLength(wrapped.feasibilityCause.detail) <= 256);
    assert.doesNotMatch(
      JSON.stringify(wrapped),
      /private|synthetic|configWarning|remoteControl|serverName|installationId|environmentId|authority|emittedAtMs/u,
    );
    if (typeof value?.emittedAtMs === "number") {
      const metadata = String(value.emittedAtMs),
        serialized = JSON.stringify(wrapped);
      assert.ok(!serialized.includes(metadata));
      assert.ok(
        !serialized.includes(
          createHash("sha256").update(metadata).digest("hex"),
        ),
      );
    }
    const forged = feasibilityCommandError("command", "inspection", {
      ...first,
      readerStage: "private-stage",
      readerReason: "toString",
      readerShape: "private-shape",
      readerSubreason: "status",
      readerMetadata: "private-field",
    });
    assert.doesNotMatch(
      JSON.stringify(forged),
      /reader=|reason=|shape=|private|toString/u,
    );
    const forgedShape = feasibilityCommandError("command", "inspection", {
      ...first,
      readerShape: "private-shape",
      readerSubreason: "private-subreason",
      readerMetadata: "private-field",
    });
    assert.doesNotMatch(
      JSON.stringify(forgedShape),
      /shape=|subreason=|private/u,
    );
  }
  for (const checkpoint of [
    { code: "ERR_FEASIBILITY_RPC_REJECTED" },
    { readerStage: "stream" },
    { readerReason: "config-warning" },
  ]) {
    const unrelated = feasibilityCommandError("command", "inspection", {
      code: "ERR_FEASIBILITY_READER_FAILED",
      readerStage: "envelope",
      readerReason: "remote-status",
      readerSubreason: "status",
      ...checkpoint,
    });
    assert.doesNotMatch(JSON.stringify(unrelated), /subreason=/u);
  }
});

test("model-free RPC rejection facts stay bounded and first across later failures", async () => {
  const privateMessage =
    "exec failed: bwrap: Can't bind mount /private/fixture: No such file or directory\n" +
    "private-output \u{1f642}".repeat(800);
  for (const [code, message, timedOut, native] of [
    [-32603, privateMessage, "unknown", true],
    [-32045, privateMessage, "unknown", false],
    [-32603, "exec failed: sandbox error: command timed out", "true", false],
  ]) {
    const controller = new AbortController();
    const fixture = modelFreeFailureFixture(controller.signal, {
      code,
      message,
      data: { private: "discarded" },
    });
    await fixture.client.initialize();
    let first;
    await assert.rejects(fixture.exec(), (error) => {
      first = error;
      assert.equal(error.rpcCode, code);
      assert.ok(Buffer.byteLength(error.cause.message) <= 8192);
      return true;
    });
    fixture.completion.resolve(
      feasibilityCommandError("command", "later-close", { signal: "SIGABRT" }),
    );
    controller.abort();
    await assert.rejects(fixture.client.close(), (error) => error === first);
    const wrapped = feasibilityCommandError("command", "inspection", first);
    const cause = wrapped.feasibilityCause;
    assert.equal(wrapped.cause, first);
    assert.match(
      cause.detail,
      new RegExp(`exit=unknown, signal=unknown, timeout=${timedOut}`),
    );
    assert.match(cause.detail, /failure=rpc-rejection, rpc=command-exec#2/u);
    assert.match(
      cause.detail,
      new RegExp(
        `rpcCode=${code}, rejection=${code === -32603 ? "internal-error" : "unknown"}`,
      ),
    );
    assert.equal(cause.detail.includes("native=ENOENT"), native);
    assert.equal(cause.code, timedOut === "true" ? "deadline" : "setup-failed");
    assert.ok(Buffer.byteLength(cause.detail) <= 256);
    assert.doesNotMatch(
      JSON.stringify(wrapped),
      /private|discarded|bind mount/u,
    );
    assert.deepEqual(
      feasibilityCommandError("cleanup", "retirement", wrapped)
        .feasibilityCause,
      cause,
    );
  }
});

test("model-free reader failure retains its original error and deadline over later failures", async () => {
  for (const [code, timeout] of [
    ["EIO", "unknown"],
    ["ETIMEDOUT", "true"],
  ]) {
    const controller = new AbortController(),
      fixture = modelFreeFailureFixture(controller.signal);
    await fixture.client.initialize();
    const pending = fixture.exec();
    const original = Object.assign(
      new Error("/private/fixture reader failed"),
      { code },
    );
    let first;
    const rejected = assert.rejects(pending, (error) => {
      first = error;
      assert.equal(error.cause, original);
      assert.equal(error.readerStage, "stream");
      return true;
    });
    fixture.errorOutput.destroy(original);
    await rejected;
    controller.abort();
    fixture.completion.resolve(
      feasibilityCommandError("command", "later-close", { exitCode: 1 }),
    );
    await assert.rejects(fixture.client.close(), (error) => error === first);
    const wrapped = feasibilityCommandError("command", "inspection", first);
    assert.equal(wrapped.cause.cause, original);
    assert.match(
      wrapped.feasibilityCause.detail,
      new RegExp(
        `timeout=${timeout}; failure=reader-failure, rpc=command-exec#2.*native=${code}`,
      ),
    );
    assert.equal(
      wrapped.feasibilityCause.code,
      timeout === "true" ? "deadline" : "setup-failed",
    );
    assert.doesNotMatch(JSON.stringify(wrapped), /private|fixture/u);
  }
});

test("model-free request deadline stays explicit after later owned crash", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const fixture = modelFreeFailureFixture();
  await fixture.client.initialize();
  const pending = fixture.exec();
  let first;
  const rejected = assert.rejects(pending, (error) => {
    first = error;
    assert.equal(error.code, "ERR_FEASIBILITY_DEADLINE");
    return true;
  });
  t.mock.timers.tick(15000);
  await rejected;
  fixture.completion.resolve(
    feasibilityCommandError("command", "later-close", { signal: "SIGKILL" }),
  );
  await assert.rejects(fixture.client.close(), (error) => error === first);
  const wrapped = feasibilityCommandError("command", "inspection", first);
  assert.equal(wrapped.feasibilityCause.code, "deadline");
  assert.match(
    wrapped.feasibilityCause.detail,
    /signal=unknown, timeout=true; failure=deadline, rpc=command-exec#2/u,
  );
});

test("model-free native close remains the first failure across EOF and cleanup", async () => {
  const output = new PassThrough(),
    errorOutput = new PassThrough();
  const controller = new AbortController(),
    owned = Promise.withResolvers();
  const describe = (error) =>
    feasibilityCommandError("command", "transport-admission", error);
  const completion = observeFeasibilityCompletion(
    { stderr: errorOutput, ownedCompletion: owned.promise },
    (error) => {
      assert.equal(error.stderr.length, 8192);
      return describe(error);
    },
  );
  const input = new PassThrough();
  const client = openFeasibilityCommand(
    { input, output, errorOutput, completion },
    controller.signal,
    "linux",
  );
  const pending = client.initialize();
  input.emit(
    "error",
    Object.assign(new Error("write failed"), { code: "EPIPE" }),
  );
  errorOutput.end(
    "strace: /private/fixture/output: No such device or address\n" +
      "x".repeat(8192),
  );
  output.end();
  owned.resolve({ outcome: { type: "close", exitCode: 1, signal: null } });
  const original = await completion;
  await assert.rejects(pending, (error) => error === original);
  assert.match(
    original.feasibilityCause.detail,
    /exit=1, signal=none.*output=unrecognized/u,
  );
  assert.doesNotMatch(JSON.stringify(original), /private|fixture|strace/u);
  controller.abort();
  await assert.rejects(client.close());
  const cleanup = {
    code: "cleanup-unobserved",
    detail: "No retirement witness.",
  };
  original.feasibilityCleanupCause = cleanup;
  const wrapped = feasibilityCommandError("cleanup", "retirement", original);
  assert.deepEqual(wrapped.feasibilityCause, original.feasibilityCause);
  assert.deepEqual(wrapped.feasibilityCleanupCause, cleanup);
  const rejected = Promise.reject(
    Object.assign(new Error("private"), { code: "EACCES" }),
  );
  const startup = await observeFeasibilityCompletion(
    { stderr: new PassThrough(), ownedCompletion: rejected },
    describe,
  );
  assert.match(startup.feasibilityCause.detail, /exit=unknown.*native=EACCES/u);
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
  for (const [error, failure] of [
    [new FeasibilityError(), "invalid-feasibility"],
    [new Error("Unverified native tool observation"), "invalid-observation"],
    ...["capture-bound", "capture-substitution", "trace-incomplete"].map(
      (namespaceNativeCode) => [
        Object.assign(new Error("/private/fixture"), { namespaceNativeCode }),
        namespaceNativeCode,
      ],
    ),
  ]) {
    Object.assign(error, { line: "private-line", pid: 12345, sha256: DIGEST });
    const first = feasibilityCommandError("command", "trace-read", error);
    assert.equal(first.cause, error);
    assert.equal(
      unavailableFeasibilityResults("linux", first.feasibilityCause)[0].status,
      "FAIL",
    );
    assert.match(
      first.feasibilityCause.detail,
      new RegExp(
        `^command trace-read: exit=unknown, signal=unknown, timeout=unknown; failure=${failure};`,
      ),
    );
    assert.ok(Buffer.byteLength(first.feasibilityCause.detail) <= 256);
    assert.doesNotMatch(JSON.stringify(first), /private|fixture|12345/u);
    assert.ok(!JSON.stringify(first).includes(DIGEST));
    first.feasibilityCleanupCause = {
      code: "cleanup-unobserved",
      detail: "No retirement witness.",
    };
    const cleanup = feasibilityCommandError("cleanup", "retirement", first);
    assert.deepEqual(cleanup.feasibilityCause, first.feasibilityCause);
    assert.deepEqual(
      cleanup.feasibilityCleanupCause,
      first.feasibilityCleanupCause,
    );
    assert.doesNotMatch(
      feasibilityCommandError("command", "inspection", error).feasibilityCause
        .detail,
      /failure=/u,
    );
  }
  const unknown = feasibilityCommandError("command", "trace-read", {
    message: "Unverified native tool observation /private/fixture",
    namespaceNativeCode: "toString",
    line: "private-line",
    pid: 12345,
  });
  assert.doesNotMatch(
    JSON.stringify(unknown),
    /failure=|private|fixture|toString|12345/u,
  );
  assert.match(
    unknown.feasibilityCause.detail,
    /exit=unknown, signal=unknown, timeout=unknown/u,
  );
  const protocol = feasibilityCommandError("command", "client-close", {
    code: "ERR_FEASIBILITY_READER_FAILED",
    message: "Unverified native tool observation",
    namespaceNativeCode: "capture-bound",
  });
  assert.match(protocol.feasibilityCause.detail, /failure=reader-failure;/u);
  assert.doesNotMatch(
    protocol.feasibilityCause.detail,
    /invalid-observation|capture-bound/u,
  );
});

test("model-free successful transport completion cannot replace fresh owner retirement", async () => {
  const child = {
    stderr: new PassThrough(),
    controllerClosed: Promise.resolve(),
    linuxCommandReceipt: { file: "/fixture/receipt.json", sha256: DIGEST },
    ownedCompletion: Promise.resolve({
      outcome: { type: "close", exitCode: 0, signal: null },
    }),
  };
  assert.equal(
    await observeFeasibilityCompletion(child, () =>
      assert.fail("Successful transport."),
    ),
    null,
  );
  const verification = verifyLinuxCommandControllers([child], {
    verify: async () => {
      return {
        status: "RETAINED",
        independent: false,
        emergencyCleanup: false,
      };
    },
  });
  await assert.rejects(verification, FeasibilityError);
  delete child.linuxCommandReceipt;
  await assert.rejects(
    verifyLinuxCommandControllers([child], {
      verify: () => assert.fail("Missing receipt."),
    }),
  );
});

test("model-free completion checkpoints own attribution before each existing operation", async () => {
  const source = await readFile(
    new URL("../ci/native/providers/feasibility-command.js", import.meta.url),
    "utf8",
  );
  for (const boundary of [
    /operation = "trace-read";\s+for \(const line of \(await capture\.read\(\)\)/u,
    /operation = "trace-line-decode";\s+const event = decoder\.line\(line\);/u,
    /operation = "trace-finish";\s+return decoder\.finish\(\);/u,
    /operation = "client-close";\s+await client\.close\(\);/u,
    /operation = "transport-completion";\s+const completion = await child\.ownedCompletion;/u,
    /operation = "completion-validation";\s+commandEvidence\(/u,
    /operation = "retirement-verification";\s+settlements = await verifyRetirement\(\);/u,
    /settlements = await verifyRetirement\(\);\s+await trace\(\);\s+operation = "exact-exec-join";/u,
    /operation = "exact-exec-join";\s+commandEvidence\(/u,
    /operation = "file-join";\s+commandEvidence\(/u,
    /operation = "emergency-check";\s+commandEvidence\(\s*!emergency,/u,
  ])
    assert.ok(boundary.test(source), String(boundary));
  let previous = source.indexOf('operation = "outside-write-denial";');
  for (const operation of [
    "client-close",
    "transport-completion",
    "completion-validation",
    "retirement-verification",
    "exact-exec-join",
    "file-join",
    "emergency-check",
  ]) {
    const position = source.indexOf(`operation = "${operation}";`);
    assert.ok(position > previous, operation);
    previous = position;
  }
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
    { cleanupCause: undefined },
    { cleanupCause: {} },
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
  for (const policy of [readOnly, editing]) {
    assert.deepEqual(
      policy.split("\n").filter((line) => line.includes('(literal "/")')),
      ['(allow file-read-data (literal "/"))'],
    );
    assert.doesNotMatch(
      policy,
      /\(subpath "\/"\)|^\(allow file-read[^ ]*\)$/mu,
    );
  }
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

function darwinBundleFixture(t, fault = null) {
  const owner = {
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
  const parked = { ...owner, pid: 43, pidVersion: 8, startMicroseconds: 10 };
  const events = [],
    saved = [],
    calls = new Map();
  const primary = new Error("Independent child image observer failed");
  if (["observer-loss", "child-cleanup", "native-cleanup"].includes(fault))
    Object.assign(primary, {
      code: 78,
      stderr: Buffer.from(
        "native-darwin: operation=task-name domain=mach value=5 effects=none settlement=unsettled\n",
      ),
    });
  const child = Object.assign(new EventEmitter(), {
    pid: owner.pid,
    stdin: new PassThrough(),
    stdout: new PassThrough(),
    stderr: new PassThrough(),
  });
  let closed = false;
  const close = (code = 126) => {
    if (closed) return;
    closed = true;
    if (fault === "native-cleanup")
      child.stderr.write(
        "native-darwin: operation=bundle-authorization domain=invariant value=0 effects=possible settlement=unsettled\nnative-darwin-cleanup: operation=bundle-wait domain=errno value=5 effects=possible settlement=unsettled\n",
      );
    child.stdout.end();
    child.stderr.end();
    child.emit("close", code, null);
  };
  t.after(() => {
    child.stdin.destroy();
    child.stdout.destroy();
    child.stderr.destroy();
  });
  const running = openDarwinFeasibilitySession("/fixture", "bundle", [], {
    launch: () => child,
  });
  const send = (value) => child.stdout.write(JSON.stringify(value) + "\n");
  const pair = (operation, error) => {
    send({ event: "attempt", operation });
    send({ event: "completed", operation, error });
  };
  child.stdin.on("data", (bytes) => {
    const value = bytes.toString();
    events.push(`release:${value}`);
    if (value === "A") {
      pair("inspect", 0);
      pair("edit", 13);
      if (fault === "truncated-locator") {
        child.stdout.write('{"event":"attempt"');
        close();
        return;
      }
      send({
        event: "attempt",
        operation: "git-status",
        childPid: fault === "locator" ? 44 : parked.pid,
      });
    } else {
      assert.equal(value, "G");
      if (fault === "git-interrupted") {
        close();
        return;
      }
      send({ event: "completed", operation: "git-status", error: 0 });
      for (const operation of [
        "git-index",
        "git-ref",
        "control",
        "outside",
        "tcp",
        "unix",
      ])
        pair(operation, 13);
      close(0);
    }
  });
  child.stdin.once("finish", () => close());
  child.stdin.once("close", () => close());
  child.stderr.write(
    "native-darwin-phase: phase=policy-enter\nnative-darwin-phase: phase=policy-applied\n",
  );
  send({ event: "ready" });
  const policy = darwinFeasibilityPolicy("/fixture");
  const inspect = async (_root, operation, ...args) => {
    const pid = operation === "identity" ? Number(args[0]) : Number(args[5]);
    const key = `${operation}:${pid}`,
      count = (calls.get(key) ?? 0) + 1;
    calls.set(key, count);
    events.push(key);
    if (operation === "identity") {
      assert.equal(Number(args[1]), pid === owner.pid ? 9000 : owner.pid);
      if (fault === "owner-parent" && pid === owner.pid) throw primary;
      if (fault === "parent-join" && pid === parked.pid) throw primary;
      if (![owner.pid, parked.pid].includes(pid)) throw primary;
      const value = { ...(pid === owner.pid ? owner : parked) };
      if (
        (fault === "parent-birth" && pid === owner.pid && count === 4) ||
        (fault === "child-birth" && pid === parked.pid && count === 2)
      )
        value.pidVersion++;
      if (fault === "child-credentials" && pid === parked.pid) value.uid++;
      return value;
    }
    if (operation === "files")
      return [
        {
          sha256:
            fault === "policy-file" && count > 1
              ? DIGEST
              : createHash("sha256").update(policy).digest("hex"),
        },
      ];
    if (operation === "image") {
      assert.equal(args.at(-1), "/fixture/build/helper");
      assert.equal(
        running.bundleCustody[pid === owner.pid ? "owner" : "child"].pid,
        pid,
      );
      if (pid === parked.pid) {
        if (
          ["observer-loss", "child-cleanup", "native-cleanup"].includes(fault)
        )
          throw primary;
        if (fault === "partial") child.stdout.write('{"event":');
        if (fault === "partial-utf8") child.stdout.write(Buffer.from([0xe2]));
        if (fault === "premature-completion")
          send({ event: "completed", operation: "git-status", error: 0 });
        if (fault === "malformed") child.stdout.write("invalid\n");
        if (fault === "native-refusal")
          child.stderr.write(
            "native-darwin: operation=bundle-authorization domain=invariant value=0 effects=possible settlement=unsettled\n",
          );
        if (fault === "input-error") child.stdin.emit("error", primary);
        if (["output-error", "stream-then-observer"].includes(fault)) {
          child.stdout.emit("error", primary);
          events.push(`output-refused:${child.stdin.writableEnded}`);
          if (fault === "stream-then-observer")
            throw new Error("Later image observation failed");
        }
        if (fault === "stderr-error") {
          child.stderr.emit("error", primary);
          events.push(`output-refused:${child.stdin.writableEnded}`);
        }
        if (fault === "stdout-end" || fault === "stderr-end") {
          const stream = fault === "stdout-end" ? child.stdout : child.stderr;
          const ended = once(stream, "end");
          stream.end();
          await ended;
          assert.equal(child.stdin.writableEnded, true);
        }
        if (fault === "stdout-close") {
          const closed = once(child.stdout, "close");
          child.stdout.destroy();
          await closed;
          assert.equal(child.stdin.writableEnded, true);
        }
      }
      return {
        sha256:
          (fault === "parent-image" && pid === owner.pid && count > 1) ||
          (fault === "child-image" && pid === parked.pid)
            ? SHA
            : DIGEST,
      };
    }
    if (operation === "policy")
      return {
        sandboxed: !(
          (fault === "parent-policy" && pid === owner.pid && count > 1) ||
          (fault === "child-policy" && pid === parked.pid)
        ),
      };
    assert.ok(["observe", "retire"].includes(operation));
    if (fault === "child-cleanup" && pid === parked.pid)
      throw new Error("Child settlement observer unavailable");
    assert.deepEqual(
      args,
      darwinFeasibilityIdentityArguments(pid === owner.pid ? owner : parked),
    );
    if (
      ["child-live", "git-interrupted"].includes(fault) &&
      pid === parked.pid &&
      operation === "observe"
    )
      return { status: "LIVE" };
    return { status: "RETIRED" };
  };
  return {
    owner,
    parked,
    running,
    child,
    events,
    saved,
    primary,
    run: () =>
      runDarwinFeasibilityBundle(
        "/fixture",
        running,
        [{ role: "helper", name: "helper", sha256: DIGEST }],
        "/fixture/evidence/read-only.sb",
        policy,
        {
          ownerPid: 9000,
          inspect,
          save: async (_root, name, custody) => saved.push({ name, custody }),
        },
      ),
  };
}

test("Darwin parked Git admission binds original identities, images and policy before separate release", async (t) => {
  const f = darwinBundleFixture(t);
  const proof = await f.run();
  assert.equal(proof.receipts.length, 19);
  assert.deepEqual(proof.gitIdentity, f.parked);
  assert.deepEqual(
    f.events.filter((event) => event.startsWith("release:")),
    ["release:A", "release:G"],
  );
  assert.ok(
    f.events.lastIndexOf("identity:42") < f.events.indexOf("release:G"),
  );
  assert.ok(
    f.events.lastIndexOf("identity:43") < f.events.indexOf("release:G"),
  );
  assert.ok(f.events.indexOf("observe:43") < f.events.indexOf("retire:42"));
  assert.equal(proof.custody.closed, true);
  assert.equal(f.saved[0].name, "read-only-custody");
  for (const fault of [
    "owner-parent",
    "locator",
    "parent-join",
    "truncated-locator",
    "parent-birth",
    "child-birth",
    "child-credentials",
    "parent-image",
    "child-image",
    "parent-policy",
    "child-policy",
    "policy-file",
  ]) {
    const denied = darwinBundleFixture(t, fault);
    await assert.rejects(denied.run());
    assert.ok(!denied.events.includes("release:G"), fault);
    assert.equal(denied.saved.length, 1);
    assert.equal(denied.child.stdin.writableEnded, true);
    if (
      ["owner-parent", "locator", "parent-join", "truncated-locator"].includes(
        fault,
      )
    ) {
      assert.equal(denied.running.bundleCustody.child, null);
      assert.ok(!denied.events.includes("retire:42"));
    }
  }
});

test("Darwin parked Git failure retains births and first cause while unresolved children fence parent retirement", async (t) => {
  for (const fault of [
    "observer-loss",
    "child-cleanup",
    "native-cleanup",
    "stream-then-observer",
  ]) {
    const f = darwinBundleFixture(t, fault);
    await assert.rejects(f.run(), (error) => {
      assert.equal(error, f.primary);
      if (fault !== "stream-then-observer")
        assert.match(
          error.stderr.toString(),
          /operation=task-name domain=mach value=5/u,
        );
      assert.deepEqual(error.nativeCustody.child, f.parked);
      if (fault === "child-cleanup") {
        assert.equal(error.feasibilityCleanup.status, "UNCERTAIN");
        assert.equal(error.feasibilityCleanup.emergency, false);
        assert.equal(error.nativeCustody.childRetired, null);
      }
      if (fault === "native-cleanup") {
        assert.equal(error.feasibilityCleanup.status, "UNCERTAIN");
        assert.match(
          error.feasibilityCleanup.cause.detail,
          /bundle-wait.*errno=5/u,
        );
        assert.equal(error.nativeCustody.nativeCleanup.value, 5);
      }
      return true;
    });
    assert.ok(!f.events.includes("release:G"));
    assert.equal(f.events.includes("retire:42"), fault !== "child-cleanup");
    assert.equal(f.saved[0].custody.closed, true);
    assert.deepEqual(f.saved[0].custody.child, f.parked);
  }
  for (const fault of ["child-live", "git-interrupted"]) {
    const f = darwinBundleFixture(t, fault);
    await assert.rejects(f.run(), (error) => {
      assert.match(
        error.message,
        fault === "child-live"
          ? /remains live/u
          : /receipt stream ended before completion/u,
      );
      return true;
    });
    assert.ok(f.events.includes("release:G"));
    assert.ok(f.events.indexOf("retire:43") < f.events.indexOf("retire:42"));
    assert.equal(f.saved[0].custody.childRetired.status, "RETIRED");
  }
});

test("Darwin bundle release refuses partial framing, malformed output, native refusal and input loss", async (t) => {
  for (const fault of [
    "partial",
    "partial-utf8",
    "premature-completion",
    "malformed",
    "native-refusal",
    "input-error",
    "output-error",
    "stderr-error",
    "stdout-end",
    "stderr-end",
    "stdout-close",
  ]) {
    const f = darwinBundleFixture(t, fault);
    await assert.rejects(f.run());
    assert.ok(!f.events.includes("release:G"), fault);
    assert.equal(f.child.stdin.writableEnded, true);
    assert.equal(f.saved.length, 1);
    assert.deepEqual(f.running.bundleCustody.child, f.parked);
    if (["output-error", "stderr-error"].includes(fault))
      assert.ok(f.events.includes("output-refused:true"));
  }
});

test("Darwin bundle source parks on an EOF-only private gate and independently reaps every original child", async () => {
  const source = await readFile(
    new URL("../ci/native/darwin/feasibility-helper.c", import.meta.url),
    "utf8",
  );
  const bundle = source.slice(
    source.indexOf("static void bundle("),
    source.indexOf("static void fault("),
  );
  assert.doesNotMatch(bundle, /inspect\(|task_name_for_pid|emit_identity/u);
  assert.ok(
    bundle.indexOf("bundle_child = child;") < bundle.indexOf("childPid"),
  );
  assert.ok(
    bundle.indexOf("read(0, &release, 1)") <
      bundle.indexOf('write(bundle_gate[1], "G", 1)'),
  );
  assert.match(
    bundle,
    /invariant\(received == 1 && release == 'G', "bundle-authorization"\)/u,
  );
  assert.match(bundle, /written == 1/u);
  assert.match(bundle, /waitpid\(bundle_child, &status, 0\)/u);
  assert.match(
    bundle,
    /execl\(args\[7\], "git", "-c", "core.fsmonitor=false", "status", "--porcelain"/u,
  );
  for (const field of [
    "pbi_ppid",
    "pbi_uid",
    "pbi_gid",
    "pbi_ruid",
    "pbi_rgid",
    "pbi_svuid",
    "pbi_svgid",
  ])
    assert.ok(source.includes(`after.${field} == value->bsd.${field}`), field);
  assert.match(
    source,
    /invariant\(value.bsd.pbi_ppid == parent, "identity-parent"\)/u,
  );
  assert.match(
    source,
    /if \(prerequisite_mode\) settle_prerequisite\(\);\s*settle_bundle\(\);/u,
  );
  const gate = bundle
    .slice(
      bundle.indexOf("int closed = close(bundle_gate[1]);"),
      bundle.indexOf('int null = open("/dev/null"'),
    )
    .replace(/\b(?:int|ssize_t|char)\b/gu, "let")
    .replace(/&byte\b/gu, "(value) => byte = value");
  const dispatch = new Script(
    `function run() {${gate} execAllowed = true;} run();`,
  );
  for (const byte of [null, "N", "G"]) {
    const api = {
      bundle_gate: [11, 12],
      errno: 0,
      EINTR: 4,
      execAllowed: false,
      close: () => 0,
      posix_check: (value) => assert.ok(value >= 0),
      remember: () => {},
      read: (_fd, output) => {
        if (byte !== null) output(byte);
        return byte === null ? 0 : 1;
      },
      failure: (code) => {
        throw code;
      },
      _exit: (code) => {
        throw code;
      },
    };
    let exit;
    try {
      dispatch.runInNewContext(api);
    } catch (code) {
      exit = code;
    }
    assert.equal(api.execAllowed, byte === "G");
    assert.equal(exit, byte === "G" ? undefined : 0);
  }
});

function darwinFaultFixture(
  fault = "survives",
  caseId = "cancel",
  completeDomain = false,
) {
  const owner = {
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
  const descendant = {
    ...owner,
    pid: 43,
    pidVersion: 8,
    startMicroseconds: 10,
    ...(fault === "credentials" ? { uid: 502 } : {}),
  };
  const events = [],
    saved = new Map(),
    calls = new Map();
  const primary = new Error("Original outside observer refused");
  primary.code = 78;
  primary.stderr = Buffer.from(
    "native-darwin: operation=task-name domain=mach value=5 effects=none settlement=unsettled\n",
  );
  let ownerLive = true,
    childLive = true,
    writes = 0;
  const records = [
    { event: "armed", ownerPid: owner.pid, childPid: descendant.pid },
    { event: "detached" },
    { event: "fault-ack", caseId: fault === "ack" ? "other" : caseId },
  ];
  const armed = records[0];
  if (completeDomain) armed.controls = fault !== "controls";
  if (fault === "locator-owner") armed.ownerPid++;
  if (fault === "locator-child") armed.childPid = "43";
  if (fault === "locator-bound") armed.childPid = 0x80000000;
  if (fault === "locator-self") armed.childPid = owner.pid;
  if (fault === "locator-extra") armed.extra = true;
  const running = {
    child: { pid: owner.pid, stdin: { writableEnded: false } },
    next: async () => records.shift(),
    authorize: async (value) => {
      assert.equal(value, writes === 0 ? "A" : caseId === "cancel" ? "C" : "L");
      writes++;
      events.push("release:" + value);
      if (value !== "A") events.push("ack");
    },
    authorizationStarted: () => writes > 0,
    closeInput: () => {
      running.child.stdin.writableEnded = true;
      if (!writes) {
        childLive = false;
        if (fault !== "unclosed") ownerLive = false;
      }
    },
    finish: async (signal) => {
      assert.equal(signal, caseId === "cancel" ? "SIGTERM" : "SIGKILL");
      events.push("closed");
    },
    waitClosed: async () => {
      events.push("closed");
      if (fault === "unclosed") throw new Error("Unproved helper closure");
    },
    failure: () => null,
    diagnostic: () =>
      fault.startsWith("reaping")
        ? { operation: "fault-wait", domain: "errno", value: 5 }
        : null,
  };
  const inspect = async (_root, operation, ...args) => {
    const selected = Number(args[operation === "identity" ? 0 : 5]);
    const identity = selected === owner.pid ? owner : descendant;
    const key = operation + ":" + selected,
      count = (calls.get(key) ?? 0) + 1;
    calls.set(key, count);
    events.push(key);
    if (operation === "identity") {
      assert.equal(Number(args[1]), selected === owner.pid ? 9000 : owner.pid);
      if (
        (fault === "owner-acquire" && selected === owner.pid) ||
        (fault === "child-acquire" && selected === descendant.pid)
      )
        throw primary;
      const value = { ...identity };
      if (fault === "birth-drift" && selected === descendant.pid && count === 3)
        value.pidVersion++;
      return value;
    }
    if (operation === "files")
      return [
        {
          identity: "policy",
          sha256:
            fault === "policy-file" && count > 1
              ? DIGEST
              : createHash("sha256")
                  .update(darwinFeasibilityPolicy("/fixture"))
                  .digest("hex"),
        },
      ];
    assert.deepEqual(
      args.slice(0, 12),
      darwinFeasibilityIdentityArguments(identity),
    );
    if (operation === "image" || operation === "policy") {
      assert.deepEqual(running.faultCustody.owner, owner);
      assert.ok(running.faultCustody.child); // Both births precede every binding query.
      if (
        (["observer", "unproved", "unclosed"].includes(fault) ||
          fault.startsWith("reaping")) &&
        operation === "image"
      )
        throw primary;
      return operation === "image"
        ? { sha256: fault === "image-drift" && count > 1 ? SHA : DIGEST }
        : { sandboxed: !(fault === "policy-drift" && count > 1) };
    }
    if (
      selected === descendant.pid &&
      operation === "observe" &&
      (fault === "unproved" || (fault === "observation" && count === 1))
    )
      throw primary;
    if (operation === "cancel" || operation === "retire") {
      if (selected === descendant.pid) childLive = false;
      else {
        ownerLive = false;
        if (fault === "retired") childLive = false;
      }
    }
    return {
      status: (selected === owner.pid ? ownerLive : childLive)
        ? "LIVE"
        : "RETIRED",
    };
  };
  const custodian = {
    ...owner,
    pid: 9000,
    asid: 3,
    auid: 0,
    uid: 0,
    ruid: 0,
    svuid: 0,
    gid: 0,
    rgid: 0,
    svgid: 0,
  };
  let admission;
  const domain = completeDomain
    ? {
        parentPid: 9000,
        intent: async (pin) => {
          events.push("protected-intent");
          admission = {
            emergency: false,
            candidateSha: SHA,
            caseId,
            stage: 2,
            asid: owner.asid,
            intentSha256: pin,
            helperSha256: DIGEST,
            policySha256: createHash("sha256")
              .update(darwinFeasibilityPolicy("/fixture"))
              .digest("hex"),
            owner,
            descendant,
            custodian,
          };
          return structuredClone(admission);
        },
        retire: async () => {
          events.push("domain-retire");
          if (["lost-custody", "census-unavailable"].includes(fault))
            throw primary;
          childLive = false;
          const record = {
            ...admission,
            stage: 5,
            members: [
              owner,
              descendant,
              ...(fault === "extra-member"
                ? [{ ...descendant, pid: 44, pidVersion: 9 }]
                : []),
            ],
          };
          if (fault === "stale-receipt") record.intentSha256 = "f".repeat(64);
          const changed = {
            "stale-candidate": ["candidateSha", "f".repeat(40)],
            "stale-case": ["caseId", "other"],
            "stale-helper": ["helperSha256", "f".repeat(64)],
            "stale-policy": ["policySha256", "f".repeat(64)],
          }[fault];
          if (changed) record[changed[0]] = changed[1];
          const fresh = {
            independent: true,
            complete: fault !== "partial-census",
            held: fault !== "unheld",
            record,
            verifier: { ...custodian, pid: 9100 },
          };
          const settled = {
            independent: true,
            complete: true,
            held: false,
            record: { ...record, stage: 6 },
            verifier: { ...custodian, pid: 9200 },
          };
          events.push("fresh-domain");
          events.push("custodian-retired");
          return {
            complete: true,
            independent: true,
            nonEmergency: fault !== "emergency",
            record,
            fresh,
            settled,
          };
        },
        abort: async () => {
          events.push("emergency");
          if (fault === "lost-custody") throw primary;
        },
      }
    : null;
  return {
    owner,
    descendant,
    primary,
    events,
    saved,
    running,
    run: () =>
      runDarwinFeasibilityFault(
        "/fixture",
        running,
        [{ role: "helper", name: "helper", sha256: DIGEST }],
        {},
        caseId,
        SHA,
        {
          domain,
          ownerPid: 9000,
          inspect,
          snapshot: async () => {
            if (fault === "snapshot") throw primary;
            return {};
          },
          save: async (_root, name, record) => {
            if (
              ["reaping-save", "save"].includes(fault) &&
              name.endsWith("-custody")
            )
              throw new Error("Custody persistence failed");
            events.push("save:" + name);
            saved.set(name, structuredClone(record));
          },
          read: async (file) =>
            fault === "intent-drift"
              ? "changed"
              : JSON.stringify(saved.get(path.basename(file, ".json"))),
        },
      ),
  };
}

test("Darwin faults retain outside births and original verdicts before cleanup intervention", async () => {
  for (const caseId of ["cancel", "owner-loss"])
    for (const fault of ["survives", "retired"]) {
      const f = darwinFaultFixture(fault, caseId),
        entry = await f.run();
      assert.equal(entry.status, fault === "survives" ? "FAIL" : "BLOCKED");
      assert.equal(
        entry.cause.code,
        fault === "survives" ? "observed-escape" : "prerequisite-unavailable",
      );
      assert.equal(
        entry.cleanup.status,
        fault === "survives" ? "UNCERTAIN" : "PASS",
      );
      assert.equal(entry.cleanup.independent, true);
      const before = (a, b) => {
        const first = f.events.indexOf(a),
          second = f.events.indexOf(b);
        assert.ok(first >= 0 && first < second, `${a} before ${b}`);
      };
      before("identity:43", "image:42");
      before("save:" + caseId + "-intent", "release:A");
      before("release:A", "ack");
      before("ack", (caseId === "cancel" ? "cancel" : "retire") + ":42");
      before("observe:42", "save:" + caseId);
      before("observe:43", "save:" + caseId);
      if (fault === "survives") before("save:" + caseId, "retire:43");
      assert.equal(f.saved.get(caseId).decision.status, entry.status);
      assert.deepEqual(f.running.faultCustody.child, f.descendant);
    }
});

test("Darwin original faults pass only with protected complete independent domain retirement", async () => {
  for (const caseId of ["cancel", "owner-loss"]) {
    const f = darwinFaultFixture("extra-member", caseId, true),
      entry = await f.run();
    assert.equal(entry.status, "PASS", JSON.stringify(entry));
    assert.equal(
      entry.evidence.outcome,
      feasibilityCapabilities("darwin").find(
        ({ id }) => id === `ownership.${caseId}`,
      ).outcome,
    );
    assert.equal(entry.cleanup.status, "PASS");
    assert.equal(entry.cleanup.emergency, false);
    const proof = f.saved.get(caseId).domain;
    assert.equal(proof.record.members.length, 3);
    assert.ok(
      f.events.indexOf("protected-intent") < f.events.indexOf("release:A"),
    );
    assert.ok(f.events.indexOf("ack") < f.events.indexOf("domain-retire"));
    assert.ok(
      f.events.indexOf("fresh-domain") < f.events.indexOf("custodian-retired"),
    );
    assert.deepEqual(proof.record.owner, f.owner);
    assert.deepEqual(proof.record.descendant, f.descendant);
  }
  for (const fault of [
    "controls",
    "lost-custody",
    "census-unavailable",
    "partial-census",
    "stale-receipt",
    "stale-candidate",
    "stale-case",
    "stale-helper",
    "stale-policy",
    "unheld",
    "emergency",
    "intent-drift",
    "snapshot",
    "save",
    "ack",
  ]) {
    const f = darwinFaultFixture(fault, "owner-loss", true),
      entry = await f.run();
    assert.notEqual(entry.status, "PASS", fault);
    assert.equal(entry.cleanup.status, "UNCERTAIN", fault);
    assert.equal(entry.cleanup.emergency, true, fault);
    if (["controls", "intent-drift"].includes(fault))
      assert.ok(!f.events.includes("release:A"), fault);
  }
});

test("Darwin fault custody channel retains native failure diagnostics and handles output errors", async (t) => {
  for (const fault of [
    "native-exit",
    "stream-error",
    "late-native-exit",
    "access-refusal",
    "diagnostic-sink",
  ]) {
    const child = Object.assign(new EventEmitter(), {
      stdin: new PassThrough(),
      stdout: new PassThrough(),
      stderr: new PassThrough(),
    });
    t.after(() => {
      for (const stream of [child.stdin, child.stdout, child.stderr])
        stream.destroy();
    });
    const custodian = {
      pid: 9000,
      pidVersion: 1,
      asid: 3,
      auid: 0,
      uid: 0,
      gid: 0,
      ruid: 0,
      rgid: 0,
      svuid: 0,
      svgid: 0,
      startSeconds: 100,
      startMicroseconds: 1,
    };
    const raw = [],
      diagnostic = ["access-refusal", "diagnostic-sink"].includes(fault)
        ? "native-darwin-fault-access-lifecycle: phase=custodian-fork pid=9000 parent=1 uid=0 euid=0 gid=0 egid=0 get=0 name=200 type=0x10000 query=0 release=0\n" +
          "native-darwin-fault-access-lifecycle: phase=untrusted malformed private=value\n" +
          "native-darwin: operation=fault-access-authority domain=invariant value=0 effects=possible settlement=unsettled\n" +
          "native-darwin-cleanup: operation=fault-access-release domain=mach value=15 effects=possible settlement=unsettled\n"
        : "native-darwin: operation=bsd-identity domain=errno value=5 effects=possible settlement=unsettled\n";
    const streamError = new Error("Custody output unavailable");
    child.stdin.on("data", () => {
      try {
        if (
          !["native-exit", "access-refusal", "diagnostic-sink"].includes(fault)
        )
          child.stdout.emit("error", streamError);
        if (fault !== "stream-error") {
          child.stderr.write(diagnostic.slice(0, 40));
          child.stderr.write(diagnostic.slice(40));
        }
      } finally {
        child.emit("close", fault !== "stream-error" ? 78 : 0, null);
      }
    });
    const domain = await withNativeDiagnostics(
      () =>
        openDarwinFaultDomain(
          "/fixture",
          SHA,
          "cancel",
          "c".repeat(32),
          DIGEST,
          DIGEST,
          {},
          (_root, _operation, _args, { launch }) => {
            const virtual = launch();
            virtual.on("error", (error) => {
              error.stderr = Buffer.from("payload diagnostics");
            });
            return { failure: () => null };
          },
          {
            uid: 501,
            gid: 20,
            launch: () => {
              queueMicrotask(() =>
                child.stdout.write(
                  JSON.stringify({
                    ready: {
                      candidateSha: SHA,
                      caseId: "cancel",
                      stage: 1,
                      helperSha256: DIGEST,
                      policySha256: DIGEST,
                      asid: 55,
                      custodian,
                      owner: { pid: 42 },
                    },
                  }) + "\n",
                ),
              );
              return child;
            },
          },
        ),
      (owner, value) => {
        assert.equal(owner, "darwin-fault-custody");
        if (value.stderr) {
          raw.push(value.stderr);
          if (fault === "diagnostic-sink")
            throw new Error("Diagnostic sink failure");
        }
      },
    );
    await assert.rejects(
      domain.inspect("/fixture", "identity", "42", "9000"),
      (error) => {
        assert.equal(domain.running.failure(), error);
        if (fault === "late-native-exit") assert.equal(error, streamError);
        if (fault !== "stream-error") {
          assert.equal(error.exitCode, 78);
          assert.equal(error.stderr.toString(), diagnostic);
          assert.match(
            darwinFeasibilityCause("cancel", error).detail,
            ["access-refusal", "diagnostic-sink"].includes(fault)
              ? /fault-access-authority failed.*invariant=0/u
              : /bsd-identity failed.*errno=5/u,
          );
        } else assert.equal(error, streamError);
        return true;
      },
    );
    assert.equal(
      Buffer.concat(raw).toString(),
      fault === "stream-error" ? "" : diagnostic,
    );
  }
});

test("Darwin fault custody transport keeps the original fault stdio separate from protected retirement", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  for (const [caseId, trailing] of [
    ["cancel", null],
    ["owner-loss", null],
    ["cancel", "malformed"],
    ["cancel", "partial"],
    ["cancel", "unclosed"],
    ["owner-loss", "malformed"],
    ["owner-loss", "partial"],
    ["owner-loss", "unclosed"],
    ["cancel", "startup"],
    ["owner-loss", "startup"],
    ["cancel", "preexec"],
    ["owner-loss", "preexec"],
    ["cancel", "preexec-signal"],
    ["cancel", "recovery-incomplete"],
    ["cancel", "recovery-birth"],
    ["cancel", "recovery-close"],
    ["cancel", "recovery-emergency"],
    ["cancel", "admission"],
  ]) {
    const recovering =
      trailing?.startsWith("preexec") || trailing?.startsWith("recovery-");
    const owner = {
      pid: 42,
      pidVersion: 7,
      asid: 55,
      auid: 90001,
      uid: 90001,
      gid: 90002,
      ruid: 90001,
      rgid: 90002,
      svuid: 90001,
      svgid: 90002,
      startSeconds: 100,
      startMicroseconds: 1,
    };
    const descendant = {
      ...owner,
      pid: 43,
      pidVersion: 8,
      startMicroseconds: 2,
    };
    const custodian = {
      ...owner,
      pid: 9000,
      asid: 77,
      auid: 0,
      uid: 0,
      gid: 0,
      ruid: 0,
      rgid: 0,
      svuid: 0,
      svgid: 0,
    };
    const policyHash = createHash("sha256")
      .update(darwinFeasibilityPolicy("/fixture"))
      .digest("hex");
    const child = Object.assign(new EventEmitter(), {
      pid: 9000,
      stdin: new PassThrough(),
      stdout: new PassThrough(),
      stderr: new PassThrough(),
    });
    t.after(() => {
      for (const stream of [child.stdin, child.stdout, child.stderr])
        stream.destroy();
    });
    let record = {
      emergency: false,
      candidateSha: SHA,
      caseId,
      asid: 55,
      stage: 1,
      receiptSha256: DIGEST,
      intentSha256: "",
      helperSha256: DIGEST,
      policySha256: policyHash,
      custodian,
      owner: { ...owner, pidVersion: 6 },
      descendant: {},
      members: [],
    };
    const frames = [],
      actions = [];
    let closeReply;
    const replied = new Promise((resolve) => {
      closeReply = resolve;
    });
    const send = (value) => child.stdout.write(JSON.stringify(value) + "\n");
    const payload = (value) =>
      send({
        stream: "stdout",
        hex: Buffer.from(JSON.stringify(value) + "\n").toString("hex"),
      });
    child.stdin.on("data", (chunk) => {
      const [sequence, operation, ...args] = chunk.toString().trim().split(" ");
      actions.push(operation);
      let value = null;
      if (operation === "identity")
        value = Number(args[0]) === owner.pid ? owner : descendant;
      else if (operation === "image") value = { sha256: DIGEST };
      else if (operation === "policy") value = { sandboxed: true };
      else if (operation === "files") value = [{ sha256: policyHash }];
      else if (operation === "intent") {
        record = {
          ...record,
          stage: 2,
          owner,
          descendant,
          members: [owner, descendant],
          intentSha256: args[0],
        };
        value = record;
      } else if (operation === "fault") value = { status: "RETIRED" };
      else if (operation === "observe")
        value = { status: Number(args[5]) === owner.pid ? "RETIRED" : "LIVE" };
      else if (operation === "retire") {
        record = { ...record, stage: 5 };
        value = record;
      } else if (operation === "recover" || operation === "emergency") {
        record = { ...record, stage: 5 };
        if (trailing === "recovery-emergency") record.emergency = true;
        if (operation === "recover" && trailing === "recovery-birth")
          record = { ...record, owner: { ...record.owner, startSeconds: 101 } };
        value = record;
      } else if (operation === "close") {
        record = { ...record, stage: 6 };
        value = record;
      } else assert.equal(operation, "payload");
      send({ sequence: Number(sequence), value });
      if (operation === "payload") {
        frames.push(args[0]);
        payload(
          args[0] === "A"
            ? { event: "detached" }
            : { event: "fault-ack", caseId },
        );
      }
      if (operation === "close") {
        if (trailing && !recovering && trailing !== "unclosed")
          child.stdout.write(trailing === "partial" ? "{" : "malformed\n");
        child.stdout.end();
        child.stderr.end();
        if (trailing !== "unclosed") child.emit("close", 0, null);
        closeReply();
      }
    });
    let acquired;
    const opening = openDarwinFaultDomain(
      "/fixture",
      SHA,
      caseId,
      "c".repeat(32),
      DIGEST,
      policyHash,
      {},
      openDarwinFeasibilitySession,
      {
        uid: 501,
        gid: 20,
        retain: (value) => {
          acquired = value;
        },
        launch: (file, args) => {
          assert.equal(file, "/usr/bin/sudo");
          assert.ok(args.includes("fault-domain") && args.includes("-i"));
          queueMicrotask(() => {
            if (trailing === "startup") {
              child.stderr.write(
                "native-darwin: operation=fault-journal-write domain=errno value=9 effects=possible settlement=unsettled\n",
              );
              child.emit("close", 126, null);
              return;
            }
            if (trailing === "admission") {
              send({ ready: { ...record, candidateSha: "f".repeat(40) } });
              return;
            }
            send({ ready: record });
            if (recovering) {
              send({
                stream: "stderr",
                hex: Buffer.from(
                  "native-darwin: operation=fault-access-authority domain=invariant value=0 effects=possible settlement=unsettled\n",
                ).toString("hex"),
              });
              send({
                exit:
                  trailing === "preexec-signal"
                    ? { code: -1, signal: 5 }
                    : { code: 126, signal: 0 },
              });
              return;
            }
            send({
              stream: "stderr",
              hex: Buffer.from(
                "native-darwin-phase: phase=policy-enter\nnative-darwin-phase: phase=policy-applied\nnative-darwin-phase: phase=exec-enter\n",
              ).toString("hex"),
            });
            payload({
              event: "armed",
              ownerPid: owner.pid,
              childPid: descendant.pid,
              controls: true,
            });
          });
          return child;
        },
        execute: async (file, args) => {
          assert.equal(file, "/usr/bin/sudo");
          const closed = args.includes("fault-closed");
          if (closed && trailing === "recovery-close")
            throw new Error("Custodian remains unverified");
          actions.push(closed ? "verified-close" : "verified-empty");
          return {
            stdout: JSON.stringify({
              independent: true,
              complete: trailing !== "recovery-incomplete",
              held: !closed,
              record,
              verifier: { ...custodian, pid: closed ? 9200 : 9100 },
            }),
          };
        },
      },
    );
    if (trailing === "startup") {
      await assert.rejects(opening, (error) => {
        assert.equal(error.faultDomain, acquired);
        assert.equal(acquired.owner, child);
        assert.equal(child.stdin.writableEnded, true);
        assert.equal(error.exitCode, 126);
        assert.match(
          darwinFeasibilityCause(caseId, error).detail,
          /fault-journal-write failed.*errno=9/u,
        );
        assert.match(
          error.stderr.toString(),
          /effects=possible settlement=unsettled/u,
        );
        return true;
      });
      assert.deepEqual(frames, []);
      assert.deepEqual(actions, []);
      continue;
    }
    if (trailing === "admission") {
      await assert.rejects(opening, (error) => {
        assert.equal(error.faultDomain, acquired);
        assert.equal(acquired.owner, child);
        assert.equal(child.stdin.writableEnded, true);
        return true;
      });
      assert.deepEqual(actions, []);
      child.emit("close", 126, null);
      continue;
    }
    const domain = await opening;
    const saved = new Map();
    const work = runDarwinFeasibilityFault(
      "/fixture",
      domain.running,
      [{ role: "helper", name: "helper", sha256: DIGEST }],
      {},
      caseId,
      SHA,
      {
        domain,
        snapshot: async () => ({}),
        save: async (_root, name, value) =>
          saved.set(name, structuredClone(value)),
        read: async (file) =>
          JSON.stringify(saved.get(path.basename(file, ".json"))),
      },
    );
    if (trailing === "unclosed") {
      await replied;
      // Let the reply continuation install its closure deadline before advancing time.
      await new Promise((resolve) => setImmediate(resolve));
      assert.equal(domain.running.failure(), null);
      t.mock.timers.tick(12000);
      child.emit("close", 0, null);
    }
    const entry = await work;
    if (recovering) {
      assert.notEqual(entry.status, "PASS", trailing);
      assert.match(entry.cause.detail, /fault-access-authority/u);
      assert.deepEqual(frames, []);
      assert.ok(actions.includes("recover"));
      assert.ok(
        !actions.some((action) =>
          ["payload", "intent", "fault", "retire"].includes(action),
        ),
      );
      assert.equal(
        entry.cleanup.status,
        trailing.startsWith("preexec") ? "PASS" : "UNCERTAIN",
        trailing,
      );
      assert.equal(
        entry.cleanup.emergency,
        !trailing.startsWith("preexec"),
        trailing,
      );
      if (trailing.startsWith("preexec")) {
        assert.deepEqual(actions, [
          "recover",
          "verified-empty",
          "close",
          "verified-close",
        ]);
        assert.equal(
          saved.get(`${caseId}-custody`).domain.record.owner.pidVersion,
          6,
        );
      }
      continue;
    }
    if (trailing) {
      assert.notEqual(entry.status, "PASS", trailing);
      assert.equal(entry.cleanup.status, "UNCERTAIN", trailing);
      assert.equal(entry.cleanup.emergency, true, trailing);
      assert.ok(!actions.includes("verified-close"), trailing);
      if (trailing === "unclosed") {
        assert.equal(domain.running.failure().code, "ERR_FEASIBILITY_DEADLINE");
        assert.match(entry.cause.detail, /failure=deadline/u);
      }
      continue;
    }
    assert.equal(entry.status, "PASS", JSON.stringify(entry));
    assert.deepEqual(frames, ["A", caseId === "cancel" ? "C" : "L"]);
    assert.ok(actions.indexOf("intent") < actions.indexOf("payload"));
    assert.ok(actions.indexOf("fault") < actions.indexOf("retire"));
    assert.ok(actions.indexOf("verified-empty") < actions.indexOf("close"));
    assert.equal(actions.at(-1), "verified-close");
  }
});

test("Darwin fault admission refuses malformed locators and binding drift without release", async () => {
  for (const fault of [
    "locator-owner",
    "locator-child",
    "locator-bound",
    "locator-self",
    "locator-extra",
    "credentials",
    "birth-drift",
    "image-drift",
    "policy-drift",
    "policy-file",
    "intent-drift",
  ]) {
    const f = darwinFaultFixture(fault),
      entry = await f.run();
    assert.notEqual(entry.status, "PASS", fault);
    assert.ok(!f.events.includes("release:A"), fault);
    assert.equal(entry.evidence, null);
    assert.equal(f.running.child.stdin.writableEnded, true);
    if (f.running.faultCustody.child)
      assert.equal(
        f.running.faultCustody.child.pidVersion,
        f.descendant.pidVersion,
      );
    assert.equal(f.running.faultCustody.releasePossible, false);
    if (fault.startsWith("locator")) {
      assert.equal(entry.cleanup.independent, false);
      assert.ok(!f.events.includes("retire:42"));
    }
  }
});

test("Darwin fault partial acquisition, missing evidence and reaping failure retain separate uncertainty", async () => {
  for (const fault of [
    "owner-acquire",
    "child-acquire",
    "observer",
    "unproved",
    "unclosed",
    "reaping",
    "reaping-save",
    "ack",
    "observation",
    "snapshot",
    "save",
  ]) {
    const f = darwinFaultFixture(fault),
      entry = await f.run();
    assert.notEqual(entry.status, "PASS");
    assert.equal(entry.evidence, null);
    if (["snapshot", "save"].includes(fault))
      assert.equal(entry.cause.code, "observed-escape");
    else if (!["ack", "observation"].includes(fault))
      assert.match(entry.cause.detail, /task-name failed.*mach=5/u);
    if (
      [
        "owner-acquire",
        "child-acquire",
        "unproved",
        "unclosed",
        "observation",
      ].includes(fault)
    ) {
      assert.equal(entry.cleanup.independent, false);
      assert.equal(entry.cleanup.witnessSha256, null);
      assert.ok(!f.events.includes("retire:43"));
      assert.ok(!f.events.includes("retire:42"));
    }
    if (!["owner-acquire", "child-acquire"].includes(fault))
      assert.deepEqual(f.running.faultCustody.child, f.descendant);
    if (fault.startsWith("reaping") || ["snapshot", "save"].includes(fault)) {
      assert.equal(entry.cleanup.status, "UNCERTAIN");
      assert.equal(entry.cleanup.independent, false);
      assert.equal(entry.cleanup.witnessSha256, null);
      if (fault.startsWith("reaping"))
        assert.match(entry.cleanup.cause.detail, /fault-wait failed.*errno=5/u);
    }
    if (fault === "ack") {
      assert.ok(!f.events.includes("cancel:42"));
      assert.ok(
        f.events.indexOf("save:cancel") < f.events.indexOf("retire:43"),
      );
    }
    if (fault === "observation") assert.ok(f.events.includes("observe:42"));
  }
});

test("Darwin fault sessions close refused releases and retain valid fault acknowledgments", async (t) => {
  for (const fault of [
    "cancel",
    "owner-loss",
    "truncated",
    "eof",
    "partial",
    "utf8",
    "refusal",
    "stream-error",
  ]) {
    const child = Object.assign(new EventEmitter(), {
      pid: 42,
      stdin: new PassThrough(),
      stdout: new PassThrough(),
      stderr: new PassThrough(),
    });
    t.after(() => {
      for (const stream of [child.stdin, child.stdout, child.stderr])
        stream.destroy();
    });
    const running = openDarwinFeasibilitySession(
      "/fixture",
      "exec",
      ["/fixture/evidence/cancel.sb", "/fixture/build/helper", "fault"],
      { launch: () => child },
    );
    const send = (value) => child.stdout.write(JSON.stringify(value) + "\n");
    child.stderr.write(
      "native-darwin-phase: phase=policy-enter\nnative-darwin-phase: phase=policy-applied\nnative-darwin-phase: phase=exec-enter\n",
    );
    if (["truncated", "eof"].includes(fault)) {
      const absent = running.next();
      if (fault === "truncated") child.stdout.write('{"event":"armed"');
      child.stdout.end();
      child.stderr.end();
      await assert.rejects(absent);
    } else {
      send({ event: "armed", ownerPid: 42, childPid: 43 });
      await running.next();
      if (["cancel", "owner-loss"].includes(fault)) {
        child.stdin.on("data", (bytes) =>
          send(
            bytes.toString() === "A"
              ? { event: "detached" }
              : { event: "fault-ack", caseId: fault },
          ),
        );
        await running.authorize("A");
        assert.equal((await running.next()).event, "detached");
        await running.authorize(fault === "cancel" ? "C" : "L");
        assert.deepEqual(await running.next(), {
          event: "fault-ack",
          caseId: fault,
        });
        running.closeInput();
      } else {
        if (fault === "partial") child.stdout.write('{"event":');
        if (fault === "utf8") child.stdout.write(Buffer.from([0xe2]));
        if (fault === "refusal")
          child.stderr.write(
            "native-darwin: operation=fault-read domain=errno value=5 effects=possible settlement=unsettled\n" +
              "native-darwin-cleanup: operation=fault-wait domain=errno value=5 effects=possible settlement=unsettled\n",
          );
        if (fault === "stream-error")
          child.stdout.emit("error", new Error("Output transport failed"));
        await assert.rejects(running.authorize("A"));
        if (fault === "refusal")
          assert.equal(running.diagnostic(true).operation, "fault-wait");
      }
      child.stdout.end();
      child.stderr.end();
    }
    const accepted = ["cancel", "owner-loss"].includes(fault);
    assert.equal(running.authorizationStarted(), accepted);
    assert.equal(child.stdin.writableEnded, true);
    child.emit("close", null, "SIGKILL");
    if (accepted) await running.finish("SIGKILL");
    else await running.waitClosed();
  }
});

test("Darwin fault failure hook closes owned gates and checks only unreleased original-child reaping", async () => {
  const source = await readFile(
    new URL("../ci/native/darwin/feasibility-helper.c", import.meta.url),
    "utf8",
  );
  const fault = /static void fault\(void\) \{([\s\S]*?)\n\}/u.exec(source)[1];
  assert.doesNotMatch(fault, /inspect\(|emit_identity|kill\(/u);
  assert.match(
    /static void prerequisites\(void\) \{([\s\S]*?)\n\}/u.exec(source)[1],
    /inspect\(child, &value\)/u,
  );
  assert.ok(fault.indexOf("fault_child = child;") < fault.indexOf("ownerPid"));
  assert.ok(
    fault.indexOf("fault_release_possible = true;") <
      fault.indexOf('write(fault_gate[1], "A", 1)'),
  );
  assert.match(
    fault,
    /received == 1 && command == 'A', "fault-authorization"/u,
  );
  const gate = fault
    .slice(
      fault.indexOf("char byte;"),
      fault.indexOf("posix_check((int)setsid()"),
    )
    .replace(/\b(?:char|ssize_t|int)\b/gu, "let")
    .replace(/\(let\)/gu, "")
    .replace(/&byte\b/gu, "(value) => byte = value");
  for (const byte of [null, "N", "A"]) {
    const api = {
      fault_gate: [11, 12],
      errno: 0,
      EINTR: 4,
      detached: false,
      close: () => 0,
      posix_check: (value) => assert.ok(value >= 0),
      read: (_fd, output) => {
        if (byte !== null) output(byte);
        return byte === null ? 0 : 1;
      },
      _exit: (code) => {
        throw code;
      },
    };
    try {
      new Script(
        `function run() {${gate} detached = true;} run();`,
      ).runInNewContext(api);
    } catch (code) {
      assert.equal(code, 0);
    }
    assert.equal(api.detached, byte === "A");
  }
  const body = /static void settle_fault\(void\) \{([\s\S]*?)\n\}/u
    .exec(source)[1]
    .replace(
      "int *gates[] = {fault_gate, fault_ack};",
      "let gates = [fault_gate, fault_ack];",
    )
    .replace(/\b(?:unsigned|int|pid_t)\b/gu, "let")
    .replace(/&status\b/gu, "(value) => status = value");
  const failure =
    /static void failure\(int code\) \{\n([\s\S]*?)  fprintf/u.exec(source)[1];
  assert.ok(failure.includes("settle_fault();"));
  const release = fault
    .slice(
      fault.indexOf("fault_release_possible = true;"),
      fault.indexOf("do { received = read(fault_ack[0]"),
    )
    .replace(/\bssize_t\b/gu, "let")
    .replace(/\(int\)/gu, "");
  for (const mode of [
    "reaped",
    "eintr",
    "wait",
    "deadline",
    "status",
    "close",
    "released",
    "write-refused",
    "write-empty",
    "write-wait",
  ]) {
    const events = [],
      diagnostics = [];
    const api = {
      fault_gate: [11, 12],
      fault_ack: [13, 14],
      fault_child: 43,
      fault_release_possible: mode === "released",
      prerequisite_mode: false,
      errno: mode === "eintr" ? 4 : 5,
      EINTR: 4,
      WNOHANG: 1,
      settle_bundle: () => {},
      settle_domain: () => {},
      settle_prerequisite: () => {},
      write: (fd, byte, size) => {
        assert.deepEqual([fd, byte, size], [12, "A", 1]);
        return mode === "write-empty" ? 0 : -1;
      },
      posix_check: (value, operation) => assert.ok(value >= 0, operation),
      invariant: (value, operation) => assert.ok(value, operation),
      close: (fd) => {
        events.push("close:" + fd);
        return mode === "close" && fd === 11 ? -1 : 0;
      },
      waitpid: (pid, output) => {
        events.push("wait:" + pid);
        output(mode === "status" ? 1 : 0);
        return ["wait", "write-wait"].includes(mode) ||
          (mode === "eintr" && events.length === 5)
          ? -1
          : mode === "deadline"
            ? 0
            : pid;
      },
      WIFEXITED: () => true,
      WEXITSTATUS: (status) => status,
      usleep: () => {},
      remember_cleanup: (...diagnostic) => diagnostics.push(diagnostic),
    };
    if (mode.startsWith("write-")) {
      assert.throws(
        () => new Script(release).runInNewContext(api),
        /fault-write/u,
      );
      assert.equal(api.fault_release_possible, false);
    }
    new Script(`function settle_fault() {${body}} ${failure}`).runInNewContext(
      api,
    );
    assert.deepEqual(events.slice(0, 4), [
      "close:11",
      "close:12",
      "close:13",
      "close:14",
    ]);
    assert.equal(events.includes("wait:43"), mode !== "released");
    assert.equal(
      diagnostics.length > 0,
      ["wait", "deadline", "status", "close", "write-wait"].includes(mode),
    );
    if (!["released", "wait", "deadline", "write-wait"].includes(mode))
      assert.equal(api.fault_child, -1);
    if (["wait", "deadline", "write-wait"].includes(mode))
      assert.equal(diagnostics[0][0], "fault-wait");
  }
});

test("ordinary Windows null diagnostic publishes separately before native cases and excludes other routes", async () => {
  const context = { candidateSha: SHA, runId: "1", runAttempt: "1" };
  const observed = { checkoutSha: SHA };
  const dispatch = {
    platform: "win32",
    expectedSha: SHA,
    protectedAcceptance: false,
  };
  const order = [],
    published = [];
  const identity = (caseId, slot) => ({
    pid:
      10 *
        ([
          "shadow",
          "no-shadow-control",
          "no-shadow-mapped",
          "workspace-rooted",
        ].indexOf(caseId) +
          1) +
      slot,
    creationTime: String(slot),
    sessionId: 1,
    userSid: "S-1-5-21-1000",
  });
  const outcome = (caseId) => ({
    purpose: "diagnostic-only",
    caseId,
    fixture: {
      root: `/fixture/${caseId}`,
      profile:
        caseId === "workspace-rooted"
          ? "native.feasibility." + "4".repeat(32)
          : undefined,
      nonce: String(
        [
          "shadow",
          "no-shadow-control",
          "no-shadow-mapped",
          "workspace-rooted",
        ].indexOf(caseId) + 1,
      ).repeat(32),
    },
    start: {
      receipt: { owner: identity(caseId, 1), child: identity(caseId, 2) },
      gitStarted: { child: identity(caseId, 3) },
      ...(caseId === "workspace-rooted"
        ? {
            workspaceProof: {
              ready: true,
              trustedVerifier: identity(caseId, 5),
            },
          }
        : {}),
    },
    binding: {
      bound: caseId !== "shadow",
      mappedSetup:
        caseId === "no-shadow-mapped" || caseId === "workspace-rooted",
      setSucceeded: caseId !== "shadow",
      ...(caseId === "workspace-rooted"
        ? {
            workspaceReady: true,
            payloadAssignment: {
              setSucceeded: true,
              identity: identity(caseId, 2),
            },
            gitAssignment: {
              setSucceeded: true,
              identity: identity(caseId, 3),
            },
          }
        : {}),
      owner: identity(caseId, 4),
    },
    git: {
      ran: caseId === "no-shadow-mapped" || caseId === "workspace-rooted",
      exitCode: ["no-shadow-mapped", "workspace-rooted"].includes(caseId)
        ? 0
        : null,
      terminationExitCode: ["no-shadow-mapped", "workspace-rooted"].includes(
        caseId,
      )
        ? null
        : 127,
    },
    cleanup: {
      status: "SETTLED",
      profileRetired: caseId === "workspace-rooted",
    },
    reusable: true,
  });
  const options = {
    run: async (caseId) => {
      order.push(caseId);
      return outcome(caseId);
    },
    publish: async (artifact) => {
      order.push("published");
      published.push(structuredClone(artifact));
      for (const key of Object.keys(context))
        assert.equal(artifact[key], context[key]);
      assert.equal(Object.hasOwn(artifact, "results"), false);
    },
  };
  for (const change of [
    { platform: "linux" },
    { platform: "darwin" },
    { protectedAcceptance: true },
  ])
    assert.equal(
      await runWindowsNullDiagnostic(
        { ...dispatch, ...change },
        observed,
        context,
        options,
      ),
      null,
    );
  assert.deepEqual(order, []);
  const artifact = await runWindowsNullDiagnostic(
    dispatch,
    observed,
    context,
    options,
  );
  const failed = report("win32");
  failed.results = unavailableFeasibilityResults("win32", {
    code: "setup-failed",
    detail: "Original null-device open failure",
  });
  const assessed = assessFeasibilityReport(failed);
  assert.deepEqual(order, [
    "published",
    "shadow",
    "published",
    "published",
    "no-shadow-control",
    "published",
    "published",
    "no-shadow-mapped",
    "published",
    "published",
    "workspace-rooted",
    "published",
  ]);
  assert.equal(artifact.diagnostic.git.ran, false);
  assert.equal(artifact.control.git.terminationExitCode, 127);
  assert.equal(artifact.control.binding.setSucceeded, true);
  assert.notDeepEqual(artifact.diagnostic.fixture, artifact.control.fixture);
  assert.equal(artifact.mapped.git.exitCode, 0);
  assert.equal(published[3].mapped.cleanup.status, "NOT_RUN");
  assert.equal(published[4].mapped.cleanup.status, "UNCERTAIN");
  assert.equal(published[6].workspaceRooted.cleanup.status, "UNCERTAIN");
  assert.equal(artifact.workspaceRooted.git.ran, true);
  for (const probe of [
    artifact.diagnostic,
    artifact.control,
    artifact.mapped,
    artifact.workspaceRooted,
  ])
    for (const key of Object.keys(context))
      assert.equal(probe[key], context[key]);
  assert.equal(published[0].diagnostic.cleanup.status, "UNCERTAIN");
  assert.equal(published[1].control.cleanup.status, "NOT_RUN");
  assert.equal(published[2].control.cleanup.status, "UNCERTAIN");
  assert.deepEqual(published[1].diagnostic, published[3].diagnostic);
  const summary = renderFeasibilitySummary(
    assessed,
    { ...dispatch, ...context },
    {
      NATIVE_CANDIDATE_SHA: SHA,
      NATIVE_PLATFORM: "win32",
      GITHUB_RUN_ID: "1",
      GITHUB_RUN_ATTEMPT: "1",
    },
    renderWindowsNullDiagnostic(artifact, context),
  );
  const shadowAt = summary.indexOf("shadow (diagnostic only)"),
    controlAt = summary.indexOf("no-shadow-control (diagnostic only)"),
    mappedAt = summary.indexOf("no-shadow-mapped (diagnostic only)"),
    rootedAt = summary.indexOf("workspace-rooted (diagnostic only)");
  assert.ok(
    shadowAt >= 0 &&
      shadowAt < controlAt &&
      controlAt < mappedAt &&
      mappedAt < rootedAt &&
      rootedAt < summary.indexOf("| Capability |"),
  );
  assert.match(summary, /cancellation=127/u);
  assert.equal(assessed.status, "FAIL");
  assert.equal(
    assessed.report.results[0].cause.detail,
    "Original null-device open failure",
  );
  const original = { operation: "NtSetInformationProcess", value: 0xc000000d };
  for (const unsettled of [
    "shadow",
    "no-shadow-control",
    "no-shadow-mapped",
    "workspace-rooted",
  ]) {
    order.length = 0;
    options.run = async (caseId) => {
      order.push(caseId);
      return {
        ...outcome(caseId),
        ...(caseId === unsettled
          ? {
              failure: original,
              binding: {
                ...outcome(caseId).binding,
                bound: false,
                mappedSetup: false,
                setSucceeded: false,
              },
              git: { ran: false, exitCode: null, terminationExitCode: 127 },
            }
          : {}),
        cleanup: { status: caseId === unsettled ? "UNCERTAIN" : "SETTLED" },
      };
    };
    await assert.rejects(
      runWindowsNullDiagnostic(dispatch, observed, context, options),
    );
    assert.equal(order.at(-1), "published");
    assert.deepEqual(
      published.at(-1)[
        unsettled === "shadow"
          ? "diagnostic"
          : unsettled === "no-shadow-control"
            ? "control"
            : unsettled === "no-shadow-mapped"
              ? "mapped"
              : "workspaceRooted"
      ].failure,
      original,
    );
    if (unsettled === "shadow") {
      assert.equal(order.includes("no-shadow-control"), false);
      assert.equal(published.at(-1).control.cleanup.status, "NOT_RUN");
    }
    if (["shadow", "no-shadow-control"].includes(unsettled)) {
      assert.equal(order.includes("no-shadow-mapped"), false);
      assert.equal(published.at(-1).mapped.cleanup.status, "NOT_RUN");
    }
    if (unsettled !== "workspace-rooted") {
      assert.equal(order.includes("workspace-rooted"), false);
      assert.equal(published.at(-1).workspaceRooted.cleanup.status, "NOT_RUN");
    }
  }
  options.run = async (caseId) => ({
    ...outcome(caseId),
    fixture: outcome("shadow").fixture,
  });
  await assert.rejects(
    runWindowsNullDiagnostic(dispatch, observed, context, options),
  );
  options.run = async (caseId) => ({
    ...outcome(caseId),
    runAttempt: "foreign",
  });
  await assert.rejects(
    runWindowsNullDiagnostic(dispatch, observed, context, options),
  );
  assert.equal(published.at(-1).diagnostic.runAttempt, "foreign");
  for (const actor of ["git", "holder", "same-run"]) {
    options.run = async (caseId) => {
      const probe = outcome(caseId),
        previous = outcome("shadow").start.gitStarted.child;
      if (caseId === "no-shadow-mapped") {
        if (actor === "git") probe.start.gitStarted.child = previous;
        else
          probe.binding.owner =
            actor === "holder" ? previous : probe.start.gitStarted.child;
      }
      return probe;
    };
    await assert.rejects(
      runWindowsNullDiagnostic(dispatch, observed, context, options),
    );
  }
  for (const finding of ["target", "verifier", "profile", "readiness"]) {
    options.run = async (caseId) => {
      const probe = outcome(caseId);
      if (caseId === "workspace-rooted") {
        if (finding === "target")
          probe.binding.gitAssignment.identity = probe.start.receipt.child;
        if (finding === "verifier")
          probe.start.workspaceProof.trustedVerifier =
            outcome("shadow").start.gitStarted.child;
        if (finding === "profile")
          probe.fixture.profile = "native.feasibility." + "1".repeat(32);
        if (finding === "readiness") probe.start.workspaceProof.ready = false;
      }
      return probe;
    };
    await assert.rejects(
      runWindowsNullDiagnostic(dispatch, observed, context, options),
    );
  }
});

test("null control cancels successful SET while unknown selectors refuse before effects", async () => {
  const settled = {
    independent: true,
    jobEmpty: true,
    processRetired: true,
    resourcesClosed: true,
    endpointAbsent: true,
    holderRetired: true,
    outsideUnchanged: true,
  };
  for (const caseId of [undefined, "shadow", "no-shadow-control"]) {
    const probe = await observeWindowsGitNullProbe({
      caseId,
      start: async () => ({ owned: true }),
      bind: async () => ({ bound: true }),
      execute: async (release) => {
        assert.equal(release, caseId !== "no-shadow-control");
        return {
          ran: release,
          exitCode: release ? 0 : null,
          terminationExitCode: release ? null : 127,
        };
      },
      retire: async () => settled,
    });
    assert.equal(probe.caseId, caseId ?? "shadow");
    assert.equal(probe.binding.bound, true);
    assert.equal(probe.git.ran, caseId !== "no-shadow-control");
    assert.equal(
      probe.git.terminationExitCode,
      caseId === "no-shadow-control" ? 127 : null,
    );
    assert.equal(probe.reusable, true);
  }
  const refuse = async () => assert.fail("Unknown selector reached effects");
  await assert.rejects(
    observeWindowsGitNullProbe({
      caseId: "unknown",
      start: refuse,
      bind: refuse,
      execute: refuse,
      retire: refuse,
    }),
    Error,
  );
  await assert.rejects(
    runWindowsFeasibility(
      {},
      {},
      { nullDeviceProbe: true, nullDeviceProbeCase: "unknown" },
    ),
    Error,
  );
});

test("null diagnostic retains distinct exclusive helper and Git admission records", async () => {
  const records = new Map();
  const persist = async (name, value) => {
    const destination = `control/${name}.json`;
    if (records.has(destination))
      throw Object.assign(new Error("Existing admission record"), {
        code: "EEXIST",
      });
    records.set(destination, JSON.stringify(value));
    return destination;
  };
  const receipt = { owner: { pid: 41 }, child: { pid: 42 } };
  const helper = {
    receipt,
    admission: { admitted: true, verifier: { pid: 43 } },
  };
  const git = {
    receipt,
    gitStarted: { child: { pid: 44 } },
    admission: { admitted: true, verifier: { pid: 45 } },
  };
  const helperName = windowsFeasibilityAdmissionName("null-probe");
  const gitName = windowsFeasibilityAdmissionName("null-probe", true);
  const helperDestination = await persist(helperName, helper);
  const gitDestination = await persist(gitName, git);
  assert.notEqual(helperDestination, gitDestination);
  assert.equal(helperDestination, "control/null-probe-admission.json");
  assert.equal(gitDestination, "control/null-probe-git-admission.json");
  const expected = [
    [helperDestination, JSON.stringify(helper)],
    [gitDestination, JSON.stringify(git)],
  ];
  assert.deepEqual([...records], expected);
  for (const name of [helperName, gitName]) {
    await assert.rejects(persist(name, { replacement: true }), {
      code: "EEXIST",
    });
    assert.deepEqual([...records], expected);
  }
});

test("null diagnostic SET dispatch uses its handle-only ABI and shared request context", async () => {
  const source = await readFile(
    new URL("../ci/native/win32/feasibility-null-probe.h", import.meta.url),
    "utf8",
  );
  assert.match(
    source,
    /_Static_assert\(sizeof\(\(\(NULL_DEVICE_MAP \*\)0\)->Set\) == 8 &&\s+offsetof\(NULL_DEVICE_MAP, Set\.DirectoryHandle\) == 0, "x64 PROCESS_DEVICEMAP_INFORMATION SET"\);/u,
  );
  assert.equal((source.match(/\bsetMap\(/gu) ?? []).length, 2);
  assert.match(
    source,
    /HANDLE creationShadow = !wcscmp\(nullProbeCase, L"shadow"\) \? null_owned\.shadow : NULL;/u,
  );
  assert.match(
    source,
    /createDirectory\(&null_owned\.directory, 0x0f, &attributes, creationShadow, 0\)/u,
  );
  for (const event of ["null-directory-request", "null-set-request"]) {
    const line = source.split("\n").find((value) => value.includes(event));
    assert.match(line, /\\"caseId\\":\\"%ls\\".*\\"shadowPresent\\":%s/u);
    assert.match(line, /nullProbeCase, creationShadow \? "true" : "false"/u);
  }
  const helper = await readFile(
    new URL("../ci/native/win32/feasibility-helper.c", import.meta.url),
    "utf8",
  );
  const main = helper.slice(helper.indexOf("int wmain("));
  assert.match(main, /nullProbeCase = argv\[probe \? 6 : 13\]/u);
  assert.match(
    main,
    /nullProbeCase = argv\[11\]; invariant\(argc == \(!wcscmp\(nullProbeCase, L"workspace-rooted"\) \? 14 : 12\)/u,
  );
  const validated = main.indexOf('invariant(!wcscmp(nullProbeCase, L"shadow")');
  assert.ok(validated >= 0 && validated < main.indexOf("BOOL payload ="));
  const bundle = helper.slice(
    helper.indexOf("static void bundle("),
    helper.indexOf("static void fault("),
  );
  assert.match(
    bundle,
    /if \(!wcscmp\(nullProbeCase, L"no-shadow-control"\)\) action = 'N';/u,
  );
  assert.ok(
    bundle.indexOf("action = 'N'") <
      bundle.indexOf("ResumeThread(child.hThread)"),
  );
  const request = source.slice(
    source.indexOf("NULL_DEVICE_MAP map ="),
    source.indexOf("held:"),
  );
  assert.match(
    request,
    /const ULONG informationClass = 23, requestBytes = sizeof\(map\.Set\);/u,
  );
  const originalRequest = request.replace(
    /\s+if \(rooted && wcscmp\(workspaceRole, L"null-probe"\)\) \{[\s\S]*?\n  \}/u,
    "",
  );
  assert.match(
    originalRequest,
    /printf\([^\n]*null-set-request[^\n]*\\"informationClass\\":%lu,\\"requestBytes\\":%lu[^\n]*, informationClass, requestBytes\);\s+setSucceeded = null_status\("NtSetInformationProcess", setMap\(null_owned\.child, informationClass, &map\.Set, requestBytes\)\);\s+if \(rooted\) \{[^\n]+\}\s+if \(!setSucceeded\) goto held;\s+if \(mapped\) \{ if \(!null_link_drives\(createLink, queryLink\) \|\| !null_recheck\("release"\)\) goto held; mappedSetup = TRUE; \}\s+if \(rooted && !null_ready_links\(queryLink\)\) \{ mappedSetup = FALSE; goto held; \}\s+bound = setSucceeded && \(!mapped \|\| mappedSetup\);\s*$/u,
  );
  assert.match(
    source,
    /if \(!status\) return TRUE; null_error\(operation, "ntstatus", \(DWORD\)status\); return FALSE;/u,
  );
});

test("mapped release needs complete setup and actual SET success", async () => {
  const settled = {
    independent: true,
    jobEmpty: true,
    processRetired: true,
    resourcesClosed: true,
    endpointAbsent: true,
    holderRetired: true,
    outsideUnchanged: true,
  };
  for (const { bound = true, mappedSetup, setSucceeded, failure } of [
    { bound: false, mappedSetup: true, setSucceeded: true },
    {},
    { mappedSetup: false, setSucceeded: true },
    { mappedSetup: true },
    { mappedSetup: true, setSucceeded: false },
    ...[
      "NtCreateSymbolicLinkObject",
      "mapping-link-binding",
      "mapping-recheck",
    ].map((operation) => ({
      bound: false,
      mappedSetup: false,
      setSucceeded: true,
      failure: {
        event: "null-error",
        operation,
        value: operation === "NtCreateSymbolicLinkObject" ? 0xc000000d : 0,
      },
    })),
    { mappedSetup: true, setSucceeded: true },
  ]) {
    const release = bound && mappedSetup === true && setSucceeded === true;
    const probe = await observeWindowsGitNullProbe({
      caseId: "no-shadow-mapped",
      start: async () => ({}),
      bind: async (capture) => {
        if (failure) capture(failure);
        return { bound, mappedSetup, setSucceeded };
      },
      execute: async (allowed) => {
        assert.equal(allowed, release);
        return {
          ran: allowed,
          exitCode: allowed ? 0 : null,
          terminationExitCode: allowed ? null : 127,
        };
      },
      retire: async () => settled,
    });
    assert.equal(probe.git.ran, release);
    assert.equal(probe.git.terminationExitCode, release ? null : 127);
    assert.deepEqual(probe.failure, failure ?? null);
    assert.equal(probe.cleanup.status, "SETTLED");
  }
});

test("actual mapped owner predicates select the current entry, deduplicate letters and refuse aliases or bounds", async () => {
  const source = await readFile(
    new URL("../ci/native/win32/feasibility-null-probe.h", import.meta.url),
    "utf8",
  );
  const chars = (value) =>
    [...value].map((character) => character.charCodeAt(0));
  const predicate = (name, parameters) => {
    const start = source.indexOf(` ${name}(`),
      end = source.indexOf("\nstatic ", start);
    const owner = source.slice(start, end),
      body = owner
        .slice(owner.indexOf("{") + 1, owner.lastIndexOf("}"))
        .replace(/\b(?:DWORD|WCHAR)\b/gu, "let")
        .replace(/L"/gu, '"')
        .replace(/L'((?:\\.|[^'])*)'/gu, (_, literal) =>
          String(JSON.parse(`"${literal}"`).charCodeAt(0)),
        );
    return new Script(`(function(${parameters}) {${body}})`).runInNewContext({
      FALSE: false,
      wcslen: (value) => value.indexOf(0),
      wcsncmp: (value, prefix, count) =>
        String.fromCharCode(...value.slice(0, count)) === prefix.slice(0, count)
          ? 0
          : 1,
    });
  };
  const current = predicate("null_current", "bytes,count,capacity"),
    local = predicate("null_local_target", "target"),
    letter = predicate("null_drive_letter", "path"),
    count = predicate("null_drive_count", "first,second"),
    fits = predicate("null_path_fits", "target,suffix");
  const target = "\\Device\\HarddiskVolume4",
    raw = chars(`${target}\0\\Device\\HarddiskVolume9\0\0`);
  assert.equal(current(raw, raw.length, 512), target.length);
  const full = chars(`${target}\0${"h".repeat(512 - target.length - 3)}\0\0`);
  assert.equal(full.length, 512);
  assert.equal(current(full, full.length, 512), target.length);
  full[511] = 65;
  assert.equal(current(full, full.length, 512), 0);
  assert.equal(local([...raw]), true);
  for (const malformed of [
    "\0\0",
    `${target}\0`,
    `${target}\0\0junk\0\0`,
    `${target}\0history\0`,
  ]) {
    const bytes = chars(malformed);
    assert.equal(current(bytes, bytes.length, 512), 0);
  }
  for (const size of [0, 2, 512, 513]) assert.equal(current(raw, size, 512), 0);
  for (const [targetSize, suffix, expected] of [
    [22, 987, true],
    [22, 988, false],
    [1024, 0, false],
  ])
    assert.equal(fits(targetSize, suffix), expected);
  for (const alias of [
    "\\??\\C:",
    "\\Device\\Mup\\server",
    `${target}\\folder`,
    "\\Device\\HarddiskVolume",
  ])
    assert.equal(local(chars(`${alias}\0`)), false);
  assert.equal(
    count(letter(chars("c:\\fixture\0")), letter(chars("C:\\Windows\0"))),
    1,
  );
  assert.equal(
    count(letter(chars("D:\\fixture\0")), letter(chars("C:\\Windows\0"))),
    2,
  );
  for (const invalid of ["", "C:", "\\\\host\\share", "1:\\bad"])
    assert.equal(letter(chars(`${invalid}\0`)), 0);
  assert.equal((source.match(/QueryDosDeviceW\(/gu) ?? []).length, 2);
  assert.match(source, /QueryDosDeviceW\(label, bytes, 512\)/u);
  assert.match(source, /selected = null_current\(bytes, count, 512\)/u);
  assert.match(source, /!null_local_target\(bytes\)/u);
  assert.match(
    source,
    /!null_path_fits\(wcslen\(null_drives\[drive\]\.target\), wcslen\(paths\[i\] \+ 2\)\)/u,
  );
  assert.match(
    source,
    /null_driveCount = null_drive_count\(letters\[0\], letters\[1\]\)/u,
  );
  assert.match(
    source,
    /for \(unsigned i = 0; i < 2; i\+\+\) \{\s+unsigned drive/u,
  );
  assert.match(
    source,
    /null_same\(&null_paths\[i\]\.heldProof, &null_paths\[i\]\.reachedProof\)/u,
  );
  assert.ok(
    source.indexOf("if (mapped && !null_prepare_drives())") <
      source.indexOf("LONG status = createDirectory("),
  );
  assert.ok(
    source.indexOf('!null_recheck("release")') <
      source.indexOf("mappedSetup = TRUE"),
  );
});

test("mapped file-type failures retain the actual error without adopting a stale successful-call error", async () => {
  const source = await readFile(
    new URL("../ci/native/win32/feasibility-null-probe.h", import.meta.url),
    "utf8",
  );
  const snapshot = source.slice(
    source.indexOf("static BOOL null_snapshot("),
    source.indexOf("static BOOL null_same("),
  );
  const capture =
    /SetLastError\(0\); DWORD type = GetFileType\(handle\), typeError = ([^;]+);/u.exec(
      snapshot,
    );
  assert.ok(capture);
  for (const [type, nativeError, expected] of [
    [0, 6, 6],
    [0, 0, 0],
    [1, 6, 0],
  ])
    assert.equal(
      new Script(capture[1]).runInNewContext({
        type,
        FILE_TYPE_UNKNOWN: 0,
        GetLastError: () => nativeError,
      }),
      expected,
    );
  assert.match(
    snapshot,
    /if \(typeError\) \{ null_error\("mapping-file-type", "win32", typeError\); return FALSE; \}/u,
  );
  assert.ok(
    snapshot.indexOf("if (typeError)") < snapshot.indexOf("if (!proof->valid)"),
  );
});

test("partial mapped links remain owned until the actual retirement gate permits closure", async () => {
  const source = await readFile(
    new URL("../ci/native/win32/feasibility-null-probe.h", import.meta.url),
    "utf8",
  );
  const settle = source.slice(
    source.indexOf("static BOOL settle_null_map("),
    source.indexOf("static void null_map("),
  );
  const refusal =
    /if \((!retired)\) \{ null_cleanup_error\("null-retirement", "invariant", 0\); retainUnsettledMap = TRUE; return FALSE; \}/u.exec(
      settle,
    );
  assert.ok(refusal);
  assert.ok(
    settle.indexOf(refusal[0]) < settle.indexOf("release_handle(mapped[j]"),
  );
  assert.match(source, /createLink\(&null_drives\[i\]\.link/u);
  assert.match(
    settle,
    /&null_drives\[i\]\.link, &null_paths\[i\]\.reached, &null_paths\[i\]\.held, &null_drives\[i\]\.volume/u,
  );
  for (const [operation, retired] of [
    ["NtCreateSymbolicLinkObject", false],
    ["NtCreateSymbolicLinkObject", true],
    ["mapping-link-binding", false],
    ["mapping-link-binding", true],
    ["mapping-recheck", false],
    ["mapping-recheck", true],
  ]) {
    const owned = new Set([
        "root-volume",
        "SystemRoot-volume",
        "root-held",
        "root-reached",
        "SystemRoot-held",
        "SystemRoot-reached",
        "NUL-link",
        "first-drive-link",
        "directory",
        "endpoint",
      ]),
      original = {
        event: "null-error",
        operation,
        value: operation === "NtCreateSymbolicLinkObject" ? 0xc000000d : 0,
      };
    if (operation !== "NtCreateSymbolicLinkObject")
      owned.add("second-drive-link");
    const acquired = [...owned];
    const probe = await observeWindowsGitNullProbe({
      caseId: "no-shadow-mapped",
      start: async () => ({}),
      bind: async (capture) => {
        capture({
          event: "null-operation",
          operation: "NtSetInformationProcess",
          status: 0,
        });
        capture(original);
        throw new Error("Mapped setup refused after SET");
      },
      execute: async () => assert.fail("No release after mapped setup refusal"),
      retire: async () => {
        assert.deepEqual([...owned], acquired);
        if (new Script(refusal[1]).runInNewContext({ retired }))
          throw new Error("Retirement uncertain");
        owned.clear();
        return {
          independent: true,
          jobEmpty: true,
          processRetired: true,
          resourcesClosed: true,
          endpointAbsent: true,
          holderRetired: true,
          outsideUnchanged: true,
        };
      },
    });
    assert.deepEqual(probe.failure, original);
    assert.deepEqual(
      probe.events.map(({ operation }) => operation),
      ["NtSetInformationProcess", operation],
    );
    assert.deepEqual([...owned], retired ? [] : acquired);
    assert.equal(probe.reusable, retired);
  }
});

test("null diagnostic retains original binding refusal separately from uncertain retirement", async () => {
  const partial = windowsFeasibilityDiagnostics(
    "native-windows: operation=null-endpoint-state domain=invariant value=0\nnative-windows-cleanup: operation=null-retirement domain=invariant value=0\n",
  );
  assert.equal(partial.failure.operation, "null-endpoint-state");
  assert.equal(partial.cleanup.operation, "null-retirement");
  const request = {
    event: "null-set-request",
    informationClass: 23,
    requestBytes: 8,
  };
  const original = {
    event: "null-error",
    operation: "NtSetInformationProcess",
    domain: "ntstatus",
    value: 0xc0000004,
    messageUtf16: "0064",
  };
  const probe = await observeWindowsGitNullProbe({
    start: async () => ({ owned: true }),
    bind: async (capture) => {
      capture(request);
      capture(original);
      return { bound: false };
    },
    execute: async (bound) => {
      assert.equal(bound, false);
      return { ran: false, exitCode: null };
    },
    retire: async () => {
      throw new Error("Owned endpoint close refused");
    },
  });
  assert.deepEqual(probe.events, [request, original]);
  assert.deepEqual(probe.binding, { bound: false });
  assert.deepEqual(probe.failure, original);
  assert.equal(probe.git.ran, false);
  assert.equal(probe.cleanup.status, "UNCERTAIN");
  assert.equal(probe.cleanup.message, "Owned endpoint close refused");
  assert.equal(probe.reusable, false);
});

test("null diagnostic retires only its allocated subset and requires every independent settlement witness", async () => {
  const settled = {
    independent: true,
    jobEmpty: true,
    processRetired: true,
    resourcesClosed: true,
    endpointAbsent: true,
    holderRetired: true,
    outsideUnchanged: true,
  };
  const owned = new Set(),
    foreign = new Set(["sentinel"]);
  const effects = {
    start: async () => {
      owned.add("endpoint");
      throw new Error("Exclusive allocation refused");
    },
    bind: async () => assert.fail("No binding after allocation refusal"),
    execute: async () =>
      assert.fail("No Git execution after allocation refusal"),
    retire: async () => {
      owned.delete("endpoint");
      return settled;
    },
  };
  const refused = await observeWindowsGitNullProbe(effects);
  assert.equal(refused.failure.operation, "allocate");
  assert.equal(refused.git, null);
  assert.equal(owned.size, 0);
  assert.deepEqual([...foreign], ["sentinel"]);
  effects.start = async () => ({ owned: true });
  effects.bind = async () => ({ bound: true });
  effects.execute = async () => {
    throw new Error("Git release unobserved");
  };
  for (const field of Object.keys(settled)) {
    effects.retire = async () => ({ ...settled, [field]: false });
    const probe = await observeWindowsGitNullProbe(effects);
    assert.equal(probe.failure.operation, "git");
    assert.equal(probe.git, null);
    assert.equal(probe.cleanup.status, "UNCERTAIN", field);
    assert.equal(probe.reusable, false, field);
  }
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

function windowsSessionFixture(
  environment = windowsCallerEnvironment,
  diagnostics,
  probeCase,
  rootedLaunch = false,
  { launchCase = "null-probe", onSend, writeFailure } = {},
) {
  const sent = [];
  const child = Object.assign(new EventEmitter(), {
    pid: 42,
    stdin: new Writable({
      write: (bytes, _, done) => {
        const value = bytes.toString();
        sent.push(value);
        onSend?.(value, child);
        done(writeFailure?.(value));
      },
    }),
    stdout: new PassThrough(),
    stderr: new PassThrough(),
  });
  let capturedOptions;
  const argumentsList = probeCase
    ? [probeCase]
    : rootedLaunch
      ? [
          launchCase,
          "image",
          launchCase === "null-probe" ? "null-probe" : "bundle",
          "root",
          "nonce",
          "0",
          "unused",
          launchCase === "null-probe" ? "workspace-rooted" : launchCase,
          "identity",
          "native-path",
        ]
      : WINDOWS_LITERAL_ARGUMENTS;
  const session = windowsFeasibilityHelperSession(
    "C:\\fixture\\helper.exe",
    "C:\\fixture",
    "a".repeat(32),
    environment,
    probeCase ? "null-map" : "launch",
    argumentsList,
    {
      diagnostics,
      spawnProcess: (image, args, options) => {
        capturedOptions = options;
        assert.equal(image, "C:\\fixture\\helper.exe");
        assert.deepEqual(
          args.slice(3),
          argumentsList.map(quoteWindowsArgument),
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
    sent,
    options: capturedOptions,
    close: (code = 126, signal = null) => {
      child.stdout.end();
      child.stderr.end();
      child.emit("close", code, signal);
    },
  };
}
const windowsDiagnostic = (operation, domain, value) =>
  `native-windows: operation=${operation} domain=${domain} value=${value}\n`;

test("TCP source shares one finite deadline and closes before returning any connection receipt", async () => {
  const source = await readFile(
    new URL("../ci/native/win32/feasibility-helper.c", import.meta.url),
    "utf8",
  );
  const tcp = source.slice(
    source.indexOf("static int tcp_wait("),
    source.indexOf("static int connection("),
  );
  assert.equal(tcp.match(/GetTickCount64\(\) \+ 5000/gu).length, 1);
  assert.match(tcp, /remaining = end - now/u);
  assert.ok(
    tcp.indexOf('tcp_observe("select", "enter"') <
      tcp.indexOf("remaining = end - now"),
  );
  assert.match(
    tcp,
    /TIMEVAL wait = \{\(long\)\(remaining \/ 1000\), \(long\)\(\(remaining % 1000\) \* 1000\)\}/u,
  );
  assert.match(
    tcp,
    /select\(0, writing \? NULL : &ready, writing \? &ready : NULL, &exceptional, &wait\)/u,
  );
  assert.equal(tcp.match(/\bconnect\(/gu).length, 1);
  assert.equal(tcp.match(/\bbind\(/gu).length, 1);
  assert.equal(tcp.match(/\bWSASocketW\(/gu).length, 1);
  assert.ok(
    tcp.indexOf("ioctlsocket(socket, FIONBIO, &mode)") <
      tcp.indexOf("bind(socket,"),
  );
  assert.ok(tcp.indexOf("bind(socket,") < tcp.indexOf("connect(socket,"));
  assert.ok(
    tcp.indexOf("setsockopt(socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE") <
      tcp.indexOf("bind(socket,"),
  );
  assert.match(
    tcp,
    /local\.sin_family = AF_INET; local\.sin_port = htons\(0\); local\.sin_addr\.s_addr = htonl\(INADDR_LOOPBACK\)/u,
  );
  assert.ok(
    tcp.indexOf("GetTickCount64() + 5000") < tcp.indexOf("bind(socket,"),
  );
  assert.match(tcp, /error != WSAEWOULDBLOCK/u);
  assert.ok(
    tcp.indexOf("tcp_wait(socket, TRUE, end, &problem, &selected)") <
      tcp.indexOf("getsockopt(socket, SOL_SOCKET, SO_ERROR"),
  );
  assert.ok(tcp.indexOf("if (completed)") < tcp.indexOf("if (ready != 1)"));
  assert.match(
    tcp,
    /if \(completed\) \{[^\n]*nativeReceipt = GetTickCount64\(\) < end; goto done;/u,
  );
  assert.match(tcp, /size != sizeof\(completed\)/u);
  assert.match(
    tcp,
    /recv\(socket, reply \+ at, 32 - at, 0\) : send\(socket, text \+ at, 32 - at, 0\)/u,
  );
  assert.match(
    tcp,
    /used == SOCKET_ERROR\) \{\s*int error = WSAGetLastError\(\); if \(error == WSAEWOULDBLOCK\) continue/u,
  );
  assert.match(tcp, /used <= 0 \|\| used > 32 - at/u);
  assert.match(tcp, /receive && !used \? "tcp-eof" : "tcp-progress"/u);
  assert.match(tcp, /at \+= used/u);
  assert.match(tcp, /memcmp\(reply, text, 32\)/u);
  assert.doesNotMatch(tcp, /SO_RCVTIMEO|SO_SNDTIMEO|Sleep\(/u);
  const close = tcp.slice(tcp.indexOf("done:"));
  assert.ok(
    close.indexOf("remember(problem.operation") <
      close.indexOf("closesocket(socket)"),
  );
  assert.match(close, /closed \? 0 : WSAGetLastError\(\)/u);
  assert.match(
    close,
    /if \(problem.operation\) remember\(problem.operation, problem.domain, problem.value\);\s*remember\("tcp-close"/u,
  );
  assert.ok(
    close.indexOf('cleanup_error("tcp-close"') < close.indexOf("failure(126)"),
  );
  assert.ok(
    close.indexOf("failure(126)") < close.indexOf("return nativeReceipt"),
  );
  const driver = await readFile(
    new URL("../ci/native/win32/feasibility.js", import.meta.url),
    "utf8",
  );
  assert.match(driver, /\}, 15000\)/u);
  assert.match(driver, /operation === "tcp" \? 10013 : 5/u);
});

test("TCP setup and observer failures retain native causes and close each acquired socket", async () => {
  const source = await readFile(
    new URL("../ci/native/win32/feasibility-helper.c", import.meta.url),
    "utf8",
  );
  const tcp = source.slice(
    source.indexOf("static int tcp_connection("),
    source.indexOf("static int connection("),
  );
  const translate = (text) =>
    text
      .replace(
        /\(struct diagnosis\)\{"([a-z-]+)", "(win32|invariant)", ([^}]+)\}/gu,
        '{operation:"$1",domain:"$2",value:$3}',
      )
      .replace(/\(struct sockaddr \*\)&(local|endpoint)/gu, "$1")
      .replace(/\((?:DWORD|int)\)/gu, "")
      .replace(/sizeof\(local\)/gu, "16")
      .replace(
        /struct diagnosis acknowledgment = \{0\};/u,
        "let acknowledgment = {};",
      )
      .replace(
        /&(socket|problem|transferred|acknowledgment|selected|completed|size)/gu,
        "$1",
      )
      .replace(/\b(?:int|BOOL|unsigned)\b/gu, "let")
      .replace(/goto done;/gu, "return false;");
  const setup = translate(
    tcp
      .slice(
        tcp.indexOf("struct sockaddr_in local = {0};"),
        tcp.indexOf('tcp_observe("connect", "enter", 0);'),
      )
      .replace(
        "struct sockaddr_in local = {0};",
        "const local = {sin_addr:{}};",
      ),
  );
  const cleanup = translate(
    tcp.slice(tcp.indexOf("done:") + 5, tcp.lastIndexOf("}")),
  )
    .replace(/fprintf\(stderr, TCP_PREFIX " end\\n"\); fflush\(stderr\);/u, "")
    .replace(/#(?:ifndef NATIVE_COMMAND_EXPERIMENT|endif)/gu, "");
  const connection = translate(
    tcp.slice(
      tcp.indexOf('tcp_observe("connect", "enter", 0);'),
      tcp.indexOf("done:"),
    ),
  )
    .replace(
      /\(struct diagnosis\)\{([^,]+), "(win32|invariant)", ([^}]+)\}/gu,
      '{operation:$1,domain:"$2",value:$3}',
    )
    .replace("sizeof(endpoint)", "16")
    .replace(
      "let completed = 0, size = sizeof(completed);",
      "const completed = {value:0}, size = {value:4};",
    )
    .replace("(char *)completed", "completed")
    .replace("size != sizeof(completed)", "size.value != 4")
    .replaceAll("if (completed)", "if (completed.value)")
    .replace("value:completed}", "value:completed.value}")
    .replace("char reply[32];", "const reply = new Uint8Array(32);")
    .replaceAll("reply + at", "reply.subarray(at)")
    .replaceAll("text + at", "text.subarray(at)");
  const exercise =
    new Script(`function prepare() {${setup} return true;} function connect_once() {${connection}}
    function close() {${cleanup}}
    if (prepare()) connect_once(); result = close();`);
  for (const {
    bindError = 0,
    now = 4999,
    closeError = 0,
    transferError = 0,
    expireAfterTransfer = false,
    acknowledged = true,
    connectError = 0,
    completedError = 0,
    completionError = 0,
  } of [
    {},
    { connectError: 10013 },
    { connectError: 10035 },
    { connectError: 10035, completedError: 10013 },
    { connectError: 10035, completionError: 10038 },
    { bindError: 10013 },
    { bindError: 10022 },
    { bindError: 10013, closeError: 10038 },
    { now: 5000 },
    { transferError: 10013 },
    { transferError: 10022 },
    { transferError: 10022, closeError: 10038 },
    { expireAfterTransfer: true },
    { acknowledged: false },
    { acknowledged: false, connectError: 10013 },
  ]) {
    const events = [],
      failures = [],
      secondary = [],
      sent = [];
    let actualError = bindError,
      received = 0;
    const api = {
      socket: 17,
      started: 1,
      end: 5000,
      endpoint: {
        sin_family: 2,
        sin_addr: { s_addr: 0x7f000001 },
        sin_port: 32100,
      },
      text: new Uint8Array(Buffer.from("0123456789abcdef".repeat(2))),
      attempted: false,
      transferred: false,
      selected: false,
      problem: {},
      nativeReceipt: false,
      AF_INET: 2,
      INADDR_LOOPBACK: 0x7f000001,
      SOCKET_ERROR: -1,
      INVALID_SOCKET: -1,
      FALSE: false,
      TRUE: true,
      WSAEWOULDBLOCK: 10035,
      SOL_SOCKET: 0xffff,
      SO_ERROR: 0x1007,
      Uint8Array,
      htonl: (value) => value,
      htons: (value) => value,
      GetTickCount64: () =>
        expireAfterTransfer && api.transferred ? 5000 : now,
      WSAGetLastError: () => actualError,
      wfp_now: () => 1100,
      tcp_observe: (name, phase) => {
        events.push(`${name}:${phase}`);
        actualError = 10057;
      },
      bind: (socket, local, size) => {
        assert.equal(socket, 17);
        assert.equal(size, 16);
        assert.equal(local.sin_family, 2);
        assert.equal(local.sin_port, 0);
        assert.equal(local.sin_addr.s_addr, 0x7f000001);
        actualError = bindError;
        return bindError ? -1 : 0;
      },
      connect: (socket, endpoint, size) => {
        assert.equal(socket, 17);
        assert.equal(endpoint, api.endpoint);
        assert.equal(size, 16);
        events.push("connect");
        actualError = connectError;
        return connectError ? -1 : 0;
      },
      tcp_wait: () => 1,
      getsockopt(socket, level, option, completed, size) {
        assert.deepEqual(
          [socket, level, option, size.value],
          [17, 0xffff, 0x1007, 4],
        );
        completed.value = completedError;
        actualError = completionError;
        return completionError ? -1 : 0;
      },
      send(socket, text, size) {
        assert.equal(socket, 17);
        assert.ok(size > 0 && size <= 32);
        const used = Math.min(7, size);
        sent.push(...text.subarray(0, used));
        return used;
      },
      recv(socket, reply, size) {
        assert.equal(socket, 17);
        const used = Math.min(9, size);
        reply.set(api.text.subarray(received, received + used));
        received += used;
        return used;
      },
      memcmp: (reply, text) => Buffer.compare(reply, text),
      wfp_transfer: () => {
        events.push("observer-transfer");
        if (transferError) {
          api.problem = {
            operation: "observer-transfer",
            domain: "win32",
            value: transferError,
          };
          return false;
        }
        api.transferred = true;
        return true;
      },
      tcp_ack: (expected, deadline, problem) => {
        assert.equal(expected, "U");
        assert.equal(deadline, 15000);
        events.push("observer-ack");
        if (!acknowledged)
          Object.assign(problem, {
            operation: "ack-read",
            domain: "win32",
            value: 109,
          });
        return acknowledged;
      },
      wfp_tuple: (socket, _started, attempted) => {
        assert.equal(socket, 17);
        events.push(`tuple:${attempted}`);
        actualError = 10057;
      },
      closesocket: (socket) => {
        assert.equal(socket, 17);
        events.push("close");
        actualError = closeError;
        return closeError ? -1 : 0;
      },
      remember: (...fields) => {
        if (!failures.length) failures.push(fields);
      },
      cleanup_error: (...fields) => secondary.push(fields),
      failure: (code) => {
        events.push(`failure:${code}`);
        throw new Error("Native refusal");
      },
    };
    const unattempted =
      bindError || now >= 5000 || transferError || expireAfterTransfer;
    if (unattempted || !acknowledged || completionError)
      assert.throws(() => exercise.runInNewContext(api), /Native refusal/u);
    else {
      exercise.runInNewContext(api);
      assert.equal(
        api.result,
        completedError || (connectError === 10013 ? 10013 : 0),
      );
      if (!api.result) {
        assert.deepEqual(sent, [...api.text]);
        assert.equal(received, 32);
      }
    }
    assert.equal(
      events.filter((event) => event === "connect").length,
      unattempted ? 0 : 1,
    );
    assert.equal(events.filter((event) => event === "close").length, 1);
    assert.ok(
      events.indexOf(`tuple:${api.attempted}`) < events.indexOf("close"),
    );
    if (bindError)
      assert.deepEqual(failures[0], ["tcp-bind", "win32", bindError]);
    else if (now >= 5000 || expireAfterTransfer)
      assert.deepEqual(failures[0], ["tcp-deadline", "invariant", 0]);
    else if (transferError)
      assert.deepEqual(failures[0], [
        "observer-transfer",
        "win32",
        transferError,
      ]);
    else if (completionError)
      assert.deepEqual(failures[0], [
        "tcp-completion",
        "win32",
        completionError,
      ]);
    else if (!acknowledged && connectError)
      assert.deepEqual(failures[0], ["tcp-connect", "win32", connectError]);
    else if (!acknowledged)
      assert.deepEqual(failures[0], ["ack-read", "win32", 109]);
    assert.equal(events.includes("observer-ack"), api.transferred);
    if (api.transferred)
      assert.ok(events.indexOf("observer-ack") < events.indexOf("close"));
    if (closeError)
      assert.deepEqual(secondary[0], ["tcp-close", "win32", closeError]);
    if (failures.length)
      assert.ok(events.indexOf("close") < events.indexOf("failure:126"));
  }
});

test("socket source authority is confined to the held child and independently read back", async () => {
  const source = await readFile(
    new URL("../ci/native/win32/feasibility-helper.c", import.meta.url),
    "utf8",
  );
  const body = (name) =>
    new RegExp(
      `static (?:void|BOOL) ${name}\\([^\\n]+\\) \\{([\\s\\S]*?)\\n\\}`,
      "u",
    ).exec(source)[1];
  const native = (text) =>
    text
      .replaceAll('L"', '"')
      .replace(/&(?=[a-zA-Z_])/gu, "")
      .replaceAll("->", ".")
      .replaceAll("(DWORD)", "")
      .replace(/\b(?:BOOL|DWORD)\b/gu, "let");
  const readback = native(body("socket_source_acl"))
    .replace(
      "PSID owner = NULL; PACL dacl = NULL; PSECURITY_DESCRIPTOR sd = NULL;",
      "const owner = {}, dacl = {}, sd = {};",
    )
    .replace(
      "SECURITY_DESCRIPTOR_CONTROL flags = 0; let revision = 0;",
      "const flags = {}, revision = {};",
    )
    .replace("ACCESS_ALLOWED_ACE *ace = NULL;", "const ace = {};")
    .replaceAll("(void **)ace", "ace")
    .replaceAll("owner &&", "owner.value &&")
    .replaceAll("IsValidSid(owner)", "IsValidSid(owner.value)")
    .replaceAll("EqualSid(owner,", "EqualSid(owner.value,")
    .replaceAll("dacl &&", "dacl.value &&")
    .replaceAll("IsValidAcl(dacl)", "IsValidAcl(dacl.value)")
    .replaceAll("dacl.AceCount", "dacl.value.AceCount")
    .replaceAll("GetAce(dacl,", "GetAce(dacl.value,")
    .replaceAll("ace.", "ace.value.")
    .replaceAll("(flags &", "(flags.value &")
    .replaceAll(
      "GetSecurityDescriptorControl(sd,",
      "GetSecurityDescriptorControl(sd.value,",
    )
    .replace("if (sd) LocalFree(sd)", "if (sd.value) LocalFree(sd.value)");
  const grant = native(body("socket_source_grant"))
    .replace("WCHAR sddl[1024];", "const sddl = [];")
    .replace("PSECURITY_DESCRIPTOR sd = NULL;", "const sd = {};")
    .replace(
      "PACL dacl = NULL; let present = FALSE, defaulted = FALSE;",
      "const dacl = {}, present = {}, defaulted = {};",
    )
    .replace(
      "GetSecurityDescriptorDacl(sd,",
      "GetSecurityDescriptorDacl(sd.value,",
    )
    .replace(
      "present && !defaulted && dacl",
      "present.value && !defaulted.value && dacl.value",
    )
    .replace("NULL, NULL, dacl, NULL", "NULL, NULL, dacl.value, NULL")
    .replace("LocalFree(sd)", "LocalFree(sd.value)");
  const ready = native(body("socket_source_ready"))
    .replace("HANDLE process", "const process")
    .replace(
      /\(struct diagnosis\)\{"([a-z-]+)", "win32", ([^}]+)\}/gu,
      '{operation:"$1",domain:"win32",value:$2}',
    )
    .replace(/\*problem = ([^;]+);/gu, "Object.assign(problem, $1);");
  const script = new Script(`
    function socket_source_ready(problem) {${ready}}
    function socket_source_acl(process) {${readback}}
    function socket_source_grant(process) {${grant}}
    ({grant:socket_source_grant, read:socket_source_acl, ready:socket_source_ready});
  `);
  for (const fault of [
    null,
    "set",
    "descriptor",
    "missing-dacl",
    "read",
    "control",
    "entry",
    "owner",
    "sid",
    "mask",
    "inherited",
    "type",
    "unprotected",
    "extra",
  ]) {
    const original = {
      owner: "user",
      flags: 0x1000,
      entries: [
        {
          Header: { AceType: 0, AceFlags: 0 },
          Mask: 0x1fffff,
          SidStart: "user",
        },
      ],
    };
    let current = structuredClone(original),
      applied = false;
    const freed = [],
      operations = [],
      opened = [],
      closed = [];
    const context = {
      TRUE: true,
      FALSE: false,
      NULL: null,
      SE_KERNEL_OBJECT: 6,
      OWNER_SECURITY_INFORMATION: 1,
      DACL_SECURITY_INFORMATION: 4,
      PROTECTED_DACL_SECURITY_INFORMATION: 0x80000000,
      SE_DACL_PROTECTED: 0x1000,
      SDDL_REVISION_1: 1,
      ERROR_INVALID_DATA: 13,
      PROCESS_DUP_HANDLE: 0x40,
      GENERIC_ALL: 0x10000000,
      PROCESS_ALL_ACCESS: 0x1fffff,
      ACCESS_ALLOWED_ACE_TYPE: 0,
      userText: "user",
      appText: "package",
      userSid: "user",
      appSid: "package",
      acl(process, type, privateAcl) {
        assert.deepEqual([process, type, privateAcl], [73, 6, true]);
        assert.deepEqual(current, original);
        operations.push("private");
      },
      swprintf_s(out, bound, format, owner, user, mask, app) {
        assert.equal(bound, 1024);
        assert.equal(format, "O:%lsD:P(A;;GA;;;%ls)(A;;0x%08lx;;;%ls)");
        assert.deepEqual(
          [owner, user, mask, app],
          ["user", "user", 0x40, "package"],
        );
        out.push("descriptor");
        return 1;
      },
      ConvertStringSecurityDescriptorToSecurityDescriptorW(
        text,
        revision,
        out,
      ) {
        assert.deepEqual(Array.from(text), ["descriptor"]);
        assert.equal(revision, 1);
        out.value = "new-descriptor";
        return true;
      },
      GetSecurityDescriptorDacl(sd, present, dacl, defaulted) {
        assert.equal(sd, "new-descriptor");
        present.value = fault !== "missing-dacl";
        defaulted.value = false;
        dacl.value = "source-acl";
        return fault !== "descriptor";
      },
      SetSecurityInfo(process, type, flags, owner, group, dacl, sacl) {
        assert.deepEqual(
          [process, type, flags >>> 0, owner, group, dacl, sacl],
          [73, 6, 0x80000004, null, null, "source-acl", null],
        );
        operations.push("set");
        if (fault === "set") return 5;
        applied = true;
        current.entries.push({
          Header: { AceType: 0, AceFlags: 0 },
          Mask: 0x40,
          SidStart: "package",
        });
        return 0;
      },
      GetSecurityInfo(process, type, flags, owner, group, dacl, sacl, sd) {
        assert.deepEqual(
          [process, type, flags, group, sacl],
          [73, 6, 5, null, null],
        );
        operations.push("read");
        if (fault === "read") return 5;
        const observed = structuredClone(current);
        if (fault === "owner") observed.owner = "other";
        if (fault === "sid") observed.entries[1].SidStart = "other";
        if (fault === "mask") observed.entries[1].Mask |= 0x20;
        if (fault === "inherited") observed.entries[1].Header.AceFlags = 0x10;
        if (fault === "type") observed.entries[1].Header.AceType = 1;
        if (fault === "unprotected") observed.flags = 0;
        if (fault === "extra") observed.entries.push(observed.entries[1]);
        owner.value = observed.owner;
        dacl.value = {
          AceCount: observed.entries.length,
          entries: observed.entries,
        };
        sd.value = observed;
        return 0;
      },
      GetSecurityDescriptorControl(sd, flags) {
        flags.value = sd.flags;
        return fault !== "control";
      },
      GetAce(dacl, index, ace) {
        ace.value = dacl.entries[index];
        return fault !== "entry";
      },
      IsValidSid: (sid) => typeof sid === "string",
      EqualSid: (a, b) => a === b,
      IsValidAcl: (dacl) => Array.isArray(dacl.entries),
      LocalFree: (sd) => freed.push(sd),
      GetCurrentProcessId: () => 43,
      OpenProcess(access, inherit, pid) {
        assert.deepEqual([access, inherit, pid], [0x40, false, 43]);
        opened.push(pid);
        return current.entries.some(
          (ace) => ace.SidStart === "package" && (ace.Mask & access) === access,
        )
          ? 74
          : null;
      },
      CloseHandle(handle) {
        closed.push(handle);
        return true;
      },
      cleanup_error: () =>
        assert.fail("No preflight closure failure injected here"),
      GetLastError: () => 5,
      status_check(status, operation) {
        if (status) throw new Error(operation);
      },
      win32_check(ok, operation) {
        if (!ok) throw new Error(operation);
      },
      invariant(ok, operation) {
        if (!ok) throw new Error(operation);
      },
    };
    const actual = script.runInNewContext(context);
    if (fault) assert.throws(() => actual.grant(73), /socket-source/u, fault);
    else {
      const problem = {};
      assert.equal(
        actual.ready(problem),
        false,
        "the original protected user-only DACL denies the source's restricted token",
      );
      assert.deepEqual(problem, {
        operation: "observer-source-open",
        domain: "win32",
        value: 5,
      });
      actual.grant(73);
      actual.read(73); // Independent held-handle observation uses the same exact predicate.
      assert.deepEqual(current.entries[1], {
        Header: { AceType: 0, AceFlags: 0 },
        Mask: 0x40,
        SidStart: "package",
      });
      assert.deepEqual(operations, ["private", "set", "read", "read"]);
      assert.equal(actual.ready({}), true);
      assert.deepEqual(opened, [43, 43]);
      assert.deepEqual(closed, [74]);
    }
    assert.equal(
      applied,
      !["descriptor", "missing-dacl", "set"].includes(fault),
      fault,
    );
    assert.equal(freed[0], "new-descriptor", fault);
    if (applied && fault !== "read")
      assert.equal(typeof freed[1], "object", fault);
  }
  const launch = source.slice(
    source.indexOf("static void launch("),
    source.indexOf("static void observe("),
  );
  const grantCall =
    /if \(workspaceRole &&[^\n]+socket_source_grant\(child.hProcess\);/u.exec(
      launch,
    )[0];
  assert.ok(launch.indexOf(grantCall) > launch.indexOf('"launch-image-equal"'));
  assert.ok(launch.indexOf(grantCall) < launch.indexOf("CreateThread("));
  const inspect = source.slice(
    source.indexOf("  if (suspended) {"),
    source.indexOf("    WCHAR expected[4096], actual[4096], native[4096]"),
  );
  const inspectCall = inspect
    .slice(inspect.indexOf("    if (!git"))
    .replaceAll("#endif", "");
  for (const mode of ["read", "edit", "null-probe", "argv", "cancel", null]) {
    const granted = [],
      verified = [];
    const context = {
      workspaceRole: mode,
      child: { hProcess: 73 },
      args: [0, 0, 0, 0, 0, 0, mode],
      git: false,
      TRUE: true,
      SE_KERNEL_OBJECT: 6,
      wcscmp: (a, b) => (a === b ? 0 : 1),
      socket_source_grant: (process) => granted.push(process),
      socket_source_acl: (process) => verified.push([process, "source"]),
      acl: (process, type, privateAcl) =>
        verified.push([process, type, privateAcl]),
    };
    new Script(native(grantCall)).runInNewContext(context);
    new Script(native(inspectCall)).runInNewContext({ ...context, child: 73 });
    assert.deepEqual(granted, ["read", "edit"].includes(mode) ? [73] : []);
    assert.deepEqual(verified, [
      [73, ...(["read", "edit"].includes(mode) ? ["source"] : [6, true])],
    ]);
    verified.length = 0;
    new Script(native(inspectCall)).runInNewContext({
      ...context,
      child: 73,
      git: true,
    });
    assert.deepEqual(
      verified,
      [[73, 6, true]],
      "Git child keeps its private DACL",
    );
  }
});

test("socket creation and observer admission bind the actual child primary token", async () => {
  const source = await readFile(
    new URL("../ci/native/win32/feasibility-helper.c", import.meta.url),
    "utf8",
  );
  const body = (name) =>
    new RegExp(
      `static (?:BOOL|void|DWORD) ${name}\\([^\\n]+\\) \\{([\\s\\S]*?)\\n\\}`,
      "u",
    ).exec(source)[1];
  const native = (text) =>
    text
      .replaceAll("->", ".")
      .replaceAll("sizeof(DWORD)", "4")
      .replaceAll("sizeof(LUID)", "8")
      .replaceAll("sizeof(*statistics)", "56")
      .replaceAll("sizeof(active)", "4")
      .replaceAll("sizeof(*app)", "8")
      .replaceAll("sizeof(*user)", "16")
      .replaceAll("sizeof(appBytes)", "76")
      .replaceAll("sizeof(userBytes)", "84")
      .replaceAll("sizeof(capabilities)", "24")
      .replaceAll("sizeof(exclusive)", "4")
      .replaceAll("sizeof(local)", "16")
      .replaceAll("sizeof(packet.local)", "16")
      .replaceAll("sizeof(packet)", "1392")
      .replaceAll("sizeof(bytes)", "1393")
      .replaceAll("(void *)", "")
      .replaceAll("(char *)", "")
      .replaceAll("(struct sockaddr *)", "")
      .replace(/&(?=[a-zA-Z_])/gu, "")
      .replace(
        /\b(?:BOOL|DWORD|HANDLE|SOCKET|TOKEN_STATISTICS|u_long|int)\b/gu,
        "let",
      );
  const appToken = native(body("socket_app_token"))
    .replace(
      "let used = 0, active = 0;",
      "const used = {value:0}, active = {value:0};",
    )
    .replace(/BYTE appBytes\[[^;]+;/u, "const appBytes = {};")
    .replace(/BYTE userBytes\[[^;]+;/u, "const userBytes = {};")
    .replace("TOKEN_GROUPS capabilities;", "const capabilities = {};")
    .replace("TOKEN_APPCONTAINER_INFORMATION *app", "const app")
    .replace("TOKEN_USER *user", "const user")
    .replace(/\bused (==|!=|<|>=)/gu, "used.value $1")
    .replace("active !=", "active.value !=");
  const target =
    "{version:1,pid:wfpChildPid,birth:wfpChildBirth,token:wfpTokenIdentity.TokenId,authentication:wfpTokenIdentity.AuthenticationId,modified:wfpTokenIdentity.ModifiedId}";
  const primaryBody = native(body("socket_primary_identity"))
    .replace(
      "let thread = NULL, token = NULL; let statistics; let status = 0;",
      "const thread = {value:null}, token = {value:null}, statistics = {}; let status = 0;",
    )
    .replaceAll("close_handle(thread,", "close_handle(thread.value,")
    .replaceAll("close_handle(token,", "close_handle(token.value,")
    .replaceAll("socket_app_token(token,", "socket_app_token(token.value,")
    .replace(
      "*value = (struct socket_target){1, GetCurrentProcessId(), creation(GetCurrentProcess()), statistics.TokenId, statistics.AuthenticationId, statistics.ModifiedId};",
      "Object.assign(value, {version:1,pid:43,birth:100,token:statistics.TokenId,authentication:statistics.AuthenticationId,modified:statistics.ModifiedId});",
    );
  const original = native(body("socket_original"))
    .replace(
      "(struct socket_target){1, wfpChildPid, wfpChildBirth, wfpTokenIdentity.TokenId, wfpTokenIdentity.AuthenticationId, wfpTokenIdentity.ModifiedId}",
      target,
    )
    .replaceAll("sizeof(wfpDestination)", "40");
  const destination = native(body("socket_destination_binding"))
    .replace(
      "let token = NULL; let statistics;",
      "const token = {value:null}, statistics = {};",
    )
    .replace("socket_app_token(token,", "socket_app_token(token.value,")
    .replace("close_handle(token,", "close_handle(token.value,");
  const exported = native(body("socket_export"))
    .replace(
      "struct socket_import packet = {0};",
      "const packet = {offer:{protocol:{}},local:{sin_addr:{}}};",
    )
    .replace("BYTE bytes[1 + 1392];", "const bytes = Array(1393).fill(0);")
    .replace("bytes + 1", "bytes")
    .replace("let sent = 0;", "const sent = {value:0};")
    .replace("sent == 1393", "sent.value == 1393");
  const ownerWrite = native(body("owner_write"))
    .replace("let sent = 0;", "const sent = {value:0};")
    .replace(/\bsent (==|!=) size/gu, "sent.value $1 size");
  const tcp = source.slice(source.indexOf("static int tcp_connection("));
  const create = native(
    tcp.slice(
      tcp.indexOf("#ifndef NATIVE_COMMAND_EXPERIMENT"),
      tcp.indexOf("  if (socket == INVALID_SOCKET)"),
    ),
  )
    .replace(/#(?:ifndef NATIVE_COMMAND_EXPERIMENT|endif)/gu, "")
    .replaceAll('L"', '"');
  const script =
    new Script(`function socket_app_token(token,statistics) {${appToken}}
    function socket_primary_identity(value) {${primaryBody}}
    function socket_target_binding(expected) {${native(body("socket_target_binding")).replace("struct socket_target actual", "const actual").replaceAll("sizeof(actual)", "40")}}
    function socket_destination_binding() {${destination}}
    function socket_original(packet) {${original}}
    function owner_write(bytes,size) {${ownerWrite}}
    function socket_export() {${exported}}
    function begin_socket() {${create}}
    function wfp_close() {${native(body("wfp_close"))}}
    try {begin_socket(); socket_original(packet); socket_export(); accepted = true;}
    finally {cleanupOkay = wfp_close();}`);
  const luid = (LowPart) => ({ HighPart: 0, LowPart });
  const child = {
    version: 1,
    pid: 43,
    birth: 100,
    token: luid(1),
    authentication: luid(2),
    modified: luid(7),
  };
  for (const fault of [
    null,
    "thread-token",
    "thread-open",
    "primary-type",
    "token-api",
    "token-api-zero",
    "short",
    "package",
    "user",
    "capability",
    "primary-not-app",
    "token-close",
    "owner-token-close",
    "creator",
    "effective",
    "local",
    "destination-change",
    "owner-birth",
    "owner-token",
    "owner-exit",
    "deadline",
    "packet-partial",
    "packet-write",
    "failure-before-write",
  ]) {
    let lastError = 0,
      reads = 0;
    const events = [],
      errors = [],
      cleanup = [];
    const packet = {
      creator: structuredClone(child),
      effective: structuredClone(child),
      local: {
        sin_family: 2,
        sin_addr: { s_addr: 0x7f000001 },
        sin_port: 45678,
      },
    };
    if (fault === "creator") packet.creator.token = luid(9);
    if (fault === "effective") packet.effective.modified = luid(9);
    if (fault === "local") packet.local.sin_addr.s_addr++;
    const context = {
      packet,
      socketCreation: {},
      role: "bundle",
      workspaceRole: "read",
      transport: { child: { hProcess: 43 }, write: 55 },
      transportLock: {},
      failing: { value: 0 },
      wfpTarget: {
        version: 1,
        pid: 41,
        birth: 90,
        token: luid(3),
        authentication: luid(2),
        modified: luid(4),
      },
      wfpToken: { value: null },
      wfpTokenIdentity: {},
      wfpDestination: {},
      wfpEffective: {},
      wfpLocal: {},
      wfpLocalPort: 0,
      wfpProtocol: { catalog: 7 },
      wfpChildPid: 43,
      wfpChildBirth: 100,
      wfpEngine: null,
      wfpCleanupFailed: false,
      wfpPreparedAt: 0,
      wfpTransferEnd: 5000,
      TRUE: true,
      FALSE: false,
      NULL: null,
      INVALID_SOCKET: -1,
      WAIT_TIMEOUT: 258,
      WAIT_FAILED: 0xffffffff,
      ERROR_NO_TOKEN: 1008,
      ERROR_INVALID_DATA: 13,
      TokenPrimary: 1,
      TokenImpersonation: 2,
      TOKEN_QUERY: 8,
      TokenStatistics: 10,
      TokenIsAppContainer: 29,
      TokenAppContainerSid: 31,
      TokenUser: 1,
      TokenCapabilities: 30,
      AF_INET: 2,
      SOCK_STREAM: 1,
      IPPROTO_TCP: 6,
      INADDR_LOOPBACK: 0x7f000001,
      appSid: "package",
      userSid: "user",
      GetCurrentThread: () => 42,
      GetCurrentProcess: () => 43,
      GetCurrentProcessId: () => 43,
      creation: () => 100,
      GetTickCount64: () => (fault === "deadline" ? 5000 : 10),
      GetLastError: () => lastError,
      wcscmp: (a, b) => (a === b ? 0 : 1),
      tcp_observe: () => {},
      WSASocketW() {
        assert.deepEqual(structuredClone(context.socketCreation), child);
        events.push("create");
        return 17;
      },
      ntohl: (v) => v,
      ntohs: (v) => v,
      OpenThreadToken(thread, rights, self, out) {
        assert.deepEqual([thread, rights, self], [42, 8, true]);
        lastError = fault === "thread-open" ? 5 : 1008;
        if (fault !== "thread-token") return false;
        out.value = 63;
        return true;
      },
      OpenProcessToken(process, rights, out) {
        assert.deepEqual([process, rights], [43, 8]);
        out.value = 61;
        return true;
      },
      GetTokenInformation(token, kind, out, capacity, used) {
        if (typeof token === "object") token = token.value;
        assert.equal(token, 61);
        lastError = fault === "token-api-zero" ? 0 : 5;
        if (["token-api", "token-api-zero"].includes(fault)) return false;
        if (kind === 10) {
          used.value = fault === "short" ? 1 : 56;
          Object.assign(out, {
            TokenType: fault === "primary-type" ? 2 : 1,
            TokenId: luid(1),
            AuthenticationId: luid(2),
            ModifiedId: luid(
              fault === "destination-change" && reads++ > 1 ? 9 : 7,
            ),
          });
        } else if (kind === 29) {
          used.value = 4;
          out.value = fault === "primary-not-app" ? 0 : 1;
        } else if (kind === 31) {
          used.value = 76;
          out.TokenAppContainer = fault === "package" ? "other" : "package";
        } else if (kind === 1) {
          used.value = 84;
          out.User = { Sid: fault === "user" ? "other" : "user" };
        } else {
          assert.equal(kind, 30);
          used.value = 4;
          out.GroupCount = fault === "capability" ? 1 : 0;
        }
        return true;
      },
      IsValidSid: (v) => typeof v === "string",
      EqualSid: (a, b) => a === b,
      socket_target: () => ({
        ...structuredClone(context.wfpTarget),
        ...(fault === "owner-birth"
          ? { birth: 91 }
          : fault === "owner-token"
            ? { token: luid(9) }
            : {}),
      }),
      WaitForSingleObject: () => (fault === "owner-exit" ? 0 : 258),
      wfp_binding: () => events.push("child-binding"),
      close_handle(handle, operation) {
        assert.ok([61, 63].includes(handle));
        events.push(`close:${handle}`);
        if (fault === "token-close") {
          cleanup.push(operation);
          return false;
        }
        return true;
      },
      release_handle(token) {
        if (token.value) events.push("owned-token-close");
        token.value = null;
        return fault !== "owner-token-close";
      },
      memcmp: (a, b) => (JSON.stringify(a) === JSON.stringify(b) ? 0 : 1),
      memcpy(bytes, value) {
        assert.deepEqual(structuredClone(value.creator), child);
        assert.deepEqual(structuredClone(value.effective), child);
        assert.deepEqual(structuredClone(value.offer.target), child);
        assert.deepEqual(structuredClone(value.offer.protocol), {});
      },
      InterlockedCompareExchange: (v) => v.value,
      AcquireSRWLockExclusive() {
        if (fault === "failure-before-write") context.failing.value = 1;
      },
      ReleaseSRWLockExclusive: () => events.push("unlocked"),
      WriteFile(pipe, bytes, size, sent) {
        assert.deepEqual([pipe, size, bytes[0]], [55, 1393, "D"]);
        events.push("packet");
        sent.value = fault === "packet-partial" ? 100 : size;
        lastError = 109;
        return fault !== "packet-write";
      },
      remember: (...v) => errors.push(v),
      cleanup_error: (...v) => cleanup.push(v),
      invariant(ok) {
        if (!ok) context.failure();
      },
      status_check(status) {
        if (status) context.failure();
      },
      win32_check(ok) {
        if (!ok) context.failure();
      },
      failure: () => {
        throw new Error("Native refusal");
      },
    };
    if (fault && fault !== "owner-token-close")
      assert.throws(
        () => script.runInNewContext(context),
        /Native refusal/u,
        fault,
      );
    else {
      script.runInNewContext(context);
      assert.equal(context.accepted, true);
    }
    assert.equal(context.cleanupOkay, fault !== "owner-token-close");
    if (events.includes("packet"))
      assert.ok(events.includes("owned-token-close"));
    if (fault === "packet-write")
      assert.deepEqual(errors[0], ["owner-write", "win32", 109]);
    if (fault === "failure-before-write") {
      assert.equal(events.includes("packet"), false);
      assert.equal(events.filter((v) => v === "unlocked").length, 1);
    }
    if (["thread-token", "token-close"].includes(fault))
      assert.ok(events.some((v) => v.startsWith("close:")));
  }
});

test("child-owned socket self-transfer binds identities and closes partial transfers", async () => {
  const source = await readFile(
    new URL("../ci/native/win32/feasibility-helper.c", import.meta.url),
    "utf8",
  );
  const body = (name) =>
    new RegExp(
      `static (?:BOOL|void|DWORD) ${name}\\([^\\n]+\\) \\{([\\s\\S]*?)\\n\\}`,
      "u",
    ).exec(source)[1];
  const native = (text) =>
    text
      .replace(
        /\(struct diagnosis\)\{"([a-z-]+)", "(win32|invariant)", ([^}]+)\}/gu,
        '{operation:"$1",domain:"$2",value:$3}',
      )
      .replace(/\*problem = ([^;]+);/gu, "Object.assign(problem, $1);")
      .replaceAll("*transferred", "transferState.value")
      .replaceAll("*socket", "socket.value")
      .replaceAll("((BYTE *)&offer.target)[i]", "targetBytes[i]")
      .replaceAll("((BYTE *)&offer)[i]", "offerByte(offer,i)")
      .replaceAll("((BYTE *)&observed)[i]", "offerByte(observed.offer,i)")
      .replaceAll("sizeof(observed)", "1392")
      .replaceAll("sizeof(observed.local)", "16")
      .replaceAll("sizeof(packet.local)", "16")
      .replaceAll("sizeof(empty)", "628")
      .replaceAll("sizeof(int)", "4")
      .replaceAll("sizeof(DWORD)", "4")
      .replaceAll("->", ".")
      .replaceAll("(struct sockaddr *)", "")
      .replace(/\((?:const )?(?:BYTE|char|DWORD|int)(?: \*)?\)/gu, "")
      .replace(/&(?=[a-zA-Z_])/gu, "")
      .replaceAll('L"', '"')
      .replace(/L'([^'])'/gu, (_match, value) => String(value.charCodeAt(0)))
      .replaceAll("sizeof(offer.target)", "40")
      .replaceAll("sizeof(offer.source)", "628")
      .replaceAll("sizeof(offer)", "1296")
      .replaceAll("sizeof(current)", "40")
      .replaceAll("sizeof(after)", "40")
      .replaceAll("sizeof(LUID)", "8")
      .replaceAll("sizeof(exclusive)", "4")
      .replaceAll("sizeof(local)", "16")
      .replaceAll("sizeof(remote)", "16")
      .replace(/\b(?:BOOL|DWORD|HANDLE|SOCKET|unsigned|int)\b/gu, "let");
  const protocol = native(body("socket_protocol"))
    .replace("const GUID empty = {0};", "const empty = {};")
    .replaceAll("sizeof(empty)", "16");
  const protocolSame = native(body("socket_protocol_same"))
    .replaceAll("sizeof(GUID)", "16")
    .replaceAll("sizeof(a.ProtocolChain)", "32");
  const controlProtocol = native(body("socket_control_protocol"))
    .replace("let size = sizeof(*actual);", "const size = {value:628};")
    .replace("size == sizeof(*actual)", "size.value == 628");
  const transfer = native(body("wfp_transfer"))
    .replace(
      "struct socket_import observed = {0};",
      "const observed = {local:{sin_addr:{}}};",
    )
    .replace(
      "observed.offer = offer;",
      "observed.offer = structuredClone(offer);",
    )
    .replace("let localSize = 16;", "const localSize = {value:16};")
    .replace("localSize != 16", "localSize.value != 16")
    .replace("const WSAPROTOCOL_INFOW empty = {0};", "const empty = {};")
    .replace(
      "struct socket_offer shared = {0};",
      "const shared = {protocol:{}};",
    )
    .replace(
      "struct socket_offer offer = {0}; WCHAR target[2 * 40 + 1];",
      "const offer = {target:{},source:{},protocol:{}}; const target = [], targetBytes = Buffer.alloc(40);",
    )
    .replaceAll("sizeof(target) / sizeof(WCHAR)", "81")
    .replace(
      "if (offer.target.version",
      "decodeTarget(targetBytes,offer.target); if (offer.target.version",
    )
    .replace("u_long nonblocking = 1;", "const nonblocking = {value:1};")
    .replace("WCHAR a", "const a")
    .replace("let protocolSize = 628;", "const protocolSize = {value:628};")
    .replace("protocolSize != 628", "protocolSize.value != 628")
    .replace(
      "struct socket_import packet = {0}; struct socket_target current = {0};",
      "const packet = {}, current = {};",
    )
    .replace(
      "let exclusive = FALSE; let size = 4; struct sockaddr_in local = {0}, remote = {0};",
      "const exclusive = {value:false}, size = {value:4}, local = {sin_addr:{}}, remote = {sin_addr:{}};",
    )
    .replaceAll("size = 16", "size.value = 16")
    .replaceAll("size !=", "size.value !=")
    .replace("!exclusive)", "!exclusive.value)")
    .replace("struct socket_target after = {0};", "const after = {};");
  const tcp = source.slice(
    source.indexOf("static int tcp_connection("),
    source.indexOf("static int connection("),
  );
  const close = native(
    tcp.slice(tcp.indexOf("done:") + 5, tcp.lastIndexOf("}")),
  )
    .replace(
      "struct diagnosis acknowledgment = {0};",
      "const acknowledgment = {};",
    )
    .replace(/#(?:ifndef NATIVE_COMMAND_EXPERIMENT|endif)/gu, "")
    .replace(/fprintf\(stderr, TCP_PREFIX " end\\n"\); fflush\(stderr\);/u, "");
  const script = new Script(`function socket_protocol(value) {${protocol}}
    function socket_protocol_same(a,b) {${protocolSame}}
    function socket_control_protocol(socket,expected,actual) {${controlProtocol}}
    function socket_source_ready(problem) {${native(body("socket_source_ready"))}}
    function wfp_transfer(socket,end,problem) {${transfer}}
    function close() {${close}}
    accepted = wfp_transfer(socketBox,end,problem); transferred = transferState.value;
    socket = socketBox.value; result = close();`);
  const luid = (LowPart) => ({ HighPart: 0, LowPart });
  const destination = {
    version: 1,
    pid: 43,
    birth: 100,
    token: luid(1),
    authentication: luid(2),
    modified: luid(7),
  };
  const provider = {
    ProviderId: { id: 1 },
    dwCatalogEntryId: 7,
    iAddressFamily: 2,
    iSocketType: 1,
    iProtocol: 6,
    ProtocolChain: { ChainLen: 1 },
  };
  for (const fault of [
    null,
    "pid-only",
    "bad-input",
    "self",
    "creator",
    "destination",
    "birth",
    "token",
    "effective",
    "provider",
    "ticket-injection",
    "export",
    "export-provider",
    "source-open",
    "source-close",
    "packet",
    "ack-D",
    "ack-T",
    "import",
    "import-deadline",
    "import-provider",
    "nonblocking",
    "exclusive",
    "local",
    "connected",
    "token-drift",
    "preflight-close",
    "close",
    "carrier",
  ]) {
    const bytes = Buffer.alloc(40);
    bytes.writeUInt32LE(1);
    bytes.writeUInt32LE(fault === "self" ? 43 : 41, 4);
    bytes.writeBigUInt64LE(90n, 8);
    for (const [offset, value] of [
      [16, 3],
      [24, 2],
      [32, 4],
    ])
      bytes.writeUInt32LE(value, offset);
    const packet = {
      creator: structuredClone(destination),
      effective: structuredClone(destination),
      offer: {
        target: structuredClone(destination),
        source: structuredClone(provider),
        protocol: {},
      },
      local: {
        sin_family: 2,
        sin_addr: { s_addr: 0x7f000001 },
        sin_port: 45678,
      },
    };
    if (fault === "creator") packet.creator.token = luid(9);
    if (fault === "destination") packet.offer.target.pid++;
    if (fault === "birth") packet.offer.target.birth++;
    if (fault === "token") packet.offer.target.token = luid(9);
    if (fault === "effective") packet.effective.authentication = luid(9);
    if (fault === "provider") packet.offer.source.dwCatalogEntryId++;
    if (fault === "ticket-injection")
      packet.offer.protocol = structuredClone(provider);
    const events = [],
      failures = [],
      cleanup = [];
    let lastError = 0,
      identities = 0;
    const context = {
      Buffer,
      structuredClone,
      socketCreation: structuredClone(destination),
      role: "bundle",
      workspaceRole: "read",
      socketBox: { value: 17 },
      end: 5000,
      started: 1,
      attempted: false,
      transferred: false,
      nativeReceipt: false,
      problem: {},
      transferState: { value: false },
      TRUE: true,
      FALSE: false,
      NULL: null,
      INVALID_SOCKET: -1,
      SOCKET_ERROR: -1,
      FROM_PROTOCOL_INFO: -1,
      ERROR_SUCCESS: 0,
      ERROR_INVALID_DATA: 13,
      PROCESS_DUP_HANDLE: 64,
      AF_INET: 2,
      SOCK_STREAM: 1,
      IPPROTO_TCP: 6,
      MAX_PROTOCOL_CHAIN: 7,
      SOL_SOCKET: 0xffff,
      SO_PROTOCOL_INFOW: 0x2005,
      SO_EXCLUSIVEADDRUSE: 0xfffffffb,
      FIONBIO: 0x8004667e,
      INADDR_LOOPBACK: 0x7f000001,
      WSAENOTCONN: 10057,
      SOCKET_PREFIX: "socket: ",
      stderr: {},
      wcscmp: (a, b) => (a === b ? 0 : 1),
      GetEnvironmentVariableW(key, out, capacity) {
        assert.equal(capacity, 81);
        out.push(
          ...[
            ...(fault === "pid-only"
              ? "41"
              : fault === "bad-input"
                ? "x".repeat(80)
                : bytes.toString("hex")),
          ].map((c) => c.charCodeAt(0)),
        );
        return out.length;
      },
      wcsspn: (value, allowed) =>
        value.every((c) => allowed.includes(String.fromCharCode(c)))
          ? value.length
          : 0,
      decodeTarget(data, out) {
        Object.assign(out, {
          version: data.readUInt32LE(),
          pid: data.readUInt32LE(4),
          birth: Number(data.readBigUInt64LE(8)),
          token: luid(data.readUInt32LE(16)),
          authentication: luid(data.readUInt32LE(24)),
          modified: luid(data.readUInt32LE(32)),
        });
      },
      GetCurrentProcessId: () => 43,
      GetTickCount64: () =>
        fault === "import-deadline" && events.includes("close:17") ? 5000 : 10,
      GetLastError: () => lastError,
      WSAGetLastError: () => lastError,
      SetLastError: (value) => {
        lastError = value;
      },
      OpenProcess(access, inherit, pid) {
        assert.deepEqual([access, inherit, pid], [64, false, 43]);
        assert.ok(!events.includes("D"));
        events.push("source-open");
        lastError = 5;
        return fault === "source-open" ? null : 72;
      },
      CloseHandle(handle) {
        assert.equal(handle, 72);
        events.push("source-close");
        lastError = 6;
        return fault !== "source-close";
      },
      socket_packet(out, deadline, problem) {
        assert.equal(deadline, 5000);
        events.push("packet");
        if (fault === "packet") {
          Object.assign(problem, {
            operation: "ack-read",
            domain: "win32",
            value: 109,
          });
          return false;
        }
        Object.assign(out, structuredClone(packet));
        return true;
      },
      socket_primary_identity(out) {
        Object.assign(out, structuredClone(destination));
        if (identities++ && fault === "token-drift") out.modified = luid(9);
        return 0;
      },
      getsockopt(socket, level, option, out, size) {
        assert.equal(level, 0xffff);
        assert.ok([17, 73].includes(socket));
        if (option === 0x2005) {
          assert.equal(size.value, 628);
          Object.assign(out, structuredClone(provider));
          if (socket === 73 && fault === "import-provider")
            out.dwCatalogEntryId++;
        } else {
          assert.equal(option, 0xfffffffb);
          assert.equal(size.value, 4);
          out.value = fault !== "exclusive";
        }
        return 0;
      },
      WSADuplicateSocketW(socket, pid, out) {
        assert.deepEqual([socket, pid], [17, 43]);
        events.push("export");
        lastError = 10022;
        Object.assign(out, structuredClone(provider));
        if (fault === "export-provider") out.dwCatalogEntryId++;
        return fault === "export" ? -1 : 0;
      },
      socket_transfer_observe: () => events.push("refusal"),
      socket_transfer_controls: () => events.push("controls"),
      WSASocketW(af, type, protocol, info, group, flags) {
        assert.deepEqual(
          [af, type, protocol, group, flags],
          [-1, -1, -1, 0, 0],
        );
        assert.equal(info.dwCatalogEntryId, 7);
        assert.ok(!events.includes("close:17"));
        events.push("import");
        lastError = 10022;
        return fault === "import" ? -1 : 73;
      },
      ioctlsocket(socket, command, mode) {
        assert.deepEqual([socket, command, mode.value], [73, 0x8004667e, 1]);
        lastError = 10022;
        return fault === "nonblocking" ? -1 : 0;
      },
      getsockname(socket, out, size) {
        assert.ok([17, 73].includes(socket));
        assert.equal(size.value, 16);
        Object.assign(out, structuredClone(packet.local));
        if (fault === "local" && socket === 73) out.sin_port++;
        return 0;
      },
      getpeername(socket) {
        assert.equal(socket, 73);
        lastError = 10057;
        return fault === "connected" ? 0 : -1;
      },
      htonl: (v) => v,
      memcmp(a, b) {
        try {
          assert.deepEqual(structuredClone(a), structuredClone(b));
          return 0;
        } catch {
          return 1;
        }
      },
      offerByte: (offer) => {
        if (events.includes("import"))
          assert.deepEqual(structuredClone(offer.protocol), provider);
        return 0;
      },
      fputs: () => events.push("carrier"),
      fprintf: () => {},
      fputc: () => {},
      fflush: () => {},
      ferror: () => fault === "carrier" && context.transferState.value,
      tcp_ack(expected, deadline, problem) {
        events.push(expected);
        if (fault === `ack-${expected}`) {
          Object.assign(problem, {
            operation: "ack-read",
            domain: "win32",
            value: 109,
          });
          return false;
        }
        return true;
      },
      tcp_observe: (api, phase) => events.push(`observe:${api}:${phase}`),
      wfp_tuple: () => events.push("tuple"),
      closesocket(socket) {
        events.push(`close:${socket}`);
        lastError = 10038;
        return fault === (socket === 17 ? "preflight-close" : "close") ? -1 : 0;
      },
      remember(...value) {
        if (!failures.length) failures.push(value);
      },
      cleanup_error: (...v) => cleanup.push(v),
      failure: () => {
        throw new Error(
          "Native refusal: " +
            JSON.stringify({ problem: context.problem, events }),
        );
      },
    };
    if (fault)
      assert.throws(
        () => script.runInNewContext(context),
        /Native refusal/u,
        fault,
      );
    else {
      script.runInNewContext(context);
      assert.equal(context.accepted, true);
      assert.equal(context.result, 0);
    }
    assert.equal(events.filter((e) => e === "close:17").length, 1, fault);
    assert.equal(
      events.filter((e) => e === "close:73").length,
      events.includes("import") && fault !== "import" ? 1 : 0,
      fault,
    );
    assert.equal(events.includes("U"), context.transferState.value, fault);
    assert.equal(
      events.includes("observe:closesocket:enter"),
      context.socketBox.value !== -1,
      fault,
    );
    assert.equal(
      events.includes("observe:closesocket:complete"),
      context.socketBox.value !== -1 && fault !== "close",
      fault,
    );
    if (
      [
        "creator",
        "destination",
        "birth",
        "token",
        "effective",
        "provider",
        "ticket-injection",
        "packet",
        "ack-D",
        "source-open",
        "source-close",
        "export",
        "export-provider",
      ].includes(fault)
    )
      assert.equal(events.includes("import"), false, fault);
    if (["preflight-close", "close"].includes(fault))
      assert.deepEqual(cleanup[0], ["tcp-close", "win32", 10038]);
    if (fault === "import")
      assert.deepEqual(failures[0], ["observer-socket", "win32", 10022]);
  }
});

test("socket import packets retain bounded partial-read and native pipe failures", async () => {
  const source = await readFile(
    new URL("../ci/native/win32/feasibility-helper.c", import.meta.url),
    "utf8",
  );
  const body = /static BOOL socket_packet\([^\n]+\) \{([\s\S]*?)\n\}/u
    .exec(source)[1]
    .replaceAll("sizeof(*packet)", "1392")
    .replaceAll("(DWORD)", "")
    .replace("(BYTE *)packet + at", "packet.subarray(at)")
    .replace("HANDLE pipe", "const pipe")
    .replaceAll("DWORD ", "let ")
    .replace(
      "let available = 0, used = 0;",
      "const available = {value:0}, used = {value:0};",
    )
    .replaceAll("&available", "available")
    .replaceAll("&used", "used")
    .replace("!available)", "!available.value)")
    .replaceAll(
      "available < remaining ? available",
      "available.value < remaining ? available.value",
    )
    .replaceAll("!used || used > size", "!used.value || used.value > size")
    .replace("at += used", "at += used.value")
    .replaceAll("*problem =", "problem.value =")
    .replace(
      /\(struct diagnosis\)\{"([a-z-]+)", "(win32|invariant)", ([^}]+)\}/gu,
      '{operation:"$1",domain:"$2",value:$3}',
    );
  const script = new Script(
    `function socket_packet(packet,end,problem) {${body}} result = socket_packet(packet,5,problem);`,
  );
  for (const fault of [
    null,
    "peek",
    "read",
    "eof",
    "oversized",
    "partial",
    "expired",
  ]) {
    let clock = fault === "expired" ? 5 : 0,
      reads = 0;
    const context = {
      packet: Buffer.alloc(1392),
      problem: { value: null },
      TRUE: true,
      FALSE: false,
      NULL: null,
      STD_INPUT_HANDLE: 1,
      GetStdHandle: () => 31,
      GetTickCount64: () => clock,
      GetLastError: () => 109,
      PeekNamedPipe(pipe, _a, _b, _c, available) {
        assert.equal(pipe, 31);
        available.value = fault === "partial" && reads ? 0 : 400;
        return fault !== "peek";
      },
      ReadFile(pipe, target, size, used) {
        assert.equal(pipe, 31);
        assert.ok(size > 0 && size <= 400);
        reads++;
        target.fill(0xa5, 0, size);
        used.value =
          fault === "eof" ? 0 : fault === "oversized" ? size + 1 : size;
        return fault !== "read";
      },
      Sleep(amount) {
        assert.equal(amount, 1);
        clock++;
      },
    };
    script.runInNewContext(context);
    assert.equal(context.result, !fault, fault);
    if (!fault) {
      assert.equal(reads, 4);
      assert.ok(context.packet.every((byte) => byte === 0xa5));
    } else
      assert.equal(
        context.problem.value.operation,
        ["peek", "read"].includes(fault)
          ? "ack-read"
          : ["partial", "expired"].includes(fault)
            ? "tcp-deadline"
            : "observer-carrier",
        fault,
      );
    if (["peek", "read"].includes(fault))
      assert.equal(context.problem.value.value, 109);
    if (fault === "partial") assert.equal(reads, 1);
  }
});

test("native TCP acknowledgments use bounded pipe reads and retain their actual failures", async () => {
  const source = await readFile(
    new URL("../ci/native/win32/feasibility-helper.c", import.meta.url),
    "utf8",
  );
  const begin = source.indexOf("static BOOL tcp_ack(");
  const body = source
    .slice(begin, source.indexOf("/* Controls never", begin))
    .replace(
      "static BOOL tcp_ack(char expected, ULONGLONG end, struct diagnosis *problem)",
      "function tcp_ack(expected, end, problem)",
    )
    .replace("HANDLE pipe", "const pipe")
    .replace("DWORD available = 0;", "const available = {value: 0};")
    .replace(
      "char value = 0; DWORD size = 0;",
      "const value = {value: 0}, size = {value: 0};",
    )
    .replaceAll("*problem =", "problem.value =")
    .replace(
      /\(struct diagnosis\)\{"([a-z-]+)", "(win32|invariant)", ([^}]+)\}/gu,
      '{operation:"$1",domain:"$2",value:$3}',
    )
    .replace(/&(available|value|size)/gu, "$1")
    .replace("if (available)", "if (available.value)")
    .replace(
      "size != 1 || value != expected",
      "size.value != 1 || value.value != expected",
    );
  const exercise = new Script(body + "result = tcp_ack(expected, 5, problem);");
  for (const expected of ["D", "T", "U", "V"])
    for (const scenario of [
      "ready",
      "delayed",
      "wrong",
      "read-error",
      "broken",
      "expired",
      "empty",
    ]) {
      let clock = scenario === "expired" ? 5 : 0,
        peeks = 0,
        reads = 0;
      const problem = { value: null };
      const context = {
        expected,
        problem,
        TRUE: true,
        FALSE: false,
        NULL: null,
        STD_INPUT_HANDLE: 1,
        GetStdHandle: () => 31,
        GetTickCount64: () => clock,
        GetLastError: () => 109,
        PeekNamedPipe: (pipe, _, _size, _read, available) => {
          assert.equal(pipe, 31);
          peeks++;
          available.value =
            scenario === "empty" || (scenario === "delayed" && peeks === 1)
              ? 0
              : 1;
          return scenario !== "broken";
        },
        ReadFile: (pipe, value, count, size) => {
          assert.equal(pipe, 31);
          assert.equal(count, 1);
          reads++;
          assert.notEqual(scenario, "empty");
          value.value = scenario === "wrong" ? "X" : expected;
          size.value = 1;
          return scenario !== "read-error";
        },
        Sleep: (value) => {
          assert.equal(value, 1);
          clock++;
        },
      };
      exercise.runInNewContext(context, { timeout: 1000 });
      assert.equal(context.result, ["ready", "delayed"].includes(scenario));
      if (["broken", "read-error"].includes(scenario))
        assert.equal(problem.value.value, 109);
      if (scenario === "wrong")
        assert.equal(problem.value.operation, "ack-value");
      if (["expired", "empty"].includes(scenario))
        assert.equal(problem.value.operation, "tcp-deadline");
      if (["expired", "empty", "broken"].includes(scenario))
        assert.equal(reads, 0);
      if (scenario === "expired") assert.equal(peeks, 0);
      assert.ok(clock <= 5);
    }
});

function wfpFixture() {
  const stream = windowsSessionFixture(),
    saved = [];
  const child = {
    pid: 43,
    creationTime: "100",
    sessionId: 1,
    userSid: "S-1-5-21-1000",
  };
  const image = { identity: "1:2", private: false, sha256: DIGEST };
  const sid = "S-1-15-2-1-2-3-4-5-6-7";
  const bytes = Buffer.alloc(72);
  for (const [offset, value] of [
    [0, 0x57465031],
    [4, 43],
    [40, 0x7f000001],
    [44, 0x7f000001],
    [52, 2],
    [56, 2],
    [60, 16],
    [64, 16],
    [68, 1],
  ])
    bytes.writeUInt32LE(value, offset);
  for (const [offset, value] of [
    [8, 100n],
    [16, 1000n],
    [24, 2000n],
  ])
    bytes.writeBigUInt64LE(value, offset);
  bytes.writeUInt16LE(45678, 48);
  bytes.writeUInt16LE(32100, 50);
  const observation = {
    status: "matched",
    reason: "none",
    nativeStatus: 0,
    enumClose: 0,
    engineClose: 0,
    child: { pid: 43, creationTime: "100" },
    sid,
    userSid: child.userSid,
    image: { ...image },
    matches: [
      {
        filterId: "7",
        layerId: 48,
        direction: 0,
        actionType: 0x1001,
        flags: 0x57f,
        isLoopback: true,
        time: "1500",
        filterKey: "a".repeat(32),
        layerKey: "c".repeat(32),
      },
    ],
  };
  return {
    ...stream,
    bytes,
    observation,
    saved,
    run: {
      caseId: "read",
      session: stream.session,
      receipt: { child, sid, image },
    },
    tuple: () => "native-windows-wfp: tuple=" + bytes.toString("hex") + "\n",
    snapshot: () =>
      "native-windows-wfp: snapshot=" + JSON.stringify(observation) + "\n",
    persist: async (name, value) => saved.push([name, value]),
  };
}

function tcpDenialFixture(
  receipt = {
    owner: { pid: 41, creationTime: "90" },
    child: { pid: 43, creationTime: "100", userSid: "S-1-5-21-1000" },
    sid: "S-1-15-2-1-2-3-4-5-6-7",
    image: { identity: "1:2", private: false, sha256: DIGEST },
  },
) {
  const binding = {
    child: { pid: receipt.child.pid, creationTime: receipt.child.creationTime },
    owner: { pid: receipt.owner.pid, creationTime: receipt.owner.creationTime },
    sid: receipt.sid,
    userSid: receipt.child.userSid,
    image: { ...receipt.image },
    tokenId: "0000000000000001",
    authenticationId: "0000000000000002",
    preparedAt: "1000",
    exclusive: true,
    transfer: {
      direction: "child-self",
      appContainer: true,
      creator: {
        pid: receipt.child.pid,
        creationTime: receipt.child.creationTime,
        tokenId: "0000000000000001",
        authenticationId: "0000000000000002",
        modifiedId: "0000000000000007",
      },
      effective: {
        pid: receipt.child.pid,
        creationTime: receipt.child.creationTime,
        tokenId: "0000000000000001",
        authenticationId: "0000000000000002",
        modifiedId: "0000000000000007",
      },
      destination: {
        pid: receipt.child.pid,
        creationTime: receipt.child.creationTime,
        tokenId: "0000000000000001",
        authenticationId: "0000000000000002",
        modifiedId: "0000000000000007",
      },
      providerId: "a".repeat(32),
      catalogId: 7,
      creationFlags: 0,
      addressFamily: 2,
      socketType: 1,
      protocol: 6,
    },
  };
  const requested = { address: 0x7f000001, port: 32100 };
  const local = { address: 0x7f000001, port: 45678 };
  return {
    receipt,
    endpoint: "32100",
    transfer: {
      event: "tcp-transfer-ready",
      child: structuredClone(binding.child),
      owner: structuredClone(binding.owner),
      transfer: structuredClone(binding.transfer),
    },
    prepared: {
      event: "tcp-observer-ready",
      ...structuredClone(binding),
      local: { ...local },
      requested: { ...requested },
      collectionEnabled: true,
      peerStatus: 10057,
    },
    attribution: {
      event: "tcp-attribution",
      ...structuredClone(binding),
      requested,
      local,
      localStatus: 0,
      peerStatus: 10057,
      startedAt: "1100",
      endedAt: "2000",
      socketHeld: true,
      tokenClosed: true,
      status: "matched",
      reason: "none",
      nativeStatus: 0,
      enumClose: 0,
      engineClose: 0,
      matches: [
        {
          filterId: "7",
          layerId: 48,
          direction: 0,
          actionType: 0x1001,
          flags: 0x57f,
          isLoopback: true,
          time: "1500",
          filterKey: "a".repeat(32),
          layerKey: "d1578dc3a705334c904f7fbceee60e82",
          providerKey: "b".repeat(32),
          calloutKey: null,
          calloutProviderKey: null,
        },
      ],
    },
  };
}

test("feasibility requires socket-bound ALE attribution and actual 10013 without inventing a connected peer", () => {
  const f = tcpDenialFixture();
  const accept = (value, result = 10013) =>
    assertWindowsFeasibilityTcpDenial(
      value,
      f.prepared,
      f.receipt,
      f.endpoint,
      result,
    );
  assert.equal(accept(f.attribution), f.attribution);
  assert.equal(f.attribution.peerStatus, 10057);
  assert.throws(() =>
    assertWindowsFeasibilityTcpDenial(
      f.attribution,
      f.prepared,
      f.receipt,
      f.endpoint,
      undefined,
    ),
  );
  const callout = structuredClone(f.attribution);
  callout.matches[0].actionType = 0x5003;
  callout.matches[0].calloutKey = "c".repeat(32);
  callout.matches[0].calloutProviderKey = "d".repeat(32);
  assert.equal(accept(callout), callout);
  for (const change of [
    (v) => (v.matches[0].providerKey = null),
    (v) => (v.matches[0].providerKey = "0".repeat(32)),
    (v) => (v.matches[0].calloutKey = null),
    (v) => (v.matches[0].actionType = 0x1001),
  ]) {
    const altered = structuredClone(callout);
    change(altered);
    assert.throws(() => accept(altered));
  }
  for (const code of [0, 5, 10035, 10061, 10060, 10054, null])
    assert.throws(() => accept(f.attribution, code));
  for (const change of [
    (v) => v.child.pid++,
    (v) => (v.child.creationTime = "101"),
    (v) => v.owner.pid++,
    (v) => (v.owner.creationTime = "91"),
    (v) => (v.sid += "-1"),
    (v) => (v.userSid += "-1"),
    (v) => (v.image.sha256 = "c".repeat(64)),
    (v) => (v.image.identity = "2:3"),
    (v) => (v.image.private = true),
    (v) => (v.tokenId = "0000000000000003"),
    (v) => (v.authenticationId = "0000000000000003"),
    (v) => (v.preparedAt = "1001"),
    (v) => (v.transfer.direction = "child-to-creator"),
    (v) => (v.transfer.appContainer = false),
    (v) => v.transfer.creator.pid++,
    (v) => (v.transfer.creator.creationTime = "91"),
    (v) => (v.transfer.effective.tokenId = "f".repeat(16)),
    (v) => (v.transfer.effective.authenticationId = "f".repeat(16)),
    (v) => v.transfer.destination.pid++,
    (v) => (v.transfer.destination.creationTime = "91"),
    (v) => (v.transfer.destination.tokenId = "0000000000000005"),
    (v) => (v.transfer.providerId = "b".repeat(32)),
    (v) => v.transfer.catalogId++,
    (v) => (v.transfer.creationFlags = 1),
    (v) => v.requested.port++,
    (v) => v.requested.address++,
    (v) => v.local.port++,
    (v) => v.local.address++,
    (v) => (v.localStatus = 10022),
    (v) => (v.peerStatus = -1),
    (v) => (v.peerStatus = 0),
    (v) => (v.startedAt = "999"),
    (v) => (v.endedAt = "1099"),
    (v) => (v.endedAt = "50001001"),
    (v) => (v.socketHeld = false),
    (v) => (v.tokenClosed = false),
    (v) => (v.exclusive = false),
    (v) => (v.engineClose = 5),
    (v) => (v.enumClose = null),
    (v) => (v.nativeStatus = 5),
    (v) => (v.status = "unproved"),
    (v) => (v.matches = []),
    (v) => (v.matches[0].time = "2001"),
    (v) => (v.matches[0].time = "1099"),
    (v) => (v.matches[0].filterId = "0"),
    (v) => (v.matches[0].filterKey = "0".repeat(32)),
    (v) => (v.matches[0].layerId = 0),
    (v) => (v.matches[0].layerKey = "a".repeat(32)),
    (v) => (v.matches[0].direction = 1),
    (v) => (v.matches[0].actionType = 0x1002),
    (v) => (v.matches[0].flags &= ~0x400),
    (v) => (v.matches[0].isLoopback = false),
    (v) => (v.remote = { address: 0x7f000001, port: 32100 }),
  ]) {
    const altered = structuredClone(f.attribution);
    change(altered);
    assert.throws(() => accept(altered), change.toString());
  }
  for (const change of [
    (v) => (v.collectionEnabled = false),
    (v) => (v.peerStatus = 0),
    (v) => v.requested.port++,
    (v) => (v.local.port = 0),
    (v) => (v.child.creationTime = "99"),
    (v) => (v.tokenId = "0".repeat(16)),
  ]) {
    const altered = structuredClone(f.prepared);
    change(altered);
    assert.throws(
      () => assertWindowsFeasibilityTcpObserver(altered, f.receipt, f.endpoint),
      change.toString(),
    );
  }
  assert.throws(() =>
    assertWindowsFeasibilityTcpObserver(f.prepared, f.receipt, "32101"),
  );
});

test("native WFP filter lookup binds block and terminating-callout providers and frees partial results", async () => {
  const source = await readFile(
    new URL("../ci/native/win32/feasibility-helper.c", import.meta.url),
    "utf8",
  );
  const body = /static DWORD wfp_filter\([^\n]+\) \{([\s\S]*?)\n\}/u
    .exec(source)[1]
    .replaceAll("->", ".")
    .replaceAll("sizeof(empty)", "16")
    .replaceAll("sizeof(GUID)", "16")
    .replaceAll("(void **)", "")
    .replace(/&(?=[a-z])/gu, "")
    .replace(
      "const GUID empty = {0}; FWPM_PROVIDER0 *provider = NULL, *calloutProvider = NULL; FWPM_CALLOUT0 *callout = NULL; DWORD status = ERROR_INVALID_DATA;",
      "const empty = 'zero'; let provider = null, calloutProvider = null, callout = null, status = ERROR_INVALID_DATA; do {",
    )
    .replace(
      "status = FwpmProviderGetByKey0(engine, filter.providerKey, provider);",
      "({status,provider} = FwpmProviderGetByKey0(engine, filter.providerKey));",
    )
    .replace(
      "status = FwpmProviderGetByKey0(engine, callout.providerKey, calloutProvider);",
      "({status,calloutProvider} = FwpmProviderGetByKey0(engine, callout.providerKey));",
    )
    .replace(
      "status = FwpmCalloutGetByKey0(engine, filter.action.calloutKey, callout);",
      "({status,callout} = FwpmCalloutGetByKey0(engine, filter.action.calloutKey));",
    )
    .replaceAll("*providerKey =", "providerKey.value =")
    .replaceAll("*calloutKey =", "calloutKey.value =")
    .replaceAll("*calloutProviderKey =", "calloutProviderKey.value =")
    .replaceAll("goto closed;", "break;")
    .replace("closed:", "} while (false);");
  const script = new Script(`result = (function() {${body}})();`);
  for (const action of [0x1001, 0x5003])
    for (const fault of [
      null,
      "missing-provider",
      "provider-error",
      "provider-null",
      "provider-key",
      "callout-error",
      "callout-null",
      "callout-key",
      "callout-provider",
      "callout-provider-error",
      "callout-provider-null",
      "callout-layer",
      "action",
    ]) {
      if (action === 0x1001 && fault?.startsWith("callout")) continue;
      const freed = [],
        acquired = [],
        calloutProvider = {
          providerKey:
            fault === "callout-provider" ? "other" : "callout-provider",
        },
        provider = {
          providerKey: fault === "provider-key" ? "other" : "provider",
        },
        callout = {
          calloutKey: fault === "callout-key" ? "other" : "callout",
          providerKey: "callout-provider",
          applicableLayer: fault === "callout-layer" ? "other" : "connect",
        };
      const context = {
        engine: 17,
        filter: {
          providerKey: fault === "missing-provider" ? null : "provider",
          action: {
            type: fault === "action" ? 0x1002 : action,
            calloutKey: "callout",
          },
        },
        layer: { layerKey: "connect" },
        providerKey: { value: null },
        calloutKey: { value: null },
        calloutProviderKey: { value: null },
        NULL: null,
        ERROR_INVALID_DATA: 13,
        FWP_ACTION_BLOCK: 0x1001,
        FWP_ACTION_CALLOUT_TERMINATING: 0x5003,
        memcmp: (a, b) =>
          (a && typeof a === "object" && "value" in a ? a.value : a) ===
          (b && typeof b === "object" && "value" in b ? b.value : b)
            ? 0
            : 1,
        FwpmProviderGetByKey0(engine, key) {
          assert.equal(engine, 17);
          if (key === "provider") {
            if (!["provider-null", "provider-error"].includes(fault))
              acquired.push(provider);
            return {
              status: fault === "provider-error" ? 5 : 0,
              provider:
                fault === "provider-null" || fault === "provider-error"
                  ? null
                  : provider,
            };
          }
          assert.equal(key, "callout-provider");
          if (
            !["callout-provider-error", "callout-provider-null"].includes(fault)
          )
            acquired.push(calloutProvider);
          return {
            status: fault === "callout-provider-error" ? 5 : 0,
            calloutProvider:
              fault === "callout-provider-error" ||
              fault === "callout-provider-null"
                ? null
                : calloutProvider,
          };
        },
        FwpmCalloutGetByKey0(engine, key) {
          assert.deepEqual([engine, key], [17, "callout"]);
          if (!["callout-null", "callout-error"].includes(fault))
            acquired.push(callout);
          return {
            status: fault === "callout-error" ? 5 : 0,
            callout:
              fault === "callout-null" || fault === "callout-error"
                ? null
                : callout,
          };
        },
        FwpmFreeMemory0: (value) => freed.push(value),
      };
      script.runInNewContext(context);
      assert.equal(context.result === 0, !fault, `${action}:${fault}`);
      assert.equal(freed.length, acquired.length);
      for (const allocation of acquired)
        assert.equal(freed.filter((value) => value === allocation).length, 1);
      if (freed.includes(callout)) assert.ok(freed.includes(provider));
      if (!fault) {
        assert.equal(context.providerKey.value, "provider");
        assert.equal(
          context.calloutKey.value,
          action === 0x5003 ? "callout" : "zero",
        );
      }
      if (fault === "callout-error") assert.deepEqual(freed, [provider]);
    }
  // The final lookup on the final page must not bypass the observation budget.
  const start = source.indexOf("      GUID providerKey = {0}, calloutKey");
  const admission = source
    .slice(start, source.indexOf("      if (matched == 8)", start))
    .replace(
      "GUID providerKey = {0}, calloutKey = {0}, calloutProviderKey = {0};",
      "const providerKey = {}, calloutKey = {}, calloutProviderKey = {};",
    )
    .replaceAll("filter->", "filter.")
    .replace(/&(?=[a-z])/gu, "")
    .replaceAll("goto closed;", "return false;");
  const finish = new Script(
    `accepted = (function() {${admission}return true;})();`,
  );
  for (const finishedAt of [4999, 5000, 5001]) {
    let now = 0;
    const context = {
      socketBound: true,
      engine: 17,
      filter: {},
      layer: {},
      status: 0,
      reason: "none",
      deadline: 5000,
      GetTickCount64: () => now,
      wfp_filter: () => {
        now = finishedAt;
        return 0;
      },
    };
    finish.runInNewContext(context);
    assert.equal(context.accepted, finishedAt < 5000);
    assert.equal(context.reason, finishedAt < 5000 ? "none" : "exhausted");
  }
});

test("native socket and WFP predicates reject fabricated peers, stale windows and unrelated tuples", async () => {
  const source = await readFile(
    new URL("../ci/native/win32/feasibility-helper.c", import.meta.url),
    "utf8",
  );
  const peer = /BOOL peerBound = ([\s\S]*?);\n/u.exec(source)[1];
  const bound = /socketBound = (tuple\.attempted[\s\S]*?);\n/u.exec(source)[1];
  const translate = (value) =>
    value
      .replace(/sizeof\((?:remote|local|struct sockaddr_in)\)/gu, "16")
      .replace(/\bTRUE\b/gu, "true");
  const predicate = new Script(
    `peerBound = ${translate(peer)}; socketBound = ${translate(bound)};`,
  );
  const fixture = () => ({
    tuple: {
      attempted: true,
      localStatus: 0,
      localSize: 16,
      localFamily: 2,
      localAddress: 0x7f000001,
      localPort: 45678,
      remoteStatus: 10057,
      remoteSize: 0,
      remoteFamily: 0,
      remoteAddress: 0,
      remotePort: 0,
      started: 1100,
      ended: 2000,
    },
    localBound: true,
    localStatus: 0,
    remoteResult: -1,
    remoteStatus: 10057,
    remote: {
      sin_family: 2,
      sin_addr: { s_addr: 0x7f000001 },
      sin_port: 32100,
    },
    length: 16,
    wfpLocalPort: 45678,
    wfpRemotePort: 32100,
    wfpPreparedAt: 1000,
    wfpPreparedTick: 100,
    AF_INET: 2,
    INADDR_LOOPBACK: 0x7f000001,
    SOCKET_ERROR: -1,
    WSAENOTCONN: 10057,
    ntohl: (value) => value,
    ntohs: (value) => value,
    GetTickCount64: () => 200,
  });
  const valid = fixture();
  predicate.runInNewContext(valid);
  assert.equal(valid.socketBound, true);
  for (const change of [
    (v) => (v.tuple.remoteStatus = 0),
    (v) => (v.tuple.remotePort = 32100),
    (v) => v.tuple.localPort++,
    (v) => (v.localBound = false),
    (v) => (v.tuple.localStatus = 10022),
    (v) => (v.tuple.attempted = false),
    (v) => (v.tuple.started = 999),
    (v) => (v.tuple.ended = 50001101),
    (v) => (v.GetTickCount64 = () => 5100),
    (v) => {
      v.remoteResult = 0;
      v.tuple.remoteStatus = 0;
    },
  ]) {
    const altered = fixture();
    change(altered);
    predicate.runInNewContext(altered);
    assert.equal(altered.socketBound, false, change.toString());
  }
  const tupleGuard = /if \(h->ipVersion ([\s\S]*?)\) continue;/u.exec(
    source,
  )[1];
  const eventPredicate = new Script(
    "rejected = (h.ipVersion " + tupleGuard.replaceAll("h->", "h.") + ");",
  );
  const event = {
    ipVersion: 0,
    ipProtocol: 6,
    localAddrV4: 0x7f000001,
    remoteAddrV4: 0x7f000001,
    localPort: 45678,
    remotePort: 32100,
  };
  for (const field of [null, ...Object.keys(event)]) {
    const context = {
      ...fixture(),
      h: { ...event },
      FWP_IP_VERSION_V4: 0,
      IPPROTO_TCP: 6,
      socketBound: true,
    };
    if (field) context.h[field]++;
    eventPredicate.runInNewContext(context);
    assert.equal(context.rejected, field !== null, field);
  }
  const filterGuard =
    /if \((!filter \|\| !layer \|\| filter->filterId[\s\S]*?)\) \{ reason = "fields"; goto closed; \}/u.exec(
      source,
    )[1];
  const filterPredicate = new Script(
    "rejected = (" +
      filterGuard
        .replaceAll("&filter->layerKey", "filter.layerKey")
        .replaceAll("&layer->layerKey", "layer.layerKey")
        .replaceAll("filter->", "filter.")
        .replaceAll("layer->", "layer.")
        .replaceAll("drop->", "drop.")
        .replace("sizeof(GUID)", "16") +
      ");",
  );
  for (const change of [
    null,
    (v) => v.filter.filterId++,
    (v) => v.layer.layerId++,
    (v) => (v.filter.layerKey = "other"),
    (v) => (v.filter = null),
  ]) {
    const context = {
      filter: { filterId: 7, layerKey: "connect", action: { type: 0x1001 } },
      layer: { layerId: 48, layerKey: "connect" },
      drop: { filterId: 7, layerId: 48 },
      FWP_ACTION_BLOCK: 0x1001,
      memcmp: (left, right) => (left === right ? 0 : 1),
    };
    change?.(context);
    filterPredicate.runInNewContext(context);
    assert.equal(
      Boolean(context.rejected),
      change !== null,
      change?.toString(),
    );
  }
});

test("socket export refusals retain distinct self/destination evidence and bounded prerequisites", async () => {
  const [source, driver] = await Promise.all([
    readFile(
      new URL("../ci/native/win32/feasibility-helper.c", import.meta.url),
      "utf8",
    ),
    readFile(
      new URL("../ci/native/win32/feasibility.js", import.meta.url),
      "utf8",
    ),
  ]);
  const body = (name) =>
    new RegExp(
      `static (?:BOOL|void|DWORD) ${name}\\([^\\n]+\\) \\{([\\s\\S]*?)\\n\\}`,
      "u",
    ).exec(source)[1];
  // Translate syntax and pointer carriers only. Acquisition, failed-call
  // observation, transfer/import predicates and cleanup retain their C bodies.
  const native = (text) =>
    text
      .replace(
        /\(struct diagnosis\)\{"([a-z-]+)", "(win32|invariant)", ([^}]+)\}/gu,
        '{operation:"$1",domain:"$2",value:$3}',
      )
      .replace(/\*problem = ([^;]+);/gu, "Object.assign(problem, $1);")
      .replaceAll("*transferred", "transferState.value")
      .replaceAll("((BYTE *)&offer.target)[i]", "targetBytes[i]")
      .replaceAll("((BYTE *)&offer)[i]", "carrier[i]")
      .replaceAll("((BYTE *)&control)[i]", "controlCarrier[i]")
      .replaceAll(
        "((const BYTE *)&offer->source)[i]",
        "protocolBytes(offer.source)[i]",
      )
      .replaceAll("->", ".")
      .replaceAll("sizeof(DWORD)", "4")
      .replace(
        /\((?:const )?(?:BYTE|char|DWORD|int|ULONGLONG|LONGLONG|unsigned)(?: \*)?\)/gu,
        "",
      )
      .replace(/&(?=[a-zA-Z_])/gu, "")
      .replaceAll('L"', '"')
      .replace(/L'([^'])'/gu, (_match, value) => String(value.charCodeAt(0)))
      .replace(/'(\\[rn]|[^'])'/gu, (_match, value) =>
        String(
          (value === "\\r" ? "\r" : value === "\\n" ? "\n" : value).charCodeAt(
            0,
          ),
        ),
      )
      .replaceAll('TCP_PREFIX "', 'TCP_PREFIX + "')
      .replaceAll("sizeof(GUID)", "16")
      .replaceAll("sizeof(wfpTarget)", "40")
      .replaceAll("sizeof(actual)", "40")
      .replaceAll("sizeof(offer.target)", "40")
      .replaceAll("sizeof(offer.source)", "628")
      .replaceAll("sizeof(offer.protocol)", "628")
      .replaceAll("sizeof(offer)", "1296")
      .replaceAll("sizeof(control)", "1312")
      .replaceAll("offsetof(WSAPROTOCOL_INFOW, dwProviderReserved)", "112")
      .replace(
        /\b(?:BOOL|DWORD|HANDLE|SOCKET|LONGLONG|ULONGLONG|BYTE|unsigned)\b/gu,
        "let",
      );
  const protocol = native(body("socket_protocol"))
    .replace("const GUID empty = {0};", 'const empty = {hex:"0".repeat(32)};')
    .replaceAll("sizeof(empty)", "16");
  const binding = native(body("socket_target_binding")).replace(
    "struct socket_target actual",
    "const actual",
  );
  // Keep refused-call diagnostics separate from creator/import admission and
  // partial cleanup above; none of these controls may prepare an original.
  const exportBody = body("wfp_transfer");
  const refusedExport = native(
    exportBody.slice(
      exportBody.indexOf("  if (WSADuplicateSocketW("),
      exportBody.indexOf("  if (!socket_protocol_same(&shared.source"),
    ),
  )
    .replaceAll("*socket", "socket")
    .replaceAll("current.pid", "offer.target.pid")
    .replaceAll("shared", "offer")
    .replace("return FALSE;", "failure(126);")
    .replace(
      "socket_transfer_controls(offer, error, end)",
      "await socket_transfer_controls(offer, error, end)",
    );
  const tokenRead = native(body("socket_token_observe"))
    .replace(
      "let token = NULL; let used = 0;",
      "const token = {value:null}, used = {value:0};",
    )
    .replaceAll("sizeof(value.statistics)", "56")
    .replaceAll("sizeof(value.container)", "4")
    .replaceAll(
      "GetTokenInformation(token,",
      "GetTokenInformation(token.value,",
    )
    .replace("value.container, 4, used", "value, 4, used")
    .replaceAll("used ==", "used.value ==")
    .replace("used = 0; read", "used.value = 0; read")
    .replace("IsTokenRestricted(token)", "IsTokenRestricted(token.value)")
    .replace("CloseHandle(token)", "CloseHandle(token.value)");
  const tokenWrite = native(body("socket_token_write")).replace(
    "const TOKEN_STATISTICS *s",
    "const s",
  );
  const observation = native(body("socket_transfer_observe"))
    .replace(
      "let exclusive = FALSE; int exclusiveSize = sizeof(exclusive);",
      "const exclusive = {value:false}, exclusiveSize = {value:4};",
    )
    .replaceAll("sizeof(exclusive)", "4")
    .replaceAll("exclusiveSize ==", "exclusiveSize.value ==")
    .replaceAll('"%d", exclusiveSize)', '"%d", exclusiveSize.value)')
    .replaceAll('"%u", exclusive)', '"%u", exclusive.value)')
    .replace("int exclusiveResult", "const exclusiveResult")
    .replace(
      "struct socket_token_observation source = {{-1, -1, -1, -1, -1}}, destination = {{-1, -1, -1, -1, -1}};",
      "const source = tokenObservation(), destination = tokenObservation();",
    )
    .replace(
      "struct socket_token_observation effective = {{-1, -1, -1, -1, -1}};",
      "const effective = tokenObservation();",
    )
    .replace(
      "QOS qos = {0}; let qosBytes = 0;",
      "const qos = {SendingFlowspec:{},ReceivingFlowspec:{},ProviderSpecific:{}}, qosBytes = {value:0};",
    )
    .replaceAll("sizeof(qos)", "80")
    .replaceAll("qosBytes ==", "qosBytes.value ==")
    .replace("? -1 : qosBytes)", "? -1 : qosBytes.value)")
    .replace("int qosResult", "let qosResult")
    .replace(
      "FILETIME born = {0}, exited, kernel, user;",
      "const born = {}, exited = {}, kernel = {}, user = {};",
    )
    .replace(/_Static_assert\([^;]+;/u, "");
  const controlIdentity = native(body("socket_control_identity"))
    .replace(
      "let token = NULL; TOKEN_STATISTICS statistics; let used = 0, container = 0, status = 0;",
      "const token = {value:null}, statistics = {}, used = {value:0}, container = {value:0}; let status = 0;",
    )
    .replace(
      "FILETIME born, exited, kernel, user;",
      "const born = {}, exited = {}, kernel = {}, user = {};",
    )
    .replaceAll("sizeof(statistics)", "56")
    .replaceAll("sizeof(container)", "4")
    .replaceAll(
      "GetTokenInformation(token,",
      "GetTokenInformation(token.value,",
    )
    .replaceAll("used !=", "used.value !=")
    .replaceAll("!!container", "!!container.value")
    .replace("CloseHandle(token)", "CloseHandle(token.value)");
  const controlProtocol = native(body("socket_control_protocol"))
    .replace("int size = sizeof(*actual);", "const size = {value:628};")
    .replace("size == sizeof(*actual)", "size.value == 628");
  const transferRefusal = native(body("socket_transfer_refusal"))
    .replaceAll("const char *", "const ")
    .replace("line + offset", "line.subarray(offset)");
  const controlClose = native(body("socket_control_close")).replaceAll(
    "*status",
    "result[index]",
  );
  const controlReceive = native(body("socket_control_receive"))
    .replace(
      "let offset = sizeof(SOCKET_CONTROL_PREFIX) - 1, end = size - 1;",
      "let offset = SOCKET_CONTROL_PREFIX.length, end = size - 1;",
    )
    .replace(
      "struct socket_control_offer control = {0};",
      "const control = {error:0,offer:{target:{},source:{},protocol:{}}}, carrier = Buffer.alloc(1312);",
    )
    .replaceAll("controlCarrier[i]", "carrier[i]")
    .replace(
      "invariant(control.error",
      "decodeControl(carrier, control); invariant(control.error",
    )
    .replace(
      "let status[11] = {-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1};",
      "const status = Array(11).fill(-1);",
    )
    .replace(
      "struct socket_target actualTarget = {0}; WSAPROTOCOL_INFOW actual = {0};",
      "const actualTarget = {}, actual = {};",
    )
    .replace(
      "let exclusive = FALSE; int length = sizeof(exclusive);",
      "const exclusive = {value:false}, length = {value:4};",
    )
    .replace("sizeof(exclusive)", "4")
    .replace("length == 4 && exclusive", "length.value == 4 && exclusive.value")
    .replace("int result", "const result")
    .replace("let sent = 0;", "const sent = {value:0};")
    .replaceAll("sent ==", "sent.value ==")
    .replaceAll(
      "socket_control_close(imported, status[7])",
      "socket_control_close(imported, status, 7)",
    );
  const controls = native(body("socket_transfer_controls"))
    .replace("struct socket_target source = {0};", "const source = {};")
    .replace(
      "struct socket_control_offer control = {0};",
      "const control = {error:0,offer:{target:{},source:{},protocol:{}}};",
    )
    .replace(
      "let status[11] = {-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1};",
      "const status = Array(11).fill(-1);",
    )
    .replace(
      "WSAPROTOCOL_INFOW actual = {0}, selection = original.source; struct socket_target current = {0}; u_long nonblocking = 1;",
      "const actual = {}, selection = structuredClone(original.source), current = {}, nonblocking = {value:1};",
    )
    .replaceAll("sizeof(source)", "40")
    .replaceAll("sizeof(exclusive)", "4")
    .replaceAll("controlCarrier[i]", "controlByte(control, i)")
    .replace(
      "struct diagnosis acknowledgment = {0};",
      "const acknowledgment = {};",
    )
    .replace("tcp_ack(86", "await tcp_ack(86")
    .replaceAll(
      "socket_control_close(imported, status[7])",
      "socket_control_close(imported, status, 7)",
    )
    .replaceAll(
      "socket_control_close(socket, status[8])",
      "socket_control_close(socket, status, 8)",
    )
    // Preserve the C single-exit cleanup when translating goto to a scoped loop.
    .replaceAll("goto closed;", "break;")
    .replace("status[0] = identity;", "do { status[0] = identity;")
    .replace("closed:", "} while (false);");
  const tcp = source.slice(
    source.indexOf("static int tcp_connection("),
    source.indexOf("static int connection("),
  );
  const close = native(
    tcp.slice(tcp.indexOf("done:") + 5, tcp.lastIndexOf("}")),
  )
    .replace(
      "struct diagnosis acknowledgment = {0};",
      "const acknowledgment = {};",
    )
    .replace(/#(?:ifndef NATIVE_COMMAND_EXPERIMENT|endif)/gu, "")
    .replace(/\bint\b/gu, "let")
    .replaceAll("!tcp_ack(", "!await tcp_ack(");
  const script = new Script(`
    function socket_source_ready(problem) {${native(body("socket_source_ready"))}}
    function socket_protocol(value) {${protocol}}
    function socket_protocol_same(a,b) {${native(body("socket_protocol_same"))}}
    function socket_target_binding(expected) {${binding}}
    function socket_status(value) {${native(body("socket_status"))}}
    function socket_token_observe(process,value,effective) {${tokenRead}}
    function socket_token_write(value) {${tokenWrite}}
    function socket_transfer_observe(socket,offer,error) {${observation}}
    function socket_transfer_refusal(line,size) {${transferRefusal}}
    function socket_control_identity(value,appContainer) {${controlIdentity}}
    function socket_control_protocol(socket,expected,actual) {${controlProtocol}}
    function socket_control_close(socket,result,index) {${controlClose}}
    function socket_control_write(kind,side,target,status) {${native(body("socket_control_write"))}}
    function socket_control_receive(line,size) {${controlReceive}}
    async function socket_transfer_controls(original,error,end) {${controls}}
    async function refusedExport(socket,end,offer) {${refusedExport}}
    function wfp_prepare() { throw new Error("Original preparation cannot follow a refused export"); }
    function wfp_close() {${native(body("wfp_close"))}}
    async function closeSource() {${close}}
    async function runSource() {
      const offer = {target:structuredClone(wfpTarget), source:structuredClone(wfpProtocol), protocol:{}};
      puts(); await tcp_ack(68,end,problem);
      try { await refusedExport(socket,end,offer); }
      catch (error) { if (error.message !== "Native refusal") throw error; }
      problem = {operation:"observer-transfer",domain:"win32",value:10022};
      return closeSource();
    }
    ({prepare:wfp_prepare, control:socket_control_receive, refusal:socket_transfer_refusal, run:runSource, close:wfp_close, bind:socket_target_binding});
  `);
  const loopStart = driver.indexOf("for (const operation of OPERATIONS)");
  const loop = driver.slice(
    loopStart,
    driver.indexOf("complete = true;", loopStart),
  );
  const protocolFields = [
    ["dwServiceFlags1", 0],
    ["dwServiceFlags2", 4],
    ["dwServiceFlags3", 8],
    ["dwServiceFlags4", 12],
    ["dwProviderFlags", 16],
    ["dwCatalogEntryId", 36],
    ["iVersion", 72],
    ["iAddressFamily", 76],
    ["iMaxSockAddr", 80],
    ["iMinSockAddr", 84],
    ["iSocketType", 88],
    ["iProtocol", 92],
    ["iProtocolMaxOffset", 96],
    ["iNetworkByteOrder", 100],
    ["iSecurityScheme", 104],
    ["dwMessageSize", 108],
  ];
  for (const [mode, fault] of ["read", "edit"].flatMap((mode) =>
    [
      "10022",
      "no-control-receiver",
      "self-open",
      "self-close",
      "destination-open",
      "destination-time",
      "token-open",
      "token-read",
      "token-short",
      "restricted-read",
      "effective-token",
      "qos-unavailable",
      "qos-short",
      "exclusive-unavailable",
      "exclusive-short",
      "diagnostic-close",
      "diagnostic-output",
      "diagnostic-form",
      "diagnostic-private",
      "diagnostic-qos",
      "diagnostic-effective",
      "10022-close",
      "control-create-self",
      "control-create-destination",
      "control-duplicate-self",
      "control-duplicate-destination",
      "control-duplicate-both",
      "control-import-self",
      "control-import-destination",
      "control-provider",
      "control-close-self",
      "control-close-self-import",
      "control-close-destination",
      "control-close-destination-import",
      "control-ack",
      "control-replay",
      "control-short",
      "control-budget",
      "control-arrival-late",
      "control-import-late",
      "control-deadline-extended",
      "control-target-birth",
      "control-target-token",
      "control-observation-form",
      "control-observation-replay",
      "control-observation-bound",
      "control-observation-target",
    ].map((fault) => [mode, fault]),
  )) {
    const f = tcpDenialFixture(),
      order = [],
      primary = [],
      launcherPrimary = [],
      optionObservations = [],
      cleanup = [],
      saved = new Map(),
      acknowledgments = new Map();
    let lastError = 0,
      rows = 0,
      ended = false,
      ready = false,
      sourceTask,
      offerCarrier,
      output = "",
      launcherFailed = false,
      inLauncher = false,
      creations = 0,
      controlCarrier,
      controlAcknowledged = false,
      effectiveRead = false,
      clock = 10;
    const failsTransfer = true;
    const incompleteObservation = [
      "diagnostic-output",
      "diagnostic-form",
      "diagnostic-private",
      "diagnostic-qos",
      "diagnostic-effective",
      "control-observation-form",
      "control-observation-replay",
      "control-observation-bound",
      "control-observation-target",
    ].includes(fault);
    const protocol = {
      iAddressFamily: 2,
      iSocketType: 1,
      iProtocol: 6,
      ProviderId: { hex: "a".repeat(32) },
      dwCatalogEntryId: 7,
      ProtocolChain: { ChainLen: 1, ChainEntries: [7, 0, 0, 0, 0, 0, 0] },
      dwServiceFlags1: 0x20000,
      dwServiceFlags2: 0,
      dwServiceFlags3: 0,
      dwServiceFlags4: 0,
      dwProviderFlags: 0,
      iVersion: 2,
      iMinSockAddr: 16,
      iMaxSockAddr: 16,
      iProtocolMaxOffset: 0,
      iNetworkByteOrder: 0,
      iSecurityScheme: 0,
      dwMessageSize: 0,
    };
    const target = {
      version: 1,
      pid: 41,
      birth: 90,
      token: { HighPart: 0, LowPart: 3 },
      authentication: { HighPart: 0, LowPart: 2 },
      modified: { HighPart: 0, LowPart: 4 },
    };
    const targetBytes = Buffer.alloc(40);
    targetBytes.writeUInt32LE(1);
    targetBytes.writeUInt32LE(41, 4);
    targetBytes.writeBigUInt64LE(90n, 8);
    targetBytes.writeUInt32LE(3, 16);
    targetBytes.writeUInt32LE(2, 24);
    targetBytes.writeUInt32LE(4, 32);
    const protocolBytes = (value) => {
      const bytes = Buffer.alloc(628);
      if (!value.ProviderId) return bytes;
      for (const [key, at] of protocolFields)
        bytes.writeUInt32LE(value[key], at);
      Buffer.from(value.ProviderId.hex, "hex").copy(bytes, 20);
      bytes.writeInt32LE(value.ProtocolChain.ChainLen, 40);
      value.ProtocolChain.ChainEntries.forEach((entry, index) =>
        bytes.writeUInt32LE(entry, 44 + 4 * index),
      );
      return bytes;
    };
    const decodeProtocol = (bytes) => {
      if (bytes.every((byte) => byte === 0)) return {};
      const value = {};
      for (const [key, at] of protocolFields)
        value[key] = bytes.readUInt32LE(at);
      value.ProviderId = { hex: bytes.subarray(20, 36).toString("hex") };
      value.ProtocolChain = {
        ChainLen: bytes.readInt32LE(40),
        ChainEntries: Array.from({ length: 7 }, (_, index) =>
          bytes.readUInt32LE(44 + 4 * index),
        ),
      };
      return value;
    };
    const decodeTarget = (bytes, value) => {
      Object.assign(value, {
        version: bytes.readUInt32LE(0),
        pid: bytes.readUInt32LE(4),
        birth: Number(bytes.readBigUInt64LE(8)),
      });
      for (const [key, at] of [
        ["token", 16],
        ["authentication", 24],
        ["modified", 32],
      ])
        value[key] = {
          HighPart: bytes.readInt32LE(at + 4),
          LowPart: bytes.readUInt32LE(at),
        };
    };
    const format = (text, values) => {
      let at = 0;
      return text.replace(
        /%(?:0(2|8))?(?:ll|l)?([xuds])/gu,
        (_match, width, kind) => {
          const value = values[at++];
          return kind === "x"
            ? Number(value)
                .toString(16)
                .padStart(Number(width ?? 0), "0")
            : String(value);
        },
      );
    };
    const write = (stream, text) => {
      if (stream === context.stdout) return text.length;
      output += text;
      const diagnosticWrite = output.startsWith(
        context.TCP_PREFIX + " transfer=",
      );
      for (let end; (end = output.indexOf("\n")) >= 0;) {
        const line = output.slice(0, end + 1);
        if (line.startsWith("native-windows-socket-input:"))
          optionObservations.push(line);
        output = output.slice(end + 1);
        if (line.startsWith(context.SOCKET_PREFIX)) {
          const input = Buffer.from(line);
          inLauncher = true;
          try {
            nativeCalls.prepare(input, input.length);
          } catch (error) {
            if (error.message !== "Native refusal") throw error;
            launcherFailed = true;
          } finally {
            inLauncher = false;
          }
        } else if (line.startsWith(context.SOCKET_CONTROL_PREFIX)) {
          let input = Buffer.from(line);
          if (fault === "control-arrival-late") clock = 5000;
          if (fault === "control-short")
            input = input.subarray(0, input.length - 2);
          inLauncher = true;
          try {
            nativeCalls.control(input, input.length);
            if (fault === "control-replay")
              nativeCalls.control(input, input.length);
          } catch (error) {
            if (error.message !== "Native refusal") throw error;
            launcherFailed = true;
          } finally {
            inLauncher = false;
          }
        } else if (line.startsWith(context.TCP_PREFIX + " transfer=")) {
          inLauncher = true;
          try {
            nativeCalls.refusal(Buffer.from(line), Buffer.byteLength(line));
          } finally {
            inLauncher = false;
          }
          let observed = line;
          if (fault === "diagnostic-output")
            observed = context.TCP_PREFIX + " incomplete\n";
          if (fault === "diagnostic-form")
            observed = context.TCP_PREFIX + " transfer={\n";
          if (fault === "diagnostic-private") {
            const value = JSON.parse(
              line.slice((context.TCP_PREFIX + " transfer=").length),
            );
            value.provider += "00000000";
            observed =
              context.TCP_PREFIX + " transfer=" + JSON.stringify(value) + "\n";
          }
          if (["diagnostic-qos", "diagnostic-effective"].includes(fault)) {
            const value = JSON.parse(
              line.slice((context.TCP_PREFIX + " transfer=").length),
            );
            if (fault === "diagnostic-qos")
              value.qos = [0, 80, null, null, null];
            else value.source.effective.extra = true;
            observed =
              context.TCP_PREFIX + " transfer=" + JSON.stringify(value) + "\n";
          }
          transport.child.stderr.write(observed);
        } else if (line.startsWith(context.TCP_PREFIX + " control=")) {
          let observed = line;
          if (fault === "control-observation-form")
            observed = context.TCP_PREFIX + " control=[0]\n";
          if (fault === "control-observation-bound")
            observed =
              context.TCP_PREFIX + " control=" + "x".repeat(2048) + "\n";
          if (fault === "control-observation-target") {
            const value = JSON.parse(
              line.slice((context.TCP_PREFIX + " control=").length),
            );
            value[2]++;
            observed =
              context.TCP_PREFIX + " control=" + JSON.stringify(value) + "\n";
          }
          transport.child.stderr.write(observed);
          if (fault === "control-observation-replay")
            transport.child.stderr.write(observed);
        } else transport.child.stderr.write(line);
      }
      return fault === "diagnostic-output" && diagnosticWrite
        ? -1
        : text.length;
    };
    const context = {
      Buffer,
      transport: { child: { hProcess: 43 } },
      role: fault === "no-control-receiver" ? "launch" : "bundle",
      workspaceRole: mode,
      socket: 17,
      end: 5000,
      started: 1,
      attempted: false,
      transferred: false,
      problem: {},
      nativeReceipt: false,
      transferState: { value: false },
      wfpTarget: target,
      wfpTargetReady: { value: 1 },
      wfpTransferReady: { value: 0 },
      wfpDuplicateReleased: { value: 0 },
      wfpControlSeen: { value: 0 },
      wfpTransferError: 0,
      wfpPreparedAt: 0,
      wfpEngine: null,
      wfpToken: null,
      wfpCleanupFailed: false,
      wfpProtocol: structuredClone(protocol),
      wfpChildPid: 43,
      wfpChildBirth: 100,
      TRUE: true,
      FALSE: false,
      NULL: null,
      ERROR_SUCCESS: 0,
      ERROR_NO_TOKEN: 1008,
      ERROR_INVALID_DATA: 13,
      ERROR_WRITE_FAULT: 29,
      INVALID_SOCKET: -1,
      SOCKET_ERROR: -1,
      FROM_PROTOCOL_INFO: -1,
      AF_INET: 2,
      SOCK_STREAM: 1,
      IPPROTO_TCP: 6,
      MAX_PROTOCOL_CHAIN: 7,
      MAXDWORD: 0xffffffff,
      SOL_SOCKET: 0xffff,
      SO_PROTOCOL_INFOW: 0x2005,
      SO_EXCLUSIVEADDRUSE: 0xfffffffb,
      FIONBIO: 0x8004667e,
      WAIT_TIMEOUT: 258,
      WAIT_FAILED: 0xffffffff,
      TOKEN_QUERY: 8,
      TokenStatistics: 10,
      TokenImpersonation: 2,
      TokenIsAppContainer: 29,
      PROCESS_QUERY_LIMITED_INFORMATION: 0x1000,
      PROCESS_DUP_HANDLE: 0x40,
      SOCKET_PREFIX: "native-windows-socket: ",
      SOCKET_CONTROL_PREFIX: "native-windows-socket-control: ",
      TCP_PREFIX: "native-windows-tcp:",
      stdout: {},
      stderr: {},
      socketVersion: 514,
      socketHighVersion: 514,
      decodeTarget,
      structuredClone,
      protocolBytes,
      tokenObservation: () => ({
        status: [-1, -1, -1, -1, -1],
        statistics: {},
        container: 0,
        statisticsRead: false,
        containerRead: false,
        restricted: false,
      }),
      offerByte(offer, i) {
        if (!i)
          offerCarrier = Buffer.concat([
            targetBytes,
            protocolBytes(offer.source),
            protocolBytes(offer.protocol),
          ]);
        return offerCarrier[i];
      },
      decodeOffer(bytes, offer) {
        decodeTarget(bytes.subarray(0, 40), offer.target);
        offer.source = decodeProtocol(bytes.subarray(40, 668));
        offer.protocol = decodeProtocol(bytes.subarray(668, 1296));
      },
      controlByte(control, i) {
        if (!i) {
          const header = Buffer.alloc(16);
          header.writeUInt32LE(control.error);
          assert.equal(control.end, 5000);
          header.writeBigUInt64LE(
            BigInt(fault === "control-deadline-extended" ? 50001 : control.end),
            8,
          );
          const destination = Buffer.alloc(40);
          destination.writeUInt32LE(1);
          destination.writeUInt32LE(control.offer.target.pid, 4);
          destination.writeBigUInt64LE(BigInt(control.offer.target.birth), 8);
          for (const [key, at] of [
            ["token", 16],
            ["authentication", 24],
            ["modified", 32],
          ])
            destination.writeUInt32LE(control.offer.target[key].LowPart, at);
          controlCarrier = Buffer.concat([
            header,
            destination,
            protocolBytes(control.offer.source),
            protocolBytes(control.offer.protocol),
          ]);
        }
        return controlCarrier[i];
      },
      decodeControl(bytes, control) {
        control.error = bytes.readUInt32LE();
        control.end = Number(bytes.readBigUInt64LE(8));
        context.decodeOffer(bytes.subarray(16), control.offer);
      },
      memcmp: (a, b, size) =>
        Buffer.isBuffer(a) && typeof b === "string"
          ? Buffer.compare(
              a.subarray(0, size),
              Buffer.from(b).subarray(0, size),
            )
          : observationDigest(a) === observationDigest(b)
            ? 0
            : 1,
      strlen: (value) => value.length,
      wcscmp: (a, b) => (a === b ? 0 : 1),
      wcsspn: (text, allowed) =>
        text.every((c) => allowed.includes(String.fromCharCode(c)))
          ? text.length
          : 0,
      GetEnvironmentVariableW(key, value, capacity) {
        assert.equal(key, "NATIVE_FEASIBILITY_SOCKET_OWNER");
        assert.equal(capacity, 81);
        value.push(
          ...[...targetBytes.toString("hex")].map((c) => c.charCodeAt(0)),
        );
        return value.length;
      },
      socket_target: () => ({
        ...structuredClone(target),
        ...(ready && fault === "birth"
          ? { birth: 91 }
          : ready && fault === "token"
            ? { token: { HighPart: 0, LowPart: 5 } }
            : {}),
      }),
      GetCurrentProcess: () => (inLauncher ? 41 : 43),
      GetCurrentProcessId: () => (inLauncher ? 41 : 43),
      GetCurrentThread: () => 42,
      OpenThreadToken(thread, access, self, token) {
        assert.deepEqual([thread, access, self], [42, 8, true]);
        if (fault === "effective-token" && !effectiveRead) {
          effectiveRead = true;
          token.value = 144;
          return true;
        }
        lastError = 1008;
        return false;
      },
      SIO_GET_QOS: 0xc8000007,
      WSAIoctl(
        socket,
        command,
        input,
        inputSize,
        qos,
        size,
        used,
        overlapped,
        completion,
      ) {
        assert.deepEqual(
          [socket, command, input, inputSize, size, overlapped, completion],
          [17, 0xc8000007, null, 0, 80, null, null],
        );
        used.value = fault === "qos-short" ? 16 : 80;
        qos.SendingFlowspec.ServiceType = 1;
        qos.ReceivingFlowspec.ServiceType = 1;
        qos.ProviderSpecific.len = 0;
        lastError = 10045;
        return fault === "qos-unavailable" ? -1 : 0;
      },
      WaitForSingleObject(process) {
        assert.equal(process, 41);
        return 258;
      },
      GetTickCount64: () => {
        if (fault === "control-budget" && creations) clock = 5000;
        return clock;
      },
      SetLastError(value) {
        lastError = value;
      },
      GetLastError: () => lastError,
      WSAGetLastError: () => lastError,
      InterlockedCompareExchange(value, exchange, comparand) {
        const before = value.value;
        if (before === comparand) value.value = exchange;
        return before;
      },
      InterlockedExchange(value, exchange) {
        value.value = exchange;
      },
      invariant(ok, operation) {
        if (!ok) {
          context.remember(operation, "invariant", 0);
          context.failure();
        }
      },
      win32_check(ok, operation) {
        if (!ok) {
          context.remember(operation, "win32", lastError);
          context.failure();
        }
      },
      wfp_binding: () => order.push("child-binding"),
      remember(...value) {
        if (inLauncher && !launcherPrimary.length) launcherPrimary.push(value);
        if (!primary.length) primary.push(value);
      },
      cleanup_error: (...value) => cleanup.push(value),
      failure: () => {
        throw new Error("Native refusal");
      },
      AcquireSRWLockExclusive: () => {},
      ReleaseSRWLockExclusive: () => {},
      diagnosticOutputLock: {},
      transportLock: {},
      getsockopt(socket, level, option, actual, size) {
        assert.ok([17, 73, 81, 83, 91, 93].includes(socket));
        assert.equal(level, 0xffff);
        if (option === context.SO_EXCLUSIVEADDRUSE) {
          assert.ok([17, 93].includes(socket));
          if (socket === 17) {
            assert.deepEqual(primary[0], ["observer-transfer", "win32", 10022]);
            assert.equal(size.value, 4);
            size.value = fault === "exclusive-short" ? 1 : 4;
            lastError = 10042;
            if (fault === "exclusive-unavailable") return -1;
          }
          actual.value = socket === 17 ? 1 : true;
          return 0;
        }
        assert.equal(option, 0x2005);
        assert.equal(size.value, 628);
        Object.assign(actual, structuredClone(protocol));
        if (socket === 81 && fault === "control-provider")
          actual.dwCatalogEntryId++;
        return 0;
      },
      ioctlsocket(socket, command, value) {
        assert.ok([81, 91].includes(socket));
        assert.deepEqual([command, value.value], [context.FIONBIO, 1]);
        order.push(`nonblocking:${socket}`);
        return 0;
      },
      setsockopt(socket, level, option, exclusive, size) {
        assert.ok([81, 91].includes(socket));
        assert.deepEqual(
          [level, option, exclusive, size],
          [0xffff, context.SO_EXCLUSIVEADDRUSE, true, 4],
        );
        order.push(`exclusive:${socket}`);
        return 0;
      },
      WSADuplicateSocketW(socket, pid, ticket) {
        if (socket !== 17) {
          assert.deepEqual([socket, pid], socket === 81 ? [81, 43] : [91, 41]);
          assert.ok(
            order.includes(`nonblocking:${socket}`) &&
              order.includes(`exclusive:${socket}`),
          );
          order.push(`control-duplicate:${socket}`);
          if (fault === "control-duplicate-both") {
            lastError = 10022;
            return -1;
          }
          if (
            fault ===
            `control-duplicate-${socket === 81 ? "self" : "destination"}`
          ) {
            lastError = socket === 81 ? 10045 : 10022;
            return -1;
          }
          Object.assign(ticket, structuredClone(protocol));
          return 0;
        }
        assert.deepEqual([socket, pid], [17, 41]);
        assert.ok(saved.has(`${mode}-tcp-transfer`));
        order.push("duplicate");
        if (failsTransfer) {
          lastError = 10022;
          return -1;
        }
        Object.assign(ticket, structuredClone(protocol));
        return 0;
      },
      WSASocketW(af, type, ip, ticket, group, flags) {
        if (af === 2) {
          assert.deepEqual([af, type, ip, group, flags], [2, 1, 6, 0, 0]);
          assert.equal(ticket.dwCatalogEntryId, 7);
          const kind = creations++ ? "destination" : "self";
          order.push(`control-create:${kind}`);
          if (fault === `control-create-${kind}`) {
            lastError = 10055;
            return -1;
          }
          return kind === "self" ? 81 : 91;
        }
        assert.deepEqual([af, type, ip, group, flags], [-1, -1, -1, 0, 0]);
        assert.equal(ticket.dwCatalogEntryId, 7);
        if (failsTransfer) {
          const kind = inLauncher ? "destination" : "self";
          order.push(`control-import:${kind}`);
          if (fault === `control-import-${kind}`) {
            lastError = 10045;
            return -1;
          }
          return inLauncher ? 93 : 83;
        }
        order.push("import");
        if (fault === "import") {
          lastError = 10022;
          return -1;
        }
        return 73;
      },
      DuplicateHandle: () =>
        assert.fail("Application socket copying is forbidden"),
      OpenProcess(access, inherit, pid) {
        if (access === context.PROCESS_DUP_HANDLE) {
          assert.deepEqual([access, inherit, pid], [0x40, false, 43]);
          if (!primary.length) {
            assert.equal(inLauncher, false);
            order.push("source-open");
            return 72;
          }
          assert.deepEqual(primary[0], ["observer-transfer", "win32", 10022]);
          assert.equal(
            inLauncher,
            false,
            "the original effective token opens only itself",
          );
          order.push("self-open");
          lastError = 5;
          return fault === "self-open" ? null : 71;
        }
        assert.deepEqual([access, inherit, pid], [0x1000, false, 41]);
        assert.deepEqual(primary[0], ["observer-transfer", "win32", 10022]);
        order.push("destination-open");
        lastError = 5;
        return fault === "destination-open" ? null : 61;
      },
      GetProcessTimes(process, born) {
        assert.ok([41, 43, 61].includes(process));
        lastError = 6;
        born.value = process === 43 ? 100 : 90;
        if (process === 41 && creations && fault === "control-target-birth")
          born.value++;
        return fault !== "destination-time";
      },
      wfp_time: (value) => value.value,
      OpenProcessToken(process, access, token) {
        assert.ok([41, 43, 61].includes(process));
        assert.equal(access, 8);
        order.push(`token-open:${process}`);
        lastError = 5;
        if (fault === "token-open") return false;
        token.value = process + 100;
        return true;
      },
      GetTokenInformation(token, kind, value, size, used) {
        assert.ok([141, 143, 144, 161].includes(token));
        if (token === 141 && fault === "control-import-late") clock = 5000;
        used.value = size;
        lastError = 5;
        if (fault === "token-read") return false;
        if (kind === 10) {
          Object.assign(value, {
            TokenId: { HighPart: 0, LowPart: token === 143 ? 5 : 3 },
            AuthenticationId: { HighPart: 0, LowPart: 2 },
            ModifiedId: { HighPart: 0, LowPart: 4 },
            TokenType: token === 144 ? 2 : 1,
            ImpersonationLevel: 2,
          });
          if (token === 141 && creations && fault === "control-target-token")
            value.ModifiedId.LowPart++;
          if (fault === "token-short") used.value = 0;
        } else {
          assert.equal(kind, 29);
          if (Object.hasOwn(value, "value"))
            value.value =
              token === 143 && fault !== "no-control-receiver" ? 1 : 0;
          else
            value.container =
              token === 143 && fault !== "no-control-receiver" ? 1 : 0;
        }
        return true;
      },
      IsTokenRestricted(token) {
        assert.equal(lastError, 0);
        if (fault === "restricted-read") {
          lastError = 5;
          return false;
        }
        return token === 143;
      },
      CloseHandle(handle) {
        if (handle === 72) {
          assert.equal(inLauncher, false);
          assert.equal(primary.length, 0);
          order.push("source-close");
          return true;
        }
        assert.ok([61, 71, 141, 143, 144, 161].includes(handle));
        order.push(`handle-close:${handle}`);
        lastError = 6;
        return (
          fault !== "diagnostic-close" &&
          !(handle === 71 && fault === "self-close")
        );
      },
      closesocket(socket) {
        assert.ok([17, 73, 81, 83, 91, 93].includes(socket));
        order.push(`socket-close:${socket}`);
        lastError = 10038;
        return (socket === 17 && fault === "10022-close") ||
          fault ===
            {
              81: "control-close-self",
              83: "control-close-self-import",
              91: "control-close-destination",
              93: "control-close-destination-import",
            }[socket]
          ? -1
          : 0;
      },
      WriteFile(pipe, value, length, sent) {
        assert.equal(value, "V");
        assert.equal(length, 1);
        order.push("control-ack-write");
        sent.value = 1;
        controlAcknowledged = fault !== "control-ack";
        return true;
      },
      FwpmEngineClose0: () =>
        assert.fail("No engine acquired in this boundary"),
      release_handle: () => true,
      fprintf: (stream, text, ...values) => write(stream, format(text, values)),
      fputs: (text, stream) => write(stream, text),
      fputc: (value, stream) => write(stream, String.fromCharCode(value)),
      fflush: () => {},
      ferror: () => false,
      printf: () => {},
      socket_transfer_identity: () => {},
      puts() {
        context.wfpTransferReady.value = 1;
        ready = true;
        order.push("ready");
        emit(f.transfer);
      },
      observerReady: () => emit(f.prepared),
      tcp_observe: (api, phase, value) =>
        write(
          context.stderr,
          `${context.TCP_PREFIX} api=${api} phase=${phase} value=${value}\n`,
        ),
      wfp_tuple() {
        if (context.transferred && !launcherFailed) {
          nativeCalls.close();
          emit(f.attribution);
        }
      },
      tcp_ack: async (expected, deadline, problem) => {
        expected = String.fromCharCode(expected);
        if (expected === "V") {
          assert.equal(deadline, 5000);
          order.push("control-ack-read");
          const accepted = controlAcknowledged && clock < deadline;
          if (!accepted)
            Object.assign(problem, {
              operation: "tcp-deadline",
              domain: "invariant",
              value: 0,
            });
          return accepted;
        }
        assert.equal(deadline, expected === "U" ? 15000 : 5000);
        const accepted = launcherFailed
          ? false
          : await new Promise((resolve) =>
              acknowledgments.set(expected, resolve),
            );
        if (!accepted)
          Object.assign(problem, {
            operation: "ack-read",
            domain: "win32",
            value: 109,
          });
        return accepted;
      },
    };
    const nativeCalls = script.runInNewContext(context);
    const emit = (value) =>
      transport.child.stdout.write(JSON.stringify(value) + "\n");
    const stopNative = () => {
      if (ended) return;
      ended = true;
      nativeCalls.close();
      const [operation, domain, value] = primary[0];
      transport.child.stderr.write(windowsDiagnostic(operation, domain, value));
      if (cleanup.length) {
        const [operation, domain, value] = cleanup[0];
        transport.child.stderr.write(
          `native-windows-cleanup: operation=${operation} domain=${domain} value=${value}\n`,
        );
      }
      transport.close(126);
    };
    const transport = windowsSessionFixture(
      windowsCallerEnvironment,
      () => {},
      undefined,
      true,
      {
        launchCase: mode,
        onSend(command) {
          order.push(command);
          if (command === "O") {
            for (const api of [
              "WSASocketW",
              "ioctlsocket",
              "setsockopt",
              "bind",
            ]) {
              context.tcp_observe(api, "enter", 0);
              context.tcp_observe(api, "complete", 0);
            }
            sourceTask = nativeCalls
              .run()
              .then((error) =>
                emit({ event: "completed", operation: "tcp", error }),
              )
              .catch((error) => {
                if (error.message !== "Native refusal") {
                  transport.child.emit("error", error);
                  return;
                }
                stopNative();
              });
            return;
          }
          if (command === "D") {
            inLauncher = true;
            try {
              nativeCalls.bind(target);
              context.wfpDuplicateReleased.value = 1;
            } catch (error) {
              assert.match(error.message, /Native refusal/u);
              acknowledgments.get("D")(false);
              return;
            } finally {
              inLauncher = false;
            }
          }
          assert.ok(acknowledgments.has(command), command);
          acknowledgments.get(command)(fault !== `ack-${command}`);
        },
      },
    );
    const caller = {
      OPERATIONS: ["tcp"],
      mode,
      run: { receipt: f.receipt, session: transport.session },
      tcpEndpoint: f.endpoint,
      operations: [],
      nextRun: async () => {
        const row = await transport.session.next();
        rows++;
        return row;
      },
      need: assert.ok,
      nativeException: () => {},
      assertWindowsFeasibilityTcpTransfer,
      assertWindowsFeasibilityTcpObserver,
      assertWindowsFeasibilityTcpDenial,
      observeWindowsFeasibilityWfp: async () => {},
      persist: async (name, value) => {
        order.push(name);
        saved.set(name, structuredClone(value));
      },
    };
    try {
      emit({ event: "attempt", operation: "tcp" });
      const execution = new Script(`(async()=>{${loop}})()`).runInNewContext(
        caller,
      );
      if (fault)
        await assert.rejects(execution, (error) => {
          const diagnostic = windowsFeasibilityDiagnostics(error.stderr);
          if (!diagnostic) throw error;
          assert.deepEqual(diagnostic.failure, {
            operation: primary[0][0],
            domain: primary[0][1],
            value: primary[0][2],
          });
          assert.deepEqual(
            diagnostic.cleanup,
            cleanup.length
              ? {
                  operation: cleanup[0][0],
                  domain: cleanup[0][1],
                  value: cleanup[0][2],
                }
              : null,
          );
          if (failsTransfer) {
            assert.deepEqual(primary[0], ["observer-transfer", "win32", 10022]);
            const observation = error.tcpObservation;
            assert.equal(
              observation.status,
              incompleteObservation ? "incomplete" : "complete",
            );
            if (!incompleteObservation) {
              assert.equal(observation.transfer.error, 10022);
              assert.deepEqual(observation.transfer.winsock, [514, 514]);
              assert.equal(observation.transfer.creationFlags, 0);
              assert.equal(
                observation.transfer.source.effective.status[0],
                fault === "effective-token" ? 0 : 1008,
              );
              if (fault === "effective-token")
                assert.deepEqual(
                  observation.transfer.source.effective.identity.slice(3),
                  [2, 2],
                );
              assert.deepEqual(
                observation.transfer.qos,
                fault === "qos-unavailable"
                  ? [10045, null, null, null, null]
                  : fault === "qos-short"
                    ? [0, 16, null, null, null]
                    : [0, 80, 1, 1, 0],
              );
              assert.equal(observation.transfer.destination.access, 0x1000);
              assert.equal(
                observation.transfer.provider,
                protocolBytes(protocol).subarray(0, 112).toString("hex"),
              );
              if (fault === "destination-open")
                assert.deepEqual(observation.transfer.destination.status, [
                  5,
                  null,
                  null,
                ]);
              if (fault === "destination-time")
                assert.equal(observation.transfer.destination.birth, null);
              if (["token-open", "token-read", "token-short"].includes(fault))
                assert.equal(observation.transfer.source.token.identity, null);
              if (fault === "restricted-read") {
                assert.equal(
                  observation.transfer.source.token.restricted,
                  null,
                );
                assert.deepEqual(
                  observation.transfer.source.token.status,
                  [0, 0, 0, 5, 0],
                );
              }
              if (fault === "diagnostic-close")
                assert.deepEqual(
                  observation.transfer.source.token.status,
                  [0, 0, 0, 0, 6],
                );
            }
          }
          return true;
        });
      else await execution;
      await sourceTask;
      assert.equal(caller.operations.length, fault ? 0 : 1);
      assert.equal(
        order.filter((value) => value === "duplicate").length,
        ["birth", "token", "ack-D"].includes(fault) ? 0 : 1,
      );
      assert.equal(
        order.filter((value) => value === "socket-close:17").length,
        1,
      );
      if (failsTransfer) {
        assert.equal(optionObservations.length, 2);
        assert.match(
          optionObservations[0],
          /caller=wfp_transfer api=WSADuplicateSocketW error=10022 option=SO_EXCLUSIVEADDRUSE/u,
        );
        assert.ok(
          optionObservations[0].includes(
            fault === "exclusive-unavailable"
              ? "status=10042 size=unavailable value=unavailable"
              : fault === "exclusive-short"
                ? "status=0 size=1 value=unavailable"
                : "status=0 size=4 value=1",
          ),
        );
        assert.equal(
          optionObservations[1],
          `native-windows-socket-input: caller=wfp_transfer api=OpenProcess original-error=10022 pid=43 access=64 status=${fault === "self-open" ? 5 : 0} close=${fault === "self-open" ? "null" : ["self-close", "diagnostic-close"].includes(fault) ? 6 : 0}\n`,
        );
        assert.equal(order.filter((value) => value === "self-open").length, 1);
        assert.equal(
          order.filter((value) => value === "handle-close:71").length,
          fault === "self-open" ? 0 : 1,
        );
        if (fault === "self-close")
          assert.deepEqual(cleanup[0], [
            "observer-diagnostic-process-close",
            "win32",
            6,
          ]);
        assert.equal(order.includes("import"), false);
        assert.equal(context.attempted, false);
        assert.equal(saved.has(`${mode}-tcp-intent`), false);
        assert.equal(context.wfpPreparedAt, 0);
        assert.equal(order.includes("T") || order.includes("U"), false);
        for (const [socket, event, refusal] of [
          [81, "control-create:self", "control-create-self"],
          [91, "control-create:destination", "control-create-destination"],
          [83, "control-import:self", "control-import-self"],
          [93, "control-import:destination", "control-import-destination"],
        ])
          assert.equal(
            order.filter((value) => value === `socket-close:${socket}`).length,
            order.includes(event) && fault !== refusal ? 1 : 0,
            fault,
          );
        for (const kind of ["self", "destination"])
          assert.ok(
            order.filter((value) => value === `control-import:${kind}`)
              .length <= 1,
          );
        if (!incompleteObservation) {
          const captured = transport.session.tcpObservation.controls;
          const sources = captured.filter((row) => row.side === 0);
          const imported = captured.find((row) => row.side === 1);
          assert.deepEqual(
            sources.map((row) => row.kind),
            [0, 1],
          );
          assert.deepEqual(
            sources.map((row) => row.target.pid),
            [43, 41],
          );
          assert.ok(saved.has(`${mode}-tcp-controls`));
          assert.equal(saved.get(`${mode}-tcp-controls`).admission, false);
          if (fault === "10022") {
            assert.deepEqual(sources[0].status.slice(4, 9), [0, 0, 0, 0, 0]);
            assert.deepEqual(sources[1].status.slice(4), [
              0,
              0,
              null,
              null,
              0,
              0,
              0,
            ]);
            assert.deepEqual(imported.status.slice(6), [0, 0, null, 0, 0]);
          }
          if (fault === "no-control-receiver") {
            assert.equal(imported, undefined);
            assert.equal(sources[0].status[6], 0);
            assert.equal(sources[1].status[5], 0);
            assert.equal(sources[1].status[6], null);
            assert.equal(sources[1].status[9], 1);
            assert.ok(!order.includes("control-ack-write"));
            assert.ok(
              cleanup.some((entry) => entry[0] === "observer-control-ack"),
            );
          }
          if (fault === "control-duplicate-self") {
            assert.equal(sources[0].status[5], 10045);
            assert.equal(sources[1].status[5], 0);
          }
          if (fault === "control-duplicate-destination") {
            assert.equal(sources[0].status[6], 0);
            assert.equal(sources[1].status[5], 10022);
          }
          if (fault === "control-duplicate-both") {
            assert.equal(imported, undefined);
            for (const row of sources)
              assert.deepEqual(row.status.slice(5, 9), [10022, null, null, 0]);
          }
          if (fault === "control-import-self")
            assert.equal(sources[0].status[6], 10045);
          if (fault === "control-import-destination")
            assert.equal(imported.status[6], 10045);
          if (
            [
              "control-import-self",
              "control-import-destination",
              "control-target-birth",
              "control-target-token",
            ].includes(fault)
          )
            assert.ok(
              cleanup.some((entry) => entry[0] === "observer-control-import"),
            );
          if (
            ["control-target-birth", "control-target-token"].includes(fault)
          ) {
            assert.equal(imported.status[0], 13);
            assert.equal(imported.status[6], null);
            assert.equal(order.includes("control-import:destination"), false);
          }
          if (fault === "control-create-self")
            assert.equal(sources[0].status[1], 10055);
          if (fault === "control-create-destination")
            assert.equal(sources[1].status[1], 10055);
          if (fault === "control-provider") {
            assert.equal(sources[0].status[4], 13);
            assert.equal(sources[0].status[5], null);
            assert.equal(sources[1].status[5], 0);
          }
          if (
            [
              "control-ack",
              "control-short",
              "control-deadline-extended",
            ].includes(fault)
          ) {
            assert.equal(sources[0].status[6], 0);
            assert.equal(sources[1].status[9], 1);
            assert.ok(
              cleanup.some((entry) => entry[0] === "observer-control-ack"),
            );
          }
          assert.deepEqual(launcherPrimary[0], [
            "observer-transfer",
            "win32",
            10022,
          ]);
          if (fault.startsWith("control-close-"))
            assert.ok(
              cleanup.some(
                (entry) =>
                  entry[0] === "observer-control-close" && entry[2] === 10038,
              ),
            );
          if (fault === "control-budget") {
            assert.equal(creations, 1);
            assert.equal(sources[0].status[5], null);
            assert.equal(sources[1].status[1], null);
            assert.equal(sources[1].status[10], 258);
          }
          if (["control-arrival-late", "control-import-late"].includes(fault)) {
            assert.equal(imported.status[10], 258);
            assert.equal(imported.status[6], null);
            assert.equal(order.includes("control-import:destination"), false);
            assert.equal(sources[1].status[9], 1);
            assert.equal(sources[1].status[10], 258);
          }
          captured[0].status[0] = 123;
          assert.notEqual(
            transport.session.tcpObservation.controls[0].status[0],
            123,
          );
        }
      }
      if (fault === "diagnostic-close") {
        for (const handle of [61, 71, 143, 161])
          assert.ok(order.includes(`handle-close:${handle}`));
        assert.deepEqual(
          cleanup.map((value) => value[0]),
          [
            "observer-diagnostic-token-close",
            "observer-diagnostic-process-close",
            "observer-diagnostic-token-close",
            "observer-diagnostic-process-close",
            "observer-diagnostic-token-close",
          ],
        );
      }
      if (fault === "10022-close")
        assert.deepEqual(cleanup[0], ["tcp-close", "win32", 10038]);
      assert.ok(order.indexOf("ready") < order.indexOf(`${mode}-tcp-transfer`));
      if (order.includes("duplicate"))
        assert.ok(
          order.indexOf(`${mode}-tcp-transfer`) < order.indexOf("D") &&
            order.indexOf("D") < order.indexOf("duplicate"),
        );
    } finally {
      launcherFailed = true;
      for (const resolve of acknowledgments.values()) resolve(false);
      try {
        await sourceTask;
      } finally {
        try {
          nativeCalls.close();
        } finally {
          if (!ended) {
            transport.close(0);
            ended = true;
          }
          if (fault) await assert.rejects(transport.session.finish(rows));
          else await transport.session.finish(rows);
        }
      }
    }
  }
});

test("native launcher delivers each TCP phase once to the child's sole input reader", async () => {
  const source = await readFile(
    new URL("../ci/native/win32/feasibility-helper.c", import.meta.url),
    "utf8",
  );
  const body = (name) =>
    new RegExp(
      `static (?:BOOL|void) ${name}\\([^\\n]+\\) \\{([\\s\\S]*?)\\n\\}`,
      "u",
    ).exec(source)[1];
  const native = (text) =>
    text
      .replace(/\b(?:BOOL|DWORD|HANDLE|char)\b/gu, "let")
      .replaceAll('L"', '"')
      .replace(/&(?=[a-zA-Z_])/gu, "");
  const write = native(body("owner_write"))
    .replace("let sent = 0;", "const sent = {value:0};")
    .replace(/\bsent (==|!=) size/gu, "sent.value $1 size");
  const ack = native(body("tcp_ack"))
    .replace("let available = 0;", "const available = {value:0};")
    .replace(
      "let value = 0; let size = 0;",
      "const value = {value:0}, size = {value:0};",
    )
    .replace(/\bavailable(?=\)| >=| >|\s*\{)/gu, "available.value")
    .replace(
      "size != 1 || value != expected",
      "size.value != 1 || value.value != expected",
    )
    .replace(
      /\*problem = \(struct diagnosis\)\{"([a-z-]+)", "(win32|invariant)", ([^}]+)\};/gu,
      'Object.assign(problem,{operation:"$1",domain:"$2",value:$3});',
    );
  const closure = source.slice(
    source.indexOf(
      "  if (wfpPreparedAt && InterlockedCompareExchange(&wfpAttemptReleased",
    ),
    source.indexOf(
      "  AcquireSRWLockExclusive(&diagnosticOutputLock);",
      source.indexOf(
        "  if (wfpPreparedAt && InterlockedCompareExchange(&wfpAttemptReleased",
      ),
    ),
  );
  const preparation = body("wfp_prepare");
  const ready = preparation.slice(
    preparation.indexOf("  wfpOwnerBirth ="),
    preparation.indexOf("  fputs("),
  );
  const script = new Script(`function owner_write(bytes,size){${write}}
    function socket_command(command){${native(body("socket_command"))}}
    function tcp_ack(expected,end,problem){${ack}}
    function observer(){${native(ready)}}
    function closure(){${closure.replaceAll("&wfp", "wfp")}}
    ({send:socket_command,read:tcp_ack,observer,closure});`);
  for (const fault of [
    null,
    "write",
    "short",
    "owner-loss",
    "expired",
    "token",
  ]) {
    const bytes = [],
      writes = [],
      failures = [];
    const context = {
      TRUE: true,
      FALSE: false,
      NULL: null,
      transport: { write: 55 },
      transportLock: {},
      failing: { value: 0 },
      workspaceRole: "read",
      wfpTarget: {},
      wfpTransferEnd: 5000,
      wfpPreparedAt: 0,
      ...Object.fromEntries(
        [
          "wfpTargetReady",
          "wfpTransferReady",
          "wfpDuplicateReleased",
          "wfpObserverReady",
          "wfpAttemptReleased",
          "wfpClosureReady",
          "wfpClosureReleased",
        ].map((key) => [key, { value: 0 }]),
      ),
      strchr: (text, value) => text.includes(value),
      wcscmp: (a, b) => (a === b ? 0 : 1),
      GetTickCount64: () => (fault === "expired" ? 5000 : 10),
      GetLastError: () => 109,
      GetCurrentProcess: () => 41,
      creation: () => 90,
      wfp_now: () => 1100,
      GetStdHandle: () => 56,
      STD_INPUT_HANDLE: -10,
      InterlockedCompareExchange(slot, value, expected) {
        const before = slot.value;
        if (before === expected) slot.value = value;
        return before;
      },
      InterlockedExchange(slot, value) {
        slot.value = value;
      },
      AcquireSRWLockExclusive: () => {},
      ReleaseSRWLockExclusive: () => {},
      invariant(ok, operation) {
        if (!ok) throw new Error(operation);
      },
      remember: (...value) => failures.push(value),
      failure: () => {
        throw new Error("Native refusal");
      },
      socket_target_binding: () => {},
      socket_destination_binding() {
        if (fault === "token") throw new Error("observer-token");
      },
      // The actual exporter/packet is exercised above. Use its fixed size here
      // to join launcher delivery to the same stdin reader, not a TCP receipt.
      socket_export() {
        actualWrite("D" + "x".repeat(1392), 1393);
      },
      WriteFile(pipe, value, size, sent) {
        assert.equal(pipe, 55);
        assert.equal(value.length, size);
        writes.push(value[0]);
        sent.value = fault === "short" && value[0] === "D" ? 7 : size;
        bytes.push(...value.slice(0, sent.value));
        return !(fault === "write" && value[0] === "D");
      },
      PeekNamedPipe(pipe, buffer, size, used, available) {
        assert.equal(pipe, 56);
        available.value = bytes.length;
        return true;
      },
      ReadFile(pipe, value, size, used) {
        assert.deepEqual([pipe, size], [56, 1]);
        value.value = bytes.shift();
        used.value = 1;
        return true;
      },
      Sleep: () => assert.fail("No acknowledgment was delivered"),
    };
    const api = script.runInNewContext(context);
    const actualWrite = new Script(`(bytes,size)=>{${write}}`).runInNewContext(
      context,
    );
    assert.equal(api.send("G"), false);
    for (const command of ["D", "T", "U"])
      assert.throws(() => api.send(command), /observer-owner-once/u);
    assert.equal(api.send("O"), true);
    assert.equal(api.read("O", 5000, {}), fault !== "expired");
    assert.throws(() => api.send("O"), /observer-owner-once/u);
    context.wfpTransferReady.value = 1;
    if (fault === "owner-loss") context.failing.value = 1;
    if (["write", "short", "owner-loss"].includes(fault)) {
      assert.throws(() => api.send("D"), /Native refusal|owner-write-size/u);
      assert.equal(context.wfpDuplicateReleased.value, 1);
      const count = writes.length;
      assert.throws(() => api.send("D"), /observer-owner-once/u);
      assert.equal(writes.length, count, "A partial packet cannot be replayed");
      if (fault === "write")
        assert.deepEqual(failures[0], ["owner-write", "win32", 109]);
      if (fault === "short")
        assert.deepEqual(failures[0], ["owner-write-size", "invariant", 0]);
      continue;
    }
    api.send("D");
    if (fault !== "expired") {
      assert.equal(api.read("D", 5000, {}), true);
      assert.equal(bytes.splice(0).join(""), "x".repeat(1392));
    }
    assert.throws(() => api.send("T"), /observer-owner-once/u);
    api.closure();
    assert.equal(context.wfpClosureReady.value, 0);
    api.observer();
    if (["expired", "token"].includes(fault)) {
      assert.throws(() => api.send("T"), /tcp-deadline|observer-token/u);
      assert.equal(context.wfpAttemptReleased.value, 0);
      continue;
    }
    api.send("T");
    assert.equal(api.read("T", 5000, {}), true);
    assert.throws(() => api.send("T"), /observer-owner-once/u);
    assert.throws(() => api.send("U"), /observer-owner-once/u);
    api.closure();
    api.send("U");
    assert.equal(api.read("U", 15000, {}), true);
    assert.throws(() => api.send("U"), /observer-owner-once/u);
    assert.deepEqual(writes, ["O", "D", "T", "U"]);
    assert.deepEqual(bytes, []);
  }
});

test("original TCP operation loop uses the guarded session and withholds unpersisted acknowledgments", async () => {
  const driver = await readFile(
    new URL("../ci/native/win32/feasibility.js", import.meta.url),
    "utf8",
  );
  const start = driver.indexOf("for (const operation of OPERATIONS)");
  const loop = driver.slice(start, driver.indexOf("complete = true;", start));
  const commands = ["O", "D", "T", "U"];
  const stages = ["tcp-transfer", "tcp-intent", "tcp-observed", "tcp-denial"];
  for (const mode of ["read", "edit"]) {
    for (const failAt of [null, ...stages.slice(0, -1)]) {
      const f = tcpDenialFixture(),
        order = [],
        persisted = new Map();
      const completed = { event: "completed", operation: "tcp", error: 10013 };
      const replies = {
        O: f.transfer,
        D: f.prepared,
        T: f.attribution,
        U: completed,
      };
      const authorizations = {
        D: ["tcp-transfer", "transfer", f.transfer],
        T: ["tcp-intent", "prepared", f.prepared],
        U: ["tcp-observed", "attribution", f.attribution],
      };
      let released = 0;
      const transport = windowsSessionFixture(
        windowsCallerEnvironment,
        () => {},
        undefined,
        true,
        {
          launchCase: mode,
          onSend: (value, child) => {
            assert.equal(value, commands[released++]);
            order.push(`send:${value}`);
            if (authorizations[value]) {
              const [stage, property, expected] = authorizations[value];
              const intent = persisted.get(`${mode}-${stage}`);
              assert.ok(intent);
              assert.equal(intent.pending, true);
              assert.equal(intent.requestedEndpoint, f.endpoint);
              assert.deepEqual(intent[property], expected);
            }
            child.stdout.write(JSON.stringify(replies[value]) + "\n");
          },
        },
      );
      const run = { receipt: f.receipt, session: transport.session };
      const original = new Error("Intent write failed");
      let received = 0;
      const context = {
        OPERATIONS: ["tcp"],
        mode,
        run,
        tcpEndpoint: f.endpoint,
        nextRun: async () => {
          const row = await transport.session.next();
          received++;
          return row;
        },
        need: (value) => assert.ok(value),
        nativeException: () => {},
        assertWindowsFeasibilityTcpObserver,
        assertWindowsFeasibilityTcpTransfer,
        assertWindowsFeasibilityTcpDenial,
        observeWindowsFeasibilityWfp: async () => order.push("wfp-observed"),
        operations: [],
        persist: async (name, value) => {
          order.push(name);
          if (name === `${mode}-${failAt}`) throw original;
          persisted.set(name, structuredClone(value));
        },
      };
      try {
        for (const command of ["X", "DD", "d", "O\n"])
          assert.throws(() => transport.session.send(command));
        assert.deepEqual(transport.sent, []);
        transport.child.stdout.write(
          JSON.stringify({ event: "attempt", operation: "tcp" }) + "\n",
        );
        const execution = new Script(
          `(async () => {${loop}})()`,
        ).runInNewContext(context);
        if (failAt)
          await assert.rejects(
            execution,
            (error) => error === original && error.operation === "tcp",
          );
        else await execution;

        const acknowledged = failAt ? stages.indexOf(failAt) + 1 : 4;
        assert.deepEqual(transport.sent, commands.slice(0, acknowledged));
        const expectedOrder = [
          "send:O",
          `${mode}-tcp-transfer`,
          "send:D",
          `${mode}-tcp-intent`,
          "send:T",
          `${mode}-tcp-observed`,
          "send:U",
          "wfp-observed",
          `${mode}-tcp-denial`,
        ];
        assert.deepEqual(
          order,
          failAt
            ? [...expectedOrder.slice(0, acknowledged * 2), "wfp-observed"]
            : expectedOrder,
        );
        assert.deepEqual(
          [...persisted.keys()],
          stages
            .slice(0, failAt ? acknowledged - 1 : 4)
            .map((stage) => `${mode}-${stage}`),
        );
        assert.equal(received, acknowledged + 1);
        assert.equal(context.operations.length, failAt ? 0 : 1);
        assert.equal(run.tcpAttribution.pending, failAt !== null);
        if (!failAt) {
          assert.deepEqual(context.operations[0].completed, completed);
          assert.equal(persisted.get(`${mode}-tcp-denial`).pending, false);
        }
      } finally {
        transport.session.stop();
        transport.close(0);
        await transport.session.finish(received);
      }
    }
  }
});

test("TCP delivery failures consume the phase and retain the original transport error", async () => {
  for (const command of "ODTU")
    for (const kind of ["throw", "callback"]) {
      const original = new Error("Interrupted private input delivery");
      const f = tcpDenialFixture();
      const rows = [
        { event: "attempt", operation: "tcp" },
        f.transfer,
        f.prepared,
        f.attribution,
      ];
      const transport = windowsSessionFixture(
        windowsCallerEnvironment,
        () => {},
        undefined,
        true,
        {
          launchCase: "read",
          writeFailure: (value) =>
            kind === "callback" && value === command ? original : undefined,
        },
      );
      let received = 0,
        closed = false;
      try {
        for (const value of "ODTU") {
          assert.throws(
            () => transport.session.send(value),
            "No unread frame permits release",
          );
          transport.child.stdout.write(JSON.stringify(rows[received]) + "\n");
          assert.throws(
            () => transport.session.send(value),
            "The frame must be consumed first",
          );
          await transport.session.next();
          received++;
          if (value !== command) {
            transport.session.send(value);
            assert.throws(
              () => transport.session.send(value),
              "No replay after delivery",
            );
            continue;
          }
          if (kind === "throw") {
            transport.child.stdin.write = (bytes) => {
              transport.sent.push(bytes);
              throw original;
            };
            assert.throws(
              () => transport.session.send(value),
              (error) => error === original,
            );
          } else {
            const failed = once(transport.child.stdin, "error");
            transport.session.send(value);
            assert.equal((await failed)[0], original);
          }
          const delivered = [...transport.sent];
          for (const retry of "ODTU")
            assert.throws(
              () => transport.session.send(retry),
              (error) => error === original,
            );
          assert.deepEqual(transport.sent, delivered);
          transport.close();
          closed = true;
          await assert.rejects(
            transport.session.finish(received),
            (error) => error === original,
          );
          break;
        }
      } finally {
        transport.session.stop();
        if (!closed) transport.close();
      }
    }
});

test("TCP transport acknowledgments remain unavailable to unrelated helper roles", async () => {
  for (const [probeCase, rootedLaunch] of [
    [undefined, false],
    [undefined, true],
    ["workspace-rooted", false],
  ]) {
    const transport = windowsSessionFixture(
      windowsCallerEnvironment,
      () => {},
      probeCase,
      rootedLaunch,
    );
    try {
      for (const command of ["O", "D", "T", "U"])
        assert.throws(() => transport.session.send(command));
      assert.deepEqual(transport.sent, []);
    } finally {
      transport.session.stop();
      transport.close(0);
      await transport.session.finish(0);
    }
  }
});

test("original outside and closed-port controls remain mandatory around attributed denial", async () => {
  const driver = await readFile(
    new URL("../ci/native/win32/feasibility.js", import.meta.url),
    "utf8",
  );
  const start = driver.indexOf("      const controlsBefore = [];");
  const before = driver.slice(
    start,
    driver.indexOf("      const counts =", start),
  );
  const end = driver.indexOf(
    "      need(servers.every((c, i) => c.accepted === counts[i]));",
  );
  const after = driver.slice(end, driver.indexOf("      bundles.push", end));
  for (const [ready, accepted] of [
    [true, 0],
    [false, 0],
    [true, 1],
  ]) {
    const context = {
      servers: [
        { kind: "tcp", address: "32100", accepted },
        { kind: "pipe", address: "pipe", accepted: 0 },
      ],
      counts: [0, 0],
      need: (value) => assert.ok(value),
      native: async (role, kind, address) => {
        assert.equal(role, "control");
        assert.equal(address, kind === "tcp" ? "32100" : "pipe");
        return { ready };
      },
    };
    const run = (text) =>
      new Script(`(async () => {${text}})()`).runInNewContext(context);
    if (ready) await run(before);
    else await assert.rejects(run(before));
    if (ready && !accepted) await run(after);
    else await assert.rejects(run(after));
  }
  const source = await readFile(
    new URL("../ci/native/win32/feasibility-helper.c", import.meta.url),
    "utf8",
  );
  const condition =
    /need\((error == \(tcp \? WSAECONNREFUSED : ERROR_FILE_NOT_FOUND\))\);/u.exec(
      source,
    )[1];
  for (const error of [0, 10013, 10035, 10061]) {
    const context = {
      tcp: true,
      error,
      WSAECONNREFUSED: 10061,
      ERROR_FILE_NOT_FOUND: 2,
    };
    new Script(`closed = ${condition};`).runInNewContext(context);
    assert.equal(context.closed, error === 10061);
  }
});

test("native SO_ERROR completion preserves actual denial for every select readiness and rejects late completion", async () => {
  const source = await readFile(
    new URL("../ci/native/win32/feasibility-helper.c", import.meta.url),
    "utf8",
  );
  const begin = source.indexOf("    if (completed) { problem =");
  const branch = source
    .slice(begin, source.indexOf("    if (ready != 1)", begin))
    .replace(
      /\(struct diagnosis\)\{"tcp-connect", "win32", \(DWORD\)completed\}/u,
      '{operation:"tcp-connect",domain:"win32",value:completed}',
    )
    .replace("goto done;", "return;");
  for (const ready of [1, 2, 3])
    for (const now of [4999, 5000]) {
      const context = {
        ready,
        completed: 10013,
        end: 5000,
        GetTickCount64: () => now,
        problem: null,
        nativeReceipt: false,
      };
      new Script(`(function () {${branch}})()`).runInNewContext(context);
      assert.equal(context.problem.value, 10013);
      assert.equal(context.nativeReceipt, now < 5000);
    }
  for (const operation of [
    "observer-socket-close",
    "observer-engine-close",
    "observer-enum-close",
    "observer-token-close",
  ]) {
    const diagnosis = windowsFeasibilityDiagnostics(
      windowsDiagnostic("tcp-connect", "win32", 10013) +
        `native-windows-cleanup: operation=${operation} domain=win32 value=5\n`,
    );
    assert.equal(diagnosis.failure.value, 10013);
    assert.equal(diagnosis.cleanup.operation, operation);
    assert.equal(diagnosis.cleanup.value, 5);
  }
});

test("WFP observations join exact held birth, image, package, endpoints and event windows", async () => {
  for (const ending of ["\n", "\r\n"]) {
    const valid = wfpFixture(),
      text = (valid.tuple() + valid.snapshot()).replaceAll("\n", ending);
    for (const chunk of [
      text.slice(0, 30),
      text.slice(30, 171),
      text.slice(171),
    ])
      valid.child.stderr.write(chunk);
    const observed = await observeWindowsFeasibilityWfp(
      valid.run,
      valid.persist,
    );
    assert.equal(observed.status, "matched");
    assert.equal(observed.cleanup, "CLOSED");
    assert.equal(observed.tuple.local.port, 45678);
    assert.equal(observed.matches[0].filterId, "7");
    assert.equal(valid.saved[0][0], "read-wfp");
    valid.close(0);
  }
  for (const substitute of [
    (f) => (f.observation.child.creationTime = "101"),
    (f) => (f.observation.sid += "-1"),
    (f) => (f.observation.userSid = "S-1-5-21-2000"),
    (f) => (f.observation.image.sha256 = "d".repeat(64)),
    (f) => (f.observation.matches[0].time = "2001"),
    (f) => (f.observation.matches[0].flags = 0x17f),
    (f) => (f.observation.matches[0].direction = 9),
    (f) => (f.observation.matches[0].filterKey = "partial"),
    (f) => f.bytes.writeUInt32LE(0, 40),
    (f) => f.bytes.writeUInt16LE(0, 48),
    (f) => f.bytes.writeUInt32LE(10057, 36),
  ]) {
    const f = wfpFixture();
    substitute(f);
    f.child.stderr.write(f.tuple() + f.snapshot());
    const result = await observeWindowsFeasibilityWfp(f.run, f.persist);
    assert.equal(result.status, "unproved");
    assert.deepEqual(result.matches, []);
    f.close(0);
  }
});

test("WFP disabled, unknown, partial and cleanup failures preserve actual statuses without adopting prefixes", async () => {
  for (const [status, reason, nativeStatus, enumClose, engineClose] of [
    ["disabled", "api", 0x80320013, null, 0],
    ["unproved", "api", 0x803200ff, null, 0],
    ["unproved", "empty", 0, 0, 0],
    ["unproved", "exhausted", 0, 0, 0],
    ["unproved", "lookup", 5, 0, 0],
    ["unproved", "empty", 0, 5, 0],
    ["unproved", "empty", 0, 0, 5],
  ]) {
    const f = wfpFixture();
    Object.assign(f.observation, {
      status,
      reason,
      nativeStatus,
      enumClose,
      engineClose,
      matches: [],
    });
    f.child.stderr.write(f.tuple() + f.snapshot());
    const result = await observeWindowsFeasibilityWfp(f.run, f.persist);
    assert.equal(result.status, status);
    assert.equal(result.nativeStatus, nativeStatus);
    assert.equal(
      result.cleanup,
      enumClose || engineClose ? "UNCERTAIN" : "CLOSED",
    );
    f.close(0);
  }
  for (const carrier of [
    (f) => f.tuple() + f.snapshot() + f.snapshot(),
    (f) => f.tuple() + f.snapshot().slice(0, -1),
    (f) =>
      f.tuple() + "native-windows-wfp: snapshot=" + "x".repeat(4096) + "\n",
    (f) => f.tuple() + "native-windows-wfp: snapshot={bad}\n",
  ]) {
    const f = wfpFixture();
    f.child.stderr.write(carrier(f));
    f.child.stdout.write(
      '{"event":"completed","operation":"tcp","error":10013}\n',
    );
    assert.equal((await f.session.next()).error, 10013);
    f.close(0);
    await f.session.finish(1);
    const result = await observeWindowsFeasibilityWfp(f.run, f.persist);
    assert.equal(result.status, "unproved");
    assert.deepEqual(result.matches, []);
  }
  const failed = wfpFixture();
  Object.assign(failed.observation, {
    status: "unproved",
    reason: "empty",
    engineClose: 5,
    matches: [],
  });
  failed.child.stderr.write(
    failed.tuple() +
      failed.snapshot() +
      windowsDiagnostic("tcp-deadline", "invariant", 0),
  );
  failed.close();
  await assert.rejects(
    failed.session.next(),
    (error) =>
      windowsFeasibilityDiagnostics(error.stderr).failure.operation ===
      "tcp-deadline",
  );
  assert.equal(
    (await observeWindowsFeasibilityWfp(failed.run, failed.persist))
      .engineClose,
    5,
  );
});

test("actual WFP source is read-only, bounded, type-safe and closes every SDK allocation and handle", async () => {
  const source = await readFile(
    new URL("../ci/native/win32/feasibility-helper.c", import.meta.url),
    "utf8",
  );
  const observer = source.slice(
    source.indexOf("struct wfp_tuple {"),
    source.indexOf("#else\n#define wfp_tuple"),
  );
  const tokenStart = source.indexOf(
    "BOOL read = GetTokenInformation(current, TokenStatistics",
  );
  const tokenRead = source
    .slice(
      tokenStart,
      source.indexOf("    invariant(used == sizeof(token)", tokenStart),
    )
    .replace(/\b(?:BOOL|DWORD)\b/gu, "let")
    .replaceAll("sizeof(token)", "56")
    .replace(/&(token|used)/gu, "$1");
  for (const [read, closed, nativeError] of [
    [true, true, 0],
    [false, true, 5],
    [false, true, 0],
    [true, false, 0],
  ]) {
    let closureAttempted = false;
    const context = {
      current: 17,
      TokenStatistics: 10,
      token: {},
      used: 56,
      GetTokenInformation: () => read,
      GetLastError: () => nativeError,
      remember: () => {},
      close_handle: () => {
        closureAttempted = true;
        return closed;
      },
      status_check: (value) => {
        if (value) throw new Error("Native token refused");
      },
      invariant: (value) => {
        if (!value) throw new Error("Native token refused");
      },
      failure: () => {
        throw new Error("Native token refused");
      },
    };
    const execute = () => new Script(tokenRead).runInNewContext(context);
    if (read && closed) execute();
    else assert.throws(execute, /Native token refused/u);
    assert.equal(closureAttempted, true);
  }
  // Native stderr remains in CRT text mode: the forwarded tuple uses CRLF.
  assert.match(observer, /if \(!size \|\| line\[size - 1\] != '\\n'\) return/u);
  assert.match(observer, /if \(end && line\[end - 1\] == '\\r'\) end--/u);
  assert.match(observer, /end != offset \+ sizeof\(tuple\) \* 2/u);
  for (const api of [
    "FwpmNetEventCreateEnumHandle0",
    "FwpmNetEventEnum2",
    "FwpmFilterGetById0",
    "FwpmLayerGetById0",
  ])
    assert.match(observer, new RegExp(api, "u"));
  assert.doesNotMatch(
    observer,
    /FwpmEngineSetOption|FwpmFilterAdd|FwpmFilterDelete|FwpmTransaction|FwpmNetEventSubscribe|SetTokenInformation|AuditSet/u,
  );
  assert.match(observer, /FWPM_NET_EVENT2 \*\*events/u);
  assert.match(observer, /const FWPM_NET_EVENT_HEADER2 \*h = &event->header/u);
  assert.ok(
    observer.indexOf("event->type != FWPM_NET_EVENT_TYPE_CLASSIFY_DROP") <
      observer.indexOf("event->classifyDrop"),
  );
  for (const field of [
    "IP_VERSION",
    "IP_PROTOCOL",
    "LOCAL_ADDR",
    "REMOTE_ADDR",
    "LOCAL_PORT",
    "REMOTE_PORT",
    "APP_ID",
    "USER_ID",
    "PACKAGE_ID",
  ])
    assert.ok(observer.includes("FWPM_NET_EVENT_FLAG_" + field + "_SET"));
  for (const slot of ["filter", "layer", "events", "appId"])
    assert.match(
      observer,
      new RegExp(
        `if \\(${slot}\\) FwpmFreeMemory0\\(\\(void \\*\\*\\)&${slot}\\)`,
        "u",
      ),
    );
  assert.match(
    observer,
    /enumClose = FwpmNetEventDestroyEnumHandle0\(engine, enumeration\)/u,
  );
  assert.match(observer, /engineClose = FwpmEngineClose0\(engine\)/u);
  assert.match(observer, /page < 4/u);
  assert.match(observer, /enumeration, 64, &events, &count/u);
  assert.ok(
    source.indexOf("wfpSnapshotTaken = TRUE;") <
      source.indexOf("wfp_snapshot(line, at)"),
  );
  assert.match(
    observer,
    /EqualSid\(h->userId, userSid\).*EqualSid\(h->packageSid, appSid\)/u,
  );
  assert.match(observer, /local\.sin_addr\.s_addr\).*local\.sin_port/u);
  assert.match(
    observer,
    /getsockname\(socket, \(struct sockaddr \*\)&local, &localSize\)/u,
  );
  assert.match(observer, /value\.localPort = ntohs\(local\.sin_port\)/u);
  assert.match(
    source,
    /error == \(tcp \? WSAECONNREFUSED : ERROR_FILE_NOT_FOUND\)/u,
  );
  const tcp = source.slice(
    source.indexOf("static int tcp_connection("),
    source.indexOf("static int connection("),
  );
  assert.ok(
    tcp.indexOf('problem = (struct diagnosis){"tcp-connect"') <
      tcp.lastIndexOf("wfp_tuple(socket, started, attempted)"),
  );
  assert.ok(
    tcp.lastIndexOf("wfp_tuple(socket, started, attempted)") <
      tcp.indexOf("closesocket(socket)"),
  );
  const driver = await readFile(
    new URL("../ci/native/win32/feasibility.js", import.meta.url),
    "utf8",
  );
  for (const inventory of [
    "fwpmu.h",
    "fwpmtypes.h",
    "windows-feasibility-source",
    "fwpuclnt.lib",
    "windows-wfp-loader",
  ])
    assert.ok(driver.includes(inventory));
});

test("WFP SDK inventory and post-build rechecks read the fixed header directories under one version", async () => {
  const source = await readFile(
    new URL("../ci/native/win32/feasibility.js", import.meta.url),
    "utf8",
  );
  const mapping = source.match(
    /const WFP_SDK_HEADERS = Object\.freeze\(\{[\s\S]*?\}\);/u,
  );
  assert.ok(mapping);
  const inventory = source.slice(
    source.indexOf(
      "for (const [header, directory] of Object.entries(WFP_SDK_HEADERS))",
    ),
    source.indexOf('stage = "exclusive-fixture";'),
  );
  const recheck = source.slice(
    source.indexOf(
      "for (const [file, name] of [",
      source.indexOf('stage = "native-build";'),
    ),
    source.indexOf('stage = "synthetic-git";'),
  );
  const reads = [],
    sdkVersion = "10.0.10000.0",
    sourceFile = "C:\\source\\feasibility-helper.c",
    headers = [
      "C:\\SDK\\Include\\10.0.10000.0\\um\\fwpmu.h",
      "C:\\SDK\\Include\\10.0.10000.0\\shared\\fwpmtypes.h",
    ];
  const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
  const components = [
    {
      name: "windows-feasibility-source",
      sha256: digest(Buffer.from(sourceFile)),
    },
  ];
  await new Script(
    `(async () => { ${mapping[0]} ${inventory} ${recheck} })()`,
  ).runInNewContext({
    path: path.win32,
    process: { env: { WindowsSdkDir: "C:\\SDK" } },
    sdkVersion,
    SOURCE: "C:\\source",
    components,
    digest,
    need: (value) => assert.ok(value),
    regular: async (file) => {
      reads.push(file);
      return Buffer.from(file);
    },
  });
  assert.deepEqual(reads, [...headers, sourceFile, ...headers]);
  assert.ok(components.slice(1).every((value) => value.version === sdkVersion));
  assert.deepEqual(
    components.slice(1).map((value) => value.sha256),
    headers.map((file) => digest(Buffer.from(file))),
  );
});

test("TCP observations are bounded data and cannot authorize or reject an otherwise valid receipt", async () => {
  const enter = "native-windows-tcp: api=WSASocketW phase=enter value=0\n";
  for (const [capture, status] of [
    [
      enter +
        "native-windows-tcp: api=WSASocketW phase=failed value=10013\nnative-windows-tcp: end\n",
      "complete",
    ],
    [
      enter + "native-windows-tcp: api=connect phase=pending value=10035\n",
      "incomplete",
    ],
    [
      enter +
        "native-windows-tcp: api=bind phase=enter value=0\nnative-windows-tcp: api=bind phase=complete value=0\nnative-windows-tcp: api=closesocket phase=complete value=0\nnative-windows-tcp: end\n",
      "complete",
    ],
    [
      enter + "native-windows-tcp: api=bind phase=pending value=10035\n",
      "incomplete",
    ],
    [enter + "native-windows-tcp: end\n", "incomplete"],
    [
      "native-windows-tcp: api=closesocket phase=complete value=0\nnative-windows-tcp: end\n",
      "incomplete",
    ],
    ["native-windows-tcp: api=foreign phase=enter value=0\n", "incomplete"],
    [
      "native-windows-tcp: api=connect phase=pending value=10013\n",
      "incomplete",
    ],
    [
      "native-windows-tcp: api=recv phase=failed value=4294967296\n",
      "incomplete",
    ],
    ["native-windows-tcp: " + "x".repeat(4096), "incomplete"],
    [enter.repeat(48) + "native-windows-tcp: end\n", "incomplete"],
  ]) {
    const f = windowsSessionFixture();
    assert.equal(f.session.tcpObservation.status, "unavailable");
    f.child.stderr.write(capture.slice(0, 18));
    f.child.stderr.write(capture.slice(18));
    const row = f.session.next();
    f.child.stdout.write(
      '{"event":"completed","operation":"tcp","error":10013}\n',
    );
    assert.equal((await row).error, 10013);
    f.close(0);
    await f.session.finish(1);
    assert.equal(f.session.tcpObservation.status, status);
    assert.ok(f.session.tcpObservation.calls.length < 48);
    const copy = f.session.tcpObservation;
    const count = copy.calls.length;
    copy.calls.length = 0;
    assert.equal(f.session.tcpObservation.calls.length, count);
  }
});

test("TCP pending observations without a completion receipt remain EOF failure", async () => {
  const f = windowsSessionFixture(),
    waiting = f.session.next();
  f.child.stderr.write(
    "native-windows-tcp: api=connect phase=enter value=0\nnative-windows-tcp: api=connect phase=pending value=10035\n",
  );
  f.close();
  await assert.rejects(
    waiting,
    (error) =>
      error.nativeRejection === "eof" &&
      error.stderr === "" &&
      error.tcpObservation.status === "incomplete",
  );
  await assert.rejects(f.session.finish(0));
});

test("TCP bind diagnostics and an empty WFP snapshot cannot supply a denial receipt", async () => {
  const f = wfpFixture(),
    waiting = f.session.next();
  f.bytes.writeUInt32LE(0, 68); // No connect attempt was observed on the original socket.
  Object.assign(f.observation, {
    status: "unproved",
    reason: "empty",
    matches: [],
  });
  f.child.stderr.write(
    "native-windows-tcp: api=WSASocketW phase=enter value=0\nnative-windows-tcp: api=bind phase=failed value=10013\nnative-windows-tcp: api=closesocket phase=complete value=0\nnative-windows-tcp: end\n" +
      f.tuple() +
      f.snapshot(),
  );
  f.close();
  await assert.rejects(
    waiting,
    (error) =>
      error.nativeRejection === "eof" &&
      error.tcpObservation.status === "complete",
  );
  await assert.rejects(f.session.finish(0));
  const observed = await observeWindowsFeasibilityWfp(f.run, f.persist);
  assert.equal(observed.status, "unproved");
  assert.deepEqual(observed.matches, []);
});

test("TCP API, partial exchange and expiry refusals survive later owner and independent close failures", async () => {
  for (const [operation, domain, value] of [
    ["tcp-connect", "win32", 10013],
    ["tcp-bind", "win32", 10013],
    ["tcp-bind", "win32", 10022],
    ["tcp-nonblocking", "win32", 10022],
    ["tcp-completion", "win32", 10022],
    ["tcp-select", "win32", 10038],
    ["tcp-send", "win32", 10054],
    ["tcp-receive", "win32", 10054],
    ["tcp-close", "win32", 10038],
    ["tcp-progress", "invariant", 0],
    ["tcp-eof", "invariant", 0],
    ["tcp-deadline", "invariant", 0],
    ["tcp-ready", "invariant", 0],
    ["tcp-nonce", "invariant", 0],
  ]) {
    const f = windowsSessionFixture(),
      waiting = f.session.next();
    const primary = windowsDiagnostic(operation, domain, value);
    f.child.stderr.write(
      primary +
        "native-windows-tcp: api=transaction phase=failed value=" +
        value +
        "\n",
    );
    let refused;
    await assert.rejects(waiting, (error) => {
      refused = error;
      return true;
    });
    f.child.stderr.write(
      "native-windows-cleanup: operation=tcp-close domain=win32 value=10038\n" +
        windowsDiagnostic("owner-read", "win32", 109),
    );
    f.child.stdout.write(
      '{"event":"completed","operation":"tcp","error":10013}\n',
    );
    f.close();
    await assert.rejects(f.session.finish(0), (error) => {
      assert.equal(error, refused);
      const diagnosis = windowsFeasibilityDiagnostics(error.stderr);
      assert.deepEqual(diagnosis.failure, { operation, domain, value });
      assert.deepEqual(diagnosis.cleanup, {
        operation: "tcp-close",
        domain: "win32",
        value: 10038,
      });
      assert.equal(error.tcpObservation.status, "incomplete");
      assert.match(
        windowsFeasibilityCause("tcp", error).detail,
        new RegExp(`Native ${operation} failed`),
      );
      return true;
    });
  }
  for (const [operation, domain, value] of [
    ["tcp-close", "invariant", 0],
    ["tcp-bind", "invariant", 0],
    ["tcp-bind", "win32", 0],
    ["tcp-send", "win32", 0],
    ["tcp-deadline", "win32", 10060],
  ])
    assert.equal(
      windowsFeasibilityDiagnostics(
        windowsDiagnostic(operation, domain, value),
      ),
      null,
    );
});

test("only the mapped and workspace-rooted holders receive larger finite transcript budgets", async () => {
  const line =
    JSON.stringify({
      event: "null-map-object",
      nativePathUtf16: "0".repeat(8000),
    }) + "\n";
  for (const caseId of [
    "shadow",
    "no-shadow-control",
    "no-shadow-mapped",
    "workspace-rooted",
  ]) {
    const f = windowsSessionFixture(
      windowsCallerEnvironment,
      undefined,
      caseId,
    );
    const next = f.session.next();
    f.child.stdout.write(line.repeat(9));
    if (caseId === "no-shadow-mapped" || caseId === "workspace-rooted") {
      await next;
      for (let i = 1; i < 9; i++) await f.session.next();
      const oversized = f.session.next();
      f.child.stdout.write(
        "x".repeat(caseId === "workspace-rooted" ? 524288 : 262144),
      );
      f.close();
      await assert.rejects(
        oversized,
        (error) => error.nativeRejection === "stdout-bound",
      );
    } else {
      f.close();
      await assert.rejects(
        next,
        (error) => error.nativeRejection === "stdout-bound",
      );
    }
  }
});

function windowsImageFrames(
  expected,
  actual,
  {
    succeeded = true,
    returnedLength = actual.length / 4,
    lastError = null,
  } = {},
) {
  const available = succeeded && returnedLength > 0 && returnedLength < 4096;
  let frames = `native-windows-image: query=${Number(succeeded)} capacity=4096 flags=1 length=${returnedLength} error=${succeeded ? "unavailable" : lastError} expected=${expected.length / 4} actual=${Number(available)}\n`;
  for (const [kind, hex] of [
    ["expected", expected],
    ["actual", available ? actual : ""],
  ])
    for (let offset = 0; offset < hex.length; offset += 2048)
      frames += `native-windows-image: ${kind} ${hex.slice(offset, offset + 2048)}\n`;
  return frames + "native-windows-image: end\n";
}

function windowsCwdFrames(overrides = {}, closure = "success") {
  const calls = {
    current: ["success", 1, null, "0061"],
    open: ["success", null, null, ""],
    dos: ["success", 1, null, "0062"],
    nt: ["success", 1, null, "0063"],
    long: ["not-attempted", null, null, ""],
    ...overrides,
  };
  let frames =
    "native-windows-cwd: pid=42 birth=7 error=unavailable context=payload-original capacity=260\n";
  for (const [name, [outcome, length, error, utf16]] of Object.entries(calls))
    frames += `native-windows-cwd: ${name} outcome=${outcome} length=${length ?? "unavailable"} error=${error ?? "unavailable"} utf16=${utf16}\n`;
  return frames + `native-windows-cwd: end close=${closure}\n`;
}

test("Windows cwd records retain exact API outcomes without granting authority", async () => {
  const skipped = ["not-attempted", null, null, ""],
    failed = ["failed", 0, 5, ""],
    oversized = ["oversized", 260, null, ""];
  const bounded = "0043003a005cd800" + "0061".repeat(255);
  const success = ["success", 259, null, bounded];
  const withoutDirectory = { open: skipped, dos: skipped, nt: skipped };
  const withoutHandle = { dos: skipped, nt: skipped };
  const exactPaths = { current: success, nt: success, long: success };
  const ntFailure = ["failed", 0, 3, ""],
    longFailure = ["failed", 0, 2, ""];
  const frames = windowsCwdFrames();
  const complete = [
    frames,
    windowsCwdFrames({ ...withoutDirectory, current: failed }, "not-attempted"),
    windowsCwdFrames(
      { ...withoutDirectory, current: oversized },
      "not-attempted",
    ),
    windowsCwdFrames(
      { ...withoutHandle, open: ["failed", null, 5, ""] },
      "not-attempted",
    ),
    windowsCwdFrames({ ...exactPaths, dos: failed }),
    windowsCwdFrames({ dos: oversized, nt: ntFailure, long: longFailure }),
    windowsCwdFrames({ dos: failed, nt: ntFailure, long: longFailure }),
    windowsCwdFrames({ dos: failed, nt: oversized, long: oversized }),
    windowsCwdFrames({ nt: failed }),
    windowsCwdFrames({ dos: failed }, "failed"),
  ];
  const incomplete = [
    frames.replace("birth=7 error=unavailable", "birth=unavailable error=5"),
    frames.replace("context=payload-original", "context=git-private"),
    frames.replace("capacity=260", "capacity=261"),
    frames.replace("dos outcome=success", "dos outcome=unknown"),
    frames.replace("error=unavailable utf16=0062", "error=5 utf16=0062"),
    windowsCwdFrames({ dos: failed }),
    windowsCwdFrames({ long: success }),
    windowsCwdFrames({ nt: ["failed", 0, 5, "0063"] }),
    frames.replace("utf16=0062", "utf16=" + "0062".repeat(260)),
    frames.repeat(20),
    "native-windows-cwd: " + "x".repeat(4096) + "\n",
    frames.slice(0, frames.lastIndexOf("native-windows-cwd: end")),
    frames.slice(0, -1),
  ];
  for (const input of [...complete, ...incomplete, ""]) {
    const status = input
      ? complete.includes(input)
        ? "complete"
        : "incomplete"
      : "unavailable";
    const f = windowsSessionFixture(),
      waiting = f.session.next();
    const primary = windowsDiagnostic("git-process-create", "win32", 5);
    const cleanup =
      "native-windows-cleanup: operation=file-close domain=win32 value=6\n";
    if (input.endsWith("\n")) {
      f.child.stderr.write(input.slice(0, 9));
      f.child.stderr.write(input.slice(9, 101));
      f.child.stderr.write(input.slice(101));
    }
    f.child.stderr.write(windowsImageFrames("0061", "0062"));
    f.child.stderr.write(
      "native-windows-output: " +
        "61".repeat(1024) +
        "\nnative-windows-output-end: complete\n",
    );
    assert.equal(f.child.stdin.writableEnded, false);
    f.child.stderr.write(primary + cleanup);
    if (!input.endsWith("\n")) f.child.stderr.write(input);
    f.close(0);
    await assert.rejects(waiting, {
      stderr: primary + cleanup,
      nativeDiagnosticInvalid: false,
      nativeRejection: undefined,
    });
    assert.throws(() => f.session.send("G"));
    assert.throws(() =>
      f.session.checkGitReceipt(() =>
        assert.fail("Diagnostic cannot admit a receipt"),
      ),
    );
    await assert.rejects(f.session.finish(0));
    const capture = f.session.cwdObservation;
    assert.equal(capture.status, status);
    assert.equal(f.session.imageBinding.status, "complete");
    assert.equal(f.session.gitCapture.stderr.complete, true);
    if (status === "complete") {
      assert.deepEqual(capture.owner, {
        pid: 42,
        creationTime: "7",
        lastError: null,
      });
      assert.equal(capture.context, "payload-original");
      if (capture.calls.current.returnedLength === 259) {
        assert.equal(capture.calls.current.utf16, bounded);
        assert.equal(capture.calls.long.utf16, bounded);
        assert.equal(capture.calls.dos.lastError, 5);
        assert.equal(capture.calls.nt.lastError, null);
      }
      if (
        capture.calls.dos.outcome === "failed" &&
        capture.calls.nt.outcome === "failed"
      )
        assert.deepEqual(
          [
            capture.calls.dos.lastError,
            capture.calls.nt.lastError,
            capture.calls.long.lastError,
          ],
          [5, 3, 2],
        );
      for (const call of Object.values(capture.calls))
        if (call.outcome !== "success") assert.equal(call.utf16, "");
    }
  }
});

test("Windows cwd observation survives refused-start draining without settling cleanup", async () => {
  const f = windowsSessionFixture(),
    frames = windowsCwdFrames();
  const split = frames.indexOf("native-windows-cwd: open");
  const primary = windowsDiagnostic("owner-read", "win32", 109);
  f.child.stderr.write(frames.slice(0, split) + primary);
  const probe = await observeWindowsGitNullProbe({
    start: () => f.session.next(),
    retire: async () => {
      f.child.stderr.write(frames.slice(split));
      throw new Error("Independent settlement unavailable");
    },
  });
  f.close(0);
  assert.equal(probe.cwdObservation.status, "complete");
  assert.equal(probe.cwdObservation.calls.current.utf16, "0061");
  assert.equal(probe.failure.stderr, primary);
  assert.equal(probe.git, null);
  assert.equal(probe.cleanup.status, "UNCERTAIN");
  assert.equal(probe.reusable, false);
});

test("Windows payload cwd recipe latches API errors and owns closure before DOS fallback", async () => {
  const source = await readFile(
    new URL("../ci/native/win32/feasibility-helper.c", import.meta.url),
    "utf8",
  );
  const query = source.slice(
    source.indexOf("static void cwd_query("),
    source.indexOf("static void observe_cwd("),
  );
  assert.match(query, /\{\s+result->error = length \? 0 : GetLastError\(\);/u);
  const body = source.slice(
    source.indexOf("static void observe_cwd("),
    source.indexOf("static DWORD git_wait("),
  );
  assert.match(body, /GetCurrentDirectoryW\(MAX_PATH, calls\[0\]\.text\)/u);
  assert.match(
    body,
    /calls\[0\]\.length > 0 && calls\[0\]\.length < MAX_PATH/u,
  );
  assert.match(
    body,
    /transport\.cwd = CreateFileW\(calls\[0\]\.text, 0, FILE_SHARE_READ \| FILE_SHARE_WRITE \| FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL\);\s+calls\[1\]\.error = transport\.cwd == INVALID_HANDLE_VALUE \? GetLastError\(\) : 0;/u,
  );
  assert.match(body, /if \(transport\.cwd != INVALID_HANDLE_VALUE\) \{/u);
  for (const [slot, flags] of [
    [2, "0"],
    [3, "VOLUME_NAME_NT"],
  ])
    assert.ok(
      body.includes(
        `cwd_query(&calls[${slot}], GetFinalPathNameByHandleW(transport.cwd, calls[${slot}].text, MAX_PATH, ${flags}));`,
      ),
    );
  const dos = body.indexOf("cwd_query(&calls[2]"),
    nt = body.indexOf("cwd_query(&calls[3]"),
    close = body.indexOf("release_handle(&transport.cwd"),
    long = body.indexOf("GetLongPathNameW(");
  assert.ok(dos < nt && nt < close && close < long);
  assert.match(
    body,
    /if \(closed && \(!calls\[2\]\.length \|\| calls\[2\]\.length >= MAX_PATH\)\)\s+cwd_query\(&calls\[4\], GetLongPathNameW\(calls\[0\]\.text, calls\[4\]\.text, MAX_PATH\)\);/u,
  );
  assert.match(body, /if \(i != 1 && !strcmp\(outcome, "success"\)\)/u);
  assert.match(
    body,
    /GetProcessTimes\([^\n]+\);\s+DWORD birthError = born \? 0 : GetLastError\(\)/u,
  );
  assert.match(
    body,
    /workspaceEntered \? "payload-private-workspace-rooted" : "payload-original"/u,
  );
  assert.match(body, /if \(!closed\) failure\(126\)/u);
  assert.equal(
    source.match(/release_handle\(&transport\.cwd, "file-close"\)/gu).length,
    2,
  );
  assert.match(source, /#define CWD_LIMIT 8192/u);
  assert.match(
    source,
    /limits\[\] = \{IMAGE_LIMIT, CWD_LIMIT, TCP_LIMIT, WFP_LIMIT\}/u,
  );
  const bundle = source.slice(
    source.indexOf("static void bundle("),
    source.indexOf("static void fault("),
  );
  const observation = bundle.indexOf("if (owned) observe_cwd();");
  assert.ok(
    observation >= 0 &&
      observation < bundle.indexOf("BOOL launched = CreateProcessW("),
  );
});

test("Windows image availability never replaces original refusal or cleanup", async () => {
  const frames = windowsImageFrames("0061", "0062");
  const utf16 = (value) =>
    value
      .split("")
      .map((unit) => unit.charCodeAt(0).toString(16).padStart(4, "0"))
      .join("");
  const native = "\\Device\\HarddiskVolume1\\owned\\experiment\\build\\git.exe";
  const bindings = [
    ["D:\\owned\\experiment\\build\\git.exe", native],
    [native, native],
    [native, native.replace("Volume1", "Volume2")],
    [native, native.replace("git.exe", "other.exe")],
  ].map(([expected, actual]) => {
    const paths = { expected: utf16(expected), actual: utf16(actual) };
    return [windowsImageFrames(paths.expected, paths.actual), paths];
  });
  const failed = windowsImageFrames("0061", "", {
    succeeded: false,
    returnedLength: 4096,
    lastError: 5,
  });
  const budget =
    failed.split("\n")[0].replace("expected=1", "expected=4095") + "\n";
  for (const [input, status] of [
    ["", "unavailable"],
    [frames, "complete"],
    ...bindings.map(([binding]) => [binding, "complete"]),
    [failed, "complete"],
    [windowsImageFrames("0061", "", { returnedLength: 4096 }), "complete"],
    [windowsImageFrames("0061", "", { returnedLength: 0 }), "complete"],
    [windowsImageFrames("", "0062"), "unavailable"],
    ...["0", "2", "01", "0x1"].map((flag) => [
      frames.replace("flags=1", `flags=${flag}`),
      "unavailable",
    ]),
    [frames.replace("0061", "00zz"), "incomplete"],
    [frames.replace("error=unavailable", "error=203"), "unavailable"],
    [
      frames.slice(0, frames.lastIndexOf("native-windows-image: end")),
      "incomplete",
    ],
    [frames.slice(0, -1), "incomplete"],
    [
      frames.replace("expected 0061", "expected " + "0061".repeat(1024)),
      "incomplete",
    ],
    [
      budget +
        "native-windows-image: expected 0061\n".repeat(4095) +
        "native-windows-image: end\n",
      "incomplete",
    ],
    [
      failed.replace(
        "native-windows-image: end",
        "native-windows-image: actual 0061\nnative-windows-image: end",
      ),
      "incomplete",
    ],
  ]) {
    const f = windowsSessionFixture(),
      waiting = f.session.next();
    if (input.endsWith("\n")) f.child.stderr.write(input);
    const primary =
      input === failed
        ? windowsDiagnostic("git-image-query", "win32", 5)
        : windowsDiagnostic("git-image-equal", "invariant", 0);
    const cleanup =
      "native-windows-cleanup: operation=file-close domain=win32 value=6\n";
    f.child.stderr.write(primary + cleanup);
    if (!input.endsWith("\n")) f.child.stderr.write(input);
    f.close(0);
    await assert.rejects(waiting, {
      stderr: primary + cleanup,
      nativeDiagnosticInvalid: false,
      nativeRejection: undefined,
    });
    assert.throws(() => f.session.send("G"));
    assert.throws(() =>
      f.session.checkGitReceipt(() => assert.fail("No receipt admission")),
    );
    await assert.rejects(f.session.finish(0));
    const capture = f.session.imageBinding;
    assert.equal(capture.status, status);
    if (capture.query) assert.equal(capture.query.flags, 1);
    if ([0, 4096].includes(capture.query?.returnedLength))
      assert.equal(capture.actual.available, false);
    const binding = bindings.find(([frame]) => frame === input)?.[1];
    if (binding) {
      assert.equal(capture.actual.length, capture.query.returnedLength);
      for (const kind of ["expected", "actual"])
        assert.equal(capture[kind].utf16, binding[kind]);
    }
    if (input === failed) {
      assert.equal(capture.query.lastError, 5);
      assert.equal(capture.expected.available, true);
      assert.equal(capture.actual.length, null);
      assert.equal(capture.actual.utf16, "");
    }
  }
});

test("Windows image capture retains frames drained during refused-start cleanup", async () => {
  const f = windowsSessionFixture(),
    frames = windowsImageFrames("0061", "0062");
  const split = frames.indexOf("native-windows-image: expected");
  const primary = windowsDiagnostic("owner-read", "win32", 109);
  f.child.stderr.write(frames.slice(0, split) + primary);
  const probe = await observeWindowsGitNullProbe({
    start: () => f.session.next(),
    retire: async () => {
      f.child.stderr.write(frames.slice(split));
      throw new Error("Independent settlement unavailable");
    },
  });
  f.close(0);
  assert.equal(probe.imageBinding.status, "complete");
  assert.equal(probe.imageBinding.actual.utf16, "0062");
  assert.equal(probe.failure.stderr, primary);
  assert.equal(probe.git, null);
  assert.equal(probe.cleanup.status, "UNCERTAIN");
  assert.equal(probe.reusable, false);
});

test("Windows fragmented raw Git and image transport supplies no receipt and preserves first and cleanup failures", async () => {
  const captured = [];
  const f = windowsSessionFixture(
    undefined,
    createNativeDiagnosticWriter((bytes) => captured.push(bytes)),
  );
  const raw = Buffer.from(
    'unknown fatal\n{"event":"suspended"}\nnative-windows: operation=git-process-exit domain=exit value=0\n',
  );
  const carrier = `native-windows-output: ${raw.toString("hex")}\n`;
  const waiting = f.session.next();
  const encoded = [...raw]
    .map((byte) => byte.toString(16).padStart(4, "0"))
    .join("");
  const expected = "0043003a005c" + "0061".repeat(4092),
    actual = "d800dc00" + encoded + "0062".repeat(4093 - raw.length);
  const images = windowsImageFrames(expected, actual);
  assert.ok(images.length > 4096);
  f.child.stderr.write(images.slice(0, 17));
  f.child.stderr.write(images.slice(17, 3079));
  f.child.stderr.write(images.slice(3079));
  f.child.stderr.write(carrier.slice(0, 29));
  f.child.stderr.write(carrier.slice(29));
  const filler = Buffer.alloc(1024, 0x61).toString("hex");
  f.child.stderr.write(`native-windows-output: ${filler}\n`.repeat(4));
  f.child.stderr.write("native-windows-output-end: complete\n");
  assert.equal(f.child.stdin.writableEnded, false);
  f.child.stdout.write('{"event":"transport-only"}\n');
  assert.deepEqual(await waiting, { event: "transport-only" });
  const primary = windowsDiagnostic("git-process-exit", "exit", 128);
  const failed = f.session.next();
  f.child.stderr.write(primary);
  f.child.stderr.write(
    "native-windows-cleanup: operation=git-diagnostic-close domain=win32 value=6\n",
  );
  f.close(0);
  await assert.rejects(failed, (error) => {
    assert.equal(
      error.stderr,
      primary +
        "native-windows-cleanup: operation=git-diagnostic-close domain=win32 value=6\n",
    );
    assert.equal(windowsFeasibilityCause("access", error).code, "setup-failed");
    assert.equal(windowsFeasibilityDiagnostics(error.stderr).cleanup.value, 6);
    return true;
  });
  assert.ok(Buffer.concat(captured).includes(raw));
  assert.equal(
    f.session.gitCapture.stderr.hex,
    raw.toString("hex") + filler.repeat(4),
  );
  assert.equal(f.session.gitCapture.stderr.complete, true);
  const capture = f.session.imageBinding;
  assert.equal(capture.status, "complete");
  assert.deepEqual(capture.query, {
    succeeded: true,
    capacity: 4096,
    flags: 1,
    returnedLength: 4095,
    lastError: null,
  });
  for (const [kind, utf16] of [
    ["expected", expected],
    ["actual", actual],
  ])
    assert.deepEqual(capture[kind], { available: true, length: 4095, utf16 });
  assert.ok(
    Buffer.concat(captured).includes(Buffer.from(expected.slice(0, 2048))),
  );
  const probe = await observeWindowsGitNullProbe({
    start: () => f.session.next(),
    retire: async () => {
      throw new Error("Independent settlement unavailable");
    },
  });
  assert.deepEqual(probe.imageBinding, capture);
  assert.equal(
    probe.failure.stderr,
    primary +
      "native-windows-cleanup: operation=git-diagnostic-close domain=win32 value=6\n",
  );
  assert.equal(probe.git, null);
  assert.equal(probe.cleanup.status, "UNCERTAIN");
  assert.equal(probe.reusable, false);
  captured.length = 0;
  const invalidEvidence = windowsSessionFixture(
    undefined,
    createNativeDiagnosticWriter((bytes) => captured.push(bytes)),
  );
  const refused = invalidEvidence.session.next();
  invalidEvidence.child.stderr.write("unknown unframed helper output\n");
  invalidEvidence.child.stderr.write(
    carrier + "native-windows-output-end: complete\n",
  );
  invalidEvidence.close();
  await assert.rejects(
    refused,
    (error) => error.nativeRejection === "diagnostic-form",
  );
  assert.ok(Buffer.concat(captured).includes(raw));
  assert.equal(invalidEvidence.session.gitCapture.stderr.complete, false);
  const malformed = windowsSessionFixture();
  const rejected = malformed.session.next();
  malformed.child.stderr.write("native-windows-output: 0\n");
  malformed.close();
  await assert.rejects(
    rejected,
    (error) => error.nativeRejection === "diagnostic-form",
  );
});

test("model-free stderr diagnostics stream beyond bounded evidence capture and identify truncation", async (t) => {
  const bytes = [],
    stderr = new PassThrough();
  t.after(() => stderr.destroy());
  let finish;
  const child = {
    stderr,
    ownedCompletion: new Promise((resolve) => {
      finish = resolve;
    }),
  };
  const raw = Buffer.from("unknown-output:" + "x".repeat(8192));
  let inspected;
  await withNativeDiagnostics(
    async () => {
      const completed = observeFeasibilityCompletion(child, (value) => {
        inspected = value;
        return value;
      });
      stderr.write(raw);
      finish({ outcome: { type: "close", exitCode: 19, signal: null } });
      await completed;
    },
    createNativeDiagnosticWriter((chunk) => bytes.push(chunk)),
  );
  assert.equal(inspected.stderr.length, 8192);
  const output = Buffer.concat(bytes);
  assert.ok(output.includes(raw));
  assert.match(output.toString(), /truncated: true/u);
});

test("completion leaves model-free stdout buffered for its owner with or without diagnostics", async (t) => {
  for (const diagnostics of [null, createNativeDiagnosticWriter(() => {})]) {
    const stdout = new PassThrough(),
      stderr = new PassThrough();
    const completion = Promise.withResolvers();
    t.after(() => {
      stdout.destroy();
      stderr.destroy();
    });
    const observing = withNativeDiagnostics(
      () =>
        observeFeasibilityCompletion(
          {
            stdout,
            stderr,
            ownedCompletion: completion.promise,
          },
          (value) => value,
        ),
      diagnostics,
    );
    try {
      await new Promise((resolve, reject) =>
        stdout.write("buffered owner output", (error) =>
          error ? reject(error) : resolve(),
        ),
      );
      assert.deepEqual(stdout.read(), Buffer.from("buffered owner output"));
    } finally {
      completion.resolve({
        outcome: { type: "close", exitCode: 19, signal: null },
      });
      await observing;
    }
  }
});

test("model-free protocol publishes unknown stdout bytes before rejecting them", async (t) => {
  const chunks = [],
    output = new PassThrough(),
    errorOutput = new PassThrough();
  const raw = Buffer.from([0xff, 0, 0x61, 10]);
  const input = new Writable({
    write(_, __, done) {
      output.write(raw);
      done();
    },
    final(done) {
      output.end();
      errorOutput.end();
      done();
    },
  });
  await withNativeDiagnostics(
    async () => {
      const client = openFeasibilityCommand({ input, output, errorOutput });
      t.after(async () => {
        await client.close().catch(() => {});
        for (const stream of [input, output, errorOutput]) stream.destroy();
      });
      await assert.rejects(
        client.initialize(),
        (error) => error.code === "ERR_FEASIBILITY_READER_FAILED",
      );
      await assert.rejects(
        client.close(),
        (error) => error.code === "ERR_FEASIBILITY_READER_FAILED",
      );
    },
    createNativeDiagnosticWriter((bytes) => chunks.push(bytes)),
  );
  assert.ok(Buffer.concat(chunks).includes(raw));
});

test("model-free input exceptions remain visible when completion supplies the first outcome", async (t) => {
  const chunks = [],
    output = new PassThrough(),
    errorOutput = new PassThrough();
  const original = new Error("unknown input failure", {
    cause: new Error("unknown input cause"),
  });
  const refused = new Error("independent completion refusal");
  const completion = Promise.withResolvers();
  const input = new Writable({
    write(_, __, done) {
      done();
    },
    final(done) {
      output.end();
      errorOutput.end();
      done();
    },
  });
  await withNativeDiagnostics(
    async () => {
      const client = openFeasibilityCommand(
        { input, output, errorOutput, completion: completion.promise },
        undefined,
        "linux",
      );
      const pending = assert.rejects(
        client.initialize(),
        (error) => error === refused,
      );
      t.after(async () => {
        completion.resolve(refused);
        await Promise.allSettled([pending, client.close()]);
        for (const stream of [input, output, errorOutput]) stream.destroy();
      });
      input.emit("error", original);
      const captured = Buffer.concat(chunks).toString();
      assert.ok(captured.includes(original.stack));
      assert.ok(captured.includes(original.cause.stack));
      completion.resolve(refused);
      await pending;
      await assert.rejects(client.close(), (error) => error === refused);
    },
    createNativeDiagnosticWriter((bytes) => chunks.push(bytes)),
  );
});

test("model-free stdout publication marks capture refusal at the existing reader bound", async (t) => {
  const chunks = [],
    output = new PassThrough(),
    errorOutput = new PassThrough();
  const raw = Buffer.from("unknown output:" + "x".repeat(1048576) + "\n");
  const input = new Writable({
    write(_, __, done) {
      output.write(raw);
      done();
    },
    final(done) {
      output.end();
      errorOutput.end();
      done();
    },
  });
  await withNativeDiagnostics(
    async () => {
      const client = openFeasibilityCommand({ input, output, errorOutput });
      t.after(async () => {
        await client.close().catch(() => {});
        for (const stream of [input, output, errorOutput]) stream.destroy();
      });
      await assert.rejects(
        client.initialize(),
        (error) =>
          error.code === "ERR_FEASIBILITY_TRANSPORT_FAILED" &&
          error.readerReason === "total-bound",
      );
      await assert.rejects(
        client.close(),
        (error) => error.readerReason === "total-bound",
      );
    },
    createNativeDiagnosticWriter((bytes) => chunks.push(bytes)),
  );
  const captured = Buffer.concat(chunks);
  assert.ok(captured.includes(raw));
  assert.match(captured.toString(), /truncated: true/u);
});
const GIT_RUNTIME_OPERATIONS = [
  "git-stdio-io",
  "git-random-read",
  "git-winsock-init",
  "git-console-init",
];

test("Windows fragmented refusal latches before owner teardown and retains cleanup after partial JSON", async () => {
  const f = windowsSessionFixture(),
    waiting = f.session.next();
  const primary = windowsDiagnostic("bundle-read-size", "invariant", 31);
  const teardown = new Promise((resolve) =>
    f.child.stdin.once("finish", () => {
      f.child.stdin.emit(
        "error",
        Object.assign(new Error("Owner input closed"), { code: "EPIPE" }),
      );
      f.child.stderr.write(windowsDiagnostic("owner-read", "win32", 109));
      f.child.stderr.write("native-windows-cleanup: operation=file-close ");
      f.child.stderr.write("domain=win32 value=6\n");
      f.child.stderr.write(
        "native-windows-cleanup: operation=job-close domain=win32 value=6\n",
      );
      f.close();
      resolve();
    }),
  );
  f.child.stdout.write('{"event":"suspended"');
  f.child.stderr.write(primary.slice(0, 19));
  assert.equal(f.child.stdin.writableEnded, false);
  f.child.stderr.write(primary.slice(19));
  assert.equal(f.child.stdin.writableEnded, true);
  let first;
  assert.throws(
    () => f.session.send("G"),
    (error) => {
      first = error;
      assert.equal(error.stderr, primary);
      return true;
    },
  );
  await assert.rejects(waiting, (error) => error === first);
  await teardown;
  await assert.rejects(f.session.finish(0), (error) => {
    assert.equal(error, first);
    assert.equal(error.nativeRejection, undefined);
    assert.equal(error.nativeStreamInvalid, true);
    assert.equal(error.exitCode, 126);
    assert.equal(error.signal, null);
    const diagnosis = windowsFeasibilityDiagnostics(error.stderr);
    assert.equal(diagnosis.failure.operation, "bundle-read-size");
    assert.equal(diagnosis.cleanup.operation, "file-close");
    assert.doesNotMatch(
      windowsFeasibilityCause("read", error).detail,
      /owner-read|EPIPE/u,
    );
    return true;
  });
});

test("Windows refusal rejects queued and pending receipts even with valid trailing output or exit zero", async () => {
  for (const [pending, code, signal] of [
    [false, 0, null],
    [true, null, "SIGTERM"],
  ]) {
    const f = windowsSessionFixture();
    const waiting = pending ? f.session.next() : null;
    f.child.stdout.write('{"event":"ready"}\n');
    f.child.stderr.write(windowsDiagnostic("git-process-exit", "exit", 128));
    let first;
    await assert.rejects(waiting ?? f.session.next(), (error) => {
      first = error;
      return true;
    });
    f.child.stdout.write('{"event":"closed"}\n');
    assert.throws(
      () => f.session.send("Q"),
      (error) => error === first,
    );
    let checked = false;
    assert.throws(
      () =>
        f.session.checkGitReceipt(() => {
          checked = true;
        }),
      (error) => error === first,
    );
    assert.equal(checked, false);
    f.close(code, signal);
    await assert.rejects(f.session.next(), (error) => error === first);
    await assert.rejects(f.session.finish(1), (error) => {
      assert.equal(error, first);
      assert.equal(error.exitCode, code);
      assert.equal(error.signal, signal);
      assert.equal(error.nativeStreamInvalid, undefined);
      assert.equal(
        windowsFeasibilityDiagnostics(error.stderr).failure.operation,
        "git-process-exit",
      );
      return true;
    });
  }
});

test("Windows stderr sequences stay bounded and incomplete trailing diagnostics cannot disappear after refusal", async () => {
  const primary = windowsDiagnostic("git-process-exit", "exit", 128),
    cleanup =
      "native-windows-cleanup: operation=job-close domain=win32 value=6\n";
  for (const [chunks, rejection, nativeFirst] of [
    [[primary + primary + primary], "diagnostic-form", true],
    [[primary + cleanup + cleanup], "diagnostic-form", true],
    [[cleanup], "diagnostic-form", false],
    [
      [primary, "native-windows: operation=owner-read"],
      "diagnostic-form",
      true,
    ],
    [[primary, "x".repeat(4096)], "diagnostic-bound", true],
  ]) {
    const f = windowsSessionFixture(),
      waiting = f.session.next();
    for (const chunk of chunks) f.child.stderr.write(chunk);
    f.close(0);
    await assert.rejects(waiting);
    await assert.rejects(f.session.finish(0), (error) => {
      assert.equal(error.nativeStreamInvalid, true);
      assert.equal(error.nativeRejection, nativeFirst ? undefined : rejection);
      assert.equal(error.nativeDiagnosticInvalid, !nativeFirst);
      assert.ok(Buffer.byteLength(error.stderr) <= 4096);
      if (nativeFirst)
        assert.equal(
          windowsFeasibilityDiagnostics(error.stderr).failure.operation,
          "git-process-exit",
        );
      return true;
    });
  }
});

test("Windows relayed payload failure survives owner loss without becoming a JSON stream error", async () => {
  for (const line of [
    windowsDiagnostic("bundle-read-size", "invariant", 31),
    windowsDiagnostic("payload-job", "win32", 5),
    windowsDiagnostic("forward-write", "win32", 6),
    windowsDiagnostic("git-null-input", "win32", 5),
    windowsDiagnostic("git-process-exit", "exit", 128).replace("\n", "\r\n"),
    windowsDiagnostic("git-dubious-owner", "exit", 128),
    windowsDiagnostic("git-home-missing", "exit", 128),
    windowsDiagnostic("git-path-read", "exit", 128),
    windowsDiagnostic("git-cwd-read", "exit", 128),
    windowsDiagnostic("git-path-normalize", "exit", 128),
    windowsDiagnostic("git-index-read", "exit", 128),
    ...GIT_RUNTIME_OPERATIONS.map((operation) =>
      windowsDiagnostic(operation, "exit", 128),
    ),
    windowsDiagnostic("git-stderr-fatal", "exit", 128),
    windowsDiagnostic("git-stderr-invalid", "exit", 128),
    windowsDiagnostic("git-image-equal", "invariant", 0),
  ]) {
    const f = windowsSessionFixture();
    f.session.send("G");
    f.child.stdout.write('{"event":"attempt","operation":"git-status"}\n');
    assert.equal((await f.session.next()).operation, "git-status");
    const waiting = f.session.next();
    f.child.stderr.write(line.slice(0, 11));
    const combinedCleanup = line.includes("git-home-missing")
      ? "native-windows-cleanup: operation=git-thread-close domain=win32 value=6\n"
      : "";
    f.child.stderr.write(line.slice(11) + combinedCleanup);
    await assert.rejects(waiting, (error) => {
      assert.equal(error.nativeStreamInvalid, undefined);
      assert.equal(error.stderr, line + combinedCleanup);
      return true;
    });
    const payloadClose =
      line.includes("git-path-read") ||
      line.includes("git-index-read") ||
      GIT_RUNTIME_OPERATIONS.some((operation) => line.includes(operation));
    const cleanupOperation = payloadClose
      ? "git-process-close"
      : combinedCleanup
        ? "git-thread-close"
        : "job-close";
    if (payloadClose) {
      f.child.stderr.write(
        "native-windows-cleanup: operation=git-process-close ",
      );
      f.child.stderr.write("domain=win32 value=6\n");
    }
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
      assert.equal(diagnosis.cleanup.operation, cleanupOperation);
      return true;
    });
  }
  const invalid = windowsSessionFixture();
  const waiting = invalid.session.next();
  invalid.child.stderr.write("native-windows: private unrecognized payload\n");
  await assert.rejects(waiting, { nativeStreamInvalid: true });
  invalid.close();
  const invalidCleanup = windowsSessionFixture();
  const cleanupRead = invalidCleanup.session.next();
  const first = windowsDiagnostic("git-process-exit", "exit", 128);
  invalidCleanup.child.stderr.write(
    first + "native-windows-cleanup: private details\n",
  );
  await assert.rejects(cleanupRead, (error) => {
    assert.equal(error.nativeStreamInvalid, true);
    assert.equal(error.stderr, first);
    return true;
  });
  invalidCleanup.close();
});

test("bundle principal storage survives Git completion through its last TCP consumer", async () => {
  const source = await readFile(
    new URL("../ci/native/win32/feasibility-helper.c", import.meta.url),
    "utf8",
  );
  const bundle = source.slice(
    source.indexOf("static void bundle("),
    source.indexOf("static void fault("),
  );
  const acquisition = bundle.slice(
    bundle.indexOf("  TOKEN_USER *ownUser"),
    bundle.indexOf("  HANDLE executable"),
  );
  const input = bundle.slice(
    bundle.indexOf("  win32_check(SetHandleInformation"),
    bundle.indexOf("  puts("),
  );
  const completion = bundle.slice(bundle.lastIndexOf("  BOOL closed = "));
  const probe = bundle.slice(
    bundle.indexOf("    BOOL closed = "),
    bundle.indexOf("  if (code != 0)"),
  );
  const native = (text) =>
    text
      .replace(/\bTOKEN_USER \*|\bTOKEN_APPCONTAINER_INFORMATION \*/gu, "let ")
      .replaceAll("->", ".")
      .replace(/\bBOOL\b/gu, "let")
      .replace(/&transport\.([\w.]+)/gu, (_, slot) => JSON.stringify(slot))
      .replace(/&(userText|appText)/gu, 'globalThis, "$1"')
      .replaceAll('L"', '"')
      .replace(/#(?:ifndef NATIVE_COMMAND_EXPERIMENT|endif)/gu, "");
  for (const mode of ["read", "edit", "null-probe"]) {
    const user = { User: { Sid: { live: true } } },
      app = { TokenAppContainer: { live: true } },
      allocations = [user.User.Sid, app.TokenAppContainer],
      order = [];
    let inherited = true;
    const context = {
      token: 91,
      TokenUser: 1,
      TokenAppContainerSid: 31,
      workspaceRole: mode,
      FALSE: false,
      TRUE: true,
      NULL: null,
      code: 0,
      port: "32100",
      pipe: "unused",
      nonce: "a".repeat(32),
      GetStdHandle: () => 56,
      STD_INPUT_HANDLE: -10,
      HANDLE_FLAG_INHERIT: 1,
      SetHandleInformation(handle, mask, flags) {
        assert.deepEqual([handle, mask, flags], [56, 1, 0]);
        inherited = false;
        return true;
      },
      info: (token, kind) => {
        assert.equal(token, 91);
        return kind === 1 ? user : app;
      },
      IsValidSid: (sid) => sid?.live,
      ConvertSidToStringSidW(sid, globals, key) {
        globals[key] = { live: true, sid };
        allocations.push(globals[key]);
        return true;
      },
      CloseHandle: (token) => token === 91,
      win32_check: assert.ok,
      invariant: assert.ok,
      failure: () => assert.fail("Unexpected native refusal"),
      release_handle: () => true,
      wcscmp: (left, right) => (left === right ? 0 : 1),
      receipt: (operation) => order.push(operation),
      write_attempt: () => {},
      attempt: () => {},
      ack: (command) => order.push(command),
      connection(tcp) {
        assert.equal(context.userSid, user.User.Sid);
        assert.equal(context.appSid, app.TokenAppContainer);
        assert.ok(allocations.every((value) => value.live));
        assert.equal(
          inherited,
          false,
          "Git cannot inherit the bundle's input reader",
        );
        order.push(tcp ? "tcp-token-read" : "pipe");
        return tcp ? 10013 : 5;
      },
      free(value) {
        const allocation =
          value === user ? user.User.Sid : app.TokenAppContainer;
        assert.equal(allocation.live, true);
        allocation.live = false;
      },
      LocalFree(value) {
        assert.equal(value.live, true);
        value.live = false;
      },
    };
    const tail = (mode === "null-probe" ? probe : completion).replace(
      /\n\s*\}\s*$/u,
      "",
    );
    new Script(
      `(function(){${native(input + acquisition + tail)}})()`,
    ).runInNewContext(context);
    assert.equal(inherited, false);
    assert.ok(allocations.every((value) => !value.live));
    assert.equal(context.userSid, null);
    assert.equal(context.appSid, null);
    assert.deepEqual(
      order,
      mode === "null-probe"
        ? []
        : ["git-status", "O", "tcp-token-read", "tcp", "pipe", "pipe"],
    );
  }
});

test("original Git completion clears retained handles before refusal cleanup", async () => {
  const source = await readFile(
    new URL("../ci/native/win32/feasibility-helper.c", import.meta.url),
    "utf8",
  );
  const begin = source.lastIndexOf(
    "  BOOL closed = ",
    source.indexOf("static void fault("),
  );
  assert.ok(begin >= 0);
  const cleanup = source
    .slice(begin, source.indexOf('  receipt("git-status", 0);', begin))
    .replace(/\bBOOL\b/gu, "let")
    .replace(/\bFALSE\b/gu, "false")
    .replace(/&transport\.([\w.]+)/gu, (_, slot) => JSON.stringify(slot));
  for (const code of [0, 128]) {
    const slots = new Map(
      [
        "gitDiagnosticRead",
        "child.hThread",
        "child.hProcess",
        "executable",
        "workspacePhysical",
        "workspaceLogical",
      ].map((slot, index) => [slot, index + 1]),
    );
    const closed = new Set(),
      refusal = new Error("Original Git exit 128");
    const close_handle = (handle) => {
      assert.equal(closed.has(handle), false, "Handle closed twice");
      closed.add(handle);
      return true;
    };
    const release_handle = (slot) => {
      const handle = slots.get(slot);
      slots.set(slot, null);
      return !handle || close_handle(handle);
    };
    const execute = () =>
      new Script(cleanup).runInNewContext({
        code,
        diagnosticRead: slots.get("gitDiagnosticRead"),
        child: {
          hThread: slots.get("child.hThread"),
          hProcess: slots.get("child.hProcess"),
        },
        close_handle,
        release_handle,
        failure: () => {
          for (const slot of slots.keys()) release_handle(slot);
          throw refusal;
        },
      });
    if (code) assert.throws(execute, (error) => error === refusal);
    else execute();
    assert.equal(closed.size, slots.size);
    assert.ok([...slots.values()].every((handle) => handle === null));
  }
});

test("Windows helper failures before the first record retain their operation through pending reads and completion", async () => {
  for (const [operation, domain, value, code] of [
    ["acl-read", "win32", 5, 126],
    ["acl-entries", "invariant", 0, 126],
    ["socket-source-descriptor", "win32", 5, 126],
    ["socket-source-descriptor", "invariant", 0, 126],
    ["socket-source-grant", "win32", 5, 126],
    ["socket-source-acl", "win32", 5, 126],
    ["socket-source-acl", "invariant", 0, 126],
    ["observer-source-open", "win32", 5, 126],
    ["observer-source-close", "win32", 6, 126],
    ["hash-create", "ntstatus", 0xc000000d, 126],
    ["profile-derive", "hresult", 0x80004001, 78],
    ["thread-query", "ntstatus", 0xc0000003, 78],
    ["local-appdata", "win32", 203, 78],
    ["local-appdata", "invariant", 0, 78],
    ["git-null-input", "win32", 5, 126],
    ["git-process-create", "win32", 203, 126],
    ["git-process-exit", "exit", 128, 126],
    ["git-cwd-read", "exit", 128, 126],
    ["git-path-normalize", "exit", 128, 126],
    ["git-stderr-other-partial", "exit", 128, 126],
    ["original-image-query", "win32", 5, 126],
    ["verifier-image-bound", "invariant", 0, 126],
    ["payload-capabilities", "invariant", 1, 126],
    ["git-diagnostic-read-type", "win32", 6, 126],
    ["git-diagnostic-read-type", "invariant", 1, 126],
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
      assert.equal(error.nativeRejection, undefined);
      assert.equal(error.nativeStreamInvalid, undefined);
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

test("Windows fixed Git predicate failures retain their facts through separate cleanup failure", async () => {
  const f = windowsSessionFixture(),
    waiting = f.session.next();
  const primary = windowsDiagnostic("bundle-read-size", "invariant", 31);
  f.child.stderr.write(primary);
  await assert.rejects(waiting);
  f.child.stderr.write(
    "native-windows-cleanup: operation=file-close domain=win32 value=6\n",
  );
  f.close();
  await assert.rejects(f.session.finish(0), (error) => {
    const parsed = windowsFeasibilityDiagnostics(error.stderr);
    assert.deepEqual(parsed.failure, {
      operation: "bundle-read-size",
      domain: "invariant",
      value: 31,
    });
    assert.deepEqual(parsed.cleanup, {
      operation: "file-close",
      domain: "win32",
      value: 6,
    });
    assert.match(
      windowsFeasibilityCause("read-access-git-status", error).detail,
      /Native bundle-read-size failed \(invariant=31\)/u,
    );
    return true;
  });
});

test("Windows diagnostic grammar rejects malformed, tainted and oversized streams without adopting stale errors", async () => {
  for (const stderr of [
    windowsDiagnostic("foreign-operation", "win32", 5),
    windowsDiagnostic("acl-read", "errno", 5),
    windowsDiagnostic("socket-source-grant", "invariant", 0),
    windowsDiagnostic("observer-source-open", "win32", 0),
    windowsDiagnostic("observer-source-close", "invariant", 0),
    windowsDiagnostic("acl-read", "win32", 0x100000000),
    windowsDiagnostic("acl-entries", "invariant", 203),
    windowsDiagnostic("hash-create", "ntstatus", 5),
    windowsDiagnostic("git-process-exit", "exit", 0),
    windowsDiagnostic("git-process-exit", "win32", 128),
    windowsDiagnostic("git-path-normalize", "exit", 0),
    windowsDiagnostic("git-path-normalize", "win32", 128),
    windowsDiagnostic("git-index-read", "exit", 0),
    windowsDiagnostic("git-index-read", "win32", 128),
    ...GIT_RUNTIME_OPERATIONS.map((operation) =>
      windowsDiagnostic(operation, "win32", 128),
    ),
    windowsDiagnostic("git-runtime-init", "exit", 128),
    windowsDiagnostic("git-console-init", "exit", 128).trimEnd(),
    windowsDiagnostic("git-stdio-io", "exit", 128).replace("128", "12\0"),
    windowsDiagnostic("git-winsock-init", "exit", 128).replace(
      "\n",
      " source=7\n",
    ),
    windowsDiagnostic("git-stderr-fatal", "win32", 128),
    windowsDiagnostic("git-stderr-empty", "exit", 0),
    windowsDiagnostic("launch-image-equal", "win32", 5),
    windowsDiagnostic("git-process-close", "win32", 0),
    windowsDiagnostic("git-thread-close", "ntstatus", 0xc000000d),
    windowsDiagnostic("bundle-read-size", "invariant", 32),
    windowsDiagnostic("payload-capabilities", "invariant", 4097),
    windowsDiagnostic("payload-token", "invariant", 0),
    windowsDiagnostic("stderr-pipe", "win32", 0),
    windowsDiagnostic("diagnostic-forward-read", "invariant", 0),
    windowsDiagnostic("diagnostic-forward-bound", "win32", 5),
    windowsDiagnostic("git-diagnostic-read-type", "invariant", 3),
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
    const nativeFirst =
      typeof stderr === "string" &&
      Buffer.byteLength(stderr) <= 4096 &&
      windowsFeasibilityDiagnostics(stderr.slice(0, stderr.indexOf("\n") + 1));
    await assert.rejects(waiting, (error) => {
      assert.equal(error.nativeDiagnosticInvalid, !nativeFirst);
      assert.equal(error.nativeStreamInvalid, true);
      assert.equal(
        error.nativeRejection,
        nativeFirst
          ? undefined
          : Buffer.byteLength(stderr) > 4096
            ? "diagnostic-bound"
            : "diagnostic-form",
      );
      assert.ok(Buffer.byteLength(error.stderr) <= 4096);
      const cause = windowsFeasibilityCause("literal-argv", {
        ...error,
        nativeError: 203,
      });
      assert.equal(cause.code, "setup-failed");
      assert.match(
        cause.detail,
        nativeFirst
          ? /Native acl-read failed \(win32=5\).*stream rejected/u
          : /diagnostic rejected/u,
      );
      assert.doesNotMatch(cause.detail, /Win32=203|private|S-1-/u);
      return true;
    });
    await assert.rejects(f.session.finish(0));
  }
});

test("Windows native stdout remains strict while successful sessions retain literal arguments", async () => {
  const ready = '{"event":"ready"}\n';
  for (const [stdout, rejection] of [
    [ready, null],
    [ready + "unfinished", "eof"],
    [ready + ready, "record-count"],
    ["invalid\n", "json"],
    [windowsDiagnostic("git-process-exit", "exit", 128), "json"],
    [ready.replace("\n", "\r\n"), "framing"],
    ["x".repeat(65537), "stdout-bound"],
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
        assert.equal(error.nativeRejection, rejection);
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

test("Windows first protocol rejection survives fragmented input and teardown owner-read failure", async () => {
  for (const [chunks, rejection] of [
    [[Buffer.from([0xc3]), Buffer.from([0x28, 10])], "encoding"],
    [['{"event":', '"ready"}\r\n'], "framing"],
    [["{", "private-json}\n"], "json"],
    [['{"event":"ready"}\n{', "private-json}\n"], "json"],
    [["x".repeat(65536), "x"], "stdout-bound"],
    [["native-windows:", "x".repeat(4096) + "\n"], "diagnostic-bound"],
    [null, "git-receipt"],
  ]) {
    const f = windowsSessionFixture();
    const teardown = new Promise((resolve) =>
      f.child.stdin.once("finish", () => {
        f.child.stdin.emit(
          "error",
          Object.assign(new Error("Owner input closed"), { code: "EPIPE" }),
        );
        f.child.stderr.write(windowsDiagnostic("owner-read", "win32", 109));
        f.child.stderr.write(
          "native-windows-output: 61\nnative-windows-output-end: complete\n",
        );
        f.child.stderr.write("native-windows-cleanup: operation=job-close ");
        f.child.stderr.write("domain=win32 value=6\n");
        f.close();
        resolve();
      }),
    );
    const waiting = f.session.next();
    if (chunks)
      for (const chunk of chunks)
        f.child[rejection === "diagnostic-bound" ? "stderr" : "stdout"].write(
          chunk,
        );
    else
      assert.throws(() =>
        f.session.checkGitReceipt(() => {
          throw new Error("private receipt payload");
        }),
      );
    let first;
    await assert.rejects(waiting, (error) => {
      first = error;
      assert.equal(error.nativeRejection, rejection);
      return true;
    });
    await teardown;
    if (rejection.endsWith("bound")) {
      assert.equal(f.session.gitCapture.stderr.truncated, true);
      assert.equal(f.session.gitCapture.stderr.complete, false);
    }
    assert.throws(
      () => f.session.send("R"),
      (error) => error === first,
    );
    await assert.rejects(f.session.finish(1), (error) => {
      assert.equal(error, first);
      assert.equal(error.nativeRejection, rejection);
      assert.equal(error.exitCode, 126);
      if (rejection !== "diagnostic-bound")
        assert.equal(
          windowsFeasibilityDiagnostics(error.stderr).cleanup.operation,
          "job-close",
        );
      const cause = windowsFeasibilityCause("read-access-git-status", error);
      assert.ok(cause.detail.includes(`rejected (${rejection})`));
      assert.doesNotMatch(cause.detail, /owner-read|109|private|payload/u);
      return true;
    });
  }
});

test("Windows observed native-first ordering and unacknowledged EOF remain failures", async () => {
  for (const stream of ["stdout", "stderr"]) {
    const native = windowsSessionFixture(),
      waiting = native.session.next();
    native.child.stderr.write(windowsDiagnostic("owner-read", "win32", 109));
    native.child[stream].write("private-json\n");
    native.close(78);
    await assert.rejects(waiting, (error) => {
      assert.equal(error.nativeRejection, undefined);
      const cause = windowsFeasibilityCause("read", error);
      assert.equal(cause.code, "setup-failed");
      assert.match(cause.detail, /Native owner-read failed \(win32=109\)/u);
      assert.doesNotMatch(cause.detail, /private/u);
      return true;
    });
    await assert.rejects(native.session.finish(1));
  }
  const refusal = windowsSessionFixture();
  refusal.child.stderr.write(
    windowsDiagnostic("profile-derive", "hresult", 0x80004001),
  );
  refusal.close(78);
  let first;
  await assert.rejects(refusal.session.next(), (error) => {
    first = error;
    assert.equal(error.nativeRejection, undefined);
    assert.equal(error.nativeStreamInvalid, undefined);
    assert.equal(
      windowsFeasibilityCause("literal-argv", error).code,
      "prerequisite-unavailable",
    );
    return true;
  });
  await assert.rejects(refusal.session.finish(0), (error) => error === first);
  const eof = windowsSessionFixture();
  eof.child.stdout.write('{"event":"ready"}\n');
  await eof.session.next();
  const acknowledgement = eof.session.next();
  eof.close(0);
  await assert.rejects(acknowledgement, { nativeRejection: "eof" });
  await assert.rejects(eof.session.finish(2), { nativeRejection: "eof" });
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
    /static void need\(bool ok\) \{ invariant\(ok, "helper-invariant"\); \}/u,
  );
  assert.match(launch, /sizeError != ERROR_INSUFFICIENT_BUFFER/u);
  assert.match(launch, /PROC_THREAD_ATTRIBUTE_JOB_LIST/u);
  assert.match(launch, /PROC_THREAD_ATTRIBUTE_HANDLE_LIST/u);
  assert.match(
    launch,
    /CreatePipe\(&transport.errorRead, &transport.errorWrite, &sa, 4096\)/u,
  );
  for (const endpoint of ["write", "read", "errorRead"])
    assert.ok(
      launch.includes(
        `SetHandleInformation(transport.${endpoint}, HANDLE_FLAG_INHERIT, 0)`,
      ),
    );
  assert.match(
    launch,
    /hStdOutput = transport.out; startup.StartupInfo.hStdError = transport.errorWrite/u,
  );
  assert.match(
    launch,
    /HANDLE handles\[\] = \{transport.in, transport.out, transport.errorWrite, gitInput, gitOutput, gitDiagnosticRead, gitDiagnosticWrite\}/u,
  );
  assert.match(launch, /\(gitIo \? 7 : 3\) \* sizeof\(HANDLE\)/u);
  assert.match(launch, /owner_write\(&command, 1\)/u);
  const inputWriter = source.slice(
    source.indexOf("static void owner_write("),
    source.indexOf("static void launch("),
  );
  for (const [owner, operation] of [
    [launch, "ResumeThread(transport.child.hThread)"],
    [inputWriter, "WriteFile(transport.write"],
  ]) {
    assert.ok(owner.includes(operation));
    const before = owner.slice(0, owner.indexOf(operation));
    assert.match(
      before.slice(
        before.lastIndexOf("AcquireSRWLockExclusive(&transportLock)"),
      ),
      /InterlockedCompareExchange\(&failing, 0, 0\)[\s\S]*?ReleaseSRWLockExclusive\(&transportLock\); failure\(126\)/u,
    );
  }
  const forward = source.slice(
    source.indexOf("static DWORD WINAPI forward("),
    source.indexOf("static BOOL caller_directory("),
  );
  assert.match(forward, /WriteFile\(GetStdHandle\(STD_OUTPUT_HANDLE\), bytes/u);
  assert.match(forward, /WriteFile\(GetStdHandle\(STD_ERROR_HANDLE\), line/u);
  assert.ok(
    forward.indexOf("AcquireSRWLockExclusive(&diagnosticOutputLock)") <
      forward.indexOf("STD_ERROR_HANDLE"),
  );
  assert.ok(
    forward.indexOf("STD_ERROR_HANDLE") <
      forward.indexOf("ReleaseSRWLockExclusive(&diagnosticOutputLock)"),
  );
  assert.match(
    source,
    /HANDLE \*threads\[\] = \{&transport.writer, &transport.diagnosticWriter\}/u,
  );
  assert.match(
    source,
    /HANDLE \*reads\[\] = \{&transport.read, &transport.errorRead\}/u,
  );
  assert.match(
    source,
    /transport_wait\(\*threads\[i\], expires, "forward-wait"\)/u,
  );
  assert.match(source, /release_handle\(reads\[i\], "forward-close"\)/u);
  const closeObserver =
    /if \(!transport\.diagnosticWriter && !wfp_close\(\)\) ok = FALSE;/u.exec(
      source,
    )[0];
  for (const [active, closed] of [
    [false, true],
    [false, false],
    [true, false],
  ]) {
    let calls = 0;
    const context = {
      transport: { diagnosticWriter: active ? 17 : null },
      ok: !active,
      FALSE: false,
      wfp_close: () => {
        calls++;
        return closed;
      },
    };
    new Script(closeObserver).runInNewContext(context);
    assert.equal(calls, active ? 0 : 1);
    assert.equal(context.ok, !active && closed);
  }
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
      source.indexOf("static DWORD git_environment("),
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
      "NATIVE_FEASIBILITY_SOCKET_OWNER",
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
  assert.match(environment, /GetWindowsDirectoryW\(actual, 4096\)/u);
  assert.match(
    environment,
    /GetEnvironmentVariableW\(L"SystemRoot", windows, 4096\)/u,
  );
  assert.match(environment, /!_wcsicmp\(windows, actual\)/u);
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

test("Windows fixed Git is verified suspended before release and drains bounded stderr during execution", async () => {
  const source = await readFile(
    new URL("../ci/native/win32/feasibility-helper.c", import.meta.url),
    "utf8",
  );
  const wait = source.slice(
    source.indexOf("static DWORD git_wait("),
    source.indexOf("static void launch("),
  );
  assert.ok(
    wait.indexOf("PeekNamedPipe(") < wait.indexOf("WaitForSingleObject("),
  );
  assert.match(wait, /available <= 65536 - captured/u);
  assert.match(wait, /GetTickCount64\(\) < expires/u);
  assert.ok(
    wait.indexOf("GetTickCount64() < expires") < wait.indexOf("PeekNamedPipe("),
  );
  assert.ok(wait.indexOf("GetExitCodeProcess(") > wait.indexOf("ReadFile("));
  const bundle = source.slice(
    source.indexOf("static void bundle("),
    source.indexOf("static void fault("),
  );
  assert.match(
    bundle,
    /CREATE_SUSPENDED \| CREATE_NO_WINDOW \| CREATE_UNICODE_ENVIRONMENT/u,
  );
  assert.match(
    bundle,
    /environment, workspaceEntered \? L"W:\\\\" : workspace, &startup.StartupInfo, &child/u,
  );
  assert.match(bundle, /container\(child.hProcess\)/u);
  assert.match(bundle, /IsProcessInJob\(child.hProcess, NULL, &member\)/u);
  assert.match(
    bundle,
    /HANDLE allow\[\] = \{input, output, diagnosticWrite\}/u,
  );
  assert.ok(
    bundle.indexOf("ack('G')") < bundle.indexOf("ResumeThread(child.hThread)"),
  );
  assert.ok(
    bundle.indexOf("git_wait(child.hProcess") >
      bundle.indexOf("ResumeThread(child.hThread)"),
  );
  assert.ok(
    bundle.indexOf('remember(reason, "exit", code)') <
      bundle.lastIndexOf("release_handle(&transport.gitDiagnosticRead"),
  );
  assert.ok(
    bundle.indexOf("if (code || !closed) failure(126)") <
      bundle.indexOf('receipt("git-status", 0)'),
  );
  assert.doesNotMatch(
    bundle,
    /CREATE_BREAKAWAY_FROM_JOB|SetFileSecurity|printf\([^\n]*diagnostic/u,
  );
  const admission = source.slice(
    source.indexOf("static void observe("),
    source.indexOf("static int connection("),
  );
  assert.match(admission, /if \(git\)[\s\S]*container\(source\)/u);
  assert.match(admission, /git \? L"build\\\\git.exe"/u);
  assert.match(admission, /IsProcessInJob\(child, job, &member\)/u);
  assert.match(admission, /count == 1, "thread-state"/u);
  const driver = await readFile(
    new URL("../ci/native/win32/feasibility.js", import.meta.url),
    "utf8",
  );
  assert.match(driver, /validateWindowsFeasibilityGitStart\(\{\s+root,/u);
  const validation = driver.indexOf("validateWindowsFeasibilityGitStart({"),
    unchanged = driver.indexOf(
      "const currentGitFiles = await gitFiles();",
      validation,
    ),
    persisted = driver.indexOf(
      "await persist(`${mode}-git-start`, gitStart);",
      unchanged,
    ),
    released = driver.indexOf('run.session.send("G");', persisted);
  assert.ok(validation >= 0 && unchanged > validation);
  assert.ok(persisted > unchanged && released > persisted);
  assert.ok(
    driver
      .slice(unchanged, persisted)
      .includes("hash(currentGitFiles) === hash(gitBefore)"),
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
    const probe = await runWindowsFeasibility(
      {},
      {},
      { nullDeviceProbe: true },
    );
    assert.equal(probe.imageBinding.status, "unavailable");
    assert.equal(probe.imageBinding.query, null);
    assert.equal(probe.imageBinding.expected.available, false);
    assert.equal(probe.imageBinding.actual.available, false);
    assert.equal(probe.cwdObservation.status, "unavailable");
    assert.equal(probe.cwdObservation.owner, null);
    assert.deepEqual(probe.cwdObservation.calls, {});
    assert.equal(probe.cleanup.status, "NOT_RUN");
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
  const metadata =
    "native-darwin-fault-metadata: object=created-root uid=0 gid=20 mode=040700 links=2 size=64 dev=1 inode=42\n" +
    "native-darwin-fault-access: name=200 type=0x10000 query=0\n" +
    "native-darwin-fault-port: name=111 census-type=0x10000 type-query=0 type=0x10000 object-query=0 object-kind=2 object=42\n" +
    "native-darwin-fault-access-lifecycle: phase=payload pid=42 parent=9000 uid=90001 euid=90001 gid=90002 egid=90002 get=0 name=200 type=0x10000 query=0 release=0\n" +
    "native-darwin-fault-access-lifecycle: phase=unknown get=0 malformed\n";
  for (const [operation, domain, value] of [
    ["fault-journal-access", "invariant", 0],
    ["fault-journal-owner", "errno", 1],
    ["fault-journal-mode", "errno", 5],
    ["fault-journal-write", "errno", 9],
    ["fault-lease-owner", "errno", 1],
    ["fault-lease-mode", "errno", 5],
    ["fault-root-owner", "errno", 1],
    ["fault-birth-read", "status", 0],
    ["fault-child-status", "status", 256],
    ["fault-host-port", "mach", 5],
    ["fault-port-owner", "invariant", 0],
    ["fault-reply-port", "invariant", 0],
    ["fault-special-reply-port", "invariant", 0],
    ["fault-runtime-reply-port", "invariant", 0],
    ["fault-thread-port", "invariant", 0],
    ["fault-bootstrap-release", "mach", 15],
    ["fault-access-kind", "mach", 15],
    ["fault-access-service", "mach", 15],
    ["fault-access-authority", "invariant", 0],
    ["fault-access-release", "mach", 15],
    ["fault-notify-get", "mach", 4],
    ["fault-notify-port", "mach", 4],
    ["fault-notify-read", "mach", 5],
    ["fault-notify-read", "invariant", 0],
    ["fault-notify-release", "mach", 15],
    ["fault-port-authority", "invariant", 0],
    ["audit-session-create", "errno", 1],
    ["audit-census-bsd", "status", 12],
    ["audit-census-audit-again", "errno", 3],
  ]) {
    const cause = darwinFeasibilityCause("cancel", {
      code: 126,
      stderr:
        metadata +
        `native-darwin: operation=${operation} domain=${domain} value=${value} effects=possible settlement=unsettled\n`,
    });
    assert.ok(
      cause.detail.includes(`Native ${operation} failed (${domain}=${value})`),
      cause.detail,
    );
  }
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
    metadata,
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
    darwinFeasibilityCause("cancel", {
      code: 126,
      stderr:
        "native-darwin: operation=fault-lease-shape domain=invariant value=0 effects=possible settlement=unsettled\n",
    }),
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
    assert.equal(assessment.report.results[0].cleanup.status, "UNCERTAIN");
    assert.equal(assessment.report.results[0].cleanup.independent, false);
    for (const entry of assessment.report.results.filter(({ capability }) =>
      feasibilityCapabilities("darwin").some(
        ({ id, tier }) => id === capability && tier !== "native",
      ),
    )) {
      assert.equal(entry.status, "BLOCKED");
      assert.equal(entry.cause.code, "prerequisite-unavailable");
      assert.ok(
        entry.cause.detail.includes(
          `origin=setup-failed; ${cause.detail.split(":")[0]}:`,
        ),
      );
      if (cause.detail.includes("task-audit"))
        assert.match(
          entry.cause.detail,
          /Native task-audit failed \(mach=5\)/u,
        );
      if (cause.detail.includes("fault-lease-shape"))
        assert.match(
          entry.cause.detail,
          /Native fault-lease-shape failed \(invariant=0\)/u,
        );
      assert.ok(Buffer.byteLength(entry.cause.detail) <= 256);
      assert.equal(entry.cause.detail.isWellFormed(), true);
      assert.equal(entry.cleanup.status, "NOT_RUN");
    }
  }
});

test("Darwin failed builds settle fixed preparation outputs without promoting crashed compiler cleanup", async () => {
  for (const [code, expected, laterUnsettled = false] of [
    ["setup-failed", "PASS"],
    ["deadline", "UNCERTAIN"],
    ["crash", "UNCERTAIN"],
    ["setup-failed", "UNCERTAIN", true],
  ]) {
    const injected = darwinPreparationEffects(),
      build = injected.options.build;
    const first = {
      code,
      detail: "build helper-compile-link: fixed synthetic failure.",
    };
    injected.options.build = async (...args) => {
      await build(...args);
      const original = Object.assign(new Error("Synthetic compiler failure"), {
        code: 1,
        signal: null,
      });
      if (laterUnsettled)
        await assert.rejects(
          attemptNativeBuilds("build-fixture", [
            {
              name: "first",
              run: async () => {
                throw original;
              },
            },
            {
              name: "later",
              run: async () => {
                throw new Error("Unsettled later compiler");
              },
            },
          ]),
          (error) => error === original,
        );
      throw Object.assign(
        new Error("Synthetic build failure", { cause: original }),
        {
          feasibilityCause: first,
        },
      );
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

test("workspace-rooted release requires distinct successful target assignments and readiness", async () => {
  const identity = (pid) => ({
    pid,
    creationTime: String(pid),
    sessionId: 1,
    userSid: "S-1-5-21-1000",
  });
  const settled = {
    independent: true,
    jobEmpty: true,
    processRetired: true,
    resourcesClosed: true,
    endpointAbsent: true,
    holderRetired: true,
    outsideUnchanged: true,
  };
  for (const [bound, ready, payloadSet, gitSet, distinct] of [
    [true, true, true, true, true],
    [false, true, true, true, true],
    [true, false, true, true, true],
    [true, true, false, true, true],
    [true, true, true, false, true],
    [true, true, true, true, false],
  ]) {
    const expected = bound && ready && payloadSet && gitSet && distinct;
    const probe = await observeWindowsGitNullProbe({
      caseId: "workspace-rooted",
      start: async () => ({
        receipt: { child: identity(41) },
        gitStarted: { child: identity(42) },
      }),
      bind: async () => ({
        bound,
        mappedSetup: true,
        setSucceeded: payloadSet,
        workspaceReady: ready,
        payloadAssignment: { setSucceeded: payloadSet, identity: identity(41) },
        gitAssignment: {
          setSucceeded: gitSet,
          identity: identity(distinct ? 42 : 41),
        },
      }),
      execute: async (release) => {
        assert.equal(release, expected);
        return { ran: release, exitCode: release ? 0 : null };
      },
      retire: async () => settled,
    });
    assert.equal(probe.git.ran, expected);
    assert.equal(probe.reusable, true);
  }
});

test("workspace holder exchange is one-shot and cwd context stays confined through refused-start capture", async () => {
  const target = {
    process: "11",
    thread: "12",
    child: {
      pid: 43,
      creationTime: "13",
      sessionId: 1,
      userSid: "S-1-5-21-1000",
    },
  };
  for (const probeCase of ["workspace-rooted", "shadow", "no-shadow-mapped"]) {
    const f = windowsSessionFixture(
      windowsCallerEnvironment,
      undefined,
      probeCase,
    );
    try {
      if (probeCase === "workspace-rooted") {
        f.session.sendTarget(target);
        assert.deepEqual(f.sent, ["T11 13 12 43\n"]);
        assert.throws(() => f.session.sendTarget(target));
      } else assert.throws(() => f.session.sendTarget(target));
    } finally {
      f.close(0);
      await f.session.finish(0);
    }
  }
  for (const rooted of [false, true]) {
    const f = windowsSessionFixture(
      windowsCallerEnvironment,
      undefined,
      undefined,
      rooted,
    );
    const frames = windowsCwdFrames().replace(
      "context=payload-original",
      "context=payload-private-workspace-rooted",
    );
    const split = frames.indexOf("native-windows-cwd: open");
    const primary = windowsDiagnostic("owner-read", "win32", 109);
    const pending = f.session.next();
    f.child.stderr.write(frames.slice(0, split) + primary);
    await assert.rejects(pending);
    f.child.stderr.write(frames.slice(split));
    f.close(126);
    if (rooted) await f.session.drainRefused();
    assert.equal(
      f.session.cwdObservation.status,
      rooted ? "complete" : "incomplete",
    );
    if (rooted)
      assert.equal(
        f.session.cwdObservation.context,
        "payload-private-workspace-rooted",
      );
    await assert.rejects(
      f.session.finish(0),
      (error) => error.stderr === primary,
    );
  }
});

function workspaceGitFixture() {
  const root = "C:\\owned\\probe",
    workspace = root + "\\workspace",
    build = root + "\\build";
  const identity = (pid) => ({
    pid,
    creationTime: String(pid),
    sessionId: 1,
    userSid: "S-1-5-21-1000",
  });
  const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
  const args = [
    "-c",
    "core.fsmonitor=false",
    "-c",
    "safe.directory=.",
    "--git-dir",
    ".git",
    "--work-tree",
    ".",
    "status",
    "--porcelain",
  ];
  const env = {
    GIT_ATTR_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: workspace + "\\.git\\runner-global.conf",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_OPTIONAL_LOCKS: "0",
    GIT_TERMINAL_PROMPT: "0",
    HOME: workspace,
    LANG: "C",
    LC_ALL: "C",
    LOCALAPPDATA: workspace,
    PATH: build + ";C:\\Windows\\System32",
    SystemRoot: "C:\\Windows",
    TEMP: workspace,
    TMP: workspace,
    USERPROFILE: workspace,
    XDG_CONFIG_HOME: workspace,
  };
  const files = [DIGEST, null, null, digest(Buffer.alloc(0)), DIGEST].map(
    (sha256, index) => ({
      identity: "a".repeat(16) + ":" + String(index + 1).repeat(32),
      private: false,
      sha256,
    }),
  );
  const image = build + "\\git.exe";
  const started = {
    event: "git-started",
    suspended: true,
    capabilities: 0,
    sid: "S-1-15-2-1-2-3-4-5-6-7",
    owner: identity(42),
    child: identity(43),
    image: files[0],
    cwd: files[1],
    metadata: files[2],
    config: files[3],
    repositoryConfig: files[4],
    commandSha256: digest(
      Buffer.from(
        [image, ...args].map(quoteWindowsArgument).join(" "),
        "utf16le",
      ),
    ),
    environmentSha256: digest(
      Buffer.from(
        Object.entries(env)
          .map(([key, value]) => `${key}=${value}`)
          .join("\0") + "\0\0",
        "utf16le",
      ),
    ),
  };
  const evidence = {
    root,
    files,
    prepared: {
      image,
      manifest: [{ name: "git.exe", sha256: DIGEST }],
      invocation: { cwd: workspace, env, args },
      repositorySha256: DIGEST,
    },
    receipt: { owner: identity(41), child: identity(42), sid: started.sid },
    started,
    admission: {
      admitted: true,
      suspended: true,
      capabilities: 0,
      sid: started.sid,
      child: identity(43),
      verifier: identity(44),
      image: files[0],
    },
  };
  const nativePath = "\\Device\\HarddiskVolume4\\owned\\probe\\workspace";
  const trusted = {
    identity: files[1].identity,
    nativePathUtf16: [...nativePath]
      .map((unit) => unit.charCodeAt(0).toString(16).padStart(4, "0"))
      .join(""),
  };
  return { evidence, trusted, identity };
}

test("workspace logical cwd needs independent full held proof while every original Git input remains fixed", () => {
  const { evidence, trusted, identity } = workspaceGitFixture();
  assert.doesNotThrow(() => validateWindowsFeasibilityGitStart(evidence));
  const rooted = {
    ...structuredClone(evidence),
    caseId: "workspace-rooted",
    workspaceProof: {
      ready: true,
      trusted,
      held: structuredClone(trusted),
      payloadTarget: identity(42),
      holder: identity(45),
      trustedVerifier: identity(46),
    },
  };
  rooted.started.logicalCwd = "W:\\";
  rooted.started.workspaceBinding = structuredClone(trusted);
  assert.doesNotThrow(() => validateWindowsFeasibilityGitStart(rooted));
  for (const mode of ["read", "edit"]) {
    const bundle = structuredClone(rooted);
    bundle.caseId = bundle.started.workspaceRole = mode;
    assert.doesNotThrow(() => validateWindowsFeasibilityGitStart(bundle));
    bundle.started.workspaceRole = mode === "read" ? "edit" : "read";
    assert.throws(() => validateWindowsFeasibilityGitStart(bundle));
  }
  for (const mutate of [
    (v) => {
      v.caseId = null;
    },
    (v) => {
      v.workspaceProof.ready = false;
    },
    (v) => {
      v.workspaceProof.held.identity = "b".repeat(16) + ":" + "b".repeat(32);
    },
    (v) => {
      v.workspaceProof.held.nativePathUtf16 += "0061";
    },
    (v) => {
      v.started.workspaceBinding.nativePathUtf16 += "0061";
    },
    (v) => {
      v.workspaceProof.payloadTarget = identity(43);
    },
    (v) => {
      v.workspaceProof.holder = identity(46);
    },
    (v) => {
      v.started.logicalCwd = v.prepared.invocation.cwd;
    },
    (v) => {
      v.prepared.invocation.env.HOME = "W:\\";
    },
    (v) => {
      v.prepared.invocation.args[3] = "safe.directory=*";
    },
    (v) => {
      v.started.cwd.identity = "b".repeat(49);
    },
  ]) {
    const changed = structuredClone(rooted);
    mutate(changed);
    assert.throws(() => validateWindowsFeasibilityGitStart(changed));
  }
});

test("actual workspace owner keeps both suspended SET gates and partial resources behind whole-Job retirement", async () => {
  const header = await readFile(
    new URL("../ci/native/win32/feasibility-null-probe.h", import.meta.url),
    "utf8",
  );
  const helper = await readFile(
    new URL("../ci/native/win32/feasibility-helper.c", import.meta.url),
    "utf8",
  );
  const driver = await readFile(
    new URL("../ci/native/win32/feasibility.js", import.meta.url),
    "utf8",
  );
  const collision =
    /if \((count \|\| error != ERROR_FILE_NOT_FOUND)\) goto refused;/u.exec(
      header,
    );
  assert.ok(collision);
  for (const [count, error, refused] of [
    [0, 2, false],
    [1, 0, true],
    [0, 5, true],
  ])
    assert.equal(
      Boolean(
        new Script(collision[1]).runInNewContext({
          count,
          error,
          ERROR_FILE_NOT_FOUND: 2,
        }),
      ),
      refused,
    );
  assert.match(header, /null_drives\[i\]\.letter == L'W'/u);
  assert.match(
    header,
    /!null_same\(&value\.proof, &null_paths\[2\]\.heldProof\)/u,
  );
  assert.match(
    header,
    /!null_same\(&value\.proof, &null_paths\[2\]\.reachedProof\)/u,
  );
  assert.match(header, /_wcsicmp\(value\.proof\.path, reached \+ 14\)/u);
  assert.match(
    header,
    /status = query\(\*thread, 35, &count, sizeof\(count\), NULL\)/u,
  );
  assert.match(header, /count != 1 \|\| threadPid != targetPid/u);
  assert.match(
    header,
    /!pid \|\| targetPid != pid \|\| \(git && targetPid == GetProcessId\(null_owned\.child\)\)/u,
  );
  const set = header.indexOf("setMap(null_owned.child"),
    links = header.indexOf("!null_link_drives(", set);
  const targetCheck = header.lastIndexOf("!null_target(null_owned.source", set);
  assert.ok(targetCheck > 0 && targetCheck < set && set < links);
  assert.ok(
    header.indexOf('null_recheck("before-git")') <
      header.indexOf("setMap(null_owned.git"),
  );
  assert.match(
    header,
    /if \(admitted\) \{[\s\S]*setMap\(null_owned\.git, 23, &gitMap\.Set, sizeof\(gitMap\.Set\)\)/u,
  );
  assert.match(
    header,
    /transport_wait\(null_owned\.git, expires, "null-retirement"\)/u,
  );
  assert.ok(
    header.indexOf("if (!retired)") <
      header.indexOf("release_handle(mapped[j]"),
  );
  assert.match(header, /if \(retainUnsettledMap\) return FALSE;/u);
  assert.match(
    header,
    /workspaceRole && null_owned\.job && !null_retirementReleased/u,
  );
  assert.ok(
    helper.indexOf("if (retainUnsettledMap) Sleep(INFINITE)") <
      helper.indexOf("ExitProcess(code)"),
  );
  const owner = await readFile(
    new URL("../ci/native/win32/feasibility-workspace.js", import.meta.url),
    "utf8",
  );
  const mappingIntent = owner.indexOf("`${caseId}-workspace-map-possible`");
  assert.ok(
    mappingIntent > 0 &&
      mappingIntent < owner.indexOf("acquisitions.mappingPossible = true"),
  );
  assert.ok(
    owner.includes("await effects.persist(`${caseId}-workspace-git-possible`"),
  );
  for (const [start, gate] of [
    [
      "diagnostic = await observeWindowsGitNullProbe",
      "await workspace?.beforeGit();",
    ],
    [
      'for (const mode of ["read", "edit"])',
      "await heldWorkspace.beforeGit();",
    ],
  ]) {
    const begin = driver.indexOf(start),
      intent = driver.indexOf(gate, begin),
      release = driver.indexOf('run.session.send("A")', begin);
    assert.ok(begin >= 0 && intent > begin && release > intent);
  }
  assert.ok(
    owner.indexOf("acquisitions.admission = admission") <
      owner.indexOf("gitAdmitted = true"),
  );
  const gitIntent = owner.indexOf("`${caseId}-git-admission`");
  assert.ok(
    gitIntent > 0 &&
      gitIntent < owner.indexOf("mapper.sendTarget(acquisitions.gitStarted)"),
  );
  assert.match(driver, /hooks\?\.acquired\(run\)/u);
  const hook = driver.indexOf("if (hooks) await hooks.beforeRelease(run)");
  assert.ok(
    driver.indexOf("await persist(windowsFeasibilityAdmissionName(caseId)") <
      hook && hook < driver.indexOf('session.send("R")'),
  );
  const gitOwned = driver.indexOf("workspace?.admittedGit(admission)");
  assert.ok(
    gitOwned > 0 &&
      gitOwned <
        driver.indexOf("validateWindowsFeasibilityGitStart({", gitOwned),
  );
  assert.match(
    driver,
    /rootedLaunch = windowsFeasibilityWorkspaceLaunch\(role, args\)/u,
  );
  assert.match(
    header,
    /value\.role\[10\] \|\| wcscmp\(value\.role, workspaceRole\)/u,
  );
  assert.match(
    header,
    /null_pipe_query\(null_owned\.pipeSource, queryLink, "recheck-original"\)/u,
  );
  assert.match(
    header,
    /null_pipe_query\(null_owned\.pipeLink, queryLink, "recheck-private"\)/u,
  );
  assert.match(
    header,
    /const WCHAR expected\[\] = L"\\\\Device\\\\NamedPipe"/u,
  );
  assert.match(
    header,
    /createLink\(&null_owned\.pipeLink, 1, &attributes, &target\)/u,
  );
  assert.ok(
    header.indexOf('null_recheck("git-release")') >
      header.indexOf("setMap(null_owned.git"),
  );
  const dead =
    /else invariant\((!suspended && !watch && \(!terminate \|\| rooted\)), "process-wait"\)/u.exec(
      helper,
    );
  assert.ok(dead);
  for (const rooted of [false, true])
    assert.equal(
      new Script(dead[1]).runInNewContext({
        suspended: false,
        watch: false,
        terminate: true,
        rooted,
      }),
      rooted,
    );
  const terminalStart = helper.indexOf(
    "if (rooted) { printf(",
    helper.indexOf("static void observe("),
  );
  assert.ok(terminalStart > 0);
  const terminal = helper.slice(
    terminalStart,
    helper.indexOf("else puts(", terminalStart),
  );
  assert.match(terminal, /GetProcessId\(child\), creation\(child\)/u);
  assert.doesNotMatch(terminal, /identity\(child\)|OpenProcessToken/u);
  assert.match(
    helper,
    /!strcmp\(physicalId, logicalId\) && !_wcsicmp\(physical, logical\) && !_wcsicmp\(physical, expected\)/u,
  );
  assert.match(
    helper,
    /SetCurrentDirectoryW\(L"W:\\\\"\), "file-path"\); workspaceEntered = TRUE;/u,
  );
  assert.match(
    helper,
    /environment, workspaceEntered \? L"W:\\\\" : workspace, &startup/u,
  );
  assert.match(helper, /TerminateProcess\(transport\.child\.hProcess, 127\)/u);
  const recipe = helper.split("\n").find((line) => line.includes("logicalCwd"));
  const literal = /printf\(("(?:\\.|[^"])*")/u.exec(recipe)[1];
  const rendered = JSON.parse(literal)
    .replace("%ls", "identity")
    .replace("%ls", "native");
  assert.equal(JSON.parse("{" + rendered.slice(1) + "}").logicalCwd, "W:\\");
});

function heldWorkspaceFixture(mode = "read") {
  const { evidence, trusted, identity } = workspaceGitFixture();
  const order = [],
    persisted = new Set();
  const pipeTargetUtf16 = Buffer.from("\\Device\\NamedPipe", "utf16le")
    .swap16()
    .toString("hex");
  const started = {
    ...evidence.started,
    process: "21",
    thread: "22",
    logicalCwd: "W:\\",
    workspaceBinding: trusted,
    workspaceRole: mode,
  };
  const run = {
    receipt: { ...evidence.receipt, job: "11", process: "12", thread: "13" },
    admission: { admitted: true },
    session: {
      refused: false,
      checkGitReceipt: (check) => check(),
      send: (value) => order.push("payload:" + value),
    },
  };
  const binding = {
    event: "null-bound",
    caseId: "workspace-rooted",
    role: mode,
    bound: true,
    mappedSetup: true,
    setSucceeded: true,
    owner: identity(45),
    workspace: structuredClone(trusted),
    pipeTargetUtf16,
  };
  const rows = [
    { event: "null-owner", owner: identity(45) },
    { event: "null-controller", phase: "before", openError: 0 },
    {
      event: "null-custody",
      owner: identity(45),
      child: identity(42),
      job: "31",
      process: "32",
    },
    {
      event: "null-target-set",
      target: "payload",
      identity: identity(42),
      setSucceeded: true,
    },
    binding,
    { event: "null-controller", phase: "after", openError: 0 },
    { event: "null-retired", resourcesClosed: true },
  ];
  let targetSent = false;
  const state = { retired: true, birth: "42", cleanupFailure: false };
  const mapper = {
    pid: 45,
    exited: false,
    refused: false,
    next: async () => {
      assert.ok(rows.length);
      return rows.shift();
    },
    sendTarget: (target) => {
      assert.equal(targetSent, false);
      targetSent = true;
      assert.ok(persisted.has(`${mode}-git-admission`));
      assert.equal(target.child.pid, 43);
      order.push("git:set");
      rows.unshift({
        event: "null-target-bound",
        target: "git",
        identity: identity(43),
        setSucceeded: true,
        workspaceReady: true,
      });
    },
    send: (action) => {
      assert.equal(action, "Q");
      assert.ok(order.includes("job-empty"));
      order.push("map:Q");
    },
    finish: async () => {},
  };
  const native = async (role, ...args) => {
    order.push(role);
    if (role === "workspace-proof")
      return {
        event: role,
        role: mode,
        workspace: trusted,
        verifier: identity(46),
        pipeTargetUtf16,
      };
    if (role === "git-inspect") return evidence.admission;
    if (role === "process-retired") return { retired: true };
    assert.ok(["workspace-cancel", "workspace-settle"].includes(role));
    if (state.retired) order.push("job-empty");
    return {
      retired: state.retired,
      jobEmpty: state.retired,
      child: { pid: 42, creationTime: state.birth },
      verifier: identity(47),
    };
  };
  const effects = {
    normalizeWindowsIdentity,
    sameWindowsIdentity,
    native,
    persist: async (name) => {
      assert.equal(persisted.has(name), false);
      persisted.add(name);
      order.push(name);
    },
    observerArgs: (receipt, caseId) => [receipt.owner.pid, caseId],
    holder: () => {
      assert.ok(persisted.has(`${mode}-workspace-map-possible`));
      order.push("payload:set");
      return mapper;
    },
    releaseSession: () => order.push("holder-closed"),
    gitFiles: async () =>
      state.gitChanged
        ? [
            { ...evidence.files[0], sha256: "c".repeat(64) },
            ...evidence.files.slice(1),
          ]
        : evidence.files,
    files: async () => [],
    outsideBaseline: [],
    absent: async (name) => {
      assert.equal(name, `workspace\\${mode}-null-endpoint`);
      order.push("endpoint-absent");
    },
  };
  const owner = createWindowsFeasibilityWorkspace(mode, effects);
  const callbacks = {
    cancelPayload: async () => order.push("payload:N"),
    closePayload: async () => {
      if (state.cleanupFailure) throw new Error("Uncertain launcher cleanup");
      order.push("payload-closed");
    },
  };
  return {
    owner,
    callbacks,
    evidence,
    run,
    order,
    persisted,
    native,
    started,
    binding,
    state,
  };
}

test("shared workspace confines release and rejects pending, timeout and other TCP results in the actual operation loop", async () => {
  const driver = await readFile(
    new URL("../ci/native/win32/feasibility.js", import.meta.url),
    "utf8",
  );
  const begin = driver.indexOf("for (const operation of OPERATIONS)");
  const loop = driver.slice(begin, driver.indexOf("complete = true;", begin));
  const operations = [
    "inspect",
    "edit",
    "git-status",
    "git-index",
    "git-ref",
    "control",
    "outside",
    "tcp",
    "pipe",
  ];
  for (const [mode, pipeError, tcpError, drift] of [
    ["read", 5, 10013],
    ["edit", 5, 10013],
    ["read", 2, 10013],
    ["read", 5, 10035],
    ["read", 5, 10061],
    ["read", 5, 10060],
    ["read", 5, 10054],
    ["read", 5, 0],
    ["read", 5, null],
    ["read", 5, 10013, true],
    ["read", 5, 0, true],
  ]) {
    const f = heldWorkspaceFixture(mode);
    await f.owner.prepare(f.evidence.files, 1);
    f.owner.launching();
    f.owner.acquired(f.run);
    assert.throws(() => f.owner.releasingPayload());
    await f.owner.beforeRelease(f.run);
    f.owner.releasingPayload();
    f.run.session.send("R");
    await f.owner.beforeGit();
    assert.throws(() => f.owner.releasingGit());
    f.run.receipt.image = { identity: "1:2", private: false, sha256: DIGEST };
    const tcp = tcpDenialFixture(f.run.receipt);
    if (drift) tcp.attribution.requested.port++;
    const tcpAccepted = tcpError === 10013 && !drift;
    const rows = operations.flatMap((operation) => [
      { event: "attempt", operation },
      ...(operation === "git-status" ? [f.started] : []),
      ...(operation === "tcp"
        ? [tcp.transfer, tcp.prepared, tcp.attribution]
        : []),
      {
        event: "completed",
        operation,
        error:
          operation === "pipe"
            ? pipeError
            : ["inspect", "git-status"].includes(operation) ||
                (mode === "edit" && operation === "edit")
              ? 0
              : operation === "tcp"
                ? tcpError
                : 5,
      },
    ]);
    const original = Object.assign(new Error("Native TCP deadline"), {
      code: 126,
    });
    const context = {
      OPERATIONS: operations,
      tcpEndpoint: "32100",
      assertWindowsFeasibilityTcpObserver,
      assertWindowsFeasibilityTcpTransfer,
      assertWindowsFeasibilityTcpDenial,
      mode,
      run: f.run,
      heldWorkspace: f.owner,
      root: f.evidence.root,
      preparedGit: f.evidence.prepared,
      gitBefore: f.evidence.files,
      nextRun: async () => {
        const row = rows.shift();
        if (
          tcpError === null &&
          row.event === "completed" &&
          row.operation === "tcp"
        )
          throw original;
        return row;
      },
      native: f.native,
      gitFiles: async () => f.evidence.files,
      persist: async (name) => f.order.push(name),
      need: (value) => assert.ok(value),
      hash: JSON.stringify,
      nativeException: () => {},
      normalizeWindowsIdentity: (value) => assert.ok(value.pid),
      sameWindowsIdentity,
      validateWindowsFeasibilityGitStart,
      operations: [],
      gitStart: null,
      observeWindowsFeasibilityWfp: async () => f.order.push("wfp-observed"),
    };
    const execution = new Script(
      "(async () => {" + loop + "})()",
    ).runInNewContext(context);
    if (tcpError === null)
      await assert.rejects(
        execution,
        (error) =>
          error === original && error.code === 126 && error.operation === "tcp",
      );
    else if (tcpError !== 10013)
      await assert.rejects(
        execution,
        (error) =>
          error.operation === "tcp" && error.escape === (tcpError === 0),
      );
    else if (drift)
      await assert.rejects(execution, (error) => error.operation === "tcp");
    else if (pipeError === 5) await execution;
    else await assert.rejects(execution, (error) => error.operation === "pipe");
    assert.deepEqual(
      Array.from(context.operations, ({ completed }) => completed.operation),
      !tcpAccepted
        ? operations.slice(0, -2)
        : pipeError === 5
          ? operations
          : operations.slice(0, -1),
    );
    assert.equal(rows.length, !tcpAccepted ? 2 : 0);
    assert.equal(f.order.filter((item) => item === "wfp-observed").length, 1);
    for (const [before, after] of [
      ["payload:O", `${mode}-tcp-transfer`],
      [`${mode}-tcp-transfer`, "payload:D"],
      ["payload:D", `${mode}-tcp-intent`],
      [`${mode}-tcp-intent`, "payload:T"],
      ["payload:T", `${mode}-tcp-observed`],
      [`${mode}-tcp-observed`, "payload:U"],
    ])
      assert.ok(f.order.indexOf(before) < f.order.indexOf(after));
    assert.equal(f.order.filter((item) => item === "payload:T").length, 1);
    assert.equal(f.run.tcpAttribution.pending, !tcpAccepted);
    assert.ok(f.order.indexOf("payload:set") < f.order.indexOf("payload:R"));
    assert.ok(
      f.order.indexOf(`${mode}-git-start`) < f.order.indexOf("git:set"),
    );
    assert.ok(f.order.indexOf("git:set") < f.order.indexOf("payload:G"));
    assert.equal(f.order.filter((item) => item === "git:set").length, 1);
    const retirement = await f.owner.retire({
      ...f.callbacks,
      complete: pipeError === 5 && tcpAccepted,
    });
    assert.equal(f.owner.settled, true);
    assert.ok(
      f.order.indexOf("wfp-observed") < f.order.indexOf("payload-closed"),
    );
    assert.equal(f.owner.evidence.retirement, retirement);
    assert.equal(retirement.retirement.child.pid, f.run.receipt.child.pid);
    for (const property of [
      "independent",
      "jobEmpty",
      "processRetired",
      "resourcesClosed",
      "endpointAbsent",
      "holderRetired",
      "outsideUnchanged",
    ])
      assert.equal(retirement[property], true);
    assert.ok(f.order.indexOf("job-empty") < f.order.indexOf("map:Q"));
    assert.ok(f.order.indexOf("map:Q") < f.order.indexOf("endpoint-absent"));
    assert.equal(
      windowsFeasibilityWorkspaceLaunch("launch", [
        mode,
        "helper",
        "bundle",
        "root",
        "nonce",
        "port",
        "pipe",
        mode,
        "id",
        "path",
      ]),
      true,
    );
  }
  for (const mode of [
    "argv",
    "cancel",
    "owner-loss",
    "final-handle-close",
    "unknown",
  ])
    assert.throws(() => createWindowsFeasibilityWorkspace(mode, {}));
  assert.equal(
    windowsFeasibilityWorkspaceLaunch("launch", [
      "read",
      "helper",
      "fault",
      "root",
      "nonce",
      "port",
      "pipe",
      "read",
      "id",
      "path",
    ]),
    false,
  );
});

test("shared workspace rejects mismatched held binding before payload release", async () => {
  for (const field of [
    "identity",
    "nativePathUtf16",
    "pipeTargetUtf16",
    "role",
  ]) {
    const f = heldWorkspaceFixture();
    await f.owner.prepare(f.evidence.files, 1);
    f.owner.launching();
    f.owner.acquired(f.run);
    if (field === "role") f.binding.role = "edit";
    else if (field === "pipeTargetUtf16") f.binding.pipeTargetUtf16 += "0061";
    else f.binding.workspace[field] += "0061";
    await assert.rejects(f.owner.beforeRelease(f.run));
    assert.throws(() => f.owner.releasingPayload());
    await f.owner.retire(f.callbacks);
    assert.equal(f.order.includes("payload:R"), false);
    assert.equal(f.order.includes("git:set"), false);
    assert.equal(f.owner.settled, true);
  }
  const f = heldWorkspaceFixture();
  await f.owner.prepare(f.evidence.files, 1);
  f.owner.launching();
  f.owner.acquired(f.run);
  await f.owner.beforeRelease(f.run);
  f.owner.releasingPayload();
  await f.owner.beforeGit();
  f.owner.startedGit(f.started);
  f.owner.admittedGit(f.evidence.admission);
  f.state.gitChanged = true;
  await assert.rejects(f.owner.assignGit());
  assert.throws(() => f.owner.releasingGit());
  f.state.gitChanged = false;
  await f.owner.retire(f.callbacks);
});

test("actual shared workspace settles acquired subsets and retains resources and primary refusal on uncertainty", async () => {
  for (const [subset, retired, cleanupFailure, birth = "42"] of [
    ["none", true, false],
    ["payload", true, false],
    ["map", true, false],
    ["git", true, false],
    ["refused", true, false],
    ["refused", true, true],
    ["map", false, false],
    ["map", true, false, "43"],
  ]) {
    const f = heldWorkspaceFixture("null-probe");
    Object.assign(f.state, { retired, cleanupFailure, birth });
    await f.owner.prepare(f.evidence.files, 1);
    if (subset !== "none") {
      f.owner.launching();
      f.owner.acquired(f.run);
    }
    if (!["none", "payload"].includes(subset))
      await f.owner.beforeRelease(f.run);
    if (["git", "refused"].includes(subset)) f.owner.releasingPayload();
    let completed = false;
    if (subset === "git") {
      await f.owner.beforeGit();
      f.owner.startedGit(f.started);
      f.owner.admittedGit(f.evidence.admission);
      await f.owner.assignGit();
      f.callbacks.cancelGit = async () => {
        completed = true;
        f.order.push("git:N");
      };
    }
    if (subset === "refused") f.run.session.refused = true;
    const first = {
      event: "null-error",
      operation: "mapping-workspace-binding",
    };
    const probe = await observeWindowsGitNullProbe({
      caseId: "workspace-rooted",
      acquisitions: f.owner.acquisitions,
      start: async (capture) => {
        capture(first);
        throw new Error("Refused setup");
      },
      execute: async () => assert.fail("Incomplete work executed"),
      retire: () =>
        f.owner.retire({ ...f.callbacks, complete: () => completed }),
    });
    assert.deepEqual(probe.failure, first);
    assert.equal(probe.reusable, retired && !cleanupFailure && birth === "42");
    assert.equal(f.owner.settled, probe.reusable);
    assert.equal(Boolean(f.owner.evidence.retirement), probe.reusable);
    assert.equal(
      f.order.includes("map:Q"),
      !["none", "payload"].includes(subset) && probe.reusable,
    );
    if (!probe.reusable)
      assert.equal(f.order.includes("endpoint-absent"), false);
    if (subset === "git") assert.ok(f.order.includes("git:N"));
    if (subset === "refused") assert.ok(f.order.includes("workspace-cancel"));
  }
});
