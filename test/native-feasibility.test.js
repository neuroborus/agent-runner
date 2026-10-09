import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { Writable, PassThrough } from "node:stream";
import { gzipSync } from "node:zlib";
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
} from "../ci/native/darwin/index.js";
import {
  runWindowsFeasibility,
  windowsFeasibilityProfileName,
  windowsFeasibilityToolEnvironment,
  windowsFeasibilityImports,
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
    for (const [result, code, outcome] of [
      [
        {
          status: 1,
          signal: null,
          stderr:
            "bwrap: Creating new namespace failed: Operation not permitted\npassword=private",
        },
        "prerequisite-unavailable",
        "exit=1, signal=none, timeout=false",
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
              assert.deepEqual(vector.slice(0, 4), [
                "--die-with-parent",
                "--unshare-pid",
                "--as-pid-1",
                ownershipMode === "ordinary" ? "--ro-bind" : "--bind",
              ]);
              assert.equal(
                vector.includes("--unshare-net"),
                ownershipMode !== "ordinary",
              );
              assert.equal(
                vector.includes("--cap-drop"),
                ownershipMode !== "ordinary",
              );
              assert.equal(vector.at(-1), "/bin/true");
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
          if (result.status === 1)
            assert.match(
              error.feasibilityCause.detail,
              /namespace creation failure/u,
            );
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

test("Linux failed fixture diagnostics retain installed identity without extending acceptance prerequisites", async () => {
  const bytes = Buffer.from("synthetic launcher bytes");
  const component = {
    role: "tool",
    name: "bubblewrap",
    version: "bubblewrap 0.11.0",
    sha256: createHash("sha256").update(bytes).digest("hex"),
  };
  for (const [version, components] of [
    [component.version, [component]],
    [`bubblewrap ${"1".repeat(120)}.1.1`, []],
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
          stderr:
            "bwrap: Creating new namespace failed: Operation not permitted",
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
        assert.match(
          error.feasibilityCause.detail,
          /namespace creation failure/u,
        );
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
