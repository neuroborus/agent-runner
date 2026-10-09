import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import {
  assessFeasibilityReport,
  assessFeasibilityPreparation,
  feasibilityDiagnostic,
  feasibilityFailureCause,
  renderFeasibilitySummary,
  runFeasibilityExperiment,
  unavailableFeasibilityResults,
} from "../ci/native/feasibility/index.js";

const SHA = "a".repeat(40);
const intent = {
  expectedSha: SHA,
  platform: "linux",
  protectedAcceptance: false,
  runId: "7",
  runAttempt: "2",
};
const env = {
  NATIVE_CANDIDATE_SHA: SHA,
  NATIVE_PLATFORM: "linux",
  GITHUB_RUN_ID: "7",
  GITHUB_RUN_ATTEMPT: "2",
  NATIVE_PREPARATION_CONCLUSION: "failure",
  NATIVE_PREPARATION_OPERATION: "linux-package-update",
  NATIVE_PREPARATION_EXIT_CODE: "7",
  NATIVE_PROBE_CONCLUSION: "skipped",
  NATIVE_CLEANUP_CONCLUSION: "failure",
};
function initialized(platform = "linux") {
  return assessFeasibilityReport({
    schemaVersion: 1,
    expectedSha: SHA,
    checkoutSha: SHA,
    platform,
    os: platform,
    build: "synthetic-build",
    architecture: "x64",
    results: unavailableFeasibilityResults(platform, {
      code: "missing-record",
      detail: "The probe stage has not returned a complete report.",
    }),
  });
}

test("preparation failure replaces only initialized missing probes and retains the original cause and cleanup", () => {
  const input = structuredClone(initialized());
  const original = { code: "crash", detail: "An observed fixture crashed." };
  input.report.results = input.report.results.map((entry, index) =>
    index === 0
      ? {
          ...entry,
          cause: original,
          cleanup: {
            ...entry.cleanup,
            status: "UNCERTAIN",
            cause: {
              code: "cleanup-unobserved",
              detail: "Independent cleanup was not observed.",
            },
          },
        }
      : entry,
  );
  const normalized = assessFeasibilityReport(input.report);
  const before = structuredClone(normalized);
  const result = assessFeasibilityPreparation(normalized, intent, env);
  assert.deepEqual(result.report.results[0], normalized.report.results[0]);
  assert.match(
    result.report.results[1].cause.detail,
    /prepare linux-package-update: exit=7/u,
  );
  assert.equal(result.report.results[1].cleanup.status, "NOT_RUN");
  assert.equal(result.report.results[1].cleanup.cause, null);
  assert.deepEqual(normalized, before);
  const cancelled = assessFeasibilityPreparation(initialized(), intent, {
    ...env,
    NATIVE_PREPARATION_CONCLUSION: "cancelled",
    NATIVE_PREPARATION_EXIT_CODE: "",
  });
  assert.match(
    cancelled.report.results[0].cause.detail,
    /exit=unknown, signal=unknown, timeout=unknown/u,
  );
  const windows = assessFeasibilityPreparation(
    initialized("win32"),
    { ...intent, platform: "win32" },
    {
      ...env,
      NATIVE_PLATFORM: "win32",
      NATIVE_PREPARATION_OPERATION: "windows-sdk-setup",
      NATIVE_PREPARATION_EXIT_CODE: "-1073741510",
    },
  );
  assert.match(
    windows.report.results[0].cause.detail,
    /windows-sdk-setup: exit=-1073741510, signal=unknown, timeout=unknown/u,
  );
  assert.deepEqual(
    assessFeasibilityPreparation(initialized(), intent, {
      ...env,
      NATIVE_PREPARATION_CONCLUSION: "success",
      NATIVE_PREPARATION_EXIT_CODE: "0",
    }),
    initialized(),
  );
});

test("preparation metadata rejects mismatched run binding, foreign operations and malformed process or step outcomes", () => {
  for (const change of [
    { NATIVE_CANDIDATE_SHA: "b".repeat(40) },
    { NATIVE_PLATFORM: "darwin" },
    { GITHUB_RUN_ID: "8" },
    { GITHUB_RUN_ATTEMPT: "3" },
    { NATIVE_PREPARATION_OPERATION: "windows-sdk-setup" },
    { NATIVE_PREPARATION_EXIT_CODE: "7\nextra=value" },
    { NATIVE_PREPARATION_EXIT_CODE: "256" },
    { NATIVE_PREPARATION_CONCLUSION: "success" },
    { NATIVE_PROBE_CONCLUSION: "unknown" },
  ])
    assert.throws(
      () =>
        assessFeasibilityPreparation(initialized(), intent, {
          ...env,
          ...change,
        }),
      { code: "ERR_INVALID_NATIVE_FEASIBILITY" },
    );
});

test("native diagnoses preserve observed exit, crash and deadline facts without treating killed as a timeout", () => {
  const exit = feasibilityFailureCause("probe", "native-owner", {
    code: 1,
    signal: null,
    timedOut: false,
  });
  assert.equal(exit.code, "setup-failed");
  assert.match(exit.detail, /exit=1, signal=none, timeout=false/u);
  assert.equal(
    feasibilityFailureCause("probe", "native-owner", { signal: "SIGSEGV" })
      .code,
    "crash",
  );
  assert.equal(
    feasibilityFailureCause("probe", "native-owner", { timedOut: true }).code,
    "deadline",
  );
  const unknown = feasibilityFailureCause("probe", "native-owner", {
    code: 1,
    killed: true,
    message: "private error text",
  });
  assert.equal(unknown.code, "setup-failed");
  assert.match(
    unknown.detail,
    /exit=unknown, signal=unknown, timeout=unknown/u,
  );
  assert.doesNotMatch(unknown.detail, /private/u);
});

test("diagnostic extraction is bounded, recognizes native causes and rejects unsafe compiler output", () => {
  assert.equal(
    feasibilityDiagnostic(
      "bwrap: Creating new namespace failed: Operation not permitted",
    ),
    "Bubblewrap reported a namespace creation failure.",
  );
  const captured =
    "\u001b[31m/fixture/private/helper.c:4:2: error: use of undeclared identifier 'missing_symbol'\u001b[0m";
  const diagnostic = feasibilityDiagnostic(captured);
  assert.equal(
    diagnostic,
    "error: use of undeclared identifier 'missing_symbol'",
  );
  assert.equal(
    feasibilityDiagnostic(
      "error: unknown type name 'fixture_type' trailing private payload",
    ),
    "error: unknown type name 'fixture_type'",
  );
  assert.equal(
    feasibilityDiagnostic(
      "error: incompatible declaration at C:\\Private Files\\fixture.h; trailing private payload",
    ),
    "The compiler reported incompatible declarations or types.",
  );
  assert.equal(
    feasibilityDiagnostic(
      "fatal error: '/fixture/private/header.h' file not found",
    ),
    "The compiler reported an unavailable include file.",
  );
  assert.equal(
    feasibilityDiagnostic(
      "error: use of undeclared identifier 'first_symbol'\nld: library not found for -lfixture",
    ),
    "error: use of undeclared identifier 'first_symbol'",
  );
  assert.equal(
    feasibilityDiagnostic("x".repeat(65536) + "\n" + captured),
    null,
  );
  assert.equal(
    feasibilityDiagnostic(Buffer.from("x".repeat(65536) + "\n" + captured)),
    null,
  );
  assert.equal(feasibilityDiagnostic("λ".repeat(32768) + captured), null);
  for (const value of [
    "password=private-value",
    "pas\u0000sword=private-value",
    "https://example.invalid/private",
    "::warning::private",
    "Bearer private-value",
  ]) {
    assert.equal(
      feasibilityDiagnostic(`error: unknown type name '${value}'`),
      null,
    );
  }
  assert.equal(feasibilityDiagnostic("arbitrary provider transcript"), null);
  const cause = feasibilityFailureCause("build", "compile", {
    code: 1,
    stderr: captured.repeat(1000),
  });
  assert.ok(Buffer.byteLength(cause.detail) <= 256);
  assert.doesNotMatch(cause.detail, /\/fixture|\u001b/u);
});

test("native failure causes distinguish capture presence from recognition without changing diagnostic callers", () => {
  const recognized =
    "bwrap: Creating new namespace failed: Operation not permitted";
  for (const [streams, output] of [
    [{}, "absent"],
    [{ stderr: "", stdout: Buffer.alloc(0) }, "absent"],
    [{ stderr: "password=private-value" }, "unrecognized"],
    [{ stdout: Buffer.from("opaque\u0000native output") }, "unrecognized"],
    [{ stderr: "\u001b[31m\u001b[0m" }, "unrecognized"],
    [{ stderr: recognized }, "recognized"],
    [{ stderr: "opaque output", stdout: recognized }, "recognized"],
  ]) {
    const cause = feasibilityFailureCause("prepare", "ordinary-namespace", {
      exitCode: 1,
      signal: null,
      timedOut: false,
      ...streams,
    });
    assert.equal(cause.code, "setup-failed");
    assert.match(cause.detail, /exit=1, signal=none, timeout=false/u);
    assert.ok(cause.detail.includes(`output=${output};`));
    if (output === "recognized")
      assert.match(cause.detail, /namespace creation failure/u);
    else {
      assert.equal(feasibilityDiagnostic(streams.stderr), null);
      assert.equal(feasibilityDiagnostic(streams.stdout), null);
      assert.ok(
        cause.detail.endsWith(
          output === "absent"
            ? "No native output was captured."
            : "Native output was captured but no explanation was recognized.",
        ),
      );
    }
    assert.doesNotMatch(
      JSON.stringify(cause),
      /password|private|opaque|\u001b|\u0000/u,
    );
  }
});

test("native diagnostics retain only finite error and fixed-launch operation classes", () => {
  for (const code of [
    "ENOTDIR",
    "ENOEXEC",
    "ELOOP",
    "ENOBUFS",
    "ERR_CHILD_PROCESS_STDIO_MAXBUFFER",
    "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
  ]) {
    for (const stderr of [undefined, "unrecognized private output"]) {
      const cause = feasibilityFailureCause(
        "prepare",
        "launcher-construction",
        {
          code,
          stderr,
          killed: true,
          message: "private exception message",
        },
      );
      assert.equal(cause.code, "setup-failed");
      assert.match(
        cause.detail,
        /exit=unknown, signal=unknown, timeout=unknown/u,
      );
      assert.ok(cause.detail.includes(`native=${code};`));
      assert.ok(
        cause.detail.includes(
          `output=${stderr === undefined ? "absent" : "unrecognized"},`,
        ),
      );
      assert.doesNotMatch(cause.detail, /private/u);
    }
  }
  const unknown = feasibilityFailureCause("prepare", "launcher-construction", {
    code: "UNREVIEWED_PRIVATE_CLASS",
    message: "private exception message",
  });
  assert.doesNotMatch(unknown.detail, /PRIVATE|native=/u);
  for (const [stderr, explanation] of [
    [
      "bwrap: Can't bind mount /fixture/private: Invalid argument",
      "bind-mount failure",
    ],
    [
      "bwrap: Can't mount proc on /proc: Operation not permitted",
      "procfs mount failure",
    ],
    [
      "bwrap: Can't create /dev/fixture: Permission denied",
      "device setup failure",
    ],
    [
      "bwrap: execvp /fixture/private: Exec format error",
      "executable launch failure",
    ],
  ]) {
    const cause = feasibilityFailureCause("prepare", "ordinary-namespace", {
      stderr,
    });
    assert.ok(cause.detail.includes(explanation));
    assert.match(cause.detail, /output=recognized/u);
    assert.doesNotMatch(cause.detail, /\/fixture|\/proc|\/dev/u);
  }
  for (const stderr of [
    "bwrap: Can't open /fixture/failed to bind mount: Invalid argument",
    "bwrap: Can't mount /fixture/processed-data: Invalid argument",
    "bwrap: Can't open /fixture/execvp: Exec format error",
  ]) {
    const cause = feasibilityFailureCause("prepare", "ordinary-namespace", {
      stderr,
    });
    assert.equal(feasibilityDiagnostic(stderr), null);
    assert.match(cause.detail, /output=unrecognized/u);
  }
  const bounded = feasibilityFailureCause("p".repeat(24), "o".repeat(48), {
    code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
    exitCode: 4294967295,
    signal: "SIGABCDEFGHIJKLMNOP",
    timedOut: true,
    stderr: "unrecognized private output",
  });
  assert.ok(Buffer.byteLength(bounded.detail) <= 256);
  assert.match(
    bounded.detail,
    /output=unrecognized, native=ERR_EXECUTION_PROCESS_UNVERIFIABLE;/u,
  );
});

test("native owner rejection retains a sanitized explanation without executing any platform effect", async () => {
  const assessment = await runFeasibilityExperiment(
    ["--platform", "linux", "--expected-sha", SHA],
    {
      host: {
        ci: true,
        githubActions: true,
        runnerEnvironment: "github-hosted",
        runnerOs: "Linux",
        platform: "linux",
        architecture: "x64",
      },
      observe: async () => initialized().report,
      runNative: async () => {
        throw {
          code: 1,
          signal: null,
          timedOut: false,
          stderr: "bwrap: Operation not permitted",
        };
      },
      runProviders: async () => {
        assert.fail(
          "Unsettled native cleanup must prevent provider invocation.",
        );
      },
    },
  );
  const result = assessment.report.results[0];
  assert.match(
    result.cause.detail,
    /probe native-owner: exit=1, signal=none, timeout=false; output=recognized; Bubblewrap/u,
  );
  assert.equal(result.cleanup.cause.code, "cleanup-unobserved");
});

test("summary separates first and cleanup explanations, escapes cells and includes the validated run", () => {
  const input = structuredClone(initialized().report);
  input.build = "synthetic | <build>";
  input.results = input.results.map((entry, index) =>
    index === 0
      ? {
          ...entry,
          cause: { code: "crash", detail: "first | <failure>" },
          cleanup: {
            ...entry.cleanup,
            status: "FAIL",
            cause: { code: "cleanup-failed", detail: "cleanup | <failure>" },
          },
        }
      : entry,
  );
  const summary = renderFeasibilitySummary(
    assessFeasibilityReport(input),
    intent,
    env,
  );
  assert.match(summary, /Run: 7; attempt: 2/u);
  assert.match(summary, /crash: first &#124; &#60;failure&#62;/u);
  assert.match(summary, /cleanup-failed: cleanup &#124; &#60;failure&#62;/u);
  assert.match(summary, /synthetic &#124; &#60;build&#62;/u);
  assert.doesNotMatch(summary, /<failure>|<build>/u);
});

test(
  "Linux preparation captures each actual status before failure handling in both workflows",
  { skip: process.platform !== "linux" },
  async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "native-preparation-"));
    try {
      for (const workflow of [
        "native-feasibility.yml",
        "native-feasibility-acceptance.yml",
      ]) {
        const source = await readFile(
          new URL(`../.github/workflows/${workflow}`, import.meta.url),
          "utf8",
        );
        const block = source
          .split("        id: prepare_linux\n")[1]
          .split("        run: |\n")[1]
          .split("      - name:")[0]
          .split("\n")
          .map((line) => line.slice(10))
          .join("\n");
        for (const [update, install, operation, expected] of [
          [7, 9, "update", 7],
          [0, 9, "install", 9],
          [0, 0, "install", 0],
        ]) {
          const file = path.join(directory, `${workflow}-${update}-${install}`);
          const result = spawnSync(
            "bash",
            ["--noprofile", "--norc", "-e", "-o", "pipefail"],
            {
              input: `sudo() { if [ "$2" = update ]; then return ${update}; else return ${install}; fi; }\n${block}`,
              env: { PATH: process.env.PATH, GITHUB_OUTPUT: file },
              encoding: "utf8",
              timeout: 3000,
              maxBuffer: 1024,
            },
          );
          assert.ifError(result.error);
          assert.equal(result.status, expected);
          const outputs = Object.fromEntries(
            (await readFile(file, "utf8"))
              .trim()
              .split("\n")
              .map((line) => line.split("=")),
          );
          assert.deepEqual(outputs, {
            operation: `linux-package-${operation}`,
            exit_code: String(expected),
          });
        }
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
