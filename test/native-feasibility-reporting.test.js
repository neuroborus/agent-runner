import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import {
  assessFeasibilityReport,
  assessFeasibilityPreparation,
  feasibilityCapabilities,
  feasibilityDiagnostic,
  feasibilityFailureCause,
  prepareDarwinFeasibilityObserver,
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

test("Darwin preparation bounds installed discovery and captures unavailable authority before native effects", async () => {
  const calls = [],
    captures = [];
  const command = async (file, args, options) => {
    calls.push([file, args]);
    assert.equal(options.timeout, 10000);
    assert.equal(options.maxBuffer, 65536);
    return { stdout: file.endsWith("xcrun") ? "/fixture/installed\n" : "" };
  };
  const prepared = await prepareDarwinFeasibilityObserver({
    command,
    capture: async (entry) => captures.push(entry),
  });
  assert.deepEqual(calls, [
    ["/usr/bin/xcrun", ["--sdk", "macosx", "--show-sdk-path"]],
    ["/usr/bin/xcrun", ["--sdk", "macosx", "--find", "clang"]],
    ["/usr/bin/sudo", ["-n", "/usr/bin/true"]],
  ]);
  assert.deepEqual(
    captures.map((entry) => entry.exitCode),
    [null, 0, null, 0, null, 0],
  );
  assert.deepEqual(prepared, {
    operation: "darwin-observer-authority",
    exitCode: 0,
    cause: null,
  });
  for (const [failedFile, error, expected] of [
    [
      "sudo",
      { code: 1, signal: null, stderr: "private output" },
      "prerequisite-unavailable",
    ],
    [
      "xcrun",
      { code: 1, signal: null, stderr: "private output" },
      "setup-failed",
    ],
    ["xcrun", { code: "ENOENT" }, "prerequisite-unavailable"],
    ["sudo", { killed: true }, "setup-failed"],
  ]) {
    calls.length = 0;
    const failed = await prepareDarwinFeasibilityObserver({
      command: async (...args) => {
        if (args[0].endsWith(failedFile)) throw error;
        return command(...args);
      },
    });
    assert.equal(failed.cause.code, expected);
    assert.doesNotMatch(failed.cause.detail, /private/u);
    if (error.killed) assert.match(failed.cause.detail, /timeout=unknown/u);
    assert.equal(calls.length, failedFile === "sudo" ? 2 : 0);
    const assessed = assessFeasibilityPreparation(
      initialized("darwin"),
      { ...intent, platform: "darwin" },
      {
        ...env,
        NATIVE_PLATFORM: "darwin",
        NATIVE_PREPARATION_OPERATION: failed.operation,
        NATIVE_PREPARATION_EXIT_CODE: String(failed.exitCode ?? ""),
        NATIVE_PREPARATION_CAUSE: JSON.stringify(failed.cause),
      },
    );
    assert.ok(
      assessed.report.results.every(
        (entry) =>
          entry.status ===
            (expected === "prerequisite-unavailable" ? "BLOCKED" : "FAIL") &&
          entry.cleanup.status === "NOT_RUN",
      ),
    );
  }
  const malformed = await prepareDarwinFeasibilityObserver({
    command: async () => ({ stdout: "/fixture/../unvalidated\n" }),
  });
  assert.equal(malformed.operation, "darwin-sdk-discovery");
  assert.equal(malformed.exitCode, 0);
  assert.equal(malformed.cause.code, "setup-failed");
  assert.match(malformed.cause.detail, /output=unrecognized/u);
  assert.doesNotMatch(malformed.cause.detail, /fixture|unvalidated/u);
  assert.throws(() =>
    assessFeasibilityPreparation(
      initialized("darwin"),
      { ...intent, platform: "darwin" },
      {
        ...env,
        NATIVE_PLATFORM: "darwin",
        NATIVE_PREPARATION_OPERATION: "darwin-sdk-discovery",
        NATIVE_PREPARATION_CLEANUP_CAUSE: JSON.stringify({
          code: "cleanup-failed",
          detail: "cleanup windows-toolchain-files: exit=unknown",
        }),
      },
    ),
  );
});

test("preparation failure replaces only initialized missing probes and retains the original cause and cleanup", () => {
  const input = structuredClone(initialized());
  const original = { code: "crash", detail: "An observed fixture crashed." };
  input.report.results = input.report.results.map((entry, index) =>
    index === 0
      ? {
          ...entry,
          cause: original,
          components: [
            {
              role: "tool",
              name: "fixture-compiler",
              version: "1",
              sha256: "b".repeat(64),
            },
          ],
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

test("both minimal workflows bind Darwin preparation outcomes to always-run reporting", async () => {
  for (const workflow of [
    "native-feasibility.yml",
    "native-feasibility-acceptance.yml",
  ]) {
    const source = await readFile(
      new URL(`../.github/workflows/${workflow}`, import.meta.url),
      "utf8",
    );
    const preparation = source
      .split("        id: prepare_darwin\n")[1]
      .split("      - name:")[0];
    assert.match(preparation, /matrix\.platform == 'darwin'/u);
    assert.match(preparation, /timeout-minutes: 1/u);
    assert.match(
      preparation,
      /--stage prepare-darwin --platform "\$NATIVE_PLATFORM" --expected-sha "\$NATIVE_CANDIDATE_SHA"/u,
    );
    assert.equal(
      preparation.includes("--protected"),
      workflow.includes("acceptance"),
    );
    assert.match(
      source,
      /NATIVE_PREPARATION_CONCLUSION:.*steps\.prepare_darwin\.conclusion/u,
    );
    for (const [name, output] of [
      ["OPERATION", "operation"],
      ["EXIT_CODE", "exit_code"],
      ["CAUSE", "cause"],
    ])
      assert.match(
        source,
        new RegExp(
          `NATIVE_PREPARATION_${name}:.*steps\\.prepare_darwin\\.outputs\\.${output}`,
          "u",
        ),
      );
  }
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
    assert.ok(cause.detail.includes(`output=${output}`));
    if (output === "recognized")
      assert.match(
        cause.detail,
        /output=recognized, native=EPERM; Bubblewrap reported a namespace creation failure\./u,
      );
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

test("Bubblewrap source diagnostics retain operations and finite errors without paths or policy advice", () => {
  for (const [message, explanation, native] of [
    [
      "No permissions to create a new namespace, likely because the kernel does not allow non-privileged user namespaces. This can be enabled with 'sysctl kernel.unprivileged_userns_clone=1'.",
      "namespace creation",
      null,
    ],
    [
      "Creating new namespace failed: Invalid argument",
      "namespace creation",
      "EINVAL",
    ],
    [
      "Creating new namespace failed: nesting depth or /proc/sys/user/max_*_namespaces exceeded (ENOSPC)",
      "namespace creation",
      "ENOSPC",
    ],
    ["unshare pid ns: Operation not permitted", "namespace creation", "EPERM"],
    ["unshare user ns: Invalid argument", "namespace creation", "EINVAL"],
    [
      "setting up uid map: Operation not permitted",
      "UID or GID mapping",
      "EPERM",
    ],
    ["setting up uid map: Permission denied", "UID or GID mapping", "EACCES"],
    ["setting up gid map: Invalid argument", "UID or GID mapping", "EINVAL"],
    [
      "error writing to setgroups: Permission denied",
      "UID or GID mapping",
      "EACCES",
    ],
    [
      "Failed to make / slave: Permission denied",
      "mount-propagation",
      "EACCES",
    ],
    [
      "Failed to make old root rprivate: Operation not permitted",
      "mount-propagation",
      "EPERM",
    ],
    ["Failed to mount tmpfs: No space left on device", "tmpfs mount", "ENOSPC"],
    [
      "Can't mount tmpfs on /fixture/private: Invalid argument",
      "tmpfs mount",
      "EINVAL",
    ],
    [
      "Can't mount tmpfs on /fixture/private: Limit exceeded (ENOSPC). (Hint: Check that /proc/sys/fs/mount-max is sufficient, typically 100000)",
      "tmpfs mount",
      "ENOSPC",
    ],
    ["setting up newroot bind: Permission denied", "bind-mount", "EACCES"],
    [
      "Can't bind mount /fixture/source on /fixture/destination: Unable to remount destination with correct flags: Invalid argument",
      "bind-mount",
      "EINVAL",
    ],
    [
      "Can't mount proc on /fixture/private: Operation not permitted",
      "procfs mount",
      "EPERM",
    ],
    [
      "Can't mount devpts on /fixture/private: Operation not supported",
      "device setup",
      "ENOTSUP",
    ],
    [
      "Can't create file /dev/null: Permission denied",
      "device setup",
      "EACCES",
    ],
    [
      "Can't create symlink /dev/stdin: Not a directory",
      "device setup",
      "ENOTDIR",
    ],
    [
      "Can't make symlink at /dev/ptmx: Permission denied",
      "device setup",
      "EACCES",
    ],
    [
      "execvp /fixture/private: Exec format error",
      "executable launch",
      "ENOEXEC",
    ],
  ]) {
    for (const stream of ["stderr", "stdout"]) {
      const output = `<3>bwrap: ${message}\npassword=private-value\n::warning::private`;
      const cause = feasibilityFailureCause("prepare", "ordinary-namespace", {
        exitCode: 1,
        signal: null,
        timedOut: false,
        [stream]: Buffer.from(output),
      });
      assert.ok(cause.detail.includes(`${explanation} failure.`));
      assert.match(
        cause.detail,
        /exit=1, signal=none, timeout=false; output=recognized/u,
      );
      if (native) assert.ok(cause.detail.includes(`native=${native};`));
      else assert.doesNotMatch(cause.detail, /native=/u);
      assert.doesNotMatch(
        cause.detail,
        /\/fixture|\/dev|\/proc|private|password|warning|kernel|Hint|sysctl/u,
      );
      assert.ok(Buffer.byteLength(cause.detail) <= 256);
    }
  }
  for (const output of [
    "bwrap: Can't open /fixture/namespace failed: Invalid argument",
    "bwrap: Can't open /fixture/setting up uid map: Invalid argument",
    "bwrap: Can't mount /fixture/tmpfs: Invalid argument",
  ])
    assert.equal(feasibilityDiagnostic(output), null);
  for (const native of ["constructor", "toString", "unrecognized errno"]) {
    const cause = feasibilityFailureCause("prepare", "ordinary-namespace", {
      stderr: `bwrap: Failed to make / slave: ${native}`,
    });
    assert.doesNotMatch(cause.detail, /native=/u);
  }
});

test("Bubblewrap diagnostics obey both byte capture bounds and first-failure ordering", () => {
  const diagnostic = "bwrap: Failed to make / slave: Permission denied";
  for (const prefix of ["x".repeat(65536), "λ".repeat(32768)]) {
    for (const output of [
      prefix + "\n" + diagnostic,
      Buffer.from(prefix + "\n" + diagnostic),
    ]) {
      assert.equal(feasibilityDiagnostic(output), null);
      const cause = feasibilityFailureCause("prepare", "ordinary-namespace", {
        stderr: output,
        stdout: diagnostic,
      });
      assert.match(cause.detail, /output=recognized, native=EACCES/u);
    }
  }
  assert.equal(
    feasibilityDiagnostic(
      diagnostic + "\nbwrap: execvp /fixture/private: Exec format error",
    ),
    "Bubblewrap reported a mount-propagation failure.",
  );
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
          components: [
            {
              role: "tool",
              name: "fixture",
              version: "1 | <version>",
              sha256: "b".repeat(64),
            },
          ],
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
  assert.match(summary, /fixture@1 &#124; &#60;version&#62; sha256=b{64}/u);
  assert.match(
    summary,
    /independent=false, emergency=false, sha256=UNOBSERVED/u,
  );
  assert.doesNotMatch(summary, /<failure>|<build>/u);
});

test("Linux mapping refusal retains preparation, derivative blocks, installed identity and model-free cleanup", async () => {
  const mapping = {
    exitCode: 1,
    signal: null,
    timedOut: false,
    stderr: "bwrap: setting up uid map: Permission denied",
  };
  const preparation = feasibilityFailureCause(
    "prepare",
    "ordinary-namespace",
    mapping,
    "prerequisite-unavailable",
  );
  const admission = feasibilityFailureCause(
    "admission",
    "ordinary-namespace",
    mapping,
    "prerequisite-unavailable",
  );
  const component = {
    role: "tool",
    name: "bubblewrap",
    version: "bubblewrap 0.9.0",
    sha256: "b".repeat(64),
  };
  const nativeIds = new Set(
    feasibilityCapabilities("linux")
      .filter(({ tier }) => tier === "native")
      .map(({ id }) => id),
  );
  const native = unavailableFeasibilityResults("linux", preparation)
    .filter(({ capability }) => nativeIds.has(capability))
    .map((entry) => ({ ...entry, components: [component] }));
  const providers = unavailableFeasibilityResults("linux", admission).filter(
    ({ capability }) => !nativeIds.has(capability),
  );
  const command = providers.find(
    ({ capability }) => capability === "codex.command-exec",
  );
  command.cleanup = {
    status: "PASS",
    independent: true,
    emergency: false,
    elapsedMs: 1,
    witnessSha256: "c".repeat(64),
    cause: null,
  };
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
      runNative: async () => native,
      runProviders: async () => providers,
    },
  );
  const conclusions = {
    ...env,
    NATIVE_PREPARATION_CONCLUSION: "success",
    NATIVE_PREPARATION_OPERATION: "linux-package-install",
    NATIVE_PREPARATION_EXIT_CODE: "0",
    NATIVE_PROBE_CONCLUSION: "failure",
    NATIVE_CLEANUP_CONCLUSION: "success",
  };
  const reported = assessFeasibilityPreparation(
    assessment,
    intent,
    conclusions,
  );
  assert.equal(reported.status, "BLOCKED");
  assert.deepEqual(reported.issues, []);
  for (const entry of reported.report.results) {
    assert.equal(entry.status, "BLOCKED");
    assert.equal(entry.evidence, null);
    assert.deepEqual(
      entry.cause,
      nativeIds.has(entry.capability) ? preparation : admission,
    );
    assert.match(
      entry.cause.detail,
      /native=EACCES; Bubblewrap reported a UID or GID mapping failure\./u,
    );
    assert.deepEqual(
      entry.components,
      nativeIds.has(entry.capability) ? [component] : [],
    );
    assert.deepEqual(
      entry.cleanup,
      entry.capability === command.capability
        ? command.cleanup
        : native[0].cleanup,
    );
  }
  const summary = renderFeasibilitySummary(reported, intent, conclusions);
  assert.match(
    summary,
    /launch\.argv \| BLOCKED \| NOT_RUN \| prerequisite-unavailable: prepare ordinary-namespace/u,
  );
  assert.match(
    summary,
    /codex\.command-exec \| BLOCKED \| PASS \| prerequisite-unavailable: admission ordinary-namespace/u,
  );
  assert.match(
    summary,
    /provider\.transport \| BLOCKED \| NOT_RUN \| prerequisite-unavailable: admission ordinary-namespace/u,
  );
  assert.match(summary, /bubblewrap@bubblewrap 0\.9\.0 sha256=b{64}/u);
  assert.match(summary, /independent=true, emergency=false, sha256=c{64}/u);
  assert.doesNotMatch(summary, /AppArmor|sysctl|\/proc|\/fixture/u);
});

test("summary binds build diagnostics and inspected bytes without turning admission blocks into defects", () => {
  const input = structuredClone(initialized("win32").report);
  const primary = {
    code: "setup-failed",
    detail:
      "prepare helper-compile: exit=2, signal=none, timeout=false; output=recognized; MSVC error C2065: undeclared identifier.",
  };
  const components = [
    { role: "tool", name: "msvc", version: "1", sha256: "b".repeat(64) },
    {
      role: "tool",
      name: "windows-sdk-header",
      version: "2",
      sha256: "c".repeat(64),
    },
    {
      role: "tool",
      name: "windows-command-source",
      version: "1",
      sha256: "d".repeat(64),
    },
  ];
  input.results[0] = {
    ...input.results[0],
    status: "FAIL",
    cause: primary,
    components,
    cleanup: {
      ...input.results[0].cleanup,
      status: "UNCERTAIN",
      cause: {
        code: "cleanup-unobserved",
        detail:
          "Owned temporary resource removal was not independently observed.",
      },
    },
  };
  input.results[1].components = structuredClone(components);
  input.results[2].components = [{ ...components[0], sha256: "e".repeat(64) }];
  const dependent = input.results.find(
    ({ capability }) => capability === "codex.command-exec",
  );
  dependent.status = "BLOCKED";
  dependent.cause = {
    code: "prerequisite-unavailable",
    detail: `Unsettled native cleanup prevents provider admission; origin=${primary.code}; ${primary.detail}`,
  };
  const assessment = assessFeasibilityReport(input);
  const before = structuredClone(assessment);
  const render = (value) =>
    renderFeasibilitySummary(
      value,
      { ...intent, platform: "win32" },
      {
        ...env,
        NATIVE_PLATFORM: "win32",
        NATIVE_PREPARATION_OPERATION: "windows-discovery",
        NATIVE_PREPARATION_CONCLUSION: "success",
        NATIVE_PREPARATION_EXIT_CODE: "0",
        NATIVE_PROBE_CONCLUSION: "failure",
      },
    );
  const summary = render(assessment);
  assert.deepEqual(assessment, before);
  assert.equal(assessment.status, "FAIL");
  assert.match(
    summary,
    /launch.argv \| FAIL \| UNCERTAIN \| setup-failed: prepare helper-compile/u,
  );
  assert.match(
    summary,
    /codex.command-exec \| BLOCKED \| NOT_RUN \| none \| prerequisite-unavailable: Unsettled native cleanup/u,
  );
  assert.match(
    summary,
    /cleanup-unobserved: Owned temporary resource removal/u,
  );
  assert.match(summary, /Checkout: a{40}; platform: win32; architecture: x64/u);
  for (const component of components) {
    assert.equal(summary.split(`sha256=${component.sha256}`).length - 1, 1);
    assert.ok(
      summary.includes(
        `${component.name}@${component.version} sha256=${component.sha256} | launch.argv, access.read-only`,
      ),
    );
  }
  assert.match(summary, /msvc@1 sha256=e{64} \| access.workspace-write/u);
  assert.doesNotMatch(summary, /helper:windows-command-helper/u);
  assert.match(
    summary,
    /Tool or source inspection does not prove compilation, linking or admission/u,
  );

  // An acknowledged provider attempt with settled cleanup remains its own
  // observed cause, even when native cleanup is independently unsettled.
  dependent.evidence = {
    ready: false,
    positiveControl: false,
    attemptAcknowledged: true,
    independent: false,
    outcome: null,
    observationSha256: null,
    sentinelsBeforeSha256: null,
    sentinelsAfterSha256: null,
  };
  dependent.cleanup = {
    status: "PASS",
    independent: true,
    emergency: false,
    elapsedMs: 1,
    witnessSha256: "f".repeat(64),
    cause: null,
  };
  const admitted = render(assessFeasibilityReport(input));
  assert.match(
    admitted,
    /codex.command-exec \| BLOCKED \| PASS \| prerequisite-unavailable: Unsettled native cleanup/u,
  );
  dependent.evidence = null;
  dependent.cleanup = structuredClone(input.results[1].cleanup);

  // The same text without unsettled native cleanup cannot imply this gate ran.
  input.results[0].cleanup = structuredClone(input.results[1].cleanup);
  const settled = render(assessFeasibilityReport(input));
  assert.match(
    settled,
    /codex.command-exec \| BLOCKED \| NOT_RUN \| prerequisite-unavailable: Unsettled native cleanup/u,
  );
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
