import assert from "node:assert/strict";
import test from "node:test";
import {
  assessFeasibilityPreparation,
  assessFeasibilityReport,
  renderFeasibilitySummary,
  selectInstalledWindowsToolchain,
  unavailableFeasibilityResults,
} from "../ci/native/feasibility/index.js";

const temporaryRoot = "C:\\Native Temp";
const directory = `${temporaryRoot}\\msvc-fixture`;
const installation = "C:\\Program Files (x86)\\Fixture Toolchain";
const environment = {
  "ProgramFiles(x86)": "C:\\Program Files (x86)",
  SystemRoot: "C:\\Windows",
};
const selected = {
  PATH: "C:\\Tools With Spaces\\bin",
  INCLUDE: "C:\\Fixture SDK\\include",
  LIB: "C:\\Fixture SDK\\lib",
  LIBPATH: "C:\\Fixture SDK\\references",
  WindowsSdkDir: "C:\\Fixture SDK\\",
  WindowsSDKVersion: "0.0.0.0\\",
  VCINSTALLDIR: "C:\\Fixture = Toolchain\\",
  VCToolsInstallDir: "C:\\Fixture Tools\\",
};
const output = Object.entries({ PRIVATE_VALUE: "never-export", ...selected })
  .map(([key, value]) => `${key === "PATH" ? "Path" : key}=${value}\r\n`)
  .join("");
function fixture(options = {}) {
  const events = [];
  const effects = {
    execute: async (file, args, settings) => {
      events.push({ kind: "process", file, args, settings });
      if (file.endsWith("vswhere.exe")) {
        if (options.discoveryError) throw options.discoveryError;
        return { stdout: options.discovery ?? `${installation}\r\n` };
      }
      if (options.setupError) throw options.setupError;
      return { stdout: options.output ?? output };
    },
    mkdtemp: async (prefix) => {
      events.push({ kind: "directory", prefix });
      return directory;
    },
    writeFile: async (file, contents, settings) => {
      events.push({ kind: "write", file, contents, settings });
      if (options.writeError) throw options.writeError;
    },
    unlink: async (file) => {
      events.push({ kind: "unlink", file });
      if (options.cleanupError) throw options.cleanupError;
    },
    rmdir: async (file) => {
      events.push({ kind: "rmdir", file });
      if (options.directoryError) throw options.directoryError;
    },
    capture: async (record) => {
      events.push({ kind: "capture", ...record });
    },
  };
  return {
    events,
    run: () =>
      selectInstalledWindowsToolchain({ environment, temporaryRoot }, effects),
  };
}
function reporting(prepared) {
  const sha = "a".repeat(40),
    platform = "win32";
  const intent = {
    expectedSha: sha,
    platform,
    protectedAcceptance: false,
    runId: "7",
    runAttempt: "2",
  };
  const input = assessFeasibilityReport({
    schemaVersion: 1,
    expectedSha: sha,
    checkoutSha: sha,
    platform,
    os: platform,
    build: "synthetic-build",
    architecture: "x64",
    results: unavailableFeasibilityResults(platform, {
      code: "missing-record",
      detail: "The probe stage has not returned a complete report.",
    }),
  });
  const env = {
    NATIVE_CANDIDATE_SHA: sha,
    NATIVE_PLATFORM: platform,
    GITHUB_RUN_ID: "7",
    GITHUB_RUN_ATTEMPT: "2",
    NATIVE_PREPARATION_CONCLUSION: "failure",
    NATIVE_PROBE_CONCLUSION: "skipped",
    NATIVE_CLEANUP_CONCLUSION: "failure",
    NATIVE_PREPARATION_OPERATION: prepared.operation,
    NATIVE_PREPARATION_EXIT_CODE: String(prepared.exitCode ?? ""),
    NATIVE_PREPARATION_CAUSE: prepared.cause
      ? JSON.stringify(prepared.cause)
      : "",
    NATIVE_PREPARATION_CLEANUP_CAUSE: prepared.cleanupCause
      ? JSON.stringify(prepared.cleanupCause)
      : "",
  };
  return { input, intent, env };
}

test("installed MSVC selection preserves spaced paths and exports only allowed environment values", async () => {
  const { run, events } = fixture();
  const result = await run();
  assert.deepEqual(result.environment, selected);
  assert.equal(result.cause, null);
  assert.equal(result.cleanupCause, null);
  const [discovery, setup] = events.filter(({ kind }) => kind === "process");
  assert.equal(
    discovery.file,
    `${environment["ProgramFiles(x86)"]}\\Microsoft Visual Studio\\Installer\\vswhere.exe`,
  );
  assert.deepEqual(discovery.args, [
    "-latest",
    "-products",
    "*",
    "-requires",
    "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
    "-property",
    "installationPath",
  ]);
  assert.equal(setup.file, "C:\\Windows\\System32\\cmd.exe");
  assert.deepEqual(setup.args, ["/d", "/s", "/c", ".\\setup.cmd"]);
  assert.equal(setup.settings.cwd, directory);
  assert.equal(setup.settings.windowsVerbatimArguments, true);
  assert.equal(setup.settings.maxBuffer, 65536);
  const written = events.find(({ kind }) => kind === "write");
  assert.equal(written.settings.flag, "wx");
  assert.equal(written.file, `${directory}\\setup.cmd`);
  assert.ok(
    written.contents.includes(
      `call "${installation}\\VC\\Auxiliary\\Build\\vcvars64.bat" 1>&2\r\nset "NATIVE_FEASIBILITY_SETUP_STATUS=%errorlevel%"\r\n`,
    ),
  );
  assert.ok(
    written.contents.indexOf(
      'if not "%NATIVE_FEASIBILITY_SETUP_STATUS%"=="0" exit /b',
    ) < written.contents.indexOf("\r\nset\r\n"),
  );
  assert.deepEqual(
    events
      .filter(({ kind }) => ["unlink", "rmdir"].includes(kind))
      .map(({ file }) => file),
    [written.file, directory],
  );
  assert.doesNotMatch(JSON.stringify(result), /never-export/u);
});

test("nonzero setup status and sanitized first cause survive temporary-file cleanup failures and reporting", async () => {
  const { run, events } = fixture({
    setupError: {
      code: 7,
      signal: null,
      timedOut: false,
      stderr:
        "'fixture-command' is not recognized as an internal or external command",
      stdout: "PRIVATE_VALUE=never-export",
    },
    cleanupError: { code: "EACCES" },
    directoryError: { code: "ENOTEMPTY" },
  });
  const prepared = await run();
  assert.equal(prepared.exitCode, 7);
  assert.deepEqual(prepared.environment, {});
  assert.match(
    prepared.cause.detail,
    /windows-sdk-setup: exit=7, signal=none, timeout=false; output=recognized; The command interpreter/u,
  );
  assert.match(
    prepared.cleanupCause.detail,
    /cleanup windows-toolchain-files: .*access check/u,
  );
  const captured = events.findIndex(
    (event) => event.kind === "capture" && event.exitCode === 7,
  );
  assert.ok(
    captured > 0 &&
      captured < events.findIndex(({ kind }) => kind === "unlink"),
  );
  const { input, intent, env } = reporting(prepared);
  const assessment = assessFeasibilityPreparation(input, intent, env);
  assert.deepEqual(assessment.report.results[0].cause, prepared.cause);
  assert.equal(assessment.report.results[0].cleanup.cause, null);
  const summary = renderFeasibilitySummary(assessment, intent, env);
  assert.match(
    summary,
    /Preparation file cleanup: cleanup-failed: cleanup windows-toolchain-files/u,
  );
  assert.doesNotMatch(JSON.stringify(assessment), /never-export/u);
  for (const value of [
    "{",
    "x".repeat(513),
    JSON.stringify({
      ...prepared.cause,
      detail: "prepare windows-discovery: exit=7, wrong operation",
    }),
    JSON.stringify({
      ...prepared.cause,
      detail:
        "prepare windows-sdk-setup: exit=7, https://example.invalid/private",
    }),
  ]) {
    assert.throws(
      () =>
        assessFeasibilityPreparation(input, intent, {
          ...env,
          NATIVE_PREPARATION_CAUSE: value,
        }),
      { code: "ERR_INVALID_NATIVE_FEASIBILITY" },
    );
  }
});

test("unavailable or malformed discovery stops before creating a wrapper or running cmd", async () => {
  for (const options of [
    { discovery: "" },
    { discovery: `${installation}\r\nC:\\Other Tools\r\n` },
    { discovery: "C:\\Tools\\%PRIVATE_VALUE%" },
    { discovery: "relative\\tools" },
    { discovery: "x".repeat(16385) },
    { discoveryError: { code: "ENOENT" } },
  ]) {
    const { run, events } = fixture(options);
    const result = await run();
    assert.equal(result.cause.code, "prerequisite-unavailable");
    assert.equal(result.cleanupCause, null);
    assert.equal(events.filter(({ kind }) => kind === "process").length, 1);
    assert.equal(
      events.some(({ kind }) => kind === "directory" || kind === "write"),
      false,
    );
    assert.deepEqual(result.environment, {});
  }
});

test("private environment capture rejects oversized, duplicate, missing and unsafe allowed values", async () => {
  for (const value of [
    "x".repeat(65537),
    output + "PATH=C:\\Other Tools\r\n",
    "PATH=C:\\Tools\r\n",
    output.replace(selected.INCLUDE, "C:\\Fixture\u0000SDK"),
  ]) {
    const prepared = await fixture({ output: value }).run();
    assert.equal(prepared.operation, "windows-environment-export");
    assert.match(
      prepared.cause.detail,
      /exit=unknown.*valid bounded compiler environment/u,
    );
    assert.deepEqual(prepared.environment, {});
    assert.equal(prepared.cleanupCause, null);
  }
});

test("cleanup-only failure is separate, and a failed exclusive write never removes an unowned wrapper", async () => {
  const prepared = await fixture({ cleanupError: { code: "EACCES" } }).run();
  assert.equal(prepared.cause, null);
  assert.equal(prepared.cleanupCause.code, "cleanup-failed");
  const { input, intent, env } = reporting(prepared);
  const assessment = assessFeasibilityPreparation(input, intent, env);
  assert.deepEqual(assessment.report.results[0].cause, prepared.cleanupCause);
  assert.equal(assessment.report.results[0].cleanup.status, "NOT_RUN");
  const { run, events } = fixture({
    writeError: { code: "EEXIST" },
    directoryError: { code: "ENOTEMPTY" },
  });
  const failed = await run();
  assert.equal(failed.cause.code, "setup-failed");
  assert.equal(
    events.some(({ kind }) => kind === "unlink"),
    false,
  );
  assert.equal(events.filter(({ kind }) => kind === "rmdir").length, 1);
  assert.equal(events.filter(({ kind }) => kind === "process").length, 1);
});
