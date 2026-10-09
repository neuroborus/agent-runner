import { execFile } from "node:child_process";
import { mkdtemp, rmdir, unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { feasibilityFailureCause, requireFeasibility } from "./result.js";

const execute = promisify(execFile);
const ENVIRONMENT = [
  "PATH",
  "INCLUDE",
  "LIB",
  "LIBPATH",
  "WindowsSdkDir",
  "WindowsSDKVersion",
  "VCINSTALLDIR",
  "VCToolsInstallDir",
];
const safePath = (value) =>
  typeof value === "string" &&
  value.length <= 1024 &&
  /^[A-Za-z]:\\/u.test(value) &&
  !/[^\x20-\x7e]|["%!^&|<>]/u.test(value) &&
  path.win32.normalize(value) === value;
const fail = (code) => {
  throw Object.assign(
    new Error("Installed Windows toolchain selection failed."),
    { code },
  );
};

/** Installed CI toolchain only. Injection proves construction, not cmd parsing. */
export async function selectInstalledWindowsToolchain(
  { environment, temporaryRoot },
  {
    execute: command = execute,
    mkdtemp: temporary = mkdtemp,
    writeFile: write = writeFile,
    unlink: removeFile = unlink,
    rmdir: removeDirectory = rmdir,
    capture = async () => {},
  } = {},
) {
  requireFeasibility(
    command !== execute ||
      (process.platform === "win32" &&
        process.arch === "x64" &&
        process.env.CI === "true" &&
        process.env.GITHUB_ACTIONS === "true" &&
        process.env.RUNNER_ENVIRONMENT === "github-hosted" &&
        process.env.RUNNER_OS === "Windows"),
  );
  requireFeasibility(safePath(temporaryRoot));
  let operation,
    exitCode = null,
    cause = null,
    cleanupCause = null,
    directory,
    wrapper;
  let wrapperOwned = false,
    outcome = {},
    selected = {};
  const record = async (next, observed = {}) => {
    operation = next;
    outcome = observed;
    exitCode = observed.exitCode ?? null;
    await capture({ operation, exitCode });
  };
  try {
    await record("windows-discovery");
    const programFiles = environment["ProgramFiles(x86)"],
      systemRoot = environment.SystemRoot;
    if (!safePath(programFiles) || !safePath(systemRoot))
      fail("ERR_FEASIBILITY_WINDOWS_DISCOVERY");
    const found = await command(
      path.win32.join(
        programFiles,
        "Microsoft Visual Studio",
        "Installer",
        "vswhere.exe",
      ),
      [
        "-latest",
        "-products",
        "*",
        "-requires",
        "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
        "-property",
        "installationPath",
      ],
      {
        env: environment,
        encoding: "utf8",
        timeout: 10000,
        maxBuffer: 16384,
        windowsHide: true,
      },
    );
    await record(operation, { exitCode: 0, signal: null, timedOut: false });
    if (
      typeof found.stdout !== "string" ||
      Buffer.byteLength(found.stdout) > 16384
    )
      fail("ERR_FEASIBILITY_WINDOWS_DISCOVERY");
    const installation = found.stdout.trim();
    if (!safePath(installation)) fail("ERR_FEASIBILITY_WINDOWS_DISCOVERY");
    await record("windows-sdk-setup");
    const created = await temporary(path.win32.join(temporaryRoot, "msvc-"));
    requireFeasibility(
      safePath(created) &&
        path.win32.dirname(created) === temporaryRoot &&
        /^msvc-.+/u.test(path.win32.basename(created)),
    );
    directory = created;
    wrapper = path.win32.join(directory, "setup.cmd");
    await write(
      wrapper,
      [
        "@echo off",
        "setlocal DisableDelayedExpansion",
        "set ERRORLEVEL=",
        `call "${path.win32.join(installation, "VC", "Auxiliary", "Build", "vcvars64.bat")}" 1>&2`,
        'set "NATIVE_FEASIBILITY_SETUP_STATUS=%errorlevel%"',
        'if not "%NATIVE_FEASIBILITY_SETUP_STATUS%"=="0" exit /b %NATIVE_FEASIBILITY_SETUP_STATUS%',
        "set",
        "exit /b %NATIVE_FEASIBILITY_SETUP_STATUS%",
        "",
      ].join("\r\n"),
      { flag: "wx", encoding: "utf8" },
    );
    wrapperOwned = true;
    // The fixed relative name avoids quoting a temporary path at /c's boundary.
    const configured = await command(
      path.win32.join(systemRoot, "System32", "cmd.exe"),
      ["/d", "/s", "/c", ".\\setup.cmd"],
      {
        cwd: directory,
        env: environment,
        encoding: "utf8",
        timeout: 60000,
        maxBuffer: 65536,
        windowsHide: true,
        windowsVerbatimArguments: true,
      },
    );
    await record(operation, { exitCode: 0, signal: null, timedOut: false });
    await record("windows-environment-export");
    if (
      typeof configured.stdout !== "string" ||
      Buffer.byteLength(configured.stdout) > 65536
    )
      fail("ERR_FEASIBILITY_WINDOWS_ENVIRONMENT");
    for (const line of configured.stdout.split(/\r?\n/u)) {
      const separator = line.indexOf("="),
        name = ENVIRONMENT.find(
          (key) => key.toLowerCase() === line.slice(0, separator).toLowerCase(),
        );
      if (separator < 1 || !name) continue;
      const value = line.slice(separator + 1);
      if (
        Object.hasOwn(selected, name) ||
        !value.isWellFormed() ||
        /[\p{Cc}\p{Zl}\p{Zp}]/u.test(value)
      )
        fail("ERR_FEASIBILITY_WINDOWS_ENVIRONMENT");
      selected[name] = value;
    }
    if (!["PATH", "INCLUDE", "LIB"].every((name) => selected[name]))
      fail("ERR_FEASIBILITY_WINDOWS_ENVIRONMENT");
  } catch (error) {
    const facts = {
      ...outcome,
      code: error?.code,
      stderr: error?.stderr,
      signal: error?.signal === undefined ? outcome.signal : error.signal,
      timedOut:
        error?.timedOut === undefined ? outcome.timedOut : error.timedOut,
    };
    if (error && Object.hasOwn(error, "exitCode"))
      facts.exitCode = error.exitCode;
    else if (Number.isInteger(error?.code) && error?.signal === null)
      facts.exitCode = error.code;
    exitCode =
      Number.isInteger(facts.exitCode) &&
      facts.exitCode >= -2147483648 &&
      facts.exitCode <= 4294967295
        ? facts.exitCode
        : null;
    // stdout may contain a private environment enumeration; never diagnose it.
    cause = feasibilityFailureCause(
      "prepare",
      operation,
      facts,
      operation === "windows-discovery"
        ? "prerequisite-unavailable"
        : "setup-failed",
    );
    selected = {};
    await capture({ operation, exitCode });
  } finally {
    for (const [remove, owned] of [
      [removeFile, wrapperOwned ? wrapper : null],
      [removeDirectory, directory],
    ]) {
      if (!owned) continue;
      try {
        await remove(owned);
      } catch (error) {
        cleanupCause ??= feasibilityFailureCause(
          "cleanup",
          "windows-toolchain-files",
          error,
          "cleanup-failed",
        );
      }
    }
  }
  return { operation, exitCode, cause, cleanupCause, environment: selected };
}
