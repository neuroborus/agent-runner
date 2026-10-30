import { win32 as path } from "node:path";
import {
  observationDigest,
  observationObject,
  requireObservation,
} from "../index.js";
import { hash } from "./protocol.js";
import { location } from "./custody-protocol.js";
import { WINDOWS_BUILD_TOOLS, WINDOWS_HELPER_NAMES } from "./build.js";
import { windowsSystemRecipes } from "./system.js";
import {
  WINDOWS_EXPERIMENT_SOURCES,
  windowsHostedCompilerArguments,
} from "./experiment-native.js";
import { assertWindowsExperimentGitSelection } from "./experiment-cases.js";

export function windowsExperimentBuildInventory(prepared) {
  observationObject(prepared, [
    "purpose",
    "schemaVersion",
    "job",
    "binding",
    "directory",
    "output",
    "sourceDirectory",
    "bootstrap",
    "sources",
    "tools",
    "helpers",
    "entries",
    "environment",
    "sdkBuild",
    "sdkHeader",
    "gitRuntime",
    "commands",
    "versions",
  ]);
  requireObservation(
    prepared.schemaVersion === 4 &&
      prepared.purpose === "experiment" &&
      prepared.job.platform === "win32" &&
      prepared.output === path.join(prepared.directory, "platform-build") &&
      prepared.sourceDirectory === prepared.directory + "-bootstrap" &&
      prepared.bootstrap.context.jobBindingSha256 ===
        observationDigest(prepared.binding),
  );
  assertWindowsExperimentGitSelection(prepared.gitRuntime);
  for (const [entries, names] of [
    [prepared.sources, WINDOWS_EXPERIMENT_SOURCES],
    [prepared.helpers, WINDOWS_HELPER_NAMES],
  ])
    requireObservation(
      Array.isArray(entries) &&
        entries.length === names.length &&
        new Set(entries.map(({ name }) => name)).size === names.length &&
        entries.every(
          ({ name, sha256 }) => names.includes(name) && hash(sha256),
        ),
    );
  for (const helper of prepared.helpers) {
    observationObject(helper, [
      "name",
      "path",
      "sha256",
      "signatureSha256",
      "sourceSha256",
    ]);
    requireObservation(
      helper.path ===
        path.join(prepared.sourceDirectory, helper.name + ".exe") &&
        helper.signatureSha256 === helper.sha256 &&
        helper.sourceSha256 ===
          prepared.sources.find((source) => source.name === helper.name + ".c")
            .sha256,
    );
  }
  requireObservation(prepared.tools.length === WINDOWS_BUILD_TOOLS.length);
  for (const [index, recipe] of WINDOWS_BUILD_TOOLS.entries()) {
    const tool = prepared.tools[index];
    observationObject(tool, ["name", "path", "sha256"]);
    requireObservation(
      tool.name === recipe.name &&
        recipe.path.test(tool.path) &&
        hash(tool.sha256),
    );
  }
  observationObject(prepared.environment, [
    "INCLUDE",
    "LIB",
    "SystemRoot",
    "PATH",
  ]);
  requireObservation(
    Object.values(prepared.environment).every(
      (value) =>
        typeof value === "string" &&
        value.length > 0 &&
        !/[\0\r\n]/u.test(value),
    ) && /^[0-9]+(?:\.[0-9]+){3}$/u.test(prepared.sdkBuild),
  );
  observationObject(prepared.sdkHeader, ["file", "sha256"]);
  requireObservation(
    location(prepared.sdkHeader.file) &&
      /\\Windows Kits\\10\\Include\\[0-9.]+\\um\\Windows\.h$/u.test(
        prepared.sdkHeader.file,
      ) &&
      hash(prepared.sdkHeader.sha256),
  );
  observationObject(prepared.versions, ["compiler", "sdk"]);
  requireObservation(
    Object.values(prepared.versions).every((value) =>
      /^[0-9.]+$/u.test(value),
    ) &&
      Array.isArray(prepared.commands) &&
      prepared.commands.length === WINDOWS_HELPER_NAMES.length + 7,
  );
  for (const command of prepared.commands) {
    observationObject(command, [
      "file",
      "args",
      "cwd",
      "env",
      "timeout",
      "maxBuffer",
      "exitCode",
      "signal",
      "timedOut",
      "stdout",
      "stderr",
    ]);
    requireObservation(
      typeof command.file === "string" &&
        Array.isArray(command.args) &&
        command.args.every(
          (arg) => typeof arg === "string" && !arg.includes("\0"),
        ) &&
        location(command.cwd) &&
        command.env &&
        typeof command.env === "object" &&
        command.timeout === 60000 &&
        command.maxBuffer === 1048576 &&
        Number.isInteger(command.exitCode) &&
        command.signal === null &&
        command.timedOut === false &&
        [command.stdout, command.stderr].every(
          (value) =>
            typeof value === "string" && Buffer.byteLength(value) <= 1048576,
        ),
    );
  }
  const [git, where, gitWhere, gitExec] = prepared.commands,
    who = prepared.commands.at(-1);
  requireObservation(
    git.file === "git" &&
      observationDigest(git.args) ===
        observationDigest(["rev-parse", "HEAD"]) &&
      git.stdout.trim() === prepared.job.candidateSha &&
      git.exitCode === 0 &&
      where.file === "where.exe" &&
      observationDigest(where.args) === observationDigest(["cl.exe"]) &&
      where.stdout.trim().split(/\r?\n/u)[0] === prepared.tools[0].path &&
      where.exitCode === 0 &&
      gitWhere.file === "where.exe" &&
      observationDigest(gitWhere.args) === observationDigest(["git.exe"]) &&
      gitWhere.stdout.trim().split(/\r?\n/u)[0] ===
        prepared.gitRuntime.executable &&
      gitWhere.exitCode === 0 &&
      gitExec.file === prepared.gitRuntime.executable &&
      observationDigest(gitExec.args) === observationDigest(["--exec-path"]) &&
      gitExec.stdout.trim().replaceAll("/", "\\") ===
        prepared.gitRuntime.execPath &&
      gitExec.exitCode === 0 &&
      who.file ===
        path.join(prepared.environment.SystemRoot, "System32", "whoami.exe") &&
      observationDigest(who.args) ===
        observationDigest(["/user", "/fo", "csv", "/nh"]) &&
      who.exitCode === 0 &&
      /"(S-1-5-21-(?:[0-9]+-){3}[0-9]+)"\s*$/u.exec(who.stdout.trim())?.[1] ===
        prepared.bootstrap.runnerSid,
  );
  const compiler = prepared.commands.filter(
      (command) => command.file === prepared.tools[0].path,
    ),
    compilerEnvironment = {
      CI: "true",
      GITHUB_ACTIONS: "true",
      LANG: "C",
      ...prepared.environment,
      TEMP: path.dirname(prepared.directory),
      TMP: path.dirname(prepared.directory),
    };
  requireObservation(compiler.length === WINDOWS_HELPER_NAMES.length + 1);
  for (const [index, name] of WINDOWS_HELPER_NAMES.entries()) {
    const command = compiler[index + 1];
    requireObservation(
      command.exitCode === 0 &&
        command.cwd === prepared.sourceDirectory &&
        observationDigest(command.args) ===
          observationDigest(
            windowsHostedCompilerArguments(
              path.join(prepared.sourceDirectory, name + ".c"),
              path.join(prepared.sourceDirectory, name + ".exe"),
            ),
          ),
    );
  }
  // TEMP/TMP are the actual hosted temporary root, which may contain the private
  // report through multiple parent directories. Preserve it explicitly.
  for (const command of prepared.commands.filter((command) =>
    prepared.tools.some((tool) => tool.path === command.file),
  )) {
    observationObject(command.env, Object.keys(compilerEnvironment));
    requireObservation(
      location(command.env.TEMP) &&
        command.env.TEMP === command.env.TMP &&
        prepared.directory.startsWith(command.env.TEMP + "\\") &&
        Object.entries(compilerEnvironment).every(
          ([key, value]) =>
            ["TEMP", "TMP"].includes(key) || command.env[key] === value,
        ),
    );
  }
  for (const [index, tool] of prepared.tools.entries()) {
    const commands = prepared.commands.filter(
      (command) =>
        command.file === tool.path &&
        observationDigest(command.args) ===
          observationDigest(WINDOWS_BUILD_TOOLS[index].args),
    );
    requireObservation(
      commands.length === 1 &&
        [0, ...WINDOWS_BUILD_TOOLS[index].versionExitCodes].includes(
          commands[0].exitCode,
        ),
    );
    const text = commands[0].stdout + "\n" + commands[0].stderr;
    requireObservation(
      (index === 0
        ? /Compiler Version ([0-9.]+) for x64/u.exec(text)?.[1]
        : /Version ([0-9.]+)/u.exec(text)?.[1]) ===
        prepared.versions[tool.name],
    );
  }
  return windowsSystemRecipes();
}
