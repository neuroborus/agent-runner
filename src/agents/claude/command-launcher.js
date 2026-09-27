import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import {
  access,
  chmod,
  mkdtemp,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { delimiter, isAbsolute, join, relative, resolve, sep } from "node:path";

export const CLAUDE_COMMAND_LAUNCHER_TOKEN =
  "AGENT_RUNNER_CLAUDE_COMMAND_LAUNCHER_TOKEN";

export function claudeCommandLauncherSettings(path) {
  return JSON.stringify({ sandbox: { bwrapPath: path } });
}

function containsPath(parent, child) {
  const path = relative(resolve(parent), resolve(child));
  return path === "" || (path !== ".." && !path.startsWith(`..${sep}`));
}

async function resolveExecutable(binary, environment) {
  if (isAbsolute(binary)) {
    await access(binary, constants.X_OK);
    return realpath(binary);
  }
  for (const directory of (environment.PATH ?? "")
    .split(delimiter)
    .filter(isAbsolute)) {
    const candidate = join(directory, binary);
    try {
      await access(candidate, constants.X_OK);
      return await realpath(candidate);
    } catch {
      // Continue past unusable absolute PATH entries.
    }
  }
  throw new Error("Claude command isolation executable is unavailable.");
}

async function claudeIncidentalWritablePaths(environment) {
  const homeDirectory =
    typeof environment.HOME === "string" && isAbsolute(environment.HOME)
      ? environment.HOME
      : homedir();
  const candidates = [
    "/tmp/claude",
    "/private/tmp/claude",
    join(homeDirectory, ".npm/_logs"),
    join(homeDirectory, ".claude/debug"),
  ];
  const paths = new Set(candidates.map((path) => resolve(path)));
  for (const path of candidates) {
    try {
      paths.add(await realpath(path));
    } catch {
      // Claude omits missing default write paths from its bubblewrap arguments.
    }
  }
  return [...paths];
}

function runnerBoundaryArguments({
  access,
  cwd,
  gitDirectories,
  hiddenDirectory,
}) {
  const filesystemArguments = [
    "--tmpfs",
    "/tmp",
    "--dir",
    "/tmp/claude",
    "--tmpfs",
    "/run",
  ];
  if (
    !containsPath("/tmp", hiddenDirectory) &&
    !containsPath("/run", hiddenDirectory) &&
    !containsPath("/dev", hiddenDirectory)
  ) {
    filesystemArguments.push("--tmpfs", hiddenDirectory);
  }
  filesystemArguments.push(
    access === "workspace-write" ? "--bind" : "--ro-bind",
    cwd,
    cwd,
  );
  const finalArguments = ["--as-pid-1", "--cap-drop", "ALL", "--proc", "/proc"];
  for (const gitDirectory of new Set(gitDirectories)) {
    finalArguments.push("--ro-bind", gitDirectory, gitDirectory);
  }
  return { filesystemArguments, finalArguments };
}

function launcherSource({
  access,
  bubblewrapBinary,
  canonicalCwd,
  canonicalGitDirectories,
  canonicalTemporaryRoot,
  claudeWritablePaths,
  cwd,
  filesystemArguments,
  finalArguments,
  gitDirectories,
  hiddenDirectory,
  token,
  unsetEnvironmentNames,
}) {
  return `#!${process.execPath}
const { spawnSync } = require("node:child_process");
const { lstatSync, readdirSync, realpathSync } = require("node:fs");
const {
  basename,
  dirname,
  isAbsolute,
  relative,
  resolve,
  sep,
} = require("node:path");

const tokenName = ${JSON.stringify(CLAUDE_COMMAND_LAUNCHER_TOKEN)};
if (process.env[tokenName] !== ${JSON.stringify(token)}) process.exit(125);
const access = ${JSON.stringify(access)};
const cwd = ${JSON.stringify(cwd)};
const canonicalCwd = ${JSON.stringify(canonicalCwd)};
const canonicalGitDirectories = ${JSON.stringify(canonicalGitDirectories)};
const canonicalTemporaryRoot = ${JSON.stringify(canonicalTemporaryRoot)};
const claudeWritablePaths = new Set(${JSON.stringify(claudeWritablePaths)});
const hiddenDirectory = ${JSON.stringify(hiddenDirectory)};
const gitDirectories = new Set(
  ${JSON.stringify([...new Set(gitDirectories)])},
);
const protectedEnvironmentNames = new Set(${JSON.stringify([
    CLAUDE_COMMAND_LAUNCHER_TOKEN,
    ...unsetEnvironmentNames,
  ])});
const sourceArguments = process.argv.slice(2);
const validatedArguments = [];
const presentUnsetEnvironmentNames = [];
const environmentOperations = new Set();
const privateWorkspaceMasks = new Map();
const readOnlyWorkspacePaths = new Set();
let index = 0;

function fail() {
  process.exit(125);
}
function take(expected) {
  if (sourceArguments[index] !== expected) fail();
  validatedArguments.push(sourceArguments[index]);
  index += 1;
}
function takeValue() {
  const value = sourceArguments[index];
  if (typeof value !== "string" || value.includes("\\0")) {
    fail();
  }
  index += 1;
  return value;
}
function validEnvironmentName(name) {
  return /^[A-Za-z_][A-Za-z0-9_]*$/.test(name);
}
function validPath(path) {
  return isAbsolute(path) && resolve(path) === path;
}
function containsPath(parent, child) {
  const path = relative(parent, child);
  return path === "" || (path !== ".." && !path.startsWith(".." + sep));
}
function canonicalPath(path) {
  let candidate = path;
  const missing = [];
  while (true) {
    try {
      const metadata = lstatSync(candidate);
      if (missing.length > 0 && !metadata.isDirectory()) fail();
      return resolve(realpathSync(candidate), ...missing);
    } catch (cause) {
      if (!["ENOENT", "ENOTDIR"].includes(cause?.code)) fail();
      const parent = dirname(candidate);
      if (parent === candidate) fail();
      missing.unshift(basename(candidate));
      candidate = parent;
    }
  }
}
function validClaudeEmptyMask(path) {
  try {
    const metadata = lstatSync(path);
    const canonical = realpathSync(path);
    return (
      metadata.isDirectory() &&
      !metadata.isSymbolicLink() &&
      (process.getuid === undefined || metadata.uid === process.getuid()) &&
      (metadata.mode & 0o077) === 0 &&
      basename(path).startsWith("claude-empty-") &&
      canonical !== canonicalTemporaryRoot &&
      containsPath(canonicalTemporaryRoot, canonical) &&
      readdirSync(path).length === 0
    );
  } catch {
    return false;
  }
}
function pathKind(path) {
  try {
    return lstatSync(path).isDirectory() ? "directory" : "file";
  } catch (cause) {
    if (["ENOENT", "ENOTDIR"].includes(cause?.code)) return "missing";
    fail();
  }
}

take("--new-session");
take("--die-with-parent");
while (["--unsetenv", "--setenv"].includes(sourceArguments[index])) {
  const operation = sourceArguments[index];
  validatedArguments.push(operation);
  index += 1;
  const name = takeValue();
  if (!validEnvironmentName(name) || environmentOperations.has(name)) fail();
  environmentOperations.add(name);
  validatedArguments.push(name);
  if (operation === "--unsetenv") {
    presentUnsetEnvironmentNames.push(name);
  } else {
    if (protectedEnvironmentNames.has(name)) fail();
    validatedArguments.push(takeValue());
  }
}
take("--unshare-net");
take("--ro-bind");
take("/");
take("/");
validatedArguments.push(...${JSON.stringify(filesystemArguments)});
while (["--bind", "--ro-bind", "--tmpfs"].includes(sourceArguments[index])) {
  const operation = sourceArguments[index];
  index += 1;
  if (operation === "--tmpfs") {
    const path = takeValue();
    if (!["/tmp", "/run"].includes(path)) fail();
    continue;
  }
  const source = takeValue();
  const destination = takeValue();
  if (!validPath(source) || !validPath(destination)) fail();
  const runnerWorkspaceMount =
    operation ===
      (access === "workspace-write" ? "--bind" : "--ro-bind") &&
    source === cwd &&
    destination === cwd;
  const runnerGitMount =
    operation === "--ro-bind" &&
    source === destination &&
    gitDirectories.has(destination);
  const discardedClaudeWriteMount =
    operation === "--bind" &&
    source === destination &&
    claudeWritablePaths.has(destination);
  if (
    !runnerWorkspaceMount &&
    !runnerGitMount &&
    !discardedClaudeWriteMount
  ) {
    if (source === destination && pathKind(source) === "missing") fail();
    const canonicalDestination = canonicalPath(destination);
    if (operation === "--bind") {
      if (access !== "workspace-write" || source !== destination) fail();
      if (
        !containsPath(canonicalCwd, canonicalDestination) ||
        canonicalGitDirectories.some((path) =>
          containsPath(path, canonicalDestination),
        ) ||
        [...readOnlyWorkspacePaths].some(
          (path) =>
            containsPath(path, canonicalDestination) ||
            containsPath(canonicalDestination, path),
        )
      ) fail();
    } else {
      const withinWorkspace = containsPath(
        canonicalCwd,
        canonicalDestination,
      );
      const withinGit = canonicalGitDirectories.some((path) =>
        containsPath(path, canonicalDestination),
      );
      const emptyMask =
        source !== destination && validClaudeEmptyMask(source);
      const safeMask =
        source !== destination &&
        (source === "/dev/null" || emptyMask);
      const maskKind = emptyMask
        ? "directory"
        : source === "/dev/null"
          ? "file"
          : undefined;
      const maskIdentity =
        maskKind === undefined
          ? undefined
          : JSON.stringify([maskKind, destination]);
      if (withinGit) {
        if (source !== destination && !safeMask) fail();
        continue;
      }
      if (withinWorkspace) {
        const overlapsPrivateMask = [...privateWorkspaceMasks.keys()].some(
          (path) =>
            containsPath(path, canonicalDestination) ||
            containsPath(canonicalDestination, path),
        );
        const existingMaskIdentity = privateWorkspaceMasks.get(
          canonicalDestination,
        );
        if (
          access !== "workspace-write" ||
          canonicalDestination === canonicalCwd ||
          (source !== destination && !safeMask) ||
          (emptyMask && pathKind(destination) === "file") ||
          (source === "/dev/null" &&
            pathKind(destination) === "directory") ||
          (overlapsPrivateMask &&
            !(safeMask && existingMaskIdentity === maskIdentity))
        ) fail();
        readOnlyWorkspacePaths.add(canonicalDestination);
        if (emptyMask) {
          if (existingMaskIdentity === undefined) {
            privateWorkspaceMasks.set(canonicalDestination, maskIdentity);
            validatedArguments.push(
              "--tmpfs",
              destination,
              "--remount-ro",
              destination,
            );
          }
          continue;
        }
        if (source === "/dev/null") {
          if (existingMaskIdentity !== undefined) continue;
          privateWorkspaceMasks.set(canonicalDestination, maskIdentity);
        }
      } else if (source !== destination) {
        fail();
      }
      if (
        access === "workspace-write" &&
        containsPath(canonicalDestination, canonicalCwd)
      ) fail();
      if (
        !withinWorkspace &&
        ["/dev", "/proc", "/run", "/tmp", hiddenDirectory].some(
          (path) =>
            containsPath(path, destination) ||
            containsPath(path, canonicalDestination) ||
            containsPath(destination, path) ||
            containsPath(canonicalDestination, path),
        )
      ) fail();
    }
    validatedArguments.push(operation, source, destination);
  }
}
take("--dev");
take("/dev");
take("--unshare-pid");
take("--unshare-user");
if (
  sourceArguments[index] !== "--bind" ||
  sourceArguments[index + 1] !== "/proc" ||
  sourceArguments[index + 2] !== "/proc"
) fail();
index += 3;
if (sourceArguments[index] !== "--") fail();
index += 1;
const shell = takeValue();
const shellOption = takeValue();
const payload = takeValue();
if (
  !validPath(shell) ||
  shellOption !== "-c" ||
  index !== sourceArguments.length
) {
  fail();
}

const environment = { ...process.env };
for (const name of protectedEnvironmentNames) delete environment[name];
const missingUnsetArguments = [...protectedEnvironmentNames]
  .filter((name) => !presentUnsetEnvironmentNames.includes(name))
  .flatMap((name) => ["--unsetenv", name]);
const result = spawnSync(
  ${JSON.stringify(bubblewrapBinary)},
  [
    ...validatedArguments,
    ...${JSON.stringify(finalArguments)},
    ...missingUnsetArguments,
    "--chdir",
    cwd,
    "--",
    shell,
    shellOption,
    payload,
  ],
  { env: environment, stdio: "inherit" },
);
if (result.error !== undefined || result.signal !== null) process.exit(125);
process.exit(result.status ?? 125);
`;
}

export async function createClaudeCommandLauncher({
  access,
  bubblewrapBinary,
  cwd,
  environment,
  gitDirectories,
  unsetEnvironmentNames,
}) {
  let launcherDirectory;
  try {
    const temporaryRoot = await realpath(tmpdir());
    const canonicalCwd = await realpath(cwd);
    const canonicalGitDirectories = await Promise.all(
      [...new Set(gitDirectories)].map((path) => realpath(path)),
    );
    const claudeWritablePaths =
      await claudeIncidentalWritablePaths(environment);
    const protectedRoots = [canonicalCwd, ...canonicalGitDirectories];
    if (protectedRoots.some((path) => containsPath(path, temporaryRoot))) {
      throw new Error("Claude command launcher temporary root is unsafe.");
    }
    const resolvedBubblewrapBinary = await resolveExecutable(
      bubblewrapBinary,
      environment,
    );
    if (
      protectedRoots.some((path) =>
        containsPath(path, resolvedBubblewrapBinary),
      )
    ) {
      throw new Error("Claude command isolation executable is unsafe.");
    }
    launcherDirectory = await mkdtemp(
      join(temporaryRoot, "agent-runner-claude-command-"),
    );
    const path = join(launcherDirectory, "bwrap");
    const packagePath = join(launcherDirectory, "package.json");
    const token = randomUUID();
    const { filesystemArguments, finalArguments } = runnerBoundaryArguments({
      access,
      cwd,
      gitDirectories,
      hiddenDirectory: launcherDirectory,
    });
    await Promise.all([
      writeFile(
        path,
        launcherSource({
          access,
          bubblewrapBinary: resolvedBubblewrapBinary,
          canonicalCwd,
          canonicalGitDirectories,
          canonicalTemporaryRoot: temporaryRoot,
          claudeWritablePaths,
          cwd,
          filesystemArguments,
          finalArguments,
          gitDirectories,
          hiddenDirectory: launcherDirectory,
          token,
          unsetEnvironmentNames,
        }),
        { mode: 0o500 },
      ),
      writeFile(packagePath, '{"type":"commonjs"}\n', { mode: 0o400 }),
    ]);
    await Promise.all([chmod(path, 0o500), chmod(packagePath, 0o400)]);
    await chmod(launcherDirectory, 0o500);
    return Object.freeze({
      environment(environment) {
        return Object.freeze({
          ...environment,
          [CLAUDE_COMMAND_LAUNCHER_TOKEN]: token,
        });
      },
      path,
      async remove() {
        await chmod(launcherDirectory, 0o700);
        await rm(launcherDirectory, { force: true, recursive: true });
      },
    });
  } catch (cause) {
    if (launcherDirectory !== undefined) {
      try {
        await chmod(launcherDirectory, 0o700);
        await rm(launcherDirectory, { force: true, recursive: true });
      } catch {
        // Preserve the construction failure; preflight still fails closed.
      }
    }
    throw cause;
  }
}
