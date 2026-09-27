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
import { tmpdir } from "node:os";
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

function runnerBoundaryArguments({
  access,
  cwd,
  gitDirectories,
  hiddenDirectory,
  unsetEnvironmentNames,
}) {
  const argumentsList = [
    "--new-session",
    "--die-with-parent",
    "--unshare-user",
    "--unshare-pid",
    "--unshare-net",
    "--as-pid-1",
    "--ro-bind",
    "/",
    "/",
    "--dev",
    "/dev",
    "--proc",
    "/proc",
    "--tmpfs",
    "/tmp",
    "--tmpfs",
    "/run",
  ];
  if (
    !containsPath("/tmp", hiddenDirectory) &&
    !containsPath("/run", hiddenDirectory) &&
    !containsPath("/dev", hiddenDirectory)
  ) {
    argumentsList.push("--tmpfs", hiddenDirectory);
  }
  argumentsList.push(
    access === "workspace-write" ? "--bind" : "--ro-bind",
    cwd,
    cwd,
  );
  for (const gitDirectory of new Set(gitDirectories)) {
    argumentsList.push("--ro-bind", gitDirectory, gitDirectory);
  }
  for (const name of new Set([
    CLAUDE_COMMAND_LAUNCHER_TOKEN,
    ...unsetEnvironmentNames,
  ])) {
    argumentsList.push("--unsetenv", name);
  }
  argumentsList.push("--chdir", cwd);
  return argumentsList;
}

function launcherSource({ argumentsList, bubblewrapBinary, token }) {
  return `#!${process.execPath}
const { spawnSync } = require("node:child_process");

const tokenName = ${JSON.stringify(CLAUDE_COMMAND_LAUNCHER_TOKEN)};
if (process.env[tokenName] !== ${JSON.stringify(token)}) process.exit(125);
const environment = { ...process.env };
delete environment[tokenName];
const result = spawnSync(
  ${JSON.stringify(bubblewrapBinary)},
  [
    ...${JSON.stringify(argumentsList)},
    "--",
    ${JSON.stringify(bubblewrapBinary)},
    ...process.argv.slice(2),
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
    const protectedRoots = await Promise.all(
      [...new Set([cwd, ...gitDirectories])].map((path) => realpath(path)),
    );
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
    const argumentsList = runnerBoundaryArguments({
      access,
      cwd,
      gitDirectories,
      hiddenDirectory: launcherDirectory,
      unsetEnvironmentNames,
    });
    await Promise.all([
      writeFile(
        path,
        launcherSource({
          argumentsList,
          bubblewrapBinary: resolvedBubblewrapBinary,
          token,
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
