import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import {
  access,
  chmod,
  mkdtemp,
  mkdir,
  lstat,
  realpath,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { delimiter, isAbsolute, join, relative, resolve, sep } from "node:path";

import {
  createToolHome,
  nativeLauncherSource,
  projectionSource,
  toolHomeArguments,
} from "./projection.js";

import { createClaudeSeccompFilter } from "./seccomp-filter.js";

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
    const path = await realpath(binary);
    if (!(await stat(path)).isFile()) {
      throw new Error("Claude command isolation executable is unavailable.");
    }
    return path;
  }
  for (const directory of (environment.PATH ?? "")
    .split(delimiter)
    .filter(isAbsolute)) {
    const candidate = join(directory, binary);
    try {
      await access(candidate, constants.X_OK);
      const path = await realpath(candidate);
      if ((await stat(path)).isFile()) return path;
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
  privateTemporaryRoot,
  claudeWritablePaths,
  cwd,
  filter,
  filesystemArguments,
  finalArguments,
  gitDirectories,
  hiddenDirectory,
  token,
  home,
  unsetEnvironmentNames,
}) {
  return `#!${process.execPath}
const { spawnSync } = require("node:child_process");
const { createHash, timingSafeEqual } = require("node:crypto");
const {
  chmodSync,
  closeSync,
  constants,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdtempSync,
  openSync,
  readSync,
  readdirSync,
  realpathSync,
  rmdirSync,
  rmSync,
  unlinkSync,
  writeSync,
} = require("node:fs");
const {
  basename,
  dirname,
  isAbsolute,
  join,
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
const expectedFilter = Buffer.from(${JSON.stringify(filter.base64)}, "base64");
const expectedFilterByteLength = ${JSON.stringify(filter.byteLength)};
const expectedFilterSha256 = ${JSON.stringify(filter.sha256)};
const hiddenDirectory = ${JSON.stringify(hiddenDirectory)};
const gitDirectories = new Set(
  ${JSON.stringify([...new Set(gitDirectories)])},
);
const protectedEnvironmentNames = new Set(${JSON.stringify([
    "ARGV0",
    CLAUDE_COMMAND_LAUNCHER_TOKEN,
    ...unsetEnvironmentNames,
  ])});
${projectionSource({ access, cwd, home, injectHome: false })}
let sourceArguments;
try { sourceArguments = projectArguments(process.argv.slice(2)); } catch { process.exit(125); }
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
function closeDescriptor(descriptor) {
  if (descriptor === undefined) return true;
  try {
    closeSync(descriptor);
    return true;
  } catch {
    return false;
  }
}
function createSeccompDescriptor() {
  let directory;
  let path;
  let readDescriptor;
  let writeDescriptor;
  try {
    if (
      expectedFilter.length !== expectedFilterByteLength ||
      createHash("sha256").update(expectedFilter).digest("hex") !==
        expectedFilterSha256 ||
      !Number.isInteger(constants.O_NOFOLLOW)
    ) throw new Error("invalid filter");
    directory = mkdtempSync(
      join(${JSON.stringify(privateTemporaryRoot)}, "agent-runner-claude-seccomp-"),
    );
    path = join(directory, "filter.bpf");
    writeDescriptor = openSync(
      path,
      constants.O_CREAT |
        constants.O_EXCL |
        constants.O_NOFOLLOW |
        constants.O_WRONLY,
      0o600,
    );
    let offset = 0;
    while (offset < expectedFilter.length) {
      const written = writeSync(
        writeDescriptor,
        expectedFilter,
        offset,
        expectedFilter.length - offset,
        offset,
      );
      if (written <= 0) throw new Error("incomplete filter");
      offset += written;
    }
    fsyncSync(writeDescriptor);
    if (!closeDescriptor(writeDescriptor)) throw new Error("close failed");
    writeDescriptor = undefined;
    chmodSync(path, 0o400);
    readDescriptor = openSync(
      path,
      constants.O_NOFOLLOW | constants.O_RDONLY,
    );
    const metadata = fstatSync(readDescriptor);
    if (
      !metadata.isFile() ||
      metadata.nlink !== 1 ||
      metadata.size !== expectedFilter.length ||
      (metadata.mode & 0o777) !== 0o400 ||
      (process.getuid !== undefined && metadata.uid !== process.getuid())
    ) throw new Error("invalid filter descriptor");
    unlinkSync(path);
    path = undefined;
    const sealed = fstatSync(readDescriptor);
    if (
      sealed.dev !== metadata.dev ||
      sealed.ino !== metadata.ino ||
      sealed.nlink !== 0 ||
      sealed.size !== metadata.size ||
      (sealed.mode & 0o777) !== 0o400
    ) throw new Error("unsealed filter descriptor");
    rmdirSync(directory);
    directory = undefined;
    const actualFilter = Buffer.alloc(expectedFilter.length);
    offset = 0;
    while (offset < actualFilter.length) {
      const count = readSync(
        readDescriptor,
        actualFilter,
        offset,
        actualFilter.length - offset,
        offset,
      );
      if (count <= 0) throw new Error("incomplete filter");
      offset += count;
    }
    if (!timingSafeEqual(actualFilter, expectedFilter)) {
      throw new Error("unexpected filter");
    }
    return readDescriptor;
  } catch {
    closeDescriptor(writeDescriptor);
    closeDescriptor(readDescriptor);
    if (path !== undefined) {
      try {
        unlinkSync(path);
      } catch {
        // The authenticated launcher still fails closed below.
      }
    }
    if (directory !== undefined) {
      try {
        rmSync(directory, { force: true, recursive: true });
      } catch {
        // Process exit closes descriptors when cleanup cannot complete.
      }
    }
    return undefined;
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
    const value = takeValue();
    if (protectedEnvironmentNames.has(name)) fail();
    validatedArguments.push(value);
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
const filterDescriptor = createSeccompDescriptor();
if (filterDescriptor === undefined) fail();
let result;
try {
  result = spawnSync(
    ${JSON.stringify(bubblewrapBinary)},
    [
      ...validatedArguments,
      ...${JSON.stringify(finalArguments)},
      ...${JSON.stringify(toolHomeArguments(home))},
      "--seccomp",
      "3",
      ...missingUnsetArguments,
      "--chdir",
      cwd,
      "--",
      shell,
      shellOption,
      payload,
    ],
    {
      env: environment,
      stdio: ["inherit", "inherit", "inherit", filterDescriptor],
    },
  );
} catch {
  result = undefined;
}
if (!closeDescriptor(filterDescriptor)) process.exit(125);
if (
  result === undefined ||
  result.error !== undefined ||
  result.signal !== null
) process.exit(125);
process.exit(result.status ?? 125);
`;
}

export async function createClaudeCommandLauncher({
  access,
  directory,
  isolationPolicy = "runner-boundary",
  architecture = process.arch,
  bubblewrapBinary,
  cwd,
  environment,
  gitDirectories,
  unsetEnvironmentNames,
}) {
  let launcherDirectory;
  let launcherIdentity;
  async function remove() {
    const current = await lstat(launcherDirectory);
    if (
      !launcherIdentity ||
      current.dev !== launcherIdentity.dev ||
      current.ino !== launcherIdentity.ino ||
      !current.isDirectory() ||
      (await realpath(launcherDirectory)) !== launcherDirectory
    ) {
      throw new Error("Claude launcher identity changed.");
    }
    await chmod(launcherDirectory, 0o700);
    await rm(launcherDirectory, { force: true, recursive: true });
  }
  try {
    const filter =
      isolationPolicy === "runner-boundary"
        ? createClaudeSeccompFilter(architecture)
        : undefined;
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
    launcherDirectory =
      directory === undefined
        ? await mkdtemp(join(temporaryRoot, "agent-runner-claude-command-"))
        : join(directory, "launcher");
    if (directory !== undefined)
      await mkdir(launcherDirectory, { mode: 0o700 });
    launcherIdentity = await lstat(launcherDirectory);
    const home = await createToolHome(launcherDirectory);
    const path = join(launcherDirectory, "bwrap");
    const packagePath = join(launcherDirectory, "package.json");
    const token = randomUUID();
    const { filesystemArguments, finalArguments } = runnerBoundaryArguments({
      access,
      cwd,
      gitDirectories,
      hiddenDirectory: directory ?? launcherDirectory,
    });
    await Promise.all([
      writeFile(
        path,
        isolationPolicy === "native"
          ? nativeLauncherSource({
              bubblewrapBinary: resolvedBubblewrapBinary,
              cwd,
              home,
              tokenName: CLAUDE_COMMAND_LAUNCHER_TOKEN,
              token,
              unsetEnvironmentNames,
              access,
            })
          : launcherSource({
              access,
              bubblewrapBinary: resolvedBubblewrapBinary,
              canonicalCwd,
              canonicalGitDirectories,
              canonicalTemporaryRoot: temporaryRoot,
              privateTemporaryRoot: directory ?? temporaryRoot,
              claudeWritablePaths,
              cwd,
              filter,
              filesystemArguments,
              finalArguments,
              gitDirectories,
              hiddenDirectory: directory ?? launcherDirectory,
              token,
              home,
              unsetEnvironmentNames,
            }),
        { mode: 0o500 },
      ),
      writeFile(packagePath, '{"type":"commonjs"}\n', { mode: 0o400 }),
    ]);
    await Promise.all([chmod(path, 0o500), chmod(packagePath, 0o400)]);
    if (directory === undefined) await chmod(launcherDirectory, 0o500);
    return Object.freeze({
      environment(environment) {
        return Object.freeze({
          ...environment,
          [CLAUDE_COMMAND_LAUNCHER_TOKEN]: token,
        });
      },
      path,
      remove,
    });
  } catch (cause) {
    if (directory === undefined && launcherDirectory !== undefined) {
      try {
        await remove();
      } catch {
        // Preserve the construction failure; preflight still fails closed.
      }
    }
    throw cause;
  }
}
