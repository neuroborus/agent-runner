import { mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";

const MAX_COMMIT_OUTPUT_BYTES = 64 * 1024 * 1024;
const PROBE_OUTPUT = "agent-runner-claude-commit-ok";
const PROBE_SCRIPT = `
import { writeFileSync, writeSync } from "node:fs";
import { createConnection } from "node:net";
import { join } from "node:path";

const [gitDirectory, outsideDirectory] = process.argv.slice(1);
writeFileSync("workspace-probe", "");
writeFileSync(join(gitDirectory, "git-probe"), "");
try {
  writeFileSync(join(outsideDirectory, "outside-probe"), "");
  process.exit(4);
} catch ({ code }) {
  if (!["EACCES", "ENOENT", "EPERM", "EROFS"].includes(code)) process.exit(3);
}
const socket = createConnection({ host: "1.1.1.1", port: 53 });
socket.once("error", ({ code }) => {
  if (!["EACCES", "ENETUNREACH", "EPERM"].includes(code)) process.exit(2);
  writeSync(1, ${JSON.stringify(PROBE_OUTPUT)});
  process.exit(0);
});
socket.once("connect", () => process.exit(5));
setTimeout(() => process.exit(6), 1_000);
`.trim();
const COMMIT_SCRIPT = `
import { spawnSync } from "node:child_process";

const [expectedHead, message] = process.argv.slice(1);

function runGit(argumentsList, capture = false) {
  const result = spawnSync(
    "git",
    ["-c", "core.fsmonitor=false", ...argumentsList],
    capture ? { encoding: "utf8" } : { stdio: "inherit" },
  );
  if (result.status !== 0) process.exit(result.status ?? 1);
  return result.stdout;
}

function assertExpectedHead() {
  if (runGit(["rev-parse", "HEAD"], true).trim() !== expectedHead) {
    process.exit(64);
  }
}

function assertStagedDiff() {
  runGit(["diff", "--quiet"]);
  runGit(["diff", "--cached", "--check"]);
  const result = spawnSync(
    "git",
    ["-c", "core.fsmonitor=false", "diff", "--cached", "--quiet"],
    { stdio: "inherit" },
  );
  if (result.status !== 1) {
    process.exit(result.status === 0 ? 65 : (result.status ?? 1));
  }
}

assertExpectedHead();
runGit(["add", "-A"]);
assertExpectedHead();
assertStagedDiff();
runGit(["commit", "--message", message]);
`.trim();

function processOutput(value) {
  if (typeof value === "string") {
    return value;
  }
  if (Buffer.isBuffer(value)) {
    return value.toString("utf8");
  }
  return "";
}

function sandboxArguments(cwd, writableDirectories, command) {
  const argumentsList = [
    "--die-with-parent",
    "--new-session",
    "--unshare-net",
    "--ro-bind",
    "/",
    "/",
    "--proc",
    "/proc",
    "--dev",
    "/dev",
    "--tmpfs",
    "/tmp",
    "--tmpfs",
    "/run",
  ];
  for (const directory of new Set([cwd, ...writableDirectories])) {
    argumentsList.push("--bind", directory, directory);
  }
  argumentsList.push("--chdir", cwd, "--", ...command);
  return argumentsList;
}

export async function probeClaudeLocalCommit({
  bubblewrapBinary,
  env,
  execute,
}) {
  let fixturePath;
  let gitDirectory;
  let outsidePath;
  let available = false;
  try {
    fixturePath = await mkdtemp(join(tmpdir(), "agent-runner-claude-"));
    gitDirectory = await mkdtemp(join(tmpdir(), "agent-runner-claude-git-"));
    outsidePath = await mkdtemp(
      join(tmpdir(), "agent-runner-claude-outside-"),
    );
    const result = await execute(
      bubblewrapBinary,
      sandboxArguments(fixturePath, [gitDirectory], [
        process.execPath,
        "--input-type=module",
        "-e",
        PROBE_SCRIPT,
        gitDirectory,
        outsidePath,
      ]),
      {
        encoding: "utf8",
        env,
        maxBuffer: 1024 * 1024,
        timeout: 10_000,
      },
    );
    available = processOutput(result.stdout) === PROBE_OUTPUT;
  } catch {}
  let cleaned = true;
  for (const path of [fixturePath, gitDirectory, outsidePath]) {
    if (path === undefined) {
      continue;
    }
    try {
      await rm(path, { force: true, recursive: true });
    } catch {
      cleaned = false;
    }
  }
  return available && cleaned;
}

export async function executeClaudeLocalCommit({
  bubblewrapBinary,
  cwd,
  env,
  execute,
  expectedHead,
  message,
}) {
  const gitResult = await execute(
    "git",
    [
      "-C",
      cwd,
      "rev-parse",
      "--absolute-git-dir",
      "--git-common-dir",
    ],
    {
      encoding: "utf8",
      env,
      maxBuffer: 1024 * 1024,
      timeout: 10_000,
    },
  );
  const gitDirectories = processOutput(gitResult.stdout)
    .trim()
    .split(/\r?\n/u)
    .map((gitDirectory) =>
      isAbsolute(gitDirectory) ? gitDirectory : resolve(cwd, gitDirectory),
    );
  if (
    gitDirectories.length !== 2 ||
    gitDirectories.some(
      (gitDirectory) =>
        !isAbsolute(gitDirectory) ||
        gitDirectory.length === 0 ||
        /[\0\r\n]/u.test(gitDirectory),
    )
  ) {
    throw new Error("Git returned an invalid directory.");
  }
  const canonicalGitDirectories = await Promise.all(
    gitDirectories.map((gitDirectory) => realpath(gitDirectory)),
  );
  await execute(
    bubblewrapBinary,
    sandboxArguments(cwd, canonicalGitDirectories, [
      process.execPath,
      "--input-type=module",
      "-e",
      COMMIT_SCRIPT,
      expectedHead,
      message,
    ]),
    {
      encoding: "utf8",
      env,
      maxBuffer: MAX_COMMIT_OUTPUT_BYTES,
    },
  );
}
