import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";

const MAX_COMMIT_OUTPUT_BYTES = 64 * 1024 * 1024;
const PROFILE = "agent_runner_local_commit";
const PROBE_OUTPUT = "agent-runner-local-commit-ok";
const PROBE_SCRIPT =
  'import { writeFileSync, writeSync } from "node:fs"; ' +
  'import { createConnection } from "node:net"; ' +
  'import { join } from "node:path"; ' +
  'try { writeFileSync(join(process.argv[1], "probe"), ""); process.exit(6); } ' +
  'catch ({ code }) { ' +
  'if (!["EACCES", "EPERM", "EROFS"].includes(code)) process.exit(3); } ' +
  'writeFileSync(".git/probe", ""); ' +
  'const socket = createConnection({ host: "1.1.1.1", port: 53 }); ' +
  'socket.once("error", ({ code }) => { ' +
  'if (!["EACCES", "EPERM"].includes(code)) process.exit(2); ' +
  `writeSync(1, ${JSON.stringify(PROBE_OUTPUT)}); process.exit(0); }); ` +
  'socket.once("connect", () => process.exit(4)); ' +
  'setTimeout(() => process.exit(5), 1_000);';
const COMMIT_SCRIPT = `
import { spawnSync } from "node:child_process";

const [expectedHead, message] = process.argv.slice(1);

function runGit(argumentsList, capture = false) {
  const result = spawnSync(
    "git",
    ["-c", "core.fsmonitor=false", ...argumentsList],
    capture ? { encoding: "utf8" } : { stdio: "inherit" },
  );
  // The Codex sandbox can attach EPERM after a child has exited successfully.
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
  return result.stdout;
}

function assertExpectedHead() {
  if (runGit(["rev-parse", "HEAD"], true).trim() !== expectedHead) {
    process.exit(64);
  }
}

assertExpectedHead();
runGit(["add", "-A"]);
assertExpectedHead();
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

function profile(gitDirectories) {
  const gitPermissions = [...new Set(gitDirectories)]
    .map((gitDirectory) => `${JSON.stringify(gitDirectory)}="write"`)
    .join(",");
  return (
    `permissions.${PROFILE}={` +
    'description="Agent Runner authorized local commit",' +
    'filesystem={":root"="read",":workspace_roots"={"."="write"},' +
    `${gitPermissions}},network={enabled=false}}`
  );
}

function sandboxArguments(cwd, gitDirectories, command) {
  return [
    "sandbox",
    "-C",
    cwd,
    "-P",
    PROFILE,
    "-c",
    `default_permissions=${JSON.stringify(PROFILE)}`,
    "-c",
    profile(gitDirectories),
    "--",
    ...command,
  ];
}

export async function probeCodexLocalCommit({ codexBinary, env, execute }) {
  let fixturePath;
  let outsidePath;
  let available = false;
  try {
    fixturePath = await mkdtemp(join(tmpdir(), "agent-runner-codex-"));
    outsidePath = await mkdtemp(join(tmpdir(), "agent-runner-codex-outside-"));
    const gitDirectory = join(fixturePath, ".git");
    await mkdir(gitDirectory);
    const result = await execute(
      codexBinary,
      sandboxArguments(fixturePath, [gitDirectory], [
        process.execPath,
        "--input-type=module",
        "-e",
        PROBE_SCRIPT,
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
  for (const path of [fixturePath, outsidePath]) {
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

export async function executeCodexLocalCommit({
  codexBinary,
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
  await execute(
    codexBinary,
    sandboxArguments(cwd, gitDirectories, [
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
