import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, realpath } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";

const MAX_GIT_OUTPUT_BYTES = 64 * 1024 * 1024;
const REPOSITORY_ENV_OVERRIDES = Object.freeze([
  "GIT_ALTERNATE_OBJECT_DIRECTORIES",
  "GIT_COMMON_DIR",
  "GIT_CEILING_DIRECTORIES",
  "GIT_DIR",
  "GIT_INDEX_FILE",
  "GIT_NAMESPACE",
  "GIT_OBJECT_DIRECTORY",
  "GIT_SHALLOW_FILE",
  "GIT_WORK_TREE",
]);

export class GitSafetyError extends Error {
  constructor(
    message,
    { cause, changes = [], code = "ERR_GIT_SAFETY" } = {},
  ) {
    super(message, { cause });
    this.name = "GitSafetyError";
    this.code = code;
    this.changes = Object.freeze([...changes]);
  }
}

export function isEnvironment(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function isWithin(parentPath, childPath) {
  const pathFromParent = relative(parentPath, childPath);
  return (
    pathFromParent === "" ||
    (!pathFromParent.startsWith(`..${sep}`) &&
      pathFromParent !== ".." &&
      !isAbsolute(pathFromParent))
  );
}

export function hashBuffer(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function decodeUtf8(value, name) {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(value);
  } catch (cause) {
    throw new GitSafetyError(`${name} contains invalid UTF-8.`, {
      cause,
      code: "ERR_UNSUPPORTED_GIT_PATH",
    });
  }
}

export function decodeLine(value, name) {
  const line = decodeUtf8(value, name).replace(/\r?\n$/u, "");
  if (line.length === 0 || /[\0\r\n]/u.test(line)) {
    throw new GitSafetyError(`${name} is invalid.`, {
      code: "ERR_UNSUPPORTED_GIT_PATH",
    });
  }
  return line;
}

export function decodeNullList(value, name) {
  const source = decodeUtf8(value, name);
  if (source.length === 0) {
    return [];
  }
  const entries = source.split("\0");
  if (entries.at(-1) === "") {
    entries.pop();
  }
  if (entries.some((entry) => entry.length === 0)) {
    throw new GitSafetyError(`${name} contains an invalid empty path.`, {
      code: "ERR_UNSUPPORTED_GIT_PATH",
    });
  }
  return entries;
}

export function createGitCommandRunner({ env, gitBinary }) {
  const gitEnvironment = {
    ...env,
    GIT_OPTIONAL_LOCKS: "0",
    GIT_TERMINAL_PROMPT: "0",
    LC_ALL: "C",
  };
  for (const name of REPOSITORY_ENV_OVERRIDES) {
    delete gitEnvironment[name];
  }

  return async function runGit(
    workingDirectory,
    argumentsList,
    { allowedExitCodes = [0], extraEnv = {} } = {},
  ) {
    return new Promise((resolvePromise, rejectPromise) => {
      const stdout = [];
      const stderr = [];
      let outputBytes = 0;
      let settled = false;
      const child = spawn(
        gitBinary,
        ["-c", "core.fsmonitor=false", "-C", workingDirectory, ...argumentsList],
        {
          env: { ...gitEnvironment, ...extraEnv },
          stdio: ["ignore", "pipe", "pipe"],
        },
      );

      function fail(error) {
        if (!settled) {
          settled = true;
          rejectPromise(error);
        }
      }

      function collect(chunks) {
        return (chunk) => {
          outputBytes += chunk.length;
          if (outputBytes > MAX_GIT_OUTPUT_BYTES) {
            child.kill();
            fail(
              new GitSafetyError("Git command output exceeds the safe limit.", {
                code: "ERR_GIT_OUTPUT_TOO_LARGE",
              }),
            );
            return;
          }
          chunks.push(chunk);
        };
      }

      child.stdout.on("data", collect(stdout));
      child.stderr.on("data", collect(stderr));
      child.once("error", (cause) =>
        fail(
          new GitSafetyError("Cannot execute Git.", {
            cause,
            code: "ERR_GIT_UNAVAILABLE",
          }),
        ),
      );
      child.once("close", (exitCode) => {
        if (settled) {
          return;
        }
        if (!allowedExitCodes.includes(exitCode)) {
          fail(
            new GitSafetyError("Git command failed.", {
              code: "ERR_GIT_COMMAND_FAILED",
            }),
          );
          return;
        }
        settled = true;
        resolvePromise({
          exitCode,
          stderr: Buffer.concat(stderr),
          stdout: Buffer.concat(stdout),
        });
      });
    });
  };
}

export async function resolveRepository(runGit, projectPath) {
  if (
    typeof projectPath !== "string" ||
    projectPath.trim().length === 0 ||
    /[\0\r\n]/u.test(projectPath)
  ) {
    throw new GitSafetyError("Project path must be a non-empty path.", {
      code: "ERR_INVALID_GIT_OPTIONS",
    });
  }
  try {
    const requestedPath = await realpath(resolve(projectPath));
    if (!(await lstat(requestedPath)).isDirectory()) {
      throw new GitSafetyError("Project path must be a directory.", {
        code: "ERR_NOT_GIT_REPOSITORY",
      });
    }
    const result = await runGit(requestedPath, [
      "rev-parse",
      "--show-toplevel",
    ]);
    const repositoryPath = await realpath(
      decodeLine(result.stdout, "Git repository path"),
    );
    if (
      !(await lstat(repositoryPath)).isDirectory() ||
      !isWithin(repositoryPath, requestedPath)
    ) {
      throw new GitSafetyError("Git repository root must be a directory.", {
        code: "ERR_NOT_GIT_REPOSITORY",
      });
    }
    return repositoryPath;
  } catch (cause) {
    if (
      cause instanceof GitSafetyError &&
      cause.code !== "ERR_GIT_COMMAND_FAILED"
    ) {
      throw cause;
    }
    throw new GitSafetyError("Project path is not a Git working tree.", {
      cause,
      code: "ERR_NOT_GIT_REPOSITORY",
    });
  }
}
