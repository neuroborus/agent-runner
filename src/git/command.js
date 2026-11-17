import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import {
  lstat,
  mkdtemp,
  open,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

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
  constructor(message, { cause, changes = [], code = "ERR_GIT_SAFETY" } = {}) {
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
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
      value,
    );
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
    { allowedExitCodes = [0], extraEnv = {}, signal } = {},
  ) {
    return executeGit(
      { env: { ...gitEnvironment, ...extraEnv }, gitBinary },
      workingDirectory,
      argumentsList,
      { allowedExitCodes, signal },
    );
  };
}

async function executeGit(
  { env, gitBinary },
  workingDirectory,
  argumentsList,
  { allowedExitCodes = [0], signal, stdin } = {},
) {
  signal?.throwIfAborted();
  return new Promise((resolvePromise, rejectPromise) => {
    const stdout = [];
    const stderr = [];
    let outputBytes = 0;
    let settled = false;
    let pendingError;
    let inputFailed = false;
    const child = spawn(
      gitBinary,
      [
        "-c",
        "core.fsmonitor=false",
        "-c",
        "submodule.recurse=false",
        "-C",
        workingDirectory,
        ...argumentsList,
      ],
      {
        env,
        stdio: [stdin === undefined ? "ignore" : "pipe", "pipe", "pipe"],
      },
    );
    const abort = () => child.kill();
    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted) abort();

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
          pendingError ??= new GitSafetyError(
            "Git command output exceeds the safe limit.",
            {
              code: "ERR_GIT_OUTPUT_TOO_LARGE",
            },
          );
          return;
        }
        chunks.push(chunk);
      };
    }

    child.stdout.on("data", collect(stdout));
    child.stderr.on("data", collect(stderr));
    child.once("error", (cause) => {
      pendingError = new GitSafetyError("Cannot execute Git.", {
        cause,
        code: "ERR_GIT_UNAVAILABLE",
      });
    });
    if (stdin !== undefined) {
      child.stdin.on("error", () => {
        inputFailed = true;
      });
      child.stdin.end(stdin);
    }
    child.once("close", (exitCode) => {
      signal?.removeEventListener("abort", abort);
      if (settled) {
        return;
      }
      if (pendingError) {
        fail(pendingError);
        return;
      }
      if (signal?.aborted) {
        fail(signal.reason);
        return;
      }
      if (allowedExitCodes !== null && !allowedExitCodes.includes(exitCode)) {
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
        ...(stdin === undefined ? {} : { inputFailed }),
      });
    });
  });
}

export function createCheckinHasher({ env, gitBinary, runGit }) {
  const baseEnvironment = Object.fromEntries(
    Object.entries(env).filter(([key]) => !key.startsWith("GIT_")),
  );
  return async (repositoryPath, content, attributes, configuration) => {
    let directory;
    let directoryIdentity;
    let parentHandle;
    let allocation;
    async function binding(path) {
      const canonical = await realpath(path);
      const stat = await lstat(canonical, { bigint: true });
      if (!stat.isDirectory()) throw new Error("Not a directory");
      return { path: canonical, dev: stat.dev, ino: stat.ino };
    }
    async function verify(path, expected) {
      const current = await binding(path);
      if (
        current.path !== expected.path ||
        current.dev !== expected.dev ||
        current.ino !== expected.ino
      )
        throw new Error("Directory binding changed");
    }
    try {
      if (!["text", "text eol=lf", "text eol=crlf"].includes(attributes))
        return null;
      const controlOptions = ["--absolute-git-dir", "--git-common-dir"];
      async function controlPath(option) {
        const result = await runGit(repositoryPath, [
          "rev-parse",
          "--path-format=absolute",
          option,
        ]);
        const path = decodeLine(result.stdout, "Git control directory");
        if (!isAbsolute(path)) throw new Error("Relative control directory");
        return path;
      }
      const protectedRoots = [await binding(repositoryPath)];
      for (const option of controlOptions)
        protectedRoots.push(await binding(await controlPath(option)));
      const verifyRoots = async () => {
        await verify(repositoryPath, protectedRoots[0]);
        for (let index = 0; index < controlOptions.length; index++)
          await verify(
            await controlPath(controlOptions[index]),
            protectedRoots[index + 1],
          );
      };
      const parentPath = resolve(tmpdir());
      const parent = await binding(parentPath);
      const unsafe = (path) =>
        protectedRoots.some((root) => isWithin(root.path, path));
      const representable = (path) =>
        isAbsolute(path) && !/[:\0\r\n]/u.test(path);
      // Prove separation before allocation, including linked-worktree common controls.
      if (unsafe(parent.path) || !representable(parent.path))
        throw new Error("Unsafe scratch parent");
      parentHandle = await open(
        parent.path,
        constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
      );
      const opened = await parentHandle.stat({ bigint: true });
      if (opened.dev !== parent.dev || opened.ino !== parent.ino)
        throw new Error("Scratch parent changed");
      await verify(parentPath, parent);
      await verifyRoots();
      allocation = await mkdtemp(
        `/proc/self/fd/${parentHandle.fd}/agent-runner-checkin-`,
      );
      directory = await realpath(allocation);
      directoryIdentity = await binding(allocation);
      if (
        directoryIdentity.path !== directory ||
        dirname(directory) !== parent.path ||
        !representable(directory) ||
        unsafe(directory) ||
        protectedRoots.some((root) => isWithin(directory, root.path))
      )
        throw new Error("Unsafe scratch directory");
      const verifyBindings = async () => {
        await verify(parentPath, parent);
        await verify(directory, directoryIdentity);
        await verifyRoots();
      };
      await verifyBindings();
      const attributesPath = join(directory, "attributes");
      await writeFile(attributesPath, `candidate ${attributes}\n`, {
        flag: "wx",
        mode: 0o600,
      });
      const isolatedEnv = {
        ...baseEnvironment,
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_GLOBAL: "/dev/null",
        GIT_ATTR_NOSYSTEM: "1",
        HOME: directory,
        XDG_CONFIG_HOME: directory,
        GIT_CEILING_DIRECTORIES: parent.path,
        GIT_TERMINAL_PROMPT: "0",
        GIT_OPTIONAL_LOCKS: "0",
        LC_ALL: "C",
      };
      const overrides = ["-c", `core.attributesFile=${attributesPath}`];
      for (const [key, value] of configuration) {
        if (
          !["core.autocrlf", "core.eol", "core.safecrlf"].includes(key) ||
          !/^[A-Za-z0-9]+$/u.test(value)
        )
          return null;
        overrides.push("-c", `${key}=${value}`);
      }
      await verifyBindings();
      const result = await executeGit(
        { env: isolatedEnv, gitBinary },
        directory,
        [...overrides, "hash-object", "--stdin", "--path=candidate"],
        { stdin: content, allowedExitCodes: null },
      );
      await verifyBindings();
      return result.exitCode === 0 &&
        !result.inputFailed &&
        /^[a-f0-9]{40}\n$/u.test(result.stdout.toString("utf8"))
        ? result.stdout.toString("utf8").trim()
        : null;
    } catch (cause) {
      if (
        ["ERR_GIT_UNAVAILABLE", "ERR_GIT_OUTPUT_TOO_LARGE"].includes(
          cause?.code,
        )
      )
        throw cause;
      throw new GitSafetyError("Cannot establish isolated Git hashing.", {
        cause,
        code: "ERR_GIT_UNAVAILABLE",
      });
    } finally {
      // Never delete a substituted directory or retire scratch before Git closes.
      try {
        if (allocation && directoryIdentity) {
          await verify(allocation, directoryIdentity);
          await rm(allocation, { recursive: true, force: true });
        }
      } catch (cause) {
        throw new GitSafetyError("Cannot safely retire Git hashing scratch.", {
          cause,
          code: "ERR_GIT_UNAVAILABLE",
        });
      } finally {
        await parentHandle?.close();
      }
    }
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
