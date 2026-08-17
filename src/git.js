import { createHash } from "node:crypto";

import {
  createGitCommandRunner,
  decodeLine,
  decodeUtf8,
  GitSafetyError,
  hashBuffer,
  isEnvironment,
  resolveRepository,
} from "./git-command.js";
import {
  contentFingerprintsAtRoot,
  inspectPathAtRoot,
  normalizeAllowedPaths,
} from "./git-content.js";

export { GitSafetyError };

const GIT_SNAPSHOT_SCHEMA_VERSION = 1;
const LOCAL_CONFIGURATION_PATH = ".agent-runner.json";
const SNAPSHOT_COMPARISONS = Object.freeze([
  ["head", "head"],
  ["branch", "branch"],
  ["refsFingerprint", "refs"],
  ["trackedContentFingerprint", "tracked-content"],
  ["untrackedContentFingerprint", "untracked-content"],
  ["indexFingerprint", "index"],
  ["remoteConfigurationFingerprint", "remote-configuration"],
  ["identityFingerprint", "identity"],
]);
const SNAPSHOT_FINGERPRINT_FIELDS = Object.freeze([
  "contentFingerprint",
  ...SNAPSHOT_COMPARISONS.slice(2).map(([field]) => field),
]);
const OBJECT_ID_PATTERN = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/u;
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;

function isRecord(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertOptions(value, name) {
  if (!isRecord(value)) {
    throw new GitSafetyError(`${name} must be an object.`, {
      code: "ERR_INVALID_GIT_OPTIONS",
    });
  }
  return value;
}

function assertBoolean(value, name) {
  if (typeof value !== "boolean") {
    throw new GitSafetyError(`${name} must be a boolean.`, {
      code: "ERR_INVALID_GIT_OPTIONS",
    });
  }
  return value;
}

function isPathList(value) {
  if (!Array.isArray(value) || value.length > 256) {
    return false;
  }
  for (const entry of value) {
    if (typeof entry !== "string" || entry.length === 0) {
      return false;
    }
  }
  return true;
}

function assertPathList(value, name) {
  if (!isPathList(value)) {
    throw new GitSafetyError(`${name} must be an array of paths.`, {
      code: "ERR_INVALID_GIT_OPTIONS",
    });
  }
  return value;
}

function assertSnapshot(value) {
  if (
    !isRecord(value) ||
    value.schemaVersion !== GIT_SNAPSHOT_SCHEMA_VERSION ||
    typeof value.projectPath !== "string" ||
    value.projectPath.length === 0 ||
    !isPathList(value.allowedPaths) ||
    (value.head !== null &&
      (typeof value.head !== "string" || !OBJECT_ID_PATTERN.test(value.head))) ||
    (value.branch !== null &&
      (typeof value.branch !== "string" || value.branch.length === 0)) ||
    typeof value.detached !== "boolean" ||
    value.detached !== (value.branch === null && value.head !== null) ||
    typeof value.clean !== "boolean" ||
    typeof value.identityAvailable !== "boolean" ||
    SNAPSHOT_FINGERPRINT_FIELDS.some(
      (field) =>
        typeof value[field] !== "string" ||
        !SHA256_PATTERN.test(value[field]),
    )
  ) {
    throw new GitSafetyError("Previous Git snapshot is invalid.", {
      code: "ERR_INVALID_GIT_SNAPSHOT",
    });
  }
  return value;
}

export function createGitService(options = {}) {
  assertOptions(options, "Git-service options");
  const { env = process.env, gitBinary = "git" } = options;
  if (
    !isEnvironment(env) ||
    typeof gitBinary !== "string" ||
    gitBinary.trim().length === 0 ||
    /[\0\r\n]/u.test(gitBinary)
  ) {
    throw new GitSafetyError("Git-service options are invalid.", {
      code: "ERR_INVALID_GIT_OPTIONS",
    });
  }
  const runGit = createGitCommandRunner({ env, gitBinary });

  async function currentHead(repositoryPath) {
    const result = await runGit(
      repositoryPath,
      ["rev-parse", "--verify", "HEAD"],
      { allowedExitCodes: [0, 128] },
    );
    return result.exitCode === 0
      ? decodeLine(result.stdout, "Git HEAD")
      : null;
  }

  const contentContext = Object.freeze({ currentHead, runGit });

  async function inspectPath(options) {
    assertOptions(options, "Path-inspection options");
    const { path, projectPath } = options;
    const repositoryPath = await resolveRepository(runGit, projectPath);
    return inspectPathAtRoot(contentContext, repositoryPath, path);
  }

  async function refsFingerprint(repositoryPath) {
    const result = await runGit(repositoryPath, [
      "for-each-ref",
      "--format=%(refname)%00%(objectname)%00%(symref)",
    ]);
    return hashBuffer(result.stdout);
  }

  async function indexFingerprint(repositoryPath) {
    const [entries, flags, cachedChanges] = await Promise.all([
      runGit(repositoryPath, [
        "ls-files",
        "--stage",
        "--resolve-undo",
        "-z",
      ]),
      runGit(repositoryPath, ["ls-files", "-v", "-z"]),
      runGit(repositoryPath, [
        "diff",
        "--cached",
        "--raw",
        "--abbrev=64",
        "--ita-invisible-in-index",
        "--ignore-submodules=none",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        "-z",
      ]),
    ]);
    return createHash("sha256")
      .update(entries.stdout)
      .update("\0")
      .update(flags.stdout)
      .update("\0")
      .update(cachedChanges.stdout)
      .digest("hex");
  }

  async function remoteConfigurationFingerprint(repositoryPath) {
    const remotesResult = await runGit(repositoryPath, ["remote"]);
    const remotes = decodeUtf8(remotesResult.stdout, "Git remote names")
      .split(/\r?\n/u)
      .filter(Boolean)
      .sort();
    const hash = createHash("sha256");
    for (const remote of remotes) {
      if (/\0|\r|\n/u.test(remote)) {
        throw new GitSafetyError("Git remote name is invalid.", {
          code: "ERR_UNSUPPORTED_GIT_CONFIGURATION",
        });
      }
      const fetch = await runGit(
        repositoryPath,
        ["remote", "get-url", "--all", "--", remote],
        { allowedExitCodes: [0, 2] },
      );
      const push = await runGit(
        repositoryPath,
        ["remote", "get-url", "--push", "--all", "--", remote],
        { allowedExitCodes: [0, 2] },
      );
      hash
        .update(Buffer.from(remote))
        .update("\0")
        .update(fetch.stdout)
        .update("\0")
        .update(push.stdout)
        .update("\0");
    }
    const configuration = await runGit(
      repositoryPath,
      ["config", "--null", "--get-regexp", "^(remote|url)\\."],
      { allowedExitCodes: [0, 1] },
    );
    hash.update(configuration.stdout);
    return hash.digest("hex");
  }

  async function identitySnapshot(repositoryPath) {
    const fixedDates = {
      GIT_AUTHOR_DATE: "2000-01-01T00:00:00Z",
      GIT_COMMITTER_DATE: "2000-01-01T00:00:00Z",
    };
    const author = await runGit(
      repositoryPath,
      ["-c", "user.useConfigOnly=true", "var", "GIT_AUTHOR_IDENT"],
      { allowedExitCodes: [0, 128], extraEnv: fixedDates },
    );
    const committer = await runGit(
      repositoryPath,
      ["-c", "user.useConfigOnly=true", "var", "GIT_COMMITTER_IDENT"],
      { allowedExitCodes: [0, 128], extraEnv: fixedDates },
    );
    const configuration = await runGit(
      repositoryPath,
      ["config", "--null", "--get-regexp", "^user\\.(name|email)$"],
      { allowedExitCodes: [0, 1] },
    );
    const identityFingerprint = createHash("sha256")
      .update(`${author.exitCode}\0`)
      .update(author.stdout)
      .update(`\0${committer.exitCode}\0`)
      .update(committer.stdout)
      .update("\0")
      .update(configuration.stdout)
      .digest("hex");
    return Object.freeze({
      identityAvailable: author.exitCode === 0 && committer.exitCode === 0,
      identityFingerprint,
    });
  }

  async function snapshot(options) {
    assertOptions(options, "Git-snapshot options");
    const { allowedPaths = [], projectPath } = options;
    assertPathList(allowedPaths, "allowedPaths");
    const repositoryPath = await resolveRepository(runGit, projectPath);
    const normalizedAllowedPaths = await normalizeAllowedPaths(
      repositoryPath,
      allowedPaths,
    );
    const head = await currentHead(repositoryPath);
    const branchResult = await runGit(
      repositoryPath,
      ["symbolic-ref", "-q", "HEAD"],
      { allowedExitCodes: [0, 1] },
    );
    const branch =
      branchResult.exitCode === 0
        ? decodeLine(branchResult.stdout, "Git branch")
        : null;
    const status = await runGit(repositoryPath, [
      "status",
      "--porcelain=v1",
      "-z",
      "--untracked-files=all",
      "--ignore-submodules=none",
    ]);
    const content = await contentFingerprintsAtRoot(
      contentContext,
      repositoryPath,
      normalizedAllowedPaths,
    );
    const identity = await identitySnapshot(repositoryPath);
    return Object.freeze({
      schemaVersion: GIT_SNAPSHOT_SCHEMA_VERSION,
      projectPath: repositoryPath,
      allowedPaths: normalizedAllowedPaths,
      head,
      branch,
      detached: branch === null && head !== null,
      clean: status.stdout.length === 0,
      refsFingerprint: await refsFingerprint(repositoryPath),
      ...content,
      indexFingerprint: await indexFingerprint(repositoryPath),
      remoteConfigurationFingerprint:
        await remoteConfigurationFingerprint(repositoryPath),
      ...identity,
    });
  }

  async function contentFingerprint(options) {
    assertOptions(options, "Content-fingerprint options");
    const { allowedPaths = [], projectPath } = options;
    assertPathList(allowedPaths, "allowedPaths");
    const repositoryPath = await resolveRepository(runGit, projectPath);
    const normalizedAllowedPaths = await normalizeAllowedPaths(
      repositoryPath,
      allowedPaths,
    );
    return (
      await contentFingerprintsAtRoot(
        contentContext,
        repositoryPath,
        normalizedAllowedPaths,
      )
    ).contentFingerprint;
  }

  async function preflight(options) {
    assertOptions(options, "Git-preflight options");
    const {
      allowedPaths = [],
      projectPath,
      requireClean = false,
      requireIdentity = false,
      requiredIgnoredPaths = [],
    } = options;
    assertPathList(allowedPaths, "allowedPaths");
    assertBoolean(requireClean, "requireClean");
    assertBoolean(requireIdentity, "requireIdentity");
    assertPathList(requiredIgnoredPaths, "requiredIgnoredPaths");
    const repositoryPath = await resolveRepository(runGit, projectPath);
    const configuration = await inspectPathAtRoot(
      contentContext,
      repositoryPath,
      LOCAL_CONFIGURATION_PATH,
    );
    if (configuration.tracked) {
      throw new GitSafetyError(
        `${LOCAL_CONFIGURATION_PATH} must remain untracked.`,
        { code: "ERR_TRACKED_RUNNER_CONFIGURATION" },
      );
    }
    if (!configuration.ignored) {
      throw new GitSafetyError(
        `${LOCAL_CONFIGURATION_PATH} must be ignored by the repository.`,
        { code: "ERR_UNIGNORED_RUNNER_CONFIGURATION" },
      );
    }
    const ignoredPaths = [];
    for (const path of requiredIgnoredPaths) {
      const inspected = await inspectPathAtRoot(
        contentContext,
        repositoryPath,
        path,
      );
      if (inspected.tracked || !inspected.ignored) {
        throw new GitSafetyError(
          "Repository-local artifact path must be ignored and untracked.",
          { code: "ERR_REPOSITORY_ARTIFACT_NOT_IGNORED" },
        );
      }
      ignoredPaths.push(inspected);
    }
    const repositorySnapshot = await snapshot({
      allowedPaths,
      projectPath: repositoryPath,
    });
    if (requireClean && !repositorySnapshot.clean) {
      throw new GitSafetyError("Repository must be clean before this run.", {
        code: "ERR_REPOSITORY_NOT_CLEAN",
      });
    }
    if (requireIdentity && !repositorySnapshot.identityAvailable) {
      throw new GitSafetyError(
        "Repository must have an existing Git author and committer identity.",
        { code: "ERR_GIT_IDENTITY_REQUIRED" },
      );
    }
    return Object.freeze({
      configuration,
      ignoredPaths: Object.freeze(ignoredPaths),
      snapshot: repositorySnapshot,
    });
  }

  async function assertUnchanged(previousSnapshot) {
    assertSnapshot(previousSnapshot);
    const currentSnapshot = await snapshot({
      allowedPaths: previousSnapshot.allowedPaths,
      projectPath: previousSnapshot.projectPath,
    });
    const changes = SNAPSHOT_COMPARISONS.filter(
      ([field]) => previousSnapshot[field] !== currentSnapshot[field],
    ).map(([, change]) => change);
    if (changes.length > 0) {
      throw new GitSafetyError("Read-only repository snapshot changed.", {
        changes,
        code: "ERR_READ_ONLY_REPOSITORY_CHANGED",
      });
    }
    return currentSnapshot;
  }

  return Object.freeze({
    assertUnchanged,
    contentFingerprint,
    inspectPath,
    preflight,
    snapshot,
  });
}
