import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, readFile, realpath } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { fileURLToPath } from "node:url";

import { PROVIDER_REGISTRY } from "../agents/index.js";

import {
  CONFIG_FILENAME,
  CONFIG_SCHEMA_VERSION,
  ConfigurationError,
  DEFAULT_ARTIFACT_ROOT,
  normalizeConfiguration,
  parseProjectConfiguration,
  parseRunnerConfiguration,
  PROJECT_CONFIG_FILENAME,
} from "./parsing.js";

const CONFIG_PATH = fileURLToPath(
  new URL(`../../${CONFIG_FILENAME}`, import.meta.url),
);
const MAX_CONFIGURATION_BYTES = 1024 * 1024;
const NO_FOLLOW = constants.O_NOFOLLOW ?? 0;
const NONBLOCK = constants.O_NONBLOCK ?? 0;

function isWithin(parentPath, childPath) {
  const pathFromParent = relative(parentPath, childPath);
  return (
    pathFromParent === "" ||
    (!pathFromParent.startsWith(`..${sep}`) &&
      pathFromParent !== ".." &&
      !isAbsolute(pathFromParent))
  );
}

function fileIdentity(metadata) {
  return Object.freeze({
    device: metadata.dev.toString(),
    inode: metadata.ino.toString(),
    size: metadata.size.toString(),
    modifiedNs: metadata.mtimeNs.toString(),
    changedNs: metadata.ctimeNs.toString(),
  });
}

async function confinedAncestors(projectPath, path) {
  if (!isWithin(projectPath, path) || path === projectPath) {
    throw new ConfigurationError(
      "Project configuration must remain inside the project.",
      { code: "ERR_PROJECT_CONFIGURATION_READ" },
    );
  }
  const paths = [];
  for (let current = dirname(path); ; current = dirname(current)) {
    paths.unshift(current);
    if (current === projectPath) break;
    if (current === dirname(current)) {
      throw new ConfigurationError(
        "Project configuration must remain inside the project.",
        { code: "ERR_PROJECT_CONFIGURATION_READ" },
      );
    }
  }
  return Promise.all(
    paths.map(async (ancestorPath) => {
      const before = await lstat(ancestorPath, { bigint: true });
      const canonicalPath = await realpath(ancestorPath);
      const after = await lstat(ancestorPath, { bigint: true });
      if (
        !before.isDirectory() ||
        !after.isDirectory() ||
        canonicalPath !== ancestorPath ||
        before.dev !== after.dev ||
        before.ino !== after.ino
      ) {
        throw new ConfigurationError(
          "Project configuration ancestors must be real directories.",
          { code: "ERR_PROJECT_CONFIGURATION_READ" },
        );
      }
      return Object.freeze({
        path: ancestorPath,
        device: after.dev.toString(),
        inode: after.ino.toString(),
      });
    }),
  );
}

async function readConfinedConfiguration(path, projectPath, relativePath) {
  let handle;
  try {
    const [pathBefore, ancestorsBefore] = await Promise.all([
      lstat(path, { bigint: true }),
      confinedAncestors(projectPath, path),
    ]);
    if (
      !pathBefore.isFile() ||
      pathBefore.nlink !== 1n ||
      pathBefore.size > BigInt(MAX_CONFIGURATION_BYTES)
    ) {
      throw new ConfigurationError(
        "Project configuration must be a bounded, unlinked regular file.",
        { code: "ERR_PROJECT_CONFIGURATION_READ" },
      );
    }
    handle = await open(path, constants.O_RDONLY | NO_FOLLOW | NONBLOCK);
    const before = await handle.stat({ bigint: true });
    if (
      !before.isFile() ||
      before.nlink !== 1n ||
      before.size > BigInt(MAX_CONFIGURATION_BYTES)
    ) {
      throw new ConfigurationError(
        "Project configuration must be a bounded, unlinked regular file.",
        { code: "ERR_PROJECT_CONFIGURATION_READ" },
      );
    }
    if (
      pathBefore.dev !== before.dev ||
      pathBefore.ino !== before.ino ||
      pathBefore.size !== before.size ||
      pathBefore.mtimeNs !== before.mtimeNs ||
      pathBefore.ctimeNs !== before.ctimeNs
    ) {
      throw new ConfigurationError(
        "Project configuration changed while it was read.",
        { code: "ERR_PROJECT_CONFIGURATION_READ" },
      );
    }
    const buffer = Buffer.allocUnsafe(MAX_CONFIGURATION_BYTES + 1);
    let length = 0;
    while (length < buffer.length) {
      const { bytesRead } = await handle.read(
        buffer,
        length,
        buffer.length - length,
        null,
      );
      if (bytesRead === 0) {
        break;
      }
      length += bytesRead;
    }
    const source = buffer.subarray(0, length);
    if (source.length > MAX_CONFIGURATION_BYTES) {
      throw new ConfigurationError(
        "Project configuration must be a bounded regular file.",
        { code: "ERR_PROJECT_CONFIGURATION_READ" },
      );
    }
    const [after, pathAfter, canonicalPath, ancestorsAfter] = await Promise.all(
      [
        handle.stat({ bigint: true }),
        lstat(path, { bigint: true }),
        realpath(path),
        confinedAncestors(projectPath, path),
      ],
    );
    if (
      !pathAfter.isFile() ||
      pathAfter.nlink !== 1n ||
      canonicalPath !== path ||
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.size !== after.size ||
      before.mtimeNs !== after.mtimeNs ||
      before.ctimeNs !== after.ctimeNs ||
      after.dev !== pathAfter.dev ||
      after.ino !== pathAfter.ino ||
      after.size !== pathAfter.size ||
      after.mtimeNs !== pathAfter.mtimeNs ||
      after.ctimeNs !== pathAfter.ctimeNs ||
      !isDeepStrictEqual(ancestorsBefore, ancestorsAfter)
    ) {
      throw new ConfigurationError(
        "Project configuration changed while it was read.",
        { code: "ERR_PROJECT_CONFIGURATION_READ" },
      );
    }
    let content;
    try {
      content = new TextDecoder("utf-8", { fatal: true }).decode(source);
    } catch (cause) {
      throw new ConfigurationError(
        "Project configuration must contain valid UTF-8.",
        { cause, code: "ERR_PROJECT_CONFIGURATION_READ" },
      );
    }
    return Object.freeze({
      content,
      protection: Object.freeze({
        schemaVersion: 1,
        path,
        projectPath,
        relativePath,
        contentHash: createHash("sha256").update(source).digest("hex"),
        identity: fileIdentity(after),
        ancestors: Object.freeze(ancestorsAfter),
      }),
    });
  } catch (cause) {
    if (cause instanceof ConfigurationError) {
      throw cause;
    }
    throw new ConfigurationError(
      `Cannot read project configuration at ${path}.`,
      { cause, code: "ERR_PROJECT_CONFIGURATION_READ" },
    );
  } finally {
    await handle?.close();
  }
}

export async function loadProjectConfiguration({
  configurationPath,
  inspectPath,
  projectPath,
  providers = PROVIDER_REGISTRY,
  runnerConfiguration,
}) {
  if (typeof inspectPath !== "function") {
    throw new ConfigurationError(
      "Project configuration path inspection is unavailable.",
      { code: "ERR_PROJECT_CONFIGURATION_READ" },
    );
  }
  const explicit = configurationPath !== undefined;
  if (
    explicit &&
    (typeof configurationPath !== "string" ||
      configurationPath.trim().length === 0)
  ) {
    throw new ConfigurationError(
      "Project configuration path must be a non-empty string.",
    );
  }
  const requestedPath =
    configurationPath ??
    join(projectPath, DEFAULT_ARTIFACT_ROOT, PROJECT_CONFIG_FILENAME);
  const inspection = await inspectPath({ path: requestedPath, projectPath });
  if (!inspection.exists) {
    if (!explicit) {
      return null;
    }
    throw new ConfigurationError(
      `Project configuration does not exist at ${inspection.path}.`,
      { code: "ERR_PROJECT_CONFIGURATION_READ" },
    );
  }
  if (inspection.tracked || !inspection.ignored) {
    throw new ConfigurationError(
      "Project configuration must be ignored and untracked.",
      { code: "ERR_PROJECT_CONFIGURATION_NOT_IGNORED" },
    );
  }
  const loaded = await readConfinedConfiguration(
    inspection.path,
    projectPath,
    inspection.relativePath,
  );
  return Object.freeze({
    path: inspection.path,
    configuration: parseProjectConfiguration(
      loaded.content,
      runnerConfiguration,
      providers,
    ),
    protection: loaded.protection,
  });
}

export async function assertProjectConfigurationProtected({
  inspectPath,
  projectPath,
  protection,
}) {
  if (protection === null) return;
  try {
    const inspection = await inspectPath({
      path: protection.path,
      projectPath,
    });
    if (
      !inspection.exists ||
      inspection.path !== protection.path ||
      inspection.relativePath !== protection.relativePath ||
      inspection.tracked ||
      !inspection.ignored
    ) {
      throw new Error("Project configuration confinement changed.");
    }
    const current = await readConfinedConfiguration(
      protection.path,
      projectPath,
      protection.relativePath,
    );
    if (!isDeepStrictEqual(current.protection, protection)) {
      throw new Error("Project configuration identity changed.");
    }
  } catch (cause) {
    throw new ConfigurationError(
      "The resolved project configuration changed during the run.",
      { cause, code: "ERR_PROJECT_CONFIGURATION_CHANGED" },
    );
  }
}

export async function loadRunnerConfiguration(providers = PROVIDER_REGISTRY) {
  let source;
  try {
    source = await readFile(CONFIG_PATH, "utf8");
  } catch (cause) {
    if (cause?.code === "ENOENT") {
      return normalizeConfiguration(
        { schemaVersion: CONFIG_SCHEMA_VERSION },
        providers,
      );
    }

    throw new ConfigurationError(
      `Cannot read runner configuration at ${CONFIG_PATH}.`,
      { cause, code: "ERR_CONFIGURATION_READ" },
    );
  }

  return parseRunnerConfiguration(source, providers);
}
