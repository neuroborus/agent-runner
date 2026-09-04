import { constants } from "node:fs";
import { lstat, open, readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

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

async function readConfinedConfiguration(path) {
  let handle;
  try {
    const pathBefore = await lstat(path, { bigint: true });
    if (
      !pathBefore.isFile() ||
      pathBefore.size > BigInt(MAX_CONFIGURATION_BYTES)
    ) {
      throw new ConfigurationError(
        "Project configuration must be a bounded regular file.",
        { code: "ERR_PROJECT_CONFIGURATION_READ" },
      );
    }
    handle = await open(path, constants.O_RDONLY | NO_FOLLOW | NONBLOCK);
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.size > BigInt(MAX_CONFIGURATION_BYTES)) {
      throw new ConfigurationError(
        "Project configuration must be a bounded regular file.",
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
    const [after, pathAfter] = await Promise.all([
      handle.stat({ bigint: true }),
      lstat(path, { bigint: true }),
    ]);
    if (
      !pathAfter.isFile() ||
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.size !== after.size ||
      before.mtimeNs !== after.mtimeNs ||
      before.ctimeNs !== after.ctimeNs ||
      after.dev !== pathAfter.dev ||
      after.ino !== pathAfter.ino ||
      after.size !== pathAfter.size ||
      after.mtimeNs !== pathAfter.mtimeNs ||
      after.ctimeNs !== pathAfter.ctimeNs
    ) {
      throw new ConfigurationError(
        "Project configuration changed while it was read.",
        { code: "ERR_PROJECT_CONFIGURATION_READ" },
      );
    }
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(source);
    } catch (cause) {
      throw new ConfigurationError(
        "Project configuration must contain valid UTF-8.",
        { cause, code: "ERR_PROJECT_CONFIGURATION_READ" },
      );
    }
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
  return Object.freeze({
    path: inspection.path,
    configuration: parseProjectConfiguration(
      await readConfinedConfiguration(inspection.path),
      runnerConfiguration,
    ),
  });
}

export async function loadRunnerConfiguration() {
  let source;
  try {
    source = await readFile(CONFIG_PATH, "utf8");
  } catch (cause) {
    if (cause?.code === "ENOENT") {
      return normalizeConfiguration({ schemaVersion: CONFIG_SCHEMA_VERSION });
    }

    throw new ConfigurationError(
      `Cannot read runner configuration at ${CONFIG_PATH}.`,
      { cause, code: "ERR_CONFIGURATION_READ" },
    );
  }

  return parseRunnerConfiguration(source);
}
