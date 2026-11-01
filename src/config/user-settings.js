import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import {
  link,
  lstat,
  mkdir,
  open,
  realpath,
  stat,
  unlink,
} from "node:fs/promises";
import { homedir } from "node:os";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  parse,
  relative,
  resolve,
  sep,
  win32,
} from "node:path";
import { fileURLToPath } from "node:url";

import { PROVIDER_REGISTRY } from "../agents/index.js";
import { getRuntimeContext } from "../runtime/index.js";

import { readConfinedConfiguration } from "./files.js";
import {
  CONFIG_FILENAME,
  CONFIG_SCHEMA_VERSION,
  ConfigurationError,
  normalizeConfiguration,
  parseRunnerConfiguration,
} from "./parsing.js";

const INSTALLATION_PATH = fileURLToPath(new URL("../../", import.meta.url));
const DIRECTORY_FLAGS =
  constants.O_RDONLY |
  (constants.O_DIRECTORY ?? 0) |
  (constants.O_NOFOLLOW ?? 0);
const UNSAFE_PATH = /[\p{Cc}\p{Zl}\p{Zp}]/u;

function absolutePath(value, paths = { isAbsolute, resolve }) {
  if (
    typeof value !== "string" ||
    UNSAFE_PATH.test(value) ||
    !paths.isAbsolute(value) ||
    (paths === win32 && win32.parse(value).root.length === 1)
  ) {
    throw new ConfigurationError(
      "Configuration locations must be absolute, safe paths.",
    );
  }
  return paths.resolve(value);
}

export function resolveUserConfigurationPath({
  env = process.env,
  homeDirectory,
  platform = process.platform,
} = {}) {
  if (platform === "win32") {
    return win32.join(
      absolutePath(env.APPDATA, win32),
      "agent-runner",
      "config.json",
    );
  }
  if (platform === "darwin") {
    return join(
      absolutePath(homeDirectory ?? env.HOME ?? homedir()),
      "Library",
      "Application Support",
      "agent-runner",
      "config.json",
    );
  }
  if (platform !== "linux")
    throw new ConfigurationError(
      "User configuration location is unsupported on this platform.",
    );
  // XDG specifies that relative values are ignored.
  const root =
    env.XDG_CONFIG_HOME && isAbsolute(env.XDG_CONFIG_HOME)
      ? absolutePath(env.XDG_CONFIG_HOME)
      : join(absolutePath(homeDirectory ?? env.HOME ?? homedir()), ".config");
  return join(root, "agent-runner", "config.json");
}

function locations(options) {
  const installationPath = absolutePath(
    options.installationPath ??
      getRuntimeContext()?.installationPath ??
      INSTALLATION_PATH,
  );
  const userPath = resolveUserConfigurationPath(options);
  const local = relative(installationPath, userPath);
  if (
    local === "" ||
    (local !== ".." && !local.startsWith(`..${sep}`) && !isAbsolute(local))
  ) {
    throw new ConfigurationError(
      "User settings must remain outside the installation.",
    );
  }
  return { userPath, legacyPath: join(installationPath, CONFIG_FILENAME) };
}

async function readOptional(path) {
  // Check existing ancestors first: a missing leaf must not hide a dangling link.
  const ancestors = [];
  for (let current = dirname(path); ; current = dirname(current)) {
    ancestors.unshift(current);
    if (current === dirname(current)) break;
  }
  for (const current of [...ancestors, path]) {
    let metadata;
    try {
      metadata = await lstat(current);
    } catch (cause) {
      if (cause?.code === "ENOENT") return null;
      throw cause;
    }
    if (
      current !== path &&
      (!metadata.isDirectory() || (await realpath(current)) !== current)
    ) {
      throw new ConfigurationError(
        "Configuration ancestors must be real directories.",
      );
    }
  }
  return readConfinedConfiguration(
    path,
    parse(path).root,
    relative(parse(path).root, path),
  );
}

export async function loadRunnerConfiguration(
  providers = PROVIDER_REGISTRY,
  options = {},
) {
  let loaded;
  try {
    const { userPath, legacyPath } = locations(options);
    loaded = (await readOptional(userPath)) ?? (await readOptional(legacyPath));
  } catch (cause) {
    throw new ConfigurationError("Cannot read global runner configuration.", {
      cause,
      code: "ERR_CONFIGURATION_READ",
    });
  }
  return loaded === null
    ? normalizeConfiguration(
        { schemaVersion: CONFIG_SCHEMA_VERSION },
        providers,
      )
    : parseRunnerConfiguration(loaded.content, providers);
}

async function descriptorPath(handle) {
  const identity = await handle.stat();
  for (const root of ["/proc/self/fd", "/dev/fd"]) {
    const path = join(root, String(handle.fd));
    try {
      const metadata = await stat(path);
      if (metadata.dev === identity.dev && metadata.ino === identity.ino)
        return path;
    } catch (cause) {
      if (!["ENOENT", "ENOTDIR"].includes(cause?.code)) throw cause;
    }
  }
  throw new ConfigurationError(
    "Configuration migration requires descriptor-bound directory access.",
  );
}

async function prepareDirectory(path) {
  const bindings = [];
  try {
    const root = parse(path).root;
    let current = root;
    let handle = await open(root, DIRECTORY_FLAGS);
    bindings.push({ path: root, handle, identity: await handle.stat() });
    for (const name of relative(root, path).split(sep).filter(Boolean)) {
      const child = join(await descriptorPath(handle), name);
      let next;
      try {
        next = await open(child, DIRECTORY_FLAGS);
      } catch (cause) {
        if (cause?.code !== "ENOENT") throw cause;
        try {
          await mkdir(child, { mode: 0o700 });
          await handle.sync();
        } catch (creationError) {
          if (creationError?.code !== "EEXIST") throw creationError;
        }
        next = await open(child, DIRECTORY_FLAGS);
      }
      handle = next;
      current = join(current, name);
      bindings.push({ path: current, handle, identity: await handle.stat() });
    }
    const verify = async () => {
      for (const binding of bindings) {
        const metadata = await lstat(binding.path);
        if (
          !metadata.isDirectory() ||
          metadata.dev !== binding.identity.dev ||
          metadata.ino !== binding.identity.ino ||
          (await realpath(binding.path)) !== binding.path
        ) {
          throw new ConfigurationError(
            "Configuration directory identity changed.",
          );
        }
      }
    };
    await verify();
    return {
      handle,
      path: await descriptorPath(handle),
      verify,
      close: () => Promise.all(bindings.map(({ handle }) => handle.close())),
    };
  } catch (cause) {
    await Promise.all(bindings.map(({ handle }) => handle.close()));
    throw cause;
  }
}

function sameDestination(existing, bytes) {
  if (!existing.bytes.equals(bytes)) {
    throw new ConfigurationError(
      "User configuration conflicts with the migration source; neither file was changed.",
      { code: "ERR_CONFIGURATION_CONFLICT" },
    );
  }
}

export async function migrateRunnerConfiguration({
  from,
  providers = PROVIDER_REGISTRY,
  ...options
} = {}) {
  let directory;
  let temporary;
  try {
    if (
      typeof from !== "string" ||
      from.trim().length === 0 ||
      UNSAFE_PATH.test(from)
    ) {
      throw new ConfigurationError(
        "Migration requires a safe source file path.",
      );
    }
    const { userPath } = locations(options);
    const sourcePath = resolve(from);
    const source = await readOptional(sourcePath);
    if (source === null)
      throw new ConfigurationError("Migration source does not exist.");
    parseRunnerConfiguration(source.content, providers);
    const existing = await readOptional(userPath);
    if (existing !== null) {
      sameDestination(existing, source.bytes);
      return Object.freeze({ path: userPath, migrated: false });
    }
    directory = await prepareDirectory(dirname(userPath));
    const temporaryPath = join(directory.path, `.config-${randomUUID()}.tmp`);
    const file = await open(
      temporaryPath,
      constants.O_WRONLY |
        constants.O_CREAT |
        constants.O_EXCL |
        (constants.O_NOFOLLOW ?? 0),
      0o600,
    );
    temporary = temporaryPath;
    try {
      await file.writeFile(source.bytes);
      await file.sync();
    } finally {
      await file.close();
    }
    await directory.verify();
    let migrated = true;
    try {
      // Linking a complete private file is atomic and cannot replace a winner.
      await link(temporary, join(directory.path, basename(userPath)));
    } catch (cause) {
      if (cause?.code !== "EEXIST") throw cause;
      migrated = false;
    }
    await unlink(temporary);
    temporary = undefined;
    await directory.handle.sync();
    await directory.verify();
    const published = await readOptional(userPath);
    if (published === null)
      throw new ConfigurationError("Migrated configuration is missing.");
    sameDestination(published, source.bytes);
    return Object.freeze({ path: userPath, migrated });
  } catch (cause) {
    if (cause?.code === "ERR_CONFIGURATION_CONFLICT") throw cause;
    throw new ConfigurationError(
      "Cannot migrate global runner configuration; source was retained.",
      { cause, code: "ERR_CONFIGURATION_MIGRATION" },
    );
  } finally {
    try {
      if (temporary !== undefined) await unlink(temporary);
    } finally {
      await directory?.close();
    }
  }
}
