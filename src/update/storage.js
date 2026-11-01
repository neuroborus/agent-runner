import { constants } from "node:fs";
import { lstat, mkdir, open, realpath, rm, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

import { openRuntimeStorage } from "../runtime/index.js";

export const identity = (value) =>
  Object.fromEntries(
    ["dev", "ino", "uid"].map((key) => [key, String(value[key])]),
  );
export const sameIdentity = (value, expected) =>
  expected !== null &&
  ["dev", "ino", "uid"].every((key) => String(value[key]) === expected[key]);

export function assertStoragePath(path, installation) {
  const within = (parent, child) => {
    const part = relative(parent, child);
    return (
      !part ||
      (part !== ".." && !part.startsWith(`..${sep}`) && !isAbsolute(part))
    );
  };
  if (
    typeof path !== "string" ||
    path.length > 4096 ||
    resolve(path) !== path ||
    !isAbsolute(path) ||
    /[\p{Cc}\p{Zl}\p{Zp}]/u.test(path) ||
    path
      .split(sep)
      .some((part) =>
        [".git", ".agents", ".codex", ".claude"].includes(part),
      ) ||
    [installation.rootPath, installation.installationPath]
      .filter(Boolean)
      .some(
        (application) => within(path, application) || within(application, path),
      )
  )
    throw new Error(
      "Candidate storage overlaps application or control storage.",
    );
}

export async function openAttempt(root, attempt) {
  await root.verify();
  const path = join(root.path, attempt.id);
  if (attempt.identity === null) {
    // Exclusive creation never adopts a directory left without an ownership receipt.
    await mkdir(join(root.anchor, attempt.id), { mode: 0o700 });
    await root.handle.sync();
  }
  const binding = await openRuntimeStorage(path);
  try {
    const actual = await binding.handle.stat({ bigint: true });
    if (attempt.identity !== null && !sameIdentity(actual, attempt.identity))
      throw new Error("Candidate directory was substituted.");
    return { ...binding, path, identity: identity(actual) };
  } catch (error) {
    await binding.close();
    throw error;
  }
}

export async function commandEnvironment(directory) {
  const paths = Object.fromEntries(
    [
      "home",
      "config",
      "state",
      "data",
      "cache",
      "temporary",
      "work",
      "prefix",
    ].map((name) => [name, join(directory.path, name)]),
  );
  for (const [name, path] of Object.entries(paths)) {
    try {
      await mkdir(join(directory.anchor, name), { mode: 0o700 });
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
    }
    const binding = await openRuntimeStorage(path);
    await binding.close();
  }
  // A private local package also stops npm from discovering ancestor settings.
  const configs = ["user.npmrc", "global.npmrc", ".npmrc", "package.json"];
  for (const name of configs) {
    const bytes = Buffer.from(
      name === "package.json" ? '{"private":true}\n' : "",
    );
    try {
      await writeFile(join(directory.anchor, name), bytes, {
        flag: "wx",
        mode: 0o600,
      });
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
    }
    const handle = await open(
      join(directory.anchor, name),
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    try {
      const stat = await handle.stat();
      if (
        !stat.isFile() ||
        stat.nlink !== 1 ||
        stat.size !== bytes.length ||
        stat.uid !== process.getuid() ||
        (stat.mode & 0o7777) !== 0o600 ||
        !(await handle.readFile()).equals(bytes)
      )
        throw new Error("Candidate npm configuration changed.");
    } finally {
      await handle.close();
    }
  }
  await directory.verify();
  const node = await realpath(process.execPath);
  return {
    paths,
    env: {
      PATH: dirname(node),
      HOME: paths.home,
      XDG_CONFIG_HOME: paths.config,
      XDG_STATE_HOME: paths.state,
      XDG_DATA_HOME: paths.data,
      XDG_CACHE_HOME: paths.cache,
      TMPDIR: paths.temporary,
      TMP: paths.temporary,
      TEMP: paths.temporary,
      NODE_COMPILE_CACHE: join(paths.cache, "node"),
      npm_config_cache: join(paths.cache, "npm"),
      npm_config_userconfig: join(directory.path, configs[0]),
      npm_config_globalconfig: join(directory.path, configs[1]),
      npm_config_update_notifier: "false",
      npm_config_fetch_retries: "0",
      npm_config_fetch_timeout: "30000",
    },
  };
}

export async function archiveSnapshot(directory, bytes) {
  const path = join(directory.path, "selected.tgz");
  const target = join(directory.anchor, "selected.tgz");
  try {
    await writeFile(target, bytes, { flag: "wx", mode: 0o400 });
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
  }
  const handle = await open(
    target,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const stat = await handle.stat();
    if (
      !stat.isFile() ||
      stat.nlink !== 1 ||
      stat.size !== bytes.length ||
      stat.uid !== process.getuid() ||
      (stat.mode & 0o7777) !== 0o400 ||
      !(await handle.readFile()).equals(bytes)
    )
      throw new Error("Candidate archive snapshot changed.");
    return { path, handle, close: () => handle.close() };
  } catch (error) {
    await handle.close();
    throw error;
  }
}

export async function removeSmoke(parent, expected) {
  await parent.verify();
  const path = join(parent.anchor, "smoke");
  let actual;
  try {
    actual = await lstat(path, { bigint: true });
  } catch (error) {
    if (error.code === "ENOENT") return;
    throw error;
  }
  if (!sameIdentity(actual, expected))
    throw new Error("Smoke storage ownership changed.");
  // Smoke storage is mutable; never change permissions or follow a substituted root.
  await rm(path, { recursive: true });
}
