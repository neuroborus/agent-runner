import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
  open,
  readFile,
  readdir,
  realpath,
  unlink,
  writeFile,
} from "node:fs/promises";
import {
  dirname,
  isAbsolute,
  join,
  matchesGlob,
  relative,
  resolve,
  sep,
} from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { isDeepStrictEqual, parseArgs } from "node:util";

import { inspectReleaseArchive } from "./release-archive.js";
import {
  assertPublicationMetadata,
  OFFICIAL_RELEASE_POLICY,
} from "../src/config/release/index.js";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const json = (bytes) => JSON.parse(bytes.toString("utf8"));
const within = (parent, path) =>
  relative(parent, path) === "" ||
  (!relative(parent, path).startsWith(`..${sep}`) &&
    relative(parent, path) !== ".." &&
    !isAbsolute(relative(parent, path)));

function safeRelative(path) {
  if (
    typeof path !== "string" ||
    isAbsolute(path) ||
    /[\\\p{Cc}]/u.test(path) ||
    path.split("/").some((part) => ["", ".", ".."].includes(part))
  )
    throw new Error("Unsafe release input path.");
  return path;
}

// Read one bounded snapshot without following file links or accepting drift.
export async function readReleaseFile(path) {
  const before = await lstat(path, { bigint: true });
  if (
    !before.isFile() ||
    before.nlink !== 1n ||
    before.size > 64n * 1024n * 1024n ||
    (await realpath(path)) !== path
  )
    throw new Error("Release inputs must be real, unlinked regular files.");
  const handle = await open(
    path,
    constants.O_RDONLY |
      (constants.O_NOFOLLOW ?? 0) |
      (constants.O_NONBLOCK ?? 0),
  );
  try {
    const inspected = await handle.stat({ bigint: true });
    const keys = ["dev", "ino", "size", "mtimeNs", "ctimeNs", "mode", "nlink"];
    if (
      !inspected.isFile() ||
      keys.some((key) => before[key] !== inspected[key])
    )
      throw new Error("Release input changed before reading.");
    const bytes = await handle.readFile();
    for (const after of [
      await handle.stat({ bigint: true }),
      await lstat(path, { bigint: true }),
    ]) {
      if (keys.some((key) => before[key] !== after[key]))
        throw new Error("Release input changed while reading.");
    }
    return { bytes, mode: (before.mode & 0o111n) === 0n ? 0o644 : 0o755 };
  } finally {
    await handle.close();
  }
}

async function selectedFiles(root, rules) {
  if (!Array.isArray(rules) || rules.length === 0)
    throw new Error("An explicit package file allowlist is required.");
  const selected = new Set();
  async function walk(path, rule) {
    const absolute = join(root, path);
    const metadata = await lstat(absolute);
    if (metadata.isSymbolicLink())
      throw new Error("Release input links are not allowed.");
    if (metadata.isDirectory()) {
      for (const name of (await readdir(absolute)).sort()) {
        if (name === "node_modules" || name.startsWith(".")) continue;
        await walk(path ? `${path}/${name}` : name, rule);
      }
    } else if (
      metadata.isFile() &&
      (path === rule || path.startsWith(rule + "/") || matchesGlob(path, rule))
    )
      selected.add(path);
    else if (!metadata.isFile())
      throw new Error("Release input contains a special file.");
  }
  for (const rule of rules) {
    safeRelative(rule);
    const wildcard = rule.search(/[?*[]/u);
    const prefix = rule.slice(0, wildcard);
    const base =
      wildcard === -1
        ? rule
        : prefix.slice(0, prefix.lastIndexOf("/") + 1).replace(/\/$/u, "");
    await walk(base, rule);
  }
  return [...selected].sort();
}

function dependencySlot(packages, from, name) {
  if (!/^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/u.test(name))
    throw new Error("Invalid dependency name.");
  for (let current = from; ; current = dirname(current)) {
    const slot =
      (current === "." || current === "" ? "" : `${current}/`) +
      `node_modules/${name}`;
    if (
      current.split("/").at(-1) !== "node_modules" &&
      Object.hasOwn(packages, slot)
    )
      return slot;
    if (current === "." || current === "") break;
  }
  throw new Error(`Missing locked production dependency: ${name}.`);
}

export async function assembleRelease({
  projectPath = ROOT,
  outputPath = join(projectPath, "dist", "release"),
  publicationPolicy = OFFICIAL_RELEASE_POLICY,
} = {}) {
  const root = await realpath(projectPath);
  const metadata = json(
    (await readReleaseFile(join(root, "package.json"))).bytes,
  );
  const lockBytes = (await readReleaseFile(join(root, "package-lock.json")))
    .bytes;
  const lock = json(lockBytes);
  const lockedRoot = lock.packages?.[""];
  const isLocalCandidate =
    metadata.name === "@your-scope/agent-runner" &&
    metadata.private === true &&
    metadata.license === "UNLICENSED" &&
    !metadata.repository &&
    !metadata.publishConfig;
  if (!isLocalCandidate) assertPublicationMetadata(metadata, publicationPolicy);
  if (
    lock.lockfileVersion !== 3 ||
    lock.name !== metadata.name ||
    lock.version !== metadata.version ||
    lockedRoot?.name !== metadata.name ||
    lockedRoot.version !== metadata.version ||
    lockedRoot.license !== metadata.license ||
    !isDeepStrictEqual(lockedRoot.workspaces, metadata.workspaces) ||
    !isDeepStrictEqual(
      lockedRoot.bundleDependencies,
      metadata.bundleDependencies,
    ) ||
    !isDeepStrictEqual(lockedRoot.dependencies, metadata.dependencies) ||
    !isDeepStrictEqual(lockedRoot.engines, metadata.engines)
  )
    throw new Error("Package and lock metadata disagree.");
  if (
    !isDeepStrictEqual(
      [...metadata.bundleDependencies].sort(),
      Object.keys(metadata.dependencies).sort(),
    )
  )
    throw new Error("Every direct production dependency must be bundled.");

  const links = new Map();
  for (const [slot, entry] of Object.entries(lock.packages)) {
    if (entry.link) {
      safeRelative(slot);
      safeRelative(entry.resolved);
      if (
        !metadata.workspaces.some((rule) => matchesGlob(entry.resolved, rule))
      )
        throw new Error("Locked workspace is outside declared workspaces.");
      links.set(entry.resolved, slot);
    }
  }
  const destinationSlot = (slot) => {
    const owner = [...links.keys()]
      .sort((a, b) => b.length - a.length)
      .find((path) => slot.startsWith(`${path}/node_modules/`));
    return owner ? links.get(owner) + slot.slice(owner.length) : slot;
  };
  const dependencies = new Map();
  async function visit(slot) {
    if (dependencies.has(slot)) return;
    safeRelative(slot);
    const entry = lock.packages[slot];
    if (!entry || entry.dev || (!entry.link && !entry.integrity))
      throw new Error("Production dependency is not locked.");
    const source = entry.link ? entry.resolved : slot;
    const expected = entry.link ? lock.packages[source] : entry;
    const sourceRoot = join(root, source);
    if (
      (await realpath(sourceRoot)) !== sourceRoot ||
      !within(root, sourceRoot)
    )
      throw new Error("Dependency source escapes the checkout.");
    if (entry.link && (await realpath(join(root, slot))) !== sourceRoot)
      throw new Error("Installed workspace link disagrees with the lock.");
    const manifestBytes = (
      await readReleaseFile(join(sourceRoot, "package.json"))
    ).bytes;
    const manifest = json(manifestBytes);
    if (
      manifest.version !== expected?.version ||
      slot.split("node_modules/").at(-1) !== manifest.name ||
      !isDeepStrictEqual(
        manifest.dependencies ?? {},
        expected.dependencies ?? {},
      ) ||
      (entry.link && manifest.private !== true)
    )
      throw new Error("Installed dependency disagrees with the lock.");
    if (
      Object.keys(manifest.optionalDependencies ?? {}).length ||
      Object.keys(manifest.peerDependencies ?? {}).length
    )
      throw new Error(
        "This assembler requires an explicit lock-closure implementation for optional or peer dependencies.",
      );
    if (!Array.isArray(manifest.files) || manifest.files.length === 0)
      throw new Error(
        "Dependencies require an explicit runtime file allowlist.",
      );
    dependencies.set(slot, {
      sourceRoot,
      manifest,
      manifestBytes,
      entry,
      destination: destinationSlot(slot),
    });
    for (const name of Object.keys(manifest.dependencies ?? {}).sort())
      await visit(dependencySlot(lock.packages, source, name));
  }
  for (const name of Object.keys(metadata.dependencies).sort())
    await visit(dependencySlot(lock.packages, "", name));

  const output = resolve(outputPath);
  if (
    within(root, output) &&
    (!within(join(root, "dist"), output) || output === join(root, "dist"))
  )
    throw new Error(
      "Checkout release output must be a fresh directory under dist.",
    );
  if (
    output
      .split(sep)
      .some((part) => [".git", ".agents", ".codex", ".claude"].includes(part))
  )
    throw new Error("Release output cannot use control storage.");
  const parent = dirname(output);
  if (parent === join(root, "dist")) {
    try {
      await mkdir(parent);
    } catch (cause) {
      if (cause.code !== "EEXIST") throw cause;
    }
  }
  if (
    (await realpath(parent)) !== parent ||
    !(await lstat(parent)).isDirectory()
  )
    throw new Error(
      "Release output parent must be an existing real directory.",
    );
  await mkdir(output, { mode: 0o700 });
  const packagePath = join(output, "package");
  await mkdir(packagePath);
  const files = [];
  async function write(path, bytes, mode) {
    safeRelative(path);
    const target = join(packagePath, path);
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, bytes, { flag: "wx", mode });
    await chmod(target, mode);
    files.push({ path, size: bytes.length, mode, sha256: digest(bytes) });
  }
  async function copy(sourceRoot, prefix, rules, manifestBytes) {
    for (const path of await selectedFiles(sourceRoot, rules)) {
      const source = await readReleaseFile(join(sourceRoot, path));
      if (
        path === "package.json" &&
        manifestBytes &&
        !manifestBytes.equals(source.bytes)
      )
        throw new Error("Dependency manifest changed during assembly.");
      await write(prefix + path, source.bytes, source.mode);
    }
  }
  const candidate = { ...metadata };
  delete candidate.workspaces;
  delete candidate.devDependencies;
  delete candidate.scripts;
  await write(
    "package.json",
    Buffer.from(JSON.stringify(candidate, null, 2) + "\n"),
    0o644,
  );
  await copy(
    root,
    "",
    metadata.files.filter((path) => path !== "release-manifest.json"),
  );
  for (const {
    sourceRoot,
    manifest,
    manifestBytes,
    destination,
  } of dependencies.values()) {
    const notices = (await readdir(sourceRoot)).filter((name) =>
      /^(?:README|LICEN[CS]E|COPYING|NOTICE)(?:\..*)?$/iu.test(name),
    );
    await copy(
      sourceRoot,
      destination + "/",
      [...new Set(["package.json", ...notices, ...manifest.files])],
      manifestBytes,
    );
  }
  files.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  const manifest = {
    schemaVersion: 1,
    name: candidate.name,
    version: candidate.version,
    lockSha256: digest(lockBytes),
    dependencies: [...dependencies.values()]
      .map(({ manifest, destination, entry }) => ({
        path: destination,
        name: manifest.name,
        version: manifest.version,
        integrity: entry.integrity ?? null,
      }))
      .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0)),
    files,
  };
  await writeFile(
    join(packagePath, "release-manifest.json"),
    JSON.stringify(manifest, null, 2) + "\n",
    { flag: "wx", mode: 0o644 },
  );
  return Object.freeze({ outputPath: output, packagePath, manifest });
}

export async function packRelease(release) {
  const userConfig = join(release.outputPath, "user.npmrc");
  const globalConfig = join(release.outputPath, "global.npmrc");
  for (const path of [userConfig, globalConfig])
    await writeFile(path, "", { flag: "wx", mode: 0o600 });
  const logPath = join(release.outputPath, "pack.stdout");
  const log = await open(logPath, "wx", 0o600);
  let stdout;
  try {
    const child = spawn(
      "npm",
      [
        "pack",
        "--json",
        "--offline",
        "--ignore-scripts",
        "--pack-destination",
        release.outputPath,
      ],
      {
        cwd: release.packagePath,
        env: {
          PATH: process.env.PATH,
          HOME: join(release.outputPath, "home"),
          TMPDIR: process.env.TMPDIR,
          NODE_COMPILE_CACHE: join(release.outputPath, "cache", "node"),
          npm_config_cache: join(release.outputPath, "cache"),
          npm_config_userconfig: userConfig,
          npm_config_globalconfig: globalConfig,
        },
        stdio: ["ignore", log.fd, "ignore"],
      },
    );
    const result = await new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("close", (code, signal) => resolve({ code, signal }));
    });
    if (result.code !== 0)
      throw new Error(`npm pack failed (${result.code ?? result.signal}).`);
    if ((await log.stat()).size > 8 * 1024 * 1024)
      throw new Error("npm pack output is too large.");
    stdout = await readFile(logPath, "utf8");
  } finally {
    await log.close();
    await unlink(logPath);
  }
  const [packed] = JSON.parse(stdout);
  if (
    typeof packed?.filename !== "string" ||
    !/^[a-z0-9._-]+\.tgz$/u.test(packed.filename)
  )
    throw new Error("npm returned an unsafe archive filename.");
  const tarballPath = join(release.outputPath, packed.filename);
  const inspection = await inspectReleaseArchive(tarballPath, release.manifest);
  return Object.freeze({ tarballPath, ...inspection });
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  try {
    const { values } = parseArgs({
      options: { output: { type: "string" } },
      strict: true,
    });
    const release = await assembleRelease({ outputPath: values.output });
    const packed = await packRelease(release);
    process.stdout.write(
      JSON.stringify({ ...packed, packagePath: release.packagePath }) + "\n",
    );
  } catch (error) {
    process.stderr.write(`Release assembly failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}
