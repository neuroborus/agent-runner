import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  appendFile,
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

import {
  assembleRelease,
  packRelease,
  readReleaseFile,
} from "./assemble-release.js";
import { inspectReleaseArchive } from "./release-archive.js";
import {
  npmPublicationEnvironment,
  publishRelease,
  selectRelease,
  validateRelease,
} from "./release-policy.js";

const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const integrity = (bytes) =>
  "sha512-" + createHash("sha512").update(bytes).digest("base64");
const json = async (path) => JSON.parse(await readFile(path, "utf8"));
const REGISTRY = "https://registry.npmjs.org/";
const OUTPUT = "dist/npm-release";

function command(
  executable,
  args,
  {
    env = process.env,
    capture = false,
    allowFailure = false,
    cwd = process.cwd(),
  } = {},
) {
  const result = spawnSync(executable, args, {
    cwd,
    env,
    encoding: "utf8",
    stdio: capture ? "pipe" : "inherit",
    timeout: 20 * 60_000,
    maxBuffer: 2 * 1024 * 1024,
  });
  if (result.error || result.signal || (!allowFailure && result.status !== 0))
    throw new Error(`${executable} did not complete successfully.`);
  return result;
}

const regularBytes = async (path) => (await readReleaseFile(path)).bytes;

// Used by both the selected install suite and publication. The immutable job
// output independently binds downloaded artifacts to the validated tarball.
export async function inspectCandidate(receiptPath, expected = {}) {
  const path = resolve(receiptPath);
  const root = dirname(path);
  const receipt = JSON.parse(await regularBytes(path));
  if (
    Object.keys(receipt).sort().join() !==
      "commit,integrity,manifestSha256,name,schemaVersion,tag,tarball,version" ||
    receipt.schemaVersion !== 1 ||
    receipt.tarball !== "candidate.tgz" ||
    !/^@[a-z0-9][a-z0-9-]*\/[a-z0-9][a-z0-9-]*$/u.test(receipt.name ?? "") ||
    !/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/u.test(
      receipt.version ?? "",
    ) ||
    receipt.tag !== `v${receipt.version}` ||
    !/^[0-9a-f]{40}$/u.test(receipt.commit ?? "") ||
    !/^sha512-[A-Za-z0-9+/]{86}==$/u.test(receipt.integrity ?? "") ||
    !/^[0-9a-f]{64}$/u.test(receipt.manifestSha256 ?? "") ||
    !["commit", "tag", "name", "version", "integrity"].every(
      (key) => expected[key] === undefined || expected[key] === receipt[key],
    )
  )
    throw new Error("Release receipt does not match the validated selection.");
  const tarballPath = join(root, receipt.tarball);
  const bytes = await regularBytes(tarballPath);
  const manifestBytes = await regularBytes(join(root, "manifest.json"));
  const manifest = JSON.parse(manifestBytes);
  if (
    integrity(bytes) !== receipt.integrity ||
    hash(manifestBytes) !== receipt.manifestSha256 ||
    manifest.name !== receipt.name ||
    manifest.version !== receipt.version
  )
    throw new Error("Release artifact identity changed.");
  await inspectReleaseArchive(bytes, manifest);
  return Object.freeze({
    ...receipt,
    receiptPath: path,
    tarballPath,
    tarballBytes: bytes,
    manifest,
    manifestBytes,
  });
}

async function selection() {
  const metadata = await json("package.json");
  const policy = await json(".github/npm-release.json");
  const event = await json(process.env.GITHUB_EVENT_PATH);
  const git = (args) => command("git", args, { capture: true });
  const head = git(["rev-parse", "--verify", "HEAD"]).stdout.trim();
  // Resolve only a constructed stable tag, never an event-supplied Git option.
  if (
    !/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/u.test(
      metadata.version,
    )
  )
    throw new Error("A stable package version is required.");
  const tagHead = git([
    "rev-parse",
    "--verify",
    `refs/tags/v${metadata.version}^{commit}`,
  ]).stdout.trim();
  const ancestor = command(
    "git",
    ["merge-base", "--is-ancestor", head, "refs/remotes/origin/main"],
    { capture: true, allowFailure: true },
  );
  return selectRelease({
    policy,
    metadata,
    event,
    head,
    tagHead,
    inMain: ancestor.status === 0,
    eventName: process.env.GITHUB_EVENT_NAME,
    repository: process.env.GITHUB_REPOSITORY,
    ref: process.env.GITHUB_REF,
  });
}

async function prepare(selected) {
  const release = await assembleRelease({ outputPath: resolve(OUTPUT) });
  const packed = await packRelease(release);
  const manifestPath = join(release.outputPath, "manifest.json");
  await copyFile(
    join(release.packagePath, "release-manifest.json"),
    manifestPath,
  );
  const tarballPath = join(release.outputPath, "candidate.tgz");
  await copyFile(packed.tarballPath, tarballPath);
  const receipt = {
    schemaVersion: 1,
    commit: selected.commit,
    tag: selected.tag,
    name: selected.name,
    version: selected.version,
    tarball: "candidate.tgz",
    integrity: integrity(await regularBytes(tarballPath)),
    manifestSha256: hash(await regularBytes(manifestPath)),
  };
  const receiptPath = join(release.outputPath, "candidate.json");
  await writeFile(receiptPath, JSON.stringify(receipt, null, 2) + "\n", {
    flag: "wx",
  });
  return { ...receipt, receiptPath };
}

async function fetchBytes(url) {
  const response = await fetch(url, {
    redirect: "error",
    signal: AbortSignal.timeout(60_000),
  });
  if (response.status === 404) return null;
  if (!response.ok) throw new Error("Public registry lookup failed.");
  const chunks = [];
  let size = 0;
  for await (const chunk of response.body) {
    size += chunk.length;
    if (size > 64 * 1024 * 1024)
      throw new Error("Public registry response exceeded its bound.");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

async function readVersion(selected) {
  const bytes = await fetchBytes(
    `${REGISTRY}${encodeURIComponent(selected.name)}/${selected.version}`,
  );
  if (bytes === null) return null;
  const metadata = JSON.parse(bytes);
  if (
    metadata.name !== selected.name ||
    metadata.version !== selected.version ||
    typeof metadata.dist?.tarball !== "string" ||
    new URL(metadata.dist.tarball).origin !== new URL(REGISTRY).origin
  )
    throw new Error("Public registry returned a different package.");
  return metadata;
}

async function publish(selected) {
  const oidc = npmPublicationEnvironment(process.env);
  const npm = command("npm", ["--version"], { capture: true })
    .stdout.trim()
    .split(".")
    .map(Number);
  if (!(
    npm[0] > 11 ||
    (npm[0] === 11 && npm[1] >= 5 && (npm[1] !== 5 || npm[2] >= 1))
  ))
    throw new Error("npm >=11.5.1 is required for trusted publishing.");
  const scratch = await realpath(
    await mkdtemp(join(tmpdir(), "agent-runner-public-install-")),
  );
  const identity = await lstat(scratch);
  try {
    const userConfig = join(scratch, "user.npmrc");
    const globalConfig = join(scratch, "global.npmrc");
    for (const path of [userConfig, globalConfig])
      await writeFile(path, "", { flag: "wx", mode: 0o600 });
    const env = {
      PATH: process.env.PATH,
      HOME: join(scratch, "home"),
      TMPDIR: scratch,
      npm_config_cache: join(scratch, "cache"),
      npm_config_userconfig: userConfig,
      npm_config_globalconfig: globalConfig,
      npm_config_update_notifier: "false",
      CI: "true",
    };
    const expected = { ...selected, integrity: process.env.EXPECTED_INTEGRITY };
    if (!expected.integrity)
      throw new Error("Missing validated job artifact identity.");
    const result = await publishRelease(selected, {
      inspect: () => inspectCandidate(join(OUTPUT, "candidate.json"), expected),
      readVersion,
      publish: async (candidate) => {
        await selection();
        const archive = join(scratch, "validated.tgz");
        await writeFile(archive, candidate.tarballBytes, {
          flag: "wx",
          mode: 0o400,
        });
        command(
          "npm",
          [
            "publish",
            archive,
            "--access",
            "public",
            "--provenance",
            "--ignore-scripts",
            "--registry",
            REGISTRY,
          ],
          { env: { ...env, ...oidc }, cwd: scratch },
        );
      },
      verifyInstall: async (metadata, candidate) => {
        const bytes = await fetchBytes(metadata.dist.tarball);
        if (bytes === null || integrity(bytes) !== candidate.integrity)
          throw new Error("Public download differs from the tested tarball.");
        const archive = join(scratch, "public.tgz");
        await writeFile(archive, bytes, { flag: "wx" });
        await inspectReleaseArchive(archive, candidate.manifest);
        const prefix = join(scratch, "prefix");
        await mkdir(prefix);
        command(
          "npm",
          [
            "install",
            "--prefix",
            prefix,
            "--offline",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
            "--package-lock=false",
            "--no-save",
            archive,
          ],
          { env, cwd: scratch },
        );
        const installed = join(prefix, "node_modules", selected.name);
        if (
          !(await readFile(join(installed, "release-manifest.json"))).equals(
            candidate.manifestBytes,
          ) ||
          !((await lstat(join(installed, "bin/agent-run.js"))).mode & 0o100)
        )
          throw new Error("The public package did not install completely.");
      },
    });
    await appendFile(
      process.env.GITHUB_STEP_SUMMARY,
      `Release result: ${result.status}\n\n${selected.releaseUrl}\n\n${selected.npmUrl}\n\n${result.reason ?? "The anonymous public download and isolated installation match the tested archive."}\n`,
    );
    if (result.status === "partial_failure") throw new Error(result.reason);
  } finally {
    const current = await lstat(scratch);
    if (
      current.dev !== identity.dev ||
      current.ino !== identity.ino ||
      (await realpath(scratch)) !== scratch
    )
      throw new Error(
        "Public-install fixture identity changed; storage was preserved.",
      );
    await rm(scratch, { recursive: true });
  }
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  try {
    const [mode, ...extra] = process.argv.slice(2);
    if (!["validate", "publish"].includes(mode) || extra.length)
      throw new Error("Expected validate or publish.");
    const selected = await selection();
    if (mode === "publish") await publish(selected);
    else
      await validateRelease(selected, {
        prepare,
        run: async (args, env) => {
          command("npm", args, { env: { ...process.env, ...env } });
        },
        inspect: inspectCandidate,
        seal: async (candidate) => {
          await appendFile(
            process.env.GITHUB_OUTPUT,
            `integrity=${candidate.integrity}\n`,
          );
        },
      });
  } catch (error) {
    process.stderr.write(`Release failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}
