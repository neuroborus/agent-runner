import { lstat, mkdir, open, realpath, writeFile } from "node:fs/promises";
import { posix as path } from "node:path";
import { performance } from "node:perf_hooks";
import { normalizeLinuxFileBuildPins } from "./file-build.js";
import { digest } from "./inspect.js";
import {
  linuxReleaseComponentId,
  normalizeLinuxReleaseInputs,
  readLinuxReviewedFile,
} from "./release.js";

const LIMIT = 1048576;
const HASH = /^[a-f0-9]{64}$/u;
const FILES = [
  "linux-file-build.json",
  "linux-release.json",
  "linux-review.json",
];
const bytes = (value) => JSON.stringify(value) + "\n";

function requireValue(value) {
  if (!value)
    throw new Error("Missing or mismatched reviewed Linux preparation");
}

function closed(value, keys) {
  requireValue(
    value &&
      Object.getPrototypeOf(value) === Object.prototype &&
      Reflect.ownKeys(value).length === keys.length &&
      keys.every((key) => {
        const field = Object.getOwnPropertyDescriptor(value, key);
        return field?.enumerable && Object.hasOwn(field, "value");
      }),
  );
}

export function initialLinuxReviewedPreparation(candidateSha) {
  return {
    schemaVersion: 1,
    candidateSha,
    status: "NOT_RUN",
    phase: null,
    reviewSha256: null,
    missingInputs: [],
  };
}

/** Independent review supplies expected bytes and provenance, never CI output.
 * The legacy build and release-v1 inputs retain their original schemas. */
export function normalizeLinuxReviewedManifest(value, candidateSha) {
  closed(value, ["schemaVersion", "candidateSha", "build", "release", "abi"]);
  requireValue(
    typeof candidateSha === "string" &&
      /^[a-f0-9]{40}$/u.test(candidateSha) &&
      value.schemaVersion === 1 &&
      value.candidateSha === candidateSha,
  );
  const pins = normalizeLinuxFileBuildPins(value.build, candidateSha);
  const build = {
    schemaVersion: 1,
    candidateSha,
    sourceSha256: pins.sourceSha256,
    compilerVersion: pins.compilerVersion,
    inputs: pins.inputs.map(({ source, target, sha256 }) => ({
      source,
      target,
      sha256,
    })),
  };
  const input = normalizeLinuxReleaseInputs(value.release, candidateSha);
  const release = {
    schemaVersion: 1,
    candidateSha,
    buildPinsSha256: input.buildPinsSha256,
    components: input.components,
    unresolvedAssumptions: input.unresolvedAssumptions,
  };
  requireValue(release.buildPinsSha256 === digest(JSON.stringify(build)));
  requireValue(
    Array.isArray(value.abi) &&
      Object.getPrototypeOf(value.abi) === Array.prototype &&
      value.abi.length > 0 &&
      value.abi.length <= 80 &&
      Reflect.ownKeys(value.abi).length === value.abi.length + 1,
  );
  const abi = Array.from({ length: value.abi.length }, (_, index) => {
    const field = Object.getOwnPropertyDescriptor(value.abi, index);
    requireValue(field?.enumerable && Object.hasOwn(field, "value"));
    const entry = field.value;
    closed(entry, ["target", "sha256"]);
    requireValue(
      typeof entry.target === "string" &&
        entry.target.length <= 512 &&
        /^\/(?:lib(?:64)?|usr\/lib)\/[A-Za-z0-9_./+-]+$/u.test(entry.target) &&
        path.normalize(entry.target) === entry.target &&
        !entry.target.endsWith("/") &&
        typeof entry.sha256 === "string" &&
        HASH.test(entry.sha256),
    );
    return { target: entry.target, sha256: entry.sha256 };
  });
  requireValue(new Set(abi.map(({ target }) => target)).size === abi.length);
  const byName = new Map(
    release.components.map((entry) => [entry.name, entry]),
  );
  const executables = ["node", "bubblewrap", "git", "compiler", "file-helper"];
  requireValue(executables.every((name) => byName.has(name)));
  const compiler = build.inputs.find(
    ({ target }) => target === "/usr/bin/x86_64-linux-gnu-gcc-13",
  );
  requireValue(
    byName.get("compiler").sha256 === compiler.sha256 &&
      byName.get("compiler").version === build.compilerVersion &&
      byName.get("file-helper").version === "1",
  );
  const expected = [...executables];
  for (const [prefix, entries] of [
    ["build-input", build.inputs],
    ["abi", abi],
  ])
    for (const entry of entries) {
      const name = linuxReleaseComponentId(prefix, entry.target);
      expected.push(name);
      requireValue(
        byName.get(name)?.sha256 === entry.sha256 &&
          byName.get(name)?.version === "unversioned",
      );
    }
  requireValue(
    expected.length === byName.size &&
      new Set(expected).size === expected.length,
  );
  const result = { schemaVersion: 1, candidateSha, build, release, abi };
  requireValue(Buffer.byteLength(bytes(result)) <= LIMIT);
  return result;
}

export function linuxReviewedManifestDigest(value, candidateSha) {
  return digest(
    JSON.stringify(normalizeLinuxReviewedManifest(value, candidateSha)),
  );
}

/** Rejoin the complete publication to its independently approved digest before
 * build admission. Partial files or a self-reported digest cannot supply pins. */
export async function loadPreparedLinuxReviewedInputs(
  directory,
  candidateSha,
  approvedSha256,
  options,
) {
  if (!directory || !approvedSha256) return { build: null, release: null };
  requireValue(
    typeof directory === "string" &&
      directory === path.resolve(directory) &&
      typeof approvedSha256 === "string" &&
      HASH.test(approvedSha256),
  );
  const manifestBytes = await readLinuxReviewedFile(
    path.join(directory, FILES[2]),
    options,
  );
  requireValue(manifestBytes !== null);
  const manifest = normalizeLinuxReviewedManifest(
    JSON.parse(manifestBytes),
    candidateSha,
  );
  requireValue(
    linuxReviewedManifestDigest(manifest, candidateSha) === approvedSha256,
  );
  for (const [index, key] of [
    [0, "build"],
    [1, "release"],
  ]) {
    const supplied = await readLinuxReviewedFile(
      path.join(directory, FILES[index]),
      options,
    );
    requireValue(
      supplied !== null && supplied.equals(Buffer.from(bytes(manifest[key]))),
    );
  }
  return { build: manifest.build, release: manifest.release };
}

/** Explicit dedicated external preparation. No acquisition, compilation or
 * provider execution occurs here; publication is exclusive and immutable. */
export async function prepareLinuxReviewedInputs(
  candidateSha,
  directory,
  persist,
  {
    env = process.env,
    sourceFile = env.NATIVE_LINUX_REVIEW_FILE,
    approvedSha256 = env.NATIVE_LINUX_REVIEW_SHA256,
    previous,
    fs = { lstat, mkdir, open, realpath, writeFile },
    ownerUid = process.getuid,
    platform = process.platform,
    architecture = process.arch,
    now = performance.now,
  } = {},
) {
  requireValue(
    typeof candidateSha === "string" &&
      /^[a-f0-9]{40}$/u.test(candidateSha) &&
      typeof persist === "function" &&
      platform === "linux" &&
      architecture === "x64" &&
      env.CI === "true" &&
      env.GITHUB_ACTIONS === "true" &&
      env.ImageOS === "ubuntu24",
  );
  const record = initialLinuxReviewedPreparation(candidateSha);
  closed(previous, Object.keys(record));
  requireValue(
    previous.schemaVersion === 1 &&
      previous.candidateSha === candidateSha &&
      previous.status === "NOT_RUN" &&
      previous.phase === null &&
      previous.reviewSha256 === null &&
      Array.isArray(previous.missingInputs) &&
      previous.missingInputs.length === 0 &&
      Reflect.ownKeys(previous.missingInputs).length === 1,
  );
  record.status = "BLOCKED";
  if (!sourceFile) record.missingInputs.push("NATIVE_LINUX_REVIEW_FILE");
  if (!approvedSha256) record.missingInputs.push("NATIVE_LINUX_REVIEW_SHA256");
  if (!directory) record.missingInputs.push("NATIVE_REVIEWED_INPUT_DIRECTORY");
  if (record.missingInputs.length) {
    record.missingInputs.push("linux-file-build.json", "linux-release.json");
    await persist({ ...record });
    return record;
  }
  const start = now();
  const withinBudget = () => {
    const elapsed = now() - start;
    requireValue(Number.isFinite(elapsed) && elapsed >= 0 && elapsed <= 10000);
  };
  try {
    record.status = "RUNNING";
    record.phase = "review";
    await persist({ ...record });
    requireValue(
      typeof approvedSha256 === "string" && HASH.test(approvedSha256),
    );
    const source = await readLinuxReviewedFile(sourceFile, { fs, ownerUid });
    requireValue(source !== null);
    const manifest = normalizeLinuxReviewedManifest(
      JSON.parse(source),
      candidateSha,
    );
    const sha256 = linuxReviewedManifestDigest(manifest, candidateSha);
    requireValue(sha256 === approvedSha256);
    record.reviewSha256 = sha256;
    requireValue(
      typeof directory === "string" && directory === path.resolve(directory),
    );
    const root = await fs.realpath(env.RUNNER_TEMP);
    const relative = path.relative(root, directory);
    requireValue(
      relative &&
        !relative.startsWith("..") &&
        !path.isAbsolute(relative) &&
        (await fs.realpath(path.dirname(directory))) ===
          path.dirname(directory),
    );
    withinBudget();
    record.phase = "publication";
    await persist({ ...record });
    await fs.mkdir(directory, { mode: 0o700 });
    // Publish the reviewed manifest last. A partial directory cannot be read as
    // prepared, and no recovery path overwrites an earlier attempt's files.
    for (const [index, value] of [
      [0, manifest.build],
      [1, manifest.release],
      [2, manifest],
    ]) {
      withinBudget();
      await fs.writeFile(path.join(directory, FILES[index]), bytes(value), {
        flag: "wx",
        mode: 0o400,
      });
    }
    await loadPreparedLinuxReviewedInputs(
      directory,
      candidateSha,
      approvedSha256,
      { fs, ownerUid },
    );
    withinBudget();
    record.status = "PASS";
  } catch {
    record.status = "FAIL";
  }
  await persist({ ...record });
  return record;
}
