import { createHash } from "node:crypto";
import {
  lstat,
  mkdir,
  open,
  readFile,
  realpath,
  writeFile,
} from "node:fs/promises";
import { constants } from "node:fs";
import path from "node:path";
import { performance } from "node:perf_hooks";
import {
  observationDigest,
  observationObject,
  requireObservation,
} from "./observation.js";
import { normalizeReleaseClosure, releaseClosureDigest } from "./closure.js";
import { sourceReviewDigest, admitNativeSourceReview } from "./evidence.js";
import { admitCompositionPlan } from "./composition-plan.js";
import {
  normalizeNativePrerequisites,
  NATIVE_PREREQUISITE_LIMITS,
  prerequisitePreparationBound,
  materializeBootstrapAssets,
  materializePrerequisitePackages,
  persistPrerequisiteRecord,
} from "./prerequisites.js";
import {
  assertNativePreparationInputs,
  nativePreparationError,
  nativeFailureDetails,
} from "./first-failure.js";

const hash = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const authority = (candidateSha, platform, manifestSha256) => ({
  candidateSha,
  platform,
  manifestSha256,
  authority: "operator-protected",
});
export const systemPreparationBound = (profile) =>
  60000 +
  (profile.platform
    ? prerequisitePreparationBound(
        profile.platform,
        profile.sources,
        profile.platform === "linux" ? 0 : (profile.recipes?.().length ?? 0),
      )
    : 0) +
  profile.tools.length * 30000 +
  (profile.compileBound ??
    profile.sources.length * (profile.sign ? 60000 : 30000));

async function capability(bundle) {
  return import(
    `data:text/javascript;base64,${bundle.capabilityBytes.toString("base64")}`
  );
}

/** Credential-free, data-only acquisition from a fixed public GitHub revision.
 * Approval is an independently configured digest, never a downloaded status.
 * Private helpers and SDK installation remain the platform's native custody. */
export async function acquireSystemCIInputs(
  job,
  profile,
  directory,
  {
    env = process.env,
    fetchInput = fetch,
    fs = { mkdir, writeFile },
    verify = readSystemCIMetadata,
    signal,
    templateReviews = [],
  } = {},
) {
  assertNativePreparationInputs(job, env);
  requireObservation(
    env.CI === "true" &&
      env.GITHUB_ACTIONS === "true" &&
      /^[a-f0-9]{40}$/u.test(job.candidateSha) &&
      ["linux", "darwin", "win32"].includes(job.platform) &&
      directory ===
        path.resolve(env.RUNNER_TEMP, `native-${job.platform}-reviewed`) &&
      /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(
        env.NATIVE_SYSTEM_INPUT_REPOSITORY,
      ) &&
      /^[a-f0-9]{40}$/u.test(env.NATIVE_SYSTEM_INPUT_REVISION) &&
      hash(env.NATIVE_SYSTEM_REVIEW_SHA256),
  );
  const root = `https://raw.githubusercontent.com/${env.NATIVE_SYSTEM_INPUT_REPOSITORY}/${env.NATIVE_SYSTEM_INPUT_REVISION}/ci/native/reviews/${job.candidateSha}/${job.platform}/`;
  const download = async (name) => {
    const response = await fetchInput(root + name, {
      redirect: "error",
      signal: signal
        ? AbortSignal.any([signal, AbortSignal.timeout(10000)])
        : AbortSignal.timeout(10000),
      credentials: "omit",
    });
    if (!response.ok)
      throw nativePreparationError("acquisition", [
        { id: name, diagnosis: "missing" },
      ]);
    const chunks = [];
    let size = 0;
    for await (const chunk of response.body) {
      size += chunk.length;
      if (
        size >
        (name === "system-inputs.json"
          ? NATIVE_PREREQUISITE_LIMITS.metadataBytes
          : 2097152)
      )
        throw nativePreparationError("acquisition", [
          { id: name, diagnosis: "malformed" },
        ]);
      chunks.push(chunk);
    }
    if (!size)
      throw nativePreparationError("acquisition", [
        { id: name, diagnosis: "missing" },
      ]);
    return Buffer.concat(chunks);
  };
  // Neither source nor approval is guessed from the current runner image.
  const manifestBytes = await download("system-inputs.json");
  let manifest;
  try {
    manifest = JSON.parse(manifestBytes);
  } catch {
    throw nativePreparationError("review", [
      { id: "system-inputs.json", diagnosis: "malformed" },
    ]);
  }
  if (!(
    manifest &&
    manifest.candidateSha === job.candidateSha &&
    manifest.platform === job.platform &&
    observationDigest(manifest) === env.NATIVE_SYSTEM_REVIEW_SHA256 &&
    hash(manifest.capabilitySha256)
  ))
    throw nativePreparationError("review", [
      { id: "system-inputs.json", diagnosis: "malformed" },
    ]);
  const capabilityBytes = await download("native-effects.mjs");
  if (digest(capabilityBytes) !== manifest.capabilitySha256)
    throw nativePreparationError("review", [
      { id: "native-effects.mjs", diagnosis: "malformed" },
    ]);
  requireObservation(!signal?.aborted);
  await fs.mkdir(directory, { mode: 0o700 });
  await fs.writeFile(
    path.join(directory, "system-inputs.json"),
    manifestBytes,
    { flag: "wx", mode: 0o400 },
  );
  await fs.writeFile(
    path.join(directory, "native-effects.mjs"),
    capabilityBytes,
    { flag: "wx", mode: 0o400 },
  );
  try {
    await verify(job, profile, directory, env, { templateReviews });
  } catch {
    throw nativePreparationError("review", [
      { id: "system-inputs.json", diagnosis: "malformed" },
    ]);
  }
  requireObservation(!signal?.aborted);
  if (job.platform === "linux") {
    const linuxReview = await download("linux-review.json");
    try {
      profile.verifyLegacy(JSON.parse(linuxReview), env, job, manifest);
    } catch {
      throw nativePreparationError("review", [
        { id: "linux-review.json", diagnosis: "malformed" },
      ]);
    }
    const legacy = path.resolve(env.RUNNER_TEMP, "native-linux-provision");
    await fs.mkdir(legacy, { mode: 0o700 });
    await fs.writeFile(path.join(legacy, "linux-review.json"), linuxReview, {
      flag: "wx",
      mode: 0o400,
    });
  }
}

/** Timeout fences the controller, never supplies native retirement. Unsettled
 * work remains POSSIBLE in its persisted receipt for independent recovery. */
export async function boundSystemEffect(operation, deadlineMs, parentSignal) {
  requireObservation(Number.isSafeInteger(deadlineMs) && deadlineMs > 0);
  const controller = new AbortController();
  const signal = parentSignal
    ? AbortSignal.any([controller.signal, parentSignal])
    : controller.signal;
  let rejectDeadline;
  const deadline = new Promise((_, reject) => {
    rejectDeadline = reject;
  });
  const stop = () => rejectDeadline(nativePreparationError("deadline"));
  const timer = setTimeout(() => controller.abort(), deadlineMs);
  signal.addEventListener("abort", stop, { once: true });
  try {
    requireObservation(!signal.aborted);
    return await Promise.race([
      Promise.resolve().then(() => {
        requireObservation(!signal.aborted);
        return operation(signal);
      }),
      deadline,
    ]);
  } finally {
    clearTimeout(timer);
    signal.removeEventListener("abort", stop);
    controller.abort();
  }
}

/** A fixed, independently reviewed single-file native capability is external
 * provisioning, never a CLI-selected plugin or an observed approval. Its bytes
 * are imported from memory; native proofs still use the platform's validators. */
export async function readSystemCIInputs(
  job,
  profile,
  directory,
  env = process.env,
  { verifyFiles = true, templateReviews = [] } = {},
) {
  const root = path.resolve(env.RUNNER_TEMP, `native-${job.platform}-reviewed`);
  requireObservation(directory === root && (await realpath(root)) === root);
  const read = async (file, maximum = 2097152) => {
    requireObservation(
      (await realpath(file)) === file &&
        (await realpath(path.dirname(file))) === path.dirname(file),
    );
    const handle = await open(
      file,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
    );
    try {
      const before = await handle.stat({ bigint: true });
      requireObservation(
        before.isFile() &&
          before.nlink === 1n &&
          before.size >= 0n &&
          before.size <= BigInt(maximum),
      );
      const bytes = Buffer.alloc(Number(before.size) + 1);
      let offset = 0;
      while (offset < bytes.length) {
        const result = await handle.read(
          bytes,
          offset,
          bytes.length - offset,
          offset,
        );
        if (!result.bytesRead) break;
        offset += result.bytesRead;
      }
      const after = await handle.stat({ bigint: true }),
        named = await lstat(file, { bigint: true });
      requireObservation(
        offset === Number(before.size) &&
          named.isFile() &&
          ["dev", "ino", "mode", "size", "nlink", "mtimeNs", "ctimeNs"].every(
            (key) => before[key] === after[key] && before[key] === named[key],
          ) &&
          (await realpath(file)) === file,
      );
      return bytes.subarray(0, offset);
    } finally {
      await handle.close();
    }
  };
  const manifest = JSON.parse(
    await read(
      path.join(root, "system-inputs.json"),
      NATIVE_PREREQUISITE_LIMITS.metadataBytes,
    ),
  );
  const admission = admitSystemCIManifest(
    job,
    profile,
    manifest,
    env,
    templateReviews,
  );
  const capabilityBytes = await read(path.join(root, "native-effects.mjs"));
  requireObservation(digest(capabilityBytes) === manifest.capabilitySha256);
  const bundle = { manifest, ...admission, read, capabilityBytes };
  bundle.verify = () => verifySystemCIInputFiles(job, profile, bundle);
  if (verifyFiles) await bundle.verify();
  return bundle;
}

/** Metadata admission has no host reads or executable effects. */
export function admitSystemCIManifest(
  job,
  profile,
  manifest,
  env,
  templateReviews = [],
) {
  observationObject(manifest, [
    "schemaVersion",
    "candidateSha",
    "platform",
    "source",
    "release",
    "execution",
    "tools",
    "inputs",
    "helpers",
    "environment",
    "capabilitySha256",
    ...(profile.fields ?? []),
    ...(manifest.schemaVersion === 2 ? ["prerequisites"] : []),
  ]);
  requireObservation(
    [1, 2].includes(manifest.schemaVersion) &&
      manifest.candidateSha === job.candidateSha &&
      manifest.platform === job.platform &&
      hash(env.NATIVE_SYSTEM_REVIEW_SHA256) &&
      observationDigest(manifest) === env.NATIVE_SYSTEM_REVIEW_SHA256 &&
      hash(manifest.capabilitySha256),
  );
  const release = normalizeReleaseClosure(manifest.release);
  requireObservation(
    release.candidateSha === job.candidateSha &&
      release.platform === job.platform,
  );
  const reviews = {
    source: authority(
      job.candidateSha,
      null,
      sourceReviewDigest(manifest.source),
    ),
    release: authority(
      job.candidateSha,
      job.platform,
      releaseClosureDigest(release),
    ),
  };
  admitNativeSourceReview(manifest.source, reviews.source);
  requireObservation(
    manifest.source.citations.some(
      (citation) =>
        citation.kind === "reached-code" &&
        citation.member.split("/").at(-1) === "native-effects.mjs" &&
        citation.sha256 === manifest.capabilitySha256,
    ),
  );
  const executionAuthority = authority(
    job.candidateSha,
    job.platform,
    observationDigest(manifest.execution),
  );
  admitCompositionPlan(
    { ...job, reviews: { ...job.reviews, ...reviews } },
    profile.recipes(),
    manifest.execution,
    executionAuthority,
    manifest.source,
    templateReviews,
  );
  requireObservation(
    Array.isArray(manifest.helpers) &&
      manifest.helpers.length === profile.sources.length &&
      new Set(manifest.helpers.map(({ name }) => name)).size ===
        profile.sources.length,
  );
  for (const name of profile.sources) {
    const helper = manifest.helpers.find((entry) => entry.name === name);
    observationObject(helper, ["name", "sourceSha256", "sha256"]);
    requireObservation(hash(helper.sourceSha256) && hash(helper.sha256));
  }
  requireObservation(
    Array.isArray(manifest.tools) &&
      manifest.tools.length === profile.tools.length &&
      new Set(manifest.tools.map(({ name }) => name)).size ===
        profile.tools.length,
  );
  for (const tool of manifest.tools) {
    observationObject(tool, [
      "name",
      "path",
      "sha256",
      "version",
      ...(manifest.schemaVersion === 2 ? ["bytes"] : []),
    ]);
    const expected = profile.tools.find(({ name }) => name === tool.name);
    requireObservation(
      expected &&
        expected.path.test(tool.path) &&
        hash(tool.sha256) &&
        typeof tool.version === "string" &&
        /^[\x20-\x7e]{1,256}$/u.test(tool.version),
    );
    if (manifest.schemaVersion === 2)
      requireObservation(
        Number.isSafeInteger(tool.bytes) &&
          tool.bytes > 0 &&
          tool.bytes <= NATIVE_PREREQUISITE_LIMITS.assetBytes,
      );
  }
  requireObservation(
    Array.isArray(manifest.inputs) &&
      manifest.inputs.length > 0 &&
      manifest.inputs.length <=
        (manifest.schemaVersion === 2
          ? NATIVE_PREREQUISITE_LIMITS.inputMembers
          : 600),
  );
  for (const entry of manifest.inputs)
    observationObject(entry, [
      "path",
      "sha256",
      ...(manifest.schemaVersion === 2 ? ["bytes"] : []),
    ]);
  const paths = new Set();
  let total = 0;
  for (const entry of [...manifest.inputs, ...manifest.tools]) {
    requireObservation(
      (manifest.platform === "win32" ? path.win32 : path.posix).isAbsolute(
        entry.path,
      ) &&
        (manifest.platform === "win32" ? path.win32 : path.posix).normalize(
          entry.path,
        ) === entry.path &&
        !paths.has(entry.path.toLowerCase()) &&
        hash(entry.sha256),
    );
    paths.add(entry.path.toLowerCase());
    if (manifest.schemaVersion === 2) {
      requireObservation(
        Number.isSafeInteger(entry.bytes) &&
          entry.bytes >= 0 &&
          entry.bytes <= NATIVE_PREREQUISITE_LIMITS.inputBytes,
      );
      total += entry.bytes;
      requireObservation(total <= NATIVE_PREREQUISITE_LIMITS.inputTotalBytes);
    }
  }
  observationObject(manifest.environment, profile.environment);
  for (const value of Object.values(manifest.environment))
    requireObservation(
      typeof value === "string" &&
        value.length > 0 &&
        value.length <= 32768 &&
        !/[\x00-\x1f]/u.test(value),
    );
  profile.validate?.(manifest);
  if (manifest.schemaVersion === 2)
    normalizeNativePrerequisites(manifest.prerequisites, manifest, profile);
  return { reviews, authority: executionAuthority };
}

export const readSystemCIMetadata = (
  job,
  profile,
  directory,
  env,
  options = {},
) =>
  readSystemCIInputs(job, profile, directory, env, {
    ...options,
    verifyFiles: false,
  });

export async function verifySystemCIInputFiles(
  job,
  profile,
  { manifest, read },
) {
  for (const helper of manifest.helpers)
    requireObservation(
      digest(
        await read(
          path.resolve(`ci/native/${job.platform}/${helper.name}.c`),
          1048576,
        ),
      ) === helper.sourceSha256,
    );
  let total = 0;
  for (const entry of [...manifest.inputs, ...manifest.tools]) {
    const maximum =
      manifest.schemaVersion === 2 ? Math.max(1, entry.bytes) : 134217728;
    const bytes = await read(entry.path, maximum);
    total += bytes.length;
    requireObservation(
      digest(bytes) === entry.sha256 &&
        (manifest.schemaVersion !== 2 || bytes.length === entry.bytes) &&
        total <=
          (manifest.schemaVersion === 2
            ? NATIVE_PREREQUISITE_LIMITS.inputTotalBytes
            : 1073741824),
    );
  }
}

export function initialSystemPreparation(job) {
  return {
    schemaVersion: 1,
    candidateSha: job.candidateSha,
    platform: job.platform,
    reviewSha256: null,
    status: "NOT_RUN",
    phase: null,
    versions: [],
    helpers: [],
    commands: [],
  };
}

export function normalizeSystemPreparation(value, job) {
  observationObject(value, [
    "schemaVersion",
    "candidateSha",
    "platform",
    "reviewSha256",
    "status",
    "phase",
    "versions",
    "helpers",
    "commands",
  ]);
  requireObservation(
    [1, 2].includes(value.schemaVersion) &&
      value.candidateSha === job.candidateSha &&
      value.platform === job.platform &&
      (value.reviewSha256 === null || hash(value.reviewSha256)) &&
      ["NOT_RUN", "RUNNING", "FAIL", "PASS"].includes(value.status) &&
      [
        null,
        "review",
        "native-bootstrap",
        "bootstrap-assets",
        "packages",
        "toolchain",
        "build",
        "verification",
      ].includes(value.phase),
  );
  for (const [key, maximum] of [
    ["versions", 3],
    ["helpers", job.platform === "win32" ? 13 : 10],
    // Largest fixed inventory: 14 images, 15 sources/headers, 38 custody plans,
    // bootstrap, two tool queries, 13 builds, three packages and verification.
    [
      "commands",
      value.schemaVersion === 2 ? 14 + 15 + 38 + 1 + 2 + 13 + 3 + 1 : 32,
    ],
  ])
    requireObservation(
      Array.isArray(value[key]) && value[key].length <= maximum,
    );
  for (const entry of value.versions) {
    observationObject(entry, ["name", "version", "sha256"]);
    requireObservation(
      ["compiler", "sdk", "signer"].includes(entry.name) &&
        typeof entry.version === "string" &&
        /^[\x20-\x7e]{1,256}$/u.test(entry.version) &&
        hash(entry.sha256),
    );
  }
  for (const entry of value.helpers) {
    observationObject(entry, ["name", "sha256"]);
    requireObservation(
      typeof entry.name === "string" &&
        /^[a-z][a-z-]{0,63}$/u.test(entry.name) &&
        hash(entry.sha256),
    );
  }
  for (const list of [value.versions, value.helpers])
    requireObservation(
      new Set(list.map(({ name }) => name)).size === list.length,
    );
  for (const entry of value.commands) {
    observationObject(entry, ["requestSha256", "status", "receiptSha256"]);
    requireObservation(
      hash(entry.requestSha256) &&
        ["POSSIBLE", "RETIRED"].includes(entry.status) &&
        (entry.status === "RETIRED"
          ? hash(entry.receiptSha256)
          : entry.receiptSha256 === null),
    );
  }
  if (value.status === "PASS")
    requireObservation(
      value.phase === "verification" &&
        hash(value.reviewSha256) &&
        value.helpers.length > 0 &&
        value.versions.length >= 2 &&
        value.commands.length >= 2 &&
        value.commands.every(({ status }) => status === "RETIRED"),
    );
  return structuredClone(value);
}

/** Dedicated external CI phase. No compiler, signer or native capability runs
 * during ordinary imports/tests. Expected output hashes precede compilation. */
export async function prepareSystemCI(
  job,
  profile,
  root,
  output,
  persist,
  {
    env = process.env,
    platform = process.platform,
    inputs = readSystemCIMetadata,
    loadCapability = capability,
    now = () => performance.now(),
    fs = { mkdir, readFile, lstat },
    onFailure = async () => {},
    fetchInput = fetch,
    preparePackage,
    templateReviews = [],
  } = {},
) {
  requireObservation(
    env.CI === "true" &&
      env.GITHUB_ACTIONS === "true" &&
      platform === job.platform &&
      process.arch === "x64" &&
      profile.imageOS.test(env.ImageOS) &&
      typeof persist === "function",
  );
  const record = initialSystemPreparation(job);
  const start = now();
  const maximumMs = systemPreparationBound(profile);
  const lifetime = new AbortController();
  const preparationSignal = AbortSignal.any([
    lifetime.signal,
    AbortSignal.timeout(maximumMs),
  ]);
  const remaining = () => {
    const left = maximumMs - Math.ceil(now() - start);
    requireObservation(left > 0);
    return left;
  };
  const phase = async (value) => {
    record.status = "RUNNING";
    record.phase = value;
    await persist(structuredClone(record));
  };
  try {
    await phase("review");
    const bundle = await boundSystemEffect(
      () => inputs(job, profile, root, env, { templateReviews }),
      remaining(),
    );
    const { manifest } = bundle;
    record.reviewSha256 = env.NATIVE_SYSTEM_REVIEW_SHA256;
    if (manifest.schemaVersion === 2) record.schemaVersion = 2;
    else await bundle.verify?.();
    await fs.mkdir(output, { mode: 0o700 });
    const module = await boundSystemEffect(
      () => loadCapability(bundle),
      remaining(),
    );
    requireObservation(typeof module.createBuildEffects === "function");
    const api = await profile.api();
    let prerequisiteEffects, bootstrapEntry, bootstrapRequest;
    const possible = async (request) => {
      const entry = {
        requestSha256: observationDigest(request),
        status: "POSSIBLE",
        receiptSha256: null,
      };
      record.commands.push(entry);
      await persist(structuredClone(record));
      return async (receiptSha256) => {
        requireObservation(hash(receiptSha256));
        entry.status = "RETIRED";
        entry.receiptSha256 = receiptSha256;
        await persist(structuredClone(record));
      };
    };
    const prerequisites =
      manifest.schemaVersion === 2
        ? normalizeNativePrerequisites(
            manifest.prerequisites,
            manifest,
            profile,
          )
        : null;
    if (prerequisites) {
      await phase("bootstrap-assets");
      requireObservation(
        typeof module.createPrerequisiteEffects === "function",
      );
      prerequisiteEffects = await boundSystemEffect(
        () =>
          module.createPrerequisiteEffects({
            job: structuredClone(job),
            manifest: structuredClone(manifest),
            api,
          }),
        remaining(),
        preparationSignal,
      );
      await boundSystemEffect(
        (signal) =>
          materializeBootstrapAssets(prerequisites, {
            env,
            fetchInput,
            effects: prerequisiteEffects,
            persist: possible,
            read: bundle.read,
            signal,
          }),
        remaining(),
        preparationSignal,
      );
    }
    await phase("native-bootstrap");
    if (prerequisites) {
      const request = {
        schemaVersion: 1,
        candidateSha: job.candidateSha,
        platform: job.platform,
        phase: "native-bootstrap",
        assets: prerequisites.assets,
        preparation:
          manifest.darwinPreparation ?? manifest.windowsPreparation ?? null,
        prerequisiteSha256: observationDigest(prerequisites),
        output,
      };
      bootstrapRequest = request;
      bootstrapEntry = await possible(request);
      await persistPrerequisiteRecord(prerequisiteEffects, {
        request,
        requestSha256: observationDigest(request),
        status: "POSSIBLE",
      });
    }
    const buildEffects = await boundSystemEffect(
      () =>
        module.createBuildEffects({
          job: structuredClone(job),
          output,
          manifest: structuredClone(manifest),
          api,
          signal: preparationSignal,
        }),
      remaining(),
      preparationSignal,
    );
    requireObservation(typeof buildEffects?.run === "function");
    if (prerequisites) {
      requireObservation(typeof buildEffects.bootstrap === "function");
      // A held reader outlives bootstrap admission. Its work signal remains
      // valid through the first command's independent retirement, rather than
      // being canceled when the admission operation returns.
      await boundSystemEffect(
        () => buildEffects.bootstrap(preparationSignal),
        remaining(),
        preparationSignal,
      );
    }
    const environment = {
      CI: "true",
      GITHUB_ACTIONS: "true",
      LANG: "C",
      ...manifest.environment,
    };
    const command = async (file, args, maximum = 30000) => {
      const timeout = Math.min(maximum, maximumMs - Math.ceil(now() - start));
      requireObservation(timeout > 0);
      const tool = manifest.tools.find((entry) => entry.path === file);
      requireObservation(
        tool &&
          digest(await bundle.read(file, tool.bytes ?? 134217728)) ===
            tool.sha256,
      );
      const request = {
        candidateSha: job.candidateSha,
        platform: job.platform,
        toolSha256: tool.sha256,
        file,
        args,
        cwd: output,
        env: environment,
        deadlineMs: timeout,
      };
      const requestSha256 = observationDigest(request);
      const entry = { requestSha256, status: "POSSIBLE", receiptSha256: null };
      record.commands.push(entry);
      await persist(structuredClone(record));
      const result = await boundSystemEffect(
        (signal) => buildEffects.run(request, { signal }),
        timeout,
      );
      requireObservation(
        result?.requestSha256 === requestSha256 &&
          result.toolSha256 === tool.sha256 &&
          hash(result.nativeEventSha256) &&
          result.independent === true &&
          result.settlement?.status === "RETIRED" &&
          result.settlement.independent === true &&
          result.settlement.emergencyCleanup === false &&
          Number.isSafeInteger(result.exitCode) &&
          result.exitCode >= 0 &&
          result.exitCode <= 255 &&
          result.signal === null &&
          result.timedOut === false &&
          typeof result.stdout === "string" &&
          typeof result.stderr === "string" &&
          Buffer.byteLength(result.stdout) + Buffer.byteLength(result.stderr) <=
            65536,
      );
      profile.inspectProcess(result.identity);
      entry.status = "RETIRED";
      entry.receiptSha256 = observationDigest(result);
      await persist(structuredClone(record));
      return result;
    };
    await phase("toolchain");
    for (const expected of profile.tools) {
      const tool = manifest.tools.find(({ name }) => name === expected.name);
      requireObservation(
        digest(await bundle.read(tool.path, 134217728)) === tool.sha256,
      );
      let version;
      if (expected.versionByDigest) {
        version = `sha256:${digest(await bundle.read(tool.path, 134217728))}`;
      } else {
        const result = await command(tool.path, expected.args);
        requireObservation(
          result.exitCode === 0 ||
            expected.versionExitCodes.includes(result.exitCode),
        );
        version = (result.stdout + result.stderr).trim().split(/\r?\n/u)[0];
      }
      requireObservation(version === tool.version);
      requireObservation(
        digest(await bundle.read(tool.path, 134217728)) === tool.sha256,
      );
      record.versions.push({
        name: expected.name,
        version,
        sha256: tool.sha256,
      });
    }
    await phase("build");
    for (const name of profile.sources) {
      const pin = manifest.helpers.find((entry) => entry.name === name);
      const checkedSource = path.resolve(`ci/native/${job.platform}/${name}.c`);
      requireObservation(
        digest(await fs.readFile(checkedSource)) === pin.sourceSha256,
      );
      const source = profile.source?.(manifest, name) ?? checkedSource;
      if (source !== checkedSource)
        requireObservation(
          digest(await fs.readFile(source)) === pin.sourceSha256,
        );
      const target =
        profile.target?.(output, name) ??
        path.join(output, name + profile.extension);
      const compiler = manifest.tools.find(({ name }) => name === "compiler");
      if (profile.compile) {
        const entry = {
          requestSha256: observationDigest({
            candidateSha: job.candidateSha,
            output,
            helper: pin,
            reviewSha256: record.reviewSha256,
          }),
          status: "POSSIBLE",
          receiptSha256: null,
        };
        record.commands.push(entry);
        await persist(structuredClone(record));
        const built = await boundSystemEffect(
          () => profile.compile(job, output, manifest),
          remaining(),
        );
        requireObservation(
          built?.settlement?.status === "RETIRED" &&
            built.settlement.independent === true &&
            built.settlement.emergencyCleanup === false,
        );
        entry.status = "RETIRED";
        entry.receiptSha256 = observationDigest(built);
        await persist(structuredClone(record));
      } else {
        const result = await command(
          compiler.path,
          profile.arguments(source, target, manifest.environment),
          profile.compileCommandMs ?? 30000,
        );
        requireObservation(result.exitCode === 0);
      }
      if (profile.sign) {
        const signer = manifest.tools.find(({ name }) => name === "signer");
        const result = await command(signer.path, [
          "--force",
          "--sign",
          "-",
          "--timestamp=none",
          target,
        ]);
        requireObservation(result.exitCode === 0);
      }
      const metadata = await fs.lstat(target);
      requireObservation(
        metadata.isFile() &&
          metadata.nlink === 1 &&
          metadata.size > 0 &&
          metadata.size <= 134217728,
      );
      const bytes = await fs.readFile(target);
      requireObservation(digest(bytes) === pin.sha256);
      profile.inspect(bytes);
      record.helpers.push({ name, sha256: pin.sha256 });
      await persist(structuredClone(record));
    }
    if (prerequisites) {
      await phase("packages");
      await boundSystemEffect(
        (signal) =>
          materializePrerequisitePackages(prerequisites, {
            effects: prerequisiteEffects,
            persist: possible,
            signal,
            preparePackage,
          }),
        remaining(),
      );
      await phase("verification");
      const request = {
        schemaVersion: 1,
        candidateSha: job.candidateSha,
        platform: job.platform,
        phase: "verification",
        prerequisites,
        inputs: manifest.inputs,
        tools: manifest.tools,
        bootstrapRequest,
        preparationSha256: observationDigest(record),
      };
      requireObservation(
        typeof prerequisiteEffects.verifyInputs === "function",
      );
      const verificationEntry = await possible(request);
      await persistPrerequisiteRecord(prerequisiteEffects, {
        request,
        requestSha256: observationDigest(request),
        status: "POSSIBLE",
      });
      const observed = await boundSystemEffect(
        (signal) =>
          prerequisiteEffects.verifyInputs(structuredClone(request), {
            signal,
          }),
        remaining(),
      );
      requireObservation(
        observed?.requestSha256 === observationDigest(request) &&
          observed.bootstrapRequestSha256 ===
            observationDigest(bootstrapRequest) &&
          observed.independent === true &&
          observed.complete === true &&
          observed.held === true &&
          observed.protectedParents === true &&
          observed.unchanged === true &&
          observed.bootstrapRetired === true &&
          observed.noLiveMembers === true &&
          observed.emergencyCleanup === false &&
          hash(observed.nativeEventSha256),
      );
      await boundSystemEffect(() => bundle.verify(), remaining());
      for (const retiredRequest of [bootstrapRequest, request])
        await persistPrerequisiteRecord(prerequisiteEffects, {
          request: retiredRequest,
          requestSha256: observationDigest(retiredRequest),
          status: "RETIRED",
          receiptSha256: observationDigest(observed),
        });
      await bootstrapEntry(observationDigest(observed));
      await verificationEntry(observationDigest(observed));
    }
    requireObservation(
      now() - start <= maximumMs &&
        record.commands.every(({ status }) => status === "RETIRED"),
    );
    record.phase = "verification";
    record.status = "PASS";
  } catch (error) {
    record.status = "FAIL";
    await onFailure(nativeFailureDetails(error, record.phase ?? "review"));
  } finally {
    lifetime.abort();
  }
  await persist(structuredClone(record));
  return record;
}

/** The fixed native-effect package is reviewed and immutable in memory. Native
 * admission/retirement and held-image reads remain owned by the platform index. */
export async function loadSystemCI(
  job,
  profile,
  root,
  directory,
  receipt,
  env = process.env,
  { recovery = false, templateReviews = [] } = {},
) {
  requireObservation(
    env.CI === "true" &&
      env.GITHUB_ACTIONS === "true" &&
      process.platform === job.platform &&
      process.arch === "x64" &&
      profile.imageOS.test(env.ImageOS),
  );
  receipt = normalizeSystemPreparation(receipt, job);
  requireObservation(
    (recovery
      ? ["RUNNING", "FAIL", "PASS"].includes(receipt.status)
      : receipt.status === "PASS") &&
      receipt.candidateSha === job.candidateSha &&
      receipt.platform === job.platform &&
      receipt.reviewSha256 === env.NATIVE_SYSTEM_REVIEW_SHA256,
  );
  const bundle = await readSystemCIInputs(job, profile, root, env, {
    verifyFiles: !recovery,
    templateReviews,
  });
  if (recovery && bundle.manifest.schemaVersion === 2)
    for (const asset of bundle.manifest.prerequisites.assets)
      requireObservation(
        digest(await bundle.read(asset.path, asset.bytes)) === asset.sha256,
      );
  const output = path.join(directory, "platform-build");
  requireObservation(
    recovery || receipt.helpers.length === profile.sources.length,
  );
  for (const version of receipt.versions)
    requireObservation(
      bundle.manifest.tools.some(
        (tool) =>
          tool.name === version.name &&
          tool.version === version.version &&
          tool.sha256 === version.sha256,
      ),
    );
  requireObservation(
    recovery || receipt.versions.length === profile.tools.length,
  );
  for (const entry of receipt.helpers) {
    const pin = bundle.manifest.helpers.find(
      (value) => value.name === entry.name && value.sha256 === entry.sha256,
    );
    requireObservation(pin);
    if (recovery && profile.recoveryFromBootstrap) continue;
    const target =
      profile.target?.(output, pin.name) ??
      path.join(output, pin.name + profile.extension);
    requireObservation(
      digest(await bundle.read(target, 134217728)) === pin.sha256,
    );
  }
  // data: imports cannot resolve a mutable relative dependency tree. Approved
  // capability source must be self-contained; repository APIs are supplied.
  const module = await capability(bundle);
  requireObservation(typeof module.createSystemEffects === "function");
  const effects = await module.createSystemEffects({
    job: structuredClone(job),
    directory,
    helpers: output,
    recovery,
    preparation: structuredClone(receipt),
    manifest: structuredClone(bundle.manifest),
    api: await profile.api(),
  });
  requireObservation(
    typeof effects?.prepare === "function" &&
      typeof effects.settle === "function" &&
      typeof effects.recover === "function" &&
      typeof effects.verifyBuild === "function",
  );
  // Probe's build case verifies the already-built private artifacts; it cannot
  // compile a second time or supply different unreviewed source/output bytes.
  effects.build = async ({
    candidateSha,
    reviewSha256,
    signal,
    policyBinding,
    recordPolicy,
  }) => {
    requireObservation(candidateSha === job.candidateSha);
    const observed = await effects.verifyBuild(structuredClone(receipt), {
      signal,
      policyBinding,
      recordPolicy,
    });
    requireObservation(
      observed?.independent === true &&
        observed.status === "OBSERVED" &&
        observed.candidateSha === candidateSha &&
        observed.preparationSha256 === observationDigest(receipt) &&
        hash(observed.nativeEventSha256) &&
        observed.settlement?.status === "RETIRED" &&
        observed.settlement.independent === true &&
        observed.settlement.emergencyCleanup === false,
    );
    return { ...observed, reviewSha256 };
  };
  return { ...bundle, effects };
}

/** Fresh recovery covers the exact preparation and execution ledgers, including
 * partial builds. It never repairs a failed or uncertain proof record. */
export async function recoverSystemCI(
  job,
  prepared,
  preparation,
  deadlineMs,
  persist,
) {
  preparation = normalizeSystemPreparation(preparation, job);
  const request = {
    candidateSha: job.candidateSha,
    platform: job.platform,
    reviewSha256: preparation.reviewSha256,
    preparationSha256: observationDigest(preparation),
    jobSha256: observationDigest(job),
    deadlineMs,
  };
  const requestSha256 = observationDigest(request);
  await persist({
    ...request,
    requestSha256,
    status: "POSSIBLE",
    receiptSha256: null,
  });
  const observed = await boundSystemEffect(
    (signal) =>
      prepared.effects.recover({
        request,
        job: structuredClone(job),
        preparation: structuredClone(preparation),
        signal,
      }),
    deadlineMs,
  );
  observationObject(observed, [
    "requestSha256",
    "nativeEventSha256",
    "status",
    "independent",
    "emergencyCleanup",
  ]);
  requireObservation(
    observed.requestSha256 === requestSha256 &&
      hash(observed.nativeEventSha256) &&
      observed.independent === true &&
      observed.status === "RETIRED" &&
      observed.emergencyCleanup === false,
  );
  await persist({
    ...request,
    requestSha256,
    status: "RETIRED",
    receiptSha256: observationDigest(observed),
  });
  return observed;
}
