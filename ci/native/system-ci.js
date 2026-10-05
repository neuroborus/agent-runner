import { createHash } from "node:crypto";
import { lstat, mkdir, readFile, realpath, writeFile } from "node:fs/promises";
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
    verify = readSystemCIInputs,
    signal,
  } = {},
) {
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
    requireObservation(response.ok);
    const chunks = [];
    let size = 0;
    for await (const chunk of response.body) {
      size += chunk.length;
      requireObservation(size <= 2097152);
      chunks.push(chunk);
    }
    requireObservation(size > 0);
    return Buffer.concat(chunks);
  };
  // Neither source nor approval is guessed from the current runner image.
  const manifestBytes = await download("system-inputs.json");
  const manifest = JSON.parse(manifestBytes);
  requireObservation(
    manifest.candidateSha === job.candidateSha &&
      manifest.platform === job.platform &&
      observationDigest(manifest) === env.NATIVE_SYSTEM_REVIEW_SHA256 &&
      hash(manifest.capabilitySha256),
  );
  const capabilityBytes = await download("native-effects.mjs");
  requireObservation(digest(capabilityBytes) === manifest.capabilitySha256);
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
  await verify(job, profile, directory, env);
  requireObservation(!signal?.aborted);
  if (job.platform === "linux") {
    const linuxReview = await download("linux-review.json");
    profile.verifyLegacy(JSON.parse(linuxReview), env, job, manifest);
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
  const stop = () => rejectDeadline(new Error("Native system effect deadline"));
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
) {
  const root = path.resolve(env.RUNNER_TEMP, `native-${job.platform}-reviewed`);
  requireObservation(directory === root && (await realpath(root)) === root);
  const read = async (file, maximum = 2097152) => {
    const metadata = await lstat(file);
    requireObservation(
      metadata.isFile() &&
        !metadata.isSymbolicLink() &&
        metadata.nlink === 1 &&
        metadata.size > 0 &&
        metadata.size <= maximum &&
        (await realpath(file)) === file,
    );
    const bytes = await readFile(file);
    requireObservation(bytes.length === metadata.size);
    return bytes;
  };
  const manifest = JSON.parse(
    await read(path.join(root, "system-inputs.json")),
  );
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
  ]);
  requireObservation(
    manifest.schemaVersion === 1 &&
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
    requireObservation(
      digest(
        await read(path.resolve(`ci/native/${job.platform}/${name}.c`), 65536),
      ) === helper.sourceSha256,
    );
  }
  requireObservation(
    Array.isArray(manifest.tools) &&
      manifest.tools.length === profile.tools.length &&
      new Set(manifest.tools.map(({ name }) => name)).size ===
        profile.tools.length,
  );
  for (const tool of manifest.tools) {
    observationObject(tool, ["name", "path", "sha256", "version"]);
    const expected = profile.tools.find(({ name }) => name === tool.name);
    requireObservation(
      expected &&
        expected.path.test(tool.path) &&
        hash(tool.sha256) &&
        typeof tool.version === "string" &&
        /^[\x20-\x7e]{1,256}$/u.test(tool.version),
    );
  }
  requireObservation(
    Array.isArray(manifest.inputs) &&
      manifest.inputs.length > 0 &&
      manifest.inputs.length <= 600,
  );
  for (const entry of manifest.inputs)
    observationObject(entry, ["path", "sha256"]);
  const paths = new Set();
  let total = 0;
  for (const entry of [...manifest.inputs, ...manifest.tools]) {
    requireObservation(
      path.isAbsolute(entry.path) &&
        !paths.has(entry.path) &&
        hash(entry.sha256),
    );
    paths.add(entry.path);
    const bytes = await read(entry.path, 134217728);
    total += bytes.length;
    requireObservation(total <= 1073741824 && digest(bytes) === entry.sha256);
  }
  observationObject(manifest.environment, profile.environment);
  for (const value of Object.values(manifest.environment))
    requireObservation(
      typeof value === "string" &&
        value.length > 0 &&
        value.length <= 32768 &&
        !/[\x00-\x1f]/u.test(value),
    );
  const capabilityBytes = await read(path.join(root, "native-effects.mjs"));
  requireObservation(digest(capabilityBytes) === manifest.capabilitySha256);
  profile.validate?.(manifest);
  return {
    manifest,
    reviews,
    read,
    capabilityBytes,
    authority: executionAuthority,
  };
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
    value.schemaVersion === 1 &&
      value.candidateSha === job.candidateSha &&
      value.platform === job.platform &&
      (value.reviewSha256 === null || hash(value.reviewSha256)) &&
      ["NOT_RUN", "RUNNING", "FAIL", "PASS"].includes(value.status) &&
      [
        null,
        "review",
        "native-bootstrap",
        "toolchain",
        "build",
        "verification",
      ].includes(value.phase),
  );
  for (const [key, maximum] of [
    ["versions", 3],
    ["helpers", 10],
    ["commands", 32],
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
    inputs = readSystemCIInputs,
    loadCapability = capability,
    now = () => performance.now(),
    fs = { mkdir, readFile, lstat },
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
      () => inputs(job, profile, root, env),
      remaining(),
    );
    const { manifest } = bundle;
    record.reviewSha256 = env.NATIVE_SYSTEM_REVIEW_SHA256;
    await phase("native-bootstrap");
    await fs.mkdir(output, { mode: 0o700 });
    const module = await boundSystemEffect(
      () => loadCapability(bundle),
      remaining(),
    );
    requireObservation(typeof module.createBuildEffects === "function");
    const api = await profile.api();
    const buildEffects = await boundSystemEffect(
      (signal) =>
        module.createBuildEffects({
          job: structuredClone(job),
          output,
          manifest: structuredClone(manifest),
          api,
          signal,
        }),
      remaining(),
    );
    requireObservation(typeof buildEffects?.run === "function");
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
        tool && digest(await bundle.read(file, 134217728)) === tool.sha256,
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
      const source = path.resolve(`ci/native/${job.platform}/${name}.c`);
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
    requireObservation(
      now() - start <= maximumMs &&
        record.commands.every(({ status }) => status === "RETIRED"),
    );
    record.phase = "verification";
    record.status = "PASS";
  } catch {
    record.status = "FAIL";
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
  { recovery = false } = {},
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
  const bundle = await readSystemCIInputs(job, profile, root, env);
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
  effects.build = async ({ candidateSha, reviewSha256, signal }) => {
    requireObservation(candidateSha === job.candidateSha);
    const observed = await effects.verifyBuild(structuredClone(receipt), {
      signal,
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
