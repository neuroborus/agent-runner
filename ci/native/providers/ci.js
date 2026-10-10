import { createHash } from "node:crypto";
import { mkdir, realpath, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  observationObject,
  observationDigest,
  requireObservation,
  admitNativeSourceReview,
  releaseClosureDigest,
  admitCompositionPlan,
  assertNativePreparationInputs,
  nativePreparationError,
  boundSystemEffect,
  readSystemCIFile,
  nativeCandidateReader,
  guardNativeCIAdmissions,
} from "../index.js";
import { linuxProviderCIContract } from "../linux/index.js";
import { darwinProviderCIContract } from "../darwin/index.js";
import { windowsProviderCIContract } from "../win32/index.js";
import * as providerFactories from "./effects.js";
import { normalizeProviderPreparation } from "./preparation.js";
import {
  admitProtectedProviderJob,
  protectedProviderRecipes,
} from "./dispatch.js";

const hash = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const authority = (job, platform, manifestSha256) => ({
  candidateSha: job.candidateSha,
  platform,
  manifestSha256,
  authority: "operator-protected",
});
const platformCI = {
  linux: linuxProviderCIContract,
  darwin: darwinProviderCIContract,
  win32: windowsProviderCIContract,
};
const apiFor = {
  linux: () => import("../linux/index.js"),
  darwin: () => import("../darwin/index.js"),
  win32: () => import("../win32/index.js"),
};

export function providerJobBounds(platform) {
  const probeMs =
    5 * 30000 +
    protectedProviderRecipes(platform).reduce(
      (sum, { deadlineMs }) => sum + deadlineMs + 60000,
      0,
    );
  return {
    probeMs,
    cleanupMs: 2 * 120000 + 4 * 30000,
    preparationMs: 120000,
    probeMinutes: Math.ceil(probeMs / 60000) + 1,
    cleanupMinutes: 7,
    preparationMinutes: 3,
  };
}

/** Public immutable review acquisition is credential-free. Neither a downloaded
 * approval field nor a provider-tier flag admits this source. */
export async function fetchAcceptanceInput(
  env,
  candidateSha,
  member,
  { fetchInput = fetch, signal } = {},
) {
  requireObservation(
    env.CI === "true" &&
      env.GITHUB_ACTIONS === "true" &&
      /^[a-f0-9]{40}$/u.test(candidateSha) &&
      /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(
        env.NATIVE_SYSTEM_INPUT_REPOSITORY,
      ) &&
      /^[a-f0-9]{40}$/u.test(env.NATIVE_SYSTEM_INPUT_REVISION) &&
      /^(?:source-manifest\.json|(?:linux|darwin|win32)\/(?:system-inputs\.json|provider-(?:inputs\.json|effects\.mjs)))$/u.test(
        member,
      ),
  );
  const response = await fetchInput(
    `https://raw.githubusercontent.com/${env.NATIVE_SYSTEM_INPUT_REPOSITORY}/${env.NATIVE_SYSTEM_INPUT_REVISION}/ci/native/reviews/${candidateSha}/${member}`,
    {
      credentials: "omit",
      redirect: "error",
      signal: signal
        ? AbortSignal.any([signal, AbortSignal.timeout(10000)])
        : AbortSignal.timeout(10000),
    },
  );
  requireObservation(response.ok);
  const chunks = [];
  let size = 0;
  for await (const chunk of response.body) {
    size += chunk.length;
    requireObservation(size <= 2097152);
    chunks.push(chunk);
  }
  requireObservation(size > 0 && !signal?.aborted);
  return Buffer.concat(chunks);
}

export async function acquireProviderCI(job, env) {
  assertNativePreparationInputs(job, env);
  const root = path.resolve(
    env.RUNNER_TEMP,
    `native-${job.platform}-provider-reviewed`,
  );
  const bytes = await fetchAcceptanceInput(
    env,
    job.candidateSha,
    `${job.platform}/provider-inputs.json`,
  );
  let manifest;
  try {
    manifest = JSON.parse(bytes);
  } catch {
    throw nativePreparationError("review", [
      { id: "provider-inputs.json", diagnosis: "malformed" },
    ]);
  }
  if (
    !manifest ||
    observationDigest(manifest) !== env.NATIVE_PROVIDER_REVIEW_SHA256 ||
    !hash(manifest.capabilitySha256)
  )
    throw nativePreparationError("review", [
      { id: "provider-inputs.json", diagnosis: "malformed" },
    ]);
  const capability = await fetchAcceptanceInput(
    env,
    job.candidateSha,
    `${job.platform}/provider-effects.mjs`,
  );
  if (
    !hash(manifest.capabilitySha256) ||
    digest(capability) !== manifest.capabilitySha256
  )
    throw nativePreparationError("review", [
      { id: "provider-effects.mjs", diagnosis: "malformed" },
    ]);
  await mkdir(root, { mode: 0o700 });
  await writeFile(path.join(root, "provider-inputs.json"), bytes, {
    flag: "wx",
    mode: 0o400,
  });
  await writeFile(path.join(root, "provider-effects.mjs"), capability, {
    flag: "wx",
    mode: 0o400,
  });
}

async function privateBytes(file, limit = 2097152) {
  const bytes = await readSystemCIFile(file, limit);
  requireObservation(bytes.length > 0);
  return bytes;
}

/** Manifest validation remains useful to the read-only collector, without
 * loading native capabilities or reading host package paths. */
export function admitProviderCIManifest(
  job,
  manifest,
  approvedSha256,
  sourceSha256,
  templateReviews = [],
) {
  observationObject(manifest, [
    "schemaVersion",
    "candidateSha",
    "platform",
    "source",
    "release",
    "execution",
    "capabilitySha256",
    "inputs",
    "helpers",
    ...(manifest.schemaVersion === 2 ? ["providerPreparation"] : []),
  ]);
  requireObservation(
    [1, 2].includes(manifest.schemaVersion) &&
      manifest.candidateSha === job.candidateSha &&
      manifest.platform === job.platform &&
      hash(approvedSha256) &&
      observationDigest(manifest) === approvedSha256 &&
      hash(manifest.capabilitySha256),
  );
  const reviews = {
    source: authority(job, null, sourceSha256),
    release: authority(
      job,
      job.platform,
      releaseClosureDigest(manifest.release),
    ),
    provider: authority(
      job,
      job.platform,
      observationDigest(manifest.execution),
    ),
  };
  admitNativeSourceReview(manifest.source, reviews.source);
  requireObservation(
    manifest.release.candidateSha === job.candidateSha &&
      manifest.release.platform === job.platform &&
      manifest.source.citations.some(
        (entry) =>
          entry.kind === "reached-code" &&
          entry.member.split("/").at(-1) === "provider-effects.mjs" &&
          entry.sha256 === manifest.capabilitySha256,
      ),
  );
  const admitted = {
    ...job,
    closure: job.closure,
    reviews: { ...job.reviews, ...reviews },
  };
  // The collector supplies a selected system closure; preparation may precede
  // that join only after it was independently established by its controller.
  admitCompositionPlan(
    admitted,
    protectedProviderRecipes(job.platform),
    manifest.execution,
    reviews.provider,
    manifest.source,
    templateReviews,
  );
  const contract = platformCI[job.platform]();
  const helpers = contract.helpers;
  requireObservation(
    Array.isArray(manifest.helpers) &&
      manifest.helpers.length === helpers.length &&
      helpers.every((name) =>
        manifest.helpers.some((entry) => entry.name === name),
      ),
  );
  for (const helper of manifest.helpers) {
    observationObject(helper, ["name", "sourceSha256", "sha256"]);
    requireObservation(hash(helper.sourceSha256) && hash(helper.sha256));
  }
  requireObservation(
    Array.isArray(manifest.inputs) &&
      manifest.inputs.length > 0 &&
      manifest.inputs.length <= 128,
  );
  const ids = new Set();
  let total = 0;
  for (const entry of manifest.inputs) {
    observationObject(entry, ["id", "path", "sha256", "bytes"]);
    const component = manifest.release.components.find(
      (item) => item.id === entry.id,
    );
    requireObservation(
      component &&
        component.sha256 === entry.sha256 &&
        !ids.has(entry.id) &&
        contract.validInputPath(entry.path) &&
        Number.isSafeInteger(entry.bytes) &&
        entry.bytes > 0 &&
        entry.bytes <= 536870912,
    );
    ids.add(entry.id);
    total += entry.bytes;
  }
  requireObservation(total <= 2147483648);
  if (manifest.schemaVersion === 2)
    normalizeProviderPreparation(manifest.providerPreparation, manifest);
  return reviews;
}

export async function loadProviderCI(
  job,
  system,
  binding,
  prepared,
  directory,
  env,
  {
    recovery = false,
    credentialCustody,
    templateReviews = [],
    assertLive = () => {},
  } = {},
) {
  if (!recovery) assertLive();
  const root = path.resolve(
    env.RUNNER_TEMP,
    `native-${job.platform}-provider-reviewed`,
  );
  requireObservation((await realpath(root)) === root);
  const manifest = JSON.parse(
    await privateBytes(path.join(root, "provider-inputs.json")),
  );
  const reviews = admitProviderCIManifest(
    {
      ...job,
      closure: system.closure,
      selectedSystem: {
        schemaVersion: 1,
        jobSha256: observationDigest(system),
        binding,
        closure: system.closure,
      },
    },
    manifest,
    env.NATIVE_PROVIDER_REVIEW_SHA256,
    env.NATIVE_SOURCE_REVIEW_SHA256,
    templateReviews,
  );
  const admitted = admitProtectedProviderJob(job, system, binding, reviews);
  requireObservation(
    observationDigest(prepared.manifest.release) ===
      observationDigest(manifest.release) &&
      observationDigest(prepared.manifest.source) ===
        observationDigest(manifest.source),
  );
  for (const input of recovery ? [] : manifest.inputs) {
    const bytes = await privateBytes(input.path, 536870912);
    requireObservation(
      bytes.length === input.bytes && digest(bytes) === input.sha256,
    );
  }
  for (const helper of recovery ? [] : manifest.helpers)
    requireObservation(
      digest(
        await privateBytes(
          path.resolve(`ci/native/${job.platform}/${helper.name}.c`),
        ),
      ) === helper.sourceSha256,
    );
  const capability = await privateBytes(
    path.join(root, "provider-effects.mjs"),
  );
  requireObservation(
    digest(capability) === manifest.capabilitySha256 &&
      (
        await nativeCandidateReader(
          job.candidateSha,
          fileURLToPath(new URL("../../../", import.meta.url)),
        )("ci/native/provider-effects.mjs", 2097152)
      ).equals(capability),
  );
  const module = await loadProviderEffects({
    manifest,
    capabilityBytes: capability,
    read: privateBytes,
  });
  requireObservation(typeof module.createProviderEffects === "function");
  let preparation = null;
  try {
    preparation = JSON.parse(
      await privateBytes(path.join(directory, "provider-preparation.json")),
    );
  } catch (error) {
    requireObservation(error.code === "ENOENT");
  }
  if (job.stages.setup.status === "PASS" && !recovery) {
    const request = buildRequest(job, manifest, prepared.manifest, directory);
    requireObservation(
      preparation?.status === "PASS" &&
        hash(preparation.receiptSha256) &&
        preparation.requestSha256 === observationDigest(request) &&
        observationDigest(preparation.request) === observationDigest(request),
    );
    for (const helper of manifest.helpers)
      requireObservation(
        digest(
          await privateBytes(path.join(request.output, helper.name), 134217728),
        ) === helper.sha256,
      );
  }
  // Fixed factory construction is effect-free. No credential
  // is supplied to this factory or its platform launch/preparation callbacks.
  const effects = await module.createProviderEffects(
    {
      job: structuredClone(admitted),
      manifest: structuredClone(manifest),
      directory,
      recovery,
      helpers: path.join(directory, "platform-build"),
      providerHelpers: path.join(directory, "provider-build"),
      preparation: structuredClone(preparation),
      buildManifest: structuredClone(prepared.manifest),
      templateReviews: structuredClone(templateReviews),
      api: await apiFor[job.platform](),
    },
    { env },
  );
  requireObservation(
    ["prepareBuild", "settleBuild", "prepare", "settle", "recover"].every(
      (key) => typeof effects?.[key] === "function",
    ),
  );
  if (credentialCustody) {
    const prepare = effects.prepare.bind(effects);
    effects.prepare = async (...args) => {
      const value = await prepare(...args);
      const native = value.effects;
      requireObservation(
        typeof native?.admitTransport === "function" &&
          typeof native.verifyRelayCustody === "function",
      );
      const admit = native.admitTransport.bind(native);
      native.admitTransport = async (role, context, ...rest) => {
        const expected = Object.freeze({ ...context });
        const receiver = await admit(role, expected, ...rest);
        if (role === "relay") {
          const verified = await native.verifyRelayCustody(
            receiver,
            expected,
            rest.at(-1),
          );
          await credentialCustody.deliver(
            job.platform,
            expected,
            receiver,
            verified,
            rest.at(-1),
          );
        }
        return receiver;
      };
      return value;
    };
  }
  guardNativeCIAdmissions(effects, () => {
    requireObservation(!recovery);
    assertLive();
  });
  return {
    job: admitted,
    manifest,
    reviews,
    authority: reviews.provider,
    effects,
    templateReviews: structuredClone(templateReviews),
    buildManifest: prepared.manifest,
  };
}

function buildRequest(job, manifest, system, directory) {
  const request = {
    candidateSha: job.candidateSha,
    platform: job.platform,
    reviewSha256: observationDigest(manifest),
    helpers: manifest.helpers,
    tools: system.tools,
    output: path.join(directory, "provider-build"),
    deadlineMs: 120000,
    commands: platformCI[job.platform]({
      tools: system.tools,
      output: path.join(directory, "provider-build"),
      sourceDirectory: manifest.providerPreparation?.sourceDirectory,
    }).commands,
  };
  return request;
}

export async function prepareProviderCI(
  job,
  bundle,
  systemManifest,
  directory,
  persist,
) {
  const request = buildRequest(job, bundle.manifest, systemManifest, directory);
  const requestSha256 = observationDigest(request);
  await persist({
    request,
    requestSha256,
    status: "POSSIBLE",
    receiptSha256: null,
  });
  const receipt = await boundSystemEffect(
    (signal) =>
      bundle.effects.prepareBuild(structuredClone(request), { signal }),
    request.deadlineMs,
  );
  requireObservation(
    receipt?.requestSha256 === requestSha256 &&
      receipt.status === "OBSERVED" &&
      receipt.independent === true &&
      hash(receipt.nativeEventSha256) &&
      receipt.settlement?.status === "RETIRED" &&
      receipt.settlement.independent === true &&
      receipt.settlement.emergencyCleanup === false,
  );
  for (const helper of request.helpers)
    requireObservation(
      digest(
        await privateBytes(path.join(request.output, helper.name), 134217728),
      ) === helper.sha256,
    );
  const filesSettlement = await bundle.effects.settleBuild();
  requireObservation(
    filesSettlement?.status === "RETIRED" &&
      filesSettlement.independent === true &&
      filesSettlement.emergencyCleanup === false &&
      filesSettlement.noLiveMembers === true &&
      hash(filesSettlement.nativeEventSha256),
  );
  await persist({
    request,
    requestSha256,
    status: "PASS",
    receiptSha256: observationDigest(receipt),
    filesSettlement,
  });
}

export async function loadProviderEffects(bundle) {
  const file = fileURLToPath(
      new URL("../provider-effects.mjs", import.meta.url),
    ),
    bytes = await bundle.read(file, 2097152),
    expected = bundle.manifest.capabilitySha256,
    citations = bundle.manifest.source.citations.filter(
      (entry) => entry.member === "candidate/ci/native/provider-effects.mjs",
    );
  requireObservation(
    bundle.manifest.schemaVersion === 2 &&
      Buffer.isBuffer(bytes) &&
      Buffer.isBuffer(bundle.capabilityBytes) &&
      bytes.equals(bundle.capabilityBytes) &&
      digest(bytes) === expected &&
      citations.length === 1 &&
      citations[0].kind === "reached-code" &&
      citations[0].sha256 === expected,
  );
  requireObservation(Buffer.from(bytes.toString("utf8")).equals(bytes));
  return providerFactories;
}

export async function recoverProviderCI(job, bundle, preparation, persist) {
  const request = {
    candidateSha: job.candidateSha,
    platform: job.platform,
    jobSha256: observationDigest(job),
    preparationSha256: observationDigest(preparation),
    deadlineMs: 120000,
  };
  const requestSha256 = observationDigest(request);
  await persist({
    request,
    requestSha256,
    status: "POSSIBLE",
    receiptSha256: null,
  });
  const receipt = await boundSystemEffect(
    (signal) =>
      bundle.effects.recover({
        request: structuredClone(request),
        job: structuredClone(job),
        preparation: structuredClone(preparation),
        signal,
      }),
    request.deadlineMs,
  );
  requireObservation(
    receipt?.requestSha256 === requestSha256 &&
      receipt.status === "RETIRED" &&
      receipt.independent === true &&
      receipt.emergencyCleanup === false &&
      hash(receipt.nativeEventSha256),
  );
  await persist({
    request,
    requestSha256,
    status: "RETIRED",
    receiptSha256: observationDigest(receipt),
  });
}
