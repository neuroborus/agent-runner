import { createHash } from "node:crypto";
import { posix, win32 } from "node:path";
import {
  normalizeBinding,
  normalizeClosureReference,
  normalizeNativePolicyContext,
  nativePolicyContext,
  normalizePolicyTemplateApprovals,
  normalizeReviewAuthority,
  observationObject,
  observationDigest,
  requireObservation,
} from "../index.js";
import { normalizeProviderSpec } from "./contract.js";
import { protectedProviderRecipes } from "./dispatch.js";

export const providerHash = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
export const providerBytesDigest = (bytes) =>
  createHash("sha256").update(bytes).digest("hex");
export const providerRetired = (value) =>
  value?.status === "RETIRED" &&
  value.independent === true &&
  value.emergencyCleanup === false &&
  providerHash(value.nativeEventSha256);
export const providerRetained = () => ({
  status: "RETAINED",
  independent: false,
  emergencyCleanup: false,
});
export const providerFunctions = (value, names) =>
  names.forEach((name) =>
    requireObservation(typeof value?.[name] === "function"),
  );
export const providerPaths = (platform) =>
  platform === "win32" ? win32 : posix;

/** Selections are independently reviewed inputs. They cannot stand in for
 * package, process, policy, credential-custody or tool observations. */
export function normalizeProviderPreparation(value, manifest) {
  observationObject(value, [
    "schemaVersion",
    "sourceDirectory",
    "bootstrap",
    "cases",
  ]);
  const paths = providerPaths(manifest.platform);
  requireObservation(
    value.schemaVersion === 1 &&
      paths.isAbsolute(value.sourceDirectory) &&
      paths.normalize(value.sourceDirectory) === value.sourceDirectory &&
      value.sourceDirectory.length <= 4096 &&
      value.sourceDirectory.isWellFormed() &&
      value.sourceDirectory !== paths.parse(value.sourceDirectory).root &&
      !/[\\/]$/u.test(value.sourceDirectory) &&
      (manifest.platform !== "win32" ||
        /^[A-Za-z]:\\[^:]+$/u.test(value.sourceDirectory)) &&
      !/[\u0000-\u001f\u007f]/u.test(value.sourceDirectory),
  );
  const context = normalizeNativePolicyContext(value.bootstrap.context);
  requireObservation(
    context.candidateSha === manifest.candidateSha &&
      context.platform === manifest.platform &&
      context.tier === "provider" &&
      context.executionId === "provider-build",
  );
  const recipes = protectedProviderRecipes(manifest.platform),
    seen = new Set(),
    nonces = new Set();
  requireObservation(
    Array.isArray(value.cases) && value.cases.length === recipes.length,
  );
  requireObservation(
    manifest.execution.schemaVersion === 2 &&
      Array.isArray(manifest.execution.cases) &&
      manifest.execution.cases.length === recipes.length &&
      new Set(manifest.execution.cases.map(({ id }) => id)).size ===
        recipes.length,
  );
  for (const entry of value.cases) {
    observationObject(entry, [
      "id",
      "specification",
      "launch",
      "custody",
      "bindings",
    ]);
    const recipe = recipes.find((item) => item.id === entry.id),
      spec = normalizeProviderSpec(entry.specification),
      caseContext = normalizeNativePolicyContext(entry.custody.context);
    requireObservation(
      recipe &&
        !seen.has(entry.id) &&
        !nonces.has(spec.nonce) &&
        spec.candidateSha === manifest.candidateSha &&
        spec.platform === manifest.platform &&
        spec.provider === recipe.group &&
        spec.profile === recipe.profile &&
        observationDigest({ ...caseContext, executionId: "provider-build" }) ===
          observationDigest(context) &&
        caseContext.executionId === entry.id &&
        entry.bindings &&
        Object.getPrototypeOf(entry.bindings) === Object.prototype,
    );
    seen.add(entry.id);
    nonces.add(spec.nonce);
  }
  return structuredClone(value);
}

/** Effect-free construction. The admitted CI controller owns the selected
 * complete system gate; this factory retains that exact closure/attempt join. */
export function providerPreparationContext(input, options) {
  const value = structuredClone({
    job: input.job,
    manifest: input.manifest,
    buildManifest: input.buildManifest,
    directory: input.directory,
    helpers: input.helpers,
    providerHelpers: input.providerHelpers,
    preparation: input.preparation,
    templateReviews: input.templateReviews,
  });
  const { job, manifest } = value,
    paths = providerPaths(job.platform);
  requireObservation(
    job.tier === "provider" &&
      manifest.schemaVersion === 2 &&
      /^[a-f0-9]{40}$/u.test(job.candidateSha) &&
      manifest.candidateSha === job.candidateSha &&
      manifest.platform === job.platform &&
      ["linux", "darwin", "win32"].includes(job.platform) &&
      manifest.execution.schemaVersion === 2 &&
      observationDigest(manifest.execution) ===
        job.reviews.provider.manifestSha256 &&
      value.buildManifest.candidateSha === job.candidateSha &&
      value.buildManifest.platform === job.platform,
  );
  observationObject(job.selectedSystem, [
    "schemaVersion",
    "jobSha256",
    "binding",
    "closure",
  ]);
  const selected = normalizeBinding(job.selectedSystem.binding),
    closure = normalizeClosureReference(job.closure);
  requireObservation(
    job.selectedSystem.schemaVersion === 1 &&
      providerHash(job.selectedSystem.jobSha256) &&
      selected.tier === "system" &&
      selected.authority === "ordinary" &&
      selected.conclusion === "success" &&
      selected.candidateSha === job.candidateSha &&
      selected.platform === job.platform &&
      observationDigest(
        normalizeClosureReference(job.selectedSystem.closure),
      ) === observationDigest(closure),
  );
  const plan = normalizeProviderPreparation(
    manifest.providerPreparation,
    manifest,
  );
  const templates = normalizePolicyTemplateApprovals(
    manifest.execution.policyTemplates,
    job,
  );
  requireObservation(
    Array.isArray(value.templateReviews) && value.templateReviews.length <= 256,
  );
  const approvals = value.templateReviews.map((review) =>
    normalizeReviewAuthority(review, job.candidateSha, job.platform),
  );
  requireObservation(
    templates.every(({ approval }) =>
      approvals.some(
        (review) => review.manifestSha256 === approval.manifestSha256,
      ),
    ),
  );
  requireObservation(
    observationDigest(plan.bootstrap.context) ===
      observationDigest(nativePolicyContext(job, "provider-build")) &&
      plan.bootstrap.context.selectedSystemSha256 ===
        observationDigest(job.selectedSystem) &&
      plan.bootstrap.context.closureSha256 === observationDigest(closure) &&
      paths.isAbsolute(value.directory) &&
      paths.normalize(value.directory) === value.directory &&
      value.helpers === paths.join(value.directory, "platform-build") &&
      value.providerHelpers === paths.join(value.directory, "provider-build"),
  );
  // No credential or ambient provider configuration is captured by a factory.
  const sourceEnv = options.env ?? process.env,
    env = Object.fromEntries(
      ["CI", "GITHUB_ACTIONS", "ImageOS", "ImageVersion", "RUNNER_TEMP"].map(
        (key) => [key, sourceEnv[key]],
      ),
    );
  const guard = (signal) =>
    requireObservation(
      !signal?.aborted &&
        env.CI === "true" &&
        env.GITHUB_ACTIONS === "true" &&
        {
          linux: /^ubuntu24$/u,
          darwin: /^macos15$/u,
          win32: /^win25(?:-vs2026)?$/u,
        }[job.platform].test(env.ImageOS),
    );
  const primitive = (name, ...args) => {
    providerFunctions(options, [name]);
    return options[name](...args);
  };
  const verifyDirectory = async () => {
    const proof = await primitive("verifyDirectory", {
      directory: value.directory,
      output: value.providerHelpers,
      context: plan.bootstrap.context,
    });
    requireObservation(
      proof?.independent === true &&
        proof.held === true &&
        proof.protectedParents === true &&
        proof.exclusiveWriter === true &&
        proof.protectedAuthority === true &&
        proof.directory === value.directory &&
        providerHash(proof.nativeEventSha256),
    );
  };
  const read = async (file, pin, maximum, receipt = false) => {
    const result = await primitive("readProtected", {
      file,
      sha256: pin,
      maximum,
      receipt,
      context: plan.bootstrap.context,
    });
    requireObservation(
      Buffer.isBuffer(result?.bytes) &&
        result.bytes.length > 0 &&
        result.bytes.length <= maximum &&
        result.independent === true &&
        result.held === true &&
        result.protectedParents === true &&
        result.protectedAuthority === true &&
        result.unchanged === true &&
        result.file === file &&
        result.sha256 === providerBytesDigest(result.bytes) &&
        (!pin || result.sha256 === pin) &&
        providerHash(result.identitySha256) &&
        providerHash(result.nativeEventSha256) &&
        (!receipt || result.immutable === true),
    );
    return result.bytes;
  };
  const write = async (name, record) => {
    requireObservation(/^provider-[a-z0-9.-]+\.json$/u.test(name));
    await verifyDirectory();
    const file = paths.join(value.directory, name),
      bytes = Buffer.from(JSON.stringify(record) + "\n");
    requireObservation(bytes.length <= 1048576);
    const result = await primitive("writeProtected", {
      file,
      bytes,
      exclusive: true,
      context: plan.bootstrap.context,
    });
    requireObservation(
      result?.independent === true &&
        result.file === file &&
        result.sha256 === providerBytesDigest(bytes) &&
        result.exclusive === true &&
        result.immutable === true &&
        result.writerClosed === true &&
        result.protectedParents === true &&
        result.protectedAuthority === true &&
        providerHash(result.identitySha256) &&
        providerHash(result.nativeEventSha256),
    );
  };
  return {
    ...value,
    paths,
    plan,
    templates,
    env,
    guard,
    primitive,
    read,
    write,
    verifyDirectory,
  };
}
