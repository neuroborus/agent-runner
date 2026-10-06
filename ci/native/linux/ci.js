import { writeFile } from "node:fs/promises";
import path from "node:path";
import {
  acquireSystemCIInputs,
  prepareSystemCI,
  loadSystemCI,
  systemPreparationBound,
} from "../system-ci.js";
import {
  requireObservation,
  observationObject,
  observationDigest,
} from "../observation.js";
import {
  normalizeLinuxFileBuildPins,
  verifyLinuxFileElf,
  LINUX_FILE_BUILD_ARGUMENTS,
} from "./file-build.js";
import { freshVerifier, LINUX_FILE_PROOF_BUILD_MS } from "./proof.js";
import { digest, protectedReceipt } from "./inspect.js";
import { linuxSystemRecipes } from "./composition.js";
import { linuxReviewedManifestDigest } from "./reviewed-inputs.js";

const profile = {
  imageOS: /^ubuntu24$/u,
  extension: "",
  sources: ["file-helper"],
  environment: [],
  fields: ["linuxBuild"],
  tools: [
    {
      name: "compiler",
      path: /^\/usr\/bin\/x86_64-linux-gnu-gcc-13$/u,
      args: ["--version"],
      versionExitCodes: [],
    },
    {
      name: "sdk",
      path: /^\/usr\/bin\/x86_64-linux-gnu-ld\.bfd$/u,
      args: ["--version"],
      versionExitCodes: [],
    },
  ],
  target: (output, name) => path.join(output, "build", "output", name),
  compileBound: LINUX_FILE_PROOF_BUILD_MS,
  inspectProcess: (identity) => {
    observationObject(identity, ["pid", "bootId", "startTicks"]);
    requireObservation(
      Number.isSafeInteger(identity.pid) &&
        identity.pid > 1 &&
        identity.pid <= 2147483647 &&
        /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/u.test(
          identity.bootId,
        ) &&
        /^[1-9][0-9]{0,31}$/u.test(identity.startTicks),
    );
  },
  inspect: verifyLinuxFileElf,
  validate: (manifest) => {
    const pins = normalizeLinuxFileBuildPins(
      manifest.linuxBuild,
      manifest.candidateSha,
    );
    requireObservation(pins.sourceSha256 === manifest.helpers[0].sourceSha256);
  },
  verifyLegacy: (manifest, env, job, system) =>
    requireObservation(
      linuxReviewedManifestDigest(manifest, job.candidateSha) ===
        env.NATIVE_LINUX_REVIEW_SHA256 &&
        observationDigest(manifest.build) ===
          observationDigest(system.linuxBuild),
    ),
  compile: async (job, output, manifest) => {
    const { createLinuxBuildEffects } = await import("./effects.js");
    return createLinuxBuildEffects({ job, output, manifest }).build();
  },
  api: () => import("./index.js"),
  recipes: linuxSystemRecipes,
};
export const prepareLinuxSystemCI = (job, root, output, persist, options) =>
  prepareSystemCI(job, profile, root, output, persist, options);
export const acquireLinuxSystemCI = (job, root, options) =>
  acquireSystemCIInputs(job, profile, root, options);
export const LINUX_SYSTEM_PREPARATION_MS = systemPreparationBound(profile);
export async function loadLinuxSystemCI(
  job,
  root,
  directory,
  receipt,
  env,
  { load = loadSystemCI, ...options } = {},
) {
  const bundle = await load(
    job,
    profile,
    root,
    directory,
    receipt,
    env,
    options,
  );
  const prepare = bundle.effects.prepare;
  const output = path.join(directory, "platform-build");
  bundle.referenceDirectory = output;
  bundle.effects.prepare = async (...args) => {
    const prepared = await prepare(...args);
    if (args[0].group === "reference") {
      // The historical engine still verifies its exact build/retirement
      // evidence, but its build callback may only rejoin the dedicated phase.
      prepared.options = {
        ...prepared.options,
        build: (reference, referenceDirectory, fixture, suppliedPins) =>
          rejoinPreparedBuild(
            job,
            bundle,
            output,
            receipt,
            reference,
            referenceDirectory,
            fixture,
            suppliedPins,
          ),
      };
    }
    return prepared;
  };
  return bundle;
}

export async function rejoinPreparedBuild(
  job,
  bundle,
  output,
  preparation,
  reference,
  referenceDirectory,
  fixture,
  suppliedPins,
) {
  requireObservation(
    reference.candidateSha === job.candidateSha &&
      referenceDirectory === output &&
      observationDigest(suppliedPins) ===
        observationDigest(bundle.manifest.linuxBuild),
  );
  const result = await verifyPreparedLinuxBuild(
    job,
    bundle,
    output,
    preparation,
  );
  const { executable: _executable, ...buildRecord } = result.build;
  await writeFile(
    path.join(fixture.directory, "evidence", "helper-build.json"),
    JSON.stringify(buildRecord) + "\n",
    { flag: "wx", mode: 0o400 },
  );
  return result;
}

/** Reread prepared bytes and independently retire their original commands.
 * Verification cannot compile or repair preparation evidence. */
export async function verifyPreparedLinuxBuild(
  job,
  bundle,
  output,
  preparation,
  { readReceipt = protectedReceipt, verify = freshVerifier } = {},
) {
  const result = JSON.parse(
    await bundle.read(path.join(output, "prepared-build.json")),
  );
  observationObject(result, ["build", "receipts", "settlement"]);
  requireObservation(
    observationDigest(result) === preparation.commands.at(-1)?.receiptSha256,
  );
  const pins = normalizeLinuxFileBuildPins(
    bundle.manifest.linuxBuild,
    job.candidateSha,
  );
  const executable = profile.target(output, "file-helper");
  const bytes = await bundle.read(executable, 4194304);
  requireObservation(
    result.build?.candidateSha === job.candidateSha &&
      result.build.sourceSha256 === pins.sourceSha256 &&
      result.build.executable === executable &&
      result.build.sha256 === bundle.manifest.helpers[0].sha256 &&
      digest(bytes) === result.build.sha256 &&
      observationDigest(verifyLinuxFileElf(bytes)) ===
        observationDigest(result.build.abi) &&
      observationDigest(result.build.inputs) ===
        observationDigest(pins.inputs) &&
      observationDigest(result.build.arguments) ===
        observationDigest(LINUX_FILE_BUILD_ARGUMENTS) &&
      result.build.compiler.file === "/usr/bin/x86_64-linux-gnu-gcc-13" &&
      result.build.compiler.version === pins.compilerVersion &&
      result.build.compiler.sha256 ===
        pins.inputs.find(({ target }) => target === result.build.compiler.file)
          ?.sha256 &&
      result.settlement.status === "RETIRED" &&
      result.settlement.independent === true &&
      result.settlement.emergencyCleanup === false &&
      result.receipts.length === 2,
  );
  for (const [index, entry] of result.receipts.entries()) {
    observationObject(entry, ["file", "sha256"]);
    requireObservation(
      entry.file === path.join(output, "build", `command-${index}.json`),
    );
    const receipt = await readReceipt(entry.file, entry.sha256);
    const retired = await verify(entry.file, entry.sha256);
    requireObservation(
      receipt.candidateSha === job.candidateSha &&
        retired.status === "RETIRED" &&
        retired.independent &&
        !retired.emergencyCleanup,
    );
  }
  return result;
}

export function linuxProviderCIContract({
  tools,
  output,
  sourceDirectory,
} = {}) {
  return {
    helpers: ["provider-gate"],
    relayPrincipal: { brokerUid: 0 },
    validInputPath: (file) =>
      typeof file === "string" &&
      path.posix.isAbsolute(file) &&
      path.posix.normalize(file) === file,
    commands:
      tools && output
        ? [
            {
              executable: tools.find(({ name }) => name === "compiler").path,
              arguments: [
                "-std=c17",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                sourceDirectory
                  ? path.posix.join(sourceDirectory, "provider-gate.c")
                  : path.resolve("ci/native/linux/provider-gate.c"),
                "-o",
                path.join(output, "provider-gate"),
              ],
            },
          ]
        : [],
  };
}
