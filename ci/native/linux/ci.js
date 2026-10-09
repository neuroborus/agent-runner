import { writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  acquireSystemCIInputs,
  prepareSystemCI,
  loadSystemCI,
  systemPreparationBound,
  requireObservation,
  observationObject,
  observationDigest,
  preparedNativeCommands,
} from "../index.js";
import {
  normalizeLinuxFileBuildPins,
  verifyLinuxFileElf,
  LINUX_FILE_BUILD_ARGUMENTS,
} from "./file-build.js";
import { freshVerifier, LINUX_FILE_PROOF_BUILD_MS } from "./proof.js";
import { digest, protectedReceipt, readProtectedEvidence } from "./inspect.js";
import { linuxSystemRecipes } from "./composition.js";
import { linuxReviewedManifestDigest } from "./reviewed-inputs.js";

const profile = {
  platform: "linux",
  imageOS: /^ubuntu24$/u,
  extension: "",
  sources: ["file-helper"],
  environment: [],
  fields: ["linuxBuild"],
  recoveryFromBootstrap: true,
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
  {
    fs,
    ownerUid,
    verifierOptions,
    verificationPending = false,
    launcherSha256,
    readReceipt = (file, sha256) =>
      protectedReceipt(file, sha256, { fs, ownerUid }),
    verify = (file, sha256) => freshVerifier(file, sha256, verifierOptions),
  } = {},
) {
  const commands = preparedNativeCommands(
    preparation,
    bundle.manifest,
    profile.tools.length + profile.sources.length,
    { verificationPending },
  );
  const result = JSON.parse(
    await bundle.read(path.join(output, "prepared-build.json")),
  );
  observationObject(result, ["build", "receipts", "settlement"]);
  requireObservation(
    observationDigest(result) === commands.at(-1).receiptSha256,
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
  const observations = [];
  // Rejoin the original compiler inputs as well as their approved host bytes.
  const source = fileURLToPath(new URL("./file-helper.c", import.meta.url));
  for (const file of [source, path.join(output, "build", "file-helper.c")])
    requireObservation(
      digest(await bundle.read(file, 65536)) === pins.sourceSha256,
    );
  let total = 0;
  for (const [index, input] of pins.inputs.entries()) {
    for (const file of [
      input.source,
      path.join(output, "build", "inputs", String(index)),
    ]) {
      const bytes = await bundle.read(file, 67108864);
      total += bytes.length;
      requireObservation(digest(bytes) === input.sha256 && total <= 134217728);
    }
  }
  if (bundle.manifest.schemaVersion === 2) {
    requireObservation(
      commands.at(-1).requestSha256 ===
        observationDigest({
          candidateSha: job.candidateSha,
          output,
          helper: bundle.manifest.helpers[0],
          reviewSha256: preparation.reviewSha256,
        }),
    );
    for (const [index, expected] of profile.tools.entries()) {
      const tool = bundle.manifest.tools.find(
        ({ name }) => name === expected.name,
      );
      requireObservation(tool && expected.path.test(tool.path));
      requireObservation(
        digest(await bundle.read(tool.path, 134217728)) === tool.sha256,
      );
      const entry = commands[index],
        id = entry.requestSha256,
        directory = path.join(output, `command-${id}`);
      const input = JSON.parse(
        await readProtectedEvidence(path.join(directory, "input.json"), {
          fs,
          ownerUid,
        }),
      );
      // The failure-IPC binding is absent from historical successful requests.
      const hasNonce = Object.hasOwn(input ?? {}, "nonce");
      observationObject(input, [
        "candidateSha",
        "directory",
        "launcher",
        "command",
        ...(hasNonce ? ["nonce"] : []),
      ]);
      requireObservation(
        input.candidateSha === job.candidateSha &&
          input.directory === directory &&
          input.launcher === "/usr/bin/bwrap" &&
          (!hasNonce ||
            (typeof input.nonce === "string" &&
              /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/u.test(
                input.nonce,
              ))) &&
          Number.isSafeInteger(input.command?.deadlineMs) &&
          input.command.deadlineMs > 0 &&
          input.command.deadlineMs <= 30000,
      );
      const request = {
        candidateSha: job.candidateSha,
        platform: "linux",
        toolSha256: tool.sha256,
        file: tool.path,
        args: expected.args,
        cwd: output,
        env: { CI: "true", GITHUB_ACTIONS: "true", LANG: "C" },
        deadlineMs: input.command.deadlineMs,
      };
      requireObservation(
        observationDigest(request) === id &&
          observationDigest(input.command) === id &&
          preparation.versions.some(
            (version) =>
              version.name === tool.name &&
              version.sha256 === tool.sha256 &&
              version.version === tool.version,
          ),
      );
      const prefix = path.join(path.dirname(output), `linux-command-${id}`);
      const intent = JSON.parse(
        await readProtectedEvidence(prefix + "-intent.json", { fs, ownerUid }),
      );
      observationObject(intent, ["candidateSha", "requestSha256", "status"]);
      requireObservation(
        intent.candidateSha === job.candidateSha &&
          intent.requestSha256 === id &&
          intent.status === "POSSIBLE",
      );
      const record = JSON.parse(
        await readProtectedEvidence(prefix + "-result.json", { fs, ownerUid }),
      );
      observationObject(record, [
        "requestSha256",
        "toolSha256",
        "nativeEventSha256",
        "settlement",
        "receiptSha256",
        "receipt",
      ]);
      observationObject(record.receipt, ["file", "sha256"]);
      requireObservation(
        record.requestSha256 === id &&
          record.toolSha256 === tool.sha256 &&
          record.receiptSha256 === entry.receiptSha256 &&
          record.receipt.file === path.join(directory, "command-0.json") &&
          record.settlement?.status === "RETIRED" &&
          record.settlement.independent === true &&
          record.settlement.emergencyCleanup === false &&
          /^[a-f0-9]{64}$/u.test(record.nativeEventSha256),
      );
      const receipt = await readReceipt(
        record.receipt.file,
        record.receipt.sha256,
      );
      requireObservation(
        receipt.candidateSha === job.candidateSha &&
          receipt.caseId === "argv" &&
          receipt.policyDigest === id &&
          receipt.executableDigest === tool.sha256,
      );
      const settlement = await verify(
        record.receipt.file,
        record.receipt.sha256,
      );
      requireObservation(
        settlement.status === "RETIRED" &&
          settlement.independent === true &&
          settlement.emergencyCleanup === false,
      );
      observations.push({ receipt, settlement });
    }
  }
  for (const [index, entry] of result.receipts.entries()) {
    observationObject(entry, ["file", "sha256"]);
    requireObservation(
      entry.file === path.join(output, "build", `command-${index}.json`),
    );
    const receipt = await readReceipt(entry.file, entry.sha256);
    if (bundle.manifest.schemaVersion === 2) {
      const intent = JSON.parse(
        await readProtectedEvidence(
          path.join(output, "build", `command-${index}-possible.json`),
          { fs, ownerUid },
        ),
      );
      observationObject(intent, ["candidateSha", "nonce", "policyDigest"]);
      requireObservation(
        intent.candidateSha === receipt.candidateSha &&
          intent.nonce === receipt.nonce &&
          intent.policyDigest === receipt.policyDigest,
      );
    }
    const retired = await verify(entry.file, entry.sha256);
    requireObservation(
      receipt.candidateSha === job.candidateSha &&
        receipt.caseId === "argv" &&
        (!launcherSha256 || receipt.executableDigest === launcherSha256) &&
        retired.status === "RETIRED" &&
        retired.independent &&
        !retired.emergencyCleanup,
    );
    observations.push({ receipt, settlement: retired });
  }
  // Keep the original receipt bytes/digest above, but return the fresh reads.
  return {
    ...result,
    settlement: {
      status: "RETIRED",
      independent: true,
      emergencyCleanup: false,
    },
    nativeEventSha256: observationDigest(observations),
  };
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
