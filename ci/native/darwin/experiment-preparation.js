import * as filesystem from "node:fs/promises";
import path from "node:path";
import { nativeException } from "../diagnostics.js";
import {
  normalizeExperimentJob,
  normalizeExperimentPreparation,
  recordExperimentPreparation,
  recordExperimentPreparationEffect,
  observationDigest,
  requireObservation,
} from "../index.js";
import { darwinExperimentWorker } from "./experiment-build-inputs.js";
import {
  prepareDarwinExperimentBuild,
  loadDarwinExperimentBuild,
  recoverDarwinExperimentBuild,
  darwinExperimentBuildInput,
} from "./experiment-build.js";
import { acquireDarwinExperimentInputs } from "./experiment-inputs.js";
import { prepareDarwinExperimentCases } from "./experiment-cases.js";
import { darwinExperimentCaseDeclarations } from "./case-provisioning.js";
import { darwinPreparationContext } from "./preparation.js";
import { createDarwinSystemEffects } from "./effects.js";
import { darwinSystemRecipes } from "./system.js";
import { digest } from "./protocol.js";

const retired = (value) =>
  value?.status === "RETIRED" &&
  value.independent === true &&
  value.emergencyCleanup === false;

function systemInput(job, preparation) {
  requireObservation(
    job.purpose === "experiment" &&
      preparation.purpose === "experiment" &&
      preparation.system.cases.length === darwinSystemRecipes().length - 1,
  );
  const canonical = darwinExperimentCaseDeclarations(preparation.system.cases);
  requireObservation(
    observationDigest(canonical.policyBindings) ===
      observationDigest(preparation.system.policyBindings),
  );
  const input = darwinExperimentBuildInput(
    preparation.prepared,
    job,
    preparation.prepared.directory,
  );
  input.manifest.helpers = preparation.build.helpers.map(
    ({ name, sha256, sourceSha256 }) => ({ name, sha256, sourceSha256 }),
  );
  input.preparation = preparation;
  input.manifest.darwinPreparation.cases = canonical.cases;
  return input;
}
function selectors(preparation, options) {
  const read = options.read;
  return {
    ...options,
    read: async (file, pin, maximum = 134217728) => {
      const asset = preparation.system.uploads.find(
        ({ path }) => path === file,
      );
      if (!asset) {
        if (read) return read(file, pin, maximum);
        const { protectedBytes } = await import("./private-files.js"),
          fs = options.fs ?? filesystem,
          stat = await fs.lstat(file);
        return protectedBytes(
          { path: file, sha256: pin },
          0,
          stat.mode & 0o7777,
          maximum,
          fs,
        );
      }
      // These bytes select expected data. The sealed custodian independently
      // reads the actual root-only plan and assets before releasing any effect.
      const bytes = Buffer.from(asset.hex, "hex");
      requireObservation(
        bytes.length <= maximum &&
          asset.sha256 === pin &&
          digest(bytes) === pin,
      );
      return bytes;
    },
  };
}
function observation(prepared, build, inputs, readSha256) {
  const runtime = new Map(
      build.sdk.runtime.map(({ path, observation }) => [path, observation]),
    ),
    id = (file) =>
      file === "/usr/lib/dyld"
        ? "dyld"
        : "runtime-" + digest(file).slice(0, 24),
    bindings = (source) => ({
      source,
      build: observationDigest(build),
      abi: observationDigest(build.abi),
    }),
    components = build.helpers.map((helper) => ({
      id: helper.name,
      role: "helper",
      sha256: helper.sha256,
      format: "macho-x64",
      loader: helper.macho.dependencies.map(id),
      bindings: bindings(helper.sourceSha256),
    }));
  for (const [file, actual] of runtime) {
    requireObservation(actual.runtime?.sha256);
    components.push({
      id: id(file),
      role: "dependency",
      sha256: actual.runtime.sha256,
      format: "macho-x64",
      loader: actual.runtime.macho.dependencies.map(id),
      bindings: bindings(actual.runtime.signatureSha256),
    });
  }
  components.push({
    id: "dyld",
    role: "dependency",
    sha256: inputs.loader.sha256,
    format: "macho-x64",
    loader: inputs.loader.macho.dependencies.map(id),
    bindings: bindings(inputs.loader.sha256),
  });
  const expected = {
      binding: prepared.binding,
      sources: prepared.sources.map(({ name, sha256 }) => ({
        id: name.replace(/\.c$/u, ""),
        sha256,
      })),
      tools: build.tools.map(({ name, sha256 }) => ({
        id: name,
        sha256,
        version:
          name === "compiler"
            ? build.commands[0].stdout.split("\n")[0]
            : name === "sdk"
              ? build.sdk.build
              : prepared.binding.osBuild + ":" + sha256,
      })),
      sdk: { build: build.sdk.build, sha256: build.sdk.sha256 },
      components,
    },
    identities = new Map(
      build.helpers.map(({ name, identity }) => [name, identity]),
    );
  for (const [file, actual] of runtime)
    identities.set(id(file), actual.object.identity);
  identities.set("dyld", inputs.loader.identity);
  return normalizeExperimentPreparation(
    {
      purpose: "experiment",
      expected,
      observed: {
        ...expected,
        components: components.map(({ role, ...component }) => ({
          ...component,
          identityBefore: digest(identities.get(component.id)),
          identityAfter: digest(identities.get(component.id)),
          held: true,
          independent: true,
        })),
        independent: true,
        readSha256,
      },
    },
    build.context,
  );
}

/** Complete preparation stays admitted until every declaration is sealed and
 * its native input observer has independently retired. No case is executed. */
export async function prepareDarwinExperiment(
  input,
  directory,
  persist,
  options = {},
) {
  let job = normalizeExperimentJob(input),
    state,
    closed = false,
    primary;
  const save = async (value) => {
    await persist(value);
    job = value;
  };
  try {
    const built = await prepareDarwinExperimentBuild(
        job,
        directory,
        async (value) => {
          // The private build receipt remains available for cold verification, but
          // it cannot settle the still-active whole preparation admission.
          if (!retired(value.preparationEffects.settlement)) await save(value);
        },
        options,
      ),
      base = darwinExperimentBuildInput(built.prepared, built.job, directory);
    state = darwinPreparationContext(base, options);
    const { reader } = await state.bootstrap(options.signal);
    let sequence = 0;
    const journal = (record) =>
        state.write(`experiment-input-${sequence++}.json`, record),
      acquisition = await (
        options.acquireCases ?? acquireDarwinExperimentInputs
      )(built.prepared, built.build, reader, journal, options),
      system = await prepareDarwinExperimentCases(
        built.prepared,
        built.build,
        acquisition.inputs,
        acquisition.publish,
      ),
      preparation = {
        purpose: "experiment",
        prepared: built.prepared,
        buildJob: built.job,
        build: built.build,
        inputs: acquisition.inputs,
        system,
        observation: observation(
          built.prepared,
          built.build,
          acquisition.inputs,
          built.readSha256,
        ),
        recipes: darwinSystemRecipes(),
      };
    systemInput(job, preparation);
    const pin = await state.write(
      "darwin-experiment-preparation.json",
      preparation,
      false,
    );
    await reader.verifyBuildReceipt(pin);
    const close = {
      purpose: "experiment",
      ...(await state.releaseBootstrap()),
    };
    closed = true;
    requireObservation(
      retired(close) && close.purpose === "experiment" && close.closed === true,
    );
    await state.write("darwin-experiment-preparation-close.json", close, false);
    await save(
      recordExperimentPreparation(
        job,
        preparation.observation.expected,
        preparation.observation.observed,
      ),
    );
    await save(
      recordExperimentPreparationEffect(job, {
        admission: "possible",
        settlement: {
          status: "RETIRED",
          independent: true,
          emergencyCleanup: false,
        },
        receiptSha256: observationDigest({ preparation, close }),
      }),
    );
    return { job, preparation: { ...preparation, close } };
  } catch (cause) {
    primary = cause;
    try {
      await save(
        normalizeExperimentJob({
          ...job,
          failure: job.failure ?? "preparation-failed",
        }),
      );
    } catch (error) {
      nativeException("darwin-experiment-preparation-failure", error);
    }
    throw cause;
  } finally {
    if (state && !closed)
      try {
        requireObservation(retired(await state.releaseBootstrap()));
      } catch (cause) {
        if (!primary) throw cause;
        nativeException("darwin-experiment-preparation-cleanup", cause);
      }
  }
}

export async function loadDarwinExperiment(input, directory, options = {}) {
  const job = normalizeExperimentJob(input),
    fs = options.fs ?? filesystem;
  darwinExperimentWorker(job, options.binding, options);
  requireObservation(
    job.preparation && retired(job.preparationEffects.settlement),
  );
  const preparationBytes = await fs.readFile(
      path.join(directory, "darwin-experiment-preparation.json"),
    ),
    closeBytes = await fs.readFile(
      path.join(directory, "darwin-experiment-preparation-close.json"),
    );
  requireObservation(
    preparationBytes.length <= 1048576 && closeBytes.length <= 1048576,
  );
  const preparation = JSON.parse(preparationBytes),
    close = JSON.parse(closeBytes);
  requireObservation(
    observationDigest({ preparation, close }) ===
      job.preparationEffects.receiptSha256 &&
      retired(close) &&
      close.purpose === "experiment" &&
      close.closed &&
      observationDigest(preparation.observation) ===
        observationDigest(job.preparation) &&
      preparation.prepared.directory === directory,
  );
  const fresh = await loadDarwinExperimentBuild(
    preparation.buildJob,
    directory,
    options,
  );
  requireObservation(
    observationDigest(fresh.build) === observationDigest(preparation.build),
  );
  const settings = selectors(preparation, options),
    state = darwinPreparationContext(systemInput(job, preparation), settings);
  let primary;
  try {
    // Rejoin the protected original preparation receipts through a distinct native reader.
    await state.receipt(
      path.join(directory, "darwin-experiment-preparation.json"),
    );
    await state.receipt(
      path.join(directory, "darwin-experiment-preparation-close.json"),
    );
    const { reader } = await state.bootstrap(options.signal);
    for (const { path, sha256 } of preparation.system.uploads)
      await reader.readBuildInput(path, sha256);
    for (const value of [
      preparation.inputs.git,
      preparation.inputs.pfctl,
      preparation.inputs.hdiutil,
      preparation.inputs.loader,
      preparation.inputs.volume,
    ])
      await reader.readBuildInput(value.path, value.sha256);
    return { job, preparation: { ...preparation, close } };
  } catch (cause) {
    primary = cause;
    throw cause;
  } finally {
    try {
      requireObservation(retired(await state.releaseBootstrap()));
    } catch (cause) {
      if (!primary) throw cause;
      nativeException("darwin-experiment-load-cleanup", cause);
    }
  }
}

export function createDarwinExperimentSystemEffects(
  job,
  preparation,
  options = {},
) {
  job = normalizeExperimentJob(job);
  const { close, ...record } = preparation;
  requireObservation(
    job.preparation &&
      retired(close) &&
      close.purpose === "experiment" &&
      close.closed &&
      retired(job.preparationEffects.settlement) &&
      observationDigest(job.preparation) ===
        observationDigest(preparation.observation) &&
      observationDigest({ preparation: record, close }) ===
        job.preparationEffects.receiptSha256,
  );
  return createDarwinSystemEffects(
    systemInput(job, preparation),
    selectors(preparation, options),
  );
}

/** Rejoin original build and case journals independently. Recovery never executes
 * a recipe or promotes an unsuccessful observation to experiment success. */
export async function recoverDarwinExperimentPreparation(
  input,
  directory,
  persist,
  options = {},
) {
  const job = normalizeExperimentJob(input),
    fs = options.fs ?? filesystem;
  darwinExperimentWorker(job, options.binding, options);
  if (job.preparationEffects.admission === "not-started") return job;
  let result, preparationReceiptSha256;
  try {
    const bytes = await fs.readFile(
      path.join(directory, "darwin-experiment-preparation.json"),
    );
    requireObservation(bytes.length <= 1048576);
    const preparation = JSON.parse(bytes),
      owner = createDarwinSystemEffects(
        systemInput(job, preparation),
        selectors(preparation, options),
      ),
      request = {
        candidateSha: job.candidateSha,
        platform: "darwin",
        jobSha256: observationDigest(job),
        preparationSha256: observationDigest(preparation),
      };
    result = await owner.recover({
      request,
      job,
      preparation,
      signal: options.signal,
    });
    if (retired(result) && job.preparation !== null) {
      const closeBytes = await fs.readFile(
        path.join(directory, "darwin-experiment-preparation-close.json"),
      );
      requireObservation(closeBytes.length <= 1048576);
      const close = JSON.parse(closeBytes);
      requireObservation(
        retired(close) &&
          close.purpose === "experiment" &&
          close.closed &&
          observationDigest(preparation.observation) ===
            observationDigest(job.preparation),
      );
      preparationReceiptSha256 = observationDigest({ preparation, close });
      if (retired(job.preparationEffects.settlement))
        requireObservation(
          preparationReceiptSha256 === job.preparationEffects.receiptSha256,
        );
    }
  } catch (cause) {
    nativeException("darwin-experiment-case-recovery", cause);
    if (result) result = { ...result, status: "RETAINED", independent: false };
  }
  if (!result) {
    const names = await fs.readdir(directory).catch((cause) => {
      if (cause.code === "ENOENT") return [];
      throw cause;
    });
    const build = await recoverDarwinExperimentBuild(
      job,
      directory,
      async (value) => {
        if (!retired(value.preparationEffects.settlement)) await persist(value);
      },
      options,
    );
    result = names.some((name) => name.startsWith("darwin-case-"))
      ? {
          status: "RETAINED",
          independent: false,
          emergencyCleanup: false,
          nativeEventSha256: observationDigest({ missingCaseSelectors: true }),
        }
      : {
          ...build.preparationEffects.settlement,
          nativeEventSha256: build.preparationEffects.receiptSha256,
        };
  }
  const settled =
    retired(result) && !job.preparationEffects.settlement.emergencyCleanup;
  const effect = {
    admission: "possible",
    settlement: {
      status: settled ? "RETIRED" : "RETAINED",
      independent: settled,
      emergencyCleanup: job.preparationEffects.settlement.emergencyCleanup,
    },
    receiptSha256: settled
      ? (preparationReceiptSha256 ?? observationDigest(result))
      : null,
  };
  // Later cold readers have original native admissions after preparation has
  // retired. Their uncertainty reopens cleanup without replacing observed
  // preparation or its original receipt with a recovery observation.
  const recovery =
    job.preparationEffects.settlement.status === "RETIRED"
      ? settled
        ? job
        : normalizeExperimentJob({
            ...job,
            preparationEffects: effect,
            failure: job.failure ?? "cleanup-failed",
          })
      : recordExperimentPreparationEffect(job, effect);
  await persist(recovery);
  return recovery;
}
