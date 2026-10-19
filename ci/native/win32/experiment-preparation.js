import { win32 as path } from "node:path";
import { nativeException } from "../diagnostics.js";
import { readFile } from "node:fs/promises";
import {
  normalizeExperimentJob,
  normalizeExperimentPreparation,
  recordExperimentPreparationEffect,
  recordExperimentPreparation,
  recordExperimentRecovery,
  observationDigest,
  observationObject,
  requireObservation,
} from "../index.js";
import { digest, hash, sameWindowsIdentity } from "./protocol.js";
import { encode, windowsClosedPreparationOwner } from "./custody-protocol.js";
import { windowsSystemRecipes } from "./system.js";
import {
  bootstrapWindowsExperiment,
  openWindowsExperimentNative,
} from "./experiment-native.js";
import {
  prepareWindowsExperimentCases,
  windowsExperimentDependencies,
} from "./experiment-cases.js";
import { inspectWindowsExperimentPe } from "./experiment-image.js";
import { createWindowsPreparationFiles } from "./preparation-files.js";
import {
  normalizeWindowsExperimentPreparation,
  recoverWindowsPreparationOwners,
} from "./preparation.js";
import { normalizeNativePolicyBinding } from "./experiment-policy.js";
import { createWindowsSystemEffects } from "./effects.js";
import { windowsExperimentBuildInventory } from "./experiment-build-inputs.js";

export { windowsExperimentBuildInventory };

const retired = (value) =>
  value?.status === "RETIRED" &&
  value.independent === true &&
  value.emergencyCleanup === false &&
  hash(value.nativeEventSha256);
const retained = () => ({
  status: "RETAINED",
  independent: false,
  emergencyCleanup: false,
});

function worker(
  job,
  binding,
  env,
  platform,
  architecture,
  cleanup = false,
  nodeVersion = process.version,
) {
  requireObservation(
    job.platform === "win32" &&
      platform === "win32" &&
      architecture === "x64" &&
      env.CI === "true" &&
      env.GITHUB_ACTIONS === "true" &&
      /^win25(?:-vs2026)?$/u.test(env.ImageOS) &&
      env.RUNNER_ENVIRONMENT === "github-hosted" &&
      env.RUNNER_OS === "Windows" &&
      env.GITHUB_REPOSITORY === job.repository &&
      env.GITHUB_RUN_ID === job.runId &&
      env.GITHUB_RUN_ATTEMPT === String(job.runAttempt) &&
      (cleanup ||
        (binding?.checkoutSha === job.candidateSha &&
          binding.osBuild === "10.0.26100" &&
          binding.nodeVersion === "v24.21.0" &&
          nodeVersion === binding.nodeVersion)),
  );
}

function windowsExperimentBuildBinding(prepared, outputDaclSha256) {
  requireObservation(hash(outputDaclSha256));
  return {
    purpose: "experiment",
    context: prepared.bootstrap.context,
    template: {
      purpose: "experiment",
      schemaVersion: 1,
      candidateSha: prepared.job.candidateSha,
      platform: "win32",
      sourceSha256: observationDigest(prepared.sources),
      provisioningSha256: prepared.bootstrap.bindingSha256,
      policy: {
        launch: {
          buildSha256: observationDigest({
            commands: prepared.commands,
            versions: prepared.versions,
          }),
        },
        policy: {
          images: prepared.helpers.map(
            ({ name, path, sha256, sourceSha256 }) => ({
              name,
              path,
              sha256,
              sourceSha256,
            }),
          ),
          output: {
            path: prepared.output,
            identitySha256: { binding: "output" },
            daclSha256: outputDaclSha256,
          },
        },
      },
      bindings: [
        {
          id: "output",
          kind: "custody",
          paths: [["policy", "output", "identitySha256"]],
          minimum: null,
          maximum: null,
        },
      ],
    },
  };
}

async function observeBuild(
  prepared,
  binding,
  native,
  commands,
  versions,
  readInstalled = readFile,
) {
  windowsExperimentBuildInventory(prepared);
  const proofs = [],
    actualHelpers = new Map();
  const held = async (file, sha256, installed = false) => {
    const read = installed
      ? await native.readInput(file)
      : await native.read(file, sha256);
    requireObservation(
      Buffer.isBuffer(read.bytes) &&
        read.independent &&
        read.held &&
        read.unchanged &&
        read.protectedDacl &&
        read.protectedParents &&
        hash(read.identitySha256) &&
        hash(read.nativeEventSha256) &&
        (!sha256 || digest(read.bytes) === sha256),
    );
    proofs.push(read.nativeEventSha256);
    return read;
  };
  for (const source of prepared.sources)
    await held(path.join(prepared.sourceDirectory, source.name), source.sha256);
  for (const tool of prepared.tools)
    requireObservation(digest(await readInstalled(tool.path)) === tool.sha256);
  const sdkInput = await held(
    prepared.sdkHeader.file,
    prepared.sdkHeader.sha256,
    true,
  );
  for (const helper of prepared.helpers) {
    const read = await native.readImage(helper.path);
    requireObservation(
      read.independent &&
        read.held &&
        read.unchanged &&
        read.protectedDacl &&
        read.protectedParents &&
        digest(read.bytes) === helper.sha256,
    );
    proofs.push(read.nativeEventSha256);
    inspectWindowsExperimentPe(read.bytes);
    actualHelpers.set(helper.name, read);
  }
  const sdk = {
      build: prepared.sdkBuild,
      sha256: observationDigest({
        build: prepared.sdkBuild,
        header: {
          file: prepared.sdkHeader.file,
          sha256: digest(sdkInput.bytes),
        },
      }),
    },
    tools = prepared.tools.map((tool) => ({
      id: tool.name,
      sha256: tool.sha256,
      version: versions[tool.name],
    })),
    build = observationDigest(commands),
    abi = sdk.sha256,
    components = [],
    reads = [];
  const add = (id, read, source) => {
    const component = {
      id,
      role: "helper",
      sha256: digest(read.bytes),
      format: "pe-x64",
      loader: [],
      bindings: { source, build, abi },
    };
    components.push(component);
    const { role: _role, ...observed } = component;
    reads.push({
      ...observed,
      identityBefore: read.identitySha256,
      identityAfter: read.identitySha256,
      held: true,
      independent: true,
    });
  };
  for (const helper of prepared.helpers)
    add(helper.name, actualHelpers.get(helper.name), helper.sourceSha256);
  const sources = prepared.sources.map((source) => ({
      id: source.name.endsWith(".c") ? source.name.slice(0, -2) : source.name,
      sha256: source.sha256,
    })),
    expected = { binding, sources, tools, sdk, components },
    observation = normalizeExperimentPreparation(
      {
        purpose: "experiment",
        expected,
        observed: {
          binding,
          sources,
          tools,
          sdk,
          components: reads,
          independent: true,
          readSha256: observationDigest(proofs),
        },
      },
      Object.fromEntries(
        ["candidateSha", "platform", "repository", "runId", "runAttempt"].map(
          (key) => [key, prepared.job[key]],
        ),
      ),
    );
  return {
    observation,
    sdkInputs: [
      { file: prepared.sdkHeader.file, sha256: digest(sdkInput.bytes) },
    ],
  };
}

/** Only matching disposable Windows CI may create the ordinary local inventory. */
export async function prepareWindowsExperiment(
  input,
  directory,
  persist,
  options = {},
) {
  let job = normalizeExperimentJob(input),
    native,
    prepared,
    primary;
  const binding = options.binding,
    env = options.env ?? process.env;
  worker(
    job,
    binding,
    env,
    options.platform ?? process.platform,
    options.architecture ?? process.arch,
    false,
    options.nodeVersion ?? process.version,
  );
  requireObservation(typeof persist === "function" && job.preparation === null);
  const save = async (value) => {
    await persist(value);
    job = value;
  };
  await save(
    recordExperimentPreparationEffect(job, {
      admission: "possible",
      settlement: retained(),
      receiptSha256: null,
    }),
  );
  try {
    prepared = await (options.bootstrap ?? bootstrapWindowsExperiment)(
      job,
      directory,
      binding,
      options,
    );
    windowsExperimentBuildInventory(prepared);
    native = await (options.open ?? openWindowsExperimentNative)(prepared, {
      ...options,
      retain: (owner) => {
        native = owner;
      },
    });
    const { commands, versions } = prepared;
    const observed = await observeBuild(
      prepared,
      binding,
      native,
      commands,
      versions,
      options.readInstalled ?? options.filesystem?.readFile,
    );
    const system = await prepareWindowsExperimentCases(
      prepared,
      observed,
      native,
      options,
    );
    const output = await native.files.readBuildDirectory(prepared.output);
    requireObservation(
      output.independent &&
        output.held &&
        output.protectedParents &&
        hash(output.daclSha256),
    );
    const buildBinding = windowsExperimentBuildBinding(
      prepared,
      output.daclSha256,
    );
    system.bindings.unshift({ id: "build", policyBinding: buildBinding });
    await native.write("windows-experiment-preparation.json", {
      purpose: "experiment",
      schemaVersion: 4,
      prepared,
      commands,
      versions,
      system,
      ...observed,
    });
    const settlement = await native.close();
    requireObservation(retired(settlement));
    await save(
      recordExperimentPreparation(
        job,
        observed.observation.expected,
        observed.observation.observed,
      ),
    );
    await save(
      recordExperimentPreparationEffect(job, {
        admission: "possible",
        settlement: {
          status: settlement.status,
          independent: settlement.independent,
          emergencyCleanup: settlement.emergencyCleanup,
        },
        receiptSha256: observationDigest({
          commands,
          settlement,
          observation: observed.observation,
        }),
      }),
    );
    return {
      job,
      preparation: {
        purpose: "experiment",
        schemaVersion: 4,
        prepared,
        commands,
        versions,
        system,
        ...observed,
        settlement,
        recipes: windowsSystemRecipes(),
      },
    };
  } catch (error) {
    primary = error;
    const cleanupFailures = [],
      signal = AbortSignal.timeout(30000),
      reportCleanup = (cause) => {
        cleanupFailures.push(cause);
        try {
          nativeException("windows-experiment-preparation-cleanup", cause);
        } catch {
          /* preserve both failures */
        }
      };
    try {
      nativeException("windows-experiment-preparation", error);
    } catch {
      /* Preserve the original cause and independent cleanup. */
    }
    native ??= error?.experimentNative;
    // Failed/partial native startup never becomes retirement by catching an
    // exception. Retain its write-ahead intent and original first cause.
    if (native) {
      let settlement;
      try {
        settlement = await native.close({ signal });
      } catch (cleanup) {
        reportCleanup(cleanup);
        settlement = cleanup?.settlement;
      }
      try {
        if (retired(settlement))
          await save(
            recordExperimentPreparationEffect(job, {
              admission: "possible",
              settlement: {
                status: settlement.status,
                independent: settlement.independent,
                emergencyCleanup: settlement.emergencyCleanup,
              },
              receiptSha256: observationDigest(settlement),
            }),
          );
      } catch (cleanup) {
        reportCleanup(cleanup);
      }
    }
    const failedJob = { ...job, failure: job.failure ?? "preparation-failed" };
    try {
      await save(failedJob);
    } catch (cleanup) {
      reportCleanup(cleanup);
    }
    throw Object.assign(
      new Error("Windows experiment preparation failed", { cause: primary }),
      { experimentJob: failedJob, cleanupFailures },
    );
  }
}

/** The manifest-shaped private view contains selectors, never a reviewed
 * manifest or operator authority. Existing case owners retain native admission. */
export function windowsExperimentSystemInput(job, preparation) {
  requireObservation(
    job.purpose === "experiment" &&
      preparation.purpose === "experiment" &&
      preparation.schemaVersion === 4 &&
      retired(preparation.settlement),
  );
  const { prepared, system } = preparation;
  windowsExperimentBuildInventory(prepared);
  requireObservation(
    system.purpose === "experiment" &&
      system.bindings.length === windowsSystemRecipes().length,
  );
  observationObject(system.dependencies, ["payload", "git"]);
  requireObservation(
    Object.values(system.dependencies).every(
      (images) => Array.isArray(images) && images.length > 0,
    ),
  );
  requireObservation(
    system.dependencies.git[0].path === prepared.gitRuntime.path &&
      system.dependencies.git[0].sha256 === prepared.gitRuntime.sha256,
  );
  for (const [index, recipe] of windowsSystemRecipes().entries()) {
    const entry = system.bindings[index],
      binding = normalizeNativePolicyBinding(entry?.policyBinding);
    requireObservation(
      entry.id === recipe.id &&
        binding.purpose === "experiment" &&
        binding.context.executionId === recipe.id &&
        observationDigest({ ...binding.context, executionId: "build" }) ===
          observationDigest(prepared.bootstrap.context),
    );
  }
  requireObservation(
    prepared.job.candidateSha === job.candidateSha &&
      prepared.job.repository === job.repository &&
      prepared.job.runId === job.runId &&
      prepared.job.runAttempt === job.runAttempt &&
      observationDigest(preparation.observation) ===
        observationDigest(job.preparation),
  );
  const plan = normalizeWindowsExperimentPreparation(
    {
      purpose: "experiment",
      schemaVersion: 3,
      sourceDirectory: prepared.sourceDirectory,
      sources: prepared.sources,
      bootstrap: prepared.bootstrap,
      command: {
        helper: (({ path, sha256, signatureSha256 }) => ({
          path,
          sha256,
          signatureSha256,
        }))(prepared.helpers.find(({ name }) => name === "build-helper")),
      },
      cases: system.cases,
    },
    job.candidateSha,
  );
  return {
    job,
    preparation,
    directory: prepared.directory,
    output: prepared.output,
    manifest: {
      purpose: "experiment",
      candidateSha: job.candidateSha,
      platform: "win32",
      helpers: prepared.helpers,
      tools: prepared.tools,
      environment: prepared.environment,
      windowsPreparation: plan,
    },
  };
}

/** Protected original receipts select cold custody; stored completion supplies
 * no current process, Job or task observation. */
async function closedExperimentObserver(files, prepared, expected) {
  const { directory, output, bootstrap } = prepared;
  const read = async (name) =>
    JSON.parse(
      (
        await files.readProtected({
          file: path.join(directory, name),
          receipt: true,
        })
      ).bytes,
    );
  const close = await read("windows-experiment-close.json");
  observationObject(close, ["purpose", "schemaVersion", "observer"]);
  requireObservation(
    close.purpose === "experiment" && close.schemaVersion === 3,
  );
  const observer = close.observer;
  observationObject(observer, ["nonce", "helper", "bridge", "taskSha256"]);
  requireObservation(
    /^[a-f0-9]{32}$/u.test(observer.nonce) && hash(observer.taskSha256),
  );
  const birth = await read(`windows-files-${observer.nonce}-birth.json`),
    result = await read(`windows-files-${observer.nonce}-result.json`),
    owner = windowsClosedPreparationOwner(birth, result),
    intent = await read(`windows-files-${observer.nonce}-intent.json`);
  observationObject(intent, ["schemaVersion", "argumentsHex", "status"]);
  requireObservation(
    intent.schemaVersion === 1 &&
      intent.status === "POSSIBLE" &&
      observationDigest(intent.argumentsHex) ===
        observationDigest(
          [
            "--observe",
            bootstrap.reader.path,
            bootstrap.reader.sha256,
            bootstrap.reader.signatureSha256,
            bootstrap.plan.path,
            bootstrap.plan.sha256,
            observer.nonce,
            bootstrap.runnerSid,
            directory,
            output,
          ].map(encode),
        ),
  );
  owner.receiptsSha256 = observationDigest({ close, intent, birth, result });
  for (const value of [observer, ...(expected ? [expected] : [])])
    requireObservation(
      value.nonce === owner.nonce &&
        value.taskSha256 === owner.taskSha256 &&
        sameWindowsIdentity(value.helper, owner.identities[0]) &&
        sameWindowsIdentity(value.bridge, owner.identities[1]),
    );
  return {
    observer,
    owner,
    nativeEventSha256: observationDigest({ close, birth, result }),
  };
}

/** Cold verification reads existing outputs and original case-custody births;
 * ordinary compiler commands have no System worker or retirement receipts. */
export async function verifyWindowsExperimentBuild(
  input,
  { files, signal, readInstalled, exists } = {},
) {
  const { job, preparation } = input,
    { prepared, commands, versions, settlement } = preparation;
  windowsExperimentSystemInput(job, preparation);
  requireObservation(files && retired(settlement));
  files.beginVerification(signal);
  const actual = [];
  requireObservation(
    settlement.observer?.helper && settlement.observer?.bridge,
  );
  const original = await closedExperimentObserver(
    files,
    prepared,
    settlement.observer,
  );
  const retiredDomains = await files.verify(
    "verifyColdPreparation",
    prepared.bootstrap,
    [original.owner],
  );
  requireObservation(
    retired(retiredDomains) &&
      retiredDomains.noLiveMembers &&
      retiredDomains.tasksRemoved,
  );
  const native = {
    read: (file, sha256) => files.readProtected({ file, sha256 }),
    readInput: (file) => files.readExperimentInput(file),
    readImage: (file, installed) => files.readExperimentImage(file, installed),
    resolveImport: (name, image) => files.resolveExperimentImport(name, image),
  };
  const observed = await observeBuild(
    prepared,
    job.preparation.expected.binding,
    native,
    commands,
    versions,
    readInstalled,
  );
  requireObservation(
    observationDigest(observed.observation.expected) ===
      observationDigest(job.preparation.expected),
  );
  requireObservation(
    observationDigest(
      await windowsExperimentDependencies(prepared, native, { exists }),
    ) === observationDigest(preparation.system.dependencies),
  );
  actual.push(
    observed.observation.observed.readSha256,
    retiredDomains.nativeEventSha256,
  );
  return {
    purpose: "experiment",
    status: "OBSERVED",
    independent: true,
    prepared,
    commands,
    settlement: retiredDomains,
    components: observed.observation.observed.components,
    nativeEventSha256: observationDigest(actual),
  };
}

export function createWindowsExperimentSystemEffects(
  job,
  preparation,
  options = {},
  owners = new Map(),
) {
  const input = windowsExperimentSystemInput(job, preparation);
  let current, activeId, preparedCase, cause;
  const create = () => {
    const key = observationDigest({
        context: input.manifest.windowsPreparation.bootstrap.context,
        manifest: input.manifest,
        output: input.output,
        directory: input.directory,
      }),
      files = owners.get(key) ?? createWindowsPreparationFiles(input, options);
    owners.set(key, files);
    return createWindowsSystemEffects(
      input,
      {
        ...options,
        verifyExperimentBuild: (state, settings) =>
          verifyWindowsExperimentBuild(state, {
            files,
            exists: options.exists,
            readInstalled:
              options.readInstalled ?? options.filesystem?.readFile,
            ...settings,
          }),
      },
      owners,
    );
  };
  const begin = (id) => {
    requireObservation(!current);
    activeId = id;
    current = create();
    return current;
  };
  return {
    get cause() {
      return cause ?? current?.cause;
    },
    build: (request) => begin("build").build(request),
    async prepare(recipe, settings) {
      preparedCase = await begin(recipe.id).prepare(recipe, settings);
      preparedCase.purpose = "experiment";
      return preparedCase;
    },
    literal: (...args) => {
      requireObservation(current);
      return current.literal(...args);
    },
    persistReceipt: (...args) => {
      requireObservation(current);
      return current.persistReceipt(...args);
    },
    async settle(recipe, prepared, settings) {
      requireObservation(
        current &&
          activeId === recipe.id &&
          (recipe.id === "build" || prepared === preparedCase),
      );
      const result = await current.settle(recipe, prepared, settings);
      if (
        Object.values(result).every(
          (entry) =>
            entry === null ||
            (entry.settlement.status === "RETIRED" &&
              entry.settlement.independent &&
              !entry.settlement.emergencyCleanup),
        )
      ) {
        current = null;
        activeId = null;
        preparedCase = null;
      }
      return result;
    },
    async recover(request) {
      const owner = current ?? create(),
        result = await owner.recover(request);
      cause ??= owner.cause;
      if (retired(result)) {
        current = null;
        activeId = null;
        preparedCase = null;
      }
      return result;
    },
  };
}

async function publicationSelector(job, directory, options) {
  const bytes = await (options.read ?? readFile)(directory + "-selector.json");
  requireObservation(Buffer.isBuffer(bytes) && bytes.length <= 1048576);
  const prepared = JSON.parse(bytes);
  windowsExperimentBuildInventory(prepared);
  requireObservation(
    prepared.directory === directory &&
      prepared.job.candidateSha === job.candidateSha &&
      prepared.job.repository === job.repository &&
      prepared.job.runId === job.runId &&
      prepared.job.runAttempt === job.runAttempt,
  );
  return prepared;
}

/** Reuse native whole-Job and owned-task recovery even before case construction
 * finishes. Incomplete publication or missing original birth acknowledgements
 * retain uncertainty; recovery never rebuilds, reseals, or retries a case. */
export async function recoverWindowsExperimentPreparation(
  input,
  directory,
  persist,
  options = {},
) {
  const job = normalizeExperimentJob(input);
  worker(
    job,
    options.binding ?? job.preparation?.expected.binding,
    options.env ?? process.env,
    options.platform ?? process.platform,
    options.architecture ?? process.arch,
    true,
  );
  requireObservation(typeof persist === "function");
  if (
    job.preparationEffects.admission === "not-started" ||
    job.preparationEffects.settlement.status === "RETIRED"
  )
    return job;
  let result;
  try {
    const prepared = await publicationSelector(job, directory, options),
      plan = {
        purpose: "experiment",
        schemaVersion: 3,
        bootstrap: prepared.bootstrap,
      },
      input = {
        job,
        directory,
        output: prepared.output,
        manifest: {
          purpose: "experiment",
          candidateSha: job.candidateSha,
          platform: "win32",
          helpers: prepared.helpers,
          tools: prepared.tools,
          environment: prepared.environment,
          windowsPreparation: {
            ...plan,
            sourceDirectory: prepared.sourceDirectory,
            sources: prepared.sources,
          },
        },
      };
    // Cleanup has its own finite signal; a failed preparation signal cannot
    // cancel original-owner recovery before its first independent attempt.
    result = await recoverWindowsPreparationOwners(input, options, {
      signal: AbortSignal.timeout(30000),
    });
    requireObservation(retired(result));
  } catch (cause) {
    try {
      nativeException("windows-experiment-preparation-recovery", cause);
    } catch {
      /* retain uncertainty */
    }
    result = retained();
  }
  const settled = recordExperimentPreparationEffect(job, {
    admission: "possible",
    settlement: {
      status: result.status,
      independent: result.independent,
      emergencyCleanup: result.emergencyCleanup,
    },
    receiptSha256: retired(result) ? observationDigest(result) : null,
  });
  await persist(settled);
  return settled;
}

/** The private publication selector supplies expectations only. Protected
 * contents and original observer births are re-read by a fresh System owner. */
async function withWindowsExperimentPreparation(
  input,
  directory,
  options,
  read,
) {
  const job = normalizeExperimentJob(input);
  worker(
    job,
    job.preparation?.expected.binding,
    options.env ?? process.env,
    options.platform ?? process.platform,
    options.architecture ?? process.arch,
    false,
    options.nodeVersion ?? process.version,
  );
  requireObservation(
    job.preparation && job.preparationEffects.settlement.status === "RETIRED",
  );
  const prepared = await publicationSelector(job, directory, options);
  const files =
    options.files ??
    createWindowsPreparationFiles(
      {
        job,
        directory,
        output: prepared.output,
        manifest: {
          helpers: prepared.helpers,
          windowsPreparation: { bootstrap: prepared.bootstrap },
        },
      },
      options,
    );
  let primary;
  try {
    const record = JSON.parse(
        (
          await files.readProtected({
            file: path.join(directory, "windows-experiment-preparation.json"),
            receipt: true,
          })
        ).bytes,
      ),
      preparation = {
        purpose: "experiment",
        ...record,
        settlement: job.preparationEffects.settlement,
      };
    observationObject(record, [
      "purpose",
      "schemaVersion",
      "prepared",
      "commands",
      "versions",
      "system",
      "observation",
      "sdkInputs",
    ]);
    requireObservation(
      record.purpose === "experiment" && record.schemaVersion === 4,
    );
    // The preparation close is itself protected; the job digest alone cannot
    // establish original helper/observer identities or whole-domain settlement.
    const original = await closedExperimentObserver(files, prepared);
    // Stored completion selects the explicit cold lane; fresh native proof is
    // still required before success or dependent-reader release.
    preparation.settlement = {
      ...job.preparationEffects.settlement,
      observer: original.observer,
      nativeEventSha256: original.nativeEventSha256,
    };
    requireObservation(
      observationDigest(record.prepared) === observationDigest(prepared) &&
        observationDigest(record.prepared.bootstrap) ===
          observationDigest(prepared.bootstrap),
    );
    return await read(job, preparation, files);
  } catch (error) {
    primary = error;
    throw error;
  } finally {
    try {
      requireObservation(retired(await files.settleFiles()));
    } catch (error) {
      if (primary && primary !== error)
        throw new AggregateError(
          [primary, error],
          "Windows experiment loading and cleanup failed",
          { cause: primary },
        );
      throw error;
    }
  }
}

/** Cold loading still requires complete held build and runtime verification. */
export function loadWindowsExperiment(input, directory, options = {}) {
  return withWindowsExperimentPreparation(
    input,
    directory,
    options,
    async (job, preparation, files) => {
      const verified = await verifyWindowsExperimentBuild(
        windowsExperimentSystemInput(job, preparation),
        {
          files,
          exists: options.exists,
          signal: options.signal,
          readInstalled: options.readInstalled ?? options.filesystem?.readFile,
        },
      );
      return { job, preparation, runtime: verified.components };
    },
  );
}

/** A fresh native system owner rejoins original case births and held receipts.
 * Final build/runtime reads cannot gate recovery. Protected selectors provide
 * no new retirement proof, and preparation recovery cannot close case admissions. */
export async function recoverWindowsExperimentProofs(
  input,
  directory,
  persist,
  options = {},
) {
  const job = normalizeExperimentJob(input);
  const preparation = await withWindowsExperimentPreparation(
      job,
      directory,
      options,
      async (_, preparation) => preparation,
    ),
    effects = (options.createEffects ?? createWindowsExperimentSystemEffects)(
      job,
      preparation,
      options,
    ),
    proof = await effects.recover({
      request: {
        candidateSha: job.candidateSha,
        platform: job.platform,
        jobSha256: observationDigest(job),
        preparationSha256: observationDigest(preparation),
      },
      job,
      preparation,
      signal: options.signal,
    });
  const updated = recordExperimentRecovery(job, proof);
  await persist(updated);
  return updated;
}
