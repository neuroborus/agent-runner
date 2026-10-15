import { win32 as path } from "node:path";
import { writeFile, readFile, readdir } from "node:fs/promises";
import {
  normalizeExperimentJob,
  normalizeExperimentPreparation,
  recordExperimentPreparationEffect,
  recordExperimentPreparation,
  observationDigest,
  requireObservation,
} from "../index.js";
import { digest, hash } from "./protocol.js";
import {
  WINDOWS_BUILD_TOOLS,
  WINDOWS_BUILD_LIBRARIES,
  WINDOWS_HELPER_NAMES,
  windowsCompilerArguments,
  windowsBuildOperation,
} from "./build.js";
import { windowsSystemRecipes } from "./system.js";
import {
  bootstrapWindowsExperiment,
  openWindowsExperimentNative,
  WINDOWS_EXPERIMENT_SOURCES,
} from "./experiment-native.js";
import { prepareWindowsExperimentCases } from "./experiment-cases.js";
import { inspectWindowsExperimentPe } from "./experiment-image.js";
import { createWindowsPreparationFiles } from "./preparation-files.js";
import {
  normalizeWindowsExperimentPreparation,
  windowsPreparationOptions,
} from "./preparation.js";
import { normalizeNativePolicyBinding } from "./experiment-policy.js";
import { createWindowsSystemEffects } from "./effects.js";
import { createWindowsCaseProvisioning } from "./case-provisioning.js";

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

export function windowsExperimentBuildInventory(prepared) {
  requireObservation(
    prepared?.purpose === "experiment" &&
      prepared.job.platform === "win32" &&
      Array.isArray(prepared.helpers) &&
      prepared.helpers.length === WINDOWS_HELPER_NAMES.length &&
      new Set(prepared.helpers.map(({ name }) => name)).size ===
        WINDOWS_HELPER_NAMES.length &&
      Array.isArray(prepared.sources) &&
      prepared.sources.length === WINDOWS_EXPERIMENT_SOURCES.length &&
      new Set(prepared.sources.map(({ name }) => name)).size ===
        WINDOWS_EXPERIMENT_SOURCES.length &&
      prepared.tools.length === WINDOWS_BUILD_TOOLS.length,
  );
  for (const name of WINDOWS_EXPERIMENT_SOURCES)
    requireObservation(
      prepared.sources.some(
        (source) => source.name === name && hash(source.sha256),
      ),
    );
  for (const name of WINDOWS_HELPER_NAMES) {
    const helper = prepared.helpers.find((helper) => helper.name === name);
    requireObservation(
      helper &&
        hash(helper.sha256) &&
        helper.sourceSha256 ===
          prepared.sources.find((source) => source.name === name + ".c").sha256,
    );
  }
  for (const [index, recipe] of WINDOWS_BUILD_TOOLS.entries()) {
    const tool = prepared.tools[index];
    requireObservation(
      tool &&
        tool.name === recipe.name &&
        recipe.path.test(tool.path) &&
        hash(tool.sha256) &&
        hash(tool.signatureSha256),
    );
  }
  return windowsSystemRecipes();
}

/** Typed MSVC dependency output is private data. Reject missing sources,
 * modules, foreign paths and unbounded lists rather than guessing SDK closure. */
export function windowsExperimentDependencies(bytes, source, directory) {
  requireObservation(
    Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= 1048576,
  );
  const value = JSON.parse(
    new TextDecoder("utf-8", { fatal: true })
      .decode(bytes)
      .replace(/^\uFEFF/u, ""),
  );
  requireObservation(
    value.Version === "1.2" &&
      value.Data?.Source === source &&
      Array.isArray(value.Data.Includes) &&
      value.Data.Includes.length > 0 &&
      value.Data.Includes.length <= 2048 &&
      (!value.Data.ImportedModules ||
        value.Data.ImportedModules.length === 0) &&
      (!value.Data.ImportedHeaderUnits ||
        value.Data.ImportedHeaderUnits.length === 0),
  );
  const files = [...new Set(value.Data.Includes)];
  requireObservation(
    files.every(
      (file) =>
        typeof file === "string" &&
        path.isAbsolute(file) &&
        path.normalize(file) === file &&
        !/[\0\r\n]/u.test(file) &&
        (path.dirname(file) === directory ||
          /^[A-Z]:\\Program Files(?: \(x86\))?\\(?:Microsoft Visual Studio|Windows Kits)\\/u.test(
            file,
          )),
    ),
  );
  return files.sort();
}

async function observeBuild(prepared, binding, native, commands, versions) {
  windowsExperimentBuildInventory(prepared);
  const proofs = [],
    sdkInputs = new Map(),
    actualHelpers = new Map(),
    runtime = [],
    helperLoaders = {};
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
  for (const tool of prepared.tools) await held(tool.path, tool.sha256);
  for (const helper of prepared.helpers) {
    const target = path.join(prepared.output, helper.name + ".exe"),
      read = await native.readImage(target);
    requireObservation(
      read.independent &&
        read.held &&
        read.unchanged &&
        read.protectedDacl &&
        read.protectedParents &&
        digest(read.bytes) === helper.sha256,
    );
    proofs.push(read.nativeEventSha256);
    const image = inspectWindowsExperimentPe(read.bytes);
    await held(helper.path, helper.sha256);
    actualHelpers.set(helper.name, { read, image });
    const dependencies = await held(target + ".deps.json");
    for (const file of windowsExperimentDependencies(
      dependencies.bytes,
      path.join(prepared.sourceDirectory, helper.name + ".c"),
      prepared.sourceDirectory,
    )) {
      if (path.dirname(file) === prepared.sourceDirectory) {
        const source = prepared.sources.find(
          (source) => source.name === path.basename(file),
        );
        requireObservation(source);
        await held(file, source.sha256);
      } else if (!sdkInputs.has(file))
        sdkInputs.set(file, await held(file, null, true));
    }
  }
  // Fixed link libraries, linker and compiler implementation are observed data;
  // nothing here asserts authenticated source or release closure.
  for (const name of ["link.exe", "c1.dll", "c1xx.dll", "c2.dll"]) {
    const file = path.join(path.dirname(prepared.tools[0].path), name);
    sdkInputs.set(file, await held(file, null, true));
  }
  for (const name of WINDOWS_BUILD_LIBRARIES) {
    let selected;
    const file = await native.findLibrary(
      name,
      prepared.environment.LIB.split(";").filter(Boolean),
    );
    if (file) selected = { file, read: await held(file, null, true) };
    requireObservation(selected);
    sdkInputs.set(selected.file, selected.read);
  }
  requireObservation(
    commands.length === WINDOWS_HELPER_NAMES.length + 2 &&
      commands.every((command) => retired(command.settlement)),
  );
  const sdk = {
      build: prepared.sdkBuild,
      sha256: observationDigest(
        [...sdkInputs].map(([file, read]) => ({
          file,
          sha256: digest(read.bytes),
          identitySha256: read.identitySha256,
        })),
      ),
    },
    tools = prepared.tools.map((tool) => ({
      id: tool.name,
      sha256: tool.sha256,
      version: versions[tool.name],
    })),
    build = observationDigest(commands),
    abi = sdk.sha256,
    components = [],
    reads = [],
    paths = new Map();
  const add = (id, role, read, imports, source) => {
    const component = {
      id,
      role,
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
    return { component, read, imports, imagePath: null };
  };
  const pending = prepared.helpers.map((helper) => {
    const { read, image } = actualHelpers.get(helper.name);
    const item = add(
      helper.name,
      "helper",
      read,
      read.pe.imports,
      helper.sourceSha256,
    );
    item.imagePath = helper.path;
    runtime.push({
      path: helper.path,
      sha256: helper.sha256,
      signatureSha256: helper.signatureSha256,
      imports: [],
    });
    return item;
  });
  for (let index = 0; index < pending.length; index++) {
    requireObservation(pending.length <= 128);
    const item = pending[index];
    for (const imported of item.imports) {
      const name = imported.name,
        file = await native.resolveImport(imported.host);
      let dependency = paths.get(file.toLowerCase());
      if (!dependency) {
        const read = await native.readImage(file, true),
          id =
            "dll-" +
            path
              .basename(file)
              .toLowerCase()
              .replace(/\.dll$/u, "");
        requireObservation(
          !components.some((component) => component.id === id),
        );
        requireObservation(
          read.independent &&
            read.held &&
            read.unchanged &&
            read.protectedDacl &&
            read.protectedParents &&
            hash(read.signatureSha256),
        );
        proofs.push(read.nativeEventSha256);
        dependency = add(id, "dependency", read, read.pe.imports, sdk.sha256);
        dependency.imagePath = file;
        runtime.push({
          path: file,
          sha256: read.sha256,
          signatureSha256: read.signatureSha256,
          imports: [],
        });
        paths.set(file.toLowerCase(), dependency);
        pending.push(dependency);
      }
      runtime
        .find((image) => image.path === item.imagePath)
        .imports.push({ name, path: file });
      if (!item.component.loader.includes(dependency.component.id))
        item.component.loader.push(dependency.component.id);
    }
    reads.find((read) => read.id === item.component.id).loader = [
      ...item.component.loader,
    ];
  }
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
      prepared.job,
    );
  for (const helper of prepared.helpers) {
    const reached = new Set([helper.path]);
    for (let size = -1; size !== reached.size;) {
      size = reached.size;
      for (const image of runtime)
        if (reached.has(image.path))
          for (const target of image.imports) reached.add(target.path);
    }
    helperLoaders[helper.name] = [...reached].filter(
      (file) => file !== helper.path,
    );
  }
  return {
    observation,
    runtime,
    helperLoaders,
    sdkInputs: [...sdkInputs].map(([file, read]) => ({
      file,
      sha256: digest(read.bytes),
    })),
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
    let bootstrapSequence = 0;
    const persistBootstrap =
      options.persistBootstrap ??
      (async (record) =>
        writeFile(
          `${directory}-bootstrap-${bootstrapSequence++}.json`,
          JSON.stringify(record) + "\n",
          { flag: "wx" },
        ));
    prepared = await (options.bootstrap ?? bootstrapWindowsExperiment)(
      job,
      directory,
      binding,
      persistBootstrap,
      options,
    );
    windowsExperimentBuildInventory(prepared);
    native = await (options.open ?? openWindowsExperimentNative)(prepared, {
      ...options,
      retain: (owner) => {
        native = owner;
      },
    });
    const commands = [],
      versions = {};
    const run = async (tool, args, operation, deadlineMs) => {
      const request = {
          candidateSha: job.candidateSha,
          platform: "win32",
          file: tool.path,
          toolSha256: tool.sha256,
          args,
          cwd: prepared.output,
          env: {
            CI: "true",
            GITHUB_ACTIONS: "true",
            LANG: "C",
            ...prepared.environment,
          },
          deadlineMs,
        },
        result = await native.run(request, operation);
      requireObservation(
        result.independent &&
          result.requestSha256 === observationDigest(request) &&
          result.toolSha256 === tool.sha256 &&
          result.signal === null &&
          result.timedOut === false &&
          retired(result.settlement),
      );
      const accepted =
        operation.mode === "compile"
          ? [0]
          : [
              0,
              ...WINDOWS_BUILD_TOOLS.find((entry) => entry.name === tool.name)
                .versionExitCodes,
            ];
      requireObservation(accepted.includes(result.exitCode));
      const { stdout, stderr, ...receipt } = result;
      commands.push({
        ...receipt,
        stdoutSha256: digest(stdout),
        stderrSha256: digest(stderr),
      });
      return stdout + "\n" + stderr;
    };
    for (const tool of prepared.tools) {
      const recipe = WINDOWS_BUILD_TOOLS.find(
          (entry) => entry.name === tool.name,
        ),
        text = await run(
          tool,
          recipe.args,
          {
            mode: tool.name === "compiler" ? "compiler-version" : "sdk-version",
            tool,
          },
          30000,
        );
      versions[tool.name] =
        tool.name === "compiler"
          ? /Compiler Version ([0-9.]+) for x64/u.exec(text)?.[1]
          : /Version ([0-9.]+)/u.exec(text)?.[1];
      requireObservation(versions[tool.name]);
    }
    for (const helper of prepared.helpers) {
      const source = {
          path: path.join(prepared.sourceDirectory, helper.name + ".c"),
          sha256: helper.sourceSha256,
        },
        target = path.join(prepared.output, helper.name + ".exe"),
        tool = prepared.tools.find((tool) => tool.name === "compiler");
      await run(
        tool,
        windowsCompilerArguments(source.path, target, "experiment"),
        { mode: "compile", tool, helper, source, target },
        60000,
      );
    }
    const observed = await observeBuild(
      prepared,
      binding,
      native,
      commands,
      versions,
    );
    const system = await prepareWindowsExperimentCases(
      prepared,
      observed,
      native,
      options,
    );
    const buildBinding = {
      purpose: "experiment",
      context: prepared.bootstrap.context,
      template: {
        purpose: "experiment",
        schemaVersion: 1,
        candidateSha: job.candidateSha,
        platform: "win32",
        sourceSha256: observationDigest(prepared.sources),
        provisioningSha256: prepared.bootstrap.bindingSha256,
        policy: {
          launch: {},
          policy: { output: { identitySha256: { binding: "output" } } },
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
    const buildProof = await createWindowsCaseProvisioning(
      {
        job,
        directory: prepared.directory,
        output: prepared.output,
        plan: { bootstrap: prepared.bootstrap },
        fs: { readdir: native.files.readdir },
        guard: () => requireObservation(!options.signal?.aborted),
        receipt: async (file) => (await native.read(file)).bytes,
      },
      native.files,
    ).observeBuildPolicy(
      buildBinding,
      { commands, settlement: commands.map(({ settlement }) => settlement) },
      { signal: options.signal },
    );
    const buildPolicy = structuredClone(buildProof.observed.policy);
    buildPolicy.policy.output.identitySha256 = { binding: "output" };
    buildBinding.template.policy = buildPolicy;
    system.bindings.unshift({ id: "build", policyBinding: buildBinding });
    await native.write("windows-experiment-preparation.json", {
      purpose: "experiment",
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
    native ??= error.experimentNative;
    // Failed/partial native startup never becomes retirement by catching an
    // exception. Retain its write-ahead intent and original first cause.
    if (native) {
      try {
        const settlement = await native.close();
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
      } catch {
        /* independent recovery owns unsettled resources */
      }
    }
    await save({ ...job, failure: "preparation-failed" });
    throw Object.assign(
      new Error("Windows experiment preparation failed", { cause: primary }),
      { experimentJob: job },
    );
  }
}

/** The manifest-shaped private view contains selectors, never a reviewed
 * manifest or operator authority. Existing case owners retain native admission. */
export function windowsExperimentSystemInput(job, preparation) {
  requireObservation(
    job.purpose === "experiment" &&
      preparation.purpose === "experiment" &&
      retired(preparation.settlement),
  );
  const { prepared, system } = preparation;
  windowsExperimentBuildInventory(prepared);
  requireObservation(
    system.purpose === "experiment" &&
      system.bindings.length === windowsSystemRecipes().length,
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
      schemaVersion: 1,
      sourceDirectory: prepared.sourceDirectory,
      sources: prepared.sources,
      bootstrap: prepared.bootstrap,
      command: {
        helper: (({ path, sha256, signatureSha256 }) => ({
          path,
          sha256,
          signatureSha256,
        }))(prepared.helpers.find(({ name }) => name === "build-helper")),
        toolSignatures: Object.fromEntries(
          prepared.tools.map(({ name, signatureSha256 }) => [
            name,
            signatureSha256,
          ]),
        ),
        unsignedHelpers: Object.fromEntries(
          prepared.helpers.map(({ name, sha256 }) => [name, sha256]),
        ),
        helperSignatures: Object.fromEntries(
          prepared.helpers.map(({ name, signatureSha256 }) => [
            name,
            signatureSha256,
          ]),
        ),
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

/** Fresh verification rejoins held bytes and every original compiler receipt;
 * it never recompiles or substitutes the current observer for an original owner. */
export async function verifyWindowsExperimentBuild(
  input,
  { files, signal } = {},
) {
  const { job, preparation, manifest, directory } = input,
    { prepared, commands, versions, settlement } = preparation;
  windowsExperimentSystemInput(job, preparation);
  requireObservation(
    files &&
      commands.length === WINDOWS_HELPER_NAMES.length + 2 &&
      retired(settlement),
  );
  const actual = [],
    identities = [],
    originals = [];
  for (const receipt of commands) {
    const prefix = `windows-command-${receipt.requestSha256}`,
      intent = JSON.parse(
        (
          await files.readProtected({
            file: path.join(directory, prefix + "-intent.json"),
            receipt: true,
          })
        ).bytes,
      ),
      record = JSON.parse(
        (
          await files.readProtected({
            file: path.join(directory, prefix + "-result.json"),
            receipt: true,
          })
        ).bytes,
      );
    requireObservation(
      intent.purpose === "experiment" &&
        record.purpose === "experiment" &&
        observationDigest(intent.request) === receipt.requestSha256 &&
        record.result.requestSha256 === receipt.requestSha256,
    );
    windowsBuildOperation(intent.request, manifest, prepared.output);
    const { stdout, stderr, ...saved } = record.result;
    requireObservation(
      observationDigest({
        ...saved,
        stdoutSha256: digest(stdout),
        stderrSha256: digest(stderr),
      }) === observationDigest(receipt) &&
        retired(record.result.settlement) &&
        record.result.independent,
    );
    const workerNames = (await files.readdir(directory)).filter((name) =>
      new RegExp(`^${prefix}-[0-9]+\\.json$`, "u").test(name),
    );
    const workers = [];
    for (const name of workerNames) {
      const record = JSON.parse(
        (
          await files.readProtected({
            file: path.join(directory, name),
            receipt: true,
          })
        ).bytes,
      );
      if (record.phase === "worker-admitted") workers.push(record);
    }
    requireObservation(
      workers.length === 1 &&
        observationDigest(workers[0].compilerPolicy) ===
          observationDigest(receipt.compilerPolicy),
    );
    identities.push(receipt.identity, receipt.helperIdentity);
    originals.push(record.result);
  }
  const owner = settlement.bootstrapSettlement;
  requireObservation(
    retired(owner) && owner.taskRemoved && owner.helper && owner.bridge,
  );
  identities.push(owner.helper, owner.bridge);
  const retiredDomains = await files.verify(
    "verifyPreparation",
    prepared.bootstrap,
    [
      {
        nonce: prepared.bootstrap.nonce,
        identities: [
          ...new Map(
            identities.map((identity) => [
              observationDigest(identity),
              identity,
            ]),
          ).values(),
        ],
      },
      {
        nonce: settlement.observer.nonce,
        identities: [settlement.observer.helper, settlement.observer.bridge],
      },
    ],
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
    resolveImport: (name) => files.resolveExperimentImport(name),
    findLibrary: async (name) =>
      preparation.sdkInputs.find(
        ({ file }) => path.basename(file).toLowerCase() === name.toLowerCase(),
      )?.file,
  };
  const observed = await observeBuild(
    prepared,
    job.preparation.expected.binding,
    native,
    commands,
    versions,
  );
  requireObservation(
    observationDigest(observed.observation.expected) ===
      observationDigest(job.preparation.expected),
  );
  actual.push(
    observed.observation.observed.readSha256,
    retiredDomains.nativeEventSha256,
  );
  return {
    purpose: "experiment",
    status: "OBSERVED",
    independent: true,
    commands: originals,
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
          verifyWindowsExperimentBuild(state, { files, ...settings }),
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
      cause = owner.cause;
      if (retired(result)) {
        current = null;
        activeId = null;
        preparedCase = null;
      }
      return result;
    },
  };
}

async function bootstrapSelector(job, directory, options) {
  const names = await (options.readdir ?? readdir)(path.dirname(directory)),
    prefix = path.basename(directory) + "-bootstrap-",
    journals = names
      .filter(
        (name) =>
          name.startsWith(prefix) &&
          /^[0-9]+\.json$/u.test(name.slice(prefix.length)),
      )
      .sort(
        (a, b) =>
          Number(a.slice(prefix.length, -5)) -
          Number(b.slice(prefix.length, -5)),
      );
  requireObservation(journals.length > 0 && journals.length <= 128);
  let selected;
  for (const [index, name] of journals.entries()) {
    requireObservation(name === prefix + index + ".json");
    const record = JSON.parse(
      await (options.read ?? readFile)(
        path.join(path.dirname(directory), name),
      ),
    );
    requireObservation(record.purpose === "experiment");
    if (record.phase === "bootstrap-seal-possible") {
      requireObservation(!selected);
      selected = record;
    }
  }
  requireObservation(
    selected &&
      selected.directory === directory &&
      selected.bootstrap.context.candidateSha === job.candidateSha &&
      selected.bootstrap.context.runId === job.runId &&
      selected.bootstrap.context.runAttempt === job.runAttempt,
  );
  const prepared = {
    purpose: "experiment",
    job,
    ...selected,
    sourceDirectory: directory + "-bootstrap",
  };
  windowsExperimentBuildInventory(prepared);
  return prepared;
}

/** Reuse native whole-Job and owned-task recovery even before case construction
 * finishes. Unsealed seeds or missing original birth acknowledgements retain
 * uncertainty; recovery never recompiles, reseals, or retries a native case. */
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
  let result, files;
  try {
    const prepared = await bootstrapSelector(job, directory, options),
      plan = { purpose: "experiment", bootstrap: prepared.bootstrap },
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
    files = createWindowsPreparationFiles(input, options);
    const owners = new Map();
    // Pass the same fresh observer to recovery rather than opening an untracked second owner.
    const key = observationDigest({
      context: prepared.bootstrap.context,
      manifest: input.manifest,
      output: input.output,
      directory,
    });
    owners.set(key, files);
    const native = windowsPreparationOptions(input, options, owners),
      names = await files.readdir(directory),
      records = [];
    await files.beginCleanup(options.signal ?? new AbortController().signal);
    for (const name of names.filter((name) =>
      /^windows-(?:files-|bootstrap-|command-)/u.test(name),
    ))
      records.push({
        name,
        record: JSON.parse(
          (
            await files.readProtected({
              file: path.join(directory, name),
              receipt: true,
            })
          ).bytes,
        ),
      });
    requireObservation(records.length > 0);
    result = await native.recover(
      {
        request: { candidateSha: job.candidateSha, platform: "win32" },
        records,
        plan: input.manifest.windowsPreparation,
      },
      { signal: options.signal },
    );
    requireObservation(retired(result));
    const custody = await native.settleFiles();
    requireObservation(retired(custody));
    files = null;
    result.nativeEventSha256 = observationDigest({
      recovery: result.nativeEventSha256,
      custody,
    });
  } catch {
    result = retained();
  } finally {
    if (files)
      try {
        await files.settleFiles();
      } catch {
        /* original uncertainty remains */
      }
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

/** Bootstrap journals are selectors only. Protected contents and original
 * admission receipts are re-read by a fresh System owner before use. */
export async function loadWindowsExperiment(input, directory, options = {}) {
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
  const prepared = await bootstrapSelector(job, directory, options);
  const files =
    options.files ??
    createWindowsPreparationFiles(
      {
        job,
        directory,
        output: prepared.output,
        manifest: { windowsPreparation: { bootstrap: prepared.bootstrap } },
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
    // The preparation close is itself protected; the job digest alone cannot
    // establish original helper/observer identities or whole-domain settlement.
    const close = JSON.parse(
      (
        await files.readProtected({
          file: path.join(directory, "windows-experiment-close.json"),
          receipt: true,
        })
      ).bytes,
    );
    requireObservation(
      close.purpose === "experiment" && retired(close.bootstrapSettlement),
    );
    const birth = JSON.parse(
        (
          await files.readProtected({
            file: path.join(
              directory,
              `windows-files-${close.observer.nonce}-birth.json`,
            ),
            receipt: true,
          })
        ).bytes,
      ),
      result = JSON.parse(
        (
          await files.readProtected({
            file: path.join(
              directory,
              `windows-files-${close.observer.nonce}-result.json`,
            ),
            receipt: true,
          })
        ).bytes,
      );
    requireObservation(
      birth.status === "POSSIBLE" &&
        result.status === "RETIRED" &&
        [birth, result].every(
          (value) =>
            value.nonce === close.observer.nonce &&
            value.taskSha256 === close.observer.taskSha256 &&
            observationDigest(value.helper) ===
              observationDigest(close.observer.helper) &&
            observationDigest(value.bridge) ===
              observationDigest(close.observer.bridge),
        ),
    );
    // Stored completion is a selector; verifyPreparation below observes the
    // original complete Jobs and task absence through this distinct owner.
    preparation.settlement = {
      ...job.preparationEffects.settlement,
      bootstrapSettlement: close.bootstrapSettlement,
      observer: close.observer,
      nativeEventSha256: observationDigest({ close, birth, result }),
    };
    requireObservation(
      observationDigest(record.prepared.bootstrap) ===
        observationDigest(prepared.bootstrap),
    );
    const input = windowsExperimentSystemInput(job, preparation);
    const verified = await verifyWindowsExperimentBuild(input, {
      files,
      signal: options.signal,
    });
    return { job, preparation, runtime: verified.components };
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
