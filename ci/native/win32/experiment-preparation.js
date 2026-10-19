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
import { location } from "./custody-protocol.js";
import { WINDOWS_BUILD_TOOLS, WINDOWS_HELPER_NAMES } from "./build.js";
import { windowsSystemRecipes } from "./system.js";
import {
  bootstrapWindowsExperiment,
  openWindowsExperimentNative,
  WINDOWS_EXPERIMENT_SOURCES,
  windowsHostedCompilerArguments,
} from "./experiment-native.js";
import {
  prepareWindowsExperimentCases,
  windowsExperimentDependencies,
  assertWindowsExperimentGitSelection,
} from "./experiment-cases.js";
import { inspectWindowsExperimentPe } from "./experiment-image.js";
import { createWindowsPreparationFiles } from "./preparation-files.js";
import {
  normalizeWindowsExperimentPreparation,
  recoverWindowsPreparationOwners,
} from "./preparation.js";
import { normalizeNativePolicyBinding } from "./experiment-policy.js";
import { createWindowsSystemEffects } from "./effects.js";

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
  observationObject(prepared, [
    "purpose",
    "schemaVersion",
    "job",
    "binding",
    "directory",
    "output",
    "sourceDirectory",
    "bootstrap",
    "sources",
    "tools",
    "helpers",
    "entries",
    "environment",
    "sdkBuild",
    "sdkHeader",
    "gitRuntime",
    "commands",
    "versions",
  ]);
  requireObservation(
    prepared.schemaVersion === 4 &&
      prepared.purpose === "experiment" &&
      prepared.job.platform === "win32" &&
      prepared.output === path.join(prepared.directory, "platform-build") &&
      prepared.sourceDirectory === prepared.directory + "-bootstrap" &&
      prepared.bootstrap.context.jobBindingSha256 ===
        observationDigest(prepared.binding),
  );
  assertWindowsExperimentGitSelection(prepared.gitRuntime);
  for (const [entries, names] of [
    [prepared.sources, WINDOWS_EXPERIMENT_SOURCES],
    [prepared.helpers, WINDOWS_HELPER_NAMES],
  ])
    requireObservation(
      Array.isArray(entries) &&
        entries.length === names.length &&
        new Set(entries.map(({ name }) => name)).size === names.length &&
        entries.every(
          ({ name, sha256 }) => names.includes(name) && hash(sha256),
        ),
    );
  for (const helper of prepared.helpers) {
    observationObject(helper, [
      "name",
      "path",
      "sha256",
      "signatureSha256",
      "sourceSha256",
    ]);
    requireObservation(
      helper.path ===
        path.join(prepared.sourceDirectory, helper.name + ".exe") &&
        helper.signatureSha256 === helper.sha256 &&
        helper.sourceSha256 ===
          prepared.sources.find((source) => source.name === helper.name + ".c")
            .sha256,
    );
  }
  requireObservation(prepared.tools.length === WINDOWS_BUILD_TOOLS.length);
  for (const [index, recipe] of WINDOWS_BUILD_TOOLS.entries()) {
    const tool = prepared.tools[index];
    observationObject(tool, ["name", "path", "sha256"]);
    requireObservation(
      tool.name === recipe.name &&
        recipe.path.test(tool.path) &&
        hash(tool.sha256),
    );
  }
  observationObject(prepared.environment, [
    "INCLUDE",
    "LIB",
    "SystemRoot",
    "PATH",
  ]);
  requireObservation(
    Object.values(prepared.environment).every(
      (value) =>
        typeof value === "string" &&
        value.length > 0 &&
        !/[\0\r\n]/u.test(value),
    ) && /^[0-9]+(?:\.[0-9]+){3}$/u.test(prepared.sdkBuild),
  );
  observationObject(prepared.sdkHeader, ["file", "sha256"]);
  requireObservation(
    location(prepared.sdkHeader.file) &&
      /\\Windows Kits\\10\\Include\\[0-9.]+\\um\\Windows\.h$/u.test(
        prepared.sdkHeader.file,
      ) &&
      hash(prepared.sdkHeader.sha256),
  );
  observationObject(prepared.versions, ["compiler", "sdk"]);
  requireObservation(
    Object.values(prepared.versions).every((value) =>
      /^[0-9.]+$/u.test(value),
    ) &&
      Array.isArray(prepared.commands) &&
      prepared.commands.length === WINDOWS_HELPER_NAMES.length + 7,
  );
  for (const command of prepared.commands) {
    observationObject(command, [
      "file",
      "args",
      "cwd",
      "env",
      "timeout",
      "maxBuffer",
      "exitCode",
      "signal",
      "timedOut",
      "stdout",
      "stderr",
    ]);
    requireObservation(
      typeof command.file === "string" &&
        Array.isArray(command.args) &&
        command.args.every(
          (arg) => typeof arg === "string" && !arg.includes("\0"),
        ) &&
        location(command.cwd) &&
        command.env &&
        typeof command.env === "object" &&
        command.timeout === 60000 &&
        command.maxBuffer === 1048576 &&
        Number.isInteger(command.exitCode) &&
        command.signal === null &&
        command.timedOut === false &&
        [command.stdout, command.stderr].every(
          (value) =>
            typeof value === "string" && Buffer.byteLength(value) <= 1048576,
        ),
    );
  }
  const [git, where, gitWhere, gitExec] = prepared.commands,
    who = prepared.commands.at(-1);
  requireObservation(
    git.file === "git" &&
      observationDigest(git.args) ===
        observationDigest(["rev-parse", "HEAD"]) &&
      git.stdout.trim() === prepared.job.candidateSha &&
      git.exitCode === 0 &&
      where.file === "where.exe" &&
      observationDigest(where.args) === observationDigest(["cl.exe"]) &&
      where.stdout.trim().split(/\r?\n/u)[0] === prepared.tools[0].path &&
      where.exitCode === 0 &&
      gitWhere.file === "where.exe" &&
      observationDigest(gitWhere.args) === observationDigest(["git.exe"]) &&
      gitWhere.stdout.trim().split(/\r?\n/u)[0] ===
        prepared.gitRuntime.executable &&
      gitWhere.exitCode === 0 &&
      gitExec.file === prepared.gitRuntime.executable &&
      observationDigest(gitExec.args) === observationDigest(["--exec-path"]) &&
      gitExec.stdout.trim().replaceAll("/", "\\") ===
        prepared.gitRuntime.execPath &&
      gitExec.exitCode === 0 &&
      who.file ===
        path.join(prepared.environment.SystemRoot, "System32", "whoami.exe") &&
      observationDigest(who.args) ===
        observationDigest(["/user", "/fo", "csv", "/nh"]) &&
      who.exitCode === 0 &&
      /"(S-1-5-21-(?:[0-9]+-){3}[0-9]+)"\s*$/u.exec(who.stdout.trim())?.[1] ===
        prepared.bootstrap.runnerSid,
  );
  const compiler = prepared.commands.filter(
      (command) => command.file === prepared.tools[0].path,
    ),
    compilerEnvironment = {
      CI: "true",
      GITHUB_ACTIONS: "true",
      LANG: "C",
      ...prepared.environment,
      TEMP: path.dirname(prepared.directory),
      TMP: path.dirname(prepared.directory),
    };
  requireObservation(compiler.length === WINDOWS_HELPER_NAMES.length + 1);
  for (const [index, name] of WINDOWS_HELPER_NAMES.entries()) {
    const command = compiler[index + 1];
    requireObservation(
      command.exitCode === 0 &&
        command.cwd === prepared.sourceDirectory &&
        observationDigest(command.args) ===
          observationDigest(
            windowsHostedCompilerArguments(
              path.join(prepared.sourceDirectory, name + ".c"),
              path.join(prepared.sourceDirectory, name + ".exe"),
            ),
          ),
    );
  }
  // TEMP/TMP are the actual hosted temporary root, which may contain the private
  // report through multiple parent directories. Preserve it explicitly.
  for (const command of prepared.commands.filter((command) =>
    prepared.tools.some((tool) => tool.path === command.file),
  )) {
    observationObject(command.env, Object.keys(compilerEnvironment));
    requireObservation(
      location(command.env.TEMP) &&
        command.env.TEMP === command.env.TMP &&
        prepared.directory.startsWith(command.env.TEMP + "\\") &&
        Object.entries(compilerEnvironment).every(
          ([key, value]) =>
            ["TEMP", "TMP"].includes(key) || command.env[key] === value,
        ),
    );
  }
  for (const [index, tool] of prepared.tools.entries()) {
    const commands = prepared.commands.filter(
      (command) =>
        command.file === tool.path &&
        observationDigest(command.args) ===
          observationDigest(WINDOWS_BUILD_TOOLS[index].args),
    );
    requireObservation(
      commands.length === 1 &&
        [0, ...WINDOWS_BUILD_TOOLS[index].versionExitCodes].includes(
          commands[0].exitCode,
        ),
    );
    const text = commands[0].stdout + "\n" + commands[0].stderr;
    requireObservation(
      (index === 0
        ? /Compiler Version ([0-9.]+) for x64/u.exec(text)?.[1]
        : /Version ([0-9.]+)/u.exec(text)?.[1]) ===
        prepared.versions[tool.name],
    );
  }
  return windowsSystemRecipes();
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
  const actual = [];
  requireObservation(
    settlement.observer?.helper && settlement.observer?.bridge,
  );
  const retiredDomains = await files.verify(
    "verifyPreparation",
    prepared.bootstrap,
    [
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
    const close = JSON.parse(
      (
        await files.readProtected({
          file: path.join(directory, "windows-experiment-close.json"),
          receipt: true,
        })
      ).bytes,
    );
    observationObject(close, ["purpose", "schemaVersion", "observer"]);
    requireObservation(
      close.purpose === "experiment" && close.schemaVersion === 3,
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
            sameWindowsIdentity(value.helper, close.observer.helper) &&
            sameWindowsIdentity(value.bridge, close.observer.bridge),
        ),
    );
    // Stored completion is a selector. Loading or recovery must independently
    // observe original complete Jobs and task absence before using retirement.
    preparation.settlement = {
      ...job.preparationEffects.settlement,
      observer: close.observer,
      nativeEventSha256: observationDigest({ close, birth, result }),
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
