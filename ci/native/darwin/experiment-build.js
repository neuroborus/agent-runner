import * as filesystem from "node:fs/promises";
import path from "node:path";
import { attemptNativeBuilds, nativeException } from "../diagnostics.js";
import {
  normalizeExperimentJob,
  recordExperimentPreparationEffect,
  observationDigest,
  observationObject,
  requireObservation,
  nativeCandidateReader,
} from "../index.js";
import {
  acquireDarwinExperimentBuild,
  darwinExperimentWorker,
  DARWIN_EXPERIMENT_SOURCES,
  DARWIN_PF_ABI_REFERENCE,
} from "./experiment-build-inputs.js";
import { DARWIN_HELPER_NAMES, darwinCompilerArguments } from "./build.js";
import {
  createDarwinBuildEffects,
  darwinPreparationContext,
  recoverDarwinBuild,
} from "./preparation.js";
import { digest, inspectDarwinMachO } from "./protocol.js";
import { protectedInstalledInput } from "./private-files.js";
import { readDarwinBootstrapTools } from "./bootstrap-tools.js";

const hash = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
const retired = (value) =>
  value?.status === "RETIRED" &&
  value.independent === true &&
  value.emergencyCleanup === false;
const retained = () => ({
  status: "RETAINED",
  independent: false,
  emergencyCleanup: false,
});
const jobContext = (job) =>
  Object.fromEntries(
    ["candidateSha", "platform", "repository", "runId", "runAttempt"].map(
      (key) => [key, job[key]],
    ),
  );

/** Parse Clang's bounded Make dependency data, including escaped spaces and
 * continuation lines. These paths are observed build inputs, never approvals. */
export function darwinExperimentDependencies(bytes, source, directory, sdk) {
  requireObservation(
    Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= 1048576,
  );
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  requireObservation(!/[\0\r]/u.test(text) && text.indexOf(":") > 0);
  const words = [];
  let word = "";
  const body = text.slice(text.indexOf(":") + 1).replace(/\\\n/gu, " ");
  for (let i = 0; i < body.length; i++) {
    const char = body[i];
    if (char === "\\") {
      requireObservation(i + 1 < body.length);
      word += body[++i];
    } else if (/\s/u.test(char)) {
      if (word) words.push(word);
      word = "";
    } else word += char;
  }
  if (word) words.push(word);
  requireObservation(
    words.includes(source) &&
      words.length <= 2048 &&
      words.every(
        (file) =>
          path.isAbsolute(file) &&
          path.normalize(file) === file &&
          (path.dirname(file) === directory ||
            file.startsWith(sdk + "/") ||
            (/^\/Applications\//u.test(file) &&
              file.includes("/Contents/Developer/")) ||
            file.startsWith("/Library/Developer/CommandLineTools/") ||
            file.startsWith("/usr/include/")),
      ),
  );
  return [...new Set(words)].sort();
}

export function darwinExperimentBuildInput(prepared, job, directory) {
  observationObject(prepared, [
    "purpose",
    "job",
    "binding",
    "directory",
    "output",
    "sourceDirectory",
    "bootstrapSeed",
    "sources",
    "tools",
    "inputs",
    "environment",
    "helpers",
    "bootstrap",
    "command",
    "cachePath",
  ]);
  requireObservation(
    prepared?.purpose === "experiment" &&
      prepared.directory === directory &&
      prepared.output === path.join(directory, "platform-build") &&
      observationDigest(jobContext(prepared.job)) ===
        observationDigest(jobContext(job)) &&
      prepared.bootstrap.context.jobBindingSha256 ===
        observationDigest(prepared.binding) &&
      Array.isArray(prepared.sources) &&
      prepared.sources.length === DARWIN_EXPERIMENT_SOURCES.length &&
      new Set(prepared.sources.map((source) => source.name)).size ===
        prepared.sources.length &&
      Array.isArray(prepared.helpers) &&
      prepared.helpers.length === DARWIN_HELPER_NAMES.length &&
      new Set(prepared.helpers.map((helper) => helper.name)).size ===
        prepared.helpers.length &&
      Array.isArray(prepared.tools) &&
      prepared.tools.length === 3 &&
      Array.isArray(prepared.inputs) &&
      prepared.inputs.length <= 2048,
  );
  requireObservation(
    new Set(prepared.inputs.map((input) => input.path)).size ===
      prepared.inputs.length &&
      prepared.inputs.length >= 3 &&
      [
        path.join(prepared.environment.SDKROOT, "SDKSettings.json"),
        "/usr/lib/dyld",
      ].every((file) => prepared.inputs.some((input) => input.path === file)),
  );
  normalizeExperimentJob(prepared.job);
  observationObject(prepared.bootstrapSeed, ["path", "sha256", "acquisition"]);
  requireObservation(
    prepared.bootstrapSeed.path ===
      path.join(prepared.sourceDirectory, "bootstrap-seed") &&
      hash(prepared.bootstrapSeed.sha256) &&
      retired(prepared.bootstrapSeed.acquisition?.settlement) &&
      observationDigest(prepared.bootstrap.tools) ===
        observationDigest(prepared.bootstrapSeed.acquisition.tools),
  );
  observationObject(prepared.environment, ["SDKROOT"]);
  for (const helper of prepared.helpers)
    observationObject(helper, ["name", "sourceSha256", "sha256"]);
  for (const tool of prepared.tools)
    observationObject(tool, ["name", "path", "sha256", "cdhash"]);
  for (const input of prepared.inputs)
    observationObject(input, ["path", "sha256"]);
  for (const name of DARWIN_EXPERIMENT_SOURCES)
    requireObservation(
      prepared.sources.some(
        (source) => source.name === name && hash(source.sha256),
      ),
    );
  for (const name of DARWIN_HELPER_NAMES)
    requireObservation(
      prepared.helpers.some(
        (helper) =>
          helper.name === name &&
          helper.sourceSha256 ===
            prepared.sources.find((source) => source.name === name + ".c")
              .sha256,
      ),
    );
  for (const [index, name] of ["compiler", "sdk", "signer"].entries())
    requireObservation(
      prepared.tools[index].name === name &&
        prepared.tools[index].path ===
          ["/usr/bin/clang", "/usr/bin/xcrun", "/usr/bin/codesign"][index] &&
        hash(prepared.tools[index].sha256) &&
        /^[a-f0-9]{40}$/u.test(prepared.tools[index].cdhash),
    );
  requireObservation(
    prepared.inputs.every(
      (input) => typeof input.path === "string" && hash(input.sha256),
    ),
  );
  return {
    job,
    directory,
    output: prepared.output,
    manifest: {
      purpose: "experiment",
      candidateSha: job.candidateSha,
      platform: "darwin",
      environment: prepared.environment,
      tools: prepared.tools,
      helpers: prepared.helpers,
      darwinPreparation: {
        purpose: "experiment",
        schemaVersion: 1,
        sourceDirectory: prepared.sourceDirectory,
        sources: prepared.sources,
        bootstrap: prepared.bootstrap,
        command: prepared.command,
        cases: [],
      },
    },
  };
}
async function candidateSources(prepared, options) {
  const read =
    options.readCandidate ??
    nativeCandidateReader(
      prepared.job.candidateSha,
      path.resolve(import.meta.dirname, "../../.."),
    );
  for (const source of prepared.sources)
    requireObservation(
      digest(await read("ci/native/darwin/" + source.name, 1048576)) ===
        source.sha256,
    );
}
async function recordsFor(state) {
  const names = await state.fs.readdir(state.directory);
  requireObservation(names.length <= 65536);
  const records = [];
  for (const name of names.filter((name) =>
    /^darwin-(?:bootstrap-[0-9]+-|command-[a-f0-9]{64}-)/u.test(name),
  ))
    records.push({
      name,
      record: JSON.parse(await state.receipt(path.join(state.directory, name))),
    });
  return records;
}
async function observe(prepared, commands, reader, options, previous) {
  const reads = [],
    inputs = new Map(
      prepared.inputs.map((input) => [input.path, input.sha256]),
    ),
    helpers = [],
    runtime = new Map();
  const held = async (file, pin) => {
    const value = await reader.readBuildInput(file, pin);
    requireObservation(
      value.independent === true &&
        value.held === true &&
        value.unchanged === true &&
        value.sha256 === pin &&
        hash(value.nativeEventSha256),
    );
    reads.push(value.nativeEventSha256);
  };
  for (const source of prepared.sources)
    await held(path.join(prepared.sourceDirectory, source.name), source.sha256);
  for (const tool of prepared.tools) await held(tool.path, tool.sha256);
  const readInput =
    options.readInstalled ??
    (async (file) => {
      const fs = options.fs ?? filesystem,
        stat = await fs.lstat(file);
      requireObservation(
        stat.isFile() &&
          !stat.isSymbolicLink() &&
          stat.uid === 0 &&
          !(stat.mode & 0o6022) &&
          (stat.nlink === 1 ||
            (await protectedInstalledInput(file, stat, fs))) &&
          stat.size > 0 &&
          stat.size <= 536870912,
      );
      const bytes = await fs.readFile(file),
        after = await fs.lstat(file);
      requireObservation(
        bytes.length === stat.size &&
          [
            "dev",
            "ino",
            "mode",
            "uid",
            "gid",
            "nlink",
            "size",
            "mtimeMs",
            "ctimeMs",
          ].every((key) => stat[key] === after[key]) &&
          (stat.nlink === 1 ||
            (await protectedInstalledInput(file, after, fs))),
      );
      return bytes;
    });
  const prior =
    previous &&
    new Map(previous.sdk.inputs.map((input) => [input.path, input.sha256]));
  for (const name of DARWIN_HELPER_NAMES) {
    const file = path.join(prepared.output, name),
      expected = previous?.helpers.find((helper) => helper.name === name),
      image = await reader.readBuildImage(file, expected?.sha256 ?? null),
      macho = inspectDarwinMachO(image.bytes, 134217728, "experiment");
    requireObservation(
      image.independent === true &&
        image.held === true &&
        image.unchanged === true &&
        hash(image.nativeEventSha256) &&
        image.sha256 === macho.sha256 &&
        image.signature?.valid === true &&
        /^[a-f0-9]{40}$/u.test(image.signature.cdhash) &&
        macho.libraries.length > 0 &&
        image.macho.rpaths.length === 0 &&
        JSON.stringify(image.macho.dependencies.slice().sort()) ===
          JSON.stringify([...macho.libraries, macho.loader].sort()),
    );
    reads.push(image.nativeEventSha256);
    const dependencies = await reader.readBuildImage(
      file + ".deps",
      null,
      1048576,
    );
    requireObservation(
      dependencies.independent &&
        dependencies.held &&
        dependencies.unchanged &&
        hash(dependencies.nativeEventSha256),
    );
    reads.push(dependencies.nativeEventSha256);
    const dependencyPaths = darwinExperimentDependencies(
      dependencies.bytes,
      path.join(prepared.sourceDirectory, name + ".c"),
      prepared.sourceDirectory,
      prepared.environment.SDKROOT,
    );
    if (name === "custody-reader")
      requireObservation(
        ["pf-abi.h", "feasibility-sandbox.h"].every(
          (header) =>
            dependencyPaths.includes(
              path.join(prepared.sourceDirectory, header),
            ) &&
            dependencyPaths.filter((file) => path.basename(file) === header)
              .length === 1,
        ),
      );
    for (const input of dependencyPaths) {
      const source = prepared.sources.find(
        (source) => path.join(prepared.sourceDirectory, source.name) === input,
      );
      if (source) continue;
      const file = await (options.fs ?? filesystem).realpath(input),
        pin = prior ? prior.get(file) : digest(await readInput(file));
      requireObservation(
        hash(pin) && (!inputs.has(file) || inputs.get(file) === pin),
      );
      inputs.set(file, pin);
    }
    for (const dependency of macho.libraries)
      if (!runtime.has(dependency)) {
        const value = await reader.readBuildRuntime(
          prepared.cachePath,
          dependency,
        );
        requireObservation(
          value.independent &&
            value.held &&
            value.unchanged &&
            hash(value.nativeEventSha256),
        );
        reads.push(value.nativeEventSha256);
        runtime.set(dependency, value);
      }
    helpers.push({
      name,
      sha256: image.sha256,
      sourceSha256: prepared.sources.find(
        (source) => source.name === name + ".c",
      ).sha256,
      cdhash: image.signature.cdhash,
      identity: image.identity,
      rootIdentity: image.rootIdentity,
      macho: image.macho,
      dependenciesSha256: digest(dependencies.bytes),
    });
  }
  // Rejoin the transitive installed cache closure, never just a helper's direct imports.
  for (const [file, value] of runtime)
    for (const dependency of value.runtime.macho.dependencies) {
      if (dependency === "/usr/lib/dyld" || runtime.has(dependency)) continue;
      requireObservation(runtime.size < 120);
      const actual = await reader.readBuildRuntime(
        prepared.cachePath,
        dependency,
      );
      requireObservation(
        actual.independent &&
          actual.held &&
          actual.unchanged &&
          hash(actual.runtime.sha256) &&
          hash(actual.nativeEventSha256),
      );
      reads.push(actual.nativeEventSha256);
      runtime.set(dependency, actual);
    }
  for (const [file, pin] of inputs) await held(file, pin);
  const installed = await reader.build();
  requireObservation(
    installed.purpose === "experiment" &&
      installed.osBuild === prepared.binding.osBuild,
  );
  const sdk = {
    build: commands[1].stdout.trim(),
    inputs: [...inputs]
      .map(([path, sha256]) => ({ path, sha256 }))
      .sort((a, b) => a.path.localeCompare(b.path)),
    runtime: [...runtime].map(([path, observation]) => ({ path, observation })),
  };
  sdk.sha256 = observationDigest(sdk);
  const build = {
    purpose: "experiment",
    status: "OBSERVED",
    context: jobContext(prepared.job),
    bindingSha256: observationDigest(prepared.binding),
    preparationSha256: observationDigest(prepared),
    helpers,
    tools: prepared.tools,
    sources: prepared.sources,
    sdk,
    commands,
    abi: installed,
    pfAbi: {
      reference: DARWIN_PF_ABI_REFERENCE,
      adapter: {
        path: path.join(prepared.sourceDirectory, "pf-abi.h"),
        sha256: prepared.sources.find((source) => source.name === "pf-abi.h")
          .sha256,
      },
      runtimeCompatibility: "UNPROVED",
    },
  };
  if (previous)
    requireObservation(
      observationDigest(build) === observationDigest(previous),
    );
  return { purpose: "experiment", build, readSha256: observationDigest(reads) };
}

/** Private build-only lifecycle. It deliberately leaves full experiment
 * preparation and case admission unestablished until their declarations exist. */
export async function prepareDarwinExperimentBuild(
  input,
  directory,
  persist,
  options = {},
) {
  let job = normalizeExperimentJob(input),
    prepared,
    effects,
    primary,
    state;
  const binding = structuredClone(options.binding);
  darwinExperimentWorker(job, binding, options);
  requireObservation(
    typeof persist === "function" &&
      job.failure === null &&
      job.preparation === null &&
      job.preparationEffects.admission === "not-started",
  );
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
    let sequence = 0;
    const bootstrap =
      options.persistBootstrap ??
      ((record) =>
        (options.fs ?? filesystem).writeFile(
          `${options.bootstrapJournal ?? directory}-bootstrap-${sequence++}.json`,
          JSON.stringify(record) + "\n",
          { flag: "wx", mode: 0o400 },
        ));
    prepared = structuredClone(
      await (options.acquire ?? acquireDarwinExperimentBuild)(
        job,
        directory,
        binding,
        bootstrap,
        options,
      ),
    );
    const declaration = darwinExperimentBuildInput(prepared, job, directory);
    await candidateSources(prepared, options);
    state = darwinPreparationContext(declaration, options);
    await state.write("darwin-experiment-build-selector.json", prepared, false);
    effects = createDarwinBuildEffects(declaration, options);
    const commands = [],
      settledFailures = new WeakSet();
    const run = async (tool, args) => {
      const result = await effects.run(
        {
          purpose: "experiment",
          candidateSha: job.candidateSha,
          platform: "darwin",
          toolSha256: tool.sha256,
          file: tool.path,
          args,
          cwd: prepared.output,
          env: {
            CI: "true",
            GITHUB_ACTIONS: "true",
            LANG: "C",
            ...prepared.environment,
          },
          deadlineMs: 30000,
        },
        { signal: options.signal },
      );
      requireObservation(
        result.purpose === "experiment" &&
          Number.isInteger(result.exitCode) &&
          result.exitCode >= 0 &&
          result.exitCode <= 255 &&
          result.signal === null &&
          result.timedOut === false &&
          retired(result.settlement) &&
          hash(result.nativeEventSha256),
      );
      commands.push(result);
      if (result.exitCode !== 0) {
        const error = Object.assign(
          new Error("Darwin compiler recipe failed"),
          result,
        );
        settledFailures.add(error);
        throw error;
      }
    };
    await run(prepared.tools[0], ["--version"]);
    await run(prepared.tools[1], ["--show-sdk-build-version"]);
    requireObservation(
      /^(?:Apple )?clang version /u.test(commands[0].stdout) &&
        /^[A-Za-z0-9.]+\n?$/u.test(commands[1].stdout),
    );
    const build = async (name) => {
      const source = path.join(prepared.sourceDirectory, name + ".c"),
        target = path.join(prepared.output, name);
      await run(
        prepared.tools[0],
        darwinCompilerArguments(
          source,
          target,
          prepared.environment,
          "experiment",
        ),
      );
      await run(prepared.tools[2], [
        "--force",
        "--sign",
        "-",
        "--timestamp=none",
        target,
      ]);
    };
    await attemptNativeBuilds(
      "darwin-protected-builds",
      DARWIN_HELPER_NAMES.map((name) => ({ name, run: () => build(name) })),
      {
        signal: options.signal,
        settled: (error) => settledFailures.has(error),
        verify: () => state.admit(options.signal),
      },
    );
    const { reader } = await effects.bootstrap(options.signal);
    const observed = await observe(prepared, commands, reader, options);
    await reader.verifyBuildReceipt(
      await state.write("darwin-experiment-build.json", observed, false),
    );
    const close = {
      purpose: "experiment",
      ...(await effects.releaseBootstrap()),
    };
    requireObservation(
      retired(close) && close.closed === true && hash(close.nativeEventSha256),
    );
    await state.write("darwin-experiment-build-close.json", close, false);
    await state.admit(options.signal);
    await save(
      recordExperimentPreparationEffect(job, {
        admission: "possible",
        settlement: {
          status: "RETIRED",
          independent: true,
          emergencyCleanup: false,
        },
        receiptSha256: observationDigest({ observed, close }),
      }),
    );
    return { job, prepared, ...observed };
  } catch (cause) {
    primary = cause;
    nativeException("darwin-experiment-build", cause);
    try {
      await save(
        normalizeExperimentJob({
          ...job,
          failure: job.failure ?? "preparation-failed",
        }),
      );
    } catch (failure) {
      nativeException("darwin-experiment-build-failure-record", failure);
    }
    throw cause;
  } finally {
    if (effects)
      try {
        requireObservation(retired(await effects.settle()));
      } catch (cause) {
        nativeException("darwin-experiment-build-cleanup", cause);
        if (!primary) throw cause;
      }
  }
}

async function selected(input, directory, options) {
  const job = normalizeExperimentJob(input),
    fs = options.fs ?? filesystem;
  // Selectors are not native evidence. Source and protected custody joins follow.
  let prepared;
  if (options.bootstrapJournal) {
    const parent = path.dirname(options.bootstrapJournal),
      prefix = path.basename(options.bootstrapJournal) + "-bootstrap-",
      journals = (await fs.readdir(parent))
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
    requireObservation(journals.length > 0 && journals.length <= 512);
    for (const [index, name] of journals.entries()) {
      requireObservation(name === prefix + index + ".json");
      const bytes = await fs.readFile(path.join(parent, name));
      requireObservation(Buffer.isBuffer(bytes) && bytes.length <= 1048576);
      const record = JSON.parse(bytes);
      requireObservation(record.purpose === "experiment");
      if (record.phase === "seal-possible") {
        requireObservation(!prepared && record.prepared);
        prepared = record.prepared;
      }
      if (record.phase === "sealed") {
        requireObservation(
          prepared &&
            record.prepared &&
            record.prepared.bootstrapSeed.sha256 ===
              prepared.bootstrapSeed.sha256,
        );
        prepared = record.prepared;
      }
    }
    requireObservation(prepared);
  } else {
    const bytes = await (options.readSelector ?? fs.readFile)(
      path.join(directory, "darwin-experiment-build-selector.json"),
    );
    requireObservation(Buffer.isBuffer(bytes) && bytes.length <= 1048576);
    prepared = JSON.parse(bytes);
  }
  darwinExperimentWorker(job, prepared.binding, options);
  requireObservation(
    prepared.directory === directory &&
      prepared.output === path.join(directory, "platform-build") &&
      observationDigest(jobContext(prepared.job)) ===
        observationDigest(jobContext(job)) &&
      Object.keys(prepared.binding).every(
        (key) => prepared.binding[key] === options.binding[key],
      ),
  );
  requireObservation(
    Array.isArray(prepared.sources) &&
      Array.isArray(prepared.bootstrap.sources) &&
      observationDigest(
        prepared.sources.map((source) => source.name).sort(),
      ) === observationDigest([...DARWIN_EXPERIMENT_SOURCES].sort()) &&
      observationDigest(prepared.bootstrap.sources) ===
        observationDigest(
          prepared.sources.map((source) => ({
            path: path.join(prepared.sourceDirectory, source.name),
            sha256: source.sha256,
          })),
        ),
  );
  await candidateSources(prepared, options);
  const acquisition = await (
    options.readBootstrapTools ?? readDarwinBootstrapTools
  )(prepared, { ...options, allowIncomplete: options.recovery === true });
  if (prepared.bootstrapSeed.acquisition !== null)
    requireObservation(
      observationDigest(acquisition) ===
        observationDigest(prepared.bootstrapSeed.acquisition),
    );
  const selectorName = "darwin-experiment-build-selector.json",
    names = options.recovery === true ? await fs.readdir(directory) : [];
  if (options.recovery === true && !names.includes(selectorName)) {
    requireObservation(
      retired(acquisition.settlement) &&
        !names.some((name) =>
          /^(?:darwin-bootstrap-|darwin-command-)/u.test(name),
        ),
    );
    return { job, prepared, acquisitionOnly: true, acquisition };
  }
  requireObservation(acquisition.tools !== null);
  if (prepared.bootstrapSeed.acquisition === null) {
    prepared.bootstrapSeed.acquisition = acquisition;
    prepared.bootstrap.tools = acquisition.tools;
    prepared.bootstrap.bindingSha256 = observationDigest({
      binding: prepared.binding,
      sources: prepared.sources,
      tools: prepared.tools,
      acquisition,
    });
  }
  const declaration = darwinExperimentBuildInput(prepared, job, directory);
  const state = darwinPreparationContext(declaration, options);
  const selector = await state.receipt(path.join(directory, selectorName));
  requireObservation(
    observationDigest(JSON.parse(selector)) === observationDigest(prepared),
  );
  return {
    job,
    prepared,
    state,
  };
}
export async function loadDarwinExperimentBuild(
  input,
  directory,
  options = {},
) {
  const job = normalizeExperimentJob(input);
  darwinExperimentWorker(job, options.binding, options);
  requireObservation(
    retired(job.preparationEffects.settlement) &&
      hash(job.preparationEffects.receiptSha256),
  );
  const { prepared, state } = await selected(job, directory, options);
  let primary;
  try {
    const observed = JSON.parse(
        await state.receipt(
          path.join(directory, "darwin-experiment-build.json"),
        ),
      ),
      close = JSON.parse(
        await state.receipt(
          path.join(directory, "darwin-experiment-build-close.json"),
        ),
      );
    requireObservation(
      observationDigest({ observed, close }) ===
        job.preparationEffects.receiptSha256 &&
        observed.build.preparationSha256 === observationDigest(prepared) &&
        retired(close) &&
        close.closed === true,
    );
    const records = await recordsFor(state);
    // Recovery owns and retires its read-only directory join. Output reads use
    // a fresh custody session rather than reopening that retained native root.
    await recoverDarwinBuild(state, records, options.signal);
    const { reader } = await state.bootstrap(options.signal);
    const fresh = await observe(
      prepared,
      observed.build.commands,
      reader,
      options,
      observed.build,
    );
    return { job, prepared, ...fresh };
  } catch (cause) {
    primary = cause;
    throw cause;
  } finally {
    try {
      await state.releaseBootstrap();
    } catch (cause) {
      if (!primary) throw cause;
    }
  }
}
export async function recoverDarwinExperimentBuild(
  input,
  directory,
  persist,
  options = {},
) {
  const job = normalizeExperimentJob(input);
  const env = darwinExperimentWorker(job, options.binding, options);
  if (job.preparationEffects.admission === "not-started") return job;
  let state,
    settlement = retained(),
    receiptSha256 = null,
    primary;
  try {
    const fs = options.fs ?? filesystem,
      ownerUid = (options.ownerUid ?? (() => process.getuid()))();
    requireObservation(
      typeof directory === "string" &&
        path.isAbsolute(directory) &&
        path.normalize(directory) === directory &&
        typeof env.RUNNER_TEMP === "string" &&
        directory.startsWith(env.RUNNER_TEMP + "/") &&
        (await fs.realpath(env.RUNNER_TEMP)) === env.RUNNER_TEMP,
    );
    let stat;
    try {
      stat = await fs.lstat(directory);
    } catch (cause) {
      if (cause.code !== "ENOENT") throw cause;
      const parent = path.dirname(directory),
        authority = await fs.lstat(parent);
      requireObservation(
        authority.isDirectory() &&
          !authority.isSymbolicLink() &&
          authority.uid === ownerUid &&
          !(authority.mode & 0o22) &&
          (await fs.realpath(parent)) === parent,
      );
      // The original possible admission covers this private artifact directory.
      // Persist it before creating the missing home for the recovery fence.
      await persist(job);
      try {
        await fs.mkdir(directory, { mode: 0o700 });
      } catch (cause) {
        if (cause.code !== "EEXIST") throw cause;
      }
      stat = await fs.lstat(directory);
    }
    requireObservation(
      stat.isDirectory() &&
        !stat.isSymbolicLink() &&
        stat.uid === ownerUid &&
        (stat.mode & 0o7777) === 0o700 &&
        (await fs.realpath(directory)) === directory,
    );
    const sequence = (await fs.readdir(directory)).filter((name) =>
        /^darwin-recovery-.*-intent\.json$/u.test(name),
      ).length,
      fence = path.join(directory, `darwin-recovery-${sequence}-intent.json`);
    await fs.writeFile(
      fence,
      JSON.stringify({
        purpose: "experiment",
        admission: "CLOSED",
        context: jobContext(job),
      }) + "\n",
      { flag: "wx", mode: 0o400 },
    );
    const selection = await selected(job, directory, {
      ...options,
      recovery: true,
    });
    ({ state } = selection);
    state?.fence();
    if (state) await state.receipt(fence);
    const records = state ? await recordsFor(state) : [];
    const result = selection.acquisitionOnly
      ? selection.acquisition.settlement
      : await recoverDarwinBuild(state, records, options.signal, undefined, {
          recovery: true,
        });
    requireObservation(retired(result));
    settlement = {
      status: "RETIRED",
      independent: true,
      emergencyCleanup: false,
    };
    receiptSha256 = observationDigest(result);
  } catch (cause) {
    primary = cause;
    nativeException("darwin-experiment-build-recovery", cause);
  } finally {
    if (state)
      try {
        await state.settleBootstrap();
      } catch (cause) {
        if (!primary)
          nativeException("darwin-experiment-build-recovery-cleanup", cause);
      }
  }
  // Cleanup preserves the first failure and never fills missing build evidence.
  const effect = {
    admission: "possible",
    settlement: {
      ...settlement,
      emergencyCleanup:
        settlement.emergencyCleanup ||
        job.preparationEffects.settlement.emergencyCleanup,
    },
    receiptSha256,
  };
  // Cold reads have their own durable native admissions after the original
  // build retires. Their uncertainty must reopen cleanup, not rewrite the
  // successful build's receipt or authorize another preparation attempt.
  const recovered =
    job.preparationEffects.settlement.status === "RETIRED"
      ? retired(effect.settlement)
        ? job
        : normalizeExperimentJob({
            ...job,
            preparationEffects: effect,
            failure: job.failure ?? "cleanup-failed",
          })
      : recordExperimentPreparationEffect(job, effect);
  await persist(recovered);
  return recovered;
}
