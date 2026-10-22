import * as filesystem from "node:fs/promises";
import path from "node:path";
import { nativeException } from "../diagnostics.js";
import {
  normalizeExperimentJob,
  recordExperimentPreparationEffect,
  observationDigest,
  observationList,
  observationObject,
  requireObservation,
  nativeCandidateReader,
} from "../index.js";
import {
  acquireDarwinExperimentBuild,
  darwinExperimentWorker,
  DARWIN_EXPERIMENT_SOURCES,
  DARWIN_PF_ABI_REFERENCE,
  DARWIN_HOSTED_OUTPUT_BYTES,
  darwinHostedCompilerArguments,
} from "./experiment-build-inputs.js";
import { DARWIN_HELPER_NAMES, darwinDeveloperDirectory } from "./build.js";
import {
  darwinBuildRecords as recordsFor,
  readDarwinPreparationReceipt,
  darwinPreparationContext,
  recoverDarwinBuild,
} from "./preparation.js";
import { digest, inspectDarwinMachO } from "./protocol.js";
import { protectedBytes, isDarwinInstalledPath } from "./private-files.js";

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

export function darwinExperimentBuildInput(prepared, job, directory) {
  observationObject(prepared, [
    "schemaVersion",
    "purpose",
    "job",
    "binding",
    "directory",
    "output",
    "sourceDirectory",
    "sources",
    "tools",
    "environment",
    "helpers",
    "bootstrap",
    "command",
    "sdk",
    "compilerVersion",
    "commands",
  ]);
  requireObservation(
    prepared.schemaVersion === 3 &&
      prepared.purpose === "experiment" &&
      prepared.directory === directory &&
      prepared.output === path.join(directory, "platform-build") &&
      observationDigest(jobContext(prepared.job)) ===
        observationDigest(jobContext(job)) &&
      prepared.bootstrap.context.jobBindingSha256 ===
        observationDigest(prepared.binding),
  );
  normalizeExperimentJob(prepared.job);
  observationObject(prepared.environment, ["SDKROOT", "DEVELOPER_DIR"]);
  observationObject(prepared.sdk, ["path", "build", "settingsSha256"]);
  requireObservation(
    prepared.sdk.path === prepared.environment.SDKROOT &&
      prepared.environment.DEVELOPER_DIR ===
        darwinDeveloperDirectory(prepared.sdk.path) &&
      hash(prepared.sdk.settingsSha256) &&
      /^[A-Za-z0-9.]+$/u.test(prepared.sdk.build) &&
      /^(?:Apple )?clang version /u.test(prepared.compilerVersion),
  );
  requireObservation(
    Array.isArray(prepared.sources) &&
      prepared.sources.length === DARWIN_EXPERIMENT_SOURCES.length &&
      new Set(prepared.sources.map(({ name }) => name)).size ===
        prepared.sources.length,
  );
  for (const source of prepared.sources) {
    observationObject(source, ["name", "sha256"]);
    requireObservation(
      DARWIN_EXPERIMENT_SOURCES.includes(source.name) && hash(source.sha256),
    );
  }
  requireObservation(
    Array.isArray(prepared.helpers) &&
      prepared.helpers.length === DARWIN_HELPER_NAMES.length &&
      new Set(prepared.helpers.map(({ name }) => name)).size ===
        prepared.helpers.length,
  );
  for (const helper of prepared.helpers) {
    observationObject(helper, ["name", "sha256", "sourceSha256", "cdhash"]);
    requireObservation(
      DARWIN_HELPER_NAMES.includes(helper.name) &&
        hash(helper.sha256) &&
        helper.sourceSha256 ===
          prepared.sources.find(({ name }) => name === helper.name + ".c")
            .sha256 &&
        /^[a-f0-9]{40}$/u.test(helper.cdhash),
    );
  }
  requireObservation(
    Array.isArray(prepared.tools) && prepared.tools.length === 3,
  );
  for (const [index, name] of ["compiler", "sdk", "signer"].entries()) {
    const tool = prepared.tools[index];
    observationObject(tool, ["name", "path", "sha256"]);
    requireObservation(
      tool.name === name &&
        hash(tool.sha256) &&
        path.isAbsolute(tool.path) &&
        (index === 0 ||
          tool.path === [null, "/usr/bin/xcrun", "/usr/bin/codesign"][index]),
    );
  }
  requireObservation(
    Array.isArray(prepared.commands) &&
      prepared.commands.length > 2 &&
      prepared.commands.length <= 128,
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
    const args = observationList(command.args, 128);
    requireObservation(
      typeof command.file === "string" &&
        (command.file === "git" ||
          (path.isAbsolute(command.file) &&
            path.normalize(command.file) === command.file)) &&
        !/[\0\r\n]/u.test(command.file) &&
        args.every(
          (arg) =>
            typeof arg === "string" &&
            arg.length <= 8192 &&
            !arg.includes("\0"),
        ),
    );
    const environment = {
      CI: "true",
      GITHUB_ACTIONS: "true",
      LANG: "C",
      PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
      ...(command.file === prepared.tools[0].path ||
      (command.file === "/usr/bin/xcrun" && args[0] === "--sdk")
        ? prepared.environment
        : {}),
    };
    observationObject(command.env, Object.keys(environment));
    requireObservation(
      Object.entries(environment).every(
        ([key, value]) => command.env[key] === value,
      ) &&
        command.exitCode === 0 &&
        command.signal === null &&
        command.timedOut === false &&
        command.timeout === 60000 &&
        command.maxBuffer === DARWIN_HOSTED_OUTPUT_BYTES &&
        command.cwd === directory &&
        [command.stdout, command.stderr].every(
          (value) => typeof value === "string",
        ) &&
        Buffer.byteLength(command.stdout) + Buffer.byteLength(command.stderr) <=
          DARWIN_HOSTED_OUTPUT_BYTES,
    );
  }
  const compilerCommands = prepared.commands.filter(
    ({ file }) => file === prepared.tools[0].path,
  );
  requireObservation(
    compilerCommands.length === 1 + DARWIN_HELPER_NAMES.length &&
      observationDigest(compilerCommands[0].args) ===
        observationDigest(["--version"]) &&
      compilerCommands[0].stdout.trim() === prepared.compilerVersion,
  );
  for (const [index, name] of DARWIN_HELPER_NAMES.entries())
    requireObservation(
      observationDigest(compilerCommands[index + 1].args) ===
        observationDigest(
          darwinHostedCompilerArguments(
            path.join(directory, "hosted-build", name + ".c"),
            path.join(directory, "hosted-build", name),
            prepared.environment,
          ),
        ),
    );
  const signing = prepared.commands.filter(
    ({ file }) => file === "/usr/bin/codesign",
  );
  requireObservation(signing.length === DARWIN_HELPER_NAMES.length * 3);
  for (const [index, name] of DARWIN_HELPER_NAMES.entries()) {
    const target = path.join(directory, "hosted-build", name);
    for (const [offset, args] of [
      ["--force", "--sign", "-", "--timestamp=none", target],
      ["--verify", "--strict", target],
      ["-d", "--verbose=4", target],
    ].entries())
      requireObservation(
        observationDigest(signing[index * 3 + offset].args) ===
          observationDigest(args),
      );
    requireObservation(
      new RegExp(`^CDHash=${prepared.helpers[index].cdhash}$`, "mu").test(
        signing[index * 3 + 2].stderr,
      ),
    );
  }
  requireObservation(
    prepared.commands.some(
      ({ file, args, stdout }) =>
        file === "/usr/bin/xcrun" &&
        observationDigest(args) ===
          observationDigest([
            "--sdk",
            prepared.sdk.path,
            "--show-sdk-build-version",
          ]) &&
        stdout.trim() === prepared.sdk.build,
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
        schemaVersion: 3,
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
// Recovery validates completed records without reconstructing missing observations.
export function assertDarwinExperimentBuild(prepared, build) {
  observationObject(build, [
    "schemaVersion",
    "purpose",
    "status",
    "context",
    "bindingSha256",
    "preparationSha256",
    "helpers",
    "tools",
    "sources",
    "sdk",
    "commands",
    "compilerVersion",
    "abi",
    "pfAbi",
  ]);
  requireObservation(
    prepared.schemaVersion === 3 &&
      build.schemaVersion === 3 &&
      build.purpose === "experiment" &&
      build.status === "OBSERVED" &&
      build.preparationSha256 === observationDigest(prepared) &&
      build.bindingSha256 === observationDigest(prepared.binding) &&
      observationDigest(build.context) ===
        observationDigest(jobContext(prepared.job)) &&
      observationDigest(build.sdk) ===
        observationDigest({
          ...prepared.sdk,
          sha256: observationDigest(prepared.sdk),
        }) &&
      ["tools", "sources", "commands", "compilerVersion"].every(
        (key) =>
          observationDigest(build[key]) === observationDigest(prepared[key]),
      ) &&
      Array.isArray(build.helpers) &&
      build.abi?.purpose === "experiment" &&
      observationDigest(build.pfAbi) ===
        observationDigest({
          reference: DARWIN_PF_ABI_REFERENCE,
          adapter: {
            path: path.join(prepared.sourceDirectory, "pf-abi.h"),
            sha256: prepared.sources.find(({ name }) => name === "pf-abi.h")
              .sha256,
          },
          runtimeCompatibility: "UNPROVED",
        }) &&
      build.helpers.length === DARWIN_HELPER_NAMES.length &&
      new Set(build.helpers.map(({ name }) => name)).size ===
        DARWIN_HELPER_NAMES.length,
  );
  for (const helper of build.helpers) {
    observationObject(helper, [
      "name",
      "sha256",
      "sourceSha256",
      "cdhash",
      "identity",
      "rootIdentity",
      "macho",
    ]);
    const expected = prepared.helpers.find(({ name }) => name === helper.name);
    requireObservation(
      expected &&
        ["sha256", "sourceSha256", "cdhash"].every(
          (key) => helper[key] === expected[key],
        ) &&
        typeof helper.identity === "string" &&
        helper.identity.length > 0 &&
        typeof helper.rootIdentity === "string" &&
        helper.rootIdentity.length > 0,
    );
  }
}
/** Fresh held-image evidence belongs to the admitted native observer. ABI and
 * retirement receipts remain observations of the original build lifecycle. */
export async function observeDarwinExperimentImages(
  prepared,
  reader,
  previous,
) {
  const reads = [],
    helpers = [];
  for (const name of DARWIN_HELPER_NAMES) {
    const expected = prepared.helpers.find((helper) => helper.name === name),
      image = await reader.readBuildImage(
        path.join(prepared.output, name),
        expected.sha256,
      ),
      macho = inspectDarwinMachO(image.bytes, 134217728, "experiment");
    requireObservation(
      image.independent === true &&
        image.held === true &&
        image.unchanged === true &&
        hash(image.nativeEventSha256) &&
        image.sha256 === expected.sha256 &&
        image.sha256 === macho.sha256 &&
        image.signature?.valid === true &&
        image.signature.cdhash === expected.cdhash &&
        macho.libraries.length > 0 &&
        image.macho.rpaths.length === 0 &&
        observationDigest(image.macho.dependencies.slice().sort()) ===
          observationDigest([...macho.libraries, macho.loader].sort()),
    );
    reads.push(image.nativeEventSha256);
    helpers.push({
      name,
      sha256: image.sha256,
      sourceSha256: expected.sourceSha256,
      cdhash: image.signature.cdhash,
      identity: image.identity,
      rootIdentity: image.rootIdentity,
      macho: image.macho,
    });
  }
  if (previous)
    requireObservation(
      observationDigest(helpers) === observationDigest(previous.helpers),
    );
  return {
    purpose: "experiment",
    source: "native",
    helpers,
    readSha256: observationDigest(reads),
  };
}

async function observe(prepared, reader, options) {
  const reads = [],
    helpers = [],
    fs = options.fs ?? filesystem;
  for (const tool of prepared.tools)
    requireObservation(
      digest(await (options.readInstalled ?? fs.readFile)(tool.path)) ===
        tool.sha256,
    );
  requireObservation(
    digest(
      await (options.readInstalled ?? fs.readFile)(
        path.join(prepared.sdk.path, "SDKSettings.json"),
      ),
    ) === prepared.sdk.settingsSha256,
  );
  for (const source of prepared.sources) {
    const value = await reader.readBuildInput(
      path.join(prepared.sourceDirectory, source.name),
      source.sha256,
    );
    requireObservation(
      value.independent === true &&
        value.held === true &&
        value.unchanged === true &&
        value.sha256 === source.sha256 &&
        hash(value.nativeEventSha256),
    );
    reads.push(value.nativeEventSha256);
  }
  const images = await observeDarwinExperimentImages(prepared, reader);
  helpers.push(...images.helpers);
  reads.push(images.readSha256);
  const installed = await reader.build();
  requireObservation(installed.purpose === "experiment");
  const sdk = { ...prepared.sdk };
  sdk.sha256 = observationDigest(sdk);
  const build = {
    schemaVersion: 3,
    purpose: "experiment",
    status: "OBSERVED",
    context: jobContext(prepared.job),
    bindingSha256: observationDigest(prepared.binding),
    preparationSha256: observationDigest(prepared),
    helpers,
    tools: prepared.tools,
    sources: prepared.sources,
    sdk,
    commands: prepared.commands,
    compilerVersion: prepared.compilerVersion,
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
  assertDarwinExperimentBuild(prepared, build);
  return { purpose: "experiment", build, readSha256: observationDigest(reads) };
}

/** Build completion is distinct from full case preparation and its native custody. */
export async function prepareDarwinExperimentBuild(
  input,
  directory,
  persist,
  options = {},
) {
  let job = normalizeExperimentJob(input),
    state,
    primary,
    closed = false;
  darwinExperimentWorker(job, options.binding, options);
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
    const prepared = structuredClone(
      await (options.acquire ?? acquireDarwinExperimentBuild)(
        job,
        directory,
        options.binding,
        options,
      ),
    );
    const declaration = darwinExperimentBuildInput(prepared, job, directory);
    await candidateSources(prepared, options);
    state = darwinPreparationContext(declaration, options);
    await state.write("darwin-experiment-build-selector.json", prepared, false);
    const { reader } = await state.bootstrap(options.signal);
    const observed = await observe(prepared, reader, options);
    await reader.verifyBuildReceipt(
      await state.write("darwin-experiment-build.json", observed, false),
    );
    const close = {
      purpose: "experiment",
      ...(await state.releaseBootstrap()),
    };
    closed = true;
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
    if (state && !closed)
      try {
        requireObservation(
          retired(await state.settleBootstrap({ recover: !!primary })),
        );
      } catch (cause) {
        nativeException("darwin-experiment-build-cleanup", cause);
        if (!primary) throw cause;
      }
  }
}

async function selected(job, directory, options, recovery = false) {
  const fs = options.fs ?? filesystem;
  const bytes = await (
    options.readSelector ??
    ((file) =>
      readDarwinPreparationReceipt(
        file,
        fs,
        options.ownerUid ?? (() => process.getuid()),
      ))
  )(path.join(directory, "darwin-experiment-build-selector.json"));
  requireObservation(Buffer.isBuffer(bytes) && bytes.length <= 1048576);
  const prepared = JSON.parse(bytes);
  darwinExperimentWorker(job, prepared.binding, options);
  requireObservation(
    Object.keys(prepared.binding).every(
      (key) => prepared.binding[key] === options.binding[key],
    ),
  );
  const declaration = darwinExperimentBuildInput(prepared, job, directory);
  await candidateSources(prepared, options);
  const state = darwinPreparationContext(declaration, options),
    readReceipt = recovery
      ? state.receipt
      : (options.readReceipt ?? state.stockReceipt);
  if (recovery)
    requireObservation(
      observationDigest(
        JSON.parse(
          await readReceipt(
            path.join(directory, "darwin-experiment-build-selector.json"),
          ),
        ),
      ) === observationDigest(prepared),
    );
  return { prepared, state, readReceipt };
}

/** Rejoin a settled build through bounded file reads. This creates no native
 * owner, recovery journal, ABI event or independent held-image observation. */
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
  if (options.signal?.aborted) throw options.signal.reason;
  const { prepared, state, readReceipt } = await selected(
    job,
    directory,
    options,
  );
  await state.admit(options.signal);
  const record = async (name) => {
    const bytes = await readReceipt(path.join(directory, name));
    requireObservation(
      Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= 1048576,
    );
    return JSON.parse(bytes);
  };
  const observed = await record("darwin-experiment-build.json"),
    close = await record("darwin-experiment-build-close.json");
  observationObject(observed, ["purpose", "build", "readSha256"]);
  requireObservation(
    observed.purpose === "experiment" &&
      hash(observed.readSha256) &&
      observationDigest({ observed, close }) ===
        job.preparationEffects.receiptSha256 &&
      close.purpose === "experiment" &&
      retired(close) &&
      close.closed === true &&
      hash(close.nativeEventSha256),
  );
  assertDarwinExperimentBuild(prepared, observed.build);
  const reads = [];
  const read = async (file, pin, maximum = 134217728, installed = false) => {
    state.guard(options.signal);
    let bytes;
    if (installed) {
      // Ordinary installed toolchains retain hosted-image eligibility. Private
      // source/output reads below keep their protected metadata requirements.
      requireObservation(isDarwinInstalledPath(file));
      bytes = options.readInstalled
        ? await options.readInstalled(file)
        : await protectedBytes(
            { path: file, sha256: pin },
            0,
            0,
            maximum,
            state.fs,
            true,
            "experiment",
          );
    } else bytes = await state.read(file, pin, maximum);
    requireObservation(
      Buffer.isBuffer(bytes) &&
        bytes.length > 0 &&
        bytes.length <= maximum &&
        digest(bytes) === pin,
    );
    reads.push({ path: file, sha256: pin });
    return bytes;
  };
  for (const tool of prepared.tools)
    await read(tool.path, tool.sha256, 134217728, true);
  await read(
    path.join(prepared.sdk.path, "SDKSettings.json"),
    prepared.sdk.settingsSha256,
    1048576,
    true,
  );
  for (const source of prepared.sources)
    await read(
      path.join(prepared.sourceDirectory, source.name),
      source.sha256,
      1048576,
    );
  for (const helper of observed.build.helpers) {
    const bytes = await read(
      path.join(prepared.output, helper.name),
      helper.sha256,
    );
    const macho = inspectDarwinMachO(bytes, 134217728, "experiment");
    requireObservation(
      macho.sha256 === helper.sha256 &&
        macho.libraries.length > 0 &&
        helper.macho.rpaths.length === 0 &&
        observationDigest(helper.macho.dependencies.slice().sort()) ===
          observationDigest([...macho.libraries, macho.loader].sort()),
    );
  }
  await state.admit(options.signal);
  return {
    job,
    purpose: "experiment",
    prepared,
    build: observed.build,
    retained: { readSha256: observed.readSha256, close },
    revalidation: { source: "file", readSha256: observationDigest(reads) },
  };
}

/** Interrupted compiler/publication work has no replacement receipt. Only an
 * already completed build and original native reader journals can be rejoined. */
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
    prepared,
    settlement = retained(),
    receiptSha256 = null;
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
    ).length;
    const fence = path.join(
      directory,
      `darwin-recovery-${sequence}-intent.json`,
    );
    await fs.writeFile(
      fence,
      JSON.stringify({
        purpose: "experiment",
        admission: "CLOSED",
        context: jobContext(job),
      }) + "\n",
      { flag: "wx", mode: 0o400 },
    );
    ({ state, prepared } = await selected(job, directory, options, true));
    state.fence();
    await state.receipt(fence);
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
    observationObject(observed, ["purpose", "build", "readSha256"]);
    requireObservation(
      observed.purpose === "experiment" &&
        hash(observed.readSha256) &&
        close.purpose === "experiment" &&
        hash(close.nativeEventSha256) &&
        observed.build.schemaVersion === 3 &&
        observed.build.preparationSha256 ===
          observationDigest(
            JSON.parse(
              await state.receipt(
                path.join(directory, "darwin-experiment-build-selector.json"),
              ),
            ),
          ) &&
        retired(close) &&
        close.closed === true,
    );
    assertDarwinExperimentBuild(prepared, observed.build);
    const result = await recoverDarwinBuild(
      state,
      await recordsFor(state),
      options.signal,
      undefined,
      { recovery: true },
    );
    requireObservation(retired(result));
    settlement = {
      status: "RETIRED",
      independent: true,
      emergencyCleanup: false,
    };
    receiptSha256 = observationDigest({ observed, close });
    if (retired(job.preparationEffects.settlement))
      requireObservation(
        receiptSha256 === job.preparationEffects.receiptSha256,
      );
  } catch (cause) {
    settlement = retained();
    receiptSha256 = null;
    nativeException("darwin-experiment-build-recovery", cause);
  } finally {
    if (state)
      try {
        requireObservation(retired(await state.settleBootstrap()));
      } catch (cause) {
        settlement = retained();
        receiptSha256 = null;
        nativeException("darwin-experiment-build-recovery-cleanup", cause);
      }
  }
  const effect = {
    admission: "possible",
    settlement: {
      ...settlement,
      emergencyCleanup: job.preparationEffects.settlement.emergencyCleanup,
    },
    receiptSha256,
  };
  const recovered = retired(job.preparationEffects.settlement)
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
