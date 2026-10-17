import { execFile } from "node:child_process";
import * as filesystem from "node:fs/promises";
import * as os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import {
  attemptNativeBuilds,
  diagnosticCommand,
  nativeDiagnostic,
} from "../diagnostics.js";
import {
  nativeCandidateReader,
  observationDigest,
  observationObject,
  requireObservation,
} from "../index.js";
import {
  DARWIN_HELPER_NAMES,
  darwinCompilerArguments,
  darwinDeveloperDirectory,
  darwinBuildToolchain,
} from "./build.js";
import { encodeDarwinCustodyPlan } from "./custody.js";
import { digest, inspectDarwinMachO } from "./protocol.js";
import { protectedInstalledInput } from "./private-files.js";
import { acquireDarwinBootstrapTools } from "./bootstrap-tools.js";
import {
  observeDarwinPfCapabilities,
  observeDarwinPfExecutable,
} from "./pf-preparation.js";

const ROOT = fileURLToPath(new URL("../../../", import.meta.url));
export const DARWIN_EXPERIMENT_SOURCES = Object.freeze([
  ...DARWIN_HELPER_NAMES.map((name) => name + ".c"),
  "custody.h",
  "file-identity.h",
  "effective-reader.h",
  "feasibility-sandbox.h",
  "experiment.h",
  "pf-abi.h",
]);
export const DARWIN_PF_ABI_REFERENCE = Object.freeze({
  url: "https://github.com/apple-oss-distributions/xnu/blob/xnu-11417.140.69/bsd/net/pfvar.h",
  tag: "xnu-11417.140.69",
  gitBlob: "691a4e711f5c8ec77184d575e4ffebb9ce41d772",
  sha256: "aeaaa90c761577247bfa0328bd4765512f787f5af9a56b9bb530030c90a692c9",
});
const execute = diagnosticCommand(
  "darwin-experiment-bootstrap",
  promisify(execFile),
);
const absolute = (value) =>
  typeof value === "string" &&
  path.isAbsolute(value) &&
  path.normalize(value) === value &&
  !/[\0\r\n]/u.test(value);
export function darwinExperimentWorker(job, binding, options) {
  const env = options.env ?? process.env;
  observationObject(binding, [
    "candidateSha",
    "platform",
    "repository",
    "runId",
    "runAttempt",
    "checkoutSha",
    "image",
    "osBuild",
    "architecture",
    "nodeVersion",
    "workflow",
    "jobId",
  ]);
  requireObservation(
    job.purpose === "experiment" &&
      job.platform === "darwin" &&
      (options.platform ?? process.platform) === "darwin" &&
      (options.architecture ?? process.arch) === "x64" &&
      env.CI === "true" &&
      env.GITHUB_ACTIONS === "true" &&
      env.ImageOS === "macos15" &&
      env.RUNNER_ENVIRONMENT === "github-hosted" &&
      env.RUNNER_OS === "macOS" &&
      env.GITHUB_REPOSITORY === job.repository &&
      env.GITHUB_RUN_ID === job.runId &&
      env.GITHUB_RUN_ATTEMPT === String(job.runAttempt) &&
      binding?.checkoutSha === job.candidateSha &&
      binding.platform === "darwin" &&
      binding.architecture === "x64" &&
      binding.nodeVersion === "v24.21.0" &&
      (options.nodeVersion ?? process.version) === binding.nodeVersion,
  );
  for (const key of ["candidateSha", "repository", "runId", "runAttempt"])
    requireObservation(binding[key] === job[key]);
  requireObservation(
    binding.image === "macos-15-intel" &&
      typeof binding.osBuild === "string" &&
      /^[A-Za-z0-9.]{1,256}$/u.test(binding.osBuild) &&
      binding.workflow === "native-poc" &&
      typeof binding.jobId === "string" &&
      /^[1-9][0-9]{0,19}$/u.test(binding.jobId),
  );
  return env;
}

/** Acquisition and seed compilation supply selectors only. Native custody must
 * independently re-read every input and rebuild every reported helper. */
export async function acquireDarwinExperimentBuild(
  job,
  directory,
  binding,
  persist,
  options = {},
) {
  const env = darwinExperimentWorker(job, binding, options),
    fs = options.fs ?? filesystem;
  requireObservation(job.preparationEffects.admission === "possible");
  const admit = async () => {
    requireObservation(!options.signal?.aborted);
    try {
      requireObservation(
        !(await fs.readdir(directory)).some((name) =>
          name.startsWith("darwin-recovery-"),
        ),
      );
    } catch (cause) {
      if (cause.code !== "ENOENT") throw cause;
    }
  };
  const run = async (file, args, extra = {}) => {
    if (!options.command)
      requireObservation(
        process.platform === "darwin" &&
          process.arch === "x64" &&
          process.env.GITHUB_ACTIONS === "true",
      );
    await admit();
    await persist({
      purpose: "experiment",
      phase: "seed-command-possible",
      file,
      args,
    });
    await admit();
    const { env: commandEnvironment = {}, ...settings } = extra;
    return (options.command ?? execute)(file, args, {
      env: {
        CI: "true",
        GITHUB_ACTIONS: "true",
        LANG: "C",
        PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
        ...commandEnvironment,
      },
      signal: options.signal,
      encoding: "utf8",
      timeout: 60000,
      maxBuffer: 1048576,
      ...settings,
    });
  };
  const read = async (
    file,
    maximum = 134217728,
    installed = false,
    identity,
  ) => {
    let canonical;
    requireObservation(
      absolute(file) && (canonical = await fs.realpath(file)) === file,
    );
    const before = await fs.lstat(file);
    let isFile = null,
      isSymbolicLink = null;
    try {
      requireObservation(
        (isFile = before.isFile()) &&
          !(isSymbolicLink = before.isSymbolicLink()) &&
          (before.nlink === 1 ||
            (installed && (await protectedInstalledInput(file, before, fs)))) &&
          before.size > 0 &&
          before.size <= maximum,
      );
    } catch (error) {
      try {
        nativeDiagnostic("darwin-experiment-installed-input", {
          stderr: JSON.stringify({
            requestedPath: file.slice(0, 1024),
            canonicalPath: canonical.slice(0, 1024),
            requestedPathLength: file.length,
            canonicalPathLength: canonical.length,
            // Preserve short-circuit sampling; unsampled predicates remain null.
            isFile: typeof isFile === "boolean" ? isFile : null,
            isSymbolicLink:
              typeof isSymbolicLink === "boolean" ? isSymbolicLink : null,
            maximum,
            stat: Object.fromEntries(
              [
                "dev",
                "ino",
                "mode",
                "uid",
                "gid",
                "nlink",
                "size",
                "atimeMs",
                "mtimeMs",
                "ctimeMs",
                "birthtimeMs",
              ].map((key) => {
                const value = before[key];
                return [
                  key,
                  typeof value === "number" && Number.isFinite(value)
                    ? value
                    : null,
                ];
              }),
            ),
          }),
        });
      } catch {
        // Diagnostic construction and sink failure cannot change admission.
      }
      throw error;
    }
    const bytes = await fs.readFile(file),
      after = await fs.lstat(file);
    requireObservation(
      bytes.length === before.size &&
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
        ].every((key) => before[key] === after[key]) &&
        (before.nlink === 1 ||
          (installed && (await protectedInstalledInput(file, after, fs)))),
    );
    if (identity) Object.assign(identity, { dev: after.dev, ino: after.ino });
    return bytes;
  };
  requireObservation(
    absolute(directory) &&
      absolute(env.RUNNER_TEMP) &&
      directory.startsWith(env.RUNNER_TEMP + "/") &&
      (await fs.realpath(env.RUNNER_TEMP)) === env.RUNNER_TEMP,
  );
  requireObservation(
    (await run("git", ["rev-parse", "HEAD"], { cwd: ROOT })).stdout.trim() ===
      job.candidateSha,
  );
  const discover = async (args, environment) => {
    const value = (
      await run("/usr/bin/xcrun", args, { env: environment })
    ).stdout.trim();
    requireObservation(absolute(value));
    return fs.realpath(value);
  };
  // These observations only reject unsafe candidates. Native held reads and
  // the sealed compiler entry independently establish admission later.
  const seen = new Set();
  const inspectSdk = async (candidate, alternative = false) => {
    try {
      const canonical = await fs.realpath(candidate);
      requireObservation(
        absolute(canonical) &&
          canonical.length < 4096 &&
          !/[\u0000-\u001f\u007f]/u.test(canonical),
      );
      if (seen.has(canonical)) return null;
      seen.add(canonical);
      if (alternative)
        requireObservation(
          canonical.startsWith("/Library/Developer/CommandLineTools/SDKs/") &&
            (await fs.realpath("/Library/Developer/CommandLineTools")) ===
              "/Library/Developer/CommandLineTools",
        );
      let root;
      for (let parent = canonical, depth = 0; depth < 32; depth++) {
        const before = await fs.lstat(parent);
        requireObservation(
          before.isDirectory() &&
            !before.isSymbolicLink() &&
            before.uid === 0 &&
            !(before.mode & 0o22) &&
            (await fs.realpath(parent)) === parent,
        );
        const after = await fs.lstat(parent);
        requireObservation(
          ["dev", "ino", "mode", "uid", "gid", "mtimeMs", "ctimeMs"].every(
            (key) => before[key] === after[key],
          ),
        );
        if (parent === canonical) root = before;
        if (parent === "/") {
          const settings = path.join(canonical, "SDKSettings.json"),
            stat = await fs.lstat(settings);
          requireObservation(await protectedInstalledInput(settings, stat, fs));
          const settingsSha256 = digest(await read(settings, 536870912, true));
          const current = await fs.lstat(canonical);
          requireObservation(
            [root.dev, root.ino].every(
              (value) => Number.isSafeInteger(value) && value >= 0,
            ) &&
              ["dev", "ino", "mode", "uid", "gid", "mtimeMs", "ctimeMs"].every(
                (key) => root[key] === current[key],
              ),
          );
          return {
            path: canonical,
            dev: String(root.dev),
            ino: String(root.ino),
            settingsSha256,
          };
        }
        parent = path.dirname(parent);
      }
    } catch (cause) {
      if (options.signal?.aborted) throw cause;
      // An unverifiable candidate cannot be adopted. There is only one
      // documented alternative, and no reselection after seed admission.
    }
    return null;
  };
  const defaultSdk = (
    await run("/usr/bin/xcrun", ["--show-sdk-path"])
  ).stdout.trim();
  requireObservation(absolute(defaultSdk));
  const sdk =
    (await inspectSdk(defaultSdk)) ??
    (await inspectSdk(
      "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk",
      true,
    ));
  requireObservation(sdk);
  const SDKROOT = sdk.path,
    DEVELOPER_DIR = darwinDeveloperDirectory(SDKROOT),
    environment = { SDKROOT, DEVELOPER_DIR },
    developerBefore = await fs.lstat(DEVELOPER_DIR);
  requireObservation(
    (await fs.realpath(DEVELOPER_DIR)) === DEVELOPER_DIR &&
      developerBefore.isDirectory() &&
      !developerBefore.isSymbolicLink() &&
      developerBefore.uid === 0 &&
      !(developerBefore.mode & 0o22) &&
      [developerBefore.dev, developerBefore.ino].every(
        (value) => Number.isSafeInteger(value) && value >= 0,
      ),
  );
  const compiler = await discover(
      ["--sdk", SDKROOT, "--find", "clang"],
      environment,
    ),
    bin =
      DEVELOPER_DIR +
      (DEVELOPER_DIR === "/Library/Developer/CommandLineTools"
        ? "/usr/bin"
        : "/Toolchains/XcodeDefault.xctoolchain/usr/bin");
  requireObservation(compiler === (await fs.realpath(path.join(bin, "clang"))));
  const sourceDirectory = "/Library/native-poc-" + observationDigest(binding),
    staging = directory + "-seed",
    output = path.join(directory, "platform-build");
  await persist({
    purpose: "experiment",
    phase: "seed-possible",
    directory,
    staging,
    sourceDirectory,
    output,
    bindingSha256: observationDigest(binding),
  });
  await admit();
  await fs.mkdir(directory, { mode: 0o700 });
  await fs.mkdir(staging, { mode: 0o700 });
  const candidate =
      options.readCandidate ?? nativeCandidateReader(job.candidateSha, ROOT),
    sources = [];
  for (const name of DARWIN_EXPERIMENT_SOURCES) {
    const bytes = await candidate("ci/native/darwin/" + name, 1048576);
    requireObservation(
      Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= 1048576,
    );
    await admit();
    await fs.writeFile(path.join(staging, name), bytes, {
      flag: "wx",
      mode: 0o444,
    });
    sources.push({ name, sha256: digest(bytes) });
  }
  const signature = async (file) => {
    const result = await run("/usr/bin/codesign", ["-d", "--verbose=4", file]),
      cdhash = /^CDHash=([a-f0-9]{40})$/mu.exec(result.stderr)?.[1];
    requireObservation(cdhash);
    return cdhash;
  };
  const tools = [];
  for (const [name, file] of [
    ["compiler", "/usr/bin/clang"],
    ["sdk", "/usr/bin/xcrun"],
    ["signer", "/usr/bin/codesign"],
  ])
    tools.push({
      name,
      path: file,
      sha256: digest(await read(file, 134217728, true)),
      cdhash: await signature(file),
    });
  const inputs = new Map(),
    inputIdentities = new Map();
  const input = async (file) => {
    file = await fs.realpath(file);
    const identity = {},
      sha256 = digest(await read(file, 536870912, true, identity));
    requireObservation(
      [identity.dev, identity.ino].every(
        (value) => Number.isSafeInteger(value) && value >= 0,
      ),
    );
    if (inputs.has(file)) requireObservation(inputs.get(file) === sha256);
    const previous = inputIdentities.get(file);
    if (previous)
      requireObservation(
        previous.dev === identity.dev && previous.ino === identity.ino,
      );
    inputs.set(file, sha256);
    inputIdentities.set(file, identity);
    return file;
  };
  await input(compiler);
  await input(path.join(SDKROOT, "SDKSettings.json"));
  requireObservation(
    inputs.get(path.join(SDKROOT, "SDKSettings.json")) === sdk.settingsSha256,
  );
  await input("/usr/lib/dyld");
  await observeDarwinPfCapabilities(SDKROOT, compiler, {
    context: {
      binding,
      observed: Object.fromEntries(
        ["type", "release", "version", "arch"].map((key) => [
          key,
          String((options.os ?? os)[key]()).slice(0, 1024),
        ]),
      ),
      sdk: {
        path: SDKROOT,
        settingsSha256: inputs.get(path.join(SDKROOT, "SDKSettings.json")),
      },
      compiler: { path: compiler, sha256: inputs.get(compiler) },
    },
    read: (file) => read(file, 134217728, true),
    executable: (file) => observeDarwinPfExecutable(file, fs),
    run: (file, args, settings) =>
      run(
        file,
        args,
        file === compiler ? { ...settings, env: environment } : settings,
      ),
    signal: options.signal,
  });
  const delegated = new Set();
  for (const name of DARWIN_HELPER_NAMES) {
    const args = darwinCompilerArguments(
      path.join(staging, name + ".c"),
      path.join(staging, name),
      environment,
      "experiment",
    );
    const query = await run(compiler, ["-###", ...args], {
      cwd: staging,
      env: environment,
    });
    let programs = 0;
    for (const line of query.stderr.split(/\r?\n/u)) {
      const program = /^\s*"((?:[^"\\]|\\.)+)"\s/u.exec(line)?.[1];
      if (!program) continue;
      const file = JSON.parse('"' + program + '"');
      requireObservation(absolute(file));
      const canonical = await input(file);
      requireObservation(path.dirname(canonical) === bin);
      if (canonical !== compiler) delegated.add(canonical);
      requireObservation(delegated.size < 16);
      programs++;
    }
    requireObservation(programs >= 2);
  }
  const tool = async (file) => ({
    path: file,
    sha256: inputs.get(file),
    cdhash: await signature(file),
    dev: String(inputIdentities.get(file).dev),
    ino: String(inputIdentities.get(file).ino),
  });
  const delegatedTools = [];
  for (const file of [...delegated].sort())
    delegatedTools.push(await tool(file));
  const toolchain = darwinBuildToolchain(
    {
      developer: {
        path: DEVELOPER_DIR,
        dev: String(developerBefore.dev),
        ino: String(developerBefore.ino),
      },
      compiler: await tool(compiler),
      delegated: delegatedTools,
    },
    SDKROOT,
    DEVELOPER_DIR,
  );
  const build = (name) =>
    run(
      compiler,
      darwinCompilerArguments(
        path.join(staging, name + ".c"),
        path.join(staging, name),
        environment,
        "experiment",
      ),
      { cwd: staging, env: environment },
    );
  await attemptNativeBuilds(
    "darwin-bootstrap-builds",
    DARWIN_HELPER_NAMES.map((name) => ({ name, run: () => build(name) })),
    {
      signal: options.signal,
      verify: async () => {
        await admit();
        for (const source of sources)
          requireObservation(
            digest(await read(path.join(staging, source.name))) ===
              source.sha256,
          );
        for (const tool of tools)
          requireObservation(
            digest(await read(tool.path, 134217728, true)) === tool.sha256,
          );
        for (const [file, pin] of inputs) {
          const actual = {};
          requireObservation(
            digest(await read(file, 536870912, true, actual)) === pin &&
              actual.dev === inputIdentities.get(file).dev &&
              actual.ino === inputIdentities.get(file).ino,
          );
        }
        const after = await fs.lstat(DEVELOPER_DIR);
        requireObservation(
          (await fs.realpath(DEVELOPER_DIR)) === DEVELOPER_DIR &&
            ["dev", "ino", "mode", "uid", "gid", "mtimeMs", "ctimeMs"].every(
              (key) => developerBefore[key] === after[key],
            ) &&
            (await fs.realpath(path.join(bin, "clang"))) === compiler,
        );
      },
    },
  );
  const seeds = [];
  for (const name of ["custody-reader", "build-helper"]) {
    const target = path.join(staging, name);
    await run("/usr/bin/codesign", [
      "--force",
      "--sign",
      "-",
      "--timestamp=none",
      target,
    ]);
    await run("/usr/bin/codesign", ["--verify", "--strict", target]);
    const bytes = await read(target);
    inspectDarwinMachO(bytes, 134217728, "experiment");
    seeds.push({
      name,
      path: path.join(sourceDirectory, name),
      sha256: digest(bytes),
      cdhash: await signature(target),
    });
  }
  const context = {
    candidateSha: job.candidateSha,
    platform: "darwin",
    tier: "system",
    runId: job.runId,
    runAttempt: job.runAttempt,
    jobBindingSha256: observationDigest(binding),
    executionId: "build",
    closureSha256: observationDigest({
      sources,
      tools,
      inputs: [...inputs],
      sdk,
      toolchain,
    }),
    selectedSystemSha256: null,
  };
  const entries = [
    { kind: "directory", path: output, sha256: null },
    ...seeds.map((seed) => ({
      kind: "helper",
      path: seed.path,
      sha256: seed.sha256,
    })),
    ...sources.map((source) => ({
      kind: "data",
      path: path.join(sourceDirectory, source.name),
      sha256: source.sha256,
    })),
    ...tools.map((tool) => ({
      kind: "image",
      path: tool.path,
      sha256: tool.sha256,
    })),
  ];
  // Build custody reserves no subject account; these unused numeric bindings
  // cannot authorize a payload or grant the runner's inherited primary group.
  const planBytes = encodeDarwinCustodyPlan({
      purpose: "experiment",
      candidateSha: job.candidateSha,
      uid: 90001,
      gid: 90002,
      entries,
    }),
    plan = {
      path: path.join(sourceDirectory, "build-plan"),
      sha256: digest(planBytes),
    };
  await fs.writeFile(path.join(staging, "build-plan"), planBytes, {
    flag: "wx",
    mode: 0o400,
  });
  const seedBytes = Buffer.from(
    [
      `native-experiment-bootstrap-v1 ${job.candidateSha} ${Buffer.from(directory).toString("hex")}`,
      ...sources.map((source) => `${source.name} ${source.sha256} -`),
      ...seeds.map((seed) => `${seed.name} ${seed.sha256} ${seed.cdhash}`),
      "",
    ].join("\n"),
  );
  await fs.writeFile(path.join(staging, "bootstrap-seed"), seedBytes, {
    flag: "wx",
    mode: 0o400,
  });
  const prepared = {
    purpose: "experiment",
    job,
    binding,
    directory,
    output,
    sourceDirectory,
    bootstrapSeed: {
      path: path.join(sourceDirectory, "bootstrap-seed"),
      sha256: digest(seedBytes),
      acquisition: null,
    },
    sources,
    tools,
    inputs: [...inputs].map(([path, sha256]) => ({ path, sha256 })),
    environment,
    helpers: DARWIN_HELPER_NAMES.map((name) => ({
      name,
      sourceSha256: sources.find((source) => source.name === name + ".c")
        .sha256,
      sha256: seeds.find((seed) => seed.name === name)?.sha256 ?? null,
    })),
    bootstrap: {
      purpose: "experiment",
      context,
      reader: { ...seeds[0] },
      sources: sources.map((source) => ({
        path: path.join(sourceDirectory, source.name),
        sha256: source.sha256,
      })),
      plan,
      tools: null,
      reportDirectory: directory,
      bindingSha256: observationDigest({ binding, sources, tools }),
      sdkSha256: observationDigest({ inputs: [...inputs], sdk, toolchain }),
      buildSha256: observationDigest({
        sources,
        tools,
        environment,
        sdk,
        toolchain,
      }),
    },
    command: {
      helper: { ...seeds[1] },
      sdk,
      toolchain,
      toolCdhashes: Object.fromEntries(
        tools.map((tool) => [tool.name, tool.cdhash]),
      ),
    },
  };
  delete prepared.bootstrap.reader.name;
  delete prepared.command.helper.name;
  for (const base of [
    "/System/Library/dyld",
    "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld",
  ]) {
    for (const name of [
      "dyld_shared_cache_x86_64h",
      "dyld_shared_cache_x86_64",
    ]) {
      try {
        const file = await fs.realpath(path.join(base, name));
        if ((await fs.lstat(file)).isFile()) {
          prepared.cachePath = file;
          break;
        }
      } catch (cause) {
        if (cause.code !== "ENOENT") throw cause;
      }
    }
    if (prepared.cachePath) break;
  }
  requireObservation(prepared.cachePath);
  await persist({ purpose: "experiment", phase: "seal-possible", prepared });
  await run("/usr/bin/sudo", [
    "-n",
    "--",
    "/bin/mkdir",
    "-m",
    "0700",
    sourceDirectory,
  ]);
  for (const name of [
    ...sources.map((source) => source.name),
    ...seeds.map((seed) => seed.name),
    "build-plan",
    "bootstrap-seed",
  ])
    await run("/usr/bin/sudo", [
      "-n",
      "--",
      "/bin/cp",
      "-p",
      path.join(staging, name),
      path.join(sourceDirectory, name),
    ]);
  await run("/usr/bin/sudo", [
    "-n",
    "--",
    "/usr/sbin/chown",
    "-R",
    "0:0",
    sourceDirectory,
  ]);
  await run("/usr/bin/sudo", [
    "-n",
    "--",
    "/bin/chmod",
    "0555",
    sourceDirectory,
    ...seeds.map((seed) => seed.path),
  ]);
  await persist({ purpose: "experiment", phase: "seed-sealed", prepared });
  const acquisition = await acquireDarwinBootstrapTools(
    prepared,
    persist,
    options,
  );
  prepared.bootstrapSeed.acquisition = acquisition;
  prepared.bootstrap.tools = acquisition.tools;
  prepared.bootstrap.bindingSha256 = observationDigest({
    binding,
    sources,
    tools,
    acquisition,
  });
  await persist({ purpose: "experiment", phase: "sealed", prepared });
  return prepared;
}
