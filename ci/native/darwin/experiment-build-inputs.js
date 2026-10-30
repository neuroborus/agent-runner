import { spawn } from "node:child_process";
import * as filesystem from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { diagnosticCommand } from "../diagnostics.js";
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
} from "./build.js";
import { encodeDarwinCustodyPlan } from "./custody.js";
import { digest, inspectDarwinMachO } from "./protocol.js";

const ROOT = fileURLToPath(new URL("../../../", import.meta.url));
// Match the native installed-input readers; private helper ceilings stay separate.
export const DARWIN_HOSTED_INPUT_BYTES = 536870912;
export const DARWIN_HOSTED_OUTPUT_BYTES = 256 * 1024;
export const DARWIN_EXPERIMENT_SOURCES = Object.freeze([
  ...DARWIN_HELPER_NAMES.map((name) => name + ".c"),
  "custody.h",
  "exec-handoff.h",
  "image-closure.h",
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
const absolute = (value) =>
  typeof value === "string" &&
  path.isAbsolute(value) &&
  path.normalize(value) === value &&
  !/[\0\r\n]/u.test(value);

export async function readDarwinHostedInput(file, maximum, read) {
  const bytes = await read(file, maximum);
  requireObservation(
    Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= maximum,
  );
  return bytes;
}

// The trusted compiler still owns a bounded process group. Abort/deadline kills
// the group, awaits the reaped leader and never publishes uncertain completion.
export function runDarwinHostedCommand(file, args, settings) {
  return new Promise((resolve, reject) => {
    settings.signal?.throwIfAborted();
    const child = (settings.spawn ?? spawn)(file, args, {
      cwd: settings.cwd,
      env: settings.env,
      detached: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout = [],
      stderr = [];
    let size = 0,
      failure,
      escalation;
    const kill = (signal) => {
      if (!child.pid) return;
      try {
        (settings.kill ?? process.kill)(-child.pid, signal);
      } catch (cause) {
        if (cause.code !== "ESRCH") failure ??= cause;
      }
    };
    const stop = (cause) => {
      failure ??=
        cause instanceof Error
          ? cause
          : new Error("Darwin hosted command cancelled", { cause });
      kill("SIGTERM");
      escalation ??= setTimeout(() => kill("SIGKILL"), 2000);
    };
    const abort = () => stop(settings.signal.reason);
    const deadline = setTimeout(
      () =>
        stop(
          Object.assign(new Error("Darwin hosted command timed out"), {
            timedOut: true,
          }),
        ),
      settings.timeout,
    );
    settings.signal?.addEventListener("abort", abort, { once: true });
    if (settings.signal?.aborted) abort();
    for (const [stream, chunks] of [
      [child.stdout, stdout],
      [child.stderr, stderr],
    ]) {
      stream.on("error", stop);
      stream.on("data", (bytes) => {
        size += bytes.length;
        if (size > settings.maxBuffer)
          stop(new Error("Darwin hosted command output exceeded its bound"));
        else chunks.push(bytes);
      });
    }
    child.once("error", (cause) => {
      failure ??= cause;
    });
    child.once("close", (exitCode, signal) => {
      clearTimeout(deadline);
      clearTimeout(escalation);
      settings.signal?.removeEventListener("abort", abort);
      if (child.pid) {
        try {
          (settings.kill ?? process.kill)(-child.pid, 0);
          stop(new Error("Darwin hosted command group remains live"));
          kill("SIGKILL");
          clearTimeout(escalation);
        } catch (cause) {
          if (cause.code !== "ESRCH") failure ??= cause;
        }
      }
      const result = {
        exitCode,
        signal,
        timedOut: false,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      };
      if (failure || exitCode !== 0 || signal !== null)
        reject(
          Object.assign(failure ?? new Error("Darwin hosted command failed"), {
            ...result,
            timedOut: failure?.timedOut ?? false,
          }),
        );
      else resolve(result);
    });
  });
}
const execute = diagnosticCommand(
  "darwin-hosted-build",
  runDarwinHostedCommand,
);

// No dependency snapshots: only the required experiment marker and build flags.
export function darwinHostedCompilerArguments(source, target, environment) {
  const args = darwinCompilerArguments(
    source,
    target,
    environment,
    "experiment",
  );
  const index = args.indexOf("-MD");
  args.splice(index, 3);
  return args;
}
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

/** Trust the installed hosted toolchain; compile/sign once, then publish case
 * images through the existing root custody boundary. This is no reviewed build. */
export async function acquireDarwinExperimentBuild(
  job,
  directory,
  binding,
  options = {},
) {
  const env = darwinExperimentWorker(job, binding, options),
    fs = options.fs ?? filesystem,
    readInstalled = (file, maximum) =>
      readDarwinHostedInput(file, maximum, (file) => fs.readFile(file));
  requireObservation(
    job.preparationEffects.admission === "possible" &&
      absolute(directory) &&
      absolute(env.RUNNER_TEMP) &&
      directory.startsWith(env.RUNNER_TEMP + "/") &&
      (await fs.realpath(env.RUNNER_TEMP)) === env.RUNNER_TEMP,
  );
  const commands = [];
  const admit = async () => {
    options.signal?.throwIfAborted();
    requireObservation(
      !(await fs.readdir(directory)).some((name) =>
        name.startsWith("darwin-recovery-"),
      ),
    );
  };
  const run = async (file, args, extra = {}) => {
    await admit();
    if (!options.command)
      requireObservation(
        process.platform === "darwin" && process.arch === "x64",
      );
    const request = {
      file,
      args,
      cwd: directory,
      env: {
        CI: "true",
        GITHUB_ACTIONS: "true",
        LANG: "C",
        PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
        ...extra,
      },
      timeout: 60000,
      maxBuffer: DARWIN_HOSTED_OUTPUT_BYTES,
    };
    const result = await (options.command ?? execute)(file, args, {
      ...request,
      signal: options.signal,
    });
    options.signal?.throwIfAborted();
    if (
      result.exitCode !== 0 ||
      result.signal !== null ||
      result.timedOut !== false
    )
      throw Object.assign(new Error("Darwin hosted command failed"), result);
    requireObservation(
      result.exitCode === 0 &&
        result.signal === null &&
        result.timedOut === false &&
        [result.stdout, result.stderr].every(
          (value) => typeof value === "string",
        ) &&
        Buffer.byteLength(result.stdout) + Buffer.byteLength(result.stderr) <=
          DARWIN_HOSTED_OUTPUT_BYTES,
    );
    commands.push({ ...request, ...result });
    return result;
  };
  await fs.mkdir(directory, { mode: 0o700 });
  const staging = path.join(directory, "hosted-build"),
    output = path.join(directory, "platform-build"),
    sourceDirectory = "/Library/native-poc-" + observationDigest(binding);
  await fs.mkdir(staging, { mode: 0o700 });
  requireObservation(
    (await run("git", ["-C", ROOT, "rev-parse", "HEAD"])).stdout.trim() ===
      job.candidateSha,
  );
  const sdkPath = (
    await run("/usr/bin/xcrun", ["--show-sdk-path"])
  ).stdout.trim();
  requireObservation(absolute(sdkPath));
  const SDKROOT = await fs.realpath(sdkPath),
    environment = { SDKROOT, DEVELOPER_DIR: darwinDeveloperDirectory(SDKROOT) };
  const compilerPath = (
    await run(
      "/usr/bin/xcrun",
      ["--sdk", SDKROOT, "--find", "clang"],
      environment,
    )
  ).stdout.trim();
  requireObservation(absolute(compilerPath));
  const compiler = await fs.realpath(compilerPath),
    sources = [],
    candidate =
      options.readCandidate ?? nativeCandidateReader(job.candidateSha, ROOT);
  for (const name of DARWIN_EXPERIMENT_SOURCES) {
    const bytes = await candidate("ci/native/darwin/" + name, 1048576);
    requireObservation(
      Buffer.isBuffer(bytes) &&
        bytes.length > 0 &&
        bytes.length <= 1048576 &&
        digest(await fs.readFile(path.join(ROOT, "ci/native/darwin", name))) ===
          digest(bytes),
    );
    await admit();
    await fs.writeFile(path.join(staging, name), bytes, {
      flag: "wx",
      mode: 0o444,
    });
    sources.push({ name, sha256: digest(bytes) });
  }
  const tools = [];
  for (const [name, file] of [
    ["compiler", compiler],
    ["sdk", "/usr/bin/xcrun"],
    ["signer", "/usr/bin/codesign"],
  ])
    tools.push({
      name,
      path: file,
      sha256: digest(await readInstalled(file, DARWIN_HOSTED_INPUT_BYTES)),
    });
  const version = await run(compiler, ["--version"], environment),
    sdkVersion = await run(
      "/usr/bin/xcrun",
      ["--sdk", SDKROOT, "--show-sdk-build-version"],
      environment,
    );
  requireObservation(
    /^(?:Apple )?clang version /u.test(version.stdout) &&
      /^[A-Za-z0-9.]+\n?$/u.test(sdkVersion.stdout),
  );
  const helpers = [];
  for (const name of DARWIN_HELPER_NAMES) {
    const target = path.join(staging, name);
    await run(
      compiler,
      darwinHostedCompilerArguments(
        path.join(staging, name + ".c"),
        target,
        environment,
      ),
      environment,
    );
    await run("/usr/bin/codesign", [
      "--force",
      "--sign",
      "-",
      "--timestamp=none",
      target,
    ]);
    await run("/usr/bin/codesign", ["--verify", "--strict", target]);
    const signature = await run("/usr/bin/codesign", [
        "-d",
        "--verbose=4",
        target,
      ]),
      cdhash = /^CDHash=([a-f0-9]{40})$/mu.exec(signature.stderr)?.[1];
    const bytes = await fs.readFile(target);
    inspectDarwinMachO(bytes, 134217728, "experiment");
    requireObservation(cdhash);
    helpers.push({
      name,
      sha256: digest(bytes),
      sourceSha256: sources.find((source) => source.name === name + ".c")
        .sha256,
      cdhash,
    });
  }
  const sdk = {
    path: SDKROOT,
    build: sdkVersion.stdout.trim(),
    settingsSha256: digest(
      await readInstalled(path.join(SDKROOT, "SDKSettings.json"), 1048576),
    ),
  };
  const context = {
    candidateSha: job.candidateSha,
    platform: "darwin",
    tier: "system",
    runId: job.runId,
    runAttempt: job.runAttempt,
    jobBindingSha256: observationDigest(binding),
    executionId: "build",
    closureSha256: observationDigest({ sources, tools, sdk }),
    selectedSystemSha256: null,
  };
  const image = (name) => {
    const value = helpers.find((helper) => helper.name === name);
    return {
      path: path.join(sourceDirectory, name),
      sha256: value.sha256,
      cdhash: value.cdhash,
    };
  };
  const planBytes = encodeDarwinCustodyPlan({
    purpose: "experiment",
    candidateSha: job.candidateSha,
    uid: 90001,
    gid: 90002,
    entries: [
      { kind: "directory", path: output, sha256: null },
      ...["custody-reader", "build-helper"].map((name) => ({
        kind: "helper",
        path: image(name).path,
        sha256: image(name).sha256,
      })),
      ...sources.map((source) => ({
        kind: "data",
        path: path.join(sourceDirectory, source.name),
        sha256: source.sha256,
      })),
    ],
  });
  await fs.writeFile(path.join(staging, "build-plan"), planBytes, {
    flag: "wx",
    mode: 0o400,
  });
  // Root publication already needs fixed sudo authority. A bounded byte read
  // also observes execute-only sudo without another acquisition owner/journal.
  const launchTools = await run("/usr/bin/sudo", [
    "-n",
    "--",
    "/usr/bin/shasum",
    "-a",
    "256",
    "/usr/bin/sudo",
    "/usr/bin/env",
  ]);
  const launchPins = launchTools.stdout.trimEnd().split("\n");
  requireObservation(launchPins.length === 2);
  const launchTool = (file, index) => {
    const match = /^([a-f0-9]{64})  (\/usr\/bin\/(?:sudo|env))$/u.exec(
      launchPins[index],
    );
    requireObservation(match && match[2] === file);
    return { path: file, sha256: match[1] };
  };
  const bootstrap = {
    purpose: "experiment",
    context,
    reader: image("custody-reader"),
    sources: sources.map((source) => ({
      path: path.join(sourceDirectory, source.name),
      sha256: source.sha256,
    })),
    plan: {
      path: path.join(sourceDirectory, "build-plan"),
      sha256: digest(planBytes),
    },
    tools: {
      elevation: launchTool("/usr/bin/sudo", 0),
      environment: launchTool("/usr/bin/env", 1),
    },
    reportDirectory: directory,
    bindingSha256: observationDigest({ binding, sources, tools }),
    sdkSha256: observationDigest(sdk),
    buildSha256: observationDigest({ sources, tools, environment, helpers }),
  };
  await run("/usr/bin/sudo", [
    "-n",
    "--",
    "/bin/mkdir",
    "-m",
    "0700",
    sourceDirectory,
    output,
  ]);
  // Darwin mkdir inherits the parent's GID. Both directories were just created
  // exclusively above; published native custody still requires UID0/GID0.
  await run("/usr/bin/sudo", [
    "-n",
    "--",
    "/usr/sbin/chown",
    "0:0",
    sourceDirectory,
    output,
  ]);
  const publish = async (source, target, mode) =>
    run("/usr/bin/sudo", [
      "-n",
      "--",
      "/usr/bin/install",
      "-o",
      "0",
      "-g",
      "0",
      "-m",
      mode,
      path.join(staging, source),
      target,
    ]);
  for (const { name } of sources)
    await publish(name, path.join(sourceDirectory, name), "0444");
  for (const { name } of helpers)
    await publish(name, path.join(output, name), "0555");
  for (const name of ["custody-reader", "build-helper"])
    await publish(name, path.join(sourceDirectory, name), "0555");
  await publish("build-plan", bootstrap.plan.path, "0400");
  await run("/usr/bin/sudo", [
    "-n",
    "--",
    "/bin/chmod",
    "0555",
    sourceDirectory,
    output,
  ]);
  // Sources and installed tools are observations of actual bytes, not receipts.
  for (const { name, sha256 } of sources)
    requireObservation(
      digest(await fs.readFile(path.join(staging, name))) === sha256,
    );
  for (const tool of tools)
    requireObservation(
      digest(await readInstalled(tool.path, DARWIN_HOSTED_INPUT_BYTES)) ===
        tool.sha256,
    );
  return {
    purpose: "experiment",
    schemaVersion: 3,
    job,
    binding,
    directory,
    output,
    sourceDirectory,
    sources,
    tools,
    environment,
    helpers,
    bootstrap,
    command: { helper: image("build-helper") },
    sdk,
    compilerVersion: version.stdout.trim(),
    commands,
  };
}
