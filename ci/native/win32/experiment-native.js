import { execFile, spawn } from "node:child_process";
import * as fs from "node:fs/promises";
import { win32 as path } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import { diagnosticCommand, nativeException } from "../diagnostics.js";
import { selectInstalledWindowsToolchain } from "../feasibility/index.js";
import {
  nativeCandidateReader,
  observationDigest,
  requireObservation,
} from "../index.js";
import { digest } from "./protocol.js";
import {
  WINDOWS_HELPER_NAMES,
  WINDOWS_BUILD_TOOLS,
  windowsCompilerArguments,
} from "./build.js";
import { encodeWindowsCustodyPlan, location } from "./custody-protocol.js";
import { createWindowsPreparationFiles } from "./preparation-files.js";
import {
  recoverWindowsPreparationOwners,
  windowsRetired,
} from "./preparation.js";
import { inspectWindowsExperimentPe } from "./experiment-image.js";

// Ordinary compilers own a bounded child tree; privileged case processes retain
// their separate creation-time Jobs and native retirement owners.
export function runWindowsHostedCommand(file, args, settings) {
  return new Promise((resolve, reject) => {
    settings.signal?.throwIfAborted();
    requireObservation(settings.spawn || process.platform === "win32");
    const child = (settings.spawn ?? spawn)(file, args, {
      cwd: settings.cwd,
      env: settings.env,
      windowsHide: true,
      windowsVerbatimArguments: settings.windowsVerbatimArguments,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout = [],
      stderr = [];
    let size = 0,
      failure,
      cleanup,
      cleanupCause;
    const stop = (cause) => {
      failure ??=
        cause instanceof Error
          ? cause
          : new Error("Windows hosted command cancelled", { cause });
      if (cleanup) return;
      cleanup = (async () => {
        // Never signal a recycled PID after the owned leader has exited.
        requireObservation(child.pid && child.exitCode === null);
        if (settings.killTree) await settings.killTree(child.pid);
        else
          await promisify(execFile)(
            path.join(settings.env.SystemRoot, "System32", "taskkill.exe"),
            ["/PID", String(child.pid), "/T", "/F"],
            {
              windowsHide: true,
              timeout: 5000,
              maxBuffer: 65536,
              env: settings.env,
            },
          );
      })().catch((error) => {
        cleanupCause = error;
        if (child.exitCode === null) child.kill();
        child.stdout.destroy();
        child.stderr.destroy();
      });
    };
    const abort = () => stop(settings.signal.reason);
    const deadline = setTimeout(
      () =>
        stop(
          Object.assign(new Error("Windows hosted command timed out"), {
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
          stop(new Error("Windows hosted command output exceeded its bound"));
        else chunks.push(bytes);
      });
    }
    child.once("error", (cause) => {
      failure ??= cause;
    });
    child.once("close", async (exitCode, signal) => {
      clearTimeout(deadline);
      settings.signal?.removeEventListener("abort", abort);
      await cleanup;
      const result = {
        exitCode,
        signal,
        timedOut: failure?.timedOut ?? false,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      };
      if (failure || signal !== null || !Number.isInteger(exitCode))
        reject(
          Object.assign(
            failure ?? new Error("Windows hosted command failed"),
            result,
            { cleanupCause },
          ),
        );
      else resolve(result);
    });
  });
}
const execute = diagnosticCommand(
    "windows-experiment",
    runWindowsHostedCommand,
  ),
  ROOT = fileURLToPath(new URL("../../../", import.meta.url));

export function windowsHostedCompilerArguments(source, target) {
  const args = windowsCompilerArguments(source, target, "experiment");
  args.splice(args.indexOf("/sourceDependencies"), 2);
  return args;
}
export const WINDOWS_EXPERIMENT_SOURCES = Object.freeze([
  ...WINDOWS_HELPER_NAMES.map((name) => name + ".c"),
  "custody.h",
  "effective-reader.h",
  "account.h",
  "audit-policy-remove.h",
  "experiment.h",
]);
/** Compile exact-candidate helpers once with the hosted toolchain, then seal
 * the actual outputs for the existing System publication and case owners. */
export async function bootstrapWindowsExperiment(
  job,
  directory,
  binding,
  {
    env = process.env,
    signal,
    command = execute,
    filesystem = fs,
    selectToolchain = selectInstalledWindowsToolchain,
    readCandidate: optionsReadCandidate,
    checkoutRoot = ROOT,
  } = {},
) {
  const sourceDirectory = directory + "-bootstrap",
    output = path.join(directory, "platform-build");
  requireObservation(
    location(directory) &&
      location(sourceDirectory) &&
      directory.startsWith(env.RUNNER_TEMP + "\\") &&
      location(env.RUNNER_TEMP),
  );
  const commands = [],
    versions = {};
  const run = async (
    file,
    args,
    settings = {},
    accepted = [0],
    record = true,
  ) => {
    signal?.throwIfAborted();
    const request = {
      file,
      args,
      cwd: checkoutRoot,
      env: {
        CI: "true",
        GITHUB_ACTIONS: "true",
        SystemRoot: env.SystemRoot,
        PATH: env.PATH ?? env.Path,
      },
      timeout: 60000,
      maxBuffer: 1048576,
      ...settings,
    };
    const result = await command(file, args, { ...request, signal });
    signal?.throwIfAborted();
    requireObservation(
      result.signal === null &&
        result.timedOut === false &&
        [result.stdout, result.stderr].every(
          (value) =>
            typeof value === "string" &&
            Buffer.byteLength(value) <= request.maxBuffer,
        ),
    );
    if (!accepted.includes(result.exitCode))
      throw Object.assign(new Error("Windows hosted command failed"), result);
    if (record) commands.push({ ...request, ...result });
    return result;
  };
  const read = async (file) => {
    const stat = await filesystem.lstat(file);
    requireObservation(
      stat.isFile() &&
        !stat.isSymbolicLink() &&
        stat.nlink === 1 &&
        stat.size > 0 &&
        stat.size <= 134217728 &&
        (await filesystem.realpath(file)) === file,
    );
    return filesystem.readFile(file);
  };
  requireObservation(
    (
      await run("git", ["rev-parse", "HEAD"], { cwd: checkoutRoot })
    ).stdout.trim() === job.candidateSha,
  );
  const selected = await selectToolchain(
    { environment: env, temporaryRoot: env.RUNNER_TEMP },
    {
      execute: async (file, args, settings) => {
        try {
          const result = await runWindowsHostedCommand(file, args, {
            ...settings,
            signal,
          });
          if (result.exitCode !== 0)
            throw Object.assign(
              new Error("Windows toolchain setup failed"),
              result,
            );
          return result;
        } catch (error) {
          // Setup stdout is an environment enumeration, never diagnostics.
          if (path.basename(file).toLowerCase() === "cmd.exe")
            error.stdout = undefined;
          throw error;
        }
      },
    },
  );
  requireObservation(!selected.cause && !selected.cleanupCause);
  const environment = Object.fromEntries(
    ["INCLUDE", "LIB", "SystemRoot", "PATH"].map((name) => [
      name,
      name === "SystemRoot" ? env.SystemRoot : selected.environment[name],
    ]),
  );
  requireObservation(
    Object.values(environment).every(
      (value) => typeof value === "string" && value.length > 0,
    ),
  );
  const compiler = (
      await run("where.exe", ["cl.exe"], { env: environment })
    ).stdout
      .trim()
      .split(/\r?\n/u)[0],
    sdkBuild = selected.environment.WindowsSDKVersion?.replace(/\\$/u, ""),
    sdk = path.join(
      selected.environment.WindowsSdkDir ?? "",
      "bin",
      sdkBuild ?? "",
      "x64",
      "rc.exe",
    );
  requireObservation(/^[0-9]+(?:\.[0-9]+){3}$/u.test(sdkBuild ?? ""));
  const tools = [];
  for (const [name, file] of [
    ["compiler", compiler],
    ["sdk", sdk],
  ]) {
    requireObservation(
      WINDOWS_BUILD_TOOLS.find((tool) => tool.name === name).path.test(file),
    );
    const bytes = await read(file);
    tools.push({
      name,
      path: file,
      sha256: digest(bytes),
    });
  }
  await filesystem.mkdir(sourceDirectory);
  await filesystem.mkdir(directory);
  const sources = [],
    readCandidate =
      optionsReadCandidate ??
      nativeCandidateReader(job.candidateSha, checkoutRoot, { env });
  for (const name of WINDOWS_EXPERIMENT_SOURCES) {
    const source = path.join(checkoutRoot, "ci", "native", "win32", name),
      bytes = await read(source),
      candidate = await readCandidate("ci/native/win32/" + name, 1048576);
    requireObservation(Buffer.isBuffer(candidate) && bytes.equals(candidate));
    await filesystem.writeFile(path.join(sourceDirectory, name), bytes, {
      flag: "wx",
    });
    sources.push({ name, sha256: digest(bytes) });
  }
  const helpers = [];
  const compilerEnvironment = {
    CI: "true",
    GITHUB_ACTIONS: "true",
    LANG: "C",
    ...environment,
    TEMP: env.RUNNER_TEMP,
    TMP: env.RUNNER_TEMP,
  };
  for (const tool of tools) {
    const recipe = WINDOWS_BUILD_TOOLS.find(
      (entry) => entry.name === tool.name,
    );
    const result = await run(
      tool.path,
      recipe.args,
      { env: compilerEnvironment },
      [0, ...recipe.versionExitCodes],
    );
    const text = result.stdout + "\n" + result.stderr;
    versions[tool.name] =
      tool.name === "compiler"
        ? /Compiler Version ([0-9.]+) for x64/u.exec(text)?.[1]
        : /Version ([0-9.]+)/u.exec(text)?.[1];
    requireObservation(versions[tool.name]);
  }
  for (const name of WINDOWS_HELPER_NAMES) {
    const target = path.join(sourceDirectory, name + ".exe");
    await run(
      compiler,
      windowsHostedCompilerArguments(
        path.join(sourceDirectory, name + ".c"),
        target,
      ),
      { cwd: sourceDirectory, env: compilerEnvironment },
    );
    const bytes = await read(target),
      image = inspectWindowsExperimentPe(bytes);
    helpers.push({
      name,
      path: target,
      sha256: image.sha256,
      signatureSha256: image.sha256,
      sourceSha256: sources.find((source) => source.name === name + ".c")
        .sha256,
    });
    await filesystem.unlink(target + ".obj");
  }
  const who = await run(path.join(env.SystemRoot, "System32", "whoami.exe"), [
      "/user",
      "/fo",
      "csv",
      "/nh",
    ]),
    runnerSid = /"(S-1-5-21-(?:[0-9]+-){3}[0-9]+)"\s*$/u.exec(
      who.stdout.trim(),
    )?.[1];
  requireObservation(runnerSid);
  const context = {
      candidateSha: job.candidateSha,
      platform: "win32",
      tier: "system",
      runId: job.runId,
      runAttempt: job.runAttempt,
      jobBindingSha256: observationDigest(binding),
      executionId: "build",
      closureSha256: observationDigest({ sources, tools }),
      selectedSystemSha256: null,
    },
    nonce = randomBytes(16).toString("hex"),
    entries = [
      ...helpers.map((image) => ({
        kind: "helper",
        path: image.path,
        sha256: image.sha256,
        signatureSha256: image.sha256,
      })),
      { kind: "directory", path: output, sha256: null, signatureSha256: null },
      ...sources.map((source) => ({
        kind: "data",
        path: path.join(sourceDirectory, source.name),
        sha256: source.sha256,
        signatureSha256: null,
      })),
    ],
    bytes = encodeWindowsCustodyPlan({
      purpose: "experiment",
      candidateSha: job.candidateSha,
      nonce,
      entries,
    }),
    plan = {
      path: path.join(sourceDirectory, "experiment-plan"),
      sha256: digest(bytes),
    },
    image = (name) => {
      const helper = helpers.find((helper) => helper.name === name);
      return {
        path: helper.path,
        sha256: helper.sha256,
        signatureSha256: helper.sha256,
      };
    },
    bootstrap = {
      purpose: "experiment",
      context,
      nonce,
      runnerSid,
      reader: image("custody-reader"),
      bridge: image("custody-bridge"),
      plan,
      sources: [
        "custody-reader.c",
        "custody-bridge.c",
        "custody.h",
        "effective-reader.h",
        "account.h",
        "audit-policy-remove.h",
        "experiment.h",
      ].map((name) => ({
        path: path.join(sourceDirectory, name),
        sha256: sources.find((source) => source.name === name).sha256,
      })),
      bindingSha256: observationDigest({ binding, sources, tools }),
      sdkSha256: observationDigest({ sdkBuild, tools }),
      buildSha256: observationDigest({ helpers, sources, tools, environment }),
    };
  await filesystem.writeFile(plan.path, bytes, { flag: "wx" });
  const sdkHeader = {
    file: path.join(
      selected.environment.WindowsSdkDir,
      "Include",
      sdkBuild,
      "um",
      "Windows.h",
    ),
  };
  sdkHeader.sha256 = digest(await read(sdkHeader.file));
  for (const source of sources)
    requireObservation(
      digest(await read(path.join(sourceDirectory, source.name))) ===
        source.sha256,
    );
  for (const tool of tools)
    requireObservation(digest(await read(tool.path)) === tool.sha256);
  const prepared = {
    purpose: "experiment",
    schemaVersion: 2,
    job,
    binding,
    directory,
    output,
    sourceDirectory,
    bootstrap,
    sources,
    tools,
    helpers,
    entries,
    environment,
    sdkBuild,
    sdkHeader,
    commands,
    versions,
  };
  // This private selector identifies possible System publication; only the
  // protected native records can later attest custody or retirement.
  await filesystem.writeFile(
    directory + "-selector.json",
    JSON.stringify(prepared) + "\n",
    { flag: "wx" },
  );
  const sealed = JSON.parse(
    (
      await run(
        bootstrap.bridge.path,
        [
          "--experiment-seal",
          plan.path,
          plan.sha256,
          runnerSid,
          job.candidateSha,
        ],
        {
          env: {
            CI: "true",
            GITHUB_ACTIONS: "true",
            SystemRoot: env.SystemRoot,
          },
        },
        [0],
        false,
      )
    ).stdout,
  );
  requireObservation(
    sealed.purpose === "experiment" &&
      sealed.sealed === true &&
      sealed.planSha256 === plan.sha256,
  );
  return prepared;
}

/** One System file observer owns publication reads. Case readers keep their
 * own creation-time Jobs and independent original-owner retirement. */
export async function openWindowsExperimentNative(prepared, options = {}) {
  const { job, directory, output, bootstrap } = prepared;
  const input = {
    job,
    directory,
    output,
    signal: options.signal,
    manifest: {
      purpose: "experiment",
      candidateSha: job.candidateSha,
      platform: "win32",
      helpers: prepared.helpers,
      tools: prepared.tools,
      environment: prepared.environment,
      windowsPreparation: {
        purpose: "experiment",
        schemaVersion: 2,
        bootstrap,
        sourceDirectory: prepared.sourceDirectory,
        sources: prepared.sources,
      },
    },
  };
  const files = options.files ?? createWindowsPreparationFiles(input, options);
  const write = (name, record) =>
    files.writeProtected({
      file: path.join(directory, name),
      bytes: Buffer.from(JSON.stringify(record) + "\n"),
      exclusive: true,
    });
  let closing,
    finished = false,
    complete = false;
  const native = {
    prepared,
    files,
    write,
    writeBytes: (name, bytes) =>
      files.writeProtected({
        file: path.join(directory, name),
        bytes,
        exclusive: true,
      }),
    read: (file, sha256) => files.readProtected({ file, sha256 }),
    readInput: (file) => files.readExperimentInput(file),
    readImage: (file, installed = false) =>
      files.readExperimentImage(file, installed),
    resolveImport: (name, image) => files.resolveExperimentImport(name, image),
    prepareVolume: () => files.prepareExperimentVolume(),
    close({ signal: supplied, recovery = false } = {}) {
      if (closing && (!recovery || !finished || complete)) return closing;
      files.fenceAdmission();
      const signal = supplied
        ? AbortSignal.any([supplied, AbortSignal.timeout(30000)])
        : AbortSignal.timeout(30000);
      finished = false;
      closing = (async () => {
        let primary, settlement, observer;
        const failures = [];
        try {
          await files.beginCleanup(signal);
          const verification = files.verification;
          observer = {
            nonce: verification.input.nonce,
            helper: verification.identity,
            bridge: verification.bridge,
            taskSha256: verification.taskSha256,
          };
          if (!recovery)
            await write("windows-experiment-close.json", {
              purpose: "experiment",
              schemaVersion: 2,
              observer,
            });
        } catch (error) {
          if (!recovery) primary = error;
        }
        try {
          settlement = await files.settleFiles();
        } catch (error) {
          if (!recovery) primary ??= error;
        }
        if (!windowsRetired(settlement)) {
          try {
            settlement = await recoverWindowsPreparationOwners(input, options, {
              signal,
              onReadersRetired: async (proof) => {
                if (proof) files.releaseRecoveredReaders(proof);
                try {
                  await files.settleFiles();
                } catch (error) {
                  nativeException(
                    "windows-experiment-original-observer",
                    error,
                  );
                }
                await files.waitForExit(signal);
              },
            });
          } catch (error) {
            if (!primary) primary = error;
            else failures.push(error);
          }
        }
        if (primary)
          throw Object.assign(
            new AggregateError(
              [primary, ...failures],
              "Windows experiment cleanup failed",
              { cause: primary },
            ),
            { settlement },
          );
        requireObservation(windowsRetired(settlement));
        complete = true;
        return { ...settlement, observer };
      })().finally(() => {
        finished = true;
      });
      return closing;
    },
    recover(settings = {}) {
      return native.close({ ...settings, recovery: true });
    },
  };
  // Retain the owner before its first System startup can lose an acknowledgement.
  options.retain?.(native);
  try {
    await files.verifyDirectory({ directory, context: bootstrap.context });
    await write("windows-experiment-selector.json", {
      purpose: "experiment",
      schemaVersion: 2,
      prepared,
    });
    if (!options.reopen) await files.provisionBuild({ output });
  } catch (error) {
    throw Object.assign(error, { experimentNative: native });
  }
  return native;
}
