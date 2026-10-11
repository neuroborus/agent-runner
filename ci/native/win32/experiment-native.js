import { execFile } from "node:child_process";
import * as fs from "node:fs/promises";
import { win32 as path } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import { selectInstalledWindowsToolchain } from "../feasibility/windows-toolchain.js";
import { observationDigest, requireObservation } from "../index.js";
import { digest, inspectWindowsPe } from "./protocol.js";
import {
  WINDOWS_HELPER_NAMES,
  WINDOWS_BUILD_TOOLS,
  WINDOWS_BUILD_LIBRARIES,
  windowsCompilerArguments,
  runWindowsBuildCommand,
} from "./build.js";
import { encodeWindowsCustodyPlan, location } from "./custody-protocol.js";
import { createWindowsPreparationFiles } from "./preparation-files.js";
import { createWindowsCustodyReader } from "./custody.js";
import { inspectWindowsExperimentPe } from "./experiment-image.js";

const execute = promisify(execFile),
  ROOT = fileURLToPath(new URL("../../../", import.meta.url));
export const WINDOWS_EXPERIMENT_SOURCES = Object.freeze([
  ...WINDOWS_HELPER_NAMES.map((name) => name + ".c"),
  "custody.h",
  "effective-reader.h",
  "account.h",
  "audit-policy-remove.h",
  "experiment.h",
]);
const verifierMethods = [
  "verifyBootstrap",
  "verifyAdmission",
  "verifyTransfer",
  "verifyHelperRetirement",
  "verifyRetirement",
  "verifyTaskRemoval",
  "verifyPublication",
];

/** The initial local compilation creates bootstrap data only. A separate
 * System custodian subsequently holds/rechecks it and owns all reported builds. */
export async function bootstrapWindowsExperiment(
  job,
  directory,
  binding,
  persist,
  { env = process.env, signal, command = execute, filesystem = fs } = {},
) {
  const sourceDirectory = directory + "-bootstrap",
    output = path.join(directory, "platform-build");
  requireObservation(
    location(directory) &&
      location(sourceDirectory) &&
      directory.startsWith(env.RUNNER_TEMP + "\\") &&
      location(env.RUNNER_TEMP),
  );
  const run = (file, args, settings = {}) =>
    command(file, args, {
      env,
      signal,
      windowsHide: true,
      encoding: "utf8",
      timeout: 60000,
      maxBuffer: 1048576,
      ...settings,
    });
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
    (await run("git", ["rev-parse", "HEAD"], { cwd: ROOT })).stdout.trim() ===
      job.candidateSha,
  );
  const selected = await selectInstalledWindowsToolchain(
    { environment: env, temporaryRoot: env.RUNNER_TEMP },
    {
      capture: async (event) =>
        persist({ purpose: "experiment", phase: "toolchain", ...event }),
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
    const bytes = await read(file),
      image = inspectWindowsPe(bytes);
    tools.push({
      name,
      path: file,
      sha256: digest(bytes),
      signatureSha256: image.signatureSha256,
    });
  }
  await persist({
    purpose: "experiment",
    phase: "bootstrap-possible",
    candidateSha: job.candidateSha,
    directory,
    sourceDirectory,
    output,
    bindingSha256: observationDigest(binding),
  });
  await filesystem.mkdir(sourceDirectory);
  await filesystem.mkdir(directory);
  const sources = [];
  for (const name of WINDOWS_EXPERIMENT_SOURCES) {
    const source = fileURLToPath(new URL(name, import.meta.url)),
      bytes = await read(source),
      candidate = await run(
        "git",
        ["show", `${job.candidateSha}:ci/native/win32/${name}`],
        { cwd: ROOT, encoding: "buffer" },
      );
    requireObservation(
      Buffer.isBuffer(candidate.stdout) && bytes.equals(candidate.stdout),
    );
    await filesystem.writeFile(path.join(sourceDirectory, name), bytes, {
      flag: "wx",
    });
    sources.push({ name, sha256: digest(bytes) });
  }
  const helpers = [];
  for (const name of WINDOWS_HELPER_NAMES) {
    const source = path.join(sourceDirectory, name + ".c"),
      target = path.join(sourceDirectory, name + ".exe"),
      args = windowsCompilerArguments(source, target, "experiment");
    await persist({
      purpose: "experiment",
      phase: "bootstrap-compile-possible",
      name,
      requestSha256: observationDigest({ file: compiler, args, environment }),
    });
    await run(compiler, args, {
      cwd: sourceDirectory,
      env: {
        CI: "true",
        GITHUB_ACTIONS: "true",
        ...environment,
        TEMP: env.RUNNER_TEMP,
        TMP: env.RUNNER_TEMP,
      },
    });
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
    await filesystem.unlink(target + ".deps.json");
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
      executionId: "build",
      jobBindingSha256: observationDigest(binding),
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
      ...tools.map((tool) => ({
        kind: "image",
        path: tool.path,
        sha256: tool.sha256,
        signatureSha256: tool.signatureSha256,
      })),
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
  await persist({
    purpose: "experiment",
    phase: "bootstrap-seal-possible",
    bootstrap,
    sources,
    helpers,
    tools,
    environment,
    sdkBuild,
    directory,
    output,
  });
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
        { env: { CI: "true", GITHUB_ACTIONS: "true" } },
      )
    ).stdout,
  );
  requireObservation(
    sealed.purpose === "experiment" &&
      sealed.sealed === true &&
      sealed.planSha256 === plan.sha256,
  );
  return {
    purpose: "experiment",
    job,
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
  };
}

/** Reuse the live System observer, held-file readers and compiler controller.
 * Local expectations have no source, release, template or custody approvals. */
export async function openWindowsExperimentNative(
  prepared,
  { signal, reopen = false, retain, files: suppliedFiles } = {},
) {
  const { bootstrap, job, directory, output, helpers, entries } = prepared,
    files =
      suppliedFiles ??
      createWindowsPreparationFiles({
        job,
        directory,
        output,
        manifest: { helpers, windowsPreparation: { bootstrap } },
      }),
    write = async (name, record) =>
      files.writeProtected({
        file: path.join(directory, name),
        bytes: Buffer.from(JSON.stringify(record) + "\n"),
        exclusive: true,
      });
  retain?.({ files, close: () => files.settleFiles() });
  await files.verifyDirectory({ directory, context: bootstrap.context });
  const names = await files.readdir(directory),
    sequence = names.filter((name) =>
      /^windows-bootstrap-[0-9]+-intent\.json$/u.test(name),
    ).length;
  requireObservation(sequence <= 65535);
  await write(`windows-bootstrap-${sequence}-intent.json`, {
    purpose: "experiment",
    prepared,
    candidateSha: job.candidateSha,
    context: bootstrap.context,
    preparationSha256: observationDigest(bootstrap),
    status: "POSSIBLE",
  });
  const reader = createWindowsCustodyReader(bootstrap, {
    ...Object.fromEntries(
      verifierMethods.map((name) => [
        name,
        (...args) => files.verify(name, ...args),
      ]),
    ),
    read: async (file) =>
      (
        await files.readProtected({
          file,
          sha256: [
            bootstrap.reader,
            bootstrap.bridge,
            bootstrap.plan,
            ...bootstrap.sources,
          ].find((pin) => pin.path === file)?.sha256,
        })
      ).bytes,
    persist: (() => {
      let index = 0;
      return (record) =>
        write(`windows-bootstrap-${sequence}-custody-${index++}.json`, record);
    })(),
  });
  files.retainReader(reader, signal);
  let closing;
  const native = {
    prepared,
    files,
    reader,
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
    resolveImport: (name) => files.resolveExperimentImport(name),
    prepareVolume: () => files.prepareExperimentVolume(),
    close() {
      return (closing ??= (async () => {
        const settlement = await reader.close();
        requireObservation(
          settlement.status === "RETIRED" &&
            settlement.independent &&
            !settlement.emergencyCleanup &&
            settlement.taskRemoved,
        );
        files.releaseReader(reader);
        const observer = {
          nonce: files.verification.input.nonce,
          helper: files.verification.identity,
          bridge: files.verification.bridge,
          taskSha256: files.verification.taskSha256,
        };
        await write("windows-experiment-close.json", {
          purpose: "experiment",
          bootstrapSettlement: settlement,
          observer,
        });
        const custody = await files.settleFiles();
        requireObservation(
          custody.status === "RETIRED" &&
            custody.independent &&
            !custody.emergencyCleanup,
        );
        return {
          status: "RETIRED",
          independent: true,
          emergencyCleanup: false,
          bootstrapSettlement: settlement,
          observer,
          observerSettlement: custody,
          nativeEventSha256: observationDigest({ settlement, custody }),
        };
      })());
    },
  };
  // The owner is retained before startup can release a process or lose its
  // acknowledgement. An opening exception cannot erase this cleanup obligation.
  retain?.(native);
  try {
    await reader.start({ signal });
  } catch (error) {
    throw Object.assign(error, { experimentNative: native });
  }
  const helper = entries.findIndex(
    (entry) =>
      entry.path ===
      helpers.find((helper) => helper.name === "build-helper").path,
  );
  await reader.open(helper);
  for (let i = 0; i < entries.length; i++)
    if (["data", "image"].includes(entries[i].kind)) await reader.open(i);
  if (!reopen) await files.provisionBuild({ output });
  return {
    ...native,
    async findLibrary(name, roots) {
      requireObservation(WINDOWS_BUILD_LIBRARIES.includes(name));
      for (const root of roots) {
        const file = path.join(root, name);
        requireObservation(location(file));
        try {
          await fs.lstat(file);
          return file;
        } catch (error) {
          if (error?.code !== "ENOENT") throw error;
        }
      }
      return null;
    },
    async run(request, operation) {
      const tool = entries.findIndex((entry) => entry.path === request.file),
        pin = prepared.tools.find((entry) => entry.path === request.file);
      let index = 0;
      await write(`windows-command-${observationDigest(request)}-intent.json`, {
        purpose: "experiment",
        request,
        requestSha256: observationDigest(request),
        candidateSha: job.candidateSha,
        status: "POSSIBLE",
      });
      const result = await runWindowsBuildCommand(
        request,
        operation,
        { helper, tool, toolSignatureSha256: pin.signatureSha256 },
        reader,
        async (record) => {
          const proof =
            record.phase === "worker-admitted"
              ? (
                  await files.verify(
                    "verifyBuildWorker",
                    record,
                    operation.tool,
                    pin.signatureSha256,
                  )
                ).compilerPolicy
              : null;
          await write(
            `windows-command-${observationDigest(request)}-${index++}.json`,
            {
              purpose: "experiment",
              ...record,
              ...(proof ? { compilerPolicy: proof } : {}),
            },
          );
          return proof;
        },
        { signal },
      );
      await write(`windows-command-${observationDigest(request)}-result.json`, {
        purpose: "experiment",
        result,
      });
      return result;
    },
  };
}
