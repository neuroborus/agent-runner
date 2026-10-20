import assert from "node:assert/strict";
import test from "node:test";
import path from "node:path";
import { constants } from "node:fs";
import { readFile } from "node:fs/promises";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { deflateSync } from "node:zlib";
import { createHash } from "node:crypto";
import { kernelPfFixture, stockPfFixture } from "./pf.fixture.js";
import { darwinPfExpectedRules, darwinPfAuthorityDigest } from "./pf-kernel.js";
import { createProviderEffects as fixedProviderEffects } from "../provider-effects.mjs";
import { providerPreparationFixture } from "../providers/preparation.fixture.js";
import {
  createNativeDiagnosticWriter,
  withNativeDiagnostics,
} from "../diagnostics.js";
import { createBuildEffects, createSystemEffects } from "../native-effects.mjs";
import {
  observationDigest,
  initialExperimentJob,
  recordExperimentPreparationEffect,
  nativePolicyLaunchData,
  nativePolicyTemplateDigest,
  materializeNativePolicy,
  verifyExperimentPolicy,
  normalizeExperimentPolicyBinding,
  NATIVE_EFFECT_CLASSES,
  NATIVE_GROUPS,
  releaseClosureDigest,
} from "../index.js";
import {
  prepareDarwinExperiment,
  loadDarwinExperiment,
  recoverDarwinExperimentPreparation,
  createDarwinExperimentSystemEffects,
  createDarwinBuildEffects,
  createDarwinSystemEffects,
  normalizeDarwinPreparation,
  DARWIN_HELPER_NAMES,
  DARWIN_LITERAL_ARGUMENTS,
  darwinCompilerArguments,
  darwinBuildOperation,
  runDarwinBuildCommand,
  darwinSystemRecipes,
  DARWIN_SYSTEM_PREPARATION_MS,
  observeDarwinRelease,
  buildDarwinPolicy,
  encodeDarwinCustodyPlan,
} from "./index.js";
import { digest, darwinLaunchDigest, sameDarwinIdentity } from "./protocol.js";
import { DARWIN_OWNERSHIP_CASES, runDarwinOwnershipCase } from "./ownership.js";
import { runDarwinFileCase, DARWIN_FILE_CASE_IDS } from "./files-cases.js";
import { runDarwinGitCase } from "./git.js";
import { DARWIN_ACCESS_DENIALS, runDarwinAccessCase } from "./access.js";
import {
  darwinExperimentCaseDeclarations,
  createDarwinCaseProvisioning,
} from "./case-provisioning.js";
import { darwinGitPolicies } from "./git-effects.js";
import { createDarwinExperimentRuntimeEffects } from "./experiment-runtime.js";
import { acquireDarwinExperimentInputs } from "./experiment-inputs.js";
import { bindDarwinMachAccess, darwinMachLogArguments } from "./mach-access.js";
import { darwinAccessPreparation } from "./access-effects.js";
import { prepareDarwinExperimentCases } from "./experiment-cases.js";
import { darwinExperimentBuildBinding } from "./experiment-preparation.js";
import { darwinPreparationContext } from "./preparation.js";
import { darwinPfRootDigest } from "./pf-preparation.js";
import { assertDarwinLiteralObservation } from "./literal.js";
import { DARWIN_BUILD_CUSTODY_MS } from "./build.js";
import { darwinCustodyChannel } from "./channel.js";
import { fixture as darwinCustodyFixture } from "./custody.test.js";
import {
  prepareDarwinExperimentBuild,
  loadDarwinExperimentBuild,
  recoverDarwinExperimentBuild,
  darwinExperimentBuildInput,
} from "./experiment-build.js";
import {
  acquireDarwinExperimentBuild,
  DARWIN_EXPERIMENT_SOURCES,
  DARWIN_PF_ABI_REFERENCE,
  DARWIN_HOSTED_OUTPUT_BYTES,
  darwinHostedCompilerArguments,
  runDarwinHostedCommand,
} from "./experiment-build-inputs.js";

const candidateSha = "a".repeat(40),
  bytes = Buffer.from("sealed reviewed bytes"),
  hash = digest(bytes),
  cdhash = "c".repeat(40),
  output = "/fixture/report/platform-build",
  directory = path.dirname(output),
  sourceDirectory = "/fixture/sealed/darwin";
const longDiagnostic = "compiler warning\n".repeat(5000);
const retired = {
  status: "RETIRED",
  independent: true,
  emergencyCleanup: false,
  nativeEventSha256: hash,
};
const sdkSelection = {
  path: "/Library/Developer/CommandLineTools/SDKs/Fixture.sdk",
  dev: "1",
  ino: "99",
  settingsSha256: hash,
};
const toolchainSelection = {
  developer: {
    path: "/Library/Developer/CommandLineTools",
    dev: "1",
    ino: "99",
  },
  compiler: {
    path: "/Library/Developer/CommandLineTools/usr/bin/clang",
    sha256: hash,
    dev: "1",
    ino: "99",
    cdhash,
  },
  delegated: [
    {
      path: "/Library/Developer/CommandLineTools/usr/bin/ld",
      sha256: hash,
      dev: "1",
      ino: "99",
      cdhash,
    },
  ],
};
const identity = (pid) => ({
  pid,
  pidVersion: 1,
  uid: 0,
  gid: 0,
  ruid: 0,
  rgid: 0,
  svuid: 0,
  svgid: 0,
  auid: 0,
  asid: 0,
  startSeconds: 100,
  startMicroseconds: pid,
});
const context = (executionId) => ({
  candidateSha,
  platform: "darwin",
  tier: "system",
  runId: "1",
  runAttempt: 1,
  jobBindingSha256: hash,
  executionId,
  closureSha256: hash,
  selectedSystemSha256: null,
});
const custody = (id) => ({
  context: context(id),
  reader: { path: "/fixture/sealed/custody-reader", sha256: hash, cdhash },
  sources: [
    "custody-reader.c",
    "custody.h",
    "file-identity.h",
    "effective-reader.h",
    "feasibility-sandbox.h",
  ].map((name) => ({ path: `/fixture/sealed/${name}`, sha256: hash })),
  plan: { path: `/fixture/sealed/${id}-plan`, sha256: hash },
  tools: {
    elevation: { path: "/usr/bin/sudo", sha256: hash },
    environment: { path: "/usr/bin/env", sha256: hash },
  },
  reportDirectory: directory,
  reviewSha256: hash,
  sdkSha256: hash,
  buildSha256: hash,
});

function wiring({ defaultRead = false } = {}) {
  let nextReaderPid = 20;
  const events = [],
    files = new Map(),
    env = {
      CI: "true",
      GITHUB_ACTIONS: "true",
      ImageOS: "macos15",
      RUNNER_TEMP: "/fixture",
    };
  const manifest = {
    schemaVersion: 1,
    candidateSha,
    platform: "darwin",
    environment: {
      SDKROOT: "/Library/Developer/CommandLineTools/SDKs/Fixture.sdk",
    },
    tools: [
      ["compiler", "/usr/bin/clang"],
      ["sdk", "/usr/bin/xcrun"],
      ["signer", "/usr/bin/codesign"],
    ].map(([name, file]) => ({
      name,
      path: file,
      sha256: hash,
      version: "reviewed",
    })),
    helpers: DARWIN_HELPER_NAMES.map((name) => ({
      name,
      sourceSha256: hash,
      sha256: hash,
    })),
    inputs: [],
    darwinPreparation: {
      schemaVersion: 1,
      sourceDirectory,
      sources: [
        ...DARWIN_HELPER_NAMES.map((name) => name + ".c"),
        "custody.h",
        "file-identity.h",
        "effective-reader.h",
        "feasibility-sandbox.h",
      ].map((name) => ({ name, sha256: hash })),
      bootstrap: custody("build"),
      command: {
        helper: { path: "/fixture/sealed/build-helper", sha256: hash, cdhash },
        toolCdhashes: { compiler: cdhash, sdk: cdhash, signer: cdhash },
      },
      cases: darwinSystemRecipes()
        .filter((recipe) => recipe.id !== "build")
        .map((recipe) => ({
          id: recipe.id,
          custody: custody(recipe.id),
          bindings: {},
        })),
    },
  };
  const job = { candidateSha, platform: "darwin" };
  const request = (tool, args) => ({
    candidateSha,
    platform: "darwin",
    toolSha256: tool.sha256,
    file: tool.path,
    args,
    cwd: output,
    env: {
      CI: "true",
      GITHUB_ACTIONS: "true",
      LANG: "C",
      SDKROOT: manifest.environment.SDKROOT,
    },
    deadlineMs: 30000,
  });
  const requests = [
    request(manifest.tools[0], ["--version"]),
    request(manifest.tools[1], ["--show-sdk-build-version"]),
  ];
  for (const name of DARWIN_HELPER_NAMES) {
    requests.push(
      request(
        manifest.tools[0],
        darwinCompilerArguments(
          path.join(sourceDirectory, name + ".c"),
          path.join(output, name),
          manifest.environment,
        ),
      ),
    );
    requests.push(
      request(manifest.tools[2], [
        "--force",
        "--sign",
        "-",
        "--timestamp=none",
        path.join(output, name),
      ]),
    );
  }
  const preparation = {
    schemaVersion: 1,
    status: "PASS",
    candidateSha,
    platform: "darwin",
    reviewSha256: observationDigest(manifest),
    helpers: manifest.helpers.map(({ name, sha256 }) => ({ name, sha256 })),
    versions: manifest.tools.map(({ name, version, sha256 }) => ({
      name,
      version,
      sha256,
    })),
    commands: [],
  };
  for (const value of requests) {
    const id = observationDigest(value),
      result = {
        requestSha256: id,
        toolSha256: hash,
        exitCode: 0,
        signal: null,
        timedOut: false,
        independent: true,
        identity: identity(11),
        helperIdentity: identity(12),
        nativeEventSha256: hash,
        settlement: retired,
        bootstrapSettlement: {
          status: "RETIRED",
          independent: true,
          closed: true,
        },
        stdout: "reviewed\n",
        stderr: "",
      };
    files.set(path.join(directory, `darwin-command-${id}-intent.json`), {
      candidateSha,
      request: value,
      requestSha256: id,
      status: "POSSIBLE",
    });
    files.set(path.join(directory, `darwin-command-${id}-result.json`), result);
    preparation.commands.push({
      requestSha256: id,
      status: "RETIRED",
      receiptSha256: observationDigest(result),
    });
  }
  const options = {
    env,
    ownerUid: () => 1001,
    fs: {
      realpath: async (file) => file,
      lstat: async () => ({
        isDirectory: () => true,
        isSymbolicLink: () => false,
        uid: 1001,
        mode: 0o700,
      }),
      readdir: async () => [...files.keys()].map((file) => path.basename(file)),
      async writeFile(file, value, settings) {
        assert.equal(settings.flag, "wx");
        assert.equal(settings.mode, 0o400);
        assert.ok(!files.has(file));
        files.set(file, JSON.parse(value));
        events.push(path.basename(file));
      },
    },
    ...(!defaultRead
      ? {
          read: async () => {
            events.push("sealed-read");
            return bytes;
          },
        }
      : {}),
    inspectImage: (value) => assert.ok(Buffer.isBuffer(value)),
    readReceipt: async (file) => {
      assert.ok(files.has(file));
      return Buffer.from(JSON.stringify(files.get(file)));
    },
    createReader: (value, readerOptions) => {
      const building = value.context.executionId === "build",
        pid = nextReaderPid++,
        helper = building
          ? { ...identity(pid), asid: 100 + pid }
          : identity(20),
        verifier = identity(nextReaderPid++);
      return {
        async start() {
          events.push(`start:${value.context.executionId}`);
          assert.notEqual(helper.pid, verifier.pid);
          const request = { helper, verifier };
          for (const [sequence, phase] of (building
            ? ["entry", "admitted"]
            : ["entry"]
          ).entries())
            await readerOptions.persist({
              ...(value.purpose === "experiment"
                ? { purpose: "experiment" }
                : {}),
              schemaVersion: 1,
              context: value.context,
              sequence,
              phase,
              request,
              requestSha256: digest(JSON.stringify(request)),
              [value.purpose === "experiment"
                ? "bindingSha256"
                : "reviewSha256"]: value.bindingSha256 ?? value.reviewSha256,
              custody: "POSSIBLE",
              ...(phase === "admitted" ? { subjects: request } : {}),
            });
          return { helper, independent: true, planSha256: hash };
        },
        async beginCleanup({ signal }) {
          assert.ok(signal instanceof AbortSignal && !signal.aborted);
          events.push("cleanup");
        },
        async retired(value) {
          assert.ok(value.pid);
          if (building) assert.notEqual(value.pid, helper.pid);
          events.push("fresh-retirement");
          return retired;
        },
        ...(building
          ? {
              async retiredRootDomain(value) {
                assert.ok(value.asid > 0);
                assert.notEqual(value.asid, helper.asid);
                events.push("fresh-root-retirement");
                return { independent: true, complete: true, members: [] };
              },
            }
          : {}),
        async close() {
          events.push(`close:${value.context.executionId}`);
          return {
            status: "RETIRED",
            independent: true,
            emergencyCleanup: false,
            closed: true,
            nativeEventSha256: hash,
          };
        },
      };
    },
    createReaders: () => ({
      gitSnapshot: async () => {
        events.push("git-snapshot");
        return {};
      },
    }),
    provisionBuild: async () => {
      events.push("provision-build");
    },
  };
  const input = {
    job,
    manifest,
    output,
    directory,
    preparation,
    api: { mustNotClone() {} },
  };
  return { input, options, manifest, preparation, requests, events, files };
}

function experimentBuildFixture(failure = null) {
  const f = wiring(),
    image = Buffer.alloc(384),
    imageHash = () => digest(image);
  f.files.clear();
  for (const [offset, value] of [
    [0, 0xfeedfacf],
    [4, 0x01000007],
    [12, 2],
    [16, 4],
    [20, 256],
    [32, 0xe],
    [36, 32],
    [40, 12],
    [64, 0x1d],
    [68, 16],
    [72, 368],
    [76, 16],
    [80, 0x19],
    [84, 152],
    [136, 5],
    [140, 5],
    [144, 1],
    [200, 304],
    [232, 0xc],
    [236, 56],
    [240, 24],
  ])
    image.writeUInt32LE(value, offset);
  image.write("/usr/lib/dyld\0", 44);
  image.write("__TEXT", 88);
  image.writeBigUInt64LE(384n, 112);
  image.writeBigUInt64LE(384n, 128);
  image.write("__nexp", 152);
  image.write("__TEXT", 168);
  image.writeBigUInt64LE(304n, 184);
  image.writeBigUInt64LE(
    BigInt(Buffer.byteLength("native-ci-experiment-v1\0")),
    192,
  );
  image.write("/usr/lib/libSystem.B.dylib\0", 256);
  image.write("native-ci-experiment-v1\0", 304);
  const job = initialExperimentJob({
    candidateSha,
    platform: "darwin",
    repository: "fixture/native",
    runId: "1",
    runAttempt: 1,
  });
  const binding = {
    ...jobContextForTest(job),
    checkoutSha: candidateSha,
    image: "macos-15-intel",
    osBuild: "20260101.1",
    architecture: "x64",
    nodeVersion: "v24.21.0",
    workflow: "native-poc",
    jobId: "2",
  };
  const sources = DARWIN_EXPERIMENT_SOURCES.map((name) => ({
    name,
    sha256: hash,
  }));
  const bootstrap = {
    ...custody("build"),
    purpose: "experiment",
    bindingSha256: hash,
    sources: sources.map((source) => ({
      path: "/fixture/sealed/" + source.name,
      sha256: hash,
    })),
  };
  delete bootstrap.reviewSha256;
  bootstrap.context.jobBindingSha256 = observationDigest(binding);
  const environment = {
    ...f.manifest.environment,
    DEVELOPER_DIR: toolchainSelection.developer.path,
  };
  const compiler = toolchainSelection.compiler.path;
  const command = (file, args, stdout = "") => ({
    file,
    args,
    cwd: directory,
    env: {
      CI: "true",
      GITHUB_ACTIONS: "true",
      LANG: "C",
      PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
      ...(file === compiler ||
      (file === "/usr/bin/xcrun" && args[0] === "--sdk")
        ? environment
        : {}),
    },
    timeout: 60000,
    maxBuffer: DARWIN_HOSTED_OUTPUT_BYTES,
    exitCode: 0,
    signal: null,
    timedOut: false,
    stdout,
    stderr: "",
  });
  const commands = [
    command(compiler, ["--version"], "Apple clang version 17.0\n"),
    command(
      "/usr/bin/xcrun",
      ["--sdk", environment.SDKROOT, "--show-sdk-build-version"],
      "24A\n",
    ),
  ];
  for (const name of DARWIN_HELPER_NAMES) {
    const target = path.join(directory, "hosted-build", name);
    commands.push(
      command(
        compiler,
        darwinHostedCompilerArguments(target + ".c", target, environment),
      ),
    );
    commands.push(
      command("/usr/bin/codesign", [
        "--force",
        "--sign",
        "-",
        "--timestamp=none",
        target,
      ]),
    );
    commands.push(
      command("/usr/bin/codesign", ["--verify", "--strict", target]),
    );
    commands.push({
      ...command("/usr/bin/codesign", ["-d", "--verbose=4", target]),
      stderr: `CDHash=${cdhash}\n`,
    });
  }
  const prepared = {
    purpose: "experiment",
    schemaVersion: 3,
    job,
    binding,
    directory,
    output,
    sourceDirectory: "/fixture/sealed",
    sources,
    tools: [
      { name: "compiler", path: compiler, sha256: hash },
      { name: "sdk", path: "/usr/bin/xcrun", sha256: hash },
      { name: "signer", path: "/usr/bin/codesign", sha256: hash },
    ],
    environment,
    helpers: DARWIN_HELPER_NAMES.map((name) => ({
      name,
      sourceSha256: hash,
      sha256: imageHash(),
      cdhash,
    })),
    bootstrap,
    command: { helper: f.manifest.darwinPreparation.command.helper },
    sdk: { path: environment.SDKROOT, build: "24A", settingsSha256: hash },
    compilerVersion: "Apple clang version 17.0",
    commands,
  };
  const options = {
    ...f.options,
    binding,
    platform: "darwin",
    architecture: "x64",
    nodeVersion: "v24.21.0",
    readCandidate: async () => bytes,
    readInstalled: async () => bytes,
    env: {
      ...f.options.env,
      RUNNER_ENVIRONMENT: "github-hosted",
      RUNNER_OS: "macOS",
      GITHUB_REPOSITORY: job.repository,
      GITHUB_RUN_ID: job.runId,
      GITHUB_RUN_ATTEMPT: "1",
    },
    acquire: async (actual) => {
      f.events.push("hosted-build");
      if (failure === "compile") throw new Error("Original compile failure");
      return { ...prepared, job: actual };
    },
    readSelector: f.options.readReceipt,
  };
  delete options.provisionBuild;
  let births = 20;
  const id = "1:2:3:99:100:0:" + "d".repeat(32);
  options.createReader = (input, settings) => {
    const helper = { ...identity(births++), asid: 51 },
      verifier = identity(births++);
    let sequence = 0,
      joined = false;
    const save = (phase, request) =>
      settings.persist({
        purpose: "experiment",
        schemaVersion: 1,
        context: input.context,
        sequence: sequence++,
        phase,
        request,
        requestSha256: observationDigest(request),
        bindingSha256: input.bindingSha256,
        custody: "POSSIBLE",
        ...(phase === "admitted" ? { subjects: request } : {}),
      });
    return {
      async start() {
        for (const phase of ["entry", "admitted"])
          await save(phase, { helper, verifier });
        return {
          purpose: "experiment",
          independent: true,
          helper,
          planSha256: hash,
        };
      },
      verifyBuildReceipt: async () => {
        f.events.push("receipt-read");
      },
      provisionBuild: async () => ({ independent: true, identity: id }),
      readBuildDirectory: async () => {
        joined = true;
        return { independent: true, identity: id, uid: 0, gid: 0, mode: 0o555 };
      },
      readBuildInput: async (file, pin, toolCdhash) => ({
        sha256: pin,
        ...(toolCdhash ? { cdhash: toolCdhash } : {}),
        object: { identity: file === "/usr/lib/dyld" ? "held-loader" : id },
        ...(file.endsWith("/SDKSettings.json")
          ? {
              sdk: { identity: id, directory: true },
              developer: { identity: id, directory: true },
              compilerPathHex: Buffer.from(
                toolchainSelection.compiler.path,
              ).toString("hex"),
            }
          : {}),
        ...(file === "/usr/lib/dyld" ? { macho: { dependencies: [] } } : {}),
        independent: true,
        held: true,
        unchanged: true,
        nativeEventSha256: hash,
      }),
      cache: async () =>
        assert.fail("Ordinary preparation cannot enumerate caches"),
      readBuildImage: async (file) => {
        assert.equal(
          joined,
          false,
          "A read-only root join must close before a fresh output session",
        );
        const dependencies = file.endsWith(".deps"),
          name = path.basename(file).replace(/\.deps$/u, ""),
          data = dependencies
            ? Buffer.from(
                `${name}: /fixture/sealed/${name}.c /Library/Developer/CommandLineTools/SDKs/Fixture.sdk/input.h${["launcher", "custody-reader"].includes(name) ? " /fixture/sealed/custody.h" : ""}${name === "custody-reader" ? " /fixture/sealed/pf-abi.h /fixture/sealed/feasibility-sandbox.h /Library/Developer/CommandLineTools/SDKs/Fixture.sdk/usr/include/mach/task_info.h /Library/Developer/CommandLineTools/SDKs/Fixture.sdk/usr/include/mach-o/dyld_images.h" : ""}\n`,
              )
            : image;
        return {
          purpose: "experiment",
          bytes: data,
          sha256: digest(data),
          identity: id,
          rootIdentity: id,
          independent: true,
          held: true,
          unchanged: true,
          nativeEventSha256: hash,
          ...(!dependencies
            ? {
                signature: { valid: true, cdhash },
                macho: {
                  dependencies: ["/usr/lib/dyld", "/usr/lib/libSystem.B.dylib"],
                  rpaths: [],
                  sdk: 1,
                  minimum: 1,
                  uuid: "0".repeat(32),
                  headerSha256: hash,
                },
              }
            : {}),
        };
      },
      build: async () => {
        // The native reader journals this ABI command before sending it.
        await save("build", { sequence: 1, arguments: [] });
        return {
          purpose: "experiment",
          osBuild: "24A100",
          observedBindings: { sdkSha256: hash, buildSha256: hash },
        };
      },
      retired: async () => {
        f.events.push("original-retirement");
        return retired;
      },
      retiredRootDomain: async () => ({
        independent: true,
        complete: true,
        members: [],
      }),
      close: async () => ({ ...retired, helper, verifier, closed: true }),
    };
  };
  const jobs = [],
    persist = async (value) => {
      jobs.push(value);
      f.events.push("job:" + value.preparationEffects.admission);
    };
  return { ...f, prepared, job, options, jobs, persist, image };
}
const jobContextForTest = (job) =>
  Object.fromEntries(
    ["candidateSha", "platform", "repository", "runId", "runAttempt"].map(
      (key) => [key, job[key]],
    ),
  );

function hostedAcquisitionFixture(diagnostic = "") {
  const f = experimentBuildFixture(),
    files = new Map(),
    calls = [],
    environment = f.prepared.environment;
  const options = {
    ...f.options,
    fs: {
      mkdir: async () => {},
      readdir: async () => [],
      realpath: async (file) => {
        assert.ok(!file.includes("dyld_shared_cache"));
        return file;
      },
      lstat: async () => ({ isFile: () => true }),
      readFile: async (file) => {
        if (files.has(file)) return files.get(file);
        if (DARWIN_HELPER_NAMES.includes(path.basename(file)))
          throw Object.assign(new Error("Missing output"), { code: "ENOENT" });
        return bytes;
      },
      writeFile: async (file, value) => {
        assert.ok(!files.has(file));
        files.set(file, Buffer.from(value));
      },
    },
    command: async (file, args) => {
      calls.push({ file, args });
      let stdout = "",
        stderr = "";
      if (file === "git") stdout = candidateSha + "\n";
      if (file === "/usr/bin/xcrun")
        stdout =
          (args.includes("--find")
            ? f.prepared.tools[0].path
            : args.includes("--show-sdk-build-version")
              ? "24A"
              : environment.SDKROOT) + "\n";
      if (file === f.prepared.tools[0].path) {
        if (args[0] === "--version") stdout = "Apple clang version 17.0\n";
        else {
          files.set(args[args.indexOf("-o") + 1], f.image);
          if (
            args.includes(
              path.join(directory, "hosted-build", "custody-reader.c"),
            )
          )
            stderr = diagnostic;
        }
      }
      if (file === "/usr/bin/codesign" && args[0] === "-d")
        stderr = `CDHash=${cdhash}\n`;
      if (file === "/usr/bin/sudo" && args[2] === "/usr/bin/shasum")
        stdout = `${hash}  /usr/bin/sudo\n${hash}  /usr/bin/env\n`;
      if (file === "/usr/bin/sudo" && args[2] === "/usr/bin/install")
        files.set(args.at(-1), files.get(args.at(-2)));
      return { exitCode: 0, signal: null, timedOut: false, stdout, stderr };
    },
  };
  const job = recordExperimentPreparationEffect(f.job, {
    admission: "possible",
    settlement: {
      status: "RETAINED",
      independent: false,
      emergencyCleanup: false,
    },
    receiptSha256: null,
  });
  return { ...f, files, calls, options, job };
}

test("Darwin hosted preparation compiles each helper once and publishes only observed signed output", async () => {
  const f = hostedAcquisitionFixture(longDiagnostic);
  const prepared = await acquireDarwinExperimentBuild(
    f.job,
    directory,
    f.options.binding,
    f.options,
  );
  assert.equal(prepared.schemaVersion, 3);
  assert.equal(prepared.command.toolchain, undefined);
  assert.equal(prepared.bootstrapSeed, undefined);
  assert.equal(
    prepared.commands.find(({ args }) =>
      args.includes(path.join(directory, "hosted-build", "custody-reader.c")),
    ).stderr,
    longDiagnostic,
  );
  const compiled = f.calls.filter(
    ({ file, args }) =>
      file === prepared.tools[0].path && args[0] !== "--version",
  );
  assert.equal(compiled.length, DARWIN_HELPER_NAMES.length);
  assert.ok(
    compiled.every(
      ({ args }) =>
        !args.includes("-MD") && args.includes("-DNATIVE_CI_EXPERIMENT=1"),
    ),
  );
  assert.equal(
    new Set(compiled.map(({ args }) => args[args.indexOf("-o") + 1])).size,
    DARWIN_HELPER_NAMES.length,
  );
  assert.ok(f.calls.every(({ file }) => !file.includes("build-helper")));
  assert.equal(
    darwinExperimentBuildInput(prepared, f.job, directory).manifest
      .darwinPreparation.schemaVersion,
    3,
  );
  assert.throws(() =>
    normalizeDarwinPreparation(
      darwinExperimentBuildInput(prepared, f.job, directory).manifest
        .darwinPreparation,
      candidateSha,
    ),
  );
  for (const helper of prepared.helpers)
    assert.equal(
      digest(f.files.get(path.join(prepared.output, helper.name))),
      helper.sha256,
    );
});

test("Darwin hosted failures and cancellation keep real diagnostics and stop publication", async () => {
  for (const fault of ["compile", "missing-output", "cancel", "candidate"]) {
    const f = hostedAcquisitionFixture(),
      command = f.options.command,
      controller = new AbortController();
    const original = Object.assign(
      new Error("Original hosted compilation failure"),
      {
        exitCode: 65,
        stdout: "compiler output",
        stderr: "compiler diagnostic",
      },
    );
    f.options.signal = controller.signal;
    if (fault === "candidate")
      f.options.readCandidate = async () => Buffer.from("changed candidate");
    f.options.command = async (file, args, settings) => {
      if (file === f.prepared.tools[0].path && args[0] !== "--version") {
        if (fault === "compile") throw original;
        if (fault === "cancel") {
          controller.abort(original);
          throw original;
        }
        if (fault === "missing-output")
          return {
            exitCode: 0,
            signal: null,
            timedOut: false,
            stdout: "",
            stderr: "",
          };
      }
      return command(file, args, settings);
    };
    await assert.rejects(
      acquireDarwinExperimentBuild(
        f.job,
        directory,
        f.options.binding,
        f.options,
      ),
      (cause) =>
        fault === "compile" || fault === "cancel"
          ? cause === original && cause.stderr === "compiler diagnostic"
          : fault === "missing-output"
            ? cause.code === "ENOENT"
            : /Unverified/u.test(cause.message),
    );
    assert.ok(!f.calls.some(({ file }) => file === "/usr/bin/sudo"));
  }
});

test("Darwin hosted command failures own the process group and reap closure", async () => {
  for (const fault of ["cancel", "survivor", "exit", "stream"]) {
    const controller = new AbortController(),
      child = new EventEmitter(),
      kills = [];
    child.pid = 4321;
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    let closed = false;
    const original = new Error("Original command failure");
    const completion = runDarwinHostedCommand("/synthetic/compiler", [], {
      timeout: 60000,
      maxBuffer: 65536,
      signal: controller.signal,
      spawn: () => child,
      kill: (pid, signal) => {
        kills.push([pid, signal]);
        if (signal === 0 && (fault !== "survivor" || !closed))
          throw Object.assign(new Error("Absent"), { code: "ESRCH" });
      },
    });
    child.stderr.write("original compiler diagnostic");
    if (fault === "cancel") controller.abort(original);
    try {
      if (fault === "stream") child.stderr.emit("error", original);
    } finally {
      closed = true;
      child.stdout.end();
      child.stderr.end();
      child.emit("close", fault === "exit" ? 7 : 0, null);
    }
    await assert.rejects(completion, (cause) => {
      assert.equal(cause.stderr, "original compiler diagnostic");
      return ["cancel", "stream"].includes(fault)
        ? cause === original
        : fault === "exit"
          ? cause.exitCode === 7
          : /group remains live/u.test(cause.message);
    });
    if (["cancel", "stream"].includes(fault))
      assert.ok(
        kills.some(
          ([pid, signal]) => pid === -child.pid && signal === "SIGTERM",
        ),
      );
    if (fault === "survivor")
      assert.ok(
        kills.some(
          ([pid, signal]) => pid === -child.pid && signal === "SIGKILL",
        ),
      );
  }
});

test("Darwin hosted streams retain long diagnostics and enforce the combined byte boundary", async () => {
  for (const outcome of ["long", "boundary", "overflow"]) {
    const child = new EventEmitter(),
      kills = [],
      stdout = Buffer.from("é".repeat(17000)),
      stderr =
        outcome === "long"
          ? Buffer.from(longDiagnostic)
          : Buffer.alloc(DARWIN_HOSTED_OUTPUT_BYTES - stdout.length, "w");
    child.pid = 4321;
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    const completion = runDarwinHostedCommand("/synthetic/compiler", [], {
      timeout: 60000,
      maxBuffer: DARWIN_HOSTED_OUTPUT_BYTES,
      spawn: () => child,
      kill: (pid, signal) => {
        kills.push([pid, signal]);
        if (signal === 0)
          throw Object.assign(new Error("Absent"), { code: "ESRCH" });
      },
    });
    child.stdout.write(stdout.subarray(0, 1));
    child.stdout.end(stdout.subarray(1));
    child.stderr.write(stderr);
    if (outcome === "overflow") child.stderr.write(Buffer.from("!"));
    child.stderr.end();
    child.emit("close", 0, null);
    if (outcome === "overflow") {
      await assert.rejects(completion, /output exceeded its bound/u);
      assert.ok(
        kills.some(
          ([pid, signal]) => pid === -child.pid && signal === "SIGTERM",
        ),
      );
    } else {
      const result = await completion;
      assert.equal(result.stdout, stdout.toString());
      assert.equal(result.stderr, stderr.toString());
      assert.ok(stdout.length + stderr.length > 65536);
      assert.ok(kills.every(([, signal]) => signal === 0));
    }
  }
});

test("Darwin versioned build loading needs no cache and rejects substituted evidence without rebuilding", async () => {
  const f = experimentBuildFixture();
  f.prepared.commands[2].stderr = longDiagnostic;
  const built = await prepareDarwinExperimentBuild(
    f.job,
    directory,
    f.persist,
    f.options,
  );
  f.options.acquire = f.options.command = () =>
    assert.fail("Cold loading cannot rebuild or rediscover");
  const loaded = await loadDarwinExperimentBuild(
    built.job,
    directory,
    f.options,
  );
  for (const observed of [built, loaded]) {
    assert.equal(observed.prepared.binding.osBuild, "20260101.1");
    assert.equal(observed.build.abi.osBuild, "24A100");
  }
  const stored = JSON.parse(
    await f.options.readSelector(
      path.join(directory, "darwin-experiment-build-selector.json"),
    ),
  );
  assert.equal(stored.commands[2].stderr, longDiagnostic);
  assert.deepEqual(loaded.build, built.build);
  assert.equal(loaded.build.commands[2].stderr, longDiagnostic);
  assert.ok(Buffer.byteLength(JSON.stringify(stored)) < 1048576);
  assert.ok(
    built.build.commands.every(
      (command) =>
        command.compilerPolicy === undefined &&
        command.settlement === undefined,
    ),
  );
  for (const mutate of [
    (record) => {
      record.schemaVersion = 2;
    },
    (record) => {
      record.schemaVersion = 1;
    },
    (record) => {
      record.cachePath = "/System/Library/dyld/dyld_shared_cache_x86_64h";
    },
    (record) => {
      record.bootstrapSeed = {};
    },
    (record) => {
      record.commands.pop();
    },
    (record) => {
      record.commands[2].args = ["-fplugin=/synthetic/plugin"];
    },
    (record) => {
      record.commands[0].env = null;
    },
    (record) => {
      record.commands[0].env.SDKROOT = "/synthetic/other-sdk";
    },
    (record) => {
      record.commands[2].stdout = "é".repeat(DARWIN_HOSTED_OUTPUT_BYTES / 2);
      record.commands[2].stderr = "!";
    },
  ]) {
    const changed = structuredClone(built.prepared);
    mutate(changed);
    assert.throws(() =>
      darwinExperimentBuildInput(changed, built.job, directory),
    );
  }
  const buildPath = path.join(directory, "darwin-experiment-build.json"),
    original = f.files.get(buildPath),
    close = f.files.get(
      path.join(directory, "darwin-experiment-build-close.json"),
    );
  for (const mutate of [
    (record) => {
      record.build.schemaVersion = 2;
    },
    (record) => {
      record.build.sdk.runtime = [];
    },
    (record) => {
      record.build.helpers.pop();
    },
  ]) {
    const changed = structuredClone(original);
    mutate(changed);
    f.files.set(buildPath, changed);
    const stale = {
      ...built.job,
      failure: "preparation-failed",
      preparationEffects: {
        ...built.job.preparationEffects,
        receiptSha256: observationDigest({ observed: changed, close }),
      },
    };
    await assert.rejects(
      loadDarwinExperimentBuild(stale, directory, f.options),
    );
    const recovered = await recoverDarwinExperimentBuild(
      stale,
      directory,
      f.persist,
      f.options,
    );
    assert.equal(recovered.preparationEffects.settlement.status, "RETAINED");
    assert.equal(recovered.failure, stale.failure);
  }
  f.files.set(buildPath, original);
  const create = f.options.createReader;
  f.options.createReader = (...args) => {
    const reader = create(...args);
    return {
      ...reader,
      build: async () => ({
        ...(await reader.build()),
        osBuild: "24A101",
      }),
    };
  };
  await assert.rejects(
    loadDarwinExperimentBuild(built.job, directory, f.options),
    /Unverified native tool observation/u,
  );
  f.options.createReader = (...args) => {
    const reader = create(...args),
      read = reader.readBuildImage;
    return {
      ...reader,
      readBuildImage: async (...values) => ({
        ...(await read(...values)),
        sha256: "f".repeat(64),
      }),
    };
  };
  await assert.rejects(
    loadDarwinExperimentBuild(built.job, directory, f.options),
  );
  f.options.createReader = create;
  for (const target of ["compiler", "SDKSettings.json"]) {
    await assert.rejects(
      loadDarwinExperimentBuild(built.job, directory, {
        ...f.options,
        readInstalled: async (file) =>
          (
            target === "compiler"
              ? file === built.prepared.tools[0].path
              : file.endsWith(target)
          )
            ? Buffer.from("substituted installed input")
            : bytes,
      }),
    );
  }
  await assert.rejects(
    loadDarwinExperimentBuild(
      { ...built.job, candidateSha: "b".repeat(40) },
      directory,
      f.options,
    ),
  );
  await assert.rejects(
    loadDarwinExperimentBuild(built.job, directory, {
      ...f.options,
      readCandidate: async () => Buffer.from("substituted source"),
    }),
  );
});

test("Darwin initial preparation rejects non-experiment native build observations", async () => {
  const f = experimentBuildFixture(),
    create = f.options.createReader;
  f.options.createReader = (...args) => {
    const reader = create(...args);
    return {
      ...reader,
      build: async () => ({
        ...(await reader.build()),
        purpose: "reviewed",
      }),
    };
  };
  await assert.rejects(
    prepareDarwinExperimentBuild(f.job, directory, f.persist, f.options),
    /Unverified native tool observation/u,
  );
});

test("Darwin cold loading compares binding values independently of key order", async () => {
  const f = experimentBuildFixture(),
    built = await prepareDarwinExperimentBuild(
      f.job,
      directory,
      f.persist,
      f.options,
    );
  const loaded = await loadDarwinExperimentBuild(built.job, directory, {
    ...f.options,
    binding: Object.fromEntries(Object.entries(f.options.binding).reverse()),
    acquire: () => assert.fail("Cold loading cannot acquire inputs"),
    command: () => assert.fail("Cold loading cannot execute commands"),
  });
  assert.deepEqual(loaded.build, built.build);
});

test("Darwin completed-build policy needs fresh held bytes and an independent output identity", async () => {
  const f = experimentBuildFixture(),
    built = await prepareDarwinExperimentBuild(
      f.job,
      directory,
      f.persist,
      f.options,
    );
  const binding = normalizeExperimentPolicyBinding(
      darwinExperimentBuildBinding(built),
    ),
    owner = createDarwinCaseProvisioning(
      {
        guard: () => {},
        plan: { bootstrap: built.prepared.bootstrap },
        output,
      },
      {},
    );
  const reader = f.options.createReader(built.prepared.bootstrap, {});
  const proof = await owner.observeBuildPolicy(
    binding,
    { build: built.build, reader },
    {},
  );
  const policy = verifyExperimentPolicy(
    binding.template,
    proof.provisioning,
    binding.context,
    proof.requestSha256,
    proof.observed,
  );
  assert.equal(policy.independent, true);
  assert.equal(proof.observed.policy.policy.compilerDomains, undefined);
  assert.equal(
    proof.observed.policy.policy.images.length,
    DARWIN_HELPER_NAMES.length,
  );
  const fresh = () => f.options.createReader(built.prepared.bootstrap, {});
  await assert.rejects(
    owner.observeBuildPolicy(
      binding,
      {
        build: built.build,
        reader: {
          ...fresh(),
          readBuildDirectory: async () => ({
            independent: false,
            uid: 0,
            gid: 0,
            mode: 0o555,
            identity: "copied expectation",
          }),
        },
      },
      {},
    ),
  );
  const substitute = fresh(),
    read = substitute.readBuildImage;
  substitute.readBuildImage = async (...args) => ({
    ...(await read(...args)),
    bytes: Buffer.from("substituted output"),
  });
  await assert.rejects(
    owner.observeBuildPolicy(
      binding,
      { build: built.build, reader: substitute },
      {},
    ),
  );
});

test("Darwin interrupted preparation never reconstructs compiler completion or hides its first failure", async () => {
  const f = experimentBuildFixture("compile");
  await assert.rejects(
    prepareDarwinExperimentBuild(f.job, directory, f.persist, f.options),
    /Original compile failure/u,
  );
  const failed = f.jobs.at(-1),
    recovered = await recoverDarwinExperimentBuild(
      failed,
      directory,
      f.persist,
      f.options,
    );
  assert.equal(recovered.failure, "preparation-failed");
  assert.equal(recovered.preparationEffects.settlement.status, "RETAINED");
  assert.equal(recovered.preparation, null);
  assert.ok(
    [...f.files.keys()].some((file) =>
      path.basename(file).startsWith("darwin-recovery-"),
    ),
  );
  const late = hostedAcquisitionFixture();
  late.options.fs.readdir = async () => ["darwin-recovery-0-intent.json"];
  await assert.rejects(
    acquireDarwinExperimentBuild(
      late.job,
      directory,
      late.options.binding,
      late.options,
    ),
  );
  assert.equal(late.calls.length, 0);
});

const execution = (recipe) => ({
  id: recipe.id,
  effects: Object.fromEntries(
    NATIVE_EFFECT_CLASSES.map((name) => [
      name,
      {
        admission:
          name === "policy" ||
          (recipe.id === "build"
            ? ["builds"]
            : NATIVE_GROUPS.darwin[recipe.group].effects
          ).includes(name)
            ? "possible"
            : "not-started",
      },
    ]),
  ),
});
const settled = (receipts) =>
  Object.values(receipts).find((value) => value !== null).settlement;
function policy(value, id) {
  const request = {
    schemaVersion: 1,
    candidateSha,
    nonce: "d".repeat(32),
    uid: 90001,
    gid: 90002,
    custody: "/fixture/custody",
    storage: "/fixture/storage",
    workspace: "/fixture/storage/work",
    launcher: { path: "/fixture/custody/launcher", sha256: hash },
    executable: { path: "/fixture/storage/payload", sha256: hash, cdhash },
    policy: { path: "/fixture/custody/policy", sha256: hash },
    bindings: { source: hash, system: hash, closure: hash, policy: hash },
  };
  const input = id.startsWith("access.")
    ? {
        request,
        profile: id.slice(7),
        disposable: true,
        metadata: "/fixture/storage/metadata",
        pointer: "/fixture/storage/work/.git",
        checkout: "/protected/checkout",
        configuration: "/protected/config",
        credentials: "/protected/credentials",
        runtime: [
          {
            path: request.executable.path,
            sha256: hash,
            executable: true,
            mapped: true,
          },
          {
            path: "/usr/lib/dyld",
            sha256: hash,
            executable: false,
            mapped: true,
          },
        ],
        endpoints: ["inet", "inet6"].flatMap((family, i) =>
          ["tcp", "udp"].map((protocol, j) => ({
            family,
            protocol,
            clientPort: 41001 + i * 4 + j * 2,
            serverPort: 41002 + i * 4 + j * 2,
          })),
        ),
        reviewSha256: hash,
      }
    : request;
  let parameters = {};
  if (input !== request) {
    const native = buildDarwinPolicy(input);
    request.policy.sha256 = native.seatbeltSha256;
    request.bindings.policy = native.compositionSha256;
    const { request: allocation, ...policy } = native.value;
    parameters = policy;
  }
  const template = {
    schemaVersion: 1,
    candidateSha,
    platform: "darwin",
    sourceReviewSha256: hash,
    provisioningReviewSha256: hash,
    policy: {
      launch: nativePolicyLaunchData(request, DARWIN_LITERAL_ARGUMENTS),
      policy: parameters,
    },
    bindings: [],
  };
  const approval = {
    candidateSha,
    platform: "darwin",
    authority: "operator-protected",
    manifestSha256: nativePolicyTemplateDigest(template),
  };
  const binding = { template, approval, context: context(id) },
    provisioning = {
      schemaVersion: 1,
      context: context(id),
      authoritySha256: hash,
      bindings: [],
      held: true,
      independent: true,
      verifierSha256: hash,
      nativeEventSha256: hash,
    };
  const expected = materializeNativePolicy(
      template,
      approval,
      provisioning,
      binding.context,
    ),
    requestSha256 = darwinLaunchDigest(request, DARWIN_LITERAL_ARGUMENTS);
  const proof = {
    provisioning,
    requestSha256,
    observed: {
      schemaVersion: 1,
      context: binding.context,
      templateSha256: expected.templateSha256,
      provisioningSha256: expected.provisioningSha256,
      requestSha256,
      policySha256: expected.expectedPolicySha256,
      policy: expected.policy,
      held: true,
      complete: true,
      independent: true,
      verifierSha256: hash,
      nativeEventSha256: hash,
    },
  };
  value.options.provision = async () => {
    assert.ok(
      value.events.some((event) => event.startsWith(`darwin-case-${id}-`)),
    );
    value.events.push("provision");
    return {
      input,
      provisioning,
      arguments: DARWIN_LITERAL_ARGUMENTS,
    };
  };
  value.options.ownerEffects = async (current) => {
    assert.equal(typeof current.owners.launch, "function");
    assert.equal(typeof current.owners.retire, "function");
    value.events.push("owner-effects");
    const noop = async () => {};
    return Object.fromEntries(
      [
        "admit",
        "observe",
        "armFault",
        "fireFault",
        "recoverAndRetire",
        "verify",
        "prepare",
        "verifyPolicy",
        "retire",
        "restore",
        "snapshot",
        "review",
        "open",
        "ordinary",
        "fileEffects",
        "verifyRetirement",
        "privateProbe",
        "startPublishers",
        "finishPublishers",
        "startReader",
        "finishReader",
        "applyControl",
        "observeDenial",
        "restoreControl",
        "nameControl",
        "openHeld",
        "inspectHeld",
        "readHeld",
        "loaderClosure",
        "buildBindings",
        "observeAuthority",
        "inspectProvider",
        "closeHeld",
        "verifyClosed",
        "verifyInputs",
        "verifyAuthority",
        "verifyReceipt",
        "readProvisioning",
        "readPolicy",
        "persist",
      ].map((name) => [name, noop]),
    );
  };
  value.options.readPolicy = async () => {
    value.events.push("policy-read");
    return proof;
  };
  value.options.retire = async () => {
    value.events.push("payload-retire");
    return retired;
  };
  value.options.verifyRetirement = async () => true;
  value.options.releaseAudit = async () => {
    value.events.push("audit-release");
    return retired;
  };
  value.options.restore = async () => {
    value.events.push("policy-restore");
    return { status: "RESTORED", independent: true, nativeEventSha256: hash };
  };
  return { binding, proof };
}

test("Darwin factories construct without effects and retain the complete fixed inventory", () => {
  const value = wiring();
  createDarwinBuildEffects(value.input, value.options);
  createDarwinSystemEffects(value.input, value.options);
  assert.deepEqual(value.events, []);
  const incomplete = structuredClone(value.manifest.darwinPreparation);
  incomplete.cases.pop();
  assert.throws(() => normalizeDarwinPreparation(incomplete, candidateSha));
  incomplete.cases.push(incomplete.cases[0]);
  assert.throws(() => normalizeDarwinPreparation(incomplete, candidateSha));
  assert.equal(
    DARWIN_SYSTEM_PREPARATION_MS,
    60000 +
      3 * 30000 +
      DARWIN_HELPER_NAMES.length * 60000 +
      60000 +
      (3 + DARWIN_HELPER_NAMES.length + 4 + darwinSystemRecipes().length) *
        30000 +
      2 * 120000,
  );
  assert.equal(
    darwinSystemRecipes().find(({ id }) => id === "files.aliases").deadlineMs,
    360000,
  );
});

test("Darwin experimental declarations and fixed compilation cannot borrow reviewed bindings", async () => {
  const { manifest, requests } = wiring(),
    reviewed = requests[2],
    original = darwinBuildOperation(reviewed, manifest, output);
  manifest.purpose = "experiment";
  manifest.darwinPreparation.purpose = "experiment";
  manifest.darwinPreparation.command.sdk = { ...sdkSelection };
  manifest.darwinPreparation.command.toolchain =
    structuredClone(toolchainSelection);
  manifest.environment.DEVELOPER_DIR = toolchainSelection.developer.path;
  for (const request of requests)
    request.env.DEVELOPER_DIR = toolchainSelection.developer.path;
  manifest.darwinPreparation.sources.push({
    name: "experiment.h",
    sha256: hash,
  });
  assert.throws(() =>
    normalizeDarwinPreparation(manifest.darwinPreparation, candidateSha),
  );
  const request = {
      ...reviewed,
      purpose: "experiment",
      args: darwinCompilerArguments(
        original.source.path,
        original.target,
        manifest.environment,
        "experiment",
      ),
    },
    operation = darwinBuildOperation(request, manifest, output);
  assert.equal(operation.header.sha256, hash);
  assert.equal(operation.header.path, sourceDirectory + "/experiment.h");
  assert.equal(operation.purpose, "experiment");
  assert.throws(() =>
    darwinBuildOperation(request, { ...manifest, purpose: "reviewed" }, output),
  );
  assert.throws(() =>
    darwinBuildOperation({ ...request, args: reviewed.args }, manifest, output),
  );
  manifest.darwinPreparation.sources.pop();
  assert.throws(() => darwinBuildOperation(request, manifest, output));
  await assert.rejects(
    runDarwinBuildCommand(
      request,
      operation,
      {},
      {},
      () => assert.fail("No admission without a compiler-policy reader"),
      {
        open: () => {
          throw new Error("Unexpected native effect");
        },
      },
    ),
    /Unverified Darwin launch authority/u,
  );
});

test("Darwin command admission rejects unreviewed vectors before effects and persists intent before provisioning", async () => {
  const value = wiring();
  value.files.clear();
  value.options.runCommand = async (request) => {
    assert.ok(value.events.includes("provision-build"));
    value.events.push("command");
    return {
      requestSha256: observationDigest(request),
      toolSha256: hash,
      independent: true,
      nativeEventSha256: hash,
      settlement: retired,
      identity: identity(11),
      helperIdentity: identity(12),
      exitCode: 0,
      signal: null,
      timedOut: false,
    };
  };
  const effects = createDarwinBuildEffects(value.input, value.options);
  await assert.rejects(
    effects.run({ ...value.requests[0], args: ["-fplugin=/fixture/plugin"] }),
  );
  assert.deepEqual(value.events, []);
  const result = await effects.run(value.requests[0]);
  assert.equal(result.bootstrapSettlement.closed, true);
  assert.ok(
    value.events.findIndex(
      (event) =>
        event.endsWith("-intent.json") && event.startsWith("darwin-command"),
    ) < value.events.indexOf("provision-build"),
  );
  assert.ok(
    value.events.indexOf("command") < value.events.indexOf("close:build"),
  );
  const substituted = wiring();
  substituted.files.clear();
  substituted.options.read = async () => Buffer.from("substituted");
  await assert.rejects(
    createDarwinBuildEffects(substituted.input, substituted.options).run(
      substituted.requests[0],
    ),
  );
  assert.ok(!substituted.events.includes("provision-build"));
});

test("Darwin build entry classifies fixed installed tools through the default preparation reader", async () => {
  for (const [purpose, scenario, requestIndex = 0] of [
    ["reviewed", "compiler"],
    ["experiment", "compiler"],
    ["reviewed", "full-width"],
    ["experiment", "full-width"],
    ["reviewed", "uint64-max"],
    ["experiment", "uint64-max"],
    ["reviewed", "sdk", 1],
    ["reviewed", "signer", 3],
    ["reviewed", "generated-source"],
    ["reviewed", "generated-helper"],
    ["reviewed", "unclassified-tool"],
    ["reviewed", "unsafe-ancestry"],
    ["reviewed", "unsafe-single-link"],
    ["reviewed", "held-bytes"],
  ]) {
    const value = wiring({ defaultRead: true }),
      { manifest, options, events } = value,
      plan = manifest.darwinPreparation;
    value.files.clear();
    assert.equal(Object.hasOwn(options, "read"), false);
    if (purpose === "experiment") {
      manifest.purpose = purpose;
      plan.purpose = purpose;
      plan.command.sdk = { ...sdkSelection };
      plan.command.toolchain = structuredClone(toolchainSelection);
      manifest.environment.DEVELOPER_DIR = toolchainSelection.developer.path;
      for (const request of value.requests)
        request.env.DEVELOPER_DIR = toolchainSelection.developer.path;
      plan.cases = [];
      plan.bootstrap.purpose = purpose;
      plan.bootstrap.bindingSha256 = plan.bootstrap.reviewSha256;
      delete plan.bootstrap.reviewSha256;
      for (const name of ["experiment.h", "pf-abi.h"]) {
        plan.sources.push({ name, sha256: hash });
        plan.bootstrap.sources.push({
          path: path.join(path.dirname(plan.bootstrap.reader.path), name),
          sha256: hash,
        });
      }
    }
    // Even an installed SDK ancestry cannot classify a sealed source by pin.
    if (scenario === "generated-source")
      plan.sourceDirectory = "/Library/Developer/Fixture";
    const request = {
      ...value.requests[requestIndex],
      ...(purpose === "experiment" ? { purpose } : {}),
    };
    if (scenario === "unclassified-tool") {
      request.file = "/fixture/tools/clang";
      manifest.tools[0].path = request.file;
    }
    const sources = new Set(
        plan.sources.map(({ name }) => path.join(plan.sourceDirectory, name)),
      ),
      tools = new Set(manifest.tools.map(({ path }) => path)),
      helper = plan.command.helper.path,
      inputs = new Map(
        [...sources, helper, ...tools].map((file, index) => [file, index + 1]),
      ),
      readFiles = [],
      fullWidthInode =
        scenario === "full-width"
          ? 9007199254740995n
          : scenario === "uint64-max"
            ? 18446744073709551615n
            : null;
    let openFiles = 0,
      changedTool = false;
    const stat = (file, bigint = false) => {
      const leaf = inputs.has(file),
        privateDirectory =
          file === directory || file.startsWith(directory + "/"),
        unsafe =
          file === "/usr" &&
          ["unsafe-ancestry", "unsafe-single-link"].includes(scenario),
        linked =
          (tools.has(file) && scenario !== "unsafe-single-link") ||
          (scenario === "generated-source" && sources.has(file)) ||
          (scenario === "generated-helper" && file === helper),
        convert = (number) => (bigint ? BigInt(number) : number);
      return {
        isFile: () => leaf,
        isDirectory: () => !leaf,
        isSymbolicLink: () => false,
        dev: convert(1),
        // Only the compatibility sample rounds; held reads use the exact literal.
        ino:
          fullWidthInode === null
            ? convert(inputs.get(file) ?? 1)
            : bigint
              ? fullWidthInode
              : Number(fullWidthInode),
        uid: convert(!leaf && privateDirectory ? 1001 : 0),
        gid: convert(0),
        mode: convert(
          leaf
            ? 0o100000 |
                (tools.has(file) ? 0o755 : file === helper ? 0o555 : 0o444)
            : 0o040000 | (unsafe ? 0o777 : privateDirectory ? 0o700 : 0o755),
        ),
        nlink: convert(linked ? 78 : 1),
        size: convert(leaf ? bytes.length : 0),
        mtimeNs: convert(1),
        ctimeNs: convert(changedTool && file === request.file ? 2 : 1),
      };
    };
    options.fs = {
      ...options.fs,
      lstat: async (file, settings) => stat(file, settings?.bigint),
      open: async (file, flags) => {
        assert.ok(inputs.has(file));
        assert.equal(
          flags,
          constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
        );
        openFiles++;
        let closed = false;
        return {
          stat: async () => stat(file, true),
          async read(buffer, offset, length, position) {
            const changed = scenario === "held-bytes" && file === request.file;
            if (changed) changedTool = true;
            const content = changed ? Buffer.alloc(bytes.length) : bytes,
              chunk = content.subarray(position, position + length);
            if (chunk.length) readFiles.push(file);
            chunk.copy(buffer, offset);
            return { bytesRead: chunk.length };
          },
          async close() {
            assert.equal(closed, false);
            closed = true;
            openFiles--;
          },
        };
      },
    };
    options.digestIntermediate = async () => hash;
    options.runCommand = async (current, operation, entry) => {
      assert.equal(current.file, request.file);
      assert.equal(operation.tool.path, request.file);
      assert.equal(operation.tool.sha256, hash);
      assert.equal(entry.toolCdhash, cdhash);
      assert.ok(readFiles.includes(request.file));
      assert.ok(events.includes("provision-build"));
      events.push("command");
      return {
        ...(purpose === "experiment" ? { purpose } : {}),
        requestSha256: observationDigest(current),
        toolSha256: hash,
        independent: true,
        nativeEventSha256: hash,
        settlement: retired,
        exitCode: 0,
        signal: null,
        timedOut: false,
      };
    };
    const effects = createDarwinBuildEffects(value.input, options),
      accepted = [
        "compiler",
        "sdk",
        "signer",
        "full-width",
        "uint64-max",
      ].includes(scenario);
    try {
      if (accepted) {
        const result = await effects.run(request);
        assert.equal(result.bootstrapSettlement.closed, true);
        assert.equal(result.purpose ?? "reviewed", purpose);
        assert.ok(events.includes("command"));
      } else {
        await assert.rejects(effects.run(request), /Unverified/u, scenario);
        assert.equal(events.includes("command"), false);
        assert.equal(events.includes("provision-build"), false);
        assert.equal(
          [...value.files.keys()].some((file) =>
            path.basename(file).startsWith("darwin-command-"),
          ),
          false,
        );
      }
    } finally {
      const settlement = await effects.settle();
      if (events.includes("start:build")) {
        assert.equal(settlement.status, "RETIRED", scenario);
        assert.equal(settlement.independent, true, scenario);
        if (!accepted)
          assert.ok(events.includes("fresh-root-retirement"), scenario);
      }
      assert.equal(openFiles, 0);
    }
  }
});

test("Darwin native compiler entry verifies parked images, bounded output and retirement before publication", async () => {
  for (const [purpose, scenario] of [
    ...[
      "retired",
      "descendants",
      "publication-failure",
      "oversized-output",
      "malformed-output",
      "invalid-utf8",
      "unexpected-field",
    ].map((scenario) => ["reviewed", scenario]),
    ...["retired", "descendants", "mutation"].map((scenario) => [
      "experiment",
      scenario,
    ]),
  ]) {
    const value = wiring();
    if (purpose === "experiment") {
      value.manifest.purpose = purpose;
      value.manifest.darwinPreparation.purpose = purpose;
      value.manifest.darwinPreparation.command.sdk = { ...sdkSelection };
      value.manifest.darwinPreparation.command.toolchain =
        structuredClone(toolchainSelection);
      value.manifest.environment.DEVELOPER_DIR =
        toolchainSelection.developer.path;
      for (const request of value.requests)
        request.env.DEVELOPER_DIR = toolchainSelection.developer.path;
    }
    const request = {
        ...value.requests[0],
        ...(purpose === "experiment" ? { purpose } : {}),
      },
      operation = darwinBuildOperation(request, value.manifest, output),
      admittedRequest = structuredClone(request),
      admittedTarget = operation.target ?? null,
      entry = {
        helper: { path: "/fixture/sealed/build-helper", sha256: hash, cdhash },
        tools: custody("build").tools,
        toolCdhash: cdhash,
      },
      events = [],
      helper = { ...identity(10), asid: 51 },
      worker = { ...identity(11), asid: 51 },
      result = {
        exitCode: 0,
        signal: null,
        stdoutHex: Buffer.from("reviewed\n").toString("hex"),
        stderrHex: Buffer.from("bounded warning\n").toString("hex"),
      };
    if (scenario === "oversized-output") {
      result.stdoutHex = "00".repeat(32768);
      result.stderrHex = "00".repeat(32769);
    }
    if (scenario === "malformed-output") result.stderrHex = "0";
    if (scenario === "invalid-utf8") result.stdoutHex = "ff";
    if (scenario === "unexpected-field") result.release = true;
    const frames = [{ helper }, { worker }, result];
    let domains = 0;
    const reader = {
      ...(purpose === "experiment"
        ? {
            compilerPolicy: async (identity) => ({
              identity,
              sandboxed: false,
            }),
          }
        : {}),
      helper: async (id) => {
        events.push(`inspect:${id.pid}`);
        return { identity: id, sha256: hash, signature: { cdhash } };
      },
      retired: async (id) => {
        events.push(`retired:${id.pid}`);
        return retired;
      },
      rootDomain: async () => ({
        complete: true,
        independent: true,
        members:
          ++domains === 3
            ? []
            : domains === 2 && scenario === "descendants"
              ? [helper, { ...identity(12), asid: 51 }]
              : [helper],
      }),
    };
    const pending = runDarwinBuildCommand(
      request,
      operation,
      entry,
      reader,
      async (record) => {
        assert.equal(
          record.purpose,
          purpose === "experiment" ? purpose : undefined,
        );
        assert.equal(record.requestSha256, observationDigest(admittedRequest));
        events.push(`persist:${record.phase}`);
        if (record.phase === "publication-possible") {
          assert.equal(record.output, admittedRequest.cwd);
          assert.equal(record.target, admittedTarget);
          if (scenario === "publication-failure")
            throw new Error("Cannot persist publication intent");
        }
      },
      {
        open: async (_, args) => {
          assert.equal(args.length, purpose === "experiment" ? 26 : 10);
          if (scenario === "mutation") {
            delete request.purpose;
            request.toolSha256 = "e".repeat(64);
            operation.target = "/fixture/substituted";
            entry.helper.sha256 = "e".repeat(64);
          }
          return {
            channel: {
              receive: async () => frames.shift(),
              send: async (command) => {
                events.push(command);
              },
              completion: Promise.resolve({ code: 0, signal: null }),
              close() {},
            },
          };
        },
      },
    );
    if (!["retired", "mutation"].includes(scenario)) {
      await assert.rejects(pending);
      assert.ok(events.indexOf("persist:worker") < events.indexOf("R"));
      assert.ok(!events.includes("S"));
      assert.ok(!events.includes("retired:10"));
      assert.equal(events.at(-1), "persist:uncertain");
      continue;
    }
    const observed = await pending;
    assert.equal(
      observed.purpose,
      purpose === "experiment" ? purpose : undefined,
    );
    assert.equal(observed.requestSha256, observationDigest(admittedRequest));
    assert.equal(observed.toolSha256, admittedRequest.toolSha256);
    assert.equal(observed.stdout, "reviewed\n");
    assert.equal(observed.stderr, "bounded warning\n");
    assert.ok(!Object.hasOwn(observed, "stdoutHex"));
    assert.ok(events.indexOf("persist:worker") < events.indexOf("R"));
    assert.ok(events.indexOf("retired:11") < events.indexOf("S"));
    assert.ok(
      events.indexOf("retired:11") <
        events.indexOf("persist:publication-possible"),
    );
    assert.ok(
      events.indexOf("persist:publication-possible") < events.indexOf("S"),
    );
    assert.ok(events.indexOf("S") < events.indexOf("retired:10"));
  }
});

test("Darwin prepared-build verification rejoins all pinned bytes and commands without recompiling", async () => {
  const value = wiring();
  value.options.runCommand = () => assert.fail("Verification cannot compile");
  const effects = createDarwinSystemEffects(value.input, value.options),
    result = await effects.verifyBuild(value.preparation);
  assert.equal(result.status, "OBSERVED");
  assert.equal(result.preparationSha256, observationDigest(value.preparation));
  assert.equal(
    value.events.filter((event) => event === "fresh-retirement").length,
    value.requests.length * 2,
  );
  value.preparation.commands[0].receiptSha256 = "f".repeat(64);
  await assert.rejects(effects.verifyBuild(value.preparation));
});

test("Darwin prepared-build policy observation is bound to the bootstrap execution and independently verified", async () => {
  for (const failure of [null, "context", "observation"]) {
    const value = wiring(),
      { binding, proof } = policy(value, "build"),
      records = [];
    value.options.observeBuildPolicy = async (actual, observed) => {
      assert.deepEqual(actual, binding);
      assert.equal(observed.status, "OBSERVED");
      return proof;
    };
    if (failure === "context")
      binding.context.executionId = "ownership.literal";
    if (failure === "observation") proof.observed.complete = false;
    const effects = createDarwinSystemEffects(value.input, value.options);
    const pending = effects.verifyBuild(value.preparation, {
      policyBinding: binding,
      recordPolicy: async (record) => records.push(record),
    });
    if (failure) {
      await assert.rejects(pending);
      assert.deepEqual(records, []);
      if (failure === "context") assert.deepEqual(value.events, []);
    } else {
      assert.equal((await pending).status, "OBSERVED");
      assert.deepEqual(records, [proof]);
    }
  }
});

test("Darwin composition binds every nonliteral recipe and retires domains before audit, policy and custody", async () => {
  for (const recipe of darwinSystemRecipes().filter(
    (entry) =>
      !["build", "ownership.literal", "ownership.storage"].includes(entry.id),
  )) {
    const value = wiring(),
      { binding } = policy(value, recipe.id),
      receipts = [],
      effects = createDarwinSystemEffects(value.input, value.options),
      prepared = await effects.prepare(
        { ...recipe, reviewSha256: hash },
        {
          policyBinding: binding,
          recordPolicy: async (proof) => {
            receipts.push(proof);
            value.events.push("record-policy");
          },
        },
      );
    assert.equal(prepared.templateSha256, binding.approval.manifestSha256);
    if (recipe.id.startsWith("access.")) {
      assert.equal(
        prepared.policySha256,
        buildDarwinPolicy(prepared.input).compositionSha256,
      );
      assert.notEqual(prepared.policySha256, receipts[0].observed.policySha256);
    }
    assert.equal(receipts.length, 1);
    assert.ok(
      value.events.indexOf("policy-read") <
        value.events.indexOf("record-policy"),
    );
    const result = await effects.settle(recipe, prepared, {
      signal: new AbortController().signal,
      execution: execution(recipe),
    });
    assert.equal(settled(result).status, "RETIRED");
    for (const name of NATIVE_EFFECT_CLASSES) {
      if (execution(recipe).effects[name].admission === "not-started")
        assert.equal(result[name], null);
      else {
        assert.equal(result[name].executionId, recipe.id);
        assert.equal(result[name].effectClass, name);
        assert.equal(result[name].candidateSha, candidateSha);
      }
    }
    for (const [a, b] of [
      ["payload-retire", "audit-release"],
      ["audit-release", "policy-restore"],
      ["policy-restore", `close:${recipe.id}`],
    ])
      assert.ok(value.events.indexOf(a) < value.events.indexOf(b));
  }
});

test("Darwin literal preparation defers policy observation to the parked payload's two launch barriers", async () => {
  const value = wiring(),
    recipe = darwinSystemRecipes().find(({ id }) => id === "ownership.literal"),
    { binding } = policy(value, recipe.id),
    work = new AbortController(),
    ownerEffects = value.options.ownerEffects;
  value.options.ownerEffects = async (...args) => ({
    ...(await ownerEffects(...args)),
    async verifyReceipt() {
      work.abort();
      return { sha256: hash };
    },
  });
  const effects = createDarwinSystemEffects(value.input, value.options);
  const prepared = await effects.prepare(
    { ...recipe, reviewSha256: hash },
    {
      signal: work.signal,
      policyBinding: binding,
      recordPolicy: () => assert.fail("No installed policy exists before park"),
    },
  );
  assert.equal(prepared.policyProof, undefined);
  assert.equal(typeof prepared.effects.readPolicy, "function");
  assert.ok(!value.events.includes("policy-read"));
  await assert.rejects(prepared.effects.verifyReceipt());
  await assert.rejects(prepared.effects.readPolicy());
});

test("Darwin access admission rejects substituted policy parameters and concrete bytes before reader setup", async () => {
  for (const change of [
    (input) => {
      input.profile = "workspace-write";
    },
    (input) => {
      input.endpoints[0].serverPort++;
    },
    (input) => {
      input.request.policy.sha256 = hash;
    },
  ]) {
    const value = wiring(),
      recipe = darwinSystemRecipes().find(
        ({ id }) => id === "access.read-only",
      ),
      { binding } = policy(value, recipe.id),
      provision = value.options.provision;
    value.options.provision = async (...args) => {
      const observed = await provision(...args);
      change(observed.input);
      return observed;
    };
    await assert.rejects(
      createDarwinSystemEffects(value.input, value.options).prepare(
        { ...recipe, reviewSha256: hash },
        { policyBinding: binding, recordPolicy() {} },
      ),
    );
    assert.ok(!value.events.includes(`start:${recipe.id}`));
    assert.ok(!value.events.includes("owner-effects"));
  }
});

test("Darwin PF composition holds inputs before setup and retains exclusion until verified baseline restoration", async () => {
  for (const outcome of ["settled", "changed-root", "context"]) {
    const value = wiring(),
      recipe = darwinSystemRecipes().find(
        ({ id }) => id === "access.read-only",
      ),
      { binding } = policy(value, recipe.id),
      work = new AbortController(),
      cleanup = new AbortController(),
      baseline = {
        active: true,
        states: 0,
        graph: [{ anchor: "", rules: [] }],
        interfaces: [{ name: "lo0", skip: true }],
        routesSha256: hash,
      },
      installed = {
        ...baseline,
        graph: [
          {
            anchor: "",
            rules: [
              {
                set: 1,
                action: 0,
                quick: true,
                state: 0,
                call: "native-poc/*",
                raw: "00",
              },
            ],
          },
        ],
        interfaces: [{ name: "lo0", skip: false }],
      },
      rootDigest = digest(
        JSON.stringify({
          active: installed.active,
          root: installed.graph[0],
          interfaces: installed.interfaces,
          routesSha256: hash,
        }),
      ),
      pfContext =
        outcome === "context"
          ? context("access.workspace-write")
          : binding.context,
      pfPreparation = {
        context: pfContext,
        approval: {
          schemaVersion: 1,
          contextSha256: digest(JSON.stringify(pfContext)),
          manifestSha256: hash,
          baselineSha256: darwinPfAuthorityDigest(baseline),
          installedRootSha256: rootDigest,
          routesSha256: hash,
          loopbackSkip: true,
        },
        tool: { index: 0, cdhash },
        install: 1,
        restore: 2,
        reservation: 3,
        nonce: "b".repeat(32),
      },
      provision = value.options.provision,
      createReader = value.options.createReader,
      ownerEffects = value.options.ownerEffects;
    let actual = structuredClone(baseline),
      reserved = false;
    value.options.provision = async (...args) => ({
      ...(await provision(...args)),
      pfPreparation,
    });
    value.options.reviewPf = async (approval) => ({
      status: "MATCHED",
      contextSha256: approval.contextSha256,
      manifestSha256: approval.manifestSha256,
    });
    value.options.createReader = (input, options) => {
      const reader = createReader(input, options);
      if (input.context.executionId === "build") return reader;
      const held = new Set();
      return {
        ...reader,
        async beginCleanup(args) {
          assert.ok(work.signal.aborted);
          await reader.beginCleanup(args);
        },
        async open(index) {
          held.add(index);
          value.events.push(`held:${index}`);
        },
        pf: async () => structuredClone(actual),
        async reserve(index) {
          assert.ok(held.has(index));
          reserved = true;
          value.events.push("pf-reserve");
        },
        reservation: async () => assert.ok(reserved),
        async writePf(tool, config, signature, operation) {
          assert.ok(
            [tool, config, 3].every((index) => held.has(index)) && reserved,
          );
          assert.equal(signature, cdhash);
          value.events.push(`pf:${operation}`);
          actual = structuredClone(
            operation === "install" ? installed : baseline,
          );
        },
        async releaseReservation(proof) {
          assert.equal(proof.pfBaselineSha256, digest(JSON.stringify(actual)));
          assert.ok(reserved);
          reserved = false;
          value.events.push("pf-release");
        },
        async close() {
          assert.ok(!reserved);
          return reader.close();
        },
      };
    };
    value.options.ownerEffects = async (...args) => {
      actual.graph.push({
        anchor: "native-poc/" + "d".repeat(32),
        rules: installed.graph[0].rules,
      });
      return ownerEffects(...args);
    };
    value.options.restore = async () => {
      assert.ok(reserved);
      actual.graph.pop();
      if (outcome === "changed-root") actual.graph[0].rules = [];
      value.events.push("policy-restore");
      return {
        status: "RESTORED",
        independent: true,
        nativeEventSha256: hash,
        reservation: {
          context: binding.context,
          nonce: pfPreparation.nonce,
          status: "RETIRED",
          independent: true,
          noLiveUid: true,
          helpersSettled: true,
          domain: { uid: 90001, gid: 90002, asid: 1 },
          verifier: identity(40),
          receiptSha256: hash,
          pfBaselineSha256: pfPreparation.approval.baselineSha256,
        },
      };
    };
    const effects = createDarwinSystemEffects(value.input, value.options),
      prepare = () =>
        effects.prepare(
          { ...recipe, reviewSha256: hash },
          {
            signal: work.signal,
            policyBinding: binding,
            recordPolicy() {},
          },
        );
    if (outcome === "context") {
      await assert.rejects(prepare());
      assert.ok(!value.events.includes("pf-reserve"));
    } else {
      const prepared = await prepare();
      work.abort();
      const result = await effects.settle(recipe, prepared, {
        signal: cleanup.signal,
        execution: execution(recipe),
      });
      assert.equal(
        settled(result).status,
        outcome === "settled" ? "RETIRED" : "RETAINED",
      );
      if (outcome === "settled") {
        for (const [a, b] of [
          ["held:3", "pf-reserve"],
          ["pf-reserve", "pf:install"],
          ["audit-release", "policy-restore"],
          ["policy-restore", "pf:restore-skip"],
          ["pf:restore-skip", "pf-release"],
          ["pf-release", `close:${recipe.id}`],
        ])
          assert.ok(value.events.indexOf(a) < value.events.indexOf(b));
      } else {
        assert.ok(reserved && !value.events.includes("pf-release"));
        assert.ok(!value.events.includes(`close:${recipe.id}`));
      }
    }
    cleanup.abort();
  }
});

test("Darwin missing policy observation and uncertain retirement retain custody for independent recovery", async () => {
  for (const failure of ["policy", "retirement"]) {
    const value = wiring(),
      recipe = darwinSystemRecipes().find(
        ({ id }) => id === "ownership.fork-exec",
      ),
      { binding, proof } = policy(value, recipe.id);
    if (failure === "policy") proof.observed.independent = false;
    const effects = createDarwinSystemEffects(value.input, value.options);
    let prepared;
    if (failure === "policy")
      await assert.rejects(
        effects.prepare(
          { ...recipe, reviewSha256: hash },
          { policyBinding: binding, recordPolicy() {} },
        ),
      );
    else
      prepared = await effects.prepare(
        { ...recipe, reviewSha256: hash },
        { policyBinding: binding, recordPolicy() {} },
      );
    value.options.retire = async () => ({ ...retired, status: "RETAINED" });
    assert.equal(
      settled(
        await effects.settle(recipe, prepared, {
          signal: new AbortController().signal,
          execution: execution(recipe),
        }),
      ).status,
      "RETAINED",
    );
    assert.ok(!value.events.includes("audit-release"));
    assert.ok(!value.events.includes("policy-restore"));
    assert.ok(!value.events.includes(`close:${recipe.id}`));
    assert.ok(
      [...value.files.keys()].some((file) =>
        file.includes(`darwin-case-${recipe.id}-`),
      ),
    );
  }
});

test("Darwin fresh recovery consumes partial immutable intents and requires every effect-class settlement", async () => {
  const value = wiring();
  value.files.clear();
  value.files.set(
    path.join(directory, "darwin-case-ownership.fork-exec-0.json"),
    {
      phase: "provisioning-possible",
      context: context("ownership.fork-exec"),
      status: "POSSIBLE",
    },
  );
  const request = {
    candidateSha,
    platform: "darwin",
    jobSha256: observationDigest(value.input.job),
    preparationSha256: observationDigest(value.preparation),
  };
  value.options.recover = async ({ records }) => {
    assert.equal(records.length, 1);
    assert.equal(records[0].record.phase, "provisioning-possible");
    return {
      ...retired,
      effects: Object.fromEntries(
        NATIVE_EFFECT_CLASSES.map((name) => [name, retired]),
      ),
    };
  };
  const effects = createDarwinSystemEffects(value.input, value.options),
    input = { request, job: value.input.job, preparation: value.preparation };
  assert.equal((await effects.recover(input)).status, "RETIRED");
  value.options.recover = async () => retired;
  assert.equal((await effects.recover(input)).status, "RETAINED");
});

test("Darwin fresh recovery rejoins case custody intents after reader admission fails", async () => {
  const value = wiring(),
    recipe = darwinSystemRecipes().find(
      ({ id }) => id === "ownership.fork-exec",
    ),
    { binding } = policy(value, recipe.id),
    createReader = value.options.createReader;
  value.options.createReader = (input, options) => {
    const reader = createReader(input, options);
    return input.context.executionId === "build"
      ? reader
      : {
          ...reader,
          async start() {
            await reader.start();
            await options.persist({
              context: input.context,
              sequence: 1,
              phase: "admitted",
              custody: "POSSIBLE",
              subjects: { helper: identity(20), verifier: identity(40) },
            });
            throw new Error("Setup acknowledgement unavailable");
          },
        };
  };
  await assert.rejects(
    createDarwinSystemEffects(value.input, value.options).prepare(
      { ...recipe, reviewSha256: hash },
      { policyBinding: binding, recordPolicy() {} },
    ),
  );
  value.options.recover = async ({ records }) => {
    const custody = records
      .filter(({ record }) => record.phase === "custody")
      .map(({ record }) => record.record);
    assert.deepEqual(
      custody.map(({ phase }) => phase),
      ["entry", "admitted"],
    );
    assert.deepEqual(custody[1].context, binding.context);
    assert.deepEqual(custody[1].subjects, {
      helper: identity(20),
      verifier: identity(40),
    });
    return {
      ...retired,
      effects: Object.fromEntries(
        NATIVE_EFFECT_CLASSES.map((name) => [name, retired]),
      ),
    };
  };
  const request = {
    candidateSha,
    platform: "darwin",
    jobSha256: observationDigest(value.input.job),
    preparationSha256: observationDigest(value.preparation),
  };
  assert.equal(
    (
      await createDarwinSystemEffects(value.input, value.options).recover({
        request,
        job: value.input.job,
        preparation: value.preparation,
      })
    ).status,
    "RETIRED",
  );
});

test("Darwin release joins version-two template observations without promoting a historical concrete hash", async () => {
  const image = Buffer.alloc(81);
  image.writeUInt32LE(0xfeedfacf, 0);
  image.writeUInt32LE(0x01000007, 4);
  image.writeUInt32LE(2, 12);
  image.writeUInt32LE(2, 16);
  image.writeUInt32LE(48, 20);
  image.writeUInt32LE(0xe, 32);
  image.writeUInt32LE(32, 36);
  image.writeUInt32LE(12, 40);
  image.write("/usr/lib/dyld\0", 44);
  image.writeUInt32LE(0x1d, 64);
  image.writeUInt32LE(16, 68);
  image.writeUInt32LE(80, 72);
  image.writeUInt32LE(1, 76);
  const manifest = {
    schemaVersion: 2,
    candidateSha,
    platform: "darwin",
    image: "macos-15-intel",
    osBuild: "fixture",
    sdkBuild: "fixture",
    policyTemplates: [hash],
    privileges: [],
    components: ["helper", "payload"].map((id) => ({
      id,
      role: id === "helper" ? "helper" : "executable",
      sha256: digest(image),
      format: "macho-x64",
      loader: [],
      bindings: {
        publication: hash,
        source: hash,
        build: hash,
        license: hash,
        abi: hash,
      },
    })),
    providers: Object.fromEntries(
      ["codex", "claude"].map((name) => [
        name,
        { reviewSha256: hash, closureSha256: hash, members: ["payload"] },
      ]),
    ),
  };
  const authority = {
    candidateSha,
    platform: "darwin",
    authority: "operator-protected",
    manifestSha256: releaseClosureDigest(manifest),
  };
  const effects = {
    openHeld: async (id) => id,
    inspectHeld: async (id) => ({
      independent: true,
      held: true,
      regular: true,
      reparse: false,
      identity: `1:2:3:${id === "helper" ? 1 : 2}:100:0:${"d".repeat(32)}`,
    }),
    readHeld: async () => image,
    loaderClosure: async () => ({
      independent: true,
      complete: true,
      ambiguous: false,
      nativeSha256: hash,
      components: [],
    }),
    buildBindings: async () => ({
      independent: true,
      complete: true,
      bindings: manifest.components[0].bindings,
    }),
    observeAuthority: async () => ({
      ...manifest,
      ownedChangesOnly: true,
      independent: true,
    }),
    inspectProvider: async (name) => ({
      ...manifest.providers[name],
      liveBindingSha256: hash,
      independent: true,
    }),
    closeHeld: async () => {},
    verifyClosed: async () => ({
      independent: true,
      closed: true,
      nativeSha256: hash,
    }),
  };
  assert.deepEqual(
    (await observeDarwinRelease(manifest, authority, effects)).closure
      .policyTemplates,
    [hash],
  );
  effects.observeAuthority = async () => ({
    ...manifest,
    policyTemplates: undefined,
    policySha256: hash,
    ownedChangesOnly: true,
    independent: true,
  });
  await assert.rejects(observeDarwinRelease(manifest, authority, effects));
});

// Native records are raw transport data. Repository owners still perform asset
// admission, persistence, command release, byte joins and fresh retirement.
function buildTranscripts(experiment = false, complete = false) {
  const f = wiring(),
    files = new Map(),
    events = [],
    processes = new Map(),
    auditRecords = new Map(),
    auditCustodies = new Map();
  let leaseHolder;
  const image = experiment ? experimentBuildFixture().image : Buffer.alloc(81);
  if (!experiment) {
    image.writeUInt32LE(0xfeedfacf, 0);
    image.writeUInt32LE(0x01000007, 4);
    image.writeUInt32LE(2, 12);
    image.writeUInt32LE(2, 16);
    image.writeUInt32LE(48, 20);
    image.writeUInt32LE(0xe, 32);
    image.writeUInt32LE(32, 36);
    image.writeUInt32LE(12, 40);
    image.write("/usr/lib/dyld\0", 44);
    image.writeUInt32LE(0x1d, 64);
    image.writeUInt32LE(16, 68);
    image.writeUInt32LE(80, 72);
    image.writeUInt32LE(1, 76);
  }
  const plan = f.manifest.darwinPreparation;
  if (experiment) {
    f.manifest.purpose = plan.purpose = "experiment";
    plan.command.sdk = { ...sdkSelection };
    plan.command.toolchain = structuredClone(toolchainSelection);
    f.manifest.environment.DEVELOPER_DIR = toolchainSelection.developer.path;
    for (const request of f.requests)
      request.env.DEVELOPER_DIR = toolchainSelection.developer.path;
    for (const name of ["experiment.h", "pf-abi.h"])
      plan.sources.push({ name, sha256: hash });
    if (!complete)
      plan.cases = plan.cases.filter(
        ({ id }) => id.startsWith("ownership.") || id.startsWith("access."),
      );
    for (const entry of [
      plan.bootstrap,
      ...plan.cases.map(({ custody }) => custody),
    ]) {
      entry.purpose = "experiment";
      entry.bindingSha256 = entry.reviewSha256;
      delete entry.reviewSha256;
      for (const name of ["experiment.h", "pf-abi.h"])
        entry.sources.push({
          path: path.dirname(entry.reader.path) + "/" + name,
          sha256: hash,
        });
      entry.reader.sha256 = digest(image);
    }
    f.input.job = initialExperimentJob({
      candidateSha,
      platform: "darwin",
      repository: "fixture/native",
      runId: "1",
      runAttempt: 1,
    });
  }
  plan.bootstrap.reader.sha256 = digest(image);
  plan.command.helper.sha256 = digest(image);
  for (const pin of f.manifest.helpers) pin.sha256 = digest(image);
  const put = (file, bytes, mode = 0o444, uid = 0) => {
    files.set(file, {
      bytes: Buffer.from(bytes),
      mode,
      uid,
      ino: files.size + 1,
      tick: 1,
    });
  };
  put(plan.bootstrap.reader.path, image, 0o555);
  put(plan.command.helper.path, image, 0o555);
  put(plan.bootstrap.plan.path, bytes, 0o400);
  for (const source of plan.bootstrap.sources) put(source.path, bytes);
  for (const source of plan.sources)
    put(path.join(sourceDirectory, source.name), bytes);
  for (const tool of [
    ...f.manifest.tools,
    ...Object.values(plan.bootstrap.tools),
  ])
    put(tool.path, bytes, 0o555);
  const directories = new Map([[directory, { uid: 1001, mode: 0o700 }]]);
  const observerFailure = new Error("Audit observer remains live");
  let nextPid = 1000,
    survivor = false,
    disconnect = false,
    changed = false,
    retainedVerifier = false,
    foreignReceipt = false,
    compilerPolicyFault = false,
    caseFault = null,
    accessSpec,
    operationFrames,
    pfInstalled = false,
    anchorInstalled = false,
    accessResources = false;
  const stat = (file, bigint = false) => {
    const entry = files.get(file),
      dir = directories.get(file),
      convert = (value) => (bigint ? BigInt(value) : value);
    return {
      uid: convert(entry?.uid ?? dir?.uid ?? 0),
      gid: convert(0),
      mode: convert(entry?.mode ?? dir?.mode ?? 0o555),
      dev: convert(1),
      ino: convert(entry?.ino ?? 900),
      nlink: convert(1),
      size: convert(entry?.bytes.length ?? 0),
      mtimeNs: convert(entry?.tick ?? 1),
      ctimeNs: convert(entry?.tick ?? 1),
      isFile: () => !!entry,
      isDirectory: () => !entry,
      isSymbolicLink: () => false,
    };
  };
  const fs = {
    realpath: async (file) => file,
    lstat: async (file, options) => stat(file, options?.bigint),
    readdir: async () =>
      [...files.keys()]
        .filter((file) => path.dirname(file) === directory)
        .map((file) => path.basename(file)),
    async open(file, flags) {
      assert.ok(flags & constants.O_NOFOLLOW);
      assert.ok(files.has(file));
      const entry = files.get(file);
      return {
        stat: async () => stat(file, true),
        async read(buffer, offset, length, position) {
          const data = entry.bytes.subarray(position, position + length);
          data.copy(buffer, offset);
          return { bytesRead: data.length };
        },
        close: async () => {
          events.push("fd-close");
        },
      };
    },
    async writeFile(file, value, settings) {
      assert.equal(settings.flag, "wx");
      assert.equal(settings.mode, 0o400);
      assert.ok(!files.has(file));
      put(file, Buffer.from(value), 0o400, 1001);
      events.push(path.basename(file));
    },
  };
  const subject = (asid = 0) => ({ ...identity(nextPid++), asid });
  const live = (id, file) =>
    processes.set(id.pid, {
      status: "live",
      identity: id,
      sha256: digest(files.get(file).bytes),
      signature: { cdhash, entitlementsSha256: hash, valid: true },
      directories: [],
    });
  const snapshot = (file, directory = false) => ({
    identity: `1:2:3:${files.get(file)?.ino ?? directories.get(file)?.ino ?? 900}:100:0:${"d".repeat(32)}`,
    bytes: directory ? 0 : files.get(file).bytes.length,
    uid: files.get(file)?.uid ?? directories.get(file)?.uid ?? 0,
    gid: files.get(file)?.gid ?? directories.get(file)?.gid ?? 0,
    mode: directory
      ? (directories.get(file)?.mode ?? 0o700)
      : (files.get(file)?.mode ?? 0o555),
    directory,
  });
  const transport = async (entry, args) => {
    const { uid = 90001, gid = 90002 } =
      plan.cases.find(({ id }) => id === entry.context.executionId)?.bindings ??
      {};
    if (["--probe", "--probe-domain"].includes(args[0])) {
      const verifier = subject(),
        pid = Number(args[1]);
      events.push("probe:" + pid);
      let enumeration;
      if (args[0] === "--probe-domain") {
        assert.equal(args[2], String(uid));
        assert.equal(args[3], String(gid));
        events.push("fresh-domain");
        enumeration = {
          uid,
          complete: true,
          asid: Number(args[4]),
          scope: Number(args[4]) ? "audit-session" : "reserved-uid",
          capacity: 33,
          zombies: [],
          live: [...processes.values()]
            .filter(
              ({ identity }) =>
                identity.uid === uid ||
                (Number(args[4]) > 0 && identity.asid === Number(args[4])),
            )
            .map(({ identity }) => identity),
        };
        if (caseFault === "fresh-members-missing") enumeration.complete = false;
      }
      return {
        receive: async () => ({
          verifier,
          subject: processes.get(pid) ?? { status: "absent" },
          ...(enumeration ? { enumeration } : {}),
        }),
        completion: Promise.resolve({ code: 0, signal: null }),
        close() {},
      };
    }
    assert.ok(
      ["--build-serve", "--case-serve", "--prepare-serve"].includes(args[0]),
    );
    const caseMode = args[0] === "--case-serve",
      planEntries = caseMode
        ? files
            .get(args[1])
            .bytes.toString()
            .trim()
            .split("\n")
            .slice(1)
            .map((line) => {
              const [kind, pin, hex] = line.split(" ");
              return { kind, pin, path: Buffer.from(hex, "hex").toString() };
            })
        : null;
    let ownershipMode,
      launcher,
      payload,
      pfHelper,
      pfWorker,
      pfOperation,
      auditObserver,
      machLogWorker,
      attemptSubject,
      attemptIndex,
      controlAttempt,
      peerSubject,
      foreignAnchor = false;
    let auditSequence = 0,
      auditTime = 0,
      auditCount = 0;
    const auditPending = [],
      packetCounts = Array(36).fill(0);
    const word = (n) => {
      const b = Buffer.alloc(4);
      b.writeUInt32BE(n);
      return b;
    };
    const pfRead = () => ({
      active: pfInstalled,
      states: 0,
      graph: [
        {
          anchor: "",
          rules: pfInstalled
            ? caseFault === "recovery-root"
              ? []
              : accessSpec.rootRules
            : [],
        },
        ...(foreignAnchor
          ? [
              {
                anchor: "native-poc/" + "f".repeat(32),
                rules: accessSpec.rootRules,
              },
            ]
          : []),
        ...(anchorInstalled
          ? [
              {
                anchor: "native-poc/" + args[3].slice(0, 32),
                rules: accessSpec.anchorRules,
              },
            ]
          : []),
      ],
      interfaces: [{ name: "lo0", skip: false }],
      routesSha256: hash,
    });
    const targetFile = (i, controlAttempt) =>
      controlAttempt && i < 13
        ? planEntries[0].path + "/outside/control-" + i
        : accessSpec.attempts[i].target;
    const socket = (identity, descriptor, endpoint) => ({
      subject: identity,
      descriptor,
      kernelId: (descriptor + 100).toString(16),
      ...endpoint,
      exclusive: true,
    });
    const attemptTarget = () => {
      const spec = accessSpec.attempts[attemptIndex];
      if (attemptIndex < 13) {
        const file = targetFile(attemptIndex, controlAttempt),
          dir = directories.has(file),
          entry = files.get(dir ? file + "/inspection" : file);
        return {
          kind: "path",
          path: file,
          value: {
            object: snapshot(file, dir),
            sha256: digest(entry.bytes),
            hex: entry.bytes.toString("hex"),
          },
        };
      }
      if (attemptIndex < 19)
        return {
          kind: "ipc",
          path: spec.target,
          value: {
            type: attemptIndex - 9,
            id:
              caseFault === "missing-ipc-identity" && attemptIndex === 13
                ? null
                : attemptIndex + 50,
            created: "100",
            authoritySha256: hash,
          },
        };
      return {
        kind: "socket",
        path: "",
        value: {
          source: socket(attemptSubject, 10, {
            family: spec.operation.includes("6") ? "inet6" : "inet",
            protocol: spec.operation.startsWith("tcp") ? "tcp" : "udp",
            address: spec.operation.includes("6") ? "::1" : "127.0.0.1",
            port: spec.local || 45000,
          }),
          target: socket(helper, attemptIndex + 20, {
            family: spec.operation.includes("6") ? "inet6" : "inet",
            protocol: spec.operation.startsWith("tcp") ? "tcp" : "udp",
            address: spec.target,
            port: spec.remote,
          }),
        },
      };
    };
    const auditTokens = (nativeCode) => {
      const spec = accessSpec.attempts[attemptIndex],
        target = attemptTarget(),
        metadata = [];
      if (target.kind === "path") {
        const token = Buffer.alloc(4 + Buffer.byteLength(target.path));
        token[0] = 0x23;
        token.writeUInt16BE(Buffer.byteLength(target.path) + 1, 1);
        token.write(target.path, 3);
        const attr = Buffer.alloc(29),
          object = target.value.object;
        attr[0] = 0x3e;
        attr.writeUInt32BE(object.mode, 1);
        attr.writeUInt32BE(object.uid, 5);
        attr.writeUInt32BE(object.gid, 9);
        attr.writeUInt32BE(1, 13);
        attr.writeBigUInt64BE(BigInt(object.identity.split(":")[3]), 17);
        metadata.push(token, attr);
      } else if (target.kind === "ipc") {
        const token = Buffer.alloc(6);
        token[0] = 0x22;
        token[1] = target.value.type;
        token.writeUInt32BE(target.value.id, 2);
        metadata.push(token);
      } else {
        const v = target.value.target,
          token = Buffer.alloc(v.family === "inet" ? 9 : 21);
        token[0] = v.family === "inet" ? 0x80 : 0x81;
        token.writeUInt16BE(v.family === "inet" ? 2 : 30, 1);
        token.writeUInt16BE(v.port, 3);
        if (v.family === "inet")
          v.address.split(".").forEach((b, i) => {
            token[5 + i] = Number(b);
          });
        else {
          const parts = v.address.split("::"),
            left = parts[0] ? parts[0].split(":") : [],
            right = parts[1] ? parts[1].split(":") : [];
          [
            ...left,
            ...Array(8 - left.length - right.length).fill("0"),
            ...right,
          ].forEach((b, i) =>
            token.writeUInt16BE(Number.parseInt(b, 16), 5 + i * 2),
          );
        }
        const fd = Buffer.alloc(11);
        fd[0] = 0x2d;
        fd[1] = 1;
        fd.writeUInt32BE(10, 2);
        fd.writeUInt16BE(3, 6);
        fd.write("fd", 8);
        metadata.push(token, fd);
      }
      const event = controlAttempt ? spec.controlEvent : spec.event;
      return {
        tokens: [
          {
            kind: "header",
            version: 11,
            event,
            name: Buffer.from(
              accessSpec.audit.mapping.events.find((v) => v.event === event)
                .opcode,
            ).toString("hex"),
            classes: 1,
            seconds: 200,
            milliseconds: ++auditTime,
          },
          {
            kind: "subject",
            pid: attemptSubject.pid,
            auid: attemptSubject.auid,
            asid: attemptSubject.asid,
            uid: attemptSubject.uid,
            gid: attemptSubject.gid,
          },
          ...metadata.map((b) => ({
            kind: "metadata",
            type: b[0],
            hex: b.toString("hex"),
          })),
          { kind: "return", result: nativeCode ? -1 : 10, error: nativeCode },
          { kind: "trailer" },
        ],
      };
    };
    const control = [],
      data = [];
    const endpoints = [],
      argsForCase = args[3];
    const helper = subject(nextPid + 10000);
    live(helper, entry.reader.path);
    const queue = [{ helper }],
      held = new Map();
    let index = 1;
    const sessions = new Set();
    let auditKey,
      reserved = false,
      fenced = false;
    return {
      receive: async () => {
        assert.ok(queue.length);
        return queue.shift();
      },
      async send(frame) {
        if (frame === "P\n") {
          if (caseMode) {
            // Native receipt custody derives the runner-owned report parent
            // from the fixed build directory; ordinary plan ancestors are root.
            const report = planEntries[11];
            assert.equal(report.kind, "directory");
            assert.equal(report.path, output);
            assert.equal(directories.get(report.path).uid, 0);
            assert.equal(directories.get(path.dirname(report.path)).uid, 1001);
          }
          queue.push({
            ...(entry.purpose === "experiment"
              ? { purpose: "experiment" }
              : {}),
            candidateSha,
            uid,
            gid,
            entries: 1,
          });
          return;
        }
        if (frame.startsWith("V ")) {
          if (foreignReceipt) throw new Error("Foreign receipt ACL");
          const [, encoded, pin] = frame.trim().split(" "),
            file = Buffer.from(encoded, "hex").toString(),
            entry = files.get(file);
          assert.equal(entry.uid, 1001);
          assert.equal(entry.mode, 0o400);
          assert.equal(digest(entry.bytes), pin);
          events.push("receipt:" + file);
          queue.push({ receipt: pin });
          return;
        }
        const [name, sequence, ...args] = frame.trim().split(" ");
        events.push(name);
        let value;
        const raw = operationFrames?.(name, args, {
          held,
          planEntries,
          helper,
          subject,
          live,
          snapshot,
          sessions,
        });
        if (raw !== undefined) value = raw;
        else if (name === "slots-closed")
          value = planEntries
            .map((_, i) => i)
            .filter((i) => !held.has(String(i)));
        else if (name === "build")
          value = {
            osBuild: Buffer.from("24A100").toString("hex"),
            macho: {
              headerSha256: hash,
              dependencies: [],
              rpaths: [],
              sdk: 1,
              minimum: 1,
              uuid: "d".repeat(32),
            },
          };
        else if (name === "signature")
          value = { cdhash, entitlementsSha256: hash, valid: true };
        else if (name === "location")
          value = {
            hex: Buffer.from(planEntries[Number(args[0])].path).toString("hex"),
          };
        else if (name === "pf-read")
          value = experiment ? stockPfFixture(pfRead()) : pfRead();
        else if (name === "pf-recover") {
          const reference = files.get(planEntries[1].path + "/pf-reference");
          assert.ok(
            reference &&
              reference.uid === 0 &&
              reference.mode === 0o400 &&
              reference.bytes.equals(Buffer.from(argsForCase + " 17\n")),
          );
          value = { held: true };
        } else if (name === "pf-write") {
          assert.ok(accessSpec);
          assert.equal(Number(args[0]), accessSpec.pf.tool.index);
          pfInstalled = args[3] === "install";
          if (pfInstalled)
            put(
              planEntries[1].path + "/pf-reference",
              Buffer.from(argsForCase + " 17\n"),
              0o400,
            );
          if (caseFault === "pf-install-interrupted")
            throw new Error("PF installation acknowledgement lost");
          value = { pid: nextPid++, settled: true };
        } else if (name === "reservation") value = { held: true };
        else if (name === "reservation-close") {
          assert.equal(pfInstalled, false);
          events.push("access-lease-released");
          value = null;
        } else if (name === "socket") {
          const endpoint = endpoints[Number(args[1]) - 100];
          value = socket(
            processes.get(Number(args[0])).identity,
            Number(args[1]),
            {
              ...endpoint,
              address: endpoint.family === "inet" ? "127.0.0.1" : "::1",
            },
          );
        } else if (name === "bsm") {
          value = auditRecords.get(args[0]);
          assert.ok(value);
        } else if (name === "access-sockets")
          value = endpoints.map((_, i) => ({
            subject: helper,
            descriptor: 100 + i,
          }));
        else if (name === "access-payload-sockets") value = { held: 8 };
        else if (name === "access-pf-start") {
          pfOperation = args[3];
          pfHelper = subject(nextPid + 100);
          live(pfHelper, planEntries[4].path);
          value = { helper: pfHelper };
        } else if (name === "access-pf-worker") {
          pfWorker = subject(pfHelper.asid);
          live(pfWorker, planEntries[4].path);
          value = { worker: pfWorker };
        } else if (name === "access-pf-run") {
          if (pfOperation === "install") anchorInstalled = true;
          if (pfOperation === "restore") anchorInstalled = false;
          if (
            caseFault === "anchor-install-interrupted" &&
            pfOperation === "install"
          )
            throw new Error("Anchor installation acknowledgement lost");
          processes.delete(pfHelper.pid);
          processes.delete(pfWorker.pid);
          value = { exitCode: 0, signal: null };
        } else if (name === "access-audit-start") {
          auditObserver = subject(helper.asid);
          live(auditObserver, planEntries[Number(args[0])].path);
          value = { identity: auditObserver };
        } else if (name === "access-audit") {
          let bytes;
          if (args[0] === "A") bytes = word(0);
          else if (args[0] === "S")
            bytes = Buffer.concat([
              word(0xffffffff),
              word(auditCount * 18),
              word(auditCount),
            ]);
          else
            bytes = Buffer.concat([
              ...auditPending.splice(0),
              word(0xfffffffe),
              word(++auditSequence),
              word(200),
              word(++auditTime),
            ]);
          value = { hex: bytes.toString("hex") };
        } else if (name === "access-audit-close") {
          if (caseFault === "observer-survives") throw observerFailure;
          processes.delete(auditObserver.pid);
          auditObserver = null;
          value = { code: 0, signal: null };
        } else if (name === "access-provision") {
          accessResources = true;
          for (let i = 0; i < 13; i++) {
            const file = accessSpec.attempts[i].target;
            if (!files.has(file) && !directories.has(file))
              put(file, Buffer.from(argsForCase.slice(0, 32)), 0o600, uid);
            if (i === 6) {
              const control = targetFile(i, true);
              directories.set(control, {
                uid,
                gid,
                mode: 0o700,
                ino: directories.size + 950,
              });
              put(
                control + "/inspection",
                Buffer.from(argsForCase.slice(0, 32)),
                0o600,
                uid,
              );
            } else if (i >= 2)
              put(
                targetFile(i, true),
                Buffer.from(argsForCase.slice(0, 32)),
                0o600,
                uid,
              );
          }
          value = null;
        } else if (name === "access-attempt") {
          controlAttempt = args[0] === "1";
          attemptIndex = Number(args[1]);
          if (caseFault === "control-unavailable" && controlAttempt)
            throw new Error("Outside control unavailable");
          peerSubject = null;
          attemptSubject = controlAttempt
            ? subject()
            : { ...payload, pid: nextPid++, startMicroseconds: nextPid };
          live(attemptSubject, planEntries[5].path);
          value = { identity: attemptSubject };
          if (attemptIndex >= 35 && !controlAttempt) {
            peerSubject = {
              ...attemptSubject,
              pid: nextPid++,
              startMicroseconds: nextPid,
            };
            live(peerSubject, planEntries[5].path);
          }
        } else if (name === "access-peer")
          value = {
            identity: peerSubject,
            socket: { ...attemptTarget().value.target, subject: peerSubject },
          };
        else if (name === "access-target") value = attemptTarget();
        else if (name === "access-mach-log-start") {
          machLogWorker = subject(helper.asid);
          live(machLogWorker, planEntries[Number(args[0])].path);
          value = machLogWorker;
        } else if (name === "access-mach-log-run") {
          assert.ok(processes.has(attemptSubject.pid));
          const event = {
            timestamp: "2026-01-01T00:00:00.000150Z",
            processID: 0,
            processImagePath: "/kernel",
            senderImagePath:
              "/System/Library/Extensions/Sandbox.kext/Contents/MacOS/Sandbox",
            eventMessage: `Sandbox: access-fixture(${attemptSubject.pid}) deny(1) mach-lookup ${accessSpec.attempts[13].target}`,
          };
          value = {
            hex: Buffer.from(JSON.stringify(event) + "\n").toString("hex"),
            exitCode: 0,
            signal: null,
          };
          processes.delete(machLogWorker.pid);
        } else if (name === "access-run") {
          let nativeCode =
            controlAttempt ||
            attemptIndex === 0 ||
            attemptIndex >= 35 ||
            (attemptIndex === 1 && accessSpec.profile !== "read-only")
              ? 0
              : 1;
          if (
            caseFault === "unknown-error" &&
            !controlAttempt &&
            attemptIndex === 2
          )
            nativeCode = 2;
          if (
            caseFault === "tcp-deadline" &&
            !controlAttempt &&
            attemptIndex === 19
          )
            nativeCode = 60;
          const spec = accessSpec.attempts[attemptIndex];
          const mach = experiment && spec.operation === "mach";
          if (mach && controlAttempt && caseFault === "mach-control-timeout")
            throw new Error("Native receipt deadline");
          if (mach && !controlAttempt) nativeCode = 1100;
          if (!nativeCode && spec.operation === "write")
            files.get(targetFile(attemptIndex, controlAttempt)).bytes =
              Buffer.from(argsForCase.slice(0, 32) + "-edit");
          if (attemptIndex >= 35 && !controlAttempt)
            for (let i = 0; i < 4; i++)
              if (caseFault !== "missing-counter-leg" || i !== 2)
                packetCounts[(attemptIndex - 35) * 8 + i]++;
          if (!mach) {
            const raw = Buffer.alloc(18);
            raw.writeUInt32BE(++auditCount);
            auditRecords.set(raw.toString("hex"), auditTokens(nativeCode));
            if (!(
              caseFault === "audit-event-loss" &&
              !controlAttempt &&
              attemptIndex === 2
            ))
              auditPending.push(word(raw.length), raw);
          }
          if (
            caseFault === "stale-attempt" &&
            !controlAttempt &&
            attemptIndex === 2
          )
            processes.get(attemptSubject.pid).identity = {
              ...attemptSubject,
              pidVersion: 9,
            };
          if (
            !controlAttempt &&
            attemptIndex === 2 &&
            caseFault === "foreign-anchor"
          )
            foreignAnchor = true;
          if (
            !controlAttempt &&
            attemptIndex === 2 &&
            caseFault === "outside-state"
          )
            files.get(accessSpec.attempts[2].target).bytes = Buffer.from(
              "substituted sentinel",
            );
          value = {
            nonce: argsForCase.slice(0, 32),
            result: nativeCode ? -1 : 0,
            nativeCode,
          };
          if (mach)
            Object.assign(value, {
              lookupCode: nativeCode,
              sendCode: controlAttempt ? 0 : null,
              mach: {
                source: "custody-mach-v1",
                startedAt: "2026-01-01T00:00:00.000100Z",
                endedAt: "2026-01-01T00:00:00.000200Z",
                before: attemptSubject,
                after: attemptSubject,
                receipt: controlAttempt
                  ? {
                      nonce: value.nonce,
                      service: spec.target,
                      sender: attemptSubject,
                      auditToken: [
                        "auid",
                        "uid",
                        "gid",
                        "ruid",
                        "rgid",
                        "pid",
                        "asid",
                        "pidVersion",
                      ].map((key) => attemptSubject[key]),
                    }
                  : null,
              },
            });
        } else if (name === "access-complete") {
          processes.delete(attemptSubject.pid);
          if (peerSubject) processes.delete(peerSubject.pid);
          value = null;
        } else if (name === "access-counters")
          value = packetCounts.map((packets, index) => ({
            ...(experiment
              ? {
                  purpose: "experiment",
                  anchor: "native-poc/" + argsForCase.slice(0, 32),
                  set: 1,
                  ticket: 1,
                  ruleTicket: "1",
                }
              : {}),
            index,
            packets: String(packets),
            ruleSha256: digest(
              Buffer.from(accessSpec.anchorRules[index].raw, "hex"),
            ),
            action:
              accessSpec.anchorRules[index].action === 0 ? "permit" : "deny",
          }));
        else if (name === "access-controls-retired") {
          assert.equal(accessResources, false);
          value = { absent: caseFault !== "mach-service-survives" };
        } else if (name === "access-controls-close") {
          assert.equal(auditObserver, null);
          accessResources = false;
          if (caseFault === "after-controls-close")
            throw new Error("Lost controls result");
          value = null;
        } else if (name === "case-start") {
          assert.ok(caseMode);
          ownershipMode = args[0];
          assert.ok(
            [
              "literal",
              "storage",
              "access",
              ...DARWIN_OWNERSHIP_CASES,
            ].includes(ownershipMode),
          );
          assert.equal(args[1], cdhash);
          launcher = subject();
          live(launcher, planEntries[4].path);
          control.push({ helper: launcher, payload: null });
          value = { pid: launcher.pid };
        } else if (name === "case-control") {
          assert.ok(control.length);
          value = control.shift();
        } else if (name === "case-eof") {
          assert.equal(data.length, 0);
          value = { complete: true };
        } else if (name === "authority") {
          const i = Number(args[1]);
          value = {
            subject: processes.get(Number(args[0])).identity,
            sandboxed: true,
            path: Buffer.from(planEntries[i].path).toString("hex"),
            object: held.get(args[1]).object,
            aclSha256: hash,
            decisions: accessSpec
              ? accessSpec.objects.find((v) => v.index === i).decisions
              : [
                  i === 3 || i === 5 ? 0 : 1,
                  i === 3 ? 0 : 1,
                  i === 3 ? 0 : 1,
                  i === 3 ? 0 : 1,
                  i === 5 ? 0 : 1,
                ],
          };
        } else if (name === "case-output") {
          assert.ok(data.length);
          value = { hex: Buffer.from(data.shift()).toString("hex") };
        } else if (name === "case-send") {
          const event = (phase, pid, count) =>
            JSON.stringify({
              nonce: argsForCase.slice(0, 32),
              phase,
              pid,
              count,
            }) + "\n";
          if (args[0] === "0" && args[1] === "P") {
            if (caseFault === "before-park")
              throw new Error("Interrupted before parked payload creation");
            payload = {
              ...subject(nextPid + 200),
              uid,
              ruid: uid,
              svuid: uid,
              gid,
              rgid: gid,
              svgid: gid,
              auid: uid,
            };
            live(payload, planEntries[5].path);
            control.push({ helper: launcher, payload, controls: true });
          } else if (args[0] === "0" && args[1] === "R") {
            payload = { ...payload, pidVersion: 2 };
            live(payload, planEntries[5].path);
            data.push(
              ["literal", "storage", "access"].includes(ownershipMode)
                ? '{"phase":"armed"}\n'
                : event("armed", payload.pid, 0),
            );
          } else if (args[0] === "1" && args[1] === "A") {
            if (["literal", "storage"].includes(ownershipMode)) {
              data.push(JSON.stringify(DARWIN_LITERAL_ARGUMENTS) + "\n");
              control.push({ exitCode: 0, signal: null });
              processes.delete(payload.pid);
            } else {
              const count = ownershipMode === "process-limit" ? 31 : 1;
              for (let i = 0; i < count; i++) {
                const leaf =
                  ownershipMode === "stale-identity"
                    ? { ...payload, pidVersion: 3 }
                    : {
                        ...payload,
                        pid: nextPid++,
                        startMicroseconds: nextPid,
                        pidVersion: 2,
                      };
                live(leaf, planEntries[5].path);
                const file = planEntries[3].path + "/nonce-" + leaf.pid;
                put(file, Buffer.from(argsForCase.slice(0, 32)), 0o600, uid);
                files.get(file).gid = gid;
                data.push(event("leaf", leaf.pid, 1));
              }
              if (ownershipMode !== "stale-identity")
                data.push(
                  event(
                    ownershipMode === "process-limit" ? "limit" : "parent",
                    payload.pid,
                    count,
                  ),
                );
              if (caseFault === "outside")
                files.get(planEntries[6].path).bytes =
                  Buffer.from("substituted policy");
            }
          } else if (args[0] === "1" && args[1] === "B")
            data.push(event("fault-armed", payload.pid, 0));
          else if (args[0] === "1" && args[1] === "C") {
            if (ownershipMode === "reparent") {
              processes.delete(payload.pid);
              control.push({ exitCode: 0, signal: null });
            }
          } else assert.fail("Unexpected ownership barrier");
          value = null;
        } else if (name === "process" || name === "session") {
          value = processes.get(Number(args[0])).identity;
          if (name === "session") sessions.add(value.asid);
        } else if (name === "case-fence") {
          fenced = true;
          value = { closed: true };
        } else if (name === "case-session" || name === "case-session-read") {
          assert.ok(held.has("1") && held.has("4"));
          assert.ok(name === "case-session" ? reserved && !fenced : fenced);
          const keys = [
            "auid",
            "uid",
            "gid",
            "ruid",
            "rgid",
            "pid",
            "asid",
            "pidVersion",
            "startSeconds",
            "startMicroseconds",
            "svuid",
            "svgid",
          ];
          const subject = Object.fromEntries(
              keys.map((key, i) => [key, Number(args[i])]),
            ),
            source = Object.fromEntries(
              keys.map((key, i) => [key, Number(args[i + 12])]),
            );
          const file = planEntries[1].path + "/audit-custody";
          const key = file + ":" + subject.asid;
          if (name === "case-session") {
            assert.ok(!auditCustodies.has(key));
            assert.ok(
              [...auditCustodies].every(
                ([name, record]) =>
                  !name.startsWith(file + ":") || record.closed,
              ),
            );
            const custodian = {
              ...identity(nextPid++),
              asid: 500000 + nextPid,
            };
            live(custodian, planEntries[4].path);
            auditCustodies.set(
              key,
              structuredClone({
                asid: subject.asid,
                held: true,
                closed: false,
                owner: helper,
                subject,
                source,
                custodian,
              }),
            );
            put(
              file,
              Buffer.from(
                JSON.stringify(
                  [...auditCustodies]
                    .filter(([name]) => name.startsWith(file + ":"))
                    .map(([, record]) => record),
                ),
              ),
              0o400,
            );
            if (caseFault === "session-publication")
              throw new Error("Interrupted audit custody publication");
          }
          auditKey = key;
          const original = auditCustodies.get(key);
          assert.ok(original);
          assert.equal(original.subject.pid, subject.pid);
          assert.equal(
            original.subject.startMicroseconds,
            subject.startMicroseconds,
          );
          if (!original.closed) {
            const actual = processes.get(original.custodian.pid)?.identity;
            if (actual) assert.deepEqual(actual, original.custodian);
            else
              assert.ok(
                [subject, original.source].some((identity) => {
                  const live = processes.get(identity.pid)?.identity;
                  return live && sameDarwinIdentity(live, identity);
                }),
              );
          } else assert.ok(!processes.has(original.custodian.pid));
          if (!original.closed) sessions.add(subject.asid);
          value = { ...original, owner: helper };
        } else if (name === "case-session-close") {
          const original = auditCustodies.get(auditKey);
          assert.ok(!processes.has(original.custodian.pid));
          original.closed = true;
          original.held = false;
          value = { closed: true };
        } else if (
          name === "case-receipt" ||
          name === "case-receipt-read" ||
          name === "case-receipt-optional"
        ) {
          const file = planEntries[1].path + "/receipt-" + args[0] + ".json";
          if (name === "case-receipt") {
            assert.ok(!files.has(file));
            put(file, Buffer.from(args[2], "hex"), 0o400);
          }
          if (name === "case-receipt-optional" && !files.has(file))
            value = null;
          else {
            assert.equal(digest(files.get(file).bytes), args[1]);
            value = { hex: files.get(file).bytes.toString("hex") };
          }
        } else if (name === "case-subject") {
          if (caseFault === "subject-missing")
            throw new Error("Payload observation unavailable");
          const id = processes.get(Number(args[0])).identity;
          value = {
            identity: id,
            imageSha256: digest(files.get(planEntries[5].path).bytes),
            cwd: {
              dev: "1",
              ino: String(directories.get(planEntries[3].path).ino),
            },
            sandboxed: true,
            decisions: [1, 1, 1, 0, 1, 1, 1],
          };
          if (caseFault === "subject-authority") value.decisions[1] = 0;
        } else if (name === "case-members") {
          if (caseFault === "members-missing")
            throw new Error("Domain census unavailable");
          value = {
            uid,
            asid: Number(args[0]),
            scope: Number(args[0]) ? "audit-session" : "reserved-uid",
            complete: true,
            capacity: 33,
            zombies: [],
            live: [...processes.values()]
              .filter(({ identity }) => identity.asid === Number(args[0]))
              .map(({ identity }) => identity),
          };
          if (caseFault === "unknown-zombie") {
            const { pidVersion, auid, asid, ...dead } = {
              ...value.live[0],
              pid: 7654,
            };
            value.zombies.push(dead);
          }
        } else if (name === "case-empty") {
          assert.ok(
            [...processes.values()].every(
              ({ identity }) => identity.uid !== uid,
            ),
          );
          value = { uid, noLiveUid: true };
        } else if (name === "case-signal") {
          const keys = [
              "auid",
              "uid",
              "gid",
              "ruid",
              "rgid",
              "pid",
              "asid",
              "pidVersion",
              "startSeconds",
              "startMicroseconds",
              "svuid",
              "svgid",
            ],
            target = Object.fromEntries(
              keys.map((key, i) => [key, Number(args[i])]),
            ),
            actual = processes.get(target.pid)?.identity;
          const outcome = !actual
            ? "not-found"
            : !keys.every((key) => actual[key] === target[key])
              ? "stale"
              : "sent";
          if (outcome === "sent") processes.delete(target.pid);
          value = { identity: target, outcome };
          if (caseFault === "stale-accepted" && outcome === "stale")
            value.outcome = "sent";
        } else if (name === "tree") {
          const base = held.get(args[0]).file + "/";
          value = [...files]
            .filter(([file]) => file.startsWith(base))
            .map(([file, entry]) => ({
              name: Buffer.from(file.slice(base.length)).toString("hex"),
              file: { object: snapshot(file), sha256: digest(entry.bytes) },
            }));
        } else if (name === "barrier") {
          const file =
            held.get(args[0]).file +
            "/" +
            Buffer.from(args[1], "hex").toString();
          value = {
            object: snapshot(file),
            sha256: digest(files.get(file).bytes),
            hex: files.get(file).bytes.toString("hex"),
          };
        } else if (name === "compiler-policy") {
          value = {
            identity: processes.get(Number(args[0])).identity,
            uid: 0,
            gid: 0,
            ruid: 0,
            rgid: 0,
            sandboxed: false,
            descriptors: [
              { fd: 0, type: "vnode" },
              { fd: 1, type: "pipe" },
              { fd: 2, type: "pipe" },
            ],
          };
          if (compilerPolicyFault)
            value.descriptors.push({ fd: 3, type: "socket" });
        } else if (name === "open") {
          const file = planEntries[Number(args[0])].path;
          value = snapshot(file, directories.has(file));
          held.set(args[0], {
            file,
            data: files.get(file)?.bytes,
            object: value,
          });
        } else if (name === "reserve") {
          assert.ok(
            !leaseHolder ||
              !processes.has(leaseHolder) ||
              leaseHolder === helper.pid,
          );
          reserved = true;
          leaseHolder = helper.pid;
          value = held.get(args[0]).object;
        } else if (name === "case-directory") {
          const i = Number(args[0]),
            file = planEntries[i].path;
          assert.ok(!directories.has(file));
          directories.set(file, {
            uid: i === 3 ? uid : 0,
            gid: i === 1 || file.endsWith("/custody/files") ? 0 : gid,
            mode: file.endsWith("/custody/files")
              ? 0o700
              : i === 0 || i === 2 || i >= 12
                ? 0o710
                : 0o700,
            ino: directories.size + 950,
          });
          value = snapshot(file, true);
          held.set(args[0], { file, object: value });
        } else if (name === "case-rejoin") {
          assert.ok(
            reserved || (fenced && [0, 1, 4, 5].includes(Number(args[0]))),
          );
          const file = planEntries[Number(args[0])].path;
          value = snapshot(file, directories.has(file));
          held.set(args[0], {
            file,
            data: files.get(file)?.bytes,
            object: value,
          });
        } else if (name === "case-copy") {
          if (caseFault === "writer")
            throw new Error("Case writer interrupted");
          const i = Number(args[0]),
            file = planEntries[i].path;
          put(
            file,
            files.get(planEntries[Number(args[1])].path).bytes,
            planEntries[i].kind === "data" ? 0o400 : 0o550,
          );
          files.get(file).gid = file.startsWith(planEntries[2].path + "/")
            ? gid
            : 0;
          if (
            i >= 12 &&
            planEntries[i].kind === "data" &&
            /\/storage\/(?:metadata|control|work|control-work)\//u.test(file)
          ) {
            const work = /\/storage\/(?:work|control-work)\//u.test(file);
            Object.assign(files.get(file), {
              uid: work ? uid : 0,
              gid,
              mode: work ? 0o400 : 0o440,
            });
          }
          value = snapshot(file);
          held.set(args[0], {
            file,
            data: files.get(file)?.bytes,
            object: value,
          });
        } else if (name === "case-endpoint") {
          endpoints.push({
            family: args[0] === "4" ? "inet" : "inet6",
            protocol: args[1] === "6" ? "tcp" : "udp",
            port: Number(args[2]),
          });
          value = null;
        } else if (name === "case-read") {
          if (caseFault === "missing") throw new Error("Case read unavailable");
          value = {
            contextSha256:
              caseFault === "context" ? "f".repeat(64) : argsForCase,
            uid: caseFault === "identity" ? uid + 2 : uid,
            gid,
            accountVerified: true,
            accounts: { uidAccounts: 1, primaryGroupMembers: 1, gidGroups: 1 },
            objects: [...held]
              .filter(
                ([i]) =>
                  Number(i) < 7 ||
                  (accessSpec &&
                    planEntries[Number(i)].path.startsWith(
                      planEntries[0].path + "/",
                    )),
              )
              .map(([index, { object }]) => ({ index: Number(index), object }))
              .sort((a, b) => a.index - b.index),
            endpoints,
          };
          if (caseFault === "authority") value.extraAuthority = true;
          if (caseFault === "account") value.accountVerified = false;
          if (caseFault === "uid-alias") value.accounts.uidAccounts = 2;
          if (caseFault === "primary-group")
            value.accounts.primaryGroupMembers = 2;
          if (caseFault === "gid-alias") value.accounts.gidGroups = 2;
          if (caseFault === "endpoint")
            value.endpoints = [
              ...endpoints,
              { family: "inet", protocol: "tcp", port: 42000 },
            ];
        } else if (name === "case-retire") {
          if (caseFault === "survivor")
            throw new Error("Reserved UID remains live");
          endpoints.length = 0;
          value = { noLiveUid: true, closed: true };
        } else if (name === "build-directory") {
          const file = Buffer.from(args[0], "hex").toString();
          assert.equal(file, output);
          assert.ok(
            events.some((name) =>
              /^darwin-command-.*-intent\.json$/u.test(name),
            ),
          );
          directories.set(output, {
            uid: 0,
            mode: 0o700,
            ino: directories.get(output)?.ino ?? 900,
          });
          value = snapshot(output, true);
        } else if (name === "build-root") {
          assert.equal(Buffer.from(args[0], "hex").toString(), output);
          value = snapshot(output, true);
        } else if (name === "build-open") {
          const file = Buffer.from(args[0], "hex").toString(),
            data = Buffer.from(files.get(file).bytes);
          value = {
            index: index++,
            object: snapshot(file),
            root: snapshot(output, true),
            sha256: digest(data),
          };
          held.set(String(value.index), { file, data, object: value.object });
          if (args[1] !== "-") assert.equal(args[1], value.sha256);
          events.push("snapshot:" + file);
        } else if (name === "read") {
          value = {
            hex: held
              .get(args[0])
              .data.subarray(Number(args[1]), Number(args[1]) + Number(args[2]))
              .toString("hex"),
          };
        } else if (name === "inspect") value = held.get(args[0]).object;
        else if (name === "close") {
          held.delete(args[0]);
          value = null;
        } else if (name === "root-domain" || name === "root-retired") {
          const pid = Number(args[0]),
            asid = Number(args[1]),
            members = [...processes.values()]
              .filter((value) => value.identity.asid === asid)
              .map((value) => value.identity);
          const id = processes.get(pid)?.identity ?? { ...identity(pid), asid };
          if (name === "root-domain") sessions.add(asid);
          value = { helper: id, complete: true, members };
        } else if (name === "finish") {
          if (
            [...processes.values()].some((entry) =>
              sessions.has(entry.identity.asid),
            )
          )
            throw new Error("Root session retained");
          processes.delete(helper.pid);
          value = { closed: true };
        } else throw new Error("Unexpected native operation: " + name);
        queue.push({ sequence: Number(sequence), value });
      },
      completion: Promise.resolve({ code: 0, signal: null }),
      close() {
        processes.delete(helper.pid);
      },
    };
  };
  const open = async (entry, args, deadlineMs) => {
    assert.ok(deadlineMs > 0 && deadlineMs <= 30000);
    events.push("tool:" + args[0]);
    if (args[0] === "sign") {
      const target = args[8];
      if (changed) put(target, Buffer.from("changed intermediate"), 0o555);
      if (digest(files.get(target).bytes) !== args[7])
        throw new Error("Intermediate changed before signing");
    }
    const helper = subject(nextPid + 100),
      worker = subject(helper.asid);
    live(helper, entry.helper.path);
    processes.get(helper.pid).directories = [
      {
        fd: 3,
        dev: "1",
        ino: String(directories.get(output).ino),
        uid: 0,
        gid: 0,
        mode: 0o700,
      },
    ];
    const queue = [{ helper }];
    const channel = {
      receive: async () => {
        if (disconnect && queue[0]?.worker)
          throw new Error("Worker acknowledgement lost");
        assert.ok(queue.length);
        return queue.shift();
      },
      async send(frame) {
        events.push("command:" + frame);
        if (frame === "P") {
          live(worker, args[1]);
          queue.push({ worker });
        } else if (frame === "R") {
          processes.delete(worker.pid);
          if (survivor) live(subject(helper.asid), entry.helper.path);
          queue.push({
            exitCode: 0,
            signal: null,
            stdoutHex: Buffer.from("reviewed\n").toString("hex"),
            stderrHex: "",
          });
        } else if (frame === "S") {
          if (args[0] === "compile")
            put(args[8], Buffer.from("unsigned intermediate"), 0o555);
          if (args[0] === "sign") put(args[8], image, 0o555);
          directories.set(output, {
            uid: 0,
            mode: 0o555,
            ino: directories.get(output)?.ino ?? 900,
          });
          processes.delete(helper.pid);
        } else throw new Error("Unexpected build barrier");
      },
      completion: Promise.resolve({ code: 0, signal: null }),
      close() {
        processes.delete(helper.pid);
        if (!survivor) processes.delete(worker.pid);
      },
    };
    return { channel };
  };
  const options = {
    fs,
    env: f.options.env,
    ownerUid: () => 1001,
    readerOptions: {
      fs,
      transport,
      kill(pid, signal) {
        assert.equal(signal, 0);
        if (retainedVerifier) return true;
        if (processes.has(pid)) return true;
        throw Object.assign(new Error("Absent kernel PID"), { code: "ESRCH" });
      },
      runtime: { platform: "darwin", arch: "x64", env: f.options.env },
    },
    commandTransport: { open },
    now: () => 0,
  };
  f.input.preparation = undefined;
  if (experiment) {
    f.input.preparation = {
      purpose: "experiment",
      build: { helpers: f.manifest.helpers },
    };
    options.loadExperimentBuild = async () => {
      events.push("experiment-build-read");
      return { ...f.input.preparation, readSha256: hash };
    };
    directories.set(output, { uid: 0, mode: 0o555, ino: 900 });
    for (const helper of f.manifest.helpers)
      put(path.join(output, helper.name), image, 0o555);
  }
  const prepared = () => ({
    schemaVersion: 1,
    status: "PASS",
    candidateSha,
    platform: "darwin",
    reviewSha256: observationDigest(f.manifest),
    helpers: f.manifest.helpers.map(({ name, sha256 }) => ({ name, sha256 })),
    versions: f.manifest.tools.map(({ name, version, sha256 }) => ({
      name,
      version,
      sha256,
    })),
    commands: f.requests.map((request) => {
      const id = observationDigest(request),
        record = JSON.parse(
          files.get(path.join(directory, `darwin-command-${id}-result.json`))
            .bytes,
        );
      return {
        requestSha256: id,
        status: "RETIRED",
        receiptSha256: observationDigest(record),
      };
    }),
  });
  return {
    ...f,
    options,
    files,
    events,
    processes,
    auditCustodies,
    directories,
    observerFailure,
    prepared,
    survive: () => {
      survivor = true;
    },
    disconnect: () => {
      disconnect = true;
    },
    change: () => {
      changed = true;
    },
    retainVerifier: () => {
      retainedVerifier = true;
    },
    compilerPolicyFault: () => {
      compilerPolicyFault = true;
    },
    caseFault: (value) => {
      caseFault = value;
    },
    access: (value) => {
      accessSpec = value;
    },
    image,
    put,
    operationFrames: (value) => {
      operationFrames = value;
    },
    foreignReceipt: () => {
      foreignReceipt = true;
    },
  };
}

test("fixed provider helper preparation rejoins Darwin ACL custody and helpers without compiling", async () => {
  // The raw transport cannot prove native command reachability. Inspect this
  // read-only guard too; a build-only guard would reject every fresh rejoin.
  const source = await readFile(
      new URL("./custody-reader.c", import.meta.url),
      "utf8",
    ),
    modes =
      /!strcmp\(tokens\[0\], "root-retired"\)[^{]+\{\s*need\(\(([^)]+)\) && n == 7\)/u
        .exec(source)?.[1]
        .split(/\s*\|\|\s*/u);
  assert.ok(
    modes?.includes("preparation_mode"),
    "Native retirement must admit provider preparation",
  );
  for (const fault of [
    null,
    "acl",
    "source",
    "tool-write",
    "output-write",
    "retirement",
    "recovery",
    "missing-birth",
  ]) {
    const f = buildTranscripts(),
      provider = providerPreparationFixture("darwin"),
      input = provider.input;
    delete input.api;
    input.buildManifest = f.manifest;
    for (const tool of f.manifest.tools) f.files.get(tool.path).mode = 0o755;
    input.manifest.providerPreparation.sourceDirectory = sourceDirectory;
    input.manifest.providerPreparation.bootstrap = {
      ...f.manifest.darwinPreparation.bootstrap,
      context: input.manifest.providerPreparation.bootstrap.context,
    };
    for (const member of input.manifest.inputs)
      f.put(member.path, provider.files.get(member.path));
    f.directories.set(output, { uid: 0, mode: 0o555, ino: 900 });
    for (const helper of f.manifest.helpers)
      f.put(path.join(output, helper.name), f.image, 0o555);
    const base = f.options.fs,
      fs = {
        ...base,
        async open(file, flags, mode) {
          if (flags & constants.O_CREAT) {
            assert.ok(flags & constants.O_EXCL);
            assert.equal(mode, 0o600);
            assert.ok(!f.files.has(file));
            f.put(file, Buffer.alloc(0), mode, 1001);
          }
          const entry = f.files.get(file);
          return {
            stat: () => base.lstat(file, { bigint: true }),
            async read(buffer, offset, count, position) {
              const bytes = entry.bytes.subarray(position, position + count);
              bytes.copy(buffer, offset);
              return { bytesRead: bytes.length };
            },
            async writeFile(bytes) {
              entry.bytes = Buffer.from(bytes);
              entry.tick++;
            },
            async chmod(mode) {
              entry.mode = mode;
              entry.tick++;
            },
            sync: async () => {},
            close: async () => {},
          };
        },
      };
    let damaged = false;
    f.operationFrames((name, args) => {
      if (name !== "prepare-observe") return undefined;
      const file = Buffer.from(args[0], "hex").toString(),
        directory = args[2] === "1",
        entry = f.files.get(file),
        dir = f.directories.get(file);
      if (damaged && fault === "acl") throw new Error("Native ACL changed");
      const object = {
        identity: `1:2:3:${entry?.ino ?? dir?.ino ?? 900}:100:0:${"d".repeat(32)}`,
        bytes: directory ? 0 : entry.bytes.length,
        uid: entry?.uid ?? dir?.uid ?? 0,
        gid: 0,
        mode: entry?.mode ?? dir?.mode ?? 0o555,
        directory,
      };
      if (!directory) assert.equal(digest(entry.bytes), args[1]);
      return {
        object,
        sha256: directory ? null : args[1],
        protectedParents: true,
      };
    });
    const options = {
        ...f.options,
        fs,
        ownerUid: 1001,
        readerOptions: { ...f.options.readerOptions, fs },
      },
      request = {
        candidateSha,
        platform: "darwin",
        reviewSha256: observationDigest(input.manifest),
        helpers: [],
        tools: input.buildManifest.tools,
        output: input.providerHelpers,
        deadlineMs: 120000,
        commands: [],
      },
      owner = fixedProviderEffects(input, options);
    assert.equal(f.events.length, 0);
    const receipt = await owner.prepareBuild(request);
    input.preparation = {
      status: "PASS",
      request,
      requestSha256: observationDigest(request),
      receiptSha256: observationDigest(receipt),
      filesSettlement: await owner.settleBuild(),
    };
    if (["recovery", "missing-birth"].includes(fault)) {
      for (const helper of f.manifest.helpers)
        f.files.delete(path.join(output, helper.name));
      f.files.delete(
        path.join(
          directory,
          `provider-build-${observationDigest(request)}-result.json`,
        ),
      );
      if (fault === "missing-birth")
        for (const [file, entry] of f.files)
          if (
            /provider-bootstrap-0-custody-/u.test(file) &&
            JSON.parse(entry.bytes).phase === "admitted"
          )
            f.files.delete(file);
      const preparation = { status: "POSSIBLE" },
        recovery = {
          candidateSha,
          platform: "darwin",
          jobSha256: observationDigest(input.job),
          preparationSha256: observationDigest(preparation),
          deadlineMs: 120000,
        };
      assert.equal(
        (
          await fixedProviderEffects(input, options).recover({
            request: recovery,
            job: input.job,
            preparation,
          })
        ).status,
        fault === "recovery" ? "RETIRED" : "RETAINED",
      );
      continue;
    }
    damaged = true;
    if (fault === "source")
      f.files.get(path.join(sourceDirectory, "launcher.c")).bytes =
        Buffer.from("changed source");
    if (fault === "tool-write")
      f.files.get(f.manifest.tools[0].path).mode = 0o775;
    if (fault === "output-write")
      f.files.get(path.join(output, f.manifest.helpers[0].name)).mode = 0o755;
    if (fault === "retirement") f.retainVerifier();
    const pending = fixedProviderEffects(input, options).verifyBuild();
    if (fault) await assert.rejects(pending);
    else assert.equal((await pending).status, "RETIRED");
    assert.equal(
      f.events.some((event) => event.startsWith("tool:")),
      false,
    );
  }
});

test("fixed Darwin entry supplies protected build defaults and fresh prepared verification", async () => {
  const f = buildTranscripts(),
    build = await createBuildEffects(f.input, f.options);
  await createSystemEffects(f.input, f.options);
  assert.deepEqual(f.events, []);
  for (const request of f.requests)
    assert.equal((await build.run(request)).settlement.status, "RETIRED");
  assert.equal(f.events.filter((name) => name.startsWith("tool:")).length, 22);
  assert.ok(f.events.some((name) => name.startsWith("snapshot:")));
  assert.equal(
    (
      await build.readPreparedImage(
        path.join(output, "launcher"),
        f.manifest.helpers[0].sha256,
      )
    ).length,
    81,
  );
  for (let i = 0; i < 2; i++) {
    await build.bootstrap();
    assert.equal((await build.settle()).status, "RETIRED");
    assert.equal(f.processes.size, 0);
  }
  const before = f.events.filter((name) => name.startsWith("tool:")).length;
  const effects = await createSystemEffects(f.input, f.options);
  assert.equal((await effects.verifyBuild(f.prepared())).status, "OBSERVED");
  assert.equal(
    f.events.filter((name) => name.startsWith("tool:")).length,
    before,
  );
  assert.equal(f.processes.size, 0);
});

test("Darwin missing source approval and changed intermediates fence compiler release", async () => {
  const approval = buildTranscripts();
  approval.manifest.darwinPreparation.bootstrap.reviewSha256 = null;
  await assert.rejects(createBuildEffects(approval.input, approval.options));
  assert.deepEqual(approval.events, []);
  const acl = buildTranscripts();
  acl.foreignReceipt();
  await assert.rejects(
    (await createBuildEffects(acl.input, acl.options)).run(acl.requests[0]),
  );
  assert.ok(
    !acl.events.includes("build-directory") &&
      !acl.events.some((name) => name.startsWith("tool:")),
  );
  const missing = buildTranscripts();
  missing.manifest.darwinPreparation.sources[0].sha256 = "f".repeat(64);
  await assert.rejects(
    (await createBuildEffects(missing.input, missing.options)).run(
      missing.requests[0],
    ),
  );
  assert.ok(!missing.events.some((name) => name.startsWith("tool:")));
  for (const [header, fault] of [
    "custody.h",
    "pf-abi.h",
    "feasibility-sandbox.h",
  ].flatMap((header) =>
    ["missing", "bytes", "path"].map((fault) => [header, fault]),
  )) {
    const adapter = buildTranscripts(true),
      plan = adapter.manifest.darwinPreparation;
    if (fault === "missing")
      plan.sources = plan.sources.filter(({ name }) => name !== header);
    else if (fault === "bytes")
      adapter.files.get(path.join(plan.sourceDirectory, header)).bytes =
        Buffer.from("substituted adapter bytes");
    else
      plan.bootstrap.sources.find(({ path }) =>
        path.endsWith("/" + header),
      ).path = "/fixture/substitute/" + header;
    await assert.rejects(async () =>
      (await createBuildEffects(adapter.input, adapter.options)).run(
        adapter.requests[0],
      ),
    );
    assert.ok(!adapter.events.some((name) => name.startsWith("tool:")));
  }
  const f = buildTranscripts(),
    build = await createBuildEffects(f.input, f.options);
  await build.run(f.requests[2]);
  f.change();
  let cause;
  await assert.rejects(build.run(f.requests[3]), (error) => {
    cause = error;
    return /Intermediate changed/u.test(error.message);
  });
  await assert.rejects(build.run(f.requests[0]), (error) => error === cause);
  assert.equal(f.events.filter((name) => name.startsWith("tool:")).length, 2);
});

test("Darwin prepared verification admits the pending prerequisite snapshot without retiring it", async () => {
  const f = buildTranscripts();
  // Only the outer receipt-selection contract is under review here; asset and
  // package acquisition retain their independent prerequisite owner.
  f.manifest.schemaVersion = 2;
  f.manifest.prerequisites = { assets: [], packages: [] };
  const build = await createBuildEffects(f.input, f.options);
  for (const request of f.requests) await build.run(request);
  const bootstrap = {
      requestSha256: observationDigest({ phase: "native-bootstrap" }),
      status: "POSSIBLE",
      receiptSha256: null,
    },
    preparation = {
      ...f.prepared(),
      schemaVersion: 2,
      commands: [bootstrap, ...f.prepared().commands],
    };
  await assert.rejects(
    (await createSystemEffects(f.input, f.options)).verifyBuild(preparation),
  );
  assert.equal(
    (
      await (
        await createSystemEffects(f.input, f.options)
      ).verifyBuild(preparation, { verificationPending: true })
    ).status,
    "OBSERVED",
  );
  assert.deepEqual(preparation.commands[0], bootstrap);
  assert.equal(f.events.filter((name) => name.startsWith("tool:")).length, 22);
});

test("Darwin uncertainty persistence cannot replace the original command failure", async () => {
  const f = buildTranscripts(),
    write = f.options.fs.writeFile;
  f.options.fs.writeFile = async (file, value, settings) => {
    if (JSON.parse(value).phase === "uncertain")
      throw new Error("Uncertainty receipt unavailable");
    return write(file, value, settings);
  };
  f.disconnect();
  const build = await createBuildEffects(f.input, f.options);
  let first;
  await assert.rejects(build.run(f.requests[0]), (cause) => {
    first = cause;
    return cause.message === "Worker acknowledgement lost";
  });
  await assert.rejects(build.run(f.requests[1]), (cause) => cause === first);
  assert.ok(f.events.includes("command:P"));
  assert.ok(!f.events.includes("command:R"));
  await build.settle();
});

test("Darwin compiler release requires the independently observed retained directory", async () => {
  const f = buildTranscripts(),
    open = f.options.commandTransport.open;
  f.options.commandTransport.open = async (...args) => {
    const owner = await open(...args),
      helper = [...f.processes.values()].find(
        (entry) => entry.directories?.length,
      );
    helper.directories[0].ino = "901";
    return owner;
  };
  const build = await createBuildEffects(f.input, f.options);
  await assert.rejects(
    build.run(f.requests[0]),
    /Unverified Darwin launch authority/u,
  );
  assert.ok(!f.events.includes("command:P"));
  assert.ok(!f.events.includes("command:R"));
  await build.settle();
});

test("Darwin partial-build recovery observes recorded custody without compilation", async () => {
  for (const condition of ["absent", "surviving", "substituted-directory"]) {
    const f = buildTranscripts(),
      build = await createBuildEffects(f.input, f.options);
    f.disconnect();
    if (condition === "surviving") f.survive();
    await assert.rejects(build.run(f.requests[0]));
    await build.settle();
    if (condition === "substituted-directory")
      f.directories.get(output).ino = 901;
    const request = {
        candidateSha,
        platform: "darwin",
        jobSha256: observationDigest(f.input.job),
        preparationSha256: observationDigest(null),
      },
      before = f.events.filter((name) => name.startsWith("tool:")).length;
    const result = await (
      await createSystemEffects(f.input, f.options)
    ).recover({ request, job: f.input.job, preparation: null });
    assert.equal(
      result.status,
      condition === "absent" ? "RETIRED" : "RETAINED",
    );
    assert.equal(
      f.events.filter((name) => name.startsWith("tool:")).length,
      before,
    );
  }
});

test("Darwin directory refusal settles original custody through a fresh reader without launching a compiler", async () => {
  for (const fault of [
    null,
    "cancelled",
    "expired-authority",
    "descendant",
    "missing-proof",
    "recovery-close",
    "missing-birth",
    "missing-refusal",
    "unexpected-launch",
  ]) {
    const f = buildTranscripts(),
      original = new Error("Original build-directory guard refusal"),
      diagnostics = [],
      controller = new AbortController();
    if (fault === "expired-authority") f.options.signal = controller.signal;
    const build = await createBuildEffects(f.input, f.options);
    let helper,
      refused = false;
    f.operationFrames((name, args, owner) => {
      if (name === "build-directory") {
        helper = owner.helper;
        refused = true;
        if (fault === "cancelled" || fault === "expired-authority")
          controller.abort();
        if (fault === "descendant")
          owner.live(
            owner.subject(helper.asid),
            f.manifest.darwinPreparation.bootstrap.reader.path,
          );
        throw original;
      }
      if (
        refused &&
        ((fault === "missing-proof" && name === "root-retired") ||
          (fault === "recovery-close" && name === "finish"))
      )
        throw new Error("Independent cleanup observation unavailable");
    });
    await assert.rejects(
      build.run(f.requests[0], { signal: controller.signal }),
      (cause) => cause === original,
    );
    assert.equal(f.events.includes("finish"), false);
    assert.equal(
      f.events.some((event) => event.startsWith("tool:")),
      false,
    );
    if (fault === "missing-birth")
      for (const [file, entry] of f.files)
        if (
          /darwin-bootstrap-0-custody-/u.test(file) &&
          JSON.parse(entry.bytes).phase === "admitted"
        )
          f.files.delete(file);
    if (fault === "missing-refusal")
      f.files.delete(
        path.join(
          directory,
          `darwin-command-${observationDigest(f.requests[0])}-provision-failed.json`,
        ),
      );
    if (fault === "unexpected-launch")
      f.put(
        path.join(
          directory,
          `darwin-command-${observationDigest(f.requests[0])}-0.json`,
        ),
        Buffer.from(
          JSON.stringify({
            phase: "helper",
            helper,
            requestSha256: observationDigest(f.requests[0]),
          }),
        ),
        0o400,
        1001,
      );
    const result = await withNativeDiagnostics(
      () => build.settle(),
      (owner, value) => diagnostics.push({ owner, value }),
    );
    const success = !fault || fault === "cancelled";
    assert.equal(result.status, success ? "RETIRED" : "RETAINED", fault);
    assert.equal(result.emergencyCleanup, false);
    if (fault === "expired-authority")
      assert.equal(f.events.includes("darwin-bootstrap-1-intent.json"), false);
    if (success) {
      assert.equal(result.independent, true);
      assert.equal(result.noLiveMembers, true);
      assert.equal(f.processes.size, 0);
      assert.ok(f.events.includes("probe:" + helper.pid));
      assert.ok(f.events.includes("root-retired"));
    } else
      assert.ok(
        diagnostics.some(({ owner }) => owner === "darwin-build-recovery"),
      );
    assert.strictEqual(await build.settle(), result);
    await assert.rejects(
      build.run(f.requests[1]),
      (cause) => cause === original,
    );
    assert.equal(
      f.events.some((event) => event.startsWith("tool:")),
      false,
    );
  }
});

test("Darwin SDK refusal retains original command custody until independent domain retirement", async () => {
  for (const [purpose, requestIndex] of [
    ["reviewed", 2],
    ["experiment", 2],
    ["experiment", 1],
  ])
    for (const fault of [
      null,
      "descendant",
      "missing-birth",
      "replaced",
      "census",
      "cancelled",
    ]) {
      const f = buildTranscripts(purpose === "experiment"),
        original = Object.assign(
          new Error("Original SDK root-ownership refusal"),
          {
            stderr:
              "native-darwin-sdk: realpath=1 equal=1 lstat=0 kind=1 owner=0 writable=-1\n",
          },
        ),
        cleanup = new AbortController(),
        open = f.options.commandTransport.open,
        order = [];
      f.options.signal = cleanup.signal;
      let helper;
      f.options.commandTransport.open = async (...args) => {
        const { channel } = await open(...args);
        let admitted = false;
        return {
          channel: {
            ...channel,
            receive: async () => {
              if (admitted) throw original;
              const frame = await channel.receive();
              helper = frame.helper;
              return frame;
            },
            send: async (frame) => {
              assert.equal(frame, "P");
              admitted = true;
              order.push("sdk-admission");
            },
          },
        };
      };
      const build = await createBuildEffects(f.input, f.options),
        request = {
          ...f.requests[requestIndex],
          ...(purpose === "experiment"
            ? {
                purpose,
                args:
                  requestIndex === 1
                    ? ["--sdk", sdkSelection.path, "--show-sdk-build-version"]
                    : darwinCompilerArguments(
                        path.join(
                          sourceDirectory,
                          DARWIN_HELPER_NAMES[0] + ".c",
                        ),
                        path.join(output, DARWIN_HELPER_NAMES[0]),
                        f.manifest.environment,
                        purpose,
                      ),
              }
            : {}),
        };
      await assert.rejects(build.run(request), (cause) => cause === original);
      assert.ok(helper);
      if (fault === "descendant")
        f.processes.set(9900, {
          identity: { ...helper, pid: 9900, startMicroseconds: 9900 },
        });
      if (fault === "missing-birth")
        for (const [file, entry] of f.files)
          if (
            /darwin-command-.*-[0-9]+\.json$/u.test(file) &&
            JSON.parse(entry.bytes).phase === "helper"
          )
            f.files.delete(file);
      if (fault === "cancelled") cleanup.abort();
      f.operationFrames((name, args) => {
        if (name === "finish") order.push("observer-finish");
        if (name === "root-retired" && Number(args[0]) === helper.pid) {
          order.push("original-domain");
          if (fault === "census")
            return { helper, complete: false, members: [] };
          if (fault === "replaced")
            return {
              helper: { ...helper, startSeconds: 101 },
              complete: true,
              members: [],
            };
        }
      });
      const result = await build.settle();
      assert.equal(
        result.status,
        fault ? "RETAINED" : "RETIRED",
        `${purpose}:${fault}`,
      );
      assert.equal(result.emergencyCleanup, false);
      assert.equal(
        f.events.filter((event) => event.startsWith("tool:")).length,
        1,
      );
      assert.ok(
        !f.events.includes("command:R") && !f.events.includes("command:S"),
      );
      const commandRecords = [...f.files.entries()]
        .filter(([file]) => /darwin-command-.*-[0-9]+\.json$/u.test(file))
        .map(([, entry]) => JSON.parse(entry.bytes));
      assert.ok(
        commandRecords.some(
          (record) => record.phase === "uncertain" && record.worker === null,
        ),
      );
      assert.ok(
        !commandRecords.some((record) =>
          ["worker", "publication-possible"].includes(record.phase),
        ),
      );
      assert.ok(
        !f.files.has(
          path.join(
            directory,
            `darwin-command-${observationDigest(request)}-result.json`,
          ),
        ),
      );
      if (!fault) {
        assert.equal(result.independent, true);
        assert.equal(f.processes.size, 0);
        assert.ok(
          order.indexOf("original-domain") < order.indexOf("observer-finish"),
        );
        assert.equal(
          order.filter((event) => event === "original-domain").length,
          2,
        );
      }
      await assert.rejects(
        build.run({
          ...f.requests[3],
          ...(purpose === "experiment" ? { purpose } : {}),
        }),
        (cause) => cause === original,
      );
    }
});

test("Darwin lost finish acknowledgment is not replayed during independent recovery", async () => {
  const f = buildTranscripts(),
    build = await createBuildEffects(f.input, f.options),
    finishes = new Map();
  let first;
  f.operationFrames((name, args, { helper }) => {
    if (name !== "finish") return;
    finishes.set(helper.pid, (finishes.get(helper.pid) ?? 0) + 1);
    if (!first) {
      first = helper.pid;
      // Native finish consumed the request and exited; only its reply is lost.
      f.processes.delete(helper.pid);
      throw new Error("Original finish acknowledgment lost");
    }
  });
  await assert.rejects(build.run(f.requests[0]));
  const result = await build.settle();
  assert.equal(result.status, "RETIRED");
  assert.equal(finishes.get(first), 1);
  assert.equal(f.processes.size, 0);
  assert.equal(f.events.filter((event) => event.startsWith("tool:")).length, 1);
});

test("Darwin build settlement forwards the separate cleanup signal to original-reader recovery", async () => {
  const f = buildTranscripts(),
    work = new AbortController(),
    cleanup = new AbortController();
  f.options.signal = work.signal;
  const effects = await createSystemEffects(f.input, f.options);
  await effects.bootstrap(work.signal);
  let lost = false;
  f.operationFrames((name, args, { helper }) => {
    if (name === "finish" && !lost) {
      lost = true;
      f.processes.delete(helper.pid);
      throw new Error("Original reader finish acknowledgment lost");
    }
  });
  work.abort();
  const result = await effects.settle(darwinSystemRecipes()[0], undefined, {
    signal: cleanup.signal,
    execution: {
      id: "build",
      effects: Object.fromEntries(
        NATIVE_EFFECT_CLASSES.map((key) => [
          key,
          {
            admission: key === "builds" ? "possible" : "not-started",
          },
        ]),
      ),
    },
  });
  assert.equal(lost, true);
  assert.equal(result.builds.settlement.status, "RETIRED");
  assert.equal(result.builds.settlement.independent, true);
  assert.equal(f.processes.size, 0);
});

test("Darwin build lifetimes fence pending IPC and verifier exit requires kernel absence", async () => {
  assert.equal(DARWIN_BUILD_CUSTODY_MS, 120000 + 22 * 60000);
  for (const deadlineMs of [12345, DARWIN_BUILD_CUSTODY_MS]) {
    const child = new EventEmitter();
    child.stdin = new PassThrough();
    child.stdout = new PassThrough();
    let expire;
    const channel = darwinCustodyChannel(child, {
      deadlineMs,
      schedule(callback, delay) {
        assert.equal(delay, deadlineMs);
        expire = callback;
      },
      cancel() {},
    });
    const pending = assert.rejects(channel.receive()),
      complete = assert.rejects(channel.completion);
    expire();
    await Promise.all([pending, complete]);
    assert.equal(child.stdin.destroyed, true);
    child.emit("close", 0, null);
    child.stdout.destroy();
  }
  const f = buildTranscripts();
  f.retainVerifier();
  await assert.rejects(
    (await createBuildEffects(f.input, f.options)).run(f.requests[0]),
  );
  assert.ok(!f.events.some((name) => name.startsWith("tool:")));
});

test("Darwin build and prepared reads reject a substituted native directory identity", async () => {
  const f = buildTranscripts(),
    build = await createBuildEffects(f.input, f.options);
  await build.run(f.requests[0]);
  f.directories.get(output).ino = 901;
  await assert.rejects(build.run(f.requests[1]));
  assert.equal(f.events.filter((name) => name.startsWith("tool:")).length, 1);

  const complete = buildTranscripts(),
    owner = await createBuildEffects(complete.input, complete.options);
  for (const request of complete.requests) await owner.run(request);
  complete.directories.get(output).ino = 901;
  const effects = await createSystemEffects(complete.input, complete.options);
  await assert.rejects(effects.verifyBuild(complete.prepared()));
  assert.equal(
    complete.events.filter((name) => name.startsWith("tool:")).length,
    22,
  );
});

test("Darwin prepared verification rejoins intermediate verifier creation identities", async () => {
  const f = buildTranscripts(),
    build = await createBuildEffects(f.input, f.options);
  for (const request of f.requests) await build.run(request);
  const record = [...f.files.entries()]
    .filter(([name]) => /darwin-bootstrap-0-custody-[0-9]+\.json$/u.test(name))
    .map(([, value]) => JSON.parse(value.bytes))
    .find((value) => value.phase === "probe-created");
  const verifier = record.request.verifier;
  // A reused PID is an accessible kernel observation, never absence of the
  // previously completed verifier's possible custody.
  f.processes.set(verifier.pid, {
    status: "live",
    identity: { ...verifier, pidVersion: verifier.pidVersion + 1 },
    sha256: f.manifest.darwinPreparation.bootstrap.reader.sha256,
    signature: { cdhash, entitlementsSha256: hash, valid: true },
    directories: [],
  });
  const before = f.events.filter(
    (name) => name === `probe:${verifier.pid}`,
  ).length;
  const effects = await createSystemEffects(f.input, f.options);
  await assert.rejects(
    effects.verifyBuild(f.prepared()),
    /Unverified Darwin launch authority/u,
  );
  assert.equal(
    f.events.filter((name) => name === `probe:${verifier.pid}`).length,
    before + 1,
  );
  assert.equal(f.events.filter((name) => name.startsWith("tool:")).length, 22);
});

function buildBinding(f) {
  const authority = {
    uid: 0,
    gid: 0,
    ruid: 0,
    rgid: 0,
    sandboxed: false,
    descriptors: [
      { fd: 0, type: "vnode" },
      { fd: 1, type: "pipe" },
      { fd: 2, type: "pipe" },
    ],
  };
  const template = {
    schemaVersion: 1,
    candidateSha,
    platform: "darwin",
    sourceReviewSha256: hash,
    provisioningReviewSha256:
      f.manifest.darwinPreparation.bootstrap.reviewSha256,
    policy: {
      launch: {
        commands: f.requests.map((request) => ({
          requestSha256: observationDigest(request),
          toolSha256: request.toolSha256,
        })),
      },
      policy: {
        compilerDomains: f.requests.map(() => authority),
        output: {
          path: output,
          identitySha256: { binding: "build-root" },
          uid: 0,
          gid: 0,
          mode: 0o555,
        },
      },
    },
    bindings: [
      {
        id: "build-root",
        kind: "custody",
        paths: [["policy", "output", "identitySha256"]],
        minimum: null,
        maximum: null,
      },
    ],
  };
  return {
    template,
    approval: {
      candidateSha,
      platform: "darwin",
      authority: "operator-protected",
      manifestSha256: nativePolicyTemplateDigest(template),
    },
    context: context("build"),
  };
}
function caseBinding(f, id = "ownership.literal", ownershipEffects = false) {
  const experiment = f.manifest.purpose === "experiment",
    bindingContext = context(id),
    root =
      "/private/var/run/native-poc/cases/" + observationDigest(bindingContext);
  const request = {
    ...(experiment ? { purpose: "experiment" } : {}),
    schemaVersion: 1,
    candidateSha,
    nonce: observationDigest(bindingContext).slice(0, 32),
    uid: 90001,
    gid: 90002,
    custody: root + "/custody",
    storage: root + "/storage",
    workspace: root + "/storage/work",
    launcher: { path: root + "/custody/launcher", sha256: digest(f.image) },
    executable: {
      path: root + "/storage/payload",
      sha256: digest(f.image),
      cdhash,
    },
    policy: { path: root + "/custody/policy", sha256: hash },
    bindings: { source: hash, system: hash, closure: hash, policy: hash },
  };
  let input = request,
    parameters = {},
    policyBytes = bytes;
  if (id.startsWith("access.")) {
    input = {
      ...(experiment ? { purpose: "experiment" } : {}),
      request,
      profile: id.slice(7),
      disposable: true,
      metadata: request.storage + "/metadata",
      pointer: request.workspace + "/.git",
      checkout: "/protected/checkout",
      configuration: "/protected/config",
      credentials: "/protected/credentials",
      runtime: [
        {
          path: request.executable.path,
          sha256: request.executable.sha256,
          executable: true,
          mapped: true,
        },
        {
          path: "/usr/lib/dyld",
          sha256: hash,
          executable: false,
          mapped: true,
        },
      ],
      endpoints: ["inet", "inet6"].flatMap((family, i) =>
        ["tcp", "udp"].map((protocol, j) => ({
          family,
          protocol,
          clientPort: 41001 + i * 4 + j * 2,
          serverPort: 41002 + i * 4 + j * 2,
          address: family === "inet" ? "127.0.0.1" : "::1",
          owned: true,
        })),
      ),
      ...(experiment ? { bindingSha256: hash } : { reviewSha256: hash }),
    };
    const native = buildDarwinPolicy(input);
    request.policy.sha256 = native.seatbeltSha256;
    request.bindings.policy = native.compositionSha256;
    const { request: ignored, ...rest } = native.value;
    parameters = rest;
    policyBytes = Buffer.from(native.seatbelt);
  }
  const argumentsList =
    id.startsWith("ownership.") &&
    !["ownership.literal", "ownership.storage"].includes(id)
      ? [request.nonce, id.slice(10)]
      : DARWIN_LITERAL_ARGUMENTS;
  if (ownershipEffects) {
    policyBytes = Buffer.from(
      [
        "(version 1)",
        "(deny default)",
        "(allow process-fork)",
        "(allow process-info* (target same-sandbox))",
        `(allow file-read* file-write* (subpath ${JSON.stringify(request.workspace)}))`,
        `(allow file-read-metadata (literal ${JSON.stringify(request.storage)}))`,
        ...[
          request.executable.path,
          "/usr/lib/dyld",
          "/usr/lib/libSystem.B.dylib",
        ].map(
          (name) =>
            `(allow file-read-data file-read-metadata file-map-executable (literal ${JSON.stringify(name)}))`,
        ),
        `(allow process-exec (literal ${JSON.stringify(request.executable.path)}))`,
        "",
      ].join("\n"),
    );
    request.policy.sha256 = digest(policyBytes);
    parameters = {
      kind: "darwin-ownership",
      seatbeltSha256: request.policy.sha256,
      processLimit: 32,
    };
  }
  const template = {
    ...(experiment ? { purpose: "experiment" } : {}),
    schemaVersion: 1,
    candidateSha,
    platform: "darwin",
    ...(experiment
      ? { sourceSha256: hash, provisioningSha256: hash }
      : { sourceReviewSha256: hash, provisioningReviewSha256: hash }),
    policy: {
      launch: nativePolicyLaunchData(request, argumentsList),
      policy: parameters,
    },
    bindings: [
      {
        id: "uid",
        kind: "uid",
        paths: [["launch", "request", "uid"]],
        minimum: 90001,
        maximum: 90001,
      },
      {
        id: "gid",
        kind: "gid",
        paths: [["launch", "request", "gid"]],
        minimum: 90002,
        maximum: 90002,
      },
      {
        id: "nonce",
        kind: "custody",
        paths: [["launch", "request", "nonce"]],
        minimum: null,
        maximum: null,
      },
    ],
  };
  for (const rule of template.bindings)
    template.policy.launch.request[rule.paths[0][2]] = { binding: rule.id };
  if (id.startsWith("access."))
    for (const [i, endpoint] of parameters.endpoints.entries())
      for (const key of ["clientPort", "serverPort"]) {
        const port = endpoint[key],
          rule = {
            id: `port-${i}-${key === "clientPort" ? "client" : "server"}`,
            kind: "loopback-port",
            paths: [["policy", "endpoints", i, key]],
            minimum: port,
            maximum: port,
          };
        template.bindings.push(rule);
        template.policy.policy.endpoints[i][key] = { binding: rule.id };
      }
  const assets = ["case-launcher", "case-payload", "case-policy"].map(
    (name, i) => {
      const path = sourceDirectory + "/" + name,
        data = i === 2 ? policyBytes : f.image;
      f.put(path, data, i === 2 ? 0o444 : 0o555);
      return { path, sha256: digest(data) };
    },
  );
  const entries = [
    { kind: "directory", path: root, sha256: null },
    ...[request.custody, request.storage, request.workspace].map((path) => ({
      kind: "authority",
      path,
      sha256: null,
    })),
    ...[request.launcher, request.executable, request.policy].map(
      ({ path, sha256 }, i) => ({
        kind: i === 2 ? "data" : "image",
        path,
        sha256,
      }),
    ),
    ...assets.map((asset, i) => ({
      kind: i === 2 ? "data" : "image",
      ...asset,
    })),
    {
      kind: "data",
      path: "/private/var/run/native-poc/pf-lease",
      sha256: digest(Buffer.from("native-poc-pf-lease-v1\n")),
    },
    { kind: "directory", path: output, sha256: null },
  ];
  f.put(entries[10].path, Buffer.from("native-poc-pf-lease-v1\n"), 0o400);
  const declared = f.manifest.darwinPreparation.cases.find(
      (entry) => entry.id === id,
    ),
    plan = encodeDarwinCustodyPlan({
      ...(experiment ? { purpose: "experiment" } : {}),
      candidateSha,
      uid: 90001,
      gid: 90002,
      entries,
    });
  declared.custody.reader.sha256 = digest(f.image);
  declared.custody.plan.sha256 = digest(plan);
  f.put(declared.custody.plan.path, plan, 0o400);
  declared.bindings = {
    schemaVersion: 1,
    ...(experiment ? { bindingSha256: hash } : { authoritySha256: hash }),
    uid: 90001,
    gid: 90002,
    input,
    assets,
  };
  return {
    template,
    ...(experiment
      ? { purpose: "experiment" }
      : {
          approval: {
            candidateSha,
            platform: "darwin",
            authority: "operator-protected",
            manifestSha256: nativePolicyTemplateDigest(template),
          },
        }),
    context: bindingContext,
  };
}
function accessBinding(f, profile, observedPins = false, mach) {
  const experiment = f.manifest.purpose === "experiment",
    id = "access." + profile,
    binding = caseBinding(f, id),
    declared = f.manifest.darwinPreparation.cases.find(
      (entry) => entry.id === id,
    ),
    input = declared.bindings.input,
    request = input.request,
    root = path.dirname(request.custody);
  input.checkout = root + "/checkout";
  input.configuration = root + "/configuration";
  input.credentials = root + "/credentials";
  const native = buildDarwinPolicy(input),
    plan = f.files
      .get(declared.custody.plan.path)
      .bytes.toString()
      .trim()
      .split("\n")
      .slice(1)
      .map((line) => {
        const [kind, sha256, hex] = line.split(" ");
        return {
          kind,
          sha256: sha256 === "-" ? null : sha256,
          path: Buffer.from(hex, "hex").toString(),
        };
      }),
    assets = [];
  const add = (kind, file, bytes, source = null) => {
    const index = 12 + assets.length,
      sha256 = kind === "authority" ? null : digest(bytes);
    assets.push({ kind, path: file, sha256, source });
    if (source === null && kind !== "authority")
      f.put(file, bytes, kind === "image" || kind === "helper" ? 0o555 : 0o400);
    return index;
  };
  const install = add(
      "data",
      sourceDirectory + "/pf-root-install",
      Buffer.from('anchor "native-poc/*" all quick\n'),
    ),
    restore = add(
      "data",
      sourceDirectory + "/pf-root-restore",
      Buffer.from("\n"),
    ),
    toolSource = add("helper", "/sbin/pfctl", f.image),
    tool = add("helper", request.custody + "/pfctl", f.image, toolSource),
    observerSource = add("image", output + "/observer-helper", f.image),
    observer = add(
      "helper",
      request.custody + "/observer",
      f.image,
      observerSource,
    ),
    pfSource = add(
      "data",
      sourceDirectory + "/pf-anchor",
      Buffer.from(native.pf),
    ),
    configuration = add(
      "data",
      request.custody + "/darwin-pf.conf",
      Buffer.from(native.pf),
      pfSource,
    ),
    beforeSource = add(
      "data",
      sourceDirectory + "/pf-anchor-before",
      Buffer.from("\n"),
    ),
    before = add(
      "data",
      request.custody + "/darwin-pf-before.conf",
      Buffer.from("\n"),
      beforeSource,
    );
  const operations = [
      "read",
      "write",
      "write",
      "write",
      "unlink",
      "replace",
      "parent",
      "read",
      "write",
      "read",
      "read",
      "read",
      "write",
      "mach",
      "unix",
      "shm",
      "sem",
      "sysv-shm",
      "sysv-sem",
    ],
    targets = [
      request.workspace + "/inspection",
      request.workspace + "/edit",
      input.metadata + "/sentinel",
      input.pointer,
      input.pointer,
      input.pointer,
      request.workspace,
      request.custody + "/sentinel",
      request.custody + "/sentinel",
      input.checkout + "/sentinel",
      input.configuration + "/sentinel",
      input.credentials + "/sentinel",
      root + "/outside/sentinel",
      "org.native-poc." + request.nonce,
      root + "/ipc",
      "/native-poc-" + request.nonce,
      "/native-poc-" + request.nonce,
      "sysv-shm",
      "sysv-sem",
    ],
    attempts = [
      "inspection",
      "edit",
      ...DARWIN_ACCESS_DENIALS,
      ...native.value.endpoints.map(
        ({ family, protocol }) => `loopback-${family}-${protocol}`,
      ),
    ].map((id, i) => {
      const endpoint = i >= 35 ? native.value.endpoints[i - 35] : null;
      return {
        id,
        ...(experiment
          ? { source: i === 13 ? "unified-log-mach-v1" : "bsm" }
          : {}),
        event: experiment && i === 13 ? null : i < 13 ? 1 : i < 19 ? 2 : 3,
        controlEvent:
          experiment && i === 13 ? null : i < 13 ? 1 : i < 19 ? 2 : 3,
        operation:
          operations[i] ??
          (endpoint
            ? `${endpoint.protocol}${endpoint.family === "inet" ? 4 : 6}-pair`
            : `${(i - 19) % 2 ? "udp" : "tcp"}${(i - 19) % 4 >= 2 ? 6 : 4}`),
        target:
          targets[i] ??
          (endpoint
            ? endpoint.address
            : Math.floor((i - 19) / 4) === 1
              ? (i - 19) % 4 >= 2
                ? "::"
                : "0.0.0.0"
              : Math.floor((i - 19) / 4) === 2
                ? (i - 19) % 4 >= 2
                  ? "2001:db8::1"
                  : "192.0.2.1"
                : (i - 19) % 4 >= 2
                  ? "::1"
                  : "127.0.0.1"),
        remote: endpoint?.serverPort ?? (i < 17 ? 0 : 45001 + i * 2),
        local: endpoint?.clientPort ?? (i < 19 ? 0 : 45002 + i * 2),
      };
    });
  const bank = Buffer.from(
      attempts
        .map(
          ({ operation, target, remote, local }) =>
            `${operation} ${Buffer.from(target).toString("hex")} ${remote} ${local}\n`,
        )
        .join(""),
    ),
    bankSource = add("data", sourceDirectory + "/access-bank", bank);
  add("data", request.custody + "/access-cases", bank, bankSource);
  for (const file of [
    input.metadata,
    input.checkout,
    input.configuration,
    input.credentials,
    root + "/outside",
    request.storage + "/work.replacement",
  ])
    add("authority", file);
  add("data", "/usr/lib/dyld", bytes);
  input.runtime[1].sha256 = hash;
  // The pointer is exclusively created by the sealed resource owner after the
  // separately pinned bank is read, then joined by its held identity.
  const pointer = 12 + assets.length;
  assets.push({
    kind: "data",
    path: input.pointer,
    sha256: digest(request.nonce),
    source: null,
  });
  if (mach) assert.equal(mach.tool.sha256, digest(f.image));
  const machTool = experiment
    ? add("helper", mach?.tool.path ?? "/usr/bin/log", f.image)
    : null;
  const entryList = [...plan, ...assets.map(({ source, ...entry }) => entry)],
    required = [
      request.custody,
      request.storage,
      request.workspace,
      input.metadata,
      input.pointer,
      input.checkout,
      input.configuration,
      input.credentials,
      request.executable.path,
      "/usr/lib/dyld",
    ],
    objects = required.map((file) => ({
      index: entryList.findIndex(({ path }) => path === file),
      decisions: [1, 1, 1, 1, 1],
      aclSha256: observedPins ? null : hash,
    })),
    rootRules = [
      {
        set: 1,
        action: 0,
        quick: true,
        state: 0,
        call: "native-poc/*",
        raw: "00",
      },
    ],
    anchorRules = Array.from({ length: 36 }, (_, i) => ({
      set: 1,
      action: i >= 32 || i % 8 >= 4 ? 1 : 0,
      quick: true,
      state: 0,
      call: "",
      raw: i.toString(16).padStart(2, "0"),
      ...(experiment ? { match: darwinPfExpectedRules(native)[i].match } : {}),
    })),
    baseline = (experiment ? stockPfFixture : (value) => value)({
      active: false,
      states: 0,
      graph: [{ anchor: "", rules: [] }],
      interfaces: [{ name: "lo0", skip: false }],
      routesSha256: hash,
    }),
    installed = (experiment ? stockPfFixture : (value) => value)({
      ...baseline,
      active: true,
      graph: [{ anchor: "", rules: rootRules }],
    }),
    events = [
      { event: 1, opcode: "AUE_OPEN", classes: 1, selector: "path" },
      { event: 2, opcode: "AUE_SEMGET", classes: 1, selector: "ipc" },
      { event: 3, opcode: "AUE_CONNECT", classes: 1, selector: "socket" },
    ],
    record = {
      ...(experiment ? { purpose: "experiment" } : {}),
      schemaVersion: experiment ? 2 : 1,
      contextSha256: observationDigest(binding.context),
      pf: {
        [experiment ? "bindings" : "approval"]: {
          schemaVersion: 1,
          contextSha256: observationDigest(binding.context),
          [experiment ? "bindingSha256" : "manifestSha256"]: hash,
          baselineSha256: darwinPfAuthorityDigest(baseline),
          installedRootSha256: observedPins
            ? null
            : darwinPfRootDigest(installed),
          routesSha256: hash,
          loopbackSkip: false,
        },
        tool: { index: tool, cdhash },
        install,
        restore,
        configuration,
        before,
        anchorRulesSha256: observedPins
          ? null
          : digest(
              JSON.stringify(
                experiment ? darwinPfExpectedRules(native) : anchorRules,
              ),
            ),
      },
      audit: {
        mapping: {
          sdkSha256: hash,
          abiSha256: hash,
          headerVersion: 11,
          events,
          mappingSha256: digest(JSON.stringify({ headerVersion: 11, events })),
        },
        classes: 1,
        helper: { index: observer, cdhash },
      },
      ...(experiment
        ? {
            mach: {
              source: mach?.source ?? "unified-log-mach-v1",
              tool: { index: machTool, cdhash: mach?.tool.cdhash ?? cdhash },
            },
          }
        : {}),
      assets,
      objects,
      attempts,
    };
  const approvalBytes = Buffer.from(JSON.stringify(record) + "\n"),
    approval = {
      path:
        sourceDirectory + (experiment ? "/access-binding" : "/access-approval"),
      sha256: digest(approvalBytes),
    };
  f.put(approval.path, approvalBytes, 0o400);
  input[experiment ? "bindingSha256" : "reviewSha256"] = approval.sha256;
  const policy = buildDarwinPolicy(input);
  request.policy.sha256 = policy.seatbeltSha256;
  request.bindings.policy = policy.compositionSha256;
  f.put(declared.bindings.assets[2].path, Buffer.from(policy.seatbelt));
  declared.bindings.assets[2].sha256 = policy.seatbeltSha256;
  entryList[6].sha256 = policy.seatbeltSha256;
  entryList[9].sha256 = policy.seatbeltSha256;
  const { request: ignored, ...parameters } = policy.value;
  binding.template.policy.policy = parameters;
  for (const rule of binding.template.bindings.filter(
    ({ kind }) => kind === "loopback-port",
  )) {
    const [a, b, i, key] = rule.paths[0];
    binding.template.policy[a][b][i][key] = { binding: rule.id };
  }
  binding.template.policy.launch = nativePolicyLaunchData(
    request,
    DARWIN_LITERAL_ARGUMENTS,
  );
  for (const rule of binding.template.bindings.filter(
    ({ kind }) => kind !== "loopback-port",
  ))
    binding.template.policy.launch.request[rule.paths[0][2]] = {
      binding: rule.id,
    };
  if (!experiment)
    binding.approval.manifestSha256 = nativePolicyTemplateDigest(
      binding.template,
    );
  const custody = encodeDarwinCustodyPlan({
    ...(experiment ? { purpose: "experiment" } : {}),
    candidateSha,
    uid: request.uid,
    gid: request.gid,
    entries: entryList,
  });
  declared.custody.plan.sha256 = digest(custody);
  f.put(declared.custody.plan.path, custody, 0o400);
  declared.bindings.access = {
    [experiment ? "binding" : "approval"]: approval,
  };
  if (experiment) declared.bindings.schemaVersion = 2;
  f.access({ ...record, profile, rootRules, anchorRules, pointer });
  return binding;
}

// Only the selected declaration owns native fixture resources; the remaining
// fixed declarations are inert expectations for inventory/materialization checks.
function experimentCase(f, id) {
  const cases = f.manifest.darwinPreparation.cases,
    prepare = (id) =>
      id.startsWith("access.")
        ? accessBinding(f, id.slice(7), id === "access.trusted-command")
        : caseBinding(f, id, true);
  for (const entry of cases) if (entry.id !== id) prepare(entry.id);
  prepare(id);
  if (!id.startsWith("access.")) f.access(undefined);
  for (const [i, entry] of cases.entries()) {
    if (entry.id === id) continue;
    const request = entry.bindings.input.request ?? entry.bindings.input;
    request.uid = entry.bindings.uid = 91000 + i * 2;
    request.gid = entry.bindings.gid = 91001 + i * 2;
  }
  return darwinExperimentCaseDeclarations(cases).policyBindings.find(
    (binding) => binding.context.executionId === id,
  );
}

test("Darwin experiment declarations retain every ownership fault and access profile through existing native owners", async () => {
  const recipes = darwinSystemRecipes().filter(
    (recipe) => recipe.group === "ownership" || recipe.id.startsWith("access."),
  );
  for (const recipe of recipes) {
    const f = buildTranscripts(true),
      binding = experimentCase(f, recipe.id),
      effects = createDarwinSystemEffects(f.input, f.options),
      work = new AbortController();
    if (recipe.id === "ownership.literal") {
      const read = f.options.loadExperimentBuild;
      f.options.loadExperimentBuild = async (...args) => {
        recipe.group = "release";
        return read(...args);
      };
    }
    let proof;
    const prepared = await effects.prepare(recipe, {
      signal: work.signal,
      policyBinding: binding,
      recordPolicy: async (value) => {
        proof = value;
      },
    });
    if (recipe.id === "ownership.literal") recipe.group = "ownership";
    assert.equal(prepared.purpose, "experiment");
    assert.equal(prepared.reviewSha256, undefined);
    assert.equal(
      proof.provisioning.bindingSha256,
      binding.template.provisioningSha256,
    );
    assert.equal(proof.provisioning.authoritySha256, undefined);
    assert.equal(
      proof.observed.templateSha256,
      observationDigest(binding.template),
    );
    if (recipe.id.startsWith("access.")) {
      const result = await runDarwinAccessCase(
        prepared.input,
        prepared.effects,
      );
      assert.equal(result.status, "OBSERVED");
      assert.equal(
        result.nativeEvidence.denials.length,
        DARWIN_ACCESS_DENIALS.length,
      );
    } else if (
      !["ownership.literal", "ownership.storage"].includes(recipe.id)
    ) {
      assert.equal(
        (
          await runDarwinOwnershipCase(
            recipe.id.slice(10),
            prepared.input,
            prepared.effects,
          )
        ).status,
        "OBSERVED",
      );
    } else {
      prepared.admitted = await prepared.admit();
      assert.equal(prepared.admitted.record.status, "ADMITTED");
      await effects.literal(prepared);
    }
    work.abort();
    assert.equal(
      settled(
        await effects.settle(recipe, prepared, {
          signal: new AbortController().signal,
          execution: execution(recipe),
        }),
      ).status,
      "RETIRED",
    );
    assert.equal(f.processes.size, 0);
    assert.ok(f.events.includes("experiment-build-read"));
  }
});

test("Darwin experiment cases withhold admission for mixed bindings and unavailable or surviving native effects", async () => {
  for (const fault of [
    "missing",
    "context",
    "subject-authority",
    "fresh-members-missing",
    "tcp-deadline",
    "mach-control-timeout",
  ]) {
    const access = ["tcp-deadline", "mach-control-timeout"].includes(fault),
      id = access ? "access.read-only" : "ownership.cancel",
      f = buildTranscripts(true),
      binding = experimentCase(f, id),
      effects = createDarwinSystemEffects(f.input, f.options),
      recipe = darwinSystemRecipes().find((recipe) => recipe.id === id),
      work = new AbortController();
    f.caseFault(fault);
    let prepared;
    if (
      [
        "missing",
        "context",
        "subject-authority",
        "mach-control-timeout",
      ].includes(fault)
    )
      await assert.rejects(
        effects.prepare(recipe, {
          signal: work.signal,
          policyBinding: binding,
          recordPolicy() {},
        }),
        fault === "mach-control-timeout"
          ? /Unverified Darwin mach-lookup:/u
          : undefined,
      );
    else {
      prepared = await effects.prepare(recipe, {
        signal: work.signal,
        policyBinding: binding,
        recordPolicy() {},
      });
      const result = access
        ? await runDarwinAccessCase(prepared.input, prepared.effects)
        : await runDarwinOwnershipCase(
            "cancel",
            prepared.input,
            prepared.effects,
          );
      assert.notEqual(result.status, "OBSERVED");
    }
    work.abort();
    await effects.settle(recipe, prepared, {
      signal: new AbortController().signal,
      execution: execution(recipe),
    });
    await assert.rejects(
      effects.prepare(recipe, { policyBinding: binding, recordPolicy() {} }),
    );
  }
  const f = buildTranscripts(true),
    binding = experimentCase(f, "ownership.literal"),
    cases = f.manifest.darwinPreparation.cases;
  assert.throws(() => darwinExperimentCaseDeclarations(cases.slice(1)));
  const mixed = structuredClone(cases);
  mixed[0].custody.reviewSha256 = hash;
  assert.throws(() => darwinExperimentCaseDeclarations(mixed));
  binding.approval = { manifestSha256: hash };
  await assert.rejects(
    createDarwinSystemEffects(f.input, f.options).prepare(
      darwinSystemRecipes().find(({ id }) => id === "ownership.literal"),
      { policyBinding: binding, recordPolicy() {} },
    ),
  );
  delete binding.approval;
  binding.template.sourceSha256 = "e".repeat(64);
  const fenced = createDarwinSystemEffects(f.input, f.options),
    literal = darwinSystemRecipes().find(
      ({ id }) => id === "ownership.literal",
    );
  await assert.rejects(
    fenced.prepare(literal, { policyBinding: binding, recordPolicy() {} }),
  );
  const canonical = darwinExperimentCaseDeclarations(cases).policyBindings.find(
    (value) => value.context.executionId === literal.id,
  );
  await assert.rejects(
    fenced.provision(literal, { policyBinding: canonical, recordPolicy() {} }),
  );
  assert.ok(!f.events.includes("experiment-build-read"));

  const active = buildTranscripts(true),
    first = experimentCase(active, "ownership.literal"),
    effects = createDarwinSystemEffects(active.input, active.options),
    work = new AbortController(),
    recipe = darwinSystemRecipes().find(({ id }) => id === "ownership.literal"),
    prepared = await effects.prepare(recipe, {
      signal: work.signal,
      policyBinding: first,
      recordPolicy() {},
    }),
    next = darwinSystemRecipes().find(({ id }) => id === "ownership.storage"),
    nextBinding = darwinExperimentCaseDeclarations(
      active.manifest.darwinPreparation.cases,
    ).policyBindings.find((value) => value.context.executionId === next.id),
    reads = active.events.filter(
      (name) => name === "experiment-build-read",
    ).length;
  await assert.rejects(
    effects.prepare(next, { policyBinding: nextBinding, recordPolicy() {} }),
  );
  assert.equal(
    active.events.filter((name) => name === "experiment-build-read").length,
    reads,
  );
  work.abort();
  assert.equal(
    settled(
      await effects.settle(recipe, prepared, {
        signal: new AbortController().signal,
        execution: execution(recipe),
      }),
    ).status,
    "RETIRED",
  );

  const concurrent = buildTranscripts(true),
    concurrentBinding = experimentCase(concurrent, recipe.id),
    concurrentNextBinding = darwinExperimentCaseDeclarations(
      concurrent.manifest.darwinPreparation.cases,
    ).policyBindings.find((value) => value.context.executionId === next.id),
    entered = Promise.withResolvers(),
    release = Promise.withResolvers();
  let concurrentReads = 0;
  concurrent.options.loadExperimentBuild = async () => {
    concurrentReads++;
    entered.resolve();
    await release.promise;
    throw new Error("Interrupted build observation");
  };
  const concurrentEffects = createDarwinSystemEffects(
      concurrent.input,
      concurrent.options,
    ),
    firstRejected = assert.rejects(
      concurrentEffects.prepare(recipe, {
        policyBinding: concurrentBinding,
        recordPolicy() {},
      }),
    );
  await entered.promise;
  const nextRejected = assert.rejects(
    concurrentEffects.prepare(next, {
      policyBinding: concurrentNextBinding,
      recordPolicy() {},
    }),
  );
  release.resolve();
  await Promise.all([firstRejected, nextRejected]);
  assert.equal(concurrentReads, 1);
});

async function prepareTranscripts(f) {
  const build = await createBuildEffects(f.input, f.options);
  for (const request of f.requests) await build.run(request);
  f.input.preparation = f.prepared();
  return createSystemEffects(f.input, f.options);
}

test("fixed Darwin entry observes compiler policy independently and never recompiles at its mandatory gate", async () => {
  const f = buildTranscripts(),
    binding = buildBinding(f),
    effects = await prepareTranscripts(f);
  let proof;
  assert.equal(
    (
      await effects.build({
        candidateSha,
        reviewSha256: hash,
        policyBinding: binding,
        recordPolicy: async (record) => {
          proof = record;
        },
      })
    ).status,
    "OBSERVED",
  );
  assert.equal(proof.observed.policy.policy.compilerDomains.length, 22);
  assert.equal(
    f.events.filter((event) => event.startsWith("tool:")).length,
    22,
  );
  assert.equal(
    f.events.filter((event) => event === "compiler-policy").length,
    22,
  );
  const wrong = structuredClone(binding);
  wrong.template.policy.policy.compilerDomains[0].sandboxed = true;
  wrong.approval.manifestSha256 = nativePolicyTemplateDigest(wrong.template);
  await assert.rejects(
    effects.build({
      candidateSha,
      reviewSha256: hash,
      policyBinding: wrong,
      recordPolicy: async () => assert.fail("Substituted policy admitted"),
    }),
  );
});

test("Darwin additional compiler authority and missing parked observations withhold build admission", async () => {
  const f = buildTranscripts();
  f.compilerPolicyFault();
  await assert.rejects(
    (await createBuildEffects(f.input, f.options)).run(f.requests[0]),
  );
  assert.ok(!f.events.includes("command:R"));
  for (const fault of ["missing", "substitution"]) {
    const f = buildTranscripts(),
      binding = buildBinding(f),
      effects = await prepareTranscripts(f),
      worker = [...f.files.values()].find(
        (entry) =>
          JSON.parse(
            entry.bytes.toString().startsWith("{") ? entry.bytes : "{}",
          ).phase === "worker",
      );
    const record = JSON.parse(worker.bytes);
    if (fault === "missing") record.compilerPolicy = null;
    else record.compilerPolicy.identity.pidVersion++;
    worker.bytes = Buffer.from(JSON.stringify(record));
    await assert.rejects(
      effects.build({
        candidateSha,
        reviewSha256: hash,
        policyBinding: binding,
        recordPolicy: async () => assert.fail("Missing native read admitted"),
      }),
    );
  }
});

test("fixed Darwin entry provisions bound private custody using only filesystem and native IPC", async () => {
  const f = buildTranscripts(),
    binding = caseBinding(f),
    effects = await prepareTranscripts(f),
    recipe = darwinSystemRecipes().find(({ id }) => id === "ownership.literal"),
    work = new AbortController();
  const actual = await effects.provision(recipe, {
    signal: work.signal,
    policyBinding: binding,
    recordPolicy: async () => {},
  });
  assert.deepEqual(
    actual.provisioning.bindings.map(({ value }) => value),
    [90001, 90002, observationDigest(binding.context).slice(0, 32)],
  );
  assert.equal(f.events.filter((name) => name === "case-directory").length, 4);
  assert.equal(f.events.filter((name) => name === "case-copy").length, 3);
  work.abort();
  assert.equal(
    settled(
      await effects.settle(recipe, null, {
        signal: new AbortController().signal,
        execution: execution(recipe),
      }),
    ).status,
    "RETIRED",
  );
  assert.equal(f.processes.size, 0);
});

test("Darwin missing case reads, undeclared identities, extra authority and substituted context withhold provisioning", async () => {
  for (const fault of [
    "missing",
    "identity",
    "authority",
    "context",
    "account",
    "uid-alias",
    "primary-group",
    "gid-alias",
  ]) {
    const f = buildTranscripts(),
      binding = caseBinding(f),
      effects = await prepareTranscripts(f),
      recipe = darwinSystemRecipes().find(
        ({ id }) => id === "ownership.literal",
      );
    f.caseFault(fault);
    let first;
    await assert.rejects(
      effects.provision(recipe, {
        policyBinding: binding,
        recordPolicy: async () => {},
      }),
      (cause) => {
        first = cause;
        return true;
      },
    );
    await assert.rejects(
      effects.verifyBuild(f.prepared()),
      (cause) => cause === first,
    );
    assert.ok(!f.events.includes("case-retire"));
    assert.ok(
      ![...f.files.values()].some((entry) =>
        entry.bytes.toString().includes('"phase":"provisioned"'),
      ),
    );
  }
});

test("Darwin access provisioning holds only approved exclusive loopback endpoints", async () => {
  for (const fault of [null, "endpoint"]) {
    const f = buildTranscripts(),
      binding = caseBinding(f, "access.workspace-write"),
      effects = await prepareTranscripts(f),
      recipe = darwinSystemRecipes().find(
        ({ id }) => id === "access.workspace-write",
      );
    f.caseFault(fault);
    const operation = effects.provision(recipe, {
      policyBinding: binding,
      recordPolicy: async () => {},
    });
    if (fault) await assert.rejects(operation);
    else {
      const receipt = await operation;
      assert.equal(
        receipt.provisioning.bindings.filter(
          ({ kind }) => kind === "loopback-port",
        ).length,
        8,
      );
      assert.equal(
        settled(
          await effects.settle(recipe, null, {
            signal: new AbortController().signal,
            execution: execution(recipe),
          }),
        ).status,
        "RETIRED",
      );
    }
    assert.equal(f.events.filter((name) => name === "case-endpoint").length, 8);
  }
});

test("Darwin partial case recovery rejoins protected births and objects without setup or compilation", async () => {
  for (const fault of ["missing", "substituted", "surviving", "writer"]) {
    const f = buildTranscripts(),
      binding = caseBinding(f),
      effects = await prepareTranscripts(f),
      recipe = darwinSystemRecipes().find(
        ({ id }) => id === "ownership.literal",
      );
    f.caseFault(fault === "writer" ? "writer" : "missing");
    await assert.rejects(
      effects.provision(recipe, {
        policyBinding: binding,
        recordPolicy: async () => {},
      }),
    );
    const caseRoot =
      "/private/var/run/native-poc/cases/" + observationDigest(binding.context);
    if (fault === "substituted") f.directories.get(caseRoot).ino++;
    if (fault === "surviving") {
      const record = [...f.files.values()]
        .filter((entry) => entry.bytes.toString().startsWith("{"))
        .map((entry) => JSON.parse(entry.bytes))
        .find(
          (entry) =>
            entry.phase === "custody" && entry.record.phase === "admitted",
        ).record;
      f.processes.set(record.subjects.helper.pid, {
        status: "live",
        identity: record.subjects.helper,
        sha256: digest(f.image),
        signature: { cdhash, entitlementsSha256: hash, valid: true },
        directories: [],
      });
    }
    const request = {
        candidateSha,
        platform: "darwin",
        jobSha256: observationDigest(f.input.job),
        preparationSha256: observationDigest(null),
      },
      before = f.events.filter((name) =>
        ["case-directory", "case-copy"].includes(name),
      ).length;
    const recovered = await (
      await createSystemEffects(f.input, f.options)
    ).recover({ request, job: f.input.job, preparation: null });
    assert.equal(
      recovered.status,
      fault === "missing" ? "RETIRED" : "RETAINED",
    );
    if (fault === "missing") {
      const resumed = await (
        await createSystemEffects(f.input, f.options)
      ).recover({
        request,
        job: f.input.job,
        preparation: null,
      });
      assert.equal(resumed.status, "RETIRED");
    }
    assert.equal(
      f.events.filter((name) => ["case-directory", "case-copy"].includes(name))
        .length,
      before,
    );
    assert.equal(
      f.events.filter((name) => name.startsWith("tool:")).length,
      22,
    );
  }
});

test("fixed Darwin entry executes each ownership owner through raw custody and held observations", async () => {
  for (const mode of ["literal", "storage", ...DARWIN_OWNERSHIP_CASES]) {
    const f = buildTranscripts(),
      id = "ownership." + mode,
      binding = caseBinding(f, id, true),
      effects = await prepareTranscripts(f),
      controller = new AbortController(),
      recipe = {
        ...darwinSystemRecipes().find((entry) => entry.id === id),
        reviewSha256: hash,
      };
    let proof;
    const prepared = await effects.prepare(recipe, {
      signal: controller.signal,
      policyBinding: binding,
      recordPolicy: async (value) => {
        proof = value;
      },
    });
    assert.equal(proof.observed.policy.policy.kind, "darwin-ownership");
    if (["literal", "storage"].includes(mode)) {
      prepared.admitted = await prepared.admit();
      const value = await effects.literal(prepared, {
        signal: controller.signal,
      });
      assert.equal(
        assertDarwinLiteralObservation(
          prepared.input,
          DARWIN_LITERAL_ARGUMENTS,
          prepared.admitted.record,
          value,
        ).status,
        "OBSERVED",
      );
      assert.equal(
        value.output,
        JSON.stringify(DARWIN_LITERAL_ARGUMENTS) + "\n",
      );
    } else {
      const record = await runDarwinOwnershipCase(
        mode,
        prepared.input,
        prepared.effects,
      );
      assert.equal(
        record.status,
        "OBSERVED",
        mode + ": " + JSON.stringify(record),
      );
      assert.ok(f.events.includes("case-members"));
      assert.ok(f.events.includes("fresh-domain"));
      if (mode === "stale-identity")
        assert.ok(f.events.includes("case-signal"));
    }
    controller.abort();
    const execution = {
      id,
      effects: Object.fromEntries(
        NATIVE_EFFECT_CLASSES.map((name) => [name, { admission: "possible" }]),
      ),
    };
    const settled = await effects.settle(recipe, prepared, {
      signal: new AbortController().signal,
      execution,
    });
    assert.ok(
      Object.values(settled).every(
        (value) => value.settlement.status === "RETIRED",
      ),
    );
    assert.equal(f.processes.size, 0);
    assert.equal(
      f.events.filter((value) => value.startsWith("tool:")).length,
      22,
    );
  }
});

test("Darwin ownership admission withholds missing and additional native authority", async () => {
  for (const fault of ["subject-missing", "subject-authority"]) {
    const f = buildTranscripts(),
      binding = caseBinding(f, "ownership.literal", true),
      effects = await prepareTranscripts(f);
    f.caseFault(fault);
    await assert.rejects(
      effects.prepare(
        {
          ...darwinSystemRecipes().find(({ id }) => id === "ownership.literal"),
          reviewSha256: hash,
        },
        {
          policyBinding: binding,
          recordPolicy: async () =>
            assert.fail("Unobserved authority admitted"),
        },
      ),
    );
    assert.ok(f.events.includes("case-start"));
    assert.ok(
      !f.events.includes("case-send") || !f.events.includes("case-members"),
    );
  }
});

test("Darwin ownership rejects changed outside bytes, incomplete independent census, unknown zombies and accepted stale signalling", async () => {
  for (const fault of [
    "outside",
    "members-missing",
    "fresh-members-missing",
    "unknown-zombie",
    "stale-accepted",
  ]) {
    const f = buildTranscripts(),
      mode = fault === "stale-accepted" ? "stale-identity" : "fork-exec",
      id = "ownership." + mode,
      binding = caseBinding(f, id, true),
      effects = await prepareTranscripts(f),
      controller = new AbortController(),
      recipe = {
        ...darwinSystemRecipes().find((entry) => entry.id === id),
        reviewSha256: hash,
      },
      prepared = await effects.prepare(recipe, {
        signal: controller.signal,
        policyBinding: binding,
        recordPolicy: async () => {},
      });
    f.caseFault(fault);
    const record = await runDarwinOwnershipCase(
      mode,
      prepared.input,
      prepared.effects,
    );
    assert.equal(record.status, "FAIL");
    assert.equal(
      record.cleanup.status,
      fault === "stale-accepted" ? "RETIRED" : "RETAINED",
    );
    let first;
    await assert.rejects(
      prepared.effects.observe(mode, prepared.input, {}),
      (cause) => {
        first = cause;
        return true;
      },
    );
    await assert.rejects(
      prepared.effects.observe(mode, prepared.input, {}),
      (cause) => cause === first,
    );
    controller.abort();
    const execution = {
      id,
      effects: Object.fromEntries(
        NATIVE_EFFECT_CLASSES.map((name) => [name, { admission: "possible" }]),
      ),
    };
    const settled = await effects.settle(recipe, prepared, {
      signal: new AbortController().signal,
      execution,
    });
    assert.ok(
      Object.values(settled).every(
        (value) =>
          value.settlement.status ===
          (fault === "stale-accepted" ? "RETIRED" : "RETAINED"),
      ),
    );
  }
});

test("Darwin interrupted ownership admission recovers protected receipts without relaunching", async () => {
  for (const fault of [
    "interrupted",
    "interrupted-members",
    "surviving",
    "missing-receipt",
    "substituted",
    "pending-writer",
    "custodian-missing",
    "custodian-substituted",
    "custodian-replaced",
  ]) {
    const f = buildTranscripts(),
      id = "ownership.fork-exec",
      binding = caseBinding(f, id, true),
      effects = await prepareTranscripts(f),
      recipe = {
        ...darwinSystemRecipes().find((entry) => entry.id === id),
        reviewSha256: hash,
      };
    const prepared = await effects.prepare(recipe, {
      policyBinding: binding,
      recordPolicy: async () => {},
    });
    if (fault === "interrupted-members") {
      await prepared.effects.observe("fork-exec");
      await prepared.effects.armFault("fork-exec");
    }
    const records = [...f.files]
        .filter(([file]) =>
          file.startsWith(directory + "/darwin-case-" + id + "-"),
        )
        .map(([file, entry]) => ({ file, record: JSON.parse(entry.bytes) })),
      admission = records.find(
        ({ record }) =>
          record.phase === "custody" && record.record.phase === "admitted",
      ).record.record;
    if (fault !== "surviving")
      f.processes.delete(admission.subjects.helper.pid);
    if (fault === "missing-receipt") {
      const pin = records
        .filter(
          ({ record }) =>
            record.phase === "ownership-receipt" && record.kind === "admission",
        )
        .at(-1).record.pin;
      const root =
        "/private/var/run/native-poc/cases/" +
        observationDigest(binding.context);
      f.files.delete(root + "/custody/receipt-" + pin.index + ".json");
    }
    if (fault === "substituted")
      f.directories.get(
        "/private/var/run/native-poc/cases/" +
          observationDigest(binding.context),
      ).ino++;
    if (fault === "custodian-missing")
      for (const {
        custodian,
        owner,
        source,
        subject,
      } of f.auditCustodies.values())
        for (const identity of [custodian, owner, source, subject])
          f.processes.delete(identity.pid);
    if (["custodian-substituted", "custodian-replaced"].includes(fault))
      for (const { custodian } of f.auditCustodies.values()) {
        custodian.startMicroseconds++;
        if (fault === "custodian-replaced")
          Object.assign(f.processes.get(custodian.pid).identity, custodian);
      }
    if (fault === "pending-writer")
      f.files.delete(
        records
          .filter(({ record }) => record.phase === "ownership-receipt")
          .at(-1).file,
      );
    const request = {
        candidateSha,
        platform: "darwin",
        jobSha256: observationDigest(f.input.job),
        preparationSha256: observationDigest(null),
      },
      before = f.events.filter((name) =>
        ["case-start", "case-directory", "case-copy"].includes(name),
      ).length;
    const recovered = await (
      await createSystemEffects(f.input, f.options)
    ).recover({ request, job: f.input.job, preparation: null });
    assert.equal(
      recovered.status,
      fault.startsWith("interrupted") || fault === "surviving"
        ? "RETIRED"
        : "RETAINED",
      fault,
    );
    assert.equal(
      f.events.filter((name) =>
        ["case-start", "case-directory", "case-copy"].includes(name),
      ).length,
      before,
    );
    assert.equal(
      f.events.filter((name) => name.startsWith("tool:")).length,
      22,
    );
    if (fault === "interrupted") {
      const resumed = await (
        await createSystemEffects(f.input, f.options)
      ).recover({ request, job: f.input.job, preparation: null });
      assert.equal(resumed.status, "RETIRED");
      assert.equal(
        f.events.filter((name) =>
          ["case-start", "case-directory", "case-copy"].includes(name),
        ).length,
        before,
      );
    }
  }
});

test("Darwin interrupted audit-custody publication retains its original operation without relaunching", async () => {
  const f = buildTranscripts(),
    id = "ownership.fork-exec",
    binding = caseBinding(f, id, true),
    effects = await prepareTranscripts(f),
    recipe = {
      ...darwinSystemRecipes().find(({ id: actual }) => actual === id),
      reviewSha256: hash,
    };
  f.caseFault("session-publication");
  await assert.rejects(
    effects.prepare(recipe, {
      policyBinding: binding,
      recordPolicy: async () => assert.fail("Unpublished custody"),
    }),
  );
  const holders = [...f.auditCustodies.values()].map(
    ({ custodian }) => custodian.pid,
  );
  assert.equal(holders.length, 1);
  f.caseFault(null);
  assert.equal((await recoverTranscripts(f)).status, "RETAINED");
  assert.equal(f.events.filter((name) => name === "case-start").length, 1);
  assert.equal(f.auditCustodies.size, 1);
  assert.ok(holders.every((pid) => f.processes.has(pid)));
});

test("Darwin interrupted root-only admission retires only after independent UID absence", async () => {
  const f = buildTranscripts(),
    id = "ownership.fork-exec",
    binding = caseBinding(f, id, true),
    effects = await prepareTranscripts(f),
    recipe = {
      ...darwinSystemRecipes().find((entry) => entry.id === id),
      reviewSha256: hash,
    };
  f.caseFault("before-park");
  await assert.rejects(
    effects.prepare(recipe, {
      policyBinding: binding,
      recordPolicy: async () => assert.fail("Incomplete admission"),
    }),
  );
  const request = {
      candidateSha,
      platform: "darwin",
      jobSha256: observationDigest(f.input.job),
      preparationSha256: observationDigest(null),
    },
    before = f.events.filter((name) => name === "case-start").length;
  f.caseFault(null);
  const recovered = await (
    await createSystemEffects(f.input, f.options)
  ).recover({ request, job: f.input.job, preparation: null });
  assert.equal(recovered.status, "RETIRED");
  assert.ok(f.events.includes("case-empty"));
  assert.equal(f.events.filter((name) => name === "case-start").length, before);
  assert.equal(f.processes.size, 0);
});

test("fixed Darwin defaults withhold access owners without their separate approvals", async () => {
  const f = buildTranscripts(),
    id = "access.read-only",
    binding = caseBinding(f, id),
    effects = await prepareTranscripts(f),
    controller = new AbortController(),
    recipe = {
      ...darwinSystemRecipes().find((entry) => entry.id === id),
      reviewSha256: hash,
    };
  await assert.rejects(
    effects.prepare(recipe, {
      signal: controller.signal,
      policyBinding: binding,
      recordPolicy: async () => assert.fail("Unfinished owner admitted"),
    }),
  );
  assert.ok(!f.events.includes("case-start"));
  controller.abort();
  const execution = {
      id,
      effects: Object.fromEntries(
        NATIVE_EFFECT_CLASSES.map((name) => [name, { admission: "possible" }]),
      ),
    },
    settled = await effects.settle(recipe, null, {
      signal: new AbortController().signal,
      execution,
    });
  assert.ok(
    Object.values(settled).every(
      (value) => value.settlement.status === "RETIRED",
    ),
  );
});

test("fixed Darwin entry composes all access profiles from raw custody and BSM frames", async () => {
  for (const profile of ["read-only", "workspace-write", "trusted-command"]) {
    const f = buildTranscripts(),
      binding = accessBinding(f, profile),
      effects = await prepareTranscripts(f),
      recipe = {
        ...darwinSystemRecipes().find(({ id }) => id === "access." + profile),
        reviewSha256: hash,
      },
      controller = new AbortController();
    let proof;
    const prepared = await effects.prepare(recipe, {
      signal: controller.signal,
      policyBinding: binding,
      recordPolicy: async (value) => {
        proof = value;
      },
    });
    assert.equal(proof.observed.policy.policy.profile, profile);
    const result = await runDarwinAccessCase(prepared.input, prepared.effects);
    assert.equal(result.status, "OBSERVED");
    assert.equal(result.nativeEvidence.denials.length, 33);
    assert.equal(result.nativeEvidence.loopback.length, 4);
    controller.abort();
    const settled = await effects.settle(recipe, prepared, {
      signal: new AbortController().signal,
      execution: execution(recipe),
    });
    assert.ok(
      Object.values(settled)
        .filter(Boolean)
        .every(({ settlement }) => settlement.status === "RETIRED"),
    );
    assert.ok(
      f.events.indexOf("access-audit-close") <
        f.events.indexOf("access-controls-close"),
    );
    assert.ok(
      f.events.lastIndexOf("case-retire") <
        f.events.indexOf("access-lease-released"),
    );
    assert.equal(
      f.events.filter((name) => name.startsWith("tool:")).length,
      22,
    );
  }
});

test("fixed Darwin access retains custody on interrupted setup and rejects missing or substituted native evidence", async () => {
  for (const fault of [
    "pf-install-interrupted",
    "anchor-install-interrupted",
    "control-unavailable",
    "missing-ipc-identity",
    "audit-event-loss",
    "stale-attempt",
    "unknown-error",
    "observer-survives",
    "missing-counter-leg",
    "foreign-anchor",
    "outside-state",
  ]) {
    const f = buildTranscripts(),
      binding = accessBinding(f, "read-only"),
      effects = await prepareTranscripts(f),
      recipe = {
        ...darwinSystemRecipes().find(({ id }) => id === "access.read-only"),
        reviewSha256: hash,
      };
    f.caseFault(fault);
    if (
      [
        "pf-install-interrupted",
        "anchor-install-interrupted",
        "control-unavailable",
        "missing-ipc-identity",
      ].includes(fault)
    ) {
      await assert.rejects(
        effects.prepare(recipe, {
          signal: new AbortController().signal,
          policyBinding: binding,
          recordPolicy: async () => {},
        }),
      );
    } else {
      const prepared = await effects.prepare(recipe, {
        signal: new AbortController().signal,
        policyBinding: binding,
        recordPolicy: async () => {},
      });
      const result = await runDarwinAccessCase(
        prepared.input,
        prepared.effects,
      ).catch((cause) => ({ status: "FAIL", cause }));
      assert.equal(result.status, "FAIL", fault);
      if (fault === "observer-survives")
        await assert.rejects(
          prepared.effects.verifyPolicy(),
          (cause) => cause === f.observerFailure,
        );
      let first;
      try {
        await prepared.effects.observe();
      } catch (cause) {
        first = cause;
      }
      assert.ok(first, fault);
      await assert.rejects(
        prepared.effects.verifyPolicy(),
        (cause) => cause === first,
      );
    }
    assert.ok(!f.events.includes("access-lease-released"));
    if (
      [
        "pf-install-interrupted",
        "anchor-install-interrupted",
        "observer-survives",
      ].includes(fault)
    )
      assert.ok(!f.events.includes("access-controls-close"));
    assert.equal(
      f.events.filter((name) => name.startsWith("tool:")).length,
      22,
    );
  }
});

// Approval records are separate inputs. These fixtures inject only raw native
// frames and filesystem bytes; no family owner or proof callback is supplied.
function operationBinding(f, id) {
  const binding = caseBinding(f, id),
    experiment = f.manifest.purpose === "experiment",
    declared = f.manifest.darwinPreparation.cases.find(
      (value) => value.id === id,
    );
  const request = declared.bindings.input,
    assets = [];
  const entries = f.files
    .get(declared.custody.plan.path)
    .bytes.toString()
    .trim()
    .split("\n")
    .slice(1)
    .map((line) => {
      const [kind, pin, hex] = line.split(" ");
      return {
        kind,
        sha256: pin === "-" ? null : pin,
        path: Buffer.from(hex, "hex").toString(),
      };
    });
  const add = (kind, file, data = null, source = null) => {
    const index = entries.length + assets.length,
      sha256 = kind === "authority" ? null : digest(data);
    assets.push({ kind, path: file, sha256, source });
    if (source === null && kind !== "authority")
      f.put(file, data, ["image", "helper"].includes(kind) ? 0o555 : 0o400);
    return index;
  };
  const copy = (kind, file, data) =>
    add(
      kind,
      file,
      data,
      add(kind, sourceDirectory + "/asset-" + assets.length, data),
    );
  const dynamic = (key, paths) => {
    binding.template.bindings.push({
      id: key,
      kind: "custody",
      paths,
      minimum: null,
      maximum: null,
    });
    for (const keys of paths) {
      let value = binding.template.policy;
      for (const key of keys.slice(0, -1)) value = value[key];
      value[keys.at(-1)] = { binding: key };
    }
  };
  const finish = (input, slots, policy) => {
    if (id.startsWith("files.") || id === "git.fixed")
      entries[5].kind = entries[8].kind = "helper";
    const {
      [experiment ? "bindingSha256" : "reviewSha256"]: inputPin,
      ...reviewed
    } = input;
    const record = {
      ...(experiment ? { purpose: "experiment" } : {}),
      schemaVersion: 1,
      contextSha256: observationDigest(binding.context),
      id,
      inputSha256: observationDigest(reviewed),
      assets,
      slots,
    };
    const data = Buffer.from(JSON.stringify(record) + "\n"),
      approval = {
        path: sourceDirectory + "/operations-" + id,
        sha256: digest(data),
      };
    f.put(approval.path, data, 0o400);
    input[experiment ? "bindingSha256" : "reviewSha256"] = approval.sha256;
    declared.bindings.input = input;
    declared.bindings.operations = {
      [experiment ? "binding" : "approval"]: approval,
    };
    binding.template.policy.policy = policy;
    binding.template.policy.launch = nativePolicyLaunchData(
      request,
      DARWIN_LITERAL_ARGUMENTS,
    );
    for (const rule of binding.template.bindings.slice(0, 3))
      binding.template.policy.launch.request[rule.paths[0][2]] = {
        binding: rule.id,
      };
    const plan = [...entries, ...assets.map(({ source, ...value }) => value)];
    const bytes = encodeDarwinCustodyPlan({
      ...(experiment ? { purpose: "experiment" } : {}),
      candidateSha,
      uid: 90001,
      gid: 90002,
      entries: plan,
    });
    f.put(declared.custody.plan.path, bytes, 0o400);
    declared.custody.plan.sha256 = digest(bytes);
    return {
      binding,
      declared,
      request,
      assets,
      slots,
      plan,
      dynamic,
      approve() {
        if (experiment) return;
        binding.approval.manifestSha256 = nativePolicyTemplateDigest(
          binding.template,
        );
      },
    };
  };
  return { binding, declared, request, entries, add, copy, finish };
}

function fileBinding(f, id, fault) {
  const setup = operationBinding(f, id),
    { request, add, copy } = setup;
  const root = add("authority", request.custody + "/files"),
    outside = add("authority", path.dirname(request.custody) + "/outside");
  copy(
    "data",
    path.dirname(request.custody) + "/outside/sentinel",
    Buffer.from("outside control\n"),
  );
  const alias = add("authority", "/fixture/alias-volume");
  f.directories.set("/fixture/alias-volume", {
    uid: 0,
    gid: 0,
    mode: 0o700,
    ino: 930,
  });
  const tool = add("helper", "/usr/bin/hdiutil", f.image),
    image = add("data", "/fixture/control.dmg", bytes);
  const slots = {
    base: 1,
    root,
    outside,
    alias,
    volume: { tool, image, cdhash },
  };
  const result = setup.finish(
    {
      ...(f.manifest.purpose === "experiment"
        ? { purpose: "experiment", bindingSha256: null }
        : { reviewSha256: null }),
      request,
      base: null,
      root: null,
    },
    slots,
    {
      kind: "darwin-files",
      base: { identitySha256: null },
      root: { identitySha256: null },
      authority: { uid: 0, gid: 0, sandboxed: false },
    },
  );
  result.dynamic("file-base", [["policy", "base", "identitySha256"]]);
  result.dynamic("file-root", [["policy", "root", "identitySha256"]]);
  result.approve();
  let next = 20000,
    allocation = null,
    leaf = null,
    pending = null,
    fileHelper,
    probe,
    callers,
    reader,
    volumeOwner,
    volumeWorker,
    control;
  let messages = [],
    phase,
    operation,
    exitCode = 0,
    decision = null;
  const object = (directory, data = null) => ({
    identity: `1:2:3:${next++}:100:0:${"d".repeat(32)}`,
    namedIdentity: null,
    uid: 0,
    gid: 0,
    mode: directory ? 0o700 : 0o600,
    links: 1,
    kind: directory ? "directory" : "file",
    bytes: data,
  });
  const named = (value) => value && { ...value, namedIdentity: value.identity };
  const rootObject = (ctx, index) => {
    const value = ctx.snapshot(ctx.planEntries[index].path, true);
    return {
      ...named(object(true)),
      identity: value.identity,
      namedIdentity: value.identity,
    };
  };
  const view = (ctx) => ({
    base: rootObject(ctx, 1),
    root: rootObject(ctx, root),
    allocation: named(allocation),
    leaf: named(leaf),
    temporary: named(pending),
  });
  const frame = (ctx, kind) => {
    phase = kind;
    const objects = view(ctx);
    if (kind === "ready")
      Object.assign(objects, { allocation: null, leaf: null, temporary: null });
    messages.push({
      nonce: request.nonce,
      phase: kind,
      ...Object.fromEntries(
        Object.entries(objects).map(([key, value]) => [
          key,
          value?.identity ?? null,
        ]),
      ),
      alias: kind !== "ready" && leaf !== null && leaf === pending,
    });
  };
  const spawn = (
    ctx,
    file = setup.declared.custody.reader.path,
    uid = false,
    asid,
  ) => {
    const identity = ctx.subject(asid ?? next++);
    if (uid)
      Object.assign(identity, {
        uid: 90001,
        ruid: 90001,
        svuid: 90001,
        gid: 90002,
        rgid: 90002,
        svgid: 90002,
        auid: 90001,
      });
    ctx.live(identity, file);
    return identity;
  };
  f.operationFrames((name, args, ctx) => {
    if (name === "operation-authority")
      return { identity: ctx.helper, sandboxed: false, noLiveUid: true };
    if (name === "file-view") {
      if (fault === "missing-read") throw new Error("File read unavailable");
      return view(ctx);
    }
    if (name === "transfer" || name === "transfer-recovery") {
      messages = [];
      exitCode = 0;
      decision = null;
      control = null;
      fileHelper = spawn(ctx, request.executable.path);
      f.processes.get(fileHelper.pid).directories = [
        {
          uid: 0,
          gid: 0,
          mode: 0o700,
          fd: 3,
          dev: "1",
          ino: ctx
            .snapshot(ctx.planEntries[root].path, true)
            .identity.split(":")[3],
        },
        {
          uid: 0,
          gid: 0,
          mode: 0o700,
          fd: 4,
          dev: "1",
          ino: ctx.snapshot(request.custody, true).identity.split(":")[3],
        },
      ];
      frame(ctx, "ready");
      return { pid: fileHelper.pid };
    }
    if (name === "file-read") {
      const value = messages.shift() ?? { eof: true };
      if (fault === "interrupted" && value.phase === "complete") {
        exitCode = 126;
        return { eof: true };
      }
      return value;
    }
    if (name === "file-send" || name === "file-send-recovery") {
      const words = Buffer.from(args[0], "hex").toString().trim().split(" "),
        type = words[0],
        hex = words[4];
      if (type === "start") return null;
      if (type === "allocate") {
        allocation = object(true);
        frame(ctx, "allocated");
      } else if (type === "recover") frame(ctx, "recovered");
      else if (type === "publish" || type === "replace") {
        operation = type;
        pending = object(false, hex);
        frame(ctx, "prepared");
      } else if (type === "inspect") frame(ctx, "inspected");
      else if (type === "cleanup") frame(ctx, "removing");
      else if (type === "finish") frame(ctx, "finished");
      else if (type === "continue") {
        if (control) {
          exitCode = 126;
          decision =
            "reject-" +
            {
              parent: "identity",
              leaf: "identity",
              symlink: "symlink",
              hardlink: "hardlink",
              "cross-volume": "volume",
            }[control.kind];
          messages = [];
        } else if (phase === "prepared") {
          if (operation === "publish" && leaf) {
            pending = null;
            frame(ctx, "exists");
          } else if (operation === "publish") {
            leaf = pending;
            leaf.links = 2;
            frame(ctx, "linked");
          } else {
            leaf = pending;
            pending = null;
            frame(ctx, "published");
          }
        } else if (phase === "linked") {
          leaf.links = 1;
          pending = null;
          frame(ctx, "published");
        } else if (phase === "published") frame(ctx, "complete");
        else if (phase === "removing") {
          allocation = leaf = pending = null;
          frame(ctx, "removed");
        }
      } else assert.fail("Unexpected file command " + type);
      return null;
    }
    if (name === "file-close") {
      if (fault !== "surviving") f.processes.delete(fileHelper.pid);
      return {
        code:
          exitCode ||
          (["prepared", "linked", "published", "removing"].includes(phase)
            ? 126
            : 0),
        signal: null,
        drained: true,
        decision,
      };
    }
    if (name === "file-probe-start") {
      probe = spawn(ctx, undefined, true);
      return probe;
    }
    if (name === "file-probe-finish") {
      f.processes.delete(probe.pid);
      return { code: "EACCES" };
    }
    if (name === "file-publishers-start") {
      callers = Array.from({ length: 3 }, () => spawn(ctx));
      return callers;
    }
    if (name === "file-publishers-ack")
      return ["006f6c64ff", "006e657700ff", "7365636f6e64"];
    if (name === "file-publishers-finish") {
      callers.forEach((value) => f.processes.delete(value.pid));
      return { reaped: true };
    }
    if (name === "file-reader-start") {
      reader = spawn(ctx);
      return reader;
    }
    if (name === "file-reader-read")
      return {
        code: "OK",
        identity: leaf.identity,
        bytes: leaf.bytes,
        links: leaf.links,
      };
    if (name === "file-reader-finish") {
      f.processes.delete(reader.pid);
      return { reaped: true };
    }
    if (name === "file-control-start") {
      const kind = args[1],
        parent = ["parent", "cross-volume"].includes(kind),
        saved = parent ? allocation : leaf;
      const changed =
        kind === "hardlink"
          ? saved
          : object(parent, kind === "symlink" ? null : "foreign");
      if (kind === "hardlink") changed.links = 2;
      if (kind === "symlink")
        Object.assign(changed, { kind: "symlink", target: ".held-value" });
      if (kind === "cross-volume")
        changed.identity = changed.identity.replace(/^1:/u, "9:");
      control = {
        kind,
        saved,
        object: changed,
        mountpoint: parent ? named(object(true)) : null,
      };
      if (parent) allocation = changed;
      else leaf = changed;
      return kind === "cross-volume"
        ? { prepared: true, mountpoint: control.mountpoint }
        : {
            object: named(changed),
            saved: named(saved),
            temporary: named(pending),
          };
    }
    if (name === "file-control-read")
      return {
        object: named(control.object),
        saved: named(control.saved),
        temporary: named(pending),
      };
    if (name === "file-control-restore") {
      if (["parent", "cross-volume"].includes(control.kind))
        allocation = control.saved;
      else leaf = control.saved;
      leaf.links = 1;
      control = null;
      return { restored: true };
    }
    if (name === "file-volume-start") {
      control.volumeMode = Number(args[3]);
      volumeOwner = spawn(ctx);
      return volumeOwner;
    }
    if (name === "file-volume-worker") {
      volumeWorker = spawn(ctx, "/usr/bin/hdiutil", false, volumeOwner.asid);
      return volumeWorker;
    }
    if (name === "file-volume-run") {
      f.processes.delete(volumeWorker.pid);
      return { exitCode: 0 };
    }
    if (name === "file-volume-finish") {
      f.processes.delete(volumeOwner.pid);
      return {
        reaped: true,
        ...(control.volumeMode === 1
          ? {
              mountpoint:
                fault === "mountpoint"
                  ? { ...control.mountpoint, identity: object(true).identity }
                  : control.mountpoint,
            }
          : {}),
      };
    }
    if (name === "file-name") {
      const id = object(false).identity;
      return {
        nativeIdentity: id,
        aliasIdentity: id,
        beforeSha256: hash,
        afterSha256: hash,
      };
    }
    return undefined;
  });
  return result;
}

async function preparedOperation(f, setup, id, signal) {
  const effects = await prepareTranscripts(f),
    recipe = {
      ...darwinSystemRecipes().find((value) => value.id === id),
      reviewSha256: hash,
    };
  const prepared = await effects.prepare(recipe, {
    signal,
    policyBinding: setup.binding,
    recordPolicy: async () => {},
  });
  return { effects, recipe, prepared };
}

test("fixed Darwin file defaults execute private, publisher, reader and recovery protocols", async () => {
  for (const id of DARWIN_FILE_CASE_IDS) {
    const f = buildTranscripts(),
      setup = fileBinding(f, id),
      { effects, recipe, prepared } = await preparedOperation(f, setup, id);
    const result = await runDarwinFileCase(
      id,
      prepared.input,
      prepared.effects,
    );
    assert.equal(result.status, "OBSERVED", JSON.stringify(result));
    const settled = await effects.settle(recipe, prepared, {
      signal: new AbortController().signal,
      execution: execution(recipe),
    });
    assert.ok(
      Object.values(settled)
        .filter(Boolean)
        .every(({ settlement }) => settlement.status === "RETIRED"),
      JSON.stringify(settled),
    );
    assert.equal(f.processes.size, 0);
    assert.equal(
      f.events.filter((value) => value.startsWith("tool:")).length,
      22,
    );
  }
});

function gitBinding(f, id, fault, generatedInput) {
  const setup = operationBinding(f, id),
    { request, add, copy } = setup,
    profileBytes = (profile) =>
      f.manifest.purpose === "experiment"
        ? darwinGitPolicies({
            request,
            git: { path: request.storage + "/git" },
            metadata: request.storage + "/metadata",
          }).find((item) => item.profile === profile).bytes
        : Buffer.from("(version 1)\n(deny default)\n");
  const git = copy("helper", request.storage + "/git", f.image),
    metadata = add("authority", request.storage + "/metadata"),
    hooks = add("authority", request.storage + "/hooks");
  const outside = add("authority", path.dirname(request.custody) + "/outside");
  copy("data", path.dirname(request.custody) + "/outside/sentinel", bytes);
  const object = (kind, body) => {
    const bytes = Buffer.concat([
      Buffer.from(kind + " " + body.length + "\0"),
      body,
    ]);
    return {
      sha: createHash("sha1").update(bytes).digest("hex"),
      bytes: deflateSync(bytes),
    };
  };
  const graph = (content, parent, subject) => {
    const blob = object("blob", Buffer.from(content)),
      tree = object(
        "tree",
        Buffer.concat([
          Buffer.from("100644 content.txt\0"),
          Buffer.from(blob.sha, "hex"),
        ]),
      );
    const commit = object(
      "commit",
      Buffer.from(
        `tree ${tree.sha}\n${parent ? "parent " + parent + "\n" : ""}author Fixture <fixture@example.invalid> 100 +0000\ncommitter Fixture <fixture@example.invalid> 100 +0000\n\n${subject}\n`,
      ),
    );
    return { blob, tree, commit };
  };
  const initial = graph("base\n", null, "test(fixture): seed owned base"),
    after = graph(
      "owned edit\n",
      generatedInput?.parent ?? initial.commit.sha,
      "test(fixture): record owned edit",
    );
  const index = (sha) => {
    const bytes = Buffer.alloc(100);
    bytes.write("DIRC");
    bytes.writeUInt32BE(2, 4);
    bytes.writeUInt32BE(1, 8);
    bytes.writeUInt32BE(0o100644, 36);
    Buffer.from(sha, "hex").copy(bytes, 52);
    bytes.writeUInt16BE(11, 72);
    bytes.write("content.txt", 74);
    return Buffer.concat([bytes, createHash("sha1").update(bytes).digest()]);
  };
  const seed = (meta, work) => {
    for (const name of [
      "refs",
      "refs/heads",
      "objects",
      "logs",
      "logs/refs",
      "logs/refs/heads",
    ])
      add("authority", meta + "/" + name);
    for (const prefix of new Set(
      Object.values(initial).map((value) => value.sha.slice(0, 2)),
    ))
      add("authority", meta + "/objects/" + prefix);
    const data = {
      config: Buffer.from(
        "[core]\n\trepositoryformatversion = 0\n\tbare = false\n\tlogallrefupdates = true\n[user]\n\tname = Fixture\n\temail = fixture@example.invalid\n",
      ),
      HEAD: Buffer.from("ref: refs/heads/proof\n"),
      "refs/heads/proof": Buffer.from(initial.commit.sha + "\n"),
      index: index(initial.blob.sha),
    };
    for (const value of Object.values(initial))
      data["objects/" + value.sha.slice(0, 2) + "/" + value.sha.slice(2)] =
        value.bytes;
    for (const [name, bytes] of Object.entries(data))
      copy("data", meta + "/" + name, bytes);
    copy("data", work + "/.git", Buffer.from("gitdir: " + meta + "\n"));
    copy("data", work + "/content.txt", Buffer.from("owned edit\n"));
  };
  seed(request.storage + "/metadata", request.workspace);
  const profiles = [],
    slots = {
      git,
      metadata,
      hooks,
      outside,
      control: null,
      profiles,
      audit: null,
    };
  if (id === "git.ordinary") {
    const meta = add("authority", request.storage + "/control"),
      work = add("authority", request.storage + "/control-work"),
      hook = add("authority", request.storage + "/control-hooks"),
      helper = copy("helper", request.custody + "/git-executor", f.image);
    seed(request.storage + "/control", request.storage + "/control-work");
    slots.control = {
      metadata: meta,
      workspace: work,
      hooks: hook,
      helper,
      cdhash,
    };
    for (const profile of ["read-only", "workspace-write", "trusted-command"])
      profiles.push({
        profile,
        policy: copy(
          "data",
          request.custody + "/git-policy-" + profile,
          profileBytes(profile),
        ),
      });
    const observer = copy("helper", request.custody + "/observer", f.image),
      events = [{ event: 1, opcode: "open", classes: 1, selector: "path" }];
    slots.audit = {
      helper: { index: observer, cdhash },
      classes: 1,
      mapping: {
        sdkSha256: hash,
        abiSha256: hash,
        headerVersion: 11,
        events,
        mappingSha256: digest(JSON.stringify({ headerVersion: 11, events })),
      },
    };
  }
  const syntheticInput = {
    request,
    git: { path: request.storage + "/git", sha256: digest(f.image), cdhash },
    metadata: request.storage + "/metadata",
    hooks: request.storage + "/hooks",
    parent: initial.commit.sha,
    ...(f.manifest.purpose === "experiment"
      ? { purpose: "experiment", bindingSha256: null }
      : { reviewSha256: null }),
  };
  const result = setup.finish(syntheticInput, slots, {
    kind: "darwin-git",
    gitSha256: syntheticInput.git.sha256,
    metadata: { identitySha256: null },
    hooks: { identitySha256: null },
    authority: { uid: 0, gid: 0, sandboxed: false },
    profiles: profiles.map(({ profile }) => ({
      profile,
      seatbeltSha256: digest(profileBytes(profile)),
    })),
  });
  result.dynamic("git-metadata", [["policy", "metadata", "identitySha256"]]);
  result.dynamic("git-hooks", [["policy", "hooks", "identitySha256"]]);
  result.approve();
  const input = generatedInput ?? syntheticInput;
  let owner,
    worker,
    payload,
    mode,
    metadataIndex,
    step = 0,
    stage = "worker",
    ordinary = false,
    observer,
    sequence = 0,
    time = 0,
    auditCount = 0;
  const records = new Map(),
    pending = [];
  const word = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(n);
    return b;
  };
  const commit = (ctx) => {
    const meta = ctx.planEntries[metadataIndex].path;
    for (const value of Object.values(after))
      f.put(
        meta + "/objects/" + value.sha.slice(0, 2) + "/" + value.sha.slice(2),
        value.bytes,
        0o644,
      );
    f.put(
      meta + "/refs/heads/proof",
      Buffer.from(after.commit.sha + "\n"),
      0o644,
    );
    f.put(meta + "/index", index(after.blob.sha), 0o644);
    f.put(meta + "/logs/HEAD", Buffer.from("fixed owned reflog\n"), 0o644);
    f.put(
      meta + "/logs/refs/heads/proof",
      Buffer.from("fixed owned reflog\n"),
      0o644,
    );
  };
  const spawn = (ctx, file, asid, uid = false) => {
    const value = ctx.subject(asid);
    if (uid)
      Object.assign(value, {
        uid: input.request.uid,
        ruid: input.request.uid,
        svuid: input.request.uid,
        gid: input.request.gid,
        rgid: input.request.gid,
        svgid: input.request.gid,
        auid: input.request.uid,
      });
    ctx.live(value, file);
    return value;
  };
  f.operationFrames((name, args, ctx) => {
    if (name === "operation-authority")
      return { identity: ctx.helper, sandboxed: false, noLiveUid: true };
    if (name === "git-object") {
      const value = f.files.get(
          ctx.planEntries[Number(args[0])].path +
            "/objects/" +
            args[1].slice(0, 2) +
            "/" +
            args[1].slice(2),
        ),
        file =
          ctx.planEntries[Number(args[0])].path +
          "/objects/" +
          args[1].slice(0, 2) +
          "/" +
          args[1].slice(2);
      return {
        object: ctx.snapshot(file),
        sha256: digest(value.bytes),
        hex: value.bytes.toString("hex"),
      };
    }
    if (name === "git-start") {
      ordinary = false;
      metadataIndex = Number(args[1]);
      owner = spawn(ctx, ctx.planEntries[Number(args[4])].path, 25000);
      step = 0;
      stage = "worker";
      return owner;
    }
    if (name === "git-send") {
      if (args[0] === "S") {
        step++;
        stage = "worker";
      }
      if (args[0] === "R") {
        if (step === 4) commit(ctx);
        if (fault !== "surviving") f.processes.delete(worker.pid);
        stage = "reaped";
      }
      return null;
    }
    if (name === "git-event" && !ordinary) {
      if (step === 5)
        return { nonce: request.nonce, phase: "finished", pid: owner.pid };
      if (stage === "worker") {
        if (fault === "loader")
          throw Object.assign(new Error("Injected x64 Git loader refusal"), {
            code: "ENOEXEC",
          });
        worker = spawn(ctx, input.git.path, owner.asid);
        if (fault === "stale")
          f.processes.get(worker.pid).sha256 = "f".repeat(64);
        return { worker };
      }
      return { reaped: worker.pid, exitCode: 0, stdoutHex: "" };
    }
    if (name === "git-close") {
      f.processes.delete(owner.pid);
      return { code: 0, signal: null, drained: true };
    }
    if (name === "git-ordinary-start") {
      ordinary = true;
      mode = args[4];
      stage = "root";
      owner = spawn(ctx, request.launcher.path, 0);
      return { pid: owner.pid };
    }
    if (name === "git-event" && ordinary) {
      if (stage === "root") return { helper: owner, payload: null };
      if (stage === "payload")
        return { helper: owner, payload, controls: true };
      if (stage === "ready")
        return { nonce: request.nonce, parked: true, pid: payload.pid };
      if (stage === "worker") return { worker };
      if (stage === "outcome")
        return {
          exitCode: mode === "inspect" ? 0 : 1,
          stdoutHex:
            mode === "inspect"
              ? Buffer.from(input.parent + "\n").toString("hex")
              : "",
        };
      if (stage === "exit") return { exitCode: 0, signal: null };
    }
    if (name === "git-ordinary-release") {
      if (args[0] === "0" && args[1] === "P") {
        payload = spawn(ctx, request.executable.path, 26000 + auditCount, true);
        stage = "payload";
      } else if (args[0] === "0" && args[1] === "R") {
        payload = {
          ...payload,
          pidVersion: payload.pidVersion + (fault === "epoch-stale" ? 0 : 1),
        };
        if (fault === "epoch-birth") payload.startMicroseconds++;
        if (fault === "epoch-session") payload.asid++;
        if (fault === "epoch-credentials") payload.svuid = 0;
        ctx.live(payload, request.executable.path);
        stage = "ready";
      } else if (args[1] === "P") {
        worker = spawn(ctx, input.git.path, payload.asid, true);
        stage = "worker";
      } else if (args[1] === "R") {
        const raw = word(++auditCount),
          selector = Buffer.from(input.metadata + "/index.lock\0"),
          token = Buffer.alloc(selector.length + 3);
        token[0] = 0x23;
        token.writeUInt16BE(selector.length, 1);
        selector.copy(token, 3);
        records.set(raw.toString("hex"), {
          tokens: [
            {
              kind: "header",
              version: 11,
              event: 1,
              name: Buffer.from("open").toString("hex"),
              classes: 1,
              seconds: 200,
              milliseconds: time + 1,
            },
            {
              kind: "subject",
              pid: worker.pid,
              auid: worker.auid,
              asid: worker.asid,
              uid: worker.uid,
              gid: worker.gid,
            },
            { kind: "metadata", type: 0x23, hex: token.toString("hex") },
            {
              kind: "return",
              error: mode === "inspect" ? 0 : 1,
              result: mode === "inspect" ? 0 : -1,
            },
            { kind: "trailer" },
          ],
        });
        if (fault !== "event-loss") pending.push(word(raw.length), raw);
        f.processes.delete(worker.pid);
        stage = "outcome";
      } else if (args[1] === "S") {
        f.processes.delete(payload.pid);
        stage = "exit";
      }
      return null;
    }
    if (name === "case-resume") return { resumed: true };
    if (name === "authority") {
      const target = ctx.snapshot(ctx.planEntries[Number(args[1])].path, true),
        subject = f.processes.get(Number(args[0])).identity;
      return {
        subject,
        object: target,
        path: Buffer.from(ctx.planEntries[Number(args[1])].path).toString(
          "hex",
        ),
        aclSha256: hash,
        sandboxed: true,
        decisions: [0, 1, 1, 1, 1],
      };
    }
    if (name === "git-ordinary-finish") {
      f.processes.delete(owner.pid);
      return { reaped: true };
    }
    if (name === "access-audit-start") {
      observer = spawn(ctx, ctx.planEntries[Number(args[0])].path, 0);
      return { identity: observer };
    }
    if (name === "access-audit") {
      let data;
      if (args[0] === "A") data = word(0);
      else if (args[0] === "S")
        data = Buffer.concat([
          word(0xffffffff),
          word(auditCount * 4),
          word(auditCount),
        ]);
      else {
        time += 2;
        data = Buffer.concat([
          ...pending.splice(0),
          word(0xfffffffe),
          word(++sequence),
          word(200),
          word(time),
        ]);
      }
      return { hex: data.toString("hex") };
    }
    if (name === "bsm") return records.get(args[0]);
    if (name === "access-audit-close") {
      f.processes.delete(observer.pid);
      return { code: 0, signal: null };
    }
    return undefined;
  });
  return result;
}

test("fixed Darwin Git defaults verify loose objects and every native Git child", async () => {
  for (const id of ["git.fixed", "git.ordinary"]) {
    const f = buildTranscripts(),
      setup = gitBinding(f, id),
      { effects, recipe, prepared } = await preparedOperation(f, setup, id);
    const result = await runDarwinGitCase(
      id === "git.fixed" ? "git.fixed-commit" : "git.ordinary-denial",
      prepared.input,
      prepared.effects,
    );
    assert.equal(result.status, "OBSERVED", JSON.stringify(result));
    const settled = await effects.settle(recipe, prepared, {
      signal: new AbortController().signal,
      execution: execution(recipe),
    });
    assert.ok(
      Object.values(settled)
        .filter(Boolean)
        .every(({ settlement }) => settlement.status === "RETIRED"),
      JSON.stringify(settled),
    );
    assert.equal(f.processes.size, 0);
    assert.equal(
      f.events.filter((value) => value.startsWith("tool:")).length,
      22,
    );
  }
});

function releaseBinding(f, fault) {
  const setup = operationBinding(f, "release"),
    { request, add } = setup,
    components = [],
    manifestComponents = [];
  const dependency = Buffer.from(f.image);
  dependency.writeUInt32LE(6, 12);
  const policy = add("data", sourceDirectory + "/release-policy", bytes);
  const metadata = {
    headerSha256: hash,
    dependencies: [],
    rpaths: [],
    sdk: 1,
    minimum: 1,
    uuid: "d".repeat(32),
  };
  for (const id of ["helper", "payload", "dyld"]) {
    const image = id === "dyld" ? dependency : f.image,
      index = add(
        "image",
        id === "dyld" ? "/usr/lib/dyld" : sourceDirectory + "/release-" + id,
        image,
      ),
      bindings = {},
      pins = {};
    for (const key of ["publication", "source", "build", "license", "abi"]) {
      const data =
        key === "build"
          ? Buffer.from(
              JSON.stringify({
                componentSha256: digest(image),
                contextSha256: observationDigest(setup.binding.context),
                osBuild: "24A100",
                sdk: 1,
                minimum: 1,
                sdkBuild: "reviewed",
              }) + "\n",
            )
          : Buffer.from("approved " + id + " " + key + "\n");
      bindings[key] = add(
        "data",
        sourceDirectory + "/release-" + id + "-" + key,
        data,
      );
      pins[key] = digest(data);
    }
    components.push({
      id,
      index,
      signature: { cdhash, entitlementsSha256: hash },
      loader: [],
      bindings,
    });
    manifestComponents.push({
      id,
      role:
        id === "helper"
          ? "helper"
          : id === "payload"
            ? "executable"
            : "dependency",
      sha256: digest(image),
      format: "macho-x64",
      loader: id === "dyld" ? [] : ["dyld"],
      bindings: pins,
    });
  }
  const dyld = components.find((value) => value.id === "dyld");
  for (const component of components.filter((value) => value.id !== "dyld"))
    component.loader.push({
      id: "dyld",
      path: "/usr/lib/dyld",
      index: dyld.index,
      cache: false,
      cacheUuid: null,
      imageUuid: null,
      signatureSha256: null,
    });
  const cache = fault?.startsWith("cache")
    ? add("cache", sourceDirectory + "/dyld-cache", bytes)
    : null;
  if (cache !== null)
    for (const component of components.filter((value) => value.id !== "dyld"))
      Object.assign(component.loader[0], {
        index: cache,
        cache: true,
        cacheUuid: "c".repeat(32),
        imageUuid: metadata.uuid,
        signatureSha256: hash,
      });
  const providers = {},
    providerSlots = {};
  for (const name of ["codex", "claude"]) {
    const record = {
      reviewSha256: hash,
      closureSha256: hash,
      members: ["dyld", "helper", "payload"],
    };
    providers[name] = record;
    providerSlots[name] = add(
      "data",
      sourceDirectory + "/package-" + name,
      Buffer.from(JSON.stringify(record) + "\n"),
    );
  }
  const authority = add(
    "data",
    sourceDirectory + "/release-authority",
    Buffer.from(
      JSON.stringify({
        schemaVersion: 1,
        contextSha256: observationDigest(setup.binding.context),
        image: "macos-15-intel",
        sdkBuild: "reviewed",
        policyTemplates: [policy],
        privileges: ["root"],
      }) + "\n",
    ),
  );
  const slots = { components, providers: providerSlots, authority };
  // The independent template binds the exact declared inventory, before reads.
  const result = setup.finish({ request, reviewSha256: null }, slots, {
    kind: "darwin-release",
    authority: { uid: 0, gid: 0, sandboxed: false },
    inventorySha256: null,
  });
  result.binding.template.policy.policy.inventorySha256 =
    result.declared.custody.plan.sha256;
  result.approve();
  const manifest = {
    schemaVersion: 2,
    candidateSha,
    platform: "darwin",
    image: "macos-15-intel",
    osBuild: "24A100",
    sdkBuild: "reviewed",
    policyTemplates: [hash],
    privileges: ["root"],
    components: manifestComponents,
    providers,
  };
  const approval = {
    candidateSha,
    platform: "darwin",
    authority: "operator-protected",
    manifestSha256: releaseClosureDigest(manifest),
  };
  f.operationFrames((name, args, ctx) => {
    if (name === "operation-authority")
      return { identity: ctx.helper, sandboxed: false, noLiveUid: true };
    if (name === "macho")
      return {
        ...metadata,
        dependencies:
          Number(args[0]) === dyld.index
            ? []
            : [Buffer.from("/usr/lib/dyld").toString("hex")],
      };
    if (name === "cache")
      return fault === "cache-missing"
        ? null
        : {
            cacheUuid:
              fault === "cache-substitution" ? "e".repeat(32) : "c".repeat(32),
            imageUuid: metadata.uuid,
            signatureSha256: hash,
            macho: metadata,
          };
    if (name === "signature" && fault === "signature")
      return { cdhash: "f".repeat(40), entitlementsSha256: hash, valid: true };
    if (name === "slots-closed" && fault === "held-reader") return [];
    if (
      name === "read" &&
      fault === "provider" &&
      Number(args[0]) === providerSlots.claude
    ) {
      const value = { ...providers.claude, reviewSha256: "f".repeat(64) };
      return { hex: Buffer.from(JSON.stringify(value) + "\n").toString("hex") };
    }
    return undefined;
  });
  return { ...result, manifest, approval };
}

test("fixed Darwin release defaults bind signed images, native loader reads and both protected packages", async () => {
  for (const fault of [undefined, "cache"]) {
    const f = buildTranscripts(),
      setup = releaseBinding(f, fault),
      { effects, recipe, prepared } = await preparedOperation(
        f,
        setup,
        "release",
      );
    const observed = await observeDarwinRelease(
      setup.manifest,
      setup.approval,
      prepared.effects,
    );
    assert.equal(observed.observation.components.length, 3);
    assert.equal(observed.observation.providers.claude.independent, true);
    const settled = await effects.settle(recipe, prepared, {
      signal: new AbortController().signal,
      execution: execution(recipe),
    });
    assert.ok(
      Object.values(settled)
        .filter(Boolean)
        .every(({ settlement }) => settlement.status === "RETIRED"),
      JSON.stringify(settled),
    );
    assert.equal(f.processes.size, 0);
    assert.equal(
      f.events.filter((value) => value.startsWith("tool:")).length,
      22,
    );
  }
});

test("Darwin file defaults retain missing native reads and surviving writers", async () => {
  const missing = buildTranscripts(),
    setup = fileBinding(missing, "files.private", "missing-read"),
    effects = await prepareTranscripts(missing);
  await assert.rejects(
    effects.prepare(
      {
        ...darwinSystemRecipes().find((value) => value.id === "files.private"),
        reviewSha256: hash,
      },
      {
        policyBinding: setup.binding,
        recordPolicy: async () => assert.fail("Missing observation admitted"),
      },
    ),
  );
  const f = buildTranscripts(),
    owner = fileBinding(f, "files.private", "surviving"),
    { prepared } = await preparedOperation(f, owner, "files.private");
  await assert.rejects(
    runDarwinFileCase("files.private", prepared.input, prepared.effects),
  );
  assert.ok(f.processes.size > 0);
});

test("Darwin Git defaults reject substituted execution identities, worker images and lost denial events", async () => {
  for (const [id, fault] of [
    ["git.fixed", "stale"],
    ["git.ordinary", "event-loss"],
    ...["epoch-birth", "epoch-session", "epoch-credentials", "epoch-stale"].map(
      (fault) => ["git.ordinary", fault],
    ),
  ]) {
    const f = buildTranscripts(),
      setup = gitBinding(f, id, fault),
      { prepared } = await preparedOperation(f, setup, id);
    const result = await runDarwinGitCase(
      id === "git.fixed" ? "git.fixed-commit" : "git.ordinary-denial",
      prepared.input,
      prepared.effects,
    );
    assert.equal(result.status, "FAIL");
    assert.equal(result.reservation, "RETAINED");
    if (fault.startsWith("epoch-"))
      assert.equal(
        f.events.filter((name) => name === "git-ordinary-release").length,
        2,
        "Rejected execution identity cannot start a worker",
      );
  }
});

test("Darwin release rejects signature, package byte and held-reader substitutions", async () => {
  for (const fault of [
    "signature",
    "provider",
    "held-reader",
    "cache-missing",
    "cache-substitution",
    "sdk",
  ]) {
    const f = buildTranscripts(),
      setup = releaseBinding(f, fault),
      { prepared } = await preparedOperation(f, setup, "release");
    if (fault === "sdk") {
      const request = f.requests.find(
        (value) => value.file === "/usr/bin/xcrun",
      );
      const file = path.join(
        directory,
        `darwin-command-${observationDigest(request)}-result.json`,
      );
      const record = JSON.parse(f.files.get(file).bytes);
      f.files.get(file).bytes = Buffer.from(
        JSON.stringify({ ...record, stdout: "different SDK build\n" }) + "\n",
      );
    }
    await assert.rejects(
      observeDarwinRelease(setup.manifest, setup.approval, prepared.effects),
    );
  }
});

test("Darwin file settlement adopts cleanup lifetime and cleans only recorded objects", async () => {
  const f = buildTranscripts(),
    setup = fileBinding(f, "files.private", "interrupted"),
    controller = new AbortController(),
    { effects, recipe, prepared } = await preparedOperation(
      f,
      setup,
      "files.private",
      controller.signal,
    );
  assert.equal(
    (await runDarwinFileCase("files.private", prepared.input, prepared.effects))
      .status,
    "FAIL",
  );
  controller.abort();
  const settled = await effects.settle(recipe, prepared, {
    signal: new AbortController().signal,
    execution: execution(recipe),
  });
  assert.ok(
    Object.values(settled)
      .filter(Boolean)
      .every(({ settlement }) => settlement.status === "RETIRED"),
    JSON.stringify(settled),
  );
  assert.ok(f.events.includes("transfer-recovery"));
  assert.equal(f.processes.size, 0);
});

test("Darwin file Git and release partial admissions rejoin protected receipts without compilation", async () => {
  for (const id of ["files.private", "git.fixed", "release"]) {
    const f = buildTranscripts(),
      setup =
        id === "release"
          ? releaseBinding(f)
          : id.startsWith("git.")
            ? gitBinding(f, id)
            : fileBinding(f, id);
    await preparedOperation(f, setup, id);
    f.processes.clear(); // Raw kernel read now reports the interrupted owner absent.
    const before = f.events.filter(
      (value) =>
        value.startsWith("tool:") ||
        ["case-directory", "case-copy"].includes(value),
    ).length;
    const request = {
      candidateSha,
      platform: "darwin",
      jobSha256: observationDigest(f.input.job),
      preparationSha256: observationDigest(null),
    };
    const recovered = await (
      await createSystemEffects(f.input, f.options)
    ).recover({ request, job: f.input.job, preparation: null });
    assert.equal(recovered.status, "RETIRED", id + JSON.stringify(recovered));
    assert.equal(
      f.events.filter(
        (value) =>
          value.startsWith("tool:") ||
          ["case-directory", "case-copy"].includes(value),
      ).length,
      before,
    );
    assert.equal(f.processes.size, 0);
  }
});

test("Darwin operation settlement rejects changed outside objects and unresolved receipt writes", async () => {
  for (const id of ["files.private", "git.fixed"]) {
    const f = buildTranscripts(),
      setup = id.startsWith("git.") ? gitBinding(f, id) : fileBinding(f, id);
    const { effects, recipe, prepared } = await preparedOperation(f, setup, id);
    const sentinel = setup.plan[setup.slots.outside].path + "/sentinel";
    f.files.get(sentinel).bytes = Buffer.from("changed outside bytes\n");
    const settled = await effects.settle(recipe, prepared, {
      signal: new AbortController().signal,
      execution: execution(recipe),
    });
    assert.ok(
      Object.values(settled)
        .filter(Boolean)
        .every(({ settlement }) => settlement.status === "RETAINED"),
    );
  }
  const f = buildTranscripts(),
    setup = fileBinding(f, "files.private");
  await preparedOperation(f, setup, "files.private");
  const prefix = directory + "/darwin-case-files.private-";
  const pending = [...f.files]
    .filter(([file]) => file.startsWith(prefix))
    .map(([file, value]) => ({ file, record: JSON.parse(value.bytes) }))
    .findLast(({ record }) => record.phase === "operation-receipt");
  f.files.delete(pending.file);
  f.processes.clear();
  const request = {
    candidateSha,
    platform: "darwin",
    jobSha256: observationDigest(f.input.job),
    preparationSha256: observationDigest(null),
  };
  const recovered = await (
    await createSystemEffects(f.input, f.options)
  ).recover({ request, job: f.input.job, preparation: null });
  assert.equal(recovered.status, "RETAINED");
  assert.ok(!f.events.includes("transfer-recovery"));
});

test("Darwin file Git and release recovery independently settles completed mutations", async () => {
  for (const id of ["files.private", "git.fixed", "release"]) {
    const f = buildTranscripts(),
      setup =
        id === "release"
          ? releaseBinding(f)
          : id.startsWith("git.")
            ? gitBinding(f, id)
            : fileBinding(f, id);
    const { prepared } = await preparedOperation(f, setup, id);
    if (id === "release")
      await observeDarwinRelease(
        setup.manifest,
        setup.approval,
        prepared.effects,
      );
    else
      assert.equal(
        (
          await (id.startsWith("git.")
            ? runDarwinGitCase(
                "git.fixed-commit",
                prepared.input,
                prepared.effects,
              )
            : runDarwinFileCase(id, prepared.input, prepared.effects))
        ).status,
        "OBSERVED",
      );
    f.processes.clear();
    const before = f.events.filter(
      (value) =>
        value.startsWith("tool:") ||
        ["case-directory", "case-copy", "git-start", "transfer"].includes(
          value,
        ),
    ).length;
    const request = {
      candidateSha,
      platform: "darwin",
      jobSha256: observationDigest(f.input.job),
      preparationSha256: observationDigest(null),
    };
    const recovered = await (
      await createSystemEffects(f.input, f.options)
    ).recover({ request, job: f.input.job, preparation: null });
    assert.equal(recovered.status, "RETIRED", id);
    assert.equal(
      f.events.filter(
        (value) =>
          value.startsWith("tool:") ||
          ["case-directory", "case-copy", "git-start", "transfer"].includes(
            value,
          ),
      ).length,
      before,
    );
    assert.equal(f.processes.size, 0);
  }
});

test("Darwin volume restoration retains a substituted owned mountpoint", async () => {
  const f = buildTranscripts(),
    setup = fileBinding(f, "files.aliases", "mountpoint");
  const { effects, recipe, prepared } = await preparedOperation(
    f,
    setup,
    "files.aliases",
  );
  const result = await runDarwinFileCase(
    "files.aliases",
    prepared.input,
    prepared.effects,
  ).catch(() => ({ status: "FAIL" }));
  assert.equal(result.status, "FAIL");
  const settled = await effects.settle(recipe, prepared, {
    signal: new AbortController().signal,
    execution: execution(recipe),
  });
  assert.ok(
    Object.values(settled)
      .filter(Boolean)
      .every(({ settlement }) => settlement.status === "RETAINED"),
  );
});

const recoveryRequest = (f) => ({
  candidateSha,
  platform: "darwin",
  jobSha256: observationDigest(f.input.job),
  preparationSha256: observationDigest(null),
});
const recoverTranscripts = async (f, signal) =>
  (await createSystemEffects(f.input, f.options)).recover({
    request: recoveryRequest(f),
    job: f.input.job,
    preparation: null,
    signal,
  });

test("Darwin recovery rejects a substituted job before fencing or cleanup", async () => {
  const f = buildTranscripts(),
    build = await createBuildEffects(f.input, f.options);
  await build.run(f.requests[0]);
  const effects = await createSystemEffects(f.input, f.options),
    job = { ...f.input.job, runId: "2", runAttempt: 2 },
    request = { ...recoveryRequest(f), jobSha256: observationDigest(job) },
    before = [...f.events],
    files = [...f.files.keys()];
  await assert.rejects(effects.recover({ request, job, preparation: null }));
  assert.deepEqual(f.events, before);
  assert.deepEqual([...f.files.keys()], files);
  assert.equal((await recoverTranscripts(f)).status, "RETIRED");
});

test("Darwin recovery fences build admission without preparation results or final images", async () => {
  const f = buildTranscripts(),
    build = await createBuildEffects(f.input, f.options);
  await build.run(f.requests[0]);
  for (const file of f.files.keys())
    if (file.endsWith("-result.json") || file.startsWith(output + "/"))
      f.files.delete(file);
  assert.equal((await recoverTranscripts(f)).status, "RETIRED");
  assert.equal(f.events.filter((name) => name.startsWith("tool:")).length, 1);
  await assert.rejects(build.run(f.requests[1]));
  assert.equal((await recoverTranscripts(f)).status, "RETIRED");
  assert.equal(f.processes.size, 0);
});

test("Darwin interrupted PF setup recovers its original reference before releasing exclusion", async () => {
  for (const fault of [
    null,
    "missing-reference",
    "substituted-root",
    "cancelled",
  ]) {
    const f = buildTranscripts(),
      binding = accessBinding(f, "read-only"),
      effects = await prepareTranscripts(f),
      recipe = {
        ...darwinSystemRecipes().find(({ id }) => id === "access.read-only"),
        reviewSha256: hash,
      };
    f.caseFault("pf-install-interrupted");
    await assert.rejects(
      effects.prepare(recipe, {
        policyBinding: binding,
        recordPolicy: async () => assert.fail("Incomplete policy"),
      }),
    );
    f.caseFault(null);
    f.processes.clear();
    if (fault === "missing-reference")
      f.files.delete(
        "/private/var/run/native-poc/cases/" +
          observationDigest(binding.context) +
          "/custody/pf-reference",
      );
    if (fault === "substituted-root") f.caseFault("recovery-root");
    const controller = new AbortController();
    if (fault === "cancelled") {
      const start = f.options.readerOptions.transport;
      f.options.readerOptions.transport = async (...args) => {
        const owner = await start(...args),
          send = owner.send;
        owner.send = async (frame) => {
          if (frame.startsWith("pf-recover")) controller.abort();
          return send.call(owner, frame);
        };
        return owner;
      };
    }
    const before = f.events.filter(
      (name) =>
        name.startsWith("tool:") ||
        ["case-directory", "case-copy", "case-start"].includes(name),
    ).length;
    const recovered = await recoverTranscripts(f, controller.signal);
    assert.equal(recovered.status, fault ? "RETAINED" : "RETIRED", fault);
    assert.equal(
      f.events.filter(
        (name) =>
          name.startsWith("tool:") ||
          ["case-directory", "case-copy", "case-start"].includes(name),
      ).length,
      before,
    );
    assert.equal(f.events.includes("access-lease-released"), fault === null);
    if (fault === null) {
      assert.ok(
        f.events.indexOf("pf-recover") <
          f.events.indexOf("access-lease-released"),
      );
      assert.equal((await recoverTranscripts(f)).status, "RETIRED");
      await assert.rejects(
        effects.prepare(recipe, {
          policyBinding: binding,
          recordPolicy: async () => {},
        }),
      );
      assert.equal(f.processes.size, 0);
    }
  }
});

test("Darwin access recovery joins drained audit and independent IPC absence after a lost cleanup result", async () => {
  const f = buildTranscripts(),
    binding = accessBinding(f, "read-only"),
    effects = await prepareTranscripts(f),
    recipe = {
      ...darwinSystemRecipes().find(({ id }) => id === "access.read-only"),
      reviewSha256: hash,
    },
    controller = new AbortController();
  const prepared = await effects.prepare(recipe, {
    signal: controller.signal,
    policyBinding: binding,
    recordPolicy: async () => {},
  });
  f.caseFault("after-controls-close");
  const observed = await runDarwinAccessCase(
    prepared.input,
    prepared.effects,
  ).catch(() => ({ status: "FAIL" }));
  assert.equal(observed.status, "FAIL");
  controller.abort();
  const settled = await effects.settle(recipe, prepared, {
    signal: new AbortController().signal,
    execution: execution(recipe),
  });
  assert.ok(
    Object.values(settled)
      .filter(Boolean)
      .every(({ settlement }) => settlement.status === "RETAINED"),
  );
  f.caseFault(null);
  const holders = new Set(
    [...f.auditCustodies.values()].map(({ custodian }) => custodian.pid),
  );
  for (const pid of f.processes.keys())
    if (!holders.has(pid)) f.processes.delete(pid);
  assert.equal((await recoverTranscripts(f)).status, "RETIRED");
  assert.ok(f.events.includes("access-controls-retired"));
  assert.ok(f.events.includes("access-lease-released"));
  assert.equal(f.events.filter((name) => name === "case-start").length, 1);
  assert.equal(
    f.events.filter((name) => name === "access-provision").length,
    1,
  );
  assert.equal(f.processes.size, 0);
});

test("Darwin interrupted pre-policy custody releases exclusion only after fresh baseline and UID absence", async () => {
  const f = buildTranscripts(),
    binding = accessBinding(f, "read-only"),
    effects = await prepareTranscripts(f),
    recipe = {
      ...darwinSystemRecipes().find(({ id }) => id === "access.read-only"),
      reviewSha256: hash,
    };
  f.operationFrames((name) => {
    if (name === "case-receipt")
      throw new Error("Interrupted initial native receipt");
  });
  await assert.rejects(
    effects.prepare(recipe, {
      policyBinding: binding,
      recordPolicy: async () => {},
    }),
  );
  assert.ok(!f.events.includes("pf-write"));
  f.operationFrames(null);
  f.processes.clear();
  assert.equal((await recoverTranscripts(f)).status, "RETIRED");
  assert.ok(f.events.includes("access-lease-released"));
  assert.ok(!f.events.includes("case-start"));
  assert.equal(f.processes.size, 0);
});

test("Darwin uncertain observation retires possible payloads and retains undrained audit and policy", async () => {
  const f = buildTranscripts(),
    binding = accessBinding(f, "workspace-write"),
    effects = await prepareTranscripts(f),
    recipe = {
      ...darwinSystemRecipes().find(
        ({ id }) => id === "access.workspace-write",
      ),
      reviewSha256: hash,
    };
  await effects.prepare(recipe, {
    policyBinding: binding,
    recordPolicy: async () => {},
  });
  const oldReader = [...f.auditCustodies.values()][0].owner,
    signals = f.events.filter((name) => name === "case-signal").length;
  assert.equal((await recoverTranscripts(f)).status, "RETAINED");
  assert.ok(
    f.processes.has(oldReader.pid),
    "Undrained capture keeps its original consumer",
  );
  assert.equal(
    f.events.filter((name) => name === "case-signal").length,
    signals,
  );
  for (const [pid, process] of f.processes)
    if (process.identity.uid === 0) f.processes.delete(pid);
  const before = f.events.filter((name) => name === "pf-write").length;
  assert.equal((await recoverTranscripts(f)).status, "RETAINED");
  assert.ok(f.events.includes("case-signal"));
  assert.equal(
    [...f.processes.values()].filter(({ identity }) => identity.uid === 90001)
      .length,
    0,
  );
  assert.equal(f.events.filter((name) => name === "pf-write").length, before);
  assert.ok(!f.events.includes("access-lease-released"));
});

test("Darwin failed build evidence cannot suppress independent case retirement", async () => {
  const f = buildTranscripts(),
    id = "ownership.fork-exec",
    binding = caseBinding(f, id, true),
    effects = await prepareTranscripts(f),
    recipe = {
      ...darwinSystemRecipes().find((entry) => entry.id === id),
      reviewSha256: hash,
    };
  await effects.prepare(recipe, {
    policyBinding: binding,
    recordPolicy: async () => {},
  });
  const command = [...f.files.values()]
    .map(({ bytes }) => {
      try {
        return JSON.parse(bytes);
      } catch {}
    })
    .find((record) => record?.phase === "helper" && record.requestSha256);
  const intent = [...f.files].find(
    ([file]) =>
      file ===
      directory + "/darwin-command-" + command.requestSha256 + "-intent.json",
  );
  const record = JSON.parse(intent[1].bytes);
  record.candidateSha = "f".repeat(40);
  intent[1].bytes = Buffer.from(JSON.stringify(record) + "\n");
  for (const [pid, process] of f.processes)
    if (
      process.identity.uid === 0 &&
      process.sha256 === f.manifest.darwinPreparation.bootstrap.reader.sha256
    )
      f.processes.delete(pid);
  assert.equal((await recoverTranscripts(f)).status, "RETAINED");
  assert.ok(f.events.includes("case-signal"));
  assert.equal(
    [...f.processes.values()].filter(({ identity }) => identity.uid === 90001)
      .length,
    0,
  );
});

test("Darwin recovery retains an unacknowledged native operation birth", async () => {
  const f = buildTranscripts(),
    setup = gitBinding(f, "git.fixed"),
    transport = f.options.readerOptions.transport,
    write = f.options.fs.writeFile;
  let interrupted = false,
    writerLost = false;
  f.options.fs.writeFile = async (...args) => {
    if (writerLost) throw new Error("Interrupted runner receipt writer");
    return write(...args);
  };
  f.options.readerOptions.transport = async (...args) => {
    const owner = await transport(...args),
      send = owner.send;
    owner.send = async (frame) => {
      await send.call(owner, frame);
      if (interrupted && frame.startsWith("git-start ")) {
        writerLost = true;
        throw new Error("Lost native helper acknowledgement");
      }
    };
    return owner;
  };
  const { prepared } = await preparedOperation(f, setup, "git.fixed");
  interrupted = true;
  await assert.rejects(
    runDarwinGitCase("git.fixed-commit", prepared.input, prepared.effects),
  );
  interrupted = writerLost = false;
  assert.ok(
    [...f.processes.values()].some(({ identity }) => identity.asid === 25000),
  );
  // Later absence cannot manufacture the missing immutable birth receipt.
  f.processes.clear();
  assert.equal((await recoverTranscripts(f)).status, "RETAINED");
});

test("Darwin recovery independently checks sealed root births without a domain acknowledgement", async () => {
  const f = buildTranscripts(),
    setup = gitBinding(f, "git.fixed"),
    write = f.options.fs.writeFile;
  let interrupted = false,
    writerLost = false;
  f.options.fs.writeFile = async (file, bytes, settings) => {
    if (writerLost) throw new Error("Interrupted runner receipt writer");
    await write(file, bytes, settings);
    const record = JSON.parse(bytes);
    if (interrupted && record.phase === "operation-receipt") {
      const value = JSON.parse(
        f.files.get(
          setup.request.custody + "/receipt-" + record.pin.index + ".json",
        ).bytes,
      );
      if (value.kind === "birth" && value.identity.asid === 25000)
        writerLost = true;
    }
  };
  const { prepared } = await preparedOperation(f, setup, "git.fixed");
  interrupted = true;
  await assert.rejects(
    runDarwinGitCase("git.fixed-commit", prepared.input, prepared.effects),
  );
  interrupted = writerLost = false;
  assert.ok(
    ![...f.files.values()]
      .map(({ bytes }) => {
        try {
          return JSON.parse(bytes);
        } catch {}
      })
      .some(
        ({ record } = {}) =>
          record?.phase === "root-domain" &&
          record.request.arguments[1] === 25000,
      ),
  );
  const root = [...f.processes.values()].find(
    ({ identity }) => identity.asid === 25000,
  );
  assert.ok(root);
  f.processes.clear();
  // The sealed parent is absent, but its independently read domain still lives.
  const descendant = { ...root.identity, pid: root.identity.pid + 10000 };
  f.processes.set(descendant.pid, { ...root, identity: descendant });
  assert.equal((await recoverTranscripts(f)).status, "RETAINED");
  f.processes.clear();
  assert.equal((await recoverTranscripts(f)).status, "RETIRED");
});

test("Darwin unreadable and undeclared recovery records cannot suppress independent case retirement", async () => {
  for (const fault of ["malformed", "undeclared", "bootstrap-phase"]) {
    const f = buildTranscripts(),
      binding = caseBinding(f, "ownership.fork-exec", true),
      effects = await prepareTranscripts(f),
      recipe = {
        ...darwinSystemRecipes().find(({ id }) => id === "ownership.fork-exec"),
        reviewSha256: hash,
      };
    await effects.prepare(recipe, {
      policyBinding: binding,
      recordPolicy: async () => {},
    });
    if (fault === "malformed") {
      const file = [...f.files].find(([name]) =>
        /^darwin-command-[a-f0-9]{64}-intent\.json$/u.test(path.basename(name)),
      );
      file[1].bytes = Buffer.from("{interrupted record\n");
    } else if (fault === "bootstrap-phase") {
      const [, entry] = [...f.files].find(([name]) =>
        /darwin-bootstrap-0-custody-0\.json$/u.test(name),
      );
      const record = JSON.parse(entry.bytes);
      record.phase = "unannounced";
      entry.bytes = Buffer.from(JSON.stringify(record) + "\n");
    } else
      f.put(
        directory + "/darwin-unannounced.json",
        Buffer.from("{}\n"),
        0o400,
        1001,
      );
    for (const [pid, process] of f.processes)
      if (process.identity.uid === 0) f.processes.delete(pid);
    assert.equal((await recoverTranscripts(f)).status, "RETAINED", fault);
    assert.ok(f.events.includes("case-signal"));
    assert.equal(
      [...f.processes.values()].filter(({ identity }) => identity.uid === 90001)
        .length,
      0,
    );
  }
});

test("Darwin recovery retains policy when sealed audit frames or independent IPC absence are missing", async () => {
  for (const fault of ["audit-frame", "audit-close", "named-ipc"]) {
    const f = buildTranscripts(),
      binding = accessBinding(f, "read-only"),
      effects = await prepareTranscripts(f),
      recipe = {
        ...darwinSystemRecipes().find(({ id }) => id === "access.read-only"),
        reviewSha256: hash,
      };
    const prepared = await effects.prepare(recipe, {
      policyBinding: binding,
      recordPolicy: async () => {},
    });
    f.caseFault("after-controls-close");
    await assert.rejects(runDarwinAccessCase(prepared.input, prepared.effects));
    f.caseFault(null);
    f.processes.clear();
    const records = [...f.files].flatMap(([file, entry]) => {
      try {
        return [{ file, record: JSON.parse(entry.bytes) }];
      } catch {
        return [];
      }
    });
    if (fault === "audit-frame") {
      const frame = records.find(
        ({ record }) => record.phase === "access-audit-frame",
      );
      frame.record.hex = "00";
      f.files.get(frame.file).bytes = Buffer.from(
        JSON.stringify(frame.record) + "\n",
      );
    } else if (fault === "audit-close") {
      const { record } = records.find(
        ({ record }) =>
          record.phase === "ownership-receipt" &&
          record.kind === "audit-closed",
      );
      f.files.delete(
        path.dirname(prepared.input.request.policy.path) +
          `/receipt-${record.pin.index}.json`,
      );
    } else
      f.operationFrames((name) =>
        name === "access-controls-retired" ? { absent: false } : undefined,
      );
    const writes = f.events.filter((name) =>
      ["pf-write", "access-pf-run"].includes(name),
    ).length;
    assert.equal((await recoverTranscripts(f)).status, "RETAINED", fault);
    assert.equal(
      f.events.filter((name) => ["pf-write", "access-pf-run"].includes(name))
        .length,
      writes,
    );
    assert.ok(!f.events.includes("access-lease-released"));
  }
});

function completeExperimentCase(f, id, mach) {
  const create = (entry) => {
    if (entry.startsWith("files.")) return fileBinding(f, entry);
    if (entry.startsWith("git.")) return gitBinding(f, entry);
    if (entry.startsWith("access."))
      return { binding: accessBinding(f, entry.slice(7), true, mach) };
    if (entry !== "release") return { binding: caseBinding(f, entry, true) };
    const setup = operationBinding(f, entry);
    return setup.finish(
      { purpose: "experiment", request: setup.request, bindingSha256: null },
      { components: [] },
      {},
    );
  };
  const cases = f.manifest.darwinPreparation.cases;
  for (const entry of cases) if (entry.id !== id) create(entry.id);
  const selected = create(id);
  if (!id.startsWith("access.")) f.access(undefined);
  for (const [i, entry] of cases.entries())
    if (entry.id !== id) {
      const request = entry.bindings.input.request ?? entry.bindings.input;
      request.uid = entry.bindings.uid = 92001 + i * 2;
      request.gid = entry.bindings.gid = 92002 + i * 2;
    }
  return {
    ...selected,
    binding: darwinExperimentCaseDeclarations(cases).policyBindings.find(
      (binding) => binding.context.executionId === id,
    ),
  };
}

test("complete Darwin experiments retain all file and Git native owners and original recovery", async () => {
  for (const id of [...DARWIN_FILE_CASE_IDS, "git.ordinary", "git.fixed"]) {
    const f = buildTranscripts(true, true),
      setup = completeExperimentCase(f, id),
      effects = createDarwinSystemEffects(f.input, f.options),
      recipe = darwinSystemRecipes().find((recipe) => recipe.id === id),
      prepared = await effects.prepare(recipe, {
        policyBinding: setup.binding,
        recordPolicy() {},
      });
    const diagnostics = [],
      result = await withNativeDiagnostics(
        () =>
          id.startsWith("files.")
            ? runDarwinFileCase(id, prepared.input, prepared.effects)
            : runDarwinGitCase(
                id === "git.fixed" ? "git.fixed-commit" : "git.ordinary-denial",
                prepared.input,
                prepared.effects,
              ),
        (owner, value) =>
          diagnostics.push(owner + ": " + value.exception?.stack),
      );
    assert.equal(result.status, "OBSERVED", id + "\n" + diagnostics.join("\n"));
    assert.equal(prepared.input.reviewSha256, undefined);
    assert.equal(
      settled(
        await effects.settle(recipe, prepared, {
          signal: new AbortController().signal,
          execution: execution(recipe),
        }),
      ).status,
      "RETIRED",
      id,
    );
    assert.equal(f.processes.size, 0);
  }
  for (const id of ["files.private", "git.fixed", "access.read-only"]) {
    const f = buildTranscripts(true, true),
      setup = completeExperimentCase(f, id),
      effects = createDarwinSystemEffects(f.input, f.options),
      recipe = darwinSystemRecipes().find((recipe) => recipe.id === id);
    await effects.bootstrap();
    if (id.startsWith("access.")) f.caseFault("pf-install-interrupted");
    await effects
      .prepare(recipe, { policyBinding: setup.binding, recordPolicy() {} })
      .catch((error) => {
        if (!id.startsWith("access.")) throw error;
      });
    f.processes.clear();
    f.caseFault(null);
    const before = f.events.filter((event) =>
        ["case-directory", "case-copy", "git-start", "transfer"].includes(
          event,
        ),
      ).length,
      request = {
        candidateSha,
        platform: "darwin",
        jobSha256: observationDigest(f.input.job),
        preparationSha256: observationDigest(f.input.preparation),
      },
      diagnostics = [],
      recovered = await withNativeDiagnostics(
        () =>
          createDarwinSystemEffects(f.input, f.options).recover({
            request,
            job: f.input.job,
            preparation: f.input.preparation,
          }),
        (owner, value) =>
          diagnostics.push(owner + ": " + value.exception?.stack),
      );
    assert.equal(
      recovered.status,
      "RETIRED",
      id + "\n" + diagnostics.join("\n"),
    );
    assert.equal(
      f.events.filter((event) =>
        ["case-directory", "case-copy", "git-start", "transfer"].includes(
          event,
        ),
      ).length,
      before,
    );
    assert.equal(f.processes.size, 0);
  }
});

test("Darwin experiment access drains capture before restoring owned PF effects over stock policy", async () => {
  const f = buildTranscripts(true),
    id = "access.read-only",
    setup = completeExperimentCase(f, id),
    effects = createDarwinSystemEffects(f.input, f.options),
    recipe = darwinSystemRecipes().find((recipe) => recipe.id === id),
    prepared = await effects.prepare(recipe, {
      policyBinding: setup.binding,
      recordPolicy() {},
    });
  assert.equal(
    (await runDarwinAccessCase(prepared.input, prepared.effects)).status,
    "OBSERVED",
  );
  assert.equal(
    settled(
      await effects.settle(recipe, prepared, {
        signal: new AbortController().signal,
        execution: execution(recipe),
      }),
    ).status,
    "RETIRED",
  );
  assert.ok(
    f.events.indexOf("access-audit-close") <
      f.events.lastIndexOf("access-pf-run"),
  );
  assert.ok(
    f.events.lastIndexOf("access-pf-run") <
      f.events.indexOf("access-lease-released"),
  );
  assert.equal(f.processes.size, 0);
});

function experimentInputs(f, build) {
  const events = [
      { event: 1, opcode: "AUE_OPEN", classes: 1, selector: "path" },
    ],
    headerVersion = 11;
  return {
    git: {
      path: "/fixture/git",
      sha256: hash,
      cdhash,
      identity: build.helpers[0].identity,
    },
    pfctl: {
      path: "/sbin/pfctl",
      sha256: hash,
      cdhash,
      identity: build.helpers[0].identity,
    },
    hdiutil: {
      path: "/usr/bin/hdiutil",
      sha256: hash,
      cdhash,
      identity: build.helpers[0].identity,
    },
    loader: {
      path: "/usr/lib/dyld",
      sha256: hash,
      identity: "held-loader",
      macho: { dependencies: [] },
    },
    volume: { path: "/fixture/control.dmg", sha256: hash },
    pf: stockPfFixture({
      active: false,
      states: 0,
      graph: [{ anchor: "", rules: [] }],
      interfaces: [{ name: "lo0", skip: false }],
      routesSha256: hash,
    }),
    audit: {
      sdkSha256: build.sdk.sha256,
      abiSha256: observationDigest(build.abi),
      headerVersion,
      events,
      mappingSha256: digest(JSON.stringify({ headerVersion, events })),
    },
    mach: {
      source: "unified-log-mach-v1",
      tool: {
        path: "/usr/bin/log",
        sha256: hash,
        cdhash,
        identity: build.helpers[0].identity,
      },
    },
    classes: 1,
    addresses: { inet: "192.0.2.1", inet6: "2001:db8::1" },
    events: Object.fromEntries(
      [
        "read",
        "write",
        "unlink",
        "replace",
        "parent",
        "unix",
        "shm",
        "sem",
        "sysv-shm",
        "sysv-sem",
        "tcp4",
        "udp4",
        "tcp6",
        "udp6",
      ].map((name) => [name, 1]),
    ),
  };
}

test("Darwin Mach access binds exact native windows, caller births, kernel sources and delivered controls", () => {
  const nonce = "b".repeat(32),
    service = "org.native-poc." + nonce,
    subject = { ...identity(4002), asid: 7001 },
    event = {
      timestamp: "2026-01-01T00:00:00.000150Z",
      processID: 0,
      processImagePath: "/kernel",
      senderImagePath:
        "/System/Library/Extensions/Sandbox.kext/Contents/MacOS/Sandbox",
      eventMessage: `Sandbox: access-fixture(${subject.pid}) deny(1) mach-lookup ${service}`,
    },
    denial = {
      nonce,
      result: -1,
      nativeCode: 1100,
      lookupCode: 1100,
      sendCode: null,
      mach: {
        source: "custody-mach-v1",
        startedAt: "2026-01-01T00:00:00.000100Z",
        endedAt: "2026-01-01T00:00:00.000200Z",
        before: subject,
        after: subject,
        receipt: null,
      },
    },
    control = {
      ...denial,
      result: 0,
      nativeCode: 0,
      lookupCode: 0,
      sendCode: 0,
      mach: {
        ...denial.mach,
        receipt: {
          nonce,
          service,
          sender: subject,
          auditToken: [
            "auid",
            "uid",
            "gid",
            "ruid",
            "rgid",
            "pid",
            "asid",
            "pidVersion",
          ].map((key) => subject[key]),
        },
      },
    },
    bind = (result, log = [event], after = subject, permitted = false) =>
      bindDarwinMachAccess(result, subject, after, {
        nonce,
        service,
        control: permitted,
        log: log.map((row) => JSON.stringify(row)).join("\n"),
      });
  assert.equal(bind(denial).error, 1100);
  assert.equal(bind(control, [], subject, true).error, 0);
  assert.match(
    darwinMachLogArguments(denial, subject, service)[1],
    /00:00:00\+0000$/u,
  );
  for (const mutate of [
    (value) => {
      value.nonce = "c".repeat(32);
    },
    (value) => {
      value.result = 0;
    },
    (value) => {
      value.lookupCode = 1102;
    },
    (value) => {
      value.nativeCode = 1;
    },
    (value) => {
      value.sendCode = 0;
    },
    (value) => {
      value.mach.before.pidVersion++;
    },
    (value) => {
      delete value.mach.after.svgid;
    },
    (value) => {
      value.mach.source = "child";
    },
    (value) => {
      value.mach.startedAt = value.mach.endedAt;
    },
  ]) {
    const value = structuredClone(denial);
    mutate(value);
    assert.throws(() => bind(value), /Unverified Darwin mach-lookup:/u);
  }
  for (const log of [
    [],
    [event, event],
    [
      {
        ...event,
        eventMessage: event.eventMessage.replace(service, service + "-wrong"),
      },
    ],
    [{ ...event, eventMessage: event.eventMessage.replace("4002", "4003") }],
    [{ ...event, eventMessage: "<private>" }],
    [
      {
        ...event,
        senderImagePath: "/fixture/Sandbox",
        subsystem: "com.apple.sandbox.reporting",
      },
    ],
    [{ ...event, processID: subject.pid }],
    [{ ...event, processImagePath: "/fixture/kernel" }],
    [{ ...event, timestamp: "2026-01-01T00:00:00.000099Z" }],
    [{ ...event, timestamp: "2026-01-01T00:00:00.000201Z" }],
  ])
    assert.throws(() => bind(denial, log), /Unverified Darwin mach-lookup:/u);
  assert.throws(
    () => bind(denial, [event], { ...subject, startMicroseconds: 4003 }),
    /mach-lookup:/u,
  );
  for (const mutate of [
    (value) => {
      value.lookupCode = 1100;
    },
    (value) => {
      value.sendCode = 268435460;
    },
    (value) => {
      value.mach.receipt = null;
    },
    (value) => {
      value.mach.receipt.auditToken[7]++;
    },
    (value) => {
      value.mach.receipt.sender.startSeconds++;
    },
    (value) => {
      value.mach.receipt.nonce = "c".repeat(32);
    },
    (value) => {
      value.mach.receipt.service += "-wrong";
    },
  ]) {
    const value = structuredClone(control);
    mutate(value);
    assert.throws(
      () => bind(value, [], subject, true),
      /Unverified Darwin mach-lookup:/u,
    );
  }
});

test("Darwin experiment access refuses legacy and mixed observation records before admission", async () => {
  const f = buildTranscripts(true),
    binding = experimentCase(f, "access.read-only"),
    declared = f.manifest.darwinPreparation.cases.find(
      ({ id }) => id === "access.read-only",
    ),
    original = JSON.parse(
      f.files.get(declared.bindings.access.binding.path).bytes,
    ),
    base = f.files
      .get(declared.custody.plan.path)
      .bytes.toString()
      .trim()
      .split("\n")
      .slice(1, 13)
      .map((line) => {
        const [kind, sha256, encoded] = line.split(" ");
        return {
          kind,
          sha256: sha256 === "-" ? null : sha256,
          path: Buffer.from(encoded, "hex").toString(),
        };
      });
  for (const mutate of [
    null,
    (value) => {
      value.schemaVersion = 1;
    },
    (value) => {
      delete value.mach;
    },
    (value) => {
      value.attempts[13].event = 2;
    },
    (value) => {
      delete value.attempts[13].source;
    },
    (value) => {
      value.attempts[13].source = "bsm";
    },
    (value) => {
      value.attempts[0].source = "unified-log-mach-v1";
    },
  ]) {
    const value = structuredClone(original),
      setup = structuredClone(declared.bindings);
    mutate?.(value);
    const bytes = Buffer.from(JSON.stringify(value) + "\n");
    setup.input.bindingSha256 = setup.access.binding.sha256 = digest(bytes);
    const load = () =>
      darwinAccessPreparation(
        { manifest: f.manifest, read: async () => bytes },
        setup,
        binding,
        base,
      );
    if (mutate) await assert.rejects(load);
    else assert.equal((await load()).attempts.length, 39);
  }
});

test("Darwin experiment input journals await real receipt admission and stay outside retirement inventories", async () => {
  const f = buildTranscripts(true),
    name = "darwin-experiment-input-0.json",
    sent = Promise.withResolvers(),
    acknowledge = Promise.withResolvers(),
    transport = f.options.readerOptions.transport;
  f.options.readerOptions.transport = async (...args) => {
    const owner = await transport(...args);
    let inputReceipt = false;
    return {
      ...owner,
      async send(frame) {
        inputReceipt =
          frame.startsWith("V ") &&
          Buffer.from(frame.split(" ")[1], "hex").toString() ===
            path.join(directory, name);
        await owner.send(frame);
      },
      async receive() {
        const actual = await owner.receive();
        if (inputReceipt) {
          sent.resolve();
          await acknowledge.promise;
          inputReceipt = false;
          f.events.push("input-receipt-acknowledged");
        }
        return actual;
      },
    };
  };
  const state = darwinPreparationContext(f.input, f.options);
  const { reader } = await state.bootstrap(),
    primary = experimentBuildFixture(),
    createReader = primary.options.createReader,
    original = new Error("Original acquisition effect failure");
  let acquiring = false;
  // Keep hosted build effects injected; the production acquisition journal must
  // cross the real receipt boundary over the raw held-file transport.
  primary.options.createReader = (...args) => {
    const injected = createReader(...args);
    return {
      ...injected,
      verifyBuildReceipt: async (pin) => {
        if (!acquiring) return injected.verifyBuildReceipt(pin);
        f.put(
          pin.path,
          JSON.stringify(primary.files.get(pin.path)) + "\n",
          0o400,
          1001,
        );
        return reader.verifyBuildReceipt(pin);
      },
    };
  };
  primary.options.acquireCases = async (prepared, build, observer, journal) => {
    acquiring = true;
    await journal({ purpose: "experiment", phase: "case-inputs-possible" });
    f.events.push("acquisition-effect");
    throw original;
  };
  const acquisition = assert.rejects(
    prepareDarwinExperiment(
      primary.job,
      directory,
      primary.persist,
      primary.options,
    ),
    (cause) => cause === original,
  );
  await Promise.race([sent.promise, acquisition]);
  assert.ok(!f.events.includes("acquisition-effect"));
  acknowledge.resolve();
  await acquisition;
  assert.ok(primary.events.includes(name));
  assert.ok(
    f.events.indexOf("input-receipt-acknowledged") <
      f.events.indexOf("acquisition-effect"),
  );
  const closed = await state.releaseBootstrap();
  assert.equal(closed.status, "RETIRED");
  assert.equal(closed.independent, true);
  assert.equal(closed.emergencyCleanup, false);
  assert.equal(closed.closed, true);
  const request = {
    candidateSha,
    platform: "darwin",
    jobSha256: observationDigest(f.input.job),
    preparationSha256: observationDigest(f.input.preparation),
  };
  let inspected = false;
  const normal = createDarwinSystemEffects(f.input, {
    ...f.options,
    recover: async ({ records }) => {
      inspected = true;
      assert.ok(records.length > 0);
      assert.ok(
        records.every(({ name }) => !name.startsWith("darwin-experiment-")),
      );
      return {
        ...retired,
        effects: Object.fromEntries(
          NATIVE_EFFECT_CLASSES.map((id) => [id, retired]),
        ),
      };
    },
  });
  const input = { request, job: f.input.job, preparation: f.input.preparation };
  assert.equal((await normal.recover(input)).status, "RETIRED");
  assert.equal(inspected, true);
  assert.equal(
    (await createDarwinSystemEffects(f.input, f.options).recover(input)).status,
    "RETIRED",
  );
  assert.equal(
    f.events.some((event) => event.startsWith("tool:")),
    false,
  );
  assert.equal(f.processes.size, 0);
});

test("Darwin input receipt and inventory admission refuse invalid or reviewed journal names", async () => {
  const invalid = buildTranscripts(true),
    state = darwinPreparationContext(invalid.input, invalid.options);
  await state.bootstrap();
  await assert.rejects(
    state.write("experiment-input-0.json", {}),
    /Unverified Darwin launch authority/,
  );
  assert.ok(
    !invalid.events.includes(
      "receipt:" + path.join(directory, "experiment-input-0.json"),
    ),
  );
  assert.equal(invalid.processes.size, 0);
  for (const [experiment, name] of [
    [true, "darwin-experiment-input-0-extra.json"],
    [true, "darwin-experiment-unexpected.json"],
    [false, "darwin-experiment-input-0.json"],
  ]) {
    const f = buildTranscripts(experiment),
      state = darwinPreparationContext(f.input, f.options);
    await state.bootstrap();
    await state.releaseBootstrap();
    f.put(path.join(directory, name), "{}\n", 0o400, 1001);
    const input = {
      request: {
        candidateSha,
        platform: "darwin",
        jobSha256: observationDigest(f.input.job),
        preparationSha256: observationDigest(f.input.preparation ?? null),
      },
      job: f.input.job,
      preparation: f.input.preparation ?? null,
    };
    let admitted = false;
    const normal = createDarwinSystemEffects(f.input, {
      ...f.options,
      recover: () => {
        admitted = true;
        return retired;
      },
    });
    assert.equal((await normal.recover(input)).status, "RETAINED", name);
    assert.equal(admitted, false, name);
    assert.equal(
      (await createDarwinSystemEffects(f.input, f.options).recover(input))
        .status,
      "RETAINED",
      name,
    );
    assert.equal(f.processes.size, 0);
  }
});

test("indexed Darwin experiment preparation seals all helpers and cold-loads without compilation or cache admission", async () => {
  const f = experimentBuildFixture();
  f.options.fs.readFile = f.options.readReceipt;
  f.options.acquireCases = async (prepared, build, reader, journal) => {
    await journal({ purpose: "experiment", phase: "case-inputs-possible" });
    return {
      inputs: experimentInputs(f, build),
      publish: async ({ path, bytes, sha256 }) => {
        assert.equal(digest(bytes), sha256);
        f.files.set(path, bytes);
      },
    };
  };
  const result = await prepareDarwinExperiment(
    f.job,
    directory,
    f.persist,
    f.options,
  );
  assert.equal(result.job.preparationEffects.settlement.status, "RETIRED");
  assert.equal(
    f.files.get(path.join(directory, "darwin-experiment-input-0.json")).phase,
    "case-inputs-possible",
  );
  assert.equal(
    result.preparation.system.cases.length,
    darwinSystemRecipes().length - 1,
  );
  assert.deepEqual(result.preparation.recipes, darwinSystemRecipes());
  assert.equal(
    result.job.preparation.expected.components.filter(
      ({ role }) => role === "helper",
    ).length,
    DARWIN_HELPER_NAMES.length,
  );
  assert.ok(
    result.job.preparation.expected.components.every(
      ({ role, loader }) => role === "helper" && loader.length === 0,
    ),
  );
  const commands = f.events.filter((event) =>
    event.startsWith("compile-owner:"),
  ).length;
  const loaded = await loadDarwinExperiment(result.job, directory, f.options);
  const reloaded = await loadDarwinExperiment(result.job, directory, f.options);
  assert.equal(observationDigest(reloaded), observationDigest(loaded));
  assert.equal(
    f.events.filter((event) => event.startsWith("compile-owner:")).length,
    commands,
  );
  assert.equal(
    observationDigest(loaded.preparation),
    observationDigest(result.preparation),
  );
  const preparationPath = path.join(
      directory,
      "darwin-experiment-preparation.json",
    ),
    original = f.files.get(preparationPath);
  for (const mutate of [
    (value) => {
      value.schemaVersion = 3;
    },
    (value) => {
      value.system.schemaVersion = 1;
    },
    (value) => {
      value.inputs.events.mach = 1;
    },
    (value) => {
      value.inputs.mach.source = "bsm";
    },
    (value) => {
      value.system.cases.find(({ id }) =>
        id.startsWith("access."),
      ).bindings.schemaVersion = 1;
    },
  ]) {
    const preparation = structuredClone(original);
    mutate(preparation);
    f.files.set(preparationPath, preparation);
    const job = {
      ...result.job,
      preparationEffects: {
        ...result.job.preparationEffects,
        receiptSha256: observationDigest({
          preparation,
          close: result.preparation.close,
        }),
      },
    };
    await assert.rejects(loadDarwinExperiment(job, directory, f.options));
  }
  f.files.set(preparationPath, original);
  for (const identity of [undefined, "substituted-loader"]) {
    const preparation = structuredClone(original);
    if (identity === undefined) delete preparation.inputs.loader.identity;
    else preparation.inputs.loader.identity = identity;
    f.files.set(preparationPath, preparation);
    await assert.rejects(
      loadDarwinExperiment(
        {
          ...result.job,
          preparationEffects: {
            ...result.job.preparationEffects,
            receiptSha256: observationDigest({
              preparation,
              close: result.preparation.close,
            }),
          },
        },
        directory,
        f.options,
      ),
    );
  }
  f.files.set(preparationPath, original);
  const before = [...f.events];
  const owner = createDarwinExperimentSystemEffects(
    loaded.job,
    loaded.preparation,
    f.options,
  );
  assert.equal(typeof owner.prepare, "function");
  assert.deepEqual(f.events, before);
  assert.equal(
    (await owner.verifyBuild(loaded.preparation)).status,
    "OBSERVED",
  );
  const binding = darwinExperimentBuildBinding(loaded.preparation);
  let compilerPolicy;
  await owner.build({
    candidateSha,
    policyBinding: binding,
    recordPolicy: async (proof) => {
      compilerPolicy = verifyExperimentPolicy(
        binding.template,
        proof.provisioning,
        binding.context,
        proof.requestSha256,
        proof.observed,
      );
    },
  });
  assert.equal(compilerPolicy.independent, true);
  assert.deepEqual(loaded.runtime, loaded.job.preparation.observed.components);
  const build = darwinSystemRecipes()[0];
  const receipts = await owner.settle(build, undefined, {
    execution: {
      id: "build",
      effects: Object.fromEntries(
        NATIVE_EFFECT_CLASSES.map((key) => [
          key,
          {
            admission: ["builds", "policy"].includes(key)
              ? "possible"
              : "not-started",
          },
        ]),
      ),
    },
  });
  assert.equal(receipts.builds.settlement.status, "RETIRED");
  const missing = structuredClone(loaded.preparation);
  missing.system.cases.pop();
  assert.throws(() =>
    createDarwinExperimentSystemEffects(loaded.job, missing, f.options),
  );
  const createReader = f.options.createReader;
  f.options.createReader = (input, settings) => {
    const reader = createReader(input, settings),
      read = reader.readBuildInput,
      close = reader.close;
    let interrupted = false;
    reader.readBuildInput = async (file, pin, ...rest) => {
      if (file.includes("experiment-asset-")) {
        interrupted = true;
        throw new Error("Original cold input read failure");
      }
      return read(file, pin, ...rest);
    };
    reader.close = async () => {
      if (interrupted)
        throw new Error("Lost cold reader close acknowledgement");
      return close();
    };
    return reader;
  };
  await assert.rejects(
    loadDarwinExperiment(result.job, directory, f.options),
    /Original cold input read failure/,
  );
  const failed = { ...result.job, failure: "preparation-failed" };
  f.options.createReader = (input, settings) => ({
    ...createReader(input, settings),
    retired: async () => {
      throw new Error("Unavailable original reader retirement");
    },
  });
  const retained = await recoverDarwinExperimentPreparation(
    failed,
    directory,
    f.persist,
    f.options,
  );
  assert.equal(retained.failure, failed.failure);
  assert.equal(retained.preparationEffects.settlement.status, "RETAINED");
  f.options.createReader = createReader;
  const recovered = await recoverDarwinExperimentPreparation(
    retained,
    directory,
    f.persist,
    f.options,
  );
  assert.equal(recovered.failure, failed.failure);
  assert.equal(recovered.preparationEffects.settlement.status, "RETIRED");
  assert.equal(
    recovered.preparationEffects.receiptSha256,
    result.job.preparationEffects.receiptSha256,
  );
  assert.deepEqual(recovered.preparation, result.job.preparation);
  assert.equal(
    f.events.filter((event) => event.startsWith("compile-owner:")).length,
    commands,
  );
  const closePath = path.join(
    directory,
    "darwin-experiment-preparation-close.json",
  );
  f.files.set(closePath, {
    ...f.files.get(closePath),
    nativeEventSha256: "e".repeat(64),
  });
  const substituted = await recoverDarwinExperimentPreparation(
    recovered,
    directory,
    f.persist,
    f.options,
  );
  assert.equal(substituted.preparationEffects.settlement.status, "RETAINED");
  assert.equal(substituted.failure, failed.failure);
  f.files.set(closePath, { ...f.files.get(closePath), purpose: "reviewed" });
  const mixed = await recoverDarwinExperimentPreparation(
    substituted,
    directory,
    f.persist,
    f.options,
  );
  assert.equal(mixed.preparationEffects.settlement.status, "RETAINED");
  const legacy = { ...original, schemaVersion: 3 },
    beforeRetirement = f.events.filter(
      (event) => event === "original-retirement",
    ).length;
  f.files.set(preparationPath, legacy);
  await recoverDarwinExperimentPreparation(
    mixed,
    directory,
    f.persist,
    f.options,
  );
  assert.ok(
    f.events.filter((event) => event === "original-retirement").length >
      beforeRetirement,
  );
});

test("Darwin cold installed Git joins optional images without reacquisition and rejects lost bindings", async () => {
  for (const format of ["thin", "universal"]) {
    const custody = darwinCustodyFixture({
      purpose: "experiment",
      build: true,
      hosted: true,
      loaderFormat: format,
    });
    await custody.reader.start();
    const loader = await custody.reader.readBuildInput(
      "/usr/lib/dyld",
      digest(custody.loaderBytes),
    );
    const f = experimentBuildFixture(),
      gitPath = "/Applications/Fixture.app/Contents/Developer/usr/bin/git",
      macho = { dependencies: ["/usr/lib/libfixture.dylib"] },
      createReader = f.options.createReader;
    let fault,
      acquired = 0;
    f.options.fs.readFile = f.options.readReceipt;
    f.options.acquireCases = async (prepared, build) => {
      acquired++;
      const inputs = experimentInputs(f, build);
      inputs.loader = {
        path: "/usr/lib/dyld",
        sha256: loader.sha256,
        identity: loader.object.identity,
        macho: loader.macho,
      };
      inputs.git.path = gitPath;
      if (format === "thin") inputs.git.macho = macho;
      return {
        inputs,
        publish: async ({ path, bytes }) => f.files.set(path, bytes),
      };
    };
    f.options.createReader = (input, settings) => {
      const reader = createReader(input, settings),
        read = reader.readBuildInput,
        image = reader.readBuildImage;
      reader.readBuildInput = async (file, ...args) => {
        const actual =
          file === "/usr/lib/dyld"
            ? await custody.reader.readBuildInput(file, ...args)
            : await read(file, ...args);
        if (file === gitPath) {
          if (format === "thin") actual.macho = structuredClone(macho);
          if (fault === "bytes") actual.sha256 = "e".repeat(64);
          if (fault === "identity") actual.object.identity = "substituted-git";
          if (fault === "signature") actual.cdhash = "e".repeat(40);
          if (fault === "macho-missing") delete actual.macho;
          if (fault === "macho-changed") actual.macho.dependencies = [];
        }
        if (file === "/usr/lib/dyld" && fault === "loader-macho")
          delete actual.macho;
        if (file === "/usr/lib/dyld" && fault === "loader-macho-changed")
          actual.macho.sdk++;
        return actual;
      };
      reader.readBuildImage = async (...args) => {
        const actual = await image(...args);
        if (fault === "helper-macho") delete actual.macho;
        return actual;
      };
      return reader;
    };
    const result = await prepareDarwinExperiment(
      f.job,
      directory,
      f.persist,
      f.options,
    );
    f.options.acquire = async () =>
      assert.fail("Cold loading cannot acquire or compile");
    const loaded = await loadDarwinExperiment(result.job, directory, f.options);
    assert.equal(
      Object.hasOwn(loaded.preparation.inputs.git, "macho"),
      format === "thin",
    );
    await custody.reader.open(0);
    assert.deepEqual(
      loaded.preparation.inputs.loader.macho,
      await custody.reader.macho(0),
    );
    for (fault of [
      "bytes",
      "identity",
      "signature",
      "loader-macho",
      "loader-macho-changed",
      "helper-macho",
      ...(format === "thin" ? ["macho-missing", "macho-changed"] : []),
    ])
      await assert.rejects(
        loadDarwinExperiment(result.job, directory, f.options),
        undefined,
        `${format}: ${fault}`,
      );
    fault = undefined;
    const file = path.join(directory, "darwin-experiment-preparation.json"),
      original = f.files.get(file);
    for (const [tool, field] of [
      ["git", "identity"],
      ["git", "cdhash"],
      ["pfctl", "identity"],
      ["pfctl", "cdhash"],
      ["hdiutil", "identity"],
      ["hdiutil", "cdhash"],
      ["loader", "macho"],
    ]) {
      const preparation = structuredClone(original);
      delete preparation.inputs[tool][field];
      f.files.set(file, preparation);
      await assert.rejects(
        loadDarwinExperiment(
          {
            ...result.job,
            preparationEffects: {
              ...result.job.preparationEffects,
              receiptSha256: observationDigest({
                preparation,
                close: result.preparation.close,
              }),
            },
          },
          directory,
          f.options,
        ),
        undefined,
        `${format}: ${tool}.${field}`,
      );
    }
    f.files.set(file, original);
    await loadDarwinExperiment(result.job, directory, f.options);
    assert.equal(acquired, 1);
    await custody.reader.close();
  }
});

async function experimentRuntime(format) {
  const custody = darwinCustodyFixture({
    purpose: "experiment",
    build: true,
    hosted: true,
    loaderFormat: format,
  });
  await custody.reader.start();
  await custody.reader.open(0);
  const loader = await custody.reader.readBuildInput(
    "/usr/lib/dyld",
    digest(custody.loaderBytes),
  );
  const f = experimentBuildFixture(),
    built = await prepareDarwinExperimentBuild(
      f.job,
      directory,
      f.persist,
      f.options,
    ),
    slots = {
      components: built.build.helpers.map(({ name }, index) => ({
        id: name,
        index,
      })),
      loader: 10,
    },
    core = {
      state: {
        preparation: {
          build: built.build,
          inputs: {
            loader: {
              sha256: loader.sha256,
              identity: loader.object.identity,
              macho: loader.macho,
            },
          },
        },
      },
      current: { binding: { purpose: "experiment" } },
      specification: {
        slots,
        entries: Array.from({ length: 11 }, (_, index) => ({
          sha256: index === 10 ? loader.sha256 : hash,
        })),
      },
      persist: async () => {},
      latch: (fn) => fn,
      reader: {
        inspect: async (index) => ({
          identity:
            index === 10
              ? loader.object.identity
              : built.build.helpers[index].identity,
          uid: index === 10 ? 501 : 0,
          mode: index === 10 ? 0o777 : 0o555,
          directory: false,
        }),
        read: async (index) => (index === 10 ? custody.loaderBytes : f.image),
        signature: async () => ({ valid: true, cdhash }),
        macho: async (index) =>
          index === 10 ? custody.reader.macho(0) : built.build.helpers[0].macho,
        cache: async () =>
          assert.fail("Ordinary runtime cannot enumerate caches"),
        build: async () => built.build.abi,
      },
    };
  assert.equal(
    (await createDarwinExperimentRuntimeEffects(core).effects.observe()).status,
    "OBSERVED",
  );
  slots.components.pop();
  assert.throws(() => createDarwinExperimentRuntimeEffects(core));
  slots.components.push({ id: DARWIN_HELPER_NAMES.at(-1), index: 9 });
  const inspect = core.reader.inspect;
  core.reader.inspect = async (index) => ({
    ...(await inspect(index)),
    identity: "substituted-held-image",
  });
  await assert.rejects(
    createDarwinExperimentRuntimeEffects(core).effects.observe(),
  );
  core.reader.inspect = inspect;
  core.reader.build = async () => ({
    ...built.build.abi,
    osBuild: "changed",
  });
  await assert.rejects(
    createDarwinExperimentRuntimeEffects(core).effects.observe(),
  );
  await assert.rejects(
    observeDarwinRelease(
      {},
      {},
      createDarwinExperimentRuntimeEffects(core).effects,
    ),
  );
  await custody.reader.close();
}

test("Darwin experiment runtime requires every held helper and original loader/ABI observations", async () => {
  for (const format of ["thin", "universal"]) await experimentRuntime(format);
});

test("Darwin preparation recovery preserves failure and cannot settle admitted cases from build receipts alone", async () => {
  for (const admitted of [false, true]) {
    const f = experimentBuildFixture(),
      built = await prepareDarwinExperimentBuild(
        f.job,
        directory,
        f.persist,
        f.options,
      ),
      job = {
        ...built.job,
        failure: "preparation-failed",
        preparationEffects: {
          admission: "possible",
          settlement: {
            status: "RETAINED",
            independent: false,
            emergencyCleanup: false,
          },
          receiptSha256: null,
        },
      };
    f.options.fs.readFile = f.options.readReceipt;
    if (admitted)
      f.files.set(
        path.join(directory, "darwin-case-ownership.cancel-0.json"),
        Buffer.from("{}\n"),
      );
    const commands = f.events.filter((event) =>
        event.startsWith("compile-owner:"),
      ).length,
      published = [];
    const result = await recoverDarwinExperimentPreparation(
      job,
      directory,
      async (value) => published.push(value),
      f.options,
    );
    assert.equal(result.failure, "preparation-failed");
    assert.equal(result.preparation, null);
    assert.equal(
      result.preparationEffects.settlement.status,
      admitted ? "RETAINED" : "RETIRED",
    );
    assert.equal(
      f.events.filter((event) => event.startsWith("compile-owner:")).length,
      commands,
    );
    if (admitted)
      assert.ok(
        published.every(
          (value) => value.preparationEffects.settlement.status !== "RETIRED",
        ),
      );
  }
});

async function installedCaseAcquisition(format) {
  let selectedGit = "/Applications/Fixture.app/Contents/Developer/usr/bin/git",
    changedIdentity = false,
    changeOnRead = false,
    interfaceReads = 0;
  const f = experimentBuildFixture(),
    built = await prepareDarwinExperimentBuild(
      f.job,
      directory,
      f.persist,
      f.options,
    ),
    // Compact declaration excerpt from Apple XNU xnu-11417.140.69,
    // bsd/bsm/audit_kevents.h. Mach lookup has no declaration here.
    declarations = {
      OPEN_R: 72,
      OPEN_W: 76,
      UNLINK: 6,
      RENAME: 42,
      CONNECT: 32,
      SHMOPEN: 43035,
      SEMOPEN: 43032,
      SHMGET: 95,
      SEMGET: 109,
      SENDTO: 184,
      OPEN_RWTC: 83,
    },
    names = Object.keys(declarations),
    headerPath = path.join(
      built.prepared.environment.SDKROOT,
      "usr/include/bsm/audit_kevents.h",
    ),
    recordHeaderPath = path.join(
      built.prepared.environment.SDKROOT,
      "usr/include/bsm/audit_record.h",
    ),
    // Public XNU audit_record.h excerpt: producer contract, not hosted bytes.
    recordSource = [
      "#ifndef _BSM_AUDIT_RECORD_H_",
      "#define _BSM_AUDIT_RECORD_H_",
      "#define AUDIT_HEADER_VERSION_OLDDARWIN  1 /* In retrospect, a mistake. */",
      "#define AUDIT_HEADER_VERSION_SOLARIS    2",
      "#define AUDIT_HEADER_VERSION_OPENBSM10  10",
      "#define AUDIT_HEADER_VERSION_OPENBSM11  11",
      "#define AUDIT_HEADER_VERSION_OPENBSM    AUDIT_HEADER_VERSION_OPENBSM11",
      "#endif /* ! _BSM_AUDIT_RECORD_H_ */",
      "",
    ].join("\n"),
    records = new Map([
      [
        headerPath,
        Buffer.from(
          names
            .map((name) => `#define AUE_${name} ${declarations[name]}`)
            .join("\n"),
        ),
      ],
      [recordHeaderPath, Buffer.from(recordSource)],
      [
        "/etc/security/audit_event",
        Buffer.from(
          names
            .map(
              (name) =>
                `${declarations[name]}:AUE_${name}:event:${name === "OPEN_RWTC" ? "all,extra" : "all"}`,
            )
            .join("\n"),
        ),
      ],
      [
        "/etc/security/audit_class",
        Buffer.from("0x1:all:all events\n0x2:extra:extra events\n"),
      ],
    ]),
    commands = [],
    journal = [],
    pins = [],
    read = async (file) => records.get(file) ?? f.image,
    options = {
      ...f.options,
      fs: {
        readdir: async () => [],
        mkdir: async () => {},
        realpath: async (file) => file,
        lstat: async (file, options) => {
          const leaf =
              records.has(file) ||
              [
                selectedGit,
                "/sbin/pfctl",
                "/usr/bin/hdiutil",
                "/usr/bin/log",
                "/usr/lib/dyld",
              ].includes(file),
            number = (value) => (options?.bigint ? BigInt(value) : value);
          return {
            isFile: () => leaf,
            isDirectory: () => !leaf,
            isSymbolicLink: () => false,
            dev: number(1),
            ino: number(changedIdentity && leaf ? 2 : 1),
            uid: number(501),
            gid: number(20),
            mode: number(leaf ? 0o666 : 0o777),
            nlink: number(3),
            size: number(leaf ? (await read(file)).length : 0),
            mtimeMs: number(1),
            ctimeMs: number(1),
            mtimeNs: number(1),
            ctimeNs: number(1),
          };
        },
        readFile: read,
        open: async (file, flags) => {
          assert.ok(flags & constants.O_NOFOLLOW);
          return {
            stat: () => options.fs.lstat(file),
            read: async (buffer, offset, length, position) => {
              const data = await read(file),
                chunk = data.subarray(position, position + Math.min(length, 7));
              chunk.copy(buffer, offset);
              if (changeOnRead) changedIdentity = true;
              return { bytesRead: chunk.length };
            },
            close: async () => {},
          };
        },
        writeFile: async (file, value) => records.set(file, Buffer.from(value)),
      },
      networkInterfaces: () => {
        interfaceReads++;
        return {
          fixture: [
            { internal: true, family: "IPv6", address: "::1", scopeid: 0 },
            {
              internal: false,
              family: "IPv6",
              address: "fe80::1",
              scopeid: 7,
            },
            { internal: false, family: "IPv4", address: "192.0.2.1" },
            {
              internal: false,
              family: "IPv6",
              address: "2001:db8::1",
              scopeid: 0,
            },
          ],
        };
      },
      command: async (file, args) => {
        assert.equal(journal.at(-1).phase, "case-input-command-possible");
        commands.push([file, args]);
        if (file === "/usr/bin/sudo" && args.includes("/usr/bin/install"))
          records.set(args.at(-1), Buffer.from(await read(args.at(-2))));
        return {
          stdout: file === "/usr/bin/xcrun" ? selectedGit + "\n" : "",
          stderr: file === "/usr/bin/codesign" ? `CDHash=${cdhash}\n` : "",
        };
      },
    },
    custody = darwinCustodyFixture({
      purpose: "experiment",
      build: true,
      hosted: true,
      inputData: read,
      loaderFormat: format,
      signing: { entitlements: [["fixture.installed-tool", true]] },
    }),
    reader = {
      readBuildInput: async (file, sha256, signature) => {
        pins.push([file, sha256, signature]);
        return custody.reader.readBuildInput(file, sha256, signature);
      },
      pf: async () => kernelPfFixture(experimentInputs(f, built.build).pf),
    },
    persist = async (value) => journal.push(value);
  const gitBytes =
    format === "thin"
      ? f.image
      : Buffer.concat([Buffer.from("cafebabe00000002", "hex"), bytes]);
  records.set(selectedGit, gitBytes);
  records.set("/usr/lib/dyld", custody.loaderBytes);
  await custody.reader.start();
  const acquired = await acquireDarwinExperimentInputs(
    built.prepared,
    built.build,
    reader,
    persist,
    options,
  );
  assert.equal(
    interfaceReads,
    1,
    "both families must use one interface snapshot",
  );
  assert.deepEqual(acquired.inputs.addresses, {
    inet: "192.0.2.1",
    inet6: "2001:db8::1",
  });
  assert.equal(Object.hasOwn(acquired.inputs.events, "mach"), false);
  assert.equal(acquired.inputs.mach.source, "unified-log-mach-v1");
  assert.equal(acquired.inputs.mach.tool.path, "/usr/bin/log");
  assert.equal(acquired.inputs.audit.headerVersion, 11);
  assert.equal(acquired.inputs.audit.sdkSha256, built.build.sdk.sha256);
  assert.equal(
    acquired.inputs.audit.abiSha256,
    observationDigest(built.build.abi),
  );
  assert.equal(
    acquired.inputs.audit.mappingSha256,
    digest(
      JSON.stringify({
        headerVersion: 11,
        events: acquired.inputs.audit.events,
      }),
    ),
  );
  assert.ok(
    pins.some(
      ([file, pin]) =>
        file === recordHeaderPath && pin === digest(Buffer.from(recordSource)),
    ),
  );
  assert.ok(
    acquired.inputs.audit.events.some(
      ({ opcode }) => opcode === "AUE_OPEN_RWTC",
    ),
  );
  assert.equal(acquired.inputs.classes, 1);
  assert.equal(acquired.inputs.git.path, selectedGit);
  assert.equal(Object.hasOwn(acquired.inputs.git, "macho"), format === "thin");
  assert.equal(acquired.inputs.git.cdhash, cdhash);
  assert.ok(
    pins.some(
      ([file, pin, signature]) =>
        file === selectedGit &&
        pin === digest(gitBytes) &&
        signature === cdhash,
    ),
  );
  assert.ok(acquired.inputs.loader.identity);
  await custody.reader.open(0);
  assert.deepEqual(acquired.inputs.loader.macho, await custody.reader.macho(0));
  const system = await prepareDarwinExperimentCases(
      {
        ...built.prepared,
        bootstrap: {
          ...built.prepared.bootstrap,
          context: context("build"),
          reader: {
            ...built.prepared.bootstrap.reader,
            sha256: built.build.helpers.find(
              ({ name }) => name === "custody-reader",
            ).sha256,
          },
        },
      },
      built.build,
      acquired.inputs,
      acquired.publish,
    ),
    declared = system.cases.find(({ id }) => id === "git.fixed");
  for (const fault of [undefined, "loader"]) {
    const native = buildTranscripts(true, true);
    gitBinding(native, declared.id, fault, declared.bindings.input);
    native.manifest.darwinPreparation.cases = system.cases;
    for (const upload of system.uploads)
      native.put(upload.path, Buffer.from(upload.hex, "hex"), 0o400);
    for (const source of declared.custody.sources)
      native.put(source.path, bytes);
    native.put(selectedGit, gitBytes, 0o755, 501);
    const effects = createDarwinSystemEffects(native.input, native.options),
      recipe = darwinSystemRecipes().find(({ id }) => id === declared.id),
      prepared = await effects.prepare(recipe, {
        policyBinding: system.policyBindings.find(
          ({ context }) => context.executionId === declared.id,
        ),
        recordPolicy() {},
      }),
      copied = native.files.get(prepared.input.git.path);
    assert.deepEqual(copied.bytes, gitBytes);
    assert.equal(copied.mode, 0o550);
    assert.equal(copied.uid, 0);
    assert.equal(copied.gid, prepared.input.request.gid);
    assert.deepEqual(prepared.input.git, {
      path: declared.bindings.input.git.path,
      sha256: acquired.inputs.git.sha256,
      cdhash,
    });
    // The transcript supplies native outcomes, never portable loading proof.
    const run = () =>
      runDarwinGitCase("git.fixed-commit", prepared.input, prepared.effects);
    if (fault) {
      const diagnostics = [];
      await withNativeDiagnostics(
        () => assert.rejects(run),
        (owner, value) => {
          if (owner === "darwin-custody-command")
            diagnostics.push(value.exception);
        },
      );
      assert.ok(diagnostics.some((cause) => cause?.code === "ENOEXEC"));
    } else {
      const result = await run();
      assert.equal(result.status, "OBSERVED", JSON.stringify(result));
    }
    assert.ok(native.events.includes("git-event"));
    assert.equal(
      settled(
        await effects.settle(recipe, prepared, {
          signal: new AbortController().signal,
          execution: execution(recipe),
        }),
      ).status,
      fault ? "RETAINED" : "RETIRED",
    );
    if (!fault) assert.equal(native.processes.size, 0);
  }
  if (format === "thin") {
    const access = system.cases.find(({ id }) => id === "access.read-only"),
      pin = access.bindings.access.binding,
      record = JSON.parse(
        Buffer.from(
          system.uploads.find(({ path }) => path === pin.path).hex,
          "hex",
        ),
      );
    assert.equal(record.schemaVersion, 2);
    assert.equal(record.mach.source, acquired.inputs.mach.source);
    assert.equal(
      record.assets[record.mach.tool.index - 12].sha256,
      acquired.inputs.mach.tool.sha256,
    );
    assert.equal(record.attempts[13].event, null);
    assert.equal(record.attempts.length, 39);
    for (const [id, target] of [
      ["host-network-inet-tcp", "192.0.2.1"],
      ["host-network-inet-udp", "192.0.2.1"],
      ["host-network-inet6-tcp", "2001:db8::1"],
      ["host-network-inet6-udp", "2001:db8::1"],
      ["host-loopback-inet-tcp", "127.0.0.1"],
      ["host-loopback-inet6-tcp", "::1"],
    ])
      assert.equal(
        record.attempts.find((attempt) => attempt.id === id).target,
        target,
      );
    // Retain the separate portable BSM transcript model. The acquired Mach
    // source/tool crosses the existing full access and original-retirement path;
    // synthetic BSM tokens establish no installed/native acceptance.
    const native = buildTranscripts(true, true),
      setup = completeExperimentCase(native, access.id, acquired.inputs.mach),
      effects = createDarwinSystemEffects(native.input, native.options),
      recipe = darwinSystemRecipes().find(({ id }) => id === access.id);
    native.operationFrames(undefined);
    const bootstrap = darwinPreparationContext(native.input, native.options);
    await bootstrap.bootstrap();
    await bootstrap.releaseBootstrap();
    const prepared = await effects.prepare(recipe, {
      policyBinding: setup.binding,
      recordPolicy() {},
    });
    const result = await runDarwinAccessCase(prepared.input, prepared.effects);
    assert.equal(result.status, "OBSERVED");
    assert.equal(result.nativeEvidence.denials.length, 33);
    assert.equal(result.nativeEvidence.loopback.length, 4);
    assert.ok(native.events.includes("access-mach-log-run"));
    assert.equal(
      settled(
        await effects.settle(recipe, prepared, {
          signal: new AbortController().signal,
          execution: execution(recipe),
        }),
      ).status,
      "RETIRED",
    );
    const diagnostics = [];
    const recovery = await withNativeDiagnostics(
      () => recoverTranscripts(native),
      (owner, value) => diagnostics.push(owner + ": " + value.exception?.stack),
    );
    assert.equal(recovery.status, "RETIRED", diagnostics.join("\n"));
    native.caseFault("mach-service-survives");
    assert.equal((await recoverTranscripts(native)).status, "RETAINED");
    native.caseFault(null);
    assert.equal((await recoverTranscripts(native)).status, "RETIRED");
    assert.equal(native.processes.size, 0);
  }
  const originalPins = [...pins];
  for (let i = 0; i < 2; i++)
    for (const [file, pin, signature] of originalPins)
      assert.equal(
        (await reader.readBuildInput(file, pin, signature)).sha256,
        pin,
      );
  if (format === "thin") {
    const networkSnapshot = options.networkInterfaces,
      ipv4 = { internal: false, family: "IPv4", address: "192.0.2.1" },
      ipv6 = {
        internal: false,
        family: "IPv6",
        address: "2001:db8::1",
        scopeid: 0,
      },
      excluded = [
        { internal: true, family: "IPv6", address: "::1", scopeid: 0 },
        { internal: false, family: "IPv6", address: "fe80::1", scopeid: 7 },
        { internal: false, family: "IPv6", address: "FEBF::2", scopeid: 0 },
        { internal: false, family: "IPv6", address: "2001:db8::2", scopeid: 4 },
        {
          internal: false,
          family: "IPv6",
          address: "2001:db8::3%fixture",
          scopeid: 0,
        },
      ];
    for (const [family, inventory] of [
      ["IPv4", { external: [ipv6] }],
      ["IPv6", { external: [ipv4] }],
      ["IPv6", { external: [ipv4], excluded }],
    ]) {
      const diagnostics = [],
        before = commands.length;
      let reads = 0,
        refusal;
      options.networkInterfaces = () => {
        reads++;
        return inventory;
      };
      const acquire = () =>
        acquireDarwinExperimentInputs(
          built.prepared,
          built.build,
          reader,
          persist,
          options,
        );
      await withNativeDiagnostics(
        () =>
          assert.rejects(acquire, (cause) => {
            refusal = cause;
            return cause.message === "Unverified native tool observation";
          }),
        (owner, value) => {
          if (owner === "darwin-experiment-addresses")
            diagnostics.push(value.exception);
        },
      );
      assert.equal(reads, 1);
      assert.equal(diagnostics.length, 1);
      assert.equal(diagnostics[0].requiredFamily, family);
      assert.deepEqual(diagnostics[0].interfaces[0], {
        name: "external",
        family: family === "IPv4" ? "IPv6" : "IPv4",
        address: family === "IPv4" ? "2001:db8::1" : "192.0.2.1",
        internal: false,
        scopeId: family === "IPv4" ? 0 : null,
        exclusions: ["family-mismatch"],
      });
      if (inventory.excluded) {
        assert.deepEqual(
          diagnostics[0].interfaces.slice(1),
          excluded.map((entry, i) => ({
            name: "excluded",
            family: "IPv6",
            address: entry.address,
            internal: entry.internal,
            scopeId: entry.scopeid,
            exclusions: [i === 0 ? "internal" : "unsupported-ipv6-scope"],
          })),
        );
      }
      await withNativeDiagnostics(
        () =>
          assert.rejects(acquire, (cause) => cause.message === refusal.message),
        () => {
          throw new Error("Diagnostic sink failure");
        },
      );
      assert.ok(
        commands
          .slice(before)
          .every(
            ([file]) => !["/usr/bin/sudo", "/usr/bin/hdiutil"].includes(file),
          ),
      );
    }
    options.networkInterfaces = networkSnapshot;
    const producer = "AUDIT_HEADER_VERSION_OPENBSM",
      define = (value) => `#define ${producer} ${value}\n`,
      leaf = `#define ${producer}11 11\n`,
      alias = leaf + define(`${producer}11`),
      sample = async (source) => {
        records.set(recordHeaderPath, Buffer.from(source));
        return acquireDarwinExperimentInputs(
          built.prepared,
          built.build,
          reader,
          persist,
          options,
        );
      };
    for (const source of [
      "",
      "#define AUDIT_HEADER_VERSION 11\n",
      ...[
        "0",
        "256",
        "11U",
        "0x0b",
        "(11)",
        "11 + 1",
        "11 trailing",
        producer,
        `${producer}11`,
      ].map(define),
      "#define AUDIT_HEADER_VERSION_SOLARIS 2\n" +
        define("AUDIT_HEADER_VERSION_SOLARIS"),
      define("11") + define("11"),
      `#define FIRST_TEXT "/*"\n${define("10")}#define SECOND_TEXT "*/"\n${define("11")}`,
      `#define FIRST_CHAR '/*'\n${define("10")}#define SECOND_CHAR '*/'\n${define("11")}`,
      alias + define("12"),
      leaf + alias,
      `#define ${producer}11 12\n` + define(`${producer}11`),
      `#define ${producer}11 ${producer}\n` + define(`${producer}11`),
      `#define ${producer}() 11\n`,
      `#ifndef ${producer}\n#define ${producer}\n${alias}#endif\n`,
      `#if 1\n${alias}#endif\n`,
      `#if 0\n${define("10")}#else\n${alias}#endif\n`,
      alias + `#undef ${producer}\n`,
      `/* ${alias}`,
    ]) {
      const before = commands.length;
      await assert.rejects(sample(source), undefined, source);
      assert.ok(
        commands
          .slice(before)
          .every(
            ([file]) => !["/usr/bin/sudo", "/usr/bin/hdiutil"].includes(file),
          ),
      );
    }
    for (const [source, version] of [
      [define("17"), 17],
      [`#define ${producer}10 10\n` + define(`${producer}10`), 10],
      ["#define AUDIT_HEADER_VERSION 2\n" + alias, 11],
      [alias + `/*\n${define("12")}*/\n`, 11],
      [`#define FIRST_TEXT "/*"\n${alias}#define SECOND_TEXT "*/"\n`, 11],
    ]) {
      const actual = (await sample(source)).inputs.audit;
      assert.equal(actual.headerVersion, version);
      assert.equal(actual.sdkSha256, acquired.inputs.audit.sdkSha256);
      assert.equal(actual.abiSha256, acquired.inputs.audit.abiSha256);
      assert.equal(
        actual.mappingSha256,
        digest(
          JSON.stringify({ headerVersion: version, events: actual.events }),
        ),
      );
    }
    records.set(recordHeaderPath, Buffer.from(recordSource));
  }
  records.set(selectedGit, Buffer.alloc(bytes.length));
  await assert.rejects(
    reader.readBuildInput(selectedGit, acquired.inputs.git.sha256),
  );
  records.set(selectedGit, gitBytes);
  for (const failure of ["build-signature", "native-signature"]) {
    const invalidSignature = darwinCustodyFixture({
      purpose: "experiment",
      build: true,
      hosted: true,
      inputData: read,
      failure,
      signing: { valid: failure !== "native-signature" },
    });
    await invalidSignature.reader.start();
    await assert.rejects(
      acquireDarwinExperimentInputs(
        built.prepared,
        built.build,
        {
          ...reader,
          readBuildInput: (...args) =>
            invalidSignature.reader.readBuildInput(...args),
        },
        persist,
        options,
      ),
    );
    await invalidSignature.reader.close();
  }
  records.set(
    "/usr/lib/dyld",
    Buffer.from("missing required image observation"),
  );
  const invalidLoader = darwinCustodyFixture({
    purpose: "experiment",
    build: true,
    hosted: true,
    inputData: read,
  });
  await invalidLoader.reader.start();
  await assert.rejects(
    acquireDarwinExperimentInputs(
      built.prepared,
      built.build,
      {
        ...reader,
        readBuildInput: (...args) =>
          invalidLoader.reader.readBuildInput(...args),
      },
      persist,
      options,
    ),
  );
  await invalidLoader.reader.close();
  records.set("/usr/lib/dyld", custody.loaderBytes);
  const asset = {
    path: path.join(
      built.prepared.sourceDirectory,
      "experiment-asset-" + system.uploads.length,
    ),
    bytes,
    sha256: hash,
  };
  await acquired.publish(asset);
  assert.ok(
    pins.some(([file, sha256]) => file === asset.path && sha256 === hash),
  );
  await assert.rejects(
    acquired.publish({ ...asset, path: "/outside/experiment-asset-1" }),
  );
  records.set(headerPath, Buffer.from("#define AUE_OPEN_R 1\n"));
  const before = commands.length;
  await assert.rejects(
    acquireDarwinExperimentInputs(
      built.prepared,
      built.build,
      reader,
      persist,
      options,
    ),
  );
  assert.ok(
    commands
      .slice(before)
      .every(([file]) => !["/usr/bin/sudo", "/usr/bin/hdiutil"].includes(file)),
  );
  selectedGit = "/unrelated/git";
  await assert.rejects(
    acquireDarwinExperimentInputs(
      built.prepared,
      built.build,
      reader,
      persist,
      options,
    ),
  );
  await withNativeDiagnostics(
    () =>
      assert.rejects(
        acquireDarwinExperimentInputs(
          built.prepared,
          built.build,
          reader,
          persist,
          options,
        ),
        (cause) => cause.message !== "Diagnostic sink failure",
      ),
    () => {
      throw new Error("Diagnostic sink failure");
    },
  );
  selectedGit = acquired.inputs.git.path;
  changeOnRead = true;
  const diagnostics = [];
  await withNativeDiagnostics(
    () =>
      assert.rejects(
        acquireDarwinExperimentInputs(
          built.prepared,
          built.build,
          reader,
          persist,
          options,
        ),
      ),
    (owner, value) => {
      if (owner === "darwin-experiment-input")
        diagnostics.push(value.exception);
    },
  );
  assert.equal(diagnostics[0].canonical, selectedGit);
  assert.equal(diagnostics[0].sampled.stable, false);
  assert.equal(diagnostics[0].sampled.recheck, null);
  assert.equal(diagnostics[0].stat.uid, 501);
  changeOnRead = false;
  changedIdentity = false;
  await custody.reader.close();
}

for (const format of ["thin", "universal"])
  test(`Darwin ${format} installed Git crosses acquisition, case custody and native operations`, () =>
    installedCaseAcquisition(format));
