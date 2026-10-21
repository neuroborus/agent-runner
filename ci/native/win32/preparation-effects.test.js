import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  unlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, win32 as path } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { withNativeDiagnostics } from "../diagnostics.js";
import { createProviderEffects as fixedProviderEffects } from "../provider-effects.mjs";
import { providerPreparationFixture } from "../providers/preparation.fixture.js";
import {
  observationDigest,
  initializeNativeJob,
  nativePolicyLaunchData,
  nativePolicyContext,
  nativePolicyTemplateDigest,
  materializeNativePolicy,
  nativePackageReviewDigest,
  nativePackageInput,
  normalizeExperimentPolicyBinding,
  normalizeGitExtraction,
  normalizeNativePackageReview,
  NATIVE_EFFECT_CLASSES,
  releaseClosureDigest,
} from "../index.js";
import {
  createWindowsBuildEffects,
  createWindowsSystemEffects,
  runWindowsExperimentProofs,
  normalizeWindowsPreparation,
  WINDOWS_HELPER_NAMES,
  WINDOWS_BUILD_TOOLS,
  WINDOWS_BUILD_LIBRARIES,
  windowsCompilerArguments,
  windowsBuildOperation,
  windowsSignedPublication,
  runWindowsBuildCommand,
  windowsSystemRecipes,
  encodeWindowsCustodyPlan,
  WINDOWS_LITERAL_ARGUMENTS,
  WINDOWS_SYSTEM_PREPARATION_MS,
  WINDOWS_CUSTODY_DEADLINE_MS,
  observeWindowsRelease,
  runWindowsFileCase,
  runWindowsGitCase,
  createWindowsCustodyReader,
} from "./index.js";
import {
  runWindowsOwnershipCase,
  WINDOWS_OWNERSHIP_CASES,
} from "./ownership.js";
import { assertWindowsLiteralObservation } from "./literal.js";
import { windowsOwnershipArguments } from "./case-effects.js";
import { windowsAccessArguments } from "./case-effects.js";
import { buildWindowsPolicy } from "./policy.js";
import { runWindowsAccessCase } from "./access.js";
import { installAccessNativeFixture } from "./access-native.fixture.js";
import {
  installOperationNativeFixture,
  operationAssets,
} from "./operation-native.fixture.js";
import { createWindowsOperationReaders } from "./operation-readers.js";
import { installPackageNativeFixture } from "./package-native.fixture.js";
import { createWindowsPreparationFiles } from "./preparation-files.js";
import { compilerTrustFixture } from "./compiler-trust.fixture.js";
import {
  windowsPreparationOptions,
  windowsPreparationContext,
  recoverWindowsPreparationOwners,
} from "./preparation.js";
import { windowsClosedPreparationOwner } from "./custody-protocol.js";
import {
  readWindowsRecoveryRecords,
  recoverWindowsCases,
} from "./case-recovery.js";
import {
  WINDOWS_EXPERIMENT_SOURCES,
  windowsHostedCompilerArguments,
  openWindowsExperimentNative,
} from "./experiment-native.js";
import {
  prepareWindowsExperiment,
  recoverWindowsExperimentPreparation,
  loadWindowsExperiment,
  recoverWindowsExperimentProofs,
  createWindowsExperimentSystemEffects,
  windowsExperimentSystemInput,
} from "./experiment-preparation.js";
import { windowsExperimentGitRuntime } from "./experiment-cases.js";
import { digest, windowsLaunchDigest } from "./protocol.js";
import { inspectWindowsPe } from "./protocol.js";
import { windowsPolicyFixture } from "./policy.fixture.js";
import { decodePlan as decodeWindowsPlan, encode } from "./custody-protocol.js";
import {
  createBuildEffects,
  createSystemEffects,
  createPrerequisiteEffects,
} from "../native-effects.mjs";

const candidateSha = "b".repeat(40),
  nonce = "c".repeat(32),
  bytes = Buffer.from("reviewed fixture bytes"),
  hash = digest(bytes),
  directory = "C:\\Fixture\\report",
  output = path.join(directory, "platform-build"),
  sourceDirectory = "C:\\Fixture\\sealed";
const identity = (pid) => ({
  pid,
  userSid: "S-1-5-18",
  sessionId: 0,
  creationTime: String(10000 + pid),
});
const retired = {
  status: "RETIRED",
  independent: true,
  emergencyCleanup: false,
  nativeEventSha256: hash,
};
const context = (executionId) => ({
  candidateSha,
  platform: "win32",
  tier: "system",
  runId: "1",
  runAttempt: 1,
  jobBindingSha256: hash,
  executionId,
  closureSha256: hash,
  selectedSystemSha256: null,
});
function wiring() {
  const events = [],
    files = new Map(),
    tools = [
      {
        name: "compiler",
        path: "C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise\\VC\\Tools\\MSVC\\14.0\\bin\\Hostx64\\x64\\cl.exe",
        sha256: hash,
        version: "reviewed",
      },
      {
        name: "sdk",
        path: "C:\\Program Files (x86)\\Windows Kits\\10\\bin\\10.0\\x64\\rc.exe",
        sha256: hash,
        version: "reviewed",
      },
    ];
  const sources = [
    ...WINDOWS_HELPER_NAMES.map((name) => name + ".c"),
    "custody.h",
    "effective-reader.h",
    "account.h",
    "audit-policy-remove.h",
  ].map((name) => ({ name, sha256: hash }));
  const image = (name) => ({
    path: path.join(sourceDirectory, name + ".exe"),
    sha256: hash,
    signatureSha256: hash,
  });
  const entries = [
    ...WINDOWS_HELPER_NAMES.map((name) => ({ kind: "helper", ...image(name) })),
    { kind: "directory", path: output, sha256: null, signatureSha256: null },
    ...tools.map((entry) => ({
      kind: "image",
      path: entry.path,
      sha256: hash,
      signatureSha256: hash,
    })),
    ...sources.map((entry) => ({
      kind: "data",
      path: path.join(sourceDirectory, entry.name),
      sha256: hash,
      signatureSha256: null,
    })),
  ];
  const custody = (id) => {
    const plan = {
      path: path.join(sourceDirectory, id + "-plan"),
      sha256: null,
    };
    const data = encodeWindowsCustodyPlan({ candidateSha, nonce, entries });
    plan.sha256 = digest(data);
    files.set(plan.path, data);
    return {
      context: context(id),
      nonce,
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
      ].map((name) => ({
        path: path.join(sourceDirectory, name),
        sha256: hash,
      })),
      runnerSid: "S-1-5-21-1-2-3-1001",
      reviewSha256: hash,
      sdkSha256: hash,
      buildSha256: hash,
    };
  };
  const manifest = {
    schemaVersion: 1,
    candidateSha,
    platform: "win32",
    tools,
    helpers: WINDOWS_HELPER_NAMES.map((name) => ({
      name,
      sourceSha256: hash,
      sha256: hash,
    })),
    environment: {
      INCLUDE: "C:\\Fixture\\sdk\\include",
      LIB: "C:\\Fixture\\sdk\\lib",
      SystemRoot: "C:\\Windows",
      PATH: "C:\\Fixture\\sdk",
    },
    windowsPreparation: {
      schemaVersion: 1,
      sourceDirectory,
      sources,
      bootstrap: custody("build"),
      command: {
        helper: image("build-helper"),
        toolSignatures: { compiler: hash, sdk: hash },
        helperSignatures: Object.fromEntries(
          WINDOWS_HELPER_NAMES.map((name) => [name, hash]),
        ),
        unsignedHelpers: Object.fromEntries(
          WINDOWS_HELPER_NAMES.map((name) => [name, hash]),
        ),
      },
      cases: windowsSystemRecipes()
        .filter((entry) => entry.id !== "build")
        .map((entry) => ({
          id: entry.id,
          custody: custody(entry.id),
          bindings: {},
        })),
    },
  };
  const request = (tool, args) => ({
    candidateSha,
    platform: "win32",
    toolSha256: hash,
    file: tool.path,
    args,
    cwd: output,
    env: {
      CI: "true",
      GITHUB_ACTIONS: "true",
      LANG: "C",
      ...manifest.environment,
    },
    deadlineMs: 30000,
  });
  const requests = [
    request(tools[0], ["/Bv"]),
    request(tools[1], ["/?"]),
    ...WINDOWS_HELPER_NAMES.map((name) =>
      request(
        tools[0],
        windowsCompilerArguments(
          path.join(sourceDirectory, name + ".c"),
          path.join(output, name + ".exe"),
        ),
      ),
    ),
  ];
  const publication = (request, operation) => ({
    ...retired,
    requestSha256: observationDigest(request),
    unsignedSha256: hash,
    sourceSha256: operation.source.sha256,
    imageSha256: operation.helper.sha256,
    signatureSha256: hash,
    writerClosed: true,
    protectedDacl: true,
    settlement: retired,
  });
  const preparation = {
    schemaVersion: 1,
    status: "PASS",
    phase: "verification",
    candidateSha,
    platform: "win32",
    reviewSha256: observationDigest(manifest),
    versions: tools.map(({ name, version, sha256 }) => ({
      name,
      version,
      sha256,
    })),
    helpers: manifest.helpers.map(({ name, sha256 }) => ({ name, sha256 })),
    commands: [],
  };
  const commandResult = (request) => ({
    requestSha256: observationDigest(request),
    toolSha256: hash,
    exitCode: request.args[0] === "/Bv" ? 2 : 0,
    signal: null,
    timedOut: false,
    independent: true,
    identity: identity(11),
    helperIdentity: identity(12),
    stdout: "reviewed\n",
    stderr: "",
    nativeEventSha256: hash,
    settlement: retired,
  });
  for (const request of requests) {
    const id = observationDigest(request),
      operation = windowsBuildOperation(request, manifest, output),
      result = {
        ...commandResult(request),
        bootstrapSettlement: { ...retired, closed: true, taskRemoved: true },
      };
    if (operation.mode === "compile")
      result.publication = publication(request, operation);
    files.set(
      path.join(directory, `windows-command-${id}-intent.json`),
      Buffer.from(
        JSON.stringify({
          candidateSha,
          request,
          requestSha256: id,
          status: "POSSIBLE",
        }),
      ),
    );
    files.set(
      path.join(directory, `windows-command-${id}-result.json`),
      Buffer.from(JSON.stringify(result)),
    );
    preparation.commands.push({
      requestSha256: id,
      status: "RETIRED",
      receiptSha256: observationDigest(result),
    });
  }
  const options = {
    env: {
      CI: "true",
      GITHUB_ACTIONS: "true",
      ImageOS: "win25",
      RUNNER_TEMP: "C:\\Fixture",
    },
    fs: {
      readdir: async () =>
        [...files.keys()]
          .filter((name) => path.dirname(name) === directory)
          .map((name) => path.basename(name)),
    },
    verifyDirectory: async (value) => {
      events.push("directory");
      return {
        ...value,
        independent: true,
        held: true,
        protectedDacl: true,
        protectedParents: true,
        exclusiveWriter: true,
        candidateSha,
        nativeEventSha256: hash,
      };
    },
    readProtected: async ({ file, sha256, receipt }) => {
      events.push("read:" + file);
      const data = files.get(file) ?? (receipt ? undefined : bytes);
      assert.ok(data);
      return {
        file,
        bytes: data,
        sha256: digest(data),
        independent: true,
        held: true,
        protectedDacl: true,
        protectedParents: true,
        unchanged: true,
        immutable: true,
        identitySha256: hash,
        nativeEventSha256: hash,
      };
    },
    writeProtected: async ({ file, bytes, exclusive }) => {
      assert.equal(exclusive, true);
      assert.ok(!files.has(file));
      files.set(file, Buffer.from(bytes));
      events.push("write:" + path.basename(file));
      return {
        file,
        sha256: digest(bytes),
        independent: true,
        immutable: true,
        protectedDacl: true,
        protectedParents: true,
        exclusive: true,
        writerClosed: true,
        identitySha256: hash,
        nativeEventSha256: hash,
      };
    },
    inspectImage: () => ({ signatureSha256: hash }),
    createReader: (input) => ({
      start: async () => {
        events.push("reader:" + input.context.executionId);
        return {
          independent: true,
          helper: identity(50),
          verifier: identity(51),
          planSha256: input.plan.sha256,
        };
      },
      open: async (index) => {
        events.push("open:" + index);
      },
      close: async () => {
        events.push("close:" + input.context.executionId);
        return { ...retired, taskRemoved: true, closed: true };
      },
      beginCleanup: async () => {
        events.push("cleanup");
      },
      authorizeRestoration: async () => {
        events.push("restoration-authorized");
      },
      retainProcess: async (value) => ({
        slot: value.pid,
        observation: { identity: value },
        independent: true,
      }),
      process: async (slot) => ({
        identity: identity(slot),
        independent: true,
        retired: true,
      }),
      verifier: async (value) => value,
      build: async () => ({
        independent: true,
        major: 10,
        minor: 0,
        build: 26100,
      }),
    }),
    provisionBuild: async () => {
      events.push("build-provision");
    },
    publishBuild: async ({ request, operation }) => {
      events.push("publication");
      return publication(request, operation);
    },
    runCommand: async (request) => {
      events.push("command");
      return commandResult(request);
    },
    verifyCommands: async (commands) => {
      events.push("verify-commands");
      return {
        ...retired,
        commandsSha256: observationDigest(commands),
        noLiveMembers: true,
        tasksRemoved: true,
      };
    },
    createReaders: () => ({}),
  };
  return {
    job: { candidateSha, platform: "win32" },
    manifest,
    preparation,
    output,
    directory,
    requests,
    files,
    events,
    options,
  };
}
function policy(f, recipe) {
  const request = {
    schemaVersion: 3,
    candidateSha,
    nonce,
    restrictingSid: "S-1-5-21-4-5-6-1002",
    custody: "C:\\Fixture\\custody",
    storage: "C:\\Fixture\\storage",
    workspace: "C:\\Fixture\\storage\\work",
    launcher: {
      path: "C:\\Fixture\\custody\\launcher.exe",
      sha256: hash,
      signatureSha256: hash,
    },
    executable: {
      path: "C:\\Fixture\\storage\\fixture.exe",
      sha256: hash,
      signatureSha256: hash,
      parser: "msvc-ucrt-wmain-v1",
    },
    policy: { path: "C:\\Fixture\\custody\\policy.json", sha256: null },
    bindings: { source: hash, system: hash, closure: hash, policy: null },
  };
  let input = request,
    parameters = {};
  if (recipe.id.startsWith("access.")) {
    input = windowsPolicyFixture(
      request,
      "S-1-5-21-1-2-3-1001",
      recipe.profile,
    ).input;
    const { request: ignored, ...rest } = input;
    parameters = rest;
  }
  const template = {
      schemaVersion: 1,
      candidateSha,
      platform: "win32",
      sourceReviewSha256: hash,
      provisioningReviewSha256: hash,
      policy: {
        launch: nativePolicyLaunchData(request, WINDOWS_LITERAL_ARGUMENTS),
        policy: parameters,
      },
      bindings: [],
    },
    approval = {
      candidateSha,
      platform: "win32",
      authority: "operator-protected",
      manifestSha256: nativePolicyTemplateDigest(template),
    },
    binding = { template, approval, context: context(recipe.id) },
    provisioning = {
      schemaVersion: 1,
      context: binding.context,
      authoritySha256: hash,
      bindings: [],
      held: true,
      independent: true,
      verifierSha256: hash,
      nativeEventSha256: hash,
    },
    expected = materializeNativePolicy(
      template,
      approval,
      provisioning,
      binding.context,
    ),
    requestSha256 = windowsLaunchDigest(request, WINDOWS_LITERAL_ARGUMENTS),
    proof = {
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
  f.options.provision = async () => {
    f.events.push("provision");
    return { input, provisioning, arguments: WINDOWS_LITERAL_ARGUMENTS };
  };
  f.options.bindResources = async () => ({});
  f.options.ownerEffects = async (current) => {
    f.current = current;
    const noop = async () => {};
    const raw = Object.fromEntries(
      [
        "verifyComposition",
        "admit",
        "observe",
        "armFault",
        "fireFault",
        "recoverAndRetire",
        "verify",
        "prepare",
        "snapshot",
        "retire",
        "review",
        "open",
        "admitChild",
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
        "inspect",
        "verifySetup",
        "installPolicy",
        "verifyAuthority",
        "verifyReceipt",
        "readProvisioning",
        "readPolicy",
        "persist",
      ].map((name) => [name, noop]),
    );
    raw.readProvisioning = async () => provisioning;
    raw.readPolicy = async () => proof.observed;
    return raw;
  };
  f.options.readPolicy = async () => {
    f.events.push("policy-read");
    return proof;
  };
  f.options.retire = async () => {
    f.events.push("payload-retire");
    return { ...retired, candidateSha, nonce, noLiveMembers: true };
  };
  f.options.verifyRetirement = async () => true;
  f.options.releaseAudit = async () => {
    f.events.push("audit-release");
    return retired;
  };
  f.options.restore = async () => {
    f.events.push("policy-restore");
    return {
      status: "RESTORED",
      independent: true,
      unchangedInstalled: true,
      nativeEventSha256: hash,
    };
  };
  return { binding, proof, input, request };
}
const execution = (id) => ({
  id,
  effects: Object.fromEntries(
    NATIVE_EFFECT_CLASSES.map((name, index) => [
      name,
      { admission: index === 0 ? "not-started" : "possible" },
    ]),
  ),
});

test("Windows compiler directory forms retain vendor, edition, tool and x64 layout restrictions", () => {
  const compiler = WINDOWS_BUILD_TOOLS.find(
      ({ name }) => name === "compiler",
    ).path,
    sdk = WINDOWS_BUILD_TOOLS.find(({ name }) => name === "sdk").path,
    installed = String.raw`C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\cl.exe`;
  const versionPath = (version) =>
    installed.replace("\\18\\", `\\${version}\\`);
  for (const version of ["10", "18", "99", "2019", "2022"])
    assert.equal(compiler.test(versionPath(version)), true, version);
  for (const version of [
    "8",
    "00",
    "01",
    "018",
    "180",
    "18000",
    "202A",
    "18.0",
    "v18",
    "18-preview",
    "-18",
    "",
    "18\\..\\18",
  ])
    assert.equal(compiler.test(versionPath(version)), false, version);
  for (const file of [
    installed.replace("Program Files", "Tools"),
    installed.replace("Microsoft Visual Studio", "Visual Studio"),
    installed.replace("Enterprise", "Community"),
    installed.replace("14.51.36231", "latest"),
    installed.replace("Hostx64", "Hostx86"),
    installed.replace("\\x64\\cl.exe", "\\arm64\\cl.exe"),
    installed.replace("cl.exe", "clang-cl.exe"),
    installed + ".bak",
    installed.replaceAll("\\", "/"),
  ])
    assert.equal(compiler.test(file), false, file);
  const resourceCompiler = String.raw`C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\rc.exe`;
  assert.equal(sdk.test(resourceCompiler), true);
  assert.equal(sdk.test(resourceCompiler.replace("\\x64\\", "\\x86\\")), false);
  assert.equal(sdk.test(installed), false);
});

test("Windows build operations keep exact installed compiler bindings for major and legacy directories", () => {
  for (const version of ["18", "2022"]) {
    const file =
        String.raw`C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\cl.exe`.replace(
          "\\18\\",
          `\\${version}\\`,
        ),
      tool = { name: "compiler", path: file, sha256: hash },
      alternate = file.replace(
        `\\${version}\\`,
        version === "18" ? "\\2022\\" : "\\18\\",
      );
    assert.equal(WINDOWS_BUILD_TOOLS[0].path.test(alternate), true);
    for (const purpose of ["reviewed", "experiment"]) {
      const manifest = {
        candidateSha,
        purpose,
        tools: [tool],
        environment: {},
        helpers: [{ name: "launcher", sourceSha256: hash }],
        windowsPreparation: {
          sourceDirectory,
          sources: [{ name: "launcher.c", sha256: hash }],
        },
      };
      for (const [args, mode] of [
        [["/Bv"], "compiler-version"],
        [
          windowsCompilerArguments(
            path.join(sourceDirectory, "launcher.c"),
            path.join(output, "launcher.exe"),
            purpose,
          ),
          "compile",
        ],
      ]) {
        const request = {
          candidateSha,
          platform: "win32",
          toolSha256: hash,
          file,
          args,
          cwd: output,
          env: { CI: "true", GITHUB_ACTIONS: "true", LANG: "C" },
          deadlineMs: 30000,
        };
        const operation = windowsBuildOperation(request, manifest, output);
        assert.equal(operation.mode, mode);
        assert.equal(operation.tool, tool);
        for (const changed of [
          { file: alternate },
          { toolSha256: "f".repeat(64) },
          { args: [...args, "/DUNREVIEWED=1"] },
        ])
          assert.throws(() =>
            windowsBuildOperation({ ...request, ...changed }, manifest, output),
          );
      }
    }
  }
});

test("Windows factories construct without effects and reject inventory/vector substitutions", () => {
  const f = wiring();
  createWindowsBuildEffects(f, f.options);
  createWindowsSystemEffects(f, f.options);
  assert.deepEqual(f.events, []);
  assert.equal(
    WINDOWS_SYSTEM_PREPARATION_MS,
    60000 +
      2 * 30000 +
      WINDOWS_HELPER_NAMES.length * 60000 +
      60000 +
      (2 * WINDOWS_HELPER_NAMES.length +
        1 +
        4 +
        windowsSystemRecipes().length) *
        30000 +
      3 * 120000 +
      150000,
  );
  assert.equal(
    WINDOWS_CUSTODY_DEADLINE_MS,
    Math.max(...windowsSystemRecipes().map((recipe) => recipe.deadlineMs)) +
      60000,
  );
  for (const request of f.requests)
    assert.ok(windowsBuildOperation(request, f.manifest, output));
  const bad = structuredClone(f.requests[2]);
  bad.args.push("/DUNREVIEWED=1");
  assert.throws(() => windowsBuildOperation(bad, f.manifest, output));
  const missing = structuredClone(f.manifest.windowsPreparation);
  missing.sources.pop();
  assert.throws(() => normalizeWindowsPreparation(missing, candidateSha));
  assert.ok(
    WINDOWS_BUILD_LIBRARIES.includes("taskschd.lib") &&
      WINDOWS_BUILD_LIBRARIES.includes("fwpuclnt.lib"),
  );
});
test("Windows explicit build persists command and signing publication before effects", async () => {
  const f = wiring(),
    request = f.requests[2],
    id = observationDigest(request);
  f.files.delete(path.join(directory, `windows-command-${id}-intent.json`));
  f.files.delete(path.join(directory, `windows-command-${id}-result.json`));
  const result = await createWindowsBuildEffects(f, f.options).run(request);
  assert.equal(result.publication.imageSha256, hash);
  assert.equal(result.bootstrapSettlement.taskRemoved, true);
  assert.ok(
    f.events.indexOf(`write:windows-command-${id}-intent.json`) <
      f.events.indexOf("build-provision"),
  );
  const intent = f.events.findIndex((event) =>
    /write:windows-command-.*-0\.json/u.test(event),
  );
  assert.ok(intent < f.events.indexOf("publication"));
  assert.ok(f.events.indexOf("publication") < f.events.indexOf("close:build"));
  const failed = wiring(),
    run = failed.options.runCommand;
  failed.files.delete(
    path.join(directory, `windows-command-${id}-intent.json`),
  );
  failed.files.delete(
    path.join(directory, `windows-command-${id}-result.json`),
  );
  failed.options.runCommand = async (value) => ({
    ...(await run(value)),
    exitCode: 1,
  });
  await assert.rejects(
    createWindowsBuildEffects(failed, failed.options).run(request),
  );
  assert.ok(!failed.events.includes("publication"));
});
test("Windows verifyBuild rereads all prepared images and receipts without compiling, including cl /Bv exit 2", async () => {
  const f = wiring();
  const result = await createWindowsSystemEffects(f, f.options).verifyBuild(
    f.preparation,
  );
  assert.equal(result.status, "OBSERVED");
  assert.ok(f.events.includes("verify-commands"));
  assert.ok(!f.events.includes("command"));
  assert.ok(!f.events.includes("publication"));
  for (const name of WINDOWS_HELPER_NAMES)
    assert.ok(f.events.includes("read:" + path.join(output, name + ".exe")));
  for (const change of [
    (g) => {
      g.preparation.commands.pop();
    },
    (g) => {
      g.options.verifyCommands = async () => ({
        ...retired,
        commandsSha256: hash,
        noLiveMembers: true,
        tasksRemoved: true,
      });
    },
    (g) => {
      const id = g.preparation.commands[0].requestSha256,
        file = path.join(directory, `windows-command-${id}-result.json`);
      const result = JSON.parse(g.files.get(file));
      result.timedOut = true;
      g.files.set(file, Buffer.from(JSON.stringify(result)));
    },
    (g) => {
      const command = g.preparation.commands[0],
        file = path.join(
          directory,
          `windows-command-${command.requestSha256}-result.json`,
        ),
        result = JSON.parse(g.files.get(file));
      result.stdout = "Different observed tool version\n";
      g.files.set(file, Buffer.from(JSON.stringify(result)));
      command.receiptSha256 = observationDigest(result);
    },
    (g) => {
      g.options.readProtected = async () => ({
        bytes,
        file: path.join(output, "launcher.exe"),
        sha256: hash,
        independent: true,
        held: true,
        protectedDacl: false,
      });
    },
  ]) {
    const g = wiring();
    change(g);
    await assert.rejects(
      createWindowsSystemEffects(g, g.options).verifyBuild(g.preparation),
    );
  }
});
test("Windows supported composition prepares every fixed recipe and settles each admitted effect only after ordered native retirement", async () => {
  for (const recipe of windowsSystemRecipes().filter(
    (entry) => entry.id !== "build",
  )) {
    const f = wiring(),
      p = policy(f, recipe),
      recorded = [],
      work = new AbortController(),
      owner = createWindowsSystemEffects(f, f.options);
    const prepared = await owner.prepare(
      { ...recipe, reviewSha256: hash },
      {
        signal: work.signal,
        policyBinding: p.binding,
        recordPolicy: async (proof) => recorded.push(proof),
      },
    );
    const literal = ["ownership.literal", "ownership.storage"].includes(
      recipe.id,
    );
    assert.equal(recorded.length, literal ? 0 : 1);
    assert.equal(prepared.templateSha256, p.binding.approval.manifestSha256);
    assert.ok(
      f.events.findIndex((event) => event.startsWith("write:windows-case-")) <
        f.events.indexOf("provision"),
    );
    work.abort();
    const receipts = await owner.settle(recipe, prepared, {
      signal: new AbortController().signal,
      execution: execution(recipe.id),
    });
    for (const [name, value] of Object.entries(receipts))
      assert.equal(
        value === null ? "not-started" : value.settlement.status,
        execution(recipe.id).effects[name].admission === "not-started"
          ? "not-started"
          : "RETIRED",
      );
    assert.ok(
      f.events.indexOf("payload-retire") < f.events.indexOf("audit-release"),
    );
    assert.ok(
      f.events.indexOf("audit-release") < f.events.indexOf("policy-restore"),
    );
    assert.ok(
      f.events.indexOf("policy-restore") <
        f.events.indexOf("close:" + recipe.id),
    );
  }
});
test("Windows concrete policy mismatch blocks custody, and literal policy readers reject mismatched barrier evidence", async () => {
  const recipe = windowsSystemRecipes().find(
      (entry) => entry.id === "access.workspace-write.none",
    ),
    f = wiring(),
    p = policy(f, recipe);
  f.options.provision = async () => ({
    input: { ...p.input, accountSid: "S-1-5-21-9-8-7-1001" },
    provisioning: p.proof.provisioning,
  });
  await assert.rejects(
    createWindowsSystemEffects(f, f.options).prepare(recipe, {
      policyBinding: p.binding,
      recordPolicy: async () => {},
    }),
  );
  assert.ok(!f.events.includes("reader:" + recipe.id));
  const literal = windowsSystemRecipes().find(
      (entry) => entry.id === "ownership.literal",
    ),
    g = wiring(),
    q = policy(g, literal),
    owner = createWindowsSystemEffects(g, g.options);
  const prepared = await owner.prepare(literal, {
    policyBinding: q.binding,
    recordPolicy: async () => {},
  });
  await prepared.effects.readProvisioning(q.request, {});
  const record = {
    provisioning: q.proof.provisioning,
    requestSha256: q.proof.requestSha256,
    policyInput: { request: q.request },
  };
  assert.deepEqual(
    await prepared.effects.readPolicy(q.request, record),
    q.proof.observed,
  );
  record.requestSha256 = "f".repeat(64);
  await assert.rejects(prepared.effects.readPolicy(q.request, record));
});

test("Windows audit drains after payload retirement, closes the observer before owned restoration and retains uncertain setup", async () => {
  for (const damage of [null, "payload", "restore"]) {
    const f = wiring(),
      recipe = windowsSystemRecipes().find(
        (entry) => entry.id === "access.read-only.none",
      ),
      p = policy(f, recipe),
      work = new AbortController();
    f.options.bindResources = async () => ({
      audit: {
        context: p.binding.context,
        input: {},
        transfer: {},
        mapping: {},
      },
    });
    f.options.createAudit = () => ({
      install: async () => {
        f.events.push("audit-install");
        return {
          channel: {
            close: async () => {
              f.events.push("observer-close");
              return { ...retired, closed: true };
            },
          },
        };
      },
      restore: async () => {
        f.events.push("owned-audit-restore");
        if (damage === "restore") throw new Error("installed state changed");
        return {
          independent: true,
          beforeSha256: hash,
          restoredSha256: hash,
          nativeEventSha256: hash,
        };
      },
    });
    f.options.createDecoder = () => ({});
    f.options.createCapture = () => ({
      start: async () => {
        f.events.push("capture-start");
      },
      stop: async () => {
        f.events.push("capture-stop");
        return { complete: true };
      },
    });
    if (damage === "payload") f.options.verifyRetirement = async () => false;
    const owner = createWindowsSystemEffects(f, f.options),
      prepared = await owner.prepare(recipe, {
        signal: work.signal,
        policyBinding: p.binding,
        recordPolicy: async () => {},
      });
    work.abort();
    const result = await owner.settle(recipe, prepared, {
      signal: new AbortController().signal,
      execution: execution(recipe.id),
    });
    assert.equal(
      Object.values(result).find(Boolean).settlement.status,
      damage ? "RETAINED" : "RETIRED",
    );
    if (!damage) {
      for (const [first, next] of [
        ["payload-retire", "capture-stop"],
        ["capture-stop", "observer-close"],
        ["observer-close", "owned-audit-restore"],
        ["owned-audit-restore", "policy-restore"],
        ["policy-restore", "close:" + recipe.id],
      ])
        assert.ok(f.events.indexOf(first) < f.events.indexOf(next));
    } else {
      assert.ok(!f.events.includes("policy-restore"));
      assert.ok(!f.events.includes("close:" + recipe.id));
      if (damage === "payload") assert.ok(!f.events.includes("capture-stop"));
    }
  }
});

test("Windows failed prepared-build retirement cannot be replaced by retirement of the new bootstrap reader", async () => {
  const f = wiring(),
    owner = createWindowsSystemEffects(f, {
      ...f.options,
      verifyCommands: async () => ({
        ...retired,
        commandsSha256: hash,
        noLiveMembers: false,
        tasksRemoved: true,
      }),
    });
  await assert.rejects(owner.verifyBuild(f.preparation));
  const result = await owner.settle({ id: "build" }, undefined, {
    signal: new AbortController().signal,
    execution: execution("build"),
  });
  assert.equal(
    Object.values(result).find(Boolean).settlement.status,
    "RETAINED",
  );
});
test("Windows partial recovery uses bootstrap assets and protected intents without successful preparation outputs", async () => {
  const f = wiring(),
    preparation = {
      ...f.preparation,
      status: "FAIL",
      helpers: [],
      versions: [],
      commands: [],
    },
    job = f.job;
  for (const file of [...f.files.keys()])
    if (file.startsWith(directory + "\\")) f.files.delete(file);
  f.files.set(
    path.join(directory, "windows-case-release-0.json"),
    Buffer.from(
      JSON.stringify({
        context: context("release"),
        phase: "provisioning-possible",
      }),
    ),
  );
  const request = {
    candidateSha,
    platform: "win32",
    jobSha256: observationDigest(job),
    preparationSha256: observationDigest(preparation),
  };
  let recovery = 0;
  f.options.recover = async ({ records }) => {
    if (recovery++ === 0) assert.equal(records.length, 1);
    else
      assert.ok(
        records.some(
          (entry) =>
            /-0-intent\.json$/u.test(entry.name) &&
            entry.name.startsWith("windows-recovery-"),
        ),
      );
    return {
      ...retired,
      recordsSha256: observationDigest(records),
      noLiveMembers: true,
      tasksRemoved: true,
      effects: Object.fromEntries(
        NATIVE_EFFECT_CLASSES.map((name) => [name, retired]),
      ),
    };
  };
  const owner = createWindowsSystemEffects({ ...f, preparation }, f.options);
  const result = await owner.recover({ request, job, preparation });
  assert.equal(result.status, "RETIRED");
  assert.equal(
    (await owner.recover({ request, job, preparation })).status,
    "RETIRED",
  );
  assert.ok(!f.events.includes("command"));
  assert.ok(!f.events.some((event) => event.startsWith("read:" + output)));
  const g = wiring();
  g.options.recover = async () => ({ ...retired, effects: {} });
  assert.equal(
    (
      await createWindowsSystemEffects(g, g.options).recover({
        request: {
          ...request,
          preparationSha256: observationDigest(g.preparation),
        },
        job,
        preparation: g.preparation,
      })
    ).status,
    "RETAINED",
  );
});
test("Windows compiler bridge holds the actual worker image before release and rejects malformed or live settlement", async () => {
  for (const damage of [null, "image", "output", "live"]) {
    const f = wiring(),
      request = f.requests[0],
      events = [],
      worker = identity(61),
      helper = identity(60),
      frames = [
        { worker },
        { stream: "stdout", hex: Buffer.from("reviewed\n").toString("hex") },
        { exitCode: 2, signal: null, members: 0 },
      ];
    if (damage === "output") frames[1].hex = "ff";
    const channel = {
      identity: helper,
      receive: async () => frames.shift(),
      send: async (value) => events.push(value),
      close: async () =>
        damage === "live" ? { ...retired, status: "RETAINED" } : retired,
    };
    const reader = {
      openBuild: async () => channel,
      retainProcess: async () => {
        events.push("held");
        return { slot: 0, observation: { identity: worker } };
      },
      processImage: async () => ({
        identity: worker,
        sha256: damage === "image" ? "f".repeat(64) : hash,
        signatureSha256: hash,
      }),
      process: async () => ({ identity: worker, retired: true }),
    };
    const result = runWindowsBuildCommand(
      request,
      windowsBuildOperation(request, f.manifest, output),
      { helper: 0, tool: 1, toolSignatureSha256: hash },
      reader,
      async (record) => events.push(record.phase),
    );
    if (damage) {
      await assert.rejects(result);
      assert.ok(events.includes("uncertain"));
      if (damage === "image") assert.ok(!events.includes("R"));
    } else {
      assert.equal((await result).exitCode, 2);
      assert.ok(events.indexOf("held") < events.indexOf("R"));
      assert.ok(events.indexOf("publication-possible") < events.indexOf("S"));
    }
  }
});

test("Windows Git composition retains actual status and rejects divergence from held snapshot reads", async () => {
  for (const damage of [null, "observation", "changed"]) {
    const f = wiring(),
      recipe = windowsSystemRecipes().find((entry) => entry.id === "git.fixed"),
      { binding } = policy(f, recipe);
    const held = {
      head: "e".repeat(40),
      config: "reviewed bytes",
      metadata: [["HEAD", hash, hash]],
    };
    f.options.bindResources = async () => ({
      gitSlots: { metadata: 1, workspace: 2 },
    });
    let reads = 0;
    f.options.createReaders = () => ({
      gitSnapshot: async () => ({
        ...held,
        head: damage === "changed" && reads++ ? "f".repeat(40) : held.head,
      }),
    });
    const ownerEffects = f.options.ownerEffects;
    f.options.ownerEffects = async (...args) => ({
      ...(await ownerEffects(...args)),
      snapshot: async () => ({
        ...held,
        head: damage === "observation" ? "f".repeat(40) : held.head,
        status: " M content.txt\n",
      }),
    });
    const effects = createWindowsSystemEffects(f, f.options),
      prepared = await effects.prepare(
        { ...recipe, reviewSha256: hash },
        {
          signal: new AbortController().signal,
          policyBinding: binding,
          recordPolicy: async () => {},
        },
      );
    if (damage) await assert.rejects(prepared.effects.snapshot(prepared.input));
    else
      assert.equal(
        (await prepared.effects.snapshot(prepared.input)).status,
        " M content.txt\n",
      );
  }
});

test("Windows release retains approved template pins for prepared version-two package closures", async () => {
  const image = Buffer.alloc(512);
  image.writeUInt16LE(0x5a4d);
  image.writeUInt32LE(64, 0x3c);
  image.writeUInt32LE(0x4550, 64);
  image.writeUInt16LE(0x8664, 68);
  image.writeUInt16LE(1, 70);
  image.writeUInt16LE(240, 84);
  image.writeUInt16LE(0x20b, 88);
  image.writeUInt32LE(16, 196);
  image.writeUInt32LE(448, 232);
  image.writeUInt32LE(8, 236);
  image.writeUInt32LE(8, 448);
  image.writeUInt16LE(0x200, 452);
  image.writeUInt16LE(2, 454);
  const manifest = {
    schemaVersion: 2,
    candidateSha,
    platform: "win32",
    image: "windows-2025",
    osBuild: "fixture",
    sdkBuild: "fixture",
    policyTemplates: [hash],
    privileges: [],
    components: ["helper", "payload"].map((id) => ({
      id,
      role: id === "helper" ? "helper" : "executable",
      sha256: digest(image),
      format: "pe-x64",
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
    platform: "win32",
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
      identity: "1".repeat(16) + ":" + (id === "helper" ? "2" : "3").repeat(32),
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
    (await observeWindowsRelease(manifest, authority, effects)).closure
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
  await assert.rejects(observeWindowsRelease(manifest, authority, effects));
});

function publicationBytes() {
  const unsigned = Buffer.alloc(512);
  unsigned.writeUInt16LE(0x5a4d);
  unsigned.writeUInt32LE(64, 0x3c);
  unsigned.writeUInt32LE(0x4550, 64);
  unsigned.writeUInt16LE(0x8664, 68);
  unsigned.writeUInt16LE(1, 70);
  unsigned.writeUInt16LE(240, 84);
  unsigned.writeUInt16LE(0x20b, 88);
  unsigned.writeUInt32LE(16, 196);
  const signed = Buffer.concat([unsigned, Buffer.alloc(16)]);
  signed.writeUInt32LE(512, 232);
  signed.writeUInt32LE(16, 236);
  signed.writeUInt32LE(12, 512);
  signed.writeUInt16LE(0x200, 516);
  signed.writeUInt16LE(2, 518);
  signed.writeUInt32LE(0x1234, 520);
  return { unsigned, signed };
}

test("Windows native checkout attributes preserve candidate C and header bytes with autocrlf", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "native-checkout-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const execute = promisify(execFile),
    config = join(root, "empty-config"),
    git = (...args) =>
      execute("git", ["-c", "core.autocrlf=true", ...args], {
        cwd: root,
        encoding: "buffer",
        env: {
          PATH: process.env.PATH,
          SystemRoot: process.env.SystemRoot,
          GIT_CONFIG_NOSYSTEM: "1",
          GIT_CONFIG_GLOBAL: config,
          GIT_ATTR_NOSYSTEM: "1",
        },
      });
  await writeFile(config, "");
  await writeFile(
    join(root, ".gitattributes"),
    await readFile(new URL("../../../.gitattributes", import.meta.url)),
  );
  await mkdir(join(root, "ci/native/win32"), { recursive: true });
  const names = ["feasibility-helper.c", "effective-reader.h"];
  const sources = await Promise.all(
    names.map((name) => readFile(new URL(name, import.meta.url))),
  );
  for (const [index, name] of names.entries())
    await writeFile(join(root, "ci/native/win32", name), sources[index]);
  await git("init", "-q");
  await git("add", ".gitattributes", "ci/native/win32");
  for (const name of names) await unlink(join(root, "ci/native/win32", name));
  await git("checkout", "--", "ci/native/win32");
  for (const [index, name] of names.entries()) {
    const candidate = await git("show", `:ci/native/win32/${name}`);
    assert.deepEqual(candidate.stdout, sources[index], name);
    assert.deepEqual(
      await readFile(join(root, "ci/native/win32", name)),
      candidate.stdout,
      name,
    );
  }
});

let rawRun = 0;

function operationCase(f, id) {
  const result = provisionCase(f, id),
    { declaration, binding } = result;
  const old = declaration.bindings.input,
    request = { ...old };
  const input = id.startsWith("files.")
    ? {
        request,
        base: f.rawFileId(old.custody),
        root: f.rawFileId(old.custody + "\\files"),
        reviewSha256: hash,
      }
    : id.startsWith("git.")
      ? {
          request,
          git: {},
          metadata: "",
          hooks: "",
          parent: "",
          accountSid: "S-1-5-21-1-2-3-1003",
          reviewSha256: hash,
        }
      : { request, reviewSha256: hash };
  const entries = decodeWindowsPlan(
    f.files.get(declaration.custody.plan.path),
    declaration.custody,
  );
  const specification = operationAssets(f, input, entries, id, binding);
  const planBytes = encodeWindowsCustodyPlan({
    candidateSha,
    nonce: declaration.custody.nonce,
    entries,
  });
  declaration.custody.plan.sha256 = digest(planBytes);
  f.files.set(declaration.custody.plan.path, planBytes);
  declaration.bindings.input = input;
  const parameters = {
    kind: id.startsWith("files.")
      ? "windows-files"
      : id.startsWith("git.")
        ? "windows-git"
        : "windows-release",
    ...(id.startsWith("git.")
      ? { grant: id === "git.fixed" ? "commit" : "ordinary" }
      : { authority: "system-only" }),
    accountSid: { binding: "account" },
    restrictingSid: { binding: "restricting" },
    ...(id.startsWith("files.")
      ? {
          base: { identitySha256: { binding: "base" } },
          root: { identitySha256: { binding: "root" } },
        }
      : {}),
    inventorySha256: declaration.custody.plan.sha256,
  };
  binding.template.policy = {
    launch: nativePolicyLaunchData(request, WINDOWS_LITERAL_ARGUMENTS),
    policy: parameters,
  };
  binding.template.policy.launch.request.restrictingSid = {
    binding: "restricting",
  };
  binding.template.bindings = binding.template.bindings.slice(0, 2);
  if (id.startsWith("files."))
    for (const name of ["base", "root"])
      binding.template.bindings.push({
        id: name,
        kind: "custody",
        minimum: null,
        maximum: null,
        paths: [["policy", name, "identitySha256"]],
      });
  binding.approval.manifestSha256 = nativePolicyTemplateDigest(
    binding.template,
  );
  const { reviewSha256, ...reviewed } = structuredClone(input);
  if (id.startsWith("files.")) reviewed.base = reviewed.root = null;
  const approval = {
      schemaVersion: 1,
      contextSha256: observationDigest(binding.context),
      id,
      inputSha256: observationDigest(reviewed),
      ...specification,
      sourceSha256: hash,
    },
    approvalBytes = Buffer.from(JSON.stringify(approval) + "\n");
  const approvalPin = {
    path: path.join(sourceDirectory, "operation-approval-" + id + ".json"),
    sha256: digest(approvalBytes),
  };
  f.files.set(approvalPin.path, approvalBytes);
  input.reviewSha256 = approvalPin.sha256;
  declaration.bindings.operations = { approval: approvalPin };
  const native = installOperationNativeFixture(f, input, specification);
  return { ...result, input, specification, native };
}

test("Windows default operation families use the fixed entry with raw custody and no owner callback", async (t) => {
  for (const id of [
    "files.private",
    "files.publish",
    "files.replace",
    "files.substitution",
    "files.aliases",
    "files.cleanup",
    "git.fixed",
    "git.ordinary",
    "release",
  ]) {
    await t.test(id, async () => {
      const f = rawPreparation(),
        { recipe, binding, declaration, specification } = operationCase(f, id);
      if (id.startsWith("git.")) {
        const entries = decodeWindowsPlan(
          f.files.get(declaration.custody.plan.path),
          declaration.custody,
        );
        // Immutable Git sources belong to the case custodian; reject any
        // attempted bootstrap read in the raw native transport itself.
        f.forbiddenPreparationRead =
          entries[
            specification.assets.find(
              ({ index }) => index === specification.slots.git,
            ).source
          ].path;
      }
      await buildRawPreparation(f);
      const system = await createSystemEffects(f, f.options),
        controller = new AbortController(),
        proofs = [];
      const prepared = await system.prepare(recipe, {
        signal: controller.signal,
        policyBinding: binding,
        recordPolicy: (proof) => proofs.push(proof),
      });
      assert.equal(proofs.length, 1, id);
      assert.ok(prepared.independent, id);
      const result = id.startsWith("files.")
        ? await runWindowsFileCase(id, prepared.input, prepared.effects)
        : id.startsWith("git.")
          ? await runWindowsGitCase(
              id === "git.fixed" ? "git.fixed-commit" : "git.ordinary-denial",
              prepared.input,
              prepared.effects,
            )
          : {
              status: "OBSERVED",
              ...(await observeWindowsRelease(
                f.releaseManifest,
                {
                  candidateSha,
                  platform: "win32",
                  authority: "operator-protected",
                  manifestSha256: releaseClosureDigest(f.releaseManifest),
                },
                prepared.effects,
              )),
            };
      if (prepared.effects.cause)
        throw new Error(id, { cause: prepared.effects.cause });
      assert.equal(
        result.status,
        "OBSERVED",
        id +
          ": " +
          JSON.stringify(
            result.sessions?.map(({ result }) => ({
              status: result.status,
              events: result.events.slice(-3),
            })) ?? result,
          ),
      );
      controller.abort();
      const settled = await system.settle(recipe, prepared, {
        signal: new AbortController().signal,
        execution: {
          id,
          effects: Object.fromEntries(
            NATIVE_EFFECT_CLASSES.map((key) => [
              key,
              { admission: "possible" },
            ]),
          ),
        },
      });
      if (prepared.effects.cause)
        throw new Error(id + ": " + f.rawEvents.slice(-5).join(", "), {
          cause: prepared.effects.cause,
        });
      assert.ok(
        Object.values(settled).every(
          ({ settlement }) => settlement.status === "RETIRED",
        ),
        id,
      );
      assert.ok(
        f.rawEvents.some((value) => value.startsWith("operation-bind ")),
        id,
      );
      assert.ok(!Object.hasOwn(f.options, "ownerEffects"), id);
      await recoverRecordedCase(f);
    });
  }
});

test("Windows release defaults reject extra dependencies and unmatched signatures and close failed readers", async () => {
  for (const damage of ["dependency", "signature"]) {
    const f = rawPreparation(),
      { recipe, binding } = operationCase(f, "release");
    await buildRawPreparation(f);
    const system = await createSystemEffects(f, f.options),
      work = new AbortController();
    const prepared = await system.prepare(recipe, {
      signal: work.signal,
      policyBinding: binding,
      recordPolicy() {},
    });
    f.operationDamage = damage;
    await assert.rejects(
      observeWindowsRelease(
        f.releaseManifest,
        {
          candidateSha,
          platform: "win32",
          authority: "operator-protected",
          manifestSha256: releaseClosureDigest(f.releaseManifest),
        },
        prepared.effects,
      ),
    );
    work.abort();
    const settled = await system.settle(recipe, prepared, {
      signal: new AbortController().signal,
      execution: execution(recipe.id),
    });
    assert.ok(
      Object.values(settled)
        .filter(Boolean)
        .every(({ settlement }) => settlement.status === "RETIRED"),
      damage,
    );
    assert.ok(
      f.rawEvents.some((event) => event.startsWith("release-close ")),
      damage,
    );
  }
});

test("Windows ordinary Git defaults reject lost audit evidence and restore partial read grants after helper interruption", async () => {
  for (const damage of ["audit-loss", "git-policy-interruption"]) {
    const f = rawPreparation(),
      { recipe, binding } = operationCase(f, "git.ordinary");
    await buildRawPreparation(f);
    const system = await createSystemEffects(f, f.options),
      work = new AbortController();
    let prepared;
    if (damage === "git-policy-interruption") {
      f.operationDamage = damage;
      await assert.rejects(
        system.prepare(recipe, {
          signal: work.signal,
          policyBinding: binding,
          recordPolicy() {},
        }),
      );
    } else {
      prepared = await system.prepare(recipe, {
        signal: work.signal,
        policyBinding: binding,
        recordPolicy() {},
      });
      f.operationDamage = damage;
      assert.equal(
        (
          await runWindowsGitCase(
            "git.ordinary-denial",
            prepared.input,
            prepared.effects,
          )
        ).status,
        "FAIL",
      );
    }
    work.abort();
    const settled = await system.settle(recipe, prepared, {
      signal: new AbortController().signal,
      execution: execution(recipe.id),
    });
    assert.ok(
      Object.values(settled)
        .filter(Boolean)
        .every(({ settlement }) => settlement.status === "RETIRED"),
      damage,
    );
    const position = (name) =>
      f.rawEvents.findIndex((event) => event.startsWith(name + " "));
    assert.ok(
      position("operation-fence") < position("operation-helper-retire"),
    );
    assert.ok(
      position("operation-helper-retire") < position("git-policy-restore"),
    );
    assert.ok(position("git-policy-restore") < position("case-retire"));
  }
});

test("Windows default file admission rejects substituted loaded images and independently closes its helper", async () => {
  const f = rawPreparation(),
    { recipe, binding } = operationCase(f, "files.private");
  await buildRawPreparation(f);
  const system = await createSystemEffects(f, f.options),
    work = new AbortController();
  const prepared = await system.prepare(recipe, {
    signal: work.signal,
    policyBinding: binding,
    recordPolicy() {},
  });
  f.operationDamage = "loaded-substitution";
  assert.equal(
    (await runWindowsFileCase(recipe.id, prepared.input, prepared.effects))
      .status,
    "FAIL",
  );
  work.abort();
  const settled = await system.settle(recipe, prepared, {
    signal: new AbortController().signal,
    execution: execution(recipe.id),
  });
  assert.ok(
    Object.values(settled)
      .filter(Boolean)
      .every(({ settlement }) => settlement.status === "RETIRED"),
  );
  assert.ok(f.rawEvents.some((event) => event.startsWith("loader ")));
  assert.ok(
    f.rawEvents.some((event) => event.startsWith("operation-helper-retire ")),
  );
});

test("Windows changed file controls retain exclusion after helper retirement", async () => {
  const f = rawPreparation(),
    { recipe, binding, native } = operationCase(f, "files.aliases");
  await buildRawPreparation(f);
  const system = await createSystemEffects(f, f.options),
    work = new AbortController();
  const prepared = await system.prepare(recipe, {
    signal: work.signal,
    policyBinding: binding,
    recordPolicy() {},
  });
  f.operationDamage = "changed-control";
  assert.equal(
    (await runWindowsFileCase(recipe.id, prepared.input, prepared.effects))
      .status,
    "FAIL",
  );
  work.abort();
  const settled = await system.settle(recipe, prepared, {
    signal: new AbortController().signal,
    execution: execution(recipe.id),
  });
  assert.ok(
    Object.values(settled)
      .filter(Boolean)
      .every(({ settlement }) => settlement.status === "RETAINED"),
  );
  assert.ok(native.control);
  assert.ok(f.actors.get(native.helper.pid).retired);
  assert.ok(!f.rawEvents.some((event) => event.startsWith("case-retire ")));
});

test("Windows known interrupted file objects recover under a fresh cleanup signal", async () => {
  const f = rawPreparation(),
    { recipe, binding, native } = operationCase(f, "files.private");
  await buildRawPreparation(f);
  const system = await createSystemEffects(f, f.options),
    work = new AbortController();
  const prepared = await system.prepare(recipe, {
    signal: work.signal,
    policyBinding: binding,
    recordPolicy() {},
  });
  f.operationDamage = "finish-nonce";
  const result = await runWindowsFileCase(
    recipe.id,
    prepared.input,
    prepared.effects,
  );
  assert.equal(result.status, "FAIL");
  assert.ok(native.objects.allocation);
  work.abort();
  const settled = await system.settle(recipe, prepared, {
    signal: new AbortController().signal,
    execution: execution(recipe.id),
  });
  assert.ok(
    Object.values(settled)
      .filter(Boolean)
      .every(({ settlement }) => settlement.status === "RETIRED"),
  );
  assert.equal(native.objects.allocation, undefined);
  const helpers = [...native.helpers.values()].filter(
    ({ kind }) => kind === "file",
  );
  assert.equal(helpers.length, 2);
  assert.ok(
    helpers.every(({ identity }) => f.actors.get(identity.pid).retired),
  );
});

test("Windows loader reads reject repeated imports replacing a required API-set edge", async () => {
  const bytes = Buffer.from("synthetic held image"),
    entries = [
      {
        kind: "image",
        path: "C:\\Fixture\\image.exe",
        sha256: digest(bytes),
        signatureSha256: hash,
      },
      {
        kind: "image",
        path: "C:\\Fixture\\shared.dll",
        sha256: digest(bytes),
        signatureSha256: hash,
      },
      {
        kind: "sdk",
        path: "C:\\Fixture\\sdk\\Include\\1.0\\header.h",
        sha256: digest(bytes),
      },
    ];
  const components = [
    {
      index: 0,
      imports: [
        { name: "api-first.dll", index: 1 },
        { name: "api-second.dll", index: 1 },
      ],
    },
    { index: 1, imports: [] },
  ];
  let duplicate = false;
  const reader = {
    inspect: async (index) => ({
      identity: "object-" + index,
      daclSha256: hash,
      links: 1,
    }),
    signature: async () => ({ sha256: hash }),
    read: async (index, offset, length) =>
      bytes.subarray(offset, offset + length),
    operation: async (name, index) =>
      name === "release-build"
        ? { bytes: bytes.length }
        : {
            complete: true,
            dll: index === 1,
            imports: index
              ? []
              : [
                  "api-first.dll",
                  duplicate ? "API-FIRST.DLL" : "api-second.dll",
                ].map((name) => ({ name, host: "shared.dll", delay: false })),
          },
    buildBindings: async () => ({
      major: 10,
      minor: 0,
      build: 26100,
      sdkRootHex: Buffer.from("C:\\Fixture\\sdk\\", "utf16le").toString("hex"),
    }),
    loader: async () => ({
      loaded: entries.slice(0, 2).map((entry, index) => ({
        ...entry,
        pathHex: Buffer.from(entry.path, "utf16le").toString("hex"),
        identity: "object-" + index,
        daclSha256: hash,
        links: 1,
      })),
      imports: [
        "api-first.dll",
        duplicate ? "api-first.dll" : "api-second.dll",
      ].map((name) => ({
        source: 0,
        resolved: 1,
        delay: false,
        importHex: Buffer.from(name).toString("hex"),
      })),
    }),
  };
  const reads = createWindowsOperationReaders(reader, { entries });
  await reads.loader(components, [0]);
  await reads.runtime(0, 0, components);
  duplicate = true;
  await assert.rejects(reads.loader(components, [0]));
  await assert.rejects(reads.runtime(0, 0, components));
  duplicate = false;
  const ordinary = structuredClone(components);
  ordinary[0].imports = [
    { name: "api-first.dll", index: 1, delay: false },
    { name: "shared.dll", index: 1, delay: true },
  ];
  let fault;
  const original = reader.operation;
  reader.operation = async (name, index, image) => {
    if (name === "release-import") {
      assert.equal(index, "api-first.dll");
      assert.equal(image, 0);
      if (fault === "unresolved")
        throw new Error("Unresolved installed import");
      return {
        pathHex: Buffer.from(entries[1].path, "utf16le").toString("hex"),
        identity: fault === "identity" ? "changed" : "object-1",
        sha256: fault === "bytes" ? "f".repeat(64) : entries[1].sha256,
      };
    }
    const value = await original(name, index);
    if (name === "release-pe")
      value.imports = index
        ? []
        : ordinary[0].imports.map(({ name, delay }) => ({ name, delay }));
    return value;
  };
  const experiment = createWindowsOperationReaders(
    reader,
    { entries },
    "experiment",
  );
  const mappedImports = structuredClone(ordinary[0].imports),
    loaded = reader.loader;
  reader.loader = async () => ({
    ...(await loaded()),
    importScope: "private-runtime",
    imports: mappedImports.map(({ name, delay }) => ({
      source: 0,
      resolved: 1,
      delay,
      importHex: Buffer.from(name).toString("hex"),
    })),
  });
  await experiment.loader(ordinary, [0]);
  await experiment.runtime(0, 0, ordinary);
  for (fault of ["unresolved", "identity", "bytes"])
    await assert.rejects(experiment.loader(ordinary, [0]));
  fault = null;
  ordinary[0].imports[1].delay = false;
  // A declaration cannot substitute a delay edge for the held PE observation.
  const observe = reader.operation;
  reader.operation = async (name, index) => {
    const value = await observe(name, index);
    if (name === "release-pe" && index === 0) value.imports[1].delay = true;
    return value;
  };
  await assert.rejects(experiment.loader(ordinary, [0]));
  await assert.rejects(experiment.runtime(0, 0, ordinary));
  // Omitted helper admission is explicit; it cannot omit private DLL evidence.
  const omitted = [{ index: 0, imports: null }];
  await assert.rejects(experiment.loader(omitted, [0]));
  entries[0].kind = "helper";
  let malformed;
  reader.operation = async (name, index) => {
    const value = await original(name, index);
    if (name === "release-pe")
      value.imports = value.imports.map(({ name, delay }, index) => ({
        name: !index && malformed === "name" ? "../foreign.dll" : name,
        delay: !index && malformed === "delay" ? "false" : delay,
      }));
    return value;
  };
  const module = { ...(await loaded()).loaded[0] };
  const system = {
    ...module,
    pathHex: Buffer.from(
      "C:\\Windows\\System32\\fixture.dll",
      "utf16le",
    ).toString("hex"),
  };
  reader.loader = async () => ({
    importScope: "private-runtime",
    loaded: [module, system],
    imports: [],
  });
  await experiment.loader(omitted, [0]);
  for (malformed of ["delay", "name"])
    await assert.rejects(experiment.loader(omitted, [0]));
  malformed = null;
  await experiment.runtime(0, 0, omitted);
  await assert.rejects(reads.loader(omitted, [0]));
  await assert.rejects(reads.runtime(0, 0, omitted));
  system.pathHex = Buffer.from(
    "C:\\Fixture\\substituted.dll",
    "utf16le",
  ).toString("hex");
  await assert.rejects(experiment.runtime(0, 0, omitted));
  module.identity = "substituted";
  reader.loader = async () => ({
    importScope: "private-runtime",
    loaded: [module],
    imports: [],
  });
  await assert.rejects(experiment.runtime(0, 0, omitted));

  // The native private-runtime lane emits private Git edges, including their
  // delay evidence, while holding stock modules without traversing their imports.
  entries[0].kind = "image";
  entries.push({
    kind: "image",
    path: "C:\\Windows\\System32\\stock.dll",
    sha256: digest(bytes),
    signatureSha256: hash,
  });
  const graph = [
    { index: 0, imports: [{ name: "shared.dll", index: 1, delay: false }] },
    { index: 1, imports: [{ name: "stock.dll", index: 3, delay: true }] },
    { index: 3, imports: null },
  ];
  let boundaryFault;
  reader.operation = async (name, index) => {
    assert.notEqual(
      name,
      "release-import",
      "Stock transitive imports cannot be resolved",
    );
    if (name !== "release-pe") return original(name, index);
    return {
      complete: true,
      dll: index !== 0,
      imports:
        index === 3
          ? [{ name: "unresolved-stock.dll", delay: true }]
          : graph
              .find((entry) => entry.index === index)
              .imports.map(({ name, delay }) => ({
                name,
                delay:
                  boundaryFault === "delay" && index === 1 ? !delay : delay,
              })),
    };
  };
  reader.loader = async () => {
    const loaded = [0, 1, 3].map((index) => ({
      pathHex: Buffer.from(entries[index].path, "utf16le").toString("hex"),
      identity:
        boundaryFault === "substitution" && index === 1
          ? "changed"
          : "object-" + index,
      sha256: entries[index].sha256,
      signatureSha256: entries[index].signatureSha256,
      daclSha256: hash,
      links: 1,
    }));
    if (boundaryFault === "missing-private") loaded.splice(1, 1);
    const imports = [
      {
        source: 0,
        resolved: 1,
        delay: false,
        importHex: Buffer.from("shared.dll").toString("hex"),
      },
      {
        source: 1,
        resolved: 2,
        delay: boundaryFault !== "delay",
        importHex: Buffer.from("stock.dll").toString("hex"),
      },
    ];
    if (boundaryFault === "stock-edge")
      imports.push({
        source: 2,
        resolved: 0,
        delay: true,
        importHex: Buffer.from("unresolved-stock.dll").toString("hex"),
      });
    return { importScope: "private-runtime", loaded, imports };
  };
  await experiment.loader(graph, [0]);
  await experiment.runtime(0, 0, graph);
  const emptyStock = structuredClone(graph);
  emptyStock[2].imports = [];
  await assert.rejects(experiment.loader(emptyStock, [0]));
  boundaryFault = "delay";
  await assert.rejects(experiment.loader(graph, [0]));
  for (boundaryFault of [
    "delay",
    "missing-private",
    "substitution",
    "stock-edge",
  ])
    await assert.rejects(experiment.runtime(0, 0, graph));
});

test("Windows interrupted publication retires held workers and retains objects without matched final state", async () => {
  const f = rawPreparation(),
    { recipe, binding, native } = operationCase(f, "files.publish");
  await buildRawPreparation(f);
  const system = await createSystemEffects(f, f.options),
    work = new AbortController();
  const prepared = await system.prepare(recipe, {
    signal: work.signal,
    policyBinding: binding,
    recordPolicy() {},
  });
  f.operationDamage = "publisher-interruption";
  const record = await runWindowsFileCase(
    recipe.id,
    prepared.input,
    prepared.effects,
  );
  assert.equal(record.status, "FAIL");
  work.abort();
  const settled = await system.settle(recipe, prepared, {
    signal: new AbortController().signal,
    execution: execution(recipe.id),
  });
  assert.ok(
    Object.values(settled)
      .filter(Boolean)
      .every(({ settlement }) => settlement.status === "RETAINED"),
  );
  assert.ok(
    f.rawEvents.some((event) => event.startsWith("file-workers-retire ")),
  );
  assert.equal(native.workers.length, 3);
  assert.ok(native.workers.every(({ pid }) => f.actors.get(pid).retired));
  assert.ok(!f.rawEvents.some((event) => event.startsWith("case-retire ")));
});

function rawPreparation({ experiment = false, environment } = {}) {
  const f = wiring(),
    { unsigned, signed } = publicationBytes(),
    helperBytes = experiment ? experimentImage() : signed,
    helperSha = digest(helperBytes),
    helperSignature = experiment
      ? helperSha
      : inspectWindowsPe(signed).signatureSha256,
    imageSha = digest(signed),
    signatureSha = inspectWindowsPe(signed).signatureSha256,
    actors = new Map(),
    exitCodes = new Map(),
    images = new Map(),
    jobs = new Map(),
    compilerJobs = new Map(),
    jobNonces = new Map(),
    jobCreators = new Map(),
    tasks = new Map(),
    events = [],
    commands = [],
    fileIds = new Map();
  if (environment) {
    Object.assign(f.manifest.environment, environment);
    for (const request of f.requests) Object.assign(request.env, environment);
  }
  let nextPid = 100;
  const encode = (text) => Buffer.from(text, "utf16le").toString("hex"),
    decode = (text) => Buffer.from(text, "hex").toString("utf16le"),
    fileId = (file) => {
      if (!fileIds.has(file))
        fileIds.set(
          file,
          "1".repeat(16) + ":" + String(fileIds.size + 1).padStart(32, "0"),
        );
      return fileIds.get(file);
    },
    actor = (system = true) => {
      const value = {
        ...identity(++nextPid),
        userSid: system
          ? "S-1-5-18"
          : f.manifest.windowsPreparation.bootstrap.runnerSid,
      };
      actors.set(value.pid, {
        identity: value,
        processDaclSha256: hash,
        tokenId: "1".repeat(16),
        authenticationId: "2".repeat(16),
        integritySid: "S-1-16-16384",
        groups: [],
        restricting: [],
        privileges: [],
        retired: false,
      });
      return value;
    },
    job = (helper) => ({
      daclSha256: hash,
      limitFlags: compilerJobs.has(helper.pid) ? 0x2808 : 0x2008,
      processLimit: 32,
      uiRestrictions: 255,
      members: (jobs.get(helper.pid) ?? []).filter(
        (member) => !actors.get(member.pid).retired,
      ),
    });
  f.job.runId = String(++rawRun);
  f.job.runAttempt = 1;
  f.job.tier = "system";
  f.job.provenance = {
    repository: "fixture/repository",
    workflow: "native-fixture",
    runId: f.job.runId,
    runAttempt: 1,
    jobId: "1",
  };
  f.job.closure = { fixture: "reviewed-closure" };
  f.manifest.windowsPreparation.bootstrap.context = nativePolicyContext(
    f.job,
    "build",
  );
  for (const declaration of f.manifest.windowsPreparation.cases)
    declaration.custody.context = nativePolicyContext(f.job, declaration.id);
  for (const file of [...f.files.keys()])
    if (path.basename(file).startsWith("windows-")) f.files.delete(file);
  for (const helper of f.manifest.helpers) helper.sha256 = helperSha;
  for (const tool of f.manifest.tools) {
    tool.sha256 = imageSha;
    if (experiment) tool.signatureSha256 = signatureSha;
    f.files.set(tool.path, signed);
  }
  const plan = f.manifest.windowsPreparation;
  for (const pin of [
    plan.bootstrap.reader,
    plan.bootstrap.bridge,
    plan.command.helper,
  ]) {
    pin.sha256 = helperSha;
    pin.signatureSha256 = helperSignature;
  }
  plan.command.helperSignatures = Object.fromEntries(
    WINDOWS_HELPER_NAMES.map((name) => [name, signatureSha]),
  );
  plan.command.unsignedHelpers = Object.fromEntries(
    WINDOWS_HELPER_NAMES.map((name) => [name, digest(unsigned)]),
  );
  plan.command.toolSignatures = { compiler: signatureSha, sdk: signatureSha };
  for (const helper of f.manifest.helpers)
    f.files.set(path.join(sourceDirectory, helper.name + ".exe"), helperBytes);
  if (experiment) {
    f.job = initializeNativeJob(
      {
        candidateSha,
        platform: "win32",
        repository: "fixture/repository",
        runId: f.job.runId,
        runAttempt: 1,
      },
      { schemaVersion: 7, purpose: "experiment" },
    );
    f.manifest.purpose = plan.purpose = plan.bootstrap.purpose = "experiment";
    plan.schemaVersion = 3;
    plan.command = { helper: plan.command.helper };
    plan.bootstrap.bindingSha256 = plan.bootstrap.reviewSha256;
    delete plan.bootstrap.reviewSha256;
    plan.sources.push({ name: "experiment.h", sha256: hash });
    plan.bootstrap.sources.push({
      path: path.join(sourceDirectory, "experiment.h"),
      sha256: hash,
    });
  }
  for (const source of plan.sources)
    f.files.set(path.join(sourceDirectory, source.name), bytes);
  const sdkFile =
    "C:\\Program Files (x86)\\Windows Kits\\10\\Include\\1.0\\um\\Windows.h";
  f.files.set(sdkFile, bytes);
  const entries = [
    { kind: "sdk", path: sdkFile, sha256: hash, signatureSha256: null },
    ...f.manifest.helpers.map(({ name }) => ({
      kind: "helper",
      path: path.join(sourceDirectory, name + ".exe"),
      sha256: helperSha,
      signatureSha256: helperSignature,
    })),
    { kind: "directory", path: output, sha256: null, signatureSha256: null },
    ...f.manifest.tools.map((tool) => ({
      kind: "image",
      path: tool.path,
      sha256: imageSha,
      signatureSha256: signatureSha,
    })),
    ...plan.sources.map((source) => ({
      kind: "data",
      path: path.join(sourceDirectory, source.name),
      sha256: hash,
      signatureSha256: null,
    })),
  ];
  const planBytes = encodeWindowsCustodyPlan({
    ...(experiment ? { purpose: "experiment" } : {}),
    candidateSha,
    nonce,
    entries,
  });
  plan.bootstrap.plan.sha256 = digest(planBytes);
  f.files.set(plan.bootstrap.plan.path, planBytes);
  for (const request of f.requests) request.toolSha256 = imageSha;
  const runtimeRead = (args, scope) => {
    const process = scope.retained[Number(args[0])],
      file = scope.heldFilePaths[Number(args[1])],
      data = scope.heldFiles[Number(args[1])];
    assert.ok(process && !process.retired && data);
    assert.equal(images.get(process.identity.pid), file);
    assert.equal(digest(data), args[2]);
    assert.equal(helperSignature, args[3]);
    return {
      processImage: {
        identity: process.identity,
        sha256: digest(data),
        signatureSha256: helperSignature,
      },
      imageIdentity: fileId(file),
      loader: {
        importScope: "private-runtime",
        loaded: (f.runtimeModules?.get(process.identity.pid) ?? [file]).map(
          (name) => {
            const bytes = f.files.get(name);
            assert.ok(bytes);
            return {
              pathHex: encode(name),
              identity: fileId(name),
              sha256: digest(bytes),
              signatureSha256: bytes.equals(helperBytes)
                ? helperSignature
                : signatureSha,
              daclSha256: hash,
              links: 1,
            };
          },
        ),
        imports: [],
        linkerMajor: 0,
        linkerMinor: 0,
        timestamp: f.runtimeTimestamp ?? 0,
        complete: true,
      },
    };
  };
  const rawNative = async (operation, args, scope) => {
    const { retained, heldFiles, entries: selected } = scope;
    events.push(operation);
    if (f.damage === operation) throw new Error("Interrupted native writer");
    if (f.accessNative) {
      const value = await f.accessNative(operation, args, scope);
      if (value !== undefined) return value;
    }
    if (operation === "prepare-batch") {
      const records = [],
        deferred = [];
      let total = 0;
      for (const encoded of args) {
        const name = decode(encoded),
          file = path.join(directory, name),
          bytes = f.files.get(file);
        assert.ok(bytes);
        if (bytes.length + total > 60000) {
          deferred.push(encoded);
          continue;
        }
        total += bytes.length;
        records.push({
          nameHex: encoded,
          identity: fileId(file),
          daclSha256: hash,
          protectedParents: true,
          sha256: digest(bytes),
          hex: bytes.toString("hex"),
        });
      }
      return { records, deferred };
    }
    if (operation === "prepare-list") {
      const offset = Number(args[0]);
      if (!offset)
        scope.listedNames = [...f.files.keys()]
          .filter(
            (file) =>
              path.dirname(file) === directory &&
              /^windows-[a-z0-9.-]+\.json$/u.test(path.basename(file)),
          )
          .map((file) => path.basename(file));
      return {
        names: scope.listedNames.slice(offset, offset + 128).map(encode),
        complete: offset + 128 >= scope.listedNames.length,
      };
    }
    if (operation === "prepare-directory")
      return {
        identity: fileId(decode(args[0])),
        daclSha256: hash,
        protectedParents: true,
      };
    if (["prepare-read", "prepare-experiment-input"].includes(operation)) {
      assert.ok(!scope.readBytes && !scope.upload);
      const file = decode(args[0]);
      if (operation === "prepare-experiment-input") {
        assert.equal(experiment, true);
        assert.equal(args[1], "-");
        assert.ok(
          f.manifest.tools.some((tool) => tool.path === file) ||
            file === f.prepared?.sdkHeader?.file ||
            file === f.prepared?.gitRuntime?.path,
        );
      }
      assert.notEqual(file, f.forbiddenPreparationRead);
      scope.readBytes = f.files.get(file);
      assert.ok(scope.readBytes, file);
      if (args[1] !== "-") assert.equal(digest(scope.readBytes), args[1]);
      return {
        identity: fileId(file),
        daclSha256: hash,
        protectedParents: true,
        sha256: digest(scope.readBytes),
        bytes: scope.readBytes.length,
        slot: 0,
      };
    }
    if (operation === "prepare-bytes")
      return {
        hex: scope.readBytes
          .subarray(Number(args[1]), Number(args[1]) + Number(args[2]))
          .toString("hex"),
      };
    if (operation === "prepare-release") {
      scope.readBytes = null;
      return { closed: true };
    }
    if (operation === "prepare-experiment-signature") {
      assert.ok(experiment && scope.readBytes);
      return { signatureSha256: digest(scope.readBytes) };
    }
    if (operation === "prepare-experiment-pe") {
      assert.ok(experiment && scope.readBytes);
      return {
        dll: false,
        linkerMajor: 1,
        linkerMinor: 0,
        timestamp: 0,
        imports: f.experimentImports ?? [],
        complete: true,
      };
    }
    if (operation === "prepare-experiment-loader") {
      assert.ok(experiment && !scope.readBytes);
      assert.equal(args.length, 2);
      assert.ok(f.files.has(decode(args[1])));
      const file = f.importResolutions?.get(decode(args[0]));
      assert.ok(file, "Unresolved installed import");
      return {
        pathHex: encode(file),
        identity: fileId(file),
        sha256: digest(f.files.get(file)),
      };
    }
    if (operation === "prepare-write") {
      assert.ok(!scope.readBytes && !scope.upload);
      const file = path.join(directory, decode(args[0]));
      assert.ok(!f.files.has(file));
      scope.upload = {
        file,
        bytes: Buffer.alloc(Number(args[1])),
        sha256: args[2],
      };
      return { created: true };
    }
    if (operation === "prepare-chunk") {
      Buffer.from(args[1], "hex").copy(scope.upload.bytes, Number(args[0]));
      return { written: args[1].length / 2 };
    }
    if (operation === "prepare-seal") {
      assert.equal(digest(scope.upload.bytes), scope.upload.sha256);
      f.files.set(scope.upload.file, scope.upload.bytes);
      const sha256 = scope.upload.sha256;
      scope.upload = null;
      return { sha256, writerClosed: true };
    }
    if (operation === "verify-case") {
      const custody = selected[Number(args[1])].path,
        account = f.accounts.get(custody),
        root = path.dirname(custody);
      assert.ok(account && !account.retired);
      assert.equal(account.contextSha256, args[2]);
      const objects = selected.flatMap((entry, index) =>
        entry.path === root || entry.path.startsWith(root + "\\")
          ? [
              {
                index,
                object: f.objectRead(entry),
                security: {
                  ownerSid: "S-1-5-18",
                  protectedDacl: true,
                  daclSha256: hash,
                  descriptorSha256: hash,
                  aces: [
                    { type: 0, flags: 0, mask: 0x1f01ff, sid: "S-1-5-18" },
                  ],
                  sacl: [],
                },
              },
            ]
          : [],
      );
      f.caseReads = (f.caseReads ?? 0) + 1;
      if (f.caseDamage === "resource-substitution" && f.caseReads === 2)
        objects[0].object.identity = "f".repeat(16) + ":" + "e".repeat(32);
      if (f.caseDamage === "extra-token-grant")
        account.token.enabledGroups.push("S-1-5-32-544");
      if (f.caseDamage === "extra-principal")
        objects[0].security.aces.push({
          type: 0,
          flags: 0,
          mask: 1,
          sid: "S-1-5-21-4-5-6-1004",
        });
      if (f.caseDamage === "substituted-object")
        objects[0].object.identity = "f".repeat(16) + ":" + "e".repeat(32);
      if (f.caseDamage === "wrong-context")
        account.contextSha256 = "d".repeat(64);
      return {
        accountSid: account.accountSid,
        restrictingSid: account.restrictingSid,
        contextSha256: account.contextSha256,
        recordSha256: hash,
        token: account.token,
        objects,
      };
    }
    if (operation === "verify-recovery-object") {
      return {
        object: f.objectRead(selected[Number(args[0])]),
        security: {
          ownerSid: "S-1-5-18",
          protectedDacl: true,
          daclSha256: hash,
          descriptorSha256: hash,
          aces: [{ type: 0, flags: 0, mask: 0x1f01ff, sid: "S-1-5-18" }],
          sacl: [],
        },
      };
    }
    if (operation === "verify-cold-process") {
      if (f.coldDamage === "census-read")
        throw new Error("Process census failed");
      const process = actors.get(Number(args[0]));
      if (!process)
        return {
          complete: f.coldDamage !== "incomplete-census",
          present: false,
        };
      return {
        complete: true,
        present: true,
        original: true,
        identity: process.identity,
        signaled: process.retired,
        exitCode: exitCodes.get(process.identity.pid) ?? 0,
      };
    }
    if (["verify-recovery-jobs", "verify-cold-jobs"].includes(operation)) {
      const cold = operation === "verify-cold-jobs";
      if (cold && f.coldDamage === "job-read")
        throw new Error("Original Job read failed");
      const creator = cold
          ? { pid: Number(args[0]), creationTime: args[1] }
          : retained[Number(args[0])].identity,
        nonce = args[cold ? 2 : 1];
      const owned = [...jobs.entries()].filter(
        ([pid]) =>
          jobNonces.get(pid) === nonce && jobCreators.get(pid) === creator.pid,
      );
      assert.ok(owned.length <= 128);
      for (const [pid] of owned) scope.recoveryJobs.add(pid);
      const observed = {
        nonce,
        ...(cold
          ? {
              pid: creator.pid,
              creationTime: creator.creationTime,
              controllingJob: { absent: true },
            }
          : { identity: creator }),
        jobs: Array.from({ length: 128 }, (_, index) =>
          index < owned.length
            ? job(actors.get(owned[index][0]).identity)
            : { absent: true },
        ),
        compilerJob: compilerJobs.has(creator.pid)
          ? {
              daclSha256: hash,
              limitFlags: 0x2008,
              processLimit: 31,
              uiRestrictions: 255,
              members: compilerJobs
                .get(creator.pid)
                .filter((worker) => !actors.get(worker.pid).retired),
            }
          : { absent: true },
      };
      if (f.coldDamage === "surviving-helper-job")
        observed.jobs[127] = {
          ...job(identity(999)),
          members: [identity(999)],
        };
      if (f.coldDamage === "surviving-compiler-job")
        observed.compilerJob = {
          ...job(identity(999)),
          processLimit: 31,
          members: [identity(999)],
        };
      if (f.coldDamage === "incomplete-job-inventory") observed.jobs.pop();
      if (f.coldDamage === "substituted-job-creator")
        observed.identity = { ...creator, creationTime: "999" };
      return observed;
    }
    if (operation === "verify-receipt") {
      const data = f.files.get(
        path.join(
          selected[Number(args[0])].path,
          "ownership-" + args[1] + ".json",
        ),
      );
      assert.ok(data);
      assert.equal(digest(data), args[2]);
      return { hex: data.toString("hex") };
    }
    if (
      [
        "verify-policy-recover",
        "verify-audit-recover",
        "verify-audit-check",
      ].includes(operation)
    ) {
      const account = f.accounts.get(selected[Number(args[0])].path);
      assert.ok(
        !account || account.retired,
        "Original creators must retire before recovery setters",
      );
      assert.ok(!account || account.contextSha256 === args[1]);
      if (["partial-restoration", "policy-substitution"].includes(f.coldDamage))
        throw new Error("Native restoration interrupted or changed");
      return operation !== "verify-policy-recover"
        ? { restored: true, admission: "possible" }
        : { restored: true };
    }
    if (operation === "verify-case-recover") {
      const account = f.accounts.get(selected[Number(args[0])].path);
      assert.ok(
        !account || account.retired,
        "Recovery must retire the original account first",
      );
      assert.ok(!account || account.contextSha256 === args[1]);
      return {
        accountAbsent: true,
        rightsAbsent: f.coldDamage !== "rights",
        jobAbsent: f.coldDamage !== "job",
        contextSha256: args[1],
        policyRestored: f.coldDamage !== "policy",
        auditDrained: f.coldDamage !== "audit",
        readersClosed: f.coldDamage !== "reader",
      };
    }
    if (operation === "verify-task-remove") {
      const task = tasks.get(decode(args[1]));
      assert.ok(task && actors.get(task.pid).retired);
      assert.equal(args[2], hash);
      assert.ok(retained[Number(args[3])].retired);
      assert.ok(
        retained.every((process) => process.retired),
        "Native task removal requires every retained process to be retired",
      );
      for (const pid of scope.recoveryJobs)
        assert.equal(job(actors.get(pid).identity).members.length, 0);
      tasks.delete(decode(args[1]));
      return { removed: true, sha256: hash };
    }
    if (operation === "verify-case-retired") {
      assert.ok(f.accounts.get(selected[Number(args[0])].path).retired);
      return {
        accountAbsent: true,
        rightsAbsent: f.caseDamage !== "surviving-rights",
        jobAbsent: true,
        contextSha256: args[1],
      };
    }
    if (operation === "verify-file") {
      const file = decode(args[0]),
        data = f.files.get(file);
      assert.ok(data, file);
      assert.equal(digest(data), args[1]);
      const slot = heldFiles.push(data) - 1;
      scope.heldFilePaths[slot] = file;
      assert.ok(slot < 128);
      return {
        identity: fileId(file),
        sha256: digest(data),
        signatureSha256:
          args[2] === "-"
            ? null
            : experiment && digest(data) === helperSha
              ? helperSignature
              : signatureSha,
        daclSha256: hash,
        slot,
        bytes: data.length,
      };
    }
    if (operation === "verify-retain") {
      const actual = actors.get(Number(args[0]));
      assert.ok(actual);
      assert.notEqual(
        actual.identity.pid,
        scope.serving.pid,
        "Native self-retain refusal",
      );
      assert.equal(actual.identity.creationTime, args[1]);
      let slot = retained.indexOf(actual);
      if (slot < 0) slot = retained.push(actual) - 1;
      assert.ok(slot < 128);
      return { slot, process: actual };
    }
    if (operation === "verify-process") return retained[Number(args[0])];
    if (operation === "verify-process-exit") {
      const process = retained[Number(args[0])];
      assert.ok(process.retired);
      return {
        exitCode:
          f.preSetupExitCode ?? exitCodes.get(process.identity.pid) ?? 0,
      };
    }
    if (operation === "verify-task-instance") {
      const helper = retained[Number(args[1])].identity;
      return {
        absent: false,
        sha256: hash,
        instances: f.preSetupRejected ? 0 : 1,
        registeredInstances: 0,
        running: f.preSetupRejected
          ? []
          : [
              {
                guid: "{11111111-2222-3333-4444-555555555555}",
                state: 4,
                engine: helper,
                helperLinked: true,
              },
            ],
      };
    }
    if (operation === "verify-compiler-policy") {
      const worker = retained[Number(args[0])].identity;
      return {
        defaultDacl: [{ type: 0, flags: 0, mask: 0x10000000, sid: "S-1-5-18" }],
        inheritedHandles: ["pipe", "pipe", "pipe"],
        compilerJob: {
          daclSha256: hash,
          limitFlags: 0x2008,
          processLimit: 31,
          uiRestrictions: 255,
          members: [worker],
        },
      };
    }
    if (operation === "verify-runtime") return runtimeRead(args, scope);
    if (operation === "verify-image") {
      const file = images.get(retained[Number(args[0])].identity.pid),
        helper = [
          plan.bootstrap.reader.path,
          plan.bootstrap.bridge.path,
        ].includes(file);
      scope.heldFilePaths[heldFiles.length] = file;
      heldFiles.push(f.files.get(file));
      assert.ok(heldFiles.length <= 128);
      return {
        sha256: helper ? helperSha : imageSha,
        signatureSha256: helper ? helperSignature : signatureSha,
        pathHex: encode(file),
      };
    }
    if (operation === "verify-transfer") {
      const child = retained[Number(args[0])].identity;
      scope.boundJobs.add(child.pid);
      return {
        threadDaclSha256: hash,
        creatorDefaultDaclSha256: hash,
        pipeDaclSha256: [hash, hash],
        job: job(child),
        objects: [null, null],
        inheritedHandleCount: 2,
      };
    }
    if (operation === "verify-job") {
      const child = retained[Number(args[0])].identity;
      return scope.boundJobs.has(child.pid) ? job(child) : { absent: true };
    }
    if (operation === "verify-subjects")
      return { identities: retained.map((state) => state.identity), jobs: [] };
    if (operation === "verify-task") {
      if (f.coldDamage === "task-read")
        throw new Error("Original task read failed");
      if (f.hiddenTasks?.has(decode(args[1])))
        throw new Error("Original hidden task survives");
      return tasks.has(decode(args[1]))
        ? {
            absent: false,
            sha256: f.coldDamage === "task" ? "e".repeat(64) : hash,
            instances: actors.get(tasks.get(decode(args[1])).pid)?.retired
              ? 0
              : 1,
          }
        : { absent: true };
    }
    if (operation === "verify-read")
      return {
        hex: heldFiles[Number(args[0])]
          .subarray(Number(args[1]), Number(args[1]) + Number(args[2]))
          .toString("hex"),
      };
    throw new Error("Unexpected native operation: " + operation);
  };

  const ownershipNative = (operation, values, scope, declaration) => {
    const selected = scope.entries,
      account = f.accounts.get(selected[2].path),
      value = (scope.ownership ??= {
        members: [],
        frames: [],
        output: [],
        released: false,
        jobAbsent: false,
        policy: null,
      });
    const mode = declaration.context.executionId.slice(10),
      literal = ["literal", "storage"].includes(mode),
      payload = () => value.members[0],
      bytes = (data) => ({
        hex: Buffer.from(
          typeof data === "string" ? data : JSON.stringify(data) + "\n",
        ).toString("hex"),
      });
    const add = () => {
      const member = { ...actor(), userSid: account.accountSid };
      actors.get(member.pid).identity = member;
      value.members.push(member);
      return member;
    };
    if (operation === "ownership-outside") {
      const file = path.join(
        directory,
        "outside-" + account.contextSha256 + ".sentinel",
      );
      if (!f.files.has(file))
        f.files.set(file, Buffer.from("independent outside control"));
      return {
        record: account.contextSha256,
        sentinel: { identity: fileId(file), sha256: digest(f.files.get(file)) },
        objects: selected.slice(1, 7).map((entry) => fileId(entry.path)),
        assets: selected
          .slice(5, 7)
          .map((entry) => digest(f.files.get(entry.path))),
      };
    }
    if (operation === "ownership-launch") {
      assert.equal(value.launcher, undefined);
      value.launcher = actor();
      value.owner = actor();
      assert.deepEqual(
        values.slice(1).map((value) => (value === "-" ? "" : decode(value))),
        declaration.context.executionId === "package.git-for-windows"
          ? f.packageArguments
          : windowsOwnershipArguments(declaration.context.executionId, {
              nonce: declaration.nonce,
            }),
      );
      value.frames.push({
        nonce: declaration.nonce,
        phase: "helper",
        helper: value.launcher,
        payload: null,
        accountSid: null,
      });
      return { helper: value.launcher, owner: value.owner };
    }
    if (operation === "ownership-control") {
      const frame = bytes(value.frames.shift());
      if (f.ownershipDamage === "malformed-control") frame.hex += "zz";
      if (f.ownershipDamage === "prefixed-control")
        frame.hex = "efbbbf" + frame.hex;
      return frame;
    }
    if (operation === "ownership-output") {
      if (f.ownershipDamage === "missing-output")
        throw new Error("Interrupted ownership output");
      assert.ok(value.output.length, "ownership output must be acknowledged");
      return bytes(value.output.shift());
    }
    if (operation === "ownership-send") {
      const command = Buffer.from(values[0], "hex").toString();
      if (command === "P")
        value.frames.push({
          nonce: declaration.nonce,
          phase: "setup",
          helper: value.launcher,
          payload: null,
          accountSid: account.accountSid,
        });
      else if (command.startsWith("C")) {
        assert.ok(value.policy);
        assert.equal(
          command.slice(1, 65),
          digest(f.files.get(selected[2].path + "\\policy")),
        );
        add();
        value.frames.push({
          nonce: declaration.nonce,
          phase: "ready",
          helper: value.launcher,
          payload: payload(),
          accountSid: account.accountSid,
        });
      } else if (command === "R") {
        value.released = true;
        if (declaration.context.executionId === "package.git-for-windows")
          value.output.push({ phase: "ready", nonce: declaration.nonce });
        if (literal) {
          actors.get(payload().pid).retired = true;
          value.output.push(
            JSON.stringify({
              argvUtf16: WINDOWS_LITERAL_ARGUMENTS.map((arg) =>
                Array.from({ length: arg.length }, (_, i) =>
                  arg.charCodeAt(i).toString(16).padStart(4, "0"),
                ).join(""),
              ),
            }) + "\n",
          );
        }
      } else if (command === "G") {
        const denied = [
          "breakaway",
          "spoofed-parent",
          "wmi",
          "com",
          "service",
        ].includes(mode);
        if (!denied)
          for (let i = 0; i < (mode === "process-limit" ? 31 : 1); i++) add();
        const event = {
          caseId: mode,
          nonce: declaration.nonce,
          acknowledged: true,
          ...(denied
            ? { nativeError: "ERROR_ACCESS_DENIED" }
            : {
                children: value.members
                  .slice(1)
                  .map(({ pid, creationTime }) => ({ pid, creationTime })),
                nestedOutcome: "contained",
              }),
        };
        value.output.push(event);
        if (mode === "process-limit")
          value.output.push({
            caseId: mode,
            nonce: declaration.nonce,
            acknowledged: true,
            nativeError: "ERROR_NOT_ENOUGH_QUOTA",
          });
      } else if (command === "E") actors.get(payload().pid).retired = true;
      else assert.fail(command);
      return { sent: true };
    }
    if (operation === "ownership-policy") {
      const data = Buffer.from(values[0], "hex");
      value.policy = JSON.parse(data);
      assert.equal(value.policy.policy.network, "deny-all");
      f.files.set(selected[2].path + "\\policy", data);
      if (f.ownershipDamage === "interrupted-policy")
        throw new Error("Interrupted ownership installation");
      return { installed: true };
    }
    if (operation === "ownership-receipt") {
      const file = selected[2].path + "\\ownership-" + values[0] + ".json";
      if (values[2]) {
        assert.ok(!f.files.has(file));
        f.files.set(file, Buffer.from(values[2], "hex"));
      }
      const data = f.files.get(file);
      assert.equal(digest(data), values[1]);
      return {
        hex:
          data.toString("hex") +
          (f.ownershipDamage === "malformed-receipt" ? "zz" : ""),
      };
    }
    if (operation === "ownership-retain") {
      assert.ok(
        value.members.some(
          (member) =>
            member.pid === Number(values[0]) &&
            member.creationTime === values[1],
        ),
      );
      return { retained: true };
    }
    if (operation === "ownership-stale") {
      assert.equal(Number(values[0]), payload().pid);
      assert.notEqual(values[1], payload().creationTime);
      return { rejected: true, current: payload() };
    }
    if (operation === "ownership-reconstruct")
      return {
        helper: value.launcher,
        jobObjectSha256: hash,
        members: value.members,
      };
    if (operation === "ownership-arm") {
      if (mode === "last-handle-close") {
        actors.get(value.owner.pid).retired = true;
        value.jobAbsent = true;
        for (const member of value.members)
          actors.get(member.pid).retired = true;
      }
      return {
        armed: true,
        fixtureAcknowledged:
          !mode.startsWith("receipt-") && mode !== "admission-interruption",
        holderInventoryComplete: true,
      };
    }
    if (operation === "ownership-fire") {
      actors.get(
        mode === "owner-loss" ? value.owner.pid : value.launcher.pid,
      ).retired = true;
      return { acknowledged: true };
    }
    if (operation === "ownership-stop") {
      for (const member of value.members) actors.get(member.pid).retired = true;
      actors.get(value.launcher.pid).retired = true;
      actors.get(value.owner.pid).retired = true;
      value.jobAbsent = true;
      return { creationSealed: true, helpersSettled: true };
    }
    if (operation === "ownership-restore") {
      assert.ok(value.jobAbsent);
      value.policy = null;
      value.restored = true;
      return { restored: true };
    }
    if (operation === "ownership-account-retire") {
      assert.ok(value.jobAbsent && !value.policy);
      account.retired = true;
      return { retired: true };
    }
    if (operation === "ownership-outside-control")
      return {
        ready: true,
        reachable: f.ownershipDamage !== "missing-control",
      };
    if (operation === "ownership-witness") {
      const verifier = actor();
      actors.get(verifier.pid).retired = true;
      const result = {
        verifier,
        imageSha256: declaration.reader.sha256,
        settled: true,
        accountSid: account.accountSid,
        restrictingSid: account.restrictingSid,
        contextSha256: account.contextSha256,
        accountToken: account.token,
        jobObjectSha256: hash,
        jobAbsent: value.jobAbsent,
        jobHolders: value.jobAbsent ? 0 : 2,
        job: {
          limitFlags: 0x2008,
          processLimit: 32,
          uiRestrictions: 255,
          members: value.members,
        },
        enumeration: {
          complete: true,
          accountSid: account.accountSid,
          accountReservationVerified: true,
          capacity: 33,
          truncated: false,
          processes: value.members.map((member) => ({
            identity: member,
            heldProcessVerified: true,
            signaled: actors.get(member.pid).retired,
            inJob: true,
            jobObjectSha256: hash,
          })),
        },
        tokens: value.members.map(() => ({ ...account.token })),
        policyVerified: !!value.policy,
        policyRestored:
          !!value.restored && f.ownershipDamage !== "missing-restoration",
        objects: selected.slice(1, 7).map((entry, i) => ({
          identitySha256: observationDigest(fileId(entry.path)),
          mask: [
            0,
            0,
            0x120020,
            declaration.context.executionId === "package.git-for-windows"
              ? 0x1200a9
              : 0x12019f,
            0,
            0x1200a9,
          ][i],
        })),
        payloadSuspended: value.members.length > 0 && !value.released,
        payloadSignaled: !!payload() && actors.get(payload().pid).retired,
        payloadImageSha256: selected[6].sha256,
        cwdIdentity: fileId(selected[4].path),
        exitCode: 0,
        explicitHandles: true,
        creationTimeJob: true,
        launcherSignaled:
          !value.launcher || actors.get(value.launcher.pid).retired,
        ownerSignaled: !value.owner || actors.get(value.owner.pid).retired,
        ownerJobEmpty: !value.owner || actors.get(value.owner.pid).retired,
        helpers: value.launcher
          ? [
              { role: "launcher", identity: value.launcher },
              { role: "custodian", identity: value.owner },
            ]
          : [],
        sourceVerified: true,
        sdkExportsVerified: true,
        creatorAccessDenied: true,
        noForeignHandles: true,
      };
      if (f.ownershipDamage === "wrong-job") result.job.limitFlags |= 0x800;
      if (f.ownershipDamage === "wrong-token" && result.tokens.length)
        result.tokens[0].privileges.push("unexpected");
      if (
        f.ownershipDamage === "live-member" &&
        value.jobAbsent &&
        result.enumeration.processes.length
      )
        result.enumeration.processes[0].signaled = false;
      if (f.ownershipDamage === "foreign-holder" && value.jobAbsent)
        result.jobHolders = 1;
      if (f.ownershipDamage === "live-owner" && value.jobAbsent)
        result.ownerSignaled = false;
      if (f.ownershipDamage === "live-owner-job" && value.jobAbsent)
        result.ownerJobEmpty = false;
      if (f.ownershipDamage === "substituted-object" && value.policy)
        result.objects[0].identitySha256 = "f".repeat(64);
      if (f.ownershipDamage === "missing-witness") result.settled = false;
      return result;
    }
    assert.fail(operation);
  };
  const channel = (declaration, observer = false, args = []) => {
    const selected = decodeWindowsPlan(
        f.files.get(declaration.plan.path),
        observer
          ? [
              plan.bootstrap,
              ...plan.cases.map((entry) => entry.custody),
              ...(f.packageDeclaration ? [f.packageDeclaration.custody] : []),
            ].find((entry) => entry.plan.path === declaration.plan.path)
          : declaration,
      ),
      scope = {
        retained: [],
        heldFiles: [],
        heldFilePaths: [],
        entries: selected,
        boundJobs: new Set(),
        recoveryJobs: new Set(),
      },
      queue = [],
      bridge = actor(false),
      helper = actor(),
      processSlots = [];
    scope.serving = helper;
    scope.processSlots = processSlots;
    const prefix = path.join(directory, `windows-files-${declaration.nonce}-`);
    if (observer)
      f.files.set(
        prefix + "intent.json",
        Buffer.from(
          JSON.stringify({
            schemaVersion: 1,
            argumentsHex: args.map(encode),
            status: "POSSIBLE",
          }),
        ),
      );
    images.set(bridge.pid, plan.bootstrap.bridge.path);
    images.set(helper.pid, plan.bootstrap.reader.path);
    queue.push({
      phase: "task-intent",
      bridge,
      taskSha256: digest(Buffer.from("native task XML intent")),
      ...(observer ? { intentSha256: hash } : {}),
    });
    let child,
      worker,
      frames = [],
      currentOperation;
    return {
      pid: bridge.pid,
      receive: async () => {
        assert.ok(queue.length, "missing raw frame");
        return JSON.parse(JSON.stringify(queue.shift()));
      },
      completion: Promise.resolve({ code: 0, signal: null }),
      close: () => {},
      settle: () => {},
      async send(frame) {
        events.push(frame.trim());
        if (frame === "T") {
          tasks.set(declaration.nonce, helper);
          queue.push({ phase: "task-registered", taskSha256: hash });
        } else if (frame === "B") {
          if (observer)
            f.files.set(
              prefix + "birth.json",
              Buffer.from(
                JSON.stringify({
                  schemaVersion: 1,
                  nonce: declaration.nonce,
                  taskSha256: hash,
                  bridge,
                  helper,
                  status: "POSSIBLE",
                }),
              ),
            );
          queue.push(
            {
              phase: "entry",
              helper,
              bridge,
              processDaclSha256: hash,
              instance: {
                guid: "{11111111-2222-3333-4444-555555555555}",
                state: 4,
                enginePid: helper.pid,
              },
            },
            { helper, peer: bridge },
          );
        } else if (frame === "X\n") {
          assert.ok(!observer);
          actors.get(helper.pid).retired = true;
          queue.push({ phase: "helper-retired", helper, exitCode: 0 });
        } else if (frame === "D") {
          assert.ok(actors.get(helper.pid).retired);
          actors.get(bridge.pid).retired = true;
          const taskLost = !observer && f.coldDamage === "task";
          if (!taskLost) tasks.delete(declaration.nonce);
          if (observer)
            f.files.set(
              prefix + "result.json",
              Buffer.from(
                JSON.stringify({
                  schemaVersion: 1,
                  nonce: declaration.nonce,
                  taskSha256: hash,
                  helper,
                  bridge,
                  status: "RETIRED",
                }),
              ),
            );
          if (observer && f.disappearObservers) {
            actors.delete(helper.pid);
            actors.delete(bridge.pid);
          }
          queue.push({
            phase: "retired",
            taskSha256: hash,
            taskRemoved: !taskLost,
            helperRetired: true,
            ...(observer
              ? { helper, observations: f.survivingObserver ? 1 : 2 }
              : {}),
          });
        } else if (frame === "P\n")
          queue.push({
            candidateSha,
            nonce: declaration.nonce,
            entries: selected.length,
          });
        else {
          const [operation, sequence, ...values] = frame.trim().split(/ +/u);
          commands.push({ owner: helper, operation, values });
          await f.beforeRawCommand?.(operation);
          let value;
          if (observer)
            f.files.set(
              prefix + sequence + ".json",
              Buffer.from(
                JSON.stringify({
                  schemaVersion: 1,
                  candidateSha,
                  nonce: declaration.nonce,
                  helper,
                  commandHex: Buffer.from(frame.trim()).toString("hex"),
                }),
              ),
            );
          if (f.damage === operation)
            throw new Error("Interrupted native case operation");
          const accessValue =
            !observer && f.accessNative
              ? await f.accessNative(
                  operation,
                  values,
                  scope,
                  declaration,
                  Number(sequence),
                )
              : undefined;
          if (accessValue !== undefined) value = accessValue;
          else if (observer && operation !== "finish")
            value = await rawNative(operation, values, scope);
          else if (operation.startsWith("ownership-"))
            value = ownershipNative(operation, values, scope, declaration);
          else if (operation === "case-directory") {
            const entry = selected[Number(values[0])];
            assert.ok(!f.files.has(entry.path));
            f.files.set(entry.path, Buffer.from("directory"));
            value = f.objectRead(entry);
          } else if (operation === "case-copy") {
            const target = selected[Number(values[0])],
              source = selected[Number(values[1])];
            f.files.set(target.path, f.files.get(source.path));
            value = f.objectRead(target);
          } else if (operation === "case-account") {
            const custody = selected[Number(values[0])].path,
              accountSid = "S-1-5-21-4-5-6-1009",
              restrictingSid = "S-1-5-21-7-8-9-1011";
            value = {
              accountSid,
              restrictingSid,
              contextSha256: values[1],
              tokenHandle: "12345",
            };
            const token = {
              userSid: accountSid,
              restrictedSids: [restrictingSid],
              privileges: [],
              enabledGroups: [],
              integritySid: "S-1-16-4096",
              sessionId: 0,
              tokenId: "3".repeat(16),
              authenticationId: "4".repeat(16),
              primary: true,
              virtualized: false,
              writeRestricted: false,
            };
            if (f.caseDamage === "malformed-token-type") token.primary = 1;
            f.accounts.set(custody, {
              ...value,
              token,
              endpoints: [],
              retired: false,
            });
          } else if (operation === "case-endpoint") {
            const account = f.accounts.get(selected[2].path);
            account.endpoints.push({
              family: values[0],
              protocol: values[1],
              port: Number(values[2]),
            });
            value = { bound: true };
          } else if (operation === "case-read") {
            const account = f.accounts.get(selected[2].path);
            value = {
              token: account.token,
              job: {
                daclSha256: hash,
                limitFlags: 0x2008,
                processLimit: 32,
                uiRestrictions: 255,
                members: [],
              },
              endpoints: account.endpoints,
            };
            if (f.caseDamage === "substituted-endpoint")
              value.endpoints = value.endpoints.map((entry, i) => ({
                ...entry,
                port: entry.port + (i === 0 ? 1 : 0),
              }));
          } else if (operation === "case-partial-retire") {
            const account = f.accounts.get(selected[2].path);
            if (account) account.retired = true;
            value = { retired: true };
          } else if (operation === "case-retire") {
            if (f.caseDamage === "retirement-loss")
              throw new Error("Missing retirement read");
            f.accounts.get(selected[2].path).retired = true;
            value = { retired: true };
          } else if (operation === "inspect")
            value = f.objectRead(selected[Number(values[0])]);
          else if (operation === "build")
            value = {
              major: 10,
              minor: 0,
              build: 26100,
              sdkRootHex: encode("C:\\Program Files (x86)\\Windows Kits\\10\\"),
            };
          else if (operation === "open") {
            const entry = selected[Number(values[0])];
            value = {
              identity: fileId(entry.path),
              pathHex: encode(entry.path),
              volumeHex: encode(
                "\\\\?\\Volume{11111111-1111-1111-1111-111111111111}\\",
              ),
              filesystemHex: encode("NTFS"),
              daclSha256: hash,
              links: 1,
              directory: entry.kind === "directory",
              held: true,
              reparse: false,
            };
          } else if (operation === "helper-start") {
            child = actor();
            worker = actor();
            jobs.set(child.pid, [child]);
            compilerJobs.set(child.pid, [worker]);
            jobNonces.set(child.pid, declaration.nonce);
            jobCreators.set(child.pid, helper.pid);
            images.set(child.pid, plan.command.helper.path);
            const nativeArgs = values
              .slice(3, 3 + Number(values[2]))
              .map(decode);
            images.set(worker.pid, nativeArgs[2]);
            currentOperation = nativeArgs[1];
            frames = [
              { worker },
              {
                stream: "stdout",
                hex: Buffer.from("reviewed\n").toString("hex"),
              },
              {
                exitCode: currentOperation === "compiler-version" ? 2 : 0,
                signal: null,
                members: 0,
              },
            ];
            if (currentOperation === "compile")
              f.files.set(
                nativeArgs[7],
                f.unsignedMismatch
                  ? Buffer.from("wrong unsigned image")
                  : unsigned,
              );
            value = {
              helper: child,
              processDaclSha256: hash,
              threadDaclSha256: hash,
              inheritedHandleCount: 2,
              job: job(child),
              creatorDefaultDaclSha256: hash,
            };
          } else if (operation === "helper-release") value = { released: true };
          else if (operation === "helper-read") {
            value = {
              hex: Buffer.from(JSON.stringify(frames.shift())).toString("hex"),
            };
          } else if (operation === "process-open") {
            const state = actors.get(Number(values[0]));
            assert.ok(state);
            assert.notEqual(
              state.identity.pid,
              helper.pid,
              "Native self-retain refusal",
            );
            assert.ok(processSlots.length < 32);
            value = { slot: processSlots.push(state) - 1, observation: state };
          } else if (operation === "process-image")
            value = {
              identity: worker,
              sha256: imageSha,
              signatureSha256: signatureSha,
            };
          else if (operation === "process")
            value = processSlots[Number(values[0])];
          else if (operation === "verifier") {
            const actual = actors.get(Number(values[0]));
            assert.ok(actual && !actual.retired);
            assert.equal(actual.identity.creationTime, values[1]);
            assert.notEqual(actual.identity.pid, helper.pid);
            value = actual.identity;
          } else if (operation === "helper-send") {
            const control = Buffer.from(values[1], "hex").toString();
            if (control === "R") actors.get(worker.pid).retired = true;
            if (control === "S") actors.get(child.pid).retired = true;
            value = { sent: true };
          } else if (operation === "helper-finish")
            value = { retired: true, members: 0, drained: true, exitCode: 0 };
          else if (operation === "publish-build") {
            const file = path.join(output, decode(values[1]));
            f.files.set(file, f.publicationMismatch ? unsigned : signed);
            value = {
              identity: fileId(file),
              sha256: imageSha,
              signatureSha256: signatureSha,
              daclSha256: hash,
              writerClosed: true,
            };
          } else if (operation === "finish") {
            if (observer)
              assert.ok(
                !scope.upload &&
                  !scope.readBytes &&
                  scope.retained.every((subject) => subject.retired),
              );
            actors.get(helper.pid).retired = true;
            value = { closed: true };
            queue.push(
              { sequence: Number(sequence), value },
              { phase: "helper-retired", helper, exitCode: 0 },
            );
            return;
          } else throw new Error("Unexpected custody operation: " + operation);
          queue.push({ sequence: Number(sequence), value });
        }
      },
    };
  };
  f.accounts = new Map();
  f.objectRead = (entry) => ({
    identity: fileId(entry.path),
    pathHex: encode(entry.path),
    volumeHex: encode("\\\\?\\Volume{11111111-1111-1111-1111-111111111111}\\"),
    filesystemHex: encode("NTFS"),
    daclSha256: hash,
    links: 1,
    directory: entry.kind === "directory",
    held: true,
    reparse: false,
  });
  f.options = {
    env: f.options.env,
    fs: {
      readFile: async (file) => {
        assert.fail(
          "Node must not read System-private preparation files: " + file,
        );
      },
      readdir: async () =>
        assert.fail("Directory discovery needs native custody"),
    },
    openPreparation: async (file, args, settings) => {
      assert.equal(file, plan.bootstrap.bridge.path);
      assert.deepEqual(settings.env, {
        CI: "true",
        GITHUB_ACTIONS: "true",
        PATH: "C:\\nonexistent",
      });
      assert.equal(settings.shell, false);
      assert.equal(args[0], "--observe");
      const declaration = [
        plan.bootstrap,
        ...plan.cases.map((entry) => entry.custody),
        ...(f.packageDeclaration ? [f.packageDeclaration.custody] : []),
      ].find((entry) => entry.plan.path === args[4]);
      assert.ok(declaration);
      return channel({ ...declaration, nonce: args[6] }, true, args);
    },
    readerOptions: { open: async (declaration) => channel(declaration) },
  };
  return Object.assign(f, {
    ...(experiment
      ? {
          prepared: {
            purpose: "experiment",
            job: f.job,
            directory,
            output,
            sourceDirectory,
            bootstrap: plan.bootstrap,
            sources: plan.sources,
            tools: f.manifest.tools,
            environment: f.manifest.environment,
            entries,
            helpers: f.manifest.helpers.map((helper) => ({
              ...helper,
              path: path.join(sourceDirectory, helper.name + ".exe"),
            })),
          },
        }
      : {}),
    rawEvents: events,
    rawCommands: commands,
    rawTasks: tasks,
    rawExitCodes: exitCodes,
    signed,
    unsigned,
    actors,
    sdkFile,
    rawActor: actor,
    rawFileId: fileId,
    rawJobs: jobs,
    rawCompilerJobs: compilerJobs,
    rawImages: images,
    rawRuntime: runtimeRead,
  });
}

function experimentImage() {
  const bytes = Buffer.alloc(1024);
  publicationBytes().unsigned.copy(bytes);
  bytes.write(".nexp", 328);
  bytes.writeUInt32LE(512, 336);
  bytes.writeUInt32LE(4096, 340);
  bytes.writeUInt32LE(512, 344);
  bytes.writeUInt32LE(512, 348);
  bytes.writeUInt32LE(0x40000040, 364);
  bytes.write("native-ci-experiment-v1\0", 512);
  return bytes;
}

function experimentBootstrapFixture() {
  const f = rawPreparation({ experiment: true }),
    checkoutRoot = "C:\\Fixture\\checkout",
    privateRoot = directory + "-bootstrap",
    sdkBuild = "10.0.22621.0",
    sdkRoot = "C:\\Program Files (x86)\\Windows Kits\\10\\",
    compiler = f.manifest.tools[0].path,
    sdk = path.join(sdkRoot, "bin", sdkBuild, "x64", "rc.exe"),
    header = path.join(sdkRoot, "Include", sdkBuild, "um", "Windows.h"),
    launcher = "C:\\Program Files\\Git\\cmd\\git.exe",
    runtime = "C:\\Program Files\\Git\\ucrt64\\bin\\git.exe",
    installed = new Set([compiler, sdk, header, launcher, runtime]),
    stats = new Map(),
    closed = [],
    commands = [],
    saved = [],
    diagnostics = [],
    reached = new Error("bootstrap consumer reached");
  for (const file of installed) f.files.set(file, f.signed);
  for (const name of WINDOWS_EXPERIMENT_SOURCES)
    f.files.set(path.join(checkoutRoot, "ci", "native", "win32", name), bytes);
  const stat = (file) => {
    if (!f.files.has(file))
      throw Object.assign(new Error("Fixture input missing"), {
        code: "ENOENT",
        path: file,
      });
    if (!stats.has(file))
      stats.set(file, {
        dev: 1,
        ino: stats.size + 1,
        mode: 0o100644,
        nlink: installed.has(file) ? 4 : 1,
        size: f.files.get(file).length,
        mtimeMs: 1,
        ctimeMs: 1,
        isFile: () => true,
        isSymbolicLink: () => false,
      });
    return { ...stats.get(file) };
  };
  const filesystem = {
    lstat: async (file) => stat(file),
    realpath: async (file) => file,
    open: async (file) => {
      const content = f.files.get(file);
      return {
        stat: async () => stat(file),
        read: async (buffer, offset, length, position) => ({
          bytesRead: content.copy(
            buffer,
            offset,
            position,
            position + Math.min(length, 37),
          ),
        }),
        close: async () => closed.push(file),
      };
    },
    mkdir: async () => {},
    writeFile: async (file, content, settings) => {
      assert.equal(settings.flag, "wx");
      assert.ok(!f.files.has(file), file);
      f.files.set(file, Buffer.from(content));
    },
    unlink: async (file) => assert.ok(f.files.delete(file)),
  };
  const binding = {
      checkoutSha: candidateSha,
      osBuild: "10.0.26100",
      nodeVersion: "v24.21.0",
    },
    options = {
      platform: "win32",
      architecture: "x64",
      nodeVersion: binding.nodeVersion,
      binding,
      checkoutRoot,
      filesystem,
      env: {
        ...f.options.env,
        SystemRoot: "C:\\Windows",
        PATH: "C:\\Fixture\\tools",
        RUNNER_ENVIRONMENT: "github-hosted",
        RUNNER_OS: "Windows",
        GITHUB_REPOSITORY: f.job.repository,
        GITHUB_RUN_ID: f.job.runId,
        GITHUB_RUN_ATTEMPT: "1",
      },
      selectToolchain: async () => ({
        environment: {
          ...f.manifest.environment,
          WindowsSDKVersion: sdkBuild + "\\",
          WindowsSdkDir: sdkRoot,
        },
      }),
      readCandidate: async () => bytes,
      command: async (file, args) => {
        commands.push({ file, args });
        let stdout = "";
        if (file === "git") stdout = candidateSha;
        else if (file === "where.exe")
          stdout = args[0] === "cl.exe" ? compiler : launcher;
        else if (file === launcher)
          stdout = "C:\\Program Files\\Git\\ucrt64\\libexec\\git-core";
        else if (file === compiler && args[0] === "/Bv")
          stdout = "Compiler Version 1.2 for x64";
        else if (file === sdk) stdout = "Version 1.2";
        else if (file === compiler) {
          const target = args.find((arg) => arg.startsWith("/Fe")).slice(3);
          f.files.set(target, experimentImage());
          f.files.set(target + ".obj", bytes);
        } else if (path.basename(file) === "whoami.exe")
          stdout = '"fixture","S-1-5-21-1-2-3-1001"';
        else {
          assert.equal(args[0], "--experiment-seal");
          stdout = JSON.stringify({
            purpose: "experiment",
            sealed: true,
            planSha256: args[2],
          });
        }
        return {
          exitCode: 0,
          signal: null,
          timedOut: false,
          stdout,
          stderr: "",
        };
      },
      open: async (prepared) => {
        f.bootstrap = prepared;
        throw reached;
      },
    };
  return Object.assign(f, {
    checkoutRoot,
    privateRoot,
    compiler,
    sdk,
    header,
    launcher,
    runtime,
    stats,
    stat,
    closed,
    commands,
    saved,
    diagnostics,
    reached,
    filesystem,
    bootstrapOptions: options,
    runBootstrap: () =>
      withNativeDiagnostics(
        () =>
          prepareWindowsExperiment(
            f.job,
            directory,
            async (job) => saved.push(job),
            options,
          ),
        (owner, value) => diagnostics.push({ owner, value }),
      ),
  });
}

test("Windows default experiment bootstrap admits installed links and binds private consumer bytes", async () => {
  const f = experimentBootstrapFixture();
  f.stat(f.runtime);
  f.stats.get(f.runtime).nlink = 128;
  await assert.rejects(f.runBootstrap(), (error) => {
    assert.equal(error.cause, f.reached);
    return true;
  });
  const prepared = f.bootstrap;
  assert.equal(prepared.gitRuntime.path, f.runtime);
  assert.equal(prepared.gitRuntime.sha256, digest(f.signed));
  assert.ok(f.closed.includes(f.launcher) && f.closed.includes(f.header));
  assert.equal(prepared.helpers.length, WINDOWS_HELPER_NAMES.length);
  f.prepared = prepared;
  f.manifest.windowsPreparation.bootstrap = prepared.bootstrap;
  const native = await openWindowsExperimentNative(prepared, {
    ...f.options,
    reopen: true,
  });
  try {
    for (const source of prepared.sources) {
      const file = path.join(prepared.sourceDirectory, source.name);
      assert.deepEqual((await native.read(file, source.sha256)).bytes, bytes);
    }
    const helper = prepared.helpers[0];
    assert.deepEqual(
      (await native.readImage(helper.path)).bytes,
      experimentImage(),
    );
    assert.deepEqual(
      (await native.readImage(f.compiler, true)).bytes,
      f.signed,
    );
    const runtime = await windowsExperimentGitRuntime(
      native,
      prepared.gitRuntime,
    );
    assert.equal(runtime[0].sha256, prepared.gitRuntime.sha256);
    f.files.set(f.runtime, Buffer.from("substituted runtime"));
    await assert.rejects(
      windowsExperimentGitRuntime(native, prepared.gitRuntime),
    );
    f.files.set(f.runtime, f.signed);
    // Inject substituted observations so the real consumer must reject its
    // unchanged source/helper pins without requiring a broken IPC peer.
    f.accessNative = async (operation, args) => {
      if (operation !== "prepare-read") return;
      const file = Buffer.from(args[0], "hex").toString("utf16le"),
        content = f.files.get(file);
      if (digest(content) === args[1]) return;
      return {
        identity: f.rawFileId(file),
        daclSha256: hash,
        protectedParents: true,
        sha256: digest(content),
        bytes: content.length,
        slot: 0,
      };
    };
    f.files.set(helper.path, Buffer.from("substituted helper"));
    await assert.rejects(native.readImage(helper.path));
    f.files.set(helper.path, experimentImage());
    const source = prepared.sources[0],
      file = path.join(prepared.sourceDirectory, source.name);
    f.files.set(file, Buffer.from("substituted source copy"));
    await assert.rejects(native.read(file, source.sha256));
    f.files.set(file, bytes);
  } finally {
    assert.equal((await native.close()).status, "RETIRED");
  }
});

test("Windows experiment case recovery rejoins closed original receipts and separates cancellation and observer cleanup failure", async () => {
  for (const fault of [null, "source", "object", "cleanup", "cancel"]) {
    const f = experimentBootstrapFixture();
    Object.assign(f.bootstrapOptions.binding, {
      candidateSha,
      platform: "win32",
      repository: f.job.repository,
      runId: f.job.runId,
      runAttempt: f.job.runAttempt,
      image: "windows-2025",
      architecture: "x64",
      workflow: "native-poc",
      jobId: "1",
    });
    await assert.rejects(
      f.runBootstrap(),
      (error) => error.cause === f.reached,
    );
    f.prepared = f.bootstrap;
    f.manifest.windowsPreparation.bootstrap = f.prepared.bootstrap;
    f.accessNative = (operation, args) => {
      if (operation === "prepare-experiment-volume")
        return {
          identity: f.rawFileId(
            Buffer.from(args[0], "hex").toString("utf16le"),
          ),
          distinctVolume: true,
        };
    };
    f.disappearObservers = true;
    const options = {
        ...f.options,
        ...f.bootstrapOptions,
        signal: new AbortController().signal,
        bootstrap: async () => f.prepared,
        open: openWindowsExperimentNative,
        readInstalled: async (file) => f.files.get(file),
        read: async (file) => f.files.get(file),
      },
      { job, preparation } = await prepareWindowsExperiment(
        f.job,
        directory,
        async () => {},
        options,
      ),
      input = windowsExperimentSystemInput(job, preparation),
      owners = new Map(),
      system = createWindowsExperimentSystemEffects(
        job,
        preparation,
        options,
        owners,
      ),
      recipe = windowsSystemRecipes().find(
        ({ id }) => id === "ownership.literal",
      );
    f.manifest.windowsPreparation.cases =
      input.manifest.windowsPreparation.cases;
    const prepared = await system.prepare(recipe, {
      policyBinding: preparation.system.bindings.find(
        ({ id }) => id === recipe.id,
      ).policyBinding,
      recordPolicy: async () => {},
    });
    prepared.admitted = await prepared.admitLiteral();
    assert.equal(
      assertWindowsLiteralObservation(
        prepared.input,
        WINDOWS_LITERAL_ARGUMENTS,
        prepared.admitted.record,
        await system.literal(prepared),
      ).status,
      "OBSERVED",
    );
    const settlementSettings = {
      signal: new AbortController().signal,
      execution: {
        id: recipe.id,
        effects: Object.fromEntries(
          NATIVE_EFFECT_CLASSES.map((effect) => [
            effect,
            { admission: "possible" },
          ]),
        ),
      },
    };
    await assert.rejects(
      system.settle(recipe, { ...prepared }, settlementSettings),
    );
    await assert.rejects(system.settle(recipe, null, settlementSettings));
    const settlements = await system.settle(
      recipe,
      prepared,
      settlementSettings,
    );
    assert.ok(
      Object.values(settlements).every(
        (entry) => !entry || entry.settlement.status === "RETIRED",
      ),
    );
    for (const files of owners.values())
      assert.equal((await files.settleFiles()).status, "RETIRED");
    assert.equal(f.rawTasks.size, 0);
    for (const [pid, actor] of f.actors) {
      assert.equal(actor.retired, true);
      f.actors.delete(pid);
      f.rawJobs.delete(pid);
      f.rawCompilerJobs.delete(pid);
    }
    for (const helper of input.manifest.helpers)
      f.files.delete(path.join(input.output, helper.name + ".exe"));
    const native = windowsPreparationOptions(input, options, new Map()),
      state = windowsPreparationContext(input, native),
      cleanup = new AbortController(),
      cleanupCause = new Error("Independent case observer finish failed"),
      cancellation = new Error("Case census canceled"),
      entered = Promise.withResolvers(),
      blocked = Promise.withResolvers();
    blocked.promise.catch(() => {});
    try {
      const { records } = await readWindowsRecoveryRecords(state),
        before = f.rawEvents.length,
        commands = f.commands.length;
      if (fault === "source")
        f.files.set(
          input.manifest.windowsPreparation.cases.find(
            ({ id }) => id === recipe.id,
          ).custody.sources[0].path,
          Buffer.from("changed sealed source"),
        );
      if (fault === "object") {
        const read = f.objectRead;
        f.objectRead = (entry) => ({
          ...read(entry),
          identity: "f".repeat(16) + ":" + "e".repeat(32),
        });
      }
      f.beforeRawCommand = async (operation) => {
        if (operation === "verify-cold-process" && fault === "cancel") {
          entered.resolve();
          await blocked.promise;
        }
        if (operation === "finish" && fault === "cleanup") throw cleanupCause;
      };
      let closed = 0;
      if (fault === "cancel") {
        const open = options.openPreparation;
        options.openPreparation = async (...args) => {
          const channel = await open(...args);
          return {
            ...channel,
            close() {
              closed++;
              blocked.reject(cancellation);
              channel.close();
            },
          };
        };
      }
      if (fault === "cleanup") f.coldDamage = "rights";
      const recover = () =>
        recoverWindowsCases(
          state,
          options,
          records,
          new Map(),
          () => assert.fail("No live case is available for replay"),
          {},
          cleanup.signal,
        );
      if (!fault) {
        const result = await recover();
        assert.equal(result.status, "RETIRED");
        assert.equal(result.independent, true);
      } else if (["source", "object"].includes(fault)) {
        await assert.rejects(recover);
      } else {
        const pending = recover();
        if (fault === "cancel") {
          await entered.promise;
          cleanup.abort(cancellation);
        }
        await assert.rejects(pending, (cause) => {
          assert.ok(cause instanceof AggregateError);
          assert.equal(cause.cause, cause.errors[0]);
          if (fault === "cleanup") assert.equal(cause.errors[1], cleanupCause);
          if (fault === "cancel") assert.equal(cause.cause, cancellation);
          return true;
        });
        if (fault === "cancel") assert.ok(closed > 0);
      }
      const events = f.rawEvents.slice(before);
      assert.equal(
        events.some((frame) => frame.startsWith("verify-cold-process ")),
        fault !== "source",
      );
      assert.ok(
        !events.some((frame) =>
          /^(?:verify-retain|helper-start|case-account|case-copy) /u.test(
            frame,
          ),
        ),
      );
      assert.equal(f.commands.length, commands, "Recovery cannot rebuild");
      assert.ok(
        !events.some((frame) => frame.startsWith("prepare-experiment-pe ")),
        "Final images remain unopened",
      );
    } finally {
      f.beforeRawCommand = null;
      f.coldDamage = null;
      assert.equal((await native.settleFiles()).status, "RETIRED");
    }
  }
});

test("Windows experiment partial preparation settles only its matching owner and keeps observer failure separate", async () => {
  for (const stage of ["pre-setup", "account"])
    for (const observerFailure of [false, true]) {
      const f = experimentBootstrapFixture();
      Object.assign(f.bootstrapOptions.binding, {
        candidateSha,
        platform: "win32",
        repository: f.job.repository,
        runId: f.job.runId,
        runAttempt: f.job.runAttempt,
        image: "windows-2025",
        architecture: "x64",
        workflow: "native-poc",
        jobId: "1",
      });
      await assert.rejects(
        f.runBootstrap(),
        (error) => error.cause === f.reached,
      );
      f.prepared = f.bootstrap;
      f.manifest.windowsPreparation.bootstrap = f.prepared.bootstrap;
      f.accessNative = (operation, args) =>
        operation === "prepare-experiment-volume"
          ? {
              identity: f.rawFileId(
                Buffer.from(args[0], "hex").toString("utf16le"),
              ),
              distinctVolume: true,
            }
          : undefined;
      f.disappearObservers = true;
      const options = {
          ...f.options,
          ...f.bootstrapOptions,
          signal: new AbortController().signal,
          bootstrap: async () => f.prepared,
          open: openWindowsExperimentNative,
          readInstalled: async (file) => f.files.get(file),
          read: async (file) => f.files.get(file),
        },
        { job, preparation } = await prepareWindowsExperiment(
          f.job,
          directory,
          async () => {},
          options,
        ),
        input = windowsExperimentSystemInput(job, preparation),
        recipe = windowsSystemRecipes().find(
          ({ id }) => id === "ownership.literal",
        ),
        declared = input.manifest.windowsPreparation.cases.find(
          ({ id }) => id === recipe.id,
        ),
        primary = new Error("Case preparation did not return"),
        secondary = new Error("Independent case observer did not retire");
      f.manifest.windowsPreparation.cases =
        input.manifest.windowsPreparation.cases;
      f.preSetupRejected = stage === "pre-setup";
      if (stage === "account")
        options.bindResources = async () => {
          throw primary;
        };
      const open = options.openPreparation;
      options.openPreparation = async (file, args, settings) => {
        const channel = await open(file, args, settings);
        if (!observerFailure || args[4] !== declared.custody.plan.path)
          return channel;
        return {
          ...channel,
          async send(frame) {
            if (frame.startsWith("finish ")) throw secondary;
            return channel.send(frame);
          },
        };
      };
      f.beforeRawCommand = (operation) => {
        if (operation === "verify-retain") {
          const pid = Number(f.rawEvents.at(-1).split(" ")[2]);
          assert.equal(
            f.actors.get(pid)?.retired,
            false,
            "Independent custody must be acquired before original exit",
          );
        }
      };
      const owners = new Map(),
        system = createWindowsExperimentSystemEffects(
          job,
          preparation,
          options,
          owners,
        ),
        settings = {
          signal: new AbortController().signal,
          execution: {
            id: recipe.id,
            effects: Object.fromEntries(
              NATIVE_EFFECT_CLASSES.map((effect) => [
                effect,
                { admission: "possible" },
              ]),
            ),
          },
        };
      let original;
      await assert.rejects(
        system.prepare(recipe, {
          signal: options.signal,
          policyBinding: preparation.system.bindings.find(
            ({ id }) => id === recipe.id,
          ).policyBinding,
          recordPolicy: async () => {},
        }),
        (cause) => {
          original = cause;
          if (stage === "account") assert.equal(cause, primary);
          else assert.equal(cause.admission.predicates.unique, false);
          return true;
        },
      );
      assert.equal(system.cause, original);
      const before = f.rawEvents.length;
      await assert.rejects(
        system.settle(
          { ...recipe, deadlineMs: recipe.deadlineMs + 1 },
          null,
          settings,
        ),
      );
      await assert.rejects(system.settle(recipe, {}, settings));
      await assert.rejects(
        system.settle(recipe, null, {
          ...settings,
          execution: { ...settings.execution, id: "files.private" },
        }),
      );
      assert.equal(
        f.rawEvents.length,
        before,
        "A foreign case cannot reach the retained owner",
      );
      const diagnostics = [],
        settlements = await withNativeDiagnostics(
          () => system.settle(recipe, null, settings),
          (_, value) => diagnostics.push(value),
        );
      assert.ok(
        Object.values(settlements).every(
          (entry) =>
            entry.settlement.status ===
            (observerFailure ? "RETAINED" : "RETIRED"),
        ),
      );
      assert.equal(
        system.cause,
        original,
        "Settlement cannot replace preparation failure",
      );
      if (observerFailure)
        assert.ok(
          diagnostics.some((value) =>
            value.exception?.errors?.includes(secondary),
          ),
        );
      else {
        assert.equal(f.rawTasks.size, 0);
        assert.ok([...f.actors.values()].every((actor) => actor.retired));
      }
      const records = [...f.files]
        .filter(([name]) =>
          name.startsWith(path.join(directory, `windows-case-${recipe.id}-`)),
        )
        .map(([, bytes]) => JSON.parse(bytes))
        .filter((record) => record.phase === "custody")
        .map(({ record }) => record);
      assert.ok(
        records.some(
          (record) =>
            record.phase === "retired" &&
            (stage !== "pre-setup" || record.preSetup === true),
        ),
      );
      if (stage === "pre-setup") {
        assert.ok(
          records.some((record) => record.phase === "pre-setup-helper-retired"),
        );
        assert.ok(
          !records.some((record) => record.phase === "finish-acknowledged"),
        );
        assert.equal(f.accounts.size, 0);
      } else
        assert.ok([...f.accounts.values()].every((account) => account.retired));
      assert.equal(
        f.commands.filter(
          ({ file, args }) => file === f.compiler && args[0] !== "/Bv",
        ).length,
        13,
      );
      if (stage === "pre-setup" && !observerFailure) {
        for (const pid of f.actors.keys()) {
          f.actors.delete(pid);
          f.rawJobs.delete(pid);
          f.rawCompilerJobs.delete(pid);
        }
        const native = windowsPreparationOptions(input, options, new Map()),
          state = windowsPreparationContext(input, native);
        try {
          const { records } = await readWindowsRecoveryRecords(state),
            before = f.rawEvents.length,
            proof = await recoverWindowsCases(
              state,
              options,
              records,
              new Map(),
              () => assert.fail("Pre-setup closure cannot replay a live owner"),
              {},
              settings.signal,
            );
          assert.equal(proof.status, "RETIRED");
          const events = f.rawEvents.slice(before);
          assert.ok(
            events.some((frame) => frame.startsWith("verify-cold-process ")),
          );
          assert.ok(
            !events.some((frame) => frame.startsWith("verify-retain ")),
          );
        } finally {
          assert.equal((await native.settleFiles()).status, "RETIRED");
        }
      }
    }
});

async function preparedExperimentFixture() {
  const f = experimentBootstrapFixture();
  f.bootstrapOptions.binding = {
    candidateSha,
    platform: "win32",
    repository: f.job.repository,
    runId: f.job.runId,
    runAttempt: f.job.runAttempt,
    checkoutSha: candidateSha,
    image: "windows-2025",
    osBuild: "10.0.26100",
    architecture: "x64",
    nodeVersion: "v24.21.0",
    workflow: "native-poc",
    jobId: "1",
  };
  await assert.rejects(f.runBootstrap(), (error) => error.cause === f.reached);
  f.prepared = f.bootstrap;
  f.manifest.windowsPreparation.bootstrap = f.prepared.bootstrap;
  f.accessNative = (operation, args) =>
    operation === "prepare-experiment-volume"
      ? {
          identity: f.rawFileId(
            Buffer.from(args[0], "hex").toString("utf16le"),
          ),
          distinctVolume: true,
        }
      : undefined;
  f.disappearObservers = true;
  const options = {
      ...f.options,
      ...f.bootstrapOptions,
      bootstrap: async () => f.prepared,
      open: openWindowsExperimentNative,
      readInstalled: async (file) => f.files.get(file),
      read: async (file) => f.files.get(file),
    },
    { job, preparation } = await prepareWindowsExperiment(
      f.job,
      directory,
      async () => {},
      options,
    );
  return { f, options, job, preparation };
}

async function experimentRuntimeFixture() {
  const { f, options, job, preparation } = await preparedExperimentFixture(),
    declaration = preparation.system.cases.find(({ id }) => id === "release"),
    specification = JSON.parse(
      f.files.get(declaration.bindings.operations.expectation.path),
    );
  f.manifest.windowsPreparation.cases = preparation.system.cases;
  installOperationNativeFixture(f, declaration.bindings.input, specification);
  const system = createWindowsExperimentSystemEffects(
      job,
      preparation,
      options,
      new Map(),
    ),
    recipe = windowsSystemRecipes().find(({ id }) => id === "release"),
    prepared = await system.prepare(recipe, {
      policyBinding: preparation.system.bindings.find(
        ({ id }) => id === "release",
      ).policyBinding,
      recordPolicy() {},
    });
  return { f, system, recipe, prepared };
}

test("Windows experiment runtime reads fresh images and modules through its admitted independent verifier", async () => {
  const { f, system, recipe, prepared } = await experimentRuntimeFixture();
  let helper, verifier, slots;
  for (let i = 0; i < 2; i++) {
    f.runtimeTimestamp = i;
    if (i) {
      const stock = "C:\\Windows\\System32\\dynamic.dll";
      f.files.set(stock, f.signed);
      f.runtimeModules = new Map([
        [helper.pid, [f.rawImages.get(helper.pid), stock]],
      ]);
    }
    const start = f.rawCommands.length,
      actual = await prepared.effects.observe(),
      commands = f.rawCommands.slice(start),
      reads = commands.filter(
        ({ operation }) => operation === "verify-runtime",
      );
    helper ??= actual.processImage.identity;
    verifier ??= actual.verifier;
    assert.notEqual(helper.pid, verifier.pid);
    assert.equal(actual.actual.images.length, 13);
    assert.deepEqual(actual.processImage.identity, helper);
    assert.equal(actual.runtime.timestamp, i);
    assert.equal(actual.runtime.loaded.length, i + 1);
    assert.equal(actual.runtime.importScope, "private-runtime");
    assert.equal(actual.runtime.independent, true);
    assert.equal(reads.length, 1);
    assert.deepEqual(reads[0].owner, verifier);
    if (slots) assert.deepEqual(reads[0].values, slots);
    slots = reads[0].values;
    assert.ok(
      !commands.some(({ operation }) =>
        ["process-open", "process-image", "loader"].includes(operation),
      ),
    );
    assert.deepEqual(
      commands
        .filter(({ operation }) => operation === "verify-process")
        .map(({ owner }) => owner),
      [verifier, verifier],
    );
  }
  const settled = await system.settle(recipe, prepared, {
    signal: new AbortController().signal,
    execution: execution(recipe.id),
  });
  assert.ok(
    Object.values(settled)
      .filter(Boolean)
      .every(({ settlement }) => settlement.status === "RETIRED"),
  );
  assert.equal(f.rawTasks.size, 0);
  assert.ok([...f.actors.values()].every(({ retired }) => retired));
});

test("Windows experiment runtime refuses substituted owners, image/module bindings and failed reads after success", async () => {
  for (const damage of [
    "pid",
    "birth",
    "session",
    "sid",
    "verifier",
    "image-slot",
    "case-image",
    "image-sha",
    "image-signature",
    "module-path",
    "module-identity",
    "module-sha",
    "module-signature",
    "module-dacl",
    "module-links",
    "missing",
    "extra-private",
    "import-scope",
    "process-slot",
    "fresh-process",
    "fresh-runtime",
  ]) {
    const { f, prepared } = await experimentRuntimeFixture(),
      observed = await prepared.effects.observe(),
      native = f.accessNative,
      cause = new Error("Fresh admitted runtime unavailable");
    let readRuntime = false;
    f.accessNative = async (operation, values, scope, ...args) => {
      if (
        damage === "case-image" &&
        readRuntime &&
        operation === "inspect" &&
        scope.entries[Number(values[0])].path ===
          f.rawImages.get(observed.processImage.identity.pid)
      )
        return {
          ...f.objectRead(scope.entries[Number(values[0])]),
          daclSha256: "f".repeat(64),
        };

      if (operation === "verify-process" && damage === "fresh-process")
        throw cause;
      if (operation === "verifier" && damage === "verifier")
        return { ...observed.verifier, creationTime: "99999" };
      if (operation !== "verify-runtime")
        return native(operation, values, scope, ...args);
      if (damage === "fresh-runtime") throw cause;
      readRuntime = true;
      const value = f.rawRuntime(values, scope),
        pid = value.processImage.identity.pid,
        file = scope.heldFilePaths[Number(values[1])];
      value.processImage.identity = { ...value.processImage.identity };
      const image = value.processImage,
        module = value.loader.loaded[0];
      if (damage === "pid") image.identity.pid++;
      if (damage === "birth") image.identity.creationTime = "99999";
      if (damage === "session") image.identity.sessionId++;
      if (damage === "sid") image.identity.userSid = "S-1-5-21-1-2-3-1001";
      if (damage === "image-slot")
        value.imageIdentity = f.rawFileId(
          scope.heldFilePaths.find((name) => name !== file),
        );
      if (damage === "image-sha") image.sha256 = "f".repeat(64);
      if (damage === "image-signature") image.signatureSha256 = "f".repeat(64);
      if (damage === "module-path") module.pathHex = encode(file + ".other");
      if (damage === "module-identity")
        module.identity = f.rawFileId(file + ".other");
      if (damage === "module-sha") module.sha256 = "f".repeat(64);
      if (damage === "module-signature")
        module.signatureSha256 = "f".repeat(64);
      if (damage === "module-dacl") module.daclSha256 = "f".repeat(64);
      if (damage === "module-links") module.links++;
      if (damage === "missing") value.loader.loaded = [];
      if (damage === "extra-private")
        value.loader.loaded.push({
          ...module,
          pathHex: encode("C:\\Fixture\\unapproved.dll"),
          identity: f.rawFileId("unapproved"),
        });
      if (damage === "import-scope") value.loader.importScope = "complete";
      if (damage === "process-slot")
        image.identity = scope.retained.find(
          ({ identity }) => identity.pid !== pid,
        ).identity;
      return value;
    };
    await assert.rejects(
      prepared.effects.observe(),
      (error) =>
        damage.startsWith("fresh-")
          ? error === cause
          : /Unverified/u.test(error.message),
      damage,
    );
  }
});

test("Windows raw experiment bindings cross the normalizing factory and shared preparation gate", async () => {
  const { f, options, job, preparation } = await preparedExperimentFixture(),
    raw = preparation.system.bindings.find(
      ({ id }) => id === "release",
    ).policyBinding,
    original = structuredClone(raw),
    normalized = normalizeExperimentPolicyBinding(raw),
    expected = observationDigest(normalized.template),
    declaration = preparation.system.cases.find(({ id }) => id === "release");
  assert.equal(
    raw.context.jobBindingSha256,
    observationDigest(job.preparation.expected.binding),
    "the CI job binding must match before testing policy parameter order",
  );
  assert.deepEqual(Object.keys(raw.template.policy.policy), [
    "kind",
    "authority",
    "accountSid",
    "restrictingSid",
    "inventorySha256",
  ]);
  assert.notEqual(observationDigest(raw.template), expected);
  f.manifest.windowsPreparation.cases = preparation.system.cases;
  installOperationNativeFixture(
    f,
    declaration.bindings.input,
    JSON.parse(f.files.get(declaration.bindings.operations.expectation.path)),
  );
  const boundary = new Error(
      "Controlled stop after the shared preparation gate",
    ),
    failures = [],
    commands = f.commands.length;
  let preparedCases = 0;
  const result = await withNativeDiagnostics(
    () =>
      runWindowsExperimentProofs(job, directory, {
        ...options,
        now: () => 0,
        persist: async () => {},
        load: async (current) => ({
          job: current,
          preparation,
          runtime: job.preparation.observed.components,
        }),
        runCase: async (_, recipe, prepared, effects, policy) => {
          assert.equal(recipe.id, "release");
          assert.equal(prepared.templateSha256, expected);
          assert.deepEqual(policy.policyBinding, normalized);
          assert.equal(policy.hasReceipt(), true);
          preparedCases++;
          // Native assertions are outside this binding regression. Refuse here
          // and exercise the real factory's independent settlement unchanged.
          throw boundary;
        },
        onFailure: async (_, cause) => failures.push(cause),
      }),
    () => {},
  );
  assert.equal(preparedCases, 1);
  assert.deepEqual(failures, [boundary]);
  assert.equal(result.failure, "probe-failed");
  assert.deepEqual(
    result.cases.map(({ id, status }) => [id, status]),
    [
      ["build", "PASS"],
      ["release", "FAIL"],
    ],
  );
  assert.equal(result.cases[1].policy.independent, true);
  assert.equal(result.cases[1].policy.effective, true);
  for (const entry of result.cases)
    for (const effect of Object.values(entry.effects))
      if (effect.admission === "possible")
        assert.deepEqual(effect.settlement, {
          status: "RETIRED",
          independent: true,
          emergencyCleanup: false,
        });
  assert.deepEqual(raw, original);
  assert.equal(f.commands.length, commands, "verification must not rebuild");
  assert.equal(f.rawTasks.size, 0);
  assert.ok([...f.actors.values()].every((actor) => actor.retired));
});

test("Windows experiment build settlement and cold consumers join original custody without replay", async () => {
  const f = experimentBootstrapFixture();
  Object.assign(f.bootstrapOptions.binding, {
    candidateSha,
    platform: "win32",
    repository: f.job.repository,
    runId: f.job.runId,
    runAttempt: f.job.runAttempt,
    image: "windows-2025",
    architecture: "x64",
    workflow: "native-poc",
    jobId: "1",
  });
  await assert.rejects(f.runBootstrap(), (error) => error.cause === f.reached);
  f.prepared = f.bootstrap;
  f.manifest.windowsPreparation.bootstrap = f.prepared.bootstrap;
  f.accessNative = (operation, args) => {
    if (operation === "prepare-experiment-volume")
      return {
        identity: f.rawFileId(Buffer.from(args[0], "hex").toString("utf16le")),
        distinctVolume: true,
      };
  };
  f.disappearObservers = true;
  let recoveries = 0;
  const options = {
      ...f.options,
      ...f.bootstrapOptions,
      signal: new AbortController().signal,
      bootstrap: async () => f.prepared,
      open: openWindowsExperimentNative,
      readInstalled: async (file) => f.files.get(file),
      read: async (file) => f.files.get(file),
      createEffects: (...args) => {
        const owner = createWindowsExperimentSystemEffects(...args);
        return {
          async recover(request) {
            recoveries++;
            const proof = await owner.recover(request);
            assert.equal(proof.status, "RETIRED", owner.cause?.stack);
            return proof;
          },
        };
      },
    },
    { job, preparation } = await prepareWindowsExperiment(
      f.job,
      directory,
      async () => {},
      options,
    ),
    closeFile = path.join(directory, "windows-experiment-close.json"),
    close = JSON.parse(f.files.get(closeFile)),
    observer = close.observer,
    records = [
      path.join(directory, `windows-files-${observer.nonce}-birth.json`),
      path.join(directory, `windows-files-${observer.nonce}-result.json`),
      closeFile,
    ],
    pristine = records.map((file) => f.files.get(file)),
    consumers = [
      () => loadWindowsExperiment(job, directory, options),
      () =>
        recoverWindowsExperimentProofs(job, directory, async () => {}, options),
    ],
    assertSettled = () => {
      assert.equal(f.rawTasks.size, 0);
      assert.ok([...f.actors.values()].every((actor) => actor.retired));
    };
  for (const file of records.slice(0, 2)) {
    const record = JSON.parse(f.files.get(file));
    for (const role of ["helper", "bridge"]) {
      assert.deepEqual(record[role], observer[role]);
      assert.notEqual(
        observationDigest(record[role]),
        observationDigest(observer[role]),
      );
    }
  }
  const beforeCold = f.commands.length;
  const work = new AbortController(),
    cleanup = new AbortController(),
    buildOwners = new Map(),
    system = createWindowsExperimentSystemEffects(
      job,
      preparation,
      options,
      buildOwners,
    ),
    policyProofs = [],
    built = await system.build({
      candidateSha,
      signal: work.signal,
      policyBinding: preparation.system.bindings.find(
        ({ id }) => id === "build",
      ).policyBinding,
      recordPolicy: (proof) => policyProofs.push(proof),
    });
  assert.equal(built.status, "OBSERVED");
  assert.equal(built.purpose, "experiment");
  assert.equal(built.independent, true);
  assert.equal(policyProofs.length, 1);
  assert.equal(buildOwners.size, 1);
  const files = [...buildOwners.values()][0],
    buildObserver = files.verification,
    beforeSettlement = f.rawEvents.length;
  assert.equal(files.admissionClosed, false);
  assert.equal(f.rawTasks.has(buildObserver.input.nonce), true);
  assert.equal(f.actors.get(buildObserver.identity.pid).retired, false);
  work.abort();
  // Follow the controller's real phase boundary. Only system settlement may
  // hand this owner's work signal to cleanup; the fixture supplies no handoff.
  const settled = await system.settle({ id: "build" }, null, {
    signal: cleanup.signal,
    execution: {
      id: "build",
      effects: Object.fromEntries(
        NATIVE_EFFECT_CLASSES.map((effect) => [
          effect,
          {
            admission: ["builds", "policy"].includes(effect)
              ? "possible"
              : "not-started",
          },
        ]),
      ),
    },
  });
  for (const [effect, receipt] of Object.entries(settled)) {
    if (!["builds", "policy"].includes(effect)) assert.equal(receipt, null);
    else
      assert.deepEqual(receipt.settlement, {
        status: "RETIRED",
        independent: true,
        emergencyCleanup: false,
      });
  }
  assert.equal(files.admissionClosed, true);
  assert.equal(buildOwners.size, 0);
  assertSettled();
  const custody = await files.settleFiles();
  assert.equal(custody.status, "RETIRED");
  assert.equal(custody.noLiveMembers, true);
  assert.equal(custody.taskRemoved, true);
  assert.equal(await files.settleFiles(), custody);
  assert.equal(
    f.rawEvents
      .slice(beforeSettlement)
      .filter((frame) => frame.startsWith("finish ")).length,
    1,
    "settlement must consume the original observer finish exactly once",
  );
  assert.equal(f.commands.length, beforeCold, "verification must not rebuild");
  for (const consume of consumers) {
    const start = f.rawEvents.length;
    await consume();
    const events = f.rawEvents.slice(start);
    for (const original of [observer.helper, observer.bridge])
      assert.ok(
        events.some((frame) =>
          new RegExp(`^verify-cold-process [0-9]+ ${original.pid} `, "u").test(
            frame,
          ),
        ),
      );
    assert.ok(!events.some((frame) => frame.startsWith("verify-retain ")));
    assert.ok(events.some((frame) => frame.startsWith("verify-cold-jobs ")));
    assert.ok(events.some((frame) => frame.startsWith("verify-task ")));
    assertSettled();
  }
  const recovered = await recoverWindowsPreparationOwners(
    {
      job,
      directory,
      output: f.prepared.output,
      manifest: {
        helpers: f.prepared.helpers,
        windowsPreparation: {
          purpose: "experiment",
          schemaVersion: 3,
          bootstrap: f.prepared.bootstrap,
        },
      },
    },
    f.options,
  );
  assert.equal(recovered.status, "RETIRED");
  assert.equal(recovered.observerSettlement.status, "RETIRED");
  assertSettled();
  const input = windowsExperimentSystemInput(job, preparation),
    selectorFile = path.join(directory, "windows-experiment-selector.json"),
    selectorBytes = f.files.get(selectorFile),
    inventory = async () => {
      const native = windowsPreparationOptions(input, options, new Map());
      try {
        return await readWindowsRecoveryRecords(
          windowsPreparationContext(input, native),
        );
      } finally {
        assert.equal((await native.settleFiles()).status, "RETIRED");
      }
    };
  const selected = await inventory();
  assert.ok(selected.entries.includes("windows-experiment-selector.json"));
  assert.ok(
    !selected.records.some(
      ({ name }) => name === "windows-experiment-selector.json",
    ),
    "the producer selector is metadata, not an effect intent",
  );
  const reordered = JSON.parse(selectorBytes);
  reordered.prepared.bootstrap.reader = Object.fromEntries(
    Object.entries(reordered.prepared.bootstrap.reader).reverse(),
  );
  f.files.set(selectorFile, Buffer.from(JSON.stringify(reordered)));
  await inventory();
  for (const change of [
    (value) => {
      value.purpose = "reviewed";
    },
    (value) => {
      value.schemaVersion = 4;
    },
    (value) => {
      value.extra = true;
    },
    (value) => {
      delete value.prepared;
    },
    (value) => {
      value.prepared.extra = true;
    },
    (value) => {
      value.prepared.job.candidateSha = "a".repeat(40);
    },
    (value) => {
      value.prepared.bootstrap.nonce = "d".repeat(32);
    },
    (value) => {
      value.prepared.bootstrap.plan.sha256 = "e".repeat(64);
    },
    (value) => {
      value.prepared.directory += "-other";
    },
    (value) => {
      value.prepared.commands.pop();
    },
    (value) => {
      value.prepared.gitRuntime.sha256 = "e".repeat(64);
    },
  ]) {
    const changed = JSON.parse(selectorBytes);
    change(changed);
    f.files.set(selectorFile, Buffer.from(JSON.stringify(changed)));
    await assert.rejects(inventory());
  }
  f.files.set(selectorFile, Buffer.from("{"));
  await assert.rejects(inventory());
  f.files.set(selectorFile, selectorBytes);
  const unknown = path.join(
    directory,
    "windows-experiment-selector-other.json",
  );
  f.files.set(unknown, selectorBytes);
  await assert.rejects(inventory());
  f.files.delete(unknown);
  f.files.delete(selectorFile);
  await inventory();
  f.files.set(selectorFile, selectorBytes);
  // Recovery needs original intent/birth journals, not completed preparation.
  const finals = [
      closeFile,
      path.join(directory, "windows-experiment-preparation.json"),
    ],
    savedFinals = finals.map((file) => f.files.get(file));
  for (const file of finals) f.files.delete(file);
  const originalOwner = createWindowsExperimentSystemEffects(
      job,
      preparation,
      options,
    ),
    recoveryRequest = {
      request: {
        candidateSha,
        platform: "win32",
        jobSha256: observationDigest(job),
        preparationSha256: observationDigest(preparation),
      },
      job,
      preparation,
      signal: options.signal,
    };
  assert.equal(
    (await originalOwner.recover(recoveryRequest)).status,
    "RETIRED",
    originalOwner.cause?.stack,
  );
  for (const [index, file] of finals.entries())
    f.files.set(file, savedFinals[index]);
  assertSettled();
  // Mutate the protected receipt bytes, leaving selectors and the job intact.
  // Both consumers must refuse before treating stored completion as proof.
  const changes = [
    ["pid", (value) => value.pid + 1],
    ["creationTime", (value) => String(BigInt(value.creationTime) + 1n)],
    ["sessionId", (value) => value.sessionId + 1],
    ["userSid", () => "S-1-5-21-4-5-6-1002"],
    ["pid", (value) => String(value.pid)],
    ["creationTime", (value) => Number(value.creationTime)],
    ["sessionId", (value) => String(value.sessionId)],
    ["userSid", () => "invalid"],
    ["creationTime", () => undefined],
    ["extra", () => true],
  ];
  for (const [index, file] of records.entries()) {
    for (const role of ["helper", "bridge"])
      for (const [field, change] of changes) {
        const record = JSON.parse(pristine[index]),
          value = (index === 2 ? record.observer : record)[role];
        value[field] = change(value);
        f.files.set(file, Buffer.from(JSON.stringify(record)));
        try {
          for (const consume of consumers) {
            await assert.rejects(consume());
            assertSettled();
          }
        } finally {
          f.files.set(file, pristine[index]);
        }
      }
    const fields =
      index === 2 ? ["taskSha256"] : ["nonce", "taskSha256", "status"];
    for (const field of fields) {
      const record = JSON.parse(pristine[index]),
        subject = index === 2 ? record.observer : record;
      subject[field] =
        field === "status"
          ? "RETAINED"
          : "d".repeat(field === "nonce" ? 32 : 64);
      f.files.set(file, Buffer.from(JSON.stringify(record)));
      try {
        for (const consume of consumers) {
          await assert.rejects(consume());
          assertSettled();
        }
      } finally {
        f.files.set(file, pristine[index]);
      }
    }
  }
  const intentFile = path.join(
      directory,
      `windows-files-${observer.nonce}-intent.json`,
    ),
    originalIntent = f.files.get(intentFile);
  for (const index of [1, 2, 4, 5, 6, 7, 8, 9]) {
    const intent = JSON.parse(originalIntent);
    intent.argumentsHex[index] = Buffer.from(
      "changed input",
      "utf16le",
    ).toString("hex");
    f.files.set(intentFile, Buffer.from(JSON.stringify(intent)));
    for (const consume of consumers) await assert.rejects(consume());
    f.files.set(intentFile, originalIntent);
  }
  assert.ok(
    !f.actors.has(observer.helper.pid) && !f.actors.has(observer.bridge.pid),
  );
  for (const fault of [
    "census-read",
    "incomplete-census",
    "job-read",
    "task-read",
    "surviving-helper-job",
    "surviving-compiler-job",
    "incomplete-job-inventory",
  ]) {
    f.coldDamage = fault;
    await assert.rejects(consumers[0](), fault);
    assert.ok(
      !f.actors.has(observer.helper.pid) && !f.actors.has(observer.bridge.pid),
    );
  }
  f.coldDamage = null;
  f.hiddenTasks = new Set([observer.nonce]);
  await assert.rejects(consumers[0]());
  f.hiddenTasks.clear();
  // A PID reused by a different birth or principal is never an absent original.
  for (const field of ["creationTime", "sessionId", "userSid"]) {
    const changed = {
      ...observer.helper,
      [field]:
        field === "creationTime"
          ? "999"
          : field === "sessionId"
            ? 1
            : f.prepared.bootstrap.runnerSid,
    };
    f.actors.set(changed.pid, { identity: changed, retired: true });
    await assert.rejects(consumers[0]());
    f.actors.delete(changed.pid);
  }
  // A fresh observer's own failed retirement still prevents consumer success.
  f.damage = "finish";
  await assert.rejects(consumers[0]());
  f.damage = null;
  // Stored completion cannot substitute for fresh original-task absence.
  f.rawTasks.set(observer.nonce, observer.helper);
  try {
    await assert.rejects(consumers[0]());
  } finally {
    f.rawTasks.delete(observer.nonce);
  }
  const uncertainTasks = [...f.rawTasks.keys()];
  assert.ok(
    uncertainTasks.length > 0,
    "failed fresh observers retain uncertainty",
  );
  await consumers[0]();
  assert.deepEqual(
    [...f.rawTasks.keys()],
    uncertainTasks,
    "a later observer cannot settle earlier uncertainty",
  );
  assert.equal(recoveries, 1, "invalid receipts cannot reach recovery effects");
  assert.equal(
    f.commands.length,
    beforeCold,
    "cold consumers must not rebuild",
  );
  const owners = new Map();
  windowsPreparationOptions(input, options, owners);
  const heldFiles = [...owners.values()][0],
    dependent = {
      beginCleanup: async () => {},
      close: async () => {
        throw new Error("Original reader remains unverified");
      },
    };
  await heldFiles.readdir(directory);
  heldFiles.retainReader(dependent, options.signal);
  const failedOwner = createWindowsExperimentSystemEffects(
    job,
    preparation,
    options,
    owners,
  );
  f.coldDamage = "census-read";
  assert.equal((await failedOwner.recover(recoveryRequest)).status, "RETAINED");
  const firstCause = failedOwner.cause,
    retainedTasks = [...f.rawTasks.keys()];
  assert.ok(firstCause);
  assert.ok(f.rawTasks.has(heldFiles.verification.input.nonce));
  f.coldDamage = null;
  const later = createWindowsPreparationFiles(input, options);
  await later.readdir(directory);
  assert.equal((await later.settleFiles()).status, "RETIRED");
  assert.deepEqual([...f.rawTasks.keys()], retainedTasks);
  await assert.rejects(heldFiles.settleFiles());
  assert.equal((await failedOwner.recover(recoveryRequest)).status, "RETAINED");
  assert.equal(failedOwner.cause, firstCause);
});

test("Windows experiment recovery partitions departed closed observers from interrupted held originals", async () => {
  for (const fault of [
    null,
    "cold-proof",
    "live-hold",
    "live-job",
    "cold-retirement",
  ]) {
    const f = rawPreparation({ experiment: true }),
      closed = createWindowsPreparationFiles(f, f.options);
    await closed.readdir(directory);
    const departed = [closed.verification.identity, closed.verification.bridge];
    f.disappearObservers = true;
    assert.equal((await closed.settleFiles()).status, "RETIRED");
    assert.ok(departed.every(({ pid }) => !f.actors.has(pid)));
    f.disappearObservers = false;
    const interrupted = createWindowsPreparationFiles(f, f.options),
      stop = new AbortController(),
      cause = new Error("Original observer interrupted");
    await interrupted.readdir(directory);
    const originals = [
        interrupted.verification.identity,
        interrupted.verification.bridge,
      ],
      nonce = interrupted.verification.input.nonce;
    await interrupted.beginCleanup(stop.signal);
    stop.abort(cause);
    for (const { pid } of originals) {
      f.actors.get(pid).retired = true;
      f.rawExitCodes.set(pid, 126);
    }
    assert.ok(
      !f.files.has(path.join(directory, `windows-files-${nonce}-result.json`)),
    );
    f.disappearObservers = true;
    f.beforeRawCommand = (operation) => {
      if (
        (fault === "cold-proof" && operation === "verify-cold-process") ||
        (fault === "live-hold" && operation === "verify-retain") ||
        (fault === "cold-retirement" && operation === "finish")
      )
        throw new Error(fault);
      if (fault === "live-job" && operation === "verify-recovery-jobs")
        f.coldDamage = "surviving-helper-job";
    };
    const start = f.rawEvents.length,
      recover = () =>
        recoverWindowsPreparationOwners(
          {
            job: f.job,
            directory,
            output: f.prepared.output,
            manifest: {
              helpers: f.prepared.helpers,
              windowsPreparation: {
                purpose: "experiment",
                schemaVersion: 3,
                bootstrap: f.prepared.bootstrap,
              },
            },
          },
          f.options,
          { onReadersRetired: async (proof) => assert.equal(proof, null) },
        );
    if (fault) {
      await assert.rejects(recover());
      assert.ok(
        f.rawTasks.has(nonce),
        "incomplete proof retains the original task",
      );
    } else {
      const proof = await recover();
      assert.equal(proof.status, "RETIRED");
      assert.equal(proof.tasksRemoved, true);
      assert.equal(proof.observerSettlement.status, "RETIRED");
      assert.deepEqual(
        proof.originals.flatMap(({ identities }) => identities),
        departed,
      );
      assert.equal(f.rawTasks.size, 0);
    }
    const events = f.rawEvents.slice(start);
    for (const { pid } of departed)
      assert.ok(
        !events.some((frame) =>
          new RegExp(`^verify-retain [0-9]+ ${pid} `, "u").test(frame),
        ),
      );
    if (!fault)
      for (const { pid } of originals)
        assert.ok(
          events.some((frame) =>
            new RegExp(`^verify-retain [0-9]+ ${pid} `, "u").test(frame),
          ),
        );
    const firstRetain = events.findIndex((frame) =>
      frame.startsWith("verify-retain "),
    );
    if (firstRetain >= 0) {
      const coldFinish = events.findIndex((frame) =>
        frame.startsWith("finish "),
      );
      assert.ok(coldFinish >= 0 && coldFinish < firstRetain);
      assert.ok(
        !events
          .slice(firstRetain)
          .some((frame) => frame.startsWith("verify-cold-process ")),
      );
    }
    if (["cold-proof", "cold-retirement"].includes(fault))
      assert.ok(!events.some((frame) => frame.startsWith("verify-retain ")));
    await assert.rejects(interrupted.settleFiles(), (error) => error === cause);
  }
});

test("Windows default experiment bootstrap diagnoses strict input predicates without reselection", async () => {
  for (const [damage, rule] of [
    ["missing", "lstat"],
    ["directory", "regular-file"],
    ["reparse", "nonsymlink"],
    ["empty", "positive-size"],
    ["oversize", "bounded-size"],
    ["canonical", "exact-realpath"],
    ["zero-links", "link-count"],
    ["too-many-links", "link-count"],
    ["source-links", "link-count"],
    ["helper-links", "link-count"],
    ["substitution", "opened-identity-and-metadata"],
    ["changed-links", "held-stability"],
    ["short-read", "complete-read"],
    ["path-substitution", "path-stability"],
  ]) {
    const f = experimentBootstrapFixture(),
      file =
        damage === "source-links"
          ? path.join(
              f.checkoutRoot,
              "ci",
              "native",
              "win32",
              WINDOWS_EXPERIMENT_SOURCES[0],
            )
          : damage === "helper-links"
            ? path.join(f.privateRoot, WINDOWS_HELPER_NAMES[0] + ".exe")
            : f.launcher;
    if (damage === "helper-links") {
      const lstat = f.filesystem.lstat;
      f.filesystem.lstat = async (name) => ({
        ...(await lstat(name)),
        ...(name === file ? { nlink: 2 } : {}),
      });
    } else {
      f.stat(file);
      const stat = f.stats.get(file);
      if (damage === "missing") f.files.delete(file);
      if (damage === "directory") stat.isFile = () => false;
      if (damage === "reparse") stat.isSymbolicLink = () => true;
      if (damage === "empty") stat.size = 0;
      if (damage === "oversize") stat.size = 134217729;
      if (damage === "zero-links") stat.nlink = 0;
      if (damage === "too-many-links") stat.nlink = 129;
      if (damage === "source-links") stat.nlink = 2;
      if (damage === "canonical")
        f.filesystem.realpath = async (name) =>
          name === file ? name.toLowerCase() : name;
      if (
        [
          "substitution",
          "changed-links",
          "short-read",
          "path-substitution",
        ].includes(damage)
      ) {
        const open = f.filesystem.open;
        f.filesystem.open = async (name) => {
          const handle = await open(name),
            held = await handle.stat();
          if (name !== file) return handle;
          if (damage === "substitution") stat.ino++;
          return {
            ...handle,
            read: async (...args) => {
              if (damage === "changed-links") stat.nlink++;
              if (damage === "path-substitution") stat.ino++;
              if (damage === "short-read") return { bytesRead: 0 };
              return handle.read(...args);
            },
            stat: async () =>
              damage === "path-substitution" ? held : handle.stat(),
          };
        };
      }
    }
    await assert.rejects(
      f.runBootstrap(),
      (error) => error.cause !== f.reached,
    );
    const diagnostic = f.diagnostics.find(
      ({ owner }) => owner === "windows-experiment-input",
    ).value.exception;
    assert.equal(diagnostic.file, file, damage);
    assert.equal(diagnostic.rule, rule, damage);
    assert.equal(diagnostic.maximumLinks, file === f.launcher ? 128 : 1);
    if (damage !== "missing")
      assert.equal(typeof diagnostic.before.nlink, "number");
    assert.equal(
      f.commands.filter(
        ({ file: command, args }) =>
          command === "where.exe" && args[0] === "git.exe",
      ).length,
      1,
    );
    if (file === f.launcher)
      assert.ok(
        !f.commands.some(({ file: command }) => command === f.launcher),
        damage,
      );
    assert.equal(
      f.saved.at(-1).preparationEffects.settlement.status,
      "RETAINED",
    );
  }
});

test("Windows default experiment bootstrap keeps arbitrary Git roots and source bindings strict", async () => {
  {
    const f = experimentBootstrapFixture(),
      arbitrary = "C:\\Fixture\\caller\\git.exe",
      command = f.bootstrapOptions.command;
    f.files.set(arbitrary, f.signed);
    f.stat(arbitrary);
    f.stats.get(arbitrary).nlink = 2;
    f.bootstrapOptions.command = async (file, args) => {
      const result = await command(file, args);
      return file === "where.exe" && args[0] === "git.exe"
        ? { ...result, stdout: arbitrary }
        : result;
    };
    await assert.rejects(f.runBootstrap());
    const diagnostic = f.diagnostics.find(
      ({ owner }) => owner === "windows-experiment-input",
    ).value.exception;
    assert.equal(diagnostic.file, arbitrary);
    assert.equal(diagnostic.installed, false);
    assert.equal(diagnostic.rule, "link-count");
  }
  for (const copied of [false, true]) {
    const f = experimentBootstrapFixture();
    if (copied) {
      const write = f.filesystem.writeFile;
      f.filesystem.writeFile = (file, content, settings) =>
        write(
          file,
          file === path.join(f.privateRoot, WINDOWS_EXPERIMENT_SOURCES[0])
            ? Buffer.from("changed copy")
            : content,
          settings,
        );
    } else
      f.bootstrapOptions.readCandidate = async () =>
        Buffer.from("changed candidate");
    await assert.rejects(
      f.runBootstrap(),
      (error) => error.cause !== f.reached,
    );
    assert.ok(!f.commands.some(({ args }) => args[0] === "--experiment-seal"));
    assert.equal(f.bootstrap, undefined);
  }
});

test("Windows default experiment bootstrap preserves filesystem and close failures when diagnostics fail", async () => {
  for (const [readFails, brokenDiagnostics] of [
    [true, false],
    [true, true],
    [false, true],
  ]) {
    const f = experimentBootstrapFixture(),
      primary = Object.assign(new Error("Fixture read failed"), {
        code: "EIO",
        errno: -5,
      }),
      cleanup = new Error("Fixture close failed"),
      open = f.filesystem.open;
    f.filesystem.open = async (file) => {
      const handle = await open(file);
      return file === f.launcher
        ? {
            ...handle,
            read: readFails
              ? async () => {
                  throw primary;
                }
              : handle.read,
            close: async () => {
              await handle.close();
              throw cleanup;
            },
          }
        : handle;
    };
    await assert.rejects(
      withNativeDiagnostics(
        () =>
          prepareWindowsExperiment(
            f.job,
            directory,
            async (job) => f.saved.push(job),
            f.bootstrapOptions,
          ),
        (owner, value) => {
          f.diagnostics.push({ owner, value });
          if (brokenDiagnostics)
            throw new Error("Fixture diagnostic sink failed");
        },
      ),
      (error) => {
        if (readFails) {
          assert.equal(error.cause.cause, primary);
          assert.deepEqual(error.cause.errors, [primary, cleanup]);
        } else assert.equal(error.cause, cleanup);
        assert.deepEqual(error.cleanupFailures, []);
        return true;
      },
    );
    const failure = f.diagnostics.find(
        ({ owner }) => owner === "windows-experiment-input",
      )?.value.exception,
      closed = f.diagnostics.find(
        ({ owner }) => owner === "windows-experiment-input-cleanup",
      ).value.exception;
    if (readFails) {
      assert.equal(failure.rule, "read");
      assert.equal(failure.cause, primary);
    } else assert.equal(failure, undefined);
    assert.equal(closed.cause, cleanup);
    assert.ok(f.closed.includes(f.launcher));
    assert.equal(
      f.saved.at(-1).preparationEffects.settlement.status,
      "RETAINED",
    );
  }
});

test("Windows experiment held-image protocol pins exact helpers and keeps installed reads separate", async () => {
  const f = rawPreparation({ experiment: true }),
    helper = f.prepared.helpers.find(({ name }) => name === "launcher"),
    installed = f.prepared.tools[0].path,
    requests = [];
  let changed = false;
  f.accessNative = async (operation, args) => {
    if (!["prepare-read", "prepare-experiment-input"].includes(operation))
      return;
    if (operation === "prepare-read" && args[0] !== encode(helper.path)) return;
    requests.push({ operation, args });
    if (operation === "prepare-read") {
      assert.deepEqual(args, [
        encode(helper.path),
        helper.sha256,
        "134217728",
        "0",
      ]);
      if (changed)
        return {
          identity: f.rawFileId(helper.path),
          daclSha256: hash,
          protectedParents: true,
          sha256: digest(Buffer.from("changed image")),
          bytes: 13,
          slot: 0,
        };
    } else assert.deepEqual(args, [encode(installed), "-", "134217728", "0"]);
  };
  const native = await openWindowsExperimentNative(f.prepared, {
    ...f.options,
    reopen: true,
  });
  try {
    const contract = "api-fixture-runtime-l1-1-0.dll",
      physical = "api-fixture-forward-l1-1-0.dll",
      target = "C:\\Windows\\System32\\fixture-runtime.dll";
    f.files.set(target, f.signed);
    f.importResolutions = new Map([
      [contract, target],
      [physical, target],
    ]);
    f.experimentImports = [
      { name: contract, delay: false },
      { name: physical, delay: true },
    ];
    const held = await native.readImage(helper.path);
    assert.equal(held.sha256, helper.sha256);
    assert.deepEqual(held.bytes, f.files.get(helper.path));
    assert.deepEqual(held.pe.imports, f.experimentImports);
    for (const name of [contract, physical])
      assert.deepEqual(await native.resolveImport(name, helper.path), {
        file: target,
        sha256: digest(f.signed),
        identitySha256: observationDigest(f.rawFileId(target)),
      });
    const stock = await native.readImage(installed, true);
    assert.deepEqual(stock.bytes, f.files.get(installed));
    assert.equal(requests.length, 2);
    for (const [file, isInstalled] of [
      [path.join(sourceDirectory, "unlisted.exe"), false],
      [installed, false],
      [helper.path, true],
    ])
      await assert.rejects(async () => native.readImage(file, isInstalled));
    assert.equal(requests.length, 2);
    changed = true;
    await assert.rejects(native.readImage(helper.path));
    assert.equal(requests.length, 3);
  } finally {
    assert.equal((await native.close()).status, "RETIRED");
  }
});

test("Windows experiment close coalesces its System publication observer retirement", async () => {
  const f = rawPreparation({ experiment: true }),
    work = new AbortController(),
    exited = Promise.withResolvers(),
    retiring = Promise.withResolvers(),
    open = f.options.openPreparation;
  f.options.openPreparation = async (...args) => {
    const channel = await open(...args);
    return {
      ...channel,
      get exited() {
        retiring.resolve();
        return exited.promise;
      },
    };
  };
  const native = await openWindowsExperimentNative(f.prepared, {
    ...f.options,
    signal: work.signal,
    reopen: true,
  });
  const entered = Promise.withResolvers(),
    release = Promise.withResolvers();
  f.beforeRawCommand = async (operation) => {
    if (operation === "finish") {
      entered.resolve();
      await release.promise;
    }
  };
  const first = native.close();
  await entered.promise;
  assert.equal(native.close(), first);
  assert.equal(native.files.admissionClosed, true);
  // Work cancellation after handoff cannot cancel the finite cleanup signal.
  work.abort();
  release.resolve();
  let completed = false;
  first.then(() => {
    completed = true;
  });
  await retiring.promise;
  await Promise.resolve();
  assert.equal(
    completed,
    false,
    "a retirement frame cannot replace actual bridge closure",
  );
  exited.resolve({ code: 0, signal: null });
  const result = await first;
  assert.equal(result.status, "RETIRED");
  assert.equal(await native.close(), result);
  assert.equal(
    f.rawEvents.filter((frame) => /^finish /u.test(frame)).length,
    1,
  );
  assert.equal(f.rawTasks.size, 0);
  assert.ok([...f.actors.values()].every((actor) => actor.retired));
});

test("Windows preparation observer cannot finish while its raw held subject is live", async () => {
  const f = rawPreparation(),
    files = createWindowsPreparationFiles(f, f.options);
  await files.readdir(directory);
  const subject = f.rawActor();
  await assert.rejects(
    files.verify("recoverCompleted", f.manifest.windowsPreparation.bootstrap, [
      subject,
    ]),
  );
  await assert.rejects(files.settleFiles(), { code: "ERR_ASSERTION" });
  assert.equal(f.actors.get(subject.pid).retired, false);
});

test("Windows preparation retains deadline exhaustion while awaiting actual bridge exit", async () => {
  const f = rawPreparation({ experiment: true }),
    open = f.options.openPreparation,
    waiting = Promise.withResolvers(),
    exited = Promise.withResolvers();
  let clock = 0;
  f.options.clock = () => clock;
  f.options.openPreparation = async (...args) => {
    const channel = await open(...args);
    return {
      ...channel,
      get exited() {
        waiting.resolve();
        return exited.promise;
      },
    };
  };
  const files = createWindowsPreparationFiles(f, f.options);
  await files.readdir(directory);
  const closing = files.settleFiles();
  await waiting.promise;
  clock = Number.MAX_SAFE_INTEGER;
  exited.resolve({ code: 0, signal: null });
  let original;
  await assert.rejects(closing, (cause) => {
    original = cause;
    return true;
  });
  await assert.rejects(files.settleFiles(), (cause) => cause === original);
  assert.equal(
    f.rawEvents.filter((frame) => /^finish /u.test(frame)).length,
    1,
  );
});

test("Windows fresh file observer cannot consume or release an original observer's pending read", async () => {
  const f = rawPreparation(),
    original = createWindowsPreparationFiles(f, f.options),
    entered = Promise.withResolvers(),
    release = Promise.withResolvers();
  await original.readdir(directory);
  const birth = original.verification.identity;
  f.beforeRawCommand = async (operation) => {
    if (operation === "prepare-bytes") {
      f.beforeRawCommand = null;
      entered.resolve();
      await release.promise;
    }
  };
  const pending = original.readProtected({ file: f.sdkFile, sha256: hash });
  await entered.promise;
  try {
    const fresh = createWindowsPreparationFiles(f, f.options),
      read = await fresh.readProtected({
        file: path.join(sourceDirectory, "custody.h"),
        sha256: hash,
      }),
      reader = createWindowsCustodyReader(
        f.manifest.windowsPreparation.bootstrap,
      );
    assert.deepEqual(read.bytes, bytes);
    const finishing = fresh.settleFiles();
    assert.throws(() => fresh.retainReader(reader));
    assert.equal((await finishing).status, "RETIRED");
    assert.throws(() => fresh.retainReader(reader));
    assert.equal(f.actors.get(birth.pid).retired, false);
  } finally {
    release.resolve();
    assert.deepEqual((await pending).bytes, bytes);
    assert.equal((await original.settleFiles()).status, "RETIRED");
  }
  assert.equal(f.rawTasks.size, 0);
  assert.ok([...f.actors.values()].every((actor) => actor.retired));
});

test("Windows retained reader release joins complete identities and exact recovery bindings", async () => {
  const f = rawPreparation(),
    files = createWindowsPreparationFiles(f, f.options),
    original = {
      inputSha256: hash,
      helper: identity(10),
      bridge: identity(11),
      taskSha256: hash,
    },
    reader = { retirementBinding: original },
    reorder = (value) => Object.fromEntries(Object.entries(value).reverse());
  await files.readdir(directory);
  files.retainReader(reader);
  const binding = {
      ...original,
      helper: reorder(original.helper),
      bridge: reorder(original.bridge),
    },
    proof = {
      ...retired,
      noLiveMembers: true,
      tasksRemoved: true,
      recordsSha256: hash,
      readers: [binding],
      observerCustody: {
        independent: true,
        nativeEventSha256: hash,
        identities: [files.verification.identity, files.verification.bridge],
      },
    };
  for (const invalid of [
    { ...binding, inputSha256: "f".repeat(64) },
    { ...binding, taskSha256: "f".repeat(64) },
    { ...binding, helper: { ...binding.helper, pid: 12 } },
    { ...binding, bridge: { ...binding.bridge, pid: "11" } },
    { ...binding, helper: { ...binding.helper, extra: true } },
    { ...binding, bridge: { pid: 11 } },
    { ...binding, extra: true },
  ])
    assert.throws(() =>
      files.releaseRecoveredReaders({ ...proof, readers: [invalid] }),
    );
  original.extra = true;
  try {
    assert.throws(() => files.releaseRecoveredReaders(proof));
  } finally {
    delete original.extra;
  }
  await assert.rejects(files.settleFiles());
  files.releaseRecoveredReaders(proof);
  assert.equal((await files.settleFiles()).status, "RETIRED");
  assert.equal(f.rawTasks.size, 0);
});

test("Windows experiment receipt rejection still settles the real file observer", async () => {
  const f = rawPreparation({ experiment: true }),
    native = await openWindowsExperimentNative(f.prepared, {
      ...f.options,
      reopen: true,
    });
  f.accessNative = (operation, args) => {
    if (
      operation === "prepare-write" &&
      Buffer.from(args[0], "hex").toString("utf16le") ===
        "windows-experiment-close.json"
    )
      return { created: false };
  };
  let failed;
  await assert.rejects(native.close(), (error) => {
    failed = error;
    assert.ok(error instanceof AggregateError);
    assert.equal(error.settlement?.status, "RETIRED");
    return true;
  });
  assert.equal(f.rawTasks.size, 0);
  assert.ok([...f.actors.values()].every((actor) => actor.retired));
  const commands = f.rawEvents.length;
  await assert.rejects(native.close(), (error) => error === failed);
  assert.equal(f.rawEvents.length, commands);
  assert.equal((await native.recover()).status, "RETIRED");
  assert.ok(
    !f.rawEvents
      .slice(commands)
      .some((frame) => /^(?:open|helper-start) /u.test(frame)),
  );
  assert.equal(f.rawTasks.size, 0);
});

test("Windows lost original observer finish waits for bridge exit without replaying finish", async () => {
  const f = rawPreparation({ experiment: true }),
    open = f.options.openPreparation,
    exited = Promise.withResolvers(),
    waiting = Promise.withResolvers(),
    primary = new Error("observer finish acknowledgement lost");
  let original;
  f.options.openPreparation = async (...args) => {
    const channel = await open(...args);
    if (original) return channel;
    original = channel;
    return {
      ...channel,
      async send(frame) {
        await channel.send(frame);
        if (frame.startsWith("finish ")) throw primary;
      },
      get exited() {
        waiting.resolve();
        return exited.promise;
      },
    };
  };
  const native = await openWindowsExperimentNative(f.prepared, {
    ...f.options,
    reopen: true,
  });
  const observer = native.files.verification.identity,
    bridge = native.files.verification.bridge,
    beforeClose = f.rawEvents.length,
    closing = native.close(),
    rejected = assert.rejects(closing, (error) => {
      assert.ok(error.settlement);
      assert.equal(error.settlement.status, "RETIRED");
      assert.ok(error.errors.includes(primary));
      return true;
    });
  await waiting.promise;
  assert.equal(native.close(), closing);
  assert.equal(f.actors.get(bridge.pid).retired, false);
  assert.ok(
    f.rawEvents
      .slice(beforeClose)
      .some((frame) =>
        new RegExp(`^verify-retain [0-9]+ ${observer.pid} `, "u").test(frame),
      ),
    "fresh recovery must hold the original observer before waiting for exit",
  );
  for (const actor of [observer, bridge]) {
    f.actors.get(actor.pid).retired = true;
    f.rawExitCodes.set(actor.pid, 126);
  }
  exited.resolve({ code: 126, signal: null });
  await rejected;
  // Neither the lost finish nor bridge exit establishes retirement. Recovery
  // has now independently rejoined the old births, whole Jobs and owned tasks.
  const originalFinishes = [...f.files.entries()]
    .filter(
      ([file]) =>
        file.includes(
          `windows-files-${native.files.verification.input.nonce}-`,
        ) && /-[0-9]+\.json$/u.test(file),
    )
    .map(([, bytes]) => JSON.parse(bytes))
    .filter((record) =>
      Buffer.from(record.commandHex, "hex").toString().startsWith("finish "),
    );
  assert.equal(originalFinishes.length, 1);
  const before = f.rawEvents.length;
  assert.equal((await native.recover()).status, "RETIRED");
  assert.ok(
    !f.rawEvents
      .slice(before)
      .some((frame) => /^(?:open|helper-start) /u.test(frame)),
  );
  assert.equal(f.rawTasks.size, 0);
});

test("original failed compiler trust observes bounded optional provider data before CLOSE", async () => {
  const absent = [0, -1, -1, -1, -1, 0, -1, -1, -1, 0];
  for (const [provider, expected] of [
    [{}, [1, 1, 1, 1, 8, 0, 3, 1, 3, 1, 1, 5, 1]],
    [{ module: false }, [0, 1, 0, ...absent]],
    [{ api: false }, [0, 1, 0, ...absent]],
    [{ state: false }, [1, 0, 0, ...absent]],
    [{ data: false }, [1, 1, 0, ...absent]],
    [{ structureSize: 0 }, [1, 1, 1, ...absent]],
    [{ readable: false }, [1, 1, 1, ...absent]],
    [{ shortRead: true }, [1, 1, 1, ...absent]],
    [{ count: 3, pointer: false }, [1, 1, 1, 1, 8, 0, 3, 0, 0, -1, -1, -1, 0]],
    [{ count: 0, pointer: true }, [1, 1, 1, 1, 8, 0, 0, 1, 0, -1, -1, -1, 0]],
    [{ stepsReadable: false }, [1, 1, 1, 1, 8, 0, 3, 1, 0, -1, -1, -1, 0]],
    [{ errors: [] }, [1, 1, 1, 1, 8, 0, 0, 0, 0, 0, -1, -1, 1]],
    [{ errors: [5, 8] }, [1, 1, 1, 1, 8, 0, 2, 1, 2, 2, 0, 5, 1]],
    [
      { errors: Array.from({ length: 65 }, (_, i) => (i >= 63 ? 5 : 0)) },
      [1, 1, 1, 1, 8, 0, 65, 1, 64, 1, 63, 5, 0],
    ],
  ]) {
    const f = rawPreparation({ experiment: true }),
      compiler = f.prepared.tools.find((tool) => tool.name === "compiler"),
      index = f.prepared.entries.findIndex(
        (entry) => entry.path === compiler.path,
      ),
      source = await compilerTrustFixture({
        entries: f.prepared.entries,
        files: f.files,
        identity: f.rawFileId,
        inspect: f.objectRead,
        result: 8,
        provider,
      });
    await assert.rejects(source.open(index, 2), (cause) => {
      const failure = cause.custodyReaderFailure;
      assert.equal(failure.sequence, 2);
      assert.equal(failure.trust.result, "0x00000008");
      assert.equal(failure.trust.closeResult, "0x00000000");
      assert.equal(failure.trust.entry, index);
      assert.equal(failure.trust.identity, f.rawFileId(compiler.path));
      assert.deepEqual(failure.trust.provider, expected);
      return true;
    });
    assert.deepEqual(source.calls, [1, 2]);
    assert.deepEqual(source.events.slice(0, 4), [
      "windows-directory",
      "environment",
      "verify",
      "provider-module",
    ]);
    assert.equal(source.events.at(-1), "close");
    assert.ok(
      source.records.every((record) => Buffer.byteLength(record) < 1024),
    );
  }
});

test("ordinary pin failures retain guard diagnostics before compiler trust", async () => {
  const f = rawPreparation({ experiment: true }),
    entries = structuredClone(f.prepared.entries),
    index = entries.findIndex(
      (entry) => entry.path === f.prepared.tools[0].path,
    );
  entries[index].sha256 = "f".repeat(64);
  const source = await compilerTrustFixture({
    entries,
    files: f.files,
    identity: f.rawFileId,
    inspect: f.objectRead,
  });
  await assert.rejects(source.open(index, 2), (error) => {
    const failure = error.custodyReaderFailure;
    assert.equal(failure.sequence, 2);
    assert.equal(failure.command, "open");
    assert.equal(typeof failure.lastError, "number");
    assert.ok(!Object.hasOwn(failure, "trust"));
    return true;
  });
  assert.deepEqual(source.calls, []);
});

test("actual reader and helper startup use fresh OS-derived environments", async () => {
  const f = rawPreparation({ experiment: true }),
    compiler = f.prepared.tools.find((tool) => tool.name === "compiler"),
    index = f.prepared.entries.findIndex(
      (entry) => entry.path === compiler.path,
    ),
    ambient = { SystemRoot: "Z:\\Caller", PATH: "Z:\\Tools", EXTRA: "discard" };
  for (const environment of [
    {},
    { ambient },
    { ambient, directory: "D:\\Shared OS\\系统 🌿" },
    { directory: "C:\\" + "a".repeat(4092) },
  ]) {
    const directory = environment.directory ?? "C:\\Windows",
      source = await compilerTrustFixture({
        entries: f.prepared.entries,
        files: f.files,
        identity: f.rawFileId,
        inspect: f.objectRead,
        environment,
      });
    await source.open(index, 2);
    assert.deepEqual(source.environment, {
      CI: "true",
      GITHUB_ACTIONS: "true",
      PATH: "C:\\nonexistent",
      SystemRoot: directory,
    });
    const expected = (root) =>
      Buffer.from(
        `CI=true\0GITHUB_ACTIONS=true\0PATH=C:\\nonexistent\0SystemRoot=${root}\0\0`,
        "utf16le",
      );
    assert.deepEqual(source.environmentBlock, expected(directory));
    assert.deepEqual(source.events, [
      "windows-directory",
      "environment",
      "verify",
      "close",
    ]);
    assert.deepEqual(source.calls, [1, 2]);
    for (const kind of [
      "build",
      "git",
      "file",
      "policy",
      "observer",
      "git-policy",
    ]) {
      const before = source.events.length,
        previous = source.helperStarts.at(-1)?.buffer,
        api =
          kind === "build" || kind === "git"
            ? "CreateProcessAsUserW"
            : "CreateProcessW";
      source.startHelper(kind);
      const started = source.helperStarts.at(-1);
      assert.equal(started.api, api);
      assert.deepEqual(started.environment, expected(directory));
      assert.notEqual(started.buffer, previous);
      assert.equal(started.buffer.length, 4160);
      assert.equal(started.flags, 0x80404);
      assert.equal(started.inherit, true);
      assert.deepEqual(source.events.slice(before), [
        "windows-directory",
        ...(kind === "file" ? ["file-sharing"] : []),
        "launch-setup",
        api,
      ]);
    }
    environment.directory = "E:\\Fresh OS\\系统 🌿";
    for (const kind of ["build", "file"]) {
      source.startHelper(kind);
      assert.deepEqual(
        source.helperStarts.at(-1).environment,
        expected(environment.directory),
      );
    }
    assert.deepEqual(source.environmentBlock, expected(directory));
    assert.deepEqual(source.calls, [1, 2]);
  }
});

test("actual reader startup refuses invalid directory or environment installation before trust", async () => {
  const f = rawPreparation({ experiment: true });
  for (const environment of [
    { length: 0 },
    { length: 4096 },
    { length: 4097 },
    { length: 8 },
    { terminated: false },
    { directory: "C:\\Win\0Other" },
    { directory: "Windows" },
    { directory: "C:Windows" },
    { directory: "C:\\" },
    { directory: "\\\\server\\Windows" },
    { directory: "1:\\Windows" },
    { directory: "C:/Windows" },
    { directory: 'C:\\Bad"Windows' },
    { directory: "C:\\Windows\n" },
    { install: false },
  ]) {
    const source = await compilerTrustFixture({
      entries: f.prepared.entries,
      files: f.files,
      identity: f.rawFileId,
      inspect: f.objectRead,
      environment,
    });
    await assert.rejects(source.open(0, 1), /native guard rejected/u);
    assert.deepEqual(
      source.events,
      environment.install === false
        ? ["windows-directory", "environment"]
        : ["windows-directory"],
    );
    assert.deepEqual(source.calls, []);
    assert.deepEqual(source.seeks, []);
    assert.deepEqual(source.records, []);
  }
});

test("Windows registry attempts retained and thrown readers without bypassing dependencies", async () => {
  const f = rawPreparation(),
    files = createWindowsPreparationFiles(f, f.options),
    calls = [];
  await files.readdir(directory);
  const retainedCause = new Error("retained close"),
    thrownCause = new Error("thrown close");
  const reader = (name, close) => ({
    beginCleanup: async () => calls.push(name + " cleanup"),
    close,
  });
  files.retainReader(
    reader("retained", async () => {
      calls.push("retained");
      return { status: "RETAINED", cause: retainedCause };
    }),
  );
  files.retainReader(
    reader("thrown", async () => {
      calls.push("thrown");
      throw thrownCause;
    }),
  );
  files.retainReader(
    reader("retired", async () => {
      calls.push("retired");
      return { ...retired, taskRemoved: true };
    }),
  );
  await files.beginCleanup(AbortSignal.timeout(30000));
  const attempts = [files.retireReaders(), files.retireReaders()];
  for (const attempt of attempts)
    await assert.rejects(
      attempt,
      (error) =>
        error.errors[0].cause === retainedCause &&
        error.errors[1] === thrownCause,
    );
  assert.deepEqual(calls, [
    "retained cleanup",
    "thrown cleanup",
    "retired cleanup",
    "retained",
    "thrown",
    "retired",
  ]);
  await assert.rejects(files.settleFiles());
  assert.throws(() =>
    files.retainReader(reader("late", () => assert.fail("late admission"))),
  );
  assert.ok(!f.rawEvents.some((frame) => /^finish /u.test(frame)));
});

test("Windows file observer cleanup cancellation ends pending IPC without replaying finish", async () => {
  const f = rawPreparation(),
    open = f.options.openPreparation,
    entered = Promise.withResolvers(),
    blocked = Promise.withResolvers(),
    cleanup = new AbortController();
  blocked.promise.catch(() => {});
  let closed = 0;
  f.options.openPreparation = async (...args) => {
    const channel = await open(...args),
      send = channel.send.bind(channel),
      receive = channel.receive.bind(channel);
    let finishing = false;
    return {
      ...channel,
      send: async (frame) => {
        await send(frame);
        if (/^finish /u.test(frame)) {
          finishing = true;
          entered.resolve();
        }
      },
      receive: () => (finishing ? blocked.promise : receive()),
      close: () => {
        closed++;
        blocked.reject(cleanup.signal.reason);
        channel.close();
      },
    };
  };
  const files = createWindowsPreparationFiles(f, f.options);
  await files.readdir(directory);
  await files.beginCleanup(cleanup.signal);
  const pending = files.settleFiles();
  await entered.promise;
  cleanup.abort(new Error("cleanup interval exhausted"));
  await assert.rejects(pending, /cleanup interval exhausted/u);
  await assert.rejects(
    files.settleFiles(),
    (error) => error === cleanup.signal.reason,
  );
  assert.ok(closed > 0);
  assert.equal(
    f.rawEvents.filter((frame) => /^finish /u.test(frame)).length,
    1,
  );
});

test("Windows experiment cold observer cancellation interrupts its pending native census", async () => {
  const f = rawPreparation({ experiment: true }),
    original = createWindowsPreparationFiles(f, f.options);
  await original.readdir(directory);
  const nonce = original.verification.input.nonce;
  f.disappearObservers = true;
  assert.equal((await original.settleFiles()).status, "RETIRED");
  const receipt = (suffix) =>
      JSON.parse(
        f.files.get(
          path.join(directory, `windows-files-${nonce}-${suffix}.json`),
        ),
      ),
    owner = windowsClosedPreparationOwner(receipt("birth"), receipt("result")),
    entered = Promise.withResolvers(),
    blocked = Promise.withResolvers(),
    work = new AbortController(),
    cause = new Error("Cold verification canceled"),
    open = f.options.openPreparation;
  let closed = 0;
  blocked.promise.catch(() => {});
  f.beforeRawCommand = async (operation) => {
    if (operation === "verify-cold-process") {
      entered.resolve();
      await blocked.promise;
    }
  };
  f.options.openPreparation = async (...args) => {
    const channel = await open(...args);
    return {
      ...channel,
      close() {
        closed++;
        blocked.reject(cause);
        channel.close();
      },
    };
  };
  const files = createWindowsPreparationFiles(f, f.options),
    start = f.rawEvents.length;
  files.beginVerification(work.signal);
  const pending = files.verify("verifyColdPreparation", f.prepared.bootstrap, [
    owner,
  ]);
  await entered.promise;
  work.abort(cause);
  await assert.rejects(
    pending,
    (error) => error === cause || error.errors?.includes(cause),
  );
  assert.ok(closed > 0);
  await assert.rejects(
    files.verify("verifyColdPreparation", f.prepared.bootstrap, [owner]),
    (error) => error === cause,
  );
  assert.ok(
    !f.rawEvents.slice(start).some((frame) => frame.startsWith("finish ")),
  );
});

test("Windows preparation preserves the open failure and separately persists cleanup and receipt failures", async () => {
  const f = rawPreparation({ experiment: true }),
    primary = new Error("original publication write"),
    receipt = new Error("job receipt unavailable"),
    saved = [];
  const prepared = structuredClone(f.prepared);
  prepared.schemaVersion = 4;
  prepared.gitRuntime = {
    executable: "C:\\Program Files\\Git\\cmd\\git.exe",
    execPath: "C:\\Program Files\\Git\\mingw64\\libexec\\git-core",
    directory: "C:\\Program Files\\Git\\mingw64\\bin",
    path: "C:\\Program Files\\Git\\mingw64\\bin\\git.exe",
    sha256: hash,
  };
  prepared.sourceDirectory = directory + "-bootstrap";
  prepared.helpers = prepared.helpers.map((helper) => ({
    ...helper,
    path: path.join(prepared.sourceDirectory, helper.name + ".exe"),
  }));
  prepared.binding = {
    checkoutSha: candidateSha,
    osBuild: "10.0.26100",
    nodeVersion: "v24.21.0",
  };
  prepared.bootstrap.context.jobBindingSha256 = observationDigest(
    prepared.binding,
  );
  f.manifest.windowsPreparation.bootstrap.context.jobBindingSha256 =
    observationDigest(prepared.binding);
  prepared.tools = prepared.tools.map(({ name, path, sha256 }) => ({
    name,
    path,
    sha256,
  }));
  prepared.helpers = prepared.helpers.map((helper) => ({
    ...helper,
    signatureSha256: helper.sha256,
  }));
  prepared.sdkBuild = "10.0.22621.0";
  prepared.sdkHeader = { file: f.sdkFile, sha256: hash };
  prepared.versions = { compiler: "1.2", sdk: "1.2" };
  const environment = {
    CI: "true",
    GITHUB_ACTIONS: "true",
    LANG: "C",
    ...prepared.environment,
    TEMP: "C:\\Fixture",
    TMP: "C:\\Fixture",
  };
  const command = (file, args, stdout = "") => ({
    file,
    args,
    cwd: prepared.sourceDirectory,
    env: environment,
    timeout: 60000,
    maxBuffer: 1048576,
    exitCode: 0,
    signal: null,
    timedOut: false,
    stdout,
    stderr: "",
  });
  prepared.commands = [
    command("git", ["rev-parse", "HEAD"], candidateSha),
    command("where.exe", ["cl.exe"], prepared.tools[0].path),
    command("where.exe", ["git.exe"], prepared.gitRuntime.executable),
    command(
      prepared.gitRuntime.executable,
      ["--exec-path"],
      prepared.gitRuntime.execPath,
    ),
    command(prepared.tools[0].path, ["/Bv"], "Compiler Version 1.2 for x64"),
    ...WINDOWS_HELPER_NAMES.map((name) =>
      command(
        prepared.tools[0].path,
        windowsHostedCompilerArguments(
          path.join(prepared.sourceDirectory, name + ".c"),
          path.join(prepared.sourceDirectory, name + ".exe"),
        ),
      ),
    ),
    command(prepared.tools[1].path, ["/?"], "Version 1.2"),
    command(
      path.join(prepared.environment.SystemRoot, "System32", "whoami.exe"),
      ["/user", "/fo", "csv", "/nh"],
      `"fixture","${prepared.bootstrap.runnerSid}"`,
    ),
  ];
  f.beforeRawCommand = (operation) => {
    if (operation === "prepare-write") throw primary;
  };
  await assert.rejects(
    prepareWindowsExperiment(
      f.job,
      directory,
      async (value) => {
        saved.push(value);
        if (value.failure === "preparation-failed") throw receipt;
      },
      {
        ...f.options,
        platform: "win32",
        architecture: "x64",
        nodeVersion: "v24.21.0",
        binding: {
          checkoutSha: candidateSha,
          osBuild: "10.0.26100",
          nodeVersion: "v24.21.0",
        },
        env: {
          ...f.options.env,
          RUNNER_ENVIRONMENT: "github-hosted",
          RUNNER_OS: "Windows",
          GITHUB_REPOSITORY: f.job.repository,
          GITHUB_RUN_ID: f.job.runId,
          GITHUB_RUN_ATTEMPT: "1",
        },
        bootstrap: async () => prepared,
      },
    ),
    (error) => {
      assert.equal(error.cause, primary);
      assert.ok(error.cleanupFailures.includes(receipt));
      assert.equal(error.experimentJob.failure, "preparation-failed");
      return true;
    },
  );
  assert.equal(saved.at(-1).preparationEffects.settlement.status, "RETAINED");
  for (const actor of f.actors.values()) actor.retired = true;
  const recovered = await recoverWindowsExperimentPreparation(
    saved.at(-1),
    directory,
    async (value) => saved.push(value),
    {
      ...f.options,
      platform: "win32",
      architecture: "x64",
      signal: AbortSignal.abort(new Error("preparation already ended")),
      env: {
        ...f.options.env,
        RUNNER_ENVIRONMENT: "github-hosted",
        RUNNER_OS: "Windows",
        GITHUB_REPOSITORY: f.job.repository,
        GITHUB_RUN_ID: f.job.runId,
        GITHUB_RUN_ATTEMPT: "1",
      },
      read: async () => Buffer.from(JSON.stringify(prepared)),
    },
  );
  assert.equal(recovered.preparationEffects.settlement.status, "RETIRED");
  assert.equal(recovered.failure, "preparation-failed");
  assert.equal(f.rawTasks.size, 0);
  assert.equal(
    f.rawEvents.filter((frame) => /^helper-start /u.test(frame)).length,
    0,
  );
});

test("fixed provider helper preparation rejoins Windows System custody and helpers without compiling", async () => {
  for (const fault of [
    null,
    "image",
    "task-loss",
    "surviving-helper-job",
    "surviving-compiler-job",
    "incomplete-job-inventory",
    "recovery",
    "missing-birth",
  ]) {
    const f = rawPreparation(),
      provider = providerPreparationFixture("win32", candidateSha),
      input = provider.input;
    delete input.api;
    input.buildManifest = f.manifest;
    input.manifest.providerPreparation.bootstrap = {
      ...f.manifest.windowsPreparation.bootstrap,
      context: input.manifest.providerPreparation.bootstrap.context,
    };
    input.manifest.providerPreparation.sourceDirectory =
      f.manifest.windowsPreparation.sourceDirectory;
    for (const member of input.manifest.inputs)
      f.files.set(member.path, provider.files.get(member.path));
    for (const helper of f.manifest.helpers)
      f.files.set(path.join(output, helper.name + ".exe"), f.signed);
    const request = {
        candidateSha,
        platform: "win32",
        reviewSha256: observationDigest(input.manifest),
        helpers: [],
        tools: input.buildManifest.tools,
        output: input.providerHelpers,
        deadlineMs: 120000,
        commands: [],
      },
      options = {
        env: f.options.env,
        fileTransport: f.options,
        readerOptions: f.options.readerOptions,
      },
      owner = fixedProviderEffects(input, options);
    assert.equal(f.rawEvents.length, 0);
    const receipt = await owner.prepareBuild(request);
    input.preparation = {
      status: "PASS",
      request,
      requestSha256: observationDigest(request),
      receiptSha256: observationDigest(receipt),
      filesSettlement: await owner.settleBuild(),
    };
    assert.equal(f.rawTasks.size, 0);
    if (["recovery", "missing-birth"].includes(fault)) {
      for (const helper of f.manifest.helpers)
        f.files.delete(path.join(output, helper.name + ".exe"));
      f.files.delete(
        path.join(
          directory,
          `provider-build-${observationDigest(request)}-result.json`,
        ),
      );
      if (fault === "missing-birth")
        for (const file of [...f.files.keys()])
          if (/windows-files-.*-birth\.json$/u.test(file)) f.files.delete(file);
      const preparation = { status: "POSSIBLE" },
        recovery = {
          candidateSha,
          platform: "win32",
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
    if (fault === "image")
      f.files.set(
        path.join(output, "launcher.exe"),
        Buffer.from("substituted image"),
      );
    if (fault === "task-loss")
      input.preparation.filesSettlement.observations[0].taskRemoved = false;
    if (
      [
        "surviving-helper-job",
        "surviving-compiler-job",
        "incomplete-job-inventory",
      ].includes(fault)
    )
      f.coldDamage = fault;
    const pending = fixedProviderEffects(input, options).verifyBuild();
    if (fault) await assert.rejects(pending, undefined, fault);
    else {
      assert.equal((await pending).status, "RETIRED");
      assert.equal(f.rawTasks.size, 0);
    }
    assert.equal(
      f.rawEvents.some((event) => event.startsWith("build-launch")),
      false,
    );
  }
});

async function buildRawPreparation(f) {
  const build = await createBuildEffects(f, f.options);
  f.preparation.reviewSha256 = observationDigest(f.manifest);
  f.preparation.helpers = f.manifest.helpers.map(({ name, sha256 }) => ({
    name,
    sha256,
  }));
  f.preparation.versions = f.manifest.tools.map(
    ({ name, version, sha256 }) => ({ name, version, sha256 }),
  );
  f.preparation.commands = [];
  for (const request of f.requests) {
    const result = await build.run(request);
    f.preparation.commands.push({
      requestSha256: observationDigest(request),
      status: "RETIRED",
      receiptSha256: observationDigest(result),
    });
  }
  return build;
}
function provisionAccessCase(f, profile, fault, runtimeCount = 0) {
  f.options.nativeOptions = { platform: "win32", architecture: "x64" };
  f.options.env.ImageVersion = "20260101.1.0";
  const result = provisionCase(f, `access.${profile}.${fault}`),
    { declaration, binding } = result,
    request = declaration.bindings.input,
    input = windowsPolicyFixture(request, "S-1-5-21-1-2-3-1001", profile).input,
    versions = [4656, 4663, 5152, 5156, 5157].map((id) => ({
      id,
      versions: [1],
    })),
    sourceFacts = Object.fromEntries(
      [
        "inheritedAccessVerified",
        "hostObjectAccessReviewed",
        "noForeignHandles",
        "noDelegation",
        "noUnreviewedLoaderExceptions",
        "accountReservationVerified",
        "ancestorTraversalVerified",
        "disposableStorageVerified",
        "baselineInventoryVerified",
        "inheritedOwnerRightsProtected",
        "creationDaclProtectionVerified",
        "registryParentProtected",
      ].map((key) => [key, true]),
    ),
    wfpFacts = Object.fromEntries(
      [
        "localSocketPrincipal",
        "restrictedTokenMatchVerified",
        "unknownIdentityDenied",
        "loopbackAleVerified",
        "udpReturnAleVerified",
        "globalPrecedenceVerified",
        "noConflictingHardPermit",
        "noLoopbackExemption",
        "noUnfilteredRoute",
        "noForeignCallout",
      ].map((key) => [key, true]),
    ),
    approval = {
      schemaVersion: 1,
      candidateSha,
      contextSha256: observationDigest(binding.context),
      sourceReviewSha256: hash,
      profile,
      disposable: true,
      sourceFacts,
      wfpFacts,
      foreignGraphSha256: observationDigest([]),
      audit: {
        pins: {
          manifestSha256: hash,
          imageSha256: digest(f.signed),
          sourceSha256: hash,
          abiSha256: hash,
        },
        mapping: {
          sdkSha256: hash,
          abiSha256: hash,
          versions,
          mappingSha256: observationDigest(versions),
        },
      },
    },
    approvalBytes = Buffer.from(JSON.stringify(approval) + "\n"),
    approvalPath = path.join(
      sourceDirectory,
      declaration.id + "-approval.json",
    );
  input.reviewSha256 = digest(approvalBytes);
  f.files.set(approvalPath, approvalBytes);
  for (let i = 0; i < runtimeCount; i++)
    input.runtime.push({
      path: request.storage + "\\runtime-" + i + ".exe",
      sha256: digest(f.signed),
      reviewSha256: hash,
    });
  const plan = buildWindowsPolicy(input);
  request.policy.sha256 = plan.policySha256;
  request.bindings.policy = plan.compositionSha256;
  const entries = decodeWindowsPlan(
    f.files.get(declaration.custody.plan.path),
    declaration.custody,
  );
  entries[8].path = path.join(sourceDirectory, "access-fixture.exe");
  declaration.bindings.assets[1].path = entries[8].path;
  for (const object of plan.manifest.objects.filter(
    ({ name }) => name !== "registry",
  ))
    if (!entries.some(({ path: file }) => file === object.path)) {
      const directory = [
          "metadata",
          "checkout",
          "configuration",
          "credentials",
        ].includes(object.name),
        bytes = Buffer.from(
          object.name === "pointer"
            ? `gitdir: ${request.storage.replaceAll("\\", "/")}/metadata\n`
            : request.nonce,
        );
      const runtime = object.name.startsWith("runtime-");
      entries.push({
        kind: directory
          ? "directory"
          : runtime
            ? entries[6].kind
            : object.name === "owned"
              ? "mutable"
              : "data",
        path: object.path,
        sha256: directory ? null : runtime ? object.sha256 : digest(bytes),
        signatureSha256: runtime
          ? inspectWindowsPe(f.signed).signatureSha256
          : null,
      });
    }
  for (const name of ["policy-helper", "observer-helper"])
    entries.push({
      kind: "helper",
      path: path.join(sourceDirectory, name + ".exe"),
      sha256: digest(f.signed),
      signatureSha256: inspectWindowsPe(f.signed).signatureSha256,
    });
  const sealed = encodeWindowsCustodyPlan({
    candidateSha,
    nonce: request.nonce,
    entries,
  });
  declaration.custody.plan.sha256 = digest(sealed);
  f.files.set(declaration.custody.plan.path, sealed);
  declaration.bindings.input = input;
  declaration.bindings.endpoints = input.endpoints.flatMap(
    ({ family, protocol, clientPort, serverPort }) =>
      [clientPort, serverPort].map((port) => ({ family, protocol, port })),
  );
  declaration.bindings.access = {
    approval: { path: approvalPath, sha256: input.reviewSha256 },
    runtimeAssets: input.runtime
      .filter(({ path: file }) => file !== request.executable.path)
      .map(({ path: file }) => ({
        target: entries.findIndex((entry) => entry.path === file),
        source: 8,
      })),
  };
  if (runtimeCount >= 3)
    declaration.bindings.access.runtimeAssets[2].source = entries.findIndex(
      ({ path: file }) =>
        file === path.join(sourceDirectory, "policy-helper.exe"),
    );
  const { request: _request, ...parameters } = input;
  binding.template.policy = {
    launch: nativePolicyLaunchData(request, windowsAccessArguments(request)),
    policy: { ...parameters, accountSid: { binding: "account" } },
  };
  binding.template.policy.launch.request.restrictingSid = {
    binding: "restricting",
  };
  binding.template.bindings = [
    binding.template.bindings[0],
    {
      ...binding.template.bindings[1],
      paths: [["launch", "request", "restrictingSid"]],
    },
  ];
  binding.approval.manifestSha256 = nativePolicyTemplateDigest(
    binding.template,
  );
  return { ...result, input, model: installAccessNativeFixture(f, input) };
}

test("Windows fixed access entry owns all profiles and faults through raw filesystem/process/IPC reads", async () => {
  for (const profile of ["read-only", "workspace-write", "trusted-command"])
    for (const fault of ["none", "owner-loss", "helper-loss"]) {
      const f = rawPreparation(),
        { recipe, binding, model } = provisionAccessCase(
          f,
          profile,
          fault,
          profile === "workspace-write" && fault === "none" ? 3 : 0,
        );
      const build = await buildRawPreparation(f);
      const system = await createSystemEffects(f, f.options),
        records = [],
        prepared = await system.prepare(recipe, {
          policyBinding: binding,
          recordPolicy: (record) => records.push(record),
        });
      const record = await runWindowsAccessCase(
        prepared.input,
        prepared.effects,
        { fault },
      );
      if (record.status === "FAILED" && prepared.effects.cause)
        throw prepared.effects.cause;
      assert.equal(record.status, "OBSERVED", recipe.id + ": " + record.phase);
      assert.equal(record.observation.denials.length, 38);
      assert.equal(record.observation.loopback.length, 4);
      const settled = await system.settle(recipe, prepared, {
        signal: new AbortController().signal,
        execution: {
          id: recipe.id,
          effects: Object.fromEntries(
            NATIVE_EFFECT_CLASSES.map((key) => [
              key,
              { admission: "possible" },
            ]),
          ),
        },
      });
      if (prepared.effects.cause) throw prepared.effects.cause;
      assert.ok(
        Object.values(settled).every(
          ({ settlement }) => settlement.status === "RETIRED",
        ),
        recipe.id,
      );
      assert.ok(
        records.length > 0 &&
          model.retired &&
          !model.audit &&
          !model.policy &&
          f.accounts.get(prepared.input.request.custody).retired,
      );
      const operations = f.rawEvents.map((frame) => frame.split(" ")[0]);
      assert.ok(
        operations.indexOf("access-controls-drain") <
          operations.indexOf("audit-restore"),
      );
      assert.ok(
        operations.indexOf("audit-restore") <
          operations.indexOf("access-policy-restore"),
      );
      // End original preparation custody before reconstructing cold recovery;
      // the public factory otherwise reuses that live observer's command budget.
      const custody = await build.settle();
      assert.equal(custody.status, "RETIRED");
      assert.equal(custody.independent, true);
      assert.equal(custody.emergencyCleanup, false);
      assert.equal(custody.taskRemoved, true);
      assert.equal(f.rawTasks.size, 0);
      assert.ok([...f.actors.values()].every((actor) => actor.retired));
      await recoverRecordedCase(f);
    }
});
test("Windows fixed access entry rejects invalid file/runtime bindings before private case writes", async () => {
  for (const damage of [
    "duplicate-target",
    "missing-target",
    "noninteger-source",
    "immutable-owned",
  ]) {
    const f = rawPreparation(),
      { recipe, binding, declaration } = provisionAccessCase(
        f,
        "workspace-write",
        "none",
        2,
      ),
      assets = declaration.bindings.access.runtimeAssets;
    if (damage === "duplicate-target") assets[1].target = assets[0].target;
    if (damage === "missing-target") assets.pop();
    if (damage === "noninteger-source")
      assets[0].source = String(assets[0].source);
    if (damage === "immutable-owned") {
      const entries = decodeWindowsPlan(
        f.files.get(declaration.custody.plan.path),
        declaration.custody,
      );
      entries.find(
        ({ path: file }) =>
          file === declaration.bindings.input.request.workspace + "\\owned.txt",
      ).kind = "data";
      const bytes = encodeWindowsCustodyPlan({
        candidateSha,
        nonce: declaration.custody.nonce,
        entries,
      });
      declaration.custody.plan.sha256 = digest(bytes);
      f.files.set(declaration.custody.plan.path, bytes);
    }
    await buildRawPreparation(f);
    const system = await createSystemEffects(f, f.options);
    await assert.rejects(
      system.prepare(recipe, {
        policyBinding: binding,
        recordPolicy: async () => {},
      }),
    );
    assert.ok(
      !f.rawEvents.some((frame) =>
        /^(?:case-directory|case-copy|case-file|case-account) /u.test(frame),
      ),
      damage,
    );
  }
});
test("Windows fixed access entry rejects unrelated file-denial rights and retains independent recovery", async () => {
  const f = rawPreparation(),
    { recipe, binding, model } = provisionAccessCase(
      f,
      "workspace-write",
      "none",
    );
  await buildRawPreparation(f);
  f.accessDamage = "unrelated-file-denial";
  const system = await createSystemEffects(f, f.options),
    prepared = await system.prepare(recipe, {
      policyBinding: binding,
      recordPolicy: async () => {},
    });
  const record = await runWindowsAccessCase(prepared.input, prepared.effects),
    firstCause = prepared.effects.cause;
  assert.equal(record.status, "FAILED");
  assert.equal(record.reservation, "RETAINED");
  assert.ok(firstCause);
  const settled = await system.settle(recipe, prepared, {
    signal: new AbortController().signal,
    execution: {
      id: recipe.id,
      effects: Object.fromEntries(
        NATIVE_EFFECT_CLASSES.map((key) => [key, { admission: "possible" }]),
      ),
    },
  });
  assert.equal(prepared.effects.cause, firstCause);
  assert.ok(
    Object.values(settled).every(
      ({ settlement }) => settlement.status === "RETIRED",
    ),
  );
  assert.ok(model.retired && !model.audit && !model.policy);
});
test("Windows fixed access entry excludes missing proof and independently settles interrupted policy/audit setup", async () => {
  for (const damage of [
    "policy-interruption",
    "audit-interruption",
    "missing-control",
    "unjoined-drop",
    "audit-clear",
    "incomplete-policy",
    "surviving-flow",
    "overpowered-root",
    "substituted-root",
    "root-interruption",
  ]) {
    const f = rawPreparation(),
      { recipe, binding, model } = provisionAccessCase(
        f,
        "workspace-write",
        "none",
      );
    await buildRawPreparation(f);
    f.accessDamage = damage;
    const system = await createSystemEffects(f, f.options),
      prepared = await system.prepare(recipe, {
        policyBinding: binding,
        recordPolicy: async () => {},
      });
    let record;
    try {
      record = await runWindowsAccessCase(prepared.input, prepared.effects);
    } catch (error) {
      assert.equal(error, prepared.effects.cause);
    }
    if (record) {
      assert.equal(record.status, "FAILED", damage);
      assert.equal(record.reservation, "RETAINED");
    }
    const firstCause = prepared.effects.cause;
    assert.ok(firstCause);
    const settled = await system.settle(recipe, prepared, {
      signal: new AbortController().signal,
      execution: {
        id: recipe.id,
        effects: Object.fromEntries(
          NATIVE_EFFECT_CLASSES.map((key) => [key, { admission: "possible" }]),
        ),
      },
    });
    assert.equal(prepared.effects.cause, firstCause);
    if (
      [
        "policy-interruption",
        "audit-interruption",
        "unjoined-drop",
        "overpowered-root",
        "substituted-root",
        "root-interruption",
      ].includes(damage)
    ) {
      assert.ok(
        Object.values(settled).every(
          ({ settlement }) => settlement.status === "RETIRED",
        ),
        damage,
      );
      assert.ok(model.retired && !model.audit && !model.policy);
    } else
      assert.ok(
        Object.values(settled).every(
          ({ settlement }) => settlement.status !== "RETIRED",
        ),
        damage,
      );
    const operations = f.rawEvents.map((frame) => frame.split(" ")[0]);
    if (operations.includes("audit-restore"))
      assert.ok(
        operations.indexOf("access-controls-drain") <
          operations.indexOf("audit-restore"),
      );
  }
});
test("Windows receipt batches drain aggregate deferral before reopening oversized records", async () => {
  for (const oversized of [false, true]) {
    const f = rawPreparation(),
      files = createWindowsPreparationFiles(f, f.options),
      names = Array.from(
        { length: 16 },
        (_, index) => `windows-receipt-${index}.json`,
      ),
      expected = names.map((name, index) => {
        const bytes = Buffer.alloc(
          oversized && index === 0 ? 60001 : 40000,
          index + 1,
        );
        f.files.set(path.join(directory, name), bytes);
        return bytes;
      });
    assert.deepEqual(await files.readReceipts(names), expected);
    assert.equal(
      f.rawEvents.filter((frame) => frame.startsWith("prepare-read ")).length,
      oversized ? 1 : 0,
    );
    assert.equal(
      f.rawEvents.filter((frame) => frame.startsWith("prepare-batch ")).length,
      16,
    );
    assert.equal((await files.settleFiles()).status, "RETIRED");
    assert.equal(f.rawTasks.size, 0);
  }
});

test("Windows preparation preserves its observer through rejected admission and a fresh pre-setup verifier", async () => {
  for (const fault of [null, "unbound", "birth", "exit124"]) {
    const f = rawPreparation(),
      files = createWindowsPreparationFiles(f, f.options),
      records = [],
      reader = createWindowsCustodyReader(
        f.manifest.windowsPreparation.bootstrap,
        {
          ...f.options.readerOptions,
          read: async (file) => f.files.get(file),
          verifyBootstrap: (...args) =>
            files.verify("verifyBootstrap", ...args),
          verifyAdmission: (...args) =>
            files.verify("verifyAdmission", ...args),
          preSetupVerifier: () => files.preSetupVerifier(),
          persist: async (record) => records.push(record),
        },
      );
    f.preSetupRejected = true;
    files.retainReader(reader);
    await assert.rejects(
      reader.start(),
      (error) => error.admission.predicates.unique === false,
    );
    assert.ok(records.some((record) => record.phase === "task-parked"));
    assert.equal((await reader.close()).status, "RETIRED");
    assert.ok(f.rawEvents.indexOf("X") < f.rawEvents.indexOf("D"));
    assert.equal(f.rawEvents.filter((event) => event === "P").length, 1); // Outer observer only.
    assert.ok(records.some((record) => record.phase === "pre-setup-bound"));
    files.releaseReader(reader);
    assert.equal((await files.settleFiles()).status, "RETIRED");
    assert.ok([...f.actors.values()].every((actor) => actor.retired));
    const plan = f.manifest.windowsPreparation;
    f.files.set(
      path.join(directory, "windows-bootstrap-0-intent.json"),
      Buffer.from(
        JSON.stringify({
          candidateSha,
          context: plan.bootstrap.context,
          preparationSha256: observationDigest(plan),
          status: "POSSIBLE",
        }),
      ),
    );
    for (const record of records) {
      if (record.phase === "pre-setup-bound") {
        if (fault === "unbound") record.phase = "uncertain";
        if (fault === "birth") record.helper.creationTime = "99999";
      }
      f.files.set(
        path.join(
          directory,
          `windows-bootstrap-0-custody-${record.sequence}.json`,
        ),
        Buffer.from(JSON.stringify(record)),
      );
    }
    if (fault === "exit124") f.preSetupExitCode = 124;
    const native = windowsPreparationOptions(f, f.options, new Map());
    await native.readdir(directory);
    const retained = [...f.files]
        .filter(([file]) =>
          /^windows-(?:files-|bootstrap-)/u.test(path.basename(file)),
        )
        .map(([file, bytes]) => ({
          name: path.basename(file),
          record: JSON.parse(bytes),
        })),
      recovery = native.recover(
        { request: {}, records: retained, plan },
        { signal: new AbortController().signal },
      );
    if (fault) await assert.rejects(recovery);
    else assert.equal((await recovery).status, "RETIRED");
    assert.equal((await native.settleFiles()).status, "RETIRED");
  }
});

test("Windows fixed entry supplies build/file/verifier defaults through raw IPC and rereads preparation without another compiler", async () => {
  const environment = {
      INCLUDE: "C:\\Fixture\\include;".padEnd(663, "i"),
      LIB: "C:\\Fixture\\lib;".padEnd(376, "l"),
      SystemRoot: "C:\\Windows",
      PATH: 'C:\\Fixture\\λ雪😀\\"quoted";'.padEnd(4515, "p") + "\\",
    },
    f = rawPreparation({ environment }),
    preparationWork = new AbortController(),
    verificationWork = new AbortController();
  f.signal = preparationWork.signal;
  assert.equal(f.rawEvents.length, 0);
  const admissions = [];
  f.beforeRawCommand = (operation) => {
    if (operation !== "helper-send") return;
    for (const [file, bytes] of f.files) {
      if (!/windows-command-.*-[0-9]+\.json$/u.test(path.basename(file)))
        continue;
      const record = JSON.parse(bytes);
      if (
        record.phase !== "worker-admitted" ||
        f.actors.get(record.worker.pid).retired
      )
        continue;
      assert.deepEqual(record.compilerPolicy.outerJob.members, [record.helper]);
      assert.deepEqual(record.compilerPolicy.compilerJob.members, [
        record.worker,
      ]);
      assert.deepEqual(f.rawCompilerJobs.get(record.helper.pid), [
        record.worker,
      ]);
      assert.equal(record.compilerPolicy.outerJob.limitFlags, 0x2808);
      assert.equal(record.compilerPolicy.compilerJob.limitFlags, 0x2008);
      admissions.push(record);
    }
  };
  await buildRawPreparation(f);
  assert.equal(admissions.length, 15);
  for (const record of admissions) {
    const result = JSON.parse(
      f.files.get(
        path.join(
          directory,
          `windows-command-${record.requestSha256}-result.json`,
        ),
      ),
    );
    assert.deepEqual(result.identity, record.worker);
    assert.deepEqual(result.helperIdentity, record.helper);
    assert.deepEqual(result.compilerPolicy, record.compilerPolicy);
    assert.equal(result.settlement.status, "RETIRED");
    assert.equal(result.settlement.independent, true);
  }
  preparationWork.abort();
  const compilerCount = f.rawEvents.filter((event) =>
      event.startsWith("helper-start "),
    ).length,
    actorCount = f.actors.size;
  assert.equal(compilerCount, 15);
  for (const frame of f.rawEvents.filter((event) =>
    event.startsWith("helper-start "),
  )) {
    const args = frame
      .split(" ")
      .slice(15, 19)
      .map((value) => Buffer.from(value, "hex").toString("utf16le"));
    assert.deepEqual(args, Object.values(environment));
    assert.deepEqual(
      args.map((value) => value.length),
      [663, 376, 10, 4516],
    );
  }
  const system = await createSystemEffects(
      { ...f, signal: verificationWork.signal },
      f.options,
    ),
    observed = await system.verifyBuild(f.preparation, {
      signal: verificationWork.signal,
    });
  assert.equal(observed.status, "OBSERVED");
  assert.equal(f.actors.size, actorCount);
  assert.equal(
    f.rawEvents.filter((event) => event.startsWith("helper-start ")).length,
    compilerCount,
  );
  assert.equal(
    [...f.actors.values()].every((actor) => actor.retired),
    true,
  );
  const settlement = await system.settle({ id: "build" }, null, {
    execution: {
      id: "build",
      effects: Object.fromEntries(
        NATIVE_EFFECT_CLASSES.map((effect) => [
          effect,
          { admission: "possible" },
        ]),
      ),
    },
  });
  assert.ok(
    Object.values(settlement).every(
      (effect) =>
        effect.settlement.status === "RETIRED" &&
        effect.settlement.independent === true &&
        effect.settlement.emergencyCleanup === false,
    ),
  );
  assert.equal(
    f.rawEvents.filter((event) => event.startsWith("helper-start ")).length,
    compilerCount,
  );
});

test("Windows prepared defaults reject substituted inputs, missing completion and incomplete observer retirement without recompilation", async () => {
  for (const damage of [
    "source",
    "sdk",
    "output",
    "completion",
    "observer",
    "aborted",
    "deadline",
    "transport",
  ]) {
    const f = rawPreparation(),
      preparationWork = new AbortController(),
      verificationWork = new AbortController();
    let now = 1000;
    f.options.clock = () => now;
    f.signal = preparationWork.signal;
    await buildRawPreparation(f);
    preparationWork.abort();
    if (damage === "source")
      f.files.set(
        path.join(sourceDirectory, "custody.h"),
        Buffer.from("substituted source"),
      );
    if (damage === "sdk")
      f.files.set(f.sdkFile, Buffer.from("substituted SDK input"));
    if (damage === "output")
      f.files.set(path.join(output, "launcher.exe"), f.unsigned);
    if (damage === "completion")
      f.files.delete(
        path.join(
          directory,
          `windows-command-${observationDigest(f.requests[0])}-result.json`,
        ),
      );
    if (damage === "observer") f.survivingObserver = true;
    if (damage === "aborted") verificationWork.abort();
    if (damage === "deadline")
      now += 2 * 30000 + WINDOWS_HELPER_NAMES.length * 60000 + 120000;
    if (damage === "transport") f.damage = "prepare-bytes";
    const before = f.rawEvents.filter((event) =>
        event.startsWith("helper-start "),
      ).length,
      events = f.rawEvents.length,
      system = await createSystemEffects(f, f.options);
    let first;
    await assert.rejects(
      system.verifyBuild(f.preparation, { signal: verificationWork.signal }),
      (error) => {
        first = error;
        return true;
      },
    );
    if (["aborted", "deadline"].includes(damage))
      assert.equal(f.rawEvents.length, events);
    if (damage === "transport") {
      f.damage = null;
      const events = f.rawEvents.length;
      await assert.rejects(
        system.verifyBuild(f.preparation, {
          signal: new AbortController().signal,
        }),
        (error) => error === first,
      );
      assert.equal(f.rawEvents.length, events);
    }
    assert.equal(
      f.rawEvents.filter((event) => event.startsWith("helper-start ")).length,
      before,
    );
  }
});

test("Windows defaults require every unsigned approval, serialize read slots and fence the whole preparation lifetime", async () => {
  const missing = rawPreparation();
  delete missing.manifest.windowsPreparation.command.unsignedHelpers.launcher;
  await assert.rejects(createBuildEffects(missing, missing.options));
  assert.equal(missing.rawEvents.length, 0);
  const f = rawPreparation();
  let now = 1000;
  f.options.clock = () => now;
  const build = await createBuildEffects(f, f.options);
  await build.run(f.requests[2]);
  const file = path.join(output, "launcher.exe"),
    pin = f.manifest.helpers.find(({ name }) => name === "launcher").sha256;
  for (const bytes of await Promise.all([
    build.readPreparedImage(file, pin),
    build.readPreparedImage(file, pin),
  ]))
    assert.deepEqual(bytes, f.signed);
  now += 2 * 30000 + WINDOWS_HELPER_NAMES.length * 60000 + 120000;
  const before = f.rawEvents.length;
  await assert.rejects(
    build.readPreparedImage(
      path.join(output, "launcher.exe"),
      f.manifest.helpers.find(({ name }) => name === "launcher").sha256,
    ),
  );
  assert.equal(f.rawEvents.length, before);
  assert.equal((await build.settle()).status, "RETAINED");
});

test("Windows fixed entry retains first failure for unsigned mismatch, substituted publication and interrupted receipt writer", async () => {
  for (const damage of [
    "unsignedMismatch",
    "publicationMismatch",
    "prepare-chunk",
  ]) {
    const f = rawPreparation(),
      build = await createBuildEffects(f, f.options);
    if (damage === "prepare-chunk") f.damage = damage;
    else f[damage] = true;
    let first;
    await assert.rejects(build.run(f.requests[2]), (error) => {
      first = error;
      return true;
    });
    await assert.rejects(build.run(f.requests[0]), (error) => error === first);
    assert.equal((await build.settle()).status, "RETAINED");
  }
});

test("Windows publication admits only checksum/security-directory and aligned certificate changes", () => {
  const { unsigned, signed } = publicationBytes();
  assert.deepEqual(windowsSignedPublication(unsigned, signed), {
    unsignedSha256: digest(unsigned),
    imageSha256: digest(signed),
  });
  for (const mutate of [
    (bytes) => {
      bytes[400] = 1;
    },
    (bytes) => {
      bytes[527] = 1;
    },
    (bytes) => {
      bytes.writeUInt32LE(520, 232);
    },
    (bytes) => {
      bytes.writeUInt32LE(8, 236);
    },
  ]) {
    const changed = Buffer.from(signed);
    mutate(changed);
    assert.throws(() => windowsSignedPublication(unsigned, changed));
  }
  assert.throws(() =>
    windowsSignedPublication(
      unsigned,
      Buffer.concat([signed, Buffer.alloc(8)]),
    ),
  );
});

async function recoverRecordedCase(f, owner, expected = "RETIRED") {
  const preparation = {
    ...f.preparation,
    status: "FAIL",
    helpers: [],
    versions: [],
    commands: [],
  };
  for (const helper of f.manifest.helpers)
    f.files.delete(path.join(output, helper.name + ".exe"));
  const system =
      owner ?? (await createSystemEffects({ ...f, preparation }, f.options)),
    request = {
      candidateSha,
      platform: "win32",
      jobSha256: observationDigest(f.job),
      preparationSha256: observationDigest(preparation),
    };
  const before = f.rawEvents.length;
  const result = await system.recover({
    request,
    job: f.job,
    preparation,
    signal: new AbortController().signal,
  });
  const sequences = new Map();
  for (const name of f.files.keys()) {
    const match = /windows-files-([a-f0-9]{32})-([0-9]+)\.json$/u.exec(name);
    if (match)
      sequences.set(
        match[1],
        Math.max(Number(match[2]), sequences.get(match[1]) ?? 0),
      );
  }
  assert.equal(
    result.status,
    expected,
    system.cause?.stack +
      "\nObserver command counts: " +
      JSON.stringify([...sequences.values()]),
  );
  const launches = f.rawEvents
    .slice(before)
    .filter((event) => event.startsWith("helper-start "));
  assert.ok(
    launches.every((event) => {
      const values = event.split(" ");
      return (
        ["policy", "git-policy"].includes(values[2]) &&
        values.includes(encode("remove"))
      );
    }),
    "Only the approved unchanged-policy removal helper may launch during recovery",
  );
  await assert.rejects(() => system.prepare(windowsSystemRecipes()[1], {}));
  return { system, request, preparation };
}

test("Windows fixed-entry partial recovery uses protected build records and fresh held retirement without prepared outputs", async () => {
  for (const damage of [
    null,
    "missing-birth",
    "worker-request",
    "observer-intent",
    "observer-birth",
    "journal-gap",
    "bootstrap-birth",
    "bootstrap-journal-gap",
    "bootstrap-intent",
    "surviving-worker",
    "surviving-compiler-job",
  ]) {
    const f = rawPreparation(),
      build = await createBuildEffects(f, f.options);
    await build.run(f.requests[2]);
    if (damage === "surviving-compiler-job") {
      const members = [...f.rawCompilerJobs.values()][0];
      members.push(f.rawActor());
    }
    for (const helper of f.manifest.helpers)
      f.files.delete(path.join(output, helper.name + ".exe"));
    for (const [file, bytes] of f.files)
      if (
        path.basename(file).startsWith("windows-command-") &&
        path.basename(file).endsWith("-result.json")
      )
        f.files.delete(file);
      else if (
        path.basename(file).startsWith("windows-command-") &&
        JSON.parse(bytes).phase === "worker-admitted"
      ) {
        if (damage === "missing-birth") f.files.delete(file);
        if (damage === "worker-request") {
          const record = JSON.parse(bytes);
          record.requestSha256 = "d".repeat(64);
          f.files.set(file, Buffer.from(JSON.stringify(record)));
        }
        if (damage === "surviving-worker")
          f.actors.get(JSON.parse(bytes).worker.pid).retired = false;
      }
    if (["observer-intent", "observer-birth"].includes(damage))
      for (const file of f.files.keys())
        if (
          file.endsWith(
            damage === "observer-intent" ? "-intent.json" : "-birth.json",
          ) &&
          path.basename(file).startsWith("windows-files-")
        )
          f.files.delete(file);
    if (damage === "journal-gap")
      for (const file of f.files.keys())
        if (/windows-files-.*-1\.json$/u.test(file)) f.files.delete(file);
    if (damage?.startsWith("bootstrap-"))
      for (const [file, bytes] of f.files) {
        if (!/^windows-bootstrap-/u.test(path.basename(file))) continue;
        const record = JSON.parse(bytes);
        if (
          (damage === "bootstrap-birth" && record.phase === "admitted") ||
          (damage === "bootstrap-journal-gap" && record.sequence === 0) ||
          (damage === "bootstrap-intent" && file.endsWith("-intent.json"))
        )
          f.files.delete(file);
      }
    const preparation = {
        ...f.preparation,
        status: "FAIL",
        helpers: [],
        versions: [],
        commands: [],
      },
      system = await createSystemEffects({ ...f, preparation }, f.options),
      request = {
        candidateSha,
        platform: "win32",
        jobSha256: observationDigest(f.job),
        preparationSha256: observationDigest(preparation),
      };
    const before = f.rawEvents.filter((event) =>
        event.startsWith("helper-start "),
      ).length,
      result = await system.recover({
        request,
        job: f.job,
        preparation,
        signal: new AbortController().signal,
      });
    assert.equal(
      result.status,
      damage ? "RETAINED" : "RETIRED",
      String(damage),
    );
    assert.equal(
      f.rawEvents.filter((event) => event.startsWith("helper-start ")).length,
      before,
    );
  }
});

test("Windows fixed-entry recovery retains partial bootstrap without admitting another compiler", async () => {
  const f = rawPreparation(),
    build = await createBuildEffects(f, f.options);
  f.damage = "helper-start";
  await assert.rejects(() => build.run(f.requests[2]));
  f.damage = null;
  const { system, request, preparation } = await recoverRecordedCase(
    f,
    undefined,
    "RETAINED",
  );
  const firstCause = system.cause;
  assert.ok(firstCause);
  assert.ok(
    [...f.files.values()].some((bytes) => {
      try {
        return JSON.parse(bytes).status === "RETAINED";
      } catch {
        return false;
      }
    }),
  );
  await system.recover({
    request,
    job: f.job,
    preparation,
    signal: new AbortController().signal,
  });
  assert.equal(system.cause, firstCause);
});

test("Windows cold recovery requires the complete native Job inventory when transfer slots are unbound", async () => {
  for (const damage of [
    null,
    "surviving-helper-job",
    "surviving-compiler-job",
    "incomplete-job-inventory",
    "substituted-job-creator",
  ]) {
    const f = rawPreparation(),
      build = await createBuildEffects(f, f.options);
    await build.run(f.requests[2]);
    f.coldDamage = damage;
    await recoverRecordedCase(f, undefined, damage ? "RETAINED" : "RETIRED");
    assert.ok(
      f.rawEvents.some((frame) => frame.startsWith("verify-recovery-jobs ")),
    );
  }
});

test("Windows fixed-entry recovery fences retained case APIs before its first cleanup read", async () => {
  const f = rawPreparation(),
    { recipe, binding } = operationCase(f, "files.private");
  await buildRawPreparation(f);
  const system = await createSystemEffects(f, f.options),
    prepared = await system.prepare(recipe, {
      policyBinding: binding,
      recordPolicy() {},
    });
  let enter, release;
  const entered = new Promise((resolve) => {
      enter = resolve;
    }),
    paused = new Promise((resolve) => {
      release = resolve;
    });
  f.beforeRawCommand = async (name) => {
    if (name === "prepare-list") {
      f.beforeRawCommand = null;
      enter();
      await paused;
    }
  };
  const request = {
      candidateSha,
      platform: "win32",
      jobSha256: observationDigest(f.job),
      preparationSha256: observationDigest(f.preparation),
    },
    pending = system.recover({
      request,
      job: f.job,
      preparation: f.preparation,
      signal: new AbortController().signal,
    });
  await entered;
  try {
    await assert.rejects(() =>
      system.prepare(recipe, { policyBinding: binding, recordPolicy() {} }),
    );
    await assert.rejects(() => prepared.effects.fileEffects());
  } finally {
    release();
  }
  assert.equal((await pending).status, "RETIRED", system.cause?.stack);
});

test("Windows recovery fences preparation already waiting on its first protected read", async () => {
  const f = rawPreparation(),
    { recipe, binding } = operationCase(f, "files.private");
  await buildRawPreparation(f);
  const system = await createSystemEffects(f, f.options);
  let enter, release;
  const entered = new Promise((resolve) => {
      enter = resolve;
    }),
    paused = new Promise((resolve) => {
      release = resolve;
    });
  f.beforeRawCommand = async (name) => {
    if (name === "prepare-release") {
      f.beforeRawCommand = null;
      enter();
      await paused;
    }
  };
  const preparation = assert.rejects(() =>
    system.prepare(recipe, {
      policyBinding: binding,
      recordPolicy() {},
    }),
  );
  await entered;
  const request = {
      candidateSha,
      platform: "win32",
      jobSha256: observationDigest(f.job),
      preparationSha256: observationDigest(f.preparation),
    },
    recovery = system.recover({
      request,
      job: f.job,
      preparation: f.preparation,
      signal: new AbortController().signal,
    });
  release();
  await preparation;
  assert.equal((await recovery).status, "RETIRED", system.cause?.stack);
  assert.equal(f.accounts.size, 0);
  assert.ok(
    ![...f.files.keys()].some((file) =>
      path.basename(file).startsWith("windows-case-"),
    ),
  );
});

test("Windows fixed-entry recovery rejoins setup before prepare returns and fences fresh factories", async () => {
  const f = rawPreparation(),
    { recipe, binding } = operationCase(f, "files.private");
  await buildRawPreparation(f);
  const system = await createSystemEffects(f, f.options);
  const interrupted = new Error("Interrupted policy receipt barrier");
  await assert.rejects(
    () =>
      system.prepare(recipe, {
        policyBinding: binding,
        recordPolicy() {
          throw interrupted;
        },
      }),
    (cause) => cause === interrupted,
  );
  await recoverRecordedCase(f, system);
  assert.ok([...f.accounts.values()].every((account) => account.retired));
  const fresh = await createSystemEffects(f, f.options);
  const before = f.rawEvents.filter((frame) =>
    frame.startsWith("case-account "),
  ).length;
  await assert.rejects(() =>
    fresh.prepare(recipe, { policyBinding: binding, recordPolicy() {} }),
  );
  assert.equal(
    f.rawEvents.filter((frame) => frame.startsWith("case-account ")).length,
    before,
  );
});

test("Windows fixed-entry recovery retires interrupted policy and audit barriers before closing custody", async () => {
  for (const damage of ["policy-interruption", "audit-interruption"]) {
    const f = rawPreparation(),
      { recipe, binding, model } = provisionAccessCase(
        f,
        "workspace-write",
        "none",
      );
    await buildRawPreparation(f);
    const system = await createSystemEffects(f, f.options),
      prepared = await system.prepare(recipe, {
        policyBinding: binding,
        recordPolicy() {},
      });
    f.accessDamage = damage;
    try {
      await runWindowsAccessCase(prepared.input, prepared.effects);
    } catch {}
    const cause = prepared.effects.cause;
    assert.ok(cause);
    await recoverRecordedCase(f, system);
    assert.equal(prepared.effects.cause, cause);
    assert.ok(model.retired && !model.policy && !model.audit);
  }
});

test("Windows fixed-entry recovery rejects task substitution and missing records while retiring known owners", async () => {
  for (const damage of [
    "task",
    "policy",
    "audit",
    "reader",
    "case-record",
    "receipt",
    "partial-restoration",
    "policy-substitution",
  ]) {
    const f = rawPreparation(),
      { recipe, binding } = provisionCase(f, "ownership.detached", true);
    await buildRawPreparation(f);
    const system = await createSystemEffects(f, f.options),
      prepared = await system.prepare(recipe, {
        policyBinding: binding,
        recordPolicy() {},
      });
    await runWindowsOwnershipCase("detached", prepared.input, prepared.effects);
    if (damage === "case-record") {
      const file = [...f.files.keys()].find((file) =>
        file.endsWith("windows-case-ownership.detached-0.json"),
      );
      f.files.delete(file);
    } else if (damage === "receipt") {
      const file = [...f.files.keys()].find((file) =>
        file.endsWith("ownership-0.json"),
      );
      f.files.set(file, Buffer.from("changed"));
    } else f.coldDamage = damage;
    await recoverRecordedCase(f, system, "RETAINED");
    assert.ok([...f.accounts.values()].every((account) => account.retired));
    assert.ok(f.rawEvents.some((frame) => frame.startsWith("finish ")));
  }
});

test("Windows fixed-entry cold recovery removes only the independently verified retired task after lost task acknowledgement", async () => {
  for (const role of ["case", "bootstrap", "observer"]) {
    const f = rawPreparation(),
      { recipe, binding, declaration } = provisionCase(
        f,
        "ownership.detached",
        true,
      );
    await buildRawPreparation(f);
    const system = await createSystemEffects(f, f.options),
      prepared = await system.prepare(recipe, {
        policyBinding: binding,
        recordPolicy() {},
      });
    await runWindowsOwnershipCase("detached", prepared.input, prepared.effects);
    await system.settle(recipe, prepared, {
      signal: new AbortController().signal,
      execution: {
        id: recipe.id,
        effects: Object.fromEntries(
          NATIVE_EFFECT_CLASSES.map((key) => [key, { admission: "possible" }]),
        ),
      },
    });
    const values = [...f.files.values()].flatMap((bytes) => {
      try {
        return [JSON.parse(bytes)];
      } catch {
        return [];
      }
    });
    const birth = values.find(
      (record) =>
        record?.context?.executionId ===
          (role === "bootstrap" ? "build" : recipe.id) &&
        (role === "bootstrap"
          ? record.phase === "admitted"
          : record.phase === "custody" && record.record.phase === "admitted"),
    );
    const observer = [...f.files.entries()].find(
      ([file]) =>
        /windows-files-[a-f0-9]{32}-birth\.json$/u.test(path.basename(file)) &&
        JSON.parse(f.files.get(file.replace(/birth\.json$/u, "intent.json")))
          .argumentsHex[4] === encode(declaration.custody.plan.path),
    );
    const owner =
      role === "observer"
        ? JSON.parse(observer[1])
        : {
            nonce:
              role === "bootstrap"
                ? f.manifest.windowsPreparation.bootstrap.nonce
                : declaration.custody.nonce,
            helper: role === "bootstrap" ? birth.helper : birth.record.helper,
          };
    f.rawTasks.set(owner.nonce, owner.helper);
    await recoverRecordedCase(f);
    assert.ok(!f.rawTasks.has(owner.nonce), role);
    assert.ok(
      f.rawEvents.some((frame) => frame.startsWith("verify-task-remove")),
      role,
    );
    if (role === "bootstrap") await recoverRecordedCase(f);
  }
});

function buildPolicy(f) {
  const compiler = {
    userSid: "S-1-5-18",
    sessionId: 0,
    integritySid: "S-1-16-16384",
    groups: [],
    restricting: [],
    privileges: [],
    defaultDacl: [{ type: 0, flags: 0, mask: 0x10000000, sid: "S-1-5-18" }],
    inheritedHandles: ["pipe", "pipe", "pipe"],
    outerJob: { limitFlags: 0x2808, processLimit: 32, uiRestrictions: 255 },
    compilerJob: { limitFlags: 0x2008, processLimit: 31, uiRestrictions: 255 },
  };
  const template = {
    schemaVersion: 1,
    candidateSha,
    platform: "win32",
    sourceReviewSha256: hash,
    provisioningReviewSha256: hash,
    policy: {
      launch: {
        commands: f.requests.map((request) => ({
          requestSha256: observationDigest(request),
          toolSha256: request.toolSha256,
        })),
      },
      policy: {
        compiler,
        output: {
          path: output,
          identitySha256: { binding: "output" },
          daclSha256: hash,
        },
      },
    },
    bindings: [
      {
        id: "output",
        kind: "custody",
        minimum: null,
        maximum: null,
        paths: [["policy", "output", "identitySha256"]],
      },
    ],
  };
  return {
    template,
    approval: {
      candidateSha,
      platform: "win32",
      manifestSha256: nativePolicyTemplateDigest(template),
      authority: "operator-protected",
    },
    context: structuredClone(f.manifest.windowsPreparation.bootstrap.context),
  };
}

test("Windows fixed build entry requires independent compiler policy joined to pre-release custody and approved output", async () => {
  for (const damage of [
    null,
    "missing-policy",
    "extra-authority",
    "wrong-attempt",
    "stale-template",
    "stale-nested",
    "compiler-breakaway",
    "controller-member",
    "result-helper",
    "record-helper",
    "extra-policy",
  ]) {
    const f = rawPreparation();
    await buildRawPreparation(f);
    const binding = buildPolicy(f);
    if (damage === "extra-authority")
      binding.template.policy.policy.compiler.groups = [
        { sid: "S-1-5-32-544", attributes: 4 },
      ];
    if (damage === "wrong-attempt") binding.context.runAttempt++;
    if (damage === "stale-template")
      binding.template.policy.policy.compiler.outerJob.limitFlags = 0x2008;
    // Reapprove only a deliberately different expected policy, never an observed pin.
    binding.approval.manifestSha256 = nativePolicyTemplateDigest(
      binding.template,
    );
    if (
      [
        "missing-policy",
        "stale-nested",
        "compiler-breakaway",
        "controller-member",
        "result-helper",
        "record-helper",
        "extra-policy",
      ].includes(damage)
    ) {
      const command = f.preparation.commands[0],
        file = path.join(
          directory,
          `windows-command-${command.requestSha256}-result.json`,
        ),
        record = JSON.parse(f.files.get(file));
      if (damage === "missing-policy") delete record.compilerPolicy;
      if (damage === "stale-nested") {
        record.compilerPolicy.outerJob.limitFlags = 0x2008;
        record.compilerPolicy.outerJob.members.push(record.identity);
      }
      if (damage === "compiler-breakaway")
        record.compilerPolicy.compilerJob.limitFlags |= 0x800;
      if (damage === "controller-member")
        record.compilerPolicy.outerJob.members.push(record.identity);
      if (damage === "result-helper")
        record.helperIdentity.creationTime = "999";
      if (damage === "extra-policy") record.compilerPolicy.extra = true;
      if (damage === "record-helper")
        for (const [name, bytes] of f.files) {
          if (!name.includes(`windows-command-${command.requestSha256}-`))
            continue;
          const worker = JSON.parse(bytes);
          if (worker.phase !== "worker-admitted") continue;
          worker.helper.creationTime = "999";
          f.files.set(name, Buffer.from(JSON.stringify(worker)));
        }
      f.files.set(file, Buffer.from(JSON.stringify(record)));
      command.receiptSha256 = observationDigest(record);
    }
    const system = await createSystemEffects(f, f.options),
      proofs = [];
    await assert.rejects(() =>
      system.build({ candidateSha, reviewSha256: hash }),
    );
    const run = () =>
      system.build({
        candidateSha,
        reviewSha256: hash,
        policyBinding: binding,
        recordPolicy: (proof) => proofs.push(proof),
      });
    if (damage) {
      await assert.rejects(run);
      assert.equal(proofs.length, 0);
    } else {
      assert.equal((await run()).status, "OBSERVED");
      assert.equal(proofs.length, 1);
      assert.equal(
        proofs[0].observed.policy.policy.compiler.userSid,
        "S-1-5-18",
      );
    }
    assert.equal(
      f.rawEvents.filter((event) => event.startsWith("helper-start ")).length,
      15,
    );
  }
});

function provisionCase(f, id = "ownership.literal", ownership = false) {
  const recipe = windowsSystemRecipes().find((entry) => entry.id === id),
    declaration = f.manifest.windowsPreparation.cases.find(
      (entry) => entry.id === recipe.id,
    ),
    context = declaration.custody.context,
    nonce = observationDigest(context).slice(0, 32),
    root = path.join(directory, "case-" + observationDigest(context));
  declaration.custody.reader = structuredClone(
    f.manifest.windowsPreparation.bootstrap.reader,
  );
  declaration.custody.bridge = structuredClone(
    f.manifest.windowsPreparation.bootstrap.bridge,
  );
  const request = {
    schemaVersion: 3,
    candidateSha,
    nonce,
    restrictingSid: "S-1-5-21-1-2-3-1002",
    custody: root + "\\custody",
    storage: root + "\\storage",
    workspace: root + "\\storage\\work",
    launcher: {
      path: root + "\\custody\\launcher.exe",
      sha256: digest(f.signed),
      signatureSha256: inspectWindowsPe(f.signed).signatureSha256,
    },
    executable: {
      path:
        root +
        "\\storage\\" +
        (id.startsWith("files.")
          ? "file-helper.exe"
          : id.startsWith("git.")
            ? "git-fixture.exe"
            : "payload.exe"),
      sha256: digest(f.signed),
      signatureSha256: inspectWindowsPe(f.signed).signatureSha256,
      parser: "msvc-ucrt-wmain-v1",
    },
    policy: { path: root + "\\custody\\policy", sha256: null },
    bindings: {
      system: hash,
      source: hash,
      closure: context.closureSha256,
      policy: null,
    },
  };
  const assets = [
    "launcher",
    ["ownership.literal", "ownership.storage"].includes(id)
      ? "argv-fixture"
      : id.startsWith("files.")
        ? "file-helper"
        : id.startsWith("git.")
          ? "git-fixture"
          : "ownership-fixture",
  ].map((name) => ({
    path: path.join(sourceDirectory, name + ".exe"),
    sha256: digest(f.signed),
    signatureSha256: inspectWindowsPe(f.signed).signatureSha256,
  }));
  const entries = [
    directory,
    root,
    request.custody,
    request.storage,
    request.workspace,
  ].map((path) => ({
    kind: "directory",
    path,
    sha256: null,
    signatureSha256: null,
  }));
  entries.push(
    ...[request.launcher, request.executable].map((target, i) => ({
      kind: "helper",
      path: target.path,
      sha256: target.sha256,
      signatureSha256: assets[i].signatureSha256,
    })),
    ...assets.map((asset) => ({ kind: "helper", ...asset })),
    ...[declaration.custody.reader, declaration.custody.bridge].map(
      (image) => ({ kind: "helper", ...image }),
    ),
    ...declaration.custody.sources.map((source) => ({
      kind: "data",
      ...source,
      signatureSha256: null,
    })),
    { kind: "sdk", path: f.sdkFile, sha256: hash, signatureSha256: null },
    { kind: "directory", path: output, sha256: null, signatureSha256: null },
  );
  declaration.custody.nonce = nonce;
  const bytes = encodeWindowsCustodyPlan({ candidateSha, nonce, entries });
  declaration.custody.plan.sha256 = digest(bytes);
  f.files.set(declaration.custody.plan.path, bytes);
  declaration.bindings = {
    schemaVersion: 1,
    authoritySha256: hash,
    input: request,
    assets,
    endpoints: [],
  };
  const template = {
    schemaVersion: 1,
    candidateSha,
    platform: "win32",
    sourceReviewSha256: hash,
    provisioningReviewSha256: hash,
    policy: {
      launch: nativePolicyLaunchData(
        request,
        id.startsWith("access.")
          ? windowsAccessArguments(request)
          : id.startsWith("ownership.")
            ? windowsOwnershipArguments(id, request)
            : WINDOWS_LITERAL_ARGUMENTS,
      ),
      policy: {
        ...(ownership
          ? { kind: "windows-ownership", processLimit: 32, network: "deny-all" }
          : {}),
        accountSid: { binding: "account" },
        restrictingSid: { binding: "restricting" },
        objects: Array.from({ length: 6 }, (_, i) => ({
          identitySha256: { binding: "object." + i },
          ...(ownership
            ? { mask: [0, 0, 0x120020, 0x12019f, 0, 0x1200a9][i] }
            : {}),
        })),
      },
    },
    bindings: [
      {
        id: "account",
        kind: "sid",
        minimum: null,
        maximum: null,
        paths: [["policy", "accountSid"]],
      },
      {
        id: "restricting",
        kind: "sid",
        minimum: null,
        maximum: null,
        paths: [
          ["launch", "request", "restrictingSid"],
          ["policy", "restrictingSid"],
        ],
      },
      ...Array.from({ length: 6 }, (_, i) => ({
        id: "object." + i,
        kind: "custody",
        minimum: null,
        maximum: null,
        paths: [["policy", "objects", i, "identitySha256"]],
      })),
    ],
  };
  template.policy.launch.request.restrictingSid = { binding: "restricting" };
  return {
    recipe,
    declaration,
    binding: {
      template,
      approval: {
        candidateSha,
        platform: "win32",
        manifestSha256: nativePolicyTemplateDigest(template),
        authority: "operator-protected",
      },
      context: structuredClone(context),
    },
  };
}

test("Windows fixed entry provisions acknowledged fresh identities and held resources with no owner callback, retaining unfinished execution", async () => {
  const f = rawPreparation(),
    { recipe, binding } = provisionCase(f);
  await buildRawPreparation(f);
  const system = await createSystemEffects(f, f.options);
  await assert.rejects(
    () =>
      system.prepare(recipe, {
        policyBinding: binding,
        recordPolicy: () => assert.fail("No execution owner is implemented"),
      }),
    (error) => {
      assert.match(
        error.stack,
        /ownerEffects|requireWindowsFunctions|assertNativePolicyParameters/u,
      );
      return true;
    },
  );
  const records = [...f.files]
    .filter(([file]) =>
      path.basename(file).startsWith("windows-case-ownership.literal-"),
    )
    .map(([, bytes]) => JSON.parse(bytes));
  const observed = records.find(
    (record) => record.phase === "provisioning-observed",
  );
  assert.ok(
    observed,
    "normal provisioning must reach independent admission before the unfinished owner gate",
  );
  assert.equal(observed.actual.accountSid, "S-1-5-21-4-5-6-1009");
  assert.equal(
    observed.provisioning.bindings.find((rule) => rule.id === "restricting")
      .value,
    "S-1-5-21-7-8-9-1011",
  );
  assert.equal(records[0].phase, "provisioning-possible");
  assert.ok(f.rawEvents.some((event) => event.startsWith("verify-case ")));
  const settlements = await system.settle(recipe, null, {
    signal: new AbortController().signal,
    execution: {
      id: recipe.id,
      effects: Object.fromEntries(
        NATIVE_EFFECT_CLASSES.map((name) => [name, { admission: "possible" }]),
      ),
    },
  });
  assert.ok(
    Object.values(settlements).every(
      (receipt) => receipt.settlement.status === "RETIRED",
    ),
  );
});

test("Windows fixed provisioning rejects undeclared identities, extra principals, substituted objects and context before admission", async () => {
  for (const damage of [
    "undeclared-account",
    "undeclared-object",
    "extra-principal",
    "substituted-object",
    "wrong-context",
    "wrong-attempt",
    "wrong-job",
    "extra-endpoint",
    "extra-token-grant",
    "malformed-token-type",
  ]) {
    const f = rawPreparation(),
      { recipe, binding } = provisionCase(f);
    if (damage === "undeclared-account") {
      binding.template.bindings = binding.template.bindings.filter(
        (rule) => rule.id !== "account",
      );
      binding.template.policy.policy.accountSid = "S-1-5-21-1-2-3-1003";
    }
    if (damage === "undeclared-object") {
      binding.template.bindings = binding.template.bindings.filter(
        (rule) => rule.id !== "object.0",
      );
      binding.template.policy.policy.objects[0].identitySha256 = hash;
    }
    if (damage === "wrong-attempt") binding.context.runAttempt++;
    binding.approval.manifestSha256 = nativePolicyTemplateDigest(
      binding.template,
    );
    if (damage === "wrong-job") f.job.provenance.jobId = "2";
    if (damage === "extra-endpoint")
      f.manifest.windowsPreparation.cases
        .find((entry) => entry.id === recipe.id)
        .bindings.endpoints.push({
          family: "v4",
          protocol: "tcp",
          port: 41000,
        });
    f.caseDamage = damage;
    await buildRawPreparation(f);
    const system = await createSystemEffects(f, f.options);
    await assert.rejects(() =>
      system.prepare(recipe, {
        policyBinding: binding,
        recordPolicy: () =>
          assert.fail("Invalid provisioning cannot record policy"),
      }),
    );
    assert.ok(
      ![...f.files.values()].some((bytes) => {
        try {
          return JSON.parse(bytes).phase === "provisioning-observed";
        } catch {
          return false;
        }
      }),
      damage,
    );
    if (
      [
        "extra-principal",
        "substituted-object",
        "wrong-context",
        "extra-token-grant",
        "malformed-token-type",
      ].includes(damage)
    )
      assert.ok(
        f.rawEvents.some((event) => event.startsWith("verify-case ")),
        damage,
      );
  }
});

test("Windows interrupted provisioning retains unacknowledged account intent and requires independent cleanup completion", async () => {
  for (const damage of [
    "case-account",
    "verify-case",
    "retirement-loss",
    "surviving-rights",
    "cleanup-cancelled",
  ]) {
    const f = rawPreparation(),
      { recipe, binding } = provisionCase(f);
    await buildRawPreparation(f);
    if (["case-account", "verify-case"].includes(damage)) f.damage = damage;
    else f.caseDamage = damage;
    const system = await createSystemEffects(f, f.options);
    await assert.rejects(() =>
      system.prepare(recipe, {
        policyBinding: binding,
        recordPolicy: () =>
          assert.fail("Interrupted setup cannot admit policy"),
      }),
    );
    const cleanup = new AbortController();
    if (damage === "cleanup-cancelled") cleanup.abort();
    const result = await system.settle(recipe, null, {
      signal: cleanup.signal,
      execution: {
        id: recipe.id,
        effects: Object.fromEntries(
          NATIVE_EFFECT_CLASSES.map((name) => [
            name,
            { admission: "possible" },
          ]),
        ),
      },
    });
    assert.ok(
      Object.values(result).every(
        (receipt) => receipt.settlement.status === "RETAINED",
      ),
      damage,
    );
    assert.ok(
      [...f.files.keys()].some(
        (file) =>
          path.basename(file) === "windows-case-ownership.literal-0.json",
      ),
    );
  }
});

test("Windows resource binding independently rereads provisioned identities and withholds substituted custody", async () => {
  const f = rawPreparation(),
    { recipe, binding } = provisionCase(f);
  f.caseDamage = "resource-substitution";
  await buildRawPreparation(f);
  const system = await createSystemEffects(f, f.options);
  await assert.rejects(
    () =>
      system.prepare(recipe, {
        policyBinding: binding,
        recordPolicy: () =>
          assert.fail("Substituted resources cannot admit policy"),
      }),
    (error) => {
      assert.match(error.stack, /bindResources/u);
      return true;
    },
  );
  assert.equal(f.caseReads, 2);
  assert.ok(
    [...f.files.values()].some((bytes) => {
      try {
        return JSON.parse(bytes).phase === "provisioning-observed";
      } catch {
        return false;
      }
    }),
  );
});

test("Windows fixed provisioning reserves only template-approved TCP/UDP loopback endpoints and rereads their native ports", async () => {
  for (const damage of [null, "unapproved-endpoints", "substituted-endpoint"]) {
    const f = rawPreparation(),
      { recipe, binding, declaration } = provisionCase(f),
      { input } = windowsPolicyFixture(
        declaration.bindings.input,
        "S-1-5-21-1-2-3-1003",
      );
    // Policy installation remains behind the parked payload's separate barriers.
    input.request.policy.sha256 = input.request.bindings.policy = null;
    input.endpoints = input.endpoints.map((endpoint) => ({
      ...endpoint,
      address: endpoint.family === "v4" ? "127.0.0.1" : "::1",
      owned: true,
    }));
    declaration.bindings.input = input;
    declaration.bindings.endpoints = input.endpoints.flatMap(
      ({ family, protocol, clientPort, serverPort }) =>
        [clientPort, serverPort].map((port) => ({ family, protocol, port })),
    );
    binding.template.policy.launch = nativePolicyLaunchData(
      input.request,
      WINDOWS_LITERAL_ARGUMENTS,
    );
    binding.template.policy.launch.request.restrictingSid = {
      binding: "restricting",
    };
    if (damage !== "unapproved-endpoints")
      binding.template.policy.policy.endpoints = structuredClone(
        input.endpoints,
      );
    if (!damage) {
      binding.template.policy.policy.endpoints[0].clientPort = {
        binding: "client-port",
      };
      binding.template.bindings.push({
        id: "client-port",
        kind: "loopback-port",
        minimum: 41000,
        maximum: 42000,
        paths: [["policy", "endpoints", 0, "clientPort"]],
      });
    }
    binding.approval.manifestSha256 = nativePolicyTemplateDigest(
      binding.template,
    );
    f.caseDamage = damage;
    await buildRawPreparation(f);
    const system = await createSystemEffects(f, f.options);
    await assert.rejects(
      () =>
        system.prepare(recipe, {
          policyBinding: binding,
          recordPolicy: () => assert.fail("Execution owners remain unfinished"),
        }),
      (error) => {
        assert.match(
          error.stack,
          damage
            ? /provision/u
            : /ownerEffects|requireWindowsFunctions|assertNativePolicyParameters/u,
        );
        return true;
      },
    );
    assert.equal(
      f.rawEvents.filter((event) => event.startsWith("case-endpoint ")).length,
      damage === "unapproved-endpoints" ? 0 : 8,
    );
    const observed = [...f.files.values()].some((bytes) => {
      try {
        return JSON.parse(bytes).phase === "provisioning-observed";
      } catch {
        return false;
      }
    });
    assert.equal(observed, !damage);
  }
});

async function caseReaderObservationFixture() {
  const f = rawPreparation(),
    { recipe, binding } = provisionCase(f),
    observed = { independent: true, nativeEventSha256: hash };
  f.options.ownerEffects = async (current) => {
    f.current = current;
    // Only the unrelated launch result is injected; its consuming custody and
    // admission-verifier guards run through the real owners and raw IPC below.
    return {
      ...Object.fromEntries(
        [
          "verifyInputs",
          "verifySetup",
          "installPolicy",
          "verifyAuthority",
          "verifyReceipt",
          "retire",
          "readProvisioning",
          "readPolicy",
          "persist",
        ].map((name) => [name, async () => {}]),
      ),
      inspect: async () => observed,
    };
  };
  await buildRawPreparation(f);
  const system = await createSystemEffects(f, f.options),
    prepared = await system.prepare(recipe, {
      policyBinding: binding,
      recordPolicy: () => {},
    });
  return { f, prepared, observed };
}

test("Windows launch observation reads its admitted primary through the bound independent owner", async () => {
  const { f, prepared, observed } = await caseReaderObservationFixture(),
    { helper, verifier } = f.current.admission,
    payload = f.rawActor(false),
    other = f.rawActor(),
    subjects = {
      helper,
      payload,
      helpers: [
        { identity: { ...helper } },
        { identity: other },
        { identity: Object.fromEntries(Object.entries(other).reverse()) },
      ],
    },
    observations = [],
    observeHelper = f.current.reader.observeHelper.bind(f.current.reader);
  f.current.reader.observeHelper = async (...args) => {
    const actual = await observeHelper(...args);
    observations.push(actual);
    return actual;
  };
  for (let i = 0; i < 2; i++) {
    f.actors.get(helper.pid).privileges = [
      { luid: "5".repeat(16), attributes: i },
    ];
    const start = f.rawCommands.length;
    assert.equal(
      await prepared.effects.inspect(prepared.input, subjects),
      observed,
    );
    const commands = f.rawCommands.slice(start);
    assert.deepEqual(
      commands
        .filter(({ operation }) => operation === "process-open")
        .map(({ owner, values }) => [owner, Number(values[0])]),
      i === 0
        ? [
            [helper, payload.pid],
            [helper, other.pid],
          ]
        : [],
    );
    assert.deepEqual(
      commands
        .filter(({ operation }) => operation === "process")
        .map(({ owner, values }) => [owner, Number(values[0])]),
      [
        [helper, 0],
        [helper, 1],
      ],
    );
    assert.deepEqual(
      commands
        .filter(({ operation }) => operation === "verify-process")
        .map(({ owner }) => owner),
      [verifier],
    );
    assert.deepEqual(observations.at(-1).privileges, [
      { luid: "5".repeat(16), attributes: i },
    ]);
  }
});

test("Windows launch observation rejects substituted identities, owner slots and failed fresh reads", async () => {
  for (const damage of [
    "birth",
    "session",
    "sid",
    "retired",
    "observer-slot",
    "case-slot",
    "fresh",
  ]) {
    const { f, prepared } = await caseReaderObservationFixture(),
      { helper } = f.current.admission,
      payload = f.rawActor(false),
      other = f.rawActor(),
      subjects = { helper, payload, helpers: [{ identity: other }] },
      cause = new Error("Fresh process observation unavailable");
    // First obtain the slots normally: a prior success cannot replace the next read.
    await prepared.effects.inspect(prepared.input, subjects);
    f.accessNative = (operation, values, scope) => {
      if (operation === "verify-process") {
        const actual = structuredClone(scope.retained[Number(values[0])]);
        if (actual.identity.pid !== helper.pid) return;
        if (damage === "fresh") throw cause;
        if (damage === "birth") actual.identity.creationTime = "99999";
        if (damage === "session") actual.identity.sessionId++;
        if (damage === "sid") actual.identity.userSid = payload.userSid;
        if (damage === "retired") actual.retired = true;
        if (damage === "observer-slot") return scope.retained[1];
        return actual;
      }
      if (damage === "case-slot" && operation === "process")
        return scope.processSlots[1 - Number(values[0])];
    };
    await assert.rejects(
      prepared.effects.inspect(prepared.input, subjects),
      (error) =>
        damage === "fresh"
          ? error === cause
          : /Unverified/u.test(error.message),
    );
  }
});

test("Windows fixed entry executes every ownership recipe with raw IPC and independently held filesystem controls", async () => {
  for (const name of ["literal", "storage", ...WINDOWS_OWNERSHIP_CASES]) {
    const f = rawPreparation(),
      { recipe, binding } = provisionCase(f, "ownership." + name, true);
    await buildRawPreparation(f);
    const system = await createSystemEffects(f, f.options),
      policyRecords = [],
      prepared = await system.prepare(recipe, {
        policyBinding: binding,
        recordPolicy: (value) => policyRecords.push(value),
      });
    if (prepared.admitLiteral) {
      prepared.admitted = await prepared.admitLiteral();
      const observed = await system.literal(prepared);
      assert.equal(
        assertWindowsLiteralObservation(
          prepared.input,
          WINDOWS_LITERAL_ARGUMENTS,
          prepared.admitted.record,
          observed,
        ).status,
        "OBSERVED",
      );
    } else {
      const record = await runWindowsOwnershipCase(
        name,
        prepared.input,
        prepared.effects,
      );
      assert.equal(
        record.status,
        "OBSERVED",
        recipe.id + ": " + JSON.stringify(record),
      );
    }
    assert.ok(policyRecords.length > 0);
    const settled = await system.settle(recipe, prepared, {
      signal: new AbortController().signal,
      execution: {
        id: recipe.id,
        effects: Object.fromEntries(
          NATIVE_EFFECT_CLASSES.map((key) => [key, { admission: "possible" }]),
        ),
      },
    });
    assert.ok(
      Object.values(settled).every(
        (value) => value.settlement.status === "RETIRED",
      ),
      recipe.id,
    );
    assert.equal(
      [...f.accounts.values()].filter((account) => !account.retired).length,
      0,
    );
    assert.ok(
      f.rawEvents.some((frame) => frame.startsWith("ownership-reconstruct ")),
    );
    assert.ok(
      [...f.files.keys()].some(
        (file) => file.includes("outside-") && file.endsWith(".sentinel"),
      ),
    );
    if (name === "stale-identity")
      assert.ok(
        f.rawEvents.some((frame) => frame.startsWith("ownership-stale ")),
      );
    await recoverRecordedCase(f);
  }
});

test("Windows ownership rejects missing controls, substituted objects and ambiguous retirement without releasing reservations", async () => {
  for (const damage of [
    "malformed-control",
    "prefixed-control",
    "malformed-receipt",
    "missing-control",
    "wrong-job",
    "wrong-token",
    "substituted-object",
    "missing-witness",
    "live-member",
    "foreign-holder",
    "live-owner",
    "live-owner-job",
  ]) {
    const f = rawPreparation(),
      { recipe, binding } = provisionCase(
        f,
        damage === "missing-control"
          ? "ownership.service"
          : "ownership.detached",
        true,
      );
    await buildRawPreparation(f);
    const system = await createSystemEffects(f, f.options);
    const prepared = await system.prepare(recipe, {
      policyBinding: binding,
      recordPolicy: () => {},
    });
    f.ownershipDamage = damage;
    const attempt = runWindowsOwnershipCase(
      recipe.id.slice(10),
      prepared.input,
      prepared.effects,
    );
    if (damage === "malformed-receipt") await assert.rejects(attempt);
    else {
      const result = await attempt;
      assert.notEqual(result.status, "OBSERVED", damage);
      assert.equal(result.reservation, "RETAINED");
    }
    const settled = await system.settle(recipe, prepared, {
      signal: new AbortController().signal,
      execution: {
        id: recipe.id,
        effects: Object.fromEntries(
          NATIVE_EFFECT_CLASSES.map((key) => [key, { admission: "possible" }]),
        ),
      },
    });
    if (
      [
        "malformed-control",
        "prefixed-control",
        "malformed-receipt",
        "live-member",
        "foreign-holder",
        "live-owner",
        "live-owner-job",
        "substituted-object",
        "missing-witness",
        "wrong-token",
        "wrong-job",
      ].includes(damage)
    )
      assert.ok(
        Object.values(settled).every(
          (value) => value.settlement.status !== "RETIRED",
        ),
        damage,
      );
  }
});

test("Windows ownership reconstructs held interrupted admission without a final fixture result and retains custody if cleanup is cancelled", async () => {
  const f = rawPreparation(),
    { recipe, binding } = provisionCase(f, "ownership.receipt-before", true);
  await buildRawPreparation(f);
  const system = await createSystemEffects(f, f.options),
    prepared = await system.prepare(recipe, {
      policyBinding: binding,
      recordPolicy: () => {},
    });
  await prepared.effects.admit();
  const admissions = [...f.files.entries()]
    .filter(([file]) => /\\ownership-[0-9]+\.json$/u.test(file))
    .map(([, bytes]) => JSON.parse(bytes))
    .filter((record) => record.admission === "possible");
  assert.equal(admissions.length, 1);
  assert.equal(admissions[0].payload, null);
  assert.equal(
    f.rawEvents.some((frame) => frame.startsWith("ownership-output ")),
    false,
  );
  f.preparation.status = "FAIL";
  for (const file of [...f.files.keys()])
    if (/windows-command-.*-result\.json$/u.test(path.basename(file)))
      f.files.delete(file);
  const retired = await prepared.effects.recoverAndRetire();
  assert.equal(retired.status, "RETIRED");
  const controller = new AbortController();
  controller.abort();
  const retained = await system.settle(recipe, prepared, {
    signal: controller.signal,
    execution: {
      id: recipe.id,
      effects: Object.fromEntries(
        NATIVE_EFFECT_CLASSES.map((key) => [key, { admission: "possible" }]),
      ),
    },
  });
  assert.ok(
    Object.values(retained).every(
      (value) => value.settlement.status !== "RETIRED",
    ),
  );
  assert.equal(
    [...f.accounts.values()].some((account) => !account.retired),
    true,
  );
  const settled = await system.settle(recipe, prepared, {
    signal: new AbortController().signal,
    execution: {
      id: recipe.id,
      effects: Object.fromEntries(
        NATIVE_EFFECT_CLASSES.map((key) => [key, { admission: "possible" }]),
      ),
    },
  });
  assert.ok(
    Object.values(settled).every(
      (value) => value.settlement.status === "RETIRED",
    ),
  );
});

test("Windows ownership requires acknowledged results and fresh unchanged outside and restoration evidence", async () => {
  for (const damage of [
    "missing-output",
    "interrupted-policy",
    "outside-changed",
    "missing-restoration",
  ]) {
    const f = rawPreparation(),
      { recipe, binding } = provisionCase(f, "ownership.detached", true);
    await buildRawPreparation(f);
    const system = await createSystemEffects(f, f.options),
      prepared = await system.prepare(recipe, {
        policyBinding: binding,
        recordPolicy: () => {},
      });
    f.ownershipDamage = damage;
    if (damage === "outside-changed") {
      const sentinel = [...f.files.keys()].find((file) =>
        file.endsWith(".sentinel"),
      );
      f.files.set(sentinel, Buffer.from("changed outside object"));
    }
    let observed;
    try {
      observed = await runWindowsOwnershipCase(
        "detached",
        prepared.input,
        prepared.effects,
      );
    } catch (cause) {
      assert.ok(["missing-output", "interrupted-policy"].includes(damage));
      assert.ok(cause instanceof Error);
    }
    if (damage !== "missing-restoration")
      assert.notEqual(observed?.status, "OBSERVED", damage);
    const settled = await system.settle(recipe, prepared, {
      signal: new AbortController().signal,
      execution: {
        id: recipe.id,
        effects: Object.fromEntries(
          NATIVE_EFFECT_CLASSES.map((key) => [key, { admission: "possible" }]),
        ),
      },
    });
    assert.ok(
      Object.values(settled).every(
        (value) => value.settlement.status !== "RETIRED",
      ),
      damage,
    );
    assert.equal(
      [...f.accounts.values()].some((account) => !account.retired),
      true,
    );
  }
});

async function packageFixture(prepare = true) {
  const f = rawPreparation(),
    { declaration, binding } = provisionCase(f, "ownership.literal", true),
    id = "package.git-for-windows",
    context = nativePolicyContext(f.job, id),
    contextHash = observationDigest(context),
    root = path.join(directory, "case-" + contextHash),
    publication = path.join(directory, "git-package");
  const selected = structuredClone(declaration);
  selected.id = id;
  selected.custody.context = context;
  selected.custody.nonce = contextHash.slice(0, 32);
  selected.custody.plan.path = path.join(sourceDirectory, "package.plan");
  const input = selected.bindings.input;
  input.nonce = selected.custody.nonce;
  input.custody = root + "\\custody";
  input.storage = root + "\\storage";
  input.workspace = input.storage + "\\work";
  input.launcher.path = input.custody + "\\launcher.exe";
  input.executable.path = input.storage + "\\package-extractor.exe";
  input.policy.path = input.custody + "\\policy";
  input.bindings.closure = context.closureSha256;
  selected.bindings.assets[1].path = path.join(
    sourceDirectory,
    "package-extractor.exe",
  );
  f.files.set(selected.bindings.assets[1].path, f.signed);
  f.packageDeclaration = selected;
  const entries = decodeWindowsPlan(
    f.files.get(declaration.custody.plan.path),
    declaration.custody,
  );
  [
    directory,
    root,
    input.custody,
    input.storage,
    input.workspace,
    input.launcher.path,
    input.executable.path,
    selected.bindings.assets[0].path,
    selected.bindings.assets[1].path,
  ].forEach((file, index) => (entries[index].path = file));
  entries.splice(9, 0, {
    kind: "directory",
    path: publication,
    sha256: null,
    signatureSha256: null,
  });
  const planBytes = encodeWindowsCustodyPlan({
    candidateSha,
    nonce: selected.custody.nonce,
    entries,
  });
  selected.custody.plan.sha256 = digest(planBytes);
  f.files.set(selected.custody.plan.path, planBytes);
  f.packageArguments = [
    "x",
    "-y",
    "-bd",
    "-bb0",
    "-o" + publication + "\\content",
    publication + "\\archive",
  ];
  binding.context = context;
  binding.template.policy.launch = nativePolicyLaunchData(
    input,
    f.packageArguments,
  );
  binding.template.policy.launch.request.restrictingSid = {
    binding: "restricting",
  };
  binding.template.policy.policy.objects[3].mask = 0x1200a9;
  binding.approval.manifestSha256 = nativePolicyTemplateDigest(
    binding.template,
  );
  const build = {
      major: 10,
      minor: 0,
      build: 26100,
      sdkRootHex: encode("C:\\Program Files (x86)\\Windows Kits\\10\\"),
    },
    loader = {
      components: [5, 6].map((index) => ({ index, imports: [] })),
      buildSha256: observationDigest({
        ...build,
        independent: true,
        nativeSha256: observationDigest(build),
      }),
      sdkSha256: observationDigest(
        entries.flatMap((entry, index) =>
          entry.kind === "sdk" ? [{ index, sha256: entry.sha256 }] : [],
        ),
      ),
    },
    ref = { url: "https://example.com/review", revision: null, sha256: hash },
    extraction = normalizeGitExtraction(
      {
        schemaVersion: 1,
        candidateSha,
        extractor: {
          path: selected.bindings.assets[1].path,
          bytes: f.signed.length,
          sha256: digest(f.signed),
          bindings: {
            source: hash,
            build: hash,
            toolchain: observationDigest(f.manifest.tools),
            loader: nativePackageReviewDigest(loader),
          },
        },
        policyBinding: binding,
        custody: selected.custody,
        setup: selected.bindings,
        loader,
      },
      candidateSha,
    );
  const reviewed = normalizeNativePackageReview(
    {
      schemaVersion: 2,
      candidateSha,
      packageId: "git-for-windows",
      archiveBytes: nativePackageInput("git-for-windows").bytes,
      entrypoint: "usr/bin/bash.exe",
      extraction,
      bindings: Object.fromEntries(
        [
          "publication",
          "source",
          "build",
          "dependencies",
          "license",
          "abi",
          "transport",
          "extraction",
        ].map((name) => [
          name,
          name === "extraction"
            ? { ...ref, sha256: nativePackageReviewDigest(extraction) }
            : ref,
        ]),
      ),
      files: [
        {
          path: "bin/git.exe",
          bytes: f.signed.length,
          sha256: digest(f.signed),
          executable: true,
        },
        {
          path: "share/empty",
          bytes: 0,
          sha256: digest(Buffer.alloc(0)),
          executable: false,
        },
        {
          path: "usr/bin/bash.exe",
          bytes: f.signed.length,
          sha256: digest(f.signed),
          executable: true,
        },
      ],
    },
    candidateSha,
  );
  f.packageBytes = new Map(
    reviewed.files.map((member) => [
      member.path,
      member.bytes ? f.signed : Buffer.alloc(0),
    ]),
  );
  const entry = {
    packageId: "git-for-windows",
    directory: publication,
    reviewed,
    approvedReviewSha256: nativePackageReviewDigest(reviewed),
  };
  const assets = [
    ...[...WINDOWS_HELPER_NAMES, "package-extractor"].map((name) => ({
      name,
      kind: "image",
      member: "bootstrap/" + name + ".exe",
      path: path.join(sourceDirectory, name + ".exe"),
      bytes: f.signed.length,
      sha256: digest(f.signed),
      bindings:
        name === "package-extractor"
          ? extraction.extractor.bindings
          : {
              source: hash,
              build: hash,
              toolchain: observationDigest(f.manifest.tools),
              loader: hash,
            },
    })),
    ...f.manifest.windowsPreparation.sources.map((source) => ({
      name: source.name,
      kind: "source",
      member: "bootstrap/" + source.name,
      path: path.join(sourceDirectory, source.name),
      bytes: bytes.length,
      sha256: source.sha256,
      bindings: {
        source: hash,
        build: hash,
        toolchain: observationDigest(f.manifest.tools),
        loader: hash,
      },
    })),
    ...[
      f.manifest.windowsPreparation.bootstrap,
      ...f.manifest.windowsPreparation.cases.map((entry) => entry.custody),
      selected.custody,
    ].map((custody) => ({
      name: "custody-plan." + custody.context.executionId,
      kind: "plan",
      member: "bootstrap/custody-plan." + custody.context.executionId,
      path: custody.plan.path,
      bytes: f.files.get(custody.plan.path)?.length ?? bytes.length,
      sha256: custody.plan.sha256,
      bindings: {
        source: hash,
        build: hash,
        toolchain: observationDigest(f.manifest.tools),
        loader: hash,
      },
    })),
  ];
  const packages = [
    ...["codex-win32", "claude-win32"].map((packageId) => {
      const catalog = nativePackageInput(packageId),
        reviewed = {
          schemaVersion: 1,
          candidateSha,
          packageId,
          archiveBytes: catalog.bytes ?? 100,
          bindings: Object.fromEntries(
            [
              "publication",
              "source",
              "build",
              "dependencies",
              "license",
              "abi",
              "transport",
              "extraction",
            ].map((name) => [
              name,
              name === "source" && catalog.sourceRevision
                ? {
                    ...ref,
                    url: ref.url + "/" + catalog.sourceRevision,
                    revision: catalog.sourceRevision,
                  }
                : ref,
            ]),
          ),
          files: [
            {
              path: catalog.entrypoint,
              bytes: f.signed.length,
              sha256: digest(f.signed),
              executable: true,
            },
          ],
        };
      return {
        packageId,
        directory: path.join(directory, packageId),
        reviewed,
        approvedReviewSha256: nativePackageReviewDigest(reviewed),
      };
    }),
    entry,
  ];
  f.manifest.schemaVersion = 2;
  f.manifest.prerequisites = {
    schemaVersion: 1,
    candidateSha,
    platform: "win32",
    assets,
    packages,
  };
  f.manifest.release = {
    providers: Object.fromEntries(
      packages
        .slice(0, 2)
        .map((entry) => [
          entry.packageId.split("-")[0],
          { reviewSha256: entry.approvedReviewSha256 },
        ]),
    ),
  };
  f.manifest.inputs = packages.flatMap((entry) =>
    entry.reviewed.files.map((member) => ({
      path: path.join(entry.directory, "content", ...member.path.split("/")),
      bytes: member.bytes,
      sha256: member.sha256,
    })),
  );
  const operation = installOperationNativeFixture(
    f,
    { request: input },
    { slots: {}, entries },
  );
  installPackageNativeFixture(f, reviewed, publication);
  const prerequisiteInput = {
      ...f,
      directory,
      output: path.join(directory, "prerequisites"),
      buildOutput: output,
      admission: {
        schemaVersion: 1,
        platform: "win32",
        root: "C:\\Fixture",
        readRoots: ["C:\\Fixture"],
        writeRoots: [publication],
        controllerUid: null,
        controllerSid: selected.custody.runnerSid,
        nonce,
        expires: Date.now() + 120000,
      },
    },
    effects = createPrerequisiteEffects(prerequisiteInput, f.options);
  const options = await effects.packageOptions(entry),
    owner = options.extractionEffects;
  assert.ok(owner && options.custody && options.persist);
  assert.equal(f.rawEvents.length, 0, "construction must be effect-free");
  const fixture = {
    f,
    owner,
    entry,
    binding: extraction.policyBinding,
    operation,
    prerequisiteInput,
  };
  if (!prepare) return fixture;
  await owner.sealArchive(
    Buffer.alloc(reviewed.archiveBytes),
    nativePackageInput("git-for-windows").integrity,
    { signal: new AbortController().signal },
  );
  const provisioning = await owner.readProvisioning(extraction.policyBinding),
    policy = materializeNativePolicy(
      extraction.policyBinding.template,
      extraction.policyBinding.approval,
      provisioning,
      context,
    ),
    request = {
      schemaVersion: 1,
      candidateSha,
      platform: "win32",
      mode: "7z-data-only",
      extractor: extraction.extractor,
      archive: publication + "\\archive",
      directory: publication + "\\content",
      archiveBytes: reviewed.archiveBytes,
      archiveIntegrity: nativePackageInput("git-for-windows").integrity,
      arguments: f.packageArguments,
      reviewSha256: observationDigest(reviewed),
      inventory: reviewed.files,
      policySha256: policy.expectedPolicySha256,
      deadlineMs: 120000,
    };
  return { ...fixture, request };
}

test("fixed prerequisite entry composes confined Git extraction, whole-domain retirement and independently sealed publication from raw IPC", async () => {
  const { f, owner, entry, binding, request } = await packageFixture();
  await owner.readPolicy(request, binding);
  await assert.rejects(owner.extract(request));
  assert.ok(
    !f.rawEvents.some((value) => value.startsWith("package-archive-send ")),
  );
  await owner.persist({
    status: "POSSIBLE",
    request,
    requestSha256: observationDigest(request),
  });
  await owner.readPolicy(request, binding);
  const result = await owner.extract(request);
  assert.equal(result.dataOnly, true);
  assert.equal(result.archiveExecuted, false);
  const cleanup = AbortSignal.timeout(30000);
  assert.equal(
    (await owner.settle(request, { signal: cleanup })).status,
    "RETIRED",
  );
  const staged = await owner.verifyStaged(request);
  assert.equal(staged.files.length, 3);
  for (const member of entry.reviewed.files) {
    const actual = await owner.readProtected({
      file: path.join(request.directory, ...member.path.split("/")),
      sha256: member.sha256,
      maximum: Math.max(1, member.bytes),
    });
    assert.equal(
      actual.identitySha256,
      staged.files.find((value) => value.path === member.path).identitySha256,
    );
  }
  assert.equal((await owner.seal(request)).readExecuteOnly, true);
  assert.equal((await owner.verifyPublication()).files.length, 3);
  assert.deepEqual(
    (
      await owner.readPublication(
        path.join(request.directory, "usr", "bin", "bash.exe"),
      )
    ).bytes,
    f.signed,
  );
  assert.ok([...f.accounts.values()].every((account) => account.retired));
  assert.ok(
    f.rawEvents.findIndex((value) => value.startsWith("ownership-stop ")) <
      f.rawEvents.findIndex((value) =>
        value.startsWith("package-publication-seal "),
      ),
  );
});

test("confined extraction rejects escaping, linked, streamed, duplicate and undeclared members before a publication write", async () => {
  for (const damage of [
    "escape",
    "link",
    "stream",
    "duplicate",
    "undeclared",
  ]) {
    const { f, owner, binding, request } = await packageFixture();
    f.packageDamage = damage;
    await owner.readPolicy(request, binding);
    await owner.readPolicy(request, binding);
    await assert.rejects(owner.extract(request));
    assert.ok(
      !f.rawEvents.some((value) => /^package-file [0-9]+ create /u.test(value)),
    );
    const signal = AbortSignal.timeout(30000);
    await owner.settle(request, { signal });
    await owner.recover({ signal });
    assert.ok([...f.accounts.values()].every((account) => account.retired));
  }
});

test("package publication cannot accept substituted held identities or an interrupted policy barrier", async () => {
  {
    const { f, owner, binding, request } = await packageFixture();
    await owner.readPolicy(request, binding);
    await owner.readPolicy(request, binding);
    await owner.extract(request);
    await owner.settle(request, { signal: AbortSignal.timeout(30000) });
    f.packageDamage = "substitution";
    await assert.rejects(owner.seal(request));
    await owner.recover();
  }
  {
    const { f, owner, binding, request } = await packageFixture();
    f.ownershipDamage = "interrupted-policy";
    await assert.rejects(
      owner.readPolicy(request, binding),
      /Interrupted ownership installation/u,
    );
    await assert.rejects(owner.recover());
    assert.ok(
      !f.rawEvents.some((value) => value.startsWith("package-archive-send ")),
    );
    assert.ok(
      f.rawEvents.some((value) => value.startsWith("verify-recovery-jobs ")),
    );
  }
});

test("fixed prerequisite extraction reconstructs partial setup, pre-admission and extraction from bootstrap records without final outputs", async () => {
  for (const phase of ["setup", "pre-admission", "extraction"]) {
    const { f, owner, entry, binding, request, prerequisiteInput } =
      await packageFixture(phase !== "setup");
    if (phase === "setup") {
      const native = f.accessNative;
      f.accessNative = async (...args) => {
        const value = await native(...args);
        return args[0] === "release-build"
          ? { ...value, bytes: value.bytes + 1 }
          : value;
      };
      await assert.rejects(
        owner.sealArchive(
          Buffer.alloc(entry.reviewed.archiveBytes),
          nativePackageInput("git-for-windows").integrity,
        ),
      );
      f.accessNative = native;
    } else if (phase === "extraction") {
      await owner.readPolicy(request, binding);
      await owner.readPolicy(request, binding);
      f.packageDamage = "link";
      await assert.rejects(owner.extract(request));
      f.packageDamage = null;
    }
    for (const helper of f.manifest.helpers)
      f.files.delete(path.join(output, helper.name + ".exe"));
    const open = f.options.openPreparation,
      closedObservers = new Set(),
      originalOwners = [...f.actors.values()].filter((actor) => !actor.retired);
    assert.ok(originalOwners.length > 0);
    f.options.openPreparation = async (...args) => {
      const channel = await open(...args),
        nonce = args[1][6];
      return {
        ...channel,
        close: () => {
          if (closedObservers.has(nonce)) return;
          channel.close();
          // Model the failed cold observer's eventual EOF exit, leaving its
          // task and the original owners for fresh independent retirement.
          for (const pid of [channel.pid, f.rawTasks.get(nonce).pid]) {
            f.actors.get(pid).retired = true;
            f.rawExitCodes.set(pid, 126);
          }
          closedObservers.add(nonce);
        },
      };
    };
    const before = f.rawEvents.length,
      cold = createPrerequisiteEffects(prerequisiteInput, f.options),
      options = await cold.packageOptions(entry);
    assert.equal(f.rawEvents.length, before);
    await assert.rejects(options.custody.recover());
    assert.ok(closedObservers.size > 0);
    assert.ok(originalOwners.every((actor) => !actor.retired));
    assert.ok(
      f.rawEvents
        .slice(before)
        .some((value) => value.startsWith("verify-recovery-jobs ")),
    );
    await owner.recover();
    if (phase === "pre-admission") {
      const closed = f.rawEvents.findIndex((value) =>
          value.startsWith("package-files-close "),
        ),
        retired = f.rawEvents.findIndex((value) =>
          value.startsWith("case-retire "),
        );
      assert.ok(closed >= 0 && retired > closed);
    }
    const settled = createPrerequisiteEffects(prerequisiteInput, f.options),
      reconstructed = await settled.packageOptions(entry),
      result = await reconstructed.custody.recover();
    assert.equal(result.status, "RETAINED");
    assert.equal(result.admitted, false);
    assert.ok([...f.accounts.values()].every((account) => account.retired));
    assert.equal(f.rawTasks.size, 0);
    assert.ok([...f.actors.values()].every((actor) => actor.retired));
    assert.ok(
      !f.rawEvents
        .slice(before)
        .some((value) => value.startsWith("ownership-launch ")),
    );
    await assert.rejects(reconstructed.extractionEffects.verifyPublication());
  }
});

test("package recovery observers accept the declared larger ledger and reject an unbounded recovery sequence", async () => {
  const { f, entry } = await packageFixture(false);
  const input = {
    ...f,
    manifest: {
      ...f.manifest,
      windowsPreparation: {
        ...f.manifest.windowsPreparation,
        bootstrap: entry.reviewed.extraction.custody,
      },
    },
  };
  const ordinary = createWindowsPreparationFiles(
    {
      ...input,
      manifest: {
        ...input.manifest,
        prerequisites: { ...input.manifest.prerequisites, packages: [] },
      },
      recoverySequence: 65537,
    },
    f.options,
  );
  await assert.rejects(ordinary.readBuildDirectory(output));
  assert.equal(f.rawEvents.length, 0);
  for (const recoverySequence of [1048577, 65537]) {
    const files = createWindowsPreparationFiles(
      { ...input, recoverySequence },
      f.options,
    );
    if (recoverySequence > 1048576) {
      const before = f.rawEvents.length;
      await assert.rejects(files.readBuildDirectory(output));
      assert.equal(f.rawEvents.length, before);
    } else {
      await files.readBuildDirectory(output);
      assert.equal((await files.settleFiles()).status, "RETIRED");
    }
  }
  assert.ok([...f.actors.values()].every((actor) => actor.retired));
});

test("package reconstruction rejects changed protected extraction requests without adopting publication", async () => {
  const { f, owner, entry, binding, request, prerequisiteInput } =
    await packageFixture();
  await owner.readPolicy(request, binding);
  await owner.readPolicy(request, binding);
  f.packageDamage = "link";
  await assert.rejects(owner.extract(request));
  f.packageDamage = null;
  await owner.recover();
  for (const [file, bytes] of f.files) {
    if (
      !path.basename(file).startsWith("windows-case-package.git-for-windows-")
    )
      continue;
    const record = JSON.parse(bytes);
    if (record.phase === "package-launch-possible") {
      record.request.arguments[5] = "C:\\Fixture\\foreign-archive";
      f.files.set(file, Buffer.from(JSON.stringify(record) + "\n"));
    }
  }
  const before = f.rawEvents.length,
    effects = createPrerequisiteEffects(prerequisiteInput, f.options),
    options = await effects.packageOptions(entry);
  await assert.rejects(options.custody.recover());
  await assert.rejects(options.extractionEffects.verifyPublication());
  assert.ok([...f.accounts.values()].every((account) => account.retired));
  assert.ok(
    !f.rawEvents
      .slice(before)
      .some((value) => value.startsWith("ownership-launch ")),
  );
});
