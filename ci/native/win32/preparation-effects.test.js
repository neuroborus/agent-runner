import assert from "node:assert/strict";
import test from "node:test";
import { win32 as path } from "node:path";
import {
  observationDigest,
  nativePolicyLaunchData,
  nativePolicyContext,
  nativePolicyTemplateDigest,
  materializeNativePolicy,
  NATIVE_EFFECT_CLASSES,
  releaseClosureDigest,
} from "../index.js";
import {
  createWindowsBuildEffects,
  createWindowsSystemEffects,
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
import { digest, windowsLaunchDigest } from "./protocol.js";
import { inspectWindowsPe } from "./protocol.js";
import { windowsPolicyFixture } from "./policy.fixture.js";
import { decodePlan as decodeWindowsPlan } from "./custody-protocol.js";
import { createBuildEffects, createSystemEffects } from "../native-effects.mjs";

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
        3 +
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
        { recipe, binding } = operationCase(f, id);
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

function rawPreparation() {
  const f = wiring(),
    { unsigned, signed } = publicationBytes(),
    imageSha = digest(signed),
    signatureSha = inspectWindowsPe(signed).signatureSha256,
    actors = new Map(),
    images = new Map(),
    retained = [],
    heldFiles = [],
    jobs = new Map(),
    tasks = new Map(),
    events = [],
    fileIds = new Map();
  let nextPid = 100,
    upload,
    readBytes,
    listedNames;
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
      limitFlags: 0x2008,
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
  for (const helper of f.manifest.helpers) helper.sha256 = imageSha;
  for (const tool of f.manifest.tools) {
    tool.sha256 = imageSha;
    f.files.set(tool.path, signed);
  }
  const plan = f.manifest.windowsPreparation;
  for (const pin of [
    plan.bootstrap.reader,
    plan.bootstrap.bridge,
    plan.command.helper,
  ]) {
    pin.sha256 = imageSha;
    pin.signatureSha256 = signatureSha;
  }
  plan.command.helperSignatures = Object.fromEntries(
    WINDOWS_HELPER_NAMES.map((name) => [name, signatureSha]),
  );
  plan.command.unsignedHelpers = Object.fromEntries(
    WINDOWS_HELPER_NAMES.map((name) => [name, digest(unsigned)]),
  );
  plan.command.toolSignatures = { compiler: signatureSha, sdk: signatureSha };
  for (const helper of f.manifest.helpers)
    f.files.set(path.join(sourceDirectory, helper.name + ".exe"), signed);
  for (const source of plan.sources)
    f.files.set(path.join(sourceDirectory, source.name), bytes);
  const sdkFile =
    "C:\\Program Files (x86)\\Windows Kits\\10\\Include\\1.0\\um\\fixture.h";
  f.files.set(sdkFile, bytes);
  const entries = [
    { kind: "sdk", path: sdkFile, sha256: hash, signatureSha256: null },
    ...f.manifest.helpers.map(({ name }) => ({
      kind: "helper",
      path: path.join(sourceDirectory, name + ".exe"),
      sha256: imageSha,
      signatureSha256: signatureSha,
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
  const planBytes = encodeWindowsCustodyPlan({ candidateSha, nonce, entries });
  plan.bootstrap.plan.sha256 = digest(planBytes);
  f.files.set(plan.bootstrap.plan.path, planBytes);
  for (const request of f.requests) request.toolSha256 = imageSha;
  const rawNative = async (operation, args, scope) => {
    const { retained, heldFiles, entries: selected } = scope;
    events.push(operation);
    if (f.damage === operation) throw new Error("Interrupted native writer");
    if (f.accessNative) {
      const value = await f.accessNative(operation, args, scope);
      if (value !== undefined) return value;
    }
    if (operation === "prepare-list") {
      const offset = Number(args[0]);
      if (!offset)
        listedNames = [...f.files.keys()]
          .filter(
            (file) =>
              path.dirname(file) === directory &&
              /^windows-[a-z0-9.-]+\.json$/u.test(path.basename(file)),
          )
          .map((file) => path.basename(file));
      return {
        names: listedNames.slice(offset, offset + 128).map(encode),
        complete: offset + 128 >= listedNames.length,
      };
    }
    if (operation === "prepare-directory")
      return {
        identity: fileId(decode(args[0])),
        daclSha256: hash,
        protectedParents: true,
      };
    if (operation === "prepare-read") {
      assert.ok(!readBytes && !upload);
      const file = decode(args[0]);
      readBytes = f.files.get(file);
      assert.ok(readBytes, file);
      if (args[1] !== "-") assert.equal(digest(readBytes), args[1]);
      return {
        identity: fileId(file),
        daclSha256: hash,
        protectedParents: true,
        sha256: digest(readBytes),
        bytes: readBytes.length,
        slot: 0,
      };
    }
    if (operation === "prepare-bytes")
      return {
        hex: readBytes
          .subarray(Number(args[1]), Number(args[1]) + Number(args[2]))
          .toString("hex"),
      };
    if (operation === "prepare-release") {
      readBytes = null;
      return { closed: true };
    }
    if (operation === "prepare-write") {
      assert.ok(!readBytes && !upload);
      const file = path.join(directory, decode(args[0]));
      assert.ok(!f.files.has(file));
      upload = { file, bytes: Buffer.alloc(Number(args[1])), sha256: args[2] };
      return { created: true };
    }
    if (operation === "prepare-chunk") {
      Buffer.from(args[1], "hex").copy(upload.bytes, Number(args[0]));
      return { written: args[1].length / 2 };
    }
    if (operation === "prepare-seal") {
      assert.equal(digest(upload.bytes), upload.sha256);
      f.files.set(upload.file, upload.bytes);
      const sha256 = upload.sha256;
      upload = null;
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
      assert.ok(slot < 128);
      return {
        identity: fileId(file),
        sha256: digest(data),
        signatureSha256: args[2] === "-" ? null : signatureSha,
        daclSha256: hash,
        slot,
        bytes: data.length,
      };
    }
    if (operation === "verify-retain") {
      const actual = actors.get(Number(args[0]));
      assert.ok(actual);
      let slot = retained.indexOf(actual);
      if (slot < 0) slot = retained.push(actual) - 1;
      assert.ok(slot < 128);
      return { slot, process: actual };
    }
    if (operation === "verify-process") return retained[Number(args[0])];
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
    if (operation === "verify-image")
      return {
        sha256: imageSha,
        signatureSha256: signatureSha,
        pathHex: encode(images.get(retained[Number(args[0])].identity.pid)),
      };
    if (operation === "verify-transfer") {
      const child = retained[Number(args[0])].identity;
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
      return jobs.has(child.pid) ? job(child) : { absent: true };
    }
    if (operation === "verify-subjects")
      return { identities: retained.map((state) => state.identity), jobs: [] };
    if (operation === "verify-task")
      return tasks.has(decode(args[1]))
        ? { absent: false, sha256: hash, instances: 1 }
        : { absent: true };
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
        windowsOwnershipArguments(declaration.context.executionId, {
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
          mask: [0, 0, 0x120020, 0x12019f, 0, 0x1200a9][i],
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
          ? [plan.bootstrap, ...plan.cases.map((entry) => entry.custody)].find(
              (entry) => entry.plan.path === declaration.plan.path,
            )
          : declaration,
      ),
      scope = { retained: [], heldFiles: [], entries: selected },
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
      taskSha256: hash,
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
            { phase: "entry", helper, bridge, processDaclSha256: hash },
            { helper, peer: bridge },
          );
        } else if (frame === "P\n")
          queue.push({
            candidateSha,
            nonce: declaration.nonce,
            entries: selected.length,
          });
        else {
          const [operation, sequence, ...values] = frame.trim().split(/ +/u);
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
              ? await f.accessNative(operation, values, scope, declaration)
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
            jobs.set(child.pid, [child, worker]);
            value = {
              hex: Buffer.from(JSON.stringify(frames.shift())).toString("hex"),
            };
          } else if (operation === "process-open") {
            const state = actors.get(Number(values[0]));
            value = { slot: processSlots.push(state) - 1, observation: state };
          } else if (operation === "process-image")
            value = {
              identity: worker,
              sha256: imageSha,
              signatureSha256: signatureSha,
            };
          else if (operation === "process")
            value = processSlots[Number(values[0])];
          else if (operation === "helper-send") {
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
                !upload &&
                  !readBytes &&
                  retained.every((subject) => subject.retired),
              );
            actors.get(helper.pid).retired = true;
            actors.get(bridge.pid).retired = true;
            tasks.delete(declaration.nonce);
            value = { closed: true };
            queue.push(
              { sequence: Number(sequence), value },
              {
                phase: "retired",
                taskSha256: hash,
                taskRemoved: true,
                helperRetired: true,
                ...(observer
                  ? { helper, observations: f.survivingObserver ? 1 : 2 }
                  : {}),
              },
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
      ].find((entry) => entry.plan.path === args[4]);
      assert.ok(declaration);
      return channel({ ...declaration, nonce: args[6] }, true, args);
    },
    readerOptions: { open: async (declaration) => channel(declaration) },
  };
  return Object.assign(f, {
    rawEvents: events,
    signed,
    unsigned,
    actors,
    sdkFile,
    rawActor: actor,
    rawFileId: fileId,
    rawJobs: jobs,
    rawImages: images,
  });
}

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
      await buildRawPreparation(f);
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
test("Windows fixed entry supplies build/file/verifier defaults through raw IPC and rereads preparation without another compiler", async () => {
  const f = rawPreparation(),
    preparationWork = new AbortController(),
    verificationWork = new AbortController();
  f.signal = preparationWork.signal;
  assert.equal(f.rawEvents.length, 0);
  await buildRawPreparation(f);
  preparationWork.abort();
  const compilerCount = f.rawEvents.filter((event) =>
      event.startsWith("helper-start "),
    ).length,
    actorCount = f.actors.size;
  assert.equal(compilerCount, 15);
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

test("Windows fixed-entry partial recovery uses protected build records and fresh held retirement without prepared outputs", async () => {
  for (const damage of [
    null,
    "missing-birth",
    "worker-request",
    "observer-intent",
    "observer-birth",
    "journal-gap",
    "surviving-worker",
  ]) {
    const f = rawPreparation(),
      build = await createBuildEffects(f, f.options);
    await build.run(f.requests[2]);
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
    outerJob: { limitFlags: 0x2008, processLimit: 32, uiRestrictions: 255 },
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
  ]) {
    const f = rawPreparation();
    await buildRawPreparation(f);
    const binding = buildPolicy(f);
    if (damage === "extra-authority")
      binding.template.policy.policy.compiler.groups = [
        { sid: "S-1-5-32-544", attributes: 4 },
      ];
    if (damage === "wrong-attempt") binding.context.runAttempt++;
    // Reapprove only a deliberately different expected policy, never an observed pin.
    binding.approval.manifestSha256 = nativePolicyTemplateDigest(
      binding.template,
    );
    if (damage === "missing-policy") {
      const command = f.preparation.commands[0],
        file = path.join(
          directory,
          `windows-command-${command.requestSha256}-result.json`,
        ),
        record = JSON.parse(f.files.get(file));
      delete record.compilerPolicy;
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
