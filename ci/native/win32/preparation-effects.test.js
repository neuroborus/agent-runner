import assert from "node:assert/strict";
import test from "node:test";
import { win32 as path } from "node:path";
import {
  observationDigest,
  nativePolicyLaunchData,
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
  runWindowsBuildCommand,
  windowsSystemRecipes,
  encodeWindowsCustodyPlan,
  WINDOWS_LITERAL_ARGUMENTS,
  WINDOWS_SYSTEM_PREPARATION_MS,
  WINDOWS_CUSTODY_DEADLINE_MS,
  observeWindowsRelease,
} from "./index.js";
import { digest, windowsLaunchDigest } from "./protocol.js";
import { windowsPolicyFixture } from "./policy.fixture.js";

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
        2 +
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
