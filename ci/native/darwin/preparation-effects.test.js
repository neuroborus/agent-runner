import assert from "node:assert/strict";
import test from "node:test";
import path from "node:path";
import {
  observationDigest,
  nativePolicyLaunchData,
  nativePolicyTemplateDigest,
  materializeNativePolicy,
  NATIVE_EFFECT_CLASSES,
  NATIVE_GROUPS,
  releaseClosureDigest,
} from "../index.js";
import {
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
} from "./index.js";
import { digest, darwinLaunchDigest } from "./protocol.js";

const candidateSha = "a".repeat(40),
  bytes = Buffer.from("sealed reviewed bytes"),
  hash = digest(bytes),
  cdhash = "c".repeat(40),
  output = "/fixture/report/platform-build",
  directory = path.dirname(output),
  sourceDirectory = "/fixture/sealed/darwin";
const retired = {
  status: "RETIRED",
  independent: true,
  emergencyCleanup: false,
  nativeEventSha256: hash,
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

function wiring() {
  const events = [],
    files = new Map(),
    env = {
      CI: "true",
      GITHUB_ACTIONS: "true",
      ImageOS: "macos15",
      RUNNER_TEMP: "/fixture",
    };
  const manifest = {
    candidateSha,
    platform: "darwin",
    environment: { SDKROOT: "/fixture/sdk" },
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
    read: async () => {
      events.push("sealed-read");
      return bytes;
    },
    inspectImage: (value) => assert.ok(Buffer.isBuffer(value)),
    readReceipt: async (file) => {
      assert.ok(files.has(file));
      return Buffer.from(JSON.stringify(files.get(file)));
    },
    createReader: (value, readerOptions) => ({
      async start() {
        events.push(`start:${value.context.executionId}`);
        await readerOptions.persist({
          context: value.context,
          sequence: 0,
          phase: "entry",
          custody: "POSSIBLE",
        });
        return { helper: identity(20), independent: true, planSha256: hash };
      },
      async beginCleanup({ signal }) {
        assert.ok(signal instanceof AbortSignal && !signal.aborted);
        events.push("cleanup");
      },
      async retired(value) {
        assert.ok(value.pid);
        events.push("fresh-retirement");
        return retired;
      },
      async close() {
        events.push(`close:${value.context.executionId}`);
        return {
          status: "RETIRED",
          independent: true,
          closed: true,
          nativeEventSha256: hash,
        };
      },
    }),
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
    60000 + 3 * 30000 + DARWIN_HELPER_NAMES.length * 60000,
  );
  assert.equal(
    darwinSystemRecipes().find(({ id }) => id === "files.aliases").deadlineMs,
    360000,
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

test("Darwin native compiler entry verifies parked images, bounded output and retirement before publication", async () => {
  for (const scenario of [
    "retired",
    "descendants",
    "publication-failure",
    "oversized-output",
    "malformed-output",
    "invalid-utf8",
    "unexpected-field",
  ]) {
    const value = wiring(),
      request = value.requests[0],
      operation = darwinBuildOperation(request, value.manifest, output),
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
      {
        helper: { path: "/fixture/sealed/build-helper", sha256: hash, cdhash },
        tools: custody("build").tools,
        toolCdhash: cdhash,
      },
      reader,
      async (record) => {
        events.push(`persist:${record.phase}`);
        if (record.phase === "publication-possible") {
          assert.equal(record.output, request.cwd);
          assert.equal(record.target, operation.target ?? null);
          if (scenario === "publication-failure")
            throw new Error("Cannot persist publication intent");
        }
      },
      {
        open: async () => ({
          channel: {
            receive: async () => frames.shift(),
            send: async (command) => {
              events.push(command);
            },
            completion: Promise.resolve({ code: 0, signal: null }),
            close() {},
          },
        }),
      },
    );
    if (scenario !== "retired") {
      await assert.rejects(pending);
      assert.ok(events.indexOf("persist:worker") < events.indexOf("R"));
      assert.ok(!events.includes("S"));
      assert.ok(!events.includes("retired:10"));
      assert.equal(events.at(-1), "persist:uncertain");
      continue;
    }
    const observed = await pending;
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
          baselineSha256: digest(JSON.stringify(baseline)),
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
