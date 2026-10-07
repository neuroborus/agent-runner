import assert from "node:assert/strict";
import test from "node:test";
import path from "node:path";
import { constants } from "node:fs";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { createBuildEffects, createSystemEffects } from "../native-effects.mjs";
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
  encodeDarwinCustodyPlan,
} from "./index.js";
import { digest, darwinLaunchDigest } from "./protocol.js";
import { DARWIN_OWNERSHIP_CASES, runDarwinOwnershipCase } from "./ownership.js";
import { assertDarwinLiteralObservation } from "./literal.js";
import { DARWIN_BUILD_CUSTODY_MS } from "./build.js";
import { darwinCustodyChannel } from "./channel.js";

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
    schemaVersion: 1,
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
    60000 +
      3 * 30000 +
      DARWIN_HELPER_NAMES.length * 60000 +
      60000 +
      (3 + DARWIN_HELPER_NAMES.length + 3 + darwinSystemRecipes().length) *
        30000 +
      2 * 120000,
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

// Native records are raw transport data. Repository owners still perform asset
// admission, persistence, command release, byte joins and fresh retirement.
function buildTranscripts() {
  const f = wiring(),
    files = new Map(),
    events = [],
    processes = new Map();
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
  const plan = f.manifest.darwinPreparation;
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
  let nextPid = 1000,
    survivor = false,
    disconnect = false,
    changed = false,
    retainedVerifier = false,
    foreignReceipt = false,
    compilerPolicyFault = false,
    caseFault = null;
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
    if (["--probe", "--probe-domain"].includes(args[0])) {
      const verifier = subject(),
        pid = Number(args[1]);
      events.push("probe:" + pid);
      let enumeration;
      if (args[0] === "--probe-domain") {
        assert.equal(args[2], "90001");
        assert.equal(args[3], "90002");
        events.push("fresh-domain");
        enumeration = {
          uid: 90001,
          complete: true,
          capacity: 33,
          zombies: [],
          live: [...processes.values()]
            .filter(
              ({ identity }) =>
                identity.uid === 90001 ||
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
    assert.ok(["--build-serve", "--case-serve"].includes(args[0]));
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
    let ownershipMode, launcher, payload;
    const control = [],
      data = [];
    const endpoints = [],
      argsForCase = args[3];
    const helper = subject();
    live(helper, entry.reader.path);
    const queue = [{ helper }],
      held = new Map();
    let index = 1;
    const sessions = new Set();
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
            const report = planEntries.at(-1);
            assert.equal(report.kind, "directory");
            assert.equal(report.path, output);
            assert.equal(directories.get(report.path).uid, 0);
            assert.equal(directories.get(path.dirname(report.path)).uid, 1001);
          }
          queue.push({ candidateSha, uid: 90001, gid: 90002, entries: 1 });
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
        if (name === "case-start") {
          assert.ok(caseMode);
          ownershipMode = args[0];
          assert.ok(
            ["literal", "storage", ...DARWIN_OWNERSHIP_CASES].includes(
              ownershipMode,
            ),
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
            decisions: [
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
              uid: 90001,
              ruid: 90001,
              svuid: 90001,
              gid: 90002,
              rgid: 90002,
              svgid: 90002,
              auid: 90001,
            };
            live(payload, planEntries[5].path);
            control.push({ helper: launcher, payload });
          } else if (args[0] === "0" && args[1] === "R") {
            payload = { ...payload, pidVersion: 2 };
            live(payload, planEntries[5].path);
            data.push(
              ["literal", "storage"].includes(ownershipMode)
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
                put(file, Buffer.from(argsForCase.slice(0, 32)), 0o600, 90001);
                files.get(file).gid = 90002;
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
        } else if (name === "case-session") {
          sessions.add(Number(args[0]));
          value = { asid: Number(args[0]), held: true };
        } else if (name === "case-receipt" || name === "case-receipt-read") {
          const file = planEntries[1].path + "/receipt-" + args[0] + ".json";
          if (name === "case-receipt") {
            assert.ok(!files.has(file));
            put(file, Buffer.from(args[2], "hex"), 0o400);
          }
          assert.equal(digest(files.get(file).bytes), args[1]);
          value = { hex: files.get(file).bytes.toString("hex") };
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
            uid: 90001,
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
              ({ identity }) => identity.uid !== 90001,
            ),
          );
          value = { uid: 90001, noLiveUid: true };
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
          value = snapshot(file);
          held.set(args[0], {
            file,
            data: files.get(file).bytes,
            object: value,
          });
        } else if (name === "reserve") {
          value = held.get(args[0]).object;
        } else if (name === "case-directory") {
          const i = Number(args[0]),
            file = planEntries[i].path;
          assert.ok(!directories.has(file));
          directories.set(file, {
            uid: i === 3 ? 90001 : 0,
            gid: i === 1 ? 0 : 90002,
            mode: i === 0 || i === 2 ? 0o710 : 0o700,
            ino: directories.size + 950,
          });
          value = snapshot(file, true);
          held.set(args[0], { file, object: value });
        } else if (name === "case-rejoin") {
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
            i === 6 ? 0o400 : 0o550,
          );
          files.get(file).gid = i === 5 ? 90002 : 0;
          value = snapshot(file);
          held.set(args[0], {
            file,
            data: files.get(file).bytes,
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
            uid: caseFault === "identity" ? 90003 : 90001,
            gid: 90002,
            accountVerified: true,
            accounts: { uidAccounts: 1, primaryGroupMembers: 1, gidGroups: 1 },
            objects: [...held]
              .filter(([i]) => Number(i) < 7)
              .map(([index, { object }]) => ({ index: Number(index), object })),
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
  };
  f.input.preparation = undefined;
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
    directories,
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
    image,
    put,
    foreignReceipt: () => {
      foreignReceipt = true;
    },
  };
}

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
        (entry) => entry.identity.asid > 0,
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
  const bindingContext = context(id),
    root =
      "/private/var/run/native-poc/cases/" + observationDigest(bindingContext);
  const request = {
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
      reviewSha256: hash,
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
    schemaVersion: 1,
    candidateSha,
    platform: "darwin",
    sourceReviewSha256: hash,
    provisioningReviewSha256: hash,
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
    authoritySha256: hash,
    uid: 90001,
    gid: 90002,
    input,
    assets,
  };
  return {
    template,
    approval: {
      candidateSha,
      platform: "darwin",
      authority: "operator-protected",
      manifestSha256: nativePolicyTemplateDigest(template),
    },
    context: bindingContext,
  };
}
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
      fault.startsWith("interrupted") ? "RETIRED" : "RETAINED",
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

test("fixed Darwin ownership defaults leave unfinished access owners blocked", async () => {
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
