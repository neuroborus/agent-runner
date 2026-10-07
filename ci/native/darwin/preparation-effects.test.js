import assert from "node:assert/strict";
import test from "node:test";
import path from "node:path";
import { constants } from "node:fs";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { deflateSync } from "node:zlib";
import { createHash } from "node:crypto";
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
import { runDarwinFileCase, DARWIN_FILE_CASE_IDS } from "./files-cases.js";
import { runDarwinGitCase } from "./git.js";
import { DARWIN_ACCESS_DENIALS, runDarwinAccessCase } from "./access.js";
import { darwinPfRootDigest } from "./pf-preparation.js";
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
    operationFrames;
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
    let ownershipMode,
      launcher,
      payload,
      pfHelper,
      pfWorker,
      pfOperation,
      auditObserver,
      attemptSubject,
      attemptIndex,
      controlAttempt,
      peerSubject,
      foreignAnchor = false;
    let pfInstalled = false,
      anchorInstalled = false,
      auditSequence = 0,
      auditTime = 0,
      auditCount = 0;
    const auditRecords = new Map(),
      auditPending = [],
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
        { anchor: "", rules: pfInstalled ? accessSpec.rootRules : [] },
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
            const report = planEntries[11];
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
        else if (name === "pf-read") value = pfRead();
        else if (name === "pf-write") {
          assert.ok(accessSpec);
          assert.equal(Number(args[0]), accessSpec.pf.tool.index);
          pfInstalled = args[3] === "install";
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
          pfHelper = subject();
          live(pfHelper, planEntries[4].path);
          value = { helper: pfHelper };
        } else if (name === "access-pf-worker") {
          pfWorker = subject();
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
          auditObserver = subject();
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
          for (let i = 0; i < 13; i++) {
            const file = accessSpec.attempts[i].target;
            if (!files.has(file) && !directories.has(file))
              put(file, Buffer.from(argsForCase.slice(0, 32)), 0o600, 90001);
            if (i === 6) {
              const control = targetFile(i, true);
              directories.set(control, {
                uid: 90001,
                gid: 90002,
                mode: 0o700,
                ino: directories.size + 950,
              });
              put(
                control + "/inspection",
                Buffer.from(argsForCase.slice(0, 32)),
                0o600,
                90001,
              );
            } else if (i >= 2)
              put(
                targetFile(i, true),
                Buffer.from(argsForCase.slice(0, 32)),
                0o600,
                90001,
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
        else if (name === "access-run") {
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
          const spec = accessSpec.attempts[attemptIndex];
          if (!nativeCode && spec.operation === "write")
            files.get(targetFile(attemptIndex, controlAttempt)).bytes =
              Buffer.from(argsForCase.slice(0, 32) + "-edit");
          if (attemptIndex >= 35 && !controlAttempt)
            for (let i = 0; i < 4; i++)
              if (caseFault !== "missing-counter-leg" || i !== 2)
                packetCounts[(attemptIndex - 35) * 8 + i]++;
          const raw = Buffer.alloc(18);
          raw.writeUInt32BE(++auditCount);
          auditRecords.set(raw.toString("hex"), auditTokens(nativeCode));
          if (!(
            caseFault === "audit-event-loss" &&
            !controlAttempt &&
            attemptIndex === 2
          ))
            auditPending.push(word(raw.length), raw);
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
        } else if (name === "access-complete") {
          processes.delete(attemptSubject.pid);
          if (peerSubject) processes.delete(peerSubject.pid);
          value = null;
        } else if (name === "access-counters")
          value = packetCounts.map((packets, index) => ({
            index,
            packets: String(packets),
            ruleSha256: digest(
              Buffer.from(accessSpec.anchorRules[index].raw, "hex"),
            ),
            action:
              accessSpec.anchorRules[index].action === 0 ? "permit" : "deny",
          }));
        else if (name === "access-controls-close") {
          assert.equal(auditObserver, null);
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
          value = snapshot(file, directories.has(file));
          held.set(args[0], {
            file,
            data: files.get(file)?.bytes,
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
            gid: i === 1 || file.endsWith("/custody/files") ? 0 : 90002,
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
          files.get(file).gid = i === 5 ? 90002 : 0;
          if (
            i >= 12 &&
            planEntries[i].kind === "data" &&
            /\/storage\/(?:metadata|control|work|control-work)\//u.test(file)
          ) {
            const work = /\/storage\/(?:work|control-work)\//u.test(file);
            Object.assign(files.get(file), {
              uid: work ? 90001 : 0,
              gid: 90002,
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
            uid: caseFault === "identity" ? 90003 : 90001,
            gid: 90002,
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
function accessBinding(f, profile) {
  const id = "access." + profile,
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
        event: i < 13 ? 1 : i < 19 ? 2 : 3,
        controlEvent: i < 13 ? 1 : i < 19 ? 2 : 3,
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
      aclSha256: hash,
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
    })),
    baseline = {
      active: false,
      states: 0,
      graph: [{ anchor: "", rules: [] }],
      interfaces: [{ name: "lo0", skip: false }],
      routesSha256: hash,
    },
    installed = {
      ...baseline,
      active: true,
      graph: [{ anchor: "", rules: rootRules }],
    },
    events = [
      { event: 1, opcode: "AUE_OPEN", classes: 1, selector: "path" },
      { event: 2, opcode: "AUE_SEMGET", classes: 1, selector: "ipc" },
      { event: 3, opcode: "AUE_CONNECT", classes: 1, selector: "socket" },
    ],
    record = {
      schemaVersion: 1,
      contextSha256: observationDigest(binding.context),
      pf: {
        approval: {
          schemaVersion: 1,
          contextSha256: observationDigest(binding.context),
          manifestSha256: hash,
          baselineSha256: digest(JSON.stringify(baseline)),
          installedRootSha256: darwinPfRootDigest(installed),
          routesSha256: hash,
          loopbackSkip: false,
        },
        tool: { index: tool, cdhash },
        install,
        restore,
        configuration,
        before,
        anchorRulesSha256: digest(JSON.stringify(anchorRules)),
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
      assets,
      objects,
      attempts,
    };
  const approvalBytes = Buffer.from(JSON.stringify(record) + "\n"),
    approval = {
      path: sourceDirectory + "/access-approval",
      sha256: digest(approvalBytes),
    };
  f.put(approval.path, approvalBytes, 0o400);
  input.reviewSha256 = approval.sha256;
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
  binding.approval.manifestSha256 = nativePolicyTemplateDigest(
    binding.template,
  );
  const custody = encodeDarwinCustodyPlan({
    candidateSha,
    uid: request.uid,
    gid: request.gid,
    entries: entryList,
  });
  declared.custody.plan.sha256 = digest(custody);
  f.put(declared.custody.plan.path, custody, 0o400);
  declared.bindings.access = { approval };
  f.access({ ...record, profile, rootRules, anchorRules, pointer });
  return binding;
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
    const { reviewSha256, ...reviewed } = input;
    const record = {
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
    input.reviewSha256 = approval.sha256;
    declared.bindings.input = input;
    declared.bindings.operations = { approval };
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
    { request, base: null, root: null, reviewSha256: null },
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

function gitBinding(f, id, fault) {
  const setup = operationBinding(f, id),
    { request, add, copy } = setup;
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
      initial.commit.sha,
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
          Buffer.from("(version 1)\n(deny default)\n"),
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
  const input = {
    request,
    git: { path: request.storage + "/git", sha256: digest(f.image), cdhash },
    metadata: request.storage + "/metadata",
    hooks: request.storage + "/hooks",
    parent: initial.commit.sha,
    reviewSha256: null,
  };
  const result = setup.finish(input, slots, {
    kind: "darwin-git",
    gitSha256: input.git.sha256,
    metadata: { identitySha256: null },
    hooks: { identitySha256: null },
    authority: { uid: 0, gid: 0, sandboxed: false },
    profiles: profiles.map(({ profile }) => ({
      profile,
      seatbeltSha256: digest(Buffer.from("(version 1)\n(deny default)\n")),
    })),
  });
  result.dynamic("git-metadata", [["policy", "metadata", "identitySha256"]]);
  result.dynamic("git-hooks", [["policy", "hooks", "identitySha256"]]);
  result.approve();
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
        uid: 90001,
        ruid: 90001,
        svuid: 90001,
        gid: 90002,
        rgid: 90002,
        svgid: 90002,
        auid: 90001,
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
      if (stage === "payload") return { helper: owner, payload };
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
      } else if (args[0] === "0" && args[1] === "R") stage = "ready";
      else if (args[1] === "P") {
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

test("Darwin Git defaults reject substituted worker images and lost denial events", async () => {
  for (const [id, fault] of [
    ["git.fixed", "stale"],
    ["git.ordinary", "event-loss"],
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
