import assert from "node:assert/strict";
import test from "node:test";
import { EventEmitter } from "node:events";
import { readFile } from "node:fs/promises";
import { prerequisiteFixture } from "../prerequisite-fixture.js";
import { createProviderEffects as fixedProviderEffects } from "../provider-effects.mjs";
import { loadProviderEffects } from "./index.js";
import {
  observationDigest,
  materializeNativePolicy,
  NATIVE_EFFECT_CLASSES,
} from "../index.js";
import {
  createProviderEffects,
  normalizeProviderPreparation,
  normalizeProviderSpec,
  providerInvocation,
  protectedProviderRecipes,
} from "./index.js";
import { providerBytesDigest } from "./preparation.js";
import { providerPreparationFixture } from "./preparation.fixture.js";

const candidateSha = "a".repeat(40),
  bytes = Buffer.from("sealed fixture bytes"),
  hash = providerBytesDigest(bytes),
  retired = {
    status: "RETIRED",
    independent: true,
    emergencyCleanup: false,
    nativeEventSha256: hash,
  };

function wiring(platform = "linux") {
  const {
    input,
    manifest,
    templates,
    context,
    contracts,
    paths,
    files,
    events,
    sourceDirectory,
  } = providerPreparationFixture(platform);
  const directory = input.directory;
  const options = {
    env: {
      CI: "true",
      GITHUB_ACTIONS: "true",
      ImageOS: { linux: "ubuntu24", darwin: "macos15", win32: "win25" }[
        platform
      ],
      NATIVE_CODEX_MODEL_CREDENTIAL: "fixture-secret",
    },
    verifyDirectory: async ({ directory }) => ({
      independent: true,
      held: true,
      protectedParents: true,
      exclusiveWriter: true,
      protectedAuthority: true,
      directory,
      nativeEventSha256: hash,
    }),
    writeProtected: async ({ file, bytes }) => {
      assert.ok(!files.has(file), file);
      files.set(file, bytes);
      events.push("write:" + paths.basename(file));
      return {
        independent: true,
        file,
        sha256: providerBytesDigest(bytes),
        exclusive: true,
        immutable: true,
        writerClosed: true,
        protectedParents: true,
        protectedAuthority: true,
        identitySha256: hash,
        nativeEventSha256: hash,
      };
    },
    readProtected: async ({ file }) => {
      events.push("read:" + file);
      const bytes = files.get(file);
      return {
        bytes,
        independent: true,
        held: true,
        protectedParents: true,
        protectedAuthority: true,
        unchanged: true,
        file,
        sha256: bytes && providerBytesDigest(bytes),
        identitySha256: hash,
        nativeEventSha256: hash,
        immutable: true,
      };
    },
    listReceipts: async () => ({
      independent: true,
      held: true,
      protectedAuthority: true,
      nativeEventSha256: hash,
      names: [...files.keys()]
        .filter((file) => paths.dirname(file) === directory)
        .map((file) => paths.basename(file)),
    }),
    createReader: (declaration) => ({
      start: async () => {
        events.push("start:" + declaration.context.executionId);
        return {
          independent: true,
          context: declaration.context,
          planSha256: hash,
          nativeEventSha256: hash,
        };
      },
      beginCleanup: async () => events.push("cleanup"),
      authorizeRestoration: async () => events.push("authorize"),
      close: async () => {
        events.push("close:" + declaration.context.executionId);
        return { ...retired, closed: true, taskRemoved: true };
      },
    }),
    provisionBuild: async () => events.push("build-provision"),
    runCommand: async (request) => {
      events.push("compile");
      return {
        independent: true,
        requestSha256: observationDigest(request),
        toolSha256: hash,
        exitCode: 0,
        signal: null,
        timedOut: false,
        nativeEventSha256: hash,
        settlement: retired,
      };
    },
    verifyBuild: async ({ request, commands }) => ({
      ...retired,
      requestSha256: observationDigest(request),
      commandsSha256: observationDigest(commands),
      noLiveMembers: true,
    }),
    verifyPrepared: async ({ request }) => {
      events.push("verify-prepared");
      return {
        ...retired,
        requestSha256: observationDigest(request),
        noLiveMembers: true,
        unchanged: true,
      };
    },
    provision: async (declared) => {
      events.push("provision");
      return { specification: declared.specification, launch: declared.launch };
    },
    bindReaders: async () => ({
      release: {},
      inspect: async () => ({}),
      observe: async () => ({}),
    }),
    launchEffects: async (current) => ({
      persist: async () => {},
      readProvisioning: async () => ({
        schemaVersion: 1,
        context: current.binding.context,
        authoritySha256: hash,
        bindings: [],
        held: true,
        independent: true,
        verifierSha256: hash,
        nativeEventSha256: hash,
      }),
      readPolicy: async () => {
        const expected = materializeNativePolicy(
          current.binding.template,
          current.binding.approval,
          current.provisioning,
          current.binding.context,
        );
        return {
          schemaVersion: 1,
          context: current.binding.context,
          templateSha256: expected.templateSha256,
          provisioningSha256: expected.provisioningSha256,
          requestSha256: hash,
          policySha256: expected.expectedPolicySha256,
          policy: expected.policy,
          held: true,
          complete: true,
          independent: true,
          verifierSha256: hash,
          nativeEventSha256: hash,
        };
      },
    }),
    transportEffects: async (_current, { services }) => {
      assert.equal(typeof services.relay, "function");
      assert.equal(typeof services.bridge, "function");
      return {
        review: async () => ({}),
        admitTransport: async (role, context) => {
          events.push("admit:" + role);
          return {
            role,
            ...retired,
            admitted: true,
            receiptVerified: true,
            candidateSha,
            nonce: context.spec.nonce,
            configurationSha256: context.configurationSha256,
            nativeSha256: hash,
          };
        },
        verifyRelayCustody: async () => ({}),
        verifyTransport: async () => ({}),
        controls: async () => ({}),
        closeTransport: async () => {},
        retire: async () => ({}),
        verifySettlement: async () => ({}),
        modelReceipts: async () => ({}),
      };
    },
    retire: async (current) => {
      events.push("payload-retire");
      return {
        ...retired,
        candidateSha,
        nonce: current.specification.nonce,
        noLiveMembers: true,
      };
    },
    releaseAudit: async () => {
      events.push("audit-release");
      return { ...retired, drained: true };
    },
    restore: async () => {
      events.push("restore");
      return {
        status: "RESTORED",
        independent: true,
        unchangedInstalled: true,
        nativeEventSha256: hash,
      };
    },
    recover: async ({ request, records }) => {
      events.push("recover");
      return {
        ...retired,
        requestSha256: observationDigest(request),
        tasksRemoved: true,
        recordsSha256: observationDigest(records),
        noLiveMembers: true,
        ownedRestoration: true,
        effects: Object.fromEntries(
          NATIVE_EFFECT_CLASSES.map((id) => [id, retired]),
        ),
      };
    },
  };
  const request = {
    candidateSha,
    platform,
    reviewSha256: observationDigest(manifest),
    helpers: manifest.helpers,
    tools: input.buildManifest.tools,
    output: input.providerHelpers,
    deadlineMs: 120000,
    commands: contracts[platform]({
      tools: input.buildManifest.tools,
      output: input.providerHelpers,
      sourceDirectory,
    }).commands,
  };
  const seedBuild = async () => {
    const receipt = await createProviderEffects(input, options).prepareBuild(
      request,
    );
    input.preparation = {
      request,
      requestSha256: observationDigest(request),
      receiptSha256: observationDigest(receipt),
      status: "PASS",
    };
    events.length = 0;
  };
  const binding = (recipe) => {
    const { template, approval } = templates.find(
      ({ template }) => template.policy.launch.profile === recipe.profile,
    );
    return { template, approval, context: context(recipe.id) };
  };
  return { input, options, events, files, request, seedBuild, binding, paths };
}
const execution = (id) => ({
  id,
  effects: Object.fromEntries(
    NATIVE_EFFECT_CLASSES.map((effect) => [
      effect,
      { admission: effect === "providers" ? "not-started" : "possible" },
    ]),
  ),
});

async function rawLinuxPreparation() {
  const f = providerPreparationFixture(),
    raw = await prerequisiteFixture(),
    fs = raw.edges.fs;
  delete f.input.api;
  raw.add(f.input.directory);
  for (const [file, bytes] of f.files)
    if (!file.startsWith(f.input.providerHelpers + "/")) raw.add(file, bytes);
  raw.nodes.get(f.input.buildManifest.tools[0].path).mode = 0o755n;
  const bootId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    identity = { bootId, startTicks: "110" },
    verifications = [];
  let fault;
  const verify = async (file, args) => {
    assert.equal(file, process.execPath);
    assert.equal(args[1], "--verify");
    assert.equal(providerBytesDigest(raw.nodes.get(args[2]).content), args[3]);
    verifications.push(args[2]);
    return {
      stdout: JSON.stringify({
        status: fault === "retirement" ? "RETAINED" : "RETIRED",
        independent: fault !== "retirement",
        emergencyCleanup: false,
      }),
    };
  };
  const start = (_file, args, settings) => {
    assert.deepEqual(settings.execArgv, []);
    assert.equal(settings.env.NATIVE_CODEX_MODEL_CREDENTIAL, undefined);
    const worker = new EventEmitter();
    worker.pid = 700;
    const input = JSON.parse(raw.nodes.get(args[1]).content),
      command = input.command,
      commandId = observationDigest(command);
    assert.equal(
      input.providerSource.path,
      f.input.manifest.providerPreparation.sourceDirectory + "/provider-gate.c",
    );
    assert.equal(input.providerSource.sha256, hash);
    const init = {
        pid: 701,
        identity,
        namespaceId: "pid:[2]",
        nspid: [701, 1],
      },
      receipt = {
        schemaVersion: 1,
        candidateSha,
        caseId: "argv",
        nonce: bootId,
        policyDigest: commandId,
        executableDigest: hash,
        isolatedNamespace: true,
        hostSession: false,
        parentNamespaceId: "pid:[1]",
        init,
        launcher: { pid: 702, identity: { bootId, startTicks: "100" } },
        controller: { pid: 700, identity: { bootId, startTicks: "90" } },
        admission: {
          processIdentity: identity,
          namespaceId: init.namespaceId,
          launchCutoff: identity,
          ancestryBaseline: [{ bootId, pid: 1, startTicks: "1" }],
          controlGroup: hash,
        },
      };
    const file = input.directory + "/command-0.json",
      bytes = Buffer.from(JSON.stringify(receipt));
    raw.add(file, bytes, 0o400);
    raw.add(
      f.input.providerHelpers + "/provider-gate",
      Buffer.from("sealed fixture bytes"),
      0o555,
    );
    raw.events.push("compiler-release");
    queueMicrotask(() => {
      worker.emit("message", {
        status: "PASS",
        receipts: [{ file, sha256: providerBytesDigest(bytes) }],
        observation: { exitCode: 0, signal: null, timedOut: false },
      });
      worker.emit("close", 0);
    });
    return worker;
  };
  const options = {
    env: {
      CI: "true",
      GITHUB_ACTIONS: "true",
      ImageOS: "ubuntu24",
      RUNNER_TEMP: "/fixture",
      NATIVE_CODEX_MODEL_CREDENTIAL: "unused-secret",
    },
    fs,
    ownerUid: 0,
    processTransport: async (pid) => ({
      pid,
      identity: { bootId, startTicks: "90" },
    }),
    commandTransport: {
      fs: {
        mkdir: fs.mkdir,
        writeFile: async (file, bytes, settings) => {
          assert.equal(settings.flag, "wx");
          raw.add(file, bytes, settings.mode);
        },
      },
      start,
      receiptOptions: { fs, ownerUid: () => 0 },
      verifierOptions: { executeFile: verify },
    },
    verifierTransport: verify,
  };
  const request = {
    candidateSha,
    platform: "linux",
    reviewSha256: observationDigest(f.input.manifest),
    helpers: f.input.manifest.helpers,
    tools: f.input.buildManifest.tools,
    output: f.input.providerHelpers,
    deadlineMs: 120000,
    commands: f.contracts.linux({
      tools: f.input.buildManifest.tools,
      output: f.input.providerHelpers,
      sourceDirectory: f.input.manifest.providerPreparation.sourceDirectory,
    }).commands,
  };
  return {
    ...f,
    raw,
    options,
    request,
    verifications,
    fault: (value) => {
      fault = value;
    },
  };
}

test("fixed provider entry compiles Linux helpers through protected file and command owners and verifies without recompiling", async (t) => {
  const f = await rawLinuxPreparation();
  t.after(() => f.raw.teardown());
  const owner = fixedProviderEffects(f.input, f.options);
  assert.equal(f.raw.events.includes("compiler-release"), false);
  const receipt = await owner.prepareBuild(f.request);
  f.input.preparation = {
    status: "PASS",
    request: f.request,
    requestSha256: observationDigest(f.request),
    receiptSha256: observationDigest(receipt),
    filesSettlement: await owner.settleBuild(),
  };
  assert.equal(f.raw.handles.size, 0);
  assert.ok(
    f.raw.events.findIndex((event) =>
      /create:.*provider-build-.*-command-0-intent/u.test(event),
    ) < f.raw.events.indexOf("compiler-release"),
  );
  assert.equal(
    (await fixedProviderEffects(f.input, f.options).verifyBuild()).status,
    "RETIRED",
  );
  assert.equal(
    f.raw.events.filter((event) => event === "compiler-release").length,
    1,
  );
  assert.ok(f.verifications.length >= 3);
  assert.equal(f.raw.handles.size, 0);
});

test("fixed Linux helper admission rejects changed or writable source/tool/output and missing fresh retirement or selected-system binding", async (t) => {
  for (const fault of [
    "source",
    "tool",
    "output",
    "source-write",
    "tool-write",
    "output-write",
    "retirement",
    "selected-system",
  ]) {
    const f = await rawLinuxPreparation();
    t.after(() => f.raw.teardown());
    const owner = fixedProviderEffects(f.input, f.options),
      receipt = await owner.prepareBuild(f.request);
    f.input.preparation = {
      status: "PASS",
      request: f.request,
      requestSha256: observationDigest(f.request),
      receiptSha256: observationDigest(receipt),
      filesSettlement: await owner.settleBuild(),
    };
    if (fault === "retirement") f.fault(fault);
    else if (fault === "selected-system")
      f.input.job.selectedSystem.jobSha256 = "f".repeat(64);
    else {
      const file = fault.startsWith("source")
        ? f.input.manifest.providerPreparation.sourceDirectory +
          "/provider-gate.c"
        : fault.startsWith("tool")
          ? f.request.tools[0].path
          : f.input.providerHelpers + "/provider-gate";
      const entry = f.raw.nodes.get(file);
      if (fault.endsWith("-write"))
        entry.mode = fault === "tool-write" ? 0o775n : 0o755n;
      else entry.content = Buffer.from("substituted bytes");
    }
    if (fault === "selected-system")
      assert.throws(() => fixedProviderEffects(f.input, f.options));
    else
      await assert.rejects(
        fixedProviderEffects(f.input, f.options).verifyBuild(),
        undefined,
        fault,
      );
    assert.equal(
      f.raw.events.filter((event) => event === "compiler-release").length,
      1,
    );
  }
});

test("fixed provider entry loader requires exact candidate bytes and their unique source citation", async () => {
  const bytes = await readFile(
      new URL("../provider-effects.mjs", import.meta.url),
    ),
    sha256 = providerBytesDigest(bytes),
    manifest = {
      schemaVersion: 2,
      capabilitySha256: sha256,
      source: {
        citations: [
          {
            kind: "reached-code",
            member: "candidate/ci/native/provider-effects.mjs",
            sha256,
          },
        ],
      },
    },
    bundle = { manifest, capabilityBytes: bytes, read: async () => bytes };
  assert.equal(
    typeof (await loadProviderEffects(bundle)).createProviderEffects,
    "function",
  );
  await assert.rejects(
    loadProviderEffects({
      ...bundle,
      capabilityBytes: Buffer.from("substitute"),
    }),
  );
  await assert.rejects(
    loadProviderEffects({
      ...bundle,
      manifest: { ...manifest, source: { citations: [] } },
    }),
  );
  await assert.rejects(
    loadProviderEffects({
      ...bundle,
      manifest: {
        ...manifest,
        source: {
          citations: [
            ...manifest.source.citations,
            { ...manifest.source.citations[0], sha256: "f".repeat(64) },
          ],
        },
      },
    }),
  );
});

test("fixed Linux helper recovery rejoins command ownership without final preparation or outputs and retains missing proof", async (t) => {
  for (const missing of [false, "command", "orphan"]) {
    const f = await rawLinuxPreparation();
    t.after(() => f.raw.teardown());
    const owner = fixedProviderEffects(f.input, f.options);
    await owner.prepareBuild(f.request);
    await owner.settleBuild();
    const id = observationDigest(f.request),
      command = [...f.raw.nodes.keys()].find((file) =>
        file.endsWith("/command-0.json"),
      );
    f.raw.nodes.delete(f.input.providerHelpers + "/provider-gate");
    f.raw.nodes.delete(f.input.directory + `/provider-build-${id}-result.json`);
    if (missing === "command") f.raw.nodes.delete(command);
    if (missing === "orphan")
      f.raw.add(
        f.input.directory + "/provider-build-unjoined-intent.json",
        Buffer.from(JSON.stringify({ status: "POSSIBLE" })),
        0o400,
      );
    const preparation = { status: "POSSIBLE" },
      request = {
        candidateSha,
        platform: "linux",
        jobSha256: observationDigest(f.input.job),
        preparationSha256: observationDigest(preparation),
        deadlineMs: 120000,
      };
    const result = await fixedProviderEffects(f.input, f.options).recover({
      request,
      job: f.input.job,
      preparation,
      signal: new AbortController().signal,
    });
    assert.equal(result.status, missing ? "RETAINED" : "RETIRED");
    assert.equal(
      f.raw.events.filter((event) => event === "compiler-release").length,
      1,
    );
  }
});

test("CI provider factories are effect-free, require the selected system join and retain complete fixed recipes", () => {
  for (const platform of ["linux", "darwin", "win32"]) {
    const f = wiring(platform);
    createProviderEffects(f.input, f.options);
    assert.deepEqual(f.events, []);
    const unapproved = { ...f.input, templateReviews: [] };
    assert.throws(() => createProviderEffects(unapproved, f.options));
    const bad = structuredClone(f.input.manifest.providerPreparation);
    bad.cases.pop();
    assert.throws(() => normalizeProviderPreparation(bad, f.input.manifest));
    const reused = structuredClone(f.input.manifest.providerPreparation);
    reused.cases[1].specification.nonce = reused.cases[0].specification.nonce;
    assert.throws(() => normalizeProviderPreparation(reused, f.input.manifest));
    delete f.input.job.selectedSystem;
    assert.throws(() => createProviderEffects(f.input, f.options));
  }
});
test("provider helper preparation persists sealed vectors before native effects and verification never compiles", async () => {
  for (const platform of ["linux", "darwin", "win32"]) {
    const f = wiring(platform);
    await f.seedBuild();
    await createProviderEffects(f.input, f.options).verifyBuild();
    assert.ok(f.events.includes("verify-prepared"));
    assert.ok(!f.events.includes("compile"));
    f.input.preparation.receiptSha256 = "0".repeat(64);
    await assert.rejects(
      createProviderEffects(f.input, f.options).verifyBuild(),
    );
  }
  const f = wiring(),
    owner = createProviderEffects(f.input, f.options);
  await owner.prepareBuild(f.request);
  const intent = f.events.findIndex((event) =>
    /^write:provider-build-.*-intent.json$/u.test(event),
  );
  assert.ok(intent >= 0 && intent < f.events.indexOf("build-provision"));
  assert.ok(
    f.request.commands[0].arguments.includes("/fixture/sealed/provider-gate.c"),
  );
  assert.ok(
    f.events.indexOf("compile") < f.events.indexOf("close:provider-build"),
  );
});
test("every provider profile/case uses protected intent, concrete policy before relay admission and ordered settlement", async () => {
  for (const platform of ["linux", "darwin", "win32"]) {
    const f = wiring(platform);
    await f.seedBuild();
    const owner = createProviderEffects(f.input, f.options);
    for (const fixed of protectedProviderRecipes(platform)) {
      const binding = f.binding(fixed),
        recipe = {
          ...fixed,
          reviewSha256: hash,
          templateSha256: binding.approval.manifestSha256,
        },
        work = new AbortController();
      const prepared = await owner.prepare(recipe, {
        signal: work.signal,
        policyBinding: binding,
      });
      assert.equal(
        prepared.launchOptions.env.NATIVE_CODEX_MODEL_CREDENTIAL,
        undefined,
      );
      assert.equal(prepared.approvedSha256, undefined);
      const spec = normalizeProviderSpec(prepared.specification),
        invocation = providerInvocation(spec),
        context = {
          spec,
          invocation,
          policy: prepared.relayPolicy,
          configurationSha256: observationDigest({
            specificationSha256: invocation.specificationSha256,
            policy: prepared.relayPolicy,
          }),
        };
      await assert.rejects(prepared.effects.admitTransport("relay", context));
      await prepared.launchEffects.readProvisioning();
      await prepared.launchEffects.readPolicy();
      await assert.rejects(
        prepared.effects.admitTransport("relay", {
          ...context,
          configurationSha256: "0".repeat(64),
        }),
      );
      await prepared.effects.admitTransport("relay", context);
      await prepared.launchEffects.readPolicy();
      work.abort();
      const result = await owner.settle(recipe, prepared, {
        signal: new AbortController().signal,
        execution: execution(recipe.id),
      });
      assert.equal(result.providers, null);
      assert.ok(
        Object.values(result)
          .filter(Boolean)
          .every((value) => value.settlement.status === "RETIRED"),
      );
    }
    assert.ok(
      f.events.findIndex((event) => event.startsWith("write:provider-case-")) <
        f.events.indexOf("provision"),
    );
    assert.ok(
      f.events.indexOf("payload-retire") < f.events.indexOf("audit-release"),
    );
    assert.ok(f.events.indexOf("audit-release") < f.events.indexOf("restore"));
    const fresh = [...f.files.values()]
      .map((value) => {
        try {
          return JSON.parse(value);
        } catch {
          return null;
        }
      })
      .find((value) => value?.phase === "release-observed");
    assert.equal(fresh.closure.observationSha256, "c".repeat(64));
    assert.equal(fresh.closure.providerBindings.codex, "d".repeat(64));
  }
});
test("malformed installed policy and uncertain retirement withhold relay authority and restoration", async () => {
  const f = wiring();
  await f.seedBuild();
  const original = f.options.launchEffects;
  f.options.launchEffects = async (current) => {
    const value = await original(current),
      read = value.readPolicy;
    value.readPolicy = async () => ({ ...(await read()), complete: false });
    return value;
  };
  const owner = createProviderEffects(f.input, f.options),
    fixed = protectedProviderRecipes("linux")[0],
    binding = f.binding(fixed),
    recipe = {
      ...fixed,
      reviewSha256: hash,
      templateSha256: binding.approval.manifestSha256,
    },
    work = new AbortController(),
    prepared = await owner.prepare(recipe, {
      signal: work.signal,
      policyBinding: binding,
    });
  await prepared.launchEffects.readProvisioning();
  await assert.rejects(prepared.launchEffects.readPolicy());
  const spec = normalizeProviderSpec(prepared.specification);
  await assert.rejects(
    prepared.effects.admitTransport("relay", {
      spec,
      invocation: providerInvocation(spec),
      configurationSha256: hash,
    }),
  );
  work.abort();
  f.options.retire = async () => ({ ...retired, noLiveMembers: false });
  const result = await owner.settle(recipe, prepared, {
    signal: new AbortController().signal,
    execution: execution(recipe.id),
  });
  assert.equal(result.policy.settlement.status, "RETAINED");
  assert.ok(!f.events.includes("restore"));
});
test("expired provider admission cannot continue after protected persistence", async () => {
  for (const scope of ["recipe", "transport"]) {
    const f = wiring();
    await f.seedBuild();
    const work = new AbortController(),
      transport = new AbortController(),
      fixed = protectedProviderRecipes("linux")[0],
      binding = f.binding(fixed),
      recipe = {
        ...fixed,
        reviewSha256: hash,
        templateSha256: binding.approval.manifestSha256,
      },
      prepared = await createProviderEffects(f.input, f.options).prepare(
        recipe,
        {
          signal: work.signal,
          policyBinding: binding,
        },
      );
    await prepared.launchEffects.readProvisioning();
    await prepared.launchEffects.readPolicy();
    const write = f.options.writeProtected;
    f.options.writeProtected = async (record) => {
      const result = await write(record);
      if (JSON.parse(record.bytes).phase === "relay-possible")
        (scope === "recipe" ? work : transport).abort();
      return result;
    };
    const spec = normalizeProviderSpec(prepared.specification),
      invocation = providerInvocation(spec);
    await assert.rejects(
      prepared.effects.admitTransport(
        "relay",
        {
          spec,
          invocation,
          policy: prepared.relayPolicy,
          configurationSha256: observationDigest({
            specificationSha256: invocation.specificationSha256,
            policy: prepared.relayPolicy,
          }),
        },
        { signal: transport.signal },
      ),
    );
    assert.ok(!f.events.includes("admit:relay"), scope);
  }
});
test("expired provider cleanup retains authority and custody after late native results", async () => {
  for (const [phase, next] of [
    ["retire", "audit-release"],
    ["releaseAudit", "restore"],
    ["restore", "close:"],
  ]) {
    const f = wiring();
    await f.seedBuild();
    const owner = createProviderEffects(f.input, f.options),
      fixed = protectedProviderRecipes("linux")[0],
      binding = f.binding(fixed),
      recipe = {
        ...fixed,
        reviewSha256: hash,
        templateSha256: binding.approval.manifestSha256,
      },
      work = new AbortController(),
      cleanup = new AbortController(),
      prepared = await owner.prepare(recipe, {
        signal: work.signal,
        policyBinding: binding,
      }),
      original = f.options[phase];
    f.options[phase] = async (...args) => {
      const result = await original(...args);
      cleanup.abort();
      return result;
    };
    work.abort();
    const result = await owner.settle(recipe, prepared, {
      signal: cleanup.signal,
      execution: execution(recipe.id),
    });
    assert.equal(result.policy.settlement.status, "RETAINED", phase);
    assert.ok(!f.events.some((event) => event.startsWith(next)), phase);
  }
});
test("fresh provider recovery uses complete protected partial ledgers without prepared helper images", async () => {
  for (const platform of ["linux", "darwin", "win32"]) {
    const f = wiring(platform);
    const file = f.paths.join(
      f.input.directory,
      "provider-build-partial-intent.json",
    );
    f.files.set(file, Buffer.from(JSON.stringify({ status: "POSSIBLE" })));
    for (const helper of f.input.manifest.helpers)
      f.files.delete(f.paths.join(f.input.providerHelpers, helper.name));
    const preparation = { status: "POSSIBLE" },
      request = {
        candidateSha,
        platform,
        deadlineMs: 120000,
        jobSha256: observationDigest(f.input.job),
        preparationSha256: observationDigest(preparation),
      };
    const result = await createProviderEffects(f.input, f.options).recover({
      request,
      job: f.input.job,
      preparation,
      signal: new AbortController().signal,
    });
    assert.equal(result.status, "RETIRED");
    assert.ok(f.events.includes("recover"));
    assert.ok(!f.events.includes("compile"));
    assert.ok(!f.events.includes("verify-prepared"));
    f.options.recover = async () => ({ ...retired, noLiveMembers: false });
    const retained = await createProviderEffects(f.input, f.options).recover({
      request,
      job: f.input.job,
      preparation,
      signal: new AbortController().signal,
    });
    assert.equal(retained.status, "RETAINED");
  }
});
test("provider recovery rejects native evidence for a different request", async () => {
  const f = wiring(),
    recover = f.options.recover,
    preparation = { status: "POSSIBLE" },
    request = {
      candidateSha,
      platform: "linux",
      deadlineMs: 120000,
      jobSha256: observationDigest(f.input.job),
      preparationSha256: observationDigest(preparation),
    };
  f.options.recover = async (...args) => ({
    ...(await recover(...args)),
    requestSha256: "0".repeat(64),
  });
  const result = await createProviderEffects(f.input, f.options).recover({
    request,
    job: f.input.job,
    preparation,
    signal: new AbortController().signal,
  });
  assert.equal(result.status, "RETAINED");
  assert.ok(!f.events.includes("close:provider-build"));
});
