import assert from "node:assert/strict";
import test from "node:test";
import { posix, win32 } from "node:path";
import {
  CODEX_RELEASE_REFERENCE,
  nativePackageInput,
  observationDigest,
  nativePolicyTemplateDigest,
  materializeNativePolicy,
  NATIVE_EFFECT_CLASSES,
  nativePolicyContext,
} from "../index.js";
import {
  createProviderEffects,
  normalizeProviderPreparation,
  normalizeProviderSpec,
  providerInvocation,
  protectedProviderRecipes,
} from "./index.js";
import { linuxProviderCIContract } from "../linux/index.js";
import { darwinProviderCIContract } from "../darwin/index.js";
import { windowsProviderCIContract } from "../win32/index.js";
import { providerBytesDigest } from "./preparation.js";

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
  const paths = platform === "win32" ? win32 : posix,
    directory =
      platform === "win32" ? "C:\\Fixture\\report" : "/fixture/report",
    sourceDirectory =
      platform === "win32" ? "C:\\Fixture\\sealed" : "/fixture/sealed",
    events = [],
    files = new Map();
  const templates = ["read-only", "workspace-write", "trusted-command"].map(
    (profile) => {
      const template = {
        schemaVersion: 1,
        candidateSha,
        platform,
        sourceReviewSha256: hash,
        provisioningReviewSha256: hash,
        policy: { launch: { profile }, policy: { fixed: true } },
        bindings: [],
      };
      return {
        template,
        approval: {
          candidateSha,
          platform,
          authority: "operator-protected",
          manifestSha256: nativePolicyTemplateDigest(template),
        },
      };
    },
  );
  const closure = {
    schemaVersion: 2,
    policyTemplates: templates
      .map(({ approval }) => approval.manifestSha256)
      .sort(),
    manifestSha256: hash,
    observationSha256: hash,
    sourceReviewSha256: hash,
    providerBindings: { codex: hash, claude: hash },
  };
  const selectedSystem = {
    schemaVersion: 1,
    jobSha256: hash,
    closure,
    binding: {
      artifactId: "1",
      candidateSha,
      platform,
      tier: "system",
      authority: "ordinary",
      conclusion: "success",
      provenance: {
        repository: "example/native",
        workflow: "native-poc.yml",
        runId: "1",
        runAttempt: 1,
        jobId: "1",
      },
    },
  };
  const provenance = {
    repository: "example/native",
    workflow: "native-poc.yml",
    runId: "2",
    runAttempt: 1,
    jobId: "2",
  };
  const context = (executionId) =>
    nativePolicyContext(
      {
        candidateSha,
        platform,
        tier: "provider",
        provenance,
        closure,
        selectedSystem,
      },
      executionId,
    );
  const specifications = protectedProviderRecipes(platform).map(
    (recipe, index) => {
      const input = nativePackageInput(recipe.group + "-" + platform),
        reference = {
          url: "https://example.org/review",
          revision: null,
          sha256: hash,
        };
      return {
        candidateSha,
        nonce: (index + 1).toString(16).padStart(32, "0"),
        provider: recipe.group,
        platform,
        profile: recipe.profile,
        home: paths.join(sourceDirectory, "home"),
        cache: paths.join(sourceDirectory, "cache"),
        path: paths.join(sourceDirectory, "runtime"),
        endpoint: "http://127.0.0.1:41001",
        model: "fixture-model",
        review: {
          schemaVersion: 1,
          candidateSha,
          packageId: input.id,
          archiveBytes: input.bytes ?? 100,
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
            ].map((key) => [
              key,
              key === "source"
                ? recipe.group === "claude"
                  ? null
                  : {
                      url: CODEX_RELEASE_REFERENCE.sourceUrl,
                      revision: CODEX_RELEASE_REFERENCE.revision,
                      sha256: hash,
                    }
                : reference,
            ]),
          ),
          files: [
            {
              path: input.entrypoint,
              bytes: 100,
              sha256: hash,
              executable: true,
            },
          ],
        },
      };
    },
  );
  const cases = protectedProviderRecipes(platform).map((recipe, index) => ({
    id: recipe.id,
    specification: specifications[index],
    launch: { candidateSha, nonce: specifications[index].nonce },
    custody: { context: context(recipe.id), plan: { sha256: hash } },
    bindings: {
      relayPolicy: {
        provider: recipe.group,
        nonce: specifications[index].nonce,
        model: "fixture-model",
        requests: 32,
        outputTokens: 100,
        budgetMicros: 100,
        inputMicros: 1,
        outputMicros: 1,
        beta: [],
      },
    },
  }));
  const manifest = {
    schemaVersion: 2,
    candidateSha,
    platform,
    inputs: [
      {
        path: paths.join(sourceDirectory, "package"),
        sha256: hash,
        bytes: bytes.length,
      },
    ],
    helpers:
      platform === "linux"
        ? [{ name: "provider-gate", sha256: hash, sourceSha256: hash }]
        : [],
    source: {},
    release: {},
    execution: {
      schemaVersion: 2,
      policyTemplates: templates,
      cases: protectedProviderRecipes(platform).map((recipe) => ({
        ...recipe,
        reviewSha256: hash,
        templateSha256: templates.find(
          ({ template }) => template.policy.launch.profile === recipe.profile,
        ).approval.manifestSha256,
      })),
    },
    providerPreparation: {
      schemaVersion: 1,
      sourceDirectory,
      bootstrap: { context: context("provider-build"), plan: { sha256: hash } },
      cases,
    },
  };
  const input = {
    job: {
      candidateSha,
      platform,
      tier: "provider",
      provenance,
      closure,
      selectedSystem,
      reviews: {
        source: { manifestSha256: hash },
        release: { manifestSha256: hash },
        provider: { manifestSha256: observationDigest(manifest.execution) },
      },
    },
    manifest,
    templateReviews: templates.map(({ approval }) => approval),
    buildManifest: {
      candidateSha,
      platform,
      tools: [
        {
          name: "compiler",
          path: "/usr/bin/x86_64-linux-gnu-gcc-13",
          sha256: hash,
        },
      ],
    },
    directory,
    helpers: paths.join(directory, "platform-build"),
    providerHelpers: paths.join(directory, "provider-build"),
    preparation: null,
  };
  const contracts = {
    linux: linuxProviderCIContract,
    darwin: darwinProviderCIContract,
    win32: windowsProviderCIContract,
  };
  input.api = {
    [{
      linux: "linuxProviderCIContract",
      darwin: "darwinProviderCIContract",
      win32: "windowsProviderCIContract",
    }[platform]]: contracts[platform],
    [{
      linux: "observeLinuxCandidateClosure",
      darwin: "observeDarwinRelease",
      win32: "observeWindowsRelease",
    }[platform]]: async () => {
      events.push("release");
      const { sourceReviewSha256, ...reference } = closure;
      return {
        closure: {
          ...reference,
          observationSha256: "c".repeat(64),
          providerBindings: { codex: "d".repeat(64), claude: "e".repeat(64) },
        },
      };
    },
  };
  for (const member of manifest.inputs) files.set(member.path, bytes);
  for (const helper of manifest.helpers) {
    files.set(paths.join(sourceDirectory, helper.name + ".c"), bytes);
    files.set(paths.join(input.providerHelpers, helper.name), bytes);
  }
  files.set(input.buildManifest.tools[0].path, bytes);
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
