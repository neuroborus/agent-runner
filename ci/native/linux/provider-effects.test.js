import assert from "node:assert/strict";
import test from "node:test";
import { PassThrough, Readable } from "node:stream";
import { EventEmitter } from "node:events";
import { createProviderEffects } from "../provider-effects.mjs";
import { linuxProviderFixedFixture } from "./provider-fixed.fixture.js";
import {
  createLinuxProviderEffects,
  assertLinuxObserverEvent,
} from "./index.js";
import { linuxProviderFrames } from "./provider-channel.js";
import {
  linuxProviderFixture,
  linuxProviderProcessFixture,
  providerFixtureDigest,
} from "./provider-effects.fixture.js";
import { linuxProviderArguments } from "./index.js";
import { linuxProviderObjectDigest } from "./provider-observation.js";
import {
  linuxFileIdentity,
  createLinuxProviderKernel,
} from "./provider-kernel.js";
import { createLinuxProviderControls } from "./provider-controls.js";
import {
  providerInvocation,
  runCodexMediation,
  runClaudeMediationCase,
  protectedProviderRecipes,
} from "../providers/index.js";
import { linuxProviderOwner } from "./index.js";
import {
  nativePolicyContext,
  observationDigest,
  NATIVE_EFFECT_CLASSES,
} from "../index.js";

async function executeFixed(f, prepared) {
  const owner = linuxProviderOwner(
    prepared.launch,
    f.binding,
    {
      ...prepared.launchEffects,
      async recordPolicy(receipt, sha256) {
        assert.equal(receipt.expectedPolicySha256, sha256);
        await prepared.effects.persist({
          type: "policy-admitted",
          receipt,
          sha256,
        });
      },
    },
    { ...prepared.launchOptions, spawn: f.options.spawn },
  );
  return prepared.specification.provider === "codex"
    ? runCodexMediation(
        prepared.specification,
        prepared.cases,
        prepared.relayPolicy,
        owner,
        prepared.effects,
      )
    : runClaudeMediationCase(
        prepared.specification,
        prepared.cases,
        f.recipe.id.split(".").at(-1),
        prepared.relayPolicy,
        owner,
        prepared.effects,
      );
}

const caseExecution = (id) => ({
  id,
  effects: Object.fromEntries(
    NATIVE_EFFECT_CLASSES.map((key) => [key, { admission: "possible" }]),
  ),
});

test("fixed Linux entry executes complete Codex and Claude cases through default owners", async (t) => {
  for (const recipe of protectedProviderRecipes("linux")) {
    const f = await linuxProviderFixedFixture(
      recipe.group,
      recipe.profile,
      recipe.id,
    );
    t.after(() => f.close());
    const prepared = await f.prepare(),
      result = await executeFixed(f, prepared);
    assert.equal(
      result.status,
      recipe.group === "codex"
        ? "MEDIATION_OBSERVED"
        : "CASE_MEDIATION_OBSERVED",
      JSON.stringify(result),
    );
    f.controller.abort();
    const settlement = await f.owner.settle(f.recipe, prepared, {
      execution: caseExecution(recipe.id),
    });
    assert.ok(
      Object.values(settlement).every(
        (proof) => proof.settlement.status === "RETIRED",
      ),
    );
    assert.equal(
      [...f.processes.keys()].some(
        (pid) => ![1, 42, process.pid].includes(pid),
      ),
      false,
    );
  }
});

test("fixed Linux entry excludes substituted transport and independently settles interrupted provider work", async (t) => {
  for (const provider of ["codex", "claude"])
    for (const fault of ["transport", "interruption"]) {
      const id =
          provider === "codex" ? "codex.read-only" : "claude.read-only.command",
        f = await linuxProviderFixedFixture(provider, "read-only", id);
      t.after(() => f.close());
      const prepared = await f.prepare();
      if (fault === "transport") f.blockTransport();
      else f.interrupt();
      const result = await executeFixed(f, prepared);
      assert.equal(result.status, "FAIL");
      assert.notEqual(result.nativeObservation?.status, "OBSERVED");
      f.controller.abort();
      const settlement = await f.owner.settle(f.recipe, prepared, {
        execution: caseExecution(id),
      });
      assert.ok(
        Object.values(settlement).every(
          (proof) =>
            proof.settlement.status ===
            (fault === "transport" ? "RETAINED" : "RETIRED"),
        ),
      );
      assert.equal(
        [...f.processes.keys()].some(
          (pid) => ![1, 42, process.pid].includes(pid),
        ),
        false,
      );
    }
});

test("fixed provider entry construction opens no file, process, socket or credential", async (t) => {
  const f = await linuxProviderFixture();
  t.after(() => f.raw.teardown());
  const fail = () => {
    throw new Error("Construction performed an effect");
  };
  const env = { ...f.options.env };
  for (const key of [
    "NATIVE_CODEX_MODEL_CREDENTIAL",
    "NATIVE_CLAUDE_MODEL_CREDENTIAL",
  ])
    Object.defineProperty(env, key, { get: fail });
  const owner = createProviderEffects(f.input, {
    env,
    fs: new Proxy({}, { get: fail }),
    spawn: fail,
    httpServer: fail,
    unixServer: fail,
  });
  assert.equal(typeof owner.prepare, "function");
  assert.equal(f.raw.events.length, 0);
});

test("Linux owner provisions every fixed Codex/Claude profile from held bytes and settles before a prepared launch exists", async (t) => {
  const f = await linuxProviderFixture();
  t.after(() => f.raw.teardown());
  const owner = createLinuxProviderEffects(f.input, f.options);
  const profiles = new Set(),
    families = new Set();
  for (const declared of f.input.manifest.providerPreparation.cases) {
    const approval = f.templates.find(
        ({ template }) =>
          template.policy.launch.profile === declared.specification.profile,
      ),
      binding = {
        ...approval,
        context: nativePolicyContext(f.input.job, declared.id),
      },
      prepared = await owner.provision(declared, binding, {
        signal: new AbortController().signal,
        persist: f.persist,
      });
    assert.deepEqual(prepared.launch, declared.launch);
    assert.equal(prepared.specification.nonce, declared.specification.nonce);
    profiles.add(prepared.specification.profile);
    families.add(declared.id);
    const current = { recipe: { id: declared.id }, binding };
    const payload = await owner.retire(current, {
      signal: new AbortController().signal,
    });
    assert.equal(payload.noLiveMembers, true);
    assert.equal((await owner.releaseAudit(current, payload)).drained, true);
    assert.equal((await owner.restore(current)).status, "RESTORED");
    assert.equal(f.raw.handles.size, 0);
  }
  assert.deepEqual([...profiles].sort(), [
    "read-only",
    "trusted-command",
    "workspace-write",
  ]);
  assert.equal(families.size, 60);
  assert.ok(
    f.raw.events.indexOf("intent:linux-provider-provisioning-possible") <
      f.raw.events.findIndex((event) => event.startsWith("mkdir:")),
  );
  assert.ok(
    f.raw.events.indexOf("intent:linux-provider-file-possible") <
      f.raw.events.findIndex((event) => event.startsWith("write:")),
  );
});

test("changed assets, private aliases and missing selector inventories block Linux cases without starting a provider", async (t) => {
  for (const fault of ["source", "alias", "controls"]) {
    const f = await linuxProviderFixture();
    t.after(() => f.raw.teardown());
    f.input.manifest.release.components = [];
    const declared = f.input.manifest.providerPreparation.cases[0],
      binding = {
        ...f.templates[0],
        context: nativePolicyContext(f.input.job, declared.id),
      };
    if (fault === "source")
      f.raw.nodes.get("/usr/bin/strace").content = Buffer.from(
        "substituted trace image",
      );
    if (fault === "alias")
      declared.launch.storage.home = declared.launch.storage.workspace;
    const owner = createLinuxProviderEffects(f.input, {
      ...f.options,
      spawn() {
        assert.fail("Invalid input started a provider");
      },
    });
    if (fault === "controls") {
      await owner.provision(declared, binding, { persist: f.persist });
      await assert.rejects(
        owner.bindReaders({ recipe: { id: declared.id }, binding }, {}),
      );
    } else
      await assert.rejects(
        owner.provision(declared, binding, { persist: f.persist }),
      );
  }
});

test("partial Linux provisioning reconstructs without outputs and missing worker birth retains exclusion", async (t) => {
  const f = await linuxProviderFixture();
  t.after(() => f.raw.teardown());
  const declared = f.input.manifest.providerPreparation.cases[0],
    binding = {
      ...f.templates[0],
      context: nativePolicyContext(f.input.job, declared.id),
    },
    owner = createLinuxProviderEffects(f.input, f.options),
    records = [
      {
        name: `provider-case-${declared.id}-0.json`,
        record: { phase: "provisioning-possible", context: binding.context },
      },
    ];
  f.raw.nodes.delete(declared.bindings.casesFile);
  await assert.rejects(
    owner.provision(declared, binding, {
      persist: async (record) =>
        records.push({
          name: `provider-case-${declared.id}-${records.length}.json`,
          record: { context: binding.context, phase: "native", record },
        }),
    }),
    { code: "ENOENT" },
  );
  const proof = await owner.recoverCases(records, { persist: f.persist });
  assert.equal(proof.status, "RETIRED");
  assert.equal(proof.recordsSha256, observationDigest(records));
  assert.equal(f.raw.handles.size, 0);
  records.push({
    name: `provider-case-${declared.id}-late.json`,
    record: {
      context: binding.context,
      record: { phase: "admission-possible" },
    },
  });
  await assert.rejects(
    createLinuxProviderEffects(f.input, f.options).recoverCases(records, {
      persist: f.persist,
    }),
  );
});

test("native frame loss cannot be repaired by a subsequent matching acknowledgement", async () => {
  const pipe = new PassThrough(),
    frames = linuxProviderFrames(pipe, { maximum: 16 });
  pipe.write('{"id":1}\n');
  assert.deepEqual(await frames.take(), { id: 1 });
  pipe.write('{"id":2}\n');
  assert.throws(() => frames.assertHealthy());
  pipe.end();
  const partial = new PassThrough(),
    broken = linuxProviderFrames(partial);
  partial.end('{"id":');
  await new Promise((resolve) => partial.once("end", resolve));
  assert.throws(() => broken.take());
});

test("Linux descriptor cleanup retries independent closure after an unverified close acknowledgement", async (t) => {
  const f = await linuxProviderFixture();
  t.after(() => f.raw.teardown());
  let release = false;
  const fs = {
    ...f.options.fs,
    async open(...args) {
      const handle = await f.options.fs.open(...args);
      return {
        ...handle,
        async close() {
          if (release) await handle.close();
        },
      };
    },
  };
  const kernel = createLinuxProviderKernel({ ...f.options, fs }),
    held = await kernel.hold("/fixture/sealed/nonce");
  for (let attempt = 0; attempt < 2; attempt++) {
    await assert.rejects(kernel.close(held), /descriptor remains open/u);
    assert.equal(held.closed, false);
    assert.equal(kernel.handles.size, 1);
  }
  release = true;
  await kernel.close(held);
  assert.equal(kernel.handles.size, 0);
  assert.equal(f.raw.handles.size, 0);
});

test("Linux namespace denial requires an acknowledged bound outside control, never a fixture error alone", () => {
  const hash = "b".repeat(64),
    domain = {
      bootId: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      namespaceId: "pid:[2]",
      initPid: 70,
      initStartTicks: "10",
    },
    plan = {
      schemaVersion: 1,
      candidateSha: "a".repeat(40),
      nonce: "a".repeat(32),
      domainSha256: observationDigest(domain),
      policySha256: hash,
      reviewSha256: hash,
      routes: [
        {
          id: "outside",
          operation: "outside",
          targetSha256: hash,
          permitTargetSha256: "c".repeat(64),
          denyTargetSha256: "d".repeat(64),
          nonceSha256: hash,
          beforeSha256: hash,
          afterSha256: hash,
          outcome: "deny",
        },
      ],
    },
    bindings = ["tool", "control-permit", "control-deny"].map((phase) => ({
      routeId: "outside",
      phase,
      selector: "/outside/owned",
      opcode: "openat",
      accessMask: null,
      filterId: null,
    })),
    input = {
      plan,
      domain,
      bindings,
      pins: {
        manifestSha256: hash,
        imageSha256: hash,
        sourceSha256: hash,
        abiSha256: hash,
      },
    },
    raw = {
      id: "linux:70:1:1",
      pid: 70,
      opcode: "openat",
      target: "/outside/owned",
      result: -1,
      errno: "ENOENT",
    },
    process = {
      pid: 70,
      identity: { bootId: domain.bootId, startTicks: "10" },
      namespaceId: domain.namespaceId,
    },
    bound = {
      independent: true,
      held: true,
      timeBound: true,
      nativeId: raw.id,
      selector: raw.target,
      objectSha256: hash,
      before: process,
      after: process,
    };
  assert.throws(() => assertLinuxObserverEvent(raw, bound, input, bindings[0]));
  bound.boundary = {
    independent: true,
    outsideControlReady: true,
    completeInventory: true,
    objectSha256: hash,
    domainSha256: plan.domainSha256,
    selector: raw.target,
    nativeId: raw.id,
    nativeEventSha256: hash,
    controlSha256: hash,
  };
  assert.equal(
    assertLinuxObserverEvent(raw, bound, input, bindings[0]),
    "deny",
  );
  for (const key of [
    "outsideControlReady",
    "completeInventory",
    "independent",
  ]) {
    assert.throws(() =>
      assertLinuxObserverEvent(
        raw,
        { ...bound, boundary: { ...bound.boundary, [key]: false } },
        input,
        bindings[0],
      ),
    );
  }
});

test("Linux defaults join parked namespaces, both policy barriers and private relay/bridge custody from raw process edges", async (t) => {
  for (const [provider, profile, substitute] of [
    ...["codex", "claude"].flatMap((provider) =>
      ["read-only", "workspace-write", "trusted-command"].map((profile) => [
        provider,
        profile,
        false,
      ]),
    ),
    ...["argv", "environment", "identity", "trace", "receipt"].map((fault) => [
      "codex",
      "read-only",
      fault,
    ]),
  ]) {
    const withControls =
      provider === "codex" &&
      profile === "read-only" &&
      (!substitute || substitute === "trace");
    const f = await linuxProviderProcessFixture(
      provider,
      profile,
      withControls,
    );
    t.after(() => f.raw.teardown());
    if (substitute === "trace") {
      const spawn = f.options.spawn;
      f.options.spawn = (...args) => {
        const child = spawn(...args),
          write = child.stdio[8]?.write;
        if (write)
          child.stdio[8].write = function (bytes, ...settings) {
            return write.call(
              this,
              bytes.toString().replace(" = -1 ENOENT", " = 9"),
              ...settings,
            );
          };
        return child;
      };
    }
    let receiverFault = false;
    const readFile = f.options.fs.readFile;
    f.options.fs = {
      ...f.options.fs,
      async readFile(file, ...args) {
        const bytes = await readFile(file, ...args),
          match = file.match(/^\/proc\/([0-9]+)\/environ$/u),
          receiver = match && f.processes.get(Number(match[1]));
        if (
          receiverFault &&
          receiver?.argv.at(-1)?.endsWith("relay-process.js")
        ) {
          if (substitute === "environment")
            return Buffer.from(bytes.toString().replace("LANG=C\0", ""));
          if (substitute === "identity") {
            receiver.startTicks = "99999";
            receiverFault = false;
          }
        }
        return bytes;
      },
    };
    const owner = createLinuxProviderEffects(f.input, f.options),
      controller = new AbortController(),
      current = {
        recipe: { id: f.declared.id, reviewSha256: f.reviewSha256 },
        binding: f.binding,
      },
      signal = controller.signal;
    const auditMembers = [];
    await owner.provision(f.declared, f.binding, {
      signal,
      async persist(record) {
        if (record.phase === "linux-provider-audit-retired")
          auditMembers.push([...f.processes.keys()].sort((a, b) => a - b));
        await f.persist(record);
      },
    });
    const readers = await owner.bindReaders(current, { signal });
    const effects = await owner.launchEffects(current, { signal }),
      record = { nonce: f.spec.nonce };
    await effects.verifyInputs(
      f.declared.launch,
      f.spec,
      f.binding.approval.manifestSha256,
      observationDigest("request"),
    );
    const child = effects.spawnProvider(
      f.declared.launch.launcher,
      linuxProviderArguments(f.spec, f.declared.launch),
      {
        signal,
        stdio: ["pipe", "pipe", "pipe", "pipe", "pipe", "pipe", "pipe"],
        async onProcess(pid, admission) {
          record.init = await effects.processDetails(pid);
          record.admission = admission;
        },
      },
    );
    const gate = await linuxProviderFrames(child.stdio[5]).take(signal),
      domain = await effects.inspectGate(child, gate, record);
    await effects.readProvisioning();
    const before = await effects.readPolicy();
    const transport = await owner.transportEffects(current);
    const context = {
      spec: f.spec,
      invocation: providerInvocation(f.spec),
      policy: f.declared.bindings.relayPolicy,
      configurationSha256: observationDigest({
        specificationSha256: providerInvocation(f.spec).specificationSha256,
        policy: f.declared.bindings.relayPolicy,
      }),
      domain,
    };
    const review = await transport.review(context);
    assert.equal(review.packageSha256, f.spec.closureSha256);
    if (["environment", "identity"].includes(substitute)) {
      receiverFault = true;
      await assert.rejects(
        transport.admitTransport("relay", context, { signal }),
        undefined,
        substitute,
      );
      await transport.closeTransport();
      await transport.retire();
      const payload = await owner.retire(current, { signal });
      await owner.releaseAudit(current, payload);
      await owner.restore(current);
      assert.equal(f.raw.handles.size, 0);
      assert.deepEqual(
        [...f.processes.keys()].sort((a, b) => a - b),
        [1, 42],
      );
      controller.abort();
      continue;
    }
    const relay = await transport.admitTransport("relay", context, { signal });
    assert.equal(
      (await transport.verifyRelayCustody(relay, context)).privateControl,
      true,
    );
    const bridge = await transport.admitTransport("bridge", context, relay, {
      signal,
    });
    const verified = await transport.verifyTransport(context, relay, bridge);
    assert.equal(verified.receivingPrincipalVerified, true);
    if (substitute === "trace") {
      await assert.rejects(
        transport.controls(context, relay, bridge, { signal }),
      );
      await assert.rejects(transport.verifyTransport());
      await transport.closeTransport();
      await transport.retire();
      const payload = await owner.retire(current, { signal });
      await owner.releaseAudit(current, payload);
      await owner.restore(current);
      assert.equal(f.raw.handles.size, 0);
      assert.deepEqual(
        [...f.processes.keys()].sort((a, b) => a - b),
        [1, 42],
      );
      controller.abort();
      continue;
    }
    if (withControls)
      assert.equal(
        Object.keys(
          (await transport.controls(context, relay, bridge, { signal })).cases,
        ).length,
        10,
      );
    assert.deepEqual(await effects.readPolicy(), before);
    current.policySha256 = before.policySha256;
    const complete = await owner.prepareCases(current, domain, { signal });
    assert.equal(complete.cases.length, provider === "codex" ? 14 : 19);
    assert.equal(
      new Set(complete.plan.routes.map((route) => route.id)).size,
      complete.cases.length,
    );
    assert.deepEqual(await effects.inspectGate(child, gate, record), domain);
    assert.equal(
      f.records.filter((record) => record.phase === "worker-created").length,
      withControls ? 5 : 3,
    );
    const receipts = transport.modelReceipts(
      f.spec,
      "native-session",
      provider === "codex" ? "native-turn" : ["native-message"],
      { signal },
    );
    f.children[1].stdio[5].write(
      JSON.stringify(
        provider === "codex"
          ? { threadId: "native-session", turnId: "native-turn" }
          : { messageId: "native-message" },
      ) + "\n",
    );
    assert.equal((await receipts).receipts.length, 1);
    if (["argv", "receipt"].includes(substitute)) {
      const receiver = [...f.processes.values()].find((item) =>
          item.argv.at(-1)?.endsWith("relay-process.js"),
        ),
        argv = receiver.argv,
        receiptPipe = receiver.descriptors["4"];
      if (substitute === "argv") receiver.argv = ["/unapproved/transport"];
      if (substitute === "receipt") {
        const readlink = f.options.fs.readlink;
        let replaced = false;
        f.options.fs.readlink = async (file) => {
          const target = await readlink(file);
          if (file === `/proc/${receiver.pid}/fd/4` && !replaced) {
            replaced = true;
            receiver.descriptors["4"] = "pipe:[9998]";
            f.children[1].stdio[5].write(
              JSON.stringify({
                threadId: "substituted-session",
                turnId: "substituted-turn",
              }) + "\n",
            );
          }
          return target;
        };
        try {
          await assert.rejects(
            transport.modelReceipts(
              f.spec,
              "substituted-session",
              "substituted-turn",
              { signal },
            ),
          );
          assert.equal(replaced, true);
        } finally {
          f.options.fs.readlink = readlink;
        }
      }
      await assert.rejects(transport.verifyTransport());
      receiver.argv = argv;
      receiver.descriptors["4"] = receiptPipe;
      await assert.rejects(transport.verifyTransport());
    }
    f.processes.get(72).descriptors["99"] = "pipe:[999]";
    await assert.rejects(effects.readPolicy());
    delete f.processes.get(72).descriptors["99"];
    if (withControls) {
      const mapping = f.declared.launch.mappings[0],
        mapped = await f.options.fs.lstat(mapping.source),
        startTicks = f.processes.get(72).startTicks,
        major =
          ((mapped.dev >> 8n) & 0xfffn) | ((mapped.dev >> 32n) & 0xfffff000n),
        minor = (mapped.dev & 0xffn) | ((mapped.dev >> 12n) & 0xffffff00n),
        readFile = f.options.fs.readFile,
        readlink = f.options.fs.readlink,
        stat = f.options.fs.stat;
      let device = major,
        replaceIdentity = false,
        replaceImage = false,
        image = mapped;
      f.options.fs.readFile = async (file, ...args) => {
        if (file === "/proc/72/environ")
          return Buffer.from(
            Object.entries(providerInvocation(f.spec).execution.environment)
              .map(([key, value]) => `${key}=${value}`)
              .join("\0") + "\0",
          );
        if (file === "/proc/72/maps") {
          if (replaceIdentity) f.processes.get(72).startTicks = "99999";
          if (replaceImage) image = { ...mapped, ino: mapped.ino + 1n };
          return Buffer.from(
            `1000-2000 r-xp 00000000 ${device.toString(16)}:${minor.toString(16)} ${mapped.ino} ${mapping.target}\n`,
          );
        }
        return readFile(file, ...args);
      };
      f.options.fs.readlink = async (file) =>
        file === "/proc/72/exe" ? mapping.target : readlink(file);
      f.options.fs.stat = async (file, ...args) =>
        file === "/proc/72/exe" ? image : stat(file, ...args);
      let liveMatched = false,
        deviceRejected = false,
        identityRejected = false,
        imageRejected = false;
      const selected = f.targets.find(
          (item) => item.routeId === "read" && item.phase === "tool",
        ),
        result = await readers.observe(
          domain,
          {
            ...complete.plan,
            routes: complete.plan.routes.filter((route) => route.id === "read"),
          },
          async (context) => {
            assert.equal(
              (await readers.inspect(f.spec, complete, domain, { signal }))
                .status,
              "MATCHED",
            );
            liveMatched = true;
            device = major + 1n;
            await assert.rejects(
              readers.inspect(f.spec, complete, domain, { signal }),
            );
            deviceRejected = true;
            device = major;
            replaceIdentity = true;
            await assert.rejects(
              readers.inspect(f.spec, complete, domain, { signal }),
            );
            identityRejected = true;
            replaceIdentity = false;
            f.processes.get(72).startTicks = startTicks;
            replaceImage = true;
            await assert.rejects(
              readers.inspect(f.spec, complete, domain, { signal }),
            );
            imageRejected = true;
            replaceImage = false;
            image = mapped;
            await context.attempt("read", async () => {
              child.stdio[8].write(
                `3 1001.000001 openat(AT_FDCWD, "${selected.selector}", O_RDONLY) = 9\n`,
              );
            });
          },
        );
      assert.equal(liveMatched, true, "approved live mapping was inspected");
      assert.equal(
        deviceRejected,
        true,
        "another device with the same inode was rejected",
      );
      assert.equal(
        identityRejected,
        true,
        "replacement during live inspection was rejected",
      );
      assert.equal(
        imageRejected,
        true,
        "exec during live inspection was rejected",
      );
      assert.equal(result.status, "OBSERVED");
      assert.deepEqual(
        auditMembers,
        [[1, 42]],
        "helpers retired before audit settlement",
      );
    }
    await transport.closeTransport();
    assert.equal((await transport.retire()).payloadsRetired, true);
    if (["argv", "receipt"].includes(substitute))
      await assert.rejects(transport.verifySettlement());
    else assert.equal((await transport.verifySettlement()).restored, true);
    const payload = await owner.retire(current, { signal });
    await owner.releaseAudit(current, payload);
    await owner.restore(current);
    assert.equal(f.raw.handles.size, 0);
    assert.deepEqual(
      [...f.processes.keys()].sort((a, b) => a - b),
      [1, 42],
    );
    controller.abort();
  }
});

test("recovery fences delayed transport and payload release receipts", async (t) => {
  for (const phase of ["linux-provider-transport-possible", "release"]) {
    const f = await linuxProviderProcessFixture();
    t.after(() => f.raw.teardown());
    const pending = Promise.withResolvers(),
      resume = Promise.withResolvers(),
      signal = new AbortController().signal,
      owner = createLinuxProviderEffects(f.input, f.options),
      current = { recipe: { id: f.declared.id }, binding: f.binding };
    let paused = false;
    await owner.provision(f.declared, f.binding, {
      signal,
      async persist(record) {
        await f.persist(record);
        if (paused && record.phase === phase) {
          pending.resolve();
          await resume.promise;
        }
      },
    });
    await owner.bindReaders(current, { signal });
    const effects = await owner.launchEffects(current, { signal }),
      record = { nonce: f.spec.nonce };
    await effects.verifyInputs(
      f.declared.launch,
      f.spec,
      f.binding.approval.manifestSha256,
      observationDigest("request"),
    );
    const child = effects.spawnProvider(
      f.declared.launch.launcher,
      linuxProviderArguments(f.spec, f.declared.launch),
      {
        signal,
        stdio: ["pipe", "pipe", "pipe", "pipe", "pipe", "pipe", "pipe"],
        async onProcess(pid, admission) {
          record.init = await effects.processDetails(pid);
          record.admission = admission;
        },
      },
    );
    await effects.inspectGate(
      child,
      await linuxProviderFrames(child.stdio[5]).take(signal),
      record,
    );
    const transport = await owner.transportEffects(current),
      invocation = providerInvocation(f.spec),
      context = {
        spec: f.spec,
        invocation,
        policy: f.declared.bindings.relayPolicy,
        configurationSha256: observationDigest({
          specificationSha256: invocation.specificationSha256,
          policy: f.declared.bindings.relayPolicy,
        }),
      };
    await transport.review(context);
    paused = true;
    const operation =
      phase === "release"
        ? effects.persist({ phase })
        : transport.admitTransport("relay", context, { signal });
    operation.catch(() => {});
    await pending.promise;
    const records = [
      {
        name: `provider-case-${f.declared.id}-0.json`,
        record: { phase: "provisioning-possible", context: f.binding.context },
      },
      ...f.records.map((record, index) => ({
        name: `provider-case-${f.declared.id}-${index + 1}.json`,
        record: { context: f.binding.context, phase: "native", record },
      })),
    ];
    const recovery = owner.recoverCases(records, {
      signal,
      persist: f.persist,
    });
    if (phase === "release") assert.equal((await recovery).status, "RETIRED");
    else await assert.rejects(recovery);
    resume.resolve();
    await assert.rejects(operation);
    assert.equal(f.children.length, 1);
    assert.deepEqual(
      [...f.processes.keys()].sort((a, b) => a - b),
      [1, 42],
    );
  }
});

test("a fenced pending worker birth cannot release its supervisor and still permits deregistration", async (t) => {
  const f = await linuxProviderProcessFixture();
  t.after(() => f.raw.teardown());
  const pending = Promise.withResolvers(),
    resume = Promise.withResolvers(),
    controller = new AbortController();
  let registered,
    admissions = 0,
    deregistrations = 0;
  const kernel = createLinuxProviderKernel({
    ...f.options,
    spawn(file, args, settings) {
      registered = settings;
      return f.options.spawn(file, args, settings);
    },
  });
  const worker = kernel.start("/usr/bin/strace", ["--", "parked"], {
    signal: controller.signal,
    stdio: ["pipe", "pipe", "pipe", "pipe", "pipe", "pipe", "pipe", "pipe"],
    async persist() {
      pending.resolve();
      await resume.promise;
    },
    onProcess(pid) {
      if (pid === null) deregistrations++;
      else admissions++;
    },
  });
  await pending.promise;
  kernel.fence();
  controller.abort();
  resume.resolve();
  await assert.rejects(worker.started);
  await worker.child.ownedCompletion;
  await registered.onProcess(null);
  assert.equal(admissions, 0);
  assert.equal(deregistrations, 1);
  assert.throws(() => kernel.start("/usr/bin/strace", [], {}));
  assert.deepEqual(
    [...f.processes.keys()].sort((a, b) => a - b),
    [1, 42],
  );
});

test("repository Linux observer joins native controls, trace watermarks and owned bytes, rejecting substituted objects", async (t) => {
  for (const substitute of [false, true]) {
    const f = await linuxProviderProcessFixture();
    t.after(() => f.raw.teardown());
    if (substitute) {
      const stat = f.options.fs.stat;
      f.options.fs.stat = async (file, ...args) => {
        const value = await stat(file, ...args);
        return /\/root\/workspace\/read-/u.test(file)
          ? { ...value, ino: value.ino + 1n }
          : value;
      };
    }
    const owner = createLinuxProviderEffects(f.input, f.options),
      controller = new AbortController(),
      signal = controller.signal,
      current = {
        recipe: { id: f.declared.id, reviewSha256: f.reviewSha256 },
        binding: f.binding,
      };
    await owner.provision(f.declared, f.binding, {
      signal,
      persist: f.persist,
    });
    const readers = await owner.bindReaders(current, { signal }),
      effects = await owner.launchEffects(current, { signal }),
      record = { nonce: f.spec.nonce };
    await effects.verifyInputs(
      f.declared.launch,
      f.spec,
      f.binding.approval.manifestSha256,
      observationDigest("request"),
    );
    const child = effects.spawnProvider(
      f.declared.launch.launcher,
      linuxProviderArguments(f.spec, f.declared.launch),
      {
        signal,
        stdio: ["pipe", "pipe", "pipe", "pipe", "pipe", "pipe", "pipe"],
        async onProcess(pid, admission) {
          record.init = await effects.processDetails(pid);
          record.admission = admission;
        },
      },
    );
    const domain = await effects.inspectGate(
      child,
      await linuxProviderFrames(child.stdio[5]).take(signal),
      record,
    );
    await effects.readProvisioning();
    const policy = await effects.readPolicy();
    // A PID local to another private namespace is not a tracee identity.
    f.processes.set(80, {
      ...f.processes.get(72),
      pid: 80,
      parent: 42,
      startTicks: "1080",
      nspid: [80, 3],
      namespaces: { ...f.processes.get(72).namespaces, pid: "pid:[1080]" },
    });
    const selected = f.targets.filter((item) => item.routeId === "read");
    const identity = linuxFileIdentity(
        await f.options.fs.lstat(selected[0].file),
      ),
      nonce = providerFixtureDigest(f.raw.nodes.get(selected[0].file).content),
      targets = Object.fromEntries(
        selected.map((item) => [
          item.phase,
          linuxProviderObjectDigest(identity, item.selector),
        ]),
      ),
      nativeDomain = {
        bootId: record.init.identity.bootId,
        namespaceId: "pid:[1072]",
        initPid: 72,
        initStartTicks: "1072",
      },
      plan = {
        schemaVersion: 1,
        candidateSha: f.spec.candidateSha,
        nonce: f.spec.nonce,
        domainSha256: observationDigest(nativeDomain),
        policySha256: policy.policySha256,
        reviewSha256: f.reviewSha256,
        routes: [
          {
            id: "read",
            operation: "read",
            targetSha256: targets.tool,
            permitTargetSha256: targets["control-permit"],
            denyTargetSha256: targets["control-deny"],
            nonceSha256: nonce,
            beforeSha256: nonce,
            afterSha256: nonce,
            outcome: "permit",
          },
        ],
      };
    const result = await readers.observe(domain, plan, async (context) => {
      await context.attempt("read", async () => {
        child.stdio[8].write(
          `3 1001.000001 openat(AT_FDCWD, "${selected[0].selector}", O_RDONLY) = 9\n`,
        );
      });
    });
    assert.equal(result.status, substitute ? "FAIL" : "OBSERVED");
    if (!substitute)
      assert.deepEqual(result.observation.operationIds, ["read"]);
    assert.ok(
      f.records.some(
        (record) => record.phase === "linux-provider-audit-retired",
      ),
    );
    const payload = await owner.retire(current, { signal });
    await owner.releaseAudit(current, payload);
    await owner.restore(current);
    assert.equal(f.raw.handles.size, 0);
    assert.ok(f.processes.has(80));
    controller.abort();
  }
});

test("fresh Linux recovery uses a parked pidfd receiver and retains exclusion until independent audit drain exists", async (t) => {
  const f = await linuxProviderProcessFixture();
  t.after(() => f.raw.teardown());
  const owner = createLinuxProviderEffects(f.input, f.options),
    controller = new AbortController(),
    signal = controller.signal,
    current = { recipe: { id: f.declared.id }, binding: f.binding };
  await owner.provision(f.declared, f.binding, { signal, persist: f.persist });
  await owner.bindReaders(current, { signal });
  const effects = await owner.launchEffects(current, { signal }),
    record = { nonce: f.spec.nonce };
  await effects.verifyInputs(
    f.declared.launch,
    f.spec,
    f.binding.approval.manifestSha256,
    observationDigest("request"),
  );
  const child = effects.spawnProvider(
    f.declared.launch.launcher,
    linuxProviderArguments(f.spec, f.declared.launch),
    {
      signal,
      stdio: ["pipe", "pipe", "pipe", "pipe", "pipe", "pipe", "pipe"],
      async onProcess(pid, admission) {
        record.init = await effects.processDetails(pid);
        record.admission = admission;
      },
    },
  );
  await effects.inspectGate(
    child,
    await linuxProviderFrames(child.stdio[5]).take(signal),
    record,
  );
  const receipts = () => [
    {
      name: `provider-case-${f.declared.id}-0.json`,
      record: { phase: "provisioning-possible", context: f.binding.context },
    },
    ...f.records.map((record, index) => ({
      name: `provider-case-${f.declared.id}-${index + 1}.json`,
      record: { context: f.binding.context, phase: "native", record },
    })),
  ];
  const bootstrap = "/fixture/sealed/provider-gate",
    preparedGate = f.raw.nodes.get(f.declared.launch.gate);
  f.raw.add(bootstrap, Buffer.from(preparedGate.content), 0o555);
  f.input.manifest.inputs.push({
    path: bootstrap,
    sha256: providerFixtureDigest(preparedGate.content),
    bytes: preparedGate.content.length,
  });
  f.raw.nodes.delete(f.declared.launch.gate);
  const held = [],
    fs = {
      ...f.options.fs,
      async stat(file, ...args) {
        return file === "/proc/90/exe"
          ? f.options.fs.lstat(bootstrap)
          : f.options.fs.stat(file, ...args);
      },
    };
  const recovery = createLinuxProviderEffects(f.input, {
    ...f.options,
    fs,
    retirementSpawn(file, args, settings) {
      assert.equal(file, "/usr/bin/sudo");
      assert.equal(settings.shell, false);
      assert.equal(args.at(-5), bootstrap);
      const targetPid = Number(args.at(-3)),
        target = f.processes.get(targetPid),
        native = new EventEmitter();
      assert.ok(target);
      assert.equal(target.nspid.at(-1), 1);
      const receiver = {
        ...f.processes.get(42),
        pid: 90,
        parent: 42,
        session: 90,
        startTicks: "1090",
        nspid: [90],
        argv: [bootstrap, ...args.slice(-4)],
      };
      f.processes.set(90, receiver);
      native.pid = 90;
      native.stdio = [null, null, null, new PassThrough(), new PassThrough()];
      native.stdio[3].once("data", (command) => {
        assert.equal(command.toString(), "R");
        held.push(targetPid);
        for (const item of [...f.processes.values()])
          if (item.namespaces.pid === target.namespaces.pid)
            f.processes.delete(item.pid);
        f.processes.delete(90);
        native.stdio[4].end();
        native.emit("close", 0, null);
      });
      queueMicrotask(() =>
        native.stdio[4].write(
          JSON.stringify({
            phase: "retirement-held",
            pid: 90,
            targetPid,
            startTicks: target.startTicks,
            bootId: record.init.identity.bootId,
          }) + "\n",
        ),
      );
      return native;
    },
  });
  await assert.rejects(
    recovery.recoverCases(receipts(), {
      persist: f.persist,
      signal: new AbortController().signal,
    }),
  );
  assert.deepEqual(held, [72, 70]);
  assert.deepEqual(
    [...f.processes.keys()].sort((a, b) => a - b),
    [1, 42],
  );
  f.raw.nodes.set(f.declared.launch.gate, preparedGate);
  controller.abort();
  const payload = await owner.retire(current, {
    signal: new AbortController().signal,
  });
  await owner.releaseAudit(current, payload);
  await owner.restore(current);
  assert.equal(
    (
      await recovery.recoverCases(receipts(), {
        persist: f.persist,
        signal: new AbortController().signal,
      })
    ).status,
    "RETIRED",
  );
  const missingBirth = receipts();
  missingBirth.push({
    name: `provider-case-${f.declared.id}-65535.json`,
    record: {
      context: f.binding.context,
      record: {
        phase: "linux-provider-transport-possible",
        args: ["unreturned helper"],
      },
    },
  });
  await assert.rejects(
    recovery.recoverCases(missingBirth, {
      persist: f.persist,
      signal: new AbortController().signal,
    }),
  );
  const foreign = receipts();
  foreign[0].record.context.candidateSha = "b".repeat(40);
  await assert.rejects(
    recovery.recoverCases(foreign, {
      persist: f.persist,
      signal: new AbortController().signal,
    }),
  );
  assert.equal(f.raw.handles.size, 0);
});

test("outside controls require an actual nonce exchange and unchanged kernel socket, and close only after payload retirement", async (t) => {
  for (const fault of ["nonce", "socket", "setup", "listening"]) {
    const f = await linuxProviderProcessFixture();
    t.after(() => f.raw.teardown());
    let handler,
      inode = "socket:[8900]",
      corrupt = false,
      replace = false;
    const pending = Promise.withResolvers(),
      resume = Promise.withResolvers();
    const kernel = createLinuxProviderKernel({
        ...f.options,
        fs: {
          ...f.options.fs,
          async readlink(file) {
            return file === "/proc/self/fd/890"
              ? inode
              : f.options.fs.readlink(file);
          },
        },
      }),
      held = await kernel.hold("/fixture/sealed/nonce"),
      selector = "127.0.0.1:42002",
      session = {
        launch: f.declared.launch,
        spec: f.spec,
        objects: new Map([[held.file, { held }]]),
        async persist(record) {
          await f.persist(record);
          if (
            fault === "setup" &&
            record.phase === "linux-provider-outside-control-possible"
          ) {
            pending.resolve();
            await resume.promise;
          }
        },
        observationData: {
          targets: [{ selector, file: held.file }],
          outsideControls: [{ kind: "tcp", selector, file: held.file }],
        },
      };
    const controls = createLinuxProviderControls(session, kernel, {
      pid: 42,
      httpServer(receive) {
        handler = receive;
        const server = new EventEmitter();
        server._handle = { fd: 890 };
        server.listening = false;
        server.listen = () => {
          const ready = () => {
            server.listening = true;
            f.processes.get(42).descriptors["890"] = inode;
            queueMicrotask(() => server.emit("listening"));
          };
          if (fault === "listening") {
            pending.resolve();
            resume.promise.then(ready);
          } else ready();
        };
        server.close = (callback) => {
          server.listening = false;
          delete f.processes.get(42).descriptors["890"];
          callback();
        };
        return server;
      },
      httpRequest(url, settings, callback) {
        assert.equal(url, "http://" + selector);
        assert.equal(settings.agent, false);
        const client = new EventEmitter();
        client.setTimeout = () => {};
        client.end = () =>
          queueMicrotask(() =>
            handler(
              { resume() {} },
              {
                end(bytes) {
                  if (replace) inode = "socket:[8901]";
                  const response = Readable.from([
                    corrupt ? Buffer.from("wrong nonce") : bytes,
                  ]);
                  response.statusCode = 200;
                  callback(response);
                },
              },
            ),
          );
        client.destroy = (error) => client.emit("error", error);
        return client;
      },
    });
    if (fault === "setup") {
      const initialization = controls.initialize();
      await pending.promise;
      session.payloadRetired = true;
      await controls.close();
      resume.resolve();
      await assert.rejects(initialization);
      assert.equal(f.processes.get(42).descriptors["890"], undefined);
      await kernel.close(held);
      continue;
    }
    if (fault === "listening") {
      const initialization = controls.initialize();
      await pending.promise;
      session.payloadRetired = true;
      const retirement = controls.close();
      resume.resolve();
      await assert.rejects(initialization);
      await retirement;
      await controls.close();
      assert.equal(f.processes.get(42).descriptors["890"], undefined);
      await kernel.close(held);
      continue;
    }
    await controls.initialize();
    assert.equal((await controls.verify(selector)).identity, inode);
    await assert.rejects(controls.close());
    assert.equal((await controls.verify(selector)).identity, inode);
    corrupt = fault === "nonce";
    replace = fault === "socket";
    await assert.rejects(controls.verify(selector));
    corrupt = false;
    replace = false;
    inode = "socket:[8900]";
    await assert.rejects(controls.verify(selector));
    session.payloadRetired = true;
    await controls.close();
    assert.ok(
      f.records.some(
        (record) => record.phase === "linux-provider-outside-control-held",
      ),
    );
    await kernel.close(held);
    assert.equal(f.raw.handles.size, 0);
  }
});
