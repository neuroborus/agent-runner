import assert from "node:assert/strict";
import test from "node:test";
import {
  initializeNativeJob,
  recordExperimentPreparationEffect,
  recordExperimentPreparation,
  recordExperimentCase,
  observationDigest,
  nativeExperimentInventory,
  materializeExperimentPolicy,
  NATIVE_EFFECT_CLASSES,
  PLATFORMS,
  SYSTEM_CHECK_IDS,
} from "./index.js";
import { runDarwinExperimentProofs } from "./darwin/index.js";
import { runWindowsExperimentProofs } from "./win32/index.js";

const H = "a".repeat(64),
  C = "b".repeat(40);
const retired = {
  status: "RETIRED",
  independent: true,
  emergencyCleanup: false,
};
const retained = {
  status: "RETAINED",
  independent: false,
  emergencyCleanup: false,
};

// Pure ledger observations only. Retained platform proof/preparation suites own
// native assertion coverage; these injections establish no native PASS.
function fixture(platform, fault) {
  const inventory = nativeExperimentInventory(platform),
    context = {
      candidateSha: C,
      platform,
      repository: "example/native",
      runId: "1",
      runAttempt: 1,
    };
  const expected = {
    binding: {
      ...context,
      checkoutSha: C,
      image: PLATFORMS.find(({ os }) => os === platform).image,
      osBuild: "synthetic-build",
      architecture: "x64",
      nodeVersion: "v24.21.0",
      workflow: "native-poc",
      jobId: "2",
    },
    sources: inventory.helpers.map((id) => ({ id, sha256: H })),
    tools: inventory.tools.map((id) => ({
      id,
      sha256: H,
      version: "synthetic",
    })),
    sdk: { build: "synthetic", sha256: H },
    components: inventory.helpers.map((id) => ({
      id,
      role: "helper",
      sha256: H,
      format: platform === "darwin" ? "macho-x64" : "pe-x64",
      loader: [],
      bindings: { source: H, build: H, abi: H },
    })),
  };
  const runtime = expected.components.map(({ role, ...value }) => ({
    ...value,
    identityBefore: H,
    identityAfter: H,
    held: true,
    independent: true,
  }));
  let job = initializeNativeJob(context, {
    schemaVersion: 7,
    purpose: "experiment",
  });
  job = recordExperimentPreparationEffect(job, {
    admission: "possible",
    settlement: retained,
    receiptSha256: null,
  });
  job = recordExperimentPreparation(job, expected, {
    ...expected,
    components: runtime,
    independent: true,
    readSha256: H,
  });
  job = recordExperimentPreparationEffect(job, {
    admission: "possible",
    settlement: retired,
    receiptSha256: H,
  });
  const nativeContext = (id) => ({
    candidateSha: C,
    platform,
    runId: "1",
    runAttempt: 1,
    executionId: id,
    tier: "system",
    jobBindingSha256: observationDigest(expected.binding),
    closureSha256: H,
    selectedSystemSha256: null,
  });
  const bindings = inventory.cases.map(({ id }) => ({
    purpose: "experiment",
    context: nativeContext(id),
    template: {
      purpose: "experiment",
      schemaVersion: 1,
      candidateSha: C,
      platform,
      sourceSha256: H,
      provisioningSha256: H,
      policy: { launch: {}, policy: { kind: "synthetic" } },
      bindings: [],
    },
  }));
  const preparation = {
    purpose: "experiment",
    prepared: {
      job: context,
      bootstrap: { context: nativeContext("build"), bindingSha256: H },
      sources: [],
      output: "/synthetic/build",
    },
    build: { commands: [] },
    system: {
      policyBindings: bindings,
      bindings: bindings.map((policyBinding) => ({
        id: policyBinding.context.executionId,
        policyBinding,
      })),
    },
  };
  const saves = [],
    events = [],
    failures = [];
  const policy = async (settings) => {
    const { policyBinding: binding } = settings;
    const provisioning = {
      schemaVersion: 1,
      context: binding.context,
      bindingSha256: binding.template.provisioningSha256,
      bindings: binding.template.bindings.map(({ id, kind }) => ({
        id,
        kind,
        value: H,
      })),
      held: true,
      independent: true,
      verifierSha256: H,
      nativeEventSha256: H,
    };
    const actual = materializeExperimentPolicy(
        binding.template,
        provisioning,
        binding.context,
      ),
      requestSha256 = observationDigest(actual.policy.launch);
    await settings.recordPolicy({
      provisioning,
      requestSha256,
      observed: {
        schemaVersion: 1,
        context: binding.context,
        templateSha256: actual.templateSha256,
        provisioningSha256: observationDigest(provisioning),
        requestSha256,
        policySha256: actual.expectedPolicySha256,
        policy: actual.policy,
        held: true,
        independent: fault !== "policy",
        complete: true,
        verifierSha256: H,
        nativeEventSha256: H,
      },
    });
  };
  const options = {
    platform,
    architecture: "x64",
    now: () => 0,
    persist: async (value) => {
      saves.push(structuredClone(value));
    },
    onFailure: async (_, error) => failures.push(error),
    load: async (value) => {
      const entry = saves.at(-1).cases.at(-1);
      assert.equal(entry.status, "NOT_RUN");
      assert.equal(entry.effects.policy.admission, "possible");
      events.push("load:" + entry.id);
      const actual = structuredClone(runtime);
      if (fault === "runtime") actual[0].sha256 = "c".repeat(64);
      return { job: value, preparation, runtime: actual };
    },
    createEffects: () => ({
      build: async (settings) => {
        events.push("build");
        await policy(settings);
        return { purpose: "experiment", independent: true, status: "OBSERVED" };
      },
      prepare: async (recipe, settings) => {
        events.push("prepare:" + recipe.id);
        await policy(settings);
        return {
          purpose: "experiment",
          independent: true,
          templateSha256: observationDigest(settings.policyBinding.template),
          effects: {
            observe: async () => ({
              purpose: "experiment",
              status: fault === "native" ? "FAIL" : "OBSERVED",
              evidenceSha256: H,
            }),
          },
        };
      },
      settle: async (recipe, _, { execution, signal }) => {
        assert.equal(signal.aborted, false);
        events.push("settle:" + recipe.id);
        return Object.fromEntries(
          NATIVE_EFFECT_CLASSES.map((effectClass) => [
            effectClass,
            execution.effects[effectClass].admission === "not-started"
              ? null
              : {
                  candidateSha: C,
                  executionId: recipe.id,
                  effectClass,
                  sha256: H,
                  settlement:
                    fault === "cleanup" && recipe.id === "release"
                      ? retained
                      : fault === "emergency"
                        ? { ...retired, emergencyCleanup: true }
                        : retired,
                },
          ]),
        );
      },
    }),
    runCase: async (_, recipe) => {
      events.push("case:" + recipe.id);
      return { status: "OBSERVED", evidenceSha256: H };
    },
  };
  return {
    job,
    inventory,
    options,
    saves,
    events,
    failures,
    run:
      platform === "darwin"
        ? runDarwinExperimentProofs
        : runWindowsExperimentProofs,
  };
}

test("indexed Darwin/Windows experiment loops persist every recipe including build and all 23 checks", async () => {
  for (const platform of ["darwin", "win32"]) {
    const f = fixture(platform),
      job = await f.run(f.job, "/synthetic", f.options);
    assert.equal(job.failure, null);
    assert.deepEqual(
      job.cases.map(({ id }) => id),
      f.inventory.cases.map(({ id }) => id),
    );
    assert.ok(job.cases.every(({ status }) => status === "PASS"));
    assert.deepEqual(
      [
        ...new Set(
          job.cases.flatMap(({ observations }) =>
            observations.map(({ checkId }) => checkId),
          ),
        ),
      ].sort(),
      [...SYSTEM_CHECK_IDS].sort(),
    );
    assert.equal(job.cases[0].observations.length, 0);
    assert.equal(
      f.events.filter((event) => event.startsWith("load:")).length,
      job.cases.length,
    );
    assert.ok(
      f.events.indexOf("settle:build") < f.events.indexOf("prepare:release"),
    );
    assert.equal(job.schemaVersion, 7);
    assert.equal(job.reviews, undefined);
  }
});

test("native, policy, held-runtime and retirement failures stop admission and cannot be repaired into PASS", async () => {
  for (const platform of ["darwin", "win32"])
    for (const fault of [
      "policy",
      "runtime",
      "cleanup",
      "emergency",
      "native",
    ]) {
      const f = fixture(platform, fault);
      if (fault === "native") delete f.options.runCase;
      const job = await f.run(f.job, "/synthetic", f.options);
      assert.equal(job.failure, "probe-failed", platform + ":" + fault);
      assert.equal(job.cases.at(-1).status, "FAIL");
      assert.equal(
        job.cases.length,
        ["native", "cleanup"].includes(fault) ? 2 : 1,
      );
      assert.equal(f.failures.length, 1);
      assert.ok(!f.events.includes("prepare:ownership.literal"));
      await assert.rejects(f.run(job, "/synthetic", f.options));
      if (fault === "cleanup") {
        const last = job.cases.at(-1),
          effects = structuredClone(last.effects);
        for (const effect of Object.values(effects))
          if (effect.admission === "possible") {
            effect.settlement = retired;
            effect.receiptSha256 = H;
          }
        const recovered = recordExperimentCase(job, { ...last, effects });
        assert.equal(recovered.failure, job.failure);
        assert.equal(recovered.cases.at(-1).status, "FAIL");
        assert.deepEqual(
          recovered.cases.at(-1).observations,
          last.observations,
        );
      }
    }
});

test("execution deadline fences late completion and cannot witness denial or independently settle pending work", async () => {
  const f = fixture("darwin"),
    timers = new Map();
  let announce, finish;
  const entered = new Promise((resolve) => {
    announce = resolve;
  });
  const pending = new Promise((resolve) => {
    finish = resolve;
  });
  f.options.schedule = (fn, ms) => {
    const token = {};
    timers.set(token, { fn, ms });
    return token;
  };
  f.options.cancel = (token) => timers.delete(token);
  f.options.runCase = async () => {
    announce();
    return pending;
  };
  const running = f.run(f.job, "/synthetic", f.options);
  await entered;
  [...timers.values()].find(({ ms }) => ms === 120000).fn();
  const job = await running;
  assert.equal(job.failure, "deadline");
  assert.equal(job.cases.at(-1).status, "FAIL");
  assert.equal(job.cases.at(-1).effects.helpers.settlement.status, "RETAINED");
  assert.ok(
    job.cases
      .at(-1)
      .observations.every(({ observation }) => !observation.attempted),
  );
  const count = f.saves.length;
  finish({ status: "OBSERVED", evidenceSha256: H });
  await pending;
  assert.equal(f.saves.length, count);
  assert.equal(timers.size, 0);
});

test("a delayed policy publication cannot overwrite terminal failure after independent cleanup", async () => {
  const f = fixture("darwin"),
    timers = new Map();
  let entered, release, cleaned;
  const publicationEntered = new Promise((resolve) => {
    entered = resolve;
  });
  const publication = new Promise((resolve) => {
    release = resolve;
  });
  const cleanupEntered = new Promise((resolve) => {
    cleaned = resolve;
  });
  const persist = f.options.persist,
    create = f.options.createEffects;
  f.options.schedule = (fn, ms) => {
    const token = {};
    timers.set(token, { fn, ms });
    return token;
  };
  f.options.cancel = (token) => timers.delete(token);
  f.options.persist = async (value) => {
    const entry = value.cases.at(-1);
    if (
      entry.id === "release" &&
      entry.status === "NOT_RUN" &&
      entry.policy.independent
    ) {
      entered();
      await publication;
    }
    await persist(value);
  };
  f.options.createEffects = () => {
    const effects = create(),
      settle = effects.settle;
    effects.settle = async (...args) => {
      const result = await settle(...args);
      if (args[0].id === "release") cleaned();
      return result;
    };
    return effects;
  };
  const running = f.run(f.job, "/synthetic", f.options);
  await publicationEntered;
  [...timers.values()].find(({ ms }) => ms === 120000).fn();
  await cleanupEntered;
  release();
  const job = await running;
  assert.equal(job.failure, "deadline");
  assert.equal(job.cases.at(-1).status, "FAIL");
  assert.equal(f.saves.at(-1).failure, "deadline");
  assert.equal(f.saves.at(-1).cases.at(-1).status, "FAIL");
  assert.equal(timers.size, 0);
});
