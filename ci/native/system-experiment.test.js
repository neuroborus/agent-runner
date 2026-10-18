import assert from "node:assert/strict";
import path, { win32 as windowsPath } from "node:path";
import { readFile } from "node:fs/promises";
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
  resolveNativeDispatch,
  systemJobBounds,
  normalizeExperimentJob,
  recordExperimentRecovery,
  recordNativeStage,
  recordNativeAdmission,
  recordNativeSettlement,
  NATIVE_GROUPS,
} from "./index.js";
import {
  recoverLinuxExperimentProofs,
  runLinuxExperimentProofs,
  linuxNamespaceSettlement,
} from "./linux/index.js";
import {
  observeExperimentBinding,
  runExperimentStage,
  initializeExperimentCI,
  runExperimentProofs,
} from "./experiment-ci.js";
import { nativePreparationError } from "./first-failure.js";
import { runDarwinExperimentProofs } from "./darwin/index.js";
import {
  runWindowsExperimentProofs,
  recoverWindowsExperimentProofs,
  loadWindowsExperiment,
  WINDOWS_HELPER_NAMES,
} from "./win32/index.js";
import { WINDOWS_EXPERIMENT_SOURCES } from "./win32/experiment-native.js";

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

function linuxProofJournal(job, releasePossible = true) {
  return {
    purpose: "experiment",
    context: Object.fromEntries(
      ["candidateSha", "platform", "repository", "runId", "runAttempt"].map(
        (key) => [key, job[key]],
      ),
    ),
    stages: { probe: "FAIL", cleanup: "PASS" },
    proof: {
      preparationSha256: observationDigest(job.preparation),
      owner: {
        pid: 77,
        identity: {
          bootId: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
          startTicks: "1",
        },
      },
      releasePossible,
      retirementSha256: null,
    },
  };
}

// Pure ledger observations only. Retained platform proof/preparation suites own
// native assertion coverage; these injections establish no native PASS.
function fixture(platform, fault, osBuild = "synthetic-build") {
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
      osBuild,
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
      format: { linux: "elf-x64", darwin: "macho-x64", win32: "pe-x64" }[
        platform
      ],
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
    build:
      platform === "darwin"
        ? {
            schemaVersion: 2,
            purpose: "experiment",
            commands: [],
            helpers: inventory.helpers.map((name) => ({
              name,
              sha256: H,
              sourceSha256: H,
              macho: { dependencies: [] },
            })),
          }
        : { commands: [] },
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

function stageFixture(platform = "darwin") {
  const f = fixture(
      platform,
      undefined,
      platform === "win32" ? "10.0.26100" : "syntheticbuild",
    ),
    directory = "/synthetic/native-system",
    files = new Map(),
    events = [];
  const context = Object.fromEntries(
    ["candidateSha", "platform", "repository", "runId", "runAttempt"].map(
      (key) => [key, f.job[key]],
    ),
  );
  const env = {
    CI: "true",
    GITHUB_ACTIONS: "true",
    RUNNER_TEMP: "/synthetic",
    RUNNER_ENVIRONMENT: "github-hosted",
    RUNNER_OS: { linux: "Linux", darwin: "macOS", win32: "Windows" }[platform],
    GITHUB_REPOSITORY: "example/native",
    GITHUB_RUN_ID: "1",
    GITHUB_RUN_ATTEMPT: "1",
    ImageVersion: "syntheticbuild",
  };
  const controller = {
    readJSON: async (name) => {
      if (!files.has(name))
        throw Object.assign(new Error("Absent receipt"), { code: "ENOENT" });
      return structuredClone(files.get(name));
    },
    persistJSON: async (name, value, settings = {}) => {
      if (settings.exclusive && files.has(name))
        throw Object.assign(new Error("Existing public journal"), {
          code: "EEXIST",
        });
      files.set(name, structuredClone(value));
    },
    inspectImage: async () => ({
      os: platform,
      image: PLATFORMS.find(({ os }) => os === platform).image,
      architecture: "x64",
      build: platform === "win32" ? "10.0.26100.1" : "15.0",
    }),
    command: async () => ({ stdout: C }),
    listMetadata: async () => [
      { id: 2, name: `native-system-${platform}`, run_id: 1, run_attempt: 1 },
    ],
    publish: async (_, __, rendered) => events.push(rendered),
  };
  const options = {
    host: { platform, arch: "x64", version: "v24.21.0" },
    owner: {
      prepare: async (_, __, persist) => {
        events.push("prepare");
        await persist(f.job);
      },
      load: async () => events.push("load"),
      probe: (job, dir, settings) =>
        f.run(job, dir, {
          ...f.options,
          persist: async (value) => {
            await f.options.persist(value);
            await settings.persist(value);
          },
        }),
      recover: async (job, _, persist) => {
        events.push("recover");
        const next = recordExperimentRecovery(job, {
          ...retired,
          nativeEventSha256: H,
        });
        await persist(next);
        return next;
      },
    },
  };
  files.set(
    directory + "/native-job.json",
    initializeNativeJob(context, { schemaVersion: 7, purpose: "experiment" }),
  );
  if (platform === "linux")
    files.set(directory + "/experiment-stages.json", {
      purpose: "experiment",
      context,
      stages: {},
    });
  return {
    f,
    directory,
    storage: path.join(
      env.RUNNER_TEMP,
      `native-${platform}-experiment-${observationDigest(context)}`,
    ),
    files,
    events,
    env,
    controller,
    options,
    stage: (name) =>
      runExperimentStage(name, env, directory, controller, options),
  };
}

test("experiment stages keep private native storage outside public upload traversal", async () => {
  for (const platform of ["darwin", "win32"]) {
    const f = stageFixture(platform),
      storage = f.storage,
      directories = new Set([f.directory]),
      calls = [],
      original = f.options.owner;
    assert.ok(path.relative(f.directory, storage).startsWith(".." + path.sep));
    const inspect = (stage, directory, options) => {
      assert.equal(directory, storage);
      assert.ok(directories.has(directory));
      assert.equal(
        options.bootstrapJournal,
        platform === "win32" ? path.join(f.directory, "native") : undefined,
      );
      calls.push(stage);
    };
    f.options.owner = {
      prepare: async (job, directory, persist, options) => {
        assert.ok(f.files.has(path.join(f.directory, "native-job.json")));
        assert.ok(
          f.files.has(path.join(f.directory, "experiment-stages.json")),
        );
        assert.equal(directory, storage);
        assert.deepEqual([...directories], [f.directory]);
        directories.add(directory); // Inject exclusive native allocation only.
        inspect("prepare", directory, options);
        if (platform === "win32") {
          await options.persistBootstrap({
            purpose: "experiment",
            phase: "original-intent",
          });
          await options.persistBootstrap({
            purpose: "experiment",
            phase: "original-selector",
          });
        } else assert.equal(options.persistBootstrap, undefined);
        return original.prepare(job, directory, persist, options);
      },
      load: async (job, directory, options) => {
        inspect("load", directory, options);
        return original.load(job, directory, options);
      },
      probe: async (job, directory, options) => {
        inspect("probe", directory, options);
        return original.probe(job, directory, options);
      },
      recover: async (job, directory, persist, options) => {
        inspect("recover", directory, options);
        return original.recover(job, directory, persist, options);
      },
    };
    const publish = f.controller.publish;
    f.controller.publish = async (env, directory, rendered) => {
      assert.equal(directory, f.directory);
      // Simulate publication with private traversal denied, as on the native hosts.
      const visit = (root) => {
        if (root === storage)
          throw Object.assign(new Error("Private custody"), { code: "EACCES" });
        for (const child of directories)
          if (child !== root && path.dirname(child) === root) visit(child);
      };
      assert.throws(() => visit(storage), { code: "EACCES" });
      visit(directory);
      if (platform === "win32") {
        assert.equal(
          f.files.get(path.join(directory, "native-bootstrap-0.json")).phase,
          "original-intent",
        );
        assert.equal(
          f.files.get(path.join(directory, "native-bootstrap-1.json")).phase,
          "original-selector",
        );
      } else {
        assert.equal(
          f.files.has(path.join(directory, "native-bootstrap-0.json")),
          false,
        );
      }
      return publish(env, directory, rendered);
    };
    await initializeExperimentCI(
      f.files.get(path.join(f.directory, "native-job.json")),
      f.directory,
      f.controller,
    );
    assert.deepEqual([...directories], [f.directory]);
    for (const stage of ["prepare", "setup", "probe", "cleanup", "report"])
      assert.equal(await f.stage(stage), true, platform + ":" + stage);
    assert.deepEqual(calls, ["prepare", "load", "probe", "recover"]);
    assert.deepEqual([...directories], [f.directory, storage]);
  }
});

test("preexisting Windows public bootstrap journals survive failed preparation without native allocation", async () => {
  const f = stageFixture("win32"),
    file = path.join(f.directory, "native-bootstrap-0.json"),
    original = { purpose: "experiment", phase: "original-admission" };
  f.files.set(file, original);
  f.options.owner.prepare = async (_, __, ___, options) => {
    await options.persistBootstrap({
      purpose: "experiment",
      phase: "replacement",
    });
    assert.fail("An existing journal must stop native allocation");
  };
  assert.equal(await f.stage("prepare"), false);
  assert.deepEqual(f.files.get(file), original);
  assert.equal(
    f.files.get(path.join(f.directory, "native-first-failure.json")).stage,
    "prepare",
  );
});

test("preexisting native storage fails preparation and partial recovery rejoins that same path", async () => {
  for (const [platform, cleanupFailure] of [
    ["darwin", false],
    ["darwin", true],
    ["win32", false],
    ["win32", true],
  ]) {
    const f = stageFixture(platform),
      storage = f.storage,
      directories = new Set([f.directory, storage]),
      calls = [];
    f.options.owner.prepare = async (job, directory, persist) => {
      assert.equal(directory, storage);
      await persist(
        recordExperimentPreparationEffect(job, {
          admission: "possible",
          settlement: retained,
          receiptSha256: null,
        }),
      );
      assert.ok(directories.has(directory));
      calls.push("exclusive-create");
      throw Object.assign(new Error("Native storage already exists"), {
        code: "EEXIST",
      });
    };
    f.options.owner.recoverPreparation = async (job, directory, _, options) => {
      assert.equal(directory, storage);
      assert.equal(
        options.bootstrapJournal,
        platform === "win32" ? path.join(f.directory, "native") : undefined,
      );
      assert.deepEqual([...directories], [f.directory, storage]);
      assert.equal(job.preparation, null);
      calls.push("recover-original");
      if (cleanupFailure) throw new Error("Independent cleanup failed");
      return recordExperimentPreparationEffect(job, {
        admission: "possible",
        settlement: retired,
        receiptSha256: H,
      });
    };
    f.options.owner.load =
      f.options.owner.probe =
      f.options.owner.recover =
        async () =>
          assert.fail("No dependent effects after failed preparation");
    assert.equal(await f.stage("prepare"), false);
    const first = structuredClone(
      f.files.get("/synthetic/native-system/native-first-failure.json"),
    );
    assert.equal(first.stage, "prepare");
    assert.equal(await f.stage("setup"), false);
    assert.equal(await f.stage("cleanup"), !cleanupFailure);
    assert.deepEqual(calls, ["exclusive-create", "recover-original"]);
    assert.deepEqual(
      f.files.get("/synthetic/native-system/native-first-failure.json"),
      first,
    );
    assert.equal(await f.stage("report"), false);
    const report = f.events.at(-1).report;
    assert.deepEqual(report.firstFailures, [first]);
    if (cleanupFailure)
      assert.equal(report.cleanupFailures[0].stage, "cleanup");
  }
});

test("Windows cold experiment selection reads only the original public bootstrap journals before protected custody", async () => {
  for (const damage of [null, "directory", "gap"]) {
    const f = stageFixture("win32"),
      storage = "C:\\Synthetic\\native-win32-experiment",
      journal = "C:\\Synthetic\\native-system\\native",
      boundary = new Error("Protected native receipt boundary"),
      reads = [];
    let protectedRead = false;
    const seal = {
      purpose: "experiment",
      phase: "bootstrap-seal-possible",
      directory: damage === "directory" ? storage + "-other" : storage,
      output: windowsPath.join(storage, "platform-build"),
      bootstrap: { context: { candidateSha: C, runId: "1", runAttempt: 1 } },
      sources: WINDOWS_EXPERIMENT_SOURCES.map((name) => ({ name, sha256: H })),
      helpers: WINDOWS_HELPER_NAMES.map((name) => ({
        name,
        sha256: H,
        sourceSha256: H,
      })),
      tools: [
        {
          name: "compiler",
          path: "C:\\Program Files\\Microsoft Visual Studio\\18\\Enterprise\\VC\\Tools\\MSVC\\14.0\\bin\\Hostx64\\x64\\cl.exe",
          sha256: H,
          signatureSha256: H,
        },
        {
          name: "sdk",
          path: "C:\\Program Files (x86)\\Windows Kits\\10\\bin\\10.0.26100.0\\x64\\rc.exe",
          sha256: H,
          signatureSha256: H,
        },
      ],
    };
    await assert.rejects(
      loadWindowsExperiment(f.f.job, storage, {
        env: { ...f.env, ImageOS: "win25" },
        platform: "win32",
        architecture: "x64",
        nodeVersion: "v24.21.0",
        bootstrapJournal: journal,
        readdir: async (root) => {
          assert.equal(root, windowsPath.dirname(journal));
          return ["native-bootstrap-" + (damage === "gap" ? 1 : 0) + ".json"];
        },
        read: async (file) => {
          reads.push(file);
          assert.equal(file, journal + "-bootstrap-0.json");
          return Buffer.from(JSON.stringify(seal));
        },
        files: {
          readProtected: async ({ file }) => {
            protectedRead = true;
            assert.equal(
              file,
              windowsPath.join(storage, "windows-experiment-preparation.json"),
            );
            throw boundary;
          },
          settleFiles: async () => ({ ...retired, nativeEventSha256: H }),
        },
      }),
      damage
        ? /Unverified native tool observation/u
        : (error) => error === boundary,
    );
    assert.equal(protectedRead, damage === null);
    assert.equal(reads.length, damage === "gap" ? 0 : 1);
  }
});

test("Windows experiment stages pass one normalized copied environment to every native checkpoint", async () => {
  const f = stageFixture("win32"),
    checkpoints = [];
  Object.assign(f.env, {
    systemroot: "C:\\Windows",
    "PROGRAMFILES(X86)": "C:\\Program Files (x86)",
    GH_TOKEN: "synthetic-metadata",
    gh_token: "synthetic-metadata-alias",
    Git_Dir: "foreign-repository",
    git_config_global: "foreign-config",
    Path: "native-tools",
    INCLUDE: "sdk-headers",
    LIB: "sdk-libraries",
  });
  const source = { ...f.env };
  for (const name of ["prepare", "load", "probe", "recover"]) {
    const operation = f.options.owner[name];
    f.options.owner[name] = async (...args) => {
      const { env } = args.at(-1);
      checkpoints.push(name);
      assert.notEqual(env, f.env);
      assert.equal(env.SystemRoot, "C:\\Windows");
      assert.equal(env["ProgramFiles(x86)"], "C:\\Program Files (x86)");
      assert.equal(env.Path, source.Path);
      assert.equal(env.INCLUDE, source.INCLUDE);
      assert.equal(env.LIB, source.LIB);
      assert.equal(env.systemroot, undefined);
      assert.equal(env["PROGRAMFILES(X86)"], undefined);
      assert.ok(Object.keys(env).every((key) => !/^GH_TOKEN$/iu.test(key)));
      assert.deepEqual(
        Object.fromEntries(
          Object.entries(env).filter(([key]) => /^GIT_/iu.test(key)),
        ),
        {
          GIT_CONFIG_NOSYSTEM: "1",
          GIT_CONFIG_GLOBAL: "NUL",
          GIT_OPTIONAL_LOCKS: "0",
          GIT_TERMINAL_PROMPT: "0",
        },
      );
      return operation(...args);
    };
  }
  for (const stage of ["prepare", "setup", "probe", "cleanup"])
    assert.equal(await f.stage(stage), true, stage);
  assert.deepEqual(checkpoints, ["prepare", "load", "probe", "recover"]);
  assert.deepEqual(f.env, source); // Controller metadata authority is retained.
});

test("conflicting Windows environment aliases stop experiment commands before native admission", async () => {
  for (const [canonical, alias] of [
    ["SystemRoot", "SYSTEMROOT"],
    ["ProgramFiles(x86)", "PROGRAMFILES(X86)"],
  ]) {
    const f = stageFixture("win32");
    let commands = 0;
    Object.assign(f.env, {
      [canonical]: "C:\\Fixture",
      [alias]: "D:\\Conflicting",
    });
    f.controller.command = async () => {
      commands++;
      return { stdout: C };
    };
    assert.equal(await f.stage("prepare"), false);
    assert.equal(commands, 0);
    assert.equal(f.events.includes("prepare"), false);
    assert.equal(
      f.files.get("/synthetic/native-system/native-job.json").preparationEffects
        .admission,
      "not-started",
    );
    assert.throws(() =>
      runExperimentProofs(f.f.job, f.directory, {
        ...f.f.options,
        env: f.env,
      }),
    );
  }
});

test("explicit experimental stages bypass reviewed acquisition and require hosted identity before effects", async () => {
  assert.deepEqual(
    resolveNativeDispatch([
      "--tier",
      "system",
      "--purpose",
      "experiment",
      "--stage",
      "cleanup",
    ]),
    { tier: "system", purpose: "experiment", stage: "cleanup" },
  );
  assert.deepEqual(resolveNativeDispatch(["--tier", "provider"]), {
    tier: "provider",
    stage: "all",
  });
  for (const args of [
    ["--tier", "provider", "--purpose", "experiment"],
    ["--tier", "system", "--purpose", "reviewed"],
    ["--tier", "system", "--stage", "probe", "--purpose", "experiment"],
    [
      "--tier",
      "system",
      "--purpose",
      "experiment",
      "--stage",
      "prepare-inputs",
    ],
  ])
    assert.throws(() => resolveNativeDispatch(args));
  const f = stageFixture();
  for (const change of [
    () => {
      f.options.host.arch = "arm64";
    },
    () => {
      f.options.host.version = "v24.0.0";
    },
    () => {
      f.env.RUNNER_ENVIRONMENT = "self-hosted";
    },
    () => {
      f.controller.command = async () => ({ stdout: "c".repeat(40) });
    },
    () => {
      f.controller.listMetadata = async () => [];
    },
    () => {
      f.controller.inspectImage = async () => ({
        os: "darwin",
        image: "macos-14",
        architecture: "x64",
      });
    },
  ]) {
    const original = stageFixture();
    Object.assign(f.options, original.options);
    Object.assign(f.env, original.env);
    Object.assign(f.controller, original.controller);
    change();
    await assert.rejects(
      observeExperimentBinding(f.f.job, f.env, f.controller, f.options.host),
    );
  }
  const valid = stageFixture();
  valid.env.GH_TOKEN = "synthetic-metadata";
  const prepare = valid.options.owner.prepare;
  valid.options.owner.prepare = async (...args) => {
    assert.equal(args[3].env.GH_TOKEN, undefined);
    return prepare(...args);
  };
  for (const name of ["prepare", "setup", "probe", "cleanup", "report"])
    assert.equal(await valid.stage(name), true, name);
  assert.equal(
    valid.files.get("/synthetic/native-system/native-job.json").failure,
    null,
  );
  assert.equal(valid.events.at(-1).report.experimentStatus, "PASS");
  assert.equal(valid.events.at(-1).report.decision, "BLOCKED");
  assert.equal(
    valid.files.get("/synthetic/native-system/native-job.json").provenance,
    undefined,
  );
  await assert.rejects(valid.stage("probe"));
  for (const platform of ["linux", "darwin", "win32"]) {
    const bounds = systemJobBounds(platform, 7),
      inventory = nativeExperimentInventory(platform);
    assert.ok(
      bounds.probeMs >=
        inventory.cases.reduce(
          (sum, entry) => sum + entry.deadlineMs + 60000,
          0,
        ),
    );
    assert.ok(bounds.cleanupMs >= inventory.cases.length * 30000);
  }
});

test("ordinary Linux preparation installs the fixed hosted recipe once and retains actual package failures", async () => {
  const feasibility = await readFile(
      new URL(
        "../../.github/workflows/native-feasibility.yml",
        import.meta.url,
      ),
      "utf8",
    ),
    expected = [...feasibility.matchAll(/sudo apt-get ([^\n]+)/gu)].map(
      (match) => match[1].split(" "),
    );
  assert.equal(expected.length, 2);
  for (const failedOperation of ["update", "install", null]) {
    const f = stageFixture("linux"),
      calls = [];
    await initializeExperimentCI(
      f.files.get("/synthetic/native-system/native-job.json"),
      f.directory,
      f.controller,
    );
    f.controller.command = async (file, args, timeout) => {
      if (file === "git") return { stdout: C };
      assert.equal(file, "/usr/bin/sudo");
      assert.deepEqual(args.slice(0, 3), [
        "--non-interactive",
        "--",
        "/usr/bin/apt-get",
      ]);
      assert.equal(timeout, args[3] === "update" ? 60000 : 90000);
      const receipt = f.files.get(
        "/synthetic/native-system/linux-experiment-packages.json",
      );
      assert.equal(receipt.status, "POSSIBLE");
      assert.equal(receipt.operation, args[3]);
      assert.equal(receipt.context.candidateSha, C);
      assert.equal(receipt.context.runId, "1");
      calls.push(args.slice(3));
      if (args[3] === failedOperation)
        throw Object.assign(new Error("Injected package failure"), { code: 7 });
      return { stdout: "" };
    };
    f.options.prepareNamespaces = async (context, directory) => {
      assert.equal(directory, f.directory);
      assert.deepEqual(context, {
        candidateSha: C,
        runId: "1",
        runAttempt: "1",
      });
      assert.equal(
        f.files.get("/synthetic/native-system/linux-experiment-packages.json")
          .status,
        "PASS",
      );
      f.events.push("namespace-policy");
      return { status: "PASS" };
    };
    assert.equal(await f.stage("prepare-linux"), failedOperation === null);
    assert.deepEqual(
      calls,
      expected.slice(0, failedOperation === "update" ? 1 : 2),
    );
    const receipt = f.files.get(
      "/synthetic/native-system/linux-experiment-packages.json",
    );
    assert.equal(receipt.status, failedOperation ? "FAIL" : "PASS");
    assert.equal(receipt.exitCode, failedOperation ? 7 : 0);
    assert.equal(
      f.events.includes("namespace-policy"),
      failedOperation === null,
    );
    assert.equal(
      f.files.has("/synthetic/native-system/linux-preparation.json"),
      false,
    );
    assert.equal(
      f.files.has("/synthetic/native-system/linux-experiment-trust.json"),
      false,
    );
    if (failedOperation === null) {
      assert.equal(await f.stage("prepare"), true);
    } else {
      const failure = f.files.get(
        "/synthetic/native-system/native-first-failure.json",
      );
      assert.equal(failure.stage, "prepare-linux");
      assert.equal(await f.stage("prepare"), false);
      assert.equal(f.events.includes("prepare"), false);
      assert.equal(await f.stage("report"), false);
      assert.deepEqual(f.events.at(-1).report.firstFailures, [failure]);
    }
  }
});

test("Linux hosted admission, package intent and cancellation fence package effects and namespace preparation", async () => {
  for (const fault of ["host", "context", "status", "intent", "cancel"]) {
    const f = stageFixture("linux"),
      effects = [],
      abort = new AbortController();
    await initializeExperimentCI(
      f.files.get("/synthetic/native-system/native-job.json"),
      f.directory,
      f.controller,
    );
    const packageFile =
        "/synthetic/native-system/linux-experiment-packages.json",
      receipt = f.files.get(packageFile),
      persist = f.controller.persistJSON;
    if (fault === "context") receipt.context.runId = "2";
    if (fault === "status") receipt.status = "PASS";
    f.controller.persistJSON = async (file, value, ...args) => {
      if (file === packageFile && value.status === "POSSIBLE") {
        if (fault === "intent") throw new Error("intent refusal");
        if (fault === "cancel") abort.abort();
      }
      return persist(file, value, ...args);
    };
    f.controller.command = async (file) => {
      if (file === "git") return { stdout: C };
      effects.push("package");
      return { stdout: "" };
    };
    f.options.prepareNamespaces = async () => {
      effects.push("namespace");
      return { status: "PASS" };
    };
    if (fault === "host") f.env.RUNNER_ENVIRONMENT = "self-hosted";
    f.options.bound = (work) => work(abort.signal);
    assert.equal(await f.stage("prepare-linux"), false, fault);
    assert.deepEqual(effects, [], fault);
    assert.equal(
      f.files.get("/synthetic/native-system/experiment-stages.json").stages[
        "prepare-linux"
      ],
      "FAIL",
      fault,
    );
  }
});

test("failed Linux package receipt persistence preserves the original command failure", async () => {
  const f = stageFixture("linux"),
    original = Object.assign(new Error("package command failed"), { code: 9 });
  await initializeExperimentCI(
    f.files.get("/synthetic/native-system/native-job.json"),
    f.directory,
    f.controller,
  );
  const persist = f.controller.persistJSON;
  f.controller.persistJSON = async (file, value, ...args) => {
    if (
      file.endsWith("linux-experiment-packages.json") &&
      value.status === "FAIL"
    )
      throw new Error("failure receipt unavailable");
    return persist(file, value, ...args);
  };
  f.controller.command = async (file) => {
    if (file === "git") return { stdout: C };
    throw original;
  };
  f.options.prepareNamespaces = async () =>
    assert.fail("No namespace admission");
  let observed;
  f.options.bound = async (work) => {
    try {
      return await work(new AbortController().signal);
    } catch (error) {
      observed = error;
      throw error;
    }
  };
  assert.equal(await f.stage("prepare-linux"), false);
  assert.equal(observed, original);
  assert.equal(
    f.files.get("/synthetic/native-system/linux-experiment-packages.json")
      .status,
    "POSSIBLE",
  );
  assert.equal(
    f.files.get("/synthetic/native-system/native-first-failure.json").stage,
    "prepare-linux",
  );
});

test("Linux namespace cleanup failure reaches the experiment report without replacing its first cause", async () => {
  for (const previousFailure of [false, true]) {
    const f = stageFixture("linux");
    if (previousFailure) assert.equal(await f.stage("setup"), false);
    f.env.NATIVE_NAMESPACE_CLEANUP_OUTCOME = "failure";
    assert.equal(await f.stage("report"), false);
    const report = f.events.at(-1).report;
    assert.equal(report.experimentStatus, "FAIL");
    assert.equal(
      report.firstFailures[0].stage,
      previousFailure ? "setup" : "cleanup",
    );
    assert.equal(report.cleanupFailures[0].diagnosis, "namespace-policy");
  }
});

test("cleanup closes experiment admission before any later probe or preparation stage", async () => {
  const f = stageFixture();
  let probes = 0;
  f.options.owner.probe = async () => {
    probes++;
    return f.f.job;
  };
  assert.equal(await f.stage("prepare"), true);
  assert.equal(await f.stage("setup"), true);
  assert.equal(await f.stage("cleanup"), true);
  await assert.rejects(f.stage("probe"));
  await assert.rejects(f.stage("prepare-linux"));
  assert.equal(probes, 0);
  assert.equal(await f.stage("cleanup"), true);
  assert.equal(await f.stage("report"), false);
});

test("experiment stage failure retains its first cause, recovers only admissions and reports separate cleanup failure", async () => {
  const f = stageFixture();
  assert.equal(await f.stage("setup"), false);
  const first = structuredClone(
    f.files.get("/synthetic/native-system/native-first-failure.json"),
  );
  assert.equal(first.schemaVersion, 2);
  assert.equal(first.stage, "setup");
  assert.equal(first.purpose, "experiment");
  assert.equal(await f.stage("prepare"), false);
  f.controller.listMetadata = async () => [];
  assert.equal(await f.stage("cleanup"), false);
  assert.deepEqual(
    f.files.get("/synthetic/native-system/native-first-failure.json"),
    first,
  );
  assert.equal(
    f.files.get("/synthetic/native-system/native-cleanup-failure.json").stage,
    "cleanup",
  );
  assert.equal(await f.stage("report"), false);
  assert.equal(f.events.at(-1).report.firstFailures[0].stage, "setup");
  assert.equal(f.events.at(-1).report.cleanupFailures[0].stage, "cleanup");
  assert.equal(f.events.includes("prepare"), false);
});

test("a stage deadline fences late native publication without replacing the first failure", async () => {
  const f = stageFixture();
  let late;
  const entered = Promise.withResolvers();
  f.options.owner.prepare = async (_, __, persist) => {
    late = () => persist(f.f.job);
    entered.resolve();
    return new Promise(() => {});
  };
  f.options.bound = async (work) => {
    const controller = new AbortController();
    void work(controller.signal).catch(() => {});
    await entered.promise;
    controller.abort();
    throw new Error("Controlled execution deadline");
  };
  assert.equal(await f.stage("prepare"), false);
  const original = structuredClone(
    f.files.get("/synthetic/native-system/native-job.json"),
  );
  await assert.rejects(late());
  assert.deepEqual(
    f.files.get("/synthetic/native-system/native-job.json"),
    original,
  );
  normalizeExperimentJob(original);
});

test("a deadline waits for an in-flight admission write before retaining its first cause", async () => {
  const f = stageFixture(),
    entered = Promise.withResolvers(),
    release = Promise.withResolvers(),
    expired = Promise.withResolvers();
  const persist = f.controller.persistJSON;
  f.controller.persistJSON = async (file, value) => {
    if (
      file.endsWith("native-job.json") &&
      value.preparationEffects.admission === "possible" &&
      value.failure === null
    ) {
      entered.resolve();
      await release.promise;
    }
    await persist(file, value);
  };
  f.options.owner.prepare = async (job, _, save) =>
    save(
      recordExperimentPreparationEffect(job, {
        admission: "possible",
        settlement: retained,
        receiptSha256: null,
      }),
    );
  f.options.bound = async (work) => {
    const controller = new AbortController();
    void work(controller.signal).catch(() => {});
    await entered.promise;
    controller.abort();
    expired.resolve();
    throw new Error("Controlled deadline");
  };
  const running = f.stage("prepare");
  await expired.promise;
  release.resolve();
  assert.equal(await running, false);
  assert.equal(
    f.files.get("/synthetic/native-system/native-first-failure.json").admission,
    "possible",
  );
  assert.equal(
    f.files.get("/synthetic/native-system/native-job.json").preparationEffects
      .admission,
    "possible",
  );
  assert.equal(
    f.files.get("/synthetic/native-system/native-job.json").failure,
    "preparation-failed",
  );
});

test("a Linux prerequisite deadline fences late package receipts and subsequent policy installation", async () => {
  const f = stageFixture("linux"),
    entered = Promise.withResolvers(),
    release = Promise.withResolvers();
  await initializeExperimentCI(
    f.files.get("/synthetic/native-system/native-job.json"),
    f.directory,
    f.controller,
  );
  let pending,
    installations = 0;
  f.controller.command = async (file) => {
    if (file === "git") return { stdout: C };
    entered.resolve();
    await release.promise;
    return { stdout: "" };
  };
  f.options.prepareNamespaces = async () => {
    installations++;
    return { status: "PASS" };
  };
  f.options.bound = async (work) => {
    const controller = new AbortController();
    pending = work(controller.signal);
    pending.catch(() => {});
    await entered.promise;
    controller.abort();
    throw nativePreparationError("deadline");
  };
  assert.equal(await f.stage("prepare-linux"), false);
  const receipt = structuredClone(
    f.files.get("/synthetic/native-system/linux-experiment-packages.json"),
  );
  release.resolve();
  await assert.rejects(pending);
  assert.deepEqual(
    f.files.get("/synthetic/native-system/linux-experiment-packages.json"),
    receipt,
  );
  assert.equal(installations, 0);
  assert.equal(
    f.files.get("/synthetic/native-system/native-first-failure.json").diagnosis,
    "deadline",
  );
  assert.ok(
    systemJobBounds("linux", 7).bootstrapMinutes * 60000 >= 150000 + 120000,
  );
});

test("Linux startup intent precedes validation, reference publication and native release despite lost replies", async () => {
  for (const fault of [
    "preflight",
    "reference",
    "admission",
    "native",
    "diagnostic",
  ]) {
    const f = fixture("linux"),
      events = [],
      failure = new Error(`Controlled ${fault} failure`),
      namespace = {
        status: "PASS",
        candidateSha: C,
        runId: "1",
        runAttempt: "1",
        before: { executable: { sha256: H, version: "synthetic" } },
      };
    const job = structuredClone(f.job);
    const buildRecord = { schemaVersion: 2, purpose: "experiment" };
    job.preparationEffects.receiptSha256 = observationDigest(buildRecord);
    for (const preparation of [
      job.preparation.expected,
      job.preparation.observed,
    ]) {
      preparation.sources.push({
        id: "namespace-binding",
        sha256: observationDigest(namespace),
      });
    }
    const journal = linuxProofJournal(job, false),
      context = { candidateSha: C, runId: "1", runAttempt: "1" };
    let reference,
      latest,
      time = 0,
      lost = false;
    const persistProof = async (proof) => {
      journal.proof = structuredClone(proof);
      events.push(proof.releasePossible ? "release-intent" : "startup-intent");
    };
    const env = {
      CI: "true",
      GITHUB_ACTIONS: "true",
      ImageOS: "ubuntu24",
      RUNNER_ENVIRONMENT: "github-hosted",
      RUNNER_OS: "Linux",
      GITHUB_REPOSITORY: "example/native",
      GITHUB_RUN_ID: "1",
      GITHUB_RUN_ATTEMPT: "1",
    };
    const result = await runLinuxExperimentProofs(job, "/synthetic", {
      env,
      platform: "linux",
      architecture: "x64",
      nodeVersion: "v24.21.0",
      now: () => time,
      identity: async () => journal.proof.owner.identity,
      persistProof,
      persist: async (value) => {
        latest = value;
        if (value.cases[0]?.effects.policy.admission === "possible") {
          events.push("case-admission");
          assert.ok(events.includes("reference"));
          assert.ok(
            events.indexOf("reference") < events.indexOf("case-admission"),
          );
          if (fault === "admission" && !lost) {
            lost = true;
            throw failure;
          }
        }
      },
      onFailure: async (_, error) => {
        assert.equal(error, failure);
        if (fault === "diagnostic")
          throw new Error("Controlled diagnostic write failure");
      },
      load: async () => {
        assert.equal(events[0], "startup-intent");
        time = 7;
        if (["preflight", "diagnostic"].includes(fault)) throw failure;
        return { record: buildRecord, interpreter: { source: { sha256: H } } };
      },
      read: async () => ({ sha256: H }),
      namespaces: async () => namespace,
      verifyNamespaces: async () => {},
      persistReference: async (value) => {
        events.push("reference");
        reference = value;
        if (fault === "reference") throw failure;
      },
      run: async (value, _, settings) => {
        time = 11;
        assert.equal(fault, "native");
        assert.ok(events.includes("case-admission"));
        await settings.persist(
          recordNativeAdmission(value, "ownership", { purpose: "experiment" }),
        );
        throw failure;
      },
    }).catch((error) => {
      assert.equal(fault, "diagnostic");
      assert.equal(error, failure);
      return latest;
    });
    assert.equal(result.failure, "probe-failed");
    assert.equal(
      result.cases.length,
      ["admission", "native"].includes(fault) ? 1 : 0,
    );
    if (result.cases.length)
      assert.equal(result.cases[0].elapsedMs, fault === "native" ? 11 : 7);
    assert.equal(
      linuxNamespaceSettlement(result, context, "system", journal),
      false,
    );
    let reconciliations = 0;
    const recovered = await recoverLinuxExperimentProofs(
      result,
      "/synthetic",
      async () => {},
      {
        env,
        platform: "linux",
        architecture: "x64",
        proofJournal: journal,
        persistProof,
        fence: async () => {},
        visible: async () => {},
        identity: async () => null,
        fs: {
          lstat: async () => {
            throw Object.assign(new Error("Absent owner"), { code: "ENOENT" });
          },
        },
        reconcilePreparation: async () => {
          reconciliations++;
        },
        rejoinInterpreter: async () => null,
        read: async (file) => {
          if (reference && file.endsWith("experiment-reference.json"))
            return JSON.stringify({
              purpose: "experiment",
              preparationSha256: journal.proof.preparationSha256,
              owner: journal.proof.owner,
              job: reference,
            });
          throw Object.assign(new Error("Missing original evidence"), {
            code: "ENOENT",
          });
        },
      },
    );
    assert.equal(reconciliations, 1);
    assert.equal(recovered.failure, "probe-failed");
    assert.equal(
      linuxNamespaceSettlement(recovered, context, "system", journal),
      fault !== "native",
    );
    journal.stages.cleanup = "FAIL";
    assert.equal(
      linuxNamespaceSettlement(recovered, context, "system", journal),
      false,
    );
  }
});

test("Linux cleanup dispatches zero-case started proofs and retains their original failure", async () => {
  for (const failedRecovery of [false, true]) {
    const f = stageFixture("linux"),
      file = path.join(f.directory, "experiment-stages.json");
    const persist = f.controller.persistJSON;
    f.controller.persistJSON = async (name, value, settings) => {
      if (name === file) assert.equal(settings.mode, 0o600);
      await persist(name, value, settings);
    };
    f.files.set(path.join(f.directory, "native-job.json"), f.f.job);
    f.files.set(file, {
      ...linuxProofJournal(f.f.job),
      stages: { setup: "PASS" },
    });
    delete f.files.get(file).proof;
    f.options.owner.probe = async (job, _, settings) => {
      assert.equal(f.files.get(file).proof.owner, null);
      await settings.persistProof(linuxProofJournal(job, false).proof);
      throw new Error("Original startup rejection");
    };
    f.options.owner.recover = async (job, _, __, settings) => {
      assert.equal(job.cases.length, 0);
      f.events.push("zero-case-recovery");
      if (failedRecovery)
        throw new Error("Original operation remains uncertain");
      await settings.persistProof({
        ...settings.proofJournal.proof,
        retirementSha256: H,
      });
      return job;
    };
    assert.equal(await f.stage("probe"), false);
    const first = structuredClone(
      f.files.get(path.join(f.directory, "native-first-failure.json")),
    );
    assert.equal(await f.stage("cleanup"), !failedRecovery);
    assert.ok(f.events.includes("zero-case-recovery"));
    assert.deepEqual(
      f.files.get(path.join(f.directory, "native-first-failure.json")),
      first,
    );
  }
  const missing = stageFixture("linux"),
    journal = path.join(missing.directory, "experiment-stages.json");
  missing.files.delete(journal);
  await assert.rejects(missing.stage("cleanup"));
  assert.equal(missing.files.has(journal), false);
});

test("Linux proof recovery binds the original purpose, writer and native receipts before namespace release", async () => {
  const f = fixture("linux"),
    recipe = f.inventory.cases[0],
    context = { candidateSha: C, runId: "1", runAttempt: "1" },
    effects = Object.fromEntries(
      NATIVE_EFFECT_CLASSES.map((key) => [
        key,
        {
          admission: NATIVE_GROUPS.linux.reference.effects.includes(key)
            ? "possible"
            : "not-started",
          settlement: retained,
          receiptSha256: null,
        },
      ]),
    );
  const failed = normalizeExperimentJob({
    ...f.job,
    cases: [
      {
        purpose: "experiment",
        id: recipe.id,
        preparationSha256: observationDigest(f.job.preparation),
        status: "FAIL",
        elapsedMs: 1,
        cleanupMs: null,
        policy: {
          expectedSha256: H,
          observedSha256: null,
          independent: false,
          effective: false,
        },
        components: null,
        observations: [],
        effects,
      },
    ],
    failure: "probe-failed",
  });
  let reference = recordNativeStage(
    initializeNativeJob(
      {
        candidateSha: C,
        platform: "linux",
        repository: "example/native",
        runId: "1",
        runAttempt: 1,
      },
      { schemaVersion: 5 },
    ),
    "setup",
    { status: "PASS", elapsedMs: 0, deadlineMs: 120000, reason: null },
    {
      checkoutSha: C,
      observed: {
        os: "linux",
        image: "ubuntu-24.04",
        build: "synthetic",
        architecture: "x64",
      },
      provenance: {
        repository: "example/native",
        runId: "1",
        runAttempt: 1,
        workflow: "native-poc.yml",
        jobId: "2",
      },
      versions: [{ name: "node", version: "v24.21.0", sha256: H }],
    },
  );
  reference = {
    ...reference,
    purpose: "experiment",
    buildObservationSha256: f.job.preparationEffects.receiptSha256,
  };
  reference = recordNativeSettlement(
    recordNativeAdmission(reference, "ownership", { purpose: "experiment" }),
    "ownership",
    retired,
    { purpose: "experiment" },
  );
  const envelope = {
      purpose: "experiment",
      preparationSha256: observationDigest(f.job.preparation),
      owner: {
        pid: 77,
        identity: {
          bootId: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
          startTicks: "1",
        },
      },
      job: reference,
    },
    names = [
      "argv",
      "cancel",
      "owner-loss",
      "supervisor-loss",
      "launcher-loss",
    ].map((id) => id + ".json");
  let saved;
  const journal = linuxProofJournal(failed);
  const base = {
    proofJournal: journal,
    persistProof: async (proof) => {
      journal.proof = structuredClone(proof);
    },
    reconcilePreparation: async () => {},
    rejoinInterpreter: async () => null,
    env: {
      CI: "true",
      GITHUB_ACTIONS: "true",
      ImageOS: "ubuntu24",
      RUNNER_ENVIRONMENT: "github-hosted",
      RUNNER_OS: "Linux",
      GITHUB_REPOSITORY: "example/native",
      GITHUB_RUN_ID: "1",
      GITHUB_RUN_ATTEMPT: "1",
    },
    platform: "linux",
    architecture: "x64",
    fence: async (value) => assert.equal(value.purpose, "experiment"),
    visible: async () => {},
    identity: async () => null,
    fs: {
      lstat: async () => {
        throw Object.assign(new Error("Absent owner"), { code: "ENOENT" });
      },
      readdir: async () => names,
    },
    read: async (file) =>
      file.endsWith(".sentinel")
        ? "dddddddd-dddd-dddd-dddd-dddddddddddd"
        : JSON.stringify(
            file.endsWith("experiment-reference.json")
              ? envelope
              : { native: "synthetic" },
          ),
    receipt: async (file) => ({
      candidateSha: C,
      nonce: "dddddddd-dddd-dddd-dddd-dddddddddddd",
      caseId: file.split("/").at(-1).slice(0, -5),
    }),
    verify: async () => retired,
  };
  assert.equal(linuxNamespaceSettlement(failed, context, "system"), false);
  const recovered = await recoverLinuxExperimentProofs(
    failed,
    "/synthetic",
    async (value) => {
      saved = value;
    },
    base,
  );
  assert.equal(
    linuxNamespaceSettlement(recovered, context, "system", journal),
    true,
  );
  assert.equal(saved.failure, "probe-failed");
  assert.equal(saved.cases[0].status, "FAIL");
  assert.deepEqual(saved.cases[0].observations, failed.cases[0].observations);
  const nonce = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
    helper = `file-helper-${nonce}`,
    fileCase = `file-cases-${nonce}`,
    session = {
      nonce,
      anchorName: `file-${nonce}`,
      receiptDigest: observationDigest({ native: "synthetic" }),
      storage: "REMOVED",
      exclusion: "RELEASED",
      settlement: retired,
    },
    records = {
      [`${helper}-terminal.json`]: session,
      [`${fileCase}-0.json`]: {
        candidateSha: C,
        type: "admission",
        checkId: "files.complete",
        sequence: 0,
      },
      [`${fileCase}-1.json`]: {
        candidateSha: C,
        type: "session",
        checkId: "files.complete",
        sequence: 0,
        result: session,
      },
    },
    fileJob = failed,
    fileOptions = {
      ...base,
      fs: {
        ...base.fs,
        readdir: async () => [
          ...names,
          helper + ".json",
          helper + "-result.json",
          ...Object.keys(records),
        ],
      },
      read: async (file) =>
        file.endsWith("experiment-reference.json")
          ? JSON.stringify({
              ...envelope,
              job: recordNativeAdmission(reference, "file-helper", {
                purpose: "experiment",
              }),
            })
          : file.endsWith(".sentinel")
            ? "dddddddd-dddd-dddd-dddd-dddddddddddd"
            : JSON.stringify(
                records[file.split("/").at(-1)] ?? { native: "synthetic" },
              ),
      receipt: async (file) => ({
        candidateSha: C,
        nonce: file.includes(helper)
          ? nonce
          : "dddddddd-dddd-dddd-dddd-dddddddddddd",
        caseId: file.includes(helper)
          ? "file-helper"
          : file.split("/").at(-1).slice(0, -5),
      }),
    };
  assert.equal(
    linuxNamespaceSettlement(
      await recoverLinuxExperimentProofs(
        fileJob,
        "/synthetic",
        async () => {},
        fileOptions,
      ),
      context,
      "system",
      journal,
    ),
    true,
  );
  delete records[`${fileCase}-1.json`];
  assert.equal(
    linuxNamespaceSettlement(
      await recoverLinuxExperimentProofs(
        fileJob,
        "/synthetic",
        async () => {},
        fileOptions,
      ),
      context,
      "system",
      journal,
    ),
    false,
  );
  for (const options of [
    { identity: async () => envelope.owner.identity },
    { verify: async () => retained },
    { verify: async () => ({ ...retired, emergencyCleanup: true }) },
    { receipt: async () => ({ candidateSha: "c".repeat(40), caseId: "argv" }) },
    {
      read: async () => {
        throw Object.assign(new Error("Missing receipt"), { code: "ENOENT" });
      },
    },
    { read: async () => JSON.stringify({ ...envelope, purpose: "reviewed" }) },
    {
      read: async () =>
        JSON.stringify({
          ...envelope,
          job: {
            ...reference,
            admissions: {
              ...reference.admissions,
              "file-build": { admission: "possible", settlement: retired },
            },
          },
        }),
    },
  ]) {
    const uncertain = await recoverLinuxExperimentProofs(
      failed,
      "/synthetic",
      async () => {},
      { ...base, ...options },
    );
    assert.equal(
      linuxNamespaceSettlement(uncertain, context, "system", journal),
      false,
    );
    assert.equal(uncertain.failure, "probe-failed");
  }
});

test("indexed Darwin/Windows experiment loops persist every recipe including build and all 23 checks", async () => {
  for (const platform of ["darwin", "win32"]) {
    const f = fixture(platform),
      load = f.options.load;
    f.options.env = { RUNNER_TEMP: "/synthetic" };
    if (platform === "win32")
      f.options.env = {
        ...f.options.env,
        systemroot: "C:\\Windows",
        "PROGRAMFILES(X86)": "C:\\Program Files (x86)",
        gh_token: "synthetic-metadata",
        Git_Dir: "foreign-repository",
      };
    f.options.load = async (job, directory, options) => {
      assert.equal(
        directory,
        path.join(
          "/synthetic",
          `native-${platform}-experiment-${observationDigest(Object.fromEntries(["candidateSha", "platform", "repository", "runId", "runAttempt"].map((key) => [key, f.job[key]])))}`,
        ),
      );
      assert.equal(
        options.bootstrapJournal,
        platform === "win32" ? "/synthetic/native-system/native" : undefined,
      );
      if (platform === "win32") {
        assert.equal(options.env.SystemRoot, "C:\\Windows");
        assert.equal(
          options.env["ProgramFiles(x86)"],
          "C:\\Program Files (x86)",
        );
        assert.equal(options.env.gh_token, undefined);
        assert.equal(options.env.Git_Dir, undefined);
        assert.equal(options.env.GIT_CONFIG_GLOBAL, "NUL");
      }
      return load(job, directory, options);
    };
    const job = await runExperimentProofs(
      f.job,
      "/synthetic/native-system",
      f.options,
    );
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

test("Windows fresh cleanup rejoins protected selectors despite missing final outputs without replaying failed cases", async () => {
  const f = fixture("win32", "cleanup", "10.0.26100"),
    failed = await f.run(f.job, "/synthetic", f.options),
    directory = windowsPath.join("C:\\Fixture\\report", "native"),
    bootstrap = {
      context: { candidateSha: C, runId: "1", runAttempt: 1 },
    },
    prepared = {
      purpose: "experiment",
      job: failed,
      directory,
      output: windowsPath.join(directory, "platform-build"),
      bootstrap,
      helpers: f.inventory.helpers.map((name) => ({
        name,
        sha256: H,
        sourceSha256: H,
      })),
      sources: [
        ...f.inventory.helpers.map((name) => name + ".c"),
        "custody.h",
        "effective-reader.h",
        "account.h",
        "audit-policy-remove.h",
        "experiment.h",
      ].map((name) => ({ name, sha256: H })),
      tools: [
        {
          name: "compiler",
          path: "C:\\Program Files\\Microsoft Visual Studio\\2022\\BuildTools\\VC\\Tools\\MSVC\\14.0\\bin\\Hostx64\\x64\\cl.exe",
          sha256: H,
          signatureSha256: H,
        },
        {
          name: "sdk",
          path: "C:\\Program Files (x86)\\Windows Kits\\10\\bin\\10.0\\x64\\rc.exe",
          sha256: H,
          signatureSha256: H,
        },
      ],
    },
    observer = {
      nonce: "c".repeat(32),
      taskSha256: H,
      helper: { pid: 10 },
      bridge: { pid: 11 },
    },
    records = new Map([
      [
        "windows-experiment-preparation.json",
        { prepared, observation: failed.preparation },
      ],
      [
        "windows-experiment-close.json",
        {
          purpose: "experiment",
          bootstrapSettlement: { ...retired, nativeEventSha256: H },
          observer,
        },
      ],
      [
        `windows-files-${observer.nonce}-birth.json`,
        { ...observer, status: "POSSIBLE" },
      ],
      [
        `windows-files-${observer.nonce}-result.json`,
        { ...observer, status: "RETIRED" },
      ],
    ]);
  let saved,
    requests = 0,
    closed = 0;
  const options = {
    platform: "win32",
    architecture: "x64",
    nodeVersion: "v24.21.0",
    env: {
      CI: "true",
      GITHUB_ACTIONS: "true",
      ImageOS: "win25",
      RUNNER_ENVIRONMENT: "github-hosted",
      RUNNER_OS: "Windows",
      GITHUB_REPOSITORY: failed.repository,
      GITHUB_RUN_ID: failed.runId,
      GITHUB_RUN_ATTEMPT: String(failed.runAttempt),
    },
    readdir: async (parent) => {
      assert.equal(parent, windowsPath.dirname(directory));
      return ["native-bootstrap-0.json"];
    },
    read: async (file) => {
      assert.equal(
        file,
        windowsPath.join(
          windowsPath.dirname(directory),
          "native-bootstrap-0.json",
        ),
      );
      return JSON.stringify({ ...prepared, phase: "bootstrap-seal-possible" });
    },
    // Normal loading cannot validate missing final outputs. Recovery must use
    // the protected selector reads below before invoking its native owner.
    load: async () => {
      throw Object.assign(new Error("Final output unavailable"), {
        code: "ENOENT",
      });
    },
    files: {
      readProtected: async ({ file, receipt }) => {
        assert.equal(receipt, true);
        assert.equal(windowsPath.dirname(file), directory);
        const record = records.get(windowsPath.basename(file));
        if (!record)
          throw Object.assign(new Error("Final output unavailable"), {
            code: "ENOENT",
          });
        return { bytes: Buffer.from(JSON.stringify(record)) };
      },
      settleFiles: async () => {
        closed++;
        return { ...retired, nativeEventSha256: H };
      },
    },
    createEffects: () => ({
      recover: async ({ request, job, preparation }) => {
        requests++;
        assert.deepEqual(job, failed);
        assert.deepEqual(preparation.prepared, prepared);
        assert.equal(closed, requests);
        assert.equal(request.jobSha256, observationDigest(job));
        assert.equal(request.preparationSha256, observationDigest(preparation));
        return { ...retired, nativeEventSha256: H };
      },
    }),
  };
  const recovered = await recoverWindowsExperimentProofs(
    failed,
    directory,
    async (value) => {
      saved = value;
    },
    options,
  );
  assert.equal(requests, 1);
  assert.equal(saved, recovered);
  assert.equal(recovered.failure, failed.failure);
  assert.equal(recovered.cases.at(-1).status, "FAIL");
  assert.deepEqual(
    recovered.cases.at(-1).observations,
    failed.cases.at(-1).observations,
  );
  assert.ok(
    Object.values(recovered.cases.at(-1).effects).every(
      (effect) =>
        effect.admission === "not-started" ||
        effect.settlement.status === "RETIRED",
    ),
  );
  await assert.rejects(
    recoverWindowsExperimentProofs(failed, directory, async () => {}, {
      ...options,
      createEffects: () => ({ recover: async () => retained }),
    }),
  );
  records.set("windows-experiment-preparation.json", {
    prepared: {
      ...prepared,
      bootstrap: {
        ...bootstrap,
        context: { ...bootstrap.context, runId: "2" },
      },
    },
  });
  await assert.rejects(
    recoverWindowsExperimentProofs(failed, directory, async () => {}, options),
  );
  assert.equal(requests, 1);
  assert.equal(closed, 3);
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
