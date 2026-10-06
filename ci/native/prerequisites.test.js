import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { posix, win32 } from "node:path";
import {
  normalizeNativePrerequisites,
  materializeBootstrapAssets,
} from "./prerequisites.js";
import {
  normalizeNativePackageReview,
  nativePackageReviewDigest,
  nativePackageInput,
  nativePackageReadiness,
} from "./package-inputs.js";
import { prepareReviewedNativePackage } from "./package-acquisition.js";
import { materializeReviewedGit } from "./package-extraction.js";
import { observationDigest } from "./observation.js";
import {
  nativePolicyContext,
  nativePolicyTemplateDigest,
  materializeNativePolicy,
} from "./policy-template.js";
import { CODEX_RELEASE_REFERENCE } from "./package-catalog.js";
import {
  prepareSystemCI,
  normalizeSystemPreparation,
  verifySystemCIInputFiles,
} from "./system-ci.js";
import { nativePreparationError } from "./first-failure.js";
import { WINDOWS_HELPER_NAMES, windowsSystemRecipes } from "./win32/index.js";
import {
  createPosixPrerequisiteFiles,
  prerequisiteCreationRequest,
} from "./prerequisite-files.js";
import { createWindowsPrerequisiteFiles } from "./prerequisite-windows.js";

const candidateSha = "a".repeat(40),
  bytes = Buffer.from("reviewed fixture"),
  hash = createHash("sha256").update(bytes).digest("hex");
const bindings = (tools) => ({
  source: hash,
  build: hash,
  toolchain: observationDigest(tools),
  loader: hash,
});
const context = nativePolicyContext(
  {
    candidateSha,
    platform: "win32",
    tier: "system",
    provenance: {
      repository: "example/native",
      workflow: "native-poc.yml",
      runId: "1",
      runAttempt: 1,
      jobId: "1",
    },
    closure: { manifestSha256: hash },
  },
  "package.git-for-windows",
);
const template = {
  schemaVersion: 1,
  candidateSha,
  platform: "win32",
  sourceReviewSha256: hash,
  provisioningReviewSha256: hash,
  policy: { launch: { fixed: true }, policy: { fixed: true } },
  bindings: [],
};
const extraction = (tools = []) => ({
  schemaVersion: 1,
  candidateSha,
  extractor: {
    path: "C:\\Fixture\\temp\\bootstrap\\package-extractor.exe",
    bytes: bytes.length,
    sha256: hash,
    bindings: bindings(tools),
  },
  policyBinding: {
    template,
    approval: {
      candidateSha,
      platform: "win32",
      authority: "operator-protected",
      manifestSha256: nativePolicyTemplateDigest(template),
    },
    context,
  },
});
function review(packageId, tools = []) {
  const input = nativePackageInput(packageId),
    reference = {
      url: "https://example.org/review",
      revision: null,
      sha256: hash,
    },
    value = {
      schemaVersion: packageId === "git-for-windows" ? 2 : 1,
      candidateSha,
      packageId,
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
          key === "source" && input.sourceRevision
            ? {
                url: CODEX_RELEASE_REFERENCE.sourceUrl,
                revision: input.sourceRevision,
                sha256: hash,
              }
            : reference,
        ]),
      ),
      files: [
        {
          path: input.entrypoint ?? "usr/bin/bash.exe",
          bytes: bytes.length,
          sha256: hash,
          executable: true,
        },
      ],
    };
  if (packageId === "git-for-windows") {
    value.entrypoint = "usr/bin/bash.exe";
    value.extraction = extraction(tools);
    value.bindings.extraction = {
      ...reference,
      sha256: nativePackageReviewDigest(value.extraction),
    };
  }
  return normalizeNativePackageReview(value, candidateSha);
}
function fixture(platform = "linux") {
  const paths = platform === "win32" ? win32 : posix,
    root = platform === "win32" ? "C:\\Fixture\\temp" : "/fixture/temp",
    sources =
      platform === "linux"
        ? ["helper"]
        : platform === "darwin"
          ? ["custody-reader", "build-helper", "launcher"]
          : [...WINDOWS_HELPER_NAMES],
    tools = ["compiler", "sdk"].map((name) => ({
      name,
      path: paths.join(root, name),
      bytes: bytes.length,
      sha256: hash,
      version: "fixture tool",
    })),
    images =
      platform === "linux"
        ? []
        : [...sources, ...(platform === "win32" ? ["package-extractor"] : [])],
    headers =
      platform === "linux"
        ? []
        : platform === "darwin"
          ? ["custody.h", "file-identity.h", "effective-reader.h"]
          : ["custody.h", "effective-reader.h"],
    assets = [
      ...images.map((name) => ({
        name,
        kind: "image",
        member: "bootstrap/" + name + (platform === "win32" ? ".exe" : ""),
        path: paths.join(
          root,
          "bootstrap",
          name + (platform === "win32" ? ".exe" : ""),
        ),
        bytes: bytes.length,
        sha256: hash,
        bindings: bindings(tools),
      })),
      ...[...sources.map((name) => name + ".c"), ...headers].map((name) => ({
        name,
        kind: "source",
        member: "bootstrap/" + name,
        path: paths.join(
          root,
          platform === "win32" ? "bootstrap" : "sources",
          name,
        ),
        bytes: bytes.length,
        sha256: hash,
        bindings: bindings(tools),
      })),
    ],
    packages = [
      "codex-" + platform,
      "claude-" + platform,
      ...(platform === "win32" ? ["git-for-windows"] : []),
    ].map((packageId) => {
      const reviewed = review(packageId, tools);
      return {
        packageId,
        directory: paths.join(root, packageId),
        reviewed,
        approvedReviewSha256: nativePackageReviewDigest(reviewed),
      };
    }),
    manifest = {
      schemaVersion: 2,
      candidateSha,
      platform,
      tools,
      helpers: sources.map((name) => ({
        name,
        sourceSha256: hash,
        sha256: hash,
      })),
      environment: {},
      release: {
        providers: Object.fromEntries(
          packages
            .filter((entry) => entry.packageId !== "git-for-windows")
            .map((entry) => [
              entry.packageId.split("-")[0],
              { reviewSha256: entry.approvedReviewSha256 },
            ]),
        ),
      },
      inputs: packages.flatMap((entry) =>
        entry.reviewed.files.map((file) => ({
          path: paths.join(entry.directory, "content", ...file.path.split("/")),
          bytes: file.bytes,
          sha256: file.sha256,
        })),
      ),
    };
  manifest.prerequisites = {
    schemaVersion: 1,
    candidateSha,
    platform,
    assets,
    packages,
  };
  const profile = {
    platform,
    sources,
    imageOS: /^fixture$/u,
    extension: "",
    tools: tools.map(({ name }) => ({
      name,
      args: ["--version"],
      versionExitCodes: [],
    })),
    arguments: (source, target) => [source, target],
    api: async () => ({}),
    inspect: () => {},
    inspectProcess: () => {},
  };
  return { paths, root, manifest, profile };
}

test("approved prerequisite metadata requires the fixed assets, complete packages and declared byte counts", () => {
  for (const platform of ["linux", "darwin", "win32"]) {
    const f = fixture(platform);
    assert.doesNotThrow(() =>
      normalizeNativePrerequisites(
        f.manifest.prerequisites,
        f.manifest,
        f.profile,
      ),
    );
    for (const mutate of [
      (value) => value.assets.pop(),
      (value) => {
        value.assets[0].bindings.loader = null;
      },
      (value) => {
        value.assets[0].bytes = 0;
      },
      (value) => value.packages.pop(),
      (value) => {
        value.packages[0].reviewed.bindings.build = null;
      },
      (value) => {
        value.packages[0].approvedReviewSha256 = "0".repeat(64);
      },
    ]) {
      const value = structuredClone(f.manifest.prerequisites);
      mutate(value);
      assert.throws(() =>
        normalizeNativePrerequisites(value, f.manifest, f.profile),
      );
    }
    f.manifest.inputs[0].bytes++;
    assert.throws(() =>
      normalizeNativePrerequisites(
        f.manifest.prerequisites,
        f.manifest,
        f.profile,
      ),
    );
  }
});

test("bootstrap acquisition seals only pinned bytes before any image construction", async () => {
  const f = fixture(),
    plan = normalizeNativePrerequisites(
      f.manifest.prerequisites,
      f.manifest,
      f.profile,
    );
  for (const valid of [true, false]) {
    const events = [];
    const effects = {
      persist: async (record) => ({
        recordSha256: observationDigest(record),
        independent: true,
        held: true,
        immutable: true,
        protectedParents: true,
        birthProtected: true,
        identitySha256: hash,
        nativeEventSha256: hash,
      }),
      sealAsset: async (request, actual) => {
        events.push("seal");
        assert.deepEqual(actual, bytes);
        return {
          requestSha256: observationDigest(request),
          independent: true,
          birthProtected: true,
          protectedParents: true,
          exclusive: true,
          held: true,
          unchanged: true,
          executed: false,
          identitySha256: hash,
          nativeEventSha256: hash,
        };
      },
      verifyAsset: async (request) => ({
        requestSha256: observationDigest(request),
        independent: true,
        held: true,
        unchanged: true,
        readExecuteOnly: true,
        bytes: bytes.length,
        sha256: hash,
        noLiveMembers: true,
        emergencyCleanup: false,
        nativeEventSha256: hash,
      }),
    };
    const operation = materializeBootstrapAssets(plan, {
      env: {
        RUNNER_TEMP: f.root,
        NATIVE_SYSTEM_INPUT_REPOSITORY: "example/reviews",
        NATIVE_SYSTEM_INPUT_REVISION: "b".repeat(40),
      },
      effects,
      read: async () => bytes,
      persist: async () => {
        events.push("possible");
        return async () => events.push("retired");
      },
      fetchInput: async (url, options) => {
        assert.equal(options.redirect, "error");
        assert.equal(options.credentials, "omit");
        return {
          ok: true,
          url,
          headers: new Headers(),
          body: [valid ? bytes : Buffer.from("wrong")],
        };
      },
    });
    if (valid) {
      await operation;
      assert.deepEqual(events, ["possible", "seal", "retired"]);
    } else {
      await assert.rejects(operation);
      assert.deepEqual(events, ["possible"]);
    }
  }
});

test("bootstrap inventory includes the exact independently pinned custody plans used by native preparation", () => {
  for (const platform of ["darwin", "win32"]) {
    const f = fixture(platform),
      images = Object.fromEntries(
        f.manifest.prerequisites.assets
          .filter((asset) => asset.kind === "image")
          .map((asset) => [asset.name, asset]),
      );
    const custody = (id) => ({
      context: { executionId: id },
      plan: {
        path: f.paths.join(f.root, "bootstrap", id + "-plan"),
        sha256: hash,
      },
      reader: images["custody-reader"],
      bridge: images["custody-bridge"],
    });
    const preparation = {
      bootstrap: custody("build"),
      command: { helper: images["build-helper"] },
      sourceDirectory: f.paths.join(
        f.root,
        platform === "win32" ? "bootstrap" : "sources",
      ),
      sources: f.manifest.prerequisites.assets.filter(
        (asset) => asset.kind === "source",
      ),
      cases: [{ custody: custody("fixture") }],
    };
    f.manifest[
      platform === "darwin" ? "darwinPreparation" : "windowsPreparation"
    ] = preparation;
    for (const entry of [preparation.bootstrap, preparation.cases[0].custody])
      f.manifest.prerequisites.assets.push({
        name: "custody-plan." + entry.context.executionId,
        kind: "plan",
        member: "bootstrap/custody-plan." + entry.context.executionId,
        path: entry.plan.path,
        bytes: bytes.length,
        sha256: hash,
        bindings: bindings(f.manifest.tools),
      });
    assert.doesNotThrow(() =>
      normalizeNativePrerequisites(
        f.manifest.prerequisites,
        f.manifest,
        f.profile,
      ),
    );
    f.manifest.prerequisites.assets.at(-1).sha256 = "0".repeat(64);
    assert.throws(() =>
      normalizeNativePrerequisites(
        f.manifest.prerequisites,
        f.manifest,
        f.profile,
      ),
    );
  }
});

test("complete input verification independently rereads declared files and rejects missing or mismatched byte counts", async () => {
  const f = fixture(),
    job = { candidateSha, platform: "linux" };
  await verifySystemCIInputFiles(job, f.profile, {
    manifest: f.manifest,
    read: async () => bytes,
  });
  await assert.rejects(
    verifySystemCIInputFiles(job, f.profile, {
      manifest: f.manifest,
      read: async () => {
        throw new Error("missing materialized input");
      },
    }),
  );
  f.manifest.inputs[0].bytes++;
  await assert.rejects(
    verifySystemCIInputFiles(job, f.profile, {
      manifest: f.manifest,
      read: async () => bytes,
    }),
  );
});

test("Windows prerequisite images must match the native builder's signed publication directory", () => {
  const f = preparationFixture("win32");
  f.manifest.windowsPreparation.sourceDirectory = f.paths.join(
    f.root,
    "separate-sources",
  );
  for (const asset of f.manifest.prerequisites.assets)
    if (asset.kind === "source")
      asset.path = f.paths.join(
        f.manifest.windowsPreparation.sourceDirectory,
        asset.name,
      );
  assert.throws(() =>
    normalizeNativePrerequisites(
      f.manifest.prerequisites,
      f.manifest,
      f.profile,
    ),
  );
});

function preparationFixture(platform = "linux") {
  const f = fixture(platform),
    events = [],
    journal = [],
    privateRecords = [],
    persist = async (value) => journal.push(structuredClone(value));
  if (platform === "win32") {
    const custody = (id) => ({
      context: { executionId: id },
      plan: {
        path: f.paths.join(f.root, "bootstrap", id + "-plan"),
        sha256: hash,
      },
      reader: f.manifest.prerequisites.assets.find(
        (asset) => asset.name === "custody-reader",
      ),
      bridge: f.manifest.prerequisites.assets.find(
        (asset) => asset.name === "custody-bridge",
      ),
    });
    f.manifest.windowsPreparation = {
      bootstrap: custody("build"),
      command: {
        helper: f.manifest.prerequisites.assets.find(
          (asset) => asset.name === "build-helper",
        ),
      },
      sourceDirectory: f.paths.join(f.root, "bootstrap"),
      sources: f.manifest.prerequisites.assets.filter(
        (asset) => asset.kind === "source",
      ),
      cases: windowsSystemRecipes()
        .filter(({ id }) => id !== "build")
        .map(({ id }) => ({ id, custody: custody(id) })),
    };
    for (const entry of [
      f.manifest.windowsPreparation.bootstrap,
      ...f.manifest.windowsPreparation.cases.map((entry) => entry.custody),
    ])
      f.manifest.prerequisites.assets.push({
        name: "custody-plan." + entry.context.executionId,
        kind: "plan",
        member: "bootstrap/custody-plan." + entry.context.executionId,
        path: entry.plan.path,
        bytes: bytes.length,
        sha256: hash,
        bindings: bindings(f.manifest.tools),
      });
    f.profile.recipes = windowsSystemRecipes;
  }
  const effects = {
    persist: async (record) => {
      privateRecords.push(record);
      return {
        recordSha256: observationDigest(record),
        independent: true,
        held: true,
        immutable: true,
        protectedParents: true,
        birthProtected: true,
        identitySha256: hash,
        nativeEventSha256: hash,
      };
    },
    sealAsset: async (request) => {
      events.push("seal");
      return {
        requestSha256: observationDigest(request),
        independent: true,
        birthProtected: true,
        protectedParents: true,
        exclusive: true,
        held: true,
        unchanged: true,
        executed: false,
        identitySha256: hash,
        nativeEventSha256: hash,
      };
    },
    verifyAsset: async (request) => ({
      requestSha256: observationDigest(request),
      independent: true,
      held: true,
      unchanged: true,
      readExecuteOnly: true,
      bytes: bytes.length,
      sha256: hash,
      noLiveMembers: true,
      emergencyCleanup: false,
      nativeEventSha256: hash,
    }),
    packageOptions: async () => ({}),
    verifyInputs: async (request) => {
      events.push("verify");
      return {
        requestSha256: observationDigest(request),
        bootstrapRequestSha256: observationDigest(request.bootstrapRequest),
        independent: true,
        complete: true,
        held: true,
        protectedParents: true,
        unchanged: true,
        bootstrapRetired: true,
        noLiveMembers: true,
        emergencyCleanup: false,
        nativeEventSha256: hash,
      };
    },
  };
  let bootstrapSignal;
  const options = {
    platform,
    now: () => 0,
    env: {
      CI: "true",
      GITHUB_ACTIONS: "true",
      ImageOS: "fixture",
      RUNNER_TEMP: f.root,
      NATIVE_SYSTEM_INPUT_REPOSITORY: "example/reviews",
      NATIVE_SYSTEM_INPUT_REVISION: "b".repeat(40),
      NATIVE_SYSTEM_REVIEW_SHA256: hash,
    },
    inputs: async () => ({
      manifest: f.manifest,
      read: async () => bytes,
      verify: async () => events.push("input-read"),
    }),
    fs: {
      mkdir: async () => {},
      readFile: async () => bytes,
      lstat: async () => ({ isFile: () => true, nlink: 1, size: bytes.length }),
    },
    fetchInput: async (url) => ({
      ok: true,
      url,
      headers: new Headers(),
      body: [bytes],
    }),
    loadCapability: async () => ({
      createPrerequisiteEffects: () => effects,
      createBuildEffects: () => {
        assert.ok(events.includes("seal"));
        return {
          bootstrap: async (signal) => {
            bootstrapSignal = signal;
            events.push("bootstrap");
            assert.equal(
              privateRecords.at(-1).request.phase,
              "native-bootstrap",
            );
          },
          run: async (request) => {
            assert.equal(bootstrapSignal.aborted, false);
            events.push("command");
            assert.equal(journal.at(-1).commands.at(-1).status, "POSSIBLE");
            return {
              requestSha256: observationDigest(request),
              toolSha256: hash,
              nativeEventSha256: hash,
              independent: true,
              settlement: {
                status: "RETIRED",
                independent: true,
                emergencyCleanup: false,
              },
              exitCode: 0,
              signal: null,
              timedOut: false,
              stdout: "fixture tool",
              stderr: "",
              identity: {},
            };
          },
        };
      },
    }),
    preparePackage: async (entry) => {
      events.push("package");
      return {
        status: "BOUND_BYTES",
        candidateSha,
        packageId: entry.packageId,
        reviewSha256: entry.approvedReviewSha256,
        integrity: nativePackageInput(entry.packageId).integrity,
        members: entry.reviewed.files.length,
        entrypoint: f.paths.join(
          entry.directory,
          "content",
          ...(
            entry.reviewed.entrypoint ??
            nativePackageInput(entry.packageId).entrypoint
          ).split("/"),
        ),
      };
    },
  };
  return { ...f, options, effects, persist, journal, privateRecords, events };
}
test("supported preparation uses fixed phases and complete verification; uncertainty keeps bootstrap POSSIBLE", async () => {
  for (const [platform, failure] of [
    ["linux", null],
    ["darwin", null],
    ["win32", null],
    ["linux", "assets"],
    ["linux", "bootstrap"],
    ["linux", "package"],
    ["linux", "verification"],
    ["linux", "inputs"],
  ]) {
    const f = preparationFixture(platform),
      diagnoses = [];
    f.options.onFailure = async (value) => diagnoses.push(value.diagnosis);
    if (failure === "assets") f.manifest.prerequisites.assets.pop();
    else if (failure === "bootstrap") {
      const original = f.options.loadCapability;
      f.options.loadCapability = async () => {
        const module = await original();
        const create = module.createBuildEffects;
        module.createBuildEffects = () => ({
          ...create(),
          bootstrap: async () => {
            throw nativePreparationError("native-bootstrap");
          },
        });
        return module;
      };
    } else if (failure === "package")
      f.options.preparePackage = async () => ({ status: "BLOCKED" });
    else if (failure === "verification")
      f.effects.verifyInputs = async () => ({ complete: false });
    else if (failure === "inputs") {
      const original = f.options.inputs;
      f.options.inputs = async () => ({
        ...(await original()),
        verify: async () => {
          throw nativePreparationError("verification");
        },
      });
    }
    const result = await prepareSystemCI(
      { candidateSha, platform },
      f.profile,
      f.root,
      f.paths.join(f.root, "platform-build"),
      f.persist,
      f.options,
    );
    assert.equal(result.status, failure ? "FAIL" : "PASS", failure);
    assert.deepEqual(
      normalizeSystemPreparation(result, { candidateSha, platform }),
      result,
    );
    if (!failure) {
      assert.deepEqual(
        [...new Set(f.journal.map((entry) => entry.phase))],
        [
          "review",
          "bootstrap-assets",
          "native-bootstrap",
          "toolchain",
          "build",
          "packages",
          "verification",
        ],
      );
      assert.ok(result.commands.every((entry) => entry.status === "RETIRED"));
      if (platform === "win32") {
        assert.equal(result.commands.length, 87);
        const overflow = structuredClone(result);
        overflow.commands.push(overflow.commands[0]);
        assert.throws(() =>
          normalizeSystemPreparation(overflow, { candidateSha, platform }),
        );
      }
      assert.ok(f.events.indexOf("package") < f.events.indexOf("verify"));
      assert.equal(f.events.at(-1), "input-read");
      for (const intent of f.privateRecords.filter(
        (entry) => entry.status === "POSSIBLE",
      ))
        assert.ok(
          f.privateRecords.some(
            (entry) =>
              entry.status === "RETIRED" &&
              entry.requestSha256 === intent.requestSha256,
          ),
        );
    } else {
      if (failure === "assets") {
        assert.equal(result.commands.length, 0);
        assert.deepEqual(f.events, []);
      } else
        assert.ok(result.commands.some((entry) => entry.status === "POSSIBLE"));
      if (failure === "bootstrap") {
        assert.deepEqual(diagnoses, ["native-bootstrap"]);
        assert.ok(!f.events.includes("command"));
        assert.ok(!f.events.includes("package"));
      }
    }
  }
});

function extractorFixture() {
  const reviewed = review("git-for-windows"),
    events = [],
    records = [];
  const provisioning = {
    schemaVersion: 1,
    context,
    authoritySha256: hash,
    bindings: [],
    held: true,
    independent: true,
    verifierSha256: hash,
    nativeEventSha256: hash,
  };
  const policy = materializeNativePolicy(
    template,
    reviewed.extraction.policyBinding.approval,
    provisioning,
    context,
  );
  const effects = {
    readProtected: async ({ file }) => ({
      file,
      bytes,
      held: true,
      independent: true,
      birthProtected: true,
      protectedParents: true,
      unchanged: true,
      identitySha256: hash,
      bindingsSha256: observationDigest(reviewed.extraction.extractor.bindings),
      loadedDependenciesVerified: true,
      nativeEventSha256: hash,
    }),
    readProvisioning: async () => provisioning,
    readPolicy: async (request) => ({
      schemaVersion: 1,
      context,
      templateSha256: policy.templateSha256,
      provisioningSha256: policy.provisioningSha256,
      requestSha256: observationDigest(request),
      policySha256: policy.expectedPolicySha256,
      policy: policy.policy,
      held: true,
      complete: true,
      independent: true,
      verifierSha256: hash,
      nativeEventSha256: hash,
    }),
    extract: async (request) => {
      events.push("extract");
      assert.equal(records.at(-1).status, "POSSIBLE");
      assert.equal(request.mode, "7z-data-only");
      assert.equal(
        request.extractor.path.endsWith("package-extractor.exe"),
        true,
      );
      assert.ok(!request.arguments.includes(request.extractor.path));
      return {
        requestSha256: observationDigest(request),
        independent: true,
        inventoryVerifiedBeforeWrite: true,
        archiveVerified: true,
        archiveBytes: request.archiveBytes,
        archiveIntegrity: request.archiveIntegrity,
        dataOnly: true,
        archiveExecuted: false,
        extractorSha256: request.extractor.sha256,
        exitCode: 0,
        signal: null,
        timedOut: false,
        nativeEventSha256: hash,
      };
    },
    settle: async (request) => {
      events.push("settle");
      return {
        requestSha256: observationDigest(request),
        status: "RETIRED",
        independent: true,
        noLiveMembers: true,
        emergencyCleanup: false,
        nativeEventSha256: hash,
      };
    },
    verifyStaged: async (request) => {
      events.push("staged");
      return {
        requestSha256: observationDigest(request),
        independent: true,
        complete: true,
        noReparsePoints: true,
        noAlternateStreams: true,
        protectedParents: true,
        nativeEventSha256: hash,
        files: reviewed.files.map((file) => ({
          ...file,
          kind: "file",
          links: 1,
        })),
      };
    },
    seal: async (request) => {
      events.push("seal");
      return {
        requestSha256: observationDigest(request),
        independent: true,
        unchanged: true,
        readExecuteOnly: true,
        complete: true,
        nativeEventSha256: hash,
      };
    },
  };
  return {
    reviewed,
    effects,
    events,
    records,
    options: { persist: async (record) => records.push(record) },
  };
}
test("Git materialization requires reviewed native extraction and independently retires before verifying staged members", async () => {
  const f = extractorFixture();
  assert.equal(nativePackageReadiness(f.reviewed).status, "BOUND_INPUTS");
  const blocked = await prepareReviewedNativePackage({
    candidateSha,
    platform: "win32",
    packageId: "git-for-windows",
    directory: "C:\\Fixture\\git",
    reviewed: f.reviewed,
    approvedReviewSha256: nativePackageReviewDigest(f.reviewed),
  });
  assert.equal(blocked.status, "BLOCKED");
  await materializeReviewedGit(
    "C:\\Fixture\\archive",
    "C:\\Fixture\\content",
    f.reviewed,
    f.effects,
    f.options,
  );
  assert.deepEqual(f.events, ["extract", "settle", "staged", "seal"]);
  assert.deepEqual(
    f.records.map((record) => record.status),
    ["POSSIBLE", "RETIRED"],
  );
  for (const malformed of [
    "../escape",
    "usr/bin/bash.exe:stream",
    "undeclared",
    "link",
  ]) {
    const bad = extractorFixture(),
      inspect = bad.effects.verifyStaged;
    bad.effects.verifyStaged = async (...args) => {
      const observed = await inspect(...args);
      if (malformed === "link") observed.files[0].kind = "symlink";
      else observed.files[0].path = malformed;
      return observed;
    };
    await assert.rejects(
      materializeReviewedGit(
        "C:\\Fixture\\archive",
        "C:\\Fixture\\content",
        bad.reviewed,
        bad.effects,
        bad.options,
      ),
    );
    assert.ok(!bad.events.includes("seal"));
  }
  for (const malformed of ["loader", "policy", "exit"]) {
    const bad = extractorFixture();
    if (malformed === "loader") {
      const original = bad.effects.readProtected;
      bad.effects.readProtected = async (...args) => ({
        ...(await original(...args)),
        loadedDependenciesVerified: false,
      });
    } else if (malformed === "policy") {
      const original = bad.effects.readPolicy;
      let reads = 0;
      bad.effects.readPolicy = async (...args) => ({
        ...(await original(...args)),
        complete: ++reads < 2,
      });
    } else {
      const original = bad.effects.extract;
      bad.effects.extract = async (...args) => ({
        ...(await original(...args)),
        exitCode: 1,
      });
    }
    await assert.rejects(
      materializeReviewedGit(
        "C:\\Fixture\\archive",
        "C:\\Fixture\\content",
        bad.reviewed,
        bad.effects,
        bad.options,
      ),
    );
    assert.ok(!bad.events.includes("seal"));
    if (malformed !== "exit") assert.ok(!bad.events.includes("extract"));
  }
});
test("uncertain extractor retirement preserves the first failure and never grants staged bytes", async () => {
  for (const uncertain of ["retirement", "persistence"]) {
    const f = extractorFixture(),
      failure = nativePreparationError("deadline");
    f.effects.extract = async () => {
      throw failure;
    };
    if (uncertain === "retirement")
      f.effects.settle = async () => ({ status: "RETAINED" });
    else {
      const original = f.options.persist;
      f.options.persist = async (record) => {
        if (record.status === "RETIRED")
          throw new Error("private receipt unavailable");
        await original(record);
      };
    }
    await assert.rejects(
      materializeReviewedGit(
        "C:\\Fixture\\archive",
        "C:\\Fixture\\content",
        f.reviewed,
        f.effects,
        f.options,
      ),
      (error) => error === failure,
    );
    assert.deepEqual(
      f.records.map((record) => record.status),
      ["POSSIBLE"],
    );
    assert.ok(!f.events.includes("seal"));
  }
});
test("falsy extraction failures cannot admit staged bytes or be replaced by cleanup errors", async () => {
  for (const [failure, uncertain] of [
    [undefined, null],
    [null, "retirement"],
    [false, "persistence"],
    [0, null],
    ["", null],
  ]) {
    const f = extractorFixture();
    f.effects.extract = async () => {
      throw failure;
    };
    if (uncertain === "retirement")
      f.effects.settle = async () => ({ status: "RETAINED" });
    else if (uncertain === "persistence") {
      const original = f.options.persist;
      f.options.persist = async (record) => {
        if (record.status === "RETIRED")
          throw new Error("private receipt unavailable");
        await original(record);
      };
    }
    await assert.rejects(
      materializeReviewedGit(
        "C:\\Fixture\\archive",
        "C:\\Fixture\\content",
        f.reviewed,
        f.effects,
        f.options,
      ),
      (error) => error === failure,
    );
    assert.ok(!f.events.includes("staged"));
    assert.ok(!f.events.includes("seal"));
  }
});

// Only the filesystem/IPC edges are substituted. Descriptors keep their
// original object after pathname replacement, and close failures retain them.
function prerequisiteFileKernel() {
  const nodes = new Map(),
    handles = new Set(),
    events = [];
  let next = 0;
  const add = (
    file,
    content = null,
    mode = content === null ? 0o700 : 0o444,
  ) => {
    const node = {
      dev: 1n,
      ino: BigInt(++next),
      uid: 0n,
      gid: 0n,
      mode: BigInt(mode),
      nlink: 1n,
      mtimeNs: 1n,
      ctimeNs: 1n,
      content: content === null ? null : Buffer.from(content),
      link: false,
    };
    nodes.set(file, node);
    return node;
  };
  const lookup = (file) => {
    const node = nodes.get(file);
    if (!node)
      throw Object.assign(new Error("Missing filesystem object"), {
        code: "ENOENT",
      });
    return node;
  };
  const stat = (node) => ({
    ...node,
    size: BigInt(node.content?.length ?? 0),
    isFile: () => node.content !== null && !node.link,
    isDirectory: () => node.content === null && !node.link,
  });
  add("/", null, 0o755);
  add("/private");
  add("/private/records");
  const fs = {
    realpath: async (file) => (lookup(file).link ? "/other" : file),
    lstat: async (file) => stat(lookup(file)),
    async mkdir(file, options) {
      assert.equal(options.mode, 0o700);
      lookup(posix.dirname(file));
      assert.ok(!nodes.has(file));
      add(file);
      events.push("mkdir:" + file);
    },
    async open(file, flags, mode) {
      let node;
      if (flags & constants.O_CREAT) {
        assert.ok(flags & constants.O_EXCL);
        assert.ok(flags & constants.O_NOFOLLOW);
        assert.equal(mode, 0o600);
        lookup(posix.dirname(file));
        if (nodes.has(file))
          throw Object.assign(new Error("Existing object"), { code: "EEXIST" });
        node = add(file, Buffer.alloc(0), mode);
        events.push("create:" + file);
      } else node = lookup(file);
      if (node.link && flags & constants.O_NOFOLLOW)
        throw Object.assign(new Error("Link rejected"), { code: "ELOOP" });
      const handle = {
        stat: async () => stat(node),
        async read(target, offset, count, position) {
          const bytesRead = Math.min(
            count,
            Math.max(0, node.content.length - position),
          );
          node.content.copy(target, offset, position, position + bytesRead);
          return { bytesRead };
        },
        async writeFile(content) {
          node.content = Buffer.from(content);
          node.mtimeNs++;
          node.ctimeNs++;
        },
        async sync() {
          events.push("sync:" + file);
        },
        async chmod(value) {
          node.mode = BigInt(value);
          node.ctimeNs++;
        },
        async close() {
          assert.ok(handles.has(handle));
          handles.delete(handle);
        },
      };
      handles.add(handle);
      return handle;
    },
  };
  const intent = (request) => {
    const content = Buffer.from(JSON.stringify(request)),
      file = "/private/records/request";
    add(file, content);
    return {
      file,
      bytes: content.length,
      sha256: createHash("sha256").update(content).digest("hex"),
    };
  };
  return {
    nodes,
    handles,
    events,
    fs,
    add,
    intent,
    files: () =>
      createPosixPrerequisiteFiles({
        root: "/private",
        ownerUid: 0,
        fs,
        platform: "linux",
      }),
  };
}

test("Darwin ACLs cannot be admitted through mode-only filesystem custody", () => {
  const k = prerequisiteFileKernel(),
    file = "/private/input",
    node = k.add(file, Buffer.from("data"));
  k.nodes.get("/private").acl = [{ uid: 17, allow: "write", inherit: true }];
  node.acl = [{ uid: 17, allow: "write", inherit: false }];
  assert.equal(k.nodes.get("/private").mode, 0o700n);
  assert.equal(node.mode, 0o444n);
  assert.throws(() =>
    createPosixPrerequisiteFiles({
      root: "/private",
      ownerUid: 0,
      fs: k.fs,
      platform: "darwin",
    }),
  );
  assert.equal(k.events.length, 0);
  assert.equal(k.handles.size, 0);
  assert.deepEqual(node.content, Buffer.from("data"));
});

test("file custody requires immutable exact intent before exclusive creation and independently rereads sealed bytes", async () => {
  const k = prerequisiteFileKernel(),
    files = k.files(),
    content = Buffer.from("approved data"),
    file = "/private/assets/reader";
  const request = prerequisiteCreationRequest("/private", file, content, true),
    intent = k.intent(request);
  const result = await files.create(file, content, {
    executable: true,
    intent,
  });
  assert.deepEqual(result.bytes, content);
  assert.equal(result.birthProtected, true);
  assert.equal(result.exclusive, true);
  assert.equal(result.readExecuteOnly, true);
  assert.equal(result.requestSha256, observationDigest(request));
  assert.equal(k.nodes.get(file).mode, 0o555n);
  assert.equal(k.nodes.get("/private/assets").mode, 0o700n);
  assert.ok(k.events.includes("sync:" + file));
  assert.ok(k.handles.size > 0);
  await assert.rejects(async () =>
    files.create(file, content, { executable: true, intent }),
  );
  const closed = await files.close();
  assert.equal(closed.status, "CLOSED");
  assert.equal(closed.custodianRetired, false);
  assert.equal(k.handles.size, 0);
  await assert.rejects(async () => files.hold(file, { maximum: 100 }));
});

test("invalid creation intent and pre-existing destinations cannot enable writes or directory creation", async () => {
  for (const damage of [
    "missing",
    "hash",
    "request",
    "mutable",
    "existing",
    "escape",
  ]) {
    const k = prerequisiteFileKernel(),
      files = k.files(),
      content = Buffer.from("data"),
      file = "/private/assets/reader";
    const request = prerequisiteCreationRequest("/private", file, content),
      intent = k.intent(request);
    if (damage === "hash") intent.sha256 = "0".repeat(64);
    if (damage === "request") k.intent({ ...request, executable: true });
    if (damage === "mutable") k.nodes.get(intent.file).mode = 0o600n;
    if (damage === "existing") {
      k.add("/private/assets");
      k.add(file, Buffer.from("foreign"));
    }
    await assert.rejects(async () =>
      files.create(
        damage === "escape" ? "/private/../outside" : file,
        content,
        { intent: damage === "missing" ? undefined : intent },
      ),
    );
    assert.ok(!k.events.some((event) => event.startsWith("create:")));
    if (damage !== "existing")
      assert.ok(!k.events.some((event) => event.startsWith("mkdir:")));
    else assert.equal(k.nodes.get(file).content.toString(), "foreign");
    await files.close();
    assert.equal(k.handles.size, 0);
  }
});

test("held reads reject links, unexpected writers, oversize files, object replacement and changed bytes", async () => {
  for (const damage of [
    "link",
    "parent-link",
    "writer",
    "owner",
    "hardlink",
    "oversize",
    "parent-replace",
    "bytes",
    "during-read",
    "invalid-count",
    "cancel",
  ]) {
    const k = prerequisiteFileKernel(),
      files = k.files(),
      file = "/private/input",
      node = k.add(file, Buffer.from("data"));
    if (damage === "link") node.link = true;
    if (damage === "parent-link") k.nodes.get("/private").link = true;
    if (damage === "writer") node.mode = 0o466n;
    if (damage === "owner") node.uid = 17n;
    if (damage === "hardlink") node.nlink = 2n;
    const controller = new AbortController();
    if (["parent-replace", "bytes"].includes(damage)) {
      await files.hold(file, { maximum: 4 });
      if (damage === "parent-replace") k.add("/private");
      else node.content = Buffer.from("edit");
    }
    if (["during-read", "invalid-count", "cancel"].includes(damage)) {
      const open = k.fs.open;
      k.fs.open = async (...args) => {
        const handle = await open(...args),
          read = handle.read;
        handle.read = async (...input) => {
          const result = await read(...input);
          if (damage === "during-read") node.mtimeNs++;
          if (damage === "cancel") controller.abort();
          return damage === "invalid-count" ? { bytesRead: 100 } : result;
        };
        return handle;
      };
    }
    await assert.rejects(
      files.hold(file, {
        maximum: damage === "oversize" ? 3 : 4,
        signal: controller.signal,
      }),
    );
    await files.close();
    assert.equal(k.handles.size, 0);
  }
});

test("failed creation retains both transfer handles, original failure and reconstruction exclusion", async () => {
  for (const damage of ["transfer", "write", "sealed-metadata"]) {
    const k = prerequisiteFileKernel(),
      files = k.files(),
      file = "/private/reader",
      content = Buffer.from("data");
    const request = prerequisiteCreationRequest("/private", file, content),
      intent = k.intent(request),
      failure = new Error("Interrupted write"),
      open = k.fs.open;
    k.fs.open = async (name, flags, ...args) => {
      if (
        damage === "transfer" &&
        name === file &&
        !(flags & constants.O_CREAT)
      )
        k.add(file, content);
      const handle = await open(name, flags, ...args);
      if (damage === "write" && name === file)
        handle.writeFile = async () => {
          throw failure;
        };
      if (
        damage === "sealed-metadata" &&
        name === file &&
        flags & constants.O_CREAT
      ) {
        const close = handle.close;
        handle.close = async () => {
          k.nodes.get(file).ctimeNs++;
          await close();
        };
      }
      return handle;
    };
    await assert.rejects(
      files.create(file, content, { intent }),
      damage === "write" ? (error) => error === failure : undefined,
    );
    await assert.rejects(files.hold(file, { maximum: 4 }));
    const closed = await files.close();
    assert.deepEqual(closed.uncertainFiles, [file]);
    assert.equal(k.handles.size, 0);
    const reconstructed = k.files(),
      requestSha256 = observationDigest(request),
      recovery = reconstructed.recover(request, { intent });
    request.file = "/private/other";
    const recovered = await recovery;
    assert.equal(recovered.status, "RETAINED");
    assert.equal(recovered.requestSha256, requestSha256);
    assert.equal(recovered.admitted, false);
    assert.equal(recovered.birthProtected, false);
    await assert.rejects(reconstructed.hold(file, { maximum: 4 }));
    await reconstructed.close();
  }
});

test("failed descriptor closure fences admissions and retains the failed handle for an explicit closure retry", async () => {
  const k = prerequisiteFileKernel(),
    files = k.files(),
    file = "/private/input";
  k.add(file, Buffer.from("data"));
  await files.hold(file, { maximum: 4 });
  const handle = [...k.handles][0],
    close = handle.close;
  let fail = true;
  handle.close = async () => {
    if (fail) throw new Error("Uncertain close");
    await close();
  };
  await assert.rejects(files.close());
  assert.equal(k.handles.size, 1);
  await assert.rejects(async () => files.hold(file, { maximum: 4 }));
  fail = false;
  await files.close();
  assert.equal(k.handles.size, 0);
});

function windowsFileTranscript() {
  const root = "C:\\Private",
    nodes = new Map(),
    events = [];
  let next = 0;
  const add = (file, bytes, access = "read") => {
    const node = {
      bytes: Buffer.from(bytes),
      identity: (++next).toString(16).padStart(48, "0"),
      metadata: "0".repeat(80),
      access,
    };
    nodes.set(file, node);
    return node;
  };
  const observe = (file) => {
    const node = nodes.get(file);
    assert.ok(node);
    return {
      file,
      identity: node.identity,
      bytes: node.bytes.length,
      links: 1,
      metadata: node.metadata,
      security: {
        owner: "S-1-5-18",
        protected: true,
        sddl: "O:SYD:P(A;;FA;;;SY)",
        rules: [
          { sid: "S-1-5-18", rights: 0x1f01ff, allow: true, inherited: false },
        ],
      },
      access: node.access,
      share: 1,
    };
  };
  const exchange = async (request) => {
    events.push(request.operation);
    let observation;
    if (request.operation === "create") {
      assert.ok(!nodes.has(request.file));
      add(request.file, Buffer.alloc(0), "write");
    } else if (request.operation === "write") {
      const node = nodes.get(request.file);
      assert.equal(request.offset, node.bytes.length);
      node.bytes = Buffer.concat([
        node.bytes,
        Buffer.from(request.data, "base64"),
      ]);
    } else if (request.operation === "seal")
      nodes.get(request.file).access = "read";
    if (request.operation === "close")
      observation = {
        status: "CLOSED",
        closedHandles: nodes.size,
        custodianRetired: false,
      };
    else {
      observation = observe(request.file);
      if (request.operation === "read")
        observation.data = nodes
          .get(request.file)
          .bytes.subarray(request.offset, request.offset + request.count)
          .toString("base64");
    }
    return {
      schemaVersion: 1,
      requestId: request.requestId,
      operation: request.operation,
      observation,
    };
  };
  const intent = (request) => {
    const content = Buffer.from(JSON.stringify(request)),
      file = root + "\\records\\request";
    add(file, content);
    return {
      file,
      bytes: content.length,
      sha256: createHash("sha256").update(content).digest("hex"),
    };
  };
  return {
    root,
    nodes,
    events,
    add,
    observe,
    exchange,
    intent,
    files: (edge = exchange) =>
      createWindowsPrerequisiteFiles(
        { root, controllerSid: "S-1-5-21-1" },
        { exchange: edge },
      ),
  };
}

test("Windows file custody uses bounded raw operations, exact protected intent and held native identity through writer transfer", async () => {
  const k = windowsFileTranscript(),
    files = k.files(),
    file = k.root + "\\reader",
    content = Buffer.alloc(49153, 7);
  const request = prerequisiteCreationRequest(k.root, file, content, true),
    intent = k.intent(request);
  const result = await files.create(file, content, {
    executable: true,
    intent,
  });
  assert.deepEqual(result.bytes, content);
  assert.equal(result.birthProtected, true);
  assert.equal(result.readExecuteOnly, true);
  assert.equal(k.events.filter((operation) => operation === "write").length, 2);
  assert.ok(k.events.indexOf("read") < k.events.indexOf("create"));
  assert.ok(k.events.indexOf("seal") > k.events.lastIndexOf("write"));
  result.event.before.identity = "f".repeat(48);
  const reread = await files.hold(file, { maximum: content.length });
  assert.equal(reread.identity.identity, k.nodes.get(file).identity);
  assert.deepEqual(reread.bytes, content);
  assert.equal((await files.close()).custodianRetired, false);
});

test("Windows file custody rejects unheld identity, sharing, DACL, malformed frames and substituted transfer without native admission", async () => {
  for (const damage of [
    "identity",
    "identity-array",
    "metadata-array",
    "sharing",
    "dacl",
    "owner",
    "request",
    "frame",
    "oversized-frame",
    "extra-field",
    "transfer",
    "sealed-identity",
    "sealed-metadata",
    "birth-dacl",
  ]) {
    const k = windowsFileTranscript(),
      file = k.root + "\\reader",
      content = Buffer.from("data");
    const request = prerequisiteCreationRequest(k.root, file, content),
      intent = k.intent(request);
    const files = k.files(async (input) => {
      const reply = await k.exchange(input);
      if (input.operation === "close") return reply;
      if (damage === "transfer" && input.operation === "seal")
        reply.observation.identity = "f".repeat(48);
      if (
        damage.startsWith("sealed-") &&
        input.operation === "hold" &&
        input.file === file
      ) {
        const node = k.nodes.get(file);
        if (damage === "sealed-identity") node.identity = "f".repeat(48);
        else node.metadata = "1".repeat(80);
        reply.observation = k.observe(file);
      }
      if (damage === "birth-dacl" && input.operation === "create")
        reply.observation.security.rules.push({
          sid: "S-1-5-32-544",
          rights: 0x1f01ff,
          allow: true,
          inherited: false,
        });
      if (
        ![
          "transfer",
          "sealed-identity",
          "sealed-metadata",
          "birth-dacl",
        ].includes(damage)
      ) {
        if (damage === "identity") reply.observation.identity = "inode";
        if (damage === "identity-array")
          reply.observation.identity = [reply.observation.identity];
        if (damage === "metadata-array")
          reply.observation.metadata = [reply.observation.metadata];
        if (damage === "sharing") reply.observation.share = 3;
        if (damage === "dacl")
          reply.observation.security.rules.push({
            sid: "S-1-1-0",
            rights: 2,
            allow: true,
            inherited: true,
          });
        if (damage === "owner") reply.observation.security.owner = "S-1-1-0";
        if (damage === "request") reply.requestId++;
        if (damage === "frame" && input.operation === "read")
          reply.observation.data = "!!!";
        if (damage === "oversized-frame")
          reply.observation.security.sddl = "x".repeat(65537);
        if (damage === "extra-field") reply.unreviewed = true;
      }
      return reply;
    });
    await assert.rejects(files.create(file, content, { intent }));
    if (
      ![
        "transfer",
        "sealed-identity",
        "sealed-metadata",
        "birth-dacl",
      ].includes(damage)
    )
      assert.ok(!k.events.includes("create"));
    else await assert.rejects(files.hold(file, { maximum: 4 }));
    await files.close();
  }
});

test("Windows disconnect after exclusive creation preserves the exact cause and excludes the unacknowledged object", async () => {
  const k = windowsFileTranscript(),
    file = k.root + "\\reader",
    content = Buffer.from("data"),
    failure = new Error("Disconnected before acknowledgement");
  const request = prerequisiteCreationRequest(k.root, file, content),
    intent = k.intent(request);
  const files = k.files(async (input) => {
    const reply = await k.exchange(input);
    if (input.operation === "create") throw failure;
    return reply;
  });
  await assert.rejects(
    files.create(file, content, { intent }),
    (error) => error === failure,
  );
  assert.ok(k.nodes.has(file));
  assert.ok(!k.events.includes("write"));
  await assert.rejects(files.hold(file, { maximum: 4 }));
  const closed = await files.close();
  assert.deepEqual(closed.uncertainFiles, [file.toLowerCase()]);
  assert.equal(closed.custodianRetired, false);
});

test("Windows reconstruction retains exclusion and missing transport starts no host or filesystem operation", async () => {
  const k = windowsFileTranscript(),
    file = k.root + "\\reader",
    content = Buffer.from("data");
  const request = prerequisiteCreationRequest(k.root, file, content),
    intent = k.intent(request);
  k.add(file, content);
  const files = k.files(),
    requestSha256 = observationDigest(request),
    recovery = files.recover(request, { intent });
  request.file = k.root + "\\other";
  const result = await recovery;
  assert.equal(result.status, "RETAINED");
  assert.equal(result.requestSha256, requestSha256);
  assert.equal(result.admitted, false);
  assert.equal(result.birthProtected, false);
  await assert.rejects(files.hold(file, { maximum: 4 }));
  await files.close();
  const inactive = createWindowsPrerequisiteFiles({
    root: k.root,
    controllerSid: "S-1-5-21-1",
  });
  await assert.rejects(inactive.hold(file, { maximum: 4 }));
});
