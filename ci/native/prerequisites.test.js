import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import * as filesystem from "node:fs/promises";
import net from "node:net";
import readline from "node:readline";
import { syncBuiltinESMExports } from "node:module";
import { Readable, Writable, Duplex, PassThrough } from "node:stream";
import { finished } from "node:stream/promises";
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
import {
  prerequisiteSourceMembers,
  prerequisiteSourceSnapshot,
  prerequisiteWorkerEntry,
  windowsPrerequisiteWorker,
  windowsPrerequisiteGatewayAdmission,
} from "./prerequisite-source.js";
import {
  createPrerequisiteWorker,
  normalizePrerequisiteAdmission,
  prerequisiteFrames,
  runPrerequisiteWorker,
  PREREQUISITE_WORKER_LIMITS,
} from "./prerequisite-worker.mjs";

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
          : [
              "custody.h",
              "effective-reader.h",
              "account.h",
              "audit-policy-remove.h",
            ],
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
        assert.equal(result.commands.length, 89);
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
          identitySha256: hash,
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

function workerAdmission(platform = "linux", now = Date.now()) {
  const root = platform === "win32" ? "C:\\Private" : "/private";
  return {
    schemaVersion: 1,
    platform,
    root,
    readRoots: [root],
    writeRoots: [root + (platform === "win32" ? "\\assets" : "/assets")],
    controllerUid: platform === "win32" ? null : 0,
    controllerSid: platform === "win32" ? "S-1-5-21-1" : null,
    nonce: "b".repeat(32),
    expires: now + 60000,
  };
}

async function workerSourceFixture(platform = "linux") {
  const source = new Map();
  for (const member of prerequisiteSourceMembers(platform)) {
    const name = member.slice("candidate/ci/native/".length);
    source.set(name, await filesystem.readFile(new URL(name, import.meta.url)));
  }
  const manifest = {
    platform,
    source: {
      citations: [...source].map(([name, bytes]) => ({
        kind: "reached-code",
        member: "candidate/ci/native/" + name,
        sha256: createHash("sha256").update(bytes).digest("hex"),
      })),
    },
  };
  return { source, manifest, read: async (name) => source.get(name) };
}

function workerFileFixture() {
  const k = prerequisiteFileKernel(),
    now = Date.now(),
    plan = workerAdmission("linux", now);
  let id = 0,
    time = now;
  const binding = {
      nonce: plan.nonce,
      admissionSha256: observationDigest(plan),
    },
    worker = createPrerequisiteWorker(binding, {
      fs: k.fs,
      platform: "linux",
      uid: 0,
      pid: 42,
      clock: () => time,
    });
  const frame = (operation, args = []) => ({
    id: ++id,
    nonce: plan.nonce,
    operation,
    args,
  });
  return {
    k,
    plan,
    binding,
    worker,
    frame,
    invoke: (operation, args = []) => worker.invoke(frame(operation, args)),
    expire: () => {
      time = plan.expires;
    },
  };
}

test("worker imports and captured source evaluation cannot start IPC or service stdin", async () => {
  const f = await workerSourceFixture(),
    snapshot = await prerequisiteSourceSnapshot(f.manifest, f.read),
    originalConnect = net.connect,
    originalInterface = readline.createInterface;
  let calls = 0;
  try {
    net.connect = readline.createInterface = () => {
      calls++;
      throw new Error("Import-time IPC");
    };
    syncBuiltinESMExports();
    await import("./prerequisite-worker.mjs?effect-free");
    const captured = snapshot.code;
    f.source.get("prerequisite-worker.mjs").fill(0);
    // Evaluate the exact captured graph. An activation suffix is deliberately
    // absent, and no live checkout import may be reloaded from this data URL.
    await import(
      "data:text/javascript;base64," +
        Buffer.from(snapshot.code).toString("base64")
    );
    assert.equal(snapshot.code, captured);
    assert.equal(calls, 0);
    assert.ok(
      snapshot.sources.some((member) => member.name === "observation.js"),
    );
    assert.match(
      prerequisiteWorkerEntry(snapshot, workerAdmission()),
      /await modules\["prerequisite-worker.mjs"\]\.runPrerequisiteWorker/u,
    );
  } finally {
    net.connect = originalConnect;
    readline.createInterface = originalInterface;
    syncBuiltinESMExports();
  }
});

test("source snapshot rejects substitution, missing citations and undeclared dependencies before activation", async () => {
  for (const damage of [
    "bytes",
    "missing",
    "duplicate",
    "dependency",
    "dynamic",
    "commented-dynamic",
  ]) {
    const f = await workerSourceFixture();
    if (damage === "missing") f.manifest.source.citations.shift();
    if (damage === "duplicate")
      f.manifest.source.citations.push(f.manifest.source.citations[0]);
    if (
      ["bytes", "dependency", "dynamic", "commented-dynamic"].includes(damage)
    ) {
      const name = "prerequisite-worker.mjs",
        bytes = Buffer.concat([
          f.source.get(name),
          Buffer.from(
            damage === "dependency"
              ? '\nimport { extra } from "./unreviewed.js";\n'
              : damage === "dynamic"
                ? '\nawait import("./unreviewed.js");\n'
                : damage === "commented-dynamic"
                  ? '\nconst extra = await import /* dependency */ ("./unreviewed.js");\n'
                  : "\n// changed\n",
          ),
        ]);
      f.source.set(name, bytes);
      if (damage !== "bytes")
        f.manifest.source.citations.find((entry) =>
          entry.member.endsWith(name),
        ).sha256 = createHash("sha256").update(bytes).digest("hex");
    }
    await assert.rejects(prerequisiteSourceSnapshot(f.manifest, f.read));
  }
});

test("worker admission freezes the complete plan and performs protected creation through repository file owners", async () => {
  const f = workerFileFixture(),
    content = Buffer.alloc(40000, 37),
    file = "/private/assets/source",
    request = prerequisiteCreationRequest(f.plan.root, file, content),
    intent = f.k.intent(request);
  assert.equal(f.k.events.length, 0);
  assert.deepEqual(await f.invoke("init", [f.plan]), {
    pid: 42,
    platform: "linux",
  });
  f.plan.writeRoots.push("/outside");
  await f.invoke("create-begin", [request, { executable: false, intent }]);
  await f.invoke("create-chunk", [
    0,
    { nativeBytes: content.subarray(0, 32768).toString("base64") },
  ]);
  assert.ok(!f.k.nodes.has(file));
  await f.invoke("create-chunk", [
    32768,
    { nativeBytes: content.subarray(32768).toString("base64") },
  ]);
  const created = await f.invoke("create-finish");
  assert.equal(created.birthProtected, true);
  assert.equal(created.requestSha256, observationDigest(request));
  const held = await f.invoke("hold", [
    file,
    { maximum: content.length, sealed: true },
  ]);
  assert.equal(held.bytesLength, content.length);
  const first = await f.invoke("read-held", [held.readId, 0, 32768]);
  assert.deepEqual(
    Buffer.from(first.nativeBytes, "base64"),
    content.subarray(0, 32768),
  );
  await f.invoke("release-read", [held.readId]);
  const closed = await f.invoke("close");
  assert.equal(closed.status, "CLOSED");
  assert.equal(closed.custodianRetired, false);
  assert.equal(f.k.handles.size, 0);
});

test("worker rejects undeclared operations, escaped paths, wrong nonce and substituted admission", async () => {
  for (const damage of [
    "operation",
    "escape",
    "prefix",
    "control",
    "nonce",
    "digest",
    "reinit",
    "id",
    "shape",
  ]) {
    const f = workerFileFixture();
    if (damage !== "digest") await f.invoke("init", [f.plan]);
    let frame = f.frame("hold", [
      "/private/input",
      { maximum: 4, sealed: true },
    ]);
    if (damage === "operation") frame.operation = "kernel-start";
    if (damage === "escape") frame.args[0] = "/private/assets/../outside";
    if (damage === "prefix") frame.args[0] = "/private-other/input";
    if (damage === "control") frame.args[0] += "\u0000";
    if (damage === "nonce") frame.nonce = "0".repeat(32);
    if (damage === "id") frame.id++;
    if (damage === "shape") frame.extra = true;
    if (["digest", "reinit"].includes(damage)) {
      frame = {
        ...frame,
        operation: "init",
        args: [
          {
            ...f.plan,
            ...(damage === "digest" ? { readRoots: ["/outside"] } : {}),
          },
        ],
      };
    }
    await assert.rejects(f.worker.invoke(frame));
    assert.equal(f.k.handles.size, 0);
    assert.equal(f.k.events.length, 0);
    await f.worker.close();
  }
  const now = Date.now();
  for (const path of [
    "C:\\Private\\..\\Other",
    "C:\\Private\\data:stream",
    "C:\\Private\\NUL",
    "C:\\Private\\trailing.",
    "\\\\server\\share",
  ]) {
    assert.throws(() =>
      normalizePrerequisiteAdmission(
        {
          ...workerAdmission("win32", now),
          writeRoots: [path],
          readRoots: [path],
        },
        now,
      ),
    );
  }
});

test("worker expiry permits closure only, and interrupted uploads or failed writes cannot become admitted", async () => {
  const expired = workerFileFixture();
  await expired.invoke("init", [expired.plan]);
  expired.expire();
  assert.equal((await expired.invoke("close")).custodianRetired, false);
  const f = workerFileFixture();
  await f.invoke("init", [f.plan]);
  f.expire();
  await assert.rejects(
    f.invoke("hold", ["/private/input", { maximum: 4, sealed: true }]),
  );
  assert.equal(f.k.handles.size, 0);
  await f.worker.close();
  for (const damage of ["partial", "hash", "write"]) {
    const f = workerFileFixture(),
      content = Buffer.from("data"),
      file = "/private/assets/input",
      request = prerequisiteCreationRequest(f.plan.root, file, content),
      intent = f.k.intent(request);
    await f.invoke("init", [f.plan]);
    await f.invoke("create-begin", [request, { executable: false, intent }]);
    if (damage === "write") {
      const open = f.k.fs.open;
      f.k.fs.open = async (...args) => {
        const handle = await open(...args);
        if (args[0] === file)
          handle.sync = async () => {
            throw new Error("Interrupted payload write");
          };
        return handle;
      };
    }
    await f.invoke("create-chunk", [
      0,
      {
        nativeBytes: (damage === "hash"
          ? Buffer.from("evil")
          : content.subarray(0, damage === "partial" ? 2 : 4)
        ).toString("base64"),
      },
    ]);
    await assert.rejects(f.invoke("create-finish"));
    const closed = await f.worker.close();
    assert.equal(closed.custodianRetired, false);
    assert.deepEqual(closed.uncertainFiles, damage === "write" ? [file] : []);
    if (damage !== "write") assert.ok(!f.k.nodes.has(file));
    assert.equal(f.k.handles.size, 0);
  }
});

test("raw framing rejects malformed, unterminated and oversized data before JSON admission", async () => {
  for (const bytes of [
    Buffer.from("{}"),
    Buffer.from("{bad}\n"),
    Buffer.from("\n"),
    Buffer.from([0xff, 10]),
    Buffer.alloc(PREREQUISITE_WORKER_LIMITS.frameBytes + 1, 32),
  ]) {
    await assert.rejects(async () => {
      for await (const frame of prerequisiteFrames(Readable.from([bytes])))
        void frame;
    });
  }
  const values = [];
  for await (const frame of prerequisiteFrames(
    Readable.from([Buffer.from('{"id":'), Buffer.from('1}\n{"id":2}\n')]),
  ))
    values.push(frame);
  assert.deepEqual(values, [{ id: 1 }, { id: 2 }]);
});

test("expiry during intent read or payload write cannot admit a late file effect", async () => {
  for (const phase of ["intent", "payload"]) {
    const f = workerFileFixture(),
      file = "/private/assets/input",
      content = Buffer.from("data"),
      request = prerequisiteCreationRequest(f.plan.root, file, content),
      intent = f.k.intent(request),
      open = f.k.fs.open;
    f.k.fs.open = async (...args) => {
      const handle = await open(...args);
      if (phase === "intent" && args[0] === intent.file) {
        const read = handle.read;
        handle.read = async (...values) => {
          const result = await read(...values);
          f.expire();
          return result;
        };
      }
      if (phase === "payload" && args[0] === file) {
        const write = handle.writeFile;
        handle.writeFile = async (...values) => {
          await write(...values);
          f.expire();
        };
      }
      return handle;
    };
    await f.invoke("init", [f.plan]);
    await assert.rejects(
      f.invoke("create", [
        file,
        { nativeBytes: content.toString("base64") },
        { executable: false, intent },
      ]),
    );
    const closed = await f.worker.close();
    assert.equal(f.k.nodes.has(file), phase === "payload");
    assert.deepEqual(closed.uncertainFiles, phase === "payload" ? [file] : []);
    assert.equal(f.k.handles.size, 0);
  }
});

test("worker reconstruction retains possible creation without adopting matching file bytes", async () => {
  const f = workerFileFixture(),
    file = "/private/assets/input",
    content = Buffer.from("data"),
    request = prerequisiteCreationRequest(f.plan.root, file, content),
    intent = f.k.intent(request),
    requestSha256 = observationDigest(request);
  f.k.add("/private/assets");
  f.k.add(file, content);
  await f.invoke("init", [f.plan]);
  const pending = f.invoke("recover", [request, { intent }]);
  request.file = "/private/assets/other";
  const result = await pending;
  assert.equal(result.requestSha256, requestSha256);
  assert.equal(result.status, "RETAINED");
  assert.equal(result.admitted, false);
  assert.equal(result.birthProtected, false);
  assert.equal(f.k.events.length, 0);
  await assert.rejects(f.invoke("hold", [file, { maximum: 4, sealed: true }]));
  const closed = await f.worker.close();
  assert.deepEqual(closed.uncertainFiles, [file]);
  assert.equal(f.k.handles.size, 0);
});

test("worker read count byte budget and chunk ranges bound retained data before dispatch", async () => {
  for (const damage of ["count", "bytes", "range"]) {
    const f = workerFileFixture(),
      file = "/private/input";
    f.k.add(file, Buffer.from("data"));
    await f.invoke("init", [f.plan]);
    const held = await f.invoke("hold", [file, { maximum: 4, sealed: true }]);
    if (damage === "count") {
      for (let count = 1; count < PREREQUISITE_WORKER_LIMITS.reads; count++)
        await f.invoke("hold", [file, { maximum: 4, sealed: true }]);
    }
    await assert.rejects(
      damage === "range"
        ? f.invoke("read-held", [held.readId, 0, 5])
        : f.invoke("hold", [
            file,
            {
              maximum:
                damage === "bytes" ? PREREQUISITE_WORKER_LIMITS.heldBytes : 4,
              sealed: true,
            },
          ]),
    );
    await f.worker.close();
    assert.equal(f.k.handles.size, 0);
  }
});

test("explicit worker entry clears its environment and requires a separate close acknowledgement", async () => {
  for (const disconnect of [false, true]) {
    const f = workerFileFixture(),
      env = { NODE_OPTIONS: "unapproved", SECRET: "unapproved" },
      replies = [];
    const frames = [f.frame("init", [f.plan])];
    if (!disconnect) frames.push(f.frame("close"));
    const result = runPrerequisiteWorker(
      { ...f.binding, expires: f.plan.expires },
      {
        env,
        fs: f.k.fs,
        platform: "linux",
        uid: 0,
        pid: 42,
        clock: () => f.plan.expires - 60000,
        input: Readable.from(
          frames.map((frame) => Buffer.from(JSON.stringify(frame) + "\n")),
        ),
        output: new Writable({
          write(bytes, encoding, done) {
            replies.push(JSON.parse(bytes.toString()));
            done();
          },
        }),
      },
    );
    if (disconnect) await assert.rejects(result);
    else assert.equal((await result).custodianRetired, false);
    assert.deepEqual(env, {});
    assert.equal(replies.length, disconnect ? 1 : 2);
    assert.equal(f.k.handles.size, 0);
    await f.worker.close();
  }
});

test("explicit pipe activation retains the connection failure without unhandled IPC errors", async () => {
  const f = workerFileFixture(),
    failure = new Error("Unavailable private pipe");
  let socket;
  await assert.rejects(
    runPrerequisiteWorker(
      {
        ...f.binding,
        expires: f.plan.expires,
        pipe: "\\\\.\\pipe\\AgentRunnerPrerequisites-" + f.plan.nonce,
      },
      {
        env: {},
        fs: f.k.fs,
        platform: "win32",
        uid: 0,
        clock: () => f.plan.expires - 60000,
        connect() {
          socket = new Duplex({
            read() {},
            write(bytes, encoding, done) {
              done();
            },
          });
          queueMicrotask(() => socket.destroy(failure));
          return socket;
        },
      },
    ),
    (error) => error === failure,
  );
  assert.equal(socket.destroyed, true);
  assert.equal(f.k.handles.size, 0);
  await f.worker.close();
});

test("Windows pipe selectors cannot become relative Unix socket destinations", async () => {
  const f = workerFileFixture();
  let connected = false;
  await assert.rejects(
    runPrerequisiteWorker(
      {
        ...f.binding,
        expires: f.plan.expires,
        pipe: "\\\\.\\pipe\\AgentRunnerPrerequisites-" + f.plan.nonce,
      },
      {
        env: {},
        platform: "linux",
        clock: () => f.plan.expires - 60000,
        connect() {
          connected = true;
          throw new Error("Unexpected socket admission");
        },
      },
    ),
  );
  assert.equal(connected, false);
  await f.worker.close();
});

test("stream interruption aborts active file writes and preserves the original failure", async () => {
  const f = workerFileFixture(),
    input = new PassThrough(),
    failure = new Error("Lost controller stream"),
    file = "/private/assets/input",
    content = Buffer.from("data"),
    request = prerequisiteCreationRequest(f.plan.root, file, content),
    intent = f.k.intent(request),
    initialized = Promise.withResolvers(),
    replies = [],
    open = f.k.fs.open;
  f.k.fs.open = async (...args) => {
    const handle = await open(...args);
    if (args[0] === file) {
      const write = handle.writeFile;
      handle.writeFile = async (...values) => {
        await write(...values);
        const interrupted = new Promise((resolve) =>
          input.once("error", resolve),
        );
        input.destroy(failure);
        await interrupted;
      };
    }
    return handle;
  };
  const output = new Writable({
    write(bytes, encoding, done) {
      replies.push(JSON.parse(bytes.toString()));
      initialized.resolve();
      done();
    },
  });
  const result = runPrerequisiteWorker(
    { ...f.binding, expires: f.plan.expires },
    {
      env: {},
      fs: f.k.fs,
      input,
      output,
      platform: "linux",
      uid: 0,
      clock: () => f.plan.expires - 60000,
    },
  );
  result.catch(initialized.reject);
  try {
    input.write(JSON.stringify(f.frame("init", [f.plan])) + "\n");
    await initialized.promise;
    input.write(
      JSON.stringify(
        f.frame("create", [
          file,
          { nativeBytes: content.toString("base64") },
          { executable: false, intent },
        ]),
      ) + "\n",
    );
    await assert.rejects(result, (error) => error === failure);
    assert.equal(replies.length, 1);
    assert.equal(f.k.nodes.get(file).mode, 0o600n);
    assert.ok(!f.k.events.includes("sync:" + file));
    assert.equal(f.k.handles.size, 0);
  } finally {
    input.destroy();
    output.destroy();
    await Promise.allSettled([
      finished(input, { cleanup: true }),
      finished(output, { cleanup: true }),
    ]);
    await f.worker.close();
  }
});

test("STDIO write errors and cancelled backpressure cannot escape cleanup or acknowledge success", async () => {
  for (const blocked of [false, true]) {
    const f = workerFileFixture(),
      failure = new Error("Unavailable controller output"),
      controller = new AbortController(),
      input = Readable.from([
        Buffer.from(JSON.stringify(f.frame("init", [f.plan])) + "\n"),
      ]);
    let release;
    const output = new Writable({
      write(bytes, encoding, done) {
        if (blocked) {
          release = done;
          controller.abort(failure);
        } else done(failure);
      },
    });
    try {
      await assert.rejects(
        runPrerequisiteWorker(
          { ...f.binding, expires: f.plan.expires },
          {
            env: {},
            fs: f.k.fs,
            input,
            output,
            signal: controller.signal,
            platform: "linux",
            uid: 0,
            clock: () => f.plan.expires - 60000,
          },
        ),
        (error) => error === failure,
      );
      assert.equal(f.k.handles.size, 0);
    } finally {
      release?.();
      input.destroy();
      output.destroy();
      await Promise.allSettled([
        finished(input, { cleanup: true }),
        finished(output, { cleanup: true }),
      ]);
      await f.worker.close();
    }
  }
});

test("Windows gateway admission requires exact short vector and independent host source and privilege pins", async () => {
  const f = await workerSourceFixture("win32"),
    snapshot = await prerequisiteSourceSnapshot(f.manifest, f.read),
    admission = workerAdmission("win32"),
    node = { path: "C:\\Tools\\node.exe", bytes: 100, sha256: "c".repeat(64) },
    host = {
      path: "C:\\Program Files\\PowerShell\\7\\pwsh.exe",
      bytes: 100,
      sha256: "d".repeat(64),
    },
    output = "C:\\Private\\reports",
    privilege = {
      userSid: "S-1-5-18",
      sessionId: 0,
      task: "exclusive",
      pipe: "private",
    },
    worker = windowsPrerequisiteWorker(
      snapshot,
      node.path,
      output,
      admission.nonce,
      admission,
    ),
    request = {
      schemaVersion: 1,
      platform: "win32",
      output,
      expires: admission.expires,
      admission,
      node,
      host,
      privilege,
      source: snapshot.sources,
      worker,
    },
    approvals = {
      nodeSha256: node.sha256,
      hostSha256: host.sha256,
      sourceSha256: observationDigest(snapshot.sources),
      privilegeSha256: observationDigest(privilege),
    };
  assert.deepEqual(
    windowsPrerequisiteGatewayAdmission(request, snapshot, approvals),
    request,
  );
  assert.equal(worker.args.length, 2);
  assert.ok(worker.args.join(" ").length < 1024);
  assert.throws(() =>
    prerequisiteWorkerEntry(snapshot, workerAdmission("linux"), {
      windowsPipe: true,
    }),
  );
  for (const damage of [
    "interpreter",
    "source",
    "privilege",
    "pipe",
    "snapshot",
    "gateway",
    "expired",
    "output",
  ]) {
    const value = structuredClone(request),
      pins = { ...approvals },
      captured = { ...snapshot, gateway: { ...snapshot.gateway } };
    if (damage === "interpreter") delete pins.hostSha256;
    if (damage === "source") pins.sourceSha256 = "0".repeat(64);
    if (damage === "privilege") delete pins.privilegeSha256;
    if (damage === "pipe") value.worker.args[1] += "other";
    if (damage === "snapshot") value.worker.source.text += "\n// changed";
    if (damage === "gateway")
      captured.gateway.bytes = Buffer.from("changed script");
    if (damage === "expired") value.admission.expires = 0;
    if (damage === "output") value.output = "C:\\Outside\\reports";
    assert.throws(() =>
      windowsPrerequisiteGatewayAdmission(value, captured, pins),
    );
  }
  const inactive = createPrerequisiteWorker(
    { nonce: admission.nonce, admissionSha256: observationDigest(admission) },
    { platform: "win32" },
  );
  await assert.rejects(
    inactive.invoke({
      id: 1,
      nonce: admission.nonce,
      operation: "init",
      args: [admission],
    }),
  );
  await inactive.close();
});

test("Windows worker operations reach held native file reads through raw IPC only", async () => {
  const k = windowsFileTranscript(),
    plan = workerAdmission("win32"),
    file = k.root + "\\assets\\source",
    content = Buffer.from("data"),
    request = prerequisiteCreationRequest(plan.root, file, content),
    intent = k.intent(request),
    worker = createPrerequisiteWorker(
      { nonce: plan.nonce, admissionSha256: observationDigest(plan) },
      { platform: "win32", exchange: k.exchange },
    );
  let id = 0;
  const invoke = (operation, args = []) =>
    worker.invoke({ id: ++id, nonce: plan.nonce, operation, args });
  await invoke("init", [plan]);
  const created = await invoke("create", [
    file,
    { nativeBytes: content.toString("base64") },
    { executable: false, intent },
  ]);
  assert.equal(created.birthProtected, true);
  assert.equal(created.identity.identity, k.nodes.get(file).identity);
  const held = await invoke("hold", [file, { maximum: 4, sealed: true }]);
  const bytes = await invoke("read-held", [held.readId, 0, 4]);
  assert.deepEqual(Buffer.from(bytes.nativeBytes, "base64"), content);
  assert.ok(k.events.includes("create"));
  assert.ok(k.events.includes("seal"));
  assert.equal((await invoke("close")).custodianRetired, false);
});

test("Git extraction independently settles a failed second policy barrier before propagating its first cause", async () => {
  const f = extractorFixture(),
    original = f.effects.readPolicy,
    cause = new Error("Interrupted policy barrier");
  let reads = 0;
  f.effects.readPolicy = async (request) => {
    if (++reads === 2) throw cause;
    return original(request);
  };
  await assert.rejects(
    materializeReviewedGit(
      "C:\\Private\\archive",
      "C:\\Private\\content",
      f.reviewed,
      f.effects,
      f.options,
    ),
    (error) => error === cause,
  );
  assert.deepEqual(f.events, ["settle"]);
  assert.equal(f.records.at(-1).status, "RETIRED");
});

test("Git staged inventory must rejoin the independently held member identity before sealing", async () => {
  const f = extractorFixture(),
    original = f.effects.readProtected;
  f.effects.readProtected = async (request) => ({
    ...(await original(request)),
    identitySha256: f.events.includes("staged") ? "f".repeat(64) : hash,
  });
  await assert.rejects(
    materializeReviewedGit(
      "C:\\Private\\archive",
      "C:\\Private\\content",
      f.reviewed,
      f.effects,
      f.options,
    ),
  );
  assert.deepEqual(f.events, ["extract", "settle", "staged"]);
});
