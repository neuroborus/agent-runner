import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { win32 as path } from "node:path";
import {
  initializeNativeJob,
  observationDigest,
  recordExperimentPreparationEffect,
  recordExperimentPreparation,
  PLATFORMS,
} from "../ci/native/index.js";
import {
  WINDOWS_HELPER_NAMES,
  windowsSystemRecipes,
  windowsExperimentBuildInventory,
  windowsExperimentDependencies,
  normalizeWindowsExperimentPreparation,
  normalizeWindowsPreparation,
  inspectWindowsExperimentPe,
  inspectWindowsPe,
  windowsSignedPublication,
  prepareWindowsExperiment,
  recoverWindowsExperimentPreparation,
  prepareWindowsExperimentCases,
  loadWindowsExperiment,
} from "../ci/native/win32/index.js";

const candidateSha = "a".repeat(40),
  H = "b".repeat(64),
  directory = "C:\\Fixture\\report\\native";
const sources = [
  ...WINDOWS_HELPER_NAMES.map((name) => name + ".c"),
  "custody.h",
  "effective-reader.h",
  "account.h",
  "audit-policy-remove.h",
  "experiment.h",
].map((name) => ({ name, sha256: H }));
function fixture() {
  const job = initializeNativeJob(
    {
      candidateSha,
      platform: "win32",
      repository: "example/native",
      runId: "1",
      runAttempt: 1,
    },
    { schemaVersion: 7, purpose: "experiment" },
  );
  const sourceDirectory = directory + "-bootstrap",
    output = path.join(directory, "platform-build"),
    image = (name) => ({
      path: path.join(sourceDirectory, name + ".exe"),
      sha256: H,
      signatureSha256: H,
    }),
    context = {
      candidateSha,
      platform: "win32",
      tier: "system",
      runId: "1",
      runAttempt: 1,
      executionId: "build",
      jobBindingSha256: H,
      closureSha256: H,
      selectedSystemSha256: null,
    },
    bootstrap = {
      purpose: "experiment",
      context,
      nonce: "c".repeat(32),
      reader: image("custody-reader"),
      bridge: image("custody-bridge"),
      plan: { path: path.join(sourceDirectory, "plan"), sha256: H },
      runnerSid: "S-1-5-21-1-2-3-1001",
      sources: sources
        .filter(({ name }) =>
          [
            "custody-reader.c",
            "custody-bridge.c",
            "custody.h",
            "effective-reader.h",
            "account.h",
            "audit-policy-remove.h",
            "experiment.h",
          ].includes(name),
        )
        .map(({ name, sha256 }) => ({
          path: path.join(sourceDirectory, name),
          sha256,
        })),
      bindingSha256: H,
      sdkSha256: H,
      buildSha256: H,
    },
    prepared = {
      purpose: "experiment",
      job,
      directory,
      sourceDirectory,
      output,
      bootstrap,
      sources: structuredClone(sources),
      helpers: WINDOWS_HELPER_NAMES.map((name) => ({
        name,
        sourceSha256: H,
        ...image(name),
      })),
      tools: [
        {
          name: "compiler",
          path: "C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise\\VC\\Tools\\MSVC\\14.0\\bin\\Hostx64\\x64\\cl.exe",
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
    declaration = {
      purpose: "experiment",
      schemaVersion: 1,
      sourceDirectory,
      sources: prepared.sources,
      bootstrap,
      command: {
        helper: image("build-helper"),
        toolSignatures: { compiler: H, sdk: H },
        unsignedHelpers: Object.fromEntries(
          WINDOWS_HELPER_NAMES.map((name) => [name, H]),
        ),
        helperSignatures: Object.fromEntries(
          WINDOWS_HELPER_NAMES.map((name) => [name, H]),
        ),
      },
      cases: windowsSystemRecipes()
        .filter(({ id }) => id !== "build")
        .map(({ id }) => ({
          id,
          custody: { ...bootstrap, context: { ...context, executionId: id } },
          bindings: {},
        })),
    };
  const binding = {
      ...job,
      checkoutSha: candidateSha,
      osBuild: "10.0.26100",
      nodeVersion: "v24.21.0",
    },
    env = {
      CI: "true",
      GITHUB_ACTIONS: "true",
      ImageOS: "win25",
      RUNNER_ENVIRONMENT: "github-hosted",
      RUNNER_OS: "Windows",
      GITHUB_REPOSITORY: job.repository,
      GITHUB_RUN_ID: "1",
      GITHUB_RUN_ATTEMPT: "1",
    };
  return {
    job,
    prepared,
    declaration,
    settings: {
      binding,
      env,
      platform: "win32",
      architecture: "x64",
      nodeVersion: "v24.21.0",
      persistBootstrap: async () => {},
    },
  };
}

test("Windows experiment preparation requires every fixed helper/header/case and disjoint custody purpose", () => {
  const f = fixture();
  assert.deepEqual(
    windowsExperimentBuildInventory(f.prepared),
    windowsSystemRecipes(),
  );
  assert.deepEqual(
    normalizeWindowsExperimentPreparation(f.declaration, candidateSha),
    f.declaration,
  );
  assert.throws(() => normalizeWindowsPreparation(f.declaration, candidateSha));
  for (const damage of [
    (value) => value.helpers.pop(),
    (value) => value.sources.pop(),
    (value) => (value.helpers[0].sourceSha256 = "d".repeat(64)),
  ]) {
    const value = structuredClone(f.prepared);
    damage(value);
    assert.throws(() => windowsExperimentBuildInventory(value));
  }
  const missing = structuredClone(f.declaration);
  missing.cases.pop();
  assert.throws(() =>
    normalizeWindowsExperimentPreparation(missing, candidateSha),
  );
  const promoted = structuredClone(f.declaration);
  delete promoted.bootstrap.purpose;
  promoted.bootstrap.reviewSha256 = promoted.bootstrap.bindingSha256;
  delete promoted.bootstrap.bindingSha256;
  assert.throws(() =>
    normalizeWindowsExperimentPreparation(promoted, candidateSha),
  );
});

test("Windows dependency output rejects substituted sources, ambient inputs and omitted includes", () => {
  const source = "C:\\Fixture\\source\\helper.c",
    include = "C:\\Fixture\\source\\experiment.h",
    value = { Version: "1.2", Data: { Source: source, Includes: [include] } },
    encode = (value) => Buffer.from(JSON.stringify(value));
  assert.deepEqual(
    windowsExperimentDependencies(encode(value), source, path.dirname(source)),
    [include],
  );
  for (const data of [
    { Source: source + ".other", Includes: [include] },
    { Source: source, Includes: [] },
    { Source: source, Includes: ["C:\\Other\\header.h"] },
    { ...value.Data, ImportedModules: ["unbound"] },
  ])
    assert.throws(() =>
      windowsExperimentDependencies(
        encode({ ...value, Data: data }),
        source,
        path.dirname(source),
      ),
    );
});

test("Windows fixed cases retain copy kinds and the complete copied Git loader graph", async () => {
  const { prepared } = fixture(),
    records = new Map(),
    system = "C:\\Windows\\System32\\KERNEL32.dll",
    git = "C:\\Program Files\\Git\\mingw64\\bin\\git.exe",
    dependency = path.join(path.dirname(git), "runtime.dll"),
    image = (file, imports) => ({
      path: file,
      sha256: H,
      signatureSha256: H,
      imports,
    }),
    runtime = [
      ...prepared.helpers.map((helper) =>
        image(helper.path, [{ name: "KERNEL32.dll", path: system }]),
      ),
      image(system, []),
    ],
    observed = {
      runtime,
      helperLoaders: Object.fromEntries(
        prepared.helpers.map(({ name }) => [name, [system]]),
      ),
      sdkInputs: [
        {
          file: "C:\\Program Files (x86)\\Windows Kits\\10\\Include\\10.0.26100.0\\um\\windows.h",
          sha256: H,
        },
      ],
      observation: { expected: { sdk: { sha256: H } } },
    },
    native = {
      readImage: async (file) => ({
        held: true,
        independent: true,
        unchanged: true,
        sha256: H,
        signatureSha256: H,
        pe: {
          imports:
            file === git ? [{ name: "runtime.dll", host: "runtime.dll" }] : [],
        },
      }),
      prepareVolume: async () => ({ file: "D:\\Fixture\\foreign" }),
      write: async (name, value) =>
        records.set(name, Buffer.from(JSON.stringify(value) + "\n")),
      writeBytes: async (name, value) => records.set(name, value),
    };
  prepared.environment = { SystemRoot: "C:\\Windows" };
  const result = await prepareWindowsExperimentCases(
    prepared,
    observed,
    native,
    { exists: async (file) => assert.equal(file, dependency) },
  );
  assert.deepEqual(
    result.cases.map(({ id }) => id),
    windowsSystemRecipes()
      .slice(1)
      .map(({ id }) => id),
  );
  for (const entry of result.cases.filter(
    ({ bindings }) => bindings.operations,
  )) {
    const specification = JSON.parse(
        records.get(path.basename(entry.bindings.operations.expectation.path)),
      ),
      entries = records
        .get(path.basename(entry.custody.plan.path))
        .toString()
        .trim()
        .split("\n")
        .slice(1)
        .map((line) => {
          const [kind, _sha, _signature, hex] = line.split(" ");
          return { kind, path: Buffer.from(hex, "hex").toString("utf16le") };
        });
    for (const asset of specification.assets)
      if (asset.source !== null)
        assert.equal(entries[asset.index].kind, entries[asset.source].kind);
    const loader = specification.slots.loader;
    for (const component of loader)
      for (const imported of component.imports)
        assert.ok(loader.some(({ index }) => index === imported.index));
    if (entry.id.startsWith("git.")) {
      assert.ok(
        loader.some(
          ({ index }) =>
            entries[index].path ===
            entry.bindings.input.request.storage + "\\runtime.dll",
        ),
      );
      const asset = specification.assets.find(
          ({ index }) =>
            entries[index].path === entry.bindings.input.metadata + "\\index",
        ),
        bytes = records.get(path.basename(entries[asset.source].path)),
        body = bytes.subarray(0, -20);
      assert.equal(body.subarray(0, 4).toString(), "DIRC");
      assert.equal(body.readUInt32BE(4), 2);
      assert.equal(body.readUInt32BE(8), 1);
      assert.equal((body.length - 12) % 8, 0);
      const pathnameEnd = 74 + (body.readUInt16BE(72) & 0xfff);
      assert.ok(body.subarray(pathnameEnd).length > 0);
      assert.ok(body.subarray(pathnameEnd).every((byte) => byte === 0));
      assert.deepEqual(
        bytes.subarray(-20),
        createHash("sha1").update(body).digest(),
      );
    }
  }
});

function markedPe() {
  const bytes = Buffer.alloc(1024),
    optional = 88,
    section = 328;
  bytes.writeUInt16LE(0x5a4d);
  bytes.writeUInt32LE(64, 60);
  bytes.writeUInt32LE(0x4550, 64);
  bytes.writeUInt16LE(0x8664, 68);
  bytes.writeUInt16LE(1, 70);
  bytes.writeUInt16LE(240, 84);
  bytes.writeUInt16LE(0x20b, optional);
  bytes.writeUInt32LE(16, optional + 108);
  bytes.write(".nexp", section);
  bytes.writeUInt32LE(512, section + 8);
  bytes.writeUInt32LE(4096, section + 12);
  bytes.writeUInt32LE(512, section + 16);
  bytes.writeUInt32LE(512, section + 20);
  bytes.writeUInt32LE(0x40000040, section + 36);
  bytes.write("native-ci-experiment-v1\0", 512);
  return bytes;
}
test("unsigned experiment PE observations cannot be promoted by adding a certificate", () => {
  const bytes = markedPe(),
    observed = inspectWindowsExperimentPe(bytes);
  assert.equal(observed.purpose, "experiment");
  assert.equal(observed.signature.authenticated, false);
  const signed = Buffer.concat([bytes, Buffer.alloc(8)]);
  signed.writeUInt32LE(1024, 232);
  signed.writeUInt32LE(8, 236);
  signed.writeUInt32LE(8, 1024);
  signed.writeUInt16LE(0x200, 1028);
  signed.writeUInt16LE(2, 1030);
  assert.throws(() => inspectWindowsPe(signed));
  assert.throws(() => windowsSignedPublication(bytes, signed));
  const unsafe = Buffer.from(bytes);
  unsafe.writeUInt32LE(0xc0000040, 364);
  assert.throws(() => inspectWindowsExperimentPe(unsafe));
});

test("Windows protected compiles continue after retired failures while partial builds remain inadmissible", async () => {
  for (const uncertain of [false, true]) {
    const f = fixture(),
      attempted = [],
      saved = [],
      settlement = {
        status: "RETIRED",
        independent: true,
        emergencyCleanup: false,
        nativeEventSha256: H,
      };
    await assert.rejects(
      prepareWindowsExperiment(
        f.job,
        directory,
        async (job) => saved.push(job),
        {
          ...f.settings,
          bootstrap: async () => f.prepared,
          open: async () => ({
            run: async (request, operation) => {
              if (operation.mode === "compile")
                attempted.push(operation.helper.name);
              return {
                independent: true,
                requestSha256: observationDigest(request),
                toolSha256: request.toolSha256,
                signal: null,
                timedOut: false,
                settlement:
                  uncertain && attempted.length === 2
                    ? { ...settlement, independent: false }
                    : settlement,
                exitCode: operation.mode === "compile" ? 1 : 0,
                stdout:
                  operation.mode === "compiler-version"
                    ? "Compiler Version 1.2 for x64"
                    : operation.mode === "sdk-version"
                      ? "Version 1.2"
                      : "",
                stderr:
                  operation.mode === "compile"
                    ? "compiler failure " + attempted.length
                    : "",
              };
            },
            write: () =>
              assert.fail("A failed build cannot publish preparation"),
            close: async () => settlement,
          }),
        },
      ),
      (error) => error.cause.stderr === "compiler failure 1",
    );
    assert.deepEqual(
      attempted,
      uncertain ? WINDOWS_HELPER_NAMES.slice(0, 2) : [...WINDOWS_HELPER_NAMES],
    );
    assert.equal(saved.at(-1).failure, "preparation-failed");
    assert.equal(saved.at(-1).preparation, null);
  }
});

test("interrupted Windows startup and unsealed recovery retain uncertainty without retry", async () => {
  const f = fixture(),
    saved = [];
  let closed = 0;
  await assert.rejects(
    prepareWindowsExperiment(
      f.job,
      directory,
      async (value) => saved.push(value),
      {
        ...f.settings,
        bootstrap: async () => f.prepared,
        open: async (_value, { retain }) => {
          retain({
            close: async () => {
              closed++;
              throw new Error("unsettled owner");
            },
          });
          throw new Error("lost startup acknowledgement");
        },
      },
    ),
    (error) => error.experimentJob.failure === "preparation-failed",
  );
  assert.equal(closed, 1);
  assert.equal(saved.at(-1).preparationEffects.settlement.status, "RETAINED");
  const partial = recordExperimentPreparationEffect(f.job, {
    admission: "possible",
    settlement: {
      status: "RETAINED",
      independent: false,
      emergencyCleanup: false,
    },
    receiptSha256: null,
  });
  const recovered = await recoverWindowsExperimentPreparation(
    partial,
    directory,
    async () => {},
    {
      ...f.settings,
      readdir: async (parent) => {
        assert.equal(parent, path.dirname(directory));
        return ["native-bootstrap-0.json"];
      },
      read: async () =>
        Buffer.from(
          JSON.stringify({
            purpose: "experiment",
            phase: "bootstrap-compile-possible",
          }),
        ),
    },
  );
  assert.equal(recovered.preparationEffects.settlement.status, "RETAINED");
  assert.equal(recovered.preparationEffects.receiptSha256, null);
  assert.equal(observationDigest(recovered), observationDigest(partial));
});

test("Windows cold loading preserves verification and cleanup failures separately", async () => {
  const f = fixture(),
    expected = {
      binding: {
        ...Object.fromEntries(
          ["candidateSha", "platform", "repository", "runId", "runAttempt"].map(
            (key) => [key, f.job[key]],
          ),
        ),
        checkoutSha: candidateSha,
        image: PLATFORMS.find(({ os }) => os === "win32").image,
        osBuild: "10.0.26100",
        architecture: "x64",
        nodeVersion: "v24.21.0",
        workflow: "native-poc",
        jobId: "2",
      },
      sources: WINDOWS_HELPER_NAMES.map((id) => ({ id, sha256: H })),
      tools: f.prepared.tools.map(({ name }) => ({
        id: name,
        sha256: H,
        version: "synthetic-version",
      })),
      sdk: { build: "synthetic-sdk", sha256: H },
      components: WINDOWS_HELPER_NAMES.map((id) => ({
        id,
        role: "helper",
        sha256: H,
        format: "pe-x64",
        loader: [],
        bindings: { source: H, build: H, abi: H },
      })),
    },
    observed = {
      ...expected,
      independent: true,
      readSha256: H,
      components: expected.components.map(({ role: _role, ...value }) => ({
        ...value,
        identityBefore: H,
        identityAfter: H,
        held: true,
        independent: true,
      })),
    };
  let job = recordExperimentPreparationEffect(f.job, {
    admission: "possible",
    settlement: {
      status: "RETAINED",
      independent: false,
      emergencyCleanup: false,
    },
    receiptSha256: null,
  });
  job = recordExperimentPreparation(job, expected, observed);
  job = recordExperimentPreparationEffect(job, {
    admission: "possible",
    settlement: {
      status: "RETIRED",
      independent: true,
      emergencyCleanup: false,
    },
    receiptSha256: H,
  });
  const primary = new Error("substituted preparation binding"),
    cleanup = new Error("unsettled observer");
  for (const failure of [null, cleanup, primary, "retained"]) {
    let closes = 0;
    await assert.rejects(
      loadWindowsExperiment(job, directory, {
        ...f.settings,
        readdir: async (parent) => {
          assert.equal(parent, path.dirname(directory));
          return ["native-bootstrap-0.json"];
        },
        read: async (file) => {
          assert.equal(
            file,
            path.join(path.dirname(directory), "native-bootstrap-0.json"),
          );
          return Buffer.from(
            JSON.stringify({ phase: "bootstrap-seal-possible", ...f.prepared }),
          );
        },
        files: {
          readProtected: async () => {
            throw primary;
          },
          settleFiles: async () => {
            closes++;
            if (failure === "retained")
              return {
                status: "RETAINED",
                independent: false,
                emergencyCleanup: false,
              };
            if (failure) throw failure;
            return {
              status: "RETIRED",
              independent: true,
              emergencyCleanup: false,
              nativeEventSha256: H,
            };
          },
        },
      }),
      (error) =>
        failure === cleanup || failure === "retained"
          ? error instanceof AggregateError &&
            error.cause === primary &&
            error.errors.length === 2 &&
            error.errors[0] === primary &&
            (failure === cleanup
              ? error.errors[1] === cleanup
              : error.errors[1] instanceof Error)
          : error === primary,
    );
    assert.equal(closes, 1);
  }
});
