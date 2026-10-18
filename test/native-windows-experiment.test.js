import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { win32 as path } from "node:path";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";

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
  normalizeWindowsExperimentPreparation,
  normalizeWindowsPreparation,
  inspectWindowsExperimentPe,
  inspectWindowsPe,
  windowsSignedPublication,
  prepareWindowsExperiment,
  recoverWindowsExperimentPreparation,
  prepareWindowsExperimentCases,
  loadWindowsExperiment,
  createWindowsPreparationFiles,
  createWindowsCaseProvisioning,
  normalizeNativePolicyBinding,
  verifyNativePolicy,
  windowsHostedCompilerArguments,
  runWindowsHostedCommand,
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
      schemaVersion: 2,
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
          path: "C:\\Program Files (x86)\\Windows Kits\\10\\bin\\10.0.22621.0\\x64\\rc.exe",
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
      ...Object.fromEntries(
        ["candidateSha", "platform", "repository", "runId", "runAttempt"].map(
          (key) => [key, job[key]],
        ),
      ),
      image: "windows-2025",
      architecture: "x64",
      workflow: "native-poc",
      jobId: "2",
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
  declaration.schemaVersion = 2;
  declaration.command = { helper: declaration.command.helper };
  for (const entry of declaration.cases)
    entry.custody.context.jobBindingSha256 = observationDigest(binding);
  prepared.binding = binding;
  prepared.bootstrap.context.jobBindingSha256 = observationDigest(binding);
  prepared.environment = {
    INCLUDE: "C:\\Fixture\\include",
    LIB: "C:\\Fixture\\lib",
    SystemRoot: "C:\\Windows",
    PATH: "C:\\Fixture\\tools",
  };
  prepared.entries = [];
  prepared.sdkBuild = "10.0.22621.0";
  prepared.sdkHeader = {
    file: "C:\\Program Files (x86)\\Windows Kits\\10\\Include\\10.0.22621.0\\um\\Windows.h",
    sha256: H,
  };
  prepared.tools = prepared.tools.map(({ signatureSha256, ...tool }) => tool);
  prepared.versions = { compiler: "1.2", sdk: "1.2" };
  const commandEnvironment = {
    CI: "true",
    GITHUB_ACTIONS: "true",
    LANG: "C",
    ...prepared.environment,
    TEMP: "C:\\Fixture",
    TMP: "C:\\Fixture",
  };
  const command = (file, args, stdout = "") => ({
    file,
    args,
    cwd: sourceDirectory,
    env: commandEnvironment,
    timeout: 60000,
    maxBuffer: 1048576,
    exitCode: 0,
    signal: null,
    timedOut: false,
    stdout,
    stderr: "",
  });
  prepared.commands = [
    command("git", ["rev-parse", "HEAD"], candidateSha),
    command("where.exe", ["cl.exe"], prepared.tools[0].path),
    command(prepared.tools[0].path, ["/Bv"], "Compiler Version 1.2 for x64"),
    ...WINDOWS_HELPER_NAMES.map((name) =>
      command(
        prepared.tools[0].path,
        windowsHostedCompilerArguments(
          path.join(sourceDirectory, name + ".c"),
          path.join(sourceDirectory, name + ".exe"),
        ),
      ),
    ),
    command(prepared.tools[1].path, ["/?"], "Version 1.2"),
    command(
      path.join(prepared.environment.SystemRoot, "System32", "whoami.exe"),
      ["/user", "/fo", "csv", "/nh"],
      '"fixture","S-1-5-21-1-2-3-1001"',
    ),
  ];
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

test("Windows fixed cases retain copy kinds and the complete copied Git loader graph", async () => {
  const { prepared } = fixture(),
    records = new Map(),
    system = "C:\\Windows\\System32\\KERNEL32.dll",
    git = "C:\\Program Files\\Git\\mingw64\\bin\\git.exe",
    bytes = Buffer.from("held Git fixture"),
    dependency = path.join(path.dirname(git), "runtime.dll"),
    image = (file, imports) => ({
      path: file,
      sha256: H,
      signatureSha256: H,
      imports,
    }),
    runtime = [
      ...prepared.helpers.map((helper) =>
        image(helper.path, [
          { name: "KERNEL32.dll", path: system, delay: false },
        ]),
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
        bytes,
        sha256: createHash("sha256").update(bytes).digest("hex"),
        identitySha256: H,
        signatureSha256: H,
        pe: {
          imports: file === git ? [{ name: "runtime.dll", delay: false }] : [],
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
        read: async (file) => {
          assert.equal(file, directory + "-selector.json");
          return Buffer.from(JSON.stringify(f.prepared));
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

test("experiment registry retains pre-setup dependencies until independent task settlement", async () => {
  for (const fault of [null, "retained", "emergency"]) {
    const f = fixture(),
      files = createWindowsPreparationFiles({
        job: f.job,
        directory,
        output: f.prepared.output,
        manifest: { windowsPreparation: { bootstrap: f.prepared.bootstrap } },
      }),
      signal = new AbortController().signal;
    const primary = new Error("rejected admission"),
      cleanup = new Error("cleanup interrupted"),
      calls = [],
      reader = {
        beginCleanup: async () => calls.push("cleanup"),
        close: async () => {
          calls.push("bootstrap");
          return {
            status: fault === "retained" ? "RETAINED" : "RETIRED",
            independent: fault !== "retained",
            emergencyCleanup: fault === "emergency",
            taskRemoved: true,
            preSetup: true,
            nativeEventSha256: H,
            primaryCause: primary,
            cause: cleanup,
          };
        },
      };
    files.retainReader(reader);
    await files.beginCleanup(signal);
    if (fault) {
      await assert.rejects(
        files.retireReaders(),
        (error) =>
          error.errors.length === 1 &&
          error.errors[0].cause === cleanup &&
          error.errors[0].primaryCause === primary,
      );
      await assert.rejects(files.settleFiles());
    } else {
      const [settlement] = await files.retireReaders();
      assert.equal(settlement.preSetup, true);
      assert.equal(await files.settleFiles(), null); // No observer was started.
    }
    assert.deepEqual(calls, ["cleanup", "bootstrap"]);
  }
});

function hostedFixture() {
  const f = fixture(),
    files = new Map(),
    calls = [],
    directories = new Set(),
    image = markedPe(),
    source = Buffer.from("/* exact candidate */\n");
  const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
  const compiler = f.prepared.tools[0].path,
    sdk = f.prepared.tools[1].path;
  files.set(compiler, source);
  files.set(sdk, source);
  files.set(f.prepared.sdkHeader.file, source);
  const read = async (file) => {
    if (files.has(file)) return files.get(file);
    if (/\.(?:c|h)$/u.test(file) && !file.includes("Windows Kits"))
      return source;
    throw Object.assign(new Error("Missing output"), { code: "ENOENT" });
  };
  const options = {
    ...f.settings,
    checkoutRoot: "C:\\Fixture\\checkout",
    env: {
      ...f.settings.env,
      RUNNER_TEMP: "C:\\Fixture",
      SystemRoot: "C:\\Windows",
      PATH: "C:\\Fixture\\tools",
    },
    readCandidate: async () => source,
    read: read,
    readInstalled: read,
    selectToolchain: async () => ({
      environment: {
        ...f.prepared.environment,
        WindowsSDKVersion: "10.0.22621.0\\",
        WindowsSdkDir: "C:\\Program Files (x86)\\Windows Kits\\10\\",
      },
    }),
    filesystem: {
      realpath: async (file) => file,
      lstat: async (file) => ({
        isFile: () => true,
        isSymbolicLink: () => false,
        nlink: 1,
        size: (await read(file)).length,
      }),
      readFile: read,
      mkdir: async (file) => {
        if (directories.has(file))
          throw Object.assign(new Error("Exists"), { code: "EEXIST" });
        directories.add(file);
      },
      writeFile: async (file, bytes) => {
        if (files.has(file))
          throw Object.assign(new Error("Exists"), { code: "EEXIST" });
        files.set(file, Buffer.from(bytes));
      },
      unlink: async (file) => {
        files.delete(file);
      },
    },
    command: async (file, args, settings) => {
      calls.push({ file, args, settings });
      let stdout = "",
        stderr = "";
      if (file === "git") stdout = candidateSha + "\n";
      else if (file === "where.exe") stdout = compiler + "\n";
      else if (file === compiler) {
        if (args[0] === "/Bv") stdout = "Compiler Version 1.2 for x64";
        else
          files.set(args.find((arg) => arg.startsWith("/Fe")).slice(3), image);
      } else if (file === sdk) stdout = "Version 1.2";
      else if (file.endsWith("whoami.exe"))
        stdout = '"fixture","S-1-5-21-1-2-3-1001"';
      else if (args[0] === "--experiment-seal")
        stdout = JSON.stringify({
          purpose: "experiment",
          sealed: true,
          planSha256: args[2],
        });
      else assert.fail("Unexpected hosted command: " + file);
      return { exitCode: 0, signal: null, timedOut: false, stdout, stderr };
    },
  };
  const retired = {
    status: "RETIRED",
    independent: true,
    emergencyCleanup: false,
    nativeEventSha256: H,
  };
  const held = async (file) => {
    const bytes = await read(file);
    return {
      bytes,
      sha256: sha(bytes),
      identitySha256: H,
      nativeEventSha256: H,
      held: true,
      independent: true,
      unchanged: true,
      protectedDacl: true,
      protectedParents: true,
      signatureSha256: sha(bytes),
      pe: { imports: [] },
    };
  };
  const write = async (name, value) =>
    files.set(path.join(directory, name), Buffer.from(JSON.stringify(value)));
  const filesOwner = {
    readBuildDirectory: async () => ({
      independent: true,
      held: true,
      protectedParents: true,
      daclSha256: H,
      identity: "held directory",
    }),
    readProtected: async ({ file }) => held(file),
    readExperimentInput: held,
    readExperimentImage: held,
    resolveExperimentImport: () => assert.fail("No synthetic imports"),
    verify: async () => ({
      ...retired,
      noLiveMembers: true,
      tasksRemoved: true,
    }),
    settleFiles: async () => retired,
  };
  options.open = async (prepared) => ({
    files: filesOwner,
    read: held,
    readInput: held,
    readImage: async (file) =>
      files.has(file)
        ? held(file)
        : { ...(await held(prepared.helpers[0].path)), pe: { imports: [] } },
    prepareVolume: async () => ({ file: "D:\\Fixture\\volume" }),
    write,
    writeBytes: async (name, bytes) =>
      files.set(path.join(directory, name), bytes),
    close: async () => {
      const observer = {
        nonce: "e".repeat(32),
        helper: { pid: 3 },
        bridge: { pid: 4 },
        taskSha256: H,
      };
      await write("windows-experiment-close.json", {
        purpose: "experiment",
        schemaVersion: 2,
        observer,
      });
      for (const [kind, status] of [
        ["birth", "POSSIBLE"],
        ["result", "RETIRED"],
      ])
        await write(`windows-files-${observer.nonce}-${kind}.json`, {
          ...observer,
          status,
        });
      return { ...retired, observer };
    },
  });
  return { ...f, files, calls, options, filesOwner, source, image };
}

test("Windows hosted preparation builds each exact-candidate helper once and cold-loads held output", async () => {
  const f = hostedFixture(),
    saved = [];
  f.options.env.Path = f.options.env.PATH;
  delete f.options.env.PATH;
  const built = await prepareWindowsExperiment(
    f.job,
    directory,
    async (job) => saved.push(job),
    f.options,
  );
  const compiles = f.calls.filter(
    ({ file, args }) => file === f.prepared.tools[0].path && args[0] !== "/Bv",
  );
  assert.equal(f.calls[0].settings.env.PATH, f.options.env.Path);
  assert.equal(compiles.length, WINDOWS_HELPER_NAMES.length);
  assert.ok(
    compiles.every(
      ({ args }) =>
        !args.includes("/sourceDependencies") &&
        args.includes("/DNATIVE_CI_EXPERIMENT=1"),
    ),
  );
  assert.equal(built.preparation.schemaVersion, 2);
  assert.ok(
    built.preparation.commands.every(
      (command) =>
        command.compilerPolicy === undefined &&
        command.settlement === undefined,
    ),
  );
  const prepared = built.preparation.prepared,
    binding = normalizeNativePolicyBinding(
      built.preparation.system.bindings[0].policyBinding,
    );
  const owner = createWindowsCaseProvisioning(
    {
      job: built.job,
      directory,
      output: prepared.output,
      plan: { bootstrap: prepared.bootstrap },
      guard: () => {},
    },
    f.filesOwner,
  );
  const proof = await owner.observeBuildPolicy(binding, { prepared }, {});
  assert.equal(
    verifyNativePolicy(
      binding.template,
      null,
      proof.provisioning,
      binding.context,
      proof.requestSha256,
      proof.observed,
    ).independent,
    true,
  );
  assert.equal(proof.observed.policy.policy.compiler, undefined);
  const readImage = f.filesOwner.readExperimentImage;
  f.filesOwner.readExperimentImage = async (file) => ({
    ...(await readImage(file)),
    independent: false,
  });
  await assert.rejects(owner.observeBuildPolicy(binding, { prepared }, {}));
  f.filesOwner.readExperimentImage = readImage;
  f.options.command = f.options.bootstrap = () =>
    assert.fail("Cold loading cannot compile or acquire");
  const loaded = await loadWindowsExperiment(built.job, directory, {
    ...f.options,
    files: f.filesOwner,
  });
  assert.equal(loaded.runtime.length, WINDOWS_HELPER_NAMES.length);
  for (const fault of [
    "output",
    "mixed-close",
    "candidate",
    "environment",
    "legacy",
    "incomplete",
  ]) {
    if (["output", "mixed-close"].includes(fault)) {
      const file =
          fault === "output"
            ? built.preparation.prepared.helpers[0].path
            : path.join(directory, "windows-experiment-close.json"),
        original = f.files.get(file);
      f.files.set(
        file,
        fault === "output"
          ? Buffer.from("substituted output")
          : Buffer.from(
              JSON.stringify({
                ...JSON.parse(original),
                bootstrapSettlement: {},
              }),
            ),
      );
      await assert.rejects(
        loadWindowsExperiment(built.job, directory, {
          ...f.options,
          files: f.filesOwner,
        }),
      );
      f.files.set(file, original);
    } else {
      const record = structuredClone(built.preparation.prepared);
      if (fault === "candidate")
        record.helpers[0].sourceSha256 = "f".repeat(64);
      if (fault === "environment")
        record.commands.find(
          (command) => command.file === record.tools[0].path,
        ).env.INCLUDE = "C:\\Other";
      if (fault === "legacy") record.schemaVersion = 1;
      if (fault === "incomplete") record.commands.pop();
      assert.throws(() => windowsExperimentBuildInventory(record));
    }
  }
});

test("Windows ordinary imports rejoin observed namespace and physical modules on cold load", async () => {
  const f = hostedFixture(),
    contract = "api-fixture-runtime-l1-1-0.dll",
    physical = "api-fixture-forward-l1-1-0.dll",
    host = "C:\\Windows\\System32\\fixture-runtime.dll",
    forward = "C:\\Windows\\System32\\" + physical,
    resolutions = new Map([
      [contract, host],
      [physical, forward],
    ]),
    names = [],
    unresolved = new Error("Unresolved installed import"),
    immutable = Object.freeze(new Error("Immutable loader failure"));
  for (const file of resolutions.values()) f.files.set(file, f.image);
  let fault;
  const open = f.options.open;
  f.options.open = async (prepared) => {
    const native = await open(prepared),
      read = native.readImage,
      image = prepared.helpers[0].path;
    native.readImage = f.filesOwner.readExperimentImage = async (
      file,
      installed,
    ) => {
      const held = await read(file, installed);
      if (file === image)
        held.pe = {
          imports: [
            { name: contract, delay: false },
            { name: physical, delay: true },
          ],
        };
      if (fault === "held-image" && file === host)
        held.bytes = Buffer.from("changed held image");
      return held;
    };
    native.resolveImport = f.filesOwner.resolveExperimentImport = async (
      name,
    ) => {
      names.push(name);
      assert.ok(resolutions.has(name));
      if (fault === "unresolved") throw unresolved;
      if (fault === "immutable-error") throw immutable;
      return {
        file: resolutions.get(name),
        sha256:
          fault === "bytes"
            ? "f".repeat(64)
            : createHash("sha256").update(f.image).digest("hex"),
        identitySha256: fault === "identity" ? "f".repeat(64) : H,
      };
    };
    return native;
  };
  const built = await prepareWindowsExperiment(
      f.job,
      directory,
      async () => {},
      f.options,
    ),
    compiles = f.calls.length;
  assert.ok(names.includes(contract) && names.includes(physical));
  f.options.command = () =>
    assert.fail("Cold loading cannot compile or acquire");
  const load = () =>
    loadWindowsExperiment(built.job, directory, {
      ...f.options,
      files: f.filesOwner,
    });
  const beforeCold = names.length,
    loaded = await load(),
    recorded = JSON.parse(
      f.files.get(path.join(directory, "windows-experiment-preparation.json")),
    );
  assert.deepEqual(names.slice(beforeCold), [contract, physical]);
  assert.equal(loaded.runtime.length, WINDOWS_HELPER_NAMES.length + 2);
  assert.deepEqual(recorded.runtime[0].imports, [
    { name: contract, path: host, delay: false },
    { name: physical, path: forward, delay: true },
  ]);
  for (fault of ["unresolved", "identity", "bytes", "held-image"])
    await assert.rejects(
      load,
      (error) =>
        fault !== "unresolved" ||
        (error === unresolved &&
          error.importName === contract &&
          error.image === recorded.runtime[0].path),
    );
  fault = "immutable-error";
  await assert.rejects(load, (error) => error === immutable);
  assert.equal(f.calls.length, compiles);
});

test("Windows direct-build failures and cancellation preserve the cause before System publication", async () => {
  for (const fault of ["compiler", "candidate", "output", "cancel"]) {
    const f = hostedFixture(),
      run = f.options.command,
      controller = new AbortController(),
      original = Object.assign(new Error("Original MSVC failure"), {
        exitCode: 2,
        stderr: "actual compiler diagnostic",
      }),
      saved = [];
    f.options.signal = controller.signal;
    if (fault === "candidate")
      f.options.readCandidate = async () => Buffer.from("changed source");
    f.options.command = async (file, args, settings) => {
      if (file === f.prepared.tools[0].path && args[0] !== "/Bv") {
        if (fault === "compiler") throw original;
        if (fault === "cancel") {
          controller.abort(original);
          throw original;
        }
        if (fault === "output")
          return {
            exitCode: 0,
            signal: null,
            timedOut: false,
            stdout: "",
            stderr: "",
          };
      }
      return run(file, args, settings);
    };
    await assert.rejects(
      prepareWindowsExperiment(
        f.job,
        directory,
        async (job) => saved.push(job),
        f.options,
      ),
      (error) =>
        ["compiler", "cancel"].includes(fault)
          ? error.cause === original
          : true,
    );
    assert.equal(saved.at(-1).preparationEffects.settlement.status, "RETAINED");
    assert.equal(saved.at(-1).preparation, null);
    assert.ok(!f.calls.some(({ args }) => args[0] === "--experiment-seal"));
  }
});

test("Windows ordinary cancellation owns its child tree, awaits closure and retains cleanup uncertainty", async () => {
  for (const fault of ["cancel", "stream", "cleanup"]) {
    const controller = new AbortController(),
      child = new EventEmitter(),
      kills = [],
      original = new Error("Original interruption"),
      cleanup = new Error("Tree cleanup uncertain");
    Object.assign(child, {
      pid: 4321,
      exitCode: null,
      stdout: new PassThrough(),
      stderr: new PassThrough(),
      kill: () => kills.push("leader"),
    });
    const pending = runWindowsHostedCommand("C:\\Fixture\\cl.exe", [], {
      signal: controller.signal,
      timeout: 60000,
      maxBuffer: 65536,
      spawn: () => child,
      killTree: async (pid) => {
        kills.push(pid);
        if (fault === "cleanup") throw cleanup;
      },
    });
    child.stderr.write("original compiler diagnostic");
    if (fault === "stream") child.stderr.emit("error", original);
    else controller.abort(original);
    await Promise.resolve();
    child.exitCode = 1;
    child.stdout.end();
    child.stderr.end();
    child.emit("close", 1, null);
    await assert.rejects(
      pending,
      (error) =>
        error === original &&
        error.stderr === "original compiler diagnostic" &&
        (fault !== "cleanup" || error.cleanupCause === cleanup),
    );
    assert.ok(kills.includes(child.pid));
  }
});
