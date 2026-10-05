import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  observationDigest,
  nativePolicyTemplateDigest,
  verifyNativePolicy,
  NATIVE_EFFECT_CLASSES,
  nativePackageInput,
  CODEX_RELEASE_REFERENCE,
  initializeNativeJob,
} from "../index.js";
import {
  createLinuxBuildEffects,
  createLinuxSystemEffects,
  createLinuxReleaseReaders,
  linuxElfLoadCommands,
  runLinuxOwnershipProofs,
  runLinuxFileProofs,
  runLinuxFileSession,
} from "./index.js";
import { digest } from "./inspect.js";
import { runLinuxBuildCommand } from "./proof.js";

const candidateSha = "a".repeat(40),
  hash = "b".repeat(64);
const retired = {
  status: "RETIRED",
  independent: true,
  emergencyCleanup: false,
};
const output = "/fixture/report/platform-build",
  directory = path.dirname(output);
const env = {
  CI: "true",
  GITHUB_ACTIONS: "true",
  ImageOS: "ubuntu24",
  RUNNER_TEMP: "/fixture",
  NATIVE_REVIEWED_INPUT_DIRECTORY: "/fixture/reviewed",
  NATIVE_LINUX_REVIEW_SHA256: hash,
};
function wiring() {
  const events = [],
    files = new Map(),
    tool = Buffer.from("reviewed tool bytes");
  const manifest = {
    candidateSha,
    platform: "linux",
    linuxBuild: { candidateSha },
    tools: [
      {
        name: "compiler",
        path: "/usr/bin/x86_64-linux-gnu-gcc-13",
        sha256: digest(tool),
      },
    ],
    inputs: [],
  };
  const bootstrap = {
    schemaVersion: 1,
    candidateSha,
    status: "PASS",
    phase: "verification",
    package: {
      filename: "pool/universe/b/bubblewrap/bubblewrap_0.9.0_amd64.deb",
      sha256: hash,
      size: 10,
      version: "0.9.0",
    },
    version: {
      name: "bubblewrap",
      version: "bubblewrap 0.9.0",
      sha256: digest(tool),
    },
  };
  const input = {
    job: { candidateSha, platform: "linux", versions: [] },
    output,
    manifest,
    api: { mustNotClone() {} },
    signal: new AbortController().signal,
  };
  const options = {
    env,
    readEvidence: async () => {
      events.push("bootstrap");
      return Buffer.from(JSON.stringify(bootstrap));
    },
    ownerUid: () => 1001,
    loadReviewed: async () => {
      events.push("review");
      return {
        build: manifest.linuxBuild,
        release: {
          candidateSha,
          components: [
            {
              name: "bubblewrap",
              version: "bubblewrap 0.9.0",
              sha256: digest(tool),
            },
          ],
        },
      };
    },
    protect: () => {
      events.push("protect");
    },
    read: async () => tool,
    fs: {
      realpath: async (file) => file,
      lstat: async () => ({
        isDirectory: () => true,
        isSymbolicLink: () => false,
        uid: 1001,
        mode: 0o700,
      }),
      async writeFile(file, bytes, settings) {
        assert.equal(settings.flag, "wx");
        assert.equal(settings.mode, 0o400);
        assert.ok(!files.has(file));
        files.set(file, JSON.parse(bytes));
        events.push(path.basename(file));
      },
      async mkdir() {
        events.push("mkdir");
      },
    },
    runCommand: async (request) => {
      events.push("command");
      assert.ok(
        files.has(
          path.join(
            directory,
            `linux-command-${observationDigest(request)}-intent.json`,
          ),
        ),
      );
      return {
        requestSha256: observationDigest(request),
        toolSha256: request.toolSha256,
        nativeEventSha256: hash,
        settlement: retired,
        stdout: "observed banner",
        stderr: "",
        exitCode: 0,
        signal: null,
        timedOut: false,
      };
    },
    compile: async () => {
      events.push("compile");
      assert.ok(files.has(path.join(directory, "linux-build-intent.json")));
      return { build: { candidateSha }, receipts: [], settlement: retired };
    },
  };
  const request = {
    candidateSha,
    platform: "linux",
    toolSha256: digest(tool),
    file: manifest.tools[0].path,
    args: ["--version"],
    cwd: output,
    env: { CI: "true", GITHUB_ACTIONS: "true", LANG: "C" },
    deadlineMs: 30000,
  };
  return { input, options, request, events, files, bootstrap };
}

test("Linux factories construct without effects and join bootstrap before persisted command/build admission", async () => {
  const value = wiring(),
    effects = createLinuxBuildEffects(value.input, value.options);
  createLinuxSystemEffects(
    { ...value.input, helpers: output, directory },
    value.options,
  );
  assert.deepEqual(value.events, []);
  const result = await effects.run(value.request);
  assert.equal(result.stdout, "observed banner");
  assert.ok(value.events.indexOf("review") < value.events.indexOf("command"));
  assert.ok(
    value.events.indexOf("bootstrap") < value.events.indexOf("command"),
  );
  assert.ok(!JSON.stringify([...value.files]).includes("observed banner"));
  await effects.build();
  assert.equal(
    value.files.get(path.join(output, "prepared-build.json")).settlement.status,
    "RETIRED",
  );
});

test("Linux missing review, substituted bootstrap and unapproved commands withhold effects", async () => {
  for (const failure of ["review", "bootstrap", "publication", "command"]) {
    const value = wiring();
    if (failure === "review")
      value.options.loadReviewed = async () => ({ build: null, release: null });
    if (failure === "bootstrap") value.bootstrap.candidateSha = "c".repeat(40);
    if (failure === "publication")
      value.options.loadReviewed = async () => ({
        build: value.input.manifest.linuxBuild,
        release: {
          components: [
            { name: "bubblewrap", version: "bubblewrap 0.9.0", sha256: hash },
          ],
        },
      });
    if (failure === "command") value.request.args = ["-o", "unapproved"];
    await assert.rejects(
      createLinuxBuildEffects(value.input, value.options).run(value.request),
    );
    assert.ok(!value.events.includes("command"));
    assert.equal(value.files.size, 0);
  }
});

test("Linux command uncertainty retains intent without a settled result", async () => {
  const value = wiring();
  value.options.runCommand = async (request) => ({
    requestSha256: observationDigest(request),
    toolSha256: request.toolSha256,
    settlement: {
      status: "RETAINED",
      independent: false,
      emergencyCleanup: false,
    },
  });
  await assert.rejects(
    createLinuxBuildEffects(value.input, value.options).run(value.request),
  );
  assert.equal(value.files.size, 1);
  assert.equal([...value.files.values()][0].status, "POSSIBLE");
});

test("Linux command observations retain PID and bind the complete request to independently retired receipts", async () => {
  for (const substituted of [false, true]) {
    const { request } = wiring(),
      worker = new EventEmitter(),
      writes = [];
    worker.pid = 102;
    const receipt = {
      candidateSha,
      controller: { pid: worker.pid },
      init: {
        pid: 103,
        identity: {
          bootId: "1".repeat(8) + "-1111-1111-1111-" + "1".repeat(12),
          startTicks: "1",
        },
      },
      executableDigest: request.toolSha256,
      policyDigest: observationDigest(
        substituted ? { ...request, env: { LANG: "C" } } : request,
      ),
    };
    const observe = () =>
      runLinuxBuildCommand(request, {
        env,
        platform: "linux",
        fs: {
          mkdir: async () => {},
          writeFile: async (file, bytes) =>
            writes.push({ file, input: JSON.parse(bytes) }),
        },
        start: (file, args, settings) => {
          assert.equal(args[1], writes[0].file);
          assert.deepEqual(writes[0].input.command, request);
          assert.equal(settings.env.LANG, "C");
          assert.ok(!("HOME" in settings.env));
          queueMicrotask(() => {
            worker.emit("message", {
              status: "PASS",
              receipts: [
                {
                  file: path.join(
                    path.dirname(writes[0].file),
                    "command-0.json",
                  ),
                  sha256: hash,
                },
              ],
              observation: {
                stdout: "banner",
                stderr: "",
                exitCode: 0,
                signal: null,
                timedOut: false,
              },
            });
            worker.emit("close", 0);
          });
          return worker;
        },
        readReceipt: async () => receipt,
        verify: async () => retired,
      });
    if (substituted) await assert.rejects(observe());
    else
      assert.deepEqual((await observe()).identity, {
        pid: 103,
        ...receipt.init.identity,
      });
  }
});

test("Linux prepared-build verification cannot compile; partial recovery does not require final helper bytes", async () => {
  const value = wiring(),
    preparation = { candidateSha, commands: [] };
  value.options.verifyPrepared = async (
    job,
    bundle,
    preparedOutput,
    receipt,
  ) => {
    assert.equal(preparedOutput, output);
    assert.deepEqual(receipt, preparation);
    value.events.push("verify");
    return { build: { candidateSha }, settlement: retired };
  };
  value.options.fs.lstat = async () => ({
    isDirectory: () => true,
    isSymbolicLink: () => false,
    uid: 1001,
    mode: 0o700,
  });
  value.options.fs.realpath = async (file) => file;
  value.options.fs.readdir = async () => [];
  const effects = createLinuxSystemEffects(
    { ...value.input, directory, preparation },
    value.options,
  );
  const result = await effects.verifyBuild(preparation);
  assert.equal(result.preparationSha256, observationDigest(preparation));
  assert.equal(result.status, "OBSERVED");
  assert.ok(!value.events.includes("compile"));
  const receipts = await effects.settle({ id: "linux.reference" }, null, {
    execution: {
      id: "linux.reference",
      effects: Object.fromEntries(
        NATIVE_EFFECT_CLASSES.map((effectClass) => [
          effectClass,
          {
            admission: ["builds", "policy"].includes(effectClass)
              ? "possible"
              : "not-started",
          },
        ]),
      ),
    },
  });
  assert.equal(receipts.builds.settlement.status, "RETIRED");
  assert.equal(receipts.policy.executionId, "linux.reference");
  assert.equal(receipts.helpers, null);
  assert.equal(
    (await effects.recover({ request: { candidateSha } })).status,
    "RETIRED",
  );
  value.options.fs.readdir = async (file) =>
    file === output
      ? ["build"]
      : [{ name: "command-0-possible.json", isSymbolicLink: () => false }];
  assert.equal(
    (await effects.recover({ request: { candidateSha } })).status,
    "RETAINED",
  );
  value.options.fs.readdir = async (file) =>
    file === directory ? ["linux-reference-0.json"] : [];
  const read = value.options.read;
  value.options.read = async (file) =>
    file.endsWith("/linux-reference-0.json")
      ? Buffer.from(JSON.stringify({ admissions: {} }))
      : read(file);
  const malformed = createLinuxSystemEffects(
    { ...value.input, directory, preparation },
    value.options,
  );
  assert.equal(
    (await malformed.recover({ request: { candidateSha } })).status,
    "RETAINED",
  );
});

test("Linux reference wiring records fresh policy before release and rejects undeclared authority and identities", async () => {
  for (const failure of [null, "identity", "authority"]) {
    const controller = new AbortController();
    const value = wiring(),
      launch = {
        request: { candidateSha, recipe: "linux.reference" },
        arguments: [],
      };
    const template = {
      schemaVersion: 1,
      candidateSha,
      platform: "linux",
      sourceReviewSha256: hash,
      provisioningReviewSha256: hash,
      policy: { launch, policy: { uid: { binding: "principal" } } },
      bindings: [
        {
          id: "principal",
          kind: "uid",
          paths: [["policy", "uid"]],
          minimum: 1000,
          maximum: 1099,
        },
      ],
    };
    const approval = {
      candidateSha,
      platform: "linux",
      authority: "operator-protected",
      manifestSha256: nativePolicyTemplateDigest(template),
    };
    const context = {
      candidateSha,
      platform: "linux",
      tier: "system",
      runId: "1",
      runAttempt: 1,
      jobBindingSha256: hash,
      executionId: "linux.reference",
      closureSha256: hash,
      selectedSystemSha256: null,
    };
    value.input.manifest.inputs.push({
      path: fileURLToPath(new URL("./proof.js", import.meta.url)),
      sha256: value.request.toolSha256,
    });
    value.options.verifyPrepared = async () => ({
      build: { candidateSha },
      settlement: retired,
    });
    value.options.ownership = async (job, preparedOutput, hooks) => {
      assert.equal(hooks.signal, controller.signal);
      const policy = {
        uid: failure === "identity" ? 2000 : 1001,
        ...(failure === "authority" ? { extraGrant: true } : {}),
      };
      await hooks.onPolicy({
        policy: { launch, policy },
        nativeEventSha256: hash,
      });
      value.events.push("release");
    };
    const effects = createLinuxSystemEffects(
      { ...value.input, directory, preparation: {} },
      value.options,
    );
    const prepared = await effects.prepare(
      { id: "linux.reference", group: "reference", reviewSha256: hash },
      {
        signal: controller.signal,
        policyBinding: { template, approval, context },
        recordPolicy: async (proof) => {
          verifyNativePolicy(
            template,
            approval,
            proof.provisioning,
            context,
            proof.requestSha256,
            proof.observed,
          );
          value.events.push("policy");
        },
      },
    );
    const execute = () =>
      prepared.options.ownership(value.input.job, output, {});
    if (failure) {
      await assert.rejects(execute());
      assert.ok(!value.events.includes("release"));
    } else {
      await execute();
      assert.ok(
        value.events.indexOf("policy") < value.events.indexOf("release"),
      );
      controller.abort();
      await assert.rejects(execute());
      assert.throws(() => effects.persistReference({}));
      await assert.rejects(prepared.options.files({}, {}, {}));
      for (const start of [
        () =>
          runLinuxOwnershipProofs({}, output, { signal: controller.signal }),
        () => runLinuxFileProofs({}, {}, {}, { signal: controller.signal }),
        () =>
          runLinuxFileSession({}, {}, {}, () => {}, {
            signal: controller.signal,
          }),
      ])
        await assert.rejects(
          start(),
          (error) => error === controller.signal.reason,
        );
    }
  }
});

test("Linux reference recovery requires same-run receipt bundles and every independently observed member", async () => {
  const value = wiring(),
    file = path.join(output, "linux", "evidence", "argv.json"),
    bytes = Buffer.from("protected receipt");
  const reference = initializeNativeJob(
    {
      candidateSha,
      platform: "linux",
      repository: "example/reviews",
      runId: "1",
      runAttempt: 1,
    },
    { schemaVersion: 5 },
  );
  reference.admissions.ownership = {
    admission: "possible",
    settlement: retired,
  };
  value.input.job.provenance = structuredClone(reference.provenance);
  let bundle = false,
    member = true;
  const read = value.options.read;
  value.options.read = async (name) => {
    if (name.endsWith("/linux-reference-0.json"))
      return Buffer.from(JSON.stringify(reference));
    if (name.endsWith("/linux-reference-ownership-receipts.json")) {
      if (!bundle) throw new Error("missing bundle");
      return Buffer.from(
        JSON.stringify({
          candidateSha,
          provenance: reference.provenance,
          receipts: [{ file, sha256: digest(bytes) }],
        }),
      );
    }
    return name === file ? bytes : read(name);
  };
  value.options.fs.readdir = async (name) =>
    name === output
      ? ["linux"]
      : name === directory
        ? ["linux-reference-0.json"]
        : member
          ? [{ name: "argv.json", isSymbolicLink: () => false }]
          : [];
  value.options.readReceipt = async () => ({ candidateSha });
  value.options.verify = async () => retired;
  const effects = createLinuxSystemEffects(
    { ...value.input, directory },
    value.options,
  );
  const recover = () => effects.recover({ request: { candidateSha } });
  assert.equal((await recover()).status, "RETAINED");
  bundle = true;
  assert.equal((await recover()).status, "RETIRED");
  member = false;
  assert.equal((await recover()).status, "RETAINED");
  member = true;
  reference.provenance.runAttempt = 2;
  assert.equal((await recover()).status, "RETAINED");
});

test("Linux partial command recovery uses admitted receipts when result persistence was lost", async () => {
  const value = wiring(),
    id = observationDigest(value.request),
    name = `linux-command-${id}-intent.json`;
  const read = value.options.read;
  value.options.read = async (file) => {
    if (file.endsWith("/" + name))
      return Buffer.from(
        JSON.stringify({ candidateSha, requestSha256: id, status: "POSSIBLE" }),
      );
    if (file.endsWith("-result.json"))
      throw Object.assign(new Error("absent"), { code: "ENOENT" });
    return read(file);
  };
  value.options.fs.readdir = async (file) =>
    file === output
      ? [`command-${id}`]
      : file === directory
        ? [name]
        : [{ name: "command-0.json", isSymbolicLink: () => false }];
  value.options.readReceipt = async () => ({
    candidateSha,
    policyDigest: id,
    executableDigest: value.request.toolSha256,
  });
  let observed = retired;
  value.options.verify = async () => observed;
  const effects = createLinuxSystemEffects(
    { ...value.input, directory },
    value.options,
  );
  assert.equal(
    (await effects.recover({ request: { candidateSha } })).status,
    "RETIRED",
  );
  observed = {
    status: "RETAINED",
    independent: false,
    emergencyCleanup: false,
  };
  assert.equal(
    (await effects.recover({ request: { candidateSha } })).status,
    "RETAINED",
  );
});

test("Linux build recovery joins approved build/bootstrap intent and each command's nonce and policy", async () => {
  const value = wiring(),
    bootstrap = await createLinuxBuildEffects(
      value.input,
      value.options,
    ).bootstrap();
  const intent = {
    candidateSha,
    buildSha256: observationDigest(value.input.manifest.linuxBuild),
    bootstrapSha256: bootstrap.nativeEventSha256,
    status: "POSSIBLE",
  };
  const commands = [0, 1].map((index) => ({
    candidateSha,
    nonce: `${index + 1}`.repeat(8) + "-1111-1111-1111-" + "1".repeat(12),
    policyDigest: `${index + 1}`.repeat(64),
  }));
  const read = value.options.read;
  let failure;
  value.options.read = async (file) => {
    if (file.endsWith("/linux-build-intent.json")) {
      const changed = { ...intent };
      if (failure === "candidate") changed.candidateSha = "c".repeat(40);
      if (failure === "build") changed.buildSha256 = hash;
      if (failure === "bootstrap") changed.bootstrapSha256 = hash;
      return Buffer.from(JSON.stringify(changed));
    }
    const index = file.match(/command-([01])-possible\.json$/u)?.[1];
    if (index !== undefined)
      return Buffer.from(JSON.stringify(commands[index]));
    return read(file);
  };
  value.options.fs.readdir = async (file) =>
    file === output
      ? ["build"]
      : file === directory
        ? ["linux-build-intent.json"]
        : [0, 1]
            .flatMap((index) => [
              `command-${index}.json`,
              ...(failure === "missing-intent" && index === 1
                ? []
                : [`command-${index}-possible.json`]),
            ])
            .map((name) => ({ name, isSymbolicLink: () => false }));
  value.options.readReceipt = async (file) => {
    const index = Number(file.match(/command-([01])\.json$/u)[1]);
    const receipt = {
      ...commands[index],
      caseId: "argv",
      executableDigest: value.request.toolSha256,
    };
    if (index === 1) {
      if (failure === "nonce") receipt.nonce = commands[0].nonce;
      if (failure === "policy") receipt.policyDigest = commands[0].policyDigest;
      if (failure === "executable") receipt.executableDigest = hash;
    }
    return receipt;
  };
  value.options.verify = async () => retired;
  const effects = createLinuxSystemEffects(
    { ...value.input, directory },
    value.options,
  );
  const recover = () => effects.recover({ request: { candidateSha } });
  assert.equal((await recover()).status, "RETIRED");
  for (failure of [
    "candidate",
    "build",
    "bootstrap",
    "nonce",
    "policy",
    "executable",
    "missing-intent",
  ])
    assert.equal((await recover()).status, "RETAINED", failure);
  assert.ok(!value.events.includes("compile"));
});

function elf(dynamic = false, runpath = false) {
  const bytes = Buffer.alloc(512);
  Buffer.from([127, 69, 76, 70, 2, 1, 1]).copy(bytes);
  bytes.writeUInt16LE(2, 16);
  bytes.writeUInt16LE(62, 18);
  bytes.writeUInt32LE(1, 20);
  bytes.writeUInt16LE(64, 52);
  bytes.writeBigUInt64LE(64n, 32);
  bytes.writeUInt16LE(56, 54);
  bytes.writeUInt16LE(dynamic ? 2 : 1, 56);
  bytes.writeUInt32LE(1, 64);
  bytes.writeBigUInt64LE(512n, 96);
  if (dynamic) {
    bytes.writeUInt32LE(2, 120);
    bytes.writeBigUInt64LE(200n, 128);
    bytes.writeBigUInt64LE(runpath ? 80n : 64n, 152);
    for (const [index, tag, value] of [
      [0, 5n, 300n],
      [1, 10n, 64n],
      [2, 1n, 1n],
      ...(runpath ? [[3, 29n, 16n]] : []),
    ]) {
      bytes.writeBigUInt64LE(tag, 200 + index * 16);
      bytes.writeBigUInt64LE(value, 208 + index * 16);
    }
    bytes.write("libfixture.so", 301);
    if (runpath) bytes.write("/fixture", 316);
  }
  return bytes;
}

test("Linux data-only ELF reader resolves declared load commands and rejects escaped or truncated names", () => {
  assert.deepEqual(linuxElfLoadCommands(elf()), {
    interpreter: null,
    needed: [],
    search: [],
  });
  const bytes = elf(true);
  assert.deepEqual(linuxElfLoadCommands(bytes).needed, ["libfixture.so"]);
  const escape = Buffer.from(bytes);
  escape.write("../../image.so", 301);
  assert.throws(() => linuxElfLoadCommands(escape));
  assert.throws(() => linuxElfLoadCommands(bytes.subarray(0, 250)));
});

test("Linux held readers observe bytes, provenance and kernel authority and detect substitution", async () => {
  const image = elf(),
    provenance = Buffer.from("independently reviewed publication");
  const files = new Map([
    ["/fixture/image", image],
    ["/fixture/publication", provenance],
    ["/etc/os-release", Buffer.from('ID=ubuntu\nVERSION_ID="24.04"\n')],
  ]);
  let substitute = false,
    closed = 0;
  const stat = (file) => ({
    isFile: () => true,
    isDirectory: () => false,
    dev: 1n,
    ino: BigInt([...files.keys()].indexOf(file) + 2),
    size: BigInt(files.get(file).length),
    mode: 0o100500n,
    nlink: 1n,
    uid: 0n,
    gid: 0n,
    mtimeNs: 1n,
    ctimeNs: 1n,
  });
  const fs = {
    realpath: async (file) => file,
    lstat: async (file) => ({
      ...stat(file),
      ...(substitute ? { ino: 9n } : {}),
    }),
    readFile: async () =>
      "Uid:\t1001 1001 0 1001\nGid:\t1001 1001 1001 1003\nGroups:\t1002\n" +
      ["Inh", "Prm", "Eff", "Bnd", "Amb"]
        .map((name) => `Cap${name}:\t0000000000000000\n`)
        .join("") +
      "NoNewPrivs:\t1\nSeccomp:\t2\n",
    open: async (file) => {
      let isClosed = false;
      return {
        stat: async () => {
          if (isClosed)
            throw Object.assign(new Error("closed"), { code: "EBADF" });
          return stat(file);
        },
        read: async (bytes, offset, length, position) => ({
          bytesRead: files
            .get(file)
            .copy(bytes, offset, position, position + length),
        }),
        close: async () => {
          isClosed = true;
          closed++;
        },
      };
    },
  };
  const manifest = {
    inputs: [...files].map(([file, bytes]) => ({
      path: file,
      sha256: digest(bytes),
    })),
    tools: [
      { name: "compiler", path: "/fixture/image", sha256: digest(image) },
    ],
    release: { components: [{ id: "image" }] },
  };
  const effects = createLinuxReleaseReaders(
    {
      job: { candidateSha },
      manifest,
      runnerTemp: "/private",
      compilerVersion: "13.3.0",
      bindings: {
        schemaVersion: 1,
        candidateSha,
        providers: { codex: {}, claude: {} },
        components: [
          {
            id: "image",
            path: "/fixture/image",
            bindings: Object.fromEntries(
              ["publication", "source", "build", "license"].map((key) => [
                key,
                "/fixture/publication",
              ]),
            ),
          },
        ],
      },
    },
    {
      fs,
      protect: () => {},
      inspectProcess: async () => ({
        session: 42,
        identity: { bootId: hash, startTicks: "1" },
      }),
    },
  );
  const held = await effects.openHeld("image");
  assert.equal((await effects.inspectHeld(held)).identity, "1:2");
  assert.deepEqual(await effects.readHeld(held), image);
  assert.equal(
    (await effects.buildBindings(held)).bindings.publication,
    digest(provenance),
  );
  assert.deepEqual((await effects.loaderClosure(held, image)).components, []);
  const authority = await effects.observeAuthority();
  assert.deepEqual(authority.authority.groups, [{ gid: 1002 }]);
  assert.deepEqual(authority.authority.uids, {
    real: 1001,
    effective: 1001,
    saved: 0,
    filesystem: 1001,
  });
  assert.equal(authority.authority.gids.filesystem, 1003);
  assert.equal(authority.authority.capabilitySets.Prm, "0000000000000000");
  assert.equal(authority.authority.seccomp, 2);
  substitute = true;
  await assert.rejects(effects.inspectHeld(held));
  substitute = false;
  await effects.closeHeld(held);
  assert.equal((await effects.verifyClosed()).closed, true);
  assert.equal(closed, 3);
});

test("Linux package observations bind both actual inventories and their external ELF dependency closure", async () => {
  const files = new Map([
    ["/fixture/library", elf()],
    ["/fixture/publication", Buffer.from("reviewed provenance")],
  ]);
  const components = [{ id: "library", path: "/fixture/library" }],
    providers = {};
  for (const name of ["codex", "claude"]) {
    const input = nativePackageInput(name + "-linux"),
      image = elf(true, name === "claude");
    const directory = "/fixture/" + name,
      reviewFile = "/fixture/" + name + "-review.json";
    files.set(path.join(directory, input.entrypoint), image);
    components.push({ id: name, path: path.join(directory, input.entrypoint) });
    const reference = {
      url: "https://example.org/review",
      revision: null,
      sha256: hash,
    };
    files.set(
      reviewFile,
      Buffer.from(
        JSON.stringify({
          schemaVersion: 1,
          candidateSha,
          packageId: input.id,
          archiveBytes: input.bytes ?? 10,
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
            ].map((kind) => [
              kind,
              kind === "source"
                ? name === "claude"
                  ? null
                  : {
                      ...reference,
                      url: CODEX_RELEASE_REFERENCE.sourceUrl,
                      revision: CODEX_RELEASE_REFERENCE.revision,
                    }
                : reference,
            ]),
          ),
          files: [
            {
              path: input.entrypoint,
              bytes: image.length,
              sha256: digest(image),
              executable: true,
            },
          ],
        }),
      ),
    );
    providers[name] = { directory, reviewFile };
  }
  const cache = Buffer.alloc(160),
    key = "libfixture.so",
    target = "/fixture/library";
  cache.write("glibc-ld.so.cache1.1");
  cache.writeUInt32LE(1, 20);
  cache.writeUInt32LE(0x303, 48);
  cache.writeUInt32LE(72, 52);
  cache.writeUInt32LE(72 + key.length + 1, 56);
  cache.write(key, 72);
  cache.write(target, 72 + key.length + 1);
  const manifest = {
    inputs: [...files].map(([file, bytes]) => ({
      path: file,
      sha256: digest(bytes),
    })),
    release: { components: components.map(({ id }) => ({ id })) },
  };
  files.set("/etc/ld.so.cache", cache);
  const directories = new Map();
  const metadata = (file) => {
    const directory = !files.has(file);
    if (directory && !directories.has(file))
      directories.set(file, directories.size + 100);
    return {
      isFile: () => !directory,
      isDirectory: () => directory,
      dev: 1n,
      ino: BigInt(
        directory ? directories.get(file) : [...files.keys()].indexOf(file) + 2,
      ),
      nlink: directory ? 2n : 1n,
      size: BigInt(files.get(file)?.length ?? 4096),
      mode: directory ? 0o40500n : 0o100500n,
      uid: 0n,
      gid: 0n,
      mtimeNs: 1n,
      ctimeNs: 1n,
    };
  };
  let hardware = false,
    preload = false;
  const fs = {
    realpath: async (file) =>
      file === "/fixture/libfixture.so" ? "/fixture/library" : file,
    lstat: async (file) => {
      if (
        (file.endsWith("/glibc-hwcaps") && !hardware) ||
        (file === "/etc/ld.so.preload" && !preload)
      )
        throw Object.assign(new Error("absent"), { code: "ENOENT" });
      return metadata(file);
    },
    readdir: async (directory) => {
      const names = new Map();
      for (const file of files.keys())
        if (file.startsWith(directory + "/")) {
          const parts = file.slice(directory.length + 1).split("/");
          names.set(parts[0], parts.length > 1);
        }
      return [...names].map(([name, isDirectory]) => ({
        name,
        isDirectory: () => isDirectory,
        isFile: () => !isDirectory,
        isSymbolicLink: () => false,
      }));
    },
    open: async (file) => {
      let closed = false;
      return {
        stat: async () => {
          if (closed)
            throw Object.assign(new Error("closed"), { code: "EBADF" });
          return metadata(file);
        },
        read: async (bytes, offset, length, position) => ({
          bytesRead: files
            .get(file)
            .copy(bytes, offset, position, position + length),
        }),
        close: async () => {
          closed = true;
        },
      };
    },
  };
  const effects = createLinuxReleaseReaders(
    {
      job: { candidateSha },
      manifest,
      runnerTemp: "/private",
      compilerVersion: "13.3.0",
      bindings: {
        schemaVersion: 1,
        candidateSha,
        providers,
        components: components.map((component) => ({
          ...component,
          bindings: Object.fromEntries(
            ["publication", "source", "build", "license"].map((kind) => [
              kind,
              "/fixture/publication",
            ]),
          ),
        })),
      },
    },
    { fs, protect: () => {}, ownerUid: () => 0 },
  );
  for (const { id } of components) {
    const held = await effects.openHeld(id);
    await effects.loaderClosure(held, await effects.readHeld(held));
  }
  const codex = await effects.inspectProvider("codex"),
    claude = await effects.inspectProvider("claude");
  assert.deepEqual(codex.members, ["codex", "library"]);
  assert.deepEqual(claude.members, ["claude", "library"]);
  assert.notEqual(codex.liveBindingSha256, claude.liveBindingSha256);
  const image = await effects.openHeld("claude");
  hardware = true;
  await assert.rejects(
    effects.loaderClosure(image, await effects.readHeld(image)),
  );
  hardware = false;
  files.set("/etc/ld.so.preload", Buffer.from("/fixture/unreviewed-image"));
  preload = true;
  await assert.rejects(
    effects.loaderClosure(image, await effects.readHeld(image)),
  );
  files.set("/fixture/codex/undeclared", Buffer.from("extra authority"));
  await assert.rejects(effects.inspectProvider("codex"));
  assert.equal((await effects.verifyClosed()).closed, true);
});
