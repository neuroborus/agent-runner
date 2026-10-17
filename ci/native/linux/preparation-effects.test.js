import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { constants } from "node:fs";
import * as filesystem from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { PassThrough } from "node:stream";
import {
  createNativeDiagnosticWriter,
  withNativeDiagnostics,
} from "../diagnostics.js";
import { observeLinuxPreparationProtectionFailure } from "./preparation-protection.js";
import {
  prepareLinuxBubblewrap,
  linuxPreparationVersion,
} from "./preparation.js";
import {
  observationDigest,
  nativePolicyTemplateDigest,
  verifyNativePolicy,
  NATIVE_EFFECT_CLASSES,
  nativePackageInput,
  CODEX_RELEASE_REFERENCE,
  initializeNativeJob,
  SOURCE_FINDING_IDS,
  preparedNativeCommands,
  recordExperimentPreparationEffect,
} from "../index.js";
import { createBuildEffects, createSystemEffects } from "../native-effects.mjs";
import { prerequisiteFixture } from "../prerequisite-fixture.js";
import {
  createLinuxBuildEffects,
  createLinuxSystemEffects,
  createLinuxReleaseReaders,
  hardenLinuxPreparationTrust,
  linuxElfLoadCommands,
  runLinuxOwnershipProofs,
  runLinuxFileProofs,
  runLinuxFileSession,
  spawnLinuxCommandController,
  verifyLinuxCommandControllers,
  freshVerifier,
  normalizeLinuxReceipt,
} from "./index.js";
import {
  digest,
  verifyLinuxRetirement,
  readLinuxObservedFile,
  readLinuxInterpreterSource,
  readLinuxRunningInterpreterIdentity,
} from "./inspect.js";
import {
  LINUX_FILE_BUILD_ARGUMENTS,
  buildLinuxFileHelper,
  normalizeLinuxFileBuildPins,
  verifyLinuxFileElf,
  linuxFileBuildInvocation,
} from "./file-build.js";
import { linuxReleaseComponentId } from "./release.js";
import {
  linuxReviewedManifestDigest,
  normalizeLinuxReviewedManifest,
} from "./reviewed-inputs.js";
import {
  runLinuxBuildCommand,
  createLinuxBuildCommandRunner,
  linuxExperimentQueryArguments,
  LINUX_EXPERIMENT_QUERIES,
} from "./proof.js";
import {
  linuxExperimentHeaders,
  linuxExperimentProgram,
  verifyLinuxExperimentBuild,
  recoverLinuxExperimentPreparation,
  prepareLinuxExperiment,
  rejoinLinuxExperimentInterpreter,
} from "./experiment-preparation.js";
import { acquireLinuxExperimentInterpreter } from "./confinement.js";
import { linuxControllerFailure, linuxDiagnosticError } from "./index.js";
import { runLinuxCommandController } from "./command-controller.js";

function linuxTrustFixture() {
  const targets = [
      "/usr/share",
      "/usr/share/keyrings",
      "/usr/share/keyrings/ubuntu-archive-keyring.gpg",
    ],
    contents = Buffer.from("synthetic archive trust bytes"),
    records = [],
    commands = [],
    events = [],
    nodes = new Map();
  for (const file of [
    "/",
    "/usr",
    "/usr/bin",
    ...targets,
    ...["sudo", "timeout", "chmod", "apt-get", "apt-cache", "dpkg-query"].map(
      (name) => "/usr/bin/" + name,
    ),
  ]) {
    const directory = !file.includes("/usr/bin/") && file !== targets[2];
    nodes.set(file, {
      directory,
      symlink: false,
      dev: 1,
      ino: nodes.size + 1,
      mode:
        (directory ? 0o40000 : 0o100000) |
        (targets.includes(file) ? 0o777 : 0o755),
      uid: 0,
      gid: 0,
      nlink: directory ? 2 : 1,
      size: file === targets[2] ? contents.length : 4096,
      mtimeMs: 1,
      ctimeMs: 1,
      birthtimeMs: 1,
    });
  }
  const stat = (node) => ({
    ...node,
    ...Object.fromEntries(
      ["dev", "ino", "mode", "uid", "gid", "nlink", "size"].map((key) => [
        key,
        BigInt(node[key]),
      ]),
    ),
    mtimeNs: BigInt(node.mtimeMs),
    ctimeNs: BigInt(node.ctimeMs),
    birthtimeNs: BigInt(node.birthtimeMs),
    isFile: () => !node.directory,
    isDirectory: () => node.directory,
    isSymbolicLink: () => node.symlink,
  });
  const binding = {
    platform: "linux",
    workflow: "native-poc",
    image: "ubuntu-24.04",
    architecture: "x64",
    candidateSha: "a".repeat(40),
    checkoutSha: "a".repeat(40),
    repository: "example/native",
    runId: "1",
    runAttempt: 1,
  };
  const options = {
    platform: "linux",
    architecture: "x64",
    now: () => 0,
    env: {
      CI: "true",
      GITHUB_ACTIONS: "true",
      ImageOS: "ubuntu24",
      RUNNER_OS: "Linux",
      RUNNER_ENVIRONMENT: "github-hosted",
      GITHUB_REPOSITORY: binding.repository,
      GITHUB_RUN_ID: "1",
      GITHUB_RUN_ATTEMPT: "1",
    },
    fs: {
      lstat: async (file) => stat(nodes.get(file)),
      realpath: async (file) => file,
      readFile: async () => 'ID=ubuntu\nVERSION_ID="24.04"\n',
      open: async (file, flags) => {
        assert.equal(file, targets[2]);
        assert.equal(
          flags,
          constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
        );
        const node = nodes.get(file);
        return {
          stat: async () => stat(node),
          read: async (buffer, offset, length, position) => ({
            bytesRead: contents.copy(
              buffer,
              offset,
              position,
              position + length,
            ),
          }),
          close: async () => events.push("close"),
        };
      },
    },
    protect(file) {
      events.push("protect:" + file);
      for (let current = file; ; current = path.posix.dirname(current)) {
        assert.ok(
          !(nodes.get(current).mode & 0o022),
          "Strict protection refusal: " + current,
        );
        if (current === "/") break;
      }
    },
    run: async (file, args, settings) => {
      assert.equal(file, "/usr/bin/sudo");
      const target = args.at(-1);
      assert.deepEqual(args, [
        "--non-interactive",
        "--",
        "/usr/bin/timeout",
        "--signal=TERM",
        "--kill-after=2s",
        "5s",
        "/usr/bin/chmod",
        "go-w",
        "--",
        target,
      ]);
      assert.deepEqual(settings.env, { PATH: "/usr/bin:/bin", LANG: "C" });
      assert.equal(settings.timeout, 8000);
      assert.equal(settings.killSignal, "SIGKILL");
      assert.deepEqual(records.at(-1), { status: "POSSIBLE", target });
      commands.push(target);
      const node = nodes.get(target);
      node.mode &= ~0o022;
      node.ctimeMs++;
    },
  };
  const persist = async (record) => {
    records.push({ ...record });
    events.push("persist:" + record.status);
  };
  return {
    targets,
    contents,
    records,
    commands,
    events,
    nodes,
    binding,
    options,
    persist,
    run: () => hardenLinuxPreparationTrust(binding, persist, options),
  };
}

test("disposable Linux trust hardening validates tools before ancestor-first fixed mutations and retains bytes and ownership", async () => {
  const f = linuxTrustFixture(),
    original = structuredClone([...f.nodes]),
    bytes = Buffer.from(f.contents);
  assert.deepEqual(await f.run(), { status: "PASS", target: null });
  assert.deepEqual(f.commands, f.targets);
  assert.ok(
    f.events.indexOf("protect:/usr/bin/dpkg-query") <
      f.events.indexOf("persist:POSSIBLE"),
  );
  for (const [file, before] of original) {
    const expected = { ...before };
    if (f.targets.includes(file)) {
      expected.mode &= ~0o022;
      expected.ctimeMs++;
    }
    assert.deepEqual(f.nodes.get(file), expected);
  }
  assert.deepEqual(f.contents, bytes);
  assert.equal(f.records.at(-1).status, "PASS");
});

test("Linux trust hardening refuses undeclared hosts, unsafe paths, owners, types and unbounded keyrings before mutation", async () => {
  for (const fault of [
    "host",
    "image",
    "workflow",
    "candidate",
    "release",
    "tool-owner",
    "tool-symlink",
    "tool-type",
    "tool-canonical",
    "tool-protection",
    "parent-owner",
    "parent-type",
    "parent-symlink",
    "keyring-owner",
    "keyring-type",
    "keyring-symlink",
    "keyring-links",
    "keyring-size",
    "held-identity",
  ]) {
    const f = linuxTrustFixture(),
      keyring = f.nodes.get(f.targets[2]),
      tool = f.nodes.get("/usr/bin/chmod"),
      parent = f.nodes.get(f.targets[0]);
    if (fault === "host") f.options.env.RUNNER_ENVIRONMENT = "self-hosted";
    if (fault === "image") f.binding.image = "ubuntu-22.04";
    if (fault === "workflow") f.binding.workflow = "other-workflow";
    if (fault === "candidate") f.binding.checkoutSha = "b".repeat(40);
    if (fault === "release") f.options.fs.readFile = async () => "ID=other\n";
    if (fault === "tool-owner") tool.uid = 1;
    if (fault === "tool-symlink") tool.symlink = true;
    if (fault === "tool-type") tool.directory = true;
    if (fault === "tool-canonical")
      f.options.fs.realpath = async () => "/substituted";
    if (fault === "tool-protection")
      f.options.protect = () => {
        throw new Error("protection");
      };
    if (fault === "parent-owner") parent.gid = 1;
    if (fault === "parent-type") parent.directory = false;
    if (fault === "parent-symlink") parent.symlink = true;
    if (fault === "keyring-owner") keyring.uid = 1;
    if (fault === "keyring-type") keyring.directory = true;
    if (fault === "keyring-symlink") keyring.symlink = true;
    if (fault === "keyring-links") keyring.nlink = 2;
    if (fault === "keyring-size") keyring.size = 1048577;
    if (fault === "held-identity") {
      const open = f.options.fs.open;
      f.options.fs.open = async (...args) => {
        const held = await open(...args),
          stat = held.stat;
        held.stat = async () => ({ ...(await stat()), ino: 999n });
        return held;
      };
    }
    await assert.rejects(f.run(), undefined, fault);
    assert.deepEqual(f.commands, [], fault);
  }
});

test("Linux trust hardening refuses substitutions, changed bytes, failed commands and strict protection without restoring modes", async () => {
  for (const fault of [
    "next-identity",
    "next-bytes",
    "secured-parent",
    "tool-substitution",
    "post-identity",
    "post-owner",
    "post-mode",
    "post-mtime",
    "post-bytes",
    "command",
    "strict",
  ]) {
    const f = linuxTrustFixture(),
      run = f.options.run,
      original = new Error(fault);
    f.options.run = async (...args) => {
      await run(...args);
      if (fault === "post-bytes" && f.commands.length === 3) f.contents[0] ^= 1;
      if (fault === "secured-parent" && f.commands.length === 2)
        f.nodes.get(f.targets[0]).ino++;
      if (f.commands.length !== 1) return;
      const next = f.nodes.get(f.targets[1]),
        changed = f.nodes.get(f.targets[0]);
      if (fault === "next-identity") next.ino++;
      if (fault === "next-bytes") f.contents[0] ^= 1;
      if (fault === "tool-substitution") f.nodes.get("/usr/bin/chmod").ino++;
      if (fault === "post-identity") changed.ino++;
      if (fault === "post-owner") changed.gid++;
      if (fault === "post-mode") changed.mode &= ~0o100;
      if (fault === "post-mtime") changed.mtimeMs++;
      if (fault === "command") throw original;
    };
    if (fault === "strict") {
      const protect = f.options.protect;
      f.options.protect = (file) => {
        if (f.commands.length && file === f.targets[0]) throw original;
        protect(file);
      };
    }
    await assert.rejects(
      f.run(),
      fault === "command" || fault === "strict"
        ? (error) => error === original
        : undefined,
      fault,
    );
    assert.equal(
      f.commands.length,
      fault === "post-bytes"
        ? 3
        : ["next-bytes", "secured-parent"].includes(fault)
          ? 2
          : 1,
      fault,
    );
    assert.equal(f.nodes.get(f.targets[0]).mode & 0o022, 0, fault);
    assert.equal(f.records.at(-1).status, "FAIL", fault);
  }
});

test("Linux trust intents, completion persistence and cancellation fence later mutations", async () => {
  for (const fault of [
    "intent",
    "completion",
    "completion-substitution",
    "failure-receipt",
    "cancel",
    "deadline",
  ]) {
    const f = linuxTrustFixture(),
      abort = new AbortController(),
      original = new Error(fault);
    f.options.signal = abort.signal;
    let time = 0;
    f.options.now = () => time;
    if (fault === "failure-receipt")
      f.options.run = async () => {
        throw original;
      };
    const persist = async (record) => {
      if (fault === "completion" && record.status === "PASS") throw original;
      if (fault === "completion-substitution" && record.status === "PASS")
        f.nodes.get(f.targets[2]).ino++;
      if (fault === "failure-receipt" && record.status === "FAIL")
        throw new Error("receipt failure");
      if (record.target === f.targets[1] && record.status === "POSSIBLE") {
        if (fault === "intent") throw original;
        if (fault === "cancel") abort.abort();
        if (fault === "deadline") time = 30000;
      }
      await f.persist(record);
    };
    await assert.rejects(
      hardenLinuxPreparationTrust(f.binding, persist, f.options),
      fault === "failure-receipt" ? (error) => error === original : undefined,
    );
    assert.deepEqual(
      f.commands,
      fault.startsWith("completion")
        ? f.targets
        : fault === "failure-receipt"
          ? []
          : [f.targets[0]],
    );
    assert.equal(
      f.records.at(-1).status,
      fault === "failure-receipt" ? "POSSIBLE" : "FAIL",
    );
    if (fault !== "failure-receipt")
      assert.equal(f.nodes.get(f.targets[0]).mode & 0o022, 0);
  }
});

function protectionInspection(
  mountinfo = "1 0 0:1 / / rw - rootfs rootfs rw\n",
) {
  const calls = [],
    target = "/usr/lib/package-tools/apt-get";
  const fs = {
    openSync(file, flags) {
      assert.equal(file, "/proc/self/mountinfo");
      assert.equal(flags, constants.O_RDONLY | constants.O_NOFOLLOW);
      calls.push("open");
      return { bytes: Buffer.from(mountinfo), offset: 0 };
    },
    readSync(handle, buffer, offset, length, position) {
      assert.equal(position, null);
      const count = handle.bytes.copy(
        buffer,
        offset,
        handle.offset,
        handle.offset + length,
      );
      handle.offset += count;
      calls.push("read");
      return count;
    },
    closeSync() {
      calls.push("close");
    },
    lstatSync(file) {
      calls.push(file);
      return {
        dev: 1,
        ino: 2,
        mode: 0o755,
        uid: 0,
        gid: 0,
        mtimeMs: 1,
        ctimeMs: 1,
        isSymbolicLink: () => false,
      };
    },
    accessSync(file, mode) {
      assert.equal(mode, constants.W_OK);
      if (file !== "/usr/lib")
        throw Object.assign(new Error("denied"), { code: "EACCES" });
    },
    realpathSync: () => target,
  };
  return { fs, calls, target };
}

test("Linux prerequisite protection diagnostics identify the input, canonical target and observed writable ancestor", () => {
  const { fs, calls, target } = protectionInspection(),
    output = [];
  const report = withNativeDiagnostics(
    () =>
      observeLinuxPreparationProtectionFailure("/usr/bin/apt-get", target, {
        fs,
      }),
    createNativeDiagnosticWriter((bytes) => output.push(bytes)),
  );
  assert.equal(report.file, "/usr/bin/apt-get");
  assert.equal(report.target, target);
  assert.equal(report.observation, "after-protection-failure");
  const ancestor = report.ancestors.find(({ path }) => path === "/usr/lib");
  assert.deepEqual(ancestor.observedPredicates, ["runner-writable"]);
  assert.deepEqual(ancestor.mount, { id: 1, mountPoint: "/", readOnly: false });
  assert.equal(ancestor.runnerWrite.value, true);
  assert.equal(ancestor.before.value.symlink, false);
  assert.equal(ancestor.changed, false);
  assert.equal(report.targetChanged, false);
  assert.equal(report.mountsChanged, false);
  assert.equal(calls.filter((call) => call === "close").length, 2);
  const text = Buffer.concat(output).toString();
  assert.match(text, /linux-preparation-protection/u);
  assert.ok(text.includes(JSON.stringify(report)));
  assert.doesNotMatch(text, /rootfs|mountinfo|GH_TOKEN/u);
});

test("Linux prerequisite protection diagnostics distinguish mount, symlink and read-only-anchor observations", () => {
  const { fs, target } = protectionInspection(
    [
      "1 0 0:1 / / rw - rootfs rootfs rw",
      "2 1 0:2 / /usr ro - tmpfs tmpfs ro",
      "3 2 0:3 / /usr/lib ro - tmpfs tmpfs ro",
      "4 3 0:4 / /usr/lib/package-tools ro - tmpfs tmpfs ro",
      "5 3 0:5 / /usr/lib/package-tools ro - tmpfs tmpfs ro",
    ].join("\n"),
  );
  const lstat = fs.lstatSync;
  fs.lstatSync = (file) => ({
    ...lstat(file),
    isSymbolicLink: () => file === "/usr/lib",
  });
  const report = observeLinuxPreparationProtectionFailure(
    "/usr/bin/apt-get",
    target,
    { fs },
  );
  assert.equal(report.ancestors[0].mount.id, 5); // Highest ID at the longest matching mount.
  assert.equal(report.ancestors[1].readOnlyAnchor, "/usr/lib/package-tools");
  assert.equal(report.ancestors.at(-1).path, "/usr/lib/package-tools");
  const crossing = observeLinuxPreparationProtectionFailure(
    "/usr/bin/apt-get",
    target,
    {
      fs: {
        ...fs,
        openSync: () => ({
          bytes: Buffer.from(
            "1 0 0:1 / / rw - rootfs rootfs rw\n2 1 0:2 / /usr/lib/package-tools/apt-get ro - tmpfs tmpfs ro\n",
          ),
          offset: 0,
        }),
      },
    },
  );
  // A mount anchored at the target stops there; no parent observation is invented.
  assert.equal(crossing.ancestors.length, 1);
  const missing = protectionInspection(
    "1 0 0:1 / /elsewhere rw - tmpfs tmpfs rw\n",
  );
  missing.fs.lstatSync = fs.lstatSync;
  const absent = observeLinuxPreparationProtectionFailure(
    "/usr/bin/apt-get",
    target,
    missing,
  );
  assert.deepEqual(absent.ancestors[0].observedPredicates, [
    "missing-effective-mount",
  ]);
  assert.deepEqual(
    absent.ancestors.find(({ path }) => path === "/usr/lib").observedPredicates,
    ["missing-effective-mount", "symlink"],
  );
});

test("Linux prerequisite protection diagnostics retain inspection uncertainty and changed observations", () => {
  const { fs, target } = protectionInspection();
  let stats = 0,
    opens = 0;
  const lstat = fs.lstatSync,
    open = fs.openSync;
  fs.lstatSync = (file) => {
    if (file === "/usr")
      throw Object.assign(new Error("unavailable"), { code: "ENOENT" });
    return { ...lstat(file), ino: ++stats };
  };
  fs.accessSync = () => {
    throw Object.assign(new Error("unknown"), { code: "EIO" });
  };
  fs.realpathSync = () => "/usr/lib/replaced/apt-get";
  fs.openSync = (...args) => {
    if (++opens === 2)
      throw Object.assign(new Error("changed view"), { code: "EACCES" });
    return open(...args);
  };
  const report = observeLinuxPreparationProtectionFailure(
    "/usr/bin/apt-get",
    target,
    { fs },
  );
  assert.equal(report.ancestors[0].changed, true);
  assert.equal(report.ancestors[0].runnerWrite.unavailable, "EIO");
  assert.equal(
    report.ancestors.find(({ path }) => path === "/usr").before.unavailable,
    "ENOENT",
  );
  assert.equal(report.targetChanged, true);
  assert.equal(report.mountsChanged, null);
  assert.equal(report.mountsAfterUnavailable, "EACCES");
  assert.ok(
    report.ancestors.every(
      ({ observedPredicates }) =>
        !observedPredicates.includes("runner-writable"),
    ),
  );
});

test("Linux prerequisite protection diagnostics bound reads, ancestry and output without publishing a mount table", () => {
  const { fs, calls } = protectionInspection("x".repeat(262145));
  const read = fs.readSync;
  fs.readSync = (handle, buffer, offset, _length, position) =>
    read(handle, buffer, offset, 1, position);
  const target =
    "/" + "a".repeat(600) + "/" + Array(40).fill("ancestor").join("/");
  fs.realpathSync = () => target;
  const report = observeLinuxPreparationProtectionFailure(
    "/usr/bin/apt-get",
    target,
    { fs },
  );
  assert.equal(report.mountsUnavailable, "MOUNT_READ_LIMIT");
  assert.equal(report.traversalUnavailable, "ANCESTOR_LIMIT");
  assert.equal(report.outputTruncated, true);
  assert.ok(report.ancestors.length <= 32);
  assert.ok(Buffer.byteLength(JSON.stringify(report)) <= 32768);
  assert.equal(calls.filter((call) => call === "read").length, 256);
  assert.equal(calls.filter((call) => call === "close").length, 2);
  assert.doesNotMatch(JSON.stringify(report), /xxxx/u);
  const malformed = protectionInspection("invalid\n");
  assert.equal(
    observeLinuxPreparationProtectionFailure(
      "/usr/bin/apt-get",
      "/usr/bin/apt-get",
      malformed,
    ).mountsUnavailable,
    "MOUNT_FORMAT",
  );
});

test("Linux prerequisite protection refusal preserves the original error and failed receipt despite diagnostic failures", async () => {
  for (const failure of ["none", "inspection", "observer", "sink"]) {
    const records = [],
      errors = [],
      effects = [],
      observations = [];
    const original = Object.assign(new Error("original protection refusal"), {
      code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
    });
    const { fs, target } = protectionInspection();
    if (failure === "inspection")
      fs.openSync = () => {
        throw new Error("inspection failure");
      };
    const failed = await withNativeDiagnostics(
      () =>
        prepareLinuxBubblewrap(
          "a".repeat(40),
          "/fixture/report",
          async (record) => records.push(record),
          {
            platform: "linux",
            architecture: "x64",
            env: { CI: "true", GITHUB_ACTIONS: "true", ImageOS: "ubuntu24" },
            now: () => 0,
            fs: {
              readFile: async () => 'ID=ubuntu\nVERSION_ID="24.04"\n',
              realpath: async (file) => {
                effects.push(file);
                return file === "/usr/bin/apt-get" ? target : file;
              },
              mkdir: async () => effects.push("mkdir"),
              writeFile: async () => effects.push("write"),
            },
            protect(file) {
              if (file === target) throw original;
            },
            run: async () => {
              effects.push("command");
            },
            observeProtectionFailure(file, canonical) {
              observations.push([file, canonical]);
              if (failure === "observer") throw new Error("observer failure");
              observeLinuxPreparationProtectionFailure(file, canonical, { fs });
            },
          },
        ),
      (_owner, value) => {
        if (value.exception) errors.push(value.exception);
        if (failure === "sink") throw new Error("sink failure");
      },
    );
    assert.deepEqual(errors, [original]);
    assert.deepEqual(observations, [["/usr/bin/apt-get", target]]);
    assert.equal(failed.status, "FAIL");
    assert.equal(failed.phase, "metadata");
    assert.equal(failed.package, null);
    assert.equal(failed.version, null);
    assert.deepEqual(
      records.map(({ status }) => status),
      ["RUNNING", "FAIL"],
    );
    assert.throws(() => linuxPreparationVersion(failed, "a".repeat(40)));
    assert.deepEqual(effects, [
      "/usr/share/keyrings/ubuntu-archive-keyring.gpg",
      "/usr/bin/timeout",
      "/usr/bin/sudo",
      "/usr/bin/apt-get",
    ]);
  }
});

const candidateSha = "a".repeat(40),
  hash = "b".repeat(64);
const retired = {
  status: "RETIRED",
  independent: true,
  emergencyCleanup: false,
};
const output = "/fixture/report/platform-build",
  directory = path.dirname(output);

// Raw held files, native receipt transcripts and procfs only. The fixed entry,
// bootstrap reader, command owner and independent verifier do their own work.
async function preparedFixture(
  t,
  { deadlineMs = 30000, root = "/private/report" } = {},
) {
  const raw = await prerequisiteFixture();
  t.after(() => raw.teardown());
  const buildOutput = root + "/platform-build";
  raw.add(root);
  raw.add(buildOutput);
  const numberStat = (stat, options) =>
    options?.bigint
      ? stat
      : {
          ...stat,
          ...Object.fromEntries(
            ["dev", "ino", "size", "uid", "gid", "mode", "nlink"].map((key) => [
              key,
              Number(stat[key]),
            ]),
          ),
          mtimeMs: Number(stat.mtimeNs),
          ctimeMs: Number(stat.ctimeNs),
          isSymbolicLink: () => false,
        };
  const fs = {
    ...raw.edges.fs,
    async lstat(file, options) {
      if (/^\/proc\/[0-9]+$/u.test(file)) {
        if (raw.faults.absence) throw raw.faults.absence;
        if (!raw.processes.has(Number(path.basename(file))))
          throw Object.assign(new Error("Missing process"), { code: "ENOENT" });
        return { isDirectory: () => true };
      }
      const stat = await raw.edges.fs.lstat(file);
      return { ...numberStat(stat, options), isSymbolicLink: () => false };
    },
    async open(file, flags, mode) {
      const actual =
        file === "/proc/self/stat" && raw.faults.observerPid
          ? `/proc/${raw.faults.observerPid}/stat`
          : file;
      const handle = await raw.edges.fs.open(actual, flags, mode);
      return {
        ...handle,
        stat: async (options) => numberStat(await handle.stat(), options),
        async read(...args) {
          const result = await handle.read(...args);
          if (raw.faults.changeReceipt === file && result.bytesRead)
            raw.nodes.get(file).mtimeNs++;
          return result;
        },
      };
    },
    async readFile(file, encoding) {
      const handle = await fs.open(file, 0);
      try {
        const bytes = Buffer.alloc(65537),
          { bytesRead } = await handle.read(bytes, 0, bytes.length, 0);
        assert.ok(bytesRead < bytes.length);
        const result = bytes.subarray(0, bytesRead);
        return encoding ? result.toString(encoding) : result;
      } finally {
        await handle.close();
      }
    },
    async access(file) {
      assert.ok(raw.nodes.has(file));
      throw Object.assign(new Error("Read-only stock object"), {
        code: "EROFS",
      });
    },
    async writeFile(file, bytes, options) {
      assert.equal(options.flag, "wx");
      assert.equal(options.mode, 0o400);
      assert.ok(!raw.nodes.has(file));
      raw.add(file, Buffer.from(bytes), options.mode);
      raw.events.push("write:" + file);
    },
    async readdir(file, options) {
      const names = await raw.edges.fs.readdir(file);
      return options?.withFileTypes
        ? names.map((name) => ({
            name,
            isSymbolicLink: () => false,
          }))
        : names;
    },
  };
  const sourceFile = fileURLToPath(new URL("./file-helper.c", import.meta.url)),
    source = await filesystem.readFile(sourceFile),
    compiler = Buffer.from("approved compiler"),
    sdk = Buffer.from("approved linker"),
    bwrap = Buffer.from("approved bootstrap launcher"),
    image = elf();
  image.writeUInt16LE(2, 56);
  image.writeBigUInt64LE(0x400080n, 24);
  image.writeUInt32LE(5, 68);
  image.writeBigUInt64LE(0x400000n, 80);
  image.writeBigUInt64LE(512n, 104);
  image.writeUInt32LE(0x6474e551, 120);
  image.writeUInt32LE(6, 124);
  const tools = [
    {
      name: "compiler",
      path: "/usr/bin/x86_64-linux-gnu-gcc-13",
      sha256: digest(compiler),
      version: "13.3.0",
    },
    {
      name: "sdk",
      path: "/usr/bin/x86_64-linux-gnu-ld.bfd",
      sha256: digest(sdk),
      version: "GNU ld 2.42",
    },
  ];
  const pins = {
    schemaVersion: 1,
    candidateSha,
    sourceSha256: digest(source),
    compilerVersion: "13.3.0",
    inputs: tools.map((tool) => ({
      source: tool.path,
      target: tool.path,
      sha256: tool.sha256,
    })),
  };
  const abi = [{ target: "/usr/lib/fixture.so", sha256: hash }];
  const review = {
    schemaVersion: 1,
    candidateSha,
    build: pins,
    abi,
    release: {
      schemaVersion: 1,
      candidateSha,
      buildPinsSha256: observationDigest(pins),
      unresolvedAssumptions: SOURCE_FINDING_IDS,
      components: [
        ["node", "24.21.0", hash],
        ["bubblewrap", "bubblewrap 0.8.0", digest(bwrap)],
        ["git", "2.0.0", hash],
        ["compiler", "13.3.0", digest(compiler)],
        ["file-helper", "1", digest(image)],
        ...pins.inputs.map((entry) => [
          linuxReleaseComponentId("build-input", entry.target),
          "unversioned",
          entry.sha256,
        ]),
        ...abi.map((entry) => [
          linuxReleaseComponentId("abi", entry.target),
          "unversioned",
          entry.sha256,
        ]),
      ].map(([name, version, sha256]) => ({
        name,
        version,
        sha256,
        ...Object.fromEntries(
          ["publication", "source", "build", "license"].map((kind) => [
            kind,
            { id: "approved-" + kind, sha256: hash },
          ]),
        ),
      })),
    },
  };
  for (const [name, bytes] of [
    [sourceFile, source],
    [tools[0].path, compiler],
    [tools[1].path, sdk],
    ["/usr/bin/bwrap", bwrap],
    [buildOutput + "/build/file-helper.c", source],
    [buildOutput + "/build/inputs/0", compiler],
    [buildOutput + "/build/inputs/1", sdk],
    [buildOutput + "/build/output/file-helper", image],
  ])
    raw.add(name, bytes, 0o500);
  const normalized = normalizeLinuxReviewedManifest(review, candidateSha);
  for (const [name, value] of [
    ["linux-review", normalized],
    ["linux-file-build", normalized.build],
    ["linux-release", normalized.release],
  ])
    raw.add(
      `/private/review/${name}.json`,
      JSON.stringify(value) + "\n",
      0o400,
    );
  raw.add(
    root + "/linux-preparation.json",
    JSON.stringify({
      schemaVersion: 1,
      candidateSha,
      status: "PASS",
      phase: "verification",
      package: {
        filename: "pool/universe/b/bubblewrap/bubblewrap_0.8.0-1_amd64.deb",
        sha256: hash,
        size: 1,
        version: "0.8.0-1",
      },
      version: {
        name: "bubblewrap",
        version: "bubblewrap 0.8.0",
        sha256: digest(bwrap),
      },
    }),
    0o400,
  );
  const manifest = {
    ...raw.input.manifest,
    schemaVersion: 2,
    tools,
    linuxBuild: pins,
    helpers: [
      {
        name: "file-helper",
        sourceSha256: digest(source),
        sha256: digest(image),
      },
    ],
    prerequisites: { assets: [{}, {}], packages: [{}, {}] },
  };
  raw.input.manifest = manifest;
  raw.input.approvals.manifestSha256 = observationDigest(manifest);
  const env = {
    CI: "true",
    GITHUB_ACTIONS: "true",
    ImageOS: "ubuntu24",
    RUNNER_TEMP: "/private",
    NATIVE_REVIEWED_INPUT_DIRECTORY: "/private/review",
    NATIVE_LINUX_REVIEW_SHA256: linuxReviewedManifestDigest(
      review,
      candidateSha,
    ),
  };
  let sequence = 0;
  const receipt = (file, policyDigest, executableDigest) => {
    const init = 1000 + sequence++ * 3,
      identity = {
        bootId: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        startTicks: "1000",
      },
      nonce = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    const record = {
      schemaVersion: 1,
      candidateSha,
      caseId: "argv",
      nonce,
      policyDigest,
      executableDigest,
      isolatedNamespace: true,
      hostSession: false,
      parentNamespaceId: "pid:[1]",
      init: {
        pid: init,
        identity,
        namespaceId: `pid:[${init}]`,
        nspid: [init, 1],
      },
      launcher: { pid: init + 1, identity },
      controller: { pid: init + 2, identity },
      admission: {
        processIdentity: identity,
        namespaceId: `pid:[${init}]`,
        launchCutoff: identity,
        ancestryBaseline: [
          { pid: 1, bootId: identity.bootId, startTicks: "1" },
        ],
        controlGroup: hash,
      },
    };
    const bytes = Buffer.from(JSON.stringify(record));
    raw.add(file, bytes, 0o400);
    raw.add(
      path.join(
        path.dirname(file),
        path.basename(file, ".json") + "-possible.json",
      ),
      JSON.stringify({ candidateSha, nonce, policyDigest }),
      0o400,
    );
    return { file, sha256: digest(bytes) };
  };
  const options = {
    ...raw.edges,
    fs,
    env,
    ownerUid: () => 0,
    async executeFile(file, args, settings) {
      assert.equal(file, process.execPath);
      assert.equal(args[1], "--verify");
      assert.equal(settings.timeout, 5000);
      raw.events.push("verify:" + args[2]);
      return {
        stdout: JSON.stringify(
          await verifyLinuxRetirement(args[2], args[3], {
            fs,
            ownerUid: () => 0,
            pid: raw.faults.observerPid ?? 42,
          }),
        ),
      };
    },
    start(file, args) {
      raw.events.push("compiler-controller");
      assert.equal(args[0], "--build");
      const input = JSON.parse(raw.nodes.get(args[1]).content),
        pin = receipt(
          input.directory + "/command-0.json",
          observationDigest(input.command),
          input.command.toolSha256,
        ),
        record = JSON.parse(raw.nodes.get(pin.file).content),
        worker = new EventEmitter();
      worker.pid = record.controller.pid;
      queueMicrotask(() => {
        worker.emit("message", {
          status: "PASS",
          receipts: [pin],
          observation: {
            exitCode: 0,
            signal: null,
            timedOut: false,
            stdout:
              tools.find((tool) => tool.path === input.command.file).version +
              "\n",
            stderr: "",
          },
        });
        worker.emit("close", 0);
      });
      return worker;
    },
  };
  const input = {
    job: raw.input.job,
    manifest,
    directory: root,
    output: buildOutput,
    prerequisiteCustody: raw.input,
  };
  const effects = await createBuildEffects(input, options),
    commands = [];
  for (const tool of tools) {
    const request = {
        candidateSha,
        platform: "linux",
        toolSha256: tool.sha256,
        file: tool.path,
        args: ["--version"],
        cwd: buildOutput,
        env: { CI: "true", GITHUB_ACTIONS: "true", LANG: "C" },
        deadlineMs,
      },
      result = await effects.run(request);
    commands.push({
      requestSha256: observationDigest(request),
      status: "RETIRED",
      receiptSha256: observationDigest(result),
    });
  }
  const result = {
    build: {
      schemaVersion: 1,
      candidateSha,
      sourceSha256: pins.sourceSha256,
      compiler: {
        file: tools[0].path,
        version: pins.compilerVersion,
        sha256: tools[0].sha256,
      },
      arguments: LINUX_FILE_BUILD_ARGUMENTS,
      inputs: pins.inputs,
      sha256: digest(image),
      abi: verifyLinuxFileElf(image),
      executable: buildOutput + "/build/output/file-helper",
    },
    receipts: [0, 1].map((index) =>
      receipt(
        buildOutput + `/build/command-${index}.json`,
        hash,
        digest(bwrap),
      ),
    ),
    settlement: retired,
  };
  raw.add(buildOutput + "/prepared-build.json", JSON.stringify(result), 0o400);
  const preparation = {
    schemaVersion: 2,
    candidateSha,
    platform: "linux",
    reviewSha256: hash,
    versions: tools.map(({ name, version, sha256 }) => ({
      name,
      version,
      sha256,
    })),
    commands: [0, 1, 2].map((index) => ({
      requestSha256: digest("before" + index),
      status: "RETIRED",
      receiptSha256: hash,
    })),
  };
  preparation.commands.push(...commands, {
    requestSha256: observationDigest({
      candidateSha,
      output: buildOutput,
      helper: manifest.helpers[0],
      reviewSha256: hash,
    }),
    status: "RETIRED",
    receiptSha256: observationDigest(result),
  });
  preparation.commands.push(
    ...[0, 1, 2].map((index) => ({
      requestSha256: digest("after" + index),
      status: "RETIRED",
      receiptSha256: hash,
    })),
  );
  return { ...raw, input, options, preparation, result, root, buildOutput };
}

test("fixed Linux entry rejoins the compiler slice and fresh retirement without recompiling", async (t) => {
  const value = await preparedFixture(t, {
      deadlineMs: 12345,
      root: "/private/report.json",
    }),
    effects = await createSystemEffects(value.input, value.options);
  value.events.length = 0;
  const observed = await effects.verifyBuild(value.preparation);
  assert.equal(observed.settlement.status, "RETIRED");
  assert.deepEqual(observed.settlement, retired);
  assert.equal(
    value.events.filter((event) => event.startsWith("verify:")).length,
    4,
  );
  assert.ok(value.events.every((event) => event.startsWith("verify:")));
  const snapshot = structuredClone(value.preparation);
  snapshot.commands.pop();
  Object.assign(snapshot.commands[2], {
    status: "POSSIBLE",
    receiptSha256: null,
  });
  assert.throws(() =>
    preparedNativeCommands(snapshot, value.input.manifest, 3),
  );
  const legacyInput = structuredClone(value.input);
  legacyInput.manifest.schemaVersion = 1;
  delete legacyInput.manifest.prerequisites;
  const legacyPreparation = {
    ...value.preparation,
    schemaVersion: 1,
    commands: value.preparation.commands.slice(3, 6),
  };
  value.events.length = 0;
  const legacy = await (
    await createSystemEffects(legacyInput, value.options)
  ).verifyBuild(legacyPreparation);
  assert.deepEqual(legacy.settlement, retired);
  assert.equal(
    value.events.filter((event) => event.startsWith("verify:")).length,
    2,
  );
  assert.equal(
    (await effects.verifyBuild(snapshot, { verificationPending: true })).status,
    "OBSERVED",
  );
  // Historical command inputs predate the diagnostic-only IPC nonce.
  for (const [file, node] of value.nodes) {
    if (!/command-[a-f0-9]{64}\/input\.json$/u.test(file)) continue;
    const input = JSON.parse(node.content);
    assert.equal(typeof input.nonce, "string");
    delete input.nonce;
    node.content = Buffer.from(JSON.stringify(input));
  }
  assert.deepEqual(
    (await effects.verifyBuild(value.preparation)).settlement,
    retired,
  );
  const invalid = structuredClone(snapshot);
  invalid.commands[0].status = "POSSIBLE";
  assert.throws(() =>
    preparedNativeCommands(invalid, value.input.manifest, 3, {
      verificationPending: true,
    }),
  );
});

test("fixed Linux verification rejects changed inputs, missing completion and uncertain or reused processes", async (t) => {
  const value = await preparedFixture(t);
  const commandInput = [...value.nodes.keys()].find((file) =>
    /command-[a-f0-9]{64}\/input\.json$/u.test(file),
  );
  const node = value.nodes.get(commandInput),
    original = node.content;
  for (const fields of [{ nonce: "invalid" }, { unknown: true }]) {
    node.content = Buffer.from(
      JSON.stringify({ ...JSON.parse(original), ...fields }),
    );
    const effects = await createSystemEffects(value.input, value.options);
    await assert.rejects(effects.verifyBuild(value.preparation));
  }
  node.content = original;
  for (const file of [
    value.result.build.executable,
    value.buildOutput + "/build/file-helper.c",
    value.buildOutput + "/build/inputs/0",
    value.input.manifest.tools[0].path,
    commandInput,
  ]) {
    const node = value.nodes.get(file),
      original = node.content;
    if (file.endsWith("/input.json")) {
      const input = JSON.parse(original);
      input.command.deadlineMs = 15000;
      node.content = Buffer.from(JSON.stringify(input));
    } else node.content = Buffer.from("substitution");
    const effects = await createSystemEffects(value.input, value.options);
    let primary;
    await assert.rejects(effects.verifyBuild(value.preparation), (error) => {
      primary = error;
      return true;
    });
    node.content = original;
    await assert.rejects(
      effects.verifyBuild(value.preparation),
      (error) => error === primary,
    );
  }
  const resultFile = [...value.nodes.keys()].find((file) =>
      /linux-command-.*-result\.json$/u.test(file),
    ),
    saved = value.nodes.get(resultFile);
  value.nodes.delete(resultFile);
  await assert.rejects(
    (await createSystemEffects(value.input, value.options)).verifyBuild(
      value.preparation,
    ),
  );
  value.nodes.set(resultFile, saved);
  value.faults.changeReceipt = resultFile;
  await assert.rejects(
    (await createSystemEffects(value.input, value.options)).verifyBuild(
      value.preparation,
    ),
  );
  delete value.faults.changeReceipt;
  value.faults.absence = Object.assign(new Error("Unreadable procfs"), {
    code: "EACCES",
  });
  await assert.rejects(
    (await createSystemEffects(value.input, value.options)).verifyBuild(
      value.preparation,
    ),
  );
  delete value.faults.absence;
  const receipt = JSON.parse(
    value.nodes.get(value.result.receipts[0].file).content,
  );
  value.processes.set(receipt.init.pid, {
    pid: receipt.init.pid,
    parent: 1,
    group: receipt.init.pid,
    session: receipt.init.pid,
    startTicks: "2000",
  });
  await assert.rejects(
    (await createSystemEffects(value.input, value.options)).verifyBuild(
      value.preparation,
    ),
  );
});

test("fixed Linux recovery joins interrupted stock custody and retains unknown child effects", async (t) => {
  const value = await preparedFixture(t),
    worker = value.transport();
  await worker.createDirectory("/private/assets");
  await worker.close();
  value.nodes.delete(value.recordPath("completion"));
  value.nodes.delete(value.buildOutput + "/prepared-build.json");
  value.nodes.delete(value.result.build.executable);
  value.processes.delete(42);
  value.processes.set(87, {
    pid: 87,
    parent: 1,
    group: 87,
    session: 87,
    startTicks: "3000",
  });
  value.faults.observerPid = 87;
  value.options.pid = 87;
  value.events.length = 0;
  const effects = await createSystemEffects(value.input, value.options),
    request = { candidateSha };
  assert.equal((await effects.recover({ request })).status, "RETIRED");
  assert.ok(!value.events.includes("spawn"));
  value.events.length = 0;
  value.processes.set(74, {
    pid: 74,
    parent: 1,
    group: 73,
    session: 73,
    startTicks: "1001",
  });
  assert.equal(
    (
      await (
        await createSystemEffects(value.input, value.options)
      ).recover({ request })
    ).status,
    "RETAINED",
  );
  assert.equal(
    value.events.filter((event) => event.startsWith("verify:")).length,
    4,
  );
  value.processes.delete(74);
  value.events.length = 0;
  value.faults.census = Object.assign(new Error("Unreadable census"), {
    code: "EACCES",
  });
  assert.equal(
    (
      await (
        await createSystemEffects(value.input, value.options)
      ).recover({ request })
    ).status,
    "RETAINED",
  );
  assert.equal(
    value.events.filter((event) => event.startsWith("verify:")).length,
    4,
  );
  assert.ok(!value.events.includes("compiler-controller"));
  const missingContext = { ...value.input, prerequisiteCustody: undefined };
  assert.equal(
    (
      await (
        await createSystemEffects(missingContext, value.options)
      ).recover({ request })
    ).status,
    "RETAINED",
  );
  delete value.faults.census;
  value.events.length = 0;
  value.options.loadReviewed = async () => {
    throw new Error("Missing prepared runtime");
  };
  assert.equal(
    (
      await (
        await createSystemEffects(value.input, value.options)
      ).recover({ request })
    ).status,
    "RETAINED",
  );
  const stockRecord = value.events.find(
    (event) =>
      event.startsWith(
        "create:" +
          value.input.prerequisiteCustody.output +
          "/prerequisite-custody-",
      ) && /-recovery-[a-f0-9]{32}\.json$/u.test(event),
  );
  assert.ok(
    stockRecord,
    "Original stock custody retires even when bootstrap inspection fails",
  );
  assert.equal(
    JSON.parse(value.nodes.get(stockRecord.slice("create:".length)).content)
      .settlement.status,
    "RETIRED",
  );
});
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

function modelFreeControllerFixture(fault) {
  const events = [],
    stored = new Map(),
    ready = Promise.withResolvers(),
    close = Promise.withResolvers();
  const worker = new EventEmitter(),
    channel = new EventEmitter(),
    payload = new EventEmitter();
  worker.pid = channel.pid = 101;
  payload.pid = 102;
  for (const name of ["stdin", "stdout", "stderr"]) {
    worker[name] = channel[name] = new PassThrough();
    payload[name] = new PassThrough();
  }
  const identity = (pid) => ({
    bootId: "11111111-1111-4111-8111-111111111111",
    startTicks: String(pid),
  });
  const details = async (pid) => ({
    pid,
    identity: identity(pid),
    parent: pid === 103 ? 102 : 101,
    namespaceId: pid === 103 ? "pid:[201]" : "pid:[200]",
    nspid: pid === 103 ? [103, 1] : [pid],
  });
  const admission = {
    processIdentity: identity(103),
    namespaceId: "pid:[201]",
    launchCutoff: identity(103),
    ancestryBaseline: [{ pid: 101, ...identity(101) }],
    controlGroup: hash,
  };
  const done = Promise.withResolvers();
  payload.ownedCompletion = done.promise;
  payload.kill = () => done.reject(new Error("Registration refused."));
  channel.connected = worker.connected = true;
  channel.disconnect = () => {
    channel.connected = false;
  };
  channel.send = (message, callback) => {
    worker.emit("message", message);
    if (fault === "stream" && message.type === "completed")
      channel.stdout.emit(
        "error",
        Object.assign(new Error("Private output forwarding failed."), {
          code: "EIO",
        }),
      );
    callback();
  };
  worker.send = (message, callback) => {
    events.push("ack");
    channel.emit("message", message);
    callback();
  };
  worker.kill = () => channel.emit("disconnect");
  const request = {
    candidateSha,
    file: "/fixture/tool",
    args: ["app-server", "--listen", "stdio://"],
    cwd: "/fixture/workspace",
    env: { HOME: "/fixture/home", LANG: "C" },
    receiptFile: "/fixture/receipt.json",
  };
  const received = new Promise((resolve) =>
    payload.stdin.once("data", (bytes) => resolve(bytes.toString())),
  );
  spawnLinuxCommandController(request, {
    env: { CI: "true", GITHUB_ACTIONS: "true", ImageOS: "ubuntu24" },
    platform: "linux",
    read: async () => Buffer.from("image"),
    readReceipt: async (file, sha256) => {
      events.push("inspect");
      if (fault === "receipt") throw new Error("Unprotected receipt.");
      assert.equal(digest(stored.get(file)), sha256);
      return normalizeLinuxReceipt(JSON.parse(stored.get(file)));
    },
    details: async (pid) => ({
      ...(await details(pid)),
      identity: identity(fault === "owner" && pid === 101 ? 999 : pid),
    }),
    start: (entry, args, settings) => {
      const config = JSON.parse(args[0]);
      queueMicrotask(async () => {
        await runLinuxCommandController(config, channel, {
          details,
          read: async () => Buffer.from("image"),
          write: async (file, bytes, options) => {
            assert.deepEqual(options, { flag: "wx", mode: 0o400 });
            if (fault === "write")
              throw new Error("Receipt publication refused.");
            stored.set(file, bytes);
            events.push("publish");
          },
          spawn: (file, argv, options) => {
            assert.equal(file, request.file);
            assert.deepEqual(argv, request.args);
            assert.equal(options.cwd, request.cwd);
            assert.deepEqual(options.env, request.env);
            options
              .onProcess(103, admission)
              .then(async () => {
                events.push("payload");
                await received;
                payload.stdout.end("actual-output");
                payload.stderr.end("actual-error");
                await options.onProcess(null);
                if (fault === "completion")
                  throw new Error("Private command settlement failed.");
                done.resolve({
                  outcome: { type: "close", exitCode: 0, signal: null },
                });
              })
              .catch(done.reject);
            return payload;
          },
        });
        ready.resolve();
        await close.promise;
        worker.stdout.end();
        worker.stderr.end();
        events.push("close");
        worker.emit("close", channel.exitCode ?? 0, null);
      });
      return worker;
    },
  });
  worker.ownedCompletion.catch(() => {});
  worker.stdin.end("actual-input");
  return {
    worker,
    events,
    stored,
    ready: ready.promise,
    close: () => close.resolve(),
    input: received,
  };
}

test("Linux model-free command controller binds admission and waits for publication acknowledgement and owner close", async () => {
  const f = modelFreeControllerFixture();
  await f.ready;
  const receipt = JSON.parse(f.stored.get("/fixture/receipt.json"));
  assert.equal(receipt.controller.pid, f.worker.pid);
  assert.equal(receipt.controller.identity.startTicks, "101");
  assert.equal(receipt.launcher.pid, 102);
  assert.equal(await f.input, "actual-input");
  assert.equal(f.worker.stdout.read().toString(), "actual-output");
  assert.equal(f.worker.stderr.read().toString(), "actual-error");
  const verification = verifyLinuxCommandControllers([f.worker], {
    verify: async () => {
      f.events.push("verify");
      return retired;
    },
  });
  assert.deepEqual(f.events, ["publish", "inspect", "ack", "payload"]);
  f.close();
  await f.worker.ownedCompletion;
  assert.deepEqual(await verification, [retired]);
  assert.equal(f.events.join(), "publish,inspect,ack,payload,close,verify");
});

test("Linux model-free command controller refuses failed publication, protected receipt reads and substituted owners", async () => {
  for (const fault of ["write", "receipt", "owner"]) {
    const f = modelFreeControllerFixture(fault);
    await f.ready;
    f.close();
    await assert.rejects(f.worker.ownedCompletion);
    assert.ok(!f.events.includes("payload"));
    assert.ok(!f.events.includes("ack"));
    assert.equal(f.worker.linuxCommandEmergency, true);
    await assert.rejects(
      verifyLinuxCommandControllers([f.worker], {
        verify: async () => retired,
      }),
    );
  }
});

test("Linux model-free command controller keeps admitted completion failures separate from cleanup", async () => {
  const f = modelFreeControllerFixture("completion");
  await f.ready;
  f.close();
  await assert.rejects(f.worker.ownedCompletion, (error) => {
    assert.match(
      error.feasibilityCause.detail,
      /^command transport-completion:/u,
    );
    assert.equal(error.feasibilityCleanupCause.code, "cleanup-unobserved");
    assert.doesNotMatch(JSON.stringify(error), /Private|actual-error/u);
    return true;
  });
});

test("Linux model-free command controller refuses a forwarding failure after successful payload completion", async () => {
  const f = modelFreeControllerFixture("stream");
  await f.ready;
  f.close();
  await assert.rejects(f.worker.ownedCompletion, (error) => {
    assert.match(
      error.feasibilityCause.detail,
      /^command transport-completion:.*native=EIO/u,
    );
    assert.equal(error.feasibilityCleanupCause.code, "cleanup-unobserved");
    assert.doesNotMatch(JSON.stringify(error), /Private|actual-error/u);
    return true;
  });
});

test("Linux command observations retain PID and bind the complete request to independently retired receipts", async () => {
  for (const substituted of [
    false,
    "request-binding",
    "retirement-verification",
    "receipt-protection",
  ]) {
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
        substituted === "request-binding"
          ? { ...request, env: { LANG: "C" } }
          : request,
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
        readReceipt: async () => {
          if (substituted === "receipt-protection")
            throw Object.defineProperty(
              new Error("unpublished /fixture/receipt password=hidden"),
              "code",
              { value: "EIO" },
            );
          return receipt;
        },
        verify: async () =>
          substituted === "retirement-verification"
            ? { ...retired, independent: false }
            : retired,
      });
    if (substituted)
      await assert.rejects(observe(), (error) => {
        assert.ok(
          error.feasibilityCause.detail.startsWith(`build ${substituted}:`),
        );
        if (substituted === "receipt-protection")
          assert.match(error.feasibilityCause.detail, /native=EIO/u);
        assert.doesNotMatch(JSON.stringify(error), /unpublished|password/u);
        return true;
      });
    else
      assert.deepEqual((await observe()).identity, {
        pid: 103,
        ...receipt.init.identity,
      });
  }
});

test("Linux failed compiler observations survive success assertions and admission errors keep their origin", async () => {
  for (const outcome of [
    { type: "close", exitCode: 1, signal: null },
    { type: "close", exitCode: null, signal: "SIGSEGV" },
  ]) {
    const observations = [],
      receipts = [],
      child = new EventEmitter();
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    child.ownedCompletion = Promise.resolve({ outcome });
    const run = createLinuxBuildCommandRunner(
      { candidateSha, directory },
      receipts,
      observations,
      {
        write: async () => {},
        spawn: () => {
          receipts.push({});
          queueMicrotask(() =>
            child.stderr.emit(
              "data",
              Buffer.from(
                "/private/helper.c:4: error: unknown type name 'fixture_type'\npassword=private",
              ),
            ),
          );
          return child;
        },
      },
    );
    await assert.rejects(
      run("/fixture/compiler", [], {
        cwd: directory,
        env: {},
        maxBuffer: 65536,
        timeout: 10000,
      }),
      (error) => {
        assert.equal(
          error.feasibilityCause.code,
          outcome.signal ? "crash" : "setup-failed",
        );
        assert.match(
          error.feasibilityCause.detail,
          /^build compiler-execution:/u,
        );
        assert.match(
          error.feasibilityCause.detail,
          /unknown type name 'fixture_type'/u,
        );
        assert.doesNotMatch(error.feasibilityCause.detail, /private|password/u);
        return true;
      },
    );
    assert.equal(observations.length, 1);
    assert.equal(observations[0].exitCode, outcome.exitCode);
    assert.equal(observations[0].signal, outcome.signal);
  }
  for (const [error, code, timeout] of [
    [
      { code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE", killed: true },
      "setup-failed",
      "unknown",
    ],
    [{ code: "ETIMEDOUT", signal: "SIGTERM" }, "deadline", "true"],
  ]) {
    const run = createLinuxBuildCommandRunner(
      { candidateSha, directory },
      [],
      [],
      {
        write: async () => {},
        spawn: () => ({
          stdout: new EventEmitter(),
          stderr: new EventEmitter(),
          ownedCompletion: Promise.reject(error),
        }),
      },
    );
    await assert.rejects(
      run("/fixture/compiler", [], {
        cwd: directory,
        maxBuffer: 65536,
        timeout: 10000,
      }),
      (failure) => {
        assert.equal(failure.feasibilityCause.code, code);
        assert.match(
          failure.feasibilityCause.detail,
          /^admission owned-process-admission:/u,
        );
        assert.ok(
          failure.feasibilityCause.detail.includes(`timeout=${timeout}`),
        );
        assert.match(failure.feasibilityCause.detail, /exit=unknown/u);
        assert.ok(
          failure.feasibilityCause.detail.includes(
            `signal=${error.signal ?? "unknown"}`,
          ),
        );
        return true;
      },
    );
  }
  const first = linuxDiagnosticError("admission", "ordinary-namespace", {
    exitCode: 1,
    signal: null,
    timedOut: false,
  });
  const run = createLinuxBuildCommandRunner(
    { candidateSha, directory },
    [],
    [],
    {
      write: async () => {},
      spawn: () => {
        throw first;
      },
    },
  );
  await assert.rejects(
    run("/fixture/compiler", [], { cwd: directory }),
    (error) => error === first,
  );
});

test("Linux build failure IPC retains only bound diagnostics and cannot attest retirement", async () => {
  for (const substituted of [false, true]) {
    const { request } = wiring(),
      worker = new EventEmitter();
    let input;
    const first = linuxDiagnosticError("build", "helper-compilation", {
      exitCode: 1,
      signal: null,
      timedOut: false,
      stderr: "/private/helper.c:4: error: unknown type name 'fixture_type'",
    });
    const cleanup = {
      code: "cleanup-unobserved",
      detail: "No independent build retirement witness was available.",
    };
    await assert.rejects(
      runLinuxBuildCommand(request, {
        env,
        platform: "linux",
        fs: {
          mkdir: async () => {},
          writeFile: async (file, bytes) => {
            input = JSON.parse(bytes);
          },
        },
        start: () => {
          queueMicrotask(() => {
            worker.emit(
              "message",
              linuxControllerFailure(
                substituted ? "c".repeat(40) : candidateSha,
                input.nonce,
                first,
                cleanup,
              ),
            );
            worker.emit("close", 1);
          });
          return worker;
        },
        verify: async () => assert.fail("Failure is not retirement evidence."),
      }),
      (error) => {
        if (substituted)
          assert.equal(error.code, "ERR_INVALID_NATIVE_FEASIBILITY");
        else {
          assert.deepEqual(error.feasibilityCause, first.feasibilityCause);
          assert.deepEqual(error.feasibilityCleanupCause, cleanup);
        }
        return true;
      },
    );
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

test("Linux ordinary discovery admits only the fixed GCC recipe and remains matching-CI only", async () => {
  const source = "/fixture/preparation/file-helper.c";
  const args = linuxExperimentQueryArguments(source, "headers");
  const search = [
    "-B/usr/lib/gcc/x86_64-linux-gnu/13/",
    "-B/usr/libexec/gcc/x86_64-linux-gnu/13/",
    "-B/usr/bin/x86_64-linux-gnu-",
    "-B/usr/bin/",
    "--sysroot=/",
  ];
  assert.deepEqual(args.slice(0, search.length), search);
  for (const query of LINUX_EXPERIMENT_QUERIES.filter(
    (name) => name !== "headers",
  ))
    assert.deepEqual(linuxExperimentQueryArguments(source, query), [
      ...search,
      query,
    ]);
  assert.ok(args.includes("-M"));
  assert.ok(args.includes("-std=c11"));
  assert.ok(!args.includes("-o"));
  assert.deepEqual(LINUX_FILE_BUILD_ARGUMENTS.slice(0, search.length), search);
  for (const [program, source, target] of [
    ["cc1", "/usr/libexec/gcc/x86_64-linux-gnu/13/cc1"],
    ["collect2", "/usr/libexec/gcc/x86_64-linux-gnu/13/collect2"],
    ["as", "/usr/bin/x86_64-linux-gnu-as"],
    ["ld", "/usr/bin/x86_64-linux-gnu-ld.bfd", "/usr/bin/x86_64-linux-gnu-ld"],
  ]) {
    const exposed = target ?? source,
      resolutions = [],
      resolve = async (file) => {
        resolutions.push(file);
        return source;
      };
    assert.deepEqual(
      await linuxExperimentProgram(program, exposed, { resolve }),
      { source, target: exposed },
    );
    assert.deepEqual(resolutions, [exposed]);
    for (const reported of [program, "/usr/bin/" + program, source + ".alias"])
      await assert.rejects(
        linuxExperimentProgram(program, reported, {
          resolve: () => assert.fail("Reject unbound targets before discovery"),
        }),
      );
    await assert.rejects(
      linuxExperimentProgram(program, exposed, {
        resolve: async () => "/usr/bin/substituted-tool",
      }),
    );
  }
  assert.deepEqual(
    linuxExperimentHeaders(
      `file-helper: ${source} /usr/include/stdio.h \\
 /usr/include/stdio.h\n`,
      source,
    ),
    ["/usr/include/stdio.h"],
  );
  assert.throws(() =>
    linuxExperimentHeaders(`file-helper: ${source} /tmp/header.h`, source),
  );
  assert.throws(() =>
    linuxExperimentQueryArguments(source, "-fplugin=/fixture/plugin.so"),
  );
  const job = initializeNativeJob(
    {
      candidateSha,
      platform: "linux",
      repository: "example/native",
      runId: "1",
      runAttempt: 1,
    },
    { schemaVersion: 7, purpose: "experiment" },
  );
  await assert.rejects(
    prepareLinuxExperiment(
      job,
      {},
      "/fixture",
      () => assert.fail("No native intent on another platform"),
      { platform: "darwin", env: {} },
    ),
  );
  const env = {
    CI: "true",
    GITHUB_ACTIONS: "true",
    ImageOS: "ubuntu24",
    RUNNER_ENVIRONMENT: "github-hosted",
    RUNNER_OS: "Linux",
    GITHUB_REPOSITORY: job.repository,
    GITHUB_RUN_ID: "2",
    GITHUB_RUN_ATTEMPT: "1",
  };
  await assert.rejects(
    prepareLinuxExperiment(
      job,
      {},
      "/fixture",
      () => assert.fail("No native intent for another run"),
      { platform: "linux", architecture: "x64", env },
    ),
  );
});

function experimentBuildFixture() {
  const directory = "/fixture/native",
    source = Buffer.from("candidate helper source"),
    tool = Buffer.from("fixed native tool"),
    image = elf();
  image.writeUInt16LE(2, 56);
  image.writeBigUInt64LE(0x400080n, 24);
  image.writeUInt32LE(5, 68);
  image.writeBigUInt64LE(0x400000n, 80);
  image.writeBigUInt64LE(512n, 104);
  image.writeUInt32LE(0x6474e551, 120);
  image.writeUInt32LE(6, 124);
  const compiler = "/usr/bin/x86_64-linux-gnu-gcc-13",
    sdk = "/usr/bin/x86_64-linux-gnu-ld.bfd";
  const pins = {
    schemaVersion: 1,
    candidateSha,
    sourceSha256: digest(source),
    compilerVersion: "13.3.0",
    inputs: [
      ...[
        compiler,
        sdk,
        "/usr/libexec/gcc/x86_64-linux-gnu/13/cc1",
        "/usr/libexec/gcc/x86_64-linux-gnu/13/collect2",
      ].map((file) => ({
        source: file,
        target: file,
        sha256: digest(tool),
      })),
      {
        source: "/usr/bin/x86_64-linux-gnu-as",
        target: "/usr/bin/x86_64-linux-gnu-as",
        sha256: digest(tool),
      },
      {
        source: sdk,
        target: "/usr/bin/x86_64-linux-gnu-ld",
        sha256: digest(tool),
      },
      {
        source: "/usr/libexec/gcc/x86_64-linux-gnu/13/liblto_plugin.so",
        target: "/usr/lib/gcc/x86_64-linux-gnu/13/liblto_plugin.so",
        sha256: digest(tool),
      },
    ],
  };
  const intents = new Map(),
    receipts = new Map();
  const commands = [
    [compiler, ["--version"]],
    [sdk, ["--version"]],
    ...LINUX_EXPERIMENT_QUERIES.map((query) => [
      compiler,
      linuxExperimentQueryArguments(
        directory + "/preparation/file-helper.c",
        query,
      ),
    ]),
  ].map(([file, args], index) => {
    const request = {
      candidateSha,
      platform: "linux",
      file,
      args,
      cwd: directory + "/preparation",
      env: { PATH: "/usr/bin:/bin", LANG: "C" },
      deadlineMs: 20000,
      toolSha256: digest(tool),
    };
    intents.set(directory + `/preparation/intent-${index}.json`, {
      purpose: "experiment",
      request,
    });
    const member = {
      file:
        request.cwd + `/command-${observationDigest(request)}/command-0.json`,
      sha256: hash,
    };
    receipts.set(member.file, {
      candidateSha,
      caseId: "argv",
      policyDigest: observationDigest(request),
      executableDigest: digest(tool),
    });
    return member;
  });
  const built = {
    build: {
      candidateSha,
      executable: directory + "/build/output/file-helper",
      sourceSha256: pins.sourceSha256,
      compiler: {
        file: compiler,
        version: pins.compilerVersion,
        sha256: digest(tool),
      },
      inputs: pins.inputs,
      arguments: [...LINUX_FILE_BUILD_ARGUMENTS],
      sha256: digest(image),
      abi: verifyLinuxFileElf(image),
    },
    settlement: retired,
    receipts: [0, 1].map((index) => {
      const policyDigest = digest(
        JSON.stringify(
          linuxFileBuildInvocation(
            directory + "/build",
            pins,
            index === 0
              ? ["-dumpfullversion", "-dumpversion"]
              : LINUX_FILE_BUILD_ARGUMENTS,
          ),
        ),
      );
      const member = {
        file: directory + `/build/command-${index}.json`,
        sha256: hash,
      };
      intents.set(directory + `/build/command-${index}-possible.json`, {
        candidateSha,
        nonce: "original-command",
        policyDigest,
      });
      receipts.set(member.file, {
        candidateSha,
        caseId: "argv",
        nonce: "original-command",
        policyDigest,
        executableDigest: digest(tool),
      });
      return member;
    }),
  };
  const options = {
    read: async (file) => {
      const bytes = file.endsWith("file-helper.c")
        ? source
        : file.endsWith("/file-helper")
          ? image
          : tool;
      return { bytes, sha256: digest(bytes), identitySha256: hash };
    },
    readIntent: async (file) => Buffer.from(JSON.stringify(intents.get(file))),
    receipt: async (file) => receipts.get(file),
    verify: async () => retired,
  };
  return {
    directory,
    record: { purpose: "experiment", candidateSha, pins, built, commands },
    options,
    receipts,
    intents,
  };
}

test("Linux rejected build bindings retain bounded diagnostics despite sink failure", () => {
  const f = experimentBuildFixture(),
    pins = structuredClone(f.record.pins),
    source = "/usr/libexec/" + "x".repeat(70000),
    target = pins.inputs.at(-1).target,
    diagnosticError = new Error("unavailable diagnostic sink");
  pins.inputs.at(-1).source = source;
  for (const failSink of [false, true]) {
    const output = [];
    assert.throws(
      () =>
        withNativeDiagnostics(
          () => normalizeLinuxFileBuildPins(pins, candidateSha),
          (owner, value) => {
            output.push({ owner, value });
            if (failSink) throw diagnosticError;
          },
        ),
      (error) => {
        assert.notEqual(error, diagnosticError);
        assert.equal(
          error.message,
          "Missing or mismatched Linux helper build inputs",
        );
        return true;
      },
    );
    assert.equal(output.length, 1);
    assert.equal(output[0].owner, "linux-file-build-input");
    const facts = JSON.parse(output[0].value.stderr);
    assert.equal(facts.index, pins.inputs.length - 1);
    assert.equal(facts.source, source.slice(0, 1024));
    assert.equal(facts.sourceLength, source.length);
    assert.equal(facts.target, target);
    assert.ok(Buffer.byteLength(JSON.stringify(output)) < 4096);
  }
});

test("Linux ordinary preparation rejoins actual fixed commands, source, output and fresh retirement", async () => {
  const f = experimentBuildFixture(),
    job = { candidateSha };
  assert.equal(
    (await verifyLinuxExperimentBuild(job, f.directory, f.record, f.options))
      .sha256,
    f.record.built.build.sha256,
  );
  const invocation = linuxFileBuildInvocation(
    f.directory + "/build",
    f.record.pins,
    LINUX_FILE_BUILD_ARGUMENTS,
  );
  assert.deepEqual(
    invocation.slice(invocation.indexOf("--") + 2),
    LINUX_FILE_BUILD_ARGUMENTS,
  );
  const linker = f.record.pins.inputs.find(
      ({ target }) => target === "/usr/bin/x86_64-linux-gnu-ld",
    ),
    snapshot = `${f.directory}/build/inputs/${f.record.pins.inputs.indexOf(linker)}`,
    executions = [];
  for (const target of ["/usr/bin/x86_64-linux-gnu-ld", "/usr/bin/ld"]) {
    const at = invocation.indexOf(target);
    assert.deepEqual(invocation.slice(at - 2, at + 1), [
      "--ro-bind",
      snapshot,
      target,
    ]);
    assert.equal(invocation.filter((value) => value === target).length, 1);
  }
  for (const input of [
    { ...linker, target: "/usr/bin/ld" },
    { ...linker, source: "/usr/bin/substituted-tool", target: "/usr/bin/ld" },
    { ...linker, source: "/usr/bin/ld", target: "/usr/bin/alternate-ld" },
  ])
    assert.throws(() =>
      normalizeLinuxFileBuildPins(
        {
          ...f.record.pins,
          inputs: [...f.record.pins.inputs, input],
        },
        candidateSha,
      ),
    );
  await buildLinuxFileHelper(
    candidateSha,
    f.directory + "/build",
    "/usr/bin/bwrap",
    f.record.pins,
    {
      platform: "linux",
      architecture: "x64",
      env: { CI: "true", GITHUB_ACTIONS: "true", ImageOS: "ubuntu24" },
      protect: () => {},
      fs: {
        mkdir: async () => {},
        realpath: async (file) => file,
        readFile: async (file) =>
          file === "/etc/os-release"
            ? 'ID=ubuntu\nVERSION_ID="24.04"\n'
            : (await f.options.read(file)).bytes,
        lstat: async (file) => ({
          isFile: () => true,
          nlink: 1,
          mode: 0o500,
          size: (await f.options.read(file)).bytes.length,
        }),
        writeFile: async () => {},
        chmod: async () => {},
      },
      run: async (file, args) => {
        assert.equal(file, "/usr/bin/bwrap");
        executions.push(args);
        return { stdout: f.record.pins.compilerVersion };
      },
    },
  );
  assert.equal(executions.length, 2);
  assert.deepEqual(executions[1], invocation);
  for (const [index, args] of executions.entries()) {
    const receipt = f.receipts.get(f.record.built.receipts[index].file),
      marker = f.intents.get(
        f.directory + `/build/command-${index}-possible.json`,
      ),
      original = receipt.policyDigest,
      at = args.indexOf("/usr/bin/ld");
    assert.equal(original, digest(JSON.stringify(args)));
    for (const replacement of [
      [],
      ["--ro-bind", "/usr/bin/ld", "/usr/bin/ld"],
      ["--bind", snapshot, "/usr/bin/ld"],
    ]) {
      const changed = [...args];
      changed.splice(at - 2, 3, ...replacement);
      receipt.policyDigest = marker.policyDigest = digest(
        JSON.stringify(changed),
      );
      await assert.rejects(
        verifyLinuxExperimentBuild(job, f.directory, f.record, f.options),
      );
    }
    receipt.policyDigest = marker.policyDigest = original;
  }
  assert.equal(invocation.includes("/usr/bin/as"), false);
  for (const { source, target } of f.record.pins.inputs.slice(2)) {
    const index = f.record.pins.inputs.findIndex(
        (input) => input.target === target,
      ),
      at = invocation.indexOf(target);
    assert.ok(index >= 0);
    assert.deepEqual(invocation.slice(at - 2, at + 1), [
      "--ro-bind",
      `${f.directory}/build/inputs/${index}`,
      target,
    ]);
    for (const file of [source, `${f.directory}/build/inputs/${index}`])
      await assert.rejects(
        verifyLinuxExperimentBuild(job, f.directory, f.record, {
          ...f.options,
          read: async (name, ...args) => ({
            ...(await f.options.read(name, ...args)),
            ...(name === file ? { sha256: hash } : {}),
          }),
        }),
      );
  }
  for (const target of [
    "/usr/bin/x86_64-linux-gnu-as",
    "/usr/bin/x86_64-linux-gnu-ld",
  ]) {
    for (const field of ["source", "target"]) {
      const value = structuredClone(f.record),
        input = value.pins.inputs.find((member) => member.target === target);
      input[field] = "/usr/bin/substituted-tool";
      await assert.rejects(
        verifyLinuxExperimentBuild(job, f.directory, value, f.options),
      );
    }
    const value = structuredClone(f.record);
    value.pins.inputs = value.pins.inputs.filter(
      (input) => input.target !== target,
    );
    value.built.build.inputs = value.pins.inputs;
    await assert.rejects(
      verifyLinuxExperimentBuild(job, f.directory, value, f.options),
    );
  }
  const missing = structuredClone(f.record);
  missing.commands.pop();
  await assert.rejects(
    verifyLinuxExperimentBuild(job, f.directory, missing, f.options),
  );
  for (const change of [
    (value) => {
      value.built.build.sha256 = hash;
    },
    (value) => {
      value.pins.sourceSha256 = hash;
    },
    (value) => {
      value.built.build.arguments.push("-shared");
    },
    (value) => {
      value.built.build.arguments = value.built.build.arguments.filter(
        (argument) => argument !== "-B/usr/bin/x86_64-linux-gnu-",
      );
    },
    (value) => {
      value.pins.inputs[2].source = "/usr/lib/gcc/x86_64-linux-gnu/13/cc1";
    },
    (value) => {
      value.pins.inputs[2].target = value.pins.inputs[3].target;
    },
    (value) => {
      value.pins.inputs.at(-1).source = value.pins.inputs.at(-1).target;
    },
    (value) => {
      value.pins.inputs.at(-1).target = value.pins.inputs.at(-1).source;
    },
  ]) {
    const value = structuredClone(f.record);
    change(value);
    await assert.rejects(
      verifyLinuxExperimentBuild(job, f.directory, value, f.options),
    );
  }
  const last = f.receipts.get(f.record.built.receipts[1].file);
  const marker = f.intents.get(f.directory + "/build/command-1-possible.json"),
    originalPolicy = last.policyDigest;
  last.policyDigest = marker.policyDigest = digest(
    JSON.stringify(
      linuxFileBuildInvocation(
        f.directory + "/build",
        f.record.pins,
        LINUX_FILE_BUILD_ARGUMENTS.filter(
          (argument) => argument !== "-B/usr/bin/x86_64-linux-gnu-",
        ),
      ),
    ),
  );
  await assert.rejects(
    verifyLinuxExperimentBuild(job, f.directory, f.record, f.options),
  );
  last.policyDigest = marker.policyDigest = originalPolicy;
  last.policyDigest = hash;
  await assert.rejects(
    verifyLinuxExperimentBuild(job, f.directory, f.record, f.options),
  );
  last.policyDigest = f.intents.get(
    f.directory + "/build/command-1-possible.json",
  ).policyDigest;
  const discovery = f.intents.get(f.directory + "/preparation/intent-3.json");
  for (const prefix of [
    "-B/usr/libexec/gcc/x86_64-linux-gnu/13/",
    "-B/usr/bin/x86_64-linux-gnu-",
  ]) {
    const original = discovery.request.args;
    discovery.request.args = original.filter((argument) => argument !== prefix);
    await assert.rejects(
      verifyLinuxExperimentBuild(job, f.directory, f.record, f.options),
    );
    discovery.request.args = original;
  }
  discovery.request.args = linuxExperimentQueryArguments(
    f.directory + "/preparation/file-helper.c",
    "-print-prog-name=cc1",
  );
  await assert.rejects(
    verifyLinuxExperimentBuild(job, f.directory, f.record, {
      ...f.options,
      verify: async () => ({ ...retired, independent: false }),
    }),
  );
});

test("Linux ordinary interrupted preparation retains missing receipts and never erases the first failure", async () => {
  const f = experimentBuildFixture();
  let job = initializeNativeJob(
    {
      candidateSha,
      platform: "linux",
      repository: "example/native",
      runId: "1",
      runAttempt: 1,
    },
    { schemaVersion: 7, purpose: "experiment" },
  );
  job = recordExperimentPreparationEffect(job, {
    admission: "possible",
    settlement: {
      status: "RETAINED",
      independent: false,
      emergencyCleanup: false,
    },
    receiptSha256: null,
  });
  job = { ...job, failure: "preparation-failed" };
  const env = {
    CI: "true",
    GITHUB_ACTIONS: "true",
    ImageOS: "ubuntu24",
    RUNNER_ENVIRONMENT: "github-hosted",
    RUNNER_OS: "Linux",
    GITHUB_REPOSITORY: job.repository,
    GITHUB_RUN_ID: job.runId,
    GITHUB_RUN_ATTEMPT: String(job.runAttempt),
  };
  const owner = {
    purpose: "experiment",
    candidateSha,
    contextSha256: observationDigest({
      repository: job.repository,
      runId: job.runId,
      runAttempt: job.runAttempt,
    }),
    pid: 123,
    identity: {
      bootId: "a1234567-1234-1234-1234-123456789012",
      startTicks: "10",
    },
  };
  const read = async (file) => {
    if (file.endsWith("experiment-preparation-owner.json"))
      return Buffer.from(JSON.stringify(owner));
    if (file.endsWith("intent-0.json")) return f.options.readIntent(file);
    if (f.receipts.has(file)) return Buffer.from("original protected receipt");
    throw new Error("Interrupted admission has no birth receipt");
  };
  for (const complete of [false, true]) {
    const recovered = await recoverLinuxExperimentPreparation(
      job,
      f.directory,
      async () => {},
      {
        env,
        platform: "linux",
        architecture: "x64",
        fs: {
          readdir: async () => [
            "intent-0.json",
            ...(complete ? [] : ["build-intent.json"]),
          ],
          lstat: async () => {
            throw Object.assign(new Error("Absent original preparer"), {
              code: "ENOENT",
            });
          },
        },
        read,
        receipt: f.options.receipt,
        verify: f.options.verify,
        rejoinInterpreter: async () => null,
        identity: async () => null,
        visible: async () => {},
      },
    );
    assert.equal(recovered.failure, "preparation-failed");
    assert.equal(recovered.preparationEffects.admission, "possible");
    assert.equal(
      recovered.preparationEffects.settlement.status,
      complete ? "RETIRED" : "UNVERIFIABLE",
    );
    assert.equal(recovered.preparation, null);
  }
  for (const identity of [
    async () => owner.identity,
    async () => {
      throw new Error("Observer lacks procfs authority");
    },
  ]) {
    const recovered = await recoverLinuxExperimentPreparation(
      job,
      f.directory,
      async () => {},
      {
        env,
        platform: "linux",
        architecture: "x64",
        read,
        receipt: f.options.receipt,
        verify: f.options.verify,
        rejoinInterpreter: async () => null,
        identity,
        visible: async () => {},
        fs: {
          readdir: () =>
            assert.fail("Live or uncertain preparers keep admissions open"),
        },
      },
    );
    assert.equal(
      recovered.preparationEffects.settlement.status,
      "UNVERIFIABLE",
    );
  }
  const inaccessible = await recoverLinuxExperimentPreparation(
    job,
    f.directory,
    async () => {},
    {
      env,
      platform: "linux",
      architecture: "x64",
      read,
      rejoinInterpreter: async () => null,
      identity: async () => null,
      visible: async () => {},
      fs: {
        lstat: async () => {
          throw Object.assign(new Error("Inaccessible preparer"), {
            code: "EACCES",
          });
        },
        readdir: () => assert.fail("Inaccessibility proves no absence"),
      },
    },
  );
  assert.equal(
    inaccessible.preparationEffects.settlement.status,
    "UNVERIFIABLE",
  );
  const bytes = Buffer.from("original protected receipt"),
    members = (values) =>
      values.map((value) => ({ ...value, sha256: digest(bytes) })),
    settled = recordExperimentPreparationEffect(job, {
      admission: "possible",
      settlement: retired,
      receiptSha256: observationDigest({
        commands: members(f.record.commands),
        receipts: members(f.record.built.receipts),
      }),
    });
  for (const unavailable of [false, true]) {
    const rejoin = () =>
      recoverLinuxExperimentPreparation(
        settled,
        f.directory,
        () => assert.fail("A settled preparation is not rewritten"),
        {
          env,
          platform: "linux",
          architecture: "x64",
          reconcile: true,
          rejoinInterpreter: async () => null,
          identity: async () => null,
          visible: async () => {},
          fs: {
            readdir: async () => [
              ...f.record.commands.map((_, index) => `intent-${index}.json`),
              "build-intent.json",
            ],
            lstat: async () => {
              throw Object.assign(new Error("Absent preparer"), {
                code: "ENOENT",
              });
            },
          },
          read: async (file) =>
            file.endsWith("experiment-preparation-owner.json")
              ? JSON.stringify(owner)
              : file.endsWith("build-intent.json")
                ? JSON.stringify({
                    purpose: "experiment",
                    candidateSha,
                    pins: f.record.pins,
                  })
                : f.receipts.has(file)
                  ? bytes
                  : f.options.readIntent(file),
          receipt: f.options.receipt,
          verify: async () =>
            unavailable
              ? {
                  status: "RETAINED",
                  independent: false,
                  emergencyCleanup: false,
                }
              : retired,
        },
      );
    if (unavailable) await assert.rejects(rejoin());
    else assert.deepEqual(await rejoin(), settled);
  }
});

test("Linux independent held reads reject substituted inode and byte-window identities and always close", async () => {
  for (const fault of [null, "inode", "bytes"]) {
    let closed = false,
      calls = 0;
    const stat = {
      isFile: () => true,
      dev: 1n,
      ino: 2n,
      size: 1n,
      mode: 0o100400n,
      nlink: 1n,
      uid: 0n,
      gid: 0n,
      mtimeNs: 1n,
      ctimeNs: 1n,
    };
    const fs = {
      realpath: async (file) => file,
      lstat: async () => ({ ...stat, ino: fault === "inode" ? 3n : 2n }),
      open: async () => ({
        stat: async () => ({
          ...stat,
          mtimeNs: fault === "bytes" && calls++ ? 2n : 1n,
        }),
        read: async (bytes, offset, length, position) => ({
          bytesRead:
            position === 0
              ? Buffer.from("x").copy(bytes, offset, 0, length)
              : 0,
        }),
        close: async () => {
          closed = true;
        },
      }),
    };
    const result = readLinuxObservedFile("/fixture/tool", 1024, {
      fs,
      protect: () => {},
    });
    if (fault) await assert.rejects(result);
    else assert.equal((await result).sha256, digest(Buffer.from("x")));
    assert.equal(closed, true);
  }
});

test("Linux interpreter acquisition binds held setup bytes to the running inode and closes both handles", async () => {
  for (const fault of [null, "source", "running", "inode", "bytes"]) {
    const bytes = elf(),
      closed = [],
      source = "/fixture/setup/node";
    let changed = false;
    const stat = () => ({
      isFile: () => true,
      dev: 1n,
      ino: 2n,
      size: BigInt(bytes.length),
      mode: 0o100755n,
      nlink: 1n,
      uid: 1000n,
      gid: 1000n,
      mtimeNs: fault === "bytes" && changed ? 2n : 1n,
      ctimeNs: 1n,
    });
    const fs = {
      realpath: async (file) =>
        file === "/proc/self/exe" && fault === "source"
          ? "/fixture/other/node"
          : source,
      lstat: async () => ({ ...stat(), ino: fault === "inode" ? 3n : 2n }),
      open: async (file, flags) => {
        if (file === source) assert.ok(flags & constants.O_NOFOLLOW);
        return {
          stat: async () => ({
            ...stat(),
            ino: file === "/proc/self/exe" && fault === "running" ? 3n : 2n,
          }),
          read: async (buffer, offset, length, position) => {
            changed = true;
            return {
              bytesRead: bytes.copy(
                buffer,
                offset,
                position,
                position + length,
              ),
            };
          },
          close: async () => closed.push(file),
        };
      },
    };
    if (fault) await assert.rejects(readLinuxInterpreterSource({ fs }));
    else {
      const acquired = await readLinuxInterpreterSource({ fs });
      assert.equal(acquired.sha256, digest(bytes));
      assert.deepEqual(await readLinuxRunningInterpreterIdentity({ fs }), {
        version: process.version,
        identitySha256: acquired.identitySha256,
      });
    }
    assert.equal(closed.length, fault === "source" ? 0 : fault ? 2 : 3);
    await assert.rejects(
      readLinuxObservedFile(source, 1024, {
        fs,
        protect: () => {
          throw new Error("Mutable launcher refused");
        },
      }),
    );
  }
});

test("Linux sealed interpreter cold rejoin rejects substitutions and never repeats interrupted acquisition", async () => {
  for (const fault of [
    null,
    "inode",
    "bytes",
    "library",
    "library-inode",
    "running",
    "running-version",
    "pin",
    "owner",
    "intent",
    "missing",
    "interrupted",
    "lost-reply",
  ]) {
    const job = {
        candidateSha,
        platform: "linux",
        repository: "example/native",
        runId: "1",
        runAttempt: 1,
        preparation: null,
      },
      directory = "/fixture/native",
      bytes = elf(),
      owner = {
        purpose: "experiment",
        candidateSha,
        contextSha256: observationDigest({
          repository: job.repository,
          runId: job.runId,
          runAttempt: 1,
        }),
        pid: 77,
        identity: {
          bootId: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
          startTicks: "1",
        },
      },
      ownerFile = directory + "/experiment-preparation-owner.json",
      recordFile = directory + "/preparation/interpreter.json",
      intentFile = directory + "/preparation/interpreter-intent.json",
      executable = directory + "/preparation/executables/node",
      library = "/usr/lib/libfixture.so",
      files = new Map([
        [ownerFile, Buffer.from(JSON.stringify(owner))],
        [library, bytes],
      ]),
      identities = new Map([[executable, "d".repeat(64)]]);
    let acquisitions = 0,
      writes = 0;
    const read = async (file, _, settings) => {
      assert.ok(files.has(file), "Only the held inventory is observed");
      if (file === library) assert.notEqual(settings?.protectedInput, false);
      return {
        bytes: files.get(file),
        sha256: digest(files.get(file)),
        identitySha256: identities.get(file) ?? hash,
        metadata: { mode: 0o500 },
      };
    };
    const acquire = () =>
      acquireLinuxExperimentInterpreter(job, owner, directory, {
        version: "v24.21.0",
        read,
        source: async () => {
          assert.ok(files.has(ownerFile));
          acquisitions++;
          return {
            file: "/fixture/setup/node",
            bytes,
            sha256: digest(bytes),
            identitySha256: hash,
          };
        },
        sharedObjects: () => ["linux-vdso.so.1", library],
        fs: {
          mkdir: async () => {},
          realpath: async (file) => file,
          writeFile: async (file, data, options) => {
            writes++;
            assert.equal(options.flag, "wx");
            assert.equal(options.mode, file === executable ? 0o500 : 0o400);
            if (file === recordFile && fault === "interrupted")
              throw new Error("Interrupted original publication");
            files.set(file, Buffer.from(data));
            if (file === recordFile && fault === "lost-reply")
              throw new Error("Lost original reply");
          },
        },
      });
    let interpreter;
    if (["interrupted", "lost-reply"].includes(fault))
      await assert.rejects(acquire());
    else interpreter = await acquire();
    if (files.has(recordFile)) {
      interpreter ??= JSON.parse(files.get(recordFile));
      job.preparation = {
        expected: {
          sources: [
            { id: "node-interpreter", sha256: observationDigest(interpreter) },
          ],
        },
      };
    }
    if (fault === "inode") identities.set(executable, "c".repeat(64));
    if (fault === "bytes")
      files.set(executable, Buffer.from("substituted image"));
    if (fault === "library")
      files.set(library, Buffer.from("substituted loader"));
    if (fault === "library-inode") identities.set(library, "c".repeat(64));
    if (fault === "pin")
      job.preparation.expected.sources[0].sha256 = "c".repeat(64);
    if (fault === "owner")
      files.set(
        ownerFile,
        Buffer.from(
          JSON.stringify({
            ...owner,
            identity: { ...owner.identity, startTicks: "2" },
          }),
        ),
      );
    if (fault === "intent") files.set(intentFile, Buffer.from("{}"));
    if (fault === "missing") files.delete(recordFile);
    const readIntent = async (file) => {
      if (!files.has(file))
        throw Object.assign(new Error("Missing original inventory"), {
          code: "ENOENT",
        });
      return files.get(file);
    };
    const written = writes,
      running = async (identitySha256 = hash) => ({
        version: fault === "running-version" ? "v24.0.0" : "v24.21.0",
        identitySha256: fault === "running" ? "c".repeat(64) : identitySha256,
      }),
      rejoin = (identitySha256) =>
        rejoinLinuxExperimentInterpreter(job, directory, {
          read,
          readIntent,
          running: () => running(identitySha256),
        });
    if (fault && fault !== "lost-reply") await assert.rejects(rejoin(), fault);
    else {
      assert.deepEqual(await rejoin(), interpreter);
      assert.deepEqual(await rejoin(interpreter.identitySha256), interpreter);
      assert.deepEqual(
        await freshVerifier("/fixture/original-receipt.json", hash, {
          interpreter,
          readInterpreter: read,
          executeFile: async (file, args) => {
            assert.equal(
              file,
              executable,
              "The fresh verifier uses the original sealed image",
            );
            assert.equal(args[2], "/fixture/original-receipt.json");
            return { stdout: JSON.stringify(retired) };
          },
        }),
        retired,
      );
    }
    assert.equal(acquisitions, 1);
    assert.equal(
      writes,
      written,
      "Cold rejoin performs no acquisition or publication",
    );
    if (["interrupted", "lost-reply"].includes(fault)) {
      const initial = initializeNativeJob(
        {
          candidateSha,
          platform: "linux",
          repository: job.repository,
          runId: "1",
          runAttempt: 1,
        },
        { schemaVersion: 7, purpose: "experiment" },
      );
      const admitted = {
        ...recordExperimentPreparationEffect(initial, {
          admission: "possible",
          settlement: {
            status: "RETAINED",
            independent: false,
            emergencyCleanup: false,
          },
          receiptSha256: null,
        }),
        failure: "preparation-failed",
      };
      const recovered = await recoverLinuxExperimentPreparation(
        admitted,
        directory,
        async () => {},
        {
          platform: "linux",
          architecture: "x64",
          env: {
            CI: "true",
            GITHUB_ACTIONS: "true",
            ImageOS: "ubuntu24",
            RUNNER_ENVIRONMENT: "github-hosted",
            RUNNER_OS: "Linux",
            GITHUB_REPOSITORY: job.repository,
            GITHUB_RUN_ID: "1",
            GITHUB_RUN_ATTEMPT: "1",
          },
          read: readIntent,
          rejoinInterpreter: (value, root, options) =>
            rejoinLinuxExperimentInterpreter(value, root, {
              ...options,
              read,
              running,
            }),
          identity: async () => null,
          visible: async () => {},
          verify: () =>
            assert.fail("No original compiler operation was released"),
          fs: {
            readdir: async () => [
              "executables",
              "interpreter-intent.json",
              ...(files.has(recordFile) ? ["interpreter.json"] : []),
            ],
            lstat: async () => {
              throw Object.assign(new Error("Absent original owner"), {
                code: "ENOENT",
              });
            },
          },
        },
      );
      assert.equal(recovered.failure, "preparation-failed");
      assert.equal(
        recovered.preparationEffects.settlement.status,
        fault === "lost-reply" ? "RETIRED" : "UNVERIFIABLE",
      );
    }
  }
});
