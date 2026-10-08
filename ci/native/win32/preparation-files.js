import { randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { win32 as path } from "node:path";
import { observationDigest, requireObservation } from "../index.js";
import {
  closed,
  digest,
  hash,
  sameWindowsIdentity,
  systemIdentity,
  normalizeWindowsIdentity,
} from "./protocol.js";
import {
  decode,
  encode,
  location,
  windowsVerificationArguments,
} from "./custody-protocol.js";
import { windowsCustodyChannel } from "./channel.js";
import { createWindowsCustodyVerifier } from "./custody-verifier.js";
import { normalizeWindowsFileIdentity } from "./files-protocol.js";
import {
  WINDOWS_BUILD_COMMAND_MS,
  WINDOWS_BUILD_TOOLS,
  WINDOWS_HELPER_NAMES,
} from "./build.js";

// One observer spans the two version queries, thirteen compilations and a
// separate cleanup budget. It never launches a compiler or a work helper.
export const WINDOWS_PREPARATION_CUSTODY_MS =
  WINDOWS_BUILD_TOOLS.length * 30000 +
  WINDOWS_HELPER_NAMES.length * WINDOWS_BUILD_COMMAND_MS +
  120000;

/** The separately approved reader/bridge are bootstrap inputs. Only their raw
 * file/IPC edges are injectable. The native bridge persists its exact observer
 * request before registering a task; the System observer admits no helpers. */
export function createWindowsPreparationFiles(input, options = {}) {
  const bootstrap = structuredClone(
      input.manifest.windowsPreparation.bootstrap,
    ),
    directory = input.directory ?? path.dirname(input.output ?? input.helpers),
    output = input.output ?? input.helpers,
    clock = options.clock ?? Date.now,
    maximumReceipts = input.manifest.prerequisites?.packages.some(
      (entry) =>
        entry.packageId === "git-for-windows" &&
        entry.reviewed.extraction?.custody,
    )
      ? 1048576
      : 65536;
  let owner,
    identity,
    bridge,
    taskSha256,
    starting,
    failed,
    sequence = 0,
    serial = Promise.resolve(),
    fileSerial = Promise.resolve(),
    verifier,
    closedOwner = false,
    nonce,
    declaration,
    deadline,
    workSignal = input.signal;
  const readers = new Map();
  const caseOwners = new Map();
  let admissionClosed = false;
  let admissionChecked = false;
  const guard = (signal = workSignal) => {
    if (failed) throw failed;
    requireObservation(
      !closedOwner &&
        !signal?.aborted &&
        (deadline === undefined || clock() < deadline),
    );
  };
  const start = async () => {
    guard();
    requireObservation(
      typeof options.openPreparation === "function" ||
        typeof options.spawnProcess === "function" ||
        (process.platform === "win32" && process.arch === "x64"),
    );
    requireObservation(
      location(directory) &&
        !directory.includes("%") &&
        output === path.join(directory, "platform-build"),
    );
    const env = options.env ?? process.env;
    requireObservation(
      env.CI === "true" &&
        env.GITHUB_ACTIONS === "true" &&
        /^win25(?:-vs2026)?$/u.test(env.ImageOS) &&
        location(env.RUNNER_TEMP) &&
        directory.startsWith(env.RUNNER_TEMP + "\\"),
    );
    nonce = observationDigest({
      bootstrap,
      directory,
      role: "preparation-files",
      allocation: randomBytes(16).toString("hex"),
      ...(input.recoverySequence === undefined
        ? {}
        : { recoverySequence: input.recoverySequence }),
    }).slice(0, 32);
    requireObservation(
      input.recoverySequence === undefined ||
        (Number.isSafeInteger(input.recoverySequence) &&
          input.recoverySequence >= 0 &&
          input.recoverySequence <= maximumReceipts),
    );
    declaration = { ...bootstrap, nonce };
    deadline = clock() + WINDOWS_PREPARATION_CUSTODY_MS;
    // This bridge is the separately admitted, held bootstrap seed, never an
    // acquired build result. It independently holds the approved reader/plan
    // before task creation. System-private inputs are read only by that owner.
    const args = [
      "--observe",
      bootstrap.reader.path,
      bootstrap.reader.sha256,
      bootstrap.reader.signatureSha256,
      bootstrap.plan.path,
      bootstrap.plan.sha256,
      nonce,
      bootstrap.runnerSid,
      directory,
      output,
    ];
    owner = await (
      options.openPreparation ??
      ((file, args, settings) =>
        windowsCustodyChannel(
          (options.spawnProcess ?? spawn)(file, args, settings),
          { deadlineMs: WINDOWS_PREPARATION_CUSTODY_MS },
        ))
    )(bootstrap.bridge.path, args, {
      cwd: path.dirname(bootstrap.bridge.path),
      env: { CI: "true", GITHUB_ACTIONS: "true", PATH: "C:\\nonexistent" },
      shell: false,
      stdio: ["pipe", "pipe", "ignore"],
    });
    const intent = await owner.receive();
    closed(intent, ["phase", "taskSha256", "bridge", "intentSha256"]);
    bridge = normalizeWindowsIdentity(intent.bridge);
    requireObservation(
      intent.phase === "task-intent" &&
        hash(intent.taskSha256) &&
        hash(intent.intentSha256) &&
        bridge.pid === owner.pid &&
        bridge.userSid === bootstrap.runnerSid,
    );
    await owner.send("T");
    const registered = await owner.receive();
    closed(registered, ["phase", "taskSha256"]);
    requireObservation(
      registered.phase === "task-registered" && hash(registered.taskSha256),
    );
    taskSha256 = registered.taskSha256;
    await owner.send("B");
    const entry = await owner.receive(),
      peer = await owner.receive();
    closed(entry, ["phase", "helper", "bridge", "processDaclSha256"]);
    closed(peer, ["helper", "peer"]);
    identity = systemIdentity(entry.helper);
    requireObservation(
      entry.phase === "entry" &&
        hash(entry.processDaclSha256) &&
        sameWindowsIdentity(entry.bridge, bridge) &&
        sameWindowsIdentity(peer.peer, bridge) &&
        sameWindowsIdentity(peer.helper, identity),
    );
    await owner.send("P\n");
    const setup = await owner.receive();
    closed(setup, ["candidateSha", "nonce", "entries"]);
    requireObservation(
      setup.candidateSha === input.job.candidateSha &&
        setup.nonce === nonce &&
        Number.isSafeInteger(setup.entries) &&
        setup.entries > 0 &&
        setup.entries <= 128,
    );
    if (bootstrap.context.executionId === "package.git-for-windows") {
      await owner.send(`prepare-package-bind ${++sequence}\n`);
      const reply = await owner.receive();
      closed(reply, ["sequence", "value"]);
      closed(reply.value, ["bound"]);
      requireObservation(
        reply.sequence === sequence && reply.value.bound === true,
      );
    }
  };
  const ensure = () =>
    (starting ??= start().catch((error) => {
      failed ??= error;
      owner?.close();
      throw failed;
    }));
  const command = (name, args = []) => {
    const work = serial.then(async () => {
      guard();
      await ensure();
      requireObservation(
        ++sequence <=
          (declaration.context.executionId === "package.git-for-windows"
            ? 1048576
            : 32768),
      );
      await owner.send([name, sequence, ...args].join(" ") + "\n");
      const reply = await owner.receive();
      closed(reply, ["sequence", "value"]);
      requireObservation(reply.sequence === sequence);
      guard();
      return reply.value;
    });
    serial = work.catch((error) => {
      failed ??= error;
      owner?.close();
    });
    return work;
  };
  // A native read/upload owns its single slot until release/seal. Independent
  // verifier commands may run between chunks, but file flows cannot interleave.
  const fileOperation = (operation) => {
    const work = fileSerial.then(operation);
    fileSerial = work.catch(() => {});
    return work;
  };
  const native = {
    get input() {
      return structuredClone(declaration);
    },
    get identity() {
      guard();
      return structuredClone(identity);
    },
    get bridge() {
      guard();
      return structuredClone(bridge);
    },
    get taskSha256() {
      guard();
      return taskSha256;
    },
    command: (name, args) =>
      command("verify-" + name, windowsVerificationArguments(name, args)),
  };
  const observer = async () => {
    await ensure();
    return (verifier ??= createWindowsCustodyVerifier(
      { verification: native },
      { clock, maximumSubjects: 128, deadline },
    ));
  };
  const proof = (actual) => {
    normalizeWindowsFileIdentity(actual.identity);
    requireObservation(
      typeof actual.identity === "string" &&
        hash(actual.daclSha256) &&
        actual.protectedParents === true,
    );
    return {
      independent: true,
      held: true,
      protectedDacl: true,
      protectedParents: true,
      identitySha256: observationDigest(actual.identity),
      nativeEventSha256: observationDigest(actual),
    };
  };
  const readFile = async ({
    file,
    sha256,
    maximum = 134217728,
    receipt = false,
    snapshot = false,
  }) => {
    requireObservation(
      location(file) &&
        (!sha256 || hash(sha256)) &&
        Number.isSafeInteger(maximum) &&
        maximum > 0 &&
        maximum <= 134217728,
    );
    const actual = await command("prepare-read", [
      encode(file),
      sha256 ?? "-",
      maximum,
      snapshot ? 1 : 0,
    ]);
    closed(actual, [
      "identity",
      "daclSha256",
      "protectedParents",
      "sha256",
      "bytes",
      "slot",
    ]);
    requireObservation(
      hash(actual.sha256) &&
        (!sha256 || actual.sha256 === sha256) &&
        Number.isSafeInteger(actual.bytes) &&
        actual.bytes > 0 &&
        actual.bytes <= maximum &&
        actual.slot === 0,
    );
    const bytes = Buffer.alloc(actual.bytes);
    try {
      for (let offset = 0; offset < bytes.length; offset += 32768) {
        const count = Math.min(32768, bytes.length - offset),
          frame = await command("prepare-bytes", [actual.slot, offset, count]);
        closed(frame, ["hex"]);
        requireObservation(
          typeof frame.hex === "string" &&
            frame.hex.length === count * 2 &&
            /^[a-f0-9]+$/u.test(frame.hex),
        );
        Buffer.from(frame.hex, "hex").copy(bytes, offset);
      }
      requireObservation(digest(bytes) === actual.sha256);
    } finally {
      const released = await command("prepare-release", [actual.slot]);
      closed(released, ["closed"]);
      requireObservation(released.closed === true);
    }
    return {
      ...proof(actual),
      file,
      bytes,
      sha256: actual.sha256,
      unchanged: true,
      immutable: receipt,
    };
  };
  const readProtected = (request) => fileOperation(() => readFile(request));
  const api = {
    readProtected,
    // The approved package plan fixes slot 9. The native observer admits only
    // reads below that held System-only publication root.
    readPackage(operation, file, values = []) {
      requireObservation(
        ["hold", "read", "observe", "directory"].includes(operation) &&
          location(file),
      );
      return command("prepare-package-file", [
        operation,
        encode(file),
        ...values,
      ]);
    },
    closePackage() {
      return command("prepare-package-close", []);
    },
    verifyPackageArchive() {
      return command("prepare-package-archive", []);
    },
    async readReceipts(names) {
      requireObservation(
        Array.isArray(names) &&
          names.length > 0 &&
          names.length <= 16 &&
          new Set(names).size === names.length &&
          names.every((name) => /^windows-[a-z0-9.-]+\.json$/u.test(name)),
      );
      return fileOperation(async () => {
        const batch = await command("prepare-batch", names.map(encode));
        closed(batch, ["records", "deferred"]);
        requireObservation(
          Array.isArray(batch.records) && Array.isArray(batch.deferred),
        );
        const selected = new Map();
        for (const record of batch.records) {
          closed(record, [
            "nameHex",
            "identity",
            "daclSha256",
            "protectedParents",
            "sha256",
            "hex",
          ]);
          const name = decode(record.nameHex),
            bytes = Buffer.from(record.hex, "hex");
          requireObservation(
            names.includes(name) &&
              !selected.has(name) &&
              /^(?:[a-f0-9]{2}){1,60000}$/u.test(record.hex) &&
              digest(bytes) === record.sha256,
          );
          proof(record);
          selected.set(name, bytes);
        }
        for (const encoded of batch.deferred) {
          const name = decode(encoded);
          requireObservation(names.includes(name) && !selected.has(name));
          const result = await readFile({
            file: path.join(directory, name),
            maximum: 1048576,
            receipt: true,
          });
          selected.set(name, result.bytes);
        }
        requireObservation(selected.size === names.length);
        return names.map((name) => selected.get(name));
      });
    },
    async readBuildDirectory(file) {
      requireObservation(file === output);
      const actual = await command("prepare-directory", [encode(file), 0]);
      closed(actual, ["identity", "daclSha256", "protectedParents"]);
      return { ...actual, ...proof(actual) };
    },
    readdir(selected) {
      return fileOperation(async () => {
        requireObservation(selected === directory);
        const names = [];
        for (let offset = 0; ;) {
          const page = await command("prepare-list", [offset]);
          closed(page, ["names", "complete"]);
          requireObservation(
            Array.isArray(page.names) &&
              page.names.length <= 128 &&
              typeof page.complete === "boolean",
          );
          for (const name of page.names) {
            const leaf = decode(name);
            requireObservation(/^windows-[a-z0-9.-]+\.json$/u.test(leaf));
            names.push(leaf);
          }
          requireObservation(
            names.length <= maximumReceipts &&
              new Set(names).size === names.length,
          );
          if (page.complete) return names;
          requireObservation(page.names.length === 128);
          offset = names.length;
        }
      });
    },
    readIntermediate: async (file, pin) => {
      requireObservation(
        input.manifest.helpers.some(
          ({ name }) => file === path.join(output, name + ".exe"),
        ),
      );
      return (await readProtected({ file, sha256: pin, snapshot: true })).bytes;
    },
    async verifyDirectory({ directory: selected, context }) {
      requireObservation(
        selected === directory &&
          context.candidateSha === input.job.candidateSha,
      );
      const actual = await command("prepare-directory", [encode(directory), 0]);
      closed(actual, ["identity", "daclSha256", "protectedParents"]);
      return {
        ...proof(actual),
        directory,
        candidateSha: input.job.candidateSha,
        exclusiveWriter: true,
      };
    },
    async provisionBuild({ output: selected }) {
      requireObservation(selected === output);
      const actual = await command("prepare-directory", [encode(output), 1]);
      closed(actual, ["identity", "daclSha256", "protectedParents"]);
      return {
        ...proof(actual),
        output,
      };
    },
    writeProtected({ file, bytes, exclusive }) {
      return fileOperation(async () => {
        requireObservation(
          exclusive === true &&
            path.dirname(file) === directory &&
            /^windows-[a-z0-9.-]+\.json$/u.test(path.basename(file)) &&
            Buffer.isBuffer(bytes) &&
            bytes.length > 0 &&
            bytes.length <= 1048576,
        );
        const created = await command("prepare-write", [
          encode(path.basename(file)),
          bytes.length,
          digest(bytes),
        ]);
        closed(created, ["created"]);
        requireObservation(created.created === true);
        for (let offset = 0; offset < bytes.length; offset += 32768) {
          const chunk = bytes.subarray(offset, offset + 32768),
            written = await command("prepare-chunk", [
              offset,
              chunk.toString("hex"),
            ]);
          closed(written, ["written"]);
          requireObservation(written.written === chunk.length);
        }
        const sealed = await command("prepare-seal");
        closed(sealed, ["sha256", "writerClosed"]);
        requireObservation(
          sealed.sha256 === digest(bytes) && sealed.writerClosed === true,
        );
        const actual = await readFile({
          file,
          sha256: digest(bytes),
          maximum: 1048576,
          receipt: true,
        });
        return { ...actual, exclusive: true, writerClosed: true };
      });
    },
    verification: native,
    caseOwners,
    get admissionClosed() {
      return admissionClosed;
    },
    fenceAdmission() {
      admissionClosed = true;
    },
    async assertAdmission() {
      requireObservation(!admissionClosed);
      if (admissionChecked) return;
      const names = await api.readdir(directory);
      requireObservation(!admissionClosed);
      if (
        names.some((name) =>
          /^windows-recovery-[a-f0-9]{64}-[0-9]+-intent\.json$/u.test(name),
        )
      ) {
        admissionClosed = true;
        await api.settleFiles();
        requireObservation(false);
      }
      admissionChecked = true;
    },
    retainReader(reader, signal) {
      readers.set(reader, signal);
    },
    releaseReader(reader) {
      readers.delete(reader);
    },
    beginVerification(signal) {
      requireObservation(
        readers.size === 0 &&
          (signal === undefined || signal instanceof AbortSignal),
      );
      // Preparation's signal ends with that phase. Rejoin the original owner
      // under verification's signal without resetting its deadline or failure.
      guard(signal);
      if (signal !== undefined) workSignal = signal;
    },
    async beginCleanup(signal) {
      requireObservation(signal instanceof AbortSignal && !signal.aborted);
      workSignal = signal;
      let failure;
      for (const [reader, prior] of readers)
        if (!prior || prior.aborted) {
          try {
            await reader.beginCleanup({ signal });
            readers.set(reader, signal);
          } catch (cause) {
            failure ??= cause;
          }
        }
      if (failure) throw failure;
    },
    async retireReaders() {
      let failure;
      for (const reader of readers.keys()) {
        try {
          const result = await reader.close();
          requireObservation(
            result.status === "RETIRED" &&
              result.independent === true &&
              result.taskRemoved === true,
          );
          readers.delete(reader);
        } catch (cause) {
          failure ??= cause;
        }
      }
      if (failure) throw failure;
    },
    async verify(name, ...args) {
      return (await observer())[name](...args);
    },
    async settleFiles() {
      if (!starting) return null;
      guard();
      await fileSerial;
      requireObservation(readers.size === 0);
      const value = await command("finish");
      closed(value, ["closed"]);
      requireObservation(value.closed === true);
      const final = await owner.receive();
      closed(final, [
        "phase",
        "taskSha256",
        "taskRemoved",
        "helperRetired",
        "helper",
        "observations",
      ]);
      const exit = await owner.completion;
      requireObservation(
        final.phase === "retired" &&
          final.taskSha256 === taskSha256 &&
          final.taskRemoved === true &&
          final.helperRetired === true &&
          final.observations === 2 &&
          sameWindowsIdentity(final.helper, identity) &&
          exit.code === 0 &&
          exit.signal === null,
      );
      closedOwner = true;
      owner.settle?.();
      return {
        status: "RETIRED",
        independent: true,
        noLiveMembers: true,
        taskRemoved: true,
        emergencyCleanup: false,
        nativeEventSha256: observationDigest({ final, bridge }),
      };
    },
  };
  return api;
}
