import { spawn } from "node:child_process";
import * as filesystem from "node:fs/promises";
import { win32 as path } from "node:path";

import { FIXED_SUBJECT, observationDigest } from "../index.js";
import {
  closed,
  dense,
  digest,
  hash,
  requireWindows,
  systemIdentity,
  normalizeWindowsIdentity,
  sameWindowsIdentity,
  inspectWindowsPe,
} from "./protocol.js";
import { normalizeWindowsFileIdentity } from "./files-protocol.js";
import {
  normalizeWindowsFileInput,
  windowsFileHelperArguments,
} from "./files.js";
import { buildWindowsPolicy, windowsPolicyHelperArguments } from "./policy.js";
import { WINDOWS_ACCESS_DENIALS } from "./access.js";
import { windowsObserverConfiguration } from "./observer.js";
import { assertWindowsWfpFilterRead } from "./wfp-reader.js";
import { windowsCompilerArguments, WINDOWS_BUILD_COMMAND_MS } from "./build.js";
import {
  normalizeWindowsGitInput,
  windowsFixedCommitArguments,
  windowsGitPolicyArguments,
} from "./git.js";

import { windowsCustodyChannel } from "./channel.js";
import { createWindowsCustodyVerifier } from "./custody-verifier.js";
import {
  integer,
  location,
  encode,
  decode,
  normalizeWindowsCustodyInput,
  fileObservation,
  processObservation,
  jobObservation,
  decodePlan,
  windowsVerificationArguments,
} from "./custody-protocol.js";

function transport(input) {
  requireWindows(
    process.platform === "win32" &&
      process.arch === "x64" &&
      process.env.CI === "true" &&
      process.env.GITHUB_ACTIONS === "true" &&
      /^win25(?:-vs2026)?$/u.test(process.env.ImageOS),
  );
  return windowsCustodyChannel(
    spawn(
      input.bridge.path,
      [
        "--entry",
        input.reader.path,
        input.reader.sha256,
        input.reader.signatureSha256,
        input.plan.path,
        input.plan.sha256,
        input.nonce,
        input.runnerSid,
      ],
      {
        cwd: path.dirname(input.bridge.path),
        env: { CI: "true", GITHUB_ACTIONS: "true", PATH: "C:\\nonexistent" },
        stdio: ["pipe", "pipe", "ignore"],
      },
    ),
  );
}
const retired = (value) =>
  value?.status === "RETIRED" &&
  value.independent === true &&
  value.emergencyCleanup === false &&
  hash(value.nativeEventSha256);

/** The independently reviewed bootstrap capability retains sealed native code
 * before exec. Node path bytes alone cannot prove Windows DACL protection. */
export function createWindowsCustodyReader(value, options = {}) {
  const input = normalizeWindowsCustodyInput(value),
    fs = options.fs ?? filesystem,
    verification = options.verificationReader
      ? createWindowsCustodyVerifier(options.verificationReader)
      : options;
  let owner,
    helper,
    bridge,
    verifier,
    taskSha256,
    started = false,
    opening = false,
    retiring = false,
    closing = false,
    failed = false,
    firstCause,
    signal,
    sequence = 0,
    receiptSequence = 0,
    serial = Promise.resolve(),
    auditOwned = false,
    auditRestoring = false,
    cleanup = false,
    admitted = false,
    restoration;
  const held = new Map(),
    processes = new Map(),
    jobs = new Set(),
    children = new Map();
  let plan;
  const guard = (finish = false) => {
    if (firstCause) throw firstCause;
    requireWindows(
      started &&
        owner &&
        (!retiring || finish) &&
        !closing &&
        !failed &&
        !signal?.aborted,
    );
  };
  const save = (phase, detail = {}) => {
    requireWindows(typeof options.persist === "function");
    return options.persist(
      structuredClone({
        context: input.context,
        nonce: input.nonce,
        sequence: receiptSequence++,
        phase,
        requestSha256: observationDigest(input),
        reviewSha256: input.reviewSha256,
        custody: phase === "retired" ? "RETIRED" : "POSSIBLE",
        ...detail,
      }),
    );
  };
  const observe = async (name, ...args) => {
    const action = serial.then(async () => {
      guard(name === "finish");
      const next = ++sequence;
      requireWindows(next <= 32768);
      await save(name, {
        commandSequence: next,
        argumentsSha256: observationDigest(args),
        ...(name.startsWith("verify-") ||
        name.startsWith("case-") ||
        name.startsWith("ownership-") ||
        name.startsWith("access-") ||
        /^(?:operation|file|git|release)-/u.test(name)
          ? { arguments: args }
          : {}),
      });
      guard(name === "finish");
      await owner.send([name, next, ...args].join(" ") + "\n");
      const message = await owner.receive();
      closed(message, ["sequence", "value"]);
      requireWindows(message.sequence === next);
      guard(name === "finish");
      return message.value;
    });
    serial = action.catch((error) => {
      firstCause ??= error;
      failed = true;
      owner?.close();
    });
    return action;
  };
  const verify = async (name, ...args) => {
    try {
      requireWindows(typeof verification[name] === "function");
      const pending = verification[name](
          structuredClone(args[0]),
          ...args.slice(1),
        ),
        result = await (owner?.wait ? owner.wait(pending) : pending);
      requireWindows(!failed && !signal?.aborted);
      return result;
    } catch (error) {
      failed = true;
      firstCause ??= error;
      owner?.close();
      throw error;
    }
  };
  const startHelper = async (kind, index, args, slots, request) => {
    const lane = kind === "observer" ? 1 : 0,
      privateCreator = ["build", "git"].includes(kind);
    requireWindows(
      !children.has(lane) &&
        held.has(index) &&
        dense(args, kind === "git-policy" ? 386 : 55).every(
          (value) => typeof value === "string" && value.length > 0,
        ) &&
        dense(slots, kind === "git-policy" ? 128 : 44).every((index) =>
          held.has(index),
        ) &&
        new Set(slots).size === slots.length,
    );
    const actual = await observe(
      "helper-start",
      kind,
      index,
      args.length,
      ...args.map(encode),
      slots.length,
      ...slots,
    );
    closed(actual, [
      "helper",
      "processDaclSha256",
      "threadDaclSha256",
      "inheritedHandleCount",
      "job",
      ...(privateCreator ? ["creatorDefaultDaclSha256"] : []),
      ...(kind === "file" ? ["fileRootDeleteSharing"] : []),
    ]);
    const child = systemIdentity(actual.helper);
    children.set(lane, child);
    requireWindows(
      child.pid !== helper.pid &&
        child.pid !== verifier.pid &&
        [...children].every(
          ([slot, identity]) => slot === lane || identity.pid !== child.pid,
        ),
    );
    const job = jobObservation(actual.job);
    requireWindows(
      hash(actual.processDaclSha256) &&
        hash(actual.threadDaclSha256) &&
        (!privateCreator || hash(actual.creatorDefaultDaclSha256)) &&
        (kind !== "file" || actual.fileRootDeleteSharing === true) &&
        actual.inheritedHandleCount === slots.length + 2 &&
        job.limitFlags === 0x2008 &&
        job.processLimit === (["build", "git"].includes(kind) ? 32 : 1) &&
        job.uiRestrictions === 255 &&
        job.members.length === 1 &&
        sameWindowsIdentity(job.members[0], child),
    );
    const transfer = {
        kind,
        args,
        request,
        image: plan[index],
        objects: slots.map((index) => ({ index, ...held.get(index) })),
      },
      transferSha256 = observationDigest(transfer);
    const proof = await verify(
      "verifyTransfer",
      {
        input,
        child,
        creator: helper,
        verifier,
        actual,
        transfer,
        transferSha256,
      },
      { signal },
    );
    requireWindows(
      proof.independent === true &&
        sameWindowsIdentity(proof.helper, child) &&
        sameWindowsIdentity(systemIdentity(proof.verifier), verifier) &&
        proof.explicitHandleList === true &&
        proof.inheritedHandleCount === slots.length + 2 &&
        proof.transferSha256 === transferSha256 &&
        proof.imageSha256 === plan[index].sha256 &&
        proof.signatureSha256 === plan[index].signatureSha256 &&
        proof.processDaclSha256 === actual.processDaclSha256 &&
        proof.threadDaclSha256 === actual.threadDaclSha256 &&
        (!privateCreator ||
          proof.creatorDefaultDaclSha256 === actual.creatorDefaultDaclSha256) &&
        (kind !== "file" || proof.fileRootDeleteSharing === true) &&
        proof.jobSha256 === observationDigest(job) &&
        hash(proof.nativeEventSha256),
    );
    await save("helper-admitted", {
      child,
      verifier,
      nativeEventSha256: proof.nativeEventSha256,
    });
    guard();
    const released = await observe("helper-release", lane);
    closed(released, ["released"]);
    requireWindows(released.released === true);
    const identity = child;
    let completed = false;
    const current = () =>
      requireWindows(
        !completed &&
          children.has(lane) &&
          sameWindowsIdentity(children.get(lane), identity),
      );
    return {
      identity: structuredClone(identity),
      receive: async (size = 16384) => {
        current();
        requireWindows(integer(size, 16384) && size > 0);
        const frame = await (kind === "observer"
          ? observe("helper-bytes", lane, size)
          : observe("helper-read", lane));
        closed(frame, ["hex"]);
        requireWindows(
          /^(?:[a-f0-9]{2}){1,16384}$/u.test(frame.hex) &&
            frame.hex.length <= size * 2,
        );
        if (kind === "observer") return Buffer.from(frame.hex, "hex");
        return JSON.parse(
          new TextDecoder("utf-8", { fatal: true }).decode(
            Buffer.from(frame.hex, "hex"),
          ),
        );
      },
      send: async (bytes) => {
        current();
        requireWindows(
          typeof bytes === "string" &&
            Buffer.byteLength(bytes) > 0 &&
            Buffer.byteLength(bytes) <= 16384,
        );
        const sent = await observe(
          "helper-send",
          lane,
          Buffer.from(bytes).toString("hex"),
        );
        closed(sent, ["sent"]);
        requireWindows(sent.sent === true);
      },
      closeInput: async () => {
        current();
        const result = await observe("helper-close-input", lane);
        closed(result, ["closed"]);
        requireWindows(result.closed === true);
      },
      close: async () => {
        current();
        const proof = await verify("verifyHelperRetirement", child, { signal });
        requireWindows(
          retired(proof) &&
            sameWindowsIdentity(proof.helper, child) &&
            sameWindowsIdentity(systemIdentity(proof.verifier), verifier),
        );
        await save("helper-retired", {
          child,
          nativeEventSha256: proof.nativeEventSha256,
        });
        const result = await observe("helper-finish", lane);
        closed(result, ["retired", "members", "drained", "exitCode"]);
        requireWindows(
          result.retired === true &&
            result.members === 0 &&
            result.drained === true &&
            (result.exitCode === 0 ||
              (result.exitCode === 126 &&
                (kind === "file" ||
                  (cleanup && input.context.executionId.startsWith("git."))))),
        );
        children.delete(lane);
        completed = true;
        return {
          ...proof,
          closed: true,
          drained: result.drained,
          exitCode: result.exitCode,
        };
      },
    };
  };
  const openHelper = async (
    kind,
    index,
    args,
    slots,
    request,
    removing = false,
  ) => {
    guard();
    requireWindows(
      !opening &&
        !children.has(kind === "observer" ? 1 : 0) &&
        !auditRestoring &&
        (!cleanup ||
          (removing &&
            restoration &&
            ["policy", "git-policy"].includes(kind)) ||
          (kind === "file" && input.context.executionId.startsWith("files."))),
    );
    opening = true;
    try {
      if (cleanup && kind === "file") {
        const actual = await observe("operation-retirement");
        requireWindows(
          actual.admissionsClosed &&
            actual.noLiveMembers &&
            actual.helpersSettled,
        );
        await save("file-recovery-helper-possible", { request, actual });
      } else if (cleanup) {
        const observations = {
          input,
          helper,
          verifier,
          retirement: restoration,
          kind,
          request,
          image: plan[index],
          objects: slots.map((slot) => ({ slot, ...held.get(slot) })),
        };
        const state = input.context.executionId.startsWith("access.")
          ? await observe("access-state", verifier.pid, verifier.creationTime)
          : null;
        const proof = await verify(
          "verifyRestoration",
          {
            ...observations,
            ...(state
              ? {
                  custody: 2,
                  contextSha256: observationDigest(input.context),
                  hex: state.hex,
                }
              : {}),
          },
          {
            signal,
          },
        );
        requireWindows(
          proof?.independent === true &&
            proof.noLiveMembers === true &&
            proof.unchangedInstalled === true &&
            proof.observationsSha256 === observationDigest(observations) &&
            sameWindowsIdentity(systemIdentity(proof.verifier), verifier) &&
            hash(proof.nativeEventSha256),
        );
        await save("restore-helper-possible", {
          request,
          retirementSha256: observationDigest(restoration),
          nativeEventSha256: proof.nativeEventSha256,
        });
        guard();
      }
      return await startHelper(kind, index, args, slots, request);
    } catch (error) {
      // A malformed acknowledgement can follow native creation, before a
      // usable child identity exists. Preserve the possible helper intent.
      failed = true;
      owner?.close();
      throw error;
    } finally {
      opening = false;
    }
  };
  return {
    verification: Object.freeze({
      get input() {
        return structuredClone(input);
      },
      get identity() {
        guard();
        return structuredClone(helper);
      },
      command(name, args) {
        return observe(
          "verify-" + name,
          ...windowsVerificationArguments(name, args),
        );
      },
      record(phase, detail) {
        guard();
        requireWindows(
          ["prerequisite-bound", "prerequisite-settled"].includes(phase),
        );
        closed(
          detail,
          phase === "prerequisite-bound"
            ? ["request", "binding"]
            : ["intent", "birthPin", "settlement"],
        );
        return save("verify-" + phase, detail);
      },
    }),
    async beginCleanup({ signal: finish }) {
      await serial;
      requireWindows(
        started &&
          owner &&
          !failed &&
          !closing &&
          !opening &&
          !cleanup &&
          (!signal || signal.aborted) &&
          finish instanceof AbortSignal &&
          !finish.aborted,
      );
      await save("cleanup", { admission: "CLOSED" });
      requireWindows(!finish.aborted);
      cleanup = true;
      signal = finish;
      finish.addEventListener(
        "abort",
        () => {
          if (!closing) {
            failed = true;
            owner?.close();
          }
        },
        { once: true },
      );
    },
    async authorizeRestoration(retirement) {
      guard();
      requireWindows(
        cleanup &&
          children.size === 0 &&
          !opening &&
          !restoration &&
          retired(retirement) &&
          retirement.candidateSha === input.context.candidateSha &&
          retirement.nonce === input.nonce &&
          retirement.noLiveMembers === true,
      );
      for (const [index, identity] of processes) {
        const actual = processObservation(await observe("process", index));
        requireWindows(
          actual.retired === true &&
            sameWindowsIdentity(actual.identity, identity),
        );
      }
      for (const index of jobs)
        requireWindows(
          jobObservation(await observe("job", index)).members.length === 0,
        );
      await save("restoration-authorized", { retirement });
      guard();
      restoration = structuredClone(retirement);
    },
    async start({ signal: work } = {}) {
      requireWindows(!started && !work?.aborted);
      started = true;
      signal = work;
      await save("task-possible", {
        taskName: "\\NativeProof-Custody-" + input.nonce,
      });
      try {
        const seal = await verify("verifyBootstrap", structuredClone(input), {
          signal,
        });
        closed(seal, [
          "independent",
          "held",
          "protectedDacl",
          "protectedParents",
          "reviewSha256",
          "sdkSha256",
          "buildSha256",
          "entries",
          "nativeEventSha256",
        ]);
        requireWindows(
          seal.independent === true &&
            seal.held === true &&
            seal.protectedDacl === true &&
            seal.protectedParents === true &&
            seal.reviewSha256 === input.reviewSha256 &&
            seal.sdkSha256 === input.sdkSha256 &&
            seal.buildSha256 === input.buildSha256 &&
            hash(seal.nativeEventSha256),
        );
        const sealed = [
            input.bridge,
            input.reader,
            input.plan,
            ...input.sources,
          ],
          observed = dense(seal.entries, 8);
        requireWindows(observed.length === sealed.length);
        for (const [index, entry] of sealed.entries()) {
          const actual = observed[index];
          closed(actual, [
            "path",
            "sha256",
            "signatureSha256",
            "identity",
            "daclSha256",
          ]);
          normalizeWindowsFileIdentity(actual.identity);
          requireWindows(
            actual.path === entry.path &&
              actual.sha256 === entry.sha256 &&
              actual.signatureSha256 === (entry.signatureSha256 ?? null) &&
              hash(actual.daclSha256),
          );
          const bytes = await (options.read ?? ((file) => fs.readFile(file)))(
            entry.path,
          );
          requireWindows(
            Buffer.isBuffer(bytes) &&
              bytes.length > 0 &&
              bytes.length <= 134217728 &&
              digest(bytes) === entry.sha256,
          );
          if (entry.signatureSha256) inspectWindowsPe(bytes);
          if (entry === input.plan) plan = decodePlan(bytes, input);
        }
        requireWindows(!signal?.aborted);
        owner = await (options.open ?? transport)(structuredClone(input));
        signal?.addEventListener(
          "abort",
          () => {
            if (!admitted) {
              failed = true;
              owner.close();
            }
          },
          { once: true },
        );
        requireWindows(!signal?.aborted);
        const intent = await owner.receive();
        closed(intent, ["phase", "taskSha256", "bridge"]);
        bridge = normalizeWindowsIdentity(intent.bridge);
        requireWindows(
          intent.phase === "task-intent" &&
            hash(intent.taskSha256) &&
            bridge.pid === owner.pid &&
            bridge.userSid === input.runnerSid,
        );
        await save("task-register-possible", {
          bridge,
          taskSha256: intent.taskSha256,
        });
        requireWindows(!signal?.aborted);
        await owner.send("T");
        const registered = await owner.receive();
        closed(registered, ["phase", "taskSha256"]);
        requireWindows(
          registered.phase === "task-registered" && hash(registered.taskSha256),
        );
        taskSha256 = registered.taskSha256;
        await save("task-run-possible", { bridge, taskSha256 });
        requireWindows(!signal?.aborted);
        await owner.send("B");
        const entry = await owner.receive();
        closed(entry, ["phase", "helper", "bridge", "processDaclSha256"]);
        helper = systemIdentity(entry.helper);
        requireWindows(
          entry.phase === "entry" &&
            hash(entry.processDaclSha256) &&
            sameWindowsIdentity(entry.bridge, bridge),
        );
        const native = await owner.receive();
        closed(native, ["helper", "peer"]);
        requireWindows(
          sameWindowsIdentity(native.helper, helper) &&
            sameWindowsIdentity(native.peer, bridge),
        );
        const admission = await verify(
          "verifyAdmission",
          {
            input,
            helper,
            bridge,
            taskSha256,
            processDaclSha256: entry.processDaclSha256,
          },
          { signal },
        );
        verifier = systemIdentity(admission.verifier);
        requireWindows(
          admission.independent === true &&
            verifier.pid !== helper.pid &&
            admission.planSha256 === input.plan.sha256 &&
            admission.taskSha256 === taskSha256 &&
            admission.imageSha256 === input.reader.sha256 &&
            admission.signatureSha256 === input.reader.signatureSha256 &&
            admission.processDaclSha256 === entry.processDaclSha256 &&
            sameWindowsIdentity(admission.helper, helper) &&
            hash(admission.nativeEventSha256),
        );
        await save("admitted", {
          helper: structuredClone(helper),
          verifier: structuredClone(verifier),
          taskSha256,
          nativeEventSha256: admission.nativeEventSha256,
        });
        requireWindows(!signal?.aborted);
        await owner.send("P\n");
        const setup = await owner.receive();
        closed(setup, ["candidateSha", "nonce", "entries"]);
        requireWindows(
          setup.candidateSha === input.context.candidateSha &&
            setup.nonce === input.nonce &&
            setup.entries === plan.length,
        );
        admitted = true;
        return {
          helper: structuredClone(helper),
          verifier: structuredClone(verifier),
          planSha256: input.plan.sha256,
          entries: setup.entries,
          independent: true,
        };
      } catch (error) {
        failed = true;
        owner?.close();
        try {
          await save("uncertain", {
            helper: helper ?? null,
            verifier: verifier ?? null,
            taskSha256: taskSha256 ?? null,
          });
        } catch {
          // The persisted intent remains possible; preserve the first failure.
        }
        throw error;
      }
    },
    async provisionCaseDirectory(index, parent) {
      requireWindows(
        !cleanup &&
          integer(index) &&
          plan?.[index]?.kind === "directory" &&
          !held.has(index) &&
          held.has(parent),
      );
      const actual = fileObservation(
        await observe("case-directory", index, parent),
      );
      requireWindows(
        decode(actual.pathHex) === plan[index].path && actual.directory,
      );
      held.set(index, actual);
      return actual;
    },
    async copyCaseAsset(index, source, parent) {
      requireWindows(
        !cleanup &&
          integer(index) &&
          plan?.[index] &&
          !held.has(index) &&
          held.has(source) &&
          held.has(parent),
      );
      const actual = fileObservation(
        await observe("case-copy", index, source, parent),
      );
      requireWindows(
        decode(actual.pathHex) === plan[index].path && !actual.directory,
      );
      held.set(index, actual);
      return actual;
    },
    async provisionCaseFile(index, parent, bytes, mutable = false) {
      requireWindows(
        !cleanup &&
          integer(index) &&
          plan?.[index]?.kind === (mutable ? "mutable" : "data") &&
          !held.has(index) &&
          held.has(parent) &&
          Buffer.isBuffer(bytes) &&
          bytes.length > 0 &&
          bytes.length <= 4096 &&
          digest(bytes) === plan[index].sha256 &&
          typeof mutable === "boolean",
      );
      await save("case-file-possible", {
        index,
        parent,
        sha256: digest(bytes),
        mutable,
      });
      const actual = fileObservation(
        await observe(
          "case-file",
          index,
          parent,
          mutable ? 1 : 0,
          bytes.toString("hex"),
        ),
      );
      requireWindows(
        decode(actual.pathHex) === plan[index].path && !actual.directory,
      );
      held.set(index, actual);
      return actual;
    },
    async provisionCaseAccount(custody, contextSha256) {
      requireWindows(
        !cleanup &&
          held.has(custody) &&
          contextSha256 === observationDigest(input.context),
      );
      const actual = await observe("case-account", custody, contextSha256);
      closed(actual, [
        "accountSid",
        "restrictingSid",
        "contextSha256",
        "tokenHandle",
      ]);
      requireWindows(
        actual.contextSha256 === contextSha256 &&
          /^[1-9][0-9]{0,19}$/u.test(actual.tokenHandle),
      );
      await save("case-account-acknowledged", { actual });
      return actual;
    },
    async provisionCaseEndpoint({ family, protocol, port }) {
      requireWindows(
        !cleanup &&
          ["v4", "v6"].includes(family) &&
          ["tcp", "udp"].includes(protocol) &&
          integer(port, 65535) &&
          port >= 1024,
      );
      const actual = await observe("case-endpoint", family, protocol, port);
      closed(actual, ["bound"]);
      requireWindows(actual.bound === true);
    },
    readCase: () => observe("case-read"),
    async sendAccessCommand(operation, args) {
      requireWindows(
        !cleanup &&
          input.context.executionId.startsWith("access.") &&
          [
            "read",
            "write",
            "delete",
            "replace",
            "rename",
            "registry",
            "host-pipe",
            "alpc",
            "rpc",
            "com",
            "wmi",
            "delegation",
            "network",
            "socket",
            "pair",
            "socket-info",
            "file-root",
          ].includes(operation) &&
          dense(args, 8).every(
            (value) =>
              typeof value === "string" &&
              value.length > 0 &&
              value.length <= 4096,
          ),
      );
      const bytes = [operation, ...args].map(encode).join(" ") + "\n";
      requireWindows(Buffer.byteLength(bytes) <= 32768);
      requireWindows(
        (await observe("ownership-send", Buffer.from(bytes).toString("hex")))
          .sent === true,
      );
    },
    async transferAccessFileRoots() {
      requireWindows(
        !cleanup &&
          input.context.executionId.startsWith("access.") &&
          held.get(1)?.directory,
      );
      const roots = [];
      for (let index = 0; index < 2; index++) {
        requireWindows(held.get(index + 1)?.directory);
        const actual = await observe("access-transfer-root", index);
        closed(actual, ["handle"]);
        requireWindows(/^[1-9][0-9]{0,19}$/u.test(actual.handle));
        await this.sendAccessCommand("file-root", [
          String(index),
          actual.handle,
          plan[index + 1].path,
        ]);
        const result = JSON.parse(await this.ownershipOutput());
        closed(result, ["nonce", "operation", "phase", "index", "handle"]);
        requireWindows(
          result.nonce === input.nonce &&
            result.operation === "file-root" &&
            result.phase === "retained" &&
            result.index === index &&
            result.handle === actual.handle,
        );
        roots.push(actual);
      }
      return roots;
    },
    async transferAccessSockets() {
      requireWindows(
        !cleanup && input.context.executionId.startsWith("access."),
      );
      for (let index = 0; index < 8; index++) {
        const info = await observe("access-transfer-socket", index);
        closed(info, ["hex"]);
        requireWindows(/^(?:[a-f0-9]{2}){1,1024}$/u.test(info.hex));
        await this.sendAccessCommand("socket", [String(index), info.hex]);
        const result = JSON.parse(await this.ownershipOutput());
        closed(result, ["nonce", "operation", "phase", "index", "handle"]);
        requireWindows(
          result.nonce === input.nonce &&
            result.operation === "socket" &&
            result.phase === "retained" &&
            result.index === index &&
            /^[1-9][0-9]{0,19}$/u.test(result.handle),
        );
        const registered = await observe(
          "access-register-socket",
          index,
          result.handle,
        );
        closed(registered, ["registered"]);
        requireWindows(registered.registered === true);
      }
    },
    async verifyAccessFilters(value) {
      const policy = buildWindowsPolicy(value),
        inventory = await this.wfpInventory();
      requireWindows(
        value.request.nonce === input.nonce &&
          policy.manifest.filters.length === 52,
      );
      for (const descriptor of policy.manifest.filters) {
        requireWindows(inventory.includes(descriptor.key));
        assertWindowsWfpFilterRead(
          await this.wfp("filter", descriptor.key),
          descriptor,
          policy,
        );
      }
      return true;
    },
    async prepareAccessControls() {
      const actual = await observe("access-controls");
      closed(actual, ["ready"]);
      requireWindows(actual.ready === true);
      return actual;
    },
    async startAccessPeers(beforeRelease) {
      requireWindows(!cleanup && typeof beforeRelease === "function");
      const parked = await observe("access-peers-park", verifier.pid);
      closed(parked, ["privatePeer", "otherPeer"]);
      normalizeWindowsIdentity(parked.privatePeer);
      normalizeWindowsIdentity(parked.otherPeer);
      requireWindows(
        parked.privatePeer.userSid !== parked.otherPeer.userSid &&
          parked.privatePeer.pid !== parked.otherPeer.pid,
      );
      for (const [index, identity] of [
        parked.privatePeer,
        parked.otherPeer,
      ].entries()) {
        const state = await observe("access-peer-state", index);
        closed(state, ["hex"]);
        const proof = await verify(
          "verifyAccessPeerPolicy",
          {
            input,
            helper,
            identity,
            custody: 2,
            image: plan[6],
            hex: state.hex,
          },
          { signal },
        );
        requireWindows(
          proof.independent &&
            sameWindowsIdentity(systemIdentity(proof.verifier), verifier),
        );
      }
      await beforeRelease(structuredClone(parked));
      const actual = await observe("access-peers", verifier.pid);
      requireWindows(observationDigest(actual) === observationDigest(parked));
      return actual;
    },
    async accessControl(id, subject) {
      requireWindows(!cleanup && WINDOWS_ACCESS_DENIALS.includes(id));
      const raw = await observe("access-control", id, verifier.pid);
      closed(raw, ["hex"]);
      const proof = await verify(
        "verifyAccessControl",
        { input, helper, custody: 2, id, hex: raw.hex },
        { signal },
      );
      requireWindows(
        proof.independent &&
          sameWindowsIdentity(systemIdentity(proof.verifier), verifier),
      );
      const actual = proof.actual,
        endpoint = actual.endpoint
          ? { ...actual.endpoint, identityVerified: true }
          : null;
      const registry = actual.kind === 2 ? await this.registry(subject) : null;
      return {
        independent: true,
        verifier,
        nativeEventSha256: proof.nativeEventSha256,
        nonce: input.nonce,
        timedOut: false,
        lossCount: 0,
        identityVerified: true,
        ready: true,
        reachable: true,
        bytes: input.nonce,
        identity: id.startsWith("foreign-sender-")
          ? endpoint.identity
          : id.startsWith("cross-allocation-")
            ? endpoint.identity
            : actual.controller,
        target: decode(actual.targetHex),
        targetIdentitySha256: endpoint
          ? endpoint.socketIdentitySha256
          : registry
            ? observationDigest({
                nameHex: registry.nameHex,
                written: registry.written,
              })
            : actual.targetIdentitySha256,
        endpoint,
        denialCode: actual.denialCode,
        privatePeer: id.startsWith("foreign-sender-"),
        tokenReviewed: true,
        accountReservationVerified: true,
      };
    },
    async accessSocket(value) {
      const proof = await verify(
        "verifyAccessSocket",
        { input, ...value, contextSha256: observationDigest(input.context) },
        { signal },
      );
      requireWindows(
        proof.independent &&
          sameWindowsIdentity(systemIdentity(proof.verifier), verifier),
      );
      return proof;
    },
    async accessReservation(index) {
      requireWindows(integer(index, 7));
      const actual = await observe("access-reservation", index, verifier.pid);
      closed(actual, ["identity", "handle", "hex"]);
      return this.accessSocket(actual);
    },
    async accessPeerResult(index, identity) {
      const frame = await observe("access-peer-result", index);
      closed(frame, ["hex"]);
      const actual = JSON.parse(Buffer.from(frame.hex, "hex"));
      requireWindows(
        actual.nonce === input.nonce &&
          actual.operation === "serve" &&
          actual.phase === "served" &&
          actual.index === index * 2 + 1 &&
          actual.bytes === input.nonce &&
          actual.echo === input.nonce,
      );
      return {
        frame: actual,
        proof: await this.accessSocket({
          identity,
          handle: actual.handle,
          hex: actual.hex,
        }),
      };
    },
    accessForeign: (id) => observe("access-foreign", id, verifier.pid),
    async closeAccessForeign() {
      const result = await observe("access-foreign-close");
      closed(result, ["closed"]);
      requireWindows(result.closed === true);
    },
    async retireAccessControls() {
      const actual = await observe("access-controls-stop");
      closed(actual, ["fenced"]);
      requireWindows(actual.fenced);
      return actual;
    },
    async verifyAccessPeerRetirement(identity) {
      return verify(
        "verifyAccessPeerRetirement",
        { input, identity, custody: 2 },
        { signal },
      );
    },
    async drainAccessControls() {
      const actual = await observe("access-controls-drain");
      closed(actual, ["drained"]);
      requireWindows(actual.drained === true);
      return actual;
    },
    async armAccessFault(kind) {
      requireWindows(["owner-loss", "helper-loss"].includes(kind));
      const actual = await observe("access-fault-arm", encode(kind));
      const proof = await verify(
        "verifyAccessFault",
        { input, identity: actual.identity, signaled: false },
        { signal },
      );
      requireWindows(proof.independent);
      return { ...actual, nativeEventSha256: proof.nativeEventSha256 };
    },
    async fireAccessFault(kind) {
      requireWindows(["owner-loss", "helper-loss"].includes(kind));
      const actual = await observe("access-fault-fire", encode(kind));
      const proof = await verify(
        "verifyAccessFault",
        { input, identity: actual.identity, signaled: true },
        { signal },
      );
      requireWindows(proof.independent);
      return { ...actual, nativeEventSha256: proof.nativeEventSha256 };
    },
    async beginAccessPolicy(profile) {
      requireWindows(
        !cleanup &&
          ["read-only", "workspace-write", "trusted-command"].includes(profile),
      );
      const result = await observe("access-policy-begin", encode(profile));
      closed(result, ["possible"]);
      requireWindows(result.possible === true);
    },
    async acknowledgeAccessPolicy(bytes) {
      requireWindows(
        !cleanup &&
          Buffer.isBuffer(bytes) &&
          bytes.length > 0 &&
          bytes.length <= 32768,
      );
      const result = await observe(
        "access-policy-installed",
        bytes.toString("hex"),
      );
      closed(result, ["installed"]);
      requireWindows(result.installed === true);
    },
    async restoreAccessPolicy() {
      requireWindows(cleanup && !auditOwned && !children.size);
      const result = await observe("access-policy-restore");
      closed(result, ["restored"]);
      requireWindows(result.restored === true);
      return result;
    },
    async closeDomainJobs() {
      requireWindows(cleanup && !auditOwned && !children.size);
      for (const index of jobs)
        requireWindows((await this.inspectJob(index)).members.length === 0);
      const result = await observe("access-jobs-close");
      closed(result, ["closed"]);
      requireWindows(result.closed === true);
      jobs.clear();
    },
    async bindAccessInventory(objects) {
      requireWindows(
        !cleanup &&
          dense(objects, 44).length >= 11 &&
          objects.every((index) => held.has(index)) &&
          new Set(objects).size === objects.length,
      );
      const result = await observe("access-inventory", ...objects);
      closed(result, ["bound"]);
      requireWindows(result.bound === true);
    },
    async readAccessCoverage() {
      const state = await observe(
        "access-state",
        verifier.pid,
        verifier.creationTime,
      );
      closed(state, ["hex"]);
      requireWindows(
        typeof state.hex === "string" &&
          /^(?:[a-f0-9]{2}){1,32768}$/u.test(state.hex),
      );
      const proof = await verify(
        "verifyAccessCoverage",
        {
          input,
          helper,
          custody: 2,
          contextSha256: observationDigest(input.context),
          hex: state.hex,
        },
        { signal },
      );
      requireWindows(
        proof.independent === true &&
          sameWindowsIdentity(systemIdentity(proof.verifier), verifier) &&
          proof.nativeEventSha256 === observationDigest(proof.actual),
      );
      return proof;
    },
    async retireAccessHelper(lane) {
      requireWindows(
        cleanup &&
          input.context.executionId.startsWith("access.") &&
          [0, 1].includes(lane),
      );
      const child = children.get(lane);
      if (!child) return null;
      await save("access-helper-stop-possible", { lane, child });
      const stopped = await observe("helper-stop", lane);
      closed(stopped, ["stopped", "drained"]);
      requireWindows(stopped.stopped && stopped.drained);
      const proof = await verify("verifyHelperRetirement", child, { signal });
      requireWindows(
        retired(proof) &&
          sameWindowsIdentity(proof.helper, child) &&
          sameWindowsIdentity(systemIdentity(proof.verifier), verifier),
      );
      const result = await observe("helper-finish", lane);
      closed(result, ["retired", "members", "drained", "exitCode"]);
      requireWindows(
        result.retired &&
          result.members === 0 &&
          result.drained &&
          [0, 126].includes(result.exitCode),
      );
      children.delete(lane);
      await save("access-helper-retired", { lane, child, proof, result });
      return {
        ...proof,
        closed: true,
        drained: true,
        exitCode: result.exitCode,
      };
    },
    async readAccessReceipt(index, sha256) {
      requireWindows(integer(index, 4095) && hash(sha256));
      const proof = await verify(
        "readAccessReceipt",
        { input, custody: 2, index, sha256 },
        { signal },
      );
      requireWindows(
        proof.independent &&
          sameWindowsIdentity(systemIdentity(proof.verifier), verifier),
      );
      return Buffer.from(proof.actual.hex, "hex");
    },
    async startOwnership(args) {
      requireWindows(!cleanup && args.length >= 2 && args.length <= 64);
      const value = await observe(
        "ownership-launch",
        args.length,
        ...args.map((value) => (value === "" ? "-" : encode(value))),
      );
      closed(value, ["helper", "owner"]);
      const helper = systemIdentity(value.helper),
        owner = systemIdentity(value.owner);
      requireWindows(helper.pid !== owner.pid);
      return { helper, owner };
    },
    async ownershipControl() {
      const actual = await observe("ownership-control");
      closed(actual, ["hex"]);
      requireWindows(
        typeof actual.hex === "string" &&
          /^(?:[a-f0-9]{2})+$/u.test(actual.hex) &&
          actual.hex.length <= 32768,
      );
      return JSON.parse(
        new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
          Buffer.from(actual.hex, "hex"),
        ),
      );
    },
    async ownershipOutput() {
      const actual = await observe("ownership-output");
      closed(actual, ["hex"]);
      requireWindows(
        typeof actual.hex === "string" &&
          /^(?:[a-f0-9]{2})+$/u.test(actual.hex) &&
          actual.hex.length <= 32768,
      );
      return Buffer.from(actual.hex, "hex");
    },
    async sendOwnership(bytes) {
      requireWindows(
        typeof bytes === "string" && Buffer.byteLength(bytes) <= 128,
      );
      requireWindows(
        (await observe("ownership-send", Buffer.from(bytes).toString("hex")))
          .sent === true,
      );
    },
    async retainOwnershipChildren(values) {
      for (const value of dense(values, 32)) {
        requireWindows(
          integer(value.pid, 0xffffffff) &&
            value.pid > 0 &&
            /^[1-9][0-9]{0,19}$/u.test(value.creationTime),
        );
        requireWindows(
          (await observe("ownership-retain", value.pid, value.creationTime))
            .retained === true,
        );
      }
    },
    ownershipWitness: () => observe("ownership-witness"),
    reconstructOwnership: () => observe("ownership-reconstruct"),
    ownershipOutside: () => observe("ownership-outside"),
    ownershipOutsideControl: (mode) =>
      observe("ownership-outside-control", encode(mode)),
    ownershipStale: (value) =>
      observe("ownership-stale", value.pid, value.creationTime),
    armOwnership: (mode) => observe("ownership-arm", encode(mode)),
    fireOwnership: (mode) => observe("ownership-fire", encode(mode)),
    ownershipStop: () => observe("ownership-stop"),
    async ownershipReceipt(index, sha256, bytes) {
      requireWindows(
        integer(index, 4095) &&
          hash(sha256) &&
          (!bytes ||
            (Buffer.isBuffer(bytes) &&
              bytes.length <= 16384 &&
              digest(bytes) === sha256)),
      );
      const value = await observe(
        "ownership-receipt",
        index,
        sha256,
        ...(bytes ? [bytes.toString("hex")] : []),
      );
      closed(value, ["hex"]);
      requireWindows(
        typeof value.hex === "string" &&
          /^(?:[a-f0-9]{2})+$/u.test(value.hex) &&
          value.hex.length <= 32768,
      );
      const actual = Buffer.from(value.hex, "hex");
      requireWindows(actual.length <= 16384 && digest(actual) === sha256);
      return actual;
    },
    async installOwnershipPolicy(bytes) {
      requireWindows(
        Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= 16384,
      );
      requireWindows(
        (await observe("ownership-policy", bytes.toString("hex"))).installed ===
          true,
      );
    },
    async restoreOwnershipPolicy() {
      requireWindows(
        cleanup && (await observe("ownership-restore")).restored === true,
      );
    },
    async retireOwnershipAccount() {
      requireWindows(
        cleanup && (await observe("ownership-account-retire")).retired === true,
      );
      return verify("verifyCaseRetirement", {
        input,
        custody: 2,
        contextSha256: observationDigest(input.context),
      });
    },
    verifyCaseProvisioning: (custody, actual) =>
      verify("verifyCaseProvisioning", {
        input,
        helper,
        custody,
        contextSha256: observationDigest(input.context),
        tokenHandle: actual.tokenHandle,
      }),
    async retireCase(custody) {
      requireWindows(cleanup && !children.size);
      const actual = await observe("case-retire");
      closed(actual, ["retired"]);
      requireWindows(actual.retired === true);
      const proof = await verify("verifyCaseRetirement", {
        input,
        custody,
        contextSha256: observationDigest(input.context),
      });
      requireWindows(retired(proof));
      return proof;
    },
    async open(index) {
      requireWindows(integer(index) && plan?.[index] && !held.has(index));
      const value = fileObservation(await observe("open", index));
      requireWindows(
        decode(value.pathHex) === plan[index].path &&
          value.directory === (plan[index].kind === "directory"),
      );
      held.set(index, value);
      return structuredClone(value);
    },
    async inspect(index) {
      requireWindows(held.has(index));
      const actual = fileObservation(await observe("inspect", index)),
        prior = held.get(index);
      requireWindows(
        actual.identity === prior.identity &&
          actual.pathHex === prior.pathHex &&
          actual.volumeHex === prior.volumeHex &&
          actual.filesystemHex === prior.filesystemHex &&
          actual.links === prior.links &&
          actual.directory === prior.directory,
      );
      return actual;
    },
    async read(index, offset, size) {
      requireWindows(
        held.has(index) &&
          integer(offset, 536870912) &&
          integer(size, 65536) &&
          size > 0 &&
          offset <= 536870912 - size,
      );
      const value = await observe("read", index, offset, size);
      closed(value, ["hex"]);
      requireWindows(
        typeof value.hex === "string" &&
          /^(?:[a-f0-9]{2})+$/u.test(value.hex) &&
          value.hex.length === size * 2,
      );
      return Buffer.from(value.hex, "hex");
    },
    async signature(index) {
      requireWindows(held.has(index) && plan[index].signatureSha256);
      const value = await observe("signature", index);
      closed(value, ["sha256"]);
      requireWindows(value.sha256 === plan[index].signatureSha256);
      return { ...value, independent: true };
    },
    async retainProcess(identity) {
      requireWindows(
        !auditRestoring &&
          (!cleanup || input.context.executionId.startsWith("files.")),
      );
      identity = normalizeWindowsIdentity(identity);
      const value = await observe("process-open", identity.pid);
      closed(value, ["slot", "observation"]);
      const actual = processObservation(value.observation);
      requireWindows(
        integer(value.slot, 31) &&
          !processes.has(value.slot) &&
          sameWindowsIdentity(actual.identity, identity),
      );
      processes.set(value.slot, identity);
      return { slot: value.slot, observation: actual, independent: true };
    },
    async process(index) {
      requireWindows(processes.has(index));
      const value = processObservation(await observe("process", index));
      requireWindows(sameWindowsIdentity(value.identity, processes.get(index)));
      return { ...value, independent: true };
    },
    async processImage(index, image) {
      requireWindows(
        processes.has(index) &&
          held.has(image) &&
          ["image", "helper"].includes(plan[image]?.kind),
      );
      const value = await observe("process-image", index, image);
      closed(value, ["identity", "sha256", "signatureSha256"]);
      requireWindows(
        sameWindowsIdentity(value.identity, processes.get(index)) &&
          value.sha256 === plan[image].sha256 &&
          value.signatureSha256 === plan[image].signatureSha256,
      );
      return { ...value, independent: true };
    },
    async verifier(identity) {
      identity = systemIdentity(identity);
      requireWindows(sameWindowsIdentity(identity, verifier));
      const actual = systemIdentity(
        await observe("verifier", identity.pid, identity.creationTime),
      );
      requireWindows(sameWindowsIdentity(actual, identity));
      return actual;
    },
    async job() {
      requireWindows(!auditRestoring && !cleanup);
      const value = await observe("job-open", 0);
      closed(value, ["slot", "observation"]);
      requireWindows(integer(value.slot, 31) && !jobs.has(value.slot));
      jobs.add(value.slot);
      return {
        slot: value.slot,
        observation: jobObservation(value.observation),
        independent: true,
      };
    },
    async inspectJob(index) {
      requireWindows(jobs.has(index));
      return {
        ...jobObservation(await observe("job", index)),
        independent: true,
      };
    },
    async loader(process, index) {
      requireWindows(
        processes.has(process) &&
          held.has(index) &&
          ["image", "helper"].includes(plan[index].kind),
      );
      const value = await observe("loader", process, index);
      closed(value, [
        "loaded",
        "imports",
        "linkerMajor",
        "linkerMinor",
        "timestamp",
        "complete",
      ]);
      requireWindows(
        value.complete === true &&
          dense(value.loaded, 128).length > 0 &&
          integer(value.linkerMajor, 255) &&
          integer(value.linkerMinor, 255) &&
          integer(value.timestamp, 0xffffffff),
      );
      for (const file of value.loaded) {
        closed(file, [
          "pathHex",
          "identity",
          "sha256",
          "signatureSha256",
          "daclSha256",
          "links",
        ]);
        requireWindows(
          location(decode(file.pathHex)) &&
            hash(file.sha256) &&
            hash(file.signatureSha256) &&
            hash(file.daclSha256) &&
            integer(file.links, 128) &&
            file.links > 0,
        );
        normalizeWindowsFileIdentity(file.identity);
      }
      for (const entry of dense(value.imports, 2048)) {
        closed(entry, ["source", "resolved", "delay", "importHex"]);
        requireWindows(
          integer(entry.source, value.loaded.length - 1) &&
            integer(entry.resolved, value.loaded.length - 1) &&
            typeof entry.delay === "boolean" &&
            /^(?:[a-f0-9]{2}){1,255}$/u.test(entry.importHex),
        );
      }
      requireWindows(
        value.loaded.some(
          (file) =>
            file.identity === held.get(index).identity &&
            file.sha256 === plan[index].sha256 &&
            file.signatureSha256 === plan[index].signatureSha256,
        ),
      );
      return {
        ...structuredClone(value),
        independent: true,
        nativeSha256: observationDigest(value),
      };
    },
    async buildBindings() {
      const value = await observe("build");
      closed(value, ["major", "minor", "build", "sdkRootHex"]);
      requireWindows(
        value.major === 10 &&
          value.minor === 0 &&
          value.build === 26100 &&
          location(decode(value.sdkRootHex).replace(/\\$/u, "")),
      );
      return {
        ...value,
        independent: true,
        nativeSha256: observationDigest(value),
      };
    },
    async effectiveToken(subject) {
      requireWindows(processes.has(subject));
      return observe("effective-token", subject);
    },
    async acl(subject, index) {
      requireWindows(processes.has(subject) && held.has(index));
      return observe("acl", subject, index);
    },
    async registry(subject) {
      requireWindows(processes.has(subject));
      return observe("registry", subject);
    },
    async wfp(kind, key) {
      requireWindows(
        ["provider", "sublayer", "filter"].includes(kind) &&
          /^[a-f0-9-]{36}$/u.test(key),
      );
      return observe(
        "wfp",
        ["provider", "sublayer", "filter"].indexOf(kind),
        key,
      );
    },
    async wfpInventory() {
      return observe("wfp-inventory");
    },
    async wfpGlobal(key) {
      requireWindows(/^[a-f0-9-]{36}$/u.test(key));
      return observe("wfp-global", key);
    },
    async barrier(index, name) {
      requireWindows(
        held.get(index)?.directory &&
          typeof name === "string" &&
          name.length < 2048 &&
          !/[\u0000-\u001f\u007f/:*?]/u.test(name) &&
          name.split("\\").every((part) => part && ![".", ".."].includes(part)),
      );
      return observe("barrier", index, encode(name));
    },
    async tree(index) {
      requireWindows(held.get(index)?.directory);
      return observe("tree", index);
    },
    async file(index) {
      requireWindows(held.has(index) && !held.get(index).directory);
      return observe("file", index);
    },
    async parents(index) {
      requireWindows(held.has(index));
      const values = dense(await observe("parents", index), 32).map(
        normalizeWindowsFileIdentity,
      );
      requireWindows(
        values.length > 0 && new Set(values).size === values.length,
      );
      return values;
    },
    async xml(bytes) {
      requireWindows(
        Buffer.isBuffer(bytes) &&
          bytes.length >= 4 &&
          bytes.length <= 65536 &&
          bytes.length % 2 === 0,
      );
      return observe("xml", bytes.toString("hex"));
    },
    async auditSnapshot(subject) {
      requireWindows(processes.has(subject));
      return observe("audit-snapshot", subject);
    },
    async installAudit(subject, objects, systemSha256) {
      guard();
      requireWindows(
        !auditOwned &&
          hash(systemSha256) &&
          processes.has(subject) &&
          dense(objects, 44).length > 0 &&
          objects.every((item) => {
            closed(item, ["index", "descriptorSha256"]);
            return held.has(item.index) && hash(item.descriptorSha256);
          }) &&
          new Set(objects.map((item) => item.index)).size === objects.length,
      );
      auditOwned = true; // An unreturned/partial setter retains the entire intent.
      const result = await observe(
        "audit-install",
        subject,
        systemSha256,
        objects.length,
        ...objects.flatMap((item) => [item.index, item.descriptorSha256]),
      );
      closed(result, ["installed", "objects"]);
      requireWindows(
        result.installed === true && result.objects === objects.length,
      );
      return result;
    },
    async restoreAudit() {
      guard();
      requireWindows(auditOwned && children.size === 0 && !opening);
      requireWindows(!auditRestoring);
      auditRestoring = true;
      try {
        let access = {};
        if (input.context.executionId.startsWith("access.")) {
          const state = await observe(
            "access-state",
            verifier.pid,
            verifier.creationTime,
          );
          closed(state, ["hex"]);
          access = {
            helper,
            custody: 2,
            contextSha256: observationDigest(input.context),
            hex: state.hex,
          };
        }
        const proof = await verify(
          "verifyAuditRetirement",
          {
            input,
            processes: [...processes.values()],
            jobs: [...jobs],
            ...access,
          },
          { signal },
        );
        requireWindows(
          retired(proof) &&
            proof.exclusiveWriter === true &&
            proof.admissionsClosed === true &&
            proof.candidateSha === input.context.candidateSha &&
            proof.nonce === input.nonce &&
            proof.noLiveMembers === true &&
            proof.noForeignCreators === true &&
            proof.noPrincipalFlows === true &&
            sameWindowsIdentity(systemIdentity(proof.verifier), verifier),
        );
        for (const [index, identity] of processes) {
          const actual = processObservation(await observe("process", index));
          requireWindows(
            actual.retired === true &&
              sameWindowsIdentity(actual.identity, identity),
          );
        }
        for (const index of jobs)
          requireWindows(
            jobObservation(await observe("job", index)).members.length === 0,
          );
        const result = await observe("audit-restore");
        closed(result, ["restored"]);
        requireWindows(result.restored === true);
        auditOwned = false;
        return { ...proof, restored: true };
      } catch (error) {
        failed = true;
        owner?.close();
        throw error;
      } finally {
        auditRestoring = false;
      }
    },
    async openObserver(value, index) {
      const configuration = windowsObserverConfiguration(value);
      requireWindows(
        auditOwned &&
          value.plan.candidateSha === input.context.candidateSha &&
          value.plan.nonce === input.nonce &&
          plan[index]?.kind === "helper" &&
          path.basename(plan[index].path) === "observer-helper.exe" &&
          plan[index].sha256 === value.pins.imageSha256 &&
          configuration.query.length <= 16384,
      );
      return openHelper(
        "observer",
        index,
        [input.nonce, configuration.query],
        [],
        value,
      );
    },
    async openBuild(request, operation, entry) {
      requireWindows(
        !cleanup &&
          request.platform === "win32" &&
          request.candidateSha === input.context.candidateSha &&
          held.has(entry.helper) &&
          held.has(entry.tool) &&
          plan[entry.helper]?.kind === "helper" &&
          path.basename(plan[entry.helper].path) === "build-helper.exe" &&
          plan[entry.tool]?.kind === "image" &&
          plan[entry.tool].path === request.file &&
          plan[entry.tool].sha256 === request.toolSha256 &&
          plan[entry.tool].signatureSha256 === entry.toolSignatureSha256,
      );
      const expected =
        operation.mode === "compiler-version"
          ? ["/Bv"]
          : operation.mode === "sdk-version"
            ? ["/?"]
            : windowsCompilerArguments(operation.source.path, operation.target);
      requireWindows(
        observationDigest(request.args) === observationDigest(expected) &&
          ["compile", "compiler-version", "sdk-version"].includes(
            operation.mode,
          ) &&
          location(request.cwd) &&
          Number.isSafeInteger(request.deadlineMs) &&
          request.deadlineMs > 0 &&
          request.deadlineMs <= WINDOWS_BUILD_COMMAND_MS,
      );
      closed(request.env, [
        "CI",
        "GITHUB_ACTIONS",
        "LANG",
        "INCLUDE",
        "LIB",
        "SystemRoot",
        "PATH",
      ]);
      requireWindows(
        request.env.CI === "true" &&
          request.env.GITHUB_ACTIONS === "true" &&
          request.env.LANG === "C",
      );
      if (operation.mode === "compile") {
        const source = plan.findIndex(
          (value) =>
            value.path === operation.source.path &&
            value.sha256 === operation.source.sha256 &&
            ["data", "sdk"].includes(value.kind),
        );
        requireWindows(
          source >= 0 &&
            held.has(source) &&
            location(operation.target) &&
            path.dirname(operation.target) === request.cwd,
        );
      }
      return openHelper(
        "build",
        entry.helper,
        [
          input.nonce,
          operation.mode,
          request.file,
          request.toolSha256,
          entry.toolSignatureSha256,
          operation.source?.path ?? "-",
          operation.source?.sha256 ?? "-",
          operation.target ?? "-",
          request.cwd,
          String(request.deadlineMs),
          ...["INCLUDE", "LIB", "SystemRoot", "PATH"].map(
            (name) => request.env[name],
          ),
        ],
        [],
        request,
      );
    },
    async publishBuild(request, operation, unsignedSha256, transfer) {
      guard();
      closed(transfer, ["image", "root"]);
      const image = plan[transfer.image],
        root = plan[transfer.root];
      requireWindows(
        children.size === 0 &&
          !cleanup &&
          input.context.executionId === "build" &&
          request.candidateSha === input.context.candidateSha &&
          operation.mode === "compile" &&
          hash(unsignedSha256) &&
          held.has(transfer.image) &&
          held.has(transfer.root) &&
          root?.kind === "directory" &&
          root.path === request.cwd &&
          path.dirname(operation.target) === root.path &&
          image?.kind === "helper" &&
          path.basename(image.path) === path.basename(operation.target) &&
          image.sha256 === operation.helper.sha256 &&
          observationDigest(request.args) ===
            observationDigest(
              windowsCompilerArguments(operation.source.path, operation.target),
            ),
      );
      const actual = await observe(
        "publish-build",
        transfer.root,
        encode(path.basename(operation.target)),
        unsignedSha256,
        transfer.image,
      );
      closed(actual, [
        "identity",
        "sha256",
        "signatureSha256",
        "daclSha256",
        "writerClosed",
      ]);
      normalizeWindowsFileIdentity(actual.identity);
      requireWindows(
        actual.sha256 === image.sha256 &&
          actual.signatureSha256 === image.signatureSha256 &&
          hash(actual.daclSha256) &&
          actual.writerClosed === true,
      );
      const observations = {
        input,
        request,
        operation,
        unsignedSha256,
        transfer,
        actual,
      };
      const proof = await verify("verifyPublication", observations, { signal });
      requireWindows(
        proof?.independent === true &&
          proof.observationsSha256 === observationDigest(observations) &&
          proof.protectedDacl === true &&
          proof.writerClosed === true &&
          sameWindowsIdentity(systemIdentity(proof.verifier), verifier) &&
          retired(proof.settlement) &&
          hash(proof.nativeEventSha256),
      );
      await save("build-published", {
        requestSha256: observationDigest(request),
        nativeEventSha256: proof.nativeEventSha256,
      });
      return {
        independent: true,
        requestSha256: observationDigest(request),
        unsignedSha256,
        sourceSha256: operation.source.sha256,
        imageSha256: actual.sha256,
        signatureSha256: actual.signatureSha256,
        protectedDacl: true,
        writerClosed: true,
        nativeEventSha256: proof.nativeEventSha256,
        settlement: proof.settlement,
      };
    },
    async openFile(value, transfer) {
      const file = normalizeWindowsFileInput(value);
      closed(transfer, ["helper", "root", "base"]);
      requireWindows(
        file.request.nonce === input.nonce &&
          file.request.candidateSha === input.context.candidateSha &&
          held.get(transfer.root)?.identity === file.root &&
          held.get(transfer.base)?.identity === file.base,
      );
      requireWindows(
        plan[transfer.helper]?.kind === "helper" &&
          path.basename(plan[transfer.helper].path) === "file-helper.exe" &&
          held.get(transfer.root).directory &&
          held.get(transfer.base).directory,
      );
      const image = plan[transfer.helper];
      requireWindows(
        image.path === file.request.executable.path &&
          image.sha256 === file.request.executable.sha256 &&
          image.signatureSha256 === file.request.executable.signatureSha256,
      );
      const channel = await openHelper(
        "file",
        transfer.helper,
        windowsFileHelperArguments(file, { root: "1", base: "2" }),
        [transfer.root, transfer.base],
        file,
      );
      const completion = Promise.withResolvers();
      completion.promise.catch(() => {});
      let closing;
      const close = () => {
        if (!closing) {
          closing = (async () => {
            await channel.closeInput();
            const result = await channel.close();
            completion.resolve({
              code: result.exitCode,
              signal: null,
              failed: false,
              partialBytes: 0,
              remainingMessages: 0,
            });
            return result;
          })();
          closing.catch(completion.reject);
        }
        return closing;
      };
      return {
        ...channel,
        helper: channel.identity,
        completion: completion.promise,
        close,
        dispose: () => {
          close();
        },
      };
    },
    async bindOperationInventory(id, slots) {
      requireWindows(
        /^(?:files\.(?:private|publish|replace|substitution|aliases|cleanup)|git\.(?:fixed|ordinary)|release)$/u.test(
          id,
        ),
      );
      const indices = id.startsWith("files.")
        ? [slots.base, slots.root, slots.outside, slots.alias, slots.foreign]
        : id.startsWith("git.")
          ? [
              slots.git,
              slots.metadata,
              slots.hooks,
              slots.outside,
              ...slots.policyObjects,
            ]
          : [];
      requireWindows(
        indices.every(
          (index) => Number.isSafeInteger(index) && held.has(index),
        ) && indices.length <= 126,
      );
      const result = await observe(
        "operation-bind",
        encode(id),
        indices.length,
        ...indices,
      );
      closed(result, ["bound"]);
      requireWindows(result.bound === true);
    },
    async operation(name, ...args) {
      requireWindows(
        [
          "operation-authority",
          "operation-fence",
          "operation-helper-retire",
          "operation-retirement",
          "operation-closed",
          "file-view",
          "file-private",
          "file-recovery-retirement",
          "file-workers-retire",
          "file-publishers-start",
          "file-publishers-finish",
          "file-reader-start",
          "file-reader-read",
          "file-reader-finish",
          "file-control",
          "file-control-read",
          "file-control-restore",
          "git-child",
          "git-child-retired",
          "git-ordinary",
          "git-policy-read",
          "git-policy-install",
          "git-policy-restore",
          "git-audit-install",
          "release-pe",
          "release-build",
          "release-close",
        ].includes(name) && args.length <= 128,
      );
      requireWindows(
        args.every(
          (arg) =>
            typeof arg === "string" ||
            (Number.isSafeInteger(arg) && arg >= 0 && arg <= 536870912),
        ),
      );
      return observe(
        name,
        ...args.map((arg) => (typeof arg === "string" ? encode(arg) : arg)),
      );
    },
    async openPolicy(value, operation, transfer) {
      const policy = buildWindowsPolicy(value);
      closed(transfer, ["helper", "objects"]);
      const objects = policy.manifest.objects.filter(
        (entry) => entry.name !== "registry",
      );
      requireWindows(
        policy.value.request.nonce === input.nonce &&
          policy.value.request.candidateSha === input.context.candidateSha &&
          dense(transfer.objects, 44).length === objects.length,
      );
      const handles = objects.map((entry, index) => {
        requireWindows(
          held.has(transfer.objects[index]) &&
            decode(held.get(transfer.objects[index]).pathHex).toLowerCase() ===
              entry.path.toLowerCase(),
        );
        return { path: entry.path, handle: String(index + 1) };
      });
      requireWindows(
        plan[transfer.helper]?.kind === "helper" &&
          path.basename(plan[transfer.helper].path) === "policy-helper.exe",
      );
      return openHelper(
        "policy",
        transfer.helper,
        windowsPolicyHelperArguments(value, operation, handles),
        transfer.objects,
        { value: policy.value, operation },
        operation.startsWith("remove"),
      );
    },
    async openGit(value, transfer) {
      const git = normalizeWindowsGitInput(value);
      closed(transfer, ["helper", "git", "metadata", "workspace", "hooks"]);
      const image = plan[transfer.helper];
      requireWindows(
        git.request.nonce === input.nonce &&
          git.request.candidateSha === input.context.candidateSha &&
          image?.kind === "helper" &&
          path.basename(image.path) === "git-fixture.exe" &&
          image.path === git.request.executable.path &&
          image.sha256 === git.request.executable.sha256 &&
          image.signatureSha256 === git.request.executable.signatureSha256,
      );
      for (const name of ["git", "metadata", "workspace", "hooks"]) {
        const index = transfer[name],
          expected =
            name === "workspace"
              ? git.request.workspace
              : name === "git"
                ? git.git.path
                : git[name];
        requireWindows(
          held.has(index) &&
            plan[index].path === expected &&
            (name === "git"
              ? plan[index].kind === "image" &&
                plan[index].sha256 === git.git.sha256 &&
                plan[index].signatureSha256 === git.git.signatureSha256
              : held.get(index).directory),
        );
      }
      return openHelper(
        "git",
        transfer.helper,
        windowsFixedCommitArguments(git, {
          operation: "commit",
          subject: FIXED_SUBJECT,
        }),
        [],
        git,
      );
    },
    async openGitPolicy(value, operation, transfer) {
      const git = normalizeWindowsGitInput(value);
      closed(transfer, ["helper", "storage", "workspace", "objects"]);
      requireWindows(
        git.request.nonce === input.nonce &&
          git.request.candidateSha === input.context.candidateSha &&
          plan[transfer.helper]?.kind === "helper" &&
          path.basename(plan[transfer.helper].path) === "git-policy.exe",
      );
      const slots = [
        transfer.storage,
        transfer.workspace,
        ...dense(transfer.objects, 126),
      ];
      requireWindows(
        slots.every((index) => held.has(index)) &&
          new Set(slots).size === slots.length &&
          held.get(transfer.storage).directory &&
          plan[transfer.storage].path === git.request.storage &&
          held.get(transfer.workspace).directory &&
          plan[transfer.workspace].path === git.request.workspace,
      );
      const objects = slots.map((index, position) => ({
        handle: String(position + 1),
        identity: held.get(index).identity,
      }));
      const args = windowsGitPolicyArguments(git, operation, {
        storage: objects[0],
        workspace: objects[1],
        objects: objects.slice(2).map((object, position) => ({
          ...object,
          path: plan[slots[position + 2]].path,
          kind: held.get(slots[position + 2]).directory ? "directory" : "file",
        })),
      });
      return openHelper(
        "git-policy",
        transfer.helper,
        args,
        slots,
        { value: git, operation },
        operation === "remove",
      );
    },
    async close() {
      try {
        await serial;
        guard();
        requireWindows(
          children.size === 0 && !opening && !auditOwned && !auditRestoring,
        );
        retiring = true;
        const proof = await verify(
          "verifyRetirement",
          {
            input,
            helper,
            verifier,
            processes: [...processes.values()],
            jobs: [...jobs],
          },
          { signal },
        );
        requireWindows(
          retired(proof) &&
            proof.noLiveMembers === true &&
            sameWindowsIdentity(proof.helper, helper) &&
            sameWindowsIdentity(systemIdentity(proof.verifier), verifier),
        );
        await save("finish-possible", {
          helper,
          verifier,
          nativeEventSha256: proof.nativeEventSha256,
        });
        const result = await observe("finish");
        closed(result, ["closed"]);
        requireWindows(result.closed === true);
        closing = true;
        const task = await owner.receive();
        closed(task, ["phase", "taskSha256", "taskRemoved", "helperRetired"]);
        requireWindows(
          task.phase === "retired" &&
            task.taskSha256 === taskSha256 &&
            task.taskRemoved === true &&
            task.helperRetired === true,
        );
        const exit = await owner.completion;
        requireWindows(exit.code === 0 && exit.signal === null);
        const final = await verify(
          "verifyTaskRemoval",
          { input, helper, taskSha256, task },
          { signal },
        );
        requireWindows(
          retired(final) &&
            final.taskRemoved === true &&
            sameWindowsIdentity(final.helper, helper) &&
            sameWindowsIdentity(systemIdentity(final.verifier), verifier),
        );
        await save("retired", {
          helper,
          verifier,
          taskSha256,
          nativeEventSha256: final.nativeEventSha256,
        });
        owner.settle?.();
        return {
          ...final,
          bridge: structuredClone(bridge),
          closed: true,
        };
      } catch (cause) {
        failed = true;
        owner?.close();
        await save("retained", {
          helper: helper ?? null,
          verifier: verifier ?? null,
          taskSha256: taskSha256 ?? null,
        });
        return {
          status: "RETAINED",
          independent: false,
          closed: false,
          emergencyCleanup: false,
          cause,
        };
      }
    },
  };
}
