import { spawn } from "node:child_process";
import * as filesystem from "node:fs/promises";
import { win32 as path } from "node:path";

import { observationDigest } from "../index.js";
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
import { windowsObserverConfiguration } from "./observer.js";

import { windowsCustodyChannel } from "./channel.js";
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
    fs = options.fs ?? filesystem;
  let owner,
    helper,
    verifier,
    taskSha256,
    started = false,
    opening = false,
    retiring = false,
    closing = false,
    failed = false,
    signal,
    sequence = 0,
    receiptSequence = 0,
    serial = Promise.resolve(),
    child,
    auditOwned = false,
    auditRestoring = false;
  const held = new Map(),
    processes = new Map(),
    jobs = new Set();
  let plan;
  const guard = (finish = false) =>
    requireWindows(
      started &&
        owner &&
        (!retiring || finish) &&
        !closing &&
        !failed &&
        !signal?.aborted,
    );
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
      });
      guard(name === "finish");
      await owner.send([name, next, ...args].join(" ") + "\n");
      const message = await owner.receive();
      closed(message, ["sequence", "value"]);
      requireWindows(message.sequence === next);
      guard(name === "finish");
      return message.value;
    });
    serial = action.catch(() => {
      failed = true;
      owner?.close();
    });
    return action;
  };
  const verify = async (name, ...args) => {
    try {
      requireWindows(typeof options[name] === "function");
      const pending = options[name](structuredClone(args[0]), ...args.slice(1)),
        result = await (owner?.wait ? owner.wait(pending) : pending);
      requireWindows(!failed && !signal?.aborted);
      return result;
    } catch (error) {
      failed = true;
      owner?.close();
      throw error;
    }
  };
  const startHelper = async (kind, index, args, slots, request) => {
    requireWindows(
      !child &&
        held.has(index) &&
        dense(args, 55).every(
          (value) => typeof value === "string" && value.length > 0,
        ) &&
        dense(slots, 44).every((index) => held.has(index)) &&
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
    ]);
    child = systemIdentity(actual.helper);
    requireWindows(child.pid !== helper.pid && child.pid !== verifier.pid);
    const job = jobObservation(actual.job);
    requireWindows(
      hash(actual.processDaclSha256) &&
        hash(actual.threadDaclSha256) &&
        actual.inheritedHandleCount === slots.length + 2 &&
        job.limitFlags === 0x2008 &&
        job.processLimit === 1 &&
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
      { input, child, verifier, actual, transfer, transferSha256 },
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
        proof.jobSha256 === observationDigest(job) &&
        hash(proof.nativeEventSha256),
    );
    await save("helper-admitted", {
      child,
      verifier,
      nativeEventSha256: proof.nativeEventSha256,
    });
    guard();
    const released = await observe("helper-release");
    closed(released, ["released"]);
    requireWindows(released.released === true);
    const identity = child;
    let completed = false;
    const current = () =>
      requireWindows(
        !completed && child && sameWindowsIdentity(child, identity),
      );
    return {
      identity: structuredClone(identity),
      receive: async (size = 16384) => {
        current();
        requireWindows(integer(size, 16384) && size > 0);
        const frame = await (kind === "observer"
          ? observe("helper-bytes", size)
          : observe("helper-read"));
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
          Buffer.from(bytes).toString("hex"),
        );
        closed(sent, ["sent"]);
        requireWindows(sent.sent === true);
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
        const result = await observe("helper-finish");
        closed(result, ["retired", "members", "drained"]);
        requireWindows(
          result.retired === true &&
            result.members === 0 &&
            result.drained === true,
        );
        child = null;
        completed = true;
        return { ...proof, closed: true };
      },
    };
  };
  const openHelper = async (...args) => {
    guard();
    requireWindows(!opening && !child && !auditRestoring);
    opening = true;
    try {
      return await startHelper(...args);
    } finally {
      opening = false;
    }
  };
  return {
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
          observed = dense(seal.entries, 7);
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
            failed = true;
            owner.close();
          },
          { once: true },
        );
        requireWindows(!signal?.aborted);
        const intent = await owner.receive();
        closed(intent, ["phase", "taskSha256", "bridge"]);
        const bridge = normalizeWindowsIdentity(intent.bridge);
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
          integer(offset, 134217728) &&
          integer(size, 65536) &&
          size > 0 &&
          offset <= 134217728 - size,
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
      requireWindows(!auditRestoring);
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
      requireWindows(!auditRestoring);
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
      requireWindows(auditOwned && !child && !opening);
      requireWindows(!auditRestoring);
      auditRestoring = true;
      try {
        const proof = await verify(
          "verifyAuditRetirement",
          { input, processes: [...processes.values()], jobs: [...jobs] },
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
      return openHelper(
        "file",
        transfer.helper,
        windowsFileHelperArguments(file, { root: "1", base: "2" }),
        [transfer.root, transfer.base],
        file,
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
      );
    },
    async close() {
      try {
        await serial;
        guard();
        requireWindows(!child && !opening && !auditOwned && !auditRestoring);
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
        return { ...final, closed: true };
      } catch {
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
        };
      }
    },
  };
}
