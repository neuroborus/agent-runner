import { spawn } from "node:child_process";
import * as filesystem from "node:fs/promises";
import path from "node:path";
import {
  observationObject,
  observationList,
  observationDigest,
  normalizeNativePolicyContext,
} from "../index.js";
import { protectedBytes } from "./private-files.js";
import { darwinCustodyChannel } from "./channel.js";
import {
  digest,
  inspectDarwinMachO,
  normalizeDarwinIdentity,
  sameDarwinIdentity,
  requireDarwin,
} from "./protocol.js";
import {
  normalizeDarwinFileIdentity,
  normalizeDarwinFileMessage,
} from "./files-protocol.js";
import { normalizeDarwinFileInput } from "./files.js";
import {
  normalizeDarwinAuthorityRead,
  normalizeDarwinBarrierRead,
} from "./effective.js";
import { normalizeDarwinPfRead } from "./pf-preparation.js";
import { DARWIN_BUILD_CUSTODY_MS, DARWIN_HELPER_NAMES } from "./build.js";

const hash = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
const location = (value) =>
  typeof value === "string" &&
  path.isAbsolute(value) &&
  path.normalize(value) === value &&
  !/[\u0000-\u001f\u007f\uD800-\uDFFF]/u.test(value) &&
  Buffer.byteLength(value) < 1024;
const integer = (value, maximum = 2147483647) =>
  Number.isSafeInteger(value) && value >= 0 && value <= maximum;
const root = (value) => {
  const identity = normalizeDarwinIdentity(value);
  requireDarwin(
    ["uid", "ruid", "svuid", "gid", "rgid", "svgid"].every(
      (key) => identity[key] === 0,
    ),
  );
  return identity;
};
const hex = (value) => Buffer.from(value).toString("hex");
const text = (value) => {
  requireDarwin(
    typeof value === "string" && /^(?:[a-f0-9]{2}){1,4095}$/u.test(value),
  );
  const result = new TextDecoder("utf-8", { fatal: true }).decode(
    Buffer.from(value, "hex"),
  );
  requireDarwin(!/[\u0000-\u001f\u007f]/u.test(result));
  return result;
};
function entry(value, signature = false) {
  observationObject(
    value,
    signature ? ["path", "sha256", "cdhash"] : ["path", "sha256"],
  );
  requireDarwin(
    location(value.path) &&
      hash(value.sha256) &&
      (!signature || /^[a-f0-9]{40}$/u.test(value.cdhash)),
  );
  return structuredClone(value);
}
export function normalizeDarwinCustodyInput(value) {
  observationObject(value, [
    "context",
    "reader",
    "sources",
    "plan",
    "tools",
    "reportDirectory",
    "reviewSha256",
    "sdkSha256",
    "buildSha256",
  ]);
  const context = normalizeNativePolicyContext(value.context);
  const reader = entry(value.reader, true);
  requireDarwin(
    context.platform === "darwin" &&
      location(value.reportDirectory) &&
      ["reviewSha256", "sdkSha256", "buildSha256"].every((key) =>
        hash(value[key]),
      ),
  );
  observationObject(value.tools, ["elevation", "environment"]);
  const tools = {
    elevation: entry(value.tools.elevation),
    environment: entry(value.tools.environment),
  };
  requireDarwin(
    tools.elevation.path === "/usr/bin/sudo" &&
      tools.environment.path === "/usr/bin/env",
  );
  const sources = observationList(value.sources, 16).map((source) =>
    entry(source),
  );
  requireDarwin(
    new Set(sources.map((source) => source.path)).size === sources.length,
  );
  requireDarwin(
    [
      "custody-reader.c",
      "custody.h",
      "file-identity.h",
      "effective-reader.h",
    ].every((name) =>
      sources.some((source) => path.basename(source.path) === name),
    ),
  );
  requireDarwin(
    sources.every(
      (source) => path.dirname(source.path) === path.dirname(reader.path),
    ),
  );
  return {
    ...structuredClone(value),
    context,
    reader,
    plan: entry(value.plan),
    sources,
    tools,
  };
}

/** Concrete request bytes are an expectation, never independent approval.
 * The composing owner must admit its template and trusted bindings first. */
export function encodeDarwinCustodyPlan(input) {
  observationObject(input, ["candidateSha", "uid", "gid", "entries"]);
  const { candidateSha, uid, gid } = input,
    entries = observationList(input.entries, 128);
  requireDarwin(
    typeof candidateSha === "string" &&
      /^[a-f0-9]{40}$/u.test(candidateSha) &&
      integer(uid) &&
      uid > 500 &&
      integer(gid) &&
      gid > 500 &&
      entries.length > 0,
  );
  const lines = entries.map((value) => {
    observationObject(value, ["kind", "path", "sha256"]);
    requireDarwin(
      ["directory", "authority", "image", "data", "cache", "helper"].includes(
        value.kind,
      ) &&
        location(value.path) &&
        (["directory", "authority"].includes(value.kind)
          ? value.sha256 === null
          : hash(value.sha256)),
    );
    return `${value.kind} ${value.sha256 ?? "-"} ${hex(value.path)}`;
  });
  requireDarwin(
    new Set(entries.map((value) => value.path)).size === entries.length,
  );
  const bytes = Buffer.from(
    [`native-custody-v1 ${candidateSha} ${uid} ${gid}`, ...lines, ""].join(
      "\n",
    ),
  );
  requireDarwin(bytes.length <= 262144);
  return bytes;
}

function nativeTransport(input, args) {
  requireDarwin(
    process.platform === "darwin" &&
      process.arch === "x64" &&
      process.env.CI === "true" &&
      process.env.GITHUB_ACTIONS === "true" &&
      process.env.ImageOS === "macos15",
  );
  return darwinCustodyChannel(
    spawn(
      input.tools.elevation.path,
      [
        "-n",
        "--",
        input.tools.environment.path,
        "-i",
        "CI=true",
        "GITHUB_ACTIONS=true",
        input.reader.path,
        ...args,
      ],
      {
        cwd: path.dirname(input.reader.path),
        env: { PATH: "/nonexistent" },
        stdio: ["pipe", "pipe", "ignore"],
      },
    ),
    {
      deadlineMs:
        args[0] === "--build-serve"
          ? DARWIN_BUILD_CUSTODY_MS
          : args[0] === "--case-serve"
            ? 420000
            : args[0] === "--serve"
              ? 390000
              : 120000,
    },
  );
}
async function verifyAssets(input, fs) {
  const bundle = path.dirname(input.reader.path),
    sealed = await fs.lstat(bundle);
  requireDarwin(
    sealed.isDirectory() &&
      sealed.uid === 0 &&
      sealed.gid === 0 &&
      (sealed.mode & 0o7777) === 0o555 &&
      (await fs.realpath(bundle)) === bundle,
  );
  const assets = [
    [input.reader, 0o555],
    ...input.sources.map((source) => [source, 0o444]),
  ];
  for (const [asset, mode] of assets) {
    let parent = path.dirname(asset.path);
    while (parent !== "/") {
      const stat = await fs.lstat(parent);
      requireDarwin(
        stat.isDirectory() &&
          stat.uid === 0 &&
          !(stat.mode & 0o22) &&
          (await fs.realpath(parent)) === parent,
      );
      parent = path.dirname(parent);
    }
    const bytes = await protectedBytes(asset, 0, mode, 134217728, fs);
    if (asset === input.reader) inspectDarwinMachO(bytes);
  }
  for (const tool of Object.values(input.tools)) {
    const stat = await fs.lstat(tool.path);
    requireDarwin(
      stat.isFile() && stat.uid === 0 && stat.gid === 0 && !(stat.mode & 0o22),
    );
    await protectedBytes(tool, 0, stat.mode & 0o7777, 134217728, fs);
  }
}
function snapshot(value, domain = { uid: 0, gid: 0 }) {
  observationObject(value, [
    "identity",
    "bytes",
    "uid",
    "gid",
    "mode",
    "directory",
  ]);
  normalizeDarwinFileIdentity(value.identity);
  requireDarwin(
    integer(value.bytes, 536870912) &&
      [0, domain.uid].includes(value.uid) &&
      [0, domain.gid].includes(value.gid) &&
      integer(value.mode, 0o7777) &&
      typeof value.directory === "boolean" &&
      !(value.mode & 0o22),
  );
  return structuredClone(value);
}
function signature(value) {
  observationObject(value, ["cdhash", "entitlementsSha256", "valid"]);
  requireDarwin(
    /^[a-f0-9]{40}$/u.test(value.cdhash) &&
      hash(value.entitlementsSha256) &&
      value.valid === true,
  );
  return value;
}
function macho(value) {
  observationObject(value, [
    "headerSha256",
    "dependencies",
    "rpaths",
    "sdk",
    "minimum",
    "uuid",
  ]);
  requireDarwin(
    hash(value.headerSha256) &&
      integer(value.sdk, 0xffffffff) &&
      value.sdk > 0 &&
      integer(value.minimum, 0xffffffff) &&
      value.minimum > 0 &&
      /^[a-f0-9]{32}$/u.test(value.uuid),
  );
  return {
    ...value,
    dependencies: observationList(value.dependencies, 128).map(text),
    rpaths: observationList(value.rpaths, 128).map(text),
  };
}

/** Constructor performs no I/O. Independent fresh native reads are concrete
 * defaults; transport injection is solely for deterministic non-native tests. */
export function createDarwinCustodyReader(value, options = {}) {
  const input = normalizeDarwinCustodyInput(value),
    fs = options.fs ?? filesystem;
  const transport = options.transport ?? nativeTransport;
  const persist =
    options.persist ??
    (async (record) => {
      const stat = await fs.lstat(input.reportDirectory);
      requireDarwin(
        stat.isDirectory() &&
          !stat.isSymbolicLink() &&
          stat.uid === process.getuid() &&
          (stat.mode & 0o777) === 0o700 &&
          (await fs.realpath(input.reportDirectory)) === input.reportDirectory,
      );
      const file = path.join(
          input.reportDirectory,
          `darwin-custody-${digest(JSON.stringify(input.context))}-${record.sequence}.json`,
        ),
        bytes = Buffer.from(JSON.stringify(record) + "\n");
      requireDarwin(bytes.length <= 1048576);
      await fs.writeFile(file, bytes, { flag: "wx", mode: 0o400 });
      return { path: file, sha256: digest(bytes) };
    });
  let owner,
    helper,
    workSignal,
    cleanupSignal,
    serial = Promise.resolve(),
    sequence = 0,
    receiptSequence = 0,
    failed = false,
    started = false,
    closing = false,
    fileActive = false;
  let domain, reservationNonce, reservationIndex;
  const held = new Map();
  const pendingReceipts = [];
  const verifyReceipt = async (pin) => {
    requireDarwin(
      location(pin.path) &&
        path.dirname(pin.path) === input.reportDirectory &&
        /^darwin-[a-zA-Z0-9.-]+\.json$/u.test(path.basename(pin.path)) &&
        hash(pin.sha256),
    );
    await owner.send(`V ${hex(pin.path)} ${pin.sha256}\n`);
    const actual = await owner.receive();
    observationObject(actual, ["receipt"]);
    requireDarwin(actual.receipt === pin.sha256);
  };
  const observed = (read) => {
    try {
      return read();
    } catch {
      failed = true;
      owner?.close();
      throw new Error("Unverified Darwin custody observation");
    }
  };
  const save = async (phase, request) => {
    const pin = await persist({
      schemaVersion: 1,
      context: input.context,
      sequence: receiptSequence++,
      phase,
      request: structuredClone(request),
      requestSha256: digest(JSON.stringify(request)),
      reviewSha256: input.reviewSha256,
      custody: phase === "retired" ? "RETIRED" : "POSSIBLE",
      ...(["admitted", "file-admitted", "retired"].includes(phase)
        ? {
            subjects: structuredClone({
              helper: request.helper,
              verifier: request.verifier,
            }),
          }
        : {}),
    });
    if (
      (input.context.executionId === "build" || options.caseContextSha256) &&
      pin
    ) {
      if (owner && domain && !closing) await verifyReceipt(pin);
      else pendingReceipts.push(pin);
    }
  };
  const probe = async (pid, asid, reserved = false) => {
    requireDarwin(!cleanupSignal?.aborted);
    await save("probe-intent", {
      pid,
      ...(asid === undefined ? {} : { asid }),
    });
    const observer = await transport(
      input,
      asid === undefined
        ? ["--probe", String(pid)]
        : [
            "--probe-domain",
            String(pid),
            String(domain.uid),
            String(domain.gid),
            String(asid),
          ],
    );
    try {
      const result = await observer.receive();
      observationObject(result, [
        "verifier",
        "subject",
        ...(asid === undefined ? [] : ["enumeration"]),
      ]);
      const verifier = root(result.verifier);
      requireDarwin(verifier.pid !== pid);
      await save("probe-created", { pid, verifier });
      if (result.subject.status === "absent")
        observationObject(result.subject, ["status"]);
      else {
        observationObject(result.subject, [
          "status",
          "identity",
          "sha256",
          "signature",
          "directories",
        ]);
        requireDarwin(
          result.subject.status === "live" && hash(result.subject.sha256),
        );
        const subject = reserved
          ? normalizeDarwinIdentity(result.subject.identity)
          : root(result.subject.identity);
        requireDarwin(
          subject.pid === pid &&
            (!reserved ||
              (options.caseContextSha256 &&
                subject.auid === domain.uid &&
                subject.asid > 0 &&
                ["uid", "ruid", "svuid"].every(
                  (key) => subject[key] === domain.uid,
                ) &&
                ["gid", "rgid", "svgid"].every(
                  (key) => subject[key] === domain.gid,
                ))),
        );
        signature(result.subject.signature);
        const descriptors = new Set();
        for (const directory of observationList(
          result.subject.directories,
          2,
        )) {
          observationObject(directory, [
            "fd",
            "dev",
            "ino",
            "uid",
            "gid",
            "mode",
          ]);
          requireDarwin(
            [3, 4].includes(directory.fd) &&
              !descriptors.has(directory.fd) &&
              /^[0-9]+$/u.test(directory.dev) &&
              /^[1-9][0-9]*$/u.test(directory.ino) &&
              directory.uid === 0 &&
              directory.gid === 0 &&
              directory.mode === 0o700,
          );
          descriptors.add(directory.fd);
        }
      }
      const exit = await observer.completion;
      requireDarwin(
        exit.code === 0 && exit.signal === null && !cleanupSignal?.aborted,
      );
      // A zero signal is a kernel existence read, never a termination request.
      // Permission failure, a live/reused PID or any inaccessible read retains
      // the verifier even when its private channel reported successful exit.
      let absent = false;
      try {
        (options.kill ?? process.kill)(verifier.pid, 0);
      } catch (cause) {
        absent = cause?.code === "ESRCH";
      }
      requireDarwin(absent);
      await save("probe-retired", { pid, verifier });
      return result;
    } finally {
      observer.close();
    }
  };
  // Cleanup cannot reopen admission after the work deadline. It only reads
  // existing custody, restores the fixed PF baseline, and closes owned resources.
  const cleanupCommands = new Set([
    "process",
    "inspect",
    "location",
    "read",
    "signature",
    "macho",
    "cache",
    "build",
    "pf-read",
    "pf-recover",
    "access-controls-retired",
    "authority",
    "socket",
    "ipc",
    "barrier",
    "tree",
    "bsm",
    "reservation",
    "reservation-close",
    "file-read",
    "file-close",
    "close",
    "finish",
    "build-open",
    "build-root",
    "root-retired",
    "case-read",
    "case-retire",
    "case-members",
    "case-empty",
    "case-signal",
    "case-receipt",
    "case-receipt-read",
    "case-receipt-optional",
    "case-session",
    "operation-authority",
    "slots-closed",
    "file-view",
    "file-probe-finish",
    "file-publishers-finish",
    "file-reader-read",
    "file-reader-finish",
    "file-control-read",
    "file-control-rejoin",
    "transfer-recovery",
    "file-send-recovery",
    "file-control-restore",
    "file-volume-worker",
    "file-volume-run",
    "file-volume-finish",
    "git-event",
    "git-close",
    "git-object",
    "git-ordinary-finish",
    "access-sockets",
    "access-counters",
    "access-target",
    "access-audit-close",
    "access-controls-close",
  ]);
  const permitted = (name, args) =>
    cleanupSignal
      ? !cleanupSignal.aborted &&
        (cleanupCommands.has(name) ||
          (name === "file-volume-start" && args[3] === 1) ||
          (name === "access-audit" && args[0] === "S") ||
          ["access-pf-worker", "access-pf-run"].includes(name) ||
          (name === "access-pf-start" &&
            ["validate-restore", "restore"].includes(args[3])) ||
          (name === "pf-write" &&
            ["restore", "restore-skip"].includes(args[3])))
      : !workSignal?.aborted ||
        ["close", "file-close", "finish"].includes(name);
  const command = (name, ...args) => {
    const operation = serial.then(async () => {
      requireDarwin(
        started &&
          !failed &&
          !closing &&
          owner &&
          permitted(name, args) &&
          ++sequence <= 32768,
      );
      await save(name, { sequence, arguments: args });
      requireDarwin(permitted(name, args));
      await owner.send([name, sequence, ...args].join(" ") + "\n");
      const message = await owner.receive();
      observationObject(message, ["sequence", "value"]);
      requireDarwin(message.sequence === sequence && permitted(name, args));
      return message.value;
    });
    serial = operation.catch(() => {
      failed = true;
      owner?.close();
    });
    return operation;
  };
  const recheck = async (index) => {
    const before = held.get(index);
    requireDarwin(before);
    const message = await command("inspect", index);
    return observed(() => {
      const actual = snapshot(message, domain);
      requireDarwin(JSON.stringify(actual) === JSON.stringify(before));
      return actual;
    });
  };
  return {
    async beginCleanup({ signal }) {
      await serial;
      requireDarwin(
        started &&
          !failed &&
          !closing &&
          owner &&
          !cleanupSignal &&
          (!workSignal || workSignal.aborted) &&
          signal instanceof AbortSignal &&
          !signal.aborted,
      );
      await save("cleanup", { admission: "CLOSED" });
      requireDarwin(!signal.aborted && !failed && !closing);
      cleanupSignal = signal;
      signal.addEventListener(
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
    async start({ signal } = {}) {
      const runtime = options.runtime ?? {
        platform: process.platform,
        arch: process.arch,
        env: process.env,
      };
      requireDarwin(
        runtime.platform === "darwin" &&
          runtime.arch === "x64" &&
          runtime.env.CI === "true" &&
          runtime.env.GITHUB_ACTIONS === "true" &&
          runtime.env.ImageOS === "macos15",
      );
      requireDarwin(!started && !failed && !signal?.aborted);
      started = true;
      workSignal = signal;
      try {
        await (options.verifyAssets ?? verifyAssets)(input, fs);
        await save("entry", {
          readerSha256: input.reader.sha256,
          planSha256: input.plan.sha256,
          reviewReferences: {
            sdkSha256: input.sdkSha256,
            buildSha256: input.buildSha256,
          },
        });
        requireDarwin(!signal?.aborted);
        owner = await transport(input, [
          options.caseContextSha256
            ? "--case-serve"
            : input.context.executionId === "build"
              ? "--build-serve"
              : "--serve",
          input.plan.path,
          input.plan.sha256,
          ...(options.caseContextSha256 ? [options.caseContextSha256] : []),
        ]);
        const announced = await owner.receive();
        observationObject(announced, ["helper"]);
        helper = root(announced.helper);
        // sudo may exec or retain a parent; its numeric child PID is no proof.
        const independent = await probe(helper.pid);
        requireDarwin(
          independent.subject.status === "live" &&
            sameDarwinIdentity(independent.subject.identity, helper) &&
            independent.subject.sha256 === input.reader.sha256 &&
            independent.subject.signature.cdhash === input.reader.cdhash &&
            !signal?.aborted,
        );
        await save("admitted", { helper, verifier: independent.verifier });
        requireDarwin(!signal?.aborted);
        await owner.send("P\n");
        const plan = await owner.receive();
        observationObject(plan, ["candidateSha", "entries", "uid", "gid"]);
        requireDarwin(
          plan.candidateSha === input.context.candidateSha &&
            integer(plan.entries, 128) &&
            plan.entries > 0 &&
            integer(plan.uid) &&
            plan.uid > 500 &&
            integer(plan.gid) &&
            plan.gid > 500,
        );
        domain = { uid: plan.uid, gid: plan.gid };
        for (const pin of pendingReceipts) await verifyReceipt(pin);
        pendingReceipts.length = 0;
        return {
          helper: structuredClone(helper),
          independent: true,
          planSha256: input.plan.sha256,
        };
      } catch {
        failed = true;
        owner?.close();
        throw new Error("Darwin custody admission unavailable");
      }
    },
    async process(pid, { retainSession = false } = {}) {
      requireDarwin(
        integer(pid) && pid > 1 && typeof retainSession === "boolean",
      );
      const message = await command(retainSession ? "session" : "process", pid);
      return observed(() => {
        const identity = normalizeDarwinIdentity(message);
        requireDarwin(identity.pid === pid);
        return identity;
      });
    },
    async provisionBuild(output) {
      requireDarwin(
        input.context.executionId === "build" &&
          output === path.join(input.reportDirectory, "platform-build"),
      );
      const actual = snapshot(await command("build-directory", hex(output)));
      requireDarwin(
        actual.directory &&
          actual.uid === 0 &&
          actual.gid === 0 &&
          actual.mode === 0o700,
      );
      return { ...actual, independent: true, protectedParents: true };
    },
    async verifyBuildReceipt(pin) {
      requireDarwin(
        (input.context.executionId === "build" || options.caseContextSha256) &&
          started &&
          !failed &&
          !closing,
      );
      const operation = serial.then(() => verifyReceipt(pin));
      serial = operation.catch(() => {
        failed = true;
        owner?.close();
      });
      return operation;
    },
    async readBuildDirectory(output) {
      requireDarwin(
        input.context.executionId === "build" &&
          output === path.join(input.reportDirectory, "platform-build"),
      );
      const actual = snapshot(await command("build-root", hex(output)));
      requireDarwin(
        actual.directory &&
          actual.uid === 0 &&
          actual.gid === 0 &&
          [0o700, 0o555].includes(actual.mode),
      );
      return { ...actual, independent: true, protectedParents: true };
    },
    async readBuildImage(file, pin = null, maximum = 134217728) {
      requireDarwin(
        input.context.executionId === "build" &&
          path.dirname(file) ===
            path.join(input.reportDirectory, "platform-build") &&
          DARWIN_HELPER_NAMES.includes(path.basename(file)) &&
          (pin === null || hash(pin)) &&
          integer(maximum, 134217728) &&
          maximum > 0,
      );
      const opened = await command("build-open", hex(file), pin ?? "-");
      observationObject(opened, ["index", "object", "root", "sha256"]);
      const actual = snapshot(opened.object),
        root = snapshot(opened.root);
      requireDarwin(
        root.directory &&
          root.uid === 0 &&
          root.gid === 0 &&
          root.mode === 0o555,
      );
      requireDarwin(
        integer(opened.index, 127) &&
          !held.has(opened.index) &&
          !actual.directory &&
          actual.uid === 0 &&
          actual.gid === 0 &&
          actual.mode === 0o555 &&
          actual.bytes > 0 &&
          actual.bytes <= maximum &&
          hash(opened.sha256) &&
          (!pin || opened.sha256 === pin),
      );
      held.set(opened.index, actual);
      let firstFailure;
      try {
        const chunks = [];
        for (let offset = 0; offset < actual.bytes;) {
          const size = Math.min(65536, actual.bytes - offset),
            value = await command("read", opened.index, offset, size);
          observationObject(value, ["hex"]);
          requireDarwin(
            typeof value.hex === "string" &&
              new RegExp(`^[a-f0-9]{${size * 2}}$`, "u").test(value.hex),
          );
          chunks.push(Buffer.from(value.hex, "hex"));
          offset += size;
        }
        await recheck(opened.index);
        const bytes = Buffer.concat(chunks);
        requireDarwin(digest(bytes) === opened.sha256);
        return {
          bytes,
          identity: actual.identity,
          rootIdentity: root.identity,
          sha256: opened.sha256,
        };
      } catch (cause) {
        firstFailure = cause;
        throw cause;
      } finally {
        try {
          await command("close", opened.index);
          held.delete(opened.index);
        } catch (cause) {
          if (!firstFailure) throw cause;
        }
      }
    },
    async helper(subject) {
      subject = root(subject);
      const actual = await probe(subject.pid);
      return observed(() => {
        requireDarwin(
          actual.subject.status === "live" &&
            sameDarwinIdentity(actual.subject.identity, subject),
        );
        return actual.subject;
      });
    },
    async witness(subject) {
      subject = root(subject);
      const actual = await probe(subject.pid);
      requireDarwin(
        actual.subject.status === "live" &&
          sameDarwinIdentity(actual.subject.identity, subject),
      );
      return actual;
    },
    async operationSubject(subject) {
      subject = normalizeDarwinIdentity(subject);
      const actual = await probe(subject.pid, undefined, subject.uid !== 0);
      requireDarwin(
        actual.subject.status === "live" &&
          sameDarwinIdentity(actual.subject.identity, subject),
      );
      return actual;
    },
    async ownershipHelper(subject) {
      subject = root(subject);
      const actual = await probe(subject.pid);
      requireDarwin(
        actual.subject.status === "absent" ||
          (actual.subject.status === "live" &&
            sameDarwinIdentity(actual.subject.identity, subject)),
      );
      return actual;
    },
    async verifyOwnership(asid) {
      requireDarwin(options.caseContextSha256 && integer(asid, 2147483647));
      const actual = await probe(helper.pid, asid);
      requireDarwin(
        actual.subject.status === "live" &&
          sameDarwinIdentity(actual.subject.identity, helper) &&
          actual.subject.sha256 === input.reader.sha256,
      );
      return actual;
    },
    async startOwnership(caseId, cdhash) {
      requireDarwin(
        options.caseContextSha256 && /^[a-f0-9]{40}$/u.test(cdhash),
      );
      const value = await command("case-start", caseId, cdhash);
      observationObject(value, ["pid"]);
      requireDarwin(integer(value.pid) && value.pid > 1);
      return value;
    },
    ownershipControl: () => command("case-control"),
    async ownershipEof() {
      const value = await command("case-eof");
      observationObject(value, ["complete"]);
      requireDarwin(value.complete === true);
    },
    async ownershipOutput() {
      const value = await command("case-output");
      observationObject(value, ["hex"]);
      requireDarwin(
        typeof value.hex === "string" &&
          /^(?:[a-f0-9]{2}){1,8192}$/u.test(value.hex),
      );
      return new TextDecoder("utf-8", { fatal: true }).decode(
        Buffer.from(value.hex, "hex"),
      );
    },
    async sendOwnership(payload, value) {
      requireDarwin(
        typeof payload === "boolean" &&
          (payload ? ["A", "B", "C"] : ["P", "R"]).includes(value),
      );
      requireDarwin(
        (await command("case-send", payload ? 1 : 0, value)) === null,
      );
    },
    async recoverOwnershipReceipt(index, pin) {
      requireDarwin(
        options.caseContextSha256 && integer(index, 32767) && hash(pin),
      );
      const actual = await command("case-receipt-optional", index, pin);
      if (actual === null) return null;
      observationObject(actual, ["hex"]);
      const bytes = Buffer.from(actual.hex, "hex");
      requireDarwin(
        /^(?:[a-f0-9]{2})+$/u.test(actual.hex) && digest(bytes) === pin,
      );
      return bytes;
    },
    async ownershipReceipt(index, sha256, bytes) {
      requireDarwin(
        options.caseContextSha256 && integer(index, 32767) && hash(sha256),
      );
      if (bytes)
        requireDarwin(
          Buffer.isBuffer(bytes) &&
            bytes.length < 65536 &&
            digest(bytes) === sha256,
        );
      const value = await command(
        bytes ? "case-receipt" : "case-receipt-read",
        index,
        sha256,
        ...(bytes ? [bytes.toString("hex")] : []),
      );
      observationObject(value, ["hex"]);
      requireDarwin(
        typeof value.hex === "string" &&
          /^(?:[a-f0-9]{2}){1,65535}$/u.test(value.hex),
      );
      const actual = Buffer.from(value.hex, "hex");
      requireDarwin(digest(actual) === sha256);
      return actual;
    },
    async ownershipMembers(asid) {
      requireDarwin(integer(asid, 2147483647) && asid > 0);
      const value = await command("case-members", asid);
      observationObject(value, [
        "uid",
        "complete",
        "capacity",
        "live",
        "zombies",
      ]);
      requireDarwin(
        value.uid === domain.uid &&
          value.complete === true &&
          value.capacity === 33,
      );
      for (const identity of observationList(value.live, 32))
        normalizeDarwinIdentity(identity);
      observationList(value.zombies, 32);
      return value;
    },
    async holdOwnershipSession(asid) {
      requireDarwin(integer(asid, 2147483647) && asid > 0);
      const value = await command("case-session", asid);
      observationObject(value, ["asid", "held"]);
      requireDarwin(value.asid === asid && value.held === true);
      return value;
    },
    async emptyOwnership() {
      const value = await command("case-empty");
      observationObject(value, ["uid", "noLiveUid"]);
      requireDarwin(value.uid === domain.uid && value.noLiveUid === true);
      return value;
    },
    async resumeOwnership(subject) {
      const identity = normalizeDarwinIdentity(subject);
      const actual = await command(
        "case-resume",
        ...[
          "auid",
          "uid",
          "gid",
          "ruid",
          "rgid",
          "pid",
          "asid",
          "pidVersion",
          "startSeconds",
          "startMicroseconds",
          "svuid",
          "svgid",
        ].map((key) => identity[key]),
      );
      observationObject(actual, ["resumed"]);
      requireDarwin(actual.resumed === true);
      return actual;
    },
    async signalOwnership(subject) {
      const identity = normalizeDarwinIdentity(subject);
      const value = await command(
        "case-signal",
        ...[
          "auid",
          "uid",
          "gid",
          "ruid",
          "rgid",
          "pid",
          "asid",
          "pidVersion",
          "startSeconds",
          "startMicroseconds",
          "svuid",
          "svgid",
        ].map((key) => identity[key]),
      );
      observationObject(value, ["identity", "outcome"]);
      requireDarwin(
        sameDarwinIdentity(value.identity, identity) &&
          ["sent", "not-found", "zombie", "stale"].includes(value.outcome),
      );
      return value;
    },
    async ownershipSubject(pid, { access = false } = {}) {
      const value = await command("case-subject", pid);
      observationObject(value, [
        "identity",
        "imageSha256",
        "cwd",
        "sandboxed",
        "decisions",
      ]);
      normalizeDarwinIdentity(value.identity);
      observationObject(value.cwd, ["dev", "ino"]);
      requireDarwin(
        value.identity.pid === pid &&
          hash(value.imageSha256) &&
          value.sandboxed === true &&
          (access
            ? value.decisions.length === 7 &&
              value.decisions.every((decision) => [0, 1].includes(decision))
            : observationDigest(value.decisions) ===
              observationDigest([1, 1, 1, 0, 1, 1, 1])),
      );
      return value;
    },
    async operation(name, ...args) {
      requireDarwin(
        options.caseContextSha256 &&
          [
            "operation-authority",
            "slots-closed",
            "file-view",
            "file-probe-start",
            "file-probe-finish",
            "file-publishers-start",
            "file-publishers-ack",
            "file-publishers-finish",
            "file-reader-start",
            "file-reader-read",
            "file-reader-finish",
            "file-control-start",
            "file-control-read",
            "file-control-restore",
            "file-control-rejoin",
            "file-name",
            "file-volume-start",
            "file-volume-worker",
            "file-volume-run",
            "file-volume-finish",
            "git-start",
            "git-event",
            "git-send",
            "git-close",
            "git-object",
            "git-ordinary-start",
            "git-ordinary-release",
            "git-ordinary-finish",
          ].includes(name) &&
          args.length <= 13 &&
          args.every((value) =>
            typeof value === "number"
              ? integer(value, 2147483647)
              : typeof value === "string" &&
                /^[a-zA-Z0-9.-]{1,128}$/u.test(value),
          ),
      );
      return command(name, ...args);
    },
    async closeHeld(index) {
      requireDarwin(integer(index, 127) && held.has(index));
      await recheck(index);
      requireDarwin((await command("close", index)) === null);
      held.delete(index);
      const closed = await command("slots-closed");
      requireDarwin(
        Array.isArray(closed) &&
          closed.includes(index) &&
          new Set(closed).size === closed.length &&
          closed.every((value) => integer(value, 127)),
      );
      return { index, closed: true };
    },
    async provisionCaseDirectory(index) {
      requireDarwin(
        options.caseContextSha256 && integer(index, 127) && !held.has(index),
      );
      const actual = snapshot(await command("case-directory", index), domain);
      requireDarwin(actual.directory);
      held.set(index, actual);
      await save("case-object", { index, object: actual });
      return actual;
    },
    async copyCaseAsset(index, source) {
      requireDarwin(
        options.caseContextSha256 && integer(index, 127) && !held.has(index),
      );
      await recheck(source);
      const actual = snapshot(
        await command("case-copy", index, source),
        domain,
      );
      requireDarwin(!actual.directory && actual.bytes > 0);
      held.set(index, actual);
      await save("case-object", { index, object: actual });
      return actual;
    },
    async provisionCaseEndpoint(endpoint) {
      observationObject(endpoint, ["family", "protocol", "port"]);
      requireDarwin(
        options.caseContextSha256 &&
          ["inet", "inet6"].includes(endpoint.family) &&
          ["tcp", "udp"].includes(endpoint.protocol) &&
          integer(endpoint.port, 65535) &&
          endpoint.port >= 1024,
      );
      requireDarwin(
        (await command(
          "case-endpoint",
          endpoint.family === "inet" ? 4 : 6,
          endpoint.protocol === "tcp" ? 6 : 17,
          endpoint.port,
        )) === null,
      );
      await save("case-endpoint-bound", { endpoint });
    },
    async rejoinCaseObject(index) {
      requireDarwin(
        options.caseContextSha256 && integer(index, 127) && !held.has(index),
      );
      const actual = snapshot(await command("case-rejoin", index), domain);
      held.set(index, actual);
      return actual;
    },
    async readCase() {
      requireDarwin(options.caseContextSha256);
      const actual = await command("case-read");
      observationObject(actual, [
        "contextSha256",
        "uid",
        "gid",
        "accountVerified",
        "accounts",
        "objects",
        "endpoints",
      ]);
      requireDarwin(
        actual.contextSha256 === options.caseContextSha256 &&
          actual.uid === domain.uid &&
          actual.gid === domain.gid &&
          actual.accountVerified === true,
      );
      observationObject(actual.accounts, [
        "uidAccounts",
        "primaryGroupMembers",
        "gidGroups",
      ]);
      requireDarwin(
        Object.values(actual.accounts).every((count) => count === 1),
      );
      for (const item of observationList(actual.objects, 128)) {
        observationObject(item, ["index", "object"]);
        requireDarwin(
          held.has(item.index) &&
            observationDigest(snapshot(item.object, domain)) ===
              observationDigest(held.get(item.index)),
        );
      }
      for (const item of observationList(actual.endpoints, 8)) {
        observationObject(item, ["family", "protocol", "port"]);
        requireDarwin(
          ["inet", "inet6"].includes(item.family) &&
            ["tcp", "udp"].includes(item.protocol) &&
            integer(item.port, 65535) &&
            item.port >= 1024,
        );
      }
      return structuredClone(actual);
    },
    async retireCase() {
      requireDarwin(options.caseContextSha256);
      const actual = await command("case-retire");
      observationObject(actual, ["noLiveUid", "closed"]);
      requireDarwin(actual.noLiveUid === true && actual.closed === true);
      return actual;
    },
    async compilerPolicy(subject) {
      subject = root(subject);
      requireDarwin(input.context.executionId === "build" && subject.asid > 0);
      const value = await command(
        "compiler-policy",
        subject.pid,
        subject.pidVersion,
        subject.asid,
      );
      observationObject(value, [
        "identity",
        "uid",
        "gid",
        "ruid",
        "rgid",
        "sandboxed",
        "descriptors",
      ]);
      requireDarwin(
        sameDarwinIdentity(value.identity, subject) &&
          [value.uid, value.gid, value.ruid, value.rgid].every(
            (id) => id === 0,
          ) &&
          value.sandboxed === false &&
          Array.isArray(value.descriptors),
      );
      for (const descriptor of value.descriptors)
        observationObject(descriptor, ["fd", "type"]);
      value.descriptors.sort((a, b) => a.fd - b.fd);
      requireDarwin(
        observationDigest(value.descriptors) ===
          observationDigest([
            { fd: 0, type: "vnode" },
            { fd: 1, type: "pipe" },
            { fd: 2, type: "pipe" },
          ]),
      );
      return structuredClone(value);
    },
    async retired(subject, { reserved = false } = {}) {
      subject = reserved ? normalizeDarwinIdentity(subject) : root(subject);
      if (reserved)
        requireDarwin(
          options.caseContextSha256 &&
            subject.auid === domain.uid &&
            subject.asid > 0 &&
            ["uid", "ruid", "svuid"].every(
              (key) => subject[key] === domain.uid,
            ) &&
            ["gid", "rgid", "svgid"].every(
              (key) => subject[key] === domain.gid,
            ),
        );
      const actual = await probe(subject.pid);
      requireDarwin(
        actual.subject.status === "absent" ||
          (input.context.executionId !== "build" &&
            !options.caseContextSha256 &&
            !sameDarwinIdentity(actual.subject.identity, subject)),
      );
      return {
        status: "RETIRED",
        independent: true,
        emergencyCleanup: false,
        nativeEventSha256: digest(JSON.stringify({ subject, actual })),
      };
    },
    async rootDomain(subject) {
      subject = root(subject);
      requireDarwin(subject.asid > 0 && subject.asid < 2147483648);
      const actual = await command(
        "root-domain",
        subject.pid,
        subject.asid,
        subject.pidVersion,
      );
      return observed(() => {
        observationObject(actual, ["helper", "complete", "members"]);
        requireDarwin(
          actual.complete === true &&
            sameDarwinIdentity(actual.helper, subject),
        );
        const members = observationList(actual.members, 32).map(root);
        requireDarwin(
          new Set(members.map((member) => member.pid)).size ===
            members.length &&
            members.every((member) => member.asid === subject.asid),
        );
        return {
          helper: subject,
          complete: true,
          members,
          independent: true,
          nativeEventSha256: digest(JSON.stringify(actual)),
        };
      });
    },
    async retiredRootDomain(subject) {
      subject = root(subject);
      requireDarwin(
        (input.context.executionId === "build" || options.caseContextSha256) &&
          subject.auid === 0 &&
          subject.asid > 0,
      );
      const absence = await this.retired(subject),
        actual = await command(
          "root-retired",
          subject.pid,
          subject.asid,
          subject.pidVersion,
          subject.startSeconds,
          subject.startMicroseconds,
        );
      observationObject(actual, ["helper", "complete", "members"]);
      requireDarwin(
        sameDarwinIdentity(actual.helper, subject) &&
          actual.complete === true &&
          Array.isArray(actual.members) &&
          actual.members.length === 0,
      );
      return {
        ...actual,
        independent: true,
        nativeEventSha256: digest(JSON.stringify({ absence, actual })),
      };
    },
    async open(index) {
      requireDarwin(integer(index, 127) && !held.has(index));
      const message = await command("open", index),
        actual = observed(() => snapshot(message, domain));
      held.set(index, actual);
      return structuredClone(actual);
    },
    inspect: recheck,
    async location(index) {
      await recheck(index);
      const actual = await command("location", index);
      return observed(() => {
        observationObject(actual, ["hex"]);
        const name = text(actual.hex);
        requireDarwin(location(name));
        return name;
      });
    },
    async access(operation, ...values) {
      requireDarwin(
        options.caseContextSha256 &&
          [
            "sockets",
            "payload-sockets",
            "counters",
            "pf-start",
            "pf-worker",
            "pf-run",
            "audit-start",
            "audit",
            "audit-close",
            "provision",
            "target",
            "attempt",
            "run",
            "peer",
            "complete",
            "controls-close",
            "controls-retired",
          ].includes(operation),
      );
      requireDarwin(
        values.every(
          (value) =>
            (typeof value === "string" && /^[A-Za-z0-9-]+$/u.test(value)) ||
            (Number.isSafeInteger(value) && value >= 0 && value <= 0xffffffff),
        ),
      );
      return command("access-" + operation, ...values);
    },
    async recoverPfReference() {
      requireDarwin(options.caseContextSha256);
      const result = await command("pf-recover");
      observationObject(result, ["held"]);
      requireDarwin(result.held === true);
      return result;
    },
    async pf() {
      const actual = await command("pf-read");
      return observed(() => normalizeDarwinPfRead(actual));
    },
    async writePf(tool, configuration, cdhash, operation) {
      requireDarwin(
        /^[a-f0-9]{40}$/u.test(cdhash) &&
          ["install", "restore", "restore-skip"].includes(operation),
      );
      await recheck(tool);
      await recheck(configuration);
      const actual = await command(
        "pf-write",
        tool,
        configuration,
        cdhash,
        operation,
      );
      return observed(() => {
        observationObject(actual, ["pid", "settled"]);
        requireDarwin(
          integer(actual.pid) && actual.pid > 1 && actual.settled === true,
        );
        return actual;
      });
    },
    async authority(subject, index) {
      subject = normalizeDarwinIdentity(subject);
      await recheck(index);
      const actual = await command("authority", subject.pid, index);
      return observed(() =>
        normalizeDarwinAuthorityRead(actual, subject, held.get(index)),
      );
    },
    async socket(subjectValue, descriptor) {
      const subject = normalizeDarwinIdentity(subjectValue);
      requireDarwin(integer(descriptor, 4095));
      const actual = await command("socket", subject.pid, descriptor);
      return observed(() => {
        observationObject(actual, [
          "subject",
          "descriptor",
          "kernelId",
          "family",
          "protocol",
          "address",
          "port",
          "exclusive",
        ]);
        requireDarwin(
          sameDarwinIdentity(actual.subject, subject) &&
            actual.descriptor === descriptor &&
            /^[1-9a-f][a-f0-9]{0,15}$/u.test(actual.kernelId) &&
            ["inet", "inet6"].includes(actual.family) &&
            ["tcp", "udp"].includes(actual.protocol) &&
            actual.address ===
              (actual.family === "inet" ? "127.0.0.1" : "::1") &&
            integer(actual.port, 65535) &&
            actual.port >= 1024 &&
            actual.exclusive === true,
        );
        return actual;
      });
    },
    async ipc(type, id) {
      requireDarwin([1, 2, 3].includes(type) && integer(id));
      const actual = await command("ipc", type, id);
      return observed(() => {
        observationObject(actual, [
          "type",
          "id",
          "created",
          "size",
          "authoritySha256",
        ]);
        requireDarwin(
          actual.type === type &&
            actual.id === id &&
            /^[1-9][0-9]{0,18}$/u.test(actual.created) &&
            integer(actual.size, 8388608) &&
            actual.size > 0 &&
            hash(actual.authoritySha256),
        );
        return actual;
      });
    },
    async barrier(index, name) {
      requireDarwin(
        typeof name === "string" &&
          /^[A-Za-z0-9_.\/-]{1,256}$/u.test(name) &&
          !name.startsWith("/") &&
          !name.split("/").some((part) => ["", ".", ".."].includes(part)),
      );
      await recheck(index);
      const actual = await command("barrier", index, hex(name));
      return observed(() => normalizeDarwinBarrierRead(actual));
    },
    async tree(index) {
      await recheck(index);
      const actual = await command("tree", index);
      return observed(() =>
        observationList(actual, 256)
          .map((item) => {
            observationObject(item, ["name", "file"]);
            const name = text(item.name);
            requireDarwin(
              !name.startsWith("/") &&
                !name.split("/").some((part) => ["", ".", ".."].includes(part)),
            );
            return { name, file: normalizeDarwinBarrierRead(item.file, false) };
          })
          .sort((a, b) => a.name.localeCompare(b.name, "en")),
      );
    },
    async bsm(bytes) {
      requireDarwin(
        Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= 65536,
      );
      return command("bsm", hex(bytes));
    },
    async reserve(index, nonce) {
      requireDarwin(/^[a-f0-9]{32}$/u.test(nonce));
      await recheck(index);
      const actual = await command("reserve", index, nonce);
      return observed(() => {
        const result = snapshot(actual);
        requireDarwin(
          JSON.stringify(result) === JSON.stringify(held.get(index)),
        );
        reservationNonce = nonce;
        reservationIndex = index;
        return result;
      });
    },
    async reservation() {
      await recheck(reservationIndex);
      const actual = await command("reservation");
      const result = observed(() => {
        observationObject(actual, ["held"]);
        requireDarwin(actual.held === true);
        return actual;
      });
      await recheck(reservationIndex);
      return result;
    },
    async releaseReservation(retirement) {
      observationObject(retirement, [
        "context",
        "nonce",
        "status",
        "independent",
        "noLiveUid",
        "helpersSettled",
        "domain",
        "verifier",
        "receiptSha256",
        "pfBaselineSha256",
      ]);
      observationObject(retirement.domain, ["uid", "gid", "asid"]);
      requireDarwin(
        retirement.status === "RETIRED" &&
          retirement.independent === true &&
          retirement.noLiveUid === true &&
          retirement.helpersSettled === true &&
          JSON.stringify(normalizeNativePolicyContext(retirement.context)) ===
            JSON.stringify(input.context) &&
          retirement.nonce === reservationNonce &&
          hash(retirement.receiptSha256) &&
          hash(retirement.pfBaselineSha256) &&
          retirement.domain.uid === domain.uid &&
          retirement.domain.gid === domain.gid &&
          (retirement.domain.asid === null ||
            (integer(retirement.domain.asid) && retirement.domain.asid > 0)) &&
          root(retirement.verifier).pid !== helper.pid,
      );
      await this.emptyOwnership();
      const actual = await this.verifyOwnership(retirement.domain.asid ?? 0);
      requireDarwin(
        actual.enumeration.live.length === 0 &&
          actual.enumeration.zombies.length === 0,
      );
      requireDarwin(
        digest(
          JSON.stringify(normalizeDarwinPfRead(await command("pf-read"))),
        ) === retirement.pfBaselineSha256,
      );
      await recheck(reservationIndex);
      requireDarwin((await command("reservation-close")) === null);
      reservationNonce = undefined;
      reservationIndex = undefined;
    },
    async build() {
      const actual = await command("build");
      return observed(() => {
        observationObject(actual, ["osBuild", "macho"]);
        return {
          osBuild: text(actual.osBuild),
          macho: macho(actual.macho),
          reviewReferences: {
            sdkSha256: input.sdkSha256,
            buildSha256: input.buildSha256,
          },
        };
      });
    },
    async read(index, maximum = 134217728) {
      const before = await recheck(index);
      requireDarwin(
        !before.directory &&
          integer(maximum, 536870912) &&
          before.bytes <= maximum,
      );
      const chunks = [];
      for (let offset = 0; offset < before.bytes; offset += 65536) {
        const size = Math.min(65536, before.bytes - offset),
          result = await command("read", index, offset, size);
        chunks.push(
          observed(() => {
            observationObject(result, ["hex"]);
            requireDarwin(
              typeof result.hex === "string" &&
                result.hex.length === size * 2 &&
                /^[a-f0-9]+$/u.test(result.hex),
            );
            return Buffer.from(result.hex, "hex");
          }),
        );
      }
      await recheck(index);
      return Buffer.concat(chunks);
    },
    async signature(index) {
      await recheck(index);
      const message = await command("signature", index),
        actual = observed(() => signature(message));
      await recheck(index);
      return actual;
    },
    async macho(index) {
      await recheck(index);
      const message = await command("macho", index),
        actual = observed(() => macho(message));
      await recheck(index);
      return actual;
    },
    async cache(index, imagePath) {
      requireDarwin(location(imagePath));
      await recheck(index);
      const actual = await command("cache", index, hex(imagePath));
      const result = observed(() => {
        observationObject(actual, [
          "cacheUuid",
          "imageUuid",
          "signatureSha256",
          "macho",
        ]);
        requireDarwin(
          [actual.cacheUuid, actual.imageUuid].every(
            (id) => /^[a-f0-9]{32}$/u.test(id) && id !== "0".repeat(32),
          ) && hash(actual.signatureSha256),
        );
        const image = macho(actual.macho);
        requireDarwin(image.uuid === actual.imageUuid);
        return { ...actual, macho: image };
      });
      await recheck(index);
      return result;
    },
    async openFile(fileInput, transfer) {
      observationObject(transfer, [
        "helperIndex",
        "rootIndex",
        "baseIndex",
        "authority",
        ...(Object.hasOwn(transfer, "recoveryPin") ? ["recoveryPin"] : []),
      ]);
      const { helperIndex, rootIndex, baseIndex, authority, recoveryPin } =
        transfer;
      if (recoveryPin) {
        observationObject(recoveryPin, ["index", "sha256"]);
        requireDarwin(
          integer(recoveryPin.index, 32767) && hash(recoveryPin.sha256),
        );
      }
      requireDarwin(
        [helperIndex, rootIndex, baseIndex].every((index) =>
          integer(index, 127),
        ) && rootIndex !== baseIndex,
      );
      const file = normalizeDarwinFileInput(fileInput);
      requireDarwin(
        !fileActive &&
          file.request.candidateSha === input.context.candidateSha &&
          file.request.bindings.closure === input.context.closureSha256,
      );
      observationObject(authority, [
        "context",
        "base",
        "root",
        "held",
        "exclusive",
        "independent",
        "verifier",
        "verifierSha256",
        "nativeEventSha256",
      ]);
      requireDarwin(
        JSON.stringify(normalizeNativePolicyContext(authority.context)) ===
          JSON.stringify(input.context) &&
          authority.base === file.base &&
          authority.root === file.root &&
          authority.held === true &&
          authority.exclusive === true &&
          authority.independent === true &&
          hash(authority.verifierSha256) &&
          hash(authority.nativeEventSha256) &&
          root(authority.verifier).pid !== helper.pid,
      );
      const rootObject = await recheck(rootIndex),
        baseObject = await recheck(baseIndex);
      requireDarwin(
        rootObject.directory &&
          baseObject.directory &&
          rootObject.identity === file.root &&
          baseObject.identity === file.base,
      );
      fileActive = true;
      const child = await command(
        recoveryPin ? "transfer-recovery" : "transfer",
        helperIndex,
        rootIndex,
        baseIndex,
        file.request.nonce,
        file.request.executable.cdhash,
        ...(recoveryPin ? [recoveryPin.index, recoveryPin.sha256] : []),
      );
      observationObject(child, ["pid"]);
      requireDarwin(integer(child.pid) && child.pid > 1);
      const ready = normalizeDarwinFileMessage(
        await command("file-read"),
        file.request.nonce,
      );
      requireDarwin(
        ready.phase === "ready" &&
          ready.root === file.root &&
          ready.base === file.base,
      );
      const actual = await probe(child.pid);
      const identity = root(actual.subject.identity);
      requireDarwin(
        actual.subject.status === "live" &&
          identity.pid === child.pid &&
          actual.subject.sha256 === file.request.executable.sha256 &&
          actual.subject.signature.cdhash === file.request.executable.cdhash &&
          actual.subject.directories.length === 2,
      );
      for (const [fd, object] of [
        [3, rootObject],
        [4, baseObject],
      ]) {
        const observed = actual.subject.directories.find(
            (item) => item.fd === fd,
          ),
          parts = object.identity.split(":");
        requireDarwin(observed?.dev === parts[0] && observed.ino === parts[3]);
      }
      const requestSha256 = digest(JSON.stringify(file));
      requireDarwin(root(authority.verifier).pid !== identity.pid);
      const admission = {
        helper: identity,
        verifier: actual.verifier,
        independent: true,
        soleParentAuthority: authority.exclusive,
        requestSha256,
        helperSha256: actual.subject.sha256,
        cdhash: actual.subject.signature.cdhash,
        closureSha256: input.context.closureSha256,
        reviewSha256: file.reviewSha256,
        base: file.base,
        root: file.root,
        receiptSha256: digest(JSON.stringify({ file, actual, authority })),
      };
      await save("file-admitted", admission);
      await command(
        recoveryPin ? "file-send-recovery" : "file-send",
        hex("start - - - -\n"),
      );
      let complete, closePromise;
      const completion = new Promise((resolve, reject) => {
        complete = { resolve, reject };
      });
      completion.catch(() => {});
      return {
        admission: structuredClone(admission),
        send: (bytes) => {
          requireDarwin(
            typeof bytes === "string" &&
              Buffer.byteLength(bytes) <= 9000 &&
              bytes.endsWith("\n"),
          );
          return command(
            recoveryPin ? "file-send-recovery" : "file-send",
            hex(bytes),
          );
        },
        receive: async () => {
          const value = await command("file-read");
          if (value?.eof === true) {
            observationObject(value, ["eof"]);
            return null;
          }
          return value;
        },
        close() {
          if (closePromise) return;
          closePromise = (async () => {
            const outcome = await command("file-close"),
              observed = await probe(identity.pid);
            observationObject(outcome, [
              "code",
              "signal",
              "drained",
              "decision",
            ]);
            requireDarwin(
              outcome.decision === null ||
                [
                  "reject-identity",
                  "reject-symlink",
                  "reject-hardlink",
                  "reject-volume",
                ].includes(outcome.decision),
            );
            requireDarwin(
              outcome.drained === true &&
                ((integer(outcome.code, 255) && outcome.signal === null) ||
                  (outcome.code === null && outcome.signal === "SIGKILL")),
            );
            requireDarwin(
              observed.subject.status === "absent" ||
                !sameDarwinIdentity(observed.subject.identity, identity),
            );
            fileActive = false;
            complete.resolve({
              code: outcome.code,
              signal: outcome.signal,
              decision: outcome.decision,
              failed: false,
              remainingMessages: 0,
              partialBytes: 0,
            });
          })().catch(() => {
            failed = true;
            complete.reject(new Error("Darwin file custody retained"));
          });
        },
        completion,
        dispose() {},
      };
    },
    async close() {
      let independent = null;
      try {
        requireDarwin(!fileActive && helper && !closing);
        for (const index of held.keys()) {
          await command("close", index);
          held.delete(index);
        }
        const end = await command("finish");
        observationObject(end, ["closed"]);
        requireDarwin(end.closed === true);
        closing = true;
        const exit = await owner.completion;
        requireDarwin(exit.code === 0 && exit.signal === null);
        independent = await probe(helper.pid);
        requireDarwin(
          independent.subject.status === "absent" ||
            (!options.caseContextSha256 &&
              !sameDarwinIdentity(independent.subject.identity, helper)),
        );
        await save("retired", { helper, verifier: independent.verifier });
        return {
          status: "RETIRED",
          independent: true,
          closed: true,
          emergencyCleanup: false,
          helper,
          verifier: independent.verifier,
          nativeEventSha256: digest(JSON.stringify(independent)),
        };
      } catch {
        failed = true;
        owner?.close();
        return {
          status: "RETAINED",
          independent: false,
          closed: false,
          nativeEventSha256: digest(
            JSON.stringify({ context: input.context, retained: true }),
          ),
        };
      }
    },
  };
}
