import { spawn } from "node:child_process";
import * as filesystem from "node:fs/promises";
import path from "node:path";
import {
  observationObject,
  observationList,
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
    { deadlineMs: args[0] === "--serve" ? 390000 : 120000 },
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
    const bytes = await protectedBytes(asset, 0, mode, 134217728);
    if (asset === input.reader) inspectDarwinMachO(bytes);
  }
  for (const tool of Object.values(input.tools)) {
    const stat = await fs.lstat(tool.path);
    requireDarwin(
      stat.isFile() && stat.uid === 0 && stat.gid === 0 && !(stat.mode & 0o22),
    );
    await protectedBytes(tool, 0, stat.mode & 0o7777, 134217728);
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
      await fs.writeFile(
        path.join(
          input.reportDirectory,
          `darwin-custody-${digest(JSON.stringify(input.context))}-${record.sequence}.json`,
        ),
        JSON.stringify(record) + "\n",
        { flag: "wx", mode: 0o400 },
      );
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
  const observed = (read) => {
    try {
      return read();
    } catch {
      failed = true;
      owner?.close();
      throw new Error("Unverified Darwin custody observation");
    }
  };
  const save = (phase, request) =>
    persist({
      schemaVersion: 1,
      context: input.context,
      sequence: receiptSequence++,
      phase,
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
  const probe = async (pid) => {
    requireDarwin(!cleanupSignal?.aborted);
    const observer = await transport(input, ["--probe", String(pid)]);
    try {
      const result = await observer.receive();
      observationObject(result, ["verifier", "subject"]);
      const verifier = root(result.verifier);
      requireDarwin(verifier.pid !== pid);
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
        requireDarwin(root(result.subject.identity).pid === pid);
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
  ]);
  const permitted = (name, args) =>
    cleanupSignal
      ? !cleanupSignal.aborted &&
        (cleanupCommands.has(name) ||
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
          "--serve",
          input.plan.path,
          input.plan.sha256,
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
    async retired(subject) {
      subject = root(subject);
      const actual = await probe(subject.pid);
      requireDarwin(
        actual.subject.status === "absent" ||
          !sameDarwinIdentity(actual.subject.identity, subject),
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
          integer(retirement.domain.asid) &&
          retirement.domain.asid > 0 &&
          root(retirement.verifier).pid !== helper.pid,
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
      ]);
      const { helperIndex, rootIndex, baseIndex, authority } = transfer;
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
        "transfer",
        helperIndex,
        rootIndex,
        baseIndex,
        file.request.nonce,
        file.request.executable.cdhash,
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
      await command("file-send", hex("start - - - -\n"));
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
          return command("file-send", hex(bytes));
        },
        receive: () => command("file-read"),
        close() {
          if (closePromise) return;
          closePromise = (async () => {
            const outcome = await command("file-close"),
              observed = await probe(identity.pid);
            observationObject(outcome, ["code", "signal", "drained"]);
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
            !sameDarwinIdentity(independent.subject.identity, helper),
        );
        await save("retired", { helper, verifier: independent.verifier });
        return {
          status: "RETIRED",
          independent: true,
          closed: true,
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
