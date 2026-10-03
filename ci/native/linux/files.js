import { fork } from "node:child_process";
import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import {
  lstat,
  link,
  mkdir,
  open,
  readFile,
  readlink,
  realpath,
  rename,
  rmdir,
  writeFile,
  symlink,
  unlink,
} from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { messageQueue, send } from "./channel.js";
import {
  digest,
  descendants,
  inspectFixtureMounts,
  processDetails,
  protectedReceipt,
  readProtectedEvidence,
} from "./inspect.js";
import { normalizeLinuxReceipt, sameLinuxIdentity } from "./protocol.js";
import { freshVerifier } from "./proof.js";
import {
  LINUX_FILE_BUILD_ARGUMENTS,
  verifyLinuxFileElf,
} from "./file-build.js";
import {
  encodeLinuxFileRequest,
  normalizeLinuxFileMessage,
  normalizeLinuxFileControl,
  runLinuxFileTransaction,
  retireLinuxFileStorage,
} from "./files-protocol.js";

const CONTROLLER = fileURLToPath(new URL("./controller.js", import.meta.url));
const ENVIRONMENT = Object.freeze({
  PATH: "/usr/bin:/bin",
  LANG: "C",
  CI: "true",
  GITHUB_ACTIONS: "true",
});
const NONCE = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/u;
const ANCHOR = /^file-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/u;
const RECORD = /^(?:operation|barrier)-(?:0|[1-9][0-9]?)$/u;
const CONTROL_NAMES = Object.freeze([
  "allocation",
  "allocation/value",
  "allocation/.pending",
  ".held-allocation",
  ".held-allocation/value",
  ".held-allocation/.pending",
  ".held-value",
  ".alias",
  "crossing",
  ".crossing-source",
  ".crossing-source/value",
]);
const CONTROL_BYTES = "73656e74696e656c";

async function observeFileControl(anchor, check, control) {
  await check();
  const objects = {};
  for (const name of CONTROL_NAMES) {
    const file = path.join(anchor, name);
    let handle;
    try {
      const named = await lstat(file, { bigint: true });
      const kind = named.isDirectory()
        ? "directory"
        : named.isFile()
          ? "file"
          : named.isSymbolicLink()
            ? "symlink"
            : null;
      if (
        kind === null ||
        (await realpath(path.dirname(file))) !== path.dirname(file)
      )
        throw new Error("Unknown control object");
      let bytes = null,
        target = null;
      if (kind === "symlink") target = await readlink(file);
      else if (kind === "file") {
        handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
        const held = await handle.stat({ bigint: true });
        if (
          observedIdentity(held) !== observedIdentity(named) ||
          held.size > 4096n
        )
          throw new Error("Control identity changed");
        const buffer = Buffer.alloc(4097);
        const read = await handle.read(buffer, 0, buffer.length, 0);
        if (read.bytesRead !== Number(held.size) || read.bytesRead > 4096)
          throw new Error("Control contents changed");
        bytes = buffer.subarray(0, read.bytesRead).toString("hex");
      }
      const after = await lstat(file, { bigint: true });
      if (
        [
          "dev",
          "ino",
          "birthtimeNs",
          "mode",
          "uid",
          "nlink",
          "size",
          "mtimeNs",
        ].some((key) => named[key] !== after[key])
      )
        throw new Error("Control observation changed");
      objects[name] = {
        identity: observedIdentity(named),
        kind,
        mode: Number(named.mode & 0o7777n),
        uid: Number(named.uid),
        links: Number(named.nlink),
        bytes,
        target,
      };
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
      objects[name] = null;
    } finally {
      await handle?.close();
    }
  }
  await check();
  return {
    control,
    parentAuthority: true,
    anchor: observedIdentity(await lstat(anchor, { bigint: true })),
    objects,
  };
}

/** Only the trusted parked-barrier owner creates these identity-bound controls.
 * Unknown objects are never adopted, followed or recursively removed. */
async function applyFileControl(anchor, check, control, persist, native) {
  const before = await observeFileControl(anchor, check, control);
  for (const name of [
    ".held-allocation",
    ".held-allocation/value",
    ".held-allocation/.pending",
    ".held-value",
    ".alias",
  ])
    if (before.objects[name] !== null)
      throw new Error("Unknown parked control storage");
  for (const [key, name] of [
    ["allocation", "allocation"],
    ["leaf", "allocation/value"],
    ["temporary", "allocation/.pending"],
  ]) {
    const stable =
      native[key]
        ?.split(":")
        .filter((_, index) => index !== 3)
        .join(":") ?? null;
    if ((before.objects[name]?.identity ?? null) !== stable)
      throw new Error("Parked control identity changed");
  }
  await persist("control-intent", { control, before });
  await check();
  if (control === "ancestor") {
    await rename(
      path.join(anchor, "allocation"),
      path.join(anchor, ".held-allocation"),
    );
    await check();
    await mkdir(path.join(anchor, "allocation"), { mode: 0o700 });
    await check();
    await writeFile(
      path.join(anchor, "allocation/value"),
      Buffer.from(CONTROL_BYTES, "hex"),
      { flag: "wx", mode: 0o600 },
    );
    await check();
  } else if (["leaf", "cleanup-leaf", "symlink"].includes(control)) {
    await rename(
      path.join(anchor, "allocation/value"),
      path.join(anchor, ".held-value"),
    );
    await check();
    if (control === "symlink")
      await symlink("../.held-value", path.join(anchor, "allocation/value"));
    else
      await writeFile(
        path.join(anchor, "allocation/value"),
        Buffer.from(CONTROL_BYTES, "hex"),
        { flag: "wx", mode: 0o600 },
      );
  } else if (control === "hard-link")
    await link(
      path.join(anchor, "allocation/value"),
      path.join(anchor, ".alias"),
    );
  else if (!["magic-link", "mount"].includes(control))
    throw new Error("Invalid parked control");
  const applied = await observeFileControl(anchor, check, control);
  const bytes = await persist("control", { control, before, applied });
  return { before, applied, sha256: digest(bytes) };
}

async function withFileControlAuthority(fixture, session, record, body) {
  const anchor = path.join(fixture.directory, session.anchorName),
    handles = [];
  try {
    for (const directory of [fixture.directory, anchor])
      handles.push(
        await open(
          directory,
          constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
        ),
      );
    const originals = await Promise.all(
      handles.map((handle) => handle.stat({ bigint: true })),
    );
    const check = async () => {
      for (const [index, directory] of [fixture.directory, anchor].entries()) {
        const named = await lstat(directory, { bigint: true }),
          held = await handles[index].stat({ bigint: true });
        if (
          (await realpath(directory)) !== directory ||
          !named.isDirectory() ||
          named.uid !== BigInt(process.getuid()) ||
          (named.mode & 0o7777n) !== 0o700n ||
          observedIdentity(named) !== observedIdentity(originals[index]) ||
          observedIdentity(held) !== observedIdentity(originals[index]) ||
          (index === 1 && observedIdentity(named) !== record.before.anchor)
        )
          throw new Error("Control parent authority changed");
      }
    };
    await check();
    return await body(anchor, check, handles);
  } finally {
    await Promise.all(handles.map((handle) => handle.close()));
  }
}

export async function restoreLinuxFileControl(fixture, session) {
  recoveryNames(session);
  const prefix = path.join(
    fixture.directory,
    "evidence",
    `file-helper-${session.nonce}`,
  );
  const terminal = JSON.parse(
    await readProtectedEvidence(`${prefix}-terminal.json`),
  );
  const bytes = await readProtectedEvidence(`${prefix}-control.json`);
  const record = JSON.parse(bytes);
  const rejected = JSON.parse(
    await readProtectedEvidence(`${prefix}-denied.json`),
  );
  if (
    JSON.stringify(terminal) !== JSON.stringify(session) ||
    digest(bytes) !== session.controlDigest ||
    record.candidateSha !== session.candidateSha ||
    record.nonce !== session.nonce ||
    record.control !== session.control ||
    session.status !== "FAIL" ||
    session.denial?.phase !== "denied" ||
    rejected.candidateSha !== session.candidateSha ||
    rejected.nonce !== session.nonce ||
    rejected.nativeRecord !== session.nativeRecord ||
    rejected.controlDigest !== session.controlDigest ||
    JSON.stringify(rejected.message) !== JSON.stringify(session.denial)
  )
    throw new Error("Unbound control recovery");
  const retired = await freshVerifier(`${prefix}.json`, session.receiptDigest);
  if (
    retired.status !== "RETIRED" ||
    !retired.independent ||
    retired.emergencyCleanup ||
    session.settlement.emergencyCleanup
  )
    throw new Error("Control recovery requires retirement");
  const deadline = performance.now() + 5000;
  return withFileControlAuthority(
    fixture,
    session,
    record,
    async (anchor, authority, handles) => {
      const check = async () => {
        if (performance.now() >= deadline)
          throw new Error("Control cleanup deadline");
        await authority();
      };
      const move = async (from, to) => {
        await check();
        const named = await lstat(path.join(anchor, from), { bigint: true });
        if (observedIdentity(named) !== record.applied.objects[from]?.identity)
          throw new Error("Unknown restore authority");
        try {
          await lstat(path.join(anchor, to));
          throw new Error("Restore would replace an unknown object");
        } catch (error) {
          if (error.code !== "ENOENT") throw error;
        }
        await rename(path.join(anchor, from), path.join(anchor, to));
      };
      const current = await observeFileControl(anchor, check, session.control);
      if (JSON.stringify(current) !== JSON.stringify(record.applied))
        throw new Error("Substitute or sentinel changed");
      const remove = async (name, directory = false) => {
        await check();
        const expected = record.applied.objects[name],
          metadata = await lstat(path.join(anchor, name), { bigint: true });
        if (!expected || observedIdentity(metadata) !== expected.identity)
          throw new Error("Unknown removal authority");
        if (directory) await rmdir(path.join(anchor, name));
        else await unlink(path.join(anchor, name));
      };
      // Only fault-owner objects are removed; original held objects are restored.
      if (session.control === "ancestor") {
        await remove("allocation/value");
        await remove("allocation", true);
        await move(".held-allocation", "allocation");
      } else if (
        ["leaf", "cleanup-leaf", "symlink"].includes(session.control)
      ) {
        await remove("allocation/value");
        await check();
        await move(".held-value", "allocation/value");
      } else if (session.control === "hard-link") await remove(".alias");
      else if (session.control === "mount") {
        await remove("crossing", true);
        await remove(".crossing-source/value");
        await remove(".crossing-source", true);
      }
      const restored = await observeFileControl(anchor, check, session.control);
      const expected = structuredClone(record.before);
      if (session.control === "mount")
        for (const name of [
          "crossing",
          ".crossing-source",
          ".crossing-source/value",
        ])
          expected.objects[name] = null;
      if (JSON.stringify(restored) !== JSON.stringify(expected))
        throw new Error("Original control identities not restored");
      const allocation = await open(
        path.join(anchor, "allocation"),
        constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
      );
      try {
        await allocation.sync();
      } finally {
        await allocation.close();
      }
      for (const handle of handles) await handle.sync();
      await writeFile(
        `${prefix}-control-restored.json`,
        JSON.stringify({
          candidateSha: session.candidateSha,
          nonce: session.nonce,
          control: session.control,
          restored,
        }) + "\n",
        { flag: "wx", mode: 0o400 },
      );
      await check();
      return restored;
    },
  );
}

export async function observeLinuxFileControl(fixture, session) {
  recoveryNames(session);
  const prefix = path.join(
    fixture.directory,
    "evidence",
    `file-helper-${session.nonce}`,
  );
  const terminal = JSON.parse(
    await readProtectedEvidence(`${prefix}-terminal.json`),
  );
  const bytes = await readProtectedEvidence(`${prefix}-control.json`);
  const record = JSON.parse(bytes);
  if (
    JSON.stringify(terminal) !== JSON.stringify(session) ||
    digest(bytes) !== session.controlDigest ||
    record.candidateSha !== session.candidateSha ||
    record.nonce !== session.nonce ||
    record.control !== session.control ||
    session.settlement.status !== "RETIRED" ||
    !session.settlement.independent ||
    session.settlement.emergencyCleanup
  )
    throw new Error("Unbound control observation");
  return withFileControlAuthority(fixture, session, record, (anchor, check) =>
    observeFileControl(anchor, check, session.control),
  );
}

function observedIdentity(metadata) {
  const major =
    ((metadata.dev >> 8n) & 0xfffn) | ((metadata.dev >> 32n) & 0xfffff000n);
  const minor = (metadata.dev & 0xffn) | ((metadata.dev >> 12n) & 0xffffff00n);
  return `${major}:${minor}:${metadata.ino}:${metadata.birthtimeNs / 1000000000n}:${metadata.birthtimeNs % 1000000000n}`;
}

async function observeFileObjects(anchor, checkParent) {
  await checkParent();
  const observe = async (name, directory) => {
    const file = path.join(anchor, name);
    let handle;
    try {
      const named = await lstat(file, { bigint: true });
      if (
        (directory ? !named.isDirectory() : !named.isFile()) ||
        (await realpath(file)) !== file
      )
        throw new Error("Unexpected file object");
      handle = await open(
        file,
        constants.O_RDONLY |
          constants.O_NOFOLLOW |
          (directory ? constants.O_DIRECTORY : 0),
      );
      const before = await handle.stat({ bigint: true });
      if (
        observedIdentity(named) !== observedIdentity(before) ||
        (before.size > 4096n && !directory)
      )
        throw new Error("File observation changed");
      let bytes = null;
      if (!directory) {
        const buffer = Buffer.alloc(4097);
        const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
        if (bytesRead !== Number(before.size) || bytesRead > 4096)
          throw new Error("File observation exceeded its bound");
        bytes = buffer.subarray(0, bytesRead).toString("hex");
      }
      const after = await handle.stat({ bigint: true });
      const current = await lstat(file, { bigint: true });
      if (
        [after, current].some(
          (value) =>
            observedIdentity(value) !== observedIdentity(before) ||
            value.mode !== before.mode ||
            value.uid !== before.uid ||
            value.nlink !== before.nlink ||
            value.size !== before.size ||
            value.mtimeNs !== before.mtimeNs,
        )
      )
        throw new Error("File observation changed");
      return {
        identity: observedIdentity(before),
        mode: Number(before.mode & 0o7777n),
        uid: Number(before.uid),
        links: Number(before.nlink),
        bytes,
      };
    } catch (error) {
      if (error.code === "ENOENT") return null;
      throw error;
    } finally {
      await handle?.close();
    }
  };
  // Only fixed names are observed. No payload receives these host descriptors.
  const snapshot = {
    ownerUid: process.getuid(),
    parentAuthority: true,
    anchor: await observe("", true),
    allocation: await observe("allocation", true),
    leaf: await observe("allocation/value", false),
    temporary: await observe("allocation/.pending", false),
  };
  await checkParent();
  return snapshot;
}

/** The failed session remains immutable; observation cannot release storage. */
export async function observeLinuxFileSession(fixture, session) {
  recoveryNames(session);
  const terminal = JSON.parse(
    await readProtectedEvidence(
      path.join(
        fixture.directory,
        "evidence",
        `file-helper-${session.nonce}-terminal.json`,
      ),
    ),
  );
  if (JSON.stringify(terminal) !== JSON.stringify(session))
    throw new Error("File terminal evidence changed");
  const anchor = path.join(fixture.directory, session.anchorName);
  const handles = [];
  try {
    for (const directory of [fixture.directory, anchor])
      handles.push(
        await open(
          directory,
          constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
        ),
      );
    const originals = await Promise.all(
      handles.map((handle) => handle.stat({ bigint: true })),
    );
    const check = async () => {
      for (const [index, directory] of [fixture.directory, anchor].entries()) {
        const named = await lstat(directory, { bigint: true });
        const held = await handles[index].stat({ bigint: true });
        if (
          (await realpath(directory)) !== directory ||
          !named.isDirectory() ||
          observedIdentity(named) !== observedIdentity(originals[index]) ||
          observedIdentity(held) !== observedIdentity(originals[index]) ||
          (named.mode & 0o7777n) !== 0o700n ||
          named.uid !== BigInt(process.getuid())
        )
          throw new Error("Retained file parent changed");
      }
    };
    return await observeFileObjects(anchor, check);
  } finally {
    await Promise.all(handles.map((handle) => handle.close()));
  }
}

/** Comparable policy excludes the independently bound per-session anchor. */
export function linuxFileSessionPolicy(executableDigest, control = null) {
  normalizeLinuxFileControl(control);
  if (
    typeof executableDigest !== "string" ||
    !/^[a-f0-9]{64}$/u.test(executableDigest)
  )
    throw new Error("Invalid helper policy input");
  return Object.freeze({
    id: "linux-file-authority-v1",
    executableDigest,
    namespaces: Object.freeze(["user", "pid", "net", "ipc", "uts"]),
    anchor: "/anchor",
    hostCheckout: false,
    procfs: control === "magic-link",
    payloads: false,
    inheritedDescriptors: false,
    ...(control === null
      ? {}
      : { control, readOnlyCrossing: control === "mount" }),
  });
}

function sessionPolicyDigest(policy, anchorName) {
  return digest(
    JSON.stringify({
      policyDigest: digest(JSON.stringify(policy)),
      anchorName,
    }),
  );
}

function recoveryNames(recovery) {
  if (
    !recovery ||
    typeof recovery.nonce !== "string" ||
    !NONCE.test(recovery.nonce) ||
    typeof recovery.anchorName !== "string" ||
    !ANCHOR.test(recovery.anchorName) ||
    typeof recovery.nativeRecord !== "string" ||
    !RECORD.test(recovery.nativeRecord) ||
    typeof recovery.receiptDigest !== "string" ||
    !/^[a-f0-9]{64}$/u.test(recovery.receiptDigest)
  )
    throw new Error("Invalid recovery evidence names");
}

function recoveryNative(native) {
  if (
    !native ||
    Object.getPrototypeOf(native) !== Object.prototype ||
    Reflect.ownKeys(native).length !== 3 ||
    !["allocation", "leaf", "temporary"].every((key) => {
      const descriptor = Object.getOwnPropertyDescriptor(native, key);
      return descriptor?.enumerable && Object.hasOwn(descriptor, "value");
    })
  )
    throw new Error("Invalid recovery object authority");
  encodeLinuxFileRequest({ type: "recover", ...native, bytes: "" });
  return Object.freeze({ ...native });
}

/** Recovery authority comes from protected records, never caller-supplied IDs. */
export function normalizeLinuxFileRecovery(recovery, evidence) {
  recoveryNames(recovery);
  const { candidateSha, executableDigest, admission, ready, operation } =
    evidence;
  const receipt = normalizeLinuxReceipt(evidence.receipt);
  const native = recoveryNative(recovery.native);
  const policy = linuxFileSessionPolicy(
    executableDigest,
    recovery.control ?? null,
  );
  const policyDigest = digest(JSON.stringify(policy));
  const binding = sessionPolicyDigest(policy, recovery.anchorName);
  const normalize = (record) => {
    const { candidateSha: recordedCandidate, ...message } = record;
    if (recordedCandidate !== candidateSha)
      throw new Error("Recovery candidate mismatch");
    return normalizeLinuxFileMessage(message, recovery.nonce);
  };
  const readiness = normalize(ready);
  const recorded = normalize(operation);
  if (
    recovery.candidateSha !== candidateSha ||
    receipt.candidateSha !== candidateSha ||
    receipt.caseId !== "file-helper" ||
    receipt.nonce !== recovery.nonce ||
    receipt.executableDigest !== executableDigest ||
    receipt.policyDigest !== binding ||
    admission.schemaVersion !== 1 ||
    admission.candidateSha !== candidateSha ||
    admission.nonce !== recovery.nonce ||
    admission.anchorName !== recovery.anchorName ||
    admission.admission !== "possible" ||
    admission.policyDigest !== policyDigest ||
    admission.sessionPolicyDigest !== binding ||
    JSON.stringify(admission.policy) !== JSON.stringify(policy) ||
    !(
      recovery.nativeRecord.startsWith("barrier-")
        ? ["prepared", "published", "checking", "removing"]
        : ["allocated", "recovered", "complete", "exists", "inspected"]
    ).includes(recorded.phase) ||
    readiness.phase !== "ready" ||
    readiness.anchor !== recovery.nativeAnchor ||
    recorded.anchor !== readiness.anchor ||
    recorded.allocation !== native.allocation ||
    recorded.leaf !== native.leaf ||
    recorded.temporary !== native.temporary
  )
    throw new Error("Recovery evidence mismatch; exclusion retained");
  return Object.freeze({ ...recovery, native });
}

/** A declared interruption cannot waive owner settlement or its deadline. */
export async function settleLinuxFileSessionFailure(state, effects) {
  let emergencyCleanup = state.emergencyCleanup || !state.interrupted;
  try {
    effects.stop();
    await effects.settle();
  } catch {
    emergencyCleanup = true;
  }
  return emergencyCleanup || effects.now() >= state.deadline;
}

/** This private session confers no files.* acceptance. The later system suite
 * must independently observe bytes/identities and persist admission first. */
export async function runLinuxFileSession(
  job,
  fixture,
  build,
  body,
  { recovery = null, control = null } = {},
) {
  normalizeLinuxFileControl(control);
  if (recovery !== null && control !== null)
    throw new Error("Recovery cannot inherit fault authority");
  if (
    process.platform !== "linux" ||
    process.arch !== "x64" ||
    process.env.ImageOS !== "ubuntu24" ||
    process.env.CI !== "true" ||
    process.env.GITHUB_ACTIONS !== "true" ||
    job.platform !== "linux" ||
    job.stages.setup.status !== "PASS" ||
    build.candidateSha !== job.candidateSha ||
    JSON.stringify(build.arguments) !==
      JSON.stringify(LINUX_FILE_BUILD_ARGUMENTS)
  )
    throw new Error("Linux file session requires bound system CI inputs");
  job = Object.freeze({ ...job });
  build = Object.freeze({ ...build });
  const executable = await lstat(build.executable);
  if (
    !executable.isFile() ||
    executable.nlink !== 1 ||
    executable.uid !== process.getuid() ||
    executable.size > 4194304 ||
    (executable.mode & 0o7777) !== 0o500 ||
    (await realpath(build.executable)) !== build.executable
  )
    throw new Error("Linux helper executable changed");
  const bytes = await readFile(build.executable);
  if (bytes.length !== executable.size || digest(bytes) !== build.sha256)
    throw new Error("Linux helper executable changed");
  verifyLinuxFileElf(bytes);
  if (recovery) {
    recoveryNames(recovery);
    recovery = Object.freeze({
      ...recovery,
      native: recoveryNative(recovery.native),
    });
  }
  const nonce = randomUUID();
  const anchorName = recovery?.anchorName ?? `file-${nonce}`;
  if (!ANCHOR.test(anchorName)) throw new Error("Invalid allocation anchor");
  if (recovery) {
    recoveryNames(recovery);
    const oldFile = path.join(
      fixture.directory,
      "evidence",
      `file-helper-${recovery.nonce}.json`,
    );
    const old = await protectedReceipt(oldFile, recovery.receiptDigest);
    const record = async (suffix) =>
      JSON.parse(
        await readProtectedEvidence(
          path.join(
            fixture.directory,
            "evidence",
            `file-helper-${recovery.nonce}-${suffix}.json`,
          ),
        ),
      );
    const [admission, ready, operation] = await Promise.all([
      record("result"),
      record("ready"),
      record(recovery.nativeRecord),
    ]);
    recovery = normalizeLinuxFileRecovery(recovery, {
      candidateSha: job.candidateSha,
      executableDigest: build.sha256,
      receipt: old,
      admission,
      ready,
      operation,
    });
    if (recovery.control !== null && recovery.control !== undefined) {
      const [terminal, denied, restored] = await Promise.all([
        record("terminal"),
        record("denied"),
        record("control-restored"),
      ]);
      const controlBytes = await readProtectedEvidence(
        path.join(
          fixture.directory,
          "evidence",
          `file-helper-${recovery.nonce}-control.json`,
        ),
      );
      const applied = JSON.parse(controlBytes);
      const expected = structuredClone(applied.before);
      if (recovery.control === "mount")
        for (const name of [
          "crossing",
          ".crossing-source",
          ".crossing-source/value",
        ])
          expected.objects[name] = null;
      if (
        JSON.stringify(terminal) !== JSON.stringify(recovery) ||
        recovery.denial?.phase !== "denied" ||
        denied.candidateSha !== job.candidateSha ||
        denied.nonce !== recovery.nonce ||
        denied.controlDigest !== recovery.controlDigest ||
        denied.nativeRecord !== recovery.nativeRecord ||
        JSON.stringify(denied.message) !== JSON.stringify(recovery.denial) ||
        restored.candidateSha !== job.candidateSha ||
        restored.nonce !== recovery.nonce ||
        restored.control !== recovery.control ||
        digest(controlBytes) !== recovery.controlDigest ||
        applied.candidateSha !== job.candidateSha ||
        applied.nonce !== recovery.nonce ||
        applied.control !== recovery.control ||
        JSON.stringify(restored.restored) !== JSON.stringify(expected)
      )
        throw new Error("Recovery lacks protected control restoration");
    }
    const retired = await freshVerifier(oldFile, recovery.receiptDigest);
    if (
      retired.status !== "RETIRED" ||
      !retired.independent ||
      retired.emergencyCleanup
    )
      throw new Error(
        "Recovery retains exclusion without fresh independent retirement",
      );
  }
  const anchor = path.join(fixture.directory, anchorName);
  if (!recovery) await mkdir(anchor, { mode: 0o700 });
  const handles = [];
  try {
    const held = await open(
      anchor,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
    );
    handles.push(held);
    const anchorIdentity = await held.stat({ bigint: true });
    const heldParent = await open(
      fixture.directory,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
    );
    handles.push(heldParent);
    const parentIdentity = await heldParent.stat({ bigint: true });
    const currentAnchor = async () => {
      const namedParent = await lstat(fixture.directory, { bigint: true });
      const retainedParent = await heldParent.stat({ bigint: true });
      const current = await lstat(anchor, { bigint: true });
      const retained = await held.stat({ bigint: true });
      const currentExecutable = await lstat(build.executable);
      if (
        (await realpath(anchor)) !== anchor ||
        (await realpath(fixture.directory)) !== fixture.directory ||
        !namedParent.isDirectory() ||
        namedParent.dev !== parentIdentity.dev ||
        namedParent.ino !== parentIdentity.ino ||
        namedParent.dev !== retainedParent.dev ||
        namedParent.ino !== retainedParent.ino ||
        (namedParent.mode & 0o7777n) !== 0o700n ||
        namedParent.uid !== BigInt(process.getuid()) ||
        !current.isDirectory() ||
        current.dev !== anchorIdentity.dev ||
        current.ino !== anchorIdentity.ino ||
        current.dev !== retained.dev ||
        current.ino !== retained.ino ||
        (current.mode & 0o7777n) !== 0o700n ||
        current.uid !== BigInt(process.getuid()) ||
        !currentExecutable.isFile() ||
        currentExecutable.dev !== executable.dev ||
        currentExecutable.ino !== executable.ino ||
        currentExecutable.nlink !== 1 ||
        currentExecutable.uid !== executable.uid ||
        currentExecutable.size !== executable.size ||
        (currentExecutable.mode & 0o7777) !== 0o500
      )
        throw new Error("Named anchor changed; exclusion retained");
    };
    if (control === "mount") {
      await mkdir(path.join(anchor, "crossing"), { mode: 0o700 });
      await mkdir(path.join(anchor, ".crossing-source"), { mode: 0o700 });
      await writeFile(
        path.join(anchor, ".crossing-source/value"),
        Buffer.from(CONTROL_BYTES, "hex"),
        { flag: "wx", mode: 0o600 },
      );
    }
    const policy = linuxFileSessionPolicy(build.sha256, control);
    const policyDigest = digest(JSON.stringify(policy));
    const binding = sessionPolicyDigest(policy, anchorName);
    const helperFixture = {
      ...fixture,
      fileHelper: true,
      ...(control === null ? {} : { fileControl: control }),
      executable: build.executable,
      fileAnchorIdentity: recovery?.nativeAnchor ?? null,
      executableDigest: build.sha256,
      policy,
      policyDigest: binding,
    };
    const evidenceFile = path.join(
      fixture.directory,
      "evidence",
      `file-helper-${nonce}-result.json`,
    );
    let result = {
      schemaVersion: 1,
      candidateSha: job.candidateSha,
      nonce,
      anchorName,
      receiptDigest: null,
      nativeAnchor: null,
      native: null,
      nativeRecord: null,
      recoveredFrom: recovery?.nonce ?? null,
      control,
      controlDigest: null,
      denial: null,
      admission: "possible",
      status: "RUNNING",
      policy,
      policyDigest,
      sessionPolicyDigest: binding,
      settlement: {
        status: "RETAINED",
        independent: false,
        emergencyCleanup: false,
      },
      storage: "RETAINED",
      exclusion: "RETAINED",
    };
    await writeFile(evidenceFile, JSON.stringify(result) + "\n", {
      flag: "wx",
      mode: 0o400,
    });
    const deadline = performance.now() + 30000;
    const queue = messageQueue(deadline);
    const owner = fork(
      CONTROLLER,
      [
        "--control",
        JSON.stringify({
          fixture: helperFixture,
          caseId: "file-helper",
          candidateSha: job.candidateSha,
          nonce,
          output: anchor,
        }),
      ],
      {
        cwd: fixture.directory,
        env: ENVIRONMENT,
        execArgv: [],
        stdio: ["ignore", "pipe", "pipe", "ipc"],
      },
    );
    owner.once("error", (error) => queue.fail(error));
    let ownerOutcome = null;
    const exit = new Promise((resolve) =>
      owner.once("close", (code, signal) => {
        queue.fail();
        ownerOutcome = { code, signal };
        resolve(ownerOutcome);
      }),
    );
    let settlement;
    const waitForSettlement = async () => {
      let timeout;
      try {
        return await Promise.race([
          exit,
          new Promise((_, reject) => {
            timeout = setTimeout(
              () => reject(new Error("Owner settlement deadline")),
              5000,
            );
          }),
        ]);
      } finally {
        clearTimeout(timeout);
      }
    };
    const settle = () => (settlement ??= waitForSettlement());
    owner.on("message", (message) =>
      message?.nonce === nonce ? queue.push(message) : queue.fail(),
    );
    let diagnostics = 0;
    let emergencyCleanup = false;
    const timer = setTimeout(
      () => {
        emergencyCleanup = true;
        queue.fail();
        owner.kill("SIGKILL");
      },
      Math.max(0, deadline - performance.now()),
    );
    for (const stream of [owner.stdout, owner.stderr].filter(Boolean))
      stream.on("data", (chunk) => {
        diagnostics += chunk.length;
        if (diagnostics > 65536) {
          emergencyCleanup = true;
          queue.fail();
          owner.kill("SIGKILL");
        }
      });
    let receiptDigest;
    let allocation = null;
    let leaf = null;
    let temporary = null;
    let failed = false;
    let faultApplied = false;
    let controlStarted = false;
    let interruptedPhase = null;
    let parked = null;
    let operations = Promise.resolve();
    let commands = 0;
    const receiptFile = path.join(
      fixture.directory,
      "evidence",
      `file-helper-${nonce}.json`,
    );
    const receive = async () => {
      const payload = await queue.take((message) => message.type === "payload");
      return payload.message;
    };
    const persistControl = async (suffix, value) => {
      const bytes =
        JSON.stringify({ candidateSha: job.candidateSha, nonce, ...value }) +
        "\n";
      await writeFile(
        path.join(
          fixture.directory,
          "evidence",
          `file-helper-${nonce}-${suffix}.json`,
        ),
        bytes,
        { flag: "wx", mode: 0o400 },
      );
      return bytes;
    };
    const perform = async (type, bytes, barrier) => {
      if (failed || performance.now() >= deadline)
        throw new Error("File session excluded");
      const request =
        type === "recover"
          ? { type, ...recovery.native, bytes }
          : {
              type,
              allocation: ["allocate", "finish"].includes(type)
                ? null
                : allocation,
              leaf: ["allocate", "publish", "finish"].includes(type)
                ? null
                : leaf,
              temporary: ["allocate", "finish"].includes(type)
                ? null
                : temporary,
              bytes,
            };
      const outcome = await runLinuxFileTransaction(request, {
        nonce,
        anchor: result.nativeAnchor,
        allocation,
        previousLeaf: leaf,
        temporary,
        receive,
        async denied(message) {
          if (
            control === null ||
            result.denial !== null ||
            result.controlDigest === null
          )
            throw new Error("Unbound native rejection");
          await persistControl("denied", {
            message,
            nativeRecord: result.nativeRecord,
            controlDigest: result.controlDigest,
          });
        },
        async barrier(message) {
          result.native = Object.freeze({
            allocation: message.allocation,
            leaf: message.leaf,
            temporary: message.temporary,
          });
          const record = `barrier-${barriers++}`;
          await writeFile(
            path.join(
              fixture.directory,
              "evidence",
              `file-helper-${nonce}-${record}.json`,
            ),
            JSON.stringify({
              candidateSha: job.candidateSha,
              nonce,
              ...message,
            }) + "\n",
            { flag: "wx", mode: 0o400 },
          );
          if (failed || performance.now() >= deadline)
            throw new Error("File barrier exceeded session authority");
          result.nativeRecord = record;
          parked = message.phase;
          try {
            await barrier(message);
          } finally {
            parked = null;
          }
        },
        async send(message) {
          if (failed || performance.now() >= deadline)
            throw new Error("File session excluded");
          await currentAnchor();
          await writeFile(
            path.join(
              fixture.directory,
              "evidence",
              `file-helper-${nonce}-command-${commands++}.json`,
            ),
            JSON.stringify({
              candidateSha: job.candidateSha,
              nonce,
              request: message,
            }) + "\n",
            { flag: "wx", mode: 0o400 },
          );
          if (failed || performance.now() >= deadline)
            throw new Error("File session excluded");
          await send(owner, { type: "file-command", nonce, message });
        },
      });
      if (outcome.status !== "PASS") {
        if (outcome.message?.phase === "denied")
          result.denial = outcome.message;
        failed = true;
        throw new Error("File identity or protocol failure");
      }
      if (type !== "finish") {
        allocation = outcome.message.allocation;
        leaf = outcome.message.leaf;
        temporary = outcome.message.temporary;
        result.native = Object.freeze({ allocation, leaf, temporary });
        const record = `operation-${completed++}`;
        await writeFile(
          path.join(
            fixture.directory,
            "evidence",
            `file-helper-${nonce}-${record}.json`,
          ),
          JSON.stringify({
            candidateSha: job.candidateSha,
            ...outcome.message,
          }) + "\n",
          { flag: "wx", mode: 0o400 },
        );
        if (failed || performance.now() >= deadline)
          throw new Error("File operation exceeded session authority");
        result.nativeRecord = record;
      }
      return outcome.message;
    };
    const operation = (type, bytes = "", barrier = async () => {}) => {
      // Only this trusted owner serializes parent mutation. Payloads get neither
      // this channel nor an anchor/parent fd or an ancestor directory grant.
      const pending = operations.then(() => perform(type, bytes, barrier));
      operations = pending.catch(() => {
        failed = true;
      });
      return pending;
    };
    let barriers = 0;
    let completed = 0;
    try {
      const admitted = await queue.take(
        (message) => message.type === "admitted",
      );
      receiptDigest = admitted.sha256;
      result.receiptDigest = receiptDigest;
      const receipt = await protectedReceipt(receiptFile, receiptDigest);
      const [init, launcher, controller, observer] = await Promise.all([
        processDetails(receipt.init.pid),
        processDetails(receipt.launcher.pid),
        processDetails(owner.pid),
        processDetails(process.pid),
      ]);
      if (
        receipt.candidateSha !== job.candidateSha ||
        receipt.caseId !== "file-helper" ||
        receipt.nonce !== nonce ||
        receipt.policyDigest !== helperFixture.policyDigest ||
        receipt.executableDigest !== build.sha256 ||
        !sameLinuxIdentity(init.identity, receipt.init.identity) ||
        init.namespaceId !== receipt.init.namespaceId ||
        init.nspid.at(-1) !== 1 ||
        init.parent !== launcher.pid ||
        !sameLinuxIdentity(launcher.identity, receipt.launcher.identity) ||
        launcher.namespaceId !== receipt.parentNamespaceId ||
        !sameLinuxIdentity(controller.identity, receipt.controller.identity) ||
        receipt.controller.pid !== owner.pid ||
        controller.namespaceId !== receipt.parentNamespaceId ||
        observer.namespaceId !== receipt.parentNamespaceId
      )
        throw new Error("Independent helper admission mismatch");
      await currentAnchor();
      if (performance.now() >= deadline)
        throw new Error("Helper admission deadline");
      await send(owner, { type: "admission-ack", nonce });
      const ready = normalizeLinuxFileMessage(await receive(), nonce);
      if (ready.phase !== "ready") throw new Error("Helper readiness missing");
      result.nativeAnchor = ready.anchor;
      await writeFile(
        path.join(
          fixture.directory,
          "evidence",
          `file-helper-${nonce}-ready.json`,
        ),
        JSON.stringify({ candidateSha: job.candidateSha, ...ready }) + "\n",
        { flag: "wx", mode: 0o400 },
      );
      const members = await descendants(receipt.init.pid);
      const helpers = [];
      for (const member of members) {
        if (
          member.nspid.at(-1) === 1 &&
          member.namespaceId !== init.namespaceId &&
          digest(await readFile(`/proc/${member.pid}/exe`)) === build.sha256
        )
          helpers.push(member);
      }
      if (
        helpers.length !== 1 ||
        helpers[0].networkId === observer.networkId ||
        helpers[0].ipcId === observer.ipcId ||
        helpers[0].mountId === observer.mountId
      )
        throw new Error("Helper domain mismatch");
      await inspectFixtureMounts(helpers[0].pid, helperFixture, anchor);
      const currentHelper = await processDetails(helpers[0].pid);
      if (
        !sameLinuxIdentity(currentHelper.identity, helpers[0].identity) ||
        currentHelper.namespaceId !== helpers[0].namespaceId ||
        currentHelper.mountId !== helpers[0].mountId ||
        currentHelper.networkId !== helpers[0].networkId ||
        currentHelper.ipcId !== helpers[0].ipcId
      )
        throw new Error("Helper identity changed during inspection");
      if (recovery) await operation("recover");
      const controls = {
        anchor,
        nonce,
        helper: helpers[0],
        receipt,
        observe: () => observeFileObjects(anchor, currentAnchor),
        async fault(value) {
          normalizeLinuxFileControl(value);
          const phase = ["magic-link", "mount"].includes(value)
            ? "checking"
            : value === "cleanup-leaf"
              ? "removing"
              : "prepared";
          if (
            value !== control ||
            value === null ||
            result.controlDigest !== null ||
            controlStarted ||
            parked !== phase ||
            failed ||
            performance.now() >= deadline
          )
            throw new Error("Fault requires its closed parked authority");
          controlStarted = true;
          const authority = async () => {
            if (
              parked !== phase ||
              failed ||
              performance.now() >= deadline ||
              owner.exitCode !== null ||
              owner.signalCode !== null
            )
              throw new Error("Parked control authority ended");
            await currentAnchor();
            const current = await processDetails(helpers[0].pid);
            if (
              !sameLinuxIdentity(current.identity, helpers[0].identity) ||
              current.namespaceId !== helpers[0].namespaceId ||
              current.mountId !== helpers[0].mountId
            )
              throw new Error("Parked helper identity changed");
          };
          const observation = await applyFileControl(
            anchor,
            authority,
            value,
            persistControl,
            result.native,
          );
          if (performance.now() >= deadline)
            throw new Error("Control exceeded session bound");
          result.controlDigest = observation.sha256;
          return { before: observation.before, applied: observation.applied };
        },
        async interrupt() {
          if (
            !parked ||
            faultApplied ||
            performance.now() >= deadline ||
            owner.exitCode !== null ||
            owner.signalCode !== null
          )
            throw new Error(
              "Interruption requires an acknowledged live barrier",
            );
          await writeFile(
            path.join(
              fixture.directory,
              "evidence",
              `file-helper-${nonce}-interruption.json`,
            ),
            JSON.stringify({
              candidateSha: job.candidateSha,
              nonce,
              phase: parked,
              native: result.native,
            }) + "\n",
            { flag: "wx", mode: 0o400 },
          );
          if (
            failed ||
            !parked ||
            performance.now() >= deadline ||
            owner.exitCode !== null ||
            owner.signalCode !== null
          )
            throw new Error("Interruption target no longer at a live barrier");
          if (!owner.kill("SIGKILL"))
            throw new Error("Owned interruption was not applied");
          faultApplied = true;
          interruptedPhase = parked;
        },
      };
      await Promise.race([
        (async () => {
          await body(operation, controls);
          await operations;
        })(),
        queue.take(() => false),
      ]);
      if (failed || allocation !== null)
        throw new Error("Native allocation cleanup incomplete");
      await operation("finish");
      await send(owner, { type: "fault", nonce });
      await queue.take((message) => message.type === "settled");
      await send(owner, { type: "settlement-ack", nonce });
      const completion = await settle();
      if (
        completion.code !== 0 ||
        completion.signal !== null ||
        performance.now() >= deadline
      )
        throw new Error("Helper settlement failed");
      result.status = "PASS";
    } catch {
      failed = true;
      result.status = "FAIL";
      if (result.denial !== null) {
        try {
          await send(owner, {
            type: "file-denial",
            nonce,
            message: result.denial,
          });
          await queue.take((message) => message.type === "settled");
          await send(owner, { type: "settlement-ack", nonce });
          const completion = await settle();
          if (
            completion.code !== 0 ||
            completion.signal !== null ||
            performance.now() >= deadline
          )
            throw new Error("Native denial did not settle");
        } catch {
          result.settlement.emergencyCleanup = true;
          owner.kill("SIGKILL");
          await settle().catch(() => {});
        }
      } else
        result.settlement.emergencyCleanup =
          await settleLinuxFileSessionFailure(
            { emergencyCleanup, interrupted: faultApplied, deadline },
            {
              stop() {
                queue.fail();
                owner.kill("SIGKILL");
              },
              settle,
              now: () => performance.now(),
            },
          );
    } finally {
      clearTimeout(timer);
      result.settlement.emergencyCleanup ||= emergencyCleanup;
      result.interrupted = faultApplied;
      result.interruption = faultApplied
        ? {
            phase: interruptedPhase,
            observed: ownerOutcome?.signal === "SIGKILL",
          }
        : null;
      result = await retireLinuxFileStorage(result, {
        verify: () =>
          receiptDigest
            ? freshVerifier(receiptFile, receiptDigest)
            : Promise.resolve({
                status: "RETAINED",
                independent: false,
                emergencyCleanup: false,
              }),
        async cleanup() {
          await currentAnchor();
          await rmdir(anchor); // Empty anchor, under retained sole parent authority.
          await heldParent.sync();
        },
      });
      const closed = await Promise.allSettled(
        handles.splice(0).map((handle) => handle.close()),
      );
      if (
        emergencyCleanup ||
        closed.some(({ status }) => status === "rejected")
      ) {
        result.settlement.emergencyCleanup ||= emergencyCleanup;
        result.status = "FAIL";
        result.storage = "RETAINED";
        result.exclusion = "RETAINED";
      }
      // Keep the write-ahead record; a separate terminal file cannot erase it.
      await writeFile(
        path.join(
          fixture.directory,
          "evidence",
          `file-helper-${nonce}-terminal.json`,
        ),
        JSON.stringify(result) + "\n",
        { flag: "wx", mode: 0o400 },
      );
    }
    Object.freeze(result.settlement);
    return Object.freeze(result);
  } finally {
    await Promise.allSettled(handles.map((handle) => handle.close()));
  }
}
